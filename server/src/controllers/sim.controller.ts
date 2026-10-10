/**
 * ObliWAN — mobile data lines, HTTP layer.
 *
 * ┌─ TWO SCOPES ON ONE PREFIX, AND THE SPLIT IS THE SECURITY DESIGN ──────────┐
 * │                                                                          │
 * │ /sim/accounts/*   PLATFORM. `requireRole('admin')` on the route, upstream │
 * │                   of every branch here. These rows hold a partner         │
 * │                   CREDENTIAL and have no `tenant_id` (migration 032,      │
 * │                   decision 2), so one write changes what every tenant is  │
 * │                   shown. SETTINGS_MANAGE would NOT do: it is granted to   │
 * │                   the admin of any tenant through                         │
 * │                   `TENANT_ROLE_CAPABILITIES`, which is exactly the bug    │
 * │                   weather map shipped on `ip_asn_ranges`. Worse here — a  │
 * │                   tenant admin could repoint `base_url` at a host they    │
 * │                   control and harvest the credential on the next sweep.   │
 * │                                                                          │
 * │ everything else   TENANT. Every read goes through `scope()` below, which  │
 * │                   builds `{ tenantId, masterView }` from what             │
 * │                   `requireTenant` established from the tenant AND         │
 * │                   `users.role` — never from                               │
 * │                   `req.session.currentTenantId`.                          │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHAT THIS SURFACE MUST NEVER RETURN ─────────────────────────────────────┐
 * │ A partner credential, in any shape. `toAccount()` has an explicit         │
 * │ projection that excludes `credential_blob`, and there is deliberately NO  │
 * │ reveal endpoint: SECRET_READ's routes (secretReveal.routes.ts) cover      │
 * │ device transports, SNMP credentials and secret template variables —       │
 * │ values an engineer must sometimes type into a console — and a partner     │
 * │ API token has no such use, so they deliberately do not reach              │
 * │ `sim_partner_accounts`.                                                   │
 * │ `POST /accounts/:id/otp` ACCEPTS a password and a code and returns        │
 * │ neither — it stores the resulting token and answers with the account.     │
 * │ A LINE's PUK1 / PUK2 / RADIUS password / RIO (migrations 077, 079) is     │
 * │ another matter: the reads here say only whether each is stored, and the  │
 * │ one door is `POST /sim/lines/:id/reveal` in secretReveal.routes.ts,       │
 * │ audited.                                                                  │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * No route here writes to an equipment. The one route that reaches outside
 * this installation at all is the sweep, which talks to a partner's web API.
 */

import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import {
  SIM_LINE_STATUSES,
  SIM_PLATFORM_CATALOG,
  SIM_RECHARGE_STATUSES,
  simAccountInputSchema,
  simCredentialInputSchema,
  simLineUpdateSchema,
  simManualRechargeSchema,
  simRechargeCompletionSchema,
  simRechargeDecisionSchema,
  type SimRechargeStatus,
} from '@obliwan/shared';
import { AppError } from '../middleware/errorHandler';
import { db } from '../db';
import {
  SimAccountError,
  createAccount,
  deleteAccount,
  getAccount,
  listAccounts,
  setCredential,
  testConnection,
  updateAccount,
  type SimAccountRow,
} from '../services/sim/account.service';
import {
  deviceSimView,
  fleetSummary,
  getLine,
  getLineHistory,
  listLines,
  updateLine,
  type SimScope,
} from '../services/sim/line.service';
import {
  approve,
  capUsage,
  execute,
  getRecharge,
  listRecharges,
  priceRecharge,
  proposeManual,
  recordCompletion,
  reject,
} from '../services/sim/recharge.service';
import { rechargeReport, reportToCsv } from '../services/sim/report.service';
import { fetchRechargeOffers, listPartnerRecharges } from '../services/sim/partnerRecharge.service';
import { syncAccount } from '../services/sim/sync.service';
import { accessOf, accessOfOne, simLineListScope, ungroupedLevel } from '../services/teamScope.service';
import { SimConnectorError } from '../services/sim/types';
import { phenixAuthenticateAttempt, phenixAuthenticateWithCode } from '../services/sim/phenix.connector';

// ============================================================================
// Helpers
// ============================================================================

function parseId(raw: string, what = 'id'): number {
  const id = Number.parseInt(raw, 10);
  if (!Number.isInteger(id) || id <= 0) throw new AppError(400, `Invalid ${what}`);
  return id;
}

function parse<S extends z.ZodTypeAny>(schema: S, value: unknown): z.infer<S> {
  const result = schema.safeParse(value);
  if (!result.success) {
    const flat = result.error.flatten();
    const fields = Object.entries(flat.fieldErrors)
      .map(([f, m]) => `${f}: ${((m as string[] | undefined) ?? []).join(', ')}`)
      .concat(flat.formErrors)
      .filter((s) => s.length > 0)
      .join('; ');
    throw new AppError(400, fields ? `Validation failed — ${fields}` : 'Validation failed');
  }
  return result.data;
}

/**
 * The tenant scope for every non-account route.
 *
 * `masterView` comes from `requireTenant`, which sets it only for a PLATFORM
 * ADMIN (`users.role`, read from the database) on the master tenant — not from
 * a membership row, which neither grants nor is required for it.
 * Recomputing it here from the session would reintroduce the god-view
 * defect the middleware closes.
 */
function scope(req: Request): SimScope {
  return { tenantId: req.tenantId, masterView: req.masterView };
}

/**
 * Team scope (migration 087): the line ids the caller's teams cover (null =
 * unrestricted: a platform admin), and whether top-ups whose line is gone may
 * be shown (the ungrouped grant — an object filed nowhere).
 */
async function teamLines(req: Request): Promise<{ lineIdsIn: number[] | null; orphansOk: boolean }> {
  const lineIdsIn = await simLineListScope(req);
  if (lineIdsIn === null) return { lineIdsIn, orphansOk: true };
  const userId = req.session?.userId;
  const orphansOk = !!userId && (await ungroupedLevel(userId, req.tenantId)) !== null;
  return { lineIdsIn, orphansOk };
}

/**
 * The acting user, for the audit ledger and the decision columns.
 *
 * `express-session` types every `SessionData` field as optional, and every
 * route here is behind `requireAuth`, so the fields ARE set. The guard is not
 * ceremony: a top-up decision attributed to user `undefined` is an unsigned
 * approval in a money trail, and failing loudly beats writing one.
 */
function actor(req: Request): { id: number; name: string } {
  const id = req.session.userId;
  if (typeof id !== 'number') throw new AppError(401, 'Not authenticated');
  return { id, name: req.session.username ?? String(id) };
}

/**
 * Service errors carry their own HTTP status; everything else stays what it is
 * and becomes a 500.
 *
 * Translated here rather than thrown as `AppError` from the service layer, so
 * the services stay callable from the sweep — which has no request, no response
 * and no use for an HTTP status.
 */
/** Partner-side failure codes → the HTTP status an operator should see. */
const CONNECTOR_STATUS: Record<string, number> = {
  // The operator typed a wrong password or a wrong one-time code. Their input,
  // their fix — a 400, not the 500 the first draft produced by falling through.
  AUTH_FAILED: 400,
  NOT_IMPLEMENTED: 501,
  CONFIG_ERROR: 400,
  // The partner answered badly or not at all. Nothing here is wrong; 502 says
  // "upstream", which is what an operator needs to know before retrying.
  PARTNER_ERROR: 502,
  UNREADABLE: 502,
};

function toHttp(err: unknown): unknown {
  if (err instanceof SimAccountError) return new AppError(err.status, err.message);
  if (err instanceof SimConnectorError) {
    // The message was scrubbed of credential literals in the error's own
    // constructor, so it is safe to hand to the client.
    return new AppError(CONNECTOR_STATUS[err.code] ?? 502, err.message);
  }
  return err;
}

// ============================================================================
// Platform: accounts
// ============================================================================

export const simController = {
  /** The coverage matrix, as data. The UI renders it rather than hard-coding
   *  which partners are readable — see `shared/src/sim.ts`, decision 3. */
  listPlatforms(_req: Request, res: Response): void {
    res.json({ success: true, data: SIM_PLATFORM_CATALOG });
  },

  async listAccounts(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: await listAccounts() });
    } catch (err) {
      next(err);
    }
  },

  async createAccount(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const input = parse(simAccountInputSchema, req.body);
      res.status(201).json({ success: true, data: await createAccount(input) });
    } catch (err) {
      next(toHttp(err));
    }
  },

  async updateAccount(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'account id');
      // `platform` is omitted from the patch schema: changing it would leave a
      // credential minted for one partner pointed at another's connector, and
      // every line already collected attributed to the wrong platform.
      const input = parse(simAccountInputSchema.partial().omit({ platform: true }), req.body);
      res.json({ success: true, data: await updateAccount(id, input) });
    } catch (err) {
      next(toHttp(err));
    }
  },

  async deleteAccount(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      await deleteAccount(parseId(req.params.id, 'account id'));
      res.json({ success: true });
    } catch (err) {
      next(toHttp(err));
    }
  },

  async setCredential(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'account id');
      const cred = parse(simCredentialInputSchema, req.body);
      // A token knows its own partner id and expiry; both are re-derived inside
      // `setCredential` so what is stored matches what was supplied rather than
      // what was typed into the form.
      res.json({ success: true, data: await setCredential(id, cred) });
    } catch (err) {
      next(toHttp(err));
    }
  },

  /**
   * Step ONE of the interactive sign-in: try the credentials, and say whether
   * the partner wants a code.
   *
   * ┌─ THE EMAILED CODE CANNOT BE TYPED BEFORE IT IS SENT ─────────────────────┐
   * │ `POST /accounts/:id/otp` asks for username, password AND code at once.   │
   * │ That is the right shape for a TOTP authenticator, which mints a code     │
   * │ offline — and the wrong one for a code DELIVERED BY EMAIL, because the   │
   * │ message is only sent once somebody asks to sign in, and nothing in this  │
   * │ product ever asked. The OTP screen was therefore unusable on a mailed    │
   * │ challenge: it demanded a code that could not exist yet.                  │
   * │                                                                          │
   * │ This route is the trigger. It calls `/Auth/authenticate` — the same call │
   * │ the sweep makes, read by the same `readAuthenticateResponse` — and       │
   * │ reports back one of two outcomes, so the screen reveals the code field   │
   * │ only on an answer a code challenge can look like: a 401/403, which is    │
   * │ equally a wrong password, so the screen states both readings. Every     │
   * │ other answer that is not a token is thrown, and reaches the operator as  │
   * │ the connector's own sentence.                                            │
   * └──────────────────────────────────────────────────────────────────────────┘
   *
   * On success it stores the credential in `password` mode, NOT `token`, and
   * that is a reversal of what this file used to do. A Phenix token carries
   * `expires_in: 14400` — four hours, observed on a real account — while
   * `SIM_SYNC_INTERVAL` is 240 minutes. A hand-pasted token is therefore stale
   * by the next sweep, every time; `password` mode re-authenticates on each
   * `openSession()` and mints a fresh one, so it is the only mode that sustains
   * itself. Nothing is stored when a code is required: a credential that cannot
   * complete a sign-in is not a credential.
   */
  async tryAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'account id');
      const input = parse(
        z.object({
          username: z.string().trim().min(1).max(190),
          password: z.string().min(1).max(512),
        }),
        req.body,
      );
      const account = await getAccount(id);
      if (!account) throw new AppError(404, 'Account not found');
      if (account.platform !== 'phenix') {
        throw new AppError(400, 'Interactive sign-in is only implemented for Phenix Partner.');
      }
      const row = await db<SimAccountRow>('sim_accounts').where({ id }).first();
      const attempt = await phenixAuthenticateAttempt(
        row?.base_url ?? null,
        input.username,
        input.password,
      );

      if (attempt.kind === 'code_required') {
        res.json({
          success: true,
          data: {
            status: 'code_required' as const,
            observed: attempt.observed,
            account,
          },
        });
        return;
      }

      if (account.authMode !== 'password') {
        await updateAccount(id, { authMode: 'password' });
      }
      const saved = await setCredential(
        id,
        { authMode: 'password', username: input.username, password: input.password },
        { partnerRef: attempt.partnerRef },
      );
      res.json({
        success: true,
        data: {
          status: 'authenticated' as const,
          // Informational only: what the sweep will re-mint every four hours.
          tokenExpiresAt: attempt.expiresAt,
          account: saved,
        },
      });
    } catch (err) {
      next(toHttp(err));
    }
  },

  /**
   * Step TWO: the one-time code, which is interactive BY DEFINITION.
   *
   * A sweep has no human and therefore cannot answer a code challenge. This
   * route exists so an operator can clear that challenge once; the password and
   * the code are used here and the code is stored nowhere.
   */
  async authenticateWithCode(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'account id');
      const input = parse(
        z.object({
          username: z.string().trim().min(1).max(190),
          password: z.string().min(1).max(512),
          code: z.string().trim().min(4).max(12),
        }),
        req.body,
      );
      const account = await getAccount(id);
      if (!account) throw new AppError(404, 'Account not found');
      if (account.platform !== 'phenix') {
        throw new AppError(400, 'One-time-code sign-in is only implemented for Phenix Partner.');
      }
      const row = await db<SimAccountRow>('sim_accounts').where({ id }).first();
      const result = await phenixAuthenticateWithCode(
        row?.base_url ?? null,
        input.username,
        input.password,
        input.code,
      );
      // ┌─ WHAT GETS STORED IS THE PASSWORD, NOT THE TOKEN THAT WAS JUST WON ──┐
      // │ This used to store the bearer token, on the stated reasoning that    │
      // │ an operator "authenticates once and leaves a long-lived token        │
      // │ behind". A real account has since answered `expires_in: 14400` —     │
      // │ FOUR HOURS — and `SIM_SYNC_INTERVAL` is 240 minutes, so that token   │
      // │ is stale by the next sweep and the flow would have to be walked      │
      // │ again before every single run. The premise was false; the conclusion │
      // │ went with it.                                                        │
      // │                                                                      │
      // │ The code challenge is a DEVICE-TRUST bootstrap, so clearing it once  │
      // │ should let plain `/Auth/authenticate` through from then on — which   │
      // │ is exactly what `password` mode does on every `openSession()`.       │
      // │ SHOULD, not will: whether Phenix carries that trust in something a   │
      // │ cookie-less client keeps is unobserved. Storing the password makes   │
      // │ the next "Test" answer that question in ten seconds, instead of the  │
      // │ token quietly expiring four hours later and looking like an outage.  │
      // └──────────────────────────────────────────────────────────────────────┘
      if (account.authMode !== 'password') {
        await updateAccount(id, { authMode: 'password' });
      }
      const saved = await setCredential(
        id,
        { authMode: 'password', username: input.username, password: input.password },
        { partnerRef: result.partnerRef },
      );
      res.json({
        success: true,
        data: { status: 'authenticated' as const, tokenExpiresAt: result.expiresAt, account: saved },
      });
      // A refused code — HTTP 400, 401 or 403 from Phenix — throws AUTH_FAILED,
      // which `toHttp` maps to a 400. It used to fall through as "Internal
      // server error", telling an operator who mistyped six digits that the
      // product had broken; and a 400 used to be PARTNER_ERROR, i.e. a 502
      // blaming the partner for the operator's own input.
    } catch (err) {
      next(toHttp(err));
    }
  },

  async testAccount(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'account id');
      res.json({ success: true, data: await testConnection(id) });
    } catch (err) {
      next(toHttp(err));
    }
  },

  /**
   * Runs a sweep now.
   *
   * Platform-guarded like the rest of `/accounts`, because a sweep spends a
   * partner's rate limit on an API that publishes none — a button any tenant
   * admin could press is a button that gets the whole installation throttled.
   */
  async syncAccount(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'account id');
      const row = await db<SimAccountRow>('sim_accounts').where({ id }).first();
      if (!row) throw new AppError(404, 'Account not found');
      res.json({ success: true, data: await syncAccount(row) });
    } catch (err) {
      next(toHttp(err));
    }
  },

  /** The sweep journal: why a balance is stale. */
  async listRuns(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'account id');
      const rows = await db('sim_sync_runs')
        .where({ account_id: id })
        .orderBy('started_at', 'desc')
        .limit(50);
      res.json({ success: true, data: rows });
    } catch (err) {
      next(err);
    }
  },

  async accountCaps(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: await capUsage(parseId(req.params.id, 'account id')) });
    } catch (err) {
      next(err);
    }
  },

  // ==========================================================================
  // Tenant: lines
  // ==========================================================================

  async summary(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      // God view (req.masterView, the platform admin on Default): every tenant's
      // lines summed, or one tenant's with ?tenantId= (ignored for a tenant).
      const q = parse(z.object({ tenantId: z.coerce.number().int().positive().max(2147483647).optional() }), req.query);
      res.json({
        success: true,
        data: await fleetSummary(scope(req), {
          tenantId: req.masterView ? q.tenantId : undefined,
          ...(await teamLines(req)),
        }),
      });
    } catch (err) {
      next(err);
    }
  },

  async listLines(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(
        z.object({
          accountId: z.coerce.number().int().positive().optional(),
          assignment: z.enum(['assigned', 'pool']).optional(),
          verdict: z.enum(['ok', 'low', 'unknown', 'terminated']).optional(),
          search: z.string().trim().max(120).optional(),
          tenantId: z.coerce.number().int().positive().max(2147483647).optional(),
          status: z.enum(SIM_LINE_STATUSES).optional(),
          withoutDevice: z.enum(['true', 'false']).transform((v) => v === 'true').optional(),
          onBackup4g: z.enum(['true', 'false']).transform((v) => v === 'true').optional(),
          limit: z.coerce.number().int().min(1).max(5000).optional(),
          deviceId: z.coerce.number().int().positive().max(2147483647).optional(),
          siteId: z.coerce.number().int().positive().max(2147483647).optional(),
        }),
        req.query,
      );
      // Team scope (084/087): a line hangs off its router, else its site; a
      // line attached to neither is covered by the ungrouped grant. In SQL,
      // before the limit (teamScope.service `visibleSimLineIdsQuery`).
      const lines = await listLines(scope(req), { ...q, lineIdsIn: await simLineListScope(req) });
      const accessFor = await accessOf(req, 'simLine');
      res.json({ success: true, data: lines.map((l) => ({ ...l, access: accessFor(l.id) })) });
    } catch (err) {
      next(err);
    }
  },

  /** A router's SIM block: the card the bench read, the lines linked to it. */
  async deviceSim(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      // Beyond an `integer` id nothing exists; a 404, not PostgreSQL's 22003.
      const view = deviceId > 2147483647 ? null : await deviceSimView(scope(req), deviceId);
      if (!view) throw new AppError(404, 'Device not found');
      res.json({ success: true, data: view });
    } catch (err) {
      next(err);
    }
  },

  async getLine(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const line = await getLine(scope(req), parseId(req.params.id, 'line id'));
      // 404, never 403: a 403 confirms the id exists, which on a serial primary
      // key is an enumeration oracle over another customer's SIM inventory.
      if (!line) throw new AppError(404, 'Line not found');
      res.json({ success: true, data: { ...line, access: await accessOfOne(req, 'simLine', Number(line.id)) } });
    } catch (err) {
      next(err);
    }
  },

  async getLineHistory(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'line id');
      const { days } = parse(
        z.object({ days: z.coerce.number().int().min(1).max(730).optional() }),
        req.query,
      );
      res.json({ success: true, data: await getLineHistory(scope(req), id, days ?? 90) });
    } catch (err) {
      next(err);
    }
  },

  /** What the partner itself says was bought on this line. Read from our store,
   *  filled by the sweep — never a live partner call. */
  async listPartnerRecharges(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'line id');
      res.json({ success: true, data: await listPartnerRecharges(scope(req), id) });
    } catch (err) {
      next(toHttp(err));
    }
  },

  /** The partner's volume catalogue for this line — a LIVE partner read, cached
   *  briefly. Buys nothing. */
  async rechargeOffers(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'line id');
      res.json({ success: true, data: await fetchRechargeOffers(scope(req), id) });
    } catch (err) {
      next(toHttp(err));
    }
  },

  async updateLine(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'line id');
      const patch = parse(simLineUpdateSchema, req.body);
      res.json({ success: true, data: await updateLine(scope(req), id, patch) });
    } catch (err) {
      next(toHttp(err));
    }
  },

  // ==========================================================================
  // Tenant: top-ups
  // ==========================================================================

  async listRecharges(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(
        z.object({
          status: z
            .string()
            .optional()
            .transform((s) => (s ? s.split(',').map((v) => v.trim()) : undefined))
            .pipe(z.array(z.enum(SIM_RECHARGE_STATUSES)).optional()),
          simId: z.coerce.number().int().positive().optional(),
          limit: z.coerce.number().int().min(1).max(2000).optional(),
        }),
        req.query,
      );
      const data = await listRecharges(scope(req), {
        status: q.status as SimRechargeStatus[] | undefined,
        simId: q.simId,
        limit: q.limit,
        ...(await teamLines(req)),
      });
      // A top-up is written through its line: the line's level is the row's.
      const accessFor = await accessOf(req, 'simLine');
      res.json({ success: true, data: data.map((r) => ({ ...r, access: accessFor(r.simId) })) });
    } catch (err) {
      next(err);
    }
  },

  async getRechargeById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const row = await getRecharge(scope(req), parseId(req.params.id, 'top-up id'));
      if (!row) throw new AppError(404, 'Top-up not found');
      const lineAccess = row.simId === null || row.simId === undefined ? 'ro' : await accessOfOne(req, 'simLine', Number(row.simId));
      res.json({ success: true, data: { ...row, access: req.session.role === 'admin' ? 'rw' : lineAccess } });
    } catch (err) {
      next(err);
    }
  },

  async proposeRecharge(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const input = parse(simManualRechargeSchema, req.body);
      const data = await proposeManual(scope(req), input, actor(req));
      res.status(201).json({ success: true, data });
    } catch (err) {
      next(toHttp(err));
    }
  },

  async approveRecharge(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'top-up id');
      const { note } = parse(simRechargeDecisionSchema, req.body ?? {});
      res.json({ success: true, data: await approve(scope(req), id, actor(req), note ?? null) });
    } catch (err) {
      next(toHttp(err));
    }
  },

  async rejectRecharge(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'top-up id');
      const { note } = parse(simRechargeDecisionSchema, req.body ?? {});
      res.json({ success: true, data: await reject(scope(req), id, actor(req), note ?? null) });
    } catch (err) {
      next(toHttp(err));
    }
  },

  /** Records a top-up bought on the partner's portal. The normal terminal
   *  state today, and never refused by a cap — see `recharge.service`. */
  async recordRecharge(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'top-up id');
      const input = parse(simRechargeCompletionSchema, req.body ?? {});
      res.json({ success: true, data: await recordCompletion(scope(req), id, actor(req), input) });
    } catch (err) {
      next(toHttp(err));
    }
  },

  /**
   * Fills in the cost of a top-up that was already recorded.
   *
   * Not a state change: the row stays exactly as billable as it was. It exists
   * because the partner's invoice usually arrives after the purchase, and
   * without it `assertExecutionAllowed`'s own error message — "record their
   * cost first" — named an operation the product did not have.
   */
  async priceRecharge(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'top-up id');
      const input = parse(simRechargeCompletionSchema, req.body ?? {});
      res.json({ success: true, data: await priceRecharge(scope(req), id, actor(req), input) });
    } catch (err) {
      next(toHttp(err));
    }
  },

  /**
   * Asks ObliWAN to buy it. Answers 501 for every platform today.
   *
   * The route exists so the refusal is a documented, testable answer with a
   * reason an operator can read, rather than a missing endpoint that a future
   * client discovers as a 404.
   */
  async executeRecharge(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req.params.id, 'top-up id');
      res.json({ success: true, data: await execute(scope(req), id, actor(req)) });
    } catch (err) {
      next(toHttp(err));
    }
  },

  // ==========================================================================
  // Tenant: re-invoicing report
  // ==========================================================================

  async report(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { from, to } = parseWindow(req);
      res.json({ success: true, data: await rechargeReport(scope(req), from, to, await teamLines(req)) });
    } catch (err) {
      next(err);
    }
  },

  async reportCsv(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { from, to } = parseWindow(req);
      const report = await rechargeReport(scope(req), from, to, await teamLines(req));
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="sim-recharges-${from.toISOString().slice(0, 10)}.csv"`,
      );
      // A BOM, so Excel opens a UTF-8 CSV with accented site names intact
      // instead of as mojibake somebody then "fixes" by hand in an invoice.
      res.send('﻿' + reportToCsv(report));
    } catch (err) {
      next(err);
    }
  },
};

/**
 * The reporting window.
 *
 * Defaults to the current calendar month, which is the period somebody
 * re-invoices. Both bounds are required to be real dates; an unparseable one is
 * a 400 rather than silently becoming "the epoch", which would export every
 * top-up ever made under a heading that says one month.
 */
function parseWindow(req: Request): { from: Date; to: Date } {
  const q = parse(
    z.object({
      from: z.string().datetime({ offset: true }).optional(),
      to: z.string().datetime({ offset: true }).optional(),
    }),
    req.query,
  );
  const now = new Date();
  const from = q.from
    ? new Date(q.from)
    : new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
  const to = q.to ? new Date(q.to) : now;
  // `z.string().datetime({offset:true})` accepts an offset Postgres cannot
  // parse into a real instant (`+99:00`), which `new Date()` turns into an
  // Invalid Date — and a query built on one is a 500, not the 400 the comment
  // above promised. Checked rather than assumed.
  if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime())) {
    throw new AppError(400, 'The reporting period is not a pair of valid instants');
  }
  if (from > to) throw new AppError(400, 'The start of the period is after its end');
  return { from, to };
}
