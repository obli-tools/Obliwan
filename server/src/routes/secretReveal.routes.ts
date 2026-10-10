import { Router, type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import { CAPABILITIES, SIM_LINE_SECRET_FIELDS, isMasterTenant } from '@obliwan/shared';
import { requireCapability } from '../middleware/rbac';
import { secretRevealLimiter } from '../middleware/rateLimiter';
import { validate } from '../middleware/validate';
import { AppError } from '../middleware/errorHandler';
import { godViewBodyTenant, godViewFromParam } from '../utils/globalView';
import {
  MASTER_TENANT_REFUSAL,
  SNMP_SECRET_FIELDS,
  TRANSPORT_SECRET_FIELDS,
  revealLearnedSecret,
  revealSimLineSecret,
  revealSnmpCredential,
  revealTransportSecret,
  revealVariableSecret,
  type RevealActor,
} from '../services/secrets/reveal.service';

/**
 * Revealing a stored secret in clear — the routes of `SECRET_READ`.
 *
 * Mounted under `tenantRouter` WITHOUT a prefix (routes/index.ts), so
 * `requireAuth` and `requireTenant` have already run, and each route below
 * carries its full path:
 *
 *   POST /variables/reveal                         { scope, scopeId?, key }
 *   POST /devices/:id/transports/:transport/reveal { field?: 'secret' | 'privateKey' }
 *   POST /snmp/credentials/:id/reveal              { field?: 'community' | 'authKey' | 'privKey' }
 *   POST /sim/lines/:id/reveal                     { field: 'puk1' | 'puk2' | 'radiusPassword' | 'rio' }
 *
 * Every one answers `{ success: true, data: { value } }` — ONE field per call.
 *
 * No `router.use()` in this file, on purpose: a router mounted without a
 * prefix sees EVERY tenant-scoped request on its way to the routers after it,
 * so a router-level middleware here would run in front of the whole API. Each
 * guard is declared on its route instead.
 *
 * ┌─ THE GUARDS, IN ORDER, AND WHY EACH ONE IS THERE ────────────────────────┐
 * │ 0. `noStore` — first, so the refusals below carry it too.                 │
 * │ 1. `requireCapability(SECRET_READ)` — a platform admin passes; anybody    │
 * │    else must hold it for the CURRENT tenant (the tenant admin role, a     │
 * │    pinned team grant or an Obligate assertion). Who holds it is decided   │
 * │    in permission.service.ts, not here. The SNMP route ALSO demands        │
 * │    CREDENTIAL_MANAGE: the whole `snmp_credentials` table, its listing     │
 * │    included, is CREDENTIAL_MANAGE (snmp.routes.ts), and SECRET_READ no    │
 * │    longer implies it (shared/src/capabilities.ts).                        │
 * │ 2. `requireSecureTransport` — the answer is a plaintext, so it is not     │
 * │    sent over a hop the server sees as cleartext (below).                  │
 * │ 3. `secretRevealLimiter` — 30 / 5 min per user, AFTER the capability and  │
 * │    transport checks, so a refused caller spends nothing.                  │
 * │ 4. The body schema — 400 before any read.                                 │
 * │ 5. PLATFORM administrators only (`requireRole('admin')` semantics, read   │
 * │    from the session role that `requireAuth` re-reads from the database)   │
 * │    for INSTANCE variables — shared by every tenant, the same rule as      │
 * │    their writes in variables.routes.ts — and for anything in the MASTER   │
 * │    tenant, which holds the shared infrastructure (the concentrator's      │
 * │    credential controls every customer's tunnel) and whose membership      │
 * │    alone confers nothing. The service checks both a                       │
 * │    second time, before reading any row.                                   │
 * │                                                                          │
 * │ The variable, transport and SNMP routes act in ONE tenant, never across   │
 * │ `masterView`: from the god view (Default) they first follow the object    │
 * │ into its own tenant (`godViewBodyTenant` / `godViewFromParam`: the site,  │
 * │ router or SNMP credential named), so the audit row lands in THAT tenant's │
 * │ ledger with the god-view origin, exactly as if the platform admin had     │
 * │ switched to it.                                                           │
 * │                                                                          │
 * │ The SIM line route is the ONE exception, and it is deliberate: it ALSO   │
 * │ demands SIM_READ, and it passes `masterView` through (honoured only for a │
 * │ platform administrator, re-checked by the service) so the master view    │
 * │ reveals exactly the lines it lists — the unassigned pool included, which  │
 * │ belongs to no tenant one could switch to. Its audit row lands in the      │
 * │ LINE's tenant whatever the caller's view, and in the operating tenant     │
 * │ only for a pooled line, which has none (`revealSimLineSecret`).           │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * POST and not GET, deliberately: a GET is the verb proxies, browsers and
 * history lists feel free to cache, prefetch and replay. Every response of
 * these routes — refusals included — carries `Cache-Control: no-store` and
 * `Pragma: no-cache`.
 *
 * The plaintext reaches the response body and nothing else: the service never
 * logs it, never puts it in an error message, and the `audit_log` row it
 * writes BEFORE answering carries who / what / when / from where, never the
 * value (reveal.service.ts). Nothing in the request names a secret either —
 * a body carries a scope, an id, a variable name or a field name.
 */
const router = Router();

function noStore(_req: Request, res: Response, next: NextFunction): void {
  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');
  next();
}

/** The opt-out of `requireSecureTransport`, read on every request. */
export const ALLOW_HTTP_ENV = 'SECRET_REVEAL_ALLOW_HTTP';

/**
 * A plaintext is answered only over HTTPS, as the server sees it.
 *
 * `req.secure` is true when the connection itself is TLS or when the trusted
 * proxy hop (`trust proxy` = 1: nginx, which forwards the X-Forwarded-Proto
 * of the TLS terminator in front of it — client/nginx.conf) says `https`.
 * Behind that terminator this passes; an operator reaching the UI over plain
 * HTTP gets a refusal that names the fix instead of a password written in
 * clear on the network.
 *
 * What it is NOT: authentication. X-Forwarded-Proto travels from the client
 * when nothing in front of nginx sets it, so a caller who already holds a
 * session can claim `https` over plain HTTP. It keeps an honest browser from
 * receiving a secret over a cleartext hop; protecting the session cookie
 * itself is `FORCE_HTTPS=true` (app.ts), a deployment setting.
 *
 * `SECRET_REVEAL_ALLOW_HTTP=true` lifts it — for local development over
 * http://localhost, or for an installation that knowingly accepts the risk.
 * Read per request, not at boot, so it never needs a restart to be honest
 * about what it does.
 */
function requireSecureTransport(req: Request, _res: Response, next: NextFunction): void {
  if (req.secure || process.env[ALLOW_HTTP_ENV] === 'true') {
    next();
    return;
  }
  next(new AppError(
    403,
    'Secrets are revealed over HTTPS only, and this request reached the server over plain HTTP '
      + '(no X-Forwarded-Proto: https from the reverse proxy). Open ObliWAN through its TLS address; '
      + `for local development only, set ${ALLOW_HTTP_ENV}=true on the server.`,
  ));
}

const variableBody = z.object({
  scope: z.string().min(1).max(20),
  scopeId: z.number().int().positive().nullable().optional(),
  key: z.string().min(1).max(120),
}).strict();

const transportBody = z.object({
  field: z.enum(TRANSPORT_SECRET_FIELDS).optional(),
}).strict();

const snmpBody = z.object({
  field: z.enum(SNMP_SECRET_FIELDS).optional(),
}).strict();

/** The actor, from the SESSION only. */
function actorOf(req: Request): RevealActor {
  return {
    userId: req.session.userId as number,
    username: req.session.username ?? null,
    platformAdmin: req.session.role === 'admin',
    ip: req.ip ?? null,
  };
}

/** Fail closed if this router is ever mounted outside `tenantRouter`. */
function tenantOf(req: Request): number {
  if (!req.tenantId) throw new AppError(403, 'No tenant granted for this account');
  return req.tenantId;
}

function send(res: Response, value: string): void {
  res.json({ success: true, data: { value } });
}

/**
 * `requireRole('admin')`, but only where a reveal reaches past one customer:
 * an INSTANCE variable, or anything in the MASTER tenant. Runs after
 * `validate`, which is what makes `body.scope` readable.
 */
function sharedNeedsPlatformAdmin(req: Request, _res: Response, next: NextFunction): void {
  if (req.session.role === 'admin') {
    next();
    return;
  }
  if ((req.body as { scope?: unknown }).scope === 'instance') {
    next(new AppError(403, 'Instance variables are revealed by platform administrators only.'));
    return;
  }
  if (isMasterTenant(req.tenantId)) {
    next(new AppError(403, MASTER_TENANT_REFUSAL));
    return;
  }
  next();
}

/**
 * God view: a site, device or group variable is revealed in the tenant of the
 * row it names (the site form opened from Default on a customer's site).
 * After `sharedNeedsPlatformAdmin`, which judges the session's own position.
 */
const VARIABLE_SCOPE_TABLES = { site: 'sites', device: 'devices', group: 'device_groups' } as const;
function followVariableScope(req: Request, res: Response, next: NextFunction): void {
  const scope = (req.body as { scope?: string }).scope;
  const table = scope && Object.hasOwn(VARIABLE_SCOPE_TABLES, scope)
    ? VARIABLE_SCOPE_TABLES[scope as keyof typeof VARIABLE_SCOPE_TABLES]
    : null;
  if (!table) {
    next();
    return;
  }
  godViewBodyTenant(table, 'scopeId')(req, res, next);
}

router.post(
  '/variables/reveal',
  noStore,
  requireCapability(CAPABILITIES.SECRET_READ),
  requireSecureTransport,
  secretRevealLimiter,
  validate(variableBody),
  sharedNeedsPlatformAdmin,
  followVariableScope,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const body = req.body as z.infer<typeof variableBody>;
      const value = await revealVariableSecret({
        tenantId: tenantOf(req),
        scope: body.scope,
        scopeId: body.scopeId ?? null,
        key: body.key,
        actor: actorOf(req),
      });
      send(res, value);
    } catch (err) {
      next(err);
    }
  },
);

router.post(
  '/devices/:id/transports/:transport/reveal',
  noStore,
  requireCapability(CAPABILITIES.SECRET_READ),
  requireSecureTransport,
  secretRevealLimiter,
  validate(transportBody),
  // God view: the router's own tenant, as on its page.
  godViewFromParam('devices', 'id'),
  sharedNeedsPlatformAdmin,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const body = req.body as z.infer<typeof transportBody>;
      const value = await revealTransportSecret({
        tenantId: tenantOf(req),
        deviceId: req.params.id,
        transport: req.params.transport,
        field: body.field,
        actor: actorOf(req),
      });
      send(res, value);
    } catch (err) {
      next(err);
    }
  },
);

router.post(
  '/snmp/credentials/:id/reveal',
  noStore,
  requireCapability(CAPABILITIES.SECRET_READ),
  // `snmp_credentials` is CREDENTIAL_MANAGE throughout, listing included
  // (snmp.routes.ts): revealing one of its rows is touching it.
  requireCapability(CAPABILITIES.CREDENTIAL_MANAGE),
  requireSecureTransport,
  secretRevealLimiter,
  validate(snmpBody),
  // God view: the credential's own tenant, as on the Default credentials
  // list — the audit row lands there, marked with the god-view origin.
  godViewFromParam('snmp_credentials', 'id'),
  sharedNeedsPlatformAdmin,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const body = req.body as z.infer<typeof snmpBody>;
      const value = await revealSnmpCredential({
        tenantId: tenantOf(req),
        credentialId: req.params.id,
        field: body.field,
        actor: actorOf(req),
      });
      send(res, value);
    } catch (err) {
      next(err);
    }
  },
);

/**
 * A secret a LEARNING capture vaulted (`learned_secrets`, migration 089),
 * shown on the learning page. Same guards as a variable; the god view follows
 * the row into its own tenant, so the audit row lands there.
 */
router.post(
  '/learning/secrets/:id/reveal',
  noStore,
  requireCapability(CAPABILITIES.SECRET_READ),
  requireSecureTransport,
  secretRevealLimiter,
  validate(z.object({}).strict()),
  godViewFromParam('learned_secrets', 'id'),
  sharedNeedsPlatformAdmin,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const value = await revealLearnedSecret({
        tenantId: tenantOf(req),
        secretId: req.params.id,
        actor: actorOf(req),
      });
      send(res, value);
    } catch (err) {
      next(err);
    }
  },
);

const simLineBody = z.object({
  field: z.enum(SIM_LINE_SECRET_FIELDS),
}).strict();

/**
 * A mobile line's PUK1, PUK2, RADIUS password (migration 077) or RIO (079). SECRET_READ
 * AND SIM_READ: the line itself — its number, its customer — sits behind
 * SIM_READ (sim.routes.ts), and revealing one of its secrets is reading it.
 * The field is REQUIRED: there is no "default secret" of a SIM.
 *
 * `masterView` is passed through so the master view reveals what it lists
 * (the pool included); the service re-checks the platform role before using it.
 */
router.post(
  '/sim/lines/:id/reveal',
  noStore,
  requireCapability(CAPABILITIES.SECRET_READ),
  requireCapability(CAPABILITIES.SIM_READ),
  requireSecureTransport,
  secretRevealLimiter,
  validate(simLineBody),
  sharedNeedsPlatformAdmin,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const body = req.body as z.infer<typeof simLineBody>;
      const value = await revealSimLineSecret({
        tenantId: tenantOf(req),
        masterView: req.masterView === true,
        lineId: req.params.id,
        field: body.field,
        actor: actorOf(req),
      });
      send(res, value);
    } catch (err) {
      next(err);
    }
  },
);

export default router;
