import type { Request, Response, NextFunction } from 'express';
import { AppError } from '../middleware/errorHandler';
import { AllocationError } from '../services/allocation';
import {
  TenantReconcileRefused,
  assertTenantMayReconcile,
  reconcileTenant,
  rereadForTenant,
  tenantReconcileView,
  type TenantReconcileView,
} from '../services/allocation/reconcile.service';
import { siteListScope, ungroupedLevel } from '../services/teamScope.service';
import {
  ReconcileAttachError,
  applyAttach,
  previewAttach,
  type AttachActor,
} from '../services/fleet/reconcileAttach.service';
import { isIanaTimeZone, orphansImportXlsx } from '../services/fleet/siteImport.service';
import { XLSX_CONTENT_TYPE } from '../services/fleet/xlsx';
import { logger } from '../utils/logger';
import type { ReconcileAttachApplyInput, ReconcileAttachPreviewInput } from '../validators/reconcile.schema';

/** One CHR re-read per tenant per minute: a read capability must not let a
 *  loop keep a full /ppp/secret read running on the concentrator every tenant
 *  shares. In memory, per process. */
const REREAD_COOLDOWN_MS = 60_000;
const lastReread = new Map<number, number>();

/** One bulk attach at a time per tenant (the screen sends its slices one
 *  after the other). In memory, per process: correctness does not rest on it
 *  — every write re-checks under its own locks — it keeps a double click from
 *  dialling the same routers twice. */
const attaching = new Set<number>();

function attachActor(req: Request): AttachActor {
  const userId = req.session?.userId;
  if (typeof userId !== 'number') throw new AppError(401, 'Authentication required');
  return { userId, username: req.session.username ?? null, platformAdmin: req.session.role === 'admin' };
}

/**
 * The CHR <-> sites reconciliation of the caller's OWN tenant — HTTP layer
 * (RECONCILE_READ, reconcile.routes.ts; the bulk attach of its online routers
 * is a platform administrator's: requireRole('admin'), DEVICE_WRITE and
 * CREDENTIAL_MANAGE declared beside it).
 *
 * The tenant is ALWAYS `req.tenantId` (the session's, via `requireTenant`):
 * no route here takes a tenant, a concentrator or an account from the
 * request. The bulk attach takes SITE ids, and the service looks each one up
 * among the session tenant's sites only — another tenant's id answers like an
 * id that does not exist. The platform admin's screen over ANY tenant is
 * allocation.controller.ts, and nothing here reaches it.
 *
 * ┌─ WHAT A REFUSAL MAY SAY ─────────────────────────────────────────────────┐
 * │ The allocation engine's own sentences are written for a platform admin:  │
 * │ they quote the stored template and its parse error, name a concentrator  │
 * │ by id, and an AllocationError may carry a `holder` (another tenant's     │
 * │ ids). None of that is relayed. A refusal here is one of a few fixed      │
 * │ sentences plus the reason CODE, and a CHR that cannot be read answers    │
 * │ 502 without the transport's message (it names the CHR's address). The   │
 * │ detail goes to the log. Nothing lands in the 401/403 band beyond the     │
 * │ guards themselves (and the attach service's PLATFORM_ADMIN_ONLY 403, the │
 * │ same verdict as its route's role guard): the client logs the operator   │
 * │ out on a 401.                                                            │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

const NO_POLICY =
  'No address allocation policy is set for this workspace, so no concentrator account can be recognised ' +
  'as its own. A platform administrator sets the policy first.';
const NOT_EVALUABLE =
  "This workspace's login rule cannot be evaluated right now, so no concentrator account can be " +
  'recognised as its own. A platform administrator can see why.';
const UNREADABLE =
  'The concentrator could not be read just now. Nothing was recorded: the comparison still shows its last read.';

function requireTenantId(req: Request): number {
  const id = req.tenantId;
  // requireTenant has run; this is the fail-closed guard for a mount outside it.
  if (typeof id !== 'number' || !Number.isInteger(id) || id <= 0) throw new AppError(403, 'No tenant granted for this account');
  return id;
}

/** A refusal as a tenant user may read it (see the box above). */
function refuse(err: unknown, res: Response, next: NextFunction): void {
  if (err instanceof ReconcileAttachError) {
    res.status(err.httpStatus).json({ success: false, error: err.message, reason: err.reason });
    return;
  }
  if (err instanceof TenantReconcileRefused) {
    res.status(409).json({ success: false, error: err.message, reason: err.reason });
    return;
  }
  if (err instanceof AllocationError) {
    logger.info({ reason: err.reason, message: err.message }, 'Tenant reconciliation refused');
    // Never 403/401 (the engine's own statuses are 404/409/400 for these).
    const status = err.httpStatus === 401 || err.httpStatus === 403 ? 409 : err.httpStatus;
    res.status(status).json({ success: false, error: err.reason === 'NO_POLICY' ? NO_POLICY : NOT_EVALUABLE, reason: err.reason });
    return;
  }
  next(err);
}

function timeZoneOf(req: Request): string {
  const tzRaw = req.query.tz;
  if (tzRaw !== undefined && (typeof tzRaw !== 'string' || !isIanaTimeZone(tzRaw))) {
    throw new AppError(400, 'tz must be an IANA time zone name (e.g. Europe/Paris)');
  }
  return typeof tzRaw === 'string' ? tzRaw : 'Europe/Paris';
}

/**
 * Team scope (migration 087) of the redacted report: site rows only for the
 * sites the caller's teams cover; the accounts that name no site (orphans,
 * off-pattern) belong to the ungrouped bucket and need the ungrouped grant.
 * A platform admin reads it whole. Counts are recomputed over what is kept.
 */
async function teamView(req: Request, view: TenantReconcileView): Promise<TenantReconcileView> {
  const sites = await siteListScope(req);
  if (sites === null) return view;
  const keep = new Set(sites);
  const userId = req.session?.userId;
  const orphansOk = !!userId && (await ungroupedLevel(userId, req.tenantId)) !== null;
  const near = <T extends { siteId: number }>(xs: T[]): T[] => xs.filter((x) => keep.has(x.siteId));
  const matched = view.matched.filter((m) => keep.has(m.siteId));
  const siteOnly = view.siteOnly.filter((s) => keep.has(s.siteId));
  const orphans = orphansOk ? view.orphans.map((o) => ({ ...o, nearSites: near(o.nearSites) })) : [];
  const offPattern = orphansOk ? view.offPattern.map((o) => ({ ...o, nearSites: near(o.nearSites) })) : [];
  return {
    ...view,
    matched,
    siteOnly,
    orphans,
    offPattern,
    counts: {
      ...view.counts,
      sites: keep.size,
      matched: matched.length,
      orphans: orphans.length,
      orphansOnline: orphans.filter((o) => o.account.session.up).length,
      siteOnly: siteOnly.length,
      siteOnlyNew: siteOnly.filter((s) => s.kind === 'new').length,
      siteOnlySuspect: siteOnly.filter((s) => s.kind === 'suspect').length,
      offPattern: offPattern.length,
    },
  };
}

export const reconcileController = {
  /** GET /reconcile — the redacted report (reconcile.service `redactReport`);
   *  409 TEMPLATE_NAMES_NO_TENANT when the login template names no tenant.
   *  Reads what was recorded; dials nothing. */
  async view(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: await teamView(req, await tenantReconcileView(requireTenantId(req))) });
    } catch (err) {
      refuse(err, res, next);
    }
  },

  /** POST /reconcile/reread — re-read the /ppp/secret of the CHR(s) this
   *  tenant's reconciliation reads (the allocator's own read: nothing is
   *  written to the router, the passwords never cross the wire), then answer
   *  the fresh redacted report. Refused before any dial under a template that
   *  names no tenant. */
  async reread(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const tenantId = requireTenantId(req);
      const last = lastReread.get(tenantId) ?? 0;
      if (Date.now() - last < REREAD_COOLDOWN_MS) {
        throw new AppError(429, 'Le concentrateur a été relu il y a moins d\'une minute : réessayez dans un instant.');
      }
      lastReread.set(tenantId, Date.now());
      try {
        await rereadForTenant(tenantId);
      } catch (err) {
        if (err instanceof TenantReconcileRefused) throw err;
        if (err instanceof AllocationError && !['CONCENTRATOR_NOT_FOUND', 'CONCENTRATOR_INVALID'].includes(err.reason)) {
          throw err;
        }
        logger.warn({ err, tenantId }, 'Tenant reconciliation: /ppp/secret re-read failed');
        throw new AppError(502, UNREADABLE);
      }
      res.json({ success: true, data: await teamView(req, await tenantReconcileView(tenantId)) });
    } catch (err) {
      refuse(err, res, next);
    }
  },

  /** GET /reconcile/orphans.xlsx[?tz=] — this tenant's orphans as a workbook
   *  the site import reads back as it is (siteImport.service
   *  `orphansImportXlsx`): code, name, country — no account name, no
   *  address. Same refusals as the view. */
  async orphansXlsx(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const tenantId = requireTenantId(req);
      const timeZone = timeZoneOf(req);
      // Team scope (087): orphans name no site — the ungrouped bucket.
      if (req.session?.role !== 'admin'
        && (!req.session?.userId || (await ungroupedLevel(req.session.userId, tenantId)) === null)) {
        throw new AppError(403, 'Your teams do not cover the devices filed under no group (an ungrouped grant is needed)');
      }
      const report = await reconcileTenant(tenantId);
      assertTenantMayReconcile(report);
      const { buffer, fileName } = orphansImportXlsx(report, timeZone);
      res.setHeader('Content-Type', XLSX_CONTENT_TYPE);
      res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
      res.setHeader('Cache-Control', 'no-store');
      res.send(buffer);
    } catch (err) {
      refuse(err, res, next);
    }
  },

  /** POST /reconcile/attach-devices/preview — the dry run of the bulk attach
   *  (fleet/reconcileAttach.service.ts): per site, what would happen and why.
   *  Dials nothing, writes nothing, answers no password. Platform
   *  administrators only (the route, and the service again); the view's
   *  refusal of a template naming no tenant does not apply to them. */
  async attachPreview(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const tenantId = requireTenantId(req);
      const body = req.body as ReconcileAttachPreviewInput;
      const actor = attachActor(req);
      res.setHeader('Cache-Control', 'no-store');
      res.json({
        success: true,
        data: await previewAttach(tenantId, body.siteIds ?? null, body.credentials ?? null, actor, {
          openManagementAccess: body.openManagementAccess,
          applyCompliance: body.applyCompliance,
        }),
      });
    } catch (err) {
      refuse(err, res, next);
    }
  },

  /** POST /reconcile/attach-devices — prove each selected online router over
   *  SSH (reads only), then create it active and managed with its SSH
   *  credential, then (by default) queue its management_access job and
   *  promise its legacy_compliance after it — which needs `confirmNoDeadman`
   *  (422 DEGRADED_UNCONFIRMED otherwise, before any dial). At most
   *  RECONCILE_ATTACH_APPLY_MAX_SITES sites per call; a proof that fails
   *  creates nothing, and a follow-up refused never fails the attach. */
  async attachApply(req: Request, res: Response, next: NextFunction): Promise<void> {
    // Released only by the request that took it.
    let held: number | null = null;
    try {
      const tenantId = requireTenantId(req);
      const body = req.body as ReconcileAttachApplyInput;
      const actor = attachActor(req);
      if (attaching.has(tenantId)) {
        throw new AppError(409, 'Un rattachement est déjà en cours pour cet espace : attendez qu\'il se termine.');
      }
      attaching.add(tenantId);
      held = tenantId;
      res.setHeader('Cache-Control', 'no-store');
      res.json({
        success: true,
        data: await applyAttach(tenantId, body.siteIds, body.credentials ?? null, actor, {
          openManagementAccess: body.openManagementAccess,
          applyCompliance: body.applyCompliance,
          confirmNoDeadman: body.confirmNoDeadman,
        }, { learning: body.learning }),
      });
    } catch (err) {
      refuse(err, res, next);
    } finally {
      if (held !== null) attaching.delete(held);
    }
  },
};
