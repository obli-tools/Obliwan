import type { Request, Response, NextFunction } from 'express';
import { AppError } from '../middleware/errorHandler';
import { VaultError } from '../services/secretVault.service';
import {
  AllocationError,
  PG_INT_MAX,
  createPool,
  deletePool,
  getInstanceDomain,
  getPolicy,
  getSeedStatus,
  getSiteProvisioning,
  listAllocations,
  listConcentrators,
  listPools,
  previewAllocation,
  previewNextAllocations,
  releaseAllocation,
  renamePool,
  setInstanceDomain,
  siteExists,
  takeAllocationLock,
  tenantExists,
  upsertPolicy,
  type SiteProvisioningView,
} from '../services/allocation';
import { db } from '../db';
import { appendAudit } from '../services/attestation/auditLog.service';
import {
  createSiteForTenant,
  reconcileTenant,
  reconcileToXlsx,
  rereadConcentratorInventory,
} from '../services/allocation/reconcile.service';
import { isIanaTimeZone, orphansImportXlsx } from '../services/fleet/siteImport.service';
import { XLSX_CONTENT_TYPE } from '../services/fleet/xlsx';
import { logger } from '../utils/logger';

/**
 * Per-tenant address allocation — HTTP layer. Every route is platform-admin
 * only (requireRole('admin') in allocation.routes.ts), which is why the tenant
 * comes from the PATH here and not from `req.tenantId`: the infra operator
 * sets the numbering of every customer from one screen.
 *
 * Nothing in this file returns a PPP password, masked or not. The only reader
 * of the password is `revealPppCredential`, which is server-side and appears
 * in no controller.
 */

/** Bounded to PostgreSQL's `integer`: a larger id would reach the database and
 *  come back as an unmapped 22003, i.e. a bare 500 for a typo in a URL. */
function parseId(raw: string, what: string): number {
  const id = /^\d{1,10}$/.test(raw) ? Number(raw) : NaN;
  if (!Number.isInteger(id) || id <= 0 || id > PG_INT_MAX) throw new AppError(400, `Invalid ${what}`);
  return id;
}

function body(req: Request): Record<string, unknown> {
  const b: unknown = req.body;
  if (typeof b !== 'object' || b === null || Array.isArray(b)) {
    throw new AppError(400, 'The request body must be a JSON object');
  }
  return b as Record<string, unknown>;
}

/**
 * Turn the allocation module's refusals into HTTP. An AllocationError never
 * reaches `errorHandler` raw — it would land in the generic 500 branch — and
 * answers `{ success: false, error, reason, details?, holder? }`: `reason` is
 * the stable code a screen can branch on, `holder` says who has the address or
 * login (this API is platform-admin only, so ids may be shown). A VaultError
 * means the server has no usable OBLIWAN_ENCRYPTION_KEY, which is a server
 * condition (503), not the caller's mistake.
 */
function forward(err: unknown, res: Response, next: NextFunction): void {
  if (err instanceof AllocationError) {
    res.status(err.httpStatus).json({
      success: false,
      error: err.message,
      reason: err.reason,
      ...(err.details ? { details: err.details } : {}),
      ...(err.holder ? { holder: err.holder } : {}),
    });
    return;
  }
  if (err instanceof VaultError) {
    next(new AppError(503, err.message));
    return;
  }
  next(err);
}

/**
 * The CONFIRMED release of an allocation the concentrator has already taken.
 *
 * `releaseAllocation` refuses a 'provisioned' row on purpose: the PPP secret is
 * live on the CHR, and the row is what keeps its login and its address from
 * being handed to another site. A platform administrator may still need the
 * row gone (a site created twice, a code typed wrong and already written), so
 * the refusal can be overruled — by naming the login being released, which the
 * screen shows and the operator confirms. A login that no longer matches (the
 * allocation was re-made since the screen read it) is refused rather than
 * releasing something nobody looked at.
 *
 * NEVER TOUCHES THE CHR: the secret stays declared there, with its login and
 * its address. The next allocation re-reads a CHR whose read is not fresh,
 * and the concentrator job refuses a login or an address the CHR already
 * holds — a clash is then a failed job, never an overwrite. Removing the
 * secret is a manual act on the concentrator. A router already prepared for
 * the site keeps what it was given. The release is written to `audit_log`.
 *
 * Under the allocation lock, like every other writer of `site_provisioning`.
 */
async function releaseProvisioned(
  req: Request,
  siteId: number,
  current: SiteProvisioningView,
  confirmLogin: string,
): Promise<SiteProvisioningView> {
  if (confirmLogin !== current.pppUsername) {
    throw new AppError(409, 'The confirmation does not name this allocation\'s PPP login: nothing was released.');
  }
  await db.transaction(async (trx) => {
    await takeAllocationLock(trx);
    const deleted = await trx('site_provisioning')
      .where({ site_id: siteId, tenant_id: current.tenantId, ppp_username: confirmLogin })
      .delete();
    if (deleted === 0) {
      throw new AppError(409, 'The allocation changed since it was shown: nothing was released. Reload and confirm again.');
    }
    await appendAudit(
      {
        tenantId: current.tenantId,
        actorType: 'user',
        actorId: req.session.userId ?? null,
        actorName: req.session.username ? req.session.username.slice(0, 128) : null,
        action: 'allocation.release_provisioned',
        entityType: 'site',
        entityId: siteId,
        before: {
          pppUsername: current.pppUsername,
          tunnelIp: current.tunnelIp,
          lanSubnet: current.lanSubnet,
          concentratorId: current.concentratorId,
          concentratorState: current.concentratorState,
          source: current.source,
        },
      },
      trx,
    );
  });
  logger.warn(
    {
      siteId,
      tenantId: current.tenantId,
      pppUsername: current.pppUsername,
      tunnelIp: current.tunnelIp,
      concentratorId: current.concentratorId,
      userId: req.session.userId ?? null,
    },
    'Provisioned site allocation released by confirmation; its PPP secret stays on the concentrator',
  );
  return current;
}

export const allocationController = {
  // ── Pools ──────────────────────────────────────────────────────────────

  /** GET /pools */
  async listPools(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: await listPools() });
    } catch (err) {
      forward(err, res, next);
    }
  },

  /** POST /pools — { name, cidr, purpose: 'tunnel' | 'lan' } */
  async createPool(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.status(201).json({ success: true, data: await createPool(body(req)) });
    } catch (err) {
      forward(err, res, next);
    }
  },

  /** PATCH /pools/:poolId — { name }. Block and purpose are immutable. */
  async renamePool(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const poolId = parseId(req.params.poolId, 'pool id');
      res.json({ success: true, data: await renamePool(poolId, body(req)) });
    } catch (err) {
      forward(err, res, next);
    }
  },

  /** DELETE /pools/:poolId — 409 POOL_IN_USE while a policy names it. */
  async deletePool(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      await deletePool(parseId(req.params.poolId, 'pool id'));
      res.json({ success: true });
    } catch (err) {
      forward(err, res, next);
    }
  },

  // ── Installation domain ────────────────────────────────────────────────

  /** GET /instance-domain — `data: { domain }`, '' when unset. */
  async getInstanceDomain(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: { domain: await getInstanceDomain() } });
    } catch (err) {
      forward(err, res, next);
    }
  },

  /** PUT /instance-domain — { domain } ('' clears it, refused while used). */
  async putInstanceDomain(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: { domain: await setInstanceDomain(body(req).domain) } });
    } catch (err) {
      forward(err, res, next);
    }
  },

  // ── Seed ───────────────────────────────────────────────────────────────

  /** GET /concentrators/:concentratorId/seed — `data: SeedStatus`; 404 for an
   *  unknown device, 400 for a device that is not a concentrator. */
  async getSeed(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: await getSeedStatus(parseId(req.params.concentratorId, 'concentrator id')) });
    } catch (err) {
      forward(err, res, next);
    }
  },

  // ── Policies ───────────────────────────────────────────────────────────

  /** GET /tenants/:tenantId/policy — `data: null` when the tenant has none. */
  async getPolicy(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const tenantId = parseId(req.params.tenantId, 'tenant id');
      if (!(await tenantExists(tenantId))) throw new AppError(404, 'Tenant not found');
      res.json({ success: true, data: await getPolicy(tenantId) });
    } catch (err) {
      forward(err, res, next);
    }
  },

  /** PUT /tenants/:tenantId/policy — create or replace. Validation lives in the
   *  service (`validatePolicyInput`), the same function that re-reads stored
   *  rows, so the API and the allocator cannot disagree on what is valid. */
  async putPolicy(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const tenantId = parseId(req.params.tenantId, 'tenant id');
      res.json({ success: true, data: await upsertPolicy(tenantId, body(req)) });
    } catch (err) {
      forward(err, res, next);
    }
  },

  /** GET /tenants/:tenantId/next?limit=N — the next N allocations of the
   *  tenant's not-yet-allocated sites, planned read-only. */
  async previewNext(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const tenantId = parseId(req.params.tenantId, 'tenant id');
      const raw = typeof req.query.limit === 'string' ? req.query.limit : '10';
      const limit = /^\d{1,4}$/.test(raw) ? Number(raw) : NaN;
      res.json({ success: true, data: await previewNextAllocations(tenantId, limit) });
    } catch (err) {
      forward(err, res, next);
    }
  },

  /** GET /tenants/:tenantId/sites — the tenant's allocated sites (no password). */
  async listTenantSites(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const tenantId = parseId(req.params.tenantId, 'tenant id');
      if (!(await tenantExists(tenantId))) throw new AppError(404, 'Tenant not found');
      res.json({ success: true, data: await listAllocations(tenantId) });
    } catch (err) {
      forward(err, res, next);
    }
  },

  /** GET /concentrators — the devices declared as concentrators. */
  async listConcentrators(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: await listConcentrators() });
    } catch (err) {
      forward(err, res, next);
    }
  },

  /** POST /tenants/:tenantId/preview — { sites: [{ code, name, country? }] }.
   *  A dry run: writes nothing. POST only because a batch does not fit a
   *  query string. */
  async preview(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const tenantId = parseId(req.params.tenantId, 'tenant id');
      res.json({ success: true, data: await previewAllocation(tenantId, body(req).sites) });
    } catch (err) {
      forward(err, res, next);
    }
  },

  // ── CHR <-> sites reconciliation ───────────────────────────────────────

  /** GET /tenants/:tenantId/reconcile — read-only: matched sites, CHR
   *  accounts with no site (orphans), sites with no CHR account (new or
   *  suspect), off-pattern accounts, accounts no tenant explains, and what
   *  presence recorded per CHR. Allocates nothing, dials nothing. */
  async reconcile(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: await reconcileTenant(parseId(req.params.tenantId, 'tenant id')) });
    } catch (err) {
      forward(err, res, next);
    }
  },

  /** GET /tenants/:tenantId/reconcile.xlsx[?tz=] — the same report as an
   *  Excel workbook, one row per site or account. `tz` (IANA) is the zone the
   *  dates are written in, Europe/Paris by default. Opened by the browser (the
   *  session cookie travels with it), hence a plain GET. The file name is built
   *  from the tenant's slug and the date only. */
  async reconcileXlsx(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const tenantId = parseId(req.params.tenantId, 'tenant id');
      const tzRaw = req.query.tz;
      if (tzRaw !== undefined && (typeof tzRaw !== 'string' || !isIanaTimeZone(tzRaw))) {
        throw new AppError(400, 'tz must be an IANA time zone name (e.g. Europe/Paris)');
      }
      const report = await reconcileTenant(tenantId);
      const { buffer, fileName } = reconcileToXlsx(report, typeof tzRaw === 'string' ? tzRaw : 'Europe/Paris');
      res.setHeader('Content-Type', XLSX_CONTENT_TYPE);
      res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
      res.setHeader('Cache-Control', 'no-store');
      res.send(buffer);
    } catch (err) {
      forward(err, res, next);
    }
  },

  /** GET /tenants/:tenantId/reconcile/orphans.xlsx[?tz=] — the orphans as a
   *  workbook the SITE IMPORT reads back as it is (code, name, country, …,
   *  every cell text): the operator types the names and imports it — into the
   *  tenant the IMPORT runs in, i.e. her session's, which the screen reminds
   *  her of. See siteImport.service `orphansImportXlsx`. */
  async reconcileOrphansXlsx(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const tenantId = parseId(req.params.tenantId, 'tenant id');
      const tzRaw = req.query.tz;
      if (tzRaw !== undefined && (typeof tzRaw !== 'string' || !isIanaTimeZone(tzRaw))) {
        throw new AppError(400, 'tz must be an IANA time zone name (e.g. Europe/Paris)');
      }
      const report = await reconcileTenant(tenantId);
      const { buffer, fileName } = orphansImportXlsx(report, typeof tzRaw === 'string' ? tzRaw : 'Europe/Paris');
      res.setHeader('Content-Type', XLSX_CONTENT_TYPE);
      res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
      res.setHeader('Cache-Control', 'no-store');
      res.send(buffer);
    } catch (err) {
      forward(err, res, next);
    }
  },

  /** POST /tenants/:tenantId/reconcile/sites — { code, name, country? }.
   *  Creates ONE site in the tenant named by the path (not the session's),
   *  with its country; allocates nothing. See `createSiteForTenant`. */
  async createReconciledSite(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const tenantId = parseId(req.params.tenantId, 'tenant id');
      res.status(201).json({ success: true, data: await createSiteForTenant(tenantId, body(req)) });
    } catch (err) {
      forward(err, res, next);
    }
  },

  /** POST /concentrators/:concentratorId/secrets/read — re-read the CHR's
   *  /ppp/secret now and record it (the allocator's own re-read). A CHR that
   *  cannot be read answers 502 with the cause, and nothing is recorded. */
  async rereadConcentrator(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const concentratorId = parseId(req.params.concentratorId, 'concentrator id');
      try {
        res.json({ success: true, data: await rereadConcentratorInventory(concentratorId) });
      } catch (err) {
        if (err instanceof AllocationError || err instanceof VaultError) throw err;
        logger.warn({ err, concentratorId }, 'Reconciliation: /ppp/secret re-read failed');
        const cause = err instanceof Error ? err.message.slice(0, 300) : 'unknown error';
        throw new AppError(502, `The concentrator's /ppp/secret could not be read: ${cause}`);
      }
    } catch (err) {
      forward(err, res, next);
    }
  },

  // ── Sites ──────────────────────────────────────────────────────────────

  /** GET /sites/:siteId — the allocation without its password; `data: null`
   *  when the site exists and has not been allocated yet. */
  async getSite(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const siteId = parseId(req.params.siteId, 'site id');
      const provisioning = await getSiteProvisioning(siteId);
      if (!provisioning && !(await siteExists(siteId))) throw new AppError(404, 'Site not found');
      res.json({ success: true, data: provisioning });
    } catch (err) {
      forward(err, res, next);
    }
  },

  /** DELETE /sites/:siteId — release the site's allocation so it can be
   *  allocated again. 409 ALREADY_PROVISIONED once the CHR has taken it,
   *  unless the caller confirms with `?confirmProvisioned=<the PPP login>`
   *  (see `releaseProvisioned`); `data` is the allocation as it was (no
   *  password). Nothing here talks to the concentrator. */
  async releaseSite(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const siteId = parseId(req.params.siteId, 'site id');
      const current = await getSiteProvisioning(siteId);
      if (!current) {
        if (!(await siteExists(siteId))) throw new AppError(404, 'Site not found');
        throw new AllocationError('NOT_ALLOCATED', `site ${siteId} has no allocation; there is nothing to release.`);
      }
      const confirm = req.query.confirmProvisioned;
      if (current.concentratorState === 'provisioned' && typeof confirm === 'string' && confirm !== '') {
        res.json({ success: true, data: await releaseProvisioned(req, siteId, current, confirm) });
        return;
      }
      res.json({ success: true, data: await releaseAllocation(siteId, current.tenantId) });
    } catch (err) {
      forward(err, res, next);
    }
  },
};
