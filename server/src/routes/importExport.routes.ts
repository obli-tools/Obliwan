import { Router, type Request, type Response, type NextFunction } from 'express';
import { AppError } from '../middleware/errorHandler';
import { requireAuth } from '../middleware/auth';
import { requireTenant } from '../middleware/tenant';
import { requireRole } from '../middleware/rbac';
import { importExportController } from '../controllers/importExport.controller';

const router = Router();

// All import/export routes are admin-only
router.use(requireAuth);
router.use(requireRole('admin'));

/**
 * This router is mounted under
 * `/admin` in the "global (no tenant required)" section of routes/index.ts, so
 * it never went through `requireTenant`, and both handlers fell back to
 * `req.session.currentTenantId ?? 1`. An admin whose session had no current
 * tenant (fresh session, tenant just deleted, direct link to
 * /admin/import-export before any switch) uploaded a customer bundle straight
 * into the MASTER tenant: 40 groups, 6 teams and their settings created in
 * "Default", with the source uuids now owned by tenant 1 — after which a
 * re-import into the right tenant sees them as foreign and regenerates fresh
 * uuids, losing the correspondence with the source instance for good.
 *
 * `requireTenant` is applied HERE rather than by moving the mount under
 * `tenantRouter`, because routes/index.ts is owned elsewhere. The effect
 * is the same and the two `?? 1` in the controller are gone.
 *
 * Since `tenantService.resolveSessionTenantId()`, `requireTenant` RESOLVES a
 * tenant for a platform admin whose session names none (or names a deleted
 * one) — first membership, else the master tenant — and this router is
 * admin-only. Left alone, that would replay the sidebar design exactly: the request that
 * carries the bundle is the one that picks tenant 1, so the bundle lands in a
 * tenant no screen had shown when the operator pressed "import". Hence
 * `refuseTenantResolvedNow` below, on the import only: a tenant resolved
 * DURING this request (`req.tenantResolvedNow`) is refused with a 409 and
 * nothing is written. The resolution is still saved to the session, so after a
 * reload `/api/auth/me` and the tenant picker show it and a repeated import
 * goes through, into the tenant now on screen.
 *
 * The export stays a read, healed like every other read. What this guard does
 * NOT cover is the general case of a session moved under an open page (a
 * switch made in another tab, say): the import request carries no "expected
 * tenant" for the server to compare against — that is a client contract, not
 * something this router can check.
 */
router.use(requireTenant);

function refuseTenantResolvedNow(req: Request, _res: Response, next: NextFunction): void {
  if (req.tenantResolvedNow) {
    next(new AppError(
      409,
      `This session had no current tenant; it has now been placed on tenant ${req.tenantId}. ` +
        'Nothing was imported. Reload the page, check the selected tenant, then import again.',
    ));
    return;
  }
  next();
}

router.get('/export', importExportController.exportData);
router.post('/import', refuseTenantResolvedNow, importExportController.importData);

export default router;
