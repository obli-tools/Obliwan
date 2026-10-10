import { Router } from 'express';
import { allocationController } from '../controllers/allocation.controller';
import { lanRepriseController } from '../controllers/lanReprise.controller';
import { requireAuth } from '../middleware/auth';
import { requireRole } from '../middleware/rbac';

/**
 * Per-tenant address allocation. Mounted by routes/index.ts as
 *
 *     router.use('/allocation', allocationRoutes);   // -> /api/allocation/...
 *
 * in the GLOBAL section, beside /app-config and /system — not under
 * tenantRouter: the tenant is a path parameter and the caller is a platform
 * admin acting on every customer's numbering from one screen. Not under an
 * "/admin/" prefix either: the edge proxy bans a caller on that path.
 *
 * ┌─ requireRole('admin'), NOT A CAPABILITY ─────────────────────────────────┐
 * │ Address pools are shared infrastructure: an incremental pool may be      │
 * │ shared by several tenants, so one tenant's policy decides which           │
 * │ addresses the others can get, and the installation domain is one value  │
 * │ for everybody. A capability would be resolved through                     │
 * │ TENANT_ROLE_CAPABILITIES and handed to the admin of ANY tenant — the      │
 * │ defect once shipped on `ip_asn_ranges` and that /sim/accounts avoids the    │
 * │ same way. The READS are guarded too: a policy names the CHR and the       │
 * │ address plan of the whole fleet.                                          │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * `requireAuth` runs here as well as wherever the router is mounted, so a
 * mount outside the authenticated section fails closed instead of reaching
 * `requireRole` with an unrevalidated session role.
 *
 * Allocation itself (`allocateForSite`) has no route in this file: it is for
 * server-side callers (the bench flow and the bulk site import, when they
 * exist). RELEASING one does — `DELETE /sites/:siteId`, the operator's remedy
 * for a clash found after allocation, refused once the CHR has taken it. No
 * route anywhere returns a PPP password.
 *
 * The CHR <-> sites reconciliation (services/allocation/reconcile.service.ts)
 * lives here for the same reason as the rest: the tenant is a path parameter.
 * Its two writes are each an explicit gesture: re-reading a concentrator's
 * /ppp/secret (the allocator's own read, nothing written to the router), and
 * creating one site IN THE PATH'S TENANT with its country — POST /api/sites
 * would create it in the caller's session tenant, without a country. Its
 * orphans export (`reconcile/orphans.xlsx`) writes nothing: it is a file the
 * ordinary site import reads back.
 *
 * A TENANT user's view of her own tenant's reconciliation is NOT here: it is
 * `/api/reconcile` (reconcile.routes.ts), under the tenant router, on
 * RECONCILE_READ, the tenant the session's, redacted, and refused when the
 * login template names no tenant. Nothing in this file is opened by it.
 */
const router = Router();

router.use(requireAuth, requireRole('admin'));

router.get('/pools', allocationController.listPools);
router.post('/pools', allocationController.createPool);
router.patch('/pools/:poolId', allocationController.renamePool);
router.delete('/pools/:poolId', allocationController.deletePool);

router.get('/instance-domain', allocationController.getInstanceDomain);
router.put('/instance-domain', allocationController.putInstanceDomain);

router.get('/concentrators', allocationController.listConcentrators);
router.get('/concentrators/:concentratorId/seed', allocationController.getSeed);
router.post('/concentrators/:concentratorId/secrets/read', allocationController.rereadConcentrator);

router.get('/tenants/:tenantId/policy', allocationController.getPolicy);
router.put('/tenants/:tenantId/policy', allocationController.putPolicy);
router.post('/tenants/:tenantId/preview', allocationController.preview);
router.get('/tenants/:tenantId/next', allocationController.previewNext);
router.get('/tenants/:tenantId/sites', allocationController.listTenantSites);
router.get('/tenants/:tenantId/reconcile', allocationController.reconcile);
router.get('/tenants/:tenantId/reconcile.xlsx', allocationController.reconcileXlsx);
router.get('/tenants/:tenantId/reconcile/orphans.xlsx', allocationController.reconcileOrphansXlsx);
router.post('/tenants/:tenantId/reconcile/sites', allocationController.createReconciledSite);
// The deployed LAN of existing (adopted) sites, recorded on their allocations
// from the operator's table. A dry run unless ?dryRun=false (lanReprise.controller.ts).
router.post('/tenants/:tenantId/lan-reprise', lanRepriseController.run);

router.get('/sites/:siteId', allocationController.getSite);
router.delete('/sites/:siteId', allocationController.releaseSite);

export default router;
