import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { accessCheckController } from '../controllers/accessCheck.controller';
import { reconcileController } from '../controllers/reconcile.controller';
import { requireCapability, requireRole } from '../middleware/rbac';
import { validate } from '../middleware/validate';
import { adoptGodViewFilterTenant } from '../utils/globalView';
import { reconcileAttachApplySchema, reconcileAttachPreviewSchema } from '../validators/reconcile.schema';

/**
 * The CHR <-> sites reconciliation of the caller's OWN tenant. Mounted under
 * the tenant-scoped router (`tenantRouter.use('/reconcile', …)` in
 * routes/index.ts), so `requireAuth` and `requireTenant` have already run and
 * the tenant is `req.tenantId` — never a path parameter, never a body field.
 *
 * ┌─ RECONCILE_READ, AND WHY THAT IS SAFE ON A SHARED CHR ───────────────────┐
 * │ `TENANT_ROLE_CAPABILITIES` hands a capability to the matching role of   │
 * │ EVERY tenant — the reason allocation.routes.ts is requireRole('admin').  │
 * │ What makes this one tenant-safe is not the guard but the service:       │
 * │   - the report is the session tenant's, and only it;                    │
 * │   - it is refused (409 TEMPLATE_NAMES_NO_TENANT) when the tenant's login │
 * │     template names no tenant: such a template reads other customers'    │
 * │     accounts as this one's;                                              │
 * │   - it is REDACTED (reconcile.service `redactReport`): nothing about     │
 * │     another tenant, no address, profile, pool or concentrator identity,  │
 * │     no adoption holder, no password (none is ever read).                │
 * │ The re-read dials the CHRs this tenant's reconciliation reads — never   │
 * │ one the caller names — through the allocator's own re-read (the shared   │
 * │ RouterOS pool, the allocation lock for the write), exactly as the       │
 * │ platform admin's "Re-read the CHR". It writes nothing to the router.     │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Creating sites is NOT here: the orphans workbook goes back through the
 * ordinary site import (`POST /api/sites/import`, SITE_WRITE), whose dry run
 * shows which account each row takes over.
 *
 * ┌─ ATTACHING THE ONLINE ROUTERS: A PLATFORM ADMINISTRATOR ─────────────────┐
 * │ `attach-devices[/preview]` turns the matched, allocated, ONLINE sites    │
 * │ into devices (fleet/reconcileAttach.service.ts): it dials each router    │
 * │ over SSH (reads only) and stores an SSH credential in the vault. Each   │
 * │ device it writes carries a (concentrator, ppp_username) pair of the     │
 * │ SHARED CHR — the pair presence routes every session by, which           │
 * │ `decidePppClaim` and `bindDiscovery` let only a platform administrator  │
 * │ write — so the act is `requireRole('admin')` (operator decision,         │
 * │ 2026-10-04), not a capability: a capability resolves through            │
 * │ TENANT_ROLE_CAPABILITIES and reaches the admin of ANY tenant (the same   │
 * │ reason allocation.routes.ts gives). DEVICE_WRITE + CREDENTIAL_MANAGE     │
 * │ stay declared beside it (a router created and approved, a credential    │
 * │ put in the vault — the pair `/devices/enroll-probe` demands): a platform │
 * │ administrator holds both, so they add no refusal today, and they keep   │
 * │ the route's needs readable. The dry run needs the same guard: it is the │
 * │ first half of the act, and it names which vault level a site's password  │
 * │ would come from. The service refuses a non-administrator actor as well   │
 * │ (PLATFORM_ADMIN_ONLY).                                                   │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
const router = Router();

// God view (utils/globalView.ts): the reconciliation is one tenant's report
// (its policy, its login rule, its orphans) and cannot be merged across
// tenants, so the god view picks the tenant with `?filterTenantId=` and the
// whole request — read, re-read, attach — runs and is audited in it.
router.use(adoptGodViewFilterTenant);

router.get('/', requireCapability(CAPABILITIES.RECONCILE_READ), reconcileController.view);
router.post('/reread', requireCapability(CAPABILITIES.RECONCILE_READ), reconcileController.reread);
router.get('/orphans.xlsx', requireCapability(CAPABILITIES.RECONCILE_READ), reconcileController.orphansXlsx);
router.post(
  '/attach-devices/preview',
  requireRole('admin'),
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  requireCapability(CAPABILITIES.CREDENTIAL_MANAGE),
  validate(reconcileAttachPreviewSchema),
  reconcileController.attachPreview,
);
router.post(
  '/attach-devices',
  requireRole('admin'),
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  requireCapability(CAPABILITIES.CREDENTIAL_MANAGE),
  validate(reconcileAttachApplySchema),
  reconcileController.attachApply,
);

// Verify, then re-apply, the management access and the template fixes over
// the workspace (fleet/accessCheck.service.ts). CHANGE_APPLY, the per-device
// management-access / legacy-compliance routes' own capability; the
// controller narrows every one to the devices the caller's teams grant `rw`.
router.get('/access-check', requireCapability(CAPABILITIES.CHANGE_APPLY), accessCheckController.latest);
router.get('/access-check/schedule', requireCapability(CAPABILITIES.CHANGE_APPLY), accessCheckController.schedule);
router.post('/access-check', requireCapability(CAPABILITIES.CHANGE_APPLY), accessCheckController.start);
router.post('/access-check/reapply', requireCapability(CAPABILITIES.CHANGE_APPLY), accessCheckController.reapply);

export default router;
