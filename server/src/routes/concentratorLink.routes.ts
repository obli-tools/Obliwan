import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { concentratorLinkController } from '../controllers/concentratorLink.controller';
import { requireAuth } from '../middleware/auth';
import { requireCapability, requireRole } from '../middleware/rbac';

/**
 * The ObliWAN <-> concentrator WireGuard link. Mounted by routes/index.ts in
 * the GLOBAL section, right after `/allocation`:
 *
 *     router.use('/concentrators', concentratorLinkRoutes);   // -> /api/concentrators/...
 *
 * not under `tenantRouter`: a concentrator is shared infrastructure (the
 * master tenant's CHR carries every customer's tunnels), and `requireTenant`
 * would only lock out a platform admin with no current tenant.
 *
 * ┌─ requireRole('admin') AND CHANGE_APPLY ─────────────────────────────────┐
 * │ The POSTs queue a write on, or re-point ObliWAN's management of, the box │
 * │ every site depends on: a platform decision, never a capability a tenant  │
 * │ admin could be handed. CHANGE_APPLY is required on top and is the        │
 * │ statement of what the route does; `requireCapability` lets a platform    │
 * │ admin through today, so the role is what actually gates it. The GET is   │
 * │ guarded the same way: it names the transit, the CHR's address and keys.  │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * `requireAuth` runs here as well as wherever the router is mounted, so a
 * mount outside the authenticated section fails closed.
 */
const router = Router();

router.use(requireAuth, requireRole('admin'), requireCapability(CAPABILITIES.CHANGE_APPLY));

router.get('/:id/link', concentratorLinkController.get);
router.post('/:id/link', concentratorLinkController.connect);
router.post('/:id/link/api-transport', concentratorLinkController.switchApi);

export default router;
