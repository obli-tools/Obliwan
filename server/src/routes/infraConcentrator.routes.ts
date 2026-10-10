import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { infraConcentratorController as c } from '../controllers/infraConcentrator.controller';
import { requireAuth } from '../middleware/auth';
import { requireCapability, requireRole } from '../middleware/rbac';

/**
 * Each customer's infrastructure VPN concentrator. Mounted by routes/index.ts
 * in the GLOBAL section, beside `/allocation` and `/concentrators`:
 *
 *     router.use('/infra-concentrators', infraConcentratorRoutes);
 *
 * Platform administration, like the allocation it sits next to: the tenant is
 * a PATH PARAMETER, and `requireTenant` would only lock out a platform admin
 * with no current tenant. `requireRole('admin')` on everything (a declaration
 * names a firewall and holds its API credential); the enqueue — a write on a
 * customer's concentrator, through the queue — also states CHANGE_APPLY.
 * `requireAuth` runs here too, so a mount outside the authenticated section
 * fails closed.
 */
const router = Router();

router.use(requireAuth, requireRole('admin'));

router.get('/tenants/:tenantId', c.list);
router.post('/tenants/:tenantId', c.create);
router.get('/tenants/:tenantId/sites/:siteId/accounts', c.siteAccounts);
router.get('/jobs/:jobId', c.job);
router.patch('/:id', c.update);
router.delete('/:id', c.remove);
router.post('/:id/test', c.test);
router.get('/:id/sites/:siteId', c.read);
router.post('/:id/sites/:siteId/preview', c.preview);
router.post('/:id/sites/:siteId/enqueue', requireCapability(CAPABILITIES.CHANGE_APPLY), c.enqueue);

export default router;
