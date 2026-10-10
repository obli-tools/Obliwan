import { Router } from 'express';
import { requireRole } from '../middleware/rbac';
import { infraAnalysisController } from '../controllers/infraAnalysis.controller';

/**
 * The infrastructure analysis. Mounted by routes/index.ts under `tenantRouter`
 * (requireAuth + requireTenant) as
 *
 *     tenantRouter.use('/infra-analysis', infraAnalysisRoutes);
 *
 * so it reads the session's CURRENT workspace's routers and writes that
 * workspace's site values, never a tenant named in a path or a body.
 *
 * requireRole('admin'), NOT A CAPABILITY — like Quick Setup Tenant: it dials
 * customer routers with fleet credentials, may read their secrets, and writes
 * site values that outrank the tenant's policy. A capability would be resolved
 * through TENANT_ROLE_CAPABILITIES and handed to the admin of any tenant.
 *
 * `preview` reads routers (read-only) and writes nothing in ObliWAN; `apply`
 * is the only route that writes, and only variables.
 */
const router = Router();

router.use(requireRole('admin'));

router.get('/candidates', infraAnalysisController.candidates);
router.post('/preview', infraAnalysisController.preview);
router.post('/apply', infraAnalysisController.apply);
router.get('/:id', infraAnalysisController.get);
router.get('/:id/export', infraAnalysisController.export);
router.delete('/:id', infraAnalysisController.forget);

export default router;
