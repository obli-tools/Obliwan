import { Router } from 'express';
import { requireRole } from '../middleware/rbac';
import { godViewBodyTenants, godViewFromParam, godViewRead } from '../utils/globalView';
import { learningController } from '../controllers/learning.controller';

/**
 * Learning mode. Mounted by routes/index.ts under `tenantRouter`
 * (requireAuth + requireTenant) as
 *
 *     tenantRouter.use('/learning', learningRoutes);
 *
 * requireRole('admin'), NOT A CAPABILITY — like the infrastructure analysis:
 * a capture dials customer routers in production and reads their secrets (the
 * no-secrets exception of 2026-10-04). A capability would be resolved through
 * TENANT_ROLE_CAPABILITIES and handed to the admin of any tenant.
 *
 * God view (Default): the list reads every tenant; an action on one router
 * follows it into its own tenant (`godViewFromParam`), a bulk state change
 * fans out per tenant, and a capture or a dataset is ONE tenant's — ids of
 * several workspaces are refused with a sentence (`godViewBodyTenants`).
 */
const router = Router();

router.use(requireRole('admin'));

router.get('/devices', learningController.devices);
router.post('/devices/state', learningController.bulkState);
router.put('/devices/:id', godViewFromParam('devices'), learningController.toggle);
router.get('/devices/:id/capture', godViewFromParam('devices'), learningController.captureDetail);
router.get('/devices/:id/break-risk', godViewFromParam('devices'), learningController.breakRisk);
router.post('/captures', godViewBodyTenants('devices', 'deviceIds'), learningController.capture);
router.get('/captures/:id/export', godViewFromParam('learning_captures'), learningController.exportText);
router.get('/runs/:runId', learningController.run);
router.post('/dataset', godViewRead, godViewBodyTenants('devices', 'deviceIds'), learningController.dataset);

export default router;
