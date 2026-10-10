import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { lteApnController } from '../controllers/lteApn.controller';
import { requireCapability } from '../middleware/rbac';
import { godViewParam } from '../utils/globalView';

/**
 * The LTE APN of one router (an `lte_apn` change job over SSH). Mounted under
 * the tenant-scoped router, on `/devices`, BEFORE devicesRoutes. Same
 * capability map as management-access: DEVICE_READ for the card (it dials
 * nothing), CHANGE_APPLY to queue the job (it writes on a customer router,
 * through the change queue).
 */
const router = Router();

// God view (utils/globalView.ts): a route naming ONE devices row by `:id`
// acts in that row's own tenant — read, write and audit alike. No-op for
// anyone but a platform admin positioned on the master tenant.
router.param('id', godViewParam('devices'));

router.get('/:id/lte-apn', requireCapability(CAPABILITIES.DEVICE_READ), lteApnController.get);
router.post('/:id/lte-apn', requireCapability(CAPABILITIES.CHANGE_APPLY), lteApnController.enqueue);

export default router;
