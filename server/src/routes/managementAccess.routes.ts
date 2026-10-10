import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { managementAccessController } from '../controllers/managementAccess.controller';
import { requireCapability } from '../middleware/rbac';
import { godViewBodyTenants, godViewParam } from '../utils/globalView';

/**
 * The management API of a router in service (api-ssl on 8729, opened by a
 * `management_access` change job over SSH). Mounted under the tenant-scoped
 * router, on `/devices`, BEFORE devicesRoutes:
 *
 *   tenantRouter.use('/devices', managementAccessRoutes);
 *
 * ┌─ THE CAPABILITY MAP ──────────────────────────────────────────────────────┐
 * │ DEVICE_READ     the card's state. It writes nothing and dials nothing.  │
 * │ CHANGE_APPLY    queue one job (it writes on a customer router, through │
 * │                 the change queue), and the rollout preview (the         │
 * │                 first step of a launch; it writes nothing).             │
 * │ ROLLOUT_MANAGE  checked AGAIN in the handler of the rollout launch:     │
 * │                 several routers are done by waves, and composing and   │
 * │                 launching a rollout is ROLLOUT_MANAGE everywhere.       │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * The literal `/management-access/...` paths cannot be taken by
 * `/:id/management-access` (two segments, the second fixed).
 */
const router = Router();

// God view (utils/globalView.ts): a route naming ONE devices row by `:id`
// acts in that row's own tenant — read, write and audit alike. No-op for
// anyone but a platform admin positioned on the master tenant.
router.param('id', godViewParam('devices'));

router.post(
  '/management-access/preview',
  requireCapability(CAPABILITIES.CHANGE_APPLY),
  godViewBodyTenants('devices', 'deviceIds'),
  managementAccessController.preview,
);
router.post(
  '/management-access/rollouts',
  requireCapability(CAPABILITIES.CHANGE_APPLY),
  godViewBodyTenants('devices', 'deviceIds'),
  managementAccessController.launchRollout,
);
router.get('/:id/management-access', requireCapability(CAPABILITIES.DEVICE_READ), managementAccessController.get);
router.post('/:id/management-access', requireCapability(CAPABILITIES.CHANGE_APPLY), managementAccessController.enqueue);

export default router;
