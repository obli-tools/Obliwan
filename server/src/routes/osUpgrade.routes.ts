import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { osUpgradeController } from '../controllers/osUpgrade.controller';
import { requireCapability } from '../middleware/rbac';

/**
 * Fleet OS upgrade - "mise a jour du parc". Mounted under the tenant-scoped
 * router.
 *
 * LEAD: `tenantRouter.use('/os-upgrade', osUpgradeRoutes);` in
 * `routes/index.ts`, next to `/rollouts`. It belongs on the same side of the
 * line that file draws around the change queue: `POST /os-upgrade` ends in routers rebooting,
 * and it does so ONLY by handing work to the change queue through the
 * launcher of the controller (section 4: rollout.service `osUpgradeLauncher`
 * by default, replaceable with `setOsUpgradeLauncher()`).
 *
 * +- THE CAPABILITY MAP ----------------------------------------------------+
 * | DEVICE_READ     the listing. It writes nothing; the change-queue        |
 * |                 details in it are withheld from a caller without        |
 * |                 PLAN_CREATE (the controller's `redactQueue`).           |
 * | DEVICE_WRITE    re-reading versions: it dials routers, read-only on the |
 * |                 equipment - the grant `/identity/sweep` requires.       |
 * | CHANGE_APPLY    the preview (the first step of a launch; it writes      |
 * |                 nothing) and the launch. The handler raises the bar     |
 * |                 again: ROLLOUT_MANAGE when more than one device is      |
 * |                 selected (that is a rollout), CHANGE_APPROVE for the    |
 * |                 override reason - which every upgrade must carry,       |
 * |                 because the guard answers INDETERMINATE for a job with  |
 * |                 no plan. In practice a launch therefore needs           |
 * |                 CHANGE_APPROVE.                                         |
 * +-------------------------------------------------------------------------+
 *
 * Literal paths only, so no parameter can swallow `/preview`.
 */
const router = Router();

router.get('/devices', requireCapability(CAPABILITIES.DEVICE_READ), osUpgradeController.listDevices);
router.post('/preview', requireCapability(CAPABILITIES.CHANGE_APPLY), osUpgradeController.preview);
router.post(
  '/refresh-versions',
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  osUpgradeController.refreshVersions,
);
router.post('/', requireCapability(CAPABILITIES.CHANGE_APPLY), osUpgradeController.launch);

export default router;
