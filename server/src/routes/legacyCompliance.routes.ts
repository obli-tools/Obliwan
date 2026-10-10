import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { legacyComplianceController } from '../controllers/legacyCompliance.controller';
import { requireCapability } from '../middleware/rbac';
import { godViewBodyTenants, godViewParam } from '../utils/globalView';

/**
 * The corrected-template fixes on a router in service (a `legacy_compliance`
 * change job over SSH). Mounted under the tenant-scoped router, on
 * `/devices`, BEFORE devicesRoutes, with management-access's capability map:
 * DEVICE_READ for the card (it dials nothing), CHANGE_APPLY to queue a job or
 * preview a rollout, ROLLOUT_MANAGE checked again in the launch handler. The
 * literal `/legacy-compliance/...` paths cannot be taken by
 * `/:id/legacy-compliance` (two segments, the second fixed).
 */
const router = Router();

// God view (utils/globalView.ts): a route naming ONE devices row by `:id`
// acts in that row's own tenant — read, write and audit alike. No-op for
// anyone but a platform admin positioned on the master tenant.
router.param('id', godViewParam('devices'));

router.post('/legacy-compliance/preview', requireCapability(CAPABILITIES.CHANGE_APPLY), godViewBodyTenants('devices', 'deviceIds'), legacyComplianceController.preview);
router.post('/legacy-compliance/rollouts', requireCapability(CAPABILITIES.CHANGE_APPLY), godViewBodyTenants('devices', 'deviceIds'), legacyComplianceController.launchRollout);
router.get('/:id/legacy-compliance', requireCapability(CAPABILITIES.DEVICE_READ), legacyComplianceController.get);
router.post('/:id/legacy-compliance', requireCapability(CAPABILITIES.CHANGE_APPLY), legacyComplianceController.enqueue);

export default router;
