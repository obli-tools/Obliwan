import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { wanLinkController } from '../controllers/wanLink.controller';
import { requireCapability } from '../middleware/rbac';
import { godViewBodyTenants, godViewParam } from '../utils/globalView';

/**
 * The WAN1 link change on a router in service (a `wan_link` change job over
 * SSH). Mounted under the tenant-scoped router, on `/devices`, BEFORE
 * devicesRoutes: DEVICE_READ for the card (it dials nothing), CHANGE_APPLY to
 * queue a job (SITE_VARIABLES_WRITE checked again in the handler: the job
 * writes the site's variables). The team scope of `/devices/:deviceId` already
 * covers these paths ('rw' on POST).
 */
const router = Router();

// God view (utils/globalView.ts): a route naming ONE devices row by `:id`
// acts in that row's own tenant — read, write and audit alike.
router.param('id', godViewParam('devices'));

// The bulk gestures (a wan_link rollout): the devices named in the body are
// read in their own tenant under the god view; the team scope of every one of
// them is judged in routes/index.ts ('ro' for the preview, 'rw' to launch).
router.post('/wan-link/preview', requireCapability(CAPABILITIES.CHANGE_APPLY), godViewBodyTenants('devices', 'deviceIds'), wanLinkController.preview);
router.post('/wan-link/rollouts', requireCapability(CAPABILITIES.CHANGE_APPLY), godViewBodyTenants('devices', 'deviceIds'), wanLinkController.launchRollout);
router.get('/:id/wan-link', requireCapability(CAPABILITIES.DEVICE_READ), wanLinkController.get);
router.post('/:id/wan-link', requireCapability(CAPABILITIES.CHANGE_APPLY), wanLinkController.enqueue);

export default router;
