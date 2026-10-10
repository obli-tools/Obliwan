import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { siteRenameController } from '../controllers/siteRename.controller';
import { requireCapability } from '../middleware/rbac';
import { godViewBodyTenants, godViewParam } from '../utils/globalView';

/**
 * Renaming a site's router (a `site_rename` change job). Mounted under the
 * tenant-scoped router, on `/devices`, BEFORE devicesRoutes: DEVICE_READ for
 * the card (it dials nothing), CHANGE_APPLY to queue or preview — and the
 * platform-admin rule checked in each handler (the job writes on the shared
 * CHR). The literal `/site-rename/...` paths cannot be taken by
 * `/:id/site-rename` (two segments, the second fixed).
 */
const router = Router();

// God view (utils/globalView.ts): a route naming ONE devices row by `:id`
// acts in that row's own tenant; a site selection acts in the tenant that owns
// the sites (one workspace at a time).
router.param('id', godViewParam('devices'));

router.post('/site-rename/bulk/preview', requireCapability(CAPABILITIES.CHANGE_APPLY), godViewBodyTenants('sites', 'siteIds'), siteRenameController.bulkPreview);
router.post('/site-rename/bulk', requireCapability(CAPABILITIES.CHANGE_APPLY), godViewBodyTenants('sites', 'siteIds'), siteRenameController.bulkLaunch);
router.get('/:id/site-rename', requireCapability(CAPABILITIES.DEVICE_READ), siteRenameController.get);
router.post('/:id/site-rename', requireCapability(CAPABILITIES.CHANGE_APPLY), siteRenameController.enqueue);

export default router;
