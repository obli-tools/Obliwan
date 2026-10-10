import { Router } from 'express';
import { groupsController } from '../controllers/groups.controller';
import { requireAuth } from '../middleware/auth';
import { requireCapability, requireGroupWrite, requireCanCreate } from '../middleware/rbac';
import { requireGroupConfigCapability } from '../middleware/teamScope';
import { CAPABILITIES } from '@obliwan/shared';
import { validate } from '../middleware/validate';
import { godViewParam } from '../utils/globalView';
import {
  createGroupSchema,
  updateGroupSchema,
  moveGroupSchema,
} from '../validators/group.schema';

const router = Router();

// All routes require authentication
router.use(requireAuth);

// God view (utils/globalView.ts): a route naming ONE group acts in that
// group's own tenant — read, permission check, write and live event alike.
router.param('id', godViewParam('device_groups'));

// Read routes (visibility filtering happens in the controller)
router.get('/', groupsController.list);
router.get('/tree', groupsController.tree);
router.get('/:id', groupsController.getById);

// Write routes (permission-based: admin OR team RW)
router.post('/', requireCanCreate(), validate(createGroupSchema), groupsController.create);
// Obliance's split (migration 084): editing / moving / deleting a group is an
// 'rw' TEAM grant on it (platform admin aside), creating one is a team with
// `can_create`; reordering and the group's CONFIGURATION (isGeneral,
// groupNotifications, sortOrder) are the tenant capability `groups.manage`.
router.put('/:id', requireGroupWrite(), validate(updateGroupSchema), requireGroupConfigCapability(), groupsController.update);
router.post('/reorder', requireCapability(CAPABILITIES.GROUPS_MANAGE), groupsController.reorder);
router.post('/:id/move', requireGroupWrite(), validate(moveGroupSchema), groupsController.move);
router.delete('/:id', requireGroupWrite(), groupsController.delete);

export default router;
