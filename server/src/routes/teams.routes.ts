import { Router } from 'express';
import { teamsController } from '../controllers/teams.controller';
import { requireAuth } from '../middleware/auth';
import { requireRole } from '../middleware/rbac';
import { validate } from '../middleware/validate';
import { godViewParam } from '../utils/globalView';
import {
  createTeamSchema,
  updateTeamSchema,
  setTeamMembersSchema,
  setTeamPermissionsSchema,
} from '../validators/team.schema';

const router = Router();

// All team routes require admin
router.use(requireAuth);
router.use(requireRole('admin'));

// God view: a route naming one team acts in that team's own tenant (its
// members, its grants), like every other object reached from Default.
router.param('id', godViewParam('user_teams'));

// Team CRUD
router.get('/', teamsController.list);
router.get('/:id', teamsController.getById);
router.post('/', validate(createTeamSchema), teamsController.create);
router.put('/:id', validate(updateTeamSchema), teamsController.update);
router.delete('/:id', teamsController.delete);

// Members
router.get('/:id/members', teamsController.getMembers);
router.put('/:id/members', validate(setTeamMembersSchema), teamsController.setMembers);

// Permissions
router.get('/:id/permissions', teamsController.getPermissions);
router.put('/:id/permissions', validate(setTeamPermissionsSchema), teamsController.setPermissions);
router.delete('/:id/permissions/:permId', teamsController.removePermission);

export default router;
