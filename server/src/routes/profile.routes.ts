import { Router } from 'express';
import { requireAuth } from '../middleware/auth';
import { validate } from '../middleware/validate';
import { profileController } from '../controllers/profile.controller';
import { updateProfileSchema, changePasswordSchema, setLocalPasswordSchema } from '../validators/profile.schema';

const router = Router();

// All routes require authentication (any role)
router.use(requireAuth);

router.get('/', profileController.get);
router.put('/', validate(updateProfileSchema), profileController.update);
router.put('/password', validate(changePasswordSchema), profileController.changePassword);
// An SSO-created account with NO local password sets its first one (#30).
router.post('/local-password', validate(setLocalPasswordSchema), profileController.setLocalPassword);

export default router;
