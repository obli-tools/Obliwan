import { Router } from 'express';
import { requireRole } from '../middleware/rbac';
import { adoptGodViewFilterTenant } from '../utils/globalView';
import { tenantSetupController } from '../controllers/tenantSetup.controller';
import { onboardingController } from '../controllers/onboarding.controller';

/**
 * Quick Setup Tenant. Mounted by routes/index.ts under `tenantRouter`
 * (requireAuth + requireTenant) as
 *
 *     tenantRouter.use('/tenant-setup', tenantSetupRoutes);   // -> /api/tenant-setup/...
 *
 * so it acts on the session's CURRENT workspace, never on a tenant named in
 * a path or a file.
 *
 * ┌─ requireRole('admin'), NOT A CAPABILITY ─────────────────────────────────┐
 * │ The setup may write INSTANCE variables (every tenant's renders) and the   │
 * │ tenant's allocation rule (shared pools, the installation's CHR), both of │
 * │ which are already platform-admin-only (variables.routes `/instance`,     │
 * │ allocation.routes). A capability would be resolved through               │
 * │ TENANT_ROLE_CAPABILITIES and handed to the admin of any tenant.          │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * All three are POST: `context` may carry an uploaded template whose
 * var_schema becomes the declarations, and none of them writes except `apply`.
 */
const router = Router();

router.use(requireRole('admin'));

router.post('/context', tenantSetupController.context);
router.post('/check', tenantSetupController.check);
router.post('/apply', tenantSetupController.apply);

// The onboarding assistant (brick 14, services/tenantSetup/onboarding.service.ts).
// Unlike the three routes above it follows the god view: from the Default
// workspace the client is the one picked in the workspace filter (adopted
// here; none picked is refused in the controller), so a platform admin can
// walk a customer's onboarding without moving every tab's session. Two reads
// and one write — the inferred allocation rule, saved only on approval of the
// exact proposal shown (its fingerprint), through createPool + upsertPolicy.
router.get('/onboarding', adoptGodViewFilterTenant, onboardingController.status);
router.get('/onboarding/rule', adoptGodViewFilterTenant, onboardingController.rule);
router.post('/onboarding/rule/approve', adoptGodViewFilterTenant, onboardingController.approveRule);

export default router;
