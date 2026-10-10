import { Router, type NextFunction, type Request, type Response } from 'express';
import { CAPABILITIES, type Capability } from '@obliwan/shared';
import { variablesController } from '../controllers/variables.controller';
import { requireCapability, requireRole } from '../middleware/rbac';
import { AppError } from '../middleware/errorHandler';
import { permissionService } from '../services/permission.service';
import { godViewFromParam } from '../utils/globalView';

/**
 * Template variables — `config_variables`.
 *
 * RBAC:
 *   TEMPLATE_READ         resolve variables for a device / group / tenant, and
 *                         list what is set at one level (the instance level
 *                         included: `GET /instance`).
 *   TEMPLATE_WRITE        set or remove one, at any of the tenant's five levels.
 *   SITE_VARIABLES_WRITE  the site form only: `GET` / `PUT /sites/:siteId`.
 *   requireRole('admin')  the INSTANCE level's writes: `PUT /instance`,
 *                         `PUT /instance/bulk`, `DELETE /instance?key=`. A
 *                         value there is shared by every tenant of the
 *                         installation (migration 038), so no tenant
 *                         capability — however broad — may write one.
 *
 * `computed` and `bench` have NO route at all, read or write: they are
 * supplied by the caller of a render (the allocator, the bench) and kept in
 * memory for that render only. `/at|bulk/:scope` refuses both by name, and
 * `instance` too, pointing at its own routes.
 *
 * Writing a variable is `TEMPLATE_WRITE` and not a lesser capability, because a
 * variable is an INPUT to a rendered template: whoever can set one can change
 * what the server would push to a router. That is the same class of act as
 * authoring the template, and it gets the same capability.
 *
 * The site form is the one narrower door, and it is narrower by construction
 * rather than by trust: scope `site` only, keys that every PUBLISHED
 * declaration opens to it with `x-obliwan-level: 'site'` only, values that
 * validate against those declarations only, and the declaration — not the
 * caller — decides what goes to the vault. That is the difference between
 * typing a VLAN id and writing template code, and it is why an account
 * manager can hold it without holding TEMPLATE_WRITE. The opt-in matters as
 * much as the type: every plain tenant member holds SITE_VARIABLES_WRITE, and
 * a site value outranks the group and the tenant, so a key the author kept at
 * another level must not be overridable here. TEMPLATE_WRITE implies it
 * (`CAPABILITY_IMPLIES`), so a template author loses nothing; the generic
 * `/at/site/:scopeId` routes stay TEMPLATE_WRITE and keep accepting any key,
 * as they do at every other level — they are what the site form's refusals
 * point to.
 *
 * Reading a SECRET variable's value has no route HERE — not under a flag, not
 * for a platform admin. A secret comes back as `__OBLIWAN_SECRET_<KEY>__` with
 * a keyed fingerprint at every level of this API. The one way to read it in
 * clear is `POST /api/variables/reveal` (secretReveal.routes.ts, mounted
 * before this router): SECRET_READ, platform admin for the instance level and
 * the master tenant, HTTPS, rate-limited, and every reveal written to
 * `audit_log`.
 *
 * ┌─ WHY THE PATHS LOOK LIKE THIS ───────────────────────────────────────────┐
 * │ `scope` is one of global | tenant | group | site | device (never         │
 * │ instance, computed or bench). `global` and                               │
 * │ `tenant` carry NO scope id (their identity is the tenant, exactly as in  │
 * │ `settings`); the other three require one. Two route arities express     │
 * │ that, so a `device` write with a missing scope id cannot even be routed  │
 * │ — it 404s at the router instead of landing in the UNSCOPED partial       │
 * │ unique index and behaving, silently, like a global variable for the      │
 * │ whole fleet.                                                             │
 * │                                                                          │
 * │ The variable KEY travels in the query string on DELETE rather than as a  │
 * │ path segment: `/variables/at/global/vlan` and `/variables/at/group/12`   │
 * │ have the same arity, and telling them apart by whether the last segment  │
 * │ looks numeric is one rename away from deleting the wrong row.            │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * NOT MOUNTED HERE — `routes/index.ts` is the shared route table. It
 * mounts this router under `tenantRouter` at `/variables`.
 */
const router = Router();

/**
 * `requireCapability`, for "any one of these". Same three steps in the same
 * order — authenticated, platform admin passes, otherwise the capabilities
 * resolved for the CURRENT tenant (role matrix + by-name grants, closed under
 * `CAPABILITY_IMPLIES`) — so a caller with no tenant gets the same 403 here as
 * everywhere else. Local to this router because it is, today, its only user.
 */
function requireAnyCapability(...capabilities: Capability[]) {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.session?.userId) {
        next(new AppError(401, 'Authentication required'));
        return;
      }
      if (req.session.role === 'admin') { next(); return; }

      const tenantId = req.tenantId ?? req.session.currentTenantId;
      if (!tenantId) {
        next(new AppError(403, 'No tenant granted for this account'));
        return;
      }
      const held = await permissionService.getUserCapabilities(req.session.userId, false, tenantId);
      if (!capabilities.some((c) => held.includes(c))) {
        next(new AppError(403, 'Insufficient permissions'));
        return;
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}

// ── The site form — typed values for declared keys (SITE_VARIABLES_WRITE) ───
// Reading it is open to TEMPLATE_READ as well: the form shows declared keys
// and redacted values, nothing a template reader cannot already see.
// God view: both act in the site's own tenant (its values, its templates).
router.get(
  '/sites/:siteId',
  requireAnyCapability(CAPABILITIES.TEMPLATE_READ, CAPABILITIES.SITE_VARIABLES_WRITE),
  godViewFromParam('sites', 'siteId'),
  variablesController.siteForm,
);
router.put(
  '/sites/:siteId',
  requireCapability(CAPABILITIES.SITE_VARIABLES_WRITE),
  godViewFromParam('sites', 'siteId'),
  variablesController.setSiteForm,
);

// ── The instance level — shared by every tenant (migration 038) ─────────────
// Declared before `/at/...` and `/bulk/...` for readability only: no literal
// here can be shadowed by them, nor shadow them.
router.get(
  '/instance',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  variablesController.listInstance,
);
router.put('/instance', requireRole('admin'), variablesController.setInstance);
router.put('/instance/bulk', requireRole('admin'), variablesController.setInstanceBulk);
router.delete('/instance', requireRole('admin'), variablesController.removeInstance);

// ── Resolved views — every value with its ORIGIN (the InheritanceBadge) ─────
router.get(
  '/devices/:deviceId',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  godViewFromParam('devices', 'deviceId'),
  variablesController.forDevice,
);
router.get(
  '/groups/:groupId',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  variablesController.forGroup,
);
router.get(
  '/tenant',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  variablesController.forTenant,
);

// ── Bulk write. Declared before `/at/...` so the literal is not shadowed. ───
router.put(
  '/bulk/:scope',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  variablesController.setBulkAtScope,
);
router.put(
  '/bulk/:scope/:scopeId',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  variablesController.setBulkAtScope,
);

// ── One level, no inheritance: the editing view ─────────────────────────────
router.get(
  '/at/:scope',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  variablesController.listAtScope,
);
router.get(
  '/at/:scope/:scopeId',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  variablesController.listAtScope,
);
router.put(
  '/at/:scope',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  variablesController.setAtScope,
);
router.put(
  '/at/:scope/:scopeId',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  variablesController.setAtScope,
);
router.delete(
  '/at/:scope',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  variablesController.removeAtScope,
);
router.delete(
  '/at/:scope/:scopeId',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  variablesController.removeAtScope,
);

export default router;
