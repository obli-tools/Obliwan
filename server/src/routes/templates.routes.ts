import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { templatesController } from '../controllers/templates.controller';
import { requireCapability } from '../middleware/rbac';
import { godViewBodyTenant, godViewFromParam } from '../utils/globalView';

/**
 * Templates, revisions, partials and assignments.
 *
 * ┌─ RBAC, BY GESTURE ───────────────────────────────────────────────────────┐
 * │ TEMPLATE_READ   list and read templates, revisions, partials,           │
 * │                 assignments; diff two revisions; RENDER A STORED        │
 * │                 REVISION on a witness device.                            │
 * │ TEMPLATE_WRITE  author, import, publish, quarantine or deprecate,        │
 * │                 assign, delete a never-published draft — and RENDER AN   │
 * │                 ARBITRARY BODY.                                          │
 * │                                                                          │
 * │ `TEMPLATE_WRITE` is the injection mitigation, and it is a security       │
 * │ boundary rather than a CRUD permission: it is the capability that lets   │
 * │ a caller make this server EXECUTE TEMPLATE CODE OF THEIR CHOOSING, on    │
 * │ the machine that holds the administration credentials of every device    │
 * │ of every customer. The sandbox (`worker_threads`, `resourceLimits`, a    │
 * │ 5 s ceiling, a pure-JSON context and an empty `vm` realm) is what makes  │
 * │ that survivable; this capability is what makes it authorised. Grant it   │
 * │ the way you would grant shell access, because that is what it is.        │
 * │                                                                          │
 * │ The line falls on WHO CHOSE THE CODE, not on who pressed the button:     │
 * │   POST /preview                 body in the request  -> TEMPLATE_WRITE  │
 * │   POST /revisions/:id/preview   body in the database  -> TEMPLATE_READ   │
 * │ A stored body got there under TEMPLATE_WRITE and is frozen once          │
 * │ published; `loadRevisionBundle` reads nothing else.                      │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Route ORDER is load-bearing: every literal prefix (`/partials`,
 * `/revisions`, `/vocabulary`, `/import`, `/assignments`, `/devices`, `/preview`) is declared BEFORE
 * `/:id`, or the parameter swallows it and `GET /templates/partials` starts
 * looking up a template whose id is the string "partials".
 *
 * NOT MOUNTED BY THIS FILE. `routes/index.ts` is the shared route table;
 * it mounts this router under `tenantRouter` at `/templates`, which is
 * where `requireAuth` + `requireTenant` are applied. Nothing here reads
 * `req.tenantId` without them having run.
 */
const router = Router();

// God view (utils/globalView.ts): a route naming ONE row acts in that row's own
// tenant (route-level, because `:id` / `:revId` name rows of different tables
// on different routes). A library row (tenant_id NULL) moves nothing.

// ── Partials ────────────────────────────────────────────────────────────────
router.get(
  '/partials',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  templatesController.listPartials,
);
router.post(
  '/partials',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  templatesController.createPartial,
);
// Declared before `/partials/:id/...` so the literal is not eaten by the param.
router.post(
  '/partials/revisions/:revId/publish',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  godViewFromParam('template_partial_revisions', 'revId'),
  templatesController.publishPartialRevision,
);
router.post(
  '/partials/:id/revisions',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  godViewFromParam('template_partials'),
  templatesController.createPartialRevision,
);

// ── Revisions ───────────────────────────────────────────────────────────────
router.get(
  '/revisions/:fromId/diff/:toId',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  godViewFromParam('template_revisions', 'fromId'),
  templatesController.diffRevisions,
);
router.post(
  '/revisions/:revId/publish',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  godViewFromParam('template_revisions', 'revId'),
  templatesController.publishRevision,
);
// `{ status: 'quarantined' | 'deprecated', reason }` on a revision that left
// draft. There is no way back to `draft` or to `published` through it.
router.post(
  '/revisions/:revId/status',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  godViewFromParam('template_revisions', 'revId'),
  templatesController.setRevisionStatus,
);
// Rendering a STORED revision. See the banner: TEMPLATE_READ on purpose.
router.post(
  '/revisions/:revId/preview',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  godViewFromParam('template_revisions', 'revId'),
  templatesController.previewRevision,
);
router.get(
  '/revisions/:revId',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  godViewFromParam('template_revisions', 'revId'),
  templatesController.getRevision,
);
router.patch(
  '/revisions/:revId',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  godViewFromParam('template_revisions', 'revId'),
  templatesController.updateRevision,
);

// ── Authoring vocabulary (levels, context facts) — read-only ────────────────
router.get(
  '/vocabulary',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  templatesController.vocabulary,
);

// ── Import of template files — authoring, hence TEMPLATE_WRITE ──────────────
// `?dryRun=true` validates and writes nothing. Never publishes: every revision
// it writes is a draft, and publication stays `POST /revisions/:revId/publish`.
router.post(
  '/import',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  templatesController.importTemplates,
);

// ── Preview of an arbitrary body — THE TEMPLATE-INJECTION BOUNDARY ──────────────────────────
router.post(
  '/preview',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  // God view: rendered with the witness router's own tenant's variables.
  godViewBodyTenant('devices', 'deviceId'),
  templatesController.previewScratch,
);

// ── Assignments ─────────────────────────────────────────────────────────────
router.get(
  '/assignments',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  templatesController.listAssignments,
);
router.post(
  '/assignments',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  templatesController.createAssignment,
);
router.patch(
  '/assignments/:id',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  godViewFromParam('template_assignments'),
  templatesController.updateAssignment,
);
router.delete(
  '/assignments/:id',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  godViewFromParam('template_assignments'),
  templatesController.removeAssignment,
);

// ── Per-device views ────────────────────────────────────────────────────────
router.get(
  '/devices/:deviceId/resolution',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  godViewFromParam('devices', 'deviceId'),
  templatesController.deviceResolution,
);
router.get(
  '/devices/:deviceId/render',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  godViewFromParam('devices', 'deviceId'),
  templatesController.deviceRender,
);

// ── Templates ───────────────────────────────────────────────────────────────
router.get('/', requireCapability(CAPABILITIES.TEMPLATE_READ), templatesController.list);
router.post('/', requireCapability(CAPABILITIES.TEMPLATE_WRITE), templatesController.create);
router.get('/:id', requireCapability(CAPABILITIES.TEMPLATE_READ), godViewFromParam('templates'), templatesController.get);
router.patch('/:id', requireCapability(CAPABILITIES.TEMPLATE_WRITE), godViewFromParam('templates'), templatesController.update);
router.get(
  '/:id/revisions',
  requireCapability(CAPABILITIES.TEMPLATE_READ),
  godViewFromParam('templates'),
  templatesController.listRevisions,
);
router.post(
  '/:id/revisions',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  godViewFromParam('templates'),
  templatesController.createRevision,
);

// `DELETE /:id` and `DELETE /:id/revisions/:revId` delete DRAFTS ONLY. A
// revision that was ever published is provenance: renders, plans and rollouts
// name it, and `config_renders.revision_id` is ON DELETE RESTRICT for exactly
// that reason. So a template with such a revision, or with anything still
// pointing at it or at one of its revisions, is refused with a 409; archiving
// it is `PATCH /:id` with `status: 'archived'`, which the assignment resolver
// already honours. One exception: the baseline promotion that created a
// draft-only template does not block its delete, which undoes the promotion
// (the proposal goes back to review) instead of refusing. The last revision
// of a template is refused too: deleting
// it is the template's own delete. Rule, reference list and lock order live in
// `version.service.ts` (`deleteDraftTemplate`, `deleteDraftRevision`).
router.delete(
  '/:id/revisions/:revId',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  godViewFromParam('templates'),
  templatesController.removeRevision,
);
router.delete('/:id', requireCapability(CAPABILITIES.TEMPLATE_WRITE), godViewFromParam('templates'), templatesController.remove);

export default router;
