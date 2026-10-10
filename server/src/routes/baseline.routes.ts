import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { baselineController } from '../controllers/baseline.controller';
import { extrapolatorController } from '../controllers/extrapolator.controller';
import { requireCapability, requireRole } from '../middleware/rbac';
import { adoptGodViewFilterTenant } from '../utils/globalView';

/**
 * Fleet take-over / Golden Site. Mounted under the tenant-scoped
 * router.
 *
 * ┌─ NOT MOUNTED YET, AND ON PURPOSE ─────────────────────────────────────────┐
 * │ `routes/index.ts` is the shared route table and is not edited by this     │
 * │ module. One line under the Fleet Query block wires it up:                 │
 * │                                                                          │
 * │   tenantRouter.use('/baseline', baselineRoutes);                          │
 * │                                                                          │
 * │ Until that line exists, this surface is unreachable over HTTP and the     │
 * │ milestone is exercised through its service layer and its verification     │
 * │ harness. Stated here rather than left to be discovered by somebody        │
 * │ wondering why a 404 comes back from a route they can read.                │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THREE CAPABILITIES, AND THE SPLIT IS THE POINT ──────────────────────────┐
 * │ CONFIG_READ     mine a baseline and read everything it produced. A mined  │
 * │                 draft IS the fleet's configuration, reorganised: whoever  │
 * │                 may read a snapshot may read a draft, and whoever may     │
 * │                 not, may not. This is the separation of CONFIG_READ       │
 * │                 from DEVICE_READ applied to the one screen that would     │
 * │                 otherwise hand out thirty routers' firewalls under a      │
 * │                 different name. Mining writes only `baseline_*` rows —    │
 * │                 no equipment, no template, no plan.                       │
 * │ DRIFT_MANAGE    classify a deviation and manage the exceptions. Deciding  │
 * │                 "this customer is legitimately different" changes what    │
 * │                 the conformance screen says, which is the same class of   │
 * │                 act as acknowledging a drift finding — and it is behind   │
 * │                 the same capability for the same reason.                  │
 * │ TEMPLATE_WRITE  promote a draft into `templates` + `template_revisions`.  │
 * │                 That is authoring a template body, and the design says    │
 * │                 a body is the privilege that lets a caller make this      │
 * │                 server evaluate template code.                            │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ NOTHING HERE TOUCHES AN EQUIPMENT, AND NOTHING HERE PUBLISHES ───────────┐
 * │ Every route reads `devices`, `config_snapshots` and the `baseline_*`      │
 * │ tables. The only writes outside `baseline_*` are the promotion's          │
 * │ `templates` row and a `template_revisions` row with `status = 'draft'` —  │
 * │ which cannot be assigned, rendered into a plan or applied. That holds:    │
 * │ nothing writes to an equipment outside `change_jobs`.                     │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
const router = Router();

// God view (utils/globalView.ts): mining, its runs and the extrapolator are
// ONE client's report. The operator's workspace filter (`?filterTenantId=`)
// picks the client every route here runs in — read and action alike. With no
// client picked, the reads stay on the master tenant and the two mining
// starts refuse (`requirePickedTenant`).
router.use(adoptGodViewFilterTenant);

// ── the miner ────────────────────────────────────────────────────────────────
router.get('/params', requireCapability(CAPABILITIES.CONFIG_READ), baselineController.params);
router.post('/runs', requireCapability(CAPABILITIES.CONFIG_READ), baselineController.run);
router.get('/runs', requireCapability(CAPABILITIES.CONFIG_READ), baselineController.list);

// ── exceptions ───────────────────────────────────────────────────────────────
// Declared BEFORE `/runs/:id` could ever swallow them and on a distinct prefix,
// so no literal path is shadowed by a parameterised one.
router.get(
  '/exceptions',
  requireCapability(CAPABILITIES.DRIFT_MANAGE),
  baselineController.exceptions,
);
router.delete(
  '/exceptions/:id',
  requireCapability(CAPABILITIES.DRIFT_MANAGE),
  baselineController.removeException,
);

// ── one run ──────────────────────────────────────────────────────────────────
router.get('/runs/:id', requireCapability(CAPABILITIES.CONFIG_READ), baselineController.get);
router.get(
  '/runs/:id/deviations',
  requireCapability(CAPABILITIES.CONFIG_READ),
  baselineController.deviations,
);
router.get(
  '/runs/:id/conformance',
  requireCapability(CAPABILITIES.CONFIG_READ),
  baselineController.conformance,
);

// ── clusters and drafts ──────────────────────────────────────────────────────
router.get(
  '/clusters/:id',
  requireCapability(CAPABILITIES.CONFIG_READ),
  baselineController.cluster,
);
router.get('/drafts/:id', requireCapability(CAPABILITIES.CONFIG_READ), baselineController.draft);
router.post(
  '/drafts/:id/promote',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  baselineController.promote,
);

// ── triage ───────────────────────────────────────────────────────────────────
router.patch(
  '/deviations/:id',
  requireCapability(CAPABILITIES.DRIFT_MANAGE),
  baselineController.classify,
);

// ── brick 10: the template extrapolator ──────────────────────────────────────
// Running and reading: CONFIG_READ, like mining (a proposal IS the fleet's
// configuration, reorganised). Approving writes a template, a DRAFT revision
// and variable values: TEMPLATE_WRITE, the capability that writes both. Never a
// publication, never a router.
// An ADMIN function (operator, 2026-10-08): a proposal names every router of
// the client, so it is read and run by platform administrators only — never
// by a tenant account, whatever its teams cover.
router.use('/extrapolations', requireRole('admin'));
router.get('/extrapolations', requireCapability(CAPABILITIES.CONFIG_READ), extrapolatorController.list);
router.post('/extrapolations', requireCapability(CAPABILITIES.CONFIG_READ), extrapolatorController.start);
// Literal path BEFORE `/extrapolations/:id`, which would swallow it.
router.get(
  '/extrapolations/readiness',
  requireCapability(CAPABILITIES.CONFIG_READ),
  extrapolatorController.readiness,
);
router.get('/extrapolations/:id', requireCapability(CAPABILITIES.CONFIG_READ), extrapolatorController.get);
router.get(
  '/extrapolation-proposals/:id',
  requireCapability(CAPABILITIES.CONFIG_READ),
  extrapolatorController.proposal,
);
router.get(
  '/extrapolation-proposals/:id/sites/:deviceId',
  requireCapability(CAPABILITIES.CONFIG_READ),
  extrapolatorController.site,
);
router.post(
  '/extrapolation-proposals/:id/approve',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  extrapolatorController.approve,
);
router.post(
  '/extrapolation-proposals/:id/reject',
  requireCapability(CAPABILITIES.TEMPLATE_WRITE),
  extrapolatorController.reject,
);

export default router;
