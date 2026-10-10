import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { rolloutsController } from '../controllers/rollouts.controller';
import { requireCapability } from '../middleware/rbac';
import { godViewBodyTenants, godViewParam } from '../utils/globalView';

/**
 * Wave rollouts. Mounted under the tenant-scoped router.
 *
 * LEAD: `tenantRouter.use('/rollouts', rolloutsRoutes);` in `routes/index.ts`,
 * next to `/changes`. It belongs on the same side of the line that file draws
 * at change apply: everything above `/changes` reads, compiles or proposes; `/changes`
 * and `/rollouts` are the only two prefixes from which this server can modify
 * somebody else's hardware. The difference between them is scale — `/changes`
 * writes to one box, `/rollouts` writes to a fleet in an order it chose.
 *
 * ┌─ THE CAPABILITY MAP ──────────────────────────────────────────────────────┐
 * │ PLAN_CREATE     read a rollout and PREVIEW one. The impact screen writes  │
 * │                 nothing: the same grant that lets you ask "what would     │
 * │                 ObliWAN change on these 40 boxes" lets you watch what it  │
 * │                 did.                                                      │
 * │ ROLLOUT_MANAGE  compose, launch, advance, pause, resume, abort. The grant │
 * │                 has existed from the start ("Start, pause and abort wave  │
 * │                 rollouts", sensitive: true) and this is what uses it.     │
 * │ CHANGE_APPROVE  checked a SECOND time inside `compose`, when the body     │
 * │                 carries an override. Forcing N devices past a             │
 * │                 Management-Path Guard refusal in one gesture must not     │
 * │                 ride in on the grant that merely starts rollouts.         │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * WHAT IS DELIBERATELY ABSENT: nothing here edits a composed rollout's
 * membership or wave order. The safety-net rule's "degraded last" and the concentrator interlock's subtree
 * interlock are decided once, at composition, in front of the operator — and
 * migration 010 refuses the rows that would break either. A `PATCH /waves/:i`
 * would exist for no other purpose than to defeat both.
 *
 * There is also no `POST /rollouts/:id/rollback`, and nothing rolls a rollout
 * back automatically either. A FAILED HEALTH GATE stops the rollout,
 * quarantines its revision and lists every device that took the change « À
 * remettre en arrière » (`rollout.service.stopPushRollout`): it is undone by
 * a rollout of the previous revision to those devices; the push job's
 * pre-change backup beside each one is a record, which no operation in
 * ObliWAN loads onto a router. There is no restore job to queue —
 * `restore` has no renderer and the queue refuses it (apply.service.ts,
 * UNIMPLEMENTED_WRITE_KINDS) — and the automatic one that used to be queued
 * rebooted every landed router while restoring nothing.
 */
const router = Router();

// God view (utils/globalView.ts): a route naming ONE rollouts row by `:id`
// acts in that row's own tenant — read, write and audit alike. No-op for
// anyone but a platform admin positioned on the master tenant.
router.param('id', godViewParam('rollouts'));

/**
 * `GET /rollouts/config` — "can this build actually launch a wave rollout?"
 *
 * ┌─ THIS ROUTE DID NOT EXIST, AND THE UI PAID FOR IT ───────────────────────┐
 * │ `rolloutApi.config()` fails CLOSED on purpose — a client that decided for │
 * │ itself that launching is possible would queue N writes against a server   │
 * │ with no runner behind it. But the endpoint it asks was never written, so  │
 * │ the fallback was not a safety net, it was the permanent answer: the        │
 * │ Rollouts screen has been telling every operator "M7" since it shipped,    │
 * │ over a compose / launch / advance / pause / resume surface that is all     │
 * │ there and all reachable.                                                   │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * `canLaunch` is NOT hard-coded to true. It is `changeExecutorReadiness()` —
 * the same check that logs at boot — because a rollout is N writes and a build
 * with no registered renderer refuses every one of them at the apply step. A
 * screen that offered to launch anyway would fail forty devices in one gesture
 * to discover something the server already knew. `blockedReason` carries the
 * server's own sentence so the UI does not have to invent one.
 *
 * Declared before `/:id` so the literal path is not swallowed by the parameter.
 */
router.get('/config', requireCapability(CAPABILITIES.PLAN_CREATE), rolloutsController.config);

// ── Reads, and the impact screen ─────────────────────────────────────────────
router.get('/', requireCapability(CAPABILITIES.PLAN_CREATE), rolloutsController.list);
// Literal path before the parameterised one, so `/preview` can never be
// swallowed as a rollout id.
// In the god view a new rollout is composed in the tenant of its routers.
router.post('/preview', requireCapability(CAPABILITIES.PLAN_CREATE), godViewBodyTenants('devices', 'deviceIds'), rolloutsController.preview);
router.get('/:id', requireCapability(CAPABILITIES.PLAN_CREATE), rolloutsController.get);

// ── Composition ──────────────────────────────────────────────────────────────
router.post('/', requireCapability(CAPABILITIES.ROLLOUT_MANAGE), godViewBodyTenants('devices', 'deviceIds'), rolloutsController.compose);

// ── The gestures that move a fleet ───────────────────────────────────────────
router.post(
  '/:id/launch',
  requireCapability(CAPABILITIES.ROLLOUT_MANAGE),
  rolloutsController.launch,
);
router.post(
  '/:id/advance',
  requireCapability(CAPABILITIES.ROLLOUT_MANAGE),
  rolloutsController.advance,
);
router.post(
  '/:id/pause',
  requireCapability(CAPABILITIES.ROLLOUT_MANAGE),
  rolloutsController.pause,
);
router.post(
  '/:id/resume',
  requireCapability(CAPABILITIES.ROLLOUT_MANAGE),
  rolloutsController.resume,
);
router.post(
  '/:id/abort',
  requireCapability(CAPABILITIES.ROLLOUT_MANAGE),
  rolloutsController.abort,
);

export default router;
