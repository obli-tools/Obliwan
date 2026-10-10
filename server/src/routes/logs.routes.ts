import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { logsController } from '../controllers/logs.controller';
import { requireCapability, requireRole } from '../middleware/rbac';
import { godViewParam } from '../utils/globalView';

/**
 * Logs, attribution and the reachability verdict.
 *
 * MOUNT: under the tenant-scoped router, at `/logs` — `requireAuth` and
 * `requireTenant` have already run by then.
 *
 * ┌─ FOUR CAPABILITIES, AND EACH SPLIT IS DELIBERATE ────────────────────────┐
 * │ SNMP_READ     the journal itself and its ingestion health. The same       │
 * │               capability as the series, because syslog and traps are the  │
 * │               same telemetry domain — pushed by the same devices, stored  │
 * │               in the same partitioned tables, read on the same incident   │
 * │               screen. Deliberately NOT `DEVICE_READ`: seeing that a       │
 * │               device exists is a different question from reading what it  │
 * │               logs (the same reasoning as CONFIG_READ).                   │
 * │                                                                          │
 * │ DRIFT_READ    login events and attributions. The capability catalogue     │
 * │               already says "drift runs, findings AND THEIR ATTRIBUTION" — │
 * │               attribution is what that sentence was written for.          │
 * │                                                                          │
 * │ DRIFT_MANAGE  recomputing an attribution. It can change a verdict that    │
 * │               has already been read: an `unattributed` becoming an        │
 * │               `attributed` puts a colleague's name on a change after the  │
 * │               fact. That is a decision, not a refresh.                    │
 * │                                                                          │
 * │ PLATFORM ADMIN  the unattributed feed. It is the ONE route here that     │
 * │               cannot be tenant-scoped — a sender we cannot tie to a       │
 * │               device cannot be tied to a tenant either — so it is         │
 * │               `requireRole('admin')`. It used to be AUDIT_READ, which the │
 * │               tenant admin set holds: every customer's claimed hostnames  │
 * │               shown to one customer. No tenant predicate is writable on   │
 * │               it, so no tenant may read it.                               │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * DEVICE_WRITE guards two routes, and not for symmetry. Enabling the
 * out-of-tunnel probe makes this server open scheduled TCP connections to a
 * customer's public address — an outbound action against somebody else's
 * network. Pulling `/log` off a box now talks to the customer's router over a
 * RouterOS API session opened with the vault credential (the routerosPool) —
 * the same class of act as test-connection and the on-demand health check
 * (devices.routes.ts), which are DEVICE_WRITE too.
 */
const router = Router();

// God view (utils/globalView.ts): a route naming ONE drift_runs row by `:runId`
// acts in that row's own tenant — read, write and audit alike. No-op for
// anyone but a platform admin positioned on the master tenant.
router.param('runId', godViewParam('drift_runs'));

// God view (utils/globalView.ts): a route naming ONE devices row by `:deviceId`
// acts in that row's own tenant — read, write and audit alike. No-op for
// anyone but a platform admin positioned on the master tenant.
router.param('deviceId', godViewParam('devices'));

// -- The unified journal ------------------------------------------------------
// Literal paths before parameterised ones, so `/logs/health` is never swallowed.
router.get('/health', requireCapability(CAPABILITIES.SNMP_READ), logsController.health);
router.get('/sources', requireCapability(CAPABILITIES.SNMP_READ), logsController.sources);
router.get('/unattributed', requireRole('admin'), logsController.unattributed);
router.get('/logins', requireCapability(CAPABILITIES.DRIFT_READ), logsController.logins);

// -- Attribution --------------------------------------------------------------
router.get(
  '/attributions',
  requireCapability(CAPABILITIES.DRIFT_READ),
  logsController.attributions,
);
router.get(
  '/attributions/runs/:runId',
  requireCapability(CAPABILITIES.DRIFT_READ),
  logsController.attributionForRun,
);
router.post(
  '/attributions/runs/:runId',
  requireCapability(CAPABILITIES.DRIFT_MANAGE),
  logsController.reattribute,
);

// -- The reachability verdict ------------------------------------------------
router.get(
  '/reachability/devices/:deviceId',
  requireCapability(CAPABILITIES.DEVICE_READ),
  logsController.verdict,
);
router.post(
  '/reachability/devices/:deviceId/assess',
  requireCapability(CAPABILITIES.DEVICE_READ),
  logsController.assess,
);
router.put(
  '/reachability/devices/:deviceId/external-probe',
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  logsController.setExternalProbe,
);

// One router's sources, quota and pull state (team-gated in routes/index.ts,
// god-view hopped by the `deviceId` param above).
router.get(
  '/devices/:deviceId/sources',
  requireCapability(CAPABILITIES.SNMP_READ),
  logsController.deviceSources,
);

// -- Pull `/log` off one box now ---------------------------------------------
// Like a collection, this DIALS THE EQUIPMENT. It reads and never writes, which
// is why it is not CHANGE_APPLY, but it is an action on someone's hardware and
// not a query against our database — so not SNMP_READ either, which reads what
// is already stored and is held by the viewer and the account manager, roles
// that dial nothing. DEVICE_WRITE, like test-connection
// and the on-demand health check.
router.post(
  '/devices/:deviceId/pull',
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  logsController.pull,
);

// The list is LAST: `/logs/` with no sub-path.
router.get('/', requireCapability(CAPABILITIES.SNMP_READ), logsController.list);

export default router;
