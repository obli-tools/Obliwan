import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { acsController } from '../controllers/acs.controller';
import { requireAuth } from '../middleware/auth';
import { requireTenant } from '../middleware/tenant';
import { requireCapability } from '../middleware/rbac';
import { deviceScopeGate } from '../middleware/teamScope';

/**
 * The ACS admin API. Mounted at `/api/acs`.
 *
 * ┌─ WHY THIS ROUTER CARRIES ITS OWN `requireAuth` + `requireTenant` ─────────┐
 * │ `routes/index.ts` is off limits to this milestone, so the mount lives in  │
 * │ `app.ts` — next to the Obligate SSO callback, which is mounted the same   │
 * │ way and for the same practical reason. A router mounted outside           │
 * │ `tenantRouter` gets neither middleware for free, so it declares both      │
 * │ here. Moving the mount into `routes/index.ts` later means DELETING these  │
 * │ two lines; leaving them in by accident is harmless (both are idempotent). │
 * │                                                                          │
 * │ Without them every handler would read `req.tenantId` as `undefined`, and  │
 * │ `assertDeviceInTenant()` would compare `tenant_id = undefined` — which    │
 * │ knex renders as a query that matches nothing. That fails CLOSED, but it   │
 * │ fails as "device not found" on every request, which is the worst kind of  │
 * │ correct.                                                                  │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ ONE CAPABILITY, AND WHY IT IS NOT SPLIT ─────────────────────────────────┐
 * │ Everything here is `ACS_ADMIN` — including the reads. That is a           │
 * │ deliberate departure from the two-capability shape of `/drift` and        │
 * │ `/query`, and the reason is what the ACS reads ARE: a CPE's parameter     │
 * │ tree is the customer's complete LAN topology, Wi-Fi configuration, DHCP   │
 * │ ranges and connected-host counts. There is no "safe" half of it to give   │
 * │ to a wider audience, and the catalogue entry for `ACS_ADMIN` is already   │
 * │ marked `sensitive: true`.                                                 │
 * │                                                                          │
 * │ The one thing an operator may want without ACS rights — "does the ACS     │
 * │ cover MikroTik?" — is answered by the shared constant                     │
 * │ `ACS_BRAND_COVERAGE`, which the client can render without calling         │
 * │ anything.                                                                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ NOTHING HERE WRITES TO AN EQUIPMENT ON ITS OWN ──────────────────────────┐
 * │ The mutating routes below all pass through the one task INSERT of         │
 * │ `task.service.ts` (`enqueueTask`, `requeueUnknownTask`), which refuses     │
 * │ without a `change_jobs` row. They are POSTs that create a QUEUED INTENT,  │
 * │ and they answer 202 with the sentence saying when it will run.            │
 * │ The single exception is `/refresh`, whose whitelist and justification are │
 * │ in `task.service.ts` next to the whitelist itself — and which writes      │
 * │ `PeriodicInformInterval` on the CPE OUTSIDE `change_jobs`, by design.     │
 * │                                                                          │
 * │ A write the CPE never answered is `unknown` and is NEVER re-sent by the   │
 * │ machine; `/tasks/:taskId/requeue` is the only way it goes out again.      │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
const router = Router();

router.use(requireAuth);
router.use(requireTenant);
// Team scope (migrations 084/087): a CPE is a device; outside the caller's
// teams it does not exist (404), and a write needs 'rw' on it. Mounted here
// because this router lives outside the `/api` table's gates (app.ts).
router.use('/devices/:deviceId', deviceScopeGate('deviceId'));

const acsAdmin = requireCapability(CAPABILITIES.ACS_ADMIN);

// ── The honest answer to "which brands does the ACS cover" ──────────────────
// Declared before any parameterised path so no literal is ever swallowed.
router.get('/coverage', acsAdmin, acsController.coverage);
router.get('/status', acsAdmin, acsController.status);

// ── Settings ────────────────────────────────────────────────────────────────
router.get('/settings', acsAdmin, acsController.getSettings);
router.patch('/settings', acsAdmin, acsController.updateSettings);

// ── The parameter map (shipped library + learned proposals) ────────────────
router.get('/param-map', acsAdmin, acsController.listMappings);
router.post('/param-map', acsAdmin, acsController.upsertMapping);
router.delete('/param-map/:id', acsAdmin, acsController.deleteMapping);

// ── Files available for Download ────────────────────────────────────────────
router.get('/files', acsAdmin, acsController.listFiles);

// ── Devices ─────────────────────────────────────────────────────────────────
router.get('/devices', acsAdmin, acsController.listDevices);
router.get('/devices/:deviceId', acsAdmin, acsController.getDevice);
router.post('/devices/:deviceId/enrol', acsAdmin, acsController.enrol);

router.get('/devices/:deviceId/parameters', acsAdmin, acsController.listParameters);
// For these two families the parameter tree IS the configuration: a Vigor
// `.cfg` is an opaque vendor blob and a Zyxel CPE exports nothing at all.
router.get('/devices/:deviceId/config', acsAdmin, acsController.configDocument);
router.get('/devices/:deviceId/tasks', acsAdmin, acsController.listTasks);
router.delete('/devices/:deviceId/tasks/:taskId', acsAdmin, acsController.cancelTask);
router.get('/devices/:deviceId/transfers', acsAdmin, acsController.listTransfers);

// Reads: no change job (a CWMP read is the equivalent of `/config/collect`).
router.post('/devices/:deviceId/read', acsAdmin, acsController.queueRead);
router.post('/devices/:deviceId/discover', acsAdmin, acsController.queueDiscovery);

// Writes: refused without a change job. The 409 names the door.
router.post('/devices/:deviceId/write', acsAdmin, acsController.queueWrite);
router.post('/devices/:deviceId/download', acsAdmin, acsController.queueDownload);
router.post('/devices/:deviceId/reboot', acsAdmin, acsController.queueReboot);
// A write whose outcome is `unknown` is never re-sent by the machine; this is
// the human door: a NEW task, a live change job, and `confirm: true`.
router.post('/devices/:deviceId/tasks/:taskId/requeue', acsAdmin, acsController.requeueTask);

// NOT a Connection Request. Answers `CwmpRefreshOutcome { supported: false }`.
router.post('/devices/:deviceId/refresh', acsAdmin, acsController.refresh);

// ── The envelope log (off by default, on twice to turn on) ──────────────────
router.get('/devices/:deviceId/rpc-log', acsAdmin, acsController.rpcLog);
router.put('/devices/:deviceId/rpc-log', acsAdmin, acsController.setRpcLog);

export default router;
