import { Router } from 'express';
import { requireAuth } from '../middleware/auth';
import { requireTenant } from '../middleware/tenant';
import {
  deviceScopeGate,
  bodyDeviceScopeGate,
  siteScopeGate,
  rowScopeGate,
  simLineScopeGate,
  bodySiteIdsScopeGate,
  bodyDeviceIdsScopeGate,
  bodySimLineScopeGate,
  bodyRowScopeGate,
  bodySiteScopeGate,
  requireEveryDeviceWritable,
  readOnlyAction,
  requireUngroupedGrant,
  requireEverySiteWritable,
  requireDevicePlacementInScope,
} from '../middleware/teamScope';
import { validate } from '../middleware/validate';
import { requireApprovedBenchStation } from '../middleware/benchStation';
import {
  benchEnrolmentContext,
  benchEnrolmentLimiter,
  benchEnrolmentSchema,
} from '../middleware/benchEnrolment';
import { devicesController } from '../controllers/devices.controller';
import authRoutes from './auth.routes';
import obligateCallbackRoutes from './obligateCallback.routes';
import tenantRoutes from './tenant.routes';
import groupsRoutes from './groups.routes';
import settingsRoutes from './settings.routes';
import notificationsRoutes from './notifications.routes';
import usersRoutes from './users.routes';
import profileRoutes from './profile.routes';
import teamsRoutes from './teams.routes';
import smtpServerRoutes from './smtpServer.routes';
import appConfigRoutes from './appConfig.routes';
import twoFactorRoutes from './twoFactor.routes';
import permissionSetsRoutes from './permissionSets.routes';
import importExportRoutes from './importExport.routes';
import systemRoutes from './system.routes';
import benchRoutes from './bench.routes';
import { benchStationAdminRoutes, benchStationSelfRoutes } from './benchStations.routes';
import { benchApiRoutes } from './benchApi.routes';
import allocationRoutes from './allocation.routes';
import concentratorLinkRoutes from './concentratorLink.routes';
import infraConcentratorRoutes from './infraConcentrator.routes';
import { liveAlertRouter } from './liveAlert.routes';
import sitesRoutes from './sites.routes';
import reconcileRoutes from './reconcile.routes';
import devicesRoutes from './devices.routes';
import autoConfirmRoutes from './autoConfirm.routes';
import managementAccessRoutes from './managementAccess.routes';
import lteApnRoutes from './lteApn.routes';
import legacyComplianceRoutes from './legacyCompliance.routes';
import wanLinkRoutes from './wanLink.routes';
import siteRenameRoutes from './siteRename.routes';
import discoveriesRoutes from './discoveries.routes';
import snmpRoutes from './snmp.routes';
import backupsRoutes from './backups.routes';
import configRoutes from './config.routes';
import driftRoutes from './drift.routes';
import templatesRoutes from './templates.routes';
import variablesRoutes from './variables.routes';
import tenantSetupRoutes from './tenantSetup.routes';
import infraAnalysisRoutes from './infraAnalysis.routes';
import learningRoutes from './learning.routes';
import planRoutes from './plan.routes';
import changesRoutes from './changes.routes';
import intentRoutes from './intent.routes';
import baselineRoutes from './baseline.routes';
import exceptionsRoutes from './exceptions.routes';
import attestationRoutes from './attestation.routes';
import interventionsRoutes from './interventions.routes';
import aftermathRoutes from './aftermath.routes';
import weatherRoutes from './weather.routes';
import operatorOutageRoutes from './operatorOutage.routes';
import identityRoutes from './identity.routes';
import slaRoutes from './sla.routes';
import lifecycleRoutes from './lifecycle.routes';
import simRoutes from './sim.routes';
import rolloutsRoutes from './rollouts.routes';
import osUpgradeRoutes from './osUpgrade.routes';
import firmwareRoutes from './firmware.routes';
import logsRoutes from './logs.routes';
import queryRoutes from './query.routes';
import secretRevealRoutes from './secretReveal.routes';
import tlsRepinRoutes from './tlsRepin.routes';
import fleetAnomaliesRoutes from './fleetAnomalies.routes';
import lineQualityRoutes from './lineQuality.routes';

/**
 * The `/api` route table. Every milestone's surface is mounted here except the
 * ACS admin API, which `app.ts` mounts straight onto the app at `/api/acs`, and
 * the Obligate callback, mounted both here and at `/auth` outside `/api`.
 * Nothing is stubbed: a route that answers an empty array is
 * indistinguishable, from the client, from a fleet that has nothing in it.
 *
 * TWO SECTIONS, AND WHICH ONE A ROUTER GOES IN IS A SECURITY DECISION.
 * `tenantRouter`, at the bottom, runs `requireAuth` then `requireTenant` before
 * anything under it. The global section runs neither: each router there brings
 * its own guard (`requireAuth` + `requireRole('admin')`, a bench token), and a
 * few are public on purpose (login under `/auth`, `/bench`, the workstation
 * registration). A router mounted globally that forgets its guard is open; one
 * mounted under `tenantRouter` that a workstation must reach is closed to it —
 * the second is how bench enrolment never worked (see `/devices/enroll` below).
 */
const router = Router();

// -- Global (no tenant required) ---------------------------------------------
router.use('/auth', authRoutes);
router.use('/auth', obligateCallbackRoutes);  // Obligate SSO: sso-config, connected-apps, app-info
// NOT /admin/*: Oblihub's WAF bans a caller on an /api/admin/ path, and
// Obliance — which is not banned — has no such mount either. The prefix was
// decoration; the authorisation is inside these routers and is unchanged.
router.use('/app-config', appConfigRoutes);
router.use('/system', systemRoutes);          // system info / about (admin only)
// RouterOS releases + fleet target version. Instance-level, so NOT under
// `tenantRouter`: the router installs `requireAuth` itself (reads: any user)
// and `requireRole('admin')` on the writes (platform admin, not a capability).
router.use('/firmware', firmwareRoutes);

// -- Bench workstations ------------------------------------------------------
// The workstation's OWN half: `POST /bench/stations/register` (public — a desk
// has nothing to authenticate with before it registers; its control is
// `benchStationRegisterLimiter` and MAX_PENDING_STATIONS) and
// `GET /bench/stations/me` (its own `Bench <token>`, pending or approved).
// Global, not under `tenantRouter`: a workstation has no session, and
// `tenantRouter`'s `requireAuth` would answer 401 before the router ran.
// Mounted BEFORE `/bench` so the longer prefix is settled first: `benchRoutes`
// has no matching route and no router-level middleware today, so the order
// changes nothing now — it keeps anything later added to `/bench` (a limiter,
// a catch-all) from silently running in front of registration.
router.use('/bench/stations', benchStationSelfRoutes);

// The bench application's API (`/bench/v1/*`): tenants, sites, plan, compile and
// the apply result. Authenticated by the workstation's `Bench <token>`, NOT by
// the session: `requireApprovedBenchStation` is installed inside the router, so
// only an APPROVED station gets through, and only for paths under `/bench/v1`.
// Global for the same reason as the line above (`tenantRouter`'s `requireAuth`
// would answer 401 first), and BEFORE `/bench` so the longer prefix is settled
// first. It adds no middleware in front of any other `/api` route.
router.use('/bench/v1', benchApiRoutes);

// Bench tool version + signed installer. Unauthenticated on purpose: a
// workstation being set up has no session, and cannot hold a station token
// before it even has the tool. What is served is a signed published artefact,
// not fleet data. Enrolment (`/devices/enroll`, further down) is NOT
// unauthenticated: it used to be described as "the same decision", and that is
// no longer true.
router.use('/bench', benchRoutes);

// The platform ADMINISTRATOR's half: list, approve, revoke. Authenticated
// inside the router (`requireAuth` + `requireRole('admin')`), like `/system`:
// stations are platform-scoped, a desk prepares routers for every customer, so
// no tenant owns one and `requireTenant` would only lock out a platform admin
// with no current tenant. Its own prefix, not `/bench/stations/...`, so the
// public and the admin halves can never share a router-level middleware.
router.use('/bench-stations', benchStationAdminRoutes);

// -- Address allocation (phase A) ----------------------------------------------
// Platform-scoped allocation administration: the shared address pools, the
// installation's domain, whether a concentrator's /ppp/secret has been read
// (its seed status), each tenant's tunnel/LAN/PPP-username policy and its
// preview, and the per-site read. A pool may serve several tenants and the
// domain is one value for everybody, so no tenant owns any of it: every route
// is `requireAuth` + `requireRole('admin')` inside the router
// (allocation.routes.ts), never a capability `TENANT_ROLE_CAPABILITIES` would
// hand to a tenant admin, and it sits here rather than under `tenantRouter`,
// whose `requireTenant` would only lock out a platform admin with no current
// tenant. Where a route names a tenant, the tenant is a PATH PARAMETER. No
// route here returns a PPP password, and allocating a site has no route at
// all: `allocateForSite` is for server-side callers, and none calls it yet.
router.use('/allocation', allocationRoutes);

// The ObliWAN <-> CHR WireGuard link: platform admin + CHANGE_APPLY inside the router (concentratorLink.routes.ts).
// The CHR is shared infrastructure, so there is no requireTenant.
router.use('/concentrators', concentratorLinkRoutes);

// Each customer's INFRASTRUCTURE VPN concentrator (a RouterOS CHR or an OPNsense):
// platform admin inside the router (infraConcentrator.routes.ts); the tenant is a path parameter.
router.use('/infra-concentrators', infraConcentratorRoutes);

// Bench DEVICE enrolment. Here, in the global section, and not under
// `tenantRouter` with the rest of `/devices`: a workstation has no session, so
// `tenantRouter`'s `requireAuth` answered 401 to every bench call before any
// bench middleware ran, and enrolment never worked. Being out here does not
// make it anonymous — `requireApprovedBenchStation` demands the token of a
// workstation a platform administrator approved, and the device still lands
// `pending` + unmanaged in the master tenant (see middleware/benchEnrolment.ts).
// The guard runs BEFORE the limiter so the limiter can key on the station.
// Registered before `router.use('/', tenantRouter)` at the bottom, so this one
// path answers here; every other `/devices/*` route still falls through to the
// tenant-scoped router.
router.post(
  '/devices/enroll',
  requireApprovedBenchStation,
  benchEnrolmentLimiter,
  validate(benchEnrolmentSchema),
  benchEnrolmentContext,
  devicesController.enroll,
);

router.use('/profile/2fa', twoFactorRoutes);  // must be mounted before /profile
// Your own account is not tenant-scoped: reading your profile or changing your
// password must work before you belong to anything. This lived under tenantRouter,
// which was harmless only as long as the `?? 1` fallback gave every session a
// tenant; removing that fallback turned it into a lockout. profile.routes.ts
// carries its own requireAuth and reads no req.tenantId.
router.use('/profile', profileRoutes);
router.use('/live-alerts', liveAlertRouter);
router.use('/permission-sets', permissionSetsRoutes);
router.use('/import-export', importExportRoutes);   // GET /import-export/export, POST /import-export/import

// -- Tenant management --------------------------------------------------------
router.use('/tenants', tenantRoutes);
router.use('/tenant', tenantRoutes);

// -- Tenant-scoped routes (requireAuth + requireTenant) ------------------------
const tenantRouter = Router();
tenantRouter.use(requireAuth);
tenantRouter.use(requireTenant);

// -- Team scope (migration 084, Obliance's model) ------------------------------
// WHERE a user may act: a non-admin sees and writes only the devices, sites and
// SIM lines their teams cover ('ro' / 'rw' on a group down the closure, on a
// device, or on the ungrouped bucket). Mounted HERE, on the URL prefixes that
// address one object, so every route below them — including one added later —
// is scoped without being edited (middleware/teamScope.ts has the rule). The
// capability on each route still decides WHAT; both must pass.
tenantRouter.use('/devices/:deviceId', deviceScopeGate('deviceId'));
tenantRouter.post('/devices', requireDevicePlacementInScope());
tenantRouter.patch('/devices/:deviceId', requireDevicePlacementInScope());
tenantRouter.use('/sites/:siteId', siteScopeGate('siteId'));
tenantRouter.post('/sites', requireEverySiteWritable());
tenantRouter.post('/sites/import', requireEverySiteWritable());
tenantRouter.post('/sites/bulk/uplink-kind', bodySiteIdsScopeGate('ids'));
tenantRouter.post('/sites/bulk/fixed-provider', bodySiteIdsScopeGate('ids'));
// Opening hours (096): a bulk write names its sites; the workspace's hours
// reach every site, so they need rw on every site, like a create or an import.
tenantRouter.post('/sites/bulk/opening-hours', bodySiteIdsScopeGate('ids'));
tenantRouter.put('/sites/opening-hours', requireEverySiteWritable());
// The bulk site rename (site_rename jobs, platform admins only) names sites in its body.
tenantRouter.post(['/devices/site-rename/bulk', '/devices/site-rename/bulk/preview'], bodySiteIdsScopeGate('siteIds'));
tenantRouter.use('/config/devices/:deviceId', deviceScopeGate('deviceId'));
tenantRouter.use('/config/snapshots/:snapshotId', rowScopeGate('config_snapshots', 'snapshotId'));
tenantRouter.use('/snmp/devices/:deviceId', deviceScopeGate('deviceId'));
tenantRouter.use('/snmp/interfaces/:ifId', rowScopeGate('snmp_interfaces', 'ifId'));
tenantRouter.use('/logs/devices/:deviceId', deviceScopeGate('deviceId'));
tenantRouter.use('/logs/reachability/devices/:deviceId', deviceScopeGate('deviceId'));
tenantRouter.use('/drift/devices/:deviceId', deviceScopeGate('deviceId'));
tenantRouter.use('/identity/devices/:deviceId', deviceScopeGate('deviceId'));
tenantRouter.use('/sim/devices/:deviceId', deviceScopeGate('deviceId'));
tenantRouter.use('/line-quality/devices/:deviceId', deviceScopeGate('deviceId'));
tenantRouter.use('/sim/lines/:lineId', simLineScopeGate('lineId'));
tenantRouter.use('/variables/sites/:siteId', siteScopeGate('siteId'));
tenantRouter.use('/variables/devices/:deviceId', deviceScopeGate('deviceId'));
// A plan compile and a change preview touch no equipment: 'ro' suffices.
tenantRouter.use('/plan/devices/:deviceId', deviceScopeGate('deviceId', { level: 'ro' }));
tenantRouter.post('/changes/preview', bodyDeviceScopeGate('deviceId', { level: 'ro' }));
tenantRouter.post('/changes/jobs', bodyDeviceScopeGate('deviceId'));

// -- Team scope, every remaining area (migration 087) --------------------------
// Same rule as above, for the rows that hang off a device, a site, a SIM line
// or a rollout's devices, and for the bodies that name devices. A POST that
// only READS gets `readOnlyAction()` BEFORE the generic gate of its prefix.
// Rows addressed by their own id (judged on the object they hang off):
tenantRouter.use('/changes/jobs/:jobId', rowScopeGate('change_jobs', 'jobId'));
tenantRouter.use('/rollouts/:rolloutId', rowScopeGate('rollouts', 'rolloutId'));
tenantRouter.use('/drift/runs/:runId', rowScopeGate('drift_runs', 'runId'));
tenantRouter.use('/logs/attributions/runs/:runId', rowScopeGate('drift_runs', 'runId'));
tenantRouter.use('/drift/findings/:findingId', rowScopeGate('drift_findings', 'findingId'));
tenantRouter.use('/interventions/devices/:deviceId', deviceScopeGate('deviceId'));
tenantRouter.use('/interventions/:interventionId', rowScopeGate('interventions', 'interventionId'));
tenantRouter.use('/exceptions/:exceptionId', rowScopeGate('drift_exceptions', 'exceptionId'));
tenantRouter.use('/aftermath/:aftermathId', rowScopeGate('change_aftermath', 'aftermathId'));
tenantRouter.use('/identity/events/:eventId', rowScopeGate('device_identity_events', 'eventId'));
// Verifying or comparing an attestation reads it.
tenantRouter.post(['/attestations/:uuid/verify', '/attestations/:uuid/compare'], readOnlyAction());
tenantRouter.use('/attestations/:uuid', rowScopeGate('attestations', 'uuid'));
tenantRouter.use('/sla/reports/:reportId', rowScopeGate('sla_reports', 'reportId'));
tenantRouter.use('/sim/recharges/:rechargeId', rowScopeGate('sim_recharges', 'rechargeId'));
// Device and site prefixes of other routers:
tenantRouter.use('/templates/devices/:deviceId', deviceScopeGate('deviceId'));
tenantRouter.use('/lifecycle/devices/:deviceId', deviceScopeGate('deviceId'));
tenantRouter.use('/weather/devices/:deviceId', deviceScopeGate('deviceId'));
tenantRouter.use('/sla/objectives/sites/:siteId', siteScopeGate('siteId'));
tenantRouter.use('/sla/sites/:siteId', siteScopeGate('siteId'));
// An assessment of reachability recomputes a verdict and writes nothing to the device.
tenantRouter.post('/logs/reachability/devices/:deviceId/assess', readOnlyAction());
// Bodies that name a LIST of devices: every one must be in the caller's teams
// (404 otherwise); a preview reads, a launch needs 'rw' on all of them.
tenantRouter.post(
  ['/changes/preflight', '/rollouts/preview', '/devices/legacy-compliance/preview',
    '/devices/management-access/preview', '/devices/wan-link/preview', '/os-upgrade/preview', '/plan/compile',
    '/intent/:intentId/compile'],
  bodyDeviceIdsScopeGate('deviceIds', { level: 'ro' }),
);
tenantRouter.post(
  ['/rollouts', '/devices/legacy-compliance/rollouts', '/devices/management-access/rollouts',
    '/devices/wan-link/rollouts', '/os-upgrade', '/os-upgrade/refresh-versions'],
  bodyDeviceIdsScopeGate('deviceIds', { level: 'rw' }),
);
// Bodies that name ONE object:
tenantRouter.post('/sim/recharges', bodySimLineScopeGate('simId'));
tenantRouter.post(['/query/policies/evaluate', '/templates/preview'], bodyDeviceScopeGate('deviceId', { level: 'ro' }));
tenantRouter.post(['/interventions', '/exceptions', '/discoveries/:discoveryId/bind'], bodyDeviceScopeGate('deviceId'));
tenantRouter.post('/exceptions', bodyRowScopeGate('drift_findings', 'findingId'));
// An attestation is built from one device's history; an SLA report from one site's.
tenantRouter.post(['/attestations/preview', '/attestations/issue'], bodyDeviceScopeGate('deviceId', { level: 'ro' }));
tenantRouter.post('/sla/reports', bodySiteScopeGate('siteId', { level: 'ro' }));
// A site-bound intent follows its site (one filed on no site is tenant-level);
// compiling one only reads. Filing an intent on a site needs 'rw' on it.
tenantRouter.post('/intent/:intentId/compile', readOnlyAction());
tenantRouter.use('/intent/:intentId', rowScopeGate('site_intents', 'intentId'));
tenantRouter.post('/intent', bodySiteScopeGate('siteId'));
tenantRouter.patch('/intent/:intentId', bodySiteScopeGate('siteId'));
// Workspace-wide bookkeeping sweeps: whole-tenant writers only, or one named device.
tenantRouter.post('/interventions/sweep', bodyDeviceScopeGate('deviceId'), requireEveryDeviceWritable({ unlessBodyField: 'deviceId' }));
tenantRouter.post('/aftermath/sweep', requireEveryDeviceWritable());
// Objects filed nowhere yet: the PPP quarantine and the syslog sources no
// device claims belong to the ungrouped bucket; a bind that CREATES a device
// is judged on where it would be filed.
tenantRouter.use('/discoveries', requireUngroupedGrant('auto'));
tenantRouter.post('/discoveries/:discoveryId/bind', requireDevicePlacementInScope({ pick: (b) => b.device }));
tenantRouter.get('/logs/unattributed', requireUngroupedGrant('ro'));

tenantRouter.use('/groups', groupsRoutes);
tenantRouter.use('/settings', settingsRoutes);
tenantRouter.use('/notifications', notificationsRoutes);
tenantRouter.use('/users', usersRoutes);
tenantRouter.use('/teams', teamsRoutes);
tenantRouter.use('/smtp-servers', smtpServerRoutes);

// -- Revealing a stored secret (SECRET_READ) ----------------------------------
// The four `POST …/reveal` routes: `/variables/reveal`,
// `/devices/:id/transports/:transport/reveal`, `/snmp/credentials/:id/reveal`
// and `/sim/lines/:id/reveal`. Mounted WITHOUT a prefix and BEFORE `/devices`,
// `/snmp`, `/variables` and `/sim`, so the routers that own those prefixes can
// never answer these paths first; none of them declares a POST that matches
// today, and none has router-level middleware. The router itself has no
// `router.use()` either — it sees every tenant-scoped request — so each guard
// (no-store, SECRET_READ, plus CREDENTIAL_MANAGE for an SNMP credential and
// SIM_READ for a SIM line, HTTPS, the per-user limiter, platform admin for
// instance variables and for the master tenant) is declared on its route
// (secretReveal.routes.ts). Every reveal is written to `audit_log`.
tenantRouter.use(secretRevealRoutes);

// -- Fleet --------------------------------------------------------------------
// Tenant-scoped like everything above. `discoveries` carries no tenant column of
// its own (quarantine is pre-tenant, migration 002), so its controller scopes
// through the concentrator instead of through a WHERE clause.
tenantRouter.use('/sites', sitesRoutes);
// The session tenant's OWN CHR <-> sites reconciliation (RECONCILE_READ):
// redacted, refused when its login template names no tenant. The full report
// of any tenant stays `/allocation` (platform admin), above.
tenantRouter.use('/reconcile', reconcileRoutes);
// The automatic conformity check of a bench-prepared device (migration 049):
// GET /devices/:id/auto-confirm (DEVICE_READ; without CONFIG_READ the server
// strips the semKeys, values, exclusions and snapshot id) and
// POST /devices/:id/auto-confirm/recheck (DEVICE_WRITE + CONFIG_WRITE, its own
// rate limit, 409 when BENCH_AUTO_CONFIRM_ENABLED=false). BEFORE devicesRoutes,
// so no route of that router can answer these two paths first.
tenantRouter.use('/devices', autoConfirmRoutes);
// management-access (API-SSL): /devices/management-access/* must win over devices' /:id.
tenantRouter.use('/devices', managementAccessRoutes);
// lte-apn (an lte_apn change job): /devices/:id/lte-apn.
tenantRouter.use('/devices', lteApnRoutes);
// legacy-compliance (the corrected-template fixes, a legacy_compliance job):
// /devices/legacy-compliance/* must win over devices' /:id.
tenantRouter.use('/devices', legacyComplianceRoutes);
// wan-link (the WAN1 link change, a wan_link job): /devices/:id/wan-link.
tenantRouter.use('/devices', wanLinkRoutes);
// site-rename (renaming a site's router, a site_rename job; platform admins):
// /devices/site-rename/* must win over devices' /:id.
tenantRouter.use('/devices', siteRenameRoutes);
// Re-pin a RouterOS API certificate to the one the device presented
// (CREDENTIAL_MANAGE; platform admin for a concentrator): /devices/:id/transports/routeros_api/repin.
tenantRouter.use('/devices', tlsRepinRoutes);
tenantRouter.use('/devices', devicesRoutes);
tenantRouter.use('/discoveries', discoveriesRoutes);
// Fleet anomalies (read-only audit of what is stored; DEVICE_READ).
tenantRouter.use('/fleet-anomalies', fleetAnomaliesRoutes);
// Line quality of the stores' fixed lines (nightly pings; DEVICE_READ).
tenantRouter.use('/line-quality', lineQualityRoutes);

// -- Telemetry ----------------------------------------------------------------
// Tenant-scoped like the fleet above. `snmp_interfaces`, `snmp_if_samples` and
// the rollups carry no tenant column of their own -- the series tables
// deliberately have no foreign key at all (study 1.1b) -- so the controller
// scopes through `devices` on every single read. That is the ONLY thing
// standing between one customer and another customer's traffic graphs.
tenantRouter.use('/snmp', snmpRoutes);

// -- Configuration & drift ----------------------------------------------------
// `config_snapshots`, the ten `ncm_*` tables, `drift_runs` and `drift_findings`
// carry NO tenant column: the scoping goes through `devices` on every single
// read, exactly as the SNMP series tables above. That join is the only thing
// standing between one customer and another customer's firewall.
//
// Drift is READ-ONLY: nothing under these two prefixes proposes a
// remediation, compiles a plan or writes to an equipment. The one route that
// touches the fleet at all (`POST /config/devices/:id/collect`) runs
// `/export terse show-sensitive=no` and nothing else, and sits behind
// CONFIG_WRITE for that reason.
// Pre-change backups. READ ONLY, and it never returns the archive's
// encryption password nor its storage path — see the box in backups.routes.ts.
tenantRouter.use('/backups', backupsRoutes);
tenantRouter.use('/config', configRoutes);
tenantRouter.use('/drift', driftRoutes);

// -- Templates, variables and plans -------------------------------------------
// Still nothing writes to an equipment: `/plan` COMPILES a plan and stores it,
// applying one goes through the change queue. `TEMPLATE_WRITE` is the
// template-injection security boundary —
// it is the capability that lets a caller make this server evaluate template
// code, on the process that holds the whole fleet's admin credentials.
tenantRouter.use('/templates', templatesRoutes);
tenantRouter.use('/variables', variablesRoutes);
// Quick Setup Tenant: platform admin, on the session's current workspace
// (the router installs requireRole('admin')).
tenantRouter.use('/tenant-setup', tenantSetupRoutes);
// Infrastructure analysis: the session workspace's routers read (read-only)
// for the site values their templates declare probes for; platform admin
// (the router installs requireRole('admin')).
tenantRouter.use('/infra-analysis', infraAnalysisRoutes);
// Learning mode (the documented exception to the no-secrets rule): routers in learning refuse
// template-driven writes; a capture reads them WITH their secrets (to the
// vault, redacted copies kept). Platform admin (the router installs
// requireRole('admin')).
tenantRouter.use('/learning', learningRoutes);
tenantRouter.use('/plan', planRoutes);

// -- Change jobs --------------------------------------------------------------
// THE LINE THIS FILE CROSSES HERE. Everything mounted above reads, compiles or
// proposes; nothing under any other prefix can make this server modify somebody
// else's hardware. `/changes` can, and it is the only one — the rule is that nothing
// writes to an equipment outside `change_jobs`, and this mount is where that
// sentence becomes a route table.
//
// The capabilities are split inside `changes.routes.ts` and the split is not
// cosmetic: `CHANGE_APPLY` asks for a change, `CHANGE_APPROVE` overrules the
// Management-Path Guard, and `SETTINGS_MANAGE` releases the kill switch.
// Enqueuing with an override demands the first two together.
//
// Tenant-scoped like everything above. `command_audit` and `apply_outcomes`
// carry NO foreign key to `tenants` at all (they must outlive an offboarding),
// so the tenant filter in their controllers is the only isolation they have.
tenantRouter.use('/changes', changesRoutes);

// -- Waved rollouts ------------------------------------------------------------
// The second thing in the product that can modify somebody else's hardware, and
// it does so at scale. It still writes through change_jobs like everything else
// (the change-queue rule): a rollout never applies anything itself, it enqueues jobs wave by wave.
//
// Two refusals live under here and both are enforced by the DATABASE, not by the
// controller: a wave cannot be queued without a health baseline captured BEFORE
// it, and a concentrator can never share an active rollout with its own children
// (a concentrator that drops mid-soak leaves N armed dead-men nobody can
// disarm, and N good changes revert themselves).
tenantRouter.use('/rollouts', rolloutsRoutes);

// -- Fleet OS upgrade ("mise à jour du parc") ----------------------------------
// The listing is read-only. A launch ends in routers rebooting, and it gets
// there ONLY through the change queue: one `os_upgrade` job, or a rollout
// of them wave by wave. Capabilities are per route (osUpgrade.routes.ts).
tenantRouter.use('/os-upgrade', osUpgradeRoutes);

// -- Logs, attribution and reachability ----------------------------------------
// Read-only. Attribution answers "who changed this", and its most important
// answer is "unattributed": naming the wrong person is worse than naming nobody,
// because a name gets believed.
tenantRouter.use('/logs', logsRoutes);

// -- Fleet Query ---------------------------------------------------------------
// Turns user text into SQL over the ncm jsonb. The path whitelist is generated
// from the NCM Zod schemas and is a CORRECTNESS guard; the injection guard is the
// bound parameter, and nothing else.
tenantRouter.use('/query', queryRoutes);

// -- Intent Compiler -----------------------------------------------------------
// Compiles a site intent into the NCM of a specific box, and REFUSES at
// compilation — before any socket, session or credential — when the hardware
// cannot do what the intent asks. Applying the result still goes through
// change_jobs: this prefix produces documents, never packets.
tenantRouter.use('/intent', intentRoutes);

// -- Fleet takeover / Golden Site ----------------------------------------------
// Read-only mining of existing snapshots into template drafts. It proposes; a
// human publishes. Nothing here writes to a device or to a published revision.
tenantRouter.use('/baseline', baselineRoutes);

// -- Evidence: justified drift exceptions + attestations ------------------
// An exception REQUIRES a justification and a review date, both enforced by CHECK
// constraints rather than by validation: the point is that an unjustified
// exception cannot exist, not that we decline to create one. "Expired" is derived,
// so a stale exception hands its drift back instead of hiding it forever.
tenantRouter.use('/exceptions', exceptionsRoutes);
tenantRouter.use('/attestations', attestationRoutes);

// -- Intervention mode and change aftermath -------------------------------
// An open intervention is NOT a permission to write: nothing under here bypasses
// the change queue. It brackets a human's work so that the drift it produces is attributed to
// it instead of surfacing as an anomaly.
tenantRouter.use('/interventions', interventionsRoutes);
tenantRouter.use('/aftermath', aftermathRoutes);

// -- Operator weather -----------------------------------------------------
// Correlation, never a single-site verdict. The public address it reasons on is
// the one the CONCENTRATOR observed in the PPP caller-id — an outside observation
// that stays true behind NAT — and never an address a device claims for itself.
tenantRouter.use('/weather', weatherRoutes);
// The grouped operator outage (migration 095): one alert when several stores
// of the same provider lose their fixed line at once. Read only.
tenantRouter.use('/operator-outages', operatorOutageRoutes);

// -- Identity, availability and lifecycle -------------------------------------
// All three READ. None of them writes to a device, and none of them corrects
// anything on its own: a hardware replacement is SIGNALLED (the old snapshot
// stops being a trustworthy baseline and says so) rather than silently retired.
tenantRouter.use('/identity', identityRoutes);
tenantRouter.use('/sla', slaRoutes);
tenantRouter.use('/lifecycle', lifecycleRoutes);

// -- Mobile data lines / SIM fleet --------------------------------------------
// The partner ACCOUNTS under this prefix are platform-scoped and hold a
// credential, so `/sim/accounts/*` is guarded by requireRole('admin') inside the
// router — not by a capability, which `TENANT_ROLE_CAPABILITIES` would hand to
// the admin of any tenant. Everything else is tenant-scoped on SIM_READ /
// SIM_MANAGE / SIM_RECHARGE, and SIM_RECHARGE is the only capability in this
// product that commits a purchase.
//
// The change queue is not engaged: nothing here opens a session on an equipment.
tenantRouter.use('/sim', simRoutes);

router.use('/', tenantRouter);

export { router as routes };
