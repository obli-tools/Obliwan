import './env';
import http from 'http';
import { createApp } from './app';
import { createSocketServer } from './socket';
import { db } from './db';
import { config, validateConfig } from './config';
import { logger } from './utils/logger';
import { authService } from './services/auth.service';
import { groupService } from './services/group.service';
import { setLiveAlertIO } from './services/liveAlert.service';
import { leaderElection } from './services/leaderElection';
import { assertVaultUsable } from './services/secretVault.service';
import { obligateService } from './services/obligate.service';
import { startFleetRuntime, stopFleetRuntime } from './services/fleet';
import {
  startHealthCheckRuntime,
  stopHealthCheckRuntime,
} from './services/fleet/healthCheck.service';
import { startClosedStoreRuntime, stopClosedStoreRuntime } from './services/fleet/closedStoreAlerts.service';
import { startAutoConfirmRuntime, stopAutoConfirmRuntime } from './services/fleet/autoConfirm.service';
import { startLineQualityRuntime, stopLineQualityRuntime } from './services/fleet/lineQuality.service';
import { startSnmpRuntime, stopSnmpRuntime } from './services/snmp';
import { startLogsRuntime, stopLogsRuntime } from './services/logs';
import { startChangeWorker, stopChangeWorker } from './services/change/jobQueue.service';
import { startRolloutRuntime, stopRolloutRuntime } from './services/change/rollout.service';
import { startBackupRetentionRuntime, stopBackupRetentionRuntime } from './services/change/backupRetention.service';
import { startDataRetentionRuntime, stopDataRetentionRuntime } from './services/retention/dataRetention.service';
import {
  startConcentratorSecretRetry,
  stopConcentratorSecretRetry,
} from './services/change/concentratorSecretRetry.service';
import { startJobFollowupRuntime, stopJobFollowupRuntime } from './services/change/jobFollowup.service';
import { startAccessCheckNightlyRuntime, stopAccessCheckNightlyRuntime } from './services/fleet/accessCheckNightly.service';
import {
  startScheduledConfigRuntime,
  stopScheduledConfigRuntime,
} from './services/drift/runtime';
import { changeExecutorReadiness, runJob } from './services/change/apply.service';
import { registerChangeRenderer } from './services/change/safeApply.service';
import { routerOsChangeRenderer } from './services/change/renderer';
import { startAcsRuntime, stopAcsRuntime } from './cwmp';
import { startEvidenceRuntime, stopEvidenceRuntime } from './services/attestation/runtime';
import { startWeatherRuntime, stopWeatherRuntime } from './services/weather';
import { startSimRuntime, stopSimRuntime } from './services/sim';
import { startRouterOsReleaseWatcher, stopRouterOsReleaseWatcher } from './services/firmware/releaseWatcher';
import { sweepInterventionLinks } from './services/intervention';
import { sweepAftermath } from './services/change/aftermath.service';
import { leaderElection as leader } from './services/leaderElection';

async function main() {
  // 0. Configuration — refuse to start on a bad OBLIWAN_ROLE
  //    before touching the database or opening a port.
  for (const warning of validateConfig()) {
    logger.warn(warning);
  }
  logger.info({ role: config.role }, 'ObliWAN starting');

  // 1. Run pending migrations
  logger.info('Running database migrations...');
  await db.migrate.latest();
  logger.info('Migrations complete');

  // 1b. CREDENTIAL VAULT GUARD.
  //
  //     Placed exactly here — AFTER the migrations (it reads
  //     `device_transports`, a table migration 002 creates) and BEFORE anything
  //     that could dial a device. If the database already holds ciphertext and
  //     the configured key cannot decrypt it, this THROWS and `main().catch()`
  //     kills the process.
  //
  //     That is the whole point of the check: an instance carrying the wrong
  //     key boots, looks healthy, and then fails one device at a time — which
  //     an operator reads as "the fleet is down", not as "the key is wrong".
  //     Dying here says which of the two it is, once, at the only moment where
  //     the answer is cheap.
  //
  //     An EMPTY vault is a legitimate fresh install: the guard returns
  //     warnings instead of throwing, and they are logged through pino.
  for (const warning of await assertVaultUsable()) {
    logger.warn(warning);
  }

  // 2. Ensure the default admin exists (mirrors seeds/001_bootstrap.ts, so a
  //    plain `docker compose up` needs no manual seed step).
  await authService.ensureDefaultAdmin(
    config.defaultAdminUsername,
    config.defaultAdminPassword,
  );

  // 2b. Closure-table consistency check.
  //
  //     `group_closure` is the only source of truth for settings inheritance
  //     AND for group permissions, and a corrupt closure is INVISIBLE on
  //     screen: getTree renders from `parent_id`, so a group missing its
  //     self-row looks perfectly normal while inheriting nothing and being
  //     unreadable to every non-admin. It LOGS LOUDLY and never throws — a data
  //     inconsistency is a repair job, not a reason to refuse to serve a fleet.
  try {
    await groupService.checkClosureIntegrity();
  } catch (err) {
    logger.error(err, 'Closure integrity check failed to run (continuing startup)');
  }

  // 3. Leader election. Every background duty armed below is
  //    gated on it, inside its own runtime: some subscribe through
  //    leaderElection.onChange(), the others read isLeader() at every tick.
  await leaderElection.start();

  // 4. Express app + HTTP server
  const app = createApp();
  const server = http.createServer(app);

  // 5. Socket.io — authenticated by the session cookie (see socket.ts)
  const io = createSocketServer(server);
  app.set('io', io);
  setLiveAlertIO(io);

  // 6. Fleet runtime.
  //
  //    Armed here, and no longer from `socket.ts`: arming a background duty is
  //    a startup act and belongs in the startup sequence. Its position is not
  //    free — it must come AFTER `createSocketServer()`, which is what hands
  //    `io` to `fleetEvents` (the channel presence emits through), and AFTER
  //    the vault guard above, so the RouterOS pool is never created against a
  //    vault whose secrets we cannot read.
  //
  //    Presence itself is gated on leadership inside `startFleetRuntime()`: a
  //    `web` replica never campaigns and therefore never opens a
  //    `/ppp/active/listen` on the concentrator.
  try {
    startFleetRuntime();
  } catch (err) {
    // A fleet that fails to arm must not stop the API from serving: the
    // operator needs the UI precisely when the fleet side is unhappy.
    logger.error(err, 'Fleet runtime failed to arm — presence will not run on this process');
  }

  // 6a. PERMANENT HEALTH CHECK (migration 043): every device's management
  //     channel, at the interval its settings resolve to, with the alert and
  //     the recovery notice that go with it.
  //
  //     AFTER the fleet runtime, which creates the RouterOS pool the check reads
  //     through and the presence monitors it re-opens on a concentrator that
  //     answers again. Leader-gated INSIDE the runtime: two replicas would
  //     double every dial and race every alert.
  //
  //     Without these lines a concentrator declared degraded by a failed listen
  //     stays degraded on its page for ever, and no device is ever announced
  //     down by anything but its PPP session.
  try {
    startHealthCheckRuntime();
  } catch (err) {
    logger.error(err, 'Health check runtime failed to arm — no device is checked on this process');
  }
  // 6a-ter. Opening hours (migration 096): every minute, on the leader, a down
  //         or 4G alert lowered because its store was closed is raised again
  //         at its normal severity once the store opens with the problem
  //         still there (closedStoreAlerts.service.ts).
  try {
    startClosedStoreRuntime();
  } catch (err) {
    logger.error(err, 'Closed-store sweep failed to arm — lowered alerts are not raised again at the opening');
  }

  // 6a-bis. AUTOMATIC CONFORMITY CHECK of bench-prepared routers (migration 049):
  //         a pending bench device whose PPP session comes up is identity-checked
  //         against the serial the bench read, collected and compared with its plan
  //         in both directions; conformant -> active (identity-rule exception, operator
  //         decision: see the deviceBinding.service.ts header box).
  //
  //         AFTER the fleet runtime, which creates the RouterOS pool and the
  //         presence monitors whose session-up events it listens to. Leader-gated
  //         inside the runtime (leaderElection.onChange starts and stops its
  //         sweep), and not armed at all when BENCH_AUTO_CONFIRM_ENABLED=false.
  try {
    startAutoConfirmRuntime();
  } catch (err) {
    logger.error(err, 'Automatic conformity check failed to arm — bench devices wait for a human on this process');
  }

  // 6a-quater. LINE QUALITY of the stores' fixed lines (migration 097): once a
  //            night per site, outside opening hours, 20 pings per target
  //            through the fixed line plus the day's reconnections, judged
  //            against thresholds and the site's baseline; one grouped alert
  //            per workspace (fleet/lineQuality.service.ts). Read-only towards
  //            the routers, presence-gated, identity-checked.
  //            AFTER the fleet runtime, whose RouterOS pool it reads through;
  //            leader-gated inside the runtime.
  try {
    startLineQualityRuntime();
  } catch (err) {
    logger.error(err, 'Line quality runtime failed to arm — no fixed line is measured on this process');
  }

  // 6b. SNMP runtime: poll scheduler, rollups, partition maintenance, trap
  //     and syslog listeners. Same contract as the fleet runtime above — polling
  //     is gated on leadership inside `startSnmpRuntime()`, so two `web`
  //     replicas never poll the same device twice (which would not just double
  //     the load: it would corrupt the counter deltas the rates are derived from).
  //
  //     Without these lines the whole SNMP telemetry subsystem is dead code: it compiles,
  //     its tables exist, its routes answer — and nothing ever writes a sample.
  try {
    await startSnmpRuntime();
  } catch (err) {
    logger.error(err, 'SNMP runtime failed to arm — no polling, traps or syslog on this process');
  }

  // 6b-bis. LOGS RUNTIME: the RouterOS `/log` pull, the out-of-tunnel
  //         probe that finally feeds reachability's fourth signal, the attribution
  //         sweep and login-event retention.
  //
  //         AFTER the SNMP runtime, because the syslog RECEIVER lives there and
  //         is what produces the login events this runtime attributes from.
  //         All four duties are leader-gated inside `startLogsRuntime()`: they
  //         all either dial an equipment, dial a customer's public address, or
  //         write. The receivers stay ungated, in the SNMP runtime, because a
  //         pushed datagram a follower does not listen for is simply lost.
  //
  //         Without these lines syslog still ingests and login events are still
  //         extracted, but no drift run is ever attributed.
  try {
    startLogsRuntime();
  } catch (err) {
    logger.error(err, 'Logs runtime failed to arm — no /log pull, probes or attribution');
  }

  // 6c. CHANGE QUEUE.
  //
  //     Armed AFTER the SNMP runtime, and that order is not cosmetic: the SNMP
  //     runtime is what ensures the partitions and sweeps the stale alert
  //     state, and a change job that reboots a box while the poller is still
  //     initialising produces a counter discontinuity nobody can attribute.
  //
  //     THE LESSON OF THE SNMP SUBSYSTEM IS THE REASON THESE THREE LINES EXIST AT ALL: that
  //     subsystem compiled, its tables existed and its routes answered, and
  //     because nothing armed it in `index.ts` it never wrote a single sample.
  //     A change queue that is never armed is worse — the API accepts the job,
  //     the UI shows `queued`, and the change simply never happens.
  //
  //     `runJob` is injected rather than imported by the queue, which is what
  //     keeps `jobQueue` (the mechanics) and `apply.service` (the orchestration)
  //     acyclic. Leadership gating lives inside `startChangeWorker`: a `web`
  //     replica never arms, an `all` replica must win the election first, and a
  //     dedicated `worker` runs regardless — several of them side by side is
  //     precisely the deployment `FOR UPDATE SKIP LOCKED` exists for.
  //
  //     THE RENDERER IS INSTALLED FIRST, AND THE ORDER IS LOAD-BEARING.
  //     `safeApply.applyChange()` refuses every push until this call has run,
  //     because the queue hands the executor the REDACTED ops and a
  //     redacted op carries `***` where a PSK belongs. A worker that claimed a
  //     `push` row in the window between arming and registering would take a
  //     preflight backup, arm a dead-man on a customer's box, and only then
  //     refuse at the write — spending the entire safety budget to accomplish
  //     nothing. Registering before `startChangeWorker()` closes that window,
  //     and registering before `changeExecutorReadiness()` is what keeps the
  //     boot line below an honest report rather than a stale one.
  //
  //     The choice of renderer belongs HERE rather than inside safe-apply, because it
  //     is a brand choice: `routerOsChangeRenderer` refuses a DrayTek, a Zyxel
  //     and a SonicWall by name, and the day one of those gets a renderer the
  //     composition root is where the two are arbitrated. Nothing here weakens
  //     that refusal — a plan this renderer cannot express still fails closed,
  //     and the boot line going quiet means "a renderer exists", not "every
  //     plan will render".
  //
  //     This import is static where `apply.service` resolves `safeApply`
  //     through a variable specifier: that file must still compile on a
  //     checkout without safe-apply, whereas the composition root is precisely where a
  //     build declares what it contains. A renderer module that cannot load
  //     should kill the process at boot, not at the first Apply click.
  registerChangeRenderer(routerOsChangeRenderer);

  try {
    startChangeWorker(runJob);
    // Say out loud, at boot, whether this build can actually push — and if it
    // cannot, which piece is missing. Both gaps fail closed on their own; what
    // they do not do on their own is tell anybody before the first Apply click.
    for (const warning of (await changeExecutorReadiness()).warnings) {
      logger.warn({ subsystem: 'change' }, warning);
    }
  } catch (err) {
    // A queue that fails to arm must not stop the API: an operator needs the
    // UI most on the day the write path is unhappy. Jobs simply stay `queued`.
    logger.error(err, 'Change queue failed to arm — no change job will run on this process');
  }

  // 6c-bis-0. JOB FOLLOW-UPS (jobFollowup.service.ts). A job promised after
  //           another one on the same device (the bulk attach's
  //           `legacy_compliance` after its `management_access`) is queued by
  //           the worker that settles the first job; this sweep keeps the
  //           promises whose job ended any other way (an abort, a reaped
  //           lease). AFTER the change queue, which runs what it queues; gated
  //           inside each pass on this process taking change jobs.
  try {
    startJobFollowupRuntime();
  } catch (err) {
    logger.error(err, 'Job follow-up sweep failed to arm — an aborted job\'s follow-up stays open on this process');
  }

  // 6c-bis. ROLLOUT DRIVER. A rollout queues its first wave when it
  //         is launched; every later step — the gate after a wave, the next
  //         wave, the rollback of the previous ones — is taken by this tick.
  //         Without it a launched rollout (and the fleet OS upgrade, whose
  //         waves are rollout waves) stops after wave 0 for ever.
  //
  //         AFTER the change queue: the driver only ENQUEUES jobs, and a
  //         wave queued onto a queue nobody claims from is a wave of devices
  //         nobody is watching. Leader-gated inside `tickRollouts`: two
  //         replicas would start the same wave twice.
  try {
    startRolloutRuntime();
  } catch (err) {
    logger.error(err, 'Rollout driver failed to arm — no rollout advances past its first wave on this process');
  }

  // 6c-ter. CONCENTRATOR ACCOUNT RETRY. A `concentrator_secret` job runs once
  //         (max_attempts 1): this bounded, backed-off pass re-queues the ones
  //         that failed for a transient reason (the CHR did not answer) and
  //         raises the one "exhausted" alert when the attempts are spent. A
  //         refusal is never retried. AFTER the change queue, which runs the
  //         jobs it queues; leader-gated inside the pass. Arming it also tells
  //         the failure alert which retry policy runs on this process.
  try {
    startConcentratorSecretRetry();
  } catch (err) {
    logger.error(err, 'Concentrator account retry failed to arm — a failed CHR account job stays failed on this process');
  }

  // 6c-quater. SCHEDULED CONFIGURATION COLLECTION AND DRIFT. The reader of
  //            `snapshot_interval` and `drift_interval`: every active RouterOS
  //            device with an SSH channel, reachable by PPP presence / concentrator health / the health
  //            check / the pool's breaker, is collected on its inherited
  //            interval, and compared after a new document (services/drift/
  //            runtime.ts). Read-only on the equipment. AFTER the fleet runtime,
  //            whose pool breaker it consults; leader-gated inside each pass.
  try {
    startScheduledConfigRuntime();
  } catch (err) {
    logger.error(err, 'Scheduled configuration collection failed to arm — no snapshot or drift runs on its own on this process');
  }

  // 6c-quinquies. BACKUP RETENTION. `purgeExpiredBackups()` and
  //               `verifyStoredBackup()` had no caller: expired device backups
  //               stayed on disk, and a missing or corrupt one was found the
  //               night it was needed. Once a day: purge what has expired,
  //               re-verify a bounded sample, log and alert on a missing or
  //               corrupt file (services/change/backupRetention.service.ts).
  //               Leader-gated inside the pass; it refuses to run on a process
  //               whose backup root is not there.
  try {
    startBackupRetentionRuntime();
  } catch (err) {
    logger.error(err, 'Backup retention failed to arm — expired backups are not purged and stored ones not re-verified on this process');
  }

  // 6c-sexies. DATA RETENTION. The three `*_retention_days` settings were
  //            shown and read by nothing. Once a day, leader-gated inside the
  //            pass: superseded config snapshots (never the current one, never
  //            one a plan, an intervention or a finding names), audit and
  //            command-audit entries past max(setting, 400 days), and the
  //            5-minute series tiers' partition policy, which the hourly
  //            partition maintenance then enforces by DROP
  //            (services/retention/dataRetention.service.ts).
  try {
    startDataRetentionRuntime();
  } catch (err) {
    logger.error(err, 'Data retention failed to arm — snapshots and audit entries are not purged on this process');
  }

  // 6c-septies. NIGHTLY ACCESS VERIFICATION (migration 093). Once a night per
  //             workspace, on the leader: the reconciliation's "verify
  //             management access and compliance", read-only towards the
  //             routers, its alerts grouped by cause, and — only where a
  //             workspace turned it on — the automatic re-apply through
  //             change_jobs. AFTER the change queue, which runs what it
  //             queues (services/fleet/accessCheckNightly.service.ts).
  try {
    startAccessCheckNightlyRuntime();
  } catch (err) {
    logger.error(err, 'Nightly access verification failed to arm — no workspace is verified at night on this process');
  }

  // 6d. ACS TR-069.
  //
  //     A SEPARATE Express app on a SEPARATE listener (7547), armed here for
  //     the same reason as everything above it: ports 7547 and 7548 have been
  //     PUBLISHED by the compose files from the start with nothing behind them, and
  //     an unarmed ACS is a published port answering RST — 300 CPEs logging
  //     "ACS unreachable" at their own pace with nobody watching. That is a
  //     worse version of the SNMP-poller defect (a subsystem that compiled and never
  //     ran) because the failure is visible only from the customer's side.
  //
  //     AFTER the change queue on purpose: a CWMP write goes through
  //     `change_jobs`, so the door has to be open before the corridor.
  //
  //     NOT leader-gated. A CPE PUSHES to whatever address it was provisioned
  //     with; a follower that does not listen loses the Inform outright and
  //     nothing on our side retries. Every replica listens, and the concurrent
  //     writes are made safe by the database — `cwmp_sessions_fallback_uq` and
  //     `FOR UPDATE SKIP LOCKED` on the task queue — rather than by an
  //     election. The periodic sweeps inside the runtime ARE leader-gated.
  try {
    await startAcsRuntime();
  } catch (err) {
    // A listener that fails to bind must not stop the API from serving: the
    // operator needs the UI precisely when the CPE side is unhappy.
    logger.error(err, 'ACS runtime failed to arm — no CPE can reach this instance on 7547');
  }

  // 6e. EVIDENCE RUNTIME.
  //
  //     One duty: the drift-exception expiry sweep. An exception is a
  //     JUSTIFIED, DATED suppression of a drift finding, and when its review
  //     date passes THE FINDING MUST COME BACK. The sweep is what writes that
  //     back into `drift_findings.ignored` — the column the drift screen, the
  //     fleet roll-up and `drift_runs.max_severity` already read, and which
  //     knows nothing about exceptions.
  //
  //     Without this line the rule is a dead guard: an exception that expired
  //     on Tuesday keeps hiding a critical until somebody happens to open the
  //     exceptions page, which turns drift exceptions from "accepted drift gets revisited"
  //     into "accepted drift is hidden forever, with a date on it".
  //
  //     Leader-gated inside the runtime. It only writes and never dials an
  //     equipment, so two replicas sweeping would be wasteful rather than
  //     dangerous — but the counters it logs are only readable as a rate if one
  //     process produces them.
  try {
    startEvidenceRuntime();
  } catch (err) {
    logger.error(
      err,
      'Evidence runtime failed to arm — expired drift exceptions will only be swept when the '
        + 'exceptions screen is read on this process',
    );
  }

  // 6f. Operator weather. Leadership is gated INSIDE
  //     `startWeatherRuntime`, like every other runtime here.
  try {
    startWeatherRuntime();
  } catch (err) {
    logger.error(err, 'Weather runtime failed to arm — no operator-incident correlation on this process');
  }

  // 6f-bis. Mobile data lines. Leadership is gated INSIDE
  //     `startSimRuntime`, like every other runtime here.
  //
  //     What this arms is a sweep that reads a PARTNER'S web API, one request
  //     per line, on an API that publishes no rate limit. Two replicas polling
  //     it would double that load for no extra information and risk being
  //     throttled into silence — and silence, on this feature, is
  //     indistinguishable from good news.
  //
  //     It is also the only runtime that can create a top-up PROPOSAL. It
  //     cannot create a purchase: `SIM_RECHARGE_ADAPTERS` is empty on purpose
  //     (`services/sim/types.ts`), so nothing armed here can spend money.
  try {
    startSimRuntime();
  } catch (err) {
    logger.error(
      err,
      'SIM runtime failed to arm — remaining mobile data will not be read and no low-balance '
        + 'alert will be raised on this process',
    );
  }

  // 6f-ter. RouterOS release watcher. Leadership is gated INSIDE
  //     `startRouterOsReleaseWatcher`, like every other runtime here.
  //
  //     It reads https://upgrade.mikrotik.com/routeros/NEWESTa7.{stable,long-term}
  //     over the PUBLIC internet, not through the tunnel: once every 24 h, hourly
  //     while a check is failing. It records what MikroTik publishes and nothing
  //     else: it never dials a router and never queues a job. The fleet update
  //     writes through `change_jobs` like everything else.
  try {
    startRouterOsReleaseWatcher();
  } catch (err) {
    logger.error(
      err,
      'RouterOS release watcher failed to arm: the latest stable/long-term versions will not be '
        + 'refreshed on this process',
    );
  }

  // 6g. The two periodic sweeps that the intervention mode and the change aftermath shipped WITHOUT a caller.
  //
  //     They were delivered as plain exported functions, which is the sixth time
  //     on this project that a subsystem compiled, answered on its routes, and
  //     never ran because nothing armed it (the SNMP poller was the first).
  //     Both are leader-gated here rather than inside themselves, because
  //     neither owns a runtime module of its own.
  //
  //     `sweepInterventionLinks` attributes drift produced during a declared
  //     intervention and expires interventions nobody closed — an intervention
  //     left open forever is a permanent hole in attribution.
  //     `sweepAftermath` is the one that looks a week AFTER a change, which is
  //     the window the rollout's five-minute soak cannot see.
  const FEATURE_SWEEP_MS = 5 * 60_000;
  let featureSweepTimer: NodeJS.Timeout | null = null;
  //     Both sweeps are PER TENANT — they take a tenantId, they are not global.
  //     A tenant that fails must not stop the others: on a multi-customer
  //     platform, one broken tenant silently freezing everybody else's sweeps is
  //     the failure mode to avoid.
  const runFeatureSweeps = async (): Promise<void> => {
    if (!leader.isLeader()) return;
    let tenantIds: number[];
    try {
      tenantIds = await db('tenants').pluck<number[]>('id');
    } catch (err) {
      logger.warn({ err }, 'Feature sweeps: could not list tenants — skipping this tick');
      return;
    }
    for (const tenantId of tenantIds) {
      try { await sweepInterventionLinks(tenantId); } catch (err) {
        logger.warn({ err, tenantId }, 'Intervention link sweep failed — will retry next tick');
      }
      try { await sweepAftermath(tenantId); } catch (err) {
        logger.warn({ err, tenantId }, 'Change aftermath sweep failed — will retry next tick');
      }
    }
  };
  featureSweepTimer = setInterval(() => { void runFeatureSweeps(); }, FEATURE_SWEEP_MS);
  featureSweepTimer.unref?.();
  void runFeatureSweeps();

  // 7. Listen
  server.listen(config.port, () => {
    logger.info(`ObliWAN server listening on port ${config.port}`);
    logger.info(`Environment: ${config.nodeEnv} — role: ${config.role}`);
    void obligateService.announceSelfInfo();
  });

  // 8. Graceful shutdown
  let shuttingDown = false;
  const shutdown = async (signal: string) => {
    if (shuttingDown) return; // ignore a second signal mid-shutdown
    shuttingDown = true;
    logger.info(`Received ${signal}, shutting down...`);

    // Last resort: never let a stuck close()/destroy() block the exit forever.
    const hardExit = setTimeout(() => {
      logger.warn('shutdown: forced exit after 10s timeout');
      process.exit(0);
    }, 10_000);
    hardExit.unref();

    // Resign leadership first so a standby can take over immediately instead of
    // waiting out its retry interval.
    try { await leaderElection.stop(); } catch { /* already down */ }

    // Cancel the `/ppp/active/listen` on every concentrator and close the
    // pooled sockets. An abandoned listen stays registered on the CHR long
    // after the process that opened it is gone.
    // Stopped before the fleet: the SNMP poller reaches devices THROUGH the
    // transports the fleet runtime owns, so tearing the fleet down first would
    // leave in-flight polls talking to a closed pool.
    // Stop CLAIMING first, and wait for the jobs already in flight. A job
    // killed mid-apply is a half-configured router; a job that finishes its
    // phase and then finds the queue closed is a job that recorded what it did.
    // Anything that outlasts the grace period is left to its lease and to the
    // reaper, which never requeues past the write frontier.
    //
    // The two producers of change jobs stop ALONGSIDE the queue, not before
    // it: a rollout tick (bounded at 5 s) queued ahead of the queue's own 8 s
    // grace would spend the 10 s hard exit before `stopFleetRuntime()` below.
    // Each producer's pass in flight is still awaited, so a wave is never left
    // half queued; a job it queues after the queue stopped claiming stays
    // `queued` for the next leader, like any job queued just before a restart.
    //
    // The bench conformity check and the scheduled collection depend on the
    // fleet runtime and on nothing stopped in between, so they begin stopping
    // HERE, in the background, and are awaited just before the fleet: their
    // bounded waits (5 s each) overlap the queue's grace instead of adding to
    // the sequence.
    const settleWithin = (p: Promise<unknown>, ms: number): Promise<unknown> =>
      Promise.race([
        p.catch(() => undefined),
        new Promise((resolve) => { setTimeout(resolve, ms).unref(); }),
      ]);
    const benchAndCollectionStopped = Promise.allSettled([
      // `stopAutoConfirmRuntime()` awaits its conformity checks with no bound
      // of its own. A check abandoned here has only read the equipment; its
      // claim expires with its lease (CLAIM_LEASE_SEC) and a later sweep takes
      // the device again.
      settleWithin(stopAutoConfirmRuntime(), 5_000),
      stopScheduledConfigRuntime(),
    ]);
    await Promise.allSettled([stopRolloutRuntime(), stopConcentratorSecretRetry(), stopJobFollowupRuntime(), stopChangeWorker()]);

    // Close the CWMP listener BEFORE the database pool: a CPE mid-session
    // would otherwise get a 500 and record a transfer failure it will report
    // for days. Closed early and idle connections dropped, so a CPE holding a
    // kept-alive socket cannot pin the process for the full 120 s keep-alive.
    try { await stopAcsRuntime(); } catch { /* already down */ }

    // Before the fleet runtime: the health check reads through the pool that
    // `stopFleetRuntime()` closes, and an in-flight check should record what
    // it saw rather than a "pool is shutting down".
    try { await stopHealthCheckRuntime(); } catch { /* already down */ }
    try { await stopClosedStoreRuntime(); } catch { /* already down */ }
    try { await stopLogsRuntime(); } catch { /* already down */ }
    // Before the fleet runtime: its pings run on the pool that closes there.
    try { await stopLineQualityRuntime(); } catch { /* already down */ }
    try { await stopSnmpRuntime(); } catch { /* already down */ }
    try { stopEvidenceRuntime(); } catch { /* already down */ }
    try { await stopWeatherRuntime(); } catch { /* already down */ }
    try { await stopSimRuntime(); } catch { /* already down */ }
    try { await stopRouterOsReleaseWatcher(); } catch { /* already down */ }
    try { await stopBackupRetentionRuntime(); } catch { /* already down */ }
    try { await stopDataRetentionRuntime(); } catch { /* already down */ }
    try { await stopAccessCheckNightlyRuntime(); } catch { /* already down */ }
    if (featureSweepTimer) { clearInterval(featureSweepTimer); featureSweepTimer = null; }
    // Settled before the fleet runtime (they began stopping above): the
    // conformity check is fed by the presence session-up events the fleet
    // runtime emits, and the scheduled collection reads the RouterOS pool's
    // breaker, which would create a new pool once `stopFleetRuntime()` has
    // closed the old one.
    await benchAndCollectionStopped;
    try { await stopFleetRuntime(); } catch { /* already down */ }

    // Stop accepting new work BEFORE tearing down the DB pool.
    try { io.close(); } catch { /* ignore */ }
    try { server.close(); } catch { /* ignore */ }

    // Destroy the pool last. Any in-flight query gets aborted here — that is
    // EXPECTED on shutdown; swallow the resulting rejection so it cannot escape
    // and crash the process before we exit cleanly.
    try {
      await db.destroy();
    } catch (err) {
      logger.warn({ err }, 'shutdown: db.destroy() aborted in-flight queries (expected)');
    }

    clearTimeout(hardExit);
    process.exit(0);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  // Safety nets: a stray promise rejection or sync throw must NOT silently kill
  // the whole server.
  // - unhandledRejection: log and keep serving (usually one recoverable op).
  // - uncaughtException: log and exit so the orchestrator (Docker restart
  //   policy) restarts us cleanly rather than running on with corrupt state.
  process.on('unhandledRejection', (reason) => {
    logger.error({ reason }, 'Unhandled promise rejection (server kept running)');
  });
  process.on('uncaughtException', (err) => {
    logger.fatal(err, 'Uncaught exception — exiting for a clean restart');
    process.exit(1);
  });
}

main().catch((err) => {
  logger.fatal(err, 'Failed to start ObliWAN server');
  process.exit(1);
});
