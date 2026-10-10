/**
 * ObliWAN — the scheduled configuration collection and drift run.
 *
 *   runScheduledConfigPass()        one pass; returns what it did
 *   startScheduledConfigRuntime()   arm the periodic pass (leader-only)
 *   stopScheduledConfigRuntime()    disarm it, wait (bounded) for work in flight
 *
 * Before this file, `snapshot_interval` and `drift_interval` were promised on
 * the Settings screen and read by nothing: a configuration was collected only
 * when somebody pressed "Collect now", and a drift run happened only when
 * somebody asked for one. A fleet left alone had no baseline and no drift.
 *
 * ┌─ WHICH DEVICES A PASS LOOKS AT ──────────────────────────────────────────┐
 * │ `status = 'active'` (identity confirmed; a pending bench device is        │
 * │ collected by the conformity check instead), a family the collector can   │
 * │ read (`COLLECTABLE_FAMILIES`: RouterOS only, the same refusal the         │
 * │ collector makes, made here BEFORE anything is dialled), and an enabled    │
 * │ SSH channel with a host and a username (the export is read over SSH;      │
 * │ `collectRaw` refuses NO_TRANSPORT otherwise, and a refusal repeated every │
 * │ interval on the same device is noise, not information).                  │
 * │                                                                           │
 * │ Reachable, judged without dialling, and SKIPPED rather than failed:       │
 * │  - behind a concentrator (same predicate as the health check): its CHR    │
 * │    must not be degraded and its PPP session must be open (a               │
 * │    device whose session is down is never dialled);                        │
 * │  - the permanent health check has not confirmed it down;                  │
 * │  - the RouterOS pool's breaker for it is not open (a box the pool has     │
 * │    given up on is not dialled by a second door either).                   │
 * │ A skipped device spends no attempt and leaves no row: the reason is in    │
 * │ the pass report, and the health check is what says the box is down.      │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHEN, PER DEVICE (`decideDue`, pure) ────────────────────────────────────┐
 * │ Both intervals are the device's RESOLVED settings (default → tenant →     │
 * │ group chain → device), in minutes.                                        │
 * │  snapshot due   no snapshot yet, or the latest one was last SEEN          │
 * │                 (`config_snapshots.last_seen_at`, which an unchanged      │
 * │                 collection bumps without inserting a row) more than       │
 * │                 `snapshot_interval` ago;                                  │
 * │  drift due      no drift run yet, or the latest one (any cause, any       │
 * │                 status — a run is a run) started more than                │
 * │                 `drift_interval` ago.                                     │
 * │ Then:                                                                     │
 * │  snapshot + drift due  `runDrift({ collect: true, cause: 'scheduled' })`: │
 * │                 ONE dial, and a collection that fails is persisted by     │
 * │                 runDrift as an `unreachable` / `error` run — the drift    │
 * │                 screen says the box could not be read, rather than        │
 * │                 nothing;                                                  │
 * │  snapshot due   `collectAndStore`, then `runDrift({ cause: 'scheduled' })`│
 * │                 unless the device's LATEST drift run (any cause) already  │
 * │                 compared the very document just collected and did not     │
 * │                 fail (`needsComparison`). NOT "only when `created`": an   │
 * │                 unchanged box read again after a failed run would keep    │
 * │                 its `unreachable` verdict until drift_interval, and a     │
 * │                 revert A -> B -> A brings A's row back to the top         │
 * │                 (UNIQUE(device_id, ncm_hash)) with `created` false, so    │
 * │                 the revert would never be compared;                       │
 * │  drift due      `runDrift({ cause: 'scheduled' })` on the latest stored   │
 * │                 snapshot — only while the collection is NOT failing: a    │
 * │                 comparison of an old document, recorded after the box     │
 * │                 stopped answering, would replace its `unreachable` run    │
 * │                 with an `in_sync` one that is about the past.             │
 * │ A FAILED collection (persisted by runDrift with `snapshot_id` NULL and    │
 * │ cause `scheduled`, or remembered by this process) is retried after        │
 * │ min(snapshot_interval, FAILURE_RETRY_MIN), not at every pass.             │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * BOUNDED: at most COLLECT_CONCURRENCY collections at once, at most
 * MAX_DISPATCH_PER_PASS started per pass, never two on one device, the oldest
 * last-seen first. A fleet of a few hundred devices on the default 24 h
 * interval spreads itself over the first passes after boot instead of opening
 * a few hundred SSH sessions in the same second.
 *
 * READ-ONLY: a collection runs `/export terse` through the collector's own
 * door (identity asserted first, secrets gate) and a drift run writes rows in
 * ObliWAN's own tables. Nothing here writes to an equipment.
 *
 * LEADER-ONLY: two replicas would collect every device twice and race
 * the drift rows. Leadership is read at every pass and again before every
 * dispatch.
 */

import pLimit from 'p-limit';
import {
  SETTINGS_KEYS, clampSetting, type SettingsKey, type TenantCollectResult, type TenantCollectState,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { AppError } from '../../middleware/errorHandler';
import { leaderElection } from '../leaderElection';
import { settingsService } from '../settings.service';
import { appendAudit } from '../attestation/auditLog.service';
import {
  COLLECTABLE_FAMILIES, NoNormalizerError, SensitiveMaterialError, collectAndStore, hasNormalizer,
} from '../config/collect.service';
import { DriverError } from '../drivers/types';
import { BindingAssertionError } from '../fleet/deviceBinding.service';
import { getRouterOsPool } from '../fleet/routerosPool';
import { isConcentratorDegraded } from '../fleet/reachability.service';
import { runDrift } from './drift.service';

// ============================================================================
// Tunables (they bound the SCHEDULER; the intervals are settings)
// ============================================================================

/** How often a pass looks for due devices. */
export const SCHEDULED_CONFIG_TICK_MS = 60_000;
/** Collections in flight at once, fleet-wide. */
export const COLLECT_CONCURRENCY = 4;
/** Collections a single pass may start. The rest wait for the next pass. */
export const MAX_DISPATCH_PER_PASS = 32;
/** A failed collection is retried after min(snapshot_interval, this). */
export const FAILURE_RETRY_MIN = 60;
/** How long a resolved interval pair is reused before the settings are read again. */
const INTERVAL_CACHE_TTL_MS = 5 * 60_000;
/** How long `stop` waits for collections in flight. They are reads: one that
 *  outlives this is abandoned, not harmful. */
const STOP_WAIT_MS = 5_000;

// ============================================================================
// The decision — pure
// ============================================================================

export interface DueFacts {
  /** MAX(config_snapshots.last_seen_at): the last SUCCESSFUL collection. */
  lastSeenAt: Date | null;
  /** The last FAILED collection known (persisted scheduled failure run, or
   *  remembered by this process), whichever is later. */
  lastFailedAt: Date | null;
  /** MAX(drift_runs.started_at), any cause and any status. */
  lastDriftAt: Date | null;
}

export type DueDecision =
  | { kind: 'collect_and_drift' }
  | { kind: 'collect' }
  | { kind: 'drift' }
  | { kind: 'none'; reason: 'not_due' | 'failure_backoff' };

const MIN = 60_000;

/** See the header box WHEN, PER DEVICE. */
export function decideDue(
  f: DueFacts,
  intervals: { snapshotMin: number; driftMin: number },
  nowMs: number,
): DueDecision {
  const snapshotDue =
    f.lastSeenAt === null || nowMs - f.lastSeenAt.getTime() >= intervals.snapshotMin * MIN;
  const driftDue =
    f.lastDriftAt === null || nowMs - f.lastDriftAt.getTime() >= intervals.driftMin * MIN;
  const failing =
    f.lastFailedAt !== null && (f.lastSeenAt === null || f.lastFailedAt.getTime() > f.lastSeenAt.getTime());
  const backoffMs = Math.min(intervals.snapshotMin, FAILURE_RETRY_MIN) * MIN;
  const inBackoff = failing && nowMs - (f.lastFailedAt as Date).getTime() < backoffMs;

  if (snapshotDue) {
    if (inBackoff) return { kind: 'none', reason: 'failure_backoff' };
    return driftDue ? { kind: 'collect_and_drift' } : { kind: 'collect' };
  }
  // Never a comparison of the stored document while the collection is
  // failing: it would record a verdict about the past over the failure.
  if (driftDue && f.lastSeenAt !== null && !failing) return { kind: 'drift' };
  return { kind: 'none', reason: 'not_due' };
}

// ============================================================================
// Dependencies — real by default, replaceable by a harness
// ============================================================================

export interface ScheduledConfigDeps {
  isLeader(): boolean;
  hasNormalizer(): boolean;
  /** True when the RouterOS pool's breaker for this device is open now. */
  circuitOpen(deviceId: number, nowMs: number): boolean;
  concentratorDegraded(concentratorId: number): Promise<boolean>;
  intervals(device: { id: number; tenant_id: number; group_id: number | null }): Promise<{
    snapshotMin: number;
    driftMin: number;
  }>;
  /** `collectAndStore` with the collector's own source. */
  collect(deviceId: number, tenantId: number): Promise<{ created: boolean; snapshotId: string }>;
  /** The device's latest drift run (the one the fleet screen shows), or null. */
  lastDriftRun(deviceId: number): Promise<{ snapshotId: string | null; status: string } | null>;
  /** `runDrift` with cause `scheduled`. */
  drift(
    tenantId: number,
    deviceId: number,
    options: { collect: boolean },
  ): Promise<{ status: string; snapshotId: string | null } | null>;
  now(): Date;
}

const intervalCache = new Map<
  number,
  { tenantId: number; groupId: number | null; at: number; value: { snapshotMin: number; driftMin: number } }
>();

async function resolveIntervals(device: {
  id: number;
  tenant_id: number;
  group_id: number | null;
}): Promise<{ snapshotMin: number; driftMin: number }> {
  const hit = intervalCache.get(device.id);
  if (
    hit &&
    hit.tenantId === device.tenant_id &&
    hit.groupId === device.group_id &&
    Date.now() - hit.at < INTERVAL_CACHE_TTL_MS
  ) {
    return hit.value;
  }
  const resolved = await settingsService.resolveForDevice(device.tenant_id, device.id, device.group_id);
  const num = (key: SettingsKey): number => clampSetting(key, Number(resolved[key]?.value));
  const value = {
    snapshotMin: num(SETTINGS_KEYS.SNAPSHOT_INTERVAL),
    driftMin: num(SETTINGS_KEYS.DRIFT_INTERVAL),
  };
  intervalCache.set(device.id, { tenantId: device.tenant_id, groupId: device.group_id, at: Date.now(), value });
  return value;
}

const realDeps: ScheduledConfigDeps = {
  isLeader: () => leaderElection.isLeader(),
  hasNormalizer: () => hasNormalizer(),
  circuitOpen: (deviceId, nowMs) => {
    const h = getRouterOsPool().health(String(deviceId));
    return h.circuit === 'open' && (h.nextRetryAt === null || h.nextRetryAt.getTime() > nowMs);
  },
  concentratorDegraded: (concentratorId) => isConcentratorDegraded(concentratorId),
  intervals: resolveIntervals,
  collect: async (deviceId, tenantId) => {
    const r = await collectAndStore(deviceId, tenantId, { source: 'ssh' });
    return { created: r.snapshot.created, snapshotId: r.snapshot.snapshotId };
  },
  lastDriftRun: async (deviceId) => {
    // The same order as `fleetStatus()`'s "last run per device".
    const row = (await db('drift_runs')
      .where({ device_id: deviceId })
      .orderBy('started_at', 'desc')
      .orderBy('id', 'desc')
      .first('snapshot_id', 'status')) as { snapshot_id: string | number | null; status: string } | undefined;
    if (!row) return null;
    return { snapshotId: row.snapshot_id === null ? null : String(row.snapshot_id), status: row.status };
  },
  drift: async (tenantId, deviceId, options) => {
    const r = await runDrift(tenantId, deviceId, { cause: 'scheduled', collect: options.collect });
    return r ? { status: r.status, snapshotId: r.snapshotId } : null;
  },
  now: () => new Date(),
};

let deps: ScheduledConfigDeps = realDeps;

/** Harness only: replace some dependencies; `null` restores the real ones. */
export function setScheduledConfigDepsForTests(next: Partial<ScheduledConfigDeps> | null): void {
  deps = next ? { ...realDeps, ...next } : realDeps;
  intervalCache.clear();
  failedAt.clear();
}

// ============================================================================
// One pass
// ============================================================================

interface CandidateRow {
  id: number;
  tenant_id: number;
  group_id: number | null;
  name: string;
  role: string;
  concentrator_id: number | null;
  ppp_username: string | null;
  last_seen_at: Date | null;
  last_drift_at: Date | null;
  last_failed_at: Date | null;
  ppp_open: boolean;
  health_state: string | null;
}

export type SkipReason =
  | 'parent_degraded'
  | 'ppp_down'
  | 'health_down'
  | 'circuit_open'
  | 'in_flight';

export interface ScheduledConfigReport {
  /** Devices the pass looked at (active, collectable family, SSH channel). */
  examined: number;
  dispatched: Array<{ deviceId: number; kind: 'collect_and_drift' | 'collect' | 'drift' }>;
  skipped: Array<{ deviceId: number; reason: SkipReason }>;
  /** Due, but left for the next pass by MAX_DISPATCH_PER_PASS. */
  deferred: number;
  /** Set when the pass did nothing at all, and why. */
  idle?: 'not_leader' | 'no_normalizer' | 'stopping';
}

/** Collections (and drift runs) in flight in this process, per device. */
const inFlight = new Map<number, Promise<void>>();
/** Failures remembered by this process (the `collect` path does not persist one). */
const failedAt = new Map<number, Date>();
const limit = pLimit(COLLECT_CONCURRENCY);
let stopping = false;

/** `tenantId`: one client's candidates only (the bulk collect); absent, the
 *  whole fleet (the scheduled pass). */
async function loadCandidates(tenantId?: number): Promise<CandidateRow[]> {
  // No "?" literal anywhere in the raw fragments: knex would read it as a
  // binding (the migration 032 trap).
  const query = db('devices as d')
    .leftJoin('device_health_checks as h', 'h.device_id', 'd.id')
    .where('d.status', 'active')
    .whereIn('d.family', COLLECTABLE_FAMILIES as unknown as string[])
    .whereExists(
      db('device_transports as t')
        .whereRaw('t.device_id = d.id')
        .where('t.transport', 'ssh')
        .where('t.enabled', true)
        .whereNotNull('t.host')
        .whereNotNull('t.username')
        .select(db.raw('1')),
    )
    .select(
      'd.id', 'd.tenant_id', 'd.group_id', 'd.name', 'd.role', 'd.concentrator_id', 'd.ppp_username',
      'h.state as health_state',
      db.raw('(SELECT MAX(cs.last_seen_at) FROM config_snapshots cs WHERE cs.device_id = d.id) AS last_seen_at'),
      db.raw('(SELECT MAX(dr.started_at) FROM drift_runs dr WHERE dr.device_id = d.id) AS last_drift_at'),
      db.raw(
        "(SELECT MAX(dr.started_at) FROM drift_runs dr WHERE dr.device_id = d.id AND dr.cause = 'scheduled' "
          + "AND dr.snapshot_id IS NULL AND dr.status IN ('unreachable', 'error')) AS last_failed_at",
      ),
      // The PPP-session predicate, the one the health check and `assessDevice` use.
      db.raw(
        'EXISTS (SELECT 1 FROM ppp_sessions ps WHERE ps.concentrator_id = d.concentrator_id '
          + 'AND ps.ppp_username = d.ppp_username AND ps.ended_at IS NULL) AS ppp_open',
      ),
    );
  if (tenantId !== undefined) query.where('d.tenant_id', tenantId);
  const rows = (await query) as CandidateRow[];
  return rows.map((r) => ({
    ...r,
    id: Number(r.id),
    tenant_id: Number(r.tenant_id),
    group_id: r.group_id === null ? null : Number(r.group_id),
    concentrator_id: r.concentrator_id === null ? null : Number(r.concentrator_id),
    last_seen_at: r.last_seen_at ? new Date(r.last_seen_at) : null,
    last_drift_at: r.last_drift_at ? new Date(r.last_drift_at) : null,
    last_failed_at: r.last_failed_at ? new Date(r.last_failed_at) : null,
    ppp_open: r.ppp_open === true,
  }));
}

function laterOf(a: Date | null, b: Date | undefined): Date | null {
  if (!b) return a;
  if (!a) return b;
  return a.getTime() >= b.getTime() ? a : b;
}

async function reachability(d: CandidateRow, nowMs: number): Promise<SkipReason | null> {
  if (inFlight.has(d.id)) return 'in_flight';
  const behindChr = d.role !== 'concentrator' && d.concentrator_id !== null && !!d.ppp_username;
  if (behindChr) {
    if (await deps.concentratorDegraded(d.concentrator_id as number)) return 'parent_degraded';
    if (!d.ppp_open) return 'ppp_down';
  }
  if (d.health_state === 'down') return 'health_down';
  if (deps.circuitOpen(d.id, nowMs)) return 'circuit_open';
  return null;
}

/**
 * After a successful collection that stored nothing new: is the verdict on
 * screen still about this document? Only when the latest run compared exactly
 * the document just collected and did not fail. A failed latest run (the box
 * was unreachable, now it answers) or a run about another document (a revert
 * A -> B -> A brings A's existing row back, `created` false) both need a run.
 * Pure; exported for the harness.
 */
export function needsComparison(
  last: { snapshotId: string | null; status: string } | null,
  collectedSnapshotId: string,
): boolean {
  if (!last) return true;
  if (last.status === 'unreachable' || last.status === 'error') return true;
  return last.snapshotId !== collectedSnapshotId;
}

/** The collection itself failed (the router could not be read). */
class CollectFailure extends Error {
  constructor(readonly inner: unknown) {
    super(inner instanceof Error ? inner.message : String(inner));
    this.name = 'CollectFailure';
  }
}

/** The collection succeeded; the comparison that followed failed (a fault
 *  on our side, a database error). */
class CompareFailure extends Error {
  constructor(readonly collected: { created: boolean; snapshotId: string }, readonly inner: unknown) {
    super(inner instanceof Error ? inner.message : String(inner));
    this.name = 'CompareFailure';
  }
}

/**
 * Collect one device, then compare — the scheduler's `collect` step, and the
 * bulk collect's only step: `collectAndStore` through `deps.collect` (identity
 * asserted, secrets gate, `/export terse show-sensitive=no`), the failure
 * bookkeeping, then a drift run when the document is new or the verdict on
 * screen is not about it (`needsComparison`). Throws `CollectFailure` when
 * the router could not be read, `CompareFailure` when the comparison failed
 * after a good collection.
 */
async function collectThenCompare(d: CandidateRow): Promise<{ created: boolean; snapshotId: string }> {
  let collected: { created: boolean; snapshotId: string };
  try {
    collected = await deps.collect(d.id, d.tenant_id);
  } catch (err) {
    failedAt.set(d.id, deps.now());
    throw new CollectFailure(err);
  }
  failedAt.delete(d.id);
  try {
    if (collected.created || needsComparison(await deps.lastDriftRun(d.id), collected.snapshotId)) {
      await deps.drift(d.tenant_id, d.id, { collect: false });
    }
  } catch (err) {
    throw new CompareFailure(collected, err);
  }
  return collected;
}

async function execute(d: CandidateRow, kind: 'collect_and_drift' | 'collect' | 'drift'): Promise<void> {
  try {
    if (kind === 'collect_and_drift') {
      const run = await deps.drift(d.tenant_id, d.id, { collect: true });
      if (run && run.snapshotId === null && (run.status === 'unreachable' || run.status === 'error')) {
        failedAt.set(d.id, deps.now());
      } else {
        failedAt.delete(d.id);
      }
      return;
    }
    if (kind === 'collect') {
      try {
        await collectThenCompare(d);
      } catch (err) {
        if (err instanceof CollectFailure) {
          logger.warn(
            { deviceId: d.id, err: err.message },
            'Scheduled configuration collection failed; retried after the failure backoff',
          );
          return;
        }
        // A comparison fault: the outer handler records it as before.
        throw err instanceof CompareFailure ? err.inner : err;
      }
      return;
    }
    await deps.drift(d.tenant_id, d.id, { collect: false });
  } catch (err) {
    // runDrift persists its own failures; what lands here is a fault on our
    // side (a database error). It is logged, and the next pass decides again.
    failedAt.set(d.id, deps.now());
    logger.error({ err, deviceId: d.id, kind }, 'Scheduled configuration pass failed for a device');
  }
}

/**
 * One pass over the fleet. Returns once every collection it STARTED has been
 * handed to the concurrency limiter — not once they have finished; a harness
 * that needs them finished awaits `flushScheduledConfig()`.
 */
export async function runScheduledConfigPass(): Promise<ScheduledConfigReport> {
  const report: ScheduledConfigReport = { examined: 0, dispatched: [], skipped: [], deferred: 0 };
  if (stopping) return { ...report, idle: 'stopping' };
  if (!deps.isLeader()) return { ...report, idle: 'not_leader' };
  if (!deps.hasNormalizer()) return { ...report, idle: 'no_normalizer' };

  const now = deps.now();
  const nowMs = now.getTime();
  const candidates = await loadCandidates();
  report.examined = candidates.length;

  // Oldest last-seen first; never collected before everything else.
  candidates.sort(
    (a, b) => (a.last_seen_at?.getTime() ?? -Infinity) - (b.last_seen_at?.getTime() ?? -Infinity) || a.id - b.id,
  );

  for (const d of candidates) {
    if (stopping || !deps.isLeader()) break;
    const intervals = await deps.intervals(d);
    const decision = decideDue(
      {
        lastSeenAt: d.last_seen_at,
        lastFailedAt: laterOf(d.last_failed_at, failedAt.get(d.id)),
        lastDriftAt: d.last_drift_at,
      },
      intervals,
      nowMs,
    );
    if (decision.kind === 'none') continue;

    const skip = await reachability(d, nowMs);
    if (skip) {
      report.skipped.push({ deviceId: d.id, reason: skip });
      continue;
    }
    if (report.dispatched.length >= MAX_DISPATCH_PER_PASS) {
      report.deferred += 1;
      continue;
    }

    report.dispatched.push({ deviceId: d.id, kind: decision.kind });
    const p = limit(async () => {
      if (stopping || !deps.isLeader()) return;
      await execute(d, decision.kind);
    }).finally(() => {
      inFlight.delete(d.id);
    });
    inFlight.set(d.id, p);
  }

  if (report.dispatched.length > 0 || report.deferred > 0) {
    logger.info(
      {
        examined: report.examined,
        dispatched: report.dispatched.length,
        skipped: report.skipped.length,
        deferred: report.deferred,
      },
      'Scheduled configuration pass',
    );
  }
  return report;
}

// ============================================================================
// Collect a whole client — the bulk "collect now" (one tenant, one gesture)
// ============================================================================
//
// The same door as the device page's button and the scheduled pass:
// `collectThenCompare` → `collectAndStore` (identity asserted, secrets gate,
// `/export terse show-sensitive=no` over the router's own SSH transport — the
// `obliwan` account after management_access, the legacy one before). It
// writes snapshots and drift rows in ObliWAN; nothing reaches a router.
// The scheduler's candidates and its reachability verdicts apply unchanged:
// a router whose PPP session is down, whose concentrator is degraded
// (degraded concentrator), that the health check says is down or whose breaker is open is
// SKIPPED, never dialled; one already being collected is skipped too and
// dialled once.
//
// Progress lives in this process (the snapshots are durable, the audit trail
// records the start and the end): a restart loses the progress view, not
// what was collected.

/** Routers dialled at once by one bulk collect (on top of the scheduler's). */
export const TENANT_COLLECT_CONCURRENCY = 2;
/** Routers one bulk collect looks at; the rest are counted as deferred. */
export const TENANT_COLLECT_CAP = 500;
let tenantCollectCap = TENANT_COLLECT_CAP;

/** Harness only: a smaller cap (null restores TENANT_COLLECT_CAP). */
export function setTenantCollectCapForTests(cap: number | null): void {
  tenantCollectCap = cap ?? TENANT_COLLECT_CAP;
}

const tenantCollects = new Map<number, TenantCollectState>();

function copyState(s: TenantCollectState): TenantCollectState {
  return { ...s, results: s.results.map((r) => ({ ...r })) };
}

/** The bulk collect of this tenant in progress, or the last one finished
 *  since the process started; null when none. */
export function tenantCollectState(tenantId: number): TenantCollectState | null {
  const s = tenantCollects.get(tenantId);
  return s ? copyState(s) : null;
}

export function tenantCollectRunning(tenantId: number): boolean {
  return tenantCollects.get(tenantId)?.running === true;
}

/** Why one router's collection failed, in the collector's own words. A
 *  sensitive-material refusal names the property, never a value. */
function failureOf(err: unknown): { reason: string; message: string } {
  if (err instanceof SensitiveMaterialError) {
    return { reason: 'sensitive_material', message: `Refused: the export carries a value for [${err.props.join(', ')}].` };
  }
  if (err instanceof NoNormalizerError) return { reason: 'no_normalizer', message: err.message.slice(0, 500) };
  if (err instanceof BindingAssertionError) return { reason: 'IDENTITY_REFUSED', message: err.message.slice(0, 500) };
  if (err instanceof DriverError) return { reason: err.code, message: err.message.slice(0, 500) };
  return { reason: 'UNKNOWN', message: (err instanceof Error ? err.message : String(err)).slice(0, 500) };
}

/**
 * Start collecting every collectable router of ONE tenant. Answers at once
 * with the state (`running`); the work continues in the background. 409 while
 * one runs for the tenant, 503 when this build stores no document.
 */
export async function startTenantCollect(tenantId: number, userId: number | null): Promise<TenantCollectState> {
  if (tenantCollectRunning(tenantId)) {
    throw new AppError(409, 'A collection of this client\'s configurations is already running.');
  }
  if (!deps.hasNormalizer()) {
    throw new AppError(503, 'No NCM normaliser is registered on this build; collection is refused rather than storing an empty document');
  }
  // Reserved before the first await: a double click is a 409, not two runs.
  const state: TenantCollectState = {
    tenantId, running: true, startedAt: deps.now().toISOString(), finishedAt: null, startedBy: userId,
    total: 0, done: 0, deferred: 0, results: [],
  };
  tenantCollects.set(tenantId, state);
  let batch: CandidateRow[];
  try {
    const candidates = await loadCandidates(tenantId);
    // Oldest last-seen first, never collected before everything else.
    candidates.sort(
      (a, b) => (a.last_seen_at?.getTime() ?? -Infinity) - (b.last_seen_at?.getTime() ?? -Infinity) || a.id - b.id,
    );
    batch = candidates.slice(0, tenantCollectCap);
    state.total = batch.length;
    state.deferred = candidates.length - batch.length;
    await appendAudit({
      tenantId, actorType: userId === null ? 'system' : 'user', actorId: userId,
      action: 'config.tenant_collect.started', entityType: 'tenant', entityId: tenantId,
      after: { total: state.total, deferred: state.deferred },
    });
  } catch (err) {
    state.running = false;
    state.finishedAt = deps.now().toISOString();
    throw err;
  }
  void runTenantCollect(state, batch, userId).catch((err: unknown) => {
    logger.error({ err, tenantId }, 'Bulk configuration collection failed');
  });
  return copyState(state);
}

async function runTenantCollect(state: TenantCollectState, batch: CandidateRow[], userId: number | null): Promise<void> {
  const lim = pLimit(TENANT_COLLECT_CONCURRENCY);
  const record = (r: TenantCollectResult): void => {
    state.results.push(r);
    state.done += 1;
  };
  try {
    await Promise.all(batch.map((d) => lim(async () => {
      if (stopping) {
        record({ deviceId: d.id, deviceName: d.name, outcome: 'skipped', reason: 'stopping', message: null });
        return;
      }
      const skip = await reachability(d, deps.now().getTime());
      if (skip) {
        record({ deviceId: d.id, deviceName: d.name, outcome: 'skipped', reason: skip, message: null });
        return;
      }
      // Registered like a scheduled dispatch: the scheduler skips it while
      // it is collected here, and the other way round.
      let release!: () => void;
      inFlight.set(d.id, new Promise<void>((r) => { release = r; }));
      try {
        const collected = await collectThenCompare(d);
        record({ deviceId: d.id, deviceName: d.name, outcome: collected.created ? 'created' : 'unchanged', reason: null, message: null });
      } catch (err) {
        if (err instanceof CompareFailure) {
          // Collected; only the comparison after it failed — logged, and the
          // next scheduled pass compares again.
          logger.error({ err: err.inner, deviceId: d.id }, 'Bulk collection: the comparison after a good collection failed');
          record({
            deviceId: d.id, deviceName: d.name, outcome: err.collected.created ? 'created' : 'unchanged',
            reason: null, message: null,
          });
        } else {
          const f = failureOf(err instanceof CollectFailure ? err.inner : err);
          record({ deviceId: d.id, deviceName: d.name, outcome: 'failed', reason: f.reason, message: f.message });
        }
      } finally {
        inFlight.delete(d.id);
        release();
      }
    })));
  } finally {
    state.running = false;
    state.finishedAt = deps.now().toISOString();
    const count = (o: TenantCollectResult['outcome']) => state.results.filter((r) => r.outcome === o).length;
    await appendAudit({
      tenantId: state.tenantId, actorType: userId === null ? 'system' : 'user', actorId: userId,
      action: 'config.tenant_collect.finished', entityType: 'tenant', entityId: state.tenantId,
      after: {
        total: state.total, deferred: state.deferred, created: count('created'), unchanged: count('unchanged'),
        failed: count('failed'), skipped: count('skipped'),
      },
    }).catch((err: unknown) => logger.error({ err, tenantId: state.tenantId }, 'Bulk collection: audit row failed'));
    logger.info(
      { tenantId: state.tenantId, total: state.total, deferred: state.deferred, done: state.done },
      'Bulk configuration collection finished',
    );
  }
}

/** Harness only: wait for the tenant's bulk collect to finish. */
export async function waitTenantCollectForTests(tenantId: number, timeoutMs = 30_000): Promise<void> {
  const until = Date.now() + timeoutMs;
  while (tenantCollectRunning(tenantId) && Date.now() < until) {
    await new Promise((r) => setTimeout(r, 25));
  }
}

/** Harness only: forget every bulk collect state. */
export function resetTenantCollectsForTests(): void {
  tenantCollects.clear();
}

/** Wait for every collection and drift run this process has started. */
export async function flushScheduledConfig(): Promise<void> {
  while (inFlight.size > 0) {
    await Promise.allSettled(Array.from(inFlight.values()));
  }
}

// ============================================================================
// The runtime
// ============================================================================

let timer: NodeJS.Timeout | null = null;
let passing: Promise<unknown> | null = null;

/**
 * Arm the periodic pass on this process. Every process may call it: a pass on
 * a process that is not the leader does nothing. Idempotent.
 */
export function startScheduledConfigRuntime(options: { intervalMs?: number } = {}): void {
  if (timer) return;
  stopping = false;
  const intervalMs = Math.max(10, Math.floor(options.intervalMs ?? SCHEDULED_CONFIG_TICK_MS));
  const tick = (): void => {
    if (passing) return; // a slow pass is never stacked under the next one
    passing = runScheduledConfigPass()
      .catch((err: unknown) => logger.error({ err }, 'Scheduled configuration pass failed'))
      .finally(() => {
        passing = null;
      });
  };
  timer = setInterval(tick, intervalMs);
  timer.unref?.();
  logger.info(
    { intervalMs, concurrency: COLLECT_CONCURRENCY, maxPerPass: MAX_DISPATCH_PER_PASS },
    'Scheduled configuration collection and drift armed (leader-only; snapshot_interval / drift_interval)',
  );
}

/** Disarm; nothing new is started, and work in flight gets a bounded wait. */
export async function stopScheduledConfigRuntime(): Promise<void> {
  stopping = true;
  if (timer) clearInterval(timer);
  timer = null;
  const settle = Promise.allSettled([passing ?? Promise.resolve(), ...inFlight.values()]);
  await Promise.race([settle, new Promise((r) => setTimeout(r, STOP_WAIT_MS).unref?.())]);
}

/** Harness only: re-arm after a stop. */
export function resetScheduledConfigForTests(): void {
  stopping = false;
}
