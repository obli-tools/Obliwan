// ============================================================================
// ObliWAN — `change_jobs`: THE queue
// ============================================================================
//
// Nothing writes to an equipment outside this table. This file owns the
// MECHANICS of that queue — claiming, leasing, reaping, stepping, transitioning
// — and knows nothing about what a job actually does to a router. The
// orchestration (guard, backup, dead-man, apply, outcome) is `apply.service.ts`
// and is injected as a runner at startup, which is also what keeps the two
// modules acyclic.
//
// ┌─ FOUR PROPERTIES, AND THREE OF THEM ARE THE DATABASE'S, NOT MINE ─────────┐
// │                                                                           │
// │ 1. ONE JOB IN FLIGHT PER DEVICE. Enforced by                              │
// │    `change_jobs_one_in_flight_uq` (migration 009): UNIQUE (device_id)      │
// │    WHERE status IN (the eight active states). This service does NOT        │
// │    re-implement it with a SELECT-then-INSERT — that pair has a gap in the  │
// │    middle and two API calls, two workers or one double-click fit in it.    │
// │    `enqueue` lets the 23505 come back and translates it into a 409.        │
// │                                                                           │
// │ 2. TWO WORKERS NEVER GET THE SAME JOB. `FOR UPDATE SKIP LOCKED` inside a   │
// │    CTE, with the UPDATE re-asserting `status = 'queued'`. The row lock is  │
// │    what serialises the claim; the status predicate is what makes a claim   │
// │    that lost the race return zero rows instead of stealing a running job.  │
// │                                                                           │
// │ 3. A DEAD WORKER RELEASES ITS DEVICE — BY A LEASE, NOT BY A FLAG. A flag   │
// │    needs somebody alive to clear it, and the process that would clear it   │
// │    is the process that died. `lease_expires_at` runs out on its own.       │
// │                                                                           │
// │ 4. THE REAPER NEVER REQUEUES A JOB THAT MAY HAVE WRITTEN.                  │
// │    `WRITE_COMMITTED_STATUSES` (applying / verifying / soaking / disarming) │
// │    are left EXACTLY where they are and reported for human inspection. The  │
// │    only thing worse than a half-applied router is a twice-applied one,     │
// │    and the on-box dead-man is already handling the first case.             │
// │    THREE EXCEPTIONS, the kinds that arm no dead-man, so nothing would ever│
// │    recover them; none is ever requeued — each is FAILED (`worker_lost`).  │
// │    `concentrator_secret`: its only write is one additive /ppp/secret      │
// │    entry, and the next job for the site reads the CHR and writes nothing  │
// │    if the entry is already there. `os_upgrade`: its writes are package    │
// │    downloads and one reboot; its `os_upgrade_jobs` row is settled with    │
// │    what may be left on the router, and the next os_upgrade job's `lint`   │
// │    refuses while a .npk sits in the router's root. `concentrator_link`:   │
// │    its writes are additive items on the CHR, each found again by its      │
// │    exact comment, and the next connect job reads the CHR and adds only    │
// │    what is missing. Left untouched, it would hold the CHR's device lock — │
// │    and through the subtree interlock every site behind it — for good.     │
// └───────────────────────────────────────────────────────────────────────────┘
//
// MAINTENANCE WINDOWS (`sites.maintenance_window`, migration 002): a job
// outside its window WAITS. It is not claimed, not failed, not touched — the
// pick query simply does not see it this tick. Two consequences that are
// deliberate: (a) a job that waits burns no `attempt`, which is why the window
// is evaluated BEFORE the claim and not after it; (b) a window we cannot PARSE
// makes the job wait too, loudly, rather than be pushed on a guess.

import os from 'os';
import crypto from 'crypto';
import type { Knex } from 'knex';
import {
  ACTIVE_CHANGE_JOB_STATUSES,
  SETTINGS_KEYS,
  SOCKET_EVENTS,
  WRITE_COMMITTED_STATUSES,
  canTransition,
  isTerminalJobStatus,
  isWriteJobKind,
  type ChangeJobKind,
  type ChangeJobStatus,
  type ChangeJobSummary,
  type ChangeStepKind,
  type ChangeStepStatus,
  type GuardVerdict,
  type SafetyLevel,
} from '@obliwan/shared';
import { db } from '../../db';
import { config } from '../../config';
import { logger } from '../../utils/logger';
import { applyTenantScope, godViewMeta, withTenantNames } from '../../utils/globalView';
import { leaderElection } from '../leaderElection';
import { emitToDevice } from '../fleet/fleetEvents';
import { emitToTenantAudience } from '../fleet/scopedEmit';
import { closedHoursWindowVerdict } from '../fleet/openingHours.service';
import { settleConcentratorSecret } from './concentratorSecret.service';
import { settleInfraAccount } from '../infraConcentrator/job.service';
import { effectiveSettingNumber, envInteger, platformSettingNumber } from '../settingsRead';

// ============================================================================
// Identity and timing
// ============================================================================

/**
 * `claimed_by` is a WORKER identity, not a user: host, pid and a per-process
 * uuid. The uuid matters — two containers on the same host can share a pid
 * namespace, and a restarted process reuses pids often enough that "the same
 * host:pid" would let a new worker silently inherit a dead one's lease.
 */
export const WORKER_ID = `${os.hostname()}:${process.pid}:${crypto.randomUUID().slice(0, 8)}`;

/**
 * How long a claim is good for without a renewal.
 *
 * Long enough that a slow `/system/backup` on a congested tunnel does not lose
 * its lease mid-flight; short enough that a killed worker's device is free
 * again within a coffee. `apply.service` renews it at every phase boundary, so
 * a job that legitimately takes twenty minutes never relies on this number —
 * only a job whose worker STOPPED does.
 */
export const LEASE_TTL_MS = 120_000;

/** How often the worker looks for work and reaps expired leases. */
export const POLL_INTERVAL_MS = 3_000;

/**
 * Jobs run in parallel PER PROCESS. Not per device — that is the database's
 * unique index — and deliberately small: every one of these is a live session
 * onto somebody's production router.
 *
 * The `max_concurrent_jobs` setting, read PLATFORM-WIDE (the main workspace's
 * value): the queue is one per installation and serves every tenant, so a
 * per-tenant bound would be a bound on nothing — the definition says so.
 * `OBLIWAN_CHANGE_CONCURRENCY`, which was the only knob before, still applies
 * while no value is stored (`settingsRead.ts`): a deployment that tuned it
 * keeps its tuning until somebody writes the setting.
 *
 * Re-read at most every `CONCURRENCY_REFRESH_MS`, not on every 3-second tick.
 * Lowering it never cancels a job in flight: the loop simply claims nothing
 * until enough of them finish.
 */
const CONCURRENCY_REFRESH_MS = 60_000;
let concurrency = effectiveSettingNumber(
  SETTINGS_KEYS.MAX_CONCURRENT_JOBS,
  undefined,
  envInteger('OBLIWAN_CHANGE_CONCURRENCY'),
).value;
let concurrencyReadAt = 0;

/** The bound the worker applies now, refreshed from the settings if stale. */
export async function maxConcurrentJobs(): Promise<number> {
  if (Date.now() - concurrencyReadAt >= CONCURRENCY_REFRESH_MS) {
    concurrencyReadAt = Date.now();
    concurrency = (await platformSettingNumber(
      SETTINGS_KEYS.MAX_CONCURRENT_JOBS,
      envInteger('OBLIWAN_CHANGE_CONCURRENCY'),
    )).value;
  }
  return concurrency;
}

/** How many queued rows the window pre-pass looks at per tick. */
const PICK_SCAN_LIMIT = 200;

// ============================================================================
// Errors
// ============================================================================

/** A second active job was refused BY THE DATABASE. Carries the device so the
 *  controller can say which box is busy rather than "conflict". */
export class DeviceBusyError extends Error {
  constructor(readonly deviceId: number) {
    super(
      `Device ${deviceId} already has a change job in flight. ` +
        'One job per device is a unique index, not a policy: a second plan compiled ' +
        'against the same base state describes a world the first one is about to change.',
    );
    this.name = 'DeviceBusyError';
  }
}

/** The lease was lost while the job was running (another process reaped it, or
 *  the row was moved under us). The runner must stop touching the device. */
export class LeaseLostError extends Error {
  constructor(readonly jobId: number) {
    super(`Job ${jobId} no longer holds its lease; this worker must stop.`);
    this.name = 'LeaseLostError';
  }
}

export class InvalidTransitionError extends Error {
  constructor(readonly from: ChangeJobStatus, readonly to: ChangeJobStatus, detail?: string) {
    super(detail ?? `Illegal change_job transition ${from} -> ${to}`);
    this.name = 'InvalidTransitionError';
  }
}

/**
 * The GENERIC write kinds of migration 009: the ones `apply.service.ts` drives
 * through the executor (preflight backup, on-box dead-man, render, apply)
 * rather than through a branch of their own. Every other write kind has a
 * dedicated service, door and reaper branch. Defined here because the reaper
 * needs it too (a net left by a dead worker), and this module may not import
 * `apply.service.ts`.
 */
export const GENERIC_WRITE_KINDS: ReadonlySet<ChangeJobKind> = new Set<ChangeJobKind>([
  'push', 'restore', 'reboot', 'firmware',
]);

// ============================================================================
// Rows
// ============================================================================

export interface ChangeJobRow {
  id: string | number;
  uuid: string;
  tenant_id: number;
  device_id: number;
  plan_id: string | number | null;
  kind: ChangeJobKind;
  status: ChangeJobStatus;
  attempt: number;
  max_attempts: number;
  base_state_hash: string;
  safety_level: SafetyLevel;
  safety_peer_device_id: number | null;
  degraded_confirmed_by: number | null;
  degraded_confirmed_at: Date | null;
  guard_verdict: GuardVerdict | null;
  guard_reasons: unknown;
  override_reason: string | null;
  overridden_by: number | null;
  overridden_at: Date | null;
  claimed_by: string | null;
  claimed_at: Date | null;
  lease_expires_at: Date | null;
  scheduled_for: Date | null;
  window_start: Date | null;
  window_end: Date | null;
  preflight_backup_id: string | number | null;
  deadman_handle: string | null;
  deadman_armed_at: Date | null;
  deadman_disarmed_at: Date | null;
  confirm_deadline: Date | null;
  soak_until: Date | null;
  /**
   * The persisted write frontier (migration 099): stamped by the worker,
   * together with a lease renewal, immediately before the first command that
   * may configure the router. NULL on an `applying` row means none was handed
   * to it — what the reaper needs to take an unused net down after a crash.
   * Optional: rows read before 099 and test fixtures do not carry it.
   */
  transmit_started_at?: Date | null;
  requested_by: number | null;
  approved_by: number | null;
  outcome: string | null;
  error_kind: string | null;
  error_message: string | null;
  started_at: Date | null;
  finished_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

function iso(d: Date | null): string | null {
  return d ? new Date(d).toISOString() : null;
}

export function toJobSummary(row: ChangeJobRow, deviceName = ''): ChangeJobSummary {
  return {
    id: Number(row.id),
    uuid: row.uuid,
    tenantId: row.tenant_id,
    deviceId: row.device_id,
    deviceName,
    planId: row.plan_id === null ? null : Number(row.plan_id),
    kind: row.kind,
    status: row.status,
    attempt: row.attempt,
    safetyLevel: row.safety_level,
    safetyPeerDeviceId: row.safety_peer_device_id,
    // The type says `GuardVerdict`; the column is nullable for read-only kinds.
    // INDETERMINATE is the honest stand-in for "no guard was run", never ACCEPT.
    guardVerdict: row.guard_verdict ?? 'INDETERMINATE',
    guardReasons: [],
    overrideReason: row.override_reason,
    baseStateHash: row.base_state_hash,
    preflightBackupId: row.preflight_backup_id === null ? null : Number(row.preflight_backup_id),
    deadmanArmedAt: iso(row.deadman_armed_at),
    deadmanDisarmedAt: iso(row.deadman_disarmed_at),
    soakUntil: iso(row.soak_until),
    scheduledFor: iso(row.scheduled_for),
    windowStart: iso(row.window_start),
    windowEnd: iso(row.window_end),
    requestedBy: row.requested_by,
    startedAt: iso(row.started_at),
    finishedAt: iso(row.finished_at),
    errorKind: row.error_kind,
    errorMessage: row.error_message,
    createdAt: new Date(row.created_at).toISOString(),
  };
}

/** The raw guard reasons as `mgmtPathGuard` produced them — richer than the
 *  shared `GuardReason` union (they carry a message, a culprit record and the
 *  plan line), which is why they are stored and returned as-is. */
export function guardReasonsOf(row: ChangeJobRow): unknown[] {
  const raw = row.guard_reasons;
  if (Array.isArray(raw)) return raw as unknown[];
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw) as unknown;
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }
  return [];
}

// ============================================================================
// Maintenance windows — `sites.maintenance_window`
// ============================================================================

/**
 * The shape migration 002 declared and left opaque:
 *   { days: ['mon','tue'] | [1,2], start: 'HH:MM', end: 'HH:MM', tz?: string }
 *
 * Both spellings of `days` are accepted (three-letter / full names, and 0-6
 * with 0 = Sunday, the JavaScript convention) because the column has been
 * writable from the start with no validator in front of it, and a site whose window
 * was typed by hand must not become unpushable.
 */
export interface MaintenanceWindow {
  days?: Array<string | number> | null;
  start?: string | null;
  end?: string | null;
  tz?: string | null;
  enabled?: boolean | null;
}

const DAY_NAMES = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];

export type WindowVerdict =
  | { open: true; reason: null }
  | { open: false; reason: string };

const OPEN: WindowVerdict = { open: true, reason: null };

function parseHhMm(raw: string): number | null {
  const m = /^(\d{1,2}):(\d{2})$/.exec(raw.trim());
  if (!m) return null;
  const h = Number(m[1]);
  const min = Number(m[2]);
  if (h > 23 || min > 59) return null;
  return h * 60 + min;
}

/**
 * Is `at` inside the window, in the SITE's timezone?
 *
 * The site's timezone, never the server's: a French MSP administering a site in
 * Réunion has a maintenance window that means 02:00 there, and evaluating it in
 * Europe/Paris pushes to a live shop at 22:00.
 *
 * FAIL CLOSED. A window we cannot parse — a bad timezone, a malformed time, a
 * `days` array of objects — returns CLOSED with the reason. The job waits and
 * the log says why. "We could not tell whether this is a maintenance window" is
 * not permission to write during business hours.
 */
export function isWithinMaintenanceWindow(
  window: unknown,
  timezone: string | null,
  at: Date = new Date(),
): WindowVerdict {
  if (window === null || window === undefined) return OPEN;
  if (typeof window !== 'object' || Array.isArray(window)) {
    return { open: false, reason: 'maintenance_window is not an object' };
  }

  const w = window as MaintenanceWindow;
  if (w.enabled === false) return OPEN;

  const hasDays = Array.isArray(w.days) && w.days.length > 0;
  const hasTimes = typeof w.start === 'string' && typeof w.end === 'string';
  // An object with neither constraint is an empty window, i.e. no constraint.
  if (!hasDays && !hasTimes) return OPEN;

  const tz = (typeof w.tz === 'string' && w.tz) || timezone || 'UTC';

  let localDay: number;
  let localMinutes: number;
  try {
    const fmt = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      weekday: 'short',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    });
    const parts = fmt.formatToParts(at);
    const weekday = parts.find((p) => p.type === 'weekday')?.value?.toLowerCase() ?? '';
    const hour = Number(parts.find((p) => p.type === 'hour')?.value ?? NaN);
    const minute = Number(parts.find((p) => p.type === 'minute')?.value ?? NaN);
    localDay = DAY_NAMES.indexOf(weekday.slice(0, 3));
    // Intl renders midnight as "24" in some ICU versions under hour12:false.
    localMinutes = ((hour === 24 ? 0 : hour) * 60 + minute) | 0;
    if (localDay < 0 || !Number.isFinite(hour) || !Number.isFinite(minute)) {
      return { open: false, reason: `could not read the local time in timezone "${tz}"` };
    }
  } catch {
    return { open: false, reason: `invalid timezone "${tz}"` };
  }

  if (hasDays) {
    const allowed = new Set<number>();
    for (const raw of w.days as Array<string | number>) {
      if (typeof raw === 'number' && Number.isInteger(raw) && raw >= 0 && raw <= 6) {
        allowed.add(raw);
      } else if (typeof raw === 'string') {
        const idx = DAY_NAMES.indexOf(raw.trim().toLowerCase().slice(0, 3));
        if (idx < 0) return { open: false, reason: `unreadable day "${raw}" in maintenance_window` };
        allowed.add(idx);
      } else {
        return { open: false, reason: 'unreadable entry in maintenance_window.days' };
      }
    }
    if (!allowed.has(localDay)) {
      return { open: false, reason: `${DAY_NAMES[localDay]} is not a maintenance day (tz ${tz})` };
    }
  }

  if (!hasTimes) return OPEN;

  const start = parseHhMm(w.start as string);
  const end = parseHhMm(w.end as string);
  if (start === null || end === null) {
    return { open: false, reason: 'maintenance_window start/end are not HH:MM' };
  }
  if (start === end) return OPEN; // a zero-length window means "no time limit"

  // An overnight window (22:00 -> 06:00) wraps midnight. Getting this wrong is
  // how the one window an operator actually uses becomes permanently closed.
  const inside = start < end
    ? localMinutes >= start && localMinutes < end
    : localMinutes >= start || localMinutes < end;

  return inside
    ? OPEN
    : {
        open: false,
        reason: `outside the maintenance window ${w.start}-${w.end} (tz ${tz}, local ${String(
          Math.floor(localMinutes / 60),
        ).padStart(2, '0')}:${String(localMinutes % 60).padStart(2, '0')})`,
      };
}

// ============================================================================
// Claiming
// ============================================================================

export interface Candidate {
  id: string | number;
  device_id: number;
  maintenance_window: unknown;
  timezone: string | null;
  tenant_id: number;
  group_id: number | null;
  site_id: number | null;
}

/**
 * The window of one candidate. An explicit `maintenance_window` decides alone
 * and is never overridden. A site with NONE takes its store's CLOSED hours as
 * its window when the inherited setting `closed_hours_maintenance` is on and
 * the hours are known (openingHours.service `closedHoursWindowVerdict`);
 * otherwise no window is no constraint, as before 096. Unreadable: the job
 * waits (fail closed, like an unparseable window).
 */
export async function windowVerdictOf(row: Candidate, now: Date): Promise<WindowVerdict> {
  if (row.maintenance_window !== null && row.maintenance_window !== undefined) {
    return isWithinMaintenanceWindow(row.maintenance_window, row.timezone, now);
  }
  try {
    const closedHours = await closedHoursWindowVerdict(
      { tenantId: row.tenant_id, deviceId: row.device_id, groupId: row.group_id, siteId: row.site_id },
      now,
    );
    if (closedHours === null || closedHours.open) return OPEN;
    return { open: false, reason: closedHours.reason ?? 'the store is open' };
  } catch (err) {
    return { open: false, reason: `the store's opening hours could not be read (${(err as Error).message})` };
  }
}

/** Sites whose window we have already complained about, so a permanently
 *  malformed window logs once per process instead of once per 3 seconds. */
const warnedWindows = new Set<number>();

/**
 * The rows a worker could claim RIGHT NOW, after the maintenance-window filter.
 *
 * Deliberately a separate, lock-free SELECT before the claim: the window lives
 * in a jsonb column on another table and is evaluated in a timezone, which is
 * not something to express in the pick query — and claiming first and releasing
 * after would burn an `attempt` on a job that never ran.
 */
async function eligibleJobIds(q: Knex | Knex.Transaction = db): Promise<number[]> {
  const rows = (await q('change_jobs as j')
    .join('devices as d', 'd.id', 'j.device_id')
    .leftJoin('sites as s', 's.id', 'd.site_id')
    .where('j.status', 'queued')
    .whereRaw('j.attempt < j.max_attempts')
    .whereRaw('(j.scheduled_for IS NULL OR j.scheduled_for <= now())')
    .whereRaw('(j.window_start IS NULL OR now() >= j.window_start)')
    .whereRaw('(j.window_end IS NULL OR now() < j.window_end)')
    .orderByRaw('j.scheduled_for NULLS FIRST, j.id')
    .limit(PICK_SCAN_LIMIT)
    .select(
      'j.id',
      'j.device_id',
      's.maintenance_window',
      's.timezone',
      'd.tenant_id',
      'd.group_id',
      'd.site_id',
    )) as Candidate[];

  const now = new Date();
  const out: number[] = [];
  for (const row of rows) {
    const verdict = await windowVerdictOf(row, now);
    if (verdict.open) {
      out.push(Number(row.id));
      continue;
    }
    if (!warnedWindows.has(row.device_id)) {
      warnedWindows.add(row.device_id);
      logger.info(
        { jobId: Number(row.id), deviceId: row.device_id, reason: verdict.reason },
        'change queue: job waiting for its maintenance window (it is NOT failed)',
      );
    }
  }
  return out;
}

/**
 * Take ONE job, atomically.
 *
 * `FOR UPDATE SKIP LOCKED` inside the CTE is what stops two workers taking the
 * same row: the second one skips the locked row instead of blocking on it, so
 * a busy queue never serialises into a single-file line. The UPDATE re-asserts
 * `status = 'queued'`, which is what makes a claim that lost the race return
 * zero rows rather than stealing a job somebody else already started.
 */
export async function claimNextJob(
  workerId: string = WORKER_ID,
  q: Knex | Knex.Transaction = db,
): Promise<ChangeJobRow | null> {
  const eligible = await eligibleJobIds(q);
  if (eligible.length === 0) return null;

  const result = (await q.raw(
    `
    WITH candidate AS (
      SELECT id
        FROM change_jobs
       WHERE status = 'queued'
         AND attempt < max_attempts
         AND id = ANY(?)
         AND (scheduled_for IS NULL OR scheduled_for <= now())
         AND (window_start IS NULL OR now() >= window_start)
         AND (window_end   IS NULL OR now() <  window_end)
       ORDER BY scheduled_for NULLS FIRST, id
       FOR UPDATE SKIP LOCKED
       LIMIT 1
    )
    UPDATE change_jobs j
       SET status           = 'claimed',
           claimed_by       = ?,
           claimed_at       = now(),
           lease_expires_at = now() + (? || ' milliseconds')::interval,
           attempt          = j.attempt + 1,
           started_at       = COALESCE(j.started_at, now()),
           updated_at       = now()
      FROM candidate c
     WHERE j.id = c.id
       AND j.status = 'queued'
    RETURNING j.*
    `,
    [eligible, workerId, String(LEASE_TTL_MS)],
  )) as { rows: ChangeJobRow[] };

  const row = result.rows[0] ?? null;
  if (row) {
    logger.info(
      { jobId: Number(row.id), deviceId: row.device_id, kind: row.kind, worker: workerId },
      'change queue: job claimed',
    );
    emitJob(row, SOCKET_EVENTS.JOB_STARTED);
  }
  return row;
}

/**
 * Push the lease out. Returns FALSE when this worker no longer owns the job —
 * the caller must then stop touching the device immediately: somebody else is,
 * or the row was reaped.
 */
export async function renewLease(
  jobId: number,
  workerId: string = WORKER_ID,
  q: Knex | Knex.Transaction = db,
): Promise<boolean> {
  const updated = await q('change_jobs')
    .where({ id: jobId, claimed_by: workerId })
    .whereNotIn('status', ['queued', 'succeeded', 'rolled_back', 'failed', 'aborted'])
    .update({
      lease_expires_at: db.raw(`now() + (? || ' milliseconds')::interval`, [String(LEASE_TTL_MS)]),
      updated_at: db.fn.now(),
    });
  return updated > 0;
}

/** Throwing form, for the phase boundaries inside `apply.service`. */
export async function assertLease(jobId: number, workerId: string = WORKER_ID): Promise<void> {
  if (!(await renewLease(jobId, workerId))) throw new LeaseLostError(jobId);
}

// ============================================================================
// Transitions
// ============================================================================

export interface TransitionPatch {
  outcome?: string | null;
  errorKind?: string | null;
  errorMessage?: string | null;
  preflightBackupId?: number | null;
  deadmanHandle?: string | null;
  deadmanArmedAt?: Date | null;
  deadmanDisarmedAt?: Date | null;
  confirmDeadline?: Date | null;
  soakUntil?: Date | null;
  safetyLevel?: SafetyLevel;
  safetyPeerDeviceId?: number | null;
  guardVerdict?: GuardVerdict;
  guardReasons?: unknown[];
}

/**
 * Move a job, refusing an edge the state machine does not have.
 *
 * `CHANGE_JOB_TRANSITIONS` is advisory in the database (no trigger enforces
 * it), so this function is where it becomes real for every path that goes
 * through the service — and every write path does, because nothing writes outside change_jobs.
 */
export async function transitionJob(
  job: ChangeJobRow,
  to: ChangeJobStatus,
  patch: TransitionPatch = {},
  q: Knex | Knex.Transaction = db,
): Promise<ChangeJobRow> {
  if (job.status !== to && !canTransition(job.status, to)) {
    throw new InvalidTransitionError(job.status, to);
  }

  const update: Record<string, unknown> = { status: to, updated_at: db.fn.now() };

  if (patch.outcome !== undefined) update.outcome = patch.outcome;
  if (patch.errorKind !== undefined) update.error_kind = patch.errorKind;
  if (patch.errorMessage !== undefined) update.error_message = patch.errorMessage;
  if (patch.preflightBackupId !== undefined) update.preflight_backup_id = patch.preflightBackupId;
  if (patch.deadmanHandle !== undefined) update.deadman_handle = patch.deadmanHandle;
  if (patch.deadmanArmedAt !== undefined) update.deadman_armed_at = patch.deadmanArmedAt;
  if (patch.deadmanDisarmedAt !== undefined) update.deadman_disarmed_at = patch.deadmanDisarmedAt;
  if (patch.confirmDeadline !== undefined) update.confirm_deadline = patch.confirmDeadline;
  if (patch.soakUntil !== undefined) update.soak_until = patch.soakUntil;
  if (patch.safetyLevel !== undefined) update.safety_level = patch.safetyLevel;
  if (patch.safetyPeerDeviceId !== undefined) {
    update.safety_peer_device_id = patch.safetyPeerDeviceId;
  }
  if (patch.guardVerdict !== undefined) update.guard_verdict = patch.guardVerdict;
  if (patch.guardReasons !== undefined) {
    update.guard_reasons = JSON.stringify(patch.guardReasons);
  }

  // `change_jobs_finished_chk`: terminal IFF finished_at is set. Setting it
  // here rather than at each call site is what stops a 23514 from a forgotten
  // timestamp on the one path that matters (a failure).
  if (isTerminalJobStatus(to)) update.finished_at = db.fn.now();

  // `change_jobs_queued_unclaimed_chk`: a queued job holds nothing. And
  // `change_jobs_started_chk` forbids a `started_at` without a `claimed_at`,
  // so releasing the claim releases the start with it — which is also the
  // truth: the attempt that set it never got anywhere.
  if (to === 'queued') {
    update.claimed_by = null;
    update.claimed_at = null;
    update.lease_expires_at = null;
    update.started_at = null;
  }

  // COMPARE-AND-SET on the status the caller believes the row is in. Without
  // it, an operator's abort that read `arming` could land AFTER the worker's
  // `arming -> applying`, write `aborted` and "Nothing had been written" over
  // a job that was sending its change — and the worker, its lease gone, would
  // then stand down with the dead-man armed. The reverse race (the worker over
  // an abort) the database refuses anyway (`change_jobs_finished_chk`); this
  // makes both directions one rule: the first writer wins, the second is told.
  const rows = (await q('change_jobs')
    .where({ id: job.id, status: job.status })
    .update(update)
    .returning('*')) as ChangeJobRow[];
  const next = rows[0];
  if (!next) {
    const now = (await q('change_jobs').where({ id: job.id }).first('status')) as
      | { status: ChangeJobStatus }
      | undefined;
    throw new InvalidTransitionError(
      now?.status ?? job.status,
      to,
      `Change job ${job.id} is no longer '${job.status}' (it is '${now?.status ?? 'gone'}'): ` +
        `the move to '${to}' was refused. Something else changed the job first.`,
    );
  }

  emitTransition(next);
  return next;
}

function emitTransition(row: ChangeJobRow): void {
  switch (row.status) {
    case 'arming':
      emitJob(row, SOCKET_EVENTS.JOB_ARMED);
      break;
    case 'soaking':
      emitJob(row, SOCKET_EVENTS.JOB_SOAKING);
      break;
    case 'disarming':
      emitJob(row, SOCKET_EVENTS.JOB_DISARMED);
      break;
    case 'rolled_back':
      emitJob(row, SOCKET_EVENTS.JOB_ROLLED_BACK);
      emitJob(row, SOCKET_EVENTS.JOB_FINISHED);
      break;
    case 'succeeded':
    case 'failed':
    case 'aborted':
      emitJob(row, SOCKET_EVENTS.JOB_FINISHED);
      break;
    default:
      emitJob(row, SOCKET_EVENTS.JOB_STEP);
  }
}

// ============================================================================
// Steps — the ordered trace of what was ATTEMPTED
// ============================================================================

export interface StepHandle {
  id: number;
  jobId: number;
  seq: number;
  attempt: number;
  kind: ChangeStepKind;
  startedAt: number;
}

/**
 * Open a step. `(job, attempt, seq)` is unique, so a retry writes a SECOND
 * trace rather than overwriting the first — and the failed attempt is the
 * interesting one.
 */
export async function startStep(
  job: ChangeJobRow,
  seq: number,
  kind: ChangeStepKind,
  planOpSeq: number | null = null,
  q: Knex | Knex.Transaction = db,
): Promise<StepHandle> {
  const rows = (await q('change_job_steps')
    .insert({
      job_id: job.id,
      // Overwritten from the parent by `change_job_steps_tenant_sync`; supplied
      // anyway so the NOT NULL is satisfied without relying on the default.
      tenant_id: job.tenant_id,
      seq,
      attempt: job.attempt,
      kind,
      status: 'running',
      plan_op_seq: planOpSeq,
      started_at: db.fn.now(),
    })
    .returning('id')) as Array<{ id: string | number }>;

  const handle: StepHandle = {
    id: Number(rows[0].id),
    jobId: Number(job.id),
    seq,
    attempt: job.attempt,
    kind,
    startedAt: Date.now(),
  };
  emitStep(job, handle, 'running', null);
  return handle;
}

export async function finishStep(
  job: ChangeJobRow,
  handle: StepHandle,
  status: ChangeStepStatus,
  detail: {
    /** ALREADY REDACTED by the driver. This layer is not where secrets are
     *  removed — by the time a value reaches here it has been through a log. */
    output?: string | null;
    error?: string | null;
    detail?: Record<string, unknown>;
  } = {},
  q: Knex | Knex.Transaction = db,
): Promise<void> {
  const durationMs = Date.now() - handle.startedAt;
  await q('change_job_steps')
    .where({ id: handle.id })
    .update({
      status,
      finished_at: db.fn.now(),
      duration_ms: durationMs,
      output_redacted: detail.output ?? null,
      error_redacted: detail.error ?? null,
      detail_redacted: JSON.stringify(detail.detail ?? {}),
    });
  emitStep(job, handle, status, detail.error ?? null, durationMs);
}

/** A step that did NOT happen, recorded as a fact rather than as an absent row.
 *  "We did not arm a dead-man" must be visible in the trace. */
export async function skipStep(
  job: ChangeJobRow,
  seq: number,
  kind: ChangeStepKind,
  why: string,
  q: Knex | Knex.Transaction = db,
): Promise<void> {
  const handle = await startStep(job, seq, kind, null, q);
  await finishStep(job, handle, 'skipped', { output: why }, q);
}

function emitStep(
  job: ChangeJobRow,
  handle: StepHandle,
  status: ChangeStepStatus,
  error: string | null,
  durationMs?: number,
): void {
  const payload = {
    jobId: Number(job.id),
    stepId: handle.id,
    seq: handle.seq,
    attempt: handle.attempt,
    kind: handle.kind,
    status,
    errorRedacted: error,
    durationMs: durationMs ?? null,
  };
  emitToTenantAudience(job.tenant_id, SOCKET_EVENTS.JOB_STEP, payload, { deviceId: job.device_id });
  emitToDevice(job.device_id, SOCKET_EVENTS.JOB_STEP, payload);
}

function emitJob(row: ChangeJobRow, event: string): void {
  const payload = toJobSummary(row);
  emitToTenantAudience(row.tenant_id, event, payload, { deviceId: row.device_id });
  emitToDevice(row.device_id, event, payload);
}

// ============================================================================
// The reaper — crash recovery, property 3 and property 4
// ============================================================================

export interface ReapReport {
  requeued: number;
  failed: number;
  /** Jobs whose worker died AFTER bytes may have reached the router. Never
   *  touched, only counted and named. */
  needingInspection: number[];
  /**
   * Generic write jobs the reaper just FAILED that may have left something of
   * theirs on the router — an unused net (nothing was transmitted) or the
   * dead-man of a change whose post-conditions were already proven. Handed to
   * the releaser `apply.service.ts` registers (`setReapedNetReleaser`), which
   * dials the router; the reaper itself does no device I/O.
   */
  netsOwed: ReapedNetJob[];
}

/**
 * What the reaper hands the releaser for one job it failed.
 *
 *  - `unused_net`: the job stopped BEFORE its write frontier — in
 *    `backing_up`, in `arming`, or in `applying` with `transmit_started_at`
 *    NULL. Nothing was configured; the preflight blob and possibly the
 *    dead-man are on the router, and the dead-man would reboot it at its
 *    deadline for nothing. They come down.
 *  - `verified_change`: the job's `postcheck` step had SUCCEEDED (the change
 *    landed and was proven to hold) and the worker died before disarming.
 *    Left armed, the dead-man reverts a good change with a reboot nobody
 *    decided — the case `failJob` already disarms for a live worker.
 */
export interface ReapedNetJob {
  id: number;
  tenantId: number;
  deviceId: number;
  kind: ChangeJobKind;
  /** Where the job was when its worker was lost (`after_postcheck`: verifying,
   *  soaking or disarming, with its postcheck succeeded). */
  reapedFrom: 'backing_up' | 'arming' | 'applying' | 'after_postcheck';
  mode: 'unused_net' | 'verified_change';
  /** `lease_expires_at` as it stood: its last renewal was LEASE_TTL_MS before,
   *  which dates the arming of a job reaped in `arming`. */
  leaseExpiredAt: Date | null;
}

export type ReapedNetReleaser = (jobs: readonly ReapedNetJob[]) => Promise<void>;

let reapedNetReleaser: ReapedNetReleaser | null = null;
const pendingReleases = new Set<Promise<void>>();

/**
 * Register the code that dials the router for `ReapReport.netsOwed`.
 * `apply.service.ts` does it when it loads — it owns the executor and the
 * job-failure wording; this module may not import it (it is the runner's).
 */
export function setReapedNetReleaser(fn: ReapedNetReleaser | null): void {
  reapedNetReleaser = fn;
}

/**
 * Hand reaped jobs to the releaser and resolve when it is done. Never throws.
 * `tick()` does not await it (a release can take a minute against a slow box);
 * `stopChangeWorker()` waits for it within its grace, and a test awaits it.
 */
export function releaseReapedNets(jobs: readonly ReapedNetJob[]): Promise<void> {
  if (jobs.length === 0) return Promise.resolve();
  const releaser = reapedNetReleaser;
  const run = (async () => {
    if (!releaser) {
      logger.fatal(
        { jobs: jobs.map((j) => j.id) },
        'change queue: jobs reaped with a net possibly left on their router, and NO releaser is ' +
          'registered — the dead-man of each will fire at its deadline (check deadman_handle)',
      );
      return;
    }
    try {
      await releaser(jobs);
    } catch (err) {
      logger.error({ err, jobs: jobs.map((j) => j.id) }, 'change queue: the releaser of reaped nets threw');
    }
  })();
  pendingReleases.add(run);
  void run.finally(() => pendingReleases.delete(run));
  return run;
}

/**
 * Return the devices held by dead workers.
 *
 * ┌─ THE FRONTIER, AND IT IS THE WHOLE POINT OF THE FINE-GRAINED STATUSES ────┐
 * │ claimed      -> queued. No I/O beyond an identity assertion has happened. │
 * │                `attempt` is DECREMENTED: the attempt did not occur, and   │
 * │                with `max_attempts = 1` (the default, because a write is   │
 * │                never retried silently) leaving it bumped would make the   │
 * │                job permanently unclaimable — a device locked for ever by  │
 * │                a process that crashed between two statements.             │
 * │ backing_up   -> failed. Nothing was written to the box, but a backup of   │
 * │                unknown completeness exists and the backup must be         │
 * │                taken again from a clean start, not resumed.               │
 * │ arming       -> failed. NOTHING WAS APPLIED, BUT A DEAD-MAN MAY BE ARMED. │
 * │                The job is failed and, for a generic write, handed to the  │
 * │                releaser (`netsOwed`), which takes the unused net down —   │
 * │                or says, on the row and in a live alert, when the router   │
 * │                reboots. `backing_up` likewise, for the blob it may leave. │
 * │ applying, `transmit_started_at` NULL (generic writes) -> failed, release  │
 * │                owed: the first configuration command was never handed     │
 * │                over (migration 099; the stamp and this UPDATE are         │
 * │                serialised by the row lock, so only one of them wins).     │
 * │ verifying / soaking / disarming with a SUCCEEDED postcheck (generic) ->   │
 * │                failed, the change stands, its dead-man owed a disarm —    │
 * │                `failJob`'s rule for a live worker, applied to a dead one. │
 * │ applying / verifying / soaking / disarming otherwise -> UNTOUCHED.        │
 * │                Bytes may already be on a production router. Requeueing    │
 * │                here applies the same change twice and disarms a net this  │
 * │                process never armed. The on-box dead-man is the recovery   │
 * │                mechanism; ours is a human.                                │
 * │ concentrator_secret, any status past `claimed` -> failed (worker_lost).   │
 * │                No dead-man exists to recover it, and leaving it would    │
 * │                hold the CHR's per-device lock for good. Not requeued: a   │
 * │                write is never retried silently; the next ensure() queues  │
 * │                a new job, which re-reads the CHR before writing anything. │
 * │ os_upgrade, any status past `claimed` -> failed (worker_lost), for the    │
 * │                same reason: no dead-man, and an untouched job would hold  │
 * │                the device lock and its rollout's wave for good. Its       │
 * │                `os_upgrade_jobs` row gets outcome `failed` and a detail   │
 * │                naming what may be on the router (fetched files, a reboot  │
 * │                whose result nobody read).                                 │
 * │ concentrator_link, any status past `claimed` -> failed (worker_lost),     │
 * │                for the same reason: no dead-man, and an untouched job     │
 * │                would hold the CHR's lock and, through the subtree         │
 * │                interlock, every job on every site behind it. Not          │
 * │                requeued; the operator connects again, and the new job     │
 * │                reads the CHR and adds only what is missing.               │
 * │ management_access, any status past `claimed` -> failed (worker_lost),     │
 * │                for the same reason: no dead-man, and an untouched job     │
 * │                would hold the device lock and its rollout's wave for      │
 * │                good. Its `management_access_jobs` row gets `failed` when  │
 * │                `wrote_at` is set, `refused` otherwise. Not requeued; a    │
 * │                new job reads the router first and writes only what is     │
 * │                missing.                                                   │
 * │ lte_apn, legacy_compliance, any status past `claimed` -> failed           │
 * │                (worker_lost), for the same reason, their rows settled the │
 * │                same way (`wrote_at` says which outcome is true).          │
 * │ site_rename, any status past `claimed` -> failed (worker_lost), for the   │
 * │                same reason; its row `unsettled` once the cut left or the  │
 * │                device row was switched and not switched back, `failed`   │
 * │                after a CHR write, `refused` otherwise.                    │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
export async function reapExpiredLeases(q: Knex | Knex.Transaction = db): Promise<ReapReport> {
  const report: ReapReport = { requeued: 0, failed: 0, needingInspection: [], netsOwed: [] };

  // 1. `claimed` — the only backward edge in the state machine.
  const requeued = (await q('change_jobs')
    .where('status', 'claimed')
    .whereNotNull('lease_expires_at')
    .whereRaw('lease_expires_at < now()')
    .update({
      status: 'queued',
      claimed_by: null,
      claimed_at: null,
      lease_expires_at: null,
      // `change_jobs_started_chk` is `started_at IS NULL OR claimed_at IS NOT
      // NULL`, and clearing the claim without clearing the start would violate
      // it. The constraint is right and the semantics agree with it: a job
      // whose worker died before touching anything did not start.
      started_at: null,
      attempt: db.raw('GREATEST(attempt - 1, 0)'),
      updated_at: db.fn.now(),
    })
    .returning(['id', 'device_id'])) as Array<{ id: string | number; device_id: number }>;
  report.requeued = requeued.length;
  for (const r of requeued) {
    logger.warn(
      { jobId: Number(r.id), deviceId: r.device_id },
      'change queue: lease expired on a CLAIMED job — requeued (no device I/O had happened)',
    );
  }

  // 1b. `concentrator_secret` past `claimed` — failed, whatever the status.
  // It is handled before steps 2 and 3, whose messages (backup, dead-man) and
  // whose "untouched" rule describe a job with a net this kind never arms.
  const lostSecretJobs = (await q('change_jobs')
    .where('kind', 'concentrator_secret')
    .whereIn('status', ['backing_up', 'arming', ...WRITE_COMMITTED_STATUSES])
    .whereNotNull('lease_expires_at')
    .whereRaw('lease_expires_at < now()')
    .update({
      status: 'failed',
      finished_at: db.fn.now(),
      error_kind: 'worker_lost',
      error_message:
        'The worker died while this job was handling the site account on the concentrator. ' +
        'It may or may not have added the /ppp/secret entry; it never changes or removes one. ' +
        'The next request for the site queues a new job, which reads the concentrator first and ' +
        'writes nothing if the entry is already there.',
      updated_at: db.fn.now(),
    })
    .returning(['id', 'device_id'])) as Array<{ id: string | number; device_id: number }>;
  report.failed += lostSecretJobs.length;
  for (const r of lostSecretJobs) {
    logger.error(
      { jobId: Number(r.id), deviceId: r.device_id },
      'change queue: lease expired on a concentrator_secret job — failed, concentrator released',
    );
    // Onto the allocation too; never throws. A 'provisioned' site stays so:
    // a lost worker proves nothing about the account.
    await settleConcentratorSecret({ id: r.id }, {
      ok: false,
      error: 'The worker died while this job was running; nothing about the concentrator account was concluded.',
    });
  }

  // 1c. `os_upgrade` past `claimed` — failed, whatever the status, for 1b's
  // reason: it arms no dead-man, so step 3's "untouched, the dead-man is the
  // recovery path" would be false for it, and the job would hold the device
  // lock (and its rollout's wave) for good. Handled before step 2 too, whose
  // messages describe a backup to retake and a dead-man to check.
  const lostUpgrades = (await q('change_jobs')
    .where('kind', 'os_upgrade')
    .whereIn('status', ['backing_up', 'arming', ...WRITE_COMMITTED_STATUSES])
    .whereNotNull('lease_expires_at')
    .whereRaw('lease_expires_at < now()')
    .update({
      status: 'failed',
      finished_at: db.fn.now(),
      error_kind: 'worker_lost',
      error_message:
        'The worker died while this RouterOS upgrade was running. Depending on how far it got, ' +
        'the router may hold downloaded .npk files (installed at its next reboot) or may have ' +
        'rebooted into the new release; the os_upgrade record says which gestures were made. ' +
        'Read /file and /system/resource on the router before queueing it again.',
      updated_at: db.fn.now(),
    })
    .returning(['id', 'device_id'])) as Array<{ id: string | number; device_id: number }>;
  report.failed += lostUpgrades.length;
  if (lostUpgrades.length > 0) {
    // Its own row says WHICH gesture was the last one recorded. An outcome a
    // step already recorded is kept (`outcome IS NULL`), as in settleOsUpgrade.
    await q('os_upgrade_jobs')
      .whereIn('job_id', lostUpgrades.map((r) => Number(r.id)))
      .whereNull('outcome')
      .update({
        outcome: 'failed',
        outcome_detail: q.raw(
          'CASE WHEN rebooted_at IS NOT NULL THEN ? WHEN fetched_at IS NOT NULL THEN ? ELSE ? END',
          [
            'The worker died at or after the reboot command (rebooted_at is set). Whether the ' +
              'router came back, and on which release, was never read, and its os_version was ' +
              'not touched. Queue the job again: a router already at the target ends as a no-op.',
            'The worker died after the first package download was started and before any reboot ' +
              'was sent. .npk files may be in the router root, and RouterOS installs them at its ' +
              'NEXT reboot, power cut included: remove them (/file) or reboot it deliberately. The ' +
              'next os_upgrade job refuses while a .npk is in the root.',
            'The worker died before any package download was started: this job sent no download ' +
              'and no reboot (a preflight backup may have been in progress, and its file may ' +
              'still be on the router).',
          ],
        ),
        updated_at: db.fn.now(),
      });
  }
  for (const r of lostUpgrades) {
    logger.error(
      { jobId: Number(r.id), deviceId: r.device_id },
      'change queue: lease expired on an os_upgrade job — failed, device released',
    );
  }

  // 1d. `concentrator_link` past `claimed` — failed, whatever the status, for
  // 1b's reason: it arms no dead-man (link.service.ts, CONCENTRATOR_LINK_NO_DEADMAN),
  // so step 3's "untouched, the dead-man is the recovery path" would be false
  // for it, and the job would hold the CHR's per-device lock — and, through
  // the subtree interlock, every job on every site behind the CHR — for good.
  // Handled before step 2, whose messages describe a dead-man to check.
  // `concentrator_link_jobs` keeps what it recorded: `wrote_at` (and the
  // link's `first_write_at`) are set BEFORE the first add, so a write that may
  // have happened is already on record and the transit stays frozen.
  const lostLinkJobs = (await q('change_jobs')
    .where('kind', 'concentrator_link')
    .whereIn('status', ['backing_up', 'arming', ...WRITE_COMMITTED_STATUSES])
    .whereNotNull('lease_expires_at')
    .whereRaw('lease_expires_at < now()')
    .update({
      status: 'failed',
      finished_at: db.fn.now(),
      error_kind: 'worker_lost',
      // Before `applying` the job had added nothing (the adds follow the
      // backup); from `applying` on, some items may be there.
      error_message: q.raw('CASE WHEN status IN (?, ?) THEN ? ELSE ? END', [
        'backing_up',
        'arming',
        'The worker died before this job added anything on the concentrator (it was taking the ' +
          'pre-change backup, whose file may still be on the CHR). Connect again: the new job reads the ' +
          'concentrator first and adds only what is missing.',
        'The worker died while this job was adding the WireGuard link items on the concentrator. ' +
          'It may have added some of them; it never changes or removes one. Connect again: the new ' +
          'job reads the concentrator first and adds only what is missing.',
      ]),
      updated_at: db.fn.now(),
    })
    .returning(['id', 'device_id'])) as Array<{ id: string | number; device_id: number }>;
  report.failed += lostLinkJobs.length;
  for (const r of lostLinkJobs) {
    logger.error(
      { jobId: Number(r.id), deviceId: r.device_id },
      'change queue: lease expired on a concentrator_link job — failed, concentrator released',
    );
  }

  // 1e. `management_access` past `claimed` — failed, whatever the status, for
  // 1b's reason: it arms no dead-man (managementAccess.service.ts,
  // MANAGEMENT_ACCESS_NO_DEADMAN), so step 3's "untouched, the dead-man is the
  // recovery path" would be false for it, and the job would hold the device
  // lock — and the wave of the rollout it belongs to — for good. Handled
  // before step 2, whose messages describe a plan and a dead-man this kind
  // does not have. `management_access_jobs.wrote_at` is set BEFORE the first
  // byte that changes the router, so it says which outcome is true.
  const lostAccessJobs = (await q('change_jobs')
    .where('kind', 'management_access')
    .whereIn('status', ['backing_up', 'arming', ...WRITE_COMMITTED_STATUSES])
    .whereNotNull('lease_expires_at')
    .whereRaw('lease_expires_at < now()')
    .update({
      status: 'failed',
      finished_at: db.fn.now(),
      error_kind: 'worker_lost',
      error_message: q.raw('CASE WHEN status IN (?, ?) THEN ? ELSE ? END', [
        'backing_up',
        'arming',
        'The worker died before this job wrote anything on the router (it was taking the pre-change ' +
          'backup over SSH; a backup file may still be on the router). Queue it again: the new job reads ' +
          'the router first.',
        'The worker died while this job was opening api-ssl on the router over SSH. Its /system script ' +
          'may have run in full, in part or not at all; the obliwan-ca and obliwan-api certificates may ' +
          'exist. Queue it again: the new job reads the router first, reuses a ready certificate, removes ' +
          'an unsigned template or a script an earlier job left, and writes only what is missing.',
      ]),
      updated_at: db.fn.now(),
    })
    .returning(['id', 'device_id'])) as Array<{ id: string | number; device_id: number }>;
  report.failed += lostAccessJobs.length;
  if (lostAccessJobs.length > 0) {
    // An outcome a step already recorded is kept (`outcome IS NULL`), as in
    // settleManagementAccess.
    await q('management_access_jobs')
      .whereIn('job_id', lostAccessJobs.map((r) => Number(r.id)))
      .whereNull('outcome')
      .update({
        outcome: q.raw('CASE WHEN wrote_at IS NOT NULL THEN ? ELSE ? END', ['failed', 'refused']),
        outcome_detail: q.raw('CASE WHEN wrote_at IS NOT NULL THEN ? ELSE ? END', [
          'The worker died after this job began writing on the router: api-ssl and the certificates are ' +
            'in an unknown state until the next job reads them. The pre-change backup is kept.',
          'The worker died before this job wrote anything on the router.',
        ]),
        updated_at: db.fn.now(),
      });
  }
  for (const r of lostAccessJobs) {
    logger.error(
      { jobId: Number(r.id), deviceId: r.device_id },
      'change queue: lease expired on a management_access job — failed, device released',
    );
  }

  // 1f. `lte_apn` past `claimed` — failed, for 1e's reason: it arms no
  // dead-man (lteApn.service.ts, LTE_APN_NO_DEADMAN). `lte_apn_jobs.wrote_at`
  // is set before the first line that changes the router.
  const lostApnJobs = (await q('change_jobs')
    .where('kind', 'lte_apn')
    .whereIn('status', ['backing_up', 'arming', ...WRITE_COMMITTED_STATUSES])
    .whereNotNull('lease_expires_at')
    .whereRaw('lease_expires_at < now()')
    .update({
      status: 'failed',
      finished_at: db.fn.now(),
      error_kind: 'worker_lost',
      error_message: q.raw('CASE WHEN status IN (?, ?) THEN ? ELSE ? END', [
        'backing_up',
        'arming',
        'The worker died before this job wrote anything on the router (it was taking the pre-change ' +
          'backup over SSH; a backup file may still be on the router). Choose the profile again.',
        'The worker died while this job was writing the APN profile on the router: lte1 may or may not ' +
          'use the chosen profile. Choose the profile again: the new job reads the router first.',
      ]),
      updated_at: db.fn.now(),
    })
    .returning(['id', 'device_id'])) as Array<{ id: string | number; device_id: number }>;
  report.failed += lostApnJobs.length;
  if (lostApnJobs.length > 0) {
    await q('lte_apn_jobs')
      .whereIn('job_id', lostApnJobs.map((r) => Number(r.id)))
      .whereNull('outcome')
      .update({
        outcome: q.raw('CASE WHEN wrote_at IS NOT NULL THEN ? ELSE ? END', ['failed', 'refused']),
        outcome_detail: q.raw('CASE WHEN wrote_at IS NOT NULL THEN ? ELSE ? END', [
          'The worker died after this job began writing on the router: lte1 is in an unknown state until ' +
            'the next job reads it. The pre-change backup is kept.',
          'The worker died before this job wrote anything on the router.',
        ]),
        updated_at: db.fn.now(),
      });
  }
  for (const r of lostApnJobs) {
    logger.error({ jobId: Number(r.id), deviceId: r.device_id }, 'change queue: lease expired on an lte_apn job — failed, device released');
  }

  // 1g. `legacy_compliance` past `claimed` — failed, for 1e's reason: it arms
  // no on-box dead-man (legacyCompliance.service.ts, LEGACY_COMPLIANCE_NO_DEADMAN).
  // `legacy_compliance_jobs.wrote_at` is set before the first line that
  // changes the router, `random_source_port_sent_at` before the l2tp line.
  const lostComplianceJobs = (await q('change_jobs')
    .where('kind', 'legacy_compliance')
    .whereIn('status', ['backing_up', 'arming', ...WRITE_COMMITTED_STATUSES])
    .whereNotNull('lease_expires_at')
    .whereRaw('lease_expires_at < now()')
    .update({
      status: 'failed',
      finished_at: db.fn.now(),
      error_kind: 'worker_lost',
      error_message: q.raw('CASE WHEN status IN (?, ?) THEN ? ELSE ? END', [
        'backing_up',
        'arming',
        'The worker died before this job wrote anything on the router (it was taking the pre-change ' +
          'backup over SSH; a backup file may still be on the router). Queue it again: the new job reads the router first.',
        'The worker died while this job was writing the template corrections on the router over SSH: some may be ' +
          'there, and if the random-source-port line was sent, the self-revert it started on the router decides ' +
          'on its own. Queue it again: the new job reads the router first and writes only what is missing.',
      ]),
      updated_at: db.fn.now(),
    })
    .returning(['id', 'device_id'])) as Array<{ id: string | number; device_id: number }>;
  report.failed += lostComplianceJobs.length;
  if (lostComplianceJobs.length > 0) {
    await q('legacy_compliance_jobs')
      .whereIn('job_id', lostComplianceJobs.map((r) => Number(r.id)))
      .whereNull('outcome')
      .update({
        outcome: q.raw('CASE WHEN wrote_at IS NOT NULL THEN ? ELSE ? END', ['failed', 'refused']),
        outcome_detail: q.raw('CASE WHEN wrote_at IS NOT NULL THEN ? ELSE ? END', [
          'The worker died after this job began writing on the router: the corrections are in an unknown state until ' +
            'the next job reads them. The pre-change backup is kept.',
          'The worker died before this job wrote anything on the router.',
        ]),
        updated_at: db.fn.now(),
      });
  }
  for (const r of lostComplianceJobs) {
    logger.error({ jobId: Number(r.id), deviceId: r.device_id }, 'change queue: lease expired on a legacy_compliance job — failed, device released');
  }

  // 1g'. `site_rename` past `claimed` — failed, for 1e's reason: no on-box
  // dead-man (siteRename.service.ts, SITE_RENAME_NO_DEADMAN), and an untouched
  // job would hold the device lock for good. Its row is settled as
  // `settleSiteRename` would: `unsettled` once the router may hold a new name,
  // `failed` after a CHR write, `refused` otherwise. Not requeued: the card's
  // « Relancer » re-enqueues the same pair, and every stage is idempotent.
  const lostRenameJobs = (await q('change_jobs')
    .where('kind', 'site_rename')
    .whereIn('status', ['backing_up', 'arming', ...WRITE_COMMITTED_STATUSES])
    .whereNotNull('lease_expires_at')
    .whereRaw('lease_expires_at < now()')
    .update({
      status: 'failed',
      finished_at: db.fn.now(),
      error_kind: 'worker_lost',
      error_message: q.raw('CASE WHEN status IN (?, ?) THEN ? ELSE ? END', [
        'backing_up',
        'arming',
        'The worker died before this rename wrote anything on the router (it was taking the pre-change backup over ' +
          'SSH; a backup file may still be on the router). Queue it again: the new job reads the CHR and the router first.',
        'The worker died while this rename was writing on the CHR or the router: the login, the identity or the device ' +
          'row may be half-renamed, and the self-revert started on the router decides on its own. Relaunch the same rename ' +
          'from the device page: it reads the CHR and the router first and finishes only what is left.',
      ]),
      updated_at: db.fn.now(),
    })
    .returning(['id', 'device_id'])) as Array<{ id: string | number; device_id: number }>;
  report.failed += lostRenameJobs.length;
  if (lostRenameJobs.length > 0) {
    await q('site_rename_jobs')
      .whereIn('job_id', lostRenameJobs.map((r) => Number(r.id)))
      .whereNull('outcome')
      .update({
        outcome: q.raw(
          'CASE WHEN cut_sent_at IS NOT NULL OR (db_login_switched_at IS NOT NULL AND db_login_restored_at IS NULL) ' +
            'OR (identity_set_at IS NOT NULL AND finalized_at IS NULL) THEN ? ' +
            'WHEN chr_written_at IS NOT NULL OR finalized_at IS NOT NULL OR chr_old_removed_at IS NOT NULL OR identity_set_at IS NOT NULL THEN ? ' +
            'ELSE ? END',
          ['unsettled', 'failed', 'refused'],
        ),
        outcome_detail: 'The worker died during this rename (worker_lost). The names are whatever the CHR and the router hold now; ' +
          'relaunching the same rename reads both first and settles what is left.',
        updated_at: db.fn.now(),
      });
  }
  for (const r of lostRenameJobs) {
    logger.error({ jobId: Number(r.id), deviceId: r.device_id }, 'change queue: lease expired on a site_rename job — failed, device released');
  }

  // 1h. `infra_account` past `claimed` — failed, for 1b's reason: no dead-man
  // (services/infraConcentrator/job.service.ts), and an untouched job would hold
  // the concentrator's lock for good. Not requeued: the next request reads the
  // concentrator first and writes nothing if the entry is already as wanted.
  const lostInfraJobs = (await q('change_jobs')
    .where('kind', 'infra_account')
    .whereIn('status', ['backing_up', 'arming', ...WRITE_COMMITTED_STATUSES])
    .whereNotNull('lease_expires_at')
    .whereRaw('lease_expires_at < now()')
    .update({
      status: 'failed',
      finished_at: db.fn.now(),
      error_kind: 'worker_lost',
      error_message:
        "Le worker s'est arrêté pendant que ce job traitait le compte d'infrastructure du site : le compte a pu " +
        "être ajouté (ou retiré) ou non. La prochaine demande relit d'abord le concentrateur.",
      updated_at: db.fn.now(),
    })
    .returning(['id', 'device_id'])) as Array<{ id: string | number; device_id: number }>;
  report.failed += lostInfraJobs.length;
  for (const r of lostInfraJobs) {
    logger.error({ jobId: Number(r.id), deviceId: r.device_id }, 'change queue: lease expired on an infra_account job — failed, device released');
    await settleInfraAccount({ id: r.id }, { ok: false, error: "Le worker s'est arrêté pendant le job ; rien n'a été conclu sur le compte." });
  }

  // 1i. `wan_link` past `claimed` — failed, for 1e's reason: no on-box
  // dead-man (wanLink.service.ts, WAN_LINK_NO_DEADMAN). The script started on
  // the router decides alone and reverts by itself; the job row is settled
  // here: the outcome by `wrote_at`, the planned-cut window closed (the held
  // alerts are released), the password wiped. Not requeued.
  const lostWanJobs = (await q('change_jobs')
    .where('kind', 'wan_link')
    .whereIn('status', ['backing_up', 'arming', ...WRITE_COMMITTED_STATUSES])
    .whereNotNull('lease_expires_at')
    .whereRaw('lease_expires_at < now()')
    .update({
      status: 'failed',
      finished_at: db.fn.now(),
      error_kind: 'worker_lost',
      error_message: q.raw('CASE WHEN status IN (?, ?) THEN ? ELSE ? END', [
        'backing_up',
        'arming',
        'The worker died before this job started anything on the router (it was taking the pre-change backup over ' +
          'SSH; a backup file may still be on the router). Queue it again: the new job reads the router first.',
        'The worker died after this job may have started the WAN link script on the router. The script decides on its ' +
          'own: it keeps the new link only if it carries traffic, and puts the old one back by itself otherwise. The ' +
          'site variables were NOT updated: check the router, then relaunch (a router already on the target ends `present`).',
      ]),
      updated_at: db.fn.now(),
    })
    .returning(['id', 'device_id'])) as Array<{ id: string | number; device_id: number }>;
  report.failed += lostWanJobs.length;
  if (lostWanJobs.length > 0) {
    await q('wan_link_jobs')
      .whereIn('job_id', lostWanJobs.map((r) => Number(r.id)))
      .update({
        outcome: q.raw('COALESCE(outcome, CASE WHEN wrote_at IS NOT NULL THEN ? ELSE ? END)', ['failed', 'refused']),
        outcome_detail: q.raw('COALESCE(outcome_detail, CASE WHEN wrote_at IS NOT NULL THEN ? ELSE ? END)', [
          'The worker died after the WAN link script may have started on the router: the link is whatever the script ' +
            'decided. The site variables were not updated; the pre-change backup is kept.',
          'The worker died before this job started anything on the router.',
        ]),
        cut_expected_until: q.raw('CASE WHEN cut_expected_until IS NULL THEN NULL ELSE GREATEST(cut_expected_from, LEAST(cut_expected_until, now())) END'),
        pppoe_password_enc: null,
        pppoe_key_version: null,
        updated_at: db.fn.now(),
      });
  }
  for (const r of lostWanJobs) {
    logger.error({ jobId: Number(r.id), deviceId: r.device_id }, 'change queue: lease expired on a wan_link job — failed, device released');
  }

  type ReapedRow = {
    id: string | number;
    tenant_id: number;
    device_id: number;
    kind: ChangeJobKind;
    lease_expires_at: Date | null;
    deadman_disarmed_at?: Date | null;
  };
  const RETURNED = ['id', 'tenant_id', 'device_id', 'kind', 'lease_expires_at'];
  const owe = (r: ReapedRow, reapedFrom: ReapedNetJob['reapedFrom'], mode: ReapedNetJob['mode']): void => {
    if (!GENERIC_WRITE_KINDS.has(r.kind)) return;
    report.netsOwed.push({
      id: Number(r.id),
      tenantId: Number(r.tenant_id),
      deviceId: Number(r.device_id),
      kind: r.kind,
      reapedFrom,
      mode,
      leaseExpiredAt: r.lease_expires_at ? new Date(r.lease_expires_at) : null,
    });
  };

  // 2. `backing_up` / `arming` — recoverable, but not resumable. A generic
  // write here may have left its preflight blob, and in `arming` its
  // dead-man, on the router: nothing was configured, so they are owed a
  // release (`netsOwed`) — left there, the dead-man reboots the router at its
  // deadline for nothing. A redeploy lands here as surely as a crash.
  for (const status of ['backing_up', 'arming'] as const) {
    const failed = (await q('change_jobs')
      .where('status', status)
      .whereNotNull('lease_expires_at')
      .whereRaw('lease_expires_at < now()')
      .update({
        status: 'failed',
        finished_at: db.fn.now(),
        error_kind: 'worker_lost',
        error_message:
          status === 'arming'
            ? 'The worker died while installing the safety net. NOTHING WAS APPLIED, but a ' +
              'dead-man may still be armed on the device. ObliWAN takes it down from here; until ' +
              'this message says it did, assume the router reboots at its deadline (check deadman_handle).'
            : 'The worker died while taking the pre-change backup. Nothing was applied. ' +
              'Recompile the plan and start again.',
        updated_at: db.fn.now(),
      })
      .returning(RETURNED)) as ReapedRow[];
    report.failed += failed.length;
    for (const r of failed) {
      owe(r, status, 'unused_net');
      logger.error(
        { jobId: Number(r.id), deviceId: r.device_id, status },
        'change queue: lease expired before the write — job failed, device released',
      );
    }
  }

  // 2b. `applying` BEFORE the write frontier (migration 099). The worker
  // stamps `transmit_started_at` in the same UPDATE that renews its lease,
  // immediately before the first command that may configure the router; NULL
  // with the lease run out means that command was never handed over. The row
  // lock serialises this UPDATE with that stamp, so exactly one wins: either
  // the worker sends and this does not match, or this fails the job and the
  // worker's stamp (and therefore its send) is refused. Generic write kinds
  // only: they are the ones that stamp it (every other kind was settled above).
  const beforeFrontier = (await q('change_jobs')
    .where('status', 'applying')
    .whereIn('kind', [...GENERIC_WRITE_KINDS])
    .whereNull('transmit_started_at')
    .whereNotNull('lease_expires_at')
    .whereRaw('lease_expires_at < now()')
    .update({
      status: 'failed',
      finished_at: db.fn.now(),
      error_kind: 'worker_lost',
      error_message:
        'The worker died after installing the safety net and BEFORE handing the router its first ' +
        'configuration command (no write frontier was recorded): NOTHING WAS TRANSMITTED. ObliWAN ' +
        'takes the unused dead-man down from here; until this message says it did, assume the ' +
        'router reboots at its deadline (confirm_deadline).',
      updated_at: db.fn.now(),
    })
    .returning(RETURNED)) as ReapedRow[];
  report.failed += beforeFrontier.length;
  for (const r of beforeFrontier) {
    owe(r, 'applying', 'unused_net');
    logger.error(
      { jobId: Number(r.id), deviceId: r.device_id },
      'change queue: lease expired in applying BEFORE the write frontier — nothing sent; job failed, net owed a release',
    );
  }

  // 2c. Past the frontier with the change PROVEN: its `postcheck` step
  // succeeded, and the worker died during the soak or the disarm. `failJob`
  // disarms such a job for a live worker ("a revert nobody decided on, of a
  // change that worked"); a dead worker owed the same. Failed, never requeued
  // or succeeded (the soak did not finish); the dead-man is disarmed by the
  // releaser, and a job already disarmed owes nothing.
  const verified = (await q('change_jobs as j')
    .whereIn('j.status', ['verifying', 'soaking', 'disarming'])
    .whereIn('j.kind', [...GENERIC_WRITE_KINDS])
    .whereNotNull('j.lease_expires_at')
    .whereRaw('j.lease_expires_at < now()')
    .whereExists(function postcheckPassed() {
      void this.select(db.raw('1'))
        .from('change_job_steps as s')
        .whereRaw('s.job_id = j.id')
        .whereRaw('s.attempt = j.attempt')
        .where('s.kind', 'postcheck')
        .where('s.status', 'succeeded');
    })
    .update({
      status: 'failed',
      finished_at: db.fn.now(),
      error_kind: 'worker_lost',
      error_message: q.raw('CASE WHEN deadman_disarmed_at IS NULL THEN ? ELSE ? END', [
        'The worker died AFTER the change was applied and its post-conditions verified, before the ' +
          'dead-man was disarmed. The change stands. ObliWAN disarms the dead-man from here so it ' +
          'does not revert a verified change; until this message says it did, assume the router ' +
          'reverts it with a reboot at its deadline (confirm_deadline).',
        'The worker died AFTER the change was applied, verified and its dead-man removed, before ' +
          'the job was closed. The change stands; only the job failed.',
      ]),
      updated_at: db.fn.now(),
    })
    .returning([...RETURNED, 'deadman_disarmed_at'])) as ReapedRow[];
  report.failed += verified.length;
  for (const r of verified) {
    if (!r.deadman_disarmed_at) owe(r, 'after_postcheck', 'verified_change');
    logger.error(
      { jobId: Number(r.id), deviceId: r.device_id },
      'change queue: lease expired after a VERIFIED change — job failed, the change stands',
    );
  }

  // 3. Past the frontier. COUNTED AND NAMED, NEVER TOUCHED.
  const stuck = (await q('change_jobs')
    .whereIn('status', [...WRITE_COMMITTED_STATUSES])
    .whereNotNull('lease_expires_at')
    .whereRaw('lease_expires_at < now()')
    .select('id', 'device_id', 'status')) as Array<{
    id: string | number;
    device_id: number;
    status: string;
  }>;
  report.needingInspection = stuck.map((r) => Number(r.id));
  for (const r of stuck) {
    logger.error(
      { jobId: Number(r.id), deviceId: r.device_id, status: r.status },
      'change queue: a job whose worker died AFTER the write began. NOT requeued and NOT failed ' +
        '— it needs human inspection. The on-box dead-man is the recovery path.',
    );
  }

  return report;
}

// ============================================================================
// Reads
// ============================================================================

export interface JobQuery {
  deviceId?: number;
  /** Team scope (migration 087): only these devices' jobs; null/undefined = unrestricted. */
  deviceIdsIn?: number[] | null;
  status?: ChangeJobStatus[];
  activeOnly?: boolean;
  /** Job kinds (`management_access`, `legacy_compliance`…). */
  kinds?: string[];
  /** Device name, site name or site code, case-insensitive substring. */
  search?: string;
  limit?: number;
  offset?: number;
}

/**
 * `ChangeJobSummary` with the guard's OWN reason objects rather than the bare
 * `GuardReason` codes. The UI needs the message, the offending record and the
 * plan line it came from; a code on its own is "we refused" with nothing an
 * operator can act on.
 */
export type ChangeJobView = Omit<ChangeJobSummary, 'guardReasons'> & { guardReasons: unknown[] };

export async function listJobs(
  tenantId: number,
  query: JobQuery = {},
): Promise<{ rows: ChangeJobView[]; total: number; statusCounts: Record<string, number>; godView?: true }> {
  const limit = Math.min(Math.max(query.limit ?? 50, 1), 1000);
  const offset = Math.max(query.offset ?? 0, 0);
  const search = (query.search ?? '').trim();
  // ILIKE's own wildcards are escaped: a site code typed with "_" is literal.
  const pattern = search === '' ? null : `%${search.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;

  // God view (a platform admin's GET on the master tenant): every tenant's
  // jobs, each tagged with its tenant; anyone else: this tenant's.
  let godView = false;
  const base = (withStatus = true) => {
    const q = db('change_jobs as j');
    godView = applyTenantScope(q, 'j.tenant_id', tenantId);
    if (query.deviceId) void q.where('j.device_id', query.deviceId);
    if (query.deviceIdsIn) void q.whereIn('j.device_id', query.deviceIdsIn);
    if (query.kinds?.length) void q.whereIn('j.kind', query.kinds);
    if (withStatus && query.status?.length) void q.whereIn('j.status', query.status);
    if (withStatus && query.activeOnly) void q.whereIn('j.status', [...ACTIVE_CHANGE_JOB_STATUSES]);
    if (pattern !== null) {
      void q.whereExists(function matching() {
        void this.select(db.raw('1'))
          .from('devices as sd')
          .leftJoin('sites as ss', 'ss.id', 'sd.site_id')
          .whereRaw('sd.id = j.device_id')
          .andWhere(function anyName() {
            void this.whereRaw('sd.name ILIKE ?', [pattern])
              .orWhereRaw('ss.name ILIKE ?', [pattern])
              .orWhereRaw('ss.code ILIKE ?', [pattern]);
          });
      });
    }
    return q;
  };

  const [{ count }] = (await base().count({ count: '*' })) as Array<{ count: string }>;
  // Per status over the same filters minus the status one: the summary tiles
  // count every matching job, not only the page the screen has loaded.
  const statusRows = (await base(false)
    .select('j.status')
    .count({ n: '*' })
    .groupBy('j.status')) as Array<{ status: string; n: string }>;
  const statusCounts: Record<string, number> = {};
  for (const r of statusRows) statusCounts[r.status] = Number(r.n);
  const rows = (await base()
    .leftJoin('devices as d', 'd.id', 'j.device_id')
    .leftJoin('sites as s', 's.id', 'd.site_id')
    .orderBy('j.created_at', 'desc')
    .orderBy('j.id', 'desc')
    .limit(limit)
    .offset(offset)
    .select('j.*', 'd.name as device_name', 'd.site_id as device_site_id', 's.name as device_site_name')) as Array<
      ChangeJobRow & { device_name: string | null; device_site_id: number | null; device_site_name: string | null }
    >;

  const views = rows.map((r) => ({
    ...toJobSummary(r, r.device_name ?? ''),
    siteId: r.device_site_id === null ? null : Number(r.device_site_id),
    siteName: r.device_site_name ?? null,
    guardReasons: guardReasonsOf(r),
  }));
  return {
    rows: await withTenantNames(views, 'tenantId', godView),
    total: Number(count),
    statusCounts,
    ...godViewMeta(godView),
  };
}

/** Tenant-scoped by construction: a job of another tenant reads as absent. */
export async function getJobRow(
  tenantId: number,
  jobId: number,
  q: Knex | Knex.Transaction = db,
): Promise<(ChangeJobRow & { device_name: string | null }) | null> {
  const row = (await q('change_jobs as j')
    .leftJoin('devices as d', 'd.id', 'j.device_id')
    .where({ 'j.id': jobId, 'j.tenant_id': tenantId })
    .first('j.*', 'd.name as device_name')) as
    | (ChangeJobRow & { device_name: string | null })
    | undefined;
  return row ?? null;
}

export async function listJobSteps(
  tenantId: number,
  jobId: number,
): Promise<Array<Record<string, unknown>>> {
  const rows = (await db('change_job_steps')
    .where({ job_id: jobId, tenant_id: tenantId })
    .orderBy('attempt')
    .orderBy('seq')
    .select('*')) as Array<Record<string, unknown>>;

  return rows.map((r) => ({
    id: Number(r.id),
    jobId: Number(r.job_id),
    seq: r.seq,
    attempt: r.attempt,
    kind: r.kind,
    status: r.status,
    planOpSeq: r.plan_op_seq,
    startedAt: r.started_at ? new Date(r.started_at as Date).toISOString() : null,
    finishedAt: r.finished_at ? new Date(r.finished_at as Date).toISOString() : null,
    durationMs: r.duration_ms,
    outputRedacted: r.output_redacted,
    errorRedacted: r.error_redacted,
  }));
}

// ============================================================================
// Abort
// ============================================================================

/**
 * Cancel a job that has NOT started writing.
 *
 * `aborted` is unreachable from `applying` onward, in the state machine and
 * here: you cannot cancel a change that is already going onto a router. You can
 * only let the machinery finish or let the dead-man fire. A route that offered
 * "abort" on an applying job would be offering a button that does nothing, at
 * the exact moment somebody is desperate enough to press it twice.
 */
export async function abortJob(
  tenantId: number,
  jobId: number,
  userId: number | null,
  reason: string | null,
): Promise<ChangeJobRow> {
  const job = await getJobRow(tenantId, jobId);
  if (!job) throw new Error(`Change job ${jobId} not found`);
  if (!canTransition(job.status, 'aborted')) {
    throw new InvalidTransitionError(job.status, 'aborted');
  }
  const aborted = await transitionJob(job, 'aborted', {
    errorKind: 'aborted',
    errorMessage:
      `Aborted by user ${userId ?? 'unknown'}` + (reason ? `: ${reason}` : '') +
      '. Nothing had been written to the device.',
  });
  // A wan_link job carries its PPPoE password (encrypted) until it concludes:
  // an abort concludes it, refused, and the password goes with it.
  if (job.kind === 'wan_link') {
    await db('wan_link_jobs')
      .where({ job_id: jobId })
      .whereNull('outcome')
      .update({
        outcome: 'refused',
        outcome_detail: 'Aborted before anything was written on the router.',
        pppoe_password_enc: null,
        pppoe_key_version: null,
        updated_at: db.fn.now(),
      })
      .catch((err: unknown) => logger.error({ err, jobId }, 'wan_link: could not settle an aborted job'));
  }
  return aborted;
}

// ============================================================================
// The worker
// ============================================================================

export type JobRunner = (job: ChangeJobRow) => Promise<void>;

let timer: NodeJS.Timeout | null = null;
let runner: JobRunner | null = null;
let armed = false;
const inFlight = new Set<number>();
/** Set by `stopChangeWorker()` (and only by it), cleared by `startChangeWorker()`. */
let stopping = false;

/**
 * Is this process shutting down its change worker? `runPhases` asks it before
 * the preflight backup, before arming and before the first configuration
 * command: a job that has not crossed its write frontier STOPS there (its
 * unused net taken down by `failJob`) rather than race the grace period into
 * a half-sent change the dead-man then reverts with a reboot. A redeploy is
 * not a decision to reboot routers.
 */
export function isChangeWorkerStopping(): boolean {
  return stopping;
}

/**
 * Should THIS process take jobs?
 *
 * Leader election, with the one deliberate asymmetry the spec asks for: a
 * dedicated `worker` role processes jobs whether or not it holds the leadership
 * lock, because several workers side by side is precisely the deployment
 * `FOR UPDATE SKIP LOCKED` exists for. An `all` process must win the election
 * first — otherwise two `docker compose up` on the same database would both
 * push to the same fleet, which is the failure leader election was written to prevent.
 *
 * A `web` replica never reaches here: `config.runsBackground` is false and
 * `startChangeWorker` returns before arming anything.
 */
export function shouldProcessJobs(): boolean {
  if (!config.runsBackground) return false;
  return config.role === 'worker' || leaderElection.isLeader();
}

export function startChangeWorker(jobRunner: JobRunner): void {
  if (armed) return;
  runner = jobRunner;
  stopping = false;

  if (!config.runsBackground) {
    logger.info(
      { role: config.role },
      'Change queue: not armed (OBLIWAN_ROLE=web serves HTTP only) — no write will originate here',
    );
    return;
  }

  armed = true;
  timer = setInterval(() => {
    void tick();
  }, POLL_INTERVAL_MS);
  // A queue must never be the reason the process refuses to exit.
  timer.unref();

  logger.info(
    { worker: WORKER_ID, role: config.role, concurrency, concurrencySetting: SETTINGS_KEYS.MAX_CONCURRENT_JOBS },
    'Change queue armed — this process may now write to equipment through change_jobs',
  );
}

/**
 * Stop taking new work. In-flight jobs are AWAITED, not cancelled: killing a
 * session mid-apply is how a half-configured router happens. If they outlast
 * the grace period the process exits anyway and their leases expire, which is
 * the crash path — and the crash path is safe by construction (see the reaper).
 */
export async function stopChangeWorker(graceMs = 8_000): Promise<void> {
  armed = false;
  stopping = true;
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
  const deadline = Date.now() + graceMs;
  while ((inFlight.size > 0 || pendingReleases.size > 0) && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 200));
  }
  if (inFlight.size > 0 || pendingReleases.size > 0) {
    logger.warn(
      { jobs: [...inFlight], releasesInFlight: pendingReleases.size },
      'Change queue: shutting down with jobs still in flight — their leases will expire and the ' +
        'reaper will classify them (a job short of its write frontier has its net released by the ' +
        'next leader). Nothing is requeued past the write frontier.',
    );
  }
  logger.info('Change queue stopped');
}

/** One poll: reap, then fill the free slots. Exported for the tests, which must
 *  be able to drive the queue without a 3-second wall clock. */
export async function tick(): Promise<void> {
  if (!armed || !runner) return;
  if (!shouldProcessJobs()) return;

  try {
    const report = await reapExpiredLeases();
    // Not awaited: a release dials a router and can take a minute; the claim
    // loop below must not wait for it. `stopChangeWorker` does, within grace.
    if (report.netsOwed.length > 0) void releaseReapedNets(report.netsOwed);
  } catch (err) {
    logger.error(err, 'Change queue: the reaper failed this tick');
  }

  const limit = await maxConcurrentJobs();
  while (inFlight.size < limit && armed && shouldProcessJobs()) {
    let job: ChangeJobRow | null = null;
    try {
      job = await claimNextJob();
    } catch (err) {
      logger.error(err, 'Change queue: claim failed');
      return;
    }
    if (!job) return;

    const id = Number(job.id);
    inFlight.add(id);
    const currentRunner = runner;
    void currentRunner(job)
      .catch((err) => {
        // `runJob` is written not to throw; this is the net under the net.
        logger.error({ err, jobId: id }, 'Change queue: the runner threw — job left as it stands');
      })
      .finally(() => {
        inFlight.delete(id);
      });
  }
}

export function inFlightJobIds(): number[] {
  return [...inFlight];
}

export const jobQueue = {
  WORKER_ID,
  claimNextJob,
  renewLease,
  assertLease,
  transitionJob,
  startStep,
  finishStep,
  skipStep,
  reapExpiredLeases,
  releaseReapedNets,
  listJobs,
  getJobRow,
  listJobSteps,
  abortJob,
  startChangeWorker,
  stopChangeWorker,
  tick,
  shouldProcessJobs,
  isWithinMaintenanceWindow,
  inFlightJobIds,
};

/** Re-exported so a caller need not import `@obliwan/shared` to ask the one
 *  question that decides whether a job may be retried at all. */
export { isWriteJobKind };
