// ============================================================================
// ObliWAN - fleet OS upgrade ("mise a jour du parc"): the HTTP layer
// ============================================================================
//
// One screen, usable by somebody who is not a network engineer: "which of my
// RouterOS boxes are behind, and bring these ones up to date". Two answers and
// one gesture:
//
//   GET  /os-upgrade/devices   every RouterOS device of the tenant, its
//                              current version, the fleet target it is judged
//                              against and ONE status out of four
//   POST /os-upgrade/preview   everything the launch would decide (refusals,
//                              version, canary waves and which router is in
//                              which wave), with nothing written
//   POST /os-upgrade           one `os_upgrade` change job for one device, or
//                              a canary-wave rollout of them for several
//   POST /os-upgrade/refresh-versions
//                              re-read the version off the routers whose
//                              reading is missing or old (section 6b)
//
// +- WHAT THIS FILE DOES NOT DO --------------------------------------------+
// | It NEVER talks to a router and it NEVER writes a job or a rollout row   |
// | itself. Nothing writes to an equipment outside `change_jobs`, and       |
// | the `os_upgrade` job belongs to the firmware module. The fleet TARGET   |
// | is read from the release watch (services/firmware/releases.service);   |
// | the two WRITES are reached through ONE port, `OsUpgradeLauncher`,      |
// | which defaults to rollout.service `osUpgradeLauncher` (one job through |
// | `enqueueOsUpgradeJob`, or an `os_upgrade` rollout composed and         |
// | launched). `setOsUpgradeLauncher()` replaces it (the harness) or, with |
// | `null`, unwires it: the listing then still answers in full and the     |
// | launch answers 503 with code `backend_unwired` - a screen that offered |
// | the button over no launcher would queue nothing and say it had.        |
// +-------------------------------------------------------------------------+
//
// +- THE CAPABILITY MAP ----------------------------------------------------+
// | DEVICE_READ     the listing. Writes nothing. The change-queue details   |
// |                 in it (job and rollout ids, rollout names, error and    |
// |                 outcome texts, the kill-switch note, the kind of a      |
// |                 non-upgrade job) are returned only to a caller holding  |
// |                 PLAN_CREATE, which is what `/changes` and `/rollouts`   |
// |                 require to read them; anybody else gets the status.     |
// | DEVICE_WRITE    re-reading versions: it dials routers (read-only on the |
// |                 equipment), the same grant as `/identity/sweep`.    |
// | CHANGE_APPLY    the preview and the launch (route level). The preview   |
// |                 writes nothing; it is the first step of a launch.       |
// | ROLLOUT_MANAGE  checked AGAIN in the handler when more than one device  |
// |                 is selected: several devices become a rollout, and      |
// |                 `/rollouts` composes and launches one only under        |
// |                 ROLLOUT_MANAGE. This endpoint must not be the way round |
// |                 that grant.                                             |
// | CHANGE_APPROVE  checked AGAIN for the override reason, which every      |
// |                 upgrade carries (see SIGNATURES below).                 |
// +-------------------------------------------------------------------------+
//
// EVERY read is scoped by `req.tenantId`, which comes from the SESSION and
// never from the body. Device ids in the body are re-read inside that tenant;
// an id that belongs to another tenant is reported exactly like an id that
// does not exist.

import type { NextFunction, Request, Response } from 'express';
import type { Knex } from 'knex';
import { z } from 'zod';
import {
  ACTIVE_CHANGE_JOB_STATUSES,
  ACTIVE_ROLLOUT_TARGET_STATUSES,
  CAPABILITIES,
  compareRouterOsVersion,
  isRouterOsReleaseVersion,
  parseRouterOsVersion,
  planWaves,
  type Capability,
  type PlannedWave,
  type RouterOsTargetMode,
  type RouterOsTargetUnresolved,
} from '@obliwan/shared';
import { db } from '../db';
import { AppError } from '../middleware/errorHandler';
import { permissionService } from '../services/permission.service';
import { canWriteEveryDevice, deviceListScope } from '../services/teamScope.service';
import { KillSwitchEngagedError, readKillSwitch } from '../services/change/killSwitch.service';
import { ChangeRefusedError, changeExecutorReadiness } from '../services/change/apply.service';
import { DeviceBusyError } from '../services/change/jobQueue.service';
import { RolloutRefusedError, osUpgradeLauncher, previewRollout } from '../services/change/rollout.service';
import { getRouterOsFirmwareStatus } from '../services/firmware/releases.service';
import { MAX_SWEEP_DEVICES, observeDeviceIdentity } from '../services/fleet/identityWatch.service';
import { logger } from '../utils/logger';
import { auditGodViewFanOut } from '../services/godViewAudit.service';
import {
  enterObjectTenant,
  hasGlobalView,
  ownerTenantsOf,
  runAsTenant,
  tenantIdsInScope,
  tenantNames,
} from '../utils/globalView';

/** The change-job kind (shared `CHANGE_JOB_KINDS`, migration 047) and the
 *  rollout kind (`rollouts.kind`, migration 047) this screen launches and
 *  watches. Spelled once here so every query below agrees. */
export const OS_UPGRADE_JOB_KIND = 'os_upgrade';
export const OS_UPGRADE_ROLLOUT_KIND = 'os_upgrade';

/** 500 is the fleet ceiling ObliWAN is dimensioned for, and the
 *  same ceiling `/rollouts` puts on a composition. */
const MAX_DEVICES = 500;

/**
 * SIGNATURES - what every upgrade launch must carry, and why it is not
 * optional.
 *
 *  - An override reason (CHANGE_APPROVE). An `os_upgrade` job has no plan, so
 *    the Management-Path Guard has nothing to simulate and answers
 *    INDETERMINATE (apply.service `guardForPlanlessWrite`); migration 047 adds
 *    the kind to `change_jobs_guard_required_chk`, and 009's
 *    `change_jobs_override_chk` then demands a signed reason.
 *  - A degraded confirmation. The job arms NO dead-man (a scheduler script
 *    cannot un-install a RouterOS release), so it is queued at `degraded`, and
 *    047 adds it to `change_jobs_degraded_confirm_chk`: a box that does not
 *    boot back is a site visit.
 *
 * Refused HERE, before the launcher is called, so the operator is asked once
 * in the confirmation dialog instead of discovering both by two failures.
 */
export const UPGRADE_REQUIRES = { overrideReason: true, degradedConfirmation: true } as const;

// ============================================================================
// 1. Versions (pure) - what a box prints, read with the shared arithmetic
// ============================================================================

/**
 * The bare version out of what a RouterOS box prints: `7.24.5 (stable)` ->
 * `7.24.5`, `7.25rc1 (testing)` -> `7.25rc1`. `null` for anything the shared
 * `parseRouterOsVersion` refuses - including a vendor build id such as Zyxel's
 * `V5.70(ABLN.2)`, whose numeric spine must not be read as RouterOS 5.70. The
 * bracket may hold a channel WORD only.
 */
export function bareRouterOsVersion(raw: string | null | undefined): string | null {
  if (typeof raw !== 'string') return null;
  const m = /^\s*([0-9][0-9a-z.]*)\s*(?:\(\s*[a-z][a-z-]*\s*\))?\s*$/i.exec(raw);
  if (!m) return null;
  const bare = m[1].toLowerCase();
  return parseRouterOsVersion(bare) ? bare : null;
}

function majorOf(bare: string): number {
  return parseRouterOsVersion(bare)!.major;
}

// ============================================================================
// 2. The status (pure) - four answers, and why
// ============================================================================

export const UPGRADE_STATUSES = ['up_to_date', 'behind', 'unknown', 'in_progress'] as const;
export type UpgradeStatus = (typeof UPGRADE_STATUSES)[number];

export type UpgradeStatusReason =
  /** in_progress: an `os_upgrade` job holds the device. */
  | 'job_active'
  /** in_progress: an upgrade rollout holds the device; its job is not queued yet. */
  | 'rollout_active'
  /** unknown: no version anywhere - neither read off the box nor in the inventory. */
  | 'version_missing'
  /** unknown: a version string the shared parser refuses. */
  | 'version_unparseable'
  /** unknown: no fleet target is resolved (no release known, or an unreadable target). */
  | 'no_target'
  /** unknown: the target sits on another major line. Every RouterOS 6 box is
   *  here: the fleet target is a RouterOS 7 release, and 6 -> 7 is a
   *  migration, not an update. */
  | 'major_differs'
  | 'at_target'
  /** up_to_date: newer than the target (a newer build, a testing release).
   *  It is not behind, and it is not offered a downgrade either. */
  | 'ahead_of_target'
  | 'below_target';

export interface StatusVerdict {
  status: UpgradeStatus;
  reason: UpgradeStatusReason;
  /** Bare versions (`7.24.5`), or null when unreadable / absent. */
  current: string | null;
  target: string | null;
}

/**
 * The one place a device's upgrade status is decided.
 *
 * In-progress wins over everything: a box mid-upgrade still reports its OLD
 * version, and calling it "behind" is how somebody launches it a second time.
 * After that, ANY doubt is `unknown`, never `behind` - `behind` is the status
 * that invites a reboot of a customer's router, so it is reserved for the case
 * where both sides were read and compared on the same major line.
 */
export function computeUpgradeStatus(input: {
  currentVersion: string | null;
  targetVersion: string | null;
  activeUpgradeJob: boolean;
  inUpgradeRollout: boolean;
}): StatusVerdict {
  const current = bareRouterOsVersion(input.currentVersion);
  const target = bareRouterOsVersion(input.targetVersion);
  if (input.activeUpgradeJob) return { status: 'in_progress', reason: 'job_active', current, target };
  if (input.inUpgradeRollout) {
    return { status: 'in_progress', reason: 'rollout_active', current, target };
  }
  const raw = input.currentVersion === null ? '' : input.currentVersion.trim();
  if (raw === '') return { status: 'unknown', reason: 'version_missing', current, target };
  if (!current) return { status: 'unknown', reason: 'version_unparseable', current, target };
  if (!target) return { status: 'unknown', reason: 'no_target', current, target };
  if (majorOf(current) !== majorOf(target)) {
    return { status: 'unknown', reason: 'major_differs', current, target };
  }
  const c = compareRouterOsVersion(current, target);
  if (c === 0) return { status: 'up_to_date', reason: 'at_target', current, target };
  if (c > 0) return { status: 'up_to_date', reason: 'ahead_of_target', current, target };
  return { status: 'behind', reason: 'below_target', current, target };
}

/**
 * Which of the three version readings a device is judged on.
 *
 *  - `observed`   the newest identity observation (`device_identity_observations`),
 *                 a reading off the box with its instant;
 *  - `upgrade_job` a version an `os_upgrade` job read off the box itself:
 *                 after the reboot (`os_upgrade_jobs.observed_version`, at
 *                 `returned_at`), or - for a job that found the box already
 *                 at or above its target and did nothing (`outcome =
 *                 'already_current'`) - the version it read before deciding
 *                 (`from_version`, at the job's `finished_at`);
 *  - `inventory`  `devices.os_version`, which carries no instant: filled once
 *                 by the learn path (`learnDeviceFacts` never overwrites a
 *                 filled column), rewritten after an upgrade by deviceBinding
 *                 `recordUpgradedOsVersion`, or by an operator editing the
 *                 device.
 *
 * The newer of the two TIMED readings wins; the inventory is the fallback.
 * Neither timed source alone is enough: an upgrade done by hand on the box
 * shows only in an observation, and an upgrade done by ObliWAN may not have
 * been followed by a new observation yet.
 *
 * NOTHING SCHEDULES AN OBSERVATION. One exists only when somebody asked the
 * box: `observeDeviceIdentity()`, reached from this screen's "re-read
 * versions" (section 6b) and from `/identity/devices/:id/observe` and
 * `/identity/sweep`. That is why every view carries the age of its reading
 * (`versionAgeDays`, `versionStale`) and why the screen can start the
 * re-read itself.
 */
export function pickCurrentVersion(input: {
  observed: { version: string | null; at: string | null } | null;
  upgradeJob: { version: string | null; at: string | null } | null;
  inventory: string | null;
}): { version: string | null; source: 'observed' | 'upgrade_job' | 'inventory' | null; at: string | null } {
  const timed = [
    { source: 'observed' as const, r: input.observed },
    { source: 'upgrade_job' as const, r: input.upgradeJob },
  ]
    .filter((c) => c.r !== null && typeof c.r.version === 'string' && c.r.version.trim() !== '' && c.r.at !== null)
    .sort((a, b) => Date.parse(b.r!.at!) - Date.parse(a.r!.at!));
  if (timed.length > 0) return { version: timed[0].r!.version, source: timed[0].source, at: timed[0].r!.at };
  const inv = typeof input.inventory === 'string' && input.inventory.trim() !== '' ? input.inventory : null;
  return { version: inv, source: inv === null ? null : 'inventory', at: null };
}

/**
 * The age past which a version reading is called old. A RouterOS box can be
 * upgraded by hand (WinBox, its own scheduler) on any day, and nothing
 * re-reads a version on a timer (see above). A week is long enough not to
 * flag a fleet that was read on Monday, short enough that "behind" is not
 * stated on last quarter's evidence without saying so.
 */
export const VERSION_READING_MAX_AGE_DAYS = 7;

/**
 * The age of a reading, and whether the screen must call it old.
 *
 * An UNDATED version (the inventory column, which carries no instant) is old
 * by definition: its age is unknown, and an unknown age is never presented as
 * a fresh one. No version at all is not "stale" - it is missing, and the
 * status already says `unknown`.
 *
 * The age does not change the STATUS. A stale `behind` stays `behind`: the
 * launch is safe on it because the job re-reads the version live before
 * anything is written, and a box found already current is recorded
 * (`already_current`, no reboot) and that reading then feeds the listing as
 * an `upgrade_job` reading. What the age changes is what the screen says
 * ("as of a reading N days old") and which routers the re-read starts with.
 */
export function readingAge(
  picked: { version: string | null; at: string | null },
  now: number = Date.now(),
): { ageDays: number | null; stale: boolean } {
  if (picked.version === null) return { ageDays: null, stale: false };
  if (picked.at === null) return { ageDays: null, stale: true };
  const ms = now - Date.parse(picked.at);
  if (!Number.isFinite(ms)) return { ageDays: null, stale: true };
  const ageDays = Math.max(0, Math.floor(ms / 86_400_000));
  return { ageDays, stale: ms > VERSION_READING_MAX_AGE_DAYS * 86_400_000 };
}

// ============================================================================
// 3. The canary waves (pure)
// ============================================================================

/**
 * The waves a multi-device upgrade runs in.
 *
 * Without `sizes`, the product's own ladder (`planWaves`: 1 -> 5% -> 25% ->
 * the rest), the same one `/rollouts` uses, so the two screens cannot disagree
 * about what a canary is. With `sizes`, each number is the size of one leading
 * wave and whatever remains goes into a final `rest` wave; a ladder that asks
 * for more devices than were selected is refused rather than trimmed, because
 * a trimmed ladder is not the one the operator read.
 *
 * The ladder is handed to the launcher, which must run THAT ladder or refuse:
 * today's (rollout.service `osUpgradeLauncher`) composes with `planWaves`
 * only and refuses any other one with `waves_mismatch`, nothing written. The
 * screen never sends `sizes`; the API keeps them for a launcher that can.
 *
 * One device is not a rollout: `[]`, and the launch queues a single job.
 */
export function planUpgradeWaves(
  n: number,
  sizes?: readonly number[] | null,
): { waves: PlannedWave[]; error: string | null } {
  if (!Number.isInteger(n) || n <= 1) return { waves: [], error: null };
  if (!sizes || sizes.length === 0) return { waves: planWaves(n), error: null };
  if (sizes.some((s) => !Number.isInteger(s) || s < 1)) {
    return { waves: [], error: 'Every wave size must be a whole number of at least 1.' };
  }
  const total = sizes.reduce((a, b) => a + b, 0);
  if (total > n) {
    return {
      waves: [],
      error: `The waves ask for ${total} device(s) but only ${n} are selected.`,
    };
  }
  const waves: PlannedWave[] = [];
  let covered = 0;
  sizes.forEach((size, i) => {
    covered += size;
    waves.push({ index: i, label: i === 0 ? 'canary' : `wave-${i + 1}`, size, cumulative: covered });
  });
  if (covered < n) {
    waves.push({ index: waves.length, label: 'rest', size: n - covered, cumulative: n });
  }
  return { waves, error: null };
}

// ============================================================================
// 4. The port - the two writes, reached by name
// ============================================================================

export interface OsUpgradeJobInput {
  tenantId: number;
  deviceId: number;
  /** A RouterOS 7 RELEASE version, validated by this file. */
  version: string;
  requestedBy: number | null;
  override: { reason: string; userId: number | null };
  confirmDegraded: { userId: number | null };
}

export interface OsUpgradeRolloutInput {
  tenantId: number;
  name: string;
  deviceIds: number[];
  version: string;
  /** The ladder the operator was shown in the confirmation dialog. */
  waves: PlannedWave[];
  requestedBy: number | null;
  override: { reason: string; userId: number | null };
  confirmDegraded: { userId: number | null };
}

export interface OsUpgradeLauncher {
  /** Queue ONE `os_upgrade` change job. Throws the queue's own refusals. */
  enqueueOne(input: OsUpgradeJobInput): Promise<{ jobId: number }>;
  /** Compose AND launch a canary-wave rollout of `os_upgrade` jobs that stops
   *  at the first failed wave. Throws the rollout service's own refusals. */
  launchRollout(input: OsUpgradeRolloutInput): Promise<{ rolloutId: number }>;
}

class BackendUnwiredError extends Error {
  constructor() {
    super(
      'The fleet OS upgrade is not wired into this build: no `os_upgrade` launcher is ' +
        'registered (setOsUpgradeLauncher). Nothing was queued.',
    );
    this.name = 'BackendUnwiredError';
  }
}

const UNWIRED: OsUpgradeLauncher = {
  async enqueueOne() {
    throw new BackendUnwiredError();
  },
  async launchRollout() {
    throw new BackendUnwiredError();
  },
};

// Wired by default: the firmware stream's launcher exists in this build, and a
// screen whose launch depends on a line somebody may forget in index.ts is a
// screen that ships unable to start anything.
let launcher: OsUpgradeLauncher = osUpgradeLauncher;
let launcherWired = true;

/** Replace the `os_upgrade` launcher, or unwire it with `null`. */
export function setOsUpgradeLauncher(next: OsUpgradeLauncher | null): void {
  launcher = next ?? UNWIRED;
  launcherWired = next !== null;
}

export function osUpgradeLauncherWired(): boolean {
  return launcherWired;
}

// ============================================================================
// 5. The fleet target, from the release watch
// ============================================================================

export interface FleetTargetView {
  /** The release every RouterOS 7 device is judged against; null = none. */
  version: string | null;
  /** `stable`, `long-term` or `pinned` (null when the stored decision is unreadable). */
  mode: RouterOsTargetMode | null;
  unresolvedReason: RouterOsTargetUnresolved | null;
  /** True when the channel reading behind `version` is older than the
   *  release watch's stale threshold. */
  stale: boolean;
  /** When the release watch last read the channel successfully (or, for a
   *  pin, when the pin was set). */
  observedAt: string | null;
}

async function readFleetTarget(): Promise<FleetTargetView> {
  const status = await getRouterOsFirmwareStatus();
  const t = status.target;
  const observedAt =
    t.mode === 'stable'
      ? status.stable.lastSuccessAt
      : t.mode === 'long-term'
        ? status.longTerm.lastSuccessAt
        : t.mode === 'pinned'
          ? t.updatedAt
          : null;
  return {
    version: t.resolved,
    mode: t.mode,
    unresolvedReason: t.unresolvedReason,
    stale: t.stale,
    observedAt,
  };
}

// ============================================================================
// 6. Reading the fleet
// ============================================================================

/** What `os_upgrade_jobs` (047) recorded for a job, phase by phase. */
export interface UpgradeProgress {
  targetVersion: string;
  fromVersion: string | null;
  architecture: string | null;
  fetchedAt: string | null;
  rebootedAt: string | null;
  returnedAt: string | null;
  observedVersion: string | null;
  outcome: string | null;
  outcomeDetail: string | null;
}

/**
 * A change job as this screen shows it. For a caller without PLAN_CREATE the
 * queue's own identifiers and texts are withheld (`redactJob`): `id`,
 * `rolloutId`, `createdAt`, `errorMessage` and `upgrade.outcomeDetail` are
 * null, and the kind of a job that is not an upgrade reads `other`.
 */
export interface UpgradeJobRef {
  id: number | null;
  kind: string;
  status: string;
  rolloutId: number | null;
  createdAt: string | null;
  finishedAt: string | null;
  errorMessage: string | null;
  /** Present for an `os_upgrade` job whose `os_upgrade_jobs` row exists. */
  upgrade: UpgradeProgress | null;
}

export interface UpgradeDeviceView {
  /** God view only: the device's tenant (utils/globalView.ts). */
  tenantId?: number;
  tenantName?: string | null;
  id: number;
  name: string;
  role: string;
  /** The inventory status (`active`, `pending`...), not the upgrade status. */
  deviceStatus: string;
  isManaged: boolean;
  family: string;
  model: string | null;
  siteId: number | null;
  siteName: string | null;
  groupId: number | null;
  groupName: string | null;
  /** The root of the device's group tree: the customer, in this product. */
  clientName: string | null;
  currentVersion: string | null;
  versionSource: 'observed' | 'upgrade_job' | 'inventory' | null;
  versionObservedAt: string | null;
  /** Whole days since the reading; null when undated or absent. */
  versionAgeDays: number | null;
  /** Older than VERSION_READING_MAX_AGE_DAYS, or undated (`readingAge`). */
  versionStale: boolean;
  /** As an `os_upgrade` job read it off the box (`os_upgrade_jobs`); null
   *  until a job has run - the job reads it again itself, every time. */
  architecture: string | null;
  major: number;
  targetVersion: string | null;
  status: UpgradeStatus;
  statusReason: UpgradeStatusReason;
  /** Any change job that holds the device right now, whatever its kind. */
  activeJob: UpgradeJobRef | null;
  /** The newest `os_upgrade` job of this device, finished or not. */
  lastUpgradeJob: UpgradeJobRef | null;
  /** The active rollout holding the device. A `draft` one holds it without
   *  running anything (it is not "in progress"). `id`/`name` are null for a
   *  caller without PLAN_CREATE, and the kind of a non-upgrade rollout reads
   *  `other`. */
  heldByRollout: { id: number | null; name: string | null; status: string; kind: string } | null;
  /** Why this device cannot be selected right now; `null` = selectable. */
  blockedReason: LaunchRefusalCode | null;
}

export interface UpgradeCounts extends Record<UpgradeStatus, number> {
  total: number;
  /** `behind` AND selectable now: what "select all behind" can pick. */
  behindSelectable: number;
  /** What "re-read versions" starts with (`needsReading`). */
  needsReading: number;
}

export interface UpgradeListing {
  devices: UpgradeDeviceView[];
  counts: UpgradeCounts;
  target: FleetTargetView;
  launch: { available: boolean; reason: string | null };
  /** `reason` is null for a caller without PLAN_CREATE (`/changes/kill-switch`
   *  is PLAN_CREATE). */
  killSwitch: { blocked: boolean; reason: string | null };
  requires: typeof UPGRADE_REQUIRES;
  /** False when the queue details were withheld (no PLAN_CREATE): the screen
   *  then draws no job or rollout link the caller could not open. */
  queueDetail: boolean;
  /** The latest "re-read versions" pass of this tenant since the server
   *  started, or null. */
  refresh: VersionRefreshState | null;
  versionMaxAgeDays: number;
}

interface DeviceRow {
  id: number | string;
  name: string;
  role: string | null;
  status: string;
  is_managed: boolean;
  family: string;
  model: string | null;
  os_version: string | null;
  site_id: number | null;
  site_name: string | null;
  group_id: number | null;
}

type Row = Record<string, unknown>;

function iso(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  const d = v instanceof Date ? v : new Date(String(v));
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function strOrNull(v: unknown): string | null {
  return typeof v === 'string' ? v : null;
}

function jobRef(r: Row): UpgradeJobRef {
  return {
    id: Number(r.id),
    kind: String(r.kind),
    status: String(r.status),
    rolloutId: r.rollout_id === null || r.rollout_id === undefined ? null : Number(r.rollout_id),
    createdAt: iso(r.created_at),
    finishedAt: iso(r.finished_at),
    errorMessage: strOrNull(r.error_message),
    upgrade:
      typeof r.u_target_version === 'string'
        ? {
            targetVersion: r.u_target_version,
            fromVersion: strOrNull(r.u_from_version),
            architecture: strOrNull(r.u_architecture),
            fetchedAt: iso(r.u_fetched_at),
            rebootedAt: iso(r.u_rebooted_at),
            returnedAt: iso(r.u_returned_at),
            observedVersion: strOrNull(r.u_observed_version),
            outcome: strOrNull(r.u_outcome),
            outcomeDetail: strOrNull(r.u_outcome_detail),
          }
        : null,
  };
}

/** What a caller without PLAN_CREATE may read of a job: its status, the
 *  upgrade's phases (facts about the box), and nothing that identifies or
 *  describes the queue's work. */
function redactJob(j: UpgradeJobRef): UpgradeJobRef {
  const upgrade = j.kind === OS_UPGRADE_JOB_KIND;
  return {
    id: null,
    kind: upgrade ? j.kind : 'other',
    status: j.status,
    rolloutId: null,
    createdAt: null,
    finishedAt: upgrade ? j.finishedAt : null,
    errorMessage: null,
    upgrade: j.upgrade ? { ...j.upgrade, outcomeDetail: null } : null,
  };
}

function redactQueue(v: UpgradeDeviceView): UpgradeDeviceView {
  return {
    ...v,
    activeJob: v.activeJob ? redactJob(v.activeJob) : null,
    lastUpgradeJob: v.lastUpgradeJob ? redactJob(v.lastUpgradeJob) : null,
    heldByRollout: v.heldByRollout
      ? {
          id: null,
          name: null,
          status: v.heldByRollout.status,
          kind: v.heldByRollout.kind === OS_UPGRADE_ROLLOUT_KIND ? v.heldByRollout.kind : 'other',
        }
      : null,
  };
}

/**
 * The version an `os_upgrade` job read off the box, with its instant (see
 * `pickCurrentVersion`). The row comes from the `readingJobs` query, which
 * only returns jobs that hold one of the two readings.
 */
function jobReading(r: Row): { version: string | null; at: string | null } {
  if (typeof r.u_observed_version === 'string' && r.u_returned_at !== null && r.u_returned_at !== undefined) {
    return { version: r.u_observed_version, at: iso(r.u_returned_at) };
  }
  return { version: strOrNull(r.u_from_version), at: iso(r.finished_at) ?? iso(r.u_updated_at) };
}

/** The root ancestor of each group, by name. Groups are a tree per tenant; a
 *  depth cap keeps a corrupted parent loop from hanging the request. */
function rootNames(
  groups: Array<{ id: number | string; parent_id: number | string | null; name: string }>,
): Map<number, string> {
  const byId = new Map(groups.map((g) => [Number(g.id), g]));
  const out = new Map<number, string>();
  for (const g of groups) {
    let cur = g;
    for (let depth = 0; depth < 64 && cur.parent_id !== null; depth++) {
      const parent = byId.get(Number(cur.parent_id));
      if (!parent) break;
      cur = parent;
    }
    out.set(Number(g.id), cur.name);
  }
  return out;
}

/** `change_jobs` with its `os_upgrade_jobs` row, tenant on both sides. */
function jobsQuery(q: Knex, tenantId: number, ids: number[]): Knex.QueryBuilder {
  return q('change_jobs as j')
    .leftJoin('os_upgrade_jobs as u', function joinUpgrade() {
      this.on('u.job_id', '=', 'j.id').andOn('u.tenant_id', '=', 'j.tenant_id');
    })
    .where('j.tenant_id', tenantId)
    .whereIn('j.device_id', ids)
    .select(
      'j.id', 'j.device_id', 'j.kind', 'j.status', 'j.rollout_id', 'j.created_at', 'j.finished_at',
      'j.error_message',
      'u.target_version as u_target_version',
      'u.from_version as u_from_version',
      'u.architecture as u_architecture',
      'u.fetched_at as u_fetched_at',
      'u.rebooted_at as u_rebooted_at',
      'u.returned_at as u_returned_at',
      'u.observed_version as u_observed_version',
      'u.outcome as u_outcome',
      'u.outcome_detail as u_outcome_detail',
      'u.updated_at as u_updated_at',
    );
}

/**
 * The NEWEST `os_upgrade` job of each device among those `narrow` keeps - one
 * row per device (DISTINCT ON), so a poll reads at most one row per router
 * per question however many update campaigns the tenant has run. Job ids grow
 * with time and one device runs one job at a time (the per-device lock), so
 * the highest id is the latest job.
 */
function newestUpgradeJobs(
  q: Knex,
  tenantId: number,
  ids: number[],
  narrow?: (qb: Knex.QueryBuilder) => void,
): Promise<Row[]> {
  const qb = jobsQuery(q, tenantId, ids).where('j.kind', OS_UPGRADE_JOB_KIND).distinctOn('j.device_id');
  if (narrow) narrow(qb);
  return qb.orderBy([{ column: 'j.device_id' }, { column: 'j.id', order: 'desc' }]) as Promise<Row[]>;
}

/**
 * Every RouterOS device of the tenant, with its status.
 *
 * `deviceIds` narrows the read (the launch validation uses it); the tenant
 * predicate is on EVERY query, including the ones keyed by device id, because
 * `change_jobs`, `os_upgrade_jobs`, `rollout_targets` and
 * `device_identity_observations` carry their own `tenant_id` and a read by
 * device id alone is a cross-tenant read.
 *
 * `queueDetail` (default true, for the server's own callers) is false for an
 * HTTP caller without PLAN_CREATE: the views then go through `redactQueue`.
 */
export async function listUpgradeDevices(
  tenantId: number,
  opts: { deviceIds?: readonly number[]; queueDetail?: boolean; now?: number } = {},
  q: Knex = db,
): Promise<UpgradeListing> {
  const queueDetail = opts.queueDetail !== false;
  const now = opts.now ?? Date.now();
  let deviceQuery = q('devices as d')
    .leftJoin('sites as s', function joinSite() {
      this.on('s.id', '=', 'd.site_id').andOn('s.tenant_id', '=', 'd.tenant_id');
    })
    .where('d.tenant_id', tenantId)
    .where('d.brand', 'mikrotik');
  if (opts.deviceIds) deviceQuery = deviceQuery.whereIn('d.id', opts.deviceIds as number[]);
  const rows = (await deviceQuery
    .orderBy('d.name', 'asc')
    .select(
      'd.id',
      'd.name',
      'd.role',
      'd.status',
      'd.is_managed',
      'd.family',
      'd.model',
      'd.os_version',
      'd.site_id',
      's.name as site_name',
      'd.group_id',
    )) as DeviceRow[];

  const ids = rows.map((r) => Number(r.id));
  const none = Promise.resolve([] as Row[]);

  const [groups, observations, activeJobs, lastJobs, readingJobs, archJobs, holds, killSwitch, readiness, target] =
    await Promise.all([
      q('device_groups').where('tenant_id', tenantId).select('id', 'parent_id', 'name') as Promise<
        Array<{ id: number; parent_id: number | null; name: string }>
      >,
      // The newest observation WITH a version - and only from the box on file:
      // an observation whose serial contradicts `devices.serial` came from
      // another box (a tunnel address reassigned by the PPP pool; or a
      // replaced unit the identity watch has flagged), and its version is not
      // this device's. A serial missing on either side cannot contradict.
      ids.length === 0
        ? none
        : (q('device_identity_observations as o')
            .join('devices as dv', function joinDevice() {
              this.on('dv.id', '=', 'o.device_id').andOn('dv.tenant_id', '=', 'o.tenant_id');
            })
            .distinctOn('o.device_id')
            .where('o.tenant_id', tenantId)
            .whereIn('o.device_id', ids)
            .whereNotNull('o.os_version')
            .where(function sameBox() {
              this.whereNull('o.serial').orWhereNull('dv.serial').orWhere('o.serial', '=', q.ref('dv.serial'));
            })
            .orderBy([{ column: 'o.device_id' }, { column: 'o.last_seen_at', order: 'desc' }])
            .select('o.device_id', 'o.os_version', 'o.last_seen_at') as Promise<Row[]>),
      ids.length === 0
        ? none
        : (jobsQuery(q, tenantId, ids)
            .whereIn('j.status', [...ACTIVE_CHANGE_JOB_STATUSES])
            .orderBy('j.id', 'desc') as Promise<Row[]>),
      // The "last attempt": the newest os_upgrade job, whatever its outcome.
      ids.length === 0 ? none : newestUpgradeJobs(q, tenantId, ids),
      // The newest os_upgrade job that READ the version off the box: after the
      // reboot (whatever the job's final status - a box that came back on its
      // old release was still read), or a job that found nothing to do.
      ids.length === 0
        ? none
        : newestUpgradeJobs(q, tenantId, ids, (qb) => {
            qb.where(function readTheBox() {
              this.where(function afterReboot() {
                this.whereNotNull('u.observed_version').whereNotNull('u.returned_at');
              }).orWhere(function foundCurrent() {
                this.where('u.outcome', 'already_current')
                  .whereNotNull('u.from_version')
                  .where('j.status', 'succeeded');
              });
            });
          }),
      // The newest architecture a job read off the box.
      ids.length === 0
        ? none
        : newestUpgradeJobs(q, tenantId, ids, (qb) => {
            qb.whereNotNull('u.architecture');
          }),
      ids.length === 0
        ? none
        : (q('rollout_targets as t')
            .join('rollouts as r', function joinRollout() {
              this.on('r.id', '=', 't.rollout_id').andOn('r.tenant_id', '=', 't.tenant_id');
            })
            .where('t.tenant_id', tenantId)
            .whereIn('t.device_id', ids)
            .whereIn('t.status', [...ACTIVE_ROLLOUT_TARGET_STATUSES])
            .select(
              't.device_id',
              'r.id as rollout_id',
              'r.name as rollout_name',
              'r.status as rollout_status',
              'r.kind as rollout_kind',
            ) as Promise<Row[]>),
      readKillSwitch(tenantId, q),
      changeExecutorReadiness(),
      readFleetTarget(),
    ]);

  const clientOf = rootNames(groups);
  const groupName = new Map(groups.map((g) => [Number(g.id), g.name]));
  const observedOf = new Map(observations.map((o) => [Number(o.device_id), o]));
  const activeOf = new Map<number, Row>();
  for (const j of activeJobs) {
    const id = Number(j.device_id);
    if (!activeOf.has(id)) activeOf.set(id, j);
  }
  const lastOf = new Map(lastJobs.map((j) => [Number(j.device_id), j]));
  const readingOf = new Map(readingJobs.map((j) => [Number(j.device_id), j]));
  const archOf = new Map(
    archJobs.filter((j) => typeof j.u_architecture === 'string').map((j) => [Number(j.device_id), String(j.u_architecture)]),
  );
  const holdOf = new Map(holds.map((h) => [Number(h.device_id), h]));

  const devices: UpgradeDeviceView[] = rows.map((r) => {
    const id = Number(r.id);
    const obs = observedOf.get(id);
    const read = readingOf.get(id);
    const picked = pickCurrentVersion({
      observed: obs ? { version: strOrNull(obs.os_version), at: iso(obs.last_seen_at) } : null,
      upgradeJob: read ? jobReading(read) : null,
      inventory: r.os_version,
    });
    const age = readingAge(picked, now);
    const bare = bareRouterOsVersion(picked.version);
    const major = bare ? majorOf(bare) : r.family === 'mikrotik_routeros6' ? 6 : 7;
    const active = activeOf.get(id) ?? null;
    const hold = holdOf.get(id) ?? null;
    const verdict = computeUpgradeStatus({
      currentVersion: picked.version,
      targetVersion: target.version,
      activeUpgradeJob: active !== null && active.kind === OS_UPGRADE_JOB_KIND,
      // A DRAFT holds its devices (rollout_targets_one_active_uq) but runs
      // nothing: calling it "in progress" would show a box waiting for a wave
      // that will never come. It stays blocked (`in_rollout`) by version.
      inUpgradeRollout:
        hold !== null && hold.rollout_kind === OS_UPGRADE_ROLLOUT_KIND && hold.rollout_status !== 'draft',
    });
    const groupId = r.group_id === null ? null : Number(r.group_id);
    const last = lastOf.get(id) ?? null;
    const view: UpgradeDeviceView = {
      id,
      name: r.name,
      role: r.role ?? 'cpe',
      deviceStatus: r.status,
      isManaged: r.is_managed === true,
      family: r.family,
      model: r.model,
      siteId: r.site_id === null ? null : Number(r.site_id),
      siteName: r.site_name,
      groupId,
      groupName: groupId === null ? null : groupName.get(groupId) ?? null,
      clientName: groupId === null ? null : clientOf.get(groupId) ?? null,
      currentVersion: picked.version,
      versionSource: picked.source,
      versionObservedAt: picked.at,
      versionAgeDays: age.ageDays,
      versionStale: age.stale,
      architecture: archOf.get(id) ?? null,
      major,
      targetVersion: target.version,
      status: verdict.status,
      statusReason: verdict.reason,
      activeJob: active ? jobRef(active) : null,
      lastUpgradeJob: last ? jobRef(last) : null,
      heldByRollout: hold
        ? {
            id: Number(hold.rollout_id),
            name: String(hold.rollout_name),
            status: String(hold.rollout_status),
            kind: String(hold.rollout_kind),
          }
        : null,
      blockedReason: null,
    };
    view.blockedReason = deviceRefusal(view, verdict.current, verdict.target)?.code ?? null;
    return view;
  });

  const counts: UpgradeCounts = {
    up_to_date: 0,
    behind: 0,
    unknown: 0,
    in_progress: 0,
    total: devices.length,
    behindSelectable: 0,
    needsReading: 0,
  };
  for (const d of devices) {
    counts[d.status]++;
    if (d.status === 'behind' && d.blockedReason === null) counts.behindSelectable++;
    if (needsReading(d)) counts.needsReading++;
  }

  const launchReasons: string[] = [];
  if (!launcherWired) launchReasons.push(new BackendUnwiredError().message);
  if (!readiness.ready) launchReasons.push(...readiness.warnings);

  return {
    devices: queueDetail ? devices : devices.map(redactQueue),
    counts,
    target,
    launch: {
      available: launchReasons.length === 0,
      reason: launchReasons.length > 0 ? launchReasons.join(' ') : null,
    },
    killSwitch: { blocked: killSwitch.blocked, reason: queueDetail ? killSwitch.reason ?? null : null },
    requires: UPGRADE_REQUIRES,
    queueDetail,
    refresh: versionRefreshState(tenantId),
    versionMaxAgeDays: VERSION_READING_MAX_AGE_DAYS,
  };
}

// ============================================================================
// 6b. Re-reading versions off the routers
// ============================================================================
//
// The listing is only as true as its readings, and nothing re-reads a version
// on a timer (section 2). This is the screen's way to start that itself: the
// identity watch's `observeDeviceIdentity()` - the same read-only call as
// `/identity/sweep`, which records a timestamped observation (a new row, or
// `last_seen_at` bumped on an identical one) - for each router whose reading
// is missing or old.
//
// SEQUENTIAL, for the reason `sweepTenantIdentities` gives: the RouterOS
// channel is one pooled socket per device with a global dial budget.
// IN THE BACKGROUND, because a few hundred sequential dials outlive any HTTP
// request; the listing carries the progress and the page polls it.
// ONE PASS PER TENANT at a time. The state lives in this process and dies with
// it: a restart forgets a pass, and the observations it already recorded stay.

/** Whether the re-read starts with this router: no version, or an old or
 *  undated one. Never a router being upgraded right now (its socket belongs to
 *  the job, and it may be rebooting), never a disabled one (no transport may
 *  be opened to it). */
export function needsReading(d: UpgradeDeviceView): boolean {
  if (d.status === 'in_progress' || d.deviceStatus === 'disabled') return false;
  return d.currentVersion === null || d.versionStale;
}

export interface VersionRefreshState {
  running: boolean;
  total: number;
  done: number;
  ok: number;
  failed: number;
  /** The routers that did not answer, so the screen can name them. */
  failedDeviceIds: number[];
  startedAt: string;
  finishedAt: string | null;
}

/** Reads one router's identity (and so its version). Replaceable for the
 *  harness, which must not dial anything. */
export type VersionObserver = (tenantId: number, deviceId: number) => Promise<{ ok: boolean }>;

const OBSERVE_VERSION: VersionObserver = async (tenantId, deviceId) => {
  const outcome = await observeDeviceIdentity(tenantId, deviceId, { source: 'sweep' });
  return { ok: outcome.ok };
};
let versionObserver: VersionObserver = OBSERVE_VERSION;

export function setVersionObserver(next: VersionObserver | null): void {
  versionObserver = next ?? OBSERVE_VERSION;
}

const refreshes = new Map<number, VersionRefreshState>();

export function versionRefreshState(tenantId: number): VersionRefreshState | null {
  const s = refreshes.get(tenantId);
  return s ? { ...s, failedDeviceIds: [...s.failedDeviceIds] } : null;
}

export class VersionRefreshRefused extends Error {
  constructor(
    readonly status: number,
    readonly code: 'refresh_running' | 'not_found' | 'nothing_to_read',
    message: string,
    readonly deviceIds: number[] = [],
  ) {
    super(message);
    this.name = 'VersionRefreshRefused';
  }
}

/**
 * Start a re-read. Without `deviceIds`: every router of the tenant that
 * `needsReading`, oldest reading first (an undated one first of all), at most
 * MAX_SWEEP_DEVICES - the identity sweep's own ceiling. With `deviceIds`:
 * exactly those, all or nothing (an id outside the tenant's RouterOS fleet
 * refuses the call), minus the ones being upgraded or disabled.
 *
 * Returns the initial state and `finished`, a promise that settles when the
 * pass ends and never rejects (the handler drops it; the harness awaits it).
 */
export async function startVersionRefresh(
  tenantId: number,
  deviceIds?: readonly number[],
  /**
   * Team scope (migration 087) of a re-read started WITHOUT `deviceIds`: the
   * sweep only considers these routers (the caller's 'rw' ones).
   * null/undefined = the whole tenant.
   */
  scope: { deviceIdsIn?: number[] | null } = {},
): Promise<{ state: VersionRefreshState; finished: Promise<void> }> {
  if (refreshes.get(tenantId)?.running) {
    throw new VersionRefreshRefused(409, 'refresh_running', 'A version re-read is already running for this fleet.');
  }
  // Claimed BEFORE the first await, so two clicks cannot start two passes.
  const state: VersionRefreshState = {
    running: true,
    total: 0,
    done: 0,
    ok: 0,
    failed: 0,
    failedDeviceIds: [],
    startedAt: new Date().toISOString(),
    finishedAt: null,
  };
  const previous = refreshes.get(tenantId);
  refreshes.set(tenantId, state);

  let ids: number[];
  try {
    const wanted = deviceIds ? [...new Set(deviceIds)] : null;
    const listing = await listUpgradeDevices(
      tenantId,
      wanted ? { deviceIds: wanted } : scope.deviceIdsIn ? { deviceIds: scope.deviceIdsIn } : {},
    );
    if (wanted) {
      const listed = new Set(listing.devices.map((d) => d.id));
      const missing = wanted.filter((id) => !listed.has(id));
      if (missing.length > 0) {
        throw new VersionRefreshRefused(
          404,
          'not_found',
          `${missing.length} device(s) are not RouterOS devices of this fleet. Nothing was read.`,
          missing,
        );
      }
      ids = listing.devices
        .filter((d) => d.status !== 'in_progress' && d.deviceStatus !== 'disabled')
        .map((d) => d.id);
    } else {
      ids = listing.devices
        .filter(needsReading)
        .sort((a, b) => (a.versionObservedAt === null ? 0 : Date.parse(a.versionObservedAt)) -
          (b.versionObservedAt === null ? 0 : Date.parse(b.versionObservedAt)))
        .slice(0, MAX_SWEEP_DEVICES)
        .map((d) => d.id);
    }
    if (ids.length === 0) {
      throw new VersionRefreshRefused(409, 'nothing_to_read', 'No router needs its version re-read.');
    }
  } catch (err) {
    if (previous) refreshes.set(tenantId, previous);
    else refreshes.delete(tenantId);
    throw err;
  }

  state.total = ids.length;
  const finished = (async () => {
    for (const deviceId of ids) {
      let ok = false;
      try {
        ok = (await versionObserver(tenantId, deviceId)).ok;
      } catch (err) {
        logger.warn({ err, tenantId, deviceId }, 'os-upgrade: version re-read failed');
      }
      if (ok) state.ok++;
      else {
        state.failed++;
        state.failedDeviceIds.push(deviceId);
      }
      state.done++;
    }
  })()
    .catch((err) => {
      logger.error({ err, tenantId }, 'os-upgrade: version re-read pass stopped');
    })
    .finally(() => {
      state.running = false;
      state.finishedAt = new Date().toISOString();
    });
  return { state: { ...state, failedDeviceIds: [] }, finished };
}

// ============================================================================
// 7. Launch validation - all or nothing, with the list of what is wrong
// ============================================================================

export const LAUNCH_REFUSAL_CODES = [
  'not_found', // not in this tenant (or does not exist - indistinguishable on purpose)
  'not_routeros', // not a MikroTik: this screen upgrades RouterOS only
  'not_active', // inventory status is not `active` (identity not confirmed)
  'not_managed', // `is_managed = false`: readable, not writable
  'device_busy', // a change job already holds it
  'in_rollout', // an active rollout already holds it
  'version_unknown', // no readable current version: an upgrade cannot be proven to be one
  'no_target', // no version requested and no fleet target resolved
  'major_differs', // RouterOS 6 (or a target on another line): a migration, not an update
  'already_current', // at or above the requested version: nothing to do, no downgrade
  'concentrator', // the firmware module refuses a concentrator outright (047, header 3)
] as const;
export type LaunchRefusalCode = (typeof LAUNCH_REFUSAL_CODES)[number];

export interface DeviceRefusal {
  deviceId: number;
  deviceName: string | null;
  code: LaunchRefusalCode;
}

function deviceRefusal(
  d: UpgradeDeviceView,
  current: string | null,
  target: string | null,
): DeviceRefusal | null {
  const refuse = (code: LaunchRefusalCode): DeviceRefusal => ({
    deviceId: d.id,
    deviceName: d.name,
    code,
  });
  if (d.deviceStatus !== 'active') return refuse('not_active');
  if (!d.isManaged) return refuse('not_managed');
  // A concentrator terminates the tunnel of every CPE behind it (8.5): its
  // reboot is a fleet outage, and the os_upgrade service refuses it.
  if (d.role === 'concentrator') return refuse('concentrator');
  if (d.activeJob) return refuse('device_busy');
  if (d.heldByRollout) return refuse('in_rollout');
  if (!current) return refuse('version_unknown');
  if (!target) return refuse('no_target');
  // The recorded FAMILY counts too: the os_upgrade service refuses anything
  // not filed as `mikrotik_routeros7` (`cross_major`), whatever version the
  // box reports, so a box read as 7.x but filed as RouterOS 6 is refused here
  // rather than after the confirmation dialog.
  if (majorOf(target) !== majorOf(current) || d.family !== 'mikrotik_routeros7') {
    return refuse('major_differs');
  }
  if (compareRouterOsVersion(current, target) >= 0) return refuse('already_current');
  return null;
}

export interface LaunchRequest {
  deviceIds: number[];
  version?: string;
  waves?: number[];
  name?: string;
  overrideReason?: string;
  confirmDegraded?: boolean;
}

export interface LaunchDecision {
  ok: boolean;
  mode: 'job' | 'rollout';
  /** The one version every selected device would be upgraded to. */
  version: string | null;
  waves: PlannedWave[];
  refusals: DeviceRefusal[];
  /** Refusals of the request as a whole (not of one device). */
  problems: Array<{ code: string; message: string }>;
  deviceIds: number[];
  requires: typeof UPGRADE_REQUIRES;
}

/**
 * Everything the launch decides before it hands over to the launcher.
 *
 * ALL OR NOTHING: one refused device refuses the launch and the answer lists
 * every refused device with its reason. Silently dropping the refused ones
 * would launch a rollout whose operator believes it covers the selection.
 *
 * `checkSignatures` is false for the preview (which is how the dialog learns
 * what it must ask for) and true for the launch.
 *
 * What it does NOT decide, and leaves to the queue: the kill switch (re-read
 * at enqueue and again before the write) and the per-device safety decisions
 * of apply.service. Those come back from the launch as refusals with their
 * own codes.
 */
export async function decideLaunch(
  tenantId: number,
  input: LaunchRequest,
  opts: { checkSignatures: boolean } = { checkSignatures: true },
  q: Knex = db,
): Promise<LaunchDecision> {
  const deviceIds = [...new Set(input.deviceIds)];
  const problems: LaunchDecision['problems'] = [];
  const refusals: DeviceRefusal[] = [];
  const mode: LaunchDecision['mode'] = deviceIds.length > 1 ? 'rollout' : 'job';

  // An explicit version must be something the job can install: a RouterOS 7
  // RELEASE (os_upgrade_jobs_target_version_chk, shared `packageUrl`).
  let requested: string | null = null;
  if (input.version !== undefined) {
    const v = input.version.trim();
    if (!isRouterOsReleaseVersion(v)) {
      problems.push({
        code: 'version_invalid',
        message: `'${input.version}' is not a RouterOS release version (expected e.g. 7.24.5; never a release candidate).`,
      });
    } else if (majorOf(v) !== 7) {
      problems.push({
        code: 'version_invalid',
        message: `${v} is not a RouterOS 7 release. Only RouterOS 7 is upgraded from this screen.`,
      });
    } else {
      requested = v;
    }
  }

  // Ids this tenant does not own, and owned devices that are not RouterOS.
  const owned = (await q('devices')
    .where('tenant_id', tenantId)
    .whereIn('id', deviceIds)
    .select('id', 'name', 'brand')) as Array<{ id: number | string; name: string; brand: string }>;
  const ownedById = new Map(owned.map((o) => [Number(o.id), o]));
  for (const id of deviceIds) {
    const o = ownedById.get(id);
    if (!o) refusals.push({ deviceId: id, deviceName: null, code: 'not_found' });
    else if (o.brand !== 'mikrotik') {
      refusals.push({ deviceId: id, deviceName: o.name, code: 'not_routeros' });
    }
  }

  const routerOsIds = deviceIds.filter((id) => ownedById.get(id)?.brand === 'mikrotik');
  const listing =
    routerOsIds.length > 0 ? await listUpgradeDevices(tenantId, { deviceIds: routerOsIds }, q) : null;
  const fleetTarget = listing?.target.version ?? null;
  const version = input.version !== undefined ? requested : fleetTarget;

  for (const d of listing?.devices ?? []) {
    const refusal = deviceRefusal(d, bareRouterOsVersion(d.currentVersion), version);
    // An invalid explicit version is ONE problem of the request, already
    // stated above; repeating it as `no_target` on every device would bury it.
    if (refusal && !(refusal.code === 'no_target' && input.version !== undefined)) refusals.push(refusal);
  }

  const planned = planUpgradeWaves(deviceIds.length, input.waves ?? null);
  if (planned.error) problems.push({ code: 'waves_invalid', message: planned.error });

  if (opts.checkSignatures) {
    if (UPGRADE_REQUIRES.overrideReason && !input.overrideReason) {
      problems.push({
        code: 'override_required',
        message:
          'An OS upgrade carries no plan, so the Management-Path Guard cannot prove the site stays ' +
          'reachable (INDETERMINATE). A written reason, signed with CHANGE_APPROVE, is required.',
      });
    }
    if (UPGRADE_REQUIRES.degradedConfirmation && input.confirmDegraded !== true) {
      problems.push({
        code: 'degraded_confirmation_required',
        message:
          'An OS upgrade cannot be rolled back automatically: a router that does not boot back ' +
          'needs a site visit. This must be confirmed explicitly.',
      });
    }
  }

  return {
    ok: refusals.length === 0 && problems.length === 0 && version !== null,
    mode,
    version,
    waves: planned.waves,
    refusals,
    problems,
    deviceIds,
    requires: UPGRADE_REQUIRES,
  };
}

export interface WaveMembers {
  index: number;
  label: string;
  deviceIds: number[];
}

/**
 * WHICH router goes in which wave - so the dialog can name the test router and
 * list every router the signature covers, instead of a count.
 *
 * The membership is not decided here: the rollout service orders the devices
 * when it composes (`orderForWaves`), and a second copy of that rule in this
 * file would be free to disagree with the one that runs. So the preview asks
 * the rollout service itself, through `previewRollout` - the composition
 * `composeRollout` would write, with nothing written.
 *
 * `null` when there is no rollout to show (one device, or a decision already
 * refused). A composition that refuses devices this file accepted, or that
 * runs another ladder than the one stated, becomes a PROBLEM of the decision:
 * the launch would be refused for it (`devices_refused` / `waves_mismatch`),
 * and the preview exists to say so before anybody signs.
 */
export async function previewWaveMembers(
  tenantId: number,
  decision: LaunchDecision,
  userId: number | null,
): Promise<{ members: WaveMembers[] | null; problems: LaunchDecision['problems'] }> {
  if (!decision.ok || decision.mode !== 'rollout' || decision.version === null) {
    return { members: null, problems: [] };
  }
  let composition: Awaited<ReturnType<typeof previewRollout>>;
  try {
    composition = await previewRollout({
      tenantId,
      name: `preview ${decision.version}`,
      deviceIds: decision.deviceIds,
      kind: 'os_upgrade',
      targetVersion: decision.version,
      createdBy: userId,
    });
  } catch (err) {
    if (err instanceof RolloutRefusedError) {
      return { members: null, problems: [{ code: 'composition_refused', message: err.message }] };
    }
    throw err;
  }
  if (composition.failures.length > 0) {
    return {
      members: null,
      problems: [
        {
          code: 'composition_refused',
          message: composition.failures.map((f) => `${f.deviceName ?? `#${f.deviceId}`}: ${f.message}`).join(' '),
        },
      ],
    };
  }
  const stated = decision.waves.map((w) => w.size);
  const composed = composition.waves.map((w) => w.size);
  if (JSON.stringify(stated) !== JSON.stringify(composed)) {
    return {
      members: null,
      problems: [
        {
          code: 'waves_mismatch',
          message:
            `The rollout runs the product's wave ladder (${composed.join(' / ')} device(s)), ` +
            `not ${stated.join(' / ')}.`,
        },
      ],
    };
  }
  return {
    members: composition.waves.map((w) => ({
      index: w.index,
      label: w.label,
      deviceIds: composition.targets.filter((t) => t.waveIndex === w.index).map((t) => t.deviceId),
    })),
    problems: [],
  };
}

// ============================================================================
// 8. HTTP
// ============================================================================

const launchSchema = z
  .object({
    deviceIds: z.array(z.number().int().positive()).min(1).max(MAX_DEVICES),
    /** Omitted = the fleet target. */
    version: z.string().trim().min(1).max(32).optional(),
    /** Sizes of the leading canary waves; the remainder forms a last wave. */
    waves: z.array(z.number().int().min(1).max(MAX_DEVICES)).min(1).max(8).optional(),
    name: z.string().trim().min(1).max(200).optional(),
    overrideReason: z.string().trim().min(8).max(2000).optional(),
    confirmDegraded: z.boolean().optional(),
  })
  .strict();

export function parseLaunchBody(value: unknown): z.infer<typeof launchSchema> {
  const result = launchSchema.safeParse(value ?? {});
  if (!result.success) {
    const flat = result.error.flatten();
    const fields = Object.entries(flat.fieldErrors)
      .map(([f, m]) => `${f}: ${((m as string[] | undefined) ?? []).join(', ')}`)
      .concat(flat.formErrors)
      .filter((s) => s.length > 0)
      .join('; ');
    throw new AppError(400, fields ? `Validation failed - ${fields}` : 'Validation failed');
  }
  return result.data;
}

/** Whether the caller holds `capability` in the request's tenant - the same
 *  resolution as `requireCapability` (an instance admin holds everything). */
async function callerHas(req: Request, capability: Capability): Promise<boolean> {
  if (req.session?.role === 'admin') return true;
  const tenantId = req.tenantId ?? req.session?.currentTenantId;
  if (!req.session?.userId || !tenantId) return false;
  const caps = await permissionService.getUserCapabilities(req.session.userId, false, tenantId);
  return caps.includes(capability);
}

/** The conditional half of the RBAC split - the body raises the bar. */
async function requireExtraCapability(req: Request, capability: Capability, why: string): Promise<void> {
  if (await callerHas(req, capability)) return;
  if (!req.session?.userId || !(req.tenantId ?? req.session?.currentTenantId)) {
    throw new AppError(403, 'No tenant granted for this account');
  }
  throw new AppError(403, `This action additionally requires '${capability}'. ${why}`);
}

const refreshSchema = z
  .object({
    /** Omitted = every router whose reading is missing or old (`needsReading`). */
    deviceIds: z.array(z.number().int().positive()).min(1).max(MAX_SWEEP_DEVICES).optional(),
  })
  .strict();

/** A refusal with a machine-readable code the screen branches on. The global
 *  error handler only carries `error`; the dialog needs to know WHICH refusal
 *  it was. */
function sendRefusal(
  res: Response,
  status: number,
  code: string,
  message: string,
  extra: Record<string, unknown> = {},
): void {
  res.status(status).json({ success: false, error: message, code, ...extra });
}

function handleLaunchError(err: unknown, res: Response, next: NextFunction): void {
  if (err instanceof BackendUnwiredError) {
    sendRefusal(res, 503, 'backend_unwired', err.message);
    return;
  }
  if (err instanceof KillSwitchEngagedError) {
    sendRefusal(res, 409, 'kill_switch', err.message);
    return;
  }
  if (err instanceof DeviceBusyError) {
    sendRefusal(res, 409, 'device_busy', err.message);
    return;
  }
  if (err instanceof RolloutRefusedError || err instanceof ChangeRefusedError) {
    let status = 409;
    if (err.kind === 'not_found' || err.kind === 'device_not_found') status = 404;
    else if (err.kind === 'guard_refused' || err.kind === 'degraded_unconfirmed') status = 422;
    else if (err.kind === 'executor_unavailable') status = 503;
    const detail = err instanceof RolloutRefusedError ? err.detail : null;
    sendRefusal(res, status, err.kind, err.message, detail ? { detail } : {});
    return;
  }
  next(err);
}

// ============================================================================
// God view (utils/globalView.ts)
// ============================================================================
//
// A platform admin positioned on the master tenant sees EVERY tenant's
// RouterOS fleet on this screen, and may select routers of several tenants.
//
//  - The listing is read tenant by tenant through the SAME per-tenant
//    `listUpgradeDevices()` (every query in it keeps its tenant predicate) and
//    merged: devices tagged with their tenant, counts summed.
//  - A preview / launch whose selection lives in ONE tenant runs exactly the
//    per-tenant path, IN that tenant (`enterObjectTenant`): its job or rollout
//    belongs to that tenant and is audited there.
//  - A selection spanning SEVERAL tenants fans out: one ordinary decision per
//    tenant, ALL decided before anything is launched (one refused router in
//    any tenant refuses the whole launch, as the per-tenant rule already says),
//    then one job or rollout per tenant, each in its own tenant, plus one
//    summary row in the master tenant's audit.

/** The god-view tenant groups of a selection, or null outside the god view.
 *  An id no tenant owns is left in the request's own tenant, whose decision
 *  refuses it as `not_found` like any unknown id. */
async function godViewSelection(req: Request, deviceIds: readonly number[]): Promise<Map<number, number[]> | null> {
  if (!hasGlobalView(req)) return null;
  const owners = await ownerTenantsOf('devices', deviceIds);
  const groups = new Map<number, number[]>();
  for (const id of [...new Set(deviceIds)]) {
    const t = owners.get(String(id)) ?? req.tenantId;
    groups.set(t, [...(groups.get(t) ?? []), id]);
  }
  return groups;
}

/** Every tenant's listing, merged (god view). */
async function godViewListing(req: Request, queueDetail: boolean): Promise<UpgradeListing & { godView: true }> {
  const tenantIds = await tenantIdsInScope(req.tenantId);
  const names = await tenantNames(tenantIds);
  const parts: Array<{ tenantId: number; listing: UpgradeListing }> = [];
  for (const tid of tenantIds) {
    parts.push({ tenantId: tid, listing: await runAsTenant(req, tid, () => listUpgradeDevices(tid, { queueDetail })) });
  }
  const first = parts[0]?.listing ?? (await listUpgradeDevices(req.tenantId, { queueDetail }));
  const counts: UpgradeCounts = {
    up_to_date: 0, behind: 0, unknown: 0, in_progress: 0, total: 0, behindSelectable: 0, needsReading: 0,
  };
  for (const p of parts) {
    for (const k of Object.keys(counts) as Array<keyof UpgradeCounts>) counts[k] += p.listing.counts[k];
  }
  const blocked = parts.find((p) => p.listing.killSwitch.blocked);
  const unavailable = parts.find((p) => !p.listing.launch.available);
  return {
    ...first,
    devices: parts.flatMap((p) =>
      p.listing.devices.map((d) => ({ ...d, tenantId: p.tenantId, tenantName: names.get(p.tenantId) ?? null }))),
    counts,
    launch: unavailable ? unavailable.listing.launch : first.launch,
    killSwitch: blocked ? blocked.listing.killSwitch : first.killSwitch,
    refresh: parts.find((p) => p.listing.refresh?.running)?.listing.refresh ?? versionRefreshState(req.tenantId),
    godView: true,
  };
}

/** The per-tenant decisions of a multi-tenant selection, merged for the
 *  dialog: `ok` only when every tenant's is; refusals and problems of every
 *  tenant; the per-tenant details under `byTenant`. */
async function decideAcrossTenants(
  req: Request,
  input: LaunchRequest,
  groups: Map<number, number[]>,
  opts: { checkSignatures: boolean; withMembers: boolean },
): Promise<{
  merged: LaunchDecision & { waveMembers: null; byTenant: Array<Record<string, unknown>> };
  decisions: Array<{ tenantId: number; decision: LaunchDecision }>;
}> {
  const names = await tenantNames(groups.keys());
  const decisions: Array<{ tenantId: number; decision: LaunchDecision }> = [];
  const byTenant: Array<Record<string, unknown>> = [];
  const extraProblems: LaunchDecision['problems'] = [];
  for (const [tenantId, ids] of [...groups.entries()].sort((a, b) => a[0] - b[0])) {
    const decision = await runAsTenant(req, tenantId, () =>
      decideLaunch(tenantId, { ...input, deviceIds: ids }, { checkSignatures: opts.checkSignatures }));
    let members: WaveMembers[] | null = null;
    if (opts.withMembers) {
      const preview = await runAsTenant(req, tenantId, () => previewWaveMembers(tenantId, decision, req.session.userId ?? null));
      members = preview.members;
      extraProblems.push(...preview.problems);
    }
    decisions.push({ tenantId, decision });
    byTenant.push({
      tenantId,
      tenantName: names.get(tenantId) ?? null,
      ok: decision.ok,
      mode: decision.mode,
      version: decision.version,
      deviceIds: decision.deviceIds,
      waves: decision.waves,
      waveMembers: members,
    });
  }
  const versions = [...new Set(decisions.map((d) => d.decision.version).filter((v): v is string => v !== null))];
  const problems = [...decisions.flatMap((d) => d.decision.problems), ...extraProblems];
  if (versions.length > 1) {
    problems.push({
      code: 'version_mismatch',
      message: `The selected tenants would be upgraded to different versions (${versions.join(', ')}). Pick the version explicitly.`,
    });
  }
  const refusals = decisions.flatMap((d) => d.decision.refusals);
  const dedupProblems = problems.filter((p, i) => problems.findIndex((q) => q.code === p.code && q.message === p.message) === i);
  return {
    decisions,
    merged: {
      ok: decisions.every((d) => d.decision.ok) && dedupProblems.length === 0 && versions.length === 1,
      mode: 'rollout',
      version: versions.length === 1 ? versions[0] : null,
      waves: [],
      refusals,
      problems: dedupProblems,
      deviceIds: decisions.flatMap((d) => d.decision.deviceIds),
      requires: UPGRADE_REQUIRES,
      waveMembers: null,
      byTenant,
    },
  };
}

export const osUpgradeController = {
  /** GET /os-upgrade/devices - the table, the counts, the target. */
  async listDevices(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const queueDetail = await callerHas(req, CAPABILITIES.PLAN_CREATE);
      if (hasGlobalView(req)) {
        res.json({ success: true, data: await godViewListing(req, queueDetail), godView: true });
        return;
      }
      // Team scope (087): the routers the caller's teams cover.
      const teamIds = await deviceListScope(req);
      const data = await listUpgradeDevices(req.tenantId, { queueDetail, ...(teamIds ? { deviceIds: teamIds } : {}) });
      res.json({ success: true, data });
    } catch (err) {
      next(err);
    }
  },

  /** POST /os-upgrade/preview - the launch's decision, nothing written, the
   *  signatures not yet asked for, and which router is in which wave. */
  async preview(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const input = parseLaunchBody(req.body);
      // God view: a selection in ONE tenant is previewed in that tenant; one
      // spanning several is previewed tenant by tenant (decideAcrossTenants).
      const groups = await godViewSelection(req, input.deviceIds);
      if (groups && groups.size > 1) {
        const { merged } = await decideAcrossTenants(req, input, groups, { checkSignatures: false, withMembers: true });
        res.json({ success: true, data: merged, godView: true });
        return;
      }
      if (groups && groups.size === 1) enterObjectTenant(req, [...groups.keys()][0]);
      const decision = await decideLaunch(req.tenantId, input, { checkSignatures: false });
      const { members, problems } = await previewWaveMembers(req.tenantId, decision, req.session.userId ?? null);
      const data = {
        ...decision,
        ok: decision.ok && problems.length === 0,
        problems: [...decision.problems, ...problems],
        waveMembers: members,
      };
      res.json({ success: true, data });
    } catch (err) {
      next(err);
    }
  },

  /** POST /os-upgrade/refresh-versions - start a re-read (section 6b). 202:
   *  the pass runs in the background; the listing carries its progress. */
  async refreshVersions(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const parsed = refreshSchema.safeParse(req.body ?? {});
      if (!parsed.success) throw new AppError(400, `Validation failed - deviceIds: 1 to ${MAX_SWEEP_DEVICES} device ids, or none`);
      // God view: a re-read of routers of ONE tenant runs in that tenant; of
      // several (or of "every router that needs it"), one pass per tenant.
      if (hasGlobalView(req)) {
        const groups = parsed.data.deviceIds
          ? await godViewSelection(req, parsed.data.deviceIds)
          : new Map((await db('tenants').orderBy('id').pluck('id')).map((t: number) => [Number(t), undefined as number[] | undefined]));
        if (groups && groups.size === 1 && parsed.data.deviceIds) {
          enterObjectTenant(req, [...groups.keys()][0]);
        } else if (groups) {
          const byTenant: Array<Record<string, unknown>> = [];
          for (const [tenantId, ids] of groups) {
            try {
              const { state } = await runAsTenant(req, tenantId, () => startVersionRefresh(tenantId, ids));
              byTenant.push({ tenantId, state });
            } catch (err) {
              if (!(err instanceof VersionRefreshRefused)) throw err;
              // Nothing to read in a tenant is not a failure of the god-view pass.
              if (err.code !== 'nothing_to_read') byTenant.push({ tenantId, refused: err.code, message: err.message });
            }
          }
          const started = byTenant.find((b) => b.state) as { state: VersionRefreshState } | undefined;
          if (!started) {
            sendRefusal(res, 409, 'nothing_to_read', 'No router of any tenant needs its version re-read.', { byTenant });
            return;
          }
          res.status(202).json({ success: true, godView: true, data: started.state, byTenant });
          return;
        }
      }
      // Named ids are judged by the route's team gate ('rw' on each); a
      // sweep of "whatever needs it" only reaches the caller's 'rw' routers.
      const sweepScope = parsed.data.deviceIds || (await canWriteEveryDevice(req))
        ? {}
        : { deviceIdsIn: (await deviceListScope(req, 'rw')) ?? [] };
      const { state, finished } = await startVersionRefresh(req.tenantId, parsed.data.deviceIds, sweepScope);
      void finished;
      res.status(202).json({ success: true, data: state });
    } catch (err) {
      if (err instanceof VersionRefreshRefused) {
        sendRefusal(res, err.status, err.code, err.message, err.deviceIds.length > 0 ? { deviceIds: err.deviceIds } : {});
        return;
      }
      next(err);
    }
  },

  /** POST /os-upgrade - THE endpoint that ends in routers rebooting. */
  async launch(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const input = parseLaunchBody(req.body);
      const distinct = [...new Set(input.deviceIds)];
      if (distinct.length > 1) {
        await requireExtraCapability(
          req,
          CAPABILITIES.ROLLOUT_MANAGE,
          'Several devices are upgraded as a wave rollout, and composing and launching a rollout ' +
            'is ROLLOUT_MANAGE everywhere in this product.',
        );
      }
      if (input.overrideReason) {
        await requireExtraCapability(
          req,
          CAPABILITIES.CHANGE_APPROVE,
          'The override reason every OS upgrade carries is a signature, and signing is CHANGE_APPROVE.',
        );
      }

      // God view: a selection in ONE tenant launches in that tenant (its job or
      // rollout, its audit); one spanning several fans out per tenant.
      const groups = await godViewSelection(req, input.deviceIds);
      if (groups && groups.size > 1) {
        await launchAcrossTenants(req, res, input, groups);
        return;
      }
      if (groups && groups.size === 1) enterObjectTenant(req, [...groups.keys()][0]);

      const decision = await decideLaunch(req.tenantId, input, { checkSignatures: true });
      if (!decision.ok || decision.version === null || !input.overrideReason || !input.confirmDegraded) {
        const status = decision.refusals.some((r) => r.code === 'not_found')
          ? 404
          : decision.refusals.length === 0 &&
              decision.problems.length > 0 &&
              decision.problems.every((p) => p.code.endsWith('_required'))
            ? 422
            : 409;
        const first = decision.problems[0]?.message ?? null;
        sendRefusal(
          res,
          status,
          'launch_refused',
          decision.refusals.length > 0
            ? `${decision.refusals.length} of ${decision.deviceIds.length} selected device(s) cannot be ` +
                'upgraded now. Nothing was queued.'
            : first ?? 'Nothing to upgrade. Nothing was queued.',
          { refusals: decision.refusals, problems: decision.problems },
        );
        return;
      }

      const userId = req.session.userId ?? null;
      const override = { reason: input.overrideReason, userId };
      const confirmDegraded = { userId };

      if (decision.mode === 'job') {
        const { jobId } = await launcher.enqueueOne({
          tenantId: req.tenantId,
          deviceId: decision.deviceIds[0],
          version: decision.version,
          requestedBy: userId,
          override,
          confirmDegraded,
        });
        res.status(201).json({
          success: true,
          data: { mode: 'job', jobId, rolloutId: null, version: decision.version, waves: [] },
        });
        return;
      }

      const { rolloutId } = await launcher.launchRollout({
        tenantId: req.tenantId,
        name: input.name ?? `RouterOS ${decision.version} - ${decision.deviceIds.length} devices`,
        deviceIds: decision.deviceIds,
        version: decision.version,
        waves: decision.waves,
        requestedBy: userId,
        override,
        confirmDegraded,
      });
      res.status(201).json({
        success: true,
        data: { mode: 'rollout', jobId: null, rolloutId, version: decision.version, waves: decision.waves },
      });
    } catch (err) {
      handleLaunchError(err, res, next);
    }
  },
};

/**
 * The multi-tenant launch (god view). Every tenant's decision is taken BEFORE
 * anything is launched: one refused router anywhere refuses the whole launch
 * with every refusal listed — the per-tenant all-or-nothing rule, kept across
 * tenants. Then one job or rollout per tenant, IN that tenant (its audit, its
 * kill switch, its queue). A tenant whose launch fails after the decision
 * (kill switch engaged since, device busy) is reported in `byTenant` with its
 * error; the tenants already launched are not undone — they are ordinary,
 * independently abortable rollouts.
 */
async function launchAcrossTenants(
  req: Request,
  res: Response,
  input: LaunchRequest,
  groups: Map<number, number[]>,
): Promise<void> {
  const { merged, decisions } = await decideAcrossTenants(req, input, groups, { checkSignatures: true, withMembers: false });
  if (!merged.ok || merged.version === null || !input.overrideReason || !input.confirmDegraded) {
    const status = merged.refusals.some((r) => r.code === 'not_found') ? 404 : 409;
    sendRefusal(
      res,
      status,
      'launch_refused',
      merged.refusals.length > 0
        ? `${merged.refusals.length} of ${merged.deviceIds.length} selected device(s) cannot be upgraded now. Nothing was queued.`
        : merged.problems[0]?.message ?? 'Nothing to upgrade. Nothing was queued.',
      { refusals: merged.refusals, problems: merged.problems, byTenant: merged.byTenant },
    );
    return;
  }
  const userId = req.session.userId ?? null;
  const override = { reason: input.overrideReason, userId };
  const confirmDegraded = { userId };
  const names = await tenantNames(groups.keys());
  const byTenant: Array<Record<string, unknown>> = [];
  for (const { tenantId, decision } of decisions) {
    const version = decision.version ?? merged.version;
    try {
      if (decision.mode === 'job') {
        const { jobId } = await runAsTenant(req, tenantId, () => launcher.enqueueOne({
          tenantId, deviceId: decision.deviceIds[0], version, requestedBy: userId, override, confirmDegraded,
        }));
        byTenant.push({ tenantId, tenantName: names.get(tenantId) ?? null, mode: 'job', jobId, rolloutId: null, devices: 1 });
      } else {
        const base = input.name ?? `RouterOS ${version} - ${decision.deviceIds.length} devices`;
        const { rolloutId } = await runAsTenant(req, tenantId, () => launcher.launchRollout({
          tenantId,
          name: `${base} (${names.get(tenantId) ?? tenantId})`.slice(0, 200),
          deviceIds: decision.deviceIds,
          version,
          waves: decision.waves,
          requestedBy: userId,
          override,
          confirmDegraded,
        }));
        byTenant.push({ tenantId, tenantName: names.get(tenantId) ?? null, mode: 'rollout', jobId: null, rolloutId, devices: decision.deviceIds.length });
      }
    } catch (err) {
      logger.warn({ err, tenantId }, 'God view OS upgrade: this tenant was not launched');
      byTenant.push({
        tenantId, tenantName: names.get(tenantId) ?? null, mode: decision.mode, jobId: null, rolloutId: null,
        devices: decision.deviceIds.length, error: err instanceof Error ? err.message : String(err),
      });
    }
  }
  await auditGodViewFanOut(
    req,
    'os_upgrade.launch',
    decisions.map((d) => ({ tenantId: d.tenantId, ids: d.decision.deviceIds, result: null })),
    { version: merged.version, launched: byTenant.filter((b) => !b.error).length, failed: byTenant.filter((b) => b.error).length },
  );
  res.status(201).json({
    success: true,
    godView: true,
    data: { mode: 'multi_tenant', jobId: null, rolloutId: null, version: merged.version, waves: [], byTenant },
  });
}
