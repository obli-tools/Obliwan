// ============================================================================
// ObliWAN — wave rollouts
// ============================================================================
//
// One template revision, N devices, pushed in canary waves with a HEALTH GATE
// measured BETWEEN them. A failed gate STOPS the rollout, quarantines the
// revision that caused it and lists every device that took the change as « À
// remettre en arrière »: the remedy is a rollout of the previous revision to
// those devices (a plan, under the guard and the dead-man); the push job's
// pre-change backup is recorded beside each one as a record, since nothing in
// ObliWAN loads a stored backup onto a router. Nothing is undone
// automatically: there is no restore job (`restore` has no renderer and is
// refused by the queue), and the one this file used to queue took a backup,
// armed a dead-man and refused — the dead-man then rebooted every landed
// router, restoring nothing, under an override written in the launcher's name.
//
// A rollout has a KIND (migration 047). `push` is the above. `os_upgrade`
// brings N RouterOS devices to ONE pinned release (`rollouts.target_version`),
// one `os_upgrade` job per device (services/firmware/osUpgrade.service.ts),
// through the SAME waves and the SAME health gate — with ONE adjustment: the
// reboot is the job's point, so a device whose job saw it come back is judged
// on sysUpTime against the floor of a box that booted once before that return
// (`rebaseBaselineForUpgradeBoot`), not against the pre-wave uptime; a second
// boot still fails. What differs is the end of
// a failed gate: there is no revision to quarantine, and nothing is "rolled
// back" — restoring a configuration backup cannot un-install a RouterOS
// release, it would only reboot the box once more. The rollout STOPS: the
// waves that never ran are skipped and it ends `failed`, for a human.
//
// `management_access` (migration 058) opens api-ssl on N MikroTik routers in
// service, one `management_access` job per device
// (services/change/managementAccess.service.ts), through the SAME waves and
// the SAME health gate, so a whole customer is done canary first. It names no
// revision and no version: every job freezes the management range at its own
// enqueue. A failed gate STOPS it like an os_upgrade rollout: loading a binary
// backup to close api-ssl again would reboot the router — a disruption nobody
// asked for, to undo a change that left SSH, the path the job travels on,
// untouched — and no restore job exists anyway. The waves that never ran are
// skipped; the failed devices are a human's.
//
// `legacy_compliance` (migration 066) brings N MikroTik routers in service up
// to the corrected customer templates, one `legacy_compliance` job per device
// (services/change/legacyCompliance.service.ts), through the same waves and
// gate, with management_access's shape (no revision, no version) and its end
// of a failed gate: STOP, undo nothing — a restore would reboot the router to
// take back corrections that only opened services and added an address.
//
// Every kind now ends a failed gate the same way: STOP, undo nothing, name the
// devices a human must look at. A push differs only in what it adds — the
// revision quarantined, and each landed device's pre-change backup recorded
// (`rollout_targets.rollback_backup_id`) for the manual restore.
//
// ┌─ WHAT THIS SERVICE IS ALLOWED TO DO, AND WHAT IT MUST DELEGATE ───────────┐
// │ It NEVER opens a socket to an equipment. Nothing writes                   │
// │ outside `change_jobs`, and a rollout is no exception to that — it is a    │
// │ CUSTOMER of it. Every device this file touches is touched by enqueuing a  │
// │ job and watching its status. `jobQueue`, `apply`, `safeApply`, `backup`,  │
// │ `rollback` and `killSwitch` are called, never re-implemented, and the     │
// │ blast radius comes from `plan/blastRadius.service` for the same reason:   │
// │ the numbers on the impact screen must be produced by the code the queue   │
// │ will act on, not by a second implementation that agrees with it today.    │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ THE THREE RULES THAT DECIDE THIS MILESTONE ──────────────────────────────┐
// │ 1. THE BASELINE COMES BEFORE THE WAVE. `startWave` captures it and only   │
// │    then queues a single job. `rollout_targets_baseline_before_chk`        │
// │    (migration 010) makes the reverse order unrepresentable, so this is    │
// │    not a convention that a refactor can quietly invert.                   │
// │ 2. `degraded` GOES LAST. The order comes from `orderForWaves` in          │
// │    blastRadius.service, and `rollout_targets_safety_order` refuses any    │
// │    row that would break it.                                               │
// │ 3. A CONCENTRATOR AND ITS CHILDREN NEVER SHARE A ROLLOUT. The             │
// │    composition is REFUSED — `findSubtreeConflicts` explains it in a       │
// │    sentence, and two triggers in migration 010 make it impossible even if │
// │    somebody writes the rows by hand.                                      │
// └───────────────────────────────────────────────────────────────────────────┘
//
// LEAD, TWO LINES ARE NEEDED IN FILES THIS MILESTONE MAY NOT TOUCH:
//   • `server/src/index.ts`, next to `startChangeWorker(runJob)`:
//         startRolloutRuntime();      // and `await stopRolloutRuntime()` in shutdown
//     Without it this whole subsystem is an old lesson repeated: it compiles,
//     its tables exist, its routes answer — and no wave ever advances.
//   • `shared/src/index.ts`: `export * from './rollout';`
//
// SECRETS (the secrets rule): the plan envelopes stored on `rollout_targets` are the
// REDACTED ones the planner produced. The complete rendered config exists in
// memory only, on the vault -> equipment path, inside `safeApply`.

import type { Knex } from 'knex';
import {
  SOCKET_EVENTS,
  isRouterOsReleaseVersion,
  parseRouterOsVersion,
  type GuardVerdict,
  type SafetyLevel,
} from '@obliwan/shared';
import {
  GATE_SETTLE_MS,
  GATE_TIMEOUT_MS,
  describeSubtreeConflict,
  findSubtreeConflicts,
  isTerminalRolloutStatus,
  planWaves,
  type HealthBaseline,
  type HealthGateReason,
  type PlannedWave,
  type RolloutStatus,
  type RolloutSummary,
  type RolloutTargetStatus,
  type SubtreeConflict,
  type WaveGateResult,
} from '@obliwan/shared/dist/rollout';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { leaderElection } from '../leaderElection';
import { emitToTenantAudience } from '../fleet/scopedEmit';
import {
  CONCENTRATOR_GENERIC_WRITE_REFUSAL,
  ChangeRefusedError,
  concentratorGenericWriteMessage,
  enqueueChangeJob,
  evaluateGuardForPlan,
  guardVerdictWorsened,
  resolveSafetyNet,
  type GuardOutcome,
  type SafetyNetPlan,
} from './apply.service';
import {
  OsUpgradeError,
  enqueueOsUpgradeJob,
  osUpgradeDeviceRefusals,
  osUpgradeGuard,
  osUpgradeSafetyNet,
  rebaseBaselineForUpgradeBoot,
  upgradeSecondBootMessage,
  type UpgradeBootRebase,
} from '../firmware/osUpgrade.service';
import {
  enqueueManagementAccessJob,
  managementAccessGuard,
  managementAccessRefusals,
  managementAccessSafetyNet,
} from './managementAccess.service';
import {
  enqueueLegacyComplianceJob,
  legacyComplianceGuard,
  legacyComplianceRefusals,
  legacyComplianceSafetyNet,
} from './legacyCompliance.service';
import { enqueueWanLinkJob, wanLinkGuard, wanLinkRefusals, wanLinkSafetyNet } from './wanLink.service';
import { readKillSwitch, KillSwitchEngagedError } from './killSwitch.service';
import { abortJob } from './jobQueue.service';
import { compilePlan, PlanCompilationError } from '../plan/planner.service';
import { checkPlanUplinks, uplinkRefusalMessage, UPLINK_REFUSAL_KIND } from '../plan/uplinkGuard';
import {
  aggregateBlastRadius,
  orderForWaves,
  describeBlastRadius,
  type BlastDeviceInput,
  type FleetBlastRadius,
  type SafetyNetLevel,
} from '../plan/blastRadius.service';
import { captureBaselines, evaluateWave, type GateTarget } from './healthGate';
import { applyTenantScope, withTenantNames } from '../../utils/globalView';

// ============================================================================
// Errors
// ============================================================================

/**
 * Every refusal this service can produce, with a machine-readable `kind` the
 * controller maps to a status code. the subtree interlock arrives as
 * `subtree_interlock` and must never be flattened into a 500: an operator has
 * to be told WHICH devices to remove, not that something went wrong.
 */
export class RolloutRefusedError extends Error {
  constructor(
    readonly kind: string,
    message: string,
    readonly detail: unknown = null,
  ) {
    super(message);
    this.name = 'RolloutRefusedError';
  }
}

// ============================================================================
// Row shapes
// ============================================================================

export interface RolloutRow {
  id: number;
  uuid: string;
  tenant_id: number;
  name: string;
  description: string | null;
  /** Migration 047. `push` names a revision, `os_upgrade` a target version —
   *  never both, never neither (`rollouts_kind_shape_chk`). */
  kind: RolloutKind;
  template_revision_id: number | null;
  target_version: string | null;
  /** Migration 090: the mode a `wan_link` rollout switches to; null otherwise. */
  wan_target_mode?: string | null;
  status: RolloutStatus;
  wave_count: number;
  device_count: number;
  site_count: number;
  current_wave_index: number | null;
  succeeded_count: number;
  failed_count: number;
  rolled_back_count: number;
  failed_wave_index: number | null;
  revision_quarantined_at: Date | null;
  pause_reason: string | null;
  abort_reason: string | null;
  gate_settle_ms: number;
  override_reason: string | null;
  overridden_by: number | null;
  degraded_confirmed_by: number | null;
  created_by: number | null;
  started_by: number | null;
  started_at: Date | null;
  finished_at: Date | null;
  created_at: Date;
}

export interface WaveRow {
  id: number;
  rollout_id: number;
  tenant_id: number;
  wave_index: number;
  label: string;
  target_count: number;
  status: string;
  succeeded_count: number;
  failed_count: number;
  gate_verdict: string | null;
  gate_reasons: unknown;
  started_at: Date | null;
  gate_started_at: Date | null;
  finished_at: Date | null;
}

export interface TargetRow {
  id: number;
  rollout_id: number;
  wave_id: number;
  tenant_id: number;
  device_id: number;
  wave_index: number;
  order_rank: number;
  status: RolloutTargetStatus;
  safety_level: SafetyLevel;
  safety_peer_device_id: number | null;
  plan_envelope: unknown;
  plan_ops_count: number;
  risk_level: string;
  guard_verdict: string | null;
  job_id: number | null;
  queued_at: Date | null;
  health_baseline: unknown;
  health_baseline_at: Date | null;
  health_verdict: string | null;
  health_reasons: unknown;
  rollback_job_id: number | null;
  rollback_backup_id: number | null;
  note: string | null;
  device_name?: string;
}

/** The device columns `evaluateGuardForPlan` / `resolveSafetyNet` read. Kept
 *  in lockstep with `apply.service.DeviceRecord`; selected explicitly so a
 *  column added there does not silently arrive here as `undefined`. */
const DEVICE_COLUMNS = [
  'id', 'uuid', 'tenant_id', 'site_id', 'name', 'brand', 'family', 'model',
  'os_version', 'tunnel_ip', 'source_ip_hint', 'concentrator_id', 'status', 'is_managed',
] as const;

interface DeviceRow {
  id: number;
  uuid: string;
  tenant_id: number;
  site_id: number | null;
  name: string;
  brand: string;
  family: string;
  model: string | null;
  os_version: string | null;
  tunnel_ip: string | null;
  source_ip_hint: string | null;
  concentrator_id: number | null;
  status: string;
  is_managed: boolean;
  role?: string;
  site_name?: string | null;
}

function iso(d: Date | null | undefined): string | null {
  return d ? new Date(d).toISOString() : null;
}

function asArray<T>(v: unknown): T[] {
  return Array.isArray(v) ? (v as T[]) : [];
}

/** `SafetyLevel` (lowercase, the database's spelling) -> `SafetyNetLevel`
 *  (uppercase, blastRadius' spelling). ONE bridge, exactly as
 *  `mgmtPathVerdictOf` is the one bridge between the guard's two vocabularies.
 *  Hand-mapping this at a call site is how a `degraded` device ends up sorted
 *  as if it were armed. */
export function safetyNetLevelOf(level: SafetyLevel): SafetyNetLevel {
  switch (level) {
    case 'armed': return 'ARMED';
    case 'armed_by_peer': return 'ARMED_BY_PEER';
    default: return 'DEGRADED';
  }
}

// ============================================================================
// Composition — the impact screen, and the moment the concentrator interlock refuses
// ============================================================================

/** What a rollout carries (migration 047, `rollouts_kind_chk`; 058 adds
 *  `management_access`, 066 `legacy_compliance`). */
export type RolloutKind = 'push' | 'os_upgrade' | 'management_access' | 'legacy_compliance' | 'wan_link';

/** The rollout kinds that name nothing (no revision, no version) and whose
 *  jobs read the router at run time: each has its own enqueue door. */
export type PlanlessSshRolloutKind = 'management_access' | 'legacy_compliance' | 'wan_link';

/** The WAN1 modes a `wan_link` rollout switches every site to (migration 090). */
const WAN_TARGET_MODES = ['dhcp', 'pppoe', 'static'] as const;
export type WanTargetMode = (typeof WAN_TARGET_MODES)[number];

export interface ComposeInput {
  tenantId: number;
  name: string;
  description?: string | null;
  deviceIds: readonly number[];
  /** Default `push`. */
  kind?: RolloutKind;
  /** Required for `push`, absent for `os_upgrade`. */
  templateRevisionId?: number | null;
  /** Required for `os_upgrade` (a RouterOS 7 release), absent for `push`. */
  targetVersion?: string | null;
  createdBy: number | null;
  gateSettleMs?: number;
  /** Signed once, in front of the impact screen, for every device whose guard
   *  verdict is not ACCEPT. Copied onto each job at enqueue time, where
   *  migration 009's CHECK makes it non-optional. */
  override?: { reason: string; userId: number | null } | null;
  /** The safety-net rule's explicit confirmation, for every `degraded` device in the set. */
  confirmDegraded?: { userId: number | null } | null;
  /** Required for `wan_link` (migration 090), absent otherwise: the mode
   *  every site switches to, its parameters read from each site's variables. */
  wanTargetMode?: WanTargetMode | null;
}

/** One device on the impact screen, before anything is queued. */
export interface ComposedTarget {
  deviceId: number;
  deviceName: string;
  siteId: number | null;
  siteName: string | null;
  brand: string;
  waveIndex: number;
  orderRank: number;
  safetyLevel: SafetyLevel;
  safetyPeerDeviceId: number | null;
  safetyRationale: string;
  guardVerdict: string;
  guardSummary: string;
  planOpsCount: number;
  riskLevel: string;
  /** The REDACTED `ApplyPlan` envelope compiled BEFORE the launch. Null for an
   *  `os_upgrade` target: it has no plan. */
  planEnvelope: unknown;
}

export interface RolloutComposition {
  /** `null` in preview mode: nothing was written. */
  rolloutId: number | null;
  name: string;
  kind: RolloutKind;
  /** Null for an `os_upgrade` rollout. */
  templateRevisionId: number | null;
  /** Null for a `push` rollout. */
  targetVersion: string | null;
  /** `wan_link` only (migration 090): the mode every site switches to. */
  wanTargetMode?: WanTargetMode | null;
  waves: PlannedWave[];
  targets: ComposedTarget[];
  /** Devices whose plan did not compile. They are NOT silently dropped: a
   *  rollout that quietly excludes four devices is a rollout whose operator
   *  believes he covered the fleet. */
  failures: { deviceId: number; deviceName: string | null; reason: string; message: string }[];
  blastRadius: FleetBlastRadius;
  summaryLine: string;
  /** The safety-net rule, counted so the confirmation dialog can state the number. */
  degradedCount: number;
  guardNotClearedCount: number;
  requiresOverride: boolean;
  requiresDegradedConfirmation: boolean;
  killSwitch: { blocked: boolean; reason: string | null };
}

async function loadDevicesForRollout(
  tenantId: number,
  deviceIds: readonly number[],
  q: Knex | Knex.Transaction,
): Promise<DeviceRow[]> {
  const rows = (await q('devices as d')
    .leftJoin('sites as s', 's.id', 'd.site_id')
    .where('d.tenant_id', tenantId)
    .whereIn('d.id', deviceIds as number[])
    .select(
      ...DEVICE_COLUMNS.map((c) => `d.${c}`),
      'd.role as role',
      's.name as site_name',
    )) as DeviceRow[];
  return rows;
}

/**
 * Compile the whole rollout without writing anything to a device.
 *
 * This is the rollout's "écran de rayon d'impact (compilation des N plans AVANT
 * lancement)" and the safety-net rule's "le niveau est calculé par device et affiché sur
 * l'écran de rayon d'impact AVANT le lancement, jamais après". The three
 * expensive things — the render, the semantic diff and the Management-Path
 * Guard's forwarding simulation — all happen HERE, once, so that the operator
 * decides with the same numbers the queue will act on.
 *
 * `persist = false` is the preview; `persist = true` writes the rollout in
 * `draft`. The two share every line of arithmetic on purpose.
 */
async function build(input: ComposeInput, persist: boolean): Promise<RolloutComposition> {
  const deviceIds = [...new Set(input.deviceIds.map(Number))].filter((n) => Number.isInteger(n) && n > 0);
  if (deviceIds.length === 0) {
    throw new RolloutRefusedError('empty', 'A rollout with no device is not a rollout.');
  }

  // ── WHAT is rolled out: a revision, or a RouterOS release (migration 047) ─
  const kind: RolloutKind = input.kind ?? 'push';
  const templateRevisionId = input.templateRevisionId ?? null;
  const targetVersion = input.targetVersion ?? null;
  if (kind === 'push') {
    if (templateRevisionId === null || targetVersion !== null) {
      throw new RolloutRefusedError(
        'kind_shape',
        'A push rollout names a template revision and no target version.',
      );
    }
  } else if (kind === 'os_upgrade') {
    if (templateRevisionId !== null) {
      throw new RolloutRefusedError(
        'kind_shape',
        'An os_upgrade rollout names a RouterOS target version and no template revision.',
      );
    }
    if (!isRouterOsReleaseVersion(targetVersion) || parseRouterOsVersion(targetVersion)!.major !== 7) {
      throw new RolloutRefusedError(
        'target_invalid',
        'An os_upgrade rollout needs a RouterOS 7 release such as 7.24.5 (never a release candidate).',
      );
    }
  } else if (kind === 'management_access' || kind === 'legacy_compliance' || kind === 'wan_link') {
    // Migration 058's (and 066's, 090's) shape: no revision, no version —
    // every job decides on what it reads at its own enqueue and run.
    if (templateRevisionId !== null || targetVersion !== null) {
      throw new RolloutRefusedError(
        'kind_shape',
        `A ${kind} rollout names neither a template revision nor a target version.`,
      );
    }
    if (kind === 'wan_link' && !(WAN_TARGET_MODES as readonly string[]).includes(String(input.wanTargetMode ?? ''))) {
      throw new RolloutRefusedError('kind_shape', 'A wan_link rollout names the WAN1 mode every site switches to: dhcp, pppoe or static.');
    }
  } else {
    throw new RolloutRefusedError('kind_invalid', 'A rollout is a push, an os_upgrade, a management_access, a legacy_compliance or a wan_link.');
  }
  const wanTargetMode: WanTargetMode | null = kind === 'wan_link' ? (input.wanTargetMode as WanTargetMode) : null;

  const devices = await loadDevicesForRollout(input.tenantId, deviceIds, db);
  const missing = deviceIds.filter((id) => !devices.some((d) => Number(d.id) === id));
  if (missing.length > 0) {
    throw new RolloutRefusedError(
      'device_not_found',
      `Device(s) ${missing.join(', ')} do not exist in this tenant.`,
      { missing },
    );
  }

  // ── THE SUBTREE INTERLOCK, AT COMPOSITION AND NOWHERE LATER ───────────────
  //
  // Refused here, before a single plan is compiled, because the refusal is the
  // point: "Refuse la composition du rollout, ne la répare pas en cours de
  // route." Repairing it mid-flight would mean silently pulling devices out of
  // a set an operator already approved.
  const conflicts: SubtreeConflict[] = findSubtreeConflicts(
    devices.map((d) => ({
      deviceId: Number(d.id),
      deviceName: d.name,
      role: String(d.role ?? 'cpe'),
      concentratorId: d.concentrator_id === null ? null : Number(d.concentrator_id),
    })),
  );
  if (conflicts.length > 0) {
    throw new RolloutRefusedError(
      'subtree_interlock',
      conflicts.map(describeSubtreeConflict).join(' '),
      { conflicts },
    );
  }

  const notWritable = devices.filter(
    (d) => d.status === 'disabled' || d.status === 'quarantined' || !d.is_managed,
  );
  if (notWritable.length > 0) {
    throw new RolloutRefusedError(
      'device_not_writable',
      `${notWritable.length} device(s) in this set cannot be written to: ` +
        notWritable.map((d) => `${d.name} (${d.is_managed ? d.status : 'not managed'})`).join(', ') +
        '. A device can be readable without being writable, and that distinction is the whole ' +
        'reason `is_managed` is a separate column.',
      { deviceIds: notWritable.map((d) => Number(d.id)) },
    );
  }

  // The revision is PINNED here and used for every wave's recompilation. A
  // revision published between wave 1 and wave 4 must not change what wave 4
  // pushes: the operator approved a body, not a moving target. (An os_upgrade
  // rollout pins its release in `target_version` the same way.)
  if (kind === 'push') {
    const revision = (await db('template_revisions as r')
      .join('templates as t', 't.id', 'r.template_id')
      .where('r.id', templateRevisionId as number)
      .where((b) => b.where('t.tenant_id', input.tenantId).orWhereNull('t.tenant_id'))
      .first('r.id', 'r.status', 'r.revision', 'r.template_id')) as
      | { id: number; status: string; revision: number; template_id: number }
      | undefined;
    if (!revision) {
      throw new RolloutRefusedError(
        'revision_not_found',
        `Template revision ${templateRevisionId} does not exist in this tenant.`,
      );
    }
    if (revision.status !== 'published') {
      throw new RolloutRefusedError(
        'revision_not_published',
        `Template revision ${templateRevisionId} is '${revision.status}'. Only a published ` +
          'revision may be rolled out — a quarantined one is quarantined for a reason somebody wrote down.',
      );
    }
  }

  // ── The N plans, compiled BEFORE the launch ──────────────────────────────
  const failures: RolloutComposition['failures'] = [];
  const compiled: Array<{
    device: DeviceRow;
    plan: { ops: unknown[]; riskLevel: string; [k: string]: unknown };
    signals: Record<number, unknown>;
    guard: GuardOutcome;
    net: SafetyNetPlan;
  }> = [];

  for (const device of devices) {
    if (kind === 'os_upgrade') {
      // No plan to compile: the job decides on what the router says at run
      // time. What CAN be judged now is whether the device may get the job at
      // all — and a device that may not is listed, never silently dropped.
      const refusals = osUpgradeDeviceRefusals({
        name: device.name,
        brand: device.brand,
        family: device.family,
        role: device.role,
        status: device.status,
        is_managed: device.is_managed,
      });
      if (refusals.length > 0) {
        failures.push({
          deviceId: Number(device.id),
          deviceName: device.name,
          reason: refusals[0].kind,
          message: refusals.map((r) => r.message).join(' '),
        });
        continue;
      }
      compiled.push({
        device,
        plan: { ops: [], riskLevel: 'high' },
        signals: {},
        guard: osUpgradeGuard() as GuardOutcome,
        net: osUpgradeSafetyNet(),
      });
      continue;
    }
    if (kind === 'management_access') {
      // No plan either: the job reads the router at run time. Judged now —
      // and listed, never dropped — is whether the device may get the job:
      // brand, SSH channel, a backup road, the management range.
      const { refusals } = await managementAccessRefusals(input.tenantId, Number(device.id));
      if (refusals.length > 0) {
        failures.push({
          deviceId: Number(device.id),
          deviceName: device.name,
          reason: refusals[0].kind,
          message: refusals.map((r) => r.message).join(' '),
        });
        continue;
      }
      compiled.push({
        device,
        plan: { ops: [], riskLevel: 'low' },
        signals: {},
        guard: managementAccessGuard() as GuardOutcome,
        net: managementAccessSafetyNet(),
      });
      continue;
    }
    if (kind === 'legacy_compliance') {
      // No plan either: the job reads the router at run time. Judged now, and
      // listed: brand, role, SSH channel, a backup road.
      const { refusals } = await legacyComplianceRefusals(input.tenantId, Number(device.id));
      if (refusals.length > 0) {
        failures.push({
          deviceId: Number(device.id),
          deviceName: device.name,
          reason: refusals[0].kind,
          message: refusals.map((r) => r.message).join(' '),
        });
        continue;
      }
      compiled.push({
        device,
        plan: { ops: [], riskLevel: 'low' },
        signals: {},
        guard: legacyComplianceGuard() as GuardOutcome,
        net: legacyComplianceSafetyNet(),
      });
      continue;
    }
    if (kind === 'wan_link') {
      // No plan: each job reads its router at run time. Judged now, and
      // listed: the device, the site's declared WAN1 variables (the target's
      // parameters read from them — a missing one is named), the target.
      const { refusals } = await wanLinkRefusals(input.tenantId, Number(device.id), {
        toMode: wanTargetMode as WanTargetMode,
        params: 'site',
      });
      if (refusals.length > 0) {
        failures.push({
          deviceId: Number(device.id),
          deviceName: device.name,
          reason: refusals[0].kind,
          message: refusals.map((r) => r.message).join(' '),
        });
        continue;
      }
      compiled.push({
        device,
        plan: { ops: [], riskLevel: 'low' },
        signals: {},
        guard: wanLinkGuard() as GuardOutcome,
        net: wanLinkSafetyNet(),
      });
      continue;
    }
    // A concentrator is never the target of a push (`refuseConcentratorGenericWrite`,
    // apply.service.ts): listed by name, before a plan is compiled for it, so
    // it never sits in a wave the operator signs for. Only its dedicated kinds
    // write to it.
    if (String(device.role ?? 'cpe') === 'concentrator') {
      failures.push({
        deviceId: Number(device.id),
        deviceName: device.name,
        reason: CONCENTRATOR_GENERIC_WRITE_REFUSAL,
        message: concentratorGenericWriteMessage(device.name, 'push'),
      });
      continue;
    }
    try {
      const compilation = await compilePlan(input.tenantId, Number(device.id), {
        revisionId: templateRevisionId as number,
        // A preview must not litter `config_renders` with rows for a rollout
        // nobody launched; a composed rollout keeps its provenance.
        persistRender: persist,
        createdBy: input.createdBy,
        source: 'template',
      });
      // ── Uplink preservation (plan/uplinkGuard.ts) ─────────────────────────
      // A plan that would take a production uplink away is not a target: the
      // planner compiled those ops as `blocked` (`uplink_preserved`) and the
      // queue refuses such a plan at launch whatever is signed. Named HERE, so
      // it never sits in a wave the operator signs for.
      const uplinkCut = checkPlanUplinks(null, compilation.plan.ops).refusals;
      if (uplinkCut.length > 0) {
        failures.push({
          deviceId: Number(device.id),
          deviceName: device.name,
          reason: UPLINK_REFUSAL_KIND,
          message: uplinkRefusalMessage(uplinkCut),
        });
        continue;
      }
      const guard = await evaluateGuardForPlan(device as never, compilation.plan.ops);
      const net = await resolveSafetyNet(device as never);
      compiled.push({
        device,
        plan: compilation.plan as never,
        signals: compilation.detail.signals as never,
        guard,
        net,
      });
    } catch (err) {
      failures.push({
        deviceId: Number(device.id),
        deviceName: device.name,
        reason: err instanceof PlanCompilationError ? err.reason : (err as Error).name,
        message: err instanceof Error ? err.message : String(err),
      });
    }
  }

  if (compiled.length === 0) {
    throw new RolloutRefusedError(
      'nothing_compiles',
      (kind === 'os_upgrade' || kind === 'management_access' || kind === 'legacy_compliance' || kind === 'wan_link'
        ? `Not one of the ${devices.length} device(s) can get an ${kind} job. `
        : `Not one of the ${devices.length} device(s) produced a plan. `) +
        (failures[0]?.message ?? ''),
      { failures },
    );
  }

  // ── The blast radius, from the ONE implementation (blastRadius.service) ──
  const blastInputs: BlastDeviceInput[] = compiled.map((c) => ({
    deviceId: Number(c.device.id),
    deviceName: c.device.name,
    siteId: c.device.site_id === null ? null : Number(c.device.site_id),
    siteName: c.device.site_name ?? null,
    brand: c.device.brand,
    family: c.device.family as never,
    ops: c.plan.ops as never,
    riskLevel: c.plan.riskLevel as never,
    signals: c.signals as never,
    guardVerdict: c.guard.verdict as never,
    // The REAL, resolved level, not `classifySafetyNet`'s inventory guess: we
    // just asked `apply.service` the same question the enqueue will ask.
    safetyNet: safetyNetLevelOf(c.net.level),
  }));
  const blastRadius = aggregateBlastRadius(blastInputs);

  // ── THE SAFETY-NET RULE'S ORDER: armed first, degraded LAST ──────────────
  const ordered = orderForWaves(
    compiled.map((c) => ({
      safetyNet: safetyNetLevelOf(c.net.level),
      deviceId: Number(c.device.id),
      c,
    })),
  );
  const waves = planWaves(ordered.length);

  const targets: ComposedTarget[] = [];
  let cursor = 0;
  for (const wave of waves) {
    for (let rank = 0; rank < wave.size; rank++) {
      const { c } = ordered[cursor++];
      targets.push({
        deviceId: Number(c.device.id),
        deviceName: c.device.name,
        siteId: c.device.site_id === null ? null : Number(c.device.site_id),
        siteName: c.device.site_name ?? null,
        brand: c.device.brand,
        waveIndex: wave.index,
        orderRank: rank,
        safetyLevel: c.net.level,
        safetyPeerDeviceId: c.net.peerDeviceId,
        safetyRationale: c.net.rationale,
        guardVerdict: c.guard.verdict,
        guardSummary: c.guard.summary,
        planOpsCount: (c.plan.ops as unknown[]).length,
        riskLevel: String(c.plan.riskLevel),
        planEnvelope: kind === 'os_upgrade' || kind === 'management_access' || kind === 'legacy_compliance' || kind === 'wan_link' ? null : c.plan,
      });
    }
  }

  const degradedCount = targets.filter((t) => t.safetyLevel === 'degraded').length;
  const guardNotClearedCount = targets.filter((t) => t.guardVerdict !== 'ACCEPT').length;
  const killSwitch = await readKillSwitch(input.tenantId);

  const composition: RolloutComposition = {
    rolloutId: null,
    name: input.name,
    kind,
    templateRevisionId,
    targetVersion,
    ...(kind === 'wan_link' ? { wanTargetMode } : {}),
    waves,
    targets,
    failures,
    blastRadius,
    summaryLine: describeBlastRadius(blastRadius),
    degradedCount,
    guardNotClearedCount,
    requiresOverride: guardNotClearedCount > 0,
    requiresDegradedConfirmation: degradedCount > 0,
    killSwitch: { blocked: killSwitch.blocked, reason: killSwitch.reason },
  };

  if (!persist) return composition;

  // ── The two signatures, demanded ONCE in front of the numbers above ──────
  if (composition.requiresOverride && !input.override) {
    throw new RolloutRefusedError(
      'guard_refused',
      `${guardNotClearedCount} of ${targets.length} device(s) were not cleared by the ` +
        'Management-Path Guard — INDETERMINATE included, which is a refusal and not a pass. ' +
        'Composing this rollout requires an explicit override with a written reason ' +
        '(capability CHANGE_APPROVE), recorded against your name. It covers THESE devices and ' +
        'only these: a device cleared today and refused by the guard when its wave runs is ' +
        'failed, not pushed.',
      { deviceIds: blastRadius.guardNotClearedDeviceIds },
    );
  }
  if (composition.requiresDegradedConfirmation && !input.confirmDegraded) {
    throw new RolloutRefusedError(
      'degraded_unconfirmed',
      `${degradedCount} of ${targets.length} device(s) have NO remote recovery (the safety net ` +
        'DEGRADED: detection without repair — a failure there means a visit). They are ordered ' +
        'LAST in the waves, and the rollout still needs an explicit confirmation before it can ' +
        'be composed.',
      { degradedCount },
    );
  }

  const rolloutId = await persistComposition(input, composition);
  composition.rolloutId = rolloutId;
  return composition;
}

/**
 * Refuse unless the push revision `revisionId` is `published`, reading it
 * FOR SHARE inside `trx`. FOR SHARE conflicts with the FOR UPDATE that
 * `setRevisionStatus` (template/version.service.ts) holds while it changes a
 * status, so a change in flight is waited for and its RESULT is what is read.
 * The lock is held until `trx` commits. `stage` names the step in the
 * refusal ('composed', 'launched').
 */
async function assertRevisionPublished(
  trx: Knex.Transaction,
  revisionId: number | null,
  stage: 'composed' | 'launched',
): Promise<void> {
  const revision =
    revisionId === null
      ? undefined
      : ((await trx('template_revisions').where({ id: revisionId }).forShare().first('status')) as
          | { status: string }
          | undefined);
  if (!revision || revision.status !== 'published') {
    throw new RolloutRefusedError(
      'revision_not_published',
      `Template revision ${revisionId ?? '(none)'} is '${revision?.status ?? 'missing'}' now, so this rollout ` +
        `cannot be ${stage}: only a published revision may be rolled out. Its status changed after the ` +
        'rollout was previewed; compose it again from a published revision.',
      { templateRevisionId: revisionId, status: revision?.status ?? null },
    );
  }
}

async function persistComposition(
  input: ComposeInput,
  composition: RolloutComposition,
): Promise<number> {
  const now = new Date();
  return db.transaction(async (trx) => {
    // `build` read the revision's status without a lock, before minutes of
    // compilation. Read again FOR SHARE in the transaction that inserts the
    // draft: a lifecycle change committed since (`setRevisionStatus`, which
    // holds the row FOR UPDATE) is seen and refused here, and one that starts
    // now waits for this transaction and then finds the draft — every move but
    // quarantine is refused while a rollout of the revision is active.
    if (composition.kind === 'push') {
      await assertRevisionPublished(trx, composition.templateRevisionId, 'composed');
    }
    const [rollout] = (await trx('rollouts')
      .insert({
        tenant_id: input.tenantId,
        name: input.name.trim(),
        description: input.description ?? null,
        kind: composition.kind,
        template_revision_id: composition.templateRevisionId,
        target_version: composition.targetVersion,
        // 090: only a wan_link rollout names a mode (rollouts_wan_target_mode_chk).
        ...(composition.kind === 'wan_link' ? { wan_target_mode: composition.wanTargetMode } : {}),
        status: 'draft',
        wave_count: composition.waves.length,
        device_count: composition.targets.length,
        site_count: composition.blastRadius.siteCount,
        blast_radius: JSON.stringify(composition.blastRadius),
        gate_settle_ms: input.gateSettleMs ?? GATE_SETTLE_MS,
        override_reason: input.override?.reason ?? null,
        overridden_by: input.override ? input.override.userId : null,
        overridden_at: input.override ? now : null,
        degraded_confirmed_by: input.confirmDegraded ? input.confirmDegraded.userId : null,
        degraded_confirmed_at: input.confirmDegraded ? now : null,
        created_by: input.createdBy,
      })
      .returning('id')) as Array<{ id: string | number }>;
    const rolloutId = Number(rollout.id);

    const waveIdByIndex = new Map<number, number>();
    for (const wave of composition.waves) {
      const [row] = (await trx('rollout_waves')
        .insert({
          rollout_id: rolloutId,
          wave_index: wave.index,
          label: wave.label,
          target_count: wave.size,
          status: 'pending',
        })
        .returning('id')) as Array<{ id: string | number }>;
      waveIdByIndex.set(wave.index, Number(row.id));
    }

    for (const t of composition.targets) {
      await trx('rollout_targets').insert({
        rollout_id: rolloutId,
        wave_id: waveIdByIndex.get(t.waveIndex),
        device_id: t.deviceId,
        wave_index: t.waveIndex,
        order_rank: t.orderRank,
        status: 'pending',
        safety_level: t.safetyLevel,
        safety_peer_device_id: t.safetyPeerDeviceId,
        // SQL NULL, never the JSON `null`: `rollout_targets_shape_chk` accepts
        // NULL or an object, and an os_upgrade target has no plan.
        plan_envelope: t.planEnvelope === null ? null : JSON.stringify(t.planEnvelope),
        plan_ops_count: t.planOpsCount,
        risk_level: t.riskLevel,
        guard_verdict: t.guardVerdict,
      });
    }
    return rolloutId;
  });
}

export function previewRollout(input: ComposeInput): Promise<RolloutComposition> {
  return build(input, false);
}
export function composeRollout(input: ComposeInput): Promise<RolloutComposition> {
  return build(input, true);
}

// ============================================================================
// Reading
// ============================================================================

export async function getRollout(
  tenantId: number,
  rolloutId: number,
  q: Knex | Knex.Transaction = db,
): Promise<RolloutRow | null> {
  const row = (await q('rollouts')
    .where({ id: rolloutId, tenant_id: tenantId })
    .first('*')) as RolloutRow | undefined;
  return row ?? null;
}

export async function listRollouts(
  tenantId: number,
  /** `rolloutIdsIn`: team scope (migration 087) — null/undefined = unrestricted. */
  opts: { status?: string[]; limit?: number; offset?: number; rolloutIdsIn?: number[] | null } = {},
): Promise<RolloutSummary[]> {
  const query = db('rollouts');
  // God view (a platform admin's GET on the master tenant): every tenant's
  // rollouts, each tagged with its tenant; anyone else: this tenant's.
  const godView = applyTenantScope(query, 'tenant_id', tenantId);
  if (opts.status?.length) query.whereIn('status', opts.status);
  if (opts.rolloutIdsIn) query.whereIn('id', opts.rolloutIdsIn);
  const rows = (await query
    .orderBy('created_at', 'desc')
    .limit(Math.min(opts.limit ?? 50, 200))
    .offset(opts.offset ?? 0)
    .select('*')) as RolloutRow[];
  return withTenantNames(rows.map(toRolloutSummary), 'tenantId', godView);
}

/**
 * The wire summary. `kind` and `targetVersion` ride along beside the shared
 * `RolloutSummary` shape, and `templateRevisionId` is NULL for a rollout that
 * pushes no revision (os_upgrade, management_access, legacy_compliance):
 * writing `Number(null)` there would announce "revision 0", which does not
 * exist.
 */
export function toRolloutSummary(
  r: RolloutRow,
): RolloutSummary & { kind: RolloutKind; targetVersion: string | null; wanTargetMode: WanTargetMode | null } {
  return {
    id: Number(r.id),
    uuid: r.uuid,
    tenantId: Number(r.tenant_id),
    name: r.name,
    status: r.status,
    kind: r.kind ?? 'push',
    targetVersion: r.target_version ?? null,
    wanTargetMode: (r.wan_target_mode ?? null) as WanTargetMode | null,
    templateRevisionId:
      r.template_revision_id === null || r.template_revision_id === undefined
        ? null
        : Number(r.template_revision_id),
    deviceCount: Number(r.device_count),
    siteCount: Number(r.site_count),
    waveCount: Number(r.wave_count),
    currentWaveIndex: r.current_wave_index === null ? null : Number(r.current_wave_index),
    succeededCount: Number(r.succeeded_count),
    failedCount: Number(r.failed_count),
    rolledBackCount: Number(r.rolled_back_count),
    revisionQuarantinedAt: iso(r.revision_quarantined_at),
    failedWaveIndex: r.failed_wave_index === null ? null : Number(r.failed_wave_index),
    pauseReason: r.pause_reason,
    abortReason: r.abort_reason,
    startedBy: r.started_by === null ? null : Number(r.started_by),
    startedAt: iso(r.started_at),
    finishedAt: iso(r.finished_at),
    createdAt: new Date(r.created_at).toISOString(),
  };
}

export async function listWaves(
  rolloutId: number,
  q: Knex | Knex.Transaction = db,
): Promise<WaveRow[]> {
  return (await q('rollout_waves')
    .where({ rollout_id: rolloutId })
    .orderBy('wave_index')
    .select('*')) as WaveRow[];
}

export async function listTargets(
  rolloutId: number,
  waveIndex: number | null = null,
  q: Knex | Knex.Transaction = db,
): Promise<TargetRow[]> {
  const query = q('rollout_targets as t')
    .join('devices as d', 'd.id', 't.device_id')
    .where('t.rollout_id', rolloutId);
  if (waveIndex !== null) query.where('t.wave_index', waveIndex);
  return (await query
    .orderBy(['t.wave_index', 't.order_rank'])
    .select('t.*', 'd.name as device_name')) as TargetRow[];
}

// ============================================================================
// The state machine
// ============================================================================

async function setStatus(
  rollout: RolloutRow,
  status: RolloutStatus,
  patch: Record<string, unknown> = {},
  q: Knex | Knex.Transaction = db,
): Promise<RolloutRow> {
  const update: Record<string, unknown> = { status, updated_at: q.fn.now(), ...patch };
  if (isTerminalRolloutStatus(status) && patch.finished_at === undefined) {
    update.finished_at = new Date();
  }
  await q('rollouts').where({ id: rollout.id }).update(update);
  const fresh = (await q('rollouts').where({ id: rollout.id }).first('*')) as RolloutRow;
  return fresh;
}

// ============================================================================
// Launch — and the ORDER of the two things it does is the milestone
// ============================================================================

export async function launchRollout(
  tenantId: number,
  rolloutId: number,
  userId: number | null,
): Promise<RolloutRow> {
  const rollout = await getRollout(tenantId, rolloutId);
  if (!rollout) throw new RolloutRefusedError('not_found', `Rollout ${rolloutId} not found`);
  if (rollout.status !== 'draft') {
    throw new RolloutRefusedError(
      'not_draft',
      `Rollout ${rolloutId} is '${rollout.status}'. Only a draft can be launched.`,
    );
  }
  const killSwitch = await readKillSwitch(tenantId);
  if (killSwitch.blocked) throw new KillSwitchEngagedError(killSwitch);

  // draft -> running is decided in ONE transaction with what it depends on.
  // The rollout row is re-read FOR UPDATE, so two launches of one draft are
  // serialised and the second finds it running. A push rollout's revision is
  // re-read FOR SHARE and must still be `published`: the composition read it
  // once, possibly long before, and a draft can outlive a lifecycle change
  // (the creation race `persistComposition` closes, or a status written by
  // any other path). A `setRevisionStatus` in flight is waited for; one that
  // starts now waits for this commit and then finds the rollout running.
  const running = await db.transaction(async (trx) => {
    const fresh = (await trx('rollouts')
      .where({ id: rollout.id, tenant_id: tenantId })
      .forUpdate()
      .first('*')) as RolloutRow | undefined;
    if (!fresh) throw new RolloutRefusedError('not_found', `Rollout ${rolloutId} not found`);
    if (fresh.status !== 'draft') {
      throw new RolloutRefusedError(
        'not_draft',
        `Rollout ${rolloutId} is '${fresh.status}'. Only a draft can be launched.`,
      );
    }
    if (fresh.kind === 'push') {
      await assertRevisionPublished(trx, fresh.template_revision_id === null ? null : Number(fresh.template_revision_id), 'launched');
    }
    return setStatus(
      fresh,
      'running',
      { started_by: userId, started_at: new Date(), current_wave_index: 0, pause_reason: null },
      trx,
    );
  });

  logger.warn(
    { rolloutId, tenantId, devices: rollout.device_count, waves: rollout.wave_count, userId },
    'ROLLOUT LAUNCHED — a wave rollout is about to write to a fleet',
  );

  await startWave(running, 0);
  emitProgress(running, `wave 1/${running.wave_count} starting`);
  return (await getRollout(tenantId, rolloutId)) as RolloutRow;
}

/**
 * Start one wave. THE ORDER OF THE TWO HALVES IS THE POINT.
 *
 *   1. capture the health baseline for every device in the wave;
 *   2. only then queue a single job.
 *
 * Reversed, the gate would compare each device to its own post-change state
 * and measure nothing at all. `rollout_targets_baseline_before_chk` refuses
 * the row that would result, so this order cannot be inverted by accident —
 * but it is written this way round so nobody has to learn that from a
 * constraint violation at three in the morning.
 */
async function startWave(rollout: RolloutRow, waveIndex: number): Promise<void> {
  const targets = await listTargets(Number(rollout.id), waveIndex);
  if (targets.length === 0) return;

  // ── 1. THE BASELINE, BEFORE ANYTHING IS QUEUED ───────────────────────────
  const baselineAt = new Date();
  const baselines = await captureBaselines(
    Number(rollout.tenant_id),
    targets.map((t) => Number(t.device_id)),
    db,
    baselineAt,
  );
  for (const t of targets) {
    const b = baselines.get(Number(t.device_id));
    // `captureBaselines` returns nothing for a device `loadDevices` no longer
    // hands back — disabled since composition, moved out of the tenant. That
    // device is NOT skipped quietly: `queueTarget` refuses it below, on this
    // very field, and it never reaches a router.
    if (!b) continue;
    await db('rollout_targets').where({ id: t.id }).update({
      health_baseline: JSON.stringify(b),
      health_baseline_at: baselineAt,
      updated_at: db.fn.now(),
    });
    // The in-memory row is what `queueTarget` reads; leaving it stale would
    // make every target look baseline-less.
    t.health_baseline = b;
    t.health_baseline_at = baselineAt;
  }

  await db('rollout_waves')
    .where({ rollout_id: rollout.id, wave_index: waveIndex })
    .update({ status: 'running', started_at: new Date(), updated_at: db.fn.now() });

  // ── 2. Only now, the jobs ────────────────────────────────────────────────
  for (const t of targets) {
    await queueTarget(rollout, t);
  }

  const wave = (await db('rollout_waves')
    .where({ rollout_id: rollout.id, wave_index: waveIndex })
    .first('*')) as WaveRow;
  emitWave(rollout, wave);
}

/**
 * Queue ONE device's push — or, on an `os_upgrade` rollout, its os_upgrade job
 * for the pinned `target_version` (no plan: the rest of this note is about
 * pushes, the override, the baseline and the transaction apply to both).
 *
 * The plan is RECOMPILED against the pinned revision rather than replayed from
 * the envelope stored at composition. A plan is perishable (`PLAN_TTL_MS` is
 * 30 minutes) and wave 4 can run an hour after wave 1; replaying a stale
 * envelope would hand `enqueueChangeJob` a `base_state_hash` that no longer
 * describes the box, and `assertPlanFresh` would refuse it — correctly, and
 * unhelpfully. Recompiling against the SAME revision keeps the content pinned
 * while letting the base state be today's.
 *
 * A device that refuses to be queued is recorded as `failed` WITH the reason,
 * never dropped: a rollout that quietly skips four devices is a rollout whose
 * operator believes he covered the fleet.
 *
 * ┌─ THE SIGNED OVERRIDE IS NOT A BLANKET, AND IT DOES NOT AGE WELL ──────────┐
 * │ The operator signed in front of a screen that said "3 of 300 device(s)    │
 * │ were not cleared". He signed for THOSE THREE, and for the verdicts they   │
 * │ had at that moment. Replaying that signature verbatim onto every device   │
 * │ of every wave turned it into a standing authorisation: a device that was  │
 * │ ACCEPT at composition, and that an engineer has since fitted with a       │
 * │ `chain=input action=drop`, would be pushed to on a fresh REJECT — the     │
 * │ guard having PROVED the plan cuts the management path — under a reason    │
 * │ that talks about three CPEs in Nantes.                                    │
 * │                                                                          │
 * │ So the override is replayed only onto the devices whose COMPOSITION       │
 * │ verdict was already not ACCEPT (`rollout_targets.guard_verdict`, frozen   │
 * │ by `persistComposition` — the same set the operator was shown as          │
 * │ `blastRadius.guardNotClearedDeviceIds`), and a device whose verdict has   │
 * │ WORSENED since is refused outright, whatever was signed.                  │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ ONE TRANSACTION, OR AN ORPHAN JOB WRITES TO A ROUTER NOBODY IS WATCHING ─┐
 * │ Creating the job and recording it on the target used to be three          │
 * │ statements in three implicit transactions. The last one can fail —        │
 * │ `rollout_targets_baseline_before_chk` fires on a target whose baseline    │
 * │ was never captured — and the `catch` then marked the TARGET failed while  │
 * │ the JOB stayed queued and went on to push. A failed gate lists targets in │
 * │ `succeeded` for the manual restore (`stopPushRollout`), so that device    │
 * │ was never named: it kept the configuration the gate had just judged      │
 * │ harmful, and nobody was told to look at it.                              │
 * │                                                                          │
 * │ Now: the bookkeeping is one transaction, and if anything after the insert │
 * │ fails the job is ABORTED before the target is written off. A job that     │
 * │ cannot be aborted is one a worker has already claimed — that is a fact an │
 * │ operator has to be told, not a line in a log.                            │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
async function queueTarget(rollout: RolloutRow, target: TargetRow): Promise<void> {
  const tenantId = Number(rollout.tenant_id);
  let jobId: number | null = null;

  try {
    // ── The baseline, checked BEFORE a job can exist ───────────────────────
    // `startWave` captures it, and skips silently for a device `loadDevices`
    // no longer returns. Without it `rollout_targets_baseline_before_chk`
    // rejects the row that records the job — after the job exists. Refusing
    // here means the device is never written to at all, which is the only
    // acceptable answer for a device whose post-change health CANNOT be
    // measured: an ungated push is not what the operator asked for.
    if (target.health_baseline_at === null) {
      throw new RolloutRefusedError(
        'no_baseline',
        'No health baseline could be captured for this device, so its health gate could ' +
          'never conclude. It has NOT been queued — an unmeasurable push is not a push this ' +
          'rollout is allowed to make. Check that the device is still enabled and in this tenant.',
      );
    }

    // The verdict this device carried on the composition screen. `null` only
    // for a row written before that column existed; treated as ACCEPT would be
    // the unsafe reading, so it is treated as "not cleared" — the override
    // covers it and the worsening check below still applies.
    const composedVerdict = (target.guard_verdict ?? 'INDETERMINATE') as GuardVerdict;
    const overrideCoversThisDevice = composedVerdict !== 'ACCEPT';
    const override =
      rollout.override_reason && overrideCoversThisDevice
        ? { reason: rollout.override_reason, userId: rollout.overridden_by }
        : null;
    const confirmDegraded = rollout.degraded_confirmed_by !== null
      ? { userId: rollout.degraded_confirmed_by }
      : null;

    let result: {
      jobId: number;
      guard: { verdict: GuardVerdict; summary: string };
      safetyNet: { level: SafetyLevel; peerDeviceId: number | null };
    };
    let opsCount = 0;
    let riskLevel = 'high';
    if (rollout.kind === 'os_upgrade') {
      // One os_upgrade job, through its own door (it carries the pinned
      // release, which the generic enqueue has no field for).
      result = await enqueueOsUpgradeJob({
        tenantId,
        deviceId: Number(target.device_id),
        targetVersion: rollout.target_version as string,
        requestedBy: rollout.started_by,
        override,
        confirmDegraded,
      });
    } else if (rollout.kind === 'management_access') {
      // One management_access job, through its own door (it freezes the
      // management range at its enqueue). Its guard is ACCEPT by construction,
      // so no override is carried; the rollout's degraded confirmation is.
      // A job already running on the device is refused (DeviceBusyError),
      // never adopted: a rollout queues its own jobs.
      riskLevel = 'low';
      result = await enqueueManagementAccessJob({
        tenantId,
        deviceId: Number(target.device_id),
        requestedBy: rollout.started_by,
        confirmDegraded,
        allowExisting: false,
      });
    } else if (rollout.kind === 'wan_link') {
      // One wan_link job, through its own door: the mode the rollout names,
      // the parameters each site declares (the PPPoE password from the site's
      // vault). ACCEPT by construction (no override carried), the rollout's
      // confirmation of the expected cut carried, a job already running
      // refused, never adopted.
      riskLevel = 'low';
      result = await enqueueWanLinkJob({
        tenantId,
        deviceId: Number(target.device_id),
        requestedBy: rollout.started_by,
        request: { toMode: rollout.wan_target_mode as WanTargetMode, params: 'site' },
        confirmExpectedCut: confirmDegraded,
        allowExisting: false,
      });
    } else if (rollout.kind === 'legacy_compliance') {
      // One legacy_compliance job, through its own door, like management_access:
      // ACCEPT by construction (no override carried), the rollout's degraded
      // confirmation carried, a job already running refused, never adopted.
      riskLevel = 'low';
      result = await enqueueLegacyComplianceJob({
        tenantId,
        deviceId: Number(target.device_id),
        requestedBy: rollout.started_by,
        confirmDegraded,
        allowExisting: false,
      });
    } else {
      const compilation = await compilePlan(tenantId, Number(target.device_id), {
        revisionId: Number(rollout.template_revision_id),
        persistRender: true,
        createdBy: rollout.started_by,
        source: 'template',
      });
      result = await enqueueChangeJob({
        tenantId,
        deviceId: Number(target.device_id),
        kind: 'push',
        plan: compilation.plan,
        requestedBy: rollout.started_by,
        override,
        confirmDegraded,
      });
      opsCount = compilation.plan.ops.length;
      riskLevel = compilation.plan.riskLevel;
    }
    jobId = result.jobId;

    // The world may have moved between the signature and this wave. Nothing
    // signed at composition authorises a verdict that is worse than the one
    // signed for.
    if (guardVerdictWorsened(composedVerdict, result.guard.verdict)) {
      throw new RolloutRefusedError(
        'guard_worsened',
        `The Management-Path Guard now says ${result.guard.verdict} for this device; it was ` +
          `${composedVerdict} when this rollout was composed and signed. ${result.guard.summary} ` +
          'Nothing signed then covers this, so the device has been left untouched.',
      );
    }

    // Migration 009 forward-declared these three columns for exactly this
    // moment; `change_jobs_rollout_chk` ties the first two together and
    // `change_jobs_canary_rank_chk` (010) ties the third to them.
    //
    // ONE transaction with the target row: either this device is a queued
    // target of this rollout, or it has no job at all.
    await db.transaction(async (trx) => {
      await trx('change_jobs').where({ id: result.jobId }).update({
        rollout_id: rollout.id,
        wave_index: target.wave_index,
        canary_rank: target.order_rank,
        updated_at: trx.fn.now(),
      });

      await trx('rollout_targets').where({ id: target.id }).update({
        job_id: result.jobId,
        queued_at: new Date(),
        status: 'queued',
        guard_verdict: result.guard.verdict,
        safety_level: result.safetyNet.level,
        safety_peer_device_id: result.safetyNet.peerDeviceId,
        plan_ops_count: opsCount,
        risk_level: riskLevel,
        updated_at: trx.fn.now(),
      });
    });
    // No device-room emit here: `enqueueChangeJob` already sends JOB_QUEUED to
    // `device:{id}`, and a second payload under the ROLLOUT_PROGRESS name
    // would give one event name two shapes — which is how a client ends up
    // reading `status` off a message that has none.
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(
      { rolloutId: Number(rollout.id), deviceId: Number(target.device_id), jobId, err },
      'rollout: a device could not be queued',
    );

    // ── The job must not outlive its own bookkeeping ───────────────────────
    let note = message;
    if (jobId !== null) {
      try {
        await abortJob(
          tenantId,
          jobId,
          rollout.started_by,
          'the rollout could not record this job against its target',
        );
      } catch (abortErr) {
        // `abortJob` refuses anything past `queued`: a worker has claimed it
        // and this device IS going to be written to, outside the rollout's
        // accounting. `rollout_targets_job_chk` + `..._baseline_before_chk`
        // forbid naming the job on a target we could not queue, so the only
        // honest place left is the note — and it must scream.
        logger.error(
          { rolloutId: Number(rollout.id), deviceId: Number(target.device_id), jobId, abortErr },
          'ROLLOUT ORPHAN JOB — a change job could not be attached to its rollout target and ' +
            'could not be aborted either. It will write to the device without this rollout ' +
            'watching it, and a failed gate will NOT list that device for its manual restore.',
        );
        note =
          `${message}\n\nWARNING: change job #${jobId} was already claimed and could not be ` +
          'aborted. It will write to this device OUTSIDE this rollout, and a failed gate will ' +
          'not list it for restoring. This device needs a human.';
      }
    }

    await db('rollout_targets').where({ id: target.id }).update({
      status: 'failed',
      note: note.slice(0, 2000),
      updated_at: db.fn.now(),
    });
    await db('rollout_waves')
      .where({ rollout_id: rollout.id, wave_index: target.wave_index })
      .increment('failed_count', 1);
    await db('rollouts').where({ id: rollout.id }).increment('failed_count', 1);
    // Swallowed on purpose, whatever the shape: one device that cannot be
    // queued must not abort the wave loop for the other nineteen. The reason
    // is on the target row, where an operator reads it, and in the log above.
  }
}

// ============================================================================
// Advancing — one tick over one rollout
// ============================================================================

/** What a tick did, so the caller (and the test) can assert on it. */
export interface AdvanceReport {
  rolloutId: number;
  status: RolloutStatus;
  waveIndex: number | null;
  action:
    | 'waiting_jobs'
    | 'settling'
    | 'gate_passed'
    | 'gate_failed'
    | 'gate_indeterminate'
    | 'wave_started'
    | 'finished'
    | 'rollback_pending'
    | 'rolled_back'
    | 'idle';
  gate: WaveGateResult | null;
  message: string;
}

const JOB_TERMINAL = ['succeeded', 'rolled_back', 'failed', 'aborted'];

/**
 * Advance one rollout by at most one step.
 *
 * Deliberately NOT a loop: every step of a rollout is a decision an operator
 * may want to interrupt, and a function that runs a whole rollout to
 * completion in one call is a function that cannot be paused.
 */
export async function advanceRollout(
  tenantId: number,
  rolloutId: number,
): Promise<AdvanceReport> {
  const rollout = await getRollout(tenantId, rolloutId);
  if (!rollout) throw new RolloutRefusedError('not_found', `Rollout ${rolloutId} not found`);

  if (rollout.status === 'rolling_back') return advanceRollback(rollout);
  if (rollout.status !== 'running') {
    return {
      rolloutId,
      status: rollout.status,
      waveIndex: rollout.current_wave_index,
      action: 'idle',
      gate: null,
      message: `Rollout is '${rollout.status}'; nothing to advance.`,
    };
  }

  const waveIndex = rollout.current_wave_index ?? 0;
  const targets = await listTargets(rolloutId, waveIndex);
  const wave = (await db('rollout_waves')
    .where({ rollout_id: rolloutId, wave_index: waveIndex })
    .first('*')) as WaveRow | undefined;
  if (!wave) {
    throw new RolloutRefusedError('no_wave', `Rollout ${rolloutId} has no wave ${waveIndex}`);
  }

  // ── 1. Reconcile every target with its job ───────────────────────────────
  const jobIds = targets.map((t) => t.job_id).filter((v): v is number => v !== null);
  const jobs = jobIds.length
    ? ((await db('change_jobs')
        .whereIn('id', jobIds)
        .select('id', 'status', 'outcome')) as Array<{
        id: number;
        status: string;
        outcome: string | null;
      }>)
    : [];
  const jobById = new Map(jobs.map((j) => [Number(j.id), j]));

  let stillRunning = 0;
  for (const t of targets) {
    if (t.status === 'failed' || t.status === 'succeeded' || t.status === 'rolled_back') continue;
    if (t.job_id === null) continue;
    const job = jobById.get(Number(t.job_id));
    if (!job) continue;
    if (!JOB_TERMINAL.includes(job.status)) {
      stillRunning++;
      if (t.status !== 'running') {
        await db('rollout_targets').where({ id: t.id }).update({
          status: 'running',
          updated_at: db.fn.now(),
        });
      }
      continue;
    }
    const next: RolloutTargetStatus =
      job.status === 'succeeded' ? 'succeeded'
        : job.status === 'rolled_back' ? 'rolled_back'
          : 'failed';
    await db('rollout_targets').where({ id: t.id }).update({
      status: next,
      updated_at: db.fn.now(),
    });
    t.status = next;
  }

  if (stillRunning > 0) {
    return {
      rolloutId,
      status: rollout.status,
      waveIndex,
      action: 'waiting_jobs',
      gate: null,
      message: `${stillRunning} job(s) still in flight in wave ${waveIndex + 1}.`,
    };
  }

  // ── 2. Every job is terminal: open the settle window ─────────────────────
  const succeeded = targets.filter((t) => t.status === 'succeeded').length;
  const failed = targets.filter((t) => t.status === 'failed' || t.status === 'rolled_back').length;
  await db('rollout_waves').where({ id: wave.id }).update({
    succeeded_count: succeeded,
    failed_count: failed,
    updated_at: db.fn.now(),
  });

  let gateStartedAt = wave.gate_started_at;
  if (!gateStartedAt) {
    gateStartedAt = new Date();
    await db('rollout_waves').where({ id: wave.id }).update({
      status: 'gating',
      gate_started_at: gateStartedAt,
      updated_at: db.fn.now(),
    });
    wave.status = 'gating';
    wave.gate_started_at = gateStartedAt;
    emitWave(rollout, wave);
  }

  const settled = Date.now() - new Date(gateStartedAt).getTime();
  if (settled < Number(rollout.gate_settle_ms) && settled < GATE_TIMEOUT_MS) {
    return {
      rolloutId,
      status: rollout.status,
      waveIndex,
      action: 'settling',
      gate: null,
      message:
        `Wave ${waveIndex + 1} is settling: ${Math.round(settled / 1000)}s of ` +
        `${Math.round(Number(rollout.gate_settle_ms) / 1000)}s. The gate measures AFTER the ` +
        'poller has had a chance to write a fresh sample — measuring immediately would compare ' +
        'the device to nothing.',
    };
  }

  // ── 3. THE GATE ──────────────────────────────────────────────────────────
  const gateTargets: GateTarget[] = targets.map((t) => ({
    deviceId: Number(t.device_id),
    deviceName: t.device_name ?? `#${t.device_id}`,
    jobId: t.job_id === null ? null : Number(t.job_id),
    baseline: (t.health_baseline as HealthBaseline | null) ?? null,
  }));
  // An os_upgrade job REBOOTS the box: that is its point, and judged against
  // the pre-wave sysUpTime it would read as UNEXPECTED_BOOT and fail every wave
  // that worked. Each device whose job saw it come back is judged instead
  // against the uptime floor of a box that booted ONCE before that return,
  // so a second boot (a crash on the new release) still fails the gate.
  const rebased = new Map<number, UpgradeBootRebase>();
  if (rollout.kind === 'os_upgrade') {
    for (const g of gateTargets) {
      const r = await rebaseBaselineForUpgradeBoot(tenantId, g.deviceId, g.jobId, g.baseline);
      if (!r) continue;
      g.baseline = r.baseline;
      rebased.set(g.deviceId, r.rebase);
    }
  }
  // A wan_link job DISABLES the old link on purpose (the old PPPoE client,
  // renamed when the new one takes its name): judged against the pre-wave
  // baseline it would read as IF_OPER_DOWN and fail every wave that worked.
  // Those interfaces — and only those — leave each device's baseline.
  if (rollout.kind === 'wan_link') {
    for (const g of gateTargets) {
      if (g.jobId === null || !g.baseline) continue;
      const row = (await db('wan_link_jobs').where({ job_id: g.jobId }).first('before')) as
        | { before: { plan?: { retiredInterfaces?: unknown } } | null }
        | undefined;
      g.baseline = withoutRetiredInterfaces(g.baseline, row?.before?.plan?.retiredInterfaces);
    }
  }
  const gate = await evaluateWave(tenantId, waveIndex, gateTargets);
  for (const d of gate.devices) {
    const rebase = rebased.get(d.deviceId);
    if (!rebase) continue;
    d.reasons = d.reasons.map((r) =>
      r.code === 'UNEXPECTED_BOOT'
        ? { ...r, message: upgradeSecondBootMessage(rebase, typeof r.after === 'number' ? r.after : null) }
        : r,
    );
  }

  const now = new Date();
  for (const d of gate.devices) {
    await db('rollout_targets')
      .where({ rollout_id: rolloutId, device_id: d.deviceId })
      .update({
        health_verdict: d.verdict,
        health_reasons: JSON.stringify(d.reasons),
        health_checked_at: now,
        updated_at: db.fn.now(),
      });
  }
  const waveReasons: HealthGateReason[] = gate.devices.flatMap((d) =>
    d.verdict === 'PASS' ? [] : d.reasons.map((r) => ({ ...r, message: `${d.deviceName}: ${r.message}` })),
  );
  await db('rollout_waves').where({ id: wave.id }).update({
    gate_verdict: gate.verdict,
    gate_reasons: JSON.stringify(waveReasons),
    updated_at: db.fn.now(),
  });
  wave.gate_verdict = gate.verdict;
  wave.gate_reasons = waveReasons;

  if (gate.verdict === 'FAIL') {
    await db('rollout_waves').where({ id: wave.id }).update({
      status: 'failed',
      finished_at: now,
      updated_at: db.fn.now(),
    });
    wave.status = 'failed';
    emitWave(rollout, wave);
    const report = await stopPushRollout(rollout, waveIndex, gate);
    return report;
  }

  if (gate.verdict === 'INDETERMINATE') {
    // The train stops; nothing is undone. A rollback triggered by ignorance
    // would annul good changes every time an SNMP target is missing, and a net
    // that fires on ignorance is a net people switch off.
    const paused = await setStatus(rollout, 'paused', {
      pause_reason:
        `Wave ${waveIndex + 1}'s health gate could not conclude on ` +
        `${gate.indeterminateDeviceIds.length} device(s). Nothing has been rolled back: an ` +
        'INDETERMINATE gate has not proved harm, it has proved it cannot see. Look, then resume ' +
        'or abort.',
    });
    emitProgress(paused, `wave ${waveIndex + 1} gate INDETERMINATE — paused`);
    emitWave(paused, wave);
    return {
      rolloutId,
      status: 'paused',
      waveIndex,
      action: 'gate_indeterminate',
      gate,
      message: paused.pause_reason ?? '',
    };
  }

  // ── 4. PASS: next wave, or the end ───────────────────────────────────────
  await db('rollout_waves').where({ id: wave.id }).update({
    status: 'passed',
    finished_at: now,
    updated_at: db.fn.now(),
  });
  wave.status = 'passed';
  emitWave(rollout, wave);

  await db('rollouts').where({ id: rolloutId }).update({
    succeeded_count: await countTargets(rolloutId, ['succeeded']),
    failed_count: await countTargets(rolloutId, ['failed']),
    updated_at: db.fn.now(),
  });

  const nextIndex = waveIndex + 1;
  if (nextIndex < Number(rollout.wave_count)) {
    const advanced = await setStatus(rollout, 'running', { current_wave_index: nextIndex });
    await startWave(advanced, nextIndex);
    emitProgress(advanced, `wave ${nextIndex + 1}/${advanced.wave_count} starting`);
    return {
      rolloutId,
      status: 'running',
      waveIndex: nextIndex,
      action: 'wave_started',
      gate,
      message: `Wave ${waveIndex + 1} passed its health gate; wave ${nextIndex + 1} started.`,
    };
  }

  const done = await setStatus(rollout, 'succeeded', { current_wave_index: null });
  emitProgress(done, 'every wave passed its health gate');
  emitFinished(done, false);
  return {
    rolloutId,
    status: 'succeeded',
    waveIndex,
    action: 'finished',
    gate,
    message: `All ${done.wave_count} wave(s) passed. ${done.succeeded_count} device(s) changed.`,
  };
}

async function countTargets(rolloutId: number, statuses: string[]): Promise<number> {
  const row = (await db('rollout_targets')
    .where({ rollout_id: rolloutId })
    .whereIn('status', statuses)
    .count<{ c: string }>({ c: '*' })
    .first()) as { c: string } | undefined;
  return Number(row?.c ?? 0);
}

// ============================================================================
// The failure path — quarantine, stop, and name what a human must restore
// ============================================================================

/**
 * A gate said FAIL on a push rollout: STOP, and restore NOTHING automatically.
 *
 * ┌─ WHY NOTHING IS RESTORED ANY MORE ────────────────────────────────────────┐
 * │ This function used to queue a `restore` job for every device that took   │
 * │ the change, under an override written by the machine in the launcher's  │
 * │ name (a launcher without CHANGE_APPROVE ended up "signing" what only     │
 * │ CHANGE_APPROVE may sign). `restore` has no implementation: each job took │
 * │ a preflight backup, armed the on-box dead-man and refused at the write — │
 * │ and the dead-man then rebooted the router at its deadline, reloading its │
 * │ own backup. Every landed router rebooted and nothing was restored, while │
 * │ the screen said "its previous waves are restored". The queue now refuses │
 * │ `restore` at every door; this file no longer asks.                       │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * What happens, in this order:
 *
 *  1. THE REVISION IS QUARANTINED FIRST, so it cannot be assigned to a new
 *     device or picked up by another rollout while a human looks. A
 *     `deprecated` one is quarantined too: deprecation keeps a revision
 *     renderable (render.service and siteRender.service accept it), so a
 *     revision deprecated while its rollout ran would otherwise stay
 *     renderable after its gate proved it harmful. `template_revisions.status`
 *     already accepts `quarantined`, and its freeze trigger (migration 008)
 *     allows both flips.
 *  2. Waves that never ran are marked `skipped` and their devices released.
 *  3. Every device that ACTUALLY took the change — this wave included — keeps
 *     it, and is listed « À remettre en arrière »: its push job's pre-change
 *     backup goes on `rollout_targets.rollback_backup_id` (a record: no
 *     operation in ObliWAN loads a stored backup onto a router) with a note
 *     naming the remedy that EXISTS — a rollout of the previous revision to
 *     that device — and NO job is queued and NO override is written. "Took
 *     the change" is a `succeeded` target, and also a `failed` one whose
 *     push job proved the change and disarmed its dead-man before failing on
 *     its own bookkeeping (`failJob`: "the change stands, only the job
 *     failed"). A device whose own dead-man already restored it
 *     (`rolled_back`) is not listed: it is back on its pre-change
 *     configuration.
 *  4. The rollout ends `failed` — the state that means somebody has to look —
 *     in one step: there is nothing in flight to wait for, so `rolling_back`
 *     is never entered and an abort has nothing to stop.
 */
async function stopPushRollout(
  rollout: RolloutRow,
  failedWaveIndex: number,
  gate: WaveGateResult,
): Promise<AdvanceReport> {
  const rolloutId = Number(rollout.id);

  if (rollout.kind === 'os_upgrade') return stopOsUpgradeRollout(rollout, failedWaveIndex, gate);
  // wan_link too: each router's own script already reverted a link that did
  // not carry traffic, and nothing else can be undone from here.
  if (rollout.kind === 'management_access' || rollout.kind === 'legacy_compliance' || rollout.kind === 'wan_link') {
    return stopManagementAccessRollout(rollout, failedWaveIndex, gate);
  }

  logger.error(
    {
      rolloutId,
      waveIndex: failedWaveIndex,
      failedDeviceIds: gate.failedDeviceIds,
      revisionId: Number(rollout.template_revision_id),
    },
    'ROLLOUT GATE FAILED — quarantining the revision and stopping; the devices that took the ' +
      'change are listed for a MANUAL restore (nothing is restored automatically)',
  );

  // ── 1. Quarantine ────────────────────────────────────────────────────────
  const quarantinedAt = new Date();
  const flipped = await db('template_revisions')
    .where({ id: rollout.template_revision_id })
    .whereIn('status', ['published', 'deprecated'])
    .update({ status: 'quarantined', updated_at: db.fn.now() });

  // ── 2. Waves that never ran ──────────────────────────────────────────────
  await db('rollout_waves')
    .where({ rollout_id: rolloutId })
    .where('wave_index', '>', failedWaveIndex)
    .update({ status: 'skipped', finished_at: quarantinedAt, updated_at: db.fn.now() });
  await db('rollout_targets')
    .where({ rollout_id: rolloutId })
    .where('wave_index', '>', failedWaveIndex)
    .whereIn('status', ['pending', 'queued'])
    .update({
      status: 'skipped',
      note: `Never ran: wave ${failedWaveIndex + 1} failed its health gate.`,
      updated_at: db.fn.now(),
    });

  // ── 3. What a human must undo ────────────────────────────────────────────
  // A `succeeded` target took the change. So did a `failed` one whose push
  // job measured its post-conditions and then disarmed its dead-man (the
  // change stands, only the job failed: `failJob`, or the reaper for a dead
  // worker) — it is the job that made this gate fail on JOB_NOT_SUCCEEDED,
  // and leaving it off the list would hide exactly the device that kept it.
  const landed = (await db('rollout_targets as t')
    .join('devices as d', 'd.id', 't.device_id')
    .leftJoin('change_jobs as j', 'j.id', 't.job_id')
    .where('t.rollout_id', rolloutId)
    .where('t.wave_index', '<=', failedWaveIndex)
    .where(function tookTheChange() {
      void this.where('t.status', 'succeeded').orWhere(function changeStands() {
        void this.where('t.status', 'failed')
          .whereNotNull('j.deadman_disarmed_at')
          .whereExists(function postcheckPassed() {
            void this.select(db.raw('1'))
              .from('change_job_steps as s')
              .whereRaw('s.job_id = j.id')
              .whereRaw('s.attempt = j.attempt')
              .where('s.kind', 'postcheck')
              .where('s.status', 'succeeded');
          });
      });
    })
    .orderBy(['t.wave_index', 't.order_rank'])
    .select('t.*', 'd.name as device_name')) as TargetRow[];

  let withBackup = 0;
  for (const t of landed) {
    const backupId = await preflightBackupOf(t.job_id === null ? null : Number(t.job_id));
    if (backupId !== null) withBackup++;
    await db('rollout_targets').where({ id: t.id }).update({
      rollback_backup_id: backupId,
      note: manualRestoreNote(failedWaveIndex, t.job_id === null ? null : Number(t.job_id), backupId),
      updated_at: db.fn.now(),
    });
  }

  // ── 4. Stopped, for a human ──────────────────────────────────────────────
  // `failed` with `failed_wave_index` in the same update (`rollouts_failed_wave_chk`).
  const done = await setStatus(rollout, 'failed', {
    failed_wave_index: failedWaveIndex,
    revision_quarantined_at: flipped > 0 ? quarantinedAt : rollout.revision_quarantined_at,
    current_wave_index: null,
    succeeded_count: await countTargets(rolloutId, ['succeeded']),
    failed_count: await countTargets(rolloutId, ['failed']),
  });

  const message =
    `Wave ${failedWaveIndex + 1} failed its health gate on ${gate.failedDeviceIds.length} ` +
    `device(s). Revision #${rollout.template_revision_id} ${
      flipped > 0 ? 'has been quarantined' : 'was already not published'
    } and the rollout STOPPED: the waves that never ran were skipped. Nothing was undone ` +
    `automatically — ${landed.length} device(s) took the change and are listed « À remettre en ` +
    `arrière » (${withBackup} with their pre-change backup recorded): roll out the previous ` +
    'revision of the template to them to undo it.';
  emitProgress(
    done,
    `wave ${failedWaveIndex + 1} FAILED its health gate — stopped; ${landed.length} device(s) ` +
      'to undo with a rollout of the previous revision',
  );
  emitFinished(done, flipped > 0 || done.revision_quarantined_at !== null);

  return {
    rolloutId,
    status: 'failed',
    waveIndex: failedWaveIndex,
    action: 'gate_failed',
    gate,
    message,
  };
}

/**
 * The pre-change backup a push job took: the job's own `preflight_backup_id`
 * (the binary the dead-man would have loaded), else the binary recorded
 * against it in `device_backups`. Null when the job took none.
 */
async function preflightBackupOf(jobId: number | null): Promise<number | null> {
  if (jobId === null) return null;
  const job = (await db('change_jobs').where({ id: jobId }).first('preflight_backup_id')) as
    | { preflight_backup_id: string | number | null }
    | undefined;
  if (job?.preflight_backup_id !== null && job?.preflight_backup_id !== undefined) {
    return Number(job.preflight_backup_id);
  }
  const backup = (await db('device_backups')
    .where({ taken_before_job_id: jobId, kind: 'binary' })
    .orderBy('id', 'desc')
    .first('id')) as { id: string | number } | undefined;
  return backup ? Number(backup.id) : null;
}

/**
 * The sentence a landed target carries after a failed gate (the rollout page
 * draws « À remettre en arrière » beside it).
 *
 * It names the ONE remedy ObliWAN can carry out: a rollout of
 * the previous revision to that device, which pushes the difference back as a
 * plan, under the guard and the dead-man. The pre-change backup is named as a
 * record and NOT as the remedy: no operation loads a stored backup onto a
 * router (`restore` is refused at every door, backups.routes.ts has no
 * download), and the router's own copy was erased when the push disarmed.
 */
function manualRestoreNote(failedWaveIndex: number, jobId: number | null, backupId: number | null): string {
  return (
    `To undo: wave ${failedWaveIndex + 1} failed its health gate and this device kept the ` +
    'change — nothing was undone automatically. Roll out the previous revision of the template ' +
    'to this device (publish it again first if it was deprecated): the plan pushes the ' +
    'difference back under the guard and the dead-man. ' +
    (backupId !== null
      ? `Its pre-change backup #${backupId}${jobId !== null ? ` (taken before job #${jobId})` : ''} ` +
        'is kept on the server as a record; ObliWAN cannot load it onto the router.'
      : `No pre-change backup is recorded for${jobId !== null ? ` job #${jobId}` : ' it'}; ` +
        'its configuration before the change is in its configuration history.')
  );
}

/**
 * A gate said FAIL on an `os_upgrade` rollout: STOP, undo nothing.
 *
 * There is no revision to quarantine, and restoring a configuration backup
 * would be wrong here twice over (and no restore job exists anyway): it cannot
 * un-install a RouterOS release, and loading one reboots the box again for
 * nothing. A downgrade is not something this rollout
 * does. So the waves that never ran are skipped (their devices untouched), the
 * rollout ends `failed`, and the devices of the failed wave are a human's.
 */
async function stopOsUpgradeRollout(
  rollout: RolloutRow,
  failedWaveIndex: number,
  gate: WaveGateResult,
): Promise<AdvanceReport> {
  const rolloutId = Number(rollout.id);
  logger.error(
    {
      rolloutId,
      waveIndex: failedWaveIndex,
      failedDeviceIds: gate.failedDeviceIds,
      targetVersion: rollout.target_version,
    },
    'OS UPGRADE ROLLOUT GATE FAILED — stopping; nothing is rolled back (a release cannot be restored from a backup)',
  );
  const now = new Date();
  await db('rollout_waves')
    .where({ rollout_id: rolloutId })
    .where('wave_index', '>', failedWaveIndex)
    .update({ status: 'skipped', finished_at: now, updated_at: db.fn.now() });
  await db('rollout_targets')
    .where({ rollout_id: rolloutId })
    .where('wave_index', '>', failedWaveIndex)
    .whereIn('status', ['pending', 'queued'])
    .update({
      status: 'skipped',
      note: `Never ran: wave ${failedWaveIndex + 1} failed its health gate.`,
      updated_at: db.fn.now(),
    });

  const done = await setStatus(rollout, 'failed', {
    failed_wave_index: failedWaveIndex,
    current_wave_index: null,
    succeeded_count: await countTargets(rolloutId, ['succeeded']),
    failed_count: await countTargets(rolloutId, ['failed']),
  });
  const message =
    `Wave ${failedWaveIndex + 1} failed its health gate on ${gate.failedDeviceIds.length} ` +
    `device(s). The RouterOS ${rollout.target_version} upgrade STOPPED: the waves that never ran ` +
    'were skipped and their devices left untouched. Nothing was rolled back — a configuration ' +
    'backup cannot un-install a RouterOS release — so the failed device(s) need a human.';
  emitProgress(done, `wave ${failedWaveIndex + 1} FAILED its health gate — os_upgrade rollout stopped`);
  emitFinished(done, false);
  return {
    rolloutId,
    status: 'failed',
    waveIndex: failedWaveIndex,
    action: 'gate_failed',
    gate,
    message,
  };
}

/**
 * A gate said FAIL on a `management_access` rollout: STOP, undo nothing (the
 * file header says why — no revision to quarantine, and closing api-ssl again
 * by loading a backup would reboot the routers for a change that left SSH
 * untouched). The waves that never ran are skipped and their devices left
 * untouched; the rollout ends `failed`; the devices of the failed wave are a
 * human's. A `legacy_compliance` rollout ends the same way, for the same
 * reason: its corrections only opened services and added an address, and a
 * restore that takes them back reboots the router.
 */
async function stopManagementAccessRollout(
  rollout: RolloutRow,
  failedWaveIndex: number,
  gate: WaveGateResult,
): Promise<AdvanceReport> {
  const rolloutId = Number(rollout.id);
  const compliance = rollout.kind === 'legacy_compliance';
  logger.error(
    { rolloutId, waveIndex: failedWaveIndex, failedDeviceIds: gate.failedDeviceIds, kind: rollout.kind },
    compliance
      ? 'LEGACY COMPLIANCE ROLLOUT GATE FAILED — stopping; nothing is rolled back (a restore would reboot the routers)'
      : 'MANAGEMENT ACCESS ROLLOUT GATE FAILED — stopping; nothing is rolled back (a restore would reboot the routers)',
  );
  const now = new Date();
  await db('rollout_waves')
    .where({ rollout_id: rolloutId })
    .where('wave_index', '>', failedWaveIndex)
    .update({ status: 'skipped', finished_at: now, updated_at: db.fn.now() });
  await db('rollout_targets')
    .where({ rollout_id: rolloutId })
    .where('wave_index', '>', failedWaveIndex)
    .whereIn('status', ['pending', 'queued'])
    .update({
      status: 'skipped',
      note: `Never ran: wave ${failedWaveIndex + 1} failed its health gate.`,
      updated_at: db.fn.now(),
    });

  const done = await setStatus(rollout, 'failed', {
    failed_wave_index: failedWaveIndex,
    current_wave_index: null,
    succeeded_count: await countTargets(rolloutId, ['succeeded']),
    failed_count: await countTargets(rolloutId, ['failed']),
  });
  const message = compliance
    ? `Wave ${failedWaveIndex + 1} failed its health gate on ${gate.failedDeviceIds.length} ` +
      'device(s). The template corrections STOPPED: the waves that never ran were skipped and ' +
      'their devices left untouched. Nothing was rolled back — taking the corrections back through a ' +
      'restore would reboot the routers — so the failed device(s) need a human.'
    : `Wave ${failedWaveIndex + 1} failed its health gate on ${gate.failedDeviceIds.length} ` +
      'device(s). Opening the management API STOPPED: the waves that never ran were skipped and ' +
      'their devices left untouched. Nothing was rolled back — closing api-ssl through a restore ' +
      'would reboot the routers — so the failed device(s) need a human.';
  emitProgress(done, `wave ${failedWaveIndex + 1} FAILED its health gate — ${rollout.kind} rollout stopped`);
  emitFinished(done, false);
  return {
    rolloutId,
    status: 'failed',
    waveIndex: failedWaveIndex,
    action: 'gate_failed',
    gate,
    message,
  };
}

/**
 * Watch the restore jobs of a rollout that entered `rolling_back` BEFORE the
 * failure path stopped queueing them (`stopPushRollout`). Nothing enters that
 * state any more; this only drains the ones already there. Their `restore`
 * jobs are failed at claim (`UNIMPLEMENTED_WRITE_KINDS`), before anything is
 * dialled, so each device ends `failed` with its manual-restore note and the
 * rollout terminates `failed`. A job already past claim before the fix ends
 * however it ends; the loop below waits for it either way.
 */
async function advanceRollback(rollout: RolloutRow): Promise<AdvanceReport> {
  const rolloutId = Number(rollout.id);
  const targets = (await db('rollout_targets')
    .where({ rollout_id: rolloutId })
    .whereNotNull('rollback_job_id')
    .select('*')) as TargetRow[];

  const jobIds = targets.map((t) => Number(t.rollback_job_id));
  const jobs = jobIds.length
    ? ((await db('change_jobs').whereIn('id', jobIds).select('id', 'status')) as Array<{
        id: number;
        status: string;
      }>)
    : [];
  const jobById = new Map(jobs.map((j) => [Number(j.id), j.status]));

  let pending = 0;
  let restored = 0;
  let stuck = 0;
  for (const t of targets) {
    const status = jobById.get(Number(t.rollback_job_id));
    if (!status || !JOB_TERMINAL.includes(status)) {
      pending++;
      continue;
    }
    if (status === 'succeeded' || status === 'rolled_back') {
      restored++;
      if (t.status !== 'rolled_back') {
        await db('rollout_targets').where({ id: t.id }).update({
          status: 'rolled_back',
          updated_at: db.fn.now(),
        });
      }
    } else {
      stuck++;
      if (t.status !== 'failed') {
        await db('rollout_targets').where({ id: t.id }).update({
          status: 'failed',
          note: `The rollback job ended '${status}'. This device is NOT back on its pre-change ` +
            'configuration and needs a human. ' +
            manualRestoreNote(
              rollout.failed_wave_index === null ? Number(t.wave_index) : Number(rollout.failed_wave_index),
              t.job_id === null ? null : Number(t.job_id),
              t.rollback_backup_id === null ? null : Number(t.rollback_backup_id),
            ),
          updated_at: db.fn.now(),
        });
      }
    }
  }

  if (pending > 0) {
    return {
      rolloutId,
      status: 'rolling_back',
      waveIndex: rollout.current_wave_index,
      action: 'rollback_pending',
      gate: null,
      message: `${pending} restore job(s) still in flight.`,
    };
  }

  // A wave reads « Restaurée » only when it WAS: every restore succeeded.
  // With one stuck, nothing is relabelled — the failed wave stays `failed`
  // (the rollout page dates the devices to undo from it) and the applied ones
  // stay `passed`, beside a banner saying their devices kept the change.
  if (stuck === 0) {
    await db('rollout_waves')
      .where({ rollout_id: rolloutId })
      .whereIn('status', ['passed', 'failed'])
      .update({ status: 'rolled_back', updated_at: db.fn.now() });
  }

  const finalStatus: RolloutStatus = stuck > 0 ? 'failed' : 'rolled_back';
  const done = await setStatus(rollout, finalStatus, {
    rolled_back_count: restored,
    failed_count: await countTargets(rolloutId, ['failed']),
    succeeded_count: await countTargets(rolloutId, ['succeeded']),
    current_wave_index: null,
  });
  emitProgress(
    done,
    stuck > 0
      ? `${stuck} device(s) could NOT be restored — this rollout needs a human`
      : `${restored} device(s) restored to their pre-change configuration`,
  );
  emitFinished(done, done.revision_quarantined_at !== null);

  return {
    rolloutId,
    status: finalStatus,
    waveIndex: null,
    action: 'rolled_back',
    gate: null,
    message:
      stuck > 0
        ? `${restored} device(s) restored, ${stuck} could NOT be. A rolled-back rollout with a ` +
          'device left changed is not a rolled-back rollout, so this one is marked failed.'
        : `${restored} device(s) restored to their pre-change configuration.`,
  };
}

// ============================================================================
// Operator gestures
// ============================================================================

export async function pauseRollout(
  tenantId: number,
  rolloutId: number,
  reason: string | null,
): Promise<RolloutRow> {
  const rollout = await getRollout(tenantId, rolloutId);
  if (!rollout) throw new RolloutRefusedError('not_found', `Rollout ${rolloutId} not found`);
  if (rollout.status !== 'running') {
    throw new RolloutRefusedError(
      'not_running',
      `Rollout ${rolloutId} is '${rollout.status}'; only a running rollout can be paused.`,
    );
  }
  const paused = await setStatus(rollout, 'paused', {
    pause_reason: reason ?? 'Paused by an operator.',
  });
  logger.warn({ rolloutId, tenantId }, 'rollout PAUSED');
  emitProgress(paused, 'paused by an operator');
  return paused;
}

/**
 * Resume a paused rollout.
 *
 * A pause never stops a job that is already in flight — the queue owns those,
 * and a button that claimed to stop a change already going onto a router would
 * lie at the exact moment somebody is desperate enough to press it twice
 * (`changes.controller`, `abort`).
 *
 * ┌─ TWO PAUSES, TWO RESUMES, AND CONFLATING THEM SKIPS A HEALTH GATE ────────┐
 * │ GATE PAUSE    `advanceRollout` measured the wave, the gate came back      │
 * │               INDETERMINATE, and the rollout stopped ON that verdict. The │
 * │               wave row is `gating` with `gate_verdict='INDETERMINATE'`.   │
 * │               Resuming is a human ACCEPTING a verdict that was never a    │
 * │               PASS: the wave is marked passed and the NEXT wave starts.   │
 * │                                                                          │
 * │ MANUAL PAUSE  an operator pressed pause, possibly while the wave's jobs   │
 * │               were still on the wire. The wave has NOT been measured.     │
 * │               Resuming means "carry on where you were": `running`, SAME   │
 * │               `current_wave_index`, and `advanceRollout` picks the wave   │
 * │               up at reconciliation and takes it through its gate.         │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * Before this distinction existed, both resumes incremented
 * `current_wave_index`. Pause + resume during wave 1 therefore left wave 1
 * un-gated and pointed the rollout at a wave whose jobs had never been queued;
 * every target of it was `pending` with `job_id IS NULL`, the reconciliation
 * loop skipped them all, `stillRunning` was 0, and the settle window opened on
 * a wave that had done nothing. Repeating it walked the rollout to
 * `succeeded` with one device of forty touched. `1 -> 5% -> 25% -> rest, with a
 * MEASURED gate between each step` is the rollout's whole promise; two legitimate HTTP
 * calls must not be able to step over it.
 */
export async function resumeRollout(
  tenantId: number,
  rolloutId: number,
  userId: number | null,
): Promise<RolloutRow> {
  const rollout = await getRollout(tenantId, rolloutId);
  if (!rollout) throw new RolloutRefusedError('not_found', `Rollout ${rolloutId} not found`);
  if (rollout.status !== 'paused') {
    throw new RolloutRefusedError(
      'not_paused',
      `Rollout ${rolloutId} is '${rollout.status}'; only a paused rollout can be resumed.`,
    );
  }
  const killSwitch = await readKillSwitch(tenantId);
  if (killSwitch.blocked) throw new KillSwitchEngagedError(killSwitch);

  const waveIndex = rollout.current_wave_index ?? 0;
  const wave = (await db('rollout_waves')
    .where({ rollout_id: rolloutId, wave_index: waveIndex })
    .first('*')) as WaveRow | undefined;

  // ── MANUAL PAUSE ─────────────────────────────────────────────────────────
  // The current wave has not produced a verdict, so there is nothing to accept
  // and nothing to step over. Put the rollout back to `running` on the SAME
  // wave and let the tick loop do its job.
  if (!wave || wave.status !== 'gating' || wave.gate_verdict !== 'INDETERMINATE') {
    const resumed = await setStatus(rollout, 'running', {
      pause_reason: null,
      started_by: rollout.started_by ?? userId,
    });
    logger.warn(
      { rolloutId, tenantId, userId, waveIndex, waveStatus: wave?.status ?? null },
      'rollout RESUMED on the same wave — the wave has not been gated yet',
    );
    emitProgress(
      resumed,
      `resumed — wave ${waveIndex + 1}/${resumed.wave_count} continues, its health gate ` +
        'has not run yet',
    );
    return resumed;
  }

  // ── GATE PAUSE ───────────────────────────────────────────────────────────
  // A rollout paused on an INDETERMINATE gate is resumed by a human who has
  // LOOKED. Recording the gate verdict as accepted is what makes the resume an
  // act rather than a retry: the wave moves on with a verdict that was never
  // a PASS, and the trace must say so.
  await db('rollout_waves')
    .where({ rollout_id: rolloutId, wave_index: waveIndex, status: 'gating' })
    .update({ status: 'passed', finished_at: new Date(), updated_at: db.fn.now() });

  const nextIndex = waveIndex + 1;
  if (nextIndex >= Number(rollout.wave_count)) {
    const done = await setStatus(rollout, 'succeeded', {
      current_wave_index: null,
      pause_reason: null,
      succeeded_count: await countTargets(rolloutId, ['succeeded']),
    });
    emitProgress(done, 'resumed on the last wave — finished');
    emitFinished(done, false);
    return done;
  }

  const resumed = await setStatus(rollout, 'running', {
    current_wave_index: nextIndex,
    pause_reason: null,
    started_by: rollout.started_by ?? userId,
  });
  logger.warn(
    { rolloutId, tenantId, userId, waveIndex: nextIndex },
    'rollout RESUMED past a gate that did not PASS — a human accepted an INDETERMINATE verdict',
  );
  await startWave(resumed, nextIndex);
  emitProgress(resumed, `resumed — wave ${nextIndex + 1}/${resumed.wave_count} starting`);
  return resumed;
}

export async function abortRollout(
  tenantId: number,
  rolloutId: number,
  userId: number | null,
  reason: string | null,
): Promise<RolloutRow> {
  const rollout = await getRollout(tenantId, rolloutId);
  if (!rollout) throw new RolloutRefusedError('not_found', `Rollout ${rolloutId} not found`);
  if (isTerminalRolloutStatus(rollout.status)) {
    throw new RolloutRefusedError(
      'already_finished',
      `Rollout ${rolloutId} is already '${rollout.status}'.`,
    );
  }

  // Jobs that have not been claimed yet CAN be cancelled; anything past
  // `applying` cannot, and `abortJob` refuses it. We ask, and we record what
  // it answered — we never pretend a running apply was stopped.
  const targets = await listTargets(rolloutId);
  let cancelledJobs = 0;
  // A rollout left in `rolling_back` by the old failure path still names its
  // `restore` jobs on `rollback_job_id`; the queue fails them at claim anyway,
  // and cancelling the ones still queued is cheaper than waiting for that.
  const jobIds = targets.flatMap((t) => [t.job_id, t.rollback_job_id]).filter((id): id is number => id !== null);
  for (const id of jobIds) {
    try {
      await abortJob(tenantId, Number(id), userId, reason ?? 'rollout aborted');
      cancelledJobs++;
    } catch {
      // Past the write frontier. The dead-man owns it now, not this button.
    }
  }
  await db('rollout_targets')
    .where({ rollout_id: rolloutId })
    .whereIn('status', ['pending', 'queued', 'running'])
    .update({ status: 'cancelled', updated_at: db.fn.now() });
  await db('rollout_waves')
    .where({ rollout_id: rolloutId })
    .whereIn('status', ['pending', 'running', 'gating'])
    .update({ status: 'skipped', finished_at: new Date(), updated_at: db.fn.now() });

  const aborted = await setStatus(rollout, 'aborted', {
    abort_reason:
      (reason ?? 'Aborted by an operator.') +
      ` ${cancelledJobs} queued job(s) were cancelled. Devices already changed were NOT rolled ` +
      'back by this gesture, and nothing restores them automatically — restore them by hand ' +
      'from their pre-change backup; use the kill switch to stop the fleet.',
    current_wave_index: null,
  });
  logger.warn({ rolloutId, tenantId, userId, cancelledJobs }, 'rollout ABORTED');
  emitProgress(aborted, 'aborted by an operator');
  emitFinished(aborted, aborted.revision_quarantined_at !== null);
  return aborted;
}

// ============================================================================
// Socket progress — keyed by rolloutId
// ============================================================================
//
// Emitted to the TENANT room, with `rolloutId` in every payload.
// `socketRooms.rollout(id)` exists in the shared contract and
// `CLIENT_EVENTS.ROLLOUT_SUBSCRIBE` is declared, but nothing joins that room
// yet: the handler lives in `socket.ts`, which this milestone may not touch.
// Emitting into an empty room instead of the tenant room would have looked
// tidier and delivered nothing to anybody.
//
// LEAD: three lines in `socket.ts` (mirror the DEVICE_SUBSCRIBE block, check
// the rollout's tenant, then `socket.join(socketRooms.rollout(id))`) plus an
// `emitToRollout` in `fleet/fleetEvents.ts` complete this.

function emitProgress(r: RolloutRow, message: string): void {
  emitToTenantAudience(Number(r.tenant_id), SOCKET_EVENTS.ROLLOUT_PROGRESS, {
    rolloutId: Number(r.id),
    tenantId: Number(r.tenant_id),
    status: r.status,
    currentWaveIndex: r.current_wave_index === null ? null : Number(r.current_wave_index),
    waveCount: Number(r.wave_count),
    deviceCount: Number(r.device_count),
    succeededCount: Number(r.succeeded_count),
    failedCount: Number(r.failed_count),
    rolledBackCount: Number(r.rolled_back_count),
    message,
  }, { rolloutId: Number(r.id) });
}

function emitWave(r: RolloutRow, w: WaveRow): void {
  emitToTenantAudience(Number(r.tenant_id), SOCKET_EVENTS.ROLLOUT_WAVE_CHANGED, {
    rolloutId: Number(r.id),
    tenantId: Number(r.tenant_id),
    waveIndex: Number(w.wave_index),
    label: w.label,
    status: w.status,
    targetCount: Number(w.target_count),
    gateVerdict: w.gate_verdict,
    gateReasons: asArray<HealthGateReason>(w.gate_reasons),
  }, { rolloutId: Number(r.id) });
}

function emitFinished(r: RolloutRow, revisionQuarantined: boolean): void {
  emitToTenantAudience(Number(r.tenant_id), SOCKET_EVENTS.ROLLOUT_FINISHED, {
    rolloutId: Number(r.id),
    tenantId: Number(r.tenant_id),
    status: r.status,
    deviceCount: Number(r.device_count),
    succeededCount: Number(r.succeeded_count),
    rolledBackCount: Number(r.rolled_back_count),
    failedWaveIndex: r.failed_wave_index === null ? null : Number(r.failed_wave_index),
    revisionQuarantined,
    message: r.abort_reason ?? r.pause_reason ?? `Rollout ${r.status}.`,
  }, { rolloutId: Number(r.id) });
}

// ============================================================================
// The runtime — leader-gated, exactly like every other poller
// ============================================================================

/** How often the driver looks at the rollouts that still have work to do. */
export const ROLLOUT_TICK_MS = Number(process.env.OBLIWAN_ROLLOUT_TICK_MS) || 10_000;

let timer: NodeJS.Timeout | null = null;
let ticking = false;

/**
 * One pass over every rollout of every tenant that is not finished.
 *
 * `leaderElection.isLeader()` gates it: two replicas advancing
 * the same rollout would start the same wave twice, and the second start would
 * queue a second job against a device the first one already holds — which
 * `change_jobs_one_in_flight_uq` would refuse, loudly, on a fleet, at night.
 * Exported without the gate as well (`advanceRollout`) so a controller and a
 * test can step one rollout deliberately.
 */
export async function tickRollouts(): Promise<AdvanceReport[]> {
  if (!leaderElection.isLeader()) return [];
  const active = (await db('rollouts')
    .whereIn('status', ['running', 'rolling_back'])
    .select('id', 'tenant_id')) as Array<{ id: number; tenant_id: number }>;

  const reports: AdvanceReport[] = [];
  for (const r of active) {
    try {
      reports.push(await advanceRollout(Number(r.tenant_id), Number(r.id)));
    } catch (err) {
      logger.error({ err, rolloutId: Number(r.id) }, 'rollout tick failed');
    }
  }
  return reports;
}

/**
 * Arm the driver. LEAD: call this from `index.ts` next to
 * `startChangeWorker(runJob)` — without it every rollout stops after its first
 * wave's jobs finish, which is an old lesson (a subsystem that compiles, whose
 * tables exist, whose routes answer, and that nothing ever runs).
 */
export function startRolloutRuntime(): void {
  if (timer) return;
  timer = setInterval(() => {
    if (ticking) return;
    ticking = true;
    tickRollouts()
      .catch((err) => logger.error({ err }, 'rollout runtime tick failed'))
      .finally(() => {
        ticking = false;
      });
  }, ROLLOUT_TICK_MS);
  timer.unref();
  logger.info({ intervalMs: ROLLOUT_TICK_MS }, 'rollout runtime armed (leader-gated)');
}

export async function stopRolloutRuntime(): Promise<void> {
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
  // Let an in-flight tick finish: it may be halfway through queueing a wave,
  // and a wave half queued is a set of devices nobody is watching.
  for (let i = 0; ticking && i < 100; i++) {
    await new Promise((r) => setTimeout(r, 50));
  }
}

// ============================================================================
// The os_upgrade launcher — what the HTTP layer reaches through its port
// ============================================================================

/**
 * The two writes of the fleet OS upgrade screen, shaped for the
 * `OsUpgradeLauncher` port of controllers/osUpgrade.controller.ts (which the
 * composition root wires with `setOsUpgradeLauncher(osUpgradeLauncher)`).
 * Refusals leave as the classes that HTTP layer already maps:
 * `ChangeRefusedError`, `RolloutRefusedError`, `DeviceBusyError`,
 * `KillSwitchEngagedError`.
 */
export const osUpgradeLauncher = {
  /** ONE device: one os_upgrade job. */
  async enqueueOne(input: {
    tenantId: number;
    deviceId: number;
    version: string;
    requestedBy: number | null;
    override: { reason: string; userId: number | null };
    confirmDegraded: { userId: number | null };
  }): Promise<{ jobId: number }> {
    try {
      const out = await enqueueOsUpgradeJob({
        tenantId: input.tenantId,
        deviceId: input.deviceId,
        targetVersion: input.version,
        requestedBy: input.requestedBy,
        override: input.override,
        confirmDegraded: input.confirmDegraded,
      });
      return { jobId: out.jobId };
    } catch (err) {
      throw err instanceof OsUpgradeError ? new ChangeRefusedError(err.kind, err.message) : err;
    }
  },

  /**
   * SEVERAL devices: compose AND launch an os_upgrade rollout. Refused, with
   * nothing written, when the composition would not be the one the operator
   * was shown: a device the composition refuses, or a different wave ladder.
   */
  async launchRollout(input: {
    tenantId: number;
    name: string;
    deviceIds: number[];
    version: string;
    waves: PlannedWave[];
    requestedBy: number | null;
    override: { reason: string; userId: number | null };
    confirmDegraded: { userId: number | null };
  }): Promise<{ rolloutId: number }> {
    const killSwitch = await readKillSwitch(input.tenantId);
    if (killSwitch.blocked) throw new KillSwitchEngagedError(killSwitch);
    const compose: ComposeInput = {
      tenantId: input.tenantId,
      name: input.name,
      deviceIds: input.deviceIds,
      kind: 'os_upgrade',
      targetVersion: input.version,
      createdBy: input.requestedBy,
      override: input.override,
      confirmDegraded: input.confirmDegraded,
    };
    const preview = await previewRollout(compose);
    if (preview.failures.length > 0) {
      throw new RolloutRefusedError(
        'devices_refused',
        `${preview.failures.length} of ${input.deviceIds.length} selected device(s) cannot get an ` +
          'os_upgrade job. Nothing was queued.',
        { failures: preview.failures },
      );
    }
    const shown = input.waves.map((w) => w.size);
    const planned = preview.waves.map((w) => w.size);
    if (shown.length > 0 && JSON.stringify(shown) !== JSON.stringify(planned)) {
      throw new RolloutRefusedError(
        'waves_mismatch',
        `The rollout runs the product's wave ladder (${planned.join(' / ')} device(s)); the ladder ` +
          `shown was ${shown.join(' / ')}. Nothing was queued.`,
        { planned: preview.waves, shown: input.waves },
      );
    }
    const composed = await composeRollout(compose);
    const launched = await launchRollout(input.tenantId, Number(composed.rolloutId), input.requestedBy);
    return { rolloutId: Number(launched.id) };
  },
};

// ============================================================================
// The planless SSH launchers — what controllers/managementAccess and
// controllers/legacyCompliance reach
// ============================================================================

/**
 * The two gestures of the New Rollout panel for the kinds `management_access`
 * and `legacy_compliance`. The generic `/rollouts` compose route names a
 * template revision; these kinds name none, so each has its own door — the
 * same composition (`build`), the same launch, the same waves and gate.
 * Refusals leave as `RolloutRefusedError` and `KillSwitchEngagedError`; a
 * device the queue refuses when its wave starts is recorded on its target
 * (`queueTarget`), never thrown here.
 */
function planlessSshLauncher(kind: PlanlessSshRolloutKind) {
  return {
    /**
     * The impact screen, with nothing written: the server's own composition.
     * When NO device can get the job, the composition is refused by `build`;
     * this answers the same shape with no target and every refusal listed, so
     * the screen can say why instead of showing a bare error.
     */
    async preview(input: {
      tenantId: number;
      name: string;
      deviceIds: number[];
      requestedBy: number | null;
      /** `wan_link` only: the mode every site switches to. */
      wanTargetMode?: WanTargetMode | null;
    }): Promise<RolloutComposition> {
      const compose: ComposeInput = {
        tenantId: input.tenantId,
        name: input.name,
        deviceIds: input.deviceIds,
        kind,
        createdBy: input.requestedBy,
        ...(kind === 'wan_link' ? { wanTargetMode: input.wanTargetMode ?? null } : {}),
      };
      try {
        return await previewRollout(compose);
      } catch (err) {
        if (err instanceof RolloutRefusedError && err.kind === 'nothing_compiles') {
          const failures = ((err.detail as { failures?: RolloutComposition['failures'] } | null)?.failures ?? []);
          const killSwitch = await readKillSwitch(input.tenantId);
          return {
            rolloutId: null,
            name: input.name,
            kind,
            templateRevisionId: null,
            targetVersion: null,
            ...(kind === 'wan_link' ? { wanTargetMode: input.wanTargetMode ?? null } : {}),
            waves: [],
            targets: [],
            failures,
            blastRadius: aggregateBlastRadius([]),
            summaryLine: err.message,
            degradedCount: 0,
            guardNotClearedCount: 0,
            requiresOverride: false,
            requiresDegradedConfirmation: false,
            killSwitch: { blocked: killSwitch.blocked, reason: killSwitch.reason },
          };
        }
        throw err;
      }
    },

    /**
     * Compose AND launch. Refused, with nothing written, when the composition
     * would not be the one the operator was shown: a device the composition
     * refuses, or a different wave ladder.
     */
    async launchRollout(input: {
      tenantId: number;
      name: string;
      deviceIds: number[];
      waves: Array<{ size: number }>;
      requestedBy: number | null;
      confirmDegraded: { userId: number | null } | null;
      /** `wan_link` only: the mode every site switches to. */
      wanTargetMode?: WanTargetMode | null;
    }): Promise<{ rolloutId: number }> {
      const killSwitch = await readKillSwitch(input.tenantId);
      if (killSwitch.blocked) throw new KillSwitchEngagedError(killSwitch);
      const compose: ComposeInput = {
        tenantId: input.tenantId,
        name: input.name,
        deviceIds: input.deviceIds,
        kind,
        createdBy: input.requestedBy,
        confirmDegraded: input.confirmDegraded,
        ...(kind === 'wan_link' ? { wanTargetMode: input.wanTargetMode ?? null } : {}),
      };
      const preview = await previewRollout(compose);
      if (preview.failures.length > 0) {
        throw new RolloutRefusedError(
          'devices_refused',
          `${preview.failures.length} of ${input.deviceIds.length} selected device(s) cannot get a ` +
            `${kind} job. Nothing was queued.`,
          { failures: preview.failures },
        );
      }
      const shown = input.waves.map((w) => w.size);
      const planned = preview.waves.map((w) => w.size);
      if (JSON.stringify(shown) !== JSON.stringify(planned)) {
        throw new RolloutRefusedError(
          'waves_mismatch',
          `The rollout runs the product's wave ladder (${planned.join(' / ')} device(s)); the ladder ` +
            `shown was ${shown.join(' / ') || 'none'}. Nothing was queued.`,
          { planned: preview.waves, shown: input.waves },
        );
      }
      const composed = await composeRollout(compose);
      const launched = await launchRollout(input.tenantId, Number(composed.rolloutId), input.requestedBy);
      return { rolloutId: Number(launched.id) };
    },
  };
}

export const managementAccessLauncher = planlessSshLauncher('management_access');
export const legacyComplianceLauncher = planlessSshLauncher('legacy_compliance');
export const wanLinkLauncher = planlessSshLauncher('wan_link');

/** A wan_link device's gate baseline without the interfaces its job retired
 *  on purpose (shared `WanLinkPlan.retiredInterfaces`); unchanged otherwise. */
export function withoutRetiredInterfaces(baseline: HealthBaseline, retired: unknown): HealthBaseline {
  if (!Array.isArray(retired) || retired.length === 0) return baseline;
  return { ...baseline, interfaces: baseline.interfaces.filter((i) => !retired.includes(i.ifName)) };
}

export const rolloutService = {
  previewRollout,
  composeRollout,
  listRollouts,
  getRollout,
  listWaves,
  listTargets,
  launchRollout,
  advanceRollout,
  pauseRollout,
  resumeRollout,
  abortRollout,
  tickRollouts,
  startRolloutRuntime,
  stopRolloutRuntime,
  toRolloutSummary,
  safetyNetLevelOf,
};
