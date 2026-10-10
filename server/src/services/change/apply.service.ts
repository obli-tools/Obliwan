// ============================================================================
// ObliWAN — the safe write, orchestrated (secrets and safety-net rules)
// ============================================================================
//
// This file is the ONLY thing in the product that decides a device may be
// written to. It does not itself send a single byte: the transport work belongs
// to `safeApply` / `backup` (a separate module) and is reached through the
// `ChangeExecutor` contract at the bottom of this file. What lives here is the
// sequence of refusals that must all be passed first, and the trace they leave.
//
// ┌─ THE ORDER IS THE SPECIFICATION ──────────────────────────────────────────┐
// │  0. kill switch                 — read, fail-closed                       │
// │  1. bind_assert            — a NEW socket, identity re-proved              │
// │  2. plan freshness         — `base_state_hash` still matches              │
// │  3. Management-Path Guard  — re-run, on the latest STORED snapshot        │
// │  4. safety net           — ARMED / ARMED_BY_PEER / DEGRADED               │
// │  5. preflight backup       — a CHECK constraint, not a habit              │
// │  6. arm the dead-man            — the router repairs itself without us    │
// │  7. KILL SWITCH AGAIN           — the last statement before the write     │
// │  8. apply                       — the only line that changes a router     │
// │  9. reconnect + verify          — on a NEW socket, never the one that      │
// │                                   carried the change                      │
// │ 10. soak                        — live, watched, dead-man still armed     │
// │ 11. disarm                      — a job is not `succeeded` while a router │
// │                                   still carries a scheduler that reverts  │
// │ 12. apply_outcomes       — success AND failure. The corpus.               │
// └───────────────────────────────────────────────────────────────────────────┘
//
// STEPS 3 AND 7 ARE RE-DONE ON PURPOSE. The guard ran at enqueue time, possibly
// hours ago and certainly before an approval; the kill switch was read when the
// job was created, which is precisely NOT when somebody engages it. A check
// performed once, early, is a check that answers a question nobody is asking
// any more.
//
// WHY A NON-ACCEPT VERDICT NEEDS A SIGNATURE AND NOT A FLAG: `INDETERMINATE` is
// not `ACCEPT`. Both non-accept verdicts demand `override_reason` +
// `overridden_by` + `overridden_at`, and that demand is a CHECK constraint in
// migration 009 — so the destructive acceptance test of the apply path CAN force a
// `chain=input drop` past the guard, but not without naming a human in the
// database. That row is the line somebody reads after the incident.
//
// SECRETS: nothing in this file ever sees a complete rendered config.
// `change_plans.ops` is the redacted plan; the full version exists in memory
// only, inside the executor, on the vault -> equipment path. Every string that
// reaches `change_job_steps` or `command_audit` from here is already masked.

import crypto from 'crypto';
import type { Knex } from 'knex';
import {
  ApplyPlan,
  SOCKET_EVENTS,
  guardAllowsApply,
  isWriteJobKind,
  mgmtPathVerdictOf,
  type ChangeJobKind,
  type GuardVerdict,
  type SafetyLevel,
  deadmanReadiness,
  type DeviceModeReading,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { renderPlanOpsForRouterOs } from '../drivers/mikrotik/render';
import type { PlanOp } from '@obliwan/shared';
import { emitToDevice } from '../fleet/fleetEvents';
import { emitToTenantAudience } from '../fleet/scopedEmit';
import { assertTargetBinding, BindingAssertionError } from '../fleet/deviceBinding.service';
import {
  SESSION_GATED_JOB_KINDS,
  duplicateSessionsRefusalMessage,
  sessionGateForDevice,
} from '../fleet/pppDuplicates.service';
import { PPP_DUPLICATE_REFUSAL } from '@obliwan/shared';
import { latestDocument, findSecondUplink } from '../config/snapshot.service';
import {
  assertPlanFresh,
  checkPlanFreshness,
  PlanExpiredError,
  StalePlanError,
} from '../plan/planner.service';
import { buildMgmtPathFacts } from '../plan/riskScoring';
import { guardPlan, type MgmtGuardResult } from '../plan/mgmtPathGuard';
import { checkPlanUplinks, uplinkRefusalMessage, UPLINK_REFUSAL_KIND } from '../plan/uplinkGuard';
import { learningBlocksJob } from '@obliwan/shared';
import { LEARNING_REFUSAL_KIND, learningRefusalMessage, learningStateOf } from '../learning/guard';
import { assertWritable, KillSwitchEngagedError, readKillSwitch } from './killSwitch.service';
import {
  DeviceBusyError,
  GENERIC_WRITE_KINDS,
  LEASE_TTL_MS,
  LeaseLostError,
  WORKER_ID,
  assertLease,
  finishStep,
  getJobRow,
  isChangeWorkerStopping,
  renewLease,
  setReapedNetReleaser,
  skipStep,
  startStep,
  transitionJob,
  type ChangeJobRow,
  type ReapedNetJob,
  type StepHandle,
} from './jobQueue.service';
import { markNothingTransmitted, wasNothingTransmitted, type NetRelease } from './applyFrontier';
import { liveAlertService } from '../liveAlert.service';
import { auditedCommand, recordCommandIntent } from '../audit.service';
import {
  CONCENTRATOR_SECRET_NO_BACKUP,
  CONCENTRATOR_SECRET_NO_DEADMAN,
  ConcentratorSecretError,
  applyConcentratorSecret,
  concentratorSecretGuard,
  settleConcentratorSecret,
  verifyConcentratorSecret,
} from './concentratorSecret.service';
import {
  OS_UPGRADE_NO_APPLY_OUTCOME,
  OS_UPGRADE_NO_DEADMAN,
  OsUpgradeError,
  OsUpgradeRun,
  osUpgradeGuard,
  osUpgradeNoopReason,
  settleOsUpgrade,
} from '../firmware/osUpgrade.service';
import {
  CONCENTRATOR_LINK_NO_APPLY_OUTCOME,
  CONCENTRATOR_LINK_NO_DEADMAN,
  ConcentratorLinkError,
  ConcentratorLinkRun,
  concentratorLinkGuard,
} from '../concentratorLink/link.service';
import {
  MANAGEMENT_ACCESS_NO_APPLY_OUTCOME,
  MANAGEMENT_ACCESS_NO_DEADMAN,
  ManagementAccessError,
  ManagementAccessRun,
  assertMikrotikBindingOverSsh,
  managementAccessGuard,
  managementApiChannelReasons,
  settleManagementAccess,
  withApiChannelReasons,
} from './managementAccess.service';
import {
  LTE_APN_NO_APPLY_OUTCOME,
  LTE_APN_NO_DEADMAN,
  LteApnError,
  LteApnRun,
  lteApnGuard,
  settleLteApn,
} from './lteApn.service';
import {
  INFRA_ACCOUNT_NO_APPLY_OUTCOME,
  INFRA_ACCOUNT_NO_BACKUP,
  INFRA_ACCOUNT_NO_DEADMAN,
  InfraAccountJobError,
  infraAccountGuard,
  runInfraAccountApply,
  runInfraAccountVerify,
  settleInfraAccount,
} from '../infraConcentrator/job.service';
import {
  LEGACY_COMPLIANCE_NO_APPLY_OUTCOME,
  LEGACY_COMPLIANCE_NO_DEADMAN,
  LegacyComplianceError,
  LegacyComplianceRun,
  legacyComplianceGuard,
  settleLegacyCompliance,
} from './legacyCompliance.service';
import {
  SITE_RENAME_NO_APPLY_OUTCOME,
  SITE_RENAME_NO_DEADMAN,
  SiteRenameError,
  SiteRenameRun,
  settleSiteRename,
  siteRenameGuard,
} from './siteRename.service';
import { applyWindowProblem, resolveApplyWindow, type ApplyWindow } from './applyTimings';
import { settleFollowupsOf } from './jobFollowup.service';
import {
  WAN_LINK_NO_APPLY_OUTCOME,
  WAN_LINK_NO_DEADMAN,
  WanLinkError,
  WanLinkRun,
  settleWanLink,
  wanLinkGuard,
} from './wanLink.service';

// ============================================================================
// Constants
// ============================================================================

// How long a change is watched, live, before the dead-man is removed, is the
// `apply_soak_seconds` setting, resolved per device together with the dead-man
// window when the job reaches step 5 (`applyTimings.ts`). The dead-man is
// ARMED throughout the soak. That is the whole value of it: if the change is
// going to cut the tunnel, it cuts it now, and the router puts itself back
// without anybody dialling in.

/**
 * RECONNECTING AFTER A WRITE IS NOT A SINGLE ATTEMPT, AND THE FIRST FAILURE IS
 * NOT AN ANSWER.
 *
 * The write that just landed is, very often, precisely the write that makes the
 * box stop answering for a moment: touching `/ip/service` or an `input` chain
 * rule makes RouterOS close and re-open its API listener, typically for one to
 * three seconds, longer on a loaded router. Dialling immediately and failing
 * the job on the first `ECONNREFUSED` produced the worst outcome this milestone
 * has: a change that WORKED recorded as `failed`, the dead-man left armed
 * because `failJob` concluded, and the router quietly undoing a good change ten
 * minutes later — with nobody having decided that.
 *
 * These mirror `SAFE_APPLY_DEFAULTS.reconnect*` in `safeApply.service.ts`,
 * which `changeExecutor.verify()` already honours at the `postcheck` step.
 * They are duplicated rather than imported because the safe-apply module is resolved
 * DYNAMICALLY (see `resolveExecutor`) and a static import here would make the
 * whole server fail to compile over a file this layer deliberately does not
 * depend on. The numbers are timings, not a rule: if they drift apart, the
 * worst case is one step waiting longer than the other, and
 * `assertTimingsCoherent` still holds the dead-man window against the sum.
 */
export const RECONNECT_DELAY_MS = Number(process.env.OBLIWAN_RECONNECT_DELAY_MS ?? 5_000);
export const RECONNECT_ATTEMPTS = Math.max(
  1,
  Number(process.env.OBLIWAN_RECONNECT_ATTEMPTS ?? 6),
);
export const RECONNECT_INTERVAL_MS = Number(process.env.OBLIWAN_RECONNECT_INTERVAL_MS ?? 10_000);

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, Math.max(0, ms)));
}

/** `change_jobs.base_state_hash` is NOT NULL with a hex-64 CHECK, and a backup
 *  job has no plan to take a hash from. A device with no snapshot at all gets
 *  this sentinel, which is a legal hash and matches nothing. */
const NO_BASE_STATE = '0'.repeat(64);

/** Verdict severity, for "did the world get worse since the human signed?". */
const VERDICT_RANK: Record<GuardVerdict, number> = { ACCEPT: 0, INDETERMINATE: 1, REJECT: 2 };

/**
 * The same question, for callers that hold a verdict signed somewhere else and
 * a verdict measured now — `rollout.service` asks it about the verdict frozen
 * on `rollout_targets` at composition versus the one the enqueue just produced.
 *
 * Exported rather than duplicated: two rank tables that agree today are two
 * rank tables, and the one nobody edits is the one that decides whether a
 * REJECT gets pushed.
 */
export function guardVerdictWorsened(signed: GuardVerdict, fresh: GuardVerdict): boolean {
  return VERDICT_RANK[fresh] > VERDICT_RANK[signed];
}

// ============================================================================
// Errors
// ============================================================================

export class ChangeRefusedError extends Error {
  constructor(readonly kind: string, message: string) {
    super(message);
    this.name = 'ChangeRefusedError';
  }
}

// ============================================================================
// The generic kinds, and the two refusals that bound them
// ============================================================================

/**
 * The GENERIC write kinds of migration 009: the ones this file drives through
 * the executor (backup, dead-man, render, apply) rather than through a branch
 * of their own. Every other write kind has a dedicated service and door.
 * Defined in `jobQueue.service.ts`, whose reaper needs it too.
 */
export { GENERIC_WRITE_KINDS };

/**
 * The generic write kinds with NO implementation. They carry no plan, and no
 * renderer turns them into commands (`renderer/index.ts` refuses a job with no
 * plan). Left reachable, each one took a preflight backup, armed the on-box
 * dead-man, refused at the write — and the dead-man then rebooted the router
 * at its deadline, reloading its own backup and restoring nothing, while the
 * job read `failed`. A rollout's "rollback" queued exactly that on every
 * landed router.
 *
 * Refused at every door (`previewChange`, `enqueueChangeJob`, hence POST
 * /api/changes/jobs and every service) and at claim, before anything is
 * dialled. The kinds stay in `CHANGE_JOB_KINDS`: migrations and the history of
 * past jobs still name them. `os_upgrade` is a different kind with a real
 * implementation and is unaffected.
 */
export const UNIMPLEMENTED_WRITE_KINDS: ReadonlySet<ChangeJobKind> = new Set<ChangeJobKind>([
  'restore', 'reboot', 'firmware',
]);

export const KIND_NOT_IMPLEMENTED_REFUSAL = 'kind_not_implemented';
export const CONCENTRATOR_GENERIC_WRITE_REFUSAL = 'concentrator_generic_write';

export function unimplementedKindMessage(kind: ChangeJobKind): string {
  // The remedy named must be one that exists: ObliWAN has no
  // operation that loads a stored backup onto a router, so a change is undone
  // by pushing the configuration that preceded it, through a plan.
  const instead =
    kind === 'restore'
      ? ' To undo a change, roll out the previous revision of its template to the device ' +
        '(publish it again if it was deprecated): the plan pushes the difference back under the ' +
        'guard and the dead-man.'
      : kind === 'firmware'
        ? " A RouterOS release is installed by the 'os_upgrade' job."
        : '';
  return (
    `A '${kind}' job is not implemented: no renderer turns it into commands for the router. ` +
    'Queued, it would take a pre-change backup and arm the on-box dead-man, then refuse at ' +
    'the write — and the dead-man would reboot the router at its deadline, restoring nothing. ' +
    'Refused before anything is queued or dialled.' +
    instead
  );
}

export function concentratorGenericWriteMessage(deviceName: string, kind: ChangeJobKind): string {
  return (
    `Device ${deviceName} is a concentrator. A '${kind}' job is a generic write, and a ` +
    'concentrator — the box every site of the fleet tunnels through — is never written to that ' +
    'way. Its writes go through their dedicated jobs only: concentrator_secret (a site\'s ' +
    '/ppp/secret), concentrator_link (the ObliWAN WireGuard link), site_rename (a site\'s ' +
    'login) and infra_account (an account on a customer\'s own concentrator).'
  );
}

function refuseUnimplementedKind(kind: ChangeJobKind): void {
  if (UNIMPLEMENTED_WRITE_KINDS.has(kind)) {
    throw new ChangeRefusedError(KIND_NOT_IMPLEMENTED_REFUSAL, unimplementedKindMessage(kind));
  }
}

function refuseConcentratorGenericWrite(device: DeviceRecord, kind: ChangeJobKind): void {
  if (GENERIC_WRITE_KINDS.has(kind) && device.role === 'concentrator') {
    throw new ChangeRefusedError(
      CONCENTRATOR_GENERIC_WRITE_REFUSAL,
      concentratorGenericWriteMessage(device.name, kind),
    );
  }
}

/** The same two refusals, asked again of a job already in the queue — one
 *  queued before they existed, or written around the door. */
function claimTimeRefusal(kind: ChangeJobKind, device: DeviceRecord): ChangeRefusedError | null {
  if (UNIMPLEMENTED_WRITE_KINDS.has(kind)) {
    return new ChangeRefusedError(KIND_NOT_IMPLEMENTED_REFUSAL, unimplementedKindMessage(kind));
  }
  if (GENERIC_WRITE_KINDS.has(kind) && device.role === 'concentrator') {
    return new ChangeRefusedError(
      CONCENTRATOR_GENERIC_WRITE_REFUSAL,
      concentratorGenericWriteMessage(device.name, kind),
    );
  }
  return null;
}

// ============================================================================
// The executor contract — the safe-apply module, reached by name and never by guesswork
// ============================================================================

export interface ExecContext {
  job: ChangeJobRow;
  device: DeviceRecord;
  /** The frozen plan's ops, REDACTED. Empty for non-push kinds. */
  ops: unknown[];
  /** `change_plans.id` the job is applying, when there is one. */
  planId: number | null;
  /** Ties every command of this job together in `command_audit`. */
  correlationId: string;
  /** The safety net the operator was shown and confirmed. */
  safetyLevel: SafetyLevel;
  safetyPeerDeviceId: number | null;
  /** `device_backups.id` taken before the change. Null before step 5. */
  preflightBackupId: number | null;
  /** The on-box handle of the dead-man, once armed. */
  deadmanHandle: string | null;
  /**
   * The dead-man interval to arm, in seconds — `commit_confirm_timeout`
   * resolved for this device in the same read as the soak. Null before step 5;
   * an executor handed null resolves it itself.
   */
  deadmanSeconds: number | null;
  /**
   * THE WRITE FRONTIER, persisted (migration 099). An executor that declares
   * `reportsWriteFrontier` calls it IMMEDIATELY before the first command that
   * may configure the router, and sends nothing if it throws: in one UPDATE it
   * proves this worker still holds the job (`applying`, its lease) and stamps
   * `transmit_started_at`, so a reaper that finds the stamp NULL after a crash
   * KNOWS nothing was configured. Throws `LeaseLostError` when the job was
   * taken away. For any other executor the queue calls it just before
   * `applyChange`.
   */
  crossFrontier?: () => Promise<void>;
}

/**
 * What `safeApply` / `backup` must provide.
 *
 * IT IS RESOLVED AT RUNTIME, and its absence is a REFUSAL, not a degradation:
 * a queue whose executor is missing fails its jobs at `backing_up`, before any
 * socket is opened. That is deliberate — the alternative (a stub that "does
 * nothing successfully") is a queue that reports green while a fleet drifts.
 */
export interface ChangeExecutor {
  /** Both `binary` and `rsc` where the driver can; returns the row that
   *  `change_jobs.preflight_backup_id` will point at. */
  takePreflightBackup(ctx: ExecContext): Promise<{ backupId: number }>;
  /** The safety-net rule. Installs the on-box dead-man (`/system/scheduler start-time=startup`
   *  + the restore script), or the peer-carried one. MUST return the level it
   *  ACTUALLY obtained, which may be worse than the one planned. */
  armDeadman(
    ctx: ExecContext,
  ): Promise<{ handle: string; level: SafetyLevel; confirmDeadline: Date; peerDeviceId?: number | null }>;
  /** THE WRITE. `:do{}on-error={rollback}`, never `/import` (arbitrated
   *  rejection: `/import` stops at the first error and leaves the router half
   *  configured with no handler). */
  applyChange(ctx: ExecContext): Promise<{ appliedOps: number; outputRedacted?: string | null }>;
  /**
   * True when `applyChange` calls `ctx.crossFrontier()` itself, immediately
   * before its first configuring command (and marks every error raised before
   * that `nothingTransmitted`). Otherwise the queue crosses the frontier just
   * before calling `applyChange` — conservative: from then on the job counts
   * as having transmitted.
   */
  reportsWriteFrontier?: boolean;
  /** Reconnect on a NEW socket, re-assert the binding, check post-conditions. */
  verify(
    ctx: ExecContext,
  ): Promise<{ ok: boolean; detail?: Record<string, unknown>; errorRedacted?: string | null }>;
  /** Remove the dead-man, with retry. */
  disarmDeadman(ctx: ExecContext): Promise<void>;
  /**
   * Take down what this job put on the router — the dead-man's scheduler and
   * script, then the preflight blob kept for it — when NO configuration
   * command was transmitted (`applyFrontier.ts`). Called on the failure path
   * only, never throws, and reports what it PROVED. An executor without it
   * leaves the net armed (the router reboots at the deadline) and the job and
   * a live alert say so.
   */
  releaseUnusedNet?(ctx: ExecContext): Promise<NetRelease>;
  /** Did the device restore itself? Used to distinguish `rolled_back` from
   *  `lost_contact` in the empirical corpus, which are NOT the same night. */
  observeRollback?(ctx: ExecContext): Promise<boolean>;
  /** `export` / `backup` — the read-only kinds, in the queue so that "one
   *  operation at a time per device" is true rather than mostly true. */
  runReadOnly?(
    ctx: ExecContext,
  ): Promise<{ outputRedacted?: string | null; detail?: Record<string, unknown> }>;
}

let injectedExecutor: ChangeExecutor | null = null;
let resolvedExecutor: ChangeExecutor | null | undefined;

/**
 * Wire the executor explicitly.
 *
 *  - an object   : use it (a fake, in a test).
 *  - `null`      : forget the injection and go back to resolving `safeApply`.
 *  - `'none'`    : PIN the answer to "no executor installed". A test seam, and
 *                  the only way to exercise the refusal path once the safe-apply module
 *                  actually exists on the build — which is the situation the
 *                  refusal is hardest to prove in and most important to keep.
 */
export function setChangeExecutor(executor: ChangeExecutor | null | 'none'): void {
  if (executor === 'none') {
    injectedExecutor = null;
    resolvedExecutor = null;
    return;
  }
  injectedExecutor = executor;
  resolvedExecutor = undefined;
}

/** What the queue would use right now. Exported for the integration check that
 *  asserts the safe-apply module really satisfies the contract at runtime. */
export async function currentExecutor(): Promise<ChangeExecutor | null> {
  return resolveExecutor();
}

/**
 * Can this process actually push, and if not, WHY — answered at startup rather
 * than discovered by the first operator who presses Apply.
 *
 * Both gaps it reports fail closed on their own (a missing executor is a
 * `ChangeRefusedError`; a missing renderer makes `applyChange` throw before it
 * opens a session). Saying so out loud at boot is the difference between "the
 * job failed, is the router alright?" and "we knew, and here is the line".
 */
export async function changeExecutorReadiness(): Promise<{ ready: boolean; warnings: string[] }> {
  const warnings: string[] = [];
  const executor = await resolveExecutor();
  if (!executor) {
    warnings.push(
      'No change executor is installed (services/change/safeApply.service). The queue will ' +
        'accept jobs and refuse every one of them before opening a session. NOTHING can be ' +
        'written to any equipment on this build.',
    );
    return { ready: false, warnings };
  }
  if (typeof (executor as { runReadOnly?: unknown }).runReadOnly !== 'function') {
    warnings.push(
      "The installed executor has no runReadOnly(): change jobs of kind 'export' and 'backup' " +
        'will be refused rather than silently faked.',
    );
  }
  try {
    const specifier = './safeApply.service';
    const mod = (await import(specifier)) as { isChangeRendererRegistered?: () => boolean };
    if (typeof mod.isChangeRendererRegistered === 'function' && !mod.isChangeRendererRegistered()) {
      warnings.push(
        'No change RENDERER is registered (registerChangeRenderer). The queue hands the executor ' +
          'the REDACTED plan — the complete config with its secrets exists only on the ' +
          "vault -> equipment path — so `push` jobs will refuse at the apply step rather than " +
          'write literal `***` into a customer firewall. Register it from the composition root ' +
          'before enabling pushes.',
      );
    }
  } catch {
    /* the module was resolvable a moment ago; a probe failure is not fatal */
  }
  return { ready: warnings.length === 0, warnings };
}

/**
 * Find the safe-apply module without importing it statically.
 *
 * `safeApply.service.ts` belongs to another module and may not exist on
 * this checkout. A static import would make the whole server fail to compile
 * over a file outside this module; a dynamic one lets the queue exist,
 * refuse honestly, and start working the day the module lands — with no edit
 * here.
 */
async function resolveExecutor(): Promise<ChangeExecutor | null> {
  if (injectedExecutor) return injectedExecutor;
  if (resolvedExecutor !== undefined) return resolvedExecutor;

  const specifier = './safeApply.service';
  try {
    const mod = (await import(specifier)) as Record<string, unknown>;
    const candidate = (mod.changeExecutor ?? mod.safeApply ?? mod.default ?? mod) as
      Partial<ChangeExecutor>;
    const required: Array<keyof ChangeExecutor> = [
      'takePreflightBackup',
      'armDeadman',
      'applyChange',
      'verify',
      'disarmDeadman',
    ];
    const missing = required.filter((k) => typeof candidate[k] !== 'function');
    if (missing.length > 0) {
      logger.error(
        { missing },
        'change executor: safeApply.service was found but does not implement the ChangeExecutor ' +
          'contract. No write will be attempted.',
      );
      resolvedExecutor = null;
      return null;
    }
    logger.info('change executor: safeApply.service resolved — writes are possible');
    resolvedExecutor = candidate as ChangeExecutor;
    return resolvedExecutor;
  } catch {
    logger.warn(
      'change executor: no safeApply.service module on this build. The queue will accept and ' +
        'refuse jobs, and NOTHING will be written to any equipment.',
    );
    resolvedExecutor = null;
    return null;
  }
}

// ============================================================================
// Device record
// ============================================================================

export interface DeviceRecord {
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
  /** `cpe` | `concentrator` (migration 002). A concentrator refuses every
   *  generic write kind (`refuseConcentratorGenericWrite`). Optional only for
   *  callers that build the record elsewhere (rollout.service). */
  role?: string | null;
  /** RouterOS 7.13+ `/system/device-mode`. Null on a box that has never been
   *  read, on RouterOS 6, and on every non-MikroTik brand — `null` means
   *  UNKNOWN, never "permitted". */
  device_mode?: string | null;
  device_mode_scheduler?: boolean | null;
  device_mode_observed_at?: Date | string | null;
  /** Learning mode (migration 089): set while ObliWAN learns this router's
   *  production configuration; a `push` is refused (`learningBlocksJob`). */
  learning_since?: Date | string | null;
}

async function loadDeviceRecord(
  tenantId: number,
  deviceId: number,
  q: Knex | Knex.Transaction = db,
): Promise<DeviceRecord> {
  const row = (await q('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first(
      'id', 'uuid', 'tenant_id', 'site_id', 'name', 'brand', 'family', 'model',
      'os_version', 'tunnel_ip', 'source_ip_hint', 'concentrator_id', 'status', 'is_managed',
      'role',
      // Read here rather than in `resolveSafetyNet`, because that function is
      // also called from `rollout.service.ts` with a record loaded elsewhere —
      // a second query inside it would make the safety level depend on which
      // caller happened to build the row.
      'device_mode', 'device_mode_scheduler', 'device_mode_observed_at',
      'learning_since',
    )) as DeviceRecord | undefined;
  if (!row) throw new ChangeRefusedError('device_not_found', `Device ${deviceId} not found`);
  return row;
}

/**
 * The address the management session comes FROM — the concentrator.
 *
 * Approximate by construction, and the guard is told so: the CHR's `tunnel_ip`
 * is its address on the tunnel network, which is what a CPE sees as the source
 * of an inbound API session in the normal topology. When it cannot be
 * determined the guard receives `null` and answers INDETERMINATE with
 * NO_MGMT_PATH_KNOWN — which is the correct answer, not a fallback.
 */
async function resolvePeerAddress(device: DeviceRecord): Promise<string | null> {
  if (device.concentrator_id) {
    const chr = (await db('devices')
      .where({ id: device.concentrator_id })
      .first('tunnel_ip', 'wan_public_ip')) as
      | { tunnel_ip: string | null; wan_public_ip: string | null }
      | undefined;
    const addr = chr?.tunnel_ip ?? chr?.wan_public_ip ?? null;
    if (addr) return String(addr).split('/')[0];
  }
  return device.source_ip_hint ? String(device.source_ip_hint).split('/')[0] : null;
}

// ============================================================================
// Step 3 — the Management-Path Guard
// ============================================================================

export interface GuardOutcome {
  verdict: GuardVerdict;
  /** The guard's own richer reasons (message, culprit record, plan line). */
  reasons: unknown[];
  summary: string;
  /** True when the guard could not even be run (no snapshot, no coordinates). */
  unavailable: boolean;
}

/**
 * Which ops of this plan the renderer would refuse, asked WITHOUT arming
 * anything.
 *
 * MikroTik only, and that is not a shortcut: the three other brands have no
 * renderer at all and are refused whole, by `BRAND_UNSUPPORTED`, before the
 * preflight backup — so there is nothing per-op to preview for them. Running a
 * RouterOS renderer over a DrayTek plan would invent refusals that mean
 * nothing, which is worse than staying silent.
 *
 * A thrown renderer is swallowed to an empty list on purpose. This is a
 * PREVIEW: its job is to move a refusal earlier, never to create one. If the
 * renderer itself breaks, the apply-time call is still there and still
 * authoritative, and a preview that refused on its own bug would block a plan
 * that is perfectly applicable.
 */
function renderPlanRefusals(device: DeviceRecord, ops: readonly PlanOp[]): string[] {
  if (device.brand !== 'mikrotik') return [];
  try {
    return renderPlanOpsForRouterOs(ops).refusals.map(
      (r) => `op #${r.seq} (${r.kind} ${r.resource} ${r.semKey}): ${r.reason} [${r.code}]`,
    );
  } catch (err) {
    logger.warn({ err, deviceId: device.id }, 'Render preview failed; apply-time render stands');
    return [];
  }
}

/**
 * Which ops of this plan would take a production uplink away — a PPPoE client
 * (ADSL / FTTH / FTTO), a WAN-list membership, the interface or the static
 * default route the site's traffic leaves through (`plan/uplinkGuard.ts`).
 *
 * Judged against the latest STORED snapshot — the same document the guard reads, and
 * the one `assertPlanFresh` pins the plan to — and, where there is none, on
 * the ops' own `before` records. Every brand: the NCM is brand-neutral and so
 * is the rule.
 *
 * NOT folded into the guard verdict, on purpose. A guard REJECT is lifted by a
 * signed override (CHANGE_APPROVE); the operator rule behind this one says
 * "whatever the template says", so no signature lifts it. The planner compiles
 * such an op as a `blocked` op already; this is the same refusal at the queue,
 * for a plan that did not come from this planner, and again at the job's
 * `guard` step, before the preflight backup and the dead-man are spent.
 */
async function uplinkPlanRefusals(deviceId: number, ops: readonly unknown[]): Promise<string[]> {
  const latest = await latestDocument(deviceId);
  return checkPlanUplinks(latest?.doc ?? null, ops).refusals;
}

/**
 * Run the management-path guard against the latest STORED snapshot of the device.
 *
 * The observed document comes from the most recently observed snapshot
 * (`latestDocument()`), not from the one the plan was compiled against: the
 * question the guard answers is "does this plan cut the path we use today",
 * and an older document cannot answer it. No collection is taken before this
 * call, so "today" means "as of the last collection": an edit made on the box
 * since then is not seen here. The freshness check (step 2) is what guarantees
 * the plan's base and this document are the same snapshot when a job runs.
 *
 * A missing snapshot, a missing tunnel address or an unresolvable peer make the
 * verdict INDETERMINATE. Never ACCEPT. `guardAllowsApply()` is the only
 * predicate any caller may use — nothing in this file writes `!== 'REJECT'`.
 *
 * One rule is added beside the forwarding guard, and it needs no snapshot: a
 * plan that closes or changes api-ssl on a router whose RouterOS API channel
 * rides it (the `management_access` job opened it) is a REJECT
 * (`managementApiChannelReasons`, managementAccess.service.ts) — SSH staying
 * open is enough for the forwarding guard, not for ObliWAN's own channel.
 */
export async function evaluateGuardForPlan(
  device: DeviceRecord,
  ops: readonly unknown[],
): Promise<GuardOutcome> {
  return withApiChannelReasons(
    await evaluateForwardingGuard(device, ops),
    await managementApiChannelReasons(device.id, ops),
  );
}

async function evaluateForwardingGuard(
  device: DeviceRecord,
  ops: readonly unknown[],
): Promise<GuardOutcome> {
  const latest = await latestDocument(device.id);
  if (!latest) {
    return {
      verdict: 'INDETERMINATE',
      reasons: [
        {
          code: 'COVERAGE_INCOMPLETE',
          effect: 'indeterminate',
          message:
            'This device has no configuration snapshot, so the Management-Path Guard has ' +
            'nothing to reason over. Collect the configuration before applying anything.',
        },
      ],
      summary: 'Management-Path Guard: INDETERMINATE — no configuration snapshot for this device.',
      unavailable: true,
    };
  }

  const facts = buildMgmtPathFacts(latest.doc, {
    deviceId: device.id,
    tunnelIp: device.tunnel_ip ? String(device.tunnel_ip).split('/')[0] : null,
  });
  const peerAddress = await resolvePeerAddress(device);

  let result: MgmtGuardResult;
  try {
    result = guardPlan({
      observed: latest.doc,
      // The guard reads `PlanOp[]`; the ops come straight from the frozen plan,
      // which was validated by the shared `ApplyPlan` schema on the way in.
      ops: ops as never,
      facts,
      peerAddress,
      family: device.family as never,
    });
  } catch (err) {
    // A guard that THREW has not accepted anything. Refuse to conclude rather
    // than let an exception read as silence.
    logger.error({ err, deviceId: device.id }, 'Management-Path Guard threw');
    return {
      verdict: 'INDETERMINATE',
      reasons: [
        {
          code: 'NO_FORWARDING_MODEL',
          effect: 'indeterminate',
          message: `The Management-Path Guard failed to run: ${
            err instanceof Error ? err.message : String(err)
          }`,
        },
      ],
      summary: 'Management-Path Guard: INDETERMINATE — the guard could not run.',
      unavailable: true,
    };
  }

  return {
    verdict: result.verdict,
    reasons: result.reasons as unknown[],
    summary: result.summary,
    unavailable: false,
  };
}

/**
 * A write kind with no plan — `reboot`, `firmware`, `restore`. Those three are
 * refused at every door and at claim (`UNIMPLEMENTED_WRITE_KINDS`), so this is
 * now only the fallback verdict of the job's `guard` step for a kind with no
 * guard of its own — and it stays a refusal.
 *
 * The guard models a FORWARDING change. It has nothing to say about a reboot
 * (whose hazard is an unsaved running config coming back different) or about a
 * firmware upgrade (whose hazard is everything). Pretending it accepted them
 * would be a lie with a green tick on it, so these are INDETERMINATE by
 * construction and need a signed override like any other refusal.
 */
function guardForPlanlessWrite(kind: ChangeJobKind): GuardOutcome {
  return {
    verdict: 'INDETERMINATE',
    reasons: [
      {
        code: 'NO_FORWARDING_MODEL',
        effect: 'indeterminate',
        message:
          `A '${kind}' job carries no plan, so the Management-Path Guard has no operations to ` +
          'simulate. It cannot prove the management path survives, and it does not pretend to.',
      },
    ],
    summary: `Management-Path Guard: INDETERMINATE — '${kind}' is outside the forwarding model.`,
    unavailable: false,
  };
}

// ============================================================================
// Step 4 — the safety net
// ============================================================================

export interface SafetyNetPlan {
  level: SafetyLevel;
  peerDeviceId: number | null;
  peerDeviceName: string | null;
  /** Shown on the impact screen BEFORE launch, verbatim. */
  rationale: string;
  /**
   * True when the level is a claim that must be SIGNED for: `withPeerReason()`
   * turns it into a PEER_UNVERIFIED guard reason, i.e. INDETERMINATE, i.e. a
   * write needs a signed override. Not every assumption sets it: an `armed`
   * MikroTik whose /system/device-mode was never read is assumed scheduler-
   * capable and says so in `rationale` instead, because the arming step still
   * refuses (`safety_net_downgraded`) before any write if the box denies the
   * scheduler.
   */
  unverified: boolean;
  requiresConfirmation: boolean;
}

/**
 * Which of the three nets this device gets.
 *
 * ┌─ WHAT THIS FUNCTION KNOWS, AND WHAT IT DOES NOT ──────────────────────────┐
 * │ It is INVENTORY ARITHMETIC. It reads a brand and looks for a co-located   │
 * │ MikroTik. It does NOT probe whether `/system/scheduler` can be written,   │
 * │ whether the peer is reachable, or — the harder half of the safety-net     │
 * │ rule — whether the tunnel to that peer is one THIS change does not touch. │
 * │                                                                          │
 * │ So `armed_by_peer` is returned with `unverified: true`, which becomes a   │
 * │ PEER_UNVERIFIED guard reason, which makes the verdict INDETERMINATE,      │
 * │ which demands a signed override. That is not pessimism for its own sake:  │
 * │ The design has all four brands writing from v1, with no laboratory, so    │
 * │ the net IS the laboratory, and a net we have not verified must not be     │
 * │ presented as one we have.                                                 │
 * │                                                                          │
 * │ The level the operator finally lives with is the one `armDeadman()`       │
 * │ REPORTS at step 6. If that is worse than this one, the job stops.         │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
export async function resolveSafetyNet(device: DeviceRecord): Promise<SafetyNetPlan> {
  if (device.brand === 'mikrotik') {
    // ── device-mode decides whether the net can exist at all ────────────────
    //
    // The on-box dead-man IS `/system/scheduler start-time=startup`, and since
    // RouterOS 7.13 `/system/device-mode` can deny the scheduler outright. On
    // such a unit `armDeadman()` installs nothing, `judgeArming()` correctly
    // refuses, and the job dies at step 6 — AFTER the preflight backup has been
    // taken and a maintenance window spent. The verdict is the same; the moment
    // is the difference, and the moment is the whole point of this function.
    //
    // It cannot be repaired from here either: MikroTik requires a reset-button
    // press or a cold power cycle within five minutes, deliberately. So this is
    // not a retry, it is an errand — and an operator planning a wave needs to
    // know before the wave, not during it.
    //
    // The reading is ASYMMETRIC, per `deadmanReadiness()`: a DENIAL is
    // authoritative, silence is not. `unknown` therefore keeps `armed` rather
    // than degrading the whole MikroTik fleet on a column nothing has filled
    // yet — a stricter reading would demand a signature for every write to the
    // dominant brand, which is how a safety feature gets switched off.
    const readiness = deadmanReadiness(
      device.device_mode === undefined && device.device_mode_scheduler === undefined
        ? null
        : {
          mode: (device.device_mode ?? null) as DeviceModeReading['mode'],
          schedulerAllowed: device.device_mode_scheduler ?? null,
          // Not selected: `fetch` gates `/tool/fetch`, which has no bearing on
          // whether a dead-man can be installed (only the os_upgrade job uses
          // it, and it reads `device_mode_fetch` itself). Carried as null rather
          // than a second column on the hot path — `deadmanReadiness` reads
          // only `schedulerAllowed` and `mode`.
          fetchAllowed: null,
          observedAt: device.device_mode_observed_at
            ? new Date(device.device_mode_observed_at).toISOString()
            : new Date(0).toISOString(),
        },
    );

    if (readiness.feasibility === 'blocked') {
      return {
        level: 'degraded',
        peerDeviceId: null,
        peerDeviceName: null,
        rationale:
          'DEGRADED — this router\'s /system/device-mode DENIES the scheduler, so the on-box '
          + 'dead-man cannot be installed and the router would NOT repair itself if the change '
          + 'cut the management path. Re-enabling it needs physical access: '
          + '`/system/device-mode/update scheduler=yes` followed, within five minutes, by the '
          + 'reset button or a cold power cycle. Until then a write here needs a human to accept '
          + 'that there is no net.',
        unverified: false,
        requiresConfirmation: true,
      };
    }

    return {
      level: 'armed',
      peerDeviceId: null,
      peerDeviceName: null,
      rationale:
        'ARMED — the dead-man is installed on this device itself ' +
        '(/system/scheduler start-time=startup + a restore script). The router repairs itself ' +
        'even if the ObliWAN server is dead.'
        + (readiness.feasibility === 'unknown'
          // Said out loud rather than silently assumed: the arming step will
          // still refuse if the box denies the scheduler, and the operator
          // should know this level rests on an unread column.
          ? ' /system/device-mode has never been read on this unit, so scheduler permission is '
            + 'assumed rather than known — use "Test connection" on the device page to read it.'
          : readiness.stale
            ? ` /system/device-mode was last read ${Math.round(readiness.ageDays ?? 0)} days ago.`
            : ''),
      // NOT `feasibility === 'unknown'`. `unverified` is not a label: through
      // `withPeerReason()` it turns ACCEPT into INDETERMINATE, and INDETERMINATE
      // demands a signed override — so an unread device-mode made EVERY push to
      // a never-probed MikroTik, and to every RouterOS 6 unit (no such menu, so
      // `unknown` forever), require a signature. That is precisely the "stricter
      // reading" the box above rules out. Silence costs nothing worse than a
      // job refused at the arming step; the rationale says it out loud instead.
      unverified: false,
      requiresConfirmation: false,
    };
  }

  const peer =
    device.site_id === null
      ? undefined
      : ((await db('devices')
          .where({ tenant_id: device.tenant_id, site_id: device.site_id, brand: 'mikrotik' })
          .whereNot('id', device.id)
          .whereIn('status', ['active'])
          .orderBy('id')
          .first('id', 'name')) as { id: number; name: string } | undefined);

  if (peer) {
    return {
      level: 'armed_by_peer',
      peerDeviceId: peer.id,
      peerDeviceName: peer.name,
      rationale:
        `ARMED_BY_PEER — the dead-man would be carried by ${peer.name} (#${peer.id}), a MikroTik ` +
        'on the same site. NOT VERIFIED: nothing has yet checked that this peer is reachable, ' +
        'nor that the tunnel used to reach it is one this change does not touch. Treat the net ' +
        'as a claim until the arming step confirms it.',
      unverified: true,
      // The safety-net rule demands the explicit confirmation for DEGRADED. An unverified peer
      // is not DEGRADED — but it is not a proof either, which is why it is
      // routed through the guard's PEER_UNVERIFIED reason instead.
      requiresConfirmation: false,
    };
  }

  // ── A WAY HOME, WHEN THERE IS NO REPAIR ──────────────────────────────────
  //
  // Before filing this device `degraded` — whose text promises a van — ask
  // whether it has a second uplink. Nearly every MikroTik and DrayTek carries
  // a backup LTE SIM: break the wired WAN and the box fails over, redials the
  // concentrator, and reappears. Reachability already has a name for that: WAN_FAILOVER.
  //
  // Read from the last snapshot's NCM, so it costs no network: an interface of
  // type `lte` that is not disabled. INVENTORY ARITHMETIC like the rest of this
  // function — it does not prove the SIM has credit or the operator has
  // coverage, and the wording below says so rather than implying a guarantee.
  const secondUplink = await findSecondUplink(device.id);
  if (secondUplink) {
    return {
      level: 'armed_by_second_uplink',
      peerDeviceId: null,
      peerDeviceName: null,
      rationale:
        `ARMED_BY_SECOND_UPLINK — this device carries a second uplink ("${secondUplink}") on a ` +
        'different medium. If this change cuts the wired path, the box is expected to fail over ' +
        'and come back by itself, so a mistake is repairable REMOTELY. This is NOT a dead-man: ' +
        'it survives a mistake on the WAN, and it dies with the first path if the change denies ' +
        'management on every interface. Not verified against the operator — no call was placed.',
      unverified: true,
      requiresConfirmation: false,
    };
  }

  return {
    level: 'degraded',
    peerDeviceId: null,
    peerDeviceName: null,
    rationale:
      `DEGRADED — ${device.brand} with no co-located MikroTik and no second uplink. Detection ` +
      'WITHOUT recovery: if this change cuts the management path we will know, and we will not ' +
      'be able to repair it remotely. Repair means a visit. ObliWAN requires an explicit, recorded ' +
      'confirmation.',
    unverified: false,
    requiresConfirmation: true,
  };
}


// ============================================================================
// Enqueue — where a plan becomes a job
// ============================================================================

export interface EnqueueInput {
  tenantId: number;
  deviceId: number;
  kind: ChangeJobKind;
  /** The compiled plan, as `/api/plan/devices/:id` returned it. Required for
   *  `push`, forbidden otherwise. */
  plan?: unknown;
  requestedBy: number | null;
  /** A signed override of a non-ACCEPT guard verdict. `CHANGE_APPROVE` at the
   *  route, `override_reason` + `overridden_by` + `overridden_at` in the row. */
  override?: { reason: string; userId: number | null } | null;
  /** The explicit confirmation a DEGRADED write demands. */
  confirmDegraded?: { userId: number | null } | null;
  scheduledFor?: Date | null;
  windowStart?: Date | null;
  windowEnd?: Date | null;
  maxAttempts?: number;
}

export interface EnqueueResult {
  jobId: number;
  planId: number | null;
  guard: GuardOutcome;
  safetyNet: SafetyNetPlan;
}

/**
 * PREVIEW — everything `enqueue` would decide, decided, with nothing written.
 *
 * This is what the impact screen calls: the safety-net rule says the three levels are
 * "calculés PAR DEVICE et AFFICHÉS AVANT le lancement", and a level computed
 * only inside the enqueue transaction is a level nobody was shown.
 */
export async function previewChange(input: {
  tenantId: number;
  deviceId: number;
  kind: ChangeJobKind;
  plan?: unknown;
}): Promise<{
  device: { id: number; name: string; brand: string; family: string };
  guard: GuardOutcome;
  safetyNet: SafetyNetPlan;
  killSwitch: Awaited<ReturnType<typeof readKillSwitch>>;
  freshness: { fresh: boolean; reason: string | null } | null;
  requiresOverride: boolean;
  requiresDegradedConfirmation: boolean;
  /** Named render refusals, surfaced BEFORE anything is armed. Empty means the
   *  plan is expressible; it does not mean the apply will succeed. */
  renderRefusals: string[];
  /** Ops that would take a production uplink away (`uplinkPlanRefusals`).
   *  Non-empty means the queue WILL refuse the plan, and no override lifts it. */
  uplinkRefusals: string[];
}> {
  refuseOsUpgradeHere(input.kind);
  // A preview tells the truth the enqueue would: a kind the queue refuses is
  // refused here too, rather than shown with a guard verdict and a net.
  refuseUnimplementedKind(input.kind);
  const device = await loadDeviceRecord(input.tenantId, input.deviceId);
  refuseConcentratorGenericWrite(device, input.kind);
  const safetyNet = await resolveSafetyNet(device);

  let guard: GuardOutcome;
  let freshness: { fresh: boolean; reason: string | null } | null = null;
  /** Ops the renderer has no syntax for. Empty on every non-push kind. */
  let renderRefusals: string[] = [];
  let uplinkRefusals: string[] = [];

  if (input.kind === 'push') {
    const plan = ApplyPlan.parse(input.plan);
    const verdict = await checkPlanFreshness(input.tenantId, plan);
    freshness = { fresh: verdict.fresh, reason: verdict.reason };
    guard = await evaluateGuardForPlan(device, plan.ops);

    // ── Can this plan even be EXPRESSED, before anything is armed? ──────────
    //
    // The renderer refuses by name for eleven reasons — a mangle-chain rule it
    // cannot address, a `blocked` op, a selector whose second atom would widen
    // the rule, a `localUser` create that would set an empty administrator
    // password. Every one of those refusals was reachable ONLY from
    // `applyChange`, i.e. after the preflight backup was taken and the dead-man
    // armed. The verdict was right and the moment was the worst available: a
    // maintenance window spent to be told the plan was never renderable.
    //
    // `renderPlanOpsForRouterOs` is pure — no database, no vault, no socket —
    // which is precisely what makes this call free here. It sees the same
    // frozen ops the executor will see, so a refusal here is the same refusal,
    // hours earlier and at no cost.
    //
    // It does NOT replace the render at apply time: the secret substitution and
    // its two barriers live there and must stay there. This answers one
    // question only — is the plan expressible — and leaves the rest alone.
    // Reported on its own field, NOT folded into the guard's verdict. The guard
    // answers one question — does this change cut the management path — and
    // borrowing its REJECT for "the renderer has no syntax for this op" would
    // make the guard say something it never evaluated. Two refusals, two
    // fields; `enqueueChangeJob` is what actually stops the job.
    renderRefusals = renderPlanRefusals(device, plan.ops);
    uplinkRefusals = await uplinkPlanRefusals(device.id, plan.ops);
  } else if (isWriteJobKind(input.kind)) {
    guard = guardForPlanlessWrite(input.kind);
  } else {
    guard = {
      verdict: 'ACCEPT',
      reasons: [],
      summary: 'Read-only operation: nothing is written, so there is nothing to guard.',
      unavailable: false,
    };
  }

  guard = withPeerReason(guard, safetyNet, input.kind);

  return {
    device: { id: device.id, name: device.name, brand: device.brand, family: device.family },
    guard,
    safetyNet,
    killSwitch: await readKillSwitch(input.tenantId),
    freshness,
    renderRefusals,
    uplinkRefusals,
    requiresOverride: isWriteJobKind(input.kind) && !guardAllowsApply(guard.verdict),
    requiresDegradedConfirmation: isWriteJobKind(input.kind) && safetyNet.requiresConfirmation,
  };
}

/**
 * `os_upgrade` has its own door (`services/firmware/osUpgrade.service.ts`:
 * `previewOsUpgrade` / `enqueueOsUpgradeJob`). This generic path has no field
 * for its target version, and `resolveSafetyNet()` would show a MikroTik as
 * ARMED — a net an upgrade does not get. Refused here so neither can happen.
 */
function refuseOsUpgradeHere(kind: ChangeJobKind): void {
  if (kind === 'os_upgrade') {
    throw new ChangeRefusedError(
      'kind_not_enqueueable',
      "An 'os_upgrade' job is created by the os_upgrade service only (it needs a target version " +
        'and is queued with no dead-man); the generic change path refuses it.',
    );
  }
}

/** An unverified peer net is a blind spot, and a blind spot is INDETERMINATE. */
function withPeerReason(
  guard: GuardOutcome,
  net: SafetyNetPlan,
  kind: ChangeJobKind,
): GuardOutcome {
  if (!net.unverified || !isWriteJobKind(kind)) return guard;
  const reasons = [
    ...guard.reasons,
    {
      code: 'PEER_UNVERIFIED',
      effect: 'indeterminate',
      message: net.rationale,
    },
  ];
  return {
    verdict: guard.verdict === 'REJECT' ? 'REJECT' : 'INDETERMINATE',
    reasons,
    summary:
      guard.verdict === 'REJECT'
        ? guard.summary
        : 'Management-Path Guard: INDETERMINATE — the safety net for this device is a claim ' +
          'about a peer nothing has verified.',
    unavailable: guard.unavailable,
  };
}

/**
 * Create the job. THE only door into `change_jobs`.
 *
 * The plan is FROZEN into `change_plans` first ("plan figé"): a trigger
 * leaves only `invalidated_at` / `invalidated_reason` mutable afterwards, so
 * the ops an approver read are the ops that run. The job then points at it.
 *
 * The one-job-per-device rule is NOT checked here. It is
 * `change_jobs_one_in_flight_uq`, and the 23505 it raises is translated into a
 * `DeviceBusyError`. A SELECT-then-INSERT would have a gap in the middle, and
 * two API calls fit in that gap.
 */
export async function enqueueChangeJob(input: EnqueueInput): Promise<EnqueueResult> {
  // FIRST, before anything else is even looked up. Not the guarantee — the
  // switch is read again immediately before the write, because that is when
  // somebody actually engages it — but when the world is stopped, "the world is
  // stopped" is the answer an operator needs, not "device 1 not found".
  const killSwitch = await readKillSwitch(input.tenantId);
  if (killSwitch.blocked) throw new KillSwitchEngagedError(killSwitch);
  refuseOsUpgradeHere(input.kind);
  // 'restore', 'reboot', 'firmware': no implementation, and a queued one ended
  // in a reboot nobody decided (see UNIMPLEMENTED_WRITE_KINDS).
  refuseUnimplementedKind(input.kind);

  const device = await loadDeviceRecord(input.tenantId, input.deviceId);
  // A concentrator carries every site's tunnel: only its dedicated kinds write
  // to it, never a push — whether from this route or from a rollout.
  refuseConcentratorGenericWrite(device, input.kind);

  if (device.status === 'disabled' || device.status === 'quarantined') {
    throw new ChangeRefusedError(
      'device_not_writable',
      `Device ${device.name} is '${device.status}'. No job may be queued against it.`,
    );
  }
  if (isWriteJobKind(input.kind) && !device.is_managed) {
    throw new ChangeRefusedError(
      'device_not_managed',
      `Device ${device.name} is not managed. A device can be readable without being writable, ` +
        'and that distinction is the whole reason `is_managed` is a separate column.',
    );
  }
  // Learning mode: no template-driven write (a `push`) on a router ObliWAN is
  // still learning. The targeted jobs (management access, APN, compliance…)
  // are not refused here.
  if (learningBlocksJob(input.kind) && device.learning_since) {
    throw new ChangeRefusedError(LEARNING_REFUSAL_KIND, learningRefusalMessage(device.name, device.learning_since));
  }

  const safetyNet = await resolveSafetyNet(device);

  let planId: number | null = null;
  let baseStateHash = NO_BASE_STATE;
  let guard: GuardOutcome;

  if (input.kind === 'push') {
    const plan = ApplyPlan.parse(input.plan);
    if (plan.deviceId !== device.id) {
      throw new ChangeRefusedError(
        'plan_device_mismatch',
        `This plan targets device ${plan.deviceId}, not ${device.id}.`,
      );
    }
    // Guarantee 2, at the door. It is checked AGAIN inside the job, at the
    // `guard` step — same function, two call sites, one guarantee. Both compare
    // against the LATEST STORED snapshot: the job takes no fresh collection
    // before that step, so an edit made since the last collection is not seen.
    await assertPlanFresh(input.tenantId, plan);

    // ── A plan that takes a production uplink away never becomes a job ──────
    //
    // Before the render check, so the refusal carries its own name: a plan the
    // planner compiled already holds these ops as `blocked`, which the renderer
    // would answer with the generic "plan contains a blocked op". No override
    // is consulted — operator rule, "whatever the template says".
    const uplinkCut = await uplinkPlanRefusals(device.id, plan.ops);
    if (uplinkCut.length > 0) {
      throw new ChangeRefusedError(UPLINK_REFUSAL_KIND, uplinkRefusalMessage(uplinkCut));
    }

    // ── A plan the renderer cannot express must not become a job ────────────
    //
    // Until now this was discovered by `applyChange`, which runs AFTER the
    // preflight backup is taken and the dead-man is armed: a maintenance
    // window spent to be told the plan was never renderable in the first
    // place. The verdict is identical; only the moment changes, and the moment
    // is the entire value.
    //
    // At the door rather than only in the preview, because a preview is
    // advisory — `enqueueChangeJob` is reachable directly, and a refusal that
    // only exists on a screen is not a refusal. The same argument as the change-queue rule: the
    // queue is the chokepoint, so the check belongs on the queue.
    //
    // Note what this does NOT promise: an expressible plan is not a plan that
    // will succeed. The secret substitution, its two barriers and the box's own
    // answer all still happen at apply time.
    const unrenderable = renderPlanRefusals(device, plan.ops);
    if (unrenderable.length > 0) {
      throw new ChangeRefusedError(
        'plan_not_renderable',
        `The renderer has no syntax for ${unrenderable.length} operation(s) of this plan, so the `
        + 'apply would refuse after arming the dead-man. Recompile the plan without them. '
        + unrenderable.join(' | '),
      );
    }

    guard = withPeerReason(await evaluateGuardForPlan(device, plan.ops), safetyNet, input.kind);
    baseStateHash = plan.baseStateHash;
    planId = await freezePlan(input.tenantId, device, plan, guard, safetyNet, input.requestedBy);
  } else if (isWriteJobKind(input.kind)) {
    guard = withPeerReason(guardForPlanlessWrite(input.kind), safetyNet, input.kind);
    baseStateHash = (await currentStateHash(device.id)) ?? NO_BASE_STATE;
  } else {
    guard = {
      verdict: 'ACCEPT',
      reasons: [],
      summary: 'Read-only operation: nothing is written, so there is nothing to guard.',
      unavailable: false,
    };
    baseStateHash = (await currentStateHash(device.id)) ?? NO_BASE_STATE;
  }

  const isWrite = isWriteJobKind(input.kind);

  // ── The two refusals a human can lift, and only by signing ────────────────
  if (isWrite && !guardAllowsApply(guard.verdict) && !input.override) {
    throw new ChangeRefusedError(
      'guard_refused',
      `${guard.summary} Applying anyway requires an explicit override with a written reason ` +
        '(capability CHANGE_APPROVE) — which is recorded against your name.',
    );
  }
  if (isWrite && safetyNet.requiresConfirmation && !input.confirmDegraded) {
    throw new ChangeRefusedError(
      'degraded_unconfirmed',
      `${safetyNet.rationale} This job needs an explicit confirmation before it can be queued.`,
    );
  }

  const now = new Date();
  const row: Record<string, unknown> = {
    tenant_id: input.tenantId,
    device_id: device.id,
    plan_id: planId,
    kind: input.kind,
    status: 'queued',
    attempt: 0,
    // A WRITE IS NOT RETRIED SILENTLY. Almost nothing here is safe to try twice.
    max_attempts: Math.max(1, Math.min(input.maxAttempts ?? 1, 3)),
    base_state_hash: baseStateHash,
    safety_level: safetyNet.level,
    safety_peer_device_id: safetyNet.peerDeviceId,
    guard_verdict: isWrite ? guard.verdict : null,
    guard_reasons: JSON.stringify(guard.reasons),
    scheduled_for: input.scheduledFor ?? null,
    window_start: input.windowStart ?? null,
    window_end: input.windowEnd ?? null,
    requested_by: input.requestedBy,
  };

  if (isWrite && !guardAllowsApply(guard.verdict)) {
    row.override_reason = input.override?.reason ?? null;
    row.overridden_by = input.override?.userId ?? null;
    row.overridden_at = now;
  }
  if (isWrite && safetyNet.requiresConfirmation) {
    row.degraded_confirmed_by = input.confirmDegraded?.userId ?? null;
    row.degraded_confirmed_at = now;
  }

  let jobId: number;
  try {
    const inserted = (await db('change_jobs').insert(row).returning('id')) as Array<{
      id: string | number;
    }>;
    jobId = Number(inserted[0].id);
  } catch (err) {
    // 23505 on `change_jobs_one_in_flight_uq` is the per-device lock speaking.
    const pg = err as { code?: string; constraint?: string };
    if (pg.code === '23505' && pg.constraint === 'change_jobs_one_in_flight_uq') {
      throw new DeviceBusyError(device.id);
    }
    throw err;
  }

  logger.warn(
    {
      jobId,
      deviceId: device.id,
      kind: input.kind,
      guard: guard.verdict,
      safetyNet: safetyNet.level,
      override: Boolean(row.override_reason),
      requestedBy: input.requestedBy,
    },
    'change job QUEUED — a write to a customer equipment has been authorised',
  );

  const summary = { jobId, deviceId: device.id, kind: input.kind, status: 'queued' };
  emitToTenantAudience(input.tenantId, SOCKET_EVENTS.JOB_QUEUED, summary, { deviceId: device.id });
  emitToDevice(device.id, SOCKET_EVENTS.JOB_QUEUED, summary);

  return { jobId, planId, guard, safetyNet };
}

/**
 * The `base_state_hash` of a plan-less job: the STORED `ncm_hash` of the most
 * recently OBSERVED snapshot — the same column, and the same row (ordered on
 * `last_seen_at`, `id` breaking a tie), that `compilePlan` records for a push
 * and `assertPlanFresh` compares against through `latestDocument()`. Two job
 * kinds on one unchanged device must not record two different "states", and on
 * A -> B -> A the resurrected row A is the current one, not B.
 */
async function currentStateHash(deviceId: number): Promise<string | null> {
  const row = (await db('config_snapshots')
    .where({ device_id: deviceId })
    .orderBy('last_seen_at', 'desc')
    .orderBy('id', 'desc')
    .first('ncm_hash')) as { ncm_hash: string | null } | undefined;
  return row?.ncm_hash ?? null;
}

/** The frozen plan. Frozen by trigger the instant it exists. */
async function freezePlan(
  tenantId: number,
  device: DeviceRecord,
  plan: ApplyPlan,
  guard: GuardOutcome,
  net: SafetyNetPlan,
  createdBy: number | null,
): Promise<number> {
  const rows = (await db('change_plans')
    .insert({
      tenant_id: tenantId,
      device_id: device.id,
      source: plan.source,
      base_state_hash: plan.baseStateHash,
      ncm_version: plan.ncmVersion,
      sem_key_generation: plan.semKeyGeneration,
      // `PlanOp` values are redacted by construction; a secret never
      // transits through one. This column is the one an operator reads.
      ops: JSON.stringify(plan.ops),
      ops_count: plan.ops.length,
      risk_level: plan.riskLevel,
      // The guard's uppercase verdict, bridged through the ONE authorised function.
      mgmt_path_verdict: mgmtPathVerdictOf(guard.verdict),
      guard_reasons: JSON.stringify(guard.reasons),
      safety_level: net.level,
      safety_peer_device_id: net.peerDeviceId,
      blast_radius: JSON.stringify(plan.blastRadius),
      order_converges: plan.orderConverges,
      expires_at: plan.expiresAt,
      created_by: createdBy,
    })
    .returning('id')) as Array<{ id: string | number }>;
  return Number(rows[0].id);
}

// ============================================================================
// Override, recorded after the fact
// ============================================================================

/**
 * Sign an override on a job that is still `queued`.
 *
 * Separate from enqueue because the two are separate GESTURES with separate
 * capabilities: `CHANGE_APPLY` asks for the change, `CHANGE_APPROVE` overrules
 * the guard. Four eyes is the point, and it is defeated if one call can do both
 * — which is exactly why the route for this is a different route.
 */
export async function recordOverride(
  tenantId: number,
  jobId: number,
  userId: number | null,
  reason: string,
): Promise<void> {
  const trimmed = reason.trim();
  if (trimmed.length < 8) {
    throw new ChangeRefusedError(
      'override_reason_too_short',
      'An override reason is read after an incident. "ok" is not one. Write what you checked.',
    );
  }
  const job = await getJobRow(tenantId, jobId);
  if (!job) throw new ChangeRefusedError('not_found', `Change job ${jobId} not found`);
  if (job.status !== 'queued') {
    throw new ChangeRefusedError(
      'not_queued',
      `Job ${jobId} is '${job.status}'. An override can only be signed before the job is claimed.`,
    );
  }
  if (job.guard_verdict === 'ACCEPT') {
    throw new ChangeRefusedError(
      'nothing_to_override',
      'The guard accepted this plan. There is nothing to override, and recording one anyway ' +
        'would put a signature on a decision nobody made.',
    );
  }

  await db('change_jobs').where({ id: jobId }).update({
    override_reason: trimmed,
    overridden_by: userId,
    overridden_at: db.fn.now(),
    approved_by: userId,
    updated_at: db.fn.now(),
  });

  logger.warn(
    { jobId, deviceId: job.device_id, userId, verdict: job.guard_verdict, reason: trimmed },
    'MANAGEMENT-PATH GUARD OVERRIDDEN — a non-ACCEPT verdict was forced by a named operator',
  );
}

// ============================================================================
// runJob — the orchestration
// ============================================================================

interface RunState {
  seq: number;
  job: ChangeJobRow;
  device: DeviceRecord;
  ctx: ExecContext;
  /** True once bytes may have reached the router. Decides whether the corpus
   *  gets a row, and whether a failure is a hardware observation at all. */
  wroteToDevice: boolean;
  /** True once the post-conditions were MEASURED and held. The only state in
   *  which taking the dead-man down on a failing job is defensible. */
  postcheckPassed: boolean;
  /**
   * Generic path only: the executor left something of THIS job on the router —
   * the preflight blob it keeps for the dead-man (from the moment
   * `takePreflightBackup` returned), then the dead-man's scheduler and script.
   */
  netOnDevice: boolean;
  /** When the dead-man's arming was attempted (it may have half-installed
   *  before throwing). Dates the reboot an unremoved net would cause. */
  armAttemptedAt: Date | null;
  /**
   * THE WRITE FRONTIER (`applyFrontier.ts`). Set immediately before
   * `executor.applyChange()`, cleared again ONLY when the executor proves it
   * raised before transmitting anything. While it is false, the net in place
   * protects nothing and a failure takes it down; once true, a failure leaves
   * it armed, exactly as before — a timeout after transmission counts as sent.
   */
  configMayHaveLanded: boolean;
  /** The worker that holds the lease. Renewals are made AS this identity, so a
   *  process that did not claim the job cannot keep it alive. */
  workerId: string;
  rollbackObserved: boolean;
  startedAt: number;
  /** Dead-man interval and soak for this device, resolved once before step 5. */
  window: ApplyWindow | null;
}

/**
 * Run one claimed job to a terminal state.
 *
 * NEVER THROWS. Every exit is a status in the database, because a throw that
 * escapes here is a device left in a state nobody recorded.
 */
export async function runJob(claimed: ChangeJobRow, workerId: string = WORKER_ID): Promise<void> {
  const jobId = Number(claimed.id);
  let state: RunState | null = null;

  try {
    const device = await loadDeviceRecord(claimed.tenant_id, claimed.device_id);
    const planOps = await loadPlanOps(claimed);

    state = {
      seq: 0,
      job: claimed,
      device,
      startedAt: Date.now(),
      workerId,
      wroteToDevice: false,
      postcheckPassed: false,
      netOnDevice: false,
      armAttemptedAt: null,
      configMayHaveLanded: false,
      rollbackObserved: false,
      window: null,
      ctx: {
        job: claimed,
        device,
        ops: planOps,
        planId: claimed.plan_id === null ? null : Number(claimed.plan_id),
        correlationId: crypto.randomUUID(),
        safetyLevel: claimed.safety_level,
        safetyPeerDeviceId: claimed.safety_peer_device_id,
        preflightBackupId: null,
        deadmanHandle: null,
        deadmanSeconds: null,
        crossFrontier: () => crossWriteFrontier(jobId, workerId),
      },
    };

    await runPhases(state);
  } catch (err) {
    if (err instanceof LeaseLostError) {
      // Somebody else owns this job now. Touch NOTHING of the row's status —
      // two workers writing the same status is how a job gets disarmed twice
      // and applied twice.
      logger.error({ jobId }, 'change job: lease lost mid-run — this worker stands down');
      // ONE exception, and it is not a second hand on the job: a net this
      // worker installed and never used. The lease is lost past `claimed` only
      // when the row became terminal — the reaper fails a `backing_up` or
      // `arming` job, an operator aborts one — and the reaper never requeues
      // past `claimed`, so no other worker can hold this job and nothing will
      // ever disarm that net but us. Left there, it reboots the router at its
      // deadline after an Abort whose message says nothing was written.
      if (state && state.netOnDevice && !state.configMayHaveLanded) {
        try {
          const row = (await db('change_jobs').where({ id: jobId }).first('*')) as
            | ChangeJobRow
            | undefined;
          if (row) await takeDownUnusedNet(state, row);
        } catch (releaseErr) {
          logger.error({ err: releaseErr, jobId }, 'change job: could not release an unused net after losing the lease');
        }
      }
      return;
    }
    await failJob(state, claimed, err);
  }

  // The job's outcome is written: what was promised after it (a
  // `legacy_compliance` after a bulk attach's `management_access`,
  // jobFollowup.service.ts) is queued if it succeeded, closed otherwise. Never
  // throws, and it runs after the outcome so it can never change it; a job
  // still running (a window deferral) is left to the sweep.
  await settleFollowupsOf(jobId);
}

async function runPhases(s: RunState): Promise<void> {
  const { job } = s;
  const write = isWriteJobKind(job.kind);

  // ── Before anything is dialled: the kinds the doors refuse ───────────────
  // A job already in the queue — queued before these refusals existed, or
  // written around the door — is failed here, with its reason on a `lint`
  // step, before any session, backup or dead-man (UNIMPLEMENTED_WRITE_KINDS,
  // refuseConcentratorGenericWrite).
  const claimRefusal = claimTimeRefusal(job.kind, s.device);
  if (claimRefusal) {
    await step(s, 'lint', async () => {
      throw claimRefusal;
    });
  }

  // ── 0. Kill switch ───────────────────────────────────────────────────────
  await assertWritable(job.tenant_id);

  // ── 1. Identity binding — the ONLY authorised way to reach a device ──────
  await step(s, 'bind_assert', async () => {
    // FIRST, before anything is dialled: a PPP login holding several live
    // sessions on its concentrator is ambiguous — its tunnel address reaches
    // whichever session the CHR routes to (pppDuplicates.service.ts). The
    // jobs that reach the router through its tunnel refuse it here, before
    // the identity proof sends the device's credential to whatever answers
    // and long before any preflight backup.
    const sessionNote = SESSION_GATED_JOB_KINDS.has(job.kind) ? await gateDuplicateSessions(s) : null;
    // `management_access` reaches a MikroTik that answers SSH only, and
    // `assertTargetBinding` proves a MikroTik over its RouterOS API: the job
    // proves it over a fresh SSH session instead — same attributes, same
    // comparison, same quarantine (managementAccess.service.ts). `lte_apn`
    // and `legacy_compliance` travel the same SSH road (lteApn.service.ts,
    // legacyCompliance.service.ts).
    // `site_rename` too (siteRename.service.ts): the router it renames answers SSH.
    // `wan_link` too (wanLink.service.ts): the router whose link it switches answers SSH.
    const assertion = job.kind === 'wan_link' ||
      job.kind === 'management_access' || job.kind === 'lte_apn' || job.kind === 'legacy_compliance' ||
      job.kind === 'site_rename'
      ? await assertMikrotikBindingOverSsh(s.device.id, {
        jobId: Number(job.id),
        correlationId: s.ctx.correlationId,
      })
      : await assertTargetBinding(s.device.id, { throwOnFailure: true });
    return {
      output:
        `identity confirmed on a fresh socket (${assertion.matched} attribute(s) matched)` +
        (sessionNote ? `; ${sessionNote}` : ''),
      detail: { dialled: assertion.dialled, matched: assertion.matched },
    };
  });

  // ── 2 + 3. Freshness, then the guard, on the latest STORED snapshot ──────
  await step(s, 'guard', async () => {
    if (job.plan_id !== null) {
      // Learning mode, read FRESH: a push queued before the router was put in
      // learning stops here, before the preflight backup and the dead-man.
      if (learningBlocksJob(job.kind)) {
        const learning = await learningStateOf(s.device.id);
        if (learning) {
          throw new ChangeRefusedError(LEARNING_REFUSAL_KIND, learningRefusalMessage(s.device.name, learning.since));
        }
      }
      await assertPlanFresh(job.tenant_id, {
        deviceId: s.device.id,
        baseStateHash: job.base_state_hash,
        // The plan's own expiry was checked at enqueue; a job that waited for
        // its maintenance window must not be failed for having waited, so the
        // expiry is re-anchored here and the HASH carries the load. That is the
        // braces, and the braces are what matters (planner.service, PLAN_TTL).
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      });

      // The queue door already refused this, against the same snapshot; this is
      // the braces. Before the preflight backup and the dead-man, and with NO
      // override consulted — a signed override lifts the guard, not this rule.
      const uplinkCut = await uplinkPlanRefusals(s.device.id, s.ctx.ops);
      if (uplinkCut.length > 0) {
        throw new ChangeRefusedError(UPLINK_REFUSAL_KIND, uplinkRefusalMessage(uplinkCut));
      }
    }

    if (!write) return { output: 'read-only operation: nothing to guard' };

    const fresh: GuardOutcome = job.plan_id !== null
      ? await evaluateGuardForPlan(s.device, s.ctx.ops)
      : job.kind === 'concentrator_secret'
        ? concentratorSecretGuard()
        : job.kind === 'os_upgrade'
          ? osUpgradeGuard()
          : job.kind === 'concentrator_link'
            ? concentratorLinkGuard()
            : job.kind === 'management_access'
              ? managementAccessGuard()
              : job.kind === 'lte_apn'
                ? lteApnGuard()
                : job.kind === 'legacy_compliance'
                  ? legacyComplianceGuard()
                  : job.kind === 'site_rename'
                  ? siteRenameGuard()
                  : job.kind === 'infra_account'
                    ? infraAccountGuard()
                    : job.kind === 'wan_link'
                      ? wanLinkGuard()
                      : guardForPlanlessWrite(job.kind);

    const signed = (job.guard_verdict ?? 'INDETERMINATE') as GuardVerdict;
    const hasOverride = Boolean(job.override_reason && job.overridden_by !== null);

    // The verdict must still be one a human accepted. A plan signed off as
    // INDETERMINATE that has become REJECT since is a different decision.
    if (guardVerdictWorsened(signed, fresh.verdict)) {
      throw new ChangeRefusedError(
        'guard_worsened',
        `The Management-Path Guard now says ${fresh.verdict}; this job was authorised against ` +
          `${signed}. ${fresh.summary} Recompile and have it reviewed again.`,
      );
    }
    if (!guardAllowsApply(fresh.verdict) && !hasOverride) {
      throw new ChangeRefusedError('guard_refused', fresh.summary);
    }

    await db('change_jobs').where({ id: job.id }).update({
      guard_reasons: JSON.stringify(fresh.reasons),
      updated_at: db.fn.now(),
    });

    return {
      output: hasOverride
        ? `${fresh.summary} OVERRIDDEN by user ${job.overridden_by}: ${job.override_reason}`
        : fresh.summary,
      detail: { verdict: fresh.verdict, overridden: hasOverride, reasonCount: fresh.reasons.length },
    };
  });

  // ── The concentrator's /ppp/secret: a branch of its own, before the executor
  // (concentratorSecret.service.ts). It needs no executor — no plan, no
  // backup, no dead-man — and talks to the CHR through the RouterOS pool,
  // every command through `auditedCommand`.
  if (job.kind === 'concentrator_secret') {
    await runConcentratorSecretPhases(s);
    return;
  }

  // ── A RouterOS upgrade: a branch of its own too (osUpgrade.service.ts). No
  // executor (no plan to render, no dead-man to arm); its backup goes through
  // `takeDeviceBackup()` and every command through `openDeviceSession()`.
  if (job.kind === 'os_upgrade') {
    await runOsUpgradePhases(s);
    return;
  }

  // ── The ObliWAN WireGuard link on the CHR: a branch of its own
  // (services/concentratorLink/link.service.ts). No executor (no plan, no
  // dead-man); its backup goes through `takeDeviceBackup()`, every command
  // through `auditedCommand` on the RouterOS pool socket.
  if (job.kind === 'concentrator_link') {
    await runConcentratorLinkPhases(s);
    return;
  }

  // ── api-ssl on a router in service, over SSH: a branch of its own
  // (managementAccess.service.ts). No executor (no plan, no dead-man); its
  // backup is pulled by SFTP, every command audited on its SSH session.
  if (job.kind === 'management_access') {
    await runManagementAccessPhases(s);
    return;
  }

  // ── lte1's APN profile, over SSH: a branch of its own (lteApn.service.ts).
  // No executor, no dead-man: the job refuses on the router unless the
  // management path provably leaves through another interface.
  if (job.kind === 'lte_apn') {
    await runLteApnPhases(s);
    return;
  }

  // ── The corrected-template fixes on a router in service, over SSH: a branch
  // of its own (legacyCompliance.service.ts). No executor, no on-box dead-man:
  // no line restarts the tunnels — the random-source-port fix and its
  // self-revert are retired (2026-10-05), dormant behind LEGACY_RETIRED_FIXES.
  if (job.kind === 'legacy_compliance') {
    await runLegacyCompliancePhases(s);
    return;
  }

  // ── Renaming a site's router (siteRename.service.ts): the CHR secret, the
  // management tunnel's user behind a self-revert, the identity, the device
  // row. A branch of its own: no executor, no on-box dead-man.
  if (job.kind === 'site_rename') {
    await runSiteRenamePhases(s);
    return;
  }

  // ── One site's account on the customer's own infrastructure concentrator
  // (services/infraConcentrator/job.service.ts): concentrator_secret's shape —
  // no plan, no backup, no dead-man, one entry added or removed, read back.
  if (job.kind === 'infra_account') {
    await runInfraAccountPhases(s);
    return;
  }

  // ── WAN1's link switched by ONE self-reverting script started on the router
  // (wanLink.service.ts). A branch of its own: no executor, no on-box dead-man.
  if (job.kind === 'wan_link') {
    await runWanLinkPhases(s);
    return;
  }

  const executor = await resolveExecutor();
  if (!executor) {
    throw new ChangeRefusedError(
      'executor_unavailable',
      'No change executor is installed on this build (safeApply.service). The queue accepted ' +
        'this job and is refusing it BEFORE opening any session. Nothing was written.',
    );
  }

  // ── Read-only kinds leave here ───────────────────────────────────────────
  //
  // They walk the SAME state machine, because there is only one and inventing a
  // shortcut would mean two definitions of "what state is this job in". What
  // makes the difference legible is not a different path, it is two SKIPPED
  // steps that say, in the trace, exactly why no backup was taken and why no
  // dead-man was armed. The design's `skipped` status exists for this: "we did not
  // arm a net" must be a recorded fact and never an absent row.
  if (!write) {
    s.job = await transitionJob(s.job, 'backing_up');
    await skipStep(
      s.job,
      s.seq++,
      'preflight_backup',
      `'${job.kind}' does not modify the device, so the pre-change backup does not apply.`,
    );
    s.job = await transitionJob(s.job, 'arming');
    await skipStep(
      s.job,
      s.seq++,
      'arm_deadman',
      `'${job.kind}' writes nothing, so there is nothing for a dead-man to undo. No net armed.`,
    );
    s.job = await transitionJob(s.job, 'applying');
    await step(s, 'apply', async () => {
      if (!executor.runReadOnly) {
        throw new ChangeRefusedError(
          'executor_unavailable',
          `The installed executor cannot perform a '${job.kind}'.`,
        );
      }
      const out = await executor.runReadOnly(s.ctx);
      return { output: out.outputRedacted ?? 'done', detail: out.detail };
    });
    s.job = await transitionJob(s.job, 'verifying');
    s.job = await transitionJob(s.job, 'soaking');
    s.job = await transitionJob(s.job, 'disarming');
    s.job = await transitionJob(s.job, 'succeeded', { outcome: 'succeeded' });
    return;
  }

  // ── 4b. The two clocks, read once, judged before anything is spent ───────
  //
  // `commit_confirm_timeout` and `apply_soak_seconds` for THIS device. A pair
  // that cannot hold reconnect + soak + disarm is refused here, before the
  // preflight backup and the dead-man — not discovered when the router reverts
  // a good change mid-soak (applyTimings.ts).
  s.window = await resolveApplyWindow(job.tenant_id, s.device.id);
  // Reconnection is budgeted TWICE: the `reconnect` step below, then
  // `executor.verify()`, which runs its own sequence on its own constants
  // (the mirror of these, see RECONNECT_DELAY_MS). Worst case, not usual case:
  // that is the case the dead-man exists for.
  const windowProblem = applyWindowProblem(
    s.window,
    2 * (RECONNECT_DELAY_MS + RECONNECT_ATTEMPTS * RECONNECT_INTERVAL_MS),
  );
  if (windowProblem) {
    throw new ChangeRefusedError('apply_window_incoherent', `Nothing was written: ${windowProblem}`);
  }
  s.ctx.deadmanSeconds = s.window.deadmanSeconds;

  // ── 5. The pre-change backup. A CHECK constraint, not a habit ────────────
  refuseIfStopping('its pre-change backup');
  await assertLease(Number(job.id), s.workerId);
  s.job = await transitionJob(s.job, 'backing_up');
  await step(s, 'preflight_backup', async () => {
    const { backupId } = await executor.takePreflightBackup(s.ctx);
    // The binary blob is now ON THE ROUTER, kept for the dead-man to load. From
    // here, a failure before the first configuration command owes its removal
    // (`releaseUnusedNet`). A backup that failed half-way removed its own
    // (`takeDeviceBackup`).
    s.netOnDevice = true;
    s.ctx.preflightBackupId = backupId;
    // Written to the row BEFORE the transition to `arming`, because
    // `change_jobs_preflight_backup_chk` makes that transition impossible
    // without it. The constraint is the reason this is not a comment.
    await db('change_jobs').where({ id: job.id }).update({
      preflight_backup_id: backupId,
      updated_at: db.fn.now(),
    });
    return { output: `pre-change backup #${backupId} stored`, detail: { backupId } };
  });

  // ── 6. The net ───────────────────────────────────────────────────────────
  refuseIfStopping('arming its dead-man');
  await assertLease(Number(job.id), s.workerId);
  s.job = await transitionJob(s.job, 'arming');
  await step(s, 'arm_deadman', async () => {
    // Stamped BEFORE the call: an arming that throws half-way may have left a
    // scheduler on the box, and the failure path must know to look for it.
    s.armAttemptedAt = new Date();
    const armed = await executor.armDeadman(s.ctx);
    s.ctx.deadmanHandle = armed.handle;

    // THE NET YOU WERE SHOWN MUST BE THE NET YOU GOT. A device promised as
    // ARMED that could only be armed by a peer — or not at all — is a device
    // whose operator confirmed a different risk. Downgrading silently here is
    // exactly the lie the safety-net rule forbids, so the job stops instead.
    if (armed.level !== s.job.safety_level) {
      throw new ChangeRefusedError(
        'safety_net_downgraded',
        `The safety net actually obtained is '${armed.level}', but this job was authorised ` +
          `against '${s.job.safety_level}'. Nothing has been applied. Re-queue it with the ` +
          'real level so the confirmation matches the risk.',
      );
    }

    await db('change_jobs').where({ id: job.id }).update({
      deadman_handle: armed.handle,
      deadman_armed_at: db.fn.now(),
      confirm_deadline: armed.confirmDeadline,
      updated_at: db.fn.now(),
    });
    return {
      output: `dead-man armed (${armed.level}); the device restores itself at ${
        armed.confirmDeadline.toISOString()
      } unless disarmed`,
      detail: { handle: armed.handle, level: armed.level },
    };
  });

  // ── 7. THE LAST STATEMENT BEFORE THE WRITE ───────────────────────────────
  //
  // Not a repetition: this is the check the kill switch exists FOR. Between it
  // and `applyChange` there is one status update and no I/O. Engaged here, the
  // job stops with NOTHING sent — and `failJob` takes the unused net back off
  // the router, so stopping the world does not reboot this router at the
  // deadline.
  await assertWritable(job.tenant_id);
  // A shutdown that began while this job armed: it stops HERE, with nothing
  // sent, and `failJob` takes the unused net down — rather than start a write
  // the grace period may cut in half, which the dead-man would then revert
  // with a reboot.
  refuseIfStopping('its first configuration command');
  await assertLease(Number(job.id), s.workerId);

  // ── 8. The write ─────────────────────────────────────────────────────────
  s.job = await transitionJob(s.job, 'applying');
  s.wroteToDevice = true;
  await step(s, 'apply', async () => {
    // THE FRONTIER (applyFrontier.ts). From here a failure may follow a
    // command that reached the router, and the net stays armed — unless the
    // executor proves it raised before transmitting anything (a render
    // refusal, a vault value refused, a session that did not open).
    s.configMayHaveLanded = true;
    try {
      // The persisted half of the frontier (migration 099). An executor that
      // reports it crosses it itself, at its first configuring command; for
      // any other, the frontier is crossed HERE, before `applyChange` is even
      // called — a reaper finding it uncrossed then knows nothing was sent.
      if (!executor.reportsWriteFrontier) {
        try {
          await crossWriteFrontier(Number(job.id), s.workerId);
        } catch (err) {
          throw markNothingTransmitted(err);
        }
      }
      const out = await executor.applyChange(s.ctx);
      return {
        output: out.outputRedacted ?? `${out.appliedOps} operation(s) applied`,
        detail: { appliedOps: out.appliedOps },
      };
    } catch (err) {
      if (wasNothingTransmitted(err)) {
        s.configMayHaveLanded = false;
        s.wroteToDevice = false;
      }
      throw err;
    }
  });

  // ── 9. Verify, on a NEW socket ───────────────────────────────────────────
  await assertLease(Number(job.id), s.workerId);
  s.job = await transitionJob(s.job, 'verifying');
  await step(s, 'reconnect', async () => {
    // Let the listener come back before deciding it is gone.
    await sleep(RECONNECT_DELAY_MS);
    let lastError: unknown = null;
    for (let attempt = 1; attempt <= RECONNECT_ATTEMPTS; attempt++) {
      try {
        const assertion = await assertTargetBinding(s.device.id, { throwOnFailure: true });
        return {
          output:
            `reconnected and re-asserted identity at attempt ${attempt}/${RECONNECT_ATTEMPTS} ` +
            `(${assertion.dialled})`,
          detail: { attempt, dialled: assertion.dialled, matched: assertion.matched },
        };
      } catch (err) {
        // A MISMATCH IS AN ANSWER, AND IT IS FINAL. The box replied and it is
        // not the device on the row: retrying cannot change that, and
        // `assertTargetBinding` has already quarantined it — looping would
        // simply re-quarantine it five more times. Only SILENCE is retried.
        if (err instanceof BindingAssertionError && err.assertion.mismatched > 0) throw err;
        lastError = err;
        if (attempt < RECONNECT_ATTEMPTS) await sleep(RECONNECT_INTERVAL_MS);
      }
    }
    throw lastError instanceof Error
      ? lastError
      : new ChangeRefusedError(
          'reconnect_failed',
          `The device did not answer in ${RECONNECT_ATTEMPTS} attempts after the write.`,
        );
  });
  await step(s, 'postcheck', async () => {
    const verdict = await executor.verify(s.ctx);
    if (!verdict.ok) {
      throw new ChangeRefusedError(
        'postcheck_failed',
        verdict.errorRedacted ?? 'Post-conditions did not hold after the change.',
      );
    }
    return { output: 'post-conditions hold', detail: verdict.detail };
  });
  // From here on, the change has been WRITTEN and PROVED to hold. A failure
  // after this point is a failure of our own bookkeeping, not of the change —
  // which is the one case where `failJob` may try to take the net down.
  s.postcheckPassed = true;

  // ── 10. Soak — live, watched, dead-man STILL armed ───────────────────────
  const soakMs = s.window.soakMs;
  const soakUntil = new Date(Date.now() + soakMs);
  s.job = await transitionJob(s.job, 'soaking', { soakUntil });
  await step(s, 'soak', async () => {
    await soak(Number(job.id), soakUntil, s.workerId);
    return { output: `soaked for ${Math.round(soakMs / 1000)}s with the dead-man armed` };
  });

  // ── 11. Disarm. A job is not `succeeded` while a scheduler still reverts ─
  await assertLease(Number(job.id), s.workerId);
  s.job = await transitionJob(s.job, 'disarming');
  await step(s, 'disarm', async () => {
    await executor.disarmDeadman(s.ctx);
    await db('change_jobs').where({ id: job.id }).update({
      deadman_disarmed_at: db.fn.now(),
      updated_at: db.fn.now(),
    });
    return { output: 'dead-man removed and confirmed gone' };
  });

  s.job = await transitionJob(s.job, 'succeeded', { outcome: 'succeeded' });
  await recordOutcome(s, 'succeeded', null);
  logger.info({ jobId: Number(job.id), deviceId: s.device.id }, 'change job SUCCEEDED');
}

/**
 * `concentrator_secret` (concentratorSecret.service.ts): the same state
 * machine, with the two nets SKIPPED and recorded as such — the job only ever
 * adds one /ppp/secret entry, so there is nothing for a backup to restore or a
 * dead-man to revert — then the add (or nothing, or a refusal) and a read-back.
 * The identity assertion, the guard and the kill switch have already run in
 * `runPhases`, and the per-device lock is the queue's.
 */
async function runConcentratorSecretPhases(s: RunState): Promise<void> {
  const { job } = s;
  try {
    await assertLease(Number(job.id), s.workerId);
    s.job = await transitionJob(s.job, 'backing_up');
    await skipStep(s.job, s.seq++, 'preflight_backup', CONCENTRATOR_SECRET_NO_BACKUP);
    s.job = await transitionJob(s.job, 'arming');
    await skipStep(s.job, s.seq++, 'arm_deadman', CONCENTRATOR_SECRET_NO_DEADMAN);

    await assertWritable(job.tenant_id);
    await assertLease(Number(job.id), s.workerId);
    s.job = await transitionJob(s.job, 'applying');
    await step(s, 'apply', () =>
      applyConcentratorSecret(job, s.device, s.ctx.correlationId, () => {
        s.wroteToDevice = true;
      }),
    );

    await assertLease(Number(job.id), s.workerId);
    s.job = await transitionJob(s.job, 'verifying');
    await step(s, 'postcheck', () => verifyConcentratorSecret(job, s.device, s.ctx.correlationId));
    s.postcheckPassed = true;
    // Mirrored while this job still holds the CHR, so no later job's mirror
    // can land before it. A failure is mirrored by `failJob` (and by the lease
    // reaper), which also covers the steps before this branch.
    await settleConcentratorSecret(job, { ok: true });

    s.job = await transitionJob(s.job, 'soaking');
    s.job = await transitionJob(s.job, 'disarming');
    s.job = await transitionJob(s.job, 'succeeded', { outcome: 'succeeded' });
  } catch (err) {
    if (err instanceof LeaseLostError) throw err;
    throw err instanceof ConcentratorSecretError ? new ChangeRefusedError(err.kind, err.message) : err;
  }
  await recordOutcome(s, 'succeeded', null);
  logger.info({ jobId: Number(job.id), deviceId: s.device.id }, 'concentrator secret job SUCCEEDED');
}

/**
 * `os_upgrade` (services/firmware/osUpgrade.service.ts): the same state
 * machine. `lint` reads and decides while the job is still `claimed`, so a
 * refusal there has written nothing and a device already at the target ends
 * as a no-op `succeeded` through three SKIPPED steps that say so. Otherwise:
 * the pre-change backup, a SKIPPED `arm_deadman` (no scheduler script can un-install a
 * release), the kill switch, then `apply` (fetch the pinned packages, check
 * them, read the kill switch again, reboot) — with a `cleanup` step that
 * removes the fetched files if anything fails before the reboot, or if the
 * box is proven never to have rebooted — then
 * `reconnect` (bounded wait, identity, proof of an actual reboot) and
 * `postcheck` (version == target). The identity assertion, the guard and the first
 * kill-switch read have already run in `runPhases`.
 */
async function runOsUpgradePhases(s: RunState): Promise<void> {
  const { job } = s;
  const run = new OsUpgradeRun({
    job,
    device: s.device,
    correlationId: s.ctx.correlationId,
    workerId: s.workerId,
  });
  try {
    await step(s, 'lint', () => run.inspect());

    if (run.isNoop) {
      const why = osUpgradeNoopReason(run.currentVersion ?? '?', run.targetVersion);
      await assertLease(Number(job.id), s.workerId);
      s.job = await transitionJob(s.job, 'backing_up');
      await skipStep(s.job, s.seq++, 'preflight_backup', why);
      s.job = await transitionJob(s.job, 'arming');
      await skipStep(s.job, s.seq++, 'arm_deadman', OS_UPGRADE_NO_DEADMAN);
      s.job = await transitionJob(s.job, 'applying');
      await skipStep(s.job, s.seq++, 'apply', why);
      s.job = await transitionJob(s.job, 'verifying');
      s.job = await transitionJob(s.job, 'soaking');
      s.job = await transitionJob(s.job, 'disarming');
      s.job = await transitionJob(s.job, 'succeeded', { outcome: 'succeeded' });
    } else {
      // ── The pre-change backup ──────────────────────────────────────────────
      await assertLease(Number(job.id), s.workerId);
      s.job = await transitionJob(s.job, 'backing_up');
      await step(s, 'preflight_backup', async () => {
        const out = await run.backup();
        s.ctx.preflightBackupId = out.backupId;
        await db('change_jobs').where({ id: job.id }).update({
          preflight_backup_id: out.backupId,
          updated_at: db.fn.now(),
        });
        return { output: out.output, detail: out.detail };
      });

      s.job = await transitionJob(s.job, 'arming');
      await skipStep(s.job, s.seq++, 'arm_deadman', OS_UPGRADE_NO_DEADMAN);

      // ── The kill switch, then the first write ──────────────────────────────
      await assertWritable(job.tenant_id);
      await assertLease(Number(job.id), s.workerId);
      s.job = await transitionJob(s.job, 'applying');
      try {
        await step(s, 'apply', () =>
          run.apply(() => {
            s.wroteToDevice = true;
          }),
        );
      } catch (err) {
        // A lost lease means somebody else owns the job: touch nothing.
        if (err instanceof LeaseLostError) throw err;
        if (run.needsCleanup) {
          try {
            await step(s, 'cleanup', () => run.cleanup());
          } catch {
            // Recorded on its step; what it left behind travels with the
            // job's own error below.
          }
          if (run.leftoverNote && err instanceof Error) err.message += run.leftoverNote;
        }
        throw err;
      }

      // ── The reboot happened: wait, re-prove, verify ────────────────────────
      await assertLease(Number(job.id), s.workerId);
      s.job = await transitionJob(s.job, 'verifying');
      try {
        await step(s, 'reconnect', () => run.awaitReturn());
      } catch (err) {
        // `not_rebooted`: a live, identity-proved box still on its old boot
        // holds the fetched files and would install them at ITS next reboot.
        // `needsCleanup` is true only in that case after a reboot was sent.
        if (!(err instanceof LeaseLostError) && run.needsCleanup) {
          try {
            await step(s, 'cleanup', () => run.cleanup());
          } catch {
            // Recorded on its step; the leftover travels with the job's error.
          }
          if (run.leftoverNote && err instanceof Error) err.message += run.leftoverNote;
        }
        throw err;
      }
      await step(s, 'postcheck', () => run.verify());
      s.postcheckPassed = true;

      // No soak and nothing to disarm: there is no dead-man. The rollout's
      // health gate is what watches the box after this job.
      s.job = await transitionJob(s.job, 'soaking');
      s.job = await transitionJob(s.job, 'disarming');
      s.job = await transitionJob(s.job, 'succeeded', { outcome: 'succeeded' });
    }
  } catch (err) {
    if (err instanceof LeaseLostError) throw err;
    throw err instanceof OsUpgradeError ? new ChangeRefusedError(err.kind, err.message) : err;
  }
  await recordOutcome(s, 'succeeded', null);
  logger.info({ jobId: Number(job.id), deviceId: s.device.id }, 'os_upgrade job SUCCEEDED');
}

/**
 * `concentrator_link` (services/concentratorLink/link.service.ts): the same
 * state machine. `lint` reads six menus of the CHR and decides while the job
 * is still `claimed`, so a conflict there refuses before any backup with
 * nothing written. When every item is already present the backup and the
 * apply are SKIPPED with the reason (nothing will be written); otherwise the
 * pre-change backup, a SKIPPED `arm_deadman`, the kill switch, then `apply` (one add
 * at a time, each read back). `postcheck` reads the whole set back, records
 * the CHR's public key and writes the host's config file. The identity assertion,
 * the guard and the first kill-switch read have already run in `runPhases`.
 */
async function runConcentratorLinkPhases(s: RunState): Promise<void> {
  const { job } = s;
  const run = new ConcentratorLinkRun(job, s.device, s.ctx.correlationId);
  try {
    await step(s, 'lint', () => run.inspect());

    await assertLease(Number(job.id), s.workerId);
    s.job = await transitionJob(s.job, 'backing_up');
    if (run.isNoop) {
      await skipStep(s.job, s.seq++, 'preflight_backup', run.noopReason);
    } else {
      await step(s, 'preflight_backup', async () => {
        const out = await run.backup();
        s.ctx.preflightBackupId = out.backupId;
        await db('change_jobs').where({ id: job.id }).update({
          preflight_backup_id: out.backupId,
          updated_at: db.fn.now(),
        });
        return { output: out.output, detail: out.detail };
      });
    }
    s.job = await transitionJob(s.job, 'arming');
    await skipStep(s.job, s.seq++, 'arm_deadman', CONCENTRATOR_LINK_NO_DEADMAN);

    await assertWritable(job.tenant_id);
    await assertLease(Number(job.id), s.workerId);
    s.job = await transitionJob(s.job, 'applying');
    if (run.isNoop) {
      await skipStep(s.job, s.seq++, 'apply', run.noopReason);
    } else {
      await step(s, 'apply', () =>
        run.apply(() => {
          s.wroteToDevice = true;
        }),
      );
    }

    await assertLease(Number(job.id), s.workerId);
    s.job = await transitionJob(s.job, 'verifying');
    await step(s, 'postcheck', () => run.verify());
    s.postcheckPassed = true;

    // No soak and nothing to disarm: there is no dead-man.
    s.job = await transitionJob(s.job, 'soaking');
    s.job = await transitionJob(s.job, 'disarming');
    s.job = await transitionJob(s.job, 'succeeded', { outcome: 'succeeded' });
  } catch (err) {
    if (err instanceof LeaseLostError) throw err;
    throw err instanceof ConcentratorLinkError ? new ChangeRefusedError(err.kind, err.message) : err;
  }
  await recordOutcome(s, 'succeeded', null);
  logger.info({ jobId: Number(job.id), deviceId: s.device.id }, 'concentrator link job SUCCEEDED');
}

/**
 * `management_access` (managementAccess.service.ts): the same state machine.
 * `lint` checks the frozen range and address, PROVES the SFTP road and reads
 * api-ssl, the certificates and the `obliwan` account while the job is still
 * `claimed`, so a refusal there has written nothing. When nothing is to be
 * written (api-ssl already as wanted, and no `obliwan` account to create), the
 * backup and the apply are SKIPPED with the reason; otherwise the pre-change backup
 * (pulled by SFTP), a SKIPPED `arm_deadman`, the kill switch, then `apply`
 * (the shared builder's lines as one /system script, then the account).
 * `postcheck` reads api-ssl back on a new SSH session, makes ONE API identity
 * read over TLS (as `obliwan` when switching to it, with a fresh SSH login as
 * `obliwan` too) and writes the device's routeros_api transport with the
 * fingerprint it pinned — and, for a switch, its ssh transport. The identity
 * assertion (over SSH), the guard and the first kill-switch read have already
 * run in `runPhases`.
 */
async function runManagementAccessPhases(s: RunState): Promise<void> {
  const { job } = s;
  const run = new ManagementAccessRun(job, s.device, s.ctx.correlationId, s.workerId);
  try {
    await step(s, 'lint', () => run.inspect());

    await assertLease(Number(job.id), s.workerId);
    s.job = await transitionJob(s.job, 'backing_up');
    if (run.isNoop) {
      await skipStep(s.job, s.seq++, 'preflight_backup', run.noopReason);
    } else {
      await step(s, 'preflight_backup', async () => {
        const out = await run.backup();
        s.ctx.preflightBackupId = out.backupId;
        await db('change_jobs').where({ id: job.id }).update({
          preflight_backup_id: out.backupId,
          updated_at: db.fn.now(),
        });
        return { output: out.output, detail: out.detail };
      });
    }
    s.job = await transitionJob(s.job, 'arming');
    await skipStep(s.job, s.seq++, 'arm_deadman', MANAGEMENT_ACCESS_NO_DEADMAN);

    await assertWritable(job.tenant_id);
    await assertLease(Number(job.id), s.workerId);
    s.job = await transitionJob(s.job, 'applying');
    if (run.isNoop) {
      await skipStep(s.job, s.seq++, 'apply', run.noopReason);
    } else {
      await step(s, 'apply', () =>
        run.apply(() => {
          s.wroteToDevice = true;
        }),
      );
    }

    await assertLease(Number(job.id), s.workerId);
    s.job = await transitionJob(s.job, 'verifying');
    await step(s, 'postcheck', () => run.verify());
    s.postcheckPassed = true;

    // No soak and nothing to disarm: there is no dead-man.
    s.job = await transitionJob(s.job, 'soaking');
    s.job = await transitionJob(s.job, 'disarming');
    s.job = await transitionJob(s.job, 'succeeded', { outcome: 'succeeded' });
  } catch (err) {
    if (err instanceof LeaseLostError) throw err;
    throw err instanceof ManagementAccessError ? new ChangeRefusedError(err.kind, err.message) : err;
  }
  await recordOutcome(s, 'succeeded', null);
  logger.info({ jobId: Number(job.id), deviceId: s.device.id }, 'management_access job SUCCEEDED');
}

/**
 * `lte_apn` (lteApn.service.ts): the same state machine as management_access.
 * `lint` re-checks the frozen profile against the device's catalogue, proves
 * the SFTP road and reads lte1, the profiles and the EGRESS verdict while the
 * job is still `claimed`, so a refusal there has written nothing. Already on
 * the profile: backup and apply SKIPPED with the reason. Otherwise the pre-change
 * backup (SFTP), a SKIPPED `arm_deadman`, the kill switch, then `apply`
 * (the egress verdict read again on the writing session, then the
 * allow-listed lines). `postcheck` reads lte1 back on a new session and only
 * then records the device's chosen profile.
 */
async function runLteApnPhases(s: RunState): Promise<void> {
  const { job } = s;
  const run = new LteApnRun(job, s.device, s.ctx.correlationId, s.workerId);
  try {
    await step(s, 'lint', () => run.inspect());

    await assertLease(Number(job.id), s.workerId);
    s.job = await transitionJob(s.job, 'backing_up');
    if (run.isNoop) {
      await skipStep(s.job, s.seq++, 'preflight_backup', run.noopReason);
    } else {
      await step(s, 'preflight_backup', async () => {
        const out = await run.backup();
        s.ctx.preflightBackupId = out.backupId;
        await db('change_jobs').where({ id: job.id }).update({
          preflight_backup_id: out.backupId,
          updated_at: db.fn.now(),
        });
        return { output: out.output, detail: out.detail };
      });
    }
    s.job = await transitionJob(s.job, 'arming');
    await skipStep(s.job, s.seq++, 'arm_deadman', LTE_APN_NO_DEADMAN);

    await assertWritable(job.tenant_id);
    await assertLease(Number(job.id), s.workerId);
    s.job = await transitionJob(s.job, 'applying');
    if (run.isNoop) {
      await skipStep(s.job, s.seq++, 'apply', run.noopReason);
    } else {
      await step(s, 'apply', () =>
        run.apply(() => {
          s.wroteToDevice = true;
        }),
      );
    }

    await assertLease(Number(job.id), s.workerId);
    s.job = await transitionJob(s.job, 'verifying');
    await step(s, 'postcheck', () => run.verify(s.wroteToDevice));
    s.postcheckPassed = true;

    s.job = await transitionJob(s.job, 'soaking');
    s.job = await transitionJob(s.job, 'disarming');
    s.job = await transitionJob(s.job, 'succeeded', { outcome: 'succeeded' });
  } catch (err) {
    if (err instanceof LeaseLostError) throw err;
    throw err instanceof LteApnError ? new ChangeRefusedError(err.kind, err.message) : err;
  }
  await recordOutcome(s, 'succeeded', null);
  logger.info({ jobId: Number(job.id), deviceId: s.device.id }, 'lte_apn job SUCCEEDED');
}

/**
 * `legacy_compliance` (legacyCompliance.service.ts): the same state machine as
 * lte_apn, with one step more. `lint` proves the SFTP road, reads the router
 * and builds the plan while the job is still `claimed`. Nothing to write:
 * backup and apply SKIPPED with the reason. Otherwise the pre-change backup (SFTP), a
 * SKIPPED `arm_deadman`, the kill switch, then `apply` (the router read again
 * on the writing session, a–e one command each; the self-revert and the l2tp
 * line last only when that fix is not retired — it is, since 2026-10-05).
 * `reconnect` waits for the tunnel the l2tp line restarted and past the
 * self-revert's decision — SKIPPED when no running tunnel was changed, hence
 * always while the l2tp fix is retired — and `postcheck` reads every fix back
 * on a new session.
 */
/**
 * `infra_account` (services/infraConcentrator/job.service.ts): the
 * concentrator_secret state machine — the two nets SKIPPED and recorded as
 * such, then the driver's apply (or revoke) and a read-back. The identity
 * assertion, the guard and the kill switch have already run in `runPhases`.
 */
async function runInfraAccountPhases(s: RunState): Promise<void> {
  const { job } = s;
  try {
    await assertLease(Number(job.id), s.workerId);
    s.job = await transitionJob(s.job, 'backing_up');
    await skipStep(s.job, s.seq++, 'preflight_backup', INFRA_ACCOUNT_NO_BACKUP);
    s.job = await transitionJob(s.job, 'arming');
    await skipStep(s.job, s.seq++, 'arm_deadman', INFRA_ACCOUNT_NO_DEADMAN);

    await assertWritable(job.tenant_id);
    await assertLease(Number(job.id), s.workerId);
    s.job = await transitionJob(s.job, 'applying');
    await step(s, 'apply', () =>
      runInfraAccountApply(job, s.device, s.ctx.correlationId, () => {
        s.wroteToDevice = true;
      }),
    );

    await assertLease(Number(job.id), s.workerId);
    s.job = await transitionJob(s.job, 'verifying');
    await step(s, 'postcheck', () => runInfraAccountVerify(job, s.device, s.ctx.correlationId));
    s.postcheckPassed = true;
    await settleInfraAccount(job, { ok: true });

    s.job = await transitionJob(s.job, 'soaking');
    s.job = await transitionJob(s.job, 'disarming');
    s.job = await transitionJob(s.job, 'succeeded', { outcome: 'succeeded' });
  } catch (err) {
    if (err instanceof LeaseLostError) throw err;
    throw err instanceof InfraAccountJobError ? new ChangeRefusedError(err.kind, err.message) : err;
  }
  await recordOutcome(s, 'succeeded', null);
  logger.info({ jobId: Number(job.id), deviceId: s.device.id }, 'infra account job SUCCEEDED');
}

async function runLegacyCompliancePhases(s: RunState): Promise<void> {
  const { job } = s;
  const run = new LegacyComplianceRun(job, s.device, s.ctx.correlationId, s.workerId);
  try {
    await step(s, 'lint', () => run.inspect());

    await assertLease(Number(job.id), s.workerId);
    s.job = await transitionJob(s.job, 'backing_up');
    if (run.isNoop) {
      await skipStep(s.job, s.seq++, 'preflight_backup', run.noopReason);
    } else {
      await step(s, 'preflight_backup', async () => {
        const out = await run.backup();
        s.ctx.preflightBackupId = out.backupId;
        await db('change_jobs').where({ id: job.id }).update({
          preflight_backup_id: out.backupId,
          updated_at: db.fn.now(),
        });
        return { output: out.output, detail: out.detail };
      });
    }
    s.job = await transitionJob(s.job, 'arming');
    await skipStep(s.job, s.seq++, 'arm_deadman', LEGACY_COMPLIANCE_NO_DEADMAN);

    await assertWritable(job.tenant_id);
    await assertLease(Number(job.id), s.workerId);
    s.job = await transitionJob(s.job, 'applying');
    if (run.isNoop) {
      await skipStep(s.job, s.seq++, 'apply', run.noopReason);
    } else {
      await step(s, 'apply', () =>
        run.apply(() => {
          s.wroteToDevice = true;
        }),
      );
    }

    await assertLease(Number(job.id), s.workerId);
    s.job = await transitionJob(s.job, 'verifying');
    if (run.mustAwaitTunnel) {
      await step(s, 'reconnect', () => run.reconnect());
      await assertLease(Number(job.id), s.workerId);
    } else {
      await skipStep(s.job, s.seq++, 'reconnect', run.noTunnelReason);
    }
    await step(s, 'postcheck', () => run.verify(s.wroteToDevice));
    s.postcheckPassed = true;

    s.job = await transitionJob(s.job, 'soaking');
    s.job = await transitionJob(s.job, 'disarming');
    s.job = await transitionJob(s.job, 'succeeded', { outcome: 'succeeded' });
  } catch (err) {
    if (err instanceof LeaseLostError) throw err;
    throw err instanceof LegacyComplianceError ? new ChangeRefusedError(err.kind, err.message) : err;
  }
  await recordOutcome(s, 'succeeded', null);
  logger.info({ jobId: Number(job.id), deviceId: s.device.id }, 'legacy_compliance job SUCCEEDED');
}

/**
 * `site_rename` (siteRename.service.ts): `lint` proves the CHR on a fresh
 * socket, reads it and the router (only when the CHR says the tunnel is
 * up) and builds the plan while the job is still `claimed`. The pre-change backup only
 * when a router line is planned; a SKIPPED `arm_deadman`; both kill switches;
 * `apply` (the CHR secret, then the self-revert seen alive from a new session,
 * the device row, the cut — or the identity line alone); `reconnect` waits for
 * the new session past the self-revert's decision (SKIPPED with no cut);
 * `postcheck` reads back on fresh sessions; `cleanup` finalizes the device
 * row, the allocation, the site code and the CHR inventory in one
 * transaction, then removes the old secret when it is safe.
 */
async function runSiteRenamePhases(s: RunState): Promise<void> {
  const { job } = s;
  const run = new SiteRenameRun(job, s.device, s.ctx.correlationId, s.workerId);
  try {
    await step(s, 'lint', () => run.inspect());

    await assertLease(Number(job.id), s.workerId);
    s.job = await transitionJob(s.job, 'backing_up');
    if (run.needsBackup) {
      await step(s, 'preflight_backup', async () => {
        const out = await run.backup();
        s.ctx.preflightBackupId = out.backupId;
        await db('change_jobs').where({ id: job.id }).update({
          preflight_backup_id: out.backupId,
          updated_at: db.fn.now(),
        });
        return { output: out.output, detail: out.detail };
      });
    } else {
      await skipStep(s.job, s.seq++, 'preflight_backup', run.noBackupReason);
    }
    s.job = await transitionJob(s.job, 'arming');
    await skipStep(s.job, s.seq++, 'arm_deadman', SITE_RENAME_NO_DEADMAN);

    await assertWritable(job.tenant_id);
    await assertLease(Number(job.id), s.workerId);
    s.job = await transitionJob(s.job, 'applying');
    if (run.isNoop) {
      await skipStep(s.job, s.seq++, 'apply', run.noopReason);
    } else {
      await step(s, 'apply', () =>
        run.apply(() => {
          s.wroteToDevice = true;
        }),
      );
    }

    await assertLease(Number(job.id), s.workerId);
    s.job = await transitionJob(s.job, 'verifying');
    if (run.mustAwaitTunnel) {
      await step(s, 'reconnect', () => run.reconnect());
      await assertLease(Number(job.id), s.workerId);
    } else {
      await skipStep(s.job, s.seq++, 'reconnect', run.noTunnelReason);
    }
    await step(s, 'postcheck', () => run.verify());
    if (run.isNoop) {
      await skipStep(s.job, s.seq++, 'cleanup', run.noopReason);
    } else {
      await step(s, 'cleanup', () => run.finalize());
    }
    s.postcheckPassed = true;

    s.job = await transitionJob(s.job, 'soaking');
    s.job = await transitionJob(s.job, 'disarming');
    s.job = await transitionJob(s.job, 'succeeded', { outcome: 'succeeded' });
  } catch (err) {
    if (err instanceof LeaseLostError) throw err;
    throw err instanceof SiteRenameError ? new ChangeRefusedError(err.kind, err.message) : err;
  }
  await recordOutcome(s, 'succeeded', null);
  logger.info({ jobId: Number(job.id), deviceId: s.device.id }, 'site_rename job SUCCEEDED');
}

/**
 * `wan_link` (wanLink.service.ts): `lint` reads the router (the mode the site
 * declares, the 4G ready, the management tunnel's takeover by the 4G), builds
 * the one line and passes it through the allow-list, while the job is still
 * `claimed`. Already on the target: backup, apply and reconnect SKIPPED, the
 * site's variables recorded. Otherwise the pre-change backup (SFTP), a SKIPPED
 * `arm_deadman`, the kill switch, `apply` (the router read again, the window
 * opened and announced, the one `:execute` line, the script seen alive on a
 * new session), `reconnect` (the script's decision, a down PPP session never dialled, one more
 * failover) — SKIPPED when the router refused the line or the script died
 * with its session — and `postcheck` (the read-back, the site's variables).
 */
async function runWanLinkPhases(s: RunState): Promise<void> {
  const { job } = s;
  const run = new WanLinkRun(job, s.device, s.ctx.correlationId, s.workerId);
  try {
    await step(s, 'lint', () => run.inspect());

    await assertLease(Number(job.id), s.workerId);
    s.job = await transitionJob(s.job, 'backing_up');
    if (run.isNoop) {
      await skipStep(s.job, s.seq++, 'preflight_backup', run.noopReason);
    } else {
      await step(s, 'preflight_backup', async () => {
        const out = await run.backup();
        s.ctx.preflightBackupId = out.backupId;
        await db('change_jobs').where({ id: job.id }).update({
          preflight_backup_id: out.backupId,
          updated_at: db.fn.now(),
        });
        return { output: out.output, detail: out.detail };
      });
    }
    s.job = await transitionJob(s.job, 'arming');
    await skipStep(s.job, s.seq++, 'arm_deadman', WAN_LINK_NO_DEADMAN);

    await assertWritable(job.tenant_id);
    await assertLease(Number(job.id), s.workerId);
    s.job = await transitionJob(s.job, 'applying');
    if (run.isNoop) {
      await skipStep(s.job, s.seq++, 'apply', run.noopReason);
    } else {
      await step(s, 'apply', () =>
        run.apply(() => {
          s.wroteToDevice = true;
        }),
      );
    }

    await assertLease(Number(job.id), s.workerId);
    s.job = await transitionJob(s.job, 'verifying');
    if (run.mustAwaitDecision) {
      await step(s, 'reconnect', () => run.awaitDecision());
      await assertLease(Number(job.id), s.workerId);
    } else {
      await skipStep(s.job, s.seq++, 'reconnect', run.isNoop ? run.noopReason : run.noAwaitReason);
    }
    await step(s, 'postcheck', () => run.verify(s.wroteToDevice));
    s.postcheckPassed = true;

    s.job = await transitionJob(s.job, 'soaking');
    s.job = await transitionJob(s.job, 'disarming');
    s.job = await transitionJob(s.job, 'succeeded', { outcome: 'succeeded' });
  } catch (err) {
    if (err instanceof LeaseLostError) throw err;
    throw err instanceof WanLinkError ? new ChangeRefusedError(err.kind, err.message) : err;
  }
  await recordOutcome(s, 'succeeded', null);
  logger.info({ jobId: Number(job.id), deviceId: s.device.id }, 'wan_link job SUCCEEDED');
}

/**
 * Wait out the soak window, renewing the lease as we go.
 *
 * The renewal is the point: five minutes of silence is longer than a lease, and
 * a job whose lease expired mid-soak would be picked up by the reaper as
 * "worker died after the write" — a false alarm on the one signal that must
 * never cry wolf.
 */
async function soak(jobId: number, until: Date, workerId: string): Promise<void> {
  while (Date.now() < until.getTime()) {
    const remaining = until.getTime() - Date.now();
    await new Promise((r) => setTimeout(r, Math.min(remaining, 15_000)));
    await assertLease(jobId, workerId);
  }
}

// ============================================================================
// Steps
// ============================================================================

interface StepOutcome {
  output?: string | null;
  detail?: Record<string, unknown>;
}

/**
 * Run one step, recorded whatever happens.
 *
 * A step whose row is missing is a step nobody can prove was attempted, which
 * is why the `finishStep` on the failure path is not conditional and is not
 * inside the try.
 */
/**
 * The duplicate-sessions gate of `bind_assert` (pppDuplicates.service.ts):
 * the device's PPP login read LIVE on its concentrator, else from the last
 * read presence recorded if it is recent. Several sessions -> refused by name
 * (`duplicate_sessions`), nothing dialled. No evidence either way -> today's
 * behaviour, and a log line saying the check could not be made. Returns the
 * note the step's output carries; null when the device has no PPP login on a
 * concentrator.
 */
async function gateDuplicateSessions(s: RunState): Promise<string | null> {
  const verdict = await sessionGateForDevice(s.device.id);
  switch (verdict.state) {
    case 'duplicate':
      throw new ChangeRefusedError(PPP_DUPLICATE_REFUSAL, duplicateSessionsRefusalMessage(s.device.name, verdict));
    case 'unknown':
      logger.warn(
        { jobId: Number(s.job.id), deviceId: s.device.id, kind: s.job.kind, reason: verdict.reason },
        'change job: the PPP login\'s live sessions could not be checked; the job proceeds as before (no refusal invented)',
      );
      return `PPP sessions not checked (${verdict.reason})`;
    case 'unique':
      return verdict.source === 'live'
        ? `PPP login on ${verdict.count ?? 0} live session(s) on the concentrator (read live)`
        : `PPP login not duplicated in the read presence recorded at ${verdict.observedAt}`;
    default:
      return null;
  }
}

async function step(
  s: RunState,
  kind: Parameters<typeof startStep>[2],
  body: () => Promise<StepOutcome>,
): Promise<void> {
  const handle: StepHandle = await startStep(s.job, s.seq++, kind);
  try {
    const out = await body();
    await finishStep(s.job, handle, 'succeeded', {
      output: out.output ?? null,
      detail: out.detail,
    });
  } catch (err) {
    await finishStep(s.job, handle, 'failed', {
      // Already redacted at the source; this layer does not remove secrets, it
      // only refuses to add any.
      error: err instanceof Error ? err.message : String(err),
    });
    throw err;
  }
}

// ============================================================================
// Failure
// ============================================================================

async function failJob(s: RunState | null, claimed: ChangeJobRow, err: unknown): Promise<void> {
  const jobId = Number(claimed.id);
  const message = err instanceof Error ? err.message : String(err);
  const kind = classifyFailure(err);

  logger.error(
    { jobId, deviceId: claimed.device_id, errorKind: kind, err },
    'change job FAILED',
  );

  try {
    const current = (await db('change_jobs').where({ id: jobId }).first('*')) as
      | ChangeJobRow
      | undefined;
    if (!current) return;

    // A dead-man may still be on the box. Say so on the row: an operator who
    // reads "failed" and nothing else will not go looking for a scheduler that
    // reverts his colleague's change at the next power cut.
    let armedNotDisarmed =
      current.deadman_armed_at !== null && current.deadman_disarmed_at === null;

    // ── BEFORE THE FRONTIER, THE NET PROTECTS NOTHING ───────────────────────
    //
    // The job stopped after its preflight backup (the blob is kept on the
    // router) and possibly after arming the dead-man, but BEFORE any
    // configuration command was transmitted: a render refusal, the kill switch
    // read at step 7, a session that never opened (`applyFrontier.ts`).
    // Nothing was applied, so there is nothing for the net to undo — left
    // armed, its scheduler fires at the deadline and `/system/backup/load`
    // reboots the router into the configuration it already has. That reboot is
    // decided by nobody. So the net comes down: scheduler and script, then the
    // blob, proven on a fresh session, each recorded as a step. If that cannot
    // be proven, the job error AND a live alert say when the router reboots.
    let releaseNote = '';
    if (s && s.netOnDevice && !s.configMayHaveLanded && !s.postcheckPassed) {
      const verdict = await takeDownUnusedNet(s, current);
      releaseNote = verdict.note;
      // The release's note states the net's state in full; the generic
      // "STILL ARMED" suffix below would repeat it.
      armedNotDisarmed = false;
    }

    // ── THE NET COMES DOWN ONLY FOR A CHANGE WE PROVED GOOD ─────────────────
    //
    // Leaving a dead-man armed is the SAFE default and stays the default here:
    // an apply that threw, a box that never answered again, a postcheck that
    // did not hold — in every one of those the router reverting itself is the
    // correct ending, and disarming would be us cancelling the only net the
    // customer has, from a code path that has just admitted it does not know
    // what state the box is in.
    //
    // There is exactly one case where the opposite is true: the write landed,
    // the box answered, the post-conditions were MEASURED and held, and the job
    // then failed on something of ours — a lost lease, an interrupted soak, a
    // disarm that did not take. That job's change is good. Concluding `failed`
    // with the scheduler still counting hands the customer a revert nobody
    // decided on, ten minutes later, of a change that worked.
    //
    // So: `postcheckPassed` and nothing weaker — except the case above, where
    // nothing was sent at all. A disarm that fails changes nothing — the row
    // keeps saying STILL ARMED, which is the truth.
    let disarmNote = '';
    if (s && s.postcheckPassed && armedNotDisarmed) {
      try {
        const executor = await resolveExecutor();
        if (executor) {
          await executor.disarmDeadman(s.ctx);
          await db('change_jobs').where({ id: jobId }).update({
            deadman_disarmed_at: db.fn.now(),
            updated_at: db.fn.now(),
          });
          armedNotDisarmed = false;
          disarmNote =
            ' The post-conditions had already been verified, so the dead-man was disarmed ' +
            'before this job was closed: the change stands, only the job failed.';
          logger.warn(
            { jobId, deviceId: claimed.device_id },
            'change job failed AFTER a verified change — dead-man disarmed so a good change ' +
              'is not reverted by the router',
          );
        }
      } catch (disarmErr) {
        logger.error(
          { err: disarmErr, jobId, deviceId: claimed.device_id },
          'change job: the dead-man could not be disarmed on the failure path; the device WILL ' +
            'restore itself',
        );
      }
    }

    const operatorMessage =
      message +
      releaseNote +
      disarmNote +
      (armedNotDisarmed
        ? ` A dead-man is STILL ARMED on this device (handle ${current.deadman_handle ?? '?'}). ` +
          'It will restore the pre-change configuration at its deadline or at the next boot.'
        : '');

    if (current.status === 'failed' || current.status === 'rolled_back' ||
        current.status === 'succeeded' || current.status === 'aborted') {
      return; // already terminal — a second hand on the row is a second truth
    }

    // Every failure of this kind, including the ones before its branch in
    // runPhases (bind_assert, kill switch, guard), reaches the allocation.
    // Mirrored before the job leaves the active set, so no newer job's mirror
    // can land first. Never throws. `errorKind` is what the row is about to
    // say: the failure's one alert reads it to tell a retry from a refusal.
    if (claimed.kind === 'concentrator_secret') {
      await settleConcentratorSecret(claimed, { ok: false, error: message, errorKind: kind });
    }
    // Same for os_upgrade: an outcome its own step recorded is kept; a failure
    // before any step of its branch is recorded here. Never throws.
    if (claimed.kind === 'os_upgrade') {
      await settleOsUpgrade(claimed, operatorMessage);
    }
    // And for management_access: `refused` when nothing was written on the
    // router, `failed` after a write. Never throws.
    if (claimed.kind === 'management_access') {
      await settleManagementAccess(claimed, operatorMessage);
    }
    // And for lte_apn, the same rule.
    if (claimed.kind === 'lte_apn') {
      await settleLteApn(claimed, operatorMessage);
    }
    // And for legacy_compliance (an outcome its postcheck recorded is kept).
    if (claimed.kind === 'legacy_compliance') {
      await settleLegacyCompliance(claimed, operatorMessage);
    }
    // And for site_rename: `unsettled` when the router may hold a new name,
    // `failed` after a CHR write, `refused` otherwise. Never throws.
    if (claimed.kind === 'site_rename') {
      await settleSiteRename(claimed, operatorMessage);
    }
    // And for infra_account: the account registry keeps its state unless the
    // job read the concentrator and found the account wrong. Never throws.
    if (claimed.kind === 'infra_account') {
      await settleInfraAccount(claimed, { ok: false, error: operatorMessage });
    }
    // And for wan_link: the outcome, the planned-cut window closed (the held
    // alerts are released), the password wiped. Never throws.
    if (claimed.kind === 'wan_link') {
      await settleWanLink(claimed, operatorMessage);
    }

    await transitionJob(current, 'failed', {
      errorKind: kind,
      errorMessage: operatorMessage,
      outcome: null,
    });

    if (s) await recordOutcome(s, 'failed', kind);
  } catch (inner) {
    logger.error({ err: inner, jobId }, 'change job: could not even record the failure');
  }
}

/** `commit_confirm_timeout`'s own default, for dating a reboot when the job's
 *  window was never resolved (it always is before arming; this is the floor). */
const FALLBACK_DEADMAN_SECONDS = 600;

function parisTime(d: Date): string {
  return d.toLocaleString('fr-FR', {
    timeZone: 'Europe/Paris', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit',
  });
}

/**
 * Take an UNUSED net back off the router (see the box in `failJob`).
 *
 * Only ever called when no configuration command was transmitted
 * (`configMayHaveLanded` false) and the executor had left something of this
 * job on the box (`netOnDevice`). Records a `disarm` step (scheduler and
 * script) and a `cleanup` step (the preflight blob), stamps
 * `deadman_disarmed_at` when the removal is PROVEN on a row that recorded an
 * arming (migration 009 refuses a disarm without an arm), and returns the
 * sentence the job's error carries. When the dead-man may still be on the box,
 * a live alert says when the router reboots.
 *
 * Never throws: it runs on the failure path, after the job has already lost.
 */
async function takeDownUnusedNet(
  s: RunState,
  row: ChangeJobRow,
): Promise<{ note: string; stillArmed: boolean }> {
  const jobId = Number(s.job.id);
  const armAttempted = s.armAttemptedAt !== null || row.deadman_armed_at !== null;
  const deadline = row.confirm_deadline
    ? new Date(row.confirm_deadline)
    : s.armAttemptedAt
      ? new Date(
          s.armAttemptedAt.getTime() + (s.ctx.deadmanSeconds ?? FALLBACK_DEADMAN_SECONDS) * 1000,
        )
      : null;
  const handleText = row.deadman_handle ?? s.ctx.deadmanHandle ?? `the dead-man of job #${jobId}`;

  // The lease is held while the box is cleaned: `disarmWithRetry` may take a
  // minute against a box that answers slowly, and a reaper that failed the
  // row mid-cleanup would only add a second account of the same night.
  const keepAlive = setInterval(() => {
    void renewLease(jobId, s.workerId).catch(() => undefined);
  }, 30_000);
  keepAlive.unref?.();

  let release: NetRelease;
  let disarmStep: StepHandle | null = null;
  try {
    disarmStep = await startStep(s.job, s.seq++, 'disarm').catch(() => null);
    const executor = await resolveExecutor();
    release = executor?.releaseUnusedNet
      ? await executor.releaseUnusedNet(s.ctx)
      : {
          entriesRemoved: false,
          blobRemoved: false,
          detail: 'the installed executor cannot release a net (it has no releaseUnusedNet())',
        };
  } catch (err) {
    release = {
      entriesRemoved: false,
      blobRemoved: false,
      detail: `the release could not run: ${err instanceof Error ? err.message : String(err)}`,
    };
  } finally {
    clearInterval(keepAlive);
  }

  // ── The trace: two steps, because they are two facts ─────────────────────
  try {
    if (disarmStep) {
      await finishStep(
        s.job,
        disarmStep,
        release.entriesRemoved ? 'succeeded' : 'failed',
        release.entriesRemoved
          ? {
              output:
                'nothing had been transmitted, so the unused dead-man was removed: ' + release.detail,
              detail: { nothingTransmitted: true, entriesRemoved: true },
            }
          : {
              error:
                (armAttempted
                  ? 'nothing had been transmitted, but the dead-man could NOT be removed: '
                  : 'nothing had been transmitted; no dead-man had been installed, and the ' +
                    'router could not be cleaned: ') + release.detail,
              detail: { nothingTransmitted: true, entriesRemoved: false },
            },
      );
    }
    if (release.blobRemoved) {
      const h = await startStep(s.job, s.seq++, 'cleanup');
      await finishStep(s.job, h, 'succeeded', {
        output: 'the pre-change backup kept on the router for the dead-man was erased and verified absent',
        detail: { blobRemoved: true },
      });
    } else if (release.entriesRemoved) {
      const h = await startStep(s.job, s.seq++, 'cleanup');
      await finishStep(s.job, h, 'failed', {
        error:
          'the pre-change backup kept on the router could NOT be proven erased: a copy of the ' +
          `configuration may remain on it (${release.detail})`,
        detail: { blobRemoved: false },
      });
    } else {
      await skipStep(
        s.job,
        s.seq++,
        'cleanup',
        'Not attempted: the pre-change backup stays on the router while the dead-man that loads ' +
          'it may still be there (entries first, blob last).',
      );
    }
  } catch (err) {
    logger.error({ err, jobId }, 'change job: could not record the release of an unused net');
  }

  if (release.entriesRemoved) {
    try {
      // Guarded on `deadman_armed_at`: `change_jobs_deadman_chk` refuses a
      // disarm stamp on a row that never recorded an arming, and on such a row
      // there is no "armed" to correct.
      await db('change_jobs')
        .where({ id: jobId })
        .whereNotNull('deadman_armed_at')
        .whereNull('deadman_disarmed_at')
        .update({ deadman_disarmed_at: db.fn.now(), updated_at: db.fn.now() });
    } catch (err) {
      logger.error({ err, jobId }, 'change job: the unused net was removed but deadman_disarmed_at could not be written');
    }
    logger.warn(
      { jobId, deviceId: s.device.id, blobRemoved: release.blobRemoved },
      'change job failed BEFORE any configuration command — the unused dead-man was taken down',
    );
    return {
      stillArmed: false,
      note: release.blobRemoved
        ? ' NOTHING WAS WRITTEN to the router: the job stopped before its first configuration ' +
          'command. The safety net it had installed was removed (' + release.detail + '), so ' +
          'the router will not reboot and keeps no copy of its configuration.'
        : ' NOTHING WAS WRITTEN to the router: the job stopped before its first configuration ' +
          'command. The dead-man was removed, so the router will not reboot; but the pre-change ' +
          'backup kept on it could not be proven erased (' + release.detail + ') — remove it by hand.',
    };
  }

  if (!armAttempted) {
    return {
      stillArmed: false,
      note:
        ' NOTHING WAS WRITTEN to the router: the job stopped before its first configuration ' +
        'command, and no dead-man had been installed. The pre-change backup kept on the router ' +
        `could not be erased (${release.detail}) — remove it by hand.`,
    };
  }

  // ── The net could not be taken down: the router WILL reboot ──────────────
  const when = deadline ? deadline.toISOString() : 'its deadline';
  logger.fatal(
    { jobId, deviceId: s.device.id, deadline: deadline?.toISOString() ?? null, detail: release.detail },
    'UNUSED DEAD-MAN LEFT ARMED — nothing was written, and the router will reboot at the ' +
      'deadline unless the scheduler is removed by hand',
  );
  try {
    await liveAlertService.add(Number(s.job.tenant_id), {
      severity: 'warning',
      title: `${s.device.name} : redémarrage prévu${deadline ? ` vers ${parisTime(deadline)}` : ''}`,
      message:
        `La tâche n° ${jobId} (${s.job.kind}) s'est arrêtée avant d'envoyer la moindre commande ` +
        'de configuration, mais son dead-man n\'a pas pu être retiré du routeur. Le routeur ' +
        `redémarrera${deadline ? ` vers ${parisTime(deadline)} (heure de Paris)` : ' à l\'échéance'} ` +
        'en rechargeant sa propre sauvegarde préalable — sans rien restaurer — sauf si le ' +
        `planificateur et le script de la tâche (${handleText}) sont retirés à la main avant. ` +
        `Détail : ${release.detail}`,
      navigateTo: `/changes/${jobId}`,
      deviceId: s.device.id,
      stableKey: `deadman-unused-armed:${jobId}`,
    });
  } catch (err) {
    logger.error({ err, jobId }, 'change job: could not raise the live alert for an unused dead-man left armed');
  }
  return {
    stillArmed: true,
    note:
      ' NOTHING WAS WRITTEN to the router: the job stopped before its first configuration ' +
      `command — but its dead-man is STILL ARMED and could not be removed (${release.detail}). ` +
      `THE ROUTER WILL REBOOT around ${when} and reload its own pre-change backup, restoring ` +
      `nothing, unless the scheduler and script of ${handleText} are removed by hand before then.`,
  };
}

/**
 * Refuse to go further while this process is shutting its worker down
 * (`isChangeWorkerStopping`). Thrown BEFORE the write frontier only, so the
 * job fails with nothing configured and `failJob` takes whatever net it had
 * installed back off the router.
 */
function refuseIfStopping(before: string): void {
  if (isChangeWorkerStopping()) {
    throw new ChangeRefusedError(
      'worker_stopping',
      `The server is shutting down: this job stopped before ${before}, and nothing was ` +
        'configured on the router. Queue it again once the server is back.',
    );
  }
}

/**
 * Cross the write frontier, persisted (migration 099): ONE UPDATE that proves
 * this worker still holds the job — `applying`, claimed by it — renews the
 * lease and stamps `transmit_started_at`. The reaper's "nothing was sent"
 * (`transmit_started_at` NULL, lease expired) and this stamp are serialised by
 * the row lock, so they cannot both win: when this throws `LeaseLostError`,
 * the caller sends NOTHING.
 */
async function crossWriteFrontier(jobId: number, workerId: string): Promise<void> {
  const n = await db('change_jobs')
    .where({ id: jobId, claimed_by: workerId, status: 'applying' })
    .update({
      transmit_started_at: db.raw('COALESCE(transmit_started_at, now())'),
      lease_expires_at: db.raw(`now() + (? || ' milliseconds')::interval`, [String(LEASE_TTL_MS)]),
      updated_at: db.fn.now(),
    });
  if (n === 0) throw new LeaseLostError(jobId);
}

// ============================================================================
// The leader's half: nets left by a DEAD worker
// ============================================================================

/**
 * Release what a generic write job left on its router when its worker died —
 * the jobs `reapExpiredLeases()` failed and listed in `netsOwed`.
 *
 * `failJob` and the lease-lost path do this for a worker that is alive. A
 * crash, an OOM kill or a routine redeploy (the shutdown grace is 8 s) leaves
 * the job to the reaper, which used to fail it and do nothing else: its
 * dead-man then fired at the deadline and rebooted the router — into the
 * configuration it already had (`unused_net`), or out of a change already
 * proven good (`verified_change`). Neither reboot follows from any decision.
 *
 * The scheduler, script and blob names derive from the job id
 * (`deadmanNames`), so the release needs nothing of the dead worker's memory.
 * Every outcome is appended to the job's error message, and a release that
 * cannot be proven raises the same live alert as on the live path. Never
 * throws.
 */
export async function releaseNetsOfReapedJobs(jobs: readonly ReapedNetJob[]): Promise<void> {
  for (const j of jobs) {
    try {
      await releaseNetOfReapedJob(j);
    } catch (err) {
      logger.error({ err, jobId: j.id }, 'change job: the release of a net left by a dead worker failed to run');
    }
  }
}

// Registered when this module loads: it is the runner the worker is started
// with, so the reaper can never run in a process where it is absent.
setReapedNetReleaser(releaseNetsOfReapedJobs);

async function releaseNetOfReapedJob(j: ReapedNetJob): Promise<void> {
  const row = (await db('change_jobs').where({ id: j.id }).first('*')) as ChangeJobRow | undefined;
  // Only what the reaper itself concluded, and only once.
  if (!row || row.status !== 'failed' || row.error_kind !== 'worker_lost') return;
  if (j.mode === 'verified_change' && row.deadman_disarmed_at !== null) return;

  // The step the dead worker was in never finished: say so, rather than leave
  // it `running` on a failed job for ever.
  await db('change_job_steps')
    .where({ job_id: row.id, status: 'running' })
    .update({
      status: 'failed',
      finished_at: db.fn.now(),
      error_redacted: 'the worker was lost during this step (crash or restart); the job was failed by the reaper',
    })
    .catch((err: unknown) => logger.error({ err, jobId: j.id }, 'change job: could not close the step a dead worker left running'));

  const device = await loadDeviceRecord(row.tenant_id, row.device_id);
  let window: ApplyWindow | null = null;
  try {
    window = await resolveApplyWindow(row.tenant_id, row.device_id);
  } catch {
    window = null;
  }
  const lastSeq = (await db('change_job_steps')
    .where({ job_id: row.id, attempt: row.attempt })
    .max<{ m: number | null }>('seq as m')
    .first()) as { m: number | null } | undefined;

  // Arming starts right after the lease renewal that precedes it, so a job
  // reaped in `arming` before it recorded `confirm_deadline` armed at about
  // `lease_expires_at - LEASE_TTL_MS`. Dates the reboot an unremoved net causes.
  const armAttemptedAt =
    j.reapedFrom === 'backing_up'
      ? null
      : row.deadman_armed_at
        ? new Date(row.deadman_armed_at)
        : j.leaseExpiredAt
          ? new Date(j.leaseExpiredAt.getTime() - LEASE_TTL_MS)
          : null;

  const s: RunState = {
    seq: Number(lastSeq?.m ?? -1) + 1,
    job: row,
    device,
    startedAt: Date.now(),
    workerId: WORKER_ID,
    wroteToDevice: j.mode === 'verified_change',
    postcheckPassed: j.mode === 'verified_change',
    netOnDevice: true,
    armAttemptedAt,
    configMayHaveLanded: j.mode === 'verified_change',
    rollbackObserved: false,
    window,
    ctx: {
      job: row,
      device,
      ops: [],
      planId: row.plan_id === null ? null : Number(row.plan_id),
      correlationId: crypto.randomUUID(),
      safetyLevel: row.safety_level,
      safetyPeerDeviceId: row.safety_peer_device_id,
      preflightBackupId: row.preflight_backup_id === null ? null : Number(row.preflight_backup_id),
      deadmanHandle: row.deadman_handle,
      deadmanSeconds: window?.deadmanSeconds ?? null,
    },
  };

  const note = j.mode === 'unused_net'
    ? (await takeDownUnusedNet(s, row)).note
    : await disarmVerifiedChangeOfDeadWorker(s, row);

  await db('change_jobs')
    .where({ id: row.id, status: 'failed' })
    .update({
      error_message: `${row.error_message ?? ''} OUTCOME:${note}`.slice(0, 8000),
      updated_at: db.fn.now(),
    });
}

/**
 * `failJob`'s one disarm, for a dead worker: the change was applied and its
 * post-conditions MEASURED to hold, so the dead-man would only revert a good
 * change with a reboot. Recorded as a `disarm` step; when it cannot be done
 * the router WILL revert, and a live alert says when.
 */
async function disarmVerifiedChangeOfDeadWorker(s: RunState, row: ChangeJobRow): Promise<string> {
  const jobId = Number(row.id);
  const handle = await startStep(row, s.seq++, 'disarm').catch(() => null);
  try {
    const executor = await resolveExecutor();
    if (!executor) throw new Error('no change executor is installed on this build');
    await executor.disarmDeadman(s.ctx);
    await db('change_jobs')
      .where({ id: jobId })
      .whereNotNull('deadman_armed_at')
      .whereNull('deadman_disarmed_at')
      .update({ deadman_disarmed_at: db.fn.now(), updated_at: db.fn.now() });
    if (handle) {
      await finishStep(row, handle, 'succeeded', {
        output: 'the worker was lost after a verified change: the dead-man was disarmed so it does not revert it',
        detail: { reaped: true, verifiedChange: true },
      });
    }
    logger.warn({ jobId, deviceId: row.device_id }, 'change job: dead-man of a verified change disarmed after its worker was lost');
    return ' The dead-man was disarmed: the change stands and the router will not revert it.';
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    if (handle) {
      await finishStep(row, handle, 'failed', {
        error: `the dead-man of a verified change could NOT be disarmed: ${detail}`,
        detail: { reaped: true, verifiedChange: true },
      }).catch(() => undefined);
    }
    const deadline = row.confirm_deadline ? new Date(row.confirm_deadline) : null;
    logger.fatal(
      { jobId, deviceId: row.device_id, deadline: deadline?.toISOString() ?? null, detail },
      'DEAD-MAN OF A VERIFIED CHANGE LEFT ARMED after its worker was lost — the router will revert it at the deadline',
    );
    try {
      await liveAlertService.add(Number(row.tenant_id), {
        severity: 'warning',
        title: `${s.device.name} : retour arrière prévu${deadline ? ` vers ${parisTime(deadline)}` : ''}`,
        message:
          `La tâche n° ${jobId} (${row.kind}) avait appliqué sa modification et vérifié qu'elle tenait, ` +
          'puis le serveur s\'est arrêté avant de retirer son dead-man, qui n\'a pas pu être retiré ensuite. ' +
          `Le routeur redémarrera${deadline ? ` vers ${parisTime(deadline)} (heure de Paris)` : ' à l\'échéance'} ` +
          'en rechargeant sa sauvegarde préalable, ce qui annulera la modification, sauf si le planificateur ' +
          `et le script de la tâche (${row.deadman_handle ?? `job ${jobId}`}) sont retirés à la main avant. ` +
          `Détail : ${detail}`,
        navigateTo: `/changes/${jobId}`,
        deviceId: s.device.id,
        stableKey: `deadman-verified-armed:${jobId}`,
      });
    } catch (alertErr) {
      logger.error({ err: alertErr, jobId }, 'change job: could not raise the live alert for a verified change left armed');
    }
    return (
      ` The dead-man could NOT be disarmed (${detail}): THE ROUTER WILL REVERT this verified ` +
      `change with a reboot around ${deadline ? deadline.toISOString() : 'its deadline'}, unless ` +
      `the scheduler and script of ${row.deadman_handle ?? `job ${jobId}`} are removed by hand.`
    );
  }
}

function classifyFailure(err: unknown): string {
  if (err instanceof KillSwitchEngagedError) return 'kill_switch';
  if (err instanceof BindingAssertionError) return 'binding_mismatch';
  if (err instanceof StalePlanError) return 'plan_stale';
  if (err instanceof PlanExpiredError) return 'plan_expired';
  if (err instanceof ChangeRefusedError) return err.kind;
  if (err instanceof Error && err.name) return err.name.slice(0, 48);
  return 'unknown';
}

// ============================================================================
// Step 12 — apply_outcomes ("the laboratory we do not have")
// ============================================================================

/**
 * Append one row to the empirical corpus.
 *
 * ┌─ WHEN A ROW IS WRITTEN, AND WHY NOT ALWAYS ───────────────────────────────┐
 * │ Only once the device has been touched with intent to change it — from     │
 * │ `arming` onward, because installing a dead-man IS a write. A job the      │
 * │ guard refused, or one that died on a stale plan, tells you nothing about  │
 * │ how a 2927 running 4.4.3 behaves under a firewall push, and putting it in │
 * │ the corpus would make the corpus lie in the reassuring direction.         │
 * │                                                                          │
 * │ THE MAPPING IS PESSIMISTIC AND SAYS SO. `APPLY_OUTCOMES` has three        │
 * │ values. A post-write failure is `rolled_back` ONLY if a rollback was      │
 * │ OBSERVED; everything else lands in `lost_contact` with the real           │
 * │ `failure_kind` beside it. That over-reports the worst outcome, which is   │
 * │ the safe direction for a memory whose whole job is to warn — and it is    │
 * │ recorded here so nobody later reads a `lost_contact` count as a van       │
 * │ count without checking `failure_kind`.                                    │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
async function recordOutcome(
  s: RunState,
  result: 'succeeded' | 'failed',
  failureKind: string | null,
): Promise<void> {
  const { job, device } = s;
  if (!isWriteJobKind(job.kind)) return;

  // `apply_outcomes` is the corpus of changes made under a net on equipment,
  // and its outcomes (`rolled_back`, `lost_contact`) mean nothing for an
  // additive /ppp/secret entry; migration 040 left `op_kind` without this kind.
  if (job.kind === 'concentrator_secret') {
    await skipStep(
      s.job,
      s.seq++,
      'record_outcome',
      "No row written to apply_outcomes: 'concentrator_secret' is an additive /ppp/secret entry " +
        'made with no net, not an observation of how this hardware survives a change. Its outcome ' +
        'is on concentrator_secret_jobs.',
    );
    return;
  }
  // Migration 047 left `op_kind` without this kind either (its header, 2).
  if (job.kind === 'os_upgrade') {
    await skipStep(s.job, s.seq++, 'record_outcome', OS_UPGRADE_NO_APPLY_OUTCOME);
    return;
  }
  // Migration 053 left `op_kind` without this kind too (its header, 2).
  if (job.kind === 'concentrator_link') {
    await skipStep(s.job, s.seq++, 'record_outcome', CONCENTRATOR_LINK_NO_APPLY_OUTCOME);
    return;
  }
  // And migration 058 left it without this one (its header, 2).
  if (job.kind === 'management_access') {
    await skipStep(s.job, s.seq++, 'record_outcome', MANAGEMENT_ACCESS_NO_APPLY_OUTCOME);
    return;
  }
  // Nor did 065 for lte_apn.
  if (job.kind === 'lte_apn') {
    await skipStep(s.job, s.seq++, 'record_outcome', LTE_APN_NO_APPLY_OUTCOME);
    return;
  }
  // Nor did 066 for legacy_compliance.
  if (job.kind === 'legacy_compliance') {
    await skipStep(s.job, s.seq++, 'record_outcome', LEGACY_COMPLIANCE_NO_APPLY_OUTCOME);
    return;
  }
  // Nor does 088 for site_rename.
  if (job.kind === 'site_rename') {
    await skipStep(s.job, s.seq++, 'record_outcome', SITE_RENAME_NO_APPLY_OUTCOME);
    return;
  }
  // Nor does 074 for infra_account.
  if (job.kind === 'infra_account') {
    await skipStep(s.job, s.seq++, 'record_outcome', INFRA_ACCOUNT_NO_APPLY_OUTCOME);
    return;
  }
  // Nor does 090 for wan_link.
  if (job.kind === 'wan_link') {
    await skipStep(s.job, s.seq++, 'record_outcome', WAN_LINK_NO_APPLY_OUTCOME);
    return;
  }

  const armed = s.ctx.deadmanHandle !== null || s.wroteToDevice;
  if (!armed) {
    await skipStep(
      s.job,
      s.seq++,
      'record_outcome',
      'No row written to apply_outcomes: this job never touched the device, so it is not an ' +
        'observation about this hardware. (the corpus must not be padded with our own ' +
        'refusals.)',
    );
    return;
  }

  const outcome =
    result === 'succeeded' ? 'succeeded' : s.rollbackObserved ? 'rolled_back' : 'lost_contact';

  await step(s, 'record_outcome', async () => {
    await db('apply_outcomes').insert({
      tenant_id: job.tenant_id,
      device_id: device.id,
      job_id: job.id,
      op_kind: job.kind,
      resource: null,
      brand: device.brand,
      model: device.model,
      os_version: device.os_version,
      outcome,
      safety_level: job.safety_level,
      guard_verdict: job.guard_verdict,
      was_override: Boolean(job.override_reason),
      ops_count: s.ctx.ops.length,
      duration_ms: Date.now() - s.startedAt,
      failure_kind: failureKind,
      detail_redacted: JSON.stringify({
        rollbackObserved: s.rollbackObserved,
        wroteToDevice: s.wroteToDevice,
        overridden: Boolean(job.override_reason),
      }),
    });
    return {
      output: `apply_outcomes: ${outcome} (${device.brand} ${device.model ?? '?'} ${
        device.os_version ?? '?'
      })`,
    };
  });
}

// ============================================================================
// Plan ops
// ============================================================================

async function loadPlanOps(job: ChangeJobRow): Promise<unknown[]> {
  if (job.plan_id === null) return [];
  const row = (await db('change_plans')
    .where({ id: job.plan_id, tenant_id: job.tenant_id })
    .first('ops', 'invalidated_at')) as
    | { ops: unknown; invalidated_at: Date | null }
    | undefined;
  if (!row) {
    throw new ChangeRefusedError('plan_missing', `The frozen plan of job ${job.id} is gone.`);
  }
  if (row.invalidated_at) {
    throw new ChangeRefusedError(
      'plan_invalidated',
      'This plan was invalidated (the device moved under us). Recompile it.',
    );
  }
  const ops = typeof row.ops === 'string' ? (JSON.parse(row.ops) as unknown) : row.ops;
  return Array.isArray(ops) ? ops : [];
}

// ============================================================================
// Barrel
// ============================================================================

export const applyService = {
  enqueueChangeJob,
  previewChange,
  recordOverride,
  runJob,
  currentExecutor,
  evaluateGuardForPlan,
  resolveSafetyNet,
  setChangeExecutor,
};

// `auditedCommand` / `recordCommandIntent` are re-exported here so the executor
// module has one import for "the audited way to talk to a device" and
// cannot accidentally reach the transport without leaving a trace first.
//
// THE RULE IS NOT ENFORCED BY THIS RE-EXPORT AND NEVER WAS. It is enforced one
// layer down, in `backup.service.DeviceSession.run()`, which is the single
// place in this tree where a sentence leaves for an equipment and which now
// goes through `auditedCommand()` itself: the intent row is INSERTed before
// `conn.query`, with no try/catch, so an audit that cannot be written stops the
// command instead of following it. Nothing in `services/change/` opens a socket
// except through that class.
export { auditedCommand, recordCommandIntent };
