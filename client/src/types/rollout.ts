// ObliWAN client — wave rollout DTOs.
//
// Same rule as `types/change.ts`: the VOCABULARIES that already exist in
// `@obliwan/shared` are never redeclared here. `SafetyLevel`, `RiskLevel`,
// `ChangeJobKind`, `ChangeJobStatus` are the frozen change-queue contract, and a rollout
// is nothing but an ordered set of the jobs that contract describes.
//
// What IS declared here is the rollout envelope — waves, health gates, quarantine —
// because `shared/src` has no rollout module yet and this client must not
// invent one there (`shared/src/index.ts` is the contract barrel).
//
// ── THE ONE RULE OF THIS FILE ───────────────────────────────────────────────
// A wave carries the SAFETY NET of every device in it, and an unknown net is
// `DEGRADED`. The safety-net rule: "Un rollout par vagues qui mélange des devices ARMÉ et
// DÉGRADÉ traite les DÉGRADÉ en dernier." That ordering is a property of the
// composition, so the composition is a first-class object here —
// `WaveComposition` — and not a devices-per-wave number computed inside a
// render function where nobody can see it.

import type {
  ChangeJobKind,
  ChangeJobStatus,
  ObjectAccess,
  RiskLevel,
} from '@obliwan/shared';
import type { DeviceImpact, SafetyNetLevel } from '@/types/change';

// ── Status vocabularies ─────────────────────────────────────────────────────
//
// Mirrors what the `rollouts` / `rollout_waves` tables will hold. Every
// normaliser in `rollout.api.ts` folds an unrecognised value to the PESSIMISTIC
// member of these lists, never to a reassuring one.

export const ROLLOUT_STATUSES = [
  'draft',
  'running',
  'paused',
  'halted',      // a health gate refused; waves already applied stay applied
  'aborted',     // a human stopped it
  'rolled_back', // the applied waves were reverted
  'succeeded',
  'failed',
] as const;
export type RolloutStatus = (typeof ROLLOUT_STATUSES)[number];

export const ACTIVE_ROLLOUT_STATUSES: readonly RolloutStatus[] = [
  'draft', 'running', 'paused',
];

export const WAVE_STATUSES = [
  'pending',
  'running',
  'gating',      // applied, waiting for the health gates to conclude
  'passed',
  'failed',
  'rolled_back',
  'skipped',
] as const;
export type WaveStatus = (typeof WAVE_STATUSES)[number];

/**
 * The five health gates of a rollout, plus the one the Netwatch rule adds.
 *
 * They are named rather than numbered because the operator must be able to
 * read WHICH signal refused a wave. "Gate 3 failed" is a support ticket; "no
 * new ifInErrors: FAILED on 2 of 5 devices" is a diagnosis.
 */
export const HEALTH_GATE_KINDS = [
  'ppp_session',    // the PPP session came back up on the concentrator
  'oper_status',    // ifOperStatus up on the interfaces that were up before
  'if_errors',      // no NEW ifInErrors since the apply
  'rtt_baseline',   // RTT within tolerance of the 7-day baseline
  'no_boot',        // no unexpected BOOT (sysUpTime went backwards)
  'netwatch',       // the Netwatch rule — the CLIENT's service is still answering
] as const;
export type HealthGateKind = (typeof HEALTH_GATE_KINDS)[number];

export const GATE_STATES = ['pending', 'pass', 'fail', 'unknown', 'skipped'] as const;
export type GateState = (typeof GATE_STATES)[number];

// ── Views ───────────────────────────────────────────────────────────────────

export interface HealthGateView {
  kind: HealthGateKind;
  /** `unknown` is NOT a pass. A gate whose signal never arrived proved nothing,
   *  and the wave screen paints it on the refusing side. */
  state: GateState;
  /** Devices that failed this gate, by id — the drill-down target. */
  failedDeviceIds: number[];
  observedAt: string | null;
  /** Server sentence, shown verbatim. */
  detail: string | null;
}

export interface RolloutTargetView {
  deviceId: number;
  deviceName: string | null;
  siteId: number | null;
  siteName: string | null;
  brand: string;
  waveIndex: number;
  /** The net this device gets. Unknown folds to DEGRADED. */
  safetyNet: SafetyNetLevel;
  safetyPeerDeviceName: string | null;
  /** The job this target became, once its wave started. */
  jobId: number | null;
  jobStatus: ChangeJobStatus | null;
  /** Terminal outcome as the rollout records it, independent of the job row. */
  outcome: 'pending' | 'applied' | 'rolled_back' | 'failed' | 'skipped';
  errorMessage: string | null;
  /**
   * Set when a failed health gate listed this device « À restaurer
   * manuellement »: the device kept the change, NOTHING restores it
   * automatically, and this is its push job's pre-change backup. Null when no
   * restore is owed (or none was recorded).
   */
  rollbackBackupId: number | null;
  /** LEGACY: the restore job a rollout used to queue (never set now). */
  rollbackJobId: number | null;
}

export interface RolloutWaveView {
  id: number | null;
  rolloutId: number;
  /** 0-based. Wave 0 is the canary by convention, and the UI says so. */
  index: number;
  label: string | null;
  status: WaveStatus;
  deviceIds: number[];
  gates: HealthGateView[];
  /** The server's one verdict for the wave's health gate (shared
   *  `HealthGateVerdict`); null while the wave has not been judged. */
  gateVerdict: 'PASS' | 'FAIL' | 'INDETERMINATE' | null;
  startedAt: string | null;
  finishedAt: string | null;
  succeeded: number;
  rolledBack: number;
  failed: number;
}

export interface RolloutView {
  id: number;
  uuid: string;
  /** God view only: the owning workspace (server utils/globalView.ts). */
  tenantId?: number;
  tenantName?: string | null;
  name: string;
  status: RolloutStatus;
  kind: ChangeJobKind;
  /** The template revision being rolled out, when there is one. */
  revisionId: number | null;
  revision: number | null;
  templateName: string | null;
  deviceCount: number;
  waveCount: number;
  /** Index of the wave currently running, or the last one that ran. */
  currentWave: number | null;
  riskLevel: RiskLevel | null;
  /** Set when a gate refused and the revision was quarantined. */
  quarantinedRevisionId: number | null;
  quarantineReason: string | null;
  pausedReason: string | null;
  requestedByName: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  createdAt: string;
  /** Roll-up counters, so the list does not need every target row. */
  applied: number;
  rolledBack: number;
  failed: number;
  pending: number;
}

export interface RolloutDetail extends RolloutView {
  /** The caller's level on the rollout (migration 087): 'rw' only when every
   *  one of its devices is writable. Absent on an older server. */
  access?: ObjectAccess;
  waves: RolloutWaveView[];
  targets: RolloutTargetView[];
}

// ── The pre-launch impact radius ────────────────────────────────────────────

/**
 * One device on the impact-radius screen.
 *
 * `impact` is the change impact preview (`POST /changes/preview`) — the REAL safety net
 * and the REAL Management-Path Guard verdict for this box. `planCompiled` is
 * the N-plans-before-launch of the rollout (`POST /plan/compile`). Either may be
 * missing, and when either is missing the row SAYS so instead of showing a
 * blank cell: a device whose plan would not compile is a device that must not
 * quietly end up in wave 0.
 */
export interface ImpactRow {
  deviceId: number;
  deviceName: string;
  siteName: string | null;
  brand: string;
  role: string;
  concentratorId: number | null;
  /** Devices this one carries, when it IS a concentrator. */
  subtreeSize: number;
  impact: DeviceImpact | null;
  /** Why no impact could be computed. Shown; never swallowed. */
  impactError: string | null;
  planCompiled: boolean;
  planError: string | null;
  changeOpCount: number;
  riskLevel: RiskLevel | null;
  touchesManagementPath: boolean;
  /** Folded from `impact`; DEGRADED when there is no impact at all. */
  safetyNet: SafetyNetLevel;
}

/** One wave, as the client composes it BEFORE anything is sent. */
export interface WaveComposition {
  index: number;
  label: string;
  rows: ImpactRow[];
}

/**
 * The whole pre-launch screen in one object.
 *
 * `blockers` is a LIST of sentences and not a boolean because an operator who
 * cannot launch is entitled to know every reason at once rather than one per
 * attempt.
 */
export interface ImpactRadius {
  rows: ImpactRow[];
  waves: WaveComposition[];
  degradedCount: number;
  guardRefusedCount: number;
  concentratorCount: number;
  /** Sites that lose management if a concentrator in the set goes down
   *  ("son rayon d'impact est le sous-arbre entier"). */
  subtreeSiteCount: number;
  blockers: string[];
  warnings: string[];
}

// The launch request is `@obliwan/shared`'s `RolloutComposeBody`: the server
// composes the waves (`planWaves`) and the screen shows them; it never posts
// a ladder of its own.

// ── Safety-net ordering, the safety-net rule made executable ────────────────

const NET_ORDER: Record<SafetyNetLevel, number> = {
  ARMED: 0,
  ARMED_BY_PEER: 1,
  DEGRADED: 2,
};

/**
 * The safety-net rule, literally: DEGRADED devices are treated LAST.
 *
 * The comparison is (net, concentrator-last, name). Concentrators sort after
 * their peers WITHIN the same net because the concentrator interlock makes their blast radius the
 * whole subtree — a canary wave must never open on one.
 */
export function compareForWaveOrder(a: ImpactRow, b: ImpactRow): number {
  const net = NET_ORDER[a.safetyNet] - NET_ORDER[b.safetyNet];
  if (net !== 0) return net;
  const conc = Number(a.role === 'concentrator') - Number(b.role === 'concentrator');
  if (conc !== 0) return conc;
  return a.deviceName.localeCompare(b.deviceName);
}
