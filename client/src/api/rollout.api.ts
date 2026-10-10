import apiClient from './client';
import type {
  ApiResponse,
  ApplyPlan,
  ChangeJobKind,
  PlannedWave,
  RiskLevel,
  RolloutComposeBody,
} from '@obliwan/shared';
import { CHANGE_JOB_STATUSES } from '@obliwan/shared';
import { isRouteAbsent, normalizeGuard, normalizeSafetyNet } from './change.api';
import { accessField } from '../utils/objectAccess';
import type { DeviceImpact } from '@/types/change';
import type { ManagementAccessComposition } from '@/components/fleet/managementAccess.api';
import type {
  GateState,
  HealthGateKind,
  HealthGateView,
  RolloutDetail,
  RolloutStatus,
  RolloutTargetView,
  RolloutView,
  RolloutWaveView,
  WaveStatus,
} from '@/types/rollout';
import {
  GATE_STATES,
  HEALTH_GATE_KINDS,
  ROLLOUT_STATUSES,
  WAVE_STATUSES,
} from '@/types/rollout';

/**
 * Wave rollouts.
 *
 * ── THE ROUTES ──────────────────────────────────────────────────────────────
 *   GET    /api/rollouts?status&limit          -> RolloutView[]
 *   GET    /api/rollouts/config                -> { canLaunch, milestone, gates }
 *   GET    /api/rollouts/:id                   -> rollout + waves + targets
 *   POST   /api/rollouts/preview               -> the server's composition, nothing written
 *   POST   /api/rollouts                       -> compose a DRAFT (RolloutComposeBody)
 *   POST   /api/rollouts/:id/launch            -> start the draft
 *   POST   /api/rollouts/:id/pause             -> { reason }
 *   POST   /api/rollouts/:id/resume            -> {}
 *   POST   /api/rollouts/:id/abort             -> { reason }
 *
 * ── THE SERVER COMPOSES THE WAVES, THE SCREEN SHOWS THEM ────────────────────
 * A template push used to be composed HERE (sliders for the canary and the
 * second wave, a client-side ordering) and posted as `{ kind, waves, ... }` —
 * a body the server's strict schema refused with a 400, and a ladder it would
 * have ignored anyway: `planWaves` (shared/src/rollout.ts) composes 1 → 5% →
 * 25% → the rest, degraded routers last. And even a valid body only wrote a
 * draft: nothing ever called `/:id/launch`. So a push now goes the way
 * management_access and legacy_compliance already did: `previewPush` asks
 * the server for its composition (every plan compiled against the ONE pinned
 * revision that will be pushed, not against each router's assignment), the
 * screen shows those waves, `compose` writes the draft from the same body and
 * `start` launches it. The bodies are `@obliwan/shared`'s `RolloutComposeBody`
 * / `RolloutPreviewBody`, so the client cannot drift into a second spelling.
 */

type Raw = Record<string, unknown>;

function pick(row: Raw, camel: string): unknown {
  if (camel in row) return row[camel];
  const snake = camel.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);
  return row[snake];
}

function n(v: unknown, fallback: number): number {
  if (v === null || v === undefined || v === '') return fallback;
  const x = typeof v === 'number' ? v : Number(v);
  return Number.isFinite(x) ? x : fallback;
}

function nOrNull(v: unknown): number | null {
  if (v === null || v === undefined || v === '') return null;
  const x = typeof v === 'number' ? v : Number(v);
  return Number.isFinite(x) ? x : null;
}

function s(v: unknown): string | null {
  return v === null || v === undefined ? null : String(v);
}

function numbers(v: unknown): number[] {
  return Array.isArray(v) ? v.map((x) => Number(x)).filter((x) => Number.isFinite(x)) : [];
}

function asRows(payload: unknown): Raw[] {
  if (Array.isArray(payload)) return payload as Raw[];
  if (payload && typeof payload === 'object') {
    const p = payload as Raw;
    const items = p.items ?? p.rows ?? p.rollouts ?? p.waves ?? p.targets;
    if (Array.isArray(items)) return items as Raw[];
  }
  return [];
}

// ── Normalisers, all pessimistic ────────────────────────────────────────────

const STATUSES: readonly string[] = ROLLOUT_STATUSES;
const WAVE: readonly string[] = WAVE_STATUSES;
const GATES: readonly string[] = HEALTH_GATE_KINDS;
const GATE_STATE: readonly string[] = GATE_STATES;
const JOB_STATUSES: readonly string[] = CHANGE_JOB_STATUSES;

/** An unrecognised rollout status is `failed`, never `succeeded`. Painting an
 *  unknown terminal state green would tell an operator that twenty routers he
 *  never checked are fine. */
function rolloutStatus(v: unknown): RolloutStatus {
  const str = String(v ?? '');
  return (STATUSES.includes(str) ? str : 'failed') as RolloutStatus;
}

function waveStatus(v: unknown): WaveStatus {
  const str = String(v ?? '');
  return (WAVE.includes(str) ? str : 'failed') as WaveStatus;
}

/** An unrecognised gate state is `unknown`, and `unknown` is NOT a pass. */
function gateState(v: unknown): GateState {
  const str = String(v ?? '');
  return (GATE_STATE.includes(str) ? str : 'unknown') as GateState;
}

function riskLevel(v: unknown): RiskLevel | null {
  const str = String(v ?? '');
  return str === 'low' || str === 'medium' || str === 'high' ? str : null;
}

export function normalizeGate(raw: unknown): HealthGateView | null {
  if (!raw || typeof raw !== 'object') return null;
  const row = raw as Raw;
  const kind = String(pick(row, 'kind') ?? '');
  // A gate we do not know the NAME of cannot be rendered honestly — we would be
  // inventing a label for a signal we cannot describe. Dropped, and the wave
  // header reports the count mismatch instead.
  if (!GATES.includes(kind)) return null;
  return {
    kind: kind as HealthGateKind,
    state: gateState(pick(row, 'state') ?? pick(row, 'status')),
    failedDeviceIds: numbers(pick(row, 'failedDeviceIds')),
    observedAt: s(pick(row, 'observedAt')),
    detail: s(pick(row, 'detail') ?? pick(row, 'message')),
  };
}

/** The server's three-valued gate verdict (shared `HealthGateVerdict`). An
 *  unrecognised value is `INDETERMINATE` — never a pass. */
function gateVerdict(v: unknown): RolloutWaveView['gateVerdict'] {
  if (v === null || v === undefined || v === '') return null;
  const str = String(v);
  return str === 'PASS' || str === 'FAIL' ? str : 'INDETERMINATE';
}

/** A rollout target's status (shared `RolloutTargetStatus`) folded onto the
 *  screen's outcome. An unknown status is `failed`, never `applied`. */
function outcomeOfStatus(v: unknown): RolloutTargetView['outcome'] {
  switch (String(v ?? '')) {
    case 'succeeded': return 'applied';
    case 'pending':
    case 'queued':
    case 'running': return 'pending';
    case 'rolled_back': return 'rolled_back';
    case 'skipped':
    case 'cancelled': return 'skipped';
    default: return 'failed';
  }
}

export function normalizeWave(raw: Raw): RolloutWaveView {
  const gates = (Array.isArray(pick(raw, 'gates')) ? (pick(raw, 'gates') as unknown[]) : [])
    .map(normalizeGate)
    .filter((g): g is HealthGateView => g !== null);
  return {
    id: nOrNull(pick(raw, 'id')),
    rolloutId: n(pick(raw, 'rolloutId'), 0),
    index: n(pick(raw, 'index') ?? pick(raw, 'waveIndex'), 0),
    label: s(pick(raw, 'label')),
    status: waveStatus(pick(raw, 'status')),
    deviceIds: numbers(pick(raw, 'deviceIds')),
    gates,
    // The server sends one verdict per wave (`gateVerdict` + `gateReasons`),
    // not a per-gate list; the detail page shows it when `gates` is empty.
    gateVerdict: gateVerdict(pick(raw, 'gateVerdict')),
    startedAt: s(pick(raw, 'startedAt')),
    finishedAt: s(pick(raw, 'finishedAt')),
    succeeded: n(pick(raw, 'succeeded') ?? pick(raw, 'succeededCount'), 0),
    rolledBack: n(pick(raw, 'rolledBack') ?? pick(raw, 'rolledBackCount'), 0),
    failed: n(pick(raw, 'failed') ?? pick(raw, 'failedCount'), 0),
  };
}

export function normalizeTarget(raw: Raw): RolloutTargetView {
  // The server sends `status` (shared RolloutTargetStatus); `outcome` is the
  // older spelling, still read first.
  const rawOutcome = pick(raw, 'outcome');
  const outcome = rawOutcome !== undefined && rawOutcome !== null
    ? String(rawOutcome)
    : outcomeOfStatus(pick(raw, 'status'));
  const jobStatus = String(pick(raw, 'jobStatus') ?? '');
  return {
    deviceId: n(pick(raw, 'deviceId'), 0),
    deviceName: s(pick(raw, 'deviceName')),
    siteId: nOrNull(pick(raw, 'siteId')),
    siteName: s(pick(raw, 'siteName')),
    brand: String(pick(raw, 'brand') ?? ''),
    waveIndex: n(pick(raw, 'waveIndex') ?? pick(raw, 'index'), 0),
    // The fold happens in ONE place for the whole client and it folds
    // towards the worst reading of an unknown value.
    safetyNet: normalizeSafetyNet(pick(raw, 'safetyNet') ?? pick(raw, 'safetyLevel')),
    safetyPeerDeviceName: s(pick(raw, 'safetyPeerDeviceName') ?? pick(raw, 'peerDeviceName')),
    jobId: nOrNull(pick(raw, 'jobId')),
    jobStatus: JOB_STATUSES.includes(jobStatus)
      ? (jobStatus as RolloutTargetView['jobStatus'])
      : null,
    outcome: (['pending', 'applied', 'rolled_back', 'failed', 'skipped'].includes(outcome)
      ? outcome
      : 'failed') as RolloutTargetView['outcome'],
    errorMessage: s(pick(raw, 'errorMessage') ?? pick(raw, 'note')),
    rollbackBackupId: nOrNull(pick(raw, 'rollbackBackupId')),
    rollbackJobId: nOrNull(pick(raw, 'rollbackJobId')),
  };
}

/**
 * `RolloutSummary` (shared/src/rollout.ts) onto the screen's view. The server
 * spells `templateRevisionId`, `currentWaveIndex`, `succeededCount`,
 * `rolledBackCount`, `failedCount`, `pauseReason`; reading only the older
 * names made every counter 0 on every rollout, management access and
 * compliance included. The older names are still read first.
 */
export function normalizeRollout(raw: Raw): RolloutView {
  const revisionId = nOrNull(pick(raw, 'revisionId') ?? pick(raw, 'templateRevisionId'));
  const deviceCount = n(pick(raw, 'deviceCount'), 0);
  const applied = n(pick(raw, 'applied') ?? pick(raw, 'succeededCount'), 0);
  const rolledBack = n(pick(raw, 'rolledBack') ?? pick(raw, 'rolledBackCount'), 0);
  const failed = n(pick(raw, 'failed') ?? pick(raw, 'failedCount'), 0);
  const quarantinedAt = pick(raw, 'revisionQuarantinedAt');
  return {
    id: n(pick(raw, 'id'), 0),
    uuid: String(pick(raw, 'uuid') ?? ''),
    // God view only: present when the server tagged the row with its workspace.
    ...(pick(raw, 'tenantName') !== undefined
      ? { tenantId: nOrNull(pick(raw, 'tenantId')) ?? undefined, tenantName: s(pick(raw, 'tenantName')) }
      : {}),
    name: String(pick(raw, 'name') ?? ''),
    status: rolloutStatus(pick(raw, 'status')),
    kind: (String(pick(raw, 'kind') ?? 'push')) as ChangeJobKind,
    revisionId,
    revision: nOrNull(pick(raw, 'revision')),
    templateName: s(pick(raw, 'templateName')),
    deviceCount,
    waveCount: n(pick(raw, 'waveCount'), 0),
    currentWave: nOrNull(pick(raw, 'currentWave') ?? pick(raw, 'currentWaveIndex')),
    riskLevel: riskLevel(pick(raw, 'riskLevel')),
    quarantinedRevisionId:
      nOrNull(pick(raw, 'quarantinedRevisionId')) ??
      (quarantinedAt !== null && quarantinedAt !== undefined && quarantinedAt !== '' ? revisionId : null),
    quarantineReason: s(pick(raw, 'quarantineReason')),
    pausedReason: s(pick(raw, 'pausedReason') ?? pick(raw, 'pauseReason')),
    requestedByName: s(pick(raw, 'requestedByName')),
    startedAt: s(pick(raw, 'startedAt')),
    finishedAt: s(pick(raw, 'finishedAt')),
    createdAt: String(pick(raw, 'createdAt') ?? ''),
    applied,
    rolledBack,
    failed,
    pending: nOrNull(pick(raw, 'pending')) ?? Math.max(0, deviceCount - applied - rolledBack - failed),
  };
}

// ── The change preview, mapped onto `DeviceImpact` ──────────────────────────────

/**
 * `POST /api/changes/preview` returns the shape `previewChange()` declares in
 * `server/src/services/change/apply.service.ts` — `{ device, guard, safetyNet,
 * killSwitch, freshness, requiresOverride, requiresDegradedConfirmation }`.
 * That is NOT `DeviceImpact`, and this is the one place the two are bridged.
 *
 * Two foldings matter and both are pessimistic:
 *  - `guard.unavailable === true` becomes `ran: false`, which the badge paints
 *    as NOT RUN, on the refusing side. The guard admitting it could not run is
 *    not the guard concluding.
 *  - `requiresExplicitConfirmation` is OR-ed, never trusted: a DEGRADED net or
 *    a non-ACCEPT verdict demands the confirmation whatever the flags say.
 */
export function impactOfPreview(raw: unknown, fallbackDeviceId: number): DeviceImpact | null {
  if (!raw || typeof raw !== 'object') return null;
  const row = raw as Raw;
  const deviceRaw = (pick(row, 'device') ?? {}) as Raw;
  const netRaw = (pick(row, 'safetyNet') ?? {}) as Raw;
  const guardRaw = pick(row, 'guard');
  const guard = normalizeGuard(guardRaw);
  const unavailable = Boolean(
    guardRaw && typeof guardRaw === 'object' && pick(guardRaw as Raw, 'unavailable'),
  );
  const safetyNet = normalizeSafetyNet(pick(netRaw, 'level'));
  return {
    deviceId: n(pick(deviceRaw, 'id'), fallbackDeviceId),
    deviceName: String(pick(deviceRaw, 'name') ?? ''),
    siteId: nOrNull(pick(deviceRaw, 'siteId')),
    siteName: s(pick(deviceRaw, 'siteName')),
    brand: String(pick(deviceRaw, 'brand') ?? ''),
    safetyNet,
    safetyPeerDeviceId: nOrNull(pick(netRaw, 'peerDeviceId')),
    safetyPeerDeviceName: s(pick(netRaw, 'peerDeviceName')),
    guard: { ...guard, ran: guard.ran && !unavailable },
    // The preview carries no risk level: it decides safety, not size. `high` is
    // the documented fail-closed value of `DeviceImpact`, and the impact screen
    // reads its risk from the COMPILED PLAN instead of from here.
    riskLevel: 'high',
    changeOpCount: 0,
    blockedOpCount: 0,
    disruptiveOpCount: 0,
    byOpKind: {},
    affectedInterfaces: [],
    affectedSubnets: [],
    touchesManagementPath: false,
    requiresExplicitConfirmation:
      Boolean(pick(row, 'requiresDegradedConfirmation')) ||
      Boolean(pick(row, 'requiresOverride')) ||
      safetyNet === 'DEGRADED' ||
      guard.verdict !== 'ACCEPT' ||
      unavailable,
  };
}

// ── The server's composition of a push ─────────────────────────────────────

/** `POST /rollouts/preview` and `POST /rollouts`, as much of
 *  `RolloutComposition` as the screen reads. A push target also carries its
 *  compiled plan's size and risk; the plan envelope itself stays on the
 *  server. */
export interface PushComposition extends ManagementAccessComposition {
  rolloutId: number | null;
  waves: PlannedWave[];
  targets: Array<ManagementAccessComposition['targets'][number] & { planOpsCount: number; riskLevel: string }>;
}

// ── Config ──────────────────────────────────────────────────────────────────

export interface RolloutConfig {
  /** FAIL-CLOSED: false whenever the endpoint could not be read. A client that
   *  decided for itself that launching is possible is a client that queues N
   *  writes against a server with no rollout runner behind it. */
  canLaunch: boolean;
  milestone: string | null;
  /** The SERVER's sentence for why not — it names the missing piece (executor,
   *  renderer). `null` when launching is possible. Never invented here: a
   *  client-authored reason is a guess about a server it cannot see. */
  blockedReason?: string | null;
  /** Default canary ladder, server-owned so it is not a constant duplicated
   *  in the client. */
  waveSizes: number[];
  gates: HealthGateKind[];
}

export const ROLLOUT_CONFIG_FAIL_CLOSED: RolloutConfig = {
  canLaunch: false,
  // `null`, not a milestone name. The endpoint this falls back from did not exist until
  // now, so the fallback WAS the permanent answer and the screen announced a
  // milestone that had long shipped over a fully working compose / launch /
  // advance / pause surface. A fail-closed default may say "not now"; it may
  // not explain why with a number, because it does not know why — the server
  // does, and sends `blockedReason`.
  milestone: null,
  waveSizes: [1, 3],
  gates: [...HEALTH_GATE_KINDS],
};

// ── The client ──────────────────────────────────────────────────────────────

function clean(params: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') out[k] = v;
  }
  return out;
}

export const rolloutApi = {
  /** NEVER throws, ALWAYS fails closed. */
  async config(): Promise<RolloutConfig> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>('/rollouts/config');
      const row = (res.data.data ?? {}) as Raw;
      const sizes = numbers(pick(row, 'waveSizes'));
      const gates = (Array.isArray(pick(row, 'gates')) ? (pick(row, 'gates') as unknown[]) : [])
        .map((g) => String(g))
        .filter((g): g is HealthGateKind => GATES.includes(g));
      return {
        canLaunch: pick(row, 'canLaunch') === true,
        milestone: s(pick(row, 'milestone')) ?? null,
        blockedReason: s(pick(row, 'blockedReason')) ?? null,
        waveSizes: sizes.length > 0 ? sizes : ROLLOUT_CONFIG_FAIL_CLOSED.waveSizes,
        gates: gates.length > 0 ? gates : ROLLOUT_CONFIG_FAIL_CLOSED.gates,
      };
    } catch {
      return ROLLOUT_CONFIG_FAIL_CLOSED;
    }
  },

  /** `null` = the rollout API is not served by this build. */
  async list(params: { status?: string; limit?: number } = {}): Promise<RolloutView[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>('/rollouts', {
        params: clean(params as Record<string, unknown>),
      });
      return asRows(res.data.data).map(normalizeRollout);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /** One rollout with its waves and targets. Waves may travel inline or behind
   *  the sub-route; both are accepted rather than guessed, because getting it
   *  wrong shows up as a permanently empty wave list and never as an error. */
  async get(id: number): Promise<RolloutDetail | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>(`/rollouts/${id}`);
      const payload = res.data.data;
      if (!payload || typeof payload !== 'object') return null;
      const row = payload as Raw;
      const base = normalizeRollout((pick(row, 'rollout') ?? row) as Raw);
      const inlineWaves = pick(row, 'waves');
      const waves = Array.isArray(inlineWaves)
        ? (inlineWaves as Raw[]).map(normalizeWave)
        : ((await this.waves(id)) ?? []);
      const targets = asRows(pick(row, 'targets')).map(normalizeTarget);
      // `access` sits beside `rollout` in the answer (migration 087): the
      // caller's level on the rollout, 'rw' only when every device is writable.
      return { ...base, ...accessField(pick(row, 'access')), waves, targets };
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  async waves(rolloutId: number): Promise<RolloutWaveView[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>(`/rollouts/${rolloutId}/waves`);
      return asRows(res.data.data).map(normalizeWave);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /**
   * The change impact preview for ONE device — `POST /api/changes/preview`, which
   * is mounted TODAY. `null` means that route is absent from this build.
   *
   * The `plan` is sent whole when there is one: the server re-parses it with
   * the shared `ApplyPlan` schema, and a uuid would let a plan compiled by one
   * server version be reinterpreted by another.
   */
  async previewDevice(
    deviceId: number,
    kind: ChangeJobKind,
    plan?: ApplyPlan,
  ): Promise<DeviceImpact | null> {
    try {
      const res = await apiClient.post<ApiResponse<unknown>>('/changes/preview', {
        deviceId,
        kind,
        ...(plan ? { plan } : {}),
      });
      return impactOfPreview(res.data.data, deviceId);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /**
   * The impact screen of a template push: the SERVER's composition — every
   * plan compiled against the one revision that will be pushed, its guard
   * verdicts, its safety nets and its waves. Writes nothing. Throws on a
   * refusal (the server's sentence travels in the error).
   */
  async previewPush(deviceIds: number[], templateRevisionId: number, name?: string): Promise<PushComposition> {
    const res = await apiClient.post<ApiResponse<PushComposition>>('/rollouts/preview', {
      deviceIds,
      templateRevisionId,
      ...(name && name.trim() !== '' ? { name: name.trim() } : {}),
    });
    const data = res.data.data;
    if (!data) throw new Error(res.data.error ?? 'empty response');
    return data;
  },

  /** Compose a push rollout in DRAFT — nothing is queued until `start`. */
  async compose(body: RolloutComposeBody): Promise<PushComposition & { rolloutId: number }> {
    const res = await apiClient.post<ApiResponse<PushComposition>>('/rollouts', body);
    const data = res.data.data;
    if (!data || data.rolloutId === null || data.rolloutId === undefined) {
      throw new Error(res.data.error ?? 'empty response');
    }
    return data as PushComposition & { rolloutId: number };
  },

  /** Launch a composed draft: the first wave's baseline is captured and its
   *  jobs are queued. */
  async start(id: number): Promise<RolloutView> {
    const res = await apiClient.post<ApiResponse<unknown>>(`/rollouts/${id}/launch`, {});
    const payload = res.data.data;
    if (!payload || typeof payload !== 'object') throw new Error(res.data.error ?? 'empty response');
    return normalizeRollout(payload as Raw);
  },

  async pause(id: number, reason: string): Promise<boolean> {
    return post(`/rollouts/${id}/pause`, { reason });
  },

  async resume(id: number): Promise<boolean> {
    return post(`/rollouts/${id}/resume`, {});
  },

  /** Abort stops what has NOT started. It does not un-apply what has: waves
   *  already applied stay applied unless their own dead-man fires. The screen
   *  says that sentence next to the button. */
  async abort(id: number, reason: string): Promise<boolean> {
    return post(`/rollouts/${id}/abort`, { reason });
  },
};

async function post(path: string, body: unknown): Promise<boolean> {
  try {
    await apiClient.post<ApiResponse<unknown>>(path, body);
    return true;
  } catch (err) {
    if (isRouteAbsent(err)) return false;
    throw err;
  }
}
