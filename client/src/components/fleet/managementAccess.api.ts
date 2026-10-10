import apiClient from '@/api/client';
import type { ApiResponse, ApiSslStateDifference, ChangeJobStatus } from '@obliwan/shared';
import type { Device } from '@/types/fleet';
import type { DeviceImpact } from '@/types/change';
import type { ImpactRadius, ImpactRow, WaveComposition } from '@/types/rollout';

/**
 * The management API of a router in service (api-ssl on 8729, opened by a
 * `management_access` change job over SSH) — the client half of
 * `server/src/routes/managementAccess.routes.ts`. Kept beside its card so the
 * feature lands as one folder. The view mirrors `ManagementAccessView` in
 * server/src/services/change/managementAccess.service.ts; the sentences in it
 * (refusals, outcome, error) are written in French by the server and shown
 * verbatim.
 */

export interface ManagementAccessRefusal {
  kind: string;
  message: string;
}

export interface ManagementAccessStep {
  seq: number;
  kind: string;
  status: string;
  output: string | null;
  error: string | null;
}

export interface ManagementAccessJob {
  id: number;
  status: ChangeJobStatus;
  active: boolean;
  outcome: 'enabled' | 'present' | 'refused' | 'failed' | null;
  outcomeDetail: string | null;
  errorKind: string | null;
  errorMessage: string | null;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  wroteAt: string | null;
  backupId: number | null;
  transportAction: 'created' | 'updated' | 'unchanged' | null;
  pinnedFingerprint: string | null;
  rolloutId: number | null;
  /** What the job did about ObliWAN's own `obliwan` account (server migration
   *  071). `action` null = the job did not get that far. `switchedAt` null
   *  beside `created`/`present` = the account exists and ObliWAN does not use
   *  it yet. `detail` is the server's French sentence. `disclosedAt` set =
   *  the job's API login carried the `obliwan` password to a certificate that
   *  was not the expected one: the password was discarded and the account
   *  must be removed from the router so that a run recreates it. Optional: a
   *  server older than 071 does not send it. */
  account?: {
    action: ManagementAccountAction | null;
    detail: string | null;
    switchedAt: string | null;
    disclosedAt?: string | null;
  };
  steps: ManagementAccessStep[];
}

export type ManagementAccountAction = 'in_use' | 'created' | 'present' | 'refused';

export interface ManagementAccessView {
  deviceId: number;
  deviceName: string;
  state: 'unsupported' | 'not_enabled' | 'in_progress' | 'enabled' | 'failed';
  eligible: boolean;
  refusals: ManagementAccessRefusal[];
  range: { ok: boolean; prefixes: string[]; message: string | null };
  /** `username`: the account ObliWAN logs in with — `obliwan` once a job
   *  switched to it, the historical one before. */
  ssh: { host: string | null; port: number | null; enabled: boolean; auth: 'password' | 'key' | 'none'; username?: string | null } | null;
  api: {
    host: string | null;
    port: number | null;
    username?: string | null;
    enabled: boolean;
    tls: boolean;
    pinned: boolean;
    fingerprint: string | null;
    lastOkAt: string | null;
    lastError: string | null;
  } | null;
  apiSsl: {
    state: 'unknown' | 'conformant' | 'different';
    readAt: string | null;
    differences: ApiSslStateDifference[];
    /** Who read it last: a management-access job, or the health check. */
    source?: 'job' | 'automatic' | null;
  };
  job: ManagementAccessJob | null;
}

/** The server's rollout composition for this kind (`RolloutComposition`),
 *  as much of it as the New Rollout panel reads. */
export interface ManagementAccessComposition {
  waves: Array<{ index: number; label: string; size: number }>;
  targets: Array<{
    deviceId: number;
    deviceName: string;
    siteName: string | null;
    brand: string;
    waveIndex: number;
    orderRank: number;
    safetyLevel: 'armed' | 'armed_by_peer' | 'degraded';
    guardVerdict: string;
    guardSummary: string;
    /** A template push only: the compiled plan's op count and risk level. */
    planOpsCount?: number;
    riskLevel?: string;
  }>;
  failures: Array<{ deviceId: number; deviceName: string | null; reason: string; message: string }>;
  degradedCount: number;
}

function payload<T>(res: { data: ApiResponse<T> }): T {
  if (res.data.data === undefined || res.data.data === null) throw new Error(res.data.error ?? 'empty response');
  return res.data.data;
}

export const managementAccessApi = {
  async get(deviceId: number): Promise<ManagementAccessView> {
    return payload(await apiClient.get<ApiResponse<ManagementAccessView>>(`/devices/${deviceId}/management-access`));
  },

  /** Queue ONE job. `confirmNoDeadman` is the safety-net rule's explicit confirmation. */
  async open(deviceId: number): Promise<{ jobId: number; alreadyQueued: boolean }> {
    return payload(
      await apiClient.post<ApiResponse<{ jobId: number; alreadyQueued: boolean }>>(
        `/devices/${deviceId}/management-access`,
        { confirmNoDeadman: true },
      ),
    );
  },

  async preview(deviceIds: number[], name?: string): Promise<ManagementAccessComposition> {
    return payload(
      await apiClient.post<ApiResponse<ManagementAccessComposition>>('/devices/management-access/preview', {
        deviceIds,
        ...(name && name.trim() !== '' ? { name: name.trim() } : {}),
      }),
    );
  },

  /** Compose AND launch; `waves` is the ladder the operator was shown. */
  async launchRollout(req: { name: string; deviceIds: number[]; waves: Array<{ size: number }> }): Promise<{ rolloutId: number }> {
    return payload(
      await apiClient.post<ApiResponse<{ rolloutId: number }>>('/devices/management-access/rollouts', {
        ...req,
        confirmNoDeadman: true,
      }),
    );
  },
};

/** The server's refusal sentence (`{ success: false, error }`), or the fallback. */
export function managementAccessErrorMessage(err: unknown, fallback: string): string {
  const data = (err as { response?: { data?: { error?: unknown } } })?.response?.data;
  return typeof data?.error === 'string' && data.error !== '' ? data.error : fallback;
}

/**
 * The New Rollout panel's impact radius for this kind, built from the SERVER's
 * composition — its waves and its per-device verdicts — rather than from the
 * client ladder: the launch is refused unless the ladder shown is the one the
 * server will run. Refused devices are returned apart, never put in a wave.
 * A `legacy_compliance` rollout is composed by the server the same way (same
 * composition shape, its own door), and so is a template `push`
 * (`POST /rollouts/preview`, whose targets also carry their plan's op count
 * and risk level): `opts` names that door and its blocker. `refusedBlocker:
 * null` lists the refused devices without blocking — the caller then asks
 * for an explicit acknowledgement and launches the composed targets only.
 */
export async function buildManagementAccessRadius(
  deviceIds: number[],
  devices: readonly Device[],
  opts: { preview?: (ids: number[]) => Promise<ManagementAccessComposition>; refusedBlocker?: string | null } = {},
): Promise<{ radius: ImpactRadius; refused: ManagementAccessComposition['failures'] }> {
  const composition = await (opts.preview ?? ((ids: number[]) => managementAccessApi.preview(ids)))(deviceIds);
  const byId = new Map(devices.map((d) => [d.id, d]));
  // No plan (management access, compliance): 'low', as before. A plan's
  // unrecognised risk folds to 'high', never to 'low'.
  const riskOf = (t: ManagementAccessComposition['targets'][number]): 'low' | 'medium' | 'high' => {
    if (t.riskLevel === undefined) return 'low';
    return t.riskLevel === 'low' || t.riskLevel === 'medium' || t.riskLevel === 'high' ? t.riskLevel : 'high';
  };
  const rowOf = (t: ManagementAccessComposition['targets'][number]): ImpactRow => {
    const device = byId.get(t.deviceId);
    const opCount = typeof t.planOpsCount === 'number' && Number.isFinite(t.planOpsCount) ? t.planOpsCount : 0;
    const impact: DeviceImpact = {
      deviceId: t.deviceId,
      deviceName: t.deviceName,
      siteId: device?.siteId ?? null,
      siteName: t.siteName,
      brand: t.brand,
      safetyNet: t.safetyLevel === 'armed' ? 'ARMED' : t.safetyLevel === 'armed_by_peer' ? 'ARMED_BY_PEER' : 'DEGRADED',
      safetyPeerDeviceId: null,
      safetyPeerDeviceName: null,
      guard: {
        verdict: t.guardVerdict === 'ACCEPT' ? 'ACCEPT' : t.guardVerdict === 'REJECT' ? 'REJECT' : 'INDETERMINATE',
        planVerdict: t.guardVerdict === 'ACCEPT' ? 'accept' : t.guardVerdict === 'REJECT' ? 'veto' : 'indeterminate',
        reasons: [],
        probes: [],
        routing: null,
        culpritOpSeqs: [],
        summary: t.guardSummary,
        analysed: null,
        ran: true,
      },
      riskLevel: riskOf(t),
      changeOpCount: opCount,
      blockedOpCount: 0,
      disruptiveOpCount: 0,
      byOpKind: {},
      affectedInterfaces: [],
      affectedSubnets: [],
      touchesManagementPath: false,
      requiresExplicitConfirmation: t.safetyLevel === 'degraded',
    };
    return {
      deviceId: t.deviceId,
      deviceName: t.deviceName,
      siteName: t.siteName,
      brand: t.brand,
      role: device?.role ?? 'cpe',
      concentratorId: device?.concentratorId ?? null,
      subtreeSize: devices.filter((d) => d.concentratorId === t.deviceId).length,
      impact,
      impactError: null,
      planCompiled: true,
      planError: null,
      changeOpCount: opCount,
      riskLevel: riskOf(t),
      touchesManagementPath: false,
      safetyNet: impact.safetyNet,
    };
  };
  const ordered = [...composition.targets].sort((a, b) => a.waveIndex - b.waveIndex || a.orderRank - b.orderRank);
  const rows = ordered.map(rowOf);
  const waves: WaveComposition[] = composition.waves.map((w) => ({
    index: w.index,
    label: w.label,
    rows: ordered.filter((t) => t.waveIndex === w.index).map(rowOf),
  }));
  const blockers: string[] = [];
  if (rows.length === 0) blockers.push('NO_DEVICES');
  if (composition.failures.length > 0 && opts.refusedBlocker !== null) {
    blockers.push(opts.refusedBlocker ?? 'MANAGEMENT_ACCESS_REFUSED');
  }
  // A concentrator's blast radius is the sites of its whole subtree.
  const concentratorIds = new Set(rows.filter((r) => r.role === 'concentrator').map((r) => r.deviceId));
  const subtreeSites = new Set(
    devices
      .filter((d) => d.concentratorId !== null && concentratorIds.has(d.concentratorId) && d.siteId !== null)
      .map((d) => d.siteId as number),
  );
  return {
    radius: {
      rows,
      waves,
      degradedCount: rows.filter((r) => r.safetyNet === 'DEGRADED').length,
      guardRefusedCount: rows.filter((r) => r.impact?.guard.verdict !== 'ACCEPT').length,
      concentratorCount: concentratorIds.size,
      subtreeSiteCount: subtreeSites.size,
      blockers,
      warnings: [],
    },
    refused: composition.failures,
  };
}
