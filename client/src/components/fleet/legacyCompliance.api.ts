import apiClient from '@/api/client';
import type { ApiResponse, ChangeJobStatus, LegacyFixKey } from '@obliwan/shared';
import type { ManagementAccessComposition } from './managementAccess.api';

/**
 * The corrected-template fixes on a router in service (a `legacy_compliance`
 * change job over SSH) — the client half of
 * `server/src/routes/legacyCompliance.routes.ts`, kept beside its card. The
 * view mirrors `LegacyComplianceView` in
 * server/src/services/change/legacyCompliance.service.ts; the sentences in it
 * (refusals, outcome, error, per-fix detail) are written by the server and
 * shown verbatim, the per-fix state and reason are codes the card translates.
 */

export type LegacyFixState =
  | 'unknown'
  | 'needed'
  | 'present'
  | 'applied'
  | 'skipped'
  | 'refused'
  | 'reverted'
  | 'tunnel_down'
  | 'not_applied'
  | 'not_sent'
  | 'unverified';

/** In place on the router (green). Read by the card and by the device page's
 *  compliance chip, so the two cannot class a state differently. */
export const LEGACY_FIX_GOOD: ReadonlySet<LegacyFixState> = new Set(['present', 'applied']);
/** A job tried and it did not hold (red). */
export const LEGACY_FIX_BAD: ReadonlySet<LegacyFixState> = new Set([
  'reverted', 'tunnel_down', 'not_applied', 'not_sent', 'unverified',
]);

export interface LegacyComplianceFix {
  key: LegacyFixKey;
  state: LegacyFixState;
  reason: string | null;
  /** What could still break, written anyway (shared LEGACY_FIX_WARNINGS);
   *  absent from a server that predates the DNS-Amp fix. */
  warnings?: string[];
  detail: string | null;
  current: string | null;
}

export interface LegacyComplianceStep {
  seq: number;
  kind: string;
  status: string;
  output: string | null;
  error: string | null;
}

export interface LegacyComplianceJob {
  id: number;
  status: ChangeJobStatus;
  active: boolean;
  outcome: 'applied' | 'present' | 'refused' | 'failed' | null;
  outcomeDetail: string | null;
  errorKind: string | null;
  errorMessage: string | null;
  createdAt: string;
  finishedAt: string | null;
  wroteAt: string | null;
  backupId: number | null;
  selfRevertArmedAt: string | null;
  randomSourcePortSentAt: string | null;
  tunnelReturnedAt: string | null;
  rolloutId: number | null;
  steps: LegacyComplianceStep[];
}

export interface LegacyComplianceView {
  deviceId: number;
  deviceName: string;
  supported: boolean;
  eligible: boolean;
  refusals: Array<{ kind: string; message: string }>;
  ssh: { host: string | null; port: number | null; enabled: boolean } | null;
  readAt: string | null;
  readBy: 'readback' | 'lint' | null;
  lan: { network: string | null; bridge: string | null; reason: string | null; detail: string } | null;
  fixes: LegacyComplianceFix[];
  job: LegacyComplianceJob | null;
  /** The latest promise of these fixes after another job on the device (the
   *  bulk attach's, after its management access job); null when none, absent
   *  from a server that predates it. */
  followUp?: LegacyComplianceFollowUp | null;
}

/** What became of that promise: `pending` while it waits on `afterJobId`,
 *  `queued` with the job it queued, `refused`/`skipped` with the server's
 *  code and sentence (shown as it is). */
export interface LegacyComplianceFollowUp {
  id: number;
  state: 'pending' | 'queued' | 'refused' | 'skipped';
  afterJobId: number;
  thenJobId: number | null;
  reason: string | null;
  detail: string | null;
  createdAt: string;
  doneAt: string | null;
}

function payload<T>(res: { data: ApiResponse<T> }): T {
  if (res.data.data === undefined || res.data.data === null) throw new Error(res.data.error ?? 'empty response');
  return res.data.data;
}

export const legacyComplianceApi = {
  async get(deviceId: number): Promise<LegacyComplianceView> {
    return payload(await apiClient.get<ApiResponse<LegacyComplianceView>>(`/devices/${deviceId}/legacy-compliance`));
  },

  /** Queue ONE job. `confirmNoDeadman` is the safety-net rule's explicit confirmation. */
  async apply(deviceId: number): Promise<{ jobId: number; alreadyQueued: boolean }> {
    return payload(
      await apiClient.post<ApiResponse<{ jobId: number; alreadyQueued: boolean }>>(
        `/devices/${deviceId}/legacy-compliance`,
        { confirmNoDeadman: true },
      ),
    );
  },

  /** The server's rollout composition: same shape as management access's. */
  async preview(deviceIds: number[], name?: string): Promise<ManagementAccessComposition> {
    return payload(
      await apiClient.post<ApiResponse<ManagementAccessComposition>>('/devices/legacy-compliance/preview', {
        deviceIds,
        ...(name && name.trim() !== '' ? { name: name.trim() } : {}),
      }),
    );
  },

  /** Compose AND launch; `waves` is the ladder the operator was shown. */
  async launchRollout(req: { name: string; deviceIds: number[]; waves: Array<{ size: number }> }): Promise<{ rolloutId: number }> {
    return payload(
      await apiClient.post<ApiResponse<{ rolloutId: number }>>('/devices/legacy-compliance/rollouts', {
        ...req,
        confirmNoDeadman: true,
      }),
    );
  },
};
