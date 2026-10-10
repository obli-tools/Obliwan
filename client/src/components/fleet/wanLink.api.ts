import apiClient from '@/api/client';
import type { ApiResponse, ChangeJobStatus, Wan1Mode } from '@obliwan/shared';
import type { ManagementAccessComposition } from './managementAccess.api';

/**
 * The WAN1 link change on a router in service (a `wan_link` change job) —
 * the client half of `server/src/routes/wanLink.routes.ts`, kept beside its
 * card. The view mirrors `WanLinkView` in
 * server/src/services/change/wanLink.service.ts; the sentences in it
 * (refusals, outcome, error, step outputs) are written by the server and shown
 * verbatim, the codes (mode, warnings, 4G verdict) are translated by the card.
 * The PPPoE password never comes back: only whether the site's vault holds one.
 */

export interface WanLinkStep {
  seq: number;
  kind: string;
  status: string;
  output: string | null;
  error: string | null;
}

export type WanLinkOutcome = 'applied' | 'present' | 'reverted' | 'refused' | 'failed';

export interface WanLinkJob {
  id: number;
  status: ChangeJobStatus;
  active: boolean;
  from: Wan1Mode;
  to: Wan1Mode;
  outcome: WanLinkOutcome | null;
  outcomeDetail: string | null;
  errorKind: string | null;
  errorMessage: string | null;
  createdAt: string;
  finishedAt: string | null;
  wroteAt: string | null;
  scriptStartedAt: string | null;
  scriptSeenAliveAt: string | null;
  decision: string | null;
  decidedAt: string | null;
  tunnelReturnedAt: string | null;
  cutExpectedUntil: string | null;
  varsWrittenAt: string | null;
  backupId: number | null;
  revertAfterS: number;
  rolloutId: number | null;
  steps: WanLinkStep[];
}

export type WanLinkWarning =
  | 'leftover_kept'
  | 'public_address_on_router'
  | 'dns_open_on_wan'
  | 'ipsec_static_policies'
  | 'no_sim_line'
  | 'sim_low'
  | 'sim_balance_unknown';

export interface WanLinkView {
  deviceId: number;
  deviceName: string;
  supported: boolean;
  eligible: boolean;
  refusals: Array<{ kind: string; message: string }>;
  site: { id: number; code: string | null } | null;
  declared: {
    ok: boolean;
    message: string | null;
    mode: Wan1Mode | null;
    modeSource: string | null;
    pppoeName: string | null;
    pppoeUsername: string | null;
    passwordSet: boolean;
    address: string | null;
    gateway: string | null;
    deviceOverrides: string[];
  };
  observed: {
    readAt: string;
    readBy: 'lint' | 'readback';
    mode: Wan1Mode | null;
    reasons: string[];
    params: { pppoeName: string | null; pppoeUser: string | null; address: string | null; gateway: string | null; probeHost: string | null };
    lte: { state: 'ready' | 'not_ready' | 'unknown'; reasons: string[]; rsrp: number | null; sinr: number | null; registration: string | null } | null;
    takeover: { state: 'via_lte' | 'not_via_lte' | 'unknown'; summary: string } | null;
    warnings: WanLinkWarning[];
  } | null;
  job: WanLinkJob | null;
  constants: {
    revertAfterS: number;
    revertMinS: number;
    revertMaxS: number;
    minRsrpDbm: number;
    minSinrDb: number;
    failoverBudgetS: number;
    armLeadS: number;
    marginS: number;
    modes: Wan1Mode[];
    pppoeNames: string[];
  };
}

export interface WanLinkRequestBody {
  toMode: Wan1Mode;
  /** `password` absent: the one in the site's vault. */
  pppoe?: { name: string; username: string; password?: string };
  static?: { address: string; gateway: string };
  revertAfterS?: number;
}

function payload<T>(res: { data: ApiResponse<T> }): T {
  if (res.data.data === undefined || res.data.data === null) throw new Error(res.data.error ?? 'empty response');
  return res.data.data;
}

export const wanLinkApi = {
  async get(deviceId: number): Promise<WanLinkView> {
    return payload(await apiClient.get<ApiResponse<WanLinkView>>(`/devices/${deviceId}/wan-link`));
  },

  /** Queue ONE job. `confirmExpectedCut` is the safety-net rule's explicit confirmation. */
  async enqueue(deviceId: number, body: WanLinkRequestBody): Promise<{ jobId: number; alreadyQueued: boolean }> {
    return payload(
      await apiClient.post<ApiResponse<{ jobId: number; alreadyQueued: boolean }>>(`/devices/${deviceId}/wan-link`, {
        ...body,
        confirmExpectedCut: true,
      }),
    );
  },

  /** The rollout composition (same shape as management access's): per site,
   *  the refusals — the target's parameters are read from each site's variables. */
  async preview(deviceIds: number[], toMode: Wan1Mode, name?: string): Promise<ManagementAccessComposition> {
    return payload(
      await apiClient.post<ApiResponse<ManagementAccessComposition>>('/devices/wan-link/preview', {
        deviceIds,
        toMode,
        ...(name && name.trim() !== '' ? { name: name.trim() } : {}),
      }),
    );
  },

  /** Compose AND launch; `waves` is the ladder the operator was shown. */
  async launchRollout(req: { name: string; deviceIds: number[]; toMode: Wan1Mode; waves: Array<{ size: number }> }): Promise<{ rolloutId: number }> {
    return payload(
      await apiClient.post<ApiResponse<{ rolloutId: number }>>('/devices/wan-link/rollouts', {
        ...req,
        confirmExpectedCut: true,
      }),
    );
  },
};

/** When the alerts held by a job of `revertAfterS` would be released, from now
 *  (the server's own bound: lead + delay + two failovers + margin). */
export function wanLinkHoldUntil(view: WanLinkView, revertAfterS: number, now = Date.now()): Date {
  const c = view.constants;
  return new Date(now + (c.armLeadS + revertAfterS + 2 * c.failoverBudgetS + c.marginS) * 1000);
}
