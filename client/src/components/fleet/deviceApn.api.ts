import apiClient from '@/api/client';
import type { ApiResponse, ChangeJobStatus, LteApnEntry } from '@obliwan/shared';

/**
 * The LTE APN of one router (an `lte_apn` change job over SSH) — the client
 * half of `server/src/routes/lteApn.routes.ts`, kept beside its card. The view
 * mirrors `LteApnView` in server/src/services/change/lteApn.service.ts; the
 * sentences in it (refusals, outcome, error) are written in French by the
 * server and shown verbatim.
 */

export interface DeviceApnStep {
  seq: number;
  kind: string;
  status: string;
  output: string | null;
  error: string | null;
}

export interface DeviceApnJob {
  id: number;
  status: ChangeJobStatus;
  active: boolean;
  profile: string;
  apn: string;
  outcome: 'applied' | 'present' | 'refused' | 'failed' | null;
  outcomeDetail: string | null;
  errorKind: string | null;
  errorMessage: string | null;
  createdAt: string;
  finishedAt: string | null;
  wroteAt: string | null;
  backupId: number | null;
  observedApnProfiles: string | null;
  observedAt: string | null;
  egress: { state: string; summary: string } | null;
  steps: DeviceApnStep[];
}

export interface DeviceApnView {
  deviceId: number;
  deviceName: string;
  supported: boolean;
  eligible: boolean;
  refusals: Array<{ kind: string; message: string }>;
  catalogue: {
    ok: boolean;
    message: string | null;
    entries: LteApnEntry[];
    defaultProfile: string | null;
    feedsRender: boolean;
    revision: { id: string; number: number | null; templateId: string | null } | null;
  };
  chosenProfile: string | null;
  job: DeviceApnJob | null;
}

function payload<T>(res: { data: ApiResponse<T> }): T {
  if (res.data.data === undefined || res.data.data === null) throw new Error(res.data.error ?? 'empty response');
  return res.data.data;
}

export const deviceApnApi = {
  async get(deviceId: number): Promise<DeviceApnView> {
    return payload(await apiClient.get<ApiResponse<DeviceApnView>>(`/devices/${deviceId}/lte-apn`));
  },

  /** Queue ONE job. `confirmNoDeadman` is the safety-net rule's explicit confirmation. */
  async apply(deviceId: number, profile: string): Promise<{ jobId: number; alreadyQueued: boolean; profile: string }> {
    return payload(
      await apiClient.post<ApiResponse<{ jobId: number; alreadyQueued: boolean; profile: string }>>(
        `/devices/${deviceId}/lte-apn`,
        { profile, confirmNoDeadman: true },
      ),
    );
  },
};

/** The server's refusal sentence (`{ success: false, error }`), or the fallback. */
export function deviceApnErrorMessage(err: unknown, fallback: string): string {
  const data = (err as { response?: { data?: { error?: unknown } } })?.response?.data;
  return typeof data?.error === 'string' && data.error !== '' ? data.error : fallback;
}
