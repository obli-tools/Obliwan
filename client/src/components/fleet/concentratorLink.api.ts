import apiClient from '@/api/client';
import type { ApiResponse, ConcentratorLinkView } from '@obliwan/shared';

/**
 * The ObliWAN <-> concentrator WireGuard link — the client half of
 * `server/src/routes/concentratorLink.routes.ts` (platform admin +
 * CHANGE_APPLY). Kept beside its card so the feature lands as one folder.
 * The view's shape is `ConcentratorLinkView` in shared/src/concentratorLink.ts.
 */

export interface ConnectResult {
  jobId: number;
  alreadyQueued: boolean;
}

export interface SwitchResult {
  via: 'tunnel' | 'public';
  host: string;
  port: number;
  bindingOk: boolean;
  bindingReason: string;
}

export const concentratorLinkApi = {
  async get(concentratorId: number): Promise<ConcentratorLinkView> {
    const res = await apiClient.get<ApiResponse<ConcentratorLinkView>>(`/concentrators/${concentratorId}/link`);
    if (!res.data.data) throw new Error(res.data.error ?? 'empty response');
    return res.data.data;
  },

  async connect(
    concentratorId: number,
    body: { transit?: string | null; listenPort?: number | null },
  ): Promise<ConnectResult> {
    const res = await apiClient.post<ApiResponse<ConnectResult>>(`/concentrators/${concentratorId}/link`, {
      ...body,
      confirmNoDeadman: true,
    });
    if (!res.data.data) throw new Error(res.data.error ?? 'empty response');
    return res.data.data;
  },

  async switchApi(concentratorId: number, via: 'tunnel' | 'public'): Promise<SwitchResult> {
    const res = await apiClient.post<ApiResponse<SwitchResult>>(
      `/concentrators/${concentratorId}/link/api-transport`,
      { via },
    );
    if (!res.data.data) throw new Error(res.data.error ?? 'empty response');
    return res.data.data;
  },
};

/** The server's refusal text (`{ success: false, error }`), or the fallback. */
export function linkErrorMessage(err: unknown, fallback: string): string {
  const data = (err as { response?: { data?: { error?: unknown } } })?.response?.data;
  return typeof data?.error === 'string' && data.error !== '' ? data.error : fallback;
}
