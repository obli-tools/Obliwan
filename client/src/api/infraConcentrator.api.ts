import apiClient from './client';
import type {
  ApiResponse,
  InfraAccountAction,
  InfraAccountJobState,
  InfraConcentratorKind,
  InfraConcentratorParams,
  InfraConcentratorView,
  InfraDriverResult,
  InfraPlanView,
  InfraSiteAccountView,
} from '@obliwan/shared';

/**
 * Each customer's infrastructure VPN concentrator (server:
 * /api/infra-concentrators, platform admin only). No call here ever returns a
 * credential: an OPNsense API key and secret are WRITE-only.
 */

export interface InfraConcentratorInput {
  kind?: InfraConcentratorKind;
  name?: string;
  host?: string;
  port?: number | null;
  deviceId?: number | null;
  enabled?: boolean;
  params?: Partial<InfraConcentratorParams>;
  apiKey?: string;
  apiSecret?: string;
  tlsFingerprint?: string | null;
}

export const infraConcentratorApi = {
  async list(tenantId: number): Promise<InfraConcentratorView[]> {
    const res = await apiClient.get<ApiResponse<InfraConcentratorView[]>>(`/infra-concentrators/tenants/${tenantId}`);
    return res.data.data ?? [];
  },

  async create(tenantId: number, input: InfraConcentratorInput): Promise<InfraConcentratorView> {
    const res = await apiClient.post<ApiResponse<InfraConcentratorView>>(`/infra-concentrators/tenants/${tenantId}`, input);
    return res.data.data!;
  },

  async update(id: number, input: InfraConcentratorInput): Promise<InfraConcentratorView> {
    const res = await apiClient.patch<ApiResponse<InfraConcentratorView>>(`/infra-concentrators/${id}`, input);
    return res.data.data!;
  },

  async remove(id: number): Promise<void> {
    await apiClient.delete(`/infra-concentrators/${id}`);
  },

  async test(id: number): Promise<InfraDriverResult> {
    const res = await apiClient.post<ApiResponse<InfraDriverResult>>(`/infra-concentrators/${id}/test`);
    return res.data.data!;
  },

  async siteAccounts(tenantId: number, siteId: number): Promise<InfraSiteAccountView[]> {
    const res = await apiClient.get<ApiResponse<InfraSiteAccountView[]>>(
      `/infra-concentrators/tenants/${tenantId}/sites/${siteId}/accounts`,
    );
    return res.data.data ?? [];
  },

  async preview(id: number, siteId: number, action: InfraAccountAction = 'ensure'): Promise<InfraPlanView> {
    const res = await apiClient.post<ApiResponse<InfraPlanView>>(`/infra-concentrators/${id}/sites/${siteId}/preview`, { action });
    return res.data.data!;
  },

  async enqueue(id: number, siteId: number, action: InfraAccountAction = 'ensure'): Promise<InfraAccountJobState> {
    const res = await apiClient.post<ApiResponse<InfraAccountJobState>>(`/infra-concentrators/${id}/sites/${siteId}/enqueue`, { action });
    return res.data.data!;
  },

  async job(jobId: number): Promise<InfraAccountJobState> {
    const res = await apiClient.get<ApiResponse<InfraAccountJobState>>(`/infra-concentrators/jobs/${jobId}`);
    return res.data.data!;
  },
};

/** The server's French sentence, when it sent one. */
export function infraErrorOf(err: unknown): string | null {
  const data = (err as { response?: { data?: { error?: string } } }).response?.data;
  return data?.error ?? null;
}
