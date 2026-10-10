import apiClient from './client';
import type { ApiResponse, DiscoveryState } from '@obliwan/shared';
import type {
  Discovery,
  DiscoveryBindInput,
  DiscoveryStateInput,
  DeviceDetail,
} from '@/types/fleet';

export interface DiscoveryListParams {
  state?: DiscoveryState;
  concentratorId?: number;
  search?: string;
}

/** What one scan of a concentrator did (server: DiscoveryScanResult). */
export interface DiscoveryScanSummary {
  concentratorId: number;
  secrets: number;
  active: number;
  known: number;
  created: number;
  refreshed: number;
  newUsernames: string[];
}

export const discoveriesApi = {
  /** Read the CHR's /ppp/secret and /ppp/active now; new usernames land in quarantine. */
  async scan(concentratorId: number): Promise<DiscoveryScanSummary> {
    const res = await apiClient.post<ApiResponse<DiscoveryScanSummary>>('/discoveries/scan', { concentratorId });
    return res.data.data!;
  },

  async list(params: DiscoveryListParams = {}): Promise<Discovery[]> {
    const res = await apiClient.get<ApiResponse<Discovery[]>>('/discoveries', { params });
    return res.data.data ?? [];
  },

  /** The same list with the server's total, so a page can say "N of T". The
   *  server caps `limit` at 500 and orders by last seen, newest first. */
  async listWithTotal(params: DiscoveryListParams & { limit?: number; offset?: number } = {}): Promise<{ items: Discovery[]; total: number }> {
    const res = await apiClient.get<ApiResponse<Discovery[]> & { meta?: { total?: number } }>('/discoveries', { params });
    const items = res.data.data ?? [];
    return { items, total: Number(res.data.meta?.total ?? items.length) };
  },

  /**
   * Bind a quarantined PPP session to a device.
   *
   * This is the one inventory write that can push customer A's configuration to
   * customer B's router if it is wrong. The authority is entirely
   * server-side: the target device must already be in the caller's session
   * tenant (404 otherwise), and a device created here is created in that same
   * tenant. The dialog's attestation and retyped username are guard rails on
   * the operator, not credentials — see `DiscoveryBindInput`.
   *
   * The response carries the updated discovery AND the resulting device, so
   * the caller can refresh both without a second round trip.
   */
  async bind(
    id: number,
    data: DiscoveryBindInput,
  ): Promise<{ discovery: Discovery; device: DeviceDetail | null }> {
    const res = await apiClient.post<
      ApiResponse<{ discovery: Discovery; device: DeviceDetail | null }>
    >(`/discoveries/${id}/bind`, data);
    return res.data.data!;
  },

  /** File a row as "not ours", or push it back into the review queue. */
  async setState(id: number, data: DiscoveryStateInput): Promise<Discovery> {
    const res = await apiClient.post<ApiResponse<Discovery>>(`/discoveries/${id}/state`, data);
    return res.data.data!;
  },

  /** Convenience wrapper over `setState` for the one-click "ignore" button. */
  async ignore(id: number): Promise<Discovery> {
    return discoveriesApi.setState(id, { state: 'ignored' });
  },
};
