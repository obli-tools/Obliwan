import apiClient from './client';
import type { ApiResponse, PermissionSet, CapabilityInfo } from '@obliwan/shared';

/**
 * The permission-set matrix (platform admin). Since migration 084 a set IS a
 * tenant role and the server grants what its row lists: every write here is a
 * grant (or a revocation) for every holder in every tenant, audited server-side.
 */

/** A catalogue row as the matrix needs it (server `getAvailableCapabilities`). */
export interface CapabilityMatrixInfo extends CapabilityInfo {
  /** Cannot be ticked into any set, and why. */
  lock: 'platform_only' | 'by_name_only' | null;
  /** Ticking needs an explicit confirmation (money, secrets in clear, four-eyes). */
  explicitOnly: boolean;
  /** What holding it brings with it at resolution. */
  implies: string[];
}

export const permissionSetsApi = {
  async list(): Promise<PermissionSet[]> {
    const res = await apiClient.get<ApiResponse<PermissionSet[]>>('/permission-sets');
    return res.data.data ?? [];
  },

  async capabilities(): Promise<CapabilityMatrixInfo[]> {
    const res = await apiClient.get<ApiResponse<CapabilityMatrixInfo[]>>('/permission-sets/capabilities');
    return res.data.data ?? [];
  },

  async create(data: { name: string; slug?: string; description?: string | null; capabilities: string[] }): Promise<PermissionSet> {
    const res = await apiClient.post<ApiResponse<PermissionSet>>('/permission-sets', data);
    return res.data.data!;
  },

  async update(id: number, data: { name?: string; description?: string | null; capabilities?: string[] }): Promise<PermissionSet> {
    const res = await apiClient.put<ApiResponse<PermissionSet>>(`/permission-sets/${id}`, data);
    return res.data.data!;
  },

  async reset(id: number): Promise<PermissionSet> {
    const res = await apiClient.post<ApiResponse<PermissionSet>>(`/permission-sets/${id}/reset`, {});
    return res.data.data!;
  },

  async remove(id: number): Promise<void> {
    await apiClient.delete(`/permission-sets/${id}`);
  },
};

/** The server's refusal sentence, when there is one (400 / 409). */
export function apiErrorMessage(err: unknown): string | null {
  const e = err as { response?: { data?: { error?: unknown } } };
  const msg = e?.response?.data?.error;
  return typeof msg === 'string' && msg.length > 0 ? msg : null;
}
