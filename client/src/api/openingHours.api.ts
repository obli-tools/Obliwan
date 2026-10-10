import apiClient from './client';
import type { ApiResponse, OpeningHours } from '@obliwan/shared';

/**
 * Store opening hours (migration 096). The workspace's usual hours
 * (`/sites/opening-hours`), one site's own hours (the site edit, `PATCH
 * /sites/:id { openingHours }`) and the bulk write on selected sites. Every
 * write takes the structured value or its readable text; null = inherit (a
 * site) or no hours (the workspace).
 */
export interface OpeningHoursBulkResult {
  requested: number;
  changed: number;
  unchanged: number;
  changedSiteIds: number[];
}

export type OpeningHoursBulkMode = 'replace' | 'merge';

export const openingHoursApi = {
  async getTenant(): Promise<OpeningHours | null> {
    const res = await apiClient.get<ApiResponse<{ openingHours: OpeningHours | null }>>('/sites/opening-hours');
    return res.data.data?.openingHours ?? null;
  },

  async putTenant(openingHours: OpeningHours | null): Promise<OpeningHours | null> {
    const res = await apiClient.put<ApiResponse<{ openingHours: OpeningHours | null }>>('/sites/opening-hours', {
      openingHours,
    });
    return res.data.data?.openingHours ?? null;
  },

  async setSite(siteId: number, openingHours: OpeningHours | null): Promise<void> {
    await apiClient.patch(`/sites/${siteId}`, { openingHours });
  },

  async bulk(ids: number[], openingHours: OpeningHours | null, mode: OpeningHoursBulkMode): Promise<OpeningHoursBulkResult> {
    const res = await apiClient.post<ApiResponse<OpeningHoursBulkResult>>('/sites/bulk/opening-hours', {
      ids,
      openingHours,
      mode,
    });
    return res.data.data!;
  },
};

/** The server's refusal text, when it sent one. */
export function apiErrorText(err: unknown): string | null {
  return (err as { response?: { data?: { error?: string } } }).response?.data?.error ?? null;
}
