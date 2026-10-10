import apiClient from './client';
import type { ApiResponse, LineQualityDeviceView, LineQualityFleetItem } from '@obliwan/shared';

/**
 * Line quality of the stores' fixed lines (server: `/api/line-quality`,
 * DEVICE_READ — services/fleet/lineQuality.service.ts). Read-only: what the
 * nightly measurement filed. The fleet list's scope is the server's: the
 * session's tenant, or every tenant for a platform admin on Default.
 */
export const lineQualityApi = {
  async fleet(opts: { all?: boolean } = {}): Promise<{ items: LineQualityFleetItem[]; godView: boolean }> {
    const r = await apiClient.get<ApiResponse<LineQualityFleetItem[]> & { godView?: boolean }>('/line-quality', {
      params: opts.all ? { all: '1' } : undefined,
    });
    return { items: r.data.data ?? [], godView: r.data.godView === true };
  },

  async device(deviceId: number): Promise<LineQualityDeviceView | null> {
    const r = await apiClient.get<ApiResponse<LineQualityDeviceView>>(`/line-quality/devices/${deviceId}`);
    return r.data.data ?? null;
  },
};
