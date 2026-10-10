import apiClient from './client';
import type {
  ApiResponse,
  RouterOsFirmwareStatus,
  RouterOsReleaseCheckResult,
  RouterOsTargetSetting,
} from '@obliwan/shared';

/**
 * RouterOS releases and the fleet target (`/api/firmware/routeros`).
 *
 * A `null` version means "never read successfully", not "no release": the
 * card renders it as a dash, never as a version. A failed check keeps the last
 * good value server-side, so `version` and `lastError` can both be set.
 */
export const firmwareApi = {
  async getRouterOs(): Promise<RouterOsFirmwareStatus> {
    const res = await apiClient.get<ApiResponse<RouterOsFirmwareStatus>>('/firmware/routeros');
    return res.data.data!;
  },

  /** Platform admin only. A pin is refused (400/502) unless MikroTik publishes it. */
  async setTarget(target: RouterOsTargetSetting): Promise<RouterOsFirmwareStatus> {
    const res = await apiClient.put<ApiResponse<RouterOsFirmwareStatus>>('/firmware/routeros/target', target);
    return res.data.data!;
  },

  /** Platform admin only, rate-limited. MikroTik failures come back as `ok: false` outcomes. */
  async checkNow(): Promise<RouterOsReleaseCheckResult> {
    const res = await apiClient.post<ApiResponse<RouterOsReleaseCheckResult>>('/firmware/routeros/check');
    return res.data.data!;
  },
};
