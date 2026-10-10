import apiClient from '@/api/client';
import {
  TLS_REPIN_REFUSALS,
  type ApiResponse,
  type TlsRepinRefusal,
  type TlsRepinRequest,
  type TlsRepinResult,
} from '@obliwan/shared';

/**
 * Re-pin a RouterOS API channel to the certificate the device presented — the
 * client half of `server/src/routes/tlsRepin.routes.ts`, kept beside the
 * notice that uses it. The server accepts only the fingerprint IT recorded as
 * presented, and only while the pin is still the one sent with it.
 */
export const tlsRepinApi = {
  async repin(deviceId: number, body: TlsRepinRequest): Promise<TlsRepinResult> {
    const res = await apiClient.post<ApiResponse<TlsRepinResult>>(
      `/devices/${deviceId}/transports/routeros_api/repin`,
      body,
    );
    return res.data.data!;
  },
};

/** The refusal code of a failed re-pin, when the server sent a known one. */
export function tlsRepinRefusalOf(err: unknown): { code: TlsRepinRefusal | null; message: string | null } {
  const data = (err as { response?: { data?: { code?: unknown; error?: unknown } } }).response?.data;
  const code = typeof data?.code === 'string' && (TLS_REPIN_REFUSALS as readonly string[]).includes(data.code)
    ? (data.code as TlsRepinRefusal)
    : null;
  return { code, message: typeof data?.error === 'string' ? data.error : null };
}
