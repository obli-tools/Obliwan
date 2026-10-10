import apiClient from './client';
import type {
  ApiResponse,
  BreakRiskReport,
  LearningCaptureDetail,
  LearningCaptureStart,
  LearningDataset,
  LearningDeviceRow,
  LearningRunView,
  LearningStateResult,
} from '@obliwan/shared';

/**
 * Learning mode (server: /api/learning, platform admin only).
 *
 *  - `setLearning` / `setLearningBulk` put routers in or out of learning; while
 *    in it, template pushes are refused for them;
 *  - `startCapture` reads the routers WITH their secrets (to the vault, server
 *    side) and answers at once; the page polls `run`;
 *  - `capture`, `exportText` and `dataset` return REDACTED material only:
 *    every secret is `secret:<ref>`, never a value;
 *  - `breakRisk` compares a template with what the router runs (read-only).
 */
export const learningApi = {
  async devices(params: { learningOnly?: boolean; search?: string } = {}): Promise<{ rows: LearningDeviceRow[]; godView: boolean }> {
    const res = await apiClient.get<ApiResponse<LearningDeviceRow[]> & { godView?: boolean }>('/learning/devices', {
      params: {
        ...(params.learningOnly ? { learningOnly: 'true' } : {}),
        ...(params.search && params.search.trim() !== '' ? { search: params.search.trim() } : {}),
      },
    });
    return { rows: res.data.data ?? [], godView: res.data.godView === true };
  },
  async setLearning(deviceId: number, learning: boolean): Promise<LearningStateResult> {
    const res = await apiClient.put<ApiResponse<LearningStateResult>>(`/learning/devices/${deviceId}`, { learning });
    return res.data.data!;
  },
  async setLearningBulk(deviceIds: number[], learning: boolean): Promise<LearningStateResult> {
    const res = await apiClient.post<ApiResponse<LearningStateResult>>('/learning/devices/state', { deviceIds, learning });
    return res.data.data!;
  },
  async startCapture(deviceIds: number[]): Promise<LearningCaptureStart> {
    const res = await apiClient.post<ApiResponse<LearningCaptureStart>>('/learning/captures', { deviceIds });
    return res.data.data!;
  },
  async run(runId: string): Promise<LearningRunView> {
    const res = await apiClient.get<ApiResponse<LearningRunView>>(`/learning/runs/${encodeURIComponent(runId)}`);
    return res.data.data!;
  },
  async capture(deviceId: number): Promise<LearningCaptureDetail | null> {
    const res = await apiClient.get<ApiResponse<LearningCaptureDetail | null>>(`/learning/devices/${deviceId}/capture`);
    return res.data.data ?? null;
  },
  async exportText(captureId: number): Promise<string> {
    const res = await apiClient.get<ApiResponse<{ text: string }>>(`/learning/captures/${captureId}/export`);
    return res.data.data?.text ?? '';
  },
  async breakRisk(deviceId: number, revisionId?: string | null): Promise<BreakRiskReport> {
    const res = await apiClient.get<ApiResponse<BreakRiskReport>>(`/learning/devices/${deviceId}/break-risk`, {
      params: revisionId ? { revisionId } : {},
    });
    return res.data.data!;
  },
  async dataset(deviceIds: number[]): Promise<LearningDataset> {
    const res = await apiClient.post<ApiResponse<LearningDataset>>('/learning/dataset', { deviceIds });
    return res.data.data!;
  },
};

/** The server's refusal code (`code`), when it sent one. */
export function learningErrorCode(err: unknown): string | null {
  const code = (err as { response?: { data?: { code?: unknown } } }).response?.data?.code;
  return typeof code === 'string' ? code : null;
}
