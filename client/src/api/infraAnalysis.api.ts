import apiClient from './client';
import type {
  ApiResponse,
  InfraAnalysisApplyRequest,
  InfraAnalysisApplyResult,
  InfraAnalysisCandidates,
  InfraAnalysisExport,
  InfraAnalysisPreviewRequest,
  InfraAnalysisSnapshot,
} from '@obliwan/shared';

/**
 * The infrastructure analysis (server: /api/infra-analysis, platform admin
 * only, on the session's CURRENT workspace).
 *
 *  - `preview` starts the read and answers at once with every device pending;
 *    the page polls `get` until `status` is `done`. It reads routers
 *    (read-only) and writes nothing in ObliWAN.
 *  - `apply` is the only call that writes: the selected rows, as site values.
 *  - `exportFiles` returns the Quick Setup variables CSV (a secret's cell is
 *    always empty) and the LAN reprise CSV.
 *  - `forget` drops the analysis now, and the secrets it read with it.
 *
 * A typed credential travels in the `preview` body only. No response carries
 * a secret back: a secret read is reported as `secret_found`.
 */
export const infraAnalysisApi = {
  async candidates(): Promise<InfraAnalysisCandidates> {
    const res = await apiClient.get<ApiResponse<InfraAnalysisCandidates>>('/infra-analysis/candidates');
    return res.data.data!;
  },
  async preview(body: InfraAnalysisPreviewRequest): Promise<InfraAnalysisSnapshot> {
    const res = await apiClient.post<ApiResponse<InfraAnalysisSnapshot>>('/infra-analysis/preview', body);
    return res.data.data!;
  },
  async get(id: string): Promise<InfraAnalysisSnapshot> {
    const res = await apiClient.get<ApiResponse<InfraAnalysisSnapshot>>(`/infra-analysis/${encodeURIComponent(id)}`);
    return res.data.data!;
  },
  async apply(body: InfraAnalysisApplyRequest): Promise<InfraAnalysisApplyResult> {
    const res = await apiClient.post<ApiResponse<InfraAnalysisApplyResult>>('/infra-analysis/apply', body);
    return res.data.data!;
  },
  async exportFiles(id: string): Promise<InfraAnalysisExport> {
    const res = await apiClient.get<ApiResponse<InfraAnalysisExport>>(`/infra-analysis/${encodeURIComponent(id)}/export`);
    return res.data.data!;
  },
  async forget(id: string): Promise<void> {
    await apiClient.delete(`/infra-analysis/${encodeURIComponent(id)}`);
  },
};

/** The server's refusal code (`code`), when it sent one. */
export function infraAnalysisErrorCode(err: unknown): string | null {
  const code = (err as { response?: { data?: { code?: unknown } } }).response?.data?.code;
  return typeof code === 'string' ? code : null;
}
