import apiClient from '@/api/client';
import type { ApiResponse, LanRepriseResult } from '@obliwan/shared';

/**
 * The LAN reprise — the client half of
 * `POST /api/allocation/tenants/:tenantId/lan-reprise` (platform admin;
 * server/src/services/allocation/lanReprise.ts), kept beside its modal. The
 * result's verdicts, reasons and warnings are closed codes (@obliwan/shared,
 * lanReprise.ts) the modal translates.
 *
 * `dryRun` is sent explicitly both ways: the server treats anything but
 * `dryRun=false` as a dry run, so a check can never write by omission.
 */
export const lanRepriseApi = {
  async run(tenantId: number, csv: string, opts: { overwrite: boolean; dryRun: boolean }): Promise<LanRepriseResult> {
    const res = await apiClient.post<ApiResponse<LanRepriseResult>>(
      `/allocation/tenants/${tenantId}/lan-reprise`,
      { csv, overwrite: opts.overwrite },
      { params: { dryRun: String(opts.dryRun) } },
    );
    return res.data.data!;
  },
};
