import apiClient from './client';
import type {
  ExtrapolatedSiteResult,
  ExtrapolationApproveResult,
  ExtrapolationOverride,
  ExtrapolationProposal,
  ExtrapolationProposalSummary,
  ExtrapolationReadiness,
  ExtrapolationRun,
} from '@obliwan/shared';

/**
 * Brick 10 — the template extrapolator (proposals mined from a fleet's exports).
 *
 * Routes, read off `server/src/routes/baseline.routes.ts` (bare JSON, no
 * envelope, shapes = `shared/src/extrapolator.ts`):
 *
 *   GET  /baseline/extrapolations                        -> ExtrapolationRun[]
 *   GET  /baseline/extrapolations/readiness              -> ExtrapolationReadiness
 *   POST /baseline/extrapolations  ExtrapolationParams   -> 202 ExtrapolationRun (running)
 *   GET  /baseline/extrapolations/:id                    -> { run, proposals }
 *   GET  /baseline/extrapolation-proposals/:id           -> ExtrapolationProposal
 *   GET  /baseline/extrapolation-proposals/:id/sites/:d  -> ExtrapolatedSiteResult (all lines)
 *   POST /baseline/extrapolation-proposals/:id/approve   -> 201 ExtrapolationApproveResult
 *   POST /baseline/extrapolation-proposals/:id/reject    -> ExtrapolationProposalSummary
 *
 * Starting a run is CONFIG_READ (it mines and renders, it writes nothing a
 * router sees); approving and rejecting are TEMPLATE_WRITE.
 */
export interface StartExtrapolationRequest {
  baselineRunId: number | null;
  minReproduction?: number;
  deviationMaxSites?: number;
  overrides?: ExtrapolationOverride[];
  /** With no baselineRunId: one proposal per router model (default), or the
   *  historical structural profiles. Ignored by the server when a miner run
   *  is named. */
  groupBy?: 'model' | 'profile';
  /** groupBy 'model': at most this many profiles per model (1..4). */
  maxProfilesPerModel?: number;
}

export const extrapolatorApi = {
  async listRuns(): Promise<ExtrapolationRun[]> {
    const res = await apiClient.get<ExtrapolationRun[]>('/baseline/extrapolations');
    return Array.isArray(res.data) ? res.data : [];
  },

  /** Which of the client's routers the extrapolator can read, per model. */
  async readiness(): Promise<ExtrapolationReadiness> {
    const res = await apiClient.get<ExtrapolationReadiness>('/baseline/extrapolations/readiness');
    return res.data;
  },

  async start(req: StartExtrapolationRequest): Promise<ExtrapolationRun> {
    const res = await apiClient.post<ExtrapolationRun>('/baseline/extrapolations', req);
    return res.data;
  },

  async getRun(runId: number): Promise<{ run: ExtrapolationRun; proposals: ExtrapolationProposalSummary[] }> {
    const res = await apiClient.get<{ run: ExtrapolationRun; proposals: ExtrapolationProposalSummary[] }>(
      `/baseline/extrapolations/${runId}`,
    );
    return res.data;
  },

  async getProposal(proposalId: number): Promise<ExtrapolationProposal> {
    const res = await apiClient.get<ExtrapolationProposal>(`/baseline/extrapolation-proposals/${proposalId}`);
    return res.data;
  },

  async getSite(proposalId: number, deviceId: number): Promise<ExtrapolatedSiteResult> {
    const res = await apiClient.get<ExtrapolatedSiteResult>(
      `/baseline/extrapolation-proposals/${proposalId}/sites/${deviceId}`,
    );
    return res.data;
  },

  async approve(
    proposalId: number,
    body: { name: string; description: string | null; writeValues: boolean; modelPattern?: string | null },
  ): Promise<ExtrapolationApproveResult> {
    const res = await apiClient.post<ExtrapolationApproveResult>(
      `/baseline/extrapolation-proposals/${proposalId}/approve`,
      body,
    );
    return res.data;
  },

  async reject(proposalId: number, note: string): Promise<ExtrapolationProposalSummary> {
    const res = await apiClient.post<ExtrapolationProposalSummary>(
      `/baseline/extrapolation-proposals/${proposalId}/reject`,
      { note },
    );
    return res.data;
  },
};
