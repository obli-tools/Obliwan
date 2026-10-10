import apiClient from './client';
import type { AccessCheckReapplyResult, AccessCheckRunView, AccessCheckScheduleView, ApiResponse } from '@obliwan/shared';

/**
 * "Verify and re-apply the management access and the template fixes" over the
 * workspace (server: `/api/reconcile/access-check`, CHANGE_APPLY, narrowed to
 * the devices the caller's teams grant `rw` on — fleet/accessCheck.service.ts).
 * No call names a tenant: the server reads it off the session (in the god
 * view, the workspace filter picks it, as for the rest of the reconciliation).
 * Refusals answer `{ error, reason }`: read them with `reconcileError`.
 */
export const accessCheckApi = {
  /** The latest verification of the workspace, or null. Dials nothing. */
  async latest(): Promise<AccessCheckRunView | null> {
    const res = await apiClient.get<ApiResponse<AccessCheckRunView | null>>('/reconcile/access-check');
    return res.data.data ?? null;
  },

  /** The nightly verification as the workspace's settings resolve it, and
   *  its open alerts. Dials nothing. */
  async schedule(): Promise<AccessCheckScheduleView> {
    const res = await apiClient.get<ApiResponse<AccessCheckScheduleView>>('/reconcile/access-check/schedule');
    return res.data.data!;
  },

  /** Start a verification: every router `pending`, verified in the
   *  background (read-only towards the routers); poll `latest()`. */
  async start(): Promise<AccessCheckRunView> {
    const res = await apiClient.post<ApiResponse<AccessCheckRunView>>('/reconcile/access-check');
    return res.data.data!;
  },

  /** Queue the jobs the verification marked (it must be fresh and not
   *  re-applied yet); `confirmNoDeadman` is the safety-net rule's explicit confirmation. */
  async reapply(body: { runId: string; confirmNoDeadman: true; deviceIds?: number[] }): Promise<AccessCheckReapplyResult> {
    const res = await apiClient.post<ApiResponse<AccessCheckReapplyResult>>('/reconcile/access-check/reapply', body);
    return res.data.data!;
  },
};
