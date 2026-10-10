import apiClient from './client';
import type {
  ApiResponse,
  OnboardingStatus,
  RuleApproveRequest,
  RuleApproveResult,
  RuleInference,
} from '@obliwan/shared';

/**
 * The onboarding assistant (server: /api/tenant-setup/onboarding, platform
 * administrators only). The tenant is the session's workspace, or — from the
 * Default workspace's god view — the client picked in the workspace filter,
 * which `api/client.ts` adds to every request (`?filterTenantId=`).
 *
 * Two reads and one write: the write saves the inferred allocation rule, and
 * only the exact proposal shown (its fingerprint) — a proposal that changed
 * since is refused (409) with nothing written.
 */
export const onboardingApi = {
  async status(): Promise<OnboardingStatus> {
    const res = await apiClient.get<ApiResponse<OnboardingStatus>>('/tenant-setup/onboarding');
    if (!res.data.data) throw new Error(res.data.error ?? 'The onboarding status answered without a body');
    return res.data.data;
  },

  /** The rule read off the CHR accounts naming `slug` (default: the tenant's). */
  async inferRule(slug?: string): Promise<RuleInference> {
    const res = await apiClient.get<ApiResponse<RuleInference>>('/tenant-setup/onboarding/rule', {
      params: slug && slug.trim() !== '' ? { slug: slug.trim() } : {},
    });
    if (!res.data.data) throw new Error(res.data.error ?? 'The rule inference answered without a body');
    return res.data.data;
  },

  async approveRule(body: RuleApproveRequest): Promise<RuleApproveResult> {
    const res = await apiClient.post<ApiResponse<RuleApproveResult>>('/tenant-setup/onboarding/rule/approve', body);
    if (!res.data.data) throw new Error(res.data.error ?? 'The approval answered without a body');
    return res.data.data;
  },
};
