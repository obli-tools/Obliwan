import apiClient from './client';
import type {
  ApiResponse,
  ReconcileAttachFollowUpOptions,
  ReconcileAttachPreview,
  ReconcileAttachResult,
} from '@obliwan/shared';
import { browserTzQuery, type NearReason } from './allocation.api';
import { GOD_VIEW_TENANT_FILTER_PARAM } from '@obliwan/shared';
import { useGodViewStore } from '@/store/godViewStore';

/** The SSH account the bulk attach logs in with; absent = `admin` and the
 *  vault's `admin_password`, resolved per site by the server. */
export interface ReconcileAttachCredentials {
  username: string;
  password: string;
}

/**
 * The CHR <-> sites reconciliation of the SESSION's tenant (server:
 * `/api/reconcile`, RECONCILE_READ — reconcile.routes.ts). No call here names
 * a tenant: the server reads it off the session. The view is REDACTED
 * (reconcile.service `redactReport`): no other tenant, no address, profile,
 * pool or concentrator identity, no adoption holder, never a password.
 *
 * The platform admin's full report over any tenant is `allocationApi.reconcile`.
 */

/** An account as a tenant user sees it. */
export interface TenantChrAccount {
  name: string;
  /** false: an open PPP session with no /ppp/secret entry. */
  declared: boolean;
  disabled: boolean | null;
  /** As presence recorded it; `since` is when presence FIRST SAW the session. */
  session: { up: boolean; since: string | null; lastEndedAt: string | null };
  /** A router of this tenant dialling it. */
  device: { id: number; name: string; siteId: number | null } | null;
}

export interface TenantNearSite {
  siteId: number;
  code: string;
  name: string;
  country: string | null;
  reasons: NearReason[];
}

export interface TenantReconcileView {
  tenantName: string;
  generatedAt: string;
  pattern: string;
  inventory: Array<{
    policy: boolean;
    readAt: string | null;
    freshness: 'never' | 'stale' | 'fresh';
    presenceRecorded: boolean;
    degradedSince: string | null;
    /** The last recorded /ppp/active read (what `duplicates` is as current
     *  as); null: never recorded. */
    activeReadAt: string | null;
  }>;
  counts: {
    sites: number;
    matched: number;
    orphans: number;
    orphansOnline: number;
    siteOnly: number;
    siteOnlyNew: number;
    siteOnlySuspect: number;
    offPattern: number;
    duplicates: number;
  };
  /** This workspace's accounts the concentrator lists with SEVERAL live
   *  sessions at once (their tunnel address is ambiguous: the attach and the
   *  jobs through the tunnel refuse them). Caller-id and uptime per session. */
  duplicates: Array<{
    account: string;
    group: 'matched' | 'orphan' | 'offPattern';
    site: { siteId: number; code: string; name: string; country: string | null } | null;
    device: { id: number; name: string; siteId: number | null } | null;
    sessions: Array<{ callerId: string | null; uptime: string | null; since: string | null }>;
    firstSeenAt: string;
    observedAt: string;
  }>;
  matched: Array<{
    siteId: number;
    code: string;
    name: string;
    country: string | null;
    login: string;
    status: 'allocated' | 'adopted' | 'adoptable';
    account: TenantChrAccount;
    blocked: boolean;
    notes: Array<'disabled' | 'caseDiffers'>;
  }>;
  orphans: Array<{
    account: TenantChrAccount;
    prefill: { code: string | null; name: string | null; country: string | null };
    blocked: boolean;
    creationAdopts: boolean;
    nearSites: TenantNearSite[];
  }>;
  siteOnly: Array<{
    siteId: number;
    code: string;
    name: string;
    country: string | null;
    kind: 'new' | 'suspect';
    login: string | null;
    /** Server sentence (not localised). */
    loginError: string | null;
    allocated: boolean;
    nearMatches: Array<{ account: TenantChrAccount; reasons: NearReason[] }>;
    /** Resembling accounts withheld from this view. */
    withheld: number;
  }>;
  offPattern: Array<{ account: TenantChrAccount; via: 'anchor' | 'device'; nearSites: TenantNearSite[] }>;
}

/** The server's refusal: a sentence and a reason code (TEMPLATE_NAMES_NO_TENANT,
 *  NO_POLICY, …). */
export function reconcileError(err: unknown): { status: number | null; reason: string | null; message: string } {
  const r = (err as { response?: { status?: number; data?: { error?: unknown; reason?: unknown } } })?.response;
  return {
    status: typeof r?.status === 'number' ? r.status : null,
    reason: typeof r?.data?.reason === 'string' ? r.data.reason : null,
    message: typeof r?.data?.error === 'string' ? r.data.error : err instanceof Error ? err.message : String(err),
  };
}

export const reconcileApi = {
  /** Read-only: what the last CHR read recorded, compared with the sites. Dials nothing. */
  async view(): Promise<TenantReconcileView> {
    const res = await apiClient.get<ApiResponse<TenantReconcileView>>('/reconcile');
    return res.data.data!;
  },

  /** Re-read the concentrator's /ppp/secret (nothing written to it), then the fresh view. */
  async reread(): Promise<TenantReconcileView> {
    const res = await apiClient.post<ApiResponse<TenantReconcileView>>('/reconcile/reread');
    return res.data.data!;
  },

  /** The orphans in the site import's own columns, opened by the browser so the
   *  download carries the session cookie. */
  orphansXlsxUrl(): string {
    // A plain link, so the axios interceptor never sees it: the god view's
    // workspace pick (store/godViewStore.ts) is added here by hand.
    const { active, filterTenantId } = useGodViewStore.getState();
    const base = `/api/reconcile/orphans.xlsx${browserTzQuery()}`;
    if (!active || filterTenantId === null) return base;
    return `${base}${base.includes('?') ? '&' : '?'}${GOD_VIEW_TENANT_FILTER_PARAM}=${filterTenantId}`;
  },

  /** The bulk attach's dry run (DEVICE_WRITE + CREDENTIAL_MANAGE): per site,
   *  what would happen, and per eligible router the jobs that would follow
   *  (absent options = the server's defaults, both). Every site of the
   *  workspace when `siteIds` is absent. Dials nothing; the answer never
   *  carries a password. */
  async attachPreview(
    body: { siteIds?: number[]; credentials?: ReconcileAttachCredentials } & Partial<ReconcileAttachFollowUpOptions>,
  ): Promise<ReconcileAttachPreview> {
    const res = await apiClient.post<ApiResponse<ReconcileAttachPreview>>('/reconcile/attach-devices/preview', body);
    return res.data.data!;
  },

  /** Prove each site's router over SSH (reads only) and create it, active and
   *  managed, then queue what follows it (management access, then the
   *  template fixes) — which needs `confirmNoDeadman: true`. At most
   *  RECONCILE_ATTACH_APPLY_MAX_SITES sites per call: the caller slices the
   *  selection. */
  async attachApply(
    body: { siteIds: number[]; credentials?: ReconcileAttachCredentials; confirmNoDeadman?: boolean; learning?: boolean } & Partial<ReconcileAttachFollowUpOptions>,
  ): Promise<ReconcileAttachResult> {
    const res = await apiClient.post<ApiResponse<ReconcileAttachResult>>('/reconcile/attach-devices', body);
    return res.data.data!;
  },
};
