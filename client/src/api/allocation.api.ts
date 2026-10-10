import apiClient from './client';
import type { ApiResponse, SiteLanSource } from '@obliwan/shared';

/**
 * Platform-scoped address allocation (server: /api/allocation, admin only).
 * Mirrors server/src/services/allocation views. No call here ever returns a
 * PPP password: the shared one lives in the INSTANCE variable `ppp_password`,
 * per-site ones in the vault, and both are read server-side only.
 */

export type PoolPurpose = 'tunnel' | 'lan';
export type AddressMode = 'incremental' | 'formula';
export type LanMode = 'incremental' | 'formula' | 'fixed' | 'manual';
export type PppPasswordMode = 'shared' | 'per_site';

export interface AddressPool {
  id: number;
  name: string;
  cidr: string;
  purpose: PoolPurpose;
  allocated: number;
  policies: Array<{ tenantId: number; mode: AddressMode }>;
  createdAt: string;
  updatedAt: string;
}

export interface TunnelRuleView {
  poolId: number;
  poolName: string | null;
  poolCidr: string | null;
  mode: AddressMode;
  start: string | null;
  prefix: number | null;
  formula: string | null;
}

export interface LanRuleView {
  mode: LanMode;
  poolId: number | null;
  poolName: string | null;
  poolCidr: string | null;
  prefix: number | null;
  formula: string | null;
  subnet: string | null;
  variable: string | null;
}

export interface AllocationPolicy {
  tenantId: number;
  tunnel: TunnelRuleView;
  lan: LanRuleView | null;
  pppLoginTemplate: string;
  systemIdentityTemplate: string | null;
  pppPasswordMode: PppPasswordMode;
  derived: Record<string, string>;
  pppProfile: string | null;
  concentratorId: number;
  /** 'free' (no rule) or 'digits:N' — exactly N digits, leading zeros kept
   *  (migration 052). Judged where a site code is created or renamed. */
  siteCodeFormat?: string;
  createdAt: string;
  updatedAt: string;
}

/** The body PUT /tenants/:id/policy accepts. */
export interface AllocationPolicyInput {
  tunnel: { poolId: number; mode: AddressMode; start?: string; formula?: string };
  lan:
    | null
    | { mode: 'incremental'; poolId: number; prefix: number }
    | { mode: 'formula'; poolId: number; formula: string }
    | { mode: 'fixed'; subnet: string }
    | { mode: 'manual'; variable: string };
  pppLoginTemplate: string;
  systemIdentityTemplate: string | null;
  pppPasswordMode: PppPasswordMode;
  derived: Record<string, string> | null;
  pppProfile: string | null;
  concentratorId: number;
  /** 'free' or 'digits:N'. Absent: the stored format is kept. */
  siteCodeFormat?: string;
}

/** 'allocated': computed from the policy. 'adopted_chr': read from a secret
 *  the tenant's concentrator already declares — a deployed site, recorded as
 *  it is. */
export type AllocationSource = 'allocated' | 'adopted_chr';

export interface SitePlan {
  siteNumber: number | null;
  tunnelIp: string;
  lanSubnet: string | null;
  lanSource: 'pool' | 'fixed' | 'manual' | null;
  /** For an adopted plan, the concentrator's own spelling. */
  pppLogin: string;
  systemIdentity: string | null;
  derived: Record<string, string>;
  source: AllocationSource;
  pppProfile: string | null;
  /** Adopted only: what the tunnel formula gives, when it differs from the
   *  concentrator's address (`tunnelIp` is the concentrator's). */
  formulaTunnelIp: string | null;
  /** Server sentences (not localised), every difference adoption found. */
  warnings: string[];
}

export interface PreviewEntry {
  index: number;
  siteId: number | null;
  code: string;
  name: string;
  plan: SitePlan | null;
  refusal: { reason: string; message: string } | null;
}

export interface AllocationPreview {
  tenantId: number;
  policy: AllocationPolicy;
  seeds: Array<{ concentratorId: number; readAt: string | null; secretCount: number | null; fresh: boolean }>;
  blockedBy: { reason: string; concentratorIds: number[]; message: string } | null;
  entries: PreviewEntry[];
}

export interface AllocatedSite {
  siteId: number;
  tenantId: number;
  siteCode: string;
  siteName: string;
  pppUsername: string;
  tunnelIp: string;
  lanSubnet: string | null;
  /** 'recorded': typed from the deployed store (LAN reprise, migration 070). */
  lanSource: SiteLanSource | null;
  pppPasswordMode: PppPasswordMode;
  systemIdentity: string | null;
  concentratorId: number;
  pppProfile: string | null;
  concentratorState: 'pending' | 'provisioned' | 'failed';
  concentratorError: string | null;
  /** null: allocated before provenance was recorded (migration 044). */
  source: AllocationSource | null;
  formulaTunnelIp: string | null;
  /** false: adopted in per-site mode — no password is held for this site. */
  pppPasswordKnown: boolean;
  allocatedAt: string;
}

export interface ConcentratorOption {
  id: number;
  name: string;
  tenantId: number;
}

export interface TenantOption {
  id: number;
  name: string;
  slug: string;
}

// ── CHR <-> sites reconciliation (server: reconcile.service.ts) ─────────────

/** What would stop the allocator adopting an account: its adoption refusals,
 *  restated by the report over the same recorded state (the allocation
 *  preview remains the verdict). */
export type ReconcileBlocker =
  | 'ambiguous'
  | 'noAddress'
  | 'sessionOnly'
  | 'otherTenant'
  | 'sharedLogin'
  | 'loginTaken'
  | 'addressTaken'
  | 'addressInLan'
  | 'foreignPool'
  | 'profileInvalid'
  | 'otherConcentrator';
export type ReconcileNote = 'disabled' | 'caseDiffers' | 'addressDiffers';
export type NearReason = 'country' | 'prefix' | 'zeros' | 'separator' | 'name' | 'template' | 'device';

/** Who holds the address or the login a blocker is about. */
export interface ReconcileHolder {
  kind: 'site' | 'lan' | 'device' | 'session' | 'secret';
  /** site / lan: the site's code; device: its name; session / secret: the account name. */
  name: string;
  /** lan: the subnet; session / secret: the CHR's device id. */
  detail: string | null;
  tenantSlug: string | null;
}

export interface ChrAccount {
  concentratorId: number;
  name: string;
  /** false: an open PPP session with no /ppp/secret entry. */
  declared: boolean;
  /** As the secret declares it, never the session's address. */
  remoteAddress: string | null;
  profile: string | null;
  disabled: boolean | null;
  firstSeenAt: string | null;
  /** The last read of the CHR that listed this secret. */
  lastReadAt: string | null;
  /** As presence recorded it. `since` is when presence FIRST SAW the open
   *  session, not when the router dialled. */
  session: { up: boolean; since: string | null; address: string | null; lastEndedAt: string | null };
  /** A device of THIS tenant bound to the account (its ppp_username). */
  device: { id: number; name: string; siteId: number | null } | null;
}

export interface ParsedChrLogin {
  code: string | null;
  number: number | null;
  slug: string | null;
  country: string | null;
}

export interface ReconcileSiteRef {
  siteId: number;
  code: string;
  name: string;
  country: string | null;
}

export interface ReconcileAllocationRef {
  source: AllocationSource | null;
  state: string;
  tunnelIp: string;
  concentratorId: number;
}

export interface ReconcileMatched extends ReconcileSiteRef {
  login: string;
  status: 'allocated' | 'adopted' | 'adoptable';
  account: ChrAccount;
  variants: string[];
  allocation: ReconcileAllocationRef | null;
  blockers: ReconcileBlocker[];
  holders: ReconcileHolder[];
  notes: ReconcileNote[];
}

export type ReconcileNearSite = ReconcileSiteRef & { reasons: NearReason[] };

export interface ReconcileOrphan {
  account: ChrAccount;
  parsed: ParsedChrLogin;
  /** `name` is set only when the template uses {site.slug} (it then decides the login). */
  prefill: { code: string | null; name: string | null; country: string | null };
  blockers: ReconcileBlocker[];
  holders: ReconcileHolder[];
  /** No blocker the report can see: a site created with `prefill` SHOULD be
   *  adopted by its allocation. Not the allocator's verdict. */
  creationAdopts: boolean;
  nearSites: ReconcileNearSite[];
}

export interface ReconcileSiteOnly extends ReconcileSiteRef {
  kind: 'new' | 'suspect';
  login: string | null;
  /** Server sentence (not localised), as in the preview. */
  loginError: { reason: string; message: string } | null;
  allocation: ReconcileAllocationRef | null;
  nearMatches: Array<{ account: ChrAccount; parsed: ParsedChrLogin | null; reasons: NearReason[] }>;
}

export interface ReconcileOffPattern {
  account: ChrAccount;
  /** Why it is listed: it carries the template's fixed part, its name contains
   *  the tenant slug, or a router of this tenant dials it. */
  via: 'anchor' | 'slug' | 'device';
  nearSites: ReconcileNearSite[];
}

export interface ReconcileReport {
  tenantId: number;
  tenantSlug: string;
  tenantName: string;
  generatedAt: string;
  loginTemplate: string;
  policyConcentratorId: number;
  pattern: {
    display: string;
    regex: string;
    captures: Array<'code' | 'id' | 'slug' | 'country'>;
    anchor: { kind: 'suffix' | 'prefix'; text: string } | null;
    /** false: the template names no tenant, so an account it reads may be any customer's. */
    namesTenant: boolean;
  };
  inventory: Array<{
    concentratorId: number;
    name: string | null;
    policy: boolean;
    readAt: string | null;
    secretCount: number | null;
    freshness: 'never' | 'stale' | 'fresh';
    /** What presence recorded for this CHR: how far "online" can be trusted. */
    presence: {
      sessionsRecorded: number;
      openSessions: number;
      lastEventAt: string | null;
      degradedSince: string | null;
    };
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
    unexplained: number;
    unexplainedOnline: number;
    excludedOtherTenant: number;
    excludedSharedPattern: number;
  };
  matched: ReconcileMatched[];
  orphans: ReconcileOrphan[];
  siteOnly: ReconcileSiteOnly[];
  offPattern: ReconcileOffPattern[];
  /** CHR accounts no tenant accounts for, online first. */
  unexplained: ChrAccount[];
}

/** What one re-read of a CHR's /ppp/secret recorded. */
export interface SecretInventoryResult {
  recorded: number;
  vanished: number;
  duplicateNames: number;
}

/** The server's refusal body: a sentence, a reason code and per-field errors. */
export interface AllocationApiError {
  message: string;
  reason: string | null;
  details: Record<string, string[]>;
}

export function allocationError(err: unknown): AllocationApiError {
  const data = (err as { response?: { data?: { error?: unknown; reason?: unknown; details?: unknown } } })?.response
    ?.data;
  const details =
    data && typeof data.details === 'object' && data.details !== null ? (data.details as Record<string, string[]>) : {};
  return {
    message: typeof data?.error === 'string' ? data.error : err instanceof Error ? err.message : String(err),
    reason: typeof data?.reason === 'string' ? data.reason : null,
    details,
  };
}

/** `?tz=<the browser's IANA zone>`, or '' when the browser does not say. */
export function browserTzQuery(): string {
  let tz = '';
  try {
    tz = Intl.DateTimeFormat().resolvedOptions().timeZone ?? '';
  } catch {
    tz = '';
  }
  return tz ? `?${new URLSearchParams({ tz }).toString()}` : '';
}

export const allocationApi = {
  async tenants(): Promise<TenantOption[]> {
    const res = await apiClient.get<ApiResponse<TenantOption[]>>('/tenants');
    return res.data.data ?? [];
  },

  async pools(): Promise<AddressPool[]> {
    const res = await apiClient.get<ApiResponse<AddressPool[]>>('/allocation/pools');
    return res.data.data ?? [];
  },

  async createPool(input: { name: string; cidr: string; purpose: PoolPurpose }): Promise<AddressPool> {
    const res = await apiClient.post<ApiResponse<AddressPool>>('/allocation/pools', input);
    return res.data.data!;
  },

  async deletePool(poolId: number): Promise<void> {
    await apiClient.delete(`/allocation/pools/${poolId}`);
  },

  async concentrators(): Promise<ConcentratorOption[]> {
    const res = await apiClient.get<ApiResponse<ConcentratorOption[]>>('/allocation/concentrators');
    return res.data.data ?? [];
  },

  async instanceDomain(): Promise<string> {
    const res = await apiClient.get<ApiResponse<{ domain: string }>>('/allocation/instance-domain');
    return res.data.data?.domain ?? '';
  },

  async setInstanceDomain(domain: string): Promise<string> {
    const res = await apiClient.put<ApiResponse<{ domain: string }>>('/allocation/instance-domain', { domain });
    return res.data.data?.domain ?? '';
  },

  async policy(tenantId: number): Promise<AllocationPolicy | null> {
    const res = await apiClient.get<ApiResponse<AllocationPolicy | null>>(`/allocation/tenants/${tenantId}/policy`);
    return res.data.data ?? null;
  },

  async savePolicy(tenantId: number, input: AllocationPolicyInput): Promise<AllocationPolicy> {
    const res = await apiClient.put<ApiResponse<AllocationPolicy>>(`/allocation/tenants/${tenantId}/policy`, input);
    return res.data.data!;
  },

  /** The next `limit` allocations of the tenant's sites that have none yet. Commits nothing. */
  async previewNext(tenantId: number, limit: number): Promise<AllocationPreview> {
    const res = await apiClient.get<ApiResponse<AllocationPreview>>(`/allocation/tenants/${tenantId}/next`, {
      params: { limit },
    });
    return res.data.data!;
  },

  async allocatedSites(tenantId: number): Promise<AllocatedSite[]> {
    const res = await apiClient.get<ApiResponse<AllocatedSite[]>>(`/allocation/tenants/${tenantId}/sites`);
    return res.data.data ?? [];
  },

  /**
   * Release a site's allocation (platform admin). Refused (409
   * ALREADY_PROVISIONED) once the concentrator holds the PPP account, unless
   * `confirmProvisionedLogin` names that account's login. Never touches the
   * concentrator: the account stays declared there.
   */
  async releaseSite(siteId: number, confirmProvisionedLogin?: string): Promise<void> {
    await apiClient.delete(`/allocation/sites/${siteId}`, {
      params: confirmProvisionedLogin ? { confirmProvisioned: confirmProvisionedLogin } : undefined,
    });
  },

  /** CHR <-> sites reconciliation of the tenant. Read-only: allocates nothing, dials nothing. */
  async reconcile(tenantId: number): Promise<ReconcileReport> {
    const res = await apiClient.get<ApiResponse<ReconcileReport>>(`/allocation/tenants/${tenantId}/reconcile`);
    return res.data.data!;
  },

  /** The .xlsx URL, opened by the browser so the download carries the session
   *  cookie. Dates are written in the browser's own time zone. */
  reconcileXlsxUrl(tenantId: number): string {
    let tz = '';
    try {
      tz = Intl.DateTimeFormat().resolvedOptions().timeZone ?? '';
    } catch {
      tz = '';
    }
    const qs = tz ? `?${new URLSearchParams({ tz }).toString()}` : '';
    return `/api/allocation/tenants/${tenantId}/reconcile.xlsx${qs}`;
  },

  /** The orphans as a workbook the site import reads back as it is (code,
   *  name, country, …): fill the names, save as CSV, import it from Sites. */
  reconcileOrphansXlsxUrl(tenantId: number): string {
    return `/api/allocation/tenants/${tenantId}/reconcile/orphans.xlsx${browserTzQuery()}`;
  },

  /** Create one site IN THIS TENANT (not the session's), with its country. Allocates nothing. */
  async createReconciledSite(
    tenantId: number,
    input: { code: string; name: string; country: string | null },
  ): Promise<{ id: number; tenantId: number; code: string; name: string; country: string | null }> {
    const res = await apiClient.post<
      ApiResponse<{ id: number; tenantId: number; code: string; name: string; country: string | null }>
    >(`/allocation/tenants/${tenantId}/reconcile/sites`, input);
    return res.data.data!;
  },

  /** Re-read a concentrator's /ppp/secret now (nothing is written to the router). */
  async rereadConcentrator(concentratorId: number): Promise<SecretInventoryResult> {
    const res = await apiClient.post<ApiResponse<SecretInventoryResult>>(
      `/allocation/concentrators/${concentratorId}/secrets/read`,
    );
    return res.data.data!;
  },
};
