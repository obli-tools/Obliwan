import apiClient from './client';
import type { ApiResponse, SiteUplinkKind } from '@obliwan/shared';
import type { Site, SiteInput, PppSession, Device } from '@/types/fleet';

/** What a bulk access-link declaration did (server `SiteUplinkBulkResult`). */
export interface SiteUplinkBulkResult {
  uplinkKind: SiteUplinkKind | null;
  requested: number;
  /** Declared now (stamped and audited). */
  changed: number;
  /** Already carried this declaration: untouched. */
  unchanged: number;
  changedSiteIds: number[];
  /** Open 4G backup alerts closed because their site is now 4G-only. */
  backupAlertsClosed: number;
}

/** What a bulk « Opérateur du lien fixe » did (server `SiteFixedProviderBulkResult`). */
export interface SiteFixedProviderBulkResult {
  fixedProvider: string | null;
  requested: number;
  changed: number;
  unchanged: number;
  changedSiteIds: number[];
}

export interface SiteListParams {
  search?: string;
  /** God view only: narrow to one tenant (ignored by the server otherwise). */
  filterTenantId?: number;
}

/**
 * Deployment state of a site — mirror of `SITE_DEPLOYMENT_STATES` in
 * server/src/services/fleet/siteDeployment.service.ts, in the server's
 * precedence order (the first state that applies wins).
 */
export const SITE_DEPLOYMENT_STATES = [
  'anomaly',
  'online',
  'prepared',
  'ready',
  'allocated_pending_chr',
  'to_allocate',
  'not_applicable',
] as const;
export type SiteDeploymentState = (typeof SITE_DEPLOYMENT_STATES)[number];

/** Why the site is in its state — mirror of `SITE_DEPLOYMENT_REASONS`. */
export type SiteDeploymentReason =
  | 'device_quarantined'
  | 'chr_failed'
  | 'bench_failed'
  | 'router_down'
  | 'tunnel_down'
  | 'concentrator_degraded'
  | 'tunnel_up'
  | 'health_ok'
  | 'reconnecting'
  | 'bench_applied'
  | 'bench_applied_chr_pending'
  | 'chr_provisioned'
  | 'chr_adopted'
  | 'bench_compiled'
  | 'chr_pending'
  | 'concentrator_site'
  | 'no_allocation';

export interface SiteDeployment {
  siteId: number;
  /** The caller's level on the site (migration 087); absent on an older server. */
  access?: 'ro' | 'rw';
  code: string;
  name: string;
  state: SiteDeploymentState;
  reason: SiteDeploymentReason;
  /** The instant the state is based on. */
  since: string | null;
  /** The server's French sentence (the Excel export's "Détail"). The page
   *  localises from `reason` + `detailParams` and falls back to this text. */
  detail: string;
  detailParams: { device: string | null; station: string | null };
  pppLogin: string | null;
  tunnelIp: string | null;
  lanSubnet: string | null;
  allocationSource: 'allocated' | 'adopted_chr' | null;
  preparedAt: string | null;
  preparedBy: string | null;
  onlineSince: string | null;
  device: { id: number; name: string; model: string | null; serial: string | null } | null;
}

export interface SiteDeploymentMeta {
  generatedAt: string;
  pppDownGraceMinutes: number;
  benchTunnelWindowMinutes: number;
}

/** The page's own filters, so the exported file holds what the screen shows. */
export interface SiteDeploymentFilter {
  search?: string;
  states?: SiteDeploymentState[];
}

function deploymentParams(filter: SiteDeploymentFilter): Record<string, string> {
  const params: Record<string, string> = {};
  const search = filter.search?.trim();
  if (search) params.search = search;
  if (filter.states && filter.states.length > 0) params.state = filter.states.join(',');
  return params;
}

/** `attachment; filename="x.xlsx"` → `x.xlsx`; null when absent or odd. */
function fileNameFromDisposition(header: unknown): string | null {
  if (typeof header !== 'string') return null;
  const m = /filename="?([^";]+)"?/i.exec(header);
  const name = m?.[1]?.trim();
  return name && /^[\w.-]+$/.test(name) ? name : null;
}

/** A declared site variable the CSV template offers as a `var:<key>` column. */
export interface SiteImportTemplateVariable {
  key: string;
  label: string | null;
  secret: boolean;
  type: string | null;
  required: boolean;
}

export interface SiteImportTemplate {
  /** In order: the fixed columns, then one `var:<key>` per variable. */
  columns: string[];
  variables: SiteImportTemplateVariable[];
}

export type SiteImportAction = 'create' | 'update' | 'skip';

export interface SiteImportAllocation {
  status: 'allocated' | 'existing' | 'failed';
  pppUsername?: string;
  tunnelIp?: string;
  lanSubnet?: string | null;
  reason?: string;
  message?: string;
}

/**
 * What a dry-run row would be to the CHR (server: reconcile.service
 * `ChrRowVerdict`), for a caller allowed to see CHR matching. A WARNING, never
 * a refusal: a suspect row is written like any other.
 */
export interface SiteImportChrVerdict {
  ref: number;
  /** takesOver: its login IS a CHR account (adopted at allocation unless
   *  `blocked`); allocated: the site already holds its allocation; new: no
   *  account; suspect: an account names the same store differently; noLogin:
   *  the login cannot be rendered. */
  kind: 'takesOver' | 'allocated' | 'new' | 'suspect' | 'noLogin';
  login: string | null;
  account: { name: string; online: boolean } | null;
  blocked: boolean;
  /** Platform admin only (empty for anybody else). Same codes as the reconciliation. */
  blockers: string[];
  nearMatches: Array<{ name: string; online: boolean; reasons: string[]; slugOnly: boolean }>;
  /** Near-matches withheld from a non-admin's view. */
  withheld: number;
  /** Server sentence (not localised). */
  loginError: string | null;
}

/** How the dry run compared the file with the CHR. Absent: the caller may not see it. */
export type SiteImportChrSummary =
  | {
      status: 'compared';
      readAt: string;
      ageSeconds: number;
      freshness: 'never' | 'stale' | 'fresh';
      namesTenant: boolean;
      pattern: string;
      counts: Record<SiteImportChrVerdict['kind'], number>;
    }
  | { status: 'neverRead'; message: string }
  | { status: 'refused'; reason: 'TEMPLATE_NAMES_NO_TENANT'; message: string }
  | { status: 'unavailable'; reason: string; message: string };

/** One CSV row as the server judged it. `errors` never carries a value. */
export interface SiteImportRow {
  line: number;
  code: string;
  action: SiteImportAction;
  errors: string[];
  changes: string[];
  applied: boolean;
  siteId: number | null;
  allocation?: SiteImportAllocation;
  /** Dry run only, see `SiteImportChrVerdict`. */
  chr?: SiteImportChrVerdict;
}

export interface SiteImportResult {
  dryRun: boolean;
  allocate: boolean;
  delimiter: string;
  variableKeys: string[];
  /** Dry run only, see `SiteImportChrSummary`. */
  chr?: SiteImportChrSummary;
  rows: SiteImportRow[];
  summary: {
    rows: number;
    create: number;
    update: number;
    skip: number;
    rejected: number;
    applied: number;
    allocated: number;
    allocationFailed: number;
  };
}

export const sitesApi = {
  async list(params: SiteListParams = {}): Promise<Site[]> {
    const res = await apiClient.get<ApiResponse<Site[]>>('/sites', { params });
    return res.data.data ?? [];
  },

  /** Deployment state of every site of the tenant (`GET /sites/deployment`). */
  async deployment(
    filter: SiteDeploymentFilter = {},
  ): Promise<{ rows: SiteDeployment[]; meta: SiteDeploymentMeta | null }> {
    const res = await apiClient.get<ApiResponse<SiteDeployment[]> & { meta?: SiteDeploymentMeta }>(
      '/sites/deployment',
      { params: deploymentParams(filter) },
    );
    return { rows: res.data.data ?? [], meta: res.data.meta ?? null };
  },

  /**
   * The filtered list as an Excel workbook (`GET /sites/export.xlsx`). Dates
   * are written in the browser's own time zone. The file name is the
   * server's, from Content-Disposition.
   */
  async exportXlsx(filter: SiteDeploymentFilter = {}): Promise<{ blob: Blob; fileName: string }> {
    const params = deploymentParams(filter);
    try {
      const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
      if (tz) params.tz = tz;
    } catch {
      // No zone from the browser: the server's default (Europe/Paris) applies.
    }
    const res = await apiClient.get<Blob>('/sites/export.xlsx', { params, responseType: 'blob' });
    const fileName =
      fileNameFromDisposition(res.headers['content-disposition']) ??
      `sites-${new Date().toISOString().slice(0, 10)}.xlsx`;
    return { blob: res.data, fileName };
  },

  async getById(id: number): Promise<Site> {
    const res = await apiClient.get<ApiResponse<Site>>(`/sites/${id}`);
    return res.data.data!;
  },

  async create(data: SiteInput): Promise<Site> {
    const res = await apiClient.post<ApiResponse<Site>>('/sites', data);
    return res.data.data!;
  },

  async update(id: number, data: Partial<SiteInput>): Promise<Site> {
    const res = await apiClient.patch<ApiResponse<Site>>(`/sites/${id}`, data);
    return res.data.data!;
  },

  async remove(id: number): Promise<void> {
    await apiClient.delete(`/sites/${id}`);
  },

  /**
   * One access-link declaration for many sites (`POST /sites/bulk/uplink-kind`).
   * Every id must be a site of the session's workspace, or nothing is written
   * (404). `null` = back to "not declared" (ObliWAN infers it).
   */
  async bulkUplinkKind(ids: number[], uplinkKind: SiteUplinkKind | null): Promise<SiteUplinkBulkResult> {
    const res = await apiClient.post<ApiResponse<SiteUplinkBulkResult>>('/sites/bulk/uplink-kind', {
      ids,
      uplinkKind,
    });
    return res.data.data!;
  },

  /**
   * One « Opérateur du lien fixe » for many sites (`POST /sites/bulk/fixed-provider`,
   * migration 095). Same rule: every id of the workspace, or nothing is written
   * (404). `null` = back to "not declared" (the provider is inferred).
   */
  async bulkSetSiteFixedProvider(ids: number[], fixedProvider: string | null): Promise<SiteFixedProviderBulkResult> {
    const res = await apiClient.post<ApiResponse<SiteFixedProviderBulkResult>>('/sites/bulk/fixed-provider', {
      ids,
      fixedProvider,
    });
    return res.data.data!;
  },

  /** Columns and declared site variables for the CSV template (no values). */
  async importTemplate(): Promise<SiteImportTemplate> {
    const res = await apiClient.get<ApiResponse<SiteImportTemplate>>('/sites/import/template');
    return res.data.data!;
  },

  /**
   * Bulk import. `dryRun: true` writes nothing. A file the server cannot read
   * at all answers 400 with `errors: string[]`; refusals of single rows come
   * back inside the result, on their row.
   */
  async importCsv(
    csv: string,
    opts: { dryRun: boolean; allocate: boolean },
  ): Promise<SiteImportResult> {
    const res = await apiClient.post<ApiResponse<SiteImportResult>>(
      '/sites/import',
      { csv, allocate: opts.allocate },
      { params: { dryRun: String(opts.dryRun) } },
    );
    return res.data.data!;
  },

  /**
   * The devices filed under this site.
   *
   * Server-side filter, not a browser-side one over the whole fleet: the
   * collection endpoint is paginated, so filtering a truncated list renders a
   * busy site as emptier than it is — and on an MSP-sized fleet it costs a
   * full inventory fetch to draw one page.
   */
  async devices(siteId: number): Promise<Device[]> {
    const res = await apiClient.get<ApiResponse<Device[]>>(`/sites/${siteId}/devices`);
    return res.data.data ?? [];
  },

  /**
   * PPP timeline for a site ("chronologie PPP").
   *
   * The route now exists server-side. The `null` branch is KEPT on purpose: it
   * distinguishes "this deployment does not serve the endpoint" from "this site
   * has never connected", and those two must never render the same way. An
   * empty array here is a real answer; `null` is the absence of one.
   */
  async pppSessions(siteId: number, limit = 100): Promise<PppSession[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<PppSession[]>>(
        `/sites/${siteId}/ppp-sessions`,
        { params: { limit } },
      );
      return res.data.data ?? [];
    } catch (err) {
      const status = (err as { response?: { status?: number } }).response?.status;
      if (status === 501) return null;
      throw err;
    }
  },
};
