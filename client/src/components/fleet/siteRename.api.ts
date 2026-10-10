import apiClient from '@/api/client';
import type {
  ApiResponse,
  ChangeJobStatus,
  SiteRenameBulkLaunchRow,
  SiteRenameBulkPreviewRow,
  SiteRenameChrMode,
  SiteRenameNames,
  SiteRenameOutcome,
} from '@obliwan/shared';

/**
 * Renaming a site's router (a `site_rename` change job) — the client half of
 * `server/src/routes/siteRename.routes.ts`, kept beside its card. The view
 * mirrors `SiteRenameView` in server/src/services/change/siteRename.service.ts.
 * The sentences in it (refusals, outcome, error) are written by the server and
 * shown verbatim; outcome and state codes are translated by the card. Every
 * field is read defensively: a missing one is null or false, never a guess.
 */

export interface SiteRenameStep {
  seq: number;
  kind: string;
  status: string;
  output: string | null;
  error: string | null;
}

export interface SiteRenameJob {
  id: number;
  status: ChangeJobStatus;
  active: boolean;
  outcome: SiteRenameOutcome | null;
  outcomeDetail: string | null;
  errorKind: string | null;
  errorMessage: string | null;
  createdAt: string;
  finishedAt: string | null;
  from: SiteRenameNames;
  to: SiteRenameNames;
  chrMode: SiteRenameChrMode | null;
  backupId: number | null;
  steps: SiteRenameStep[];
}

export interface SiteRenameView {
  deviceId: number;
  deviceName: string;
  supported: boolean;
  eligible: boolean;
  refusals: Array<{ kind: string; message: string }>;
  current: SiteRenameNames;
  siteId: number | null;
  job: SiteRenameJob | null;
  unsettled: boolean;
  oldSecretLeft: boolean;
  /** The server's word on who may queue one (platform admins). */
  canLaunch: boolean;
}

type Raw = Record<string, unknown>;
const str = (v: unknown): string | null => (typeof v === 'string' && v !== '' ? v : null);
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const names = (v: unknown): SiteRenameNames => {
  const r = (v ?? {}) as Raw;
  return { login: str(r.login), identity: str(r.identity), siteCode: str(r.siteCode) };
};

function normalizeJob(raw: unknown): SiteRenameJob | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Raw;
  const id = num(r.id);
  if (id === null) return null;
  return {
    id,
    status: (str(r.status) ?? 'queued') as ChangeJobStatus,
    active: r.active === true,
    outcome: (str(r.outcome) as SiteRenameOutcome | null) ?? null,
    outcomeDetail: str(r.outcomeDetail),
    errorKind: str(r.errorKind),
    errorMessage: str(r.errorMessage),
    createdAt: str(r.createdAt) ?? new Date(0).toISOString(),
    finishedAt: str(r.finishedAt),
    from: names(r.from),
    to: names(r.to),
    chrMode: (str(r.chrMode) as SiteRenameChrMode | null) ?? null,
    backupId: num(r.backupId),
    steps: Array.isArray(r.steps)
      ? (r.steps as Raw[]).map((s) => ({
        seq: num(s.seq) ?? 0,
        kind: str(s.kind) ?? '',
        status: str(s.status) ?? '',
        output: str(s.output),
        error: str(s.error),
      }))
      : [],
  };
}

export function normalizeSiteRenameView(raw: unknown): SiteRenameView {
  const r = (raw ?? {}) as Raw;
  return {
    deviceId: num(r.deviceId) ?? 0,
    deviceName: str(r.deviceName) ?? '',
    supported: r.supported === true,
    eligible: r.eligible === true,
    refusals: Array.isArray(r.refusals)
      ? (r.refusals as Raw[]).map((x) => ({ kind: str(x.kind) ?? '', message: str(x.message) ?? '' }))
      : [],
    current: names(r.current),
    siteId: num(r.siteId),
    job: normalizeJob(r.job),
    unsettled: r.unsettled === true,
    oldSecretLeft: r.oldSecretLeft === true,
    canLaunch: r.canLaunch === true,
  };
}

function payload<T>(res: { data: ApiResponse<T> }): T {
  if (res.data.data === undefined || res.data.data === null) throw new Error(res.data.error ?? 'empty response');
  return res.data.data;
}

export interface SiteRenameRequest {
  login?: string;
  identity?: string;
  siteCode?: string;
  transform?: 'lowercase';
  includeSiteCode?: boolean;
  relaunch?: boolean;
}

export const siteRenameApi = {
  async get(deviceId: number): Promise<SiteRenameView> {
    return normalizeSiteRenameView(payload(await apiClient.get<ApiResponse<unknown>>(`/devices/${deviceId}/site-rename`)));
  },

  /** Queue ONE rename. `confirmNoDeadman` is the safety-net rule's explicit confirmation. */
  async launch(deviceId: number, req: SiteRenameRequest): Promise<{ jobId: number; alreadyQueued: boolean }> {
    return payload(
      await apiClient.post<ApiResponse<{ jobId: number; alreadyQueued: boolean }>>(`/devices/${deviceId}/site-rename`, {
        ...req,
        confirmNoDeadman: true,
      }),
    );
  },

  /** The « all lowercase » preview of a site selection; nothing is written. */
  async previewBulk(siteIds: number[], includeSiteCode: boolean): Promise<SiteRenameBulkPreviewRow[]> {
    const data = payload(
      await apiClient.post<ApiResponse<{ rows: SiteRenameBulkPreviewRow[] }>>('/devices/site-rename/bulk/preview', {
        siteIds,
        transform: 'lowercase',
        includeSiteCode,
      }),
    );
    return Array.isArray(data.rows) ? data.rows : [];
  },

  async launchBulk(siteIds: number[], includeSiteCode: boolean): Promise<SiteRenameBulkLaunchRow[]> {
    const data = payload(
      await apiClient.post<ApiResponse<{ rows: SiteRenameBulkLaunchRow[] }>>('/devices/site-rename/bulk', {
        siteIds,
        transform: 'lowercase',
        includeSiteCode,
        confirmNoDeadman: true,
      }),
    );
    return Array.isArray(data.rows) ? data.rows : [];
  },
};

/** The server's sentence of a refused request, else the fallback. */
export function siteRenameErrorMessage(err: unknown, fallback: string): string {
  const data = (err as { response?: { data?: { error?: unknown } } })?.response?.data;
  return typeof data?.error === 'string' && data.error !== '' ? data.error : fallback;
}
