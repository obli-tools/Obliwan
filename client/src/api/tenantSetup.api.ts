import apiClient from './client';
import {
  SETUP_TENANT_MISMATCH,
  type ApiResponse,
  type TenantSetupContext,
  type TenantSetupContextRequest,
  type TenantSetupReport,
  type TenantSetupRequest,
} from '@obliwan/shared';
import type { TemplateImportReport } from './templates.api';
import type { SiteImportResult } from './sites.api';

/**
 * Quick Setup Tenant (server: /api/tenant-setup, platform admin only, acting
 * on the session's CURRENT workspace).
 *
 * Three calls, and only one of them writes:
 *  - `context` reads what the designer is generated from. It is a POST
 *    because it may carry an uploaded template whose `var_schema` becomes the
 *    declarations; it writes nothing.
 *  - `check` is the dry run over every selected part TOGETHER. It never
 *    answers 422: its errors are in `report.issues`.
 *  - `apply` re-runs the whole check server-side on the same body, and
 *    refuses with 422 (nothing written) when it finds an error — what the
 *    screen showed is advice, the server's re-check is the verdict.
 *
 * Every body names the workspace it was prepared for (`expectedTenantId`).
 * The server acts on the session's workspace, which every tab shares, and
 * answers 409 with `code: TENANT_MISMATCH` when the two differ, before
 * reading or writing anything (`isTenantMismatch`).
 *
 * A request body may carry secret values (typed in the designer or read from
 * a local file). No response carries one back: rows name keys, never values.
 */

export type SetupCallResult =
  | { ok: true; report: TenantSetupReport }
  /** 422: the re-check found errors, or instance rows were not acknowledged. */
  | { ok: false; status: 422; report: TenantSetupReport; message: string };

interface RefusalBody {
  success?: boolean;
  error?: unknown;
  data?: unknown;
}

/** The session's workspace is not the one the body was prepared for: it
 *  was switched, most likely in another tab. Nothing was read or written. */
export function isTenantMismatch(err: unknown): boolean {
  const res = (err as { response?: { status?: number; data?: { code?: unknown } } }).response;
  return res?.status === 409 && res.data?.code === SETUP_TENANT_MISMATCH;
}

function asRefusal(err: unknown): SetupCallResult | null {
  const res = (err as { response?: { status?: number; data?: RefusalBody } }).response;
  if (res?.status !== 422 || !res.data || typeof res.data.data !== 'object' || res.data.data === null) return null;
  return {
    ok: false,
    status: 422,
    report: res.data.data as TenantSetupReport,
    message: typeof res.data.error === 'string' ? res.data.error : '',
  };
}

export const tenantSetupApi = {
  async context(body: TenantSetupContextRequest): Promise<TenantSetupContext> {
    const res = await apiClient.post<ApiResponse<TenantSetupContext>>('/tenant-setup/context', body);
    return res.data.data as TenantSetupContext;
  },

  async check(req: TenantSetupRequest): Promise<SetupCallResult> {
    try {
      const res = await apiClient.post<ApiResponse<TenantSetupReport>>('/tenant-setup/check', req);
      return { ok: true, report: res.data.data as TenantSetupReport };
    } catch (err) {
      const refused = asRefusal(err);
      if (refused) return refused;
      throw err;
    }
  },

  /** 409 (another quick setup is running for this workspace, or the session
   *  is on another workspace: `isTenantMismatch`) and any other failure are
   *  thrown; the caller shows the server's sentence or its own. */
  async apply(req: TenantSetupRequest): Promise<SetupCallResult> {
    try {
      const res = await apiClient.post<ApiResponse<TenantSetupReport>>('/tenant-setup/apply', req);
      return { ok: true, report: res.data.data as TenantSetupReport };
    } catch (err) {
      const refused = asRefusal(err);
      if (refused) return refused;
      throw err;
    }
  },
};

/**
 * The template part's embedded report IS the server's `ImportReport` — the
 * same object `/api/templates/import` returns — typed `unknown` in the shared
 * contract so `shared` does not depend on the template service. A cast, not a
 * conversion: nothing is renamed on the way.
 */
export function asTemplateReport(r: unknown): TemplateImportReport | null {
  return r && typeof r === 'object' && Array.isArray((r as { items?: unknown }).items)
    ? (r as TemplateImportReport)
    : null;
}

/** Same for the sites part: the server's `SiteImportResult`, verbatim. */
export function asSitesResult(r: unknown): SiteImportResult | null {
  return r && typeof r === 'object' && Array.isArray((r as { rows?: unknown }).rows)
    ? (r as SiteImportResult)
    : null;
}
