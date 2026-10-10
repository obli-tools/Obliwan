import apiClient from './client';
import type {
  SlaCoverageStatus,
  SlaExclusionLine,
  SlaIntervalKind,
  SlaObjectiveScope,
  SlaObjectiveVerdict,
  SlaTotals,
} from '@obliwan/shared';

/**
 * The calculated SLA (`/api/sla`, `routes/sla.routes.ts`).
 *
 * ┌─ THIS ROUTER ANSWERS BARE JSON ───────────────────────────────────────────┐
 * │ Unlike most of the API, `sla.controller.ts` does NOT wrap its answers in  │
 * │ `{ success, data }`: `/availability` is `{ period, algorithmVersion,      │
 * │ sites }`, `/reports` is `{ reports }`, `/reports/:id/intervals` is        │
 * │ `{ reportId, intervals }`. The readers below follow the controller, not   │
 * │ the house style.                                                          │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ `null` IS NOT A PERCENTAGE ──────────────────────────────────────────────┐
 * │ `availabilityPercent` is `null` when nothing was measured — never 100,    │
 * │ never 0 (shared/src/sla.ts, item 1). Every percentage below keeps its     │
 * │ `null`, and a reader renders it as "no measurement", not as a number.     │
 * │ `num()` never falls back to a zero.                                       │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * Capabilities (server-side, mirrored by the screen): every read is
 * DEVICE_READ; issuing a stored report is DEVICE_READ + EXPORT_RUN. Objectives
 * (SETTINGS_MANAGE) and report deletion are not wrapped here.
 */

type Raw = Record<string, unknown>;

/** Number, or null. NEVER a zero fallback. */
function num(v: unknown): number | null {
  if (v === null || v === undefined || v === '') return null;
  const n = typeof v === 'number' ? v : Number(v);
  return Number.isFinite(n) ? n : null;
}

function str(v: unknown): string | null {
  return typeof v === 'string' && v !== '' ? v : null;
}

/** One second-bucket total. A missing bucket is 0 seconds — these are SUMS the
 *  server always sends, not readings that can be absent. */
function secs(v: unknown): number {
  return num(v) ?? 0;
}

export interface SlaInterval {
  startedAt: string;
  endedAt: string;
  seconds: number;
  kind: SlaIntervalKind;
  /** One of `SLA_INTERVAL_REASONS` (a closed vocabulary the UI translates). */
  reason: string;
}

/** One site's computed availability (`toWire()` in sla.controller.ts). */
export interface SlaSiteAvailability {
  siteId: number;
  siteCode: string;
  siteName: string;
  siteTimezone: string;
  deviceCount: number;
  period: { from: string; to: string };
  availabilityPercent: number | null;
  worstCasePercent: number | null;
  bestCasePercent: number | null;
  coveragePercent: number | null;
  coverageStatus: SlaCoverageStatus;
  objectivePercent: number | null;
  objectiveScope: SlaObjectiveScope | null;
  objectiveVerdict: SlaObjectiveVerdict;
  /** Machine-readable reason for the verdict; the UI translates it. */
  verdictReason: string;
  totals: SlaTotals;
  exclusions: SlaExclusionLine[];
  /** Non-null when the site's maintenance window could not be read — nothing
   *  was excluded for maintenance then, and the report says so. */
  maintenanceError: string | null;
  unreachableSamplesIgnored: number;
  algorithmVersion: string;
  verdictValiditySeconds: number;
  paramsHash: string;
  intervalCount: number;
}

export interface SlaSiteDetail extends SlaSiteAvailability {
  /** The full classification of the period — the audit trail. */
  intervals: SlaInterval[];
}

export interface SlaAvailabilityResponse {
  period: { from: string; to: string };
  algorithmVersion: string;
  sites: SlaSiteAvailability[];
}

export interface SlaMethod {
  algorithmVersion: string;
  /** Server-side English sentences, rendered verbatim. */
  method: string[];
  vocabularies: {
    intervalKinds: SlaIntervalKind[];
    excludedKinds: SlaIntervalKind[];
    coverageStatuses: SlaCoverageStatus[];
    objectiveVerdicts: SlaObjectiveVerdict[];
  };
  bounds: {
    maxPeriodDays: number;
    minObjectivePercent: number;
    maxObjectivePercent: number;
    minVerdictValiditySeconds: number;
    maxVerdictValiditySeconds: number;
  };
}

/** A frozen report (`StoredSlaReport` in report.service.ts). */
export interface SlaStoredReport {
  id: string;
  uuid: string;
  siteId: number;
  siteCode: string | null;
  siteName: string | null;
  periodStart: string;
  periodEnd: string;
  generatedAt: string;
  actorName: string | null;
  objectivePercent: number | null;
  objectiveScope: SlaObjectiveScope | null;
  verdictValiditySeconds: number;
  algorithmVersion: string;
  paramsHash: string;
  periodSeconds: number;
  upSeconds: number;
  downSeconds: number;
  excludedManagementSeconds: number;
  excludedMaintenanceSeconds: number;
  unmeasuredSeconds: number;
  availabilityPercent: number | null;
  worstCasePercent: number | null;
  bestCasePercent: number | null;
  coveragePercent: number | null;
  coverageStatus: SlaCoverageStatus;
  objectiveVerdict: SlaObjectiveVerdict;
  verdictReason: string;
  maintenanceError: string | null;
  deviceCount: number;
  intervalCount: number;
}

function normalizeTotals(raw: unknown): SlaTotals {
  const r = (raw ?? {}) as Raw;
  return {
    periodSeconds: secs(r.periodSeconds),
    upSeconds: secs(r.upSeconds),
    downSeconds: secs(r.downSeconds),
    excludedManagementSeconds: secs(r.excludedManagementSeconds),
    excludedMaintenanceSeconds: secs(r.excludedMaintenanceSeconds),
    unmeasuredSeconds: secs(r.unmeasuredSeconds),
    measuredSeconds: secs(r.measuredSeconds),
    accountableSeconds: secs(r.accountableSeconds),
  };
}

function normalizeInterval(raw: Raw): SlaInterval {
  return {
    startedAt: String(raw.startedAt ?? ''),
    endedAt: String(raw.endedAt ?? ''),
    seconds: secs(raw.seconds),
    kind: raw.kind as SlaIntervalKind,
    reason: String(raw.reason ?? ''),
  };
}

function normalizeSite(raw: Raw): SlaSiteAvailability {
  const period = (raw.period ?? {}) as Raw;
  return {
    siteId: Number(raw.siteId),
    siteCode: String(raw.siteCode ?? ''),
    siteName: String(raw.siteName ?? ''),
    siteTimezone: String(raw.siteTimezone ?? ''),
    deviceCount: secs(raw.deviceCount),
    period: { from: String(period.from ?? ''), to: String(period.to ?? '') },
    availabilityPercent: num(raw.availabilityPercent),
    worstCasePercent: num(raw.worstCasePercent),
    bestCasePercent: num(raw.bestCasePercent),
    coveragePercent: num(raw.coveragePercent),
    coverageStatus: (raw.coverageStatus as SlaCoverageStatus) ?? 'no_data',
    objectivePercent: num(raw.objectivePercent),
    objectiveScope: (raw.objectiveScope as SlaObjectiveScope | null) ?? null,
    objectiveVerdict: (raw.objectiveVerdict as SlaObjectiveVerdict) ?? 'indeterminate',
    verdictReason: String(raw.verdictReason ?? ''),
    totals: normalizeTotals(raw.totals),
    exclusions: Array.isArray(raw.exclusions) ? (raw.exclusions as SlaExclusionLine[]) : [],
    maintenanceError: str(raw.maintenanceError),
    unreachableSamplesIgnored: secs(raw.unreachableSamplesIgnored),
    algorithmVersion: String(raw.algorithmVersion ?? ''),
    verdictValiditySeconds: secs(raw.verdictValiditySeconds),
    paramsHash: String(raw.paramsHash ?? ''),
    intervalCount: secs(raw.intervalCount),
  };
}

function normalizeReport(raw: Raw): SlaStoredReport {
  return {
    id: String(raw.id),
    uuid: String(raw.uuid ?? ''),
    siteId: Number(raw.siteId),
    siteCode: str(raw.siteCode),
    siteName: str(raw.siteName),
    periodStart: String(raw.periodStart ?? ''),
    periodEnd: String(raw.periodEnd ?? ''),
    generatedAt: String(raw.generatedAt ?? ''),
    actorName: str(raw.actorName),
    objectivePercent: num(raw.objectivePercent),
    objectiveScope: (raw.objectiveScope as SlaObjectiveScope | null) ?? null,
    verdictValiditySeconds: secs(raw.verdictValiditySeconds),
    algorithmVersion: String(raw.algorithmVersion ?? ''),
    paramsHash: String(raw.paramsHash ?? ''),
    periodSeconds: secs(raw.periodSeconds),
    upSeconds: secs(raw.upSeconds),
    downSeconds: secs(raw.downSeconds),
    excludedManagementSeconds: secs(raw.excludedManagementSeconds),
    excludedMaintenanceSeconds: secs(raw.excludedMaintenanceSeconds),
    unmeasuredSeconds: secs(raw.unmeasuredSeconds),
    availabilityPercent: num(raw.availabilityPercent),
    worstCasePercent: num(raw.worstCasePercent),
    bestCasePercent: num(raw.bestCasePercent),
    coveragePercent: num(raw.coveragePercent),
    coverageStatus: (raw.coverageStatus as SlaCoverageStatus) ?? 'no_data',
    objectiveVerdict: (raw.objectiveVerdict as SlaObjectiveVerdict) ?? 'indeterminate',
    verdictReason: String(raw.verdictReason ?? ''),
    maintenanceError: str(raw.maintenanceError),
    deviceCount: secs(raw.deviceCount),
    intervalCount: secs(raw.intervalCount),
  };
}

export function slaErrorOf(err: unknown): string {
  const data = (err as { response?: { data?: { error?: string; message?: string } } }).response?.data;
  return data?.error ?? data?.message ?? (err instanceof Error ? err.message : 'Unknown error');
}

export const slaApi = {
  async method(): Promise<SlaMethod> {
    const res = await apiClient.get<SlaMethod>('/sla/method');
    return res.data;
  },

  /** Every site of the tenant (the server refuses more than 200 at once with a
   *  400 naming the number), or one via `siteId`. Computed, nothing stored. */
  async availability(from: string, to: string, siteId?: number): Promise<SlaAvailabilityResponse> {
    const res = await apiClient.get<Raw>('/sla/availability', {
      params: siteId === undefined ? { from, to } : { from, to, siteId },
    });
    const period = (res.data.period ?? {}) as Raw;
    return {
      period: { from: String(period.from ?? from), to: String(period.to ?? to) },
      algorithmVersion: String(res.data.algorithmVersion ?? ''),
      sites: Array.isArray(res.data.sites) ? (res.data.sites as Raw[]).map(normalizeSite) : [],
    };
  },

  /** One site with its full classification (the audit trail). */
  async siteAvailability(siteId: number, from: string, to: string): Promise<SlaSiteDetail> {
    const res = await apiClient.get<Raw>(`/sla/sites/${siteId}/availability`, {
      params: { from, to },
    });
    return {
      ...normalizeSite(res.data),
      intervals: Array.isArray(res.data.intervals)
        ? (res.data.intervals as Raw[]).map(normalizeInterval)
        : [],
    };
  },

  async reports(params: { siteId?: number; limit?: number } = {}): Promise<SlaStoredReport[]> {
    const res = await apiClient.get<{ reports?: Raw[] }>('/sla/reports', { params });
    return Array.isArray(res.data.reports) ? res.data.reports.map(normalizeReport) : [];
  },

  /** Every interval of a stored report (the server caps at 5 000). */
  async reportIntervals(reportId: string): Promise<SlaInterval[]> {
    const res = await apiClient.get<{ intervals?: Raw[] }>(`/sla/reports/${reportId}/intervals`);
    return Array.isArray(res.data.intervals) ? res.data.intervals.map(normalizeInterval) : [];
  },

  /** Freeze one site's availability over a period into a stored report.
   *  DEVICE_READ + EXPORT_RUN server-side; writes one audit_log row. */
  async issue(siteId: number, from: string, to: string): Promise<SlaStoredReport> {
    const res = await apiClient.post<{ report?: Raw }>('/sla/reports', { siteId, from, to });
    if (!res.data.report) throw new Error('Empty response');
    return normalizeReport(res.data.report);
  },
};
