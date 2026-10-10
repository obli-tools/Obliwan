import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { AlertTriangle, ChevronDown, ChevronRight, FileCheck2, Gauge, Info, RotateCw, X } from 'lucide-react';
import toast from 'react-hot-toast';
import {
  CAPABILITIES,
  type SlaCoverageStatus,
  type SlaIntervalKind,
  type SlaObjectiveScope,
  type SlaObjectiveVerdict,
} from '@obliwan/shared';
import {
  slaApi,
  slaErrorOf,
  type SlaInterval,
  type SlaMethod,
  type SlaSiteAvailability,
  type SlaSiteDetail,
  type SlaStoredReport,
} from '@/api/sla.api';
import { useAuthStore } from '@/store/authStore';
import { useSiteStore } from '@/store/siteStore';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { EmptyState, Panel, When } from '@/components/mobile/SimBits';
import { cn } from '@/utils/cn';
import { formatDuration } from '@/utils/series';

/**
 * ObliWAN — the customer SLA report.
 *
 * ┌─ THIS SCREEN SHOWS WHAT THE SERVER COMPUTED, AND NOTHING IT DID NOT ──────┐
 * │ Every figure comes from `GET /api/sla/availability` (per site) and        │
 * │ `GET /api/sla/sites/:id/availability` (one site, with its audit trail).   │
 * │ The server computes availability PER SITE — the per-device timelines are  │
 * │ combined server-side (`up > excluded_management > down > unmeasured`) and │
 * │ never served — so there is no per-device column here, only the number of │
 * │ active CPEs that fed the site's figure.                                   │
 * │                                                                          │
 * │ Three things this page must never do, all from shared/src/sla.ts:        │
 * │  - show an unobserved period as 100 %: `availabilityPercent: null` is     │
 * │    "no measurement", never a number;                                      │
 * │  - fold the exclusions into downtime: management-plane outages and        │
 * │    maintenance windows are removed from BOTH sides and shown apart;       │
 * │  - decide the objective on the point estimate: the verdict is the         │
 * │    server's, made on the [worst, best] bracket, and its reason is shown.  │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * THE PERIOD NEVER RUNS INTO THE FUTURE. An open PPP session is extended by the
 * server to the END of the period, so a period ending tomorrow would count
 * seconds nobody has observed yet as service. `to` is capped at "now".
 *
 * Capabilities: the route is DEVICE_READ, like every read of `/api/sla`.
 * Issuing a stored report additionally needs EXPORT_RUN (the server checks
 * both); the button is withheld from a session without it.
 */

type Preset = 'last7' | 'last30' | 'thisMonth' | 'lastMonth' | 'custom';
const PRESETS: Preset[] = ['last7', 'last30', 'thisMonth', 'lastMonth', 'custom'];

const DAY_MS = 86_400_000;
/** Rows of an interval table drawn at once. The stored trail can hold 5 000. */
const INTERVAL_ROWS_SHOWN = 500;

const selectClass =
  'rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent';

interface Range {
  from: string;
  to: string;
  /** `to` was later than now and was capped. */
  capped: boolean;
  error: 'invalid' | null;
}

/** `YYYY-MM-DD` of a local date, for `<input type="date">`. */
function ymd(d: Date): string {
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

/** Local midnight of a `YYYY-MM-DD`, or null. */
function localMidnight(value: string): Date | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!m) return null;
  const d = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), 0, 0, 0, 0);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** Periods are drawn in the BROWSER's time zone, and the header says so. */
function computeRange(preset: Preset, customFrom: string, customTo: string): Range {
  const now = new Date();
  let from: Date;
  let to: Date;
  switch (preset) {
    case 'last7':
      from = new Date(now.getTime() - 7 * DAY_MS);
      to = now;
      break;
    case 'last30':
      from = new Date(now.getTime() - 30 * DAY_MS);
      to = now;
      break;
    case 'thisMonth':
      from = new Date(now.getFullYear(), now.getMonth(), 1);
      to = now;
      break;
    case 'lastMonth':
      from = new Date(now.getFullYear(), now.getMonth() - 1, 1);
      to = new Date(now.getFullYear(), now.getMonth(), 1);
      break;
    case 'custom': {
      const f = localMidnight(customFrom);
      const lastDay = localMidnight(customTo);
      if (!f || !lastDay) return { from: '', to: '', capped: false, error: 'invalid' };
      from = f;
      // The end date is INCLUSIVE on screen, so the instant sent is the
      // midnight that ends it.
      to = new Date(lastDay.getFullYear(), lastDay.getMonth(), lastDay.getDate() + 1);
      break;
    }
  }
  let capped = false;
  if (to.getTime() > now.getTime()) {
    to = now;
    capped = true;
  }
  if (!(to.getTime() > from.getTime())) return { from: '', to: '', capped, error: 'invalid' };
  return { from: from.toISOString(), to: to.toISOString(), capped, error: null };
}

/** A percentage stored at 4 decimals, shown without inventing precision.
 *  `null` stays null — the caller renders "no measurement". */
function fmtPct(v: number | null): string | null {
  if (v === null || !Number.isFinite(v)) return null;
  return `${v.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 4 })} %`;
}

function fmtDate(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString();
}

// ── Vocabulary labels ───────────────────────────────────────────────────────
// Every closed vocabulary the server sends is translated here, with the
// English text as the default so a missing locale key degrades to English
// rather than to a raw key.

const KIND_EN: Record<SlaIntervalKind, string> = {
  up: 'Service',
  down: 'Outage',
  excluded_management: 'Excluded — management plane',
  excluded_maintenance: 'Excluded — maintenance window',
  unmeasured: 'Unmeasured',
};

const REASON_EN: Record<string, string> = {
  ppp_session_open: 'PPP session open',
  ppp_absent_while_concentrator_observing: 'No PPP session while the concentrator was observing',
  verdict_up: 'Reachability verdict: up',
  verdict_wan_failover: 'Reachability verdict: WAN failover (service delivered)',
  verdict_site_down: 'Reachability verdict: site down',
  verdict_concentrator_degraded: 'Reachability verdict: concentrator degraded (ours)',
  verdict_tunnel_down_site_up: 'Reachability verdict: tunnel down, site up',
  no_observation: 'No observation',
  no_active_device_at_site: 'No active router at the site',
  maintenance_window: 'Declared maintenance window',
};

const VERDICT_REASON_EN: Record<string, string> = {
  entire_period_excluded:
    'The whole period was excluded (maintenance or management-plane outage): there is no billable time to judge.',
  no_measurement: 'Nothing was measured over the period: no availability figure, and no verdict.',
  no_objective_configured: 'No objective is configured for this site or tenant.',
  observed_downtime_alone_breaches_objective:
    'Observed downtime alone breaches the objective, even if every unmeasured second was service.',
  objective_held_even_if_every_gap_was_an_outage:
    'The objective holds even if every unmeasured second was an outage.',
  coverage_insufficient_to_decide:
    'Too much of the period is unmeasured to decide: the objective lies between the worst and the best case.',
};

const VERDICT_EN: Record<SlaObjectiveVerdict, string> = {
  met: 'Met',
  missed: 'Missed',
  indeterminate: 'Indeterminate',
};

const COVERAGE_EN: Record<SlaCoverageStatus, string> = {
  no_data: 'No data',
  partial: 'Partial',
  complete: 'Complete',
};

const SCOPE_EN: Record<SlaObjectiveScope, string> = {
  tenant: 'tenant default',
  site: 'site-specific',
};

const PRESET_EN: Record<Preset, string> = {
  last7: 'Last 7 days',
  last30: 'Last 30 days',
  thisMonth: 'This month (to date)',
  lastMonth: 'Previous month',
  custom: 'Custom',
};

function kindLabel(t: TFunction, kind: SlaIntervalKind): string {
  return t(`sla.kind.${kind}`, { defaultValue: KIND_EN[kind] ?? kind });
}

function reasonLabel(t: TFunction, reason: string): string {
  return t(`sla.reason.${reason}`, { defaultValue: REASON_EN[reason] ?? reason });
}

const KIND_TONE: Record<SlaIntervalKind, string> = {
  up: 'border-status-up/30 bg-status-up/10 text-status-up',
  down: 'border-status-down/40 bg-status-down/10 text-status-down',
  excluded_management: 'border-status-maintenance/30 bg-status-maintenance/10 text-status-maintenance',
  excluded_maintenance: 'border-status-maintenance/30 bg-status-maintenance/10 text-status-maintenance',
  unmeasured: 'border-border bg-bg-tertiary text-text-muted',
};

const VERDICT_TONE: Record<SlaObjectiveVerdict, string> = {
  met: 'border-status-up/30 bg-status-up/10 text-status-up',
  missed: 'border-status-down/40 bg-status-down/10 text-status-down',
  indeterminate: 'border-status-ssl-warning/30 bg-status-ssl-warning/10 text-status-ssl-warning',
};

const COVERAGE_TONE: Record<SlaCoverageStatus, string> = {
  complete: 'text-status-up',
  partial: 'text-status-ssl-warning',
  no_data: 'text-text-muted',
};

function Pill({ className, children, title }: { className: string; children: React.ReactNode; title?: string }) {
  return (
    <span
      title={title}
      className={cn('inline-flex items-center whitespace-nowrap rounded-full border px-2 py-0.5 text-[11px]', className)}
    >
      {children}
    </span>
  );
}

function VerdictPill({ verdict, reason }: { verdict: SlaObjectiveVerdict; reason: string }) {
  const { t } = useTranslation();
  // The server answers 'indeterminate' when no objective is configured — true,
  // but drawn in the amber of a coverage problem it reads as one. Same verdict,
  // neutral pill, and the tooltip still carries the server's reason.
  if (reason === 'no_objective_configured') {
    return (
      <Pill
        className="border-border bg-bg-tertiary text-text-muted"
        title={t('sla.verdictReason.no_objective_configured', { defaultValue: VERDICT_REASON_EN.no_objective_configured })}
      >
        {t('sla.verdict.noObjective', { defaultValue: 'No objective' })}
      </Pill>
    );
  }
  return (
    <Pill
      className={VERDICT_TONE[verdict] ?? VERDICT_TONE.indeterminate}
      title={t(`sla.verdictReason.${reason}`, { defaultValue: VERDICT_REASON_EN[reason] ?? reason })}
    >
      {t(`sla.verdict.${verdict}`, { defaultValue: VERDICT_EN[verdict] ?? verdict })}
    </Pill>
  );
}

function Percent({ value }: { value: number | null }) {
  const { t } = useTranslation();
  const text = fmtPct(value);
  if (text === null) {
    return <span className="text-text-muted italic">{t('sla.noMeasurement', { defaultValue: 'no measurement' })}</span>;
  }
  return <span className="tabular-nums">{text}</span>;
}

function Seconds({ value }: { value: number }) {
  if (value <= 0) return <span className="text-text-muted">—</span>;
  return <span className="tabular-nums">{formatDuration(value)}</span>;
}

// ── Page ────────────────────────────────────────────────────────────────────

export function SlaPage() {
  const { t } = useTranslation();
  const { hasCapability } = useAuthStore();
  const { sites, fetchSites } = useSiteStore();
  const canIssue = hasCapability(CAPABILITIES.EXPORT_RUN);

  const [preset, setPreset] = useState<Preset>('last30');
  const today = useMemo(() => new Date(), []);
  const [customFrom, setCustomFrom] = useState(() => ymd(new Date(today.getFullYear(), today.getMonth() - 1, 1)));
  const [customTo, setCustomTo] = useState(() => ymd(new Date(today.getFullYear(), today.getMonth(), 0)));
  const [siteFilter, setSiteFilter] = useState('');
  // Bumped by "Refresh": "now" is read again, so a rolling period moves.
  const [nonce, setNonce] = useState(0);

  const range = useMemo(
    () => computeRange(preset, customFrom, customTo),
    // `nonce` is a dependency on purpose: it is what re-reads the clock.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [preset, customFrom, customTo, nonce],
  );

  const [rows, setRows] = useState<SlaSiteAvailability[]>([]);
  const [period, setPeriod] = useState<{ from: string; to: string } | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [selected, setSelected] = useState<number | null>(null);
  const [method, setMethod] = useState<SlaMethod | null>(null);
  const [reportsNonce, setReportsNonce] = useState(0);
  // Only the newest request may write the table: switching period twice in a
  // row must not let the slower, older answer land last.
  const seq = useRef(0);

  useEffect(() => {
    void fetchSites();
    slaApi.method().then(setMethod).catch(() => setMethod(null));
  }, [fetchSites]);

  const load = useCallback(async () => {
    const mine = ++seq.current;
    if (range.error) {
      setRows([]);
      setPeriod(null);
      setLoadError(null);
      setLoading(false);
      return;
    }
    setLoading(true);
    setLoadError(null);
    try {
      const res = await slaApi.availability(
        range.from,
        range.to,
        siteFilter ? Number(siteFilter) : undefined,
      );
      if (mine !== seq.current) return;
      setRows(res.sites);
      setPeriod(res.period);
    } catch (err) {
      if (mine !== seq.current) return;
      setRows([]);
      setPeriod(null);
      setLoadError(slaErrorOf(err));
    } finally {
      if (mine === seq.current) setLoading(false);
    }
  }, [range, siteFilter]);

  useEffect(() => {
    void load();
  }, [load]);

  // A site that left the table (filter, new period with fewer sites) closes
  // its detail rather than showing figures for a period nobody asked about.
  useEffect(() => {
    if (selected !== null && !rows.some((r) => r.siteId === selected)) setSelected(null);
  }, [rows, selected]);

  const sorted = useMemo(
    () => [...rows].sort((a, b) => a.siteName.localeCompare(b.siteName) || a.siteId - b.siteId),
    [rows],
  );

  const summary = useMemo(() => {
    const s = { met: 0, missed: 0, indeterminate: 0, noData: 0 };
    for (const r of rows) {
      // A site with no objective is not "indeterminate" in the sense this card
      // counts (too little coverage to decide); its pill says "No objective".
      if (r.verdictReason !== 'no_objective_configured') s[r.objectiveVerdict] += 1;
      if (r.availabilityPercent === null) s.noData += 1;
    }
    return s;
  }, [rows]);

  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-text-primary">
            {t('sla.title', { defaultValue: 'Availability (SLA)' })}
          </h1>
          <p className="mt-1 max-w-3xl text-sm text-text-muted">
            {t('sla.subtitle', {
              defaultValue:
                'Availability per site, computed from PPP presence and reachability verdicts. Time nobody observed is reported as unmeasured — never counted as service.',
            })}
          </p>
        </div>
        <Button
          variant="secondary"
          size="sm"
          onClick={() => {
            setNonce((n) => n + 1);
            setReportsNonce((n) => n + 1);
          }}
        >
          <RotateCw size={14} className={cn('mr-1.5', loading && 'animate-spin')} />
          {t('common.refresh')}
        </Button>
      </div>

      {/* Controls */}
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <label className="text-[12px] text-text-muted">{t('sla.period.label', { defaultValue: 'Period' })}</label>
        <select className={selectClass} value={preset} onChange={(e) => setPreset(e.target.value as Preset)}>
          {PRESETS.map((p) => (
            <option key={p} value={p}>
              {t(`sla.period.${p}`, { defaultValue: PRESET_EN[p] })}
            </option>
          ))}
        </select>
        {preset === 'custom' && (
          <>
            <label className="text-[12px] text-text-muted">{t('sla.period.from', { defaultValue: 'From' })}</label>
            <input
              type="date"
              className={selectClass}
              value={customFrom}
              onChange={(e) => setCustomFrom(e.target.value)}
            />
            <label className="text-[12px] text-text-muted">
              {t('sla.period.to', { defaultValue: 'To (inclusive)' })}
            </label>
            <input
              type="date"
              className={selectClass}
              value={customTo}
              onChange={(e) => setCustomTo(e.target.value)}
            />
          </>
        )}
        <select className={selectClass} value={siteFilter} onChange={(e) => setSiteFilter(e.target.value)}>
          <option value="">{t('devices.filters.allSites')}</option>
          {sites.map((s) => (
            <option key={s.id} value={s.id}>
              {s.code ? `${s.code} — ${s.name}` : s.name}
            </option>
          ))}
        </select>
        {period && (
          <span className="ml-auto font-mono text-[11px] text-text-muted">
            {t('sla.period.shown', {
              defaultValue: 'Computed over {{from}} → {{to}} (your browser’s time zone)',
              from: fmtDate(period.from),
              to: fmtDate(period.to),
            })}
          </span>
        )}
      </div>

      {range.error && (
        <Banner tone="warn">
          {t('sla.period.invalid', { defaultValue: 'Pick a start date on or before the end date.' })}
        </Banner>
      )}
      {range.capped && !range.error && preset === 'custom' && (
        <Banner tone="info">
          {t('sla.period.cappedToNow', {
            defaultValue:
              'The period was cut at the current time: seconds that have not happened yet cannot be observed, and are not counted.',
          })}
        </Banner>
      )}

      {/* Summary */}
      {!loadError && rows.length > 0 && (
        <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-5">
          <SummaryCard label={t('sla.summary.sites', { defaultValue: 'Sites' })} value={rows.length} tone="muted" />
          <SummaryCard label={t('sla.summary.met', { defaultValue: 'Objective met' })} value={summary.met} tone="ok" />
          <SummaryCard
            label={t('sla.summary.missed', { defaultValue: 'Objective missed' })}
            value={summary.missed}
            tone={summary.missed > 0 ? 'bad' : 'muted'}
          />
          <SummaryCard
            label={t('sla.summary.indeterminate', { defaultValue: 'Indeterminate' })}
            value={summary.indeterminate}
            tone={summary.indeterminate > 0 ? 'warn' : 'muted'}
          />
          <SummaryCard
            label={t('sla.summary.noData', { defaultValue: 'No measurement' })}
            value={summary.noData}
            tone="muted"
          />
        </div>
      )}

      {/* Per-site table */}
      <Panel title={t('sla.table.title', { defaultValue: 'Availability per site' })} className="mb-4">
        {loadError ? (
          <div className="m-4 rounded-lg border border-status-ssl-expired/40 bg-status-ssl-expired/5 p-4 text-sm text-status-ssl-expired">
            {t('sla.loadFailed', { defaultValue: 'Could not compute availability' })} —{' '}
            <span className="font-mono text-xs">{loadError}</span>
          </div>
        ) : loading && rows.length === 0 ? (
          <div className="flex h-40 items-center justify-center">
            <LoadingSpinner />
          </div>
        ) : rows.length === 0 ? (
          range.error ? null : <EmptyState message={t('sla.empty', { defaultValue: 'No site to report on.' })} />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-border text-left text-xs text-text-muted">
                <tr>
                  <th className="px-4 py-2 font-medium">{t('sla.col.site', { defaultValue: 'Site' })}</th>
                  <th className="px-4 py-2 text-right font-medium">{t('sla.col.devices', { defaultValue: 'Routers' })}</th>
                  <th className="px-4 py-2 text-right font-medium">
                    {t('sla.col.availability', { defaultValue: 'Availability' })}
                  </th>
                  <th className="px-4 py-2 text-right font-medium" title={t('sla.col.bracketHint', {
                    defaultValue: 'Worst case counts every unmeasured second as an outage; best case counts it as service.',
                  })}>
                    {t('sla.col.bracket', { defaultValue: 'Worst – best case' })}
                  </th>
                  <th className="px-4 py-2 text-right font-medium">{t('sla.col.coverage', { defaultValue: 'Coverage' })}</th>
                  <th className="px-4 py-2 text-right font-medium">{t('sla.col.objective', { defaultValue: 'Objective' })}</th>
                  <th className="px-4 py-2 font-medium">{t('sla.col.verdict', { defaultValue: 'Verdict' })}</th>
                  <th className="px-4 py-2 text-right font-medium">{t('sla.col.down', { defaultValue: 'Outage' })}</th>
                  <th className="px-4 py-2 text-right font-medium">{t('sla.col.excluded', { defaultValue: 'Excluded' })}</th>
                  <th className="px-4 py-2 text-right font-medium">
                    {t('sla.col.unmeasured', { defaultValue: 'Unmeasured' })}
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {sorted.map((r) => {
                  const isSel = selected === r.siteId;
                  const excluded = r.totals.excludedManagementSeconds + r.totals.excludedMaintenanceSeconds;
                  return (
                    <tr
                      key={r.siteId}
                      onClick={() => setSelected(isSel ? null : r.siteId)}
                      className={cn('cursor-pointer hover:bg-bg-hover', isSel && 'bg-bg-active')}
                    >
                      <td className="px-4 py-2">
                        <span className="inline-flex items-center gap-1.5 text-text-primary">
                          {isSel ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                          <span className="font-mono text-[12px] text-text-muted">{r.siteCode}</span>
                          {r.siteName}
                        </span>
                        {r.maintenanceError && (
                          <span className="ml-5 block text-[11px] text-status-ssl-warning">
                            {t('sla.maintenanceUnreadable', { defaultValue: 'Maintenance window unreadable' })}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-2 text-right tabular-nums text-text-secondary">{r.deviceCount}</td>
                      <td className="px-4 py-2 text-right font-semibold text-text-primary">
                        <Percent value={r.availabilityPercent} />
                      </td>
                      <td className="px-4 py-2 text-right text-[12px] text-text-secondary">
                        {fmtPct(r.worstCasePercent) ?? '—'} – {fmtPct(r.bestCasePercent) ?? '—'}
                      </td>
                      <td className="px-4 py-2 text-right text-[12px]">
                        <span className={COVERAGE_TONE[r.coverageStatus]}>
                          {fmtPct(r.coveragePercent) ??
                            t(`sla.coverage.${r.coverageStatus}`, { defaultValue: COVERAGE_EN[r.coverageStatus] })}
                        </span>
                      </td>
                      <td className="px-4 py-2 text-right text-[12px] text-text-secondary">
                        {fmtPct(r.objectivePercent) ?? (
                          <span className="text-text-muted">{t('sla.noObjective', { defaultValue: 'none set' })}</span>
                        )}
                      </td>
                      <td className="px-4 py-2">
                        <VerdictPill verdict={r.objectiveVerdict} reason={r.verdictReason} />
                      </td>
                      <td className="px-4 py-2 text-right text-[12px] text-status-down">
                        <Seconds value={r.totals.downSeconds} />
                      </td>
                      <td className="px-4 py-2 text-right text-[12px] text-status-maintenance">
                        <Seconds value={excluded} />
                      </td>
                      <td className="px-4 py-2 text-right text-[12px] text-text-muted">
                        <Seconds value={r.totals.unmeasuredSeconds} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {selected !== null && !range.error && (
        <SiteDetail
          key={`${selected}|${range.from}|${range.to}`}
          siteId={selected}
          from={range.from}
          to={range.to}
          canIssue={canIssue}
          onClose={() => setSelected(null)}
          onIssued={() => setReportsNonce((n) => n + 1)}
        />
      )}

      <MethodPanel method={method} />

      <ReportsPanel siteId={siteFilter ? Number(siteFilter) : undefined} nonce={reportsNonce} />
    </div>
  );
}

// ── One site: totals, exclusions, audit trail ───────────────────────────────

function SiteDetail({
  siteId,
  from,
  to,
  canIssue,
  onClose,
  onIssued,
}: {
  siteId: number;
  from: string;
  to: string;
  canIssue: boolean;
  onClose: () => void;
  onIssued: () => void;
}) {
  const { t } = useTranslation();
  const [detail, setDetail] = useState<SlaSiteDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [issuing, setIssuing] = useState(false);

  useEffect(() => {
    let alive = true;
    setDetail(null);
    setError(null);
    slaApi
      .siteAvailability(siteId, from, to)
      .then((d) => alive && setDetail(d))
      .catch((err) => alive && setError(slaErrorOf(err)));
    return () => {
      alive = false;
    };
  }, [siteId, from, to]);

  const issue = async () => {
    setIssuing(true);
    try {
      await slaApi.issue(siteId, from, to);
      toast.success(t('sla.issue.done', { defaultValue: 'Report issued' }));
      onIssued();
    } catch (err) {
      toast.error(slaErrorOf(err));
    } finally {
      setIssuing(false);
    }
  };

  const title = detail
    ? `${detail.siteCode} — ${detail.siteName}`
    : t('sla.detail.loading', { defaultValue: 'Loading site…' });

  return (
    <Panel
      className="mb-4"
      title={
        <span className="inline-flex items-center gap-2">
          <Gauge size={14} className="text-text-muted" />
          {title}
          {detail && (
            <Link to={`/sites/${detail.siteId}`} className="text-[12px] font-normal text-accent hover:underline">
              {t('sla.detail.openSite', { defaultValue: 'Open site' })}
            </Link>
          )}
        </span>
      }
      action={
        <div className="flex items-center gap-2">
          {canIssue && detail && (
            <Button
              size="sm"
              variant="secondary"
              loading={issuing}
              onClick={() => void issue()}
              title={t('sla.issue.hint', {
                defaultValue:
                  'Freezes this computation into a stored report, with its audit trail, and records it in the audit log.',
              })}
            >
              <FileCheck2 size={14} className="mr-1.5" />
              {t('sla.issue.button', { defaultValue: 'Issue report' })}
            </Button>
          )}
          <button
            onClick={onClose}
            className="rounded p-1 text-text-muted hover:bg-bg-hover hover:text-text-primary"
            title={t('common.close')}
          >
            <X size={14} />
          </button>
        </div>
      }
    >
      {error ? (
        <div className="m-4 text-sm text-status-ssl-expired">
          <span className="font-mono text-xs">{error}</span>
        </div>
      ) : !detail ? (
        <div className="flex h-32 items-center justify-center">
          <LoadingSpinner />
        </div>
      ) : (
        <div className="space-y-4 p-4">
          {/* Headline and verdict */}
          <div className="flex flex-wrap items-baseline gap-x-6 gap-y-2">
            <div>
              <div className="text-[11px] uppercase tracking-wider text-text-muted">
                {t('sla.col.availability', { defaultValue: 'Availability' })}
              </div>
              <div className="text-2xl font-semibold text-text-primary">
                <Percent value={detail.availabilityPercent} />
              </div>
            </div>
            <div>
              <div className="text-[11px] uppercase tracking-wider text-text-muted">
                {t('sla.col.bracket', { defaultValue: 'Worst – best case' })}
              </div>
              <div className="text-sm tabular-nums text-text-secondary">
                {fmtPct(detail.worstCasePercent) ?? '—'} – {fmtPct(detail.bestCasePercent) ?? '—'}
              </div>
            </div>
            <div>
              <div className="text-[11px] uppercase tracking-wider text-text-muted">
                {t('sla.col.coverage', { defaultValue: 'Coverage' })}
              </div>
              <div className={cn('text-sm tabular-nums', COVERAGE_TONE[detail.coverageStatus])}>
                {fmtPct(detail.coveragePercent) ?? '—'} ·{' '}
                {t(`sla.coverage.${detail.coverageStatus}`, { defaultValue: COVERAGE_EN[detail.coverageStatus] })}
              </div>
            </div>
            <div>
              <div className="text-[11px] uppercase tracking-wider text-text-muted">
                {t('sla.col.objective', { defaultValue: 'Objective' })}
              </div>
              <div className="text-sm text-text-secondary">
                {fmtPct(detail.objectivePercent) ?? t('sla.noObjective', { defaultValue: 'none set' })}
                {detail.objectiveScope && (
                  <span className="text-text-muted">
                    {' '}
                    ({t(`sla.objectiveScope.${detail.objectiveScope}`, {
                      defaultValue: SCOPE_EN[detail.objectiveScope],
                    })})
                  </span>
                )}
              </div>
            </div>
            <div className="flex items-center gap-2">
              <VerdictPill verdict={detail.objectiveVerdict} reason={detail.verdictReason} />
            </div>
          </div>
          <p className="text-[13px] text-text-secondary">
            {t(`sla.verdictReason.${detail.verdictReason}`, {
              defaultValue: VERDICT_REASON_EN[detail.verdictReason] ?? detail.verdictReason,
            })}
          </p>

          {detail.maintenanceError && (
            <Banner tone="warn">
              {t('sla.detail.maintenanceError', {
                defaultValue:
                  'The maintenance window of this site could not be read, so nothing was excluded for maintenance: {{error}}',
                error: detail.maintenanceError,
              })}
            </Banner>
          )}

          {/* Totals */}
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-7">
            <Total label={t('sla.totals.period', { defaultValue: 'Period length' })} seconds={detail.totals.periodSeconds} />
            <Total label={kindLabel(t, 'up')} seconds={detail.totals.upSeconds} tone="text-status-up" />
            <Total label={kindLabel(t, 'down')} seconds={detail.totals.downSeconds} tone="text-status-down" />
            <Total
              label={kindLabel(t, 'excluded_management')}
              seconds={detail.totals.excludedManagementSeconds}
              tone="text-status-maintenance"
            />
            <Total
              label={kindLabel(t, 'excluded_maintenance')}
              seconds={detail.totals.excludedMaintenanceSeconds}
              tone="text-status-maintenance"
            />
            <Total label={kindLabel(t, 'unmeasured')} seconds={detail.totals.unmeasuredSeconds} tone="text-text-muted" />
            <Total
              label={t('sla.totals.accountable', { defaultValue: 'Billable time' })}
              seconds={detail.totals.accountableSeconds}
              hint={t('sla.totals.accountableHint', {
                defaultValue: 'The period minus both exclusions: what the customer may be billed for.',
              })}
            />
          </div>

          {/* Exclusions */}
          <div>
            <h3 className="mb-2 text-[13px] font-semibold text-text-primary">
              {t('sla.exclusions.title', { defaultValue: 'Exclusions' })}
            </h3>
            {detail.exclusions.length === 0 ? (
              <p className="text-[13px] text-text-muted">
                {t('sla.exclusions.none', { defaultValue: 'Nothing was excluded over this period.' })}
              </p>
            ) : (
              <table className="w-full text-sm">
                <thead className="border-b border-border text-left text-xs text-text-muted">
                  <tr>
                    <th className="py-1.5 pr-4 font-medium">{t('sla.intervals.kind', { defaultValue: 'Classification' })}</th>
                    <th className="py-1.5 pr-4 font-medium">{t('sla.intervals.reason', { defaultValue: 'Reason' })}</th>
                    <th className="py-1.5 pr-4 text-right font-medium">
                      {t('sla.exclusions.occurrences', { defaultValue: 'Occurrences' })}
                    </th>
                    <th className="py-1.5 text-right font-medium">{t('sla.intervals.duration', { defaultValue: 'Duration' })}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {detail.exclusions.map((x) => (
                    <tr key={`${x.kind}|${x.reason}`}>
                      <td className="py-1.5 pr-4">
                        <Pill className={KIND_TONE[x.kind]}>{kindLabel(t, x.kind)}</Pill>
                      </td>
                      <td className="py-1.5 pr-4 text-text-secondary">{reasonLabel(t, x.reason)}</td>
                      <td className="py-1.5 pr-4 text-right tabular-nums text-text-secondary">{x.occurrences}</td>
                      <td className="py-1.5 text-right tabular-nums text-text-primary">{formatDuration(x.seconds)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* Audit trail */}
          <div>
            <h3 className="mb-2 text-[13px] font-semibold text-text-primary">
              {t('sla.intervals.title', { defaultValue: 'Classification of the period (audit trail)' })}
            </h3>
            <IntervalTable intervals={detail.intervals} />
          </div>

          <p className="text-[11px] text-text-muted">
            {t('sla.detail.footer', {
              defaultValue:
                '{{devices}} active router(s) · one reachability sample speaks for at most {{validity}} · samples ignored as “cannot tell” (UNREACHABLE): {{unreachable}} · algorithm {{version}} · parameters {{hash}}',
              devices: detail.deviceCount,
              validity: formatDuration(detail.verdictValiditySeconds),
              unreachable: detail.unreachableSamplesIgnored,
              version: detail.algorithmVersion,
              hash: detail.paramsHash.slice(0, 12),
            })}
          </p>
        </div>
      )}
    </Panel>
  );
}

function Total({ label, seconds, tone, hint }: { label: string; seconds: number; tone?: string; hint?: string }) {
  return (
    <div className="rounded-md border border-border bg-bg-tertiary/40 p-2.5" title={hint}>
      <div className="text-[11px] text-text-muted">{label}</div>
      <div className={cn('mt-0.5 text-sm font-semibold tabular-nums', tone ?? 'text-text-primary')}>
        {seconds > 0 ? formatDuration(seconds) : '0 s'}
      </div>
    </div>
  );
}

/**
 * The classified intervals. Service intervals are hidden by default: the
 * question a customer asks of an SLA trail is "what did you count against me,
 * and what did you take off", and the answer is every interval that is not
 * service. One toggle shows the rest.
 */
function IntervalTable({ intervals }: { intervals: SlaInterval[] }) {
  const { t } = useTranslation();
  const [showUp, setShowUp] = useState(false);
  const visible = useMemo(
    () => (showUp ? intervals : intervals.filter((i) => i.kind !== 'up')),
    [intervals, showUp],
  );
  const shown = visible.slice(0, INTERVAL_ROWS_SHOWN);

  return (
    <div>
      <label className="mb-2 inline-flex cursor-pointer items-center gap-1.5 text-[12px] text-text-secondary">
        <input
          type="checkbox"
          checked={showUp}
          onChange={(e) => setShowUp(e.target.checked)}
          className="h-3.5 w-3.5 rounded border-border bg-bg-tertiary accent-accent"
        />
        {t('sla.intervals.showUp', { defaultValue: 'Show service intervals too' })}
      </label>
      {visible.length === 0 ? (
        <p className="text-[13px] text-text-muted">
          {t('sla.intervals.none', { defaultValue: 'No interval to show: the whole period was service.' })}
        </p>
      ) : (
        <div className="max-h-96 overflow-auto rounded-md border border-border">
          <table className="w-full text-sm">
            <thead className="sticky top-0 border-b border-border bg-bg-secondary text-left text-xs text-text-muted">
              <tr>
                <th className="px-3 py-1.5 font-medium">{t('sla.intervals.start', { defaultValue: 'Start' })}</th>
                <th className="px-3 py-1.5 font-medium">{t('sla.intervals.end', { defaultValue: 'End' })}</th>
                <th className="px-3 py-1.5 text-right font-medium">{t('sla.intervals.duration', { defaultValue: 'Duration' })}</th>
                <th className="px-3 py-1.5 font-medium">{t('sla.intervals.kind', { defaultValue: 'Classification' })}</th>
                <th className="px-3 py-1.5 font-medium">{t('sla.intervals.reason', { defaultValue: 'Reason' })}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {shown.map((i) => (
                <tr key={`${i.startedAt}|${i.kind}`}>
                  <td className="px-3 py-1.5 text-[12px]"><When iso={i.startedAt} /></td>
                  <td className="px-3 py-1.5 text-[12px]"><When iso={i.endedAt} /></td>
                  <td className="px-3 py-1.5 text-right text-[12px] tabular-nums text-text-primary">
                    {formatDuration(i.seconds)}
                  </td>
                  <td className="px-3 py-1.5">
                    <Pill className={KIND_TONE[i.kind] ?? KIND_TONE.unmeasured}>{kindLabel(t, i.kind)}</Pill>
                  </td>
                  <td className="px-3 py-1.5 text-[12px] text-text-secondary">{reasonLabel(t, i.reason)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {visible.length > shown.length && (
        <p className="mt-1 text-[11px] text-text-muted">
          {t('sla.intervals.truncated', {
            defaultValue: 'Showing the first {{shown}} of {{total}} intervals.',
            shown: shown.length,
            total: visible.length,
          })}
        </p>
      )}
    </div>
  );
}

// ── The published method ────────────────────────────────────────────────────

function MethodPanel({ method }: { method: SlaMethod | null }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  if (!method) return null;
  return (
    <section className="mb-4 rounded-lg border border-border bg-bg-secondary">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2 px-4 py-3 text-left text-sm font-semibold text-text-primary"
      >
        {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        <Info size={14} className="text-text-muted" />
        {t('sla.method.title', { defaultValue: 'What counts as downtime, and what is excluded' })}
        <span className="ml-auto font-mono text-[11px] font-normal text-text-muted">{method.algorithmVersion}</span>
      </button>
      {open && (
        <div className="space-y-3 border-t border-border px-4 py-3">
          <ul className="list-disc space-y-1.5 pl-5 text-[13px] text-text-secondary">
            {method.method.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
          <p className="text-[12px] text-text-muted">
            {t('sla.method.excluded', {
              defaultValue: 'Removed from both sides of the ratio: {{kinds}}.',
              kinds: method.vocabularies.excludedKinds.map((k) => kindLabel(t, k)).join(' · '),
            })}{' '}
            {t('sla.method.maxPeriod', {
              defaultValue: 'A single computation covers at most {{days}} days.',
              days: method.bounds.maxPeriodDays,
            })}
          </p>
        </div>
      )}
    </section>
  );
}

// ── Stored reports ──────────────────────────────────────────────────────────

function ReportsPanel({ siteId, nonce }: { siteId?: number; nonce: number }) {
  const { t } = useTranslation();
  const [reports, setReports] = useState<SlaStoredReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    slaApi
      .reports({ siteId, limit: 100 })
      .then((r) => alive && setReports(r))
      .catch((err) => alive && setError(slaErrorOf(err)))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [siteId, nonce]);

  return (
    <Panel title={t('sla.reports.title', { defaultValue: 'Issued reports' })}>
      {error ? (
        <div className="m-4 text-sm text-status-ssl-expired">
          <span className="font-mono text-xs">{error}</span>
        </div>
      ) : loading ? (
        <div className="flex h-24 items-center justify-center">
          <LoadingSpinner />
        </div>
      ) : reports.length === 0 ? (
        <EmptyState
          message={t('sla.reports.empty', {
            defaultValue: 'No report has been issued yet. Open a site above and issue one to freeze its figures.',
          })}
        />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="border-b border-border text-left text-xs text-text-muted">
              <tr>
                <th className="px-4 py-2 font-medium">{t('sla.reports.generated', { defaultValue: 'Issued' })}</th>
                <th className="px-4 py-2 font-medium">{t('sla.col.site', { defaultValue: 'Site' })}</th>
                <th className="px-4 py-2 font-medium">{t('sla.reports.period', { defaultValue: 'Period' })}</th>
                <th className="px-4 py-2 text-right font-medium">
                  {t('sla.col.availability', { defaultValue: 'Availability' })}
                </th>
                <th className="px-4 py-2 text-right font-medium">{t('sla.col.objective', { defaultValue: 'Objective' })}</th>
                <th className="px-4 py-2 font-medium">{t('sla.col.verdict', { defaultValue: 'Verdict' })}</th>
                <th className="px-4 py-2 font-medium">{t('sla.reports.by', { defaultValue: 'By' })}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {reports.map((r) => (
                <ReportRow key={r.id} report={r} open={open === r.id} onToggle={() => setOpen(open === r.id ? null : r.id)} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

function ReportRow({ report: r, open, onToggle }: { report: SlaStoredReport; open: boolean; onToggle: () => void }) {
  const { t } = useTranslation();
  const [intervals, setIntervals] = useState<SlaInterval[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open || intervals !== null) return;
    slaApi
      .reportIntervals(r.id)
      .then(setIntervals)
      .catch((err) => setError(slaErrorOf(err)));
  }, [open, intervals, r.id]);

  return (
    <>
      <tr onClick={onToggle} className={cn('cursor-pointer hover:bg-bg-hover', open && 'bg-bg-active')}>
        <td className="px-4 py-2 text-[12px]">
          <span className="inline-flex items-center gap-1.5">
            {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
            <When iso={r.generatedAt} />
          </span>
        </td>
        <td className="px-4 py-2 text-text-primary">
          {r.siteCode && <span className="mr-1.5 font-mono text-[12px] text-text-muted">{r.siteCode}</span>}
          {r.siteName ?? `#${r.siteId}`}
        </td>
        <td className="px-4 py-2 text-[12px] text-text-secondary">
          {fmtDate(r.periodStart)} → {fmtDate(r.periodEnd)}
        </td>
        <td className="px-4 py-2 text-right font-semibold text-text-primary">
          <Percent value={r.availabilityPercent} />
        </td>
        <td className="px-4 py-2 text-right text-[12px] text-text-secondary">
          {fmtPct(r.objectivePercent) ?? <span className="text-text-muted">{t('sla.noObjective', { defaultValue: 'none set' })}</span>}
        </td>
        <td className="px-4 py-2">
          <VerdictPill verdict={r.objectiveVerdict} reason={r.verdictReason} />
        </td>
        <td className="px-4 py-2 text-[12px] text-text-secondary">{r.actorName ?? '—'}</td>
      </tr>
      {open && (
        <tr>
          <td colSpan={7} className="bg-bg-tertiary/30 px-4 py-3">
            <div className="mb-2 flex flex-wrap gap-x-5 gap-y-1 text-[12px] text-text-secondary">
              <span>{kindLabel(t, 'down')}: <Seconds value={r.downSeconds} /></span>
              <span>{kindLabel(t, 'excluded_management')}: <Seconds value={r.excludedManagementSeconds} /></span>
              <span>{kindLabel(t, 'excluded_maintenance')}: <Seconds value={r.excludedMaintenanceSeconds} /></span>
              <span>{kindLabel(t, 'unmeasured')}: <Seconds value={r.unmeasuredSeconds} /></span>
              <span className="font-mono text-text-muted">
                {r.algorithmVersion} · {r.paramsHash.slice(0, 12)}
              </span>
            </div>
            {r.maintenanceError && (
              <Banner tone="warn">
                {t('sla.detail.maintenanceError', {
                  defaultValue:
                    'The maintenance window of this site could not be read, so nothing was excluded for maintenance: {{error}}',
                  error: r.maintenanceError,
                })}
              </Banner>
            )}
            {error ? (
              <span className="font-mono text-xs text-status-ssl-expired">{error}</span>
            ) : intervals === null ? (
              <LoadingSpinner size="sm" />
            ) : (
              <IntervalTable intervals={intervals} />
            )}
          </td>
        </tr>
      )}
    </>
  );
}

// ── Small pieces ────────────────────────────────────────────────────────────

function Banner({ tone, children }: { tone: 'warn' | 'info'; children: React.ReactNode }) {
  return (
    <div
      className={cn(
        'mb-4 flex items-start gap-2 rounded-lg border p-3 text-xs text-text-secondary',
        tone === 'warn' ? 'border-status-ssl-warning/40 bg-status-ssl-warning/5' : 'border-border bg-bg-secondary',
      )}
    >
      {tone === 'warn' ? (
        <AlertTriangle size={14} className="mt-0.5 shrink-0 text-status-ssl-warning" />
      ) : (
        <Info size={14} className="mt-0.5 shrink-0 text-text-muted" />
      )}
      <p>{children}</p>
    </div>
  );
}

const TONES = {
  ok: 'text-status-up',
  warn: 'text-status-ssl-warning',
  bad: 'text-status-down',
  muted: 'text-text-primary',
};

function SummaryCard({ label, value, tone }: { label: string; value: number; tone: keyof typeof TONES }) {
  return (
    <div className="rounded-lg border border-border bg-bg-secondary p-3">
      <div className="text-[11px] uppercase tracking-wider text-text-muted">{label}</div>
      <div className={cn('mt-1 font-display text-xl font-semibold tabular-nums', TONES[tone])}>{value}</div>
    </div>
  );
}
