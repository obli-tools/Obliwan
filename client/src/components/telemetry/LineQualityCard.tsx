import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { Activity } from 'lucide-react';
import type {
  LineQualityDeviceView,
  LineQualityNightView,
  LineQualityReason,
  LineQualityStatus,
} from '@obliwan/shared';
import { lineQualityApi } from '@/api/lineQuality.api';
import { StatusSection } from '@/components/device/StatusSection';
import type { SignalTone } from '@/components/device/deviceSignals';
import { cn } from '@/utils/cn';

/**
 * « Qualité de ligne » — the store's FIXED line, measured each night outside
 * opening hours (server: fleet/lineQuality.service.ts, migration 097).
 *
 * A figure carried by the 4G is never drawn as the line's: the sparkline
 * leaves a gap on such a night (never a bridged line), the table names the
 * link that carried each night, and a night spent on the 4G backup is shown
 * as the fixed line DOWN. The status, its reasons and the thresholds are the
 * server's; nothing here re-judges.
 */

export const STATUS_TONE: Record<LineQualityStatus, SignalTone> = {
  degraded: 'warn',
  watch: 'info',
  ok: 'ok',
  unknown: 'unknown',
};

const STATUS_CLASS: Record<LineQualityStatus, string> = {
  degraded: 'border-status-ssl-warning/40 bg-status-ssl-warning-bg text-status-ssl-warning',
  watch: 'border-status-pending/40 bg-status-pending-bg text-status-pending',
  ok: 'border-status-up/40 bg-status-up-bg text-status-up',
  unknown: 'border-border bg-bg-tertiary text-text-muted',
};

export function LineQualityStatusBadge({ status, streak }: { status: LineQualityStatus; streak?: number }) {
  const { t } = useTranslation();
  return (
    <span className={cn('inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium', STATUS_CLASS[status])}>
      {t(`lineQuality.status.${status}`)}
      {status === 'degraded' && streak ? ` · ${t('lineQuality.nights', { count: streak })}` : ''}
    </span>
  );
}

export function fmt(n: number | null | undefined, lang: string, digits = 1): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return '—';
  return n.toLocaleString(lang, { maximumFractionDigits: digits });
}

/** One reason, as an operator reads it. */
export function reasonText(t: TFunction, r: LineQualityReason, lang: string): string {
  if (r.metric === 'fixed_down') return t('lineQuality.reason.fixed_down');
  return t(`lineQuality.reason.${r.metric}_${r.kind}`, {
    value: fmt(r.value, lang),
    threshold: fmt(r.threshold, lang),
    baseline: fmt(r.baseline, lang),
  });
}

/** "9 oct." in the operator's language, from the night's local date. */
export function nightLabel(night: string, lang: string): string {
  const [y, m, d] = night.split('-').map(Number);
  return new Date(Date.UTC(y, m - 1, d)).toLocaleDateString(lang, { day: 'numeric', month: 'short', timeZone: 'UTC' });
}

/**
 * Average RTT of the last nights through the fixed line, oldest first. A
 * single series: no legend box (the label names it). A night with no
 * fixed-line figure is a GAP, never joined across; an exceeded night carries
 * a status dot. Every point has a hover tooltip on a hit target wider than
 * the mark, and the table under the chart is its table view.
 */
export function LineQualitySparkline({
  points,
  width = 168,
  height = 36,
  label,
}: {
  points: Array<{ night: string; value: number | null; exceeded: boolean }>;
  width?: number;
  height?: number;
  label: string;
}) {
  const { t, i18n } = useTranslation();
  const values = points.map((p) => p.value).filter((v): v is number => v !== null);
  if (points.length === 0) return null;
  const pad = 4;
  const max = Math.max(1, ...values);
  const min = Math.min(max, ...values);
  const span = Math.max(1, max - min);
  const step = points.length > 1 ? (width - 2 * pad) / (points.length - 1) : 0;
  const x = (i: number) => pad + i * step;
  const y = (v: number) => height - pad - ((v - min) / span) * (height - 2 * pad);
  // Runs of consecutive fixed-line nights: one path each, so a gap stays a gap.
  const runs: Array<Array<{ i: number; v: number }>> = [];
  let run: Array<{ i: number; v: number }> = [];
  points.forEach((p, i) => {
    if (p.value === null) {
      if (run.length) runs.push(run);
      run = [];
    } else {
      run.push({ i, v: p.value });
    }
  });
  if (run.length) runs.push(run);
  const lang = i18n.language;
  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label={label} className="overflow-visible">
      <line x1={pad} x2={width - pad} y1={height - pad} y2={height - pad} className="stroke-border" strokeWidth={1} />
      {runs.map((r) => (
        r.length === 1
          ? <circle key={`r${r[0].i}`} cx={x(r[0].i)} cy={y(r[0].v)} r={2} className="fill-accent" />
          : (
            <polyline
              key={`r${r[0].i}`}
              points={r.map((q) => `${x(q.i)},${y(q.v)}`).join(' ')}
              fill="none"
              className="stroke-accent"
              strokeWidth={2}
              strokeLinejoin="round"
              strokeLinecap="round"
            />
          )
      ))}
      {points.map((p, i) => (
        <g key={p.night}>
          {p.exceeded && (
            <circle
              cx={x(i)}
              cy={p.value === null ? height - pad : y(p.value)}
              r={4}
              className="fill-status-ssl-warning stroke-bg-secondary"
              strokeWidth={2}
            />
          )}
          <rect x={x(i) - Math.max(step / 2, 6)} y={0} width={Math.max(step, 12)} height={height} fill="transparent">
            <title>
              {p.value === null
                ? t('lineQuality.sparkline.noFixed', { night: nightLabel(p.night, lang) })
                : t('lineQuality.sparkline.point', { night: nightLabel(p.night, lang), value: `${fmt(p.value, lang)} ms` })}
              {p.exceeded ? ` — ${t('lineQuality.verdict.exceeded')}` : ''}
            </title>
          </rect>
        </g>
      ))}
    </svg>
  );
}

function nightUplink(t: TFunction, n: LineQualityNightView): string {
  if (n.status === 'skipped') return t(`lineQuality.skip.${n.skipReason ?? 'internal'}`);
  if (n.status === 'pending') return t('lineQuality.pending');
  if (n.fixedDown) return t('lineQuality.onBackup', { iface: n.uplinkIface ?? '—' });
  return n.uplinkIface ? `${n.uplinkIface} · ${t(`lineQuality.carrier.${n.carrier ?? 'unknown'}`)}` : t(`lineQuality.carrier.${n.carrier ?? 'unknown'}`);
}

export function LineQualityCard({ view }: { view: LineQualityDeviceView }) {
  const { t, i18n } = useTranslation();
  const lang = i18n.language;
  const line = 'text-[11px] text-text-muted';
  if (view.notMeasured) {
    return <p className="text-sm text-text-secondary">{t(`lineQuality.notMeasured.${view.notMeasured}`)}</p>;
  }
  const latestMeasured = view.nights.find((n) => n.status === 'measured') ?? null;
  const latestExceeded = view.nights.find((n) => n.verdict === 'exceeded') ?? null;
  const flagged = view.status === 'degraded' || view.status === 'watch';
  const oldestFirst = [...view.nights].reverse();
  const methods = latestMeasured?.targets
    .filter((x) => x.method)
    .map((x) => `${x.target} : ${t(`lineQuality.method.${x.method}`)}${x.iface ? ` (${x.iface})` : ''}`) ?? [];
  const th = view.thresholds;

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <LineQualityStatusBadge status={view.status} streak={view.streak} />
            {view.lastJudgedNight && (
              <span className={line}>{t('lineQuality.lastJudged', { night: nightLabel(view.lastJudgedNight, lang) })}</span>
            )}
          </div>
          {flagged && latestExceeded && (
            <ul className="mt-2 space-y-0.5">
              {latestExceeded.reasons.map((r, i) => (
                <li key={i} className="text-xs text-status-ssl-warning">{reasonText(t, r, lang)}</li>
              ))}
            </ul>
          )}
          {latestMeasured && (
            <p className="mt-2 text-xs text-text-secondary">
              <span className="text-text-muted">{t('lineQuality.measuredUplink')} : </span>
              {nightUplink(t, latestMeasured)}
            </p>
          )}
          {methods.length > 0 && <p className={line}>{methods.join(' · ')}</p>}
        </div>
        <div className="shrink-0">
          <LineQualitySparkline
            label={t('lineQuality.sparkline.label')}
            points={oldestFirst.map((n) => ({
              night: n.night,
              value: n.status === 'measured' && n.carrier === 'fixed' ? n.rttAvgMs : null,
              exceeded: n.verdict === 'exceeded',
            }))}
          />
          <p className="mt-0.5 text-right text-[10px] text-text-muted">{t('lineQuality.sparkline.label')}</p>
        </div>
      </div>

      {view.nights.length === 0 ? (
        <p className="text-sm text-text-muted">{t('lineQuality.noNights')}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="border-b border-border text-left text-[10px] uppercase tracking-wide text-text-muted">
              <tr>
                <th className="px-2 py-1.5 font-medium">{t('lineQuality.col.night')}</th>
                <th className="px-2 py-1.5 font-medium">{t('lineQuality.col.uplink')}</th>
                <th className="px-2 py-1.5 text-right font-medium">{t('lineQuality.col.latency')}</th>
                <th className="px-2 py-1.5 text-right font-medium">{t('lineQuality.col.loss')}</th>
                <th className="px-2 py-1.5 text-right font-medium">{t('lineQuality.col.jitter')}</th>
                <th className="px-2 py-1.5 text-right font-medium">{t('lineQuality.col.reconnections')}</th>
                <th className="px-2 py-1.5 font-medium">{t('lineQuality.col.verdict')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {view.nights.map((n) => {
                const fixed = n.status === 'measured' && n.carrier === 'fixed';
                const counters = t('lineQuality.counters', {
                  linkDowns: n.linkDowns ?? '—',
                  failovers: n.failovers ?? '—',
                  mgmt: n.mgmtReconnects ?? '—',
                  errors: n.wan1Errors ?? '—',
                });
                return (
                  <tr key={n.night} className={n.verdict === 'exceeded' ? 'bg-status-ssl-warning-bg/40' : undefined}>
                    <td className="whitespace-nowrap px-2 py-1.5 text-text-secondary">{nightLabel(n.night, lang)}</td>
                    <td className="px-2 py-1.5 text-text-secondary">{nightUplink(t, n)}</td>
                    {/* A 4G-carried figure is not the line's: shown in muted ink. */}
                    <td className={cn('px-2 py-1.5 text-right font-mono', fixed ? 'text-text-primary' : 'text-text-muted')}>
                      {n.rttAvgMs === null ? '—' : `${fmt(n.rttAvgMs, lang)} ms`}
                    </td>
                    <td className={cn('px-2 py-1.5 text-right font-mono', fixed ? 'text-text-primary' : 'text-text-muted')}>
                      {n.lossPct === null ? '—' : `${fmt(n.lossPct, lang)} %`}
                    </td>
                    <td className={cn('px-2 py-1.5 text-right font-mono', fixed ? 'text-text-primary' : 'text-text-muted')}>
                      {n.jitterMs === null ? '—' : `${fmt(n.jitterMs, lang)} ms`}
                    </td>
                    <td className="px-2 py-1.5 text-right font-mono text-text-primary" title={counters}>
                      {n.reconnections ?? '—'}
                    </td>
                    <td className="px-2 py-1.5">
                      <span
                        className={cn(
                          'text-[11px]',
                          n.verdict === 'exceeded' ? 'text-status-ssl-warning' : n.verdict === 'ok' ? 'text-status-up' : 'text-text-muted',
                        )}
                        title={n.reasons.map((r) => reasonText(t, r, lang)).join(' · ') || undefined}
                      >
                        {t(`lineQuality.verdict.${n.verdict}`)}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <div className="mt-3 space-y-0.5 border-t border-border pt-2">
        <p className={line}>
          {view.hoursKnown
            ? t('lineQuality.schedule.hours')
            : t('lineQuality.schedule.window', { start: view.nightWindow.startHour, end: view.nightWindow.endHour })}
        </p>
        <p className={line}>
          {view.targets.length > 0 ? t('lineQuality.targets', { targets: view.targets.join(', ') }) : t('lineQuality.noTargets')}
        </p>
        <p className={line}>
          {t('lineQuality.thresholds', {
            loss: th.lossPct, latency: th.latencyMs, reconnections: th.reconnections, relative: th.relativePct, nights: th.nights,
          })}
        </p>
      </div>
    </div>
  );
}

/**
 * The device page's section: fetches its own view and draws the folded
 * header (tone + one-line answer) like every other topic of the overview.
 * Draws nothing on a device the measurement does not concern.
 */
export function LineQualitySection({ deviceId }: { deviceId: number }) {
  const { t, i18n } = useTranslation();
  const [view, setView] = useState<LineQualityDeviceView | null | undefined>(undefined);

  useEffect(() => {
    let alive = true;
    lineQualityApi
      .device(deviceId)
      .then((v) => { if (alive) setView(v); })
      .catch(() => { if (alive) setView(null); });
    return () => { alive = false; };
  }, [deviceId]);

  if (view && (view.notMeasured === 'not_mikrotik' || view.notMeasured === 'concentrator')) return null;
  const tone: SignalTone = view === undefined ? 'loading' : view === null ? 'unknown' : view.notMeasured ? 'info' : STATUS_TONE[view.status];
  const summary = view === undefined
    ? t('lineQuality.summary.loading')
    : view === null
      ? t('lineQuality.summary.unreadable')
      : view.notMeasured
        ? t('lineQuality.summary.notMeasured')
        : view.status === 'degraded'
          ? t('lineQuality.summary.degraded', { count: view.streak })
          : view.status === 'watch'
            ? t('lineQuality.summary.watch')
            : view.status === 'ok' && view.lastJudgedNight
              ? t('lineQuality.summary.ok', { night: nightLabel(view.lastJudgedNight, i18n.language) })
              : t('lineQuality.summary.unknown');

  return (
    <StatusSection title={t('lineQuality.title')} icon={<Activity size={15} />} tone={tone} summary={summary}>
      {view ? <LineQualityCard view={view} /> : view === null ? (
        <p className="text-sm text-text-muted">{t('lineQuality.summary.unreadable')}</p>
      ) : null}
    </StatusSection>
  );
}
