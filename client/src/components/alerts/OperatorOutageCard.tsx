import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { CheckCheck, ChevronDown, ChevronRight, Trash2, Zap } from 'lucide-react';
import type {
  ApiResponse,
  OperatorOutageDetailDto,
  OperatorOutagePoint,
  ProviderEvidence,
} from '@obliwan/shared';
import apiClient from '@/api/client';
import type { AlertSeverity, LiveAlert } from '@/store/liveAlertsStore';
import { TenantBadge } from '@/components/common/TenantBadge';
import { cn } from '@/utils/cn';

/**
 * ONE card per grouped operator outage (migration 095) in the alert history.
 *
 * The server files a group's alerts with `outageRole`: 'global' (the god
 * view's, every tenant's stores), 'tenant' (a customer workspace's slice) and
 * 'member' (a per-store 4G alert FOLDED under the group — created, never sent
 * to the channels). The page hands this card every visible row of one group;
 * the header is the newest group row, the folded per-store alerts are its
 * children, and the details (stores, provider and how it was established,
 * count over time) are read from GET /api/operator-outages/:id — scoped by the
 * server: a customer sees its own stores only, a 404 means none is visible.
 */

const EVIDENCE: ProviderEvidence[] = ['declared', 'pppoe_realm', 'asn', 'prefix', 'none'];

export interface OperatorOutageGroup {
  outageId: number;
  /** The newest 'global' (god view) or 'tenant' row; null when only folded rows are visible. */
  header: LiveAlert | null;
  /** The folded per-store alerts, newest first. */
  members: LiveAlert[];
  /** Newest row of the group (sorting). */
  latestAt: number;
}

export function OperatorOutageCard({
  group,
  dateFmt,
  severityTone,
  severityIcon,
  initiallyOpen,
  onRead,
  onRemove,
}: {
  group: OperatorOutageGroup;
  dateFmt: Intl.DateTimeFormat;
  severityTone: Record<AlertSeverity, string>;
  severityIcon: Record<AlertSeverity, React.ReactNode>;
  initiallyOpen: boolean;
  onRead: (id: number) => void;
  onRemove: (id: number) => void;
}) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(initiallyOpen);
  const [detail, setDetail] = useState<OperatorOutageDetailDto | null>(null);
  const [state, setState] = useState<'idle' | 'loading' | 'missing' | 'failed'>('idle');
  const ref = useRef<HTMLLIElement>(null);
  const header = group.header;
  const needDetail = open || header === null;

  useEffect(() => {
    if (!needDetail || state !== 'idle') return;
    setState('loading');
    apiClient
      .get<ApiResponse<OperatorOutageDetailDto>>(`/operator-outages/${group.outageId}`)
      .then((r) => {
        setDetail(r.data.data ?? null);
        setState('idle');
      })
      .catch((err: { response?: { status?: number } }) => setState(err.response?.status === 404 ? 'missing' : 'failed'));
    // `state` deliberately left out: one read per opening, a retry is the refresh button.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [needDetail, group.outageId]);

  useEffect(() => {
    if (initiallyOpen) ref.current?.scrollIntoView({ block: 'start', behavior: 'smooth' });
  }, [initiallyOpen]);

  const severity: AlertSeverity = header?.severity ?? (detail?.status === 'closed' ? 'up' : 'warning');
  const title = header?.title
    ?? (detail
      ? t(detail.unknownProvider ? 'operatorOutage.card.titleUnknown' : 'operatorOutage.card.title', {
          provider: detail.providerLabel,
          count: detail.activeCount,
        })
      : t('operatorOutage.card.titleLoading'));
  const created = header ? new Date(header.createdAt) : new Date(group.latestAt);
  const unread = (header !== null && !header.read) || group.members.some((m) => !m.read);

  return (
    <li
      ref={ref}
      className={cn(
        'rounded-lg border bg-bg-secondary px-3 py-2.5',
        unread ? 'border-status-ssl-warning/50' : 'border-border',
      )}
    >
      <div className="flex items-start gap-3">
        <span
          className={cn(
            'mt-0.5 inline-flex shrink-0 items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-wider',
            severityTone[severity],
          )}
        >
          {severityIcon[severity]}
          {t(`alerts.severity.${severity}`)}
        </span>
        <div className="min-w-0 flex-1">
          <p className="flex flex-wrap items-center gap-2 text-[13px] font-medium text-text-primary">
            <Zap size={13} className="shrink-0 text-status-ssl-warning" />
            {title}
            {header && !header.read && (
              <span className="rounded bg-accent/15 px-1.5 py-px text-[9px] uppercase tracking-wider text-accent">
                {t('alerts.new')}
              </span>
            )}
            <span className="rounded border border-border px-1.5 py-px text-[10px] font-normal text-text-muted">
              {t('operatorOutage.card.grouped')}
            </span>
          </p>
          {header && (
            <p className="mt-0.5 whitespace-pre-wrap break-words text-[12px] text-text-secondary">{header.message}</p>
          )}
          <p className="mt-1 flex flex-wrap items-center gap-2 font-mono text-[11px] text-text-muted">
            <span>{Number.isNaN(created.getTime()) ? '—' : dateFmt.format(created)}</span>
            {header && (
              <span className="rounded border border-border px-1 py-px">{header.tenantName ?? `#${header.tenantId}`}</span>
            )}
            <button
              type="button"
              onClick={() => setOpen((v) => !v)}
              className="inline-flex items-center gap-0.5 font-sans text-accent hover:underline"
            >
              {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
              {open ? t('operatorOutage.card.hide') : t('operatorOutage.card.show')}
              {group.members.length > 0 && ` · ${t('operatorOutage.card.foldedCount', { count: group.members.length })}`}
            </button>
          </p>
        </div>
        {header && (
          <div className="flex shrink-0 items-center gap-1">
            {!header.read && (
              <button
                onClick={() => onRead(header.id)}
                title={t('alerts.markRead')}
                className="rounded p-1.5 text-text-muted hover:bg-bg-hover hover:text-text-primary"
              >
                <CheckCheck size={13} />
              </button>
            )}
            <button
              onClick={() => onRemove(header.id)}
              title={t('alerts.delete')}
              className="rounded p-1.5 text-text-muted hover:bg-bg-hover hover:text-status-ssl-expired"
            >
              <Trash2 size={13} />
            </button>
          </div>
        )}
      </div>

      {open && (
        <div className="mt-3 space-y-3 border-t border-border pt-3">
          {state === 'loading' && <p className="text-xs text-text-muted">…</p>}
          {state === 'missing' && <p className="text-xs text-text-muted">{t('operatorOutage.card.notVisible')}</p>}
          {state === 'failed' && <p className="text-xs text-status-ssl-expired">{t('operatorOutage.card.loadFailed')}</p>}
          {detail && <OutageDetail detail={detail} dateFmt={dateFmt} />}
          {group.members.length > 0 && (
            <div>
              <h4 className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-text-muted">
                {t('operatorOutage.card.foldedTitle')}
              </h4>
              <ul className="space-y-1">
                {group.members.map((m) => (
                  <li key={m.id} className="flex items-start gap-2 rounded border border-border/60 px-2 py-1">
                    <span
                      className={cn(
                        'mt-0.5 inline-flex shrink-0 items-center gap-1 rounded border px-1 py-px text-[9px] uppercase tracking-wider',
                        severityTone[m.severity],
                      )}
                    >
                      {severityIcon[m.severity]}
                    </span>
                    <div className="min-w-0 flex-1 text-[12px]">
                      <span className="font-medium text-text-primary">{m.title}</span>
                      <span className="ml-2 font-mono text-[10px] text-text-muted">
                        {dateFmt.format(new Date(m.createdAt))}
                      </span>
                      {m.navigateTo && (
                        <Link to={m.navigateTo} className="ml-2 text-[11px] text-accent hover:underline">
                          {t('alerts.open')}
                        </Link>
                      )}
                    </div>
                    <button
                      onClick={() => onRemove(m.id)}
                      title={t('alerts.delete')}
                      className="rounded p-1 text-text-muted hover:bg-bg-hover hover:text-status-ssl-expired"
                    >
                      <Trash2 size={11} />
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </li>
  );
}

function OutageDetail({ detail, dateFmt }: { detail: OperatorOutageDetailDto; dateFmt: Intl.DateTimeFormat }) {
  const { t } = useTranslation();
  const fmt = (iso: string | null) => (iso ? dateFmt.format(new Date(iso)) : '—');
  const evidence = EVIDENCE.filter((e) => (detail.evidence[e] ?? 0) > 0);
  return (
    <div className="space-y-3">
      <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-[12px] md:grid-cols-4">
        <div>
          <dt className="text-[10px] uppercase tracking-wider text-text-muted">{t('operatorOutage.card.provider')}</dt>
          <dd className="text-text-primary">
            {detail.unknownProvider ? t('operatorOutage.provider.unknown') : detail.providerLabel}
          </dd>
        </div>
        <div>
          <dt className="text-[10px] uppercase tracking-wider text-text-muted">{t('operatorOutage.card.status')}</dt>
          <dd className="text-text-primary">
            {detail.status === 'open'
              ? t('operatorOutage.card.statusOpen')
              : t(`operatorOutage.card.closed.${detail.closeReason ?? 'recovered'}`, { date: fmt(detail.closedAt) })}
          </dd>
        </div>
        <div>
          <dt className="text-[10px] uppercase tracking-wider text-text-muted">{t('operatorOutage.card.startedAt')}</dt>
          <dd className="font-mono text-text-primary">{fmt(detail.startedAt)}</dd>
        </div>
        <div>
          <dt className="text-[10px] uppercase tracking-wider text-text-muted">{t('operatorOutage.card.counts')}</dt>
          <dd className="text-text-primary">
            {t('operatorOutage.card.countsValue', {
              active: detail.activeCount,
              cellular: detail.cellularCount,
              offline: detail.offlineCount,
              peak: detail.peakCount,
              total: detail.totalCount,
            })}
          </dd>
        </div>
      </dl>

      <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
        <span className="text-text-muted">{t('operatorOutage.card.evidence')}</span>
        {evidence.length === 0 && <span className="text-text-muted">—</span>}
        {evidence.map((e) => (
          <span key={e} className="rounded-full border border-border px-1.5 text-text-secondary">
            {t(`operatorOutage.evidence.${e}`)} × {detail.evidence[e]}
          </span>
        ))}
        <span className="ml-2 text-text-muted">
          {t('operatorOutage.card.rule', { threshold: detail.threshold, minutes: detail.windowMinutes })}
        </span>
      </div>

      {detail.points.length > 1 && (
        <div>
          <h4 className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-text-muted">
            {t('operatorOutage.card.overTime')}
          </h4>
          <CountChart points={detail.points} dateFmt={dateFmt} />
        </div>
      )}

      <div className="overflow-x-auto">
        <table className="w-full text-left text-[12px]">
          <thead className="text-[10px] uppercase tracking-wider text-text-muted">
            <tr>
              <th className="py-1 pr-3 font-medium">{t('operatorOutage.card.colSite')}</th>
              <th className="py-1 pr-3 font-medium">{t('operatorOutage.card.colDevice')}</th>
              <th className="py-1 pr-3 font-medium">{t('operatorOutage.card.colState')}</th>
              <th className="py-1 pr-3 font-medium">{t('operatorOutage.card.colLostAt')}</th>
              <th className="py-1 pr-3 font-medium">{t('operatorOutage.card.colEvidence')}</th>
            </tr>
          </thead>
          <tbody>
            {detail.members.map((m) => (
              <tr key={m.deviceId} className="border-t border-border align-top">
                <td className="py-1 pr-3 text-text-primary">
                  {m.siteId !== null
                    ? <Link to={`/sites/${m.siteId}`} className="hover:underline">{m.siteName ?? `#${m.siteId}`}</Link>
                    : '—'}
                  <TenantBadge name={m.tenantName} className="ml-1.5 align-middle" />
                </td>
                <td className="py-1 pr-3">
                  <Link to={`/devices/${m.deviceId}`} className="text-accent hover:underline">{m.deviceName}</Link>
                  {m.alertFolded && (
                    <span className="ml-1.5 rounded-full border border-border px-1.5 text-[10px] text-text-muted">
                      {t('operatorOutage.card.alertFolded')}
                    </span>
                  )}
                </td>
                <td className="py-1 pr-3">
                  {m.recoveredAt ? (
                    <span className="text-status-up">{t('operatorOutage.card.recovered', { date: fmt(m.recoveredAt) })}</span>
                  ) : m.releasedAt ? (
                    <span className="text-status-ssl-warning">{t('operatorOutage.card.released')}</span>
                  ) : (
                    <span className="text-text-primary">
                      {m.kind === 'cellular' ? t('operatorOutage.card.kindCellular') : t('operatorOutage.card.kindOffline')}
                    </span>
                  )}
                </td>
                <td className="py-1 pr-3 font-mono text-text-secondary">{fmt(m.lostAt)}</td>
                <td className="py-1 pr-3 text-text-secondary">
                  {t(`operatorOutage.evidence.${m.evidence}`)}
                  {m.evidenceDetail && <span className="ml-1 font-mono text-text-muted">{m.evidenceDetail}</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/** The count over time, as a step line (the count holds until the next point). */
function CountChart({ points, dateFmt }: { points: OperatorOutagePoint[]; dateFmt: Intl.DateTimeFormat }) {
  const W = 320;
  const H = 56;
  const pad = 4;
  const times = points.map((p) => new Date(p.at).getTime());
  const t0 = times[0];
  const t1 = Math.max(times[times.length - 1], Date.now() > t0 ? Math.min(Date.now(), times[times.length - 1] + 60_000) : t0 + 1);
  const max = Math.max(1, ...points.map((p) => p.count));
  const x = (t: number) => pad + ((t - t0) / Math.max(1, t1 - t0)) * (W - 2 * pad);
  const y = (c: number) => H - pad - (c / max) * (H - 2 * pad);
  let d = `M ${x(times[0])} ${y(points[0].count)}`;
  for (let i = 1; i < points.length; i++) {
    d += ` H ${x(times[i])} V ${y(points[i].count)}`;
  }
  d += ` H ${x(t1)}`;
  const last = points[points.length - 1];
  return (
    <div className="flex items-end gap-3">
      <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`} className="text-accent" role="img">
        <line x1={pad} x2={W - pad} y1={H - pad} y2={H - pad} className="stroke-border" strokeWidth={1} />
        <path d={d} fill="none" stroke="currentColor" strokeWidth={1.75} />
        {points.map((p, i) => (
          <circle key={i} cx={x(times[i])} cy={y(p.count)} r={2} fill="currentColor">
            <title>{`${dateFmt.format(new Date(p.at))} — ${p.count}`}</title>
          </circle>
        ))}
      </svg>
      <div className="font-mono text-[10px] text-text-muted">
        <div>max {max}</div>
        <div>{dateFmt.format(new Date(last.at))} — {last.count}</div>
      </div>
    </div>
  );
}
