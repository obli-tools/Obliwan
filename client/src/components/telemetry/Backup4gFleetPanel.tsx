import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { BellRing, Smartphone, Zap } from 'lucide-react';
import type { SiteUplinkKind, StoreProviderDto } from '@obliwan/shared';
import { Backup4gSims, relativeTime, shortDate, type Backup4gSim } from '@/components/telemetry/Backup4gBits';
import { TenantBadge } from '@/components/common/TenantBadge';

/**
 * "Sites on 4G backup" — every router of the workspace whose ACTIVE default
 * route (as the health check last read it) is on its cellular link while the
 * site has a fixed uplink, oldest episode first (server `backup4gFleet`). A
 * 4G-only site is not listed: it is on its only link, not on a backup — and a
 * site DECLARED 4G-only (migration 076) is excluded the same way (the fleet
 * anomalies page lists it as expected on cellular). A site declared 'fixed'
 * is listed even with no fixed interface recognised, tagged as such.
 */

export interface Backup4gFleetItem {
  /** God view only: the router's workspace (server utils/globalView.ts). */
  tenantId?: number;
  tenantName?: string | null;
  deviceId: number;
  deviceName: string;
  siteId: number | null;
  siteName: string | null;
  iface: string;
  since: string | null;
  observedAt: string;
  alertedAt: string | null;
  fixedUplinks: string[];
  /** The site's declaration: 'fixed' or null here (never 'cellular_only'). */
  declaredUplink?: SiteUplinkKind | null;
  /** null = the session does not hold SIM_READ. */
  sims: Backup4gSim[] | null;
  /** The fixed line's provider and the evidence it was established by
   *  (migration 095); null/absent = unknown. */
  provider?: StoreProviderDto | null;
  /** The open grouped operator outage this store is part of. */
  outageId?: number | null;
}

/** The provider filter's value for a store: its label, or '' when unknown. */
function providerLabelOf(i: Backup4gFleetItem): string {
  return i.provider && i.provider.key !== 'unknown' ? i.provider.label : '';
}

export function Backup4gFleetPanel({ items, failed }: { items: Backup4gFleetItem[] | null; failed: boolean }) {
  const { t, i18n } = useTranslation();
  const lang = i18n.language;
  const showSim = items?.some((i) => i.sims !== null) ?? false;
  // '*' = every provider; '' = the stores whose provider is unknown.
  const [providerFilter, setProviderFilter] = useState('*');
  const providers = useMemo(
    () => [...new Set((items ?? []).map(providerLabelOf))].sort((a, b) => a.localeCompare(b, lang)),
    [items, lang],
  );
  const shown = useMemo(
    () => (items ?? []).filter((i) => providerFilter === '*' || providerLabelOf(i) === providerFilter),
    [items, providerFilter],
  );
  const unknownLabel = t('operatorOutage.provider.unknown', { defaultValue: 'unknown provider' });
  return (
    <section className="mb-6 rounded-lg border border-border bg-bg-secondary p-4">
      <h2 className="mb-3 flex items-center gap-1.5 text-sm font-semibold text-text-primary">
        <Smartphone size={15} /> {t('dashboard.backup4g.listTitle')}
      </h2>
      {failed ? (
        <p className="text-sm text-text-muted">{t('dashboard.backup4g.loadError')}</p>
      ) : items === null ? (
        <p className="text-sm text-text-muted">…</p>
      ) : items.length === 0 ? (
        <p className="text-sm text-text-muted">{t('dashboard.backup4g.empty')}</p>
      ) : (
        <div className="overflow-x-auto">
          {providers.length > 1 && (
            <label className="mb-2 flex items-center gap-2 text-xs text-text-secondary">
              {t('operatorOutage.provider.filter', { defaultValue: 'Fixed-line provider' })}
              <select
                value={providerFilter}
                onChange={(e) => setProviderFilter(e.target.value)}
                className="rounded-md border border-border bg-bg-tertiary px-2 py-1 text-xs text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
              >
                <option value="*">{t('operatorOutage.provider.all', { defaultValue: 'all' })}</option>
                {providers.map((p) => (
                  <option key={p || '__unknown'} value={p}>{p || unknownLabel}</option>
                ))}
              </select>
              <span className="text-text-muted">{shown.length} / {items.length}</span>
            </label>
          )}
          <table className="w-full text-left text-xs">
            <thead className="text-[11px] uppercase tracking-wider text-text-muted">
              <tr>
                <th className="py-1 pr-3 font-medium">{t('dashboard.backup4g.colSite')}</th>
                <th className="py-1 pr-3 font-medium">{t('operatorOutage.provider.column', { defaultValue: 'Provider (fixed line)' })}</th>
                <th className="py-1 pr-3 font-medium">{t('dashboard.backup4g.colDevice')}</th>
                <th className="py-1 pr-3 font-medium">{t('dashboard.backup4g.colIface')}</th>
                <th className="py-1 pr-3 font-medium">{t('dashboard.backup4g.colSince')}</th>
                {showSim && <th className="py-1 font-medium">{t('dashboard.backup4g.colSim')}</th>}
              </tr>
            </thead>
            <tbody>
              {shown.map((i) => (
                <tr key={i.deviceId} className="border-t border-border align-top">
                  <td className="py-1.5 pr-3 text-text-primary">
                    {i.siteId !== null
                      ? <Link to={`/sites/${i.siteId}`} className="hover:underline">{i.siteName ?? `#${i.siteId}`}</Link>
                      : '—'}
                    {/* God view: whose site this is. */}
                    <TenantBadge name={i.tenantName} className="ml-1.5 align-middle" />
                  </td>
                  <td className="py-1.5 pr-3 text-text-secondary">
                    {providerLabelOf(i) !== ''
                      ? <span className="text-text-primary">{providerLabelOf(i)}</span>
                      : <span className="italic text-text-muted">{unknownLabel}</span>}
                    {i.provider && i.provider.evidence !== 'none' && (
                      <span
                        className="ml-1.5 rounded-full border border-border px-1.5 text-[10px] text-text-muted"
                        title={`${t(`operatorOutage.evidence.${i.provider.evidence}`)}${i.provider.detail ? ` : ${i.provider.detail}` : ''}`}
                      >
                        {t(`operatorOutage.evidenceShort.${i.provider.evidence}`)}
                      </span>
                    )}
                    {i.outageId != null && (
                      <Link
                        to={`/alerts?outage=${i.outageId}`}
                        className="ml-1.5 inline-flex items-center gap-0.5 rounded-full border border-status-ssl-warning/40 bg-status-ssl-warning/10 px-1.5 text-[10px] text-status-ssl-warning hover:underline"
                      >
                        <Zap size={9} /> {t('operatorOutage.badge', { defaultValue: 'Operator outage' })}
                      </Link>
                    )}
                  </td>
                  <td className="py-1.5 pr-3">
                    <Link to={`/devices/${i.deviceId}`} className="text-accent hover:underline">{i.deviceName}</Link>
                    {i.alertedAt && (
                      <span className="ml-1.5 inline-flex items-center gap-0.5 rounded-full border border-status-warn/40 bg-status-warn/10 px-1.5 text-[10px] text-status-warn">
                        <BellRing size={9} /> {t('dashboard.backup4g.alertedBadge')}
                      </span>
                    )}
                  </td>
                  <td className="py-1.5 pr-3 font-mono text-text-secondary">
                    {i.iface}
                    {i.declaredUplink === 'fixed' && i.fixedUplinks.length === 0 && (
                      <span
                        className="ml-1.5 rounded-full border border-border px-1.5 font-sans text-[10px] text-text-muted"
                        title={t('dashboard.backup4g.declaredFixedHint')}
                      >
                        {t('dashboard.backup4g.declaredFixed')}
                      </span>
                    )}
                  </td>
                  <td className="py-1.5 pr-3 text-text-secondary">
                    {i.since
                      ? <>{shortDate(i.since, lang)} <span className="text-text-muted">({relativeTime(i.since, lang)})</span></>
                      : <span className="text-text-muted">{t('dashboard.backup4g.sinceUnknown')}</span>}
                  </td>
                  {showSim && (
                    <td className="py-1.5">{i.sims !== null && <Backup4gSims sims={i.sims} lang={lang} />}</td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
