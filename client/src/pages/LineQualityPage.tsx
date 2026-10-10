import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Activity, RotateCw } from 'lucide-react';
import type { LineQualityFleetItem } from '@obliwan/shared';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { lineQualityApi } from '@/api/lineQuality.api';
import {
  LineQualitySparkline,
  LineQualityStatusBadge,
  fmt,
  nightLabel,
  reasonText,
} from '@/components/telemetry/LineQualityCard';

/**
 * « Lignes dégradées » — the stores whose FIXED line is degraded or to be
 * watched, worst first (server: GET /api/line-quality, DEVICE_READ). What the
 * nightly measurement filed, nothing dialled from here. In the god view
 * (Default, platform admin) every tenant is listed, with its name.
 */

const TH = 'px-3 py-2 font-medium';
const TD = 'px-3 py-2 align-top';

export function LineQualityPage() {
  const { t, i18n } = useTranslation();
  const lang = i18n.language;
  const [items, setItems] = useState<LineQualityFleetItem[] | null>(null);
  const [godView, setGodView] = useState(false);
  const [all, setAll] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await lineQualityApi.fleet({ all });
      setItems(r.items);
      setGodView(r.godView);
    } catch (err) {
      const e = err as { response?: { data?: { error?: string } }; message?: string };
      setError(e.response?.data?.error ?? e.message ?? 'error');
    } finally {
      setLoading(false);
    }
  }, [all]);

  useEffect(() => { void load(); }, [load]);

  const degraded = items?.filter((i) => i.status === 'degraded').length ?? 0;
  const watch = items?.filter((i) => i.status === 'watch').length ?? 0;

  return (
    <div className="p-6">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-3">
        <h1 className="flex items-center gap-2 text-2xl font-semibold text-text-primary">
          <Activity size={22} /> {t('lineQuality.page.title')}
        </h1>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-1.5 text-xs text-text-secondary">
            <input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} />
            {t('lineQuality.page.showAll')}
          </label>
          <Button size="sm" variant="secondary" onClick={() => void load()} disabled={loading}>
            <RotateCw size={14} className="mr-1.5" />{t('common.refresh')}
          </Button>
        </div>
      </div>
      <p className="mb-5 max-w-3xl text-xs text-text-muted">{t('lineQuality.page.hint')}</p>

      {loading && !items ? <LoadingSpinner /> : error ? (
        <div className="rounded-lg border border-border bg-status-down-bg px-4 py-3 text-sm text-status-down">
          {t('lineQuality.page.loadError')} — {error}
        </div>
      ) : items && (
        <section className="rounded-lg border border-border bg-bg-secondary">
          <header className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-3 text-sm">
            <span className="rounded-full bg-status-ssl-warning-bg px-2 py-0.5 text-xs text-status-ssl-warning">
              {t('lineQuality.page.countDegraded', { count: degraded })}
            </span>
            <span className="rounded-full bg-status-pending-bg px-2 py-0.5 text-xs text-status-pending">
              {t('lineQuality.page.countWatch', { count: watch })}
            </span>
          </header>
          {items.length === 0 ? (
            <p className="px-4 py-6 text-center text-sm text-text-secondary">{t('lineQuality.page.empty')}</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="border-b border-border text-left text-xs uppercase tracking-wide text-text-muted">
                  <tr>
                    <th className={TH}>{t('lineQuality.page.col.site')}</th>
                    {godView && <th className={TH}>{t('lineQuality.page.col.tenant')}</th>}
                    <th className={TH}>{t('lineQuality.page.col.status')}</th>
                    <th className={TH}>{t('lineQuality.page.col.why')}</th>
                    <th className={`${TH} text-right`}>{t('lineQuality.col.latency')}</th>
                    <th className={`${TH} text-right`}>{t('lineQuality.col.loss')}</th>
                    <th className={`${TH} text-right`}>{t('lineQuality.col.reconnections')}</th>
                    <th className={TH}>{t('lineQuality.page.col.trend')}</th>
                    <th className={TH}>{t('lineQuality.page.col.lastNight')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {items.map((i) => (
                    <tr key={i.siteId}>
                      <td className={TD}>
                        <div className="font-mono text-xs text-text-muted">{i.siteCode}</div>
                        <div className="text-text-primary">{i.siteName}</div>
                        {i.deviceId !== null && (
                          <Link to={`/devices/${i.deviceId}`} className="text-xs text-accent hover:underline">{i.deviceName}</Link>
                        )}
                      </td>
                      {godView && <td className={`${TD} text-xs text-text-secondary`}>{i.tenantName ?? '—'}</td>}
                      <td className={TD}><LineQualityStatusBadge status={i.status} streak={i.streak} /></td>
                      <td className={`${TD} text-xs text-text-secondary`}>
                        {i.reasons.length === 0 ? '—' : (
                          <ul className="space-y-0.5">
                            {i.reasons.map((r, k) => <li key={k}>{reasonText(t, r, lang)}</li>)}
                          </ul>
                        )}
                        {i.uplinkIface && (
                          <div className="mt-0.5 text-[11px] text-text-muted">
                            {i.fixedDown ? t('lineQuality.onBackup', { iface: i.uplinkIface }) : `${t('lineQuality.measuredUplink')} : ${i.uplinkIface}`}
                          </div>
                        )}
                      </td>
                      {/* The latest night's figures are the line's only when the fixed line carried them. */}
                      <td className={`${TD} text-right font-mono text-xs ${i.carrier === 'fixed' ? 'text-text-primary' : 'text-text-muted'}`}>
                        {i.rttAvgMs === null ? '—' : `${fmt(i.rttAvgMs, lang)} ms`}
                      </td>
                      <td className={`${TD} text-right font-mono text-xs ${i.carrier === 'fixed' ? 'text-text-primary' : 'text-text-muted'}`}>
                        {i.lossPct === null ? '—' : `${fmt(i.lossPct, lang)} %`}
                      </td>
                      <td className={`${TD} text-right font-mono text-xs text-text-primary`}>{i.reconnections ?? '—'}</td>
                      <td className={TD}>
                        <LineQualitySparkline
                          width={120}
                          height={28}
                          label={t('lineQuality.sparkline.label')}
                          points={i.trend.map((p) => ({ night: p.night, value: p.rttAvgMs, exceeded: p.exceeded }))}
                        />
                      </td>
                      <td className={`${TD} whitespace-nowrap text-xs text-text-secondary`}>{nightLabel(i.lastNight, lang)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
