import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, RotateCw } from 'lucide-react';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import {
  fleetAnomaliesApi,
  type AnomalyDeviceRef,
  type FleetAnomaliesReport,
} from '@/api/fleetAnomalies.api';

/**
 * Fleet anomalies ("Anomalies du parc") — a read-only audit computed on every
 * load from what ObliWAN already stores (server:
 * services/fleet/fleetAnomalies.service.ts). Nothing on this page dials a
 * router or changes anything: each section names what to look at, and fixing
 * it goes through the usual screens.
 */

const TH = 'px-3 py-2 font-medium';
const TD = 'px-3 py-2 align-top';

function relative(iso: string | null, lang: string): string {
  if (!iso) return '—';
  const sec = Math.round((new Date(iso).getTime() - Date.now()) / 1000);
  const rtf = new Intl.RelativeTimeFormat(lang, { numeric: 'auto' });
  const abs = Math.abs(sec);
  if (abs < 3600) return rtf.format(Math.round(sec / 60), 'minute');
  if (abs < 86400) return rtf.format(Math.round(sec / 3600), 'hour');
  return rtf.format(Math.round(sec / 86400), 'day');
}

function Flag({ tone, children }: { tone: 'warn' | 'down' | 'muted'; children: ReactNode }) {
  const cls =
    tone === 'down'
      ? 'bg-status-down-bg text-status-down'
      : tone === 'warn'
        ? 'bg-status-pending-bg text-status-pending'
        : 'bg-bg-tertiary text-text-muted';
  return <span className={`ml-1.5 inline-block rounded px-1.5 py-0.5 text-[10px] font-medium ${cls}`}>{children}</span>;
}

function Section({ title, hint, count, children }: { title: string; hint: string; count: number | null; children: ReactNode }) {
  return (
    <section className="mb-6 rounded-lg border border-border bg-bg-secondary">
      <header className="border-b border-border px-4 py-3">
        <h2 className="flex items-center gap-2 text-sm font-semibold text-text-primary">
          {title}
          {count !== null && (
            <span className={`rounded-full px-2 py-0.5 text-xs ${count > 0 ? 'bg-status-pending-bg text-status-pending' : 'bg-status-up-bg text-status-up'}`}>
              {count}
            </span>
          )}
        </h2>
        <p className="mt-1 text-xs text-text-muted">{hint}</p>
      </header>
      <div className="overflow-x-auto">{children}</div>
    </section>
  );
}

export function FleetAnomaliesPage() {
  const { t, i18n } = useTranslation();
  const [report, setReport] = useState<FleetAnomaliesReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setReport(await fleetAnomaliesApi.get());
    } catch (err) {
      const e = err as { response?: { data?: { error?: string } }; message?: string };
      setError(e.response?.data?.error ?? e.message ?? 'error');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const all = report?.scope === 'all';
  const dev = (d: AnomalyDeviceRef | null, fallback?: string) =>
    d ? (
      <span>
        <Link to={`/devices/${d.id}`} className="text-accent hover:underline">{d.name}</Link>
        {d.siteCode && <span className="ml-1.5 font-mono text-[10px] text-text-muted">{d.siteCode}</span>}
        {all && <span className="ml-1.5 text-[10px] text-text-muted">{d.tenantName}</span>}
      </span>
    ) : (
      <span className="italic text-text-muted">{fallback ?? t('fleetAnomalies.noDevice')}</span>
    );
  const empty = (key: string) => <p className="px-4 py-6 text-center text-sm text-text-secondary">{t(key)}</p>;

  return (
    <div className="p-6">
      <div className="mb-2 flex items-center justify-between">
        <h1 className="flex items-center gap-2 text-2xl font-semibold text-text-primary">
          <AlertTriangle size={22} /> {t('fleetAnomalies.title')}
        </h1>
        <Button size="sm" variant="secondary" onClick={() => void load()} disabled={loading}>
          <RotateCw size={14} className="mr-1.5" />{t('common.refresh')}
        </Button>
      </div>
      <p className="mb-5 text-xs text-text-muted">
        {t('fleetAnomalies.hint')}
        {report && (
          <span className="ml-2">
            · {t(all ? 'fleetAnomalies.scopeAll' : 'fleetAnomalies.scopeTenant')}
            {' · '}{t('fleetAnomalies.generatedAt', { when: new Date(report.generatedAt).toLocaleString() })}
          </span>
        )}
      </p>

      {loading && !report ? <LoadingSpinner /> : error ? (
        <div className="rounded-lg border border-border bg-status-down-bg px-4 py-3 text-sm text-status-down">
          {t('fleetAnomalies.loadError')} — {error}
        </div>
      ) : report && (
        <>
          {/* (a) duplicate PPP logins */}
          <Section title={t('fleetAnomalies.dup.title')} hint={t('fleetAnomalies.dup.hint')} count={report.duplicateLogins.length}>
            {report.duplicateLogins.length === 0 ? empty('fleetAnomalies.dup.none') : (
              <table className="w-full text-sm">
                <thead className="border-b border-border text-left text-xs uppercase tracking-wide text-text-muted">
                  <tr>
                    <th className={TH}>{t('fleetAnomalies.col.login')}</th>
                    <th className={TH}>{t('fleetAnomalies.col.router')}</th>
                    <th className={TH}>{t('fleetAnomalies.col.signal')}</th>
                    <th className={TH}>{t('fleetAnomalies.col.openSessions')}</th>
                    <th className={TH}>{t('fleetAnomalies.col.startsLastHour')}</th>
                    <th className={TH}>{t('fleetAnomalies.col.callerIps')}</th>
                    <th className={TH}>{t('fleetAnomalies.col.lastStart')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {report.duplicateLogins.map((d) => (
                    <tr key={d.pppUsername}>
                      <td className={`${TD} font-mono text-xs`}>{d.pppUsername}</td>
                      <td className={TD}>{dev(d.device, t('fleetAnomalies.unboundLogin'))}</td>
                      <td className={TD}>
                        {(d.reason === 'concurrent' || d.reason === 'both') && <Flag tone="down">{t('fleetAnomalies.dup.concurrent')}</Flag>}
                        {(d.reason === 'churn' || d.reason === 'both') && <Flag tone="warn">{t('fleetAnomalies.dup.churn')}</Flag>}
                      </td>
                      <td className={`${TD} font-mono text-xs`}>{d.openSessions}</td>
                      <td className={`${TD} font-mono text-xs`}>{d.startsLastHour}</td>
                      <td className={`${TD} font-mono text-xs`}>
                        {d.callerIps === null
                          ? t('fleetAnomalies.dup.callersCounted', { count: d.distinctCallersLastHour })
                          : d.callerIps.join(', ') || '—'}
                      </td>
                      <td className={`${TD} whitespace-nowrap text-xs text-text-muted`}>{relative(d.lastStartedAt, i18n.language)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Section>

          {/* (b) identity ≠ login */}
          <Section title={t('fleetAnomalies.identity.title')} hint={t('fleetAnomalies.identity.hint')} count={report.identityMismatches.length}>
            {report.identityMismatches.length === 0 ? empty('fleetAnomalies.identity.none') : (
              <table className="w-full text-sm">
                <thead className="border-b border-border text-left text-xs uppercase tracking-wide text-text-muted">
                  <tr>
                    <th className={TH}>{t('fleetAnomalies.col.router')}</th>
                    <th className={TH}>{t('fleetAnomalies.col.login')}</th>
                    <th className={TH}>{t('fleetAnomalies.col.identity')}</th>
                    <th className={TH}>{t('fleetAnomalies.col.siteFromLogin')}</th>
                    <th className={TH}>{t('fleetAnomalies.col.siteFromIdentity')}</th>
                    <th className={TH}>{t('fleetAnomalies.col.siteCode')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {report.identityMismatches.map((m) => (
                    <tr key={m.device.id}>
                      <td className={TD}>{dev(m.device)}</td>
                      <td className={`${TD} font-mono text-xs`}>{m.pppUsername}</td>
                      <td className={`${TD} font-mono text-xs`}>{m.systemIdentity}</td>
                      <td className={`${TD} font-mono text-xs`}>{m.loginSite}</td>
                      <td className={`${TD} font-mono text-xs`}>{m.identitySite}</td>
                      <td className={`${TD} text-xs text-text-secondary`}>
                        {m.siteCodeAgreesWith === null ? '—' : t(`fleetAnomalies.identity.agrees.${m.siteCodeAgreesWith}`)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Section>

          {/* (c) inventory */}
          <Section title={t('fleetAnomalies.inventory.title')} hint={t('fleetAnomalies.inventory.hint', { count: report.inventory.total })} count={null}>
            <div className="grid gap-0 md:grid-cols-2 md:divide-x md:divide-border">
              <table className="w-full text-sm">
                <thead className="border-b border-border text-left text-xs uppercase tracking-wide text-text-muted">
                  <tr>
                    <th className={TH}>{t('fleetAnomalies.col.model')}</th>
                    <th className={`${TH} text-right`}>{t('fleetAnomalies.col.count')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {report.inventory.models.map((m) => (
                    <tr key={`${m.brand}|${m.model ?? ''}`}>
                      <td className={TD}>
                        <span className="text-[10px] uppercase text-text-muted">{m.brand}</span>{' '}
                        {m.model ?? <span className="italic text-text-muted">{t('fleetAnomalies.unknown')}</span>}
                      </td>
                      <td className={`${TD} text-right font-mono text-xs`}>{m.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <table className="w-full text-sm">
                <thead className="border-b border-border text-left text-xs uppercase tracking-wide text-text-muted">
                  <tr>
                    <th className={TH}>{t('fleetAnomalies.col.version')}</th>
                    <th className={`${TH} text-right`}>{t('fleetAnomalies.col.count')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {report.inventory.versions.map((v) => (
                    <tr key={`${v.brand}|${v.osVersion ?? ''}`} className={v.oldest ? 'bg-status-pending-bg/40' : undefined}>
                      <td className={TD}>
                        <span className="text-[10px] uppercase text-text-muted">{v.brand}</span>{' '}
                        <span className="font-mono text-xs">{v.osVersion ?? <span className="italic text-text-muted">{t('fleetAnomalies.unknown')}</span>}</span>
                        {v.majorBehind && <Flag tone="down">{t('fleetAnomalies.inventory.majorBehind')}</Flag>}
                        {v.oldest && <Flag tone="warn">{t('fleetAnomalies.inventory.oldest')}</Flag>}
                      </td>
                      <td className={`${TD} text-right font-mono text-xs`}>{v.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Section>

          {/* (d) shared public IPs */}
          <Section title={t('fleetAnomalies.shared.title')} hint={t('fleetAnomalies.shared.hint')} count={report.sharedPublicIps.length}>
            {report.sharedPublicIps.length === 0 ? empty('fleetAnomalies.shared.none') : (
              <table className="w-full text-sm">
                <thead className="border-b border-border text-left text-xs uppercase tracking-wide text-text-muted">
                  <tr>
                    <th className={TH}>{t('fleetAnomalies.col.publicIp')}</th>
                    <th className={TH}>{t('fleetAnomalies.col.routers')}</th>
                    <th className={TH}>{t('fleetAnomalies.col.signal')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {report.sharedPublicIps.map((s) => (
                    <tr key={s.callerIp}>
                      <td className={`${TD} font-mono text-xs`}>{s.callerIp}</td>
                      <td className={TD}>
                        <ul className="space-y-0.5">
                          {s.routers.map((r) => (
                            <li key={r.pppUsername}>
                              {dev(r.device, t('fleetAnomalies.unboundLogin'))}
                              <span className="ml-1.5 font-mono text-[10px] text-text-muted">{r.pppUsername}</span>
                              {r.cellular && <Flag tone="muted">4G</Flag>}
                            </li>
                          ))}
                        </ul>
                      </td>
                      <td className={TD}>
                        {s.sameSite && <Flag tone="warn">{t('fleetAnomalies.shared.sameSite')}</Flag>}
                        {s.anyCellular && <Flag tone="muted">{t('fleetAnomalies.shared.cgnat')}</Flag>}
                        {!s.sameSite && !s.anyCellular && <span className="text-xs text-text-muted">{t('fleetAnomalies.shared.info')}</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Section>

          {/* (e) cellular right now */}
          {/* Counted: the UNEXPECTED ones only. A site declared 4G-only (migration
              076) is listed, flagged as expected, and is not an anomaly. */}
          <Section
            title={t('fleetAnomalies.cellular.title')}
            hint={t('fleetAnomalies.cellular.hint')}
            count={report.cellular.filter((c) => !c.expected).length}
          >
            {report.cellular.length === 0 ? empty('fleetAnomalies.cellular.none') : (
              <table className="w-full text-sm">
                <thead className="border-b border-border text-left text-xs uppercase tracking-wide text-text-muted">
                  <tr>
                    <th className={TH}>{t('fleetAnomalies.col.router')}</th>
                    <th className={TH}>{t('fleetAnomalies.col.interface')}</th>
                    <th className={TH}>{t('fleetAnomalies.col.since')}</th>
                    <th className={TH}>{t('fleetAnomalies.col.readAt')}</th>
                    <th className={TH}>{t('fleetAnomalies.col.session')}</th>
                    <th className={TH}>{t('fleetAnomalies.col.publicIp')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {report.cellular.map((c) => (
                    <tr key={c.device.id} className={c.expected ? 'opacity-70' : undefined}>
                      <td className={TD}>
                        {dev(c.device)}
                        {c.expected
                          ? <Flag tone="muted">{t('fleetAnomalies.cellular.expected')}</Flag>
                          : c.declaredUplink === 'fixed'
                            ? <Flag tone="warn">{t('fleetAnomalies.cellular.declaredFixed')}</Flag>
                            : null}
                      </td>
                      <td className={`${TD} font-mono text-xs`}>{c.iface}</td>
                      <td className={`${TD} whitespace-nowrap text-xs`}>
                        {c.since
                          ? <span title={new Date(c.since).toLocaleString()}>{relative(c.since, i18n.language)}</span>
                          : <span className="text-text-muted">{t('fleetAnomalies.unknown')}</span>}
                      </td>
                      <td className={`${TD} whitespace-nowrap text-xs text-text-muted`}>
                        <span title={new Date(c.observedAt).toLocaleString()}>{relative(c.observedAt, i18n.language)}</span>
                        {c.stale && <Flag tone="warn">{t('fleetAnomalies.cellular.stale')}</Flag>}
                      </td>
                      <td className={`${TD} whitespace-nowrap text-xs`}>
                        {c.online
                          ? <span title={c.sessionSince ? new Date(c.sessionSince).toLocaleString() : undefined}>
                              {t('fleetAnomalies.cellular.onlineSince', { when: relative(c.sessionSince, i18n.language) })}
                            </span>
                          : <Flag tone="down">{t('fleetAnomalies.cellular.offline')}</Flag>}
                      </td>
                      <td className={`${TD} font-mono text-xs`}>{c.callerIp ?? '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Section>
        </>
      )}
    </div>
  );
}
