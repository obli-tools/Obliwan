import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { ChevronDown, ChevronRight, Database, DownloadCloud, RefreshCw } from 'lucide-react';
import type { ExtrapolationReadiness, TenantCollectState } from '@obliwan/shared';
import { configApi } from '@/api/config.api';
import { errorMessageOf } from '@/api/change.api';
import { useAuthStore } from '@/store/authStore';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { anonHostname } from '@/utils/anonymize';
import { cn } from '@/utils/cn';

/**
 * « Configurations du client » — which of the client's MikroTik routers the
 * extrapolator can actually read, per router model, and for every other one
 * WHY not (not active, a family the collector does not read, no SSH channel,
 * no snapshot — with the collector's own error — or no raw export kept).
 *
 * The extrapolator only ever proposes from what this card counts as usable: a
 * proposal over 4 routers of a 12-router model is explained here, not
 * discovered later.
 *
 * « Collecter les configs du client » (platform administrators only) re-reads
 * every collectable router of the client through the collector's own door —
 * read-only, without the secrets, two routers at once, the unreachable ones
 * skipped. Its progress is polled every 2.5 s and the card reloads at the end.
 */
export function ReadinessCard({
  readiness,
  loading,
  onReload,
  onCollectRunning,
  dateFmt,
}: {
  readiness: ExtrapolationReadiness | null;
  loading: boolean;
  onReload: () => void;
  /** Told when a bulk collect starts and ends (the panel holds its start). */
  onCollectRunning?: (running: boolean) => void;
  dateFmt: Intl.DateTimeFormat;
}) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const { isAdmin } = useAuthStore();
  const [collect, setCollect] = useState<TenantCollectState | null>(null);
  const [startingCollect, setStartingCollect] = useState(false);
  const [resultsOpen, setResultsOpen] = useState(false);
  const running = collect?.running === true;

  useEffect(() => { setCollect(readiness?.collect ?? null); }, [readiness]);
  useEffect(() => { onCollectRunning?.(running); }, [running, onCollectRunning]);

  // While a collection runs, its progress is polled; at the end the card
  // reloads (the reasons and counts changed).
  useEffect(() => {
    if (!running) return;
    const timer = window.setInterval(() => {
      void (async () => {
        try {
          const s = await configApi.tenantCollect();
          setCollect(s);
          if (!s || !s.running) onReload();
        } catch {
          /* the next tick asks again */
        }
      })();
    }, 2500);
    return () => window.clearInterval(timer);
  }, [running, onReload]);

  const startCollect = async (): Promise<void> => {
    setStartingCollect(true);
    try {
      setCollect(await configApi.startTenantCollect());
    } catch (err) {
      toast.error(errorMessageOf(err) ?? t('baseline.extrapolator.loadFailed'));
    } finally {
      setStartingCollect(false);
    }
  };
  const count = (o: string) => (collect?.results ?? []).filter((r) => r.outcome === o).length;
  // Failures and skips first: they are what an operator acts on.
  const ORDER: Record<string, number> = { failed: 0, skipped: 1, created: 2, unchanged: 3 };
  const results = [...(collect?.results ?? [])].sort((a, b) => (ORDER[a.outcome] ?? 9) - (ORDER[b.outcome] ?? 9));

  return (
    <section className="rounded-lg border border-border bg-bg-secondary p-3">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="flex items-center gap-1.5 text-sm font-semibold text-text-primary">
          <Database size={14} className="text-accent" />
          {t('baseline.extrapolator.readiness.title')}
        </h2>
        {readiness && (
          <span className="text-[12px] text-text-muted">
            {t('baseline.extrapolator.readiness.summary', {
              usable: readiness.totals.usable,
              total: readiness.totals.mikrotik,
              blocked: readiness.totals.blocked,
            })}
          </span>
        )}
        <span className="ml-auto flex items-center gap-2">
          {isAdmin() ? (
            <Button
              variant="secondary" size="sm" loading={startingCollect} disabled={running}
              onClick={() => void startCollect()}
              title={t('baseline.extrapolator.collect.adminOnly')}
            >
              <DownloadCloud size={13} className="mr-1.5" />
              {t('baseline.extrapolator.collect.button')}
            </Button>
          ) : (
            <span className="text-[11px] text-text-muted">{t('baseline.extrapolator.collect.adminOnly')}</span>
          )}
          <Button variant="ghost" size="sm" loading={loading} onClick={onReload}>
            <RefreshCw size={13} />
          </Button>
        </span>
      </div>

      {collect && (
        <div className="mt-2 rounded-md border border-border bg-bg-tertiary px-3 py-2">
          <div className="flex flex-wrap items-center gap-2 text-[12px] text-text-secondary">
            {running
              ? t('baseline.extrapolator.collect.running', { done: collect.done, total: collect.total })
              : t('baseline.extrapolator.collect.done', {
                created: count('created'), unchanged: count('unchanged'), failed: count('failed'), skipped: count('skipped'),
              })}
            {collect.deferred > 0 && (
              <span className="text-status-ssl-warning">
                {t('baseline.extrapolator.collect.deferred', { count: collect.deferred })}
              </span>
            )}
            {results.length > 0 && (
              <button
                onClick={() => setResultsOpen((v) => !v)}
                className="ml-auto flex items-center gap-1 text-[11px] text-text-muted hover:text-text-primary"
              >
                {resultsOpen ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                {results.length}
              </button>
            )}
          </div>
          <div className="mt-1.5 h-1.5 overflow-hidden rounded bg-bg-secondary">
            <div
              className={cn('h-full', running ? 'bg-accent' : 'bg-status-up')}
              style={{ width: `${collect.total > 0 ? Math.round((collect.done / collect.total) * 100) : 100}%` }}
            />
          </div>
          {resultsOpen && (
            <ul className="mt-2 max-h-56 space-y-0.5 overflow-y-auto text-[11px]">
              {results.map((r) => (
                <li key={r.deviceId} className="flex flex-wrap gap-x-2">
                  <span className="text-text-primary">{anonHostname(r.deviceName)}</span>
                  <span
                    className={cn(
                      r.outcome === 'failed' ? 'text-status-ssl-expired'
                        : r.outcome === 'skipped' ? 'text-status-ssl-warning' : 'text-status-up',
                    )}
                  >
                    {t(`baseline.extrapolator.collect.outcome.${r.outcome}`)}
                  </span>
                  {r.reason && <span className="font-mono text-text-muted">{r.reason}</span>}
                  {r.message && <span className="w-full font-mono text-[10px] text-text-muted">{r.message}</span>}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {readiness === null ? (
        loading ? <div className="flex justify-center py-4"><LoadingSpinner /></div> : null
      ) : (
        <>
          {readiness.models.length > 0 && (
            <ul className="mt-2 flex flex-wrap gap-2">
              {readiness.models.map((m) => {
                const label = m.model === null ? t('baseline.extrapolator.readiness.modelUnknown') : m.label;
                const tone = m.usable === m.devices
                  ? 'border-status-up/50 bg-status-up/10 text-status-up'
                  : m.usable === 0
                    ? 'border-status-ssl-expired/50 bg-status-ssl-expired/10 text-status-ssl-expired'
                    : 'border-status-ssl-warning/50 bg-status-ssl-warning/10 text-status-ssl-warning';
                return (
                  <li
                    key={m.model ?? '\u0000'}
                    className={cn('rounded-md border px-2.5 py-1.5 text-[12px]', tone)}
                    title={m.newestSnapshotAt
                      ? `${m.oldestSnapshotAt ? dateFmt.format(new Date(m.oldestSnapshotAt)) : '—'} → ${dateFmt.format(new Date(m.newestSnapshotAt))}`
                      : undefined}
                  >
                    <span className="font-medium">
                      {t('baseline.extrapolator.readiness.model', { label, usable: m.usable, devices: m.devices })}
                    </span>
                    {m.stale > 0 && (
                      <span className="ml-1.5 text-[11px] text-text-muted">
                        {t('baseline.extrapolator.readiness.stale', { count: m.stale })}
                      </span>
                    )}
                  </li>
                );
              })}
            </ul>
          )}

          {readiness.blocked.length > 0 && (
            <div className="mt-2">
              <button
                onClick={() => setOpen((v) => !v)}
                className="flex items-center gap-1 text-[12px] text-text-secondary hover:text-text-primary"
              >
                {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                {t('baseline.extrapolator.readiness.blockedTitle', { count: readiness.blocked.length })}
              </button>
              {open && (
                <div className="mt-1 max-h-72 overflow-y-auto rounded-md border border-border">
                  <table className="w-full text-left text-[12px]">
                    <tbody className="divide-y divide-border">
                      {readiness.blocked.map((b) => (
                        <tr key={b.deviceId}>
                          <td className="px-2 py-1 text-text-primary">{anonHostname(b.deviceName)}</td>
                          <td className="px-2 py-1 font-mono text-[11px] text-text-muted">{b.siteCode ?? '—'}</td>
                          <td className="px-2 py-1 text-[11px] text-text-muted">
                            {b.model ?? t('baseline.extrapolator.readiness.modelUnknown')}
                          </td>
                          <td className="px-2 py-1 text-text-secondary">
                            {t(`baseline.extrapolator.readiness.reason.${b.reason}`)}
                            {b.detail && (
                              <span className="mt-0.5 block font-mono text-[10px] text-status-ssl-expired">{b.detail}</span>
                            )}
                          </td>
                          <td className="px-2 py-1 font-mono text-[10px] text-text-muted">
                            {b.lastFailedAt ? dateFmt.format(new Date(b.lastFailedAt)) : ''}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </section>
  );
}
