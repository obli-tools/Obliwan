import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { Network, RefreshCw } from 'lucide-react';
import type { InfraConcentratorView, InfraSiteAccountView } from '@obliwan/shared';
import { Button } from '@/components/common/Button';
import { cn } from '@/utils/cn';
import { infraConcentratorApi, infraErrorOf } from '@/api/infraConcentrator.api';

/**
 * The site's account on each infrastructure concentrator of its tenant —
 * read-only state, plus, for a RouterOS CHR, one button that queues an
 * `infra_account` job (create the account, or find it present and say so).
 * Platform admin only (the API is). An OPNsense shows its state but offers no
 * button: its writes are not implemented yet.
 */

const STATE_STYLE: Record<string, string> = {
  provisioned: 'text-status-up',
  planned: 'text-status-pending',
  revoked: 'text-text-muted',
  error: 'text-status-down',
};

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export function SiteInfraBlock({ siteId, tenantId }: { siteId: number; tenantId: number }) {
  const { t } = useTranslation();
  const [concentrators, setConcentrators] = useState<InfraConcentratorView[]>([]);
  const [accounts, setAccounts] = useState<InfraSiteAccountView[]>([]);
  const [busy, setBusy] = useState<number | null>(null);
  const [loaded, setLoaded] = useState(false);

  const load = useCallback(async () => {
    try {
      const [cs, as] = await Promise.all([
        infraConcentratorApi.list(tenantId),
        infraConcentratorApi.siteAccounts(tenantId, siteId),
      ]);
      setConcentrators(cs);
      setAccounts(as);
    } catch {
      setConcentrators([]);
      setAccounts([]);
    } finally {
      setLoaded(true);
    }
  }, [siteId, tenantId]);

  useEffect(() => {
    void load();
  }, [load]);

  const ensure = async (c: InfraConcentratorView) => {
    setBusy(c.id);
    try {
      const queued = await infraConcentratorApi.enqueue(c.id, siteId, 'ensure');
      let state = queued;
      const deadline = Date.now() + 60_000;
      while (state.state === 'pending' && state.jobId !== null && Date.now() < deadline) {
        await sleep(1500);
        state = await infraConcentratorApi.job(state.jobId);
      }
      if (state.state === 'succeeded') toast.success(state.message);
      else if (state.state === 'failed') toast.error(state.message);
      else toast(t('infraConcentrator.site.stillRunning', { id: state.jobId }));
      await load();
    } catch (err) {
      toast.error(infraErrorOf(err) ?? t('infraConcentrator.site.failed'));
    } finally {
      setBusy(null);
    }
  };

  if (loaded && concentrators.length === 0) return null;

  return (
    <section className="rounded-lg border border-border bg-bg-secondary p-4">
      <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-text-secondary">
        <Network size={14} />
        <span className="flex-1">{t('infraConcentrator.site.title')}</span>
        <button type="button" onClick={() => void load()} className="rounded p-1 text-text-muted hover:text-text-primary" aria-label={t('common.refresh')}>
          <RefreshCw size={13} />
        </button>
      </h2>
      <ul className="space-y-3">
        {concentrators.map((c) => {
          const a = accounts.find((x) => x.concentratorId === c.id);
          return (
            <li key={c.id} className="rounded-md border border-border bg-bg-tertiary px-3 py-2">
              <div className="flex items-center gap-2">
                <span className="flex-1 text-sm text-text-primary">
                  {c.name} <span className="text-xs text-text-muted">· {t(`infraConcentrator.kinds.${c.kind}`)}</span>
                </span>
                <span className={cn('text-xs font-medium', a ? STATE_STYLE[a.state] : 'text-text-muted')}>
                  {a ? t(`infraConcentrator.states.${a.state}`) : t('infraConcentrator.site.noAccount')}
                </span>
              </div>
              {a && (
                <div className="mt-1 space-y-0.5 font-mono text-[11px] text-text-muted">
                  <div>{t('infraConcentrator.site.identifier')}: {a.identifier}</div>
                  {a.observedAt && <div>{t('infraConcentrator.site.observedAt')}: {new Date(a.observedAt).toLocaleString()}</div>}
                  {a.lastJobId !== null && <div>{t('infraConcentrator.site.lastJob')}: #{a.lastJobId} ({a.lastJobStatus ?? '?'})</div>}
                </div>
              )}
              {a?.detail && <p className="mt-1 text-xs text-text-secondary">{a.detail}</p>}
              {c.kind === 'routeros_chr' ? (
                <div className="mt-2 flex justify-end">
                  <Button size="sm" variant="secondary" disabled={busy !== null || !c.enabled} onClick={() => void ensure(c)}>
                    {busy === c.id ? t('infraConcentrator.site.running') : t('infraConcentrator.site.ensure')}
                  </Button>
                </div>
              ) : (
                <p className="mt-1 text-[11px] italic text-text-muted">{t('infraConcentrator.site.opnsenseLater')}</p>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
