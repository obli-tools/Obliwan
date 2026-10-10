import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { AlertTriangle, CaseLower, CheckCircle2, Loader2, MinusCircle, X } from 'lucide-react';
import type { SiteRenameBulkLaunchRow, SiteRenameBulkPreviewRow } from '@obliwan/shared';
import { Button } from '@/components/common/Button';
import { cn } from '@/utils/cn';
import { siteRenameApi, siteRenameErrorMessage } from '@/components/fleet/siteRename.api';

/**
 * « Tout en minuscules » on a Sites page selection: one `site_rename` change
 * job per site whose router login or identity (and, when asked, code) holds a
 * capital letter (the case of customer C). The server's preview comes first and
 * writes nothing: per site the router, the names from -> to, and the refusals
 * in the server's own sentences; « rien à renommer » for a site already in
 * lowercase. Launching asks for the no-dead-man confirmation, then lists what
 * each site got: its job (a link to the device page, where the rename card
 * follows it) or the refusal. Platform admins only (the job writes on the
 * shared CHR); the page opens the dialog for them alone, and the server
 * refuses anyone else anyway.
 */
export function SiteRenameBulkDialog({ siteIds, onClose }: { siteIds: number[]; onClose: () => void }) {
  const { t } = useTranslation();
  // The selection as it was when the dialog opened: the page may re-render
  // (and rebuild its array) while the operator reads the preview.
  const [ids] = useState(() => [...siteIds]);
  const [includeSiteCode, setIncludeSiteCode] = useState(false);
  const [rows, setRows] = useState<SiteRenameBulkPreviewRow[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [launching, setLaunching] = useState(false);
  const [launched, setLaunched] = useState<SiteRenameBulkLaunchRow[] | null>(null);

  const preview = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setRows(await siteRenameApi.previewBulk(ids, includeSiteCode));
    } catch (err) {
      setRows(null);
      setError(siteRenameErrorMessage(err, t('siteRename.bulk.previewError')));
    } finally {
      setLoading(false);
    }
  }, [ids, includeSiteCode, t]);

  useEffect(() => {
    void preview();
  }, [preview]);

  const renamable = (rows ?? []).filter((r) => !r.nothingToRename && r.refusals.length === 0);

  const launch = async () => {
    setLaunching(true);
    try {
      const out = await siteRenameApi.launchBulk(renamable.map((r) => r.siteId), includeSiteCode);
      setLaunched(out);
      setConfirming(false);
      const queued = out.filter((o) => o.jobId !== null).length;
      toast.success(t('siteRename.bulk.launched', { count: queued }));
    } catch (err) {
      toast.error(siteRenameErrorMessage(err, t('siteRename.bulk.launchError')));
    } finally {
      setLaunching(false);
    }
  };

  const pair = (from: string | null, to: string | null) =>
    from === to ? <span className="text-text-muted">{from ?? '—'}</span> : (
      <span>
        <span className="text-text-muted line-through">{from ?? '—'}</span>{' '}
        <span className="text-text-primary">{to ?? '—'}</span>
      </span>
    );
  const resultOf = (siteId: number) => launched?.find((l) => l.siteId === siteId) ?? null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4">
      <div className="my-8 w-full max-w-5xl rounded-xl border border-border bg-bg-secondary shadow-2xl">
        <div className="flex items-center gap-2 border-b border-border px-5 py-4">
          <CaseLower size={18} className="text-accent" />
          <h2 className="flex-1 text-base font-semibold text-text-primary">{t('siteRename.bulk.title')}</h2>
          <button
            type="button"
            onClick={onClose}
            className="rounded p-1 text-text-muted hover:text-text-primary"
            aria-label={t('siteRename.bulk.close')}
          >
            <X size={16} />
          </button>
        </div>

        <div className="space-y-4 p-5">
          <p className="text-sm text-text-muted">{t('siteRename.bulk.intro')}</p>
          <label className="flex items-center gap-2 text-sm text-text-secondary">
            <input
              type="checkbox"
              checked={includeSiteCode}
              disabled={loading || launching || launched !== null}
              onChange={(e) => setIncludeSiteCode(e.target.checked)}
            />
            {t('siteRename.bulk.includeSiteCode')}
          </label>

          {error && (
            <p className="flex items-center gap-1.5 text-sm text-status-down">
              <AlertTriangle size={14} /> {error}
            </p>
          )}
          {loading && (
            <p className="flex items-center gap-1.5 text-sm text-text-muted">
              <Loader2 size={14} className="animate-spin" /> {t('siteRename.bulk.preview')}
            </p>
          )}

          {rows && (
            <div className="overflow-x-auto rounded-md border border-border">
              <table className="w-full text-[12px]">
                <thead className="bg-bg-tertiary text-left text-[11px] uppercase tracking-wider text-text-muted">
                  <tr>
                    <th className="px-3 py-2">{t('siteRename.bulk.columns.site')}</th>
                    <th className="px-3 py-2">{t('siteRename.bulk.columns.router')}</th>
                    <th className="px-3 py-2">{t('siteRename.bulk.columns.login')}</th>
                    <th className="px-3 py-2">{t('siteRename.bulk.columns.identity')}</th>
                    <th className="px-3 py-2">{t('siteRename.bulk.columns.siteCode')}</th>
                    <th className="px-3 py-2">{t('siteRename.bulk.columns.result')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {rows.map((r) => {
                    const done = resultOf(r.siteId);
                    return (
                      <tr key={r.siteId} className={cn(r.refusals.length > 0 && 'bg-status-ssl-warning/5')}>
                        <td className="px-3 py-2 font-mono text-text-primary">{r.siteCode}</td>
                        <td className="px-3 py-2">
                          {r.deviceId !== null
                            ? <Link to={`/devices/${r.deviceId}`} className="text-accent hover:underline">{r.deviceName ?? `#${r.deviceId}`}</Link>
                            : <span className="text-text-muted">—</span>}
                        </td>
                        <td className="px-3 py-2 font-mono">{pair(r.from.login, r.to.login)}</td>
                        <td className="px-3 py-2 font-mono">{pair(r.from.identity, r.to.identity)}</td>
                        <td className="px-3 py-2 font-mono">{pair(r.from.siteCode, r.to.siteCode)}</td>
                        <td className="px-3 py-2">
                          {done ? (
                            done.jobId !== null ? (
                              <span className="inline-flex items-center gap-1 text-status-up">
                                <CheckCircle2 size={13} />
                                <Link to={`/devices/${done.deviceId}`} className="hover:underline">
                                  {t(done.alreadyQueued ? 'siteRename.bulk.alreadyQueued' : 'siteRename.bulk.queuedJob', { id: done.jobId })}
                                </Link>
                              </span>
                            ) : (
                              <span className="text-status-ssl-warning">{done.refusal?.message ?? t('siteRename.bulk.refused')}</span>
                            )
                          ) : r.nothingToRename ? (
                            <span className="inline-flex items-center gap-1 text-text-muted">
                              <MinusCircle size={13} /> {t('siteRename.bulk.nothingToRename')}
                            </span>
                          ) : r.refusals.length > 0 ? (
                            <ul className="space-y-0.5 text-status-ssl-warning">
                              {r.refusals.map((x) => <li key={x.kind}>{x.message}</li>)}
                            </ul>
                          ) : (
                            <span className="text-text-secondary">{t('siteRename.bulk.willRename')}</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {rows && launched === null && (
            confirming ? (
              <div className="rounded-md border border-status-ssl-warning/50 bg-status-ssl-warning/5 p-3">
                <p className="mb-2 text-[12px] text-text-secondary">{t('siteRename.bulk.confirmText', { count: renamable.length })}</p>
                <div className="flex gap-2">
                  <Button size="sm" variant="danger" loading={launching} disabled={launching || renamable.length === 0} onClick={() => void launch()}>
                    {t('siteRename.confirm')}
                  </Button>
                  <Button size="sm" variant="secondary" disabled={launching} onClick={() => setConfirming(false)}>{t('common.cancel')}</Button>
                </div>
              </div>
            ) : (
              <div className="flex gap-2">
                <Button size="sm" disabled={renamable.length === 0 || loading} onClick={() => setConfirming(true)}>
                  <CaseLower size={14} className="mr-1.5" /> {t('siteRename.bulk.launch', { count: renamable.length })}
                </Button>
                <Button size="sm" variant="secondary" onClick={onClose}>{t('common.cancel')}</Button>
              </div>
            )
          )}
          {launched !== null && (
            <div className="flex gap-2">
              <Button size="sm" variant="secondary" onClick={onClose}>{t('siteRename.bulk.close')}</Button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
