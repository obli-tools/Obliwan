import { Fragment, useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, EyeOff, Link2, RefreshCw, RotateCcw } from 'lucide-react';
import toast from 'react-hot-toast';
import { errorMessageOf } from '@/api/sim.api';
import { simReconcileApi, type SimLinkConflict, type SimLinkConflictKind } from '@/api/simReconcile.api';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { EmptyState, Panel, When } from '@/components/mobile/SimBits';
import { cn } from '@/utils/cn';

/**
 * « Conflits » on the SIM reconciliation (migration 080): a card read in a
 * router's modem matches a line the automatic link must NOT take on its own —
 * another customer's line, a line already linked to another router, or a card
 * read in several routers. Nothing was moved; this block is where a platform
 * operator decides.
 *
 * ┌─ TWO DECISIONS, BOTH CONFIRMED IN THE ROW, BOTH AUDITED ─────────────────┐
 * │ ASSIGN moves the line to the router that read its card: that router's     │
 * │ workspace, that router, its site. On a change of workspace the line's     │
 * │ open top-up proposals are closed and the new owner does not see the      │
 * │ previous one's consumption — the confirmation says so BEFORE the click,  │
 * │ because that is the part nobody can take back by moving the line again.  │
 * │ The server re-checks that the card is still in that router (409 if not). │
 * │ DISMISS moves nothing; the conflict comes back by itself if the router    │
 * │ later reads something different.                                          │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

const KIND_CLASS: Record<SimLinkConflictKind, string> = {
  other_tenant: 'bg-status-down/10 text-status-down border-status-down/30',
  linked_elsewhere: 'bg-status-ssl-warning/15 text-status-ssl-warning border-status-ssl-warning/30',
  ambiguous: 'bg-accent/10 text-accent border-accent/30',
};

type Pending = { id: number; action: 'assign' | 'dismiss' } | null;

export function SimLinkConflicts() {
  const { t } = useTranslation();
  const [rows, setRows] = useState<SimLinkConflict[]>([]);
  const [loading, setLoading] = useState(true);
  const [showDismissed, setShowDismissed] = useState(false);
  const [pending, setPending] = useState<Pending>(null);
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setRows(await simReconcileApi.conflicts(showDismissed));
    } catch (err) {
      toast.error(errorMessageOf(err));
    } finally {
      setLoading(false);
    }
  }, [showDismissed]);

  useEffect(() => {
    void load();
  }, [load]);

  const open = rows.filter((r) => r.dismissedAt === null).length;

  const ask = (id: number, action: 'assign' | 'dismiss') => {
    setNote('');
    setPending((p) => (p && p.id === id && p.action === action ? null : { id, action }));
  };

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    try {
      await fn();
      setPending(null);
      await load();
    } catch (err) {
      toast.error(errorMessageOf(err));
      // A 409 means the router no longer reads the card: show what is true now.
      await load();
    } finally {
      setBusy(false);
    }
  };

  const assign = (c: SimLinkConflict) =>
    run(async () => {
      const r = await simReconcileApi.assignConflict(c.id);
      toast.success(
        r.movedTenant
          ? t('simReconcile.conflicts.assignedMoved', { msisdn: c.line.msisdn, router: c.router.name, tenant: c.router.tenantName ?? '' })
          : t('simReconcile.conflicts.assigned', { msisdn: c.line.msisdn, router: c.router.name }),
      );
    });

  const dismiss = (c: SimLinkConflict) =>
    run(async () => {
      await simReconcileApi.dismissConflict(c.id, note.trim() === '' ? null : note.trim());
      toast.success(t('simReconcile.conflicts.dismissedToast'));
    });

  const reopen = (c: SimLinkConflict) =>
    run(async () => {
      await simReconcileApi.reopenConflict(c.id);
      toast.success(t('simReconcile.conflicts.reopenedToast'));
    });

  /** What ASSIGN will do to this line, said before the click. */
  const consequence = (c: SimLinkConflict): string[] => {
    const out: string[] = [];
    const moving = c.line.tenantId !== c.router.tenantId;
    if (moving) {
      out.push(
        t('simReconcile.conflicts.willMove', {
          from: c.line.tenantName ?? t('simReconcile.conflicts.pool'),
          to: c.router.tenantName ?? `#${c.router.tenantId}`,
        }),
      );
      out.push(t('simReconcile.conflicts.willSettle'));
    }
    if (c.line.deviceId !== null && c.line.deviceId !== c.router.id) {
      out.push(t('simReconcile.conflicts.willUnlink', { router: c.line.deviceName ?? `#${c.line.deviceId}` }));
    }
    out.push(
      c.router.siteName
        ? t('simReconcile.conflicts.willSite', { site: c.router.siteName })
        : moving
          ? t('simReconcile.conflicts.willNoSite')
          : t('simReconcile.conflicts.willKeepSite'),
    );
    if (c.otherRouters.length > 0) out.push(t('simReconcile.conflicts.willReevaluate', { count: c.otherRouters.length }));
    return out;
  };

  return (
    <Panel
      title={
        <span className="inline-flex items-center gap-2">
          <AlertTriangle size={14} className={open > 0 ? 'text-status-ssl-warning' : 'text-text-muted'} />
          {t('simReconcile.conflicts.title')}
          {open > 0 ? (
            <span className="rounded-full border border-status-ssl-warning/30 bg-status-ssl-warning/15 px-2 py-0.5 text-[11px] text-status-ssl-warning">
              {open}
            </span>
          ) : null}
        </span>
      }
      action={
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-1.5 text-xs text-text-secondary">
            <input type="checkbox" checked={showDismissed} onChange={(e) => setShowDismissed(e.target.checked)} />
            {t('simReconcile.conflicts.showDismissed')}
          </label>
          <Button variant="ghost" size="sm" onClick={() => void load()} disabled={loading}>
            <RefreshCw size={14} />
          </Button>
        </div>
      }
    >
      <p className="border-b border-border px-4 py-2 text-[12px] text-text-secondary">{t('simReconcile.conflicts.intro')}</p>
      {loading ? (
        <div className="flex h-24 items-center justify-center">
          <LoadingSpinner />
        </div>
      ) : rows.length === 0 ? (
        <EmptyState message={t(showDismissed ? 'simReconcile.conflicts.emptyAll' : 'simReconcile.conflicts.empty')} />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-[13px]">
            <thead className="text-left text-xs text-text-muted">
              <tr className="border-b border-border">
                <th className="px-3 py-2 font-medium">{t('simReconcile.conflicts.colKind')}</th>
                <th className="px-3 py-2 font-medium">{t('simReconcile.conflicts.colCard')}</th>
                <th className="px-3 py-2 font-medium">{t('simReconcile.conflicts.colRouter')}</th>
                <th className="px-3 py-2 font-medium">{t('simReconcile.conflicts.colLine')}</th>
                <th className="px-3 py-2 font-medium">{t('simReconcile.conflicts.colSeen')}</th>
                <th className="px-3 py-2" />
              </tr>
            </thead>
            <tbody>
              {rows.map((c) => {
                const isPending = pending?.id === c.id;
                const dismissed = c.dismissedAt !== null;
                return (
                  <Fragment key={c.id}>
                    <tr className={cn('border-t border-border align-top', dismissed && 'opacity-70')}>
                      <td className="px-3 py-2">
                        <span
                          className={cn(
                            'inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium',
                            KIND_CLASS[c.kind],
                          )}
                        >
                          {t(`simReconcile.conflicts.kind.${c.kind}`)}
                        </span>
                        <div className="mt-1 max-w-[220px] text-[11px] text-text-muted">
                          {t(`simReconcile.conflicts.kindHint.${c.kind}`)}
                        </div>
                      </td>
                      <td className="px-3 py-2">
                        <span className="font-mono">{c.iccidRead}</span>
                        {c.prefixMatch ? (
                          <div className="text-[11px] text-status-ssl-warning">
                            {t('simReconcile.conflicts.prefixMatch', { iccid: c.line.iccid ?? '—' })}
                          </div>
                        ) : null}
                      </td>
                      <td className="px-3 py-2">
                        <Link to={`/devices/${c.router.id}`} className="text-text-primary hover:text-accent">
                          {c.router.name}
                        </Link>
                        <div className="text-[11px] text-text-muted">
                          {c.router.tenantName ?? `#${c.router.tenantId}`}
                          {' · '}
                          {c.router.siteName ?? t('mobile.noSite')}
                        </div>
                        {c.otherRouters.length > 0 ? (
                          <div className="mt-1 text-[11px] text-text-secondary">
                            {t('simReconcile.conflicts.alsoReadIn')}{' '}
                            {c.otherRouters.map((o, i) => (
                              <span key={o.id}>
                                {i > 0 ? ', ' : ''}
                                <Link to={`/devices/${o.id}`} className="hover:text-accent">
                                  {o.name}
                                </Link>
                                <span className="text-text-muted"> ({o.tenantName ?? `#${o.tenantId}`})</span>
                              </span>
                            ))}
                          </div>
                        ) : null}
                      </td>
                      <td className="px-3 py-2">
                        <Link to={`/mobile/lines/${c.line.id}`} className="font-mono text-text-primary hover:text-accent">
                          {c.line.msisdn}
                        </Link>
                        {c.line.label ? <span className="ml-2 text-xs text-text-muted">{c.line.label}</span> : null}
                        <div className="text-[11px] text-text-muted">
                          {c.line.tenantId === null
                            ? t('simReconcile.conflicts.pool')
                            : `${c.line.tenantName ?? `#${c.line.tenantId}`} · ${c.line.siteName ?? t('mobile.noSite')}`}
                        </div>
                        <div className="text-[11px] text-text-secondary">
                          {c.line.deviceId !== null ? (
                            <>
                              {t('simReconcile.conflicts.linkedTo')}{' '}
                              <Link to={`/devices/${c.line.deviceId}`} className="hover:text-accent">
                                {c.line.deviceName ?? `#${c.line.deviceId}`}
                              </Link>
                            </>
                          ) : (
                            <span className="text-text-muted">{t('simReconcile.conflicts.noRouter')}</span>
                          )}
                        </div>
                      </td>
                      <td className="px-3 py-2 text-xs">
                        <When iso={c.lastSeenAt} />
                        <div className="text-[11px] text-text-muted">
                          {t('simReconcile.conflicts.since')} <When iso={c.detectedAt} />
                        </div>
                      </td>
                      <td className="px-3 py-2 text-right">
                        {dismissed ? (
                          <div className="flex flex-col items-end gap-1">
                            <span className="text-[11px] text-text-muted">
                              {t('simReconcile.conflicts.dismissedBy', { who: c.dismissedByName ?? '—' })}{' '}
                              <When iso={c.dismissedAt} />
                            </span>
                            {c.dismissedNote ? (
                              <span className="max-w-[260px] text-[11px] italic text-text-secondary">« {c.dismissedNote} »</span>
                            ) : null}
                            <Button variant="ghost" size="sm" disabled={busy} onClick={() => void reopen(c)}>
                              <RotateCcw size={13} className="mr-1" />
                              {t('simReconcile.conflicts.reopen')}
                            </Button>
                          </div>
                        ) : (
                          <div className="flex flex-wrap justify-end gap-1">
                            <Button
                              variant={isPending && pending?.action === 'assign' ? 'primary' : 'secondary'}
                              size="sm"
                              disabled={busy}
                              onClick={() => ask(c.id, 'assign')}
                            >
                              <Link2 size={13} className="mr-1" />
                              {t('simReconcile.conflicts.assign')}
                            </Button>
                            <Button variant="ghost" size="sm" disabled={busy} onClick={() => ask(c.id, 'dismiss')}>
                              <EyeOff size={13} className="mr-1" />
                              {t('simReconcile.conflicts.dismiss')}
                            </Button>
                          </div>
                        )}
                      </td>
                    </tr>
                    {isPending && !dismissed ? (
                      <tr className="bg-bg-tertiary/40">
                        <td colSpan={6} className="px-3 py-3">
                          {pending?.action === 'assign' ? (
                            <div className="flex flex-wrap items-start justify-between gap-3">
                              <div className="text-[12px] text-text-secondary">
                                <div className="mb-1 font-medium text-text-primary">
                                  {t('simReconcile.conflicts.confirmAssign', { msisdn: c.line.msisdn, router: c.router.name })}
                                </div>
                                <ul className="list-disc space-y-0.5 pl-5">
                                  {consequence(c).map((s) => (
                                    <li key={s}>{s}</li>
                                  ))}
                                  <li>{t('simReconcile.conflicts.willAudit')}</li>
                                </ul>
                              </div>
                              <div className="flex gap-2">
                                <Button variant="ghost" size="sm" disabled={busy} onClick={() => setPending(null)}>
                                  {t('common.cancel')}
                                </Button>
                                <Button size="sm" loading={busy} onClick={() => void assign(c)}>
                                  {t('simReconcile.conflicts.confirm')}
                                </Button>
                              </div>
                            </div>
                          ) : (
                            <div className="flex flex-wrap items-end gap-3">
                              <label className="min-w-[260px] flex-1">
                                <span className="mb-1 block text-xs text-text-secondary">
                                  {t('simReconcile.conflicts.dismissNote')}
                                </span>
                                <Input
                                  value={note}
                                  maxLength={500}
                                  placeholder={t('simReconcile.conflicts.dismissNotePlaceholder')}
                                  onChange={(e) => setNote(e.target.value)}
                                />
                              </label>
                              <p className="max-w-[360px] text-[11px] text-text-muted">{t('simReconcile.conflicts.dismissHint')}</p>
                              <div className="flex gap-2">
                                <Button variant="ghost" size="sm" disabled={busy} onClick={() => setPending(null)}>
                                  {t('common.cancel')}
                                </Button>
                                <Button size="sm" loading={busy} onClick={() => void dismiss(c)}>
                                  {t('simReconcile.conflicts.confirmDismiss')}
                                </Button>
                              </div>
                            </div>
                          )}
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}
