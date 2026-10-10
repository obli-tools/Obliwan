import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { AlertTriangle, CheckCircle2, ChevronDown, ChevronRight, PenLine, Search, ShieldCheck } from 'lucide-react';
import type { RuleFacet, RuleInference, SetupPolicyFile } from '@obliwan/shared';
import { onboardingApi } from '@/api/onboarding.api';
import { errorMessageOf } from '@/api/change.api';
import type { AddressPool, ConcentratorOption } from '@/api/allocation.api';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { cn } from '@/utils/cn';
import { useQuickSetupStore } from './quickSetupStore';
import { policyDraftFromFile } from './policyModel';

/**
 * « Règle proposée » — the allocation rule read off the CHR accounts naming
 * the client (or a text the operator types), field by field, each with how
 * many accounts it explains and the ones it does not.
 *
 * Nothing is saved without the operator: « Approuver et enregistrer » sends
 * the proposal's fingerprint, and the server saves exactly that proposal —
 * creating its pool first when the block needs one — or refuses (409) when it
 * changed since it was shown. « Pré-remplir le Concepteur » (only when the
 * session is on this very client, since the Concepteur acts on the session's
 * workspace) copies it into the Quick Setup rule form instead, to edit it
 * and send it through the usual check and apply.
 */
export function RuleInferencePanel({
  tenantSlug,
  canPrefill,
  onPrefilled,
  onSaved,
}: {
  tenantSlug: string;
  /** The session's workspace is this client (no god view). */
  canPrefill: boolean;
  onPrefilled: () => void;
  onSaved: () => void;
}) {
  const { t } = useTranslation();
  const [slug, setSlug] = useState(tenantSlug);
  const [data, setData] = useState<RuleInference | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async (text: string) => {
    setLoading(true);
    setError(null);
    try {
      setData(await onboardingApi.inferRule(text));
    } catch (err) {
      setData(null);
      setError(errorMessageOf(err) ?? t('onboarding.rule.loadFailed'));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    setSlug(tenantSlug);
    void load(tenantSlug);
  }, [tenantSlug, load]);

  const approve = async (): Promise<void> => {
    if (!data) return;
    setConfirming(false);
    setSaving(true);
    try {
      const r = await onboardingApi.approveRule({ slug: data.searchSlug, fingerprint: data.proposal.fingerprint });
      toast.success(r.poolCreated
        ? t('onboarding.rule.savedWithPool', { pool: r.poolCreated.name, cidr: r.poolCreated.cidr })
        : t('onboarding.rule.saved'));
      onSaved();
      void load(data.searchSlug);
    } catch (err) {
      toast.error(errorMessageOf(err) ?? t('onboarding.rule.saveFailed'));
      void load(data.searchSlug);
    } finally {
      setSaving(false);
    }
  };

  const prefill = (): void => {
    if (!data?.proposal.file) return;
    const store = useQuickSetupStore.getState();
    const pools = (store.context?.pools ?? []) as unknown as AddressPool[];
    const chrs = (store.context?.concentrators ?? []) as ConcentratorOption[];
    store.setPolicy(policyDraftFromFile(data.proposal.file as Partial<SetupPolicyFile> & Record<string, unknown>, pools, chrs));
    store.markEdited('allocationPolicy');
    toast.success(t('onboarding.rule.prefilled'));
    onPrefilled();
  };

  const p = data?.proposal;
  const canApprove = !!p && p.body !== null && p.blockers.length === 0 && (!p.allocator.checked || p.allocator.ok);

  return (
    <div className="mt-3 rounded-lg border border-accent/40 bg-bg-primary p-3">
      <div className="flex flex-wrap items-end gap-2">
        <label className="text-xs text-text-muted">
          {t('onboarding.rule.searchLabel')}
          <input
            className="ml-2 w-40 rounded-md border border-border bg-bg-secondary px-2 py-1 font-mono text-xs text-text-primary"
            value={slug}
            onChange={(e) => setSlug(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') void load(slug); }}
          />
        </label>
        <Button size="sm" variant="secondary" loading={loading} onClick={() => void load(slug)}>
          <Search size={13} className="mr-1.5" />
          {t('onboarding.rule.read')}
        </Button>
        <span className="text-[11px] text-text-muted">{t('onboarding.rule.searchHint')}</span>
      </div>

      {loading && !data && <div className="py-6"><LoadingSpinner /></div>}
      {error && <p className="mt-2 rounded border border-status-down/50 bg-status-down/10 p-2 text-xs text-status-down">{error}</p>}

      {data && (
        <div className="mt-3 space-y-3 text-sm">
          <div className="flex flex-wrap gap-3 text-xs text-text-secondary">
            <span>
              {t('onboarding.rule.accounts', {
                total: data.accounts.total, online: data.accounts.online, disabled: data.accounts.disabled,
              })}
            </span>
            {data.concentrators.map((c) => (
              <span key={c.id} className={cn(c.freshness !== 'fresh' && 'text-status-ssl-warning')}>
                {t('onboarding.rule.chr', {
                  name: c.name,
                  accounts: c.accounts,
                  read: c.readAt ? new Date(c.readAt).toLocaleString() : t('onboarding.rule.never'),
                })}
              </span>
            ))}
          </div>
          {data.accounts.excluded.length > 0 && (
            <OutlierList
              title={t('onboarding.rule.excluded', { count: data.accounts.excluded.length })}
              facet={{ explained: 0, total: 0, outliers: data.accounts.excluded, outliersTotal: data.accounts.excluded.length }}
            />
          )}

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-text-muted">
                <tr>
                  <th className="py-1 pr-3 font-medium">{t('onboarding.rule.col.field')}</th>
                  <th className="py-1 pr-3 font-medium">{t('onboarding.rule.col.proposed')}</th>
                  <th className="py-1 pr-3 font-medium">{t('onboarding.rule.col.coverage')}</th>
                </tr>
              </thead>
              <tbody className="align-top">
                <FacetRow label={t('onboarding.rule.f.login')} facet={data.login}
                  value={data.login.template
                    ? <><code className="text-text-primary">{data.login.template}</code><span className="block text-text-muted">{data.login.display}</span></>
                    : <span className="text-status-down">{t('onboarding.rule.none')}</span>}
                  extra={data.login.alternatives.length > 0
                    ? <span className="block text-text-muted">{t('onboarding.rule.alternatives')} {data.login.alternatives.map((a) => `${a.template} (${a.explained})`).join(' · ')}</span>
                    : null}
                />
                <FacetRow label={t('onboarding.rule.f.codeFormat')} facet={data.codeFormat}
                  value={<code className="text-text-primary">{data.codeFormat.format === 'free' ? t('onboarding.rule.free') : data.codeFormat.format}</code>} />
                <FacetRow label={t('onboarding.rule.f.tunnel')} facet={data.tunnel}
                  value={data.tunnel.mode === null
                    ? <span className="text-status-down">{t('onboarding.rule.none')}</span>
                    : (
                      <>
                        <span className="text-text-primary">
                          {data.tunnel.mode === 'formula'
                            ? <>{t('onboarding.rule.formula')} <code>{data.tunnel.formula}</code></>
                            : <>{t('onboarding.rule.incremental')} <code>{data.tunnel.start}</code></>}
                        </span>
                        <span className="block text-text-muted">
                          {t('onboarding.rule.block', { block: data.tunnel.block, free: data.tunnel.firstFree ?? '—' })}
                        </span>
                        <span className={cn('block', data.tunnel.pool.action === 'conflict' ? 'text-status-down' : 'text-text-muted')}>
                          {t(`onboarding.rule.pool.${data.tunnel.pool.action}`, {
                            name: data.tunnel.pool.name ?? '', cidr: data.tunnel.pool.cidr ?? '', other: data.tunnel.pool.conflictWith ?? '',
                          })}
                        </span>
                      </>
                    )}
                />
                <FacetRow label={t('onboarding.rule.f.profile')} facet={data.profile}
                  value={data.profile.value ? <code className="text-text-primary">{data.profile.value}</code> : <span className="text-text-muted">{t('onboarding.rule.none')}</span>} />
                <FacetRow label={t('onboarding.rule.f.identity')} facet={data.identity}
                  value={data.identity.template
                    ? <code className="text-text-primary">{data.identity.template}</code>
                    : <span className="text-text-muted">{data.identity.known === 0 ? t('onboarding.rule.identityUnknown') : t('onboarding.rule.none')}</span>} />
              </tbody>
            </table>
          </div>

          {data.sitesWithoutAccount.total > 0 && (
            <p className="text-xs text-status-ssl-warning">
              {t('onboarding.rule.sitesWithoutAccount', { count: data.sitesWithoutAccount.total })}{' '}
              <span className="font-mono">{data.sitesWithoutAccount.codes.slice(0, 30).join(', ')}</span>
            </p>
          )}
          {data.stored.exists && (
            <p className="text-xs text-text-secondary">
              {data.stored.differs.length === 0
                ? t('onboarding.rule.storedSame')
                : t('onboarding.rule.storedDiffers', { fields: data.stored.differs.map((f) => t(`onboarding.rule.field.${f}`)).join(', ') })}
            </p>
          )}

          {p && p.blockers.length > 0 && (
            <p className="flex items-start gap-1.5 rounded border border-status-down/50 bg-status-down/10 p-2 text-xs text-status-down">
              <AlertTriangle size={13} className="mt-0.5 shrink-0" />
              {p.blockers.map((b) => t(`onboarding.rule.blocker.${b}`)).join(' ')}
            </p>
          )}
          {p && p.body && (
            <p className={cn('flex items-start gap-1.5 text-xs',
              !p.allocator.checked ? 'text-text-muted' : p.allocator.ok ? 'text-status-up' : 'text-status-down')}>
              {p.allocator.checked && p.allocator.ok ? <CheckCircle2 size={13} className="mt-0.5 shrink-0" /> : <ShieldCheck size={13} className="mt-0.5 shrink-0" />}
              {!p.allocator.checked
                ? t('onboarding.rule.allocatorLater')
                : p.allocator.ok ? t('onboarding.rule.allocatorOk') : `${t('onboarding.rule.allocatorRefused')} ${p.allocator.message ?? ''}`}
            </p>
          )}

          <div className="flex flex-wrap gap-2">
            <Button size="sm" disabled={!canApprove} loading={saving} onClick={() => setConfirming(true)}>
              <CheckCircle2 size={13} className="mr-1.5" />
              {t('onboarding.rule.approve')}
            </Button>
            <Button size="sm" variant="secondary" disabled={!canPrefill || !p?.file} onClick={prefill}
              title={canPrefill ? undefined : t('onboarding.rule.prefillGodView')}>
              <PenLine size={13} className="mr-1.5" />
              {t('onboarding.rule.prefill')}
            </Button>
          </div>
        </div>
      )}

      {confirming && data && p?.body && (
        <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4">
          <div role="dialog" aria-modal="true" className="my-16 w-full max-w-lg rounded-xl border border-border bg-bg-secondary shadow-2xl">
            <div className="border-b border-border px-5 py-4">
              <h2 className="text-base font-semibold text-text-primary">{t('onboarding.rule.confirmTitle', { name: data.tenant.name })}</h2>
            </div>
            <div className="space-y-2 p-5 text-sm text-text-secondary">
              <p>{t('onboarding.rule.confirmBody')}</p>
              <ul className="list-disc space-y-0.5 pl-5 font-mono text-xs text-text-primary">
                {p.createPool && <li>{t('onboarding.rule.confirmPool', { name: p.createPool.name, cidr: p.createPool.cidr })}</li>}
                <li>{String(p.body.pppLoginTemplate)}</li>
                {p.body.systemIdentityTemplate ? <li>{String(p.body.systemIdentityTemplate)}</li> : null}
                <li>{data.tunnel.mode === 'formula' ? data.tunnel.formula : `${t('onboarding.rule.incremental')} ${data.tunnel.start}`}</li>
                <li>{String(p.body.siteCodeFormat)} · {String(p.body.pppProfile ?? '—')} · {String(p.body.pppPasswordMode)}</li>
              </ul>
              {data.stored.exists && <p className="text-status-ssl-warning">{t('onboarding.rule.confirmReplace')}</p>}
            </div>
            <div className="flex justify-end gap-2 border-t border-border px-5 py-3">
              <Button size="sm" variant="secondary" onClick={() => setConfirming(false)}>{t('common.cancel')}</Button>
              <Button size="sm" onClick={() => void approve()}>{t('onboarding.rule.approve')}</Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function FacetRow({
  label,
  facet,
  value,
  extra,
}: {
  label: string;
  facet: RuleFacet;
  value: ReactNode;
  extra?: ReactNode;
}) {
  const { t } = useTranslation();
  const full = facet.total > 0 && facet.explained === facet.total;
  return (
    <tr className="border-t border-border">
      <td className="py-1.5 pr-3 text-text-muted">{label}</td>
      <td className="py-1.5 pr-3">{value}{extra}</td>
      <td className="py-1.5 pr-3">
        {facet.total > 0 && (
          <span className={cn('font-mono', full ? 'text-status-up' : 'text-status-ssl-warning')}>
            {facet.explained}/{facet.total}
          </span>
        )}
        {facet.outliersTotal > 0 && (
          <OutlierList title={t('onboarding.rule.outliers', { count: facet.outliersTotal })} facet={facet} />
        )}
      </td>
    </tr>
  );
}

function OutlierList({ title, facet }: { title: string; facet: RuleFacet }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  return (
    <div className="mt-0.5">
      <button type="button" onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-1 text-[11px] text-text-muted hover:text-text-primary">
        {open ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
        {title}
      </button>
      {open && (
        <ul className="mt-1 max-h-56 space-y-0.5 overflow-y-auto text-[11px]">
          {facet.outliers.map((o, i) => (
            <li key={`${o.name}-${o.reason}-${i}`}>
              <span className="font-mono text-text-primary">{o.name}</span>{' '}
              <span className="text-status-ssl-warning">{t(`onboarding.rule.outlier.${o.reason}`)}</span>
              {o.detail ? <span className="text-text-muted"> ({o.detail})</span> : null}
            </li>
          ))}
          {facet.outliersTotal > facet.outliers.length && (
            <li className="text-text-muted">{t('onboarding.rule.more', { count: facet.outliersTotal - facet.outliers.length })}</li>
          )}
        </ul>
      )}
    </div>
  );
}
