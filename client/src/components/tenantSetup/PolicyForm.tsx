import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { Plus, Trash2 } from 'lucide-react';
import { Button } from '@/components/common/Button';
import { cn } from '@/utils/cn';
import {
  EMPTY_POLICY, MAX_DERIVED, newId, policyDraftFromStored, type NamedRef, type PolicyDraft, type StoredPolicy,
} from './policyModel';
import { useQuickSetupStore } from './quickSetupStore';
import { CARD, INPUT, LABEL } from './ui';
import { issueText } from './issueText';

/**
 * Designer step 3 — the workspace's allocation rule, as the allocation page
 * edits it, with pools and the concentrator chosen BY NAME (what an export
 * writes, portable between installations).
 *
 * Starts from the stored rule. The form is the request: the server resolves
 * the names, validates the rule with the allocation page's own validator and
 * a dry run of its save (same lock, same conflict checks), and its refusals
 * are drawn under the inputs they name. Pools are not created here: a missing
 * one is named by the check, and pools are added on the allocation page.
 */

const CODE_DIGITS = Array.from({ length: 15 }, (_, i) => i + 1);

type FieldErrors = Record<string, string[]>;

function FieldError({ errors, fields }: { errors: FieldErrors; fields: string[] }) {
  const messages = Object.entries(errors)
    .filter(([k]) => fields.some((f) => k === f || k.startsWith(`${f}.`)))
    .flatMap(([, v]) => v);
  if (messages.length === 0) return null;
  return <p className="mt-1 text-xs text-status-down">{messages.join(' ')}</p>;
}

export function PolicyForm() {
  const { t } = useTranslation();
  const context = useQuickSetupStore((s) => s.context);
  const policy = useQuickSetupStore((s) => s.policy);
  const selected = useQuickSetupStore((s) => s.selected.allocationPolicy);
  const lastCheck = useQuickSetupStore((s) => s.lastCheck);
  const setPolicy = useQuickSetupStore((s) => s.setPolicy);
  const markEdited = useQuickSetupStore((s) => s.markEdited);

  const stored = (context?.policy ?? null) as StoredPolicy | null;
  const draft: PolicyDraft = policy ?? (stored ? policyDraftFromStored(stored) : EMPTY_POLICY);
  const pools = useMemo(
    () => (context?.pools ?? []) as Array<{ id: number; name: string; cidr: string; purpose: string }>,
    [context],
  );
  const tunnelPools = pools.filter((p) => p.purpose === 'tunnel');
  const lanPools = pools.filter((p) => p.purpose === 'lan');
  const concentrators = context?.concentrators ?? [];

  // The server's verdict on THIS rule: the validator's field map, plus the
  // name references it could not resolve.
  const errors: FieldErrors = useMemo(() => {
    const out: FieldErrors = {};
    const report = lastCheck?.report;
    if (!report) return out;
    for (const [k, v] of Object.entries(report.allocationPolicy?.error?.details ?? {})) out[k] = [...v];
    for (const i of report.issues) {
      if (i.part !== 'allocationPolicy') continue;
      if (i.code === 'POLICY_REF' || i.code === 'POLICY_FIELD_UNKNOWN') {
        const field = typeof i.params.field === 'string' ? i.params.field : '';
        (out[field] ??= []).push(issueText(t, i));
      }
    }
    return out;
  }, [lastCheck, t]);
  const generalError = lastCheck?.report.allocationPolicy?.error?.message ?? null;

  const set = (patch: Partial<PolicyDraft>) => {
    setPolicy({ ...draft, ...patch });
    markEdited('allocationPolicy');
  };

  const refSelect = (
    ref: NamedRef,
    options: Array<{ name: string; detail?: string }>,
    onPick: (name: string) => void,
  ) => {
    const known = ref.name === '' || options.some((o) => o.name.toLowerCase() === ref.name.toLowerCase());
    const value = ref.name !== ''
      ? options.find((o) => o.name.toLowerCase() === ref.name.toLowerCase())?.name ?? ref.name
      : ref.id !== null ? `#${ref.id}` : '';
    return (
      <select className={cn(INPUT, !known && 'border-status-down/60')} value={value} onChange={(e) => onPick(e.target.value)}>
        <option value="" />
        {!known && (
          <option value={ref.name}>
            {t('quickSetup.policy.unknownRef', { defaultValue: '(not found) {{name}}', name: ref.name })}
          </option>
        )}
        {ref.name === '' && ref.id !== null && (
          <option value={`#${ref.id}`}>
            {t('quickSetup.policy.unknownRef', { defaultValue: '(not found) {{name}}', name: `#${ref.id}` })}
          </option>
        )}
        {options.map((o) => (
          <option key={o.name} value={o.name}>
            {o.name}{o.detail ? ` (${o.detail})` : ''}
          </option>
        ))}
      </select>
    );
  };
  const pick = (name: string): NamedRef => (name.startsWith('#') ? { name: '', id: Number(name.slice(1)) } : { name, id: null });

  const codeFormatKnown =
    draft.codeFormat === '' || draft.codeFormat === 'free' || /^digits:([1-9]|1[0-5])$/.test(draft.codeFormat);

  return (
    <section className={CARD} id="qs-step-policy">
      {!selected && (
        <p className="mb-3 text-xs text-text-muted">
          {stored
            ? t('quickSetup.policy.notSelectedStored', {
              defaultValue: 'Not part of this setup: the stored rule is used. Edit a field to include the rule.',
            })
            : t('quickSetup.policy.notSelectedNone', {
              defaultValue: 'This workspace has no allocation rule yet. Fill the form to include one in this setup.',
            })}
        </p>
      )}
      {generalError && (
        <p className="mb-3 rounded border border-status-down/50 bg-status-down/10 p-2 text-xs text-status-down">{generalError}</p>
      )}
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <div>
          <label className={LABEL}>{t('allocation.policy.tunnelPool', { defaultValue: 'Tunnel pool' })}</label>
          {refSelect(draft.tunnelPool, tunnelPools.map((p) => ({ name: p.name, detail: p.cidr })), (n) => set({ tunnelPool: pick(n) }))}
          <FieldError errors={errors} fields={['tunnel.poolId', 'tunnel.poolName']} />
        </div>
        <div>
          <label className={LABEL}>{t('allocation.policy.tunnelMode', { defaultValue: 'Tunnel rule' })}</label>
          <select
            className={INPUT}
            value={draft.tunnelMode}
            onChange={(e) => set({ tunnelMode: e.target.value as PolicyDraft['tunnelMode'] })}
          >
            <option value="formula">{t('allocation.mode.formula', { defaultValue: 'Formula on the site number' })}</option>
            <option value="incremental">{t('allocation.mode.incremental', { defaultValue: 'Incremental' })}</option>
          </select>
          <FieldError errors={errors} fields={['tunnel.mode']} />
        </div>
        {draft.tunnelMode === 'incremental' ? (
          <div>
            <label className={LABEL}>{t('allocation.policy.tunnelStart', { defaultValue: 'First address' })}</label>
            <input className={cn(INPUT, 'font-mono')} value={draft.tunnelStart} onChange={(e) => set({ tunnelStart: e.target.value })} placeholder="100.68.1.1" />
            <FieldError errors={errors} fields={['tunnel.start']} />
          </div>
        ) : (
          <div>
            <label className={LABEL}>{t('allocation.policy.tunnelFormula', { defaultValue: 'Tunnel formula' })}</label>
            <input className={cn(INPUT, 'font-mono')} value={draft.tunnelFormula} onChange={(e) => set({ tunnelFormula: e.target.value })} placeholder="100.65.{id/100}.{id%100}" />
            <FieldError errors={errors} fields={['tunnel.formula']} />
          </div>
        )}
        <div>
          <label className={LABEL}>{t('allocation.policy.concentrator', { defaultValue: 'Concentrator (CHR)' })}</label>
          {refSelect(draft.concentrator, concentrators.map((c) => ({ name: c.name })), (n) => set({ concentrator: pick(n) }))}
          <FieldError errors={errors} fields={['concentratorId', 'concentratorName']} />
        </div>

        <div>
          <label className={LABEL}>{t('allocation.policy.lanMode', { defaultValue: 'LAN' })}</label>
          <select className={INPUT} value={draft.lanMode} onChange={(e) => set({ lanMode: e.target.value as PolicyDraft['lanMode'] })}>
            <option value="">{t('allocation.lan.none', { defaultValue: 'No LAN subnet' })}</option>
            <option value="formula">{t('allocation.mode.formula', { defaultValue: 'Formula on the site number' })}</option>
            <option value="incremental">{t('allocation.mode.incremental', { defaultValue: 'Incremental' })}</option>
            <option value="fixed">{t('allocation.lan.fixed', { defaultValue: 'Fixed (same LAN on every site)' })}</option>
            <option value="manual">{t('allocation.lan.manual', { defaultValue: 'Manual (one site variable per site)' })}</option>
          </select>
          <FieldError errors={errors} fields={['lan', 'lan.mode']} />
        </div>
        <div>
          {(draft.lanMode === 'incremental' || draft.lanMode === 'formula') && (
            <>
              <label className={LABEL}>{t('allocation.policy.lanPool', { defaultValue: 'LAN pool' })}</label>
              {refSelect(draft.lanPool, lanPools.map((p) => ({ name: p.name, detail: p.cidr })), (n) => set({ lanPool: pick(n) }))}
              <FieldError errors={errors} fields={['lan.poolId', 'lan.poolName']} />
            </>
          )}
          {draft.lanMode === 'fixed' && (
            <>
              <label className={LABEL}>{t('allocation.lan.subnet', { defaultValue: 'Subnet' })}</label>
              <input className={cn(INPUT, 'font-mono')} value={draft.lanSubnet} onChange={(e) => set({ lanSubnet: e.target.value })} placeholder="192.168.88.0/24" />
              <FieldError errors={errors} fields={['lan.subnet']} />
            </>
          )}
          {draft.lanMode === 'manual' && (
            <>
              <label className={LABEL}>{t('allocation.lan.variable', { defaultValue: 'Site variable holding the LAN' })}</label>
              <input className={cn(INPUT, 'font-mono')} value={draft.lanVariable} onChange={(e) => set({ lanVariable: e.target.value })} />
              <FieldError errors={errors} fields={['lan.variable']} />
            </>
          )}
        </div>
        {draft.lanMode === 'incremental' && (
          <div>
            <label className={LABEL}>{t('allocation.lan.prefix', { defaultValue: 'Block size (prefix)' })}</label>
            <input className={INPUT} inputMode="numeric" value={draft.lanPrefix} onChange={(e) => set({ lanPrefix: e.target.value })} />
            <FieldError errors={errors} fields={['lan.prefix']} />
          </div>
        )}
        {draft.lanMode === 'formula' && (
          <div>
            <label className={LABEL}>{t('allocation.lan.formula', { defaultValue: 'LAN formula' })}</label>
            <input className={cn(INPUT, 'font-mono')} value={draft.lanFormula} onChange={(e) => set({ lanFormula: e.target.value })} placeholder="10.{100+(id%1000)/100}.{id%100}.0/24" />
            <FieldError errors={errors} fields={['lan.formula']} />
          </div>
        )}

        <div className="md:col-span-2">
          <label className={LABEL}>{t('allocation.policy.login', { defaultValue: 'PPP login template' })}</label>
          <input className={cn(INPUT, 'font-mono')} value={draft.login} onChange={(e) => set({ login: e.target.value })} placeholder="{site.code}.{tenant.slug}.{instance.domain}" />
          <FieldError errors={errors} fields={['pppLoginTemplate']} />
        </div>
        <div className="md:col-span-2">
          <label className={LABEL}>{t('allocation.policy.identity', { defaultValue: 'System identity template (empty: not computed)' })}</label>
          <input className={cn(INPUT, 'font-mono')} value={draft.identity} onChange={(e) => set({ identity: e.target.value })} placeholder="{site.country}_{site.code}.{tenant.slug}.cust.example" />
          <FieldError errors={errors} fields={['systemIdentityTemplate']} />
          <p className="mt-1 text-xs text-text-muted">
            {t('allocation.policy.placeholders', {
              defaultValue:
                'Placeholders: {site.code} (verbatim), {site.id}, {site.slug}, {site.country} (optional, drops one adjacent "." or "_"), {tenant.slug}, {instance.domain}. Literal text keeps its case.',
            })}
            {context?.instanceDomain ? ` {instance.domain} = ${context.instanceDomain}` : ''}
          </p>
        </div>
        <div>
          <label className={LABEL}>{t('allocation.policy.password', { defaultValue: 'PPP password' })}</label>
          <select className={INPUT} value={draft.passwordMode} onChange={(e) => set({ passwordMode: e.target.value as PolicyDraft['passwordMode'] })}>
            <option value="shared">{t('allocation.password.shared', { defaultValue: 'Shared (instance variable ppp_password)' })}</option>
            <option value="per_site">{t('allocation.password.perSite', { defaultValue: 'Per site (generated, vault)' })}</option>
          </select>
          <FieldError errors={errors} fields={['pppPasswordMode']} />
          {draft.passwordMode === 'shared' && (
            <p className="mt-1 text-xs text-text-muted">
              {t('quickSetup.policy.sharedHint', {
                defaultValue:
                  'Reads the instance secret ppp_password, which must be stored first: set it in the Instance group of step 2 if it is not.',
              })}
            </p>
          )}
        </div>
        <div>
          <label className={LABEL}>{t('allocation.policy.profile', { defaultValue: 'PPP profile (optional)' })}</label>
          <input className={INPUT} value={draft.profile} onChange={(e) => set({ profile: e.target.value })} />
          <FieldError errors={errors} fields={['pppProfile']} />
        </div>
        <div>
          <label className={LABEL}>{t('allocation.policy.codeFormat', { defaultValue: 'Site code format' })}</label>
          <select className={INPUT} value={draft.codeFormat} onChange={(e) => set({ codeFormat: e.target.value })}>
            <option value="">{t('quickSetup.policy.keepFormat', { defaultValue: '(keep the current format)' })}</option>
            {!codeFormatKnown && <option value={draft.codeFormat}>{draft.codeFormat}</option>}
            <option value="free">{t('allocation.policy.codeFormatFree', { defaultValue: 'Free (no rule)' })}</option>
            {CODE_DIGITS.map((n) => (
              <option key={n} value={`digits:${n}`}>
                {t('allocation.policy.codeFormatDigits', { defaultValue: 'Exactly {{count}} digits (leading zeros kept)', count: n })}
              </option>
            ))}
          </select>
          <FieldError errors={errors} fields={['siteCodeFormat']} />
          {stored?.siteCodeFormat && (
            <p className="mt-1 text-xs text-text-muted">
              {t('quickSetup.policy.currentFormat', { defaultValue: 'Current: {{format}}', format: stored.siteCodeFormat })}
            </p>
          )}
        </div>

        <div className="md:col-span-2">
          <div className="mb-1 flex items-center gap-2">
            <span className="flex-1 text-xs text-text-muted">
              {t('quickSetup.policy.derivedTitle', { defaultValue: 'Derived values' })}
              <span className="ml-1">({draft.derived.length}/{MAX_DERIVED})</span>
            </span>
            <Button
              type="button"
              size="sm"
              variant="secondary"
              disabled={draft.derived.length >= MAX_DERIVED}
              onClick={() => set({ derived: [...draft.derived, { id: newId('d'), key: '', expr: '' }] })}
            >
              <Plus size={12} className="mr-1" />
              {t('quickSetup.policy.addDerived', { defaultValue: 'Add' })}
            </Button>
          </div>
          {draft.derived.length > 0 && (
            <div className="space-y-1.5">
              {draft.derived.map((r) => (
                <div key={r.id} className="flex items-center gap-2">
                  <input
                    className={cn(INPUT, 'w-56 font-mono text-xs')}
                    value={r.key}
                    placeholder="infra_loopback_ip"
                    onChange={(e) => set({ derived: draft.derived.map((x) => (x.id === r.id ? { ...x, key: e.target.value } : x)) })}
                  />
                  <span className="text-text-muted">=</span>
                  <input
                    id={r.key.trim() ? `qs-derived-${r.key.trim()}` : undefined}
                    className={cn(INPUT, 'font-mono text-xs')}
                    value={r.expr}
                    placeholder="10.255.{id/100%100}.{id%100}"
                    onChange={(e) => set({ derived: draft.derived.map((x) => (x.id === r.id ? { ...x, expr: e.target.value } : x)) })}
                  />
                  <button
                    type="button"
                    onClick={() => set({ derived: draft.derived.filter((x) => x.id !== r.id) })}
                    className="rounded p-1 text-text-muted hover:text-status-down"
                    aria-label={t('quickSetup.designer.extra.remove', { defaultValue: 'Remove' })}
                  >
                    <Trash2 size={13} />
                  </button>
                </div>
              ))}
            </div>
          )}
          <FieldError errors={errors} fields={['derived']} />
          <p className="mt-1 text-xs text-text-muted">
            {t('quickSetup.policy.derivedHint', {
              defaultValue:
                'An expression is a formula on the site number ({id}, {id/100}, {id%100}…), a {site.code}-style template, or cidrHost(lan_subnet, N).',
            })}
          </p>
        </div>
      </div>
    </section>
  );
}
