import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { Network, Plus, RefreshCw, Save, Trash2 } from 'lucide-react';
import { Button } from '@/components/common/Button';
import { ReconcilePanel } from '@/components/allocation/ReconcilePanel';
import { LanRepriseModal } from '@/components/allocation/LanRepriseModal';
import { InfraConcentratorsPanel } from '@/components/infraConcentrator/InfraConcentratorsPanel';
import {
  allocationApi,
  allocationError,
  type AddressPool,
  type AllocatedSite,
  type AllocationPolicy,
  type AllocationPolicyInput,
  type AllocationPreview,
  type ConcentratorOption,
  type LanMode,
  type PoolPurpose,
  type PppPasswordMode,
  type TenantOption,
} from '@/api/allocation.api';

/**
 * Address allocation (platform administration): the shared address pools, the
 * installation domain, each tenant's policy (tunnel rule, LAN mode, login and
 * identity templates, PPP password mode, concentrator), the CHR <-> sites
 * reconciliation (ReconcilePanel), a read-only preview of the next allocations
 * and the list of allocated sites, each with its "Release allocation" action
 * (which never touches the concentrator).
 *
 * Nothing on this page reads or shows a PPP password. The shared one is the
 * INSTANCE variable `ppp_password` (variables page), per-site ones stay in
 * the vault.
 */

const INPUT =
  'w-full rounded-lg border border-border bg-bg-primary px-3 py-1.5 text-sm text-text-primary ' +
  'focus:outline-none focus:ring-1 focus:ring-accent';
const LABEL = 'block text-xs text-text-muted mb-1';
const CARD = 'mb-4 rounded-xl border border-border bg-bg-secondary p-4';
const TH = 'px-2 py-1.5 text-left text-xs font-medium text-text-muted';
const TD = 'px-2 py-1.5 text-sm text-text-primary align-top';

type FieldErrors = Record<string, string[]>;

/** A site already deployed on the concentrator: its login and tunnel address
 *  were read from the CHR's /ppp/secret and recorded as they are. */
function AdoptedBadge() {
  const { t } = useTranslation();
  return (
    <span
      className="ml-1 whitespace-nowrap rounded bg-accent/15 px-1.5 py-0.5 font-sans text-xs text-accent"
      title={t('allocation.source.adoptedTitle', {
        defaultValue:
          "Login and tunnel address read from the concentrator's /ppp/secret: a site already deployed, recorded as it is. Nothing is written to the concentrator.",
      })}
    >
      {t('allocation.source.adopted_chr', { defaultValue: 'taken from the CHR' })}
    </span>
  );
}

/** The address the tunnel formula gives, shown beside the concentrator's when
 *  the two differ (the concentrator's is the one recorded). */
function FormulaDiffers({ ip }: { ip: string }) {
  const { t } = useTranslation();
  return (
    <div className="text-xs text-amber-400">
      {t('allocation.source.formulaDiffers', { defaultValue: 'formula: {{ip}} (not used)', ip })}
    </div>
  );
}

function FieldError({ errors, field }: { errors: FieldErrors; field: string }) {
  const messages = Object.entries(errors)
    .filter(([k]) => k === field || k.startsWith(`${field}.`))
    .flatMap(([, v]) => v);
  if (messages.length === 0) return null;
  return <p className="mt-1 text-xs text-red-400">{messages.join(' ')}</p>;
}

interface PolicyDraft {
  tunnelPoolId: string;
  tunnelMode: 'incremental' | 'formula';
  tunnelStart: string;
  tunnelFormula: string;
  lanMode: '' | LanMode;
  lanPoolId: string;
  lanPrefix: string;
  lanFormula: string;
  lanSubnet: string;
  lanVariable: string;
  login: string;
  identity: string;
  passwordMode: PppPasswordMode;
  derived: string;
  profile: string;
  concentratorId: string;
  /** '' = free; otherwise the exact number of digits, as text. */
  codeFormat: string;
}

const EMPTY_DRAFT: PolicyDraft = {
  tunnelPoolId: '',
  tunnelMode: 'formula',
  tunnelStart: '',
  tunnelFormula: '',
  lanMode: '',
  lanPoolId: '',
  lanPrefix: '24',
  lanFormula: '',
  lanSubnet: '',
  lanVariable: 'lan_subnet',
  login: '',
  identity: '',
  passwordMode: 'shared',
  derived: '',
  profile: '',
  concentratorId: '',
  codeFormat: '',
};

/** 'digits:5' -> '5'; 'free', absent or unreadable -> '' (free). */
function codeFormatDigits(format: string | undefined): string {
  const m = /^digits:([0-9]{1,2})$/.exec(format ?? '');
  return m ? m[1] : '';
}

const CODE_FORMAT_DIGITS = Array.from({ length: 15 }, (_, i) => String(i + 1));

function draftOf(p: AllocationPolicy | null): PolicyDraft {
  if (!p) return EMPTY_DRAFT;
  return {
    tunnelPoolId: String(p.tunnel.poolId),
    tunnelMode: p.tunnel.mode,
    tunnelStart: p.tunnel.start ?? '',
    tunnelFormula: p.tunnel.formula ?? '',
    lanMode: p.lan?.mode ?? '',
    lanPoolId: p.lan?.poolId ? String(p.lan.poolId) : '',
    lanPrefix: p.lan?.prefix ? String(p.lan.prefix) : '24',
    lanFormula: p.lan?.formula ?? '',
    lanSubnet: p.lan?.subnet ?? '',
    lanVariable: p.lan?.variable ?? 'lan_subnet',
    login: p.pppLoginTemplate,
    identity: p.systemIdentityTemplate ?? '',
    passwordMode: p.pppPasswordMode,
    derived: Object.entries(p.derived)
      .map(([k, v]) => `${k} = ${v}`)
      .join('\n'),
    profile: p.pppProfile ?? '',
    concentratorId: String(p.concentratorId),
    codeFormat: codeFormatDigits(p.siteCodeFormat),
  };
}

/** "key = expression" per line; the first "=" separates them. */
function parseDerivedText(text: string): Record<string, string> | null {
  const out: Record<string, string> = {};
  for (const line of text.split('\n')) {
    const l = line.trim();
    if (l === '') continue;
    const eq = l.indexOf('=');
    if (eq < 0) out[l] = '';
    else out[l.slice(0, eq).trim()] = l.slice(eq + 1).trim();
  }
  return Object.keys(out).length > 0 ? out : null;
}

function inputOf(d: PolicyDraft): AllocationPolicyInput {
  const lan: AllocationPolicyInput['lan'] =
    d.lanMode === ''
      ? null
      : d.lanMode === 'incremental'
        ? { mode: 'incremental', poolId: Number(d.lanPoolId), prefix: Number(d.lanPrefix) }
        : d.lanMode === 'formula'
          ? { mode: 'formula', poolId: Number(d.lanPoolId), formula: d.lanFormula }
          : d.lanMode === 'fixed'
            ? { mode: 'fixed', subnet: d.lanSubnet }
            : { mode: 'manual', variable: d.lanVariable };
  return {
    tunnel:
      d.tunnelMode === 'incremental'
        ? { poolId: Number(d.tunnelPoolId), mode: 'incremental', start: d.tunnelStart }
        : { poolId: Number(d.tunnelPoolId), mode: 'formula', formula: d.tunnelFormula },
    lan,
    pppLoginTemplate: d.login,
    systemIdentityTemplate: d.identity.trim() === '' ? null : d.identity,
    pppPasswordMode: d.passwordMode,
    derived: parseDerivedText(d.derived),
    pppProfile: d.profile.trim() === '' ? null : d.profile,
    concentratorId: Number(d.concentratorId),
    siteCodeFormat: d.codeFormat === '' ? 'free' : `digits:${d.codeFormat}`,
  };
}

export function AllocationPage() {
  const { t } = useTranslation();
  const [pools, setPools] = useState<AddressPool[]>([]);
  const [tenants, setTenants] = useState<TenantOption[]>([]);
  const [concentrators, setConcentrators] = useState<ConcentratorOption[]>([]);
  const [domain, setDomain] = useState('');
  const [tenantId, setTenantId] = useState<number | null>(null);
  const [policy, setPolicy] = useState<AllocationPolicy | null>(null);
  const [draft, setDraft] = useState<PolicyDraft>(EMPTY_DRAFT);
  const [errors, setErrors] = useState<FieldErrors>({});
  const [saving, setSaving] = useState(false);
  const [newPool, setNewPool] = useState<{ name: string; cidr: string; purpose: PoolPurpose }>({
    name: '',
    cidr: '',
    purpose: 'tunnel',
  });
  const [poolErrors, setPoolErrors] = useState<FieldErrors>({});
  const [count, setCount] = useState(10);
  const [preview, setPreview] = useState<AllocationPreview | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [allocated, setAllocated] = useState<AllocatedSite[]>([]);
  const [lanRepriseOpen, setLanRepriseOpen] = useState(false);

  const loadGlobal = useCallback(async () => {
    try {
      const [p, tn, c, d] = await Promise.all([
        allocationApi.pools(),
        allocationApi.tenants(),
        allocationApi.concentrators(),
        allocationApi.instanceDomain(),
      ]);
      setPools(p);
      setTenants(tn);
      setConcentrators(c);
      setDomain(d);
    } catch (err) {
      toast.error(allocationError(err).message);
    }
  }, []);

  useEffect(() => {
    void loadGlobal();
  }, [loadGlobal]);

  // The tenant on screen. The previous tenant's policy is cleared at once and a
  // late answer for it is dropped: shown under the newly selected tenant, its
  // draft would be saved to that tenant by "Save policy".
  const shownTenant = useRef<number | null>(null);
  const loadTenant = useCallback(async (id: number) => {
    shownTenant.current = id;
    setErrors({});
    setPreview(null);
    setPreviewError(null);
    setPolicy(null);
    setDraft(EMPTY_DRAFT);
    setAllocated([]);
    try {
      const [p, sites] = await Promise.all([allocationApi.policy(id), allocationApi.allocatedSites(id)]);
      if (shownTenant.current !== id) return;
      setPolicy(p);
      setDraft(draftOf(p));
      setAllocated(sites);
    } catch (err) {
      if (shownTenant.current === id) toast.error(allocationError(err).message);
    }
  }, []);

  useEffect(() => {
    if (tenantId !== null) void loadTenant(tenantId);
  }, [tenantId, loadTenant]);

  const tunnelPools = useMemo(() => pools.filter((p) => p.purpose === 'tunnel'), [pools]);
  const lanPools = useMemo(() => pools.filter((p) => p.purpose === 'lan'), [pools]);
  const set = <K extends keyof PolicyDraft>(k: K, v: PolicyDraft[K]) => setDraft((d) => ({ ...d, [k]: v }));

  const saveDomain = async () => {
    try {
      setDomain(await allocationApi.setInstanceDomain(domain));
      toast.success(t('allocation.domain.saved', { defaultValue: 'Installation domain saved' }));
    } catch (err) {
      toast.error(allocationError(err).message);
    }
  };

  const addPool = async () => {
    setPoolErrors({});
    try {
      await allocationApi.createPool(newPool);
      setNewPool({ name: '', cidr: '', purpose: newPool.purpose });
      setPools(await allocationApi.pools());
    } catch (err) {
      const e = allocationError(err);
      setPoolErrors(e.details);
      toast.error(e.message);
    }
  };

  const removePool = async (pool: AddressPool) => {
    if (!confirm(t('allocation.pools.confirmDelete', { defaultValue: 'Delete pool {{name}}?', name: pool.name }))) return;
    try {
      await allocationApi.deletePool(pool.id);
      setPools(await allocationApi.pools());
    } catch (err) {
      toast.error(allocationError(err).message);
    }
  };

  const savePolicy = async () => {
    if (tenantId === null) return;
    setSaving(true);
    setErrors({});
    try {
      const saved = await allocationApi.savePolicy(tenantId, inputOf(draft));
      setPolicy(saved);
      setDraft(draftOf(saved));
      // The table on screen was planned under the previous policy.
      setPreview(null);
      setPreviewError(null);
      toast.success(t('allocation.policy.saved', { defaultValue: 'Policy saved' }));
    } catch (err) {
      const e = allocationError(err);
      setErrors(e.details);
      toast.error(e.message);
    } finally {
      setSaving(false);
    }
  };

  /**
   * "Release allocation". A row the concentrator has not taken is released
   * after one confirmation. A PROVISIONED one needs a second, explicit one —
   * typing its PPP login — because the server then overrules its own refusal:
   * the account stays on the concentrator, which ObliWAN never touches here.
   */
  const releaseSite = async (s: AllocatedSite) => {
    if (tenantId === null) return;
    const shown = tenantId;
    const provisioned = s.concentratorState === 'provisioned';
    if (provisioned) {
      if (
        !confirm(
          t('allocation.release.confirmProvisioned', {
            defaultValue:
              'The PPP account {{login}} of site {{code}} is already provisioned on the concentrator. Releasing the allocation removes it from ObliWAN only: the account stays on the concentrator with its login and its address, and ObliWAN does not delete it there. A later allocation that meets them is either adopted from the concentrator or refused by the concentrator job, never written over. A router already prepared for this site keeps what it was given. Continue?',
            login: s.pppUsername,
            code: s.siteCode,
          }),
        )
      ) {
        return;
      }
      const typed = window.prompt(
        t('allocation.release.typeLogin', {
          defaultValue: 'To confirm, type the PPP login {{login}}',
          login: s.pppUsername,
        }),
      );
      if (typed === null) return;
      if (typed.trim() !== s.pppUsername) {
        toast.error(t('allocation.release.loginMismatch', { defaultValue: 'The login typed does not match: nothing was released.' }));
        return;
      }
    } else if (
      !confirm(
        t('allocation.release.confirm', {
          defaultValue:
            'Release the allocation of site {{code}} ({{login}})? Its address and PPP login can be allocated again. A router already prepared for this site keeps what it was given.',
          login: s.pppUsername,
          code: s.siteCode,
        }),
      )
    ) {
      return;
    }
    try {
      await allocationApi.releaseSite(s.siteId, provisioned ? s.pppUsername : undefined);
      toast.success(t('allocation.release.done', { defaultValue: 'Allocation of site {{code}} released', code: s.siteCode }));
      const sites = await allocationApi.allocatedSites(shown);
      if (shownTenant.current === shown) setAllocated(sites);
    } catch (err) {
      toast.error(allocationError(err).message);
    }
  };

  const runPreview = async () => {
    if (tenantId === null) return;
    setPreviewError(null);
    try {
      setPreview(await allocationApi.previewNext(tenantId, count));
    } catch (err) {
      setPreview(null);
      setPreviewError(allocationError(err).message);
    }
  };

  // The preview is planned server-side from the STORED policy; while the form
  // differs from it, a preview would show another rule's logins and addresses.
  const unsaved = policy !== null && JSON.stringify(inputOf(draft)) !== JSON.stringify(inputOf(draftOf(policy)));

  const tenantName = (id: number) => tenants.find((x) => x.id === id)?.name ?? `#${id}`;

  return (
    <div className="p-6">
      <div className="mb-5">
        <h1 className="flex items-center gap-2 text-2xl font-semibold text-text-primary">
          <Network size={22} />
          {t('allocation.title', { defaultValue: 'Address allocation' })}
        </h1>
        <p className="mt-1 text-sm text-text-muted">
          {t('allocation.subtitle', {
            defaultValue:
              'Tunnel addresses, LAN subnets, PPP logins and system identities given to each site, per tenant.',
          })}
        </p>
      </div>

      {/* ── Installation domain ─────────────────────────────────────────── */}
      <div className={CARD}>
        <h2 className="mb-2 text-sm font-semibold text-text-primary">
          {t('allocation.domain.title', { defaultValue: 'Installation domain' })}
        </h2>
        <div className="flex items-end gap-2">
          <div className="w-80">
            <label className={LABEL}>
              {t('allocation.domain.label', { defaultValue: 'Value of {instance.domain} (instance variable)' })}
            </label>
            <input className={INPUT} value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="customers.example" />
          </div>
          <Button size="sm" onClick={saveDomain}>
            <Save size={14} />
          </Button>
        </div>
      </div>

      {/* ── Pools ───────────────────────────────────────────────────────── */}
      <div className={CARD}>
        <h2 className="mb-2 text-sm font-semibold text-text-primary">
          {t('allocation.pools.title', { defaultValue: 'Address pools' })}
        </h2>
        <p className="mb-3 text-xs text-text-muted">
          {t('allocation.pools.help', {
            defaultValue:
              'An incremental pool may be shared by several small tenants; a formula pool belongs to one tenant.',
          })}
        </p>
        <table className="mb-3 w-full">
          <thead>
            <tr>
              <th className={TH}>{t('allocation.pools.name', { defaultValue: 'Name' })}</th>
              <th className={TH}>{t('allocation.pools.cidr', { defaultValue: 'Block' })}</th>
              <th className={TH}>{t('allocation.pools.purpose', { defaultValue: 'Purpose' })}</th>
              <th className={TH}>{t('allocation.pools.allocated', { defaultValue: 'Allocated' })}</th>
              <th className={TH}>{t('allocation.pools.usedBy', { defaultValue: 'Used by' })}</th>
              <th className={TH} />
            </tr>
          </thead>
          <tbody>
            {pools.map((p) => (
              <tr key={p.id} className="border-t border-border">
                <td className={TD}>{p.name}</td>
                <td className={`${TD} font-mono`}>{p.cidr}</td>
                <td className={TD}>
                  {p.purpose === 'tunnel'
                    ? t('allocation.pools.tunnel', { defaultValue: 'Tunnel' })
                    : t('allocation.pools.lan', { defaultValue: 'LAN' })}
                </td>
                <td className={TD}>{p.allocated}</td>
                <td className={TD}>{p.policies.map((x) => `${tenantName(x.tenantId)} (${x.mode})`).join(', ')}</td>
                <td className={TD}>
                  <Button size="sm" variant="ghost" onClick={() => removePool(p)} disabled={p.allocated > 0 || p.policies.length > 0}>
                    <Trash2 size={14} />
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="flex flex-wrap items-end gap-2">
          <div className="w-48">
            <label className={LABEL}>{t('allocation.pools.name', { defaultValue: 'Name' })}</label>
            <input className={INPUT} value={newPool.name} onChange={(e) => setNewPool({ ...newPool, name: e.target.value })} />
            <FieldError errors={poolErrors} field="name" />
          </div>
          <div className="w-48">
            <label className={LABEL}>{t('allocation.pools.cidr', { defaultValue: 'Block' })}</label>
            <input className={INPUT} value={newPool.cidr} onChange={(e) => setNewPool({ ...newPool, cidr: e.target.value })} placeholder="100.64.0.0/16" />
            <FieldError errors={poolErrors} field="cidr" />
          </div>
          <div className="w-36">
            <label className={LABEL}>{t('allocation.pools.purpose', { defaultValue: 'Purpose' })}</label>
            <select className={INPUT} value={newPool.purpose} onChange={(e) => setNewPool({ ...newPool, purpose: e.target.value as PoolPurpose })}>
              <option value="tunnel">{t('allocation.pools.tunnel', { defaultValue: 'Tunnel' })}</option>
              <option value="lan">{t('allocation.pools.lan', { defaultValue: 'LAN' })}</option>
            </select>
          </div>
          <Button size="sm" onClick={addPool}>
            <Plus size={14} /> {t('allocation.pools.add', { defaultValue: 'Add pool' })}
          </Button>
        </div>
      </div>

      {/* ── Tenant ──────────────────────────────────────────────────────── */}
      <div className={CARD}>
        <label className={LABEL}>{t('allocation.tenant', { defaultValue: 'Tenant' })}</label>
        <select
          className={`${INPUT} max-w-sm`}
          value={tenantId ?? ''}
          onChange={(e) => setTenantId(e.target.value === '' ? null : Number(e.target.value))}
        >
          <option value="">{t('allocation.chooseTenant', { defaultValue: 'Choose a tenant…' })}</option>
          {tenants.map((x) => (
            <option key={x.id} value={x.id}>
              {x.name} ({x.slug})
            </option>
          ))}
        </select>
      </div>

      {tenantId !== null && (
        <>
          {/* ── Policy ──────────────────────────────────────────────────── */}
          <div className={CARD}>
            <h2 className="mb-3 text-sm font-semibold text-text-primary">
              {policy
                ? t('allocation.policy.title', { defaultValue: 'Allocation policy' })
                : t('allocation.policy.none', { defaultValue: 'No policy yet: sites of this tenant cannot be allocated.' })}
            </h2>
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <div>
                <label className={LABEL}>{t('allocation.policy.tunnelPool', { defaultValue: 'Tunnel pool' })}</label>
                <select className={INPUT} value={draft.tunnelPoolId} onChange={(e) => set('tunnelPoolId', e.target.value)}>
                  <option value="" />
                  {tunnelPools.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} ({p.cidr})
                    </option>
                  ))}
                </select>
                <FieldError errors={errors} field="tunnel.poolId" />
              </div>
              <div>
                <label className={LABEL}>{t('allocation.policy.tunnelMode', { defaultValue: 'Tunnel rule' })}</label>
                <select className={INPUT} value={draft.tunnelMode} onChange={(e) => set('tunnelMode', e.target.value as 'incremental' | 'formula')}>
                  <option value="formula">{t('allocation.mode.formula', { defaultValue: 'Formula on the site number' })}</option>
                  <option value="incremental">{t('allocation.mode.incremental', { defaultValue: 'Incremental' })}</option>
                </select>
                <FieldError errors={errors} field="tunnel.mode" />
              </div>
              {draft.tunnelMode === 'incremental' ? (
                <div>
                  <label className={LABEL}>{t('allocation.policy.tunnelStart', { defaultValue: 'First address' })}</label>
                  <input className={`${INPUT} font-mono`} value={draft.tunnelStart} onChange={(e) => set('tunnelStart', e.target.value)} placeholder="100.68.1.1" />
                  <FieldError errors={errors} field="tunnel.start" />
                </div>
              ) : (
                <div>
                  <label className={LABEL}>{t('allocation.policy.tunnelFormula', { defaultValue: 'Tunnel formula' })}</label>
                  <input className={`${INPUT} font-mono`} value={draft.tunnelFormula} onChange={(e) => set('tunnelFormula', e.target.value)} placeholder="100.65.{id/100}.{id%100}" />
                  <FieldError errors={errors} field="tunnel.formula" />
                </div>
              )}
              <div>
                <label className={LABEL}>{t('allocation.policy.concentrator', { defaultValue: 'Concentrator (CHR)' })}</label>
                <select className={INPUT} value={draft.concentratorId} onChange={(e) => set('concentratorId', e.target.value)}>
                  <option value="" />
                  {concentrators.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.name}
                    </option>
                  ))}
                </select>
                <FieldError errors={errors} field="concentratorId" />
              </div>

              <div>
                <label className={LABEL}>{t('allocation.policy.lanMode', { defaultValue: 'LAN' })}</label>
                <select className={INPUT} value={draft.lanMode} onChange={(e) => set('lanMode', e.target.value as PolicyDraft['lanMode'])}>
                  <option value="">{t('allocation.lan.none', { defaultValue: 'No LAN subnet' })}</option>
                  <option value="formula">{t('allocation.mode.formula', { defaultValue: 'Formula on the site number' })}</option>
                  <option value="incremental">{t('allocation.mode.incremental', { defaultValue: 'Incremental' })}</option>
                  <option value="fixed">{t('allocation.lan.fixed', { defaultValue: 'Fixed (same LAN on every site)' })}</option>
                  <option value="manual">{t('allocation.lan.manual', { defaultValue: 'Manual (one site variable per site)' })}</option>
                </select>
                <FieldError errors={errors} field="lan.mode" />
              </div>
              <div>
                {(draft.lanMode === 'incremental' || draft.lanMode === 'formula') && (
                  <>
                    <label className={LABEL}>{t('allocation.policy.lanPool', { defaultValue: 'LAN pool' })}</label>
                    <select className={INPUT} value={draft.lanPoolId} onChange={(e) => set('lanPoolId', e.target.value)}>
                      <option value="" />
                      {lanPools.map((p) => (
                        <option key={p.id} value={p.id}>
                          {p.name} ({p.cidr})
                        </option>
                      ))}
                    </select>
                    <FieldError errors={errors} field="lan.poolId" />
                  </>
                )}
                {draft.lanMode === 'fixed' && (
                  <>
                    <label className={LABEL}>{t('allocation.lan.subnet', { defaultValue: 'Subnet' })}</label>
                    <input className={`${INPUT} font-mono`} value={draft.lanSubnet} onChange={(e) => set('lanSubnet', e.target.value)} placeholder="192.168.88.0/24" />
                    <FieldError errors={errors} field="lan.subnet" />
                  </>
                )}
                {draft.lanMode === 'manual' && (
                  <>
                    <label className={LABEL}>{t('allocation.lan.variable', { defaultValue: 'Site variable holding the LAN' })}</label>
                    <input className={`${INPUT} font-mono`} value={draft.lanVariable} onChange={(e) => set('lanVariable', e.target.value)} />
                    <FieldError errors={errors} field="lan.variable" />
                  </>
                )}
              </div>
              {draft.lanMode === 'incremental' && (
                <div>
                  <label className={LABEL}>{t('allocation.lan.prefix', { defaultValue: 'Block size (prefix)' })}</label>
                  <input className={INPUT} type="number" min={8} max={30} value={draft.lanPrefix} onChange={(e) => set('lanPrefix', e.target.value)} />
                  <FieldError errors={errors} field="lan.prefix" />
                </div>
              )}
              {draft.lanMode === 'formula' && (
                <div>
                  <label className={LABEL}>{t('allocation.lan.formula', { defaultValue: 'LAN formula' })}</label>
                  <input className={`${INPUT} font-mono`} value={draft.lanFormula} onChange={(e) => set('lanFormula', e.target.value)} placeholder="10.{100+(id%1000)/100}.{id%100}.0/24" />
                  <FieldError errors={errors} field="lan.formula" />
                </div>
              )}

              <div className="md:col-span-2">
                <label className={LABEL}>{t('allocation.policy.login', { defaultValue: 'PPP login template' })}</label>
                <input className={`${INPUT} font-mono`} value={draft.login} onChange={(e) => set('login', e.target.value)} placeholder="{site.code}.{tenant.slug}.{instance.domain}" />
                <FieldError errors={errors} field="pppLoginTemplate" />
              </div>
              <div className="md:col-span-2">
                <label className={LABEL}>{t('allocation.policy.identity', { defaultValue: 'System identity template (empty: not computed)' })}</label>
                <input className={`${INPUT} font-mono`} value={draft.identity} onChange={(e) => set('identity', e.target.value)} placeholder="{site.country}_{site.code}.{tenant.slug}.cust.example" />
                <FieldError errors={errors} field="systemIdentityTemplate" />
                <p className="mt-1 text-xs text-text-muted">
                  {t('allocation.policy.placeholders', {
                    defaultValue:
                      'Placeholders: {site.code} (verbatim), {site.id}, {site.slug}, {site.country} (optional, drops one adjacent "." or "_"), {tenant.slug}, {instance.domain}. Literal text keeps its case.',
                  })}
                </p>
              </div>
              <div>
                <label className={LABEL}>{t('allocation.policy.password', { defaultValue: 'PPP password' })}</label>
                <select className={INPUT} value={draft.passwordMode} onChange={(e) => set('passwordMode', e.target.value as PppPasswordMode)}>
                  <option value="shared">{t('allocation.password.shared', { defaultValue: 'Shared (instance variable ppp_password)' })}</option>
                  <option value="per_site">{t('allocation.password.perSite', { defaultValue: 'Per site (generated, vault)' })}</option>
                </select>
                <FieldError errors={errors} field="pppPasswordMode" />
              </div>
              <div>
                <label className={LABEL}>{t('allocation.policy.profile', { defaultValue: 'PPP profile (optional)' })}</label>
                <input className={INPUT} value={draft.profile} onChange={(e) => set('profile', e.target.value)} />
                <FieldError errors={errors} field="pppProfile" />
              </div>
              <div>
                <label className={LABEL}>{t('allocation.policy.codeFormat', { defaultValue: 'Site code format' })}</label>
                <select className={INPUT} value={draft.codeFormat} onChange={(e) => set('codeFormat', e.target.value)}>
                  <option value="">{t('allocation.policy.codeFormatFree', { defaultValue: 'Free (no rule)' })}</option>
                  {CODE_FORMAT_DIGITS.map((n) => (
                    <option key={n} value={n}>
                      {t('allocation.policy.codeFormatDigits', {
                        defaultValue: 'Exactly {{count}} digits (leading zeros kept)',
                        count: Number(n),
                      })}
                    </option>
                  ))}
                </select>
                <FieldError errors={errors} field="siteCodeFormat" />
                <p className="mt-1 text-xs text-text-muted">
                  {t('allocation.policy.codeFormatHelp', {
                    defaultValue:
                      'Judged when a site code is created or renamed (site form, CSV import, reconciliation). Codes that already exist are not re-judged.',
                  })}
                </p>
              </div>
              <div className="md:col-span-2">
                <label className={LABEL}>{t('allocation.policy.derived', { defaultValue: 'Derived values (one "key = expression" per line)' })}</label>
                <textarea
                  className={`${INPUT} font-mono`}
                  rows={4}
                  value={draft.derived}
                  onChange={(e) => set('derived', e.target.value)}
                  placeholder={'lan_router_ip = cidrHost(lan_subnet, 1)\nlan_dhcp_pool = cidrHost(lan_subnet, 10)-cidrHost(lan_subnet, -2)\ninfra_loopback_ip = 10.255.{id/100%100}.{id%100}'}
                />
                <FieldError errors={errors} field="derived" />
              </div>
            </div>
            <div className="mt-3">
              <Button size="sm" onClick={savePolicy} loading={saving}>
                <Save size={14} /> {t('allocation.policy.save', { defaultValue: 'Save policy' })}
              </Button>
            </div>
          </div>

          {/* ── CHR <-> sites reconciliation, before anything is allocated ─
               Keyed by tenant: a new tenant is a new panel, so nothing a
               request of the previous one resolves into can reach it. */}
          <ReconcilePanel
            key={tenantId}
            tenantId={tenantId}
            tenantName={tenantName(tenantId)}
            policyStamp={policy?.updatedAt ?? null}
            hasPolicy={policy !== null}
            unsaved={unsaved}
          />

          {/* ── The customer's own infrastructure VPN concentrators ─────── */}
          <InfraConcentratorsPanel key={`infra-${tenantId}`} tenantId={tenantId} />

          {/* ── Preview of the next allocations ────────────────────────── */}
          <div className={CARD}>
            <h2 className="mb-2 text-sm font-semibold text-text-primary">
              {t('allocation.preview.title', { defaultValue: 'Next allocations (preview, nothing is written)' })}
            </h2>
            <div className="mb-3 flex items-end gap-2">
              <div className="w-28">
                <label className={LABEL}>{t('allocation.preview.count', { defaultValue: 'Sites' })}</label>
                <input className={INPUT} type="number" min={1} max={500} value={count} onChange={(e) => setCount(Number(e.target.value) || 1)} />
              </div>
              <Button size="sm" variant="secondary" onClick={runPreview} disabled={!policy || unsaved}>
                <RefreshCw size={14} /> {t('allocation.preview.run', { defaultValue: 'Preview' })}
              </Button>
            </div>
            {unsaved && (
              <p className="mb-2 text-sm text-amber-400">
                {t('allocation.preview.unsaved', {
                  defaultValue: 'The policy has unsaved changes: save it first, the preview is computed from the saved policy.',
                })}
              </p>
            )}
            {previewError && <p className="mb-2 text-sm text-red-400">{previewError}</p>}
            {preview?.blockedBy && <p className="mb-2 text-sm text-amber-400">{preview.blockedBy.message}</p>}
            {preview && preview.entries.length === 0 && (
              <p className="text-sm text-text-muted">
                {t('allocation.preview.empty', { defaultValue: 'Every site of this tenant is already allocated.' })}
              </p>
            )}
            {preview && preview.entries.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr>
                      <th className={TH}>{t('allocation.col.site', { defaultValue: 'Site' })}</th>
                      <th className={TH}>{t('allocation.col.login', { defaultValue: 'PPP login' })}</th>
                      <th className={TH}>{t('allocation.col.identity', { defaultValue: 'Identity' })}</th>
                      <th className={TH}>{t('allocation.col.tunnel', { defaultValue: 'Tunnel IP' })}</th>
                      <th className={TH}>{t('allocation.col.lan', { defaultValue: 'LAN' })}</th>
                      <th className={TH}>{t('allocation.col.derived', { defaultValue: 'Derived' })}</th>
                      <th className={TH}>{t('allocation.col.warnings', { defaultValue: 'Warnings' })}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {preview.entries.map((e) => (
                      <tr key={e.index} className="border-t border-border">
                        <td className={TD}>
                          <span className="font-mono">{e.code}</span> <span className="text-text-muted">{e.name}</span>
                        </td>
                        {e.plan ? (
                          <>
                            <td className={`${TD} font-mono`}>{e.plan.pppLogin}</td>
                            <td className={`${TD} font-mono`}>{e.plan.systemIdentity ?? '—'}</td>
                            <td className={`${TD} font-mono`}>
                              {e.plan.tunnelIp}
                              {e.plan.source === 'adopted_chr' && <AdoptedBadge />}
                              {e.plan.formulaTunnelIp && <FormulaDiffers ip={e.plan.formulaTunnelIp} />}
                            </td>
                            <td className={`${TD} font-mono`}>{e.plan.lanSubnet ?? '—'}</td>
                            <td className={`${TD} font-mono text-xs`}>
                              {Object.entries(e.plan.derived).map(([k, v]) => (
                                <div key={k}>
                                  {k} = {v}
                                </div>
                              ))}
                            </td>
                            <td className={`${TD} text-xs`}>
                              {e.plan.warnings.length === 0 ? (
                                <span className="text-text-muted">—</span>
                              ) : (
                                e.plan.warnings.map((w, i) => (
                                  <div key={i} className="mb-1 text-amber-400">
                                    {w}
                                  </div>
                                ))
                              )}
                            </td>
                          </>
                        ) : (
                          <td className={`${TD} text-red-400`} colSpan={6}>
                            {e.refusal?.message}
                          </td>
                        )}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* ── Allocated sites ─────────────────────────────────────────── */}
          <div className={CARD}>
            <div className="mb-2 flex items-center justify-between gap-2">
              <h2 className="text-sm font-semibold text-text-primary">
                {t('allocation.allocated.title', { defaultValue: 'Allocated sites' })} ({allocated.length})
              </h2>
              {tenantId !== null && (
                <Button size="sm" variant="secondary" onClick={() => setLanRepriseOpen(true)}>
                  <Network size={14} /> {t('allocation.lanReprise.button', { defaultValue: 'Record existing LANs' })}
                </Button>
              )}
            </div>
            {lanRepriseOpen && tenantId !== null && (
              <LanRepriseModal
                tenantId={tenantId}
                tenantLabel={tenants.find((x) => x.id === tenantId)?.name}
                onClose={() => setLanRepriseOpen(false)}
                onApplied={() => {
                  const id = tenantId;
                  void allocationApi
                    .allocatedSites(id)
                    .then((sites) => { if (shownTenant.current === id) setAllocated(sites); })
                    .catch((err: unknown) => toast.error(allocationError(err).message));
                }}
              />
            )}
            {allocated.length === 0 ? (
              <p className="text-sm text-text-muted">{t('allocation.allocated.none', { defaultValue: 'No site allocated yet.' })}</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr>
                      <th className={TH}>{t('allocation.col.site', { defaultValue: 'Site' })}</th>
                      <th className={TH}>{t('allocation.col.login', { defaultValue: 'PPP login' })}</th>
                      <th className={TH}>{t('allocation.col.identity', { defaultValue: 'Identity' })}</th>
                      <th className={TH}>{t('allocation.col.tunnel', { defaultValue: 'Tunnel IP' })}</th>
                      <th className={TH}>{t('allocation.col.lan', { defaultValue: 'LAN' })}</th>
                      <th className={TH}>{t('allocation.col.password', { defaultValue: 'Password' })}</th>
                      <th className={TH}>{t('allocation.col.source', { defaultValue: 'Provenance' })}</th>
                      <th className={TH}>{t('allocation.col.concentrator', { defaultValue: 'Concentrator' })}</th>
                      <th className={TH}>{t('allocation.col.actions', { defaultValue: 'Actions' })}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {allocated.map((s) => (
                      <tr key={s.siteId} className="border-t border-border">
                        <td className={TD}>
                          <span className="font-mono">{s.siteCode}</span> <span className="text-text-muted">{s.siteName}</span>
                        </td>
                        <td className={`${TD} font-mono`}>{s.pppUsername}</td>
                        <td className={`${TD} font-mono`}>{s.systemIdentity ?? '—'}</td>
                        <td className={`${TD} font-mono`}>
                          {s.tunnelIp}
                          {s.formulaTunnelIp && <FormulaDiffers ip={s.formulaTunnelIp} />}
                        </td>
                        <td className={`${TD} font-mono`}>
                          {s.lanSubnet ?? '—'}
                          {s.lanSource === 'fixed' && (
                            <span className="ml-1 text-xs text-text-muted">({t('allocation.lan.fixedShort', { defaultValue: 'fixed' })})</span>
                          )}
                          {s.lanSource === 'recorded' && (
                            <span
                              className="ml-1 text-xs text-text-muted"
                              title={t('allocation.lan.recordedTitle', {
                                defaultValue: "Recorded from the deployed store's configuration (Record existing LANs), not computed by a rule.",
                              })}
                            >
                              ({t('allocation.lan.recordedShort', { defaultValue: 'recorded' })})
                            </span>
                          )}
                        </td>
                        <td className={TD}>
                          {s.pppPasswordMode === 'shared' && s.source === 'adopted_chr' ? (
                            <span
                              className="text-amber-400"
                              title={t('allocation.password.sharedAssumedTitle', {
                                defaultValue:
                                  "Adopted from the concentrator, whose password is never read: a router compiled for this site gets the fleet's shared PPP password, assumed to be the one this secret holds. Nothing checks it; a different one shows only as a router that cannot authenticate.",
                              })}
                            >
                              {t('allocation.password.sharedAssumed', { defaultValue: 'shared, assumed (adopted)' })}
                            </span>
                          ) : s.pppPasswordMode === 'shared' ? (
                            t('allocation.password.sharedShort', { defaultValue: 'shared' })
                          ) : s.pppPasswordKnown ? (
                            t('allocation.password.perSiteShort', { defaultValue: 'per site' })
                          ) : (
                            <span
                              className="text-amber-400"
                              title={t('allocation.password.unknownAdoptedTitle', {
                                defaultValue:
                                  "Adopted from the concentrator: its password is never read there, and none is invented. No router configuration can be compiled for this site.",
                              })}
                            >
                              {t('allocation.password.unknownAdopted', { defaultValue: 'per site, none held (adopted)' })}
                            </span>
                          )}
                        </td>
                        <td className={TD}>
                          {s.source === 'adopted_chr' ? (
                            <AdoptedBadge />
                          ) : s.source === 'allocated' ? (
                            t('allocation.source.allocated', { defaultValue: 'allocated' })
                          ) : (
                            <span className="text-text-muted">
                              {t('allocation.source.unknown', { defaultValue: 'not recorded' })}
                            </span>
                          )}
                        </td>
                        <td className={TD} title={s.concentratorError ?? undefined}>
                          {t(`allocation.state.${s.concentratorState}`, { defaultValue: s.concentratorState })}
                        </td>
                        <td className={TD}>
                          <Button size="sm" variant="secondary" onClick={() => void releaseSite(s)}>
                            <Trash2 size={14} /> {t('allocation.release.button', { defaultValue: 'Release allocation' })}
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

export default AllocationPage;
