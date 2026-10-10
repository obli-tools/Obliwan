import { useCallback, useMemo, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { Braces } from 'lucide-react';
import { CAPABILITIES } from '@obliwan/shared';
import { variablesApi, type JsonValue, type VariableScope } from '@/api/variables.api';
import { useAuthStore } from '@/store/authStore';
import { useTenantStore } from '@/store/tenantStore';
import { ScopeValuesPanel, type ScopeRow } from '@/components/variables/ScopeValuesPanel';
import { SiteVariablesPanel } from '@/components/variables/SiteVariablesPanel';
import { RevealSecretButton, secretVersion } from '@/components/secrets/RevealSecretButton';
import { secretsApi } from '@/api/secrets.api';
import { cn } from '@/utils/cn';

/**
 * Inherited variables — three tabs, one per level a person fills in.
 *
 *  - INSTANCE: one value for every client of this installation (the management
 *    tunnel password, the SNMP community…). Readable with TEMPLATE_READ,
 *    writable by platform administrators only (the server refuses anybody
 *    else).
 *  - CLIENT: the current tenant's values. Writes land at scope `tenant`; the
 *    few values stored at the tenant's older `global` level (its widest, below
 *    `tenant`) are listed too, with a badge, and edited where they live — so
 *    nothing is hidden and nothing is silently duplicated one level up.
 *  - SITE: the form generated from what the published templates declare
 *    (SITE_VARIABLES_WRITE), one field per key, with each refusal drawn under
 *    its own field.
 *
 * ┌─ A SECRET IS SHOWN AS SET, AND REVEALED ONLY ON PURPOSE ─────────────────┐
 * │ The API returns a placeholder in `value` and `isSecret: true`. These      │
 * │ screens render "set" / "not set" and an empty field that REPLACES it.     │
 * │ Next to a secret marked "set", an account holding SECRET_READ gets an    │
 * │ eye (`RevealSecretButton`, `POST /api/variables/reveal`): the value is    │
 * │ fetched on click, shown 30 seconds, then dropped, and the server records  │
 * │ every reveal in the audit log. On the INSTANCE tab the eye is drawn for   │
 * │ platform administrators only, the server's rule for that level. Nothing  │
 * │ on this page reads a secret any other way.                                │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The tab and the chosen site live in the query string (`?tab=site&site=12`),
 * so a link to one site's values can be shared and the back button works.
 */

type Tab = 'instance' | 'client' | 'site';

export function VariablesPage() {
  const { t } = useTranslation();
  const { hasCapability, isAdmin } = useAuthStore();
  const currentTenantId = useTenantStore((s) => s.currentTenantId);
  const [params, setParams] = useSearchParams();

  const canRead = hasCapability(CAPABILITIES.TEMPLATE_READ);
  const canWriteTenant = hasCapability(CAPABILITIES.TEMPLATE_WRITE);
  const canWriteSite = hasCapability(CAPABILITIES.SITE_VARIABLES_WRITE);
  const admin = isAdmin();

  const tabs = useMemo(() => {
    const list: { id: Tab; label: string }[] = [];
    if (canRead) {
      list.push({ id: 'instance', label: t('variables.tab.instance', { defaultValue: 'Instance (all clients)' }) });
      list.push({ id: 'client', label: t('variables.tab.client', { defaultValue: 'Client' }) });
    }
    if (canRead || canWriteSite) list.push({ id: 'site', label: t('variables.tab.site', { defaultValue: 'Site' }) });
    return list;
  }, [canRead, canWriteSite, t]);

  const requested = params.get('tab') as Tab | null;
  const tab: Tab | undefined =
    tabs.find((x) => x.id === requested)?.id ?? (tabs.some((x) => x.id === 'client') ? 'client' : tabs[0]?.id);

  const rawSite = params.get('site');
  const siteId = rawSite && /^\d+$/.test(rawSite) ? Number(rawSite) : null;

  /** The Site tab holds typed, unsaved values (secrets included); leaving the
   *  tab unmounts it and drops them, so that is asked first. */
  const siteDirty = useRef(false);
  const trackSiteDirty = useCallback((dirty: boolean) => { siteDirty.current = dirty; }, []);
  const selectTab = (id: Tab) => {
    if (tab === 'site' && id !== 'site' && siteDirty.current && !window.confirm(t('variables.site.discardConfirm', {
      defaultValue: 'This site has unsaved changes. Leave and lose them?',
    }))) return;
    const next = new URLSearchParams(params);
    next.set('tab', id);
    setParams(next);
  };
  const selectSite = (id: number | null) => {
    const next = new URLSearchParams(params);
    next.set('tab', 'site');
    if (id === null) next.delete('site'); else next.set('site', String(id));
    setParams(next);
  };

  // ── Instance ──────────────────────────────────────────────────────────────
  const loadInstance = useCallback(async (): Promise<ScopeRow[]> => {
    const values = await variablesApi.instance();
    return Object.values(values).map((variable) => ({ variable }));
  }, []);
  const saveInstance = useCallback(
    (body: { key: string; value: JsonValue; isSecret: boolean }) => variablesApi.setInstance(body),
    [],
  );
  const removeInstance = useCallback((key: string) => variablesApi.removeInstance(key), []);

  // ── Client (tenant + its older `global` level) ────────────────────────────
  const baseLabel = t('variables.levelBase', { defaultValue: 'base level' });
  const loadClient = useCallback(async (): Promise<ScopeRow[]> => {
    const [base, own] = await Promise.all([variablesApi.atScope('global'), variablesApi.atScope('tenant')]);
    return [
      ...Object.values(own).map((variable) => ({ variable })),
      ...Object.values(base).map((variable) => ({ variable, level: 'global', levelLabel: baseLabel })),
    ];
  }, [baseLabel]);
  const saveClient = useCallback(
    (body: { key: string; value: JsonValue; isSecret: boolean }, level: string | undefined) =>
      variablesApi.setAtScope((level === 'global' ? 'global' : 'tenant') as VariableScope, undefined, body),
    [],
  );
  const removeClient = useCallback(
    (key: string, level: string | undefined) =>
      variablesApi.removeAtScope((level === 'global' ? 'global' : 'tenant') as VariableScope, undefined, key),
    [],
  );

  // ── Reveal (SECRET_READ): one eye per secret marked "set" ─────────────────
  // The button hides itself without SECRET_READ (and, for the instance level
  // or in the master tenant, without the platform admin role). `resetKey`
  // drops a value on screen as soon as the tenant — or, on the Site tab, the
  // site — changes, or the secret is replaced (its fingerprint changes).
  const revealInstance = useCallback((key: string, _level: string | undefined, fingerprint: unknown) => (
    <RevealSecretButton
      platformAdminOnly
      label={key}
      resetKey={`${currentTenantId ?? ''}:${secretVersion(fingerprint)}`}
      reveal={() => secretsApi.revealVariable({ scope: 'instance', key })}
    />
  ), [currentTenantId]);
  const revealClient = useCallback((key: string, level: string | undefined, fingerprint: unknown) => (
    <RevealSecretButton
      label={key}
      resetKey={`${currentTenantId ?? ''}:${level ?? ''}:${secretVersion(fingerprint)}`}
      reveal={() => secretsApi.revealVariable({ scope: level === 'global' ? 'global' : 'tenant', key })}
    />
  ), [currentTenantId]);
  const revealSite = useCallback((site: number, key: string, fingerprint: unknown) => (
    <RevealSecretButton
      label={key}
      resetKey={`${currentTenantId ?? ''}:${site}:${secretVersion(fingerprint)}`}
      reveal={() => secretsApi.revealVariable({ scope: 'site', scopeId: site, key })}
    />
  ), [currentTenantId]);

  return (
    <div className="p-6">
      <h1 className="mb-2 flex items-center gap-2 text-2xl font-semibold text-text-primary">
        <Braces size={22} /> {t('nav.variables')}
      </h1>
      <p className="mb-4 max-w-3xl text-sm text-text-secondary">
        {t('variables.intro', {
          defaultValue:
            'Variables are the values the configuration templates fill in: addresses, passwords, options. '
            + 'A value set for a site wins over the client\'s, which wins over the instance\'s.',
        })}
      </p>

      {tabs.length > 1 && (
        <nav className="mb-5 flex items-center gap-1 overflow-x-auto border-b border-border">
          {tabs.map((x) => (
            <button
              key={x.id}
              type="button"
              onClick={() => selectTab(x.id)}
              className={cn(
                'relative whitespace-nowrap px-4 py-2.5 text-[13px] transition-colors',
                'after:absolute after:inset-x-2 after:-bottom-px after:h-0.5 after:rounded-full',
                tab === x.id
                  ? 'text-text-primary after:bg-accent'
                  : 'text-text-secondary hover:text-text-primary after:bg-transparent',
              )}
            >
              {x.label}
            </button>
          ))}
        </nav>
      )}

      {tab === undefined && (
        <div className="rounded-lg border border-border bg-bg-secondary px-6 py-12 text-center text-sm text-text-secondary">
          {t('variables.noAccess', { defaultValue: 'Your account cannot view variables.' })}
        </div>
      )}

      {tab === 'instance' && (
        <ScopeValuesPanel
          key="instance"
          load={loadInstance}
          save={saveInstance}
          remove={removeInstance}
          canWrite={admin}
          readOnlyNote={t('variables.instanceReadOnly', {
            defaultValue: 'Only platform administrators can change these values.',
          })}
          hint={t('variables.instanceHint', {
            defaultValue:
              'One value for every client of this installation. A client or a site can still set its own value '
              + 'with the same name, and that one wins.',
          })}
          emptyText={t('variables.instanceEmpty', { defaultValue: 'No value is set for the whole installation.' })}
          secretReveal={revealInstance}
          removeConfirmText={(key) => t('variables.removeConfirmInstance', {
            defaultValue:
              'Delete "{{key}}" for ALL clients? No wider value takes over: every client and site without a value '
              + 'of its own loses it, and templates that need it may stop rendering.',
            key,
          })}
          reloadKey={currentTenantId}
        />
      )}

      {tab === 'client' && (
        <ScopeValuesPanel
          key="client"
          load={loadClient}
          save={saveClient}
          remove={removeClient}
          canWrite={canWriteTenant}
          readOnlyNote={t('variables.clientReadOnly', {
            defaultValue: 'You can view these values but not change them.',
          })}
          hint={t('variables.clientHint', {
            defaultValue:
              'Values for every site of the current client. They replace the instance values of the same name, '
              + 'and a site can still set its own.',
          })}
          emptyText={t('variables.clientEmpty', { defaultValue: 'No value is set for this client.' })}
          secretReveal={revealClient}
          removeConfirmText={(key) => t('variables.removeConfirm', {
            defaultValue: 'Delete "{{key}}" here? If a value exists at a wider level, that one applies instead.',
            key,
          })}
          reloadKey={currentTenantId}
        />
      )}

      {tab === 'site' && (
        <SiteVariablesPanel
          siteId={siteId}
          onSiteChange={selectSite}
          onDirtyChange={trackSiteDirty}
          canWrite={canWriteSite}
          reloadKey={currentTenantId}
          secretReveal={revealSite}
        />
      )}
    </div>
  );
}
