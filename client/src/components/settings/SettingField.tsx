import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { RotateCcw } from 'lucide-react';
import type { SettingValue, SettingsScope } from '@obliwan/shared';
import type { SettingsKey, SettingDefinition } from '@obliwan/shared';
import { InheritanceBadge } from './InheritanceBadge';
import { IPV4_SETTING_UNIT, SETTINGS_KEYS, intToIpv4, ipv4ToInt } from '@obliwan/shared';
import { snmpApi, type SnmpCredential } from '@/api/snmp.api';
import { groupsApi } from '@/api/groups.api';
import { useTenantStore } from '@/store/tenantStore';

interface SettingFieldProps {
  definition: SettingDefinition;
  inheritedValue: SettingValue;
  overrideValue: number | undefined;
  scope: SettingsScope;
  onSave: (key: SettingsKey, value: number) => Promise<void>;
  onReset: (key: SettingsKey) => Promise<void>;
}

export function SettingField({
  definition,
  inheritedValue,
  overrideValue,
  scope,
  onSave,
  onReset,
}: SettingFieldProps) {
  const hasOverride = overrideValue !== undefined;
  const [isOverriding, setIsOverriding] = useState(hasOverride);
  const [localValue, setLocalValue] = useState<number>(overrideValue ?? inheritedValue.value);
  const [saving, setSaving] = useState(false);
  // The global scope has no "override" toggle (nothing above it to inherit
  // from): its field is ALWAYS editable. Gating it on `isOverriding` froze
  // every global setting that had never been stored — the input showed the
  // default, typing changed nothing on screen and the blur never saved.
  const editing = scope === 'global' || isOverriding;
  // A value loaded or saved elsewhere replaces the field's (not while saving).
  useEffect(() => {
    if (!saving) setLocalValue(overrideValue ?? inheritedValue.value);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [overrideValue, inheritedValue.value]);
  const { t } = useTranslation();
  const currentTenantId = useTenantStore((s) => s.currentTenantId);

  // The keys whose numeric value names a ROW rather than a quantity.
  const isCredentialPicker = definition.key === SETTINGS_KEYS.SNMP_AUTO_TARGET_CREDENTIAL;
  const isGroupPicker = definition.key === SETTINGS_KEYS.BENCH_DEFAULT_GROUP;
  // A definition that names its values (`choices`: 0 = Off, 1 = On…) is a
  // select of those words; the stored value is still the number.
  const choices = definition.choices ?? null;
  const isPicker = isCredentialPicker || isGroupPicker || choices !== null;
  // Reached by a link (`#setting-<key>`, e.g. from the reconciliation page):
  // brought into view once the panel has rendered it.
  const anchor = `setting-${definition.key}`;
  useEffect(() => {
    if (window.location.hash !== `#${anchor}`) return;
    document.getElementById(anchor)?.scrollIntoView({ block: 'center' });
  }, [anchor]);
  const [credentials, setCredentials] = useState<SnmpCredential[]>([]);
  const [groups, setGroups] = useState<Array<{ id: number; name: string }> | null>(null);
  useEffect(() => {
    if (!isCredentialPicker) return;
    void snmpApi.listCredentials({ usable: true }).then(setCredentials).catch(() => setCredentials([]));
  }, [isCredentialPicker]);
  useEffect(() => {
    if (!isGroupPicker) return;
    void groupsApi
      .list()
      .then((gs) => setGroups(gs.map((g) => ({ id: g.id, name: g.name })).sort((a, b) => a.name.localeCompare(b.name))))
      .catch(() => setGroups([]));
  }, [isGroupPicker]);
  const shownValue = editing ? localValue : inheritedValue.value;
  // An IPv4 address stored as its 32-bit value (the line quality targets):
  // shown and typed in dotted form, 0 = none.
  const isIpv4 = definition.unit === IPV4_SETTING_UNIT;
  const [ipDraft, setIpDraft] = useState<string>(intToIpv4(shownValue) ?? '');
  useEffect(() => {
    if (isIpv4 && !saving) setIpDraft(intToIpv4(shownValue) ?? '');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isIpv4, shownValue]);
  const commitIp = () => {
    const text = ipDraft.trim();
    const next = text === '' || text === '0' ? 0 : ipv4ToInt(text);
    if (next === null) {
      setIpDraft(intToIpv4(shownValue) ?? '');
      return;
    }
    setLocalValue(next);
    if (editing && next !== (overrideValue ?? inheritedValue.value)) void save(next);
  };

  /** Used by the picker: a select has no blur-to-commit, it commits on change. */
  const save = async (value: number) => {
    setSaving(true);
    try {
      await onSave(definition.key, value);
    } finally {
      setSaving(false);
    }
  };

  const handleToggleOverride = async () => {
    if (isOverriding) {
      // Reset to inherited
      setSaving(true);
      try {
        await onReset(definition.key);
        setIsOverriding(false);
        setLocalValue(inheritedValue.value);
      } finally {
        setSaving(false);
      }
    } else {
      // Start overriding
      setIsOverriding(true);
      setLocalValue(inheritedValue.value);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      await onSave(definition.key, localValue);
    } finally {
      setSaving(false);
    }
  };

  const handleBlur = () => {
    if (editing && localValue !== (overrideValue ?? inheritedValue.value)) {
      void handleSave();
    }
  };

  return (
    <div id={anchor} className="flex items-center gap-4 py-3 border-b border-border last:border-b-0 scroll-mt-24">
      {/* Label and description */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-text-primary">{t(`settings.keys.${definition.key}.label`, { defaultValue: definition.label })}</span>
          {scope !== 'global' && (
            isOverriding ? (
              <span className="inline-flex items-center rounded-full bg-amber-500/10 px-2 py-0.5 text-[10px] font-medium text-amber-500">
                Override
              </span>
            ) : (
              <InheritanceBadge setting={inheritedValue} />
            )
          )}
        </div>
        <p className="text-xs text-text-muted mt-0.5">{t(`settings.keys.${definition.key}.description`, { defaultValue: definition.description })}</p>
      </div>

      {/* Value input */}
      <div className="flex items-center gap-2">
        {/* ── Two settings are IDs, not quantities ──────────────────────────
            `snmp_auto_target_credential` holds an `snmp_credentials.id`, and
            `bench_default_group` a `device_groups.id`. The settings table
            stores numbers only, which is the right storage and the wrong
            control: asking an operator to type the numeric id of a credential
            or a group means asking them to go and read it off another screen
            first, and to get it right. The value on the wire is unchanged — a
            number — but it is CHOSEN by name. */}
        {isPicker ? (
          <select
            value={shownValue}
            onChange={(e) => {
              const next = parseInt(e.target.value, 10) || 0;
              setLocalValue(next);
              void save(next);
            }}
            disabled={scope !== 'global' && !isOverriding}
            className={`w-56 rounded-md border px-2 py-1 text-sm focus:outline-none focus:ring-2 focus:ring-accent ${
              scope !== 'global' && !isOverriding
                ? 'border-border bg-bg-tertiary text-text-muted cursor-not-allowed'
                : 'border-border bg-bg-tertiary text-text-primary'
            }`}
          >
            {choices !== null ? (
              <>
                {choices.map((c) => (
                  <option key={c.value} value={c.value}>
                    {t(`settings.keys.${definition.key}.choices.${c.value}`, { defaultValue: c.label })}
                  </option>
                ))}
                {!choices.some((c) => c.value === shownValue) && <option value={shownValue}>{shownValue}</option>}
              </>
            ) : isCredentialPicker ? (
              <>
                {/* 0 is not "unset", it is a decision: do not poll automatically. */}
                <option value={0}>{t('snmpCred.noneOption')}</option>
                {credentials.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name} ({c.version})
                    {c.tenantId !== undefined && currentTenantId !== null && c.tenantId !== currentTenantId
                      ? ` — ${t('settings.fromDefaultWorkspace')}`
                      : ''}
                  </option>
                ))}
              </>
            ) : (
              <>
                <option value={0}>{t('settings.benchGroup.none', { defaultValue: 'No group' })}</option>
                {(groups ?? []).map((g) => (
                  <option key={g.id} value={g.id}>{g.name}</option>
                ))}
                {/* A stored id naming no group of this workspace (deleted
                    since): shown as such, never as the first option — a select
                    whose value is missing draws "No group", which is not what
                    is stored and not what the bench reads. The bench applies
                    no group then, and its compile says so. */}
                {groups !== null && shownValue > 0 && !groups.some((g) => g.id === shownValue) && (
                  <option value={shownValue}>
                    {t('settings.benchGroup.missing', { id: shownValue, defaultValue: 'Group #{{id}} (not found: no group is applied)' })}
                  </option>
                )}
              </>
            )}
          </select>
        ) : isIpv4 ? (
          <input
            type="text"
            inputMode="decimal"
            value={ipDraft}
            placeholder="0"
            onChange={(e) => setIpDraft(e.target.value)}
            onBlur={commitIp}
            onKeyDown={(e) => {
              if (e.key === 'Enter') commitIp();
            }}
            disabled={scope !== 'global' && !isOverriding}
            className={`w-32 rounded-md border px-2 py-1 text-sm text-right font-mono focus:outline-none focus:ring-2 focus:ring-accent ${
              scope !== 'global' && !isOverriding
                ? 'border-border bg-bg-tertiary text-text-muted cursor-not-allowed'
                : 'border-border bg-bg-tertiary text-text-primary'
            }`}
          />
        ) : (
          <input
            type="number"
            value={shownValue}
            onChange={(e) => setLocalValue(parseInt(e.target.value, 10) || 0)}
            onBlur={handleBlur}
            onKeyDown={(e) => {
              if (e.key === 'Enter') handleBlur();
            }}
            disabled={scope !== 'global' && !isOverriding}
            min={definition.min}
            max={definition.max}
            className={`w-24 rounded-md border px-2 py-1 text-sm text-right focus:outline-none focus:ring-2 focus:ring-accent ${
              scope !== 'global' && !isOverriding
                ? 'border-border bg-bg-tertiary text-text-muted cursor-not-allowed'
                : 'border-border bg-bg-tertiary text-text-primary'
            }`}
          />
        )}
        {/* "credential id" / "group id" is not a unit; the picker already says what it is. */}
        {!isPicker && (
          <span className="text-xs text-text-muted w-12">{definition.unit}</span>
        )}
      </div>

      {/* Override toggle / reset button (not shown for global scope) */}
      {scope !== 'global' && (
        <button
          onClick={handleToggleOverride}
          disabled={saving}
          className={`shrink-0 rounded-md px-2 py-1 text-xs font-medium transition-colors ${
            isOverriding
              ? 'text-amber-500 hover:bg-amber-500/10'
              : 'text-text-muted hover:bg-bg-hover hover:text-text-primary'
          }`}
          title={isOverriding ? 'Reset to inherited' : 'Override locally'}
        >
          {isOverriding ? (
            <span className="flex items-center gap-1">
              <RotateCcw size={12} />
              Reset
            </span>
          ) : (
            'Override'
          )}
        </button>
      )}
    </div>
  );
}
