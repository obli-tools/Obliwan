import { useTranslation } from 'react-i18next';
import { Building2, Globe2, MapPin } from 'lucide-react';
import type { SettingValue } from '@obliwan/shared';
import type { VariableSource } from '@/api/variables.api';

/**
 * Where a value came from. Two shapes share `{ source, sourceName }` and are
 * drawn by this one badge:
 *
 *   - a SETTING (`SettingValue`) — default | global | group | device;
 *   - a resolved template VARIABLE (the server's `ResolvedVariable`, which
 *     copies that quartet on purpose) — the same four, plus `tenant` and
 *     `site`, two levels the variable chain has and settings do not.
 *
 * Tenant and site are drawn as their NAME, like a group, with an icon in
 * front: a bare "Paris" would read as a group as easily as a premises, and
 * on a variable the difference is the precedence — a site value beats every
 * group, a tenant value loses to all of them.
 */
interface InheritanceBadgeProps {
  setting: Pick<SettingValue, 'sourceName'> & { source: SettingValue['source'] | VariableSource };
}

export function InheritanceBadge({ setting }: InheritanceBadgeProps) {
  const { t } = useTranslation();
  // The Default workspace's own value, inherited by every other workspace.
  if (setting.source === 'instance') {
    return (
      <span className="inline-flex items-center gap-1 text-xs text-accent">
        <Globe2 size={11} className="shrink-0" aria-hidden="true" />
        {t('settings.inheritedFrom', { name: setting.sourceName })}
      </span>
    );
  }

  if (setting.source === 'default') {
    return (
      <span className="text-xs text-text-muted">
        Default
      </span>
    );
  }

  if (setting.source === 'global') {
    return (
      <span className="text-xs text-accent">
        Global
      </span>
    );
  }

  if (setting.source === 'tenant') {
    return (
      <span className="inline-flex items-center gap-1 text-xs text-accent">
        <Building2 size={11} className="shrink-0" aria-hidden="true" />
        {setting.sourceName}
      </span>
    );
  }

  if (setting.source === 'group') {
    return (
      <span className="text-xs text-accent">
        {setting.sourceName}
      </span>
    );
  }

  if (setting.source === 'site') {
    return (
      <span className="inline-flex items-center gap-1 text-xs text-accent">
        <MapPin size={11} className="shrink-0" aria-hidden="true" />
        {setting.sourceName}
      </span>
    );
  }

  if (setting.source === 'device') {
    return (
      <span className="inline-flex items-center rounded-full bg-amber-500/10 px-2 py-0.5 text-[10px] font-medium text-amber-500">
        Override
      </span>
    );
  }

  return null;
}
