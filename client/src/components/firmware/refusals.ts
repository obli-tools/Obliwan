import { useTranslation } from 'react-i18next';
import type { LaunchRefusalCode } from '@/api/osUpgrade.api';

/**
 * Why a router cannot be selected (or was refused by the launch), in plain
 * words. The codes come from the server (`LAUNCH_REFUSAL_CODES` in
 * osUpgrade.controller); an unknown code falls back to the code itself rather
 * than to a sentence that would pretend to know.
 */
export const DEFAULT_REFUSAL: Record<LaunchRefusalCode, string> = {
  not_found: 'Not found.',
  not_routeros: 'Not a RouterOS device.',
  not_active: 'Identity not confirmed (device not active).',
  not_managed: 'Not managed: ObliWAN may read it but not change it.',
  device_busy: 'Another operation is running on this router.',
  in_rollout: 'Already part of a rollout.',
  version_unknown: 'Current version unknown: ObliWAN cannot prove this would be an update.',
  no_target: 'No target version.',
  major_differs: 'Other major RouterOS line (a migration, not an update).',
  already_current: 'Already at this version or newer.',
  concentrator: "Concentrator: its reboot would cut every site's tunnel. Not updated from this screen.",
};

export function useRefusalText(): (code: string) => string {
  const { t } = useTranslation();
  return (code) =>
    t(`fleetUpgrade.blocked.${code}`, {
      defaultValue: DEFAULT_REFUSAL[code as LaunchRefusalCode] ?? code,
    });
}
