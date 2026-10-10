import { useTranslation } from 'react-i18next';
import { Users } from 'lucide-react';
import { useAuthStore } from '@/store/authStore';

/**
 * Tells a member who belongs to no team of this workspace why every list is
 * empty. Since migration 087 (Obliance's rule) nobody but a platform admin sees
 * the whole workspace: a tenant admin with no team sees nothing either, and an
 * empty screen with no explanation reads as "the fleet is gone".
 *
 * Renders nothing for a platform admin, while the permissions are loading
 * (`permissions === null`: never claim "no team" about an answer not yet
 * received), and for anyone who belongs to at least one team.
 */
export function NoTeamBanner() {
  const { t } = useTranslation();
  const user = useAuthStore((s) => s.user);
  const permissions = useAuthStore((s) => s.permissions);

  if (!user || user.role === 'admin') return null;
  if (!permissions || permissions.tenantWide === true || permissions.teams.length > 0) return null;

  return (
    <div
      role="status"
      className="mb-5 flex items-start gap-2 rounded-lg border border-status-warn/40 bg-status-warn/5 p-3 text-xs text-text-secondary"
    >
      <Users size={14} className="mt-0.5 shrink-0 text-status-warn" />
      <span>{t('teamScope.noTeamBanner')}</span>
    </div>
  );
}
