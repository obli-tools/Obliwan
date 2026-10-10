import { useTranslation } from 'react-i18next';
import { Globe2 } from 'lucide-react';
import { cn } from '@/utils/cn';
import { useGodView } from '@/store/godViewStore';

/**
 * Whose row this is — the tenant column of a GOD-VIEW list (a platform admin
 * positioned on the master tenant sees every tenant's rows; the server tags
 * each with `tenantName`, server/src/utils/globalView.ts).
 *
 * Renders nothing when the row carries no tenant: a tenant's own lists are
 * never tagged, so the badge cannot appear outside the god view.
 */
export function TenantBadge({
  name,
  tenantId,
  className,
}: {
  name?: string | null;
  tenantId?: number | null;
  className?: string;
}) {
  if ((name === undefined || name === null || name === '') && (tenantId === undefined || tenantId === null)) return null;
  return (
    <span
      className={cn(
        'inline-flex max-w-[14rem] items-center truncate whitespace-nowrap rounded-full bg-accent/15 px-1.5 py-0.5 text-[10px] font-medium text-accent',
        className,
      )}
      title={name ?? undefined}
    >
      {name || `#${tenantId}`}
    </span>
  );
}

/**
 * The header of the tenant column, shown only in the god view (as the API
 * reports it). Pair it with `<GodViewTenantCell>` in each row.
 */
export function GodViewTenantHeader({ className }: { className?: string }) {
  const { t } = useTranslation();
  const godView = useGodView();
  if (!godView) return null;
  return <th className={cn('px-3 py-2 font-medium', className)}>{t('godView.tenant')}</th>;
}

/** The tenant cell of a god-view row (renders nothing outside the god view). */
export function GodViewTenantCell({
  name,
  tenantId,
  className,
}: {
  name?: string | null;
  tenantId?: number | null;
  className?: string;
}) {
  const godView = useGodView();
  if (!godView) return null;
  return (
    <td className={cn('px-3 py-2', className)}>
      <TenantBadge name={name} tenantId={tenantId} />
    </td>
  );
}

/**
 * The marker a page header shows while the god view is on: "Global view —
 * every tenant". Says what the lists below are, so nobody mistakes a fleet of
 * five customers for one.
 */
export function GodViewMarker({ className }: { className?: string }) {
  const { t } = useTranslation();
  const godView = useGodView();
  if (!godView) return null;
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-full border border-accent/40 bg-accent/10 px-2 py-0.5 text-[11px] font-medium text-accent',
        className,
      )}
      title={t('godView.badgeTitle')}
    >
      <Globe2 size={11} />
      {t('godView.active')}
    </span>
  );
}
