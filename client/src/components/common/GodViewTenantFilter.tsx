import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useGodView, useGodViewStore } from '@/store/godViewStore';
import { useTenantStore } from '@/store/tenantStore';
import { cn } from '@/utils/cn';

/**
 * The tenant filter of the GOD VIEW: "every tenant" or one of them. Shown only
 * while the API reports the god view (store/godViewStore.ts). The choice is
 * one per browser tab and rides on every request as `?filterTenantId=`
 * (api/client.ts), so every god-view list narrows the same way; the server
 * ignores it outside the god view.
 *
 * `onChange` lets the page reload what it shows; pages that read through the
 * filter in an effect can depend on `useGodViewStore(s => s.filterTenantId)`
 * instead.
 */
export function GodViewTenantFilter({
  onChange,
  allowAll = true,
  className,
}: {
  onChange?: (tenantId: number | null) => void;
  /** False on a screen that shows ONE tenant's report (the reconciliation). */
  allowAll?: boolean;
  className?: string;
}) {
  const { t } = useTranslation();
  const godView = useGodView();
  const filterTenantId = useGodViewStore((s) => s.filterTenantId);
  const setFilterTenantId = useGodViewStore((s) => s.setFilterTenantId);
  const tenants = useTenantStore((s) => s.tenants);
  const fetchTenants = useTenantStore((s) => s.fetchTenants);

  useEffect(() => {
    if (godView && tenants.length === 0) void fetchTenants();
  }, [godView, tenants.length, fetchTenants]);

  if (!godView) return null;
  return (
    <label className={cn('inline-flex items-center gap-1.5 text-xs text-text-muted', className)}>
      <span>{t('godView.tenant')}</span>
      <select
        className="rounded-md border border-border bg-bg-primary px-2 py-1 text-xs text-text-primary"
        value={filterTenantId ?? ''}
        onChange={(e) => {
          const next = e.target.value === '' ? null : Number(e.target.value);
          setFilterTenantId(next);
          onChange?.(next);
        }}
      >
        {allowAll && <option value="">{t('godView.allTenants')}</option>}
        {!allowAll && filterTenantId === null && <option value="">{t('godView.pickTenant')}</option>}
        {tenants.map((tn) => (
          <option key={tn.id} value={tn.id}>
            {tn.name}
          </option>
        ))}
      </select>
    </label>
  );
}
