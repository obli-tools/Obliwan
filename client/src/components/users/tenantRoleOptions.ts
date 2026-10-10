import { useEffect, useState } from 'react';
import { BUILTIN_TENANT_ROLES } from '@obliwan/shared';
import type { TenantRole } from '@obliwan/shared';
import { permissionSetsApi } from '@/api/permissionSets.api';

/**
 * The tenant-role picker. Since migration 084 a tenant role IS a permission
 * set (`user_tenants.role` = `permission_sets.slug`): the four builtin roles —
 * shared by every tenant, not deletable — then any custom set created in the
 * matrix (Users → Permission sets). The server validates a role against the
 * sets that exist, never against this list.
 *
 * The hints say what each role may NOT do as much as what it may. WHAT a role
 * may do is its set; WHERE is the user's teams — for `admin` too since
 * migration 087 (Obliance's rule: only the PLATFORM admin sees a whole
 * workspace without a team).
 *
 * Shared by BOTH screens that write `user_tenants.role` — the user form
 * (AdminUsersPage) and a workspace's member list (AdminTenantsPage).
 */
export interface TenantRoleOption {
  role: TenantRole;
  labelKey: string;
  label: string;
  hintKey: string;
  hint: string;
  builtin: boolean;
}

/** The four builtin roles, widest first (BUILTIN_TENANT_ROLES order). */
export const TENANT_ROLE_OPTIONS: ReadonlyArray<TenantRoleOption> = [
  {
    role: 'admin',
    labelKey: 'users.tenantRole.admin',
    label: 'Admin',
    hintKey: 'users.tenantRole.adminHint',
    hint: 'Every capability of the workspace (applies and approves changes, approves top-ups, reveals secrets, reorders and configures groups) on what its teams cover.',
    builtin: true,
  },
  {
    role: 'user',
    labelKey: 'users.tenantRole.user',
    label: 'User',
    hintKey: 'users.tenantRole.userHint',
    hint: 'Day-to-day fleet work on what their teams cover: devices, configuration snapshots, discoveries, plans, drift, queries. Applies no change.',
    builtin: true,
  },
  {
    role: 'account_manager',
    labelKey: 'users.tenantRole.accountManager',
    label: 'Account manager',
    hintKey: 'users.tenantRole.accountManagerHint',
    hint: 'Sites and their site variables, devices and their health, SIM lines (read only). Never writes to a device, sees no secret, buys no top-up.',
    builtin: true,
  },
  {
    role: 'viewer',
    labelKey: 'users.tenantRole.viewer',
    label: 'Viewer',
    hintKey: 'users.tenantRole.viewerHint',
    hint: 'Consultation of what their teams cover. No configuration snapshot, no write of any kind.',
    builtin: true,
  },
];

// Keeps this list and the shared vocabulary in step at compile time.
const _builtinCheck: readonly string[] = BUILTIN_TENANT_ROLES;
void _builtinCheck;

/**
 * Builtin roles + the custom sets the server knows (platform-admin screens
 * only: `/permission-sets` is platform admin). Falls back to the builtin four
 * when the list cannot be read.
 */
export function useTenantRoleOptions(): ReadonlyArray<TenantRoleOption> {
  const [options, setOptions] = useState<ReadonlyArray<TenantRoleOption>>(TENANT_ROLE_OPTIONS);
  useEffect(() => {
    let alive = true;
    permissionSetsApi
      .list()
      .then((sets) => {
        if (!alive) return;
        const builtin = new Set<string>(TENANT_ROLE_OPTIONS.map((o) => o.role));
        const custom: TenantRoleOption[] = sets
          .filter((s) => !builtin.has(s.slug))
          .map((s) => ({
            role: s.slug,
            labelKey: '',
            label: s.name,
            hintKey: '',
            hint: s.description ?? '',
            builtin: false,
          }));
        setOptions([...TENANT_ROLE_OPTIONS, ...custom]);
      })
      .catch(() => { /* builtin four only */ });
    return () => { alive = false; };
  }, []);
  return options;
}

/** Label / hint of an option, translated when builtin. */
export function roleOptionLabel(t: (k: string, d: string) => string, o: TenantRoleOption): string {
  return o.labelKey ? t(o.labelKey, o.label) : o.label;
}
export function roleOptionHint(t: (k: string, d: string) => string, o: TenantRoleOption): string {
  return o.hintKey ? t(o.hintKey, o.hint) : o.hint;
}
