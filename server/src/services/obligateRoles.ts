import type { Knex } from 'knex';
import {
  BUILTIN_TENANT_ROLES,
  FALLBACK_TENANT_ROLE,
  LEGACY_TENANT_ROLE_ALIASES,
  TENANT_ADMIN_ROLE,
} from '@obliwan/shared';
import { db } from '../db';
import { logger } from '../utils/logger';

/**
 * Obligate ⇄ ObliWAN tenant roles (migration 084, operator decisions of
 * 2026-10-07).
 *
 * OBLIGATE IS THE SOURCE OF TRUTH for an SSO user's role, per app and per
 * tenant: its UI lists, for each app, the roles that app ADVERTISES
 * (`GET /api/auth/app-info` → `permissionSets`), and the assertion carries,
 * for each tenant, the slug the operator picked there. ObliWAN applies that
 * slug AS-IS. It advertises its permission sets — the four builtin roles
 * (admin, user, « Chargé(e) de compte », viewer) first, then any custom set
 * created in the matrix — exactly as Obliance does.
 *
 * Three cases besides "a slug ObliWAN knows":
 *  - `member` — the value ObliWAN's own callback produced before this module
 *    ("any non-admin role"), and the value an Obligate configured against the
 *    old app-info may still send. It carries no information beyond "not
 *    admin", so it NEVER widens a local role: an existing non-admin membership
 *    (account_manager, viewer, a custom set) is KEPT; a new membership, or an
 *    `admin` being demoted, becomes `user` — exactly the pre-084 behaviour,
 *    generalised from the one role (account_manager) it used to protect.
 *  - an unknown slug (a role deleted here, a typo in Obligate) → `viewer`, the
 *    narrowest builtin, with a warning. Never `user`: THE flaw this module
 *    replaces is the callback's `t.role === 'admin' ? 'admin' : 'member'`,
 *    which turned an Obligate `viewer` into a full operator.
 *  - no role at all → treated as unknown: `viewer`.
 *
 * ┌─ WIRING (obligateCallback.routes.ts is owned by another change) ─────────┐
 * │ The callback must call `applyObligateTenantRole(trx, userId, tenantId,    │
 * │ t.role)` with the RAW asserted role, instead of collapsing it to          │
 * │ admin/member and calling `tenantService.upsertSsoMembership`; and its     │
 * │ app-info must spread `await obligateAppInfoRoles()` into its `data`.      │
 * │ Until then `tenantService.upsertSsoMembership` delegates here, so the     │
 * │ collapsed `member` it still receives is handled by the `member` rule.     │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

/** Platform roles (`users.role`) — what app-info has always advertised as `roles`. */
export const OBLIGATE_PLATFORM_ROLES = ['admin', 'user'] as const;

export type ObligateRoleReason =
  | 'asserted'          // a slug ObliWAN knows, applied as-is
  | 'legacy_alias'      // `member` with nothing narrower to keep → user (or admin demoted)
  | 'legacy_kept_local' // `member` over a narrower local non-admin role → kept
  | 'unknown_fallback'; // unknown / empty → viewer

export interface ResolvedTenantRole {
  role: string;
  reason: ObligateRoleReason;
}

/** Trim + lower-case; '' when absent or not a string. */
export function normaliseObligateRole(raw: unknown): string {
  return typeof raw === 'string' ? raw.trim().toLowerCase() : '';
}

/**
 * THE rule, pure: the slug to store for a tenant, given what Obligate asserted,
 * the membership's current role (null when none) and the slugs that exist.
 */
export function resolveObligateTenantRole(
  asserted: unknown,
  existingRole: string | null,
  knownSlugs: ReadonlySet<string>,
): ResolvedTenantRole {
  const slug = normaliseObligateRole(asserted);
  if (slug && Object.prototype.hasOwnProperty.call(LEGACY_TENANT_ROLE_ALIASES, slug) && !knownSlugs.has(slug)) {
    if (existingRole && existingRole !== TENANT_ADMIN_ROLE && knownSlugs.has(existingRole)) {
      return { role: existingRole, reason: 'legacy_kept_local' };
    }
    return { role: LEGACY_TENANT_ROLE_ALIASES[slug], reason: 'legacy_alias' };
  }
  if (slug && knownSlugs.has(slug)) return { role: slug, reason: 'asserted' };
  return { role: FALLBACK_TENANT_ROLE, reason: 'unknown_fallback' };
}

async function knownSlugs(q: Knex | Knex.Transaction): Promise<Set<string>> {
  return new Set(((await q('permission_sets').pluck('slug')) as string[]).map(String));
}

/**
 * Writes the membership for one asserted tenant and returns what was stored.
 * Runs inside the callback's transaction, so the role, the team memberships
 * and the federated capabilities of one login land together.
 */
export async function applyObligateTenantRole(
  trx: Knex.Transaction,
  userId: number,
  tenantId: number,
  asserted: unknown,
): Promise<ResolvedTenantRole> {
  const existing = (await trx('user_tenants')
    .where({ user_id: userId, tenant_id: tenantId })
    .first('role')) as { role: string } | undefined;
  const resolved = resolveObligateTenantRole(asserted, existing?.role ?? null, await knownSlugs(trx));
  if (resolved.reason === 'unknown_fallback') {
    logger.warn(
      { userId, tenantId, asserted: normaliseObligateRole(asserted).slice(0, 64) || null },
      'Obligate SSO: tenant role unknown to ObliWAN — membership set to viewer',
    );
  }
  await trx('user_tenants')
    .insert({ user_id: userId, tenant_id: tenantId, role: resolved.role })
    .onConflict(['user_id', 'tenant_id'])
    .merge({ role: resolved.role });
  return resolved;
}

/**
 * The role half of `GET /api/auth/app-info`: platform roles, and the
 * permission sets Obligate offers per tenant (slug + label), builtin first.
 */
export async function obligateAppInfoRoles(): Promise<{
  roles: string[];
  permissionSets: Array<{ slug: string; name: string; isDefault: boolean; description: string | null }>;
}> {
  const rows = (await db('permission_sets').select('slug', 'name', 'is_default', 'description')) as Array<{
    slug: string; name: string; is_default: boolean; description: string | null;
  }>;
  const order = new Map<string, number>(BUILTIN_TENANT_ROLES.map((s, i) => [s, i]));
  rows.sort((a, b) => (order.get(a.slug) ?? 99) - (order.get(b.slug) ?? 99) || a.name.localeCompare(b.name));
  return {
    roles: [...OBLIGATE_PLATFORM_ROLES],
    permissionSets: rows.map((r) => ({
      slug: r.slug,
      name: r.name,
      isDefault: r.is_default === true,
      description: r.description ?? null,
    })),
  };
}
