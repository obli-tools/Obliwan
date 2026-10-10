import type { Knex } from 'knex';
import { db } from '../db';
import { MASTER_TENANT_ID } from '@obliwan/shared';
import type { Tenant, TenantWithRole, TenantRole } from '@obliwan/shared';
import { destroyUserSessions } from '../utils/sessions';
import { applyObligateTenantRole } from './obligateRoles';

interface TenantRow {
  id: number;
  name: string;
  slug: string;
  created_at: Date;
  updated_at: Date;
}

interface UserRow {
  id: number;
  username: string;
  display_name: string | null;
  role: string;
  is_active: boolean;
  email: string | null;
}

function rowToTenant(row: TenantRow): Tenant {
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
  };
}

export const tenantService = {
  async getAll(): Promise<Tenant[]> {
    const rows = await db('tenants').select<TenantRow[]>('*').orderBy('id');
    return rows.map(rowToTenant);
  },

  async getById(id: number): Promise<Tenant | null> {
    const row = await db('tenants').where({ id }).first<TenantRow>();
    return row ? rowToTenant(row) : null;
  },

  async getBySlug(slug: string): Promise<Tenant | null> {
    const row = await db('tenants').where({ slug }).first<TenantRow>();
    return row ? rowToTenant(row) : null;
  },

  async create(data: { name: string; slug: string }): Promise<Tenant> {
    const [row] = await db('tenants')
      .insert({ name: data.name, slug: data.slug })
      .returning('*');
    return rowToTenant(row as TenantRow);
  },

  async update(id: number, data: { name?: string; slug?: string }): Promise<Tenant | null> {
    const [row] = await db('tenants')
      .where({ id })
      .update({ ...data, updated_at: db.fn.now() })
      .returning('*');
    return row ? rowToTenant(row as TenantRow) : null;
  },

  async delete(id: number): Promise<void> {
    await db('tenants').where({ id }).delete();
  },

  /** Returns the first tenant accessible by userId (lowest id). */
  async getFirstTenantForUser(userId: number): Promise<Tenant | null> {
    const row = await db('tenants')
      .join('user_tenants', 'tenants.id', 'user_tenants.tenant_id')
      .where('user_tenants.user_id', userId)
      .orderBy('tenants.id')
      .first<TenantRow & { role: string }>('tenants.*');
    return row ? rowToTenant(row) : null;
  },

  /**
   * THE tenants an account is placed on without a switch — written ONCE, here.
   * `resolveSessionTenantId()` below is its first element, and is called from
   * every place a session tenant is established or repaired: the local login
   * and the 2FA completion (auth/twoFactor controllers), the Obligate callback
   * after its slug matching, `/api/auth/me`, and `requireTenant` (which heals an
   * already-open platform-admin session without a re-login) — the Socket.io
   * handshake guard reaches it through `resolveCallerTenant()`, the gate it
   * shares with requireTenant (middleware/tenant.ts). The whole
   * list is what the cross-tenant notification surfaces cover (live alerts:
   * `GET /api/live-alerts/all`, mark-read and delete, and the Socket.io
   * notification rooms), so a platform admin placed on the master tenant by
   * step 2 hears that tenant's alerts instead of an empty feed.
   *
   *   1. the user's memberships (ascending tenant id) — anyone;
   *   2. otherwise, for a PLATFORM ADMIN only, the master tenant, if it exists;
   *   3. otherwise none: no current tenant, and `requireTenant` answers 403.
   *
   * The no-fallback rule still holds for everyone but a platform admin: there is no
   * `?? 1`, and a user with no membership gets no tenant. Step 2 is not that
   * fallback coming back, because for a platform admin tenant 1 grants nothing
   * the account did not already hold:
   *   - `requireTenant` already exempts platform admins from the membership
   *     row (any tenant, master included), and `POST /api/tenant/switch` already
   *     puts them on any tenant that exists — this resolves what one click
   *     would;
   *   - the god view (`req.masterView`) already requires `users.role = 'admin'`
   *     on top of the tenant being the master one, so a
   *     non-admin can never reach it through this function.
   * Without step 2 a platform admin whose SSO assertion names no local tenant
   * (a fresh install has only "Default") or who simply holds no membership row
   * was locked out of every tenant-scoped page, sites and devices included.
   *
   * The role is read HERE, from `users`, never taken from a caller: not from an
   * SSO assertion, not from a cookie, not from a request body. `is_active` is
   * read too, so a disabled admin is never handed a tenant by this path.
   */
  async resolveSessionTenantIds(userId: number): Promise<number[]> {
    const memberships = (await db('user_tenants')
      .join('tenants', 'tenants.id', 'user_tenants.tenant_id')
      .where('user_tenants.user_id', userId)
      .orderBy('tenants.id')
      .pluck('tenants.id')) as number[];
    if (memberships.length > 0) return memberships;

    const user = (await db('users').where({ id: userId }).first('role', 'is_active')) as
      | { role: string; is_active: boolean }
      | undefined;
    if (!user || !user.is_active || user.role !== 'admin') return [];

    const master = (await db('tenants').where({ id: MASTER_TENANT_ID }).first('id')) as
      | { id: number }
      | undefined;
    return master ? [MASTER_TENANT_ID] : [];
  },

  /**
   * The tenant a session is put on when it has none (or names one that no
   * longer exists): the first of `resolveSessionTenantIds()`, i.e. the first
   * membership, else — for an active platform admin only, role read from the
   * database — the master tenant, else `null`. See the list above for the
   * rule and why its admin step is safe.
   */
  async resolveSessionTenantId(userId: number): Promise<number | null> {
    const ids = await tenantService.resolveSessionTenantIds(userId);
    return ids[0] ?? null;
  },

  /** Returns all tenants accessible by userId, with tenant-level role. */
  async getTenantsForUser(userId: number): Promise<TenantWithRole[]> {
    const rows = await db('tenants')
      .join('user_tenants', 'tenants.id', 'user_tenants.tenant_id')
      .where('user_tenants.user_id', userId)
      .orderBy('tenants.id')
      .select<(TenantRow & { role: string })[]>('tenants.*', 'user_tenants.role');
    return rows.map((r) => ({ ...rowToTenant(r), role: r.role as TenantRole }));
  },

  /** Check if user has access to a specific tenant. */
  async userHasAccess(userId: number, tenantId: number): Promise<boolean> {
    const row = await db('user_tenants')
      .where({ user_id: userId, tenant_id: tenantId })
      .first('user_id');
    return !!row;
  },

  /**
   * `teamCount`: how many teams OF THIS TENANT the member belongs to. Since
   * migration 087 a tenant admin sees what its teams cover (like in Obliance),
   * so a member with a role and no team sees nothing: the admin screen flags it.
   */
  async getMembers(tenantId: number): Promise<(UserRow & { tenantRole: string; teamCount: number })[]> {
    return db('users')
      .join('user_tenants', 'users.id', 'user_tenants.user_id')
      .where('user_tenants.tenant_id', tenantId)
      .select<(UserRow & { tenantRole: string; teamCount: number })[]>(
        'users.id',
        'users.username',
        'users.display_name',
        'users.role',
        'users.is_active',
        'users.email',
        db.raw('user_tenants.role as "tenantRole"'),
        db.raw(
          '(SELECT COUNT(*) FROM team_memberships tm JOIN user_teams ut ON ut.id = tm.team_id ' +
            'WHERE tm.user_id = users.id AND ut.tenant_id = user_tenants.tenant_id)::int as "teamCount"',
        ),
      )
      .orderBy('users.username');
  },

  async addUser(tenantId: number, userId: number, role: TenantRole): Promise<void> {
    await db('user_tenants')
      .insert({ tenant_id: tenantId, user_id: userId, role })
      .onConflict(['user_id', 'tenant_id'])
      .merge({ role });
  },

  /**
   * The membership an Obligate assertion grants (obligateCallback.routes.ts),
   * written inside the caller's transaction.
   *
   * Since migration 084 this DELEGATES to `applyObligateTenantRole`
   * (services/obligateRoles.ts), which holds the whole rule: Obligate's slug is
   * applied as-is when ObliWAN knows it, an unknown one becomes `viewer`, and
   * the legacy `member` ("not admin", which the callback still produces until
   * it passes the raw role) keeps a local non-admin role and otherwise means
   * `user`. Kept so the callback compiles and behaves unchanged until it calls
   * the new module directly.
   */
  async upsertSsoMembership(
    trx: Knex.Transaction,
    userId: number,
    tenantId: number,
    asserted: string,
  ): Promise<void> {
    await applyObligateTenantRole(trx, userId, tenantId, asserted);
  },

  /**
   * Removing the membership row used to be ALL that
   * happened. `requireTenant` copied `currentTenantId` out of the session with
   * no re-check, so the removed user kept reading that tenant's groups,
   * settings, notification channels and live alerts until the cookie expired,
   * i.e. for up to seven days. The middleware now re-verifies membership on a
   * 10 s cache; the purge below closes even that window.
   */
  async removeUser(tenantId: number, userId: number): Promise<void> {
    await db('user_tenants').where({ tenant_id: tenantId, user_id: userId }).delete();
    await destroyUserSessions(userId);
  },

  async updateUserRole(tenantId: number, userId: number, role: TenantRole): Promise<void> {
    await db('user_tenants')
      .where({ tenant_id: tenantId, user_id: userId })
      .update({ role });
    // The tenant role is the permission set the runtime resolves (084): a
    // demotion from `admin` to `user` must not wait out a cached membership.
    await destroyUserSessions(userId);
  },
};
