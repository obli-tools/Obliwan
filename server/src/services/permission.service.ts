import { db } from '../db';
import type { PermissionLevel, UserPermissions, Capability } from '@obliwan/shared';
import {
  ALL_CAPABILITIES,
  expandCapabilities,
  ROLE_PERMISSION_SETS,
  PLATFORM_ONLY_CAPABILITIES,
  BY_NAME_ONLY_CAPABILITIES,
  LEGACY_TENANT_ROLE_ALIASES,
  sanitizeCapabilities,
} from '@obliwan/shared';
import { canWriteEverySite } from './teamScope.service';

/**
 * Team-based authorisation over the `device_groups` tree, plus the capability
 * resolver the RBAC middleware is built on.
 *
 * ── Capability derivation (migration 084: Obliance's model) ────────────────
 * `user_tenants.role` IS a `permission_sets.slug` (foreign key) and the
 * capabilities a role confers are the ones its ROW lists — read on every
 * resolution, joined onto the membership in the same query, so a tick in the
 * matrix screen is a grant at the next request (no cache to wait out, in the
 * web or the worker process). That row is GLOBAL: editing `user` edits it for
 * every tenant, which is why the set-write routes are platform-admin and
 * audited (permissionSet.service).
 *
 * One deliberate divergence from Obliance, fail-closed, and it is about
 * capabilities only:
 *  - the tenant `admin` is NOT a capability bypass: it resolves its row like
 *    everybody else (Obliance's bypass would hand a tenant admin
 *    `tenants.manage`, `users.manage`, `credential.manage`); PLATFORM_ONLY
 *    capabilities are stripped from EVERY source (a set row edited by hand, a
 *    team pin, an Obligate assertion), and BY_NAME_ONLY ones
 *    (`credential.manage`) from the role's set: those come by name or not at
 *    all (shared capabilities.ts).
 * WHERE follows Obliance exactly since migration 087: only the platform admin
 * (`users.role`) sees the whole tenant; the tenant `admin` sees the groups,
 * devices and sites its teams cover, like everybody else.
 *
 * This module answers WHAT; WHERE (devices, sites, groups covered by the
 * user's teams) is services/teamScope.service.ts, except the group closure
 * reads below, which predate it.
 *
 * ── Group permission tenant scope (critical) ───────────────────────────────
 * `getGroupPermission` read `device_groups` by id with no `where tenant_id`
 * and returned 'ro' for any `is_general` group. Since every tenant owns
 * general groups, `GET /api/groups/<id>` walked the whole id space of every
 * customer. Tenant scoping is now the FIRST thing every entry point does, and
 * `_getGroupPermissionViaClosure` refuses to inherit through an ancestor that
 * belongs to another tenant, so a forged `group_closure` edge grants nothing.
 */

// ──────────────────────────────────────────────────────────────────────────
// Capability derivation
// ──────────────────────────────────────────────────────────────────────────

const PLATFORM_ONLY = new Set<string>(PLATFORM_ONLY_CAPABILITIES);
const BY_NAME_ONLY = new Set<string>(BY_NAME_ONLY_CAPABILITIES);

function parseList(raw: unknown): unknown[] {
  let arr: unknown = raw;
  if (typeof arr === 'string') {
    try { arr = JSON.parse(arr); } catch { return []; }
  }
  return Array.isArray(arr) ? arr : [];
}

/**
 * What a permission-set row confers as a ROLE: its known capabilities, minus
 * PLATFORM_ONLY and BY_NAME_ONLY — whatever the row says. The set-write API
 * refuses both; this makes a row edited by SQL harmless too.
 */
export function roleSetCapabilities(raw: unknown): Capability[] {
  return sanitizeCapabilities(parseList(raw)).filter((c) => !PLATFORM_ONLY.has(c) && !BY_NAME_ONLY.has(c));
}

/**
 * @deprecated SEED ORACLE, NOT THE RUNTIME. What each builtin role held when
 * migration 084 seeded it (`ROLE_PERMISSION_SETS`), plus the retired `member`
 * key aliased to `user`. The runtime reads the `permission_sets` row, which an
 * operator may re-tick; kept for the older harnesses that compare against it.
 */
export const TENANT_ROLE_CAPABILITIES: Record<string, Capability[]> = (() => {
  const out: Record<string, Capability[]> = {};
  for (const s of ROLE_PERMISSION_SETS) out[s.slug] = roleSetCapabilities(s.capabilities);
  for (const [legacy, now] of Object.entries(LEGACY_TENANT_ROLE_ALIASES)) out[legacy] = out[now] ?? [];
  return out;
})();

/** @deprecated seed lookup (see TENANT_ROLE_CAPABILITIES); [] for anything else. */
export function capabilitiesForTenantRole(role: unknown): Capability[] {
  return typeof role === 'string' && Object.prototype.hasOwnProperty.call(TENANT_ROLE_CAPABILITIES, role)
    ? TENANT_ROLE_CAPABILITIES[role]
    : [];
}

// ──────────────────────────────────────────────────────────────────────────

interface GroupScopeRow {
  is_general: boolean;
  tenant_id: number;
}

/**
 * Cross-tenant reads are legitimate ONLY for a caller the middleware has
 * positively established as a PLATFORM ADMIN (`users.role = 'admin'`, re-read
 * from the database) operating on the master tenant (master-tenant
 * membership alone no longer grants it).
 * Never derive `masterView` from `req.session.currentTenantId` alone.
 */
export interface TenantScope {
  tenantId: number;
  /** Set by `requireTenant` from the tenant AND the database role, never the session number alone. */
  masterView?: boolean;
}

export const permissionService = {
  /**
   * Get all team IDs a user belongs to.
   *
   * `tenantId` is optional ONLY because `UserPermissions.teams` is a display
   * list. Every authorisation decision must pass it.
   */
  async getUserTeamIds(userId: number, tenantId?: number): Promise<number[]> {
    const q = db('team_memberships')
      .where('team_memberships.user_id', userId)
      .select('team_memberships.team_id');
    if (tenantId != null) {
      q.join('user_teams', 'user_teams.id', 'team_memberships.team_id')
        .where('user_teams.tenant_id', tenantId);
    }
    const rows = await q;
    return rows.map((r) => r.team_id as number);
  },

  /**
   * Check if user (via any of their teams IN THIS TENANT) has canCreate.
   */
  async canCreate(userId: number, isAdmin: boolean, tenantId?: number): Promise<boolean> {
    if (isAdmin) return true;
    const q = db('user_teams')
      .join('team_memberships', 'user_teams.id', 'team_memberships.team_id')
      .where('team_memberships.user_id', userId)
      .where('user_teams.can_create', true);
    if (tenantId != null) q.where('user_teams.tenant_id', tenantId);
    const row = await q.first();
    return !!row;
  },

  /**
   * Effective permission for a user on a group, within a tenant.
   * Direct grants plus anything inherited from an ancestor via the closure
   * table — never across a tenant boundary.
   */
  async getGroupPermission(
    userId: number,
    groupId: number,
    isAdmin: boolean,
    scope: TenantScope,
  ): Promise<PermissionLevel | null> {
    const group = await db('device_groups')
      .where({ id: groupId })
      .first<GroupScopeRow | undefined>('is_general', 'tenant_id');
    if (!group) return null;

    // Short-circuit BEFORE anything else, `is_general` included.
    // A group of another tenant is not "readable but not writable": it does
    // not exist as far as this caller is concerned.
    if (group.tenant_id !== scope.tenantId && scope.masterView !== true) return null;

    // Platform admin. Checked AFTER the tenant gate so an admin positioned on
    // tenant B cannot follow a stale link into tenant A's tree unless the
    // master-tenant view has been explicitly established by the middleware.
    if (isAdmin) return 'rw';

    const level = await this._getGroupPermissionViaClosure(userId, groupId, group.tenant_id);
    if (level) return level;

    // READ without a grant on the group itself (084). Never a write: editing,
    // moving and deleting a group stay a platform admin's or an 'rw' team
    // grant's (Obliance's requireGroupWrite), the tenant admin role included.
    //  - a general group is readable by every member (is_general);
    //  - a group above a device one of the user's teams reaches directly, so
    //    the tree can be navigated down to it (Obliance getVisibleGroupIds).
    // The tenant `admin` role no longer reads every group (087): like in
    // Obliance it sees the groups its teams cover.
    if (group.is_general) return 'ro';
    if ((await this._groupsAboveGrantedDevices(userId, group.tenant_id)).includes(groupId)) return 'ro';
    return null;
  },

  async canReadGroup(
    userId: number,
    groupId: number,
    isAdmin: boolean,
    scope: TenantScope,
  ): Promise<boolean> {
    const perm = await this.getGroupPermission(userId, groupId, isAdmin, scope);
    return perm !== null;
  },

  async canWriteGroup(
    userId: number,
    groupId: number,
    isAdmin: boolean,
    scope: TenantScope,
  ): Promise<boolean> {
    const perm = await this.getGroupPermission(userId, groupId, isAdmin, scope);
    return perm === 'rw';
  },

  /**
   * All group IDs visible to a user IN THIS TENANT: groups they hold a grant
   * on, every descendant of those, every ancestor (so the tree can be
   * navigated down to them), and this tenant's general groups. 'all' for
   * platform admins.
   */
  async getVisibleGroupIds(
    userId: number,
    isAdmin: boolean,
    scope: TenantScope,
  ): Promise<number[] | 'all'> {
    if (isAdmin) return 'all';
    // The tenant `admin` role sees the groups its teams cover, like everybody
    // else (087 — it used to see every group of its tenant).

    // Confined to the scope's tenant unless `masterView` — and `masterView`
    // requires `users.role = 'admin'`, an account the line
    // above answers 'all' and groups.controller answers before it ever calls
    // this. So on this path it is false in practice: a member of the master
    // tenant, plain or tenant-admin, sees only the master tenant's own groups.
    // The test stays so this function is safe on its own if a caller changes.
    // `is_general` used to be read unfiltered.
    const generalQ = db('device_groups').where({ is_general: true }).select('id');
    if (scope.masterView !== true) generalQ.where('tenant_id', scope.tenantId);
    const generalRows = await generalQ;
    const generalIds: number[] = generalRows.map((r) => r.id as number);

    const teamIds = await this.getUserTeamIds(
      userId,
      scope.masterView === true ? undefined : scope.tenantId,
    );
    if (teamIds.length === 0) return generalIds;
    // Groups holding a device granted directly, and their ancestors (084).
    for (const id of await this._groupsAboveGrantedDevices(userId, scope.tenantId)) generalIds.push(id);

    // Groups with a direct grant. Joined onto device_groups so a grant that
    // points at another tenant's group (stale row, hand-edited import) is
    // dropped here rather than expanded into a whole visible subtree.
    const permQ = db('team_permissions')
      .join('device_groups', 'device_groups.id', 'team_permissions.scope_id')
      .whereIn('team_permissions.team_id', teamIds)
      .where('team_permissions.scope', 'group')
      .select('team_permissions.scope_id');
    if (scope.masterView !== true) permQ.where('device_groups.tenant_id', scope.tenantId);
    const groupPerms = await permQ;
    const permGroupIds: number[] = groupPerms.map((r) => r.scope_id as number);

    const ids = new Set<number>(generalIds);
    if (permGroupIds.length > 0) {
      // Descendants (a grant on a group covers its whole subtree) and
      // ancestors (so the UI can render the path down to a granted group).
      // Both sides are re-joined onto device_groups and filtered by tenant:
      // A closure edge has been seen to straddle two tenants.
      const descQ = db('group_closure')
        .join('device_groups', 'device_groups.id', 'group_closure.descendant_id')
        .whereIn('group_closure.ancestor_id', permGroupIds)
        .select('group_closure.descendant_id');
      const ancQ = db('group_closure')
        .join('device_groups', 'device_groups.id', 'group_closure.ancestor_id')
        .whereIn('group_closure.descendant_id', permGroupIds)
        .select('group_closure.ancestor_id');
      if (scope.masterView !== true) {
        descQ.where('device_groups.tenant_id', scope.tenantId);
        ancQ.where('device_groups.tenant_id', scope.tenantId);
      }
      for (const r of await descQ) ids.add(r.descendant_id as number);
      for (const r of await ancQ) ids.add(r.ancestor_id as number);
    }

    return [...ids];
  },

  /**
   * Build the full UserPermissions object for the current user.
   * Sent to the client on login/session check so the UI can adapt.
   */
  async getUserPermissions(
    userId: number,
    isAdmin: boolean,
    tenantId?: number,
  ): Promise<UserPermissions> {
    if (isAdmin) {
      return {
        canCreate: true, teams: [], permissions: {}, capabilities: [...ALL_CAPABILITIES], tenantWide: true, canCreateSites: true,
      };
    }

    // `getUserCapabilities` already returned [] without a
    // tenant, but the `permissions` map and the `teams` list built above it were
    // only filtered `if (tenantId != null)`, and `getUserTeamIds(userId,
    // undefined)` returns the teams of EVERY tenant. Reproduced: a user whose
    // memberships had just been revoked reconnected and `GET /api/auth/me`
    // handed back `teams:[1,2]` and `permissions:{"group:1":"rw","group:2":"rw"}`
    // — group 1 in Globex, group 2 in Acme — while `GET /api/groups` answered
    // 403. Ids only, and every read behind them 404s, but this is precisely the
    // class of defect the capability fix removed and left standing here.
    //
    // No tenant means no scope, and no scope means no authorisation of any kind.
    if (tenantId == null) {
      return { canCreate: false, teams: [], permissions: {}, capabilities: [] };
    }

    const teamIds = await this.getUserTeamIds(userId, tenantId);
    const canCreate = await this.canCreate(userId, false, tenantId);

    // The server authorises through the closure
    // (a grant on an ancestor covers the whole subtree) but this map used to
    // list only DIRECT grants, so the UI hid the edit button on every
    // descendant of a granted group and refused drag-and-drop on rows the API
    // would have accepted. Each grant is expanded over its descendants here:
    // the key format (`group:<id>`) does not change, so no client edit is
    // needed.
    const permissions: Record<string, PermissionLevel> = {};
    if (teamIds.length > 0) {
      const perms = await db('team_permissions')
        .whereIn('team_id', teamIds)
        .select('scope', 'scope_id', 'level');

      const bump = (key: string, level: PermissionLevel) => {
        const existing = permissions[key];
        if (!existing || (existing === 'ro' && level === 'rw')) permissions[key] = level;
      };

      const groupGrantIds = perms
        .filter((p) => p.scope === 'group')
        .map((p) => p.scope_id as number);
      const descendantsByAncestor = new Map<number, number[]>();
      if (groupGrantIds.length > 0) {
        const rowsQ = db('group_closure')
          .join('device_groups', 'device_groups.id', 'group_closure.descendant_id')
          .whereIn('group_closure.ancestor_id', groupGrantIds)
          .select('group_closure.ancestor_id', 'group_closure.descendant_id');
        if (tenantId != null) rowsQ.where('device_groups.tenant_id', tenantId);
        for (const r of await rowsQ) {
          const anc = r.ancestor_id as number;
          const list = descendantsByAncestor.get(anc);
          if (list) list.push(r.descendant_id as number);
          else descendantsByAncestor.set(anc, [r.descendant_id as number]);
        }
      }

      for (const p of perms) {
        if (p.scope === 'group') {
          // The closure always contains (id, id, 0), so the granted group
          // itself is in this list — unless the row is corrupt, or the
          // grant points outside the tenant, in which case dropping it is the
          // correct outcome.
          for (const descId of descendantsByAncestor.get(p.scope_id as number) ?? []) {
            bump('group:' + descId, p.level as PermissionLevel);
          }
        } else {
          bump(p.scope + ':' + p.scope_id, p.level as PermissionLevel);
        }
      }
    }

    const capabilities = await this.getUserCapabilities(userId, false, tenantId);

    // WHERE (087, Obliance): only the platform admin (returned above) sees the
    // whole tenant; everybody else — the tenant `admin` included — what
    // `permissions` lists (teamScope.service).
    const tenantRole = await db('user_tenants')
      .where({ user_id: userId, tenant_id: tenantId })
      .first<{ role: string } | undefined>('role');
    const canCreateSites = await canWriteEverySite(userId, false, tenantId);

    return {
      canCreate,
      teams: teamIds,
      permissions,
      capabilities,
      tenantWide: false,
      tenantRole: tenantRole?.role ?? null,
      canCreateSites,
    };
  },

  /**
   * Resolve the feature capabilities a user effectively holds for a tenant.
   *
   * Three sources, unioned:
   *   1. the role's `permission_sets` row (084), minus PLATFORM_ONLY and
   *      BY_NAME_ONLY (`roleSetCapabilities`);
   *   2. capabilities pinned onto `team_permissions` rows of the user's teams
   *      IN THIS TENANT (a by-name grant from a local admin);
   *   3. `user_tenant_capabilities` — the per-(user, tenant) list asserted by
   *      Obligate (migration 003).
   *
   * `isAdmin` here means PLATFORM admin (`users.role = 'admin'`), which is a
   * different column from `user_tenants.role`; `requireRole('admin')` reads the
   * same one. A tenant admin resolves its set like everybody else.
   *
   * Without a tenant there is no capability at all. The old code fell back to
   * "whatever is pinned on any of your teams, in any tenant", which handed a
   * user their tenant-A capabilities while they operated on tenant B.
   */
  async getUserCapabilities(
    userId: number,
    isAdmin: boolean,
    tenantId?: number,
  ): Promise<Capability[]> {
    if (isAdmin) return [...ALL_CAPABILITIES];
    if (tenantId == null) return [];

    const held = new Set<string>();

    // 1. The role's permission set, joined onto the membership: one query,
    //    read live (084). A role whose row vanished grants nothing (the FK
    //    makes that unreachable; this keeps it harmless).
    const membership = await db('user_tenants as ut')
      .leftJoin('permission_sets as ps', 'ps.slug', 'ut.role')
      .where({ 'ut.user_id': userId, 'ut.tenant_id': tenantId })
      .first<{ role: string; capabilities: unknown } | undefined>('ut.role', 'ps.capabilities');
    if (!membership) return []; // not a member of this tenant: nothing at all.
    for (const c of roleSetCapabilities(membership.capabilities)) held.add(c);

    // 2. Capabilities pinned onto this tenant's team grants.
    const teamIds = await this.getUserTeamIds(userId, tenantId);
    if (teamIds.length > 0) {
      const rows = await db('team_permissions')
        .whereIn('team_id', teamIds)
        .whereNotNull('capabilities')
        .select('capabilities');
      for (const r of rows) {
        for (const c of this._parseCapabilities((r as { capabilities: unknown }).capabilities)) {
          held.add(c);
        }
      }
    }

    // 3. Federated per-user capabilities (Obligate assertion).
    const fed = await db('user_tenant_capabilities')
      .where({ user_id: userId, tenant_id: tenantId })
      .first<{ capabilities: unknown } | undefined>('capabilities');
    if (fed) for (const c of this._parseCapabilities(fed.capabilities)) held.add(c);

    // Only surface capabilities we actually recognise and enforce, then close the
    // set under CAPABILITY_IMPLIES. The expansion happens HERE — at resolution —
    // and never at storage: a grant stays exactly what an administrator typed.
    // Without it, a hand-made set with CHANGE_APPLY and no PLAN_CREATE can queue
    // a change and then read neither the job, nor its steps, nor the kill switch.
    // PLATFORM_ONLY from no source at all: nothing tenant-scoped honours them
    // (`requireRole('admin')` does), and a pin or an assertion of one would
    // only make a screen offer what the server refuses.
    return expandCapabilities(ALL_CAPABILITIES.filter((c) => held.has(c) && !PLATFORM_ONLY.has(c)));
  },

  // -- Private helpers --

  /** Parse + sanitise a jsonb capability column (string or already parsed). */
  _parseCapabilities(raw: unknown): Capability[] {
    let arr: unknown;
    try {
      arr = typeof raw === 'string' ? JSON.parse(raw) : raw;
    } catch {
      return [];
    }
    // Never trust a persisted or federated list blindly.
    return Array.isArray(arr) ? sanitizeCapabilities(arr) : [];
  },

  /**
   * Highest group permission for a user on a group, considering every ancestor
   * through the closure table — but only ancestors that live in `tenantId`,
   * and only grants held by a team of that same tenant.
   *
   * The tenant joins are the applicative half of the closure-edge fix: migration 001
   * now makes a cross-tenant `parent_id` impossible, yet `group_closure`
   * carries no such constraint, so an edge inserted by an older build (or
   * directly in SQL) could still hand tenant A's teams a grant over tenant B's
   * group. Reading through it stops here.
   */
  async _getGroupPermissionViaClosure(
    userId: number,
    groupId: number,
    tenantId: number,
  ): Promise<PermissionLevel | null> {
    const rows = await db('team_permissions')
      .join('team_memberships', 'team_permissions.team_id', 'team_memberships.team_id')
      .join('user_teams', 'user_teams.id', 'team_permissions.team_id')
      .join('group_closure', 'group_closure.ancestor_id', 'team_permissions.scope_id')
      .join('device_groups', 'device_groups.id', 'group_closure.ancestor_id')
      .where('team_memberships.user_id', userId)
      .where('team_permissions.scope', 'group')
      .where('group_closure.descendant_id', groupId)
      .where('device_groups.tenant_id', tenantId)
      .where('user_teams.tenant_id', tenantId)
      .select('team_permissions.level');

    if (rows.length === 0) return null;
    return rows.some((r) => r.level === 'rw') ? 'rw' : 'ro';
  },

  /**
   * Groups (and their ancestors) that hold a device one of the user's teams of
   * `tenantId` grants DIRECTLY — the navigation path down to it. Read only.
   */
  async _groupsAboveGrantedDevices(userId: number, tenantId: number): Promise<number[]> {
    const rows = (await db('team_permissions as tp')
      .join('team_memberships as tm', 'tm.team_id', 'tp.team_id')
      .join('user_teams as ut', 'ut.id', 'tp.team_id')
      .join('devices as d', 'd.id', 'tp.scope_id')
      .join('group_closure as gc', 'gc.descendant_id', 'd.group_id')
      .join('device_groups as g', 'g.id', 'gc.ancestor_id')
      .where('tm.user_id', userId)
      .where('ut.tenant_id', tenantId)
      .where('tp.scope', 'device')
      .where('d.tenant_id', tenantId)
      .where('g.tenant_id', tenantId)
      .distinct('gc.ancestor_id')) as Array<{ ancestor_id: number }>;
    return rows.map((r) => Number(r.ancestor_id));
  },

  _highest(a: PermissionLevel | null, b: PermissionLevel | null): PermissionLevel | null {
    if (a === 'rw' || b === 'rw') return 'rw';
    if (a === 'ro' || b === 'ro') return 'ro';
    return null;
  },
};
