import type { Knex } from 'knex';
import type { PermissionLevel } from '@obliwan/shared';
import { db } from '../db';

/**
 * WHERE a user may act — the team half of RBAC, exactly Obliance's model
 * (migration 084, « brique 12 »; the tenant admin aligned by migration 087).
 *
 * The tenant role (a permission set, permission.service) says WHAT a user may
 * do; this module says ON WHICH devices, sites and groups. A team holds grants
 * of level 'ro' (consultation) or 'rw' (modification) on:
 *
 *   - a GROUP — and therefore on every sub-group and every device filed under
 *     them (`group_closure`);
 *   - a DEVICE;
 *   - the UNGROUPED bucket (scope_id 0) — the tenant's devices filed under no
 *     group, and its sites that carry no device yet (a site has no group of
 *     its own; it is covered through its devices).
 *
 * A user sees what at least one of their teams of THAT tenant covers, at the
 * highest level any of them grants. ONE caller sees the whole tenant without a
 * team: the platform admin (`users.role = 'admin'` — Obliance's `isAdmin`,
 * which every WHERE check of Obliance reads; the god view on the master
 * tenant is the god-view port's business and is unchanged). The tenant
 * `admin` role is NOT tenant-wide since migration 087: like in Obliance it
 * holds every capability of its set (WHAT), on what its teams cover (WHERE);
 * with no team it sees nothing. 087 gave every tenant admin of the day a
 * transition team (rw on the root groups and on the ungrouped devices) so
 * nobody lost access on the day it landed. Group WRITES follow Obliance to
 * the letter: a platform admin or a team 'rw' on the group
 * (`requireGroupWrite`).
 *
 * Every query here is tenant-bound twice: the object's tenant and the TEAM's
 * tenant (`user_teams.tenant_id`), and a group grant only inherits through
 * ancestors of the same tenant — a forged closure edge grants nothing (the
 * same discipline as permission.service `_getGroupPermissionViaClosure`).
 *
 * SITES: read = at least one of its devices is readable (or, device-less, the
 * ungrouped grant); write = EVERY one of its devices is writable (or,
 * device-less, an 'rw' ungrouped grant). A site record is shared by all its
 * routers; a team that owns one of them does not get to rename or delete the
 * place the others live in. Only the site's OWN tenant's devices count: a
 * device of another tenant filed on it (an anomaly the deployment view flags)
 * neither covers it nor hides it.
 */

export type Level = PermissionLevel;

const LEVEL_RANK: Record<Level, number> = { ro: 1, rw: 2 };

export function highest(a: Level | null, b: Level | null): Level | null {
  if (a === 'rw' || b === 'rw') return 'rw';
  if (a === 'ro' || b === 'ro') return 'ro';
  return null;
}

export function satisfies(held: Level | null, wanted: Level): boolean {
  return held !== null && LEVEL_RANK[held] >= LEVEL_RANK[wanted];
}

/** The tenant role of a membership, or null when the user is not a member. */
export async function tenantRoleOf(userId: number, tenantId: number): Promise<string | null> {
  const row = await db('user_tenants')
    .where({ user_id: userId, tenant_id: tenantId })
    .first<{ role: string } | undefined>('role');
  return row?.role ?? null;
}

/**
 * Does this caller see the whole tenant without a team? The platform admin,
 * and nobody else (migration 087, Obliance's rule: `isAdmin` there is
 * `users.role`). Not the tenant `admin` role, not a custom set whatever it
 * ticks: scope is the teams' business, not the matrix's. The signature keeps
 * the user and the tenant so a caller does not change when the rule does.
 */
export async function isTenantWide(_userId: number, isPlatformAdmin: boolean, _tenantId: number): Promise<boolean> {
  return isPlatformAdmin === true;
}

// ── Grant subqueries ────────────────────────────────────────────────────────

/** `team_permissions` rows of the user's teams of `tenantId`, at least `level`. */
function grantsOf(q: Knex.QueryBuilder, userId: number, tenantId: number, level: Level): Knex.QueryBuilder {
  q.from('team_permissions as tp')
    .join('team_memberships as tm', 'tm.team_id', 'tp.team_id')
    .join('user_teams as ut', 'ut.id', 'tp.team_id')
    .where('tm.user_id', userId)
    .where('ut.tenant_id', tenantId);
  if (level === 'rw') q.where('tp.level', 'rw');
  return q;
}

/**
 * `SELECT devices.id` of `tenantId` the user reaches at `level` or above
 * through a team — a subquery, for `whereIn('d.id', …)` in a list read, so a
 * paginated list stays paginated over what the user may see.
 */
export function visibleDeviceIdsQuery(userId: number, tenantId: number, level: Level = 'ro'): Knex.QueryBuilder {
  return db('devices as vd')
    .select('vd.id')
    .where('vd.tenant_id', tenantId)
    .andWhere((w) => {
      w.whereExists(function direct(this: Knex.QueryBuilder) {
        grantsOf(this.select(db.raw('1')), userId, tenantId, level)
          .where('tp.scope', 'device')
          .whereRaw('tp.scope_id = vd.id');
      })
        .orWhere((g) => {
          g.whereNotNull('vd.group_id').whereExists(function viaGroup(this: Knex.QueryBuilder) {
            grantsOf(this.select(db.raw('1')), userId, tenantId, level)
              .join('group_closure as gc', 'gc.ancestor_id', 'tp.scope_id')
              .join('device_groups as ag', 'ag.id', 'gc.ancestor_id')
              .where('tp.scope', 'group')
              .where('ag.tenant_id', tenantId)
              .whereRaw('gc.descendant_id = vd.group_id');
          });
        })
        .orWhere((u) => {
          u.whereNull('vd.group_id').whereExists(function ungrouped(this: Knex.QueryBuilder) {
            grantsOf(this.select(db.raw('1')), userId, tenantId, level).where('tp.scope', 'ungrouped');
          });
        });
    });
}

/** Does the user hold the `ungrouped` grant of `tenantId` at `level`? */
export async function ungroupedLevel(userId: number, tenantId: number): Promise<Level | null> {
  const rows = (await grantsOf(db.queryBuilder().select('tp.level'), userId, tenantId, 'ro')
    .where('tp.scope', 'ungrouped')) as Array<{ level: Level }>;
  return rows.reduce<Level | null>((acc, r) => highest(acc, r.level), null);
}

/**
 * `SELECT sites.id` of `tenantId` the user reaches at `level`: read when one of
 * its devices is readable, write when all of them are writable; a device-less
 * site through the ungrouped grant.
 */
export function visibleSiteIdsQuery(userId: number, tenantId: number, level: Level = 'ro'): Knex.QueryBuilder {
  const deviceIds = visibleDeviceIdsQuery(userId, tenantId, level);
  return db('sites as vs')
    .select('vs.id')
    .where('vs.tenant_id', tenantId)
    .andWhere((w) => {
      w.where((withDevices) => {
        withDevices.whereExists(function hasDevice(this: Knex.QueryBuilder) {
          this.select(db.raw('1')).from('devices as sd').whereRaw('sd.site_id = vs.id AND sd.tenant_id = vs.tenant_id');
        });
        if (level === 'ro') {
          withDevices.whereExists(function oneVisible(this: Knex.QueryBuilder) {
            this.select(db.raw('1')).from('devices as sd2').whereRaw('sd2.site_id = vs.id AND sd2.tenant_id = vs.tenant_id').whereIn('sd2.id', deviceIds);
          });
        } else {
          withDevices.whereNotExists(function oneNotWritable(this: Knex.QueryBuilder) {
            this.select(db.raw('1')).from('devices as sd3').whereRaw('sd3.site_id = vs.id AND sd3.tenant_id = vs.tenant_id').whereNotIn('sd3.id', deviceIds);
          });
        }
      }).orWhere((empty) => {
        empty
          .whereNotExists(function noDevice(this: Knex.QueryBuilder) {
            this.select(db.raw('1')).from('devices as sd4').whereRaw('sd4.site_id = vs.id AND sd4.tenant_id = vs.tenant_id');
          })
          .whereExists(function ungroupedGrant(this: Knex.QueryBuilder) {
            grantsOf(this.select(db.raw('1')), userId, tenantId, level).where('tp.scope', 'ungrouped');
          });
      });
    });
}

// ── Single-object answers ───────────────────────────────────────────────────

/**
 * The user's level on one device of `tenantId`, or null (no access, or the
 * device is not in that tenant). Tenant-wide callers get 'rw'.
 */
export async function getDevicePermission(
  userId: number,
  deviceId: number,
  isPlatformAdmin: boolean,
  tenantId: number,
): Promise<Level | null> {
  const device = await db('devices')
    .where({ id: deviceId })
    .first<{ tenant_id: number; group_id: number | null } | undefined>('tenant_id', 'group_id');
  if (!device || Number(device.tenant_id) !== tenantId) return null;
  if (await isTenantWide(userId, isPlatformAdmin, tenantId)) return 'rw';

  const direct = (await grantsOf(db.queryBuilder().select('tp.level'), userId, tenantId, 'ro')
    .where('tp.scope', 'device')
    .where('tp.scope_id', deviceId)) as Array<{ level: Level }>;
  let level = direct.reduce<Level | null>((acc, r) => highest(acc, r.level), null);
  if (level === 'rw') return level;

  if (device.group_id !== null && device.group_id !== undefined) {
    const viaGroup = (await grantsOf(db.queryBuilder().select('tp.level'), userId, tenantId, 'ro')
      .join('group_closure as gc', 'gc.ancestor_id', 'tp.scope_id')
      .join('device_groups as ag', 'ag.id', 'gc.ancestor_id')
      .where('tp.scope', 'group')
      .where('ag.tenant_id', tenantId)
      .where('gc.descendant_id', device.group_id)) as Array<{ level: Level }>;
    for (const r of viaGroup) level = highest(level, r.level);
  } else {
    level = highest(level, await ungroupedLevel(userId, tenantId));
  }
  return level;
}

/** The user's level on one site of `tenantId` (see the header for the rule). */
export async function getSitePermission(
  userId: number,
  siteId: number,
  isPlatformAdmin: boolean,
  tenantId: number,
): Promise<Level | null> {
  const site = await db('sites').where({ id: siteId }).first<{ tenant_id: number } | undefined>('tenant_id');
  if (!site || Number(site.tenant_id) !== tenantId) return null;
  if (await isTenantWide(userId, isPlatformAdmin, tenantId)) return 'rw';
  const writable = await visibleSiteIdsQuery(userId, tenantId, 'rw').where('vs.id', siteId).first('vs.id');
  if (writable) return 'rw';
  const readable = await visibleSiteIdsQuery(userId, tenantId, 'ro').where('vs.id', siteId).first('vs.id');
  return readable ? 'ro' : null;
}

/**
 * The level on a SIM line, which hangs off a device, else off a site, else
 * nothing: a line attached to neither is a tenant-pool line, covered by the
 * ungrouped grant like any other object filed nowhere.
 */
export async function getSimLinePermission(
  userId: number,
  lineId: number,
  isPlatformAdmin: boolean,
  tenantId: number,
): Promise<Level | null> {
  const line = await db('sim_lines')
    .where({ id: lineId })
    .first<{ tenant_id: number | null; device_id: number | null; site_id: number | null } | undefined>(
      'tenant_id', 'device_id', 'site_id',
    );
  if (!line || line.tenant_id === null || Number(line.tenant_id) !== tenantId) return null;
  if (await isTenantWide(userId, isPlatformAdmin, tenantId)) return 'rw';
  if (line.device_id !== null && line.device_id !== undefined) {
    return getDevicePermission(userId, Number(line.device_id), false, tenantId);
  }
  if (line.site_id !== null && line.site_id !== undefined) {
    return getSitePermission(userId, Number(line.site_id), false, tenantId);
  }
  return ungroupedLevel(userId, tenantId);
}

/**
 * `SELECT sim_lines.id` of `tenantId` the user reaches at `level` — the list
 * form of `getSimLinePermission`: a line on a device follows the device, a
 * line on a site only (no device) follows the site, a pool line (neither)
 * follows the ungrouped grant.
 */
export function visibleSimLineIdsQuery(userId: number, tenantId: number, level: Level = 'ro'): Knex.QueryBuilder {
  return db('sim_lines as vl')
    .select('vl.id')
    .where('vl.tenant_id', tenantId)
    .andWhere((w) => {
      w.where((d) => {
        d.whereNotNull('vl.device_id').whereIn('vl.device_id', visibleDeviceIdsQuery(userId, tenantId, level));
      })
        .orWhere((s) => {
          s.whereNull('vl.device_id')
            .whereNotNull('vl.site_id')
            .whereIn('vl.site_id', visibleSiteIdsQuery(userId, tenantId, level));
        })
        .orWhere((p) => {
          p.whereNull('vl.device_id')
            .whereNull('vl.site_id')
            .whereExists(function poolGrant(this: Knex.QueryBuilder) {
              grantsOf(this.select(db.raw('1')), userId, tenantId, level).where('tp.scope', 'ungrouped');
            });
        });
    });
}

/**
 * `SELECT rollouts.id` of `tenantId` the user reaches at `level`: EVERY target
 * device of the rollout must be reachable at that level (a rollout names its
 * devices; reading one that spans another team's routers would read them). A
 * rollout with no target yet (a draft) follows the ungrouped grant, like any
 * object filed nowhere.
 */
export function visibleRolloutIdsQuery(userId: number, tenantId: number, level: Level = 'ro'): Knex.QueryBuilder {
  return db('rollouts as vro')
    .select('vro.id')
    .where('vro.tenant_id', tenantId)
    .andWhere((w) => {
      w.where((t) => {
        t.whereExists(function hasTarget(this: Knex.QueryBuilder) {
          this.select(db.raw('1')).from('rollout_targets as rt1').whereRaw('rt1.rollout_id = vro.id');
        }).whereNotExists(function oneOutOfScope(this: Knex.QueryBuilder) {
          this.select(db.raw('1'))
            .from('rollout_targets as rt2')
            .whereRaw('rt2.rollout_id = vro.id')
            .whereNotIn('rt2.device_id', visibleDeviceIdsQuery(userId, tenantId, level));
        });
      }).orWhere((e) => {
        e.whereNotExists(function noTarget(this: Knex.QueryBuilder) {
          this.select(db.raw('1')).from('rollout_targets as rt3').whereRaw('rt3.rollout_id = vro.id');
        }).whereExists(function draftGrant(this: Knex.QueryBuilder) {
          grantsOf(this.select(db.raw('1')), userId, tenantId, level).where('tp.scope', 'ungrouped');
        });
      });
    });
}

/** The user's level on one rollout of `tenantId` (see `visibleRolloutIdsQuery`). */
export async function getRolloutPermission(
  userId: number,
  rolloutId: number,
  isPlatformAdmin: boolean,
  tenantId: number,
): Promise<Level | null> {
  const row = await db('rollouts').where({ id: rolloutId }).first<{ tenant_id: number } | undefined>('tenant_id');
  if (!row || Number(row.tenant_id) !== tenantId) return null;
  if (await isTenantWide(userId, isPlatformAdmin, tenantId)) return 'rw';
  if (await visibleRolloutIdsQuery(userId, tenantId, 'rw').where('vro.id', rolloutId).first('vro.id')) return 'rw';
  if (await visibleRolloutIdsQuery(userId, tenantId, 'ro').where('vro.id', rolloutId).first('vro.id')) return 'ro';
  return null;
}

/** Ids, or 'all' for a tenant-wide caller. Small fleets only — prefer the subquery. */
export async function getVisibleDeviceIds(
  userId: number,
  isPlatformAdmin: boolean,
  tenantId: number,
  level: Level = 'ro',
): Promise<number[] | 'all'> {
  if (await isTenantWide(userId, isPlatformAdmin, tenantId)) return 'all';
  const rows = (await visibleDeviceIdsQuery(userId, tenantId, level)) as Array<{ id: number }>;
  return rows.map((r) => Number(r.id));
}

export async function getVisibleSiteIds(
  userId: number,
  isPlatformAdmin: boolean,
  tenantId: number,
  level: Level = 'ro',
): Promise<number[] | 'all'> {
  if (await isTenantWide(userId, isPlatformAdmin, tenantId)) return 'all';
  const rows = (await visibleSiteIdsQuery(userId, tenantId, level)) as Array<{ id: number }>;
  return rows.map((r) => Number(r.id));
}

/**
 * Whether the user may write EVERY site of the tenant — the condition for a
 * bulk act addressed by site CODE (the CSV import), which can reach any site
 * of the tenant and is not filtered row by row.
 */
export async function canWriteEverySite(userId: number, isPlatformAdmin: boolean, tenantId: number): Promise<boolean> {
  if (await isTenantWide(userId, isPlatformAdmin, tenantId)) return true;
  if ((await ungroupedLevel(userId, tenantId)) !== 'rw') return false;
  const writable = visibleSiteIdsQuery(userId, tenantId, 'rw');
  const missing = await db('sites').where('tenant_id', tenantId).whereNotIn('id', writable).first('id');
  return !missing;
}

// ── Request helpers ─────────────────────────────────────────────────────────

/** What a list read needs from an Express request. */
export interface ScopeCaller {
  session: { userId?: number; role?: string };
  tenantId: number;
  masterView?: boolean;
}

/**
 * The device ids a LIST read must keep, or null when the caller sees the whole
 * tenant (or the god view, which the god-view port widens on its own). Use as
 * `if (ids) q.whereIn('d.id', ids)`.
 *
 * Materialised ids, NOT a query builder: a knex builder is a thenable, so an
 * async function that returns one hands its caller the builder's ROWS (the
 * `await` runs it) — `[{ id: 3 }]` then reaches `whereIn` as a value.
 */
export async function deviceListScope(req: ScopeCaller, level: Level = 'ro'): Promise<number[] | null> {
  const userId = req.session.userId;
  if (!userId) return [];
  if (await isTenantWide(userId, req.session.role === 'admin', req.tenantId)) return null;
  const rows = (await visibleDeviceIdsQuery(userId, req.tenantId, level)) as Array<{ id: number }>;
  return rows.map((r) => Number(r.id));
}

/** The site ids a LIST read must keep, or null for a tenant-wide caller (same contract). */
export async function siteListScope(req: ScopeCaller, level: Level = 'ro'): Promise<number[] | null> {
  const userId = req.session.userId;
  if (!userId) return [];
  if (await isTenantWide(userId, req.session.role === 'admin', req.tenantId)) return null;
  const rows = (await visibleSiteIdsQuery(userId, req.tenantId, level)) as Array<{ id: number }>;
  return rows.map((r) => Number(r.id));
}

/** The SIM line ids a LIST read must keep, or null for a tenant-wide caller (same contract). */
export async function simLineListScope(req: ScopeCaller, level: Level = 'ro'): Promise<number[] | null> {
  const userId = req.session.userId;
  if (!userId) return [];
  if (await isTenantWide(userId, req.session.role === 'admin', req.tenantId)) return null;
  const rows = (await visibleSimLineIdsQuery(userId, req.tenantId, level)) as Array<{ id: number }>;
  return rows.map((r) => Number(r.id));
}

/** The rollout ids a LIST read must keep, or null for a tenant-wide caller (same contract). */
export async function rolloutListScope(req: ScopeCaller, level: Level = 'ro'): Promise<number[] | null> {
  const userId = req.session.userId;
  if (!userId) return [];
  if (await isTenantWide(userId, req.session.role === 'admin', req.tenantId)) return null;
  const rows = (await visibleRolloutIdsQuery(userId, req.tenantId, level)) as Array<{ id: number | string }>;
  return rows.map((r) => Number(r.id));
}

/**
 * The per-row `access` annotation of a list answer (shared `ObjectAccess`):
 * ONE `*ListScope(req, 'rw')` read, then `(id) => 'rw' | 'ro'`. It annotates
 * rows the caller can already READ (the list was filtered first), so anything
 * not writable is 'ro'. A platform admin is always 'rw'.
 */
export async function accessOf(
  req: ScopeCaller,
  kind: 'device' | 'site' | 'simLine' | 'rollout',
): Promise<(id: number | string | null | undefined) => Level> {
  const writable = kind === 'device'
    ? await deviceListScope(req, 'rw')
    : kind === 'site'
      ? await siteListScope(req, 'rw')
      : kind === 'simLine'
        ? await simLineListScope(req, 'rw')
        : await rolloutListScope(req, 'rw');
  if (writable === null) return () => 'rw';
  const set = new Set(writable);
  return (id) => (id !== null && id !== undefined && set.has(Number(id)) ? 'rw' : 'ro');
}

/**
 * The caller's level on ONE object, for a detail answer's `access` (shared
 * `ObjectAccess`). A platform admin: 'rw' (any tenant, the god view included).
 * The detail routes are team-gated first, so a null here means a path the
 * gate does not cover: answered 'ro', the safe side.
 */
export async function accessOfOne(
  req: ScopeCaller,
  kind: 'device' | 'site' | 'simLine' | 'rollout',
  id: number,
): Promise<Level> {
  if (req.session.role === 'admin') return 'rw';
  const userId = req.session.userId;
  if (!userId) return 'ro';
  const level = kind === 'device'
    ? await getDevicePermission(userId, id, false, req.tenantId)
    : kind === 'site'
      ? await getSitePermission(userId, id, false, req.tenantId)
      : kind === 'simLine'
        ? await getSimLinePermission(userId, id, false, req.tenantId)
        : await getRolloutPermission(userId, id, false, req.tenantId);
  return level ?? 'ro';
}

/**
 * Whether the caller may WRITE every device of the tenant — only to decide
 * whether a tenant-wide sweep started from a request (an identity sweep, an
 * aftermath sweep) must be narrowed to the caller's 'rw' devices.
 */
export async function canWriteEveryDevice(req: ScopeCaller): Promise<boolean> {
  return coversEveryDevice(req, 'rw');
}

/**
 * Whether the caller may READ every device of the tenant — the entry ticket of
 * the analyses that read the whole fleet's configurations (baseline mining, the
 * template extrapolator): a partial population would produce a baseline of
 * "some routers" under the name of the fleet's. A platform admin, or an account
 * whose teams cover the whole workspace (087's transition team does, for the
 * devices of the day).
 */
export async function canReadEveryDevice(req: ScopeCaller): Promise<boolean> {
  return coversEveryDevice(req, 'ro');
}

async function coversEveryDevice(req: ScopeCaller, level: Level): Promise<boolean> {
  const userId = req.session.userId;
  if (!userId) return false;
  if (await isTenantWide(userId, req.session.role === 'admin', req.tenantId)) return true;
  const missing = await db('devices')
    .where('tenant_id', req.tenantId)
    .whereNotIn('id', visibleDeviceIdsQuery(userId, req.tenantId, level))
    .first('id');
  return !missing;
}

/** Who reads a live-alert feed (liveAlert.service). */
export interface AlertViewer {
  userId: number;
  isPlatformAdmin: boolean;
}

/**
 * The team predicate of the live-alert feed (migration 087 gave `live_alerts`
 * a subject: `device_id`, `site_id`, `sim_line_id`). A platform admin: no
 * filter. Anybody else, per tenant `tid` of `tenantIds`, an alert of `tid` is
 * visible when its MOST SPECIFIC subject is: the device when it names one,
 * else the site, else the SIM line; an alert that names none of the three is
 * a tenant-level alert ("many devices stopped answering", "mobile data no
 * longer read") and stays visible to every member of the tenant — the
 * operator's decision of 2026-10-07. An empty `tenantIds` matches nothing.
 */
export function liveAlertScope(
  q: Knex.QueryBuilder,
  alias: string,
  viewer: AlertViewer,
  tenantIds: number[],
): Knex.QueryBuilder {
  if (viewer.isPlatformAdmin) return q;
  if (tenantIds.length === 0) return q.whereRaw('1 = 0');
  const col = (c: string) => `${alias}.${c}`;
  return q.where((outer) => {
    for (const tid of tenantIds) {
      outer.orWhere((t) => {
        t.where(col('tenant_id'), tid).andWhere((s) => {
          s.where((d) => {
            d.whereNotNull(col('device_id')).whereIn(col('device_id'), visibleDeviceIdsQuery(viewer.userId, tid, 'ro'));
          })
            .orWhere((st) => {
              st.whereNull(col('device_id'))
                .whereNotNull(col('site_id'))
                .whereIn(col('site_id'), visibleSiteIdsQuery(viewer.userId, tid, 'ro'));
            })
            .orWhere((l) => {
              l.whereNull(col('device_id'))
                .whereNull(col('site_id'))
                .whereNotNull(col('sim_line_id'))
                .whereIn(col('sim_line_id'), visibleSimLineIdsQuery(viewer.userId, tid, 'ro'));
            })
            .orWhere((none) => {
              none.whereNull(col('device_id')).whereNull(col('site_id')).whereNull(col('sim_line_id'));
            });
        });
      });
    }
  });
}

/** The visible site ids as a Set, or null for a tenant-wide caller. */
export async function visibleSiteIdSet(req: ScopeCaller, level: Level = 'ro'): Promise<Set<number> | null> {
  const ids = await siteListScope(req, level);
  return ids ? new Set(ids) : null;
}

/** The visible device ids as a Set, or null for a tenant-wide caller. */
export async function visibleDeviceIdSet(req: ScopeCaller, level: Level = 'ro'): Promise<Set<number> | null> {
  const ids = await deviceListScope(req, level);
  return ids ? new Set(ids) : null;
}

/** The visible device ids as an array, or null for a tenant-wide caller. */
export async function visibleDeviceIdList(req: ScopeCaller, level: Level = 'ro'): Promise<number[] | null> {
  const s = await visibleDeviceIdSet(req, level);
  return s ? [...s] : null;
}

/**
 * Filters already-loaded rows by the device they hang off (`deviceIdOf`) —
 * for the lists whose service is not paginated by the caller (interfaces,
 * journal pages read whole, SIM lines). Rows with no device are kept only
 * through `orphanLevel` (the ungrouped grant) when `keepOrphans` says so.
 */
export async function filterRowsByDevice<T>(
  req: ScopeCaller,
  rows: T[],
  deviceIdOf: (row: T) => number | null | undefined,
  opts: { siteIdOf?: (row: T) => number | null | undefined; keepOrphans?: boolean } = {},
): Promise<T[]> {
  const userId = req.session.userId;
  if (!userId) return [];
  if (await isTenantWide(userId, req.session.role === 'admin', req.tenantId)) return rows;
  const devices = new Set(
    ((await visibleDeviceIdsQuery(userId, req.tenantId, 'ro')) as Array<{ id: number }>).map((r) => Number(r.id)),
  );
  let sites: Set<number> | null = null;
  if (opts.siteIdOf) {
    sites = new Set(((await visibleSiteIdsQuery(userId, req.tenantId, 'ro')) as Array<{ id: number }>).map((r) => Number(r.id)));
  }
  const orphanOk = opts.keepOrphans === true && (await ungroupedLevel(userId, req.tenantId)) !== null;
  return rows.filter((row) => {
    const d = deviceIdOf(row);
    if (d !== null && d !== undefined) return devices.has(Number(d));
    const s = opts.siteIdOf?.(row);
    if (s !== null && s !== undefined && sites) return sites.has(Number(s));
    return orphanOk;
  });
}
