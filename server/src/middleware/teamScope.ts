import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { AppError } from './errorHandler';
import { db } from '../db';
import {
  getDevicePermission,
  getSitePermission,
  getSimLinePermission,
  getRolloutPermission,
  canWriteEverySite,
  ungroupedLevel,
  satisfies,
  visibleDeviceIdsQuery,
  type Level,
} from '../services/teamScope.service';
import { permissionService } from '../services/permission.service';

/**
 * TEAM-SCOPE GATES (migration 084, Obliance's model — services/teamScope.service.ts;
 * the tenant admin aligned by migration 087).
 *
 * Mounted ONCE, in `routes/index.ts`, on the URL prefixes that address one
 * device, one site, one snapshot, one interface, one SIM line, one job, one
 * rollout… — rather than in each of the dozen routers below them — so a route
 * added later under `/devices/:id/…` is scoped without anybody remembering to
 * scope it. Express decodes and matches `:param` exactly as it does for the
 * route itself, so a percent-encoded id reaches the gate the same way it
 * reaches the handler.
 *
 * The rule, per request:
 *  - platform admin (`users.role = 'admin'`, Obliance's `isAdmin`): passes
 *    (the god view is the god-view port's business);
 *  - the id is not a positive integer (`/devices/backup-4g`, `/sites/import`):
 *    passes — not an object address, the route decides;
 *  - the object does not exist or belongs to another tenant: passes — the
 *    route answers its usual 404, and the gate adds no oracle of its own;
 *  - otherwise — the tenant `admin` role included since 087 — the user's team
 *    level on the object: none → 404 (an object outside one's teams does not
 *    exist for them, the tenant-isolation answer); 'ro' on a write → 403. A
 *    WRITE is any method but GET/HEAD/OPTIONS unless the mount says
 *    `level: 'ro'` (a plan compile, a preview: they touch no equipment) or a
 *    `readOnlyAction()` mounted before it marked the request as a read.
 *
 * Capabilities are NOT checked here: WHAT stays with `requireCapability` on
 * the route. Both must pass.
 */

/** What a gate judges: the object the addressed row hangs off. */
type SubjectKind = 'device' | 'site' | 'simLine' | 'rollout' | 'ungrouped';
interface Subject { subject: SubjectKind; id: number; tenantId: number }
type Resolver = (key: string | number) => Promise<Subject | null>;

interface GateOptions {
  /** Required level; 'auto' = 'ro' for GET/HEAD/OPTIONS, 'rw' otherwise. */
  level?: Level | 'auto';
}

function isReadMethod(method: string): boolean {
  const m = method.toUpperCase();
  return m === 'GET' || m === 'HEAD' || m === 'OPTIONS';
}

function parseId(raw: unknown): number | null {
  if (typeof raw === 'number' && Number.isSafeInteger(raw) && raw > 0) return raw;
  if (typeof raw !== 'string' || !/^[1-9][0-9]{0,9}$/.test(raw)) return null;
  const n = Number(raw);
  return Number.isSafeInteger(n) ? n : null;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function parseUuid(raw: unknown): string | null {
  return typeof raw === 'string' && UUID_RE.test(raw) ? raw.toLowerCase() : null;
}

const NOT_FOUND: Record<SubjectKind, string> = {
  device: 'Device not found',
  site: 'Site not found',
  simLine: 'Line not found',
  rollout: 'Rollout not found',
  ungrouped: 'Not found',
};

async function levelOn(req: Request, s: Subject): Promise<Level | null> {
  const userId = req.session.userId!;
  switch (s.subject) {
    case 'device': return getDevicePermission(userId, s.id, false, s.tenantId);
    case 'site': return getSitePermission(userId, s.id, false, s.tenantId);
    case 'simLine': return getSimLinePermission(userId, s.id, false, s.tenantId);
    case 'rollout': return getRolloutPermission(userId, s.id, false, s.tenantId);
    case 'ungrouped': return ungroupedLevel(userId, s.tenantId);
  }
}

/**
 * The level a gate wants: the mount's explicit level, else a request marked
 * `readOnlyAction()` reads, else 'ro' for GET/HEAD/OPTIONS and 'rw' otherwise.
 */
function wantedLevel(req: Request, res: Response, opts: GateOptions): Level {
  if (opts.level === 'ro' || opts.level === 'rw') return opts.level;
  if ((res.locals as { teamScopeLevel?: Level }).teamScopeLevel === 'ro') return 'ro';
  return isReadMethod(req.method) ? 'ro' : 'rw';
}

function gate(
  read: (req: Request) => unknown,
  resolve: Resolver,
  opts: GateOptions = {},
  parse: (raw: unknown) => string | number | null = parseId,
): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.session?.userId) return next(); // requireAuth answers
      if (req.session.role === 'admin') return next();
      const key = parse(read(req));
      if (key === null) return next();
      const target = await resolve(key);
      if (!target || target.tenantId !== req.tenantId) return next();

      const wanted = wantedLevel(req, res, opts);
      const held = await levelOn(req, target);
      if (held === null) return next(new AppError(404, NOT_FOUND[target.subject]));
      if (!satisfies(held, wanted)) return next(new AppError(403, 'Insufficient permissions'));
      next();
    } catch (err) {
      next(err);
    }
  };
}

const byId = (table: 'devices' | 'sites', subject: 'device' | 'site'): Resolver => async (id) => {
  const row = await db(table).where({ id }).first<{ tenant_id: number } | undefined>('tenant_id');
  return row ? { subject, id: Number(id), tenantId: Number(row.tenant_id) } : null;
};

const simLine: Resolver = async (id) => {
  const row = await db('sim_lines').where({ id }).first<{ tenant_id: number | null } | undefined>('tenant_id');
  return row && row.tenant_id !== null ? { subject: 'simLine', id: Number(id), tenantId: Number(row.tenant_id) } : null;
};

// ── Rows addressed by their own id ──────────────────────────────────────────

/** A row with no tenant column, judged through its device (and the device's tenant). */
function viaDevice(table: string): Resolver {
  return async (id) => {
    const row = await db(`${table} as x`)
      .join('devices as d', 'd.id', 'x.device_id')
      .where('x.id', id)
      .first<{ device_id: number; tenant_id: number } | undefined>('x.device_id', 'd.tenant_id');
    return row ? { subject: 'device', id: Number(row.device_id), tenantId: Number(row.tenant_id) } : null;
  };
}

/**
 * A row carrying its own `tenant_id` and a subject column (`device_id`,
 * `site_id`, `sim_id`): judged in the ROW's tenant on that subject; a NULL
 * subject is an object filed nowhere, covered by the ungrouped grant.
 */
function ownTenant(table: string, column: string, subject: 'device' | 'site' | 'simLine', key: 'id' | 'uuid' = 'id'): Resolver {
  return async (k) => {
    const row = await db(table)
      .where(key, k)
      .first<{ tenant_id: number | null; subject_id: number | null } | undefined>('tenant_id', `${column} as subject_id`);
    if (!row || row.tenant_id === null || row.tenant_id === undefined) return null;
    const tenantId = Number(row.tenant_id);
    if (row.subject_id === null || row.subject_id === undefined) return { subject: 'ungrouped', id: 0, tenantId };
    return { subject, id: Number(row.subject_id), tenantId };
  };
}

/**
 * Rows a gate may judge, and HOW: an ALLOW-LIST (never an interpolated
 * identifier coming from a caller), the same discipline as globalView OWNERS.
 */
const ROW_SCOPES = {
  config_snapshots: { resolve: viaDevice('config_snapshots') },
  snmp_interfaces: { resolve: viaDevice('snmp_interfaces') },
  drift_runs: { resolve: viaDevice('drift_runs') },
  drift_findings: {
    resolve: (async (id) => {
      const row = await db('drift_findings as f')
        .join('drift_runs as r', 'r.id', 'f.run_id')
        .join('devices as d', 'd.id', 'r.device_id')
        .where('f.id', id)
        .first<{ device_id: number; tenant_id: number } | undefined>('r.device_id', 'd.tenant_id');
      return row ? { subject: 'device', id: Number(row.device_id), tenantId: Number(row.tenant_id) } : null;
    }) as Resolver,
  },
  change_jobs: { resolve: ownTenant('change_jobs', 'device_id', 'device') },
  change_aftermath: { resolve: ownTenant('change_aftermath', 'device_id', 'device') },
  interventions: { resolve: ownTenant('interventions', 'device_id', 'device') },
  device_backups: { resolve: ownTenant('device_backups', 'device_id', 'device') },
  drift_exceptions: { resolve: ownTenant('drift_exceptions', 'device_id', 'device') },
  device_identity_events: { resolve: ownTenant('device_identity_events', 'device_id', 'device') },
  attestations: { resolve: ownTenant('attestations', 'device_id', 'device', 'uuid'), uuid: true },
  sla_reports: { resolve: ownTenant('sla_reports', 'site_id', 'site') },
  sim_recharges: { resolve: ownTenant('sim_recharges', 'sim_id', 'simLine') },
  // A site-bound intent follows its site; one filed on no site is tenant-level
  // configuration (capabilities only) and passes.
  site_intents: {
    resolve: (async (id) => {
      const row = await db('site_intents').where({ id }).first<{ tenant_id: number; site_id: number | null } | undefined>('tenant_id', 'site_id');
      if (!row || row.site_id === null || row.site_id === undefined) return null;
      return { subject: 'site', id: Number(row.site_id), tenantId: Number(row.tenant_id) };
    }) as Resolver,
  },
  rollouts: {
    resolve: (async (id) => {
      const row = await db('rollouts').where({ id }).first<{ tenant_id: number } | undefined>('tenant_id');
      return row ? { subject: 'rollout', id: Number(id), tenantId: Number(row.tenant_id) } : null;
    }) as Resolver,
  },
} satisfies Record<string, { resolve: Resolver; uuid?: boolean }>;

export type RowScopeTable = keyof typeof ROW_SCOPES;

/**
 * `/…/:param/…` naming ONE row of an allow-listed table: judged on the object
 * the row hangs off (its device, its run's device, its site, its SIM line, its
 * rollout's devices), in the row's tenant.
 */
export function rowScopeGate(table: RowScopeTable, param = 'id', opts?: GateOptions): RequestHandler {
  const entry = ROW_SCOPES[table] as { resolve: Resolver; uuid?: boolean };
  return gate((req) => req.params[param], entry.resolve, opts, entry.uuid ? parseUuid : parseId);
}

/** The same, for a row named in the JSON body (`POST /exceptions {findingId}`). */
export function bodyRowScopeGate(table: RowScopeTable, field: string, opts?: GateOptions): RequestHandler {
  const entry = ROW_SCOPES[table] as { resolve: Resolver; uuid?: boolean };
  return gate(
    (req) => (req.body as Record<string, unknown> | undefined)?.[field],
    entry.resolve,
    opts,
    entry.uuid ? parseUuid : parseId,
  );
}

/** @deprecated the 084 spelling of `rowScopeGate` for a device-bound row. */
export function deviceRowScopeGate(table: 'config_snapshots' | 'snmp_interfaces', param = 'id', opts?: GateOptions): RequestHandler {
  return rowScopeGate(table, param, opts);
}

/** `/…/devices/:param/…` */
export function deviceScopeGate(param = 'deviceId', opts?: GateOptions): RequestHandler {
  return gate((req) => req.params[param], byId('devices', 'device'), opts);
}

/** A device named in the JSON body (`POST /changes/jobs {deviceId}`). */
export function bodyDeviceScopeGate(field = 'deviceId', opts?: GateOptions): RequestHandler {
  return gate((req) => (req.body as Record<string, unknown> | undefined)?.[field], byId('devices', 'device'), opts);
}

/** A site named in the JSON body (`POST /sla/reports {siteId}`, an intent's site). */
export function bodySiteScopeGate(field = 'siteId', opts?: GateOptions): RequestHandler {
  return gate((req) => (req.body as Record<string, unknown> | undefined)?.[field], byId('sites', 'site'), opts);
}

/**
 * A tenant-wide sweep started from a request (aftermath, intervention links):
 * a caller whose teams do not write EVERY device of the tenant is refused
 * (403) unless the body names one device (`unlessBodyField`), which its own
 * gate judges. A platform admin passes.
 */
export function requireEveryDeviceWritable(opts: { unlessBodyField?: string } = {}): RequestHandler {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.session?.userId || req.session.role === 'admin') return next();
      const body = (req.body ?? {}) as Record<string, unknown>;
      if (opts.unlessBodyField && body[opts.unlessBodyField] !== undefined && body[opts.unlessBodyField] !== null) return next();
      const missing = await db('devices')
        .where('tenant_id', req.tenantId)
        .whereNotIn('id', visibleDeviceIdsQuery(req.session.userId, req.tenantId, 'rw'))
        .first('id');
      if (missing) {
        return next(new AppError(403, 'A sweep of the whole workspace needs \'rw\' on every device (your teams do not cover them all)'));
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}

/**
 * For a controller writing or reading something keyed on a polymorphic
 * `(scope, scope_id)` (template assignments, variables): the caller's team
 * level on that target. `group` → the group grant (`canReadGroup` /
 * `canWriteGroup`), `site` / `device` → the site / device level; any other
 * scope (tenant, global) is tenant-level and not team-scoped. None → 404, 'ro'
 * on a write → 403. A platform admin passes. Throws an AppError.
 */
export async function assertScopeTargetInTeams(
  req: Request,
  scope: string,
  scopeId: number | null,
  wanted: Level,
): Promise<void> {
  if (!req.session?.userId || req.session.role === 'admin' || scopeId === null) return;
  const userId = req.session.userId;
  let held: Level | null;
  if (scope === 'group') {
    held = await permissionService.getGroupPermission(userId, scopeId, false, { tenantId: req.tenantId, masterView: false });
  } else if (scope === 'site') {
    held = await getSitePermission(userId, scopeId, false, req.tenantId);
  } else if (scope === 'device') {
    held = await getDevicePermission(userId, scopeId, false, req.tenantId);
  } else {
    return;
  }
  if (held === null) throw new AppError(404, `No ${scope} ${scopeId} in your teams`);
  if (!satisfies(held, wanted)) throw new AppError(403, 'Insufficient permissions');
}

/** A SIM line named in the JSON body (`POST /sim/recharges {simId}`). */
export function bodySimLineScopeGate(field = 'simId', opts?: GateOptions): RequestHandler {
  return gate((req) => (req.body as Record<string, unknown> | undefined)?.[field], simLine, opts);
}

/** `/sites/:param/…` */
export function siteScopeGate(param = 'siteId', opts?: GateOptions): RequestHandler {
  return gate((req) => req.params[param], byId('sites', 'site'), opts);
}

/** `/sim/lines/:param/…` */
export function simLineScopeGate(param = 'lineId', opts?: GateOptions): RequestHandler {
  return gate((req) => req.params[param], simLine, opts);
}

/**
 * For a POST that only READS (a reachability assessment, an attestation
 * check): marks the request so the generic gate mounted after it wants 'ro'
 * instead of the 'rw' its method would imply. Mount it BEFORE that gate.
 */
export function readOnlyAction(): RequestHandler {
  return (_req: Request, res: Response, next: NextFunction): void => {
    (res.locals as { teamScopeLevel?: Level }).teamScopeLevel = 'ro';
    next();
  };
}

/**
 * Device lists in the body (`POST /rollouts {deviceIds}`, a compliance or an
 * OS-upgrade wave, a preview): EVERY id of the request's tenant must reach the
 * level. One out of the caller's teams → 404 for the whole request (it does
 * not exist for them); one only readable on a write → 403. All or nothing,
 * like the routes behind it. Ids of another tenant, or that do not exist, are
 * left to the route (it answers its own 404 / 400).
 */
export function bodyDeviceIdsScopeGate(field = 'deviceIds', opts: GateOptions = {}): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.session?.userId || req.session.role === 'admin') return next();
      const raw = (req.body as Record<string, unknown> | undefined)?.[field];
      if (!Array.isArray(raw)) return next();
      const ids = [...new Set(raw.map(parseId).filter((n): n is number => n !== null))];
      if (ids.length === 0) return next();
      const userId = req.session.userId;
      const inTenant = ((await db('devices').whereIn('id', ids).where('tenant_id', req.tenantId).pluck('id')) as Array<number | string>)
        .map(Number);
      if (inTenant.length === 0) return next();
      const readable = new Set(
        ((await visibleDeviceIdsQuery(userId, req.tenantId, 'ro').whereIn('vd.id', inTenant)) as Array<{ id: number }>).map((r) => Number(r.id)),
      );
      if (inTenant.some((id) => !readable.has(id))) return next(new AppError(404, 'Device not found'));
      if (wantedLevel(req, res, opts) === 'rw') {
        const writable = new Set(
          ((await visibleDeviceIdsQuery(userId, req.tenantId, 'rw').whereIn('vd.id', inTenant)) as Array<{ id: number }>).map((r) => Number(r.id)),
        );
        if (inTenant.some((id) => !writable.has(id))) return next(new AppError(403, 'Insufficient permissions'));
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}

/**
 * Surfaces that list objects filed NOWHERE yet — the PPP discovery quarantine,
 * the syslog sources no device claims: they belong to the ungrouped bucket,
 * so a non-platform caller needs the ungrouped grant at the level ('auto' =
 * 'ro' for a read, 'rw' otherwise).
 */
export function requireUngroupedGrant(level: Level | 'auto' = 'auto'): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.session?.userId || req.session.role === 'admin') return next();
      const wanted = wantedLevel(req, res, { level });
      const held = await ungroupedLevel(req.session.userId, req.tenantId);
      if (!satisfies(held, wanted)) {
        return next(new AppError(403, 'Your teams do not cover the devices filed under no group (an ungrouped grant is needed)'));
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}

/**
 * Bulk site writes addressed by id in the body (`POST /sites/bulk/uplink-kind
 * {siteIds}`): every id the caller cannot write is refused as a whole, the
 * route's own all-or-nothing rule. Ids of another tenant are left to the route
 * (it 404s the whole request).
 */
export function bodySiteIdsScopeGate(field = 'ids'): RequestHandler {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.session?.userId || req.session.role === 'admin') return next();
      const raw = (req.body as Record<string, unknown> | undefined)?.[field];
      if (!Array.isArray(raw)) return next();
      for (const v of raw) {
        const id = parseId(v);
        if (id === null) continue;
        const site = await db('sites').where({ id }).first<{ tenant_id: number } | undefined>('tenant_id');
        if (!site || Number(site.tenant_id) !== req.tenantId) continue;
        const held = await getSitePermission(req.session.userId, id, false, req.tenantId);
        if (held === null) return next(new AppError(404, 'Site not found'));
        if (held !== 'rw') return next(new AppError(403, 'Insufficient permissions'));
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}

/**
 * Creating a site, or importing sites by CODE: the new site is device-less, so
 * it lands in the ungrouped bucket, and an import may touch any site of the
 * tenant. A platform admin passes; anybody else (the tenant admin included)
 * needs 'rw' on every site of the tenant (which includes the ungrouped grant)
 * — a creator must be able to see what they create, and an import must not
 * reach a site outside one's teams.
 */
export function requireEverySiteWritable(): RequestHandler {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.session?.userId || req.session.role === 'admin') return next();
      const ok = await canWriteEverySite(req.session.userId, false, req.tenantId);
      if (!ok) {
        return next(new AppError(403, 'Your teams do not cover every site of this workspace (an rw grant on the ungrouped devices and on every site is needed)'));
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}

/**
 * WHERE a device is filed is a team boundary: `POST /devices` and
 * `PATCH /devices/:id` may only file a device where the caller could write it
 * afterwards — a group their team holds 'rw' on (down the closure), the
 * ungrouped bucket only with an 'rw' ungrouped grant, a site they may write.
 * Otherwise a scoped user could push a device out of reach of the teams that
 * own it, or file one on another team's site and so read that site. Only the
 * fields present in the body are judged (a PATCH that does not move the device
 * is untouched); a platform admin passes.
 *
 * `pick` judges a device described INSIDE the body rather than the body
 * itself (`POST /discoveries/:id/bind {device}` creates one); when it answers
 * undefined there is nothing to place (a bind to an existing device, judged by
 * its own gate) and the request passes.
 */
export function requireDevicePlacementInScope(
  opts: { pick?: (body: Record<string, unknown>) => unknown } = {},
): RequestHandler {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.session?.userId || req.session.role === 'admin') return next();
      const userId = req.session.userId;
      const raw = (req.body ?? {}) as Record<string, unknown>;
      const picked = opts.pick ? opts.pick(raw) : raw;
      if (picked === undefined || picked === null || typeof picked !== 'object') return next();
      const body = picked as Record<string, unknown>;
      const creating = req.method.toUpperCase() === 'POST';
      const refuse = () => next(new AppError(403, 'Your teams cannot write where this device would be filed'));

      if (body.groupId !== undefined || creating) {
        const g = body.groupId;
        if (g === null || g === undefined) {
          if ((await ungroupedLevel(userId, req.tenantId)) !== 'rw') return refuse();
        } else {
          const gid = parseId(g);
          if (gid === null) return next(); // the validator answers
          const ok = await permissionService.canWriteGroup(userId, gid, false, { tenantId: req.tenantId, masterView: false });
          if (!ok) return refuse();
        }
      }
      if (body.siteId !== undefined && body.siteId !== null) {
        const sid = parseId(body.siteId);
        if (sid === null) return next();
        const held = await getSitePermission(userId, sid, false, req.tenantId);
        // A site of another tenant is the service's 400; one out of scope does not exist.
        const site = await db('sites').where({ id: sid }).first<{ tenant_id: number } | undefined>('tenant_id');
        if (site && Number(site.tenant_id) === req.tenantId && held !== 'rw') return refuse();
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}

/**
 * The group CONFIGURATION fields of `PUT /groups/:id` (`isGeneral`,
 * `groupNotifications`, `sortOrder`) need the tenant capability
 * `groups.manage` on top of the 'rw' team grant `requireGroupWrite` checks —
 * Obliance's split between editing a group and configuring it.
 */
export const GROUP_CONFIG_FIELDS = ['isGeneral', 'groupNotifications', 'sortOrder'] as const;

export function requireGroupConfigCapability(): RequestHandler {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.session?.userId || req.session.role === 'admin') return next();
      const body = (req.body ?? {}) as Record<string, unknown>;
      if (!GROUP_CONFIG_FIELDS.some((f) => body[f] !== undefined)) return next();
      const caps = await permissionService.getUserCapabilities(req.session.userId, false, req.tenantId);
      if (!caps.includes(CAPABILITIES.GROUPS_MANAGE)) {
        return next(new AppError(403, 'Insufficient permissions (groups.manage is needed to change a group\'s configuration)'));
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}
