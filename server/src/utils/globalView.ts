import { AsyncLocalStorage } from 'node:async_hooks';
import type { Request, Response, NextFunction, RequestParamHandler } from 'express';
import type { Knex } from 'knex';
import { GOD_VIEW_RESPONSE_HEADER, isMasterTenant, MASTER_TENANT_ID } from '@obliwan/shared';
import { db } from '../db';
import { AppError } from '../middleware/errorHandler';

/**
 * The master tenant's GOD VIEW — ported from Obliance (`utils/globalView.ts`),
 * where it is done right, and adapted to ObliWAN in ONE deliberate way (see
 * "internal code" below).
 *
 * ┌─ WHO GETS IT ─────────────────────────────────────────────────────────────┐
 * │ The PLATFORM ADMIN (`users.role = 'admin'`, re-read from the database by  │
 * │ requireAuth) positioned on the master tenant (`MASTER_TENANT_ID`, the     │
 * │ seeded "Default"). Nobody else: a master-tenant admin                     │
 * │ (`user_tenants.role = 'admin'`), a plain member of tenant 1, a custom     │
 * │ permission set — every one of them is confined to tenant 1 exactly as any │
 * │ tenant is confined to itself. The rule is `grantsGlobalView()` below and  │
 * │ it is written ONCE: `requireTenant` (middleware/tenant.ts) applies it to  │
 * │ set `req.masterView`, the Socket.io handshake applies the same verdict,   │
 * │ and `hasGlobalView(req)` / `isGodView(tenantId)` only read that verdict.  │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * Entry points:
 *  - `hasGlobalView(req)`  — routes / controllers that hold the request;
 *  - `isGodView(tenantId)` — services that only receive a tenant id. Inside an
 *    HTTP request (or a Socket.io packet, `runInRequestScope`) it reads the
 *    verdict of THAT request: true only when the request is a god-view request
 *    AND the tenant id the code passes is the master tenant. A user session
 *    that is not a platform admin never gets it, whatever tenant id is passed.
 *  - `applyTenantScope(q, column, tenantId)` — the list-read idiom: the tenant
 *    predicate, dropped in god view (and narrowed to the operator's tenant
 *    filter, `?filterTenantId=`, when one is set).
 *  - `godViewParam(table)` / `enterObjectTenant(req, id)` — the detail/action
 *    idiom: in god view, a request about ONE object of another tenant becomes
 *    a request IN THAT TENANT (req.tenantId = the object's tenant, god view
 *    off), so the existing per-tenant service code reads it, acts on it and
 *    files its audit in the object's own tenant — Obliance's "filed in the
 *    DEVICE's tenant" rule.
 *  - `fanOutByTenant(req, table, ids, fn)` — the bulk-action idiom: in god view
 *    the ids are grouped by owning tenant and `fn` runs once per tenant, in
 *    that tenant (Obliance's `auditPerTenant` shape).
 *  - `adoptGodViewFilterTenant` — for a per-tenant REPORT that cannot be
 *    merged (the reconciliation): the god view picks the tenant with the filter.
 *  - `tenantIdsInScope(tenantId)` — for a read built tenant by tenant (raw SQL,
 *    a per-tenant report): every tenant in the god view, else the one.
 *
 * WRITES NEVER WIDEN: `isGodView()` answers false on any request that is not a
 * read (GET/HEAD, or a POST marked `godViewRead`), so a list read buried in a
 * write path keeps its tenant predicate whatever the session.
 *
 * ┌─ THE ONE ADAPTATION: INTERNAL CODE NEVER GETS THE GOD VIEW ───────────────┐
 * │ Obliance keeps a historical rule: outside any user session (background    │
 * │ jobs) `isGodView(MASTER)` is TRUE — "master tenant id = every tenant".    │
 * │ ObliWAN NEVER had that rule: its schedulers (drift, presence, SNMP, the   │
 * │ change worker) iterate tenants and call the same services with each id,   │
 * │ tenant 1 included. Porting the rule verbatim would make every one of      │
 * │ those passes over tenant 1 read and WRITE every customer's rows under the │
 * │ master tenant's id. So here, outside a request scope, `isGodView()` is    │
 * │ FALSE. Widening is a property of an operator's request, never of a        │
 * │ number.                                                                   │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * Do NOT use isGodView for tests that are not about widening a READ scope (the
 * master tenant cannot be deleted, the shared concentrator lives in tenant 1,
 * settings inherit from tenant 1…): keep `isMasterTenant` / `MASTER_TENANT_ID`
 * there. And never use it on a write path: a write acts in the object's own
 * tenant (`enterObjectTenant`) or fans out per tenant (`fanOutByTenant`) — a
 * write "in the master tenant over every tenant's rows" is exactly the shape
 * this module exists to prevent.
 *
 * Credentials and secrets stay tenant-scoped (shared/src/tenants.ts): the god
 * view lists operational data; revealing a secret still goes through
 * secretReveal and SECRET_READ.
 */

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      /**
       * The operator's tenant filter on a god-view list (`?filterTenantId=`),
       * captured by `requireTenant` BEFORE any `validate()` strips unknown
       * query keys. Undefined outside the god view: a tenant user cannot use it
       * to reach another tenant.
       */
      godViewTenantFilter?: number;
      /**
       * Set by `enterObjectTenant()`: the request was a god-view request that
       * now acts IN the tenant of the object it addresses. Holds the tenant the
       * operator was positioned on (the master tenant), for the audit trail.
       */
      godViewFromTenantId?: number;
      /** Set by `godViewRead`: this POST only reads, its lists may widen. */
      godViewRead?: boolean;
    }
  }
}

/** The response header the client reads to show the tenant column / badge
 *  (one spelling, shared with the client). */
export const GOD_VIEW_HEADER = GOD_VIEW_RESPONSE_HEADER;

// ── The rule ────────────────────────────────────────────────────────────────

/**
 * THE rule, written once. `requireTenant` (HTTP) and the Socket.io handshake
 * both call it through `resolveCallerTenant()`; nothing else may decide it.
 */
export function grantsGlobalView(
  tenantId: number | null | undefined,
  isPlatformAdmin: boolean,
): boolean {
  return isPlatformAdmin === true && isMasterTenant(tenantId);
}

// ── Request scope ───────────────────────────────────────────────────────────

/** What a scope needs from a request: the verdict requireTenant stored. */
type ScopedRequest = Pick<Request, 'session'> & {
  method?: string;
  tenantId?: number;
  masterView?: boolean;
  godViewTenantFilter?: number;
  godViewFromTenantId?: number;
  godViewRead?: boolean;
};

interface RequestScope { req: ScopedRequest }
const scopeStore = new AsyncLocalStorage<RequestScope>();

/**
 * Express middleware, mounted RIGHT AFTER the session middleware (app.ts):
 * every handler down the chain — and every promise it starts — can ask
 * `isGodView()` about the session of THIS request. It stores the request
 * itself, not a verdict: `requireTenant` decides `req.masterView` further
 * down the chain and the services read it lazily.
 */
export function requestScope(req: Request, _res: Response, next: NextFunction): void {
  scopeStore.run({ req }, next);
}

/**
 * Same scope outside Express: socket.ts runs every incoming packet of a socket
 * inside the scope of its handshake request (whose `tenantId` / `masterView`
 * the handshake set from the same `resolveCallerTenant()` verdict).
 */
export function runInRequestScope<T>(req: ScopedRequest, fn: () => T): T {
  return scopeStore.run({ req }, fn);
}

/**
 * Request level: is this a god-view request? Reads the verdict requireTenant
 * stored (`req.masterView`), never re-derives it from the session number — a
 * request that did not go through requireTenant fails closed.
 */
export function hasGlobalView(req: { masterView?: boolean } | null | undefined): boolean {
  return req?.masterView === true;
}

/**
 * Does the current request belong to a platform admin's session?
 * null: not inside a user request — internal code.
 */
export function currentSessionIsPlatformAdmin(): boolean | null {
  const s = scopeStore.getStore();
  const session = s?.req?.session as { userId?: number; role?: string } | undefined;
  if (!session?.userId) return null;
  return session.role === 'admin';
}

/**
 * A READ request: GET / HEAD (a Socket.io packet runs in the scope of its
 * handshake, a GET), or a POST route that declared itself a read with
 * `godViewRead` (a preview, a query run).
 */
function isReadRequest(req: ScopedRequest): boolean {
  const m = (req.method ?? 'GET').toUpperCase();
  return m === 'GET' || m === 'HEAD' || req.godViewRead === true;
}

/**
 * Service level replacement for `isMasterTenant(tenantId)` wherever that test
 * WIDENS a read to every tenant: true only for the master tenant id, inside a
 * god-view READ request positioned on it.
 *
 * Two fail-closed cases beyond Obliance's:
 *  - outside any request: false (see the adaptation above — internal code
 *    never widens);
 *  - inside a WRITE request (POST/PUT/PATCH/DELETE not marked `godViewRead`):
 *    false. A write acts in its object's tenant (`enterObjectTenant`) or fans
 *    out per tenant (`fanOutByTenant`); a list read buried in a write path —
 *    "validate these ids against the tenant's devices" — must never see every
 *    customer's rows because the operator happened to sit on the master tenant.
 */
export function isGodView(tenantId: number | null | undefined): boolean {
  if (!isMasterTenant(tenantId)) return false;
  const req = scopeStore.getStore()?.req;
  if (!req) return false;
  if (!isReadRequest(req)) return false;
  return hasGlobalView(req) && req.tenantId === tenantId;
}

/**
 * Route middleware for a POST that only READS (a preview, a query run): lets
 * the services it calls widen in the god view like a GET would. Never put it
 * on a route that writes.
 */
export function godViewRead(req: Request, _res: Response, next: NextFunction): void {
  req.godViewRead = true;
  next();
}

/**
 * Runs `fn` with the god view OFF for the services it calls, positioned on
 * `tenantId` (the per-tenant batches of `fanOutByTenant`, and any code that
 * must do per-tenant work from inside a god-view request).
 */
export function runAsTenant<T>(req: Request, tenantId: number, fn: () => T): T {
  const scoped: ScopedRequest = {
    session: req.session,
    method: req.method,
    tenantId,
    masterView: false,
    godViewFromTenantId: hasGlobalView(req) && tenantId !== req.tenantId ? req.tenantId : req.godViewFromTenantId,
  };
  return scopeStore.run({ req: scoped }, fn);
}

/** The operator's tenant filter on a god-view list, or null. */
export function currentTenantFilter(): number | null {
  const req = scopeStore.getStore()?.req;
  if (!req || !hasGlobalView(req)) return null;
  const f = req.godViewTenantFilter;
  return typeof f === 'number' && Number.isInteger(f) && f > 0 ? f : null;
}

/**
 * Called by requireTenant once the verdict is known: captures the god-view
 * tenant filter (before `validate()` strips unknown query keys) and marks the
 * response so the client shows the tenant column. A non-god-view request
 * never carries a filter, whatever its query string says.
 */
export function applyGodViewVerdict(req: Request, res: Response | null): void {
  if (!hasGlobalView(req)) {
    delete req.godViewTenantFilter;
    if (res && !res.headersSent) res.setHeader(GOD_VIEW_HEADER, '0');
    return;
  }
  const raw = (req.query as Record<string, unknown> | undefined)?.filterTenantId;
  const n = typeof raw === 'string' && /^[1-9][0-9]{0,9}$/.test(raw) ? Number(raw) : NaN;
  if (Number.isSafeInteger(n)) req.godViewTenantFilter = n;
  if (res && !res.headersSent) res.setHeader(GOD_VIEW_HEADER, '1');
}

// ── List reads ──────────────────────────────────────────────────────────────

/**
 * The tenant predicate of a LIST read. Outside the god view: `column = tenantId`,
 * exactly as before. In the god view: no predicate (every tenant), or the
 * operator's tenant filter when one is set. Returns true when the read is a
 * god-view read, so the caller can attach tenant names and mark its response.
 */
export function applyTenantScope(
  q: Knex.QueryBuilder,
  column: string,
  tenantId: number,
): boolean {
  if (!isGodView(tenantId)) {
    void q.where(column, tenantId);
    return false;
  }
  const f = currentTenantFilter();
  if (f !== null) void q.where(column, f);
  return true;
}

/**
 * The tenant ids a god-view read covers, for code that loops over tenants
 * rather than dropping a predicate: [tenantId] outside the god view; every
 * tenant (or the filter) inside it.
 */
export async function tenantIdsInScope(tenantId: number): Promise<number[]> {
  if (!isGodView(tenantId)) return [tenantId];
  const f = currentTenantFilter();
  if (f !== null) return [f];
  const rows = await db('tenants').orderBy('id').pluck<number[]>('id');
  return rows.map(Number);
}

/** id → name of the given tenants (one query). */
export async function tenantNames(ids: Iterable<number>): Promise<Map<number, string>> {
  const wanted = [...new Set([...ids].map(Number).filter((n) => Number.isInteger(n) && n > 0))];
  if (wanted.length === 0) return new Map();
  const rows = await db('tenants').whereIn('id', wanted).select<Array<{ id: number; name: string }>>('id', 'name');
  return new Map(rows.map((r) => [Number(r.id), r.name]));
}

/**
 * Adds `tenantId` / `tenantName` to each row of a god-view list (one query for
 * the names). `key` names the field carrying the owning tenant on the row.
 * Outside the god view the rows are returned untouched — a tenant's own list
 * never grows a column it has no use for.
 */
export async function withTenantNames<T extends object>(
  rows: T[],
  key: keyof T & string,
  godView: boolean,
): Promise<Array<T & { tenantId?: number; tenantName?: string | null }>> {
  if (!godView || rows.length === 0) return rows;
  const raw = (r: T): unknown => (r as Record<string, unknown>)[key];
  const names = await tenantNames(rows.map((r) => Number(raw(r))));
  return rows.map((r) => {
    // A row owned by no tenant (a shipped library template) stays untagged.
    if (raw(r) === undefined || raw(r) === null) return r;
    const tid = Number(raw(r));
    return { ...r, tenantId: tid, tenantName: names.get(tid) ?? null };
  });
}

/** `{ godView: true }` on a god-view response, `{}` otherwise. */
export function godViewMeta(godView: boolean): { godView?: true } {
  return godView ? { godView: true } : {};
}

// ── Detail reads and single-object actions ──────────────────────────────────

/**
 * Rows a god-view request may follow into their own tenant, and HOW their
 * owning tenant is read. An ALLOW-LIST (never an interpolated identifier),
 * the same discipline as utils/tenantScope.ts. Each entry answers
 * `{ id, tenant_id }` for a set of ids: straight off the row's own
 * `tenant_id`, or through the row it belongs to (a snapshot, a drift run → its
 * device; a drift finding → its run's device; a discovery → its concentrator).
 */
type OwnerQuery = (ids: string[]) => Knex.QueryBuilder;

function ownTenant(table: string): OwnerQuery {
  return (ids) => db(table).whereIn('id', ids).select('id', 'tenant_id');
}

function viaDevice(table: string, column = 'device_id'): OwnerQuery {
  return (ids) =>
    db(`${table} as o`)
      .join('devices as od', 'od.id', `o.${column}`)
      .whereIn('o.id', ids)
      .select('o.id as id', 'od.tenant_id as tenant_id');
}

const OWNERS = {
  devices: ownTenant('devices'),
  sites: ownTenant('sites'),
  device_groups: ownTenant('device_groups'),
  change_jobs: ownTenant('change_jobs'),
  rollouts: ownTenant('rollouts'),
  // Templates and their kin: a shipped LIBRARY row has tenant_id NULL and is
  // therefore never followed (it is readable from every tenant already).
  templates: ownTenant('templates'),
  template_revisions: ownTenant('template_revisions'),
  template_partials: ownTenant('template_partials'),
  template_partial_revisions: ownTenant('template_partial_revisions'),
  template_assignments: ownTenant('template_assignments'),
  interventions: ownTenant('interventions'),
  device_identity_events: ownTenant('device_identity_events'),
  user_teams: ownTenant('user_teams'),
  // Always tenant-owned (tenant_id NOT NULL, migration 005): the Default
  // workspace's are "shared" only in that every tenant may USE them.
  snmp_credentials: ownTenant('snmp_credentials'),
  // Learning mode (migration 089): a capture and a vaulted secret carry their
  // own tenant_id NOT NULL.
  learning_captures: ownTenant('learning_captures'),
  learned_secrets: ownTenant('learned_secrets'),
  config_snapshots: viaDevice('config_snapshots'),
  snmp_interfaces: viaDevice('snmp_interfaces'),
  drift_runs: viaDevice('drift_runs'),
  drift_findings: (ids: string[]) =>
    db('drift_findings as o')
      .join('drift_runs as orun', 'orun.id', 'o.run_id')
      .join('devices as od', 'od.id', 'orun.device_id')
      .whereIn('o.id', ids)
      .select('o.id as id', 'od.tenant_id as tenant_id'),
  discoveries: viaDevice('discoveries', 'concentrator_id'),
} satisfies Record<string, OwnerQuery>;

export type GodViewTable = keyof typeof OWNERS;

const ID_TEXT = /^[1-9][0-9]{0,18}$/;

/** id → owning tenant, for the ids that exist (one query). */
export async function ownerTenantsOf(table: GodViewTable, ids: ReadonlyArray<string | number>): Promise<Map<string, number>> {
  const wanted = [...new Set(ids.map(String).filter((s) => ID_TEXT.test(s)))];
  const query = OWNERS[table];
  if (!query || wanted.length === 0) return new Map();
  const rows = (await query(wanted)) as Array<{ id: number | string; tenant_id: number | null }>;
  const out = new Map<string, number>();
  for (const r of rows) {
    if (r.tenant_id !== null && r.tenant_id !== undefined) out.set(String(r.id), Number(r.tenant_id));
  }
  return out;
}

/** The owning tenant of one row, or null when the row does not exist. */
export async function ownerTenantOf(table: GodViewTable, id: string | number): Promise<number | null> {
  return (await ownerTenantsOf(table, [id])).get(String(id)) ?? null;
}

/**
 * Turns a god-view request into a request IN `ownerTenantId`: the rest of the
 * chain reads, acts and audits in the object's own tenant, exactly as if the
 * platform admin had switched to it (which it may do anyway — a platform admin
 * is exempt from the membership row). The god view is switched OFF for the
 * remainder of the request so nothing downstream widens on top of it, and the
 * origin is kept on `req.godViewFromTenantId` for the audit trail.
 *
 * No-op outside the god view, and when the object already lives in the
 * master tenant.
 */
export function enterObjectTenant(req: Request, ownerTenantId: number): void {
  if (!hasGlobalView(req)) return;
  if (!Number.isInteger(ownerTenantId) || ownerTenantId <= 0) return;
  if (ownerTenantId === req.tenantId) return;
  req.godViewFromTenantId = req.tenantId;
  req.tenantId = ownerTenantId;
  req.masterView = false;
  delete req.godViewTenantFilter;
}

/**
 * `router.param(name, godViewParam('devices'))`: in the god view, any route of
 * that router naming `:name` acts in the tenant of the row it names. A row
 * that does not exist changes nothing — the per-tenant code then answers its
 * usual 404, so the god view adds no existence oracle.
 */
export function godViewParam(table: GodViewTable): RequestParamHandler {
  return (req, _res, next, value) => {
    if (!hasGlobalView(req)) {
      next();
      return;
    }
    ownerTenantOf(table, value as string)
      .then((owner) => {
        if (owner !== null) enterObjectTenant(req, owner);
        next();
      })
      .catch(next);
  };
}

/**
 * Route-level form of godViewParam, for a router where one param name (`:id`)
 * names rows of DIFFERENT tables on different routes (drift: `/runs/:id` and
 * `/findings/:id`), which `router.param` cannot tell apart.
 */
export function godViewFromParam(table: GodViewTable, param = 'id') {
  return (req: Request, _res: Response, next: NextFunction): void => {
    if (!hasGlobalView(req)) {
      next();
      return;
    }
    const raw = req.params?.[param];
    if (raw === undefined) {
      next();
      return;
    }
    ownerTenantOf(table, raw)
      .then((owner) => {
        if (owner !== null) enterObjectTenant(req, owner);
        next();
      })
      .catch(next);
  };
}

/**
 * For a screen whose data is a per-tenant REPORT that cannot be merged across
 * tenants (the CHR ↔ sites reconciliation: one tenant's policy, login rule and
 * orphans): in the god view, the operator's tenant filter (`?filterTenantId=`)
 * picks the tenant the whole request runs in — read and action alike, audited
 * there. Without a filter the request stays on the master tenant, as before.
 */
export function adoptGodViewFilterTenant(req: Request, _res: Response, next: NextFunction): void {
  if (!hasGlobalView(req)) {
    next();
    return;
  }
  const f = req.godViewTenantFilter;
  if (f === undefined) {
    next();
    return;
  }
  db('tenants')
    .where({ id: f })
    .first('id')
    .then((row: { id: number } | undefined) => {
      if (row) enterObjectTenant(req, Number(row.id));
      next();
    })
    .catch(next);
}

/**
 * For an ACTION on ONE client's whole fleet (mine its configurations, collect
 * them all), behind `adoptGodViewFilterTenant`: refused while the request is
 * still in the god view, i.e. while no client was picked in the workspace
 * filter. Without it the action would run on the master tenant itself — whose
 * only router is the shared concentrator — and look like a success.
 */
export function requirePickedTenant(req: Request): void {
  if (hasGlobalView(req)) {
    throw new AppError(
      400,
      'Vue globale : choisissez d’abord le client dans le filtre « Espace de travail » — cette action porte sur un seul client.',
    );
  }
}

/** Same as godViewParam, for an id carried in the BODY (`req.body[field]`). */
export function godViewBodyTenant(table: GodViewTable, field: string) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    if (!hasGlobalView(req)) {
      next();
      return;
    }
    const raw = (req.body as Record<string, unknown> | undefined)?.[field];
    if (raw === undefined || raw === null) {
      next();
      return;
    }
    ownerTenantOf(table, raw as string | number)
      .then((owner) => {
        if (owner !== null) enterObjectTenant(req, owner);
        next();
      })
      .catch(next);
  };
}

/**
 * godViewBodyTenant for a LIST of ids in the body (`req.body[field]`, e.g. a
 * rollout's `deviceIds`): the request acts in the tenant that owns them. A
 * rollout, a compliance or a management-access wave is ONE tenant's object, so
 * ids spanning several tenants are refused with a sentence rather than
 * composed in the master tenant, where every one of them reads "does not
 * exist". Ids that do not exist change nothing (the per-tenant code answers).
 */
export function godViewBodyTenants(table: GodViewTable, field: string) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    if (!hasGlobalView(req)) {
      next();
      return;
    }
    const raw = (req.body as Record<string, unknown> | undefined)?.[field];
    if (!Array.isArray(raw) || raw.length === 0) {
      next();
      return;
    }
    ownerTenantsOf(table, raw as Array<string | number>)
      .then((owners) => {
        const tenants = [...new Set(owners.values())];
        if (tenants.length > 1) {
          next(new AppError(400, `These ${table === 'devices' ? 'routers' : 'objects'} belong to ${tenants.length} different workspaces: compose one per workspace (filter the list on one client).`));
          return;
        }
        if (tenants.length === 1) enterObjectTenant(req, tenants[0]);
        next();
      })
      .catch(next);
  };
}

/** Is this request one the god view moved into an object's tenant? */
export function actedFromGodView(req: { godViewFromTenantId?: number }): boolean {
  return typeof req.godViewFromTenantId === 'number';
}

/**
 * The god-view origin of the current request, for an audit row filed in the
 * object's tenant: `{ viaGodView: true, initiatedFromTenantId }`, or null when
 * the request did not come through the god view.
 */
export function currentGodViewOrigin(): { viaGodView: true; initiatedFromTenantId: number } | null {
  const req = scopeStore.getStore()?.req as { godViewFromTenantId?: number } | undefined;
  if (!req || typeof req.godViewFromTenantId !== 'number') return null;
  return { viaGodView: true, initiatedFromTenantId: req.godViewFromTenantId };
}

// ── Bulk actions ────────────────────────────────────────────────────────────

export interface TenantBatch<R> {
  tenantId: number;
  ids: number[];
  result: R;
}

/**
 * The bulk-action idiom. Outside the god view: `fn(req.tenantId, ids)` once,
 * unchanged. In the god view: the ids are grouped by their owning tenant and
 * `fn` runs once per tenant WITH THAT TENANT — each batch is an ordinary
 * per-tenant action that validates, writes and audits in its own tenant
 * (Obliance's per-tenant fan-out). An id that exists in no tenant refuses the
 * whole action with a 404 before any batch runs.
 *
 * The master tenant's own audit gets one summary row per fan-out
 * (services/godViewAudit.service.ts `auditGodViewFanOut`), each tenant's rows
 * are written by its own batch and carry `godView.initiatedFromTenantId`.
 *
 * Batches run sequentially: a bulk action on a customer fleet is not a race.
 */
export async function fanOutByTenant<R>(
  req: Request,
  table: GodViewTable,
  ids: readonly number[],
  fn: (tenantId: number, ids: number[]) => Promise<R>,
): Promise<{ godView: boolean; batches: Array<TenantBatch<R>> }> {
  const own = req.tenantId;
  if (!hasGlobalView(req)) {
    return { godView: false, batches: [{ tenantId: own, ids: [...ids], result: await fn(own, [...ids]) }] };
  }
  const owner = await ownerTenantsOf(table, ids);
  // An id that exists in no tenant refuses the WHOLE action before any batch
  // runs: the per-tenant paths are all-or-nothing ("nothing was written"), and
  // a god-view fan-out that committed three tenants and then 404'd on the
  // fourth would not be.
  const unknown = ids.filter((id) => !owner.has(String(id)));
  if (unknown.length > 0) {
    throw new AppError(404, `Not found: ${unknown.join(', ')}`);
  }
  const groups = new Map<number, number[]>();
  for (const id of ids) {
    const t = owner.get(String(id)) ?? own;
    const list = groups.get(t) ?? [];
    list.push(Number(id));
    groups.set(t, list);
  }
  const batches: Array<TenantBatch<R>> = [];
  for (const [tenantId, group] of [...groups.entries()].sort((a, b) => a[0] - b[0])) {
    batches.push({ tenantId, ids: group, result: await runAsTenant(req, tenantId, () => fn(tenantId, group)) });
  }
  return { godView: true, batches };
}

export { MASTER_TENANT_ID };
