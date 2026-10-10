/**
 * ObliWAN — store OPENING HOURS, read side (migration 096).
 *
 * A store down at 03:00 is not an emergency; at 15:00 it is. The model, the
 * readable text and the evaluation live in shared/src/openingHours.ts; this
 * file is where the server reads them for ONE site or a list of sites, always
 * in the SITE's own time zone (`sites.timezone`), never the server's.
 *
 * INHERITANCE: workspace (`tenants.opening_hours`) -> site
 * (`sites.opening_hours`). A site's week replaces its workspace's; dated
 * exceptions merge, the site's winning on a date. There is no group level: the
 * numeric settings chain (global -> group -> device) does not reach sites, and
 * a store's hours are a fact about the store.
 *
 * UNKNOWN IS NOT CLOSED. A site with no effective week (neither its own nor
 * its workspace's), an unknown site, or a time zone this runtime cannot read
 * answers null, and every consumer then keeps the behaviour it had before 096:
 * alerts at their usual severity, notifications sent, pushes on the explicit
 * maintenance window only.
 *
 * THE CONTRACT another subsystem depends on: `siteOpenAt` and
 * `nextClosedWindow`, with these exact signatures.
 */
import {
  SETTINGS_KEYS,
  SOCKET_EVENTS,
  effectiveOpeningHours,
  formatOpeningHours,
  isEmptyOpeningHours,
  isKnownTimeZone,
  isOpenAt,
  nextChangeIn,
  nextClosedWindowIn,
  readOpeningHours,
  validateOpeningHours,
  type EffectiveOpeningHours,
  type OpeningHours,
  type SiteOpenState,
} from '@obliwan/shared';
import { db } from '../../db';
import { AppError } from '../../middleware/errorHandler';
import { logger } from '../../utils/logger';
import { appendAudit } from '../attestation/auditLog.service';
import { settingsService } from '../settings.service';
import { toSiteDto } from './dto';
import { emitToTenantAudience } from './scopedEmit';
import type { SiteRow } from './site.service';

export interface SiteHours {
  siteId: number;
  tenantId: number;
  timezone: string;
  hours: EffectiveOpeningHours;
}

interface SiteHoursRow {
  id: number;
  tenant_id: number;
  timezone: string | null;
  site_hours: unknown;
  tenant_hours: unknown;
}

/** Zones already complained about: one log line per process, not per call. */
const warnedZones = new Set<string>();

function toSiteHours(row: SiteHoursRow): SiteHours | null {
  const hours = effectiveOpeningHours(readOpeningHours(row.tenant_hours), readOpeningHours(row.site_hours));
  if (hours === null) return null;
  const tz = row.timezone || 'Europe/Paris';
  if (!isKnownTimeZone(tz)) {
    if (!warnedZones.has(tz)) {
      warnedZones.add(tz);
      logger.warn({ siteId: row.id, timezone: tz }, 'Opening hours: unknown time zone, the hours of this site are treated as unknown');
    }
    return null;
  }
  return { siteId: row.id, tenantId: row.tenant_id, timezone: tz, hours };
}

function hoursQuery() {
  return db('sites as s')
    .join('tenants as t', 't.id', 's.tenant_id')
    .select('s.id', 's.tenant_id', 's.timezone', 's.opening_hours as site_hours', 't.opening_hours as tenant_hours');
}

/** The effective hours of one site, or null when none are known. */
export async function loadSiteHours(siteId: number): Promise<SiteHours | null> {
  if (!Number.isInteger(siteId) || siteId <= 0) return null;
  const row = (await hoursQuery().where('s.id', siteId).first()) as SiteHoursRow | undefined;
  return row ? toSiteHours(row) : null;
}

/** The effective hours of several sites; a site with none known is absent. */
export async function loadSitesHours(siteIds: readonly number[]): Promise<Map<number, SiteHours>> {
  const out = new Map<number, SiteHours>();
  const ids = Array.from(new Set(siteIds.filter((id) => Number.isInteger(id) && id > 0)));
  for (let i = 0; i < ids.length; i += 1000) {
    const rows = (await hoursQuery().whereIn('s.id', ids.slice(i, i + 1000))) as SiteHoursRow[];
    for (const row of rows) {
      const h = toSiteHours(row);
      if (h) out.set(row.id, h);
    }
  }
  return out;
}

/** Open at `at`, or null = no hours known. Pure on an already loaded value. */
export function openAt(h: SiteHours | null | undefined, at: Date): boolean | null {
  if (!h) return null;
  return isOpenAt(h.hours, h.timezone, at);
}

/**
 * Is the store open at `at`, in its own time zone? null = no hours known for
 * this site (or an unknown site): the caller keeps its pre-096 behaviour.
 */
export async function siteOpenAt(siteId: number, at: Date): Promise<boolean | null> {
  return openAt(await loadSiteHours(siteId), at);
}

/**
 * The next period the store is CLOSED, seen from `from`, in its own time zone.
 * If it is closed at `from`, the period in progress, starting at `from`.
 * `end` is the next opening (capped OPENING_HORIZON_DAYS ahead for a store
 * that never opens again). null = no hours known, or a store never closed
 * within the horizon (open around the clock).
 */
export async function nextClosedWindow(
  siteId: number,
  from: Date,
): Promise<{ start: Date; end: Date } | null> {
  const h = await loadSiteHours(siteId);
  if (!h) return null;
  return nextClosedWindowIn(h.hours, h.timezone, from);
}

/** "Ouvert / Fermé maintenant" of one loaded site (lists and the device page). */
export function openStateOf(h: SiteHours | null | undefined, at: Date): SiteOpenState {
  if (!h) return { open: null, nextChangeAt: null, source: null };
  const next = nextChangeIn(h.hours, h.timezone, at);
  return {
    open: isOpenAt(h.hours, h.timezone, at),
    nextChangeAt: next ? next.toISOString() : null,
    source: h.hours.weekSource,
  };
}

/** The open state of every listed site; unknown ones carry `open: null`. */
export async function siteOpenStates(
  siteIds: readonly number[],
  at: Date = new Date(),
): Promise<Map<number, SiteOpenState>> {
  const hours = await loadSitesHours(siteIds);
  const out = new Map<number, SiteOpenState>();
  for (const id of siteIds) out.set(id, openStateOf(hours.get(id), at));
  return out;
}

// ============================================================================
// Closed hours as the default maintenance window (setting, OFF by default)
// ============================================================================

const SETTING_TTL_MS = 60_000;
const settingCache = new Map<string, { value: number; until: number }>();

/** `closed_hours_maintenance` for a device, cached a minute (the queue asks every 3 s). */
async function closedHoursMaintenanceOn(tenantId: number, deviceId: number, groupId: number | null): Promise<boolean> {
  const now = Date.now();
  const cacheKey = `${tenantId}:${deviceId}`;
  const hit = settingCache.get(cacheKey);
  if (hit && hit.until > now) return hit.value === 1;
  const resolved = await settingsService.resolveForDevice(tenantId, deviceId, groupId);
  const value = Number(resolved[SETTINGS_KEYS.CLOSED_HOURS_MAINTENANCE]?.value ?? 0);
  settingCache.set(cacheKey, { value, until: now + SETTING_TTL_MS });
  return value === 1;
}

/** For a harness: forget the cached settings. */
export function resetOpeningHoursCaches(): void {
  settingCache.clear();
}

/**
 * The verdict of the CLOSED-HOURS default window for a job on a device whose
 * site has NO explicit maintenance window — or null when it does not apply
 * (setting off, no site, hours unknown), in which case the queue keeps its
 * pre-096 rule: no window = open. Never consulted for a site that HAS a window:
 * an explicit window is never overridden.
 *
 * Applies: open when the store is closed at `at`, otherwise closed with the
 * reason. A failure to read is thrown — the caller holds the job (fail
 * closed: the operator asked for pushes in closed hours only).
 */
export async function closedHoursWindowVerdict(
  target: { tenantId: number; deviceId: number; groupId: number | null; siteId: number | null },
  at: Date,
): Promise<{ open: boolean; reason: string | null } | null> {
  if (target.siteId === null) return null;
  if (!(await closedHoursMaintenanceOn(target.tenantId, target.deviceId, target.groupId))) return null;
  const h = await loadSiteHours(target.siteId);
  if (!h) return null;
  const open = isOpenAt(h.hours, h.timezone, at);
  if (!open) return { open: true, reason: null };
  const next = nextChangeIn(h.hours, h.timezone, at);
  return {
    open: false,
    reason:
      `the store is open (tz ${h.timezone}); with no explicit maintenance window, its closed hours are the ` +
      `window (setting closed_hours_maintenance)${next ? `, next closing ${next.toISOString()}` : ''}`,
  };
}

// ============================================================================
// Writes — the workspace's hours, and many sites at once
// ============================================================================
//
// SITE_WRITE, like the rest of the customer record: the hours change what is
// ALERTED and when, never what is written to a router. When the inherited
// setting `closed_hours_maintenance` is on, they also decide when pushes run on
// a site with no explicit window — a setting only SETTINGS_MANAGE turns on,
// knowing that account managers keep the store hours.

export interface OpeningHoursActor {
  userId: number | null;
  username: string | null;
}

/** The workspace's own hours (what its sites inherit), or null. */
export async function getTenantOpeningHours(tenantId: number): Promise<OpeningHours | null> {
  const row = (await db('tenants').where({ id: tenantId }).first('opening_hours')) as
    | { opening_hours: unknown }
    | undefined;
  if (!row) throw new AppError(404, 'Workspace not found');
  return readOpeningHours(row.opening_hours);
}

/** Set (or clear, with null) the workspace's hours; audited in the same transaction. */
export async function setTenantOpeningHours(
  tenantId: number,
  hours: OpeningHours | null,
  actor: OpeningHoursActor,
): Promise<OpeningHours | null> {
  const value = isEmptyOpeningHours(hours) ? null : hours;
  await db.transaction(async (trx) => {
    const row = (await trx('tenants').where({ id: tenantId }).forUpdate().first('opening_hours')) as
      | { opening_hours: unknown }
      | undefined;
    if (!row) throw new AppError(404, 'Workspace not found');
    const before = readOpeningHours(row.opening_hours);
    await trx('tenants')
      .where({ id: tenantId })
      .update({ opening_hours: value === null ? null : JSON.stringify(value) });
    await appendAudit(
      {
        tenantId,
        actorType: 'user',
        actorId: actor.userId,
        actorName: actor.username,
        action: 'tenant.opening_hours_set',
        entityType: 'tenant',
        entityId: tenantId,
        before: { openingHours: before === null ? null : formatOpeningHours(before) },
        after: { openingHours: value === null ? null : formatOpeningHours(value) },
      },
      trx,
    );
  });
  return value;
}

/**
 * How a bulk write combines with what a site already carries:
 *  - `replace`: the given value IS the site's (null = inherit everything);
 *  - `merge`:   a week in the value replaces the site's week, its dated
 *               exceptions are added (replacing the site's on the same date),
 *               everything else the site carries stays — "these twelve stores
 *               open on Sunday the 20th".
 */
export type OpeningHoursBulkMode = 'replace' | 'merge';

export function mergeOpeningHours(current: OpeningHours | null, given: OpeningHours): OpeningHours {
  const byDate = new Map<string, OpeningHours['exceptions'][number]>();
  for (const e of current?.exceptions ?? []) byDate.set(e.date, e);
  for (const e of given.exceptions) byDate.set(e.date, e);
  return {
    week: given.week ?? current?.week ?? null,
    exceptions: Array.from(byDate.values()).sort((a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : 0)),
  };
}

export interface OpeningHoursBulkResult {
  requested: number;
  changed: number;
  unchanged: number;
  changedSiteIds: number[];
}

/**
 * One opening-hours write for many sites of `tenantId`. ALL OR NOTHING on
 * tenancy (every id a site of this workspace, read under row locks, or 404 with
 * nothing written), like the access-link bulk. Audited once, in the same
 * transaction.
 */
export async function bulkSetSiteOpeningHours(
  tenantId: number,
  ids: readonly number[],
  hours: OpeningHours | null,
  mode: OpeningHoursBulkMode,
  actor: OpeningHoursActor,
): Promise<OpeningHoursBulkResult> {
  const unique = [...new Set(ids.map(Number))];
  if (unique.length === 0) throw new AppError(400, 'Aucun site sélectionné.');
  const done = await db.transaction(async (trx) => {
    const rows = (await trx('sites')
      .where('tenant_id', tenantId)
      .whereIn('id', unique)
      .forUpdate()
      .select('id', 'opening_hours')) as Array<{ id: number; opening_hours: unknown }>;
    if (rows.length !== unique.length) {
      throw new AppError(
        404,
        `${unique.length - rows.length} des ${unique.length} site(s) demandés ne sont pas des sites de cet espace ` +
          '(ou n’existent plus) : aucun site n’a été modifié.',
      );
    }
    const changedIds: number[] = [];
    for (const r of rows) {
      const current = readOpeningHours(r.opening_hours);
      let next: OpeningHours | null =
        mode === 'merge' && hours !== null ? mergeOpeningHours(current, hours) : hours;
      if (next !== null) {
        const checked = validateOpeningHours(next);
        if (!checked.ok) throw new AppError(400, `Site #${r.id} : ${checked.error}`);
        next = isEmptyOpeningHours(checked.value) ? null : checked.value;
      }
      if (JSON.stringify(current) === JSON.stringify(next)) continue;
      await trx('sites')
        .where({ id: r.id, tenant_id: tenantId })
        .update({ opening_hours: next === null ? null : JSON.stringify(next), updated_at: db.fn.now() });
      changedIds.push(r.id);
    }
    if (changedIds.length > 0) {
      await appendAudit(
        {
          tenantId,
          actorType: 'user',
          actorId: actor.userId,
          actorName: actor.username,
          action: 'site.opening_hours.bulk',
          entityType: 'site',
          entityId: null,
          before: null,
          after: {
            mode,
            openingHours: hours === null ? null : formatOpeningHours(hours),
            requested: unique.length,
            changed: changedIds.length,
            siteIds: [...changedIds].sort((a, b) => a - b),
          },
        },
        trx,
      );
    }
    return { changedIds, unchanged: rows.length - changedIds.length };
  });
  if (done.changedIds.length > 0) {
    const updated = (await db('sites').where('tenant_id', tenantId).whereIn('id', done.changedIds)) as SiteRow[];
    for (const r of updated) {
      emitToTenantAudience(tenantId, SOCKET_EVENTS.SITE_UPDATED, { site: toSiteDto(r) }, { siteId: r.id });
    }
  }
  return {
    requested: unique.length,
    changed: done.changedIds.length,
    unchanged: done.unchanged,
    changedSiteIds: [...done.changedIds].sort((a, b) => a - b),
  };
}

/**
 * What the site page shows next to its hours: the workspace's own hours (what
 * it inherits), the open state now, and whether its closed hours are its
 * maintenance window — only with no explicit window and known hours, judged on
 * the WORKSPACE-level value of the setting (a group or device override may
 * differ per router; the queue reads those per device).
 */
export async function siteHoursContext(
  site: { id: number; tenant_id: number; maintenance_window: unknown },
  at: Date = new Date(),
): Promise<{
  tenantOpeningHours: OpeningHours | null;
  openState: SiteOpenState;
  maintenanceFromClosedHours: boolean;
}> {
  const tenantId = Number(site.tenant_id);
  const [tenantHours, hours, global] = await Promise.all([
    getTenantOpeningHours(tenantId).catch(() => null),
    loadSiteHours(Number(site.id)),
    settingsService.resolveGlobal(tenantId),
  ]);
  const settingOn =
    Number(
      global.overrides[SETTINGS_KEYS.CLOSED_HOURS_MAINTENANCE] ??
        global.resolved[SETTINGS_KEYS.CLOSED_HOURS_MAINTENANCE]?.value ??
        0,
    ) === 1;
  const noWindow = site.maintenance_window === null || site.maintenance_window === undefined;
  return {
    tenantOpeningHours: tenantHours,
    openState: openStateOf(hours, at),
    maintenanceFromClosedHours: settingOn && noWindow && hours !== null,
  };
}
