/**
 * ObliWAN — the 4G backup watch.
 *
 * A third of the fleet can be on its SIM at any moment, and a fixed line that
 * dies on a Friday evening used to be seen on the SIM invoice. The health check
 * already reads the router's ACTIVE default route (migration 073,
 * `observeDefaultRoute`); this file adds WHEN it last moved (migration 075),
 * the history of the moves, and ONE alert when a site with a fixed uplink has
 * been on its cellular link for longer than `backup_4g_alert_delay`.
 *
 * ┌─ WHAT IS RECORDED — `recordDefaultRoute`, from the health check ─────────┐
 * │ Every reading the health check files goes through here (it replaced the  │
 * │ bare UPDATE of 073), under a row lock:                                    │
 * │  · the interface CHANGED since the previous reading → `default_route_     │
 * │    since` = now and one `device_route_transitions` row (from → to);       │
 * │  · same interface → `since` untouched;                                    │
 * │  · an interface but no `since` yet (first reading ever, or a row that     │
 * │    predates 075) → `since` = now, and NO transition: nothing was seen     │
 * │    moving. That understates an old episode, never overstates one;        │
 * │  · no interface (no active route, or one not named) → `since` NULL — the  │
 * │    schema refuses a duration on an unknown interface.                     │
 * │ A failed read stores nothing (073's rule), so it never moves `since`.     │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE ALERT — `decideBackup4g`, pure; `evaluateBackup4g`, after a check ──┐
 * │ RAISED once per episode, when ALL hold:                                   │
 * │  · the stored interface is cellular (`classify` → lte: `lte1`,           │
 * │    `WAN2-LTE`), read within ROUTE_FRESH_MS, by a check that answered;     │
 * │  · `now - since` ≥ the setting (minutes; 0 = off);                        │
 * │  · the site HAS a fixed uplink: a WAN-class interface in the latest       │
 * │    snapshot (interfaces, DHCP clients) or among the active SNMP           │
 * │    interfaces. A 4G-only site is on its only link, not on a backup;       │
 * │  · the SITE'S DECLARATION (migration 076, `sites.uplink_kind`) comes      │
 * │    first: 'cellular_only' never raises, and an open alert CLOSES (a       │
 * │    notice saying why, not "back on the fixed line"); 'fixed' forces the   │
 * │    fixed-uplink premise even when inference finds none; NULL (not         │
 * │    declared) is the inference above, unchanged;                          │
 * │  · the device is active, not a concentrator, and not a bench router       │
 * │    still waiting for its qualification (benchQualification.service.ts).   │
 * │ CLEARED when a reading names a NON-cellular interface again: a recovery   │
 * │ notice, and the stamp goes. An unknown reading neither raises nor clears: │
 * │ lte1 → unknown → lte1 is one episode and one alert.                       │
 * │ The stamp (`devices.backup4g_alerted_at`) is written only AFTER the live  │
 * │ alert exists, by a conditional UPDATE: the check that wins it sends the   │
 * │ channel message, any other sends nothing — the health check's pattern.   │
 * │ Same live-alert + notification pipeline as the down alerts: no new        │
 * │ channel, the device's own global/group/device bindings.                   │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE SIM, AND NULL IS NOT 0 ─────────────────────────────────────────────┐
 * │ The alert, the uplink card and the dashboard name the SIM line linked to  │
 * │ the router (`sim_lines.device_id`) with its LAST KNOWN balance from the   │
 * │ existing line read (`listLines`). A balance the partner did not report    │
 * │ is said to be unknown — never a zero. The cards show it only to a caller  │
 * │ holding SIM_READ; the alert names it because it goes to the operators of  │
 * │ the device's own tenant through the device's own channels.               │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import { SETTINGS_KEYS, clampSetting, isSiteUplinkKind, type SiteUplinkKind } from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { applyTenantScope, tenantNames } from '../../utils/globalView';
import { liveAlertService } from '../liveAlert.service';
import { notificationService } from '../notification.service';
import { settingsService } from '../settings.service';
import { listLines, type SimLineListItem } from '../sim/line.service';
import { resolveBenchQualification } from './benchQualification.service';
import { LIVE_ROUTE_STALE_MS, classify, isUplinkCandidate } from './uplinkModel';
import { expectedCutUntil } from '../change/wanLinkWindow';
import { activeOutageMembership, foldedAlertOutage, markAlertFolded } from './operatorOutageFold';
import { closedStoreRecoveryNotify, judgeClosedStore, recordClosedStoreAlert } from './closedStoreAlerts.service';

/** History kept per device. Pruned at each insert for that device. */
export const ROUTE_TRANSITION_RETENTION_DAYS = 90;
/** A reading older than this does not raise: the health check refreshes it
 *  every five minutes while the router answers, so an older one means the
 *  route read is failing and "on 4G" is no longer a current fact. */
export const ROUTE_FRESH_MS = 15 * 60_000;
/** Transitions shown on the uplink card. */
const RECENT_TRANSITIONS = 5;

// ============================================================================
// Pure — the harness pins these on this fleet's names
// ============================================================================

export function isCellularIface(name: string | null): boolean {
  return name !== null && classify(name, null) === 'lte';
}

/**
 * A FIXED uplink: a PPPoE client, or an ethernet/SFP port named like a WAN
 * (`ether1-WAN1`, `WAN1`, `sfp-ont`), or an `ISP1`-style name (customer E's older
 * template). Never a cellular interface, never a tunnel. `ifType` is SNMP's
 * when there is one (243/244 = cellular whatever the name).
 */
export function isFixedUplinkName(name: string, ifType: number | null): boolean {
  const kind = classify(name, ifType);
  if (kind === 'lte' || kind === 'tunnel') return false;
  if (kind === 'pppoe') return true;
  return isUplinkCandidate(kind, name) || /(^|[^a-z])isp\d*($|[^a-z])/i.test(name);
}

export interface RouteSinceStep {
  /** The new value of `default_route_since`. */
  since: Date | null;
  /** A transition row is written (the interface moved between two readings). */
  changed: boolean;
}

export function nextRouteSince(
  prev: { observed: boolean; iface: string | null; since: Date | null },
  iface: string | null,
  now: Date,
): RouteSinceStep {
  const changed = prev.observed && prev.iface !== iface;
  if (iface === null) return { since: null, changed };
  if (changed || prev.since === null || prev.iface !== iface) return { since: now, changed };
  return { since: prev.since, changed };
}

export type Backup4gHold =
  | 'not_on_cellular'
  | 'off'
  | 'not_concerned'
  | 'held_until_qualified'
  | 'not_answering'
  | 'reading_old'
  | 'not_dated'
  | 'no_fixed_uplink'
  | 'declared_cellular_only'
  | 'not_yet'
  | 'alert_open'
  /** A wan_link job's planned cut of the fixed line (services/change/
   *  wanLinkWindow.ts): riding the 4G is the job working, not a backup. */
  | 'expected_cut';

/** Why an open alert ends: the route came back on a fixed line, or the site
 *  was declared 4G-only (its cellular link is then its nominal path). */
export type Backup4gClearReason = 'back_on_fixed' | 'declared_cellular_only';

export type Backup4gDecision =
  | { action: 'raise' }
  | { action: 'clear'; why: Backup4gClearReason }
  | { action: 'none'; why: Backup4gHold; dueAt?: Date };

export interface Backup4gInput {
  status: string;
  role: string;
  iface: string | null;
  since: Date | null;
  observedAt: Date | null;
  alertedAt: Date | null;
  /** `backup_4g_alert_delay`, minutes. 0 = off. */
  delayMin: number;
  /** The check that just ran answered (a down device has its own alert, and
   *  its route reading is not being refreshed). */
  checkOk: boolean;
  /** A bench router not yet qualified (the health check's `alertsHeld`). */
  alertsHeld: boolean;
  /** Fixed uplinks found for the site; only consulted to raise. */
  fixedUplinks: readonly string[];
  /** The site's declared access link (migration 076). Absent or null = not
   *  declared: the inference (`fixedUplinks`) decides, as before 076. */
  declared?: SiteUplinkKind | null;
  /** The end of a planned WAN link cut covering `now`, or null/absent. */
  expectedCutUntil?: Date | null;
  now: Date;
}

export function decideBackup4g(i: Backup4gInput): Backup4gDecision {
  const cellular = isCellularIface(i.iface);
  const declared = i.declared ?? null;
  if (i.alertedAt !== null) {
    // A site declared 4G-only is on its nominal path: the episode is over,
    // whatever the route reads (an unknown one included).
    if (declared === 'cellular_only') return { action: 'clear', why: 'declared_cellular_only' };
    // Only a NAMED non-cellular interface ends the episode: an unknown one is
    // not "back on the fixed line".
    if (i.iface !== null && !cellular) return { action: 'clear', why: 'back_on_fixed' };
    return { action: 'none', why: 'alert_open' };
  }
  if (!cellular) return { action: 'none', why: 'not_on_cellular' };
  if (declared === 'cellular_only') return { action: 'none', why: 'declared_cellular_only' };
  if (!(i.delayMin > 0)) return { action: 'none', why: 'off' };
  if (i.status !== 'active' || i.role === 'concentrator') return { action: 'none', why: 'not_concerned' };
  if (i.alertsHeld) return { action: 'none', why: 'held_until_qualified' };
  if (!i.checkOk) return { action: 'none', why: 'not_answering' };
  if (!i.observedAt || i.now.getTime() - i.observedAt.getTime() > ROUTE_FRESH_MS) {
    return { action: 'none', why: 'reading_old' };
  }
  if (!i.since) return { action: 'none', why: 'not_dated' };
  // 'fixed' is the operator saying the premise holds, even where neither the
  // snapshot nor SNMP names a fixed interface (a WAN not named like one).
  if (declared !== 'fixed' && i.fixedUplinks.length === 0) return { action: 'none', why: 'no_fixed_uplink' };
  const dueAt = new Date(i.since.getTime() + i.delayMin * 60_000);
  if (i.now.getTime() < dueAt.getTime()) return { action: 'none', why: 'not_yet', dueAt };
  // Held, never dropped: still on the 4G once the planned cut ends, it raises.
  const cut = i.expectedCutUntil ?? null;
  if (cut && i.now.getTime() < cut.getTime()) return { action: 'none', why: 'expected_cut', dueAt: cut };
  return { action: 'raise' };
}

/** The SIM part of a line, as every surface here shows it. */
export interface Backup4gSim {
  lineId: number;
  msisdn: string;
  operator: string | null;
  label: string | null;
  /** NULL = the partner did not report a balance, or it was never read.
   *  Never a zero standing in for "unknown". */
  restMb: number | null;
  zone: string | null;
  observedAt: string | null;
  verdict: SimLineListItem['verdict'];
  stale: boolean;
}

export function simSummary(l: SimLineListItem): Backup4gSim {
  const z = l.worstZone;
  return {
    lineId: l.id,
    msisdn: l.msisdn,
    operator: l.operator,
    label: l.label,
    restMb: z ? z.restMb : null,
    zone: z ? z.zone : null,
    observedAt: z ? z.observedAt : null,
    verdict: l.verdict,
    stale: l.stale,
  };
}

function mbText(mb: number): string {
  return mb >= 1024 ? `${(mb / 1024).toFixed(1)} GB` : `${mb} MB`;
}

/** One English sentence per line (server-side, like every operator message). */
export function simSentence(sims: readonly Backup4gSim[]): string {
  if (sims.length === 0) return 'No SIM line is linked to this router.';
  return sims
    .map((s) => {
      const who = `SIM line ${s.msisdn}${s.operator ? ` (${s.operator})` : ''}`;
      // Not "balance unknown": its balance is deliberately no longer read.
      if (s.verdict === 'terminated') return `${who}: terminated at the partner, no longer read.`;
      if (s.restMb === null) {
        return s.observedAt
          ? `${who}: balance unknown, the partner did not report one (read ${s.observedAt}).`
          : `${who}: balance unknown, never read.`;
      }
      const stale = s.stale ? ' STALE reading' : '';
      return `${who}: ${mbText(s.restMb)} left${s.zone ? ` in ${s.zone}` : ''}, last known at ${s.observedAt}${stale}.`;
    })
    .join(' ');
}

// ============================================================================
// Recording — called by the health check for every reading it files
// ============================================================================

export async function recordDefaultRoute(
  deviceId: number,
  route: { iface: string | null; gateway: string | null },
  now: Date = new Date(),
): Promise<RouteSinceStep | null> {
  return db.transaction(async (trx) => {
    const prev = (await trx('devices')
      .where({ id: deviceId })
      .forUpdate()
      .first('tenant_id', 'default_route_iface', 'default_route_since', 'default_route_observed_at')) as
      | {
          tenant_id: number;
          default_route_iface: string | null;
          default_route_since: Date | null;
          default_route_observed_at: Date | null;
        }
      | undefined;
    if (!prev) return null;
    const step = nextRouteSince(
      {
        observed: prev.default_route_observed_at !== null,
        iface: prev.default_route_iface,
        since: prev.default_route_since ? new Date(prev.default_route_since) : null,
      },
      route.iface,
      now,
    );
    await trx('devices').where({ id: deviceId }).update({
      default_route_iface: route.iface,
      default_route_gateway: route.gateway,
      default_route_observed_at: now,
      default_route_since: step.since,
    });
    if (step.changed) {
      await trx('device_route_transitions').insert({
        tenant_id: prev.tenant_id,
        device_id: deviceId,
        from_iface: prev.default_route_iface,
        to_iface: route.iface,
        at: now,
      });
      await trx('device_route_transitions')
        .where({ device_id: deviceId })
        .where('at', '<', new Date(now.getTime() - ROUTE_TRANSITION_RETENTION_DAYS * 86_400_000))
        .delete();
    }
    return step;
  });
}

// ============================================================================
// Reads
// ============================================================================

/**
 * The fixed uplinks of each device: active SNMP interfaces, plus the latest
 * snapshot's interfaces and DHCP clients (read in SQL, so a fleet list does
 * not parse a whole document per router).
 */
export async function fixedUplinksFor(deviceIds: readonly number[]): Promise<Map<number, string[]>> {
  const out = new Map<number, Set<string>>();
  if (deviceIds.length === 0) return new Map();
  const add = (id: number, name: string | null | undefined, ifType: number | null): void => {
    if (!name || !isFixedUplinkName(name, ifType)) return;
    if (!out.has(id)) out.set(id, new Set());
    out.get(id)!.add(name);
  };
  const snmp = (await db('snmp_interfaces')
    .whereIn('device_id', deviceIds as number[])
    .where({ state: 'active' })
    .select('device_id', 'if_name', 'if_type')) as Array<{ device_id: number; if_name: string; if_type: number | null }>;
  for (const r of snmp) add(Number(r.device_id), r.if_name, r.if_type === null ? null : Number(r.if_type));

  // One placeholder per id: knex expands an array binding into a list, so an
  // `ANY(?)` would not receive an array.
  const ids = deviceIds.map(Number);
  const snap = await db.raw(
    `SELECT DISTINCT ON (s.device_id) s.device_id,
            COALESCE((SELECT jsonb_agg(jsonb_build_array(i->>'name', i->>'type'))
                        FROM jsonb_array_elements(COALESCE(s.ncm->'resources'->'interfaces', '[]'::jsonb)) i), '[]'::jsonb) AS ifs,
            COALESCE((SELECT jsonb_agg(c->>'interfaceName')
                        FROM jsonb_array_elements(COALESCE(s.ncm->'resources'->'dhcpClients', '[]'::jsonb)) c), '[]'::jsonb) AS dhcp
       FROM config_snapshots s
      WHERE s.device_id IN (${ids.map(() => '?').join(', ')})
      ORDER BY s.device_id, s.last_seen_at DESC, s.id DESC`,
    ids,
  );
  for (const r of (snap.rows ?? []) as Array<{ device_id: number; ifs: Array<[string, string | null]>; dhcp: string[] }>) {
    const id = Number(r.device_id);
    // The snapshot's own type says "lte" for a modem whatever its name.
    for (const [name, type] of r.ifs ?? []) add(id, name, type === 'lte' ? 243 : null);
    for (const name of r.dhcp ?? []) add(id, name, null);
  }
  const result = new Map<number, string[]>();
  for (const [id, set] of out) result.set(id, [...set].sort());
  return result;
}

async function simsFor(tenantId: number, deviceId: number): Promise<Backup4gSim[]> {
  const lines = await listLines({ tenantId }, { deviceId });
  return lines.map(simSummary);
}

async function delayFor(tenantId: number, deviceId: number, groupId: number | null): Promise<number> {
  const resolved = await settingsService.resolveForDevice(tenantId, deviceId, groupId);
  const key = SETTINGS_KEYS.BACKUP_4G_ALERT_DELAY;
  return clampSetting(key, Number(resolved[key]?.value));
}

/**
 * The access link the device's SITE is declared with (migration 076), read by
 * the site's tenant AND the device's: a device filed under no site, or under a
 * row of another tenant, has no declaration — never another tenant's.
 */
export async function declaredUplinkOf(
  tenantId: number,
  siteId: number | null,
): Promise<SiteUplinkKind | null> {
  if (siteId === null || siteId === undefined) return null;
  const row = (await db('sites').where({ id: siteId, tenant_id: tenantId }).first('uplink_kind')) as
    | { uplink_kind: string | null }
    | undefined;
  return row && isSiteUplinkKind(row.uplink_kind) ? row.uplink_kind : null;
}

interface RouteRow {
  id: number;
  tenant_id: number;
  group_id: number | null;
  site_id: number | null;
  name: string;
  status: string;
  role: string;
  default_route_iface: string | null;
  default_route_since: Date | null;
  default_route_observed_at: Date | null;
  backup4g_alerted_at: Date | null;
}

const ROUTE_COLUMNS = [
  'id', 'tenant_id', 'group_id', 'site_id', 'name', 'status', 'role',
  'default_route_iface', 'default_route_since', 'default_route_observed_at', 'backup4g_alerted_at',
];

function dateOrNull(v: Date | string | null): Date | null {
  return v === null || v === undefined ? null : new Date(v);
}

// ============================================================================
// The alert — after each health check
// ============================================================================

const pending = new Set<Promise<void>>();

function deliverDetached(deviceId: number, send: () => Promise<void>): void {
  const p: Promise<void> = send()
    .catch((err: unknown) => logger.warn({ err, deviceId }, 'Backup 4G notification failed (the live alert is raised)'))
    .finally(() => { pending.delete(p); });
  pending.add(p);
}

/** For shutdown and harnesses: wait for the channel messages already sent. */
export async function flushBackup4gNotifications(): Promise<void> {
  while (pending.size > 0) await Promise.allSettled(Array.from(pending));
}

export interface Backup4gEvaluation {
  decision: Backup4gDecision;
  /** What this call actually did. */
  done: 'raised' | 'cleared' | null;
  /** The alert (or its recovery) was FOLDED under a grouped operator outage
   *  (migration 095, operatorOutageFold.ts): created, stamped, not sent. */
  folded?: true;
}

/**
 * Called by the health check after it filed its outcome (never changes it:
 * the caller swallows any failure). `delayMin` comes from the check's cached
 * settings; undefined resolves it here.
 */
export async function evaluateBackup4g(
  deviceId: number,
  ctx: { checkOk: boolean; alertsHeld: boolean; delayMin?: number; now?: Date },
): Promise<Backup4gEvaluation | null> {
  const row = (await db('devices').where({ id: deviceId }).first(ROUTE_COLUMNS)) as RouteRow | undefined;
  if (!row) return null;
  const now = ctx.now ?? new Date();
  const alertedAt = dateOrNull(row.backup4g_alerted_at);
  const iface = row.default_route_iface;
  // Nothing to raise or clear: no read beyond the row (the common case).
  if (alertedAt === null && !isCellularIface(iface)) {
    return { decision: { action: 'none', why: 'not_on_cellular' }, done: null };
  }
  const declared = await declaredUplinkOf(row.tenant_id, row.site_id);
  const delayMin = ctx.delayMin ?? (await delayFor(row.tenant_id, row.id, row.group_id));
  const fixed =
    alertedAt === null && declared !== 'cellular_only' ? (await fixedUplinksFor([row.id])).get(row.id) ?? [] : [];
  const since = dateOrNull(row.default_route_since);
  // Only on the raising path: an open alert is cleared as before.
  const cutUntil = alertedAt === null ? await expectedCutUntil(row.id, now) : null;
  const decision = decideBackup4g({
    status: row.status,
    role: row.role,
    iface,
    since,
    observedAt: dateOrNull(row.default_route_observed_at),
    alertedAt,
    delayMin,
    checkOk: ctx.checkOk,
    alertsHeld: ctx.alertsHeld,
    fixedUplinks: fixed,
    declared,
    expectedCutUntil: cutUntil,
    now,
  });

  if (decision.action === 'raise' && since) {
    const sims = await simsFor(row.tenant_id, row.id).catch((err: unknown) => {
      logger.warn({ err, deviceId }, 'Backup 4G alert: SIM lines unreadable, the alert says so');
      return null;
    });
    const minutes = Math.round((now.getTime() - since.getTime()) / 60_000);
    const premise =
      fixed.length > 0
        ? `while its fixed uplink (${fixed.join(', ')}) is configured`
        : 'while its site is declared with a fixed line (no fixed interface was found in its configuration ' +
          'or its SNMP interfaces)';
    const message =
      `${row.name} has been on its cellular link ${iface} since ${since.toISOString()} (${minutes} min), ` +
      `${premise}: the fixed line is probably down, ` +
      'and the site is running on its SIM. ' +
      // The live-alert feed and the notification channels have no SIM_READ
      // guard: the line's number, operator and balance stay on the device page.
      (sims === null || sims.length === 0
        ? ''
        : `${sims.length} SIM line(s) linked: see the device page for the balance.`);
    const title = `${row.name} is on its 4G backup`;
    const stableKey = `backup4g:${row.id}:${since.getTime()}`;
    // A store inside an open operator outage (migration 095): its alert is
    // FOLDED under the group — created as its child and stamped, never sent
    // (operatorOutageFold.ts); the group's one alert already said it, opening
    // hours or not. A membership that cannot be read sends, as before: a
    // missed fold costs one message, a wrong one would cost the alert.
    const fold = await activeOutageMembership(row.id).catch((err: unknown) => {
      logger.warn({ err, deviceId }, 'Operator outage membership unreadable; the 4G backup alert is sent');
      return null;
    });
    if (fold) {
      await liveAlertService.add(row.tenant_id, {
        severity: 'warning',
        title,
        message,
        navigateTo: `/devices/${row.id}`,
        deviceId: row.id,
        stableKey,
        outage: { id: fold.outageId, role: 'member' },
      });
      const stampedFolded = await db('devices')
        .where({ id: row.id })
        .whereNull('backup4g_alerted_at')
        .update({ backup4g_alerted_at: now });
      if (stampedFolded === 0) return { decision, done: null };
      await markAlertFolded(fold.memberId, now);
      return { decision, done: 'raised', folded: true };
    }
    // Opening hours (migration 096): raised while the store is closed, the
    // alert is one level lower (info), marked « magasin fermé », and raised
    // again at the opening if the site is still on 4G (closedStoreAlerts).
    const closed = await judgeClosedStore({
      tenantId: row.tenant_id,
      deviceId: row.id,
      groupId: row.group_id,
      siteId: row.site_id,
      severity: 'warning',
      channelSeverity: 'warning',
      title,
      message,
      at: now,
    });
    await liveAlertService.add(row.tenant_id, {
      severity: closed.closed ? closed.liveSeverity : 'warning',
      title: closed.closed ? closed.title : title,
      message: closed.closed ? closed.message : message,
      navigateTo: `/devices/${row.id}`,
      deviceId: row.id,
      stableKey,
    });
    // THE STAMP, after the live alert exists; the winner sends.
    const stamped = await db('devices')
      .where({ id: row.id })
      .whereNull('backup4g_alerted_at')
      .update({ backup4g_alerted_at: now });
    if (stamped === 0) return { decision, done: null };
    const payload = {
      entityName: row.name,
      entityUrl: `/devices/${row.id}`,
      oldStatus: 'up',
      newStatus: 'alert',
      message,
      timestamp: now.toISOString(),
      stableKey: `obliwan:device:${row.id}:backup4g:${now.getTime()}`,
      severity: 'warning' as const,
      isRecovery: false,
      occurredAt: since.toISOString(),
      entityId: row.id,
      entityType: 'device' as const,
    };
    if (closed.closed) {
      // The episode is the stamp (`backup4g_alerted_at`), which the clear
      // reads back as `alertedAt`.
      await recordClosedStoreAlert({
        tenantId: row.tenant_id,
        deviceId: row.id,
        siteId: row.site_id,
        kind: 'backup_4g',
        episodeAt: now,
        normalSeverity: 'warning',
        title,
        message,
        navigateTo: `/devices/${row.id}`,
        stableKey,
        notification: payload,
        notifiedAtRaise: closed.notify === 'now',
        opensAt: closed.opensAt,
      }).catch((err: unknown) =>
        logger.warn({ err, deviceId: row.id }, 'Closed store: the lowered 4G alert was not recorded, it will not be raised again at the opening'),
      );
      if (closed.notify === 'now') {
        const lowered = { ...payload, message: closed.message, severity: closed.channelSeverity };
        deliverDetached(row.id, () => notificationService.sendForDevice(row.tenant_id, row.id, row.group_id, lowered));
      }
      return { decision, done: 'raised' };
    }
    deliverDetached(row.id, () => notificationService.sendForDevice(row.tenant_id, row.id, row.group_id, payload));
    return { decision, done: 'raised' };
  }

  if (decision.action === 'clear' && alertedAt) {
    const byDeclaration = decision.why === 'declared_cellular_only';
    // Declared 4G-only: the episode ends because the site has no other link,
    // not because one came back — the notice must not say it did.
    const message = byDeclaration
      ? `${row.name}'s site is now declared 4G-only: its cellular link${iface ? ` ${iface}` : ''} is its ` +
        `nominal path, not a backup. The backup alert raised at ${alertedAt.toISOString()} is closed.`
      : `${row.name} is back on ${iface}: its active default route left the cellular link ` +
        `(backup alert raised at ${alertedAt.toISOString()}).`;
    // Raised folded under an operator outage and not released since: the
    // recovery is folded too — the group's own closing notice counts it.
    const foldedUnder = await foldedAlertOutage(row.id, alertedAt).catch(() => null);
    await liveAlertService.add(row.tenant_id, {
      severity: byDeclaration ? 'info' : 'up',
      title: byDeclaration
        ? `${row.name}: 4G backup alert closed (site declared 4G-only)`
        : `${row.name} is back on its fixed line`,
      message,
      navigateTo: `/devices/${row.id}`,
      deviceId: row.id,
      stableKey: `backup4g-end:${row.id}:${alertedAt.getTime()}`,
      outage: foldedUnder !== null ? { id: foldedUnder, role: 'member' } : null,
    });
    const cleared = await db('devices')
      .where({ id: row.id, backup4g_alerted_at: alertedAt })
      .update({ backup4g_alerted_at: null });
    if (cleared === 0) return { decision, done: null };
    if (foldedUnder !== null) return { decision, done: 'cleared', folded: true };
    // An episode raised while the store was closed and never notified (wait
    // for the opening): its end is not notified either.
    if (!(await closedStoreRecoveryNotify(row.id, 'backup_4g', alertedAt))) return { decision, done: 'cleared' };
    deliverDetached(row.id, () =>
      notificationService.sendForDevice(row.tenant_id, row.id, row.group_id, {
        entityName: row.name,
        entityUrl: `/devices/${row.id}`,
        oldStatus: 'alert',
        newStatus: 'up',
        message,
        timestamp: now.toISOString(),
        stableKey: `obliwan:device:${row.id}:backup4g:${alertedAt.getTime()}`,
        severity: 'warning',
        isRecovery: true,
        recoveredAt: now.toISOString(),
        entityId: row.id,
        entityType: 'device',
      }),
    );
    return { decision, done: 'cleared' };
  }
  return { decision, done: null };
}

/**
 * After sites were declared 4G-only (site form, bulk, CSV import): close the
 * open backup alert of every router filed under them NOW, rather than at each
 * router's next health check (which would close it too — `decideBackup4g`
 * reads the declaration first). Goes through `evaluateBackup4g`, so it is the
 * same conditional stamp, the same closing notice and the same channel
 * message as a check would send, at most once. Scoped by tenant. Returns how
 * many alerts this call closed.
 */
export async function closeBackup4gForSites(
  tenantId: number,
  siteIds: readonly number[],
  now: Date = new Date(),
): Promise<number> {
  if (siteIds.length === 0) return 0;
  const ids = (await db('devices')
    .where('tenant_id', tenantId)
    .whereIn('site_id', siteIds as number[])
    .whereNotNull('backup4g_alerted_at')
    .pluck('id')) as number[];
  let closed = 0;
  for (const id of ids) {
    // `checkOk: false`: no check ran, and nothing here may RAISE — only the
    // declared-4G-only clear is reachable with an alert open.
    const ev = await evaluateBackup4g(Number(id), { checkOk: false, alertsHeld: false, now }).catch(
      (err: unknown) => {
        logger.warn({ err, deviceId: id }, 'Closing a 4G backup alert after a 4G-only declaration failed');
        return null;
      },
    );
    if (ev?.done === 'cleared') closed += 1;
  }
  return closed;
}

/**
 * A grouped operator outage closed while this store was still on its 4G
 * (operatorOutage.service.ts, `receded`): the store is followed individually
 * from now on. When its 4G alert was raised FOLDED (`foldedAlertAt`, never
 * sent) and is still open, it is sent NOW — with the incident key the raise
 * would have used, so its later recovery closes the same ticket. Returns
 * whether a message was sent.
 */
export async function sendReleasedBackup4g(
  deviceId: number,
  foldedAlertAt: Date,
  outageLabel: string,
  now: Date = new Date(),
): Promise<boolean> {
  const row = (await db('devices').where({ id: deviceId }).first(ROUTE_COLUMNS)) as RouteRow | undefined;
  if (!row) return false;
  const alertedAt = dateOrNull(row.backup4g_alerted_at);
  // Already back (its folded recovery said so), or another episode: nothing.
  if (!alertedAt || alertedAt.getTime() !== foldedAlertAt.getTime()) return false;
  const since = dateOrNull(row.default_route_since);
  const message =
    `${row.name} is still on its cellular link${row.default_route_iface ? ` ${row.default_route_iface}` : ''}` +
    `${since ? ` since ${since.toISOString()}` : ''} although the grouped operator outage it was part of ` +
    `(${outageLabel}) has ended: its fixed line is probably down for a reason of its own. It is followed ` +
    'individually from now on.';
  await liveAlertService.add(row.tenant_id, {
    severity: 'warning',
    title: `${row.name} is still on its 4G backup`,
    message,
    navigateTo: `/devices/${row.id}`,
    deviceId: row.id,
    stableKey: `backup4g-released:${row.id}:${alertedAt.getTime()}`,
  });
  deliverDetached(row.id, () =>
    notificationService.sendForDevice(row.tenant_id, row.id, row.group_id, {
      entityName: row.name,
      entityUrl: `/devices/${row.id}`,
      oldStatus: 'up',
      newStatus: 'alert',
      message,
      timestamp: now.toISOString(),
      stableKey: `obliwan:device:${row.id}:backup4g:${alertedAt.getTime()}`,
      severity: 'warning',
      isRecovery: false,
      occurredAt: (since ?? alertedAt).toISOString(),
      entityId: row.id,
      entityType: 'device',
    }),
  );
  return true;
}

// ============================================================================
// Views — the uplink card and the dashboard
// ============================================================================

export interface Backup4gTransition {
  from: string | null;
  to: string | null;
  at: string;
}

export interface Backup4gDeviceView {
  iface: string | null;
  cellular: boolean;
  since: string | null;
  observedAt: string | null;
  alertedAt: string | null;
  /** Minutes; 0 = off. */
  delayMin: number;
  /** A bench router not yet qualified: no alert until it is. */
  held: boolean;
  fixedUplinks: string[];
  /** The site's declared access link (migration 076); null = not declared. */
  declaredUplink: SiteUplinkKind | null;
  /** Null when the caller does not hold SIM_READ: not "no line". */
  sims: Backup4gSim[] | null;
  transitions: Backup4gTransition[];
}

export async function backup4gDeviceView(
  tenantId: number,
  deviceId: number,
  opts: { includeSim: boolean; now?: Date },
): Promise<Backup4gDeviceView | null> {
  const row = (await db('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first([...ROUTE_COLUMNS, 'concentrator_id', 'ppp_username'])) as
    | (RouteRow & { concentrator_id: number | null; ppp_username: string | null })
    | undefined;
  if (!row) return null;
  const now = opts.now ?? new Date();
  const qualification = await resolveBenchQualification(row, now, { persist: false }).catch(() => null);
  const transitions = (await db('device_route_transitions')
    .where({ device_id: deviceId, tenant_id: tenantId })
    .orderBy('at', 'desc')
    .limit(RECENT_TRANSITIONS)
    .select('from_iface', 'to_iface', 'at')) as Array<{ from_iface: string | null; to_iface: string | null; at: Date }>;
  const since = dateOrNull(row.default_route_since);
  const observed = dateOrNull(row.default_route_observed_at);
  const alerted = dateOrNull(row.backup4g_alerted_at);
  return {
    iface: row.default_route_iface,
    cellular: isCellularIface(row.default_route_iface),
    since: since ? since.toISOString() : null,
    observedAt: observed ? observed.toISOString() : null,
    alertedAt: alerted ? alerted.toISOString() : null,
    delayMin: await delayFor(tenantId, deviceId, row.group_id),
    held: qualification !== null && qualification.verdict.state !== 'qualified',
    fixedUplinks: (await fixedUplinksFor([deviceId])).get(deviceId) ?? [],
    declaredUplink: await declaredUplinkOf(tenantId, row.site_id),
    sims: opts.includeSim ? await simsFor(tenantId, deviceId) : null,
    transitions: transitions.map((t) => ({ from: t.from_iface, to: t.to_iface, at: new Date(t.at).toISOString() })),
  };
}

export interface Backup4gFleetItem {
  /** God view only: the owning tenant (utils/globalView.ts). */
  tenantId?: number;
  tenantName?: string | null;
  deviceId: number;
  deviceName: string;
  siteId: number | null;
  siteName: string | null;
  iface: string;
  since: string | null;
  observedAt: string;
  alertedAt: string | null;
  fixedUplinks: string[];
  /** The site's declaration: 'fixed' or null here — a site declared 4G-only
   *  is never listed. 'fixed' with no `fixedUplinks` = listed on the
   *  declaration alone. */
  declaredUplink: SiteUplinkKind | null;
  sims: Backup4gSim[] | null;
}

/**
 * Every site of the tenant whose router's active route is on its cellular link
 * while it has a fixed uplink — "on its 4G backup" — oldest episode first. A
 * reading older than 24 h is left out (it is not a current fact), and so is a
 * 4G-only site (it is on its only link).
 *
 * THE DECLARATION (migration 076) decides first: a site DECLARED 4G-only is
 * EXCLUDED from this list — not shown apart: it is not on a backup, and the
 * fleet anomalies page lists it as "expected" on cellular. A site declared
 * 'fixed' is listed even when inference finds no fixed interface; a site not
 * declared keeps the inference.
 */
export async function backup4gFleet(
  tenantId: number,
  /** `deviceIdsIn`: team scope (migration 087) — null/undefined = unrestricted. */
  opts: { includeSim: boolean; now?: Date; deviceIdsIn?: number[] | null },
): Promise<Backup4gFleetItem[]> {
  const now = opts.now ?? new Date();
  const base = db('devices as d')
    .leftJoin('sites as s', function () {
      this.on('s.id', '=', 'd.site_id').andOn('s.tenant_id', '=', 'd.tenant_id');
    });
  // God view: every tenant's sites on backup, each tagged with its tenant.
  const godView = applyTenantScope(base, 'd.tenant_id', tenantId);
  if (opts.deviceIdsIn) base.whereIn('d.id', opts.deviceIdsIn);
  const rows = (await base
    .whereNot('d.role', 'concentrator')
    .whereIn('d.status', ['active'])
    .whereNotNull('d.default_route_iface')
    .where('d.default_route_observed_at', '>', new Date(now.getTime() - LIVE_ROUTE_STALE_MS))
    .select(
      'd.id', 'd.name', 'd.site_id', 's.name as site_name', 's.uplink_kind as site_uplink_kind',
      'd.default_route_iface', 'd.default_route_since', 'd.default_route_observed_at', 'd.backup4g_alerted_at',
      'd.tenant_id',
    )) as Array<{
      id: number; tenant_id: number; name: string; site_id: number | null; site_name: string | null;
      site_uplink_kind: string | null;
      default_route_iface: string; default_route_since: Date | null;
      default_route_observed_at: Date; backup4g_alerted_at: Date | null;
    }>;
  const declaredOf = (r: { site_uplink_kind: string | null }): SiteUplinkKind | null =>
    isSiteUplinkKind(r.site_uplink_kind) ? r.site_uplink_kind : null;
  const cellular = rows.filter(
    (r) => isCellularIface(r.default_route_iface) && declaredOf(r) !== 'cellular_only',
  );
  if (cellular.length === 0) return [];
  const fixed = await fixedUplinksFor(cellular.map((r) => r.id));
  // ONE read of the tenant's lines, grouped here, rather than one per router.
  let sims: Map<number, Backup4gSim[]> | null = null;
  if (opts.includeSim) {
    sims = new Map();
    const wanted = new Set(cellular.map((r) => r.id));
    // The SIM read keeps its own scope rule (SimScope.masterView, set from the
    // same god-view verdict): the god view lists every tenant's lines.
    for (const l of await listLines({ tenantId, masterView: godView })) {
      if (l.deviceId === null || !wanted.has(l.deviceId)) continue;
      const list = sims.get(l.deviceId) ?? [];
      list.push(simSummary(l));
      sims.set(l.deviceId, list);
    }
  }
  const items: Backup4gFleetItem[] = [];
  for (const r of cellular) {
    const f = fixed.get(r.id) ?? [];
    const declared = declaredOf(r);
    if (f.length === 0 && declared !== 'fixed') continue;
    const since = dateOrNull(r.default_route_since);
    const alerted = dateOrNull(r.backup4g_alerted_at);
    items.push({
      ...(godView ? { tenantId: Number(r.tenant_id) } : {}),
      deviceId: r.id,
      deviceName: r.name,
      siteId: r.site_id,
      siteName: r.site_name,
      iface: r.default_route_iface,
      since: since ? since.toISOString() : null,
      observedAt: new Date(r.default_route_observed_at).toISOString(),
      alertedAt: alerted ? alerted.toISOString() : null,
      fixedUplinks: f,
      declaredUplink: declared,
      sims: sims ? sims.get(r.id) ?? [] : null,
    });
  }
  if (godView) {
    const names = await tenantNames(items.map((i) => i.tenantId ?? 0));
    for (const i of items) i.tenantName = names.get(i.tenantId ?? 0) ?? null;
  }
  // Oldest episode first; an undated one last.
  return items.sort((a, b) =>
    (a.since ? Date.parse(a.since) : Number.MAX_SAFE_INTEGER) - (b.since ? Date.parse(b.since) : Number.MAX_SAFE_INTEGER));
}
