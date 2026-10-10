/**
 * ObliWAN — line quality of each store's FIXED line, measured outside opening
 * hours (operator GO 2026-10-09: « détecter les lignes fixes dégradées avant
 * que le magasin n'appelle »). Vocabulary: shared/src/lineQuality.ts. Pure
 * half (parsing, forcing the ping through the fixed line, judging, status):
 * lineQualityModel.ts. Storage: migration 097.
 *
 * ┌─ 1. WHEN — once per night and site, leader only ─────────────────────────┐
 * │ Every LINE_QUALITY_TICK_MS the leader plans the routers whose site has   │
 * │ no final row for the current NIGHT (the site's local date of now − 12 h). │
 * │ Opening hours known (openingHours.service): the store closed for half an │
 * │ hour and staying closed three more (a lunch break is not a night).       │
 * │ Unknown (null, or a site the service cannot read): the inherited night  │
 * │ window, 01:00–06:00 in the site's time zone by default. A failed attempt │
 * │ is retried after RETRY_AFTER_MS, at most MAX_ATTEMPTS a night; a final  │
 * │ refusal (4G-only site, no API channel, identity…) is not.                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ 2. WHAT — read-only towards the router ─────────────────────────────────┐
 * │ Nothing is written to a router: reads and `/ping`, a measurement         │
 * │ tool that changes no configuration. Per router, in this order:            │
 * │  · refusals read in the database: the site declared 4G-only, no usable   │
 * │    RouterOS API channel, no target, a change job queued or running, a   │
 * │    planned WAN link cut in progress;                                      │
 * │  · behind a concentrator, a degraded concentrator or a PPP               │
 * │    session that is not open on it — NEVER dialled;                        │
 * │  · on the pooled API session, the three identity attributes are read     │
 * │    (`readRouterOsIdentity`) and compared with the record (a rename's     │
 * │    frozen pair accepted, as everywhere): a mismatch or an unproven box   │
 * │    is not measured — its figures would be about another store's line;   │
 * │  · the WAN1 shape (PPPoE clients, the NW-WAN1 probe route, the active    │
 * │    default route), `link-downs` of the WAN interface, the uptime;        │
 * │  · 20 pings per target, forced through the fixed line where the template │
 * │    allows it (lineQualityModel.ts header), the carrier recorded either   │
 * │    way; the default route read again after them.                         │
 * │ Bounded: LINE_QUALITY_CONCURRENCY routers at a time, each within         │
 * │ LINE_QUALITY_DEVICE_BUDGET_MS, every read through the pool (its breaker  │
 * │ and its 2 dials/s budget).                                                │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ 3. THE DAY'S COUNTERS — from what ObliWAN already stores ───────────────┐
 * │ over the 24 h before the measurement: moves of the active default route  │
 * │ onto the 4G (`device_route_transitions`), sessions of the management     │
 * │ tunnel the concentrator saw open (`ppp_sessions`), WAN1 errors from the  │
 * │ SNMP 5-minute rollups when the port is polled (else NULL, never 0); and  │
 * │ the router's own `link-downs` delta since the previous night. The judged │
 * │ « reconnections » is max(link-downs, failovers).                          │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ 4. THE VERDICT AND THE GROUPED ALERT ───────────────────────────────────┐
 * │ Each measured night is judged (`judgeNight`) against the inherited       │
 * │ thresholds and the site's baseline (medians of its previous 14 FIXED-    │
 * │ line nights — a 4G-carried night never enters it). « dégradée » after    │
 * │ `line_quality_nights` consecutive exceeded nights, « à surveiller »      │
 * │ after one. ONE low-severity live alert per tenant lists the degraded     │
 * │ lines (re-issued when a line joins the list), and a notice closes it     │
 * │ when none is left (`line_quality_alerts`).                                │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import pLimit from 'p-limit';
import { createHash } from 'crypto';
import {
  LINE_QUALITY_FINAL_SKIPS,
  SETTINGS_KEYS,
  clampSetting,
  intToIpv4,
  isPingableIpv4,
  type LineQualityBaseline,
  type LineQualityCarrier,
  type LineQualityDeviceView,
  type LineQualityFleetItem,
  type LineQualityNightView,
  type LineQualityReason,
  type LineQualitySkipReason,
  type LineQualityStatus,
  type LineQualityTargetResult,
  type LineQualityThresholds,
  type LineQualityVerdict,
  type SettingsKey,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { applyTenantScope, tenantNames } from '../../utils/globalView';
import { leaderElection } from '../leaderElection';
import { settingsService } from '../settings.service';
import { liveAlertService } from '../liveAlert.service';
import { RouterOsTrapError, type RouterOsConnection } from '../transport/routeros';
import { expectedCutUntil } from '../change/wanLinkWindow';
import { getRouterOsPool, resolveRouterOsTarget } from './routerosPool';
import { compareIdentity, readRouterOsIdentity } from './deviceBinding.service';
import { renameIdentityAlternates } from './identityAlternates';
import { isConcentratorDegraded } from './reachability.service';
import { declaredUplinkOf, fixedUplinksFor, isCellularIface } from './backup4g.service';
import { routerOsApiChannelUsable } from './healthCheck.service';
import { hopsFromGatewayStatus, hopsFromImmediateGw, readActiveDefaultRoute, type ActiveDefaultRoute } from './uplinkModel';
import { nextClosedWindow, siteOpenAt } from './openingHours.service';
import {
  BASELINE_WINDOW_NIGHTS,
  CLOSED_SETTLE_MS,
  LINE_QUALITY_PING_COUNT,
  WAN1_PORT,
  addDays,
  aggregateTargets,
  alertStep,
  carrierOf,
  computeBaseline,
  decideMoment,
  inNightWindow,
  judgeNight,
  linkDownsDelta,
  nightOf,
  parseRosUptimeSec,
  pickPppoe,
  planTarget,
  reconnectionsOf,
  routerInt,
  safeZone,
  settleCarrier,
  siteLineStatus,
  summarisePing,
  type NightFacts,
  type PppoeClientRow,
  type ProbeRouteReading,
  type WanShape,
} from './lineQualityModel';

// ============================================================================
// Tunables (they bound the scheduler, not a site's policy)
// ============================================================================

export const LINE_QUALITY_TICK_MS = 5 * 60_000;
export const LINE_QUALITY_CONCURRENCY = 6;
/** One router: identity, a handful of reads, two pings of 20, one more read. */
export const LINE_QUALITY_DEVICE_BUDGET_MS = 150_000;
export const MAX_ATTEMPTS = 4;
export const RETRY_AFTER_MS = 30 * 60_000;
/** Rows older than this are pruned (once a day). */
export const LINE_QUALITY_RETENTION_NIGHTS = 120;
/** How far back the views and the alert read. */
const VIEW_NIGHTS = 16;
const READ_TIMEOUT_MS = 15_000;
/** 20 pings at 1 s, each waiting up to 1 s for its reply, plus margin. */
const PING_TIMEOUT_MS = 50_000;
const COUNTER_WINDOW_MS = 24 * 3600_000;
const SETTINGS_TTL_MS = 10 * 60_000;
const ALERT_SWEEP_EVERY_MS = 3600_000;
const ACTIVE_JOB_STATUSES = ['queued', 'claimed', 'backing_up', 'arming', 'applying', 'verifying', 'soaking', 'disarming'];

// ============================================================================
// Seams
// ============================================================================

/** The part of a RouterOS session this file uses (`queryFirst`: the identity
 *  reader's). */
export interface RouterQuery {
  query(words: string[], options?: { timeoutMs?: number }): Promise<Array<Record<string, string>>>;
  queryFirst(words: string[], options?: { timeoutMs?: number }): Promise<Record<string, string> | null>;
}

export interface LineQualityDeps {
  now(): Date;
  /** Run `fn` on the router's API session (the pool, its breaker, its budget). */
  withRouter<T>(deviceId: number, fn: (conn: RouterQuery) => Promise<T>): Promise<T>;
  siteOpenAt(siteId: number, at: Date): Promise<boolean | null>;
  nextClosedWindow(siteId: number, from: Date): Promise<{ start: Date; end: Date } | null>;
  deviceBudgetMs: number;
  concurrency: number;
}

const DEFAULT_DEPS: LineQualityDeps = {
  now: () => new Date(),
  withRouter: async (deviceId, fn) => {
    const target = await resolveRouterOsTarget(deviceId);
    return getRouterOsPool().withConnection(target, (conn) => fn(conn));
  },
  siteOpenAt: (siteId, at) => siteOpenAt(siteId, at),
  nextClosedWindow: (siteId, from) => nextClosedWindow(siteId, from),
  deviceBudgetMs: LINE_QUALITY_DEVICE_BUDGET_MS,
  concurrency: LINE_QUALITY_CONCURRENCY,
};
let deps: LineQualityDeps = { ...DEFAULT_DEPS };
export function setLineQualityDeps(next: Partial<LineQualityDeps>): void {
  deps = { ...deps, ...next };
}
export function resetLineQualityDeps(): void {
  deps = { ...DEFAULT_DEPS };
  settingsCache.clear();
}

// ============================================================================
// Settings — inherited per device, cached briefly
// ============================================================================

export interface LineQualitySettings {
  targets: string[];
  nightStart: number;
  nightEnd: number;
  thresholds: LineQualityThresholds;
}

const settingsCache = new Map<number, { key: string; at: number; value: LineQualitySettings }>();

export async function resolveLineQualitySettings(
  tenantId: number,
  deviceId: number,
  groupId: number | null,
  opts: { fresh?: boolean } = {},
): Promise<LineQualitySettings> {
  const cacheKey = `${tenantId}:${groupId ?? ''}`;
  const hit = settingsCache.get(deviceId);
  if (!opts.fresh && hit && hit.key === cacheKey && Date.now() - hit.at < SETTINGS_TTL_MS) return hit.value;
  const resolved = await settingsService.resolveForDevice(tenantId, deviceId, groupId);
  const num = (key: SettingsKey): number => clampSetting(key, Number(resolved[key]?.value));
  const targets = [num(SETTINGS_KEYS.LINE_QUALITY_TARGET_1), num(SETTINGS_KEYS.LINE_QUALITY_TARGET_2)]
    .map((n) => intToIpv4(n))
    .filter((ip): ip is string => ip !== null && isPingableIpv4(ip));
  const value: LineQualitySettings = {
    targets: [...new Set(targets)],
    nightStart: num(SETTINGS_KEYS.LINE_QUALITY_NIGHT_START),
    nightEnd: num(SETTINGS_KEYS.LINE_QUALITY_NIGHT_END),
    thresholds: {
      lossPct: num(SETTINGS_KEYS.LINE_QUALITY_LOSS_PCT),
      latencyMs: num(SETTINGS_KEYS.LINE_QUALITY_LATENCY_MS),
      reconnections: num(SETTINGS_KEYS.LINE_QUALITY_RECONNECTIONS),
      relativePct: num(SETTINGS_KEYS.LINE_QUALITY_RELATIVE_PCT),
      nights: num(SETTINGS_KEYS.LINE_QUALITY_NIGHTS),
    },
  };
  settingsCache.set(deviceId, { key: cacheKey, at: Date.now(), value });
  return value;
}

/** Drop the cached settings (a harness that changes one). */
export function clearLineQualitySettingsCache(): void {
  settingsCache.clear();
}

// ============================================================================
// Rows
// ============================================================================

interface NightRow {
  id: string | number;
  tenant_id: number;
  site_id: number;
  device_id: number | null;
  night: string | Date;
  status: 'pending' | 'measured' | 'skipped';
  skip_reason: LineQualitySkipReason | null;
  final: boolean;
  attempts: number;
  last_attempt_at: Date | null;
  schedule_source: 'opening_hours' | 'night_window' | null;
  measured_at: Date | null;
  carrier: LineQualityCarrier | null;
  uplink_iface: string | null;
  method: string | null;
  wan_shape: string | null;
  targets: LineQualityTargetResult[] | null;
  sent: number | null;
  received: number | null;
  loss_pct: string | number | null;
  rtt_min_ms: string | number | null;
  rtt_avg_ms: string | number | null;
  rtt_max_ms: string | number | null;
  jitter_ms: string | number | null;
  fixed_down: boolean;
  link_downs_iface: string | null;
  link_downs_total: string | number | null;
  boot_at: Date | null;
  link_downs: number | null;
  failovers: number | null;
  mgmt_reconnects: number | null;
  wan1_errors: string | number | null;
  reconnections: number | null;
  verdict: LineQualityVerdict;
  reasons: LineQualityReason[] | null;
  baseline: LineQualityBaseline | null;
  thresholds: LineQualityThresholds | null;
}

const numOrNull = (v: string | number | null | undefined): number | null =>
  v === null || v === undefined || v === '' ? null : Number(v);
const iso = (d: Date | string | null | undefined): string | null => (d ? new Date(d).toISOString() : null);

/** pg returns a DATE as a JS Date at local midnight, or a string: one form. */
export function nightKey(v: string | Date): string {
  if (typeof v === 'string') return v.slice(0, 10);
  return `${v.getFullYear()}-${String(v.getMonth() + 1).padStart(2, '0')}-${String(v.getDate()).padStart(2, '0')}`;
}

function toFacts(r: NightRow): NightFacts {
  return {
    night: nightKey(r.night),
    carrier: r.carrier,
    lossPct: numOrNull(r.loss_pct),
    rttAvgMs: numOrNull(r.rtt_avg_ms),
    fixedDown: r.fixed_down,
    reconnections: r.reconnections,
  };
}

export function toNightView(r: NightRow): LineQualityNightView {
  return {
    night: nightKey(r.night),
    status: r.status,
    skipReason: r.skip_reason,
    attempts: Number(r.attempts),
    measuredAt: iso(r.measured_at),
    scheduleSource: r.schedule_source,
    carrier: r.carrier,
    uplinkIface: r.uplink_iface,
    method: r.method,
    lossPct: numOrNull(r.loss_pct),
    rttMinMs: numOrNull(r.rtt_min_ms),
    rttAvgMs: numOrNull(r.rtt_avg_ms),
    rttMaxMs: numOrNull(r.rtt_max_ms),
    jitterMs: numOrNull(r.jitter_ms),
    sent: r.sent,
    received: r.received,
    fixedDown: r.fixed_down,
    linkDowns: r.link_downs,
    failovers: r.failovers,
    mgmtReconnects: r.mgmt_reconnects,
    wan1Errors: numOrNull(r.wan1_errors),
    reconnections: r.reconnections,
    verdict: r.verdict,
    reasons: r.reasons ?? [],
    baseline: r.baseline,
    targets: r.targets ?? [],
  };
}

// ============================================================================
// Candidates
// ============================================================================

export interface LineQualityCandidate {
  id: number;
  tenant_id: number;
  group_id: number | null;
  name: string;
  site_id: number;
  site_code: string;
  site_name: string;
  timezone: string;
  concentrator_id: number | null;
  ppp_username: string | null;
  tunnel_ip: string | null;
  system_identity: string | null;
  serial: string | null;
}

/** Every active MikroTik CPE filed under a site of its own tenant. */
export async function listLineQualityCandidates(): Promise<LineQualityCandidate[]> {
  return (await db('devices as d')
    .join('sites as s', function sameTenantSite(this: import('knex').Knex.JoinClause) {
      this.on('s.id', '=', 'd.site_id').andOn('s.tenant_id', '=', 'd.tenant_id');
    })
    .where('d.brand', 'mikrotik')
    .where('d.status', 'active')
    .where((w) => {
      w.whereNull('d.role').orWhereNot('d.role', 'concentrator');
    })
    .orderBy('d.id')
    .select(
      'd.id', 'd.tenant_id', 'd.group_id', 'd.name', 'd.site_id', 's.code as site_code', 's.name as site_name',
      's.timezone', 'd.concentrator_id', 'd.ppp_username', 'd.tunnel_ip', 'd.system_identity', 'd.serial',
    )) as LineQualityCandidate[];
}

// ============================================================================
// Measuring one router
// ============================================================================

type Outcome =
  | { kind: 'skip'; reason: LineQualitySkipReason }
  | {
      kind: 'measured';
      wanShape: 'pppoe' | 'ip' | 'unknown';
      targets: LineQualityTargetResult[];
      routeBefore: ActiveDefaultRoute;
      linkDownsIface: string | null;
      linkDownsTotal: number | null;
      bootAt: Date | null;
      hasFixedLine: boolean;
    };

async function optionalQuery(conn: RouterQuery, words: string[], timeoutMs = READ_TIMEOUT_MS): Promise<Array<Record<string, string>> | null> {
  try {
    return await conn.query(words, { timeoutMs });
  } catch (err) {
    if (err instanceof RouterOsTrapError) return null;
    throw err;
  }
}

function yes(v: unknown): boolean {
  const s = String(v ?? '').trim().toLowerCase();
  return s === 'true' || s === 'yes';
}

/** The NW-WAN1 route as the router has it: its /32 host, active or not, and
 *  the interface its next hop leaves by. */
export function readProbeRoute(rows: ReadonlyArray<Record<string, string>> | null): ProbeRouteReading | null {
  const enabled = (rows ?? []).filter((r) => !yes(r.disabled) && /\/32$/.test(String(r['dst-address'] ?? '')));
  const r = enabled.find((x) => yes(x.active)) ?? enabled[0];
  if (!r) return null;
  const immediate = String(r['immediate-gw'] ?? '').trim();
  const status = String(r['gateway-status'] ?? '').trim();
  const hops = immediate !== '' ? hopsFromImmediateGw(immediate) : status !== '' ? hopsFromGatewayStatus(status) : [];
  const ifaces = [...new Set(hops.map((h) => h.iface))];
  return {
    host: String(r['dst-address']).replace(/\/32$/, ''),
    active: yes(r.active),
    iface: ifaces.length === 1 ? ifaces[0] : null,
  };
}

async function pingTarget(conn: RouterQuery, target: string, shape: WanShape): Promise<{ plan: ReturnType<typeof planTarget>; result: LineQualityTargetResult }> {
  const plan = planTarget(target, shape);
  const base: LineQualityTargetResult = {
    target, method: null, iface: null, carrier: null, skipped: null, sent: null, received: null, lossPct: null,
    rttMinMs: null, rttAvgMs: null, rttMaxMs: null, jitterMs: null, error: null,
  };
  if (plan.kind === 'skip') return { plan, result: { ...base, skipped: plan.reason } };
  const words = ['/ping', `=address=${target}`, `=count=${LINE_QUALITY_PING_COUNT}`];
  if (plan.interfaceParam) words.push(`=interface=${plan.interfaceParam}`);
  const result: LineQualityTargetResult = { ...base, method: plan.method, iface: plan.iface, carrier: plan.carrier };
  try {
    const rows = await conn.query(words, { timeoutMs: PING_TIMEOUT_MS });
    const s = summarisePing(rows);
    if (!s) return { plan, result: { ...result, error: 'the router returned no packet row' } };
    return { plan, result: { ...result, ...s } };
  } catch (err) {
    if (err instanceof RouterOsTrapError) {
      return { plan, result: { ...result, error: String(err.message).slice(0, 200) } };
    }
    throw err;
  }
}

async function refusalInDatabase(c: LineQualityCandidate, settings: LineQualitySettings, now: Date): Promise<LineQualitySkipReason | null> {
  if ((await declaredUplinkOf(c.tenant_id, c.site_id)) === 'cellular_only') return 'cellular_only';
  if (settings.targets.length === 0) return 'no_targets';
  const api = (await db('device_transports')
    .where({ device_id: c.id, transport: 'routeros_api', enabled: true })
    .orderBy('priority')
    .first('host', 'username', 'secret_enc')) as { host: string | null; username: string | null; secret_enc: string | null } | undefined;
  if (!api || !routerOsApiChannelUsable(api, c.tunnel_ip)) return 'no_api_channel';
  const job = await db('change_jobs').where({ device_id: c.id }).whereIn('status', ACTIVE_JOB_STATUSES).first('id');
  if (job) return 'busy';
  if (await expectedCutUntil(c.id, now)) return 'wan_cut';
  // Behind a concentrator, presence decides whether we may dial at all.
  if (c.concentrator_id !== null && c.ppp_username) {
    if (await isConcentratorDegraded(c.concentrator_id)) return 'parent_degraded';
    const open = await db('ppp_sessions')
      .where({ concentrator_id: c.concentrator_id, ppp_username: c.ppp_username })
      .whereNull('ended_at')
      .first('id');
    if (!open) return 'ppp_down';
  }
  return null;
}

async function onRouter(c: LineQualityCandidate, settings: LineQualitySettings, now: Date): Promise<Outcome> {
  const declared = await declaredUplinkOf(c.tenant_id, c.site_id);
  const inferred = ((await fixedUplinksFor([c.id])).get(c.id) ?? []).length > 0;
  return deps.withRouter(c.id, async (conn): Promise<Outcome> => {
    // Identity — the box that answers is the recorded router, or nothing is filed.
    const observed = await readRouterOsIdentity(conn as unknown as RouterOsConnection, c.ppp_username);
    const cmp = compareIdentity(
      { ppp_username: c.ppp_username, system_identity: c.system_identity, serial: c.serial },
      observed,
      await renameIdentityAlternates(c.id),
    );
    if (!cmp.ok) return { kind: 'skip', reason: cmp.mismatched > 0 ? 'identity_mismatch' : 'identity_unproven' };

    const resource = await optionalQuery(conn, ['/system/resource/print', '=.proplist=uptime']);
    const uptime = parseRosUptimeSec(resource?.[0]?.uptime);
    const interfaces = (await optionalQuery(conn, ['/interface/print', '=.proplist=name,type,disabled,running,link-downs'])) ?? [];
    const clientsRaw = (await optionalQuery(conn, ['/interface/pppoe-client/print', '=.proplist=name,interface,disabled,running'])) ?? [];
    const clients: PppoeClientRow[] = clientsRaw.map((r) => ({
      name: String(r.name ?? ''), iface: r.interface ? String(r.interface) : null, disabled: yes(r.disabled), running: yes(r.running),
    })).filter((r) => r.name !== '');
    const routeBefore = readActiveDefaultRoute(await optionalQuery(conn, ['/ip/route/print', '?dst-address=0.0.0.0/0']));
    const probe = readProbeRoute(await optionalQuery(conn, ['/ip/route/print', '?comment=NW-WAN1']));
    const picked = pickPppoe(clients);
    const shape: WanShape = { pppoe: picked.client, pppoeAmbiguous: picked.ambiguous, probe, route: routeBefore };

    const ifaceByName = new Map(interfaces.map((r) => [String(r.name ?? ''), r]));
    const wan1Port = ifaceByName.has(WAN1_PORT) && !yes(ifaceByName.get(WAN1_PORT)?.disabled) ? WAN1_PORT : null;
    const hasFixedLine = declared === 'fixed' || inferred || picked.client !== null || wan1Port !== null
      || carrierOf(routeBefore.iface) === 'fixed';
    if (!hasFixedLine) return { kind: 'skip', reason: 'no_fixed_line' };

    const plans: Array<ReturnType<typeof planTarget>> = [];
    const results: LineQualityTargetResult[] = [];
    for (const target of settings.targets) {
      const { plan, result } = await pingTarget(conn, target, shape);
      plans.push(plan);
      results.push(result);
    }
    // A default-route target is the line's only if the route did not move.
    if (plans.some((p) => p.kind === 'ping' && p.method === 'default_route')) {
      const after = readActiveDefaultRoute(await optionalQuery(conn, ['/ip/route/print', '?dst-address=0.0.0.0/0']));
      plans.forEach((p, i) => {
        if (p.kind === 'ping' && p.method === 'default_route') results[i] = { ...results[i], carrier: settleCarrier(p, after) };
      });
    }
    const linkIface = picked.client?.name ?? wan1Port ?? (carrierOf(routeBefore.iface) === 'fixed' ? routeBefore.iface : null);
    const linkRow = linkIface ? ifaceByName.get(linkIface) : undefined;
    return {
      kind: 'measured',
      wanShape: picked.client ? 'pppoe' : wan1Port || probe ? 'ip' : 'unknown',
      targets: results,
      routeBefore,
      linkDownsIface: linkIface,
      linkDownsTotal: linkRow ? routerInt(linkRow['link-downs']) : null,
      bootAt: uptime === null ? null : new Date(now.getTime() - uptime * 1000),
      hasFixedLine,
    };
  });
}

/** The day's counters ObliWAN already stores (header box 3). */
async function dayCounters(c: LineQualityCandidate, uplinkIface: string | null, from: Date, to: Date): Promise<{
  failovers: number; mgmtReconnects: number | null; wan1Errors: number | null;
}> {
  const moves = (await db('device_route_transitions')
    .where({ device_id: c.id })
    .where('at', '>=', from)
    .where('at', '<', to)
    .select('from_iface', 'to_iface')) as Array<{ from_iface: string | null; to_iface: string | null }>;
  const failovers = moves.filter((m) => isCellularIface(m.to_iface) && !isCellularIface(m.from_iface)).length;
  let mgmtReconnects: number | null = null;
  if (c.concentrator_id !== null && c.ppp_username) {
    const row = (await db('ppp_sessions')
      .where({ concentrator_id: c.concentrator_id, ppp_username: c.ppp_username })
      .where('started_at', '>=', from)
      .where('started_at', '<', to)
      .count<{ n: string | number }[]>('id as n')
      .first()) as { n: string | number } | undefined;
    mgmtReconnects = Number(row?.n ?? 0);
  }
  let wan1Errors: number | null = null;
  try {
    const names = [...new Set([WAN1_PORT, ...(uplinkIface ? uplinkIface.split(', ') : [])])];
    const ifIds = (await db('snmp_interfaces')
      .where({ device_id: c.id, state: 'active' })
      .whereIn('if_name', names)
      .pluck('id')) as number[];
    if (ifIds.length > 0) {
      const agg = (await db('snmp_if_rollup_5m')
        .whereIn('if_id', ifIds)
        .where('bucket', '>=', from)
        .where('bucket', '<', to)
        .select(db.raw('count(*)::int as n'), db.raw('coalesce(sum(in_errs + out_errs), 0)::bigint as errs'))
        .first()) as { n: number; errs: string | number } | undefined;
      if (agg && Number(agg.n) > 0) wan1Errors = Number(agg.errs);
    }
  } catch (err) {
    logger.debug({ err, deviceId: c.id }, 'Line quality: WAN1 SNMP errors unreadable');
  }
  return { failovers, mgmtReconnects, wan1Errors };
}

function withBudget<T>(p: Promise<T>, ms: number): Promise<T | typeof BUDGET> {
  let timer: NodeJS.Timeout | null = null;
  const t = new Promise<typeof BUDGET>((resolve) => {
    timer = setTimeout(() => resolve(BUDGET), ms);
    timer.unref?.();
  });
  return Promise.race([p, t]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}
const BUDGET = Symbol('budget');

async function recordAttempt(c: LineQualityCandidate, night: string, source: 'opening_hours' | 'night_window', now: Date): Promise<void> {
  await db('line_quality_nights')
    .insert({
      tenant_id: c.tenant_id, site_id: c.site_id, device_id: c.id, night, status: 'pending', attempts: 1,
      last_attempt_at: now, schedule_source: source, updated_at: now,
    })
    .onConflict(['site_id', 'night'])
    .merge({
      device_id: c.id,
      attempts: db.raw('line_quality_nights.attempts + 1'),
      last_attempt_at: now,
      schedule_source: source,
      updated_at: now,
    });
}

async function recordSkip(c: LineQualityCandidate, night: string, reason: LineQualitySkipReason, now: Date): Promise<void> {
  const final = LINE_QUALITY_FINAL_SKIPS.includes(reason);
  await db('line_quality_nights')
    .insert({
      tenant_id: c.tenant_id, site_id: c.site_id, device_id: c.id, night, status: 'skipped', skip_reason: reason,
      final, attempts: 0, updated_at: now,
    })
    .onConflict(['site_id', 'night'])
    .merge({ device_id: c.id, status: 'skipped', skip_reason: reason, final, updated_at: now });
}

export interface MeasureResult {
  siteId: number;
  night: string;
  outcome: 'measured' | LineQualitySkipReason;
  verdict: LineQualityVerdict | null;
}

/**
 * Measure one site's router for `night` now (the scheduler's unit of work,
 * exported for the harness). Records the attempt, the outcome, the counters,
 * and judges the night. Never throws: an error of ObliWAN's is `internal`.
 */
export async function measureSite(
  c: LineQualityCandidate,
  night: string,
  source: 'opening_hours' | 'night_window',
): Promise<MeasureResult> {
  const now = deps.now();
  await recordAttempt(c, night, source, now);
  const settings = await resolveLineQualitySettings(c.tenant_id, c.id, c.group_id);
  let outcome: Outcome;
  try {
    const refused = await refusalInDatabase(c, settings, now);
    if (refused) {
      outcome = { kind: 'skip', reason: refused };
    } else {
      const r = await withBudget(
        onRouter(c, settings, now).catch((err: unknown): Outcome => {
          logger.info({ deviceId: c.id, err: err instanceof Error ? err.message : String(err) }, 'Line quality: the router could not be measured');
          return { kind: 'skip', reason: 'unreachable' };
        }),
        deps.deviceBudgetMs,
      );
      outcome = r === BUDGET ? { kind: 'skip', reason: 'budget_exceeded' } : r;
    }
  } catch (err) {
    logger.error({ err, deviceId: c.id, siteId: c.site_id }, 'Line quality: measurement failed');
    outcome = { kind: 'skip', reason: 'internal' };
  }

  if (outcome.kind === 'skip') {
    await recordSkip(c, night, outcome.reason, now);
    return { siteId: c.site_id, night, outcome: outcome.reason, verdict: null };
  }

  const agg = aggregateTargets(outcome.targets);
  const from = new Date(now.getTime() - COUNTER_WINDOW_MS);
  const counters = await dayCounters(c, agg.uplinkIface, from, now);
  const prev = (await db('line_quality_nights')
    .where({ site_id: c.site_id, device_id: c.id, status: 'measured' })
    .where('night', '<', night)
    .whereNotNull('link_downs_total')
    .orderBy('night', 'desc')
    .first('link_downs_iface', 'link_downs_total', 'boot_at', 'measured_at')) as
    | { link_downs_iface: string | null; link_downs_total: string | number | null; boot_at: Date | null; measured_at: Date }
    | undefined;
  const linkDowns = linkDownsDelta(
    prev ? { iface: prev.link_downs_iface, total: numOrNull(prev.link_downs_total), bootAt: prev.boot_at ? new Date(prev.boot_at) : null, at: new Date(prev.measured_at) } : null,
    { iface: outcome.linkDownsIface, total: outcome.linkDownsTotal, bootAt: outcome.bootAt, at: now },
  );
  // On its 4G backup at measurement time while the site has a fixed line:
  // the fixed line is down, whatever the 4G answered.
  const fixedDown = outcome.hasFixedLine && carrierOf(outcome.routeBefore.iface) === 'cellular';
  const reconnections = reconnectionsOf(linkDowns, counters.failovers);

  // Judged against the nights BEFORE this one.
  const previous = (await db('line_quality_nights')
    .where({ site_id: c.site_id })
    .where('night', '<', night)
    .where('night', '>=', addDays(night, -BASELINE_WINDOW_NIGHTS))
    .where({ status: 'measured' })
    .select('night', 'carrier', 'loss_pct', 'rtt_avg_ms', 'fixed_down', 'reconnections')) as NightRow[];
  const baseline = computeBaseline(previous.map(toFacts));
  const facts: NightFacts = { night, carrier: agg.carrier, lossPct: agg.lossPct, rttAvgMs: agg.rttAvgMs, fixedDown, reconnections };
  const judged = judgeNight(facts, baseline, settings.thresholds);

  await db('line_quality_nights').where({ site_id: c.site_id, night }).update({
    device_id: c.id,
    status: 'measured',
    skip_reason: null,
    final: true,
    measured_at: now,
    carrier: agg.carrier,
    uplink_iface: agg.uplinkIface,
    method: agg.method,
    wan_shape: outcome.wanShape,
    targets: JSON.stringify(outcome.targets),
    sent: agg.sent,
    received: agg.received,
    loss_pct: agg.lossPct,
    rtt_min_ms: agg.rttMinMs,
    rtt_avg_ms: agg.rttAvgMs,
    rtt_max_ms: agg.rttMaxMs,
    jitter_ms: agg.jitterMs,
    fixed_down: fixedDown,
    counters_from: from,
    counters_to: now,
    link_downs_iface: outcome.linkDownsIface,
    link_downs_total: outcome.linkDownsTotal,
    boot_at: outcome.bootAt,
    link_downs: linkDowns,
    failovers: counters.failovers,
    mgmt_reconnects: counters.mgmtReconnects,
    wan1_errors: counters.wan1Errors,
    reconnections,
    verdict: judged.verdict,
    reasons: JSON.stringify(judged.reasons),
    baseline: baseline ? JSON.stringify(baseline) : null,
    thresholds: JSON.stringify(settings.thresholds),
    updated_at: now,
  });
  return { siteId: c.site_id, night, outcome: 'measured', verdict: judged.verdict };
}

// ============================================================================
// The scheduler
// ============================================================================

export interface LineQualityPassStats {
  candidates: number;
  due: number;
  measured: number;
  skipped: number;
}

export interface PassSignal {
  aborted: boolean;
}

let stopping = false;
let lastAlertSweepAt = 0;
let lastPruneDay = '';

/**
 * One pass: plan every site, measure the due ones (bounded), then re-evaluate
 * the grouped alert of every tenant a measurement touched (and, at most once
 * an hour, of every tenant — a line goes stale without being measured).
 */
export async function runLineQualityPass(opts: { signal?: PassSignal } = {}): Promise<LineQualityPassStats> {
  const halted = () => stopping || opts.signal?.aborted === true;
  const stats: LineQualityPassStats = { candidates: 0, due: 0, measured: 0, skipped: 0 };
  if (halted()) return stats;
  const now = deps.now();
  const all = await listLineQualityCandidates();
  stats.candidates = all.length;

  const bySite = new Map<number, LineQualityCandidate[]>();
  for (const c of all) bySite.set(c.site_id, [...(bySite.get(c.site_id) ?? []), c]);

  const touched = new Set<number>();
  const due: Array<{ c: LineQualityCandidate; night: string; source: 'opening_hours' | 'night_window' }> = [];
  for (const [, list] of bySite) {
    if (halted()) break;
    const c = list[0];
    const tz = safeZone(c.timezone);
    const night = nightOf(now, tz);
    const row = (await db('line_quality_nights').where({ site_id: c.site_id, night }).first(
      'status', 'final', 'attempts', 'last_attempt_at',
    )) as Pick<NightRow, 'status' | 'final' | 'attempts' | 'last_attempt_at'> | undefined;
    if (row && (row.final || row.status === 'measured')) continue;
    if (list.length > 1) {
      // Which router carries the line? Not a guess: said once for the night.
      await recordSkip(c, night, 'several_routers', now);
      continue;
    }
    if (row && Number(row.attempts) >= MAX_ATTEMPTS) continue;
    if (row?.last_attempt_at && now.getTime() - new Date(row.last_attempt_at).getTime() < RETRY_AFTER_MS) continue;
    const moment = await momentFor(c, tz, now);
    if (!moment.due) continue;
    due.push({ c, night, source: moment.source });
  }
  stats.due = due.length;

  const limit = pLimit(Math.max(1, deps.concurrency));
  await Promise.all(due.map((d) => limit(async () => {
    if (halted()) return;
    const r = await measureSite(d.c, d.night, d.source).catch((err: unknown) => {
      logger.error({ err, siteId: d.c.site_id }, 'Line quality: a site could not be recorded');
      return null;
    });
    if (r?.outcome === 'measured') stats.measured += 1;
    else stats.skipped += 1;
    touched.add(d.c.tenant_id);
  })));

  const sweepAll = now.getTime() - lastAlertSweepAt >= ALERT_SWEEP_EVERY_MS;
  const tenants = sweepAll ? await tenantsToEvaluate(now) : [...touched];
  if (sweepAll) lastAlertSweepAt = now.getTime();
  for (const t of tenants) {
    if (halted()) break;
    await evaluateLineQualityAlert(t).catch((err: unknown) =>
      logger.warn({ err, tenantId: t }, 'Line quality: the grouped alert could not be evaluated'));
  }

  const today = now.toISOString().slice(0, 10);
  if (lastPruneDay !== today) {
    lastPruneDay = today;
    await db('line_quality_nights').where('night', '<', addDays(today, -LINE_QUALITY_RETENTION_NIGHTS)).delete()
      .catch((err: unknown) => logger.warn({ err }, 'Line quality: retention prune failed'));
  }
  if (stats.due > 0) logger.info({ ...stats }, 'Line quality pass');
  return stats;
}

async function momentFor(
  c: LineQualityCandidate,
  tz: string,
  now: Date,
): Promise<{ due: true; source: 'opening_hours' | 'night_window' } | { due: false }> {
  let openNow: boolean | null = null;
  let openSettleAgo: boolean | null = null;
  let closedUntil: Date | null = null;
  try {
    openNow = await deps.siteOpenAt(c.site_id, now);
    if (openNow === false) {
      openSettleAgo = await deps.siteOpenAt(c.site_id, new Date(now.getTime() - CLOSED_SETTLE_MS));
      closedUntil = (await deps.nextClosedWindow(c.site_id, now))?.end ?? null;
    }
  } catch (err) {
    // Unreadable hours are unknown hours: the night window applies.
    logger.debug({ err, siteId: c.site_id }, 'Line quality: opening hours unreadable, the night window applies');
    openNow = null;
  }
  let inWindow = false;
  if (openNow === null) {
    const s = await resolveLineQualitySettings(c.tenant_id, c.id, c.group_id);
    inWindow = inNightWindow(now, tz, s.nightStart, s.nightEnd);
  }
  const v = decideMoment({ openNow, openSettleAgo, closedUntil, inWindow, now });
  return v.due ? v : { due: false };
}

async function tenantsToEvaluate(now: Date): Promise<number[]> {
  const since = addDays(now.toISOString().slice(0, 10), -VIEW_NIGHTS);
  const a = (await db('line_quality_nights').where('night', '>=', since).distinct('tenant_id').pluck('tenant_id')) as number[];
  const b = (await db('line_quality_alerts').pluck('tenant_id')) as number[];
  return [...new Set([...a, ...b].map(Number))];
}

// ============================================================================
// Site statuses and the grouped alert
// ============================================================================

interface SiteState {
  tenantId: number;
  siteId: number;
  siteCode: string;
  siteName: string;
  deviceId: number | null;
  deviceName: string | null;
  status: LineQualityStatus;
  streak: number;
  latest: NightRow;
  rows: NightRow[];
}

/** Every site of the scope with a night in the last VIEW_NIGHTS, with its status. */
async function siteStates(
  tenantId: number,
  opts: { now: Date; deviceIdsIn?: number[] | null },
): Promise<{ godView: boolean; states: SiteState[] }> {
  const since = addDays(opts.now.toISOString().slice(0, 10), -VIEW_NIGHTS);
  const q = db('line_quality_nights as n')
    .join('sites as s', function sameTenantSite(this: import('knex').Knex.JoinClause) {
      this.on('s.id', '=', 'n.site_id').andOn('s.tenant_id', '=', 'n.tenant_id');
    })
    .leftJoin('devices as d', function sameTenantDevice(this: import('knex').Knex.JoinClause) {
      this.on('d.id', '=', 'n.device_id').andOn('d.tenant_id', '=', 'n.tenant_id');
    })
    .where('n.night', '>=', since);
  // God view (a platform admin's read on Default): every tenant. Internal
  // code — the grouped alert — runs in no request scope: always one tenant.
  const godView = applyTenantScope(q, 'n.tenant_id', tenantId);
  if (opts.deviceIdsIn) q.whereIn('n.device_id', opts.deviceIdsIn);
  const rows = (await q
    .orderBy('n.site_id')
    .orderBy('n.night', 'desc')
    .select('n.*', 's.code as site_code', 's.name as site_name', 's.timezone as site_timezone', 'd.name as device_name')) as Array<
    NightRow & { site_code: string; site_name: string; site_timezone: string; device_name: string | null }
  >;
  const bySite = new Map<number, typeof rows>();
  for (const r of rows) bySite.set(Number(r.site_id), [...(bySite.get(Number(r.site_id)) ?? []), r]);
  const out: SiteState[] = [];
  for (const [siteId, list] of bySite) {
    const latest = list[0];
    // The thresholds of its latest judged night (what the line was judged with).
    const nights = list.find((r) => r.thresholds)?.thresholds?.nights ?? 2;
    const st = siteLineStatus(
      list.map((r) => ({ night: nightKey(r.night), verdict: r.verdict })),
      nightOf(opts.now, safeZone(latest.site_timezone)),
      nights,
    );
    out.push({
      tenantId: Number(latest.tenant_id),
      siteId,
      siteCode: latest.site_code,
      siteName: latest.site_name,
      deviceId: latest.device_id === null ? null : Number(latest.device_id),
      deviceName: latest.device_name,
      status: st.status,
      streak: st.streak,
      latest,
      rows: list,
    });
  }
  return { godView, states: out };
}

const METRIC_FR: Record<LineQualityReason['metric'], (r: LineQualityReason) => string> = {
  loss: (r) => `perte ${r.value} %`,
  latency: (r) => `latence ${r.value} ms`,
  reconnections: (r) => `${r.value} reconnexion(s)`,
  fixed_down: () => 'sur secours 4G',
};

function lineSentence(s: SiteState): string {
  const judged = s.rows.find((r) => r.verdict === 'exceeded');
  const why = (judged?.reasons ?? []).map((r) => METRIC_FR[r.metric](r));
  return `${s.siteCode} ${s.siteName} (${s.streak} nuit${s.streak > 1 ? 's' : ''}${why.length ? ` : ${[...new Set(why)].join(', ')}` : ''})`;
}

const evaluating = new Map<number, Promise<unknown>>();

/**
 * The grouped alert of ONE tenant (header box 4). Opens it when a line is
 * degraded, re-issues it when a line joins the list (the previous one marked
 * read), narrows the record silently when a line leaves it, and closes it
 * with one notice when none is left. Returns what it did.
 */
export async function evaluateLineQualityAlert(tenantId: number): Promise<'none' | 'open' | 'refresh' | 'shrink' | 'close'> {
  const prior = evaluating.get(tenantId);
  if (prior) await prior.catch(() => undefined);
  const p = evaluateOnce(tenantId);
  evaluating.set(tenantId, p);
  try {
    return await p;
  } finally {
    if (evaluating.get(tenantId) === p) evaluating.delete(tenantId);
  }
}

async function evaluateOnce(tenantId: number): Promise<'none' | 'open' | 'refresh' | 'shrink' | 'close'> {
  const now = deps.now();
  const { states } = await siteStates(tenantId, { now });
  const degraded = states.filter((s) => s.status === 'degraded').sort((a, b) => b.streak - a.streak || a.siteCode.localeCompare(b.siteCode));
  const ids = degraded.map((s) => s.siteId).sort((a, b) => a - b);
  const state = (await db('line_quality_alerts').where({ tenant_id: tenantId }).first()) as
    | { tenant_id: number; opened_at: Date; site_ids: number[]; live_alert_id: number | null }
    | undefined;
  const step = alertStep(state ? (state.site_ids ?? []).map(Number) : null, ids);
  if (step === 'none') return step;

  if (step === 'shrink') {
    await db('line_quality_alerts').where({ tenant_id: tenantId }).update({ site_ids: JSON.stringify(ids), updated_at: now });
    return step;
  }

  if (step === 'close' && state) {
    const opened = new Date(state.opened_at);
    await liveAlertService.add(tenantId, {
      severity: 'up',
      title: 'Lignes fixes rétablies',
      message:
        `Plus aucune ligne fixe n’est dégradée : les ${state.site_ids.length} ligne(s) signalée(s) depuis le ` +
        `${opened.toISOString().slice(0, 10)} se sont rétablies (mesures de nuit hors horaires d’ouverture).`,
      navigateTo: '/line-quality',
      stableKey: `linequality-end:${tenantId}:${opened.getTime()}`,
    });
    if (state.live_alert_id) await liveAlertService.markRead(state.live_alert_id, tenantId).catch(() => undefined);
    await db('line_quality_alerts').where({ tenant_id: tenantId }).delete();
    return step;
  }

  // open / refresh: the list as it stands now.
  const openedAt = state ? new Date(state.opened_at) : now;
  const digest = createHash('sha1').update(ids.join(',')).digest('hex').slice(0, 12);
  const shown = degraded.slice(0, 20).map(lineSentence);
  const more = degraded.length > shown.length ? ` … et ${degraded.length - shown.length} autre(s).` : '';
  const alert = await liveAlertService.add(tenantId, {
    severity: 'info',
    title: `Lignes fixes dégradées : ${degraded.length} magasin${degraded.length > 1 ? 's' : ''}`,
    message:
      'Mesurées hors horaires d’ouverture, ces lignes fixes dépassent les seuils plusieurs nuits de suite : ' +
      `${shown.join(' ; ')}.${more} Détail : « Lignes dégradées ».`,
    navigateTo: '/line-quality',
    stableKey: `linequality:${tenantId}:${openedAt.getTime()}:${digest}`,
  });
  if (state?.live_alert_id && alert && alert.id !== state.live_alert_id) {
    await liveAlertService.markRead(state.live_alert_id, tenantId).catch(() => undefined);
  }
  await db('line_quality_alerts')
    .insert({
      tenant_id: tenantId,
      opened_at: openedAt,
      site_ids: JSON.stringify(ids),
      live_alert_id: alert?.id ?? state?.live_alert_id ?? null,
      updated_at: now,
    })
    .onConflict('tenant_id')
    .merge(['site_ids', 'live_alert_id', 'updated_at']);
  return step;
}

// ============================================================================
// Views
// ============================================================================

const STATUS_RANK: Record<LineQualityStatus, number> = { degraded: 0, watch: 1, ok: 2, unknown: 3 };

/** « Lignes dégradées »: the lines degraded or to be watched, worst first. */
export async function lineQualityFleet(
  tenantId: number,
  opts: { deviceIdsIn?: number[] | null; includeOk?: boolean; now?: Date } = {},
): Promise<LineQualityFleetItem[]> {
  const now = opts.now ?? deps.now();
  const { godView, states } = await siteStates(tenantId, { now, deviceIdsIn: opts.deviceIdsIn });
  const shown = states.filter((s) => opts.includeOk || s.status === 'degraded' || s.status === 'watch');
  const items: LineQualityFleetItem[] = shown.map((s) => {
    const m = s.rows.find((r) => r.status === 'measured') ?? s.latest;
    return {
      ...(godView ? { tenantId: s.tenantId } : {}),
      siteId: s.siteId,
      siteCode: s.siteCode,
      siteName: s.siteName,
      deviceId: s.deviceId,
      deviceName: s.deviceName,
      status: s.status,
      streak: s.streak,
      lastNight: nightKey(s.latest.night),
      measuredAt: iso(m.measured_at),
      carrier: m.carrier,
      uplinkIface: m.uplink_iface,
      lossPct: numOrNull(m.loss_pct),
      rttAvgMs: numOrNull(m.rtt_avg_ms),
      jitterMs: numOrNull(m.jitter_ms),
      reconnections: m.reconnections,
      fixedDown: m.fixed_down,
      reasons: (s.rows.find((r) => r.verdict === 'exceeded') ?? m).reasons ?? [],
      trend: [...s.rows].reverse().slice(-BASELINE_WINDOW_NIGHTS).map((r) => ({
        night: nightKey(r.night),
        rttAvgMs: r.status === 'measured' && r.carrier === 'fixed' ? numOrNull(r.rtt_avg_ms) : null,
        exceeded: r.verdict === 'exceeded',
      })),
    };
  });
  if (godView) {
    const names = await tenantNames(items.map((i) => i.tenantId ?? 0));
    for (const i of items) i.tenantName = names.get(i.tenantId ?? 0) ?? null;
  }
  const worst = (i: LineQualityFleetItem) => Math.max(0, ...i.reasons.map((r) => (r.threshold > 0 ? r.value / r.threshold : 0)));
  return items.sort((a, b) =>
    STATUS_RANK[a.status] - STATUS_RANK[b.status]
    || b.streak - a.streak
    || Number(b.fixedDown) - Number(a.fixedDown)
    || worst(b) - worst(a)
    || a.siteCode.localeCompare(b.siteCode));
}

/** The device page's « Qualité de ligne » card, tenant-scoped. null = no such device. */
export async function lineQualityDeviceView(tenantId: number, deviceId: number): Promise<LineQualityDeviceView | null> {
  const d = (await db('devices as d')
    .leftJoin('sites as s', function sameTenantSite(this: import('knex').Knex.JoinClause) {
      this.on('s.id', '=', 'd.site_id').andOn('s.tenant_id', '=', 'd.tenant_id');
    })
    .where({ 'd.id': deviceId, 'd.tenant_id': tenantId })
    .first('d.id', 'd.tenant_id', 'd.group_id', 'd.brand', 'd.role', 's.id as site_id', 's.code as site_code',
      's.name as site_name', 's.timezone as timezone')) as
    | { id: number; tenant_id: number; group_id: number | null; brand: string; role: string | null; site_id: number | null;
        site_code: string | null; site_name: string | null; timezone: string | null }
    | undefined;
  if (!d) return null;
  const now = deps.now();
  const settings = await resolveLineQualitySettings(tenantId, deviceId, d.group_id, { fresh: true });
  const site = d.site_id === null ? null : { id: Number(d.site_id), code: d.site_code as string, name: d.site_name as string };
  let notMeasured: LineQualityDeviceView['notMeasured'] = null;
  if (!site) notMeasured = 'no_site';
  else if (d.brand !== 'mikrotik') notMeasured = 'not_mikrotik';
  else if (d.role === 'concentrator') notMeasured = 'concentrator';
  else if ((await declaredUplinkOf(tenantId, site.id)) === 'cellular_only') notMeasured = 'cellular_only';
  else {
    const n = (await db('devices')
      .where({ tenant_id: tenantId, site_id: site.id, brand: 'mikrotik', status: 'active' })
      .where((w) => { w.whereNull('role').orWhereNot('role', 'concentrator'); })
      .count<{ n: string | number }[]>('id as n')
      .first()) as { n: string | number } | undefined;
    if (Number(n?.n ?? 0) > 1) notMeasured = 'several_routers';
  }
  const rows = site
    ? ((await db('line_quality_nights')
      .where({ site_id: site.id, tenant_id: tenantId })
      .orderBy('night', 'desc')
      .limit(BASELINE_WINDOW_NIGHTS)
      .select('*')) as NightRow[])
    : [];
  const tz = safeZone(d.timezone);
  const st = siteLineStatus(rows.map((r) => ({ night: nightKey(r.night), verdict: r.verdict })), nightOf(now, tz), settings.thresholds.nights);
  let hoursKnown: boolean | null = null;
  if (site) {
    try {
      hoursKnown = (await deps.siteOpenAt(site.id, now)) !== null;
    } catch {
      hoursKnown = null;
    }
  }
  return {
    deviceId,
    site,
    notMeasured,
    status: st.status,
    streak: st.streak,
    lastJudgedNight: st.lastJudgedNight,
    thresholds: settings.thresholds,
    targets: settings.targets,
    hoursKnown,
    nightWindow: { startHour: settings.nightStart, endHour: settings.nightEnd },
    nights: rows.map(toNightView),
  };
}

// ============================================================================
// Runtime — leader only
// ============================================================================

let unsubscribe: (() => void) | null = null;
let timer: NodeJS.Timeout | null = null;
let ticking = false;
let timerSignal: PassSignal | null = null;
let currentPass: Promise<unknown> | null = null;

function startTimer(): void {
  if (timer || stopping) return;
  const signal: PassSignal = { aborted: false };
  timerSignal = signal;
  const tick = (): void => {
    if (ticking || signal.aborted) return;
    ticking = true;
    currentPass = runLineQualityPass({ signal })
      .catch((err) => logger.error({ err }, 'Line quality pass failed'))
      .finally(() => {
        ticking = false;
      });
  };
  timer = setInterval(tick, LINE_QUALITY_TICK_MS);
  timer.unref();
  tick();
  logger.info({ tickMs: LINE_QUALITY_TICK_MS }, 'Line quality scheduler armed (leader)');
}

function stopTimer(): void {
  if (timer) clearInterval(timer);
  timer = null;
  if (timerSignal) timerSignal.aborted = true;
  timerSignal = null;
}

/** Idempotent; safe on every role (a `web` replica never becomes leader). */
export function startLineQualityRuntime(): void {
  if (unsubscribe) return;
  unsubscribe = leaderElection.onChange((isLeader) => {
    if (isLeader) startTimer();
    else stopTimer();
  });
  logger.info('Line quality runtime wired to leadership');
}

/**
 * Stop for good: nothing new is dialled. The pass in flight (its routers
 * already on the wire, a ping takes ~20 s) is awaited at most STOP_GRACE_MS:
 * an abandoned measurement has only read, and its night is retried by the
 * next leader.
 */
export async function stopLineQualityRuntime(): Promise<void> {
  stopping = true;
  unsubscribe?.();
  unsubscribe = null;
  stopTimer();
  if (!currentPass) return;
  let grace: NodeJS.Timeout | undefined;
  await Promise.race([
    currentPass,
    new Promise<void>((resolve) => {
      grace = setTimeout(resolve, STOP_GRACE_MS);
      grace.unref?.();
    }),
  ]);
  if (grace) clearTimeout(grace);
}
const STOP_GRACE_MS = 5_000;
