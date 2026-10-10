/**
 * ObliWAN — FLEET ANOMALIES ("Anomalies du parc").
 *
 * A read-only audit of what ObliWAN ALREADY stores, computed on every load.
 * It reads `ppp_sessions`, `devices` and `sites`; it dials nothing, writes
 * nothing and stores nothing (the change queue is not even approached). Five sections, each
 * answering one thing a ten-minute manual audit of the online fleet found:
 *
 *  (a) duplicate PPP logins — two routers dialling the same account;
 *  (b) identity ≠ login — a router whose /system/identity names another site
 *      than the PPP login it dials with;
 *  (c) inventory — devices per model and per OS version, oldest flagged;
 *  (d) public IPs shared by several routers — informational;
 *  (e) routers on cellular right now — the live default route (migration 073),
 *      and since when, once migration 075 has recorded it. Each says whether
 *      it is EXPECTED: its site is declared 4G-only (migration 076,
 *      `sites.uplink_kind`), so cellular is its nominal path, not an anomaly.
 *      The unexpected ones (declared fixed, or not declared) come first.
 *
 * ┌─ WHAT "TWO ROUTERS, ONE LOGIN" LOOKS LIKE IN `ppp_sessions` ─────────────┐
 * │ The partial unique index `ppp_sessions_open_uniq` keeps ONE open row per │
 * │ (concentrator, username). So two sessions open at once under one login   │
 * │ can only be SEEN as two open rows across two concentrators. On the one   │
 * │ shared CHR the second session refreshes the open row's caller_ip, and    │
 * │ every teardown of either closes it — the next event or sweep re-opens a │
 * │ row. Either way (concurrent or kicked by `only-one`) the history fills   │
 * │ with short sessions from ALTERNATING caller IPs, which is signal 2:      │
 * │ ≥ 3 session starts in the last hour from ≥ 2 distinct caller IPs. One    │
 * │ router flapping on one line restarts from ONE address and is not listed. │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ SCOPE ──────────────────────────────────────────────────────────────────┐
 * │ `masterView` (a platform admin on the master tenant, decided by          │
 * │ `requireTenant`, never recomputed here): every tenant, and the logins no │
 * │ device is bound to. Otherwise the session's tenant only — a session is   │
 * │ the tenant's when its login is a device of the tenant (`ppp_username` is │
 * │ globally unique on `devices`), so an unbound login on the shared CHR is  │
 * │ never shown to a tenant. In the tenant view the caller IPs of a          │
 * │ duplicate login are COUNTED, not listed: the second router dialling the  │
 * │ tenant's login may be somebody else's box, and its address is not the    │
 * │ tenant's to read.                                                        │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * `discoveries` records no system identity (only what the CHR says about a
 * session), so section (b) reads devices only.
 */

import { isSiteUplinkKind, type SiteUplinkKind } from '@obliwan/shared';
import { db } from '../../db';
import { siteNumber } from '../allocation/pppIdentity';
import { LIVE_ROUTE_STALE_MS, classify } from './uplinkModel';

/** The window of signal 2 (session churn). */
export const CHURN_WINDOW_MS = 3600_000;
/** Signal 2: at least this many session starts in the window… */
export const CHURN_MIN_STARTS = 3;
/** …from at least this many distinct caller IPs. */
export const CHURN_MIN_CALLERS = 2;
/** At most this many of a brand's oldest versions are highlighted. */
export const OLDEST_VERSIONS_FLAGGED = 3;

export interface FleetAnomalyScope {
  tenantId: number;
  masterView: boolean;
  /**
   * Team scope (migration 087): only these routers, and only the PPP
   * sessions of their logins. null/undefined = unrestricted.
   */
  deviceIdsIn?: number[] | null;
}

export interface AnomalyDeviceRef {
  id: number;
  name: string;
  tenantId: number;
  tenantName: string;
  siteId: number | null;
  siteCode: string | null;
  siteName: string | null;
  status: string;
}

export interface DuplicateLogin {
  pppUsername: string;
  /** Two open rows at once (only possible across concentrators), churn, or both. */
  reason: 'concurrent' | 'churn' | 'both';
  openSessions: number;
  startsLastHour: number;
  distinctCallersLastHour: number;
  /** null in the tenant view: counted, not listed (see the header). */
  callerIps: string[] | null;
  lastStartedAt: string | null;
  device: AnomalyDeviceRef | null;
}

export interface IdentityMismatch {
  device: AnomalyDeviceRef;
  pppUsername: string;
  systemIdentity: string;
  loginSite: string;
  identitySite: string;
  /** Which side the device's site code agrees with; null when it has no
   *  all-digit site code to compare. */
  siteCodeAgreesWith: 'login' | 'identity' | 'neither' | null;
}

export interface InventoryModel {
  brand: string;
  model: string | null;
  count: number;
}

export interface InventoryVersion {
  brand: string;
  osVersion: string | null;
  count: number;
  /** Among the brand's OLDEST_VERSIONS_FLAGGED oldest (never its newest). */
  oldest: boolean;
  /** An older major than the brand's newest (RouterOS 6 beside 7). */
  majorBehind: boolean;
}

export interface SharedIpRouter {
  pppUsername: string;
  device: AnomalyDeviceRef | null;
  cellular: boolean;
}

export interface SharedPublicIp {
  callerIp: string;
  routers: SharedIpRouter[];
  /** At least two of the routers belong to the same site. */
  sameSite: boolean;
  /** At least one router's live default route is cellular (CGNAT likely). */
  anyCellular: boolean;
}

export interface CellularDevice {
  device: AnomalyDeviceRef;
  iface: string;
  gateway: string | null;
  /** Since when the active default route has been on this interface
   *  (`default_route_since`, migration 075); null when not known. */
  since: string | null;
  /** When the routing table was last read. */
  observedAt: string;
  stale: boolean;
  online: boolean;
  /** Start of the open PPP session: the tunnel came up over the current path. */
  sessionSince: string | null;
  callerIp: string | null;
  /** The site's declared access link (migration 076); null = not declared. */
  declaredUplink: SiteUplinkKind | null;
  /** True when the site is declared 4G-only: cellular is its nominal path. A
   *  site declared 'fixed', or not declared, is NOT expected on cellular. */
  expected: boolean;
}

export interface FleetAnomaliesReport {
  generatedAt: string;
  scope: 'tenant' | 'all';
  duplicateLogins: DuplicateLogin[];
  identityMismatches: IdentityMismatch[];
  inventory: { total: number; models: InventoryModel[]; versions: InventoryVersion[] };
  sharedPublicIps: SharedPublicIp[];
  cellular: CellularDevice[];
}

// ============================================================================
// Pure helpers (pinned by the harness)
// ============================================================================

/** Every site number a text carries: its digit runs, leading zeros dropped
 *  ("00971-Lyon" -> [971], "cl1583" -> [1583]). */
export function siteNumbersOf(text: string): number[] {
  const out = new Set<number>();
  for (const run of text.match(/[0-9]+/g) ?? []) {
    const n = siteNumber(run);
    if (n !== null) out.add(n);
  }
  return [...out];
}

/**
 * The site part of an identity disagrees with the login's: both carry at least
 * one site number and they share none. Tolerant on purpose — a prefix, a model
 * number or a postal code beside the site number does not make a mismatch,
 * and a text with no digits at all is not comparable (never a finding).
 */
export function identitySiteMismatch(identity: string, login: string): { login: number[]; identity: number[] } | null {
  const l = siteNumbersOf(login);
  const i = siteNumbersOf(identity);
  if (l.length === 0 || i.length === 0) return null;
  if (l.some((n) => i.includes(n))) return null;
  return { login: l, identity: i };
}

/** The numeric tuple of a version string ("7.21.5 (stable)" -> [7,21,5]); null
 *  when it does not start with a number. */
export function versionTuple(v: string | null): number[] | null {
  if (!v) return null;
  const m = /^\s*v?([0-9]+(?:\.[0-9]+)*)/i.exec(v);
  return m ? m[1].split('.').map(Number) : null;
}

/** Ascending; an unparseable version sorts first, then by its text. */
export function compareVersions(a: string | null, b: string | null): number {
  const ta = versionTuple(a);
  const tb = versionTuple(b);
  if (!ta || !tb) return ta ? 1 : tb ? -1 : (a ?? '').localeCompare(b ?? '');
  for (let k = 0; k < Math.max(ta.length, tb.length); k++) {
    const d = (ta[k] ?? 0) - (tb[k] ?? 0);
    if (d !== 0) return d;
  }
  return (a ?? '').localeCompare(b ?? '');
}

/** Flags each brand's oldest versions and those an older major behind. */
export function flagVersions(rows: Array<{ brand: string; osVersion: string | null; count: number }>): InventoryVersion[] {
  const byBrand = new Map<string, Array<{ brand: string; osVersion: string | null; count: number }>>();
  for (const r of rows) {
    const list = byBrand.get(r.brand) ?? [];
    list.push(r);
    byBrand.set(r.brand, list);
  }
  const out: InventoryVersion[] = [];
  for (const [, list] of [...byBrand.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const known = list.filter((r) => versionTuple(r.osVersion) !== null).sort((a, b) => compareVersions(a.osVersion, b.osVersion));
    const flagged = new Set(known.slice(0, Math.min(OLDEST_VERSIONS_FLAGGED, Math.max(0, known.length - 1))).map((r) => r.osVersion));
    const newestMajor = known.length ? versionTuple(known[known.length - 1].osVersion)![0] : null;
    for (const r of [...known, ...list.filter((x) => versionTuple(x.osVersion) === null)]) {
      const t = versionTuple(r.osVersion);
      out.push({
        brand: r.brand,
        osVersion: r.osVersion,
        count: r.count,
        oldest: flagged.has(r.osVersion),
        majorBehind: t !== null && newestMajor !== null && t[0] < newestMajor,
      });
    }
  }
  return out;
}

// ============================================================================
// The report
// ============================================================================

interface DeviceRow {
  id: number;
  name: string;
  tenant_id: number;
  tenant_name: string;
  site_id: number | null;
  site_code: string | null;
  site_name: string | null;
  status: string;
  brand: string;
  model: string | null;
  os_version: string | null;
  ppp_username: string | null;
  system_identity: string | null;
  default_route_iface: string | null;
  default_route_gateway: string | null;
  default_route_observed_at: Date | null;
  /** Text: read through to_jsonb so the query does not depend on 075. */
  default_route_since: string | null;
  /** Migration 076; null without a site, or not declared. */
  site_uplink_kind: string | null;
}

function ref(d: DeviceRow): AnomalyDeviceRef {
  return {
    id: d.id,
    name: d.name,
    tenantId: d.tenant_id,
    tenantName: d.tenant_name,
    siteId: d.site_id,
    siteCode: d.site_code,
    siteName: d.site_name,
    status: d.status,
  };
}

const iso = (v: Date | string | null): string | null => (v === null ? null : new Date(v).toISOString());

export async function fleetAnomalies(scope: FleetAnomalyScope, now: Date = new Date()): Promise<FleetAnomaliesReport> {
  // Every router in scope, concentrators excluded (infrastructure, not fleet).
  const dq = db('devices as d')
    .join('tenants as t', 't.id', 'd.tenant_id')
    .leftJoin('sites as s', 's.id', 'd.site_id')
    .whereNot('d.role', 'concentrator')
    .select(
      'd.id', 'd.name', 'd.tenant_id', 't.name as tenant_name', 'd.site_id', 's.code as site_code',
      's.name as site_name', 'd.status', 'd.brand', 'd.model', 'd.os_version', 'd.ppp_username',
      'd.system_identity', 'd.default_route_iface', 'd.default_route_gateway', 'd.default_route_observed_at',
      // `default_route_since` is migration 075's (the 4G backup watch). Read
      // by NAME out of the row's JSON, so a database without that column
      // answers null ("since unknown") instead of failing the whole page.
      db.raw("to_jsonb(d) ->> 'default_route_since' AS default_route_since"),
      // The site's declared access link (migration 076). The join is on
      // `d.site_id` alone, as for the site's code and name.
      's.uplink_kind as site_uplink_kind',
    )
    .orderBy('d.name');
  if (!scope.masterView) dq.where('d.tenant_id', scope.tenantId);
  if (scope.deviceIdsIn) dq.whereIn('d.id', scope.deviceIdsIn);
  const devices = (await dq) as DeviceRow[];
  const byLogin = new Map<string, DeviceRow>();
  for (const d of devices) if (d.ppp_username) byLogin.set(d.ppp_username, d);

  // Sessions in scope: the tenant's logins only, or everything (unbound
  // logins included) in the master view.
  const since = new Date(now.getTime() - CHURN_WINDOW_MS);
  const scoped = (q: ReturnType<typeof db>) => {
    if (!scope.masterView) {
      q.whereIn('ss.ppp_username', db('devices').where('tenant_id', scope.tenantId).whereNotNull('ppp_username').whereNot('role', 'concentrator').select('ppp_username'));
    }
    if (scope.deviceIdsIn) {
      q.whereIn('ss.ppp_username', db('devices').whereIn('id', scope.deviceIdsIn).whereNotNull('ppp_username').select('ppp_username'));
    }
    return q;
  };

  // (a) duplicate logins
  const dupRows = (await scoped(
    db('ppp_sessions as ss')
      .where((w) => w.whereNull('ss.ended_at').orWhere('ss.started_at', '>=', since))
      .groupBy('ss.ppp_username')
      .select(
        'ss.ppp_username',
        db.raw('count(*) FILTER (WHERE ss.ended_at IS NULL)::int AS open_sessions'),
        db.raw('count(*) FILTER (WHERE ss.started_at >= ?)::int AS starts', [since]),
        db.raw('count(DISTINCT ss.caller_ip) FILTER (WHERE ss.started_at >= ?)::int AS callers', [since]),
        db.raw('array_remove(array_agg(DISTINCT host(ss.caller_ip)), NULL) AS caller_ips'),
        db.raw('max(ss.started_at) AS last_started_at'),
      ),
  )) as Array<{ ppp_username: string; open_sessions: number; starts: number; callers: number; caller_ips: string[]; last_started_at: Date | null }>;
  const duplicateLogins: DuplicateLogin[] = [];
  for (const r of dupRows) {
    const concurrent = r.open_sessions >= 2;
    const churn = r.starts >= CHURN_MIN_STARTS && r.callers >= CHURN_MIN_CALLERS;
    if (!concurrent && !churn) continue;
    const d = byLogin.get(r.ppp_username) ?? null;
    duplicateLogins.push({
      pppUsername: r.ppp_username,
      reason: concurrent && churn ? 'both' : concurrent ? 'concurrent' : 'churn',
      openSessions: r.open_sessions,
      startsLastHour: r.starts,
      distinctCallersLastHour: r.callers,
      callerIps: scope.masterView ? [...r.caller_ips].sort() : null,
      lastStartedAt: iso(r.last_started_at),
      device: d ? ref(d) : null,
    });
  }
  duplicateLogins.sort((a, b) => b.startsLastHour - a.startsLastHour || a.pppUsername.localeCompare(b.pppUsername));

  // (b) identity ≠ login
  const identityMismatches: IdentityMismatch[] = [];
  for (const d of devices) {
    if (!d.ppp_username || !d.system_identity) continue;
    const m = identitySiteMismatch(d.system_identity, d.ppp_username);
    if (!m) continue;
    const code = d.site_code !== null ? siteNumber(d.site_code) : null;
    identityMismatches.push({
      device: ref(d),
      pppUsername: d.ppp_username,
      systemIdentity: d.system_identity,
      loginSite: m.login.join(', '),
      identitySite: m.identity.join(', '),
      siteCodeAgreesWith:
        code === null ? null : m.login.includes(code) ? 'login' : m.identity.includes(code) ? 'identity' : 'neither',
    });
  }

  // (c) inventory
  const modelCounts = new Map<string, InventoryModel>();
  const versionCounts = new Map<string, { brand: string; osVersion: string | null; count: number }>();
  for (const d of devices) {
    const mk = `${d.brand}\u0000${d.model ?? ''}`;
    const m = modelCounts.get(mk) ?? { brand: d.brand, model: d.model, count: 0 };
    m.count++;
    modelCounts.set(mk, m);
    const vk = `${d.brand}\u0000${d.os_version ?? ''}`;
    const v = versionCounts.get(vk) ?? { brand: d.brand, osVersion: d.os_version, count: 0 };
    v.count++;
    versionCounts.set(vk, v);
  }
  const models = [...modelCounts.values()].sort((a, b) => b.count - a.count || a.brand.localeCompare(b.brand) || (a.model ?? '').localeCompare(b.model ?? ''));
  const versions = flagVersions([...versionCounts.values()]);

  // Open sessions: shared IPs (d) and cellular "since" (e).
  const openRows = (await scoped(
    db('ppp_sessions as ss')
      .whereNull('ss.ended_at')
      .select('ss.ppp_username', 'ss.started_at', db.raw('host(ss.caller_ip) AS caller_ip'))
      .orderBy('ss.started_at'),
  )) as Array<{ ppp_username: string; started_at: Date; caller_ip: string | null }>;
  const openByLogin = new Map<string, { started_at: Date; caller_ip: string | null }>();
  for (const r of openRows) if (!openByLogin.has(r.ppp_username)) openByLogin.set(r.ppp_username, r);

  const isCellular = (d: DeviceRow | null): boolean =>
    !!d?.default_route_iface && classify(d.default_route_iface, null) === 'lte';

  // (d) public IPs shared by several routers
  const byIp = new Map<string, Set<string>>();
  for (const r of openRows) {
    if (!r.caller_ip) continue;
    const set = byIp.get(r.caller_ip) ?? new Set<string>();
    set.add(r.ppp_username);
    byIp.set(r.caller_ip, set);
  }
  const sharedPublicIps: SharedPublicIp[] = [];
  for (const [ip, logins] of byIp) {
    if (logins.size < 2) continue;
    const routers = [...logins].sort().map((login) => {
      const d = byLogin.get(login) ?? null;
      return { pppUsername: login, device: d ? ref(d) : null, cellular: isCellular(d) };
    });
    const sites = routers.map((r) => r.device?.siteId).filter((s): s is number => s !== null && s !== undefined);
    sharedPublicIps.push({
      // The SCOPE rule (header): a tenant view never names a public address
      // another box may own; the group stays, its address does not.
      callerIp: scope.masterView ? ip : '',
      routers,
      sameSite: new Set(sites).size < sites.length,
      anyCellular: routers.some((r) => r.cellular),
    });
  }
  sharedPublicIps.sort((a, b) => Number(b.sameSite) - Number(a.sameSite) || b.routers.length - a.routers.length || a.callerIp.localeCompare(b.callerIp));

  // (e) cellular right now
  const cellular: CellularDevice[] = [];
  for (const d of devices) {
    if (!isCellular(d) || !d.default_route_observed_at) continue;
    const open = d.ppp_username ? openByLogin.get(d.ppp_username) : undefined;
    const declared = isSiteUplinkKind(d.site_uplink_kind) ? d.site_uplink_kind : null;
    cellular.push({
      device: ref(d),
      iface: d.default_route_iface!,
      gateway: d.default_route_gateway,
      since: d.default_route_since ? iso(d.default_route_since) : null,
      observedAt: iso(d.default_route_observed_at)!,
      stale: now.getTime() - new Date(d.default_route_observed_at).getTime() > LIVE_ROUTE_STALE_MS,
      online: !!open,
      sessionSince: open ? iso(open.started_at) : null,
      callerIp: scope.masterView ? (open?.caller_ip ?? null) : null,
      declaredUplink: declared,
      expected: declared === 'cellular_only',
    });
  }
  // The unexpected first (they are the anomalies), then fresh before stale.
  cellular.sort((a, b) =>
    Number(a.expected) - Number(b.expected) || Number(a.stale) - Number(b.stale) || a.device.name.localeCompare(b.device.name));

  return {
    generatedAt: now.toISOString(),
    scope: scope.masterView ? 'all' : 'tenant',
    duplicateLogins,
    identityMismatches,
    inventory: { total: devices.length, models, versions },
    sharedPublicIps,
    cellular,
  };
}
