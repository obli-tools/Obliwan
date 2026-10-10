/**
 * ObliWAN — the PURE half of the uplink verdict. `uplink.service.ts` does the
 * reading (SNMP samples, the latest snapshot, the live route on `devices`);
 * everything that DECIDES lives here, with no database and no socket, so the
 * no-DB harness (`testing/uplink.verify.ts`) can pin it on the real names of
 * this fleet.
 *
 * ┌─ A TUNNEL IS NEVER AN UPLINK ────────────────────────────────────────────┐
 * │ `l2tp-mgmt` (ObliWAN's own management tunnel) and `l2tp-infra` (a        │
 * │ customer's infrastructure tunnel, the equivalent of an IPsec one) are    │
 * │ PPP interfaces, so SNMP reports them as ifType 23 exactly like a PPPoE   │
 * │ client — and they used to be classified `pppoe` and offered as uplinks.  │
 * │ Their bytes already cross the physical uplink: counting them would count │
 * │ the same traffic twice, and a busy tunnel could be elected "the uplink"  │
 * │ of the site it runs over. So a tunnel is recognised by NAME first, kept  │
 * │ out of the candidates, and reported apart with its role.                 │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ "ROUTING SAYS" HAS TWO SOURCES, AND THE VERDICT SAYS WHICH ─────────────┐
 * │ snapshot  the lowest-distance default route of the latest configuration, │
 * │           when its gateway names an interface — INTENT.                  │
 * │ live      the default route the router's table has ACTIVE, read by the   │
 * │           health check over the RouterOS API (migration 073) — a FACT    │
 * │           at an instant, which after a failover names the backup.        │
 * │ The snapshot wins when it answers (it is the intent the traffic is       │
 * │ compared with); the live reading answers otherwise, with its age, and a  │
 * │ reading older than 24 h is said to be STALE, never shown as current.     │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

import { MANAGEMENT_TUNNEL_NAME, type SiteUplinkKind } from '@obliwan/shared';

/** Below this, a link is keeping itself alive, not carrying a site. Chosen an
 *  order of magnitude above keepalives/ARP/LLDP chatter and far below any real
 *  user traffic, so the classification does not hinge on a tuned threshold. */
export const IDLE_BPS = 16_000;

/** A live route reading older than this is shown as stale. */
export const LIVE_ROUTE_STALE_MS = 24 * 3600_000;

/** The l2tp-client a customer runs for its own infrastructure (customer A). */
export const INFRASTRUCTURE_TUNNEL_NAME = 'l2tp-infra';

export type UplinkKind = 'pppoe' | 'lte' | 'ethernet' | 'tunnel' | 'other';
export type TunnelRole = 'management' | 'infrastructure' | 'tunnel';

/** RouterOS names a server-side dynamic interface `<l2tp-user>`. */
function bareName(ifName: string): string {
  const n = ifName.trim().toLowerCase();
  return n.startsWith('<') && n.endsWith('>') ? n.slice(1, -1) : n;
}

/**
 * The tunnel families RouterOS names by default (`l2tp-out1`, `sstp-out1`,
 * `ovpn-out1`, `pptp-out1`, `gre-tunnel1`, `eoip-tunnel1`, `ipip-tunnel1`,
 * `6to4-tunnel1`, `vxlan1`, `wireguard1`) plus this fleet's `l2tp-mgmt` /
 * `l2tp-infra` and the usual `wg0`. Every prefix but `l2tp` must be followed
 * by a separator, a digit or nothing, so `green-lan` is not a GRE tunnel.
 */
const TUNNEL_NAME = /^(?:l2tp|(?:sstp|ovpn|pptp|gre|eoip|ipip|6to4|vxlan|wireguard|wg)(?=$|[-_.\d]))/;

export function isTunnelName(ifName: string): boolean {
  return TUNNEL_NAME.test(bareName(ifName));
}

/**
 * Classify by NAME and TYPE, never by position.
 *
 * Tunnels first, by name: SNMP cannot tell an L2TP client from a PPPoE one
 * (both ifType 23), the name can. Then the platform-imposed names (`pppoe`,
 * `lte`), then the type. A PPP interface that is not named like a tunnel is a
 * PPPoE client whatever the operator called it — `ADSL`, `FTTH`, `FTTO`,
 * `VDSL`, `Fibre` on this fleet.
 */
export function classify(ifName: string, ifType: number | null): UplinkKind {
  const n = bareName(ifName);
  if (TUNNEL_NAME.test(n)) return 'tunnel';
  if (n.includes('pppoe')) return 'pppoe';
  // `lte` at the start or after a separator: `lte1`, `WAN2-LTE` — not the
  // `lte` inside `filter` or `Alteo`.
  if (/(^|[^a-z])lte/.test(n)) return 'lte';
  // ifType 131 = tunnel, 23 = ppp, 243/244 = wwanPP/wwanPP2 (3GPP/3GPP2
  // cellular), 6 = ethernetCsmacd.
  if (ifType === 131) return 'tunnel';
  if (ifType === 23) return 'pppoe';
  if (ifType === 243 || ifType === 244) return 'lte';
  if (ifType === 6) return 'ethernet';
  return 'other';
}

/** What a tunnel is FOR, by the names this fleet gives them on purpose. */
export function tunnelRole(ifName: string): TunnelRole {
  const n = bareName(ifName);
  if (n === MANAGEMENT_TUNNEL_NAME) return 'management';
  if (n === INFRASTRUCTURE_TUNNEL_NAME) return 'infrastructure';
  return 'tunnel';
}

/** Only links that can plausibly be an uplink. A bridge or a LAN port moving
 *  traffic is not an answer to "which WAN are we on", and a tunnel never is. */
export function isUplinkCandidate(kind: UplinkKind, ifName: string): boolean {
  if (kind === 'tunnel') return false;
  if (kind === 'pppoe' || kind === 'lte') return true;
  // An ethernet port is a candidate only when it is named like a WAN: on this
  // fleet that is ether1, and the alias usually says so.
  return /(^|[^a-z])(ether1|wan|ont|orange|sfp)/i.test(ifName);
}

/**
 * The one place an SNMP interface becomes an uplink candidate, a tunnel, or
 * neither (a bridge, a LAN port). `uplink.service.ts` measures exactly what
 * this returns, and the no-DB harness filters through the same function, so
 * "a tunnel never reaches the verdict" is pinned on the code path that runs.
 */
export function partitionInterfaces<T extends { if_name: string; if_type: number | null }>(
  rows: readonly T[],
): { candidates: Array<{ row: T; kind: UplinkKind }>; tunnels: Array<{ row: T; role: TunnelRole }> } {
  const candidates: Array<{ row: T; kind: UplinkKind }> = [];
  const tunnels: Array<{ row: T; role: TunnelRole }> = [];
  for (const row of rows) {
    const kind = classify(row.if_name, row.if_type);
    if (kind === 'tunnel') tunnels.push({ row, role: tunnelRole(row.if_name) });
    else if (isUplinkCandidate(kind, row.if_name)) candidates.push({ row, kind });
  }
  return { candidates, tunnels };
}

// ============================================================================
// The live route — `/ip/route/print` rows as the RouterOS API returns them
// ============================================================================

/** One next hop of a route, as the router printed it. */
export interface RouteHop {
  gateway: string;
  /** The outgoing interface, or null when the router did not print one. */
  iface: string | null;
}

/** The main table's active default route, reduced to what the card needs.
 *  `gateway: null` = no active default route at all (and then `iface` is
 *  null too). */
export interface ActiveDefaultRoute {
  iface: string | null;
  gateway: string | null;
}

const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const looksLikeAddress = (s: string): boolean => IPV4.test(s) || s.includes(':');
const NAME_MAX = 128;
const GATEWAY_MAX = 255;

function text(v: unknown): string {
  return v === undefined || v === null ? '' : String(v).trim();
}
function yes(v: unknown): boolean {
  const s = text(v).toLowerCase();
  return s === 'true' || s === 'yes';
}

/**
 * RouterOS 7 `immediate-gw`: `192.168.1.254%ether1-WAN1` for an IP next hop,
 * the bare interface (`lte1`, `pppoe-out1`) for an interface gateway. An
 * address with no `%interface` names no interface, and none is guessed.
 */
export function hopsFromImmediateGw(value: string): RouteHop[] {
  return value
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s !== '')
    .map((s) => {
      const pct = s.indexOf('%');
      if (pct > 0) return { gateway: s.slice(0, pct), iface: s.slice(pct + 1).trim() || null };
      return { gateway: s, iface: looksLikeAddress(s) ? null : s };
    });
}

/**
 * RouterOS 6 `gateway-status`, one entry per gateway, comma-separated:
 *   `192.168.1.254 reachable via  ether1-WAN1`
 *   `8.8.8.8 recursive via 192.168.1.254 ether1-WAN1`
 *   `lte1 reachable`
 *   `192.168.1.254 unreachable`            → not a hop
 * A wording this parser does not know is not a hop either: never a guess.
 */
export function hopsFromGatewayStatus(value: string): RouteHop[] {
  const hops: RouteHop[] = [];
  for (const part of value.split(',')) {
    const s = part.trim().replace(/\s+/g, ' ');
    if (s === '') continue;
    const via = /^(\S+) (?:reachable|recursive) via (.+)$/.exec(s);
    if (via) {
      let rest = via[2].trim();
      // recursive: the immediate next hop's address precedes the interface.
      const lead = /^(\S+) (.+)$/.exec(rest);
      if (lead && looksLikeAddress(lead[1])) rest = lead[2].trim();
      hops.push({ gateway: via[1], iface: rest === '' || looksLikeAddress(rest) ? null : rest });
      continue;
    }
    const bare = /^(.+) reachable$/.exec(s);
    if (bare) {
      const g = bare[1].trim();
      hops.push({ gateway: g, iface: looksLikeAddress(g) ? null : g });
    }
  }
  return hops;
}

/**
 * The main table's ACTIVE default route out of `/ip/route/print` rows.
 *
 * Filters locally rather than trusting a query word: only `0.0.0.0/0`, only
 * `active`, never `disabled`, only the main table (`routing-table` on ROS 7,
 * no `routing-mark` on ROS 6) — a policy-routing table's default is not the
 * site's. Lowest distance wins; several active routes at that distance (ECMP)
 * through DIFFERENT interfaces leave the interface unknown, as does a hop the
 * router printed without one. Unknown stays unknown.
 */
export function readActiveDefaultRoute(rows: unknown): ActiveDefaultRoute {
  const list = (Array.isArray(rows) ? rows : []).filter(
    (r): r is Record<string, unknown> => typeof r === 'object' && r !== null,
  );
  const active = list.filter((r) => {
    const table = text(r['routing-table']);
    return (
      text(r['dst-address']) === '0.0.0.0/0' &&
      yes(r.active) &&
      !yes(r.disabled) &&
      (table === '' || table === 'main') &&
      text(r['routing-mark']) === ''
    );
  });
  if (active.length === 0) return { iface: null, gateway: null };

  // Trim BEFORE testing for emptiness: `Number(' ')` is 0, not NaN.
  const distance = (r: Record<string, unknown>): number => {
    const d = text(r.distance);
    const n = d === '' ? NaN : Number(d);
    return Number.isFinite(n) ? n : Number.POSITIVE_INFINITY;
  };
  const best = Math.min(...active.map(distance));
  const chosen = active.filter((r) => distance(r) === best);

  const hops: RouteHop[] = [];
  let unresolved = false;
  for (const r of chosen) {
    const immediate = text(r['immediate-gw']);
    const status = text(r['gateway-status']);
    const h = immediate !== ''
      ? hopsFromImmediateGw(immediate)
      : status !== '' ? hopsFromGatewayStatus(status) : [];
    if (h.length === 0) unresolved = true;
    hops.push(...h);
  }
  const ifaces = new Set(hops.map((h) => h.iface));
  const iface = !unresolved && ifaces.size === 1 && !ifaces.has(null)
    ? [...ifaces][0]!.slice(0, NAME_MAX)
    : null;

  const printed = [...new Set(chosen.map((r) => text(r.gateway)).filter((g) => g !== ''))];
  const fromHops = [...new Set(hops.map((h) => h.gateway))];
  const kind = chosen.map((r) => text(r.type)).find((t) => t !== '' && t !== 'unicast');
  const gateway = printed.length > 0
    ? printed.join(',')
    : fromHops.length > 0
      ? fromHops.join(',')
      // An active default with no gateway at all is a blackhole-type route.
      : kind ?? (chosen.some((r) => yes(r.blackhole)) ? 'blackhole' : '(no gateway printed)');
  return { iface, gateway: gateway.slice(0, GATEWAY_MAX) };
}

// ============================================================================
// The snapshot's answer — intent
// ============================================================================

/** The fields of an NCM route this needs (`NcmRoute`). */
export interface SnapshotRoute {
  dst: string;
  disabled: boolean;
  table: string;
  vrf: string | null;
  distance: number | null;
  gateway: string | null;
}

/**
 * The configured default route's outgoing interface, from a snapshot's routes.
 *
 * Main table only, never a disabled route, and only the LOWEST distance — as
 * RouterOS decides it. `gateway` is a selector atom: `iface:ether1-ONTOrange`
 * names an interface directly, `ip:…` names a next hop that could be reached
 * through any of them, and claiming an answer from the second would be a
 * guess dressed as a fact. So when the lowest-distance route has an address
 * gateway the snapshot does NOT answer: falling through to the next distance,
 * as this once did, named the BACKUP as the intent whenever the primary had an
 * IP gateway — which is every DHCP-scripted WAN1 on this fleet.
 */
export function snapshotDefaultIface(routes: readonly SnapshotRoute[]): string | null {
  const defaults = routes.filter(
    (r) => r.dst === '0.0.0.0/0' && !r.disabled && r.table === 'main' && r.vrf === null,
  );
  if (defaults.length === 0) return null;
  const best = Math.min(...defaults.map((r) => r.distance ?? 1));
  const ifaces = new Set<string>();
  for (const r of defaults.filter((d) => (d.distance ?? 1) === best)) {
    if (typeof r.gateway !== 'string' || !r.gateway.startsWith('iface:')) return null;
    ifaces.add(r.gateway.slice('iface:'.length));
  }
  return ifaces.size === 1 ? [...ifaces][0]! : null;
}

// ============================================================================
// The verdict — what the counters say against what the routing says
// ============================================================================

/**
 * Whether the router's active default route is on record, and when it is not,
 * WHY — because "not read yet" promises a reading, and on most devices that
 * have none nothing will ever take it. The health check reads the route only
 * on a RouterOS API session (`probe`), never on a concentrator (it reads
 * `/ppp/active` there), and files it only against an identity on record (
 * `observeDefaultRoute`). Each refusal is its own state so the card can say
 * which one, and what would lift it.
 *
 *   read            a reading exists (possibly stale — `isLiveStale`)
 *   not_yet         everything the check needs is there; the next check reads it
 *   no_api_channel  no usable RouterOS API channel: a legacy router reached by
 *                   SSH until the management access job opens one
 *   not_routeros    not a MikroTik: no RouterOS API exists to read it on
 *   concentrator    the check reads only `/ppp/active` on a concentrator
 *   no_identity     no `system_identity` on record: nothing to verify the box
 *                   against, so nothing is filed (Test connection records it)
 */
export type LiveRouteStatus =
  | 'read'
  | 'not_yet'
  | 'no_api_channel'
  | 'not_routeros'
  | 'concentrator'
  | 'no_identity'
  | 'not_polled';

export function liveRouteStatus(f: {
  /** `devices.default_route_observed_at` is set. */
  observed: boolean;
  brand: string;
  role: string;
  /** An enabled, complete RouterOS API channel — the health check's own rule. */
  apiChannel: boolean;
  systemIdentity: string | null;
  /** `devices.status`: the health check reads neither a disabled nor a
   *  quarantined device, so "not yet" would promise a reading that never comes. */
  status?: string | null;
}): LiveRouteStatus {
  if (f.observed) return 'read';
  if (f.status === 'disabled' || f.status === 'quarantined') return 'not_polled';
  if (f.brand !== 'mikrotik') return 'not_routeros';
  if (f.role === 'concentrator') return 'concentrator';
  if (!f.apiChannel) return 'no_api_channel';
  if (!f.systemIdentity) return 'no_identity';
  return 'not_yet';
}

/** The second half of "no default route names an interface", per status. */
function unreadClause(status: LiveRouteStatus): string {
  switch (status) {
    case 'no_api_channel':
      return "and the router's active route cannot be read: this router has no RouterOS API channel yet "
        + '(the management access job opens it).';
    case 'not_routeros':
      return "and the router's active route cannot be read: this is not a RouterOS router, and the "
        + 'route is read over the RouterOS API only.';
    case 'concentrator':
      return "and the router's active route is not read: on a concentrator the health check reads "
        + 'only /ppp/active.';
    case 'no_identity':
      return "and the router's active route is not filed: this device's identity is not on record, and "
        + 'a route is filed only against a confirmed identity (Test connection records it).';
    case 'not_polled':
      return "and the router's active route is not read: the health check skips a disabled or "
        + 'quarantined device.';
    default:
      return "and the router's active route has not been read yet (the health check reads it over the "
        + 'RouterOS API).';
  }
}

/** A live reading as stored on `devices` (migration 073). */
export interface LiveRouteReading {
  iface: string | null;
  /** null = the router had no active default route when it was read. */
  gateway: string | null;
  observedAt: Date;
}

export interface RoutingAnswer {
  iface: string | null;
  source: 'snapshot' | 'live' | null;
  /** When the answer was read: the snapshot's last sighting, or the live
   *  reading's instant. */
  at: Date | null;
  /** Only a live reading goes stale: intent does not age the way a fact does. */
  stale: boolean;
}

export function isLiveStale(live: LiveRouteReading, now: Date): boolean {
  return now.getTime() - live.observedAt.getTime() > LIVE_ROUTE_STALE_MS;
}

/** The snapshot's interface when it names one (intent), else the live one. */
export function routingAnswer(
  snapshot: { iface: string; at: Date | null } | null,
  live: LiveRouteReading | null,
  now: Date,
): RoutingAnswer {
  if (snapshot) return { iface: snapshot.iface, source: 'snapshot', at: snapshot.at, stale: false };
  if (live && live.iface) {
    return { iface: live.iface, source: 'live', at: live.observedAt, stale: isLiveStale(live, now) };
  }
  return { iface: null, source: null, at: null, stale: false };
}

/** "read 3 min ago" — English, like every sentence of this verdict. */
export function readAgo(at: Date, now: Date): string {
  const s = Math.max(0, Math.round((now.getTime() - at.getTime()) / 1000));
  if (s < 60) return `read ${s} s ago`;
  if (s < 3600) return `read ${Math.round(s / 60)} min ago`;
  if (s < 48 * 3600) return `read ${Math.round(s / 3600)} h ago`;
  return `read ${Math.round(s / 86400)} days ago`;
}

function liveWhen(live: LiveRouteReading, now: Date): string {
  return isLiveStale(live, now)
    ? `${readAgo(live.observedAt, now)} — STALE, older than 24 h`
    : readAgo(live.observedAt, now);
}

/** A sentence naming the live route, or null when it was never read. */
function liveSentence(
  live: LiveRouteReading | null,
  now: Date,
  kindOf: (ifName: string) => UplinkKind,
  declared: SiteUplinkKind | null = null,
): string | null {
  if (!live) return null;
  const when = liveWhen(live, now);
  if (live.gateway === null) return `The router had NO active default route (${when}).`;
  if (live.iface === null) {
    return `The router's active default route goes via ${live.gateway}, through an interface it did not name (${when}).`;
  }
  if (kindOf(live.iface) !== 'lte') return `The router's active default route is ${live.iface} (${when}).`;
  return declared === 'cellular_only'
    ? `The router's active default route is ${live.iface}, its cellular link (${when}): the site is declared 4G-only, so this is its nominal path.`
    : `The router's active default route is ${live.iface}, its cellular link (${when}): by its own routing table, this site is on its backup.`;
}

/** The sentence of a site declared 4G-only whose traffic is on its cellular
 *  link: the nominal path, never a failover nor a disagreement. */
function cellularOnlySentence(a: string): string {
  return `Traffic is on ${a} (LTE). This site is declared 4G-only: its cellular link is its nominal path, not a backup.`;
}

export interface MeasuredCandidate {
  ifName: string;
  kind: UplinkKind;
  inBps: number | null;
  outBps: number | null;
  /** `null` when no rate could be derived — NOT `false`. */
  carrying: boolean | null;
}

export interface TrafficJudgement {
  observed: string | null;
  onBackup: boolean | null;
  reason: string;
}

/**
 * Which candidate carries the traffic, and what that means against the
 * routing answer. `onBackup` stays a TRAFFIC verdict (the busiest carrying
 * link is cellular): the routing answer shapes the sentence, never the flag,
 * so the OS upgrade's metered-uplink refusal keeps deciding on bytes.
 *
 * The site's DECLARATION (migration 076) shapes the sentence too, and never
 * the flag either: on a site declared 4G-only, traffic on the cellular link is
 * the NOMINAL path — said as such, never as a failover or a disagreement with
 * the routing answer — while `onBackup` still says the bytes are on a metered
 * link. Traffic on a fixed link of a site declared 4G-only is said to
 * contradict the declaration.
 */
export function judgeTraffic(args: {
  candidates: MeasuredCandidate[];
  routing: RoutingAnswer;
  live: LiveRouteReading | null;
  /** Why `live` is null when it is: the sentence never promises a reading
   *  nothing will take. */
  liveStatus: LiveRouteStatus;
  now: Date;
  /** The site's declared access link; absent or null = not declared. */
  declared?: SiteUplinkKind | null;
}): TrafficJudgement {
  const { candidates, routing, live, liveStatus, now } = args;
  const declared = args.declared ?? null;
  const kindOf = (ifName: string): UplinkKind =>
    candidates.find((c) => c.ifName === ifName)?.kind ?? classify(ifName, null);

  const measured = candidates.filter((c) => c.carrying !== null);
  const carrying = measured.filter((c) => c.carrying);
  // Busiest wins when several move traffic: a backup that has taken over still
  // leaves keepalives on the primary's physical port.
  carrying.sort((a, b) => Math.max(b.inBps!, b.outBps!) - Math.max(a.inBps!, a.outBps!));
  const observed = carrying[0]?.ifName ?? null;

  const routeLive = liveSentence(live, now, kindOf, declared);
  const withLive = (s: string): string => (routeLive ? `${s} ${routeLive}` : s);

  if (measured.length === 0) {
    return {
      observed: null,
      onBackup: null,
      reason: withLive(
        candidates.length === 0
          ? 'No uplink interface was recognised on this device yet. Run an SNMP discovery first.'
          : 'No uplink has two samples yet, so no rate can be derived. A throughput is a derivative: '
            + 'the first poll gives a counter, the second gives a number.',
      ),
    };
  }

  if (!observed) {
    const idle = 'Every uplink is idle — under the noise floor. The site is up and passing nothing, '
      + 'which is normal out of hours and worth a look during them.';
    if (routeLive) return { observed: null, onBackup: null, reason: `${idle} ${routeLive}` };
    return {
      observed: null,
      onBackup: null,
      reason: routing.source === 'snapshot'
        ? `${idle} The configuration routes the site through ${routing.iface}.`
        : idle,
    };
  }

  const active = carrying[0]!;
  const a = active.ifName;
  const c = routing.iface;
  const liveWhenText = routing.source === 'live' && live ? liveWhen(live, now) : '';
  const lte = active.kind === 'lte';

  if (declared === 'cellular_only') {
    if (lte) {
      // Nominal: whatever the routing answer names, it is not a failover. The
      // live route is added only when it names something else than a cellular
      // link — that, not the SIM carrying traffic, is the thing to read.
      const liveOther = live !== null && (live.gateway === null || live.iface === null || kindOf(live.iface) !== 'lte');
      const base = cellularOnlySentence(a);
      return { observed, onBackup: lte, reason: liveOther && routeLive ? `${base} ${routeLive}` : base };
    }
    return {
      observed,
      onBackup: lte,
      reason: `Traffic is on ${a}, yet this site is declared 4G-only: the declaration may be out of date `
        + '(a fixed line was installed?). Check it on the site page.',
    };
  }

  if (c === null) {
    const base = lte
      ? `Traffic is on ${a} (LTE). This site is running on its cellular backup.`
      : `Traffic is on ${a}.`;
    return {
      observed,
      onBackup: lte,
      reason: withLive(
        routeLive
          ? base
          : `${base} No default route names an interface in the configuration, ${unreadClause(liveStatus)}`,
      ),
    };
  }

  if (routing.source === 'snapshot') {
    // Intent against fact: the original two-answer comparison.
    const reason = lte
      ? c !== a
        ? `Traffic is on ${a} (LTE) while the default route still names ${c}. The site has failed `
          + 'over to its SIM and the configuration does not say so — bandwidth is metered and '
          + 'degraded until the primary comes back.'
        : `Traffic is on ${a} (LTE). This site is running on its cellular backup.`
      : c !== a
        ? `Traffic is on ${a}, but the default route names ${c}. Both are primary-class links, so `
          + 'this is a routing question rather than a failover.'
        : `Traffic is on ${a}, which is what the routing says it should be.`;
    // The live table disagreeing with the configuration is the failover seen
    // from the routing side: say it rather than hide it behind the intent.
    const differs = live !== null && (live.gateway === null || live.iface !== c);
    return { observed, onBackup: lte, reason: differs && routeLive ? `${reason} ${routeLive}` : reason };
  }

  // routing.source === 'live': fact against fact, with the reading's age.
  const reason = lte
    ? c === a
      ? `Traffic is on ${a} (LTE), and the router's active default route is ${a} too (${liveWhenText}): `
        + 'this site is running on its cellular backup — bandwidth is metered and degraded until '
        + 'the primary comes back.'
      : `Traffic is on ${a} (LTE) while the router's active default route is ${c} (${liveWhenText}). `
        + 'Either policy routing sends traffic over the SIM, or the table changed since it was read '
        + `— bandwidth on ${a} is metered.`
    : c === a
      ? `Traffic is on ${a}, which is the router's active default route (${liveWhenText}).`
      : `Traffic is on ${a}, but the router's active default route is ${c} (${liveWhenText}). `
        + 'Policy routing, or the table changed since it was read.';
  return { observed, onBackup: lte, reason };
}
