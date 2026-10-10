/**
 * ObliWAN — changing the WAN1 link of a store (kind `wan_link`, migration 090,
 * server/src/services/change/wanLink.service.ts): a box handing out DHCP
 * (`dhcp`), a PPPoE login on ADSL, FTTH or FTTO (`pppoe`), or a fixed address
 * (`static`). The three shapes are those of the standard customer templates
 * (operator templates; the pppoe one is the production
 * microcode's effect):
 *
 *   - ether1-WAN1 and lte1 are both members of the WAN list;
 *   - route `NW-WAN1` = the probe host /32 and route `WAN1-GW` = 0.0.0.0/0
 *     (vrf-interface ether1-WAN1), distance 1, both through the WAN1 gateway;
 *   - netwatch `WAN1` pings the probe host and disables / enables the routes
 *     whose comment starts with `WAN1` (WAN1-GW) — the LTE failover;
 *   - dhcp: the client "WAN1 DHCP", add-default-route=no, whose bound script
 *     re-points both routes;
 *   - pppoe: a pppoe-client ADSL|FTTH|FTTO on ether1-WAN1, add-default-route=
 *     yes, a member of the WAN list; both routes and the netwatch disabled; the
 *     DHCP client kept;
 *   - static: the address on ether1-WAN1, both routes through the gateway, no
 *     DHCP client, the netwatch kept.
 *
 * ┌─ ONE SCRIPT, ON THE ROUTER, WITH ITS OWN WAY BACK ───────────────────────┐
 * │ Changing the link cuts the path the job travels on (l2tp-mgmt leaves     │
 * │ through WAN1). So nothing is sent line by line: ONE `:execute` starts a  │
 * │ script on the router (the operator's own rule: « en un seul bloc sur le  │
 * │ routeur, jamais ligne à ligne à travers le tunnel »), which                │
 * │   1. waits WAN_LINK_ARM_LEAD_S (the job sees it alive meanwhile),        │
 * │   2. gives up, changing nothing, unless lte1 runs and WAN1 is still the  │
 * │      mode the job read (`ABANDONED`),                                     │
 * │   3. fails over to the 4G exactly as the netwatch down-script does       │
 * │      (netwatch WAN1 disabled, then route WAN1-GW disabled),              │
 * │   4. retires the old link — DISABLED, never removed (operator decision   │
 * │      2026-10-07: an instant manual way back) — and installs the new one, │
 * │   5. waits up to N seconds for the new link to carry a ping to the probe │
 * │      host THROUGH WAN1 (never through the 4G), then either finishes      │
 * │      (`APPLIED`) or puts every object it touched back as it read it      │
 * │      (`REVERTED`).                                                        │
 * │ It never touches lte1, its APN profiles, an l2tp-client, random-source-  │
 * │ port, mac-server / mac-winbox / RoMON, a service, a user or the firewall │
 * │ (`assertWanLinkOnlyLines`).                                               │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * REASONED, NOT OBSERVED (no line of this file has reached a router): that
 * `:execute` runs under device-mode home and outlives its SSH session; the
 * field names of `/interface lte monitor … once`; that `[/ping … count=3]`
 * returns the reply count; `find where active=yes` on routes and the DHCP
 * client's `status` "bound"; that renaming a pppoe-client keeps its WAN list
 * member; that the DHCP client script survives two levels of quoting. A wrong
 * field name makes every job refuse (an unread signal is `unknown`), never
 * write.
 *
 * Pure: no I/O. Server messages are English; the service writes the
 * operator's sentences.
 */

import {
  LEGACY_GUARD_JOB_TAG,
  LEGACY_WAN_LIST,
  legacyNetworkOf,
  legacyParseIpv4Prefix,
  routerOsScriptLiteral,
} from './legacyCompliance';
import { interfacesOfGateway, type LteEgressReading, type LteRouteReading } from './lteApn';

// ============================================================================
// Vocabulary
// ============================================================================

export const WAN_LINK_KIND = 'wan_link' as const;

export const WAN1_MODES = ['dhcp', 'pppoe', 'static'] as const;
export type Wan1Mode = (typeof WAN1_MODES)[number];
export function isWan1Mode(v: unknown): v is Wan1Mode {
  return typeof v === 'string' && (WAN1_MODES as readonly string[]).includes(v);
}

export const WAN1_PPPOE_NAMES = ['ADSL', 'FTTH', 'FTTO'] as const;
export type Wan1PppoeName = (typeof WAN1_PPPOE_NAMES)[number];
export function isWan1PppoeName(v: unknown): v is Wan1PppoeName {
  return typeof v === 'string' && (WAN1_PPPOE_NAMES as readonly string[]).includes(v);
}

/** The objects of the standard structure, by the names the templates give them. */
export const WAN1_IF = 'ether1-WAN1';
export const WAN_ROUTE_GW = 'WAN1-GW';
export const WAN_ROUTE_PROBE = 'NW-WAN1';
export const WAN_NETWATCH = 'WAN1';
export const WAN_DHCP_COMMENT = 'WAN1 DHCP';
export const WAN_LIST = LEGACY_WAN_LIST;
export const WAN_LTE_DEFAULT_NAME = 'lte1';

/** The six site variables the templates declare (operator templates). */
export const WAN1_VARIABLE_KEYS = {
  mode: 'wan1_mode',
  pppoeName: 'wan1_pppoe_name',
  pppoeUsername: 'wan1_pppoe_username',
  pppoePassword: 'wan1_pppoe_password',
  address: 'wan1_address',
  gateway: 'wan1_gateway',
} as const;

/** The placeholder the script carries for the PPPoE password; the plaintext
 *  is spliced in last, after the allow-list judged the line (server). */
export const WAN_PPPOE_PASSWORD_PLACEHOLDER = '__OBLIWAN_SECRET_WAN1_PPPOE_PASSWORD__';

/** Before the script changes anything: the job sees it alive meanwhile. */
export const WAN_LINK_ARM_LEAD_S = 20;
/** How long the script waits for the new link before putting the old one back. */
export const WAN_LINK_REVERT_AFTER_S = 300;
export const WAN_LINK_REVERT_MIN_S = 120;
export const WAN_LINK_REVERT_MAX_S = 1800;
/** The operator's observed 30–60 s for l2tp-mgmt to fail over: the upper bound. */
export const WAN_LINK_FAILOVER_BUDGET_S = 60;
export const WAN_LINK_MARGIN_S = 30;
/** The script's wait between two looks at the new link. */
export const WAN_LINK_UP_POLL_S = 5;
/** What a ping of three takes at most (default 1 s timeout each). */
export const WAN_LINK_PING_S = 3;
/** The 4G must be at least this good before the fixed link is cut. */
export const WAN_LINK_MIN_RSRP_DBM = -110;
export const WAN_LINK_MIN_SINR_DB = 0;

/** The job's own bound, from the script's start: the lead, the wait, two
 *  failovers of the management tunnel (to the 4G, then back) and a margin. */
export function wanLinkWaitS(revertAfterS: number): number {
  return WAN_LINK_ARM_LEAD_S + revertAfterS + 2 * WAN_LINK_FAILOVER_BUDGET_S + WAN_LINK_MARGIN_S;
}

export function wanLinkRevertAfterValid(n: unknown): n is number {
  return typeof n === 'number' && Number.isInteger(n) && n >= WAN_LINK_REVERT_MIN_S && n <= WAN_LINK_REVERT_MAX_S;
}

/** Marks the script's log lines: `obliwan-wanlink job=<id>: <VERB> …`. */
export function wanLinkLogPrefix(jobId: number): string {
  return `obliwan-wanlink job=${jobId}:`;
}
export const WAN_LINK_LOG_VERBS = ['START', 'APPLIED', 'REVERTED', 'ABANDONED'] as const;

/** The templates' own rule for the PPPoE login. */
export const WAN_PPPOE_USER_RE = /^[A-Za-z0-9._@+/-]{1,64}$/;
/**
 * The PPPoE password the job can splice into its one line: printable ASCII,
 * 4 to 64 characters, none of what ends an argument or a statement at either
 * of the line's two quoting levels (whitespace, controls, `" \ $ ; [ ] { }`, a
 * backtick — the vault splice's own set — and `?`, which RouterOS escapes in
 * a string). Four at least: the audit scrubs a protected value of four
 * characters or more, and a shorter one would land in `command_audit`.
 */
export const WAN_PPPOE_PASSWORD_RE = /^[A-Za-z0-9!#%&'()*+,\-./:<=>@^_|~]{4,64}$/;

export class WanLinkInputError extends Error {
  constructor(readonly field: string, message: string) {
    super(message);
    this.name = 'WanLinkInputError';
  }
}

// ============================================================================
// IPv4
// ============================================================================

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export function isIpv4(text: string): boolean {
  const m = IPV4_RE.exec(text.trim());
  return m !== null && m.slice(1).every((p) => Number(p) <= 255) && text.trim() === text;
}

function maskOf(len: number): number {
  return len === 0 ? 0 : (0xffffffff << (32 - len)) >>> 0;
}

/** Why a static target is refused, or null. The templates' refusals: a /8–/32
 *  host address, a bare IPv4 gateway inside its network, not the router's own
 *  address, and not the network or broadcast address of a /8–/30. */
export type WanStaticRefusal =
  | 'address_invalid'
  | 'prefix_out_of_range'
  | 'gateway_invalid'
  | 'gateway_outside_network'
  | 'gateway_is_own_address'
  | 'address_not_host';

export function validateStaticTarget(address: string, gateway: string): WanStaticRefusal | null {
  const a = (address ?? '').trim();
  const g = (gateway ?? '').trim();
  if (a !== address || !a.includes('/')) return 'address_invalid';
  const p = legacyParseIpv4Prefix(a);
  if (!p || !isIpv4(a.split('/')[0])) return 'address_invalid';
  if (p.len < 8 || p.len > 32) return 'prefix_out_of_range';
  if (g !== gateway || !isIpv4(g)) return 'gateway_invalid';
  const gw = legacyParseIpv4Prefix(g);
  if (!gw) return 'gateway_invalid';
  if (legacyNetworkOf(`${g}/${p.len}`) !== legacyNetworkOf(a)) return 'gateway_outside_network';
  if (gw.ip === p.ip) return 'gateway_is_own_address';
  if (p.len <= 30) {
    const net = (p.ip & maskOf(p.len)) >>> 0;
    const bcast = (net | (~maskOf(p.len) >>> 0)) >>> 0;
    if (p.ip === net || p.ip === bcast) return 'address_not_host';
  }
  return null;
}

/** A gateway the restore can write back bare: an IPv4 address or an
 *  interface name of the safe set. */
const RESTORE_GATEWAY_RE = /^[A-Za-z0-9._-]{1,64}$/;
function restorableGateway(g: string): boolean {
  return isIpv4(g) || (RESTORE_GATEWAY_RE.test(g) && !/^\d/.test(g));
}

// ============================================================================
// The reading
// ============================================================================

export interface WanPppoeClientReading {
  name: string;
  interface: string;
  user: string;
  disabled: boolean;
  running: boolean;
}

export interface WanDhcpClientReading {
  disabled: boolean;
  status: string;
  /** `add-default-route` as printed. */
  addDefaultRoute: string;
  comment: string;
  /** Its script re-points WAN1-GW (the hardened script's mark). */
  stdScript: boolean;
  gateway: string;
}

export interface WanAddressReading {
  address: string;
  disabled: boolean;
}

export interface WanRouteReading {
  comment: string;
  dst: string;
  gateway: string;
  disabled: boolean;
  active: boolean;
}

export interface WanNetwatchReading {
  host: string;
  disabled: boolean;
}

export interface WanMemberReading {
  interface: string;
  disabled: boolean;
}

export interface WanLteReading {
  present: boolean;
  name: string | null;
  running: boolean;
  disabled: boolean;
  /** `registration-status` as printed; null = unread. */
  registration: string | null;
  /** dBm; null = not printed or unreadable — never 0. */
  rsrp: number | null;
  /** dB; null = not printed. */
  sinr: number | null;
  tech: string | null;
}

/** An enabled route as the takeover judge reads it: the egress read plus its comment. */
export type WanEgressRoute = LteRouteReading & { comment: string };

export interface WanLinkReading {
  /** ether1-WAN1 exists. */
  wan1If: boolean | null;
  /** Every pppoe-client, whatever its interface. */
  pppoeClients: WanPppoeClientReading[] | null;
  /** The DHCP clients on ether1-WAN1. */
  dhcpClients: WanDhcpClientReading[] | null;
  /** The non-dynamic addresses on ether1-WAN1. */
  staticAddrs: WanAddressReading[] | null;
  /** Routes commented NW-WAN1 or WAN1-GW. */
  routes: WanRouteReading[] | null;
  /** Netwatch entries commented WAN1. */
  netwatch: WanNetwatchReading[] | null;
  /** Members of the WAN list. */
  wanMembers: WanMemberReading[] | null;
  lte: WanLteReading | null;
  /** The l2tp-client named l2tp-mgmt. */
  l2tpMgmt: { present: boolean; running: boolean; disabled: boolean } | null;
  /** What carries the management tunnel (routes with their comment). */
  egress: (Omit<LteEgressReading, 'routes'> & { routes: WanEgressRoute[] | null }) | null;
}

// ============================================================================
// What mode the router is in
// ============================================================================

export interface Wan1Params {
  pppoeName: string | null;
  pppoeUser: string | null;
  address: string | null;
  gateway: string | null;
  probeHost: string | null;
}

export interface Wan1Classification {
  mode: Wan1Mode | null;
  /** Why the mode is null (codes); empty when classified. */
  reasons: string[];
  params: Wan1Params;
}

const isFalse = (v: string): boolean => ['no', 'false'].includes(v.trim().toLowerCase());

/**
 * The router's WAN1 mode, from the standard structure only. Anything else —
 * customer E's ISP1/ISP2, two clients, a PPPoE client on a VLAN, a missing or
 * doubled route — is `null` with named reasons: the job refuses rather than
 * guess what it would be changing.
 */
export function classifyWan1(r: WanLinkReading): Wan1Classification {
  const params: Wan1Params = { pppoeName: null, pppoeUser: null, address: null, gateway: null, probeHost: null };
  const reasons: string[] = [];
  const unread = (['wan1If', 'pppoeClients', 'dhcpClients', 'staticAddrs', 'routes', 'netwatch', 'wanMembers', 'lte'] as const)
    .filter((k) => r[k] === null);
  if (unread.length > 0) return { mode: null, reasons: unread.map((k) => `unread:${k}`), params };
  if (r.wan1If === false) return { mode: null, reasons: ['no_wan1_interface'], params };
  const routes = r.routes as WanRouteReading[];
  const nw = routes.filter((x) => x.comment === WAN_ROUTE_PROBE);
  const gw = routes.filter((x) => x.comment === WAN_ROUTE_GW);
  if (nw.length !== 1) reasons.push(nw.length === 0 ? 'no_probe_route' : 'two_probe_routes');
  if (gw.length !== 1) reasons.push(gw.length === 0 ? 'no_gw_route' : 'two_gw_routes');
  const probe = nw[0];
  if (probe) {
    const m = /^(.+)\/32$/.exec(probe.dst.trim());
    if (!m || !isIpv4(m[1])) reasons.push('probe_route_not_host');
    else params.probeHost = m[1];
  }
  if (gw[0] && gw[0].dst.trim() !== '0.0.0.0/0') reasons.push('gw_route_not_default');
  const nws = r.netwatch as WanNetwatchReading[];
  if (nws.length !== 1) reasons.push(nws.length === 0 ? 'no_netwatch' : 'two_netwatch');
  else if (params.probeHost !== null && nws[0].host.trim() !== params.probeHost) reasons.push('netwatch_host_mismatch');
  const members = r.wanMembers as WanMemberReading[];
  const lteName = r.lte?.name ?? WAN_LTE_DEFAULT_NAME;
  const enabledMember = (iface: string) => members.some((m) => m.interface === iface && !m.disabled);
  if (!enabledMember(WAN1_IF)) reasons.push('wan1_not_in_wan_list');
  if (!enabledMember(lteName)) reasons.push('lte_not_in_wan_list');
  if (reasons.length > 0) return { mode: null, reasons, params };

  const pppoe = (r.pppoeClients as WanPppoeClientReading[]).filter((c) => !c.disabled);
  const elsewhere = pppoe.filter((c) => c.interface !== WAN1_IF);
  const onWan1 = pppoe.filter((c) => c.interface === WAN1_IF);
  const dhcp = (r.dhcpClients as WanDhcpClientReading[]).filter((c) => !c.disabled);
  const stat = (r.staticAddrs as WanAddressReading[]).filter((a) => !a.disabled);
  if (elsewhere.length > 0) return { mode: null, reasons: ['pppoe_elsewhere'], params };
  if (onWan1.length > 1) return { mode: null, reasons: ['two_pppoe_clients'], params };
  const netwatchDisabled = nws[0].disabled;

  if (onWan1.length === 1) {
    const c = onWan1[0];
    params.pppoeName = c.name;
    params.pppoeUser = c.user;
    if (!isWan1PppoeName(c.name)) reasons.push('pppoe_name_not_standard');
    if (!probe.disabled || !gw[0].disabled) reasons.push('pppoe_routes_enabled');
    if (!netwatchDisabled) reasons.push('pppoe_netwatch_enabled');
    if (!enabledMember(c.name)) reasons.push('pppoe_not_in_wan_list');
    if (stat.length > 0) reasons.push('pppoe_and_static');
    return reasons.length > 0 ? { mode: null, reasons, params } : { mode: 'pppoe', reasons, params };
  }
  if (stat.length > 1) return { mode: null, reasons: ['two_static_addresses'], params };
  if (dhcp.length > 1) return { mode: null, reasons: ['two_dhcp_clients'], params };
  if (stat.length === 1 && dhcp.length === 1) return { mode: null, reasons: ['static_and_dhcp'], params };
  if (stat.length === 0 && dhcp.length === 0) return { mode: null, reasons: ['no_link'], params };
  // dhcp and static: NW-WAN1 enabled and the netwatch on (WAN1-GW's own flag
  // is the netwatch's to toggle).
  if (probe.disabled) reasons.push('probe_route_disabled');
  if (netwatchDisabled) reasons.push('netwatch_disabled');
  if (stat.length === 1) {
    const a = stat[0].address.trim();
    params.address = a;
    params.gateway = gw[0].gateway.trim();
    const p = legacyParseIpv4Prefix(a);
    if (!p || !a.includes('/')) reasons.push('static_address_unreadable');
    else if (!isIpv4(params.gateway) || legacyNetworkOf(`${params.gateway}/${p.len}`) !== legacyNetworkOf(a)) {
      reasons.push('static_gateway_outside');
    } else if (probe.gateway.trim() !== params.gateway) reasons.push('static_routes_differ');
    return reasons.length > 0 ? { mode: null, reasons, params } : { mode: 'static', reasons, params };
  }
  const d = dhcp[0];
  if (!isFalse(d.addDefaultRoute)) reasons.push('dhcp_adds_default_route');
  if (!d.stdScript) reasons.push('dhcp_script_not_standard');
  return reasons.length > 0 ? { mode: null, reasons, params } : { mode: 'dhcp', reasons, params };
}

// ============================================================================
// The 4G
// ============================================================================

export type LteReadiness = 'ready' | 'not_ready' | 'unknown';

export interface LteReadyVerdict {
  state: LteReadiness;
  /** Codes: why not ready / unknown. */
  reasons: string[];
  rsrp: number | null;
  sinr: number | null;
  registration: string | null;
}

/** The 4G must carry the store while the fixed link changes. An RSRP that was
 *  not read is `unknown` — never 0, never ready — and refuses. */
export function judgeLteReady(lte: WanLteReading | null): LteReadyVerdict {
  const base = { rsrp: lte?.rsrp ?? null, sinr: lte?.sinr ?? null, registration: lte?.registration ?? null };
  if (lte === null) return { state: 'unknown', reasons: ['lte_unread'], ...base };
  const notReady: string[] = [];
  if (!lte.present) return { state: 'not_ready', reasons: ['lte_absent'], ...base };
  if (lte.disabled) notReady.push('lte_disabled');
  if (!lte.running) notReady.push('lte_not_running');
  const reg = (lte.registration ?? '').trim().toLowerCase();
  if (lte.registration !== null && reg !== '' && reg !== 'registered' && reg !== 'roaming') notReady.push('lte_not_registered');
  if (lte.rsrp !== null && lte.rsrp < WAN_LINK_MIN_RSRP_DBM) notReady.push('lte_rsrp_low');
  if (lte.sinr !== null && lte.sinr < WAN_LINK_MIN_SINR_DB) notReady.push('lte_sinr_low');
  if (notReady.length > 0) return { state: 'not_ready', reasons: notReady, ...base };
  const unknown: string[] = [];
  if (lte.registration === null || reg === '') unknown.push('lte_registration_unread');
  if (lte.rsrp === null) unknown.push('lte_rsrp_unread');
  if (unknown.length > 0) return { state: 'unknown', reasons: unknown, ...base };
  return { state: 'ready', reasons: [], ...base };
}

/** A signal value as `monitor` prints it (`-95`, `-95dBm`, `12.5dB`); null
 *  when absent or unreadable. Never 0 standing in for "unknown". */
export function parseSignal(text: string | null | undefined): number | null {
  const t = (text ?? '').trim();
  const m = /^(-?\d{1,3}(?:\.\d{1,2})?)\s*(?:dBm|dB)?$/i.exec(t);
  if (!m) return null;
  const n = Number(m[1]);
  return Number.isFinite(n) ? n : null;
}

export type LteTakeoverState = 'via_lte' | 'not_via_lte' | 'unknown';

export interface LteTakeoverPath {
  target: string;
  source: 'connect_to' | 'resolved' | 'flow';
  route: string | null;
  interfaces: string[];
  state: LteTakeoverState;
  why: string;
}

export interface LteTakeoverVerdict {
  state: LteTakeoverState;
  paths: LteTakeoverPath[];
  summary: string;
}

function ipv4ToInt(ip: string): number | null {
  if (!isIpv4(ip)) return null;
  const parts = ip.split('.').map(Number);
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function prefixLenCovering(dst: string, ip: number): number | null {
  const m = /^([\d.]+)\/(\d{1,2})$/.exec(dst.trim());
  if (!m) return null;
  const net = ipv4ToInt(m[1]);
  const len = Number(m[2]);
  if (net === null || len > 32) return null;
  if (len === 0) return 0;
  const mask = maskOf(len);
  return ((ip & mask) >>> 0) === ((net & mask) >>> 0) ? len : null;
}

/**
 * Whether, once the script has failed over (route WAN1-GW disabled) and
 * retired the old link (`retired`: the old pppoe-client's name), the
 * management tunnel's addresses leave through the 4G. The addresses are
 * l2tp-mgmt's `connect-to` (or the router's own `:resolve` of it) and every
 * live L2TP flow. For each: the enabled main-table routes covering it, minus
 * WAN1-GW and any route through a retired interface; the longest prefix at
 * the lowest distance wins, inactive ones included (the 4G default route is
 * inactive until WAN1-GW goes). A winner through ether1-WAN1 or another fixed
 * interface is `not_via_lte`; one that names no listed interface is
 * `unknown`. Policy routing present or unread makes the whole verdict
 * `unknown`: the main table then does not say where the tunnel goes.
 */
export function judgeLteTakeover(
  egress: WanLinkReading['egress'],
  retired: readonly string[],
): LteTakeoverVerdict {
  if (egress === null) return { state: 'unknown', paths: [], summary: 'the routes could not be read' };
  if (egress.policyRules === null) return { state: 'unknown', paths: [], summary: 'whether policy routing is configured could not be read' };
  if (egress.policyRules > 0) {
    return { state: 'unknown', paths: [], summary: 'policy routing is configured: the main table does not say where the tunnel leaves' };
  }
  if (egress.routes === null) return { state: 'unknown', paths: [], summary: 'the routes could not be read' };
  if (egress.interfaces === null) return { state: 'unknown', paths: [], summary: 'the interface list could not be read' };
  const ifaces = new Set(egress.interfaces);
  const lte = new Set(egress.lteInterfaces);
  const isLte = (i: string) => lte.has(i) || /^lte/i.test(i);
  const retiredSet = new Set(retired);
  const mgmt = egress.l2tpClients.filter((c) => c.name === 'l2tp-mgmt' && !c.disabled);
  const targets: Array<{ target: string; source: LteTakeoverPath['source'] }> = [];
  for (const c of mgmt) {
    if (isIpv4(c.connectTo)) targets.push({ target: c.connectTo, source: 'connect_to' });
    else if (isIpv4(c.resolved)) targets.push({ target: c.resolved, source: 'resolved' });
  }
  for (const f of new Set(egress.l2tpFlows ?? [])) targets.push({ target: f, source: 'flow' });
  if (mgmt.length === 0) return { state: 'unknown', paths: [], summary: 'no enabled l2tp-client named l2tp-mgmt' };
  if (targets.length === 0) {
    return { state: 'unknown', paths: [], summary: 'l2tp-mgmt\'s concentrator did not resolve on the router and no live L2TP flow shows its address' };
  }
  const main = egress.routes.filter((r) => r.table === 'main' || r.table === '');
  const via = (r: WanEgressRoute): string[] | null =>
    interfacesOfGateway(r.immediateGw !== '' ? r.immediateGw : r.gateway, ifaces);
  const paths: LteTakeoverPath[] = [];
  for (const { target, source } of [...new Map(targets.map((t) => [t.target, t])).values()]) {
    const ip = ipv4ToInt(target) as number;
    const candidates = main.filter((r) => {
      if (r.comment === WAN_ROUTE_GW) return false;
      if (prefixLenCovering(r.dst, ip) === null) return false;
      const i = via(r);
      return !(i !== null && i.some((x) => retiredSet.has(x)));
    });
    if (candidates.length === 0) {
      paths.push({ target, source, route: null, interfaces: [], state: 'not_via_lte', why: 'no route would carry it once WAN1-GW is disabled' });
      continue;
    }
    const best = Math.max(...candidates.map((r) => prefixLenCovering(r.dst, ip) as number));
    const longest = candidates.filter((r) => prefixLenCovering(r.dst, ip) === best);
    if (longest.some((r) => !/^\d{1,3}$/.test(r.distance.trim()))) {
      paths.push({ target, source, route: longest.map((r) => r.dst).join(','), interfaces: [], state: 'unknown', why: 'a covering route printed no distance' });
      continue;
    }
    const dmin = Math.min(...longest.map((r) => Number(r.distance.trim())));
    const winners = longest.filter((r) => Number(r.distance.trim()) === dmin);
    const route = [...new Set(winners.map((r) => r.dst))].join(',');
    const per = winners.map(via);
    if (per.some((i) => i === null)) {
      paths.push({ target, source, route, interfaces: [], state: 'unknown', why: 'the gateway of the route that would carry it names no listed interface' });
      continue;
    }
    const interfaces = [...new Set((per as string[][]).flat())];
    const notLte = interfaces.filter((i) => !isLte(i));
    if (notLte.length > 0) {
      paths.push({ target, source, route, interfaces, state: 'not_via_lte', why: `it would leave through ${notLte.join(', ')}, not the 4G` });
      continue;
    }
    paths.push({ target, source, route, interfaces, state: 'via_lte', why: `it would leave through ${interfaces.join(', ')}` });
  }
  const describe = (p: LteTakeoverPath) => `${p.source === 'flow' ? 'L2TP flow' : 'l2tp-mgmt'} → ${p.target}: ${p.why}`;
  const bad = paths.filter((p) => p.state === 'not_via_lte');
  const unknown = paths.filter((p) => p.state === 'unknown');
  if (bad.length > 0) return { state: 'not_via_lte', paths, summary: bad.map(describe).join('; ') };
  if (unknown.length > 0) return { state: 'unknown', paths, summary: unknown.map(describe).join('; ') };
  return { state: 'via_lte', paths, summary: paths.map(describe).join('; ') };
}

// ============================================================================
// The plan
// ============================================================================

/** What the job froze at enqueue. */
export interface WanLinkFrozen {
  /** The mode the site declares (and the router must be in). */
  from: Wan1Mode;
  to: Wan1Mode;
  /** The target's non-secret parameters. */
  target: { pppoeName?: string | null; pppoeUser?: string | null; address?: string | null; gateway?: string | null };
  /** The FROM parameters the site declares, when it declares them: the router
   *  must match them too (a PPPoE name, a fixed address and gateway). */
  expect?: { pppoeName?: string | null; address?: string | null; gateway?: string | null };
  /** A PPPoE password typed for this job (not the vault's): a pppoe → pppoe
   *  job with the same name and user then rewrites the client — the router's
   *  password cannot be read, so "the same" cannot be established. */
  passwordTyped?: boolean;
}

export interface WanLinkRestore {
  nwGateway: string;
  nwDisabled: boolean;
  gwGateway: string;
  gwDisabled: boolean;
  netwatchDisabled: boolean;
}

export interface WanLinkSteps {
  retire: {
    /** The old pppoe-client: its member and itself disabled; renamed to
     *  `renameTo` in the same `set` when the new one takes its name. */
    pppoe: { name: string; renameTo: string | null } | null;
    /** The old fixed address, disabled. */
    staticAddress: string | null;
    /** Every DHCP client on ether1-WAN1 disabled (to static). */
    dhcpDisable: boolean;
  };
  install: {
    /** A disabled pppoe-client already holding the new name, out of its way. */
    leftoverRename: { from: string; to: string } | null;
    pppoe: { name: string; user: string } | null;
    /** The DHCP client on ether1-WAN1: added (the standard one), enabled, or left. */
    dhcp: 'add' | 'enable' | 'none';
    staticAddress: { address: string; mode: 'add' | 'enable' | 'none' } | null;
    /** Both routes re-pointed (static). */
    routeGateway: string | null;
    /** NW-WAN1 after the install: enabled (dhcp, static) or disabled (pppoe). */
    probeRoute: 'enable' | 'disable';
  };
  /** How the script knows the new link carries traffic. */
  up: Wan1Mode;
  /** WAN1-GW and the netwatch enabled once the new link is up (dhcp, static). */
  post: boolean;
  /** NW-WAN1, WAN1-GW and the netwatch as read: what the revert writes back. */
  restore: WanLinkRestore;
}

export interface WanLinkPlan {
  state: 'refused' | 'present' | 'needed';
  /** Code of the refusal, or null. */
  reason: string | null;
  /** Detail codes (classification reasons, a parameter that differs). */
  details: string[];
  from: Wan1Mode | null;
  to: Wan1Mode;
  observed: Wan1Classification;
  probeHost: string | null;
  /** The pppoe-client names the script retires (the takeover judge excludes
   *  them, the rollout's gate drops them from the baseline). */
  retiredInterfaces: string[];
  steps: WanLinkSteps | null;
  /** Never refusals (codes). */
  warnings: string[];
}

function refused(reason: string, details: string[], to: Wan1Mode, observed: Wan1Classification): WanLinkPlan {
  return {
    state: 'refused', reason, details, from: observed.mode, to, observed, probeHost: observed.params.probeHost,
    retiredInterfaces: [], steps: null, warnings: [],
  };
}

/**
 * The plan for one router, from what it reads now and what the job froze.
 * Refused when the router is not in the declared mode, when its parameters
 * are not the declared ones, or when what the script must write back could
 * not be read. `present` when the router already is the target with the same
 * non-secret parameters (a PPPoE password cannot be read, so a pppoe → pppoe
 * job with the same name and user is `present`: nothing is written).
 */
export function wanLinkPlan(reading: WanLinkReading, frozen: WanLinkFrozen, jobId: number): WanLinkPlan {
  const observed = classifyWan1(reading);
  const to = frozen.to;
  if (observed.mode === null) return refused('mode_not_standard', observed.reasons, to, observed);
  const p = observed.params;
  const t = frozen.target;
  // Already the target?
  const sameTarget =
    observed.mode === to &&
    (to === 'dhcp' ||
      (to === 'pppoe' && p.pppoeName === (t.pppoeName ?? null) && p.pppoeUser === (t.pppoeUser ?? null) &&
        !(frozen.from === 'pppoe' && frozen.passwordTyped === true)) ||
      (to === 'static' && p.address === (t.address ?? null) && p.gateway === (t.gateway ?? null)));
  if (sameTarget) {
    return {
      state: 'present', reason: null, details: [], from: observed.mode, to, observed, probeHost: p.probeHost,
      retiredInterfaces: [], steps: null, warnings: [],
    };
  }
  if (observed.mode !== frozen.from) return refused('mode_differs', [`router:${observed.mode}`, `declared:${frozen.from}`], to, observed);
  const e = frozen.expect ?? {};
  const differs: string[] = [];
  if (frozen.from === 'pppoe' && e.pppoeName && e.pppoeName !== p.pppoeName) differs.push('pppoe_name');
  if (frozen.from === 'static' && e.address && e.address !== p.address) differs.push('address');
  if (frozen.from === 'static' && e.gateway && e.gateway !== p.gateway) differs.push('gateway');
  if (differs.length > 0) return refused('params_differ', differs, to, observed);

  // Validate the target here too: the builder carries nothing unvalidated.
  if (to === 'pppoe') {
    if (!isWan1PppoeName(t.pppoeName)) return refused('target_invalid', ['pppoe_name'], to, observed);
    if (typeof t.pppoeUser !== 'string' || !WAN_PPPOE_USER_RE.test(t.pppoeUser)) return refused('target_invalid', ['pppoe_user'], to, observed);
  }
  if (to === 'static') {
    const why = validateStaticTarget(t.address ?? '', t.gateway ?? '');
    if (why) return refused('target_invalid', [why], to, observed);
  }
  const routes = reading.routes as WanRouteReading[];
  const nw = routes.find((r) => r.comment === WAN_ROUTE_PROBE) as WanRouteReading;
  const gw = routes.find((r) => r.comment === WAN_ROUTE_GW) as WanRouteReading;
  const netwatch = (reading.netwatch as WanNetwatchReading[])[0];
  if (!restorableGateway(nw.gateway.trim()) || !restorableGateway(gw.gateway.trim())) {
    return refused('restore_unreadable', ['route_gateway'], to, observed);
  }
  const restore: WanLinkRestore = {
    nwGateway: nw.gateway.trim(), nwDisabled: nw.disabled, gwGateway: gw.gateway.trim(), gwDisabled: gw.disabled,
    netwatchDisabled: netwatch.disabled,
  };
  const pppoeAll = reading.pppoeClients as WanPppoeClientReading[];
  const dhcpAll = reading.dhcpClients as WanDhcpClientReading[];
  const staticAll = reading.staticAddrs as WanAddressReading[];
  if (dhcpAll.length > 1) return refused('mode_not_standard', ['two_dhcp_clients'], to, observed);
  const from = observed.mode;
  const suffix = `-r${jobId}`;
  const retire: WanLinkSteps['retire'] = { pppoe: null, staticAddress: null, dhcpDisable: false };
  const install: WanLinkSteps['install'] = {
    leftoverRename: null, pppoe: null, dhcp: 'none', staticAddress: null, routeGateway: null, probeRoute: 'enable',
  };
  const retiredInterfaces: string[] = [];
  const dhcpClient = dhcpAll[0] ?? null;

  if (from === 'pppoe') {
    const old = p.pppoeName as string;
    const sameName = to === 'pppoe' && t.pppoeName === old;
    retire.pppoe = { name: old, renameTo: sameName ? `${old}${suffix}` : null };
    retiredInterfaces.push(old);
    if (sameName) retiredInterfaces.push(`${old}${suffix}`);
  }
  if (from === 'static' && !(to === 'static' && t.address === p.address)) retire.staticAddress = p.address;
  if (to === 'static' && dhcpClient && !dhcpClient.disabled) retire.dhcpDisable = true;

  if (to === 'pppoe') {
    const name = t.pppoeName as string;
    const holder = pppoeAll.find((c) => c.name === name && !(from === 'pppoe' && c.name === p.pppoeName));
    if (holder) {
      if (!holder.disabled) return refused('mode_not_standard', ['pppoe_name_taken'], to, observed);
      if (pppoeAll.some((c) => c.name === `${name}${suffix}`)) return refused('mode_not_standard', ['pppoe_name_taken'], to, observed);
      install.leftoverRename = { from: name, to: `${name}${suffix}` };
      retiredInterfaces.push(`${name}${suffix}`);
    }
    install.pppoe = { name, user: t.pppoeUser as string };
    install.probeRoute = 'disable';
    // The microcode keeps the DHCP client: one is there in pppoe mode.
    if (from !== 'pppoe') install.dhcp = dhcpClient === null ? 'add' : dhcpClient.disabled ? 'enable' : 'none';
  }
  if (to === 'dhcp') install.dhcp = dhcpClient === null ? 'add' : dhcpClient.disabled ? 'enable' : 'none';
  if (to === 'static') {
    const a = t.address as string;
    const same = staticAll.find((x) => x.address.trim() === a);
    install.staticAddress = { address: a, mode: same === undefined ? 'add' : same.disabled ? 'enable' : 'none' };
    install.routeGateway = t.gateway as string;
  }
  if (install.dhcp === 'add' && p.probeHost === null) return refused('restore_unreadable', ['probe_host'], to, observed);
  const warnings: string[] = [];
  // The old link stays on the router, disabled (operator decision 2026-10-07):
  // drift reports it until somebody removes it by hand.
  if (retire.pppoe || retire.staticAddress || retire.dhcpDisable) warnings.push('leftover_kept');
  return {
    state: 'needed',
    reason: null,
    details: [],
    from,
    to,
    observed,
    probeHost: p.probeHost,
    retiredInterfaces,
    steps: { retire, install, up: to, post: to !== 'pppoe', restore },
    warnings: [...new Set(warnings)],
  };
}

// ============================================================================
// The script
// ============================================================================

/** The hardened DHCP client's bound script (the templates', `; `-joined). */
export function wanDhcpScript(probeHost: string): string {
  if (!isIpv4(probeHost)) throw new WanLinkInputError('probe', 'Invalid probe host.');
  return `:if ($bound=1) do={ /ip/route/set [find where comment="${WAN_ROUTE_PROBE}"] dst-address=${probeHost}/32 gateway=$"gateway-address"; ` +
    `/ip/route/set [find where comment="${WAN_ROUTE_GW}"] dst-address=0.0.0.0/0 gateway=$"gateway-address" }`;
}

/** The standard DHCP client `add`, as the templates render it. */
export function wanDhcpAdd(probeHost: string): string {
  return `/ip dhcp-client add add-default-route=no comment="${WAN_DHCP_COMMENT}" disabled=no interface=${WAN1_IF} ` +
    `use-peer-dns=no use-peer-ntp=no script=${routerOsScriptLiteral(wanDhcpScript(probeHost))}`;
}

const q = (s: string): string => `"${s}"`;
const SAFE_TOKEN_RE = /^[A-Za-z0-9._@+/:-]{1,80}$/;
function assertToken(field: string, v: string): void {
  if (!SAFE_TOKEN_RE.test(v)) throw new WanLinkInputError(field, `The ${field} holds characters outside the job's safe set.`);
}

/** The FROM mode, re-checked at cut time: sets `$okfrom`. */
function fromSignature(plan: WanLinkPlan): string {
  const w = q(WAN1_IF);
  const noPppoe = `[:len [/interface pppoe-client find where interface=${w} and disabled=no]] = 0`;
  const noDhcp = `[:len [/ip dhcp-client find where interface=${w} and disabled=no]] = 0`;
  const noStatic = `[:len [/ip address find where interface=${w} and dynamic=no and disabled=no]] = 0`;
  const all = (conds: string[]): string =>
    conds.reduceRight((inner, c) => `:if (${c}) do={ ${inner} }`, ':set okfrom true');
  switch (plan.from) {
    case 'dhcp':
      return all([`[:len [/ip dhcp-client find where interface=${w} and disabled=no]] = 1`, noPppoe, noStatic]);
    case 'pppoe': {
      const old = plan.observed.params.pppoeName as string;
      return all([
        `[:len [/interface pppoe-client find where interface=${w} and disabled=no and name=${q(old)}]] = 1`,
        `[:len [/interface pppoe-client find where interface=${w} and disabled=no]] = 1`,
      ]);
    }
    case 'static': {
      const a = plan.observed.params.address as string;
      return all([
        `[:len [/ip address find where interface=${w} and dynamic=no and disabled=no and address=${q(a)}]] = 1`,
        noDhcp,
        noPppoe,
      ]);
    }
    default:
      throw new WanLinkInputError('plan', 'No FROM mode.');
  }
}

interface ScriptParts {
  prelude: string[];
  failover: string[];
  forward: string[];
  up: string;
  post: string[];
  revert: string[];
}

function parts(plan: WanLinkPlan, jobId: number, revertAfterS: number): ScriptParts {
  if (plan.state !== 'needed' || !plan.steps || plan.from === null) throw new WanLinkInputError('plan', 'Nothing to write.');
  if (!Number.isInteger(jobId) || jobId <= 0) throw new WanLinkInputError('job', 'Invalid job id.');
  if (!wanLinkRevertAfterValid(revertAfterS)) throw new WanLinkInputError('delay', 'Invalid self-revert delay.');
  const s = plan.steps;
  const P = plan.probeHost;
  if (P === null || !isIpv4(P)) throw new WanLinkInputError('probe', 'Invalid probe host.');
  const w = q(WAN1_IF);
  for (const v of [s.restore.nwGateway, s.restore.gwGateway]) {
    if (!restorableGateway(v)) throw new WanLinkInputError('gateway', 'A route gateway the job cannot write back.');
  }
  const prefix = wanLinkLogPrefix(jobId);
  const prelude = [
    `:local tag ${q(prefix)}`,
    ':local up false',
    ':local t 0',
    ':local okfrom false',
    `:delay ${WAN_LINK_ARM_LEAD_S}s`,
    `:log info ($tag . " START ${plan.from}->${plan.to}")`,
    `:local lte [/interface lte find where default-name=${q(WAN_LTE_DEFAULT_NAME)}]`,
    ':if ([:len $lte] != 1) do={ :log warning ($tag . " ABANDONED no lte1, nothing changed"); :error "abandoned" }',
    ':if ([/interface lte get $lte running] != true) do={ :log warning ($tag . " ABANDONED lte1 not running, nothing changed"); :error "abandoned" }',
    fromSignature(plan),
    `:if ($okfrom != true) do={ :log warning ($tag . " ABANDONED WAN1 is no longer ${plan.from}, nothing changed"); :error "abandoned" }`,
  ];
  const failover = [
    `/tool netwatch disable [find where comment=${q(WAN_NETWATCH)}]`,
    `/ip route disable [find where comment=${q(WAN_ROUTE_GW)}]`,
  ];
  const fwd: string[] = [];
  const rev: string[] = [];
  const member = (iface: string) => `[find where list=${q(WAN_LIST)} and interface=${q(iface)}]`;

  // RETIRE — disabled, never removed.
  if (s.retire.pppoe) {
    const { name, renameTo } = s.retire.pppoe;
    assertToken('pppoe name', name);
    fwd.push(`/interface list member disable ${member(name)}`);
    fwd.push(`/interface pppoe-client set [find where name=${q(name)}] disabled=yes${renameTo ? ` name=${q(renameTo)}` : ''}`);
  }
  if (s.retire.staticAddress) {
    assertToken('address', s.retire.staticAddress);
    fwd.push(`/ip address disable [find where interface=${w} and dynamic=no and address=${q(s.retire.staticAddress)}]`);
  }
  if (s.retire.dhcpDisable) fwd.push(`/ip dhcp-client disable [find where interface=${w}]`);

  // INSTALL
  const i = s.install;
  if (i.leftoverRename) {
    assertToken('pppoe name', i.leftoverRename.to);
    fwd.push(`/interface pppoe-client set [find where name=${q(i.leftoverRename.from)}] name=${q(i.leftoverRename.to)}`);
  }
  if (i.pppoe) {
    assertToken('pppoe name', i.pppoe.name);
    if (!WAN_PPPOE_USER_RE.test(i.pppoe.user)) throw new WanLinkInputError('pppoe user', 'Invalid PPPoE user.');
    fwd.push(
      `/interface pppoe-client add interface=${WAN1_IF} name=${q(i.pppoe.name)} user=${q(i.pppoe.user)} ` +
        `password=${q(WAN_PPPOE_PASSWORD_PLACEHOLDER)} add-default-route=yes disabled=no`,
    );
    fwd.push(`/interface list member add list=${WAN_LIST} interface=${q(i.pppoe.name)}`);
  }
  if (i.dhcp === 'add') fwd.push(wanDhcpAdd(P));
  if (i.dhcp === 'enable') fwd.push(`/ip dhcp-client enable [find where interface=${w}]`);
  if (i.staticAddress) {
    assertToken('address', i.staticAddress.address);
    if (i.staticAddress.mode === 'add') fwd.push(`/ip address add address=${i.staticAddress.address} interface=${WAN1_IF}`);
    if (i.staticAddress.mode === 'enable') {
      fwd.push(`/ip address enable [find where interface=${w} and dynamic=no and address=${q(i.staticAddress.address)}]`);
    }
  }
  if (i.routeGateway) {
    if (!isIpv4(i.routeGateway)) throw new WanLinkInputError('gateway', 'Invalid gateway.');
    fwd.push(`/ip route set [find where comment=${q(WAN_ROUTE_PROBE)}] gateway=${i.routeGateway}`);
    fwd.push(`/ip route set [find where comment=${q(WAN_ROUTE_GW)}] gateway=${i.routeGateway}`);
  }
  fwd.push(`/ip route ${i.probeRoute} [find where comment=${q(WAN_ROUTE_PROBE)}]`);

  // REVERT — the inverse of every forward statement, in reverse order, each
  // on its own (one that fails does not stop the others), then the routes
  // and the netwatch as read.
  if (i.staticAddress?.mode === 'add') rev.push(`/ip address remove [find where interface=${w} and dynamic=no and address=${q(i.staticAddress.address)}]`);
  if (i.staticAddress?.mode === 'enable') rev.push(`/ip address disable [find where interface=${w} and dynamic=no and address=${q(i.staticAddress.address)}]`);
  if (i.dhcp === 'add') rev.push(`/ip dhcp-client remove [find where interface=${w} and comment=${q(WAN_DHCP_COMMENT)}]`);
  if (i.dhcp === 'enable') rev.push(`/ip dhcp-client disable [find where interface=${w}]`);
  if (i.pppoe) {
    rev.push(`/interface list member remove ${member(i.pppoe.name)}`);
    rev.push(`/interface pppoe-client remove [find where name=${q(i.pppoe.name)}]`);
  }
  if (i.leftoverRename) rev.push(`/interface pppoe-client set [find where name=${q(i.leftoverRename.to)}] name=${q(i.leftoverRename.from)}`);
  if (s.retire.dhcpDisable) rev.push(`/ip dhcp-client enable [find where interface=${w}]`);
  if (s.retire.staticAddress) rev.push(`/ip address enable [find where interface=${w} and dynamic=no and address=${q(s.retire.staticAddress)}]`);
  if (s.retire.pppoe) {
    const { name, renameTo } = s.retire.pppoe;
    rev.push(`/interface pppoe-client set [find where name=${q(renameTo ?? name)}] disabled=no${renameTo ? ` name=${q(name)}` : ''}`);
    rev.push(`/interface list member enable ${member(name)}`);
  }
  const yn = (b: boolean) => (b ? 'yes' : 'no');
  rev.push(`/ip route set [find where comment=${q(WAN_ROUTE_PROBE)}] gateway=${s.restore.nwGateway} disabled=${yn(s.restore.nwDisabled)}`);
  rev.push(`/ip route set [find where comment=${q(WAN_ROUTE_GW)}] gateway=${s.restore.gwGateway} disabled=${yn(s.restore.gwDisabled)}`);
  rev.push(`/tool netwatch set [find where comment=${q(WAN_NETWATCH)}] disabled=${yn(s.restore.netwatchDisabled)}`);

  // UP — through WAN1, never through the 4G: NW-WAN1 (the probe host /32) is
  // active only when its gateway sits on WAN1; the PPPoE ping names its
  // interface. Each ping counts its own seconds.
  const ping = (iface: string | null) =>
    `:if ([/ping ${P} count=3${iface ? ` interface=${q(iface)}` : ''}] > 0) do={ :set up true }; :set t ($t + ${WAN_LINK_PING_S})`;
  const nwActive = `[:len [/ip route find where comment=${q(WAN_ROUTE_PROBE)} and active=yes]] = 1`;
  let up: string;
  if (s.up === 'pppoe') {
    const name = (i.pppoe as { name: string }).name;
    up = `:do { :if ([/interface pppoe-client get [find where name=${q(name)}] running] = true) do={ ${ping(name)} } } on-error={}`;
  } else if (s.up === 'dhcp') {
    up = `:do { :if ([/ip dhcp-client get [find where interface=${w} and disabled=no] status] = "bound") do={ ` +
      `:if (${nwActive}) do={ ${ping(null)} } } } on-error={}`;
  } else {
    up = `:do { :if (${nwActive}) do={ ${ping(null)} } } on-error={}`;
  }
  const post = s.post
    ? [`/ip route enable [find where comment=${q(WAN_ROUTE_GW)}]`, `/tool netwatch enable [find where comment=${q(WAN_NETWATCH)}]`]
    : [];
  return { prelude, failover, forward: fwd, up, post, revert: rev.map((x) => `:do { ${x} } on-error={}`) };
}

/**
 * The script `:execute` runs, as ONE line (`; `-joined). The PPPoE password
 * is the placeholder; the server splices the plaintext in last.
 */
export function wanLinkScriptSource(plan: WanLinkPlan, jobId: number, revertAfterS: number): string {
  const p = parts(plan, jobId, revertAfterS);
  const revert = p.revert.join('; ');
  const wait = `:while (($up != true) && ($t < ${revertAfterS})) do={ :delay ${WAN_LINK_UP_POLL_S}s; :set t ($t + ${WAN_LINK_UP_POLL_S}); ${p.up} }`;
  const decide =
    `:if ($up = true) do={ ${[...p.post, ':log info ($tag . " APPLIED new link up after " . $t . " s")'].join('; ')} } ` +
    `else={ ${revert}; :log warning ($tag . " REVERTED new link not up after ${revertAfterS} s") }`;
  return [
    ...p.prelude,
    ...p.failover,
    `:do { ${p.forward.join('; ')} } on-error={ ${revert}; :log warning ($tag . " REVERTED a forward step failed"); :error "reverted" }`,
    wait,
    decide,
  ].join('; ');
}

/** The one line the job sends: start the script in the background and print
 *  its job id (`revertjob|<id>`, the self-revert's tag, so the legacy readers
 *  apply unchanged). */
export function wanLinkExecuteLine(source: string): string {
  return `:put ("${LEGACY_GUARD_JOB_TAG}|" . [:execute script=${routerOsScriptLiteral(source)}])`;
}

export function wanLinkLine(plan: WanLinkPlan, jobId: number, revertAfterS: number): string {
  return wanLinkExecuteLine(wanLinkScriptSource(plan, jobId, revertAfterS));
}

// ============================================================================
// The allow-list
// ============================================================================

export class WanLinkLineRefused extends Error {
  constructor(readonly offending: string[]) {
    super(`Refused WAN link line: ${offending.join(' | ').slice(0, 400)}`);
    this.name = 'WanLinkLineRefused';
  }
}

/** Undo `routerOsScriptLiteral` on `"…"`; null when it is not one. */
function unquote(lit: string): string | null {
  if (!lit.startsWith('"') || !lit.endsWith('"') || lit.length < 2) return null;
  let out = '';
  const body = lit.slice(1, -1);
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c === '\\') {
      const n = body[i + 1];
      if (n === undefined || !'\\"$?'.includes(n)) return null;
      out += n;
      i++;
    } else if (c === '"') {
      return null;
    } else out += c;
  }
  return out;
}

/** Forbidden anywhere in the decoded script (lower-cased). */
const FORBIDDEN_TOKENS = [
  'random-source-port', 'l2tp-client', 'mac-server', 'mac-winbox', 'romon', '/ip service', '/user', '/ip firewall',
  '/ip dns', '/system', '/file', '/import', '/export', 'apn', '/interface lte set', '/interface lte apn', ':execute',
  '/interface ethernet', '/ip ipsec', '/ppp', '/interface bridge', '/interface wireless', '/interface wifi',
];

/** Every `/menu verb` the script may hold (verbs per menu). */
const ALLOWED_MENU_VERBS: Record<string, readonly string[]> = {
  'interface lte': ['find', 'get'],
  'interface pppoe-client': ['find', 'get', 'add', 'set', 'remove'],
  'interface list member': ['find', 'add', 'enable', 'disable', 'remove'],
  'ip dhcp-client': ['find', 'get', 'add', 'enable', 'disable', 'remove'],
  'ip address': ['find', 'add', 'enable', 'disable', 'remove'],
  'ip route': ['find', 'set', 'enable', 'disable'],
  'tool netwatch': ['set', 'enable', 'disable'],
};

/**
 * The allow-list, judged on the REDACTED line (the placeholder in place):
 *  1. it is exactly the line this plan builds for this job (nothing appended,
 *     nothing mutated after building);
 *  2. spelled independently of the builder: the decoded script names no
 *     forbidden token, every `/menu verb` is one of the WAN1 objects' own,
 *     the only nested literal is the standard DHCP script for the probe host,
 *     the failover comes after the ABANDONED checks and before any write, and
 *     every revert restores NW-WAN1, WAN1-GW and the netwatch;
 *  3. the placeholder, when present, sits only in the one pppoe-client add.
 * Throws `WanLinkLineRefused`.
 */
export function assertWanLinkOnlyLines(line: string, plan: WanLinkPlan, jobId: number, revertAfterS: number): void {
  const offending: string[] = [];
  let expected: string | null = null;
  try {
    expected = wanLinkLine(plan, jobId, revertAfterS);
  } catch (err) {
    offending.push(`(no line for this plan: ${err instanceof Error ? err.message : String(err)})`);
  }
  if (expected !== null && line !== expected) offending.push('(not the line this plan builds)');
  const m = /^:put \("revertjob\|" \. \[:execute script=(".*")\]\)$/.exec(line);
  const src = m ? unquote(m[1]) : null;
  if (src === null) {
    offending.push('(not one :execute of one script literal)');
    throw new WanLinkLineRefused(offending);
  }
  // The one nested literal: the standard DHCP script.
  let flat = src;
  const nested = [...src.matchAll(/script=("(?:[^"\\]|\\.)*")/g)];
  for (const n of nested) {
    const inner = unquote(n[1]);
    if (inner === null || plan.probeHost === null || inner !== wanDhcpScript(plan.probeHost)) offending.push('(a nested script that is not the standard DHCP script)');
    flat = flat.replace(n[0], 'script=<dhcp>');
  }
  // Menus and forbidden tokens are judged outside the quoted strings: a
  // PPPoE login may hold a slash, a log message any word.
  const bare = flat.replace(/"(?:[^"\\]|\\.)*"/g, '""');
  const lower = bare.toLowerCase();
  for (const tok of FORBIDDEN_TOKENS) if (lower.includes(tok)) offending.push(`(forbidden: ${tok})`);
  const prefix = wanLinkLogPrefix(jobId);
  if (!flat.startsWith(`:local tag "${prefix}"`)) offending.push('(the script does not start with its log tag)');
  for (const mm of bare.matchAll(/\/([a-z][a-z0-9-]*)((?: [a-z][a-z0-9-]*){0,3})/g)) {
    const words = [mm[1], ...mm[2].split(' ').filter((x) => x !== '')];
    if (words[0] === 'ping') continue;
    let menu: string | null = null;
    let verb: string | null = null;
    for (const k of [3, 2]) {
      const cand = words.slice(0, k).join(' ');
      if (ALLOWED_MENU_VERBS[cand] && words[k] !== undefined) {
        menu = cand;
        verb = words[k];
        break;
      }
    }
    if (menu === null || verb === null || !ALLOWED_MENU_VERBS[menu].includes(verb)) offending.push(`(menu or verb outside the WAN1 objects: /${words.join(' ')})`);
  }
  const abandonAt = flat.lastIndexOf('ABANDONED');
  const failoverAt = flat.indexOf(`/tool netwatch disable [find where comment="${WAN_NETWATCH}"]; /ip route disable [find where comment="${WAN_ROUTE_GW}"]`);
  const firstWrite = flat.search(/\/(interface pppoe-client (add|set|remove)|interface list member (add|disable|remove)|ip dhcp-client (add|enable|disable|remove)|ip address (add|enable|disable|remove))/);
  if (abandonAt < 0 || flat.split('ABANDONED').length - 1 < 3) offending.push('(the ABANDONED checks are missing)');
  if (failoverAt < 0 || failoverAt < abandonAt) offending.push('(the failover is missing or before the ABANDONED checks)');
  if (firstWrite >= 0 && failoverAt >= 0 && firstWrite < failoverAt) offending.push('(a write before the failover)');
  const restores = [
    new RegExp(`:do \\{ /ip route set \\[find where comment="${WAN_ROUTE_PROBE}"\\] gateway=[^ ]+ disabled=(yes|no) \\} on-error=\\{\\}`, 'g'),
    new RegExp(`:do \\{ /ip route set \\[find where comment="${WAN_ROUTE_GW}"\\] gateway=[^ ]+ disabled=(yes|no) \\} on-error=\\{\\}`, 'g'),
    new RegExp(`:do \\{ /tool netwatch set \\[find where comment="${WAN_NETWATCH}"\\] disabled=(yes|no) \\} on-error=\\{\\}`, 'g'),
  ];
  for (const re of restores) if ((flat.match(re) ?? []).length !== 2) offending.push('(a revert does not restore NW-WAN1, WAN1-GW and the netwatch)');
  if (!/REVERTED new link not up/.test(flat) || !/REVERTED a forward step failed/.test(flat)) offending.push('(a revert branch is missing)');
  const placeholders = flat.split(WAN_PPPOE_PASSWORD_PLACEHOLDER).length - 1;
  if (placeholders > 1 || (placeholders === 1 && !/\/interface pppoe-client add [^;]*password="__OBLIWAN_SECRET_WAN1_PPPOE_PASSWORD__"/.test(flat))) {
    offending.push('(the password placeholder outside the pppoe-client add)');
  }
  if (/__OBLIWAN_SECRET_(?!WAN1_PPPOE_PASSWORD__)/.test(flat)) offending.push('(another secret placeholder)');
  if (offending.length > 0) throw new WanLinkLineRefused([...new Set(offending)]);
}

// ============================================================================
// The script's log
// ============================================================================

export type WanLinkLogVerdict = 'applied' | 'reverted' | 'abandoned' | 'started' | 'none';

/** The script's decision from its log lines (`log|<message>` rows). */
export function parseWanLinkLog(out: string, jobId: number): { verdict: WanLinkLogVerdict; lines: string[] } {
  const prefix = wanLinkLogPrefix(jobId);
  const found = out
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.startsWith('log|') && l.includes(prefix))
    .map((l) => l.slice(4));
  const has = (verb: string) => found.some((l) => l.includes(`${prefix} ${verb}`));
  const verdict: WanLinkLogVerdict = has('APPLIED')
    ? 'applied'
    : has('REVERTED')
      ? 'reverted'
      : has('ABANDONED')
        ? 'abandoned'
        : has('START')
          ? 'started'
          : 'none';
  return { verdict, lines: found };
}

/** Whether the target holds on a reading: the mode classified, the non-secret
 *  parameters equal, and the new link up (pppoe running, dhcp bound, NW-WAN1
 *  active through WAN1). */
export function wanLinkTargetHolds(reading: WanLinkReading, frozen: WanLinkFrozen): boolean | null {
  const c = classifyWan1(reading);
  if (c.mode === null) return c.reasons.some((r) => r.startsWith('unread:')) ? null : false;
  if (c.mode !== frozen.to) return false;
  const t = frozen.target;
  const routes = reading.routes ?? [];
  const nwActive = routes.some((r) => r.comment === WAN_ROUTE_PROBE && r.active && !r.disabled);
  switch (frozen.to) {
    case 'pppoe': {
      if (c.params.pppoeName !== t.pppoeName || c.params.pppoeUser !== t.pppoeUser) return false;
      const client = (reading.pppoeClients ?? []).find((x) => x.name === t.pppoeName && !x.disabled);
      return client?.running === true;
    }
    case 'dhcp': {
      const d = (reading.dhcpClients ?? []).find((x) => !x.disabled);
      return d !== undefined && d.status.trim().toLowerCase() === 'bound' && nwActive;
    }
    case 'static':
      return c.params.address === t.address && c.params.gateway === t.gateway && nwActive;
    default:
      return false;
  }
}

/** Whether the FROM configuration is back (a revert or an abandon). */
export function wanLinkFromHolds(reading: WanLinkReading, before: Wan1Classification): boolean | null {
  const c = classifyWan1(reading);
  if (c.mode === null) return c.reasons.some((r) => r.startsWith('unread:')) ? null : false;
  if (c.mode !== before.mode) return false;
  const a = c.params;
  const b = before.params;
  return a.pppoeName === b.pppoeName && a.pppoeUser === b.pppoeUser && a.address === b.address && a.gateway === b.gateway;
}
