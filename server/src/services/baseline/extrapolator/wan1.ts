// ============================================================================
// Brick 10 — WAN1: the standard block of the store templates, read off routers
// ============================================================================
//
// Every hand-made store template carries the same WAN1 block
// (operator templates): six site variables — `wan1_mode`
// (dhcp | pppoe | static, default dhcp), `wan1_pppoe_name` (ADSL | FTTH |
// FTTO), `wan1_pppoe_username`, `wan1_pppoe_password` (secret),
// `wan1_address`, `wan1_gateway` — and a body whose WAN lines depend on the
// mode:
//
//   dhcp    the DHCP client on ether1-WAN1 repoints the NW-WAN1 / WAN1-GW
//           routes; the WAN1 netwatch fails them over to LTE;
//   pppoe   the production microcode: a PPPoE client on ether1-WAN1 (or a VLAN
//           over it — FTTH rides VLAN 832), a member of the WAN list, the two
//           routes and the WAN1 netwatch DISABLED, the DHCP client KEPT;
//   static  ONE fixed address on ether1-WAN1, the two routes through its
//           gateway, NO DHCP client, the netwatch kept.
//
// The extrapolator used to know none of it: in a fleet mixing the three, the
// PPPoE and fixed-IP stores came out as per-site deviations or literals, and
// the template could not reproduce them. This file is the extrapolator's
// knowledge of that block — PURE, no database, no render:
//
//   classifyWan1     the learning mode's own reading of a router's WAN1
//                    (siteFacts.ts calls it: one classifier, not two);
//   assessWan1Site   whether a router carries the standard block, in which
//                    mode, with which values — or the named reason it does not;
//   planWan1Cluster  whether a cluster's proposal emits the block at all;
//   wan1LinesOf      the WAN1 lines of an export, for the reproduction proof.
//
// ┌─ WHAT THIS FILE WILL NOT DO ──────────────────────────────────────────────┐
// │ 1. FORCE A MODE. A router whose WAN1 is not the standard block (no        │
// │    uplink, two clients, a PPPoE on a VLAN not named vlan<id>, a route     │
// │    left active beside a PPPoE…) gets NO wan1_* value, and its WAN lines  │
// │    are reported, never templated — the reason is named.                  │
// │ 2. READ A PASSWORD. The PPPoE password is declared secret and never      │
// │    valued: the redacted export never carries it.                         │
// │ 3. GUESS A PROBE. The only conditioned probes the extrapolator may emit  │
// │    are the standard ones below, compared key by key.                     │
// └───────────────────────────────────────────────────────────────────────────┘

import { isDeepStrictEqual } from 'util';
import type { LearnedWan1Mode } from '@obliwan/shared';
import { PPPOE_UPLINK_NAMES, WAN_LIST_NAME } from '../../plan/uplinkGuard';
import { displayLine, propValue, type ExportEntry } from './exportText';

// ============================================================================
// The learning classifier (siteFacts semantics, one implementation)
// ============================================================================

function truthy(v: string | undefined): boolean {
  return v === 'yes' || v === 'true';
}

function ipToInt(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim());
  if (!m) return null;
  const o = m.slice(1, 5).map(Number);
  if (o.some((x) => x > 255)) return null;
  return ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3];
}

function intToIp(n: number): string {
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

function covers(cidr: string, ip: string): boolean {
  const [addr, len] = cidr.split('/');
  const a = ipToInt(addr ?? '');
  const b = ipToInt(ip);
  const prefix = Number(len);
  if (a === null || b === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return ((a & mask) >>> 0) === ((b & mask) >>> 0);
}

function isDefaultRoute(e: ExportEntry): boolean {
  const dst = propValue(e, 'dst-address');
  return dst === undefined || dst === '0.0.0.0/0';
}

function entriesOf(entries: readonly ExportEntry[], path: string, verb?: string): ExportEntry[] {
  return entries.filter((e) => e.path === path && e.verb !== 'opaque' && (verb === undefined || e.verb === verb));
}

export interface Wan1Classification {
  /** The name given to the port whose default-name is ether1. */
  port: string;
  /** The port and the VLANs carried on it (an FTTH PPPoE rides VLAN 832). */
  onPort: ReadonlySet<string>;
  /** `/interface/vlan add` entries whose interface is the port. */
  vlans: ExportEntry[];
  /** Interfaces listed in the WAN interface list (uncapped). */
  wanList: string[];
  /** Every `/interface/pppoe-client add`. */
  pppoeAll: ExportEntry[];
  /** Enabled PPPoE clients on the port or a VLAN over it. */
  pppoeOn: ExportEntry[];
  /** Enabled DHCP clients on the port or a VLAN over it. */
  dhcpOn: ExportEntry[];
  /** Enabled addresses on the port or a VLAN over it. */
  staticOn: ExportEntry[];
  /** `/ip/route add` entries to 0.0.0.0/0 (or with no destination). */
  defaults: ExportEntry[];
  mode: LearnedWan1Mode;
  pppoeName: string | null;
  staticAddress: string | null;
  staticGateway: string | null;
}

/**
 * The learning mode's reading of WAN1 (`learnedSiteFacts().wan1`), with the
 * entries it read. Never throws: what it cannot read is `none`.
 */
export function classifyWan1(entries: readonly ExportEntry[]): Wan1Classification {
  let port = 'ether1';
  for (const e of entriesOf(entries, '/interface/ethernet', 'set')) {
    if (/(^| )default-name=ether1( |$)/.test(e.selectorCanon)) {
      port = propValue(e, 'name') ?? 'ether1';
      break;
    }
  }
  const onPort = new Set<string>([port]);
  const vlans: ExportEntry[] = [];
  for (const v of entriesOf(entries, '/interface/vlan', 'add')) {
    if (propValue(v, 'interface') === port) {
      vlans.push(v);
      const n = propValue(v, 'name');
      if (n) onPort.add(n);
    }
  }

  const wanList = entriesOf(entries, '/interface/list/member', 'add')
    .filter((e) => (propValue(e, 'list') ?? '').toUpperCase() === WAN_LIST_NAME)
    .map((e) => propValue(e, 'interface'))
    .filter((n): n is string => !!n);

  const pppoeAll = entriesOf(entries, '/interface/pppoe-client', 'add');
  const pppoeOn = pppoeAll.filter((e) => {
    const iface = propValue(e, 'interface');
    return !truthy(propValue(e, 'disabled')) && iface !== undefined && onPort.has(iface);
  });
  const dhcpOn = entriesOf(entries, '/ip/dhcp-client', 'add').filter((e) => {
    const iface = propValue(e, 'interface');
    return !truthy(propValue(e, 'disabled')) && iface !== undefined && onPort.has(iface);
  });
  const staticOn = entriesOf(entries, '/ip/address', 'add').filter((e) => {
    const iface = propValue(e, 'interface');
    return !truthy(propValue(e, 'disabled')) && iface !== undefined && onPort.has(iface);
  });

  const defaults = entriesOf(entries, '/ip/route', 'add').filter(isDefaultRoute);

  let mode: LearnedWan1Mode = 'none';
  let pppoeName: string | null = null;
  let staticAddress: string | null = null;
  let staticGateway: string | null = null;
  const kinds = (pppoeOn.length > 0 ? 1 : 0) + (dhcpOn.length > 0 ? 1 : 0);
  if (kinds > 1 || pppoeOn.length > 1 || dhcpOn.length > 1) {
    mode = 'ambiguous';
  } else if (pppoeOn.length === 1) {
    mode = 'pppoe';
    pppoeName = propValue(pppoeOn[0], 'name') || null;
  } else if (dhcpOn.length === 1) {
    mode = 'dhcp';
  } else if (staticOn.length > 0) {
    const withGateway = staticOn.map((e) => {
      const address = propValue(e, 'address') ?? '';
      const gw = defaults
        .map((r) => propValue(r, 'gateway') ?? '')
        .find((g) => ipToInt(g) !== null && covers(address, g));
      return { address, gateway: gw ?? null };
    });
    const covered = withGateway.filter((s) => s.gateway !== null);
    if (staticOn.length === 1 || covered.length === 1) {
      const pick = covered.length === 1 ? covered[0] : withGateway[0];
      mode = 'static';
      staticAddress = pick.address || null;
      staticGateway = pick.gateway;
    } else {
      mode = 'ambiguous';
    }
  }
  return {
    port, onPort, vlans, wanList, pppoeAll, pppoeOn, dhcpOn, staticOn, defaults,
    mode, pppoeName, staticAddress, staticGateway,
  };
}

// ============================================================================
// The standard block's vocabulary
// ============================================================================

export const WAN1_PORT = 'ether1-WAN1';
export const WAN1_ROUTE_NW = 'NW-WAN1';
export const WAN1_ROUTE_GW = 'WAN1-GW';
export const WAN1_NETWATCH_COMMENT = 'WAN1';

export const WAN1_KEYS = {
  mode: 'wan1_mode',
  pppoeName: 'wan1_pppoe_name',
  pppoeUsername: 'wan1_pppoe_username',
  pppoePassword: 'wan1_pppoe_password',
  address: 'wan1_address',
  gateway: 'wan1_gateway',
  /** Not one of the six: declared only when a router of the cluster carries
   *  its PPPoE client on a VLAN of ether1-WAN1. */
  vlanId: 'wan1_pppoe_vlan_id',
} as const;

export const WAN1_MODES = ['dhcp', 'pppoe', 'static'] as const;
export type Wan1Mode = (typeof WAN1_MODES)[number];

/** The lines of the block, by what they do. */
export type Wan1Role = 'pppoe' | 'member' | 'vlan' | 'static' | 'dhcp' | 'routeNW' | 'routeGW' | 'netwatch';

/** The declarations' patterns (same in the five operator templates).
 *  `{0,1}`, never `?`: the same text may one day reach a knex `raw()`. */
const OCTET = '(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]{0,1}[0-9])';
export const WAN1_ADDRESS_PATTERN = `^${OCTET}(\\.${OCTET}){3}/([89]|[12][0-9]|3[0-2])$`;
export const WAN1_GATEWAY_PATTERN = `^${OCTET}(\\.${OCTET}){3}$`;
export const WAN1_USERNAME_PATTERN = '^[A-Za-z0-9._@+/-]{1,64}$';
export const WAN1_VLAN_ID_PATTERN = '^([1-9][0-9]{0,2}|[1-3][0-9]{3}|40[0-8][0-9]|409[0-4])$';
const ADDRESS_RE = new RegExp(WAN1_ADDRESS_PATTERN);
const GATEWAY_RE = new RegExp(WAN1_GATEWAY_PATTERN);
const USERNAME_RE = new RegExp(WAN1_USERNAME_PATTERN);
const VLAN_ID_RE = new RegExp(WAN1_VLAN_ID_PATTERN);

/** The network address of an IPv4 CIDR (`203.0.113.10/29` -> `203.0.113.8`). */
export function networkOf(cidr: string): string | null {
  const [addr, len] = cidr.split('/');
  const a = ipToInt(addr ?? '');
  const prefix = Number(len);
  if (a === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return intToIp((a & mask) >>> 0);
}

/**
 * The render refusals of the standard block, judged here so a router whose
 * values the block would refuse is excluded with that reason instead of
 * scoring 0 in the proof. Null = the pair renders.
 */
export function staticPairProblem(address: string, gateway: string): string | null {
  if (!ADDRESS_RE.test(address)) {
    return `l'adresse fixe « ${address} » n'est pas une adresse IPv4 avec un préfixe de /8 à /32`;
  }
  if (!GATEWAY_RE.test(gateway)) return `la passerelle « ${gateway} » de ${WAN1_ROUTE_GW} n'est pas une adresse IPv4`;
  const [addr, len] = address.split('/');
  const prefix = Number(len);
  if (!covers(address, gateway)) {
    return `la passerelle ${gateway} est hors du réseau de l'adresse fixe ${address}`;
  }
  if (gateway === addr) return `la passerelle ${gateway} est l'adresse du routeur lui-même`;
  if (prefix <= 30) {
    const a = ipToInt(addr)!;
    const mask = (0xffffffff << (32 - prefix)) >>> 0;
    const net = (a & mask) >>> 0;
    const bcast = (net | (~mask >>> 0)) >>> 0;
    if (a === net || a === bcast) return `l'adresse fixe ${address} est l'adresse de réseau ou de diffusion, pas celle d'un hôte`;
  }
  return null;
}

/** The six (seven) probes of the standard block. Built here, compared key by
 *  key: the only conditioned probes the extrapolator may emit. */
export function standardWan1Probes(): Record<string, Record<string, unknown>> {
  const onPort = (): Record<string, unknown> => ({ interface: WAN1_PORT, disabled: false });
  const pppoeOnPort = (): Record<string, unknown> => ({ menu: '/interface/pppoe-client', where: onPort() });
  const unless = (): Array<Record<string, unknown>> => [
    { menu: '/ip/dhcp-client', where: onPort() },
    { menu: '/interface/pppoe-client', where: { disabled: false } },
  ];
  const fixedAddress = (): Record<string, unknown> => ({ ...onPort(), dynamic: false });
  return {
    [WAN1_KEYS.mode]: {
      ...pppoeOnPort(),
      present: 'pppoe',
      else: { menu: '/ip/address', where: fixedAddress(), present: 'static', single: true, unless: unless() },
    },
    [WAN1_KEYS.pppoeName]: { ...pppoeOnPort(), property: 'name' },
    [WAN1_KEYS.pppoeUsername]: { ...pppoeOnPort(), property: 'user' },
    [WAN1_KEYS.pppoePassword]: { ...pppoeOnPort(), property: 'password', sensitive: true },
    [WAN1_KEYS.address]: { menu: '/ip/address', where: fixedAddress(), property: 'address', unless: unless() },
    [WAN1_KEYS.gateway]: { menu: '/ip/route', where: { comment: WAN1_ROUTE_GW, disabled: false }, property: 'gateway' },
  };
}

/** True when `probe` is EXACTLY the standard probe of `key`. */
export function isStandardWan1Probe(key: string, probe: unknown): boolean {
  const standard = standardWan1Probes()[key];
  return standard !== undefined && isDeepStrictEqual(standard, probe);
}

/**
 * The block's head in the body: what the modes do, then the named refusals of
 * the hand-made templates (customer A's idiom: an undefined call named after the
 * reason, which the worker refuses with that name). They run before any line
 * is written, so a pppoe site without a login, or a static site whose gateway
 * is outside its network, never renders at all.
 */
export function wan1BodyPreamble(vlan: boolean, netwatch: boolean): string[] {
  const K = WAN1_KEYS;
  return [
    `{#- WAN1 (${K.mode}), le bloc standard des modèles magasin :`,
    `    dhcp   (défaut) le client DHCP de ${WAN1_PORT} repositionne les routes ${WAN1_ROUTE_NW} / ${WAN1_ROUTE_GW} ;`,
    `    pppoe  le client PPPoE ${K.pppoeName} sur ${WAN1_PORT}${vlan ? ` (ou sur vlan<${K.vlanId}>)` : ''}, membre de la liste ${WAN_LIST_NAME},`,
    `           routes ${WAN1_ROUTE_NW} / ${WAN1_ROUTE_GW}${netwatch ? ` et netwatch ${WAN1_NETWATCH_COMMENT}` : ''} désactivés, client DHCP conservé ;`,
    `    static ${K.address} sur ${WAN1_PORT}, routes par ${K.gateway}, pas de client DHCP. -#}`,
    `{%- if ${K.mode} is defined and ${K.mode} != "dhcp" and ${K.mode} != "pppoe" and ${K.mode} != "static" -%}`,
    '{{ refuse_wan1_mode_must_be_dhcp_pppoe_or_static() }}',
    '{%- endif -%}',
    `{%- if ${K.mode} == "pppoe" and (${K.pppoeUsername} is not defined or ${K.pppoePassword} is not defined) -%}`,
    '{{ refuse_wan1_mode_pppoe_needs_wan1_pppoe_username_and_wan1_pppoe_password() }}',
    '{%- endif -%}',
    `{%- if ${K.mode} == "pppoe" and ${K.pppoeName} != "ADSL" and ${K.pppoeName} != "FTTH" and ${K.pppoeName} != "FTTO" -%}`,
    '{{ refuse_wan1_pppoe_name_must_be_adsl_ftth_or_ftto() }}',
    '{%- endif -%}',
    `{%- if ${K.mode} == "static" and (${K.address} is not defined or ${K.gateway} is not defined) -%}`,
    '{{ refuse_wan1_mode_static_needs_wan1_address_and_wan1_gateway() }}',
    '{%- endif -%}',
    `{%- if ${K.mode} == "static" -%}`,
    `{%- if ((${K.gateway} ~ "/" ~ (${K.address} | prefixLen)) | network) != (${K.address} | network) -%}`,
    '{{ refuse_wan1_gateway_is_outside_the_network_of_wan1_address() }}',
    '{%- endif -%}',
    `{%- if (${K.gateway} ~ "/" ~ (${K.address} | prefixLen)) == ${K.address} -%}`,
    '{{ refuse_wan1_gateway_is_the_router_own_address() }}',
    '{%- endif -%}',
    `{%- if (${K.address} | prefixLen) <= 30 and (${K.address} == (${K.address} | network) ~ "/" ~ (${K.address} | prefixLen) ` +
      `or ${K.address} == (${K.address} | broadcast) ~ "/" ~ (${K.address} | prefixLen)) -%}`,
    '{{ refuse_wan1_address_is_a_network_or_broadcast_address_not_a_host() }}',
    '{%- endif -%}',
    '{%- endif -%}',
  ];
}

// ============================================================================
// The WAN1 lines of an export (the proof's focus)
// ============================================================================

/**
 * Every line of an export the standard block writes or would replace: the
 * PPPoE clients on the port or a VLAN over it (enabled or not), the VLANs on
 * the port, the list memberships of those clients, the DHCP clients and the
 * addresses on the port or its VLANs, the routes commented NW-WAN1 / WAN1-GW
 * and the netwatch commented WAN1. Read the same way on the router's export
 * and on the render, so "the WAN1 lines reproduce" means the same on both.
 */
export function wan1LinesOf(entries: readonly ExportEntry[]): ExportEntry[] {
  const c = classifyWan1(entries);
  const onPort = (e: ExportEntry): boolean => {
    const iface = propValue(e, 'interface');
    return iface !== undefined && c.onPort.has(iface);
  };
  const clients = c.pppoeAll.filter(onPort);
  const names = new Set(clients.map((e) => propValue(e, 'name')).filter((n): n is string => !!n));
  const keep = new Set<ExportEntry>([
    ...clients,
    ...c.vlans,
    ...entriesOf(entries, '/interface/list/member', 'add').filter((e) => names.has(propValue(e, 'interface') ?? '')),
    ...entriesOf(entries, '/ip/dhcp-client', 'add').filter(onPort),
    ...entriesOf(entries, '/ip/address', 'add').filter(onPort),
    ...entriesOf(entries, '/ip/route', 'add').filter((e) => {
      const comment = propValue(e, 'comment');
      return comment === WAN1_ROUTE_NW || comment === WAN1_ROUTE_GW;
    }),
    ...entriesOf(entries, '/tool/netwatch', 'add').filter((e) => propValue(e, 'comment') === WAN1_NETWATCH_COMMENT),
  ]);
  return entries.filter((e) => keep.has(e));
}

// ============================================================================
// One router: the standard block, or why not
// ============================================================================

export interface Wan1SiteShape {
  mode: Wan1Mode;
  /** The router's entry for each line of the block it carries. */
  roles: Map<Wan1Role, ExportEntry>;
  pppoeName: string | null;
  pppoeUsername: string | null;
  vlanId: string | null;
  address: string | null;
  gateway: string | null;
}

export type Wan1Assessment =
  | { ok: true; shape: Wan1SiteShape }
  /** `mode`: what the router runs, when that much could be read (a PPPoE
   *  store whose routes are left active is still a PPPoE store). */
  | { ok: false; reason: string; mode: Wan1Mode | null };

/**
 * What a router NOT carrying the standard block runs on WAN1, when that much
 * can be read — so that an excluded PPPoE or fixed-IP store still counts as
 * one (the summary, and the WAN1 proof, exist for it). Any active PPPoE
 * client on the port, a VLAN over it, or — with nothing at all on the port —
 * anywhere on the router is pppoe; several DHCP clients are dhcp; several
 * fixed addresses with no client are static. Null: nothing readable.
 */
function observedMode(c: Wan1Classification): Wan1Mode | null {
  if (c.mode === 'dhcp' || c.mode === 'pppoe' || c.mode === 'static') return c.mode;
  if (c.pppoeOn.length > 0) return 'pppoe';
  if (c.mode === 'ambiguous') return c.dhcpOn.length > 0 ? 'dhcp' : 'static';
  if (c.pppoeAll.some((e) => !truthy(propValue(e, 'disabled')))) return 'pppoe';
  return null;
}

function ambiguousReason(c: Wan1Classification): string {
  if (c.pppoeOn.length > 1) return `${c.pppoeOn.length} clients PPPoE actifs sur ${c.port} (ou un VLAN de ce port)`;
  if (c.dhcpOn.length > 1) return `${c.dhcpOn.length} clients DHCP actifs sur ${c.port} (ou un VLAN de ce port)`;
  if (c.pppoeOn.length > 0 && c.dhcpOn.length > 0) {
    return `un client PPPoE et un client DHCP qui pose sa propre route par défaut (add-default-route n'est pas « no ») sur ${c.port}`;
  }
  return `${c.staticOn.length} adresses fixes sur ${c.port} sans passerelle qui en désigne une seule`;
}

/**
 * Whether the router carries the standard WAN1 block, and in which mode. The
 * mode is the learning classifier's, with ONE reading it does not make: the
 * microcode leaves the DHCP client on ether1-WAN1 of a PPPoE store, with
 * `add-default-route=no`, and the learning facts call that `ambiguous`; the
 * standard block (and its `wan1_mode` probe) calls it pppoe — the client that
 * carries the default route wins. A DHCP client that installs its own default
 * route beside a PPPoE client stays ambiguous.
 */
export function assessWan1Site(entries: readonly ExportEntry[]): Wan1Assessment {
  const c = classifyWan1(entries);
  const no = (reason: string, mode: Wan1Mode | null = null): Wan1Assessment => ({ ok: false, reason, mode });
  if (c.port !== WAN1_PORT) {
    return no(`le port ether1 s'appelle « ${c.port} » : le bloc WAN1 standard attend « ${WAN1_PORT} »`, observedMode(c));
  }
  let mode: Wan1Mode;
  if (c.mode === 'dhcp' || c.mode === 'pppoe' || c.mode === 'static') {
    mode = c.mode;
  } else if (c.mode === 'ambiguous') {
    if (c.pppoeOn.length === 1 && c.dhcpOn.length === 1 && propValue(c.dhcpOn[0], 'add-default-route') === 'no') {
      mode = 'pppoe';
    } else {
      return no(ambiguousReason(c), observedMode(c));
    }
  } else {
    const elsewhere = observedMode(c) === 'pppoe' ? ' (un client PPPoE actif est ailleurs sur le routeur)' : '';
    return no(`ni client DHCP, ni client PPPoE, ni adresse fixe actifs sur ${WAN1_PORT} (ou un VLAN de ce port)${elsewhere}`,
      observedMode(c));
  }

  const roles = new Map<Wan1Role, ExportEntry>();
  const routes = entriesOf(entries, '/ip/route', 'add');
  const nw = routes.filter((r) => propValue(r, 'comment') === WAN1_ROUTE_NW);
  const gw = routes.filter((r) => propValue(r, 'comment') === WAN1_ROUTE_GW);
  if (nw.length !== 1 || gw.length !== 1) {
    return no(`les routes commentées ${WAN1_ROUTE_NW} et ${WAN1_ROUTE_GW} doivent exister une fois chacune ` +
      `(${nw.length} et ${gw.length} ici)`, mode);
  }
  roles.set('routeNW', nw[0]);
  roles.set('routeGW', gw[0]);
  const netwatch = entriesOf(entries, '/tool/netwatch', 'add').filter((n) => propValue(n, 'comment') === WAN1_NETWATCH_COMMENT);
  if (netwatch.length > 1) return no(`${netwatch.length} netwatch commentés ${WAN1_NETWATCH_COMMENT}`, mode);
  if (netwatch.length === 1) roles.set('netwatch', netwatch[0]);

  const shape: Wan1SiteShape = {
    mode, roles, pppoeName: null, pppoeUsername: null, vlanId: null, address: null, gateway: null,
  };

  if (mode === 'dhcp') {
    const d = c.dhcpOn[0];
    if (propValue(d, 'interface') !== WAN1_PORT) {
      return no(`le client DHCP est sur le VLAN « ${propValue(d, 'interface')} » de ${WAN1_PORT}, pas sur le port lui-même`, mode);
    }
    roles.set('dhcp', d);
  } else if (mode === 'pppoe') {
    const p = c.pppoeOn[0];
    const name = propValue(p, 'name') ?? '';
    if (!PPPOE_UPLINK_NAMES.includes(name)) {
      return no(`le client PPPoE s'appelle « ${name} » : le bloc standard n'accepte que ${PPPOE_UPLINK_NAMES.join(', ')}`, mode);
    }
    const user = propValue(p, 'user') ?? '';
    if (!USERNAME_RE.test(user)) {
      return no('le login PPPoE (user=) est absent ou hors du motif accepté (lettres, chiffres, . _ @ + / -, 64 au plus)', mode);
    }
    const iface = propValue(p, 'interface') ?? '';
    if (iface !== WAN1_PORT) {
      const vlan = c.vlans.filter((v) => propValue(v, 'name') === iface);
      const id = vlan.length === 1 ? propValue(vlan[0], 'vlan-id') ?? '' : '';
      if (vlan.length !== 1 || !VLAN_ID_RE.test(id) || iface !== `vlan${id}`) {
        return no(`le client PPPoE est sur l'interface « ${iface} » : le bloc attend ${WAN1_PORT} ou un VLAN de ce port ` +
          'nommé vlan<id> (vlan832 pour vlan-id=832)', mode);
      }
      roles.set('vlan', vlan[0]);
      shape.vlanId = id;
    }
    const memberships = entriesOf(entries, '/interface/list/member', 'add').filter((m) => propValue(m, 'interface') === name);
    if (memberships.length !== 1 || (propValue(memberships[0], 'list') ?? '').toUpperCase() !== WAN_LIST_NAME) {
      return no(`le client PPPoE ${name} doit être membre de la liste ${WAN_LIST_NAME}, et d'elle seule ` +
        `(${memberships.length} appartenance(s) ici)`, mode);
    }
    if (c.dhcpOn.length !== 1 || propValue(c.dhcpOn[0], 'interface') !== WAN1_PORT) {
      return no(`le client PPPoE n'a pas à côté de lui le client DHCP de ${WAN1_PORT} que le bloc standard conserve ` +
        '(microcode, add-default-route=no)', mode);
    }
    for (const [role, label] of [['routeNW', WAN1_ROUTE_NW], ['routeGW', WAN1_ROUTE_GW], ['netwatch', `netwatch ${WAN1_NETWATCH_COMMENT}`]] as const) {
      const e = roles.get(role);
      if (e && propValue(e, 'disabled') !== 'yes') {
        return no(`client PPPoE actif mais ${role === 'netwatch' ? 'le' : 'la route'} ${label} n'est pas désactivé(e) ` +
          '(le bloc standard le fait en mode pppoe)', mode);
      }
    }
    roles.set('pppoe', p);
    roles.set('member', memberships[0]);
    roles.set('dhcp', c.dhcpOn[0]);
    shape.pppoeName = name;
    shape.pppoeUsername = user;
  } else {
    if (c.staticOn.length !== 1) return no(`${c.staticOn.length} adresses fixes actives sur ${WAN1_PORT} (le bloc en écrit une)`, mode);
    const a = c.staticOn[0];
    if (propValue(a, 'interface') !== WAN1_PORT) {
      return no(`l'adresse fixe est sur le VLAN « ${propValue(a, 'interface')} » de ${WAN1_PORT}, pas sur le port lui-même`, mode);
    }
    const address = propValue(a, 'address') ?? '';
    const gateway = propValue(gw[0], 'gateway') ?? '';
    const problem = staticPairProblem(address, gateway);
    if (problem) return no(problem, mode);
    if ((propValue(nw[0], 'gateway') ?? '') !== gateway) {
      return no(`${WAN1_ROUTE_NW} et ${WAN1_ROUTE_GW} n'ont pas la même passerelle (le bloc les écrit toutes deux avec wan1_gateway)`, mode);
    }
    const network = propValue(a, 'network');
    if (network !== undefined && network !== networkOf(address)) {
      return no(`network=${network} ne correspond pas à l'adresse fixe ${address}`, mode);
    }
    roles.set('static', a);
    shape.address = address;
    shape.gateway = gateway;
  }

  // Every WAN1 line of the router must be a line of the block: a disabled
  // leftover client, a second address, a VLAN for something else — the block
  // cannot write them, so the router is not forced into it.
  const mine = new Set(roles.values());
  for (const e of wan1LinesOf(entries)) {
    if (!mine.has(e)) return no(`la ligne « ${displayLine(e).slice(0, 160)} » touche WAN1 et le bloc standard ne l'écrit pas`, mode);
  }
  return { ok: true, shape };
}

// ============================================================================
// One cluster: emit the block or not
// ============================================================================

export interface Wan1Exclusion {
  site: number;
  reason: string;
  /** What the router runs, when it could be read. */
  mode: Wan1Mode | null;
}

export interface Wan1Summary {
  /** The block is in the proposal. */
  emitted: boolean;
  /** Why it is not (null when emitted). French. */
  notEmittedReason: string | null;
  /** Routers of the block, per mode. */
  counts: Record<Wan1Mode, number>;
  /** PPPoE routers of the block, per client name. */
  pppoeNames: Record<string, number>;
  /** PPPoE routers of the block whose client rides a VLAN. */
  vlan: number;
  /** Routers left out of the block, with the reason. */
  excluded: Wan1Exclusion[];
  /** The routers of the block the mode-switch proof renders from: one per
   *  distinct WAN1 shape (`wan1ShapeSignature`), so the verdict never depends
   *  on which router happens to come first. Empty when not emitted. */
  baseSites: number[];
}

/**
 * The properties of each line of the block that the BLOCK writes — from the
 * wan1_* values or from the mode (`wanFixedSlots` in extrapolate.ts). Every
 * other property of a block line is the router's own, inferred like any line,
 * and may differ from router to router.
 */
const WAN1_BLOCK_KEYS: Record<Wan1Role, readonly string[]> = {
  pppoe: ['interface', 'name', 'user', 'password'],
  member: ['interface'],
  vlan: ['interface', 'name', 'vlan-id'],
  static: ['address', 'network', 'interface'],
  dhcp: [],
  routeNW: ['disabled', 'gateway'],
  routeGW: ['disabled', 'gateway'],
  netwatch: ['disabled'],
};

/**
 * What, in a router of the block, can change how ITS render of the block
 * reads in another mode: which lines it carries, and their properties the
 * block does not write (a DHCP client's add-default-route, say). Two routers
 * with the same signature render the block identically in every mode.
 */
export function wan1ShapeSignature(shape: Wan1SiteShape): string {
  return [...shape.roles.entries()]
    .map(([role, e]) => {
      const own = e.props.filter((p) => !WAN1_BLOCK_KEYS[role].includes(p.key))
        .map((p) => `${p.key}=${JSON.stringify(p.value)}`).sort().join(' ');
      return `${role}{${own}}`;
    })
    .sort()
    .join(' ');
}

export interface Wan1ClusterPlan {
  emit: boolean;
  /** Per site: its shape when it is in the block. */
  shapes: Array<Wan1SiteShape | null>;
  /** The WAN1 netwatch is a line of the block (the routers of the block carry it). */
  netwatch: boolean;
  /** A router of the block carries its PPPoE client on a VLAN. */
  vlan: boolean;
  /** Excluded routers' WAN1 lines, kept out of the alignment (reported, never templated). */
  pulled: Map<number, ExportEntry[]>;
  /** Null when there is nothing to say: no router runs pppoe or static. */
  summary: Wan1Summary | null;
}

/**
 * The decision for one cluster. The block is EMITTED when at least half of
 * the routers carry it, at least one of them runs pppoe or static, and at
 * least one carries the DHCP client the dhcp mode is read from. A cluster
 * where no router runs pppoe or static is left exactly as it was (summary
 * null): a pure-DHCP client gets the proposal it always got.
 */
export function planWan1Cluster(sites: ReadonlyArray<readonly ExportEntry[]>): Wan1ClusterPlan {
  const n = sites.length;
  const assessed = sites.map((entries) => assessWan1Site(entries));
  const shapes: Array<Wan1SiteShape | null> = assessed.map((a) => (a.ok ? a.shape : null));
  const excluded: Wan1Exclusion[] = [];
  assessed.forEach((a, site) => { if (!a.ok) excluded.push({ site, reason: a.reason, mode: a.mode }); });

  // The netwatch is a line of the block when at least half of the routers of
  // the block carry it, and then those that do not are left out; otherwise it
  // is NOT a line of the block, and the minority that carries it is left out
  // the same way. Never an ordinary variant line beside the block: its
  // `disabled` would not follow wan1_mode, and a carrier switched to pppoe
  // would keep a live WAN1 netwatch whose up-script re-enables the WAN1
  // routes beside the PPPoE default route.
  const inBlock = shapes.filter((x): x is Wan1SiteShape => x !== null);
  const withNetwatch = inBlock.filter((x) => x.roles.has('netwatch')).length;
  const netwatch = withNetwatch > 0 && withNetwatch * 2 >= inBlock.length;
  shapes.forEach((shape, site) => {
    if (!shape || shape.roles.has('netwatch') === netwatch) return;
    shapes[site] = null;
    excluded.push({
      site,
      reason: netwatch
        ? `pas de netwatch commenté ${WAN1_NETWATCH_COMMENT}, que portent ${withNetwatch} autre(s) routeur(s) du profil`
        : `un netwatch commenté ${WAN1_NETWATCH_COMMENT}, que ne portent pas ${inBlock.length - withNetwatch} autre(s) ` +
          'routeur(s) du profil : le bloc ne l\'écrit pas',
      mode: shape.mode,
    });
  });
  excluded.sort((a, b) => a.site - b.site);

  const block = shapes.filter((x): x is Wan1SiteShape => x !== null);
  const counts: Record<Wan1Mode, number> = { dhcp: 0, pppoe: 0, static: 0 };
  const pppoeNames: Record<string, number> = {};
  let vlan = 0;
  for (const s of block) {
    counts[s.mode]++;
    if (s.pppoeName) pppoeNames[s.pppoeName] = (pppoeNames[s.pppoeName] ?? 0) + 1;
    if (s.vlanId) vlan++;
  }
  const nonDhcp = counts.pppoe + counts.static;
  const carriers = counts.dhcp + counts.pppoe;
  const seenNonDhcp = nonDhcp + excluded.filter((x) => x.mode === 'pppoe' || x.mode === 'static').length;

  let notEmittedReason: string | null = null;
  if (seenNonDhcp > 0) {
    if (block.length * 2 < n) {
      notEmittedReason = `seuls ${block.length} routeur(s) sur ${n} portent la structure WAN1 standard`;
    } else if (nonDhcp === 0) {
      notEmittedReason = 'aucun routeur pppoe ou static du profil ne porte la structure WAN1 standard';
    } else if (carriers === 0) {
      notEmittedReason = `aucun routeur du bloc ne porte le client DHCP de ${WAN1_PORT} : le mode dhcp ne peut pas en être déduit`;
    }
  }
  const emit = seenNonDhcp > 0 && notEmittedReason === null;

  const pulled = new Map<number, ExportEntry[]>();
  if (emit) {
    for (const x of excluded) {
      const lines = wan1LinesOf(sites[x.site]);
      if (lines.length > 0) pulled.set(x.site, lines);
    }
  }
  const baseSites: number[] = [];
  if (emit) {
    const seen = new Set<string>();
    shapes.forEach((shape, site) => {
      if (!shape) return;
      const signature = wan1ShapeSignature(shape);
      if (seen.has(signature)) return;
      seen.add(signature);
      baseSites.push(site);
    });
  }
  return {
    emit,
    shapes: emit ? shapes : sites.map(() => null),
    netwatch: emit && netwatch,
    vlan: emit && vlan > 0,
    pulled,
    summary: seenNonDhcp === 0 ? null : {
      emitted: emit, notEmittedReason, counts, pppoeNames, vlan, excluded, baseSites,
    },
  };
}

// ============================================================================
// The mode-switch proof's stand-ins (documentation ranges, RFC 5737)
// ============================================================================

export interface Wan1StandIn {
  label: string;
  mode: Wan1Mode;
  values: Partial<Record<(typeof WAN1_KEYS)[keyof typeof WAN1_KEYS], string>>;
}

/** One render per mode (and per VLAN form, when the block has it). Never a
 *  customer's value: the proof renders one router of the block in every mode
 *  with these, and checks the WAN1 lines are exactly the block's. */
export function wan1StandIns(withVlan: boolean): Wan1StandIn[] {
  const out: Wan1StandIn[] = [
    { label: 'mode dhcp', mode: 'dhcp', values: { [WAN1_KEYS.mode]: 'dhcp' } },
    {
      label: 'mode pppoe',
      mode: 'pppoe',
      values: { [WAN1_KEYS.mode]: 'pppoe', [WAN1_KEYS.pppoeName]: 'FTTO', [WAN1_KEYS.pppoeUsername]: 'standin@isp.example' },
    },
    {
      label: 'mode static',
      mode: 'static',
      values: { [WAN1_KEYS.mode]: 'static', [WAN1_KEYS.address]: '192.0.2.10/29', [WAN1_KEYS.gateway]: '192.0.2.9' },
    },
  ];
  if (withVlan) {
    out.push({
      label: 'mode pppoe sur VLAN',
      mode: 'pppoe',
      values: {
        [WAN1_KEYS.mode]: 'pppoe', [WAN1_KEYS.pppoeName]: 'FTTH', [WAN1_KEYS.pppoeUsername]: 'fti/standin',
        [WAN1_KEYS.vlanId]: '832',
      },
    });
  }
  return out;
}

/** The problems of one stand-in render: the render must itself be a router
 *  carrying the standard block, in that mode, with exactly those values. */
export function wan1StandInProblems(standIn: Wan1StandIn, entries: readonly ExportEntry[]): string[] {
  const a = assessWan1Site(entries);
  if (!a.ok) return [a.reason];
  const s = a.shape;
  const v = standIn.values;
  const problems: string[] = [];
  if (s.mode !== standIn.mode) problems.push(`le rendu est en mode ${s.mode}, pas ${standIn.mode}`);
  const want: Array<[string, string | null, string | undefined]> = [
    [WAN1_KEYS.pppoeName, s.pppoeName, v[WAN1_KEYS.pppoeName]],
    [WAN1_KEYS.pppoeUsername, s.pppoeUsername, v[WAN1_KEYS.pppoeUsername]],
    [WAN1_KEYS.vlanId, s.vlanId, v[WAN1_KEYS.vlanId]],
    [WAN1_KEYS.address, s.address, v[WAN1_KEYS.address]],
    [WAN1_KEYS.gateway, s.gateway, v[WAN1_KEYS.gateway]],
  ];
  for (const [key, got, expected] of want) {
    if ((got ?? undefined) !== expected) problems.push(`${key} rendu « ${got ?? '(absent)'} », attendu « ${expected ?? '(absent)'} »`);
  }
  return problems;
}
