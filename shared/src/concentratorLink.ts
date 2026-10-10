// ============================================================================
// @obliwan/shared — the ObliWAN <-> concentrator WireGuard link
// ============================================================================
//
// THE PROBLEM THIS SOLVES. Every customer router's management address is its
// L2TP tunnel address, inside 100.64.0.0/10, and the only box with a route to
// those addresses is the concentrator (the CHR) that terminates the tunnels.
// An ObliWAN host that reaches the CHR on its PUBLIC address but has no route
// to 100.64.0.0/10 can talk to the CHR and to nothing behind it.
//
// THE LINK. A WireGuard tunnel between the ObliWAN host and the CHR, on a /30
// TRANSIT inside 100.64.0.0/10 but outside every allocation pool (default
// 100.127.255.252/30: CHR .253, ObliWAN .254). The host routes 100.64.0.0/10
// into it; the CHR MASQUERADES what arrives from the ObliWAN address towards
// 100.64.0.0/10, so a CPE sees its own L2TP peer as the source and answers it —
// no CPE configuration changes. The CHR half is the change job kind
// `concentrator_link` (server/src/services/concentratorLink/); the host half is
// the `obliwan-wg` sidecar (server/src/wgSidecar.ts).
//
// This file is the vocabulary both halves and the client share: the constants
// and the pure address arithmetic. Nothing here touches a socket or a file.

/** The change job kind (shared/src/change.ts CHANGE_JOB_KINDS, migration 053). */
export const CONCENTRATOR_LINK_KIND = 'concentrator_link' as const;

/** Every customer router's tunnel address lives here (RFC 6598 shared space). */
export const LINK_SUPERNET = '100.64.0.0/10';
/** Default transit: CHR .253, ObliWAN .254. Configurable per concentrator. */
export const DEFAULT_LINK_TRANSIT = '100.127.255.252/30';
/** RouterOS's own default WireGuard listen port. */
export const DEFAULT_LINK_LISTEN_PORT = 13231;
/** The interface the job creates ON THE CHR. Never another one. */
export const CHR_WG_INTERFACE = 'obliwan-wg';
/** The interface the sidecar creates ON THE DOCKER HOST. Never another one. */
export const HOST_WG_INTERFACE = 'wg-obliwan';
/** The host keeps the NAT/conntrack state on the path to the CHR alive. */
export const HOST_WG_KEEPALIVE_SECONDS = 25;
/**
 * A handshake older than this is not evidence the link works today.
 * WireGuard re-handshakes every 2 minutes on an active session, and the host
 * side sends a keepalive every 25 s, so a working link never ages past ~2 min.
 */
export const LINK_HANDSHAKE_FRESH_SECONDS = 180;
/** A sidecar status file older than this means no sidecar is running. */
export const LINK_SIDECAR_STALE_SECONDS = 30;
/**
 * Every item the job adds on the CHR carries `comment=obliwan:link:<item>`,
 * and is FOUND again by exact comment equality (never a regex: a regex over a
 * marker over-matches, see drivers/mikrotik/render.ts).
 */
export const LINK_COMMENT_PREFIX = 'obliwan:link:';

/** What the job may add on the CHR, in the order it adds them. */
export const LINK_ITEMS = [
  'wg_interface',  // /interface/wireguard name=obliwan-wg
  'wg_address',    // /ip/address <chr>/30 on it
  'wg_peer',       // /interface/wireguard/peers ObliWAN's PUBLIC key, allowed .254/32
  'input_wg',      // filter input accept udp dst-port=<listen-port>
  'input_mgmt',    // filter input accept in-interface=obliwan-wg src-address=<host>
  'forward_in',    // filter forward accept obliwan-wg -> 100.64.0.0/10 (only if forward drops)
  'forward_reply', // filter forward accept established,related back to <host> (same condition)
  'srcnat',        // nat srcnat src=<host> dst=100.64.0.0/10 masquerade
] as const;
export type LinkItem = (typeof LINK_ITEMS)[number];

export function linkComment(item: LinkItem): string {
  return `${LINK_COMMENT_PREFIX}${item}`;
}

// ============================================================================
// IPv4 arithmetic (no dependency; the server and the client both need it)
// ============================================================================

const OCTET = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

/** Dotted quad -> unsigned 32-bit integer, or null. Strict: no leading zeros. */
export function parseIpv4(text: string): number | null {
  const parts = text.trim().split('.');
  if (parts.length !== 4 || !parts.every((p) => OCTET.test(p))) return null;
  return parts.reduce((acc, p) => acc * 256 + Number(p), 0);
}

export function formatIpv4(value: number): string {
  const v = value >>> 0;
  return [v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].join('.');
}

export interface Ipv4Cidr {
  /** The address as written (host bits may be set). */
  address: number;
  prefix: number;
  /** address with the host bits cleared. */
  network: number;
}

function maskOf(prefix: number): number {
  return prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
}

/** `a.b.c.d/p` (or a bare address, read as /32) -> parts, or null. */
export function parseIpv4Cidr(text: string): Ipv4Cidr | null {
  const [addr, len, extra] = text.trim().split('/');
  if (extra !== undefined) return null;
  const address = parseIpv4(addr ?? '');
  if (address === null) return null;
  let prefix = 32;
  if (len !== undefined) {
    if (!/^\d{1,2}$/.test(len)) return null;
    prefix = Number(len);
    if (prefix > 32) return null;
  }
  return { address, prefix, network: (address & maskOf(prefix)) >>> 0 };
}

export function cidrSize(c: Ipv4Cidr): number {
  return 2 ** (32 - c.prefix);
}

/** Does `outer` contain every address of `inner`? */
export function ipv4CidrContains(outer: Ipv4Cidr, inner: Ipv4Cidr): boolean {
  if (inner.prefix < outer.prefix) return false;
  return ((inner.network & maskOf(outer.prefix)) >>> 0) === outer.network;
}

/** Do the two ranges share at least one address? */
export function ipv4CidrOverlaps(a: Ipv4Cidr, b: Ipv4Cidr): boolean {
  return ipv4CidrContains(a, b) || ipv4CidrContains(b, a);
}

export function formatIpv4Cidr(c: Ipv4Cidr): string {
  return `${formatIpv4(c.network)}/${c.prefix}`;
}

// ============================================================================
// The transit
// ============================================================================

export interface LinkTransit {
  /** Canonical network form, e.g. `100.127.255.252/30`. */
  transit: string;
  /** network + 1 — the address the job puts on the CHR's obliwan-wg. */
  chrAddress: string;
  /** network + 2 — the address the sidecar puts on the host's wg-obliwan. */
  hostAddress: string;
}

/**
 * Why `text` cannot be the transit, or null. A transit is a /30 written as its
 * NETWORK address (`.252/30`, not `.253/30`: an ambiguous spelling is refused,
 * not guessed), entirely inside 100.64.0.0/10. Whether it collides with an
 * allocation pool or an allocated address is the server's question (it needs
 * the database), asked on top of this one.
 */
export function transitProblem(text: string): string | null {
  const c = parseIpv4Cidr(text);
  if (!c || !text.includes('/')) return 'the transit must be written a.b.c.d/30';
  if (c.prefix !== 30) return `the transit must be a /30 (got /${c.prefix})`;
  if (c.address !== c.network) {
    return `the transit must be written as its network address (${formatIpv4Cidr(c)}), not a host inside it`;
  }
  const supernet = parseIpv4Cidr(LINK_SUPERNET) as Ipv4Cidr;
  if (!ipv4CidrContains(supernet, c)) return `the transit must lie inside ${LINK_SUPERNET}`;
  return null;
}

/** The three addresses of a transit `transitProblem` accepted. Throws otherwise. */
export function deriveTransit(text: string): LinkTransit {
  const problem = transitProblem(text);
  if (problem) throw new TypeError(problem);
  const c = parseIpv4Cidr(text) as Ipv4Cidr;
  return {
    transit: formatIpv4Cidr(c),
    chrAddress: formatIpv4(c.network + 1),
    hostAddress: formatIpv4(c.network + 2),
  };
}

export function listenPortProblem(port: unknown): string | null {
  if (typeof port !== 'number' || !Number.isInteger(port) || port < 1024 || port > 65535) {
    return 'the WireGuard listen port must be an integer between 1024 and 65535';
  }
  return null;
}

/** A WireGuard key: base64 of exactly 32 bytes (44 characters, one `=`). */
const WG_KEY_RE = /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/;
export function isWireGuardKey(text: unknown): text is string {
  return typeof text === 'string' && WG_KEY_RE.test(text);
}

// ============================================================================
// The view the server returns and the device page renders
// ============================================================================

/** Where the CHR half stands. */
export type LinkChrSide = 'not_started' | 'pending' | 'provisioned' | 'failed';

/**
 * Where the HOST half stands, as the sidecar reported it.
 *  disabled              OBLIWAN_WG_ENABLED is not `true`. Unset: the sidecar
 *                        configures and removes nothing. Explicitly `false`:
 *                        it removes what it created (and only that).
 *  sidecar_absent        no fresh status file: the sidecar is not running (its
 *                        compose profile `wg` is not active) or does not share
 *                        the volume with the server.
 *  no_config             the sidecar runs, and no config file is on the volume
 *                        (the server has not written one yet). An interface the
 *                        sidecar created earlier is left as it is.
 *  up                    interface, address and route in place; the handshake
 *                        age says whether the CHR answers.
 *  kernel_module_missing the host kernel has no WireGuard (see the card's fallback).
 *  foreign_interface     a `wg-obliwan` exists that the sidecar did not create.
 *  route_conflict        100.64.0.0/10 is already routed elsewhere on the host.
 *  error                 anything else; `message` says what.
 */
export const LINK_HOST_STATES = [
  'disabled',
  'sidecar_absent',
  'no_config',
  'up',
  'kernel_module_missing',
  'foreign_interface',
  'route_conflict',
  'error',
] as const;
export type LinkHostState = (typeof LINK_HOST_STATES)[number];

export interface LinkProbe {
  address: string;
  port: number;
  /** true: a TCP answer came back through the link (connect, or a refusal). */
  reachable: boolean;
  /** true only for an established connection (the service listens). */
  connected: boolean;
  detail: string;
}

/** A session is probed only once it has been up this long: a router that has
 *  just (re)connected may not have its services or routes in place yet, and
 *  its silence would be reported as the link's. */
export const LINK_PROBE_STABLE_SECONDS = 600;
/** Sites probed per client, longest-running sessions first. */
export const LINK_PROBE_SITES_PER_CLIENT = 3;
/** Clients probed per view; the rest are counted, not silently dropped. */
export const LINK_PROBE_MAX_CLIENTS = 30;

export interface LinkSiteProbe extends LinkProbe {
  deviceId: number | null;
  name: string | null;
  sessionStartedAt: string;
  /** false: no session of this client was up LINK_PROBE_STABLE_SECONDS, so a
   *  young one was probed instead — its silence is weak evidence. */
  stable: boolean;
}

export interface LinkClientProbe {
  /** null: the sessions belong to no device and fall in no tenant's tunnel pool. */
  tenantId: number | null;
  tenantName: string | null;
  /** How the sessions were attributed: the bound device's tenant, or the
   *  tenant whose tunnel pool holds the address. */
  attribution: 'device' | 'pool' | 'none';
  liveSessions: number;
  stableSessions: number;
  sites: LinkSiteProbe[];
  /** reached: every probed site answered; partial: some did; unreached: none. */
  verdict: 'reached' | 'partial' | 'unreached';
}

export interface ConcentratorLinkView {
  concentratorId: number;
  concentratorName: string;
  defaults: { transit: string; listenPort: number };
  link: null | {
    transit: string;
    chrAddress: string;
    hostAddress: string;
    listenPort: number;
    hostPublicKey: string;
    chrPublicKey: string | null;
    endpointHost: string | null;
    provisionedAt: string | null;
    /** Once a job has written on the CHR the transit and port are frozen. */
    frozen: boolean;
    apiViaTunnelAt: string | null;
    apiPublicHost: string | null;
    apiPublicPort: number | null;
  };
  chrSide: LinkChrSide;
  /**
   * Another concentrator's link holds the host half (it was written on its
   * CHR or provisioned), or a link job for it is in flight and may take it.
   * The host carries ONE WireGuard peer for all of 100.64.0.0/10, so at most
   * one link is bound per installation (migration 053), and this concentrator
   * cannot be connected meanwhile. ObliWAN has no operation that unbinds a link.
   */
  hostBoundTo: null | { concentratorId: number; name: string };
  job: null | {
    id: number;
    status: string;
    errorKind: string | null;
    errorMessage: string | null;
    outcome: string | null;
    outcomeDetail: string | null;
    createdAt: string;
    steps: Array<{ kind: string; status: string; output: string | null }>;
  };
  host: {
    state: LinkHostState;
    message: string;
    statusAt: string | null;
    /** The config file on the volume is THIS link's (its CHR key, its
     *  transit address). */
    configWritten: boolean;
    /** The sidecar applied exactly that file. */
    configApplied: boolean;
    /** The sidecar's peer is THIS link's CHR key; null when no fresh report
     *  names a peer. The handshake and the traffic below are null unless it
     *  is true: another CHR's figures are never shown as this link's. */
    peerIsThisLink: boolean | null;
    latestHandshakeAt: string | null;
    /** A handshake within LINK_HANDSHAKE_FRESH_SECONDS, with THIS link's CHR. */
    handshakeFresh: boolean;
    rxBytes: number | null;
    txBytes: number | null;
    warnings: string[];
  };
  probes: {
    chr: LinkProbe | null;
    /** One entry per CLIENT (tenant) with a live session on this CHR, sorted by
     *  name. The CHR is shared by every tenant, so "a site answers" proves
     *  nothing about another client's address plan: each one is judged on its
     *  own sites. */
    clients: LinkClientProbe[];
    /** Clients with live sessions that were NOT probed (cap reached). */
    clientsNotProbed: number;
    /** Why no probe ran, when none did. */
    skipped: string | null;
  };
  apiTransport: { host: string | null; port: number | null; viaTunnel: boolean; useTls: boolean };
  canSwitchApi: boolean;
  switchBlockers: string[];
  /** The /ip service command the OPERATOR runs by hand (ObliWAN never does):
   *  one console line that writes the configured row, an open connection's
   *  entry of the same name skipped (`routerOsServiceSet`). */
  operatorCommand: string | null;
}
