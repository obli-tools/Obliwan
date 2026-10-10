/**
 * ObliWAN — MikroTik Neighbor Discovery (MNDP), bench side.
 *
 * ┌─ WHAT THIS IS FOR ───────────────────────────────────────────────────────┐
 * │ The preparer types the MAC printed on the box and its factory password.   │
 * │ Nothing else is known: not the address the box answers on, not whether   │
 * │ the bench PC shares a subnet with it. MNDP answers the first question at  │
 * │ layer 2 — every RouterOS box announces itself on UDP 5678 and answers a   │
 * │ discovery probe, with its MAC, identity, version, board and (when it has  │
 * │ one) the IPv4 address of the interface the announcement left by.          │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ FINDING A BOX IS NOT PROVING IT IS THE BOX ─────────────────────────────┐
 * │ MNDP is unauthenticated broadcast: anything on the LAN can claim any MAC, │
 * │ and a bench that is not isolated from the office LAN also hears the       │
 * │ office's PRODUCTION MikroTiks. So a match here only says where to dial.   │
 * │ The proof that the dialled box is the one on the sticker is taken by      │
 * │ `routerosApply.ts`, AFTER login, from the router's own interface table,   │
 * │ and nothing destructive happens before it.                                │
 * │                                                                          │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHY THE TYPED MAC IS A RANGE, NOT AN EXACT MATCH ───────────────────────┐
 * │ A RouterOS box announces the MAC of the interface it sends on, and on a  │
 * │ factory box that is NEVER the sticker MAC. The SOHO default config        │
 * │ (hEX, hAP, RB5009, L009) makes ether1 the WAN — input dropped, no        │
 * │ 192.168.88.1, neighbour discovery limited to the LAN list — so the bench  │
 * │ cable goes into a LAN port, and the box answers from `bridge`, whose      │
 * │ admin-mac the default config sets to the first LAN port: sticker + 1. An  │
 * │ exact match therefore returns `null` on the standard case, every time.    │
 * │                                                                          │
 * │ So the typed MAC selects CANDIDATES: same OUI, from the typed MAC up to   │
 * │ `MNDP_CANDIDATE_WINDOW` above it, closest first. A window that wide also  │
 * │ covers the next box of the same batch on the bench, and that is accepted  │
 * │ precisely because a candidate proves nothing: `identifyFactoryBox()` and │
 * │ `applyFactoryProvisioning()` (routerosApply.ts) log in and look for the   │
 * │ typed MAC in the router's own interface table, and refuse otherwise. The  │
 * │ window decides where to dial; it can never decide what gets written.      │
 * │                                                                          │
 * │ Expected wiring: `discoverByMac(mac)` → `reachableAddress(c)` →           │
 * │ `identifyFactoryBox()` (read-only proof, model, version) → … →            │
 * │ `applyFactoryProvisioning()`, which takes the proof again on its own      │
 * │ session rather than trusting the earlier one. Two factory boxes on ONE    │
 * │ link both answer on 192.168.88.1, and which one a dial reaches is up to   │
 * │ ARP: the proof refuses the wrong one, it cannot pick the right one. One   │
 * │ factory box per bench link at a time — several links, one per box, are    │
 * │ `discoverOnAddresses` and `slots.ts`.                                     │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Wire layout (UDP payload), as dissected by Wireshark's `packet-mndp.c` and
 * implemented by MAC-Telnet's `protocol.c`:
 *
 *   4 bytes   header. NOT interpreted here: the two references disagree on its
 *             meaning (Wireshark: 2 unknown + 2 sequence; MAC-Telnet: version,
 *             ttl, checksum) and nothing below depends on it. A discovery
 *             probe is these four bytes, all zero, and nothing else.
 *   then TLVs: type u16 BIG-endian, length u16 BIG-endian, value.
 *
 *     1 MAC (6)  5 identity  7 version  8 platform  10 uptime (u32 seconds,
 *     LITTLE-endian — the one multi-byte value that is; both references read
 *     it that way)  11 software-id  12 board  14 unpack (1)  15 IPv6 (16)
 *     16 interface name  17 IPv4 (4)
 *
 * The layout is taken from those two references, not from a capture of the
 * Wednesday hardware; `mndp.verify.ts` pins it with hand-written vectors so
 * the first real capture has something exact to be compared against.
 *
 * No database, no vault, no logger: this runs inside the bench SEA binary.
 */

import dgram from 'node:dgram';
import { networkInterfaces } from 'node:os';

export const MNDP_PORT = 5678;

export const MNDP_TLV = {
  MAC: 1,
  IDENTITY: 5,
  VERSION: 7,
  PLATFORM: 8,
  UPTIME: 10,
  SOFTWARE_ID: 11,
  BOARD: 12,
  UNPACK: 14,
  IPV6: 15,
  INTERFACE_NAME: 16,
  IPV4: 17,
} as const;

/** The discovery probe: an MNDP header with no TLV. */
export const MNDP_PROBE: Buffer = Buffer.alloc(4);

const DEFAULT_TIMEOUT_MS = 4_000;
const DEFAULT_PROBE_INTERVAL_MS = 1_000;

// ============================================================================
// MAC addresses
// ============================================================================

/**
 * Canonical `AA:BB:CC:DD:EE:FF` (the way RouterOS prints it), or `null`.
 *
 * Accepts what a person copies off a sticker or a screen: `AA:BB:..`,
 * `aa-bb-..`, Cisco's `aabb.ccdd.eeff`, bare `aabbccddeeff`, with stray spaces.
 * Separators are dropped and exactly twelve hex digits must remain — eleven
 * (a missed character) or thirteen (a doubled one) is `null`, never a guess.
 */
export function normalizeMac(input: string | null | undefined): string | null {
  if (typeof input !== 'string') return null;
  const hex = input.trim().replace(/[\s:.\-]/g, '');
  if (!/^[0-9a-fA-F]{12}$/.test(hex)) return null;
  return (hex.toUpperCase().match(/../g) as string[]).join(':');
}

/**
 * True for a MAC a router interface can actually carry: not all-zero and not
 * group-addressed (the I/G bit of the first octet). A typed broadcast MAC is a
 * typo that would otherwise "match" nothing and look like a box that is off.
 */
export function isUnicastMac(mac: string): boolean {
  const n = normalizeMac(mac);
  if (!n) return false;
  if (n === '00:00:00:00:00:00') return false;
  return (parseInt(n.slice(0, 2), 16) & 0x01) === 0;
}

/**
 * How far above the typed MAC an announcement still names a candidate. A
 * factory box announces sticker + 1; a box whose default config bridged a
 * later port, or whose MACs are allocated in a block per radio and per port,
 * announces a little further up. 16 covers every port of the routers on the
 * bench and is NOT a safety margin — see the header: the login check is.
 */
export const MNDP_CANDIDATE_WINDOW = 16;

/**
 * `announced − typed`, when both MACs share an OUI and the announced one lies
 * in [typed, typed + window]; `null` otherwise. Only ABOVE: a box announces
 * one of its own ports, and the sticker carries the lowest of them. A MAC
 * below the typed one belongs to another box, and a different OUI belongs to
 * another manufacturing block — neither is worth dialling.
 */
export function macOffset(announced: string, typed: string, window = MNDP_CANDIDATE_WINDOW): number | null {
  const a = normalizeMac(announced);
  const t = normalizeMac(typed);
  if (!a || !t) return null;
  if (a.slice(0, 8) !== t.slice(0, 8)) return null;
  const nic = (m: string) => parseInt(m.slice(9).replace(/:/g, ''), 16);
  const d = nic(a) - nic(t);
  return d >= 0 && d <= window ? d : null;
}

/** Thrown for a caller mistake (an unreadable MAC), never for "not found". */
export class MndpInputError extends Error {
  readonly code = 'INVALID_MAC';
  constructor(message: string) {
    super(message);
    this.name = 'MndpInputError';
  }
}

// ============================================================================
// Parsing
// ============================================================================

export interface MndpNeighbour {
  /** Canonical MAC of the interface the packet left by. */
  mac: string;
  identity: string | null;
  version: string | null;
  platform: string | null;
  board: string | null;
  /** IPv4 the router holds on that interface. `null` on a box with none. */
  ipv4: string | null;
  /** Eight uncompressed hex groups (`fe80:0:0:0:...`), not RFC 5952 form. */
  ipv6: string | null;
  interfaceName: string | null;
  uptimeSeconds: number | null;
  softwareId: string | null;
  unpack: number | null;
  /** UDP source address of the datagram, when the packet came off a socket. */
  sourceAddress: string | null;
  /**
   * The bench PC's own address the datagram was HEARD on — set only by
   * `discoverOnAddresses`, whose sockets are bound one per bench link. It
   * says which link (`slots.ts`) the box is on; a wildcard listen cannot
   * say it (Node gives no receiving interface) and leaves it absent.
   */
  localAddress?: string | null;
  /** A TLV claimed more bytes than the datagram held; later fields are absent. */
  truncated: boolean;
  /** TLV types this parser does not model, kept so a capture can be compared. */
  unknownTypes: number[];
}

function text(value: Buffer): string | null {
  // Trailing NULs are stripped so that a NUL-padded string compares equal to
  // the unpadded one; an empty string is "not reported", i.e. null.
  const s = value.toString('utf8').replace(/\0+$/, '').trim();
  return s === '' ? null : s;
}

function formatIpv6(value: Buffer): string {
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) groups.push(value.readUInt16BE(i).toString(16));
  return groups.join(':');
}

/**
 * Parse one MNDP datagram. `null` when it carries no usable MAC — a probe
 * (ours included: we hear our own broadcast), a malformed MAC, or two
 * DIFFERENT MAC TLVs. The last is refused rather than resolved: the MAC is the
 * only field this module is used to match on, and a packet that names two
 * boxes names none.
 *
 * Other repeated TLVs keep their first value. A value of the wrong length for
 * a fixed-size field (uptime, IPv4, IPv6, unpack) is `null`, never a partial
 * read.
 */
export function parseMndpPacket(buf: Buffer, sourceAddress: string | null = null): MndpNeighbour | null {
  if (!Buffer.isBuffer(buf) || buf.length < 4) return null;

  const n: Omit<MndpNeighbour, 'mac'> & { mac: string | null } = {
    mac: null,
    identity: null,
    version: null,
    platform: null,
    board: null,
    ipv4: null,
    ipv6: null,
    interfaceName: null,
    uptimeSeconds: null,
    softwareId: null,
    unpack: null,
    sourceAddress,
    truncated: false,
    unknownTypes: [],
  };
  const seen = new Set<number>();
  let macConflict = false;

  let offset = 4;
  while (offset < buf.length) {
    if (offset + 4 > buf.length) {
      n.truncated = true;
      break;
    }
    const type = buf.readUInt16BE(offset);
    const length = buf.readUInt16BE(offset + 2);
    const start = offset + 4;
    if (start + length > buf.length) {
      n.truncated = true;
      break;
    }
    const value = buf.subarray(start, start + length);
    offset = start + length;

    if (type === MNDP_TLV.MAC) {
      const mac = length === 6 ? normalizeMac(value.toString('hex')) : null;
      if (mac === null) return null;
      if (n.mac !== null && n.mac !== mac) macConflict = true;
      n.mac = n.mac ?? mac;
      continue;
    }
    if (seen.has(type)) continue;
    seen.add(type);

    switch (type) {
      case MNDP_TLV.IDENTITY:
        n.identity = text(value);
        break;
      case MNDP_TLV.VERSION:
        n.version = text(value);
        break;
      case MNDP_TLV.PLATFORM:
        n.platform = text(value);
        break;
      case MNDP_TLV.UPTIME:
        n.uptimeSeconds = length === 4 ? value.readUInt32LE(0) : null;
        break;
      case MNDP_TLV.SOFTWARE_ID:
        n.softwareId = text(value);
        break;
      case MNDP_TLV.BOARD:
        n.board = text(value);
        break;
      case MNDP_TLV.UNPACK:
        n.unpack = length === 1 ? value[0] : null;
        break;
      case MNDP_TLV.IPV6:
        n.ipv6 = length === 16 ? formatIpv6(value) : null;
        break;
      case MNDP_TLV.INTERFACE_NAME:
        n.interfaceName = text(value);
        break;
      case MNDP_TLV.IPV4:
        n.ipv4 = length === 4 ? Array.from(value).join('.') : null;
        break;
      default:
        n.unknownTypes.push(type);
    }
  }

  if (n.mac === null || macConflict) return null;
  return n as MndpNeighbour;
}

/**
 * The address to dial for the RouterOS API: the IPv4 the router itself
 * announced, else the datagram's source. `null` when neither is a usable IPv4
 * — a box with no address configured has nothing to dial over IP.
 */
export function reachableAddress(n: MndpNeighbour): string | null {
  if (n.ipv4 && n.ipv4 !== '0.0.0.0') return n.ipv4;
  if (n.sourceAddress && /^\d+\.\d+\.\d+\.\d+$/.test(n.sourceAddress) && n.sourceAddress !== '0.0.0.0') {
    return n.sourceAddress;
  }
  return null;
}

// ============================================================================
// Discovery on the wire
// ============================================================================

export interface MndpDiscoveryOptions {
  /** How long to listen, in ms. Default 4000. Clamped to [100, 60000]. */
  timeoutMs?: number;
  /** The probe is re-sent at this interval: UDP loses packets. Default 1000. */
  probeIntervalMs?: number;
  /**
   * Where the probe goes. Default: 255.255.255.255 PLUS the directed broadcast
   * of every IPv4 interface. Both, because a multi-homed Windows host sends
   * the limited broadcast out of ONE interface — the one its routing table
   * prefers — and that need not be the NIC the bench router is plugged into.
   */
  probeTargets?: string[];
  /** Destination port of the probe. Default 5678. */
  probePort?: number;
  /**
   * Local port. Default 5678, because routers ANNOUNCE to broadcast:5678 and a
   * socket on any other port hears only the replies addressed to it. When 5678
   * is already held — Winbox, another bench window, or a second discovery in
   * this process — discovery falls back to an ephemeral port and says so in
   * `listenPortFallback`.
   *
   * The socket is bound WITHOUT SO_REUSEADDR, and that is what makes the
   * fallback fire. With it, a second socket binds a held port without error
   * and the OS hands every unicast datagram to the first one: observed on
   * Windows, where the later socket received none of six datagrams sent to
   * the shared port. A discovery that hears nothing while reporting no
   * fallback reads as "the box is off". Without it, the bind fails
   * (EADDRINUSE or EACCES, whatever options the holder used) and the
   * ephemeral port still hears the replies to its own probes.
   */
  listenPort?: number;
  /** Local address to bind. Default all interfaces. */
  bindAddress?: string;
}

export interface MndpDiscovery {
  /** One entry per MAC heard; the newest datagram for a MAC wins. */
  neighbours: MndpNeighbour[];
  listenPort: number;
  /** True when 5678 was busy and only replies to our own port could be heard. */
  listenPortFallback: boolean;
  probesSent: number;
  /** Probes the OS refused to send (no route, broadcast denied). */
  sendErrors: number;
}

function ipv4ToInt(a: string): number | null {
  const parts = a.split('.');
  if (parts.length !== 4) return null;
  let v = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const o = Number(p);
    if (o > 255) return null;
    v = v * 256 + o;
  }
  return v >>> 0;
}

function intToIpv4(v: number): string {
  return [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff].join('.');
}

/** `null` for a /31 or /32, which have no broadcast address. */
export function directedBroadcast(address: string, netmask: string): string | null {
  const ip = ipv4ToInt(address);
  const mask = ipv4ToInt(netmask);
  if (ip === null || mask === null) return null;
  if (mask >= 0xfffffffe) return null;
  return intToIpv4(((ip & mask) | (~mask >>> 0)) >>> 0);
}

export function defaultProbeTargets(): string[] {
  const out = new Set<string>(['255.255.255.255']);
  for (const list of Object.values(networkInterfaces())) {
    for (const a of list ?? []) {
      if (a.internal || String(a.family) !== 'IPv4') continue;
      const b = directedBroadcast(a.address, a.netmask);
      if (b) out.add(b);
    }
  }
  return Array.from(out);
}

function clamp(v: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, Number.isFinite(v) ? v : lo));
}

function bindOnce(port: number, address: string | undefined): Promise<dgram.Socket> {
  return new Promise((resolve, reject) => {
    // No reuseAddr: see `listenPort` — sharing the port silently starves us.
    const s = dgram.createSocket({ type: 'udp4', reuseAddr: false });
    const onError = (err: Error) => {
      try {
        s.close();
      } catch {
        /* never bound */
      }
      reject(err);
    };
    s.once('error', onError);
    s.bind({ port, address }, () => {
      s.off('error', onError);
      try {
        s.setBroadcast(true);
      } catch (err) {
        onError(err as Error);
        return;
      }
      resolve(s);
    });
  });
}

async function openSocket(
  port: number,
  address: string | undefined,
): Promise<{ socket: dgram.Socket; fallback: boolean }> {
  try {
    return { socket: await bindOnce(port, address), fallback: false };
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (port !== 0 && (code === 'EADDRINUSE' || code === 'EACCES')) {
      return { socket: await bindOnce(0, address), fallback: true };
    }
    throw err;
  }
}

/**
 * What to do after hearing a neighbour: `stop` ends the window now, `settle`
 * shortens it to `settleMs` from now (never lengthens it), `null` changes
 * nothing.
 */
type Verdict = 'stop' | 'settle' | null;

async function listen(
  options: MndpDiscoveryOptions,
  judge: ((n: MndpNeighbour) => Verdict) | null,
  settleMs = 0,
): Promise<MndpDiscovery> {
  const timeoutMs = clamp(options.timeoutMs ?? DEFAULT_TIMEOUT_MS, 100, 60_000);
  const intervalMs = clamp(options.probeIntervalMs ?? DEFAULT_PROBE_INTERVAL_MS, 50, 10_000);
  const targets = options.probeTargets ?? defaultProbeTargets();
  const probePort = options.probePort ?? MNDP_PORT;

  const { socket, fallback } = await openSocket(options.listenPort ?? MNDP_PORT, options.bindAddress);

  return new Promise((resolve) => {
    const heard = new Map<string, MndpNeighbour>();
    let probesSent = 0;
    let sendErrors = 0;
    let done = false;
    let settling = false;
    const startedAt = Date.now();
    const listenPort = socket.address().port;

    const finish = () => {
      if (done) return;
      done = true;
      clearInterval(tick);
      clearTimeout(deadline);
      socket.removeAllListeners('message');
      // A late send callback or ICMP error after close must not surface as an
      // unhandled 'error' event: on a bench that kills the whole tool.
      socket.removeAllListeners('error');
      socket.on('error', () => undefined);
      try {
        socket.close();
      } catch {
        /* already closed */
      }
      resolve({
        neighbours: Array.from(heard.values()),
        listenPort,
        listenPortFallback: fallback,
        probesSent,
        sendErrors,
      });
    };

    socket.on('message', (msg, rinfo) => {
      if (done) return;
      const n = parseMndpPacket(msg, rinfo.address);
      if (!n) return;
      if (options.bindAddress) n.localAddress = options.bindAddress;
      heard.set(n.mac, n);
      const verdict = judge ? judge(n) : null;
      if (verdict === 'stop') {
        finish();
      } else if (verdict === 'settle' && !settling) {
        settling = true;
        const remaining = timeoutMs - (Date.now() - startedAt);
        if (settleMs < remaining) {
          clearTimeout(deadline);
          deadline = setTimeout(finish, Math.max(0, settleMs));
        }
      }
    });
    // A socket error ends the window early; what was already heard stands.
    socket.on('error', () => finish());

    const probe = () => {
      if (done) return;
      for (const target of targets) {
        socket.send(MNDP_PROBE, probePort, target, (err) => {
          if (err) sendErrors++;
          else probesSent++;
        });
      }
    };

    const tick = setInterval(probe, intervalMs);
    let deadline = setTimeout(finish, timeoutMs);
    probe();
  });
}

/** Everything that announced itself within the window. */
export async function discover(options: MndpDiscoveryOptions = {}): Promise<MndpDiscovery> {
  return listen(options, null);
}

/** A neighbour whose MAC lies in the candidate window of the typed one. NOT a proof. */
export interface MndpCandidate extends MndpNeighbour {
  /** `mac − typed`: 0 is the sticker MAC itself, 1 the usual factory bridge. */
  macOffset: number;
}

export interface MndpCandidateOptions extends MndpDiscoveryOptions {
  /**
   * After the first near (non-exact) candidate is heard, keep listening this
   * long for a closer one, then stop. Default 1500 ms — more than one probe
   * interval, so a box whose first reply was lost gets one more chance.
   * The exact MAC stops the window at once.
   */
  settleMs?: number;
}

export interface MndpCandidateSearch {
  /** Closest first. Empty when nothing in the window answered. */
  candidates: MndpCandidate[];
  discovery: MndpDiscovery;
}

function wantedMac(mac: string): string {
  const wanted = normalizeMac(mac);
  if (!wanted) {
    throw new MndpInputError(
      `L'adresse MAC saisie (« ${String(mac).slice(0, 40)} ») n'est pas lisible : 12 caractères hexadécimaux sont attendus, par exemple B8:69:F4:12:34:56. Corrigez-la puis relancez la recherche du routeur.`,
    );
  }
  if (!isUnicastMac(wanted)) {
    throw new MndpInputError(
      `L'adresse ${wanted} ne peut pas être celle d'un routeur (adresse nulle ou de groupe). Relisez l'étiquette du boîtier puis relancez la recherche du routeur.`,
    );
  }
  return wanted;
}

/**
 * Every neighbour in the candidate window of `mac`, closest first. Throws
 * `MndpInputError` — BEFORE any socket is opened — when `mac` is not a unicast
 * MAC, so "you typed it wrong" never reads as "it is off".
 */
export async function discoverCandidates(
  mac: string,
  options: MndpCandidateOptions = {},
): Promise<MndpCandidateSearch> {
  const wanted = wantedMac(mac);
  const settleMs = clamp(options.settleMs ?? 1_500, 0, 60_000);
  const discovery = await listen(
    options,
    (n) => {
      const d = macOffset(n.mac, wanted);
      if (d === null) return null;
      return d === 0 ? 'stop' : 'settle';
    },
    settleMs,
  );
  const candidates: MndpCandidate[] = [];
  for (const n of discovery.neighbours) {
    const d = macOffset(n.mac, wanted);
    if (d !== null) candidates.push({ ...n, macOffset: d });
  }
  candidates.sort((a, b) => a.macOffset - b.macOffset);
  return { candidates, discovery };
}

/**
 * The closest candidate for `mac` — the exact MAC when a box announces it,
 * otherwise the nearest one above it (a factory box answers from sticker + 1)
 * — or `null` when nothing in the window answered. Where to dial, nothing
 * more: prove it with `identifyFactoryBox()` before showing it as found.
 */
export async function discoverByMac(
  mac: string,
  options: MndpCandidateOptions = {},
): Promise<MndpCandidate | null> {
  return (await discoverCandidates(mac, options)).candidates[0] ?? null;
}

// ============================================================================
// One listen per bench link
// ============================================================================

/** One bench link to listen on: this PC's address on it and its mask. */
export interface MndpListenAddress {
  address: string;
  netmask: string;
}

export interface MndpAddressDiscovery {
  /** Every neighbour heard, tagged with the address that heard it
   *  (`localAddress`). The same MAC heard on two links appears twice. */
  neighbours: MndpNeighbour[];
  /** Per address: how the listen went (a link that vanished cannot bind). */
  perAddress: Array<{ address: string; listenPortFallback: boolean; probesSent: number; error: string | null }>;
}

/**
 * Listen on each bench link SEPARATELY — one socket bound to this PC's own
 * address on it, probing the limited broadcast and that link's directed
 * broadcast only — and tag every neighbour with the address that heard it.
 * The whole window always runs (no early stop): one round answers every
 * card that is looking for a box at the same time.
 *
 * Why binding attributes a box to a link, on Windows — the strong host
 * model, which Microsoft documents as the default of its TCP/IP stack since
 * Vista, for IPv4 and IPv6:
 *   - a datagram SENT from a socket bound to 192.168.88.11 leaves by the
 *     interface that holds 192.168.88.11, whatever the routing table prefers
 *     for the destination (strong host send) — so the probe reaches only the
 *     box on that link;
 *   - a reply addressed to 192.168.88.11 is accepted only on that interface
 *     (strong host receive), and only the socket bound to it receives it.
 * Unsolicited announcements are broadcasts: that Windows hands a broadcast
 * arriving on an interface to a socket bound to THAT interface's address
 * (and not to one bound to another interface's) is reasoned, not observed.
 * None of the three was observed on the bench hardware. The application
 * refuses a box heard on two links at once (`slots.ts` `planBoxRoute`,
 * NOT_ISOLATED), which is what a wrong attribution — or two links on one
 * switch — would look like.
 */
export async function discoverOnAddresses(
  addresses: MndpListenAddress[],
  options: Omit<MndpDiscoveryOptions, 'bindAddress' | 'probeTargets'> & {
    /** Where the probe from `address` goes. Default: the limited broadcast
     *  and that link's directed broadcast. (The harness probes loopback.) */
    probeTargetsFor?: (address: string) => string[];
  } = {},
): Promise<MndpAddressDiscovery> {
  const runs = await Promise.all(addresses.map(async (a) => {
    const targets = ['255.255.255.255'];
    const directed = directedBroadcast(a.address, a.netmask);
    if (directed) targets.push(directed);
    if (options.probeTargetsFor) targets.splice(0, targets.length, ...options.probeTargetsFor(a.address));
    try {
      const d = await listen({ ...options, bindAddress: a.address, probeTargets: targets }, null);
      return { a, d, error: null as string | null };
    } catch (err) {
      // The link went away between the reading and the bind (EADDRNOTAVAIL):
      // nothing is heard on it this round; the others still are.
      return { a, d: null, error: err instanceof Error ? err.message : String(err) };
    }
  }));
  const neighbours: MndpNeighbour[] = [];
  for (const r of runs) {
    for (const n of r.d?.neighbours ?? []) neighbours.push({ ...n, localAddress: r.a.address });
  }
  return {
    neighbours,
    perAddress: runs.map((r) => ({
      address: r.a.address,
      listenPortFallback: r.d?.listenPortFallback ?? false,
      probesSent: r.d?.probesSent ?? 0,
      error: r.error,
    })),
  };
}
