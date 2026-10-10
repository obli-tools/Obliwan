/**
 * ObliWAN — the files the server and the `obliwan-wg` sidecar exchange.
 *
 * The two processes share ONE directory (a named volume, OBLIWAN_WG_DIR) and
 * nothing else — no socket, no database for the sidecar:
 *
 *   wg-obliwan.conf   SERVER -> sidecar. The desired WireGuard config, in
 *                     wg-quick format. Holds the PRIVATE key, so it is written
 *                     mode 0600, atomically (temp file + rename), and never
 *                     logged. It is also a valid `wg-quick up` file, which is
 *                     the documented fallback on a host the sidecar cannot
 *                     drive (docker-compose.yml header).
 *   status.json       SIDECAR -> server. What the sidecar applied and saw:
 *                     state, latest handshake, rx/tx. No key but the PEER's
 *                     public one. Rewritten every cycle, so its age is the
 *                     sidecar's heartbeat.
 *   owned.json        sidecar only: what it CREATED on the host, so it removes
 *                     that and nothing else.
 *
 * This module imports no database and no server configuration: the sidecar
 * process loads it too, and must start with nothing but the volume.
 */

import crypto from 'crypto';
import fsp from 'fs/promises';
import path from 'path';
import {
  HOST_WG_INTERFACE,
  HOST_WG_KEEPALIVE_SECONDS,
  LINK_HOST_STATES,
  LINK_SUPERNET,
  ipv4CidrContains,
  isWireGuardKey,
  parseIpv4Cidr,
  type Ipv4Cidr,
  type LinkHostState,
} from '@obliwan/shared';

export const HOST_CONFIG_FILE = `${HOST_WG_INTERFACE}.conf`;
export const HOST_STATUS_FILE = 'status.json';
export const SIDECAR_OWNED_FILE = 'owned.json';
export const HOST_CONFIG_MODE = 0o600;
export const HOST_STATUS_MODE = 0o644;

/** Where both processes find the shared directory. The compose files set it
 *  to the volume's mount point in BOTH containers. */
export function defaultWgDir(): string {
  return process.env.OBLIWAN_WG_DIR || path.join(process.cwd(), 'data', 'wg');
}

export interface HostWgConfig {
  privateKey: string;
  /** The host's transit address with its prefix, e.g. `100.127.255.254/30`. */
  address: string;
  peerPublicKey: string;
  /** The CHR's PUBLIC address or name. */
  endpointHost: string;
  endpointPort: number;
  /** Always LINK_SUPERNET: the host routes every tunnel address to the CHR. */
  allowedIps: string;
  keepalive: number;
}

const HOSTNAME_RE = /^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;

/** Why `host` cannot be the CHR endpoint the host dials, or null. It must be
 *  reachable WITHOUT the link — so never an address inside the supernet the
 *  link itself is what routes. */
export function endpointHostProblem(host: string): string | null {
  if (!HOSTNAME_RE.test(host)) return 'it must be an IPv4 address or a DNS name';
  const ip = parseIpv4Cidr(host);
  const supernet = parseIpv4Cidr(LINK_SUPERNET) as Ipv4Cidr;
  if (ip && ipv4CidrContains(supernet, ip)) {
    return `it is inside ${LINK_SUPERNET}, which only this link would route: the endpoint must be the CHR's public address`;
  }
  return null;
}

export function hostConfigProblem(c: HostWgConfig): string | null {
  if (!isWireGuardKey(c.privateKey)) return 'PrivateKey is not a WireGuard key';
  if (!isWireGuardKey(c.peerPublicKey)) return 'the peer PublicKey is not a WireGuard key';
  const a = parseIpv4Cidr(c.address);
  const supernet = parseIpv4Cidr(LINK_SUPERNET) as Ipv4Cidr;
  if (!a || a.prefix !== 30 || !c.address.includes('/') || !ipv4CidrContains(supernet, a)) {
    return `Address must be a host address /30 inside ${LINK_SUPERNET}`;
  }
  if (a.address === a.network || a.address === a.network + 3) return 'Address must not be the network or broadcast address';
  if (c.allowedIps !== LINK_SUPERNET) return `AllowedIPs must be exactly ${LINK_SUPERNET}`;
  const endpoint = endpointHostProblem(c.endpointHost);
  if (endpoint) return `Endpoint host: ${endpoint}`;
  if (!Number.isInteger(c.endpointPort) || c.endpointPort < 1 || c.endpointPort > 65535) return 'Endpoint port out of range';
  if (!Number.isInteger(c.keepalive) || c.keepalive < 0 || c.keepalive > 65535) return 'PersistentKeepalive out of range';
  return null;
}

export function newHostConfig(args: Omit<HostWgConfig, 'allowedIps' | 'keepalive'>): HostWgConfig {
  return { ...args, allowedIps: LINK_SUPERNET, keepalive: HOST_WG_KEEPALIVE_SECONDS };
}

/** The wg-quick file. Throws on a config `hostConfigProblem` refuses. */
export function renderHostConfig(c: HostWgConfig): string {
  const problem = hostConfigProblem(c);
  if (problem) throw new TypeError(problem);
  return [
    '# Written by the ObliWAN server (services/concentratorLink). Do not edit: it is',
    '# rewritten by every "connect" job. Read by the obliwan-wg sidecar; also a valid',
    '# wg-quick file (the fallback documented in docker-compose.yml).',
    '[Interface]',
    `PrivateKey = ${c.privateKey}`,
    `Address = ${c.address}`,
    '',
    '[Peer]',
    `PublicKey = ${c.peerPublicKey}`,
    `Endpoint = ${c.endpointHost}:${c.endpointPort}`,
    `AllowedIPs = ${c.allowedIps}`,
    `PersistentKeepalive = ${c.keepalive}`,
    '',
  ].join('\n');
}

/** The same config in `wg setconf` / `wg syncconf` syntax: `Address` is a
 *  wg-quick field the `wg` tool refuses, so it is left out (the sidecar sets
 *  the address with `ip`). Exactly what `wg-quick strip` would print — plus
 *  `ListenPort` when the sidecar hands back the port the interface already uses.
 *
 *  WHY THE PORT IS HANDED BACK. `wg setconf` / `syncconf` set every interface
 *  setting the file omits to its zero value, and a listen port of 0 means
 *  "rebind to a random port". The sidecar syncs every few seconds, so without
 *  it the host changed its UDP source port on every pass: the CHR kept
 *  answering the previous port until the host spoke again (up to the 25 s
 *  keepalive), and every RouterOS API session through the link froze mid-reply
 *  — keepalive timeouts, an open circuit, the concentrator marked degraded.
 *  Seen in production on 2026-10-04: the host's port read 36615, then 60982;
 *  the CHR saw the peer move from :47895 to :54336 within 30 s, and about 6 MiB
 *  it sent never arrived. */
export function syncconfText(c: HostWgConfig, listenPort: number | null = null): string {
  if (listenPort !== null && (!Number.isInteger(listenPort) || listenPort < 1 || listenPort > 65535)) {
    throw new TypeError('ListenPort out of range');
  }
  return [
    '[Interface]',
    `PrivateKey = ${c.privateKey}`,
    ...(listenPort !== null ? [`ListenPort = ${listenPort}`] : []),
    '',
    '[Peer]',
    `PublicKey = ${c.peerPublicKey}`,
    `Endpoint = ${c.endpointHost}:${c.endpointPort}`,
    `AllowedIPs = ${c.allowedIps}`,
    `PersistentKeepalive = ${c.keepalive}`,
    '',
  ].join('\n');
}

export type ParsedHostConfig = { ok: true; config: HostWgConfig } | { ok: false; problem: string };

/** Parse what `renderHostConfig` wrote. Strict: one [Interface], one [Peer],
 *  only the six keys it writes. The problem text never quotes a value. */
export function parseHostConfig(text: string): ParsedHostConfig {
  const sections: Array<{ name: string; kv: Map<string, string> }> = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) continue;
    const head = /^\[(\w+)\]$/.exec(line);
    if (head) {
      sections.push({ name: head[1].toLowerCase(), kv: new Map() });
      continue;
    }
    const eq = line.indexOf('=');
    if (eq === -1 || sections.length === 0) return { ok: false, problem: 'malformed line in the config' };
    sections[sections.length - 1].kv.set(line.slice(0, eq).trim().toLowerCase(), line.slice(eq + 1).trim());
  }
  const iface = sections.filter((s) => s.name === 'interface');
  const peers = sections.filter((s) => s.name === 'peer');
  if (iface.length !== 1 || peers.length !== 1 || sections.length !== 2) {
    return { ok: false, problem: 'the config must hold exactly one [Interface] and one [Peer]' };
  }
  const i = iface[0].kv;
  const p = peers[0].kv;
  const allowed = new Set(['privatekey', 'address', 'publickey', 'endpoint', 'allowedips', 'persistentkeepalive']);
  for (const k of [...i.keys(), ...p.keys()]) {
    if (!allowed.has(k)) return { ok: false, problem: `unexpected key "${k}" in the config` };
  }
  const endpoint = p.get('endpoint') ?? '';
  const colon = endpoint.lastIndexOf(':');
  if (colon <= 0) return { ok: false, problem: 'Endpoint must be host:port' };
  const config: HostWgConfig = {
    privateKey: i.get('privatekey') ?? '',
    address: i.get('address') ?? '',
    peerPublicKey: p.get('publickey') ?? '',
    endpointHost: endpoint.slice(0, colon),
    endpointPort: Number(endpoint.slice(colon + 1)),
    allowedIps: p.get('allowedips') ?? '',
    keepalive: Number(p.get('persistentkeepalive') ?? NaN),
  };
  const problem = hostConfigProblem(config);
  return problem ? { ok: false, problem } : { ok: true, config };
}

export function configHash(text: string): string {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

// ============================================================================
// Files
// ============================================================================

/** The slice of fs/promises the writers use: a test seam to observe the mode
 *  a file is created with on a platform (Windows) whose stat cannot show it. */
export type WgFs = Pick<typeof fsp, 'mkdir' | 'open' | 'chmod' | 'rename' | 'unlink' | 'readFile'>;

export async function writeFileAtomic(dir: string, name: string, text: string, mode: number, fs: WgFs): Promise<string> {
  await fs.mkdir(dir, { recursive: true });
  const target = path.join(dir, name);
  const tmp = path.join(dir, `.${name}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`);
  try {
    // Created with `mode` (the umask can only narrow it) and chmod'ed to it
    // explicitly, so the private key is never readable by anyone else, not
    // even for the instant before the rename.
    const fh = await fs.open(tmp, 'wx', mode);
    try {
      await fh.writeFile(text, 'utf8');
      await fh.sync();
    } finally {
      await fh.close();
    }
    await fs.chmod(tmp, mode);
    await fs.rename(tmp, target);
  } catch (err) {
    await fs.unlink(tmp).catch(() => undefined);
    throw err;
  }
  return target;
}

/** Write the desired config (0600). Returns its path and hash. */
export async function writeHostConfigFile(
  dir: string,
  config: HostWgConfig,
  fs: WgFs = fsp,
): Promise<{ file: string; hash: string }> {
  const text = renderHostConfig(config);
  const file = await writeFileAtomic(dir, HOST_CONFIG_FILE, text, HOST_CONFIG_MODE, fs);
  return { file, hash: configHash(text) };
}

export async function readHostConfigText(dir: string, fs: WgFs = fsp): Promise<string | null> {
  try {
    return await fs.readFile(path.join(dir, HOST_CONFIG_FILE), 'utf8');
  } catch {
    return null;
  }
}

export interface SidecarPeerStatus {
  publicKey: string;
  endpoint: string | null;
  /** Unix seconds of the latest handshake; 0 = never. */
  latestHandshake: number;
  rxBytes: number;
  txBytes: number;
}

export interface SidecarStatusFile {
  version: 1;
  state: LinkHostState;
  message: string;
  at: string;
  enabled: boolean;
  /** `configHash` of the config file the sidecar applied, or null. */
  configHash: string | null;
  address: string | null;
  route: boolean;
  peer: SidecarPeerStatus | null;
  warnings: string[];
}

export async function writeSidecarStatus(dir: string, status: SidecarStatusFile, fs: WgFs = fsp): Promise<void> {
  await writeFileAtomic(dir, HOST_STATUS_FILE, `${JSON.stringify(status, null, 2)}\n`, HOST_STATUS_MODE, fs);
}

export async function readSidecarStatus(dir: string, fs: WgFs = fsp): Promise<SidecarStatusFile | null> {
  let text: string;
  try {
    text = await fs.readFile(path.join(dir, HOST_STATUS_FILE), 'utf8');
  } catch {
    return null;
  }
  try {
    const s = JSON.parse(text) as Partial<SidecarStatusFile>;
    if (s.version !== 1 || typeof s.at !== 'string' || !(LINK_HOST_STATES as readonly string[]).includes(String(s.state))) {
      return null;
    }
    return {
      version: 1,
      state: s.state as LinkHostState,
      message: typeof s.message === 'string' ? s.message : '',
      at: s.at,
      enabled: s.enabled === true,
      configHash: typeof s.configHash === 'string' ? s.configHash : null,
      address: typeof s.address === 'string' ? s.address : null,
      route: s.route === true,
      peer: s.peer && typeof s.peer === 'object' ? (s.peer as SidecarPeerStatus) : null,
      warnings: Array.isArray(s.warnings) ? s.warnings.filter((w): w is string => typeof w === 'string') : [],
    };
  } catch {
    return null;
  }
}
