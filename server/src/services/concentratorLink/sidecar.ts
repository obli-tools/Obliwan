/**
 * ObliWAN — the HOST half of the WireGuard link: one reconciliation pass of
 * the `obliwan-wg` sidecar (entrypoint: src/wgSidecar.ts).
 *
 * The sidecar runs from the SERVER image, as a second compose service with
 * `network_mode: host` and `cap_add: NET_ADMIN`, sharing one volume with the
 * server. Each pass reads the desired config the server wrote
 * (`wg-obliwan.conf`), makes the host match it with `ip` and `wg`, and writes
 * what it saw to `status.json`.
 *
 * ┌─ IT TOUCHES ITS OWN THINGS AND NOTHING ELSE ─────────────────────────────┐
 * │ One interface, `wg-obliwan`, created by this sidecar and recorded in     │
 * │ `owned.json` BEFORE anything else is configured on it. An interface of    │
 * │ that name the sidecar did not create is `foreign_interface`: reported,   │
 * │ never configured, never removed. One route, 100.64.0.0/10 dev wg-obliwan, │
 * │ added with `ip route add` (never `replace`): if the host already routes  │
 * │ 100.64.0.0/10 elsewhere the pass stops at `route_conflict` having created │
 * │ nothing, and more specific routes inside it that use another device are │
 * │ reported as warnings, not removed.                                      │
 * │ `owned.json` names the interface INSTANCE, not just the name: its        │
 * │ ifindex as read right after `ip link add`. A `wg-obliwan` whose ifindex  │
 * │ differs (a host reboot dropped ours, then somebody ran the wg-quick      │
 * │ fallback) is foreign, and a marker naming an interface that no longer    │
 * │ exists is cleared rather than kept to match a later one by name.         │
 * │ The interface lives in the HOST's network namespace, not the container's: │
 * │ stopping the sidecar does NOT take the link down (a restart must not cut  │
 * │ the fleet off).                                                          │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ IT REMOVES ON ONE EXPLICIT ORDER ONLY ─────────────────────────────────┐
 * │ OBLIWAN_WG_ENABLED is read three ways (`sidecarModeOf`):                 │
 * │   true / 1      act.                                                    │
 * │   false / 0     remove what this sidecar created (`ip link del` of the   │
 * │                 instance owned.json names, which takes its address and   │
 * │                 route with it), configure nothing.                       │
 * │   anything else (unset, empty, a typo) configure NOTHING and remove     │
 * │                 NOTHING. A redeploy whose .env lost the line must not    │
 * │                 cut the fleet off.                                       │
 * │ A config file that is MISSING (`no_config`) or UNREADABLE (`error`) is   │
 * │ the same: reported, and the interface left as it is. When the CHR API    │
 * │ itself goes through the tunnel, removing the link cuts ObliWAN off the   │
 * │ CHR and every site, so only an explicit `false` does it.                 │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * WHY CONTAINERS ON THE BRIDGE USE THE LINK WITH NO EXTRA RULE. Docker
 * masquerades what leaves a bridge network for any other interface (bridge
 * driver option `enable_ip_masquerade`, default true; docs.docker.com, "Bridge
 * network driver": "Uses masquerading to give containers external network
 * access"), and iptables' MASQUERADE maps to "the IP address of the interface
 * the packet is going out" (iptables-extensions(8)). With the route below, a
 * packet from the server container to 100.64.x.y leaves through wg-obliwan,
 * whose only address is the transit host address, so it reaches the CHR with
 * that source — the one address the CHR's peer, firewall accept and srcnat
 * name. The CHR's replies come back through the tunnel to that address and
 * conntrack returns them to the container; Docker's FORWARD rules already
 * accept the reply direction (RELATED,ESTABLISHED) of a container-initiated
 * connection. MASQUERADE also "forgets connections when the interface goes
 * down": a flap of wg-obliwan drops the sessions through it, and the RouterOS
 * pool re-dials.
 *
 * ┌─ WITHOUT THE WIREGUARD KERNEL MODULE ───────────────────────────────────┐
 * │ `ip link add ... type wireguard` fails and the pass reports              │
 * │ `kernel_module_missing` with KERNEL_FALLBACK below, having created       │
 * │ nothing. The kernel module is in mainline Linux since 5.6.               │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * The private key is in the config and in `wg syncconf`'s input (the runner in
 * wgSidecar.ts hands it as a 0600 file in a fresh 0700 directory, removed as soon
 * as the command ends: fopen("/dev/stdin") fails on the socket Node gives a
 * child as stdin), and nowhere else: never on a command line (where `ps` shows it), never in status.json
 * (`wg show dump`'s first line, which carries it, is discarded unread), and
 * scrubbed from any tool output before a message is formed.
 */

import path from 'path';
import fsp from 'fs/promises';
import { HOST_WG_INTERFACE, LINK_SUPERNET } from '@obliwan/shared';
import {
  HOST_CONFIG_FILE,
  HOST_STATUS_MODE,
  SIDECAR_OWNED_FILE,
  configHash,
  parseHostConfig,
  syncconfText,
  writeFileAtomic,
  writeSidecarStatus,
  type SidecarPeerStatus,
  type SidecarStatusFile,
  type WgFs,
} from './wgConfig';

export interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}
/** Runs `ip` or `wg` with an argument vector (no shell) and optional stdin. */
export type CommandRunner = (cmd: 'ip' | 'wg', args: string[], stdin?: string) => Promise<RunResult>;

/** OBLIWAN_WG_ENABLED, read three ways (header, IT REMOVES ON ONE EXPLICIT ORDER ONLY). */
export type SidecarMode = 'on' | 'off' | 'unset';

export function sidecarModeOf(raw: string | undefined): SidecarMode {
  const v = (raw ?? '').trim().toLowerCase();
  if (v === 'true' || v === '1') return 'on';
  if (v === 'false' || v === '0') return 'off';
  return 'unset';
}

export interface SidecarDeps {
  dir: string;
  mode: SidecarMode;
  run: CommandRunner;
  fs?: WgFs;
  now?: () => Date;
}

export const KERNEL_FALLBACK =
  'This host kernel cannot create a WireGuard interface. Either load the module on the host ' +
  '(`modprobe wireguard`; built into Linux 5.6 and later) and restart the obliwan-wg service, or ' +
  'bring the link up by hand with the same file: install wireguard-tools (and wireguard-go if the ' +
  'kernel has no module) on the host, then `wg-quick up <volume>/wg-obliwan.conf` — that file is ' +
  'a valid wg-quick config and wg-quick adds the 100.64.0.0/10 route itself. Then stop this ' +
  'sidecar (drop `wg` from COMPOSE_PROFILES): it never configures or removes an interface it did ' +
  'not create, and would only keep reporting that one as foreign.';

const KERNEL_MISSING_RE = /unknown device type|not supported|no such device|unknown type|protocol not supported/i;

interface Owned {
  interface: string;
  createdAt: string;
  /** The ifindex of the instance this sidecar created; null only when it
   *  could not be read back right after creation. */
  ifindex: number | null;
}

interface LinkInfo {
  exists: boolean;
  ifindex: number | null;
}

class PassStop extends Error {
  constructor(readonly state: SidecarStatusFile['state'], message: string) {
    super(message);
  }
}

function scrub(text: string, secret: string | null): string {
  const t = text.trim().slice(0, 400);
  return secret ? t.split(secret).join('***') : t;
}

async function readOwned(dir: string, fs: WgFs): Promise<Owned | null> {
  try {
    const o = JSON.parse(await fs.readFile(path.join(dir, SIDECAR_OWNED_FILE), 'utf8')) as Partial<Owned>;
    if (!o || o.interface !== HOST_WG_INTERFACE) return null;
    return {
      interface: o.interface,
      createdAt: typeof o.createdAt === 'string' ? o.createdAt : '',
      ifindex: typeof o.ifindex === 'number' && Number.isInteger(o.ifindex) ? o.ifindex : null,
    };
  } catch {
    return null;
  }
}

async function writeOwned(dir: string, fs: WgFs, now: Date, ifindex: number | null): Promise<void> {
  const o: Owned = { interface: HOST_WG_INTERFACE, createdAt: now.toISOString(), ifindex };
  await writeFileAtomic(dir, SIDECAR_OWNED_FILE, `${JSON.stringify(o)}\n`, HOST_STATUS_MODE, fs);
}

async function clearOwned(dir: string, fs: WgFs): Promise<void> {
  await fs.unlink(path.join(dir, SIDECAR_OWNED_FILE)).catch(() => undefined);
}

/** `ip -o link show dev wg-obliwan` prints `<ifindex>: wg-obliwan: <FLAGS> ...`. */
async function linkInfo(run: CommandRunner): Promise<LinkInfo> {
  const r = await run('ip', ['-o', 'link', 'show', 'dev', HOST_WG_INTERFACE]);
  if (r.code !== 0 || !r.stdout.includes(HOST_WG_INTERFACE)) return { exists: false, ifindex: null };
  const m = /^\s*(\d+):\s/.exec(r.stdout);
  return { exists: true, ifindex: m ? Number(m[1]) : null };
}

/** Is the interface present now the one owned.json recorded? A marker without
 *  an ifindex (it could not be read at creation) matches by name only. */
function isOurs(owned: Owned | null, info: LinkInfo): boolean {
  if (!owned || !info.exists) return false;
  return owned.ifindex === null || owned.ifindex === info.ifindex;
}

/** Remove what this sidecar created, and only that. Returns a sentence. */
async function teardown(dir: string, deps: SidecarDeps, fs: WgFs): Promise<string> {
  const owned = await readOwned(dir, fs);
  if (!owned) return '';
  const info = await linkInfo(deps.run);
  if (!info.exists) {
    await clearOwned(dir, fs);
    return ` The ${HOST_WG_INTERFACE} this sidecar created no longer exists; its marker was cleared.`;
  }
  if (!isOurs(owned, info)) {
    await clearOwned(dir, fs);
    return (
      ` ${HOST_WG_INTERFACE} exists but is not the instance this sidecar created (ifindex ${info.ifindex}, ` +
      `recorded ${owned.ifindex}); it was left untouched and the stale marker cleared.`
    );
  }
  const r = await deps.run('ip', ['link', 'del', 'dev', HOST_WG_INTERFACE]);
  if (r.code !== 0) return ` Removing ${HOST_WG_INTERFACE} failed: ${scrub(r.stderr, null)}`;
  await clearOwned(dir, fs);
  return ` ${HOST_WG_INTERFACE} (created by this sidecar) was removed.`;
}

/** Parse `wg show <if> dump`. The FIRST line (it carries the private key) is
 *  skipped without being looked at. */
export function parseWgDump(stdout: string): SidecarPeerStatus | null {
  const lines = stdout.split('\n').filter((l) => l.trim() !== '');
  for (const line of lines.slice(1)) {
    const f = line.split('\t');
    if (f.length < 8) continue;
    return {
      publicKey: f[0],
      endpoint: f[2] === '(none)' ? null : f[2],
      latestHandshake: Number(f[4]) || 0,
      rxBytes: Number(f[5]) || 0,
      txBytes: Number(f[6]) || 0,
    };
  }
  return null;
}

/** One pass. Never throws: every outcome is a status, written and returned. */
export async function reconcileOnce(deps: SidecarDeps): Promise<SidecarStatusFile> {
  const fs = deps.fs ?? fsp;
  const now = (deps.now ?? (() => new Date()))();
  const status: SidecarStatusFile = {
    version: 1,
    state: 'error',
    message: '',
    at: now.toISOString(),
    enabled: deps.mode === 'on',
    configHash: null,
    address: null,
    route: false,
    peer: null,
    warnings: [],
  };
  let secret: string | null = null;

  const must = async (cmd: 'ip' | 'wg', args: string[], what: string, stdin?: string): Promise<RunResult> => {
    const r = await deps.run(cmd, args, stdin);
    if (r.code !== 0) throw new PassStop('error', `${what} failed: ${scrub(r.stderr || r.stdout, secret)}`);
    return r;
  };

  try {
    if (deps.mode === 'unset') {
      throw new PassStop(
        'disabled',
        'OBLIWAN_WG_ENABLED is not set: this sidecar configures nothing and removes nothing on the host ' +
          '(true acts; an explicit false removes what it created).',
      );
    }
    if (deps.mode === 'off') {
      const removed = await teardown(deps.dir, deps, fs);
      throw new PassStop('disabled', `OBLIWAN_WG_ENABLED=false: this sidecar configures nothing on the host.${removed}`);
    }

    let text: string;
    try {
      text = await fs.readFile(path.join(deps.dir, HOST_CONFIG_FILE), 'utf8');
    } catch (err) {
      // Neither case removes anything: a link that works stays up.
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'ENOENT') {
        throw new PassStop(
          'no_config',
          `The server has not written ${HOST_CONFIG_FILE} yet. Nothing was changed on the host (an ` +
            `interface this sidecar created earlier is left as it is).`,
        );
      }
      throw new PassStop('error', `${HOST_CONFIG_FILE} could not be read (${code ?? 'error'}); nothing was changed on the host.`);
    }
    const parsed = parseHostConfig(text);
    if (!parsed.ok) throw new PassStop('error', `${HOST_CONFIG_FILE} refused: ${parsed.problem}. Nothing changed.`);
    const c = parsed.config;
    secret = c.privateKey;

    let owned = await readOwned(deps.dir, fs);
    const info = await linkInfo(deps.run);
    if (owned && !info.exists) {
      // The instance the marker named is gone (a host reboot): it names nothing.
      await clearOwned(deps.dir, fs);
      owned = null;
    }
    const exists = info.exists;
    if (exists && !isOurs(owned, info)) {
      if (owned) await clearOwned(deps.dir, fs);
      throw new PassStop(
        'foreign_interface',
        `An interface named ${HOST_WG_INTERFACE} exists on this host and is not the one this sidecar ` +
          'created; it is left untouched. Remove or rename it, or stop this sidecar.',
      );
    }

    // The /10 route, judged BEFORE anything is created.
    const exact = await deps.run('ip', ['-o', '-4', 'route', 'show', 'exact', LINK_SUPERNET]);
    const exactLines = exact.stdout.split('\n').filter((l) => l.trim() !== '');
    const elsewhere = exactLines.filter((l) => !new RegExp(`\\bdev ${HOST_WG_INTERFACE}\\b`).test(l));
    if (elsewhere.length > 0) {
      throw new PassStop(
        'route_conflict',
        `This host already routes ${LINK_SUPERNET} elsewhere (${scrub(elsewhere[0], null)}); nothing ` +
          'was created. If that route reaches the tunnel addresses, this link is not needed ' +
          '(set OBLIWAN_WG_ENABLED=false); otherwise remove it first.',
      );
    }
    const inner = await deps.run('ip', ['-o', '-4', 'route', 'show', 'root', LINK_SUPERNET]);
    for (const l of inner.stdout.split('\n')) {
      if (l.trim() === '' || new RegExp(`\\bdev ${HOST_WG_INTERFACE}\\b`).test(l)) continue;
      status.warnings.push(`a more specific route inside ${LINK_SUPERNET} uses another device and wins over the link: ${scrub(l, null)}`);
    }

    if (!exists) {
      const r = await deps.run('ip', ['link', 'add', 'dev', HOST_WG_INTERFACE, 'type', 'wireguard']);
      if (r.code !== 0) {
        const why = scrub(r.stderr, null);
        if (KERNEL_MISSING_RE.test(why)) throw new PassStop('kernel_module_missing', `${why}. ${KERNEL_FALLBACK}`);
        throw new PassStop('error', `creating ${HOST_WG_INTERFACE} failed: ${why}`);
      }
      // Recorded at once, with the instance's ifindex, so a failure below
      // still leaves it removable — and only it.
      await writeOwned(deps.dir, fs, now, (await linkInfo(deps.run)).ifindex);
    }

    // The port the interface listens on NOW, handed back to syncconf: a file
    // without ListenPort rebinds the interface to a random port on every pass
    // (wgConfig.ts `syncconfText`). 0 is a fresh interface: WireGuard picks a
    // port on this pass, and every later pass keeps it.
    const portRead = await deps.run('wg', ['show', HOST_WG_INTERFACE, 'listen-port']);
    const port = portRead.code === 0 && /^\d+$/.test(portRead.stdout.trim()) ? Number(portRead.stdout.trim()) : null;
    if (port === null) {
      status.warnings.push(
        `the listen port of ${HOST_WG_INTERFACE} could not be read: this pass may move it (the CHR follows on the next packet)`,
      );
    }
    // Keys and peer from STDIN, never argv.
    await must('wg', ['syncconf', HOST_WG_INTERFACE, '/dev/stdin'], 'wg syncconf', syncconfText(c, port !== null && port > 0 ? port : null));

    // Exactly one address on our interface: ours.
    const addrs = await must('ip', ['-o', '-4', 'addr', 'show', 'dev', HOST_WG_INTERFACE], 'reading addresses');
    const present = [...addrs.stdout.matchAll(/\binet (\d+\.\d+\.\d+\.\d+\/\d+)/g)].map((m) => m[1]);
    for (const a of present) {
      if (a !== c.address) await must('ip', ['address', 'del', a, 'dev', HOST_WG_INTERFACE], `removing stale ${a}`);
    }
    if (!present.includes(c.address)) {
      await must('ip', ['address', 'add', c.address, 'dev', HOST_WG_INTERFACE], `adding ${c.address}`);
    }
    status.address = c.address;
    await must('ip', ['link', 'set', 'up', 'dev', HOST_WG_INTERFACE], `bringing ${HOST_WG_INTERFACE} up`);

    if (exactLines.length === 0) {
      await must('ip', ['route', 'add', LINK_SUPERNET, 'dev', HOST_WG_INTERFACE], `routing ${LINK_SUPERNET}`);
    }
    status.route = true;

    const dump = await must('wg', ['show', HOST_WG_INTERFACE, 'dump'], 'wg show');
    status.peer = parseWgDump(dump.stdout);
    status.configHash = configHash(text);
    status.state = 'up';
    const hs = status.peer?.latestHandshake ?? 0;
    status.message = hs > 0
      ? `${HOST_WG_INTERFACE} is up; latest handshake with the CHR ${Math.max(0, Math.round(now.getTime() / 1000 - hs))} s ago.`
      : `${HOST_WG_INTERFACE} is up; no handshake with the CHR yet.`;
  } catch (err) {
    if (err instanceof PassStop) {
      status.state = err.state;
      status.message = err.message;
    } else {
      status.state = 'error';
      status.message = scrub(err instanceof Error ? err.message : String(err), secret);
    }
  }

  try {
    await writeSidecarStatus(deps.dir, status, fs);
  } catch {
    // The volume is not writable: the server will see a stale status and say
    // "sidecar absent", which is the truth from where it stands.
  }
  return status;
}
