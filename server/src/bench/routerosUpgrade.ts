import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  compareRouterOsVersion,
  isRouterOsReleaseVersion,
  parseRouterOsVersion,
  routerOsPackageArchFromResource,
  tryRouterOsPackageUrl,
} from '@obliwan/shared';
import { bareVersion, BoxWaitError, frenchDuration, waitForBox } from './boxWait';
import { normalizeMac, type MndpCandidate } from './mndp';
import {
  judgeReportedSize,
  listFiles,
  passwordScrubber,
  removeFile,
  routerErrorKind,
  withProvenSession,
  FactoryProvisioningError,
  type DialFn,
  type FactoryBoxIdentification,
  type FactoryIdentifyRequest,
  type FileRow,
  type RouterOsApiSession,
  type SftpUploadFn,
} from './routerosApply';
import { sftpUploadOverSsh } from './sftp';
import { localDataDir } from './window';

/**
 * ObliWAN bench — bring a box's RouterOS up to the fleet target, so that a
 * template whose `os_min` it does not meet can be compiled for it.
 *
 * ┌─ ONE BUTTON, IN THIS ORDER ──────────────────────────────────────────────┐
 * │ 1. A FRESH session, and the MAC proof on it (`withProvenSession`) before │
 * │    anything is written: the box that is upgraded is the box on the label.│
 * │    On that session: version, `architecture-name`, every installed       │
 * │    package, free space.                                                 │
 * │ 2. The PC downloads every installed package at the target version from   │
 * │    download.mikrotik.com, over HTTPS only, at the URL the shared helper │
 * │    builds (`tryRouterOsPackageUrl`) — never one taken from elsewhere: a  │
 * │    URL the plan sent is compared with it and refused if it differs. The  │
 * │    files are cached per version under %LOCALAPPDATA%\ObliWAN\bench-cache │
 * │    \routeros\<version>\ (forty boxes download once), each with its      │
 * │    SHA-256 beside it so a cut or damaged cached copy is fetched again.   │
 * │ 3. Free space checked; the packages put on the box by SFTP and their     │
 * │    sizes checked on the proven session; `/system/reboot`.               │
 * │ 4. Wait, bounded (8 min), for the box to come back — MNDP by MAC, then   │
 * │    login — and take the SAME MAC proof again (`waitForBox`); its version │
 * │    must now be the target.                                               │
 * │ The caller then asks ObliWAN for the plan again: that answer decides.   │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHAT PROVES A PACKAGE IS MIKROTIK'S ────────────────────────────────────┐
 * │ RouterOS itself: it verifies the signature of every .npk it installs at  │
 * │ boot and ignores one that does not verify (MikroTik's documented upgrade │
 * │ behaviour; not observed by this code). The bench adds only what keeps a  │
 * │ wrong file from costing a reboot: HTTPS to MikroTik's own host, a 200, a │
 * │ size within bounds and equal to the announced length, no HTML. A package │
 * │ the box refused shows as a box that rebooted and is still on its old     │
 * │ version: `PACKAGE_REJECTED`.                                              │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ FALLBACK: THE ROUTER'S OWN UPDATE, ONLY WHEN THE PC IS OFFLINE ─────────┐
 * │ When a download fails without any HTTP answer (no route, no DNS, a       │
 * │ timeout), the PC cannot reach MikroTik, and the box is asked instead:    │
 * │ `/system/package/update` check-for-updates, then `install` — ONLY when   │
 * │ the version it offers on its channel is exactly the target (the other    │
 * │ of stable / long-term is tried once, and the channel put back if neither │
 * │ matches). A box that cannot reach MikroTik either is `BOTH_OFFLINE`.     │
 * │ An HTTP refusal (404: not published for this architecture) is NOT        │
 * │ offline and does not fall back.                                          │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * RouterBOARD firmware (`/system/routerboard upgrade`) is never touched: it
 * is a separate image with its own failure modes, and nothing here needs it.
 *
 * REASONED, NOT OBSERVED: no line of this module has run against a MikroTik.
 * Built against `testing/routerosUpgrade.verify.ts` (a RouterOS double and a
 * real ssh2 SFTP server for `sftp.ts`). The first lab run should check: that
 * `free-hdd-space` reads in bytes over the API; that an .npk put at the root
 * of the file system by SFTP is installed at the next reboot; that
 * `/system/reboot` over the API reboots with no prompt; the fields of
 * `/system/package/update/print` and whether `check-for-updates` and
 * `install` answer at once or stream until done.
 */

// ============================================================================
// The download cache
// ============================================================================

/** A RouterOS 7 package weighs from a few KiB (small extras) to tens of MiB. */
export const MIN_PACKAGE_BYTES = 4 * 1024;
export const MAX_PACKAGE_BYTES = 128 * 1024 * 1024;
/** Kept free on the box beyond the packages themselves. */
const SPACE_MARGIN_BYTES = 512 * 1024;
/** The only host a package (or a redirect of one) is fetched from. */
const PACKAGE_HOSTS = /^(?:[a-z0-9-]+\.)*mikrotik\.com$/;

export type DownloadErrorKind = 'offline' | 'missing' | 'http' | 'size' | 'refused';

export class DownloadError extends Error {
  constructor(readonly kind: DownloadErrorKind, message: string) {
    super(message);
    this.name = 'DownloadError';
  }
}

/** Fetches one package. Throws `DownloadError`; `offline` means no HTTP answer at all. */
export type DownloadFn = (url: string, opts: { timeoutMs: number; maxBytes: number }) => Promise<Buffer>;

/** The real download: HTTPS, MikroTik's hosts only, redirects followed by hand
 *  (https and the same hosts only), a size cap while reading. */
export const httpsDownload: DownloadFn = async (url, opts) => {
  let current = url;
  for (let hop = 0; hop < 4; hop++) {
    const u = new URL(current);
    if (u.protocol !== 'https:' || !PACKAGE_HOSTS.test(u.hostname)) {
      throw new DownloadError('refused', `adresse de téléchargement refusée (${u.protocol}//${u.hostname})`);
    }
    let res: Response;
    try {
      res = await fetch(current, { redirect: 'manual', signal: AbortSignal.timeout(opts.timeoutMs) });
    } catch (err) {
      const e = err as Error & { cause?: { code?: string } };
      throw new DownloadError('offline', e?.name === 'TimeoutError' ? 'pas de réponse' : (e?.cause?.code ?? e?.message ?? String(err)));
    }
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get('location');
      if (!loc) throw new DownloadError('http', `redirection ${res.status} sans destination`);
      current = new URL(loc, current).toString();
      continue;
    }
    if (res.status === 404) throw new DownloadError('missing', 'paquet non publié (404)');
    if (res.status !== 200) throw new DownloadError('http', `réponse ${res.status}`);
    if (/text\/html/i.test(res.headers.get('content-type') ?? '')) {
      throw new DownloadError('refused', 'une page web a été reçue à la place du paquet');
    }
    const announced = Number(res.headers.get('content-length') ?? NaN);
    if (Number.isFinite(announced) && announced > opts.maxBytes) throw new DownloadError('size', `taille annoncée ${announced} octets`);
    const chunks: Buffer[] = [];
    let size = 0;
    try {
      for await (const chunk of res.body as unknown as AsyncIterable<Uint8Array>) {
        size += chunk.length;
        if (size > opts.maxBytes) throw new DownloadError('size', `plus de ${opts.maxBytes} octets`);
        chunks.push(Buffer.from(chunk));
      }
    } catch (err) {
      if (err instanceof DownloadError) throw err;
      throw new DownloadError('offline', 'téléchargement interrompu');
    }
    const body = Buffer.concat(chunks);
    if (Number.isFinite(announced) && announced !== body.length) {
      throw new DownloadError('size', `${body.length} octets reçus sur ${announced} annoncés`);
    }
    return body;
  }
  throw new DownloadError('http', 'trop de redirections');
};

/** A package's announced size (HEAD, redirects followed by hand, MikroTik's
 *  hosts only), or null: unknown is never "fits". */
export async function httpsHeadSize(url: string, opts: { timeoutMs: number }): Promise<number | null> {
  let current = url;
  for (let hop = 0; hop < 4; hop++) {
    const u = new URL(current);
    if (u.protocol !== 'https:' || !PACKAGE_HOSTS.test(u.hostname)) return null;
    let res: Response;
    try {
      res = await fetch(current, { method: 'HEAD', redirect: 'manual', signal: AbortSignal.timeout(opts.timeoutMs) });
    } catch {
      return null;
    }
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get('location');
      if (!loc) return null;
      current = new URL(loc, current).toString();
      continue;
    }
    if (res.status !== 200) return null;
    const n = Number(res.headers.get('content-length') ?? NaN);
    return Number.isFinite(n) && n >= MIN_PACKAGE_BYTES && n <= MAX_PACKAGE_BYTES ? n : null;
  }
  return null;
}

/** %LOCALAPPDATA%\ObliWAN\bench-cache\routeros */
export function defaultPackageCacheDir(): string {
  return join(localDataDir(), 'bench-cache', 'routeros');
}

const sha256 = (b: Buffer): string => createHash('sha256').update(b).digest('hex');

/** The cached copy, if it is whole (its SHA-256 matches the one written beside it). */
function readCached(path: string): Buffer | null {
  try {
    if (!existsSync(path) || !existsSync(`${path}.sha256`)) return null;
    const body = readFileSync(path);
    const want = readFileSync(`${path}.sha256`, 'utf8').trim();
    if (sha256(body) === want && body.length >= MIN_PACKAGE_BYTES && body.length <= MAX_PACKAGE_BYTES) return body;
    rmSync(path, { force: true });
    rmSync(`${path}.sha256`, { force: true });
  } catch {
    /* unreadable cache: download again */
  }
  return null;
}

/** Written to a temporary name, then renamed; the SHA-256 last. A cut write
 *  never looks like a cached package. Best effort: a cache that cannot be
 *  written costs a download on the next box, nothing else. */
function writeCached(path: string, body: Buffer): void {
  try {
    mkdirSync(join(path, '..'), { recursive: true });
    const tmp = `${path}.part`;
    writeFileSync(tmp, body);
    renameSync(tmp, path);
    writeFileSync(`${path}.sha256`, sha256(body), 'utf8');
  } catch {
    /* see above */
  }
}

// ============================================================================
// Request, result, refusal
// ============================================================================

export interface RouterOsUpgradeTarget {
  /** The release to install: the fleet target ObliWAN resolved. */
  version: string;
  /** The smallest RouterOS the templates need; the target may not be below. */
  minimum: string | null;
  /** The largest RouterOS the templates accept, when they bound it. */
  maximum: string | null;
  /** The plan's packages (cross-checked), or null: built here. */
  packages: Array<{ name: string; url: string }> | null;
}

export interface RouterOsUpgradeRequest extends FactoryIdentifyRequest {
  target: RouterOsUpgradeTarget;
  /** SSH port for SFTP. Default 22. */
  sshPort?: number;
  /**
   * When the box has not enough free space for the packages: factory-reset it
   * to a MINIMAL configuration (a DHCP client on ether1, 192.168.88.1/24 on a
   * bridge of the other ports for the bench) and let the ROUTER download and
   * install its own upgrade through ether1. See RESET FOR SPACE below.
   * Default false: NO_SPACE, nothing touched.
   */
  resetWhenNoSpace?: boolean;
}

export type UpgradePhase = 'checking' | 'downloading' | 'uploading' | 'rebooting' | 'router-update' | 'waiting' | 'resetting';

export interface UpgradeProgress {
  phase: UpgradePhase;
  label: string;
  /** For a wait: when it started and when it gives up (ms, `now()` clock). */
  since?: number;
  deadline?: number;
}

export interface RouterOsUpgradeDeps {
  dial?: DialFn;
  /** Default `sftpUploadOverSsh`. */
  sftpUpload?: SftpUploadFn | null;
  /** Default `httpsDownload`. */
  download?: DownloadFn;
  /**
   * A package's size BEFORE downloading it (HTTPS HEAD, MikroTik's hosts only),
   * or null when it cannot be learnt. Default `httpsHeadSize` — except when a
   * `download` is injected without one (a test double): then no size is known
   * up front and the space is judged after the download, as it always was.
   */
  headSize?: (url: string, opts: { timeoutMs: number }) => Promise<number | null>;
  /** Default `defaultPackageCacheDir()`; null disables the cache. */
  cacheDir?: string | null;
  discover?: (mac: string) => Promise<MndpCandidate | null>;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  onProgress?: (p: UpgradeProgress) => void;
  timing?: { rebootWaitMs?: number; pollMs?: number; downloadMs?: number; checkMs?: number };
  /**
   * Added to the reboot wait's deadline, asked again at every attempt: the
   * application's measure of how long the box's bench link was DOWN (a
   * cable pulled during the reboot and put back), so that a box plugged in
   * again is still waited for. Default: nothing added.
   */
  waitExtensionMs?: () => number;
  /**
   * Asked at every attempt of the reboot wait: true ends it there, as a
   * timeout (`NOT_BACK`) — the technician gave up on a box that looks
   * unplugged. Default: never.
   */
  stopWaiting?: () => boolean;
}

export interface RouterOsUpgradeResult {
  from: string;
  to: string;
  /** `none`: the box was already at or above the target. `reset-router-update`:
   *  factory-reset to the minimal configuration for space, then the router's own update. */
  method: 'sftp' | 'router-update' | 'reset-router-update' | 'none';
  packages: Array<{ name: string; bytes: number; cached: boolean }>;
  /** The proof taken AFTER the reboot (or before, for `none`). */
  identity: FactoryBoxIdentification;
  waitedMs: number;
  /** The bench link that proof was taken over (`waitForBox`); for `none`,
   *  the request's own. */
  localAddress: string | null;
}

export type RouterOsUpgradeRefusal =
  | 'INVALID_TARGET'
  | 'UNSUPPORTED_BOX'
  | 'DOWNLOAD_FAILED'
  | 'BOTH_OFFLINE'
  | 'ROUTER_OFFERS_OTHER'
  | 'NO_SPACE'
  | 'UPLOAD_FAILED'
  | 'REBOOT_REFUSED'
  | 'NOT_BACK'
  | 'OTHER_BOX'
  | 'PACKAGE_REJECTED'
  | 'IDENTIFY_FAILED'
  | 'RESET_REFUSED'
  | 'NO_INTERNET';

/**
 * Every refusal, in French, saying what to do next. `rebooted` tells the
 * caller whether the box was sent a reboot (or an install): before that,
 * nothing on it changed beyond removed leftovers of an earlier attempt.
 */
export class RouterOsUpgradeError extends Error {
  constructor(
    readonly code: RouterOsUpgradeRefusal,
    message: string,
    readonly rebooted: boolean,
  ) {
    super(message);
    this.name = 'RouterOsUpgradeError';
  }
}

// ============================================================================
// Helpers
// ============================================================================

const SIZE_UNITS: Record<string, number> = { b: 1, kib: 1024, mib: 1024 ** 2, gib: 1024 ** 3 };

/** `12345678`, `12.3MiB` → bytes; `null` when neither. */
export function parseRouterBytes(raw: string | null | undefined): number | null {
  const s = (raw ?? '').trim();
  if (/^\d+$/.test(s)) return Number(s);
  const m = /^(\d+(?:\.\d+)?)\s*(B|KiB|MiB|GiB)$/i.exec(s);
  return m ? Math.floor(Number(m[1]) * SIZE_UNITS[m[2].toLowerCase()]) : null;
}

const mib = (n: number): string => `${(n / 1024 / 1024).toFixed(1).replace('.', ',')} Mo`;

const NPK_AT_ROOT = /^[A-Za-z0-9._-]+\.npk$/;

interface Prepared {
  kind: 'none' | 'sftp' | 'router-update' | 'reset';
  from: string;
  identity: FactoryBoxIdentification;
  packages: Array<{ name: string; bytes: number; cached: boolean }>;
}

// ============================================================================
// RESET FOR SPACE
// ============================================================================
//
// On some models the packages do not fit in the free space: neither the PC's
// SFTP push nor anything else that stores them first can work there. The
// procedure: factory-reset the box to a MINIMAL
// configuration — a DHCP client on ether1 and nothing else the customer
// template would need — and let the ROUTER download and install its own
// upgrade through ether1. The preparation that follows resets it a second
// time with the customer's configuration (`applyFactoryProvisioning`), so
// nothing of this minimal state survives.
//
// What the minimal file also does, because the bench must still reach the box
// after a reset with no-defaults (which leaves it with NO address): every
// ethernet port except ether1 in a bridge `obliwan-bench` carrying
// 192.168.88.1/24, where the bench dials factory boxes (ether1 alone when the
// box has no other port); neighbour discovery on every interface, so MNDP
// finds it again. The bench cable must therefore be on a port OTHER than
// ether1, and ether1 on a network with DHCP and Internet: the reset is refused
// when the bench's own session arrives on ether1.
//
// REASONED, NOT OBSERVED: built against the RouterOS double. The first lab run
// should check that the admin password after `reset-configuration
// no-defaults=yes` is the label's, and that the router's own update fits where
// the SFTP push did not.

/** The minimal file's name on the box (`flash/` prepended when it has one). */
export const MINIMAL_UPGRADE_FILE = 'obliwan-upgrade-minimal.rsc';
export const MINIMAL_UPGRADE_BRIDGE = 'obliwan-bench';
/** The router's own download (`/system/package/update/install`), streamed:
 *  never cut short in practice (see `routerSelfUpdate`). */
const INSTALL_STREAM_MS = 30 * 60_000;
/** How long the router is given to get a DHCP lease on ether1. */
const DHCP_BOUND_WAIT_MS = 120_000;
/** How long the minimal file is given to have run once the box answers again
 *  (it waits up to 60 s for ether1, then 5 s). */
const MINIMAL_APPLY_WAIT_MS = 90_000;

/** A RouterOS double-quoted string. Control characters are refused, not escaped. */
function rosString(v: string): string {
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(v)) throw new Error('control character');
  return `"${v.replace(/[\\"$?]/g, (c) => `\\${c}`)}"`;
}

/**
 * The run-after-reset file of the minimal configuration.
 *
 * Its FIRST statement puts the label password back on the bench's account: a
 * reset with no-defaults may leave the factory administrator with an EMPTY
 * password, and the bench comes back with the label's — it would no longer get
 * in. The file therefore carries that password, like the preparation's own
 * file, and removes itself at the end.
 * An empty label password (an old box that has none) writes no such line.
 */
export function buildMinimalUpgradeConfig(path: string, account: { username: string; password: string }): string {
  const name = path.replace(/^flash\//, '');
  const pw = account.password !== ''
    ? [
        `:do { /user set [find where name=${rosString(account.username)}] password=${rosString(account.password)} } ` +
          'on-error={ :log warning "obliwan-upgrade-minimal: password not set" }',
      ]
    : [];
  return [
    '# ObliWAN bench: minimal configuration so the router downloads its own RouterOS upgrade.',
    '# Replaced by the customer configuration at the preparation (a second reset).',
    ...pw,
    ':local n 0',
    ':while ([:len [/interface ethernet find where name="ether1"]] = 0 && $n < 60) do={ :delay 1s; :set n ($n + 1) }',
    ':delay 5s',
    ':do {',
    `  /interface bridge add name=${MINIMAL_UPGRADE_BRIDGE} protocol-mode=none`,
    '  :foreach e in=[/interface ethernet find where name!="ether1"] do={',
    `    /interface bridge port add bridge=${MINIMAL_UPGRADE_BRIDGE} interface=[/interface ethernet get $e name]`,
    '  }',
    `  :if ([:len [/interface bridge port find where bridge="${MINIMAL_UPGRADE_BRIDGE}"]] > 0) do={`,
    `    /ip address add address=192.168.88.1/24 interface=${MINIMAL_UPGRADE_BRIDGE}`,
    // The bench PC takes its address by DHCP from the factory configuration,
    // and asks again when the reboot drops its link: without a server here it
    // falls to 169.254.x.x and can no longer reach 192.168.88.1 (observed
    // 2026-10-03). NO gateway in the network: a gateway makes Windows route
    // its traffic — ObliWAN included — through a box that has no NAT.
    '    :do {',
    `      /ip pool add name=${MINIMAL_UPGRADE_BRIDGE} ranges=192.168.88.10-192.168.88.254`,
    `      /ip dhcp-server add name=${MINIMAL_UPGRADE_BRIDGE} interface=${MINIMAL_UPGRADE_BRIDGE} address-pool=${MINIMAL_UPGRADE_BRIDGE} disabled=no`,
    '      /ip dhcp-server network add address=192.168.88.0/24',
    '    } on-error={ :log warning "obliwan-upgrade-minimal: bench dhcp server not set" }',
    '  } else={',
    '    /ip address add address=192.168.88.1/24 interface=ether1',
    '  }',
    '} on-error={ :log warning "obliwan-upgrade-minimal: bench address not set" }',
    ':do { /ip dhcp-client add interface=ether1 disabled=no } on-error={ :log warning "obliwan-upgrade-minimal: dhcp-client not added" }',
    // Announced on the bench bridge ONLY: announced on ether1 too, the box is
    // heard by the PC through the office network as well, at its DHCP address.
    `:do { /interface list add name=${MINIMAL_UPGRADE_BRIDGE}; /interface list member add list=${MINIMAL_UPGRADE_BRIDGE} interface=${MINIMAL_UPGRADE_BRIDGE}; :if ([:len [/interface bridge port find where bridge="${MINIMAL_UPGRADE_BRIDGE}"]] = 0) do={ /interface list member add list=${MINIMAL_UPGRADE_BRIDGE} interface=ether1 }; /ip neighbor discovery-settings set discover-interface-list=${MINIMAL_UPGRADE_BRIDGE} } on-error={ :log warning "obliwan-upgrade-minimal: discovery not limited to the bench" }`,
    `:do { /file remove [find where name="${name}" or name="flash/${name}"] } on-error={}`,
    ':log info "obliwan-upgrade-minimal: done"',
    '',
  ].join('\n');
}

/** The box carries the minimal configuration: its bridge and a DHCP client on ether1. */
async function inMinimalState(session: RouterOsApiSession): Promise<boolean> {
  try {
    const clients = await session.query(['/ip/dhcp-client/print'], { timeoutMs: 15_000 });
    if (!clients.some((c) => c.interface === 'ether1')) return false;
    const bridges = await session.query(['/interface/bridge/print'], { timeoutMs: 15_000 });
    return bridges.some((b) => b.name === MINIMAL_UPGRADE_BRIDGE);
  } catch (err) {
    // A menu the box refuses to print is not the minimal state.
    if (routerErrorKind(err) === 'trap') return false;
    throw err;
  }
}

/** Waits for the ether1 DHCP client to be `bound`; NO_INTERNET otherwise. */
async function waitDhcpBound(
  session: RouterOsApiSession,
  o: { sleep?: (ms: number) => Promise<void>; now: () => number; waitMs: number; rebooted: boolean },
): Promise<void> {
  const sleep = o.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const until = o.now() + o.waitMs;
  let status = '';
  for (;;) {
    const rows = await session.query(['/ip/dhcp-client/print'], { timeoutMs: 15_000 });
    status = (rows.find((r) => r.interface === 'ether1')?.status ?? '').trim();
    if (status === 'bound') return;
    if (o.now() >= until) break;
    await sleep(5_000);
  }
  throw new RouterOsUpgradeError(
    'NO_INTERNET',
    `Le routeur n'obtient pas d'adresse sur ether1 (état « ${status || 'inconnu'} »). Reliez ether1 à une prise du réseau qui donne accès à Internet, puis relancez la recherche du routeur et la mise à jour : il ne sera pas réinitialisé une seconde fois.`,
    o.rebooted,
  );
}

/**
 * Upload the minimal file and `reset-configuration` with it. On the proven
 * session, before anything else is written: refused when the bench reaches
 * the box through ether1 (the reset would cut the bench off).
 */
async function resetToMinimal(
  session: RouterOsApiSession,
  req: RouterOsUpgradeRequest,
  o: { sftpUpload: SftpUploadFn | null; scrub: (t: unknown) => string },
): Promise<void> {
  const addresses = await session.query(['/ip/address/print'], { timeoutMs: 15_000 });
  const reached = addresses.find((a) => (a.address ?? '').split('/')[0] === req.host);
  if (!reached || reached.interface === 'ether1') {
    throw new RouterOsUpgradeError(
      'NO_SPACE',
      reached
        ? 'Le routeur n\'a pas assez de place pour la mise à jour, et ce poste lui est relié par ether1 : il ne peut pas être réinitialisé sans perdre le contact. Branchez le câble du poste sur un autre port et ether1 sur une prise avec accès à Internet, puis relancez la recherche du routeur. Rien n\'a été modifié.'
        : `Le routeur n'a pas assez de place pour la mise à jour, et l'adresse ${req.host} n'est pas sur l'une de ses interfaces : il ne peut pas être réinitialisé sans risquer de perdre le contact. Rien n'a été modifié ; appelez un technicien.`,
      false,
    );
  }
  const listing = await listFiles(session, 15_000);
  const flash = listing.some((f) => f.name === 'flash' && (f.type === null || /disk|dir/i.test(f.type ?? '')));
  const path = `${flash ? 'flash/' : ''}${MINIMAL_UPGRADE_FILE}`;
  // After the reset the factory administrator is the only account: the bench
  // must come back as it, with the label password (which the file sets).
  let content: string;
  try {
    if (req.username !== 'admin') throw new Error('account');
    content = buildMinimalUpgradeConfig(path, { username: req.username, password: req.password });
  } catch {
    throw new RouterOsUpgradeError(
      'NO_SPACE',
      'Le routeur n\'a pas assez de place pour la mise à jour, et il ne peut pas être réinitialisé avec ce compte ou ce mot de passe (le compte doit être « admin », le mot de passe celui de l\'étiquette). Rien n\'a été modifié ; appelez un technicien.',
      false,
    );
  }
  for (const f of listing.filter((r) => r.name === path)) await removeFile(session, f, 15_000);

  let placed = false;
  try {
    await session.query(['/file/add', `=name=${path}`, `=contents=${content}`], { timeoutMs: 15_000 });
    placed = true;
  } catch (err) {
    if (routerErrorKind(err) !== 'trap' || !o.sftpUpload) throw err;
  }
  if (!placed && o.sftpUpload) {
    await o.sftpUpload({
      host: req.host,
      port: req.sshPort ?? 22,
      username: req.username,
      password: req.password,
      remotePath: path,
      content: Buffer.from(content, 'utf8'),
      timeoutMs: 30_000,
      ...(req.localAddress ? { localAddress: req.localAddress } : {}),
    });
  }
  const row = (await listFiles(session, 15_000)).find((r) => r.name === path);
  const verdict = row ? judgeReportedSize(row.size, Buffer.byteLength(content, 'utf8')) : 'missing';
  if (verdict !== 'match' && verdict !== 'rounded') {
    if (row) await removeFile(session, row, 15_000).catch(() => {});
    throw new RouterOsUpgradeError(
      'RESET_REFUSED',
      'La configuration minimale n\'a pas pu être déposée entière sur le routeur. Rien n\'a été modifié ; relancez la mise à jour.',
      false,
    );
  }
  try {
    await session.query(
      ['/system/reset-configuration', '=no-defaults=yes', '=skip-backup=yes', `=run-after-reset=${path}`],
      { timeoutMs: 15_000 },
    );
  } catch (err) {
    if (routerErrorKind(err) === 'trap') {
      await removeFile(session, row!, 15_000).catch(() => {});
      throw new RouterOsUpgradeError(
        'RESET_REFUSED',
        `Le routeur a refusé la réinitialisation (${o.scrub(err)}). Rien n'a été modifié ; relancez la mise à jour.`,
        false,
      );
    }
    // The session dying is the reset happening.
  }
}

// ============================================================================
// The operation
// ============================================================================

export async function upgradeRouterOs(req: RouterOsUpgradeRequest, deps: RouterOsUpgradeDeps = {}): Promise<RouterOsUpgradeResult> {
  const now = deps.now ?? Date.now;
  const download = deps.download ?? httpsDownload;
  const sftpUpload = deps.sftpUpload === undefined ? sftpUploadOverSsh : deps.sftpUpload;
  const cacheDir = deps.cacheDir === undefined ? defaultPackageCacheDir() : deps.cacheDir;
  const rebootWaitMs = deps.timing?.rebootWaitMs ?? 8 * 60_000;
  const downloadMs = deps.timing?.downloadMs ?? 120_000;
  const checkMs = deps.timing?.checkMs ?? 30_000;
  const scrub = passwordScrubber(typeof req.password === 'string' ? req.password : '');
  const progress = (p: UpgradeProgress) => {
    try {
      deps.onProgress?.(p);
    } catch {
      /* a broken progress callback must not stop an upgrade half-way */
    }
  };
  const retry = 'relancez la mise à jour';

  // ---- the target: refused before anything is dialled ----------------------
  const t = req.target;
  const target = typeof t?.version === 'string' ? t.version.trim() : '';
  if (!isRouterOsReleaseVersion(target) || parseRouterOsVersion(target)!.major !== 7) {
    throw new RouterOsUpgradeError(
      'INVALID_TARGET',
      'ObliWAN n\'indique pas de version RouterOS 7 à installer. Rien n\'a été fait ; demandez à l\'administrateur d\'ObliWAN de choisir la version cible du parc.',
      false,
    );
  }
  const minimum = t.minimum && parseRouterOsVersion(t.minimum) ? t.minimum : null;
  if (minimum && compareRouterOsVersion(target, minimum) < 0) {
    throw new RouterOsUpgradeError(
      'INVALID_TARGET',
      `La version cible du parc (${target}) est plus ancienne que celle qu'exige le modèle de configuration (${minimum}). Rien n'a été fait ; demandez à l'administrateur d'ObliWAN de relever la version cible.`,
      false,
    );
  }
  const maximum = t.maximum && parseRouterOsVersion(t.maximum) ? t.maximum : null;
  if (maximum && compareRouterOsVersion(target, maximum) > 0) {
    throw new RouterOsUpgradeError(
      'INVALID_TARGET',
      `La version cible du parc (${target}) est plus récente que celle qu'accepte le modèle de configuration (${maximum}). Rien n'a été fait ; prévenez la personne qui gère les modèles.`,
      false,
    );
  }

  // ---- 1-3: on ONE proven session ------------------------------------------
  progress({ phase: 'checking', label: 'Vérification du routeur…' });
  let rebooted = false;
  let prepared: Prepared;
  const headSize = deps.headSize ?? (deps.download ? async () => null : httpsHeadSize);

  /**
   * Not enough room for the PC to push the packages: the ROUTER downloads and
   * installs its own update (observed 2026-10-03: a Chateau with 1,1 Mo free
   * took its own 7.24.5 through ether1 where the push could not fit). Only
   * when it cannot reach MikroTik as configured, and only on the operator's
   * procedure (`resetWhenNoSpace`), is it reset to the minimal configuration
   * first — a DHCP client on ether1 — and asked again after the reboot.
   */
  const routerUpdateForSpace = async (
    session: RouterOsApiSession,
    identity: FactoryBoxIdentification,
    from: string,
    why: string,
  ): Promise<Prepared> => {
    progress({ phase: 'router-update', label: `${why} : le routeur télécharge et installe lui-même la mise à jour par ether1…` });
    const minimal = await inMinimalState(session);
    if (minimal) await waitDhcpBound(session, { sleep: deps.sleep, now, waitMs: DHCP_BOUND_WAIT_MS, rebooted: false });
    try {
      await routerSelfUpdate(session, target, { checkMs, installMs: rebootWaitMs, scrub, onInstall: () => { rebooted = true; }, via: 'ether1' });
      return { kind: 'router-update', from, identity, packages: [] };
    } catch (err) {
      if (!(err instanceof RouterOsUpgradeError) || err.code !== 'BOTH_OFFLINE' || minimal || !req.resetWhenNoSpace) throw err;
      progress({
        phase: 'resetting',
        label: `${why}, et le routeur n'accède pas à Internet tel qu'il est configuré : réinitialisation avec une configuration minimale (client DHCP sur ether1)…`,
      });
      await resetToMinimal(session, req, { sftpUpload, scrub });
      rebooted = true;
      return { kind: 'reset', from, identity, packages: [] };
    }
  };

  /**
   * MNDP during a wait: searched from the LOWEST of the MACs the box proved
   * (same maker prefix), not from the typed one — after a reset the box may
   * announce itself under another of its MACs (a bridge takes the MAC of its
   * first port, below the typed ether3's: observed 2026-10-03), and the
   * search window only goes up from the MAC it is given.
   */
  const discoverFrom = (identity: FactoryBoxIdentification) => {
    if (!deps.discover) return undefined;
    const typed = normalizeMac(req.expectedMac);
    const oui = typed ? typed.slice(0, 8) : null;
    const lowest = identity.interfaceMacs
      .map((m) => normalizeMac(m))
      .filter((m): m is string => m !== null && (oui === null || m.startsWith(oui)))
      .sort()[0] ?? req.expectedMac;
    const discover = deps.discover;
    return (_mac: string) => discover(lowest);
  };
  const lastTry = (e: string | null) => (e ? ` Dernière tentative : ${scrub(e).slice(0, 160)}` : '');
  try {
    prepared = await withProvenSession(req, { dial: deps.dial }, { label: 'bench:upgrade', retry }, async (session, identity) => {
      const from = bareVersion(identity.router.version);
      const parsedFrom = from ? parseRouterOsVersion(from) : null;
      if (!from || !parsedFrom) {
        throw new RouterOsUpgradeError('UNSUPPORTED_BOX', 'La version RouterOS de ce routeur n\'a pas pu être lue. Rien n\'a été modifié ; appelez un technicien.', false);
      }
      if (compareRouterOsVersion(from, target) >= 0) return { kind: 'none', from, identity, packages: [] } as Prepared;
      if (parsedFrom.major !== 7) {
        throw new RouterOsUpgradeError(
          'UNSUPPORTED_BOX',
          `Ce routeur est en RouterOS ${from} : le passage à RouterOS 7 ne se fait pas depuis ce poste. Rien n'a été modifié ; mettez-le de côté et appelez un technicien.`,
          false,
        );
      }
      const arch = routerOsPackageArchFromResource(identity.router.architecture);
      if (!arch) {
        throw new RouterOsUpgradeError(
          'UNSUPPORTED_BOX',
          `L'architecture de ce routeur (« ${scrub(identity.router.architecture ?? 'inconnue')} ») n'est pas reconnue : impossible de choisir les bons fichiers. Rien n'a été modifié ; appelez un technicien.`,
          false,
        );
      }
      const names = Array.from(new Set((identity.packages ?? []).map((p) => p.name)));
      if (!identity.packages || !names.includes('routeros')) {
        throw new RouterOsUpgradeError(
          'UNSUPPORTED_BOX',
          'La liste des logiciels installés sur ce routeur n\'a pas pu être lue. Rien n\'a été modifié ; relancez la mise à jour, et appelez un technicien si cela se reproduit.',
          false,
        );
      }
      const wanted: Array<{ name: string; url: string; file: string }> = [];
      for (const name of names) {
        const u = tryRouterOsPackageUrl(target, name, arch);
        if (!u.ok) {
          throw new RouterOsUpgradeError(
            'UNSUPPORTED_BOX',
            `Le logiciel « ${scrub(name).slice(0, 40)} » installé sur ce routeur n'a pas de fichier de mise à jour connu. Rien n'a été modifié ; appelez un technicien.`,
            false,
          );
        }
        const offered = t.packages?.find((p) => p?.name === name);
        if (offered && offered.url !== u.url) {
          throw new RouterOsUpgradeError(
            'INVALID_TARGET',
            `ObliWAN propose pour « ${name} » une adresse de téléchargement qui n'est pas celle de MikroTik pour cette version. Rien n'a été fait ; signalez-le à l'administrateur d'ObliWAN.`,
            false,
          );
        }
        wanted.push({ name, url: u.url, file: u.url.slice(u.url.lastIndexOf('/') + 1) });
      }

      // ---- space FIRST: what does not fit is not downloaded by the PC at all --
      // Packages an earlier attempt left would be installed at the next reboot
      // too, and they take the space counted here.
      const leftovers: FileRow[] = (await listFiles(session, 15_000)).filter((r) => NPK_AT_ROOT.test(r.name));
      for (const f of leftovers) await removeFile(session, f, 15_000);
      const free = parseRouterBytes(((await session.query(['/system/resource/print'], { timeoutMs: 15_000 }))[0] ?? {})['free-hdd-space']);
      const sizes = await Promise.all(wanted.map((w) => headSize(w.url, { timeoutMs: checkMs }).catch(() => null)));
      const announced = sizes.every((n): n is number => typeof n === 'number')
        ? (sizes as number[]).reduce((x, y) => x + y, 0) + SPACE_MARGIN_BYTES
        : null;
      if (free !== null && announced !== null && free < announced) {
        return routerUpdateForSpace(session, identity, from, `Place insuffisante (${mib(free)} libres, ${mib(announced)} nécessaires)`);
      }

      // ---- 2: the PC downloads (cache first) ---------------------------------
      const bodies: Array<{ name: string; file: string; body: Buffer; cached: boolean }> = [];
      let offline: string | null = null;
      for (const w of wanted) {
        const cachePath = cacheDir ? join(cacheDir, target, w.file) : null;
        const hit = cachePath ? readCached(cachePath) : null;
        if (hit) {
          bodies.push({ name: w.name, file: w.file, body: hit, cached: true });
          continue;
        }
        progress({ phase: 'downloading', label: `Téléchargement de ${w.file} chez MikroTik…` });
        try {
          const body = await download(w.url, { timeoutMs: downloadMs, maxBytes: MAX_PACKAGE_BYTES });
          if (body.length < MIN_PACKAGE_BYTES) throw new DownloadError('size', `${body.length} octets seulement`);
          if (cachePath) writeCached(cachePath, body);
          bodies.push({ name: w.name, file: w.file, body, cached: false });
        } catch (err) {
          const kind = err instanceof DownloadError ? err.kind : 'offline';
          if (kind === 'offline') {
            offline = err instanceof Error ? err.message : String(err);
            break;
          }
          throw new RouterOsUpgradeError(
            'DOWNLOAD_FAILED',
            kind === 'missing'
              ? `MikroTik ne publie pas ${w.file} : cette version ne peut pas être installée sur ce routeur. Rien n'a été modifié ; prévenez l'administrateur d'ObliWAN.`
              : `Le téléchargement de ${w.file} a échoué (${scrub(err instanceof Error ? err.message : String(err))}). Rien n'a été modifié ; relancez la mise à jour.`,
            false,
          );
        }
      }

      if (offline !== null) {
        // ---- fallback: the box updates itself ---------------------------------
        progress({ phase: 'router-update', label: 'Ce poste n\'accède pas à MikroTik : le routeur télécharge lui-même la mise à jour…' });
        await routerSelfUpdate(session, target, { checkMs, installMs: rebootWaitMs, scrub, onInstall: () => { rebooted = true; } });
        return { kind: 'router-update', from, identity, packages: [] } as Prepared;
      }

      // ---- 3: space, push, check, reboot -------------------------------------
      if (!sftpUpload) {
        throw new RouterOsUpgradeError('UPLOAD_FAILED', 'Ce poste ne sait pas déposer de fichier sur le routeur. Rien n\'a été modifié ; appelez un technicien.', false);
      }
      // Sizes unknown up front (no HEAD answer): judged now, on what arrived.
      const need = bodies.reduce((n, x) => n + x.body.length, 0) + SPACE_MARGIN_BYTES;
      if (free !== null && free < need) {
        return routerUpdateForSpace(session, identity, from, `Place insuffisante (${mib(free)} libres, ${mib(need)} nécessaires)`);
      }
      if (free === null) {
        throw new RouterOsUpgradeError(
          'NO_SPACE',
          "La place libre sur le routeur n'a pas pu être lue. Rien n'a été modifié ; appelez un technicien.",
          false,
        );
      }
      const pushed: string[] = [];
      const undo = async () => {
        try {
          const rows = await listFiles(session, 15_000);
          for (const p of pushed) {
            const row = rows.find((r) => r.name === p);
            if (row) await removeFile(session, row, 15_000);
          }
        } catch {
          /* best effort: the refusal is what the preparer must see */
        }
      };
      for (const b of bodies) {
        progress({ phase: 'uploading', label: `Envoi de ${b.file} au routeur…` });
        pushed.push(b.file);
        try {
          await sftpUpload({
            host: req.host,
            port: req.sshPort ?? 22,
            username: req.username,
            password: req.password,
            remotePath: b.file,
            content: b.body,
            timeoutMs: 60_000 + Math.ceil(b.body.length / 100_000) * 1_000,
            ...(req.localAddress ? { localAddress: req.localAddress } : {}),
          });
        } catch (err) {
          await undo();
          throw new RouterOsUpgradeError(
            'UPLOAD_FAILED',
            `L'envoi de ${b.file} au routeur a échoué (${scrub(err instanceof Error ? err.message : String(err))}). Rien n'a été modifié ; relancez la mise à jour, et appelez un technicien si cela se reproduit.`,
            false,
          );
        }
      }
      const rows = await listFiles(session, 15_000);
      for (const b of bodies) {
        const row = rows.find((r) => r.name === b.file);
        const verdict = row ? judgeReportedSize(row.size, b.body.length) : 'missing';
        if (verdict !== 'match' && verdict !== 'rounded') {
          await undo();
          throw new RouterOsUpgradeError(
            'UPLOAD_FAILED',
            `${b.file} n'est pas arrivé entier sur le routeur. Rien n'a été modifié ; relancez la mise à jour.`,
            false,
          );
        }
      }
      progress({ phase: 'rebooting', label: 'Redémarrage du routeur pour installer la mise à jour…' });
      try {
        await session.query(['/system/reboot'], { timeoutMs: 10_000 });
      } catch (err) {
        if (routerErrorKind(err) === 'trap') {
          await undo();
          throw new RouterOsUpgradeError(
            'REBOOT_REFUSED',
            `Le routeur a refusé de redémarrer (${scrub(err)}). Les fichiers envoyés ont été retirés et rien n'a été modifié ; relancez la mise à jour.`,
            false,
          );
        }
        // A reboot ends the session without a goodbye: that is the expected path.
      }
      rebooted = true;
      return {
        kind: 'sftp',
        from,
        identity,
        packages: bodies.map((b) => ({ name: b.name, bytes: b.body.length, cached: b.cached })),
      } as Prepared;
    });
  } catch (err) {
    if (err instanceof RouterOsUpgradeError) throw err;
    if (err instanceof FactoryProvisioningError) {
      throw new RouterOsUpgradeError('IDENTIFY_FAILED', err.message, false);
    }
    // A refused read or a dead session on the way. Every write before the
    // reboot command is a leftover the next attempt removes first.
    const detail = scrub(err instanceof Error ? err.message : String(err));
    throw new RouterOsUpgradeError(
      'UPLOAD_FAILED',
      routerErrorKind(err) === 'trap'
        ? `Le routeur a refusé une étape de la mise à jour (${detail}). Rien n'a été installé ; relancez la mise à jour, et appelez un technicien si cela se reproduit.`
        : `La liaison avec le routeur s'est interrompue (${detail}). Vérifiez le câble, puis ${rebooted ? 'relancez la recherche du routeur' : 'relancez la mise à jour'}.`,
      rebooted,
    );
  }

  if (prepared.kind === 'none') {
    return {
      from: prepared.from, to: prepared.from, method: 'none', packages: [], identity: prepared.identity, waitedMs: 0,
      localAddress: req.localAddress ?? null,
    };
  }

  // ---- RESET FOR SPACE: back from the reset, then the router's own update ------
  let current: FactoryIdentifyRequest = req;
  if (prepared.kind === 'reset') {
    const resetSince = now();
    const resetDeadline = resetSince + rebootWaitMs;
    progress({
      phase: 'waiting',
      label: 'Le routeur redémarre avec sa configuration minimale… Ne le débranchez pas.',
      since: resetSince,
      deadline: resetDeadline,
    });
    let back;
    try {
      back = await waitForBox({
        req: { ...req, onProgress: undefined },
        deadline: () => (deps.stopWaiting?.() ? resetSince : resetDeadline + Math.max(0, deps.waitExtensionMs?.() ?? 0)),
        pollMs: deps.timing?.pollMs,
        dial: deps.dial,
        discover: discoverFrom(prepared.identity),
        sleep: deps.sleep,
        now,
        onTick: (elapsed, _seen, lastError) => progress({
          phase: 'waiting',
          label: `Le routeur redémarre avec sa configuration minimale… ${frenchDuration(elapsed)} écoulées. Ne le débranchez pas.${lastTry(lastError ?? null)}`,
          since: resetSince,
          deadline: resetDeadline,
        }),
        // Only once the reset was SEEN (an attempt that failed): the box that
        // answers right away is the old configuration still shutting down.
        accept: (_identity, sawItGo) => (sawItGo ? 'done' : 'wait'),
      });
    } catch (err) {
      if (!(err instanceof BoxWaitError)) throw err;
      if (err.code === 'OTHER_BOX') throw new RouterOsUpgradeError('OTHER_BOX', err.message, true);
      throw new RouterOsUpgradeError(
        'NOT_BACK',
        `Le routeur a été réinitialisé pour libérer de la place mais n'est pas revenu (${err.message}). Vérifiez que le câble du poste est sur un port AUTRE qu'ether1, attendez que ses voyants soient stables, puis relancez la recherche du routeur.`,
        true,
      );
    }
    current = { ...req, host: back.host, localAddress: back.localAddress ?? undefined };
    try {
      await withProvenSession(current, { dial: deps.dial }, { label: 'bench:upgrade-after-reset', retry }, async (session) => {
        // The box answers its API BEFORE its run-after-reset file has run (the
        // file itself waits for ether1, then 5 s): wait for its result.
        const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
        const until = now() + MINIMAL_APPLY_WAIT_MS;
        let applied = await inMinimalState(session);
        while (!applied && now() < until) {
          await sleep(3_000);
          applied = await inMinimalState(session);
        }
        if (!applied) {
          throw new RouterOsUpgradeError(
            'RESET_REFUSED',
            'Le routeur a redémarré mais sa configuration minimale n\'a pas été appliquée (pas de client DHCP sur ether1). Appelez un technicien.',
            true,
          );
        }
        progress({ phase: 'router-update', label: 'Le routeur attend une adresse sur ether1 pour télécharger la mise à jour…' });
        await waitDhcpBound(session, { sleep: deps.sleep, now, waitMs: DHCP_BOUND_WAIT_MS, rebooted: true });
        progress({ phase: 'router-update', label: 'Le routeur télécharge lui-même la mise à jour par ether1…' });
        await routerSelfUpdate(session, target, { checkMs, installMs: rebootWaitMs, scrub, onInstall: () => {}, via: 'ether1' });
      });
    } catch (err) {
      if (err instanceof RouterOsUpgradeError) throw new RouterOsUpgradeError(err.code, err.message, true);
      const detail = scrub(err instanceof Error ? err.message : String(err));
      throw new RouterOsUpgradeError(
        'NOT_BACK',
        `Le routeur a été réinitialisé pour libérer de la place, mais la liaison s'est interrompue avant sa mise à jour (${detail}). Relancez la recherche du routeur, puis « Mettre à jour RouterOS » : il ne sera pas réinitialisé une seconde fois.`,
        true,
      );
    }
  }

  // ---- 4: wait for it, prove it, read its version -----------------------------
  const since = now();
  // What the screen shows; the wait itself also adds the link's down time.
  const deadline = since + rebootWaitMs;
  const movingDeadline = () => (deps.stopWaiting?.() ? since : deadline + Math.max(0, deps.waitExtensionMs?.() ?? 0));
  const label = (elapsed: number) =>
    `Le routeur redémarre et installe RouterOS ${target}… ${frenchDuration(elapsed)} écoulées (${frenchDuration(rebootWaitMs)} au plus). Ne le débranchez pas.`;
  progress({ phase: 'waiting', label: label(0), since, deadline });
  try {
    const back = await waitForBox({
      req: { ...current, onProgress: undefined },
      deadline: movingDeadline,
      pollMs: deps.timing?.pollMs,
      dial: deps.dial,
      discover: discoverFrom(prepared.identity),
      sleep: deps.sleep,
      now,
      onTick: (elapsed, _seen, lastError) => progress({ phase: 'waiting', label: `${label(elapsed)}${lastTry(lastError ?? null)}`, since, deadline }),
      accept: (identity, sawItGo) => {
        const v = bareVersion(identity.router.version);
        if (v && parseRouterOsVersion(v) && compareRouterOsVersion(v, target) === 0) return 'done';
        if (sawItGo) {
          return {
            fail: `Le routeur a redémarré mais il est resté en RouterOS ${v ?? 'inconnu'} : il a refusé la mise à jour. Débranchez-le, mettez-le de côté et appelez un technicien.`,
          };
        }
        return 'wait';
      },
    });
    return {
      from: prepared.from,
      to: target,
      method: prepared.kind === 'reset' ? 'reset-router-update' : prepared.kind,
      packages: prepared.packages,
      identity: back.identity,
      waitedMs: back.waitedMs,
      localAddress: back.localAddress,
    };
  } catch (err) {
    if (!(err instanceof BoxWaitError)) throw err;
    if (err.code === 'REFUSED') throw new RouterOsUpgradeError('PACKAGE_REJECTED', err.message, true);
    if (err.code === 'OTHER_BOX') throw new RouterOsUpgradeError('OTHER_BOX', err.message, true);
    if (err.code === 'TIMEOUT') {
      throw new RouterOsUpgradeError(
        'NOT_BACK',
        `Le routeur n'est pas revenu après ${frenchDuration(rebootWaitMs)}. Ne le débranchez pas : attendez que ses voyants soient stables, puis relancez la recherche du routeur. S'il ne répond toujours pas, appelez un technicien.`,
        true,
      );
    }
    throw new RouterOsUpgradeError('NOT_BACK', `${err.message}`, true);
  }
}

/**
 * The fallback: `/system/package/update` on the box itself, installing ONLY
 * the target version. Resolves once the install was sent (the box downloads,
 * then reboots); throws `RouterOsUpgradeError` otherwise, with the channel
 * put back as it was.
 */
async function routerSelfUpdate(
  session: RouterOsApiSession,
  target: string,
  o: {
    checkMs: number;
    installMs: number;
    scrub: (t: unknown) => string;
    onInstall: () => void;
    /** 'pc-offline' (default): the PC cannot reach MikroTik; 'ether1': the reset-for-space path. */
    via?: 'pc-offline' | 'ether1';
  },
): Promise<void> {
  const read = async (): Promise<{ channel: string | null; latest: string | null; status: string }> => {
    try {
      await session.query(['/system/package/update/check-for-updates'], { timeoutMs: o.checkMs });
    } catch (err) {
      const kind = routerErrorKind(err);
      // A check that keeps streaming is cancelled by its timeout: the print
      // below says what it found. A trap is the box failing to check.
      if (kind !== 'timeout' && kind !== 'trap') throw err;
    }
    const row = (await session.query(['/system/package/update/print'], { timeoutMs: 15_000 }))[0] ?? {};
    const latest = bareVersion(row['latest-version']);
    return {
      channel: (row.channel ?? '').trim() || null,
      latest: latest && parseRouterOsVersion(latest) ? latest : null,
      status: o.scrub(row.status ?? ''),
    };
  };
  const first = await read();
  let offered = first.latest;
  let switched: string | null = null;
  if (offered === null) {
    throw new RouterOsUpgradeError(
      'BOTH_OFFLINE',
      o.via === 'ether1'
        ? 'Le routeur n\'arrive pas à joindre MikroTik par ether1 pour télécharger la mise à jour. Vérifiez que la prise d\'ether1 donne accès à Internet, puis cliquez à nouveau sur « Mettre à jour RouterOS ».'
        : 'Ni ce poste ni le routeur n\'arrivent à joindre MikroTik pour télécharger la mise à jour. Rien n\'a été modifié. Branchez ce poste à Internet, puis relancez la mise à jour.',
      false,
    );
  }
  if (compareRouterOsVersion(offered, target) !== 0 && first.channel) {
    const other = first.channel === 'long-term' ? 'stable' : 'long-term';
    await session.query(['/system/package/update/set', `=channel=${other}`], { timeoutMs: 15_000 });
    switched = first.channel;
    offered = (await read()).latest;
  }
  if (offered === null || compareRouterOsVersion(offered, target) !== 0) {
    if (switched) {
      try {
        await session.query(['/system/package/update/set', `=channel=${switched}`], { timeoutMs: 15_000 });
      } catch {
        /* the box is wiped at the provisioning anyway */
      }
    }
    throw new RouterOsUpgradeError(
      'ROUTER_OFFERS_OTHER',
      o.via === 'ether1'
        ? `Le routeur ne se voit proposer que RouterOS ${offered ?? first.latest} par MikroTik alors qu'ObliWAN vise ${target} : il ne peut pas l'installer lui-même. Mettez-le de côté et prévenez l'administrateur d'ObliWAN (version cible du parc).`
        : `Ce poste n'accède pas à MikroTik, et le routeur ne propose que RouterOS ${offered ?? first.latest} alors qu'ObliWAN vise ${target}. Rien n'a été modifié. Branchez ce poste à Internet, puis relancez la mise à jour.`,
      false,
    );
  }
  o.onInstall();
  try {
    // `install` streams its download progress, then the box reboots and the
    // session dying is the expected end. A request that outlives its timeout
    // is CANCELLED by the connection layer (`/cancel` for its tag), and
    // whether RouterOS then abandons its own download is not observed — so
    // the bound is set far beyond any real download over a wired ether1
    // (a RouterOS 7 package is about 13 Mo), never at the reboot wait.
    await session.query(['/system/package/update/install'], { timeoutMs: Math.max(o.installMs, INSTALL_STREAM_MS) });
  } catch (err) {
    if (routerErrorKind(err) === 'trap') {
      throw new RouterOsUpgradeError(
        'REBOOT_REFUSED',
        `Le routeur a refusé d'installer la mise à jour (${o.scrub(err)}). Rien n'a été modifié ; relancez la mise à jour.`,
        false,
      );
    }
  }
}
