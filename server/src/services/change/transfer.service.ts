/**
 * ObliWAN. Moving a file OFF an equipment, and leaving nothing behind.
 *
 * WHY THIS FILE EXISTS AT ALL
 * A backup that stays on the router is a copy of the customer's configuration
 * sitting on the customer's router, readable by anybody who ever gets a shell
 * on it — including the next owner of a box that gets RMA'd or resold. The
 * backup is only useful on OUR storage, and it is only safe once it is no
 * longer on THEIRS. So the contract of this module is three-part and
 * indivisible:
 *
 *   1. pull the file off,
 *   2. prove what we received is what was there (bytes AND digest),
 *   3. delete it on the device and PROVE it is gone.
 *
 * Step 3 is not best-effort. `removeDeviceFile()` re-reads the file table after
 * the delete and reports `verified: false` if the row is still there; the caller
 * (backup.service) treats that as a failure of the backup, not as a warning.
 *
 * THREE ROADS OFF THE ROUTER, AND THE ORDER IS THE POINT
 * A binary backup holds every PPP and IPsec secret of the box — on the
 * CHR, every site's. So the file is PULLED by us over a channel we already
 * hold, rather than PUSHED by the router to wherever a URL points:
 *
 *  1. `readFileOverApi()` — `/file/read` in chunks, on the RouterOS API session
 *     the backup was taken on (identity already proven on it). RouterOS
 *     7.13 and later (changelog 7.13: "console - added "read" command under
 *     "file" menu"). No range for `chunk-size`, no note on binary files and
 *     no minimum version has been found in MikroTik's manual; the 32768
 *     ceiling used here comes from a forum report and is UNVERIFIED (see
 *     `ROUTEROS_FILE_READ_MAX_CHUNK`).
 *  2. `sftpPullToSpool()` — SFTP over the device's SSH channel, encrypted by
 *     SSH but with NO pinned host key (nothing in ObliWAN stores one), so
 *     backup.service only takes it to the very address the identity-checked
 *     API session reached, and only when that address is not public. The
 *     road for boxes without `/file/read` (RouterOS 6, 7.0–7.12), PROVIDED
 *     their SSH server serves SFTP to the service account. Which RouterOS
 *     releases do is not established here (MikroTik dates SFTP in
 *     `/tool/fetch` — the client — to 6.45; that says nothing about the
 *     server), so the first pull on a given release is its test.
 *  3. `/tool/fetch upload=yes` to a `TransferReceiver` — the ROUTER dials US,
 *     over plain HTTP. Kept for one case only, decided in backup.service:
 *     an explicitly configured callback address, on a device reached on a
 *     non-public address. Never chosen by default — and nothing in
 *     production configures one today (no setting, no env var), so in
 *     production this road is closed; only a caller passing `callbackHost`
 *     or a receiver with a `publicBaseUrl` opens it.
 *
 * THE TOKEN (road 3)
 * `/tool/fetch upload=yes` inverts the trust direction: for the duration of
 * the transfer there is an HTTP listener that accepts a body from whatever can
 * reach it. So the URL carries a single-use, short-lived, 256-bit token, the
 * receiver compares it in constant time, and the token is burned on first use
 * — a replay lands on a 404, not on a second write into the same file. One
 * token authorises exactly one file, of a bounded size, for a bounded time. A
 * token protects the RECEIVER; it does nothing for the body, which crosses the
 * path in clear — which is why road 3 is last and gated.
 *
 * The secrets rule: nothing here logs a body, a token, or a backup password. The
 * audit line for a fetch carries the src-path and the URL WITHOUT its token,
 * because a token in `command_audit` is a token on the audit screen.
 */

import crypto from 'crypto';
import fs from 'fs';
import fsp from 'fs/promises';
import http from 'http';
import net from 'net';
import os from 'os';
import path from 'path';
import {
  RouterOsTimeoutError,
  RouterOsTrapError,
  attributeBytes,
  type RouterOsConnection,
  type Sentence,
} from '../transport/routeros';
import { logger } from '../../utils/logger';

// ============================================================================
// Errors
// ============================================================================

export type TransferErrorCode =
  | 'TOKEN_INVALID'
  | 'TOKEN_EXPIRED'
  | 'TOKEN_CONSUMED'
  | 'TOO_LARGE'
  | 'TRANSFER_TIMEOUT'
  | 'TRANSFER_FAILED'
  | 'DIGEST_MISMATCH'
  | 'SIZE_MISMATCH'
  | 'FILE_ABSENT'
  | 'DELETE_UNVERIFIED'
  | 'NOT_SUPPORTED';

export class TransferError extends Error {
  readonly code: TransferErrorCode;
  readonly detail: Record<string, unknown>;
  constructor(code: TransferErrorCode, message: string, detail: Record<string, unknown> = {}) {
    super(message);
    this.name = 'TransferError';
    this.code = code;
    this.detail = detail;
  }
}

// ============================================================================
// One-time tokens
// ============================================================================

export interface TokenGrant {
  /** The bearer value. Goes in the URL handed to the router, nowhere else. */
  readonly token: string;
  readonly purpose: string;
  readonly maxBytes: number;
  readonly expiresAt: number;
}

interface TokenRecord {
  hash: Buffer;
  purpose: string;
  maxBytes: number;
  expiresAt: number;
  consumedAt: number | null;
}

/** Default life of a transfer token. Long enough for a 20 MB backup over a bad
 *  ADSL, short enough that a token found in a proxy log tomorrow is dead. */
export const TRANSFER_TOKEN_TTL_MS = 5 * 60_000;

/**
 * Tokens are stored HASHED. The value only ever exists in the URL we hand the
 * router and in the request line the router sends back; a heap dump or a stray
 * dump of this store yields digests, not credentials.
 */
export class OneTimeTokenStore {
  private readonly records = new Map<string, TokenRecord>();

  mint(purpose: string, maxBytes: number, ttlMs = TRANSFER_TOKEN_TTL_MS): TokenGrant {
    const token = crypto.randomBytes(32).toString('hex');
    const hash = crypto.createHash('sha256').update(token).digest();
    const expiresAt = Date.now() + ttlMs;
    this.records.set(hash.toString('hex'), {
      hash,
      purpose,
      maxBytes,
      expiresAt,
      consumedAt: null,
    });
    return { token, purpose, maxBytes, expiresAt };
  }

  /**
   * Burn a token. The map is keyed by the DIGEST, so a wrong token cannot be
   * distinguished by timing on the lookup, and the final `timingSafeEqual`
   * covers the (theoretical) collision path.
   */
  consume(
    token: string,
  ): { ok: true; record: TokenRecord } | { ok: false; code: TransferErrorCode } {
    if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token)) {
      return { ok: false, code: 'TOKEN_INVALID' };
    }
    const hash = crypto.createHash('sha256').update(token).digest();
    const record = this.records.get(hash.toString('hex'));
    if (!record) return { ok: false, code: 'TOKEN_INVALID' };
    if (!crypto.timingSafeEqual(record.hash, hash)) return { ok: false, code: 'TOKEN_INVALID' };
    if (record.consumedAt !== null) return { ok: false, code: 'TOKEN_CONSUMED' };
    if (Date.now() > record.expiresAt) return { ok: false, code: 'TOKEN_EXPIRED' };
    record.consumedAt = Date.now();
    return { ok: true, record };
  }

  /** Drop a grant that was never used (the fetch failed, the job aborted). */
  revoke(token: string): void {
    if (!/^[0-9a-f]{64}$/.test(token ?? '')) return;
    this.records.delete(crypto.createHash('sha256').update(token).digest('hex'));
  }

  /** Housekeeping. A consumed token is kept until expiry so that a replay is
   *  reported as TOKEN_CONSUMED (a signal) rather than TOKEN_INVALID (noise). */
  sweep(now = Date.now()): number {
    let n = 0;
    for (const [key, rec] of this.records) {
      if (now > rec.expiresAt) {
        this.records.delete(key);
        n++;
      }
    }
    return n;
  }

  get size(): number {
    return this.records.size;
  }
}

// ============================================================================
// The receiver — the half-minute during which a router may write to us
// ============================================================================

export interface ReceivedFile {
  /** Absolute path of the spooled file. The caller owns it and must move it or
   *  delete it. */
  path: string;
  bytes: number;
  sha256: string;
  durationMs: number;
  remoteAddress: string | null;
}

export interface TransferReceiverOptions {
  /** Interface to bind. Defaults to every interface, because the router dials
   *  us over the tunnel and we do not always know which local address that is.
   *  Set it in production to the tunnel-facing address. */
  host?: string;
  /** 0 = an ephemeral port, which is what tests want. */
  port?: number;
  /** Where uploads land before the caller moves them. */
  spoolDir?: string;
  /** Advertised base URL, for when ObliWAN sits behind a NAT or a proxy and the
   *  router cannot reach `host:port` directly. */
  publicBaseUrl?: string;
}

export interface ExpectedUpload {
  grant: TokenGrant;
  /** The exact URL to hand `/tool/fetch`. Contains the token. NEVER audit it
   *  raw — use `redactTransferUrl()`. */
  url: string;
  /** Resolves when the body has been fully received and hashed. */
  received: Promise<ReceivedFile>;
  /** Give up waiting and refuse any later arrival. */
  cancel(reason: string): void;
}

const TRANSFER_PATH_PREFIX = '/_obliwan/transfer/';

/** Where a file lands between the wire and the backup store, whichever road
 *  it came by. Outside the backup root on purpose: the caller moves it in only
 *  once it is verified (backup.service, step 5). */
export function defaultSpoolDir(): string {
  return path.join(os.tmpdir(), 'obliwan-transfer');
}

function newSpoolPath(spoolDir: string): string {
  return path.join(spoolDir, `${Date.now()}-${crypto.randomBytes(8).toString('hex')}.part`);
}

/**
 * Matches a transfer token WHEREVER it appears, not only in a bare URL.
 *
 * This regex exists because the first run of the safe-apply recipe caught the leak it
 * closes: `/tool/fetch =url=http://…/_obliwan/transfer/<64 hex>` was being
 * written verbatim into `command_audit`, because `url` is not a secret
 * attribute and nobody had told the audit redactor that this particular URL
 * carries a bearer credential in its path. A single-use token is still a
 * credential for the seconds it is alive, and the audit screen is exactly the
 * place a credential must not be.
 */
export const TRANSFER_TOKEN_IN_TEXT = /\/_obliwan\/transfer\/[0-9a-f]+/gi;

/** Strip the token out of a fetch URL so it can be written to `command_audit`. */
export function redactTransferUrl(url: string): string {
  return url.replace(TRANSFER_TOKEN_IN_TEXT, `${TRANSFER_PATH_PREFIX}***`);
}

export class TransferReceiver {
  private readonly opts: Required<Omit<TransferReceiverOptions, 'publicBaseUrl'>> & {
    publicBaseUrl?: string;
  };
  private readonly tokens = new OneTimeTokenStore();
  private readonly pending = new Map<
    string,
    {
      resolve: (f: ReceivedFile) => void;
      reject: (e: Error) => void;
      settled: boolean;
      spoolPath: string;
      startedAt: number;
    }
  >();
  private server: http.Server | null = null;
  private boundPort = 0;

  constructor(options: TransferReceiverOptions = {}) {
    this.opts = {
      host: options.host ?? '0.0.0.0',
      port: options.port ?? 0,
      spoolDir: options.spoolDir ?? defaultSpoolDir(),
      publicBaseUrl: options.publicBaseUrl,
    };
  }

  /** The advertised base URL when one was CONFIGURED (`publicBaseUrl`), else
   *  null. A null here means `baseUrl()` would fall back to a guess — the bind
   *  address, or this host's loopback — which no remote router can reach. */
  get configuredBaseUrl(): string | null {
    const v = (this.opts.publicBaseUrl ?? '').trim();
    return v.length > 0 ? v.replace(/\/+$/, '') : null;
  }

  /** Where this receiver spools. The pull roads spool into the same place
   *  when a caller hands them a receiver, so one directory holds every
   *  in-flight copy of that caller's transfers. */
  get spoolDirectory(): string {
    return this.opts.spoolDir;
  }

  async start(): Promise<number> {
    if (this.server) return this.boundPort;
    await fsp.mkdir(this.opts.spoolDir, { recursive: true });
    const server = http.createServer((req, res) => {
      void this.onRequest(req, res);
    });
    // A router that opens a socket and says nothing must not hold us open.
    server.headersTimeout = 30_000;
    server.requestTimeout = 15 * 60_000;
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(this.opts.port, this.opts.host, () => resolve());
    });
    const addr = server.address();
    this.boundPort = typeof addr === 'object' && addr ? addr.port : this.opts.port;
    this.server = server;
    return this.boundPort;
  }

  async stop(): Promise<void> {
    for (const [, p] of this.pending) {
      if (!p.settled) {
        p.settled = true;
        p.reject(new TransferError('TRANSFER_FAILED', 'transfer receiver stopped'));
      }
    }
    this.pending.clear();
    const server = this.server;
    this.server = null;
    if (!server) return;
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  get port(): number {
    return this.boundPort;
  }

  /** The address the ROUTER should dial. Callers pass the tunnel-side address
   *  of this server. */
  baseUrl(host?: string): string {
    if (this.opts.publicBaseUrl) return this.opts.publicBaseUrl.replace(/\/+$/, '');
    const h = host ?? (this.opts.host === '0.0.0.0' ? '127.0.0.1' : this.opts.host);
    return `http://${h.includes(':') ? `[${h}]` : h}:${this.boundPort}`;
  }

  /**
   * Authorise exactly one upload.
   *
   * `timeoutMs` is a hard ceiling: the promise rejects and the token is revoked,
   * so a router that dies mid-transfer cannot leave a listener half-open with a
   * live credential attached to it.
   */
  expect(options: {
    purpose: string;
    maxBytes: number;
    timeoutMs?: number;
    /** Host to build the URL with — the address the router can reach us on. */
    callbackHost?: string;
  }): ExpectedUpload {
    if (!this.server) throw new TransferError('TRANSFER_FAILED', 'receiver is not started');
    const grant = this.tokens.mint(
      options.purpose,
      options.maxBytes,
      options.timeoutMs ?? TRANSFER_TOKEN_TTL_MS,
    );
    const spoolPath = newSpoolPath(this.opts.spoolDir);
    let resolveFn!: (f: ReceivedFile) => void;
    let rejectFn!: (e: Error) => void;
    const received = new Promise<ReceivedFile>((resolve, reject) => {
      resolveFn = resolve;
      rejectFn = reject;
    });
    const entry = {
      resolve: resolveFn,
      reject: rejectFn,
      settled: false,
      spoolPath,
      startedAt: Date.now(),
    };
    this.pending.set(grant.token, entry);

    const timer = setTimeout(() => {
      if (entry.settled) return;
      entry.settled = true;
      this.tokens.revoke(grant.token);
      this.pending.delete(grant.token);
      rejectFn(
        new TransferError('TRANSFER_TIMEOUT', 'the device never delivered the file', {
          purpose: options.purpose,
          waitedMs: Date.now() - entry.startedAt,
        }),
      );
    }, options.timeoutMs ?? TRANSFER_TOKEN_TTL_MS);
    timer.unref?.();
    void received.catch(() => undefined).finally(() => clearTimeout(timer));

    return {
      grant,
      url: `${this.baseUrl(options.callbackHost)}${TRANSFER_PATH_PREFIX}${grant.token}`,
      received,
      cancel: (reason: string) => {
        if (entry.settled) return;
        entry.settled = true;
        clearTimeout(timer);
        this.tokens.revoke(grant.token);
        this.pending.delete(grant.token);
        rejectFn(new TransferError('TRANSFER_FAILED', reason));
      },
    };
  }

  private async onRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const url = req.url ?? '';
    if (!url.startsWith(TRANSFER_PATH_PREFIX)) {
      res.writeHead(404).end();
      return;
    }
    if (req.method !== 'POST' && req.method !== 'PUT') {
      // RouterOS `/tool/fetch upload=yes` posts. Some firmwares PUT. Anything
      // else is not a transfer and gets nothing, not even a hint.
      res.writeHead(405).end();
      return;
    }
    const token = url.slice(TRANSFER_PATH_PREFIX.length).split(/[?#]/)[0];
    const verdict = this.tokens.consume(token);
    if (!verdict.ok) {
      // Deliberately indistinguishable to the caller: an expired token and a
      // forged one both get 404. The DIFFERENCE goes to our log, not to them.
      logger.warn({ code: verdict.code }, 'transfer: upload refused');
      res.writeHead(404).end();
      return;
    }
    const entry = this.pending.get(token);
    if (!entry || entry.settled) {
      res.writeHead(409).end();
      return;
    }
    this.pending.delete(token);

    const hash = crypto.createHash('sha256');
    let bytes = 0;
    let aborted: TransferError | null = null;
    const sink = fs.createWriteStream(entry.spoolPath);

    await new Promise<void>((resolve) => {
      req.on('data', (chunk: Buffer) => {
        bytes += chunk.length;
        if (bytes > verdict.record.maxBytes) {
          aborted = new TransferError('TOO_LARGE', 'upload exceeded the authorised size', {
            maxBytes: verdict.record.maxBytes,
            bytes,
          });
          req.destroy();
          sink.destroy();
          resolve();
          return;
        }
        hash.update(chunk);
        sink.write(chunk);
      });
      req.on('error', (err) => {
        aborted = new TransferError('TRANSFER_FAILED', `upload aborted: ${err.message}`);
        sink.destroy();
        resolve();
      });
      req.on('end', () => {
        sink.end(() => resolve());
      });
    });

    const abortedErr: TransferError | null = aborted;
    if (abortedErr) {
      await fsp.rm(entry.spoolPath, { force: true }).catch(() => undefined);
      entry.settled = true;
      entry.reject(abortedErr);
      res.writeHead(413).end();
      return;
    }

    entry.settled = true;
    entry.resolve({
      path: entry.spoolPath,
      bytes,
      sha256: hash.digest('hex'),
      durationMs: Date.now() - entry.startedAt,
      remoteAddress: req.socket.remoteAddress ?? null,
    });
    res.writeHead(204).end();
  }
}

// ============================================================================
// Device-side file operations (RouterOS)
// ============================================================================

export interface DeviceFile {
  name: string;
  sizeBytes: number;
  /** True when the box printed a plain byte count (RouterOS 7), which can be
   *  held to EXACT equality; false for a rounded `12.3KiB` (RouterOS 6), which
   *  is a weak size and only ever compared with a tolerance. */
  sizeExact: boolean;
  type: string | null;
  id: string | null;
}

function parseSize(raw: string | undefined): { bytes: number; exact: boolean } {
  if (!raw) return { bytes: 0, exact: false };
  // v6 prints `12.3KiB`, v7 prints the byte count. Accept both; a human-readable
  // size is a WEAK size and the caller must not treat it as a proof.
  const trimmed = raw.trim();
  if (/^\d+$/.test(trimmed)) return { bytes: Number(trimmed), exact: true };
  const plain = Number(raw);
  if (Number.isFinite(plain) && trimmed !== '') return { bytes: plain, exact: false };
  const m = /^([\d.]+)\s*([KMG])i?B$/i.exec(trimmed);
  if (!m) return { bytes: 0, exact: false };
  const mult = { k: 1024, m: 1024 ** 2, g: 1024 ** 3 }[m[2].toLowerCase()] ?? 1;
  return { bytes: Math.round(Number(m[1]) * mult), exact: false };
}

/** Read one file row, or null. A `!trap` on `/file/print` means the menu is not
 *  there — treated as "no file", never as an error. */
export async function deviceFileInfo(
  conn: RouterOsConnection,
  name: string,
): Promise<DeviceFile | null> {
  let rows: Record<string, string>[];
  try {
    rows = await conn.query(['/file/print', `?name=${name}`]);
  } catch (err) {
    if (err instanceof RouterOsTrapError) return null;
    throw err;
  }
  const row = rows.find((r) => r.name === name) ?? null;
  if (!row) return null;
  const size = parseSize(row.size);
  return {
    name: row.name,
    sizeBytes: size.bytes,
    sizeExact: size.exact,
    type: row.type ?? null,
    id: row['.id'] ?? null,
  };
}

/**
 * Wait for a file the device is writing asynchronously.
 *
 * `/system/backup/save` answers `!done` before the file is necessarily on the
 * disk, and `/export file=` certainly does. Polling `/file/print` until the size
 * STOPS GROWING is the only honest way to know it finished: a size still
 * increasing means we would pull a truncated backup and then verify it against
 * its own truncated digest, which proves nothing.
 */
export async function waitForDeviceFile(
  conn: RouterOsConnection,
  name: string,
  options: { timeoutMs?: number; pollMs?: number; stableChecks?: number } = {},
): Promise<DeviceFile> {
  const timeoutMs = options.timeoutMs ?? 60_000;
  const pollMs = options.pollMs ?? 250;
  const stableChecks = options.stableChecks ?? 2;
  const deadline = Date.now() + timeoutMs;
  let lastSize = -1;
  let stable = 0;
  let seen: DeviceFile | null = null;

  while (Date.now() < deadline) {
    const info = await deviceFileInfo(conn, name);
    if (info) {
      seen = info;
      if (info.sizeBytes > 0 && info.sizeBytes === lastSize) {
        stable++;
        if (stable >= stableChecks) return info;
      } else {
        stable = 0;
      }
      lastSize = info.sizeBytes;
    }
    await new Promise<void>((r) => setTimeout(r, pollMs));
  }
  throw new TransferError(
    'FILE_ABSENT',
    `the device never produced a stable '${name}' within ${timeoutMs} ms`,
    { name, lastSeenSize: seen?.sizeBytes ?? null },
  );
}

export interface RemovalResult {
  removed: boolean;
  /** True only when a re-read of the file table confirmed the absence. A
   *  `removed: true, verified: false` is a FAILURE for the caller: it means we
   *  asked, nothing complained, and the customer's config may still be there. */
  verified: boolean;
  attempts: number;
  lastError: string | null;
}

/**
 * Delete a file and PROVE it is gone.
 *
 * The proof is the point. `/file/remove` on a name that does not exist traps;
 * `/file/remove` on a name that does exist returns `!done` and, on a busy
 * router, occasionally leaves the row. So: remove, re-read, and only report
 * success when the re-read comes back empty.
 */
export async function removeDeviceFile(
  conn: RouterOsConnection,
  name: string,
  options: { attempts?: number; backoffMs?: number } = {},
): Promise<RemovalResult> {
  const attempts = options.attempts ?? 3;
  const backoffMs = options.backoffMs ?? 300;
  let lastError: string | null = null;

  for (let i = 1; i <= attempts; i++) {
    try {
      const existing = await deviceFileInfo(conn, name);
      if (!existing) return { removed: true, verified: true, attempts: i, lastError };
      const selector = existing.id ?? name;
      await conn.talk(['/file/remove', `=numbers=${selector}`]);
      const after = await deviceFileInfo(conn, name);
      if (!after) return { removed: true, verified: true, attempts: i, lastError: null };
      lastError = 'the file is still listed after /file/remove';
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err);
    }
    if (i < attempts) await new Promise<void>((r) => setTimeout(r, backoffMs * i));
  }
  return { removed: false, verified: false, attempts, lastError };
}

export interface FetchOutcome {
  ok: boolean;
  /** RouterOS' own view: `finished`, `failed`, `connecting`... */
  deviceStatus: string | null;
  durationMs: number;
  error: string | null;
}

/**
 * Make the device upload a file to us.
 *
 * Issued with a generous per-request budget because a 30 MB backup over a
 * saturated ADSL is slow, and the receiver has its OWN independent deadline —
 * two clocks, so a router that answers `!done` while having sent nothing still
 * fails on the receiver's side rather than passing on ours.
 */
export async function uploadFileFromDevice(
  conn: RouterOsConnection,
  options: { srcPath: string; url: string; timeoutMs?: number },
): Promise<FetchOutcome> {
  const started = Date.now();
  try {
    const rows = await conn.query(
      ['/tool/fetch', '=upload=yes', `=src-path=${options.srcPath}`, `=url=${options.url}`],
      { timeoutMs: options.timeoutMs ?? 10 * 60_000 },
    );
    const status = rows.length > 0 ? (rows[rows.length - 1].status ?? null) : null;
    return {
      ok: status === null || status === 'finished',
      deviceStatus: status,
      durationMs: Date.now() - started,
      error: null,
    };
  } catch (err) {
    return {
      ok: false,
      deviceStatus: null,
      durationMs: Date.now() - started,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

// ============================================================================
// Road 1 — /file/read over the RouterOS API session we already hold
// ============================================================================

/**
 * The `chunk-size` asked for. NOT a documented limit: no range for it has been
 * found in MikroTik's manual. 32768 comes from a MikroTik forum report
 * and has not been observed on hardware — the fakes enforce the same ceiling,
 * so the harnesses prove the code against this assumption, not against a
 * router. If a real box caps lower, it either refuses the first chunk
 * (`!trap` → `NOT_SUPPORTED`, the next road is taken) or answers short, which
 * `readFileOverApi()` refuses as `SIZE_MISMATCH` (an encrypted road may then
 * take over; see `pullDeviceFile()` in backup.service).
 */
export const ROUTEROS_FILE_READ_MAX_CHUNK = 32_768;

/** The first RouterOS release with `/file/read` (changelog 7.13, 2023-12-14:
 *  "console - added "read" command under "file" menu"). */
export const ROUTEROS_FILE_READ_SINCE = '7.13';

/**
 * Whether a RouterOS version has `/file/read`: `yes` from 7.13, `no` below it
 * (every 6.x, 7.0–7.12), `unknown` when the version could not be read or
 * parsed — in which case the caller may TRY the command and take a `!trap` as
 * the answer, but must not assume either way.
 */
export function routerOsFileReadSupport(version: string | null | undefined): 'yes' | 'no' | 'unknown' {
  const m = /^\s*(\d+)\.(\d+)/.exec(version ?? '');
  if (!m) return 'unknown';
  const major = Number(m[1]);
  const minor = Number(m[2]);
  return major > 7 || (major === 7 && minor >= 13) ? 'yes' : 'no';
}

export interface ApiFileReadOptions {
  /** The file's name exactly as `/file/print` lists it. */
  name: string;
  /** The EXACT byte count `/file/print` reported (RouterOS 7 prints one). The
   *  read stops there, and a chunk that ends early is a truncation. */
  expectedBytes: number;
  maxBytes: number;
  spoolDir?: string;
  /** Default and ceiling: `ROUTEROS_FILE_READ_MAX_CHUNK`. */
  chunkSize?: number;
  /** Budget for the whole pull. */
  timeoutMs?: number;
  /** Budget for one chunk's round trip. */
  chunkTimeoutMs?: number;
}

export interface ApiFileReadResult extends ReceivedFile {
  /** How many `/file/read` round trips it took. */
  chunks: number;
}

/** The bytes of one `/file/read` answer, or null when it carried no `data`.
 *  Several `!re` rows would be concatenated in the order they arrived; the
 *  exact size check that follows is what judges the result. */
function chunkData(sentences: readonly Sentence[]): Buffer | null {
  const parts: Buffer[] = [];
  for (const s of sentences) {
    if (s.type !== '!re') continue;
    const b = attributeBytes(s, 'data');
    if (b) parts.push(b);
  }
  if (parts.length > 0) return Buffer.concat(parts);
  const done = sentences.find((s) => s.type === '!done');
  return done ? attributeBytes(done, 'data') : null;
}

/**
 * Pull a file off a RouterOS 7.13+ box with `/file/read`, chunk by chunk, on a
 * connection that is already open and authenticated.
 *
 * Nothing leaves the box except as an answer on THIS session — no URL, no
 * listener, no second socket — so the file travels exactly as protected as the
 * session is (TLS on 8729, or the tunnel), and the identity proven on it
 * covers the bytes too. Every chunk is asked for at an explicit offset and an
 * explicit length — never more than what remains of the file — and must come
 * back EXACTLY that long:
 *  - a chunk LONGER than asked is refused: the bytes are not what the file
 *    holds (an encoding nothing here undoes), and hashing them would prove
 *    nothing;
 *  - a chunk that is EMPTY before `expectedBytes` is a truncation;
 *  - a chunk SHORTER than asked is refused too. It used to be accepted, the
 *    next one asked from where it ended — and then a wire that drops or
 *    strips bytes (a NUL, an undecodable byte) re-reads the overlap, the loop
 *    still stops at `expectedBytes`, and the size check holds BY
 *    CONSTRUCTION over a file that is garbage. A short chunk cannot be told
 *    from a lossy one, so it is not taken for either.
 * The `data` of a chunk is read as BYTES (`attributeBytes`), never as the
 * UTF-8 string the reader also produces: a binary backup is not text.
 *
 * Errors are `TransferError`s. `NOT_SUPPORTED` is reserved for "this road is
 * not available on this box" — the FIRST chunk refused (`!trap`) or answered
 * without any `data` — so a caller can take another road; every later failure
 * is a failure of the transfer and must not be retried silently elsewhere.
 * The spooled file is removed on every failure.
 *
 * HONESTY NOTE: proven against `FakeRouterOs` / `FakeDeadmanRouter`, which
 * answer `!re =data=<raw bytes>` as the console's `data: …` output suggests.
 * Not yet observed on a real router. A wire that changes the LENGTH of a chunk
 * (drops, strips, escapes, inflates) fails loudly on that chunk; one that
 * substitutes bytes one for one would not, and no check here could see it —
 * the digest is computed over what arrived.
 */
export async function readFileOverApi(
  conn: RouterOsConnection,
  options: ApiFileReadOptions,
): Promise<ApiFileReadResult> {
  const started = Date.now();
  const expected = options.expectedBytes;
  if (!Number.isInteger(expected) || expected < 0) {
    throw new TransferError('SIZE_MISMATCH', `no exact size for '${options.name}' to read up to`, {
      name: options.name,
      expectedBytes: expected,
    });
  }
  if (expected > options.maxBytes) {
    throw new TransferError('TOO_LARGE', `'${options.name}' is larger than the authorised size`, {
      expectedBytes: expected,
      maxBytes: options.maxBytes,
    });
  }
  const chunkSize = Math.max(
    1,
    Math.min(ROUTEROS_FILE_READ_MAX_CHUNK, Math.floor(options.chunkSize ?? ROUTEROS_FILE_READ_MAX_CHUNK)),
  );
  const deadline = started + (options.timeoutMs ?? 5 * 60_000);
  const chunkTimeoutMs = options.chunkTimeoutMs ?? 30_000;
  const spoolDir = options.spoolDir ?? defaultSpoolDir();
  await fsp.mkdir(spoolDir, { recursive: true });
  const spoolPath = newSpoolPath(spoolDir);
  const hash = crypto.createHash('sha256');
  const fh = await fsp.open(spoolPath, 'wx');
  let offset = 0;
  let chunks = 0;
  let ok = false;
  try {
    while (offset < expected) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        throw new TransferError('TRANSFER_TIMEOUT', `/file/read of '${options.name}' ran out of time`, {
          offset,
          expectedBytes: expected,
          chunks,
        });
      }
      const want = Math.min(chunkSize, expected - offset);
      let sentences: Sentence[];
      try {
        sentences = await conn.talk(
          ['/file/read', `=file=${options.name}`, `=offset=${offset}`, `=chunk-size=${want}`],
          { timeoutMs: Math.min(chunkTimeoutMs, remaining) },
        );
      } catch (err) {
        const why = (err instanceof Error ? err.message : String(err)).slice(0, 200);
        if (err instanceof RouterOsTrapError && chunks === 0) {
          throw new TransferError('NOT_SUPPORTED', `the box refused /file/read (${why})`, {
            name: options.name,
          });
        }
        throw new TransferError(
          err instanceof RouterOsTimeoutError ? 'TRANSFER_TIMEOUT' : 'TRANSFER_FAILED',
          `/file/read of '${options.name}' failed at offset ${offset} of ${expected}: ${why}`,
          { offset, expectedBytes: expected, chunks },
        );
      }
      const data = chunkData(sentences);
      if (data === null) {
        throw new TransferError(
          chunks === 0 ? 'NOT_SUPPORTED' : 'TRANSFER_FAILED',
          `the box answered /file/read at offset ${offset} without a data attribute`,
          { offset, expectedBytes: expected, chunks },
        );
      }
      if (data.length === 0) {
        throw new TransferError(
          'SIZE_MISMATCH',
          `'${options.name}' ended at ${offset} bytes, but /file/print reported ${expected}`,
          { received: offset, deviceReported: expected, chunks },
        );
      }
      if (data.length > want) {
        throw new TransferError(
          'SIZE_MISMATCH',
          `/file/read returned ${data.length} bytes for a ${want}-byte chunk at offset ${offset} — ` +
            'more than the file holds there, so these are not its bytes',
          { offset, asked: want, returned: data.length },
        );
      }
      if (data.length !== want) {
        // `want` never runs past `expected`, so the file holds `want` bytes
        // here: fewer means bytes were lost on the way or the file is shorter
        // than /file/print said, and the next offset would be a guess.
        throw new TransferError(
          'SIZE_MISMATCH',
          `/file/read returned ${data.length} of the ${want} bytes asked at offset ${offset} ` +
            `of '${options.name}' (${expected} bytes per /file/print) — a short chunk cannot be told ` +
            'from a lossy one, so these are not taken for the file',
          { offset, asked: want, returned: data.length, deviceReported: expected, chunks },
        );
      }
      hash.update(data);
      await fh.write(data);
      offset += want;
      chunks++;
    }
    ok = true;
  } finally {
    await fh.close().catch(() => undefined);
    if (!ok) await fsp.rm(spoolPath, { force: true }).catch(() => undefined);
  }
  return {
    path: spoolPath,
    bytes: offset,
    sha256: hash.digest('hex'),
    durationMs: Date.now() - started,
    remoteAddress: null,
    chunks,
  };
}

// ============================================================================
// Road 2 — SFTP over the device's SSH channel
// ============================================================================

export interface SftpPullOptions {
  host: string;
  port?: number;
  username: string;
  password?: string;
  privateKey?: string;
  passphrase?: string;
  remotePath: string;
  localPath: string;
  maxBytes: number;
  timeoutMs?: number;
  /** Pinned host key SHA-256 (base64). Absent = the key is NOT checked (the
   *  observed one is reported through `onHostKey`). */
  expectedHostKeySha256?: string | null;
  onHostKey?: (sha256Base64: string) => void;
}

/** ssh2 is CommonJS, and under tsx `Client` is a named export while under
 *  some interop shapes it only exists on `.default`. Accept both. */
async function loadSshClient(): Promise<new () => any> {
  const mod = (await import('ssh2')) as unknown as Record<string, any>;
  const Client = mod.Client ?? mod.default?.Client;
  if (typeof Client !== 'function') {
    throw new TransferError('NOT_SUPPORTED', 'the ssh2 module exposes no SSH client');
  }
  return Client;
}

/** What an SFTP pull received, and the size the SFTP server stated for the
 *  file before it was read (null when its STAT failed or carried no size). */
export interface SftpPullResult {
  bytes: number;
  sha256: string;
  remoteSize: number | null;
}

/**
 * Pull one file over SFTP into `localPath`, hashing as it streams.
 *
 * The file is STATed first and, when the server states a size, the stream must
 * deliver exactly that many bytes (`SIZE_MISMATCH` otherwise). That is the
 * only EXACT size a RouterOS 6 pull has: its `/file/print` prints a rounded
 * `68.4KiB`, which the caller can only hold to a tolerance, and a stream that
 * ended a few hundred bytes early would pass that tolerance. A STAT that fails
 * with anything but "no such file" leaves `remoteSize` null and the pull goes
 * on — the caller's `/file/print` check is then the only size check, and it
 * says so in its log.
 *
 * Settles exactly once: the first of {complete, too large, read error, write
 * error, connection error, timeout} wins, and the partial `localPath` is
 * removed on every failure. An SFTP "no such file" (status 2) is `FILE_ABSENT`.
 *
 * HONESTY NOTE: exercised against an ssh2 SFTP server in the backup harness
 * (`change/testing/fakeSftpServer.ts`), never against a real RouterOS SSH
 * server — whether RouterOS answers STAT with a size is not observed. The
 * remote path is the name `/file/print` lists, relative to the SFTP session's
 * starting directory.
 */
export async function sftpPullFile(options: SftpPullOptions): Promise<SftpPullResult> {
  // Imported lazily so a deployment that never uses SFTP does not pay for
  // loading ssh2 at boot.
  const Client = await loadSshClient();
  const overall = options.timeoutMs ?? 10 * 60_000;
  return new Promise((resolve, reject) => {
    const client = new Client();
    let settled = false;
    let write: fs.WriteStream | null = null;
    const finish = (err: Error | null, value?: SftpPullResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        client.end();
      } catch {
        /* already closed */
      }
      if (err) {
        write?.destroy();
        void fsp.rm(options.localPath, { force: true }).catch(() => undefined);
        reject(err);
      } else {
        resolve(value as SftpPullResult);
      }
    };
    const timer = setTimeout(
      () => finish(new TransferError('TRANSFER_TIMEOUT', `SFTP pull from ${options.host} timed out`)),
      overall,
    );
    timer.unref?.();

    client
      .on('ready', () => {
        client.sftp((err: Error | undefined, sftp: any) => {
          if (err) {
            finish(new TransferError('NOT_SUPPORTED', `SFTP subsystem refused by ${options.host}: ${err.message}`));
            return;
          }
          // An absolute path, as OpenSSH's sftp asks for it. It was suspected
          // of the "Resource temporarily unavailable" refusals of 2026-10-05
          // and REFUTED (job 30 was refused `/name` too): the cause was the
          // account, `obliwan` without `sensitive` may not read a `.backup`.
          const remotePath = options.remotePath.startsWith('/') ? options.remotePath : `/${options.remotePath}`;
          sftp.stat(remotePath, (statErr: (Error & { code?: number }) | undefined, attrs: { size?: unknown } | undefined) => {
            if (settled) return;
            const statNote = statErr && statErr.code !== 2 ? ` (stat already refused: ${statErr.message})` : '';
            if (statErr && statErr.code === 2) {
              finish(new TransferError('FILE_ABSENT', `SFTP: '${options.remotePath}' is not on ${options.host}`));
              return;
            }
            const stated = !statErr && attrs ? attrs.size : undefined;
            const remoteSize =
              typeof stated === 'number' && Number.isInteger(stated) && stated >= 0 ? stated : null;
            if (remoteSize !== null && remoteSize > options.maxBytes) {
              finish(new TransferError('TOO_LARGE', `SFTP: '${options.remotePath}' is larger than the authorised size`, {
                remoteSize,
                maxBytes: options.maxBytes,
              }));
              return;
            }
            const hash = crypto.createHash('sha256');
            let bytes = 0;
            const read = sftp.createReadStream(remotePath);
            const sink = fs.createWriteStream(options.localPath, { flags: 'wx' });
            write = sink;
            read.on('data', (chunk: Buffer | string) => {
              const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
              bytes += buf.length;
              if (bytes > options.maxBytes) {
                finish(new TransferError('TOO_LARGE', 'SFTP body exceeded the authorised size', {
                  maxBytes: options.maxBytes,
                }));
                read.destroy();
                return;
              }
              hash.update(buf);
            });
            read.on('error', (e: Error & { code?: number }) => {
              finish(
                e.code === 2
                  ? new TransferError('FILE_ABSENT', `SFTP: '${options.remotePath}' is not on ${options.host}`)
                  : new TransferError('TRANSFER_FAILED', `SFTP read of '${remotePath}' from ${options.host} failed: ${e.message}${statNote}`),
              );
            });
            sink.on('error', (e: Error) =>
              finish(new TransferError('TRANSFER_FAILED', `could not write the SFTP spool file: ${e.message}`)),
            );
            // `close`, not `finish`: the descriptor must be released before the
            // caller renames the file (Windows refuses to move an open file).
            // Every failure path above settles first, so a `close` caused by a
            // destroy is ignored.
            sink.on('close', () => {
              if (remoteSize !== null && bytes !== remoteSize) {
                finish(new TransferError(
                  'SIZE_MISMATCH',
                  `SFTP delivered ${bytes} bytes of '${options.remotePath}', whose size the SFTP server ` +
                    `stated as ${remoteSize}`,
                  { received: bytes, remoteSize },
                ));
                return;
              }
              finish(null, { bytes, sha256: hash.digest('hex'), remoteSize });
            });
            read.pipe(sink);
          });
        });
      })
      .on('error', (e: Error) =>
        finish(new TransferError('TRANSFER_FAILED', `SFTP connection to ${options.host} failed: ${e.message}`)),
      )
      .connect({
        host: options.host,
        port: options.port ?? 22,
        username: options.username,
        password: options.password,
        privateKey: options.privateKey,
        passphrase: options.passphrase,
        readyTimeout: Math.min(overall, 30_000),
        hostVerifier: ((key: Buffer) => {
          const digest = crypto.createHash('sha256').update(key).digest('base64');
          options.onHostKey?.(digest);
          if (!options.expectedHostKeySha256) return true;
          const expected = options.expectedHostKeySha256.replace(/=+$/, '');
          return digest.replace(/=+$/, '') === expected;
        }) as never,
      });
  });
}

/** `sftpPullFile()` into a fresh spool file, returned in the receiver's shape
 *  so the caller verifies and stores it exactly like any other road's. */
export async function sftpPullToSpool(
  options: Omit<SftpPullOptions, 'localPath'> & { spoolDir?: string },
): Promise<ReceivedFile & { remoteSize: number | null }> {
  const started = Date.now();
  const spoolDir = options.spoolDir ?? defaultSpoolDir();
  await fsp.mkdir(spoolDir, { recursive: true });
  const localPath = newSpoolPath(spoolDir);
  const { bytes, sha256, remoteSize } = await sftpPullFile({ ...options, localPath });
  return {
    path: localPath,
    bytes,
    sha256,
    durationMs: Date.now() - started,
    remoteAddress: options.host,
    remoteSize,
  };
}

// ============================================================================
// Where the path runs — the judgement the three roads are chosen on
// ============================================================================

/**
 * True for an IP literal that the public internet does not route: RFC 1918,
 * CGNAT (100.64.0.0/10 — where the L2TP tunnel pool lives), loopback,
 * link-local, and their IPv6 counterparts (::1, fc00::/7, fe80::/10).
 *
 * A NAME is never judged non-public: what it resolves to is not known here, and
 * a guess would be the permissive one. So `false` means "public, or unknown".
 */
export function isNonPublicAddress(host: string | null | undefined): boolean {
  const h = (host ?? '').trim().replace(/^\[|\]$/g, '');
  const kind = net.isIP(h);
  if (kind === 4) {
    const o = h.split('.').map(Number);
    if (o[0] === 10 || o[0] === 127) return true;
    if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true;
    if (o[0] === 192 && o[1] === 168) return true;
    if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return true;
    if (o[0] === 169 && o[1] === 254) return true;
    return false;
  }
  if (kind === 6) {
    const l = h.toLowerCase();
    if (l === '::1') return true;
    if (/^f[cd][0-9a-f]{2}:/.test(l)) return true;
    if (/^fe[89ab][0-9a-f]:/.test(l)) return true;
    if (l.startsWith('::ffff:')) return isNonPublicAddress(l.slice(7));
    return false;
  }
  return false;
}

/** 127.0.0.0/8 or ::1 — THIS host, from whoever dials it. */
export function isLoopbackAddress(host: string | null | undefined): boolean {
  const h = (host ?? '').trim().replace(/^\[|\]$/g, '').toLowerCase();
  if (net.isIP(h) === 4) return h.startsWith('127.');
  return h === '::1' || h === '::ffff:127.0.0.1';
}

// ============================================================================
// Verification
// ============================================================================

export interface VerifiedArtefact {
  path: string;
  bytes: number;
  sha256: string;
}

/**
 * Prove that what landed on our disk is what came off the router.
 *
 * Three separate claims, because they fail separately:
 *   - the stream digest matches a RE-READ of the file from disk (catches a
 *     truncated write, a full filesystem, a spool the OS never flushed);
 *   - the byte count matches what the device said the file was;
 *   - the file is at least `minBytes` — a zero-length or 40-byte "backup" is
 *     the classic silent failure, and a job must not proceed on one.
 */
export async function verifyArtefact(
  received: ReceivedFile,
  options: {
    minBytes: number;
    deviceReportedBytes?: number | null;
    /** The device printed an EXACT byte count (`DeviceFile.sizeExact`): hold
     *  the received size to equality with it, not to the RouterOS 6 tolerance
     *  that exists only because 6.x rounds what it prints. */
    exactDeviceBytes?: boolean;
  },
): Promise<VerifiedArtefact> {
  const stat = await fsp.stat(received.path);
  if (stat.size !== received.bytes) {
    throw new TransferError('SIZE_MISMATCH', 'the spooled file is not the size we received', {
      onDisk: stat.size,
      received: received.bytes,
    });
  }
  if (received.bytes < options.minBytes) {
    throw new TransferError(
      'SIZE_MISMATCH',
      `the artefact is ${received.bytes} bytes, below the ${options.minBytes}-byte floor — ` +
        'a backup this small is a failure that answered !done',
      { bytes: received.bytes, minBytes: options.minBytes },
    );
  }
  const rehash = crypto.createHash('sha256');
  await new Promise<void>((resolve, reject) => {
    const s = fs.createReadStream(received.path);
    s.on('data', (c: Buffer | string) => rehash.update(Buffer.isBuffer(c) ? c : Buffer.from(c)));
    s.on('error', reject);
    s.on('end', () => resolve());
  });
  const onDisk = rehash.digest('hex');
  if (onDisk !== received.sha256) {
    throw new TransferError('DIGEST_MISMATCH', 'the stored file does not hash to what we received', {
      streamed: received.sha256,
      onDisk,
    });
  }
  const reported = options.deviceReportedBytes ?? null;
  if (reported !== null && options.exactDeviceBytes === true && reported !== received.bytes) {
    throw new TransferError(
      'SIZE_MISMATCH',
      `the device reported ${reported} bytes and ${received.bytes} were received`,
      { deviceReported: reported, received: received.bytes, tolerance: 0 },
    );
  }
  if (reported !== null && reported > 0) {
    // RouterOS 6 rounds the size it prints. 2% or 1 KiB, whichever is larger.
    const tolerance = Math.max(1024, Math.ceil(reported * 0.02));
    if (Math.abs(reported - received.bytes) > tolerance) {
      throw new TransferError(
        'SIZE_MISMATCH',
        'the device reported a different size than we received',
        { deviceReported: reported, received: received.bytes, tolerance },
      );
    }
  }
  return { path: received.path, bytes: received.bytes, sha256: onDisk };
}

/** sha256 of a local file. Used to re-verify a stored backup months later. */
export async function hashFile(filePath: string): Promise<{ sha256: string; bytes: number }> {
  const hash = crypto.createHash('sha256');
  let bytes = 0;
  await new Promise<void>((resolve, reject) => {
    const s = fs.createReadStream(filePath);
    s.on('data', (c: Buffer | string) => {
      const b = Buffer.isBuffer(c) ? c : Buffer.from(c);
      bytes += b.length;
      hash.update(b);
    });
    s.on('error', reject);
    s.on('end', () => resolve());
  });
  return { sha256: hash.digest('hex'), bytes };
}
