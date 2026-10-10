import {
  ROUTEROS_RELEASE_CHANNELS,
  ROUTEROS_RELEASE_CHECK_INTERVAL_HOURS,
  ROUTEROS_RELEASE_RETRY_INTERVAL_HOURS,
  ROUTEROS_RELEASE_STALE_AFTER_HOURS,
  compareRouterOsVersion,
  isRouterOsReleaseVersion,
  parseRouterOsVersion,
  resolveRouterOsTarget,
  type RouterOsFirmwareStatus,
  type RouterOsReleaseChannel,
  type RouterOsReleaseCheckOutcome,
  type RouterOsReleaseInfo,
  type RouterOsTargetStatus,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { readRouterOsTarget } from './target.service';

/**
 * The latest RouterOS 7 releases, read from MikroTik and recorded in
 * `routeros_releases` (migration 046). This module is the table's only writer.
 *
 * SOURCE, verified with real HTTPS requests (not trusted from a
 * hint): `GET https://upgrade.mikrotik.com/routeros/NEWESTa7.<channel>` answers
 * 200 text/plain `<version> <unix seconds>\n`, e.g. `7.24.5 1790691687\n` for
 * `stable` and `7.23.7 1789561155\n` for `long-term`; an unknown channel file
 * answers 404. The second field is Unix time in SECONDS.
 *
 * ┌─ A FAILED CHECK NEVER BLANKS THE LAST GOOD VALUE ─────────────────────────┐
 * │ A timeout, a 5xx, a redirect, an oversized or malformed body all land in │
 * │ `last_error` and `last_checked_at`; `version`, `released_at`,            │
 * │ `first_seen_at` and `last_success_at` are left exactly as they were. A   │
 * │ watcher that turned "MikroTik did not answer" into "no release known"    │
 * │ would stop the fleet updater on every network blip; one that turned it   │
 * │ into "0.0" would do worse.                                               │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * A check CANCELLED by its caller (the watcher stopping at shutdown) is not a
 * failed check and records nothing: see ReleaseCheckCancelled.
 *
 * The origin is a constant. The `origin` option below exists for the harness's
 * fake HTTP origin only: it is never read from the environment or a request,
 * so nothing outside the code can point the watcher at another host. It is
 * public-internet egress, not tunnel traffic: see releaseWatcher.ts.
 */

const T = 'routeros_releases';

export const ROUTEROS_UPGRADE_ORIGIN = 'https://upgrade.mikrotik.com/routeros/';

/** The file per channel. `a7` = RouterOS 7; `NEWEST6.*` serves RouterOS 6. */
export const ROUTEROS_CHANNEL_FILES: Readonly<Record<RouterOsReleaseChannel, string>> = Object.freeze({
  stable: 'NEWESTa7.stable',
  'long-term': 'NEWESTa7.long-term',
});

/** Bounded: the whole exchange (connect, headers, body) must fit in it. */
export const RELEASE_FETCH_TIMEOUT_MS = 10_000;
/** The real body is 18 bytes; anything past this is not that file. */
const MAX_BODY_BYTES = 256;
/** What is kept of an error message (the column CHECK allows 500). */
const MAX_ERROR_CHARS = 300;
/** A last-check instant this far in the future means the clock moved back. */
const FUTURE_SKEW_MS = 5 * 60_000;

const HOUR_MS = 3_600_000;
const CHECK_INTERVAL_MS = ROUTEROS_RELEASE_CHECK_INTERVAL_HOURS * HOUR_MS;
const RETRY_INTERVAL_MS = ROUTEROS_RELEASE_RETRY_INTERVAL_HOURS * HOUR_MS;
const STALE_AFTER_MS = ROUTEROS_RELEASE_STALE_AFTER_HOURS * HOUR_MS;

/** RouterOS 7 did not exist before this; a "release time" earlier is noise. */
const EARLIEST_PLAUSIBLE_RELEASE_MS = Date.UTC(2015, 0, 1);
const LATEST_PLAUSIBLE_RELEASE_SKEW_MS = 48 * HOUR_MS;

export class ReleaseCheckError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ReleaseCheckError';
  }
}

/**
 * The check was CANCELLED by its caller (`signal`, i.e. the watcher stopping
 * at shutdown). Nothing is recorded for it: "timed out" or "request failed"
 * would be a false statement about MikroTik, and leaving `last_checked_at`
 * where it was makes the next leader's first tick retry it.
 */
export class ReleaseCheckCancelled extends Error {
  constructor() {
    super('RouterOS release check cancelled');
    this.name = 'ReleaseCheckCancelled';
  }
}

export interface ReleaseFetchOptions {
  /** Harness only (see the header). Must end with '/'. */
  origin?: string;
  timeoutMs?: number;
  /** Injected clock, harness only. */
  now?: () => Date;
  /**
   * Cancels the check without recording anything (see ReleaseCheckCancelled).
   * Unlike the timeout, which IS recorded as a failed check.
   */
  signal?: AbortSignal;
}

// -- Parsing ------------------------------------------------------------------

export type ParsedNewest =
  | { ok: true; version: string; releasedAt: Date | null }
  | { ok: false; error: string };

/** Printable ASCII only, bounded: an error may quote what it refused, safely. */
function snippet(s: string): string {
  const clean = s.replace(/[^\x20-\x7e]/g, '.');
  return clean.length > 40 ? `${clean.slice(0, 40)}...` : clean;
}

/**
 * Parse the body of `NEWESTa7.<channel>`: `<version>[ <unix seconds>]` with
 * one optional trailing newline. Strict: a pre-release, a RouterOS 6 version,
 * a second line, or any other shape is an error, never a best effort.
 */
export function parseNewestBody(body: string, now: Date = new Date()): ParsedNewest {
  const line = body.replace(/\r?\n$/, '');
  if (line.length === 0) return { ok: false, error: 'empty response body' };
  if (/[\r\n]/.test(line)) return { ok: false, error: 'unexpected multi-line response body' };
  const m = /^(\S+)(?: (\S+))?$/.exec(line);
  if (!m) return { ok: false, error: `unrecognised response body "${snippet(line)}"` };
  const version = m[1]!;
  if (!isRouterOsReleaseVersion(version)) {
    return { ok: false, error: `not a RouterOS release version: "${snippet(version)}"` };
  }
  if (parseRouterOsVersion(version)!.major !== 7) {
    return { ok: false, error: `not a RouterOS 7 version: "${version}"` };
  }
  let releasedAt: Date | null = null;
  if (m[2] !== undefined) {
    if (!/^[0-9]{9,11}$/.test(m[2])) {
      return { ok: false, error: `unrecognised release time "${snippet(m[2])}"` };
    }
    const ms = Number(m[2]) * 1000;
    // An implausible time is UNKNOWN, not a reason to discard the version.
    if (ms >= EARLIEST_PLAUSIBLE_RELEASE_MS && ms <= now.getTime() + LATEST_PLAUSIBLE_RELEASE_SKEW_MS) {
      releasedAt = new Date(ms);
    }
  }
  return { ok: true, version, releasedAt };
}

// -- Fetching -----------------------------------------------------------------

function describeFetchError(err: unknown, timeoutMs: number): string {
  const e = err as { name?: string; message?: string; cause?: { code?: string; message?: string } };
  if (e?.name === 'TimeoutError' || e?.name === 'AbortError') return `timed out after ${timeoutMs} ms`;
  const detail = e?.cause?.code ?? e?.cause?.message ?? e?.message ?? 'unknown error';
  return `request failed: ${snippet(String(detail))}`;
}

async function readBounded(res: Response, maxBytes: number): Promise<string> {
  const declared = Number(res.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) {
    await res.body?.cancel().catch(() => undefined);
    throw new ReleaseCheckError(`response larger than ${maxBytes} bytes`);
  }
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      throw new ReleaseCheckError(`response larger than ${maxBytes} bytes`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/**
 * One bounded GET of a channel file. Throws `ReleaseCheckError`, or
 * `ReleaseCheckCancelled` when `opts.signal` fired.
 */
export async function fetchChannelBody(
  channel: RouterOsReleaseChannel,
  opts: ReleaseFetchOptions = {},
): Promise<string> {
  const timeoutMs = opts.timeoutMs ?? RELEASE_FETCH_TIMEOUT_MS;
  const url = `${opts.origin ?? ROUTEROS_UPGRADE_ORIGIN}${ROUTEROS_CHANNEL_FILES[channel]}`;
  if (opts.signal?.aborted) throw new ReleaseCheckCancelled();
  const timeout = AbortSignal.timeout(timeoutMs);
  const signal = opts.signal ? AbortSignal.any([timeout, opts.signal]) : timeout;
  const failure = (err: unknown): Error => (opts.signal?.aborted
    ? new ReleaseCheckCancelled()
    : new ReleaseCheckError(describeFetchError(err, timeoutMs)));
  let res: Response;
  try {
    // redirect: 'error' keeps the origin fixed: a redirect is recorded as a
    // failed check (and shows on the settings card) instead of being followed.
    res = await fetch(url, { method: 'GET', redirect: 'error', signal, headers: { accept: 'text/plain' } });
  } catch (err) {
    throw failure(err);
  }
  if (res.status !== 200) {
    await res.body?.cancel().catch(() => undefined);
    throw new ReleaseCheckError(`HTTP ${res.status}`);
  }
  try {
    return await readBounded(res, MAX_BODY_BYTES);
  } catch (err) {
    if (err instanceof ReleaseCheckError) throw err;
    throw failure(err);
  }
}

// -- Recording ----------------------------------------------------------------

interface ReleaseRow {
  channel: RouterOsReleaseChannel;
  version: string | null;
  released_at: Date | null;
  first_seen_at: Date | null;
  last_checked_at: Date;
  last_success_at: Date | null;
  last_error: string | null;
}

async function readRow(channel: RouterOsReleaseChannel): Promise<ReleaseRow | undefined> {
  return db<ReleaseRow>(T).where({ channel }).first();
}

/** Record a successful read. Returns the version previously recorded. */
export async function recordReleaseSuccess(
  channel: RouterOsReleaseChannel,
  version: string,
  releasedAt: Date | null,
  now: Date,
): Promise<{ previous: string | null }> {
  return db.transaction(async (trx) => {
    const prev = await trx<ReleaseRow>(T).where({ channel }).forUpdate().first('version');
    await trx(T)
      .insert({
        channel,
        version,
        released_at: releasedAt,
        first_seen_at: now,
        last_checked_at: now,
        last_success_at: now,
        last_error: null,
      })
      .onConflict('channel')
      .merge({
        version,
        // Same version: keep the instant it was first seen, and keep a
        // publication time already known if this answer carried none.
        first_seen_at: trx.raw(
          `CASE WHEN ${T}.version IS NOT DISTINCT FROM excluded.version `
            + `THEN ${T}.first_seen_at ELSE excluded.first_seen_at END`,
        ),
        released_at: trx.raw(
          `CASE WHEN ${T}.version IS NOT DISTINCT FROM excluded.version `
            + `THEN COALESCE(excluded.released_at, ${T}.released_at) ELSE excluded.released_at END`,
        ),
        last_checked_at: now,
        last_success_at: now,
        last_error: null,
      });
    return { previous: prev?.version ?? null };
  });
}

/** Record a failed read: ONLY `last_checked_at` and `last_error` move. */
export async function recordReleaseFailure(
  channel: RouterOsReleaseChannel,
  error: string,
  now: Date,
): Promise<void> {
  const message = error.length > MAX_ERROR_CHARS ? `${error.slice(0, MAX_ERROR_CHARS)}...` : error;
  await db(T)
    .insert({ channel, last_checked_at: now, last_error: message })
    .onConflict('channel')
    .merge(['last_checked_at', 'last_error']);
}

// -- Scheduling ---------------------------------------------------------------

export interface ReleaseScheduleState {
  lastCheckedAt: Date | null;
  lastSuccessAt: Date | null;
}

/**
 * Is a check of this channel due? Pure.
 *  - never checked                     -> due (this is the "at startup" case);
 *  - an attempt in the last hour       -> not due (no hammering, success or not);
 *  - never succeeded                   -> due (hourly retry);
 *  - last success 24 h old or more     -> due;
 *  - an instant in the future (clock moved back by more than 5 min) -> due,
 *    since otherwise the watcher would sleep until the clock caught up.
 */
export function isReleaseCheckDue(state: ReleaseScheduleState | null, now: Date): boolean {
  if (!state || !state.lastCheckedAt) return true;
  const sinceAttempt = now.getTime() - state.lastCheckedAt.getTime();
  if (sinceAttempt < -FUTURE_SKEW_MS) return true;
  if (sinceAttempt < RETRY_INTERVAL_MS) return false;
  if (!state.lastSuccessAt) return true;
  const sinceSuccess = now.getTime() - state.lastSuccessAt.getTime();
  if (sinceSuccess < -FUTURE_SKEW_MS) return true;
  return sinceSuccess >= CHECK_INTERVAL_MS;
}

// -- Checking -----------------------------------------------------------------

/**
 * Read one channel and record the outcome. Never throws for a check failure;
 * throws `ReleaseCheckCancelled` (and records nothing) when `opts.signal` fired.
 */
export async function checkReleaseChannel(
  channel: RouterOsReleaseChannel,
  opts: ReleaseFetchOptions = {},
): Promise<RouterOsReleaseCheckOutcome> {
  const now = opts.now?.() ?? new Date();
  let parsed: ParsedNewest;
  try {
    parsed = parseNewestBody(await fetchChannelBody(channel, opts), now);
  } catch (err) {
    if (err instanceof ReleaseCheckCancelled) throw err;
    parsed = {
      ok: false,
      error: err instanceof ReleaseCheckError ? err.message : describeFetchError(err, opts.timeoutMs ?? RELEASE_FETCH_TIMEOUT_MS),
    };
  }
  if (!parsed.ok) {
    await recordReleaseFailure(channel, parsed.error, now);
    const kept = (await readRow(channel))?.version ?? null;
    // `host` names the egress this needs: an installation whose outbound
    // traffic is limited to the tunnel subnet logs this once an hour per
    // channel (the retry cadence) until upgrade.mikrotik.com is reachable.
    logger.warn(
      { channel, error: parsed.error, kept, host: new URL(ROUTEROS_UPGRADE_ORIGIN).host },
      'RouterOS release check failed; last good value kept',
    );
    return { channel, ok: false, version: kept, changed: false, error: parsed.error };
  }
  const { previous } = await recordReleaseSuccess(channel, parsed.version, parsed.releasedAt, now);
  const changed = previous !== parsed.version;
  if (changed && previous !== null && compareRouterOsVersion(parsed.version, previous) < 0) {
    // Recorded anyway: the channel is the authority, and MikroTik withdrawing a
    // release is exactly when a "latest" target must follow it down. Whether a
    // ROUTER is ever downgraded is the updater's decision, not this table's.
    logger.warn({ channel, previous, version: parsed.version }, 'RouterOS release channel moved BACKWARDS');
  } else if (changed) {
    logger.info({ channel, previous, version: parsed.version }, 'New RouterOS release recorded');
  }
  return { channel, ok: true, version: parsed.version, changed, error: null };
}

export interface CheckReleasesOptions extends ReleaseFetchOptions {
  /** true = check every channel now (the operator's button); false = only due ones. */
  force?: boolean;
}

let inFlight: { forced: boolean; promise: Promise<RouterOsReleaseCheckOutcome[]> } | null = null;

async function runChecks(opts: CheckReleasesOptions): Promise<RouterOsReleaseCheckOutcome[]> {
  const outcomes: RouterOsReleaseCheckOutcome[] = [];
  for (const channel of ROUTEROS_RELEASE_CHANNELS) {
    if (opts.signal?.aborted) throw new ReleaseCheckCancelled();
    if (!opts.force) {
      const row = await readRow(channel);
      const state = row ? { lastCheckedAt: row.last_checked_at, lastSuccessAt: row.last_success_at } : null;
      if (!isReleaseCheckDue(state, opts.now?.() ?? new Date())) continue;
    }
    outcomes.push(await checkReleaseChannel(channel, opts));
  }
  return outcomes;
}

/**
 * Check the channels (all of them when forced, the due ones otherwise).
 * Concurrent calls in one process coalesce: a call that arrives while a check
 * runs joins it, except a FORCED call arriving during an unforced one, which
 * waits for it and then runs its own (the unforced one may have skipped
 * channels that were not due). Only the call that STARTED a run brings its
 * `signal`: a call that joins a run cannot cancel it, and a run cancelled by
 * its starter rejects every call that joined it with ReleaseCheckCancelled.
 */
export async function checkRouterOsReleases(
  opts: CheckReleasesOptions = {},
): Promise<RouterOsReleaseCheckOutcome[]> {
  const forced = opts.force === true;
  if (inFlight) {
    if (inFlight.forced || !forced) return inFlight.promise;
    await inFlight.promise.catch(() => undefined);
    return checkRouterOsReleases(opts);
  }
  const promise = runChecks(opts).finally(() => {
    if (inFlight?.promise === promise) inFlight = null;
  });
  inFlight = { forced, promise };
  return promise;
}

// -- Reading ------------------------------------------------------------------

function iso(d: Date | null | undefined): string | null {
  return d ? new Date(d).toISOString() : null;
}

function toInfo(channel: RouterOsReleaseChannel, row: ReleaseRow | undefined, now: Date): RouterOsReleaseInfo {
  const lastSuccess = row?.last_success_at ? new Date(row.last_success_at) : null;
  return {
    channel,
    version: row?.version ?? null,
    releasedAt: iso(row?.released_at),
    firstSeenAt: iso(row?.first_seen_at),
    lastCheckedAt: iso(row?.last_checked_at),
    lastSuccessAt: iso(lastSuccess),
    lastError: row?.last_error ?? null,
    stale: lastSuccess === null || now.getTime() - lastSuccess.getTime() > STALE_AFTER_MS,
  };
}

/** Everything `GET /api/firmware/routeros` answers. */
export async function getRouterOsFirmwareStatus(now: Date = new Date()): Promise<RouterOsFirmwareStatus> {
  const rows = await db<ReleaseRow>(T).select('*');
  const byChannel = new Map(rows.map((r) => [r.channel, r]));
  const stable = toInfo('stable', byChannel.get('stable'), now);
  const longTerm = toInfo('long-term', byChannel.get('long-term'), now);

  const stored = await readRouterOsTarget();
  const resolution = resolveRouterOsTarget(stored.setting, {
    stable: stable.version,
    longTerm: longTerm.version,
  });
  const source = stored.setting?.mode === 'long-term' ? longTerm
    : stored.setting?.mode === 'stable' ? stable : null;
  const target: RouterOsTargetStatus = {
    mode: stored.setting?.mode ?? null,
    pinned: stored.setting?.pinned ?? null,
    ...resolution,
    isDefault: stored.isDefault,
    stale: resolution.resolved !== null && source !== null && source.stale,
    updatedAt: stored.updatedAt,
    updatedBy: stored.updatedBy,
  };

  const attempts = [stable.lastCheckedAt, longTerm.lastCheckedAt].filter((x): x is string => x !== null);
  const errors = [stable, longTerm]
    .filter((i) => i.lastError !== null)
    .map((i) => `${i.channel}: ${i.lastError}`);
  return {
    stable,
    longTerm,
    lastCheckedAt: attempts.length ? attempts.sort()[attempts.length - 1]! : null,
    lastError: errors.length ? errors.join('; ') : null,
    target,
    checkIntervalHours: ROUTEROS_RELEASE_CHECK_INTERVAL_HOURS,
  };
}

/**
 * THE fleet target: what the bench and the fleet updater must aim at.
 * `resolved === null` means "do not upgrade", with the reason in
 * `unresolvedReason`; `stale === true` means the version comes from a channel
 * reading older than ROUTEROS_RELEASE_STALE_AFTER_HOURS. Never a downgrade
 * decision: comparing it with what a router runs is the caller's job.
 */
export async function resolveRouterOsFleetTarget(now: Date = new Date()): Promise<RouterOsTargetStatus> {
  return (await getRouterOsFirmwareStatus(now)).target;
}
