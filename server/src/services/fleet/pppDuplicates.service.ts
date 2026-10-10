/**
 * ObliWAN — a PPP login with SEVERAL live sessions on its concentrator
 * (incident 2026-10-09, shared/src/pppDuplicates.ts, migration 091).
 *
 * ┌─ WHY IT IS AMBIGUOUS ────────────────────────────────────────────────────┐
 * │ Two boxes dialling the same account are handed the same remote address  │
 * │ by the secret, and the CHR routes that address to ONE of them — the     │
 * │ newest session, as observed in production. Whatever ObliWAN dials at the│
 * │ tunnel address may therefore be the other box: a forgotten router in the│
 * │ shop, on 4G, was attached as the store's router that way. The identity  │
 * │ check (`assertTargetBinding`, the serial) keeps a later WRITE from      │
 * │ crossing to the other box once the device's identity is recorded, but   │
 * │ nothing SAW the duplicate: presence keeps one open `ppp_sessions` row   │
 * │ per login (002's `ppp_sessions_open_uniq`, unchanged), and a second     │
 * │ session was folded into it silently.                                    │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * WHAT THIS FILE DOES — reads only, towards every router:
 *   - `findDuplicateSessions` (pure) groups a `/ppp/active` read by login,
 *     WITHOUT regard to case (every login comparison in ObliWAN is
 *     case-insensitive: the attach, the allocator, the reconciliation);
 *   - `recordActiveRead` records what a SUCCESSFUL read showed
 *     (`concentrator_active_reads`, `ppp_session_duplicates`), each read
 *     replacing the concentrator's rows. Its writers: presence's 60 s sweep
 *     (pppPresence.service.ts) and the reconciliation's "re-read the CHR";
 *   - `readRecordedDuplicates` / `readActiveReads`: what the reconciliation
 *     and the bulk attach read (they dial nothing);
 *   - `judgeLoginSessions` / `sessionGateForDevice`: the gate the tunnel jobs
 *     pass at `bind_assert`, BEFORE anything is dialled (apply.service.ts) —
 *     a LIVE `/ppp/active/print` on the concentrator's pool socket, and only
 *     when that read fails, the last read presence recorded, if it is recent
 *     (RECORDED_READ_MAX_AGE_MS). When neither is available the gate says
 *     `unknown`, the caller LOGS it and keeps today's behaviour: a refusal is
 *     never invented from no evidence.
 *
 * Nothing here writes to a concentrator: kicking a session or setting the
 * profile's only-one is the operator's gesture, made on the CHR.
 */

import { describeDuplicateSessions, parseRouterOsUptimeSeconds, type PppDuplicateSession } from '@obliwan/shared';
import type { Knex } from 'knex';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { readPppActive, type PppActiveEntry } from './concentratorDiscovery.service';

// ============================================================================
// Pure
// ============================================================================

export interface DuplicatedLogin {
  /** lower(login): the key the sessions were grouped by. */
  loginKey: string;
  /** The first session's spelling, as the read printed it. */
  login: string;
  /** Two or more, in the read's order. */
  sessions: PppDuplicateSession[];
}

/** One `/ppp/active` entry as a duplicated login lists it. */
export function toDuplicateSession(e: PppActiveEntry, readAt: Date): PppDuplicateSession {
  const up = parseRouterOsUptimeSeconds(e.uptime);
  return {
    name: e.name,
    callerId: e.callerId,
    address: e.address,
    uptime: e.uptime,
    since: up === null ? null : new Date(readAt.getTime() - up * 1000).toISOString(),
  };
}

/** The sessions of a read that carry `login`, without regard to case. */
export function sessionsOfLogin(entries: readonly PppActiveEntry[], login: string): PppActiveEntry[] {
  const key = login.trim().toLowerCase();
  return entries.filter((e) => e.name.toLowerCase() === key);
}

/** Every login a `/ppp/active` read lists with two sessions or more, by key. */
export function findDuplicateSessions(entries: readonly PppActiveEntry[], readAt: Date): DuplicatedLogin[] {
  const groups = new Map<string, PppActiveEntry[]>();
  for (const e of entries) {
    const key = e.name.toLowerCase();
    const list = groups.get(key);
    if (list) list.push(e);
    else groups.set(key, [e]);
  }
  const out: DuplicatedLogin[] = [];
  for (const [loginKey, list] of groups) {
    if (list.length < 2) continue;
    out.push({ loginKey, login: list[0].name, sessions: list.map((e) => toDuplicateSession(e, readAt)) });
  }
  return out.sort((a, b) => a.loginKey.localeCompare(b.loginKey));
}

// ============================================================================
// Recording a read
// ============================================================================

/** `pg_advisory_xact_lock(class, concentratorId)`: the recorders of one
 *  concentrator (the sweep, the re-read) serialise on it. */
const RECORD_LOCK_CLASS = 0x7064;

export interface ActiveReadRecord {
  sessions: number;
  duplicates: number;
  /** Logins this read found duplicated that the previous one did not. */
  appeared: string[];
  /** false: a NEWER read was already recorded; this one changed nothing. */
  recorded: boolean;
}

/**
 * Record what a SUCCESSFUL `/ppp/active` read of `concentratorId` showed: the
 * read itself, and its duplicated logins, replacing the concentrator's rows
 * (a login no longer duplicated is deleted). ONE transaction, serialised per
 * concentrator; a read older than the one already recorded is discarded
 * rather than allowed to roll the observation back. Never called with a read
 * that failed: an empty list here means "no session", not "unknown".
 */
export async function recordActiveRead(
  concentratorId: number,
  entries: readonly PppActiveEntry[],
  readAt: Date = new Date(),
): Promise<ActiveReadRecord> {
  const dups = findDuplicateSessions(entries, readAt);
  const result = await db.transaction(async (trx): Promise<ActiveReadRecord> => {
    await trx.raw('SELECT pg_advisory_xact_lock(?, ?)', [RECORD_LOCK_CLASS, concentratorId]);
    const last = (await trx('concentrator_active_reads').where({ concentrator_id: concentratorId }).first('read_at')) as
      | { read_at: Date | string }
      | undefined;
    if (last && new Date(last.read_at).getTime() > readAt.getTime()) {
      return { sessions: entries.length, duplicates: dups.length, appeared: [], recorded: false };
    }
    const before = new Set(
      (await trx('ppp_session_duplicates').where({ concentrator_id: concentratorId }).pluck('login_key')) as string[],
    );
    const keys = dups.map((d) => d.loginKey);
    const gone = trx('ppp_session_duplicates').where({ concentrator_id: concentratorId });
    if (keys.length > 0) gone.whereNotIn('login_key', keys);
    await gone.del();
    for (const d of dups) {
      await trx('ppp_session_duplicates')
        .insert({
          concentrator_id: concentratorId,
          login_key: d.loginKey,
          ppp_username: d.login,
          session_count: d.sessions.length,
          sessions: JSON.stringify(d.sessions),
          first_seen_at: readAt,
          observed_at: readAt,
        })
        .onConflict(['concentrator_id', 'login_key'])
        // first_seen_at is kept: the duplicate's age is the operator's clue.
        .merge(['ppp_username', 'session_count', 'sessions', 'observed_at']);
    }
    await trx('concentrator_active_reads')
      .insert({ concentrator_id: concentratorId, read_at: readAt, session_count: entries.length, duplicate_count: dups.length })
      .onConflict('concentrator_id')
      .merge(['read_at', 'session_count', 'duplicate_count']);
    return {
      sessions: entries.length,
      duplicates: dups.length,
      appeared: dups.filter((d) => !before.has(d.loginKey)).map((d) => d.login),
      recorded: true,
    };
  });
  if (result.appeared.length > 0) {
    // Logins and caller-ids only: `/ppp/active` carries no secret.
    logger.warn(
      {
        concentratorId,
        logins: dups
          .filter((d) => result.appeared.includes(d.login))
          .map((d) => ({ login: d.login, sessions: describeDuplicateSessions(d.sessions) })),
      },
      'PPP: a login holds SEVERAL live sessions on this concentrator; its tunnel address is ambiguous and the ' +
        'attach and the tunnel jobs refuse it until one session remains',
    );
  }
  return result;
}

// ============================================================================
// Reading what was recorded
// ============================================================================

export interface RecordedDuplicate {
  concentratorId: number;
  loginKey: string;
  login: string;
  sessions: PppDuplicateSession[];
  firstSeenAt: string;
  observedAt: string;
}

function iso(value: Date | string): string {
  return new Date(value).toISOString();
}

function asSessions(raw: unknown): PppDuplicateSession[] {
  const list = typeof raw === 'string' ? (JSON.parse(raw) as unknown) : raw;
  if (!Array.isArray(list)) return [];
  const text = (v: unknown): string | null => (typeof v === 'string' && v !== '' ? v : null);
  return list.map((s: Record<string, unknown>) => ({
    name: typeof s.name === 'string' ? s.name : '',
    callerId: text(s.callerId),
    address: text(s.address),
    uptime: text(s.uptime),
    since: text(s.since),
  }));
}

/** The duplicated logins the last read of each of `concentratorIds` recorded,
 *  optionally only those `loginKeys` (lower case). On `q`, so a caller holding
 *  a transaction (a READ ONLY one included) reads inside it. */
export async function readRecordedDuplicates(
  q: Knex | Knex.Transaction,
  concentratorIds: readonly number[],
  loginKeys: readonly string[] | null = null,
): Promise<RecordedDuplicate[]> {
  if (concentratorIds.length === 0 || (loginKeys !== null && loginKeys.length === 0)) return [];
  const query = q('ppp_session_duplicates').whereIn('concentrator_id', [...new Set(concentratorIds)]);
  if (loginKeys !== null) query.whereIn('login_key', [...new Set(loginKeys.map((k) => k.toLowerCase()))]);
  const rows = (await query
    .orderBy(['concentrator_id', 'login_key'])
    .select('concentrator_id', 'login_key', 'ppp_username', 'sessions', 'first_seen_at', 'observed_at')) as Array<{
    concentrator_id: number;
    login_key: string;
    ppp_username: string;
    sessions: unknown;
    first_seen_at: Date | string;
    observed_at: Date | string;
  }>;
  return rows.map((r) => ({
    concentratorId: Number(r.concentrator_id),
    loginKey: r.login_key,
    login: r.ppp_username,
    sessions: asSessions(r.sessions),
    firstSeenAt: iso(r.first_seen_at),
    observedAt: iso(r.observed_at),
  }));
}

export interface ActiveReadRow {
  readAt: string;
  sessionCount: number;
  duplicateCount: number;
}

/** When each concentrator's `/ppp/active` was last read successfully. */
export async function readActiveReads(
  q: Knex | Knex.Transaction,
  concentratorIds: readonly number[],
): Promise<Map<number, ActiveReadRow>> {
  if (concentratorIds.length === 0) return new Map();
  const rows = (await q('concentrator_active_reads')
    .whereIn('concentrator_id', [...new Set(concentratorIds)])
    .select('concentrator_id', 'read_at', 'session_count', 'duplicate_count')) as Array<{
    concentrator_id: number;
    read_at: Date | string;
    session_count: number;
    duplicate_count: number;
  }>;
  return new Map(
    rows.map((r) => [
      Number(r.concentrator_id),
      { readAt: iso(r.read_at), sessionCount: Number(r.session_count), duplicateCount: Number(r.duplicate_count) },
    ]),
  );
}

// ============================================================================
// The gate — live first, then the freshest recorded read
// ============================================================================

/** One live `/ppp/active/print` may take this long before the gate falls
 *  back on the recorded read. */
export const LIVE_READ_TIMEOUT_MS = 15_000;
/** A recorded read older than this is not evidence for the gate. Presence
 *  sweeps every 60 s, so a read this old means presence is not keeping it. */
export const RECORDED_READ_MAX_AGE_MS = 10 * 60_000;

export type SessionGateVerdict =
  | { state: 'not_applicable'; reason: string }
  /** At most one session: `count` from a live read, null from a recorded one
   *  (which records only the duplicated logins). */
  | { state: 'unique'; source: 'live' | 'recorded'; login: string; count: number | null; observedAt: string }
  | { state: 'duplicate'; source: 'live' | 'recorded'; login: string; sessions: PppDuplicateSession[]; observedAt: string }
  /** No evidence either way: the caller keeps today's behaviour, and logs. */
  | { state: 'unknown'; login: string; reason: string };

export interface SessionGateDeps {
  /** The live read (the harness swaps it). */
  readActive(concentratorId: number): Promise<PppActiveEntry[]>;
  now(): number;
}
const DEFAULT_GATE_DEPS: SessionGateDeps = { readActive: readPppActive, now: () => Date.now() };
let gateDeps: SessionGateDeps = { ...DEFAULT_GATE_DEPS };
export function setSessionGateDeps(next: Partial<SessionGateDeps>): void {
  gateDeps = { ...gateDeps, ...next };
}
export function resetSessionGateDeps(): void {
  gateDeps = { ...DEFAULT_GATE_DEPS };
}

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | null = null;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`no answer within ${ms} ms`)), ms);
    timer.unref();
  });
  return Promise.race([p, timeout]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

/** One live read of `concentratorId`, bounded; throws when it fails. */
export function readActiveLive(concentratorId: number): Promise<PppActiveEntry[]> {
  return withTimeout(gateDeps.readActive(concentratorId), LIVE_READ_TIMEOUT_MS);
}

/**
 * How many live sessions `login` holds on `concentratorId`. LIVE first (one
 * `/ppp/active/print` on the pool socket); when that read fails, the last
 * read presence recorded, if it is younger than RECORDED_READ_MAX_AGE_MS;
 * otherwise `unknown`. Never throws.
 */
export async function judgeLoginSessions(target: { concentratorId: number; login: string }): Promise<SessionGateVerdict> {
  const login = target.login;
  let liveError: string;
  try {
    const entries = await readActiveLive(target.concentratorId);
    const mine = sessionsOfLogin(entries, login);
    const at = new Date(gateDeps.now());
    if (mine.length >= 2) {
      return { state: 'duplicate', source: 'live', login, sessions: mine.map((e) => toDuplicateSession(e, at)), observedAt: at.toISOString() };
    }
    return { state: 'unique', source: 'live', login, count: mine.length, observedAt: at.toISOString() };
  } catch (err) {
    liveError = err instanceof Error ? err.message : String(err);
  }
  try {
    const reads = await readActiveReads(db, [target.concentratorId]);
    const read = reads.get(target.concentratorId);
    if (!read) return { state: 'unknown', login, reason: `live read failed (${liveError}); no /ppp/active read was ever recorded` };
    const age = gateDeps.now() - new Date(read.readAt).getTime();
    if (age > RECORDED_READ_MAX_AGE_MS) {
      return {
        state: 'unknown',
        login,
        reason: `live read failed (${liveError}); the last recorded /ppp/active read (${read.readAt}) is too old to judge by`,
      };
    }
    const [dup] = await readRecordedDuplicates(db, [target.concentratorId], [login.trim().toLowerCase()]);
    if (dup) return { state: 'duplicate', source: 'recorded', login, sessions: dup.sessions, observedAt: dup.observedAt };
    return { state: 'unique', source: 'recorded', login, count: null, observedAt: read.readAt };
  } catch (err) {
    return {
      state: 'unknown',
      login,
      reason: `live read failed (${liveError}); the recorded read could not be consulted (${err instanceof Error ? err.message : String(err)})`,
    };
  }
}

/**
 * The gate for one device: its PPP login on its concentrator. A device with
 * no concentrator or no login (the standalone router dialled on a public
 * address, a concentrator itself) is `not_applicable`. Never throws.
 */
export async function sessionGateForDevice(deviceId: number): Promise<SessionGateVerdict> {
  let row: { concentrator_id: number | null; ppp_username: string | null; role: string | null } | undefined;
  try {
    row = (await db('devices as d')
      .leftJoin('devices as c', 'c.id', 'd.concentrator_id')
      .where('d.id', deviceId)
      .first('d.concentrator_id', 'd.ppp_username', 'c.role')) as typeof row;
  } catch (err) {
    return { state: 'unknown', login: '', reason: `the device could not be read (${err instanceof Error ? err.message : String(err)})` };
  }
  if (!row) return { state: 'not_applicable', reason: 'device not found' };
  const login = row.ppp_username?.trim() ?? '';
  if (row.concentrator_id === null || login === '') {
    return { state: 'not_applicable', reason: 'no PPP login on a concentrator' };
  }
  if (row.role !== 'concentrator') return { state: 'not_applicable', reason: 'its concentrator_id is not a concentrator' };
  return judgeLoginSessions({ concentratorId: Number(row.concentrator_id), login });
}

/** The jobs that dial the router THROUGH its tunnel and change it: they pass
 *  the gate at `bind_assert`, before anything is dialled. The concentrator's
 *  own jobs (concentrator_secret, concentrator_link, infra_account) and the
 *  read-only ones (export, backup) do not. */
export const SESSION_GATED_JOB_KINDS: ReadonlySet<string> = new Set([
  'push',
  'restore',
  'reboot',
  'firmware',
  'os_upgrade',
  'management_access',
  'lte_apn',
  'legacy_compliance',
  'site_rename',
  'wan_link',
]);

/** The refusal's sentence: the login, the sessions (caller-id, uptime), where
 *  the observation comes from, and what to do. Never a password: `/ppp/active`
 *  carries none. */
export function duplicateSessionsRefusalMessage(
  deviceName: string,
  verdict: Extract<SessionGateVerdict, { state: 'duplicate' }>,
): string {
  const from = verdict.source === 'live' ? 'read live from the concentrator just now' : `as presence recorded it at ${verdict.observedAt}`;
  return (
    `The PPP login ${verdict.login} of ${deviceName} holds ${verdict.sessions.length} sessions at once on its concentrator ` +
    `(${describeDuplicateSessions(verdict.sessions)}; ${from}). Its tunnel address reaches whichever session the ` +
    'concentrator routes to, so the router that would answer may not be this device: nothing was dialled and nothing ' +
    'was written. Disconnect the extra router (or remove its session on the concentrator), then run the job again.'
  );
}
