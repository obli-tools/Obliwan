import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { z } from 'zod';
import { db } from '../../db';
import { logger } from '../../utils/logger';

/**
 * ObliWAN — authorised bench workstations.
 *
 * ┌─ WHAT A STATION TOKEN IS, AND WHAT IT IS NOT ────────────────────────────┐
 * │ The workstation draws a random token ONCE, keeps it, and sends it on     │
 * │ every call as `Authorization: Bench <token>`. The server keeps only its  │
 * │ sha256. A human approves the station once; after that its token          │
 * │ authorises the bench routes, and nothing else — it is not an operator    │
 * │ session, it reads no fleet data, and `requireAuth` never sees it.        │
 * │                                                                          │
 * │ It does NOT replace the per-device approval. A device a station enrols   │
 * │ still lands `pending` and unmanaged in the master tenant. There are now  │
 * │ TWO human gates where the anonymous design had one: "this desk may       │
 * │ enrol", once, and "this box is who it says", per device.                 │
 * │                                                                          │
 * │ For a box a station COMPILED a file for, the per-device gate may instead │
 * │ be the automatic conformity check (an explicit design decision; its     │
 * │ conditions are in `fleet/deviceBinding.service.ts`, header box) — and   │
 * │ that check requires this station to be `approved` at the instant of the │
 * │ confirmation: revoking a desk stops every confirmation it would carry.  │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The pure half of this file (token format, header parsing, the access verdict,
 * the transition table, the touch throttle) is kept apart from the database
 * half so the decisions can be tested without a database —
 * `testing/stations.verify.ts`. The decisions are the part that must not drift.
 */

// ============================================================================
// Vocabulary
// ============================================================================

export const BENCH_STATION_STATUSES = ['pending', 'approved', 'revoked'] as const;
export type BenchStationStatus = (typeof BENCH_STATION_STATUSES)[number];

export function isBenchStationStatus(v: unknown): v is BenchStationStatus {
  return typeof v === 'string' && (BENCH_STATION_STATUSES as readonly string[]).includes(v);
}

// ============================================================================
// The token
// ============================================================================

/** 32 random bytes, hex-encoded. The floor, not a target. */
export const STATION_TOKEN_MIN_HEX = 64;
/** A ceiling so a caller cannot make us hash a megabyte per request. */
export const STATION_TOKEN_MAX_HEX = 256;
/**
 * A token is drawn by the WORKSTATION, so the server cannot vouch for its
 * randomness — but it can refuse the one failure that is a bug rather than an
 * attack: a zero-filled buffer (`Buffer.alloc` where `randomBytes` was meant).
 * Every bench with that bug would send the SAME token, and because registration
 * is idempotent on the hash, they would all silently become one station. A
 * genuinely random 64-hex token has fewer than 8 distinct digits with a
 * probability around 1e-19.
 */
export const STATION_TOKEN_MIN_DISTINCT_DIGITS = 8;

const HEX_RE = /^[0-9a-f]+$/;

/**
 * Canonical form of a token, or null when it is not one.
 *
 * Trimmed BEFORE it is judged (the `Number(' ')` trap: emptiness is
 * tested after the trim, never before), and lower-cased because hex is
 * case-blind — the same 32 bytes typed in capitals must not become a second
 * station.
 */
export function normaliseStationToken(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const t = raw.trim().toLowerCase();
  if (t.length < STATION_TOKEN_MIN_HEX || t.length > STATION_TOKEN_MAX_HEX) return null;
  if (t.length % 2 !== 0) return null;
  if (!HEX_RE.test(t)) return null;
  if (new Set(t).size < STATION_TOKEN_MIN_DISTINCT_DIGITS) return null;
  return t;
}

/** sha256 hex of the canonical token, or null when the input is not a token.
 *  The ONLY function that turns a token into what the database holds. */
export function stationTokenHash(raw: unknown): string | null {
  const token = normaliseStationToken(raw);
  if (token === null) return null;
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

// ============================================================================
// The verification code
// ============================================================================

/**
 * What the administrator compares before approving.
 *
 * Registration is public, so anything a registrant SENDS can be copied: an
 * impostor registers as "Établi 1" / "PREP-01" as easily as the real desk does,
 * and `last_ip` is the Docker bridge gateway for every caller. Without a
 * code, the approval screen shows two identical rows. The code comes from the
 * row's `uuid`, which the DATABASE draws (`gen_random_uuid()`). No registrant
 * chooses it, so no registrant can make theirs match the real desk's.
 *
 * THE CONTRACT. The bench DISPLAYS the code it gets back from `register` and
 * from `/me`. The approval screen shows each row's code. The administrator
 * approves the row whose code matches the one the person at the desk reads off
 * the screen, and approves nothing when no row matches.
 *
 * Eight hex digits, from the uuid's first group. In a version-4 uuid those 32
 * bits are all random (the version nibble is in the third group). An impostor
 * has one chance in four billion per registration of drawing the real desk's
 * code, and the public route lets it hold at most `MAX_PENDING_STATIONS`
 * pending rows. Returns null rather than a guess when the uuid is not one: a
 * wrong code is worse than none, because somebody would compare it.
 */
export function stationVerificationCode(uuid: unknown): string | null {
  if (typeof uuid !== 'string') return null;
  const hex = uuid.replace(/-/g, '').toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(hex)) return null;
  return `${hex.slice(0, 4)}-${hex.slice(4, 8)}`.toUpperCase();
}

// ============================================================================
// The header
// ============================================================================

export type BenchAuthorization =
  | { kind: 'token'; tokenHash: string }
  | { kind: 'missing' }
  | { kind: 'wrong_scheme' }
  | { kind: 'malformed' };

/**
 * Parse `Authorization: Bench <token>`.
 *
 * The scheme is case-insensitive (RFC 9110 §11.1); the credential is exactly one
 * token. Every failure is a 401 at the caller, but the three kinds are kept
 * apart so the message can say WHICH mistake was made — "you sent a Bearer" and
 * "your token is 63 characters" have different fixes. None of them ever echoes
 * the value back.
 */
export function parseBenchAuthorization(header: unknown): BenchAuthorization {
  if (header === undefined || header === null) return { kind: 'missing' };
  if (typeof header !== 'string') return { kind: 'malformed' };
  const h = header.trim();
  if (h === '') return { kind: 'missing' };

  const sp = h.search(/\s/);
  const scheme = sp === -1 ? h : h.slice(0, sp);
  if (scheme.toLowerCase() !== 'bench') return { kind: 'wrong_scheme' };

  const credential = sp === -1 ? '' : h.slice(sp).trim();
  if (credential === '' || /\s/.test(credential)) return { kind: 'malformed' };

  const tokenHash = stationTokenHash(credential);
  return tokenHash ? { kind: 'token', tokenHash } : { kind: 'malformed' };
}

// ============================================================================
// The access verdict
// ============================================================================

/**
 * `self` — `GET /bench/stations/me`: a station asking about ITSELF, which a
 *          pending station must be able to do, or it could never learn that it
 *          has been approved.
 * `act`  — every route that does something on the platform's behalf (device
 *          enrolment today, phase B's provisioning tomorrow): approved only.
 */
export type StationScope = 'self' | 'act';

export type StationRefusalReason = 'unknown' | 'pending' | 'revoked' | 'invalid_status';

export type StationVerdict =
  | { allow: true; httpStatus: 200; reason: 'approved' | 'pending' }
  | { allow: false; httpStatus: 401 | 403; reason: StationRefusalReason };

/**
 * The single decision about what a token may do. `null` is "no station holds
 * this token", which is a 401: as far as we can tell the caller has not
 * authenticated at all. A revoked station is a 403 — we know exactly who it is,
 * and the answer is no — on every scope, `self` included, so a revoked bench
 * stops at its first call instead of waiting forever for an approval that will
 * not come.
 *
 * A status outside the vocabulary fails CLOSED. The CHECK constraint makes it
 * unreachable today; the day someone adds a fourth status to the table and not
 * to this function, it must lock benches out, not wave them through.
 */
export function stationAccessVerdict(status: string | null, scope: StationScope): StationVerdict {
  if (status === null) return { allow: false, httpStatus: 401, reason: 'unknown' };
  if (!isBenchStationStatus(status)) {
    return { allow: false, httpStatus: 403, reason: 'invalid_status' };
  }
  switch (status) {
    case 'approved':
      return { allow: true, httpStatus: 200, reason: 'approved' };
    case 'pending':
      return scope === 'self'
        ? { allow: true, httpStatus: 200, reason: 'pending' }
        : { allow: false, httpStatus: 403, reason: 'pending' };
    case 'revoked':
      return { allow: false, httpStatus: 403, reason: 'revoked' };
  }
}

// ============================================================================
// Transitions
// ============================================================================

export type StationAction = 'approve' | 'revoke';

/**
 * The whole lifecycle. `revoked` is TERMINAL, and that is the point of the
 * table rather than an omission in it: a station is revoked because its token
 * may be in somebody else's hands, and "re-approve" would revive that very
 * token. A revoked bench registers again with a FRESH token — a new row, a new
 * approval — and the old row stays as the record of what happened.
 */
export const STATION_TRANSITIONS: Readonly<
  Record<BenchStationStatus, Readonly<Partial<Record<StationAction, BenchStationStatus>>>>
> = {
  pending: { approve: 'approved', revoke: 'revoked' },
  approved: { revoke: 'revoked' },
  revoked: {},
};

const ACTION_TARGET: Readonly<Record<StationAction, BenchStationStatus>> = {
  approve: 'approved',
  revoke: 'revoked',
};

export type TransitionPlan =
  | { kind: 'apply'; from: BenchStationStatus; to: BenchStationStatus }
  | { kind: 'noop'; status: BenchStationStatus }
  | { kind: 'refused'; from: BenchStationStatus; reason: string };

/**
 * A repeat of the action already in force is a NO-OP, not an error: an
 * administrator double-clicking "approve" did not ask for anything new. It is
 * also not a rewrite — re-approving must not replace `approved_by` with the
 * second clicker, because the first one is who took the decision.
 */
export function planStationTransition(
  from: BenchStationStatus,
  action: StationAction,
): TransitionPlan {
  if (from === ACTION_TARGET[action]) return { kind: 'noop', status: from };
  const to = STATION_TRANSITIONS[from][action];
  if (to) return { kind: 'apply', from, to };
  return {
    kind: 'refused',
    from,
    reason:
      from === 'revoked'
        ? 'This workstation was REVOKED, and a revocation is final: its token may be in '
          + "somebody else's hands, and approving it again would revive that token. Have the "
          + 'bench register again with a new token, then approve the new entry.'
        : `A workstation that is '${from}' cannot be asked to ${action}.`,
  };
}

// ============================================================================
// The last-seen throttle
// ============================================================================

export const STATION_TOUCH_INTERVAL_MS = 60_000;

/** True when `last_seen_at` is due a write. A bench polling `/me` every five
 *  seconds must not turn into a database write every five seconds. */
export function shouldTouchStation(lastTouchedMs: number | undefined, nowMs: number): boolean {
  return lastTouchedMs === undefined || nowMs - lastTouchedMs >= STATION_TOUCH_INTERVAL_MS;
}

/** An address `inet` will accept, or null. `req.ip` is normally one, but a
 *  value the column refuses would turn a bookkeeping write into a failed call. */
export function storableIp(ip: unknown): string | null {
  return typeof ip === 'string' && isIP(ip) !== 0 ? ip : null;
}

// ============================================================================
// Registration payload
// ============================================================================

/**
 * C0/C1 controls refused in anything a human will read on the approval screen
 * or in a log line: a station name carrying a newline forges a second log line,
 * and one carrying an ANSI escape repaints an operator's terminal.
 */
// eslint-disable-next-line no-control-regex
export const NO_CONTROL_CHARACTERS = /^[^\u0000-\u001f\u007f-\u009f]*$/;

const label = (max: number) =>
  z
    .string()
    .trim()
    .min(1)
    .max(max)
    .regex(NO_CONTROL_CHARACTERS, 'control characters are not allowed');

export const registerStationSchema = z.object({
  name: label(128),
  hostname: z.preprocess(
    (v) => (typeof v === 'string' && v.trim() === '' ? null : v),
    label(255).nullable().optional(),
  ),
  // Validated, NOT transformed: the controller hashes it through
  // `stationTokenHash`, and a schema that returned the hash would put a second
  // spelling of "what is stored" in a place nobody looks.
  token: z.string().refine((t) => normaliseStationToken(t) !== null, {
    message:
      `token must be ${STATION_TOKEN_MIN_HEX} to ${STATION_TOKEN_MAX_HEX} hexadecimal characters `
      + 'drawn from a cryptographic random source',
  }),
});
export type RegisterStationInput = z.infer<typeof registerStationSchema>;

// ============================================================================
// Errors
// ============================================================================

export type BenchStationErrorCode = 'NOT_FOUND' | 'TRANSITION_REFUSED' | 'PENDING_CAP';

export class BenchStationError extends Error {
  constructor(
    public readonly code: BenchStationErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'BenchStationError';
  }
}

// ============================================================================
// Rows and DTO
// ============================================================================

export interface BenchStationRow {
  id: number;
  uuid: string;
  name: string;
  hostname: string | null;
  token_hash: string;
  status: string;
  created_at: Date;
  approved_at: Date | null;
  approved_by: number | null;
  revoked_at: Date | null;
  revoked_by: number | null;
  last_seen_at: Date | null;
  last_ip: string | null;
}

/** What an administrator sees. `token_hash` is not here: it is not a secret in
 *  the sense a token is, but nothing on the screen needs it, and a column that
 *  never leaves cannot leak. */
export interface BenchStationDto {
  id: number;
  uuid: string;
  name: string;
  hostname: string | null;
  /** The code the bench displays. The approval screen must show it beside
   *  the name. See `stationVerificationCode`. */
  verificationCode: string | null;
  status: BenchStationStatus;
  createdAt: string;
  approvedAt: string | null;
  approvedBy: number | null;
  approvedByUsername: string | null;
  revokedAt: string | null;
  revokedBy: number | null;
  revokedByUsername: string | null;
  lastSeenAt: string | null;
  lastIp: string | null;
  /** Devices this station enrolled — the first thing to look at before, and
   *  after, revoking it. */
  enrolledDeviceCount: number;
}

interface DtoSourceRow extends Omit<BenchStationRow, 'token_hash'> {
  approved_by_username: string | null;
  revoked_by_username: string | null;
  enrolled_device_count: string | number | null;
}

const iso = (d: Date | null): string | null => (d ? new Date(d).toISOString() : null);

function toDto(r: DtoSourceRow): BenchStationDto {
  return {
    id: r.id,
    uuid: r.uuid,
    name: r.name,
    hostname: r.hostname,
    verificationCode: stationVerificationCode(r.uuid),
    // Narrowed here so the client never has to. The CHECK makes anything else
    // unreachable; if it were reached, showing it as revoked is the reading
    // that matches what `stationAccessVerdict` does with it (refuse).
    status: isBenchStationStatus(r.status) ? r.status : 'revoked',
    createdAt: new Date(r.created_at).toISOString(),
    approvedAt: iso(r.approved_at),
    approvedBy: r.approved_by,
    approvedByUsername: r.approved_by_username,
    revokedAt: iso(r.revoked_at),
    revokedBy: r.revoked_by,
    revokedByUsername: r.revoked_by_username,
    lastSeenAt: iso(r.last_seen_at),
    lastIp: r.last_ip,
    enrolledDeviceCount: Number(r.enrolled_device_count ?? 0),
  };
}

function dtoQuery() {
  return db('bench_stations as s')
    .leftJoin('users as ua', 'ua.id', 's.approved_by')
    .leftJoin('users as ur', 'ur.id', 's.revoked_by')
    .select(
      's.id',
      's.uuid',
      's.name',
      's.hostname',
      's.status',
      's.created_at',
      's.approved_at',
      's.approved_by',
      's.revoked_at',
      's.revoked_by',
      's.last_seen_at',
      's.last_ip',
      'ua.username as approved_by_username',
      'ur.username as revoked_by_username',
      db('devices as d')
        .count('*')
        .whereRaw('d.enrolled_by_station_id = s.id')
        .as('enrolled_device_count'),
    );
}

// ============================================================================
// Database operations
// ============================================================================

/**
 * A ceiling on stations awaiting a decision. Registration is public and its
 * rate limit is per address — so without this, patience alone fills the
 * approval screen until the one real bench is lost among the rows. A full queue
 * refuses NEW registrations only: a station already registered keeps getting
 * its answer, because idempotency is checked first.
 *
 * EXACT, not approximate: the count and the insert run under one advisory lock
 * (`registerStation`), so a burst of concurrent registrations cannot all read
 * 49 and all insert.
 */
export const MAX_PENDING_STATIONS = 50;

/**
 * Advisory lock for registration, two-int form so it reads as classid/objid in
 * `pg_locks`. The class differs from every class already in the tree: 20311
 * (the rollout subtree interlock, and also 0x4F57, leader election), 730119204
 * (audit chain), 36036 (allocation) and 0x0F6 (identity watch). 0x6265 = 'be'.
 */
const BENCH_LOCK_CLASS = 0x6265;
const BENCH_LOCK_REGISTER = 1;

export async function findStationByTokenHash(tokenHash: string): Promise<BenchStationRow | null> {
  const row = await db('bench_stations')
    .where({ token_hash: tokenHash })
    .first<BenchStationRow | undefined>();
  return row ?? null;
}

/**
 * Idempotent on the token hash. A bench that lost the answer to its first call
 * (timeout, closed laptop) calls again with the same token and gets the SAME
 * station back — never a second row for the same machine.
 *
 * A repeat does NOT update the name or hostname. Renaming on re-registration
 * would let a station change, after approval, the very label the administrator
 * approved it under.
 *
 * The pending count and the insert run in ONE transaction under
 * `pg_advisory_xact_lock`, so `MAX_PENDING_STATIONS` holds under concurrency.
 * Without the lock, N simultaneous registrations would all read the same count
 * and all insert. Only an insert can raise the pending count: approve and
 * revoke only lower it, so they need not take the lock. The re-read of the
 * token under the lock is what keeps a same-token race idempotent: READ
 * COMMITTED gives each statement a fresh snapshot, and the lock is released
 * only after the previous holder has committed.
 */
export async function registerStation(input: {
  name: string;
  hostname: string | null;
  tokenHash: string;
  ip: unknown;
}): Promise<{ station: BenchStationRow; created: boolean }> {
  // Outside the lock: a bench repeating its registration is the common case
  // once a desk exists, and it must not queue behind a burst of strangers.
  const existing = await findStationByTokenHash(input.tokenHash);
  if (existing) return { station: existing, created: false };

  return db.transaction(async (trx) => {
    await trx.raw('SELECT pg_advisory_xact_lock(?, ?)', [BENCH_LOCK_CLASS, BENCH_LOCK_REGISTER]);

    const raced = await trx('bench_stations')
      .where({ token_hash: input.tokenHash })
      .first<BenchStationRow | undefined>();
    if (raced) return { station: raced, created: false };

    const [{ count }] = await trx('bench_stations')
      .where({ status: 'pending' })
      .count<{ count: string }[]>('* as count');
    if (Number(count) >= MAX_PENDING_STATIONS) {
      throw new BenchStationError(
        'PENDING_CAP',
        `${MAX_PENDING_STATIONS} workstations are already waiting for approval. An administrator `
          + 'must approve or revoke some of them on the bench workstations page before this one '
          + 'can register; then retry the registration.',
      );
    }

    const [row] = await trx('bench_stations')
      .insert({
        name: input.name,
        hostname: input.hostname,
        token_hash: input.tokenHash,
        status: 'pending',
        // Registration is itself a call made with the token, so it is the
        // first observation of the holder. See the migration's column comment.
        last_ip: storableIp(input.ip),
        last_seen_at: trx.fn.now(),
      })
      .returning<BenchStationRow[]>('*');
    return { station: row, created: true };
  });
}

export async function listStations(): Promise<BenchStationDto[]> {
  const rows = (await dtoQuery()
    // Pending first: it is the list an administrator opens this page to act on.
    .orderByRaw(`CASE s.status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END`)
    .orderBy('s.created_at', 'desc')) as DtoSourceRow[];
  return rows.map(toDto);
}

export async function getStationDto(id: number): Promise<BenchStationDto | null> {
  const row = (await dtoQuery().where('s.id', id).first()) as DtoSourceRow | undefined;
  return row ? toDto(row) : null;
}

/**
 * Apply an administrator's decision.
 *
 * Compare-and-set on the status the plan was made against: two administrators
 * acting at once must not have the second one's `approve` land on a station the
 * first one has just revoked. A lost race re-reads and re-plans ONCE, which
 * turns it into the honest answer (a no-op, or a refusal) instead of a retry
 * loop.
 */
export async function transitionStation(
  id: number,
  action: StationAction,
  userId: number | null,
): Promise<{ outcome: 'applied' | 'noop'; station: BenchStationDto }> {
  for (let attempt = 0; attempt < 2; attempt++) {
    const current = await db('bench_stations')
      .where({ id })
      .first<Pick<BenchStationRow, 'id' | 'status' | 'name'> | undefined>('id', 'status', 'name');
    if (!current) throw new BenchStationError('NOT_FOUND', 'Bench workstation not found');
    if (!isBenchStationStatus(current.status)) {
      throw new BenchStationError(
        'TRANSITION_REFUSED',
        `This workstation carries an unknown status '${current.status}'.`,
      );
    }

    const plan = planStationTransition(current.status, action);
    if (plan.kind === 'refused') throw new BenchStationError('TRANSITION_REFUSED', plan.reason);
    if (plan.kind === 'noop') {
      const dto = await getStationDto(id);
      if (!dto) throw new BenchStationError('NOT_FOUND', 'Bench workstation not found');
      return { outcome: 'noop', station: dto };
    }

    const patch: Record<string, unknown> =
      plan.to === 'approved'
        ? { status: 'approved', approved_at: db.fn.now(), approved_by: userId }
        : { status: 'revoked', revoked_at: db.fn.now(), revoked_by: userId };

    const updated = await db('bench_stations').where({ id, status: plan.from }).update(patch);
    if (updated === 1) {
      logger.info(
        { stationId: id, stationName: current.name, from: plan.from, to: plan.to, by: userId },
        `Bench workstation ${plan.to}`,
      );
      const dto = await getStationDto(id);
      if (!dto) throw new BenchStationError('NOT_FOUND', 'Bench workstation not found');
      return { outcome: 'applied', station: dto };
    }
    // Somebody moved it between our read and our write — look again.
  }
  throw new BenchStationError(
    'TRANSITION_REFUSED',
    'This workstation changed state while the decision was being recorded. Reload the list and '
      + 'retry the approval or revocation.',
  );
}

/** Per-process memory of the last write, so a polling bench costs a Map lookup
 *  and not a round-trip. The WHERE clause in `touchStation` is what makes the
 *  once-a-minute rule hold across several processes; this only makes it cheap. */
const lastTouch = new Map<number, number>();
const LAST_TOUCH_MAX = 10_000;

/**
 * Record that the holder of this token called, at most once a minute.
 * `registerStation` writes the first value. This keeps it current afterwards.
 *
 * An OBSERVATION, written whatever the verdict — including for a pending or a
 * revoked station. A revoked token still in use somewhere is exactly the
 * evidence an administrator wants to see on the row.
 *
 * Never throws: it is bookkeeping, and a bench refused because a timestamp
 * could not be written would be refused for a reason that has nothing to do
 * with it.
 */
export async function touchStation(id: number, ip: unknown): Promise<void> {
  const now = Date.now();
  if (!shouldTouchStation(lastTouch.get(id), now)) return;
  if (lastTouch.size >= LAST_TOUCH_MAX) lastTouch.clear();
  lastTouch.set(id, now);
  try {
    await db('bench_stations')
      .where({ id })
      .andWhere((q) => {
        q.whereNull('last_seen_at').orWhere(
          'last_seen_at',
          '<',
          db.raw(`now() - interval '60 seconds'`),
        );
      })
      .update({ last_seen_at: db.fn.now(), last_ip: storableIp(ip) });
  } catch (err) {
    logger.warn({ err, stationId: id }, 'Could not record bench workstation last-seen');
  }
}

/**
 * Stamp which station enrolled a device. Narrow on purpose: the device must be
 * in the tenant the caller wrote it into, and the column must still be empty —
 * provenance is written once, at enrolment, and never rewritten.
 */
export async function recordEnrolmentStation(
  tenantId: number,
  deviceId: number,
  stationId: number,
): Promise<void> {
  const updated = await db('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .whereNull('enrolled_by_station_id')
    .update({ enrolled_by_station_id: stationId });
  if (updated !== 1) {
    throw new Error(`could not record the enrolling workstation on device #${deviceId}`);
  }
}

// ============================================================================
// Enrolment retries
// ============================================================================

/** The partial unique index of migration 002 that `(brand, serial)` collides
 *  on. PostgreSQL reports a unique-INDEX violation under the index's name. */
export const BRAND_SERIAL_INDEX = 'devices_brand_serial_uniq';

/** True for a pg unique violation on `(brand, serial)` and nothing else. The
 *  test reads the index name, not the message, so a different unique
 *  violation is never mistaken for this one. */
export function isBrandSerialCollision(err: unknown): boolean {
  if (typeof err !== 'object' || err === null) return false;
  const e = err as { code?: unknown; constraint?: unknown };
  return e.code === '23505' && e.constraint === BRAND_SERIAL_INDEX;
}

/** The row that already holds a `(brand, serial)` pair, reduced to the fields
 *  the retry verdict reads. */
export interface SerialHolder {
  id: number;
  tenant_id: number;
  status: string;
  is_managed: boolean;
  enrolled_by_station_id: number | null;
}

export type EnrolmentRetryVerdict =
  | { kind: 'same_enrolment'; deviceId: number }
  | { kind: 'conflict' };

/**
 * Judge a `(brand, serial)` collision on bench enrolment.
 *
 * The serial is now stored, so a bench that lost the answer to its enrolment
 * (a timeout, a Wi-Fi drop) and retries collides with ITS OWN row. That is the
 * same enrolment. Answering "already exists" would tell the clerk the desk
 * failed when it had succeeded.
 *
 * The row counts as the same enrolment only while every fact the first call
 * wrote still holds: this station stamped it, it is still in the tenant the
 * call writes into, still `pending`, still unmanaged. If any of those changed,
 * a human has acted on the row since, and it is no longer "the enrolment you
 * just made". A 200 would hide that. A row with NO stamp is a conflict too,
 * even if it looks like ours: claiming it would write a provenance nobody
 * observed. Every other case is a conflict, and the caller's answer never says
 * whose device it is.
 */
export function judgeEnrolmentRetry(
  holder: SerialHolder | null,
  stationId: number,
  tenantId: number,
): EnrolmentRetryVerdict {
  if (
    holder !== null
    && holder.enrolled_by_station_id === stationId
    && holder.tenant_id === tenantId
    && holder.status === 'pending'
    && holder.is_managed === false
  ) {
    return { kind: 'same_enrolment', deviceId: holder.id };
  }
  return { kind: 'conflict' };
}

/**
 * The row holding `(brand, serial)`, whatever its tenant. NOT tenant-scoped,
 * deliberately: the unique index it mirrors is global, so the colliding row may
 * be in any tenant. The result only feeds `judgeEnrolmentRetry`. No field of a
 * row outside the station's own enrolment ever reaches a response.
 */
export async function findSerialHolder(brand: string, serial: string): Promise<SerialHolder | null> {
  const row = await db('devices')
    .where({ brand, serial })
    .first<SerialHolder | undefined>('id', 'tenant_id', 'status', 'is_managed', 'enrolled_by_station_id');
  return row ?? null;
}
