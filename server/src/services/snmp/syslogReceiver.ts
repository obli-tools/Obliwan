/**
 * The syslog listener (UDP/514, and TCP/514 as well).
 *
 * THE LOG PIPELINE ADDED TWO THINGS AND CHANGED NOTHING ELSE:
 *   - a TCP listener (RFC 6587, both framings) that shares this file's single
 *     admission path, so the severity floor and the per-source limits cannot
 *     be bypassed by picking a different transport;
 *   - extraction of `device_login_events` from the lines we already store,
 *     which is the evidence the attribution engine attributes a configuration change from.
 *
 * ┌─ THIS IS THE REAL BOTTLENECK OF SNMP AND SYSLOG. ─────────────────────────┐
 * │ Study section 5.5: at a modest 5 messages per device per minute, syslog   │
 * │ writes 1.04 GB/day against 1.55 GB/day for EVERY SNMP series combined. A  │
 * │ chatty firewall logging per-session triples that on its own, and one      │
 * │ device stuck in a log loop fills the volume in a night -- which takes the │
 * │ supervision of 300 sites down, because the poller cannot write either.    │
 * │                                                                          │
 * │ Four defences, all of them here, none of them optional:                   │
 * │   1. SEVERITY FLOOR AT INGESTION. What is filtered is never written.      │
 * │      There is no "store everything and filter at display".                │
 * │   2. PER-SOURCE TOKEN BUCKET, in memory, before parsing — CPU protection, │
 * │      sized for the fleet (see below).                                     │
 * │   3. PER-ROUTER DAILY QUOTA on the lines KEPT, with a circuit breaker,    │
 * │      under a FLEET-WIDE daily ceiling. In memory: a restart resets them.  │
 * │      `syslog_ingest_state` records the per-address counters for           │
 * │      visibility (who is flooding); it is written, never reloaded.         │
 * │   4. A BOUNDED QUEUE that DROPS AND COUNTS. Never a buffer that grows.    │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHY THE QUOTA IS PER ROUTER AND NOT PER SOURCE ADDRESS (2026-10-07) ────┐
 * │ Behind the Docker bridge every router arrives from the SAME address.      │
 * │ A quota keyed on that address was one quota for the whole fleet, counted  │
 * │ on every datagram including the below-floor ones never stored: a busy     │
 * │ morning spent it, and every router's syslog went silent until the UTC day │
 * │ changed — with nothing on any screen saying so. The quota is now keyed on │
 * │ the hostname the line announces (what attribution matches on; the source  │
 * │ address only for a line that announces none) and counts lines KEPT. A     │
 * │ sender inventing hostnames is held by the fleet ceiling and the bounded   │
 * │ key map (`overflow`). GET /logs/sources and /logs/health make a silence   │
 * │ visible, per router and for the fleet.                                    │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * PARTITIONED ON `received_at`, OUR CLOCK -- never on the device's timestamp.
 * A router booting without NTP cheerfully reports 1970 or 2035. Partitioning
 * on that means either a check violation on every such message or live
 * partitions decades away that retention never reaches, and it would wreck the
 * BRIN, which needs temporal/physical correlation. `device_ts` is kept
 * verbatim beside it, because the gap between the two is itself diagnostic --
 * it is how you notice a fleet with no NTP.
 *
 * Attribution follows the same rule as traps: the source IP is stored but
 * is NOT the identity. The RFC 5424 / RFC 3164 HOSTNAME field is what we match
 * on, and no match means `device_id IS NULL`.
 */

import dgram from 'dgram';
import net from 'net';
import type { Knex } from 'knex';
import type { DeviceBrand, SyslogQuotaState, SyslogRouterQuota } from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { snmpConfig } from './config';
import { ensurePartitionFor, isMissingPartitionError } from './partition.service';
import { logsConfig } from '../logs/config';
import { loginFromSyslog, recordLoginEvents, type LoginEventInput } from '../logs/loginEvents.service';

/**
 * Knex types `RawBinding` as a homogeneous scalar or array, which cannot
 * express "an array of arrays, some of which contain nulls" -- exactly the
 * shape every `unnest()` insert in this codebase needs. The cast is confined
 * to this one helper rather than sprinkled at each call site, so there is one
 * place to look if the driver's contract ever changes.
 */
function bindings(values: unknown[]): readonly Knex.RawBinding[] {
  return values as readonly Knex.RawBinding[];
}


export interface ParsedSyslog {
  facility: number;
  severity: number;
  deviceTs: Date | null;
  hostname: string | null;
  appName: string | null;
  procId: string | null;
  msgId: string | null;
  msg: string;
  structuredData: Record<string, unknown>;
}

const stats = {
  received: 0,
  accepted: 0,
  belowFloor: 0,
  malformed: 0,
  rateLimited: 0,
  /** Dropped by a router's daily quota (its breaker open or spent). */
  quotaSuppressed: 0,
  /** Dropped by the fleet-wide daily ceiling. */
  fleetQuotaSuppressed: 0,
  queueDropped: 0,
  stored: 0,
  // -- TCP -----------------------------------------------------------------
  /** Currently open TCP connections, and the ones we refused over the cap. */
  tcpOpen: 0,
  tcpRefused: 0,
  /** Frames abandoned because a sender never delimited them (see the TCP
   *  section): the unbounded-buffer failure, caught rather than allowed. */
  tcpOversizedFrames: 0,
  /** Login events extracted from stored lines. Not the number of lines that
   *  MENTION a login — the number that parsed completely enough to attribute. */
  loginEvents: 0,
  /** Lines kept DESPITE being under the severity floor because they look like
   *  account activity. Counted separately so the cost of that exception is
   *  visible instead of hiding inside `stored`. */
  belowFloorKeptAccount: 0,
};

export function syslogStats(): typeof stats {
  return { ...stats };
}

/** Queue depth and breaker state for the health endpoint. Separate from
 *  `syslogStats()` because these are gauges, not counters, and mixing the two
 *  in one object is how a dashboard ends up plotting a rate of a depth. */
export function syslogGauges(): {
  queueDepth: number;
  queueMax: number;
  suppressedSources: number;
} {
  const day = today();
  let suppressed = 0;
  for (const q of quotas.values()) if (q.day === day && q.keptToday >= snmpConfig.syslogDailyQuota) suppressed += 1;
  return { queueDepth: queue.length, queueMax: snmpConfig.syslogQueueMax, suppressedSources: suppressed };
}

// ============================================================================
// Parsing
// ============================================================================

const PRI = /^<(\d{1,3})>/;
// RFC 5424: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
const RFC5424 =
  /^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) (?:-|(\[.*?\](?=\s|$)))\s?([\s\S]*)$/;
// RFC 3164: <PRI>MMM dd hh:mm:ss HOSTNAME TAG: MSG
const RFC3164 = /^<(\d{1,3})>([A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}) (\S+) (.*)$/;

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/**
 * The BSD timestamp carries no year. Assuming the current one puts every
 * message of the last days of December into next January when the message is
 * received in the first days of January; the correction below rolls the year
 * back when the reconstructed date lands more than a day in the future.
 */
function parseBsdTimestamp(raw: string, receivedAt: Date): Date | null {
  const month = MONTHS.indexOf(raw.slice(0, 3));
  if (month < 0) return null;
  const day = Number.parseInt(raw.slice(4, 6).trim(), 10);
  const [h, m, s] = raw.slice(7).split(':').map((v) => Number.parseInt(v, 10));
  if ([day, h, m, s].some((v) => !Number.isFinite(v))) return null;
  let year = receivedAt.getUTCFullYear();
  let candidate = new Date(Date.UTC(year, month, day, h, m, s));
  if (candidate.getTime() - receivedAt.getTime() > 86_400_000) {
    year -= 1;
    candidate = new Date(Date.UTC(year, month, day, h, m, s));
  }
  return candidate;
}

/** Anything a device sends is untrusted text. Cap the length and drop control
 *  bytes: an unbounded `msg` is both a disk problem and an XSS vector on the
 *  incident screen that renders it. */
function clean(value: string | null | undefined, max: number): string | null {
  if (value === undefined || value === null) return null;
  const s = value.replace(/[\u0000-\u001f\u007f]/g, '').trim();
  if (s.length === 0 || s === '-') return null;
  return s.slice(0, max);
}

export function parseSyslog(raw: string, receivedAt: Date): ParsedSyslog | null {
  const pri = PRI.exec(raw);
  if (!pri) return null;
  const priority = Number.parseInt(pri[1], 10);
  if (!Number.isFinite(priority) || priority > 191) return null;
  const facility = Math.floor(priority / 8);
  const severity = priority % 8;

  const m5424 = RFC5424.exec(raw);
  if (m5424) {
    const ts = new Date(m5424[2]);
    return {
      facility,
      severity,
      deviceTs: Number.isNaN(ts.getTime()) ? null : ts,
      hostname: clean(m5424[3], 255),
      appName: clean(m5424[4], 64),
      procId: clean(m5424[5], 64),
      msgId: clean(m5424[6], 64),
      msg: clean(m5424[8], 8192) ?? '',
      structuredData: m5424[7] ? { raw: m5424[7].slice(0, 2048) } : {},
    };
  }

  const m3164 = RFC3164.exec(raw);
  if (m3164) {
    const body = m3164[4];
    // RFC 3164 says the TAG is alphanumeric, up to 32 characters. Real
    // equipment disagrees, and the fleet this supervises is the reason the
    // comma is in the character class: RouterOS emits topic lists such as
    // `system,error,critical` where the RFC expects `sshd`. Refusing them
    // would silently drop the app_name of every MikroTik in the estate -- the
    // majority of the fleet -- and leave a column that looks merely sparse.
    const tag = /^([A-Za-z0-9_/.,+-]{1,32})(?:\[(\d{1,10})\])?:\s?([\s\S]*)$/.exec(body);
    return {
      facility,
      severity,
      deviceTs: parseBsdTimestamp(m3164[2], receivedAt),
      hostname: clean(m3164[3], 255),
      appName: tag ? clean(tag[1], 64) : null,
      procId: tag ? clean(tag[2], 64) : null,
      msgId: null,
      msg: clean(tag ? tag[3] : body, 8192) ?? '',
      structuredData: {},
    };
  }

  // A PRI with a body we cannot structure is still a message worth keeping:
  // several vendors emit `<190>some free text`. Dropping it would lose the
  // logs of whichever brand is least standards-compliant, which tends to be
  // the one being debugged.
  return {
    facility,
    severity,
    deviceTs: null,
    hostname: null,
    appName: null,
    procId: null,
    msgId: null,
    msg: clean(raw.slice(pri[0].length), 8192) ?? '',
    structuredData: {},
  };
}

// ============================================================================
// Limiting: a CPU bucket per source address, a daily quota per router
// ============================================================================

/** Per source ADDRESS — in practice the one bridge gateway. */
interface SourceState {
  tokens: number;
  last: number;
  /** Lines from this address that were KEPT (past the floor and the quotas). */
  acceptedToday: number;
  /** Lines from this address refused by the bucket or by a quota. */
  droppedToday: number;
  rateLimitedToday: number;
  bytesToday: number;
  day: string;
}

const sources = new Map<string, SourceState>();

function today(): string {
  return new Date().toISOString().slice(0, 10);
}

/** The next UTC midnight: when every daily counter starts again. */
function nextUtcMidnight(now = new Date()): Date {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1));
}

function stateFor(ip: string): SourceState {
  const day = today();
  let state = sources.get(ip);
  if (!state || state.day !== day) {
    state = {
      // A new day must not refill a bucket mid-burst: the tokens carry over.
      tokens: state ? state.tokens : snmpConfig.syslogRateLimitPerSource,
      last: state ? state.last : Date.now(),
      acceptedToday: 0,
      droppedToday: 0,
      rateLimitedToday: 0,
      bytesToday: 0,
      day,
    };
    sources.set(ip, state);
  }
  return state;
}

/**
 * The token bucket: CPU protection BEFORE parsing, per source address.
 *
 * It absorbs a BURST; the per-router daily quota (below, after parsing)
 * catches a LOOP. A burst limit alone lets a loop through at exactly the
 * permitted rate, for ever, which is the case that fills the disk. Its rate is
 * sized for the whole fleet (snmp/config.ts): behind the bridge, this one
 * bucket is shared by every router.
 */
function admitSource(state: SourceState): boolean {
  const now = Date.now();
  state.tokens = Math.min(
    snmpConfig.syslogRateLimitPerSource,
    state.tokens + ((now - state.last) / 1000) * snmpConfig.syslogRateLimitPerSource,
  );
  state.last = now;
  if (state.tokens < 1) {
    state.droppedToday += 1;
    state.rateLimitedToday += 1;
    stats.rateLimited += 1;
    return false;
  }
  state.tokens -= 1;
  return true;
}

/** One router's daily quota (SyslogRouterQuota in shared/logs.ts). */
interface QuotaState {
  key: string;
  hostname: string | null;
  deviceId: number | null;
  keptToday: number;
  droppedToday: number;
  /** Breaker: no line from this key before this instant (epoch ms). */
  suppressedUntil: number;
  lastKeptAt: number;
  day: string;
}

/** Bounded: past this many keys, new hostnames share ONE `overflow` quota —
 *  a sender inventing a hostname per line can neither grow the map nor buy
 *  itself a fresh quota per line. */
const QUOTA_KEYS_MAX = 20_000;
const quotas = new Map<string, QuotaState>();
const fleet = { day: '', keptToday: 0, droppedToday: 0, warnedDay: '' };

/** The quota key of a line: the hostname it announces (what attribution
 *  matches on), or the source address when it announces none. NEVER the
 *  address when a hostname is there. */
function quotaKeyOf(hostname: string | null, sourceIp: string): { key: string; hostname: string | null } {
  if (hostname) {
    const h = hostname.toLowerCase();
    return { key: `h:${h}`, hostname: h };
  }
  return { key: `src:${sourceIp}`, hostname: null };
}

function quotaFor(key: string, hostname: string | null): QuotaState {
  const day = today();
  const prev = quotas.get(key);
  if (prev && prev.day === day) return prev;
  if (!prev && quotas.size >= QUOTA_KEYS_MAX) {
    // Forget yesterday's keys first; still full → the shared overflow quota.
    for (const [k, v] of quotas) if (v.day !== day) quotas.delete(k);
    if (quotas.size >= QUOTA_KEYS_MAX && key !== 'overflow') return quotaFor('overflow', null);
  }
  const q: QuotaState = {
    key,
    hostname,
    deviceId: prev?.deviceId ?? null,
    keptToday: 0,
    droppedToday: 0,
    suppressedUntil: 0,
    lastKeptAt: prev?.lastKeptAt ?? 0,
    day,
  };
  quotas.set(key, q);
  return q;
}

/**
 * The daily quotas, on a line that is about to be KEPT (it passed the floor).
 * Returns the router's quota key, or null when the line is refused.
 *
 * A router that has kept its quota today is suppressed for
 * SYSLOG_SUPPRESS_MINUTES and re-suppressed at its next line until the UTC
 * day changes: that is what a DAILY quota means. Every other router keeps
 * sending. The fleet ceiling holds when hostnames are invented.
 */
function admitQuota(src: SourceState, hostname: string | null, sourceIp: string): string | null {
  const now = Date.now();
  const { key, hostname: host } = quotaKeyOf(hostname, sourceIp);
  const q = quotaFor(key, host);
  const day = today();
  if (fleet.day !== day) {
    fleet.day = day;
    fleet.keptToday = 0;
    fleet.droppedToday = 0;
  }

  if (q.suppressedUntil > now) {
    q.droppedToday += 1;
    src.droppedToday += 1;
    stats.quotaSuppressed += 1;
    return null;
  }
  if (q.keptToday >= snmpConfig.syslogDailyQuota) {
    q.suppressedUntil = now + snmpConfig.syslogSuppressMinutes * 60_000;
    q.droppedToday += 1;
    src.droppedToday += 1;
    stats.quotaSuppressed += 1;
    logger.warn(
      {
        quotaKey: q.key,
        deviceId: q.deviceId,
        quota: snmpConfig.syslogDailyQuota,
        minutes: snmpConfig.syslogSuppressMinutes,
        resetsAt: nextUtcMidnight().toISOString(),
      },
      'Syslog daily quota exhausted for this router — suppressed (circuit breaker); other routers are unaffected',
    );
    return null;
  }
  if (fleet.keptToday >= snmpConfig.syslogFleetDailyQuota) {
    fleet.droppedToday += 1;
    q.droppedToday += 1;
    src.droppedToday += 1;
    stats.fleetQuotaSuppressed += 1;
    if (fleet.warnedDay !== day) {
      fleet.warnedDay = day;
      logger.warn(
        { fleetQuota: snmpConfig.syslogFleetDailyQuota, resetsAt: nextUtcMidnight().toISOString() },
        'Syslog FLEET daily ceiling reached — no syslog line is stored until the UTC day changes',
      );
    }
    return null;
  }
  q.keptToday += 1;
  q.lastKeptAt = now;
  fleet.keptToday += 1;
  src.acceptedToday += 1;
  return q.key;
}

function toRouterQuota(q: QuotaState): SyslogRouterQuota {
  return {
    key: q.key,
    hostname: q.hostname,
    deviceId: q.deviceId,
    keptToday: q.keptToday,
    droppedToday: q.droppedToday,
    exhausted: q.keptToday >= snmpConfig.syslogDailyQuota,
    lastKeptAt: q.lastKeptAt > 0 ? new Date(q.lastKeptAt).toISOString() : null,
  };
}

/**
 * Today's quotas, for the health endpoint — PLATFORM ADMINISTRATORS ONLY
 * (every customer's hostnames, the bridge address). Spent or dropping routers
 * first, then the busiest, at most `limit`.
 */
export function syslogQuotaStates(limit = 200): SyslogQuotaState {
  const day = today();
  const spent = (q: QuotaState): number => (q.keptToday >= snmpConfig.syslogDailyQuota ? 1 : 0);
  const routers = [...quotas.values()]
    .filter((q) => q.day === day)
    .sort((a, b) => spent(b) - spent(a) || b.droppedToday - a.droppedToday || b.keptToday - a.keptToday)
    .slice(0, limit)
    .map(toRouterQuota);
  const fleetToday = fleet.day === day;
  return {
    day,
    resetsAt: nextUtcMidnight().toISOString(),
    perRouterQuota: snmpConfig.syslogDailyQuota,
    fleetQuota: snmpConfig.syslogFleetDailyQuota,
    fleetKeptToday: fleetToday ? fleet.keptToday : 0,
    fleetDroppedToday: fleetToday ? fleet.droppedToday : 0,
    fleetExhausted: fleetToday && fleet.keptToday >= snmpConfig.syslogFleetDailyQuota,
    routers,
    sources: [...sources.entries()]
      .filter(([, s]) => s.day === day)
      .map(([ip, s]) => ({
        sourceIp: ip,
        keptToday: s.acceptedToday,
        droppedToday: s.droppedToday,
        rateLimitedToday: s.rateLimitedToday,
      })),
  };
}

/**
 * One router's quota today, by its identity (the hostname it announces is its
 * `system_identity`) or by the device a line of it was attributed to. Null when
 * nothing arrived from it since this process started.
 */
export function syslogQuotaForDevice(deviceId: number, systemIdentity: string | null): SyslogRouterQuota | null {
  const day = today();
  const byName = systemIdentity ? quotas.get(`h:${systemIdentity.toLowerCase()}`) : undefined;
  const q = byName && byName.day === day
    ? byName
    : [...quotas.values()].find((v) => v.day === day && v.deviceId === deviceId);
  return q ? toRouterQuota(q) : null;
}

/** Flush the per-ADDRESS counters into `syslog_ingest_state`, so an operator
 *  can see who is talking and how much was refused. Written for visibility
 *  only: nothing reads it back, and a restart resets the in-memory quotas.
 *  `suppressed_until` stays NULL — no address is suppressed any more, the
 *  quota is per router (above). */
async function persistIngestState(): Promise<void> {
  const day = today();
  const rows = [...sources.entries()]
    .filter(([, s]) => s.day === day && (s.acceptedToday > 0 || s.droppedToday > 0))
    .map(([ip, s]) => ({
      source_ip: ip,
      day,
      bytes_accepted: s.bytesToday,
      messages_accepted: s.acceptedToday,
      messages_dropped: s.droppedToday,
      suppressed_until: null as Date | null,
      last_seen_at: new Date(),
    }));
  if (rows.length === 0) return;
  await db.raw(
    `INSERT INTO syslog_ingest_state
       (source_ip, day, bytes_accepted, messages_accepted, messages_dropped,
        suppressed_until, last_seen_at)
     SELECT * FROM unnest(?::inet[], ?::date[], ?::bigint[], ?::bigint[], ?::bigint[],
                          ?::timestamptz[], ?::timestamptz[])
     ON CONFLICT (source_ip, day) DO UPDATE SET
       bytes_accepted    = EXCLUDED.bytes_accepted,
       messages_accepted = EXCLUDED.messages_accepted,
       messages_dropped  = EXCLUDED.messages_dropped,
       suppressed_until  = EXCLUDED.suppressed_until,
       last_seen_at      = EXCLUDED.last_seen_at`,
    bindings([
      rows.map((r) => r.source_ip),
      rows.map((r) => r.day),
      rows.map((r) => r.bytes_accepted),
      rows.map((r) => r.messages_accepted),
      rows.map((r) => r.messages_dropped),
      rows.map((r) => (r.suppressed_until ? r.suppressed_until.toISOString() : null)),
      rows.map((r) => r.last_seen_at.toISOString()),
    ]),
  );
}

// ============================================================================
// Attribution and persistence
// ============================================================================

/** Resolved identity of a sender. `brand` rides along because the login
 *  parsers are per-brand and re-querying `devices` per message to find it would
 *  put a round trip in the hot path. */
interface ResolvedSender {
  id: number;
  brand: DeviceBrand | null;
}

/** With an expiry: a miss (unknown or ambiguous identity) used to be cached
 *  until the next restart, so a router enrolled or renamed after its first
 *  line stayed unattributed for days; a stale match outlived a device that
 *  was retired. Positive SYSLOG_ATTRIBUTION_TTL_S, negative at most
 *  SYSLOG_ATTRIBUTION_NEGATIVE_TTL_S (and never longer than the positive). */
const deviceByHostname = new Map<string, { sender: ResolvedSender | null; expiresAt: number }>();

/**
 * Hostname -> device, cached.
 *
 * ┌─ AND NEVER, EVER THE SOURCE IP ───────────────────────────────────────────┐
 * │ The socket's peer address is the Docker bridge gateway: every device in   │
 * │ the fleet appears to come from the same address, so a source-IP match     │
 * │ does not fail to identify — it identifies the SAME WRONG DEVICE for all   │
 * │ of them. `sourceIp` is stored for forensics and is never a join key.      │
 * │                                                                          │
 * │ If a future reader is tempted to "improve" attribution by falling back on │
 * │ the source address when the hostname does not match: that fallback is the │
 * │ bug. An unmatched hostname must leave `device_id NULL`, and the           │
 * │ unattributed feed exists precisely so that gap is visible and fixable.    │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * An ambiguous hostname resolves to nothing rather than to the wrong router.
 */
async function attribute(hostname: string | null): Promise<ResolvedSender | null> {
  if (!hostname) return null;
  const key = hostname.toLowerCase();
  const hit = deviceByHostname.get(key);
  if (hit && hit.expiresAt > Date.now()) return hit.sender;
  // Same reasoning as `attributeTrap()` — see the box there. Syslog over UDP
  // is unauthenticated and carries no tenant, so a tenant predicate is not
  // missing here, it is unwritable. What IS narrowed: `name` is no longer
  // matched (an operator-typed label collides across customers; a hostname
  // read off the box does not), and a device that is not `active` receives no
  // attributed lines at all.
  const matches = await db('devices')
    .whereRaw('lower(system_identity) = ?', [key])
    .where('status', 'active')
    .limit(2)
    .select<{ id: number; brand: string | null }[]>('id', 'brand');
  const resolved: ResolvedSender | null =
    matches.length === 1
      ? { id: matches[0].id, brand: (matches[0].brand as DeviceBrand | null) ?? null }
      : null;
  // The cache is bounded: an attacker who can send syslog could otherwise
  // grow it without limit by inventing hostnames.
  if (deviceByHostname.size > 10_000) deviceByHostname.clear();
  const positiveS = snmpConfig.syslogAttributionTtlS;
  const ttlS = resolved ? positiveS : Math.min(snmpConfig.syslogAttributionNegativeTtlS, positiveS);
  deviceByHostname.set(key, { sender: resolved, expiresAt: Date.now() + ttlS * 1000 });
  return resolved;
}

interface QueuedMessage extends ParsedSyslog {
  receivedAt: Date;
  sourceIp: string;
  /** The daily-quota key the line was counted under (`admitQuota`). */
  quotaKey: string;
}

let queue: QueuedMessage[] = [];

async function flush(): Promise<void> {
  if (queue.length === 0) return;
  const batch = queue;
  queue = [];

  const senders = await Promise.all(batch.map((m) => attribute(m.hostname)));
  // The quota learns which device it is (the health screen names it).
  for (let i = 0; i < batch.length; i += 1) {
    const sender = senders[i];
    if (!sender) continue;
    const q = quotas.get(batch[i].quotaKey);
    if (q) q.deviceId = sender.id;
  }

  const rows = batch.map((m, i) => ({
    received_at: m.receivedAt.toISOString(),
    device_ts: m.deviceTs ? m.deviceTs.toISOString() : null,
    device_id: senders[i]?.id ?? null,
    facility: m.facility,
    severity: m.severity,
    source_ip: m.sourceIp,
    hostname: m.hostname,
    app_name: m.appName,
    proc_id: m.procId,
    msg_id: m.msgId,
    msg: m.msg,
    structured_data: JSON.stringify(m.structuredData),
    parsed: JSON.stringify({}),
  }));

  const insert = (): Promise<unknown> => db('syslog_messages').insert(rows);
  try {
    await insert();
  } catch (err) {
    if (!isMissingPartitionError(err)) throw err;
    await ensurePartitionFor('syslog_messages', batch[0].receivedAt);
    await insert();
  }
  stats.stored += rows.length;

  // ── The login events hidden inside the batch we just stored ─────────────
  // Done AFTER the insert and inside its own try: a failure to extract an
  // attribution hint must never cost us the log line itself. The line is the
  // record; the login event is a derived index over it and can be rebuilt from
  // `/log` on the next pull.
  const logins: LoginEventInput[] = [];
  for (let i = 0; i < batch.length; i += 1) {
    const sender = senders[i];
    // An unattributed line cannot produce a login event: `device_login_events`
    // needs a device to hang off, and a login on an unknown box attributes
    // nothing. The line itself is kept in `syslog_messages` with a NULL device.
    if (!sender) continue;
    const m = batch[i];
    const parsed = loginFromSyslog(m.msg, m.appName, sender.brand);
    if (!parsed) continue;
    logins.push({
      deviceId: sender.id,
      ts: m.receivedAt,
      deviceTs: m.deviceTs,
      event: parsed.event,
      account: parsed.account,
      method: parsed.method,
      sourceIp: parsed.sourceIp,
      origin: 'syslog',
      message: m.msg,
    });
  }
  if (logins.length > 0) {
    try {
      stats.loginEvents += await recordLoginEvents(logins);
    } catch (err) {
      logger.warn({ err, count: logins.length }, 'Could not store syslog-derived login events');
    }
  }
}

// ============================================================================
// The listener
// ============================================================================

let socket: dgram.Socket | null = null;
let tcpServer: net.Server | null = null;
const tcpSockets = new Set<net.Socket>();
let flushTimer: NodeJS.Timeout | null = null;
let stateTimer: NodeJS.Timeout | null = null;

/**
 * Does this line look like account activity?
 *
 * Deliberately cheap and deliberately LOOSE. It is a pre-filter in front of the
 * real parsers, not a parser: a false positive costs one stored row and one
 * failed parse, a false negative costs an attribution. Two `includes()` on a
 * lowercased tag and a bounded prefix of the message — no regex, because this
 * runs on every below-floor message, which is the majority of the traffic.
 */
function isAccountLine(appName: string | null, msg: string): boolean {
  if (appName) {
    const tag = appName.toLowerCase();
    if (
      tag.includes('account') ||
      tag.includes('auth') ||
      tag.includes('sshd') ||
      tag.includes('login')
    ) {
      return true;
    }
  }
  // Only the head of the message: an account line announces itself in its first
  // words, and scanning 8 KB of a firewall session dump would put the cost back.
  const head = msg.slice(0, 120).toLowerCase();
  return (
    head.includes('logged in') ||
    head.includes('logged out') ||
    head.includes('login failure') ||
    head.includes('login success') ||
    head.includes('has logged') ||
    head.includes('accepted password') ||
    head.includes('accepted publickey')
  );
}

/**
 * The single admission path, shared by UDP, TCP and the bench.
 *
 * The order of the five gates is the design, not a style choice, and it is the
 * same on every transport: BOUND, then RATE, then PARSE, then FLOOR, then
 * QUOTA. Parsing before the bound would let a flood cost a full regex pass per
 * message, which is the CPU sink the bound exists to prevent; applying the
 * floor after the write would mean writing the 1.04 GB/day this whole design
 * avoids. The quota comes LAST because it counts what is KEPT, keyed on the
 * hostname only parsing reveals: a below-floor line costs no disk and must not
 * spend a router's quota (it used to, on one quota for the whole fleet).
 */
function admitAndQueue(raw: string, sourceIp: string, bytes: number): boolean {
  stats.received += 1;

  // The queue bound comes FIRST. Once it is full nothing else matters: the
  // process must shed, not parse, not allocate, not queue.
  if (queue.length >= snmpConfig.syslogQueueMax) {
    stats.queueDropped += 1;
    return false;
  }
  const src = stateFor(sourceIp);
  if (!admitSource(src)) return false;

  const receivedAt = new Date();
  const parsed = parseSyslog(raw, receivedAt);
  if (!parsed) {
    stats.malformed += 1;
    return false;
  }
  // The floor is applied HERE, before the row exists.
  if (parsed.severity > snmpConfig.syslogSeverityFloor) {
    // ── THE ONE EXCEPTION, AND WHY IT HAD TO EXIST ────────────────────────
    // RouterOS emits `user admin logged in from ... via winbox` on the
    // `system,info,account` topic at severity `info` (6), which is BELOW the
    // default floor of `notice` (5). Left as it was, the log pipeline would have
    // shipped an attribution engine that never sees a single MikroTik login on the push path — silently,
    // and on the majority of the fleet. The floor is a VOLUME control, and
    // account lines are a handful per device per day: they are the one class
    // of message where the floor costs the product a feature and saves it
    // nothing.
    //
    // Three properties keep this from re-opening the door the floor closed:
    //   - the token bucket runs BEFORE this and the router's daily quota
    //     right after, so a device spamming `logged in` at info level is
    //     still capped;
    //   - the test is two `indexOf` calls, not the parser battery, so a flood
    //     of below-floor traffic does not buy itself a regex pass per message;
    //   - it is counted separately, so its volume is visible rather than
    //     hidden inside `stored`.
    if (!isAccountLine(parsed.appName, parsed.msg)) {
      stats.belowFloor += 1;
      return false;
    }
  }

  const quotaKey = admitQuota(src, parsed.hostname, sourceIp);
  if (quotaKey === null) return false;
  if (parsed.severity > snmpConfig.syslogSeverityFloor) stats.belowFloorKeptAccount += 1;
  src.bytesToday += bytes;

  stats.accepted += 1;
  queue.push({ ...parsed, receivedAt, sourceIp, quotaKey });
  return true;
}

export function startSyslogReceiver(): void {
  if (socket || !snmpConfig.syslogEnabled) return;

  const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
  socket = sock;

  sock.on('message', (msg, rinfo) => {
    if (!admitAndQueue(msg.toString('utf8'), rinfo.address, msg.length)) return;
    if (queue.length >= snmpConfig.syslogFlushBatch) {
      void flush().catch((err) => logger.error({ err }, 'Syslog flush failed — messages lost'));
    }
  });

  sock.on('error', (err) => {
    logger.error({ err, port: snmpConfig.syslogPort }, 'Syslog receiver socket error');
    try {
      sock.close();
    } catch {
      /* already closing */
    }
    socket = null;
  });

  sock.bind(snmpConfig.syslogPort, snmpConfig.syslogBind, () => {
    logger.info(
      {
        port: snmpConfig.syslogPort,
        severityFloor: snmpConfig.syslogSeverityFloor,
        perSourceRate: snmpConfig.syslogRateLimitPerSource,
        dailyQuota: snmpConfig.syslogDailyQuota,
      },
      'Syslog receiver listening (severity floor applied AT INGESTION)',
    );
  });

  flushTimer = setInterval(() => {
    void flush().catch((err) => logger.error({ err }, 'Syslog flush failed — messages lost'));
  }, snmpConfig.syslogFlushMs);
  flushTimer.unref();

  stateTimer = setInterval(() => {
    void persistIngestState().catch((err) =>
      logger.warn({ err }, 'Could not persist syslog ingest state'),
    );
  }, 30_000);
  stateTimer.unref();

  startSyslogTcpReceiver();
}

// ============================================================================
// TCP/514 — RFC 6587
// ============================================================================

/**
 * WHY TCP EXISTS HERE AT ALL, given that UDP already works.
 *
 * UDP drops silently, and the one message class attribution depends on is precisely the
 * one that cannot be resent: "user admin logged in from 10.0.0.5 via winbox".
 * A lost counter sample is a gap in a graph; a lost login line is a
 * configuration change attributed to nobody, and nothing downstream can tell
 * that apart from a change that genuinely had no author.
 *
 * ┌─ TCP MOVES THE FLOODING PROBLEM, IT DOES NOT REMOVE IT ──────────────────┐
 * │ The UDP path is bounded by a queue, a token bucket and a daily quota. TCP │
 * │ adds two failure modes those do not cover, and both are handled below:    │
 * │                                                                          │
 * │  - CONNECTIONS. An unbounded accept loop exhausts file descriptors and    │
 * │    takes the HTTP API down with it. Hard cap, and a refused connection is │
 * │    counted, not silently dropped.                                        │
 * │  - UNDELIMITED FRAMES. A sender that opens a socket and never sends a     │
 * │    newline grows one buffer for ever. That is the same unbounded-buffer   │
 * │    failure the queue bound refuses, arriving through a different door, so │
 * │    it gets the same answer: a hard byte cap, then the connection dies.    │
 * │                                                                          │
 * │ The severity floor, the per-source bucket and the daily quota are the     │
 * │ SAME code as UDP (`admitAndQueue`), on purpose. Two admission paths would │
 * │ mean one of them eventually forgets the floor, and the floor is the       │
 * │ single measure standing between this table and 1.04 GB/day.               │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Both RFC 6587 framings are accepted because both are in the field:
 *   octet-counting        `123 <PRI>1 2026-...`
 *   non-transparent       `<PRI>1 2026-...\n`
 */
function startSyslogTcpReceiver(): void {
  if (tcpServer || !logsConfig.syslogTcpEnabled) return;

  const server = net.createServer((conn) => {
    if (tcpSockets.size >= logsConfig.syslogTcpMaxConnections) {
      stats.tcpRefused += 1;
      conn.destroy();
      return;
    }
    tcpSockets.add(conn);
    stats.tcpOpen = tcpSockets.size;

    const sourceIp = conn.remoteAddress ?? '0.0.0.0';
    let buffer = Buffer.alloc(0);

    conn.setTimeout(logsConfig.syslogTcpIdleTimeoutMs);
    conn.on('timeout', () => conn.destroy());

    conn.on('data', (chunk) => {
      buffer = buffer.length === 0 ? chunk : Buffer.concat([buffer, chunk]);

      // Frames, until the buffer holds only a partial one.
      for (;;) {
        if (buffer.length === 0) break;

        // -- octet-counting: a decimal length, a space, then exactly N bytes --
        const space = buffer.indexOf(0x20);
        if (space > 0 && space <= 10 && /^\d+$/.test(buffer.subarray(0, space).toString('ascii'))) {
          const length = Number.parseInt(buffer.subarray(0, space).toString('ascii'), 10);
          if (length > logsConfig.syslogTcpMaxFrameBytes) {
            stats.tcpOversizedFrames += 1;
            conn.destroy();
            return;
          }
          if (buffer.length < space + 1 + length) break; // wait for the rest
          const frame = buffer.subarray(space + 1, space + 1 + length).toString('utf8');
          buffer = buffer.subarray(space + 1 + length);
          handleTcpFrame(frame, sourceIp, length);
          continue;
        }

        // -- non-transparent framing: LF-delimited ---------------------------
        const lf = buffer.indexOf(0x0a);
        if (lf < 0) {
          // No delimiter yet. THE BOUND IS HERE: without it a sender that never
          // sends a newline is an OOM with extra steps.
          if (buffer.length > logsConfig.syslogTcpMaxFrameBytes) {
            stats.tcpOversizedFrames += 1;
            conn.destroy();
            return;
          }
          break;
        }
        const line = buffer.subarray(0, lf).toString('utf8').replace(/\r$/, '');
        buffer = buffer.subarray(lf + 1);
        if (line.length > 0) handleTcpFrame(line, sourceIp, lf + 1);
      }
    });

    const close = (): void => {
      tcpSockets.delete(conn);
      stats.tcpOpen = tcpSockets.size;
    };
    conn.on('close', close);
    conn.on('error', (err) => {
      // A reset from a rebooting router is routine, not an incident.
      logger.debug({ err, sourceIp }, 'Syslog TCP connection error');
      close();
    });
  });

  server.on('error', (err) => {
    logger.error({ err, port: logsConfig.syslogTcpPort }, 'Syslog TCP listener error');
    try {
      server.close();
    } catch {
      /* already closing */
    }
    tcpServer = null;
  });

  server.listen(logsConfig.syslogTcpPort, logsConfig.syslogTcpBind, () => {
    logger.info(
      {
        port: logsConfig.syslogTcpPort,
        maxConnections: logsConfig.syslogTcpMaxConnections,
        maxFrameBytes: logsConfig.syslogTcpMaxFrameBytes,
      },
      'Syslog TCP receiver listening (RFC 6587, same severity floor as UDP)',
    );
  });
  tcpServer = server;
}

function handleTcpFrame(frame: string, sourceIp: string, bytes: number): void {
  if (!admitAndQueue(frame, sourceIp, bytes)) return;
  if (queue.length >= snmpConfig.syslogFlushBatch) {
    void flush().catch((err) => logger.error({ err }, 'Syslog flush failed — messages lost'));
  }
}

export function stopSyslogReceiver(): void {
  if (flushTimer) clearInterval(flushTimer);
  if (stateTimer) clearInterval(stateTimer);
  flushTimer = null;
  stateTimer = null;
  queue = [];
  sources.clear();
  quotas.clear();
  fleet.day = '';
  fleet.keptToday = 0;
  fleet.droppedToday = 0;
  fleet.warnedDay = '';
  deviceByHostname.clear();
  if (socket) {
    try {
      socket.close();
    } catch {
      /* already closed */
    }
  }
  socket = null;
  for (const conn of tcpSockets) conn.destroy();
  tcpSockets.clear();
  stats.tcpOpen = 0;
  if (tcpServer) {
    try {
      tcpServer.close();
    } catch {
      /* already closed */
    }
  }
  tcpServer = null;
}

/** Exposed for the bench: the whole ingestion path without a socket, floor and
 *  limiter included — testing a shortcut that skips them would prove nothing. */
export async function ingestSyslogLine(raw: string, sourceIp: string): Promise<boolean> {
  if (!admitAndQueue(raw, sourceIp, Buffer.byteLength(raw))) return false;
  await flush();
  return true;
}

/**
 * The same path, batched, for measuring sustained throughput.
 *
 * `ingestSyslogLine` flushes per message, which measures round-trip latency and
 * not the batched INSERT the receiver actually performs — benchmarking it would
 * report a number an order of magnitude below what the code does in production.
 * Returns how many messages were admitted (the rest hit the floor, the limiter
 * or the queue bound, and that difference is itself the measurement).
 */
export async function ingestSyslogBatch(lines: readonly string[], sourceIp: string): Promise<number> {
  let admitted = 0;
  for (const raw of lines) {
    if (admitAndQueue(raw, sourceIp, Buffer.byteLength(raw))) admitted += 1;
    if (queue.length >= snmpConfig.syslogFlushBatch) await flush();
  }
  await flush();
  return admitted;
}

export { flush as flushSyslog, persistIngestState };
