/**
 * ObliWAN — the unified journal.
 *
 * One reading surface over three stores that are deliberately NOT merged at
 * write time:
 *
 *   `syslog_messages`      pushed, lossy, partitioned by day, 7-day retention.
 *   `snmp_traps`           pushed, structured, partitioned by week, 90 days.
 *   `device_login_events`  PULLED off RouterOS `/log`, 90 days.
 *
 * ┌─ WHY NOT ONE TABLE ──────────────────────────────────────────────────────┐
 * │ Because the three have different retentions, different partition grains,  │
 * │ different volumes (syslog is ~100x the traps) and different reprocessing  │
 * │ stories — a trap must stay re-parseable against a better MIB mapping, and │
 * │ that means keeping its varbinds as it sent them. Merging them at write    │
 * │ time would force one retention on all three and would cost the syslog     │
 * │ table columns it has no use for, on the one table where a byte per row is │
 * │ a gigabyte a week. The union happens HERE, at read time, over a bounded   │
 * │ window.                                                                   │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE THIRD SOURCE IS NOT "ALL OF /log" ──────────────────────────────────┐
 * │ Only the ACCOUNT rows of `/log` are stored. Ingesting every RouterOS log  │
 * │ row we can pull would re-create, through the pull path, the exact volume  │
 * │ problem the severity floor was built to prevent on the push path — and it │
 * │ would do so while bypassing the floor entirely, because a pulled row      │
 * │ never passes through the receiver. What is filtered is never written,     │
 * │ whichever door it came through.                                           │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ TENANCY, AND WHY AN UNATTRIBUTED LINE IS NOT IN THIS FEED ──────────────┐
 * │ None of the three tables carries a tenant column. Each branch of the      │
 * │ union JOINS `devices`, which both scopes the read and — because the join  │
 * │ is inner — drops every row whose `device_id` is NULL.                     │
 * │                                                                          │
 * │ That is not an oversight. A log line we could not tie to a device cannot  │
 * │ be tied to a tenant either, so there is no tenant it could be shown to    │
 * │ without the possibility of showing customer A the logs of customer B.     │
 * │ Those lines are reachable through `unattributedSources()`, which returns  │
 * │ WHO IS TALKING and no message bodies, behind an admin-only capability.    │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

import { db } from '../../db';
import { currentTenantFilter, isGodView, withTenantNames } from '../../utils/globalView';
// Imported from the modules directly and NOT from `services/snmp/index.ts`: the
// barrel arms the whole SNMP runtime on import, and this file is reached from an
// HTTP handler.
import { snmpConfig } from '../snmp/config';
import { syslogStats, syslogGauges, syslogQuotaForDevice } from '../snmp/syslogReceiver';
import {
  syslogSeverityLabel,
  type DeviceLogSources,
  type LogQuery,
  type LogSource,
  type LogSourceStat,
  type SyslogIngestHealth,
  type UnattributedSource,
  type UnifiedLogEntry,
} from './contract';

/**
 * A trap carries no syslog severity — it is not a syslog message and SNMP has
 * no such field. Mapping it onto one is a PLATFORM CONVENTION so that a single
 * severity filter covers all three sources, and it is stated here rather than
 * hidden in a SQL literal: a trap reads as `warning`, because a device that
 * chose to send an unsolicited notification is saying something matters, and
 * nothing in the PDU tells us how much.
 */
export const TRAP_SEVERITY = 4;

/** Logins read as `notice`; a failed login reads as `warning`. Same kind of
 *  convention, same reason for stating it out loud. */
export const LOGIN_SEVERITY = 5;
export const LOGIN_FAILED_SEVERITY = 4;

/**
 * Default window. An unbounded query over the union would scan every partition
 * of `syslog_messages` (14 live days) and of `snmp_traps` (13 live weeks) —
 * which is the one query shape capable of hurting the ingestion path it shares
 * a database with. A caller may widen it explicitly; it is never unbounded by
 * accident.
 */
const DEFAULT_WINDOW_MS = 24 * 3_600_000;
const MAX_LIMIT = 500;

interface UnifiedRow {
  source: LogSource;
  received_at: Date;
  device_ts: Date | null;
  device_id: number;
  device_name: string | null;
  severity: number;
  facility: number | null;
  hostname: string | null;
  tag: string | null;
  message: string;
  source_ip: string | null;
  extra: unknown;
  tenant_id: number;
}

function toEntry(r: UnifiedRow): UnifiedLogEntry {
  return {
    source: r.source,
    receivedAt: r.received_at.toISOString(),
    deviceTs: r.device_ts ? r.device_ts.toISOString() : null,
    deviceId: r.device_id,
    deviceName: r.device_name,
    severity: r.severity,
    severityLabel: syslogSeverityLabel(r.severity),
    facility: r.facility,
    hostname: r.hostname,
    tag: r.tag,
    message: r.message,
    sourceIp: r.source_ip,
    extra: (r.extra as Record<string, unknown>) ?? {},
  };
}

/**
 * The union.
 *
 * Written as raw SQL rather than three knex builders stitched together, because
 * the casts are load-bearing: `inet` and `text`, `jsonb` and `json`, and a
 * `smallint` against an integer literal all have to line up column by column or
 * Postgres rejects the whole UNION. One readable statement beats three builders
 * and a runtime surprise.
 */
export async function listLogs(
  tenantId: number,
  query: LogQuery = {},
  /** Team scope (migration 084): only these devices' lines; null/absent = all. */
  scope: { deviceIds?: number[] | null } = {},
): Promise<UnifiedLogEntry[]> {
  const to = query.to ? new Date(query.to) : new Date();
  const from = query.from ? new Date(query.from) : new Date(to.getTime() - DEFAULT_WINDOW_MS);
  const limit = Math.min(query.limit ?? 100, MAX_LIMIT);
  const offset = query.offset ?? 0;
  const sources: LogSource[] = query.sources?.length
    ? query.sources
    : ['syslog', 'trap', 'routeros_log'];
  const maxSeverity = query.maxSeverity ?? 7;
  const search = query.search ? `%${query.search}%` : null;
  const deviceId = query.deviceId ?? null;
  // God view (a platform admin's GET on the master tenant): every tenant's
  // journal (or the operator's tenant filter), each line tagged with its
  // tenant. Anyone else: `d.tenant_id = tenantId`, as before. NULL drops the
  // predicate — only ever in the god view.
  const godView = isGodView(tenantId);
  const tenantBind: number | null = godView ? currentTenantFilter() : tenantId;

  const branches: string[] = [];
  const bindings: unknown[] = [];

  if (sources.includes('syslog')) {
    branches.push(`
      SELECT 'syslog'::text AS source, s.received_at, s.device_ts, s.device_id,
             d.name AS device_name, s.severity::int AS severity, s.facility::int AS facility,
             s.hostname, s.app_name AS tag, s.msg AS message,
             host(s.source_ip) AS source_ip, s.structured_data AS extra, d.tenant_id AS tenant_id
        FROM syslog_messages s
        JOIN devices d ON d.id = s.device_id AND (?::int IS NULL OR d.tenant_id = ?::int)
       WHERE s.received_at >= ? AND s.received_at <= ?
         AND s.severity <= ?
         AND (?::int IS NULL OR s.device_id = ?::int)
         AND (?::text IS NULL OR s.msg ILIKE ?::text)`);
    bindings.push(tenantBind, tenantBind, from, to, maxSeverity, deviceId, deviceId, search, search);
  }

  if (sources.includes('trap')) {
    branches.push(`
      SELECT 'trap'::text AS source, t.ts AS received_at, NULL::timestamptz AS device_ts,
             t.device_id, d.name AS device_name, ${TRAP_SEVERITY}::int AS severity,
             NULL::int AS facility, NULL::text AS hostname, t.trap_oid AS tag,
             t.trap_oid AS message, host(t.source_ip) AS source_ip, t.varbinds AS extra, d.tenant_id AS tenant_id
        FROM snmp_traps t
        JOIN devices d ON d.id = t.device_id AND (?::int IS NULL OR d.tenant_id = ?::int)
       WHERE t.ts >= ? AND t.ts <= ?
         AND ${TRAP_SEVERITY} <= ?
         AND (?::int IS NULL OR t.device_id = ?::int)
         AND (?::text IS NULL OR t.trap_oid ILIKE ?::text)`);
    bindings.push(tenantBind, tenantBind, from, to, maxSeverity, deviceId, deviceId, search, search);
  }

  if (sources.includes('routeros_log')) {
    branches.push(`
      SELECT 'routeros_log'::text AS source, e.ts AS received_at, e.device_ts, e.device_id,
             d.name AS device_name,
             CASE WHEN e.event = 'login_failed' THEN ${LOGIN_FAILED_SEVERITY}
                  ELSE ${LOGIN_SEVERITY} END::int AS severity,
             NULL::int AS facility, NULL::text AS hostname, 'account'::text AS tag,
             e.message, host(e.source_ip) AS source_ip,
             jsonb_build_object('account', e.account, 'event', e.event,
                                'method', e.method, 'sharedAccount', e.shared_account) AS extra,
             d.tenant_id AS tenant_id
        FROM device_login_events e
        JOIN devices d ON d.id = e.device_id AND (?::int IS NULL OR d.tenant_id = ?::int)
       WHERE e.origin = 'routeros_log'
         AND e.ts >= ? AND e.ts <= ?
         AND (CASE WHEN e.event = 'login_failed' THEN ${LOGIN_FAILED_SEVERITY}
                   ELSE ${LOGIN_SEVERITY} END) <= ?
         AND (?::int IS NULL OR e.device_id = ?::int)
         AND (?::text IS NULL OR e.message ILIKE ?::text)`);
    bindings.push(tenantBind, tenantBind, from, to, maxSeverity, deviceId, deviceId, search, search);
  }

  if (branches.length === 0) return [];

  const sql = `SELECT * FROM (${branches.join('\n UNION ALL \n')}) u
                WHERE (?::int[] IS NULL OR u.device_id = ANY(?::int[]))
                ORDER BY u.received_at DESC LIMIT ? OFFSET ?`;
  // Team scope (084) as a PG array LITERAL, not a JS array: knex expands an
  // array binding into a placeholder list, which `?::int[]` cannot take.
  const scopeIds = Array.isArray(scope.deviceIds)
    ? `{${scope.deviceIds.filter((n) => Number.isSafeInteger(n)).join(',')}}`
    : null;
  bindings.push(scopeIds, scopeIds, limit, offset);

  const result = await db.raw(sql, bindings as never[]);
  const rows = (result.rows ?? []) as UnifiedRow[];
  const entries = rows.map((r) => (godView ? { ...toEntry(r), tenantId: Number(r.tenant_id) } : toEntry(r)));
  return withTenantNames(entries, 'tenantId', godView);
}

/**
 * Who is sending us logs we cannot place.
 *
 * NO MESSAGE BODIES, and that restriction is the whole design of this function.
 * An unattributed line belongs to no tenant, so its text cannot be shown inside
 * a tenant-scoped API without the risk of handing customer A customer B's
 * firewall logs. What an operator needs in order to FIX the gap is the address
 * that is talking and the name it claims to be — that identifies the missing
 * inventory row, and nothing more.
 *
 * The hostname is also the reminder of the bridge NAT: it is the ONLY thing we attribute
 * on. `source_ip` is here to help a human find the box on the network, never to
 * be matched against `devices` — behind the Docker bridge it is the gateway for
 * every sender at once.
 */
export async function unattributedSources(hours = 24): Promise<UnattributedSource[]> {
  const since = new Date(Date.now() - hours * 3_600_000);
  const result = await db.raw(
    `SELECT host(source_ip) AS source_ip, hostname, count(*)::bigint AS count,
            min(received_at) AS first_seen, max(received_at) AS last_seen
       FROM syslog_messages
      WHERE device_id IS NULL AND received_at >= ?
      GROUP BY host(source_ip), hostname
      ORDER BY count(*) DESC
      LIMIT 200`,
    [since] as never[],
  );
  return ((result.rows ?? []) as Array<{
    source_ip: string;
    hostname: string | null;
    count: string;
    first_seen: Date;
    last_seen: Date;
  }>).map((r) => ({
    sourceIp: r.source_ip,
    hostname: r.hostname,
    count: Number(r.count),
    firstSeen: r.first_seen.toISOString(),
    lastSeen: r.last_seen.toISOString(),
  }));
}

/**
 * Ingestion health.
 *
 * `queueDepth / queueMax` is the number that matters: it is the only early
 * warning that ingestion is losing the race with the disk, and by the time
 * `queueDropped` starts climbing the messages are already gone. The counters
 * are per-process and reset on restart — deliberately not persisted, because a
 * counter that survives a restart cannot be used to spot one.
 */
export function ingestHealth(): SyslogIngestHealth & {
  severityFloor: number;
  perSourceRate: number;
  dailyQuota: number;
  fleetDailyQuota: number;
  fleetQuotaSuppressed: number;
} {
  const stats = syslogStats();
  const gauges = syslogGauges();
  return {
    received: stats.received,
    accepted: stats.accepted,
    belowFloor: stats.belowFloor,
    belowFloorKeptAccount: stats.belowFloorKeptAccount,
    malformed: stats.malformed,
    rateLimited: stats.rateLimited,
    quotaSuppressed: stats.quotaSuppressed,
    queueDropped: stats.queueDropped,
    stored: stats.stored,
    queueDepth: gauges.queueDepth,
    queueMax: gauges.queueMax,
    suppressedSources: gauges.suppressedSources,
    severityFloor: snmpConfig.syslogSeverityFloor,
    perSourceRate: snmpConfig.syslogRateLimitPerSource,
    /** Per ROUTER since 2026-10-07 (it was per source address = the fleet). */
    dailyQuota: snmpConfig.syslogDailyQuota,
    fleetDailyQuota: snmpConfig.syslogFleetDailyQuota,
    fleetQuotaSuppressed: stats.fleetQuotaSuppressed,
  };
}

// ============================================================================
// Is each source still arriving?
// ============================================================================

const DAY_MS = 24 * 3_600_000;

interface SourceCountRow {
  syslog_count: string | number;
  syslog_last: Date | null;
  trap_count: string | number;
  trap_last: Date | null;
  rlog_count: string | number;
  rlog_last: Date | null;
  rlog_read: Date | null;
}

function isoOf(d: Date | string | null | undefined): string | null {
  return d ? new Date(d).toISOString() : null;
}

function toStats(r: SourceCountRow | undefined): LogSourceStat[] {
  return [
    { source: 'syslog', count: Number(r?.syslog_count ?? 0), lastSeenAt: isoOf(r?.syslog_last) },
    { source: 'trap', count: Number(r?.trap_count ?? 0), lastSeenAt: isoOf(r?.trap_last) },
    {
      source: 'routeros_log',
      count: Number(r?.rlog_count ?? 0),
      lastSeenAt: isoOf(r?.rlog_last),
      lastReadAt: isoOf(r?.rlog_read),
    },
  ];
}

/**
 * Per source: lines stored in the last 24 hours and the newest one — the
 * counters whose job is to show an ingest that STOPPED (GET /logs/sources).
 * `routeros_log` also carries the newest successful `/log` read, because only
 * account lines are stored from it: a quiet box is not a silent pull.
 *
 * Scoped like the journal: through `devices` (tenant, team scope, one
 * device). The god view WITHOUT a tenant filter reads the tables whole,
 * unattributed lines included — that is the receiver's own liveness, the one
 * number that tells "the fleet went silent" from "these routers did".
 *
 * Every newest-line read rides an index: (device_id, ts DESC) per device, and
 * (severity, received_at DESC) per severity for the fleet-wide syslog one.
 */
export async function logSourceCounts(
  tenantId: number,
  opts: { deviceId?: number | null; deviceIds?: number[] | null } = {},
): Promise<LogSourceStat[]> {
  const since = new Date(Date.now() - DAY_MS);
  const godView = isGodView(tenantId);
  const tenantBind: number | null = godView ? currentTenantFilter() : tenantId;
  const deviceId = opts.deviceId ?? null;
  // A PG array LITERAL, as in listLogs (knex would expand a JS array).
  const scopeIds = Array.isArray(opts.deviceIds)
    ? `{${opts.deviceIds.filter((v) => Number.isSafeInteger(v)).join(',')}}`
    : null;

  if (godView && tenantBind === null && deviceId === null && scopeIds === null) {
    const result = await db.raw(
      `SELECT
         (SELECT count(*) FROM syslog_messages WHERE received_at >= ?) AS syslog_count,
         (SELECT max(x.m) FROM generate_series(0, 7) AS g(sev)
            CROSS JOIN LATERAL (SELECT s.received_at AS m FROM syslog_messages s
                                 WHERE s.severity = g.sev ORDER BY s.received_at DESC LIMIT 1) x) AS syslog_last,
         (SELECT count(*) FROM snmp_traps WHERE ts >= ?) AS trap_count,
         (SELECT max(ts) FROM snmp_traps) AS trap_last,
         (SELECT count(*) FROM device_login_events WHERE origin = 'routeros_log' AND ts >= ?) AS rlog_count,
         (SELECT max(ts) FROM device_login_events WHERE origin = 'routeros_log') AS rlog_last,
         (SELECT max(last_ok_at) FROM routeros_log_cursors) AS rlog_read`,
      [since, since, since] as never[],
    );
    return toStats((result.rows ?? [])[0] as SourceCountRow | undefined);
  }

  const result = await db.raw(
    `WITH d AS (
       SELECT dv.id FROM devices dv
        WHERE (?::int IS NULL OR dv.tenant_id = ?::int)
          AND (?::int IS NULL OR dv.id = ?::int)
          AND (?::int[] IS NULL OR dv.id = ANY(?::int[]))
     )
     SELECT
       (SELECT count(*) FROM syslog_messages s
         WHERE s.device_id IN (SELECT id FROM d) AND s.received_at >= ?) AS syslog_count,
       (SELECT max(x.m) FROM d CROSS JOIN LATERAL (SELECT s.received_at AS m FROM syslog_messages s
                                 WHERE s.device_id = d.id ORDER BY s.received_at DESC LIMIT 1) x) AS syslog_last,
       (SELECT count(*) FROM snmp_traps t
         WHERE t.device_id IN (SELECT id FROM d) AND t.ts >= ?) AS trap_count,
       (SELECT max(x.m) FROM d CROSS JOIN LATERAL (SELECT t.ts AS m FROM snmp_traps t
                                 WHERE t.device_id = d.id ORDER BY t.ts DESC LIMIT 1) x) AS trap_last,
       (SELECT count(*) FROM device_login_events e
         WHERE e.origin = 'routeros_log' AND e.device_id IN (SELECT id FROM d) AND e.ts >= ?) AS rlog_count,
       (SELECT max(e.ts) FROM device_login_events e
         WHERE e.origin = 'routeros_log' AND e.device_id IN (SELECT id FROM d)) AS rlog_last,
       (SELECT max(c.last_ok_at) FROM routeros_log_cursors c
         WHERE c.device_id IN (SELECT id FROM d)) AS rlog_read`,
    [tenantBind, tenantBind, deviceId, deviceId, scopeIds, scopeIds, since, since, since] as never[],
  );
  return toStats((result.rows ?? [])[0] as SourceCountRow | undefined);
}

/**
 * One router: its three sources, its syslog quota today and its `/log` pull.
 * The caller has already resolved the device in its tenant (404 otherwise)
 * and through its team scope.
 */
export async function deviceLogSources(tenantId: number, deviceId: number): Promise<DeviceLogSources> {
  const [sourcesNow, device, cursor] = await Promise.all([
    logSourceCounts(tenantId, { deviceId }),
    db('devices').where({ id: deviceId }).first<{ system_identity: string | null } | undefined>('system_identity'),
    db('routeros_log_cursors').where({ device_id: deviceId }).first<{
      last_poll_at: Date | null;
      last_ok_at: Date | null;
      consecutive_failures: number;
      last_error: string | null;
    } | undefined>('last_poll_at', 'last_ok_at', 'consecutive_failures', 'last_error'),
  ]);
  return {
    deviceId,
    sources: sourcesNow,
    syslogQuota: syslogQuotaForDevice(deviceId, device?.system_identity ?? null),
    logPull: cursor
      ? {
          lastPollAt: isoOf(cursor.last_poll_at),
          lastOkAt: isoOf(cursor.last_ok_at),
          consecutiveFailures: Number(cursor.consecutive_failures ?? 0),
          lastError: cursor.last_error,
        }
      : null,
  };
}
