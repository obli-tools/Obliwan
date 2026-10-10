import apiClient from './client';
import type {
  ApiResponse,
  DeviceLogSources,
  SyslogIngestHealth,
  SyslogQuotaState,
  UnattributedSource,
} from '@obliwan/shared';
import { isRouteAbsent } from './change.api';
import type {
  AttributionCandidate,
  AttributionState,
  AttributionView,
  LogEntryView,
  LogQueryParams,
  LogSeverity,
  LogSource,
  LogSourceCount,
} from '@/types/logs';
import { ATTRIBUTION_UNAVAILABLE, LOG_SEVERITIES, LOG_SOURCES } from '@/types/logs';

/**
 * The unified log and the attribution verdict.
 *
 * ── THE ROUTES — READ OFF `server/src/routes/logs.routes.ts` ────────────────
 * Every one degrades to a stated absence rather than to a blank screen:
 *
 *   GET /api/logs?source&maxSeverity&deviceId&search&from&to&limit -> LogEntryView[]
 *   GET /api/logs/sources                        -> LogSourceCount[]
 *   GET /api/logs/devices/:id/sources            -> DeviceLogSources
 *   GET /api/logs/health                         -> ingest counters (+ quota, platform admin)
 *   GET /api/logs/unattributed                   -> UnattributedSource[] (platform admin)
 *   GET /api/logs/attributions/runs/:runId       -> DriftAttribution (run-level)
 *
 * The page's filter names (`severity`, `q`, `since`, `until`) are mapped
 * onto the server's (`maxSeverity`, `search`, `from`, `to`) in `list()`,
 * once: the server used to ignore all four, silently.
 *
 * Attribution used to be called under `/drift/runs/:id/attribution` and
 * `/drift/findings/:id/attribution`, neither of which the server serves. The
 * server keeps ONE verdict per drift run, behind DRIFT_READ, under
 * `/logs/attributions`; there is no per-finding verdict at all, so
 * `ofFinding()` answers "not available" without a request (see there).
 *
 * ── `unattributed` IS NEVER MANUFACTURED HERE ───────────────────────────────
 * When the endpoint is absent, this module returns `ATTRIBUTION_UNAVAILABLE`,
 * whose `available: false` makes the banner say "attribution is not served by
 * this build". It does NOT say "unattributed". A missing service and a search
 * that found nobody are different facts, and only the second one is about the
 * change the operator is looking at.
 *
 * ── AND A NAME IS NEVER PROMOTED ────────────────────────────────────────────
 * `identity` is set only for the `attributed` state. For `ambiguous` it stays
 * null even when the payload names a "best" candidate, because a window with
 * several plausible sessions has no winner — picking the highest score would
 * put a person's name on a change they may not have made.
 */

type Raw = Record<string, unknown>;

function pick(row: Raw, camel: string): unknown {
  if (camel in row) return row[camel];
  const snake = camel.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);
  return row[snake];
}

function n(v: unknown, fallback: number): number {
  if (v === null || v === undefined || v === '') return fallback;
  const x = typeof v === 'number' ? v : Number(v);
  return Number.isFinite(x) ? x : fallback;
}

function nOrNull(v: unknown): number | null {
  if (v === null || v === undefined || v === '') return null;
  const x = typeof v === 'number' ? v : Number(v);
  return Number.isFinite(x) ? x : null;
}

function s(v: unknown): string | null {
  return v === null || v === undefined || v === '' ? null : String(v);
}

function bool(v: unknown): boolean {
  if (typeof v === 'boolean') return v;
  return v === 'true' || v === 't' || v === 1 || v === '1';
}

function asRows(payload: unknown): Raw[] {
  if (Array.isArray(payload)) return payload as Raw[];
  if (payload && typeof payload === 'object') {
    const p = payload as Raw;
    const items = p.items ?? p.rows ?? p.entries ?? p.logs ?? p.sources;
    if (Array.isArray(items)) return items as Raw[];
  }
  return [];
}

// ── Normalisers ─────────────────────────────────────────────────────────────

const SOURCES: readonly string[] = LOG_SOURCES;
const SEVERITIES: readonly string[] = LOG_SEVERITIES;

/**
 * An unrecognised source is `syslog`, the LEAST trusted of the three.
 *
 * The asymmetry matters: `routeros_log` lines are read by us over an
 * authenticated channel from a device we identified, and are therefore the only
 * ones whose origin we can vouch for. Folding an unknown source to
 * `routeros_log` would upgrade the trustworthiness of a line nobody can place.
 */
function sourceOf(v: unknown): LogSource {
  const str = String(v ?? '').toLowerCase();
  return (SOURCES.includes(str) ? str : 'syslog') as LogSource;
}

/**
 * An unrecognised severity is `warning`, not `info` and not `emerg`.
 *
 * `info` would hide the line behind the default filter; `emerg` would make one
 * malformed parser flood the top of an incident screen. `warning` keeps it
 * visible without letting it shout over lines that really are critical.
 */
function severityOf(v: unknown): LogSeverity {
  const str = String(v ?? '').toLowerCase();
  if (SEVERITIES.includes(str)) return str as LogSeverity;
  // Numeric RFC 5424 severities are accepted too — traps and raw syslog carry
  // the number, not the word.
  const num = Number(v);
  if (Number.isInteger(num) && num >= 0 && num <= 7) return LOG_SEVERITIES[num];
  return 'warning';
}

export function normalizeLogEntry(raw: Raw, index: number): LogEntryView {
  // The server sends the device's own clock as `deviceTs` (null when the box
  // sent none) beside `receivedAt`, ours.
  const timestamp = s(pick(raw, 'timestamp') ?? pick(raw, 'deviceTs') ?? pick(raw, 'ts') ?? pick(raw, 'loggedAt'));
  return {
    // A line with no id still has to be renderable and keyed: an ingest that
    // forgets an id must not collapse a hundred rows into one.
    id: String(pick(raw, 'id') ?? `${timestamp ?? 'na'}#${index}`),
    // God view only: present when the server tagged the line with its workspace.
    ...(pick(raw, 'tenantName') !== undefined
      ? { tenantId: nOrNull(pick(raw, 'tenantId')) ?? undefined, tenantName: s(pick(raw, 'tenantName')) }
      : {}),
    timestamp: timestamp ?? '',
    receivedAt: s(pick(raw, 'receivedAt')),
    source: sourceOf(pick(raw, 'source')),
    severity: severityOf(pick(raw, 'severity')),
    deviceId: nOrNull(pick(raw, 'deviceId')),
    deviceName: s(pick(raw, 'deviceName')),
    siteName: s(pick(raw, 'siteName')),
    facility: s(pick(raw, 'facility') ?? pick(raw, 'topic') ?? pick(raw, 'oid')),
    message: String(pick(raw, 'message') ?? pick(raw, 'text') ?? ''),
    sourceIp: s(pick(raw, 'sourceIp') ?? pick(raw, 'sourceAddress')),
    username: s(pick(raw, 'username') ?? pick(raw, 'user')),
  };
}

export function normalizeSourceCount(raw: Raw): LogSourceCount {
  return {
    source: sourceOf(pick(raw, 'source')),
    count: n(pick(raw, 'count'), 0),
    lastSeenAt: s(pick(raw, 'lastSeenAt') ?? pick(raw, 'lastAt')),
    lastReadAt: s(pick(raw, 'lastReadAt')),
  };
}

/** The page's filter → the server's query (logs.controller.ts `logsQuery`). */
function serverQuery(params: LogQueryParams): Record<string, unknown> {
  const rank = params.severity ? SEVERITIES.indexOf(params.severity) : -1;
  return clean({
    source: params.source,
    // "warning" means warning AND WORSE: the server's inclusive upper bound.
    maxSeverity: rank >= 0 ? rank : undefined,
    deviceId: params.deviceId,
    search: params.q,
    from: params.since,
    to: params.until,
    limit: params.limit,
  });
}

function candidate(raw: unknown): AttributionCandidate | null {
  if (!raw || typeof raw !== 'object') return null;
  const row = raw as Raw;
  const username = s(pick(row, 'username') ?? pick(row, 'user'));
  if (!username) return null;
  const score = Number(pick(row, 'score'));
  return {
    eventId: nOrNull(pick(row, 'eventId') ?? pick(row, 'id')),
    username,
    sharedAccount: bool(pick(row, 'sharedAccount') ?? pick(row, 'shared')),
    sourceIp: s(pick(row, 'sourceIp') ?? pick(row, 'sourceAddress')),
    via: s(pick(row, 'via') ?? pick(row, 'transport')),
    loggedInAt: s(pick(row, 'loggedInAt') ?? pick(row, 'startedAt')),
    loggedOutAt: s(pick(row, 'loggedOutAt') ?? pick(row, 'endedAt')),
    // An unreadable score is 0, never 1: it must not sort itself to the top of
    // a candidate list it has no claim to.
    score: Number.isFinite(score) ? Math.min(1, Math.max(0, score)) : 0,
  };
}

const STATES: readonly string[] = ['attributed', 'shared', 'ambiguous', 'unattributed'];

export function normalizeAttribution(raw: unknown): AttributionView {
  if (!raw || typeof raw !== 'object') return { ...ATTRIBUTION_UNAVAILABLE, available: true };
  const row = raw as Raw;
  const candidates = (Array.isArray(pick(row, 'candidates')) ? (pick(row, 'candidates') as unknown[]) : [])
    .map(candidate)
    .filter((c): c is AttributionCandidate => c !== null)
    .sort((a, b) => b.score - a.score);

  const declared = String(pick(row, 'state') ?? '').toLowerCase();
  const winner = candidate(pick(row, 'identity') ?? pick(row, 'attributedTo'));

  // The state is DERIVED as well as read, and the pessimistic reading wins.
  // A payload that says `attributed` while naming a shared account is reported
  // as `shared`; a payload that says `attributed` with no identity at all is
  // reported as `unattributed`. Neither is a hypothetical: the server folds one
  // flag, the client folds the other, and only the conjunction is safe.
  let state: AttributionState = (STATES.includes(declared) ? declared : 'unattributed') as AttributionState;
  if (state === 'attributed' && !winner) state = 'unattributed';
  if (state === 'attributed' && winner?.sharedAccount) state = 'shared';

  return {
    state,
    // `ambiguous` keeps a null identity ON PURPOSE — see the header comment.
    identity: state === 'attributed' || state === 'shared' ? winner : null,
    candidates,
    windowStart: s(pick(row, 'windowStart')),
    windowEnd: s(pick(row, 'windowEnd')),
    rationale: s(pick(row, 'rationale') ?? pick(row, 'summary')),
    available: true,
  };
}

// ── The client ──────────────────────────────────────────────────────────────

function clean(params: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') out[k] = v;
  }
  return out;
}

export const logsApi = {
  /** `null` = the log API is not served by this build. */
  async list(params: LogQueryParams = {}): Promise<LogEntryView[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>('/logs', {
        params: serverQuery(params),
      });
      return asRows(res.data.data).map(normalizeLogEntry);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /** Per-source counters. Their real job is to show an ingest that STOPPED:
   *  a syslog receiver that died is invisible in a log list — the list simply
   *  has fewer lines — and very visible in a "last seen 4 h ago" cell. */
  async sources(): Promise<LogSourceCount[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>('/logs/sources');
      return asRows(res.data.data).map(normalizeSourceCount);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /** One router: its sources, its syslog quota today, its `/log` pull. */
  async deviceSources(deviceId: number): Promise<(Omit<DeviceLogSources, 'sources'> & { sources: LogSourceCount[] }) | null> {
    try {
      const res = await apiClient.get<ApiResponse<DeviceLogSources>>(`/logs/devices/${deviceId}/sources`);
      const d = res.data.data;
      if (!d) return null;
      return { ...d, sources: asRows(d.sources).map(normalizeSourceCount) };
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /** Ingestion counters; `quota` is present for a platform administrator only. */
  async health(): Promise<(SyslogIngestHealth & {
    severityFloor?: number;
    perSourceRate?: number;
    dailyQuota?: number;
    fleetDailyQuota?: number;
    fleetQuotaSuppressed?: number;
    quota?: SyslogQuotaState;
  }) | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>('/logs/health');
      return (res.data.data as never) ?? null;
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /** Senders nobody can place (platform administrators only, no message body). */
  async unattributed(hours = 24): Promise<UnattributedSource[]> {
    const res = await apiClient.get<ApiResponse<unknown>>('/logs/unattributed', { params: { hours } });
    return Array.isArray(res.data.data) ? (res.data.data as UnattributedSource[]) : [];
  },
};

/**
 * The server's `DriftAttribution` (shared/logs.ts) → the raw shape
 * `normalizeAttribution()` reads, so the pessimistic derivation there (an
 * `attributed` on a shared account becomes `shared`, an `attributed` with no
 * identity becomes `unattributed`) still has the last word.
 *
 * The server has FIVE verdicts and this screen four. The two extra ones are
 * both "ObliWAN did it, not a person" — `platform` (a `change_jobs` row
 * overlaps the window) and `excluded` (the diff is ours: normalisation rules
 * or model version changed). Neither may become `unattributed`, which would
 * tell the operator a change arrived through a path nobody observes. They are
 * rendered as attributed to a NON-PERSON identity that says so, with the
 * server's reason code as the rationale.
 */
function fromDriftAttribution(raw: unknown): Raw | null {
  if (!raw || typeof raw !== 'object') return null;
  const row = raw as Raw;
  const verdict = String(pick(row, 'verdict') ?? '').toLowerCase();
  const window = (pick(row, 'window') ?? {}) as Raw;
  const candidates = (Array.isArray(pick(row, 'candidates')) ? (pick(row, 'candidates') as Raw[]) : [])
    .map((c) => ({
      eventId: pick(c, 'loginEventId'),
      username: pick(c, 'account'),
      sharedAccount: pick(c, 'sharedAccount'),
      sourceIp: pick(c, 'sourceIp'),
      via: pick(c, 'method'),
      loggedInAt: pick(c, 'loginAt'),
      loggedOutAt: pick(c, 'logoutAt'),
      score: pick(c, 'score'),
    }));
  const changeJobId = s(pick(row, 'changeJobId'));
  const ours = verdict === 'platform' || verdict === 'excluded';
  const identity = ours
    ? {
        username: verdict === 'platform' && changeJobId
          ? `ObliWAN (change job #${changeJobId})`
          : 'ObliWAN (normalisation / model change)',
        sharedAccount: false,
        sourceIp: null,
        via: 'platform',
        score: 1,
      }
    : verdict === 'attributed'
      ? {
          eventId: pick(row, 'loginEventId'),
          username: pick(row, 'account'),
          sharedAccount: pick(row, 'sharedAccount'),
          sourceIp: pick(row, 'sourceIp'),
          via: pick(row, 'method'),
          score: pick(row, 'score'),
        }
      : null;
  return {
    state: ours ? 'attributed' : verdict,
    identity,
    candidates,
    windowStart: pick(window, 'from'),
    windowEnd: pick(window, 'to'),
    rationale: pick(row, 'reason'),
  };
}

export const attributionApi = {
  /**
   * NO SERVER EQUIVALENT. Attribution is computed and stored per drift RUN
   * (`drift_attributions.run_id`); the server has no per-finding verdict, and
   * the page refuses on purpose to answer the finding question with the run
   * one. So this answers `ATTRIBUTION_UNAVAILABLE` without a request — "we did
   * not look", never "nobody was found".
   */
  async ofFinding(_findingId: number): Promise<AttributionView> {
    return ATTRIBUTION_UNAVAILABLE;
  },

  /**
   * `GET /logs/attributions/runs/:runId`. NEVER throws. A 404 there means no
   * attribution row exists for the run yet (the sweep has not reached it, or
   * the run reports no drift): that is "not looked at", so it is UNAVAILABLE
   * and never `unattributed`.
   */
  async ofRun(runId: number): Promise<AttributionView> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>(`/logs/attributions/runs/${runId}`);
      const raw = fromDriftAttribution(res.data.data);
      return raw ? normalizeAttribution(raw) : ATTRIBUTION_UNAVAILABLE;
    } catch {
      return ATTRIBUTION_UNAVAILABLE;
    }
  },
};
