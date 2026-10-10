import apiClient from './client';
import type { ApiResponse } from '@obliwan/shared';
import { isRouteAbsent } from './change.api';
import type {
  PolicySeverity,
  QueryColumn,
  QueryError,
  QueryMatch,
  QueryResult,
  QueryRow,
  SaveQueryRequest,
  SavedQuery,
} from '@/types/query';

/**
 * Fleet Query.
 *
 * ── THE ROUTES — READ OFF `server/src/routes/query.routes.ts` ───────────────
 * Every one degrades to a stated absence rather than to a blank screen:
 *
 *   POST   /api/query/run                 -> { dsl, limit } -> QueryResult
 *   POST   /api/query/explain             -> { dsl } -> 200 { plan, usesGin } | 400 parse error
 *   GET    /api/query/saved               -> SavedQuery[]
 *   POST   /api/query/saved               -> SaveQueryRequest -> SavedQuery
 *   DELETE /api/query/saved/:id
 *   POST   /api/query/saved/:id/promote   -> { severity } -> SavedQuery
 *   POST   /api/query/saved/:id/demote    -> SavedQuery
 *
 * There is no `/query/validate` and no `/saved/:id/policy` (both used to be
 * called here, and 404'd). `validate()` goes through `/explain`, which parses
 * and compiles exactly as `/run` does and answers the same 400 with an
 * `offset` on a refused expression — but it is `EXPLAIN (ANALYZE)`, so a VALID
 * query is executed once, read-only, to plan it. One more reason it stays an
 * on-demand button and never a per-keystroke check.
 *
 * The policy flag is two routes, and the severity vocabularies differ: the
 * server stores a `DIFF_SEVERITIES` value (info | low | medium | high |
 * critical), this screen speaks `info | warning | critical`. `warning` is sent
 * as `medium`; low, medium and high all read back as `warning`.
 *
 * `POST` and not `GET` for `run`: a DSL expression in a query string gets
 * truncated by proxies, logged by every hop, and URL-encoded past legibility.
 *
 * ── A TRUNCATED ANSWER IS NEVER PRESENTED AS A COMPLETE ONE ─────────────────
 * `truncated` defaults to TRUE when the payload does not say. An audit tool
 * that silently drops rows certifies boxes nobody looked at, and "we may have
 * missed some" is a cheap sentence next to that.
 *
 * ── The secrets rule ────────────────────────────────────────────────────────
 * `QueryMatch.value` is a redacted NCM resource. This module hands it through
 * untouched — no unmasking, no re-parsing — and the renderer scans it. The NCM
 * stores `SecretFingerprint` objects rather than values, so the only door left
 * open is `extensions`, which is exactly why the scan exists.
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

function asRows(payload: unknown): Raw[] {
  if (Array.isArray(payload)) return payload as Raw[];
  if (payload && typeof payload === 'object') {
    const p = payload as Raw;
    const items = p.items ?? p.rows ?? p.results ?? p.queries ?? p.saved;
    if (Array.isArray(items)) return items as Raw[];
  }
  return [];
}

// ── Normalisers ─────────────────────────────────────────────────────────────

/** This screen's policy severity → the server's `DIFF_SEVERITIES`. */
function serverSeverityOf(sev: PolicySeverity): 'info' | 'medium' | 'critical' {
  return sev === 'warning' ? 'medium' : sev;
}

/** The server's `DIFF_SEVERITIES` → this screen's three. An unknown non-empty
 *  value reads as `warning`, not `info`: a policy whose weight this client
 *  cannot name must not be drawn as the harmless one. */
function clientSeverityOf(v: unknown): PolicySeverity {
  const raw = String(v ?? '').toLowerCase();
  if (raw === 'info' || raw === '' || raw === 'null') return 'info';
  if (raw === 'critical') return 'critical';
  return 'warning';
}

function columnOf(raw: unknown): QueryColumn | null {
  if (!raw || typeof raw !== 'object') return null;
  const row = raw as Raw;
  const key = s(pick(row, 'key') ?? pick(row, 'path'));
  if (!key) return null;
  const type = String(pick(row, 'type') ?? 'string');
  return {
    key,
    path: s(pick(row, 'path')) ?? key,
    type: (['string', 'number', 'boolean', 'array', 'object'].includes(type)
      ? type
      : 'string') as QueryColumn['type'],
  };
}

function matchOf(raw: unknown): QueryMatch | null {
  if (!raw || typeof raw !== 'object') return null;
  const row = raw as Raw;
  return {
    resource: String(pick(row, 'resource') ?? ''),
    semKey: String(pick(row, 'semKey') ?? ''),
    value: pick(row, 'value') ?? row,
  };
}

export function normalizeQueryRow(raw: Raw): QueryRow {
  const cells = pick(raw, 'cells');
  return {
    deviceId: n(pick(raw, 'deviceId'), 0),
    // The server's row says name / site (savedQuery.service toRow).
    deviceName: s(pick(raw, 'deviceName') ?? pick(raw, 'name')),
    siteId: nOrNull(pick(raw, 'siteId')),
    siteName: s(pick(raw, 'siteName') ?? pick(raw, 'site')),
    brand: String(pick(raw, 'brand') ?? ''),
    model: s(pick(raw, 'model')),
    osVersion: s(pick(raw, 'osVersion')),
    cells: cells && typeof cells === 'object' ? (cells as Record<string, unknown>) : {},
    matches: (Array.isArray(pick(raw, 'matches')) ? (pick(raw, 'matches') as unknown[]) : [])
      .map(matchOf)
      .filter((m): m is QueryMatch => m !== null),
    snapshotId: s(pick(raw, 'snapshotId')),
    snapshotAt: s(pick(raw, 'snapshotAt') ?? pick(raw, 'capturedAt')),
  };
}

export function normalizeQueryResult(payload: unknown): QueryResult {
  const row = (payload ?? {}) as Raw;
  const columns = (Array.isArray(pick(row, 'columns')) ? (pick(row, 'columns') as unknown[]) : [])
    .map(columnOf)
    .filter((c): c is QueryColumn => c !== null);
  const rows = asRows(pick(row, 'rows') ?? payload).map(normalizeQueryRow);
  const truncated = pick(row, 'truncated');
  return {
    columns,
    rows,
    // `devicesExamined` falling back to the row count would turn "12 of 300"
    // into "12 of 12", which reads as a fleet-wide clean bill of health.
    // 0 is visibly wrong instead, and the page prints "unknown".
    devicesExamined: n(pick(row, 'devicesExamined') ?? pick(row, 'devices'), 0),
    elapsedMs: n(pick(row, 'elapsedMs'), 0),
    // Absent `truncated` is TRUE. See the header comment.
    truncated: !(truncated === false || truncated === 'false' || truncated === 0),
    devicesWithoutSnapshot: n(pick(row, 'devicesWithoutSnapshot'), 0),
    notice: s(pick(row, 'notice')),
  };
}

export function normalizeSavedQuery(raw: Raw): SavedQuery {
  return {
    id: n(pick(raw, 'id'), 0),
    name: String(pick(raw, 'name') ?? ''),
    dsl: String(pick(raw, 'dsl') ?? pick(raw, 'expression') ?? ''),
    description: s(pick(raw, 'description')),
    isPolicy: pick(raw, 'isPolicy') === true || pick(raw, 'is_policy') === true,
    severity: clientSeverityOf(pick(raw, 'severity')),
    createdByName: s(pick(raw, 'createdByName')),
    createdAt: String(pick(raw, 'createdAt') ?? ''),
    lastRunAt: s(pick(raw, 'lastRunAt')),
    lastMatchCount: nOrNull(pick(raw, 'lastMatchCount')),
  };
}

/** Turn an axios failure into something the editor can point at. */
export function queryErrorOf(err: unknown): QueryError {
  const response = (err as { response?: { status?: number; data?: Raw } }).response;
  const data = response?.data ?? {};
  const message = s(pick(data, 'error') ?? pick(data, 'message')) ?? 'query failed';
  const declared = String(pick(data, 'kind') ?? '');
  const kind: QueryError['kind'] =
    declared === 'syntax' || declared === 'path_not_allowed' || declared === 'unsupported'
      ? declared
      // The query controller answers a refused expression with a 400 carrying
      // the parser's `offset` (`asHttp()`); 422 is kept for older builds.
      : response?.status === 422 || response?.status === 400 ? 'syntax' : 'server';
  return {
    message,
    offset: nOrNull(pick(data, 'offset')),
    length: nOrNull(pick(data, 'length')),
    kind,
  };
}

// ── The client ──────────────────────────────────────────────────────────────

export const queryApi = {
  /**
   * Run a query. `null` = the query API is not served by this build.
   *
   * A refused query (bad syntax, path off the whitelist) is NOT a null: it
   * throws, and the caller renders `queryErrorOf(err)` against the editor. Those
   * are different situations and only one of them is the operator's fault.
   */
  async run(dsl: string, limit = 300): Promise<QueryResult | null> {
    try {
      const res = await apiClient.post<ApiResponse<unknown>>('/query/run', { dsl, limit });
      return normalizeQueryResult(res.data.data);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /** Parse and compile through `/explain` (see the header: a valid query is
   *  planned with EXPLAIN ANALYZE, i.e. run once, read-only). Used on demand,
   *  never on every keystroke: a round trip per character makes an editor feel
   *  broken and makes the server parse a hundred incomplete expressions. */
  async validate(dsl: string): Promise<QueryError | null> {
    try {
      await apiClient.post<ApiResponse<unknown>>('/query/explain', { dsl });
      return null;
    } catch (err) {
      if (isRouteAbsent(err)) {
        return { message: 'explain endpoint not served', offset: null, length: null, kind: 'server' };
      }
      return queryErrorOf(err);
    }
  },

  async listSaved(): Promise<SavedQuery[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<unknown>>('/query/saved');
      return asRows(res.data.data).map(normalizeSavedQuery);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /**
   * The server refuses `isPolicy` on a create (promotion is DRIFT_MANAGE, a
   * separate act) and refuses a `severity` on a non-policy query. So the
   * query is created bare and, when asked, promoted by its own route — two
   * requests, each behind its own capability, exactly as the server intends.
   */
  async save(req: SaveQueryRequest): Promise<SavedQuery | null> {
    try {
      const res = await apiClient.post<ApiResponse<unknown>>('/query/saved', {
        name: req.name,
        dsl: req.dsl,
        description: req.description ?? undefined,
      });
      const payload = res.data.data;
      if (!payload || typeof payload !== 'object') return null;
      const created = normalizeSavedQuery(payload as Raw);
      if (!req.isPolicy) return created;
      return (await queryApi.setPolicy(created.id, true, req.severity ?? 'info')) ?? created;
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  async remove(id: number): Promise<boolean> {
    try {
      await apiClient.delete<ApiResponse<unknown>>(`/query/saved/${id}`);
      return true;
    } catch (err) {
      if (isRouteAbsent(err)) return false;
      throw err;
    }
  },

  /**
   * Promote a saved query to a POLICY — evaluated at every snapshot.
   *
   * The DSL text is not re-sent: promoting must not be an opportunity to change
   * the expression. A policy whose text differs from the query it was promoted
   * from is a policy nobody reviewed.
   *
   * `/promote { severity }` or `/demote` (no body), both behind DRIFT_MANAGE.
   */
  async setPolicy(id: number, isPolicy: boolean, severity: PolicySeverity): Promise<SavedQuery | null> {
    try {
      const res = isPolicy
        ? await apiClient.post<ApiResponse<unknown>>(`/query/saved/${id}/promote`, {
          severity: serverSeverityOf(severity),
        })
        : await apiClient.post<ApiResponse<unknown>>(`/query/saved/${id}/demote`, {});
      const payload = res.data.data;
      if (!payload || typeof payload !== 'object') return null;
      return normalizeSavedQuery(payload as Raw);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },
};

// ── Export (CSV / JSON) ─────────────────────────────────────────────────────

/**
 * Exports are built HERE, from the rows already on screen, and not fetched from
 * an export endpoint.
 *
 * That is deliberate: the file an operator hands to an auditor must be exactly
 * the answer he read, from the same snapshot set, with the same truncation. A
 * second server round trip would re-run the query against a fleet that may have
 * moved in between, and the two would disagree in a meeting.
 *
 * The truncation flag travels INTO the file for the same reason.
 */
function csvCell(value: unknown): string {
  if (value === null || value === undefined) return '';
  const str = typeof value === 'object' ? JSON.stringify(value) : String(value);
  return /[",\n;]/.test(str) ? `"${str.replace(/"/g, '""')}"` : str;
}

export function resultToCsv(result: QueryResult): string {
  const head = ['device', 'site', 'brand', 'model', 'osVersion', 'snapshotAt',
    ...result.columns.map((c) => c.key)];
  const lines = [head.map(csvCell).join(',')];
  for (const row of result.rows) {
    lines.push([
      row.deviceName ?? `#${row.deviceId}`,
      row.siteName ?? '',
      row.brand,
      row.model ?? '',
      row.osVersion ?? '',
      row.snapshotAt ?? '',
      ...result.columns.map((c) => row.cells[c.key]),
    ].map(csvCell).join(','));
  }
  if (result.truncated) {
    lines.push('');
    lines.push(csvCell('TRUNCATED: this export is a partial answer.'));
  }
  return lines.join('\n');
}

export function resultToJson(result: QueryResult, dsl: string): string {
  return JSON.stringify(
    {
      dsl,
      exportedAt: new Date().toISOString(),
      devicesExamined: result.devicesExamined,
      devicesWithoutSnapshot: result.devicesWithoutSnapshot,
      truncated: result.truncated,
      notice: result.notice,
      rows: result.rows,
    },
    null,
    2,
  );
}

/** Hand the file to the browser. Revoking on the next tick rather than
 *  immediately: Safari cancels a download whose object URL is already gone. */
export function downloadText(filename: string, mime: string, text: string): void {
  const blob = new Blob([text], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
