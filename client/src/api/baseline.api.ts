import apiClient from './client';
import type { DeviceBrand } from '@obliwan/shared';
import { DEVICE_BRANDS } from '@obliwan/shared';
import { isRouteAbsent } from './change.api';
import type {
  BaselineFact,
  BaselineRun,
  BaselineRunState,
  ClusterMember,
  ConformanceRow,
  DeducedVariable,
  FactClass,
  FactCluster,
  StartRunRequest,
  TemplateDraft,
} from '@/types/baseline';
import { BASELINE_RUN_STATES } from '@/types/baseline';

/**
 * Fleet takeover / Golden Site.
 *
 * ── THE ROUTES — READ OFF `server/src/routes/baseline.routes.ts` ────────────
 * This module used to call a `/runs/:id/clusters`, `/clusters/:id/facts`,
 * `/clusters/:id/draft`, `/facts/:id/exception`, `/clusters/:id/promote`
 * surface the server never served. What `baseline.controller.ts` answers —
 * and NOTE it answers BARE JSON, not the `{ success, data }` envelope, which is
 * why every read below goes through `body()`:
 *
 *   GET    /api/baseline/runs                 -> BaselineRunSummary[]
 *   POST   /api/baseline/runs   BaselineParams -> 201 BaselineRunOutcome { runId }
 *   GET    /api/baseline/runs/:id             -> { run, clusters: BaselineClusterRow[] }
 *   GET    /api/baseline/runs/:id/deviations?clusterId&kind&limit -> { rows, total }
 *   GET    /api/baseline/runs/:id/conformance -> { devices, sites }
 *   GET    /api/baseline/clusters/:id         -> { cluster, members, slots }
 *   GET    /api/baseline/drafts/:id           -> BaselineDraftRow
 *   POST   /api/baseline/drafts/:id/promote { name } -> 201 { templateId, revisionId }
 *
 * The screen thinks in clusters and facts; the server keys drafts by DRAFT id
 * and never returns a cluster's run id from `/clusters/:id`. `listClusters()`
 * therefore remembers, per cluster, the run and the draft it came with
 * (`clusterIndex`), and `getDraft` / `promote` / `listFacts` resolve through it.
 * The page always lists clusters before it opens one, so the index is warm;
 * a cold one degrades to the stated absence, never to a guessed id.
 *
 * A "fact" here is one mined SLOT (`baseline_slots`): `constant` + in body is
 * `common`, `variable` + in body is `variable`, anything not in the body (or
 * `divergent`) is `outlier`. `presentOn / memberCount` is the server's own
 * pair. `missingFrom` is read from the run's `missing` deviations.
 *
 * NO SERVER EQUIVALENT — `addException` / `removeException`. The server
 * records a client specificity per DEVIATION (one device, one slot:
 * `PATCH /deviations/:id { classification: 'client_specific', reason, scope }`)
 * and never per fact. Fanning one click out into N classifications would be a
 * decision about scope this module has no business taking, so both calls fail
 * with that sentence instead. The `threshold` of `StartRunRequest` has no
 * server knob either (the miner's stopping rule is `minCoverage` /
 * `maxClusters`) and is NOT sent: `BaselineParams` is `.strict()`.
 *
 * ── THE COUNTS ARE NEVER SYNTHESISED ────────────────────────────────────────
 * `presentOn` / `total` are read straight through and a missing `total` becomes
 * 0, not the member count. A denominator this client invented would produce
 * "present on 27/27" for a fact the miner saw on 27 of 30 boxes — which is the
 * single most misleading sentence this feature could print, because it turns a
 * three-site divergence into a unanimous baseline.
 *
 * ── The secrets rule ────────────────────────────────────────────────────────
 * `DeducedVariable.sampleValues` is the dangerous field of this milestone: the
 * miner's whole job is to notice that a value differs per site, and a PPPoE
 * password differs per site. The normaliser DROPS sample values whose variable
 * name or fact path looks secret, and the renderer scans what survives. The
 * server must not send them; this is the second lock.
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
    const items = p.items ?? p.rows ?? p.runs ?? p.clusters ?? p.facts
      ?? p.members ?? p.variables ?? p.conformance;
    if (Array.isArray(items)) return items as Raw[];
  }
  return [];
}

function brandOf(v: unknown): DeviceBrand | null {
  const raw = s(v);
  return raw && (DEVICE_BRANDS as readonly string[]).includes(raw) ? (raw as DeviceBrand) : null;
}

/**
 * The server's run vocabulary (`BASELINE_RUN_STATUSES`: pending, running,
 * succeeded, failed, cancelled) onto this screen's four. A cancelled run is
 * shown as `failed`: it produced nothing an operator may build on.
 *
 * Unknown run state degrades to `running`: it claims the least and it keeps
 * the screen polling instead of declaring a result nobody produced.
 */
function runStateOf(v: unknown): BaselineRunState {
  const raw = (s(v) ?? '').toLowerCase();
  if (raw === 'pending') return 'queued';
  if (raw === 'succeeded') return 'done';
  if (raw === 'cancelled') return 'failed';
  return (BASELINE_RUN_STATES as readonly string[]).includes(raw)
    ? (raw as BaselineRunState)
    : 'running';
}

/**
 * A mined slot's class on this screen. Anything the template body does NOT
 * carry is an `outlier` — the class that DEMANDS a human decision. Guessing
 * `common` would silently fold an unclassified divergence into the template
 * everybody is about to deploy; a `divergent` slot is never templated at all.
 */
function factClassOfSlot(role: unknown, inBody: unknown): FactClass {
  const r = (s(role) ?? '').toLowerCase();
  if (inBody !== true) return 'outlier';
  if (r === 'constant') return 'common';
  if (r === 'variable') return 'variable';
  return 'outlier';
}

/** Variable names and fact paths that must not carry sample values. */
const SECRET_VARIABLE_HINTS = [
  'password', 'passwd', 'passphrase', 'secret', 'psk', 'preshared', 'pre-shared',
  'key', 'credential', 'token', 'community',
];

function looksSecretVariable(name: string, factPath: string): boolean {
  const hay = `${name} ${factPath}`.toLowerCase();
  return SECRET_VARIABLE_HINTS.some((h) => hay.includes(h));
}

/** The baseline controller answers bare JSON; tolerate an envelope anyway. */
function body(payload: unknown): unknown {
  if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
    const p = payload as Raw;
    if ('success' in p && 'data' in p) return p.data;
  }
  return payload;
}

function unsupported(message: string): Error {
  const err = new Error(message) as Error & { response: { status: number; data: { error: string } } };
  // Shaped like a server refusal so `errorMessageOf()` reads the sentence, and
  // NOT a 404, so `isRouteAbsent()` cannot turn it into a generic absence.
  err.response = { status: 422, data: { error: message } };
  return err;
}

/** `BaselineRunSummary`. `skippedCount` is the devices the run excluded —
 *  no snapshot, or one older than `maxSnapshotAgeDays`. */
export function normalizeRun(raw: Raw): BaselineRun {
  return {
    id: n(pick(raw, 'id') ?? pick(raw, 'runId'), 0),
    state: runStateOf(pick(raw, 'state') ?? pick(raw, 'status')),
    deviceCount: n(pick(raw, 'deviceCount'), 0),
    devicesWithoutSnapshot: n(pick(raw, 'devicesWithoutSnapshot') ?? pick(raw, 'skippedCount'), 0),
    clusterCount: n(pick(raw, 'clusterCount'), 0),
    startedAt: String(pick(raw, 'startedAt') ?? pick(raw, 'createdAt') ?? ''),
    finishedAt: s(pick(raw, 'finishedAt')),
    error: s(pick(raw, 'error')),
    createdByName: s(pick(raw, 'createdByName')),
  };
}

/**
 * `BaselineClusterMemberRow`. `similarity` is `1 - distanceToMedoid` (the
 * weighted Jaccard distance the miner clustered on); `divergenceCount` is the
 * member's facts the template does not explain, `factsTotal - factsCovered` —
 * the server's own two numbers, subtracted, never estimated.
 */
function memberOf(raw: Raw, brand: DeviceBrand | null): ClusterMember {
  const distance = nOrNull(pick(raw, 'distanceToMedoid'));
  const total = n(pick(raw, 'factsTotal'), 0);
  const covered = n(pick(raw, 'factsCovered'), 0);
  return {
    deviceId: n(pick(raw, 'deviceId'), 0),
    deviceName: s(pick(raw, 'deviceName')),
    siteName: s(pick(raw, 'siteName')),
    brand,
    family: null,
    similarity: distance === null ? 0 : Math.max(0, Math.min(1, 1 - distance)),
    divergenceCount: Math.max(0, total - covered),
  };
}

/** A `variable` slot (`BaselineSlotRow`) as a deduced variable. */
export function normalizeVariable(raw: Raw): DeducedVariable {
  const name = String(pick(raw, 'varName') ?? pick(raw, 'name') ?? '');
  const factPath = String(pick(raw, 'factPath') ?? pick(raw, 'slot') ?? pick(raw, 'path') ?? '');
  const samples = pick(raw, 'sampleValues') ?? pick(raw, 'samples');
  const list = Array.isArray(samples) ? samples.map((x) => String(x)) : [];
  return {
    name,
    factPath,
    // A "variable" extracted over a secret field is exactly the last audit's
    // finding with a new name on it. The samples are dropped here; the count
    // survives, because "12 distinct values" is the useful part anyway.
    sampleValues: looksSecretVariable(name, factPath) ? [] : list,
    distinctCount: n(pick(raw, 'distinctCount') ?? pick(raw, 'distinctValues'), list.length),
    presentOn: n(pick(raw, 'presentOn'), 0),
  };
}

function isTemplatedVariable(slot: Raw): boolean {
  return pick(slot, 'role') === 'variable' && pick(slot, 'inBody') === true;
}

/** `GET /runs/:id` gives the cluster row; `GET /clusters/:id` the members and
 *  the slots. Both are needed for one `FactCluster`. */
export function normalizeCluster(row: Raw, detail: Raw): FactCluster {
  const brand = brandOf(pick(row, 'brand'));
  const slots = asRows(pick(detail, 'slots'));
  return {
    id: n(pick(row, 'id'), 0),
    name: String(pick(row, 'label') ?? pick(row, 'name') ?? `cluster-${n(pick(row, 'id'), 0)}`),
    brand,
    family: null,
    members: asRows(pick(detail, 'members')).map((m) => memberOf(m, brand)),
    commonFactCount: slots.filter((sl) => factClassOfSlot(pick(sl, 'role'), pick(sl, 'inBody')) === 'common').length,
    variableFactCount: slots.filter(isTemplatedVariable).length,
    variables: slots.filter(isTemplatedVariable).map(normalizeVariable),
    cohesion: n(pick(row, 'cohesion'), 0),
  };
}

/**
 * One `BaselineSlotRow` as a fact. `total` is the slot's own `memberCount` —
 * the server's denominator, never this client's (see the header).
 */
export function normalizeFact(
  slot: Raw,
  missingFrom: Array<{ deviceId: number; deviceName: string | null }> = [],
): BaselineFact {
  const path = String(pick(slot, 'slot') ?? '');
  const role = s(pick(slot, 'role'));
  const constant = s(pick(slot, 'constantValue'));
  const varName = s(pick(slot, 'varName'));
  const summary = role === 'constant' && constant !== null
    ? `${path} = ${constant}`
    : role === 'variable' && varName
      ? `${path} = {{ ${varName} }}`
      : `${path} — ${n(pick(slot, 'distinctValues'), 0)} distinct value(s)`;
  return {
    id: String(pick(slot, 'id') ?? ''),
    resource: String(pick(slot, 'section') ?? pick(slot, 'resource') ?? ''),
    semKey: path,
    summary,
    klass: factClassOfSlot(role, pick(slot, 'inBody')),
    presentOn: n(pick(slot, 'presentOn'), 0),
    // NOT defaulted to the member list's length — see the header. A
    // denominator this client invented is a lie with a number in it.
    total: n(pick(slot, 'memberCount') ?? pick(slot, 'total'), 0),
    missingFrom,
    // Exceptions live on deviations, not on slots (see the header).
    exception: null,
  };
}

/**
 * `BaselineDraftRow` + the cluster's slots. "Covered" is a slot the body
 * carries; the uncovered ones are enumerable by id. `coverageMean` (mean
 * member coverage) is a different number and is not substituted for it.
 */
export function normalizeDraft(payload: unknown, clusterId: number, slots: Raw[] = []): TemplateDraft | null {
  if (!payload || typeof payload !== 'object') return null;
  const row = payload as Raw;
  const covered = slots.filter((sl) => pick(sl, 'inBody') === true);
  const uncovered = slots.filter((sl) => pick(sl, 'inBody') !== true);
  return {
    clusterId: n(pick(row, 'clusterId'), clusterId),
    body: String(pick(row, 'body') ?? pick(row, 'template') ?? ''),
    variables: slots.filter(isTemplatedVariable).map(normalizeVariable),
    coveredFacts: covered.length,
    totalFacts: slots.length,
    uncoveredFactIds: uncovered.map((sl) => String(pick(sl, 'id') ?? '')),
    generatedAt: String(pick(row, 'generatedAt') ?? pick(row, 'promotedAt') ?? ''),
  };
}

/**
 * One `devices[]` row of `/runs/:id/conformance`. `score` is `scoreRaw` —
 * "what the fleet actually looks like" — and NOT `scoreAdjusted`: the row
 * already prints `documentedExceptions` beside it, and a single number
 * invites the reader to assume the flattering one.
 */
export function normalizeConformance(raw: Raw, clusterName: string | null = null): ConformanceRow {
  return {
    deviceId: n(pick(raw, 'deviceId'), 0),
    deviceName: s(pick(raw, 'deviceName')),
    siteName: s(pick(raw, 'siteName')),
    clusterId: nOrNull(pick(raw, 'clusterId')),
    clusterName: s(pick(raw, 'clusterName')) ?? clusterName,
    // `null` and not 0: a device with no snapshot has no score, and 0 reads as
    // "totally non-conformant" for a box nobody has ever collected.
    score: nOrNull(pick(raw, 'score') ?? pick(raw, 'scoreRaw')),
    matchedFacts: n(pick(raw, 'matchedFacts') ?? pick(raw, 'factsCovered'), 0),
    divergences: n(pick(raw, 'divergences') ?? pick(raw, 'deviations'), 0),
    documentedExceptions: n(
      pick(raw, 'documentedExceptions')
        ?? n(pick(raw, 'excused'), 0) + n(pick(raw, 'excusedMissing'), 0),
      0,
    ),
    evaluatedAt: s(pick(raw, 'evaluatedAt')),
  };
}

// ── What a cluster id resolves to ───────────────────────────────────────────

/** clusterId → the run and the draft it was listed with. See the header. */
const clusterIndex = new Map<number, { runId: number; draftId: number | null; label: string }>();

async function getClusterDetail(clusterId: number): Promise<Raw> {
  const res = await apiClient.get<unknown>(`/baseline/clusters/${clusterId}`);
  const payload = body(res.data);
  return (payload && typeof payload === 'object' ? payload : {}) as Raw;
}

// ── The client ──────────────────────────────────────────────────────────────

export const baselineApi = {
  async listRuns(): Promise<BaselineRun[] | null> {
    try {
      const res = await apiClient.get<unknown>('/baseline/runs');
      return asRows(body(res.data)).map(normalizeRun);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /**
   * The run is SYNCHRONOUS server-side and answers a `BaselineRunOutcome`
   * (counts, no status, no timestamps); the run row it wrote is then read
   * back so the screen shows the server's summary rather than a reconstruction.
   * `threshold` is not sent — see the header.
   */
  async startRun(req: StartRunRequest): Promise<BaselineRun | null> {
    try {
      const params: Raw = {};
      if (req.brand) params.brand = req.brand;
      if (req.deviceIds && req.deviceIds.length > 0) params.deviceIds = req.deviceIds;
      const res = await apiClient.post<unknown>('/baseline/runs', params);
      const outcome = (body(res.data) ?? {}) as Raw;
      const runId = nOrNull(pick(outcome, 'runId') ?? pick(outcome, 'id'));
      if (runId === null) return null;
      const read = await apiClient.get<unknown>(`/baseline/runs/${runId}`);
      const run = pick((body(read.data) ?? {}) as Raw, 'run');
      return run && typeof run === 'object' ? normalizeRun(run as Raw) : normalizeRun(outcome);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /** `GET /runs/:id` for the rows, then one `GET /clusters/:id` per cluster
   *  for members and slots (at most `maxClusters`, 24). */
  async listClusters(runId: number): Promise<FactCluster[] | null> {
    try {
      const res = await apiClient.get<unknown>(`/baseline/runs/${runId}`);
      const rows = asRows(pick((body(res.data) ?? {}) as Raw, 'clusters'));
      for (const row of rows) {
        clusterIndex.set(n(pick(row, 'id'), 0), {
          runId,
          draftId: nOrNull(pick(row, 'draftId')),
          label: String(pick(row, 'label') ?? ''),
        });
      }
      const details = await Promise.all(rows.map((row) => getClusterDetail(n(pick(row, 'id'), 0))));
      return rows.map((row, i) => normalizeCluster(row, details[i]));
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /**
   * The cluster's slots as facts, filtered here by class. `missingFrom` comes
   * from the run's `missing` deviations for this cluster (first 500). The
   * `exception` class is always empty — exceptions are per deviation.
   */
  async listFacts(clusterId: number, klass?: FactClass): Promise<BaselineFact[] | null> {
    try {
      const detail = await getClusterDetail(clusterId);
      const names = new Map<number, string | null>(
        asRows(pick(detail, 'members')).map((m) => [n(pick(m, 'deviceId'), 0), s(pick(m, 'deviceName'))]),
      );
      const missingBySlot = new Map<string, Array<{ deviceId: number; deviceName: string | null }>>();
      const runId = clusterIndex.get(clusterId)?.runId;
      if (runId !== undefined) {
        const dev = await apiClient.get<unknown>(`/baseline/runs/${runId}/deviations`, {
          params: { clusterId, kind: 'missing', limit: 500 },
        });
        for (const d of asRows(body(dev.data))) {
          const slot = String(pick(d, 'slot') ?? '');
          const deviceId = n(pick(d, 'deviceId'), 0);
          const list = missingBySlot.get(slot) ?? [];
          list.push({ deviceId, deviceName: names.get(deviceId) ?? null });
          missingBySlot.set(slot, list);
        }
      }
      return asRows(pick(detail, 'slots'))
        .map((sl) => normalizeFact(sl, missingBySlot.get(String(pick(sl, 'slot') ?? '')) ?? []))
        .filter((f) => !klass || f.klass === klass);
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /** `null` when the cluster has no draft, or was not listed first. */
  async getDraft(clusterId: number): Promise<TemplateDraft | null> {
    const draftId = clusterIndex.get(clusterId)?.draftId ?? null;
    if (draftId === null) return null;
    try {
      const [res, detail] = await Promise.all([
        apiClient.get<unknown>(`/baseline/drafts/${draftId}`),
        getClusterDetail(clusterId),
      ]);
      return normalizeDraft(body(res.data), clusterId, asRows(pick(detail, 'slots')));
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /**
   * NO SERVER EQUIVALENT — see the header. The server's client specificity is
   * a per-deviation classification, and this screen has no deviation to name.
   * `reason` stays required by the signature for the day it does.
   */
  async addException(_factId: string, _reason: string): Promise<BaselineFact | null> {
    throw unsupported(
      'Exceptions are recorded per deviation (one device, one slot) by this server, not per fact. '
      + 'Classify the individual deviations as client-specific instead.',
    );
  },

  /** NO SERVER EQUIVALENT — no fact ever carries an exception (see above). */
  async removeException(_factId: string): Promise<boolean> {
    throw unsupported(
      'Exceptions are recorded per deviation by this server, not per fact, and are removed there.',
    );
  },

  async conformance(runId: number): Promise<ConformanceRow[] | null> {
    try {
      const res = await apiClient.get<unknown>(`/baseline/runs/${runId}/conformance`);
      const payload = body(res.data);
      const rows = Array.isArray(payload) ? (payload as Raw[]) : asRows(pick((payload ?? {}) as Raw, 'devices'));
      return rows.map((r) => {
        const cid = nOrNull(pick(r, 'clusterId'));
        return normalizeConformance(r, cid === null ? null : clusterIndex.get(cid)?.label || null);
      });
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },

  /** Hand a draft to `/templates` as an unpublished revision. The publish step
   *  stays there, behind TEMPLATE_WRITE — this screen proposes, it never
   *  publishes, and it never touches a device. The server keys the
   *  promotion by DRAFT id; a cluster with no draft answers `null`. */
  async promote(clusterId: number, name: string): Promise<number | null> {
    const draftId = clusterIndex.get(clusterId)?.draftId ?? null;
    if (draftId === null) return null;
    try {
      const res = await apiClient.post<unknown>(`/baseline/drafts/${draftId}/promote`, { name });
      const payload = (body(res.data) ?? {}) as Raw;
      return nOrNull(pick(payload, 'templateId') ?? pick(payload, 'id'));
    } catch (err) {
      if (isRouteAbsent(err)) return null;
      throw err;
    }
  },
};
