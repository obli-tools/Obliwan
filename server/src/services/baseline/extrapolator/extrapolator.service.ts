// ============================================================================
// Brick 10 — the extrapolator service: runs, proposals, approval
// ============================================================================
//
// A run stands ON a miner run: the miner chose the clusters and the
// snapshot of every member; the extrapolator reads those very snapshots' RAW
// exports (redacted, `config_snapshots.raw_gz`) and proposes one template per
// cluster, proved by rendering. When no miner run is named, one is mined first,
// narrowed to MikroTik (the only family whose raw export the collector keeps).
//
// ┌─ THE WORK RUNS IN THE BACKGROUND, AND SAYS SO ────────────────────────────┐
// │ `POST …/extrapolations` writes the run row (`running`) and answers 202;  │
// │ the work continues in this process. A 200-router tenant costs seconds of  │
// │ rendering in the template worker — not a request to hold open. The row  │
// │ is the job's state: a process that dies mid-run leaves a `running` row,  │
// │ and the next run of the same tenant marks it `failed` ("interrupted")    │
// │ rather than letting it lie. One run per tenant at a time (in-process     │
// │ set, like the miner's): a double click is a 409, not two renders.        │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ APPROVAL: A DRAFT AND THE VALUES, NOTHING ELSE ──────────────────────────┐
// │ Approving creates a template and its revision 1 with status 'draft'      │
// │ (version.service: the body is parsed on the way in), and writes the      │
// │ NON-SECRET values the proposal carries — tenant defaults and site values │
// │ — through the variable resolver's own writer. A value already stored     │
// │ with a DIFFERENT content is a conflict, reported and left alone. Secrets │
// │ are never written (the extrapolator never had one), computed values are  │
// │ never stored (the allocator owns them: the policy fragment says what to  │
// │ set there), nothing is published, nothing reaches a router.             │
// └───────────────────────────────────────────────────────────────────────────┘

import { gunzipSync } from 'zlib';
import type { Knex } from 'knex';
import {
  EXTRAPOLATOR_MODEL_VERSION, ExtrapolationApproveBody, ExtrapolationParams, ExtrapolationRejectBody,
  probesOf,
  type ExtrapolatedDeviation, type ExtrapolatedPolicyFragment, type ExtrapolatedSiteResult,
  type ExtrapolatedVariable, type ExtrapolationApproveResult, type ExtrapolationBlockedReason,
  type ExtrapolationProposal, type ExtrapolationProposalSummary, type ExtrapolationReadiness,
  type ExtrapolationRun,
} from '@obliwan/shared';
import { db } from '../../../db';
import { logger } from '../../../utils/logger';
import { AppError } from '../../../middleware/errorHandler';
import { appendAudit } from '../../attestation/auditLog.service';
import { createDraft, createTemplate } from '../../template/version.service';
import { variableResolver } from '../../template/variableResolver.service';
import { modelGlobProblem, varSchemaSchema } from '../../../validators/template.schema';
import { modelMatches } from '../../template/assignment.service';
import { COLLECTABLE_FAMILIES } from '../../config/collect.service';
import { runBaseline } from '../miner.service';
import { tenantCollectRunning } from '../../drift/runtime';
import { groupByModel, modelKeyOf } from '../partition';
import { extrapolateCluster, type ExistingProbe, type ExistingValue, type ExtrapolationSiteInput } from './index';

/** Lines kept per site in the proposal detail; the site endpoint has them all. */
const DETAIL_LINE_CAP = 20;
const SNAPSHOT_BATCH = 25;

const inFlight = new Set<number>();

type Row = Record<string, unknown>;

function num(v: unknown): number {
  return typeof v === 'number' ? v : Number(v);
}

function numOrNull(v: unknown): number | null {
  return v === null || v === undefined ? null : num(v);
}

function iso(v: unknown): string | null {
  return v === null || v === undefined ? null : new Date(v as string).toISOString();
}

function json<T>(v: unknown, fallback: T): T {
  if (v === null || v === undefined) return fallback;
  if (typeof v === 'string') {
    try { return JSON.parse(v) as T; } catch { return fallback; }
  }
  return v as T;
}

// ============================================================================
// Read model
// ============================================================================

function toRun(r: Row): ExtrapolationRun {
  const stored = json<Record<string, unknown>>(r.params, {});
  // A run recorded before `groupBy` existed mined by structural profile; the
  // schema's default ('model') would misstate it.
  const parsed = ExtrapolationParams.safeParse(
    stored && typeof stored === 'object' && !('groupBy' in stored) ? { ...stored, groupBy: 'profile' } : stored,
  );
  return {
    id: num(r.id),
    uuid: String(r.uuid),
    status: String(r.status) as ExtrapolationRun['status'],
    modelVersion: num(r.model_version),
    baselineRunId: numOrNull(r.baseline_run_id),
    params: parsed.success ? parsed.data : ExtrapolationParams.parse({}),
    deviceCount: num(r.device_count),
    skippedCount: num(r.skipped_count),
    proposalCount: num(r.proposal_count),
    error: (r.error as string | null) ?? null,
    warnings: json<string[]>(r.warnings, []),
    startedAt: iso(r.started_at),
    finishedAt: iso(r.finished_at),
  };
}

function toSummary(r: Row): ExtrapolationProposalSummary {
  return {
    id: num(r.id),
    runId: num(r.run_id),
    clusterIndex: num(r.cluster_index),
    label: String(r.label),
    model: typeof r.model === 'string' && r.model.trim() !== '' ? r.model : null,
    baselineClusterId: numOrNull(r.baseline_cluster_id),
    memberCount: num(r.member_count),
    lineCount: num(r.line_count),
    variableCount: num(r.variable_count),
    deviationCount: num(r.deviation_count),
    reproductionMin: num(r.reproduction_min),
    reproductionMean: num(r.reproduction_mean),
    gateMet: r.gate_met === true,
    status: String(r.status) as ExtrapolationProposalSummary['status'],
    templateId: numOrNull(r.template_id),
    templateRevisionId: numOrNull(r.template_revision_id),
    decidedAt: iso(r.decided_at),
    decisionNote: (r.decision_note as string | null) ?? null,
  };
}

function toSite(r: Row, cap: number | null): ExtrapolatedSiteResult {
  const notReproduced = json<string[]>(r.not_reproduced, []);
  const wouldAdd = json<string[]>(r.would_add, []);
  return {
    deviceId: num(r.device_id),
    deviceName: String(r.device_name),
    siteId: numOrNull(r.site_id),
    siteCode: (r.site_code as string | null) ?? null,
    snapshotId: numOrNull(r.snapshot_id),
    linesActual: num(r.lines_actual),
    linesRendered: num(r.lines_rendered),
    linesReproduced: num(r.lines_reproduced),
    score: num(r.score),
    notReproduced: cap === null ? notReproduced : notReproduced.slice(0, cap),
    wouldAdd: cap === null ? wouldAdd : wouldAdd.slice(0, cap),
    renderError: (r.render_error as string | null) ?? null,
  };
}

export async function listRuns(tenantId: number, limit = 25): Promise<ExtrapolationRun[]> {
  const rows = await db('extrapolation_runs')
    .where('tenant_id', tenantId)
    .orderBy('id', 'desc')
    .limit(Math.min(Math.max(limit, 1), 100));
  return rows.map(toRun);
}

export async function getRun(
  tenantId: number,
  runId: number,
): Promise<{ run: ExtrapolationRun; proposals: ExtrapolationProposalSummary[] }> {
  const row = await db('extrapolation_runs').where({ id: runId, tenant_id: tenantId }).first();
  if (!row) throw new AppError(404, 'Extrapolation run not found');
  const proposals = await db('extrapolation_proposals')
    .where({ run_id: runId, tenant_id: tenantId })
    .orderBy('cluster_index', 'asc')
    .select(
      'id', 'run_id', 'cluster_index', 'label', 'model', 'baseline_cluster_id', 'member_count', 'line_count',
      'variable_count', 'deviation_count', 'reproduction_min', 'reproduction_mean', 'gate_met', 'status',
      'template_id', 'template_revision_id', 'decided_at', 'decision_note',
    );
  return { run: toRun(row), proposals: proposals.map(toSummary) };
}

export async function getProposal(tenantId: number, proposalId: number): Promise<ExtrapolationProposal> {
  const row = await db('extrapolation_proposals').where({ id: proposalId, tenant_id: tenantId }).first();
  if (!row) throw new AppError(404, 'Extrapolation proposal not found');
  const sites = await db('extrapolation_site_results')
    .where({ proposal_id: proposalId, tenant_id: tenantId })
    .orderBy([{ column: 'score', order: 'asc' }, { column: 'device_id', order: 'asc' }]);
  return {
    ...toSummary(row),
    body: String(row.body),
    bodySha256: String(row.body_sha256),
    varSchema: json<Record<string, unknown>>(row.var_schema, {}),
    variables: json<ExtrapolatedVariable[]>(row.variables, []),
    policy: json<ExtrapolatedPolicyFragment>(row.policy, emptyPolicy()),
    deviations: json<ExtrapolatedDeviation[]>(row.deviations, []),
    sites: sites.map((s: Row) => toSite(s, DETAIL_LINE_CAP)),
    warnings: json<string[]>(row.warnings, []),
  };
}

export async function getSiteResult(
  tenantId: number,
  proposalId: number,
  deviceId: number,
): Promise<ExtrapolatedSiteResult> {
  const row = await db('extrapolation_site_results')
    .where({ proposal_id: proposalId, tenant_id: tenantId, device_id: deviceId })
    .first();
  if (!row) throw new AppError(404, 'Site result not found');
  return toSite(row, null);
}

function emptyPolicy(): ExtrapolatedPolicyFragment {
  return {
    pppLoginTemplate: null, systemIdentityTemplate: null, lanFormula: null, derived: {},
    lanRecorded: [], adopted: [], current: null,
  };
}

// ============================================================================
// Starting a run
// ============================================================================

export async function startExtrapolation(
  tenantId: number,
  rawParams: unknown,
  userId: number | null,
): Promise<ExtrapolationRun> {
  const parsed = ExtrapolationParams.safeParse(rawParams ?? {});
  if (!parsed.success) {
    throw new AppError(400, `Invalid extrapolation parameters: ${parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}`);
  }
  const params = parsed.data;
  if (inFlight.has(tenantId)) {
    throw new AppError(409, 'An extrapolation is already running for this tenant');
  }
  // Mining while the client's configurations are being re-read would mine a
  // fleet half old, half new: wait for the collection to finish.
  if (tenantCollectRunning(tenantId)) {
    throw new AppError(409, 'The client\'s configurations are being collected: start the extrapolation once the collection has finished.');
  }
  if (params.baselineRunId !== null) {
    const base = await db('baseline_runs').where({ id: params.baselineRunId, tenant_id: tenantId }).first('status');
    if (!base) throw new AppError(404, 'Baseline run not found');
    if (base.status !== 'succeeded') {
      throw new AppError(409, `Baseline run ${params.baselineRunId} is ${base.status}: only a succeeded run has clusters`);
    }
  }
  inFlight.add(tenantId);
  try {
    // A `running` row nobody in this process owns was left by a process that
    // died: it is closed, not left to lie.
    await db('extrapolation_runs')
      .where({ tenant_id: tenantId, status: 'running' })
      .update({
        status: 'failed',
        error: 'interrupted: the process running it stopped before it finished',
        finished_at: db.fn.now(),
        updated_at: db.fn.now(),
      });
    const [row] = await db('extrapolation_runs')
      .insert({
        tenant_id: tenantId,
        baseline_run_id: params.baselineRunId,
        status: 'running',
        model_version: EXTRAPOLATOR_MODEL_VERSION,
        params: JSON.stringify(params),
        started_at: db.fn.now(),
        created_by: userId,
      })
      .returning('*');
    const runId = num(row.id);
    void work(runId, tenantId, params, userId)
      .catch(async (err: unknown) => {
        const message = err instanceof Error ? err.message : String(err);
        logger.error({ runId, tenantId, err: message }, 'extrapolation run failed');
        await db('extrapolation_runs').where({ id: runId, tenant_id: tenantId }).update({
          status: 'failed',
          error: message.slice(0, 4000) || 'failed',
          finished_at: db.fn.now(),
          updated_at: db.fn.now(),
        }).catch(() => undefined);
      })
      .finally(() => inFlight.delete(tenantId));
    return toRun(row);
  } catch (err) {
    inFlight.delete(tenantId);
    throw err;
  }
}

/** Exposed for the harness: runs synchronously. */
export async function runExtrapolationNow(
  tenantId: number,
  rawParams: unknown,
  userId: number | null,
): Promise<ExtrapolationRun> {
  const started = await startExtrapolation(tenantId, rawParams, userId);
  for (let i = 0; i < 600 && inFlight.has(tenantId); i++) {
    await new Promise((r) => setTimeout(r, 200));
  }
  return (await getRun(tenantId, started.id)).run;
}

// ============================================================================
// The work
// ============================================================================

interface ClusterRow { id: number; cluster_index: number; label: string; brand: string; medoid_device_id: number | null; model: string | null }
interface MemberRow { cluster_id: number; device_id: number; snapshot_id: number | null }
interface DeviceRow { id: number; name: string; site_id: number | null; ppp_username: string | null }
interface SiteRow { id: number; code: string | null; name: string | null; country: string | null }
interface ProvisioningRow { site_id: number; ppp_username: string | null; system_identity: string | null; lan_subnet: string | null }

async function work(runId: number, tenantId: number, params: ExtrapolationParams, userId: number | null): Promise<void> {
  const warnings: string[] = [];
  let baselineRunId = params.baselineRunId;
  if (baselineRunId === null) {
    // `model`: one template per router model (concentrators excluded), at
    // most `maxProfilesPerModel` profiles per model. `profile`: the
    // historical structural clustering of the whole MikroTik fleet.
    const mined = await runBaseline(
      tenantId,
      params.groupBy === 'model'
        ? { brand: 'mikrotik', partitionBy: 'model', maxClusters: params.maxProfilesPerModel }
        : { brand: 'mikrotik' },
      userId,
    );
    baselineRunId = mined.runId;
    await db('extrapolation_runs').where({ id: runId, tenant_id: tenantId }).update({ baseline_run_id: baselineRunId });
    if (!mined.purityGateMet) {
      warnings.push(
        `Le minage #${baselineRunId} n'a pas atteint sa porte de pureté (k=${mined.chosenK}) : ` +
        'les profils proposés mélangent peut-être des configurations différentes.',
      );
    }
  }

  const clusters = (await db('baseline_clusters')
    .where({ run_id: baselineRunId, tenant_id: tenantId })
    .orderBy('cluster_index', 'asc')
    .select('id', 'cluster_index', 'label', 'brand', 'medoid_device_id', 'model')) as ClusterRow[];
  const members = (await db('baseline_cluster_members')
    .where({ run_id: baselineRunId, tenant_id: tenantId })
    .select('cluster_id', 'device_id', 'snapshot_id')) as MemberRow[];
  if (clusters.length === 0) throw new Error(`baseline run ${baselineRunId} has no cluster`);

  const deviceIds = [...new Set(members.map((m) => num(m.device_id)))];
  const devices = new Map<number, DeviceRow>();
  for (let i = 0; i < deviceIds.length; i += 500) {
    const rows = (await db('devices')
      .where('tenant_id', tenantId)
      .whereIn('id', deviceIds.slice(i, i + 500))
      .select('id', 'name', 'site_id', 'ppp_username')) as DeviceRow[];
    for (const r of rows) devices.set(num(r.id), r);
  }
  const siteIds = [...new Set([...devices.values()].map((d) => d.site_id).filter((x): x is number => x !== null))];
  const sites = new Map<number, SiteRow>();
  const provisioning = new Map<number, ProvisioningRow>();
  for (let i = 0; i < siteIds.length; i += 500) {
    const slice = siteIds.slice(i, i + 500);
    for (const r of (await db('sites').where('tenant_id', tenantId).whereIn('id', slice)
      .select('id', 'code', 'name', 'country')) as SiteRow[]) sites.set(num(r.id), r);
    for (const r of (await db('site_provisioning').where('tenant_id', tenantId).whereIn('site_id', slice)
      .select('site_id', 'ppp_username', 'system_identity',
        db.raw('lan_subnet::text as lan_subnet'))) as ProvisioningRow[]) provisioning.set(num(r.site_id), r);
  }

  const existingProbes = await loadExistingProbes(tenantId);
  const existingValues = await loadExistingValues(tenantId);
  const currentPolicy = await loadCurrentPolicy(tenantId);

  let deviceCount = 0;
  let skipped = 0;
  let proposals = 0;
  for (const cluster of clusters) {
    const label = cluster.label;
    if (cluster.brand !== 'mikrotik') {
      warnings.push(`${label} : marque ${cluster.brand}, non extrapolée (seul l'export RouterOS est conservé brut).`);
      skipped += members.filter((m) => num(m.cluster_id) === num(cluster.id)).length;
      continue;
    }
    const clusterMembers = members.filter((m) => num(m.cluster_id) === num(cluster.id))
      .sort((a, b) => num(a.device_id) - num(b.device_id));
    const raws = await loadRawExports(tenantId, clusterMembers);
    const inputs: ExtrapolationSiteInput[] = [];
    for (const m of clusterMembers) {
      const device = devices.get(num(m.device_id));
      const text = m.snapshot_id === null ? undefined : raws.get(num(m.snapshot_id));
      if (!device || text === undefined) { skipped++; continue; }
      const site = device.site_id !== null ? sites.get(num(device.site_id)) ?? null : null;
      const prov = device.site_id !== null ? provisioning.get(num(device.site_id)) ?? null : null;
      inputs.push({
        deviceId: num(device.id),
        deviceName: device.name,
        siteId: site ? num(site.id) : null,
        site: site ? { code: site.code, name: site.name, country: site.country } : null,
        recorded: {
          pppUsername: prov?.ppp_username ?? device.ppp_username ?? null,
          systemIdentity: prov?.system_identity ?? null,
          lanSubnet: prov?.lan_subnet ?? null,
        },
        snapshotId: numOrNull(m.snapshot_id),
        exportText: text,
      });
    }
    if (inputs.length === 0) {
      warnings.push(`${label} : aucun membre n'a d'export brut conservé, profil non extrapolé.`);
      continue;
    }
    if (raws.stale > 0) {
      warnings.push(
        `${label} : pour ${raws.stale} routeur(s), l'export brut lu date de plus de ${RAW_STALE_DAYS} jours ` +
        '(première collecte de cette configuration modélisée) : un changement limité à un menu non modélisé ' +
        '(SNMP, client L2TP, LTE, radio) peut ne pas y figurer.',
      );
    }
    const noSite = inputs.filter((x) => x.site === null).length;
    if (noSite > 0) {
      warnings.push(`${label} : ${noSite} routeur(s) sans site — aucune formule de site ne peut s'appuyer sur eux.`);
    }
    const proposal = await extrapolateCluster({
      label,
      clusterIndex: num(cluster.cluster_index),
      sites: inputs,
      referenceDeviceId: numOrNull(cluster.medoid_device_id),
      params,
      existingProbes,
      existingValues,
      runLabel: `extrapolation #${runId}, minage #${baselineRunId}`,
    });
    proposal.draft.policy.current = currentPolicy;
    if (inputs.length === 1) {
      warnings.push(`${label} : un seul routeur : tout y est littéral, aucune variable n’a pu être déduite.`);
    }
    deviceCount += inputs.length;
    await persistProposal(runId, tenantId, num(cluster.id), proposal, cluster.model ?? null);
    proposals++;
  }

  // The routers this run could not read at all, said once, with where to look.
  const readiness = await getReadiness(tenantId, null);
  if (readiness.totals.blocked > 0) {
    warnings.push(
      `${readiness.totals.blocked} routeur(s) MikroTik du client sans configuration exploitable — ` +
      'voir « Configurations du client ».',
    );
  }

  await db('extrapolation_runs').where({ id: runId, tenant_id: tenantId }).update({
    status: 'succeeded',
    device_count: deviceCount,
    skipped_count: skipped,
    proposal_count: proposals,
    warnings: JSON.stringify(warnings),
    finished_at: db.fn.now(),
    updated_at: db.fn.now(),
  });
  logger.info({ runId, tenantId, baselineRunId, deviceCount, skipped, proposals }, 'extrapolation run finished');
}

/**
 * The raw (redacted) exports of the members' OWN snapshots — the ones the
 * miner mined. `config_snapshots` has no tenant column: the join to `devices`
 * with the tenant predicate is what keeps another customer's export out.
 */
/** A raw export older than this is flagged (see `loadRawExports`). */
const RAW_STALE_DAYS = 30;

/**
 * …and the text is the export of the FIRST collection that produced this NCM
 * hash: `storeSnapshot` does not refresh `raw_gz` when a later collection
 * hashes the same (UNIQUE(device_id, ncm_hash)). A change confined to a menu
 * the NCM does not model (SNMP, an L2TP client, LTE, the radios) is therefore
 * absent from it. Not fixed here — it is the collector's store — but counted,
 * so a run says how old the text it read is.
 */
async function loadRawExports(
  tenantId: number,
  members: readonly MemberRow[],
): Promise<Map<number, string> & { stale: number }> {
  const out = new Map<number, string>() as Map<number, string> & { stale: number };
  out.stale = 0;
  const cutoff = Date.now() - RAW_STALE_DAYS * 86_400_000;
  const ids = members.map((m) => m.snapshot_id).filter((x): x is number => x !== null).map(num);
  for (let i = 0; i < ids.length; i += SNAPSHOT_BATCH) {
    const rows = (await db('config_snapshots as s')
      .join('devices as d', 's.device_id', 'd.id')
      .where('d.tenant_id', tenantId)
      .whereIn('s.id', ids.slice(i, i + SNAPSHOT_BATCH))
      .whereNotNull('s.raw_gz')
      .select('s.id', 's.raw_gz', 's.captured_at')) as Array<{ id: number; raw_gz: Buffer; captured_at: Date }>;
    for (const r of rows) {
      out.set(num(r.id), gunzipSync(r.raw_gz).toString('utf8'));
      if (new Date(r.captured_at).getTime() < cutoff) out.stale++;
    }
  }
  return out;
}

/** The probes the tenant's own templates already state (newest revision of
 *  each MikroTik template, its own or the library's). */
async function loadExistingProbes(tenantId: number): Promise<ExistingProbe[]> {
  const rows = (await db('template_revisions as r')
    .join('templates as t', 'r.template_id', 't.id')
    .where('t.brand', 'mikrotik')
    .andWhere((q) => q.where('t.tenant_id', tenantId).orWhereNull('t.tenant_id'))
    .orderBy([{ column: 'r.template_id' }, { column: 'r.revision', order: 'desc' }])
    .distinctOn('r.template_id')
    .select('r.var_schema', 't.name')) as Array<{ var_schema: unknown; name: string }>;
  const out: ExistingProbe[] = [];
  for (const r of rows) {
    for (const { key, probe, property } of probesOf(json(r.var_schema, {}))) {
      // A presence test (a present/absent pair or a present-only probe, e.g.
      // wan1_mode) reads no property: it names no place a value sits.
      if (!probe.property) continue;
      // A CONDITIONED read (`unless`, e.g. wan1_address only on a fixed-IP
      // store) is not a plain place a value sits: adopting its name for an
      // unconditioned read would drop the condition.
      if (probe.unless !== undefined || probe.else !== undefined || probe.single !== undefined) continue;
      out.push({
        key,
        menu: probe.menu,
        where: Object.fromEntries(Object.entries(probe.where ?? {}).map(([k, v]) => [k, String(v)])),
        property: probe.property,
        label: typeof property['x-obliwan-label'] === 'string' ? property['x-obliwan-label'] : null,
        source: r.name,
      });
    }
  }
  return out;
}

/** Non-secret string values stored at the instance, global and tenant levels. */
async function loadExistingValues(tenantId: number): Promise<ExistingValue[]> {
  const rows = (await db('config_variables')
    .where('is_secret', false)
    .andWhere((q) => q
      .where((w) => w.whereNull('tenant_id').andWhere('scope', 'instance'))
      .orWhere((w) => w.where('tenant_id', tenantId).whereIn('scope', ['global', 'tenant'])))
    .select('key', 'scope', 'value')) as Array<{ key: string; scope: string; value: unknown }>;
  const out: ExistingValue[] = [];
  for (const r of rows) {
    const v = json<unknown>(r.value, null);
    if (typeof v !== 'string') continue;
    out.push({ key: r.key, scope: r.scope as ExistingValue['scope'], value: v });
  }
  return out;
}

async function loadCurrentPolicy(tenantId: number): Promise<ExtrapolatedPolicyFragment['current']> {
  const row = (await db('tenant_allocation_policies')
    .where('tenant_id', tenantId)
    .first('ppp_login_template', 'identity_template', 'lan_mode', 'lan_formula', 'derived_values')) as
    | { ppp_login_template: string; identity_template: string | null; lan_mode: string | null; lan_formula: string | null; derived_values: unknown }
    | undefined;
  if (!row) {
    return { present: false, pppLoginTemplate: null, systemIdentityTemplate: null, lanFormula: null, derived: {} };
  }
  const derived = json<Record<string, unknown>>(row.derived_values, {});
  return {
    present: true,
    pppLoginTemplate: row.ppp_login_template,
    systemIdentityTemplate: row.identity_template,
    lanFormula: row.lan_mode === 'formula' ? row.lan_formula : null,
    derived: Object.fromEntries(Object.entries(derived ?? {}).map(([k, v]) => [k, String(v)])),
  };
}

async function persistProposal(
  runId: number,
  tenantId: number,
  baselineClusterId: number,
  p: Awaited<ReturnType<typeof extrapolateCluster>>,
  model: string | null,
): Promise<void> {
  const d = p.draft;
  await db.transaction(async (trx) => {
    const [row] = await trx('extrapolation_proposals')
      .insert({
        run_id: runId,
        tenant_id: tenantId,
        baseline_cluster_id: baselineClusterId,
        cluster_index: d.clusterIndex,
        label: d.label.slice(0, 64),
        model: model !== null && model.trim() !== '' ? model.slice(0, 64) : null,
        brand: 'mikrotik',
        member_count: p.sites.length,
        line_count: d.lineCount,
        variable_count: d.variables.length,
        deviation_count: d.deviations.length,
        body: d.body,
        body_sha256: d.bodySha256,
        var_schema: JSON.stringify(d.varSchema),
        variables: JSON.stringify(d.variables),
        policy: JSON.stringify(d.policy),
        deviations: JSON.stringify(d.deviations),
        warnings: JSON.stringify(d.warnings),
        reproduction_min: p.reproductionMin,
        reproduction_mean: p.reproductionMean,
        gate_met: p.gateMet,
      })
      .returning<{ id: number }[]>('id');
    const proposalId = num(row.id);
    const rows = p.sites.map((s) => ({
      proposal_id: proposalId,
      tenant_id: tenantId,
      device_id: s.deviceId,
      device_name: s.deviceName.slice(0, 255),
      site_id: s.siteId,
      site_code: s.siteCode ? s.siteCode.slice(0, 64) : null,
      snapshot_id: s.snapshotId,
      lines_actual: s.linesActual,
      lines_rendered: s.linesRendered,
      lines_reproduced: s.linesReproduced,
      score: s.score,
      not_reproduced: JSON.stringify(s.notReproduced),
      would_add: JSON.stringify(s.wouldAdd),
      render_error: s.renderError,
    }));
    for (let i = 0; i < rows.length; i += 200) await trx('extrapolation_site_results').insert(rows.slice(i, i + 200));
  });
}

// ============================================================================
// Decisions
// ============================================================================

interface Actor { userId: number | null; username: string | null }

export async function approveProposal(
  tenantId: number,
  proposalId: number,
  rawBody: unknown,
  actor: Actor,
): Promise<ExtrapolationApproveResult> {
  const parsedBody = ExtrapolationApproveBody.safeParse(rawBody ?? {});
  if (!parsedBody.success) {
    throw new AppError(400, `Invalid approval: ${parsedBody.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}`);
  }
  const body = parsedBody.data;
  if (body.modelPattern !== null) {
    const problem = modelGlobProblem(body.modelPattern);
    if (problem) throw new AppError(400, `Invalid model pattern: ${problem}`);
  }
  return db.transaction(async (trx) => {
    const row = await trx('extrapolation_proposals')
      .where({ id: proposalId, tenant_id: tenantId })
      .forUpdate()
      .first();
    if (!row) throw new AppError(404, 'Extrapolation proposal not found');
    if (row.status !== 'proposed') throw new AppError(409, `This proposal is already ${row.status}`);
    const varSchema = json<Record<string, unknown>>(row.var_schema, {});
    const judged = varSchemaSchema.safeParse(varSchema);
    if (!judged.success) {
      throw new AppError(409, `The proposed var_schema does not pass the template validator: ${judged.error.issues.slice(0, 3).map((i) => i.message).join('; ')}`);
    }

    let templateId: number;
    try {
      const tpl = await createTemplate(tenantId, {
        name: body.name,
        brand: String(row.brand),
        description: body.description,
        // The template applies to this router model only (assignment
        // resolution, `modelMatches`). Null = any model.
        modelPattern: body.modelPattern,
        createdBy: actor.userId,
      }, trx);
      templateId = num((tpl as unknown as { id: number }).id);
    } catch (err) {
      if ((err as { code?: string }).code === '23505') {
        throw new AppError(409, `A ${row.brand} template named "${body.name}" already exists`);
      }
      throw err;
    }
    let revisionId: number;
    try {
      const rev = await createDraft(tenantId, templateId, {
        body: String(row.body),
        varSchema,
        notes:
          `Proposé par l'extrapolateur (extrapolation #${row.run_id}, ${row.label}) et approuvé. ` +
          'Brouillon : à relire, puis publier depuis Modèles. Les secrets se saisissent dans le coffre ; ' +
          "les valeurs calculées viennent de la politique d'allocation.",
        createdBy: actor.userId,
      }, trx);
      revisionId = num((rev as unknown as { id: number }).id);
    } catch (err) {
      throw new AppError(409, `The proposed body could not be saved as a draft: ${err instanceof Error ? err.message : String(err)}`);
    }

    const result: ExtrapolationApproveResult = {
      templateId, revisionId, valuesWritten: 0, valuesAlreadySet: 0, conflicts: [], skipped: 0,
      unmatchedMembers: 0,
    };
    if (body.modelPattern !== null) {
      // The proposal's routers the pattern does not match — a model never
      // recorded on the device (modelMatches(pattern, null) is false) above
      // all: the template would not apply to them once assigned.
      const members = (await trx('extrapolation_site_results as r')
        .leftJoin('devices as d', function joinDevice() {
          this.on('d.id', '=', 'r.device_id').andOn('d.tenant_id', '=', 'r.tenant_id');
        })
        .where({ 'r.proposal_id': proposalId, 'r.tenant_id': tenantId })
        .select('d.model')) as Array<{ model: string | null }>;
      result.unmatchedMembers = members.filter((m) => !modelMatches(body.modelPattern, m.model ?? null)).length;
    }
    if (body.writeValues) {
      const variables = json<ExtrapolatedVariable[]>(row.variables, []);
      await writeValues(trx, tenantId, variables, actor, result);
    }

    await trx('extrapolation_proposals').where({ id: proposalId, tenant_id: tenantId }).update({
      status: 'approved',
      template_id: templateId,
      template_revision_id: revisionId,
      decided_by: actor.userId,
      decided_at: trx.fn.now(),
      decision_note: body.description,
      updated_at: trx.fn.now(),
    });
    await appendAudit({
      tenantId,
      actorType: 'user',
      actorId: actor.userId,
      actorName: actor.username,
      action: 'extrapolation.approved',
      entityType: 'extrapolation_proposal',
      entityId: proposalId,
      after: {
        templateId, revisionId, name: body.name, modelPattern: body.modelPattern,
        valuesWritten: result.valuesWritten, valuesAlreadySet: result.valuesAlreadySet,
        conflicts: result.conflicts.length, skipped: result.skipped, unmatchedMembers: result.unmatchedMembers,
      },
    }, trx);
    return result;
  });
}

/** The tenant default and the site values of every non-secret, stored-level
 *  variable. Never a secret, never a computed value. */
async function writeValues(
  trx: Knex.Transaction,
  tenantId: number,
  variables: readonly ExtrapolatedVariable[],
  actor: Actor,
  result: ExtrapolationApproveResult,
): Promise<void> {
  const wanted: Array<{ scope: 'tenant' | 'site'; siteId: number | null; key: string; value: string | boolean }> = [];
  // A site deleted or moved to another tenant since the run gets nothing: a
  // site-scoped row has no foreign key, and an orphan would wait for whoever
  // reuses the id.
  const siteIds = new Set(variables.flatMap((v) => v.siteValues.map((sv) => sv.siteId))
    .filter((x): x is number => x !== null));
  const liveSites = new Set<number>();
  const ids = [...siteIds];
  for (let i = 0; i < ids.length; i += 500) {
    const rows = (await trx('sites').where('tenant_id', tenantId).whereIn('id', ids.slice(i, i + 500)).select('id')) as Array<{ id: number }>;
    for (const r of rows) liveSites.add(num(r.id));
  }
  for (const v of variables) {
    if (v.secret || v.level === 'computed' || v.level === 'instance' || v.kind === 'existing') continue;
    const typed = (x: string): string | boolean => (v.type === 'boolean' ? x === 'true' : x);
    if ((v.kind === 'default_exceptions' || v.kind === 'presence') && v.defaultValue !== null) {
      wanted.push({ scope: 'tenant', siteId: null, key: v.name, value: v.defaultValue });
    }
    for (const sv of v.siteValues) {
      if (sv.siteId === null || !liveSites.has(sv.siteId)) { result.skipped++; continue; }
      if (v.kind === 'site' && sv.value === '' && v.defaultValue === '') continue;
      wanted.push({ scope: 'site', siteId: sv.siteId, key: v.name, value: typed(sv.value) });
    }
  }
  for (const w of wanted) {
    const existing = await trx('config_variables')
      .where({ tenant_id: tenantId, scope: w.scope, key: w.key })
      .modify((q) => { if (w.siteId === null) q.whereNull('scope_id'); else q.where('scope_id', w.siteId); })
      .first('value', 'is_secret');
    if (existing) {
      const same = !existing.is_secret && JSON.stringify(json(existing.value, null)) === JSON.stringify(w.value);
      if (same) result.valuesAlreadySet++;
      else result.conflicts.push({ scope: w.scope, siteId: w.siteId, key: w.key });
      continue;
    }
    await variableResolver._write(trx, tenantId, w.scope, w.siteId, w.key, w.value, false, {
      description: 'Valeur proposée par l\'extrapolateur et approuvée.',
      updatedBy: actor.userId,
    });
    result.valuesWritten++;
  }
}

export async function rejectProposal(
  tenantId: number,
  proposalId: number,
  rawBody: unknown,
  actor: Actor,
): Promise<ExtrapolationProposalSummary> {
  const parsedBody = ExtrapolationRejectBody.safeParse(rawBody ?? {});
  if (!parsedBody.success) throw new AppError(400, 'A rejection needs a reason (note)');
  return db.transaction(async (trx) => {
    const row = await trx('extrapolation_proposals')
      .where({ id: proposalId, tenant_id: tenantId })
      .forUpdate()
      .first('status');
    if (!row) throw new AppError(404, 'Extrapolation proposal not found');
    if (row.status !== 'proposed') throw new AppError(409, `This proposal is already ${row.status}`);
    const [updated] = await trx('extrapolation_proposals')
      .where({ id: proposalId, tenant_id: tenantId })
      .update({
        status: 'rejected',
        decided_by: actor.userId,
        decided_at: trx.fn.now(),
        decision_note: parsedBody.data.note,
        updated_at: trx.fn.now(),
      })
      .returning('*');
    await appendAudit({
      tenantId,
      actorType: 'user',
      actorId: actor.userId,
      actorName: actor.username,
      action: 'extrapolation.rejected',
      entityType: 'extrapolation_proposal',
      entityId: proposalId,
      after: { note: parsedBody.data.note },
    }, trx);
    return toSummary(updated);
  });
}

// ============================================================================
// Readiness — which of the client's routers the extrapolator can read
// ============================================================================

/** A snapshot older than this is not mined (BaselineParams' default
 *  `maxSnapshotAgeDays`): the router counts as unusable. */
const READINESS_MAX_AGE_DAYS = 365;
/** Usable, but not re-read for this long: counted as stale per model. */
const READINESS_STALE_DAYS = 30;

interface ReadinessRow {
  id: number;
  name: string;
  model: string | null;
  status: string;
  family: string | null;
  site_code: string | null;
  last_seen_at: Date | null;
  has_raw: boolean | null;
  export_model: string | null;
  has_ssh: boolean;
  error_reason: string | null;
  failed_at: Date | null;
}

/**
 * Per router MODEL, how many of the client's MikroTik routers (concentrators
 * excluded) the extrapolator can read — a snapshot no older than a year with
 * its raw export kept — and, for every other router, the FIRST reason in
 * `EXTRAPOLATION_BLOCKED_REASONS` order: not active, a family the collector
 * does not read, no SSH channel, no snapshot (with the last scheduled
 * collection's error), no raw export. A router with a usable snapshot counts
 * as usable whatever its state today: that is what the miner reads.
 *
 * `scope` (a team-scoped user's device ids, or null for the whole tenant)
 * narrows the rows. One query: the newest snapshot and the last failed
 * scheduled collection are LATERAL lookups; no jsonb `?` operator anywhere
 * (knex would read it as a binding).
 */
export async function getReadiness(
  tenantId: number,
  scope: number[] | null,
): Promise<Omit<ExtrapolationReadiness, 'collect'>> {
  const q = db('devices as d')
    .leftJoin('sites as s', function joinSite() {
      this.on('s.id', '=', 'd.site_id').andOn('s.tenant_id', '=', 'd.tenant_id');
    })
    .joinRaw(
      'LEFT JOIN LATERAL (SELECT cs.last_seen_at, (cs.raw_gz IS NOT NULL) AS has_raw, '
        + "cs.ncm #>> '{device,model}' AS export_model FROM config_snapshots cs "
        + 'WHERE cs.device_id = d.id ORDER BY cs.last_seen_at DESC, cs.id DESC LIMIT 1) snap ON true',
    )
    .joinRaw(
      'LEFT JOIN LATERAL (SELECT dr.error_reason, dr.started_at FROM drift_runs dr '
        + "WHERE dr.device_id = d.id AND dr.cause = 'scheduled' AND dr.snapshot_id IS NULL "
        + "AND dr.status IN ('unreachable', 'error') ORDER BY dr.started_at DESC, dr.id DESC LIMIT 1) fail ON true",
    )
    .where('d.tenant_id', tenantId)
    .where('d.brand', 'mikrotik')
    .whereNot('d.role', 'concentrator')
    .orderBy('d.id', 'asc')
    .select(
      'd.id', 'd.name', 'd.model', 'd.status', 'd.family', 's.code as site_code',
      'snap.last_seen_at', 'snap.has_raw', 'snap.export_model',
      'fail.error_reason', 'fail.started_at as failed_at',
      db.raw(
        'EXISTS (SELECT 1 FROM device_transports t WHERE t.device_id = d.id '
          + "AND t.transport = 'ssh' AND t.enabled = true AND t.host IS NOT NULL "
          + 'AND t.username IS NOT NULL) AS has_ssh',
      ),
    );
  if (scope !== null) q.whereIn('d.id', scope.length > 0 ? scope : [0]);
  const rows = (await q) as ReadinessRow[];

  const nowMs = Date.now();
  const maxAgeMs = READINESS_MAX_AGE_DAYS * 86_400_000;
  const staleMs = READINESS_STALE_DAYS * 86_400_000;
  const collectable = new Set<string>(COLLECTABLE_FAMILIES as readonly string[]);

  const judged = rows.map((r) => {
    const seenAt = r.last_seen_at ? new Date(r.last_seen_at) : null;
    const fresh = seenAt !== null && nowMs - seenAt.getTime() <= maxAgeMs;
    const usable = fresh && r.has_raw === true;
    let reason: ExtrapolationBlockedReason | null = null;
    if (!usable) {
      if (r.status !== 'active') reason = 'not_active';
      else if (!r.family || !collectable.has(r.family)) reason = 'not_collectable';
      else if (r.has_ssh !== true) reason = 'no_ssh';
      else if (seenAt === null) reason = 'no_snapshot';
      else reason = 'no_raw_export';
    }
    return {
      r,
      seenAt,
      usable,
      stale: usable && nowMs - (seenAt as Date).getTime() > staleMs,
      reason,
      model: modelKeyOf(r.model, r.export_model),
    };
  });

  const models = groupByModel(judged, (j) => j.model).map((g) => {
    const usableRows = g.items.filter((j) => j.usable);
    const times = usableRows.map((j) => (j.seenAt as Date).getTime());
    return {
      model: g.key,
      label: g.label,
      devices: g.items.length,
      usable: usableRows.length,
      stale: g.items.filter((j) => j.stale).length,
      newestSnapshotAt: times.length > 0 ? new Date(Math.max(...times)).toISOString() : null,
      oldestSnapshotAt: times.length > 0 ? new Date(Math.min(...times)).toISOString() : null,
    };
  }).sort((a, b) => b.devices - a.devices || a.label.localeCompare(b.label));

  const blocked = judged
    .filter((j) => j.reason !== null)
    .map((j) => ({
      deviceId: num(j.r.id),
      deviceName: j.r.name,
      siteCode: j.r.site_code ?? null,
      model: j.model,
      reason: j.reason as ExtrapolationBlockedReason,
      // Why the scheduled collection gave nothing, when it said so.
      detail: j.reason === 'no_snapshot' || j.reason === 'no_raw_export' ? (j.r.error_reason ?? null) : null,
      lastFailedAt: j.r.failed_at ? new Date(j.r.failed_at).toISOString() : null,
    }));

  return {
    totals: {
      mikrotik: judged.length,
      usable: judged.filter((j) => j.usable).length,
      blocked: blocked.length,
    },
    models,
    blocked,
  };
}
