// ============================================================================
// ObliWAN — planner.service : diff(ncm_desired, ncm_observed) -> PlanOp[]
// ============================================================================
//
// THE PLANNER COMPILES PLANS. IT APPLIES NOTHING. There is no code path in this file, or
// reachable from it, that opens a socket to an equipment. Applying is the change queue's job.
//
// ┌─ THE THREE GUARANTEES THIS FILE OWES THE REST OF THE PRODUCT ────────────┐
// │                                                                          │
// │ 1. N3 — NO DELETION WITHOUT A COMPLETE COLLECTION.                       │
// │    `semanticDiff` gates `extra` on the DESIRED side being complete; it   │
// │    does NOT gate it on the OBSERVED side, because a diff report is a     │
// │    statement about two documents and an `extra` really is extra.         │
// │    A PLAN is different: it is an instruction to destroy something on a    │
// │    customer's router. So a `delete` op is emitted only when              │
// │    `observed.coverage[kind].state === 'complete'`. Anything else becomes │
// │    a `blocked` op naming the record that was NOT deleted and why.        │
// │    Without this, one truncated `/export` — a session timeout, a paged    │
// │    read cut short, a `/export` that hit its own line limit — compiles    │
// │    into a plan that empties a site's firewall. This is the single most   │
// │    important property of this file.                                      │
// │                                                                          │
// │ 2. `baseStateHash` — A PLAN IS A STATEMENT ABOUT ONE STATE OF THE WORLD. │
// │    The plan records the `ncm_hash` of the snapshot it was computed        │
// │    against. `assertPlanFresh()` refuses it the moment the device's       │
// │    latest STORED snapshot hashes differently. Somebody opened Winbox     │
// │    between compilation and approval, and a collection saw it? The plan   │
// │    is dead, and recompiling is the only way forward. A stale plan        │
// │    applied to a box somebody edited is how an operator deletes a rule    │
// │    they never saw. (No collection is taken before the write: an edit no  │
// │    collection has seen yet is invisible to this check.)                  │
// │                                                                          │
// │ 3. ORDER — CREATE BEFORE REFERENCING, DELETE AFTER DEREFERENCING.        │
// │    Ops carry `dependsOn` and are emitted in an order that satisfies it.  │
// └──────────────────────────────────────────────────────────────────────────┘
//
// ┌─ WHAT THIS FILE DOES NOT DECIDE ─────────────────────────────────────────┐
// │ `mgmtPathVerdict` is ALWAYS `'indeterminate'` here. The design says a    │
// │ verdict of `accept` requires proving the management path survives, which │
// │ needs the path guard's forwarding engine. `indeterminate` is the         │
// │ fail-closed value and this file is not allowed to invent the other one.  │
// │ `riskScoring.ts` marks the ops the guard must examine (`tunnelCritical`) │
// │ and stops there.                                                         │
// └──────────────────────────────────────────────────────────────────────────┘

import crypto from 'crypto';
import type { Knex } from 'knex';
import type {
  ApplyPlan, BlastRadius, NcmDiffFinding, NcmDiffReport, NcmDocument,
  NcmOrderedRule, NcmResource, NcmResourceKind, PlanOp, PlanOpKind, PlanSource,
  RiskLevel, Selector,
} from '@obliwan/shared';
import {
  NCM_RESOURCE_KINDS, ORDERED_RESOURCE_KINDS, RESOURCE_KIND_TO_COLLECTION,
  coverageOf, planRisk, upgradeNcm,
} from '@obliwan/shared';
import { db } from '../../db';
import { topoSort, findCycles, CycleError } from '../../utils/topoSort';
import { semanticDiff } from '../drift/semanticDiff';
import { latestDocument } from '../config/snapshot.service';
import {
  renderRevisionForDevice, loadDevice,
  type RenderOptions, type RenderResultRecord, type DeviceRow,
} from '../template/render.service';
import {
  buildMgmtPathFacts, scoreOp, classifyResource,
  type MgmtPathFacts, type RiskAssessment,
} from './riskScoring';
import {
  buildUplinkFacts, uplinkViolationsForOp, uplinkRefusalSentence, UPLINK_BLOCK_REASON,
} from './uplinkGuard';
import { LEARNING_REFUSAL_KIND, learningRefusalMessage, learningStateOf } from '../learning/guard';

// ============================================================================
// Constants
// ============================================================================

/**
 * How long a compiled plan may sit before it must be recompiled.
 *
 * A plan is perishable for the same reason `baseStateHash` exists: it describes
 * a world. Thirty minutes is long enough for a four-eyes approval and short
 * enough that "the plan I approved" and "the box as it is" have not had time to
 * become two different things through anything other than an edit — which
 * `baseStateHash` catches anyway. The expiry is the belt; the hash is the
 * braces, and it is the braces that carry the load.
 */
export const PLAN_TTL_MS = 30 * 60 * 1000;

/** Every plan compiled here comes from a template. `intent`, `refactor`
 *  and `restore` arrive later and reuse the same compiler. */
const DEFAULT_SOURCE: PlanSource = 'template';

// ============================================================================
// Errors
// ============================================================================

export class PlanCompilationError extends Error {
  constructor(message: string, readonly reason: string) {
    super(message);
    this.name = 'PlanCompilationError';
  }
}

/**
 * The refusal of guarantee 2. Carries both hashes so the operator sees that the
 * world moved, and the client can offer "recompile" rather than "retry".
 */
export class StalePlanError extends Error {
  constructor(
    readonly deviceId: number,
    readonly expected: string,
    readonly actual: string | null,
  ) {
    super(
      actual === null
        ? `The plan for device #${deviceId} was computed against a snapshot that no longer ` +
          'exists. Recompile it.'
        : `The plan for device #${deviceId} is STALE: it was computed against the device state ` +
          `${expected.slice(0, 12)}… and the device is now at ${actual.slice(0, 12)}…. ` +
          'Somebody changed the configuration since the plan was compiled — recompile it ' +
          'and review the new operations before approving.',
    );
    this.name = 'StalePlanError';
  }
}

export class PlanExpiredError extends Error {
  constructor(readonly deviceId: number, readonly expiresAt: string) {
    super(
      `The plan for device #${deviceId} expired at ${expiresAt}. A plan is a statement about ` +
        'one state of the world; past its expiry it must be recompiled, not approved.',
    );
    this.name = 'PlanExpiredError';
  }
}

// ============================================================================
// Result types
// ============================================================================

export interface PlanCompilation {
  plan: ApplyPlan;
  /** Enriched, non-persisted view for the PlanPage: signals per op and the
   *  reasons behind every suppression. Never fed back into `assertPlanFresh` —
   *  the plan itself is the contract. */
  detail: {
    deviceName: string;
    renderId: string | null;
    revisionId: string;
    revision: number;
    templateId: string | null;
    observedSnapshotId: string;
    observedCapturedAt: string;
    /** Resource kinds the template claims. Everything else was not compared. */
    claimedKinds: NcmResourceKind[];
    diff: NcmDiffReport;
    /** Per-op risk signals, indexed by `seq`. */
    signals: Record<number, RiskAssessment>;
    /** Kinds where a deletion was refused by N3, with the observed coverage. */
    deletionsBlocked: { resource: NcmResourceKind; coverage: string; count: number }[];
    warnings: string[];
  };
}

export interface CompileOptions {
  /** Reuse an explicit revision instead of the assignment resolution. */
  revisionId?: string | number | null;
  /** Persist the `config_renders` row. Default TRUE — a plan whose desired
   *  state has no row is a plan with no provenance. */
  persistRender?: boolean;
  /** Compare against a specific snapshot instead of the latest. */
  snapshotId?: string | null;
  source?: PlanSource;
  createdBy?: number | null;
  trx?: Knex | Knex.Transaction;
}

// ============================================================================
// Compilation
// ============================================================================

/**
 * Compile a plan for ONE device.
 *
 * Reads: the device (tenant-scoped), the applicable template revision, the
 * variables, the latest snapshot. Writes: at most one `config_renders` row.
 * Touches no equipment.
 */
export async function compilePlan(
  tenantId: number,
  deviceId: number,
  opts: CompileOptions = {},
): Promise<PlanCompilation> {
  const q = opts.trx ?? db;
  const warnings: string[] = [];

  const device = await loadDevice(tenantId, deviceId, q);

  // ── 0. Learning mode: no template-driven plan for a router in learning ───
  // One check, here, covers POST /plan/devices/:id, the fleet compile, a
  // rollout's composition (listed as a failure) and its waves. The
  // break-risk report (learning/breakRisk.service.ts) is the read-only answer
  // to "what would this template do here" while the router is learning.
  const learning = await learningStateOf(deviceId, q);
  if (learning) {
    throw new PlanCompilationError(learningRefusalMessage(device.name, learning.since), LEARNING_REFUSAL_KIND);
  }

  // ── 1. The DESIRED side ──────────────────────────────────────────────────
  const renderOpts: RenderOptions = {
    persist: opts.persistRender !== false,
    revisionId: opts.revisionId ?? null,
    createdBy: opts.createdBy ?? null,
    trx: q,
  };
  const render = await renderRevisionForDevice(tenantId, deviceId, renderOpts);
  if (render.status !== 'ok' || !render.ncmDesired) {
    throw new PlanCompilationError(
      `Cannot compile a plan for device #${deviceId}: the template render failed. ` +
        `${render.errorMessage ?? 'no reason recorded'}`,
      render.errorKind ?? 'render_failed',
    );
  }
  warnings.push(...render.warnings);

  // ── 2. The OBSERVED side ─────────────────────────────────────────────────
  const observedRow = await loadObserved(tenantId, deviceId, opts.snapshotId ?? null, q);
  if (!observedRow) {
    throw new PlanCompilationError(
      `Device #${deviceId} has no configuration snapshot. A plan compiled against no observed ` +
        'state would propose to create the entire configuration, including what is already ' +
        'there. Collect the configuration first.',
      'no_snapshot',
    );
  }
  const observed = observedRow.doc;

  // ── 3 + 4. The semantic diff, then findings -> ops ───────────────────────
  //
  // Both are `buildPlanOps`, the pure half of this function: the op stream
  // `plan/testing/planner.verify.ts` proves without a database is the op
  // stream a push freezes, because there is no second path to it.
  const planned = buildPlanOps({
    desired: render.ncmDesired,
    observed,
    claimedKinds: render.claimedKinds,
    deviceId,
    tunnelIp: device.tunnel_ip,
  });
  // `baseStateHash` is the STORED `ncm_hash` of the snapshot row the plan was
  // compiled against — the contract `ApplyPlan` states — and NOT what
  // `semanticDiff` reports, which is `ncmHash()` of the document AFTER
  // `upgradeNcm()` (a pure function sees no row). The two differ on every row
  // stored at an older `ncmVersion` (the upgrader re-stamps the version, and
  // the version is inside the hashing scope), so a recomputed hash names no row
  // in `config_snapshots`, disagrees with the `base_state_hash` a plan-less job
  // records for the same unchanged device, and moves under a queued job the day
  // a build adds an upgrader. `checkPlanFreshness` compares against the same
  // column; one domain on both sides is the whole guarantee. The diff report
  // returned beside the plan is restamped with it too, so one compile response
  // never carries two different "base state" hashes.
  const baseStateHash = observedRow.ncmHash;
  const diff: NcmDiffReport = { ...planned.diff, baseStateHash };

  const built = planned;
  warnings.push(...built.warnings);

  const ops = built.ops;
  const risk = planRisk(ops);

  const plan: ApplyPlan = {
    planUuid: crypto.randomUUID(),
    deviceId,
    source: opts.source ?? DEFAULT_SOURCE,
    // The model version the OPS are expressed in — the observed document AFTER
    // `upgradeNcm()` — not the version the base snapshot row was stored at:
    // `baseStateHash` may name a v1 row while the ops are v2.
    ncmVersion: observed.ncmVersion,
    semKeyGeneration: observed.semKeyGeneration,
    baseStateHash,
    ops,
    riskLevel: risk,
    // The design. The planner has no forwarding engine, therefore it may not claim `accept`.
    mgmtPathVerdict: 'indeterminate',
    blastRadius: buildBlastRadius(device, ops, built.signals),
    expiresAt: new Date(Date.now() + PLAN_TTL_MS).toISOString(),
    orderConverges: built.orderConverges,
  };

  return {
    plan,
    detail: {
      deviceName: device.name,
      renderId: render.renderId,
      revisionId: render.revisionId,
      revision: render.revision,
      templateId: render.templateId,
      observedSnapshotId: observedRow.id,
      observedCapturedAt: observed.capturedAt,
      claimedKinds: render.claimedKinds,
      diff,
      signals: built.signals,
      deletionsBlocked: built.deletionsBlocked,
      warnings,
    },
  };
}

/**
 * Compile a plan for several devices — the wave-rollout preview, and the
 * milestone's own recipe (a): one template on ten devices produces ten plans,
 * each with ITS device's variables.
 *
 * Sequential on purpose. Each compilation renders in a worker with a 5 s
 * ceiling and reads two documents; running 300 of them concurrently would put
 * 300 workers on the API host. `p-limit` is already a dependency and belongs
 * here the day the fleet numbers make it necessary — but the correct
 * concurrency is a measurement, not a guess, and this milestone has not made
 * that measurement.
 */
export interface FleetCompilation {
  plans: PlanCompilation[];
  failures: { deviceId: number; deviceName: string | null; reason: string; message: string }[];
}

export async function compileForDevices(
  tenantId: number,
  deviceIds: readonly number[],
  opts: CompileOptions = {},
): Promise<FleetCompilation> {
  const plans: PlanCompilation[] = [];
  const failures: FleetCompilation['failures'] = [];

  for (const deviceId of deviceIds) {
    try {
      plans.push(await compilePlan(tenantId, deviceId, opts));
    } catch (err) {
      const name = await deviceNameOf(tenantId, deviceId, opts.trx ?? db);
      failures.push({
        deviceId,
        deviceName: name,
        reason: err instanceof PlanCompilationError ? err.reason : (err as Error).name,
        message: err instanceof Error ? err.message : String(err),
      });
    }
  }
  return { plans, failures };
}

async function deviceNameOf(
  tenantId: number,
  deviceId: number,
  q: Knex | Knex.Transaction,
): Promise<string | null> {
  const row = (await q('devices').where({ id: deviceId, tenant_id: tenantId }).first('name')) as
    | { name: string }
    | undefined;
  return row?.name ?? null;
}

async function loadObserved(
  tenantId: number,
  deviceId: number,
  snapshotId: string | null,
  q: Knex | Knex.Transaction,
): Promise<{ id: string; doc: NcmDocument; ncmHash: string } | null> {
  if (snapshotId) {
    // Tenant scoping goes THROUGH `devices`: `config_snapshots` has no tenant
    // column, exactly like the ten `ncm_*` tables and the SNMP series.
    const row = (await q('config_snapshots as s')
      .join('devices as d', 'd.id', 's.device_id')
      .where('s.id', snapshotId)
      .where('d.tenant_id', tenantId)
      .where('s.device_id', deviceId)
      .first('s.id as id', 's.ncm as ncm', 's.ncm_hash as ncm_hash')) as
      | { id: string; ncm: unknown; ncm_hash: string }
      | undefined;
    if (!row) return null;
    return { id: String(row.id), doc: upgradeNcm(row.ncm), ncmHash: row.ncm_hash };
  }
  const latest = await latestDocument(deviceId);
  return latest ? { id: latest.id, doc: latest.doc, ncmHash: latest.ncmHash } : null;
}

// ============================================================================
// Freshness — guarantee 2
// ============================================================================

export interface FreshnessVerdict {
  fresh: boolean;
  expired: boolean;
  deviceId: number;
  baseStateHash: string;
  currentStateHash: string | null;
  expiresAt: string;
  reason: string | null;
}

/**
 * Is this plan still a statement about the latest STORED snapshot of the
 * device?
 *
 * Non-throwing sibling of `assertPlanFresh`, for a screen that wants to show a
 * banner rather than an error. Both read the same two facts and there is no
 * third implementation anywhere. The change executor calls `assertPlanFresh` at enqueue and
 * again at the job's `guard` step, and both compare against the most recently
 * OBSERVED snapshot (`latestDocument()`): no collection is taken before the
 * write, so a box somebody edited since the last collection still passes
 * here. Freshness is exactly as fresh as the last collection.
 */
export async function checkPlanFreshness(
  tenantId: number,
  plan: Pick<ApplyPlan, 'deviceId' | 'baseStateHash' | 'expiresAt'>,
  q: Knex | Knex.Transaction = db,
): Promise<FreshnessVerdict> {
  // Tenant scoping first: a plan carrying another tenant's deviceId must not
  // even reveal whether that device has a snapshot.
  await loadDevice(tenantId, plan.deviceId, q);

  // The STORED `ncm_hash` of the latest row, never `ncmHash(latest.doc)`:
  // `latest.doc` has been through `upgradeNcm()`, and a row stored at an older
  // `ncmVersion` hashes differently once re-stamped. Recomputing declared a
  // plan carrying that row's `ncm_hash` — what `ApplyPlan` says it carries —
  // STALE although no new snapshot existed and nobody had touched the device.
  // See `compilePlan`, which records the same column.
  const latest = await latestDocument(plan.deviceId);
  const current = latest ? latest.ncmHash : null;
  const expired = Date.parse(plan.expiresAt) <= Date.now();
  const fresh = current !== null && current === plan.baseStateHash && !expired;

  let reason: string | null = null;
  if (current === null) reason = 'the device no longer has a configuration snapshot';
  else if (current !== plan.baseStateHash) reason = 'the device configuration changed since the plan was compiled';
  else if (expired) reason = 'the plan expired';

  return {
    fresh,
    expired,
    deviceId: plan.deviceId,
    baseStateHash: plan.baseStateHash,
    currentStateHash: current,
    expiresAt: plan.expiresAt,
    reason,
  };
}

/** Throwing form. THE function the change executor must call before touching an equipment. */
export async function assertPlanFresh(
  tenantId: number,
  plan: Pick<ApplyPlan, 'deviceId' | 'baseStateHash' | 'expiresAt'>,
  q: Knex | Knex.Transaction = db,
): Promise<void> {
  const verdict = await checkPlanFreshness(tenantId, plan, q);
  if (verdict.currentStateHash !== plan.baseStateHash) {
    throw new StalePlanError(plan.deviceId, plan.baseStateHash, verdict.currentStateHash);
  }
  if (verdict.expired) throw new PlanExpiredError(plan.deviceId, plan.expiresAt);
}

// ============================================================================
// Findings -> ops
// ============================================================================

export interface PlanOpsInput {
  desired: NcmDocument;
  observed: NcmDocument;
  /** Resource kinds the template claims (the design's diff scope). */
  claimedKinds: readonly NcmResourceKind[];
  deviceId: number;
  /** The address the platform dials the device on; feeds the management-path
   *  facts every op is scored against. */
  tunnelIp: string | null;
}

export interface PlanOpsResult {
  diff: NcmDiffReport;
  ops: PlanOp[];
  signals: Record<number, RiskAssessment>;
  deletionsBlocked: { resource: NcmResourceKind; coverage: string; count: number }[];
  orderConverges: boolean;
  warnings: string[];
}

/**
 * Two documents in, ops out — the pure half of `compilePlan`, which calls it
 * and nothing else to get its ops. No database, no template engine, no socket.
 *
 * `claimedKinds` is what makes `managed_only` usable for a plan: inside a
 * section the template claims, an observed record we did not write is still
 * `extra`. Outside it, it is inventoried and left alone (the design's diff scope).
 */
export function buildPlanOps(input: PlanOpsInput): PlanOpsResult {
  const claimed = new Set(input.claimedKinds);
  // The semantic diff — reused, never re-implemented.
  const diff = semanticDiff(input.desired, input.observed, {
    scope: 'managed_only',
    claimedKinds: claimed,
    fuzzy: true,
  });
  const facts = buildMgmtPathFacts(input.observed, {
    deviceId: input.deviceId,
    tunnelIp: input.tunnelIp,
  });
  return { diff, ...buildOps(input.desired, input.observed, diff, facts, claimed) };
}

interface BuildResult {
  ops: PlanOp[];
  signals: Record<number, RiskAssessment>;
  deletionsBlocked: { resource: NcmResourceKind; coverage: string; count: number }[];
  orderConverges: boolean;
  warnings: string[];
}

/** An op before it has a `seq`. `provides` / `requires` are the dependency
 *  edges; `orderGroup` is the chain a `move` belongs to. */
interface DraftOp {
  kind: PlanOpKind;
  resource: NcmResourceKind;
  semKey: string;
  before: NcmResource | null;
  after: NcmResource | null;
  fields: string[];
  chain: string | null;
  targetIndex: number | null;
  blockedReason: PlanOp['blockedReason'];
  finding: NcmDiffFinding | null;
  coverageDegraded: boolean;
  /** Tokens this op makes available (an interface name, a custom chain). */
  provides: string[];
  /** Tokens this op needs to already exist. */
  requires: string[];
  /** Phase, which is the coarse ordering. See `PHASES`. */
  phase: number;
  /** Stable tiebreaker inside a phase, before the graph is applied. */
  rank: number;
  /** Drafts this one must run after, beyond what `requires` can express — the
   *  delete half of a replacement, for its create half. Becomes `dependsOn`. */
  follows?: DraftOp[];
  /** Sentence put in front of the risk reason (or, on a `blocked` op, in place
   *  of the generic refusal) when the op needs explaining beyond its kind. */
  note?: string;
}

/**
 * The phases, and why they are in this order.
 *
 *  0 create  — nothing may reference a resource that does not exist yet.
 *  1 update / enable / disable — an update that REMOVES a reference has to run
 *              before the referenced resource is deleted, which is why updates
 *              sit between creates and deletes and not after them.
 *              A REPLACEMENT (a firewall or NAT rule whose match or marker
 *              changed, emitted as a delete plus a create — see
 *              `IDENTITY_FIELD_HEADS`) runs here too, in the slot its update
 *              would have had, as two adjacent ops: delete first, then create.
 *              Its create therefore runs AFTER every phase-0 create.
 *  2 delete  — reverse dependency order inside the phase: a rule that names an
 *              interface is deleted before the interface.
 *  3 move    — computed against the list as it will be AFTER creates and
 *              deletes, appended in the order those ops run, so the simulated
 *              indices are the real ones.
 *  4 verify  — the chain obtained equals the chain desired.
 *  5 blocked — information, not instructions. Last so `seq` order stays
 *              executable from 0 to the first blocked op.
 */
const PHASE_CREATE = 0;
const PHASE_UPDATE = 1;
const PHASE_DELETE = 2;
const PHASE_MOVE = 3;
const PHASE_VERIFY = 4;
const PHASE_BLOCKED = 5;

/**
 * Cross-kind creation layers.
 *
 * An interface is created before a VLAN on it, before a route through it,
 * before a firewall rule that names it. This is a FIXED layering rather than a
 * computed graph because the reference direction between NCM resource kinds is
 * a property of the model, not of a document — and a computed graph would
 * re-derive the same five numbers on every plan while being able to get them
 * wrong.
 */
const CREATE_LAYER: Readonly<Record<NcmResourceKind, number>> = {
  interface: 0,
  dhcpClient: 0,
  vlan: 1,
  ipsecPeer: 2,
  route: 3,
  dhcpScope: 3,
  qosRule: 3,
  firewallRule: 4,
  natRule: 4,
  localUser: 5,
  service: 5,
};

function asResource(v: unknown): NcmResource | null {
  return v && typeof v === 'object' ? (v as NcmResource) : null;
}

/** Tokens a resource makes available to others. */
function providesOf(r: NcmResource | null): string[] {
  if (!r) return [];
  switch (r.kind) {
    case 'interface': return [`iface:${r.name}`];
    case 'vlan': return r.name ? [`iface:${r.name}`] : [];
    case 'firewallRule':
      return r.chain === 'custom' && r.chainName ? [`chain:${r.chainName}`] : [];
    case 'natRule':
      return r.chain === 'custom' && r.chainName ? [`natchain:${r.chainName}`] : [];
    default: return [];
  }
}

/** Interface tokens named by a selector. `ifaceList:` is NOT a dependency: an
 *  interface list is not modelled as a resource, so there is nothing to create
 *  and pretending otherwise would produce an unsatisfiable edge. */
function ifaceTokens(sel: Selector | null | undefined): string[] {
  if (!sel) return [];
  const out: string[] = [];
  for (const atom of sel) {
    if (atom.startsWith('iface:')) out.push(atom);
  }
  return out;
}

/** Tokens a resource needs before it can exist. */
function requiresOf(r: NcmResource | null): string[] {
  if (!r) return [];
  const out = new Set<string>();
  switch (r.kind) {
    case 'interface':
      if (r.parent) out.add(`iface:${r.parent}`);
      break;
    case 'vlan':
      if (r.parent) out.add(`iface:${r.parent}`);
      for (const p of r.taggedPorts) out.add(`iface:${p}`);
      for (const p of r.untaggedPorts) out.add(`iface:${p}`);
      break;
    case 'route':
      if (r.gateway?.startsWith('iface:')) out.add(r.gateway);
      break;
    case 'dhcpScope':
      if (r.onInterface.startsWith('iface:')) out.add(r.onInterface);
      break;
    case 'firewallRule':
      for (const t of ifaceTokens(r.match.inInterface)) out.add(t);
      for (const t of ifaceTokens(r.match.outInterface)) out.add(t);
      // A `jump` needs its target chain to exist. On RouterOS a chain exists
      // because a rule carries it, so this edge is "the target chain's rules
      // first" — which is exactly what `provides` above expresses.
      if (r.action === 'jump' && r.jumpTarget) out.add(`chain:${r.jumpTarget}`);
      break;
    case 'natRule':
      for (const t of ifaceTokens(r.match.inInterface)) out.add(t);
      for (const t of ifaceTokens(r.match.outInterface)) out.add(t);
      break;
    case 'qosRule':
      for (const t of ifaceTokens(r.target)) out.add(t);
      if (r.parent) out.add(`iface:${r.parent}`);
      break;
    default:
      break;
  }
  return [...out];
}

function chainOf(r: NcmResource | null): string | null {
  if (!r) return null;
  if (r.kind === 'firewallRule' || r.kind === 'natRule') {
    return r.chainName ? `${r.chain}:${r.chainName}` : r.chain;
  }
  if (r.kind === 'qosRule') return r.queueClass;
  return null;
}

/**
 * ┌─ N1: WHEN A `changed` IS NOT AN EDIT ────────────────────────────────────┐
 * │ A firewall or NAT rule has TWO identities, and a `changed` that touches   │
 * │ either one is not an edit:                                               │
 * │                                                                          │
 * │  - what it SELECTS: its chain and its match (`shared/src/ncm/keys.ts`,   │
 * │    N1). That is the whole semKey of an unmarked rule (chain + matchHash).│
 * │  - for a marker rule, its SLUG: the semKey is chain + slug, and the      │
 * │    `obliwan:<slug>` comment is the only thing the renderer can locate it  │
 * │    by on the box (`locateOrderedRule`, by exact comment equality).       │
 * │                                                                          │
 * │ The diff nonetheless keeps such a rule paired through either change, on  │
 * │ purpose: by its marker (phase 1 — the semKey does not move when the match │
 * │ does), or by the fuzzy phase 3, which pairs what the exact phases left    │
 * │ over — rules whose predicate moved, or two DIFFERENT markers on rules     │
 * │ that look alike. Either way it hands this file ONE `changed` — when some  │
 * │ diffed field differs. When none does, a pairing across two markers       │
 * │ yields nothing at all; `buildMoveOps` refuses to order around it.        │
 * │                                                                          │
 * │ That `changed` must not become an `update`. A RouterOS `set` rewrites     │
 * │ only the properties it names, so an edited match would keep every         │
 * │ selector the new one drops; `renderUpdate` (drivers/mikrotik/render.ts)   │
 * │ refuses it by name, and `enqueueChangeJob` then refuses the whole plan as │
 * │ `plan_not_renderable`. Every template edit of an owned rule's source      │
 * │ address, port or protocol died there. And a pairing across two markers    │
 * │ lists no field for the marker at all (`diffFields` skips `managedSlug`,   │
 * │ and `comment` holds only the free text after it), so its `update` would   │
 * │ never write the template's marker; and `projectPlan`, which writes the    │
 * │ update's `after` (keyed by the TEMPLATE's marker) over the observed       │
 * │ record, could then not find that record for any later op on it.         │
 * │                                                                          │
 * │ So it becomes a REPLACEMENT: delete the observed rule, then create the    │
 * │ desired one, as two adjacent ops in the update phase. `add` appends to   │
 * │ the end of the chain; the order pass (`buildMoveOps`) simulates the chain │
 * │ in the order the ops RUN and moves whatever did not land in place.        │
 * │                                                                          │
 * │ DELETE FIRST, never create first. Both halves are located on the box by   │
 * │ their `obliwan:` comment, and a marker pairing whose comment text did not │
 * │ change gives both the SAME one: a `remove [find where comment=…]` issued  │
 * │ after the re-create would remove BOTH rules. `projectPlan` keys on semKey │
 * │ and fails the same way on every marker pairing: a create of a semKey     │
 * │ still present overwrites it, and the delete then takes it.               │
 * │                                                                          │
 * │ Not listed, deliberately: `qosRule` (a named queue is keyed and located   │
 * │ by its name, a different contract) and the natural-key kinds whose        │
 * │ renderer also asks for "a delete plus a create" (a route's dst/gateway,   │
 * │ an interface's type/parent, a DHCP scope's interface…). Those stay        │
 * │ `update`s and are refused BY NAME at enqueue; giving each one a           │
 * │ replacement is a decision about deleting that kind, made kind by kind.    │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
const IDENTITY_FIELD_HEADS: Readonly<Partial<Record<NcmResourceKind, readonly string[]>>> = {
  firewallRule: ['match', 'chain', 'chainName'],
  natRule: ['match', 'chain', 'chainName'],
};

/** The changed fields that are the record's identity, in diff order. */
function identityFieldsOf(kind: NcmResourceKind, fields: readonly string[]): string[] {
  const heads = IDENTITY_FIELD_HEADS[kind];
  if (!heads) return [];
  return fields.filter((f) => heads.includes(f.split('.')[0]));
}

/**
 * The marker change of a pairing, as `obliwan:<a> -> obliwan:<b>`, or null
 * when both sides carry the same one (or the kind is not listed above).
 *
 * Only the fuzzy phase can produce one: phase 1 pairs equal slugs, phase 2
 * equal semKeys, and a marker rule's semKey is chain + slug — so an unmarked
 * and a marked rule never share one either.
 */
function markerChangeOf(kind: NcmResourceKind, intent: NcmResource, actual: NcmResource): string | null {
  if (!IDENTITY_FIELD_HEADS[kind]) return null;
  const from = actual.managedSlug ?? null;
  const to = intent.managedSlug ?? null;
  if (from === to) return null;
  const show = (slug: string | null): string => (slug === null ? 'no marker' : `obliwan:${slug}`);
  return `${show(from)} -> ${show(to)}`;
}

/**
 * Kinds whose order the diff could not establish. One rule for both readers:
 * the move pass emits no `move` for them, and a replacement — whose create
 * APPENDS — is refused for them, because nothing would put the rule back.
 */
function orderSuppressedKinds(diff: NcmDiffReport): Map<NcmResourceKind, 'order_partial' | 'weak_keys'> {
  const out = new Map<NcmResourceKind, 'order_partial' | 'weak_keys'>();
  for (const s of diff.suppressed) {
    if (s.reason === 'order_partial' || s.reason === 'weak_keys') out.set(s.resource, s.reason);
  }
  return out;
}

/**
 * The record a later op finds on the box once `update` has run.
 *
 * A `move` and the `verify` after it locate their rule by what the box holds AT
 * THAT POINT of the plan — its `obliwan:` comment, on RouterOS. An update that
 * listed `comment` rewrote that comment, marker included, so a move carrying
 * the OBSERVED record would look for a comment that no longer exists, find
 * nothing, and fail the apply. Every field the update lists is the desired
 * value; the comment changes only when the update lists `comment`, and then
 * `renderUpdate` writes the desired marker in front of the new free text. That
 * marker is the observed one for every firewall and NAT update: a pairing
 * across two markers is a replacement (`markerChangeOf`), never an update. A
 * queue is located by its name, not by its comment.
 */
function onBoxAfterUpdate(update: DraftOp): NcmResource | null {
  const { before, after } = update;
  if (!before || !after) return before ?? after;
  if (update.fields.includes('comment')) return after;
  return {
    ...after,
    comment: before.comment,
    managedBy: before.managedBy,
    managedSlug: before.managedSlug,
  } as NcmResource;
}

function buildOps(
  desired: NcmDocument,
  observed: NcmDocument,
  diff: NcmDiffReport,
  facts: MgmtPathFacts,
  claimed: ReadonlySet<NcmResourceKind>,
): BuildResult {
  const drafts: DraftOp[] = [];
  const warnings: string[] = [];
  const deletionsBlocked = new Map<NcmResourceKind, { coverage: string; count: number }>();
  let rank = 0;

  const degradedKinds = new Set<NcmResourceKind>();
  for (const kind of NCM_RESOURCE_KINDS) {
    if (coverageOf(observed.coverage, kind).state !== 'complete') degradedKinds.add(kind);
  }
  const orderSuppressed = orderSuppressedKinds(diff);
  // Desired semKeys whose pairing was turned into a delete plus a create. The
  // move pass must NOT alias them onto the observed rule they were paired with:
  // that rule is gone, and the rule to place is the new one.
  const replacedIntentKeys = new Set<string>();

  // ── UPLINK PRESERVATION (operator rule, 2026-10-04) ─────────────────────
  //
  // On a router in production nothing the site's traffic leaves through is
  // removed by a plan: not the PPPoE client (ADSL / FTTH / FTTO), not its
  // membership of the WAN list, not the interface or the static default route
  // the uplink rides (`uplinkGuard.ts` says precisely which ops). Checked
  // FIRST, before the management-path veto and before N3, so the op is refused
  // under its own name: a PPPoE client is also a "tunnel-bearing" type for the path guard,
  // and an interface delete is also blocked by N3 on RouterOS — but neither of
  // those sentences tells the operator that the template is about to cut the
  // store off the internet. Facts come from the OBSERVED document: the
  // question is what runs on the box today.
  const uplinks = buildUplinkFacts(observed);
  const refuseUplink = (
    opKind: PlanOpKind,
    finding: NcmDiffFinding,
    before: NcmResource,
    after: NcmResource | null,
    degraded: boolean,
  ): boolean => {
    const fields = opKind === 'delete' ? [] : finding.fieldDiffs.map((f) => f.field);
    const violations = uplinkViolationsForOp(uplinks, {
      kind: opKind, resource: finding.resource, semKey: finding.semKey, before, after, fields,
    });
    if (violations.length === 0) return false;
    drafts.push({
      kind: 'blocked', resource: finding.resource, semKey: finding.semKey,
      before, after, fields,
      chain: chainOf(before), targetIndex: null,
      blockedReason: UPLINK_BLOCK_REASON,
      finding, coverageDegraded: degraded,
      provides: [], requires: [],
      phase: PHASE_BLOCKED, rank: rank++,
      note: uplinkRefusalSentence(violations),
    });
    return true;
  };

  for (const finding of diff.findings) {
    const kind = finding.resource;
    const intent = asResource(finding.intentValue);
    const actual = asResource(finding.actualValue);
    const degraded = degradedKinds.has(kind);

    switch (finding.kind) {
      case 'missing': {
        // Present in the desired state, absent from the device -> create it.
        if (!intent) break;
        drafts.push({
          kind: 'create', resource: kind, semKey: finding.semKey,
          before: null, after: intent, fields: [],
          chain: chainOf(intent), targetIndex: null, blockedReason: null,
          finding, coverageDegraded: degraded,
          provides: providesOf(intent), requires: requiresOf(intent),
          phase: PHASE_CREATE, rank: rank++,
        });
        break;
      }

      case 'extra': {
        // ── N3, GUARANTEE 1 ───────────────────────────────────────────────
        //
        // The device carries something the template does not. Removing it is
        // the correct instruction ONLY if we know we saw everything. If the
        // collection for this kind was partial, failed or unsupported, we do
        // not know that, and a delete compiled from an incomplete picture is
        // how a truncated export empties a firewall.
        if (!actual) break;

        if (refuseUplink('delete', finding, actual, null, degraded)) break;

        // ── THE MANAGEMENT-PATH VETO ─────────────────────────────────────
        //
        // `facts.tunnelInterfaces` is the set of interfaces the platform
        // actually reaches this box through — `l2tp-mgmt` and anything riding
        // it, a VLAN over the L2TP link included. Deleting one is not a change
        // that MIGHT break management; it is the removal of the only road.
        //
        // Recognised by TYPE, never by name (`isTunnelBearing`, riskScoring.ts
        // :178): a rule keyed on the string "l2tp-mgmt" would miss the site
        // where somebody called it "l2tp-mgmt2", which is precisely the site
        // where the mistake gets made.
        //
        // The path guard already REJECTS this — but a reject is a verdict, and a verdict
        // is overridable with CHANGE_APPROVE. Deleting the management tunnel
        // is not a decision a signature should be able to buy on a compiled
        // plan. Blocked at compilation, it is never presented as an option.
        const actualIfName =
          kind === 'interface' ? ((actual as { name?: string }).name ?? '') : '';
        if (actualIfName && facts.tunnelInterfaces.has(actualIfName)) {
          drafts.push({
            kind: 'blocked', resource: kind, semKey: finding.semKey,
            before: actual, after: null, fields: [],
            chain: chainOf(actual), targetIndex: null,
            blockedReason: 'mgmt_path_veto',
            finding, coverageDegraded: degraded,
            provides: [], requires: [],
            phase: PHASE_BLOCKED, rank: rank++,
          });
          break;
        }

        // ── THE IDENTITY VETO ────────────────────────────────────────────
        //
        // The path guard proves the PACKET arrives. It never proves an identity survives
        // to authenticate when it does: `FORWARDING_KINDS` is
        // interface/route/firewallRule/natRule/service, and `evaluateMgmtPath`
        // never reads `doc.resources.localUsers` at all. Its exclusion comment
        // is literally true — a local user cannot change the fate of a packet
        // already inside the tunnel — but the file's own header promises "can
        // the platform still reach this device?", and `reach` was quietly
        // defined as "a SYN gets an answer".
        //
        // So a template that claims `localUser` and does not list the account
        // ObliWAN logs in with compiles a `delete` for it, and the guard
        // returns ACCEPT: tunnel up, address held, service open, probes green.
        // Nothing downstream catches it either — `healthGate` measures
        // `pppUp`, `sysUpTime`, RTT and `ifOperStatus`, every one of them an
        // L3 presence signal. The box routes perfectly and nobody can log in.
        // On a brand with no on-device dead-man and no LTE, that is a truck.
        //
        // Until `checkManagementIdentity()` exists in the path guard, removing a local
        // user is not a decision a compiled plan may take on its own. Blocked
        // is INFORMATION, not a failure: the operator sees the account, the
        // reason, and does it by hand if it is really what they want.
        // Creating one is untouched — provisioning must keep working.
        if (kind === 'localUser') {
          drafts.push({
            kind: 'blocked', resource: kind, semKey: finding.semKey,
            before: actual, after: null, fields: [],
            chain: chainOf(actual), targetIndex: null,
            blockedReason: 'mgmt_path_veto',
            finding, coverageDegraded: degraded,
            provides: [], requires: [],
            phase: PHASE_BLOCKED, rank: rank++,
          });
          break;
        }

        const coverage = coverageOf(observed.coverage, kind);
        if (coverage.state !== 'complete') {
          const entry = deletionsBlocked.get(kind) ?? { coverage: coverage.state, count: 0 };
          entry.count += 1;
          deletionsBlocked.set(kind, entry);
          drafts.push({
            kind: 'blocked', resource: kind, semKey: finding.semKey,
            before: actual, after: null, fields: [],
            chain: chainOf(actual), targetIndex: null,
            blockedReason: 'coverage_incomplete',
            finding, coverageDegraded: true,
            provides: [], requires: [],
            phase: PHASE_BLOCKED, rank: rank++,
          });
          break;
        }
        drafts.push({
          kind: 'delete', resource: kind, semKey: finding.semKey,
          before: actual, after: null, fields: [],
          chain: chainOf(actual), targetIndex: null, blockedReason: null,
          finding, coverageDegraded: degraded,
          // A delete REMOVES the tokens it provided; the reverse ordering below
          // reads `provides` as "what disappears", which is why the same field
          // serves both directions.
          provides: providesOf(actual), requires: [],
          phase: PHASE_DELETE, rank: rank++,
        });
        break;
      }

      case 'changed': {
        if (!intent || !actual) break;

        // The op this change would become — the same rule as below, decided
        // early so an uplink is judged on the op that would actually run.
        {
          const changed = finding.fieldDiffs.map((f) => f.field);
          const prospective: PlanOpKind = changed.length === 1 && changed[0] === 'disabled'
            ? (intent.disabled ? 'disable' : 'enable')
            : 'update';
          if (refuseUplink(prospective, finding, actual, intent, degraded)) break;
        }

        // Disabling the management tunnel is deleting it with extra steps.
        // Only the DISABLE transition is blocked, not every edit: a comment or
        // an MTU on `l2tp-mgmt` must still be plannable, or the veto becomes a
        // line operators learn to scroll past — which is how a guard stops
        // guarding.
        if (
          kind === 'interface' &&
          facts.tunnelInterfaces.has((actual as { name?: string }).name ?? '') &&
          (intent as { disabled?: boolean }).disabled === true &&
          (actual as { disabled?: boolean }).disabled !== true
        ) {
          drafts.push({
            kind: 'blocked', resource: kind, semKey: finding.semKey,
            before: actual, after: intent, fields: [],
            chain: chainOf(actual), targetIndex: null,
            blockedReason: 'mgmt_path_veto',
            finding, coverageDegraded: degraded,
            provides: [], requires: [],
            phase: PHASE_BLOCKED, rank: rank++,
          });
          break;
        }

        // Same veto, other half. A `changed` on a `localUser` that walks
        // `group` back from full to read, or narrows `allowedFrom` past the
        // address ObliWAN dials from, locks the account out just as completely
        // as deleting it — and the path guard returns the same ACCEPT, because the account
        // still exists and the packet still arrives. Deleting and disarming
        // are the same event seen from two sides; blocking one and compiling
        // the other would only move the truck to a different Tuesday.
        if (kind === 'localUser') {
          drafts.push({
            kind: 'blocked', resource: kind, semKey: finding.semKey,
            before: actual, after: intent, fields: [],
            chain: chainOf(actual), targetIndex: null,
            blockedReason: 'mgmt_path_veto',
            finding, coverageDegraded: degraded,
            provides: [], requires: [],
            phase: PHASE_BLOCKED, rank: rank++,
          });
          break;
        }
        const fields = finding.fieldDiffs.map((f) => f.field);

        // ── N1: an identity change is a REPLACEMENT (see IDENTITY_FIELD_HEADS)
        const identityFields = identityFieldsOf(kind, fields);
        const markerChange = markerChangeOf(kind, intent, actual);
        if (identityFields.length > 0 || markerChange !== null) {
          const changes: string[] = [];
          if (identityFields.length > 0) {
            changes.push(
              `its match changed (${identityFields.slice(0, 4).join(', ')}` +
                `${identityFields.length > 4 ? ', ...' : ''})`,
            );
          }
          if (markerChange !== null) changes.push(`its marker changed (${markerChange})`);
          const what = changes.join(' and ');
          // The delete half is a deletion like any other, so guarantee 1
          // binds it exactly as it binds an `extra`. And a re-created rule is
          // APPENDED: where the order of the kind is unknown, nothing could
          // put it back, and applying it would silently move the rule.
          const orderGap = orderSuppressed.get(kind);
          if (degraded || orderGap) {
            if (degraded) {
              const coverage = coverageOf(observed.coverage, kind);
              const entry = deletionsBlocked.get(kind) ?? { coverage: coverage.state, count: 0 };
              entry.count += 1;
              deletionsBlocked.set(kind, entry);
            }
            drafts.push({
              kind: 'blocked', resource: kind, semKey: finding.semKey,
              before: actual, after: intent, fields,
              chain: chainOf(actual), targetIndex: null,
              blockedReason: degraded || orderGap === 'order_partial' ? 'coverage_incomplete' : 'weak_key',
              finding, coverageDegraded: degraded,
              provides: [], requires: [],
              phase: PHASE_BLOCKED, rank: rank++,
              note:
                `REFUSED — this ${kind} changed identity (N1): ${what}. The change can only ` +
                'be applied as a delete plus a re-create. ' +
                (degraded
                  ? `The ${kind} collection is not complete, and no deletion is compiled from ` +
                    'an incomplete collection (N3). Re-collect the configuration, then recompile.'
                  : `The order of the ${kind} list could not be established, and a re-created ` +
                    'rule is appended to its chain: nothing could put it back where it was.'),
            });
            break;
          }
          const removal: DraftOp = {
            kind: 'delete', resource: kind, semKey: actual.semKey,
            before: actual, after: null, fields,
            chain: chainOf(actual), targetIndex: null, blockedReason: null,
            finding, coverageDegraded: false,
            provides: providesOf(actual), requires: [],
            phase: PHASE_UPDATE, rank: rank++,
            note:
              `Replacement 1/2 (N1): this rule changed identity — ${what} — so it is removed ` +
              'and re-created by the next op instead of being edited in place.',
          };
          const recreation: DraftOp = {
            kind: 'create', resource: kind, semKey: intent.semKey,
            before: null, after: intent, fields,
            chain: chainOf(intent), targetIndex: null, blockedReason: null,
            finding, coverageDegraded: false,
            provides: providesOf(intent), requires: requiresOf(intent),
            // Ranks are consecutive and the update phase sorts on rank alone,
            // so the two halves land adjacent, removal first.
            phase: PHASE_UPDATE, rank: rank++,
            follows: [removal],
            note: 'Replacement 2/2 (N1): re-creates the rule the previous op removed, as the template now defines it.',
          };
          drafts.push(removal, recreation);
          replacedIntentKeys.add(intent.semKey);
          break;
        }

        // A change whose ONLY field is `disabled` is an enable/disable, not an
        // update. The distinction is not cosmetic: on RouterOS the two are
        // different commands, and the change executor dispatches on `kind`.
        const onlyDisabled = fields.length === 1 && fields[0] === 'disabled';
        const kindOp: PlanOpKind = onlyDisabled
          ? (intent.disabled ? 'disable' : 'enable')
          : 'update';
        drafts.push({
          kind: kindOp, resource: kind, semKey: finding.semKey,
          before: actual, after: intent, fields,
          chain: chainOf(intent), targetIndex: null, blockedReason: null,
          finding, coverageDegraded: degraded,
          provides: providesOf(intent),
          // An update can ADD a reference (a rule that starts naming a new
          // interface), so its requirements are the DESIRED ones.
          requires: requiresOf(intent),
          phase: PHASE_UPDATE, rank: rank++,
        });
        break;
      }

      case 'moved':
        // Handled wholesale by the move simulation below: a `moved` finding
        // says a rule crossed something, not where it must end up, and the design is
        // explicit that moves computed independently of one another produce a
        // wrong final order.
        break;

      default:
        break;
    }
  }

  // ── Moves, against a SIMULATED list, chain by chain ─────────────────────
  //
  // The simulation appends each created rule where `add` will put it: at the
  // end of its chain, IN THE ORDER THE CREATES RUN. That order is not the
  // template's — a replacement's create runs in the update phase, after every
  // phase-0 create, and fuzzy pairings reach this file in score order — so it
  // is taken from the same `orderDrafts` the plan is materialised with. Moves
  // are phase 3 and blocked ops are last, so adding them below cannot change
  // the relative order of the ops this pre-pass sees; the replay after the
  // final ordering checks that rather than trusting it. Its warnings are
  // discarded: the final pass emits the same ones.
  const runOrder = orderDrafts(drafts, []);
  const moveResult = buildMoveOps(
    desired, observed, diff, runOrder, degradedKinds, orderSuppressed, replacedIntentKeys,
  );
  drafts.push(...moveResult.drafts);
  warnings.push(...moveResult.warnings);
  for (let i = 0; i < moveResult.drafts.length; i++) moveResult.drafts[i].rank = rank++;

  // ── Suppressions the diff declared, surfaced as blocked ops ─────────────
  //
  // ONLY for kinds the template CLAIMS. A `firewallRule` suppression on a
  // template that writes the firewall is information the operator needs; a
  // `qosRule` suppression on a template that never mentioned queues is not a
  // blockage at all — it is the scope working as designed, and emitting it
  // would put eight grey rows under every plan in the product. That is the noise rule
  // applied to the plan screen: where completeness and quiet conflict, quiet
  // wins and the gap stays COUNTED (`detail.diff.suppressed` carries the full
  // list either way).
  for (const s of diff.suppressed) {
    if (!claimed.has(s.resource)) continue;
    if (s.reason === 'coverage_incomplete' && deletionsBlocked.has(s.resource)) continue;
    drafts.push({
      kind: 'blocked', resource: s.resource, semKey: `suppressed:${s.resource}`,
      before: null, after: null, fields: [], chain: null, targetIndex: null,
      blockedReason: suppressionToBlockReason(s.reason),
      finding: null, coverageDegraded: s.reason === 'coverage_incomplete',
      provides: [], requires: [], phase: PHASE_BLOCKED, rank: rank++,
    });
  }

  // ── Ordering ────────────────────────────────────────────────────────────
  const ordered = orderDrafts(drafts, warnings);

  // ── The order, replayed from the op stream itself ───────────────────────
  //
  // `orderConverges` is a claim about what the ops DO, so it is checked on the
  // ops in the order they will run, not on the simulation that produced the
  // moves: every chain the move pass targeted is rebuilt from the observed
  // document by replaying this exact sequence (a delete removes, a create
  // appends, a move repositions) and compared with that target. A
  // disagreement is a planner bug, and the plan then says it does not converge
  // instead of promising an order it would not reach.
  const replayed = replayChainOrders(observed, ordered, moveResult.targets);
  warnings.push(...replayed.warnings);
  const orderConverges = moveResult.converges && replayed.converges;

  // ── Scoring and materialisation ─────────────────────────────────────────
  const signals: Record<number, RiskAssessment> = {};
  const ops: PlanOp[] = [];
  const seqByProvidedToken = new Map<string, number>();
  const seqOfDraft = new Map<DraftOp, number>();
  ordered.forEach((draft, seq) => seqOfDraft.set(draft, seq));

  ordered.forEach((draft, seq) => {
    const assessment = scoreOp({
      kind: draft.kind,
      resource: draft.resource,
      before: draft.before,
      after: draft.after,
      fields: draft.fields,
      finding: draft.finding,
      facts,
      coverageDegraded: draft.coverageDegraded,
    });
    signals[seq] = assessment;

    const dependsOn: number[] = [];
    if (draft.kind !== 'blocked') {
      for (const token of draft.requires) {
        const producer = seqByProvidedToken.get(token);
        if (producer !== undefined && producer !== seq) dependsOn.push(producer);
      }
      // A move — and the `verify` that closes a chain — can only run once the
      // chain's POPULATION is final: `targetIndex` was computed against the
      // list as it will be after every create and every delete, and running a
      // move before them would land the rule at an index that means something
      // else.
      //
      // The comparison is on (resource, chain), not on chain alone: a firewall
      // `custom` chain and a NAT `custom` chain can carry the same name, they
      // are two different lists on the device, and an op in one must not gate
      // an op in the other.
      if (draft.kind === 'move' || draft.kind === 'verify') {
        for (let s = 0; s < seq; s++) {
          const prior = ordered[s];
          if (prior.kind === 'move' || prior.kind === 'verify' || prior.kind === 'blocked') continue;
          if (prior.resource === draft.resource && prior.chain === draft.chain) dependsOn.push(s);
        }
      }
      // Explicit edges. Ops run in ascending `seq`, so an edge pointing forward
      // is not a dependency, it is an order this plan would violate — on a
      // replacement, the create landing before the delete that shares its
      // locator. A plan known to be wrong is not returned.
      for (const prior of draft.follows ?? []) {
        const s = seqOfDraft.get(prior);
        if (s === undefined || s >= seq) {
          throw new PlanCompilationError(
            `Internal planner error: op #${seq} (${draft.kind} ${draft.resource} ` +
              `${draft.semKey}) must run after an op the ordering placed ` +
              `${s === undefined ? 'nowhere' : `at #${s}`}. No plan was produced.`,
            'op_order_violation',
          );
        }
        dependsOn.push(s);
      }
    }

    ops.push({
      seq,
      kind: draft.kind,
      resource: draft.resource,
      semKey: draft.semKey.slice(0, 180),
      risk: draft.kind === 'blocked' ? 'low' : assessment.risk,
      before: draft.before,
      after: draft.after,
      fields: draft.fields.map((f) => f.slice(0, 120)),
      chain: draft.chain === null ? null : draft.chain.slice(0, 80),
      targetIndex: draft.targetIndex,
      dependsOn: [...new Set(dependsOn)].sort((a, b) => a - b),
      blockedReason: draft.blockedReason,
      reason:
        blockedSentence(draft) ??
        (draft.note ? `${draft.note} ${assessment.reason}`.slice(0, 400) : assessment.reason),
      disruptive: assessment.disruptive,
    });

    if (draft.kind === 'create' || draft.kind === 'update') {
      for (const token of draft.provides) seqByProvidedToken.set(token, seq);
    }
  });

  return {
    ops,
    signals,
    deletionsBlocked: [...deletionsBlocked].map(([resource, v]) => ({
      resource, coverage: v.coverage, count: v.count,
    })),
    orderConverges,
    warnings,
  };
}

function suppressionToBlockReason(reason: string): PlanOp['blockedReason'] {
  switch (reason) {
    case 'version_skew': return 'version_skew';
    case 'weak_keys': return 'weak_key';
    case 'order_partial': return 'coverage_incomplete';
    default: return 'coverage_incomplete';
  }
}

/** A `blocked` op's sentence explains the refusal, not the risk. It is the one
 *  place in the product where an operator finds out WHY a change they asked for
 *  did not become an instruction — a greyed-out button with no reason is how a
 *  guard gets routed around. */
function blockedSentence(draft: DraftOp): string | null {
  if (draft.kind !== 'blocked') return null;
  // A refusal that needed its own explanation (a refused replacement) carries
  // it: the generic sentences below describe an `extra`, which it is not.
  if (draft.note) return draft.note.slice(0, 400);
  switch (draft.blockedReason) {
    case 'coverage_incomplete':
      if (draft.before) {
        return (
          `REFUSED — this ${draft.resource} exists on the device and not in the template, but ` +
          `the configuration collection for ${draft.resource} is not complete, so ObliWAN ` +
          'cannot prove it saw everything. No deletion is compiled from an incomplete ' +
          'collection (N3). Re-collect the configuration, then recompile.'
        ).slice(0, 400);
      }
      return (
        `REFUSED — ${draft.resource} was not compared: the collection for this resource kind ` +
        'is incomplete or its ordering could not be established. Nothing is claimed about it.'
      ).slice(0, 400);
    case 'weak_key':
      return (
        `REFUSED — every ${draft.resource} record on this device has an identity too weak to ` +
        'pair reliably. Acting on a coin-flip pairing would change the wrong record.'
      ).slice(0, 400);
    case 'version_skew':
      return (
        `REFUSED — the desired and observed documents use different NCM versions and were not ` +
        'compared. Re-collect the configuration so both sides speak the same model.'
      ).slice(0, 400);
    default:
      return `REFUSED — ${draft.resource}: ${draft.blockedReason ?? 'unspecified'}.`;
  }
}

// ============================================================================
// Ordering
// ============================================================================

/**
 * Order the drafts so that `dependsOn` is satisfiable in `seq` order.
 *
 * ┌─ REUSE, AND ITS ONE LIMIT, STATED PLAINLY ──────────────────────────────┐
 * │ `utils/topoSort.ts` sorts a PARENT-REFERENCING list — each item has at   │
 * │ most one parent — with real cycle detection. That is exactly the shape   │
 * │ of the interface hierarchy (a VLAN on a bridge on an ethernet port), and │
 * │ that is where it is used below, cycle detection included: a bridge whose │
 * │ parent chain closes on itself is a template bug, and `CycleError` names  │
 * │ the members instead of ordering them arbitrarily.                        │
 * │                                                                          │
 * │ It CANNOT express the rest: a firewall rule depends on its in-interface, │
 * │ its out-interface AND its jump target — three parents. A single-parent   │
 * │ sort would have to drop two of the three edges, and a dropped edge is a  │
 * │ plan that references something that does not exist yet.                  │
 * │                                                                          │
 * │ So the cross-kind order is a FIXED LAYERING (`CREATE_LAYER`) rather than │
 * │ a second graph algorithm: interfaces before VLANs before routes before   │
 * │ firewall rules. The layering is a property of the NCM model, it is five  │
 * │ numbers, and it is reviewable — which a hand-rolled Kahn implementation  │
 * │ with its own cycle handling would not be.                                │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
function orderDrafts(drafts: DraftOp[], warnings: string[]): DraftOp[] {
  const byPhase = new Map<number, DraftOp[]>();
  for (const d of drafts) {
    const list = byPhase.get(d.phase);
    if (list) list.push(d);
    else byPhase.set(d.phase, [d]);
  }

  const out: DraftOp[] = [];
  for (const phase of [PHASE_CREATE, PHASE_UPDATE, PHASE_DELETE, PHASE_MOVE, PHASE_VERIFY, PHASE_BLOCKED]) {
    const list = byPhase.get(phase) ?? [];
    if (phase === PHASE_CREATE) out.push(...orderCreates(list, warnings));
    else if (phase === PHASE_DELETE) out.push(...orderDeletes(list, warnings));
    else out.push(...list.sort((a, b) => a.rank - b.rank));
  }
  return out;
}

/** Interface-shaped drafts, as `topoSort` wants them: a key and a parent key. */
interface HierarchyItem extends Record<string, unknown> {
  key: string;
  parent: string;
  draft: DraftOp;
}

function orderCreates(list: DraftOp[], warnings: string[]): DraftOp[] {
  // 1. Within the interface layer, the parent chain decides. THIS is topoSort's
  //    shape, and its cycle detection is the point.
  const hierarchy = list.filter((d) => CREATE_LAYER[d.resource] <= 1);
  const rest = list.filter((d) => CREATE_LAYER[d.resource] > 1);

  let orderedHierarchy: DraftOp[];
  if (hierarchy.length > 1) {
    const items: HierarchyItem[] = hierarchy.map((draft) => ({
      key: providesOf(draft.after)[0] ?? `op:${draft.semKey}`,
      // A parent outside `items` is an anchor already on the device: topoSort
      // treats it as a root, which is exactly right.
      parent: requiresOf(draft.after).find((t) => t.startsWith('iface:')) ?? '',
      draft,
    }));
    try {
      orderedHierarchy = topoSort(items, 'key', 'parent').map((i) => i.draft);
    } catch (err) {
      if (err instanceof CycleError) {
        warnings.push(
          `The desired interface hierarchy contains a cycle (${err.cycle.join(' -> ')}). ` +
            'The creation order for those interfaces is the template\'s own order and may be ' +
            'wrong; fix the template rather than approving this plan.',
        );
        const cyclic = findCycles(items, 'key', 'parent');
        if (cyclic.length > 0) {
          warnings.push(`Interfaces on a cycle: ${cyclic.sort().join(', ')}.`);
        }
        orderedHierarchy = hierarchy.slice().sort((a, b) => a.rank - b.rank);
      } else {
        throw err;
      }
    }
  } else {
    orderedHierarchy = hierarchy;
  }

  // 2. Everything else follows the fixed layering, then the input order.
  rest.sort((a, b) => CREATE_LAYER[a.resource] - CREATE_LAYER[b.resource] || a.rank - b.rank);

  // 3. Inside the firewall layer, custom chains first: a rule that jumps into a
  //    chain needs the chain's rules to exist. One pass, deterministic.
  const providers: DraftOp[] = [];
  const consumers: DraftOp[] = [];
  for (const d of rest) {
    if (d.provides.some((t) => t.startsWith('chain:') || t.startsWith('natchain:'))) providers.push(d);
    else consumers.push(d);
  }

  return [...orderedHierarchy, ...providers, ...consumers];
}

/**
 * Deletes run in REVERSE dependency order: whatever names a resource is removed
 * before the resource itself.
 *
 * The reverse of the creation layering is exactly that, for the same reason the
 * layering is right in the first place — the reference direction between kinds
 * is a property of the model. Inside a layer, the interface hierarchy is
 * reversed too: a VLAN goes before the bridge it sits on.
 */
function orderDeletes(list: DraftOp[], warnings: string[]): DraftOp[] {
  const hierarchy = list.filter((d) => CREATE_LAYER[d.resource] <= 1);
  const rest = list.filter((d) => CREATE_LAYER[d.resource] > 1);

  rest.sort((a, b) => CREATE_LAYER[b.resource] - CREATE_LAYER[a.resource] || a.rank - b.rank);

  let orderedHierarchy: DraftOp[] = hierarchy;
  if (hierarchy.length > 1) {
    const items: HierarchyItem[] = hierarchy.map((draft) => ({
      key: providesOf(draft.before)[0] ?? `op:${draft.semKey}`,
      parent: requiresOf(draft.before).find((t) => t.startsWith('iface:')) ?? '',
      draft,
    }));
    try {
      orderedHierarchy = topoSort(items, 'key', 'parent').map((i) => i.draft).reverse();
    } catch (err) {
      if (err instanceof CycleError) {
        warnings.push(
          `The observed interface hierarchy contains a cycle (${err.cycle.join(' -> ')}); ` +
            'the deletion order for those interfaces is not proven safe.',
        );
        orderedHierarchy = hierarchy.slice().sort((a, b) => b.rank - a.rank);
      } else {
        throw err;
      }
    }
  }

  return [...rest, ...orderedHierarchy];
}

// ============================================================================
// Moves — the renumbering trap
// ============================================================================

/** The order the move pass aimed one chain at, in its own tokens: observed
 *  semKeys for rules already on the box, desired semKeys for created ones. */
interface ChainTarget {
  kind: NcmResourceKind;
  chain: string;
  order: string[];
}

interface MoveBuild {
  drafts: DraftOp[];
  converges: boolean;
  warnings: string[];
  /** Every chain the moves were computed for — with or without a move — so the
   *  final op stream can be replayed against it (`replayChainOrders`). */
  targets: ChainTarget[];
}

/**
 * `/ip/firewall/filter/move numbers=X destination=Y` RENUMBERS the list on
 * every move. A sequence of moves computed independently of one another
 * produces a wrong final order — the design names this as the implementation trap of
 * this milestone.
 *
 * So the moves are generated AGAINST A SIMULATION, op by op:
 *   1. build the list as it will be after the creates and the deletes: the
 *      observed chain minus what is deleted, then every created rule APPENDED
 *      in the order its create RUNS (`runOrder`) — which is not the template's
 *      order, see `buildOps`;
 *   2. walk the target order left to right;
 *   3. whenever the simulated list disagrees, emit ONE move that puts the right
 *      rule at that index, then MUTATE the simulation and continue.
 * `targetIndex` is therefore the index in the list AS IT IS WHEN THAT OP RUNS,
 * never the index in the original document.
 *
 * A chain with a move ends with a `verify` op, which the renderer turns into an
 * on-box assertion that every moved rule sits at its move's `targetIndex`. It
 * asserts nothing about a chain that received creates and no move: there, the
 * claim that `add` left the rules in the target order rests on step 1 and on
 * `replayChainOrders`, which re-derives every targeted chain from the final op
 * stream. `orderConverges` is false when either the simulation or that replay
 * misses the target, or when a template rule could not be placed at all. A plan
 * with `orderConverges: false` must not be offered for approval — the contract
 * says so, and the flag is the only way a reviewer could know.
 *
 * NOTE on the RouterOS off-by-one: `destination` on RouterOS is "before the
 * item currently numbered Y", and moving an item DOWN the list shifts the
 * target by one. That translation belongs to the driver at apply time,
 * which is also the only place that knows the live `.id` values. `targetIndex`
 * here is brand-neutral: "this resource must sit at index N of its chain".
 */
function buildMoveOps(
  desired: NcmDocument,
  observed: NcmDocument,
  diff: NcmDiffReport,
  /** Every non-move draft, in the order the plan will run it. */
  runOrder: readonly DraftOp[],
  degradedKinds: ReadonlySet<NcmResourceKind>,
  orderSuppressed: ReadonlyMap<NcmResourceKind, string>,
  replacedIntentKeys: ReadonlySet<string>,
): MoveBuild {
  const drafts: DraftOp[] = [];
  const warnings: string[] = [];
  const targets: ChainTarget[] = [];
  let converges = true;

  // Alias: a pairing may join two records whose semKeys differ (marker or fuzzy
  // pairing). The simulation speaks in OBSERVED tokens, so every desired rule
  // is translated through the pairing the diff actually made.
  const alias = new Map<string, string>();
  for (const f of diff.findings) {
    const intent = asResource(f.intentValue);
    const actual = asResource(f.actualValue);
    // A pairing the planner REPLACED is not aliased: its observed rule is
    // deleted, and the token to place is the re-created one. Skipped on every
    // finding of the pair, because a `moved` finding carries the same two
    // values and would otherwise put the alias back.
    if (intent && replacedIntentKeys.has(intent.semKey)) continue;
    if (intent && actual && intent.semKey !== actual.semKey) alias.set(intent.semKey, actual.semKey);
  }

  const deleted = new Set(runOrder.filter((d) => d.kind === 'delete').map((d) => d.semKey));
  // What the box holds, once the update phase has run, for every rule an
  // update rewrote. See `onBoxAfterUpdate`.
  const updatedOnBox = new Map<string, NcmResource>();
  for (const d of runOrder) {
    if (d.kind !== 'update') continue;
    const onBox = onBoxAfterUpdate(d);
    if (onBox) updatedOnBox.set(d.semKey, onBox);
  }

  for (const kind of ORDERED_RESOURCE_KINDS) {
    if (orderSuppressed.has(kind)) {
      drafts.push({
        kind: 'blocked', resource: kind, semKey: `order:${kind}`,
        before: null, after: null, fields: ['order'], chain: null, targetIndex: null,
        blockedReason: 'coverage_incomplete', finding: null, coverageDegraded: true,
        provides: [], requires: [], phase: PHASE_BLOCKED, rank: 0,
      });
      continue;
    }

    const desiredRules = rulesOf(desired, kind);
    const observedRules = rulesOf(observed, kind);
    if (desiredRules.length === 0) continue;

    const chains = new Set<string>();
    for (const r of desiredRules) chains.add(chainOf(r) ?? '');

    for (const chain of [...chains].sort()) {
      // The simulated list: observed rules of this chain, minus the ones the
      // plan deletes, plus the ones it creates — APPENDED, as RouterOS `add`
      // does, in the order the creates run. Walking `desiredInChain` here
      // instead would describe a box that does not exist whenever a create
      // runs later than its template position (a replacement's create runs
      // after every phase-0 create), and no move would be emitted to fix it.
      const simulated: string[] = observedRules
        .filter((r) => (chainOf(r) ?? '') === chain && !deleted.has(r.semKey))
        .map((r) => r.semKey);
      // The record each `move` carries, i.e. the one it locates on the box:
      // the observed rule, as the update phase left it.
      const byToken = new Map<string, NcmResource>();
      for (const r of observedRules) byToken.set(r.semKey, updatedOnBox.get(r.semKey) ?? r);

      for (const d of runOrder) {
        if (d.kind !== 'create' || d.resource !== kind || (d.chain ?? '') !== chain || !d.after) continue;
        if (simulated.includes(d.semKey)) continue;
        simulated.push(d.semKey);
        byToken.set(d.semKey, d.after);
      }

      const desiredInChain = desiredRules.filter((r) => (chainOf(r) ?? '') === chain);
      const desiredTokens = desiredInChain.map((r) => alias.get(r.semKey) ?? r.semKey);

      // A template rule that is neither on the box under its token nor created
      // by this plan cannot be placed. The diff paired it with a record under
      // another key without reporting a change (two markers on otherwise
      // identical rules: `managedSlug` is not a diffed field, so the pair
      // yields no finding and no alias), or the collection did not let the
      // diff emit its `missing`. Either way the observed record it stands for
      // would be read below as UNCLAIMED and pushed after every claimed rule —
      // a move that reorders a firewall nobody asked to reorder. No move is
      // better than that one.
      const unplaced = desiredTokens.filter((t) => !simulated.includes(t));
      if (unplaced.length > 0) {
        converges = false;
        warnings.push(
          `Order of ${kind} chain "${chain}" not computed: template rule(s) ` +
            `${unplaced.slice(0, 3).join(', ')}${unplaced.length > 3 ? ', ...' : ''} ` +
            'are neither on the device under that key nor created by this plan (paired with ' +
            'a rule under another key without a reported change, or not compared at all). ' +
            'No move operation was generated for this chain and its final order is not proven.',
        );
        continue;
      }

      const target = desiredTokens.slice();

      // Rules present on the box that the template did not claim keep their
      // relative position. They are appended to the target so the simulation
      // has somewhere to put them, in their observed order, AFTER the claimed
      // ones — which is the only choice that does not reorder configuration
      // nobody asked us to touch.
      const claimedSet = new Set(target);
      for (const token of simulated) if (!claimedSet.has(token)) target.push(token);

      if (target.length !== simulated.length) {
        // Cannot happen through the construction above; if it ever did, a move
        // sequence computed from it would be wrong, and a wrong move sequence
        // is worse than no move at all.
        converges = false;
        warnings.push(
          `Order simulation for ${kind} chain "${chain}" is inconsistent ` +
            `(${simulated.length} rules simulated, ${target.length} targeted); no move ` +
            'operation was generated for it.',
        );
        continue;
      }
      targets.push({ kind, chain, order: target.slice() });

      const work = simulated.slice();
      for (let i = 0; i < target.length; i++) {
        if (work[i] === target[i]) continue;
        const from = work.indexOf(target[i], i);
        if (from < 0) {
          converges = false;
          warnings.push(
            `Order simulation for ${kind} chain "${chain}" lost rule ${target[i]}; ` +
              'the plan does not prove the final order.',
          );
          break;
        }
        const [token] = work.splice(from, 1);
        work.splice(i, 0, token);
        const resource = byToken.get(token) ?? null;
        drafts.push({
          kind: 'move', resource: kind, semKey: token,
          before: resource, after: resource, fields: ['position'],
          chain, targetIndex: i, blockedReason: null,
          finding: diff.findings.find((f) => f.kind === 'moved' && f.semKey === token) ?? null,
          coverageDegraded: degradedKinds.has(kind),
          provides: [], requires: [], phase: PHASE_MOVE, rank: 0,
        });
      }

      const moved = drafts.some((d) => d.kind === 'move' && d.chain === chain && d.resource === kind);
      if (moved) {
        const ok = work.every((t, i) => t === target[i]);
        if (!ok) converges = false;
        drafts.push({
          kind: 'verify', resource: kind, semKey: `order:${kind}:${chain}`,
          before: null, after: null, fields: ['position'],
          chain, targetIndex: null, blockedReason: null,
          finding: null, coverageDegraded: degradedKinds.has(kind),
          provides: [], requires: [], phase: PHASE_VERIFY, rank: 0,
        });
      }
    }
  }

  return { drafts, converges, warnings, targets };
}

/**
 * Rebuild every targeted chain from the observed document by replaying the
 * FINAL op stream — a delete removes its rule, a create appends its rule (or
 * leaves it in place when the key is still there, as `projectPlan` does), a
 * move repositions its rule inside the chain — and compare the result with the
 * order the move pass aimed at.
 *
 * It shares the move pass's tokens and nothing else: not its list, not its
 * notion of when a create runs. That independence is the point. The move pass
 * builds its simulation from a pre-ordering of the drafts; this reads the ops
 * as they will actually be numbered, so any disagreement between the two —
 * the exact shape of the defect where a re-created rule landed after a rule
 * appended earlier, with no move and `orderConverges` still true — surfaces as
 * a non-converging plan instead of a firewall in an order nobody reviewed.
 */
function replayChainOrders(
  observed: NcmDocument,
  ordered: readonly DraftOp[],
  targets: readonly ChainTarget[],
): { converges: boolean; warnings: string[] } {
  const warnings: string[] = [];
  let converges = true;

  for (const t of targets) {
    const list = rulesOf(observed, t.kind)
      .filter((r) => (chainOf(r) ?? '') === t.chain)
      .map((r) => r.semKey);
    let broken: string | null = null;

    for (const d of ordered) {
      if (d.resource !== t.kind || (d.chain ?? '') !== t.chain) continue;
      if (d.kind === 'delete') {
        const at = list.indexOf(d.semKey);
        if (at < 0) { broken = `op deleting ${d.semKey} finds no such rule`; break; }
        list.splice(at, 1);
      } else if (d.kind === 'create') {
        if (!list.includes(d.semKey)) list.push(d.semKey);
      } else if (d.kind === 'move') {
        const at = list.indexOf(d.semKey);
        if (at < 0 || d.targetIndex === null || d.targetIndex < 0 || d.targetIndex >= list.length) {
          broken = `move of ${d.semKey} to ${d.targetIndex ?? '?'} cannot be replayed`;
          break;
        }
        list.splice(at, 1);
        list.splice(d.targetIndex, 0, d.semKey);
      }
    }

    let firstDifference = -1;
    for (let i = 0; i < Math.max(list.length, t.order.length); i++) {
      if (list[i] !== t.order[i]) { firstDifference = i; break; }
    }
    if (broken !== null || firstDifference >= 0) {
      converges = false;
      warnings.push(
        `Internal planner check: replaying this plan's ops on ${t.kind} chain "${t.chain}" ` +
          (broken !== null
            ? `fails (${broken}).`
            : 'does not reach the order the moves were computed for (first difference at ' +
              `index ${firstDifference}).`) +
          ' The final order of that chain is not proven; do not approve this plan.',
      );
    }
  }

  return { converges, warnings };
}

function rulesOf(doc: NcmDocument, kind: NcmResourceKind): NcmOrderedRule[] {
  const key = RESOURCE_KIND_TO_COLLECTION[kind] as keyof NcmDocument['resources'];
  return (doc.resources[key] ?? []) as unknown as NcmOrderedRule[];
}

// ============================================================================
// Blast radius
// ============================================================================

function buildBlastRadius(
  device: DeviceRow,
  ops: readonly PlanOp[],
  signals: Record<number, RiskAssessment>,
): BlastRadius {
  const interfaces = new Set<string>();
  const subnets = new Set<string>();
  let touchesManagementPath = false;

  for (const op of ops) {
    if (op.kind === 'blocked') continue;
    if (signals[op.seq]?.tunnelCritical) touchesManagementPath = true;
    for (const side of [op.before, op.after]) {
      const r = asResource(side);
      if (!r) continue;
      switch (r.kind) {
        case 'interface':
          interfaces.add(r.name);
          for (const a of r.addresses) subnets.add(a.cidr);
          break;
        case 'vlan':
          if (r.name) interfaces.add(r.name);
          break;
        case 'route':
          subnets.add(r.dst);
          if (r.gateway?.startsWith('iface:')) interfaces.add(r.gateway.slice('iface:'.length));
          break;
        case 'dhcpScope':
          subnets.add(r.subnet);
          if (r.onInterface.startsWith('iface:')) interfaces.add(r.onInterface.slice('iface:'.length));
          break;
        case 'firewallRule':
        case 'natRule':
          for (const atom of [...r.match.inInterface, ...r.match.outInterface]) {
            if (atom.startsWith('iface:')) interfaces.add(atom.slice('iface:'.length));
          }
          break;
        default:
          break;
      }
    }
  }

  return {
    deviceCount: 1,
    siteCount: device.site_id === null ? 0 : 1,
    // Capped: `BlastRadius` is shown on a screen before launch, and a list of
    // 400 interfaces is not information. The counts above stay exact.
    affectedInterfaces: [...interfaces].filter((s) => s.length <= 64).sort().slice(0, 200),
    affectedSubnets: [...subnets].filter((s) => s.length <= 49).sort().slice(0, 200),
    touchesManagementPath,
  };
}

// ============================================================================
// Summary — what the fleet screen shows without loading every op
// ============================================================================

export interface PlanSummary {
  deviceId: number;
  deviceName: string;
  planUuid: string;
  riskLevel: RiskLevel;
  mgmtPathVerdict: ApplyPlan['mgmtPathVerdict'];
  baseStateHash: string;
  expiresAt: string;
  orderConverges: boolean;
  opCount: number;
  byKind: Record<PlanOpKind, number>;
  blockedCount: number;
  tunnelCriticalCount: number;
  touchesManagementPath: boolean;
}

export function summarize(c: PlanCompilation): PlanSummary {
  const byKind = {
    create: 0, update: 0, delete: 0, move: 0,
    enable: 0, disable: 0, verify: 0, blocked: 0,
  } as Record<PlanOpKind, number>;
  let tunnelCriticalCount = 0;
  for (const op of c.plan.ops) {
    byKind[op.kind] += 1;
    if (c.detail.signals[op.seq]?.tunnelCritical) tunnelCriticalCount += 1;
  }
  return {
    deviceId: c.plan.deviceId,
    deviceName: c.detail.deviceName,
    planUuid: c.plan.planUuid,
    riskLevel: c.plan.riskLevel,
    mgmtPathVerdict: c.plan.mgmtPathVerdict,
    baseStateHash: c.plan.baseStateHash,
    expiresAt: c.plan.expiresAt,
    orderConverges: c.plan.orderConverges,
    opCount: c.plan.ops.length,
    byKind,
    blockedCount: byKind.blocked,
    tunnelCriticalCount,
    touchesManagementPath: c.plan.blastRadius.touchesManagementPath,
  };
}

export const plannerService = {
  compilePlan,
  compileForDevices,
  checkPlanFreshness,
  assertPlanFresh,
  summarize,
  PLAN_TTL_MS,
};

// Re-exported so a caller that already imports the planner does not reach into
// two modules for the same decision.
export { classifyResource, buildMgmtPathFacts };
export type { RenderResultRecord };
