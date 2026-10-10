// ============================================================================
// ObliWAN — the change renderer: a frozen plan -> what will actually be sent
// ============================================================================
//
// ┌─ THE SEAM THIS FILLS ─────────────────────────────────────────────────────┐
// │ `safeApply.service.ts` declares                                          │
// │                                                                          │
// │   type ChangeRenderer = (job: { id; deviceId; planId }) => …              │
// │                                                                          │
// │ and refuses every write until one is registered, because the queue hands  │
// │ the executor REDACTED ops and a redacted op carries `***` where a         │
// │ secret belongs. THIS is that renderer. Registration happens in the        │
// │ composition root, before `changeExecutorReadiness()` logs whether one     │
// │ exists — that boot line is what an operator reads to know the queue can   │
// │ write, so a registration after it would make the line a lie.              │
// └──────────────────────────────────────────────────────────────────────────┘
//
// ┌─ WHAT THE SIGNATURE DOES NOT CARRY, AND WHY IT MATTERS ───────────────────┐
// │ Three job fields, and no tenant. Every read in this codebase is           │
// │ tenant-scoped — `loadDevice(tenantId, deviceId)` treats a foreign device  │
// │ as non-existent, `loadPlanOps` filters on `tenant_id` — so a renderer     │
// │ that read `devices` or `change_plans` by id alone would be a cross-tenant │
// │ read ON THE PUSH PATH: customer A's plan rendered against customer B's    │
// │ box. The tenant is therefore looked up from `change_jobs` first, and      │
// │ every later read is scoped by it. That is also the identity rule:         │
// │ identity comes from the row, never from the argument that was handy.      │
// │                                                                          │
// │ `loadPlanOps()` in `apply.service.ts` is private, so its three behaviours │
// │ are re-implemented here rather than borrowed: the `tenant_id` predicate,  │
// │ the `plan_missing` refusal, and the `invalidated_at` refusal — the last   │
// │ being the guard that stops a plan compiled against a config somebody has  │
// │ since edited.                                                            │
// └──────────────────────────────────────────────────────────────────────────┘
//
// ┌─ THIS CODE RUNS INSIDE THE ARMED WINDOW ──────────────────────────────────┐
// │ `apply.service`'s phase order is takePreflightBackup -> armDeadman ->     │
// │ applyChange, and `applyChange` calls this renderer as its FIRST act, with │
// │ the on-box scheduler already counting down. `assertTimingsCoherent()`     │
// │ budgets reconnect, soak and disarm and knows nothing about render time,   │
// │ so every millisecond spent here is taken off the window in which a good   │
// │ change can be confirmed.                                                 │
// │                                                                          │
// │ Hence the I/O budget, which is deliberate and small: one `change_jobs`    │
// │ row, one `devices` row, one `change_plans` row, and the variable chain     │
// │ ONLY when the plan actually carries a secret placeholder. No template     │
// │ compilation, no Nunjucks worker, no snapshot read, no network.            │
// └──────────────────────────────────────────────────────────────────────────┘
//
// NOT WRITTEN HERE, ON PURPOSE: `change_plans.rendered`. The column exists and
// is documented as "the brand artefact the driver will actually send, MASKED",
// and nothing in the repo fills it. It cannot be filled from here either: the
// `change_plans_freeze()` trigger lets an UPDATE touch `invalidated_at`,
// `invalidated_reason` and `updated_at` and nothing else, so the database would
// refuse the write. Filling it belongs to whatever produces the plan, at freeze
// time, from this module's `redacted` half.

import { FAMILY_BRAND, PlanOp, type DeviceFamily } from '@obliwan/shared';
import { z } from 'zod';
import { db } from '../../../db';
import {
  assertConsoleLine,
  renderPlanOpsForRouterOs,
  SECRET_REFUSAL_CODES,
  type RenderRefusal,
} from '../../drivers/mikrotik/render';
import { ChangeError } from '../backup.service';
import { loadJob, type ChangeRenderer, type RenderedChange } from '../safeApply.service';
import {
  assembleRendering,
  buildSecretSubstitutions,
  SECRET_PLACEHOLDER_PREFIX,
  type SecretSubstitution,
} from './secrets';

const PlanOps = z.array(PlanOp);

interface PlanRow {
  ops: unknown;
  invalidated_at: Date | null;
  ops_count: number;
}

/**
 * Read the FROZEN ops, tenant-scoped, and re-validate them.
 *
 * Migration 009's comment is explicit that `ops` is validated against
 * `shared/src/ncm/plan.ts` on the way in AND on the way out, "so a plan compiled
 * by one server version cannot be applied blind by another". This is the way
 * out, and it is the last checkpoint before the values become commands.
 */
async function loadFrozenOps(jobId: number, tenantId: number, planId: number): Promise<PlanOp[]> {
  const row = (await db('change_plans')
    .where({ id: planId, tenant_id: tenantId })
    .first('ops', 'invalidated_at', 'ops_count')) as PlanRow | undefined;

  if (!row) {
    throw new ChangeError(
      'DEVICE_UNKNOWN',
      `the frozen plan ${planId} of job ${jobId} does not exist for this tenant. Nothing can be ` +
        'rendered from a plan that is gone, and re-planning now would push something nobody ' +
        'approved.',
      { jobId, planId },
    );
  }
  if (row.invalidated_at) {
    throw new ChangeError(
      'BACKUP_FAILED',
      `the frozen plan ${planId} was invalidated (the device moved under us). Its ops describe ` +
        'rules that may no longer exist, and applying them deletes things the operator never ' +
        'saw. Recompile the plan.',
      { jobId, planId, invalidatedAt: row.invalidated_at },
    );
  }

  const raw = typeof row.ops === 'string' ? (JSON.parse(row.ops) as unknown) : row.ops;
  const parsed = PlanOps.safeParse(raw);
  if (!parsed.success) {
    throw new ChangeError(
      'BACKUP_FAILED',
      `the frozen ops of plan ${planId} do not validate against the PlanOp contract ` +
        `(${parsed.error.issues.slice(0, 3).map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}). ` +
        'This plan was written by a different server version; recompile it.',
      { jobId, planId },
    );
  }
  if (parsed.data.length !== row.ops_count) {
    // `ops_count` is a denormalised copy of the same truth, and the freeze
    // trigger seals both. A disagreement means the row was edited around the
    // trigger, which is exactly the 2 a.m. psql scenario the trigger exists for.
    throw new ChangeError(
      'BACKUP_FAILED',
      `plan ${planId} carries ${parsed.data.length} ops but records ops_count=${row.ops_count}. ` +
        'The frozen row disagrees with itself; refusing to render it.',
      { jobId, planId },
    );
  }
  return parsed.data;
}

/** The plan refused, as one message an operator can act on. */
function refusalError(refusals: readonly RenderRefusal[]): ChangeError {
  // `ChangeErrorKind` is a closed union owned by `backup.service.ts`, and it has
  // no "cannot render" member. Mapping a missing secret to SECRET_LEAK_REFUSED
  // and everything else to BRAND_UNSUPPORTED keeps the two apart where it
  // matters — one is a secrets-rule boundary, the other is a coverage gap — without
  // widening a union another module owns.
  const secretBound = refusals.some((r) => SECRET_REFUSAL_CODES.has(r.code));
  const lines = refusals.map(
    (r) => `op ${r.seq} (${r.kind} ${r.resource} "${r.semKey}") [${r.code}]: ${r.reason}`,
  );
  return new ChangeError(
    secretBound ? 'SECRET_LEAK_REFUSED' : 'BRAND_UNSUPPORTED',
    `${refusals.length} operation(s) of this plan cannot be rendered for RouterOS, so none of ` +
      `it will be sent:\n${lines.join('\n')}`,
    { refusals: refusals.map((r) => ({ seq: r.seq, code: r.code, semKey: r.semKey })) },
  );
}

/**
 * Turn a job into the complete rendering, plus its masked twin.
 *
 * Exported separately from the `ChangeRenderer` value so a test, a preview
 * controller or a future review screen can call it without installing a global
 * singleton — `registerChangeRenderer()` has process-wide effect, and
 * `runSafeApply()` does not consult it at all (it takes `rendered` as an
 * argument), so "registered" and "used" are not the same statement.
 */
export async function renderChangeForJob(job: {
  id: number;
  deviceId: number;
  planId: number | null;
}): Promise<RenderedChange> {
  const row = await loadJob(job.id);

  // The job row is the authority on both. A caller-supplied device id or plan id
  // that disagrees is not a detail to reconcile: it is the identity failure — pushing
  // one site's configuration at another — arriving through the argument list.
  if (row.deviceId !== job.deviceId) {
    throw new ChangeError(
      'IDENTITY_MISMATCH',
      `job ${job.id} targets device ${row.deviceId}, and the renderer was called for device ` +
        `${job.deviceId}. Refusing: a mismatched target on the push path is how one customer's ` +
        "configuration lands on another customer's router.",
      { jobId: job.id, jobDeviceId: row.deviceId, calledWith: job.deviceId },
    );
  }
  const planId = row.planId;
  if (job.planId !== null && job.planId !== planId) {
    throw new ChangeError(
      'IDENTITY_MISMATCH',
      `job ${job.id} is frozen against plan ${planId ?? 'none'}, and the renderer was called ` +
        `for plan ${job.planId}. The plan an operator approved is the one on the job row.`,
      { jobId: job.id, jobPlanId: planId, calledWith: job.planId },
    );
  }
  if (planId === null) {
    throw new ChangeError(
      'BACKUP_FAILED',
      `job ${job.id} carries no plan, so there is nothing frozen to render. A push without a ` +
        'plan has no approved content, no blast radius and no management-path verdict; and ' +
        "the plan-less generic kinds ('restore', 'reboot', 'firmware') have no renderer at all — " +
        'the queue refuses them at every door and at claim.',
      { jobId: job.id },
    );
  }

  const device = (await db('devices')
    .where({ id: row.deviceId, tenant_id: row.tenantId })
    .first('id', 'family', 'name')) as
    | { id: number; family: DeviceFamily; name: string }
    | undefined;
  if (!device) {
    throw new ChangeError(
      'DEVICE_UNKNOWN',
      `device ${row.deviceId} does not exist for tenant ${row.tenantId}.`,
      { deviceId: row.deviceId, tenantId: row.tenantId },
    );
  }

  const brand = FAMILY_BRAND[device.family];
  if (brand !== 'mikrotik') {
    // Said HERE rather than let `openDeviceSession()` say it two steps later.
    // Either way nothing has been transmitted, so the executor marks the error
    // `nothingTransmitted` and the queue takes the armed dead-man and the
    // preflight blob back off the box (applyFrontier.ts) instead of leaving a
    // scheduler to reboot it for a write that never happened — but the earlier
    // the refusal, the less of that round trip is spent. `applyOverSsh()` is written and takes the
    // same commands/redacted/secretValues triple this module produces — what is
    // missing is a renderer for those three dialects, not a transport.
    throw new ChangeError(
      'BRAND_UNSUPPORTED',
      `device "${device.name}" is ${brand} (${device.family}), and this renderer only speaks ` +
        'RouterOS. The MikroTik apply path wraps commands in /system/script with ' +
        ':do{} on-error={}; DrayTek, Zyxel and SonicWall go through applyOverSsh() with their ' +
        'own prologue and commit verbs, and no renderer for those dialects exists yet. Refusing ' +
        'here rather than after the dead-man is armed.',
      { deviceId: device.id, family: device.family, brand },
    );
  }

  const ops = await loadFrozenOps(job.id, row.tenantId, planId);
  if (ops.length === 0) {
    throw new ChangeError(
      'BACKUP_FAILED',
      `the frozen plan ${planId} of job ${job.id} contains no operations. An empty plan is not a ` +
        'no-op to apply: it is a plan whose ops were lost.',
      { jobId: job.id, planId },
    );
  }

  const { lines, refusals } = renderPlanOpsForRouterOs(ops);
  if (refusals.length > 0) throw refusalError(refusals);
  if (lines.length === 0) {
    throw new ChangeError(
      'BACKUP_FAILED',
      `plan ${planId} rendered to zero RouterOS commands from ${ops.length} op(s). Nothing ` +
        'refused and nothing was produced, which means an op kind fell through the renderer ' +
        'without saying so — refusing rather than reporting a successful apply of nothing.',
      { jobId: job.id, planId, opCount: ops.length },
    );
  }

  return substituteSecrets(lines.map((l) => l.text), row.tenantId, row.deviceId);
}

/**
 * The secrets-rule pass. Reads the vault ONLY when the rendering actually needs it: the
 * variable chain is four joins plus a decrypt per secret, and paying for it on a
 * plan with no placeholder would eat the dead-man window for nothing.
 *
 * The assembly itself lives in `./secrets` and is pure, so the one property that
 * must never regress — a plaintext in `commands`, never in `redacted`, always in
 * `secretValues` — is asserted by `renderer.verify.ts` against THIS code rather
 * than against a copy of it.
 */
async function substituteSecrets(
  texts: readonly string[],
  tenantId: number,
  deviceId: number,
): Promise<RenderedChange> {
  const needsVault = texts.some((t) => t.includes(SECRET_PLACEHOLDER_PREFIX));
  const table: SecretSubstitution[] = needsVault
    ? await buildSecretSubstitutions(tenantId, deviceId)
    : [];
  // `assertConsoleLine` already ran inside `renderPlanOpsForRouterOs` — but on
  // lines that still carried `__OBLIWAN_SECRET_<KEY>__`, a `[A-Z0-9_]` token
  // that survives `rosQuote`, `token` and the assertion itself untouched.
  // Handing it down here is what makes it run on the SUBSTITUTED text, which is
  // the only version the router ever sees. Naming a RouterOS assertion in this
  // function is safe because the brand gate above has already refused every
  // other family.
  return assembleRendering(texts, table, assertConsoleLine);
}

/**
 * The value `registerChangeRenderer()` is given. It exists as a named export so
 * the composition root reads as a wiring statement rather than as a lambda, and
 * so a test can assert that what is registered is this and not a stub.
 */
export const routerOsChangeRenderer: ChangeRenderer = renderChangeForJob;
