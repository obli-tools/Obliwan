/**
 * ObliWAN — the `infra_account` change job: one site's account on its
 * customer's infrastructure concentrator, written ONLY through the queue.
 *
 *   enqueueInfraAccount({ concentratorId, siteId, action })   queue (idempotently)
 *   runInfraAccountApply / runInfraAccountVerify              the job's two steps
 *   settleInfraAccount                                         mirror onto the registry
 *
 * The job is queued on the concentrator's DEVICE row (a CHR: the devices row
 * whose RouterOS API transport is dialled), in that device's tenant, and run
 * by `runPhases()` in apply.service.ts: identity assertion on a fresh
 * socket, guard, kill switch (the device's tenant there, the SITE's tenant
 * again here), then this module's two steps through the concentrator's driver.
 *
 * An OPNsense is REFUSED at the door (NOT_IMPLEMENTED_YET, no job), and again
 * by its driver if a job ever reached it. Tomorrow's work is its driver body,
 * plus one decision this module cannot take alone: `change_jobs.device_id` is
 * NOT NULL, and an OPNsense has no devices row today.
 *
 * ┌─ NO BACKUP, NO DEAD-MAN, AND WHY ──────────────────────────────────────────┐
 * │ `ensure` adds one /ppp/secret under a name the CHR does not have, and     │
 * │ refuses when the name exists with other attributes: it overwrites and     │
 * │ removes nothing. `revoke` removes ONE entry, and only one whose comment    │
 * │ says ObliWAN created it for this site; its undo is this job's `ensure`,    │
 * │ from the vault-held password. Neither touches a route, an address, a       │
 * │ filter or the CHR's own management path: there is nothing for a backup to │
 * │ restore that the job cannot, and nothing for a dead-man to revert.        │
 * └────────────────────────────────────────────────────────────────────────────┘
 */

import {
  ACTIVE_CHANGE_JOB_STATUSES,
  INFRA_ACCOUNT_ACTIONS,
  INFRA_ACCOUNT_KIND,
  MASTER_TENANT_ID,
  SOCKET_EVENTS,
  infraAccountKindFor,
  type ChangeJobStatus,
  type InfraAccountAction,
  type InfraAccountJobState,
  type InfraAccountOutcome,
  type InfraPlanView,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import type { ChangeJobRow } from '../change/jobQueue.service';
import { assertWritable } from '../change/killSwitch.service';
import { emitToDevice } from '../fleet/fleetEvents';
import { emitToTenantAudience } from '../fleet/scopedEmit';
import { resolveL2tpSpec } from './credentials';
import { driverFor } from './drivers';
import { OPNSENSE_NOT_IMPLEMENTED_MESSAGE } from './opnsense.driver';
import { assertNotManagementConcentrator, getInfraConcentratorRow, noteJobQueued, noteJobSettled } from './store';
import {
  InfraConcentratorError,
  NOT_IMPLEMENTED_YET,
  type InfraConcentratorRow,
  type InfraExecContext,
  type InfraJobSpec,
  type InfraStepResult,
} from './types';

export const INFRA_ACCOUNT_NO_BACKUP =
  "'infra_account' ajoute un seul compte sous un nom absent du concentrateur, ou retire un seul compte que " +
  "ObliWAN y a lui-même créé pour ce site : rien n'est écrasé, et l'annulation est la même tâche en sens " +
  'inverse. Aucune sauvegarde préalable ne rendrait cela plus sûr.';
export const INFRA_ACCOUNT_NO_DEADMAN =
  "'infra_account' ne touche ni route, ni adresse, ni filtre, ni le chemin de gestion du concentrateur : " +
  "il n'y a rien qu'un dead-man puisse rétablir, aucun n'est armé (niveau de sécurité degraded, qui dit la vérité).";
export const INFRA_ACCOUNT_NO_APPLY_OUTCOME =
  "Aucune ligne dans apply_outcomes : 'infra_account' est un compte ajouté ou retiré sans filet, pas une " +
  "observation de la tenue d'un équipement à un changement. Son issue est sur infra_account_jobs.";

/** The services/change refusal for this kind (apply.service turns it into a
 *  `ChangeRefusedError` with the same kind). */
export class InfraAccountJobError extends Error {
  constructor(readonly kind: string, message: string) {
    super(message);
    this.name = 'InfraAccountJobError';
  }
}

export function infraAccountGuard(): { verdict: 'ACCEPT'; reasons: unknown[]; summary: string; unavailable: false } {
  return {
    verdict: 'ACCEPT',
    reasons: [
      {
        code: 'INFRA_ACCOUNT_SINGLE_ENTRY',
        effect: 'accept',
        message:
          "Adds one account on the customer's infrastructure concentrator, or removes one ObliWAN itself added " +
          'for this site; refuses instead of overwriting. No route, address, filter or management path is touched.',
      },
    ],
    summary:
      'Management-Path Guard: ACCEPT — one infrastructure account added or removed removes no management path ' +
      '(no plan was simulated: the job refuses every case that is not that single entry).',
    unavailable: false,
  };
}

// ============================================================================
// Rows
// ============================================================================

async function loadJobSpec(jobId: number): Promise<InfraJobSpec> {
  const r = (await db('infra_account_jobs')
    .where({ job_id: jobId })
    .first(
      'job_id', 'tenant_id', 'site_id', 'concentrator_id', 'action', 'identifier',
      db.raw('host(remote_address) AS remote_address'), 'ppp_profile', 'comment', 'outcome',
    )) as Record<string, unknown> | undefined;
  if (!r) {
    throw new InfraAccountJobError('infra_account_missing', `Le job ${jobId} n'a pas de ligne infra_account_jobs : rien ne dit quel site il concerne.`);
  }
  return {
    jobId: Number(r.job_id),
    tenantId: Number(r.tenant_id),
    siteId: Number(r.site_id),
    concentratorId: Number(r.concentrator_id),
    action: r.action as InfraAccountAction,
    identifier: String(r.identifier),
    remoteAddress: (r.remote_address as string | null) ?? null,
    pppProfile: (r.ppp_profile as string | null) ?? null,
    comment: String(r.comment),
    outcome: (r.outcome as InfraAccountOutcome | null) ?? null,
  };
}

async function recordFound(jobId: number, outcome: InfraAccountOutcome, detail: string): Promise<void> {
  await db('infra_account_jobs').where({ job_id: jobId }).update({ outcome, outcome_detail: detail.slice(0, 4000), updated_at: db.fn.now() });
}

function asJobError(err: unknown): unknown {
  if (err instanceof InfraConcentratorError) return new InfraAccountJobError(err.code, err.message);
  return err;
}

async function concentratorFor(spec: InfraJobSpec, job: ChangeJobRow): Promise<InfraConcentratorRow> {
  const c = await getInfraConcentratorRow(spec.concentratorId).catch(() => null);
  if (!c) throw new InfraAccountJobError('concentrator_not_found', `Le concentrateur ${spec.concentratorId} n'existe plus. Rien n'a été écrit.`);
  if (!c.enabled) throw new InfraAccountJobError('concentrator_disabled', `Le concentrateur ${c.name} est désactivé. Rien n'a été écrit.`);
  if (c.device_id !== job.device_id) {
    throw new InfraAccountJobError(
      'concentrator_moved',
      `Le concentrateur ${c.name} n'est plus lié à l'appareil sur lequel ce job a été mis en file. Rien n'a été écrit.`,
    );
  }
  return c;
}

// ============================================================================
// The job's two steps (called from apply.service.ts runPhases)
// ============================================================================

export async function runInfraAccountApply(
  job: ChangeJobRow,
  device: { id: number; uuid?: string | null; name?: string | null },
  correlationId: string,
  onWrite: () => void = () => undefined,
): Promise<InfraStepResult> {
  const jobId = Number(job.id);
  const spec = await loadJobSpec(jobId);
  // runPhases checked the device tenant's kill switch; the write is made for
  // the SITE's tenant, whose switch stops it too.
  await assertWritable(spec.tenantId);
  const c = await concentratorFor(spec, job);
  const driver = driverFor(c.kind);
  const ctx: InfraExecContext = { auditTenantId: job.tenant_id, jobId, correlationId, device, onWrite };
  try {
    const result = spec.action === 'revoke' ? await driver.revoke(c, spec, ctx) : await driver.apply(c, spec, ctx);
    if (result.outcome) await recordFound(jobId, result.outcome, result.output);
    return result;
  } catch (err) {
    if (err instanceof InfraConcentratorError && err.outcome === 'conflict') await recordFound(jobId, 'conflict', err.message);
    throw asJobError(err);
  }
}

export async function runInfraAccountVerify(
  job: ChangeJobRow,
  device: { id: number; uuid?: string | null; name?: string | null },
  correlationId: string,
): Promise<InfraStepResult> {
  const jobId = Number(job.id);
  const spec = await loadJobSpec(jobId); // re-read: the apply step recorded the outcome
  const c = await concentratorFor(spec, job);
  const ctx: InfraExecContext = { auditTenantId: job.tenant_id, jobId, correlationId, device };
  try {
    return await driverFor(c.kind).verify(c, spec, ctx);
  } catch (err) {
    throw asJobError(err);
  }
}

/**
 * Mirror a finished job onto `infra_site_accounts`. Never throws.
 * Success: `provisioned` (ensure) or `revoked` (revoke), observed now.
 * Failure: `error` ONLY when the job read the concentrator and found the
 * account wrong (outcome 'conflict'); any other failure (unreachable,
 * identity, kill switch, lost worker) proves nothing about the account and
 * leaves its state as it was — only the detail and the job move.
 */
export async function settleInfraAccount(
  job: Pick<ChangeJobRow, 'id'>,
  result: { ok: true } | { ok: false; error: string },
): Promise<void> {
  const jobId = Number(job.id);
  try {
    const spec = await loadJobSpec(jobId).catch(() => null);
    if (!spec) return;
    if (result.ok) {
      await noteJobSettled({
        tenantId: spec.tenantId, siteId: spec.siteId, concentratorId: spec.concentratorId, jobId,
        state: spec.action === 'revoke' ? 'revoked' : 'provisioned',
        observed: true,
        detail:
          (await db('infra_account_jobs').where({ job_id: jobId }).first('outcome_detail'))?.outcome_detail ??
          (spec.action === 'revoke' ? 'retiré' : 'présent'),
      });
      return;
    }
    const conflict = spec.outcome === 'conflict';
    await noteJobSettled({
      tenantId: spec.tenantId, siteId: spec.siteId, concentratorId: spec.concentratorId, jobId,
      // A refused revoke (an adopted account, not created by ObliWAN) leaves a
      // present, working account: still provisioned, the reason in detail.
      state: conflict ? (spec.action === 'revoke' ? 'provisioned' : 'error') : null,
      observed: conflict,
      detail: result.error || "le job d'infrastructure a échoué",
    });
  } catch (err) {
    logger.warn({ err: err instanceof Error ? err.message : String(err), jobId }, 'infra account: the outcome could not be mirrored');
  }
}

// ============================================================================
// Preview and enqueue
// ============================================================================

export interface InfraEnqueueInput {
  concentratorId: number;
  siteId: number;
  action?: InfraAccountAction;
  requestedBy?: number | null;
}

const ACTIVE: readonly string[] = ACTIVE_CHANGE_JOB_STATUSES;
const NO_BASE_STATE = '0'.repeat(64);

async function assertSiteOf(c: InfraConcentratorRow, siteId: number): Promise<void> {
  const site = await db('sites').where({ id: siteId, tenant_id: c.tenant_id }).first('id');
  if (!site) throw new InfraConcentratorError('site_not_found', `Le site ${siteId} n'existe pas dans le tenant de ce concentrateur.`, 404);
}

export async function previewInfraAccount(input: { concentratorId: number; siteId: number; action?: InfraAccountAction }): Promise<InfraPlanView> {
  const c = await getInfraConcentratorRow(input.concentratorId);
  await assertSiteOf(c, input.siteId);
  const action = input.action ?? 'ensure';
  return driverFor(c.kind).plan(c, { tenantId: c.tenant_id, siteId: input.siteId }, action);
}

export async function readInfraAccount(input: { concentratorId: number; siteId: number }): Promise<InfraPlanView> {
  const c = await getInfraConcentratorRow(input.concentratorId);
  await assertSiteOf(c, input.siteId);
  return driverFor(c.kind).readSiteEntry(c, { tenantId: c.tenant_id, siteId: input.siteId });
}

export async function infraAccountJobInFlight(concentratorId: number, siteId: number): Promise<number | null> {
  const row = (await db('infra_account_jobs as i')
    .join('change_jobs as j', 'j.id', 'i.job_id')
    .where('i.concentrator_id', concentratorId)
    .where('i.site_id', siteId)
    .whereIn('j.status', ACTIVE as string[])
    .orderBy('i.job_id', 'desc')
    .first('i.job_id')) as { job_id: string | number } | undefined;
  return row ? Number(row.job_id) : null;
}

/**
 * Queue a job for this site's account. Idempotent: a job of this site on this
 * concentrator still in flight is returned instead of a second one. Domain
 * refusals throw `InfraConcentratorError` (French, with an HTTP status); no
 * job is queued for them.
 */
export async function enqueueInfraAccount(input: InfraEnqueueInput): Promise<InfraAccountJobState> {
  const action = input.action ?? 'ensure';
  if (!(INFRA_ACCOUNT_ACTIONS as readonly string[]).includes(action)) {
    throw new InfraConcentratorError('invalid_request', `Action inconnue : ${String(action)}.`);
  }
  const c = await getInfraConcentratorRow(input.concentratorId);
  await assertSiteOf(c, input.siteId);
  if (!driverFor(c.kind).writesImplemented) {
    throw new InfraConcentratorError(NOT_IMPLEMENTED_YET, OPNSENSE_NOT_IMPLEMENTED_MESSAGE, 501);
  }
  if (!c.enabled) throw new InfraConcentratorError('concentrator_disabled', `Le concentrateur ${c.name} est désactivé.`, 409);
  if (c.device_id === null) {
    throw new InfraConcentratorError('no_device', "Ce CHR n'est lié à aucun appareil : ObliWAN ne sait pas comment le joindre.", 422);
  }
  const device = (await db('devices').where({ id: c.device_id }).first('id', 'tenant_id', 'name', 'status', 'is_managed')) as
    | { id: number; tenant_id: number; name: string; status: string; is_managed: boolean }
    | undefined;
  if (!device || (device.tenant_id !== c.tenant_id && device.tenant_id !== MASTER_TENANT_ID)) {
    throw new InfraConcentratorError('no_device', `L'appareil du concentrateur ${c.name} n'est plus utilisable.`, 422);
  }
  if (device.status === 'disabled' || device.status === 'quarantined') {
    throw new InfraConcentratorError('device_not_writable', `L'appareil ${device.name} est ${device.status} : rien n'y est écrit.`, 409);
  }
  // Checked again at enqueue: the device may have become a management concentrator since it was bound.
  await assertNotManagementConcentrator(device.id, device.name);
  if (!device.is_managed) {
    throw new InfraConcentratorError(
      'device_not_managed',
      `L'appareil ${device.name} n'est pas marqué géré : ObliWAN n'y écrit pas. Marquez-le géré sur sa page.`,
      409,
    );
  }

  // Frozen non-secret attributes; the password is not read here.
  const spec = await resolveL2tpSpec(c, c.tenant_id, input.siteId);
  if (action === 'ensure' && !spec.passwordResolvable) {
    throw new InfraConcentratorError(
      'password_unresolved',
      `La variable « ${c.params.passwordKey} » (mot de passe PPP d'infrastructure) n'a pas de valeur pour ce site.`,
      422,
    );
  }

  const inflight = await infraAccountJobInFlight(c.id, input.siteId);
  if (inflight !== null) return getInfraAccountJobState(inflight);

  let jobId: number;
  try {
    const guard = infraAccountGuard();
    jobId = await db.transaction(async (trx) => {
      const [inserted] = (await trx('change_jobs')
        .insert({
          tenant_id: device.tenant_id,
          device_id: device.id,
          plan_id: null,
          kind: INFRA_ACCOUNT_KIND,
          status: 'queued',
          attempt: 0,
          max_attempts: 1,
          base_state_hash: NO_BASE_STATE,
          safety_level: 'degraded',
          safety_peer_device_id: null,
          guard_verdict: guard.verdict,
          guard_reasons: JSON.stringify(guard.reasons),
          requested_by: input.requestedBy ?? null,
        })
        .returning('id')) as Array<{ id: string | number }>;
      const id = Number(inserted.id);
      await trx('infra_account_jobs').insert({
        job_id: id,
        tenant_id: c.tenant_id,
        site_id: input.siteId,
        concentrator_id: c.id,
        action,
        account_kind: infraAccountKindFor(c.kind),
        identifier: spec.name,
        remote_address: spec.remoteAddress,
        ppp_profile: spec.profile,
        comment: spec.comment,
      });
      return id;
    });
  } catch (err) {
    const pg = err as { code?: string; constraint?: string; message?: string };
    if (pg.code === '23505' && pg.constraint === 'change_jobs_one_in_flight_uq') {
      throw new InfraConcentratorError('concentrator_busy', `L'appareil ${device.name} a déjà un job en cours ; réessayez dans un instant.`, 409);
    }
    if (pg.code === '23001') {
      throw new InfraConcentratorError('subtree_interlock', `Verrou de sous-arbre : ${pg.message ?? ''}`, 409);
    }
    throw err;
  }
  await noteJobQueued({ tenantId: c.tenant_id, siteId: input.siteId, concentrator: c, identifier: spec.name, jobId });
  const summary = { jobId, deviceId: device.id, kind: INFRA_ACCOUNT_KIND, status: 'queued' };
  emitToTenantAudience(device.tenant_id, SOCKET_EVENTS.JOB_QUEUED, summary, { deviceId: device.id });
  emitToDevice(device.id, SOCKET_EVENTS.JOB_QUEUED, summary);
  logger.info({ jobId, concentratorId: c.id, siteId: input.siteId, action }, 'infra account job QUEUED');
  return { jobId, state: 'pending', outcome: null, message: `Job ${jobId} mis en file sur ${device.name}.` };
}

export async function getInfraAccountJobState(jobId: number): Promise<InfraAccountJobState> {
  const row = (await db('change_jobs as j')
    .join('infra_account_jobs as i', 'i.job_id', 'j.id')
    .where('j.id', jobId)
    .first('j.status', 'j.error_kind', 'j.error_message', 'i.outcome', 'i.outcome_detail')) as
    | { status: ChangeJobStatus; error_kind: string | null; error_message: string | null; outcome: InfraAccountOutcome | null; outcome_detail: string | null }
    | undefined;
  if (!row) throw new InfraConcentratorError('job_not_found', `Le job ${jobId} n'est pas un job infra_account.`, 404);
  if (row.status === 'succeeded') {
    return { jobId, state: 'succeeded', outcome: row.outcome, message: row.outcome_detail ?? 'terminé' };
  }
  if (ACTIVE.includes(row.status)) {
    return { jobId, state: 'pending', outcome: row.outcome, message: `job ${jobId} : ${row.status}` };
  }
  return {
    jobId,
    state: 'failed',
    outcome: row.outcome,
    message: row.error_message ?? row.outcome_detail ?? `job ${jobId} terminé ${row.status}`,
    code: row.error_kind ?? row.status,
  };
}
