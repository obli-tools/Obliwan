import { isTerminalJobStatus, type ChangeJobStatus } from '@obliwan/shared';
import type { Knex } from 'knex';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { KillSwitchEngagedError, killSwitchSentenceFr } from './killSwitch.service';
import { DeviceBusyError, shouldProcessJobs } from './jobQueue.service';
import { LegacyComplianceError, enqueueLegacyComplianceJob } from './legacyCompliance.service';

/**
 * jobFollowup.service.ts — a change job the worker queues once ANOTHER one has
 * SUCCEEDED on the same device (`change_job_followups`, migration 072).
 *
 *   recordFollowup(input, trx?)   the promise, written beside the first job
 *   settleFollowupsOf(jobId)      keep the promises waiting on a job that has
 *                                 just settled (apply.service `runJob`)
 *   sweepJobFollowups()           the same for every open promise whose job is
 *                                 terminal — aborts, reaped leases, a worker
 *                                 that died between the job and its promise,
 *                                 an enqueue that failed for no named reason
 *   startJobFollowupRuntime()     the periodic sweep (index.ts)
 *
 * Two users, both on the reconciliation page: the bulk attach
 * (fleet/reconcileAttach.service.ts) queues `management_access` on every
 * router it attaches and, when asked, promises `legacy_compliance` after it;
 * the workspace-wide re-apply (fleet/accessCheck.service.ts, source
 * `access_check`) does the same for each router whose access it found missing
 * or broken.
 * The two cannot be queued together — `change_jobs_one_in_flight_uq` holds one
 * active job per device, and that is a safety property — so the second is
 * written down here and queued by the worker. What became of the promise is
 * shown on the device's compliance card (`getLegacyComplianceView().followUp`).
 *
 * ┌─ HOW A PROMISE IS KEPT ──────────────────────────────────────────────────┐
 * │ Only once the first job is TERMINAL, and exactly once:                   │
 * │   - it SUCCEEDED ->                                                      │
 * │       1. a `legacy_compliance` job of that device created AFTER the      │
 * │          promise is ADOPTED: `queued` with its id, nothing enqueued.     │
 * │          That is the crash window — the enqueue committed, the promise's │
 * │          row did not — and also a job the operator queued by hand in     │
 * │          the meantime; enqueueing again would only be refused (busy).    │
 * │       2. the confirming user deleted -> `refused` (confirmation_lost);   │
 * │       3. the confirmation older than FOLLOWUP_CONFIRMATION_MAX_AGE_HOURS │
 * │          at this instant -> `skipped` (confirmation_stale): an operator  │
 * │          who confirmed a degraded job for a batch did not confirm it for │
 * │          whenever the first job ends;                                    │
 * │       4. otherwise the second job is enqueued through its kind's own    │
 * │          door (`enqueueLegacyComplianceJob`, `allowExisting: false`)     │
 * │          with the operator who asked and the safety-net confirmation    │
 * │          stored with the promise — its instant included: the job's      │
 * │          `degraded_confirmed_at` is when the OPERATOR confirmed, not     │
 * │          when the worker queued. `queued` with its id, or `refused` with │
 * │          the door's code and sentence (kill switch, another job on the  │
 * │          device, the device's own rules) — a NAMED refusal is final:     │
 * │          the operator queues it from the device page. An error the door  │
 * │          does not name (a dropped connection, a deadlock) is not a       │
 * │          refusal: the promise stays OPEN, `attempts` + 1, and the sweep  │
 * │          tries again; the FOLLOWUP_MAX_ATTEMPTS-th closes it `refused`  │
 * │          (`error`).                                                      │
 * │   - anything else (failed — a job refused at lint is a failed job —,     │
 * │     aborted, rolled back) -> `skipped`, nothing queued, the first job's  │
 * │     status as the reason and its error beside it. A job that did not     │
 * │     bring the router in line is no ground for the next one.             │
 * │ The promise's row is locked (FOR UPDATE SKIP LOCKED) for the whole       │
 * │ decision, so the worker that settled the job and the sweep cannot both  │
 * │ keep it; the enqueue itself runs on its own connection.                  │
 * │ NOTHING HERE THROWS into a job's outcome: `settleFollowupsOf` is called │
 * │ after the job's terminal status is written, and swallows (and logs)     │
 * │ every error — the sweep keeps the promise later.                        │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * SOCKET EVENTS. A promise kept as `queued` by an enqueue is announced by the
 * enqueue itself (`JOB_QUEUED` to the tenant and the device). A promise closed
 * `refused` or `skipped` emits NOTHING: no existing event means "a promised
 * job was not queued" (`DEVICE_UPDATED` carries a device row, the `JOB_*`
 * events a job row, and a client folds either into its stores), and the card
 * that shows the outcome reloads on its own timer.
 *
 * Operator-facing sentences are French, like the change jobs' own.
 */

// ============================================================================
// Vocabulary (mirrors migration 072's CHECKs)
// ============================================================================

export const FOLLOWUP_THEN_KINDS = ['legacy_compliance'] as const;
export type FollowupThenKind = (typeof FOLLOWUP_THEN_KINDS)[number];

export const FOLLOWUP_OUTCOMES = ['queued', 'refused', 'skipped'] as const;
export type FollowupOutcome = (typeof FOLLOWUP_OUTCOMES)[number];

/** `access_check`: the workspace-wide re-apply of the reconciliation page
 *  (fleet/accessCheck.service.ts, migration 092 widened the CHECK). */
export const FOLLOWUP_SOURCES = ['reconcile_attach', 'access_check'] as const;
export type FollowupSource = (typeof FOLLOWUP_SOURCES)[number];

/** How often the sweep runs. A promise whose job settled through `runJob` is
 *  kept at once; the sweep is for the other endings (abort, reaper) and the
 *  retries of an enqueue that failed for no named reason. */
export const JOB_FOLLOWUP_SWEEP_INTERVAL_MS = 30_000;
/** Enqueues failed for no named reason before the promise is closed `refused`
 *  (`error`). The 5th failure closes it. */
export const FOLLOWUP_MAX_ATTEMPTS = 5;
/** Age of the safety-net confirmation past which a promise is closed `skipped`
 *  (`confirmation_stale`) instead of queueing a job on it. */
export const FOLLOWUP_CONFIRMATION_MAX_AGE_HOURS = 24;
/** Promises kept per sweep at most. */
const SWEEP_BATCH = 50;
const DETAIL_MAX = 2000;

// ============================================================================
// Recording
// ============================================================================

export interface RecordFollowupInput {
  tenantId: number;
  deviceId: number;
  afterJobId: number;
  thenKind: FollowupThenKind;
  requestedBy: number | null;
  /** The confirmation of the degraded level the second job will carry. */
  confirmedBy: number;
  confirmedAt?: Date;
  source: FollowupSource;
  correlationId?: string | null;
}

export async function recordFollowup(input: RecordFollowupInput, q: Knex | Knex.Transaction = db): Promise<number> {
  const [row] = (await q('change_job_followups')
    .insert({
      tenant_id: input.tenantId,
      device_id: input.deviceId,
      after_job_id: input.afterJobId,
      then_kind: input.thenKind,
      requested_by: input.requestedBy,
      confirmed_by: input.confirmedBy,
      confirmed_at: input.confirmedAt ?? new Date(),
      source: input.source,
      correlation_id: input.correlationId ?? null,
    })
    .returning('id')) as Array<{ id: string | number }>;
  return Number(row.id);
}

// ============================================================================
// Keeping a promise
// ============================================================================

export interface FollowupSettlement {
  followupId: number;
  afterJobId: number;
  deviceId: number;
  thenKind: FollowupThenKind;
  outcome: FollowupOutcome;
  reason: string | null;
  message: string | null;
  thenJobId: number | null;
}

interface FollowupRow {
  id: string | number;
  tenant_id: number;
  device_id: number;
  after_job_id: string | number;
  then_kind: FollowupThenKind;
  requested_by: number | null;
  confirmed_by: number | null;
  confirmed_at: Date;
  attempts: number;
  /** Computed on the database's clock (`settleOne`). */
  confirmation_stale: boolean;
}

interface AfterJobRow {
  id: string | number;
  kind: string;
  status: ChangeJobStatus;
  error_kind: string | null;
  error_message: string | null;
}

type Decision = Pick<FollowupSettlement, 'reason' | 'message' | 'thenJobId'> & {
  /** `retry`: an error nobody named; the promise stays open. */
  outcome: FollowupOutcome | 'retry';
};

const KIND_LABEL: Record<string, string> = {
  management_access: "d’accès de gestion",
  legacy_compliance: 'des correctifs des modèles',
};
const THEN_LABEL: Record<FollowupThenKind, string> = {
  legacy_compliance: 'les correctifs des modèles',
};

function clip(text: string): string {
  return text.length > DETAIL_MAX ? `${text.slice(0, DETAIL_MAX - 1)}…` : text;
}

/** The second job, once the first has SUCCEEDED: adopted, refused, skipped,
 *  enqueued, or `retry` (see the header, 1–4). */
async function enqueueThen(f: FollowupRow, afterJob: AfterJobRow, trx: Knex.Transaction): Promise<Decision> {
  const then = THEN_LABEL[f.then_kind];

  // 1. Already there: the enqueue committed and the promise did not (a crash
  //    between the two), or somebody queued it in the meantime. Compared on
  //    the database's own timestamps (a JS Date would truncate microseconds).
  const adopted = (await trx('change_jobs')
    .where({ tenant_id: f.tenant_id, device_id: f.device_id, kind: f.then_kind })
    .where('created_at', '>', trx('change_job_followups').select('created_at').where({ id: f.id }))
    .orderBy('id', 'asc')
    .first('id')) as { id: string | number } | undefined;
  if (adopted) {
    logger.info({ followupId: Number(f.id), jobId: Number(adopted.id) }, 'job follow-up: an existing job adopted, nothing enqueued');
    return { outcome: 'queued', reason: null, message: null, thenJobId: Number(adopted.id) };
  }

  // 2. Nobody to carry the confirmation.
  if (f.confirmed_by === null) {
    return {
      outcome: 'refused',
      reason: 'confirmation_lost',
      message:
        `L’utilisateur qui avait confirmé le niveau de sécurité dégradé n’existe plus : ${then} n’ont pas été mis en ` +
        'file. Lancez-les depuis la fiche de l’équipement.',
      thenJobId: null,
    };
  }

  // 3. A confirmation given too long ago.
  if (f.confirmation_stale) {
    return {
      outcome: 'skipped',
      reason: 'confirmation_stale',
      message:
        `La confirmation du niveau de sécurité dégradé, donnée avec la demande, avait plus de ` +
        `${FOLLOWUP_CONFIRMATION_MAX_AGE_HOURS} h au moment de les mettre en file, après la tâche ` +
        `${KIND_LABEL[afterJob.kind] ?? `« ${afterJob.kind} »`} #${Number(afterJob.id)} : ${then} n’ont pas été mis en ` +
        'file sur une confirmation aussi ancienne. ' +
        'Lancez-les depuis la fiche de l’équipement.',
      thenJobId: null,
    };
  }

  // 4. The door.
  try {
    const out = await enqueueLegacyComplianceJob({
      tenantId: f.tenant_id,
      deviceId: f.device_id,
      requestedBy: f.requested_by,
      confirmDegraded: { userId: f.confirmed_by, at: f.confirmed_at },
      allowExisting: false,
    });
    return { outcome: 'queued', reason: null, message: null, thenJobId: out.jobId };
  } catch (err) {
    if (err instanceof LegacyComplianceError) {
      return { outcome: 'refused', reason: err.kind, message: clip(err.message), thenJobId: null };
    }
    // `scope: null` is the kill switch's own read failing (it fails closed):
    // a transient error, retried like any unnamed one — only a switch READ as
    // engaged closes the promise.
    if (err instanceof KillSwitchEngagedError && err.scope === null) {
      return { outcome: 'retry', reason: 'error', message: null, thenJobId: null };
    }
    if (err instanceof KillSwitchEngagedError) {
      return {
        outcome: 'refused',
        reason: 'kill_switch',
        message: clip(
          `${killSwitchSentenceFr(err)} : ${then} n’ont pas été mis en file. Lancez-les depuis la fiche de l’équipement ` +
            'une fois l’arrêt levé.',
        ),
        thenJobId: null,
      };
    }
    if (err instanceof DeviceBusyError) {
      return {
        outcome: 'refused',
        reason: 'device_busy',
        message: `Une autre tâche est en cours sur ce routeur : ${then} n’ont pas été mis en file. Lancez-les depuis la fiche de l’équipement quand elle sera terminée.`,
        thenJobId: null,
      };
    }
    logger.error(
      { err, followupId: Number(f.id), deviceId: f.device_id, attempt: f.attempts + 1, maxAttempts: FOLLOWUP_MAX_ATTEMPTS },
      'job follow-up: the enqueue failed unexpectedly',
    );
    return { outcome: 'retry', reason: 'error', message: null, thenJobId: null };
  }
}

/** Keep ONE open promise, if the job it waits on is terminal. Null: nothing
 *  to do (already kept, being kept by another process, the job is still
 *  running, or an unnamed enqueue error left it open for another attempt).
 *  May throw (the callers catch). */
async function settleOne(followupId: number): Promise<FollowupSettlement | null> {
  return db.transaction(async (trx) => {
    const f = (await trx('change_job_followups')
      .where({ id: followupId })
      .whereNull('done_at')
      .forUpdate()
      .skipLocked()
      .first(
        'id', 'tenant_id', 'device_id', 'after_job_id', 'then_kind', 'requested_by', 'confirmed_by', 'confirmed_at', 'attempts',
        // The database's clock, the one `confirmed_at` is compared with
        // everywhere else. Literals only: no `?` in a raw (project convention).
        trx.raw(`(confirmed_at < now() - interval '${FOLLOWUP_CONFIRMATION_MAX_AGE_HOURS} hours') AS confirmation_stale`),
      )) as FollowupRow | undefined;
    if (!f) return null;
    const job = (await trx('change_jobs')
      .where({ id: f.after_job_id })
      .first('id', 'kind', 'status', 'error_kind', 'error_message')) as AfterJobRow | undefined;
    // No job: the cascade removes the promise with it, so this is a row being
    // deleted under us. Leave it.
    if (!job || !isTerminalJobStatus(job.status)) return null;

    let decision: Decision;
    let attempts = f.attempts;
    if (job.status === 'succeeded') {
      decision = await enqueueThen(f, job, trx);
    } else {
      const label = KIND_LABEL[job.kind] ?? `« ${job.kind} »`;
      const why = [job.error_kind ? `(${job.error_kind})` : null, job.error_message?.trim() || null].filter(Boolean).join(' ');
      decision = {
        outcome: 'skipped',
        reason: `after_job_${job.status}`,
        message: clip(
          `La tâche ${label} #${Number(job.id)} s’est terminée « ${job.status} » : ${THEN_LABEL[f.then_kind]} n’ont pas été ` +
            `mis en file.${why ? ` ${why}` : ''}`,
        ),
        thenJobId: null,
      };
    }

    let final: Pick<FollowupSettlement, 'outcome' | 'reason' | 'message' | 'thenJobId'>;
    if (decision.outcome === 'retry') {
      attempts += 1;
      if (attempts < FOLLOWUP_MAX_ATTEMPTS) {
        // Left OPEN: the sweep tries again. Not a refusal — nobody refused.
        await trx('change_job_followups').where({ id: f.id }).update({ attempts });
        logger.warn(
          { followupId: Number(f.id), deviceId: f.device_id, attempts, maxAttempts: FOLLOWUP_MAX_ATTEMPTS },
          'job follow-up: left open after an unexpected enqueue error, the sweep tries again',
        );
        return null;
      }
      final = {
        outcome: 'refused',
        reason: 'error',
        message:
          `Erreur interne à la mise en file, ${attempts} tentatives : ${THEN_LABEL[f.then_kind]} n’ont pas été mis en file ` +
          '(voir le journal du serveur). Lancez-les depuis la fiche de l’équipement.',
        thenJobId: null,
      };
    } else {
      final = { outcome: decision.outcome, reason: decision.reason, message: decision.message, thenJobId: decision.thenJobId };
    }

    await trx('change_job_followups').where({ id: f.id }).update({
      done_at: trx.fn.now(),
      outcome: final.outcome,
      outcome_reason: final.reason,
      outcome_detail: final.message,
      then_job_id: final.thenJobId,
      attempts,
    });
    const settlement: FollowupSettlement = {
      followupId: Number(f.id),
      afterJobId: Number(f.after_job_id),
      deviceId: f.device_id,
      thenKind: f.then_kind,
      ...final,
    };
    logger.info(
      { followupId: settlement.followupId, afterJobId: settlement.afterJobId, deviceId: f.device_id, outcome: final.outcome, reason: final.reason, thenJobId: final.thenJobId },
      `job follow-up kept: ${f.then_kind} ${final.outcome}`,
    );
    return settlement;
  });
}

async function settleMany(ids: readonly number[]): Promise<FollowupSettlement[]> {
  const out: FollowupSettlement[] = [];
  for (const id of ids) {
    try {
      const s = await settleOne(id);
      if (s) out.push(s);
    } catch (err) {
      // Left open: the next sweep tries again.
      logger.error({ err, followupId: id }, 'job follow-up: could not be kept this time');
    }
  }
  return out;
}

/**
 * Keep the promises waiting on this job, once it is terminal (apply.service
 * `runJob`, after the job's own outcome is written). NEVER THROWS.
 */
export async function settleFollowupsOf(jobId: number): Promise<FollowupSettlement[]> {
  try {
    const rows = (await db('change_job_followups')
      .where({ after_job_id: jobId })
      .whereNull('done_at')
      .orderBy('id')
      .select('id')) as Array<{ id: string | number }>;
    return await settleMany(rows.map((r) => Number(r.id)));
  } catch (err) {
    logger.error({ err, jobId }, 'job follow-up: the promises of a settled job could not be read');
    return [];
  }
}

export interface SweepFollowupOptions {
  /** Default: this process takes change jobs (`shouldProcessJobs`). */
  isLeader?: () => boolean;
  limit?: number;
}

/** Every open promise whose job is terminal, oldest first. Never throws. */
export async function sweepJobFollowups(options: SweepFollowupOptions = {}): Promise<FollowupSettlement[]> {
  const gate = options.isLeader ?? shouldProcessJobs;
  if (!gate()) return [];
  try {
    const rows = (await db('change_job_followups as f')
      .join('change_jobs as j', 'j.id', 'f.after_job_id')
      .whereNull('f.done_at')
      .whereIn('j.status', ['succeeded', 'rolled_back', 'failed', 'aborted'])
      .orderBy('f.id')
      .limit(options.limit ?? SWEEP_BATCH)
      .select('f.id')) as Array<{ id: string | number }>;
    return await settleMany(rows.map((r) => Number(r.id)));
  } catch (err) {
    logger.error({ err }, 'job follow-up sweep failed');
    return [];
  }
}

// ============================================================================
// Runtime
// ============================================================================

let timer: NodeJS.Timeout | null = null;
let running: Promise<unknown> | null = null;

/** Arm the periodic sweep (index.ts, after the change worker). */
export function startJobFollowupRuntime(intervalMs: number = JOB_FOLLOWUP_SWEEP_INTERVAL_MS): void {
  if (timer) return;
  timer = setInterval(() => {
    if (running) return; // a slow pass is never stacked under the next one
    running = sweepJobFollowups().finally(() => {
      running = null;
    });
  }, Math.max(10, Math.floor(intervalMs)));
  timer.unref?.();
  logger.info({ intervalMs }, 'Job follow-up sweep armed (on the processes that take change jobs)');
}

/** Disarm, and wait for a pass in flight so it cannot queue after shutdown. */
export async function stopJobFollowupRuntime(): Promise<void> {
  if (timer) clearInterval(timer);
  timer = null;
  if (running) await running.catch(() => undefined);
}
