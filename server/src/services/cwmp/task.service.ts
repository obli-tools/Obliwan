/**
 * ObliWAN — the per-CPE task queue.
 *
 * ┌─ WHY A QUEUE AND NOT A REQUEST ───────────────────────────────────────────┐
 * │ Every other transport in this product is SYNCHRONOUS: the arbiter dials   │
 * │ the box and waits. TR-069 is the opposite — the CPE dials US, once every  │
 * │ few minutes, and the ACS has a few seconds of floor time before the box   │
 * │ hangs up for another interval. An operator's "read the WAN address" is    │
 * │ therefore never an action, it is an INTENT that will be executed later,   │
 * │ and modelling it as anything else produces an API that appears to hang.   │
 * │                                                                          │
 * │ `expires_at` is the second half of that: a CPE offline for a week must    │
 * │ not be handed a week of stale intent the second it reconnects. Intent     │
 * │ that outlives its usefulness is worse than intent that was never          │
 * │ recorded, because it executes.                                            │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ NOTHING WRITES TO AN EQUIPMENT OUTSIDE `change_jobs` ────────────────────┐
 * │ `set_parameter_values`, `download` and `reboot` MODIFY a customer's       │
 * │ router. The design says that is the exclusive privilege of the change     │
 * │ queue, and it applies here in full: `enqueueTask()` refuses a mutating    │
 * │ kind unless the caller passes the `change_jobs` row that authorises it.   │
 * │ The ACS API therefore exposes reads directly and mutations only through   │
 * │ a change job — the same door as a RouterOS push, with the same guard,     │
 * │ the same approval and the same audit trail.                               │
 * │                                                                          │
 * │ `get_parameter_values` is exempt because it is a READ, exactly as         │
 * │ `POST /config/devices/:id/collect` is a read on the MikroTik side.        │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ A DISPATCHED WRITE IS NEVER SENT TWICE BY THE MACHINE (`unknown`) ───────┐
 * │ When a session dies with a task in `sent` — abandoned, superseded by a   │
 * │ new Inform, reaped idle, or the CPE gave the floor back instead of        │
 * │ answering — what was lost is the ANSWER, not necessarily the command. A  │
 * │ Vigor that received a Reboot and dropped the line before replying HAS     │
 * │ rebooted. Putting that task back in `queued` (what this file used to do,  │
 * │ up to `max_attempts` times) rebooted it again at its next session, with   │
 * │ no human anywhere: a destructive act nobody launched.                    │
 * │                                                                          │
 * │ So `settleAbandonedTask` splits on the kind. A READ goes back to the     │
 * │ queue, as before. A WRITE goes to `unknown`: terminal, never re-sent, and │
 * │ its change job is failed with "outcome unknown — check the device". A    │
 * │ human re-queues it with `requeueUnknownTask`, which creates a NEW task   │
 * │ under a NEW live change job and refuses to do it twice.                  │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ A WRITE GOES OUT ONLY WHILE ITS AUTHORISATION IS STILL LIVE ─────────────┐
 * │ The change job was checked at enqueue, and a task can wait 24 h (7 days  │
 * │ for a Download) for its CPE to call in. A job that has since FAILED or    │
 * │ been ABORTED — "Nothing had been written to the device" — must not still │
 * │ reboot that device at its next Inform. `claimNextTask` re-reads the job  │
 * │ and WITHDRAWS (`cancelled`, with the reason in its fault) a write whose  │
 * │ job is no longer live, or whose job row is gone; the leader's sweep       │
 * │ (`withdrawTasksOfConcludedJobs`) does the same ahead of time so the      │
 * │ screen stops showing it as pending. The plumbing exception (no job) is    │
 * │ re-verified on its payload, exactly as at enqueue.                        │
 * │                                                                          │
 * │ A write already `sent` is never "cancelled": withdrawing it would hide   │
 * │ the one fact that matters — it may have been applied — from `unknown`.   │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import crypto from 'crypto';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import type { Knex } from 'knex';
import {
  CWMP_MUTATING_TASK_KINDS,
  CWMP_TASK_TERMINAL,
  isRetryableFault,
  summarisePayload,
  type CwmpFault,
  type CwmpTask,
  type CwmpTaskKind,
  type CwmpTaskPayload,
  type CwmpTaskState,
} from './contract';

/** Kinds that change the state of somebody else's hardware. One list, in
 *  `shared/src/cwmp.ts`, so the client and this file cannot disagree. */
const MUTATING_KINDS = CWMP_MUTATING_TASK_KINDS;

/**
 * ┌─ THE ONE NARROW EXCEPTION TO THE CHANGE QUEUE, AND ITS JUSTIFICATION ─────┐
 * │ These two leaves configure the ACS's OWN management channel: how often    │
 * │ the CPE calls home. They change nothing about the service the box         │
 * │ delivers — no interface, no route, no firewall rule, no credential of     │
 * │ the customer's — and they cannot lock anybody out of anything.            │
 * │                                                                          │
 * │ They are exempted because the alternative makes the product dishonest.    │
 * │ ObliWAN has NO Connection Request (trade-off: STUN/XMPP bindings expire   │
 * │ in 30-120 s), so lowering the inform interval is the ONLY way to make a   │
 * │ CPE call back sooner — and that is what the UI promises in                │
 * │ `CWMP_NO_CONNECTION_REQUEST_EXPLANATION`. Routing it through a change     │
 * │ job with a frozen plan, a management-path guard and an approval, in       │
 * │ order to say "please call home in a minute", would mean nobody ever uses  │
 * │ it and the UI's honest sentence quietly becomes a lie.                    │
 * │                                                                          │
 * │ MATCHED ON THE FULL SUFFIX, NOT ON A LEAF NAME. `…PeriodicInformInterval` │
 * │ under `ManagementServer` is plumbing; a vendor-specific leaf that happens │
 * │ to end the same way somewhere else in the tree is not.                    │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
const ACS_PLUMBING_SUFFIXES: readonly string[] = [
  'ManagementServer.PeriodicInformInterval',
  'ManagementServer.PeriodicInformEnable',
];

export function isAcsPlumbingPath(path: string): boolean {
  return ACS_PLUMBING_SUFFIXES.some((suffix) => path.endsWith(suffix));
}

export type TaskRefusalCode =
  | 'requires_change_job'
  | 'not_enrolled'
  | 'not_found'
  | 'not_requeueable'
  | 'already_requeued';

export class TaskRefusedError extends Error {
  constructor(message: string, readonly code: TaskRefusalCode) {
    super(message);
    this.name = 'TaskRefusedError';
  }
}

interface TaskRow {
  id: number;
  device_id: number;
  kind: CwmpTaskKind;
  command_key: string;
  state: CwmpTaskState;
  attempts: number;
  max_attempts: number;
  payload: CwmpTaskPayload;
  fault: CwmpFault | null;
  created_by: number | null;
  /** BIGINT (`change_jobs.id`): node-pg hands it back as a string. */
  change_job_id: string | number | null;
  requeued_from_task_id: number | null;
  expires_at: Date;
  sent_at: Date | null;
  completed_at: Date | null;
  created_at: Date;
}

function toTask(row: TaskRow): CwmpTask {
  return {
    id: row.id,
    deviceId: row.device_id,
    kind: row.kind,
    commandKey: row.command_key,
    state: row.state,
    attempts: row.attempts,
    maxAttempts: row.max_attempts,
    payload: row.payload,
    fault: row.fault,
    createdBy: row.created_by,
    changeJobId: row.change_job_id == null ? null : Number(row.change_job_id),
    requeuedFromTaskId: row.requeued_from_task_id ?? null,
    expiresAt: row.expires_at.toISOString(),
    sentAt: row.sent_at ? row.sent_at.toISOString() : null,
    completedAt: row.completed_at ? row.completed_at.toISOString() : null,
    createdAt: row.created_at.toISOString(),
  };
}

/**
 * A CommandKey.
 *
 * It has to be unique across the whole table (migration 015, decision 4) AND
 * survive a round trip through firmware that may truncate it — TR-069 caps it
 * at 32 characters and several vendors enforce that silently. 24 hex characters
 * plus a 4-character prefix is 28, inside every limit, and 96 bits of entropy.
 */
export function newCommandKey(prefix = 'obw'): string {
  return `${prefix}-${crypto.randomBytes(12).toString('hex')}`;
}

export interface EnqueueOptions {
  createdBy?: number | null;
  ttlSeconds?: number;
  maxAttempts?: number;
  commandKey?: string;
  /**
   * The `change_jobs.id` that authorises a mutating task. Reads do not
   * need one; a mutation without one is REFUSED, not logged and allowed.
   */
  changeJobId?: number | null;
  /**
   * Claim the `ACS_PLUMBING_SUFFIXES` exception above. The claim is VERIFIED,
   * not trusted: a payload touching anything outside the whitelist is refused
   * exactly as if the flag had not been passed.
   */
  acsPlumbing?: boolean;
}

export async function enqueueTask(
  deviceId: number,
  payload: CwmpTaskPayload,
  opts: EnqueueOptions = {},
): Promise<CwmpTask> {
  return insertTask(db, deviceId, payload, opts);
}

/**
 * The single INSERT into `cwmp_tasks`, with its two refusals (enrolment).
 * Takes a query builder so `requeueUnknownTask` can run it under the row lock
 * of the task it re-queues.
 */
async function insertTask(
  q: Knex | Knex.Transaction,
  deviceId: number,
  payload: CwmpTaskPayload,
  opts: EnqueueOptions & { requeuedFromTaskId?: number | null },
): Promise<CwmpTask> {
  const enrolled = (await q('cwmp_devices').where({ device_id: deviceId }).first('device_id')) as
    | { device_id: number }
    | undefined;
  if (!enrolled) {
    throw new TaskRefusedError(
      `device ${deviceId} is not enrolled in the ACS — enrol it first`,
      'not_enrolled',
    );
  }

  if (MUTATING_KINDS.has(payload.kind) && !opts.changeJobId) {
    const plumbing =
      opts.acsPlumbing === true &&
      payload.kind === 'set_parameter_values' &&
      payload.ops.every((op) => isAcsPlumbingPath(op.path));

    if (!plumbing) {
      throw new TaskRefusedError(
        `${payload.kind} modifies the equipment and must go through a change job ` +
          '(nothing writes to an equipment outside change_jobs)',
        'requires_change_job',
      );
    }
  }

  const ttl = opts.ttlSeconds ?? 24 * 3600;
  const [row] = (await q('cwmp_tasks')
    .insert({
      device_id: deviceId,
      kind: payload.kind,
      command_key: opts.commandKey ?? newCommandKey(),
      state: 'queued',
      max_attempts: opts.maxAttempts ?? 3,
      payload: JSON.stringify(payload),
      created_by: opts.createdBy ?? null,
      // KEPT, not just checked: it is the job an `unknown` outcome fails.
      change_job_id: opts.changeJobId ?? null,
      requeued_from_task_id: opts.requeuedFromTaskId ?? null,
      expires_at: new Date(Date.now() + ttl * 1000),
    })
    .returning('*')) as TaskRow[];

  logger.info(
    {
      deviceId,
      taskId: row.id,
      kind: payload.kind,
      summary: summarisePayload(payload),
      changeJobId: opts.changeJobId ?? null,
      requeuedFromTaskId: opts.requeuedFromTaskId ?? null,
    },
    'ACS: task queued',
  );
  return toTask(row);
}

/** `change_jobs` statuses in which a job still authorises a write (the
 *  non-terminal states of migration 009). */
const LIVE_CHANGE_JOB_STATUSES: readonly string[] = [
  'queued', 'claimed', 'backing_up', 'arming', 'applying', 'verifying', 'soaking', 'disarming',
];

/** The fault a withdrawn write carries. Not a CWMP code: no CPE said it. */
export const AUTHORISATION_ENDED_FAULT_CODE = 'AUTHORISATION_ENDED';

function withdrawnFault(reason: string): string {
  return JSON.stringify({
    faultCode: 'Server',
    code: AUTHORISATION_ENDED_FAULT_CODE,
    faultString: `not sent: ${reason}. Nothing was sent to the device.`,
  });
}

/**
 * Why a queued write may no longer go out — or null when it may. Reads have
 * no authorisation to lose; the plumbing exception is re-verified on its
 * payload, as `insertTask` verified it.
 */
async function lostAuthorisation(q: Knex | Knex.Transaction, row: TaskRow): Promise<string | null> {
  if (!MUTATING_KINDS.has(row.kind)) return null;
  if (row.change_job_id == null) {
    const plumbing =
      row.payload.kind === 'set_parameter_values' &&
      row.payload.ops.every((op) => isAcsPlumbingPath(op.path));
    return plumbing ? null : 'the change job that authorised this write no longer exists';
  }
  const job = (await q('change_jobs').where({ id: row.change_job_id }).first('status')) as
    | { status: string }
    | undefined;
  if (!job) return `change job #${row.change_job_id}, which authorised this write, no longer exists`;
  if (!LIVE_CHANGE_JOB_STATUSES.includes(job.status)) {
    return `change job #${row.change_job_id}, which authorised this write, is ${job.status}`;
  }
  return null;
}

/**
 * Claim the next task for a CPE that is on the line right now.
 *
 * `FOR UPDATE SKIP LOCKED` because two replicas may be serving two POSTs of
 * the same CPE at the same instant (a retransmit, a NAT rebinding), and handing
 * the same RPC to both would make the CPE answer twice with the same
 * `cwmp:ID` — after which nothing can be correlated to anything.
 *
 * Expiry is checked HERE and not only in the sweeper: the sweeper runs every
 * minute, and a task that expired thirty seconds ago must not go out just
 * because the CPE happened to call in first.
 */
export async function claimNextTask(deviceId: number): Promise<CwmpTask | null> {
  return db.transaction(async (trx) => {
    const next = async (): Promise<TaskRow | undefined> =>
      (await trx('cwmp_tasks')
        .where({ device_id: deviceId, state: 'queued' })
        .andWhere('expires_at', '>', trx.fn.now())
        .orderBy('id')
        .forUpdate()
        .skipLocked()
        .first()) as TaskRow | undefined;

    let row = await next();
    // The authorisation is read AGAIN here, at the last moment before the RPC
    // leaves (file header): a write whose change job has failed or been
    // aborted since it was queued is withdrawn, not sent.
    let lost = row ? await lostAuthorisation(trx, row) : null;
    while (row && lost !== null) {
      await trx('cwmp_tasks')
        .where({ id: row.id, state: 'queued' })
        .update({ state: 'cancelled', fault: withdrawnFault(lost), completed_at: trx.fn.now(), updated_at: trx.fn.now() });
      logger.warn(
        { taskId: row.id, deviceId, kind: row.kind, changeJobId: row.change_job_id, reason: lost },
        'ACS: a queued write lost its authorisation — withdrawn, NOT sent',
      );
      row = await next();
      lost = row ? await lostAuthorisation(trx, row) : null;
    }
    if (!row) return null;

    const [updated] = (await trx('cwmp_tasks')
      .where({ id: row.id })
      .update({
        state: 'sent',
        attempts: row.attempts + 1,
        sent_at: trx.fn.now(),
        updated_at: trx.fn.now(),
      })
      .returning('*')) as TaskRow[];

    return toTask(updated);
  });
}

/** The CPE answered without a fault. */
export async function completeTask(taskId: number): Promise<void> {
  await db('cwmp_tasks')
    .where({ id: taskId })
    .whereNotIn('state', [...CWMP_TASK_TERMINAL])
    .update({ state: 'done', completed_at: db.fn.now(), updated_at: db.fn.now() });
}

/**
 * The CPE answered a fault.
 *
 * ┌─ ONLY READS AUTO-RETRY, AND THE ASYMMETRY IS THE POINT ───────────────────┐
 * │ A retryable fault on a `get_parameter_values` goes BACK to `queued` and    │
 * │ the CPE gets it again next session; `9004 Resources Exceeded` on a CPE     │
 * │ that was busy is exactly the case that is worth another attempt.           │
 * │                                                                          │
 * │ A MUTATION IS NEVER RETRIED AUTOMATICALLY. `download`, `reboot` and        │
 * │ `set_parameter_values` were authorised by ONE change job against ONE       │
 * │ frozen plan; silently doing them again five minutes later is a             │
 * │ second write nobody approved. Concretely, this is the difference between   │
 * │ "the firmware push failed, a human decides" and "the ACS re-pushed a       │
 * │ firmware image to a CPE that had just failed to take it" — which is also   │
 * │ how a Download comes back around with a CommandKey that already has a      │
 * │ transfer row and dies on a unique violation.                               │
 * │                                                                          │
 * │ `9005 Invalid parameter name` is terminal for everything, mutation or not: │
 * │ retrying it forever burns the box's session budget every five minutes for  │
 * │ a path that will never exist.                                              │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
export async function failTask(taskId: number, fault: CwmpFault): Promise<CwmpTaskState> {
  const row = (await db('cwmp_tasks').where({ id: taskId }).first()) as TaskRow | undefined;
  if (!row) return 'failed';

  const canRetry =
    !MUTATING_KINDS.has(row.kind) &&
    isRetryableFault(fault.code) &&
    row.attempts < row.max_attempts;
  const state: CwmpTaskState = canRetry ? 'queued' : 'failed';

  await db('cwmp_tasks')
    .where({ id: taskId })
    .update({
      state,
      fault: JSON.stringify(fault),
      completed_at: canRetry ? null : db.fn.now(),
      updated_at: db.fn.now(),
    });

  logger.warn(
    { taskId, deviceId: row.device_id, code: fault.code, attempts: row.attempts, state },
    'ACS: task faulted',
  );
  return state;
}

/**
 * Settle an in-flight task whose answer will never come.
 *
 * Called when a session dies mid-RPC — the line dropped, the CPE rebooted, the
 * server was redeployed, the session was superseded or reaped, or the CPE gave
 * the floor back instead of answering. Without it the task sits in `sent`
 * forever and the operator sees a request that never completes and never
 * fails, which is the single most expensive state a queue can have.
 *
 * ┌─ A READ IS ASKED AGAIN; A WRITE BECOMES `unknown` ────────────────────────┐
 * │ A lost GetParameterValues answer costs nothing to ask again, so a read    │
 * │ goes back to `queued` until its attempt budget runs out.                  │
 * │                                                                          │
 * │ A write does NOT. The RPC reached the CPE's session; whether the box     │
 * │ applied it is exactly what nobody knows. Re-sending it is a second       │
 * │ Reboot, a second write, a second firmware push — none of them launched   │
 * │ by a human. It goes to `unknown` and stays there; see the file header.   │
 * │                                                                          │
 * │ Every UPDATE re-asserts `state = 'sent'`: the reaper, the orphan sweep    │
 * │ and a superseding Inform can all reach the same task, and only the first  │
 * │ may act — in particular only ONE of them may fail the change job.         │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
export async function settleAbandonedTask(
  taskId: number,
  reason: string,
): Promise<CwmpTaskState | null> {
  const row = (await db('cwmp_tasks').where({ id: taskId, state: 'sent' }).first()) as
    | TaskRow
    | undefined;
  if (!row) return null;

  if (MUTATING_KINDS.has(row.kind)) return markOutcomeUnknown(row, reason);

  if (row.attempts >= row.max_attempts) {
    const n = await db('cwmp_tasks')
      .where({ id: taskId, state: 'sent' })
      .update({
        state: 'failed',
        fault: JSON.stringify({
          faultCode: 'Server',
          code: '9002',
          faultString: `abandoned after ${row.attempts} attempts: ${reason}`,
        }),
        completed_at: db.fn.now(),
        updated_at: db.fn.now(),
      });
    return n > 0 ? 'failed' : null;
  }
  const n = await db('cwmp_tasks')
    .where({ id: taskId, state: 'sent' })
    .update({ state: 'queued', sent_at: null, updated_at: db.fn.now() });
  return n > 0 ? 'queued' : null;
}

/** The fault code an `unknown` task carries. Not a CWMP code: no CPE said it. */
export const OUTCOME_UNKNOWN_FAULT_CODE = 'OUTCOME_UNKNOWN';
/** `change_jobs.error_kind` of a job failed because its ACS write went unanswered. */
export const OUTCOME_UNKNOWN_ERROR_KIND = 'cwmp_outcome_unknown';

const RPC_NAMES: Record<CwmpTaskKind, string> = {
  get_parameter_values: 'GetParameterValues',
  set_parameter_values: 'SetParameterValues',
  download: 'Download',
  reboot: 'Reboot',
};

async function markOutcomeUnknown(row: TaskRow, reason: string): Promise<CwmpTaskState | null> {
  const rpc = RPC_NAMES[row.kind];
  const faultString =
    `outcome unknown — check the device: ${rpc} was sent to the CPE and no answer came back ` +
    `(${reason}). It will NOT be sent again automatically; re-queue it explicitly once the ` +
    'device has been checked.';

  const n = await db('cwmp_tasks')
    .where({ id: row.id, state: 'sent' })
    .update({
      state: 'unknown',
      fault: JSON.stringify({ faultCode: 'Server', code: OUTCOME_UNKNOWN_FAULT_CODE, faultString }),
      completed_at: db.fn.now(),
      updated_at: db.fn.now(),
    });
  if (n === 0) return null;

  const changeJobId = row.change_job_id == null ? null : Number(row.change_job_id);
  const job = changeJobId === null
    ? 'none'
    : await failAuthorisingChangeJob(changeJobId, row, rpc, reason);

  logger.warn(
    {
      taskId: row.id,
      deviceId: row.device_id,
      kind: row.kind,
      commandKey: row.command_key,
      changeJobId,
      changeJob: job,
      reason,
    },
    'ACS: a write was sent and never answered — outcome unknown, NOT re-sent',
  );
  return 'unknown';
}

/**
 * Fail the change job that authorised a write whose outcome is now unknown.
 *
 * ┌─ ONLY A JOB NO WORKER HOLDS ──────────────────────────────────────────────┐
 * │ `queued` → `failed` is not an edge of `CHANGE_JOB_TRANSITIONS`, and it is │
 * │ taken here on purpose: nothing in the change subsystem has touched this   │
 * │ job — the ACS acted on its authority, and its answer is what was lost.    │
 * │ Failing it also stops the worker from claiming it LATER and running its  │
 * │ own generic flow on a device whose state nobody knows. The UPDATE         │
 * │ re-asserts `status = 'queued'`, as `claimNextJob` does, so a claim and    │
 * │ this cannot both win.                                                     │
 * │                                                                          │
 * │ A job a worker HOLDS (`claimed` … `disarming`) is NOT touched. Changing   │
 * │ its status under the worker makes `assertLease` throw, and on a lost      │
 * │ lease the worker "touches nothing — not the row, not the device": it      │
 * │ stands down with whatever it had armed still armed. Saying "unknown" on   │
 * │ the task is worth less than that risk. A terminal job keeps its verdict.  │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
async function failAuthorisingChangeJob(
  changeJobId: number,
  row: TaskRow,
  rpc: string,
  reason: string,
): Promise<'failed' | 'held_by_worker' | 'already_finished' | 'gone'> {
  const message =
    `Outcome unknown — check the device. The ACS sent ${rpc} (task #${row.id}, CommandKey ` +
    `${row.command_key}) to the CPE and no answer came back (${reason}). It will not be sent ` +
    'again automatically; re-queue it explicitly from the ACS screen once the device has been ' +
    'checked.';

  const n = await db('change_jobs')
    .where({ id: changeJobId, status: 'queued' })
    .update({
      status: 'failed',
      error_kind: OUTCOME_UNKNOWN_ERROR_KIND,
      error_message: message,
      finished_at: db.fn.now(),
      updated_at: db.fn.now(),
    });
  if (n > 0) return 'failed';

  const job = (await db('change_jobs').where({ id: changeJobId }).first('status')) as
    | { status: string }
    | undefined;
  if (!job) return 'gone';
  if (['succeeded', 'rolled_back', 'failed', 'aborted'].includes(job.status)) {
    return 'already_finished';
  }
  logger.warn(
    { changeJobId, status: job.status, taskId: row.id },
    'ACS: the change job behind an unknown write is held by a worker — left to it, not failed',
  );
  return 'held_by_worker';
}

/**
 * A task left in `sent` with no OPEN session holding it.
 *
 * `claimNextTask` marks a task `sent` and the session row is pointed at it a
 * moment later; a process that dies between the two leaves a `sent` task no
 * session will ever reap. Same verdict as an abandoned session: a read is
 * asked again, a write becomes `unknown`.
 */
export async function settleOrphanedSentTasks(idleSeconds: number): Promise<number> {
  const rows = (await db('cwmp_tasks as t')
    .where('t.state', 'sent')
    .andWhere('t.sent_at', '<', db.raw(`now() - (? || ' seconds')::interval`, [idleSeconds]))
    .whereNotExists(
      db('cwmp_sessions as s')
        .whereRaw('s.pending_task_id = t.id')
        .andWhere('s.state', 'open')
        .select(db.raw('1')),
    )
    .select('t.id')) as Array<{ id: number }>;

  let settled = 0;
  for (const r of rows) {
    const state = await settleAbandonedTask(
      r.id,
      `no open session held it ${idleSeconds}s after it was sent`,
    );
    if (state !== null) settled++;
  }
  return settled;
}

/**
 * The CPE's own word settles an `unknown` task: a `TransferComplete` carrying
 * its CommandKey proves the Download was received and says how it ended.
 * Success only — a failed transfer goes through `failTask`, which records the
 * CPE's fault. The change job keeps its verdict: it was failed when nobody
 * knew, and the task row is where the outcome is now told.
 */
export async function resolveUnknownTaskAsDone(taskId: number, evidence: string): Promise<boolean> {
  const n = await db('cwmp_tasks')
    .where({ id: taskId, state: 'unknown' })
    .update({ state: 'done', fault: null, completed_at: db.fn.now(), updated_at: db.fn.now() });
  if (n > 0) logger.info({ taskId, evidence }, 'ACS: an unknown outcome was settled by the CPE');
  return n > 0;
}

/**
 * A human re-sends a write whose outcome is unknown — as a NEW task.
 *
 * Same rules as any write: the caller has checked ACS_ADMIN and passes a
 * LIVE change job of the same device. The original stays `unknown` for the
 * record; the new row points at it. Refused when the original is not
 * `unknown`, and when it has already been re-queued (a double click must not
 * become a double reboot) — unless that re-queue was withdrawn or expired
 * before anything was sent. The row lock makes the check and the insert one
 * step.
 */
export async function requeueUnknownTask(
  taskId: number,
  deviceId: number,
  opts: { createdBy: number | null; changeJobId: number; ttlSeconds?: number },
): Promise<CwmpTask> {
  return db.transaction(async (trx) => {
    const original = (await trx('cwmp_tasks')
      .where({ id: taskId, device_id: deviceId })
      .forUpdate()
      .first()) as TaskRow | undefined;
    if (!original) throw new TaskRefusedError('Task not found', 'not_found');

    if (original.state !== 'unknown') {
      throw new TaskRefusedError(
        `task ${taskId} is ${original.state}: only a write whose outcome is unknown can be ` +
          're-queued here. Queue a new task instead.',
        'not_requeueable',
      );
    }

    // A prior re-queue counts unless it provably never left: withdrawn or
    // expired while still `queued` (`sent_at` NULL). One that was sent counts
    // whatever it reads now — a row cancelled while `sent` (possible before
    // `cancelTask` refused that state) may well have rebooted the box.
    const prior = (await trx('cwmp_tasks')
      .where({ requeued_from_task_id: taskId })
      .where(function leftOrPending() {
        void this.whereNotIn('state', ['cancelled', 'expired']).orWhereNotNull('sent_at');
      })
      .first('id', 'state')) as { id: number; state: CwmpTaskState } | undefined;
    if (prior) {
      throw new TaskRefusedError(
        `task ${taskId} was already re-queued as task ${prior.id} (${prior.state})`,
        'already_requeued',
      );
    }

    const task = await insertTask(trx, deviceId, original.payload, {
      createdBy: opts.createdBy,
      changeJobId: opts.changeJobId,
      requeuedFromTaskId: taskId,
      ttlSeconds:
        opts.ttlSeconds ?? (original.kind === 'download' ? 7 * 24 * 3600 : 24 * 3600),
    });
    logger.warn(
      { taskId, newTaskId: task.id, deviceId, kind: original.kind, changeJobId: opts.changeJobId, by: opts.createdBy },
      'ACS: a write whose outcome was unknown was re-queued by a human',
    );
    return task;
  });
}

/**
 * Withdraw a task that has NOT been sent. A task in `sent` is refused (false):
 * its RPC is on the wire and the CPE may already be executing it, so calling
 * it "cancelled" would be false — and would take a write out of the path that
 * makes it `unknown`, fails its change job and guards against a second
 * re-queue. It ends `done`, `failed` or `unknown` on its own.
 */
export async function cancelTask(taskId: number, deviceId: number): Promise<boolean> {
  const affected = await db('cwmp_tasks')
    .where({ id: taskId, device_id: deviceId, state: 'queued' })
    .update({ state: 'cancelled', completed_at: db.fn.now(), updated_at: db.fn.now() });
  return affected > 0;
}

/**
 * The leader's sweep: withdraw every queued write whose change job is no
 * longer live, so the screen stops showing as pending a write that will never
 * go out (`claimNextTask` would withdraw it at the next Inform anyway).
 */
export async function withdrawTasksOfConcludedJobs(): Promise<number> {
  const rows = (await db('cwmp_tasks as t')
    .join('change_jobs as j', 'j.id', 't.change_job_id')
    .where('t.state', 'queued')
    .whereIn('t.kind', [...MUTATING_KINDS])
    .whereNotIn('j.status', [...LIVE_CHANGE_JOB_STATUSES])
    .select('t.id', 't.change_job_id', 'j.status')) as Array<{
    id: number;
    change_job_id: string | number;
    status: string;
  }>;
  let withdrawn = 0;
  for (const r of rows) {
    withdrawn += await db('cwmp_tasks')
      .where({ id: r.id, state: 'queued' })
      .update({
        state: 'cancelled',
        fault: withdrawnFault(`change job #${r.change_job_id}, which authorised this write, is ${r.status}`),
        completed_at: db.fn.now(),
        updated_at: db.fn.now(),
      });
  }
  return withdrawn;
}

/** The sweeper. Runs on the leader; see `services/cwmp/index.ts`. */
export async function expireStaleTasks(): Promise<number> {
  return db('cwmp_tasks')
    .where({ state: 'queued' })
    .andWhere('expires_at', '<=', db.fn.now())
    .update({ state: 'expired', completed_at: db.fn.now(), updated_at: db.fn.now() });
}

export async function listTasks(
  deviceId: number,
  opts: { states?: CwmpTaskState[]; limit?: number } = {},
): Promise<CwmpTask[]> {
  const q = db('cwmp_tasks').where({ device_id: deviceId });
  if (opts.states?.length) q.whereIn('state', opts.states);
  const rows = (await q.orderBy('id', 'desc').limit(opts.limit ?? 100)) as TaskRow[];
  return rows.map(toTask);
}

export async function getTask(taskId: number): Promise<CwmpTask | null> {
  const row = (await db('cwmp_tasks').where({ id: taskId }).first()) as TaskRow | undefined;
  return row ? toTask(row) : null;
}

export async function getTaskByCommandKey(commandKey: string): Promise<CwmpTask | null> {
  const row = (await db('cwmp_tasks').where({ command_key: commandKey }).first()) as
    | TaskRow
    | undefined;
  return row ? toTask(row) : null;
}

export async function countPending(deviceIds: readonly number[]): Promise<Map<number, number>> {
  if (deviceIds.length === 0) return new Map();
  const rows = (await db('cwmp_tasks')
    .whereIn('device_id', deviceIds as number[])
    .whereIn('state', ['queued', 'sent'])
    .groupBy('device_id')
    .select('device_id')
    .count<{ device_id: number; count: string }[]>('* as count')) as Array<{
    device_id: number;
    count: string;
  }>;
  return new Map(rows.map((r) => [r.device_id, Number(r.count)]));
}
