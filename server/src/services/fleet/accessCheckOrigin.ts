/**
 * ObliWAN — where a management_access / legacy_compliance job came from when
 * no operator queued it: the AUTOMATIC re-apply after the nightly
 * verification (migration 093, `access_check_auto_jobs`;
 * fleet/accessCheckNightly.service.ts).
 *
 *   jobOrigins(ids)          the origin of each job of a list: the Changes
 *                            page and the job page say "automatic re-apply
 *                            (nightly verification #n)"
 *   lastAutoFailures(...)    per router and kind, the LATEST job of that kind
 *                            when it is an automatic one that did not succeed,
 *                            with the cause it acted on: a router whose
 *                            previous automatic re-apply failed for the SAME
 *                            cause is never re-applied by the night again
 *
 * A job is automatic when the night queued it (`access_check_auto_jobs`), or
 * when it is the template fixes the night PROMISED after its management access
 * job and the worker queued once that job succeeded (`change_job_followups`,
 * `then_job_id`) — such a job names no requester; one an operator queued by
 * hand and the promise adopted does, and stays the operator's.
 *
 * Depends on the database only: the job queue imports it.
 */

import type { ChangeJobOrigin } from '@obliwan/shared';
import { db } from '../../db';

export type AutoJobKind = 'management_access' | 'legacy_compliance';

/** The cause the template fixes are re-applied on (one per router). */
export const AUTO_COMPLIANCE_CAUSE = 'compliance:fixes';

const FAILED = ['failed', 'aborted', 'rolled_back'];

export interface AutoJobOrigin extends ChangeJobOrigin {
  /** The cause the night acted on (`accessCheckCauseKey`). */
  cause: string;
}

/** The automatic origin of each job of `jobIds` that has one. */
export async function jobOrigins(jobIds: readonly number[]): Promise<Map<number, AutoJobOrigin>> {
  const out = new Map<number, AutoJobOrigin>();
  const ids = [...new Set(jobIds.map(Number).filter((n) => Number.isInteger(n) && n > 0))];
  if (ids.length === 0) return out;
  const direct = (await db('access_check_auto_jobs')
    .whereIn('job_id', ids)
    .select('job_id', 'run_number', 'cause')) as Array<{ job_id: string | number; run_number: string | number; cause: string }>;
  for (const r of direct) {
    out.set(Number(r.job_id), { kind: 'access_check_nightly', run: Number(r.run_number), cause: r.cause });
  }
  const promised = (await db('change_job_followups as f')
    .join('access_check_auto_jobs as a', 'a.job_id', 'f.after_job_id')
    .join('change_jobs as j', 'j.id', 'f.then_job_id')
    .whereIn('f.then_job_id', ids)
    .whereNull('j.requested_by')
    .select('f.then_job_id as job_id', 'a.run_number as run_number')) as Array<{ job_id: string | number; run_number: string | number }>;
  for (const r of promised) {
    if (!out.has(Number(r.job_id))) {
      out.set(Number(r.job_id), { kind: 'access_check_nightly', run: Number(r.run_number), cause: AUTO_COMPLIANCE_CAUSE });
    }
  }
  return out;
}

export interface AutoFailure {
  jobId: number;
  status: string;
  run: number;
  cause: string;
}

/** `${deviceId}:${kind}` -> the latest job of that kind on the router, when
 *  the night queued it and it did not succeed. */
export async function lastAutoFailures(
  tenantId: number,
  deviceIds: readonly number[],
): Promise<Map<string, AutoFailure>> {
  const out = new Map<string, AutoFailure>();
  const ids = [...new Set(deviceIds.map(Number))];
  if (ids.length === 0) return out;
  const latest = (await db('change_jobs')
    .distinctOn(['device_id', 'kind'])
    .where('tenant_id', tenantId)
    .whereIn('device_id', ids)
    .whereIn('kind', ['management_access', 'legacy_compliance'])
    .orderBy([{ column: 'device_id' }, { column: 'kind' }, { column: 'id', order: 'desc' }])
    .select('id', 'device_id', 'kind', 'status')) as Array<{ id: string | number; device_id: number; kind: AutoJobKind; status: string }>;
  const failed = latest.filter((j) => FAILED.includes(j.status));
  if (failed.length === 0) return out;
  const origins = await jobOrigins(failed.map((j) => Number(j.id)));
  for (const j of failed) {
    const o = origins.get(Number(j.id));
    if (!o) continue;
    out.set(`${Number(j.device_id)}:${j.kind}`, { jobId: Number(j.id), status: j.status, run: o.run, cause: o.cause });
  }
  return out;
}

/** The job kind the night queues for a cause, or null when it queues none. */
export function autoKindOfCause(cause: string): AutoJobKind | null {
  if (cause.startsWith('access:')) return 'management_access';
  if (cause === AUTO_COMPLIANCE_CAUSE) return 'legacy_compliance';
  return null;
}
