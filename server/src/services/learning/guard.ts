// ============================================================================
// Learning mode — who may act, and the refusal of template-driven writes
// ============================================================================
//
// A router in learning refuses every TEMPLATE-DRIVEN write, by name:
//  - `compilePlan` (planner.service.ts) throws `device_learning` right after
//    loading the device — which covers POST /plan/devices/:id, the fleet
//    compile, a rollout's composition (listed as a failure) and its waves;
//  - `enqueueChangeJob` refuses a `push` (`learningBlocksJob`);
//  - a `push` queued BEFORE the flag was set fails at its `guard` step, before
//    the preflight backup and the dead-man.
// The targeted jobs (management access, compliance, APN, OS upgrade…) have
// their own doors and are untouched: they are what makes a legacy router
// manageable at all.

import type { Knex } from 'knex';
import { LEARNING_REFUSAL_KIND } from '@obliwan/shared';
import { db } from '../../db';

export { LEARNING_REFUSAL_KIND };

/** A refusal of the learning services, carrying its `code` and HTTP status.
 *  Nothing in the 401 band: the client logs the operator out on a 401. */
export class LearningError extends Error {
  constructor(readonly reason: string, message: string, readonly httpStatus = 409) {
    super(message);
    this.name = 'LearningError';
  }
}

export interface LearningActor {
  userId: number;
  username: string | null;
  /** `users.role = 'admin'`, as requireAuth revalidated it. */
  platformAdmin: boolean;
}

/** Learning mode dials customer routers with fleet credentials and reads
 *  their secrets: platform administrators only, re-checked by every entry
 *  point so a re-mount behind a capability fails closed. */
export function assertPlatformAdmin(actor: Pick<LearningActor, 'platformAdmin'>): void {
  if (actor.platformAdmin !== true) {
    throw new LearningError(
      'PLATFORM_ADMIN_ONLY',
      'Learning mode is reserved to platform administrators: it reads routers in production with their secrets.',
      403,
    );
  }
}

/** The device's learning flag, or null when it is not learning. */
export async function learningStateOf(
  deviceId: number,
  q: Knex | Knex.Transaction = db,
): Promise<{ since: Date; by: number | null } | null> {
  const row = (await q('devices').where({ id: deviceId }).first('learning_since', 'learning_by')) as
    | { learning_since: Date | string | null; learning_by: number | null }
    | undefined;
  if (!row || row.learning_since === null || row.learning_since === undefined) return null;
  return { since: new Date(row.learning_since), by: row.learning_by ?? null };
}

/** The operator-facing sentence of the refusal (English, server-side). */
export function learningRefusalMessage(deviceName: string, since: Date | string | null): string {
  const when = since ? ` since ${new Date(since).toISOString()}` : '';
  return (
    `Device ${deviceName} is in learning mode${when}: template-driven writes (plans, pushes, rollouts) ` +
    'are refused until it leaves learning. Targeted jobs (management access, compliance, APN, OS upgrade) ' +
    'stay allowed. Use the break-risk report to compare a template with what it runs.'
  );
}
