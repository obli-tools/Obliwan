import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { AppError } from '../middleware/errorHandler';
import { deviceListScope } from '../services/teamScope.service';
import { requirePickedTenant } from '../utils/globalView';
import { KillSwitchEngagedError, killSwitchSentenceFr } from '../services/change/killSwitch.service';
import {
  AccessCheckError,
  latestAccessCheck,
  reapplyAccessCheck,
  startAccessCheck,
  type AccessCheckActor,
} from '../services/fleet/accessCheck.service';
import { accessCheckScheduleView } from '../services/fleet/accessCheckNightly.service';

/**
 * Verify, then re-apply, the management access and the template fixes over
 * the workspace — HTTP layer (reconcile.routes.ts, behind
 * `adoptGodViewFilterTenant`: in the god view the workspace filter picks the
 * workspace, and these routes refuse until one is picked).
 *
 *   GET  /reconcile/access-check           the latest verification (or null)
 *   POST /reconcile/access-check           start one (202: it runs in the
 *                                          background; the page polls GET)
 *   POST /reconcile/access-check/reapply   { runId, confirmNoDeadman: true,
 *                                          deviceIds? } — queue the jobs
 *   GET  /reconcile/access-check/schedule  the nightly verification as the
 *                                          workspace's settings resolve it,
 *                                          and its open alerts (read-only)
 *
 * All three are CHANGE_APPLY — the per-device management-access and
 * legacy-compliance routes' own capability: the verification dials every
 * router and shows the change queue's failure messages, the re-apply queues
 * jobs. Team scope (087) narrows all three to the devices the caller's teams
 * grant `rw` on — the level a job needs; a platform admin covers the whole
 * workspace. The tenant is the session's (`req.tenantId`), never the body's.
 * Refusals leave as `{ success: false, error, reason }` (the reconciliation's
 * shape, read by the client's `reconcileError`).
 */

const reapplySchema = z
  .object({
    runId: z.string().uuid(),
    /** Neither job arms a dead-man. */
    confirmNoDeadman: z.literal(true),
    deviceIds: z.array(z.number().int().positive()).min(1).max(5000).optional(),
  })
  .strict();

function actorOf(req: Request): AccessCheckActor {
  const userId = req.session?.userId;
  if (typeof userId !== 'number') throw new AppError(401, 'Authentication required');
  return { userId };
}

function tenantOf(req: Request): number {
  const id = req.tenantId;
  if (typeof id !== 'number' || !Number.isInteger(id) || id <= 0) throw new AppError(403, 'No tenant granted for this account');
  requirePickedTenant(req);
  return id;
}

function refuse(err: unknown, res: Response, next: NextFunction): void {
  if (err instanceof AccessCheckError) {
    res.status(err.httpStatus).json({ success: false, error: err.message, reason: err.reason });
    return;
  }
  if (err instanceof KillSwitchEngagedError) {
    res.status(409).json({ success: false, error: `${killSwitchSentenceFr(err)} : aucune écriture n’est possible.`, reason: 'KILL_SWITCH' });
    return;
  }
  next(err);
}

export const accessCheckController = {
  async latest(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const tenantId = tenantOf(req);
      res.json({ success: true, data: await latestAccessCheck(tenantId, await deviceListScope(req, 'rw')) });
    } catch (err) {
      refuse(err, res, next);
    }
  },

  async schedule(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const tenantId = tenantOf(req);
      res.json({ success: true, data: await accessCheckScheduleView(tenantId) });
    } catch (err) {
      refuse(err, res, next);
    }
  },

  async start(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const tenantId = tenantOf(req);
      const out = await startAccessCheck(tenantId, actorOf(req), await deviceListScope(req, 'rw'));
      // The run goes on in the background; its own catch logs a failure.
      void out.done;
      res.status(202).json({ success: true, data: out.view });
    } catch (err) {
      refuse(err, res, next);
    }
  },

  async reapply(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const tenantId = tenantOf(req);
      const body = reapplySchema.safeParse(req.body ?? {});
      if (!body.success) {
        res.status(400).json({
          success: false,
          reason: 'INVALID_REQUEST',
          error:
            'Expected { runId, confirmNoDeadman: true, deviceIds? }. Neither job arms a dead-man: re-applying needs that ' +
            'explicit confirmation.',
        });
        return;
      }
      const out = await reapplyAccessCheck(tenantId, actorOf(req), body.data, await deviceListScope(req, 'rw'));
      res.json({ success: true, data: out });
    } catch (err) {
      refuse(err, res, next);
    }
  },
};
