import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { CAPABILITIES, LTE_APN_TOKEN_RE } from '@obliwan/shared';
import { AppError } from '../middleware/errorHandler';
import { callerHasCapability } from '../middleware/rbac';
import { KillSwitchEngagedError } from '../services/change/killSwitch.service';
import { DeviceBusyError } from '../services/change/jobQueue.service';
import { LteApnError, enqueueLteApnJob, getLteApnView } from '../services/change/lteApn.service';

/**
 * The LTE APN of one router — HTTP layer (routes/lteApn.routes.ts).
 *
 *   GET  /devices/:id/lte-apn   the catalogue resolved for the device, its
 *                               chosen profile, the last job (DEVICE_READ)
 *   POST /devices/:id/lte-apn   { profile, confirmNoDeadman: true } -> queue
 *                               ONE lte_apn job (CHANGE_APPLY)
 *
 * Every read is scoped by `req.tenantId` (from the session). The request
 * names a profile, never an APN: the APN is taken from the catalogue the
 * server resolves for the device, so a body cannot smuggle a value the
 * templates do not declare. Refusals leave as `{ success: false, error, code }`
 * with the service's French sentence, as management-access does.
 */

const idParam = z.coerce.number().int().positive();
const enqueueSchema = z
  .object({ profile: z.string().regex(LTE_APN_TOKEN_RE), confirmNoDeadman: z.literal(true) })
  .strict();

function parseId(req: Request): number {
  const id = idParam.safeParse(req.params.id);
  if (!id.success) throw new AppError(400, 'Identifiant d’équipement invalide.');
  return id.data;
}

function refuse(res: Response, status: number, code: string, error: string): void {
  res.status(status).json({ success: false, error, code });
}

function handle(err: unknown, res: Response, next: NextFunction): void {
  if (err instanceof LteApnError) return refuse(res, err.httpStatus, err.kind, err.message);
  if (err instanceof KillSwitchEngagedError) {
    return refuse(res, 409, 'kill_switch', `Arrêt d’urgence engagé : aucune écriture n’est possible (${err.message}).`);
  }
  if (err instanceof DeviceBusyError) {
    return refuse(res, 409, 'device_busy', 'Une autre tâche est en cours sur ce routeur : relancez quand elle sera terminée.');
  }
  next(err);
}

function callerCanApply(req: Request): Promise<boolean> {
  return callerHasCapability(req, CAPABILITIES.CHANGE_APPLY);
}

export const lteApnController = {
  async get(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const view = await getLteApnView(req.tenantId, parseId(req));
      if (!view) throw new AppError(404, 'Équipement introuvable.');
      // The step trace is the change queue's detail, as on management-access.
      if (view.job && !(await callerCanApply(req))) view.job.steps = [];
      res.json({ success: true, data: view });
    } catch (err) {
      handle(err, res, next);
    }
  },

  async enqueue(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req);
      const body = enqueueSchema.safeParse(req.body ?? {});
      if (!body.success) {
        return refuse(
          res,
          400,
          'invalid_request',
          'Attendu : { profile: <nom d’un profil du catalogue>, confirmNoDeadman: true }. La tâche n’arme aucun ' +
            'dead-man ; la mettre en file exige cette confirmation explicite.',
        );
      }
      const userId = req.session?.userId;
      if (!userId) throw new AppError(401, 'Authentication required');
      const out = await enqueueLteApnJob({
        tenantId: req.tenantId,
        deviceId: id,
        profile: body.data.profile,
        requestedBy: userId,
        confirmDegraded: { userId },
        allowExisting: true,
      });
      res.status(out.alreadyQueued ? 200 : 202).json({
        success: true,
        data: { jobId: out.jobId, alreadyQueued: out.alreadyQueued, profile: out.entry.name },
      });
    } catch (err) {
      handle(err, res, next);
    }
  },
};
