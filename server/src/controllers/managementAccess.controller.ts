import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { CAPABILITIES, type Capability } from '@obliwan/shared';
import { AppError } from '../middleware/errorHandler';
import { permissionService } from '../services/permission.service';
import { KillSwitchEngagedError } from '../services/change/killSwitch.service';
import { DeviceBusyError } from '../services/change/jobQueue.service';
import {
  ManagementAccessError,
  enqueueManagementAccessJob,
  getManagementAccessView,
} from '../services/change/managementAccess.service';
import { RolloutRefusedError, managementAccessLauncher } from '../services/change/rollout.service';

/**
 * The management API of a router in service — HTTP layer
 * (routes/managementAccess.routes.ts, mounted under `/devices` before
 * devicesRoutes).
 *
 *   GET  /devices/:id/management-access            the card's state (DEVICE_READ)
 *   POST /devices/:id/management-access            queue ONE job (CHANGE_APPLY)
 *   POST /devices/management-access/preview        the rollout's impact screen,
 *                                                  nothing written (CHANGE_APPLY)
 *   POST /devices/management-access/rollouts       compose + launch a rollout
 *                                                  (CHANGE_APPLY, and ROLLOUT_MANAGE
 *                                                  checked again in the handler)
 *
 * Every read is scoped by `req.tenantId`, which comes from the SESSION; a
 * device id of another tenant is reported like one that does not exist. No
 * route takes an address or a credential: the job dials the device's own SSH
 * transport and reuses its vault credential (a diagnostic that takes a host
 * from the request is SSRF). Every refusal leaves as `{ success: false, error,
 * code }`: the job service's sentences are French (the card shows them as
 * they are), the rollout machinery's are English, like the rest of
 * `/rollouts`.
 */

const idParam = z.coerce.number().int().positive();

/** `confirmNoDeadman: true` is the safety-net rule's explicit confirmation: the job arms no
 *  dead-man, so it is queued at `degraded` and the request must say so. */
const enqueueSchema = z.object({ confirmNoDeadman: z.literal(true) }).strict();

const previewSchema = z
  .object({
    name: z.string().max(200).optional(),
    deviceIds: z.array(z.number().int().positive()).min(1).max(500),
  })
  .strict();

const launchSchema = z
  .object({
    name: z.string().min(1).max(200),
    deviceIds: z.array(z.number().int().positive()).min(1).max(500),
    /** The ladder the operator was SHOWN (sizes, in order); the server
     *  refuses a launch whose composition would differ. */
    waves: z.array(z.object({ size: z.number().int().positive() }).strict()).min(1).max(20),
    confirmNoDeadman: z.literal(true),
  })
  .strict();

function parseId(req: Request): number {
  const id = idParam.safeParse(req.params.id);
  if (!id.success) throw new AppError(400, 'Identifiant d’équipement invalide.');
  return id.data;
}

function refuse(res: Response, status: number, code: string, error: string, detail?: unknown): void {
  res.status(status).json({ success: false, error, code, ...(detail === undefined ? {} : { detail }) });
}

/** Every refusal this layer knows, as `{ success: false, error, code }`. */
function handle(err: unknown, res: Response, next: NextFunction): void {
  if (err instanceof ManagementAccessError) return refuse(res, err.httpStatus, err.kind, err.message);
  if (err instanceof KillSwitchEngagedError) {
    return refuse(res, 409, 'kill_switch', `Arrêt d’urgence engagé : aucune écriture n’est possible (${err.message}).`);
  }
  if (err instanceof DeviceBusyError) {
    return refuse(res, 409, 'device_busy', 'Une autre tâche est en cours sur ce routeur : relancez quand elle sera terminée.');
  }
  if (err instanceof RolloutRefusedError) {
    const status = err.kind === 'subtree_interlock' || err.kind === 'not_draft' ? 409 : 422;
    return refuse(res, status, err.kind, err.message, err.detail ?? undefined);
  }
  next(err);
}

async function callerHas(req: Request, capability: Capability): Promise<boolean> {
  if (req.session?.role === 'admin') return true;
  const tenantId = req.tenantId ?? req.session?.currentTenantId;
  if (!req.session?.userId || !tenantId) return false;
  const caps = await permissionService.getUserCapabilities(req.session.userId, false, tenantId);
  return caps.includes(capability);
}

export const managementAccessController = {
  async get(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const view = await getManagementAccessView(req.tenantId, parseId(req));
      if (!view) throw new AppError(404, 'Équipement introuvable.');
      // The job's step trace is the change queue's detail: withheld from a
      // reader who could not have queued the job (the state, the outcome and
      // the error stay — they are what the card is for).
      if (view.job && !(await callerHas(req, CAPABILITIES.CHANGE_APPLY))) view.job.steps = [];
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
          'Attendu : { confirmNoDeadman: true }. La tâche n’arme aucun dead-man ; la mettre en file exige cette ' +
            'confirmation explicite.',
        );
      }
      const userId = req.session?.userId;
      if (!userId) throw new AppError(401, 'Authentication required');
      const out = await enqueueManagementAccessJob({
        tenantId: req.tenantId,
        deviceId: id,
        requestedBy: userId,
        confirmDegraded: { userId },
        allowExisting: true,
      });
      res.status(out.alreadyQueued ? 200 : 202).json({
        success: true,
        data: { jobId: out.jobId, alreadyQueued: out.alreadyQueued },
      });
    } catch (err) {
      handle(err, res, next);
    }
  },

  async preview(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = previewSchema.safeParse(req.body ?? {});
      if (!body.success) {
        return refuse(res, 400, 'invalid_request', 'Attendu : { deviceIds: [nombres], name? }.');
      }
      const data = await managementAccessLauncher.preview({
        tenantId: req.tenantId,
        name: body.data.name?.trim() || 'preview',
        deviceIds: body.data.deviceIds,
        requestedBy: req.session?.userId ?? null,
      });
      res.json({ success: true, data });
    } catch (err) {
      handle(err, res, next);
    }
  },

  async launchRollout(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = launchSchema.safeParse(req.body ?? {});
      if (!body.success) {
        return refuse(
          res,
          400,
          'invalid_request',
          'Attendu : { name, deviceIds: [nombres], waves: [{ size }], confirmNoDeadman: true }.',
        );
      }
      if (!(await callerHas(req, CAPABILITIES.ROLLOUT_MANAGE))) {
        throw new AppError(
          403,
          `Cette action exige aussi '${CAPABILITIES.ROLLOUT_MANAGE}' : plusieurs routeurs sont traités par vagues, et ` +
            'composer et lancer un déploiement par vagues relève de ROLLOUT_MANAGE partout dans le produit.',
        );
      }
      const userId = req.session?.userId;
      if (!userId) throw new AppError(401, 'Authentication required');
      const out = await managementAccessLauncher.launchRollout({
        tenantId: req.tenantId,
        name: body.data.name.trim(),
        deviceIds: body.data.deviceIds,
        waves: body.data.waves,
        requestedBy: userId,
        confirmDegraded: { userId },
      });
      res.status(201).json({ success: true, data: out });
    } catch (err) {
      handle(err, res, next);
    }
  },
};
