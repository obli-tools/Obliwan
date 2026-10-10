import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { CAPABILITIES, WAN1_MODES, WAN1_PPPOE_NAMES, WAN_LINK_REVERT_MAX_S, WAN_LINK_REVERT_MIN_S, type Capability } from '@obliwan/shared';
import { AppError } from '../middleware/errorHandler';
import { permissionService } from '../services/permission.service';
import { KillSwitchEngagedError } from '../services/change/killSwitch.service';
import { DeviceBusyError } from '../services/change/jobQueue.service';
import { WanLinkError, enqueueWanLinkJob, getWanLinkView } from '../services/change/wanLink.service';
import { RolloutRefusedError, wanLinkLauncher } from '../services/change/rollout.service';

/**
 * The WAN1 link change on a router in service — HTTP layer
 * (routes/wanLink.routes.ts, mounted under `/devices` before devicesRoutes):
 *
 *   GET  /devices/:id/wan-link     the card's state (DEVICE_READ); dials nothing
 *   POST /devices/:id/wan-link     queue ONE job (CHANGE_APPLY, and
 *                                  SITE_VARIABLES_WRITE checked here: the job
 *                                  writes the site's WAN1 variables)
 *
 * Every read is scoped by `req.tenantId`. The body carries the target mode and
 * its parameters; a PPPoE password, when typed, is encrypted on the job row at
 * once and is never echoed, logged or returned. Refusals leave as
 * `{ success: false, error, code }` with the service's French sentence.
 */

const idParam = z.coerce.number().int().positive();
const enqueueSchema = z
  .object({
    toMode: z.enum(WAN1_MODES),
    pppoe: z
      .object({
        name: z.enum(WAN1_PPPOE_NAMES),
        username: z.string().min(1).max(64),
        // Absent or null: the password in the site's vault.
        password: z.string().max(64).nullable().optional(),
      })
      .strict()
      .optional(),
    static: z.object({ address: z.string().min(1).max(18), gateway: z.string().min(1).max(15) }).strict().optional(),
    revertAfterS: z.number().int().min(WAN_LINK_REVERT_MIN_S).max(WAN_LINK_REVERT_MAX_S).optional(),
    confirmExpectedCut: z.literal(true),
  })
  .strict();

const previewSchema = z
  .object({
    name: z.string().max(200).optional(),
    deviceIds: z.array(z.number().int().positive()).min(1).max(500),
    toMode: z.enum(WAN1_MODES),
  })
  .strict();
const launchSchema = z
  .object({
    name: z.string().min(1).max(200),
    deviceIds: z.array(z.number().int().positive()).min(1).max(500),
    toMode: z.enum(WAN1_MODES),
    waves: z.array(z.object({ size: z.number().int().positive() }).strict()).min(1).max(20),
    confirmExpectedCut: z.literal(true),
  })
  .strict();

function parseId(req: Request): number {
  const id = idParam.safeParse(req.params.id);
  if (!id.success) throw new AppError(400, 'Identifiant d’équipement invalide.');
  return id.data;
}

function refuse(res: Response, status: number, code: string, error: string): void {
  res.status(status).json({ success: false, error, code });
}

export function handleWanLinkError(err: unknown, res: Response, next: NextFunction): void {
  if (err instanceof WanLinkError) return refuse(res, err.httpStatus, err.kind, err.message);
  if (err instanceof KillSwitchEngagedError) {
    return refuse(res, 409, 'kill_switch', `Arrêt d’urgence engagé : aucune écriture n’est possible (${err.message}).`);
  }
  if (err instanceof DeviceBusyError) {
    return refuse(res, 409, 'device_busy', 'Une autre tâche est en cours sur ce routeur : relancez quand elle sera terminée.');
  }
  if (err instanceof RolloutRefusedError) {
    const status = err.kind === 'subtree_interlock' || err.kind === 'not_draft' ? 409 : 422;
    res.status(status).json({ success: false, error: err.message, code: err.kind, ...(err.detail ? { detail: err.detail } : {}) });
    return;
  }
  next(err);
}

export async function callerHas(req: Request, capability: Capability): Promise<boolean> {
  if (req.session?.role === 'admin') return true;
  const tenantId = req.tenantId ?? req.session?.currentTenantId;
  if (!req.session?.userId || !tenantId) return false;
  const caps = await permissionService.getUserCapabilities(req.session.userId, false, tenantId);
  return caps.includes(capability);
}

export const wanLinkController = {
  async get(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const view = await getWanLinkView(req.tenantId, parseId(req));
      if (!view) throw new AppError(404, 'Équipement introuvable.');
      // The step trace is the change queue's detail, as on legacy compliance.
      if (view.job && !(await callerHas(req, CAPABILITIES.CHANGE_APPLY))) view.job.steps = [];
      res.json({ success: true, data: view });
    } catch (err) {
      handleWanLinkError(err, res, next);
    }
  },

  async enqueue(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req);
      const body = enqueueSchema.safeParse(req.body ?? {});
      if (!body.success) {
        // The parse error is not forwarded: it could quote the password.
        return refuse(
          res,
          400,
          'invalid_request',
          'Attendu : { toMode: dhcp|pppoe|static, pppoe?: { name, username, password? }, static?: { address, gateway }, ' +
            'revertAfterS?, confirmExpectedCut: true }. La coupure prévue doit être confirmée explicitement.',
        );
      }
      if (!(await callerHas(req, CAPABILITIES.SITE_VARIABLES_WRITE))) {
        throw new AppError(
          403,
          `Cette action exige aussi '${CAPABILITIES.SITE_VARIABLES_WRITE}' : la tâche enregistre le nouveau mode WAN1 et ses ` +
            'paramètres dans les variables du site.',
        );
      }
      const userId = req.session?.userId;
      if (!userId) throw new AppError(401, 'Authentication required');
      const b = body.data;
      const out = await enqueueWanLinkJob({
        tenantId: req.tenantId,
        deviceId: id,
        requestedBy: userId,
        request: {
          toMode: b.toMode,
          params: {
            pppoe: b.toMode === 'pppoe' && b.pppoe ? { name: b.pppoe.name, username: b.pppoe.username, password: b.pppoe.password ?? null } : null,
            static: b.toMode === 'static' && b.static ? { address: b.static.address, gateway: b.static.gateway } : null,
          },
        },
        revertAfterS: b.revertAfterS,
        confirmExpectedCut: { userId },
        allowExisting: true,
      });
      res.status(out.alreadyQueued ? 200 : 202).json({ success: true, data: { jobId: out.jobId, alreadyQueued: out.alreadyQueued } });
    } catch (err) {
      handleWanLinkError(err, res, next);
    }
  },

  /** The rollout's impact screen, nothing written: per device, the refusals
   *  (the site's WAN1 variables read for the target's parameters). */
  async preview(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = previewSchema.safeParse(req.body ?? {});
      if (!body.success) return refuse(res, 400, 'invalid_request', 'Attendu : { deviceIds: [nombres], toMode: dhcp|pppoe|static, name? }.');
      const data = await wanLinkLauncher.preview({
        tenantId: req.tenantId,
        name: body.data.name?.trim() || 'preview',
        deviceIds: body.data.deviceIds,
        requestedBy: req.session?.userId ?? null,
        wanTargetMode: body.data.toMode,
      });
      res.json({ success: true, data });
    } catch (err) {
      handleWanLinkError(err, res, next);
    }
  },

  /** Compose AND launch a wan_link rollout (ROLLOUT_MANAGE and
   *  SITE_VARIABLES_WRITE checked here too). */
  async launchRollout(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = launchSchema.safeParse(req.body ?? {});
      if (!body.success) {
        return refuse(
          res,
          400,
          'invalid_request',
          'Attendu : { name, deviceIds: [nombres], toMode: dhcp|pppoe|static, waves: [{ size }], confirmExpectedCut: true }.',
        );
      }
      for (const cap of [CAPABILITIES.ROLLOUT_MANAGE, CAPABILITIES.SITE_VARIABLES_WRITE] as const) {
        if (!(await callerHas(req, cap))) {
          throw new AppError(
            403,
            cap === CAPABILITIES.ROLLOUT_MANAGE
              ? `Cette action exige aussi '${cap}' : plusieurs routeurs sont traités par vagues.`
              : `Cette action exige aussi '${cap}' : chaque tâche enregistre le nouveau mode WAN1 dans les variables du site.`,
          );
        }
      }
      const userId = req.session?.userId;
      if (!userId) throw new AppError(401, 'Authentication required');
      const out = await wanLinkLauncher.launchRollout({
        tenantId: req.tenantId,
        name: body.data.name.trim(),
        deviceIds: body.data.deviceIds,
        waves: body.data.waves,
        requestedBy: userId,
        confirmDegraded: { userId },
        wanTargetMode: body.data.toMode,
      });
      res.status(201).json({ success: true, data: out });
    } catch (err) {
      handleWanLinkError(err, res, next);
    }
  },
};
