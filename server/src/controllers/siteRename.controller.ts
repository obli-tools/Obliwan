import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { CAPABILITIES, type Capability } from '@obliwan/shared';
import { AppError } from '../middleware/errorHandler';
import { permissionService } from '../services/permission.service';
import { KillSwitchEngagedError } from '../services/change/killSwitch.service';
import { DeviceBusyError } from '../services/change/jobQueue.service';
import {
  SiteRenameError,
  enqueueSiteRenameJob,
  getSiteRenameView,
  launchSiteRenameBulk,
  previewSiteRenameBulk,
} from '../services/change/siteRename.service';

/**
 * Renaming a site's router — HTTP layer (routes/siteRename.routes.ts, mounted
 * under `/devices` before devicesRoutes):
 *
 *   GET  /devices/:id/site-rename              the card (DEVICE_READ; the step
 *                                              trace only with CHANGE_APPLY)
 *   POST /devices/:id/site-rename              queue ONE rename (CHANGE_APPLY,
 *                                              platform admin)
 *   POST /devices/site-rename/bulk/preview     the « all lowercase » preview of
 *                                              a site selection, nothing written
 *                                              (CHANGE_APPLY, platform admin)
 *   POST /devices/site-rename/bulk             queue one rename per site
 *                                              (CHANGE_APPLY, platform admin)
 *
 * PLATFORM ADMIN ONLY to queue or preview: the job writes on the SHARED
 * concentrator (the CHR of the master tenant, every customer's tunnels), which
 * no customer-tenant role may touch. Every read is scoped by `req.tenantId`
 * (the god view enters the object's tenant first). No route takes an address,
 * a credential or an interface name: the names it takes are judged against
 * the job's alphabet, and the job dials the device's own SSH transport and the
 * device's own concentrator. Refusals leave as `{ success: false, error, code }`
 * with the service's French sentence.
 */

const idParam = z.coerce.number().int().positive();
const name = z.string().trim().min(1).max(128);
const enqueueSchema = z
  .object({
    login: name.optional(),
    identity: name.optional(),
    siteCode: z.string().trim().min(1).max(64).optional(),
    transform: z.literal('lowercase').optional(),
    includeSiteCode: z.boolean().optional(),
    relaunch: z.boolean().optional(),
    confirmNoDeadman: z.literal(true),
  })
  .strict();
const bulkPreviewSchema = z
  .object({
    siteIds: z.array(z.number().int().positive()).min(1).max(500),
    transform: z.literal('lowercase'),
    includeSiteCode: z.boolean().optional(),
  })
  .strict();
const bulkLaunchSchema = bulkPreviewSchema.extend({ confirmNoDeadman: z.literal(true) }).strict();

function parseId(req: Request): number {
  const id = idParam.safeParse(req.params.id);
  if (!id.success) throw new AppError(400, 'Identifiant d’équipement invalide.');
  return id.data;
}

function refuse(res: Response, status: number, code: string, error: string): void {
  res.status(status).json({ success: false, error, code });
}

function handle(err: unknown, res: Response, next: NextFunction): void {
  if (err instanceof SiteRenameError) return refuse(res, err.httpStatus, err.kind, err.message);
  if (err instanceof KillSwitchEngagedError) {
    return refuse(res, 409, 'kill_switch', `Arrêt d’urgence engagé : aucune écriture n’est possible (${err.message}).`);
  }
  if (err instanceof DeviceBusyError) {
    return refuse(res, 409, 'device_busy', 'Une autre tâche est en cours sur ce routeur : relancez quand elle sera terminée.');
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

/** The rename writes on the shared CHR: platform admins only. */
function requirePlatformAdmin(req: Request, res: Response): boolean {
  if (req.session?.role === 'admin') return true;
  refuse(res, 403, 'platform_admin_required',
    'Le renommage écrit sur le concentrateur partagé (MkManagement) : il est réservé aux administrateurs de la plateforme.');
  return false;
}

export const siteRenameController = {
  async get(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const view = await getSiteRenameView(req.tenantId, parseId(req));
      if (!view) throw new AppError(404, 'Équipement introuvable.');
      if (view.job && !(await callerHas(req, CAPABILITIES.CHANGE_APPLY))) view.job.steps = [];
      res.json({ success: true, data: { ...view, canLaunch: req.session?.role === 'admin' } });
    } catch (err) {
      handle(err, res, next);
    }
  },

  async enqueue(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!requirePlatformAdmin(req, res)) return;
      const id = parseId(req);
      const body = enqueueSchema.safeParse(req.body ?? {});
      if (!body.success) {
        return refuse(
          res,
          400,
          'invalid_request',
          'Attendu : { login?, identity?, siteCode?, transform?: "lowercase", includeSiteCode?, relaunch?, confirmNoDeadman: true }. ' +
            'La tâche n’arme aucun dead-man ; la mettre en file exige cette confirmation explicite.',
        );
      }
      const userId = req.session?.userId;
      if (!userId) throw new AppError(401, 'Authentication required');
      const b = body.data;
      const out = await enqueueSiteRenameJob({
        tenantId: req.tenantId,
        deviceId: id,
        to: { login: b.login, identity: b.identity, siteCode: b.siteCode },
        transform: b.transform,
        includeSiteCode: b.includeSiteCode === true,
        relaunch: b.relaunch === true,
        requestedBy: userId,
        confirmDegraded: { userId },
        allowExisting: true,
      });
      res.status(out.alreadyQueued ? 200 : 202).json({ success: true, data: out });
    } catch (err) {
      handle(err, res, next);
    }
  },

  async bulkPreview(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!requirePlatformAdmin(req, res)) return;
      const body = bulkPreviewSchema.safeParse(req.body ?? {});
      if (!body.success) return refuse(res, 400, 'invalid_request', 'Attendu : { siteIds: [nombres], transform: "lowercase", includeSiteCode? }.');
      const rows = await previewSiteRenameBulk(req.tenantId, body.data.siteIds, body.data.includeSiteCode === true);
      res.json({ success: true, data: { rows } });
    } catch (err) {
      handle(err, res, next);
    }
  },

  async bulkLaunch(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!requirePlatformAdmin(req, res)) return;
      const body = bulkLaunchSchema.safeParse(req.body ?? {});
      if (!body.success) {
        return refuse(res, 400, 'invalid_request', 'Attendu : { siteIds: [nombres], transform: "lowercase", includeSiteCode?, confirmNoDeadman: true }.');
      }
      const userId = req.session?.userId;
      if (!userId) throw new AppError(401, 'Authentication required');
      const rows = await launchSiteRenameBulk({
        tenantId: req.tenantId,
        siteIds: body.data.siteIds,
        includeSiteCode: body.data.includeSiteCode === true,
        requestedBy: userId,
        confirmDegraded: { userId },
      });
      res.status(202).json({ success: true, data: { rows } });
    } catch (err) {
      handle(err, res, next);
    }
  },
};
