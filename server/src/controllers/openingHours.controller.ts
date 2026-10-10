import type { Request, Response, NextFunction } from 'express';
import {
  bulkSetSiteOpeningHours,
  getTenantOpeningHours,
  setTenantOpeningHours,
  type OpeningHoursActor,
  type OpeningHoursBulkResult,
} from '../services/fleet/openingHours.service';
import { auditGodViewFanOut } from '../services/godViewAudit.service';
import { fanOutByTenant } from '../utils/globalView';
import type { BulkSiteOpeningHoursInput, TenantOpeningHoursInput } from '../validators/openingHours.schema';

/**
 * Store opening hours (migration 096) — the workspace's usual hours and the
 * bulk write on selected sites. A single site's own hours go through the site
 * edit (`PATCH /sites/:id { openingHours }`). Mounted in sites.routes.ts.
 */

function actorOf(req: Request): OpeningHoursActor {
  return {
    userId: req.session?.userId ?? null,
    username: req.session?.username ? req.session.username.slice(0, 128) : null,
  };
}

export const openingHoursController = {
  /** GET /sites/opening-hours — the session workspace's own hours (null = none). */
  async getTenant(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: { openingHours: await getTenantOpeningHours(req.tenantId) } });
    } catch (err) {
      next(err);
    }
  },

  /** PUT /sites/opening-hours — `{ openingHours }`, the value, its text, or null. */
  async putTenant(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = req.body as TenantOpeningHoursInput;
      const saved = await setTenantOpeningHours(req.tenantId, body.openingHours, actorOf(req));
      res.json({ success: true, data: { openingHours: saved } });
    } catch (err) {
      next(err);
    }
  },

  /** POST /sites/bulk/opening-hours — `{ ids, openingHours, mode }`. */
  async bulk(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = req.body as BulkSiteOpeningHoursInput;
      const { godView, batches } = await fanOutByTenant(req, 'sites', body.ids, (tid, ids) =>
        bulkSetSiteOpeningHours(tid, ids, body.openingHours, body.mode, actorOf(req)));
      if (!godView) {
        res.json({ success: true, data: batches[0].result });
        return;
      }
      await auditGodViewFanOut(req, 'site.opening_hours.bulk', batches, { mode: body.mode });
      const sum = (pick: (r: OpeningHoursBulkResult) => number) => batches.reduce((n, b) => n + pick(b.result), 0);
      res.json({
        success: true,
        godView: true,
        data: {
          requested: sum((r) => r.requested),
          changed: sum((r) => r.changed),
          unchanged: sum((r) => r.unchanged),
          changedSiteIds: batches.flatMap((b) => b.result.changedSiteIds).sort((a, b) => a - b),
        },
      });
    } catch (err) {
      next(err);
    }
  },
};
