import type { Request, Response, NextFunction } from 'express';
import type { RouterOsReleaseCheckOutcome, RouterOsReleaseCheckResult } from '@obliwan/shared';
import {
  checkRouterOsReleases,
  getRouterOsFirmwareStatus,
} from '../services/firmware/releases.service';
import { setRouterOsTarget, type SetTargetOptions } from '../services/firmware/target.service';

/**
 * RouterOS releases and the fleet target (routes/firmware.routes.ts).
 * Reads: any authenticated user. Writes: platform admin (requireRole('admin')
 * in the router). Errors are AppErrors from the services, mapped by
 * errorHandler: 400 for an invalid target or an unpublished pin, 502 when the
 * pin could not be confirmed.
 */

export interface FirmwareControllerDeps {
  /**
   * Harness only: replaces the call to upgrade.mikrotik.com behind
   * POST /check (the harness aims it at its fake origin).
   */
  checkReleases?: () => Promise<RouterOsReleaseCheckOutcome[]>;
  /** Harness only: replaces the HEAD to download.mikrotik.com behind PUT /target. */
  probe?: SetTargetOptions['probe'];
}

export function createFirmwareController(deps: FirmwareControllerDeps = {}) {
  const checkReleases = deps.checkReleases ?? (() => checkRouterOsReleases({ force: true }));
  return {
    /** GET /firmware/routeros: `data: RouterOsFirmwareStatus`. */
    async getRouterOs(_req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        res.json({ success: true, data: await getRouterOsFirmwareStatus() });
      } catch (err) {
        next(err);
      }
    },

    /** PUT /firmware/routeros/target `{ mode, pinned }`: `data: RouterOsFirmwareStatus`. */
    async putTarget(req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        await setRouterOsTarget(req.body, req.session?.userId ?? null, deps.probe ? { probe: deps.probe } : {});
        res.json({ success: true, data: await getRouterOsFirmwareStatus() });
      } catch (err) {
        next(err);
      }
    },

    /**
     * POST /firmware/routeros/check: reads both channels now. A MikroTik failure
     * is NOT an HTTP error here: it is recorded, the last good value is kept,
     * and the outcome says `ok: false` with the reason.
     */
    async check(_req: Request, res: Response, next: NextFunction): Promise<void> {
      try {
        const outcomes = await checkReleases();
        const data: RouterOsReleaseCheckResult = { outcomes, status: await getRouterOsFirmwareStatus() };
        res.json({ success: true, data });
      } catch (err) {
        next(err);
      }
    },
  };
}
