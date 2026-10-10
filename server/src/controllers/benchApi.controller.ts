import type { NextFunction, Request, Response } from 'express';
import { AppError } from '../middleware/errorHandler';
import { assertApprovedBenchStation } from '../middleware/benchStation';
import {
  BenchApiError,
  listBenchSites,
  listBenchTenants,
  parseBenchBox,
  planForBox,
  positiveId,
} from '../services/bench/planning.service';
import { compileForBox, recordBenchResult } from '../services/bench/compile.service';

/**
 * The bench HTTP contract (/api/bench/v1), server side. Every route sits
 * behind `requireApprovedBenchStation` (routes/benchApi.routes.ts), and every
 * handler re-asserts it: `req.benchStation` alone does not prove an APPROVED
 * station (middleware/benchStation.ts).
 *
 * Refusals leave as `{ success: false, error, code }`, with a French sentence
 * the bench shows verbatim and, for a refusal of the bench services, its
 * machine-readable `code` (additive: `device_mode_denied`,
 * `replace_unconfirmed`…; an older bench reads `error` only). Anything else
 * goes through `errorHandler` (`{ success: false, error }`). None is in the
 * 401/403 band except the station guard's own: the bench reads 401/403 as
 * "this workstation is refused" (bench/benchApi.ts), never as "this request
 * is".
 *
 * Every answer is `Cache-Control: no-store`. It matters for the compile, whose
 * body holds every secret of the site, and costs nothing elsewhere.
 */

function noStore(res: Response): void {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
}

function forward(err: unknown, res: Response, next: NextFunction): void {
  if (err instanceof BenchApiError) {
    if (err.status === 401 || err.status === 403) {
      next(new AppError(err.status, err.message));
      return;
    }
    res.status(err.status).json({ success: false, error: err.message, code: err.code });
    return;
  }
  next(err);
}

/** An optional boolean of a body: absent or null is null, anything else but a
 *  boolean is a 400. */
function optionalBoolean(v: unknown, field: string): boolean | null {
  if (v === undefined || v === null) return null;
  if (typeof v !== 'boolean') throw new BenchApiError(400, `Le champ « ${field} » doit valoir true ou false.`, 'bad_input');
  return v;
}

function body(req: Request): Record<string, unknown> {
  return typeof req.body === 'object' && req.body !== null && !Array.isArray(req.body)
    ? (req.body as Record<string, unknown>)
    : {};
}

export const benchApiController = {
  async tenants(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      assertApprovedBenchStation(req);
      noStore(res);
      res.json({ success: true, data: await listBenchTenants() });
    } catch (err) {
      forward(err, res, next);
    }
  },

  async sites(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      assertApprovedBenchStation(req);
      const tenantId = positiveId(req.params.tenantId, 'tenantId');
      const search = typeof req.query.search === 'string' ? req.query.search : '';
      noStore(res);
      res.json({ success: true, data: await listBenchSites(tenantId, search) });
    } catch (err) {
      forward(err, res, next);
    }
  },

  async plan(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      assertApprovedBenchStation(req);
      const b = body(req);
      const siteId = positiveId(b.siteId, 'siteId');
      const box = parseBenchBox(b.box);
      noStore(res);
      res.json({ success: true, data: await planForBox(siteId, box) });
    } catch (err) {
      forward(err, res, next);
    }
  },

  async compile(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const station = assertApprovedBenchStation(req);
      const b = body(req);
      const siteId = positiveId(b.siteId, 'siteId');
      const revisionId = positiveId(b.revisionId, 'revisionId', Number.MAX_SAFE_INTEGER);
      const box = parseBenchBox(b.box);
      const deviceModeOverride = optionalBoolean(b.deviceModeOverride, 'deviceModeOverride');
      const confirmReplaceDeviceId = b.confirmReplaceDeviceId === undefined || b.confirmReplaceDeviceId === null
        ? null
        : positiveId(b.confirmReplaceDeviceId, 'confirmReplaceDeviceId');
      noStore(res);
      const data = await compileForBox({
        station: { id: station.id, name: station.name },
        siteId,
        revisionId,
        box,
        bench: b.bench,
        deviceModeOverride,
        confirmReplaceDeviceId,
      });
      res.json({ success: true, data });
    } catch (err) {
      noStore(res);
      forward(err, res, next);
    }
  },

  async result(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const station = assertApprovedBenchStation(req);
      const deviceId = positiveId(req.params.deviceId, 'deviceId');
      const b = body(req);
      await recordBenchResult({
        station: { id: station.id, name: station.name },
        deviceId,
        status: b.status,
        detail: b.detail,
        localCheck: b.localCheck,
        deviceModeOverride: b.deviceModeOverride,
        sim: b.sim,
      });
      noStore(res);
      res.json({ success: true, data: { ok: true } });
    } catch (err) {
      forward(err, res, next);
    }
  },
};
