import type { Request, Response, NextFunction } from 'express';
import type { z, ZodTypeAny } from 'zod';
import { fanOutByTenant } from '../utils/globalView';
import { LearningError, type LearningActor } from '../services/learning/guard';
import { getRun, startCaptureRun } from '../services/learning/capture.service';
import {
  buildDataset,
  captureDetail,
  captureExportText,
  listLearningDevices,
  setLearning,
} from '../services/learning/learning.service';
import { breakRiskForDevice } from '../services/learning/breakRisk.service';
import {
  learningBreakRiskQuerySchema,
  learningBulkStateSchema,
  learningCaptureSchema,
  learningDatasetSchema,
  learningListQuerySchema,
  learningToggleSchema,
  numericIdSchema,
  runIdSchema,
} from '../validators/learning.schema';

// ============================================================================
// learning.controller.ts — /api/learning
// ============================================================================
//
// PLATFORM ADMIN ONLY (the route installs requireRole('admin'), every service
// refuses any other actor again). A service refusal carries its `code`; a
// malformed body is a 400 naming field PATHS only. Nothing lands in the 401
// band — the client logs the operator out on a 401 — and a router refusing a
// credential is a capture row's `auth_failed`, never an HTTP status.
// ============================================================================

function actorOf(req: Request): LearningActor {
  return {
    userId: Number(req.session.userId),
    username: req.session.username ?? null,
    platformAdmin: req.session.role === 'admin',
  };
}

function parse<S extends ZodTypeAny>(schema: S, body: unknown, res: Response): z.infer<S> | null {
  const result = schema.safeParse(body ?? {});
  if (result.success) return result.data as z.infer<S>;
  const paths = [...new Set(result.error.issues.map((i) => (i.path.length > 0 ? i.path.join('.') : '(body)')))];
  res.status(400).json({ success: false, error: 'Validation failed', details: { paths: paths.slice(0, 50) } });
  return null;
}

function numericParam(req: Request, res: Response, name = 'id'): number | null {
  const parsed = numericIdSchema.safeParse(req.params[name]);
  if (parsed.success) return Number(parsed.data);
  res.status(404).json({ success: false, error: 'Not found.', code: 'NOT_FOUND' });
  return null;
}

function handle(err: unknown, res: Response, next: NextFunction): void {
  if (err instanceof LearningError) {
    res.status(err.httpStatus).json({ success: false, error: err.message, code: err.reason });
    return;
  }
  next(err);
}

export const learningController = {
  /** GET /learning/devices — every MikroTik CPE with its learning state and last capture. */
  async devices(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(learningListQuerySchema, req.query, res);
      if (!q) return;
      const data = await listLearningDevices(
        req.tenantId,
        { learningOnly: q.learningOnly === 'true', search: q.search ?? null },
        actorOf(req),
      );
      res.json({ success: true, data: data.devices, ...(data.godView ? { godView: true } : {}) });
    } catch (err) {
      handle(err, res, next);
    }
  },

  /** PUT /learning/devices/:id { learning } — one router in or out of learning. */
  async toggle(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = numericParam(req, res);
      if (id === null) return;
      const body = parse(learningToggleSchema, req.body, res);
      if (!body) return;
      res.json({ success: true, data: await setLearning(req.tenantId, [id], body.learning, actorOf(req)) });
    } catch (err) {
      handle(err, res, next);
    }
  },

  /** POST /learning/devices/state { deviceIds, learning } — in bulk, per tenant in the god view. */
  async bulkState(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(learningBulkStateSchema, req.body, res);
      if (!body) return;
      const actor = actorOf(req);
      const { batches } = await fanOutByTenant(req, 'devices', body.deviceIds, (tenantId, ids) =>
        setLearning(tenantId, ids, body.learning, actor));
      res.json({
        success: true,
        data: {
          changed: batches.flatMap((b) => b.result.changed),
          skipped: batches.flatMap((b) => b.result.skipped),
        },
      });
    } catch (err) {
      handle(err, res, next);
    }
  },

  /** POST /learning/captures { deviceIds } — start a capture; answers at once. */
  async capture(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(learningCaptureSchema, req.body, res);
      if (!body) return;
      const { runId, total } = await startCaptureRun(req.tenantId, body.deviceIds, actorOf(req));
      res.status(202).json({ success: true, data: { runId, total } });
    } catch (err) {
      handle(err, res, next);
    }
  },

  /** GET /learning/runs/:runId — the run's progress. */
  async run(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const parsed = runIdSchema.safeParse(req.params.runId);
      if (!parsed.success) {
        res.status(404).json({ success: false, error: 'No such capture run.', code: 'NOT_FOUND' });
        return;
      }
      res.json({ success: true, data: await getRun(req.tenantId, parsed.data, actorOf(req)) });
    } catch (err) {
      handle(err, res, next);
    }
  },

  /** GET /learning/devices/:id/capture — the latest capture's facts, refs, withheld lines. */
  async captureDetail(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = numericParam(req, res);
      if (id === null) return;
      res.json({ success: true, data: await captureDetail(req.tenantId, id, actorOf(req)) });
    } catch (err) {
      handle(err, res, next);
    }
  },

  /** GET /learning/captures/:id/export — the redacted copy (placeholders, no value). */
  async exportText(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = numericParam(req, res);
      if (id === null) return;
      res.set('Cache-Control', 'no-store');
      res.json({ success: true, data: await captureExportText(req.tenantId, id, actorOf(req)) });
    } catch (err) {
      handle(err, res, next);
    }
  },

  /** GET /learning/devices/:id/break-risk?revisionId= — template vs production. */
  async breakRisk(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = numericParam(req, res);
      if (id === null) return;
      const q = parse(learningBreakRiskQuerySchema, req.query, res);
      if (!q) return;
      res.json({ success: true, data: await breakRiskForDevice(req.tenantId, id, q.revisionId ?? null, actorOf(req)) });
    } catch (err) {
      handle(err, res, next);
    }
  },

  /** POST /learning/dataset { deviceIds } — the redacted dataset (one tenant). */
  async dataset(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(learningDatasetSchema, req.body, res);
      if (!body) return;
      res.set('Cache-Control', 'no-store');
      res.json({ success: true, data: await buildDataset(req.tenantId, body.deviceIds, actorOf(req)) });
    } catch (err) {
      handle(err, res, next);
    }
  },
};
