import type { Request, Response, NextFunction } from 'express';
import type { z, ZodTypeAny } from 'zod';
import type { InfraAnalysisApplyRequest, InfraAnalysisPreviewRequest } from '@obliwan/shared';
import {
  InfraAnalysisError,
  applyAnalysis,
  exportAnalysis,
  forgetAnalysis,
  getAnalysis,
  listCandidates,
  startAnalysis,
  type InfraActor,
} from '../services/infraAnalysis/infraAnalysis.service';
import {
  infraAnalysisApplySchema,
  infraAnalysisIdSchema,
  infraAnalysisPreviewSchema,
} from '../validators/infraAnalysis.schema';

// ============================================================================
// infraAnalysis.controller.ts — /api/infra-analysis
// ============================================================================
//
// PLATFORM ADMIN ONLY, on the session's CURRENT workspace (`req.tenantId`):
// the route installs requireRole('admin') and the service refuses any other
// actor again. A refusal of the service carries its `code`; a malformed body
// a 400 naming field PATHS only (a typed credential is never echoed). Nothing
// lands in the 401 band for a downstream refusal — the client logs the
// operator out on a 401 — and a router refusing a credential is a device
// row's `auth_failed`, never an HTTP status. The request body is never logged.
// ============================================================================

function actorOf(req: Request): InfraActor {
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

function analysisId(req: Request, res: Response): string | null {
  const parsed = infraAnalysisIdSchema.safeParse(req.params.id);
  if (parsed.success) return parsed.data;
  res.status(404).json({ success: false, error: 'No such analysis.', code: 'NOT_FOUND' });
  return null;
}

function handle(err: unknown, res: Response, next: NextFunction): void {
  if (err instanceof InfraAnalysisError) {
    res.status(err.httpStatus).json({ success: false, error: err.message, code: err.reason });
    return;
  }
  next(err);
}

export const infraAnalysisController = {
  /** GET /infra-analysis/candidates — the devices and the revisions with probes. */
  async candidates(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: await listCandidates(req.tenantId, actorOf(req)) });
    } catch (err) {
      handle(err, res, next);
    }
  },

  /** POST /infra-analysis/preview — starts the read; answers the first
   *  snapshot at once (every device pending). Writes nothing. */
  async preview(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(infraAnalysisPreviewSchema, req.body, res);
      if (!body) return;
      const { snapshot } = await startAnalysis(req.tenantId, body as InfraAnalysisPreviewRequest, actorOf(req));
      res.status(202).json({ success: true, data: snapshot });
    } catch (err) {
      handle(err, res, next);
    }
  },

  /** GET /infra-analysis/:id — progress and results. */
  async get(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = analysisId(req, res);
      if (!id) return;
      res.json({ success: true, data: getAnalysis(req.tenantId, actorOf(req), id) });
    } catch (err) {
      handle(err, res, next);
    }
  },

  /** POST /infra-analysis/apply — the selected rows as site values. */
  async apply(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = parse(infraAnalysisApplySchema, req.body, res);
      if (!body) return;
      res.json({ success: true, data: await applyAnalysis(req.tenantId, body as InfraAnalysisApplyRequest, actorOf(req)) });
    } catch (err) {
      handle(err, res, next);
    }
  },

  /** GET /infra-analysis/:id/export — the variables CSV and the LAN CSV. */
  async export(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = analysisId(req, res);
      if (!id) return;
      res.json({ success: true, data: exportAnalysis(req.tenantId, actorOf(req), id) });
    } catch (err) {
      handle(err, res, next);
    }
  },

  /** DELETE /infra-analysis/:id — forget it now, secrets included. */
  async forget(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = analysisId(req, res);
      if (!id) return;
      forgetAnalysis(req.tenantId, actorOf(req), id);
      res.json({ success: true });
    } catch (err) {
      handle(err, res, next);
    }
  },
};
