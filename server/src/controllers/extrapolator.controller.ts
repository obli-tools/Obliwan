/**
 * Brick 10 — the template extrapolator, HTTP layer.
 *
 * Mounted inside the baseline router (`/api/…/baseline/extrapolations…`),
 * tenant-scoped through `req.tenantId` like every baseline route. A proposal of
 * another tenant is a 404, never a 403 (no enumeration oracle).
 *
 * Starting a run answers 202 with the run row: the work continues in the
 * background (see extrapolator.service.ts) and the client polls the run.
 */

import type { NextFunction, Request, Response } from 'express';
import type { ExtrapolationReadiness } from '@obliwan/shared';
import { AppError } from '../middleware/errorHandler';
import * as extrapolator from '../services/baseline/extrapolator/extrapolator.service';
import { canReadEveryDevice, deviceListScope } from '../services/teamScope.service';
import { tenantCollectState } from '../services/drift/runtime';
import { requirePickedTenant } from '../utils/globalView';

/**
 * Mining reads EVERY configuration of the tenant: an account whose teams cover
 * only part of it may not start one (a baseline of some routers is not the
 * fleet's). Since migration 087 a tenant administrator is scoped to its teams
 * like anybody else, so the test is "does the account read every router of the
 * workspace" (a platform admin, or an account holding the whole-workspace team).
 * Exported for the baseline controller, whose `POST /runs` mines the same way.
 */
export async function requireTenantWideMining(req: Request): Promise<void> {
  if (!req.session?.userId || !(await canReadEveryDevice(req))) {
    throw new AppError(
      403,
      'Mining reads every configuration of the client: it needs an account whose teams cover the ' +
        'whole workspace (or a platform administrator), not a part of it.',
    );
  }
}

function parseId(raw: string | undefined, what: string): number {
  const id = Number.parseInt(raw ?? '', 10);
  if (!Number.isInteger(id) || id <= 0) throw new AppError(400, `Invalid ${what}`);
  return id;
}

function actorOf(req: Request): { userId: number | null; username: string | null } {
  return {
    userId: req.session?.userId ?? null,
    username: req.session?.username ? req.session.username.slice(0, 128) : null,
  };
}

export const extrapolatorController = {
  async start(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      // From the god view the client is picked in the workspace filter first
      // (baseline.routes adopts it): mining the master tenant would mine the
      // shared concentrator and look like a success.
      requirePickedTenant(req);
      await requireTenantWideMining(req);
      res.status(202).json(await extrapolator.startExtrapolation(req.tenantId, req.body ?? {}, req.session?.userId ?? null));
    } catch (err) {
      next(err);
    }
  },

  /** Which of the client's routers the extrapolator can read, per model. */
  async readiness(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body: ExtrapolationReadiness = {
        ...(await extrapolator.getReadiness(req.tenantId, await deviceListScope(req))),
        collect: tenantCollectState(req.tenantId),
      };
      res.json(body);
    } catch (err) {
      next(err);
    }
  },

  async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const limit = Number.parseInt(String(req.query.limit ?? '25'), 10);
      res.json(await extrapolator.listRuns(req.tenantId, Number.isFinite(limit) ? limit : 25));
    } catch (err) {
      next(err);
    }
  },

  async get(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json(await extrapolator.getRun(req.tenantId, parseId(req.params.id, 'run id')));
    } catch (err) {
      next(err);
    }
  },

  async proposal(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json(await extrapolator.getProposal(req.tenantId, parseId(req.params.id, 'proposal id')));
    } catch (err) {
      next(err);
    }
  },

  async site(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json(await extrapolator.getSiteResult(
        req.tenantId,
        parseId(req.params.id, 'proposal id'),
        parseId(req.params.deviceId, 'device id'),
      ));
    } catch (err) {
      next(err);
    }
  },

  /** TEMPLATE_WRITE: a template, a DRAFT revision and the non-secret values. */
  async approve(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.status(201).json(await extrapolator.approveProposal(
        req.tenantId, parseId(req.params.id, 'proposal id'), req.body ?? {}, actorOf(req),
      ));
    } catch (err) {
      next(err);
    }
  },

  async reject(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json(await extrapolator.rejectProposal(
        req.tenantId, parseId(req.params.id, 'proposal id'), req.body ?? {}, actorOf(req),
      ));
    } catch (err) {
      next(err);
    }
  },
};
