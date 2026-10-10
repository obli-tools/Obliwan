import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { INFRA_ACCOUNT_ACTIONS } from '@obliwan/shared';
import { AppError } from '../middleware/errorHandler';
import {
  InfraConcentratorError,
  createInfraConcentrator,
  deleteInfraConcentrator,
  enqueueInfraAccount,
  getInfraAccountJobState,
  listInfraConcentrators,
  listSiteAccounts,
  previewInfraAccount,
  readInfraAccount,
  testInfraConcentrator,
  updateInfraConcentrator,
} from '../services/infraConcentrator';

/**
 * Infrastructure concentrators — HTTP layer (routes/infraConcentrator.routes.ts).
 * Platform admin only (the routes say so). Answers in French for the operator.
 *
 *   GET    /infra-concentrators/tenants/:tenantId                     list
 *   POST   /infra-concentrators/tenants/:tenantId                     declare
 *   GET    /infra-concentrators/tenants/:tenantId/sites/:siteId/accounts   the site's accounts
 *   PATCH  /infra-concentrators/:id                                   update
 *   DELETE /infra-concentrators/:id                                   delete the declaration
 *   POST   /infra-concentrators/:id/test                              test the connection
 *   GET    /infra-concentrators/:id/sites/:siteId                     read the site's entry
 *   POST   /infra-concentrators/:id/sites/:siteId/preview             plan, nothing written
 *   POST   /infra-concentrators/:id/sites/:siteId/enqueue             queue an infra_account job
 *   GET    /infra-concentrators/jobs/:jobId                           where a job stands
 *
 * No route returns a credential, and none takes an address to dial: the
 * targets are the stored declarations.
 */

const id = z.coerce.number().int().positive();
const actionSchema = z.object({ action: z.enum(INFRA_ACCOUNT_ACTIONS).optional() }).strict();

function num(req: Request, name: string): number {
  const v = id.safeParse(req.params[name]);
  if (!v.success) throw new AppError(400, `Paramètre ${name} invalide`);
  return v.data;
}

function handle(fn: (req: Request, res: Response) => Promise<void>) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      await fn(req, res);
    } catch (err) {
      if (err instanceof InfraConcentratorError) {
        res.status(err.httpStatus).json({ success: false, error: err.message, code: err.code });
        return;
      }
      next(err);
    }
  };
}

function action(req: Request) {
  const body = actionSchema.safeParse(req.body ?? {});
  if (!body.success) throw new InfraConcentratorError('invalid_request', 'Corps attendu : { action?: "ensure" | "revoke" }.');
  return body.data.action ?? 'ensure';
}

export const infraConcentratorController = {
  list: handle(async (req, res) => {
    res.json({ success: true, data: await listInfraConcentrators(num(req, 'tenantId')) });
  }),

  create: handle(async (req, res) => {
    const view = await createInfraConcentrator(num(req, 'tenantId'), req.body ?? {}, req.session?.userId ?? null);
    res.status(201).json({ success: true, data: view });
  }),

  update: handle(async (req, res) => {
    res.json({ success: true, data: await updateInfraConcentrator(num(req, 'id'), req.body ?? {}) });
  }),

  remove: handle(async (req, res) => {
    await deleteInfraConcentrator(num(req, 'id'));
    res.json({ success: true });
  }),

  test: handle(async (req, res) => {
    res.json({ success: true, data: await testInfraConcentrator(num(req, 'id')) });
  }),

  siteAccounts: handle(async (req, res) => {
    res.json({ success: true, data: await listSiteAccounts(num(req, 'tenantId'), num(req, 'siteId')) });
  }),

  read: handle(async (req, res) => {
    res.json({ success: true, data: await readInfraAccount({ concentratorId: num(req, 'id'), siteId: num(req, 'siteId') }) });
  }),

  preview: handle(async (req, res) => {
    const view = await previewInfraAccount({ concentratorId: num(req, 'id'), siteId: num(req, 'siteId'), action: action(req) });
    res.json({ success: true, data: view });
  }),

  enqueue: handle(async (req, res) => {
    const userId = req.session?.userId;
    if (!userId) throw new AppError(401, 'Authentication required');
    const state = await enqueueInfraAccount({
      concentratorId: num(req, 'id'),
      siteId: num(req, 'siteId'),
      action: action(req),
      requestedBy: userId,
    });
    res.status(202).json({ success: true, data: state });
  }),

  job: handle(async (req, res) => {
    res.json({ success: true, data: await getInfraAccountJobState(num(req, 'jobId')) });
  }),
};
