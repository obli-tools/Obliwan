import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { AppError } from '../middleware/errorHandler';
import {
  ConcentratorLinkError,
  ensureConcentratorLink,
  getConcentratorLinkView,
  switchConcentratorApi,
} from '../services/concentratorLink/link.service';

/**
 * The ObliWAN <-> concentrator WireGuard link — HTTP layer
 * (routes/concentratorLink.routes.ts). Every route is platform-admin only
 * plus CHANGE_APPLY: the CHR is shared by every tenant's sites, and the POST
 * queues a write on it.
 *
 *   GET  /concentrators/:id/link                 both halves, probed
 *   POST /concentrators/:id/link                 queue the CHR half (a change job)
 *   POST /concentrators/:id/link/api-transport   move the CHR's own API transport
 *                                                into the tunnel, or back
 *
 * No route returns the private key (the view carries only public keys), and
 * no route takes an address to dial: the probes' targets come from the
 * database (a diagnostic that takes a host from the request is SSRF).
 */

const idParam = z.coerce.number().int().positive();

const connectSchema = z
  .object({
    transit: z.string().max(32).nullable().optional(),
    listenPort: z.number().int().nullable().optional(),
    confirmNoDeadman: z.literal(true),
  })
  .strict();

const switchSchema = z.object({ via: z.enum(['tunnel', 'public']) }).strict();

function refusal(res: Response, err: ConcentratorLinkError): void {
  res.status(err.httpStatus).json({ success: false, error: err.message, code: err.kind });
}

function parseId(req: Request): number {
  const id = idParam.safeParse(req.params.id);
  if (!id.success) throw new AppError(400, 'Invalid concentrator id');
  return id.data;
}

export const concentratorLinkController = {
  async get(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const view = await getConcentratorLinkView(parseId(req));
      res.json({ success: true, data: view });
    } catch (err) {
      if (err instanceof ConcentratorLinkError) return refusal(res, err);
      next(err);
    }
  },

  async connect(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req);
      const body = connectSchema.safeParse(req.body ?? {});
      if (!body.success) {
        res.status(400).json({
          success: false,
          error:
            'Expected { confirmNoDeadman: true, transit?: "a.b.c.d/30", listenPort?: number }: the job arms no ' +
            'dead-man, and queuing it requires that explicit confirmation.',
          code: 'invalid_request',
        });
        return;
      }
      const userId = req.session?.userId;
      if (!userId) throw new AppError(401, 'Authentication required');
      const out = await ensureConcentratorLink({
        concentratorId: id,
        requestedBy: userId,
        transit: body.data.transit ?? null,
        listenPort: body.data.listenPort ?? null,
        confirmNoDeadman: body.data.confirmNoDeadman,
      });
      res.status(202).json({ success: true, data: out });
    } catch (err) {
      if (err instanceof ConcentratorLinkError) return refusal(res, err);
      next(err);
    }
  },

  async switchApi(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseId(req);
      const body = switchSchema.safeParse(req.body ?? {});
      if (!body.success) {
        res.status(400).json({ success: false, error: 'Expected { via: "tunnel" | "public" }', code: 'invalid_request' });
        return;
      }
      const userId = req.session?.userId;
      if (!userId) throw new AppError(401, 'Authentication required');
      const out = await switchConcentratorApi(id, body.data.via, userId);
      res.json({ success: true, data: out });
    } catch (err) {
      if (err instanceof ConcentratorLinkError) return refusal(res, err);
      next(err);
    }
  },
};
