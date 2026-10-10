import type { NextFunction, Request, Response } from 'express';
import type { TlsRepinRequest } from '@obliwan/shared';
import { AppError } from '../middleware/errorHandler';
import { repinToPresented, TlsRepinError } from '../services/fleet/tlsRepin.service';

/**
 * Re-pin a RouterOS API channel to the certificate the device presented.
 * Refusals leave as `{ success: false, error, code }`, `code` from
 * `TLS_REPIN_REFUSALS`, which the screen translates. None of them is a 401:
 * the client logs the operator out on a 401, and nothing here is about the
 * session.
 */
export const tlsRepinController = {
  async repin(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = Number.parseInt(req.params.id, 10);
      if (!Number.isInteger(id) || id <= 0) throw new AppError(400, 'Invalid id');
      const body = req.body as TlsRepinRequest;
      const data = await repinToPresented({
        tenantId: req.tenantId,
        deviceId: id,
        presented: body.presented,
        pinned: body.pinned,
        actor: {
          userId: req.session?.userId ?? null,
          username: req.session?.username ?? null,
          // `users.role`, as `requireAuth` revalidated it — the expression
          // `devices.controller.ts` trusts for the shared-concentrator rules.
          platformAdmin: req.session?.role === 'admin',
        },
      });
      res.json({ success: true, data });
    } catch (err) {
      if (err instanceof TlsRepinError) {
        res.status(err.httpStatus).json({ success: false, error: err.message, code: err.code });
        return;
      }
      next(err);
    }
  },
};
