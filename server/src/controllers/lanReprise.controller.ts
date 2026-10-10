import type { Request, Response, NextFunction } from 'express';
import { AppError } from '../middleware/errorHandler';
import { AllocationError, PG_INT_MAX } from '../services/allocation';
import { lanReprise } from '../services/allocation/lanReprise';

/**
 * POST /api/allocation/tenants/:tenantId/lan-reprise[?dryRun=false]
 *   { csv: string, overwrite?: boolean }
 *
 * Records the deployed LAN of a tenant's existing sites on their allocations
 * (services/allocation/lanReprise.ts). Mounted in allocation.routes.ts, so it
 * is platform-admin only (`requireRole('admin')`) and the tenant is the PATH
 * parameter, like every allocation route: the LAN plan of a customer decides
 * what its shared pools may still hand out. A DRY RUN unless `dryRun=false`
 * is said explicitly — the screen's first click must never write.
 *
 * Answers `data: LanRepriseResult` (@obliwan/shared): one verdict per row,
 * with closed reason codes the screen translates. An AllocationError (the file
 * as a whole, the tenant) answers like the other allocation routes:
 * `{ success: false, error, reason, details? }`.
 */
function parseTenantId(raw: string): number {
  const id = /^\d{1,10}$/.test(raw) ? Number(raw) : NaN;
  if (!Number.isInteger(id) || id <= 0 || id > PG_INT_MAX) throw new AppError(400, 'Invalid tenant id');
  return id;
}

export const lanRepriseController = {
  async run(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const tenantId = parseTenantId(req.params.tenantId);
      const b: unknown = req.body;
      if (typeof b !== 'object' || b === null || Array.isArray(b)) {
        throw new AppError(400, 'The request body must be a JSON object');
      }
      const body = b as Record<string, unknown>;
      const dryRun = req.query.dryRun !== 'false';
      const data = await lanReprise(
        tenantId,
        { csv: body.csv, overwrite: body.overwrite },
        {
          dryRun,
          actor: { userId: req.session.userId ?? null, username: req.session.username ?? null },
        },
      );
      res.json({ success: true, data });
    } catch (err) {
      if (err instanceof AllocationError) {
        res.status(err.httpStatus).json({
          success: false,
          error: err.message,
          reason: err.reason,
          ...(err.details ? { details: err.details } : {}),
        });
        return;
      }
      next(err);
    }
  },
};
