/**
 * « Rapprochement SIM » — partner client → customer tenant (migration 081).
 *
 * PLATFORM admin (`requireRole('admin')` on the route) AND the master tenant's
 * god view (`hasGlobalView`, the verdict `requireTenant` stored): the screen
 * lists every customer's partner clients and moves lines BETWEEN tenants,
 * which is the platform act `updateLine` already reserves to `masterView`.
 */
import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { AppError } from '../middleware/errorHandler';
import { hasGlobalView } from '../utils/globalView';
import {
  LINES_ON_UNMAP,
  SimClientMapError,
  UNMAP_NEEDS_CHOICE,
  listSimClients,
  setClientMapping,
  type LinesOnUnmap,
} from '../services/sim/clientTenant.service';
import {
  SimLinkConflictError,
  assignConflictLine,
  dismissConflict,
  listLinkConflicts,
  reopenConflict,
  type ConflictActor,
} from '../services/sim/linkConflict.service';

/**
 * `tenantId: null` removes a mapping, and then `linesOnUnmap` is REQUIRED
 * (never defaulted): 'stay' keeps every line where it is, 'pool' returns the
 * lines of the mapped workspace to the pool except those on one of its
 * routers (clientTenant.service `MappingDecision`). Exported for the harness.
 */
export const decisionsSchema = z.object({
  decisions: z
    .array(
      z
        .object({
          accountId: z.number().int().positive(),
          clientCode: z.string().trim().min(1).max(64),
          tenantId: z.number().int().positive().nullable(),
          linesOnUnmap: z.enum(LINES_ON_UNMAP as [LinesOnUnmap, ...LinesOnUnmap[]]).optional(),
        })
        .superRefine((d, ctx) => {
          if (d.tenantId === null && d.linesOnUnmap === undefined) {
            ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['linesOnUnmap'], message: UNMAP_NEEDS_CHOICE });
          }
        }),
    )
    .min(1)
    .max(500),
});

function assertGodView(req: Request): void {
  if (!hasGlobalView(req)) {
    throw new AppError(403, 'SIM reconciliation is a platform action, from the master workspace.');
  }
}

function toHttp(err: unknown): unknown {
  if (err instanceof SimClientMapError) return new AppError(err.status, err.message);
  if (err instanceof SimLinkConflictError) return new AppError(err.status, err.message);
  return err;
}

function conflictActor(req: Request): ConflictActor {
  const userId = req.session.userId;
  if (typeof userId !== 'number') throw new AppError(401, 'Not authenticated');
  return { id: userId, name: req.session.username ?? String(userId), fromTenantId: req.tenantId };
}

function conflictId(raw: string): number {
  const id = Number.parseInt(raw, 10);
  if (!Number.isInteger(id) || id <= 0 || id > 2147483647) throw new AppError(400, 'Invalid conflict id');
  return id;
}

const dismissSchema = z.object({ note: z.string().max(500).nullable().optional() });

export const simReconcileController = {
  async listClients(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      assertGodView(req);
      res.json({ success: true, data: await listSimClients() });
    } catch (err) {
      next(toHttp(err));
    }
  },

  async applyMappings(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      assertGodView(req);
      const parsed = decisionsSchema.safeParse(req.body);
      if (!parsed.success) {
        // The one refusal an operator can act on is named; the rest stay generic.
        const unmap = parsed.error.issues.some((i) => i.message === UNMAP_NEEDS_CHOICE);
        throw new AppError(400, unmap ? UNMAP_NEEDS_CHOICE : 'Validation failed');
      }
      const userId = req.session.userId;
      if (typeof userId !== 'number') throw new AppError(401, 'Not authenticated');
      const actor = { id: userId, name: req.session.username ?? String(userId) };
      const results: Array<{
        accountId: number;
        clientCode: string;
        ok: boolean;
        moved?: number;
        sitesAttached?: number;
        keptElsewhere?: number;
        returnedToPool?: number;
        keptOnRouter?: number;
        error?: string;
      }> = [];
      // One decision, one transaction: a refused row does not undo the others.
      for (const d of parsed.data.decisions) {
        try {
          const r = await setClientMapping(d, actor);
          results.push({
            accountId: d.accountId,
            clientCode: d.clientCode,
            ok: true,
            moved: r.moved,
            sitesAttached: r.sitesAttached,
            keptElsewhere: r.keptElsewhere,
            returnedToPool: r.returnedToPool,
            keptOnRouter: r.keptOnRouter,
          });
        } catch (err) {
          if (!(err instanceof SimClientMapError)) throw err;
          results.push({ accountId: d.accountId, clientCode: d.clientCode, ok: false, error: err.message });
        }
      }
      res.json({ success: true, data: results });
    } catch (err) {
      next(toHttp(err));
    }
  },

  // ── Line ↔ router conflicts (sim_link_conflicts, migration 080) ─────────────

  async listConflicts(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      assertGodView(req);
      const includeDismissed = req.query.includeDismissed === 'true';
      res.json({ success: true, data: await listLinkConflicts({ includeDismissed }) });
    } catch (err) {
      next(toHttp(err));
    }
  },

  /** The line goes to the router that read its card: tenant, router, site. Audited. */
  async assignConflict(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      assertGodView(req);
      res.json({ success: true, data: await assignConflictLine(conflictId(req.params.id), conflictActor(req)) });
    } catch (err) {
      next(toHttp(err));
    }
  },

  /** Nothing moves; the conflict leaves the open list until it changes. Audited. */
  async dismissConflict(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      assertGodView(req);
      const parsed = dismissSchema.safeParse(req.body ?? {});
      if (!parsed.success) throw new AppError(400, 'Validation failed — note: at most 500 characters');
      await dismissConflict(conflictId(req.params.id), conflictActor(req), parsed.data.note ?? null);
      res.json({ success: true });
    } catch (err) {
      next(toHttp(err));
    }
  },

  async reopenConflict(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      assertGodView(req);
      await reopenConflict(conflictId(req.params.id), conflictActor(req));
      res.json({ success: true });
    } catch (err) {
      next(toHttp(err));
    }
  },
};
