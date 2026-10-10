import type { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { AppError } from '../middleware/errorHandler';
import { requirePickedTenant } from '../utils/globalView';
import { AllocationError } from '../services/allocation';
import {
  OnboardingError,
  approveInferredRule,
  getOnboardingStatus,
  inferRuleForTenant,
} from '../services/tenantSetup/onboarding.service';

// ============================================================================
// onboarding.controller.ts — the onboarding assistant (brick 14)
// ============================================================================
//
// Mounted in tenantSetup.routes.ts under `requireRole('admin')`, each route
// behind `adoptGodViewFilterTenant`: the tenant is the session's workspace,
// or the client picked in the god view's workspace filter. `requirePickedTenant`
// refuses the god view with nothing picked (400) — the assistant is one
// client's. `assertPlatformAdmin` repeats the route's guard so a re-mount
// behind a capability still refuses.
//
// Status codes: an assistant refusal keeps its own (400/404/409/422); an
// allocator refusal of the approved rule is a 422 with the allocator's
// sentence. Nothing lands in the 401/403 band for a downstream refusal (the
// client logs the operator out on a 401).
// ============================================================================

function assertPlatformAdmin(req: Request): void {
  if (req.session?.role !== 'admin') {
    throw new AppError(403, 'The onboarding assistant is reserved to platform administrators.');
  }
}

function mapError(err: unknown): unknown {
  if (err instanceof OnboardingError) return new AppError(err.status, err.message);
  if (err instanceof AllocationError) return new AppError(422, err.message);
  return err;
}

const approveSchema = z
  .object({
    slug: z.string().trim().max(64).optional(),
    fingerprint: z.string().regex(/^[0-9a-f]{64}$/),
  })
  .strict();

export const onboardingController = {
  /** GET /tenant-setup/onboarding — the nine steps, recomputed. Reads only. */
  async status(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      assertPlatformAdmin(req);
      requirePickedTenant(req);
      res.json({ success: true, data: await getOnboardingStatus(req.tenantId) });
    } catch (err) {
      next(mapError(err));
    }
  },

  /** GET /tenant-setup/onboarding/rule?slug= — the rule read off the CHR. Reads only. */
  async rule(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      assertPlatformAdmin(req);
      requirePickedTenant(req);
      const slug = typeof req.query.slug === 'string' ? req.query.slug : undefined;
      res.json({ success: true, data: await inferRuleForTenant(req.tenantId, { slug }) });
    } catch (err) {
      next(mapError(err));
    }
  },

  /** POST /tenant-setup/onboarding/rule/approve — save THE proposal shown
   *  (its fingerprint), through createPool + upsertPolicy. */
  async approveRule(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      assertPlatformAdmin(req);
      requirePickedTenant(req);
      const parsed = approveSchema.safeParse(req.body ?? {});
      if (!parsed.success) {
        const paths = [...new Set(parsed.error.issues.map((i) => (i.path.length > 0 ? i.path.join('.') : '(body)')))];
        res.status(400).json({ success: false, error: 'Validation failed', details: { paths } });
        return;
      }
      const result = await approveInferredRule(req.tenantId, parsed.data, {
        userId: req.session?.userId ?? null,
        username: req.session?.username ?? null,
      });
      res.json({ success: true, data: result });
    } catch (err) {
      next(mapError(err));
    }
  },
};
