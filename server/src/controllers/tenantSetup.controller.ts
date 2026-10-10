import type { Request, Response, NextFunction } from 'express';
import type { z, ZodTypeAny } from 'zod';
import { SETUP_TENANT_MISMATCH, type TenantSetupRequest } from '@obliwan/shared';
import { AppError } from '../middleware/errorHandler';
import {
  SetupBusyError,
  SetupInputError,
  SetupRefusedError,
  SetupTenantMismatchError,
  applySetup,
  checkSetup,
  getSetupContext,
} from '../services/tenantSetup/tenantSetup.service';
import { tenantSetupContextSchema, tenantSetupRequestSchema } from '../validators/tenantSetup.schema';

// ============================================================================
// tenantSetup.controller.ts — Quick Setup Tenant (/api/tenant-setup)
// ============================================================================
//
// PLATFORM ADMIN ONLY, on the session's CURRENT workspace (`req.tenantId`).
// The route installs `requireRole('admin')`; `assertPlatformAdmin` repeats it
// here, as variables.controller does for the instance level, so a future
// re-mount behind a mere capability still refuses: the setup writes instance
// variables (every tenant's renders) and the allocation rule (shared pools).
// Because of that guard, every per-file permission the reused services ask
// (SITE_VARIABLES_WRITE, the schedule capability, allocate) is answered yes.
//
// Status codes: a refusal of the SETUP is a 422 carrying the report; a busy
// workspace a 409; a body prepared for another workspace than the session's
// a 409 with `code: SETUP_TENANT_MISMATCH` (the session is shared by every
// tab, so a switch in another one must not redirect these drafts); a
// malformed body a 400 naming field PATHS only. Nothing
// lands in the 401/403 band for a downstream refusal: the client logs the
// operator out on a 401.
//
// The request body is never logged: it may carry secret values.
// ============================================================================

function assertPlatformAdmin(req: Request): void {
  if (req.session?.role !== 'admin') {
    throw new AppError(403, 'Quick Setup Tenant is reserved to platform administrators.');
  }
}

/** A malformed body: the field PATHS only, never zod's messages — one of them
 *  could otherwise describe a value. */
function parse<S extends ZodTypeAny>(schema: S, body: unknown, res: Response): z.infer<S> | null {
  const result = schema.safeParse(body ?? {});
  if (result.success) return result.data as z.infer<S>;
  const paths = [...new Set(result.error.issues.map((i) => (i.path.length > 0 ? i.path.join('.') : '(body)')))];
  res.status(400).json({ success: false, error: 'Validation failed', details: { paths: paths.slice(0, 50) } });
  return null;
}

/** Answered here rather than through errorHandler: the client recognises the
 *  case by its `code` and translates it, instead of showing this sentence. */
function sentTenantMismatch(err: unknown, res: Response): boolean {
  if (!(err instanceof SetupTenantMismatchError)) return false;
  res.status(409).json({ success: false, error: err.message, code: SETUP_TENANT_MISMATCH });
  return true;
}

function mapError(err: unknown): unknown {
  if (err instanceof SetupInputError) return new AppError(err.status, err.message);
  if (err instanceof SetupBusyError) return new AppError(409, err.message);
  return err;
}

export const tenantSetupController = {
  /** POST /tenant-setup/context — what the designer is built from. Writes nothing. */
  async context(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      assertPlatformAdmin(req);
      const body = parse(tenantSetupContextSchema, req.body, res);
      if (!body) return;
      const data = await getSetupContext(req.tenantId, {
        expectedTenantId: body.expectedTenantId,
        template: body.template,
        referenceRevisionIds: body.referenceRevisionIds,
      });
      res.json({ success: true, data });
    } catch (err) {
      if (sentTenantMismatch(err, res)) return;
      next(mapError(err));
    }
  },

  /** POST /tenant-setup/check — the dry run. Never a 422: errors are issues. */
  async check(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      assertPlatformAdmin(req);
      const body = parse(tenantSetupRequestSchema, req.body, res);
      if (!body) return;
      const data = await checkSetup(req.tenantId, body as TenantSetupRequest, {
        userId: req.session.userId ?? null,
      });
      res.json({ success: true, data });
    } catch (err) {
      if (sentTenantMismatch(err, res)) return;
      next(mapError(err));
    }
  },

  /** POST /tenant-setup/apply — judged again, then written in order. A step
   *  that fails is still a 200: the report says what was written. */
  async apply(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      assertPlatformAdmin(req);
      const body = parse(tenantSetupRequestSchema, req.body, res);
      if (!body) return;
      const data = await applySetup(req.tenantId, body as TenantSetupRequest, {
        userId: req.session.userId ?? null,
        username: req.session.username ?? null,
      });
      res.json({ success: true, data });
    } catch (err) {
      if (sentTenantMismatch(err, res)) return;
      if (err instanceof SetupRefusedError) {
        res.status(422).json({ success: false, error: err.message, data: err.report });
        return;
      }
      next(mapError(err));
    }
  },
};
