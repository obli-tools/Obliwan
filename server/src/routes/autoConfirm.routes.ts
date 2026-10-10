import { Router, type NextFunction, type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import { CAPABILITIES } from '@obliwan/shared';
import { requireCapability } from '../middleware/rbac';
import { AppError } from '../middleware/errorHandler';
import { permissionService } from '../services/permission.service';
import {
  AUTO_CONFIRM_ENV,
  autoConfirmEnabled,
  checkDevice,
  conformityView,
  withoutConfigDetail,
  type ConformityView,
} from '../services/fleet/autoConfirm.service';
import { godViewParam } from '../utils/globalView';

/**
 * The automatic conformity check of a bench-prepared device
 * (`services/fleet/autoConfirm.service.ts`), as the device page reads it.
 *
 * Mounted under `/devices` (tenant router). Two gestures:
 *   GET  /devices/:id/auto-confirm          DEVICE_READ — the panel; the
 *        configuration detail (semantic keys, field values, what was not
 *        compared, the snapshot) only with CONFIG_READ as well, which exists
 *        precisely so configuration can be withheld from a device reader.
 *   POST /devices/:id/auto-confirm/recheck  DEVICE_WRITE AND CONFIG_WRITE —
 *        "Re-check now". It makes the platform DIAL a customer's router and
 *        collect its configuration (CONFIG_WRITE's reason for existing, as
 *        for "Collect now"), and it may confirm the device, a fleet decision
 *        (DEVICE_WRITE). Neither implies the other, so both are required.
 *
 * The re-check runs in the request, like "Test connection" and "Collect now":
 * it never takes an address or a revision from the request — both come from
 * the device's own rows. A device that is not `pending`, or that no bench
 * compiled, is refused with a 409 naming why; so is every re-check while the
 * installation has the feature switched off. One whose PPP session is down is
 * answered with the view and the reason (`not_contacted`) and is never
 * dialled. Rate-limited per user and device: each call dials the box and
 * renders the template several times.
 */
const router = Router();

// God view (utils/globalView.ts): a route naming ONE devices row by `:id`
// acts in that row's own tenant — read, write and audit alike. No-op for
// anyone but a platform admin positioned on the master tenant.
router.param('id', godViewParam('devices'));

function parseId(raw: string): number {
  const id = Number.parseInt(raw, 10);
  if (!Number.isInteger(id) || id <= 0 || id > 2_147_483_647) throw new AppError(400, 'Invalid id');
  return id;
}

/** CONFIG_READ for the caller in this tenant — the same resolution
 *  `requireCapability` applies (a platform admin holds every capability). */
async function mayReadConfig(req: Request): Promise<boolean> {
  if (req.session?.role === 'admin') return true;
  const userId = req.session?.userId;
  const tenantId = req.tenantId ?? req.session?.currentTenantId;
  if (!userId || !tenantId) return false;
  const caps = await permissionService.getUserCapabilities(userId, false, tenantId);
  return caps.includes(CAPABILITIES.CONFIG_READ);
}

async function shaped(req: Request, view: ConformityView): Promise<ConformityView> {
  return (await mayReadConfig(req)) ? view : withoutConfigDetail(view);
}

const recheckLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 6,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request) => `auto-confirm:u:${req.session?.userId ?? 'anonymous'}:d:${String(req.params.id ?? '')}`,
  message: { success: false, error: 'Too many re-checks of this device, please wait a minute' },
});

router.get(
  '/:id/auto-confirm',
  requireCapability(CAPABILITIES.DEVICE_READ),
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const view = await conformityView(req.tenantId, parseId(req.params.id));
      if (!view) throw new AppError(404, 'Device not found');
      res.json({ success: true, data: await shaped(req, view) });
    } catch (err) {
      next(err);
    }
  },
);

router.post(
  '/:id/auto-confirm/recheck',
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  requireCapability(CAPABILITIES.CONFIG_WRITE),
  recheckLimiter,
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const id = parseId(req.params.id);
      const before = await conformityView(req.tenantId, id);
      if (!before) throw new AppError(404, 'Device not found');
      if (!autoConfirmEnabled()) {
        throw new AppError(409, `The automatic conformity check is switched off on this installation (${AUTO_CONFIRM_ENV}=false): a human confirms this device.`);
      }
      if (!before.applicable) {
        throw new AppError(
          409,
          before.notApplicableReason === 'bench_failed'
            ? 'The bench reported this preparation as failed: the automatic check does not apply, a human confirms this device.'
            : 'This device was not prepared at the bench: the automatic check does not apply to it.',
        );
      }
      if (before.deviceStatus !== 'pending') {
        throw new AppError(409, `This device is '${before.deviceStatus}', not pending: there is nothing to confirm.`);
      }
      const result = await checkDevice(req.tenantId, id, 'manual');
      res.json({
        success: true,
        data: {
          ran: result.ran,
          outcome: result.outcome,
          message: result.message,
          view: await shaped(req, result.view ?? before),
        },
      });
    } catch (err) {
      next(err);
    }
  },
);

export default router;
