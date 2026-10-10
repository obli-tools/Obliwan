import { Router, type NextFunction, type Request, type Response } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { requireCapability } from '../middleware/rbac';
import { AppError } from '../middleware/errorHandler';
import { godViewMeta, godViewParam, hasGlobalView } from '../utils/globalView';
import { deviceListScope } from '../services/teamScope.service';
import { lineQualityDeviceView, lineQualityFleet } from '../services/fleet/lineQuality.service';

/**
 * Line quality of the stores' fixed lines (fleet/lineQuality.service.ts,
 * migration 097) — mounted under the tenant-scoped router as `/line-quality`
 * (routes/index.ts), with the device team gate on `/devices/:deviceId`.
 *
 * DEVICE_READ: a read of what the nightly measurement filed. Nothing here
 * dials a router.
 *   GET /                      « Lignes dégradées » (degraded and to-watch
 *                              lines, worst first; `?all=1` adds the others).
 *                              God view aware: Default lists every tenant.
 *   GET /devices/:deviceId     the device page's « Qualité de ligne » card.
 */
const router = Router();

// God view: a route naming ONE device acts in that device's own tenant.
router.param('deviceId', godViewParam('devices'));

router.get('/', requireCapability(CAPABILITIES.DEVICE_READ), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const items = await lineQualityFleet(req.tenantId, {
      // Team scope (087): the routers the caller's teams cover.
      deviceIdsIn: await deviceListScope(req),
      includeOk: req.query.all === '1' || req.query.all === 'true',
    });
    res.json({ success: true, data: items, ...godViewMeta(hasGlobalView(req)) });
  } catch (err) {
    next(err);
  }
});

router.get('/devices/:deviceId', requireCapability(CAPABILITIES.DEVICE_READ), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const deviceId = Number(req.params.deviceId);
    if (!Number.isInteger(deviceId) || deviceId <= 0) throw new AppError(400, 'Invalid device id');
    const view = await lineQualityDeviceView(req.tenantId, deviceId);
    if (!view) throw new AppError(404, 'Device not found');
    res.json({ success: true, data: view });
  } catch (err) {
    next(err);
  }
});

export default router;
