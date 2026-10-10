import { Router, type NextFunction, type Request, type Response } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { requireCapability } from '../middleware/rbac';
import { fleetAnomalies } from '../services/fleet/fleetAnomalies.service';
import { hasGlobalView } from '../utils/globalView';
import { deviceListScope } from '../services/teamScope.service';

/**
 * Fleet anomalies ("Anomalies du parc") — mounted under the tenant-scoped
 * router as `/fleet-anomalies` (routes/index.ts).
 *
 * DEVICE_READ: a read of what ObliWAN already stores about the fleet, the same
 * facts the device pages show to anyone who may see the fleet. The scope comes
 * from `requireTenant` — `masterView` (a platform admin on the master tenant)
 * reads every tenant, everyone else the session's tenant — and is never
 * recomputed here (see fleetAnomalies.service.ts, SCOPE).
 */
const router = Router();

router.get('/', requireCapability(CAPABILITIES.DEVICE_READ), async (req: Request, res: Response, next: NextFunction) => {
  try {
    const data = await fleetAnomalies({
      tenantId: req.tenantId,
      masterView: hasGlobalView(req),
      // Team scope (087): the routers the caller's teams cover, and their sessions.
      deviceIdsIn: await deviceListScope(req),
    });
    res.json({ success: true, data });
  } catch (err) {
    next(err);
  }
});

export default router;
