import { Router, type Request } from 'express';
import rateLimit from 'express-rate-limit';
import { validateRouterOsTarget } from '@obliwan/shared';
import { createFirmwareController, type FirmwareControllerDeps } from '../controllers/firmware.controller';
import { requireAuth } from '../middleware/auth';
import { requireRole } from '../middleware/rbac';

/**
 * RouterOS releases and the fleet's target version. Meant to be mounted in
 * routes/index.ts's GLOBAL section:
 *
 *     router.use('/firmware', firmwareRoutes);   // -> /api/firmware/...
 *
 * Not under tenantRouter: the latest releases and the target are one value for
 * the whole installation, not per tenant. Guards are therefore installed HERE
 * (a global router brings its own): `requireAuth` for everything, plus
 * `requireRole('admin')` (platform admin, NOT a capability: a capability is
 * resolved per tenant and would hand an installation-wide decision to the
 * admin of any tenant) on the two writes.
 */

/** Requests to MikroTik one bucket admits per window, whoever sends them. */
export const MIKROTIK_REQUEST_LIMIT = 6;
export const MIKROTIK_REQUEST_WINDOW_MS = 10 * 60 * 1000;

/**
 * True exactly when `PUT /routeros/target` will send a HEAD to
 * download.mikrotik.com: a VALID pin (setRouterOsTarget validates before it
 * probes, so an invalid body or a non-pinned mode sends nothing).
 */
function putSendsPinProbe(body: unknown): boolean {
  const v = validateRouterOsTarget(body);
  return v.ok && v.value.mode === 'pinned';
}

/**
 * The routes. `deps` is for the harness only (it aims both writes at fakes);
 * the default export below is built without it, i.e. against MikroTik.
 */
export function createFirmwareRouter(deps: FirmwareControllerDeps = {}): Router {
  const controller = createFirmwareController(deps);

  /**
   * Both writes can make this installation call MikroTik: "Check now" GETs two
   * files from upgrade.mikrotik.com, and a pin HEADs one package on
   * download.mikrotik.com. They share ONE global bucket (constant key, not per
   * user), which bounds what the installation sends that third party, whoever
   * clicks. A PUT that sends nothing (another mode, an invalid body) is not
   * counted. Mounted after the role check, so a non-admin gets 403 and spends
   * nothing. The scheduled watcher does not go through HTTP and is bounded by
   * its own cadence (releaseWatcher.ts).
   */
  const mikrotikLimiter = rateLimit({
    windowMs: MIKROTIK_REQUEST_WINDOW_MS,
    limit: MIKROTIK_REQUEST_LIMIT,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (_req: Request) => 'routeros-mikrotik-requests',
    skip: (req: Request) => req.method === 'PUT' && !putSendsPinProbe(req.body),
    message: {
      success: false,
      error: 'Too many requests to MikroTik (release checks and version pins share one budget), please try again in a few minutes',
    },
  });

  const router = Router();
  router.use(requireAuth);
  router.get('/routeros', controller.getRouterOs);
  router.put('/routeros/target', requireRole('admin'), mikrotikLimiter, controller.putTarget);
  router.post('/routeros/check', requireRole('admin'), mikrotikLimiter, controller.check);
  return router;
}

export default createFirmwareRouter();
