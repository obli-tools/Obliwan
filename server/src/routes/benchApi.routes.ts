import { Router, type Request } from 'express';
import rateLimit from 'express-rate-limit';
import { requireApprovedBenchStation } from '../middleware/benchStation';
import { benchApiController } from '../controllers/benchApi.controller';

/**
 * The bench HTTP contract — `/api/bench/v1`. See
 * controllers/benchApi.controller.ts and services/bench/{planning,compile}.
 *
 * Mounted in the GLOBAL section of routes/index.ts, outside `tenantRouter`: a
 * workstation has no session, and `requireAuth` would answer 401 to every
 * call. Not anonymous for that: `requireApprovedBenchStation` runs first on
 * every route and demands the `Bench <token>` of a workstation a platform
 * administrator approved — the same guard as `POST /api/devices/enroll`.
 */
const router = Router();

router.use(requireApprovedBenchStation);

/** A compile renders a template in a worker, commits an allocation and may
 *  queue a concentrator job: a bench prepares a few boxes an hour, not
 *  hundreds. Keyed on the station (the guard has run). */
const compileLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 120,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  keyGenerator: (req: Request) =>
    req.benchStation ? `bench-compile:${req.benchStation.id}` : `bench-compile-ip:${req.ip ?? 'unknown'}`,
  message: {
    success: false,
    error: 'Trop de compilations depuis ce poste en une heure. Attendez un peu avant de relancer.',
  },
});

router.get('/tenants', benchApiController.tenants);
router.get('/tenants/:tenantId/sites', benchApiController.sites);
router.post('/plan', benchApiController.plan);
router.post('/compile', compileLimiter, benchApiController.compile);
router.post('/devices/:deviceId/result', benchApiController.result);

export { router as benchApiRoutes };
export default router;
