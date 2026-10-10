import { Router } from 'express';
import { requireAuth } from '../middleware/auth';
import { requireRole } from '../middleware/rbac';
import { validate } from '../middleware/validate';
import { benchStationRegisterLimiter, requireBenchStationSelf } from '../middleware/benchStation';
import { benchStationsController } from '../controllers/benchStations.controller';
import { registerStationSchema } from '../services/bench/stations.service';

/**
 * Bench workstations — two routers, because two audiences.
 *
 * MOUNT BOTH, in the GLOBAL section of `routes/index.ts`, NOT under
 * `tenantRouter` — a workstation has no session (the exact defect that made
 * bench enrolment unreachable), and stations are platform-scoped:
 *
 *   router.use('/bench/stations', benchStationSelfRoutes);
 *   router.use('/bench-stations', benchStationAdminRoutes);
 *
 * Neither prefix contains `/admin/`: the edge proxy bans a caller on it. The
 * admin half is a plain resource path whose authorisation lives inside the
 * router (`requireAuth` + `requireRole('admin')`), like `/system`.
 *
 * CONTRACT FOR BOTH CLIENTS — the verification code. `register` and `/me`
 * return `verificationCode` (e.g. `4F3A-9C1B`), and every station in the admin
 * list carries the same field. The BENCH must display it while it waits for
 * approval. The APPROVAL SCREEN must show it on each row, next to the name.
 * The administrator approves only the row whose code the person at the desk
 * reads off the screen. The name, the hostname and the address are not enough:
 * anybody can register with the first two, and the third is the bridge
 * gateway for every caller. See `stationVerificationCode`.
 */

/** `/api/bench/stations/*` — the workstation's own half. */
export const benchStationSelfRoutes = Router();

benchStationSelfRoutes.post(
  '/register',
  benchStationRegisterLimiter,
  validate(registerStationSchema),
  benchStationsController.register,
);

benchStationSelfRoutes.get('/me', requireBenchStationSelf, benchStationsController.me);

/** `/api/bench-stations/*` — the platform administrator's half. */
export const benchStationAdminRoutes = Router();

// `router.use` on a router mounted at its own prefix applies to that prefix
// only, so this cannot leak onto a neighbouring mount.
benchStationAdminRoutes.use(requireAuth, requireRole('admin'));

benchStationAdminRoutes.get('/', benchStationsController.list);
benchStationAdminRoutes.post('/:id/approve', benchStationsController.approve);
benchStationAdminRoutes.post('/:id/revoke', benchStationsController.revoke);
