import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { devicesController } from '../controllers/devices.controller';
import { requireCapability } from '../middleware/rbac';
import { validate } from '../middleware/validate';
import {
  createConcentratorSchema,
  enrollDeviceSchema,
  createDeviceSchema,
  listDevicesQuerySchema,
  updateDeviceSchema,
  upsertTransportSchema,
} from '../validators/device.schema';
import { godViewParam } from '../utils/globalView';

/**
 * Devices, transports and presence.
 *
 * RBAC, by gesture rather than by URL shape:
 *   DEVICE_READ        see the inventory, presence and verdicts
 *   DEVICE_WRITE       create / edit / delete a device, declare the CHR,
 *                      test a channel, run a health check now,
 *                      re-assert an identity
 *   CREDENTIAL_MANAGE  write or delete a transport row, because a transport row
 *                      carries a credential. Rotating a password is an operator
 *                      act; READING one is `SECRET_READ`, and that route is not
 *                      in this file: `POST /devices/:id/transports/:transport/reveal`
 *                      lives in secretReveal.routes.ts, mounted before this
 *                      router, audited, rate-limited and `no-store`. No route
 *                      here returns a secret (section 8.2).
 */
const router = Router();

// God view (utils/globalView.ts): a route naming ONE devices row by `:id`
// acts in that row's own tenant — read, write and audit alike. No-op for
// anyone but a platform admin positioned on the master tenant.
router.param('id', godViewParam('devices'));

router.get(
  '/',
  requireCapability(CAPABILITIES.DEVICE_READ),
  validate(listDevicesQuerySchema, 'query'),
  devicesController.list,
);
router.get(
  '/presence/status',
  requireCapability(CAPABILITIES.DEVICE_READ),
  devicesController.presenceStatus,
);
/** "Sites on 4G backup" (dashboard). A read of what the health check filed. */
router.get('/backup-4g', requireCapability(CAPABILITIES.DEVICE_READ), devicesController.backup4g);

// Declared before `/:id` so the literal path is not swallowed by the parameter.
router.post(
  // Single-device enrolment FROM THE UI. Unlike '/enroll' above, a
  // credential IS transmitted and goes to the vault, so this one demands
  // CREDENTIAL_MANAGE. That capability is the entire difference between the
  // two paths, which is why they are two routes and not one with a flag.
  '/enroll-probe',
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  requireCapability(CAPABILITIES.CREDENTIAL_MANAGE),
  validate(enrollDeviceSchema),
  devicesController.enrollFromUi,
);

// Bench enrolment, `POST /devices/enroll`, is NOT declared here. It is
// mounted in `routes/index.ts`, OUTSIDE `tenantRouter`, behind
// `requireApprovedBenchStation`. Declared here it sat behind this router's
// mount, whose `requireAuth` answered 401 to every bench call before any bench
// middleware ran — a workstation has no session cookie — so it never worked.
// A route declared here again would be shadowed by that mount on POST, and
// would put a second, tenant-scoped door on the same path.

router.post(
  '/concentrator',
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  requireCapability(CAPABILITIES.CREDENTIAL_MANAGE),
  validate(createConcentratorSchema),
  devicesController.createConcentrator,
);

router.get('/:id', requireCapability(CAPABILITIES.DEVICE_READ), devicesController.getById);
router.get('/:id/sessions', requireCapability(CAPABILITIES.DEVICE_READ), devicesController.sessions);
/** Which uplink carries the traffic. A read: it consults samples, never the
 *  equipment. */
router.get('/:id/uplink', requireCapability(CAPABILITIES.DEVICE_READ), devicesController.uplink);
router.get(
  '/:id/reachability',
  requireCapability(CAPABILITIES.DEVICE_READ),
  devicesController.reachability,
);
router.get(
  '/:id/transports',
  requireCapability(CAPABILITIES.DEVICE_READ),
  devicesController.listTransports,
);

router.post(
  '/',
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  validate(createDeviceSchema),
  devicesController.create,
);
router.patch(
  '/:id',
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  validate(updateDeviceSchema),
  devicesController.update,
);
/** Approve a quarantined device. DEVICE_WRITE: it is the act that lets plans
 *  and collections reach this box, which is a fleet decision, not a read. */
router.post(
  '/:id/approve',
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  devicesController.approve,
);

router.delete('/:id', requireCapability(CAPABILITIES.DEVICE_WRITE), devicesController.delete);

router.put(
  '/:id/transports/:transport',
  requireCapability(CAPABILITIES.CREDENTIAL_MANAGE),
  validate(upsertTransportSchema),
  devicesController.upsertTransport,
);
router.delete(
  '/:id/transports/:transport',
  requireCapability(CAPABILITIES.CREDENTIAL_MANAGE),
  devicesController.deleteTransport,
);
router.post(
  '/:id/transports/:transport/test',
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  devicesController.testTransport,
);
/** Device-level variant: every enabled channel at once. Same capability —
 *  opening a channel is an operator act whichever way it is asked for. */
router.post(
  '/:id/test-connection',
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  devicesController.testConnection,
);

/** Run the permanent health check now. Same capability as the test above: it
 *  opens a channel to the equipment, through the device's own rows. */
router.post(
  '/:id/health-check',
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  devicesController.checkHealth,
);

/** The follow-up question to a failed test: why. Same capability — it opens
 *  sockets to a customer's equipment, and the target comes from the device's
 *  own rows, never from the caller. */
router.post(
  '/:id/diagnose',
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  devicesController.diagnose,
);

/** Fresh-connection identity proof. Available now so the door is
 *  exercised before writes are put behind it. */
router.post(
  '/:id/assert-binding',
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  devicesController.assertBinding,
);

/** Force the 60 s sweep now, on a concentrator. */
router.post(
  '/:id/reconcile',
  requireCapability(CAPABILITIES.DEVICE_DISCOVER),
  devicesController.reconcile,
);

export default router;
