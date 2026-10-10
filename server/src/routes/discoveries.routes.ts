import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { discoveriesController } from '../controllers/discoveries.controller';
import { requireCapability } from '../middleware/rbac';
import { validate } from '../middleware/validate';
import {
  bindDiscoverySchema,
  listDiscoveriesQuerySchema,
  scanDiscoveriesSchema,
  setDiscoveryStateSchema,
} from '../validators/device.schema';
import { godViewBodyTenant, godViewParam } from '../utils/globalView';

/**
 * The PPP quarantine.
 *
 * Everything here is `DEVICE_DISCOVER`, including reading: the list is a
 * pre-tenant view of PPP usernames seen on a concentrator, and it is a
 * different, narrower audience than "can see the fleet". Binding additionally
 * writes a device, so it also demands `DEVICE_WRITE`.
 */
const router = Router();

// God view (utils/globalView.ts): a route naming ONE discoveries row by `:id`
// acts in that row's own tenant — read, write and audit alike. No-op for
// anyone but a platform admin positioned on the master tenant.
router.param('id', godViewParam('discoveries'));

router.get(
  '/',
  requireCapability(CAPABILITIES.DEVICE_DISCOVER),
  validate(listDiscoveriesQuerySchema, 'query'),
  discoveriesController.list,
);
router.post(
  '/scan',
  requireCapability(CAPABILITIES.DEVICE_DISCOVER),
  validate(scanDiscoveriesSchema),
  godViewBodyTenant('devices', 'concentratorId'),
  discoveriesController.scan,
);
router.get('/:id', requireCapability(CAPABILITIES.DEVICE_DISCOVER), discoveriesController.getById);
router.post(
  '/:id/bind',
  requireCapability(CAPABILITIES.DEVICE_DISCOVER),
  requireCapability(CAPABILITIES.DEVICE_WRITE),
  validate(bindDiscoverySchema),
  // God view, a discovery on the shared CHR bound to an EXISTING device: the
  // bind acts in that device's tenant (the bind rule still decides).
  godViewBodyTenant('devices', 'deviceId'),
  discoveriesController.bind,
);
router.post(
  '/:id/state',
  requireCapability(CAPABILITIES.DEVICE_DISCOVER),
  validate(setDiscoveryStateSchema),
  discoveriesController.setState,
);

export default router;
