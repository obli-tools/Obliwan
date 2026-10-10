import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { tlsRepinController } from '../controllers/tlsRepin.controller';
import { requireCapability } from '../middleware/rbac';
import { validate } from '../middleware/validate';
import { tlsRepinSchema } from '../validators/tlsRepin.schema';
import { godViewParam } from '../utils/globalView';

/**
 * Re-pinning a RouterOS API certificate to the one the device presented
 * (services/fleet/tlsRepin.service.ts). Mounted under the tenant-scoped
 * router on `/devices`, BEFORE devicesRoutes. CREDENTIAL_MANAGE, the
 * capability of every transport write — the pin is part of the channel's
 * trust, like its password; a concentrator additionally needs a platform
 * administrator, decided in the service. The transport segment is a literal:
 * only the RouterOS API channel is pinned by the pool.
 */
const router = Router();

// God view (utils/globalView.ts): a route naming ONE devices row by `:id`
// acts in that row's own tenant — read, write and audit alike. No-op for
// anyone but a platform admin positioned on the master tenant.
router.param('id', godViewParam('devices'));

router.post(
  '/:id/transports/routeros_api/repin',
  requireCapability(CAPABILITIES.CREDENTIAL_MANAGE),
  validate(tlsRepinSchema),
  tlsRepinController.repin,
);

export default router;
