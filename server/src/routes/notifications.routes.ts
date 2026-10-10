import type { Request, Response, NextFunction } from 'express';
import { Router } from 'express';
import { CAPABILITIES } from '@obliwan/shared';
import { notificationsController } from '../controllers/notifications.controller';
import { requireAuth } from '../middleware/auth';
import { requireCapability, requireRole } from '../middleware/rbac';
import { AppError } from '../middleware/errorHandler';
import { validate } from '../middleware/validate';
import {
  createChannelSchema,
  updateChannelSchema,
  addBindingSchema,
  removeBindingSchema,
} from '../validators/notification.schema';

/**
 * Notification channels and their bindings. Mounted under the tenant-scoped
 * router: `req.tenantId` is resolved, and every controller call passes it on —
 * `notification.service` reads a channel only if this tenant owns it or it was
 * shared to this tenant, writes one only if this tenant OWNS it, and refuses a
 * binding on another tenant's group or device.
 *
 * ┌─ NOTIFICATIONS_MANAGE, EXCEPT TWO ACTS ──────────────────────────────────┐
 * │ The tenant ADMIN was granted `notifications.manage`                      │
 * │ by the role matrix and this router answered 403 to everybody but a       │
 * │ platform admin. The service layer above was already written for a        │
 * │ tenant-scoped caller, so the capability is now what the routes check —   │
 * │ with two acts kept for a PLATFORM admin (`requireRole('admin')` reads    │
 * │ `users.role`, never the tenant role):                                    │
 * │                                                                          │
 * │  - WRITING A CHANNEL'S `config`: `POST /channels`, and a                 │
 * │    `PUT /channels/:id` whose body carries `config`. That object IS the   │
 * │    address the server sends to — a webhook URL, a Gotify or ntfy server  │
 * │    — and the plugins fetch it as typed, with no filter on where it       │
 * │    points. Choosing an address the server dials is withheld from tenant  │
 * │    admins elsewhere too (a transport's host and port are                 │
 * │    CREDENTIAL_MANAGE, which no tenant role holds). Renaming, enabling or │
 * │    disabling a channel this tenant owns is not that, and stays open.     │
 * │  - SHARING A CHANNEL INTO OTHER TENANTS (`/channels/:id/tenants`): the   │
 * │    list names other customers' tenant ids, and writing it makes this     │
 * │    tenant's channel appear in theirs.                                    │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
const router = Router();

router.use(requireAuth);

const manage = requireCapability(CAPABILITIES.NOTIFICATIONS_MANAGE);
const platformAdmin = requireRole('admin');

/**
 * A `PUT /channels/:id` that writes `config` is a platform act (see above);
 * one that only renames, enables or disables is NOTIFICATIONS_MANAGE. Runs
 * AFTER `validate(updateChannelSchema)`, so it judges the body the controller
 * will actually receive — the same `config !== undefined` test the service
 * uses to decide whether to touch the stored config at all.
 */
function platformAdminWhenConfigWritten(req: Request, _res: Response, next: NextFunction): void {
  if (req.session.role === 'admin') { next(); return; }
  const body = req.body as { config?: unknown } | undefined;
  if (body?.config !== undefined) {
    next(new AppError(403, "Changing a channel's destination is a platform administrator action"));
    return;
  }
  next();
}

// Plugin info
router.get('/plugins', manage, notificationsController.plugins);

// Channels CRUD
router.get('/channels', manage, notificationsController.listChannels);
router.get('/channels/:id', manage, notificationsController.getChannel);
router.post('/channels', platformAdmin, validate(createChannelSchema), notificationsController.createChannel);
router.put(
  '/channels/:id',
  manage,
  validate(updateChannelSchema),
  platformAdminWhenConfigWritten,
  notificationsController.updateChannel,
);
router.delete('/channels/:id', manage, notificationsController.deleteChannel);
router.post('/channels/:id/test', manage, notificationsController.testChannel);
router.get('/channels/:id/tenants', platformAdmin, notificationsController.getChannelTenants);
router.put('/channels/:id/tenants', platformAdmin, notificationsController.setChannelTenants);

// Bindings
router.get('/bindings/resolved', manage, notificationsController.resolvedBindings);
router.get('/bindings', manage, notificationsController.listBindings);
router.post('/bindings', manage, validate(addBindingSchema), notificationsController.addBinding);
router.delete('/bindings', manage, validate(removeBindingSchema), notificationsController.removeBinding);

export default router;
