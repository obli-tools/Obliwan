import { Router } from 'express';
import { requireAuth } from '../middleware/auth';
import { attachTenantIfGranted, requireTenant } from '../middleware/tenant';
import * as ctrl from '../controllers/liveAlert.controller';

export const liveAlertRouter = Router();

// All tenants accessible by this user (no requireTenant — cross-tenant)
// `attachTenantIfGranted`: the god view (a platform admin positioned on the
// master tenant) covers EVERY tenant's alerts; anyone else keeps the session's
// own tenant set, and a caller with no tenant still gets an empty answer.
liveAlertRouter.get('/all', requireAuth, attachTenantIfGranted, ctrl.getAllTenantAlerts);

// Current-tenant endpoints
liveAlertRouter.get('/', requireAuth, requireTenant, ctrl.getAlerts);
liveAlertRouter.post('/read-all', requireAuth, requireTenant, ctrl.markAllRead);
liveAlertRouter.delete('/', requireAuth, requireTenant, ctrl.clearAll);

// Cross-tenant by alert id (ownership verified inside controller)
liveAlertRouter.patch('/:id/read', requireAuth, attachTenantIfGranted, ctrl.markRead);
liveAlertRouter.delete('/:id', requireAuth, attachTenantIfGranted, ctrl.deleteAlert);
