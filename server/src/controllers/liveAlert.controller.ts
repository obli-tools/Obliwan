import type { Request, Response, NextFunction } from 'express';
import { liveAlertService } from '../services/liveAlert.service';
import { tenantService } from '../services/tenant.service';
import { db } from '../db';
import { hasGlobalView } from '../utils/globalView';
import type { AlertViewer } from '../services/teamScope.service';

/**
 * Who reads the feed. Team scope (087): the alerts that name a device, a site
 * or a SIM line are visible to the teams that cover it; an alert naming none
 * stays visible to every member of the workspace. A platform admin sees all.
 */
function viewerOf(req: Request): AlertViewer {
  return { userId: req.session.userId!, isPlatformAdmin: req.session.role === 'admin' };
}

/**
 * The tenants the cross-tenant surfaces below cover: the user's memberships,
 * or — for a platform admin with none — the master tenant its session was put
 * on. ONE set, `tenantService.resolveSessionTenantIds()`, shared with the
 * Socket.io notification rooms. Keyed on `user_tenants` alone, the platform
 * admin of a fresh SSO install (no membership, working on tenant 1) read an
 * empty global feed and could neither mark read nor delete an alert of the
 * very tenant it was on. A non-admin with no membership still gets an empty
 * set, i.e. nothing.
 */
async function notificationTenantIds(req: Request): Promise<number[]> {
  // The god view (a platform admin positioned on the master tenant, the
  // verdict `attachTenantIfGranted` carried onto the request) covers EVERY
  // tenant — the same set its socket joins (`socketRooms.godViewNotifications`).
  if (hasGlobalView(req)) {
    return (await db('tenants').orderBy('id').pluck('id')).map(Number);
  }
  return tenantService.resolveSessionTenantIds(req.session.userId!);
}

/** GET /api/live-alerts — current tenant */
export async function getAlerts(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const alerts = await liveAlertService.getForTenant(req.tenantId, viewerOf(req), 100);
    res.json(alerts);
  } catch (err) { next(err); }
}

/**
 * GET /api/live-alerts/all — all tenants accessible by this user.
 * Returns { alerts, tenants } where alerts are enriched with tenantName.
 */
export async function getAllTenantAlerts(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const tenantIds = await notificationTenantIds(req);
    const tenants = await db('tenants')
      .whereIn('id', tenantIds)
      .orderBy('id')
      .select('id', 'name') as { id: number; name: string }[];

    const alerts = await liveAlertService.getForTenants(tenantIds, viewerOf(req), 200, { godView: hasGlobalView(req) });
    res.json({ alerts, tenants, ...(hasGlobalView(req) ? { godView: true } : {}) });
  } catch (err) { next(err); }
}

/** PATCH /api/live-alerts/:id/read — mark one alert as read (cross-tenant) */
export async function markRead(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const id = parseInt(req.params.id, 10);
    // Verify the alert belongs to a tenant the user can access
    const userTenantIds = await notificationTenantIds(req);

    const alert = await liveAlertService.findVisible(id, userTenantIds, viewerOf(req));
    if (!alert) { res.status(404).json({ error: 'Alert not found' }); return; }

    await liveAlertService.markRead(id, alert.tenant_id);
    res.json({ ok: true });
  } catch (err) { next(err); }
}

/**
 * POST /api/live-alerts/read-all — mark all as read for current tenant. In the
 * god view it fans out to every tenant, one per-tenant write each: the bell
 * the god view reads shows every tenant's alerts, and "mark all read" means
 * what it shows.
 */
export async function markAllRead(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    for (const tid of hasGlobalView(req) ? await notificationTenantIds(req) : [req.tenantId]) {
      await liveAlertService.markAllRead(tid, viewerOf(req));
    }
    res.json({ ok: true });
  } catch (err) { next(err); }
}

/** DELETE /api/live-alerts/:id — delete one alert (cross-tenant) */
export async function deleteAlert(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const id = parseInt(req.params.id, 10);
    const userTenantIds = await notificationTenantIds(req);

    const alert = await liveAlertService.findVisible(id, userTenantIds, viewerOf(req));
    if (!alert) { res.status(404).json({ error: 'Alert not found' }); return; }

    await liveAlertService.deleteAlert(id);
    res.json({ ok: true });
  } catch (err) { next(err); }
}

/** DELETE /api/live-alerts — clear all for current tenant (god view: every tenant, per tenant). */
export async function clearAll(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    for (const tid of hasGlobalView(req) ? await notificationTenantIds(req) : [req.tenantId]) {
      await liveAlertService.clearAll(tid, viewerOf(req));
    }
    res.json({ ok: true });
  } catch (err) { next(err); }
}
