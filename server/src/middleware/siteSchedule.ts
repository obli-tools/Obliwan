import type { Request, Response, NextFunction } from 'express';
import { SITE_SCHEDULE_CAPABILITY, SITE_SCHEDULE_FIELDS } from '@obliwan/shared';
import type { SiteScheduleField } from '@obliwan/shared';
import { db } from '../db';
import { AppError } from './errorHandler';
import { permissionService } from '../services/permission.service';

/**
 * A site's PUSH SCHEDULE — its maintenance window and the timezone that window
 * is evaluated in — is not customer data, though it sits on the customer
 * record. `change/jobQueue.service.ts` reads a NULL window as OPEN and judges
 * every window in the site's timezone, so blanking the window or moving the
 * timezone releases queued pushes for that site's routers into trading hours.
 *
 * SITE_WRITE (shared/src/capabilities.ts) edits the customer record and was
 * carved out of DEVICE_WRITE for a role that writes nothing to a device: the
 * account manager. Changing the schedule of an EXISTING site therefore still
 * takes `SITE_SCHEDULE_CAPABILITY` (DEVICE_WRITE). This middleware is that
 * rule for the site update route; the CSV import has to apply the same rule
 * to the timezone column of a site that already exists.
 *
 * It refuses only a CHANGE. A form that sends the whole record back, schedule
 * included and untouched, passes: comparing against the stored row is what
 * lets an account manager rename a store without being refused over a field
 * she did not touch. Place it AFTER `validate(updateSiteSchema)`, so the body
 * it compares is the parsed one.
 *
 * Fails closed on an unauthenticated or tenant-less caller, and stays out of
 * the controller's way otherwise: an unknown or foreign site id is passed
 * through for the tenant-scoped controller to answer 404, exactly as it would
 * without this middleware.
 */

/** Key-sorted JSON: a window whose keys arrive in another order is the same window. */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const o = value as Record<string, unknown>;
    return `{${Object.keys(o)
      .filter((k) => o[k] !== undefined)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value ?? null);
}

export interface StoredSiteSchedule {
  timezone: string | null;
  /** jsonb as pg returns it (parsed), or its text if a driver hands back a string. */
  maintenance_window: unknown;
}

/**
 * Which schedule fields `body` would CHANGE on a site stored as `stored`. A
 * field absent from the body (or `undefined`) changes nothing; `null` for the
 * window is a change unless the site has no window either.
 */
export function siteScheduleChanges(
  stored: StoredSiteSchedule,
  body: Readonly<Record<string, unknown>>,
): SiteScheduleField[] {
  const changed: SiteScheduleField[] = [];
  if (body.timezone !== undefined && body.timezone !== stored.timezone) changed.push('timezone');
  if (body.maintenanceWindow !== undefined) {
    let current: unknown = stored.maintenance_window ?? null;
    if (typeof current === 'string') {
      try {
        current = JSON.parse(current) as unknown;
      } catch {
        // Unparseable stored text: compared as the raw string, so any body
        // value differs from it and the change is refused, never waved through.
      }
    }
    if (canonical(body.maintenanceWindow) !== canonical(current)) changed.push('maintenanceWindow');
  }
  return changed;
}

/**
 * Refuse a change to an existing site's maintenance window or timezone unless
 * the caller holds `SITE_SCHEDULE_CAPABILITY` in this tenant (platform admins
 * always do). `idParam` names the route parameter carrying the site id.
 */
export function refuseSiteScheduleChange(idParam = 'id') {
  return async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
    try {
      const body =
        req.body !== null && typeof req.body === 'object' && !Array.isArray(req.body)
          ? (req.body as Record<string, unknown>)
          : {};
      if (!SITE_SCHEDULE_FIELDS.some((f) => body[f] !== undefined)) {
        next();
        return;
      }
      if (!req.session?.userId) {
        next(new AppError(401, 'Authentication required'));
        return;
      }
      if (req.session.role === 'admin') {
        next();
        return;
      }
      if (!req.tenantId) {
        next(new AppError(403, 'No tenant granted for this account'));
        return;
      }
      const caps = await permissionService.getUserCapabilities(req.session.userId, false, req.tenantId);
      if (caps.includes(SITE_SCHEDULE_CAPABILITY)) {
        next();
        return;
      }

      const id = Number(req.params[idParam]);
      if (!Number.isInteger(id) || id <= 0) {
        next();
        return;
      }
      const site = await db('sites')
        .where({ id, tenant_id: req.tenantId })
        .first<StoredSiteSchedule | undefined>('timezone', 'maintenance_window');
      if (!site) {
        next();
        return;
      }

      const changed = siteScheduleChanges(site, body);
      if (changed.length === 0) {
        next();
        return;
      }
      next(
        new AppError(
          403,
          `Changing a site's ${changed.join(' and ')} needs the ${SITE_SCHEDULE_CAPABILITY} capability: ` +
            'the maintenance window decides when pushes may reach this site\'s routers.',
        ),
      );
    } catch (err) {
      next(err);
    }
  };
}
