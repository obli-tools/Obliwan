/**
 * ObliWAN — the planned cut of a `wan_link` job, as the alerting reads it
 * (migration 090, services/change/wanLink.service.ts).
 *
 * While a job switches a store's WAN1 link, the fixed line is cut ON PURPOSE
 * and the store rides its 4G; the management tunnel fails over twice. A down
 * alert or a "running on its 4G backup" alert during that window is not an
 * incident, it is the job doing what the operator asked. The job opens the
 * window just before the script starts (`cut_expected_from` / `_until` on
 * `wan_link_jobs`) and closes it as soon as it concludes, whatever the
 * outcome. Two readers hold their alert until the window's end, and only
 * until then:
 *   - the health check (healthCheck.service.ts): a device back inside the
 *     window never alerts; one still down after it alerts with its TRUE
 *     down_since (the window moves the alert's due time, never the outage);
 *   - the backup-4G watch (backup4g.service.ts): `expected_cut` hold.
 *
 * Kept apart from wanLink.service.ts on purpose: the health check imports
 * this, and must not pull the SSH machinery in with it. Never throws: a
 * window that cannot be read holds nothing.
 */

import { db } from '../../db';
import { logger } from '../../utils/logger';

/** The end of the planned cut covering `now` for this device, or null. */
export async function expectedCutUntil(deviceId: number, now: Date = new Date()): Promise<Date | null> {
  try {
    const row = (await db('wan_link_jobs')
      .where({ device_id: deviceId })
      .whereNotNull('cut_expected_until')
      .where('cut_expected_from', '<=', now)
      .where('cut_expected_until', '>', now)
      .max({ until: 'cut_expected_until' })
      .first()) as { until: Date | string | null } | undefined;
    if (!row || row.until === null || row.until === undefined) return null;
    const d = new Date(row.until);
    return Number.isNaN(d.getTime()) ? null : d;
  } catch (err) {
    logger.warn({ err, deviceId }, 'wan_link: the planned-cut window could not be read; no alert is held');
    return null;
  }
}

/** When a down alert becomes due: its own delay after the outage began, and
 *  never before the planned cut ends. */
export function downAlertDueAt(downSince: Date, alertDelaySec: number, cutUntil: Date | null): number {
  const own = downSince.getTime() + alertDelaySec * 1000;
  return cutUntil ? Math.max(own, cutUntil.getTime()) : own;
}
