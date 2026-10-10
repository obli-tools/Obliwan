/**
 * ObliWAN — the presence grace period (`presence_grace_period`).
 *
 * "How long a PPP session may stay down before the device is reported DOWN."
 * The SESSION is a fact and is recorded the instant the concentrator says so —
 * `ppp_sessions` keeps every flap, and SLA reads it. What waits is the REPORT:
 * the reachability verdict and the `wan:site:presence` event that colours the fleet. A
 * session that comes back inside the window never becomes an outage on any
 * screen; one that does not is reported when the window closes, dated from
 * the drop.
 *
 * Resolved PER DEVICE (default → workspace → group chain → device). The
 * default is 0, which is what presence did before the setting was read.
 *
 * Two places honour it and both read THIS file, so they cannot disagree:
 *   - `pppPresence.service.ts` defers the report of a drop, and its 60 s
 *     reconciliation reports any whose window closed while no timer was
 *     running (a restart, a leadership change) — a timer is a convenience,
 *     the sweep is the guarantee;
 *   - `reachability.service.ts` `assessDevice()`, reached by the API and the
 *     re-assessment sweeps, counts a session that dropped inside the window
 *     as still up — otherwise any re-assessment would report the very outage
 *     the window exists to hold back.
 */

import { SETTINGS_KEYS, getSettingDefinition } from '@obliwan/shared';
import { db } from '../../db';
import { deviceSettingNumbers } from '../settingsRead';

/** The longest window any device can have: the definition's ceiling. Bounds
 *  the "recent drop" lookup so it never scans a device's whole history. */
export const PRESENCE_GRACE_MAX_SEC = getSettingDefinition(SETTINGS_KEYS.PRESENCE_GRACE_PERIOD)?.max ?? 3600;

/** The device's window, in seconds. 0 = report at once. */
export async function presenceGraceSec(
  tenantId: number,
  deviceId: number,
  groupId: number | null,
): Promise<number> {
  const s = await deviceSettingNumbers(tenantId, deviceId, groupId, [SETTINGS_KEYS.PRESENCE_GRACE_PERIOD]);
  return s[SETTINGS_KEYS.PRESENCE_GRACE_PERIOD].value;
}

/** Pure: is a drop at `endedAt` still inside a window of `graceSec` at `now`? */
export function withinGrace(endedAt: Date, graceSec: number, now: Date = new Date()): boolean {
  if (!(graceSec > 0)) return false;
  return now.getTime() - endedAt.getTime() < graceSec * 1000;
}

/**
 * For a device with NO open session: did its last session end recently enough
 * that the drop is still inside the device's window? The settings tree is only
 * resolved when there is such a recent drop — the common answer ("no") costs
 * one indexed query.
 */
export async function droppedWithinGrace(device: {
  id: number;
  tenant_id: number;
  group_id: number | null;
  concentrator_id: number | null;
  ppp_username: string | null;
}): Promise<boolean> {
  if (!device.concentrator_id || !device.ppp_username) return false;
  const last = await db('ppp_sessions')
    .where({ concentrator_id: device.concentrator_id, ppp_username: device.ppp_username })
    .whereNotNull('ended_at')
    .where('ended_at', '>', new Date(Date.now() - PRESENCE_GRACE_MAX_SEC * 1000))
    .orderBy('ended_at', 'desc')
    .first<{ ended_at: Date } | undefined>('ended_at');
  if (!last) return false;
  const grace = await presenceGraceSec(device.tenant_id, device.id, device.group_id);
  return withinGrace(new Date(last.ended_at), grace);
}
