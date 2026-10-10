/**
 * ObliWAN — the seam between the per-store 4G backup alert
 * (backup4g.service.ts) and the grouped operator outage
 * (operatorOutage.service.ts, migration 095).
 *
 * A store that is an ACTIVE member of an OPEN group gets its 4G backup alert
 * FOLDED under the group: the live alert is created (a child of the group,
 * `outage_role = 'member'`) and the stamp is written exactly as before, but no
 * channel message is sent — the group's one alert already said it. The member
 * row records the stamp (`folded_alert_at`), so the store's RECOVERY is folded
 * the same way; unless the group closed first with the store still out
 * (`released_at`): its alert was then sent at release, and its recovery is
 * sent as usual — one incident, opened and closed on the same channels.
 *
 * Database only, on purpose: backup4g.service imports this file, and the
 * outage service imports backup4g.service — this file breaks the cycle.
 */

import { db } from '../../db';

export interface OutageMembership {
  outageId: number;
  memberId: number;
}

/** The open group this device is an active member of, or null. */
export async function activeOutageMembership(deviceId: number): Promise<OutageMembership | null> {
  const row = (await db('operator_outage_members as m')
    .join('operator_outages as o', 'o.id', 'm.outage_id')
    .where('m.device_id', deviceId)
    .where('o.status', 'open')
    .whereNull('m.recovered_at')
    .whereNull('m.released_at')
    .orderBy('m.id', 'desc')
    .first('m.id', 'm.outage_id')) as { id: string | number; outage_id: string | number } | undefined;
  return row ? { outageId: Number(row.outage_id), memberId: Number(row.id) } : null;
}

/** Record that the member's per-store alert, stamped `alertedAt`, was folded. */
export async function markAlertFolded(memberId: number, alertedAt: Date): Promise<void> {
  await db('operator_outage_members').where({ id: memberId }).update({ folded_alert_at: alertedAt });
}

/**
 * The group a per-store alert stamped `alertedAt` was folded under, when its
 * recovery must be folded too (not released since), or null.
 */
export async function foldedAlertOutage(deviceId: number, alertedAt: Date): Promise<number | null> {
  const row = (await db('operator_outage_members')
    .where({ device_id: deviceId, folded_alert_at: alertedAt })
    .whereNull('released_at')
    .orderBy('id', 'desc')
    .first('outage_id')) as { outage_id: string | number } | undefined;
  return row ? Number(row.outage_id) : null;
}

/** The open group each device is an active member of (one query). */
export async function activeOutagesOf(deviceIds: readonly number[]): Promise<Map<number, number>> {
  const out = new Map<number, number>();
  if (deviceIds.length === 0) return out;
  const rows = (await db('operator_outage_members as m')
    .join('operator_outages as o', 'o.id', 'm.outage_id')
    .whereIn('m.device_id', deviceIds as number[])
    .where('o.status', 'open')
    .whereNull('m.recovered_at')
    .whereNull('m.released_at')
    .select('m.device_id', 'm.outage_id')) as Array<{ device_id: number; outage_id: string | number }>;
  for (const r of rows) out.set(Number(r.device_id), Number(r.outage_id));
  return out;
}
