/**
 * ObliWAN — which router a mobile line is in, from the SIM card itself.
 *
 * The bench reads the ICCID of the card in a box's modem just before its reset
 * (`bench/routerosApply.ts`, `readSimCard`) and reports it with its result;
 * `recordBenchResult` stores it on the device (`devices.sim_iccid`, migration
 * 063) and calls `linkLineByDeviceIccid` here. In the other direction, a line
 * whose ICCID is filled in after the box left the bench — an operator types
 * it (`updateLine`), or the sweep reads it off Phenix's listing (its `simsn`,
 * when it is a full ICCID: observed 2026-10-06, `sync.service.upsertLine`) —
 * is linked by `linkDeviceByLineIccid`.
 *
 * ┌─ THE ICCID, AND NOTHING ELSE ────────────────────────────────────────────┐
 * │ A line is linked to a router only when the line's `iccid` is EXACTLY the │
 * │ one read in that router's modem. Never on the site, the MSISDN, the order │
 * │ the boxes were prepared in or a single unlinked line left on a site:      │
 * │ "this low-data alert is store 412's" is believed, and a wrong link is     │
 * │ worse than none. In the line direction, the ICCID must name ONE router of │
 * │ the line's tenant — two routers that read the same card (it moved from    │
 * │ one box to another) is not an answer.                                     │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHAT IS NEVER OVERWRITTEN, AND WHAT IS NEVER CROSSED ───────────────────┐
 * │ - A line already linked to ANOTHER router keeps its link: the outcome is  │
 * │   `linked_elsewhere`, logged and audited, for a human to settle. Moving   │
 * │   it would silently take the line away from the router somebody linked.  │
 * │ - A line of another tenant, or still in the pool, is NOT linked and the   │
 * │   outcome is `no_line`, exactly as if no line carried the card: a tenant  │
 * │   is never told that another customer's inventory holds that ICCID.       │
 * │   Assigning a pool line to a customer is a platform act (`updateLine`);   │
 * │   once assigned, the line direction links it.                              │
 * │ - The line's site is filled from the router's only when the line has     │
 * │   none; a different site already set is kept and reported (`siteDiffers`).│
 * │ - The tenant is never written: a link is an attribution inside one       │
 * │   tenant, and moving a line between tenants settles its open top-ups      │
 * │   (`settleOpenWorkOnMove`), which is not this file's decision.            │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Nothing here spends, proposes or approves anything: a link changes which
 * router and site a line is SHOWN against. The recharge chain reads the line,
 * never the link (`recharge.service.ts`).
 */

import type { Knex } from 'knex';
import { logger } from '../../utils/logger';

export type SimLinkOutcome =
  | { outcome: 'linked'; lineId: number; siteDiffers: boolean }
  | { outcome: 'already_linked'; lineId: number }
  | { outcome: 'linked_elsewhere'; lineId: number; otherDeviceId: number }
  /** No line OF THIS TENANT carries the card — none at all, one in the pool or
   *  one of another tenant, deliberately alike (box above). */
  | { outcome: 'no_line' };

/**
 * The bench direction: a router read `iccid` in its modem; link the line of
 * the router's tenant that carries it. Runs inside the caller's transaction
 * and locks the line row.
 */
export async function linkLineByDeviceIccid(
  trx: Knex.Transaction,
  p: { tenantId: number; deviceId: number; siteId: number | null; iccid: string },
): Promise<SimLinkOutcome> {
  const line = (await linesCarryingIccid(trx('sim_lines'), p.iccid)
    .forUpdate()
    .first('id', 'tenant_id', 'device_id', 'site_id')) as
    | { id: number; tenant_id: number | null; device_id: number | null; site_id: number | null }
    | undefined;
  if (!line) return { outcome: 'no_line' };
  if (line.tenant_id === null || Number(line.tenant_id) !== p.tenantId) {
    // Server log only, by id: the tenant's own audit says `no_line`.
    logger.info(
      { lineId: line.id, deviceId: p.deviceId, pooled: line.tenant_id === null },
      'SIM line carrying the ICCID read at the bench is not this tenant\'s: not linked',
    );
    return { outcome: 'no_line' };
  }
  const lineId = Number(line.id);
  if (line.device_id !== null) {
    if (Number(line.device_id) === p.deviceId) return { outcome: 'already_linked', lineId };
    return { outcome: 'linked_elsewhere', lineId, otherDeviceId: Number(line.device_id) };
  }
  const update: Record<string, unknown> = { device_id: p.deviceId, updated_at: trx.fn.now() };
  if (line.site_id === null && p.siteId !== null) update.site_id = p.siteId;
  await trx('sim_lines').where({ id: lineId, tenant_id: p.tenantId }).whereNull('device_id').update(update);
  return {
    outcome: 'linked',
    lineId,
    siteDiffers: line.site_id !== null && p.siteId !== null && Number(line.site_id) !== p.siteId,
  };
}

/**
 * The line direction: `lineId` now carries an ICCID (or just joined a
 * tenant); link it to the ONE router of its tenant whose modem was read with
 * that card. Does nothing — and says why — for a pooled line, a line with no
 * ICCID, a line already linked, or an ICCID read in no router or in several.
 */
export async function linkDeviceByLineIccid(
  trx: Knex.Transaction,
  lineId: number,
): Promise<{ linked: boolean; deviceId: number | null; reason: 'linked' | 'not_applicable' | 'no_device' | 'ambiguous' }> {
  const line = (await trx('sim_lines')
    .where({ id: lineId })
    .forUpdate()
    .first('id', 'tenant_id', 'device_id', 'site_id', 'iccid')) as
    | { id: number; tenant_id: number | null; device_id: number | null; site_id: number | null; iccid: string | null }
    | undefined;
  if (!line || line.tenant_id === null || line.iccid === null || line.device_id !== null) {
    return { linked: false, deviceId: null, reason: 'not_applicable' };
  }
  const devices = await devicesCarryingIccid(trx, Number(line.tenant_id), line.iccid);
  if (devices.length === 0) return { linked: false, deviceId: null, reason: 'no_device' };
  if (devices.length > 1) {
    logger.warn(
      { lineId, deviceIds: devices.map((d) => d.id) },
      'SIM line ICCID read in more than one router of its tenant: not linked',
    );
    return { linked: false, deviceId: null, reason: 'ambiguous' };
  }
  const device = devices[0];
  const update: Record<string, unknown> = { device_id: device.id, updated_at: trx.fn.now() };
  if (line.site_id === null && device.site_id !== null) update.site_id = device.site_id;
  await trx('sim_lines').where({ id: lineId }).whereNull('device_id').update(update);
  return { linked: true, deviceId: Number(device.id), reason: 'linked' };
}

// ============================================================================
// The fleet direction (migration 080): every LTE modem the health check read
// ============================================================================

/**
 * ┌─ 19 OR 20 DIGITS: ONE CARD ─────────────────────────────────────────────┐
 * │ An ICCID is 19 digits plus a Luhn check digit. Some modems print the     │
 * │ check digit and some do not; some partners list it and some do not. So  │
 * │ two ICCIDs are the same card when they are equal, or when one has 19     │
 * │ digits, the other 20, and the 19 first are equal — and the second case is │
 * │ SAID (`prefixMatch`, `sim_link_conflicts.prefix_match`, the server log), │
 * │ never silently treated as an exact match. Digits only: blanks and a     │
 * │ trailing BCD filler `F` are the reader's to strip (`lteModem.service`). │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
export function iccidsMatch(a: string | null, b: string | null): 'exact' | 'prefix19' | null {
  if (!a || !b) return null;
  if (a === b) return 'exact';
  if ((a.length === 19 && b.length === 20) || (a.length === 20 && b.length === 19)) {
    return a.slice(0, 19) === b.slice(0, 19) ? 'prefix19' : null;
  }
  return null;
}

/** `q` narrowed to the rows whose `column` is the same card as `iccid`, the
 *  exact match first. `column` is always a literal of this file. */
function whereSameCard(q: Knex.QueryBuilder, column: string, iccid: string): Knex.QueryBuilder {
  q.where((w) => {
    w.where(column, iccid);
    if (iccid.length === 20) w.orWhere(column, iccid.slice(0, 19));
    if (iccid.length === 19) w.orWhereRaw(`length(${column}) = 20 AND left(${column}, 19) = ?`, [iccid]);
  });
  q.orderByRaw(`(${column} = ?) DESC`, [iccid]);
  return q;
}

function linesCarryingIccid(q: Knex.QueryBuilder, iccid: string): Knex.QueryBuilder {
  return whereSameCard(q, 'iccid', iccid);
}

/** The routers of `tenantId` whose card is `iccid` — read at the bench
 *  (`devices.sim_iccid`) or by the fleet in any modem (`device_lte_modems`).
 *  At most two: two is already "ambiguous". */
async function devicesCarryingIccid(
  trx: Knex.Transaction,
  tenantId: number,
  iccid: string,
): Promise<Array<{ id: number; site_id: number | null }>> {
  const bench = (await whereSameCard(trx('devices').where({ tenant_id: tenantId }), 'sim_iccid', iccid)
    .select('id', 'site_id')) as Array<{ id: number; site_id: number | null }>;
  const fleet = (await whereSameCard(
    trx('device_lte_modems as m').join('devices as d', 'd.id', 'm.device_id').where('d.tenant_id', tenantId),
    'm.iccid',
    iccid,
  ).select('d.id', 'd.site_id')) as Array<{ id: number; site_id: number | null }>;
  const byId = new Map<number, { id: number; site_id: number | null }>();
  for (const d of [...bench, ...fleet]) {
    byId.set(Number(d.id), { id: Number(d.id), site_id: d.site_id === null ? null : Number(d.site_id) });
  }
  return [...byId.values()].sort((x, y) => x.id - y.id).slice(0, 2);
}

/** The routers, ANY tenant, that carry this card (bench or fleet reading). */
async function routersCarryingCard(trx: Knex.Transaction, iccid: string): Promise<number[]> {
  const bench = (await whereSameCard(trx('devices'), 'sim_iccid', iccid).select('id')) as Array<{ id: number }>;
  const fleet = (await whereSameCard(trx('device_lte_modems'), 'iccid', iccid).select('device_id as id')) as Array<{ id: number }>;
  return [...new Set([...bench, ...fleet].map((r) => Number(r.id)))].sort((a, b) => a - b);
}

export type SimLinkConflictKind = 'other_tenant' | 'linked_elsewhere' | 'ambiguous';

export type ModemLinkOutcome =
  | { outcome: 'linked'; lineId: number; iccid: string; prefixMatch: boolean; fromPool: boolean }
  | { outcome: 'already_linked'; lineId: number; iccid: string }
  | { outcome: 'conflict'; lineId: number; iccid: string; kind: SimLinkConflictKind; prefixMatch: boolean }
  | { outcome: 'no_line'; iccid: string };

async function recordConflict(
  trx: Knex.Transaction,
  c: { lineId: number; deviceId: number; kind: SimLinkConflictKind; iccid: string; prefixMatch: boolean },
): Promise<void> {
  const now = new Date();
  // A dismissal (`linkConflict.service`) answers the situation the operator was
  // shown: the same kind about the same card read keeps it, anything else
  // reopens the row. No `?` in the CASE (knex binding trap).
  const sameSituation =
    'sim_link_conflicts.kind = EXCLUDED.kind AND sim_link_conflicts.iccid_read = EXCLUDED.iccid_read';
  await trx('sim_link_conflicts')
    .insert({
      line_id: c.lineId,
      device_id: c.deviceId,
      kind: c.kind,
      iccid_read: c.iccid,
      prefix_match: c.prefixMatch,
      detected_at: now,
      last_seen_at: now,
    })
    .onConflict(['line_id', 'device_id'])
    .merge({
      kind: c.kind,
      iccid_read: c.iccid,
      prefix_match: c.prefixMatch,
      last_seen_at: now,
      dismissed_at: trx.raw(`CASE WHEN ${sameSituation} THEN sim_link_conflicts.dismissed_at END`),
      dismissed_by: trx.raw(`CASE WHEN ${sameSituation} THEN sim_link_conflicts.dismissed_by END`),
      dismissed_note: trx.raw(`CASE WHEN ${sameSituation} THEN sim_link_conflicts.dismissed_note END`),
    });
}

/**
 * Link every card the FLEET read in `deviceId`'s modems (migration 080) to
 * its line. Runs after each modem read and after each partner sweep.
 *
 * ┌─ WHAT IS LINKED, WHAT IS RECORDED ──────────────────────────────────────┐
 * │ · A line of the router's tenant with no router: linked, and its site     │
 * │   filled from the router's when it has none.                             │
 * │ · A line still in the POOL (no tenant): assigned to the router's tenant  │
 * │   and linked — the card is physically in that customer's router. Its     │
 * │   open work is settled exactly as `updateLine` settles a move           │
 * │   (`settleOpenWorkOnMove`), and the assignment is logged.               │
 * │ · A line of ANOTHER tenant: NEVER moved. Recorded in                     │
 * │   `sim_link_conflicts` (`other_tenant`) for the platform's SIM           │
 * │   reconciliation; the tenant's own views never name that line.           │
 * │ · A line already linked to another router: kept (`linked_elsewhere`).   │
 * │ · A card read in several routers: nothing linked (`ambiguous`).          │
 * │ A conflict that a later pass no longer finds is deleted.                 │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
export async function autoLinkDeviceModems(knex: Knex, deviceId: number): Promise<ModemLinkOutcome[]> {
  const device = (await knex('devices').where({ id: deviceId }).first('id', 'tenant_id', 'site_id')) as
    | { id: number; tenant_id: number; site_id: number | null }
    | undefined;
  if (!device) return [];
  const tenantId = Number(device.tenant_id);
  const siteId = device.site_id === null ? null : Number(device.site_id);
  const modems = (await knex('device_lte_modems')
    .where({ device_id: deviceId })
    .whereNotNull('iccid')
    .orderBy('interface')
    .select('iccid')) as Array<{ iccid: string }>;
  const cards = [...new Set(modems.map((m) => m.iccid))];
  const out: ModemLinkOutcome[] = [];
  const touchedLines: number[] = [];

  for (const iccid of cards) {
    const result = await knex.transaction(async (trx): Promise<ModemLinkOutcome> => {
      const line = (await linesCarryingIccid(trx('sim_lines'), iccid)
        .forUpdate()
        .first('id', 'tenant_id', 'device_id', 'site_id', 'iccid')) as
        | { id: number; tenant_id: number | null; device_id: number | null; site_id: number | null; iccid: string }
        | undefined;
      if (!line) return { outcome: 'no_line', iccid };
      const lineId = Number(line.id);
      touchedLines.push(lineId);
      const prefixMatch = iccidsMatch(iccid, line.iccid) === 'prefix19';

      if (line.device_id !== null && Number(line.device_id) === deviceId) {
        await trx('sim_link_conflicts').where({ line_id: lineId, device_id: deviceId }).delete();
        return { outcome: 'already_linked', lineId, iccid };
      }
      const conflict = async (kind: SimLinkConflictKind): Promise<ModemLinkOutcome> => {
        await recordConflict(trx, { lineId, deviceId, kind, iccid, prefixMatch });
        logger.warn(
          { lineId, deviceId, kind, prefixMatch },
          'SIM card read in a router matches a line that cannot be linked to it: recorded as a conflict',
        );
        return { outcome: 'conflict', lineId, iccid, kind, prefixMatch };
      };
      if (line.tenant_id !== null && Number(line.tenant_id) !== tenantId) return conflict('other_tenant');
      if (line.device_id !== null) return conflict('linked_elsewhere');
      const routers = await routersCarryingCard(trx, line.iccid);
      if (routers.length > 1 || (routers.length === 1 && routers[0] !== deviceId)) return conflict('ambiguous');

      const fromPool = line.tenant_id === null;
      const update: Record<string, unknown> = { device_id: deviceId, updated_at: trx.fn.now() };
      if (line.site_id === null && siteId !== null) update.site_id = siteId;
      if (fromPool) {
        update.tenant_id = tenantId;
        update.tenant_assigned_at = trx.fn.now();
        // A pooled line's site (if any) is of no tenant: the router's wins.
        update.site_id = siteId;
      }
      const q = trx('sim_lines').where({ id: lineId }).whereNull('device_id');
      if (fromPool) q.whereNull('tenant_id');
      else q.where({ tenant_id: tenantId });
      const n = await q.update(update);
      if (n !== 1) return { outcome: 'no_line', iccid };
      if (fromPool) {
        const { settleOpenWorkOnMove } = await import('./line.service');
        await settleOpenWorkOnMove(trx, lineId, null);
      }
      await trx('sim_link_conflicts').where({ line_id: lineId, device_id: deviceId }).delete();
      logger.info(
        { lineId, deviceId, prefixMatch, fromPool },
        prefixMatch
          ? 'SIM line linked to the router whose modem holds its card (ICCIDs equal on their first 19 digits only)'
          : 'SIM line linked to the router whose modem holds its card',
      );
      return { outcome: 'linked', lineId, iccid, prefixMatch, fromPool };
    });
    out.push(result);
  }

  // A conflict of this router about a line none of its cards matches any more
  // (the card was swapped, the line's ICCID corrected) is gone.
  const stale = knex('sim_link_conflicts').where({ device_id: deviceId });
  if (touchedLines.length > 0) stale.whereNotIn('line_id', touchedLines);
  await stale.delete();
  return out;
}

/**
 * After a partner sweep of `accountId`: every line of it with an ICCID and
 * no router is offered to the routers that read its card — the line
 * direction for a tenant's lines (bench or fleet readings), and the modem
 * direction for every router whose modem holds one of these cards, which is
 * what assigns a pool line and records the conflicts. Never throws: a link
 * is a convenience, and a sweep is not undone by it.
 */
export async function relinkAccountLines(knex: Knex, accountId: number): Promise<{ linked: number }> {
  let linked = 0;
  try {
    const lines = (await knex('sim_lines')
      .where({ account_id: accountId })
      .whereNotNull('iccid')
      .whereNull('device_id')
      .select('id', 'tenant_id', 'iccid')) as Array<{ id: number; tenant_id: number | null; iccid: string }>;
    if (lines.length === 0) return { linked };
    for (const l of lines) {
      if (l.tenant_id === null) continue;
      const r = await knex.transaction((trx) => linkDeviceByLineIccid(trx, Number(l.id)));
      if (r.linked) linked++;
    }
    const iccids = lines.map((l) => l.iccid);
    const variants = new Set<string>(iccids);
    for (const i of iccids) if (i.length === 20) variants.add(i.slice(0, 19));
    const nineteens = iccids.filter((i) => i.length === 19);
    const devices = (await knex('device_lte_modems')
      .where((w) => {
        w.whereIn('iccid', [...variants]);
        if (nineteens.length > 0) w.orWhereRaw('length(iccid) = 20 AND left(iccid, 19) = ANY(?)', [nineteens]);
      })
      .distinct('device_id')) as Array<{ device_id: number }>;
    for (const d of devices) {
      const outcomes = await autoLinkDeviceModems(knex, Number(d.device_id));
      linked += outcomes.filter((o) => o.outcome === 'linked').length;
    }
  } catch (err) {
    logger.warn({ err, accountId }, 'SIM lines could not be offered to the routers that read their cards after the sweep');
  }
  return { linked };
}
