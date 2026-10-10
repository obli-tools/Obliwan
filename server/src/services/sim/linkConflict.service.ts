/**
 * ObliWAN — the SIM line ↔ router links the fleet could NOT make
 * (`sim_link_conflicts`, migration 080), as the platform's « Rapprochement
 * SIM » shows and settles them.
 *
 * `deviceLink.autoLinkDeviceModems` records a conflict when a card read in a
 * router's modem is carried by a line it must not take on its own:
 *   · `other_tenant`     the line is ANOTHER customer's;
 *   · `linked_elsewhere` the line is already linked to another router;
 *   · `ambiguous`        the card was read in several routers.
 * Nothing was moved. This file is the human's half: the list, and two
 * decisions — ASSIGN the line to the router that read the card, or DISMISS
 * the conflict (nothing moves).
 *
 * ┌─ WHO MAY DO THIS ────────────────────────────────────────────────────────┐
 * │ The platform admin in the master god view (route `requireRole('admin')`, │
 * │ controller `hasGlobalView`). An assignment can move a line BETWEEN       │
 * │ customers, which is the platform act `updateLine` reserves to            │
 * │ `masterView`; and the list names every customer's lines and routers.    │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ AN ASSIGNMENT IS RE-CHECKED, NEVER TAKEN FROM THE ROW ON TRUST ─────────┐
 * │ The row is a past observation. Inside the transaction the router's       │
 * │ modems must STILL hold the line's card (`iccidsMatch`, the same 19/20    │
 * │ rule as the automatic link): a card swapped since the screen was loaded  │
 * │ answers 409, because a wrong link is believed and is worse than none.    │
 * │ The move then follows the assignment model exactly: the router's tenant, │
 * │ the router's site (kept when the router has none and the tenant does not │
 * │ change), `tenant_assigned_at` = now on a tenant change (the consumption  │
 * │ cut) and its open proposals expired (`settleOpenWorkOnMove`). Audited in │
 * │ the router's tenant and, on a move, in the tenant the line left.          │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Nothing here spends, proposes or approves anything, and nothing writes to a
 * router: a link changes which router and site a line is SHOWN against.
 */

import type { Knex } from 'knex';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import type { SimLineStatus } from '@obliwan/shared';
import { appendAudit } from '../attestation/auditLog.service';
import { autoLinkDeviceModems, iccidsMatch, type SimLinkConflictKind } from './deviceLink.service';
import { settleOpenWorkOnMove } from './line.service';

export class SimLinkConflictError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
    this.name = 'SimLinkConflictError';
  }
}

export interface SimLinkConflictRouter {
  id: number;
  name: string;
  tenantId: number;
  tenantName: string | null;
  siteId: number | null;
  siteName: string | null;
}

export interface SimLinkConflictView {
  id: number;
  kind: SimLinkConflictKind;
  /** The card as the router's modem printed it. */
  iccidRead: string;
  /** The two ICCIDs are equal on their first 19 digits only. */
  prefixMatch: boolean;
  detectedAt: string;
  lastSeenAt: string;
  dismissedAt: string | null;
  dismissedByName: string | null;
  dismissedNote: string | null;
  /** The router whose modem read the card. */
  router: SimLinkConflictRouter;
  line: {
    id: number;
    msisdn: string;
    iccid: string | null;
    label: string | null;
    status: SimLineStatus;
    tenantId: number | null;
    tenantName: string | null;
    siteId: number | null;
    siteName: string | null;
    /** The router the line is linked to today, if any. */
    deviceId: number | null;
    deviceName: string | null;
  };
  /** The OTHER routers, any tenant, whose modem (fleet or bench reading) holds
   *  the same card — what makes an `ambiguous` conflict ambiguous. */
  otherRouters: Array<{ id: number; name: string; tenantId: number; tenantName: string | null }>;
}

const iso = (v: Date | string | null | undefined): string | null =>
  v === null || v === undefined ? null : new Date(v).toISOString();

interface ConflictRow {
  id: number;
  kind: SimLinkConflictKind;
  iccid_read: string;
  prefix_match: boolean;
  detected_at: Date | string;
  last_seen_at: Date | string;
  dismissed_at: Date | string | null;
  dismissed_note: string | null;
  dismissed_by_name: string | null;
  r_id: number;
  r_name: string;
  r_tenant_id: number;
  r_tenant_name: string | null;
  r_site_id: number | null;
  r_site_name: string | null;
  l_id: number;
  l_msisdn: string;
  l_iccid: string | null;
  l_label: string | null;
  l_status: SimLineStatus;
  l_tenant_id: number | null;
  l_tenant_name: string | null;
  l_site_id: number | null;
  l_site_name: string | null;
  l_device_id: number | null;
  l_device_name: string | null;
}

/** Every card variant that is the same card as one of `iccids` (19/20 rule). */
async function routersHoldingCards(
  iccids: string[],
): Promise<Array<{ id: number; name: string; tenantId: number; tenantName: string | null; iccid: string }>> {
  if (iccids.length === 0) return [];
  const variants = new Set<string>(iccids);
  for (const i of iccids) if (i.length === 20) variants.add(i.slice(0, 19));
  const nineteens = iccids.filter((i) => i.length === 19);
  const fleet = (await db('device_lte_modems as m')
    .join('devices as d', 'd.id', 'm.device_id')
    .leftJoin('tenants as t', 't.id', 'd.tenant_id')
    .where((w) => {
      w.whereIn('m.iccid', [...variants]);
      if (nineteens.length > 0) w.orWhereRaw('length(m.iccid) = 20 AND left(m.iccid, 19) = ANY(?)', [nineteens]);
    })
    .select('d.id', 'd.name', 'd.tenant_id', 't.name as tenant_name', 'm.iccid as iccid')) as Array<{
    id: number; name: string; tenant_id: number; tenant_name: string | null; iccid: string;
  }>;
  const bench = (await db('devices as d')
    .leftJoin('tenants as t', 't.id', 'd.tenant_id')
    .where((w) => {
      w.whereIn('d.sim_iccid', [...variants]);
      if (nineteens.length > 0) w.orWhereRaw('length(d.sim_iccid) = 20 AND left(d.sim_iccid, 19) = ANY(?)', [nineteens]);
    })
    .select('d.id', 'd.name', 'd.tenant_id', 't.name as tenant_name', 'd.sim_iccid as iccid')) as typeof fleet;
  return [...fleet, ...bench].map((r) => ({
    id: Number(r.id),
    name: r.name,
    tenantId: Number(r.tenant_id),
    tenantName: r.tenant_name,
    iccid: r.iccid,
  }));
}

/**
 * Every conflict, the open ones first (newest seen first), then — when asked —
 * the dismissed ones. One read, joined; the other routers holding each card in
 * one more batch.
 */
export async function listLinkConflicts(opts: { includeDismissed?: boolean } = {}): Promise<SimLinkConflictView[]> {
  const q = db('sim_link_conflicts as c')
    .join('devices as d', 'd.id', 'c.device_id')
    .leftJoin('tenants as dt', 'dt.id', 'd.tenant_id')
    .leftJoin('sites as ds', function () {
      this.on('ds.id', '=', 'd.site_id').andOn('ds.tenant_id', '=', 'd.tenant_id');
    })
    .join('sim_lines as l', 'l.id', 'c.line_id')
    .leftJoin('tenants as lt', 'lt.id', 'l.tenant_id')
    .leftJoin('sites as ls', function () {
      this.on('ls.id', '=', 'l.site_id').andOn('ls.tenant_id', '=', 'l.tenant_id');
    })
    .leftJoin('devices as ld', function () {
      this.on('ld.id', '=', 'l.device_id').andOn('ld.tenant_id', '=', 'l.tenant_id');
    })
    .leftJoin('users as u', 'u.id', 'c.dismissed_by')
    .select(
      'c.id', 'c.kind', 'c.iccid_read', 'c.prefix_match', 'c.detected_at', 'c.last_seen_at',
      'c.dismissed_at', 'c.dismissed_note', 'u.username as dismissed_by_name',
      'd.id as r_id', 'd.name as r_name', 'd.tenant_id as r_tenant_id', 'dt.name as r_tenant_name',
      'd.site_id as r_site_id', 'ds.name as r_site_name',
      'l.id as l_id', 'l.msisdn as l_msisdn', 'l.iccid as l_iccid', 'l.label as l_label', 'l.status as l_status',
      'l.tenant_id as l_tenant_id', 'lt.name as l_tenant_name', 'l.site_id as l_site_id', 'ls.name as l_site_name',
      'l.device_id as l_device_id', 'ld.name as l_device_name',
    )
    .orderByRaw('(c.dismissed_at IS NOT NULL), c.last_seen_at DESC, c.id DESC')
    .limit(1000);
  if (!opts.includeDismissed) q.whereNull('c.dismissed_at');
  const rows = (await q) as ConflictRow[];

  const holders = await routersHoldingCards([...new Set(rows.map((r) => r.iccid_read))]);
  return rows.map((r) => {
    const others = new Map<number, { id: number; name: string; tenantId: number; tenantName: string | null }>();
    for (const h of holders) {
      if (h.id === Number(r.r_id) || iccidsMatch(h.iccid, r.iccid_read) === null) continue;
      others.set(h.id, { id: h.id, name: h.name, tenantId: h.tenantId, tenantName: h.tenantName });
    }
    return {
      id: Number(r.id),
      kind: r.kind,
      iccidRead: r.iccid_read,
      prefixMatch: r.prefix_match === true,
      detectedAt: iso(r.detected_at)!,
      lastSeenAt: iso(r.last_seen_at)!,
      dismissedAt: iso(r.dismissed_at),
      dismissedByName: r.dismissed_by_name,
      dismissedNote: r.dismissed_note,
      router: {
        id: Number(r.r_id),
        name: r.r_name,
        tenantId: Number(r.r_tenant_id),
        tenantName: r.r_tenant_name,
        siteId: r.r_site_id === null ? null : Number(r.r_site_id),
        siteName: r.r_site_name,
      },
      line: {
        id: Number(r.l_id),
        msisdn: r.l_msisdn,
        iccid: r.l_iccid,
        label: r.l_label,
        status: r.l_status,
        tenantId: r.l_tenant_id === null ? null : Number(r.l_tenant_id),
        tenantName: r.l_tenant_name,
        siteId: r.l_site_id === null ? null : Number(r.l_site_id),
        siteName: r.l_site_name,
        deviceId: r.l_device_id === null ? null : Number(r.l_device_id),
        deviceName: r.l_device_name,
      },
      otherRouters: [...others.values()].sort((a, b) => a.id - b.id),
    };
  });
}

export interface ConflictActor {
  id: number;
  name: string;
  /** The tenant the operator was positioned on (the master), for the ledger. */
  fromTenantId: number;
}

function godViewOrigin(actor: ConflictActor): { godView: { viaGodView: true; initiatedFromTenantId: number } } {
  return { godView: { viaGodView: true, initiatedFromTenantId: actor.fromTenantId } };
}

export interface AssignOutcome {
  lineId: number;
  deviceId: number;
  tenantId: number;
  previousTenantId: number | null;
  previousDeviceId: number | null;
  siteId: number | null;
  movedTenant: boolean;
  /** Other routers whose conflict about this line was re-evaluated. */
  reevaluated: number;
}

/**
 * ASSIGN: the line goes to the router that read its card — that router's
 * tenant, that router, that router's site. See the header for what is
 * re-checked and what follows a move.
 */
export async function assignConflictLine(conflictId: number, actor: ConflictActor): Promise<AssignOutcome> {
  const outcome = await db.transaction(async (trx): Promise<AssignOutcome & { otherDevices: number[] }> => {
    const c = (await trx('sim_link_conflicts').where({ id: conflictId }).forUpdate().first(
      'id', 'line_id', 'device_id', 'kind', 'iccid_read', 'prefix_match',
    )) as
      | { id: number; line_id: number; device_id: number; kind: SimLinkConflictKind; iccid_read: string; prefix_match: boolean }
      | undefined;
    if (!c) throw new SimLinkConflictError('Conflict not found (already settled?)', 404);
    const lineId = Number(c.line_id);
    const deviceId = Number(c.device_id);

    const line = (await trx('sim_lines').where({ id: lineId }).forUpdate().first(
      'id', 'msisdn', 'iccid', 'tenant_id', 'site_id', 'device_id',
    )) as
      | { id: number; msisdn: string; iccid: string | null; tenant_id: number | null; site_id: number | null; device_id: number | null }
      | undefined;
    if (!line) throw new SimLinkConflictError('Line not found', 404);
    const device = (await trx('devices').where({ id: deviceId }).first('id', 'name', 'tenant_id', 'site_id')) as
      | { id: number; name: string; tenant_id: number; site_id: number | null }
      | undefined;
    if (!device) throw new SimLinkConflictError('Router not found', 404);

    // The card must STILL be in that router (header). The fleet reading only:
    // that is what records a conflict; the bench reading is the box's past.
    const cards = (await trx('device_lte_modems').where({ device_id: deviceId }).whereNotNull('iccid').pluck('iccid')) as string[];
    if (!cards.some((card) => iccidsMatch(card, line.iccid) !== null)) {
      throw new SimLinkConflictError(
        'The card is no longer read in this router, or the line no longer carries it: refresh before deciding.',
        409,
      );
    }

    const tenantId = Number(device.tenant_id);
    const previousTenantId = line.tenant_id === null ? null : Number(line.tenant_id);
    const previousDeviceId = line.device_id === null ? null : Number(line.device_id);
    const movedTenant = previousTenantId !== tenantId;
    const routerSite = device.site_id === null ? null : Number(device.site_id);
    const siteId = routerSite ?? (movedTenant ? null : line.site_id === null ? null : Number(line.site_id));

    const update: Record<string, unknown> = {
      tenant_id: tenantId,
      device_id: deviceId,
      site_id: siteId,
      updated_at: trx.fn.now(),
    };
    if (movedTenant) update.tenant_assigned_at = trx.fn.now();
    await trx('sim_lines').where({ id: lineId }).update(update);
    if (movedTenant) await settleOpenWorkOnMove(trx, lineId, previousTenantId);

    // This conflict is settled; the line's conflicts with OTHER routers are
    // re-evaluated after the commit (their kind may now be different).
    await trx('sim_link_conflicts').where({ id: conflictId }).delete();
    const otherDevices = ((await trx('sim_link_conflicts').where({ line_id: lineId }).pluck('device_id')) as number[]).map(Number);

    const before = { tenantId: previousTenantId, deviceId: previousDeviceId, siteId: line.site_id === null ? null : Number(line.site_id) };
    const after = {
      tenantId, deviceId, siteId,
      msisdn: line.msisdn,
      conflict: { id: Number(c.id), kind: c.kind, iccidRead: c.iccid_read, prefixMatch: c.prefix_match === true },
      ...godViewOrigin(actor),
    };
    const base = {
      actorType: 'user' as const,
      actorId: actor.id,
      actorName: actor.name,
      entityType: 'sim_line',
      entityId: lineId,
    };
    await appendAudit({ ...base, tenantId, action: 'sim_link_conflict.line_assigned', before, after }, trx);
    if (movedTenant && previousTenantId !== null) {
      await appendAudit({ ...base, tenantId: previousTenantId, action: 'sim_link_conflict.line_moved_away', before, after }, trx);
    }
    return {
      lineId, deviceId, tenantId, previousTenantId, previousDeviceId, siteId, movedTenant,
      reevaluated: 0, otherDevices,
    };
  });

  // The other routers that read this card: their conflicts are re-recorded
  // with what is now true (or cleared). A failure here leaves the assignment
  // made and the old rows to the next modem pass — never undoes the decision.
  let reevaluated = 0;
  for (const other of outcome.otherDevices) {
    try {
      await autoLinkDeviceModems(db, other);
      reevaluated += 1;
    } catch (err) {
      logger.warn(
        { err: err instanceof Error ? err.message : String(err), lineId: outcome.lineId, deviceId: other },
        'SIM conflict re-evaluation failed after an assignment; the next modem pass will redo it',
      );
    }
  }
  logger.info(
    { lineId: outcome.lineId, deviceId: outcome.deviceId, movedTenant: outcome.movedTenant, actorId: actor.id },
    'SIM line assigned to the router that read its card (SIM reconciliation)',
  );
  const { otherDevices: _ignored, ...rest } = outcome;
  void _ignored;
  return { ...rest, reevaluated };
}

/** The conflict row, locked, with the tenant of the router that read the card
 *  (the dismissal is filed there, like the assignment). */
async function lockConflict(
  trx: Knex.Transaction,
  conflictId: number,
): Promise<{
  line_id: number; device_id: number; kind: string; iccid_read: string;
  dismissed_at: Date | string | null; dismissed_note: string | null; routerTenantId: number;
}> {
  const c = (await trx('sim_link_conflicts').where({ id: conflictId }).forUpdate().first(
    'line_id', 'device_id', 'kind', 'iccid_read', 'dismissed_at', 'dismissed_note',
  )) as
    | { line_id: number; device_id: number; kind: string; iccid_read: string; dismissed_at: Date | string | null; dismissed_note: string | null }
    | undefined;
  if (!c) throw new SimLinkConflictError('Conflict not found (already settled?)', 404);
  const d = (await trx('devices').where({ id: c.device_id }).first('tenant_id')) as { tenant_id: number } | undefined;
  // The FK cascades a router's deletion to its conflicts, so this cannot miss
  // inside the lock; checked rather than assumed.
  if (!d) throw new SimLinkConflictError('Router not found', 404);
  return { ...c, routerTenantId: Number(d.tenant_id) };
}

/** DISMISS: nothing moves; the conflict leaves the open list until the
 *  situation changes (`deviceLink.recordConflict`). */
export async function dismissConflict(
  conflictId: number,
  actor: ConflictActor,
  note: string | null,
): Promise<void> {
  const text = note === null ? null : note.trim() === '' ? null : note.trim().slice(0, 500);
  await db.transaction(async (trx) => {
    const c = await lockConflict(trx, conflictId);
    if (c.dismissed_at !== null) throw new SimLinkConflictError('This conflict is already dismissed', 409);
    await trx('sim_link_conflicts')
      .where({ id: conflictId })
      .update({ dismissed_at: trx.fn.now(), dismissed_by: actor.id, dismissed_note: text });
    await appendAudit({
      tenantId: c.routerTenantId,
      actorType: 'user',
      actorId: actor.id,
      actorName: actor.name,
      action: 'sim_link_conflict.dismissed',
      entityType: 'sim_link_conflict',
      entityId: conflictId,
      after: {
        lineId: Number(c.line_id), deviceId: Number(c.device_id), kind: c.kind, iccidRead: c.iccid_read,
        note: text, ...godViewOrigin(actor),
      },
    }, trx);
  });
}

/** REOPEN: a dismissal taken back. */
export async function reopenConflict(conflictId: number, actor: ConflictActor): Promise<void> {
  await db.transaction(async (trx) => {
    const c = await lockConflict(trx, conflictId);
    if (c.dismissed_at === null) throw new SimLinkConflictError('This conflict is not dismissed', 409);
    await trx('sim_link_conflicts')
      .where({ id: conflictId })
      .update({ dismissed_at: null, dismissed_by: null, dismissed_note: null });
    await appendAudit({
      tenantId: c.routerTenantId,
      actorType: 'user',
      actorId: actor.id,
      actorName: actor.name,
      action: 'sim_link_conflict.reopened',
      entityType: 'sim_link_conflict',
      entityId: conflictId,
      before: { dismissedAt: iso(c.dismissed_at), note: c.dismissed_note },
      after: { lineId: Number(c.line_id), deviceId: Number(c.device_id), kind: c.kind, ...godViewOrigin(actor) },
    }, trx);
  });
}
