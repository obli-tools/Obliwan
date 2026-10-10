import type { Server as SocketIOServer } from 'socket.io';
import type { Knex } from 'knex';
import { db } from '../db';
import { SOCKET_EVENTS, socketRooms, type OperatorOutageRole } from '@obliwan/shared';
import { applyTenantScope } from '../utils/globalView';
import { liveAlertScope, type AlertViewer } from './teamScope.service';
import { emitToTenantAudience, type EmitAudience } from './fleet/scopedEmit';

let _io: SocketIOServer | null = null;

export function setLiveAlertIO(io: SocketIOServer): void {
  _io = io;
}

export interface LiveAlertRow {
  id: number;
  tenantId: number;
  tenantName?: string;
  severity: 'down' | 'up' | 'warning' | 'info';
  title: string;
  message: string;
  navigateTo: string | null;
  stableKey: string | null;
  /**
   * The equipment the alert is about (migration 087). At most one of the three
   * is the alert's audience; none = a tenant-level alert, visible to every
   * member of the workspace.
   */
  deviceId: number | null;
  siteId: number | null;
  simLineId: number | null;
  read: boolean;
  createdAt: string; // ISO
  /** The grouped operator outage the alert belongs to (migration 095) and its
   *  role in it; both null for every other alert. */
  outageId: number | null;
  outageRole: OperatorOutageRole | null;
}

/** What an alert is about; the most specific one present decides who sees it. */
export interface AlertSubject {
  deviceId?: number | null;
  siteId?: number | null;
  simLineId?: number | null;
}

function rowToAlert(row: Record<string, unknown>): LiveAlertRow {
  return {
    id: row.id as number,
    tenantId: row.tenant_id as number,
    tenantName: row.tenant_name as string | undefined,
    severity: row.severity as LiveAlertRow['severity'],
    title: row.title as string,
    message: row.message as string,
    navigateTo: row.navigate_to as string | null,
    stableKey: row.stable_key as string | null,
    deviceId: (row.device_id as number | null | undefined) ?? null,
    siteId: (row.site_id as number | null | undefined) ?? null,
    simLineId: (row.sim_line_id as number | null | undefined) ?? null,
    read: row.read_at !== null,
    createdAt: (row.created_at as Date).toISOString(),
    outageId: row.outage_id === null || row.outage_id === undefined ? null : Number(row.outage_id),
    outageRole: (row.outage_role as OperatorOutageRole | null | undefined) ?? null,
  };
}

/**
 * The operator-outage roles a feed shows (migration 095). The god view shows
 * a group's GLOBAL alert (every tenant's stores) and never a customer
 * tenant's slice of the same group; anyone else shows its tenant's slice and
 * never the global alert — it counts other customers' stores. Folded
 * per-store alerts ('member') are shown to both, under their group.
 */
function outageRoleScope(q: Knex.QueryBuilder, alias: string, godView: boolean): Knex.QueryBuilder {
  const hidden = godView ? 'tenant' : 'global';
  return q.where((w) => {
    void w.whereNull(`${alias}.outage_role`).orWhereNot(`${alias}.outage_role`, hidden);
  });
}

/**
 * The alerts of one tenant a viewer may touch, as a bulk-write target. A
 * platform admin: all of them. Anybody else: through the id set the team
 * predicate selects (a sub-select, because UPDATE/DELETE take no join) —
 * never a god-view operator-outage alert (migration 095), which only the god
 * view shows.
 */
function visibleAlerts(tenantId: number, viewer: AlertViewer) {
  const base = db('live_alerts').where({ tenant_id: tenantId });
  if (viewer.isPlatformAdmin) return base;
  const ids = db('live_alerts as la').select('la.id').where('la.tenant_id', tenantId);
  liveAlertScope(ids, 'la', viewer, [tenantId]);
  outageRoleScope(ids, 'la', false);
  return base.whereIn('id', ids);
}

export const liveAlertService = {
  /**
   * Add a new live alert. If stableKey is provided, the insert is skipped when
   * an unread alert with the same (tenant_id, stable_key) already exists.
   * Returns the inserted row, or null if dedup skipped it.
   * After insert, emits NOTIFICATION_NEW via Socket.io.
   */
  async add(
    tenantId: number,
    opts: {
      severity: 'down' | 'up' | 'warning' | 'info';
      title: string;
      message: string;
      navigateTo?: string | null;
      stableKey?: string | null;
      /** An alert of a grouped operator outage (migration 095): see
       *  `outageRoleScope` for who sees each role. */
      outage?: { id: number; role: OperatorOutageRole } | null;
    } & AlertSubject,
  ): Promise<LiveAlertRow | null> {
    // Dedup: skip if an unread alert with the same stable_key already exists for this tenant
    if (opts.stableKey) {
      const existing = await db('live_alerts')
        .where({ tenant_id: tenantId, stable_key: opts.stableKey })
        .whereNull('read_at')
        .first();
      if (existing) return null;
    }

    const [row] = await db('live_alerts')
      .insert({
        tenant_id: tenantId,
        severity: opts.severity,
        title: opts.title,
        message: opts.message,
        navigate_to: opts.navigateTo ?? null,
        stable_key: opts.stableKey ?? null,
        device_id: opts.deviceId ?? null,
        site_id: opts.siteId ?? null,
        sim_line_id: opts.simLineId ?? null,
        outage_id: opts.outage?.id ?? null,
        outage_role: opts.outage?.role ?? null,
      })
      .returning('*');

    // Keep only the newest 200 alerts per tenant (trim oldest)
    await db.raw(
      `DELETE FROM live_alerts WHERE tenant_id = ? AND id NOT IN (
         SELECT id FROM live_alerts WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 200
       )`,
      [tenantId, tenantId],
    );

    const alert = rowToAlert(row);

    // Attach tenant name for socket payload
    const tenantRow = await db('tenants').where({ id: tenantId }).select('name').first() as { name: string } | undefined;
    const enriched: LiveAlertRow = { ...alert, tenantName: tenantRow?.name ?? '' };

    // Emit to the users subscribed to this tenant's notifications whose teams
    // cover the alert's subject (an alert naming none goes to every member),
    // and to the master tenant's god view (a socket in both rooms gets it once).
    // An operator-outage group alert goes to ONE of the two (migration 095):
    // the global one to the god view only, a tenant's slice to its tenant only.
    if (_io) {
      const audience: EmitAudience = enriched.deviceId !== null ? { deviceId: enriched.deviceId }
        : enriched.siteId !== null ? { siteId: enriched.siteId }
          : enriched.simLineId !== null ? { simLineId: enriched.simLineId }
            : 'tenant';
      const tenantRoom = socketRooms.tenantNotifications(tenantId);
      const godRoom = socketRooms.godViewNotifications();
      const role = enriched.outageRole;
      emitToTenantAudience(
        tenantId,
        SOCKET_EVENTS.NOTIFICATION_NEW,
        enriched,
        audience,
        role === 'global' ? godRoom : tenantRoom,
        role === 'tenant' ? tenantRoom : godRoom,
      );
    }

    return enriched;
  },

  /**
   * Fetch all alerts for a single tenant (newest first).
   *
   * This used to drop the `where tenant_id` entirely when
   * `isMasterTenant(tenantId)` was true. Combined with the `?? 1` fallback in
   * the controllers, ANY account with no tenant membership landed on tenant 1
   * and read the 100 most recent alerts of EVERY client — titles and messages
   * included, i.e. site names, IPs and outage causes.
   *
   * The god view is not removed, it is made deliberate: `isGodView(tenantId)`
   * (utils/globalView.ts) is true only inside a request `requireTenant`
   * established as a PLATFORM ADMIN (`users.role = 'admin'`, from the
   * database) positioned on the master tenant — membership of the master
   * tenant neither grants it nor is required for it. A session value alone
   * cannot buy it, and outside a request (internal code) it is false.
   */
  async getForTenant(tenantId: number, viewer: AlertViewer, limit = 100): Promise<LiveAlertRow[]> {
    const q = db('live_alerts as la')
      .leftJoin('tenants as t', 't.id', 'la.tenant_id')
      .select('la.*', 't.name as tenant_name');
    const godView = applyTenantScope(q, 'la.tenant_id', tenantId);
    // Team scope (087): an alert about a device, site or line is visible to the
    // teams that cover it; a tenant-level alert to every member.
    liveAlertScope(q, 'la', viewer, [tenantId]);
    outageRoleScope(q, 'la', godView);
    const rows = await q.orderBy('la.created_at', 'desc').limit(limit);
    return rows.map(rowToAlert);
  },

  /**
   * Fetch alerts for all of the given tenants, enriched with tenant name.
   * Used for the multi-tenant notification panel. `godView`: the caller is the
   * god view (the controller's `hasGlobalView`), which decides which
   * operator-outage alerts it shows (`outageRoleScope`).
   */
  async getForTenants(
    tenantIds: number[],
    viewer: AlertViewer,
    limit = 200,
    opts: { godView?: boolean } = {},
  ): Promise<LiveAlertRow[]> {
    if (tenantIds.length === 0) return [];
    const q = db('live_alerts')
      .join('tenants', 'live_alerts.tenant_id', 'tenants.id')
      .whereIn('live_alerts.tenant_id', tenantIds);
    liveAlertScope(q, 'live_alerts', viewer, tenantIds);
    outageRoleScope(q, 'live_alerts', opts.godView === true);
    const rows = await q
      .orderBy('live_alerts.created_at', 'desc')
      .limit(limit)
      .select('live_alerts.*', 'tenants.name as tenant_name');
    return rows.map(rowToAlert);
  },

  async markRead(id: number, tenantId: number): Promise<void> {
    await db('live_alerts').where({ id, tenant_id: tenantId }).update({ read_at: new Date() });
  },

  /**
   * Marks the alerts the VIEWER can see; the ones outside their teams stay
   * unread for whoever does see them.
   */
  async markAllRead(tenantId: number, viewer: AlertViewer): Promise<void> {
    await visibleAlerts(tenantId, viewer).whereNull('read_at').update({ read_at: new Date() });
  },

  async deleteAlert(id: number): Promise<void> {
    await db('live_alerts').where({ id }).delete();
  },

  /** Deletes the alerts the VIEWER can see; the others are left alone. */
  async clearAll(tenantId: number, viewer: AlertViewer): Promise<void> {
    await visibleAlerts(tenantId, viewer).delete();
  },

  /**
   * One alert of the given tenants, only if the VIEWER can see it (null
   * otherwise: the caller answers 404, never "forbidden" — an alert outside
   * your teams does not exist as far as you are concerned).
   */
  async findVisible(
    id: number,
    tenantIds: number[],
    viewer: AlertViewer,
  ): Promise<{ id: number; tenant_id: number } | null> {
    if (tenantIds.length === 0) return null;
    const q = db('live_alerts').where('live_alerts.id', id).whereIn('live_alerts.tenant_id', tenantIds);
    liveAlertScope(q, 'live_alerts', viewer, tenantIds);
    // A god-view operator-outage alert is a platform admin's only.
    if (!viewer.isPlatformAdmin) outageRoleScope(q, 'live_alerts', false);
    const row = (await q.first('live_alerts.id', 'live_alerts.tenant_id')) as { id: number; tenant_id: number } | undefined;
    return row ?? null;
  },

  /** Periodic cleanup: remove alerts older than daysOld. */
  async cleanup(daysOld = 30): Promise<void> {
    await db('live_alerts')
      .where('created_at', '<', new Date(Date.now() - daysOld * 86_400_000))
      .delete();
  },
};
