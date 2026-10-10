/**
 * ObliWAN — live events addressed to the people whose teams cover the object.
 *
 * `fleetEvents.emitToTenant` hands a payload to every socket of a tenant. Since
 * migration 087 that is wrong for anything naming a device, a site, a SIM line
 * or a rollout: a tenant admin holds every capability of its role, but sees
 * only what its teams cover (like in Obliance), and a socket that received
 * `wan:device:updated` for a router outside those teams would hand the same
 * data the REST lists now refuse. So the payload goes to:
 *
 *   1. the god view room (platform admins on the master tenant — unchanged);
 *   2. every socket of the tenant room whose USER may read the object.
 *
 * The verdict is `get{Device,Site,SimLine,Rollout}Permission(...) !== null`
 * (teamScope.service — the same function the REST detail routes use), cached 10
 * seconds per (user, tenant, audience): a presence storm over hundreds of sites
 * costs one lookup per user per object per window, not one per packet. The
 * cache is the price of the fan-out; REST stays authoritative, and a grant
 * revoked can leak at most that window of live events.
 *
 * Kept apart from `fleetEvents` so that module stays dependency-free (it is
 * imported by every service and must never close a require cycle). Nothing here
 * throws: an emit is best-effort and a failed verdict is a dropped event.
 */

import { SOCKET_EVENTS, socketRooms, type SitePresenceEvent } from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { emitToDevice, fleetIO } from './fleetEvents';
import {
  getDevicePermission,
  getRolloutPermission,
  getSimLinePermission,
  getSitePermission,
  ungroupedLevel,
} from '../teamScope.service';

/**
 * Who a payload is about. `'tenant'` = names no equipment: every member.
 * `{ ungrouped }` = the objects filed nowhere (a PPP username no device claims
 * yet): the teams holding the ungrouped grant, like the discovery quarantine.
 */
export type EmitAudience =
  | { deviceId: number }
  | { siteId: number }
  | { simLineId: number }
  | { rolloutId: number }
  | { ungrouped: true }
  | 'tenant';

const VERDICT_TTL_MS = 10_000;
const VERDICT_MAX_ENTRIES = 20_000;
const verdicts = new Map<string, { at: number; ok: boolean }>();

function audienceKey(a: Exclude<EmitAudience, 'tenant'>): string {
  if ('deviceId' in a) return `device:${a.deviceId}`;
  if ('siteId' in a) return `site:${a.siteId}`;
  if ('simLineId' in a) return `line:${a.simLineId}`;
  if ('ungrouped' in a) return 'ungrouped';
  return `rollout:${a.rolloutId}`;
}

async function computeVerdict(userId: number, tenantId: number, a: Exclude<EmitAudience, 'tenant'>): Promise<boolean> {
  // Re-read the account every window: a deactivated user or a demoted admin
  // must stop receiving, whatever the socket's handshake said.
  const user = await db('users')
    .where({ id: userId })
    .first<{ is_active: boolean; role: string } | undefined>('is_active', 'role');
  if (!user || !user.is_active) return false;
  if (user.role === 'admin') return true;
  const member = await db('user_tenants').where({ user_id: userId, tenant_id: tenantId }).first('user_id');
  if (!member) return false;
  let level;
  if ('deviceId' in a) level = await getDevicePermission(userId, a.deviceId, false, tenantId);
  else if ('siteId' in a) level = await getSitePermission(userId, a.siteId, false, tenantId);
  else if ('simLineId' in a) level = await getSimLinePermission(userId, a.simLineId, false, tenantId);
  else if ('ungrouped' in a) level = await ungroupedLevel(userId, tenantId);
  else level = await getRolloutPermission(userId, a.rolloutId, false, tenantId);
  return level !== null;
}

/** Whether `userId` may read the object — cached for 10 s. Fails closed. */
export async function mayReceive(
  userId: number,
  tenantId: number,
  audience: Exclude<EmitAudience, 'tenant'>,
): Promise<boolean> {
  const key = `${userId}:${tenantId}:${audienceKey(audience)}`;
  const now = Date.now();
  const hit = verdicts.get(key);
  if (hit && now - hit.at < VERDICT_TTL_MS) return hit.ok;
  let ok = false;
  try {
    ok = await computeVerdict(userId, tenantId, audience);
  } catch (err) {
    logger.warn({ err, userId, tenantId }, 'scoped emit: verdict failed, event withheld');
    return false;
  }
  if (verdicts.size >= VERDICT_MAX_ENTRIES) {
    for (const [k, v] of verdicts) if (now - v.at >= VERDICT_TTL_MS) verdicts.delete(k);
    if (verdicts.size >= VERDICT_MAX_ENTRIES) verdicts.clear();
  }
  verdicts.set(key, { at: now, ok });
  return ok;
}

/**
 * `wan:site:presence` — the presence event. Sent to the teams that cover
 * the device (else the site, else — an unbound PPP username — the ungrouped
 * grant) AND to the device room (the detail page, which DEVICE_SUBSCRIBE
 * already judged); `wan:device:presence` carries the same payload.
 */
export function emitSitePresence(tenantId: number, event: SitePresenceEvent): void {
  const audience: EmitAudience =
    event.deviceId !== null ? { deviceId: event.deviceId }
      : event.siteId !== null ? { siteId: event.siteId }
        : { ungrouped: true };
  emitToTenantAudience(tenantId, SOCKET_EVENTS.SITE_PRESENCE, event, audience);
  if (event.deviceId !== null) {
    emitToDevice(event.deviceId, SOCKET_EVENTS.DEVICE_PRESENCE, event);
  }
}

/** Test seam: forgets every cached verdict (a harness changes a grant and re-asks). */
export function resetScopedEmitCache(): void {
  verdicts.clear();
}

/**
 * Emit `event` to the god view and to the members of `room` that may read the
 * object `audience` names. `room` / `godRoom` default to the tenant's live
 * room and the god view; the notification feed passes its own pair.
 * Returns nothing and never throws.
 */
export function emitToTenantAudience(
  tenantId: number,
  event: string,
  payload: unknown,
  audience: EmitAudience,
  room: string = socketRooms.tenant(tenantId),
  godRoom: string = socketRooms.godView(),
): void {
  const io = fleetIO();
  if (!io) return;
  if (audience === 'tenant') {
    try {
      io.to([room, godRoom]).emit(event, payload);
    } catch (err) {
      logger.warn({ err, event }, 'scoped emit failed');
    }
    return;
  }
  void (async () => {
    try {
      io.to(godRoom).emit(event, payload);
      const sockets = await io.in(room).fetchSockets();
      for (const s of sockets) {
        // Already served by the god room (a socket in both rooms receives once).
        if (s.rooms.has(godRoom)) continue;
        const userId = Number((s.data as { user?: { id?: unknown } } | undefined)?.user?.id);
        if (!Number.isInteger(userId) || userId <= 0) continue;
        if (await mayReceive(userId, tenantId, audience)) s.emit(event, payload);
      }
    } catch (err) {
      logger.warn({ err, event }, 'scoped emit failed');
    }
  })();
}
