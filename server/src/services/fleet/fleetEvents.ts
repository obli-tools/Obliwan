/**
 * ObliWAN — the `wan:*` emitter.
 *
 * A deliberately tiny module with no dependency but `@obliwan/shared` and the
 * logger. `socket.ts` pushes the live `io` in at boot; every fleet service
 * imports THIS, never `socket.ts`. Importing `socket.ts` from a service would
 * close a require cycle (app -> routes -> controller -> service -> socket ->
 * app) and, under CommonJS, hand somebody a half-initialised module.
 *
 * Emitting is best-effort by construction: on a `worker` replica there is no
 * `io` at all, and presence must keep writing history whether or not anyone is
 * watching. A missing socket server is therefore a no-op, never an error.
 */

import type { Server as SocketIOServer } from 'socket.io';
import { socketRooms } from '@obliwan/shared';
import { logger } from '../../utils/logger';

let io: SocketIOServer | null = null;

/** Called once from `socket.ts` after the Socket.io server is created. */
export function setFleetIO(server: SocketIOServer | null): void {
  io = server;
}

export function hasFleetIO(): boolean {
  return io !== null;
}

/** The live server (null on a worker replica), for `scopedEmit`, which fans out per user. */
export function fleetIO(): SocketIOServer | null {
  return io;
}

/**
 * Emit to everyone currently looking at this tenant — AND to the master
 * tenant's god view (`socketRooms.godView()`, joined only by a platform admin
 * positioned on the master tenant, socket.ts). One `to([...])` call: a socket
 * in both rooms receives the event once.
 */
export function emitToTenant(tenantId: number, event: string, payload: unknown): void {
  if (!io) return;
  try {
    io.to([socketRooms.tenant(tenantId), socketRooms.godView()]).emit(event, payload);
  } catch (err) {
    logger.warn({ err, event }, 'wan:* emit failed');
  }
}

/**
 * `emitToTenant` reaches EVERY member of the tenant: use it only for a payload
 * that names no equipment (kill switch, weather incidents, a deleted id).
 * Anything about a device, site, SIM line or rollout goes through
 * `scopedEmit.emitToTenantAudience`, which only reaches the teams that cover it.
 */

/** Emit to the subscribers of one device detail page. */
export function emitToDevice(deviceId: number, event: string, payload: unknown): void {
  if (!io) return;
  try {
    io.to(socketRooms.device(deviceId)).emit(event, payload);
  } catch (err) {
    logger.warn({ err, event }, 'wan:* device emit failed');
  }
}

/**
 * Discoveries carry NO tenant of their own (migration 002: quarantine is
 * pre-tenant, by design), so they must not go to a tenant-wide room:
 * a PPP username seen on a concentrator is not something every member of the
 * tenant is entitled to review.
 *
 * They do, however, have a tenant: the CONCENTRATOR's. That is the same
 * scoping the discoveries controller uses for its HTTP reads, and it is the
 * one this emitter uses. The global `role:admin` room this function used to
 * target was tenant-blind — it delivered one customer's PPP usernames to any
 * platform admin, whatever tenant they were positioned on. It no longer
 * exists; `tenant:{id}:admin` replaces it everywhere.
 */
export function emitToTenantAdmins(tenantId: number, event: string, payload: unknown): void {
  if (!io) return;
  try {
    // The god view's sockets are platform admins by construction.
    io.to([`tenant:${tenantId}:admin`, socketRooms.godView()]).emit(event, payload);
  } catch (err) {
    logger.warn({ err, event }, 'wan:* admin emit failed');
  }
}

// `emitSitePresence` lives in scopedEmit.ts: it fans out per team, and this
// module must stay free of the services that compute a team verdict.
