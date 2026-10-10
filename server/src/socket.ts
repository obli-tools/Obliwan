import { Server as SocketIOServer } from 'socket.io';
import type { Server as HttpServer } from 'http';
import type { Request, Response, NextFunction } from 'express';
import cookieParser from 'cookie-parser';
import { CLIENT_EVENTS, socketRooms } from '@obliwan/shared';
import { sessionMiddleware } from './app';
import { config } from './config';
import { logger } from './utils/logger';
import { authService } from './services/auth.service';
import { tenantService } from './services/tenant.service';
import { resolveCallerTenant } from './middleware/tenant';
import { db } from './db';
import { setFleetIO } from './services/fleet/fleetEvents';
import { runInRequestScope } from './utils/globalView';
import { getDevicePermission } from './services/teamScope.service';

/**
 * Adapts an Express middleware to Socket.io's `io.use()` signature.
 *
 * The handshake is a real HTTP request, so express-session can read its cookie,
 * look the session up in Postgres and hang `req.session` on it exactly as it
 * would for `/api/...`. Socket.io only ever gives us `socket.request`, hence the
 * casts — they are shape assertions, not a bypass of anything.
 */
function wrap(mw: (req: Request, res: Response, next: NextFunction) => void) {
  return (socket: { request: unknown }, next: (err?: Error) => void): void => {
    mw(socket.request as Request, {} as Response, next as NextFunction);
  };
}

export function createSocketServer(httpServer: HttpServer): SocketIOServer {
  const io = new SocketIOServer(httpServer, {
    cors: {
      // Reflect the request origin so any deployment URL works without
      // reconfiguring CLIENT_ORIGIN. Authorisation is enforced by the session
      // middleware below, never by the CORS origin list.
      origin: true,
      credentials: true,
    },
    transports: ['websocket', 'polling'],
  });

  // Obliguard authenticated sockets from `handshake.auth.userId`,
  // a value the CLIENT chooses. Anyone who could open a WebSocket could claim
  // to be user 1 and join the admin rooms. We now run the SAME session
  // middleware the HTTP API uses and take the identity from the server-side
  // session, so a socket can only ever be as privileged as the cookie it
  // carries. `handshake.auth` is no longer read for identity at all.
  io.use(wrap(cookieParser()));
  io.use(wrap(sessionMiddleware as unknown as (req: Request, res: Response, next: NextFunction) => void));

  io.use(async (socket, next) => {
    try {
      const session = (socket.request as Request).session;
      const userId = session?.userId;

      if (!userId) {
        next(new Error('Authentication required'));
        return;
      }

      const user = await authService.getUserById(userId);
      if (!user || !user.isActive) {
        next(new Error('Invalid user'));
        return;
      }

      // The tenant is taken from the session too. A client that wants to switch
      // tenant does it through POST /api/tenant (which re-writes the session)
      // and then reconnects — it cannot pick a tenant from the handshake.
      //
      // SECURITY — there used to be a `?? 1` here. It was declared "dead" on the
      // grounds that a session without `currentTenantId` would fail the
      // membership check; it did not, because that check exempts platform
      // admins. A platform admin with NO `user_tenants` row therefore landed in
      // tenant 1 and joined its rooms while every HTTP route answered 403 — the
      // socket and the API disagreeing about who may see what.
      //
      // The handshake now runs THE SAME gate as every HTTP route,
      // `resolveCallerTenant()` (middleware/tenant.ts), not a second copy of it:
      // a non-admin with no current tenant is refused even when it holds a
      // membership (exactly as requireTenant refuses it — /api/auth/me is what
      // repairs such a session, and the client's `checkSession()` calls it
      // before opening the socket); membership is required of everyone but a
      // platform admin; and a platform admin with no live tenant is put on
      // `tenantService.resolveSessionTenantId()`'s answer — the master tenant
      // when it holds no membership. The role is the row just read above, i.e.
      // the database's. Two deliberate differences from HTTP: the `/users`
      // hatch does not exist here (a socket with no tenant has no room to join,
      // so it is refused), and the session is NOT written — a handshake has no
      // response to save it with; the next HTTP call through requireTenant
      // writes the same resolution.
      const verdict = await resolveCallerTenant({
        userId,
        isPlatformAdmin: user.role === 'admin',
        sessionTenantId: session.currentTenantId,
        tenantlessAdminPath: false,
      });
      if (verdict.refusal !== null || verdict.tenantId === null) {
        next(new Error(verdict.refusal ?? 'No tenant granted for this account'));
        return;
      }

      socket.data.user = user;
      socket.data.tenantId = verdict.tenantId;
      // The god view, from the SAME verdict as HTTP (`grantsGlobalView()` via
      // resolveCallerTenant). Also hung on the handshake request, because the
      // packets of this socket run in that request's scope (below) and the
      // services they call read the verdict from there.
      socket.data.masterView = verdict.masterView;
      const handshake = socket.request as Request;
      handshake.tenantId = verdict.tenantId;
      handshake.masterView = verdict.masterView;
      next();
    } catch (err) {
      logger.error(err, 'Socket authentication failed');
      next(new Error('Authentication failed'));
    }
  });

  io.on('connection', (socket) => {
    const user = socket.data.user;
    const tenantId: number = socket.data.tenantId;
    const godView: boolean = socket.data.masterView === true;
    logger.info(`Socket connected: ${user.username} (id: ${user.id}, tenant: ${tenantId}${godView ? ', god view' : ''})`);

    // Every incoming packet of this socket runs in the scope of its handshake
    // request (utils/globalView.ts), so a service a handler calls answers
    // `isGodView()` exactly as it would for the same session over HTTP.
    socket.use((_packet, nextPacket) => runInRequestScope(socket.request as Request, () => nextPacket()));

    // ── Room convention ───────────────────────────────────────────────────
    // Exactly three shapes exist, and every one of them names a tenant or a
    // single user:
    //
    //   tenant:{id}          every member of that tenant
    //   tenant:{id}:admin    the admins POSITIONED ON that tenant
    //   user:{id}            one account
    //
    // The global `role:admin` room is GONE. It was tenant-blind: it put every
    // platform admin in one bucket regardless of the tenant they were working
    // on, so the eight group/settings emits that targeted it delivered one
    // customer's group names and setting values to an admin sitting on
    // another customer. A broadcast room that outlives the tenant scope is a
    // cross-tenant channel by construction, whatever the emitter intended.
    //
    // `general` went with it: nothing ever emitted to it, and a room nobody
    // can name a tenant for is the next `role:admin` waiting to be reused.
    socket.join(`user:${user.id}`);
    socket.join(socketRooms.tenant(tenantId));
    if (user.role === 'admin') {
      socket.join(`tenant:${tenantId}:admin`);
    }
    // The god view: every tenant's live events and live alerts, emitted by
    // fleetEvents / liveAlert.service to these rooms as well as the tenant's.
    // A master-tenant member who is not a platform admin never joins them.
    if (godView) {
      socket.join(socketRooms.godView());
      socket.join(socketRooms.godViewNotifications());
    }

    // Notification rooms for EVERY tenant this user is placed on without a
    // switch, so a cross-tenant live alert reaches them even while they are
    // looking at another tenant: its memberships — or, for a platform admin
    // with none, the master tenant it was put on. The set is
    // `tenantService.resolveSessionTenantIds()`, the same one
    // `GET /api/live-alerts/all` lists; keyed on `user_tenants` alone, that
    // admin worked on tenant 1 and never heard a single one of its alerts.
    tenantService
      .resolveSessionTenantIds(user.id)
      .then((tenantIds: number[]) => {
        for (const tid of tenantIds) {
          socket.join(socketRooms.tenantNotifications(tid));
        }
      })
      .catch((err: unknown) => logger.error(err, 'Failed to join notification rooms'));

    // ── Per-device subscription ───────────────────────────────────────────
    // A device detail page asks for `device:{id}` so it gets presence, verdict
    // and transport-state events without every other client paying for them.
    //
    // The room name is derived from a number the CLIENT sent, so membership is
    // checked against the socket's tenant before joining — otherwise anyone
    // could subscribe to `device:1` and watch another customer's tunnel flap.
    // This is the same lesson as the handshake check: never trust the handshake, and never
    // trust an id that arrived over the wire either.
    socket.on(CLIENT_EVENTS.DEVICE_SUBSCRIBE, async (raw: unknown) => {
      const deviceId = Number(raw);
      if (!Number.isInteger(deviceId) || deviceId <= 0) return;
      try {
        // The god view subscribes to any tenant's device, as its REST detail
        // page opens any tenant's device; everyone else, to its own tenant's.
        const q = db('devices').where({ id: deviceId });
        if (!godView) void q.where({ tenant_id: tenantId });
        const owned = await q.first('id');
        if (!owned) {
          logger.warn(
            { userId: user.id, tenantId, deviceId },
            'Refused a device subscription outside the socket tenant',
          );
          return;
        }
        // Team scope (087): a tenant admin holds every capability of its role but
        // sees what its teams cover (Obliance), so the tenant check above is not
        // enough — the device must be inside the user's teams. The god view and a
        // platform admin are not narrowed.
        if (!godView && user.role !== 'admin') {
          const level = await getDevicePermission(user.id, deviceId, false, tenantId);
          if (level === null) {
            logger.warn(
              { userId: user.id, tenantId, deviceId },
              'Refused a device subscription outside the user teams',
            );
            return;
          }
        }
        socket.join(socketRooms.device(deviceId));
      } catch (err) {
        logger.error({ err, deviceId }, 'Device subscription failed');
      }
    });

    socket.on(CLIENT_EVENTS.DEVICE_UNSUBSCRIBE, (raw: unknown) => {
      const deviceId = Number(raw);
      if (!Number.isInteger(deviceId) || deviceId <= 0) return;
      socket.leave(socketRooms.device(deviceId));
    });

    socket.on('disconnect', () => {
      logger.debug(`Socket disconnected: ${user.username}`);
    });
  });

  if (!config.servesHttp) {
    logger.info({ role: config.role }, 'Socket.io created on a non-web role — no client will reach it');
  }

  // The fleet services emit `wan:*` through `services/fleet/fleetEvents`, which
  // holds nothing but this handle. They never import THIS module: doing so
  // would close a require cycle (app -> routes -> controller -> service ->
  // socket -> app) and hand somebody a half-initialised module under CommonJS.
  setFleetIO(io);

  // The fleet runtime (presence, the RouterOS pool) is NOT armed here any more.
  // It used to be, for want of write access to `index.ts`; arming a background
  // duty is a startup act and it now happens in the startup sequence, right
  // after this function returns and the `io` handle above has been published.
  return io;
}
