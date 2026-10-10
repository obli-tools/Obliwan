import type { Request, Response, NextFunction } from 'express';
import { AppError } from './errorHandler';
import { db } from '../db';
import { tenantService } from '../services/tenant.service';
import { logger } from '../utils/logger';
import { applyGodViewVerdict, grantsGlobalView } from '../utils/globalView';

// Extend Express.Request to carry the resolved tenantId
declare global {
  namespace Express {
    interface Request {
      tenantId: number;
      /**
       * True only when the caller is operating on the master tenant AND is a
       * PLATFORM ADMIN (`users.role = 'admin'`, re-read from the database by
       * requireAuth). A `user_tenants` row is neither
       * necessary nor sufficient: a plain member of tenant 1 never gets it, and
       * a platform admin holds it with no row at all (admins are exempt from
       * the membership row, and `tenantService.resolveSessionTenantId()` puts a
       * platform admin with no membership on the master tenant). This is the
       * ONLY thing services may consult before widening a query across
       * tenants — never `isMasterTenant(req.tenantId)` on its own, which is
       * satisfied by any session that merely carries `currentTenantId = 1`.
       *
       * Decided by `grantsGlobalView()` (utils/globalView.ts), the ONE rule;
       * read through `hasGlobalView(req)` (routes) or `isGodView(tenantId)`
       * (services, through the request scope). Set back to false by
       * `enterObjectTenant()` once a god-view request has moved into the
       * tenant of the one object it addresses.
       */
      masterView: boolean;
      /**
       * True when `requireTenant` RESOLVED the tenant during this very request
       * — the session named none, or named one that has since been deleted —
       * instead of reading one the session already held. That tenant is one no
       * screen has shown yet, so a write that must only ever land in a tenant
       * the operator could have seen (the bundle import,
       * importExport.routes.ts) refuses on it.
       */
      tenantResolvedNow?: boolean;
    }
  }
}

/**
 * Short-lived membership cache, same rationale as the identity cache in
 * `auth.ts`: one indexed PK lookup per (user, tenant) per MEMBERSHIP_TTL_MS
 * rather than one per request. The TTL bounds how long a removed member keeps
 * access; it used to be the 7-day cookie lifetime.
 */
const MEMBERSHIP_TTL_MS = 10_000;
const MEMBERSHIP_CACHE_MAX = 10_000;
const membershipCache = new Map<string, { at: number; member: boolean }>();

export function invalidateMembershipCache(userId?: number): void {
  if (userId === undefined) {
    membershipCache.clear();
    return;
  }
  const prefix = userId + ':';
  for (const key of membershipCache.keys()) {
    if (key.startsWith(prefix)) membershipCache.delete(key);
  }
}

/**
 * Paths under `tenantRouter` that a PLATFORM ADMIN (`users.role = 'admin'`) may
 * reach with NO current tenant at all.
 *
 * Dropping the `?? 1` fallback was right, but it
 * locked the platform out of itself. `POST /api/users` writes no `user_tenants`
 * row, so a freshly created platform admin has no `currentTenantId`, so every
 * route under `tenantRouter` answers 403 — and `/api/users` is itself mounted
 * under `tenantRouter`, which puts the one route that would REPAIR the account
 * (`PUT /api/users/:id/tenants`) behind the very guard that rejects it. The
 * same happens to the founding admin the moment someone posts
 * `PUT /api/users/1/tenants {"assignments": []}`.
 *
 * The exemption is narrow on all three axes:
 *   - platform admins only — every route under `/users` is already behind
 *     `requireRole('admin')`, so this reaches nothing new;
 *   - account administration only — `usersController` reads and writes `users`,
 *     `user_tenants` and `tenants`, none of which is scoped by `req.tenantId`;
 *   - `req.tenantId` stays UNSET and `req.masterView` is forced to false, so a
 *     handler that does need a tenant fails closed instead of silently widening
 *     to every customer. `routes/users.routes.ts` puts `requireResolvedTenant`
 *     in front of the single handler in that file which reads `req.tenantId`
 *     (`GET /:id/teams`).
 *
 * This is NOT a fallback to tenant 1: no tenant is invented and no
 * tenant-scoped data is served. The account can inspect and fix tenant
 * assignments, then `POST /api/tenant/switch` onto a real tenant.
 *
 * Since `tenantService.resolveSessionTenantId()` puts a platform admin with no
 * membership on the master tenant, a tenantless admin session is HEALED by
 * `requireTenant` on every other path. It still reaches this escape hatch on
 * `/users` itself (which deliberately resolves nothing, as above), and this
 * hatch stays the only way in for an admin when no master tenant exists.
 */
const TENANTLESS_PLATFORM_ADMIN_PATHS: RegExp[] = [/^\/users(?:\/|$)/];

function isTenantlessAdminPath(path: string): boolean {
  return TENANTLESS_PLATFORM_ADMIN_PATHS.some((re) => re.test(path));
}

async function isMember(userId: number, tenantId: number): Promise<boolean> {
  const key = userId + ':' + tenantId;
  const hit = membershipCache.get(key);
  const now = Date.now();
  if (hit && now - hit.at < MEMBERSHIP_TTL_MS) return hit.member;

  const row = await db('user_tenants')
    .where({ user_id: userId, tenant_id: tenantId })
    .first('user_id');
  const member = !!row;
  if (membershipCache.size >= MEMBERSHIP_CACHE_MAX) membershipCache.clear();
  membershipCache.set(key, { at: now, member });
  return member;
}

/**
 * Deliberately NOT cached. It runs only for a platform admin sitting on a
 * tenant it holds no membership row for (one PK lookup), and a cache would
 * re-open, for its TTL, exactly the window it closes: a session served a
 * tenant that no longer exists.
 */
async function tenantExists(tenantId: number): Promise<boolean> {
  return !!(await db('tenants').where({ id: tenantId }).first('id'));
}

/** What `resolveCallerTenant()` decided. */
export interface CallerTenant {
  /** The tenant to operate on; null when refused, and on the platform-admin hatch. */
  tenantId: number | null;
  masterView: boolean;
  /** What the session's `currentTenantId` must hold afterwards; undefined removes it. */
  sessionTenantId: number | undefined;
  /** True when the tenant was resolved here rather than read from the session. */
  resolvedNow: boolean;
  /** The 403 message when the caller is refused; null when it is let through. */
  refusal: string | null;
}

function refused(refusal: string): CallerTenant {
  return { tenantId: null, masterView: false, sessionTenantId: undefined, resolvedNow: false, refusal };
}

function granted(tenantId: number, isPlatformAdmin: boolean, resolvedNow: boolean): CallerTenant {
  return {
    tenantId,
    // The god view is a property of the CALLER, established here, never of
    // the number sitting in the session.
    //
    // A plain `member` row on the master tenant used to be
    // enough. Tenant 1 is the one migration 001 creates under the name
    // "Default": it is where every "for now" account is parked and the only
    // tenant that exists before the first customer is created, so
    // `POST /api/tenants/1/members {userId, role:'member'}` — an ordinary
    // gesture in the UI — handed a non-admin a read across every customer's
    // group tree. The god view is a PLATFORM property and now requires
    // `users.role = 'admin'`, which requireAuth re-reads from the database on
    // every request. Master-tenant membership alone grants nothing beyond the
    // master tenant's own data.
    masterView: grantsGlobalView(tenantId, isPlatformAdmin),
    sessionTenantId: tenantId,
    resolvedNow,
    refusal: null,
  };
}

/**
 * THE tenant gate, written once and applied by both doors into tenant-scoped
 * data: `requireTenant` (every HTTP route) and the Socket.io handshake guard
 * (socket.ts). It reads nothing from a request and writes nothing: the caller
 * applies `sessionTenantId` to the session when it has a response to save it
 * with (HTTP), and deliberately does not when it has none (a handshake).
 *
 * Two security fixes land here.
 *
 * The session no longer falls back to tenant 1 for anyone who
 * is not a platform admin: such a user with no current tenant is refused, here
 * and on every request, even when it holds a membership (`/api/auth/me` is
 * what repairs a non-admin's session from its memberships). The status is 403
 * ("no tenant granted"), not the previous 400: this is an authorisation
 * outcome, and a 400 invites the client to retry with a different body, which
 * cannot help.
 *
 * The one exception is a PLATFORM ADMIN with no live current tenant — none
 * named, or one that has since been deleted. `DELETE /api/tenants/:id` touches
 * nobody's session, and an admin is exempt from the membership row whose
 * cascade would otherwise have refused it below, so such a session used to go
 * on pointing at nothing: every list empty and every write failing on a
 * foreign key, the very state already closed on `POST /api/tenant/switch`. Its
 * tenant is resolved through `tenantService.resolveSessionTenantId()` — the
 * same rule every login path applies, which re-reads `users.role` and
 * `is_active` from the database ITSELF, so a demotion requireAuth's identity
 * cache has not seen yet is still not trusted — and it then takes EXACTLY the
 * path a named tenant takes. That is safe because platform admins are already
 * exempt from the membership row, and `masterView` already requires
 * `users.role = 'admin'`: the exception hands an admin nothing that
 * `POST /api/tenant/switch` would not. Resolving it per request, rather than
 * only at login, is what repairs a session opened before that rule existed
 * without asking for a re-login.
 *
 * Membership is RE-VERIFIED here instead of being trusted from
 * the session. `DELETE /api/tenants/:id/members/:uid` and
 * `PUT /api/users/:id/tenants` used to leave every live session of the removed
 * user reading that tenant's data until the cookie expired.
 */
export async function resolveCallerTenant(args: {
  userId: number;
  /**
   * `users.role === 'admin'` as the database last said it: requireAuth's
   * refreshed session role on HTTP, the row just read on a handshake.
   */
  isPlatformAdmin: boolean;
  sessionTenantId: number | undefined;
  /** The platform-admin hatch applies — an HTTP path under TENANTLESS_PLATFORM_ADMIN_PATHS. */
  tenantlessAdminPath: boolean;
}): Promise<CallerTenant> {
  const { userId, isPlatformAdmin, tenantlessAdminPath } = args;
  // Platform admins (`users.role = 'admin'`) have implicit access to every
  // tenant: that is what `POST /api/tenant/switch` and the Obligate cross-app
  // handoff already rely on, and what `requireRole('admin')` grants them
  // everywhere else. They are exempt from the membership row, NOT from the
  // tenant being named — nor from it existing.
  let tid = args.sessionTenantId;
  const member = tid ? await isMember(userId, tid) : false;
  if (tid && !member && isPlatformAdmin && !(await tenantExists(tid))) {
    logger.info({ userId, tenantId: tid }, 'Platform admin session named a tenant that no longer exists');
    tid = undefined;
  }

  if (tid) {
    if (!member && !isPlatformAdmin) {
      // The session names a tenant the user no longer belongs to. The caller
      // drops the stale value (`sessionTenantId: undefined`) so the next
      // /api/auth/me re-resolves a legitimate one instead of looping on a
      // tenant that will never come back.
      return refused('No access to the selected tenant');
    }
    return granted(tid, isPlatformAdmin, false);
  }

  // Platform-admin escape hatch — see TENANTLESS_PLATFORM_ADMIN_PATHS above. No tenant is
  // resolved: `req.tenantId` stays undefined and the god view stays off.
  if (isPlatformAdmin && tenantlessAdminPath) {
    return { tenantId: null, masterView: false, sessionTenantId: undefined, resolvedNow: false, refusal: null };
  }
  // A non-admin with no current tenant is refused, full stop.
  if (!isPlatformAdmin) return refused('No tenant granted for this account');

  // A platform admin with no live tenant: the one rule (first membership, else
  // the master tenant if it exists, role re-read from the database), then the
  // same verdict a session naming that tenant itself gets. No membership check
  // follows because this branch is admins only, and admins are exempt from it.
  const resolved = await tenantService.resolveSessionTenantId(userId);
  if (resolved === null) return refused('No tenant granted for this account');
  logger.info({ userId, tenantId: resolved }, 'Platform admin session had no live tenant, resolved one');
  return granted(resolved, isPlatformAdmin, true);
}

/**
 * The SOFT form of `requireTenant`, for the cross-tenant surfaces that serve a
 * caller with no current tenant an empty answer instead of a 403 (the live
 * alert bell, `GET /api/live-alerts/all`): the same `resolveCallerTenant()`
 * verdict, carried onto the request when it grants a tenant — `req.tenantId`,
 * `req.masterView`, the god-view header — and NOTHING otherwise (no refusal,
 * no session write). A handler behind it must treat `req.tenantId` as
 * optional; `hasGlobalView(req)` is false unless the verdict granted it.
 */
export function attachTenantIfGranted(req: Request, res: Response, next: NextFunction): void {
  const userId = req.session?.userId;
  if (!userId) {
    next();
    return;
  }
  resolveCallerTenant({
    userId,
    isPlatformAdmin: req.session.role === 'admin',
    sessionTenantId: req.session.currentTenantId,
    tenantlessAdminPath: false,
  })
    .then((verdict) => {
      if (verdict.refusal === null && verdict.tenantId !== null) {
        req.tenantId = verdict.tenantId;
        req.masterView = verdict.masterView;
        applyGodViewVerdict(req, res);
      } else {
        req.masterView = false;
      }
      next();
    })
    .catch(next);
}

/**
 * Resolves `req.tenantId` from the session. Applied after `requireAuth` on
 * every route that touches tenant-scoped data. The rules are
 * `resolveCallerTenant()`'s; this only carries its verdict onto the request
 * and the session.
 */
export function requireTenant(req: Request, res: Response, next: NextFunction): void {
  const userId = req.session?.userId;
  if (!userId) {
    next(new AppError(401, 'Authentication required'));
    return;
  }

  resolveCallerTenant({
    userId,
    // Re-read from the database by requireAuth (10 s identity cache).
    isPlatformAdmin: req.session.role === 'admin',
    sessionTenantId: req.session.currentTenantId,
    tenantlessAdminPath: isTenantlessAdminPath(req.path),
  })
    .then((verdict) => {
      if (verdict.sessionTenantId === undefined) delete req.session.currentTenantId;
      else req.session.currentTenantId = verdict.sessionTenantId;

      if (verdict.refusal !== null) {
        next(new AppError(403, verdict.refusal));
        return;
      }
      if (verdict.tenantId !== null) req.tenantId = verdict.tenantId;
      req.masterView = verdict.masterView;
      req.tenantResolvedNow = verdict.resolvedNow;
      // The god-view tenant filter (captured before validate() strips it) and
      // the response header the client reads to show the tenant column.
      applyGodViewVerdict(req, res);
      next();
    })
    .catch(next);
}
