import type { Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import { AppError } from './errorHandler';
import { logger } from '../utils/logger';
import {
  findStationByTokenHash,
  parseBenchAuthorization,
  stationAccessVerdict,
  stationVerificationCode,
  touchStation,
  type BenchAuthorization,
  type BenchStationRow,
  type BenchStationStatus,
  type StationRefusalReason,
  type StationScope,
} from '../services/bench/stations.service';

/**
 * ObliWAN — the bench workstation guard.
 *
 * ┌─ NOT A SESSION, AND NEVER MIXED WITH ONE ────────────────────────────────┐
 * │ `Authorization: Bench <token>` is checked here and nowhere else. It does  │
 * │ not set `req.session`, a tenant, a role or a capability, so every route   │
 * │ guarded by `requireAuth` / `requireCapability` stays closed to a bench    │
 * │ token by construction — a token found on a shared preparation desk opens │
 * │ the routes that name this guard, and only those.                          │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Every request re-reads the station row: no cache. Revocation is therefore
 * effective on the very next call, which is the property an administrator
 * revoking a leaked token is counting on. The volume — a few desks, a few dozen
 * routers a day — makes a cache a saving of nothing bought with a delay on the
 * one control that has to be immediate.
 */

/** What a guarded handler knows about its caller. Name included because every
 *  provenance line a handler writes should say WHICH desk did it. `status` is
 *  always `approved` behind `requireApprovedBenchStation`; only the `self`
 *  guard ever lets a `pending` one through. `verificationCode` is what the
 *  bench displays so the approving administrator can tell it from an impostor
 *  (`stationVerificationCode`). */
export interface BenchStationContext {
  id: number;
  name: string;
  status: BenchStationStatus;
  verificationCode: string | null;
}

declare global {
  namespace Express {
    interface Request {
      /** Set by BOTH station guards: `requireApprovedBenchStation` (approved
       *  only) and `requireBenchStationSelf` (pending too, by design). So its
       *  presence proves a registered, unrevoked station, NOT an approved one.
       *  Code that acts on the platform's behalf calls
       *  `assertApprovedBenchStation(req)` and never tests
       *  `if (req.benchStation)`. Absent on every route neither guard is on. A
       *  handler that reads it there reads `undefined`, never somebody else's
       *  station. */
      benchStation?: BenchStationContext;
    }
  }
}

/** The 401 messages. They name the mistake and the operation that fixes it, and
 *  never repeat the header back — a log of refusals must not become a log of
 *  tokens. */
export function benchAuthFailureMessage(kind: Exclude<BenchAuthorization['kind'], 'token'>): string {
  switch (kind) {
    case 'missing':
      return 'This route is for an approved bench workstation: send "Authorization: Bench <token>". '
        + 'Register the workstation first (POST /api/bench/stations/register).';
    case 'wrong_scheme':
      return 'Wrong authorization scheme: this route accepts "Bench <token>" only, not an operator '
        + 'session or a Bearer token.';
    case 'malformed':
      return 'The bench token is malformed: it must be one hexadecimal token of at least 64 '
        + 'characters. Re-register the workstation with a freshly generated token.';
  }
}

/** The 401/403 messages for a token that parsed. */
export function benchStationRefusalMessage(reason: StationRefusalReason): string {
  switch (reason) {
    case 'unknown':
      return 'This bench token belongs to no registered workstation. Register the workstation '
        + '(POST /api/bench/stations/register), then wait for an administrator to approve it.';
    case 'pending':
      return 'This bench workstation is registered but not approved yet. An administrator must '
        + 'approve it on the bench workstations page; retry once it is approved.';
    case 'revoked':
      return 'This bench workstation has been revoked. Register it again with a new token and '
        + 'ask an administrator to approve the new entry.';
    case 'invalid_status':
      return 'This bench workstation is in a state that does not allow this operation. Ask an '
        + 'administrator to check it on the bench workstations page.';
  }
}

export interface BenchStationGuardDeps {
  findByTokenHash: (
    tokenHash: string,
  ) => Promise<Pick<BenchStationRow, 'id' | 'uuid' | 'name' | 'status'> | null>;
  touch: (id: number, ip: unknown) => Promise<void>;
}

/**
 * Build the guard. Factored over its two database calls so the verdicts —
 * which status gets through, which status code each refusal carries — can be
 * exercised without a database (`services/bench/testing/stations.verify.ts`).
 */
export function createBenchStationGuard(deps: BenchStationGuardDeps, scope: StationScope = 'act') {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const auth = parseBenchAuthorization(req.headers.authorization);
      if (auth.kind !== 'token') {
        res.setHeader('WWW-Authenticate', 'Bench');
        next(new AppError(401, benchAuthFailureMessage(auth.kind)));
        return;
      }

      const station = await deps.findByTokenHash(auth.tokenHash);
      if (!station) {
        res.setHeader('WWW-Authenticate', 'Bench');
        next(new AppError(401, benchStationRefusalMessage('unknown')));
        return;
      }

      // Observed whatever the verdict below — see `touchStation`. Not awaited
      // into the verdict: it never throws, and it must never delay one.
      void deps.touch(station.id, req.ip);

      const verdict = stationAccessVerdict(station.status, scope);
      if (!verdict.allow) {
        logger.warn(
          // `stationName`, never `name`: pino reads `name` as the LOGGER's name.
          { stationId: station.id, stationName: station.name, reason: verdict.reason, ip: req.ip, path: req.path },
          'Bench workstation refused',
        );
        next(new AppError(verdict.httpStatus, benchStationRefusalMessage(verdict.reason)));
        return;
      }

      // `allow` is only ever true on a status from the vocabulary, so the cast
      // is the verdict's guarantee restated, not a guess.
      req.benchStation = {
        id: station.id,
        name: station.name,
        status: station.status as BenchStationStatus,
        verificationCode: stationVerificationCode(station.uuid),
      };
      next();
    } catch (err) {
      next(err);
    }
  };
}

/**
 * The APPROVED station behind this request, or the refusal as an `AppError`.
 *
 * A non-empty `req.benchStation` is not enough. `requireBenchStationSelf` sets
 * it for a PENDING station, because that is its job. A route that acts and is
 * mounted behind the wrong guard would then let a station nobody approved act,
 * and its provenance note would still say "approved". So every handler or
 * middleware that acts calls this rather than testing the field. It asks the
 * same verdict function the guard asks, at the `act` scope. The rule exists
 * once and is not spelled a second time here.
 */
export function assertApprovedBenchStation(req: Request): BenchStationContext {
  const station = req.benchStation;
  if (!station) throw new AppError(401, benchAuthFailureMessage('missing'));
  const verdict = stationAccessVerdict(station.status, 'act');
  if (!verdict.allow) throw new AppError(verdict.httpStatus, benchStationRefusalMessage(verdict.reason));
  return station;
}

/**
 * The guard for every route a bench uses to ACT: approved stations only.
 * Pending and revoked stations get a 403 that says which, unknown tokens a 401.
 */
export const requireApprovedBenchStation = createBenchStationGuard({
  findByTokenHash: findStationByTokenHash,
  touch: touchStation,
});

/**
 * The guard for a station asking about ITSELF (`GET /api/bench/stations/me`):
 * pending gets through too, or a bench could never learn it has been approved.
 * Revoked is still a 403. Never put this one on a route that acts.
 */
export const requireBenchStationSelf = createBenchStationGuard(
  { findByTokenHash: findStationByTokenHash, touch: touchStation },
  'self',
);

/**
 * `POST /api/bench/stations/register` is public — a workstation has nothing to
 * authenticate with before it has registered — so this limit is its control. A
 * site installs a handful of desks, ever; twenty registrations an hour from one
 * address is generous to that and stingy to a script.
 *
 * Keyed on the source address, which the bridge-NAT constraint warns is the Docker bridge gateway in a
 * NATed deployment — there it is a GLOBAL limit. Said rather than assumed, same
 * as `benchEnrolmentLimiter`. Behind it, `MAX_PENDING_STATIONS` caps what
 * patience alone can pile onto the approval screen.
 */
export const benchStationRegisterLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: {
    success: false,
    error:
      'Too many workstation registrations from this address. Registration is a once-per-desk '
      + 'gesture; retry the registration in an hour, or ask an administrator.',
  },
});
