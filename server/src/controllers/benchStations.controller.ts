import type { Request, Response, NextFunction } from 'express';
import { AppError } from '../middleware/errorHandler';
import { logger } from '../utils/logger';
import {
  BenchStationError,
  listStations,
  registerStation,
  stationTokenHash,
  stationVerificationCode,
  transitionStation,
  type RegisterStationInput,
  type StationAction,
} from '../services/bench/stations.service';

/**
 * Bench workstations — HTTP layer.
 *
 * Two audiences, never on the same route:
 *   - the WORKSTATION, which registers itself and asks whether it has been
 *     approved (`register`, `me`), authenticated by nothing and by its own
 *     token respectively;
 *   - the platform ADMINISTRATOR, who lists, approves and revokes
 *     (`list`, `approve`, `revoke`), authenticated by a session and
 *     `requireRole('admin')` in the router.
 *
 * Stations are PLATFORM-scoped, not tenant-scoped: a preparation desk prepares
 * routers for every customer, so no tenant owns it and no tenant admin may
 * approve one. That is why the admin half is `requireRole('admin')` and not a
 * capability — `TENANT_ROLE_CAPABILITIES` hands capabilities to the admin of any
 * tenant, the same reasoning as `/sim/accounts`.
 *
 * Nothing here ever returns, logs or echoes a token or its hash.
 */

function parseId(raw: string): number {
  const id = Number.parseInt(raw, 10);
  if (!Number.isInteger(id) || id <= 0 || String(id) !== raw) {
    throw new AppError(400, 'Invalid bench workstation id');
  }
  return id;
}

function translate(err: unknown): AppError | null {
  if (!(err instanceof BenchStationError)) return null;
  switch (err.code) {
    case 'NOT_FOUND':
      return new AppError(404, err.message);
    case 'TRANSITION_REFUSED':
      return new AppError(409, err.message);
    case 'PENDING_CAP':
      return new AppError(429, err.message);
  }
}

async function decide(req: Request, res: Response, next: NextFunction, action: StationAction): Promise<void> {
  try {
    const id = parseId(req.params.id);
    const { outcome, station } = await transitionStation(id, action, req.session?.userId ?? null);
    res.json({ success: true, data: { station, outcome } });
  } catch (err) {
    next(translate(err) ?? err);
  }
}

export const benchStationsController = {
  /**
   * `POST /api/bench/stations/register` — public, rate-limited, idempotent.
   *
   * 201 when this call created the station, 200 when the token was already
   * known — in which case the answer is the station's CURRENT status, which may
   * be `approved` (a bench that lost the first answer) or `revoked` (a bench
   * that must draw a new token). Either way the bench learns what to do next
   * from `status`, not from the code.
   *
   * `verificationCode` is part of the contract, not decoration. The bench must
   * DISPLAY it, and the administrator approves the row showing the same code
   * (`stationVerificationCode` says why: a name and a hostname can be copied by
   * anybody who can reach this public route).
   */
  async register(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const body = req.body as RegisterStationInput;
      const tokenHash = stationTokenHash(body.token);
      // The schema already refused a malformed token; this is the type system
      // being told so, and a guard should the route ever lose its validator.
      if (!tokenHash) {
        throw new AppError(400, 'The token is malformed. Generate a new one and retry the registration.');
      }

      const { station, created } = await registerStation({
        name: body.name,
        hostname: body.hostname ?? null,
        tokenHash,
        ip: req.ip,
      });

      if (created) {
        logger.info(
          { stationId: station.id, stationName: station.name, hostname: station.hostname, ip: req.ip },
          'Bench workstation registered — awaiting administrator approval',
        );
      }

      res.status(created ? 201 : 200).json({
        success: true,
        data: {
          stationId: station.id,
          status: station.status,
          verificationCode: stationVerificationCode(station.uuid),
        },
      });
    } catch (err) {
      next(translate(err) ?? err);
    }
  },

  /**
   * `GET /api/bench/stations/me` — behind `requireBenchStationSelf`, which has
   * already answered 401 for an unknown token and 403 for a revoked one. What
   * reaches here is pending or approved, and both are 200: "not yet" is an
   * answer the bench waits on, not an error it reports. It repeats the
   * verification code, so a bench restarted while it waits can show it again.
   */
  async me(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const station = req.benchStation;
      if (!station) throw new AppError(401, 'Bench workstation not authenticated');
      // A bench polls this while it waits; an intermediary must not hand it a
      // stale "pending" after the approval.
      res.setHeader('Cache-Control', 'no-store');
      res.json({
        success: true,
        data: {
          stationId: station.id,
          status: station.status,
          name: station.name,
          verificationCode: station.verificationCode,
        },
      });
    } catch (err) {
      next(err);
    }
  },

  /** `GET /api/bench-stations` — pending first. */
  async list(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.json({ success: true, data: await listStations() });
    } catch (err) {
      next(err);
    }
  },

  /** `POST /api/bench-stations/:id/approve` — pending → approved; a repeat is
   *  a no-op that keeps the first approver; a revoked station is a 409. */
  async approve(req: Request, res: Response, next: NextFunction): Promise<void> {
    await decide(req, res, next, 'approve');
  },

  /** `POST /api/bench-stations/:id/revoke` — pending|approved → revoked, final.
   *  Effective on the station's next request: the guard caches nothing. */
  async revoke(req: Request, res: Response, next: NextFunction): Promise<void> {
    await decide(req, res, next, 'revoke');
  },
};
