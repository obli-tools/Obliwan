import type { Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { DEVICE_FAMILIES, MASTER_TENANT_ID } from '@obliwan/shared';
import { logger } from '../utils/logger';
import { NO_CONTROL_CHARACTERS } from '../services/bench/stations.service';
import { assertApprovedBenchStation, type BenchStationContext } from './benchStation';

/**
 * ObliWAN — bench enrolment: what an APPROVED WORKSTATION may file.
 *
 * ┌─ THIS FILE USED TO DEFEND AN ANONYMOUS ROUTE THAT NO CALL EVER REACHED ──┐
 * │ It argued that `POST /devices/enroll` could take no session and no token: │
 * │ the row it creates is inert, and a human approves every device. That     │
 * │ argument was never exercised by a single request. The route was mounted  │
 * │ under `tenantRouter`, whose `requireAuth` answered 401 to every bench     │
 * │ before the anonymous middleware ran — bench enrolment has never worked.   │
 * │                                                                          │
 * │ Making it reachable forced the decision for real, and it went the other  │
 * │ way, for two reasons the old header did not weigh:                       │
 * │  - "Inert" described today's payload only. Phase B makes this the door   │
 * │    through which a bench gets a customer's configuration rendered and    │
 * │    the concentrator's L2TP account created. An anonymous door does not   │
 * │    stay harmless when what stands behind it grows.                       │
 * │  - The design counts two unauthenticated ingestion paths and asks that a  │
 * │    third be an explicit decision. Those two exist because a UDP datagram │
 * │    carries no identity and the bridge NATs its source. An HTTP call      │
 * │    can carry one, so this route had no such excuse.                      │
 * │                                                                          │
 * │ The old objection to a token — a credential at rest on a shared desk,    │
 * │ to be provisioned, rotated and revoked — is answered by the token's      │
 * │ shape rather than waved away: ONE token PER WORKSTATION, drawn by the    │
 * │ workstation, stored here only as a sha256, approved once by a platform   │
 * │ administrator, and revocable on its own, effective on its next request.  │
 * │ See `middleware/benchStation.ts` and `services/bench/stations.service`.  │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ── WHAT AN APPROVED STATION CAN DO HERE ────────────────────────────────────
 * Create ONE row that is still inert in every direction. The station approval
 * is a gate IN FRONT of the device quarantine, never a replacement for it:
 *
 *   status `pending`     — confirmed by nobody yet: SNMP auto-provisioning skips
 *                          it, and approving it is a separate human act.
 *                          The status alone refuses no write: `enqueueChangeJob`
 *                          refuses `disabled` and `quarantined`, not `pending`.
 *   `is_managed` false   — what DOES refuse a write job or a rollout against it:
 *                          `enqueueChangeJob` with `device_not_managed`, a
 *                          rollout with `device_not_writable`. The column
 *                          exists for this.
 *   no transport row     — nothing to dial even if something tried, and
 *                          `assertTargetBinding` refuses for want of one.
 *   no credential        — the factory password never leaves the workstation,
 *                          which is why this route never needed CREDENTIAL_MANAGE.
 *   master tenant        — filed nowhere, owned by nobody, until a human binds it.
 *   `enrolled_by_station_id` — WHICH desk filed it, in a column no operator
 *                          edits, so a revoked station's rows are one query away.
 *
 * ── WHAT IT CANNOT DO ───────────────────────────────────────────────────────
 * Read anything. There is no GET here. It cannot enumerate the fleet, cannot
 * learn a tenant's name, cannot reach the vault, and its response carries only
 * the id of the row it just made. An enrolment that collides with an existing
 * serial on `devices_brand_serial_uniq` gets one of two answers. If the row is
 * this station's own enrolment, still pending, the bench is retrying after a
 * lost response and gets that row's id back (`judgeEnrolmentRetry`). Otherwise
 * it is refused, and the refusal never says whose device it collided with.
 */

/**
 * Deliberately tighter than `apiLimiter`. A preparation bench does perhaps
 * forty routers in a day and each one is one call; a hundred per hour is two
 * orders of magnitude of headroom for the honest use and a hard ceiling on a
 * station whose token has been lifted.
 *
 * Keyed on the STATION, not the address — which is why it runs AFTER
 * `requireApprovedBenchStation`. Keyed on the address it was, behind the Docker
 * bridge, one GLOBAL bucket: every desk on the site shared a hundred calls
 * an hour, and one misbehaving bench could lock out all the others. A token
 * names the desk, so the budget can follow the desk. Unauthenticated calls never
 * reach this limiter; `apiLimiter` already bounds those per address.
 */
export const benchEnrolmentLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 100,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  keyGenerator: (req: Request) =>
    req.benchStation ? `bench-station:${req.benchStation.id}` : `bench-ip:${req.ip ?? 'unknown'}`,
  message: {
    success: false,
    error:
      'Too many enrolments from this workstation. A workbench does not enrol a hundred routers an '
      + 'hour; if yours does, raise the limit deliberately rather than retrying the enrolment.',
  },
});

/**
 * Trim, then judge — the `Number(' ')` trap in its string form: a
 * serial of three spaces is ABSENT, not present. Without the trim it would pass
 * "serial or system identity" below and be stored as an identity that no box
 * will ever report, so `assertTargetBinding` would refuse the device forever.
 */
const reportedText = (max: number) =>
  z.preprocess(
    (v) => {
      if (typeof v !== 'string') return v;
      const t = v.trim();
      return t === '' ? null : t;
    },
    z
      .string()
      .max(max)
      .regex(NO_CONTROL_CHARACTERS, 'control characters are not allowed')
      .nullable()
      .optional(),
  );

/**
 * The enrolment payload, as `bench/enroll.ts` (`EnrolmentRequest`) sends it.
 * Unknown keys are STRIPPED, not refused: a `status`, a `tenantId` or an
 * `isManaged` in the payload is not an attack worth a 400, it is simply never
 * read — the handler sets all three itself.
 *
 * The widths are the `devices` columns' (migration 002). A longer value would
 * otherwise reach PostgreSQL and come back as a 500.
 */
export const benchEnrolmentSchema = z
  .object({
    identity: z.object({
      family: z.enum(DEVICE_FAMILIES),
      // Accepted and IGNORED. `brand` is derived from `family` by the device
      // service and never taken from a caller: a (brand, family) pair that
      // disagreed would send every later driver lookup to the wrong dialect.
      brand: z.string().max(64).nullable().optional(),
      model: reportedText(128),
      osVersion: reportedText(64),
      serial: reportedText(128),
      systemIdentity: reportedText(128),
    }),
    /** A SUGGESTION, recorded as text and never applied. */
    proposedTenantId: z.number().int().positive().nullable().optional(),
    note: reportedText(500),
    /** What the workstation calls itself. Recorded beside the AUTHENTICATED
     *  station name, never instead of it. */
    preparedBy: reportedText(255),
    preparedAt: z.string().datetime({ offset: true }).nullable().optional(),
  })
  .superRefine((body, ctx) => {
    if (!body.identity.serial && !body.identity.systemIdentity) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['identity'],
        message:
          'The device reported neither a serial number nor a system identity. It cannot be '
          + 'recognised on a later connection, so it is not enrolled. Read the identity '
          + 'again on the bench, then retry the enrolment.',
      });
    }
  });
export type BenchEnrolmentInput = z.infer<typeof benchEnrolmentSchema>;

/**
 * No session — and a tenant all the same, because every write in this codebase
 * is tenant-scoped and a route that left `req.tenantId` undefined would fail
 * deep inside knex with "Undefined binding(s) detected" instead of here, where
 * the reason is visible.
 *
 * MASTER_TENANT_ID means "not filed yet", which is the truthful answer: the
 * preparer's `proposedTenantId` is recorded as TEXT and never applied, because
 * a suggestion that lived in a foreign key would be one migration away from
 * becoming a binding.
 *
 * Refuses unless an APPROVED station was authenticated. Any authenticated
 * station is not enough, because `requireBenchStationSelf` authenticates a
 * PENDING one. It is mounted behind `requireApprovedBenchStation`. The check
 * (`assertApprovedBenchStation`) makes a future mount fail closed here, whether
 * it forgets the guard or copies the `/me` line's guard. Without it, such a
 * mount would reopen the anonymous route this file used to describe, or open
 * one to a desk nobody approved.
 */
export function benchEnrolmentContext(req: Request, _res: Response, next: NextFunction): void {
  let station: BenchStationContext;
  try {
    station = assertApprovedBenchStation(req);
  } catch (err) {
    next(err);
    return;
  }
  req.tenantId = MASTER_TENANT_ID;
  logger.info(
    { stationId: station.id, station: station.name, ip: req.ip },
    'Bench enrolment received for quarantine — an administrator must approve the device',
  );
  next();
}
