import type { AddressHolder, LoginHolder, PlanRefusalReason } from './policy';

/**
 * The allocation module's refusals. The discriminant is `reason`, deliberately
 * NOT `code`: `errorHandler` treats any error carrying a string `code` as a pg
 * error, which is how `DriverError` once reached operators as a bare 500.
 * Messages name the site or the field, say what to change, and never carry a
 * password.
 */
export type AllocationErrorReason =
  | PlanRefusalReason
  | 'SITE_NOT_FOUND'
  | 'TENANT_NOT_FOUND'
  | 'POOL_NOT_FOUND'
  | 'NOT_ALLOCATED'
  | 'CONCENTRATOR_NOT_FOUND'
  | 'NO_POLICY'
  | 'NOT_SEEDED'
  | 'STALE_SEED'
  | 'INVALID_POLICY'
  | 'INVALID_INPUT'
  | 'INVALID_POOL'
  | 'INVALID_DOMAIN'
  | 'CONCENTRATOR_INVALID'
  | 'POLICY_CONFLICT'
  | 'POOL_OVERLAP'
  | 'POOL_NAME_TAKEN'
  | 'POOL_IN_USE'
  | 'DOMAIN_IN_USE'
  | 'DOMAIN_TOO_LONG'
  | 'ALREADY_PROVISIONED'
  | 'SHARED_PASSWORD_MISSING'
  | 'PASSWORD_UNKNOWN'
  | 'CONFLICT';

/** Nothing lands in the 401/403 band: the client logs the operator out on a
 *  401, and no refusal here says anything about the operator's session. */
const STATUS_BY_REASON: Readonly<Record<AllocationErrorReason, number>> = {
  SITE_NOT_FOUND: 404,
  TENANT_NOT_FOUND: 404,
  POOL_NOT_FOUND: 404,
  NOT_ALLOCATED: 404,
  CONCENTRATOR_NOT_FOUND: 404,

  INVALID_POLICY: 400,
  INVALID_INPUT: 400,
  INVALID_POOL: 400,
  INVALID_DOMAIN: 400,
  CONCENTRATOR_INVALID: 400,

  // Valid on its own, refused against the rest of the installation.
  POLICY_CONFLICT: 409,
  POOL_OVERLAP: 409,
  POOL_NAME_TAKEN: 409,
  POOL_IN_USE: 409,
  DOMAIN_IN_USE: 409,
  DOMAIN_TOO_LONG: 409,
  ALREADY_PROVISIONED: 409,
  NO_POLICY: 409,
  // A concentrator that could not be read just now: the installation's state,
  // not the caller's input. Retrying once the CHR answers is the remedy.
  NOT_SEEDED: 409,
  STALE_SEED: 409,
  CONFLICT: 409,

  // Per-site refusals of the engine (policy.ts): the site and the policy
  // disagree, and one of them has to change.
  SITE_CODE_NOT_NUMERIC: 409,
  LOGIN_INVALID: 409,
  INSTANCE_DOMAIN_MISSING: 409,
  INSTANCE_DOMAIN_INVALID: 409,
  LOGIN_TAKEN: 409,
  FORMULA_OUT_OF_RANGE: 409,
  FORMULA_OUT_OF_POOL: 409,
  TUNNEL_IP_TAKEN: 409,
  POOL_EXHAUSTED: 409,
  LAN_SUBNET_TAKEN: 409,
  LAN_POOL_EXHAUSTED: 409,
  IDENTITY_INVALID: 409,
  IDENTITY_TAKEN: 409,
  LAN_MANUAL_MISSING: 409,
  LAN_MANUAL_INVALID: 409,
  DERIVED_INVALID: 409,
  ADOPT_NO_ADDRESS: 409,
  ADOPT_AMBIGUOUS: 409,
  ADOPT_PROFILE_INVALID: 409,
  ADOPT_FOREIGN_POOL: 409,
  SHARED_PASSWORD_MISSING: 409,
  // An allocation adopted from a CHR in 'per_site' mode: the password is on
  // the CHR, never read, and none is invented.
  PASSWORD_UNKNOWN: 409,
};

export class AllocationError extends Error {
  constructor(
    readonly reason: AllocationErrorReason,
    message: string,
    /** Per-field validation sentences, in the shape `validate()` sends. */
    readonly details?: Record<string, string[]>,
    /** Who holds the address, block or login a refusal is about. Carries ids
     *  and CHR secret names the message deliberately leaves out for another
     *  tenant's holder; a caller that relays errors to tenant users must not
     *  forward it. */
    readonly holder?: AddressHolder | LoginHolder,
  ) {
    super(message);
    this.name = 'AllocationError';
  }

  get httpStatus(): number {
    return STATUS_BY_REASON[this.reason];
  }
}

/** `max` is PG_INT_MAX for every id held in an `integer` column; a bigint id
 *  passes its own bound. */
export function assertId(value: number, what: string, max: number): void {
  if (!Number.isInteger(value) || value <= 0 || value > max) {
    throw new AllocationError('INVALID_INPUT', `${what} must be an integer from 1 to ${max}.`);
  }
}

/** A PostgreSQL error of the given SQLSTATE (node-pg puts it in `code`). */
export function isPgError(err: unknown, sqlstate: string): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: unknown }).code === sqlstate;
}
