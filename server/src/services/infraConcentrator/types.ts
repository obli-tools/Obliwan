/**
 * ObliWAN — infrastructure concentrators: the driver contract.
 *
 * One driver per concentrator kind (`routeros_chr`, `opnsense`). Every method
 * answers in FRENCH for the operator, with a closed code beside the sentence,
 * and never carries a credential. Reads (test, read, plan) dial the
 * concentrator directly; the two WRITES (apply, revoke) are only ever called
 * from inside an `infra_account` change job, with the job's context.
 */

import type {
  InfraAccountAction,
  InfraAccountOutcome,
  InfraConcentratorKind,
  InfraConcentratorParams,
  InfraDriverResult,
  InfraPlanView,
} from '@obliwan/shared';

/** A row of `infra_concentrators` (074), as the drivers read it. */
export interface InfraConcentratorRow {
  id: number;
  tenant_id: number;
  kind: InfraConcentratorKind;
  name: string;
  host: string;
  port: number | null;
  device_id: number | null;
  enabled: boolean;
  params: InfraConcentratorParams;
  api_key_enc: string | null;
  api_secret_enc: string | null;
  key_version: number | null;
  tls_fingerprint_sha256: string | null;
  last_test_at: Date | string | null;
  last_test_ok: boolean | null;
  last_test_message: string | null;
  created_at: Date | string;
  updated_at: Date | string;
}

/** A refusal or a failure of this subsystem. `httpStatus` is what the API
 *  answers with; `code` is closed and machine-readable; `message` is French. */
export class InfraConcentratorError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly httpStatus = 400,
    /** Set when the concentrator was READ and the account found wrong. */
    readonly outcome: 'conflict' | null = null,
  ) {
    super(message);
    this.name = 'InfraConcentratorError';
  }
}

/** The code every not-yet-built OPNsense operation refuses with. */
export const NOT_IMPLEMENTED_YET = 'NOT_IMPLEMENTED_YET';

/** Which site, on which concentrator. */
export interface InfraSiteRef {
  tenantId: number;
  siteId: number;
}

/** The audit context of a call: a job's, or none for a read outside one. */
export interface InfraExecContext {
  /** The tenant the commands are audited in (the job's, i.e. the device's). */
  auditTenantId: number;
  jobId: number | null;
  correlationId: string;
  /** The device the commands are audited against (the CHR's devices row). */
  device: { id: number; uuid?: string | null; name?: string | null };
  /** Called immediately before the first byte that changes the concentrator. */
  onWrite?: () => void;
}

/** What one job step produced. `output` is French and lands in the step row. */
export interface InfraStepResult {
  output: string;
  detail: Record<string, unknown>;
  outcome?: InfraAccountOutcome;
}

/** The frozen, NON-SECRET attributes of one `infra_account` job (074). */
export interface InfraJobSpec {
  jobId: number;
  tenantId: number;
  siteId: number;
  concentratorId: number;
  action: InfraAccountAction;
  identifier: string;
  remoteAddress: string | null;
  pppProfile: string | null;
  comment: string;
  outcome: InfraAccountOutcome | null;
}

export interface InfraConcentratorDriver {
  readonly kind: InfraConcentratorKind;
  /** false = plan/apply/revoke refuse with NOT_IMPLEMENTED_YET, and the queue
   *  refuses to enqueue a job for this kind. */
  readonly writesImplemented: boolean;
  testConnection(c: InfraConcentratorRow): Promise<InfraDriverResult & { fingerprint?: string | null }>;
  /** Read this site's entry on the concentrator (never a password). */
  readSiteEntry(c: InfraConcentratorRow, site: InfraSiteRef): Promise<InfraPlanView>;
  /** Desired against read, nothing written. */
  plan(c: InfraConcentratorRow, site: InfraSiteRef, action: InfraAccountAction): Promise<InfraPlanView>;
  /** Job step: create (or find) the account. */
  apply(c: InfraConcentratorRow, job: InfraJobSpec, ctx: InfraExecContext): Promise<InfraStepResult>;
  /** Job step: remove the account (only one ObliWAN itself created). */
  revoke(c: InfraConcentratorRow, job: InfraJobSpec, ctx: InfraExecContext): Promise<InfraStepResult>;
  /** Job step: read back what apply/revoke left. */
  verify(c: InfraConcentratorRow, job: InfraJobSpec, ctx: InfraExecContext): Promise<InfraStepResult>;
}
