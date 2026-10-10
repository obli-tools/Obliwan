/**
 * ObliWAN — a site's L2TP account on the concentrator, created by ObliWAN
 * through the change queue (nothing writes to a device outside
 * `change_jobs`).
 *
 *   ensureConcentratorSecret({ tenantId, siteId })   enqueue (idempotently)
 *   waitForConcentratorSecret(jobId, timeoutMs)      block until it is decided
 *   provisionConcentratorSecret(input, timeoutMs)    both, for the bench
 *
 * The job is kind `concentrator_secret`, queued on the CONCENTRATOR's device
 * row (the CHR the site's allocation was frozen against), and run by
 * `runPhases()` in apply.service.ts, which calls `applyConcentratorSecret()`
 * and `verifyConcentratorSecret()` below. Over the RouterOS API, through the
 * process-wide pool socket to the CHR:
 *
 *   1. read every `/ppp/secret`, with a `.proplist` that names no password;
 *   2. decide, purely (`decideSecretAction`):
 *        absent                                 -> ADD it;
 *        present, same remote-address, service,
 *        profile, enabled, and comment — the
 *        comment only for an allocation ObliWAN
 *        computed, never for an ADOPTED one     -> nothing to do ("present");
 *        present and different in any of those,
 *        or the name present in another case,
 *        or the address declared by another one -> REFUSE ("conflict"),
 *                                                  and touch nothing;
 *   3. read it back and verify every attribute it can see (the comment only
 *      after an add: it is the one this job wrote).
 *
 * WHEN THE COMMENT DECIDES. A site ADOPTED from the CHR (the allocator
 * recorded a deployed account as it is, services/allocation `adoptDeclared`;
 * `site_provisioning.source` 'adopted_chr') has a secret ObliWAN never wrote,
 * so it carries no `obliwan:site:` comment, or somebody else's. Its name and
 * remote-address are what the allocation recorded, i.e. it IS this site's
 * account: a no-op, state 'provisioned', whatever its comment. Requiring
 * ObliWAN's comment there would refuse every deployed site forever — and the
 * only remedy would be a `set`, which this job never sends.
 * Every OTHER allocation (source 'allocated', or NULL: a row older than 044,
 * all computed by ObliWAN) expects to write its secret itself, with a password
 * ObliWAN generated or holds. An entry with its name and address but a
 * comment ObliWAN did not write for this site was made by somebody else — by
 * hand, between the allocation and this job — and may hold another password:
 * found "present", the CPE compiled with ObliWAN's would never authenticate.
 * So for those the comment still decides, and such an entry is a conflict.
 * Either way the comment is never rewritten.
 *
 * ┌─ ADDITIVE ONLY, AND WHY THAT MEANS NO DEAD-MAN ──────────────────────────┐
 * │ The job never sends `set`, `remove`, `enable` or `disable`: the only     │
 * │ write it can produce is one `/ppp/secret/add` under a name the CHR does   │
 * │ not have. An added secret changes no route, no address, no filter and no │
 * │ live session until a peer authenticates with it, so it cannot cut a      │
 * │ management path — there is nothing for a dead-man to revert, and none is │
 * │ armed. Its undo is removing that one entry by name. The job still takes  │
 * │ the per-device lock (one job in flight on the CHR), still asserts the    │
 * │ CHR's identity on a fresh socket, still honours the kill switch —        │
 * │ the CHR tenant's AND the site tenant's — and every command it sends goes │
 * │ through `auditedCommand` first.                                          │
 * │ A secret that exists and DIFFERS is refused, never overwritten: a live   │
 * │ secret is somebody's working tunnel, and ObliWAN does not know whose.    │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE PASSWORD ───────────────────────────────────────────────────────────┐
 * │ It is in no column, no log line, no step output and no audit row. The    │
 * │ enqueue reads the allocation for its NON-secret attributes and drops the │
 * │ password at once; the worker reads it again at apply time and puts it   │
 * │ into exactly one API word, `=password=`, built last. The audited command │
 * │ text carries `password=***`; the transport's own trace masks the word by │
 * │ its name; a RouterOS refusal is scrubbed of the value before it can      │
 * │ reach an error column. It is never read back either — the `.proplist`    │
 * │ asks for no password — so "present" says nothing about the password the  │
 * │ CHR holds, and the outcome text says so.                                 │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ A FAILURE IS ANNOUNCED ONCE, AND RETRIED ONLY IF IT CAN HEAL ALONE ─────┐
 * │ `settleConcentratorSecret` raises ONE live alert per failure EPISODE, in │
 * │ the SITE's tenant, naming the site and the reason. An episode is the     │
 * │ trailing run of this site's failed jobs against the same allocation      │
 * │ with the same cause (`failureCause`: every retryable failure is one      │
 * │ cause; a refusal is its kind, refined by its message where the kind      │
 * │ alone mixes problems). Its alert is keyed on the run's FIRST job, found  │
 * │ by walking the whole run (`walkFailureEpisode`), and is not raised       │
 * │ again while it exists, read or not, so retries add jobs, not alerts.     │
 * │ `classifyConcentratorFailure` says which failures are RETRYABLE: the     │
 * │ concentrator did not answer, timed out or dropped the session (an add    │
 * │ whose answer was lost included), or the worker died. Everything else is  │
 * │ a refusal (an account that exists with other attributes, an allocation   │
 * │ that moved, the kill switch, the CHR's identity, a RouterOS `!trap`...): │
 * │ announced as needing a human, never retried. The retry is                │
 * │ concentratorSecretRetry.service.ts: leader-only, bounded, with backoff,  │
 * │ through `ensureConcentratorSecret` like any other request. When every    │
 * │ automatic attempt has failed, ONE more alert says so (`exhausted`); when │
 * │ a later job confirms the account, ONE more says that (`resolved`, and    │
 * │ the site's unread failure alerts are marked read). Across tenants (the   │
 * │ shared CHR lives in the master tenant) an alert carries the CLASS of the │
 * │ reason and its code, never the job's raw text: a conflict names other    │
 * │ sites' secrets.                                                          │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The allocation is a DEPENDENCY, injected (`setConcentratorSecretDeps`): the
 * default reads it through the allocation module's `readPppAccount` and
 * mirrors outcomes through its `recordConcentratorOutcome`, both of which that
 * module exports for this job by name.
 */

import {
  ACTIVE_CHANGE_JOB_STATUSES,
  MASTER_TENANT_ID,
  SOCKET_EVENTS,
  type ChangeJobStatus,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { auditedCommand, type CommandIntent } from '../audit.service';
import { liveAlertService } from '../liveAlert.service';
import { emitToDevice } from '../fleet/fleetEvents';
import { emitToTenantAudience } from '../fleet/scopedEmit';
import { getRouterOsPool, resolveRouterOsTarget } from '../fleet/routerosPool';
import { parseSecretRow, type PppSecretEntry } from '../fleet/concentratorDiscovery.service';
import { readPppAccount, recordConcentratorOutcome } from '../allocation';
import {
  RouterOsConnectionClosedError,
  RouterOsTimeoutError,
  RouterOsTrapError,
  type RouterOsConnection,
} from '../transport/routeros';
import type { ChangeJobRow } from './jobQueue.service';
import { assertWritable } from './killSwitch.service';

// ============================================================================
// Vocabulary
// ============================================================================

export const CONCENTRATOR_SECRET_KIND = 'concentrator_secret' as const;

/** What the job found. Mirrors `concentrator_secret_jobs_outcome_chk` (040). */
export const CONCENTRATOR_SECRET_OUTCOMES = ['added', 'present', 'conflict'] as const;
export type ConcentratorSecretOutcome = (typeof CONCENTRATOR_SECRET_OUTCOMES)[number];

/** Where a site's account on the CHR stands, as the bench reads it. */
export type ConcentratorSecretStateName = 'provisioned' | 'pending' | 'failed';

export interface ConcentratorSecretState {
  state: ConcentratorSecretStateName;
  /** The job that decides it; null when no job could be queued (the refusal
   *  is then in `message` and `reason`). */
  jobId: number | null;
  message: string;
  /** Machine-readable: the refusal code, or the job's `error_kind`. */
  reason?: string;
  /** What the job found on the CHR, once it looked. */
  outcome?: ConcentratorSecretOutcome | null;
}

/** The services/change refusal for this kind. apply.service turns it into a
 *  `ChangeRefusedError` with the same `kind`, so `error_kind` carries it. */
export class ConcentratorSecretError extends Error {
  constructor(readonly kind: string, message: string) {
    super(message);
    this.name = 'ConcentratorSecretError';
  }
}

/** The step texts the job records when it skips the two nets. */
export const CONCENTRATOR_SECRET_NO_BACKUP =
  "'concentrator_secret' only ADDS one /ppp/secret entry under a name the concentrator does not " +
  'have, and refuses when the name exists with other attributes: it overwrites and removes ' +
  'nothing, so there is nothing a pre-change backup would restore. Its undo is removing that ' +
  'one entry by name.';
export const CONCENTRATOR_SECRET_NO_DEADMAN =
  "'concentrator_secret' cannot cut a management path: an added secret changes no route, " +
  'address, filter or live session until a peer authenticates with it. There is nothing for a ' +
  'dead-man to revert, so none is armed (the job is queued at safety level degraded, which is ' +
  'the truth about its net).';

/**
 * The guard verdict for this kind. The Management-Path Guard simulates a PLAN
 * against a forwarding model; this job carries no plan, and its one possible
 * write is an addition that the model would not contain anyway. ACCEPT is the
 * verdict because the job's own decision refuses every case that is not a pure
 * addition — not because a simulation ran.
 */
export function concentratorSecretGuard(): {
  verdict: 'ACCEPT';
  reasons: unknown[];
  summary: string;
  unavailable: false;
} {
  return {
    verdict: 'ACCEPT',
    reasons: [
      {
        code: 'ADDITIVE_CONCENTRATOR_SECRET',
        effect: 'accept',
        message:
          'Adds one /ppp/secret entry on the concentrator and nothing else; refuses instead of ' +
          'overwriting when the name or the address is already declared. An added secret ' +
          'removes no management path.',
      },
    ],
    summary:
      'Management-Path Guard: ACCEPT — an additive /ppp/secret entry removes no management path ' +
      '(no plan was simulated: the job refuses every case that is not a pure addition).',
    unavailable: false,
  };
}

// ============================================================================
// The injected allocation
// ============================================================================

/** What the CHR must carry for one site. Never a password. */
export interface ConcentratorSecretSpec {
  concentratorId: number;
  pppUsername: string;
  /** A host address, no mask. */
  tunnelIp: string;
  /** Null = the CHR's `default` profile (the add sends no `profile=`). */
  pppProfile: string | null;
}

/** The same, with the password: only `credentialFor` returns one. */
export interface ConcentratorSecretCredential extends ConcentratorSecretSpec {
  /** null = the allocation holds no password ObliWAN knows — a site adopted
   *  from the CHR in 'per_site' mode (its password is on the CHR, never read,
   *  secrets rule). The job can still find that account present; it can never ADD it,
   *  and refuses by name if the CHR no longer has it. */
  pppPassword: string | null;
  /** true = the allocation was ADOPTED from this CHR's own secret
   *  (`site_provisioning.source` 'adopted_chr'): the entry's comment is not
   *  compared (header, "WHEN THE COMMENT DECIDES"). Absent or false = ObliWAN
   *  computed it, and an entry it did not comment is somebody else's. */
  adopted?: boolean;
}

export interface ConcentratorSecretDeps {
  /** The site's allocation WITH its password. Called at enqueue (the password
   *  is dropped there) and at apply time (it is spliced there). Throws when
   *  the site has no allocation. */
  credentialFor(siteId: number, tenantId: number): Promise<ConcentratorSecretCredential>;
  /** Mirror where the CHR side stands onto the allocation. Best-effort: a
   *  failure here is logged, never fails the job.
   *
   *  Two rules bind every implementation:
   *  - `keepProvisioned: true` leaves an allocation already 'provisioned' as it
   *    is. `releaseAllocation` refuses only a 'provisioned' row, so writing
   *    'pending' (a re-verification just queued) or 'failed' (a CHR that did
   *    not answer) over it would let an operator release the login and the
   *    tunnel address of an account that is live on the CHR.
   *  - the outcome of a job never overwrites the mirror of a NEWER job
   *    (a larger `concentrator_job_id`). */
  recordOutcome(
    siteId: number,
    tenantId: number,
    outcome: {
      state: ConcentratorSecretStateName;
      jobId: number;
      error?: string | null;
      keepProvisioned?: boolean;
    },
  ): Promise<void>;
}

/** The allocation module's two exports for this job, by name. */
const defaultDeps: ConcentratorSecretDeps = {
  async credentialFor(siteId, tenantId) {
    // readPppAccount, not revealPppCredential: an adopted 'per_site' account
    // has no known password, and finding it present needs none.
    const c = await readPppAccount(siteId, tenantId);
    return {
      concentratorId: c.concentratorId,
      pppUsername: c.pppUsername,
      tunnelIp: c.tunnelIp,
      pppProfile: c.pppProfile,
      pppPassword: c.pppPassword,
      adopted: c.source === 'adopted_chr',
    };
  },
  async recordOutcome(siteId, tenantId, outcome) {
    // A read, then the allocation module's own write: two statements, not one,
    // because `recordConcentratorOutcome` (the only writer of these columns)
    // takes no condition. A row gone in between (released) makes that write
    // throw NOT_ALLOCATED, which the callers log.
    const current = (await db('site_provisioning')
      .where({ site_id: siteId, tenant_id: tenantId })
      .first('concentrator_state', 'concentrator_job_id')) as
      | { concentrator_state: string; concentrator_job_id: string | number | null }
      | undefined;
    if (current) {
      if (outcome.keepProvisioned && current.concentrator_state === 'provisioned') return;
      const mirroredJob = current.concentrator_job_id === null ? null : Number(current.concentrator_job_id);
      if (mirroredJob !== null && mirroredJob > outcome.jobId) return;
    }
    await recordConcentratorOutcome(siteId, tenantId, {
      state: outcome.state,
      jobId: outcome.jobId,
      error: outcome.error ?? null,
    });
  },
};

let deps: ConcentratorSecretDeps = defaultDeps;

/** Replace some or all of the dependencies (harnesses, or a later allocation
 *  source). Returns the previous set. */
export function setConcentratorSecretDeps(next: Partial<ConcentratorSecretDeps>): ConcentratorSecretDeps {
  const previous = deps;
  deps = { ...deps, ...next };
  return previous;
}

export function resetConcentratorSecretDeps(): void {
  deps = defaultDeps;
}

/** The site's allocation as a job would be queued with it: through the same
 *  dependency, with the password dropped here, at once. Throws when the site
 *  has no allocation. */
export async function readConcentratorSecretSpec(siteId: number, tenantId: number): Promise<ConcentratorSecretSpec> {
  const c = await deps.credentialFor(siteId, tenantId);
  return {
    concentratorId: c.concentratorId,
    pppUsername: c.pppUsername,
    tunnelIp: c.tunnelIp,
    pppProfile: c.pppProfile ?? null,
  };
}

// ============================================================================
// Attribute validation — what may be put into an API word
// ============================================================================

/** The login alphabet of migration 036 (`site_provisioning_username_chk`). */
const LOGIN_RE = /^[A-Za-z0-9._-]{1,128}$/;
/** RouterOS profile names as 036 accepts them. */
const PROFILE_RE = /^[A-Za-z0-9._-]{1,64}$/;
const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f]/;
export const COMMENT_PREFIX = 'obliwan:site:';
const COMMENT_MAX = 160;

/** `100.64.1.7/32` and `100.64.1.7` are the same host; anything else is not
 *  a host address and comes back null. */
export function hostAddress(value: string | null | undefined): string | null {
  if (!value) return null;
  const v = value.trim().replace(/\/32$/, '');
  const m = IPV4_RE.exec(v);
  if (!m) return null;
  return m.slice(1).every((o) => Number(o) <= 255) ? m.slice(1).map(Number).join('.') : null;
}

export function siteComment(siteCode: string): string {
  return `${COMMENT_PREFIX}${siteCode}`;
}

/** Null when the spec may be written; otherwise the refusal. */
export function specProblem(spec: ConcentratorSecretSpec, comment: string): string | null {
  if (!LOGIN_RE.test(spec.pppUsername) || spec.pppUsername.includes('..')) {
    return 'the PPP login is outside the allowed alphabet ([A-Za-z0-9._-], at most 128 characters)';
  }
  if (hostAddress(spec.tunnelIp) === null) return `the tunnel address "${spec.tunnelIp}" is not an IPv4 host`;
  if (spec.pppProfile !== null && !PROFILE_RE.test(spec.pppProfile)) {
    return 'the PPP profile name is outside the allowed alphabet ([A-Za-z0-9._-], at most 64 characters)';
  }
  if (comment.length > COMMENT_MAX || CONTROL_RE.test(comment)) {
    return 'the site code cannot be written as a RouterOS comment (control character, or too long)';
  }
  return null;
}

/** Never says which character was refused: that is a bit of a credential. */
function passwordProblem(password: string): string | null {
  if (typeof password !== 'string' || password === '') return 'the allocation holds an empty PPP password';
  if (CONTROL_RE.test(password)) return 'the allocation PPP password holds a character RouterOS cannot carry';
  return null;
}

/** Remove a credential from a text before it can reach a column or a log. */
function scrub(text: string, secret: string): string {
  if (!secret || !text.includes(secret)) return text;
  // Below four characters a split/join would mangle the message into noise
  // (and `redactCommand` skips such values); withhold the message instead.
  if (secret.length < 4) return 'RouterOS refused the command (message withheld: it may contain the credential)';
  return text.split(secret).join('***');
}

// ============================================================================
// The decision — pure
// ============================================================================

export interface ExpectedSecret {
  name: string;
  remoteAddress: string;
  comment: string;
  /** Null = the add sends none, so `default` is what the CHR must show. */
  profile: string | null;
  /** Comments an earlier job of THIS site (by site id, which never changes)
   *  wrote when it added an entry with this very name and remote-address.
   *  `sites.code` is editable and the comment carries it, so without these
   *  a renamed site would find its own account a permanent conflict. */
  formerComments?: readonly string[];
  /** true for an ADOPTED allocation: its comment is not compared (header,
   *  "WHEN THE COMMENT DECIDES"). Set from the allocation at apply time. */
  adopted?: boolean;
}

export type SecretDecision =
  | { action: 'add' }
  | { action: 'present'; entry: PppSecretEntry }
  | { action: 'conflict'; reasons: string[] };

/**
 * The attributes an existing entry must have to be "this site's secret": its
 * remote-address, service, profile and enabled state, and its comment — the
 * expected one or a former code of this site — UNLESS the allocation was
 * adopted (`expected.adopted`), whose deployed account ObliWAN never commented
 * (see the header). `compareComment` overrides that default either way.
 */
export function secretMismatches(
  entry: PppSecretEntry,
  expected: ExpectedSecret,
  options: { compareComment?: boolean } = {},
): string[] {
  const out: string[] = [];
  const addr = hostAddress(entry.remoteAddress);
  if (addr !== expected.remoteAddress) {
    out.push(`remote-address is ${entry.remoteAddress ?? '(none)'}, expected ${expected.remoteAddress}`);
  }
  const comment = entry.comment ?? '';
  const compareComment = options.compareComment ?? expected.adopted !== true;
  if (
    compareComment &&
    comment !== expected.comment &&
    !(expected.formerComments ?? []).includes(comment)
  ) {
    out.push(`comment is "${comment}", expected "${expected.comment}"`);
  }
  const service = entry.service ?? 'any';
  if (service !== 'l2tp' && service !== 'any') out.push(`service is ${service}, expected l2tp`);
  const profile = entry.profile ?? 'default';
  const wanted = expected.profile ?? 'default';
  if (profile !== wanted) out.push(`profile is ${profile}, expected ${wanted}`);
  if (entry.disabled) out.push('the secret is disabled (ObliWAN does not enable an existing secret)');
  return out;
}

export function decideSecretAction(entries: PppSecretEntry[], expected: ExpectedSecret): SecretDecision {
  const exact = entries.filter((e) => e.name === expected.name);
  const lower = expected.name.toLowerCase();
  const otherCase = entries.filter((e) => e.name !== expected.name && e.name.toLowerCase() === lower);
  const sameAddress = entries.filter(
    (e) => e.name.toLowerCase() !== lower && hostAddress(e.remoteAddress) === expected.remoteAddress,
  );

  const reasons: string[] = [];
  if (exact.length > 1) reasons.push(`${exact.length} secrets are named "${expected.name}"`);
  for (const e of otherCase) reasons.push(`a secret named "${e.name}" differs from "${expected.name}" only by case`);
  for (const e of sameAddress) {
    reasons.push(`remote-address ${expected.remoteAddress} is already declared by secret "${e.name}"`);
  }
  if (exact.length === 1) {
    const diff = secretMismatches(exact[0], expected);
    if (diff.length > 0) reasons.push(`secret "${expected.name}" exists and differs: ${diff.join('; ')}`);
  }
  if (reasons.length > 0) return { action: 'conflict', reasons };
  if (exact.length === 1) return { action: 'present', entry: exact[0] };
  return { action: 'add' };
}

/** The API words of the one write this module can produce. The password word
 *  is built LAST and only here. */
export function addSecretWords(expected: ExpectedSecret, password: string): string[] {
  const words = [
    '/ppp/secret/add',
    `=name=${expected.name}`,
    '=service=l2tp',
    `=remote-address=${expected.remoteAddress}`,
    `=comment=${expected.comment}`,
  ];
  if (expected.profile !== null) words.push(`=profile=${expected.profile}`);
  words.push(`=password=${password}`);
  return words;
}

/** The same command as `command_audit` stores it: the password is never in it. */
export function addSecretAuditText(expected: ExpectedSecret): string {
  return (
    `/ppp/secret/add name=${expected.name} password=*** service=l2tp ` +
    `remote-address=${expected.remoteAddress} comment=${expected.comment}` +
    (expected.profile !== null ? ` profile=${expected.profile}` : '')
  );
}

const PRINT_WORDS = [
  '/ppp/secret/print',
  // An allow-list, so no password crosses the wire (concentratorDiscovery
  // explains why there is no `show-sensitive` word).
  '=.proplist=.id,name,service,profile,remote-address,local-address,comment,disabled',
];

// ============================================================================
// Rows
// ============================================================================

interface SecretJobRow {
  job_id: string | number;
  tenant_id: number;
  site_id: number;
  ppp_username: string;
  remote_address: string;
  ppp_profile: string | null;
  comment: string;
  outcome: ConcentratorSecretOutcome | null;
  outcome_detail: string | null;
}

async function loadSecretJob(jobId: number): Promise<SecretJobRow> {
  const row = (await db('concentrator_secret_jobs')
    .where({ job_id: jobId })
    .first(
      'job_id',
      'tenant_id',
      'site_id',
      'ppp_username',
      db.raw('host(remote_address) AS remote_address'),
      'ppp_profile',
      'comment',
      'outcome',
      'outcome_detail',
    )) as SecretJobRow | undefined;
  if (!row) {
    throw new ConcentratorSecretError(
      'concentrator_secret_missing',
      `Job ${jobId} has no concentrator_secret_jobs row: nothing says which site it provisions.`,
    );
  }
  return row;
}

function expectedOf(row: SecretJobRow): ExpectedSecret {
  return {
    name: row.ppp_username,
    remoteAddress: hostAddress(row.remote_address) ?? row.remote_address,
    comment: row.comment,
    profile: row.ppp_profile,
  };
}

/** `expectedOf`, plus the comments this site's own earlier jobs ADDED with
 *  this name and address (see `ExpectedSecret.formerComments`). Keyed on the
 *  site id, never on the code: a comment another site wrote is never
 *  accepted, nor one on an entry ObliWAN found rather than wrote. */
async function expectedWithHistory(row: SecretJobRow): Promise<ExpectedSecret> {
  const expected = expectedOf(row);
  const earlier = (await db('concentrator_secret_jobs')
    .where({ site_id: row.site_id, tenant_id: row.tenant_id, ppp_username: row.ppp_username })
    .where('remote_address', expected.remoteAddress)
    .where('outcome', 'added')
    .whereNot('job_id', row.job_id)
    .whereNot('comment', expected.comment)
    .distinct('comment')) as Array<{ comment: string }>;
  return { ...expected, formerComments: earlier.map((r) => r.comment) };
}

async function recordFound(jobId: number, outcome: ConcentratorSecretOutcome, detail: string): Promise<void> {
  await db('concentrator_secret_jobs')
    .where({ job_id: jobId })
    .update({ outcome, outcome_detail: detail, updated_at: db.fn.now() });
}

// ============================================================================
// The job's two steps (called from apply.service.ts runPhases)
// ============================================================================

export interface AuditedDevice {
  id: number;
  uuid?: string | null;
  name?: string | null;
}

function intentFor(
  job: ChangeJobRow,
  device: AuditedDevice,
  correlationId: string,
  command: string,
  isWrite: boolean,
  secrets: string[] = [],
): CommandIntent {
  return {
    tenantId: job.tenant_id,
    deviceId: device.id,
    deviceUuid: device.uuid ?? null,
    deviceName: device.name ?? null,
    jobId: Number(job.id),
    transport: 'routeros_api',
    command,
    isWrite,
    correlationId,
    secrets,
  };
}

/**
 * The secrets that can decide THIS account: the one named exactly so and the
 * ones declaring its remote address — two FILTERED queries the CHR answers
 * with a row or two — plus, for the "differs only by case" refusal, the
 * case variants of its name from the last full read of the CHR
 * (`concentrator_ppp_secrets`, kept by "Relire le CHR").
 *
 * It used to print EVERY secret of the shared concentrator: hundreds of rows
 * for one account, and on 2026-10-03 that print timed out after 20 s through
 * the ObliWAN ↔ CHR link while the identity read on the same connection took
 * 189 ms — every new site's account failed, and with it every bench box
 * waiting for one. API queries are exact and case-sensitive, so a case
 * variant cannot be asked for: it is taken from the stored read, and a
 * variant created on the CHR after that read is not seen here (re-read the
 * CHR to refresh it).
 */
async function readSecrets(
  conn: RouterOsConnection,
  job: ChangeJobRow,
  device: AuditedDevice,
  correlationId: string,
  expected: ExpectedSecret,
): Promise<PppSecretEntry[]> {
  const byName = [...PRINT_WORDS, `?name=${expected.name}`];
  const byAddress = [...PRINT_WORDS, `?remote-address=${expected.remoteAddress}`];
  const rows = [
    ...(await auditedCommand(intentFor(job, device, correlationId, byName.join(' '), false), () => conn.query(byName))),
    ...(await auditedCommand(intentFor(job, device, correlationId, byAddress.join(' '), false), () => conn.query(byAddress))),
  ];
  const byId = new Map<string, Record<string, string>>();
  for (const r of rows) byId.set(r['.id'] ?? `${r.name ?? ''}|${r['remote-address'] ?? ''}`, r);
  const live = [...byId.values()].map(parseSecretRow).filter((e): e is PppSecretEntry => e !== null);

  // Never read in full yet: no stored read to take case variants from. The
  // full print this used to fall back on is the very read that times out
  // through the link (20 s, 2026-10-03 and again 2026-10-04 after a deploy),
  // and it cost the whole account for a refusal about case alone. So the
  // case check is skipped, said in the log, and the exact-name and address
  // checks above still decide; re-reading the CHR restores it.
  const known = (await db('concentrator_ppp_secrets').where({ concentrator_id: job.device_id }).first('id')) as { id: number } | undefined;
  if (!known) {
    logger.warn(
      { jobId: Number(job.id), concentratorId: job.device_id, name: expected.name },
      'PPP secret: case variants not checked — this concentrator was never read in full (Reconciliation: re-read the CHR)',
    );
    return live;
  }
  const variants = (await db('concentrator_ppp_secrets')
    .where({ concentrator_id: job.device_id })
    .whereNull('vanished_at')
    .whereRaw('lower(name) = lower(?)', [expected.name])
    .whereNot('name', expected.name)
    .select('name', 'profile', 'disabled', db.raw('host(remote_address) AS remote_address'))) as Array<{
    name: string; profile: string | null; disabled: boolean; remote_address: string | null;
  }>;
  for (const v of variants) {
    if (live.some((e) => e.name === v.name)) continue;
    live.push({
      routerId: null, name: v.name, service: null, profile: v.profile, remoteAddress: v.remote_address,
      localAddress: null, comment: null, disabled: v.disabled, raw: {},
    });
  }
  return live;
}

export interface SecretStepResult {
  output: string;
  detail: Record<string, unknown>;
}

/**
 * The `apply` step: read, decide, and at most one `/ppp/secret/add`.
 * `onWrite` is called immediately before the add is sent (apply.service marks
 * the job as having touched the device).
 */
export async function applyConcentratorSecret(
  job: ChangeJobRow,
  device: AuditedDevice,
  correlationId: string,
  onWrite: () => void = () => undefined,
): Promise<SecretStepResult> {
  const jobId = Number(job.id);
  const row = await loadSecretJob(jobId);
  const queued = await expectedWithHistory(row);

  // runPhases checked the kill switch of the job's tenant — the CHR's. The
  // write is made on behalf of the SITE's tenant, and its switch stops it too.
  await assertWritable(row.tenant_id);

  // The allocation, again, at the last moment. It must still say what the
  // job was queued with: an allocation released and re-made in between is a
  // different account, and this job was not authorised for it.
  let credential: ConcentratorSecretCredential;
  try {
    credential = await deps.credentialFor(row.site_id, row.tenant_id);
  } catch (err) {
    throw new ConcentratorSecretError(
      'allocation_unavailable',
      `The allocation of site ${row.site_id} could not be read: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  // Whether the comment decides is the allocation's provenance, read now.
  const expected: ExpectedSecret = { ...queued, adopted: credential.adopted === true };
  const moved: string[] = [];
  if (credential.concentratorId !== job.device_id) moved.push('concentrator');
  if (credential.pppUsername !== expected.name) moved.push('PPP login');
  if (hostAddress(credential.tunnelIp) !== expected.remoteAddress) moved.push('tunnel address');
  if ((credential.pppProfile ?? null) !== expected.profile) moved.push('PPP profile');
  if (moved.length > 0) {
    throw new ConcentratorSecretError(
      'allocation_moved',
      `The allocation of site ${row.site_id} changed after this job was queued (${moved.join(', ')}). ` +
        'Nothing was written; queue a new job for the current allocation.',
    );
  }
  // null: an adopted 'per_site' account. Judged at the add, the only place a
  // password is needed; "present" needs none.
  const password = credential.pppPassword;
  if (password !== null) {
    const bad = passwordProblem(password);
    if (bad) throw new ConcentratorSecretError('password_unusable', `${bad}. Nothing was written.`);
  }

  const target = await resolveRouterOsTarget(job.device_id);
  // A refusal the CHR ANSWERED — a conflict, an absent account with no
  // password, a `!trap` on the add — leaves the callback as a VALUE and is
  // thrown below, outside it: the pool counts anything thrown from inside
  // `withConnection` (other than a bare trap) against the CHR's circuit
  // breaker, and a CHR that answered correctly is not a failing transport. A
  // bench asking about one conflict four times in a row would otherwise open
  // the breaker of the SHARED concentrator for every other site.
  const decide = async (conn: RouterOsConnection): Promise<SecretStepResult | ConcentratorSecretError> => {
    const entries = await readSecrets(conn, job, device, correlationId, expected);
    const decision = decideSecretAction(entries, expected);

    if (decision.action === 'conflict') {
      const detail =
        `Refused, nothing written: ${decision.reasons.join(' | ')}. ` +
        'ObliWAN never overwrites or removes an existing secret; resolve it on the concentrator, ' +
        `or release the site's allocation (DELETE /api/allocation/sites/${row.site_id}) and compile ` +
        'the site again on the bench.';
      await recordFound(jobId, 'conflict', detail);
      return new ConcentratorSecretError('concentrator_secret_conflict', detail);
    }

    if (decision.action === 'present') {
      const found = decision.entry.comment ?? '';
      let about = '';
      if (found !== expected.comment) {
        about = (expected.formerComments ?? []).includes(found)
          ? `Its comment carries the site's former code (an earlier job of this site added it); ` +
            `the current one would be "${expected.comment}", and an existing secret is never rewritten. `
          : `Its comment is not one ObliWAN wrote for this site: the allocation was ADOPTED from this ` +
            `CHR (an account deployed before ObliWAN, recorded as it is), and an adopted account's ` +
            `comment is never compared and never rewritten. `;
      }
      const detail =
        `secret "${expected.name}" already present with remote-address ${expected.remoteAddress}, ` +
        `comment "${found}" and the expected service and profile; nothing written. ${about}` +
        'Its password was not compared: it is never read back.';
      await recordFound(jobId, 'present', detail);
      return {
        output: detail,
        detail: { outcome: 'present', secretCount: entries.length },
      };
    }

    if (password === null) {
      // ABSENT, and nothing to add it with. Recorded as a conflict: the job
      // read the CHR and found the account the allocation describes missing,
      // so a 'provisioned' mirror must not survive it (settleConcentratorSecret).
      const detail =
        `Refused, nothing written: secret "${expected.name}" is not on the concentrator, and this ` +
        "site's allocation holds no PPP password — it was adopted from the CHR in 'per_site' mode, " +
        'and the CHR\'s password is never read. ObliWAN does not invent one. Restore the ' +
        "secret on the concentrator, or release the site's allocation " +
        `(DELETE /api/allocation/sites/${row.site_id}) and compile the site again on the bench.`;
      await recordFound(jobId, 'conflict', detail);
      return new ConcentratorSecretError('password_unknown', detail);
    }

    onWrite();
    try {
      await auditedCommand(
        intentFor(job, device, correlationId, addSecretAuditText(expected), true, [password]),
        async () => {
          try {
            return await conn.query(addSecretWords(expected, password));
          } catch (err) {
            // Re-thrown scrubbed, so neither the audit's error column nor the
            // job's error message can carry an echo of the value — and under
            // the kind that says what is KNOWN (`addFailureKind`): a `!trap`
            // is the CHR refusing, nothing created; a timeout or a dropped
            // session leaves the account possibly created, which only a new
            // read of the CHR can tell.
            const message = err instanceof Error ? err.message : String(err);
            throw new ConcentratorSecretError(addFailureKind(err), scrub(message, password));
          }
        },
      );
    } catch (err) {
      if (err instanceof ConcentratorSecretError && err.kind === 'concentrator_secret_add_refused') return err;
      throw err; // the transport's failure: the breaker may count it
    }
    const detail =
      `secret "${expected.name}" added (service l2tp, remote-address ${expected.remoteAddress}, ` +
      `profile ${expected.profile ?? 'default'}, comment "${expected.comment}")`;
    await recordFound(jobId, 'added', detail);
    return { output: detail, detail: { outcome: 'added', secretCount: entries.length } };
  };
  const decided = await getRouterOsPool().withConnection(target, decide);
  if (decided instanceof ConcentratorSecretError) throw decided;
  return decided;
}

/** The `postcheck` step: read back, and every visible attribute must hold. */
export async function verifyConcentratorSecret(
  job: ChangeJobRow,
  device: AuditedDevice,
  correlationId: string,
): Promise<SecretStepResult> {
  const row = await loadSecretJob(Number(job.id));
  const expected = await expectedWithHistory(row);
  const target = await resolveRouterOsTarget(job.device_id);
  const entries = await getRouterOsPool().withConnection(target, (conn) =>
    readSecrets(conn, job, device, correlationId, expected),
  );
  const exact = entries.filter((e) => e.name === expected.name);
  if (exact.length !== 1) {
    throw new ConcentratorSecretError(
      'concentrator_secret_unverified',
      `Read-back found ${exact.length} secret(s) named "${expected.name}" on the concentrator, expected exactly one.`,
    );
  }
  // The comment is re-checked only when this job ADDED the entry (it wrote
  // it). An entry found present had its comment judged at the decision, on
  // this job's own read moments earlier — or not at all, for an adopted
  // account (header, "WHEN THE COMMENT DECIDES") — and this step does not
  // read the allocation's provenance again.
  const diff = secretMismatches(exact[0], expected, { compareComment: row.outcome === 'added' });
  if (diff.length > 0) {
    throw new ConcentratorSecretError(
      'concentrator_secret_unverified',
      `Read-back of "${expected.name}" does not match: ${diff.join('; ')}.`,
    );
  }
  return {
    output:
      `read back: "${expected.name}" present once, remote-address ${expected.remoteAddress}, ` +
      `profile ${expected.profile ?? 'default'}, enabled (password not read back)`,
    detail: { verified: true },
  };
}

/**
 * Mirror a finished job onto the allocation. Never throws; idempotent.
 *
 * Called by `failJob` and the lease reaper (failure) and by the job itself once
 * its read-back held (success). A failure demotes an allocation already
 * 'provisioned' ONLY when this job read the CHR and found the account wrong
 * (outcome 'conflict'). Any other failure — CHR unreachable, identity
 * mismatch, kill switch, lost worker, a refused add — proves nothing about the
 * account a previous job verified, and leaves 'provisioned' standing. The
 * error text is the job's own: the password is spliced only into the add, and
 * `applyConcentratorSecret` scrubs it from that command's refusal.
 *
 * A failure is then ANNOUNCED (`announceConcentratorSecretFailure`, header "A
 * FAILURE IS ANNOUNCED ONCE"). `errorKind` is the `change_jobs.error_kind` the
 * caller is about to write (`failJob` settles BEFORE the row turns terminal);
 * without it the row's own column is read, which is how the lease reaper's
 * `worker_lost` arrives. An unknown kind classifies as a refusal: the safe way
 * to be wrong is to ask a human, not to promise a retry. A success RESOLVES
 * what was announced (`announceConcentratorSecretResolved`): an operator told
 * "not confirmed" is told, once, that it now is.
 */
export async function settleConcentratorSecret(
  job: Pick<ChangeJobRow, 'id'>,
  result: { ok: true } | { ok: false; error: string; errorKind?: string | null },
): Promise<void> {
  const jobId = Number(job.id);
  let row: { tenant_id: number; site_id: number; outcome: ConcentratorSecretOutcome | null } | undefined;
  try {
    row = (await db('concentrator_secret_jobs')
      .where({ job_id: jobId })
      .first('tenant_id', 'site_id', 'outcome')) as typeof row;
    if (!row) return;
    await deps.recordOutcome(row.site_id, row.tenant_id, result.ok
      ? { state: 'provisioned', jobId }
      : {
          state: 'failed',
          jobId,
          error: result.error.slice(0, 2000) || 'concentrator job failed',
          keepProvisioned: row.outcome !== 'conflict',
        });
  } catch (err) {
    logger.warn(
      { err: err instanceof Error ? err.message : String(err), jobId },
      'concentrator secret: the outcome could not be mirrored onto the allocation',
    );
  }
  // Outside the mirror's try: an allocation that could not be written must
  // not also silence the one notice an operator gets.
  if (!row) return;
  if (result.ok) await announceConcentratorSecretResolved(jobId, row);
  else await announceConcentratorSecretFailure(jobId, row, result.error, result.errorKind ?? null);
}

// ============================================================================
// Failure: classification, episode, the one alert, the retry policy
// ============================================================================

/** The add was SENT and the session timed out or dropped before the CHR
 *  answered: the account may exist. Retryable, because the next job reads the
 *  CHR first and finds it "present" if it was created. */
const ADD_UNCONFIRMED = 'concentrator_secret_add_unconfirmed';

/** `change_jobs.error_kind` values (apply.service `classifyFailure`: an error
 *  class's own `name`, or the queue's own kinds) that heal by themselves: the
 *  RouterOS transport's timeout, closed session and open breaker, an add whose
 *  answer was lost with the session, and the reaper's `worker_lost` (the next
 *  job reads the CHR first, so a worker that died after the add makes the
 *  retry find it present). */
const RETRYABLE_KINDS: ReadonlySet<string> = new Set([
  'RouterOsTimeoutError',
  'RouterOsConnectionClosedError',
  'CircuitOpenError',
  ADD_UNCONFIRMED,
  'worker_lost',
]);

/** Kinds whose MESSAGE decides. `binding_mismatch` is what the identity-binding assertion
 *  says both for a box that answered as somebody else (never retried) and for
 *  a fresh socket that could not even connect ("fresh connection to ...
 *  failed: connect ECONNREFUSED ..."). `Error` is what a refused or timed-out
 *  TCP connect of the pool is. */
const MESSAGE_DECIDES_KINDS: ReadonlySet<string> = new Set(['binding_mismatch', 'Error']);

/** An ALLOW-list: a message it does not recognise is a refusal, so a reworded
 *  transport error costs a human a click, never a retry loop. */
const TRANSIENT_RE =
  /timed out|ETIMEDOUT|ECONNREFUSED|ECONNRESET|EHOSTUNREACH|ENETUNREACH|EHOSTDOWN|EPIPE|EAI_AGAIN|connection closed|circuit is open/i;

/** Wins over TRANSIENT_RE: an identity or fingerprint mismatch, a credential
 *  the CHR refused (retrying a login locks the account), a TLS refusal, and
 *  the identity-binding refusals that are configuration, not weather. */
const NEVER_TRANSIENT_RE =
  /mismatch|login failed|TLS handshake|alert 40|no identity attribute|no credential|no address to dial|absent or disabled|status is 'disabled'|no fresh-connection identity path/i;

export type ConcentratorFailureClass = 'retryable' | 'refusal';

/** Pure. A job that read the CHR and found the account wrong (outcome
 *  'conflict') is a refusal whatever its error says. */
export function classifyConcentratorFailure(failure: {
  errorKind: string | null | undefined;
  errorMessage: string | null | undefined;
  outcome?: ConcentratorSecretOutcome | null;
}): ConcentratorFailureClass {
  if (failure.outcome === 'conflict') return 'refusal';
  const kind = failure.errorKind ?? '';
  if (RETRYABLE_KINDS.has(kind)) return 'retryable';
  if (MESSAGE_DECIDES_KINDS.has(kind)) {
    return isTransientMessage(failure.errorMessage ?? '') ? 'retryable' : 'refusal';
  }
  return 'refusal';
}

function isTransientMessage(message: string): boolean {
  return TRANSIENT_RE.test(message) && !NEVER_TRANSIENT_RE.test(message);
}

/**
 * The kind a failed `/ppp/secret/add` is filed under. A `!trap` is the CHR
 * ANSWERING: it refused, nothing was created — a refusal. A timeout, a closed
 * session, or a socket error the allow-list recognises happened to the
 * TRANSPORT after the add was sent: the account may have been created, and
 * the retry's first read of the CHR is what tells — retryable. Anything else
 * is neither a known refusal nor a known transport failure, and asks a human.
 */
function addFailureKind(err: unknown): string {
  if (err instanceof RouterOsTrapError) return 'concentrator_secret_add_refused';
  if (err instanceof RouterOsTimeoutError || err instanceof RouterOsConnectionClosedError) return ADD_UNCONFIRMED;
  // A socket that errored rejects the pending command with the socket's own
  // Error (connection.ts `destroy(reason)`), e.g. "read ECONNRESET".
  if (isTransientMessage(err instanceof Error ? err.message : String(err))) return ADD_UNCONFIRMED;
  return 'concentrator_secret_add_failed';
}

/**
 * Pure. Which incident a failure belongs to: every retryable failure is one
 * cause ('transient'); a refusal is its `error_kind`, refined by its message
 * for the kinds whose message decides. `binding_mismatch` alone covers a
 * refused login, a TLS refusal, a box that answered as somebody else and a
 * transport with no address — four different problems, and an impostor met
 * after a login failure must not be folded into the login failure's alert.
 */
export function failureCause(failure: {
  errorKind: string | null | undefined;
  errorMessage: string | null | undefined;
  outcome?: ConcentratorSecretOutcome | null;
}): string {
  if (classifyConcentratorFailure(failure) === 'retryable') return 'transient';
  const kind = failure.errorKind ?? 'unknown';
  if (failure.outcome === 'conflict' || !MESSAGE_DECIDES_KINDS.has(kind)) return kind;
  const message = failure.errorMessage ?? '';
  // Order matters: "TLS fingerprint mismatch" is a TLS refusal, not an impostor.
  if (/TLS fingerprint|TLS handshake|alert 40/i.test(message)) return `${kind}:tls`;
  if (/login failed/i.test(message)) return `${kind}:login`;
  if (/mismatch/i.test(message)) return `${kind}:mismatch`;
  if (/no identity attribute/i.test(message)) return `${kind}:unproven`;
  if (/no credential|no address to dial|absent or disabled|status is 'disabled'|no fresh-connection identity path/i.test(message)) {
    return `${kind}:config`;
  }
  return `${kind}:other`;
}

/** One job of a site's history, newest first, as the episode walk reads it. */
export interface SecretJobHistoryEntry {
  jobId: number;
  status: string;
  /** The CHR the job was queued on. */
  deviceId: number;
  pppUsername: string;
  remoteAddress: string;
  pppProfile: string | null;
  outcome: ConcentratorSecretOutcome | null;
  errorKind: string | null;
  errorMessage: string | null;
}

/** Same allocation: same CHR, login, address and profile. The comment is not
 *  compared — it carries the site's code, which is editable. */
function sameAllocation(a: SecretJobHistoryEntry, b: SecretJobHistoryEntry): boolean {
  return (
    a.deviceId === b.deviceId &&
    a.pppUsername === b.pppUsername &&
    hostAddress(a.remoteAddress) === hostAddress(b.remoteAddress) &&
    (a.pppProfile ?? null) === (b.pppProfile ?? null)
  );
}

/** Pure. `job` (older) continues the episode `head` opened. */
function continuesEpisode(head: SecretJobHistoryEntry, headCause: string, job: SecretJobHistoryEntry): boolean {
  return job.status === 'failed' && sameAllocation(job, head) && failureCause(job) === headCause;
}

/**
 * Pure. The failure episode the NEWEST job (`history[0]`) belongs to, newest
 * first, as far as `history` reaches; empty when that job did not fail. A
 * retryable head gathers the trailing retryable failures; a refusal gathers
 * the trailing failures of the same cause (`failureCause`: the bench asking
 * ten times about one conflict is one incident). Either run stops at a
 * success, at another cause, and at a job queued for another allocation.
 * `walkFailureEpisode` is the same walk over the WHOLE history.
 */
export function failureEpisode(history: readonly SecretJobHistoryEntry[]): SecretJobHistoryEntry[] {
  const head = history[0];
  if (!head || head.status !== 'failed') return [];
  const headCause = failureCause(head);
  const out = [head];
  for (const job of history.slice(1)) {
    if (!continuesEpisode(head, headCause, job)) break;
    out.push(job);
  }
  return out;
}

export interface FailureEpisodeSummary {
  /** The newest failure: the one the episode is judged by. */
  head: SecretJobHistoryEntry;
  /** The OLDEST: the episode's alerts are keyed on its job id. */
  first: SecretJobHistoryEntry;
  /** Failed jobs in the episode, `head` included. */
  length: number;
}

const EPISODE_PAGE = 100;

/**
 * The whole episode `head` opens, paging back through the site's history
 * until the run breaks — never a fixed window. A window would let the first
 * job slide: at failure 51 of a 50-job window the "first" job becomes the
 * second one, the alert key changes, and every further failure raises a new
 * alert. Reads every job of the episode once (keyset pages of
 * `EPISODE_PAGE`), and keeps only the two ends and the count. `head` may be a
 * job whose row is not terminal yet: settle runs before `failJob` marks it.
 */
export async function walkFailureEpisode(
  head: SecretJobHistoryEntry,
  siteId: number,
  tenantId: number,
): Promise<FailureEpisodeSummary | null> {
  if (head.status !== 'failed') return null;
  const headCause = failureCause(head);
  let first = head;
  let length = 1;
  let before = head.jobId;
  for (;;) {
    const page = await loadSecretJobHistory(siteId, tenantId, EPISODE_PAGE, before);
    for (const job of page) {
      if (!continuesEpisode(head, headCause, job)) return { head, first, length };
      first = job;
      length += 1;
    }
    if (page.length < EPISODE_PAGE) return { head, first, length };
    before = page[page.length - 1].jobId;
  }
}

/** This site's latest jobs, newest first; with `beforeJobId`, only the jobs
 *  older than it (a keyset page). */
export async function loadSecretJobHistory(
  siteId: number,
  tenantId: number,
  limit: number,
  beforeJobId?: number,
): Promise<SecretJobHistoryEntry[]> {
  let query = db('concentrator_secret_jobs as c')
    .join('change_jobs as j', 'j.id', 'c.job_id')
    .where('c.site_id', siteId)
    .where('c.tenant_id', tenantId);
  if (beforeJobId !== undefined) query = query.where('c.job_id', '<', beforeJobId);
  const rows = (await query
    .orderBy('c.job_id', 'desc')
    .limit(Math.max(1, limit))
    .select(
      'c.job_id',
      'j.status',
      'j.device_id',
      'c.ppp_username',
      db.raw('host(c.remote_address) AS remote_address'),
      'c.ppp_profile',
      'c.outcome',
      'j.error_kind',
      'j.error_message',
    )) as Array<{
    job_id: string | number;
    status: string;
    device_id: number;
    ppp_username: string;
    remote_address: string;
    ppp_profile: string | null;
    outcome: ConcentratorSecretOutcome | null;
    error_kind: string | null;
    error_message: string | null;
  }>;
  return rows.map((r) => ({
    jobId: Number(r.job_id),
    status: r.status,
    deviceId: Number(r.device_id),
    pppUsername: r.ppp_username,
    remoteAddress: r.remote_address,
    pppProfile: r.ppp_profile,
    outcome: r.outcome,
    errorKind: r.error_kind,
    errorMessage: r.error_message,
  }));
}

export interface ConcentratorSecretRetryPolicy {
  /** Automatic attempts after an episode's first failure, at most. */
  maxRetries: number;
  /** The wait after the first failure; doubled after each next one. */
  baseDelayMs: number;
  /** The ceiling of one wait. */
  maxDelayMs: number;
}

/** 5 retries, 1-2-4-8-16 minutes apart: about half an hour, which outlasts a
 *  CHR reboot or a short upstream outage and is short enough for a site that
 *  is waiting at the bench. */
export const DEFAULT_CONCENTRATOR_SECRET_RETRY: Readonly<ConcentratorSecretRetryPolicy> = Object.freeze({
  maxRetries: 5,
  baseDelayMs: 60_000,
  maxDelayMs: 30 * 60_000,
});

/** Pure. How long to wait after an episode's `failures`-th failure (1-based). */
export function retryDelayMs(policy: ConcentratorSecretRetryPolicy, failures: number): number {
  return Math.min(policy.maxDelayMs, policy.baseDelayMs * 2 ** Math.max(0, failures - 1));
}

/** The policy of the retry loop armed IN THIS PROCESS, or null when none is.
 *  Set only by concentratorSecretRetry.service's start/stop, so the alert never
 *  promises a retry nothing will make. */
let armedRetryPolicy: Readonly<ConcentratorSecretRetryPolicy> | null = null;

export function setConcentratorSecretRetryPolicy(policy: ConcentratorSecretRetryPolicy | null): void {
  armedRetryPolicy = policy ? Object.freeze({ ...policy }) : null;
}

export function concentratorSecretRetryPolicy(): Readonly<ConcentratorSecretRetryPolicy> | null {
  return armedRetryPolicy;
}

/** The most of the job's own text a same-tenant alert quotes. */
const ALERT_DETAIL_MAX = 500;

/**
 * Every alert of this job: `concentrator-secret:<site>:<first job of the
 * episode>` (the failure), `...:exhausted` (every automatic attempt failed)
 * and `...:resolved` (a later job confirmed the account). Each is raised at
 * most once, whatever its read state.
 */
const ALERT_PREFIX = 'concentrator-secret:';
const ALERT_KEY_RE = /^concentrator-secret:(\d+):(\d+)(?::(exhausted|resolved))?$/;

function alertKey(siteId: number, firstJobId: number, suffix?: 'exhausted' | 'resolved'): string {
  return `${ALERT_PREFIX}${siteId}:${firstJobId}${suffix ? `:${suffix}` : ''}`;
}

async function alertExists(tenantId: number, stableKey: string): Promise<boolean> {
  return (await db('live_alerts').where({ tenant_id: tenantId, stable_key: stableKey }).first('id')) !== undefined;
}

/** "Ask again", as an operation that exists: the bench compile is the one
 *  caller that requests a site's account (`provisionConcentratorSecret`). */
const ASK_AGAIN =
  'compile the site again on the bench, which requests its concentrator account (a new job reads the ' +
  'concentrator first and writes nothing if the account is already there)';

/** Releasing an allocation is a platform administrator's API call
 *  (allocation.routes.ts, `requireRole('admin')`); allocating it again is the
 *  next bench compile. */
function releaseHint(siteId: number): string {
  return (
    `a platform administrator releases the site's allocation (DELETE /api/allocation/sites/${siteId}) ` +
    'and the next bench compile allocates the site again'
  );
}

const capitalized = (text: string): string => text.charAt(0).toUpperCase() + text.slice(1);

type FailureFacts = Pick<SecretJobHistoryEntry, 'errorKind' | 'errorMessage' | 'outcome'>;

/** What went wrong, in words that hold for any reader: no address, no other
 *  site's secret, no password. */
function reasonText(f: FailureFacts): string {
  const cause = failureCause(f);
  switch (cause) {
    case 'transient':
      if (f.errorKind === ADD_UNCONFIRMED) {
        return 'the session with the concentrator timed out or dropped while the account was being created, ' +
          'so whether it was created is not known yet';
      }
      if (f.errorKind === 'worker_lost') return 'the worker running the job stopped before it finished';
      return 'the concentrator did not answer in time, refused the connection or dropped it';
    case 'concentrator_secret_conflict':
      return 'an account with this login or this tunnel address already exists on the concentrator with ' +
        'other attributes, and ObliWAN never overwrites or removes one';
    case 'password_unknown':
      return "the account is not on the concentrator, and this site's allocation holds no PPP password to " +
        "create it with (adopted from the concentrator in 'per_site' mode)";
    case 'password_unusable':
      return "the allocation's PPP password cannot be written to RouterOS";
    case 'allocation_moved':
      return "the site's allocation changed after the job was queued";
    case 'allocation_unavailable':
      return "the site's allocation could not be read when the job ran";
    case 'concentrator_secret_add_refused':
      return 'the concentrator refused to create the account';
    case 'concentrator_secret_add_failed':
      return 'creating the account failed with an error that is neither a refusal from the concentrator nor a ' +
        'known transport failure, so whether it was created is not known';
    case 'concentrator_secret_unverified':
      return 'the account did not read back as it should';
    case 'kill_switch':
      return 'a kill switch stopped the write';
    case 'binding_mismatch:tls':
      return "the concentrator's API refused the TLS handshake, or presented another certificate than the pinned one";
    case 'binding_mismatch:login':
      return "the concentrator refused ObliWAN's API login (a credential that changed or was revoked)";
    case 'binding_mismatch:mismatch':
      return "the box answering at the concentrator's address is NOT the recorded concentrator (identity mismatch)";
    case 'binding_mismatch:unproven':
      return "the concentrator's identity could not be corroborated on a fresh connection";
    case 'binding_mismatch:config':
      return 'ObliWAN holds no usable API transport, address or credential for the concentrator';
    default:
      if (cause.startsWith('binding_mismatch:')) return "the concentrator's identity could not be proved on a fresh connection";
      return 'the job failed';
  }
}

/** What a human does about a refusal: only operations that exist. */
function refusalHint(cause: string, siteId: number): string {
  switch (cause) {
    case 'concentrator_secret_conflict':
      return `Resolve the account on the concentrator (ObliWAN never edits or removes one), or ${releaseHint(siteId)}.`;
    case 'password_unknown':
      return `Restore the account on the concentrator, or ${releaseHint(siteId)}.`;
    case 'allocation_moved':
    case 'allocation_unavailable':
      return `For its current allocation, ${ASK_AGAIN}.`;
    case 'kill_switch':
      return `Release the kill switch, then ${ASK_AGAIN}.`;
    case 'concentrator_secret_add_failed':
      return `${capitalized(ASK_AGAIN)}.`;
    case 'binding_mismatch:login':
      return "A platform administrator checks the concentrator's API credential in ObliWAN; a refused login is " +
        'never retried, because retrying it can lock the account.';
    case 'binding_mismatch:mismatch':
      return "A platform administrator checks which box answers at the concentrator's address; ObliWAN " +
        'writes nothing to that concentrator meanwhile.';
    case 'binding_mismatch:tls':
      return "A platform administrator checks the concentrator's api-ssl service and the certificate ObliWAN pinned.";
    default:
      return 'A platform administrator finds the full detail on the allocation page.';
  }
}

function formatDelay(ms: number): string {
  return ms < 60_000 ? `${Math.round(ms / 1000)} s` : `${Math.round(ms / 60_000)} min`;
}

/** Who reads an alert about this site, and whether the job's own text may be
 *  quoted to them: only when they may see the concentrator — a conflict lists
 *  OTHER secrets on it, and the shared CHR is the master tenant's. */
async function alertContext(
  siteId: number,
  tenantId: number,
  concentratorId: number | null,
): Promise<{ siteCode: string; siteLabel: string; quoteDetail: boolean }> {
  const site = (await db('sites').where({ id: siteId, tenant_id: tenantId }).first('code', 'name')) as
    | { code: string; name: string | null }
    | undefined;
  const chr = concentratorId === null
    ? undefined
    : ((await db('devices').where({ id: concentratorId }).first('tenant_id')) as { tenant_id: number } | undefined);
  return {
    siteCode: site?.code ?? `#${siteId}`,
    siteLabel: site ? `${site.code}${site.name && site.name !== site.code ? ` (${site.name})` : ''}` : `#${siteId}`,
    quoteDetail: chr !== undefined && chr.tenant_id === tenantId,
  };
}

/**
 * Raise the failure alert of `episode` — or, with `exhausted`, its second and
 * last one — unless it was raised already (read or not). Returns true when
 * this call raised it. Throws on a database error; the callers catch.
 */
async function raiseEpisodeAlert(
  site: { siteId: number; tenantId: number },
  episode: FailureEpisodeSummary,
  error: string,
  policy: Readonly<ConcentratorSecretRetryPolicy> | null,
  exhausted: boolean,
): Promise<boolean> {
  const { head } = episode;
  const stableKey = alertKey(site.siteId, episode.first.jobId, exhausted ? 'exhausted' : undefined);
  if (await alertExists(site.tenantId, stableKey)) return false;

  const ctx = await alertContext(site.siteId, site.tenantId, head.deviceId);
  const cls = classifyConcentratorFailure(head);
  const cause = failureCause(head);
  const what = `${reasonText(head)} [${head.errorKind ?? 'unknown'}].`;
  let message: string;
  let severity: 'warning' | 'down' = 'down';
  if (exhausted) {
    message =
      `The concentrator account of site ${ctx.siteLabel} is still not confirmed after ${episode.length} ` +
      `attempt(s): ${what} ObliWAN has stopped retrying it by itself: it needs a human now. Once the ` +
      `concentrator answers, ${ASK_AGAIN}.`;
  } else {
    message = `The concentrator account of site ${ctx.siteLabel} is not confirmed: ${what}`;
    if (cls === 'retryable' && policy) {
      // Not exhausted, so at least one attempt is left.
      const left = Math.max(1, policy.maxRetries - (episode.length - 1));
      const waits = Array.from({ length: left }, (_, i) => formatDelay(retryDelayMs(policy, episode.length + i)));
      severity = 'warning';
      message +=
        ` ObliWAN retries it by itself: at most ${left} more attempt(s) for this incident (a provisioning ` +
        `requested meanwhile counts as one), waiting ${waits.join(', ')} before each, as long as the ` +
        'concentrator stays managed and no kill switch is engaged. This alert is not repeated for each ' +
        'attempt; one more alert says so if they all fail.';
    } else if (cls === 'retryable') {
      severity = 'warning';
      message += ` The failure looks transient, but no automatic retry runs on this server: ${ASK_AGAIN}.`;
    } else {
      message += ` ObliWAN does not retry this: it needs a human. ${refusalHint(cause, site.siteId)}`;
    }
  }
  // The job's text holds no password (header, "THE PASSWORD").
  if (ctx.quoteDetail && error) message += ` Detail: ${error.slice(0, ALERT_DETAIL_MAX)}`;

  const added = await liveAlertService.add(site.tenantId, {
    severity,
    title: exhausted
      ? `Site ${ctx.siteCode}: concentrator account still not confirmed, retries stopped`
      : `Site ${ctx.siteCode}: concentrator account not confirmed`,
    message,
    navigateTo: `/sites/${site.siteId}`,
    siteId: site.siteId,
    stableKey,
  });
  return added !== null;
}

/** true when the site holds no allocation NOW (`readPppAccount`'s
 *  NOT_ALLOCATED, through the injected dependency): its job failed because
 *  somebody released the allocation meanwhile — a deliberate act, not an
 *  incident. Any other read failure is not "released". */
async function allocationReleased(siteId: number, tenantId: number): Promise<boolean> {
  try {
    await readConcentratorSecretSpec(siteId, tenantId);
    return false;
  } catch (err) {
    return (err as { reason?: unknown }).reason === 'NOT_ALLOCATED';
  }
}

/**
 * The live alert of a failure episode, in the SITE's tenant. Never throws.
 *
 * Deduplicated on `live_alerts.stable_key` WHATEVER its read state —
 * `liveAlertService.add` alone skips only an UNREAD duplicate, and an operator
 * who reads the first alert must not be told again at every automatic retry.
 * The key is the episode's first job, found by walking the whole episode
 * (`walkFailureEpisode`), so it does not move however long the episode lasts.
 * The failure that spends a retryable episode's LAST automatic attempt (by the
 * policy armed in this process) raises its `exhausted` alert instead. The ways
 * to be told twice: the first alert was trimmed (a tenant keeps its newest
 * 200) or cleaned up (30 days) while the episode went on.
 */
async function announceConcentratorSecretFailure(
  jobId: number,
  row: { tenant_id: number; site_id: number; outcome: ConcentratorSecretOutcome | null },
  error: string,
  errorKindIn: string | null,
): Promise<void> {
  try {
    let errorKind = errorKindIn;
    if (errorKind === null) {
      const jobRow = (await db('change_jobs').where({ id: jobId }).first('error_kind')) as
        | { error_kind: string | null }
        | undefined;
      errorKind = jobRow?.error_kind ?? null;
    }
    // The job's own row may not be terminal yet (failJob settles first): it is
    // walked as what it is about to become.
    const [self] = await loadSecretJobHistory(row.site_id, row.tenant_id, 1, jobId + 1);
    if (!self || self.jobId !== jobId) return;
    const current: SecretJobHistoryEntry = {
      ...self,
      status: 'failed',
      outcome: row.outcome,
      errorKind,
      errorMessage: error,
    };
    if (failureCause(current) === 'allocation_unavailable' && (await allocationReleased(row.site_id, row.tenant_id))) {
      logger.info(
        { jobId, siteId: row.site_id, tenantId: row.tenant_id },
        "concentrator secret: the job failed because its site's allocation was released meanwhile; nothing to announce",
      );
      return;
    }
    const episode = await walkFailureEpisode(current, row.site_id, row.tenant_id);
    if (!episode) return;
    const policy = concentratorSecretRetryPolicy();
    const exhausted =
      classifyConcentratorFailure(current) === 'retryable' && policy !== null && episode.length > policy.maxRetries;
    await raiseEpisodeAlert({ siteId: row.site_id, tenantId: row.tenant_id }, episode, error, policy, exhausted);
  } catch (err) {
    logger.warn(
      { err: err instanceof Error ? err.message : String(err), jobId, siteId: row.site_id },
      'concentrator secret: the failure could not be announced',
    );
  }
}

/**
 * The `exhausted` alert of the retryable episode `head` belongs to, for the
 * retry pass (concentratorSecretRetry.service) that finds every automatic
 * attempt made — under the same key as the failure path's, so whichever comes
 * first says it and the other is a no-op. Returns true when this call raised
 * it. Never throws.
 */
export async function announceConcentratorSecretExhausted(
  head: SecretJobHistoryEntry,
  siteId: number,
  tenantId: number,
  policy: Readonly<ConcentratorSecretRetryPolicy>,
): Promise<boolean> {
  try {
    const episode = await walkFailureEpisode(head, siteId, tenantId);
    if (!episode) return false;
    return await raiseEpisodeAlert({ siteId, tenantId }, episode, head.errorMessage ?? '', policy, true);
  } catch (err) {
    logger.warn(
      { err: err instanceof Error ? err.message : String(err), jobId: head.jobId, siteId },
      'concentrator secret: the end of the automatic retries could not be announced',
    );
    return false;
  }
}

/**
 * A job SUCCEEDED: if this site's newest alert of this job is an unresolved
 * failure, say once that the account is now confirmed (severity 'up', keyed
 * `...:resolved` on the episode's first job) and mark the site's unread
 * failure alerts read — an operator must not chase a site that is fine.
 * A success with no failure announced before it raises nothing. Never throws.
 */
async function announceConcentratorSecretResolved(
  jobId: number,
  row: { tenant_id: number; site_id: number },
): Promise<void> {
  try {
    const prefix = `${ALERT_PREFIX}${row.site_id}:`;
    const latest = (await db('live_alerts')
      .where({ tenant_id: row.tenant_id })
      .where('stable_key', 'like', `${prefix}%`)
      .orderBy('id', 'desc')
      .first('stable_key')) as { stable_key: string } | undefined;
    const m = latest ? ALERT_KEY_RE.exec(latest.stable_key) : null;
    if (!m || m[3] === 'resolved') return;
    const firstJobId = Number(m[2]);
    if (firstJobId >= jobId) return;
    const stableKey = alertKey(row.site_id, firstJobId, 'resolved');
    if (await alertExists(row.tenant_id, stableKey)) return;

    await db('live_alerts')
      .where({ tenant_id: row.tenant_id })
      .where('stable_key', 'like', `${prefix}%`)
      .whereNull('read_at')
      .update({ read_at: db.fn.now() });
    const ctx = await alertContext(row.site_id, row.tenant_id, null);
    await liveAlertService.add(row.tenant_id, {
      severity: 'up',
      title: `Site ${ctx.siteCode}: concentrator account confirmed`,
      message:
        `The concentrator account of site ${ctx.siteLabel} is confirmed: job #${jobId} read it on the ` +
        'concentrator. The failure announced earlier for this site is resolved.',
      navigateTo: `/sites/${row.site_id}`,
      siteId: row.site_id,
      stableKey,
    });
  } catch (err) {
    logger.warn(
      { err: err instanceof Error ? err.message : String(err), jobId, siteId: row.site_id },
      'concentrator secret: the resolution of an announced failure could not be announced',
    );
  }
}

// ============================================================================
// Enqueue
// ============================================================================

export interface EnsureInput {
  tenantId: number;
  siteId: number;
  requestedBy?: number | null;
}

export interface EnsureOptions {
  /** How long to keep retrying while another job holds the CHR. */
  busyWaitMs?: number;
}

const BUSY_POLL_MS = 500;
const DEFAULT_BUSY_WAIT_MS = 30_000;
const NO_BASE_STATE = '0'.repeat(64);
const ACTIVE: readonly string[] = ACTIVE_CHANGE_JOB_STATUSES;

function assertPositiveInt(value: unknown, name: string): void {
  if (!Number.isInteger(value) || (value as number) <= 0) {
    throw new TypeError(`${name} must be a positive integer`);
  }
}

function refused(reason: string, message: string): ConcentratorSecretState {
  return { state: 'failed', jobId: null, message, reason };
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * Make sure a job is deciding this site's secret on its CHR, and say where it
 * stands. Idempotent: while a job for the site is in flight, that job is
 * returned and no second one is queued. Otherwise a NEW job is queued even if
 * an earlier one succeeded — "provisioned" is only ever said by a job that has
 * just read the CHR, because a secret can be removed there by hand, and the
 * bench must not release a box on yesterday's reading. A job that finds the
 * secret already right writes nothing.
 *
 * Domain refusals (no site, no allocation, not a usable concentrator) come
 * back as `failed` with `jobId: null`; only programming errors throw.
 */
export async function ensureConcentratorSecret(
  input: EnsureInput,
  options: EnsureOptions = {},
): Promise<ConcentratorSecretState> {
  assertPositiveInt(input.tenantId, 'tenantId');
  assertPositiveInt(input.siteId, 'siteId');
  const { tenantId, siteId } = input;

  const site = (await db('sites').where({ id: siteId, tenant_id: tenantId }).first('id', 'code')) as
    | { id: number; code: string }
    | undefined;
  if (!site) return refused('site_not_found', `Site ${siteId} does not exist in tenant ${tenantId}.`);

  let spec: ConcentratorSecretSpec;
  try {
    // The password is dropped inside, on purpose: nothing is queued with it.
    spec = await readConcentratorSecretSpec(siteId, tenantId);
  } catch (err) {
    return refused(
      'not_allocated',
      `Site ${siteId} has no usable allocation: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  const comment = siteComment(site.code);
  const problem = specProblem(spec, comment);
  if (problem) return refused('invalid_allocation', `Cannot write this site's secret: ${problem}.`);
  const remoteAddress = hostAddress(spec.tunnelIp) as string;

  const chr = (await db('devices')
    .where({ id: spec.concentratorId })
    .first('id', 'tenant_id', 'name', 'role', 'status', 'is_managed')) as
    | { id: number; tenant_id: number; name: string; role: string; status: string; is_managed: boolean }
    | undefined;
  if (!chr || chr.role !== 'concentrator') {
    return refused('not_a_concentrator', `Device ${spec.concentratorId} is not a concentrator.`);
  }
  if (chr.tenant_id !== tenantId && chr.tenant_id !== MASTER_TENANT_ID) {
    return refused(
      'foreign_concentrator',
      `Concentrator ${chr.name} belongs to neither this tenant nor the master tenant.`,
    );
  }
  if (chr.status === 'disabled' || chr.status === 'quarantined') {
    return refused('concentrator_not_writable', `Concentrator ${chr.name} is ${chr.status}; nothing is written to it.`);
  }
  if (!chr.is_managed) {
    return refused(
      'concentrator_not_managed',
      `Concentrator ${chr.name} is not marked as managed, so ObliWAN does not write to it. ` +
        'Mark it managed on its device page to let ObliWAN create site accounts there.',
    );
  }

  const deadline = Date.now() + Math.max(0, options.busyWaitMs ?? DEFAULT_BUSY_WAIT_MS);
  for (;;) {
    // A job for this very site already in flight is THE answer.
    const inflight = await concentratorSecretJobInFlight(siteId, tenantId);
    if (inflight !== null) return getConcentratorSecretState(inflight);

    try {
      const jobId = await insertJob(chr, { tenantId, siteId, requestedBy: input.requestedBy ?? null }, spec, remoteAddress, comment);
      await mirrorPending(siteId, tenantId, jobId);
      const summary = { jobId, deviceId: chr.id, kind: CONCENTRATOR_SECRET_KIND, status: 'queued' };
      emitToTenantAudience(chr.tenant_id, SOCKET_EVENTS.JOB_QUEUED, summary, { deviceId: chr.id });
      emitToDevice(chr.id, SOCKET_EVENTS.JOB_QUEUED, summary);
      logger.info(
        { jobId, concentratorId: chr.id, siteId, tenantId, pppUsername: spec.pppUsername },
        'concentrator secret job QUEUED (additive /ppp/secret entry on the CHR)',
      );
      return { state: 'pending', jobId, message: `queued as job ${jobId} on ${chr.name}`, outcome: null };
    } catch (err) {
      const pg = err as { code?: string; constraint?: string };
      if (!(pg.code === '23505' && pg.constraint === 'change_jobs_one_in_flight_uq')) throw err;
    }

    // Another job holds the CHR (the per-device lock). Wait for it, bounded.
    if (Date.now() >= deadline) {
      const busy = (await db('change_jobs')
        .where({ device_id: chr.id })
        .whereIn('status', ACTIVE as string[])
        .first('id', 'kind')) as { id: string | number; kind: string } | undefined;
      return {
        state: 'pending',
        jobId: null,
        reason: 'concentrator_busy',
        message:
          `Concentrator ${chr.name} is busy` +
          (busy ? ` with job ${Number(busy.id)} (${busy.kind})` : '') +
          '; no job could be queued for this site yet. Retry in a moment.',
      };
    }
    await sleep(BUSY_POLL_MS);
  }
}

/**
 * The id of this site's concentrator_secret job still in flight, or null.
 *
 * `claimedOnly`: only a job a worker has CLAIMED (any active status but
 * 'queued'), for a caller that must not pull the allocation from under a
 * running job — the job re-reads the allocation just before it reads the CHR
 * (`applyConcentratorSecret`), so a release in the window between that read
 * and the `/ppp/secret/add` would leave a secret on the CHR for an allocation
 * that no longer exists. A job still QUEUED is harmless to such a caller: it
 * will read the allocation gone and fail without writing (and its failure is
 * not announced, `allocationReleased`); blocking on it would make a job no
 * worker claims block the release forever.
 */
export async function concentratorSecretJobInFlight(
  siteId: number,
  tenantId: number,
  options: { claimedOnly?: boolean } = {},
): Promise<number | null> {
  const statuses = options.claimedOnly ? ACTIVE.filter((s) => s !== 'queued') : ACTIVE;
  const row = (await db('concentrator_secret_jobs as c')
    .join('change_jobs as j', 'j.id', 'c.job_id')
    .where('c.site_id', siteId)
    .where('c.tenant_id', tenantId)
    .whereIn('j.status', statuses as string[])
    .orderBy('c.job_id', 'desc')
    .first('c.job_id')) as { job_id: string | number } | undefined;
  return row ? Number(row.job_id) : null;
}

async function insertJob(
  chr: { id: number; tenant_id: number },
  input: { tenantId: number; siteId: number; requestedBy: number | null },
  spec: ConcentratorSecretSpec,
  remoteAddress: string,
  comment: string,
): Promise<number> {
  const guard = concentratorSecretGuard();
  return db.transaction(async (trx) => {
    const inserted = (await trx('change_jobs')
      .insert({
        // The CHR's tenant: the queue loads a job's device scoped by it. The
        // requesting tenant is on concentrator_secret_jobs.
        tenant_id: chr.tenant_id,
        device_id: chr.id,
        plan_id: null,
        kind: CONCENTRATOR_SECRET_KIND,
        status: 'queued',
        attempt: 0,
        // A write is not retried silently; the next ensure() queues a new job.
        max_attempts: 1,
        // Plan-less: the job decides on what it reads on the CHR at apply time.
        base_state_hash: NO_BASE_STATE,
        // No dead-man is armed (CONCENTRATOR_SECRET_NO_DEADMAN): `degraded` is
        // the truth about this job's net. 009's confirmation CHECK does not
        // list this kind (migration 040), on purpose.
        safety_level: 'degraded',
        safety_peer_device_id: null,
        guard_verdict: guard.verdict,
        guard_reasons: JSON.stringify(guard.reasons),
        requested_by: input.requestedBy,
      })
      .returning('id')) as Array<{ id: string | number }>;
    const jobId = Number(inserted[0].id);
    await trx('concentrator_secret_jobs').insert({
      job_id: jobId,
      tenant_id: input.tenantId,
      site_id: input.siteId,
      ppp_username: spec.pppUsername,
      remote_address: remoteAddress,
      ppp_profile: spec.pppProfile,
      comment,
    });
    return jobId;
  });
}

async function mirrorPending(siteId: number, tenantId: number, jobId: number): Promise<void> {
  try {
    await deps.recordOutcome(siteId, tenantId, { state: 'pending', jobId, keepProvisioned: true });
  } catch (err) {
    logger.warn(
      { err: err instanceof Error ? err.message : String(err), jobId, siteId },
      'concentrator secret: the pending state could not be mirrored onto the allocation',
    );
  }
}

// ============================================================================
// Reading where a job stands
// ============================================================================

export async function getConcentratorSecretState(jobId: number): Promise<ConcentratorSecretState> {
  assertPositiveInt(jobId, 'jobId');
  const row = (await db('change_jobs as j')
    .join('concentrator_secret_jobs as c', 'c.job_id', 'j.id')
    .where('j.id', jobId)
    .first('j.status', 'j.error_kind', 'j.error_message', 'c.outcome', 'c.outcome_detail')) as
    | {
        status: ChangeJobStatus;
        error_kind: string | null;
        error_message: string | null;
        outcome: ConcentratorSecretOutcome | null;
        outcome_detail: string | null;
      }
    | undefined;
  if (!row) throw new TypeError(`job ${jobId} is not a concentrator_secret job`);

  if (row.status === 'succeeded') {
    return {
      state: 'provisioned',
      jobId,
      message: row.outcome_detail ?? 'provisioned',
      outcome: row.outcome,
    };
  }
  if (ACTIVE.includes(row.status)) {
    return { state: 'pending', jobId, message: `job ${jobId} is ${row.status}`, outcome: row.outcome };
  }
  return {
    state: 'failed',
    jobId,
    message: row.error_message ?? row.outcome_detail ?? `job ${jobId} ended ${row.status}`,
    reason: row.error_kind ?? row.status,
    outcome: row.outcome,
  };
}

/**
 * Block until the job is decided or `timeoutMs` has passed. A timeout returns
 * `pending` — never `failed`: the job may still finish, and saying it failed
 * would invite a second one onto a CHR the first is still writing.
 */
export async function waitForConcentratorSecret(
  jobId: number,
  timeoutMs: number,
  pollMs = 500,
): Promise<ConcentratorSecretState> {
  const deadline = Date.now() + Math.max(0, timeoutMs);
  for (;;) {
    const state = await getConcentratorSecretState(jobId);
    if (state.state !== 'pending') return state;
    if (Date.now() >= deadline) {
      return {
        ...state,
        message: `job ${jobId} was still in flight after ${Math.round(timeoutMs / 1000)}s (${state.message})`,
      };
    }
    await sleep(Math.max(50, Math.min(pollMs, deadline - Date.now())));
  }
}

/** `ensureConcentratorSecret` then `waitForConcentratorSecret`, one deadline. */
export async function provisionConcentratorSecret(
  input: EnsureInput,
  timeoutMs: number,
): Promise<ConcentratorSecretState> {
  const started = Date.now();
  const ensured = await ensureConcentratorSecret(input, { busyWaitMs: timeoutMs });
  if (ensured.state !== 'pending' || ensured.jobId === null) return ensured;
  return waitForConcentratorSecret(ensured.jobId, Math.max(0, timeoutMs - (Date.now() - started)));
}
