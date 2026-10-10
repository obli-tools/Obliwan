// ============================================================================
// @obliwan/shared — "verify and re-apply the management access and the
// template fixes" over a whole workspace (written for a customer onboarding,
// where a number of routers failed their management_access job)
// ============================================================================
//
// Two steps, both on the reconciliation page (server:
// services/fleet/accessCheck.service.ts, `/api/reconcile/access-check`):
//
//   1. VERIFY — read-only towards every router. For each active MikroTik of the
//      workspace: its PPP presence (session up, a login held by several
//      sessions, a job already running on it), a LIVE proof of ObliWAN's
//      management access (a fresh API-SSL session with the recorded account,
//      the pinned certificate, the identity read and compared with the record),
//      the template fixes still missing (the legacy_compliance job's own read
//      and planner, over the job's own channel: SSH with the device's
//      credential), and the last management_access / legacy_compliance job that
//      FAILED, with its failed step and its redacted message — grouped at the
//      top of the result so the operator sees WHY routers fail. Persisted per
//      workspace (migration 092) so the page shows it after a reload.
//   2. RE-APPLY — on the operator's explicit click and confirmation, for the
//      devices the verification marked, through the existing doors: access
//      missing or broken -> a management_access job (the template fixes
//      promised after it when they are not known to be in place); access in
//      place but fixes missing -> a legacy_compliance job with exactly those
//      fixes. Everything else is skipped and says why. Refused on a
//      verification older than ACCESS_CHECK_FRESH_MS, or already re-applied.
//
// This file is the vocabulary the server answers in and the screen translates:
// closed codes, never a sentence the client would have to show untranslated —
// except the redacted job messages and door refusals, which are the change
// jobs' own (French) sentences, shown as they are.

import type { LegacyFixKey } from './legacyCompliance';
import type { PppDuplicateSession } from './pppDuplicates';

/** Routers dialled at once by a verification. */
export const ACCESS_CHECK_CONCURRENCY = 8;
/** One router's whole verification (the API-SSL proof, then the SSH read):
 *  past it the router is reported `unknown` (`budget_exceeded`) and the run
 *  moves on. */
export const ACCESS_CHECK_DEVICE_BUDGET_MS = 120_000;
/** A verification may be re-applied only this long after it STARTED (its
 *  oldest observation). */
export const ACCESS_CHECK_FRESH_MS = 30 * 60_000;
/** A run whose heartbeat is older than this was killed by a restart: it reads
 *  `interrupted`. The heartbeat moves with every router verified. */
export const ACCESS_CHECK_STALE_RUN_MS = 5 * 60_000;
/** Routers per verification, at most. */
export const ACCESS_CHECK_MAX_DEVICES = 2000;
/** Verifications kept per workspace (the older ones are deleted at start). */
export const ACCESS_CHECK_RUNS_KEPT = 10;

export const ACCESS_CHECK_RUN_STATUSES = ['running', 'done', 'interrupted'] as const;
export type AccessCheckRunStatus = (typeof ACCESS_CHECK_RUN_STATUSES)[number];

/** Who started a run: an operator's click, or the nightly verification
 *  (migration 093; server: fleet/accessCheckNightly.service.ts). */
export const ACCESS_CHECK_TRIGGERS = ['manual', 'nightly'] as const;
export type AccessCheckTrigger = (typeof ACCESS_CHECK_TRIGGERS)[number];

/** The time zone the nightly hour is read in. */
export const ACCESS_CHECK_NIGHTLY_TIME_ZONE = 'Europe/Paris';
/** A night whose hour was missed (the server was down, a run of the same
 *  workspace was still going) is caught up for this long after the hour, then
 *  given up: a verification — and a re-apply — is not started at midday. */
export const ACCESS_CHECK_NIGHTLY_CATCHUP_MS = 4 * 3_600_000;
/** Runs started for one workspace's night at most: a run a restart killed
 *  is started again (its heartbeat stopped: it reads `interrupted`). */
export const ACCESS_CHECK_NIGHTLY_MAX_ATTEMPTS = 3;
/** Workspaces verified at the same time by the nightly verification. */
export const ACCESS_CHECK_NIGHTLY_PARALLEL = 2;

/** Whose devices a run covered: the whole workspace (a platform admin), or
 *  the devices the caller's teams grant `rw` on. */
export const ACCESS_CHECK_SCOPES = ['tenant', 'teams'] as const;
export type AccessCheckScope = (typeof ACCESS_CHECK_SCOPES)[number];

/**
 * The PPP presence, judged BEFORE anything is dialled:
 *  - `up`             one live session for the device's login;
 *  - `down`           none: the router is never dialled;
 *  - `duplicated`     several live sessions for the login at once: the tunnel
 *                     address reaches whichever one the concentrator routes to
 *                     (pppDuplicates.service.ts), so nothing is dialled;
 *  - `unknown`        the concentrator could not be read live and presence is
 *                     degraded on it: nothing is dialled;
 *  - `not_applicable` no login on a concentrator (a standalone router): dialled.
 */
export const ACCESS_CHECK_PRESENCE_STATES = ['up', 'down', 'duplicated', 'unknown', 'not_applicable'] as const;
export type AccessCheckPresenceState = (typeof ACCESS_CHECK_PRESENCE_STATES)[number];

/**
 * ObliWAN's management access (API-SSL on 8729, its own `obliwan` account):
 *  - `ok`          a fresh TLS session with the recorded account, on the pinned
 *                  certificate, answered this device's identity, and both
 *                  channels use the `obliwan` account;
 *  - `missing`     no usable `routeros_api` transport recorded (`reason`);
 *  - `broken`      recorded, and the live proof failed (`reason`), or the
 *                  channel works under another account than `obliwan`;
 *  - `unknown`     ObliWAN could not run the proof (vault, budget);
 *  - `not_checked` presence or a running job kept it from being dialled.
 */
export const ACCESS_CHECK_ACCESS_STATES = ['ok', 'missing', 'broken', 'unknown', 'not_checked'] as const;
export type AccessCheckAccessState = (typeof ACCESS_CHECK_ACCESS_STATES)[number];

export const ACCESS_CHECK_ACCESS_REASONS = [
  // missing
  'no_transport',
  'transport_disabled',
  'not_tls',
  'not_8729',
  'no_credential',
  // broken
  'not_pinned',
  'account_not_switched',
  'tls',
  'auth',
  'timeout',
  'refused',
  'unreachable',
  'cert_mismatch',
  'identity_mismatch',
  'identity_unproven',
  // unknown
  'vault',
  'budget_exceeded',
  'internal',
] as const;
export type AccessCheckAccessReason = (typeof ACCESS_CHECK_ACCESS_REASONS)[number];

/**
 * The template fixes (the legacy_compliance job's read and plan):
 *  - `ok`            nothing the job would write (`unobserved` lists the fixes
 *                    whose state the read could not establish — the job writes
 *                    nothing for them either);
 *  - `fixes_needed`  `fixes` lists what the job would write;
 *  - `unknown`       the read could not be made (`reason`);
 *  - `not_checked`   presence or a running job kept it from being dialled.
 */
export const ACCESS_CHECK_COMPLIANCE_STATES = ['ok', 'fixes_needed', 'unknown', 'not_checked'] as const;
export type AccessCheckComplianceState = (typeof ACCESS_CHECK_COMPLIANCE_STATES)[number];

export const ACCESS_CHECK_COMPLIANCE_REASONS = [
  'no_ssh',
  'vault',
  'auth',
  'unreachable',
  'timeout',
  'ssh_failed',
  'identity_mismatch',
  'identity_unproven',
  'budget_exceeded',
  'internal',
] as const;
export type AccessCheckComplianceReason = (typeof ACCESS_CHECK_COMPLIANCE_REASONS)[number];

/** What the re-apply does for a device. */
export const ACCESS_CHECK_ACTIONS = ['management_access', 'legacy_compliance', 'none', 'skip'] as const;
export type AccessCheckAction = (typeof ACCESS_CHECK_ACTIONS)[number];

/**
 * Why the re-apply leaves a device alone:
 *  - `offline` / `duplicated` / `presence_unknown`  presence (above);
 *  - `busy`               a change job is queued or running on it;
 *  - `identity_mismatch`  a channel answered ANOTHER device's identity:
 *                         a human looks; the verification itself quarantines
 *                         nothing (like the infra analysis), any job's own
 *                         identity proof would;
 *  - `cert_mismatch`      api-ssl serves a certificate that is not the pinned
 *                         one (indistinguishable from an interception).
 *                         management_access never re-pins — it would refuse —
 *                         so a human checks, then re-pins from the device page;
 *  - `access_unknown` / `compliance_unknown`  the state could not be read;
 *  - `refused`            the job's own door would refuse it (`refusal`: its
 *                         code and sentence — no SSH channel, a public SSH
 *                         address, the management range unset…).
 */
export const ACCESS_CHECK_SKIP_REASONS = [
  'offline',
  'duplicated',
  'presence_unknown',
  'busy',
  'identity_mismatch',
  'cert_mismatch',
  'access_unknown',
  'compliance_unknown',
  'refused',
] as const;
export type AccessCheckSkipReason = (typeof ACCESS_CHECK_SKIP_REASONS)[number];

export const ACCESS_CHECK_JOB_KINDS = ['management_access', 'legacy_compliance'] as const;
export type AccessCheckJobKind = (typeof ACCESS_CHECK_JOB_KINDS)[number];

/** The last job of a kind on the device, when it did not succeed. */
export interface AccessCheckFailure {
  kind: AccessCheckJobKind;
  jobId: number;
  /** failed | aborted | rolled_back */
  status: string;
  finishedAt: string | null;
  /** The step that failed (bind_assert, lint, preflight_backup, apply,
   *  postcheck…); null when no step is marked failed. */
  step: string | null;
  /** The job's error code (`change_jobs.error_kind`). */
  errorKind: string | null;
  /** The failed step's redacted error, else the job's message — the job's own
   *  (French) sentence, cut. */
  message: string | null;
}

export interface AccessCheckRow {
  deviceId: number;
  deviceName: string;
  site: { id: number; code: string; name: string } | null;
  /** `pending` until the router was verified. */
  state: 'pending' | 'done';
  presence: {
    state: AccessCheckPresenceState;
    /** Where the presence comes from: the concentrator read live, or what
     *  presence recorded (the live read failed). */
    source: 'live' | 'recorded' | null;
    /** The sessions of a duplicated login (caller-id, uptime). */
    sessions: PppDuplicateSession[];
  } | null;
  busy: { jobId: number; kind: string } | null;
  access: {
    state: AccessCheckAccessState;
    reason: AccessCheckAccessReason | null;
    /** The transport's or the comparison's own words, cut; never a secret. */
    detail: string | null;
    /** The account the recorded API transport logs in with. */
    account: string | null;
  } | null;
  compliance: {
    state: AccessCheckComplianceState;
    reason: AccessCheckComplianceReason | null;
    detail: string | null;
    fixes: LegacyFixKey[];
    unobserved: LegacyFixKey[];
  } | null;
  failures: AccessCheckFailure[];
  action: AccessCheckAction | null;
  skipReason: AccessCheckSkipReason | null;
  /** The door's refusal when `skipReason` is `refused`: its code and sentence. */
  refusal: { kind: string; message: string } | null;
  /** `management_access` only: the template fixes are promised after it. */
  followUp: boolean;
  checkedAt: string | null;
  /** What the re-apply did for this device; null before. */
  reapply: AccessCheckReapplyRow | null;
}

export const ACCESS_CHECK_REAPPLY_STATUSES = ['queued', 'refused', 'skipped'] as const;
export type AccessCheckReapplyStatus = (typeof ACCESS_CHECK_REAPPLY_STATUSES)[number];

export interface AccessCheckReapplyRow {
  status: AccessCheckReapplyStatus;
  kind: AccessCheckJobKind | null;
  jobId: number | null;
  /** The promise of the template fixes after management_access. */
  followupId: number | null;
  /** The door's refusal code, or the skip reason. */
  reason: string | null;
  message: string | null;
  at: string;
}

/** One cause of failure: the last failed jobs grouped by kind, step, code and
 *  message (the message with what names the device — its name, login, site
 *  code, addresses, fingerprints — replaced, so one cause groups many
 *  routers). */
export interface AccessCheckCause {
  kind: AccessCheckJobKind;
  step: string | null;
  errorKind: string | null;
  message: string | null;
  count: number;
  deviceIds: number[];
}

export interface AccessCheckCounts {
  total: number;
  pending: number;
  needsAccess: number;
  needsFixes: number;
  ok: number;
  skipped: number;
}

/**
 * Why the AUTOMATIC re-apply after the nightly verification left a router the
 * verification marked (on top of every reason the button's own path has):
 *  - `stale`              verified more than ACCESS_CHECK_FRESH_MS before the
 *                         re-apply (a long run, or one resumed after a restart);
 *  - `learning`           the template fixes on a router in learning mode: no
 *                         template write while a human studies it;
 *  - `bench_unqualified`  a bench-prepared router not qualified yet (shipping);
 *  - `auto_failed_before` its previous AUTOMATIC re-apply of this kind failed
 *                         for the same cause: never retried by the night — it
 *                         stays in the alert for a human;
 *  - `cap`                the nightly cap of the workspace was reached.
 */
export const ACCESS_CHECK_AUTO_SKIP_REASONS = ['stale', 'learning', 'bench_unqualified', 'auto_failed_before', 'cap'] as const;
export type AccessCheckAutoSkipReason = (typeof ACCESS_CHECK_AUTO_SKIP_REASONS)[number];

/**
 * What the automatic re-apply did after a nightly run:
 *  - `running`            in progress;
 *  - `off`                the workspace's setting is off (the default);
 *  - `no_consent`         on, but no platform administrator's consent is on
 *                         record for the level the value comes from (or its
 *                         author is no longer an active administrator);
 *  - `kill_switch`        writes are stopped on the workspace;
 *  - `incomplete`         the run did not verify every router;
 *  - `nothing`            no router needed (or was allowed) a job;
 *  - `already_reapplied`  an operator re-applied the run first;
 *  - `done`               jobs were queued (or refused by their door).
 */
export const ACCESS_CHECK_AUTO_STATUSES = [
  'running', 'off', 'no_consent', 'kill_switch', 'incomplete', 'nothing', 'already_reapplied', 'done',
] as const;
export type AccessCheckAutoStatus = (typeof ACCESS_CHECK_AUTO_STATUSES)[number];

export interface AccessCheckAutoReapplySummary {
  status: AccessCheckAutoStatus;
  at: string;
  queued: number;
  refused: number;
  /** The routers the automatic path left alone, per reason. */
  held: Partial<Record<AccessCheckAutoSkipReason, number>>;
  /** The administrator whose standing consent the jobs carry. */
  consentBy: { id: number; username: string } | null;
  cap: number | null;
}

export interface AccessCheckRunView {
  runId: string;
  /** The run's number, as the jobs it queued name it ("#12"). */
  number: number;
  trigger: AccessCheckTrigger;
  status: AccessCheckRunStatus;
  scope: AccessCheckScope;
  /** null for a nightly run (and for a manual one whose author was deleted). */
  requestedBy: { id: number; username: string } | null;
  /** Routers found offline: not an access failure (presence is the
   *  concentrator's job), counted apart and never alerted here. */
  offline: number;
  /** The automatic re-apply after a nightly run; null otherwise or before. */
  autoReapply: AccessCheckAutoReapplySummary | null;
  /** Whether a re-apply was the operator's or the night's. */
  reapplyTrigger: AccessCheckTrigger | null;
  startedAt: string;
  finishedAt: string | null;
  /** Re-applicable now: done, not re-applied, started less than
   *  ACCESS_CHECK_FRESH_MS ago. */
  fresh: boolean;
  freshUntil: string;
  reappliedAt: string | null;
  counts: AccessCheckCounts;
  causes: AccessCheckCause[];
  rows: AccessCheckRow[];
}

export interface AccessCheckReapplyResult {
  runId: string;
  counts: { queued: number; refused: number; skipped: number };
  rows: Array<AccessCheckReapplyRow & { deviceId: number; deviceName: string }>;
}

/** The counts of a run's rows (the server's and the screen's one rule). */
export function accessCheckCounts(rows: readonly Pick<AccessCheckRow, 'state' | 'action'>[]): AccessCheckCounts {
  const c: AccessCheckCounts = { total: rows.length, pending: 0, needsAccess: 0, needsFixes: 0, ok: 0, skipped: 0 };
  for (const r of rows) {
    if (r.state === 'pending' || r.action === null) c.pending += 1;
    else if (r.action === 'management_access') c.needsAccess += 1;
    else if (r.action === 'legacy_compliance') c.needsFixes += 1;
    else if (r.action === 'none') c.ok += 1;
    else c.skipped += 1;
  }
  return c;
}

// ============================================================================
// The nightly verification's alerts — ONE per workspace and per CAUSE
// ============================================================================
//
// After every run that covered the WHOLE workspace and verified every router
// (a nightly one, or an operator's over the whole workspace), the routers are
// grouped by what is wrong with them; each cause is one live alert listing its
// routers, notified when it opens and when a router that did not have it at
// the previous run now does, never again while it stays the same, and closed
// by the first run that no longer finds it. A cause is a KEY: `kind` or
// `kind:reason`, the reason one of the verification's own codes.
//
//   access              the management access is missing or broken (reason:
//                       AccessCheckAccessReason, identity_mismatch excepted)
//   access_unknown      it could not be established (vault, budget, internal)
//   identity            a channel answered ANOTHER router's identity
//   compliance          template fixes are missing (reason: `fixes`)
//   compliance_unknown  the fixes could not be read (reason: the SSH's)
//   ppp_duplicated      the router's login is held by several PPP sessions
//
// NOT alerted here: an offline router, a router whose concentrator's presence
// is degraded (presence is the concentrator's job and has its own alerts), a
// router busy with a job, a bench-prepared router not qualified yet.

export const ACCESS_CHECK_ALERT_KINDS = [
  'access', 'access_unknown', 'identity', 'compliance', 'compliance_unknown', 'ppp_duplicated',
] as const;
export type AccessCheckAlertKind = (typeof ACCESS_CHECK_ALERT_KINDS)[number];

export interface AccessCheckAlertCause {
  kind: AccessCheckAlertKind;
  reason: string | null;
}

export function accessCheckCauseKey(c: AccessCheckAlertCause): string {
  return c.reason ? `${c.kind}:${c.reason}` : c.kind;
}

export function parseAccessCheckCauseKey(key: string): AccessCheckAlertCause | null {
  const i = key.indexOf(':');
  const kind = (i < 0 ? key : key.slice(0, i)) as AccessCheckAlertKind;
  if (!(ACCESS_CHECK_ALERT_KINDS as readonly string[]).includes(kind)) return null;
  const reason = i < 0 ? null : key.slice(i + 1);
  return { kind, reason: reason === '' ? null : reason };
}

/** The causes one verified router is alerted under (the header's rules). */
export function accessCheckAlertCauses(
  row: Pick<AccessCheckRow, 'presence' | 'busy' | 'access' | 'compliance'>,
): AccessCheckAlertCause[] {
  const p = row.presence;
  // A router out of its budget (or whose check threw) has no presence: ONE
  // cause for it, not the same unknown counted on both channels.
  if (p === null) {
    return row.access?.state === 'unknown' ? [{ kind: 'access_unknown', reason: row.access.reason ?? 'internal' }] : [];
  }
  if (p.state === 'duplicated') return [{ kind: 'ppp_duplicated', reason: null }];
  if (p.state !== 'up' && p.state !== 'not_applicable') return [];
  if (row.busy) return [];
  const a = row.access;
  const c = row.compliance;
  if (a?.reason === 'identity_mismatch' || c?.reason === 'identity_mismatch') return [{ kind: 'identity', reason: null }];
  const out: AccessCheckAlertCause[] = [];
  if (a && (a.state === 'missing' || a.state === 'broken')) out.push({ kind: 'access', reason: a.reason ?? 'internal' });
  else if (a?.state === 'unknown') out.push({ kind: 'access_unknown', reason: a.reason ?? 'internal' });
  if (c?.state === 'fixes_needed') out.push({ kind: 'compliance', reason: 'fixes' });
  else if (c?.state === 'unknown') out.push({ kind: 'compliance_unknown', reason: c.reason ?? 'internal' });
  return out;
}

/** An open alert of the workspace, as the reconciliation page lists it. */
export interface AccessCheckOpenAlert {
  cause: string;
  kind: AccessCheckAlertKind;
  reason: string | null;
  count: number;
  openedAt: string;
  /** The run that last confirmed it. */
  lastRun: number;
  /** Routers of the cause the night no longer re-applies on its own (its
   *  previous automatic re-apply failed for this cause). */
  suspended: number;
}

/** The nightly verification of the workspace, as its settings resolve, and
 *  its open alerts (GET /reconcile/access-check/schedule). */
export interface AccessCheckScheduleView {
  nightly: {
    enabled: boolean;
    /** 0-23, in ACCESS_CHECK_NIGHTLY_TIME_ZONE. */
    hour: number;
    timeZone: string;
    /** The next nightly start, when enabled. */
    nextRunAt: string | null;
  };
  autoReapply: {
    enabled: boolean;
    cap: number;
    /** The administrator whose consent the automatic jobs carry, when the
     *  setting is on and a consent is on record for its level. */
    consent: { userId: number; username: string; at: string } | null;
  };
  openAlerts: AccessCheckOpenAlert[];
}
