// ============================================================================
// @obliwan/shared — attaching the online legacy routers of the reconciliation
// ============================================================================
//
// The CHR <-> sites reconciliation shows sites whose concentrator account is
// allocated or adopted and ONLINE, yet no ObliWAN device: routers configured
// by hand long ago, reached through the tunnel on SSH with the historical
// `admin` account. `POST /api/reconcile/attach-devices[/preview]` turns them
// into devices, each one proven over SSH before its row exists (server:
// services/fleet/reconcileAttach.service.ts). Both routes are a PLATFORM
// ADMINISTRATOR's: the act binds logins of the shared concentrator to
// devices, which no tenant role may do. This file is the vocabulary
// the server answers in and the screen translates: closed reason codes, never
// a sentence the client would have to show untranslated.

import type { PppDuplicateSession } from './pppDuplicates';

/** Why a site is not attached, decided before anything is dialled. */
export const RECONCILE_ATTACH_SKIP_REASONS = [
  /** No site of this id in the session's workspace (another workspace's site
   *  answers exactly the same). */
  'not_found',
  /** No concentrator account matches the site. */
  'no_account',
  /** An account matches, but the site's addresses were never allocated or
   *  adopted ("Allocate addresses" first). */
  'not_allocated',
  /** Presence on the site's concentrator is degraded: its open sessions are
   *  the ones it last saw, not current ones, so nothing is dialled. */
  'concentrator_degraded',
  /** The account has no open PPP session (a router whose session is down
   *  is never dialled). */
  'offline',
  /** Several open sessions match the login without regard to case. */
  'ambiguous_session',
  /** The concentrator lists SEVERAL live sessions for the account at once
   *  (`/ppp/active`, as last read, and read again before the act dials): its
   *  tunnel address reaches whichever session the CHR routes to, so whatever
   *  answers there may be another box (a forgotten router on 4G, say).
   *  Nothing is dialled; the row names the sessions (`duplicateSessions`).
   *  The cleanup is made on the CHR. */
  'duplicate_sessions',
  /** The open session carries no tunnel address. */
  'no_session_address',
  /** The tunnel address is a public one: nothing is sent to it. */
  'public_address',
  /** The open session's address is not the one the site's allocation froze:
   *  whatever answers there was not given this site's account. */
  'address_mismatch',
  /** A device of this site already carries the account: nothing left to do. */
  'already_attached',
  /** Another device holds the login (named only when it is this workspace's). */
  'login_held',
  /** The site already has another router: attach its PPP account to it. */
  'site_has_device',
  /** No credential given, and `admin_password` is set at no level. */
  'no_vault_password',
  /** The vault's `admin_password` holds a control character. */
  'vault_password_invalid',
] as const;
export type ReconcileAttachSkipReason = (typeof RECONCILE_ATTACH_SKIP_REASONS)[number];

/** The skip reasons a typed credential clears. The server judges the
 *  credential LAST, so a site skipped for one of these passed every other
 *  rule: the screen keeps it selectable, for a credential typed by hand. */
export const RECONCILE_ATTACH_CREDENTIAL_REASONS: readonly ReconcileAttachSkipReason[] = [
  'no_vault_password',
  'vault_password_invalid',
];

/** Why the SSH proof refused a site. Nothing was created for it. */
export const RECONCILE_ATTACH_FAIL_REASONS = [
  'auth_failed',
  'unreachable',
  'timeout',
  'ssh_failed',
  /** The box answered no RouterOS 6 or 7 version: no family can be chosen. */
  'version_unknown',
  /** The box has no l2tp-client at all. */
  'l2tp_absent',
  /** The box's management tunnel does not dial with the site's account: its
   *  l2tp-client named `l2tp-mgmt` uses another one (or none), or, with no
   *  `l2tp-mgmt`, no client uses it. It is not this site's router. */
  'l2tp_mismatch',
  /** No l2tp-client is named `l2tp-mgmt` and SEVERAL carry the site's
   *  account: which one is the management tunnel cannot be told
   *  (managementTunnel.ts), so the box is not proven. */
  'l2tp_ambiguous',
  /** The serial the box reported belongs to another device. */
  'serial_held',
] as const;
export type ReconcileAttachFailReason = (typeof RECONCILE_ATTACH_FAIL_REASONS)[number];

export type ReconcileAttachReason = ReconcileAttachSkipReason | ReconcileAttachFailReason;

/** Sites per apply request. Each one is dialled (four at a time, at most 45 s
 *  each), and one request must stay well inside the proxy's 300 s read
 *  timeout: the screen sends the selection in slices of this size. */
export const RECONCILE_ATTACH_APPLY_MAX_SITES = 8;

/** The historical account used when no credential is typed. */
export const RECONCILE_ATTACH_DEFAULT_USERNAME = 'admin';

/** The vault variable that holds its password (resolved site > tenant >
 *  global > instance, like the bench's historical accounts). */
export const RECONCILE_ATTACH_VAULT_KEY = 'admin_password';

export type ReconcileAttachVaultScope = 'site' | 'tenant' | 'global' | 'instance';

/** A device a row names: the holder of the account or of the site, or the
 *  device just created. */
export interface ReconcileAttachDeviceRef {
  id: number;
  name: string;
}

// ── What follows an attach ──────────────────────────────────────────────────
//
// An attached router still logs in with its historical account over SSH. The
// request may ask, for every router it attaches, the two jobs that bring it in
// line (both a PLATFORM ADMINISTRATOR's choice, like the attach itself):
//   - `management_access`, queued right after the device row exists: creates
//     ObliWAN's own `obliwan` account, opens api-ssl with a pinned certificate
//     and switches the device's transports to that account
//     (server: services/change/managementAccess.service.ts);
//   - then `legacy_compliance` (the template fixes), which cannot be queued at
//     the same time (one job in flight per device): it is RECORDED as a
//     follow-up, and the worker queues it once management_access SUCCEEDED —
//     never otherwise (services/change/jobFollowup.service.ts).
// Neither arms a dead-man: the safety-net rule wants ONE explicit confirmation of that
// degraded safety level, given for the whole batch (`confirmNoDeadman`).

/** The follow-up options of an attach request. `applyCompliance` means
 *  nothing without `openManagementAccess` (it waits for that job). */
export interface ReconcileAttachFollowUpOptions {
  openManagementAccess: boolean;
  applyCompliance: boolean;
}

/** The request's defaults: both, as the operator decided (2026-10-05). */
export const RECONCILE_ATTACH_FOLLOWUP_DEFAULTS: ReconcileAttachFollowUpOptions = {
  openManagementAccess: true,
  applyCompliance: true,
};

export const RECONCILE_ATTACH_FOLLOWUP_KINDS = ['management_access', 'legacy_compliance'] as const;
export type ReconcileAttachFollowUpKind = (typeof RECONCILE_ATTACH_FOLLOWUP_KINDS)[number];

/**
 * The dry run's word on one follow-up of an eligible router:
 *  - `queue`  management_access will be queued right after the attach;
 *  - `after`  legacy_compliance will be recorded, and queued by the worker
 *             once management_access has succeeded;
 *  - `refused` the enqueue would be refused already (`reason`, `message`):
 *             the router is still attached, nothing follows.
 * Only what can be known before the device exists is judged (the kill
 * switch, the management range); the device's own rules are judged at the
 * act, and their refusal lands on the result row.
 */
export interface ReconcileAttachFollowUpPlan {
  kind: ReconcileAttachFollowUpKind;
  plan: 'queue' | 'after' | 'refused';
  reason: string | null;
  /** The job service's own sentence (French), untranslated; null otherwise. */
  message: string | null;
}

/**
 * What became of one follow-up of an ATTACHED router:
 *  - `queued`  the job is in the queue (`jobId`);
 *  - `pending` recorded (`followupId`): the worker queues it once
 *              management_access has succeeded, and closes it without a job
 *              otherwise;
 *  - `refused` the enqueue was refused (`reason`, `message`); the router is
 *              attached all the same;
 *  - `skipped` not attempted, because what it waits for was refused
 *              (`reason` = `management_access_refused`).
 */
export interface ReconcileAttachFollowUpResult {
  kind: ReconcileAttachFollowUpKind;
  status: 'queued' | 'pending' | 'refused' | 'skipped';
  jobId: number | null;
  followupId: number | null;
  reason: string | null;
  message: string | null;
}

/** One site in the dry run. Dials nothing; never carries a password. */
export interface ReconcileAttachPreviewRow {
  siteId: number;
  /** null for `not_found`. */
  code: string | null;
  name: string | null;
  /** The account the router dials (the CHR's spelling when online). */
  login: string | null;
  /** The open session's address, where SSH will be dialled. */
  tunnelIp: string | null;
  verdict: 'eligible' | 'skipped';
  reason: ReconcileAttachSkipReason | null;
  device: ReconcileAttachDeviceRef | null;
  /** eligible rows: the SSH account, and where its password comes from. */
  sshUsername: string | null;
  credentialSource: 'operator' | 'vault' | null;
  vaultScope: ReconcileAttachVaultScope | null;
  /** eligible rows: what the attach would queue after it, in order (empty
   *  when the request asks for nothing). Skipped rows: always empty. */
  followUps: ReconcileAttachFollowUpPlan[];
  /** `duplicate_sessions` rows only: the sessions the concentrator lists for
   *  the account (caller-id, address, uptime). Absent otherwise. */
  duplicateSessions?: PppDuplicateSession[];
}

export interface ReconcileAttachPreview {
  generatedAt: string;
  rows: ReconcileAttachPreviewRow[];
  counts: { eligible: number; skipped: number };
  /** The follow-up options this dry run judged (the request's, normalised:
   *  no compliance without management access). */
  followUpOptions: ReconcileAttachFollowUpOptions;
}

/** What the box reported, as stored on the device. */
export interface ReconcileAttachFacts {
  systemIdentity: string | null;
  serial: string | null;
  model: string | null;
  osVersion: string | null;
  family: string;
}

export interface ReconcileAttachResultRow {
  siteId: number;
  code: string | null;
  name: string | null;
  login: string | null;
  /** attached: created, proven, active and managed. failed: the proof
   *  refused, nothing was created. skipped: not eligible, nothing created —
   *  and nothing dialled, unless the site (its session, say) changed while
   *  its box was being proven, which the write's re-check catches. */
  outcome: 'attached' | 'failed' | 'skipped';
  reason: ReconcileAttachReason | null;
  /** The SSH transport's own words for a failed session (password scrubbed),
   *  untranslated; null otherwise. */
  detail: string | null;
  device: ReconcileAttachDeviceRef | null;
  facts: ReconcileAttachFacts | null;
  /** attached rows: what became of each follow-up asked for, in order (empty
   *  when none was asked for). Never fails the attach. Other rows: empty. */
  followUps: ReconcileAttachFollowUpResult[];
  /** `duplicate_sessions` rows only: the sessions the concentrator lists for
   *  the account. Absent otherwise. */
  duplicateSessions?: PppDuplicateSession[];
}

export interface ReconcileAttachResult {
  /** Ties this request's SSH commands (command audit) and audit entries. */
  correlationId: string;
  rows: ReconcileAttachResultRow[];
  counts: { attached: number; failed: number; skipped: number };
  /** The request asked for the attached routers to be put in learning mode
   *  (`learning`, default true over HTTP): the ids it put in learning (the
   *  same flag and audit entry as the learning page), or why it could not.
   *  Never fails the attach. null: not asked, or nothing attached. The
   *  learning CAPTURE is started by the caller once every slice is attached
   *  (one capture run per workspace at a time). */
  learning: { enabled: number[]; error: string | null } | null;
}
