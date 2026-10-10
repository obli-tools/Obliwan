// ============================================================================
// @obliwan/shared — the vocabulary of a SAFE WRITE
// ============================================================================
//
// This file is the contract of the only path along which ObliWAN is allowed to
// modify an equipment: the `change_jobs` queue. Migration `009_change.ts`
// mirrors every union below as a CHECK constraint, `jobQueue` walks the state
// machine declared here, `mgmtPathGuard` returns the verdict declared here, and
// the client renders the live job screen from the same names.
//
// THE RULE THIS FILE EXISTS TO SERVE:
//
//   Nothing writes to a device outside `change_jobs`, with a per-device lock, a
//   frozen plan, an anti-lockout guard and an ARMED dead-man.
//
// Why the vocabulary is worth a file of its own: the difference between
// `INDETERMINATE` and `ACCEPT`, and the difference between `degraded` and
// `armed`, are the two places where a wrong synonym turns "we refused" into
// "we pushed". Both are unions here, both are CHECK constraints in Postgres,
// and neither is a boolean anywhere.
//
// SECRETS: nothing in this file ever carries a secret value. The
// complete rendered config exists in memory only, on the vault -> equipment
// path. Everything named `*Redacted` in the step/audit shapes is the masked
// version, and it is the ONLY version the database, the UI and the logs see.

import type { SafetyLevel } from './device';

// ============================================================================
// What a job is
// ============================================================================

/**
 * The eight things a job can be asked to do. `export` and `backup` are
 * READ-ONLY and are jobs anyway, on purpose: routing them through the same
 * queue is what makes "one operation at a time per device" true rather than
 * mostly true — a backup pulled while an apply is mid-flight reads a
 * half-applied box.
 *
 * `concentrator_secret` targets a CONCENTRATOR (the CHR), never a CPE: it adds
 * one site's L2TP account to `/ppp/secret`
 * (services/change/concentratorSecret.service.ts). It writes, so it is a write
 * kind and goes through the queue — but it is ADDITIVE ONLY (it never sets
 * or removes an existing secret, and refuses when one differs), so its job
 * takes no pre-change backup and arms no dead-man, and records both as skipped
 * steps that say why. Only that service enqueues it: the generic change API's
 * kind enum (changes.controller) leaves it out, and a rollout never enqueues
 * it.
 *
 * `os_upgrade` brings ONE RouterOS 7 device to a pinned RouterOS release
 * (services/firmware/osUpgrade.service.ts): the router fetches the exact
 * packages of that release, reboots, and the job proves the version on a new
 * socket. It never touches the RouterBOARD firmware — that is `firmware`'s
 * territory (TR-069), not this kind's. It takes a pre-change backup and arms
 * NO dead-man (a scheduler script cannot un-install a RouterOS release), and
 * says so in a skipped step; its protection is the rollout's canary waves and
 * health gate. Only that service enqueues it (it needs a target version, which
 * the generic enqueue has no field for), directly or for a rollout wave; the
 * generic change API leaves it out, and `enqueueChangeJob` refuses it.
 *
 * `concentrator_link` targets a CONCENTRATOR too: it adds, on the CHR, the
 * WireGuard interface, address, peer, firewall accepts and srcnat that let the
 * ObliWAN host reach 100.64.0.0/10 through it
 * (services/concentratorLink/link.service.ts, shared/src/concentratorLink.ts).
 * It is ADDITIVE ONLY — it never sets, moves or removes an item it did not add,
 * and refuses when one it would add exists differently. It takes a pre-change
 * backup before its first write and arms no dead-man (nothing it adds can cut
 * the management path ObliWAN uses, which is the CHR's public address), and
 * records that as a skipped step. Only that service enqueues it, on an explicit
 * platform-admin request; the generic change API's kind enum
 * (changes.controller) leaves it out and a rollout's kind CHECK (047) does not
 * admit it.
 *
 * `management_access` opens ObliWAN's management API on a MikroTik already in
 * service: api-ssl on 8729, restricted to the management range, serving a
 * certificate made ON the router (the lines of shared/src/managementAccess.ts,
 * the same ones the bench compile writes). It travels over SSH — the channel
 * such a router answers on today — proves the box's identity there, takes a
 * pre-change backup pulled by SFTP before its first write, sends nothing but
 * `/certificate` and the api-ssl service, reads the result back, then records
 * the device's RouterOS API transport (TLS, 8729) and pins its certificate on a
 * first identity read (services/change/managementAccess.service.ts). It arms no
 * dead-man: SSH, the path it travels on, is never written. Only that service
 * enqueues it, for one device or for a rollout wave (migration 058 admits it
 * in the rollout kind CHECK); the generic change API's kind enum
 * (changes.controller) leaves it out.
 *
 * A client choice list of what the GENERIC change API accepts must therefore
 * leave `concentrator_secret`, `os_upgrade`, `concentrator_link`,
 * `management_access`, `lte_apn` and `legacy_compliance` out, or it offers a kind the server
 * refuses with a 400.
 *
 * `legacy_compliance` brings a MikroTik in service up to the corrected customer
 * templates: the statements of shared/src/legacyCompliance.ts, over SSH with
 * the device's existing credential, a pre-change backup pulled by SFTP before the
 * first write, then a read-back on a fresh session. The l2tp-client line (last,
 * behind a self-revert started on the router) is retired since 2026-10-05
 * (`LEGACY_RETIRED_FIXES`): read, never written
 * (services/change/legacyCompliance.service.ts). Only that service enqueues it,
 * for one device or for a rollout wave (migration 066 admits it in the rollout
 * kind CHECKs).
 *
 * `site_rename` renames a site's router TOGETHER: the PPP login on the shared
 * CHR (a second secret copied beside the old one, the old removed once the new
 * session is up), the user of the router's l2tp-mgmt (behind a self-revert
 * started on the router), its /system identity, the device row and, when asked,
 * the site code (services/change/siteRename.service.ts, shared/src/siteRename.ts).
 * Only that service enqueues it, platform admins only, for one device or a bulk
 * selection of sites; no rollout admits it.
 *
 * Mirrors `change_jobs.kind` (widened by migrations 040,
 * 047, 053, 058, 065, 066 and 074).
 */
export const CHANGE_JOB_KINDS = [
  'push',     // apply a frozen plan
  'site_rename', // rename a site's router: CHR login, management tunnel user, identity, device row (siteRename.ts)
  'export',   // pull the config (read-only)
  'backup',   // take a backup (read-only)
  'restore',  // push a previously taken backup back onto the box
  'reboot',
  'firmware',
  'concentrator_secret', // add one site's /ppp/secret on the CHR (additive only)
  'os_upgrade', // bring one RouterOS 7 device to a pinned release (never the RouterBOARD firmware)
  'concentrator_link', // add the ObliWAN WireGuard link on the CHR (additive only)
  'management_access', // open api-ssl (8729, management range, on-router certificate) over SSH
  'lte_apn', // point lte1 at one APN profile of the catalogue, over SSH (lteApn.ts)
  'legacy_compliance', // the corrected-template fixes on a router in service, over SSH (legacyCompliance.ts)
  'infra_account', // one site's account on the customer's own infrastructure concentrator (infraConcentrator.ts)
  'wan_link', // switch WAN1 between dhcp / pppoe / static by one self-reverting script on the router (wanLink.ts)
] as const;
export type ChangeJobKind = (typeof CHANGE_JOB_KINDS)[number];

/**
 * The kinds that MODIFY the equipment. Everything the safety machinery is
 * mandatory for — pre-change backup, guard verdict, dead-man — is keyed off
 * this set, in the code and in the CHECK constraints of migration 009.
 *
 * `reboot` is in here deliberately: a box whose running config was never saved
 * comes back different, which is a change even though we typed no config line.
 *
 * `concentrator_secret` is in here because it writes. It is the one write kind
 * whose job takes a branch of its own in `apply.service.ts` (no backup, no
 * dead-man, a guard verdict of its own), and migration 040 adds it to 009's
 * guard-required CHECK but deliberately NOT to the pre-change-backup or the
 * degraded-confirmation CHECK.
 *
 * `os_upgrade` is in here because it writes packages onto the box and reboots
 * it. Its job is a branch of its own in `apply.service.ts` too; migration 047
 * adds it to the guard-required and the degraded-confirmation CHECKs, and NOT
 * to 009's pre-change-backup CHECK — a device already at the target ends the
 * job as a no-op `succeeded` that never had anything to back up. The rule is
 * restated on `os_upgrade_jobs` instead: no package fetch recorded without a
 * backup id beside it.
 *
 * `concentrator_link` is in here because it writes on the CHR. Its job is a
 * branch of its own in `apply.service.ts`; migration 053 adds it to the
 * guard-required and the degraded-confirmation CHECKs (the request that
 * queues it carries the operator's explicit confirmation), and NOT to 009's
 * pre-change-backup CHECK — a re-run that finds every item already present
 * writes nothing and takes no backup. The rule is restated on
 * `concentrator_link_jobs`: no write recorded without a backup id beside it.
 *
 * `management_access` is in here because it writes certificates and the
 * api-ssl service. Its job is a branch of its own in `apply.service.ts`;
 * migration 058 adds it to the guard-required and the degraded-confirmation
 * CHECKs (no dead-man is armed, and the request that queues it carries the
 * operator's explicit confirmation), and NOT to 009's pre-change-backup CHECK
 * — a re-run that finds api-ssl already as it would leave it writes nothing
 * and takes no backup. The rule is restated on `management_access_jobs`: no
 * write recorded without a backup id beside it.
 *
 * `lte_apn` is in here because it writes `/interface lte apn` and lte1's
 * `apn-profiles`. Its job is a branch of its own in `apply.service.ts`;
 * migration 065 adds it to the guard-required and the degraded-confirmation
 * CHECKs (no dead-man: the job REFUSES unless the management path provably
 * leaves through another interface), and NOT to the pre-change-backup CHECK — a
 * router already on the chosen profile is a no-op. The rule is restated on
 * `lte_apn_jobs`: no write recorded without a backup id beside it.
 *
 * `legacy_compliance` is in here because it writes `/tool mac-server`, `/tool
 * romon`, the ssh and winbox address lists and the DNS-Amp filter rules (the
 * l2tp-clients' random-source-port is retired: read, never written).
 * Its job is a branch of its own in `apply.service.ts`; migration 066 adds it to
 * the guard-required and the degraded-confirmation CHECKs (no on-box dead-man: a
 * self-revert started with `:execute` guards only the dormant l2tp line), and NOT to the
 * pre-change-backup CHECK — a router already conforming is a no-op. The rule is
 * restated on `legacy_compliance_jobs`: no write recorded without a backup id.
 *
 * `site_rename` is in here because it writes on the CHR (a /ppp/secret copied,
 * then the old one removed) and on the router (the management tunnel's user and
 * the identity). Migration 088 adds it to the guard-required and the
 * degraded-confirmation CHECKs (no on-box dead-man: a self-revert started with
 * `:execute` guards the cut line), and NOT to the pre-change-backup CHECK — a
 * rename that only settles the CHR or the device row writes nothing on the
 * router. The rule is restated on `site_rename_jobs`.
 *
 * `infra_account` is in here because it writes one site's account on the
 * customer's own infrastructure concentrator (a /ppp/secret on a RouterOS CHR;
 * OPNsense refuses until implemented). Migration 074 adds it to the
 * guard-required CHECK only, like 040 did for `concentrator_secret`: an add is
 * additive, a revoke removes only an entry ObliWAN itself added, no dead-man.
 */
export const WRITE_JOB_KINDS = [
  'push',
  'site_rename',
  'restore',
  'reboot',
  'firmware',
  'concentrator_secret',
  'os_upgrade',
  'concentrator_link',
  'management_access',
  'lte_apn',
  'legacy_compliance',
  'infra_account',
  // `wan_link` writes ether1-WAN1's link (the pppoe-client, the DHCP client,
  // the fixed address, NW-WAN1 / WAN1-GW and the WAN1 netwatch) by ONE script
  // started on the router with `:execute`, which reverts by itself unless the
  // new link carries traffic within its delay (services/change/wanLink.service.ts).
  // Migration 090 adds it to the guard-required and the degraded-confirmation
  // CHECKs (no on-box dead-man), NOT to the pre-change-backup CHECK — a router
  // already on the target writes nothing. The rule is restated on
  // `wan_link_jobs`. Rollouts admit it (090).
  'wan_link',
] as const;
export type WriteJobKind = (typeof WRITE_JOB_KINDS)[number];

export function isWriteJobKind(kind: ChangeJobKind): kind is WriteJobKind {
  return (WRITE_JOB_KINDS as readonly string[]).includes(kind);
}

// ============================================================================
// The state machine
// ============================================================================

/**
 * Every state a job passes through, in the order it passes through them.
 *
 * The list is finer-grained than the one sketched in the design
 * (`queued|running|soaking|...`) and that is the point: `running` cannot tell a
 * crash-recovery routine whether the box was written to. `backing_up` and
 * `arming` are recoverable — nothing was pushed yet. `applying` is not: a
 * worker that dies there must NEVER be replayed by another worker, because the
 * only thing worse than a half-applied router is a twice-applied one.
 * `WRITE_COMMITTED_STATUSES` below is exactly that frontier.
 *
 *  queued       accepted, waiting for a worker and for its maintenance window.
 *  claimed      a worker holds the lease (`FOR UPDATE SKIP LOCKED`). No I/O to
 *               the device has happened yet beyond identity assertion.
 *  backing_up   The mandatory pre-change backup is being taken. A push that
 *               cannot produce a backup does not proceed — it fails here.
 *  arming       the dead-man is being installed (see SafetyLevel). For a
 *               `degraded` device this state records that no net could be
 *               armed and that the operator confirmed it anyway.
 *  applying     THE WRITE. Past this point recovery is inspection, not retry.
 *  verifying    reconnected ON A NEW SOCKET (never the socket that carried the
 *               change) and re-asserted the binding; post-conditions checked.
 *  soaking      the change is live and being watched for the soak window
 *               (5 min). The dead-man is STILL ARMED throughout.
 *  disarming    post-conditions held; removing the dead-man, with retry until
 *               it succeeds. A job is not `succeeded` while a live router
 *               still carries a scheduler that will revert it at next boot.
 *  succeeded    applied, verified, soaked, disarmed.
 *  rolled_back  the device restored itself (or was restored). The config on the
 *               box is the pre-change config. THIS IS A SUCCESSFUL OUTCOME of
 *               the safety machinery, not an error.
 *  failed       we stopped, and the box is in a state we described.
 *  aborted      cancelled before anything was written.
 */
export const CHANGE_JOB_STATUSES = [
  'queued',
  'claimed',
  'backing_up',
  'arming',
  'applying',
  'verifying',
  'soaking',
  'disarming',
  'succeeded',
  'rolled_back',
  'failed',
  'aborted',
] as const;
export type ChangeJobStatus = (typeof CHANGE_JOB_STATUSES)[number];

/**
 * The states in which a job holds its device.
 *
 * `queued` IS in this list, and that is a deliberate refusal: the partial
 * unique index `change_jobs_one_in_flight_uq` is built on exactly this set, so
 * a second job cannot even be QUEUED against a device that already has one
 * pending. Stacking two plans compiled against the same `base_state_hash` means
 * the second one describes a world the first one already destroyed.
 * "Un plan bloqué coûte une réunion ; un site coupé coûte un camion."
 */
export const ACTIVE_CHANGE_JOB_STATUSES = [
  'queued', 'claimed', 'backing_up', 'arming', 'applying', 'verifying', 'soaking', 'disarming',
] as const;
export type ActiveChangeJobStatus = (typeof ACTIVE_CHANGE_JOB_STATUSES)[number];

export const TERMINAL_CHANGE_JOB_STATUSES = [
  'succeeded', 'rolled_back', 'failed', 'aborted',
] as const;
export type TerminalChangeJobStatus = (typeof TERMINAL_CHANGE_JOB_STATUSES)[number];

/**
 * The point of no return. A job found in one of these states with an expired
 * lease has had bytes written to a production router by a worker that is now
 * dead. The reaper MUST NOT requeue it: it marks it for human inspection and
 * lets the on-box dead-man do its job. Requeueing here is how you apply the
 * same change twice and disarm a net you did not arm.
 */
export const WRITE_COMMITTED_STATUSES = [
  'applying', 'verifying', 'soaking', 'disarming',
] as const;
export type WriteCommittedStatus = (typeof WRITE_COMMITTED_STATUSES)[number];

export function isActiveJobStatus(s: ChangeJobStatus): s is ActiveChangeJobStatus {
  return (ACTIVE_CHANGE_JOB_STATUSES as readonly string[]).includes(s);
}
export function isTerminalJobStatus(s: ChangeJobStatus): s is TerminalChangeJobStatus {
  return (TERMINAL_CHANGE_JOB_STATUSES as readonly string[]).includes(s);
}
/** True once the device may already carry part of the change. */
export function hasWriteCommitted(s: ChangeJobStatus): boolean {
  return (WRITE_COMMITTED_STATUSES as readonly string[]).includes(s);
}

/**
 * The only transitions that exist. Read it as a safety property, not as
 * bookkeeping:
 *
 *  - `claimed -> queued` is the ONLY backward edge, and it exists solely so a
 *    worker that died before touching the box releases its device.
 *  - `aborted` is reachable only from the states before the write. You cannot
 *    cancel a change that is already going onto a router; you can only let the
 *    machinery finish or let the dead-man fire.
 *  - every state from `arming` on can reach `rolled_back`, because from the
 *    moment a dead-man exists it can fire — including while we are disarming.
 */
export const CHANGE_JOB_TRANSITIONS: Readonly<Record<ChangeJobStatus, readonly ChangeJobStatus[]>> =
  Object.freeze({
    queued:      ['claimed', 'aborted'],
    claimed:     ['backing_up', 'queued', 'failed', 'aborted'],
    backing_up:  ['arming', 'failed', 'aborted'],
    arming:      ['applying', 'rolled_back', 'failed', 'aborted'],
    applying:    ['verifying', 'rolled_back', 'failed'],
    verifying:   ['soaking', 'rolled_back', 'failed'],
    soaking:     ['disarming', 'rolled_back', 'failed'],
    disarming:   ['succeeded', 'rolled_back', 'failed'],
    succeeded:   [],
    rolled_back: [],
    failed:      [],
    aborted:     [],
  } as Record<ChangeJobStatus, readonly ChangeJobStatus[]>);

export function canTransition(from: ChangeJobStatus, to: ChangeJobStatus): boolean {
  return CHANGE_JOB_TRANSITIONS[from].includes(to);
}

// ============================================================================
// Steps — the ordered trace of what was attempted
// ============================================================================

/**
 * Mirrors `change_job_steps.kind`.
 *
 * The design lists nine names; four are added here and each one is
 * a step an operator must be able to SEE happen, not infer:
 *
 *  - `bind_assert`    Identity binding. `deviceBinding.assertTargetBinding()` on a brand-new
 *                     connection is the only authorised way to reach a device.
 *                     A PPP pool reassigns tunnel IPs; without this step we
 *                     push client A's config onto client B's router. It is a
 *                     step so that its absence from a job's trace is visible.
 *  - `guard`          The mgmtPathGuard verdict, recorded with its reasons.
 *  - `rollback`       what the device did to itself, observed. A rolled-back
 *                     job with no `rollback` step means we ASSUMED the restore.
 *  - `record_outcome` the safety-net rule. Writing the row into `apply_outcomes` is part of
 *                     the job, because the empirical corpus is only worth
 *                     anything if it is never skipped.
 */
export const CHANGE_STEP_KINDS = [
  'lint',
  'bind_assert',
  'guard',
  'preflight_backup',
  'arm_deadman',
  'apply',
  'reconnect',
  'postcheck',
  'soak',
  'disarm',
  'rollback',
  'cleanup',
  'record_outcome',
] as const;
export type ChangeStepKind = (typeof CHANGE_STEP_KINDS)[number];

/** Mirrors `change_job_steps.status`. `skipped` is explicit so that "we did not
 *  arm a dead-man" is a recorded fact and never an absent row. */
export const CHANGE_STEP_STATUSES = [
  'pending', 'running', 'succeeded', 'failed', 'skipped',
] as const;
export type ChangeStepStatus = (typeof CHANGE_STEP_STATUSES)[number];

// ============================================================================
// The guard, and the reason `INDETERMINATE` is not `ACCEPT`
// ============================================================================

/**
 * The anti-lockout guard's answer.
 *
 *  ACCEPT         the guard PROVED the management path survives the change.
 *  REJECT         the guard PROVED the change cuts the management path.
 *  INDETERMINATE  the guard could not prove either. It is a polite refusal and
 *                 it DOES NOT EQUAL ACCEPT. Anywhere this union is narrowed
 *                 with `!== 'REJECT'`, the milestone is broken: the whole point
 *                 of a partial model (N5) is that it knows its own partiality
 *                 and declines to conclude beyond it.
 *
 * Only `ACCEPT` lets a job through without an override. Both other values
 * require `override_reason` + `overridden_by` in `change_jobs`, which is a
 * CHECK constraint, not a convention.
 */
export const GUARD_VERDICTS = ['ACCEPT', 'REJECT', 'INDETERMINATE'] as const;
export type GuardVerdict = (typeof GUARD_VERDICTS)[number];

/** The single predicate every caller must use. Written once, here, so that no
 *  call site gets to invent `verdict !== 'REJECT'`. */
export function guardAllowsApply(v: GuardVerdict): boolean {
  return v === 'ACCEPT';
}

/** True when proceeding requires a recorded override (reason + operator). */
export function guardRequiresOverride(v: GuardVerdict): boolean {
  return v !== 'ACCEPT';
}

/**
 * The guard proved harm. These are the reasons a `REJECT` carries.
 *
 * `TUNNEL_CRITICAL` and `ACCEPT_BECOMES_DROP` are the two the destructive
 * acceptance test of safe apply fires: pushing `chain=input action=drop` onto the box
 * we administer through flips the simulated verdict of the CHR -> management
 * packet from accept to drop, on a rule the tunnel depends on.
 */
export const GUARD_REJECT_REASONS = [
  /** The op touches a rule, address or interface on the CHR -> management path. */
  'TUNNEL_CRITICAL',
  /** After the change there is no route back to the management source. */
  'NO_ROUTE',
  /** The simulated verdict for the management packet flips accept -> drop. */
  'ACCEPT_BECOMES_DROP',
  /** The chain's default policy becomes drop with no preceding accept for us. */
  'DEFAULT_POLICY_DROP',
  /** The address we dial is removed or moved to another interface. */
  'MGMT_ADDRESS_REMOVED',
  /** The interface carrying the tunnel is disabled or deleted. */
  'MGMT_INTERFACE_DISABLED',
  /** The management service (API / SSH) is disabled, moved or address-filtered
   *  away from us. Losing the door is losing the room. */
  'MGMT_SERVICE_DISABLED',
  /** A NAT change breaks the return path of the management flow. */
  'NAT_BREAKS_RETURN_PATH',
  /** The change is disruptive and NO net could be armed at all. */
  'DEADMAN_UNAVAILABLE',
] as const;
export type GuardRejectReason = (typeof GUARD_REJECT_REASONS)[number];

/**
 * The guard could not conclude. Never an `ACCEPT`.
 *
 * `COVERAGE_INCOMPLETE` is N3 and it is the most common one in practice: the
 * NCM does not cover a forwarding-relevant section of this box, so the
 * simulation is running on a model with a hole in it, and a hole is exactly
 * where the rule that cuts you lives.
 */
export const GUARD_INDETERMINATE_REASONS = [
  /** N3: a forwarding-relevant section is not covered by the NCM snapshot. */
  'COVERAGE_INCOMPLETE',
  /** N5: a rule on the analysed path uses a match we do not model. */
  'UNMODELED_MATCH',
  /** Chain order could only be partially analysed. */
  'ORDER_PARTIAL',
  /** We do not know which path we manage this device through. */
  'NO_MGMT_PATH_KNOWN',
  /** `armed_by_peer` was claimed but the co-located peer could not be verified. */
  'PEER_UNVERIFIED',
  /** The device moved under us: `base_state_hash` no longer matches. */
  'BASE_STATE_STALE',
  /** The brand driver has no forwarding model at all (non-MikroTik, v1). */
  'NO_FORWARDING_MODEL',
] as const;
export type GuardIndeterminateReason = (typeof GUARD_INDETERMINATE_REASONS)[number];

export const GUARD_REASONS = [
  ...GUARD_REJECT_REASONS,
  ...GUARD_INDETERMINATE_REASONS,
] as const;
export type GuardReason = GuardRejectReason | GuardIndeterminateReason;

/**
 * Which verdict a reason implies. THE source of truth: a service that collects
 * reasons must derive the verdict from this map rather than deciding twice.
 * No reason maps to `ACCEPT` — an accept has no reason, it has a proof.
 */
export const GUARD_REASON_VERDICT: Readonly<Record<GuardReason, Exclude<GuardVerdict, 'ACCEPT'>>> =
  Object.freeze({
    TUNNEL_CRITICAL: 'REJECT',
    NO_ROUTE: 'REJECT',
    ACCEPT_BECOMES_DROP: 'REJECT',
    DEFAULT_POLICY_DROP: 'REJECT',
    MGMT_ADDRESS_REMOVED: 'REJECT',
    MGMT_INTERFACE_DISABLED: 'REJECT',
    MGMT_SERVICE_DISABLED: 'REJECT',
    NAT_BREAKS_RETURN_PATH: 'REJECT',
    DEADMAN_UNAVAILABLE: 'REJECT',
    COVERAGE_INCOMPLETE: 'INDETERMINATE',
    UNMODELED_MATCH: 'INDETERMINATE',
    ORDER_PARTIAL: 'INDETERMINATE',
    NO_MGMT_PATH_KNOWN: 'INDETERMINATE',
    PEER_UNVERIFIED: 'INDETERMINATE',
    BASE_STATE_STALE: 'INDETERMINATE',
    NO_FORWARDING_MODEL: 'INDETERMINATE',
  } as Record<GuardReason, Exclude<GuardVerdict, 'ACCEPT'>>);

/**
 * Fold a set of reasons into one verdict. Empty set = `ACCEPT`; one REJECT
 * anywhere wins over any number of INDETERMINATEs. Severity, never majority.
 */
export function guardVerdictFrom(reasons: readonly GuardReason[]): GuardVerdict {
  let verdict: GuardVerdict = 'ACCEPT';
  for (const r of reasons) {
    const v = GUARD_REASON_VERDICT[r];
    if (v === 'REJECT') return 'REJECT';
    verdict = v;
  }
  return verdict;
}

/**
 * The guard's own vocabulary is UPPERCASE and three-valued; the plan envelope
 * that predates it (`shared/src/ncm/plan.ts`, `change_plans.mgmt_path_verdict`)
 * is lowercase and calls a proven refusal a `veto`. Two names for one thing is
 * how a migration ends up storing 'REJECT' in a column whose CHECK only knows
 * 'veto'. This function is the only bridge; do not hand-map it at a call site.
 */
export function mgmtPathVerdictOf(v: GuardVerdict): 'accept' | 'indeterminate' | 'veto' {
  switch (v) {
    case 'ACCEPT': return 'accept';
    case 'REJECT': return 'veto';
    default: return 'indeterminate';
  }
}

export function guardVerdictOfMgmtPath(v: 'accept' | 'indeterminate' | 'veto'): GuardVerdict {
  switch (v) {
    case 'accept': return 'ACCEPT';
    case 'veto': return 'REJECT';
    default: return 'INDETERMINATE';
  }
}

// ============================================================================
// Backups — the mandatory pre-change artefact
// ============================================================================

/**
 * `binary` is MikroTik's `/system/backup` — restores everything including the
 * things `.rsc` cannot express (user database, certificates), but only onto the
 * same model and a compatible RouterOS. `rsc` is the text export — portable,
 * diffable, readable, and incomplete.
 *
 * A pre-change backup takes BOTH where the driver can: the binary is what the
 * dead-man restores, the `.rsc` is what a human reads at 3 a.m. to understand
 * what he is restoring.
 */
export const BACKUP_KINDS = ['binary', 'rsc'] as const;
export type BackupKind = (typeof BACKUP_KINDS)[number];

/** Why the backup was taken. `preflight` is the one the backup rule makes mandatory;
 *  `pre_rollback` is taken of the BROKEN state before restoring, because the
 *  broken state is evidence and restoring it away destroys the post-mortem. */
export const BACKUP_TRIGGERS = ['scheduled', 'preflight', 'pre_rollback', 'manual'] as const;
export type BackupTrigger = (typeof BACKUP_TRIGGERS)[number];

/** `missing` = the row says it exists, the storage says otherwise. Kept as a
 *  distinct state from `purged` so that a lost backup is an incident and an
 *  expired one is routine. */
export const BACKUP_STATUSES = ['available', 'missing', 'purged', 'failed'] as const;
export type BackupStatus = (typeof BACKUP_STATUSES)[number];

export const BACKUP_RETENTION_CLASSES = ['short', 'standard', 'long', 'legal_hold'] as const;
export type BackupRetentionClass = (typeof BACKUP_RETENTION_CLASSES)[number];

// ============================================================================
// apply_outcomes — the laboratory we do not have
// ============================================================================

/**
 * How an application ended, from the corpus' point of view.
 *
 *  succeeded    applied, verified, soaked, disarmed.
 *  rolled_back  the net caught it. The change did not stick, the site did.
 *  lost_contact THE ONE THAT MATTERS. We stopped hearing from the device and
 *               no restore was observed. On a `degraded` device this is the
 *               outcome that means a van. It is a separate value from
 *               `rolled_back` precisely so that nobody can average them into a
 *               reassuring success rate.
 *
 * Recorded per (operation kind, brand, model, firmware) on every apply; read by the
 * planner once the corpus is large enough to mean anything. Honest limit,
 * restated from the safety-net rule: while the corpus is empty this protects nothing.
 */
export const APPLY_OUTCOMES = ['succeeded', 'rolled_back', 'lost_contact'] as const;
export type ApplyOutcome = (typeof APPLY_OUTCOMES)[number];

/** Below this many observations for a (op, brand, model, firmware) tuple, the
 *  planner must show the history as "insufficient evidence" rather than as a
 *  rate. Three rollbacks out of three is not a 100% failure rate, it is three
 *  rollbacks. */
export const APPLY_OUTCOME_MIN_OBSERVATIONS = 5;

/** One aggregated row of the empirical memory, as the planner surfaces it. */
export interface ApplyOutcomeStats {
  opKind: ChangeJobKind;
  brand: string;
  model: string | null;
  osVersion: string | null;
  succeeded: number;
  rolledBack: number;
  lostContact: number;
  total: number;
  /** False while `total < APPLY_OUTCOME_MIN_OBSERVATIONS`. When false the UI
   *  shows the raw counts and no percentage. */
  significant: boolean;
}

// ============================================================================
// Kill switch — the gesture made in a panic
// ============================================================================

/** Global blocks every tenant; tenant blocks one. There is no per-device
 *  scope on purpose: the kill switch is the blunt instrument, and a blunt
 *  instrument with a target selector is not blunt. */
export const KILL_SWITCH_SCOPES = ['global', 'tenant'] as const;
export type KillSwitchScope = (typeof KILL_SWITCH_SCOPES)[number];

/**
 * The state of one switch row.
 *
 * FAIL-CLOSED: the reader (`kill_switch_blocks()` in migration 009, and any
 * service that mirrors it) treats a MISSING global row as ENGAGED. A kill
 * switch that fails open is not a kill switch. The migration seeds the global
 * row disengaged so the normal read always finds it.
 */
export interface KillSwitchState {
  scope: KillSwitchScope;
  /** `null` on the global row, the tenant on a tenant row. */
  tenantId: number | null;
  /** `true` = every write to every equipment in scope is refused. */
  engaged: boolean;
  /** Operator-facing sentence shown on every refused job. */
  reason: string | null;
  engagedBy: number | null;
  engagedAt: string | null;
  releasedBy: number | null;
  releasedAt: string | null;
}

/** What the write path checks, once, before anything else. */
export interface KillSwitchDecision {
  blocked: boolean;
  /** Which switch blocked: the global one wins and is reported first. */
  by: KillSwitchScope | null;
  reason: string | null;
}

// ============================================================================
// Safety level — the safety-net rule. The type is in `device.ts`; the RULES are here.
// ============================================================================

// `SafetyLevel` ('armed' | 'armed_by_peer' | 'degraded') is defined in
// `shared/src/device.ts` and is NOT redefined here. What this file adds is what
// each level obliges.

/**
 * Levels that require an explicit, recorded operator confirmation before a
 * write job may be created. THE SAFETY-NET RULE: DEGRADED is "detection without recovery" —
 * we will know the CPE stopped informing and we will not be able to fix it
 * remotely. That confirmation is a CHECK constraint on `change_jobs`
 * (`degraded_confirmed_by NOT NULL`), not a checkbox in the UI.
 */
export function requiresExplicitConfirmation(level: SafetyLevel): boolean {
  return level === 'degraded';
}

/**
 * Whether the net survives the death of the ObliWAN server. This is THE
 * property of the safety-net rule and the reason `armed` and `armed_by_peer` are two values:
 * an on-box scheduler repairs the router with nobody watching, a peer-carried
 * dead-man needs a second box to still be alive and reachable.
 */
export function netSurvivesServerLoss(level: SafetyLevel): boolean {
  return level === 'armed' || level === 'armed_by_peer';
}

/** `armed_by_peer` is a claim about a SPECIFIC other device. A job that claims
 *  it without naming the peer is claiming a net that does not exist —
 *  migration 009 refuses the row. */
export function requiresPeerDevice(level: SafetyLevel): boolean {
  return level === 'armed_by_peer';
}

// ============================================================================
// Job / step shapes as the API and the socket carry them
// ============================================================================

/**
 * The job as the UI sees it. Redacted by construction: there is no field here
 * that can hold a command, a config body or a credential.
 */
export interface ChangeJobSummary {
  id: number;
  uuid: string;
  tenantId: number;
  /** God view only: the owning tenant's name (GodViewTenantTag). */
  tenantName?: string | null;
  deviceId: number;
  deviceName: string;
  /** The job list only (a socket frame carries neither): the device's site. */
  siteId?: number | null;
  siteName?: string | null;
  planId: number | null;
  kind: ChangeJobKind;
  status: ChangeJobStatus;
  attempt: number;

  safetyLevel: SafetyLevel;
  /** Set only when `safetyLevel === 'armed_by_peer'`. */
  safetyPeerDeviceId: number | null;
  guardVerdict: GuardVerdict;
  guardReasons: GuardReason[];
  /** Non-null exactly when the guard did not ACCEPT and a human forced it. */
  overrideReason: string | null;

  baseStateHash: string;
  preflightBackupId: number | null;
  deadmanArmedAt: string | null;
  deadmanDisarmedAt: string | null;
  soakUntil: string | null;

  scheduledFor: string | null;
  windowStart: string | null;
  windowEnd: string | null;

  requestedBy: number | null;
  /** The job list and the job page only: a job no operator asked for — the
   *  automatic re-apply after the nightly verification run #`run` (or the
   *  template fixes it promised after its management access job). */
  origin?: ChangeJobOrigin | null;
  startedAt: string | null;
  finishedAt: string | null;
  errorKind: string | null;
  /** Operator-facing sentence. Never a stack trace, never a command. */
  errorMessage: string | null;
  createdAt: string;
}

/** Where a job came from when no operator queued it (migration 093). */
export interface ChangeJobOrigin {
  kind: 'access_check_nightly';
  /** The nightly verification's run number. */
  run: number;
}

/** One line of the live job screen. `outputRedacted` is masked at the source —
 *  the driver redacts before it returns, not the persistence layer. */
export interface ChangeJobStep {
  id: number;
  jobId: number;
  seq: number;
  attempt: number;
  kind: ChangeStepKind;
  status: ChangeStepStatus;
  /** `PlanOp.seq` this step executes, when it executes one. */
  planOpSeq: number | null;
  startedAt: string | null;
  finishedAt: string | null;
  durationMs: number | null;
  outputRedacted: string | null;
  errorRedacted: string | null;
}
