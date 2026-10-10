import crypto from 'crypto';
import {
  MANAGEMENT_TUNNEL_NAME,
  RECONCILE_ATTACH_APPLY_MAX_SITES,
  RECONCILE_ATTACH_DEFAULT_USERNAME,
  RECONCILE_ATTACH_VAULT_KEY,
  SOCKET_EVENTS,
  type DeviceFamily,
  type ReconcileAttachDeviceRef,
  type ReconcileAttachFacts,
  type ReconcileAttachFailReason,
  type ReconcileAttachFollowUpOptions,
  type ReconcileAttachFollowUpPlan,
  type ReconcileAttachFollowUpResult,
  type ReconcileAttachPreview,
  type ReconcileAttachPreviewRow,
  type ReconcileAttachResult,
  type ReconcileAttachResultRow,
  type ReconcileAttachSkipReason,
  type ReconcileAttachVaultScope,
  type PppDuplicateSession,
  managementTunnelLogin,
} from '@obliwan/shared';
import type { Knex } from 'knex';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { auditedCommand } from '../audit.service';
import { appendAudit } from '../attestation/auditLog.service';
import { currentKeyVersion, encrypt } from '../secretVault.service';
import { reconcileTenant, type ReconcileReport } from '../allocation/reconcile.service';
import { resolveLegacyVariable } from '../bench/compile.service';
import { readManagementRange } from '../bench/planning.service';
import { recordFollowup } from '../change/jobFollowup.service';
import { DeviceBusyError } from '../change/jobQueue.service';
import { KillSwitchEngagedError, killSwitchSentenceFr, readKillSwitch } from '../change/killSwitch.service';
import {
  ManagementAccessError,
  SSH_READS,
  enqueueManagementAccessJob,
  parseBoard,
  parseIdentity,
  parseL2tpClients,
} from '../change/managementAccess.service';
import { isNonPublicAddress } from '../change/transfer.service';
import { ROUTEROS_SSH_VERSION_COMMAND } from '../drivers/mikrotik/driver';
import { cleanVersion, familyFromVersion } from '../drivers/mikrotik/mikrotik.driver';
import { DriverError, redact } from '../drivers/types';
import { withSsh, type SshTarget, type SshTransport } from '../transport/ssh.transport';
import { toDeviceDto } from './dto';
import type { DeviceRow } from './device.service';
import { emitToTenantAudience } from './scopedEmit';
import { isConcentratorDegraded } from './reachability.service';
import { readActiveLive, readRecordedDuplicates, sessionsOfLogin, toDuplicateSession } from './pppDuplicates.service';
import { setLearning } from '../learning/learning.service';

/**
 * reconcileAttach.service.ts — the online legacy routers of the CHR
 * reconciliation, turned into ObliWAN devices in bulk.
 *
 * The reconciliation shows, for a tenant, sites whose concentrator account is
 * allocated or adopted and whose router is ONLINE (an open PPP session on the
 * concentrator), yet no device: routers configured by hand long ago, that
 * carry the historical `admin` account (password = the `admin_password`
 * variable) and not ObliWAN's, and answer SSH from the management range only.
 * This file makes them devices — a dry run (`previewAttach`) and the act
 * (`applyAttach`), both on the session's tenant only, both reserved to a
 * PLATFORM ADMINISTRATOR (see "WHO MAY CLAIM THE ACCOUNT"). NOTHING IS EVER
 * WRITTEN TO A ROUTER BY THIS ACT: the SSH session sends four reads, each
 * audited before it is sent (`command_audit`), and creates no account. The
 * API-SSL channel (and the `obliwan` account it logs in with) is the
 * `management_access` job's, so no `routeros_api` row is invented here — but
 * the act may QUEUE that job (see "WHAT FOLLOWS THE ATTACH").
 *
 * ┌─ WHAT FOLLOWS THE ATTACH (operator decision, 2026-10-05) ────────────────┐
 * │ An attached router still logs in with its historical account, and the   │
 * │ operator wants ObliWAN to move to its own one by itself, then apply the  │
 * │ template fixes. So the request may ask, for each router it attaches:     │
 * │   - `openManagementAccess`: a `management_access` job, queued right      │
 * │     after the device row exists, through its own door                   │
 * │     (`enqueueManagementAccessJob`: every rule of that job applies, and   │
 * │     the job proves the router again over SSH before it writes);          │
 * │   - `applyCompliance` (only with the first): a `legacy_compliance` job   │
 * │     PROMISED after it (`change_job_followups`, jobFollowup.service.ts) — │
 * │     one job in flight per device — and queued by the worker once         │
 * │     management_access has SUCCEEDED; closed without a job otherwise.     │
 * │ Neither job arms a dead-man: the safety-net rule's explicit confirmation │
 * │ of the degraded level is asked ONCE for the batch (`confirmNoDeadman`),  │
 * │ and the act refuses the whole request without it, before anything is   │
 * │ dialled — when at least one router is eligible (otherwise nothing could │
 * │ follow). A follow-up refused at the enqueue never fails the attach: the │
 * │ row says `attached` and, beside it, the refusal's code and the job's     │
 * │ sentence. The HTTP request defaults to both                              │
 * │ (RECONCILE_ATTACH_FOLLOWUP_DEFAULTS); a caller of these functions that   │
 * │ The dry run says, per eligible router, what would be queued, and judges  │
 * │ what can be judged before the device exists (kill switch, management     │
 * │ range).                                                                  │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ ELIGIBLE: ONE CLASSIFIER, THEN WHAT ONLY THIS ACT NEEDS ────────────────┐
 * │ The site list and the account each site carries are the reconciliation's│
 * │ own (`reconcileTenant`), so a site the page shows as matched is the site │
 * │ this act sees as matched. On top of it, in this order:                   │
 * │   - a device already holding the login: THIS site's -> `already_attached`│
 * │     (what makes a re-run attach only what is missing); any other ->      │
 * │     `login_held` (named only when it is this tenant's);                  │
 * │   - another router already on the site -> `site_has_device`: attach the  │
 * │     account to it instead of creating a second router for one store;    │
 * │   - the site's addresses allocated or adopted (`site_provisioning`)      │
 * │     -> otherwise `not_allocated`;                                        │
 * │   - presence on the allocation's concentrator NOT degraded: on that      │
 * │     verdict presence closes no session, so an "open" row is only the    │
 * │     last one it saw, and the address may be another router's by now;    │
 * │   - the login NOT holding several live sessions on that concentrator     │
 * │     (`duplicate_sessions`, pppDuplicates.service.ts): the tunnel address │
 * │     then reaches whichever session the CHR routes to — a forgotten      │
 * │     router on 4G was attached as a store's that way (2026-10-09). The    │
 * │     dry run judges the last recorded /ppp/active read; the act reads    │
 * │     /ppp/active LIVE once per concentrator before any dial, and the     │
 * │     write re-checks the recorded read under its lock. A live read that  │
 * │     fails leaves the recorded verdict standing (logged);                 │
 * │   - exactly one OPEN `ppp_sessions` row for the login on the            │
 * │     allocation's concentrator (a router whose session is down is         │
 * │     never dialled), carrying a non-public tunnel address that IS the     │
 * │     one the allocation froze (the CHR secret's remote-address): the      │
 * │     credential below is sent before the box has proven anything, so it  │
 * │     goes only where this site's account is the one that is answering;   │
 * │   - a credential: the operator's, or `admin` with `admin_password`       │
 * │     resolved site > tenant > global > instance (`resolveLegacyVariable`, │
 * │     the bench's own resolution). The INSTANCE level is shared by every   │
 * │     tenant and written and revealed by platform administrators only —   │
 * │     the only callers of this act — but the copy it stores is a tenant   │
 * │     device's transport, which the tenant's own SECRET_READ reveals and   │
 * │     its CREDENTIAL_MANAGE can repoint at any host before "Test": the dry │
 * │     run says so (`vaultScope`), and typing the credential avoids it.     │
 * │ Every site asked for gets a row and a named reason; none is dropped.     │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHO MAY CLAIM THE ACCOUNT: A PLATFORM ADMINISTRATOR ────────────────────┐
 * │ A device row carries (concentrator, ppp_username), the pair presence     │
 * │ routes a live session by — and on the SHARED CHR, `decidePppClaim` and   │
 * │ `bindDiscovery` let only a platform administrator write it, because     │
 * │ nothing in a session says whose it is. This act writes that pair on the │
 * │ shared CHR's logins (nothing is written to the CHR router itself), so it │
 * │ is reserved to a platform administrator too (operator decision,         │
 * │ 2026-10-04): `requireRole('admin')` on both routes, and `evaluate`       │
 * │ refuses any other actor (PLATFORM_ADMIN_ONLY) so a caller that forgot  │
 * │ the route guard fails closed. WHICH login a site may take stays the     │
 * │ `site_provisioning` row of THIS tenant's site, frozen by the allocator  │
 * │ (adoption refuses a login another tenant's allocation or device holds), │
 * │ which is why the act does not go through `createDevice`. The tenant     │
 * │ view's refusal of a login template that names no tenant                 │
 * │ (`assertTenantMayReconcile`) is not applied: it protects a TENANT user  │
 * │ from reading other customers' accounts as hers, and the platform       │
 * │ administrator speaks for the infrastructure's owner, as on the          │
 * │ allocation screen.                                                       │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ PROVEN BEFORE THE ROW EXISTS (no pending device is left behind) ────────┐
 * │ Each eligible site is dialled over SSH at its session's tunnel address   │
 * │ (four at a time, 45 s each at most) with the credential, and must answer:│
 * │   - its l2tp-clients (name and user), whose MANAGEMENT tunnel dials with │
 * │     the site's login — the identity proof that the box at that           │
 * │     address is this site's router. The management tunnel is the client   │
 * │     NAMED l2tp-mgmt, else the sole one carrying the login                │
 * │     (`managementTunnelLogin`, the                                        │
 * │     rule every later identity check applies, over SSH and over the API), │
 * │     so a store with another tunnel created first (l2tp-infra) is proven │
 * │     on its l2tp-mgmt, and a box the next check would contradict is not  │
 * │     attached;                                                            │
 * │   - a RouterOS 6 or 7 version, which decides the family (never guessed: │
 * │     the rsc export is spelled per major);                               │
 * │   - its identity and RouterBOARD serial/model, stored as read.          │
 * │ Only then is the device written — active and managed, the facts filled,│
 * │ the SSH transport stored with the password encrypted — in ONE           │
 * │ transaction that re-checks every rule above under the site's allocation │
 * │ row (FOR SHARE) and a per-login advisory lock (the session included:    │
 * │ the device is written with ITS address and start, so one that ended or  │
 * │ moved during the proof writes nothing), binds the discovery and         │
 * │ adopts the session history like `bindDiscovery`, and appends the audit  │
 * │ entry naming the operator: the bulk confirmation of THESE selected       │
 * │ sites is the human gesture the identity rule asks for.                  │
 * │                                                                          │
 * │ A proof that fails creates nothing, rather than a pending device. A      │
 * │ pending row would hold the platform-wide UNIQUE login, keep a credential │
 * │ that did not work, and point its only channel at an address where the   │
 * │ box was NOT shown to be this router — and "Test connection" fills blank  │
 * │ identity columns from whatever answers there, which is how an impostor   │
 * │ would approve itself. Nothing is lost: the refusal and its reason are an │
 * │ audit entry, the SSH reads are in the command audit, and a re-run (with  │
 * │ another credential, say) retries exactly the sites still missing.       │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * SECRETS: the password is decrypted (or received) for one SSH session,
 * stored only as `device_transports.secret_enc`, scrubbed from every error,
 * and never part of a response, a log line, an audit entry or a command.
 */

// ============================================================================
// Tuning and seams
// ============================================================================

/** Routers dialled at once. */
export const ATTACH_CONCURRENCY = 4;
/** One router's whole proof: handshake and the four reads. */
export const ATTACH_PROOF_BUDGET_MS = 45_000;
const SSH_STEP_TIMEOUT_MS = 15_000;
/** `pg_advisory_xact_lock(class, hashtext(lower(login)))`: two runs, or two
 *  operators, attaching the same login serialise on it. */
const ATTACH_LOCK_CLASS = 0x7261;
/** RouterOS's factory identity: no use as a device name. */
const FACTORY_IDENTITY = 'mikrotik';

export interface ReconcileAttachDeps {
  /** Where to dial a tunnel address (the harness maps it to its fake). */
  sshTarget(host: string, port: number): { host: string; port: number };
}
const DEFAULT_DEPS: ReconcileAttachDeps = { sshTarget: (host, port) => ({ host, port }) };
let deps: ReconcileAttachDeps = { ...DEFAULT_DEPS };
export function setReconcileAttachDeps(next: Partial<ReconcileAttachDeps>): void {
  deps = { ...deps, ...next };
}
export function resetReconcileAttachDeps(): void {
  deps = { ...DEFAULT_DEPS };
}

// ============================================================================
// Inputs
// ============================================================================

export interface AttachCredentials {
  username: string;
  password: string;
}

export interface AttachActor {
  userId: number;
  username: string | null;
  /** `users.role = 'admin'`, as requireAuth revalidated it. Must be true:
   *  the act is a platform administrator's (`assertPlatformAdmin`). */
  platformAdmin: boolean;
}

/** A refusal of the whole request (the controller maps `httpStatus`). */
export class ReconcileAttachError extends Error {
  constructor(readonly reason: string, message: string, readonly httpStatus = 409) {
    super(message);
    this.name = 'ReconcileAttachError';
  }
}

/** What the act queues after each router it attaches (header, "WHAT FOLLOWS
 *  THE ATTACH"), and the safety-net rule's confirmation of the degraded level, given once
 *  for the batch. */
export interface AttachFollowUpRequest extends ReconcileAttachFollowUpOptions {
  confirmNoDeadman: boolean;
}

/** No options: nothing follows. */
const NO_FOLLOW_UPS: ReconcileAttachFollowUpOptions = { openManagementAccess: false, applyCompliance: false };

/** No compliance without management access: it waits for that job. */
function normaliseFollowUps(options: ReconcileAttachFollowUpOptions | null | undefined): ReconcileAttachFollowUpOptions {
  const open = options?.openManagementAccess === true;
  return { openManagementAccess: open, applyCompliance: open && options?.applyCompliance === true };
}

/** The routes already demand `requireRole('admin')`; this is the service's
 *  own refusal, so a caller that forgot the guard fails closed (header, "WHO
 *  MAY CLAIM THE ACCOUNT"). Before anything is read. */
function assertPlatformAdmin(actor: Pick<AttachActor, 'platformAdmin'>): void {
  if (actor.platformAdmin !== true) {
    throw new ReconcileAttachError(
      'PLATFORM_ADMIN_ONLY',
      'Attaching routers from the reconciliation is reserved to platform administrators: it binds logins of the shared concentrator to devices.',
      403,
    );
  }
}

// ============================================================================
// Eligibility
// ============================================================================

interface SshCredential {
  username: string;
  password: string;
  source: 'operator' | 'vault';
  scope: ReconcileAttachVaultScope | null;
}

/** What an eligible site is dialled and recorded with. */
interface AttachTarget {
  siteId: number;
  code: string;
  name: string;
  /** The open session's spelling: what presence will look the device up by. */
  login: string;
  concentratorId: number;
  tunnelIp: string;
  callerIp: string | null;
  sessionStartedAt: Date | string;
  credential: SshCredential;
}

interface Verdict {
  row: ReconcileAttachPreviewRow;
  target: AttachTarget | null;
}

interface HolderRow {
  id: number;
  name: string;
  tenant_id: number;
  site_id: number | null;
  login: string;
}
interface SiteDeviceRow {
  id: number;
  name: string;
  site_id: number;
  ppp_username: string | null;
}
interface ProvRow {
  site_id: number;
  ppp_username: string;
  concentrator_id: number;
  /** `host()`: what a session's `host(tunnel_ip)` is compared with. */
  tunnel_ip: string;
}
interface SessionRow {
  concentrator_id: number;
  ppp_username: string;
  tunnel_ip: string | null;
  caller_ip: string | null;
  started_at: Date | string;
}

function lower(text: string): string {
  return text.toLowerCase();
}

/** `?, ?, ?` for a whereRaw IN list (bound, never spliced). */
function marks(values: readonly unknown[]): string {
  return values.map(() => '?').join(', ');
}

function skipRow(
  base: Pick<ReconcileAttachPreviewRow, 'siteId' | 'code' | 'name' | 'login'>,
  reason: ReconcileAttachSkipReason,
  device: ReconcileAttachDeviceRef | null = null,
  tunnelIp: string | null = null,
): Verdict {
  return {
    row: {
      ...base,
      tunnelIp,
      verdict: 'skipped',
      reason,
      device,
      sshUsername: null,
      credentialSource: null,
      vaultScope: null,
      followUps: [],
    },
    target: null,
  };
}

/** A site whose login holds several live sessions: skipped, and the row
 *  names the sessions (caller-id, address, uptime — never a password). */
function duplicateRow(
  base: Pick<ReconcileAttachPreviewRow, 'siteId' | 'code' | 'name' | 'login'>,
  sessions: PppDuplicateSession[],
): Verdict {
  const v = skipRow(base, 'duplicate_sessions');
  v.row.duplicateSessions = sessions;
  return v;
}

// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;

async function credentialFor(
  tenantId: number,
  siteId: number,
  given: AttachCredentials | null,
): Promise<SshCredential | ReconcileAttachSkipReason> {
  if (given) return { username: given.username, password: given.password, source: 'operator', scope: null };
  const found = await resolveLegacyVariable(RECONCILE_ATTACH_VAULT_KEY, tenantId, siteId);
  if (!found) return 'no_vault_password';
  // Every level, the instance one included, is the caller's to use: only a
  // platform administrator reaches this act (assertPlatformAdmin).
  if (CONTROL_CHARS.test(found.value)) return 'vault_password_invalid';
  return { username: RECONCILE_ATTACH_DEFAULT_USERNAME, password: found.value, source: 'vault', scope: found.scope };
}

/**
 * Is presence on this concentrator NOT being kept, so that its open
 * `ppp_sessions` rows are only the last ones it saw? Either reading says so:
 *   - its latest verdict is CONCENTRATOR_DEGRADED, at any age — the
 *     reconciliation's own `presence.degradedSince`. No TTL here, unlike the reachability rule's
 *     alert suppression: presence writes the recovery after its first sweep
 *     that succeeds (`recordConcentratorRecovery`), so a degraded verdict
 *     still standing means no sweep has vouched for these sessions since;
 *   - the reachability rule (`isConcentratorDegraded`): a fresh API health row confirms
 *     the CHR down, even if the verdict write that should follow it failed.
 */
async function concentratorDegraded(concentratorId: number): Promise<boolean> {
  const latest = (await db('reachability_verdicts')
    .where({ device_id: concentratorId })
    .orderBy([
      { column: 'ts', order: 'desc' },
      { column: 'id', order: 'desc' },
    ])
    .first('verdict')) as { verdict: string } | undefined;
  if (latest?.verdict === 'CONCENTRATOR_DEGRADED') return true;
  return isConcentratorDegraded(concentratorId);
}

/**
 * Every requested site's verdict (all of the tenant's sites when `siteIds` is
 * null), in the request's order. Reads only — the reconciliation runs READ
 * ONLY, the rest are plain SELECTs, and the vault is only decrypted.
 */
async function evaluate(
  tenantId: number,
  siteIds: readonly number[] | null,
  credentials: AttachCredentials | null,
  actor: Pick<AttachActor, 'platformAdmin'>,
): Promise<{ report: ReconcileReport; verdicts: Verdict[] }> {
  assertPlatformAdmin(actor);
  // No `assertTenantMayReconcile`: its refusal of a login template naming no
  // tenant guards a TENANT user's view, and the caller is a platform
  // administrator (header, "WHO MAY CLAIM THE ACCOUNT").
  const report = await reconcileTenant(tenantId);

  type SiteEntry =
    | { kind: 'matched'; m: ReconcileReport['matched'][number] }
    | { kind: 'only'; s: ReconcileReport['siteOnly'][number] };
  const bySite = new Map<number, SiteEntry>();
  for (const m of report.matched) bySite.set(m.siteId, { kind: 'matched', m });
  for (const s of report.siteOnly) bySite.set(s.siteId, { kind: 'only', s });

  const ids =
    siteIds === null
      ? [...bySite.values()]
          .map((e) => (e.kind === 'matched' ? e.m : e.s))
          .sort((a, b) => a.code.localeCompare(b.code))
          .map((s) => s.siteId)
      : [...new Set(siteIds)];

  // What only this act reads, for the sites the reconciliation matched.
  const matchedIds = ids.filter((id) => bySite.get(id)?.kind === 'matched');
  const logins = [
    ...new Set(
      matchedIds.map((id) => lower((bySite.get(id) as { m: ReconcileReport['matched'][number] }).m.login)),
    ),
  ];
  const holders = logins.length
    ? ((await db('devices')
        .whereRaw(`lower(ppp_username) IN (${marks(logins)})`, logins)
        .select('id', 'name', 'tenant_id', 'site_id', db.raw('lower(ppp_username) AS login'))) as HolderRow[])
    : [];
  const holderOf = new Map(holders.map((h) => [h.login, h]));
  const siteDevices = matchedIds.length
    ? ((await db('devices')
        .where({ tenant_id: tenantId })
        .whereIn('site_id', matchedIds)
        .whereNot({ role: 'concentrator' })
        .orderBy('id')
        .select('id', 'name', 'site_id', 'ppp_username')) as SiteDeviceRow[])
    : [];
  const provs = matchedIds.length
    ? ((await db('site_provisioning')
        .where({ tenant_id: tenantId })
        .whereIn('site_id', matchedIds)
        .select('site_id', 'ppp_username', 'concentrator_id', db.raw('host(tunnel_ip) AS tunnel_ip'))) as ProvRow[])
    : [];
  const provOf = new Map(provs.map((p) => [p.site_id, p]));
  const degraded = new Set<number>();
  for (const id of new Set(provs.map((p) => p.concentrator_id))) {
    if (await concentratorDegraded(id)) degraded.add(id);
  }
  const provLogins = [...new Set(provs.map((p) => lower(p.ppp_username)))];
  // The logins the last recorded /ppp/active read showed with several live
  // sessions (pppDuplicates.service.ts), keyed `concentrator|lower(login)`.
  const duplicated = new Map(
    (await readRecordedDuplicates(db, [...new Set(provs.map((p) => p.concentrator_id))], provLogins)).map((d) => [
      `${d.concentratorId}|${d.loginKey}`,
      d,
    ]),
  );
  const sessions = provs.length
    ? ((await db('ppp_sessions')
        .whereIn('concentrator_id', [...new Set(provs.map((p) => p.concentrator_id))])
        .whereNull('ended_at')
        .whereRaw(`lower(ppp_username) IN (${marks(provLogins)})`, provLogins)
        .select(
          'concentrator_id',
          'ppp_username',
          db.raw('host(tunnel_ip) AS tunnel_ip'),
          db.raw('host(caller_ip) AS caller_ip'),
          'started_at',
        )) as SessionRow[])
    : [];

  const verdicts: Verdict[] = [];
  for (const siteId of ids) {
    const entry = bySite.get(siteId);
    if (!entry) {
      verdicts.push(skipRow({ siteId, code: null, name: null, login: null }, 'not_found'));
      continue;
    }
    if (entry.kind === 'only') {
      const s = entry.s;
      verdicts.push(skipRow({ siteId, code: s.code, name: s.name, login: s.login }, 'no_account'));
      continue;
    }
    const m = entry.m;
    const base = { siteId, code: m.code, name: m.name, login: m.account.name };
    const holder = holderOf.get(lower(m.login)) ?? holderOf.get(lower(m.account.name));
    if (holder) {
      const own = holder.tenant_id === tenantId;
      const ref = own ? { id: holder.id, name: holder.name } : null;
      verdicts.push(skipRow(base, own && holder.site_id === siteId ? 'already_attached' : 'login_held', ref));
      continue;
    }
    const other = siteDevices.find((d) => d.site_id === siteId);
    if (other) {
      verdicts.push(skipRow(base, 'site_has_device', { id: other.id, name: other.name }));
      continue;
    }
    const prov = provOf.get(siteId);
    if (m.status === 'adoptable' || !prov) {
      verdicts.push(skipRow(base, 'not_allocated'));
      continue;
    }
    // Before any session is read: on a degraded CHR, "open" and "closed" are
    // both what presence last saw.
    if (degraded.has(prov.concentrator_id)) {
      verdicts.push(skipRow(base, 'concentrator_degraded'));
      continue;
    }
    // Before the open session is read: with several live sessions, the one
    // row presence keeps says nothing about which box the address reaches.
    const dup = duplicated.get(`${prov.concentrator_id}|${lower(prov.ppp_username)}`);
    if (dup) {
      verdicts.push(duplicateRow(base, dup.sessions));
      continue;
    }
    const open = sessions.filter(
      (s) => s.concentrator_id === prov.concentrator_id && lower(s.ppp_username) === lower(prov.ppp_username),
    );
    if (open.length === 0) {
      verdicts.push(skipRow(base, 'offline'));
      continue;
    }
    if (open.length > 1) {
      verdicts.push(skipRow(base, 'ambiguous_session'));
      continue;
    }
    const session = open[0];
    const live = { ...base, login: session.ppp_username };
    if (!session.tunnel_ip) {
      verdicts.push(skipRow(live, 'no_session_address'));
      continue;
    }
    if (!isNonPublicAddress(session.tunnel_ip)) {
      verdicts.push(skipRow(live, 'public_address', null, session.tunnel_ip));
      continue;
    }
    if (session.tunnel_ip !== prov.tunnel_ip) {
      verdicts.push(skipRow(live, 'address_mismatch', null, session.tunnel_ip));
      continue;
    }
    const credential = await credentialFor(tenantId, siteId, credentials);
    if (typeof credential === 'string') {
      verdicts.push(skipRow(live, credential, null, session.tunnel_ip));
      continue;
    }
    verdicts.push({
      row: {
        ...live,
        tunnelIp: session.tunnel_ip,
        verdict: 'eligible',
        reason: null,
        device: null,
        sshUsername: credential.username,
        credentialSource: credential.source,
        vaultScope: credential.scope,
        // Filled by the dry run (`previewAttach`), which knows the options.
        followUps: [],
      },
      target: {
        siteId,
        code: m.code,
        name: m.name,
        login: session.ppp_username,
        concentratorId: prov.concentrator_id,
        tunnelIp: session.tunnel_ip,
        callerIp: session.caller_ip,
        sessionStartedAt: session.started_at,
        credential,
      },
    });
  }
  return { report, verdicts };
}

/**
 * What the act would queue after an eligible router, judged on what is known
 * before its device exists: the tenant's kill switch, and the management
 * range every management_access job freezes (the same readers its enqueue
 * uses). The device's own rules — active, managed, MikroTik, an SSH password
 * on a private address — hold by construction for a device this act creates;
 * whatever else refuses (the CHR's subtree interlock) lands on the result row.
 */
async function followUpPlan(tenantId: number, options: ReconcileAttachFollowUpOptions): Promise<ReconcileAttachFollowUpPlan[]> {
  if (!options.openManagementAccess) return [];
  let refusal: { reason: string; message: string } | null = null;
  const killSwitch = await readKillSwitch(tenantId);
  if (killSwitch.blocked) {
    refusal = {
      reason: 'kill_switch',
      message: `${killSwitchSentenceFr(new KillSwitchEngagedError(killSwitch))} : aucune tâche ne peut être mise en file.`,
    };
  } else {
    const range = await readManagementRange();
    if (!range.ok) refusal = { reason: 'range_invalid', message: range.message };
  }
  const plans: ReconcileAttachFollowUpPlan[] = [
    refusal
      ? { kind: 'management_access', plan: 'refused', ...refusal }
      : { kind: 'management_access', plan: 'queue', reason: null, message: null },
  ];
  if (options.applyCompliance) {
    plans.push(
      refusal
        ? {
            kind: 'legacy_compliance',
            plan: 'refused',
            reason: 'management_access_refused',
            message: 'Les correctifs des modèles attendent l’accès de gestion, qui serait refusé : ils ne seraient pas mis en file.',
          }
        : { kind: 'legacy_compliance', plan: 'after', reason: null, message: null },
    );
  }
  return plans;
}

/** The dry run: what `applyAttach` would do for each site, and what it would
 *  queue after each router (no options: nothing). Dials nothing, writes
 *  nothing, answers no password. */
export async function previewAttach(
  tenantId: number,
  siteIds: readonly number[] | null,
  credentials: AttachCredentials | null,
  actor: Pick<AttachActor, 'platformAdmin'>,
  followUpOptions: ReconcileAttachFollowUpOptions | null = null,
): Promise<ReconcileAttachPreview> {
  const { verdicts } = await evaluate(tenantId, siteIds, credentials, actor);
  const options = normaliseFollowUps(followUpOptions ?? NO_FOLLOW_UPS);
  const rows = verdicts.map((v) => v.row);
  const eligible = rows.filter((r) => r.verdict === 'eligible');
  if (eligible.length > 0) {
    const plans = await followUpPlan(tenantId, options);
    for (const r of eligible) r.followUps = plans.map((p) => ({ ...p }));
  }
  return {
    generatedAt: new Date().toISOString(),
    rows,
    counts: { eligible: eligible.length, skipped: rows.length - eligible.length },
    followUpOptions: options,
  };
}

// ============================================================================
// The proof, over SSH — reads only
// ============================================================================

/** The reads the proof sends, in order. Each is a `:put` of a value: none
 *  changes the router. */
export const ATTACH_PROOF_READS = [SSH_READS.l2tp, SSH_READS.identity, SSH_READS.board, ROUTEROS_SSH_VERSION_COMMAND] as const;

/** How the management tunnel was found (`managementTunnelLogin`): recorded
 *  in the audit entry, since the second is a weaker statement than the first. */
type TunnelProof = 'named' | 'sole_match';

type ProofOutcome =
  | { ok: true; facts: ReconcileAttachFacts & { family: DeviceFamily }; tunnel: TunnelProof }
  | { ok: false; reason: ReconcileAttachFailReason; detail: string | null };

/**
 * The l2tp-clients the box printed, judged for THIS site's login by the rule
 * every later identity check applies (`managementTunnelLogin`): `ok` with
 * how the tunnel was found when the box is proven to dial with the login,
 * otherwise the refusal. The observed names are never echoed: on a mismatch
 * they are another account's, possibly another customer's.
 */
export function judgeManagementTunnel(
  out: string,
  login: string,
): { ok: true; tunnel: TunnelProof } | { ok: false; reason: Extract<ReconcileAttachFailReason, 'l2tp_absent' | 'l2tp_mismatch' | 'l2tp_ambiguous'> } {
  const found = managementTunnelLogin(parseL2tpClients(out), login);
  if (found.found === 'none') {
    if (found.why === 'no_client') return { ok: false, reason: 'l2tp_absent' };
    if (found.why === 'ambiguous') return { ok: false, reason: 'l2tp_ambiguous' };
    // no_match ('unrecorded' cannot happen: the login is never blank here).
    return { ok: false, reason: 'l2tp_mismatch' };
  }
  // `named`: the l2tp-mgmt client IS the management tunnel — another login
  // there (or none) is a contradiction, exactly what assertTargetBinding
  // would score a mismatch and quarantine. `sole_match` already carries it.
  if (lower(found.login ?? '') !== lower(login.trim())) return { ok: false, reason: 'l2tp_mismatch' };
  return { ok: true, tunnel: found.found };
}

function failureReason(err: unknown): ReconcileAttachFailReason {
  if (err instanceof DriverError) {
    if (err.code === 'AUTH_FAILED') return 'auth_failed';
    if (err.code === 'UNREACHABLE') return 'unreachable';
    if (err.code === 'TIMEOUT') return 'timeout';
  }
  return 'ssh_failed';
}

/** A column the box filled: refused (null) when it would not fit, rather
 *  than cut — a truncated identity is a different identity (compareIdentity). */
function fitting(value: string | null, max: number): string | null {
  return value !== null && value.length <= max ? value : null;
}

async function prove(
  tenantId: number,
  t: AttachTarget,
  actor: AttachActor,
  correlationId: string,
): Promise<ProofOutcome> {
  const deadline = Date.now() + ATTACH_PROOF_BUDGET_MS;
  const password = t.credential.password;
  const dial = deps.sshTarget(t.tunnelIp, 22);
  const target: SshTarget = {
    host: dial.host,
    port: dial.port,
    username: t.credential.username,
    password,
    timeoutMs: SSH_STEP_TIMEOUT_MS,
  };
  const read = async (ssh: SshTransport, command: string): Promise<string> => {
    const left = deadline - Date.now();
    if (left <= 0) throw new DriverError(`proof budget of ${ATTACH_PROOF_BUDGET_MS} ms spent`, 'TIMEOUT', { transport: 'ssh' });
    const res = await auditedCommand(
      {
        tenantId,
        // No device exists yet: the row is written only once the box is proven.
        deviceId: null,
        deviceName: t.login,
        userId: actor.userId,
        username: actor.username,
        transport: 'ssh',
        command,
        args: { purpose: 'reconcile_attach_proof', siteId: t.siteId, host: t.tunnelIp },
        isWrite: false,
        correlationId,
        secrets: [password],
      },
      () => ssh.exec(command, { pty: false, timeoutMs: Math.min(SSH_STEP_TIMEOUT_MS, left), maxOutputBytes: 64 * 1024 }),
    );
    return res.stdout;
  };

  try {
    return await withSsh(target, async (ssh): Promise<ProofOutcome> => {
      const tunnel = judgeManagementTunnel(await read(ssh, SSH_READS.l2tp), t.login);
      if (!tunnel.ok) return { ok: false, reason: tunnel.reason, detail: null };
      const identity = parseIdentity(await read(ssh, SSH_READS.identity));
      const board = parseBoard(await read(ssh, SSH_READS.board));
      const versionOut = (await read(ssh, ROUTEROS_SSH_VERSION_COMMAND)).trim().split(/\r?\n/)[0] ?? '';
      const family = familyFromVersion(versionOut.trim() || null);
      if (!family) return { ok: false, reason: 'version_unknown', detail: versionOut.trim().slice(0, 64) || null };
      return {
        ok: true,
        facts: {
          systemIdentity: fitting(identity, 128),
          serial: fitting(board.serial, 128),
          model: board.model ? board.model.slice(0, 128) : null,
          osVersion: cleanVersion(versionOut)?.slice(0, 64) ?? null,
          family,
        },
        tunnel: tunnel.tunnel,
      };
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, reason: failureReason(err), detail: redact(message, [password]).slice(0, 300) };
  }
}

// ============================================================================
// The write — one transaction per proven router
// ============================================================================

type CommitOutcome =
  | { ok: true; device: DeviceRow }
  | {
      ok: false;
      outcome: 'skipped' | 'failed';
      reason: ReconcileAttachSkipReason | ReconcileAttachFailReason;
      device: ReconcileAttachDeviceRef | null;
      duplicateSessions?: PppDuplicateSession[];
    };

function deviceNameFor(t: AttachTarget, identity: string | null): string {
  const id = (identity ?? '').trim();
  return id !== '' && lower(id) !== FACTORY_IDENTITY ? id.slice(0, 255) : t.code;
}

function pgUniqueConstraint(err: unknown): string | null {
  const e = err as { code?: string; constraint?: string };
  return e && e.code === '23505' ? e.constraint ?? '' : null;
}

async function commit(
  tenantId: number,
  t: AttachTarget,
  facts: ReconcileAttachFacts & { family: DeviceFamily },
  tunnel: TunnelProof,
  actor: AttachActor,
  correlationId: string,
): Promise<CommitOutcome> {
  const not = (reason: ReconcileAttachSkipReason, device: ReconcileAttachDeviceRef | null = null): CommitOutcome =>
    ({ ok: false, outcome: 'skipped', reason, device });
  // Outside the transaction: nothing this act locks orders the verdicts, and
  // the read would otherwise hold a second pool connection per commit. What
  // it decides is whether the session re-read below means anything.
  if (await concentratorDegraded(t.concentratorId)) return not('concentrator_degraded');
  try {
    return await db.transaction(async (trx: Knex.Transaction): Promise<CommitOutcome> => {
      await trx.raw('SELECT pg_advisory_xact_lock(?, hashtext(?))', [ATTACH_LOCK_CLASS, lower(t.login)]);

      // Everything evaluate() judged, judged again under the locks: the
      // proof took seconds, and a site may have moved meanwhile.
      const site = await trx('sites').where({ id: t.siteId, tenant_id: tenantId }).first('id');
      if (!site) return not('not_found');
      const prov = (await trx('site_provisioning')
        .where({ site_id: t.siteId, tenant_id: tenantId })
        .forShare()
        .first('ppp_username', 'concentrator_id', trx.raw('host(tunnel_ip) AS tunnel_ip'))) as
        | { ppp_username: string; concentrator_id: number; tunnel_ip: string }
        | undefined;
      if (!prov || prov.concentrator_id !== t.concentratorId || lower(prov.ppp_username) !== lower(t.login)) {
        return not('not_allocated');
      }
      if (prov.tunnel_ip !== t.tunnelIp) return not('address_mismatch');
      // The session the box was dialled through, still the only open one
      // and still at that address: the device is written with its address
      // and its start, and presence routes the next events by them.
      const open = (await trx('ppp_sessions')
        .where({ concentrator_id: t.concentratorId })
        .whereNull('ended_at')
        .whereRaw('lower(ppp_username) = ?', [lower(t.login)])
        .select(trx.raw('host(tunnel_ip) AS tunnel_ip'))) as Array<{ tunnel_ip: string | null }>;
      if (open.length === 0) return not('offline');
      if (open.length > 1) return not('ambiguous_session');
      if (open[0].tunnel_ip !== t.tunnelIp) return not('address_mismatch');
      // A second live session recorded while the box was being proven.
      const [dup] = await readRecordedDuplicates(trx, [t.concentratorId], [lower(t.login)]);
      if (dup) return { ok: false, outcome: 'skipped', reason: 'duplicate_sessions', device: null, duplicateSessions: dup.sessions };
      const holder = (await trx('devices')
        .whereRaw('lower(ppp_username) = ?', [lower(t.login)])
        .first('id', 'name', 'tenant_id', 'site_id')) as
        | { id: number; name: string; tenant_id: number; site_id: number | null }
        | undefined;
      if (holder) {
        const own = holder.tenant_id === tenantId;
        return not(own && holder.site_id === t.siteId ? 'already_attached' : 'login_held', own ? { id: holder.id, name: holder.name } : null);
      }
      const other = (await trx('devices')
        .where({ tenant_id: tenantId, site_id: t.siteId })
        .whereNot({ role: 'concentrator' })
        .first('id', 'name')) as { id: number; name: string } | undefined;
      if (other) return not('site_has_device', other);
      if (facts.serial) {
        const twin = (await trx('devices').where({ brand: 'mikrotik', serial: facts.serial }).first('id', 'name', 'tenant_id')) as
          | { id: number; name: string; tenant_id: number }
          | undefined;
        if (twin) {
          return { ok: false, outcome: 'failed', reason: 'serial_held', device: twin.tenant_id === tenantId ? { id: twin.id, name: twin.name } : null };
        }
      }

      const [device] = (await trx('devices')
        .insert({
          tenant_id: tenantId,
          site_id: t.siteId,
          name: deviceNameFor(t, facts.systemIdentity),
          brand: 'mikrotik',
          family: facts.family,
          model: facts.model,
          serial: facts.serial,
          os_version: facts.osVersion,
          role: 'cpe',
          concentrator_id: t.concentratorId,
          ppp_username: t.login,
          system_identity: facts.systemIdentity,
          tunnel_ip: t.tunnelIp,
          wan_public_ip: t.callerIp,
          // Proven on a fresh SSH session above, and confirmed by the
          // operator's selection: the gesture `approve` stands for.
          status: 'active',
          is_managed: true,
          first_seen_at: t.sessionStartedAt,
          last_seen_at: trx.fn.now(),
        })
        .returning('*')) as DeviceRow[];

      await trx('device_transports').insert({
        device_id: device.id,
        transport: 'ssh',
        enabled: true,
        priority: 10,
        host: t.tunnelIp,
        port: 22,
        username: t.credential.username,
        secret_enc: encrypt(t.credential.password),
        key_version: currentKeyVersion(),
        use_tls: false,
        params: JSON.stringify({}),
        // The proof's session logged in with exactly this credential.
        last_ok_at: trx.fn.now(),
      });

      // As `bindDiscovery` does: the quarantine row is settled, and the
      // history the CHR recorded before the device existed is filed under it.
      await trx('discoveries')
        .where({ concentrator_id: t.concentratorId, ppp_username: t.login })
        .whereNot({ state: 'bound' })
        .update({
          state: 'bound',
          bound_device_id: device.id,
          reviewed_by: actor.userId,
          reviewed_at: trx.fn.now(),
          updated_at: trx.fn.now(),
        });
      await trx('ppp_sessions')
        .where({ concentrator_id: t.concentratorId, ppp_username: t.login })
        .whereNull('device_id')
        .update({ device_id: device.id });

      // Inside the transaction: a ledger write that fails takes the creation
      // with it (auditLog.service). No password, no secret-named key.
      await appendAudit(
        {
          tenantId,
          actorType: 'user',
          actorId: actor.userId,
          actorName: actor.username,
          action: 'device.attached_from_reconcile',
          entityType: 'device',
          entityId: device.id,
          after: {
            siteId: t.siteId,
            siteCode: t.code,
            pppUsername: t.login,
            concentratorId: t.concentratorId,
            tunnelIp: t.tunnelIp,
            sshUser: t.credential.username,
            loginFrom: t.credential.source === 'vault' ? `vault:${RECONCILE_ATTACH_VAULT_KEY}@${t.credential.scope}` : 'operator',
            proof:
              tunnel === 'named'
                ? `ssh: the l2tp-client named ${MANAGEMENT_TUNNEL_NAME} dials with the login; identity, board and version read`
                : `ssh: no l2tp-client named ${MANAGEMENT_TUNNEL_NAME}, and the only one carrying the login dials with it; ` +
                  'identity, board and version read',
            systemIdentity: facts.systemIdentity,
            serial: facts.serial,
            model: facts.model,
            osVersion: facts.osVersion,
            family: facts.family,
            status: 'active',
            isManaged: true,
          },
          correlationId,
        },
        trx,
      );
      return { ok: true, device };
    });
  } catch (err) {
    // A writer outside this act (no advisory lock there) won the race.
    const constraint = pgUniqueConstraint(err);
    if (constraint !== null) {
      logger.info({ siteId: t.siteId, constraint }, 'Reconcile attach: a concurrent write took the login or the serial');
      if (/serial/.test(constraint)) return { ok: false, outcome: 'failed', reason: 'serial_held', device: null };
      return { ok: false, outcome: 'skipped', reason: 'login_held', device: null };
    }
    throw err;
  }
}

/** Best effort: the refusal created nothing, so a ledger failure only loses
 *  the entry (logged), never a write. */
async function auditRefusal(
  tenantId: number,
  t: AttachTarget,
  actor: AttachActor,
  correlationId: string,
  reason: string,
): Promise<void> {
  try {
    await appendAudit({
      tenantId,
      actorType: 'user',
      actorId: actor.userId,
      actorName: actor.username,
      action: 'device.attach_refused',
      entityType: 'site',
      entityId: t.siteId,
      after: {
        siteCode: t.code,
        pppUsername: t.login,
        tunnelIp: t.tunnelIp,
        sshUser: t.credential.username,
        loginFrom: t.credential.source === 'vault' ? `vault:${RECONCILE_ATTACH_VAULT_KEY}@${t.credential.scope}` : 'operator',
        reason,
        created: false,
      },
      correlationId,
    });
  } catch (err) {
    logger.error({ err, siteId: t.siteId, reason }, 'Reconcile attach: the refusal could not be appended to the audit log');
  }
}

/** `fn` over `items`, at most `limit` at a time, results in input order. */
async function mapLimit<T, R>(items: readonly T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]);
    }
  });
  await Promise.all(workers);
  return out;
}

/** A refusal of a follow-up's enqueue, as the result row carries it. The job
 *  services' sentences are French and shown as they are; an unexpected error
 *  is logged and named only by a fixed sentence. */
function followUpRefusal(err: unknown, deviceId: number): { reason: string; message: string } {
  if (err instanceof ManagementAccessError) return { reason: err.kind, message: err.message.slice(0, 2000) };
  if (err instanceof KillSwitchEngagedError) {
    return { reason: 'kill_switch', message: `${killSwitchSentenceFr(err)} : aucune écriture n’est possible.` };
  }
  if (err instanceof DeviceBusyError) {
    return { reason: 'device_busy', message: 'Une autre tâche est en cours sur ce routeur : relancez depuis sa fiche quand elle sera terminée.' };
  }
  logger.error({ err, deviceId }, 'Reconcile attach: a follow-up job could not be queued');
  return {
    reason: 'error',
    message: 'Erreur interne à la mise en file (voir le journal du serveur) : lancez la tâche depuis la fiche de l’équipement.',
  };
}

/**
 * Queue what follows the attach of ONE router (header, "WHAT FOLLOWS THE
 * ATTACH"): management_access now, legacy_compliance promised after it.
 * Never throws: a refusal is the row's to say, the router stays attached.
 */
async function queueFollowUps(
  tenantId: number,
  deviceId: number,
  options: ReconcileAttachFollowUpOptions,
  actor: AttachActor,
  correlationId: string,
): Promise<ReconcileAttachFollowUpResult[]> {
  if (!options.openManagementAccess) return [];
  const out: ReconcileAttachFollowUpResult[] = [];
  let managementJobId: number | null = null;
  try {
    const queued = await enqueueManagementAccessJob({
      tenantId,
      deviceId,
      requestedBy: actor.userId,
      // The batch's confirmation, given by this operator (assertFollowUpsConfirmed).
      confirmDegraded: { userId: actor.userId },
      allowExisting: false,
    });
    managementJobId = queued.jobId;
    out.push({ kind: 'management_access', status: 'queued', jobId: queued.jobId, followupId: null, reason: null, message: null });
  } catch (err) {
    const refusal = followUpRefusal(err, deviceId);
    logger.info({ tenantId, deviceId, reason: refusal.reason }, 'Reconcile attach: management_access refused after the attach');
    out.push({ kind: 'management_access', status: 'refused', jobId: null, followupId: null, ...refusal });
  }
  if (!options.applyCompliance) return out;
  if (managementJobId === null) {
    out.push({
      kind: 'legacy_compliance',
      status: 'skipped',
      jobId: null,
      followupId: null,
      reason: 'management_access_refused',
      message: 'Les correctifs des modèles attendaient l’accès de gestion, qui a été refusé : ils n’ont pas été mis en file.',
    });
    return out;
  }
  try {
    // Written after the job: a job that settles before this row exists is
    // caught by the follow-up sweep, which keeps the promise all the same.
    const followupId = await recordFollowup({
      tenantId,
      deviceId,
      afterJobId: managementJobId,
      thenKind: 'legacy_compliance',
      requestedBy: actor.userId,
      confirmedBy: actor.userId,
      source: 'reconcile_attach',
      correlationId,
    });
    out.push({ kind: 'legacy_compliance', status: 'pending', jobId: null, followupId, reason: null, message: null });
  } catch (err) {
    logger.error({ err, tenantId, deviceId, managementJobId }, 'Reconcile attach: the compliance follow-up could not be recorded');
    out.push({
      kind: 'legacy_compliance',
      status: 'refused',
      jobId: null,
      followupId: null,
      reason: 'error',
      message:
        'Erreur interne : les correctifs des modèles n’ont pas pu être programmés après l’accès de gestion (voir le journal ' +
        'du serveur). Lancez-les depuis la fiche de l’équipement une fois l’accès ouvert.',
    });
  }
  return out;
}

/** A follow-up arms no dead-man, so asking for one without the
 *  batch's explicit confirmation refuses the whole request — before any
 *  router is dialled (`applyAttach` asks only when one is eligible). */
function assertFollowUpsConfirmed(options: ReconcileAttachFollowUpOptions, confirmed: boolean): void {
  if (options.openManagementAccess && !confirmed) {
    throw new ReconcileAttachError(
      'DEGRADED_UNCONFIRMED',
      'The follow-up jobs (management access, then the template fixes) arm no dead-man: queueing them needs the ' +
        'explicit confirmation of the degraded safety level (confirmNoDeadman), or untick them. Nothing was dialled.',
      422,
    );
  }
}

/**
 * The eligible targets whose login holds several live sessions, read LIVE —
 * one bounded `/ppp/active/print` per concentrator on the pool socket
 * (pppDuplicates.service.ts) — before any router is dialled. A concentrator
 * that cannot be read is logged and judged by the recorded read `evaluate`
 * already applied: no refusal is invented from a failed read.
 */
async function liveDuplicateSessions(targets: readonly AttachTarget[]): Promise<Map<number, PppDuplicateSession[]>> {
  const out = new Map<number, PppDuplicateSession[]>();
  const byChr = new Map<number, AttachTarget[]>();
  for (const t of targets) {
    const list = byChr.get(t.concentratorId);
    if (list) list.push(t);
    else byChr.set(t.concentratorId, [t]);
  }
  for (const [concentratorId, list] of byChr) {
    const readAt = new Date();
    let entries;
    try {
      entries = await readActiveLive(concentratorId);
    } catch (err) {
      logger.warn(
        { err, concentratorId },
        'Reconcile attach: /ppp/active could not be read live; the last recorded read (duplicate sessions) stands',
      );
      continue;
    }
    for (const t of list) {
      const mine = sessionsOfLogin(entries, t.login);
      if (mine.length >= 2) out.set(t.siteId, mine.map((e) => toDuplicateSession(e, readAt)));
    }
  }
  return out;
}

/**
 * The routers this request attached, put in learning mode — the learning
 * page's own `setLearning` (the same flag, the same `learning.enabled` audit
 * entry per router, platform admin only). Learning refuses template pushes
 * only (`learningBlocksJob`): the management_access and legacy_compliance
 * follow-ups queued above still run. Never throws: a failure is reported
 * beside the attach, which stands. The capture itself is started by the
 * caller once every slice is attached (POST /learning/captures): one capture
 * run per workspace at a time.
 */
async function putAttachedInLearning(
  tenantId: number,
  deviceIds: number[],
  actor: AttachActor,
): Promise<{ enabled: number[]; error: string | null }> {
  try {
    const r = await setLearning(tenantId, deviceIds, true, actor);
    const skipped = r.skipped.map((s) => `${s.deviceId}:${s.reason}`);
    if (skipped.length > 0) logger.warn({ tenantId, skipped }, 'Reconcile attach: some attached routers could not be put in learning');
    return { enabled: r.changed, error: skipped.length > 0 ? `skipped ${skipped.join(', ')}` : null };
  } catch (err) {
    logger.error({ tenantId, err: err instanceof Error ? { name: err.name, message: err.message } : null }, 'Reconcile attach: learning mode could not be set');
    return { enabled: [], error: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * Attach the selected sites: verdicts as in the dry run, then each eligible
 * router proven over SSH and written (see the header), then what follows it
 * when `followUps` asks for it ("WHAT FOLLOWS THE ATTACH"; no options:
 * nothing). At most RECONCILE_ATTACH_APPLY_MAX_SITES per call.
 */
export async function applyAttach(
  tenantId: number,
  siteIds: readonly number[],
  credentials: AttachCredentials | null,
  actor: AttachActor,
  followUps: AttachFollowUpRequest | null = null,
  extra: { learning?: boolean } = {},
): Promise<ReconcileAttachResult> {
  assertPlatformAdmin(actor);
  if (siteIds.length === 0 || siteIds.length > RECONCILE_ATTACH_APPLY_MAX_SITES) {
    throw new ReconcileAttachError(
      'TOO_MANY_SITES',
      `Between 1 and ${RECONCILE_ATTACH_APPLY_MAX_SITES} sites per request: each one is dialled.`,
      400,
    );
  }
  const options = normaliseFollowUps(followUps ?? NO_FOLLOW_UPS);
  const correlationId = crypto.randomUUID();
  const { verdicts } = await evaluate(tenantId, siteIds, credentials, actor);
  // After the verdicts (reads only), before any dial: a request in which no
  // router is eligible attaches nothing and so queues nothing — there is
  // nothing for the confirmation to cover.
  if (verdicts.some((v) => v.target !== null)) {
    assertFollowUpsConfirmed(options, followUps?.confirmNoDeadman === true);
  }

  // Before any dial: /ppp/active read LIVE, once per concentrator, so a
  // second session that came up since the last recorded read is seen too.
  const liveDuplicates = await liveDuplicateSessions(verdicts.flatMap((v) => (v.target ? [v.target] : [])));

  const rows = await mapLimit(verdicts, ATTACH_CONCURRENCY, async (v): Promise<ReconcileAttachResultRow> => {
    const base = { siteId: v.row.siteId, code: v.row.code, name: v.row.name, login: v.row.login };
    if (!v.target) {
      return {
        ...base,
        outcome: 'skipped',
        reason: v.row.reason,
        detail: null,
        device: v.row.device,
        facts: null,
        followUps: [],
        ...(v.row.duplicateSessions ? { duplicateSessions: v.row.duplicateSessions } : {}),
      };
    }
    const t = v.target;
    const live = liveDuplicates.get(t.siteId);
    if (live) {
      logger.warn({ tenantId, siteId: t.siteId, login: t.login, sessions: live.length }, 'Reconcile attach: the login holds several live sessions; nothing dialled');
      return { ...base, outcome: 'skipped', reason: 'duplicate_sessions', detail: null, device: null, facts: null, followUps: [], duplicateSessions: live };
    }
    const proof = await prove(tenantId, t, actor, correlationId);
    if (!proof.ok) {
      logger.info({ tenantId, siteId: t.siteId, reason: proof.reason }, 'Reconcile attach: proof refused, nothing created');
      await auditRefusal(tenantId, t, actor, correlationId, proof.reason);
      return { ...base, outcome: 'failed', reason: proof.reason, detail: proof.detail, device: null, facts: null, followUps: [] };
    }
    const done = await commit(tenantId, t, proof.facts, proof.tunnel, actor, correlationId);
    if (!done.ok) {
      if (done.outcome === 'failed') await auditRefusal(tenantId, t, actor, correlationId, done.reason);
      return {
        ...base,
        outcome: done.outcome,
        reason: done.reason,
        detail: null,
        device: done.device,
        facts: proof.facts,
        followUps: [],
        ...(done.duplicateSessions ? { duplicateSessions: done.duplicateSessions } : {}),
      };
    }
    emitToTenantAudience(tenantId, SOCKET_EVENTS.DEVICE_CREATED, { device: toDeviceDto(done.device) }, { deviceId: done.device.id });
    logger.info(
      { tenantId, siteId: t.siteId, deviceId: done.device.id, by: actor.userId },
      'Reconcile attach: router proven over SSH and attached',
    );
    // After the commit: the job's enqueue reads the device it just wrote.
    const followUpResults = await queueFollowUps(tenantId, done.device.id, options, actor, correlationId);
    return {
      ...base,
      outcome: 'attached',
      reason: null,
      detail: null,
      device: { id: done.device.id, name: done.device.name },
      facts: proof.facts,
      followUps: followUpResults,
    };
  });

  const count = (o: ReconcileAttachResultRow['outcome']) => rows.filter((r) => r.outcome === o).length;
  const attachedIds = rows.flatMap((r) => (r.outcome === 'attached' && r.device ? [r.device.id] : []));
  const learning = extra.learning === true && attachedIds.length > 0 ? await putAttachedInLearning(tenantId, attachedIds, actor) : null;
  return {
    correlationId,
    rows,
    counts: { attached: count('attached'), failed: count('failed'), skipped: count('skipped') },
    learning,
  };
}
