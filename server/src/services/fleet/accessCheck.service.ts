/**
 * ObliWAN — verify, then re-apply, the management access and the template
 * fixes over a WHOLE workspace (written for a customer onboarding: a number of management_access jobs ended « échoué » and nobody
 * could see why without opening two hundred device pages).
 *
 * Shared vocabulary: shared/src/accessCheck.ts. Persisted in
 * `access_check_runs` / `access_check_results` (migration 092 says why a table
 * and not memory). Routes: `/api/reconcile/access-check[/reapply]`.
 *
 * ┌─ 1. VERIFY — READ-ONLY TOWARDS EVERY ROUTER ─────────────────────────────┐
 * │ Every ACTIVE MikroTik of the workspace that is not a concentrator (or    │
 * │ those the caller's teams grant `rw` on), ACCESS_CHECK_CONCURRENCY at a   │
 * │ time, each within ACCESS_CHECK_DEVICE_BUDGET_MS, in the web process like │
 * │ the infra analysis and the learning capture. Per router, in this order:  │
 * │   presence  (before anything is dialled) — the concentrator's            │
 * │             /ppp/active read LIVE, once per concentrator per run         │
 * │             (`readActiveLive`, the tunnel jobs' own gate read): one      │
 * │             session -> up, none -> down, several -> duplicated. When the │
 * │             live read fails: what presence recorded — a fresh recorded   │
 * │             duplicate, else the open `ppp_sessions` row (the health      │
 * │             check's predicate) — unless presence is DEGRADED on that     │
 * │             concentrator, which makes it `unknown`. A router down,       │
 * │             duplicated or unknown is not dialled.                         │
 * │   busy      a change job queued or running on it: not dialled either    │
 * │             (a half-done job is no state to judge).                      │
 * │   access    a LIVE proof over the RECORDED `routeros_api` transport: a   │
 * │             fresh TLS session to 8729 with the recorded account, dialled │
 * │             EXPECTING the pinned fingerprint (a certificate that is not  │
 * │             the pin is refused at the handshake, before `/login`), the   │
 * │             three ID attributes read (`readRouterOsIdentity`, the job's  │
 * │             and `assertTargetBinding`'s reader) and compared with the    │
 * │             record (`compareIdentity`, a rename's frozen pair accepted). │
 * │             Nothing is pinned, nothing is written: no `onFingerprint`,   │
 * │             and an UNPINNED row is never dialled (`not_pinned`: the      │
 * │             password would go to whatever answers). A channel that works │
 * │             under another account than `obliwan` is `broken`            │
 * │             (`account_not_switched`): the operator decision of            │
 * │             2026-10-04 is ObliWAN's own account on both channels.        │
 * │   fixes     the legacy_compliance job's OWN read (`readLegacyCompliance`)│
 * │             and planner (`legacyPlan`, the job's retired list), over the │
 * │             job's own channel — SSH with the device's credential — after │
 * │             the same identity proof as the job's sessions (identity,     │
 * │             serial, the l2tp-mgmt login, a rename's pair accepted). Only │
 * │             the job's read commands are sent, each audited before it is  │
 * │             sent (`command_audit`, purpose `access_check`).              │
 * │   failures  the LATEST management_access / legacy_compliance job of the  │
 * │             device when it did not succeed: its failed step and the      │
 * │             step's redacted error (else the job's message). Grouped by   │
 * │             kind + step + code + message — with what names the device   │
 * │             replaced — into the run's `causes`, counted.                  │
 * │ A proven identity MISMATCH (on either channel) is REPORTED, never acted  │
 * │ on: like the infra analysis and the learning capture, a read-only        │
 * │ analysis quarantines nothing; the re-apply skips the router            │
 * │ (`identity_mismatch`), and any job's own identity proof would quarantine │
 * │ it.                                                                      │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ 2. RE-APPLY — THE OPERATOR'S CLICK, THROUGH THE EXISTING DOORS ─────────┐
 * │ Only on the run the operator read (`runId`), done, not re-applied yet,   │
 * │ STARTED less than ACCESS_CHECK_FRESH_MS ago, with the safety-net rule's  │
 * │ explicit confirmation of the degraded level (`confirmNoDeadman`: neither │
 * │ job arms a dead-man — the attach dialog's own wording). The run is       │
 * │ marked re-applied FIRST (a conditional UPDATE: a double click queues     │
 * │ nothing twice), then, per marked router of the caller's scope:           │
 * │   management_access  `enqueueManagementAccessJob` (every rule of that    │
 * │                      job applies: refusals, kill switch, one job per    │
 * │                      device, its own identity proof and duplicate gate  │
 * │                      at bind_assert), and — when the fixes were not     │
 * │                      known to be in place — `legacy_compliance`         │
 * │                      PROMISED after it (`change_job_followups`, source  │
 * │                      `access_check`), kept by the worker once it        │
 * │                      SUCCEEDED, exactly as after the bulk attach;       │
 * │   legacy_compliance  `enqueueLegacyComplianceJob` with EXACTLY the fixes │
 * │                      the verification found missing (`fixes`: it only   │
 * │                      narrows the frozen list; the job re-reads and      │
 * │                      plans again at lint).                               │
 * │ Down, duplicated, presence unknown, busy, identity mismatch, a          │
 * │ certificate that is not the pin (the job refuses it by design: it never │
 * │ re-pins — a human checks, then re-pins from the device page), a state   │
 * │ that could not be read, a door that would refuse: skipped, each saying  │
 * │ why — decided at verification, recorded on the row. Nothing is retried. │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * SECRETS: the API and SSH passwords are decrypted for one session,
 * scrubbed from every error kept, and never stored in a result, a log line or
 * a response.
 */

import crypto from 'crypto';
import {
  ACCESS_CHECK_CONCURRENCY,
  ACCESS_CHECK_DEVICE_BUDGET_MS,
  ACCESS_CHECK_FRESH_MS,
  ACCESS_CHECK_MAX_DEVICES,
  ACCESS_CHECK_RUNS_KEPT,
  ACCESS_CHECK_STALE_RUN_MS,
  API_SSL_PORT,
  LEGACY_FIX_KEYS,
  OBLIWAN_ACCOUNT,
  accessCheckCounts,
  legacyPlan,
  legacyReasonUnobserved,
  managementTunnelLogin,
  type AccessCheckAccessReason,
  type AccessCheckAction,
  type AccessCheckAutoReapplySummary,
  type AccessCheckCause,
  type AccessCheckComplianceReason,
  type AccessCheckFailure,
  type AccessCheckJobKind,
  type AccessCheckReapplyResult,
  type AccessCheckReapplyRow,
  type AccessCheckRow,
  type AccessCheckRunStatus,
  type AccessCheckRunView,
  type AccessCheckScope,
  type AccessCheckSkipReason,
  type AccessCheckTrigger,
  type LegacyFixKey,
} from '@obliwan/shared';
import { evaluateAccessCheckAlertsSafe } from './accessCheckAlerts.service';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { decrypt } from '../secretVault.service';
import { readManagementRange } from '../bench/planning.service';
import { DriverError } from '../drivers/types';
import { withSsh } from '../transport/ssh.transport';
import {
  RouterOsAuthError,
  RouterOsFingerprintError,
  RouterOsTimeoutError,
  createRouterOsConnection,
  type RouterOsConnection,
  type RouterOsConnectionOptions,
} from '../transport/routeros';
import {
  AuditedCli,
  ManagementAccessError,
  SSH_READS,
  activeJobOf,
  enqueueManagementAccessJob,
  loadFacts,
  managementAccessDeviceRefusals,
  parseBoard,
  parseIdentity,
  parseL2tpClients,
  sshCredentialOf,
  sshHostOf,
  type Facts,
  type Refusal,
} from '../change/managementAccess.service';
import {
  LegacyComplianceError,
  enqueueLegacyComplianceJob,
  legacyComplianceDeviceRefusals,
  legacyComplianceRetiredFixes,
  readLegacyCompliance,
} from '../change/legacyCompliance.service';
import { recordFollowup } from '../change/jobFollowup.service';
import { DeviceBusyError } from '../change/jobQueue.service';
import { KillSwitchEngagedError, killSwitchSentenceFr, readKillSwitch } from '../change/killSwitch.service';
import { compareIdentity, readRouterOsIdentity, type ObservedIdentity } from './deviceBinding.service';
import { renameIdentityAlternates } from './identityAlternates';
import { isConcentratorDegraded } from './reachability.service';
import {
  RECORDED_READ_MAX_AGE_MS,
  readActiveLive,
  readActiveReads,
  readRecordedDuplicates,
  sessionsOfLogin,
  toDuplicateSession,
} from './pppDuplicates.service';
import type { PppActiveEntry } from './concentratorDiscovery.service';

// ============================================================================
// Seams and errors
// ============================================================================

export interface AccessCheckDeps {
  /** Dial the RouterOS API (the harness redirects the port to its fake). */
  openApi(options: RouterOsConnectionOptions): Promise<RouterOsConnection>;
  now(): number;
  deviceBudgetMs: number;
}
const DEFAULT_DEPS: AccessCheckDeps = {
  openApi: (options) => createRouterOsConnection(options),
  now: () => Date.now(),
  deviceBudgetMs: ACCESS_CHECK_DEVICE_BUDGET_MS,
};
let deps: AccessCheckDeps = { ...DEFAULT_DEPS };
export function setAccessCheckDeps(next: Partial<AccessCheckDeps>): void {
  deps = { ...deps, ...next };
}
export function resetAccessCheckDeps(): void {
  deps = { ...DEFAULT_DEPS };
}

/** A refusal of the whole request; the controller maps `httpStatus`. */
export class AccessCheckError extends Error {
  constructor(readonly reason: string, message: string, readonly httpStatus = 409) {
    super(message);
    this.name = 'AccessCheckError';
  }
}

export interface AccessCheckActor {
  userId: number;
}

/** The device ids the caller may act on (`rw`), or null for the whole
 *  workspace (teamScope.service `deviceListScope`). */
export type AccessCheckScopeIds = readonly number[] | null;

const SSH_TIMEOUT_MS = 20_000;
const API_TIMEOUT_MS = 15_000;
const DETAIL_MAX = 300;
const MESSAGE_MAX = 600;
const HEARTBEAT_EVERY_MS = 30_000;
const FAILED_STATUSES = ['failed', 'aborted', 'rolled_back'];
const JOB_KINDS: readonly AccessCheckJobKind[] = ['management_access', 'legacy_compliance'];

function cut(text: string | null | undefined, max = DETAIL_MAX): string | null {
  if (text === null || text === undefined) return null;
  const t = text.replace(/\s+/g, ' ').trim();
  if (t === '') return null;
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

function scrub(text: string, secrets: readonly string[]): string {
  let out = text;
  for (const s of secrets) if (s && s.length >= 4) out = out.split(s).join('***');
  return out;
}

function iso(d: Date | string | null | undefined): string | null {
  return d ? new Date(d).toISOString() : null;
}

// ============================================================================
// Pure: classifying, deciding, grouping
// ============================================================================

/** A failed API-SSL proof, as a reason code. */
export function classifyApiError(err: unknown): AccessCheckAccessReason {
  if (err instanceof RouterOsFingerprintError) return 'cert_mismatch';
  if (err instanceof RouterOsAuthError) return 'auth';
  if (err instanceof RouterOsTimeoutError) return 'timeout';
  const e = err as { code?: unknown; message?: unknown };
  const code = typeof e?.code === 'string' ? e.code : '';
  const message = typeof e?.message === 'string' ? e.message : String(err);
  if (code === 'ECONNREFUSED' || /ECONNREFUSED/.test(message)) return 'refused';
  if (code === 'ETIMEDOUT' || /timed out|timeout/i.test(message)) return 'timeout';
  if (/alert|TLS|SSL|handshake|certificate/i.test(message) || code.startsWith('ERR_SSL') || code.startsWith('ERR_TLS')) return 'tls';
  return 'unreachable';
}

/** A failed SSH session, as a reason code. */
export function classifySshError(err: unknown): AccessCheckComplianceReason {
  if (err instanceof DriverError) {
    if (err.code === 'AUTH_FAILED') return 'auth';
    if (err.code === 'UNREACHABLE') return 'unreachable';
    if (err.code === 'TIMEOUT') return 'timeout';
    return 'ssh_failed';
  }
  return 'internal';
}

type Presence = NonNullable<AccessCheckRow['presence']>;
type Access = NonNullable<AccessCheckRow['access']>;
type Compliance = NonNullable<AccessCheckRow['compliance']>;

export interface ActionDecision {
  action: AccessCheckAction;
  skipReason: AccessCheckSkipReason | null;
  refusal: { kind: string; message: string } | null;
  followUp: boolean;
}

/**
 * What the re-apply does for one router, from its verdicts (the header's
 * order). `refusals` are the doors' own, judged on the device's record:
 * those of management_access (the management range included) and those of
 * legacy_compliance.
 */
export function decideAction(input: {
  presence: Presence;
  busy: { jobId: number; kind: string } | null;
  access: Access;
  compliance: Compliance;
  accessRefusals: readonly Refusal[];
  complianceRefusals: readonly Refusal[];
}): ActionDecision {
  const skip = (skipReason: AccessCheckSkipReason, refusal: Refusal | null = null): ActionDecision => ({
    action: 'skip',
    skipReason,
    refusal: refusal ? { kind: refusal.kind, message: cut(refusal.message, 2000) ?? refusal.kind } : null,
    followUp: false,
  });
  if (input.presence.state === 'down') return skip('offline');
  if (input.presence.state === 'duplicated') return skip('duplicated');
  if (input.presence.state === 'unknown') return skip('presence_unknown');
  if (input.busy) return skip('busy');
  if (input.access.reason === 'identity_mismatch' || input.compliance.reason === 'identity_mismatch') {
    return skip('identity_mismatch');
  }
  const { access, compliance } = input;
  // A certificate that is not the pin is the TLS pin's interception signal: the
  // management_access job refuses it by design (it never re-pins), so a human
  // checks and re-pins from the device page.
  if (access.reason === 'cert_mismatch') return skip('cert_mismatch');
  if (access.state === 'missing' || access.state === 'broken') {
    if (input.accessRefusals.length > 0) return skip('refused', input.accessRefusals[0]);
    return { action: 'management_access', skipReason: null, refusal: null, followUp: compliance.state !== 'ok' };
  }
  if (access.state !== 'ok') return skip('access_unknown');
  if (compliance.state === 'ok') return { action: 'none', skipReason: null, refusal: null, followUp: false };
  if (compliance.state !== 'fixes_needed') return skip('compliance_unknown');
  if (input.complianceRefusals.length > 0) return skip('refused', input.complianceRefusals[0]);
  return { action: 'legacy_compliance', skipReason: null, refusal: null, followUp: false };
}

const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?:\/\d{1,2})?\b/g;
const HEX_RE = /\b[0-9a-f]{16,}\b/gi;
const JOB_REF_RE = /#\d+/g;
/** "device 17", "job 812", "tâche 9": the id of ONE object. */
const OBJECT_ID_RE = /(device|job|équipement|tâche)(\s+)\d+/gi;

/** A job message with what names ONE device replaced, so that the same
 *  failure on two hundred routers groups as one cause. */
export function normaliseFailureMessage(message: string | null, tokens: readonly (string | null | undefined)[]): string | null {
  if (message === null) return null;
  let out = message;
  // Longest first, so a name that contains another is replaced whole.
  const named = [...new Set(tokens.map((t) => (t ?? '').trim()).filter((t) => t.length >= 3))].sort((a, b) => b.length - a.length);
  for (const t of named) {
    out = out.replace(new RegExp(t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), '<équipement>');
  }
  out = out
    .replace(IPV4_RE, '<adresse>')
    .replace(HEX_RE, '<empreinte>')
    .replace(JOB_REF_RE, '#<n>')
    .replace(OBJECT_ID_RE, '$1$2<n>');
  return cut(out, MESSAGE_MAX);
}

/** The run's causes: its rows' failures grouped by kind, step, code and the
 *  normalised message, the largest first. */
export function groupFailureCauses(
  rows: ReadonlyArray<{ deviceId: number; failures: ReadonlyArray<AccessCheckFailure & { normalised?: string | null }> }>,
): AccessCheckCause[] {
  const groups = new Map<string, AccessCheckCause>();
  for (const r of rows) {
    for (const f of r.failures) {
      const message = f.normalised ?? f.message;
      const key = JSON.stringify([f.kind, f.step, f.errorKind, message]);
      const g = groups.get(key);
      if (g) {
        g.count += 1;
        if (!g.deviceIds.includes(r.deviceId)) g.deviceIds.push(r.deviceId);
      } else {
        groups.set(key, { kind: f.kind, step: f.step, errorKind: f.errorKind, message, count: 1, deviceIds: [r.deviceId] });
      }
    }
  }
  return [...groups.values()].sort((a, b) => b.count - a.count || a.kind.localeCompare(b.kind) || String(a.step).localeCompare(String(b.step)));
}

// ============================================================================
// The devices of a run
// ============================================================================

interface DeviceListRow {
  id: number;
  name: string;
  concentrator_id: number | null;
  ppp_username: string | null;
  site_id: number | null;
  site_code: string | null;
  site_name: string | null;
}

/** Every ACTIVE MikroTik of the workspace that is not a concentrator, in the
 *  caller's scope. */
async function devicesOf(tenantId: number, scope: AccessCheckScopeIds): Promise<DeviceListRow[]> {
  if (scope !== null && scope.length === 0) return [];
  const q = db('devices as d')
    .leftJoin('sites as s', function sameTenantSite(this: import('knex').Knex.JoinClause) {
      this.on('s.id', '=', 'd.site_id').andOn('s.tenant_id', '=', 'd.tenant_id');
    })
    .where('d.tenant_id', tenantId)
    .where('d.brand', 'mikrotik')
    .where('d.status', 'active')
    .where((w) => {
      w.whereNull('d.role').orWhereNot('d.role', 'concentrator');
    });
  if (scope !== null) q.whereIn('d.id', [...scope]);
  return (await q
    .orderBy('d.name')
    .orderBy('d.id')
    .select(
      'd.id as id', 'd.name as name', 'd.concentrator_id as concentrator_id', 'd.ppp_username as ppp_username',
      's.id as site_id', 's.code as site_code', 's.name as site_name',
    )) as DeviceListRow[];
}

// ============================================================================
// One router
// ============================================================================

type LiveRead = { ok: true; entries: PppActiveEntry[]; at: Date } | { ok: false; error: string };

interface RunContext {
  tenantId: number;
  runId: string;
  /** One live /ppp/active read per concentrator per run. */
  liveReads: Map<number, Promise<LiveRead>>;
  /** The management range, read once per run (management_access's refusal). */
  range: { ok: true; prefixes: string[] } | { ok: false; message: string };
  retired: readonly LegacyFixKey[];
}

function liveRead(ctx: RunContext, concentratorId: number): Promise<LiveRead> {
  let p = ctx.liveReads.get(concentratorId);
  if (!p) {
    p = readActiveLive(concentratorId).then(
      (entries): LiveRead => ({ ok: true, entries, at: new Date(deps.now()) }),
      (err: unknown): LiveRead => ({ ok: false, error: err instanceof Error ? err.message : String(err) }),
    );
    ctx.liveReads.set(concentratorId, p);
  }
  return p;
}

async function presenceOf(ctx: RunContext, d: DeviceListRow): Promise<Presence> {
  const login = (d.ppp_username ?? '').trim();
  if (d.concentrator_id === null || login === '') return { state: 'not_applicable', source: null, sessions: [] };
  const chr = Number(d.concentrator_id);
  const live = await liveRead(ctx, chr);
  if (live.ok) {
    const mine = sessionsOfLogin(live.entries, login);
    if (mine.length >= 2) {
      return { state: 'duplicated', source: 'live', sessions: mine.map((e) => toDuplicateSession(e, live.at)) };
    }
    return { state: mine.length === 1 ? 'up' : 'down', source: 'live', sessions: [] };
  }
  // The live read failed: what presence recorded — unless presence itself is
  // degraded on this concentrator, whose open rows are then only the last
  // sessions it saw.
  if (await isConcentratorDegraded(chr)) return { state: 'unknown', source: null, sessions: [] };
  const read = (await readActiveReads(db, [chr])).get(chr);
  if (read && deps.now() - new Date(read.readAt).getTime() <= RECORDED_READ_MAX_AGE_MS) {
    const [dup] = await readRecordedDuplicates(db, [chr], [login.toLowerCase()]);
    if (dup) return { state: 'duplicated', source: 'recorded', sessions: dup.sessions };
  }
  const open = await db('ppp_sessions')
    .where({ concentrator_id: chr, ppp_username: d.ppp_username })
    .whereNull('ended_at')
    .first('id');
  return { state: open ? 'up' : 'down', source: 'recorded', sessions: [] };
}

/** The latest job of each kind on the device, when it did not succeed. */
async function lastFailures(tenantId: number, deviceId: number): Promise<AccessCheckFailure[]> {
  const jobs = (await db('change_jobs')
    .where({ tenant_id: tenantId, device_id: deviceId })
    .whereIn('kind', [...JOB_KINDS])
    .orderBy('id', 'desc')
    .limit(50)
    .select('id', 'kind', 'status', 'error_kind', 'error_message', 'finished_at')) as Array<{
    id: string | number; kind: AccessCheckJobKind; status: string; error_kind: string | null; error_message: string | null;
    finished_at: Date | null;
  }>;
  const out: AccessCheckFailure[] = [];
  for (const kind of JOB_KINDS) {
    const latest = jobs.find((j) => j.kind === kind);
    if (!latest || !FAILED_STATUSES.includes(latest.status)) continue;
    const step = (await db('change_job_steps')
      .where({ job_id: latest.id, status: 'failed' })
      .orderBy([{ column: 'attempt', order: 'desc' }, { column: 'seq', order: 'desc' }])
      .first('kind', 'error_redacted')) as { kind: string; error_redacted: string | null } | undefined;
    out.push({
      kind,
      jobId: Number(latest.id),
      status: latest.status,
      finishedAt: iso(latest.finished_at),
      step: step?.kind ?? null,
      errorKind: latest.error_kind ?? null,
      message: cut(step?.error_redacted ?? latest.error_message, MESSAGE_MAX),
    });
  }
  return out;
}

/** The live proof of the management access (header, "access"). Never throws. */
async function proveAccess(facts: Facts): Promise<Access> {
  const api = facts.api;
  const d = facts.device;
  const account = api?.username ?? null;
  const verdict = (state: Access['state'], reason: AccessCheckAccessReason | null, detail: string | null = null): Access =>
    ({ state, reason, detail: cut(detail), account });
  if (!api) return verdict('missing', 'no_transport');
  if (!api.enabled) return verdict('missing', 'transport_disabled');
  if (!api.use_tls) return verdict('missing', 'not_tls');
  if (Number(api.port) !== API_SSL_PORT) return verdict('missing', 'not_8729', `port ${api.port ?? '—'}`);
  const host = (api.host ?? d.tunnel_ip ?? '').trim();
  if (!host || !api.username || !api.secret_enc) return verdict('missing', 'no_credential');
  // Unpinned: never dialled — the password would go to whatever answers.
  if (!api.tls_fingerprint_sha256) return verdict('broken', 'not_pinned');
  let password: string;
  try {
    password = decrypt(api.secret_enc);
  } catch {
    return verdict('unknown', 'vault');
  }
  let conn: RouterOsConnection | null = null;
  let observed: ObservedIdentity;
  try {
    conn = await deps.openApi({
      host,
      port: API_SSL_PORT,
      tls: true,
      username: api.username,
      password,
      // The pin, at the handshake: nothing reaches /login on another
      // certificate. No `onFingerprint`: nothing is ever pinned here.
      expectedFingerprint: api.tls_fingerprint_sha256,
      connectTimeoutMs: API_TIMEOUT_MS,
      loginTimeoutMs: API_TIMEOUT_MS,
      requestTimeoutMs: API_TIMEOUT_MS,
      label: `access_check:${d.name}`,
    });
    observed = await readRouterOsIdentity(conn, d.ppp_username);
  } catch (err) {
    const message = scrub(err instanceof Error ? err.message : String(err), [password]);
    return verdict('broken', classifyApiError(err), message);
  } finally {
    conn?.close();
  }
  if (!observed.systemIdentity && !observed.serial && !observed.pppUsername) {
    return verdict('broken', 'identity_unproven', 'the API answered no identity attribute');
  }
  const cmp = compareIdentity(
    { ppp_username: d.ppp_username, system_identity: d.system_identity, serial: d.serial },
    observed,
    await renameIdentityAlternates(d.id),
  );
  if (!cmp.ok) return verdict('broken', cmp.mismatched > 0 ? 'identity_mismatch' : 'identity_unproven', cmp.reason);
  const sshUser = facts.ssh?.username ?? null;
  if (api.username !== OBLIWAN_ACCOUNT || (sshUser !== null && sshUser !== OBLIWAN_ACCOUNT)) {
    return verdict('broken', 'account_not_switched', `API: ${api.username}; SSH: ${sshUser ?? '—'}`);
  }
  return verdict('ok', null);
}

/** The legacy_compliance job's read and plan, over its channel (header,
 *  "fixes"). Never throws. */
async function readCompliance(ctx: RunContext, facts: Facts): Promise<Compliance> {
  const d = facts.device;
  const unknown = (reason: AccessCheckComplianceReason, detail: string | null = null): Compliance =>
    ({ state: 'unknown', reason, detail: cut(detail), fixes: [], unobserved: [] });
  const ssh = facts.ssh;
  if (!ssh || !ssh.enabled || !sshHostOf(facts) || !ssh.username || !ssh.secret_enc) return unknown('no_ssh');
  let cred: ReturnType<typeof sshCredentialOf>;
  try {
    cred = sshCredentialOf(facts);
  } catch (err) {
    return err instanceof ManagementAccessError ? unknown('no_ssh') : unknown('vault');
  }
  try {
    return await withSsh(
      {
        host: cred.host,
        port: cred.port,
        username: cred.username,
        password: cred.password,
        timeoutMs: SSH_TIMEOUT_MS,
        legacyAlgorithms: cred.legacyAlgorithms,
      },
      async (session): Promise<Compliance> => {
        const cli = new AuditedCli(
          session,
          {
            tenantId: ctx.tenantId,
            deviceId: d.id,
            deviceUuid: d.uuid,
            deviceName: d.name,
            jobId: null,
            correlationId: ctx.runId,
            purpose: 'access_check',
          },
          [cred.password],
        );
        // The identity proof every session of the job makes — reported here,
        // never acted on (header).
        const observed: ObservedIdentity = {
          systemIdentity: parseIdentity(await cli.read(SSH_READS.identity)),
          serial: parseBoard(await cli.read(SSH_READS.board)).serial,
          pppUsername: managementTunnelLogin(parseL2tpClients(await cli.read(SSH_READS.l2tp)), d.ppp_username).login,
        };
        if (!observed.systemIdentity && !observed.serial && !observed.pppUsername) {
          return unknown('identity_unproven', 'the SSH session answered no identity attribute');
        }
        const cmp = compareIdentity(
          { ppp_username: d.ppp_username, system_identity: d.system_identity, serial: d.serial },
          observed,
          await renameIdentityAlternates(d.id),
        );
        if (!cmp.ok) return unknown(cmp.mismatched > 0 ? 'identity_mismatch' : 'identity_unproven', cmp.reason);
        const reading = await readLegacyCompliance(cli);
        const requested = LEGACY_FIX_KEYS.filter((k) => !ctx.retired.includes(k));
        const plan = legacyPlan(reading, requested, ctx.retired);
        const fixes = requested.filter((k) => plan.fixes[k].state === 'needed');
        const unobserved = requested.filter((k) => plan.fixes[k].state === 'skipped' && legacyReasonUnobserved(plan.fixes[k].reason));
        return { state: fixes.length > 0 ? 'fixes_needed' : 'ok', reason: null, detail: null, fixes, unobserved };
      },
    );
  } catch (err) {
    const message = scrub(err instanceof Error ? err.message : String(err), [cred.password]);
    return unknown(classifySshError(err), message);
  }
}

/** What a run stores per router (the row without its live name and site,
 *  read at display time, and without the re-apply, its own column). */
type StoredResult = Omit<AccessCheckRow, 'deviceId' | 'deviceName' | 'site' | 'state' | 'reapply'> & {
  /** Per failure, the message normalised for grouping. */
  normalised: Array<string | null>;
};

const NOT_CHECKED_ACCESS: Access = { state: 'not_checked', reason: null, detail: null, account: null };
const NOT_CHECKED_COMPLIANCE: Compliance = { state: 'not_checked', reason: null, detail: null, fixes: [], unobserved: [] };

async function verifyDevice(ctx: RunContext, d: DeviceListRow): Promise<StoredResult> {
  const facts = await loadFacts(d.id, ctx.tenantId);
  if (!facts) throw new Error(`device ${d.id} vanished from the workspace`);
  const failures = await lastFailures(ctx.tenantId, d.id);
  const presence = await presenceOf(ctx, d);
  const active = await activeJobOf(d.id);
  const busy = active ? { jobId: active.id, kind: active.kind } : null;
  let access = NOT_CHECKED_ACCESS;
  let compliance = NOT_CHECKED_COMPLIANCE;
  if ((presence.state === 'up' || presence.state === 'not_applicable') && !busy) {
    access = await proveAccess(facts);
    compliance = await readCompliance(ctx, facts);
  }
  const accessRefusals = [
    ...(ctx.range.ok ? [] : [{ kind: 'range_invalid', message: ctx.range.message }]),
    ...managementAccessDeviceRefusals(facts),
  ];
  const decision = decideAction({
    presence,
    busy,
    access,
    compliance,
    accessRefusals,
    complianceRefusals: legacyComplianceDeviceRefusals(facts),
  });
  const tokens = [
    facts.device.name, facts.device.ppp_username, facts.device.system_identity, facts.device.serial, d.site_code,
    facts.ssh?.host, facts.api?.host, facts.device.tunnel_ip,
  ];
  return {
    presence,
    busy,
    access,
    compliance,
    failures,
    normalised: failures.map((f) => normaliseFailureMessage(f.message, tokens)),
    action: decision.action,
    skipReason: decision.skipReason,
    refusal: decision.refusal,
    followUp: decision.followUp,
    checkedAt: new Date(deps.now()).toISOString(),
  };
}

/** The verdict of a router that ran out of its budget, or whose check threw. */
function unknownResult(reason: 'budget_exceeded' | 'internal', failures: AccessCheckFailure[] = []): StoredResult {
  return {
    presence: null,
    busy: null,
    access: { state: 'unknown', reason, detail: null, account: null },
    compliance: { state: 'unknown', reason, detail: null, fixes: [], unobserved: [] },
    failures,
    normalised: failures.map((f) => f.message),
    action: 'skip',
    skipReason: 'access_unknown',
    refusal: null,
    followUp: false,
    checkedAt: new Date(deps.now()).toISOString(),
  };
}

function withBudget<T>(p: Promise<T>, ms: number): Promise<T | typeof BUDGET> {
  let timer: NodeJS.Timeout | null = null;
  const t = new Promise<typeof BUDGET>((resolve) => {
    timer = setTimeout(() => resolve(BUDGET), ms);
    timer.unref?.();
  });
  return Promise.race([p, t]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}
const BUDGET = Symbol('budget');

async function mapLimit<T>(items: readonly T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      await fn(items[i]);
    }
  });
  await Promise.all(workers);
}

// ============================================================================
// Runs
// ============================================================================

/** `running` rows whose heartbeat stopped: a run a restart killed. */
export async function markStaleAccessChecks(tenantId: number): Promise<number> {
  return db('access_check_runs')
    .where({ tenant_id: tenantId, status: 'running' })
    .andWhere('heartbeat_at', '<', new Date(deps.now() - ACCESS_CHECK_STALE_RUN_MS))
    .update({ status: 'interrupted', finished_at: db.fn.now() });
}

/** A run the nightly verification starts (accessCheckNightly.service.ts):
 *  the whole workspace, nobody's, carrying its night. */
export interface AccessCheckStartOptions {
  trigger: 'nightly';
  /** The Europe/Paris date of the hour it was due at (YYYY-MM-DD). */
  nightDate: string;
}

/**
 * Start a verification of the workspace (header, "1. VERIFY"). Answers at
 * once with the run (every router `pending`); the routers are verified in the
 * background and `done` settles when they all were — and, for a run over the
 * whole workspace, once its alerts were evaluated (accessCheckAlerts.service).
 * `actor` is null for the nightly run (`options`), which covers the whole
 * workspace.
 */
export async function startAccessCheck(
  tenantId: number,
  actor: AccessCheckActor | null,
  scope: AccessCheckScopeIds,
  options?: AccessCheckStartOptions,
): Promise<{ view: AccessCheckRunView; done: Promise<void>; runPk: number }> {
  const trigger: AccessCheckTrigger = options?.trigger ?? 'manual';
  if (trigger === 'nightly' && scope !== null) throw new Error('a nightly verification covers the whole workspace');
  if (trigger === 'manual' && actor === null) throw new Error('a manual verification names its operator');
  await markStaleAccessChecks(tenantId);
  const running = await db('access_check_runs').where({ tenant_id: tenantId, status: 'running' }).first('run_id');
  if (running) {
    throw new AccessCheckError('RUN_RUNNING', 'A verification of this workspace is still running: wait for it to end.', 409);
  }
  const devices = await devicesOf(tenantId, scope);
  if (devices.length === 0) {
    throw new AccessCheckError('NO_DEVICES', 'This workspace has no active MikroTik router to verify (in your scope).', 422);
  }
  if (devices.length > ACCESS_CHECK_MAX_DEVICES) {
    throw new AccessCheckError('TOO_MANY_DEVICES', `At most ${ACCESS_CHECK_MAX_DEVICES} routers per verification.`, 422);
  }
  const runId = crypto.randomUUID();
  let runPk: number;
  try {
    runPk = await db.transaction(async (trx) => {
      const [row] = (await trx('access_check_runs')
        .insert({
          run_id: runId,
          tenant_id: tenantId,
          requested_by: actor?.userId ?? null,
          scope: scope === null ? 'tenant' : 'teams',
          trigger,
          night_date: options?.nightDate ?? null,
          status: 'running',
          total: devices.length,
          started_at: new Date(deps.now()),
          heartbeat_at: new Date(deps.now()),
        })
        .returning('id')) as Array<{ id: string | number }>;
      const id = Number(row.id);
      for (let i = 0; i < devices.length; i += 500) {
        await trx('access_check_results').insert(
          devices.slice(i, i + 500).map((d) => ({ run_id: id, tenant_id: tenantId, device_id: d.id, state: 'pending' })),
        );
      }
      return id;
    });
  } catch (err) {
    const pg = err as { code?: string; constraint?: string };
    if (pg.code === '23505' && pg.constraint === 'access_check_runs_one_night_uq') {
      throw new AccessCheckError('NIGHT_TAKEN', 'This night was already verified (or is being verified) for this workspace.', 409);
    }
    if (pg.code === '23505') {
      throw new AccessCheckError('RUN_RUNNING', 'A verification of this workspace is still running: wait for it to end.', 409);
    }
    throw err;
  }
  // Keep the newest runs only (never a running one).
  const keep = (await db('access_check_runs')
    .where({ tenant_id: tenantId })
    .orderBy('id', 'desc')
    .limit(ACCESS_CHECK_RUNS_KEPT)
    .pluck('id')) as Array<string | number>;
  await db('access_check_runs')
    .where({ tenant_id: tenantId })
    .whereNot('status', 'running')
    .whereNotIn('id', keep.map(Number))
    .delete();

  const range = await readManagementRange();
  const ctx: RunContext = {
    tenantId,
    runId,
    liveReads: new Map(),
    range: range.ok ? { ok: true, prefixes: range.prefixes } : { ok: false, message: range.message },
    retired: legacyComplianceRetiredFixes(),
  };
  logger.info(
    { tenantId, runId, devices: devices.length, by: actor?.userId ?? null, trigger, scope: scope === null ? 'tenant' : 'teams' },
    'Access check started',
  );
  // The answer is the run as it starts (every router pending), read before
  // the first router is dialled.
  const view = await latestAccessCheck(tenantId, scope, runId);
  const done = runChecks(ctx, runPk, devices)
    .catch((err: unknown) => {
      logger.error({ tenantId, runId, err: err instanceof Error ? { name: err.name, message: err.message } : null }, 'Access check: the run stopped');
    })
    // Its alerts (a run over part of the workspace, or one that did not
    // verify every router, moves none — the evaluation says so and stamps it).
    .then(() => evaluateAccessCheckAlertsSafe(tenantId, runPk))
    .then(() => undefined);
  return { view: view as AccessCheckRunView, done, runPk };
}

async function runChecks(ctx: RunContext, runPk: number, devices: DeviceListRow[]): Promise<void> {
  const beat = setInterval(() => {
    void db('access_check_runs').where({ id: runPk, status: 'running' }).update({ heartbeat_at: new Date(deps.now()) }).catch(() => undefined);
  }, HEARTBEAT_EVERY_MS);
  beat.unref?.();
  try {
    await mapLimit(devices, ACCESS_CHECK_CONCURRENCY, async (d) => {
      let result: StoredResult;
      try {
        const r = await withBudget(verifyDevice(ctx, d), deps.deviceBudgetMs);
        if (r === BUDGET) {
          logger.warn({ tenantId: ctx.tenantId, runId: ctx.runId, deviceId: d.id }, 'Access check: a router ran out of its budget');
          result = unknownResult('budget_exceeded', await lastFailures(ctx.tenantId, d.id).catch(() => []));
        } else {
          result = r;
        }
      } catch (err) {
        logger.error(
          { tenantId: ctx.tenantId, runId: ctx.runId, deviceId: d.id, err: err instanceof Error ? { name: err.name, message: err.message } : null },
          'Access check: a router could not be verified',
        );
        result = unknownResult('internal');
      }
      await db('access_check_results')
        .where({ run_id: runPk, device_id: d.id, state: 'pending' })
        .update({ state: 'done', result: JSON.stringify(result), action: result.action, checked_at: new Date(deps.now()) });
      await db('access_check_runs').where({ id: runPk, status: 'running' }).update({ heartbeat_at: new Date(deps.now()) });
    });
  } finally {
    clearInterval(beat);
    await db('access_check_runs')
      .where({ id: runPk, status: 'running' })
      .update({ status: 'done', finished_at: new Date(deps.now()), heartbeat_at: new Date(deps.now()) });
    logger.info({ tenantId: ctx.tenantId, runId: ctx.runId }, 'Access check finished');
  }
}

interface RunRow {
  id: string | number;
  run_id: string;
  tenant_id: number;
  requested_by: number | null;
  requested_by_name: string | null;
  scope: AccessCheckScope;
  trigger: AccessCheckTrigger;
  status: AccessCheckRunStatus;
  total: number;
  started_at: Date;
  finished_at: Date | null;
  reapplied_at: Date | null;
  reapply_trigger: AccessCheckTrigger | null;
  auto_reapply: AccessCheckAutoReapplySummary | null;
}

function isFresh(run: Pick<RunRow, 'status' | 'started_at' | 'reapplied_at'>): boolean {
  return run.status === 'done' && run.reapplied_at === null && deps.now() - new Date(run.started_at).getTime() < ACCESS_CHECK_FRESH_MS;
}

/**
 * The workspace's latest verification (or the one named), stale runs first
 * marked `interrupted`; null when there is none. Rows are those of the
 * caller's scope (`rw`): a teams-scoped caller never reads a router outside it.
 */
export async function latestAccessCheck(
  tenantId: number,
  scope: AccessCheckScopeIds,
  runId?: string,
): Promise<AccessCheckRunView | null> {
  await markStaleAccessChecks(tenantId);
  const q = db('access_check_runs as r')
    .leftJoin('users as u', 'u.id', 'r.requested_by')
    .where('r.tenant_id', tenantId);
  if (runId !== undefined) q.where('r.run_id', runId);
  const run = (await q
    .orderBy('r.id', 'desc')
    .first(
      'r.id', 'r.run_id', 'r.tenant_id', 'r.requested_by', 'u.username as requested_by_name', 'r.scope', 'r.status',
      'r.total', 'r.started_at', 'r.finished_at', 'r.reapplied_at', 'r.trigger', 'r.reapply_trigger', 'r.auto_reapply',
    )) as RunRow | undefined;
  if (!run) return null;
  const rq = db('access_check_results as x')
    .join('devices as d', 'd.id', 'x.device_id')
    .leftJoin('sites as s', function sameTenantSite(this: import('knex').Knex.JoinClause) {
      this.on('s.id', '=', 'd.site_id').andOn('s.tenant_id', '=', 'd.tenant_id');
    })
    .where('x.run_id', run.id)
    .where('x.tenant_id', tenantId)
    .where('d.tenant_id', tenantId);
  if (scope !== null) rq.whereIn('x.device_id', [...scope]);
  const raw = (await rq
    .orderBy('d.name')
    .orderBy('d.id')
    .select('x.device_id', 'd.name as device_name', 's.id as site_id', 's.code as site_code', 's.name as site_name',
      'x.state', 'x.result', 'x.reapply')) as Array<{
    device_id: number; device_name: string; site_id: number | null; site_code: string | null; site_name: string | null;
    state: 'pending' | 'done'; result: StoredResult | null; reapply: AccessCheckReapplyRow | null;
  }>;
  const grouped: Array<{ deviceId: number; failures: Array<AccessCheckFailure & { normalised?: string | null }> }> = [];
  const rows: AccessCheckRow[] = raw.map((r) => {
    const res = r.result;
    if (res) {
      grouped.push({
        deviceId: Number(r.device_id),
        failures: res.failures.map((f, i) => ({ ...f, normalised: res.normalised?.[i] ?? f.message })),
      });
    }
    return {
      deviceId: Number(r.device_id),
      deviceName: r.device_name,
      site: r.site_id === null ? null : { id: Number(r.site_id), code: r.site_code as string, name: r.site_name as string },
      state: r.state,
      presence: res?.presence ?? null,
      busy: res?.busy ?? null,
      access: res?.access ?? null,
      compliance: res?.compliance ?? null,
      failures: res?.failures ?? [],
      action: res?.action ?? null,
      skipReason: res?.skipReason ?? null,
      refusal: res?.refusal ?? null,
      followUp: res?.followUp ?? false,
      checkedAt: res?.checkedAt ?? null,
      reapply: r.reapply ?? null,
    };
  });
  return {
    runId: run.run_id,
    number: Number(run.id),
    trigger: run.trigger ?? 'manual',
    status: run.status,
    scope: run.scope,
    requestedBy: run.requested_by === null ? null : { id: Number(run.requested_by), username: run.requested_by_name ?? '' },
    offline: rows.filter((r) => r.skipReason === 'offline').length,
    autoReapply: run.auto_reapply ?? null,
    reapplyTrigger: run.reapply_trigger ?? null,
    startedAt: iso(run.started_at) as string,
    finishedAt: iso(run.finished_at),
    fresh: isFresh(run),
    freshUntil: new Date(new Date(run.started_at).getTime() + ACCESS_CHECK_FRESH_MS).toISOString(),
    reappliedAt: iso(run.reapplied_at),
    counts: accessCheckCounts(rows),
    causes: groupFailureCauses(grouped),
    rows,
  };
}

// ============================================================================
// Re-apply
// ============================================================================

/** A door's refusal, as the row records it. The job services' sentences are
 *  French and kept as they are; an unexpected error is logged and named only
 *  by a fixed sentence. */
function doorRefusal(err: unknown, deviceId: number): { reason: string; message: string } {
  if (err instanceof ManagementAccessError || err instanceof LegacyComplianceError) {
    return { reason: err.kind, message: err.message.slice(0, 2000) };
  }
  if (err instanceof KillSwitchEngagedError) {
    return { reason: 'kill_switch', message: `${killSwitchSentenceFr(err)} : aucune écriture n’est possible.` };
  }
  if (err instanceof DeviceBusyError) {
    return { reason: 'device_busy', message: 'Une autre tâche est en cours sur ce routeur : relancez quand elle sera terminée.' };
  }
  logger.error({ err, deviceId }, 'Access check re-apply: a job could not be queued');
  return { reason: 'error', message: 'Erreur interne à la mise en file (voir le journal du serveur).' };
}

/** One marked router of a run, as the re-apply acts on it. */
export interface ReapplyTarget {
  /** `access_check_results.id`: the row that records what was done. */
  resultId: number;
  deviceId: number;
  action: AccessCheckJobKind;
  /** management_access only: promise the template fixes after it. */
  followUp: boolean;
  /** legacy_compliance only: exactly the fixes found missing. */
  fixes: readonly LegacyFixKey[];
}

/**
 * Queue the job one marked router needs, through its kind's own door — the
 * button's path and the night's alike (accessCheckNightly.service.ts). The
 * night names no requester and carries the standing consent of the
 * administrator who turned it on as the safety-net confirmation. Records the
 * outcome on the result row and returns it; never throws for a door's
 * refusal.
 */
export async function enqueueReapplyRow(
  tenantId: number,
  m: ReapplyTarget,
  who: { requestedBy: number | null; confirmedBy: number; correlationId: string },
): Promise<AccessCheckReapplyRow> {
  const at = new Date(deps.now()).toISOString();
  let row: AccessCheckReapplyRow;
  if (m.action === 'management_access') {
    try {
      const queued = await enqueueManagementAccessJob({
        tenantId,
        deviceId: m.deviceId,
        requestedBy: who.requestedBy,
        confirmDegraded: { userId: who.confirmedBy },
        allowExisting: false,
      });
      let followupId: number | null = null;
      let message: string | null = null;
      if (m.followUp) {
        try {
          followupId = await recordFollowup({
            tenantId,
            deviceId: m.deviceId,
            afterJobId: queued.jobId,
            thenKind: 'legacy_compliance',
            requestedBy: who.requestedBy,
            confirmedBy: who.confirmedBy,
            source: 'access_check',
            correlationId: who.correlationId,
          });
        } catch (err) {
          logger.error({ err, tenantId, deviceId: m.deviceId, jobId: queued.jobId }, 'Access check re-apply: the compliance follow-up could not be recorded');
          message =
            'Les correctifs des modèles n’ont pas pu être programmés après l’accès de gestion (erreur interne, voir le ' +
            'journal du serveur) : lancez-les depuis la fiche de l’équipement une fois l’accès ouvert.';
        }
      }
      row = { status: 'queued', kind: 'management_access', jobId: queued.jobId, followupId, reason: null, message, at };
    } catch (err) {
      row = { status: 'refused', kind: 'management_access', jobId: null, followupId: null, ...doorRefusal(err, m.deviceId), at };
    }
  } else {
    try {
      const queued = await enqueueLegacyComplianceJob({
        tenantId,
        deviceId: m.deviceId,
        requestedBy: who.requestedBy,
        confirmDegraded: { userId: who.confirmedBy },
        allowExisting: false,
        fixes: m.fixes,
      });
      row = { status: 'queued', kind: 'legacy_compliance', jobId: queued.jobId, followupId: null, reason: null, message: null, at };
    } catch (err) {
      row = { status: 'refused', kind: 'legacy_compliance', jobId: null, followupId: null, ...doorRefusal(err, m.deviceId), at };
    }
  }
  await db('access_check_results').where({ id: m.resultId }).update({ reapply: JSON.stringify(row) });
  return row;
}

/**
 * Re-apply the run the operator read (header, "2. RE-APPLY"). `deviceIds`
 * narrows it to some of the routers it marked; absent, every marked router
 * of the caller's scope.
 */
export async function reapplyAccessCheck(
  tenantId: number,
  actor: AccessCheckActor,
  input: { runId: string; confirmNoDeadman: boolean; deviceIds?: readonly number[] },
  scope: AccessCheckScopeIds,
): Promise<AccessCheckReapplyResult> {
  if (input.confirmNoDeadman !== true) {
    throw new AccessCheckError(
      'DEGRADED_UNCONFIRMED',
      'Neither job arms a dead-man: re-applying needs the explicit confirmation of the degraded safety level (confirmNoDeadman). Nothing was queued.',
      422,
    );
  }
  await markStaleAccessChecks(tenantId);
  const run = (await db('access_check_runs')
    .where({ tenant_id: tenantId, run_id: input.runId })
    .first('id', 'status', 'started_at', 'reapplied_at')) as Pick<RunRow, 'id' | 'status' | 'started_at' | 'reapplied_at'> | undefined;
  if (!run) throw new AccessCheckError('RUN_NOT_FOUND', 'No such verification in this workspace.', 404);
  if (run.status !== 'done') {
    throw new AccessCheckError('RUN_NOT_DONE', 'This verification has not finished (or was interrupted): verify again.', 409);
  }
  if (run.reapplied_at !== null) {
    throw new AccessCheckError('ALREADY_REAPPLIED', 'This verification was already re-applied: verify again before re-applying.', 409);
  }
  if (!isFresh(run)) {
    throw new AccessCheckError(
      'STALE',
      `This verification is more than ${Math.round(ACCESS_CHECK_FRESH_MS / 60_000)} minutes old: verify again before re-applying.`,
      409,
    );
  }
  const latest = (await db('access_check_runs').where({ tenant_id: tenantId }).orderBy('id', 'desc').first('id')) as { id: string | number };
  if (Number(latest.id) !== Number(run.id)) {
    throw new AccessCheckError('NOT_LATEST', 'A newer verification of this workspace exists: re-apply that one.', 409);
  }
  const killSwitch = await readKillSwitch(tenantId);
  if (killSwitch.blocked) throw new KillSwitchEngagedError(killSwitch);

  const q = db('access_check_results as x')
    .join('devices as d', 'd.id', 'x.device_id')
    .where('x.run_id', run.id)
    .where('x.tenant_id', tenantId)
    .where('d.tenant_id', tenantId)
    .where('x.state', 'done')
    .whereIn('x.action', ['management_access', 'legacy_compliance', 'skip']);
  if (scope !== null) q.whereIn('x.device_id', [...scope]);
  if (input.deviceIds !== undefined) q.whereIn('x.device_id', [...input.deviceIds]);
  const rows = (await q.orderBy('d.name').orderBy('d.id').select('x.id', 'x.device_id', 'd.name as device_name', 'x.action', 'x.result')) as Array<{
    id: string | number; device_id: number; device_name: string; action: AccessCheckJobKind | 'skip'; result: StoredResult;
  }>;
  const marked = rows.filter((r): r is (typeof rows)[number] & { action: AccessCheckJobKind } => r.action !== 'skip');
  if (marked.length === 0) {
    throw new AccessCheckError('NOTHING_TO_REAPPLY', 'This verification marked no router to re-apply (in your scope).', 422);
  }

  // Marked FIRST and conditionally: a second click, or a second operator,
  // queues nothing twice.
  const claimed = await db('access_check_runs')
    .where({ id: run.id, status: 'done' })
    .whereNull('reapplied_at')
    .update({ reapplied_at: new Date(deps.now()), reapplied_by: actor.userId, reapply_trigger: 'manual' });
  if (claimed === 0) {
    throw new AccessCheckError('ALREADY_REAPPLIED', 'This verification was already re-applied: verify again before re-applying.', 409);
  }

  const correlationId = crypto.randomUUID();
  const out: AccessCheckReapplyResult['rows'] = [];
  for (const m of marked) {
    const row = await enqueueReapplyRow(tenantId, {
      resultId: Number(m.id),
      deviceId: Number(m.device_id),
      action: m.action,
      followUp: m.result.followUp,
      fixes: m.result.compliance?.fixes ?? [],
    }, { requestedBy: actor.userId, confirmedBy: actor.userId, correlationId });
    out.push({ ...row, deviceId: Number(m.device_id), deviceName: m.device_name });
  }
  // The routers the verification left alone, each with the reason it gave:
  // nothing was attempted for them, so nothing is recorded on their rows.
  for (const s of rows.filter((r) => r.action === 'skip')) {
    out.push({
      status: 'skipped',
      kind: null,
      jobId: null,
      followupId: null,
      reason: s.result.skipReason,
      message: s.result.refusal?.message ?? null,
      at: new Date(deps.now()).toISOString(),
      deviceId: Number(s.device_id),
      deviceName: s.device_name,
    });
  }
  const count = (s: AccessCheckReapplyRow['status']) => out.filter((r) => r.status === s).length;
  logger.warn(
    { tenantId, runId: input.runId, by: actor.userId, queued: count('queued'), refused: count('refused') },
    'Access check re-applied — management_access / legacy_compliance jobs queued on customer routers',
  );
  return { runId: input.runId, counts: { queued: count('queued'), refused: count('refused'), skipped: count('skipped') }, rows: out };
}
