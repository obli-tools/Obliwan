import crypto from 'crypto';
import {
  INFRA_ANALYSIS_MAX_APPLY_ROWS,
  INFRA_ANALYSIS_MAX_DEVICES,
  INFRA_ANALYSIS_TTL_MS,
  managementTunnelLogin,
  probesOf,
  toDelimited,
  variablesToCsv,
  type DiscoverProbe,
  type InfraAnalysisApplyRequest,
  type InfraAnalysisApplyResult,
  type InfraAnalysisCandidate,
  type InfraAnalysisCandidates,
  type InfraAnalysisCounts,
  type InfraAnalysisExport,
  type InfraAnalysisPreviewRequest,
  type InfraAnalysisRevisionOption,
  type InfraAnalysisSnapshot,
  type InfraApplyRefusal,
  type InfraDeviceReason,
  type InfraDeviceResult,
  type InfraFound,
  type InfraStoredView,
  type InfraUnreadableReason,
  type InfraVariableResult,
  type JsonValue,
  type SetupVariableRow,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { appendAudit } from '../attestation/auditLog.service';
import { decrypt } from '../secretVault.service';
import { auditedCommand } from '../audit.service';
import {
  SSH_ACCOUNT_READS,
  SSH_READS,
  judgeAccountPolicy,
  parseAccountGroup,
  parseBoard,
  parseIdentity,
  parseL2tpClients,
} from '../change/managementAccess.service';
import { compareIdentity } from '../fleet/deviceBinding.service';
import { isConcentratorDegraded } from '../fleet/reachability.service';
import { resolveRevisionForDevice } from '../template/assignment.service';
import {
  judgeValueAgainstSchema,
  siteDeclarationsQuery,
  variableResolver,
  type VarSchema,
} from '../template/variableResolver.service';
import { DriverError, redact } from '../drivers/types';
import { withSsh, type SshTransport } from '../transport/ssh.transport';
import {
  LAN_READS,
  evaluateProbe,
  menuReadCommand,
  parseMenuRead,
  parseSensitiveRead,
  readsFor,
  sensitiveReadCommand,
  typedValue,
  judgeLan,
  type MenuReading,
  type ProbeOutcome,
} from './probes';

/**
 * infraAnalysis.service.ts — "what do the routers in service actually run?",
 * per site, in the terms of a template's site-level variables.
 *
 * The routers of a customer were configured by hand or by a generator long
 * before ObliWAN, and the file a generator wrote is not what a router runs.
 * For the attached MikroTik devices of the session's workspace, this reads —
 * READ-ONLY, over each device's existing SSH transport, or an operator's
 * credential typed for this run and never stored — the value of every
 * site-level variable whose declaration carries an `x-obliwan-discover`
 * probe (grammar: @obliwan/shared infraAnalysis.ts), plus the built-in LAN
 * probe, and proposes the values per site. Nothing the server knows about a
 * customer is in this file: what to read is the template's.
 *
 * ┌─ WHO: A PLATFORM ADMINISTRATOR ──────────────────────────────────────────┐
 * │ Like Quick Setup Tenant: the routes are `requireRole('admin')`, and every│
 * │ entry point refuses any other actor again (`assertPlatformAdmin`) so a   │
 * │ re-mount behind a capability fails closed. It dials customer routers     │
 * │ with fleet credentials, may read their secrets, and writes site values  │
 * │ that outrank the tenant's policy.                                        │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE READ, PER DEVICE ───────────────────────────────────────────────────┐
 * │ Only an ACTIVE MikroTik with a site and an SSH transport (a pending      │
 * │ device's identity is not confirmed: its answers would be filed as this  │
 * │ site's). Presence first: a device behind a degraded concentrator, or     │
 * │ whose PPP session is down, is not dialled. Then ONE SSH session:         │
 * │   1. the identity reads (`SSH_READS`) and `compareIdentity` against the │
 * │      device's record — a box that is not this device, or proves          │
 * │      nothing, is read no further. It is NOT quarantined here: the       │
 * │      analysis writes nothing, and the write paths assert identity again │
 * │      and quarantine on their own proof;                                 │
 * │   2. one `menuReadCommand` per menu the probes and the LAN probe need — │
 * │      never a sensitive property;                                        │
 * │   3. ONLY when the operator asked for secrets and a probe selected one  │
 * │      item: the account's group policy (`SSH_ACCOUNT_READS`), and only   │
 * │      when it GRANTS `sensitive` (anything else — missing, unreadable —   │
 * │      reads nothing: fail closed), one `sensitiveReadCommand` per secret.│
 * │ Every command goes through `auditedCommand`: recorded in `command_audit` │
 * │ BEFORE it is sent, read-only, naming the administrator and the analysis │
 * │ (correlation id), the credential scrubbed. The audit holds the command, │
 * │ never the output, and no command carries a value — so a secret read is │
 * │ in no audit row. Each device has a budget (`DEVICE_BUDGET_MS`), a few    │
 * │ devices are read at a time (`ANALYSIS_CONCURRENCY`).                     │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ SECRETS ────────────────────────────────────────────────────────────────┐
 * │ A secret read stays in this process, in the analysis's map, until the    │
 * │ analysis expires (`INFRA_ANALYSIS_TTL_MS` after its run) or is          │
 * │ forgotten; it is never in a response, a log line, an audit entry or an  │
 * │ export (the variables CSV leaves a secret's cell empty). A response says │
 * │ `secret_found`. Applied, it goes through the variable store's own secret │
 * │ path (`variableResolver.setBulk` -> `encrypt`, which stamps the key     │
 * │ version) and nowhere else. The operator's typed credential lives in the │
 * │ run's closure and is dropped with it.                                    │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ IN MEMORY, ONE PROCESS ─────────────────────────────────────────────────┐
 * │ An analysis is a short-lived working set (secrets included), not a      │
 * │ record: it lives in the map below, bound to the workspace AND the        │
 * │ administrator who ran it, and is gone after the TTL or a restart. With  │
 * │ several web processes the poll must reach the one that runs it — the   │
 * │ deployment runs one.                                                     │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

// ============================================================================
// Tuning
// ============================================================================

export const ANALYSIS_CONCURRENCY = 6;
/** One device's whole read: handshake, identity, menus and secrets. */
export const DEVICE_BUDGET_MS = 60_000;
const SSH_STEP_TIMEOUT_MS = 15_000;
const SSH_MAX_OUTPUT = 256 * 1024;
/** Analyses held at once, every workspace together. */
const MAX_HELD = 20;
const AUDIT_PURPOSE = 'infra_analysis';

// ============================================================================
// Errors and actors
// ============================================================================

export class InfraAnalysisError extends Error {
  constructor(readonly reason: string, message: string, readonly httpStatus = 409) {
    super(message);
    this.name = 'InfraAnalysisError';
  }
}

export interface InfraActor {
  userId: number;
  username: string | null;
  /** `users.role = 'admin'`, as requireAuth revalidated it. */
  platformAdmin: boolean;
}

function assertPlatformAdmin(actor: Pick<InfraActor, 'platformAdmin'>): void {
  if (actor.platformAdmin !== true) {
    throw new InfraAnalysisError(
      'PLATFORM_ADMIN_ONLY',
      'The infrastructure analysis is reserved to platform administrators: it dials customer routers with fleet credentials and writes site values.',
      403,
    );
  }
}

// ============================================================================
// The store
// ============================================================================

interface Held {
  snapshot: InfraAnalysisSnapshot;
  tenantId: number;
  userId: number;
  /** `${deviceId}\u0000${key}` -> plaintext. Never leaves this process. */
  secrets: Map<string, string>;
  /** revision id -> its var_schema, as read when the run used it. */
  schemas: Map<string, VarSchema>;
  timer: NodeJS.Timeout | null;
  done: Promise<void>;
}

const held = new Map<string, Held>();

function secretKey(deviceId: number, key: string): string {
  return `${deviceId}\u0000${key}`;
}

function forgetHeld(id: string): void {
  const h = held.get(id);
  if (!h) return;
  h.secrets.clear();
  if (h.timer) clearTimeout(h.timer);
  held.delete(id);
}

function purgeExpired(): void {
  const now = Date.now();
  for (const [id, h] of held) {
    if (h.snapshot.status === 'done' && Date.parse(h.snapshot.expiresAt) <= now) forgetHeld(id);
  }
}

/** The caller's analysis, or a 404 — another workspace's, another
 *  administrator's, an expired one and an unknown id all read the same. */
function heldFor(tenantId: number, actor: InfraActor, id: string): Held {
  purgeExpired();
  const h = held.get(id);
  if (!h || h.tenantId !== tenantId || h.userId !== actor.userId) {
    throw new InfraAnalysisError('NOT_FOUND', 'No such analysis: it may have expired (they are kept 15 minutes).', 404);
  }
  return h;
}

function copy<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

/** For the harness: drop every analysis (and its secrets). */
export function resetInfraAnalyses(): void {
  for (const id of [...held.keys()]) forgetHeld(id);
}

/** For the harness: how many secrets the analysis holds, never their values. */
export function heldSecretCount(id: string): number {
  return held.get(id)?.secrets.size ?? 0;
}

// ============================================================================
// Devices and revisions
// ============================================================================

export interface DeviceRow {
  id: number;
  uuid: string | null;
  name: string;
  brand: string;
  role: string | null;
  status: string;
  site_id: number | null;
  site_code: string | null;
  site_name: string | null;
  concentrator_id: number | null;
  ppp_username: string | null;
  system_identity: string | null;
  serial: string | null;
  tunnel_ip: string | null;
}

export interface SshRow {
  device_id: number;
  host: string | null;
  port: number | null;
  username: string | null;
  secret_enc: string | null;
  enabled: boolean;
  params: Record<string, unknown> | null;
}

export function devicesQuery(tenantId: number) {
  return db('devices as d')
    .leftJoin('sites as s', function sameTenantSite(this: import('knex').Knex.JoinClause) {
      this.on('s.id', '=', 'd.site_id').andOn('s.tenant_id', '=', 'd.tenant_id');
    })
    .where('d.tenant_id', tenantId)
    .select(
      'd.id as id', 'd.uuid as uuid', 'd.name as name', 'd.brand as brand', 'd.role as role', 'd.status as status',
      's.id as site_id', 's.code as site_code', 's.name as site_name', 'd.concentrator_id as concentrator_id',
      'd.ppp_username as ppp_username', 'd.system_identity as system_identity', 'd.serial as serial',
      'd.tunnel_ip as tunnel_ip',
    );
}

export async function sshRows(deviceIds: readonly number[]): Promise<Map<number, SshRow>> {
  const out = new Map<number, SshRow>();
  for (let i = 0; i < deviceIds.length; i += 1000) {
    const rows = (await db('device_transports')
      .whereIn('device_id', deviceIds.slice(i, i + 1000))
      .andWhere('transport', 'ssh')
      .select('device_id', 'host', 'port', 'username', 'secret_enc', 'enabled', 'params')) as SshRow[];
    for (const r of rows) out.set(Number(r.device_id), r);
  }
  return out;
}

export function sshHost(device: DeviceRow, ssh: SshRow | undefined): string | null {
  return ((ssh?.host ?? device.tunnel_ip ?? '') as string).trim() || null;
}

/** The skip reasons knowable without dialling, in the order they are judged. */
export function staticSkip(device: DeviceRow, ssh: SshRow | undefined, operatorCredential: boolean): InfraDeviceReason | null {
  if (device.brand !== 'mikrotik') return 'not_mikrotik';
  if (device.role === 'concentrator') return 'concentrator';
  if (device.status !== 'active') return 'not_active';
  if (device.site_id === null) return 'no_site';
  if (!ssh || !ssh.enabled || !sshHost(device, ssh)) return 'no_ssh';
  if (!operatorCredential && (!ssh.username || !ssh.secret_enc)) return 'no_credential';
  return null;
}

interface RevisionRow {
  id: string;
  revision: number;
  status: string;
  templateName: string;
  varSchema: VarSchema;
}

async function loadRevision(tenantId: number, revisionId: string | number): Promise<RevisionRow | null> {
  if (!/^\d{1,18}$/.test(String(revisionId))) return null;
  const row = (await db('template_revisions as r')
    .join('templates as t', 't.id', 'r.template_id')
    .where('r.id', String(revisionId))
    .andWhere(function ownOrLibrary(this: import('knex').Knex.QueryBuilder) {
      this.where('r.tenant_id', tenantId).orWhereNull('r.tenant_id');
    })
    .first('r.id as id', 'r.revision as revision', 'r.status as status', 'r.var_schema as var_schema', 't.name as template_name')) as
    | { id: string | number; revision: number; status: string; var_schema: unknown; template_name: string }
    | undefined;
  if (!row) return null;
  const schema = typeof row.var_schema === 'string' ? (JSON.parse(row.var_schema) as unknown) : row.var_schema;
  return {
    id: String(row.id),
    revision: Number(row.revision),
    status: row.status,
    templateName: row.template_name,
    varSchema: (schema && typeof schema === 'object' ? schema : {}) as VarSchema,
  };
}

/** Site codes compared as numbers when both are all digits ("2889" sits
 *  between "02000" and "03000"), else as text. */
function compareCodes(a: string, b: string): number {
  if (/^\d+$/.test(a) && /^\d+$/.test(b)) return Number(a) - Number(b);
  return a < b ? -1 : a > b ? 1 : 0;
}

// ============================================================================
// Candidates — what the page offers
// ============================================================================

export async function listCandidates(tenantId: number, actor: InfraActor): Promise<InfraAnalysisCandidates> {
  assertPlatformAdmin(actor);
  const devices = ((await devicesQuery(tenantId)
    .andWhere('d.brand', 'mikrotik')
    .orderBy('d.name')) as DeviceRow[]).filter((d) => d.role !== 'concentrator');
  const ssh = await sshRows(devices.map((d) => d.id));
  const rows: InfraAnalysisCandidate[] = devices.map((d) => ({
    deviceId: d.id,
    deviceName: d.name,
    site: d.site_id === null ? null : { id: Number(d.site_id), code: d.site_code as string, name: d.site_name as string },
    status: d.status,
    hasSsh: !!ssh.get(d.id)?.enabled,
    skip: staticSkip(d, ssh.get(d.id), false),
  }));
  rows.sort((a, b) => compareCodes(a.site?.code ?? '￿', b.site?.code ?? '￿') || a.deviceName.localeCompare(b.deviceName));

  const revs = (await db('template_revisions as r')
    .join('templates as t', 't.id', 'r.template_id')
    .where('t.status', 'active')
    .whereIn('r.status', ['draft', 'published'])
    .andWhere(function ownOrLibrary(this: import('knex').Knex.QueryBuilder) {
      this.where('r.tenant_id', tenantId).orWhereNull('r.tenant_id');
    })
    // A cheap pre-filter on the text; `probesOf` decides.
    .whereRaw("r.var_schema::text like '%x-obliwan-discover%'")
    .orderBy('r.id', 'desc')
    .limit(100)
    .select('r.id as id', 'r.revision as revision', 'r.status as status', 'r.tenant_id as tenant_id',
      'r.var_schema as var_schema', 't.name as template_name')) as Array<{
    id: string | number; revision: number; status: string; tenant_id: number | null; var_schema: unknown; template_name: string;
  }>;
  const revisions: InfraAnalysisRevisionOption[] = [];
  for (const r of revs) {
    const keys = probesOf(r.var_schema).map((p) => p.key);
    if (keys.length === 0) continue;
    revisions.push({
      id: String(r.id), templateName: r.template_name, revision: Number(r.revision), status: r.status,
      library: r.tenant_id === null, probeKeys: keys,
    });
  }
  return { devices: rows, revisions };
}

// ============================================================================
// Start
// ============================================================================

async function selectDevices(tenantId: number, input: InfraAnalysisPreviewRequest): Promise<DeviceRow[]> {
  const sel = input.selection as Record<string, unknown>;
  if (Array.isArray(sel.deviceIds)) {
    const ids = [...new Set((sel.deviceIds as number[]).map(Number))];
    const found = (await devicesQuery(tenantId).whereIn('d.id', ids)) as DeviceRow[];
    if (found.length !== ids.length) {
      // Another workspace's device and an unknown id read the same.
      throw new InfraAnalysisError('DEVICE_NOT_FOUND', 'One of the devices named does not exist in this workspace.', 404);
    }
    const byId = new Map(found.map((d) => [d.id, d]));
    return ids.map((id) => byId.get(id)!);
  }
  const all = ((await devicesQuery(tenantId).andWhere('d.brand', 'mikrotik').orderBy('d.id')) as DeviceRow[])
    .filter((d) => d.role !== 'concentrator');
  if (sel.all === true) return all;
  const from = typeof sel.siteCodeFrom === 'string' && sel.siteCodeFrom.trim() !== '' ? sel.siteCodeFrom.trim() : null;
  const to = typeof sel.siteCodeTo === 'string' && sel.siteCodeTo.trim() !== '' ? sel.siteCodeTo.trim() : null;
  return all.filter((d) => {
    if (d.site_code === null) return false;
    if (from !== null && compareCodes(d.site_code, from) < 0) return false;
    if (to !== null && compareCodes(d.site_code, to) > 0) return false;
    return true;
  });
}

function emptyCounts(total: number): InfraAnalysisCounts {
  return { devices: total, done: 0, skipped: 0, failed: 0, proposals: 0, secretsHeld: 0, lanFound: 0, elsewhere: 0 };
}

/**
 * Start an analysis: the devices are selected and judged now, the reads run
 * in the background. Returns the first snapshot (every device `pending`),
 * and `done`, which settles when the run has ended — the controller answers
 * at once, the page polls `getAnalysis`.
 */
export async function startAnalysis(
  tenantId: number,
  input: InfraAnalysisPreviewRequest,
  actor: InfraActor,
): Promise<{ snapshot: InfraAnalysisSnapshot; done: Promise<void> }> {
  assertPlatformAdmin(actor);
  purgeExpired();
  for (const h of held.values()) {
    if (h.tenantId === tenantId && h.snapshot.status === 'running') {
      throw new InfraAnalysisError('ANALYSIS_RUNNING', 'An analysis of this workspace is already running: wait for it to end.', 409);
    }
  }
  if (held.size >= MAX_HELD) {
    throw new InfraAnalysisError('TOO_MANY_ANALYSES', 'Too many analyses are held: forget one, or wait 15 minutes.', 429);
  }

  let fixed: RevisionRow | null = null;
  if (input.revisionId !== undefined) {
    fixed = await loadRevision(tenantId, input.revisionId);
    if (!fixed) throw new InfraAnalysisError('REVISION_NOT_FOUND', 'No such template revision in this workspace.', 404);
  }
  const devices = await selectDevices(tenantId, input);
  if (devices.length === 0) {
    throw new InfraAnalysisError('NO_DEVICES', 'The selection holds no MikroTik device of this workspace.', 400);
  }
  if (devices.length > INFRA_ANALYSIS_MAX_DEVICES) {
    throw new InfraAnalysisError('TOO_MANY_DEVICES', `At most ${INFRA_ANALYSIS_MAX_DEVICES} devices per analysis.`, 400);
  }

  const id = crypto.randomUUID();
  const startedAt = new Date();
  const snapshot: InfraAnalysisSnapshot = {
    analysisId: id,
    tenantId,
    status: 'running',
    readSecrets: input.readSecrets === true,
    credentialSource: input.credential ? 'operator' : 'device',
    revisionId: fixed ? fixed.id : null,
    lanInterface: input.lanInterface?.trim() || null,
    startedAt: startedAt.toISOString(),
    finishedAt: null,
    expiresAt: new Date(startedAt.getTime() + INFRA_ANALYSIS_TTL_MS).toISOString(),
    progress: { total: devices.length, done: 0 },
    counts: emptyCounts(devices.length),
    devices: devices.map((d) => ({
      deviceId: d.id,
      deviceName: d.name,
      site: d.site_id === null ? null : { id: Number(d.site_id), code: d.site_code as string, name: d.site_name as string },
      state: 'pending',
      reason: null,
      detail: null,
      revision: null,
      noRevision: false,
      credentialSource: null,
      sensitivePolicy: null,
      variables: [],
      lan: null,
    })),
  };
  const h: Held = {
    snapshot, tenantId, userId: actor.userId, secrets: new Map(), schemas: new Map(), timer: null,
    done: Promise.resolve(),
  };
  if (fixed) h.schemas.set(fixed.id, fixed.varSchema);
  held.set(id, h);

  // The credential is captured by the run's closure only, and dropped with it.
  const credential = input.credential ? { username: input.credential.username, password: input.credential.password } : null;
  h.done = run(h, devices, fixed, credential, actor).catch(async (err: unknown) => {
    logger.error({ tenantId, analysisId: id, err: err instanceof Error ? { name: err.name } : null }, 'Infra analysis: the run stopped');
    await finish(h, actor);
  });
  logger.info(
    { tenantId, analysisId: id, devices: devices.length, readSecrets: snapshot.readSecrets, credential: snapshot.credentialSource, by: actor.userId },
    'Infra analysis started',
  );
  return { snapshot: copy(snapshot), done: h.done };
}

export function getAnalysis(tenantId: number, actor: InfraActor, id: string): InfraAnalysisSnapshot {
  assertPlatformAdmin(actor);
  return copy(heldFor(tenantId, actor, id).snapshot);
}

export function forgetAnalysis(tenantId: number, actor: InfraActor, id: string): void {
  assertPlatformAdmin(actor);
  const h = heldFor(tenantId, actor, id);
  // A running analysis keeps filling its map: forgotten now, the secrets it
  // reads next would sit in a map nobody can reach or clear.
  if (h.snapshot.status === 'running') {
    throw new InfraAnalysisError('ANALYSIS_RUNNING', 'The analysis is still running: forget it once it has ended.', 409);
  }
  forgetHeld(id);
}

// ============================================================================
// The run
// ============================================================================

export async function mapLimit<T>(items: readonly T[], limit: number, fn: (item: T, index: number) => Promise<void>): Promise<void> {
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      await fn(items[i], i);
    }
  });
  await Promise.all(workers);
}

async function run(
  h: Held,
  devices: DeviceRow[],
  fixed: RevisionRow | null,
  credential: { username: string; password: string } | null,
  actor: InfraActor,
): Promise<void> {
  const ssh = await sshRows(devices.map((d) => d.id));
  await mapLimit(devices, ANALYSIS_CONCURRENCY, async (device, index) => {
    const result = h.snapshot.devices[index];
    try {
      await analyseDevice(h, device, ssh.get(device.id), fixed, credential, actor, result);
    } catch (err) {
      result.state = 'failed';
      result.reason = 'internal';
      result.detail = null;
      logger.error(
        { tenantId: h.tenantId, analysisId: h.snapshot.analysisId, deviceId: device.id, err: err instanceof Error ? { name: err.name } : null },
        'Infra analysis: a device could not be analysed',
      );
    }
    h.snapshot.progress.done += 1;
  });
  markConflicts(h);
  await finish(h, actor);
}

async function finish(h: Held, actor: InfraActor): Promise<void> {
  if (h.snapshot.status === 'done') return;
  const s = h.snapshot;
  for (const d of s.devices) {
    if (d.state === 'pending') {
      d.state = 'failed';
      d.reason = 'internal';
    }
  }
  s.counts = countsOf(s, h.secrets.size);
  s.status = 'done';
  const finishedAt = new Date();
  s.finishedAt = finishedAt.toISOString();
  s.expiresAt = new Date(finishedAt.getTime() + INFRA_ANALYSIS_TTL_MS).toISOString();
  h.timer = setTimeout(() => forgetHeld(s.analysisId), INFRA_ANALYSIS_TTL_MS);
  h.timer.unref?.();
  // Counts only, no value. The field names avoid the audit's secret-name
  // mask (`isSecretName`: "secret", "credential", "key"...), which would
  // otherwise blank these harmless flags.
  try {
    await appendAudit({
      tenantId: h.tenantId,
      actorType: 'user',
      actorId: actor.userId,
      actorName: actor.username,
      action: 'infra_analysis.run',
      entityType: 'tenant',
      entityId: h.tenantId,
      correlationId: s.analysisId,
      after: {
        sensitiveReads: s.readSecrets,
        dialledWith: s.credentialSource,
        revisionId: s.revisionId,
        devices: s.counts.devices,
        done: s.counts.done,
        skipped: s.counts.skipped,
        failed: s.counts.failed,
        proposals: s.counts.proposals,
        sensitiveValuesHeld: s.counts.secretsHeld,
        lanFound: s.counts.lanFound,
        elsewhere: s.counts.elsewhere,
      },
    });
  } catch (err) {
    logger.error({ tenantId: h.tenantId, err: err instanceof Error ? { name: err.name } : null }, 'Infra analysis: the audit entry could not be written');
  }
  logger.info({ tenantId: h.tenantId, analysisId: s.analysisId, counts: s.counts }, 'Infra analysis finished');
}

function countsOf(s: InfraAnalysisSnapshot, secretsHeld: number): InfraAnalysisCounts {
  const c = emptyCounts(s.devices.length);
  for (const d of s.devices) {
    if (d.state === 'done') c.done += 1;
    else if (d.state === 'skipped') c.skipped += 1;
    else if (d.state === 'failed') c.failed += 1;
    if (d.lan?.status === 'found') c.lanFound += 1;
    for (const v of d.variables) if (v.action !== null) c.proposals += 1;
    if (d.variables.some((v) => v.elsewhere.length > 0)) c.elsewhere += 1;
  }
  c.secretsHeld = secretsHeld;
  return c;
}

export function failureReason(err: unknown): InfraDeviceReason {
  if (err instanceof DriverError) {
    if (err.code === 'AUTH_FAILED') return 'auth_failed';
    if (err.code === 'UNREACHABLE') return 'unreachable';
    if (err.code === 'TIMEOUT') return 'timeout';
  }
  return 'ssh_failed';
}

export async function pppSessionOpen(device: DeviceRow): Promise<boolean> {
  // The predicate the health check uses for presence (never dial a router whose PPP session is down).
  const open = await db('ppp_sessions')
    .where({ concentrator_id: device.concentrator_id, ppp_username: device.ppp_username })
    .whereNull('ended_at')
    .first('id');
  return !!open;
}

/**
 * The identity rule on an open SSH session: the identity, the board serial and the
 * management tunnel's login, read through `read` (the caller's audited
 * reader), compared with the device's record. Shared with the learning
 * capture, which proves identity on the same session it exports on.
 */
export async function proveSessionIdentity(
  read: (command: string) => Promise<string>,
  device: Pick<DeviceRow, 'ppp_username' | 'system_identity' | 'serial'>,
): Promise<{ ok: true } | { ok: false; reason: 'identity_mismatch' | 'identity_unproven'; detail: string }> {
  const identity = parseIdentity(await read(SSH_READS.identity));
  const board = parseBoard(await read(SSH_READS.board));
  const l2tp = managementTunnelLogin(parseL2tpClients(await read(SSH_READS.l2tp)), device.ppp_username).login;
  const cmp = compareIdentity(
    { ppp_username: device.ppp_username, system_identity: device.system_identity, serial: device.serial },
    { systemIdentity: identity, serial: board.serial, pppUsername: l2tp },
  );
  if (cmp.ok) return { ok: true };
  return {
    ok: false,
    reason: cmp.mismatched > 0 ? 'identity_mismatch' : 'identity_unproven',
    detail: cmp.reason.slice(0, 300),
  };
}

export interface ProbeDecl {
  key: string;
  probe: DiscoverProbe;
  property: Record<string, unknown>;
}

/** What the session read, per probe, before any comparison. */
export type SessionFinding =
  | { kind: 'outcome'; outcome: ProbeOutcome }
  | { kind: 'secret'; ok: true; elsewhere: ProbeOutcome['elsewhere'] }
  | { kind: 'secret'; ok: false; status: 'not_read' | 'unreadable'; reason?: InfraUnreadableReason; elsewhere: ProbeOutcome['elsewhere'] };

async function analyseDevice(
  h: Held,
  device: DeviceRow,
  ssh: SshRow | undefined,
  fixed: RevisionRow | null,
  credential: { username: string; password: string } | null,
  actor: InfraActor,
  result: InfraDeviceResult,
): Promise<void> {
  const tenantId = h.tenantId;
  const skip = (reason: InfraDeviceReason): void => {
    result.state = 'skipped';
    result.reason = reason;
  };
  const staticReason = staticSkip(device, ssh, credential !== null);
  if (staticReason) return skip(staticReason);
  // Behind a concentrator, presence decides whether we may dial at all.
  if (device.concentrator_id !== null && device.ppp_username) {
    if (await isConcentratorDegraded(device.concentrator_id)) return skip('concentrator_degraded');
    if (!(await pppSessionOpen(device))) return skip('ppp_down');
  }

  // The revision whose probes to run.
  let revision: RevisionRow | null = fixed;
  if (!revision) {
    const { candidate } = await resolveRevisionForDevice(tenantId, device.id);
    if (candidate?.revisionId) {
      revision = await loadRevision(tenantId, candidate.revisionId);
      // Apply judges a value against the schema the run read it with.
      if (revision && !h.schemas.has(revision.id)) h.schemas.set(revision.id, revision.varSchema);
    }
  }
  result.revision = revision
    ? { id: revision.id, templateName: revision.templateName, revision: revision.revision, status: revision.status }
    : null;
  result.noRevision = revision === null;
  const probes: ProbeDecl[] = revision ? probesOf(revision.varSchema) : [];

  // The credential: the operator's for this run, else the device's own.
  let login: { username: string; password: string; source: 'operator' | 'device' };
  if (credential) {
    login = { username: credential.username, password: credential.password, source: 'operator' };
  } else {
    try {
      login = { username: ssh!.username as string, password: decrypt(ssh!.secret_enc as string), source: 'device' };
    } catch {
      // A vault error names the key version, never the secret; it is not
      // repeated here either: the device is simply not readable this way.
      result.detail = 'the SSH password stored for this device cannot be decrypted';
      return skip('no_credential');
    }
  }
  result.credentialSource = login.source;
  const params = (ssh!.params ?? {}) as { legacyAlgorithms?: boolean };
  const host = sshHost(device, ssh) as string;
  const port = ssh!.port ?? 22;

  // Menu reads: the probes' needs and the LAN probe's, one read per menu.
  const menuProps = new Map<string, Set<string>>();
  const need = (menu: string, props: readonly string[]): void => {
    const set = menuProps.get(menu) ?? new Set<string>();
    for (const p of props) set.add(p);
    menuProps.set(menu, set);
  };
  // A probe's own menu, its `unless` selections' and its `else` chain's.
  for (const p of probes) for (const r of readsFor(p.probe)) need(r.menu, r.properties);
  for (const r of LAN_READS) need(r.menu, r.properties);

  const deadline = Date.now() + DEVICE_BUDGET_MS;
  const scrub: string[] = [login.password];
  const findings = new Map<string, SessionFinding>();
  const readings = new Map<string, MenuReading>();
  const secrets = new Map<string, string>();

  try {
    await withSsh(
      { host, port, username: login.username, password: login.password, timeoutMs: SSH_STEP_TIMEOUT_MS, legacyAlgorithms: params.legacyAlgorithms === true },
      async (session: SshTransport) => {
        // Every command is audited BEFORE it is sent (`auditedCommand`: no
        // trace, no bytes), naming the administrator; `scrub` holds the
        // credential and, once read, every secret, so neither reaches the
        // audited line or an error that leaves this session.
        const read = async (command: string): Promise<string> => {
          const left = deadline - Date.now();
          if (left <= 0) throw new DriverError(`device budget of ${DEVICE_BUDGET_MS} ms spent`, 'TIMEOUT', { transport: 'ssh' });
          const res = await auditedCommand(
            {
              tenantId,
              deviceId: device.id,
              deviceUuid: device.uuid,
              deviceName: device.name,
              userId: actor.userId,
              username: actor.username,
              transport: 'ssh',
              command,
              args: { purpose: AUDIT_PURPOSE, siteId: device.site_id },
              isWrite: false,
              correlationId: h.snapshot.analysisId,
              secrets: scrub,
            },
            async () => {
              try {
                return await session.exec(command, { pty: false, timeoutMs: Math.min(SSH_STEP_TIMEOUT_MS, left), maxOutputBytes: SSH_MAX_OUTPUT });
              } catch (err) {
                if (err instanceof Error) err.message = redact(err.message, scrub);
                throw err;
              }
            },
          );
          return res.stdout;
        };

        // 1. Identity — is this box the device?
        const proof = await proveSessionIdentity(read, device);
        if (!proof.ok) {
          result.state = 'failed';
          result.reason = proof.reason;
          result.detail = proof.detail;
          return;
        }

        // 2. The menus — never a sensitive property.
        for (const [menu, props] of menuProps) {
          const list = [...props];
          readings.set(menu, parseMenuRead(menu, list, await read(menuReadCommand(menu, list))));
        }
        const outcomes = probes.map((p) => ({ decl: p, outcome: evaluateProbe(p.probe, readings) }));

        // 3. Secrets, only on request and only with the policy.
        const targets = outcomes.filter((o) => o.outcome.kind === 'secret_target');
        let policy: InfraDeviceResult['sensitivePolicy'] = 'not_needed';
        if (targets.length > 0 && h.snapshot.readSecrets) {
          const groupRead = SSH_ACCOUNT_READS.group(login.username);
          const group = groupRead ? parseAccountGroup(await read(groupRead)) : null;
          const policyRead = group ? SSH_ACCOUNT_READS.policy(group) : null;
          policy = policyRead ? judgeAccountPolicy(await read(policyRead), ['sensitive']).state : 'unknown';
        }
        result.sensitivePolicy = targets.length > 0 && h.snapshot.readSecrets ? policy : 'not_needed';

        for (const { decl, outcome } of outcomes) {
          if (outcome.kind !== 'secret_target') {
            findings.set(decl.key, { kind: 'outcome', outcome });
            continue;
          }
          if (!h.snapshot.readSecrets) {
            findings.set(decl.key, { kind: 'secret', ok: false, status: 'not_read', elsewhere: outcome.elsewhere });
            continue;
          }
          if (policy !== 'granted') {
            findings.set(decl.key, {
              kind: 'secret', ok: false, status: 'unreadable',
              reason: policy === 'missing' ? 'no_sensitive_policy' : 'policy_unknown', elsewhere: outcome.elsewhere,
            });
            continue;
          }
          const got = parseSensitiveRead(
            await read(sensitiveReadCommand(decl.probe.menu, outcome.itemId, decl.probe.property as string)),
          );
          if (!got.ok) {
            findings.set(decl.key, { kind: 'secret', ok: false, status: 'unreadable', reason: got.reason, elsewhere: outcome.elsewhere });
            continue;
          }
          // From here on, an error message of this session is scrubbed of it.
          scrub.push(got.value);
          secrets.set(decl.key, got.value);
          findings.set(decl.key, { kind: 'secret', ok: true, elsewhere: outcome.elsewhere });
        }
      },
    );
  } catch (err) {
    secrets.clear();
    result.state = 'failed';
    result.reason = failureReason(err);
    const message = err instanceof Error ? err.message : String(err);
    result.detail = redact(message, scrub).slice(0, 300);
    return;
  }
  if (result.state === 'failed') return;

  result.lan = judgeLan(
    {
      address: readings.get('/ip/address'),
      bridge: readings.get('/interface/bridge'),
      member: readings.get('/interface/list/member'),
    },
    h.snapshot.lanInterface,
  );

  // What the site resolves to today, to compare with what the router said.
  const report = revision ? await variableResolver.resolveForDevice(tenantId, device.id, revision.varSchema) : null;
  const plaintexts = secrets.size > 0
    ? new Map((await variableResolver.loadSecrets(tenantId, device.id)).map((s) => [s.key, s.plaintext]))
    : new Map<string, string>();

  for (const p of probes) {
    const finding = findings.get(p.key);
    if (!finding) continue;
    result.variables.push(
      judgeVariable(p, finding, report?.variables ?? {}, secrets.get(p.key) ?? null, plaintexts.get(p.key) ?? null, revision!.varSchema),
    );
  }
  // A stable order for the screen and the export: by key.
  result.variables.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  for (const [key, value] of secrets) h.secrets.set(secretKey(device.id, key), value);
  plaintexts.clear();
  scrub.length = 0;
  secrets.clear();
  result.state = 'done';
}

// ============================================================================
// Judging one variable
// ============================================================================

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  if (isPlainObject(v)) {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(',')}}`;
  }
  return JSON.stringify(v) ?? 'null';
}

type Resolved = Record<string, { value: JsonValue; source: string; isSecret: boolean; redacted: boolean }>;

function storedView(resolved: Resolved, key: string): InfraStoredView {
  const r = Object.prototype.hasOwnProperty.call(resolved, key) ? resolved[key] : undefined;
  if (!r) return { present: false, level: null, isSecret: false };
  if (r.isSecret || r.redacted) return { present: true, level: r.source, isSecret: true };
  return { present: true, value: r.value, level: r.source, isSecret: false };
}

/**
 * One probe's row: what was found, what the site resolves to, the verdict
 * and what an apply would do. `secret` is the plaintext this session read
 * (in memory), `storedPlain` the one the site resolves to — compared here,
 * never returned.
 *
 * A present-only probe is asymmetric: a match is an observation and is judged
 * like any value read (a `pppoe` read against the dhcp default, or against a
 * `static` stored by hand, is `differs` with a WRITE proposal — a proposal,
 * applied only when the operator ticks it); no match is `not_seen`, verdict
 * `none`, no action, whatever the site stores.
 */
export function judgeVariable(
  decl: ProbeDecl,
  finding: SessionFinding,
  resolved: Resolved,
  secret: string | null,
  storedPlain: string | null,
  varSchema: VarSchema,
): InfraVariableResult {
  const label = typeof decl.property['x-obliwan-label'] === 'string' ? (decl.property['x-obliwan-label'] as string) : null;
  const isSecretVar = decl.property['x-obliwan-secret'] === true;
  const stored = storedView(resolved, decl.key);
  const base = {
    key: decl.key, label, secret: isSecretVar, stored, invalidReasons: [] as string[],
  };

  if (finding.kind === 'secret') {
    if (!finding.ok) {
      const found: InfraFound = finding.status === 'not_read'
        ? { status: 'not_read' }
        : { status: 'unreadable', reason: finding.reason ?? 'property_error' };
      return { ...base, found, elsewhere: finding.elsewhere, verdict: 'none', action: null };
    }
    const judged = judgeValueAgainstSchema(varSchema, decl.key, secret, { secret: true });
    if (judged.uncheckable || judged.reasons.length > 0) {
      return {
        ...base, found: { status: 'secret_found' }, elsewhere: finding.elsewhere, verdict: 'invalid',
        invalidReasons: judged.uncheckable ? ['cannot be checked against its declaration'] : judged.reasons, action: null,
      };
    }
    const verdict = !stored.present ? 'new' : storedPlain !== null && storedPlain === secret ? 'same' : 'differs';
    return {
      ...base, found: { status: 'secret_found' }, elsewhere: finding.elsewhere, verdict,
      action: verdict === 'same' ? null : 'write',
    };
  }

  const o = finding.outcome;
  if (o.kind === 'not_found') return { ...base, found: { status: 'not_found' }, elsewhere: o.elsewhere, verdict: 'none', action: null };
  // A present-only probe that matched nothing has NO reading: it is compared
  // with nothing (never `same` against a default, never a write over a value
  // set by hand). A `presence` outcome reaching here without its `absent`
  // value means the same thing, and is judged the same way — never a guess.
  if (o.kind === 'not_seen' || (o.kind === 'presence' && !o.present && decl.probe.absent === undefined)) {
    return { ...base, found: { status: 'not_seen' }, elsewhere: o.elsewhere, verdict: 'none', action: null };
  }
  if (o.kind === 'ambiguous') {
    return { ...base, found: { status: 'ambiguous', count: o.count }, elsewhere: o.elsewhere, verdict: 'none', action: null };
  }
  if (o.kind === 'unreadable') {
    return { ...base, found: { status: 'unreadable', reason: o.reason }, elsewhere: o.elsewhere, verdict: 'none', action: null };
  }
  if (o.kind === 'secret_target') {
    // Never reached: secret targets are turned into `secret` findings.
    return { ...base, found: { status: 'not_read' }, elsewhere: o.elsewhere, verdict: 'none', action: null };
  }
  const value: JsonValue = o.kind === 'presence'
    ? ((o.present ? (o.value ?? decl.probe.present) : decl.probe.absent) as JsonValue)
    : typedValue(o.text, decl.property);

  // The site inherits it: no value of its own is wanted.
  const omitKey = decl.probe.omitWhenEquals;
  if (omitKey) {
    const other = storedView(resolved, omitKey);
    if (other.present && !other.isSecret && canonicalJson(other.value) === canonicalJson(value)) {
      const siteLevel = stored.level === 'site';
      return {
        ...base, found: { status: 'omitted', equalsKey: omitKey }, elsewhere: o.elsewhere,
        verdict: siteLevel ? 'differs' : 'same', action: siteLevel ? 'unset' : null,
      };
    }
  }

  const judged = judgeValueAgainstSchema(varSchema, decl.key, value);
  if (judged.uncheckable || judged.reasons.length > 0) {
    return {
      ...base, found: { status: 'found', value }, elsewhere: o.elsewhere, verdict: 'invalid',
      invalidReasons: judged.uncheckable ? ['cannot be checked against its declaration'] : judged.reasons, action: null,
    };
  }
  let verdict: InfraVariableResult['verdict'];
  if (!stored.present) verdict = 'new';
  else if (!stored.isSecret && canonicalJson(stored.value) === canonicalJson(value)) verdict = 'same';
  else verdict = 'differs';
  return {
    ...base, found: { status: 'found', value }, elsewhere: o.elsewhere, verdict,
    action: verdict === 'same' ? null : 'write',
  };
}

/** What a device found for a key, as a comparable token (null: nothing). A
 *  secret is compared by a digest computed here and never kept. */
function foundToken(h: { secrets: Map<string, string> }, deviceId: number, v: InfraVariableResult): string | null {
  if (v.found.status === 'found') return `v:${canonicalJson(v.found.value)}`;
  if (v.found.status === 'omitted') return 'omitted';
  if (v.found.status === 'secret_found') {
    const plain = h.secrets.get(secretKey(deviceId, v.key));
    return plain === undefined ? null : `s:${crypto.createHash('sha256').update(plain).digest('hex')}`;
  }
  return null;
}

/**
 * Two routers of one site that disagree on a key: neither is proposed. Run
 * once the whole analysis is in (every secret read is in `h.secrets` by then).
 */
function markConflicts(h: Held): void {
  const s = h.snapshot;
  const bySite = new Map<number, InfraDeviceResult[]>();
  for (const d of s.devices) {
    if (d.state !== 'done' || !d.site) continue;
    const list = bySite.get(d.site.id) ?? [];
    list.push(d);
    bySite.set(d.site.id, list);
  }
  for (const devices of bySite.values()) {
    if (devices.length < 2) continue;
    const keys = new Set(devices.flatMap((d) => d.variables.map((v) => v.key)));
    for (const key of keys) {
      const rows = devices.flatMap((d) => d.variables.filter((v) => v.key === key).map((v) => ({ d, v })));
      const tokens = new Set(rows.map(({ d, v }) => foundToken(h, d.deviceId, v)).filter((t) => t !== null));
      if (tokens.size > 1) {
        for (const { v } of rows) {
          v.verdict = 'conflict';
          v.action = null;
        }
      }
    }
  }
}

// ============================================================================
// Apply
// ============================================================================

function deviceRowsForSite(h: Held, siteId: number): InfraDeviceResult[] {
  return h.snapshot.devices.filter((d) => d.state === 'done' && d.site?.id === siteId);
}

/**
 * Write the selected rows as SITE values. Per site, ALL OR NOTHING
 * (`variableResolver.setBulk`, one transaction), secrets through the vault.
 * Every value is judged again, against the revision that proposed it AND every
 * published declaration of the key in the workspace — a site value outranks
 * the tenant's for every template that reads the key. Audited per site,
 * keys only.
 */
export async function applyAnalysis(
  tenantId: number,
  input: InfraAnalysisApplyRequest,
  actor: InfraActor,
): Promise<InfraAnalysisApplyResult> {
  assertPlatformAdmin(actor);
  const h = heldFor(tenantId, actor, input.analysisId);
  if (h.snapshot.status !== 'done') {
    throw new InfraAnalysisError('ANALYSIS_RUNNING', 'The analysis is still running: apply once it has ended.', 409);
  }
  if (input.rows.length === 0 || input.rows.length > INFRA_ANALYSIS_MAX_APPLY_ROWS) {
    throw new InfraAnalysisError('ROWS', `Between 1 and ${INFRA_ANALYSIS_MAX_APPLY_ROWS} rows per apply.`, 400);
  }

  const refused: InfraAnalysisApplyResult['refused'] = [];
  const refuse = (siteId: number, key: string, reason: InfraApplyRefusal, detail: string | null = null): void => {
    refused.push({ siteId, key, reason, detail });
  };

  // Published declarations of the workspace, by key.
  const published = (await siteDeclarationsQuery(db, tenantId)) as Array<{ var_schema: unknown }>;
  const publishedSchemas = published
    .map((r) => (typeof r.var_schema === 'string' ? (JSON.parse(r.var_schema) as unknown) : r.var_schema))
    .filter(isPlainObject) as VarSchema[];
  const declares = (schema: VarSchema, key: string): Record<string, unknown> | null => {
    const props = schema.properties;
    if (!props || !Object.prototype.hasOwnProperty.call(props, key)) return null;
    return isPlainObject(props[key]) ? (props[key] as Record<string, unknown>) : null;
  };

  type Plan = { code: string; writes: Array<{ key: string; value: JsonValue; isSecret: boolean; devices: InfraDeviceResult[] }>; unset: Array<{ key: string; devices: InfraDeviceResult[] }> };
  const plans = new Map<number, Plan>();
  const seen = new Set<string>();

  for (const row of input.rows) {
    const tag = `${row.siteId}\u0000${row.key}`;
    if (seen.has(tag)) continue;
    seen.add(tag);
    const devices = deviceRowsForSite(h, row.siteId).filter((d) => d.variables.some((v) => v.key === row.key));
    if (devices.length === 0) {
      refuse(row.siteId, row.key, 'unknown_row');
      continue;
    }
    const rows = devices.map((d) => ({ d, v: d.variables.find((v) => v.key === row.key)! }));
    if (rows.some(({ v }) => v.verdict === 'conflict')) {
      refuse(row.siteId, row.key, 'conflict');
      continue;
    }
    const invalid = rows.find(({ v }) => v.verdict === 'invalid');
    if (invalid) {
      // The reasons of a secret are ajv's keywords only (judgeVariable).
      refuse(row.siteId, row.key, 'invalid', invalid.v.invalidReasons.join(' / ').slice(0, 300) || null);
      continue;
    }
    const chosen = rows.find(({ v }) => v.action !== null);
    if (!chosen) {
      refuse(row.siteId, row.key, 'not_applicable');
      continue;
    }
    const plan = plans.get(row.siteId) ?? { code: chosen.d.site!.code, writes: [], unset: [] };
    plans.set(row.siteId, plan);
    if (chosen.v.action === 'unset') {
      plan.unset.push({ key: row.key, devices: devices });
      continue;
    }

    const revisionSchema = chosen.d.revision ? h.schemas.get(chosen.d.revision.id) ?? null : null;
    if (!revisionSchema) {
      refuse(row.siteId, row.key, 'not_applicable');
      continue;
    }
    let value: JsonValue;
    if (chosen.v.found.status === 'secret_found') {
      const plain = h.secrets.get(secretKey(chosen.d.deviceId, row.key));
      if (plain === undefined) {
        refuse(row.siteId, row.key, 'not_applicable');
        continue;
      }
      value = plain;
    } else if (chosen.v.found.status === 'found') {
      value = chosen.v.found.value;
    } else {
      refuse(row.siteId, row.key, 'not_applicable');
      continue;
    }

    const schemas = [revisionSchema, ...publishedSchemas.filter((s) => declares(s, row.key) !== null)];
    const isSecret = schemas.some((s) => declares(s, row.key)?.['x-obliwan-secret'] === true);
    const reasons: string[] = [];
    for (const s of schemas) {
      const judged = judgeValueAgainstSchema(s, row.key, value, { secret: isSecret });
      if (judged.uncheckable) reasons.push('cannot be checked against one of its declarations');
      for (const r of judged.reasons) if (!reasons.includes(r)) reasons.push(r);
    }
    if (isSecret && typeof value !== 'string') reasons.push('a secret must be a text');
    if (reasons.length > 0) {
      refuse(row.siteId, row.key, 'invalid', reasons.join('; ').slice(0, 300));
      continue;
    }
    plan.writes.push({ key: row.key, value, isSecret, devices });
  }

  const written: InfraAnalysisApplyResult['written'] = [];
  const now = new Date().toISOString();
  for (const [siteId, plan] of plans) {
    if (plan.writes.length === 0 && plan.unset.length === 0) continue;
    try {
      if (plan.writes.length > 0) {
        await variableResolver.setBulk(
          tenantId,
          'site',
          siteId,
          plan.writes.map((w) => ({ key: w.key, value: w.value, isSecret: w.isSecret, meta: { updatedBy: actor.userId } })),
        );
      }
      for (const u of plan.unset) await variableResolver.remove(tenantId, 'site', siteId, u.key);
    } catch (err) {
      // The store's refusals name keys and scopes, never values; cut anyway.
      const detail = err instanceof Error ? err.message.slice(0, 300) : null;
      for (const w of plan.writes) refuse(siteId, w.key, 'write_failed', w.isSecret ? null : detail);
      for (const u of plan.unset) refuse(siteId, u.key, 'write_failed', detail);
      continue;
    }
    for (const w of plan.writes) for (const d of w.devices) for (const v of d.variables) if (v.key === w.key) v.appliedAt = now;
    for (const u of plan.unset) for (const d of u.devices) for (const v of d.variables) if (v.key === u.key) v.appliedAt = now;
    written.push({ siteId, code: plan.code, keys: plan.writes.map((w) => w.key), unset: plan.unset.map((u) => u.key) });
    try {
      await appendAudit({
        tenantId,
        actorType: 'user',
        actorId: actor.userId,
        actorName: actor.username,
        action: 'infra_analysis.applied',
        entityType: 'site',
        entityId: siteId,
        correlationId: h.snapshot.analysisId,
        // Variable NAMES only — which ones went to the vault is said, never
        // a value. Field names clear of the audit's secret-name mask.
        after: {
          written: plan.writes.map((w) => w.key),
          toVault: plan.writes.filter((w) => w.isSecret).map((w) => w.key),
          removed: plan.unset.map((u) => u.key),
        },
      });
    } catch (err) {
      logger.error({ tenantId, siteId, err: err instanceof Error ? { name: err.name } : null }, 'Infra analysis: the apply audit entry could not be written');
    }
  }
  logger.info(
    { tenantId, analysisId: h.snapshot.analysisId, sites: written.length, refused: refused.length, by: actor.userId },
    'Infra analysis applied',
  );
  return { analysisId: h.snapshot.analysisId, written, refused };
}

// ============================================================================
// Export
// ============================================================================

/**
 * The analysis as files: the Quick Setup variables table (`level;scope_ref;
 * key;value;secret`, site rows only — a secret row ALWAYS has an empty value,
 * which Quick Setup reads as "keep what is stored") and the LAN reprise table
 * (`code;lan;router_ip`, the form `POST /allocation/tenants/:id/lan-reprise`
 * reads). Only values that are valid and agreed by every router of their site.
 */
export function exportAnalysis(tenantId: number, actor: InfraActor, id: string): InfraAnalysisExport {
  assertPlatformAdmin(actor);
  const h = heldFor(tenantId, actor, id);
  if (h.snapshot.status !== 'done') {
    throw new InfraAnalysisError('ANALYSIS_RUNNING', 'The analysis is still running: export once it has ended.', 409);
  }
  const done = h.snapshot.devices
    .filter((d) => d.state === 'done' && d.site)
    .sort((a, b) => compareCodes(a.site!.code, b.site!.code) || a.deviceId - b.deviceId);

  const rows: SetupVariableRow[] = [];
  const taken = new Set<string>();
  for (const d of done) {
    for (const v of [...d.variables].sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0))) {
      if (v.verdict === 'invalid' || v.verdict === 'conflict') continue;
      // A value read that CHANGES one stored for the site (a wan1_mode=static
      // typed by hand) is not exported: re-importing this file would write it
      // with nobody having ticked the row. The screen offers it one by one.
      if (v.verdict === 'differs' && v.stored.level === 'site') continue;
      const tag = `${d.site!.code}\u0000${v.key}`;
      if (taken.has(tag)) continue;
      if (v.found.status === 'found') {
        rows.push({ level: 'site', scopeRef: d.site!.code, key: v.key, value: v.found.value, secret: false });
        taken.add(tag);
      } else if (v.found.status === 'secret_found') {
        rows.push({ level: 'site', scopeRef: d.site!.code, key: v.key, secret: true });
        taken.add(tag);
      }
    }
  }

  const lanBySite = new Map<string, { lan: string; routerIp: string } | null>();
  for (const d of done) {
    if (d.lan?.status !== 'found' || !d.lan.lan || !d.lan.routerIp) continue;
    const code = d.site!.code;
    const mine = { lan: d.lan.lan, routerIp: d.lan.routerIp };
    if (!lanBySite.has(code)) lanBySite.set(code, mine);
    else {
      const prev = lanBySite.get(code);
      // Two routers of one site disagree: the file says nothing for it.
      if (prev && (prev.lan !== mine.lan || prev.routerIp !== mine.routerIp)) lanBySite.set(code, null);
    }
  }
  const lanRows: string[][] = [['code', 'lan', 'router_ip']];
  for (const [code, lan] of lanBySite) if (lan) lanRows.push([code, lan.lan, lan.routerIp]);

  const day = h.snapshot.startedAt.slice(0, 10).replace(/-/g, '');
  return {
    variables: { filename: `infra-analysis-variables-${day}.csv`, csv: variablesToCsv(rows), rows: rows.length },
    lan: { filename: `infra-analysis-lan-${day}.csv`, csv: toDelimited(lanRows, ';'), rows: lanRows.length - 1 },
  };
}
