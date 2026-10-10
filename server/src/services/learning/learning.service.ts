// ============================================================================
// Learning mode — the flag, the listing, a capture's detail, the dataset
// ============================================================================
//
// Platform administrators only (routes: `requireRole('admin')`; here:
// `assertPlatformAdmin`). Every read is scoped to the tenant (or widened by
// the god view through `applyTenantScope`); every write acts in the device's
// own tenant and is audited there, counts and names only.

import { gunzipSync } from 'zlib';
import {
  LEARNING_MAX_DEVICES,
  type LearnedSecretRef,
  type LearnedSiteFacts,
  type LearningAccount,
  type LearningCaptureDetail,
  type LearningCaptureReason,
  type LearningCaptureStatus,
  type LearningCaptureSummary,
  type LearningDataset,
  type LearningDeviceRow,
  type LearningStateResult,
  type LearningWithheldLine,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { applyTenantScope, tenantNames } from '../../utils/globalView';
import { appendAudit } from '../attestation/auditLog.service';
import { resolveRevisionForDevice } from '../template/assignment.service';
import { LearningError, assertPlatformAdmin, type LearningActor } from './guard';
import { markStaleCaptures } from './capture.service';

// ============================================================================
// Helpers
// ============================================================================

function cleanIds(ids: readonly number[]): number[] {
  const out = [...new Set(ids.map(Number))].filter((n) => Number.isInteger(n) && n > 0);
  if (out.length === 0) throw new LearningError('NO_DEVICES', 'Name at least one router.', 400);
  if (out.length > LEARNING_MAX_DEVICES) {
    throw new LearningError('TOO_MANY_DEVICES', `At most ${LEARNING_MAX_DEVICES} routers at once.`, 400);
  }
  return out;
}

function iso(v: Date | string | null | undefined): string | null {
  return v === null || v === undefined ? null : new Date(v).toISOString();
}

function json<T>(v: unknown, fallback: T): T {
  if (v === null || v === undefined) return fallback;
  if (typeof v === 'string') {
    try {
      return JSON.parse(v) as T;
    } catch {
      return fallback;
    }
  }
  return v as T;
}

interface CaptureRow {
  id: string | number;
  device_id: number;
  run_id: string;
  status: LearningCaptureStatus;
  reason: LearningCaptureReason | null;
  detail: string | null;
  account: LearningAccount | null;
  family: string | null;
  os_version: string | null;
  model: string | null;
  facts: unknown;
  secret_count: number | null;
  withheld: unknown;
  snapshot_id: string | number | null;
  snapshot_error: string | null;
  redacted_bytes: number | null;
  redacted_sha256: string | null;
  started_at: Date;
  finished_at: Date | null;
}

const CAPTURE_COLUMNS = [
  'c.id', 'c.device_id', 'c.run_id', 'c.status', 'c.reason', 'c.detail', 'c.account', 'c.family',
  'c.os_version', 'c.model', 'c.facts', 'c.secret_count', 'c.withheld', 'c.snapshot_id',
  'c.snapshot_error', 'c.redacted_bytes', 'c.redacted_sha256', 'c.started_at', 'c.finished_at',
];

function summaryOf(c: CaptureRow): LearningCaptureSummary {
  const facts = json<LearnedSiteFacts | null>(c.facts, null);
  const withheld = json<LearningWithheldLine[]>(c.withheld, []);
  return {
    id: Number(c.id),
    runId: c.run_id,
    status: c.status,
    reason: c.reason,
    detail: c.detail,
    account: c.account,
    startedAt: new Date(c.started_at).toISOString(),
    finishedAt: iso(c.finished_at),
    wan1Mode: facts?.wan1.mode ?? null,
    pppoeName: facts?.wan1.pppoeName ?? null,
    timezone: facts?.timezone ?? null,
    apns: facts ? [...new Set(facts.lte.apnProfiles.map((p) => p.apn).filter((a): a is string => !!a))] : [],
    secretCount: c.secret_count === null ? null : Number(c.secret_count),
    withheldCount: withheld.length,
    snapshotId: c.snapshot_id === null ? null : String(c.snapshot_id),
    snapshotError: c.snapshot_error,
  };
}

/** The latest capture per device (any status, or only `succeeded`). */
async function latestCaptures(deviceIds: readonly number[], succeededOnly = false): Promise<Map<number, CaptureRow>> {
  const out = new Map<number, CaptureRow>();
  for (let i = 0; i < deviceIds.length; i += 1000) {
    const q = db('learning_captures as c')
      .whereIn('c.device_id', deviceIds.slice(i, i + 1000))
      .distinctOn('c.device_id')
      .orderBy([{ column: 'c.device_id' }, { column: 'c.started_at', order: 'desc' }, { column: 'c.id', order: 'desc' }])
      .select(CAPTURE_COLUMNS);
    if (succeededOnly) void q.where('c.status', 'succeeded');
    for (const r of (await q) as CaptureRow[]) out.set(Number(r.device_id), r);
  }
  return out;
}

// ============================================================================
// The flag
// ============================================================================

/**
 * Put routers in learning (`on`) or take them out. MikroTik CPEs only (the
 * concentrator and the other brands are listed as skipped). Idempotent: a
 * router already in the asked state is neither changed nor audited.
 */
export async function setLearning(
  tenantId: number,
  deviceIds: readonly number[],
  on: boolean,
  actor: LearningActor,
): Promise<LearningStateResult> {
  assertPlatformAdmin(actor);
  const ids = cleanIds(deviceIds);
  const rows = (await db('devices')
    .where('tenant_id', tenantId)
    .whereIn('id', ids)
    .select('id', 'name', 'brand', 'role', 'learning_since')) as Array<{
    id: number; name: string; brand: string; role: string | null; learning_since: Date | null;
  }>;
  const byId = new Map(rows.map((r) => [Number(r.id), r]));
  const result: LearningStateResult = { changed: [], skipped: [] };
  const toChange: number[] = [];
  for (const id of ids) {
    const r = byId.get(id);
    if (!r) result.skipped.push({ deviceId: id, reason: 'not_found' });
    else if (r.brand !== 'mikrotik') result.skipped.push({ deviceId: id, reason: 'not_mikrotik' });
    else if (r.role === 'concentrator') result.skipped.push({ deviceId: id, reason: 'concentrator' });
    else if (on ? r.learning_since === null : r.learning_since !== null) toChange.push(id);
  }
  if (toChange.length > 0) {
    await db('devices')
      .where('tenant_id', tenantId)
      .whereIn('id', toChange)
      .update(on
        ? { learning_since: db.fn.now(), learning_by: actor.userId }
        : { learning_since: null, learning_by: null });
  }
  result.changed = toChange;
  for (const id of toChange) {
    try {
      await appendAudit({
        tenantId,
        actorType: 'user',
        actorId: actor.userId,
        actorName: actor.username,
        action: on ? 'learning.enabled' : 'learning.disabled',
        entityType: 'device',
        entityId: id,
        after: { learning: on, deviceName: byId.get(id)?.name ?? null },
      });
    } catch (err) {
      logger.error({ tenantId, deviceId: id, err: err instanceof Error ? { name: err.name } : null }, 'Learning: the audit entry could not be written');
    }
  }
  return result;
}

// ============================================================================
// The listing
// ============================================================================

export async function listLearningDevices(
  tenantId: number,
  opts: { learningOnly?: boolean; search?: string | null },
  actor: LearningActor,
): Promise<{ godView: boolean; devices: LearningDeviceRow[] }> {
  assertPlatformAdmin(actor);
  const q = db('devices as d')
    .leftJoin('sites as s', function sameTenantSite(this: import('knex').Knex.JoinClause) {
      this.on('s.id', '=', 'd.site_id').andOn('s.tenant_id', '=', 'd.tenant_id');
    })
    .where('d.brand', 'mikrotik')
    .andWhere(function notConcentrator(this: import('knex').Knex.QueryBuilder) {
      this.whereNull('d.role').orWhereNot('d.role', 'concentrator');
    });
  const godView = applyTenantScope(q, 'd.tenant_id', tenantId);
  if (opts.learningOnly) void q.whereNotNull('d.learning_since');
  const search = (opts.search ?? '').trim();
  if (search !== '') {
    const pat = `%${search.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
    void q.andWhere(function matches(this: import('knex').Knex.QueryBuilder) {
      this.where('d.name', 'ilike', pat).orWhere('s.code', 'ilike', pat).orWhere('s.name', 'ilike', pat);
    });
  }
  const rows = (await q
    .orderBy('s.code', 'asc')
    .orderBy('d.name', 'asc')
    .limit(5000)
    .select(
      'd.id as id', 'd.tenant_id as tenant_id', 'd.name as name', 'd.status as status',
      'd.learning_since as learning_since', 'd.learning_by as learning_by',
      's.id as site_id', 's.code as site_code', 's.name as site_name',
    )) as Array<{
    id: number; tenant_id: number; name: string; status: string; learning_since: Date | null; learning_by: number | null;
    site_id: number | null; site_code: string | null; site_name: string | null;
  }>;
  await markStaleCaptures(godView ? null : tenantId);
  const captures = await latestCaptures(rows.map((r) => Number(r.id)));
  const names = godView ? await tenantNames(rows.map((r) => Number(r.tenant_id))) : new Map<number, string>();
  return {
    godView,
    devices: rows.map((r) => {
      const c = captures.get(Number(r.id));
      const row: LearningDeviceRow = {
        deviceId: Number(r.id),
        deviceName: r.name,
        site: r.site_id === null ? null : { id: Number(r.site_id), code: r.site_code as string, name: r.site_name as string },
        status: r.status,
        learning: r.learning_since ? { since: new Date(r.learning_since).toISOString(), byUserId: r.learning_by } : null,
        lastCapture: c ? summaryOf(c) : null,
      };
      if (godView) {
        row.tenantId = Number(r.tenant_id);
        row.tenantName = names.get(Number(r.tenant_id)) ?? null;
      }
      return row;
    }),
  };
}

// ============================================================================
// One capture
// ============================================================================

async function deviceOf(tenantId: number, deviceId: number): Promise<{ id: number; name: string; site_id: number | null }> {
  const d = (await db('devices').where({ id: deviceId, tenant_id: tenantId }).first('id', 'name', 'site_id')) as
    | { id: number; name: string; site_id: number | null }
    | undefined;
  if (!d) throw new LearningError('DEVICE_NOT_FOUND', 'No such router in this workspace.', 404);
  return d;
}

/** The secrets vaulted for a device, with how many sites share each value. */
async function secretRefs(tenantId: number, deviceId: number): Promise<LearnedSecretRef[]> {
  const rows = (await db('learned_secrets')
    .where({ tenant_id: tenantId, device_id: deviceId })
    .orderBy('ref')
    .select('id', 'ref', 'menu', 'item', 'prop', 'fingerprint', 'last_seen_at', 'vanished_at')) as Array<{
    id: string | number; ref: string; menu: string; item: string | null; prop: string; fingerprint: string | null;
    last_seen_at: Date; vanished_at: Date | null;
  }>;
  const fps = [...new Set(rows.map((r) => r.fingerprint).filter((f): f is string => !!f))];
  const shared = new Map<string, number>();
  if (fps.length > 0) {
    const counts = (await db('learned_secrets')
      .where('tenant_id', tenantId)
      .whereIn('fingerprint', fps)
      .whereNull('vanished_at')
      .groupBy('fingerprint')
      .select('fingerprint')
      .countDistinct({ sites: 'site_id' })) as Array<{ fingerprint: string; sites: string | number }>;
    for (const c of counts) shared.set(c.fingerprint, Number(c.sites));
  }
  return rows.map((r) => ({
    id: Number(r.id),
    ref: r.ref,
    menu: r.menu,
    item: r.item,
    prop: r.prop,
    fingerprint: r.fingerprint,
    sharedWithSites: r.fingerprint ? shared.get(r.fingerprint) ?? 1 : 1,
    lastSeenAt: new Date(r.last_seen_at).toISOString(),
    vanishedAt: iso(r.vanished_at),
  }));
}

/** The latest capture of a device: its facts, its secret refs (never a value)
 *  and its withheld lines. Null when the device was never captured. */
export async function captureDetail(
  tenantId: number,
  deviceId: number,
  actor: LearningActor,
): Promise<LearningCaptureDetail | null> {
  assertPlatformAdmin(actor);
  const device = await deviceOf(tenantId, deviceId);
  await markStaleCaptures(tenantId);
  const c = (await db('learning_captures as c')
    .where({ 'c.tenant_id': tenantId, 'c.device_id': deviceId })
    .orderBy('c.started_at', 'desc')
    .orderBy('c.id', 'desc')
    .first(CAPTURE_COLUMNS)) as CaptureRow | undefined;
  if (!c) return null;
  return {
    captureId: Number(c.id),
    deviceId: device.id,
    deviceName: device.name,
    status: c.status,
    reason: c.reason,
    detail: c.detail,
    account: c.account,
    family: c.family,
    osVersion: c.os_version,
    model: c.model,
    startedAt: new Date(c.started_at).toISOString(),
    finishedAt: iso(c.finished_at),
    facts: json<LearnedSiteFacts | null>(c.facts, null),
    secrets: await secretRefs(tenantId, deviceId),
    withheld: json<LearningWithheldLine[]>(c.withheld, []),
    snapshotId: c.snapshot_id === null ? null : String(c.snapshot_id),
    snapshotError: c.snapshot_error,
    redactedBytes: c.redacted_bytes === null ? null : Number(c.redacted_bytes),
    redactedSha256: c.redacted_sha256,
  };
}

/** The redacted copy of one capture, as text (placeholders, no value). */
export async function captureExportText(
  tenantId: number,
  captureId: number,
  actor: LearningActor,
): Promise<{ captureId: number; deviceId: number; text: string }> {
  assertPlatformAdmin(actor);
  const row = (await db('learning_captures')
    .where({ id: captureId, tenant_id: tenantId })
    .first('id', 'device_id', 'redacted_gz')) as { id: string | number; device_id: number; redacted_gz: Buffer | null } | undefined;
  if (!row || !row.redacted_gz) throw new LearningError('NOT_FOUND', 'No redacted copy for this capture in this workspace.', 404);
  return { captureId: Number(row.id), deviceId: Number(row.device_id), text: gunzipSync(row.redacted_gz).toString('utf8') };
}

// ============================================================================
// The dataset
// ============================================================================

export const LEARNING_DATASET_NOTICE =
  'ObliWAN learning dataset. Every secret read off the routers is in the ObliWAN vault and appears here only as ' +
  'secret:<ref>; lines whose secret sat inside a script or a comment are withheld. NOT pseudonymised: logins, ' +
  'public addresses and store names are readable. Keep it outside any versioned repository.';

function bump(hist: Record<string, number>, key: string | null | undefined): void {
  if (key === null || key === undefined || key === '') return;
  hist[key] = (hist[key] ?? 0) + 1;
}

/**
 * The redacted dataset of the named routers: the latest SUCCEEDED capture of
 * each (its redacted copy, facts, secret refs and fingerprints, withheld
 * lines), the template each resolves to (distinct revision bodies once), and
 * summary histograms. No value anywhere.
 */
export async function buildDataset(
  tenantId: number,
  deviceIds: readonly number[],
  actor: LearningActor,
): Promise<LearningDataset> {
  assertPlatformAdmin(actor);
  const ids = cleanIds(deviceIds);
  const devices = (await db('devices as d')
    .leftJoin('sites as s', function sameTenantSite(this: import('knex').Knex.JoinClause) {
      this.on('s.id', '=', 'd.site_id').andOn('s.tenant_id', '=', 'd.tenant_id');
    })
    .where('d.tenant_id', tenantId)
    .whereIn('d.id', ids)
    .select('d.id as id', 'd.name as name', 'd.model as model', 'd.os_version as os_version',
      's.id as site_id', 's.code as site_code', 's.name as site_name')) as Array<{
    id: number; name: string; model: string | null; os_version: string | null;
    site_id: number | null; site_code: string | null; site_name: string | null;
  }>;
  if (devices.length !== ids.length) {
    throw new LearningError('DEVICE_NOT_FOUND', 'One of the routers named does not exist in this workspace.', 404);
  }
  const captures = await latestCaptures(ids, true);
  const tenantName = (await tenantNames([tenantId])).get(tenantId) ?? null;

  const templates = new Map<string, LearningDataset['templates'][number]>();
  const out: LearningDataset['devices'] = [];
  const summary: LearningDataset['summary'] = {
    wan1Modes: {}, pppoeNames: {}, timezones: {}, apns: {}, models: {}, osVersions: {}, staticSites: [], secretSharing: [],
  };
  const sharing = new Map<string, { menu: string; prop: string; values: Set<string>; sites: Set<number> }>();

  for (const d of [...devices].sort((a, b) => (a.site_code ?? '').localeCompare(b.site_code ?? '') || a.name.localeCompare(b.name))) {
    const c = captures.get(Number(d.id));
    if (!c) continue;
    const gz = (await db('learning_captures').where({ id: c.id, tenant_id: tenantId }).first('redacted_gz')) as { redacted_gz: Buffer | null } | undefined;
    if (!gz?.redacted_gz) continue;
    const facts = json<LearnedSiteFacts | null>(c.facts, null);

    let template: LearningDataset['devices'][number]['template'] = null;
    try {
      const { candidate } = await resolveRevisionForDevice(tenantId, Number(d.id));
      if (candidate?.revisionId) {
        const rev = (await db('template_revisions as r')
          .join('templates as t', 't.id', 'r.template_id')
          .where('r.id', candidate.revisionId)
          .andWhere(function ownOrLibrary(this: import('knex').Knex.QueryBuilder) {
            this.where('r.tenant_id', tenantId).orWhereNull('r.tenant_id');
          })
          .first('r.id as id', 'r.revision as revision', 'r.body as body', 't.name as name')) as
          | { id: string | number; revision: number; body: string; name: string }
          | undefined;
        if (rev) {
          template = { revisionId: String(rev.id), name: rev.name, revision: Number(rev.revision) };
          if (!templates.has(String(rev.id))) {
            templates.set(String(rev.id), { revisionId: String(rev.id), name: rev.name, revision: Number(rev.revision), body: rev.body });
          }
        }
      }
    } catch {
      template = null;
    }

    const secrets = (await db('learned_secrets')
      .where({ tenant_id: tenantId, device_id: d.id })
      .whereNull('vanished_at')
      .orderBy('ref')
      .select('ref', 'menu', 'item', 'prop', 'fingerprint')) as Array<{
      ref: string; menu: string; item: string | null; prop: string; fingerprint: string | null;
    }>;
    for (const s of secrets) {
      const key = `${s.menu}\u0000${s.prop}`;
      const g = sharing.get(key) ?? { menu: s.menu, prop: s.prop, values: new Set<string>(), sites: new Set<number>() };
      if (s.fingerprint) g.values.add(s.fingerprint);
      if (d.site_id !== null) g.sites.add(Number(d.site_id));
      sharing.set(key, g);
    }

    bump(summary.wan1Modes, facts?.wan1.mode);
    bump(summary.pppoeNames, facts?.wan1.pppoeName);
    bump(summary.timezones, facts?.timezone);
    for (const a of facts?.lte.apnProfiles ?? []) bump(summary.apns, a.apn);
    bump(summary.models, c.model ?? d.model);
    bump(summary.osVersions, c.os_version ?? d.os_version);
    if (facts?.wan1.mode === 'static') {
      summary.staticSites.push({
        code: d.site_code, device: d.name, address: facts.wan1.staticAddress, gateway: facts.wan1.staticGateway,
      });
    }

    out.push({
      site: d.site_id === null ? null : { id: Number(d.site_id), code: d.site_code as string, name: d.site_name as string },
      device: { id: Number(d.id), name: d.name, model: c.model ?? d.model, osVersion: c.os_version ?? d.os_version },
      template,
      capturedAt: iso(c.finished_at) ?? new Date(c.started_at).toISOString(),
      account: c.account,
      facts,
      secrets,
      withheld: json<LearningWithheldLine[]>(c.withheld, []),
      export: gunzipSync(gz.redacted_gz).toString('utf8'),
    });
  }
  summary.secretSharing = [...sharing.values()]
    .map((g) => ({ menu: g.menu, prop: g.prop, distinctValues: g.values.size, sites: g.sites.size }))
    .sort((a, b) => a.menu.localeCompare(b.menu) || a.prop.localeCompare(b.prop));

  try {
    await appendAudit({
      tenantId,
      actorType: 'user',
      actorId: actor.userId,
      actorName: actor.username,
      action: 'learning.dataset',
      entityType: 'tenant',
      entityId: tenantId,
      after: { routers: out.length, asked: ids.length },
    });
  } catch (err) {
    logger.error({ tenantId, err: err instanceof Error ? { name: err.name } : null }, 'Learning: the dataset audit entry could not be written');
  }

  return {
    format: 'obliwan-learning-dataset',
    version: 1,
    notice: LEARNING_DATASET_NOTICE,
    tenant: { id: tenantId, name: tenantName },
    generatedAt: new Date().toISOString(),
    templates: [...templates.values()],
    devices: out,
    summary,
  };
}
