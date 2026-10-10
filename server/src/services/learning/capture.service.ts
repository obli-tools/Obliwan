// ============================================================================
// Learning mode — the CAPTURE (the one exception to the no-secrets rule, 2026-10-04)
// ============================================================================
//
// For each router in learning: ONE SSH session, READ-ONLY, that proves the
// box is the device, checks the account may read secrets, checks the
// RouterOS major, then reads the export WITH its secrets
// (`routerOsLearningExportCommand`, the only importer of that spelling) and
// redacts it IN MEMORY, inside the session's callback.
//
// ┌─ WHERE THE PLAINTEXT GOES, AND WHERE IT NEVER GOES ──────────────────────┐
// │ The raw export lives in one local of the export step and is dropped as  │
// │ soon as `redactSensitiveExport()` returns. Each secret value then goes:  │
// │  - into the session's scrub list (every error of the session is         │
// │    redacted of it);                                                     │
// │  - into the vault, encrypted (`learned_secrets.secret_enc`, key version │
// │    inside it), with a per-tenant HMAC fingerprint beside it;            │
// │ and NOWHERE else: not a log line (ids, reasons and `err.name` only), not │
// │ an audit row (`command_audit` holds the commands, never the output;     │
// │ `audit_log` counts), not a file (nothing is written to disk), not a      │
// │ response. The stored copy is the REDACTED one; the snapshot made from it │
// │ goes through the unchanged secrets gate (`storeSnapshotFromLearning`).   │
// │ JavaScript strings cannot be zeroed: until garbage collection the raw    │
// │ text is in the heap, and a heap dump taken during a capture holds it.    │
// └──────────────────────────────────────────────────────────────────────────┘
//
// Platform administrators only (`requireRole('admin')` on the routes, and
// `assertPlatformAdmin` here). Captures run in the web process, like the infra
// analysis: a restart leaves `running` rows, which read as `interrupted` after
// `LEARNING_STALE_RUN_MS`.

import crypto from 'crypto';
import { gzipSync } from 'zlib';
import {
  LEARNING_CAPTURES_KEPT,
  LEARNING_MAX_DEVICES,
  LEARNING_STALE_RUN_MS,
  RECONCILE_ATTACH_DEFAULT_USERNAME,
  RECONCILE_ATTACH_VAULT_KEY,
  type LearningAccount,
  type LearningCaptureReason,
  type LearningCaptureStart,
  type LearningCaptureStatus,
  type LearningRunView,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { isGodView } from '../../utils/globalView';
import { appendAudit } from '../attestation/auditLog.service';
import { auditedCommand } from '../audit.service';
import { decrypt, encrypt, inspect } from '../secretVault.service';
import { SSH_ACCOUNT_READS, judgeAccountPolicy, parseAccountGroup } from '../change/managementAccess.service';
import { isConcentratorDegraded } from '../fleet/reachability.service';
import { resolveLegacyVariable } from '../bench/compile.service';
import { learnedSecretFingerprint } from '../template/variableResolver.service';
import { DriverError, redact } from '../drivers/types';
import { withSsh, type SshExecOptions, type SshTransport } from '../transport/ssh.transport';
import {
  ExportDialectRefusal,
  RedactionIncompleteError,
  assertSshBoxSpeaksFamily,
  redactSensitiveExport,
  routerOsLearningExportCommand,
  type RedactedLearningExport,
} from '../drivers/mikrotik/driver';
import { canonicalizeText, parsePreamble } from '../drivers/mikrotik/parse';
import { storeSnapshotFromLearning } from '../config/collect.service';
import {
  devicesQuery,
  failureReason,
  mapLimit,
  pppSessionOpen,
  proveSessionIdentity,
  sshHost,
  sshRows,
  staticSkip,
  type DeviceRow,
  type SshRow,
} from '../infraAnalysis/infraAnalysis.service';
import { learnedSiteFacts } from './siteFacts';
import { LearningError, assertPlatformAdmin, type LearningActor } from './guard';

// ============================================================================
// Tuning
// ============================================================================

export const CAPTURE_CONCURRENCY = 4;
/** One device's whole capture: handshake, identity, policy, version, export. */
export const CAPTURE_DEVICE_BUDGET_MS = 120_000;
const SSH_STEP_TIMEOUT_MS = 15_000;
const SSH_MAX_OUTPUT = 256 * 1024;
const EXPORT_TIMEOUT_MS = 60_000;
const EXPORT_MAX_OUTPUT = 16 * 1024 * 1024;
const AUDIT_PURPOSE = 'learning_capture';
/** Policies the capture's account must hold: `sensitive` is what makes the
 *  export print secrets at all. */
const REQUIRED_POLICIES = ['read', 'sensitive'] as const;

// ============================================================================
// Devices
// ============================================================================

interface CaptureDevice extends DeviceRow {
  family: string | null;
  learning_since: Date | string | null;
}

function captureDevicesQuery(tenantId: number) {
  return devicesQuery(tenantId).select('d.family as family', 'd.learning_since as learning_since');
}

/** A refusal decided inside the capture, carrying its reason code. */
class CaptureStop extends Error {
  constructor(readonly status: 'failed' | 'skipped', readonly reason: LearningCaptureReason, readonly detail: string | null = null) {
    super(reason);
    this.name = 'CaptureStop';
  }
}

// ============================================================================
// Runs
// ============================================================================

/** Running rows older than the stale delay are a run a restart killed. */
export async function markStaleCaptures(tenantId: number | null): Promise<number> {
  const q = db('learning_captures')
    .where('status', 'running')
    .andWhere('started_at', '<', new Date(Date.now() - LEARNING_STALE_RUN_MS));
  if (tenantId !== null) void q.andWhere('tenant_id', tenantId);
  return q.update({ status: 'failed', reason: 'interrupted', finished_at: db.fn.now() });
}

/**
 * Start a capture of `deviceIds` (of `tenantId`). Inserts one `running` row
 * per device under a shared run id and answers at once; the captures run in
 * the background (`done` settles when they have all ended).
 */
export async function startCaptureRun(
  tenantId: number,
  deviceIds: readonly number[],
  actor: LearningActor,
): Promise<LearningCaptureStart & { done: Promise<void> }> {
  assertPlatformAdmin(actor);
  const ids = [...new Set(deviceIds.map(Number))].filter((n) => Number.isInteger(n) && n > 0);
  if (ids.length === 0) throw new LearningError('NO_DEVICES', 'Name at least one router to capture.', 400);
  if (ids.length > LEARNING_MAX_DEVICES) {
    throw new LearningError('TOO_MANY_DEVICES', `At most ${LEARNING_MAX_DEVICES} routers per capture.`, 400);
  }
  await markStaleCaptures(tenantId);
  const busy = await db('learning_captures').where({ tenant_id: tenantId, status: 'running' }).first('id');
  if (busy) {
    throw new LearningError('CAPTURE_RUNNING', 'A capture of this workspace is still running: wait for it to end.', 409);
  }
  const devices = (await captureDevicesQuery(tenantId).whereIn('d.id', ids)) as CaptureDevice[];
  if (devices.length !== ids.length) {
    // Another workspace's router and an unknown id read the same.
    throw new LearningError('DEVICE_NOT_FOUND', 'One of the routers named does not exist in this workspace.', 404);
  }
  const byId = new Map(devices.map((d) => [Number(d.id), d]));
  const ordered = ids.map((id) => byId.get(id)!);

  const runId = crypto.randomUUID();
  const inserted = (await db('learning_captures')
    .insert(ordered.map((d) => ({
      tenant_id: tenantId,
      device_id: d.id,
      site_id: d.site_id,
      run_id: runId,
      status: 'running',
      requested_by: actor.userId,
    })))
    .returning(['id', 'device_id'])) as Array<{ id: string | number; device_id: number }>;
  const captureOf = new Map(inserted.map((r) => [Number(r.device_id), Number(r.id)]));

  logger.info({ tenantId, runId, devices: ordered.length, by: actor.userId }, 'Learning capture started');
  const done = runCaptures(tenantId, runId, ordered, captureOf, actor).catch((err: unknown) => {
    logger.error({ tenantId, runId, err: err instanceof Error ? { name: err.name } : null }, 'Learning capture: the run stopped');
  });
  return { runId, total: ordered.length, done };
}

async function runCaptures(
  tenantId: number,
  runId: string,
  devices: CaptureDevice[],
  captureOf: Map<number, number>,
  actor: LearningActor,
): Promise<void> {
  const ssh = await sshRows(devices.map((d) => d.id));
  await mapLimit(devices, CAPTURE_CONCURRENCY, async (device) => {
    const captureId = captureOf.get(device.id)!;
    try {
      await captureDevice(tenantId, runId, captureId, device, ssh.get(device.id), actor);
    } catch (err) {
      logger.error(
        { tenantId, runId, deviceId: device.id, err: err instanceof Error ? { name: err.name } : null },
        'Learning capture: a device could not be captured',
      );
      await finishCapture(captureId, 'failed', 'internal', null).catch(() => undefined);
    }
  });
  logger.info({ tenantId, runId }, 'Learning capture finished');
}

async function finishCapture(
  captureId: number,
  status: 'failed' | 'skipped',
  reason: LearningCaptureReason,
  detail: string | null,
): Promise<void> {
  await db('learning_captures')
    .where({ id: captureId, status: 'running' })
    .update({ status, reason, detail: detail === null ? null : detail.slice(0, 300), finished_at: db.fn.now() });
}

/** The run's rows, stale ones first marked `interrupted`. */
export async function getRun(tenantId: number, runId: string, actor: LearningActor): Promise<LearningRunView> {
  assertPlatformAdmin(actor);
  // God view (Default): the run was started in its routers' own tenant, and
  // the page polling it sits on the master tenant — the run is read wherever
  // it lives. Anywhere else, only the tenant's own.
  const everywhere = isGodView(tenantId);
  await markStaleCaptures(everywhere ? null : tenantId);
  const q = db('learning_captures as c')
    .join('devices as d', 'd.id', 'c.device_id')
    .where('c.run_id', runId);
  if (!everywhere) void q.andWhere('c.tenant_id', tenantId);
  const rows = (await q
    .orderBy('c.id')
    .select('c.id', 'c.device_id', 'd.name as device_name', 'c.status', 'c.reason', 'c.detail', 'c.started_at', 'c.finished_at')) as Array<{
    id: string | number; device_id: number; device_name: string; status: LearningCaptureStatus;
    reason: LearningCaptureReason | null; detail: string | null; started_at: Date; finished_at: Date | null;
  }>;
  if (rows.length === 0) throw new LearningError('NOT_FOUND', 'No such capture run in this workspace.', 404);
  const counts: Record<LearningCaptureStatus, number> = { running: 0, succeeded: 0, failed: 0, skipped: 0 };
  for (const r of rows) counts[r.status] += 1;
  return {
    runId,
    status: counts.running > 0 ? 'running' : 'done',
    total: rows.length,
    counts,
    rows: rows.map((r) => ({
      captureId: Number(r.id),
      deviceId: Number(r.device_id),
      deviceName: r.device_name,
      status: r.status,
      reason: r.reason,
      detail: r.detail,
      startedAt: new Date(r.started_at).toISOString(),
      finishedAt: r.finished_at ? new Date(r.finished_at).toISOString() : null,
    })),
  };
}

// ============================================================================
// One device
// ============================================================================

async function captureDevice(
  tenantId: number,
  runId: string,
  captureId: number,
  device: CaptureDevice,
  ssh: SshRow | undefined,
  actor: LearningActor,
): Promise<void> {
  // ── Before any socket ──────────────────────────────────────────────────
  // The device's own credential is not required here: the legacy
  // administrator may be the account that dials.
  const staticReason = staticSkip(device, ssh, true);
  if (staticReason) return finishCapture(captureId, 'skipped', staticReason as LearningCaptureReason, null);
  if (device.learning_since === null || device.learning_since === undefined) {
    return finishCapture(captureId, 'skipped', 'not_learning', null);
  }
  if (device.family !== 'mikrotik_routeros6' && device.family !== 'mikrotik_routeros7') {
    return finishCapture(captureId, 'failed', 'family_mismatch', `no learning export for family '${device.family ?? 'none'}'`);
  }
  const family = device.family;
  // Behind a concentrator, presence decides whether we may dial at all.
  if (device.concentrator_id !== null && device.ppp_username) {
    if (await isConcentratorDegraded(device.concentrator_id)) return finishCapture(captureId, 'skipped', 'concentrator_degraded', null);
    if (!(await pppSessionOpen(device))) return finishCapture(captureId, 'skipped', 'ppp_down', null);
  }

  // ── The account ────────────────────────────────────────────────────────
  let login: { username: string; password: string; account: LearningAccount };
  let legacy: { value: string } | null = null;
  try {
    legacy = await resolveLegacyVariable(RECONCILE_ATTACH_VAULT_KEY, tenantId, device.site_id);
  } catch {
    legacy = null;
  }
  if (legacy && (ssh?.username ?? '') !== RECONCILE_ATTACH_DEFAULT_USERNAME) {
    login = { username: RECONCILE_ATTACH_DEFAULT_USERNAME, password: legacy.value, account: 'legacy_admin' };
  } else {
    if (!ssh?.username || !ssh.secret_enc) return finishCapture(captureId, 'skipped', 'no_credential', null);
    try {
      login = { username: ssh.username, password: decrypt(ssh.secret_enc), account: 'device_ssh' };
    } catch {
      return finishCapture(captureId, 'skipped', 'no_credential', 'the SSH password stored for this device cannot be decrypted');
    }
  }
  legacy = null;
  await db('learning_captures').where({ id: captureId }).update({ account: login.account, family });

  const params = (ssh?.params ?? {}) as { legacyAlgorithms?: boolean };
  const host = sshHost(device, ssh) as string;
  const port = ssh?.port ?? 22;
  const deadline = Date.now() + CAPTURE_DEVICE_BUDGET_MS;
  const scrub: string[] = [login.password];

  let redacted: RedactedLearningExport | null = null;
  try {
    redacted = await withSsh(
      {
        host, port, username: login.username, password: login.password,
        timeoutMs: SSH_STEP_TIMEOUT_MS, legacyAlgorithms: params.legacyAlgorithms === true,
      },
      async (session: SshTransport) => {
        const left = (): number => {
          const ms = deadline - Date.now();
          if (ms <= 0) throw new DriverError(`device budget of ${CAPTURE_DEVICE_BUDGET_MS} ms spent`, 'TIMEOUT', { transport: 'ssh' });
          return ms;
        };
        // Every command audited BEFORE it is sent (`auditedCommand`): the
        // command, never the output. `scrub` holds the credential and, once
        // read, every secret.
        const audited = <T>(command: string, send: () => Promise<T>): Promise<T> =>
          auditedCommand(
            {
              tenantId,
              deviceId: device.id,
              deviceUuid: device.uuid,
              deviceName: device.name,
              userId: actor.userId,
              username: actor.username,
              transport: 'ssh',
              command,
              args: { purpose: AUDIT_PURPOSE, siteId: device.site_id, account: login.account },
              isWrite: false,
              correlationId: runId,
              secrets: scrub,
            },
            async () => {
              try {
                return await send();
              } catch (err) {
                if (err instanceof Error) err.message = redact(err.message, scrub);
                throw err;
              }
            },
          );
        const read = async (command: string): Promise<string> => {
          const ms = left();
          const res = await audited(command, () =>
            session.exec(command, { pty: false, timeoutMs: Math.min(SSH_STEP_TIMEOUT_MS, ms), maxOutputBytes: SSH_MAX_OUTPUT }));
          return res.stdout;
        };

        // 1. Identity — is this box the device?
        const proof = await proveSessionIdentity(read, device);
        if (!proof.ok) throw new CaptureStop('failed', proof.reason, proof.detail);

        // 2. May this account read secrets? BEFORE any export.
        const groupRead = SSH_ACCOUNT_READS.group(login.username);
        const group = groupRead ? parseAccountGroup(await read(groupRead)) : null;
        const policyRead = group ? SSH_ACCOUNT_READS.policy(group) : null;
        const policy = policyRead ? judgeAccountPolicy(await read(policyRead), [...REQUIRED_POLICIES]) : null;
        if (!policy || policy.state === 'unknown') throw new CaptureStop('failed', 'policy_unknown', null);
        if (policy.state === 'missing') {
          throw new CaptureStop('failed', 'no_sensitive_policy', `the account's group lacks: ${policy.missing.join(', ')}`);
        }

        // 3. The major the box runs, on this same session, BEFORE the export.
        const auditedExec = {
          exec: (command: string, opts: SshExecOptions = {}) => {
            const ms = left();
            return audited(command, () => session.exec(command, { ...opts, timeoutMs: Math.min(opts.timeoutMs ?? SSH_STEP_TIMEOUT_MS, ms) }));
          },
        };
        try {
          await assertSshBoxSpeaksFamily(auditedExec, family, { timeoutMs: SSH_STEP_TIMEOUT_MS });
        } catch (err) {
          if (err instanceof ExportDialectRefusal) throw new CaptureStop('failed', 'family_mismatch', redact(err.message, scrub).slice(0, 300));
          throw err;
        }

        // 4. The export, redacted INSIDE this callback: the raw text never
        //    leaves the closure below.
        const command = routerOsLearningExportCommand(family);
        const ms = left();
        return audited(command, async () => {
          const res = await session.exec(command, {
            pty: false,
            timeoutMs: Math.min(EXPORT_TIMEOUT_MS, ms),
            maxOutputBytes: EXPORT_MAX_OUTPUT,
          });
          if (res.code !== null && res.code !== 0) {
            // The exit code only: stderr may echo the command line or more.
            throw new CaptureStop('failed', 'export_failed', `the export exited with code ${res.code}`);
          }
          let raw: string | null = res.stdout;
          res.stdout = '';
          res.stderr = '';
          if (raw.trim() === '') throw new CaptureStop('failed', 'export_empty', null);
          try {
            const out = redactSensitiveExport(raw);
            for (const s of out.secrets) scrub.push(s.value);
            return out;
          } finally {
            raw = null;
          }
        });
      },
    );
  } catch (err) {
    if (err instanceof CaptureStop) return finishCapture(captureId, err.status, err.reason, err.detail);
    if (err instanceof RedactionIncompleteError) return finishCapture(captureId, 'failed', 'redaction_incomplete', err.message);
    const message = err instanceof Error ? err.message : String(err);
    return finishCapture(captureId, 'failed', failureReason(err) as LearningCaptureReason, redact(message, scrub).slice(0, 300));
  } finally {
    login.password = '';
  }
  if (!redacted) return finishCapture(captureId, 'failed', 'internal', null);

  // ── Facts, the redacted copy, the vault — ONE transaction ──────────────
  const facts = learnedSiteFacts(redacted.text);
  const { preamble } = parsePreamble(canonicalizeText(redacted.text));
  const textBuf = Buffer.from(redacted.text, 'utf8');
  const sha256 = crypto.createHash('sha256').update(textBuf).digest('hex');
  const secretCount = redacted.secrets.length;
  const withheld = redacted.withheld;
  const seenRefs = redacted.secrets.map((s) => s.ref);

  try {
    await db.transaction(async (trx) => {
      const now = new Date();
      for (const s of redacted!.secrets) {
        const enc = encrypt(s.value);
        await trx('learned_secrets')
          .insert({
            tenant_id: tenantId,
            site_id: device.site_id,
            device_id: device.id,
            capture_id: captureId,
            ref: s.ref,
            menu: s.menu.slice(0, 128),
            item: s.item === null ? null : s.item.slice(0, 128),
            prop: s.prop.slice(0, 64),
            secret_enc: enc,
            key_version: inspect(enc).keyVersion,
            fingerprint: learnedSecretFingerprint(tenantId, s.value),
            first_seen_at: now,
            last_seen_at: now,
            vanished_at: null,
          })
          .onConflict(['device_id', 'ref'])
          .merge([
            'site_id', 'capture_id', 'menu', 'item', 'prop', 'secret_enc', 'key_version', 'fingerprint',
            'last_seen_at', 'vanished_at',
          ]);
      }
      const vanish = trx('learned_secrets').where({ device_id: device.id }).whereNull('vanished_at');
      if (seenRefs.length > 0) void vanish.whereNotIn('ref', seenRefs);
      await vanish.update({ vanished_at: now });

      await trx('learning_captures').where({ id: captureId }).update({
        status: 'succeeded',
        reason: null,
        detail: null,
        redacted_gz: gzipSync(textBuf),
        redacted_sha256: sha256,
        redacted_bytes: textBuf.length,
        facts: JSON.stringify(facts),
        secret_count: secretCount,
        withheld: JSON.stringify(withheld),
        os_version: (preamble.osVersion ?? '').slice(0, 64) || null,
        model: (preamble.model ?? '').slice(0, 128) || null,
        finished_at: now,
      });

      // Keep the last LEARNING_CAPTURES_KEPT captures of this device.
      const keep = trx('learning_captures')
        .where({ device_id: device.id })
        .orderBy('started_at', 'desc')
        .orderBy('id', 'desc')
        .limit(LEARNING_CAPTURES_KEPT)
        .select('id');
      await trx('learning_captures')
        .where({ device_id: device.id })
        .whereNot('status', 'running')
        .whereNotIn('id', keep)
        .delete();
    });
  } finally {
    for (const s of redacted.secrets) s.value = '';
    scrub.length = 0;
  }

  // ── The observed state, through the unchanged no-secrets gate ──────────
  let snapshotId: string | null = null;
  let snapshotError: string | null = null;
  try {
    const stored = await storeSnapshotFromLearning({
      deviceId: device.id,
      tenantId,
      family,
      text: redacted.text,
      osVersion: preamble.osVersion,
      model: preamble.model,
    });
    snapshotId = stored.snapshotId;
  } catch (err) {
    snapshotError = (err instanceof Error ? err.message : String(err)).slice(0, 300);
    logger.warn({ tenantId, runId, deviceId: device.id, err: err instanceof Error ? { name: err.name } : null }, 'Learning capture: no snapshot from this capture');
  }
  await db('learning_captures').where({ id: captureId }).update({ snapshot_id: snapshotId, snapshot_error: snapshotError });

  try {
    await appendAudit({
      tenantId,
      actorType: 'user',
      actorId: actor.userId,
      actorName: actor.username,
      action: 'learning.capture',
      entityType: 'device',
      entityId: device.id,
      correlationId: runId,
      // Counts only. Field names clear of the audit's secret-name mask.
      after: {
        captureId,
        dialledAs: login.account,
        vaultedValues: secretCount,
        withheldLines: withheld.length,
        redactedBytes: textBuf.length,
        snapshotStored: snapshotId !== null,
      },
    });
  } catch (err) {
    logger.error({ tenantId, deviceId: device.id, err: err instanceof Error ? { name: err.name } : null }, 'Learning capture: the audit entry could not be written');
  }
}
