/**
 * ObliWAN — the daily backup retention pass: purge what has expired, and
 * re-verify a bounded sample of what is kept.
 *
 * `purgeExpiredBackups()` and `verifyStoredBackup()` (backup.service.ts) were
 * written and never called. So an expired blob stayed on disk for ever (a copy
 * of a customer's configuration kept past the retention it was taken under),
 * and a blob that went missing or rotted was discovered the night somebody
 * needed to restore it: "a backup nobody verified is a backup nobody has".
 *
 * ┌─ ONE PASS, ONCE A DAY, ON THE LEADER ────────────────────────────────────┐
 * │ 1. `purgeExpiredBackups()`: every `available` row whose `expires_at` has │
 * │    passed loses its file and becomes `purged` (the row stays).           │
 * │ 2. `verifyStoredBackup()` on at most `BACKUP_VERIFY_SAMPLE` `available`  │
 * │    rows, the ones verified longest ago first (never verified first of    │
 * │    all), so successive passes walk the whole store.                      │
 * │ A file that is gone (`missing`) or no longer matches its recorded digest │
 * │ or size (`failed`) is logged as an error AND raised as a live alert to   │
 * │ the backup's tenant, one per backup (stable key, deduplicated while      │
 * │ unread). verifyStoredBackup() has already moved the row out of           │
 * │ `available`, so the next pass does not raise it again.                   │
 * │ A file that is THERE and could not be read (`unreadable`: permissions,   │
 * │ an I/O error) is not a lost backup and is not called one: the row keeps  │
 * │ its status, the alert says "could not be read" under its own key, and    │
 * │ the row stays first in the next sample, so it is retried every pass.     │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Leader-gated: two replicas would hash the same files twice and race on
 * the same rows. The tick is hourly and a pass runs when the last pass this
 * process COMPLETED is more than a day old, so a new leader runs one within
 * the hour, and a pass that was refused or cut short (below) is tried again
 * at the next tick instead of a day later.
 *
 * NO STORE, NO PASS. A process whose backup root (`OBLIWAN_BACKUP_ROOT`) is not
 * a directory it can list — a replica started without the `change_backups`
 * volume, or a volume whose owner changed — would read every row as `missing`
 * or `unreadable` and "purge" files it cannot see. That is one deployment
 * fault, not N lost backups: the pass refuses, logs it, and touches no row.
 */

import fs from 'fs';
import fsp from 'fs/promises';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { isLeader as processIsLeader } from '../leaderElection';
import { liveAlertService } from '../liveAlert.service';
import { backupRoot, purgeExpiredBackups, verifyStoredBackup, type PurgeReport } from './backup.service';

/** Rows re-verified per pass. Each one is a full read and hash of its file. */
export const BACKUP_VERIFY_SAMPLE = 50;
/** How often the runtime looks whether a pass is due. */
export const BACKUP_RETENTION_TICK_MS = 60 * 60_000;
/** A pass is due when the last completed one on this process is older than this. */
export const BACKUP_RETENTION_PERIOD_MS = 24 * 60 * 60_000;
/** The first look after start: late enough to stay out of the boot. */
export const BACKUP_RETENTION_FIRST_DELAY_MS = 5 * 60_000;

/** What the verification found wrong with one stored backup. */
export type BackupIntegrityStatus = 'missing' | 'failed' | 'unreadable';

export interface BackupIntegrityFailure {
  backupId: number;
  tenantId: number;
  deviceId: number;
  /** `missing` / `failed`: the status `verifyStoredBackup()` left on the row.
   *  `unreadable`: the row's status was left unchanged. */
  status: BackupIntegrityStatus;
  reason: string;
  /** false when the live alert could not be written (it is logged). */
  alerted: boolean;
}

export interface BackupRetentionReport {
  /** false: this process is not the leader (or stopped being it mid-pass). */
  leader: boolean;
  /** true only when the pass purged and walked its whole sample. A refused
   *  pass (no store) or one cut short by a lost leadership is not complete,
   *  and the runtime tries again at its next tick. */
  completed: boolean;
  purge: PurgeReport | null;
  verified: number;
  verifiedOk: number;
  failures: BackupIntegrityFailure[];
  /** Errors of the pass itself (a query that failed), not of a backup. */
  errors: string[];
}

export interface BackupRetentionOptions {
  now?: Date;
  sampleSize?: number;
  /** Injected by a harness; the process's own leadership otherwise. */
  isLeader?: () => boolean;
}

/** The key one backup's missing/corrupt alert is deduplicated on. */
export function backupIntegrityAlertKey(backupId: number): string {
  return `backup-integrity:${backupId}`;
}

/** The key one backup's "could not be read" alert is deduplicated on. A key of
 *  its own, so that it never hides a later `missing` or `failed` finding. */
export function backupUnreadableAlertKey(backupId: number): string {
  return `backup-unreadable:${backupId}`;
}

type SampledRow = { id: number; tenant_id: number; device_id: number; kind: string; taken_at: Date | string };

function alertText(row: SampledRow, name: string, status: BackupIntegrityStatus): { title: string; message: string } {
  const taken = new Date(row.taken_at).toISOString();
  const what = `The ${row.kind} backup #${row.id} of ${name}, taken ${taken},`;
  switch (status) {
    case 'missing':
      return {
        title: `Backup #${row.id} of ${name}: file missing`,
        message:
          `${what} is no longer in the backup store: the daily verification found no file at its ` +
          "storage path. Its status is now 'missing'.",
      };
    case 'failed':
      return {
        title: `Backup #${row.id} of ${name}: file corrupt`,
        message:
          `${what} no longer matches the digest or size recorded when it was taken: the daily ` +
          "verification re-hashed it. Its status is now 'failed'.",
      };
    default:
      return {
        title: `Backup #${row.id} of ${name}: file unreadable`,
        message:
          `${what} could not be read by the daily verification: the file is in the backup store, ` +
          'but this server was refused or failed reading it (permissions or ownership on the backup ' +
          'volume, or an I/O error; the server log has the error code). It may be intact. Its status ' +
          'is unchanged and it is checked again at the next pass.',
      };
  }
}

async function raiseIntegrityAlert(row: SampledRow, status: BackupIntegrityStatus): Promise<boolean> {
  try {
    const device = (await db('devices').where({ id: row.device_id }).first('name')) as { name: string } | undefined;
    const name = device?.name ?? `device #${row.device_id}`;
    const { title, message } = alertText(row, name, status);
    await liveAlertService.add(row.tenant_id, {
      severity: status === 'unreadable' ? 'warning' : 'down',
      title,
      message,
      navigateTo: `/devices/${row.device_id}`,
      deviceId: row.device_id,
      stableKey: status === 'unreadable' ? backupUnreadableAlertKey(row.id) : backupIntegrityAlertKey(row.id),
    });
    return true;
  } catch (err) {
    logger.error(
      { err: err instanceof Error ? err.message : String(err), backupId: row.id },
      'backup retention: the integrity alert could not be written',
    );
    return false;
  }
}

/** A directory this process can list and enter; false on anything else. */
async function storeIsUsable(root: string): Promise<boolean> {
  try {
    if (!(await fsp.stat(root)).isDirectory()) return false;
    await fsp.access(root, fs.constants.R_OK | fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * One pass: purge, then verify a bounded sample. Never throws; what failed is
 * in the report and in the log.
 */
export async function runBackupRetentionPass(options: BackupRetentionOptions = {}): Promise<BackupRetentionReport> {
  const gate = options.isLeader ?? processIsLeader;
  const report: BackupRetentionReport = {
    leader: gate(),
    completed: false,
    purge: null,
    verified: 0,
    verifiedOk: 0,
    failures: [],
    errors: [],
  };
  if (!report.leader) return report;
  const now = options.now ?? new Date();
  const sampleSize = Math.max(0, Math.floor(options.sampleSize ?? BACKUP_VERIFY_SAMPLE));

  const root = backupRoot();
  if (!(await storeIsUsable(root))) {
    report.errors.push(`the backup root ${root} is not a directory this process can read`);
    logger.error(
      { root },
      'backup retention: the backup root is not a directory this process can read — nothing purged, ' +
        'nothing verified, no row touched (is the change_backups volume mounted here, and readable by ' +
        'this user?); tried again at the next tick',
    );
    return report;
  }

  try {
    report.purge = await purgeExpiredBackups(now);
    if (report.purge.errors.length > 0) {
      logger.error(
        { examined: report.purge.examined, purged: report.purge.purged, errors: report.purge.errors },
        'backup retention: some expired backups could not be purged; they stay available and are retried next pass',
      );
    }
  } catch (err) {
    report.errors.push(`purge: ${err instanceof Error ? err.message : String(err)}`);
    logger.error({ err }, 'backup retention: the purge failed');
  }

  let sample: SampledRow[] = [];
  try {
    sample = sampleSize === 0
      ? []
      : await db('device_backups')
        .where('status', 'available')
        .orderByRaw('verified_at ASC NULLS FIRST')
        .orderBy('id', 'asc')
        .limit(sampleSize)
        .select('id', 'tenant_id', 'device_id', 'kind', 'taken_at');
  } catch (err) {
    report.errors.push(`sample: ${err instanceof Error ? err.message : String(err)}`);
    logger.error({ err }, 'backup retention: the verification sample could not be read');
  }

  let cutShort = false;
  for (const raw of sample) {
    const row = { ...raw, id: Number(raw.id), tenant_id: Number(raw.tenant_id), device_id: Number(raw.device_id) };
    if (!gate()) {
      report.leader = false; // leadership lost mid-pass: the new leader carries on
      cutShort = true;
      break;
    }
    let result: Awaited<ReturnType<typeof verifyStoredBackup>>;
    try {
      result = await verifyStoredBackup(row.id);
    } catch (err) {
      // A database error: verifyStoredBackup() wrote no status.
      report.errors.push(`verify ${row.id}: ${err instanceof Error ? err.message : String(err)}`);
      logger.error({ err, backupId: row.id }, 'backup retention: the verification itself failed');
      continue;
    }
    if (result.outcome === 'no_such_backup') continue; // gone since the sample was read
    report.verified++;
    if (result.ok) {
      report.verifiedOk++;
      continue;
    }
    const status: BackupIntegrityStatus =
      result.outcome === 'failed' ? 'failed' : result.outcome === 'unreadable' ? 'unreadable' : 'missing';
    logger.error(
      { backupId: row.id, tenantId: row.tenant_id, deviceId: row.device_id, kind: row.kind, status, reason: result.reason },
      status === 'missing'
        ? 'backup retention: a stored backup file is MISSING'
        : status === 'failed'
          ? 'backup retention: a stored backup file is CORRUPT'
          : 'backup retention: a stored backup file could not be READ (status unchanged)',
    );
    const alerted = await raiseIntegrityAlert(row, status);
    report.failures.push({
      backupId: row.id,
      tenantId: row.tenant_id,
      deviceId: row.device_id,
      status,
      reason: result.reason,
      alerted,
    });
  }
  report.completed = !cutShort;

  logger.info(
    {
      purged: report.purge?.purged ?? null,
      purgeErrors: report.purge?.errors.length ?? null,
      verified: report.verified,
      verifiedOk: report.verifiedOk,
      failures: report.failures.length,
      errors: report.errors.length,
      completed: report.completed,
    },
    'backup retention pass done',
  );
  return report;
}

// ============================================================================
// The runtime
// ============================================================================

let tickTimer: NodeJS.Timeout | null = null;
let firstTimer: NodeJS.Timeout | null = null;
let running: Promise<unknown> | null = null;
let lastPassAt = 0;

export interface StartBackupRetentionOptions extends BackupRetentionOptions {
  tickMs?: number;
  periodMs?: number;
  firstDelayMs?: number;
}

/**
 * Arm the daily pass on this process. Every process may call it: a tick on a
 * process that is not the leader does nothing. Idempotent.
 */
export function startBackupRetentionRuntime(options: StartBackupRetentionOptions = {}): void {
  if (tickTimer) return;
  const gate = options.isLeader ?? processIsLeader;
  const periodMs = Math.max(1, options.periodMs ?? BACKUP_RETENTION_PERIOD_MS);
  const tick = (): void => {
    if (running || !gate()) return;
    if (lastPassAt !== 0 && Date.now() - lastPassAt < periodMs) return;
    const startedAt = Date.now();
    running = runBackupRetentionPass({ ...options, isLeader: gate })
      .then((report) => {
        // Only a COMPLETED pass starts the day: a refused or cut-short one is
        // tried again at the next tick.
        if (report.completed) lastPassAt = startedAt;
      })
      .catch((err: unknown) => {
        logger.error({ err }, 'backup retention pass failed');
      })
      .finally(() => {
        running = null;
      });
  };
  tickTimer = setInterval(tick, Math.max(10, options.tickMs ?? BACKUP_RETENTION_TICK_MS));
  tickTimer.unref?.();
  firstTimer = setTimeout(tick, Math.max(0, options.firstDelayMs ?? BACKUP_RETENTION_FIRST_DELAY_MS));
  firstTimer.unref?.();
  logger.info(
    { periodMs, sample: options.sampleSize ?? BACKUP_VERIFY_SAMPLE },
    'Backup retention armed (leader-only; purge expired, verify a bounded sample, daily)',
  );
}

/** Disarm, and wait for a pass in flight so it cannot write after shutdown. */
export async function stopBackupRetentionRuntime(): Promise<void> {
  if (tickTimer) clearInterval(tickTimer);
  if (firstTimer) clearTimeout(firstTimer);
  tickTimer = null;
  firstTimer = null;
  // After the pass in flight, which may still record its completion.
  if (running) await running.catch(() => undefined);
  lastPassAt = 0;
}
