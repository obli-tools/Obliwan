/**
 * ObliWAN — the data retention pass: the three `*_retention_days` settings.
 *
 * They were shown in Settings and read by nothing, so nothing was ever
 * removed: configuration snapshots and both audit tables grew for ever, and the
 * 5-minute time-series tier kept the 90 days a migration had written whatever
 * an operator typed. One pass, once a day, on the leader:
 *
 * ┌─ TIME SERIES (`timeseries_retention_days`, platform-wide) ───────────────┐
 * │ NOT a DELETE. The series tables are partitioned and their retention is   │
 * │ DATA — `series_partition_policy.retention`, which the hourly partition    │
 * │ maintenance turns into DETACH + DROP of whole partitions (partition.     │
 * │ service.ts says, with numbers, why a DELETE there is never acceptable).   │
 * │ So the setting is synced INTO that row for the two 5-minute tiers, here   │
 * │ and at the top of every hourly maintenance run, and the existing machinery│
 * │ does the dropping. Raw samples, 1-minute and hourly rollups keep the     │
 * │ retention the storage study fixed (see the setting's description).       │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ CONFIGURATION SNAPSHOTS (`config_retention_days`, per device) ──────────┐
 * │ A snapshot is removed when it was last OBSERVED (`last_seen_at`, not      │
 * │ `captured_at`: a router whose configuration has not changed for two      │
 * │ years has one snapshot, captured two years ago and seen this morning)     │
 * │ longer ago than its device's retention, and NONE of these holds:          │
 * │   - it is the device's CURRENT snapshot (greatest last_seen_at, then id —│
 * │     the definition the query engine uses, migration 012). Whatever its   │
 * │     age: it is the device's configuration;                                │
 * │   - a change plan names it (the evidence a plan was computed against; the│
 * │     plan is frozen, and its trigger would refuse the FK's SET NULL);     │
 * │   - an intervention names it, before or after (a human's evidence);      │
 * │   - a drift run that FOUND something names it (a finding's evidence).    │
 * │ What goes WITH a removed snapshot is what its FKs declare to be its own  │
 * │ (ON DELETE CASCADE): the flattened NCM cache rows and the policy results │
 * │ evaluated against that configuration. What survives it is what they     │
 * │ declare independent (SET NULL): a drift run with no findings, a baseline │
 * │ membership and a bench conformity check — the last two written for       │
 * │ exactly this (migrations 017 and 049).                                    │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ AUDIT (`audit_retention_days`, per workspace, never under 400 days) ────┐
 * │ `audit_log` is a per-tenant hash chain, and its trigger only lets a row  │
 * │ go from the OLDEST end, and only past 400 days; `command_audit` likewise │
 * │ refuses anything younger. So: the cutoff is never under 400 days (the    │
 * │ setting's floor says so), it is computed by the DATABASE's clock — the   │
 * │ one the triggers judge by — and the ledger is truncated oldest first,     │
 * │ one row per statement, never its newest row: the tail is what the next   │
 * │ append chains onto, and a tenant whose whole ledger is old must not have │
 * │ its chain restarted at seq 1 with no predecessor.                         │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ HISTORIES (`event_history_retention_days` 365, `run_history_retention_  ┐
 * │ days` 180, platform-wide; notification log a fixed 30 days)               │
 * │ Append-only event histories and finished run/job records, by age, each   │
 * │ table with its own "never this row" rule: the latest row a state is      │
 * │ derived from, rows named as evidence, anything still running. See the    │
 * │ `HISTORY_RULES` below, one comment per table.                            │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * BATCHED, AND STOPPABLE. Every delete is a bounded batch in its own short
 * transaction, leadership is re-checked between batches, and a pass deletes at
 * most `maxBatches` batches per table: a first run on a two-year backlog
 * finishes over several days instead of holding locks for an hour. Every count
 * is logged. A failure in one part is logged and does not stop the others.
 */

import { SETTINGS_KEYS } from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { isLeader as processIsLeader } from '../leaderElection';
import { deviceSettingNumbers, platformSettingNumber, tenantSettingNumber } from '../settingsRead';

/** The two partitioned parents the time-series setting governs. */
export const TIMESERIES_RETENTION_TIERS = ['snmp_if_rollup_5m', 'snmp_device_rollup_5m'] as const;

/** `audit_log` and `command_audit` refuse to delete a row younger than this
 *  (AUDIT_IMMUTABLE_DAYS in migrations 009 and 019). */
export const AUDIT_IMMUTABLE_DAYS = 400;

export const RETENTION_BATCH_SIZE = 500;
export const RETENTION_MAX_BATCHES = 200;
export const RETENTION_TICK_MS = 60 * 60_000;
export const RETENTION_PERIOD_MS = 24 * 60 * 60_000;
export const RETENTION_FIRST_DELAY_MS = 10 * 60_000;

export interface RetentionOptions {
  /** Injected by a harness; the process's own leadership otherwise. */
  isLeader?: () => boolean;
  batchSize?: number;
  maxBatches?: number;
}

export interface TimeseriesRetentionResult {
  days: number;
  /** Parents whose policy row was changed by this call. */
  updated: string[];
}

export interface ConfigPurgeResult {
  devices: number;
  deleted: number;
  /** True when a device still had candidates after `maxBatches`. */
  truncated: boolean;
}

export interface AuditPurgeResult {
  tenants: number;
  auditLogDeleted: number;
  commandAuditDeleted: number;
  truncated: boolean;
}

export interface HistoryPurgeResult {
  eventDays: number;
  runDays: number;
  /** Rows removed, per table (tables with nothing to remove are absent). */
  deleted: Record<string, number>;
  /** True when a table still had candidates after `maxBatches`. */
  truncated: boolean;
  /** Tables whose purge failed (the others still ran). */
  errors: string[];
}

export interface RetentionReport {
  leader: boolean;
  completed: boolean;
  timeseries: TimeseriesRetentionResult | null;
  config: ConfigPurgeResult | null;
  audit: AuditPurgeResult | null;
  history: HistoryPurgeResult | null;
  errors: string[];
}

class LeadershipLost extends Error {}

function limits(options: RetentionOptions): { gate: () => boolean; batch: number; maxBatches: number } {
  return {
    gate: options.isLeader ?? processIsLeader,
    batch: Math.max(1, Math.floor(options.batchSize ?? RETENTION_BATCH_SIZE)),
    maxBatches: Math.max(1, Math.floor(options.maxBatches ?? RETENTION_MAX_BATCHES)),
  };
}

// ============================================================================
// Time series — sync the setting into the partition policy
// ============================================================================

/**
 * Write the `timeseries_retention_days` setting into the policy rows of the
 * 5-minute tiers. Idempotent: rows already at the value are not touched. The
 * hourly partition maintenance calls it before it drops, so a change takes
 * effect within the hour.
 */
export async function syncTimeseriesRetention(): Promise<TimeseriesRetentionResult> {
  const { value: days } = await platformSettingNumber(SETTINGS_KEYS.TIMESERIES_RETENTION_DAYS);
  const rows = (await db('series_partition_policy')
    .whereIn('parent', [...TIMESERIES_RETENTION_TIERS])
    .whereRaw('retention <> make_interval(days => ?)', [days])
    .update({ retention: db.raw('make_interval(days => ?)', [days]) })
    .returning('parent')) as Array<{ parent: string } | string>;
  const updated = rows.map((r) => (typeof r === 'string' ? r : r.parent));
  if (updated.length > 0) {
    logger.info({ days, parents: updated }, 'retention: 5-minute time-series retention set from the setting');
  }
  return { days, updated };
}

// ============================================================================
// Configuration snapshots
// ============================================================================

/**
 * The snapshots of ONE device that may go: older than the cutoff, not the
 * device's current one, and named by nothing that is evidence (see header).
 * Used as the sub-select of the DELETE, so the predicate is judged on the rows
 * as they are locked, not as they were listed.
 */
const PURGEABLE_SNAPSHOTS_SQL = `
  SELECT s.id
    FROM config_snapshots s
   WHERE s.device_id = ?
     AND s.last_seen_at < now() - make_interval(days => ?)
     AND s.id <> (SELECT c.id FROM config_snapshots c
                   WHERE c.device_id = s.device_id
                   ORDER BY c.last_seen_at DESC, c.id DESC
                   LIMIT 1)
     AND NOT EXISTS (SELECT 1 FROM change_plans p WHERE p.snapshot_id = s.id)
     AND NOT EXISTS (SELECT 1 FROM interventions i
                      WHERE i.snapshot_before_id = s.id OR i.snapshot_after_id = s.id)
     AND NOT EXISTS (SELECT 1 FROM drift_runs r
                      WHERE r.snapshot_id = s.id
                        AND (r.findings_count > 0
                             OR EXISTS (SELECT 1 FROM drift_findings f WHERE f.run_id = r.id)))
   ORDER BY s.id
   LIMIT ?
   FOR UPDATE OF s SKIP LOCKED`;

export async function purgeConfigSnapshots(options: RetentionOptions = {}): Promise<ConfigPurgeResult> {
  const { gate, batch, maxBatches } = limits(options);
  const out: ConfigPurgeResult = { devices: 0, deleted: 0, truncated: false };

  // Devices with at least one snapshot older than the SHORTEST retention any
  // device can have (the definition's floor, 1 day) — the only ones that can
  // possibly have something to remove. Their own retention is resolved next.
  const devices = (await db.raw(
    `SELECT d.id, d.tenant_id, d.group_id
       FROM devices d
      WHERE EXISTS (SELECT 1 FROM config_snapshots s
                     WHERE s.device_id = d.id AND s.last_seen_at < now() - interval '1 day')
      ORDER BY d.id`,
  )) as { rows: Array<{ id: number; tenant_id: number; group_id: number | null }> };

  for (const device of devices.rows ?? []) {
    if (!gate()) throw new LeadershipLost();
    const s = await deviceSettingNumbers(device.tenant_id, device.id, device.group_id, [
      SETTINGS_KEYS.CONFIG_RETENTION_DAYS,
    ]);
    const days = s[SETTINGS_KEYS.CONFIG_RETENTION_DAYS].value;

    let deletedHere = 0;
    for (let i = 0; i < maxBatches; i++) {
      if (!gate()) throw new LeadershipLost();
      const res = (await db.raw(
        `DELETE FROM config_snapshots WHERE id IN (${PURGEABLE_SNAPSHOTS_SQL}) RETURNING id`,
        [device.id, days, batch],
      )) as { rows: unknown[] };
      const n = res.rows?.length ?? 0;
      deletedHere += n;
      if (n < batch) break;
      if (i === maxBatches - 1) out.truncated = true;
    }
    if (deletedHere > 0) {
      out.devices++;
      out.deleted += deletedHere;
      logger.info(
        { deviceId: device.id, tenantId: device.tenant_id, retentionDays: days, deleted: deletedHere },
        'retention: superseded configuration snapshots removed',
      );
    }
  }
  return out;
}

// ============================================================================
// Audit
// ============================================================================

/** A tenant's audit retention, never under the database's floor. */
async function auditRetentionDays(tenantId: number): Promise<number> {
  const { value } = await tenantSettingNumber(tenantId, SETTINGS_KEYS.AUDIT_RETENTION_DAYS);
  return Math.max(AUDIT_IMMUTABLE_DAYS, value);
}

export async function purgeAudit(options: RetentionOptions = {}): Promise<AuditPurgeResult> {
  const { gate, batch, maxBatches } = limits(options);
  const out: AuditPurgeResult = { tenants: 0, auditLogDeleted: 0, commandAuditDeleted: 0, truncated: false };

  // Only tenants holding something past the floor can have anything to drop.
  const tenants = (await db.raw(
    `SELECT tenant_id FROM audit_log
      WHERE occurred_at < now() - make_interval(days => ?)
     UNION
     SELECT tenant_id FROM command_audit
      WHERE executed_at < now() - make_interval(days => ?)`,
    [AUDIT_IMMUTABLE_DAYS, AUDIT_IMMUTABLE_DAYS],
  )) as { rows: Array<{ tenant_id: number }> };

  for (const { tenant_id: tenantId } of tenants.rows ?? []) {
    if (!gate()) throw new LeadershipLost();
    const days = await auditRetentionDays(tenantId);
    let ledger = 0;
    let commands = 0;

    // command_audit: append-only, no chain, no FK onto it. Plain batches.
    for (let i = 0; i < maxBatches; i++) {
      if (!gate()) throw new LeadershipLost();
      const res = (await db.raw(
        `DELETE FROM command_audit WHERE id IN (
           SELECT id FROM command_audit
            WHERE tenant_id = ? AND executed_at < now() - make_interval(days => ?)
            ORDER BY id
            LIMIT ?)
         RETURNING id`,
        [tenantId, days, batch],
      )) as { rows: unknown[] };
      const n = res.rows?.length ?? 0;
      commands += n;
      if (n < batch) break;
      if (i === maxBatches - 1) out.truncated = true;
    }

    // audit_log: the chain. ONE row per statement, the oldest, so the
    // trigger's "nothing older remains" holds for every row it judges —
    // a multi-row DELETE visits rows in no guaranteed order. Never the newest
    // row of the tenant (see the header). A batch is one transaction.
    for (let i = 0; i < maxBatches; i++) {
      if (!gate()) throw new LeadershipLost();
      const n = await db.transaction(async (trx) => {
        let removed = 0;
        for (let k = 0; k < batch; k++) {
          const res = (await trx.raw(
            `DELETE FROM audit_log
              WHERE id = (SELECT id FROM audit_log WHERE tenant_id = ? ORDER BY seq ASC LIMIT 1)
                AND occurred_at < now() - make_interval(days => ?)
                AND seq < (SELECT max(seq) FROM audit_log WHERE tenant_id = ?)
              RETURNING id`,
            [tenantId, days, tenantId],
          )) as { rows: unknown[] };
          if ((res.rows?.length ?? 0) === 0) break;
          removed++;
        }
        return removed;
      });
      ledger += n;
      if (n < batch) break;
      if (i === maxBatches - 1) out.truncated = true;
    }

    if (ledger > 0 || commands > 0) {
      out.tenants++;
      out.auditLogDeleted += ledger;
      out.commandAuditDeleted += commands;
      logger.info(
        { tenantId, retentionDays: days, auditLogDeleted: ledger, commandAuditDeleted: commands },
        'retention: audit entries past their retention removed',
      );
    }
  }
  return out;
}

// ============================================================================
// Event and run histories
// ============================================================================
//
// Append-only histories and finished run/job records, removed by age under the
// two platform-wide settings `event_history_retention_days` (365) and
// `run_history_retention_days` (180); the notification delivery log under a
// fixed 30 days. None of these tables is partitioned (the partitioned ones are
// `partition.service.ts`'s, never a DELETE). Each rule below was written from
// the table's migration and its readers, and keeps, whatever its age:
//   - the LATEST row a current state is derived from (the "last verdict", the
//     "last away/back", the newest identity observation, the latest render,
//     the latest run/job of a device), so a quiet device keeps its state;
//   - every row another record names as EVIDENCE (an incident member's event,
//     a plan's render, a drift run's render, an intervention's drift run, a
//     drift run with findings or an attribution, a promoted baseline draft);
//   - everything still running (open CWMP session, unfinished sync run or
//     change job, open intervention, pending/running baseline run).
// What goes WITH a removed row is what its FKs declare to be its own (ON
// DELETE CASCADE), nothing else.
//
// Deliberately NOT purged (see the report of the change that added this):
// `apply_outcomes` (the cross-tenant safety corpus, migration 009 decision 5),
// `concentrator_secret_reads` (one row per CHR, a decision input, not a
// history).

/** The notification delivery log. Fixed: a debugging aid, not a record. */
export const NOTIFICATION_LOG_RETENTION_DAYS = 30;

type HistoryHorizon = 'notification' | 'event' | 'run';

interface HistoryRule {
  table: string;
  horizon: HistoryHorizon;
  /**
   * A SELECT of the ids that may go, aliased on the table, whose first
   * binding is the retention in days and last the batch size. Locked with
   * SKIP LOCKED so a row being written is left for the next pass. Literals
   * only besides the two bindings (knex reads a bare question mark in raw SQL
   * as a binding).
   */
  select: string;
  /** How many times the retention in days is bound before the batch size
   *  (default 1). */
  dayBindings?: number;
  /** Smaller batches for a parent with a large cascade. */
  batch?: number;
}

const HISTORY_RULES: readonly HistoryRule[] = [
  {
    table: 'notification_log',
    horizon: 'notification',
    select: `
      SELECT n.id FROM notification_log n
       WHERE n.created_at < now() - make_interval(days => ?)
       LIMIT ? FOR UPDATE OF n SKIP LOCKED`,
  },
  {
    // A CHANGE log (written only on change): the newest row of a device IS
    // its current verdict, whatever its age. Superseded rows only.
    table: 'reachability_verdicts',
    horizon: 'event',
    select: `
      SELECT v.id FROM reachability_verdicts v
       WHERE v.ts < now() - make_interval(days => ?)
         AND EXISTS (SELECT 1 FROM reachability_verdicts n
                      WHERE n.device_id = v.device_id
                        AND (n.ts > v.ts OR (n.ts = v.ts AND n.id > v.id)))
       LIMIT ? FOR UPDATE OF v SKIP LOCKED`,
  },
  {
    // `lastAwayAsnOf` reads the newest away/back of a device: kept, with all
    // that follows it. An event an incident member names is that incident's
    // evidence (operator_incident_members.event_id): kept.
    table: 'wan_path_events',
    horizon: 'event',
    select: `
      SELECT e.id FROM wan_path_events e
       WHERE e.at < now() - make_interval(days => ?)
         AND NOT EXISTS (SELECT 1 FROM operator_incident_members m WHERE m.event_id = e.id)
         AND EXISTS (SELECT 1 FROM wan_path_events n
                      WHERE n.tenant_id = e.tenant_id AND n.device_id = e.device_id
                        AND n.direction IN ('away', 'back')
                        AND (n.at > e.at OR (n.at = e.at AND n.id > e.id)))
       LIMIT ? FOR UPDATE OF e SKIP LOCKED`,
  },
  {
    // Before the observations (an event CASCADEs from its observation).
    // Kept: an unacknowledged baseline-invalidating event (the open question
    // `baselineTrust` asks), and any event at or after the capture of the
    // device's newest configuration snapshot (what `baselineTrust` reads).
    table: 'device_identity_events',
    horizon: 'event',
    select: `
      SELECT e.id FROM device_identity_events e
       WHERE e.detected_at < now() - make_interval(days => ?)
         AND NOT (e.acknowledged_at IS NULL AND e.invalidates_baseline)
         AND e.detected_at < COALESCE(
               (SELECT max(c.captured_at) FROM config_snapshots c WHERE c.device_id = e.device_id),
               'infinity'::timestamptz)
       LIMIT ? FOR UPDATE OF e SKIP LOCKED`,
  },
  {
    // Compressed history: the newest row of a device is what the next
    // observation is compared to (and bumped), and the newest row carrying an
    // OS version is what the upgrade screen reads. Never one an event still
    // names (the FK would CASCADE the event), nor the reference's pointer.
    table: 'device_identity_observations',
    horizon: 'event',
    select: `
      SELECT o.id FROM device_identity_observations o
       WHERE o.last_seen_at < now() - make_interval(days => ?)
         AND EXISTS (SELECT 1 FROM device_identity_observations n
                      WHERE n.tenant_id = o.tenant_id AND n.device_id = o.device_id AND n.id > o.id)
         AND (o.os_version IS NULL
              OR EXISTS (SELECT 1 FROM device_identity_observations n
                          WHERE n.tenant_id = o.tenant_id AND n.device_id = o.device_id
                            AND n.id > o.id AND n.os_version IS NOT NULL))
         AND NOT EXISTS (SELECT 1 FROM device_identity_events e WHERE e.observation_id = o.id)
         AND NOT EXISTS (SELECT 1 FROM device_identity_reference r
                          WHERE r.device_id = o.device_id AND r.last_observation_id = o.id)
       LIMIT ? FOR UPDATE OF o SKIP LOCKED`,
  },
  {
    // Pruned per device at insert after 90 days (backup4g.service); this
    // catches the devices whose route never moved again.
    table: 'device_route_transitions',
    horizon: 'event',
    select: `
      SELECT t.id FROM device_route_transitions t
       WHERE t.at < now() - make_interval(days => ?)
       LIMIT ? FOR UPDATE OF t SKIP LOCKED`,
  },
  {
    // Only once the intervention itself is settled: an open window keeps
    // its whole lifecycle log. The intervention row keeps its own status and
    // timestamps (and its drift links, which are not touched here).
    table: 'intervention_events',
    horizon: 'event',
    select: `
      SELECT ev.id FROM intervention_events ev
       WHERE ev.at < now() - make_interval(days => ?)
         AND EXISTS (SELECT 1 FROM interventions i
                      WHERE i.id = ev.intervention_id AND i.tenant_id = ev.tenant_id
                        AND i.status <> 'open')
       LIMIT ? FOR UPDATE OF ev SKIP LOCKED`,
  },
  {
    // Written only on change: the newest sample of a (line, zone) is kept.
    table: 'sim_balance_samples',
    horizon: 'event',
    select: `
      SELECT s.id FROM sim_balance_samples s
       WHERE s.observed_at < now() - make_interval(days => ?)
         AND EXISTS (SELECT 1 FROM sim_balance_samples n
                      WHERE n.sim_id = s.sim_id AND n.zone = s.zone AND n.observed_at > s.observed_at)
       LIMIT ? FOR UPDATE OF s SKIP LOCKED`,
  },
  {
    // Finished sweeps only, and never an account's latest finished one (the
    // "why is this balance stale" answer).
    table: 'sim_sync_runs',
    horizon: 'event',
    select: `
      SELECT r.id FROM sim_sync_runs r
       WHERE r.started_at < now() - make_interval(days => ?)
         AND r.finished_at IS NOT NULL
         AND EXISTS (SELECT 1 FROM sim_sync_runs n
                      WHERE n.account_id = r.account_id AND n.finished_at IS NOT NULL AND n.id > r.id)
       LIMIT ? FOR UPDATE OF r SKIP LOCKED`,
  },
  {
    // Closed or abandoned sessions only (an open one carries in-flight work).
    table: 'cwmp_sessions',
    horizon: 'event',
    select: `
      SELECT s.id FROM cwmp_sessions s
       WHERE s.state <> 'open'
         AND s.last_seen_at < now() - make_interval(days => ?)
       LIMIT ? FOR UPDATE OF s SKIP LOCKED`,
  },
  {
    // A drift run that found nothing, attributed nothing, is named by no
    // intervention, and is not the device's latest run (the scheduler's
    // "last run"). A run with findings is evidence and is never removed here.
    table: 'drift_runs',
    horizon: 'run',
    select: `
      SELECT r.id FROM drift_runs r
       WHERE r.findings_count = 0
         AND r.started_at < now() - make_interval(days => ?)
         AND r.finished_at IS NOT NULL
         AND NOT EXISTS (SELECT 1 FROM drift_findings f WHERE f.run_id = r.id)
         AND NOT EXISTS (SELECT 1 FROM drift_attributions a WHERE a.run_id = r.id)
         AND NOT EXISTS (SELECT 1 FROM interventions i WHERE i.drift_run_id = r.id)
         AND NOT EXISTS (SELECT 1 FROM intervention_drift_links l WHERE l.drift_run_id = r.id)
         AND EXISTS (SELECT 1 FROM drift_runs n
                      WHERE n.device_id = r.device_id
                        AND (n.started_at > r.started_at OR (n.started_at = r.started_at AND n.id > r.id)))
       LIMIT ? FOR UPDATE OF r SKIP LOCKED`,
  },
  {
    // The step trace of a FINISHED job (finished_at is set exactly for the
    // terminal statuses, migration 009), and never of the latest job of its
    // kind on its device: the management-access, APN, compliance and link
    // screens show that job's steps. The job row itself stays.
    table: 'change_job_steps',
    horizon: 'run',
    dayBindings: 2,
    select: `
      SELECT s.id FROM change_job_steps s
        JOIN change_jobs j ON j.id = s.job_id
       WHERE s.created_at < now() - make_interval(days => ?)
         AND j.finished_at IS NOT NULL
         AND j.finished_at < now() - make_interval(days => ?)
         AND EXISTS (SELECT 1 FROM change_jobs n
                      WHERE n.tenant_id = j.tenant_id AND n.device_id = j.device_id
                        AND n.kind = j.kind AND n.id > j.id)
       LIMIT ? FOR UPDATE OF s SKIP LOCKED`,
  },
  {
    // A settled mining run that produced no draft anyone kept (a promoted
    // draft is the provenance of a template revision; a draft still under
    // review is pending work) and that a newer successful run has superseded.
    // Its clusters, slots, deviations and conformance go with it (CASCADE);
    // `baseline_exceptions` are not keyed to a run and survive.
    table: 'baseline_runs',
    horizon: 'run',
    batch: 10,
    select: `
      SELECT b.id FROM baseline_runs b
       WHERE b.created_at < now() - make_interval(days => ?)
         AND b.status IN ('succeeded', 'failed', 'cancelled')
         AND NOT EXISTS (SELECT 1 FROM baseline_drafts d
                          WHERE d.run_id = b.id AND d.tenant_id = b.tenant_id AND d.status <> 'discarded')
         AND EXISTS (SELECT 1 FROM baseline_runs n
                      WHERE n.tenant_id = b.tenant_id AND n.status = 'succeeded' AND n.id > b.id)
       LIMIT ? FOR UPDATE OF b SKIP LOCKED`,
  },
  {
    // After drift_runs. Never a render a plan names (the plan is frozen: its
    // trigger refuses the FK's SET NULL), nor one a drift run names (its
    // desired side), nor the device's latest successful render (`latestRender`).
    table: 'config_renders',
    horizon: 'run',
    select: `
      SELECT c.id FROM config_renders c
       WHERE c.rendered_at < now() - make_interval(days => ?)
         AND NOT EXISTS (SELECT 1 FROM change_plans p WHERE p.render_id = c.id)
         AND NOT EXISTS (SELECT 1 FROM drift_runs r WHERE r.render_id = c.id)
         AND EXISTS (SELECT 1 FROM config_renders n
                      WHERE n.tenant_id = c.tenant_id AND n.device_id = c.device_id AND n.status = 'ok'
                        AND (n.rendered_at > c.rendered_at OR (n.rendered_at = c.rendered_at AND n.id > c.id)))
       LIMIT ? FOR UPDATE OF c SKIP LOCKED`,
  },
  {
    // The quarantine: only rows nobody decided on (`pending`) that the CHR
    // has stopped announcing. `bound` and `ignored` are operator decisions
    // and stay; a username that comes back is simply discovered again.
    table: 'discoveries',
    horizon: 'run',
    select: `
      SELECT d.id FROM discoveries d
       WHERE d.state = 'pending'
         AND d.last_seen_at < now() - make_interval(days => ?)
       LIMIT ? FOR UPDATE OF d SKIP LOCKED`,
  },
];

export async function purgeHistories(options: RetentionOptions = {}): Promise<HistoryPurgeResult> {
  const { gate, batch, maxBatches } = limits(options);
  const { value: eventDays } = await platformSettingNumber(SETTINGS_KEYS.EVENT_HISTORY_RETENTION_DAYS);
  const { value: runDays } = await platformSettingNumber(SETTINGS_KEYS.RUN_HISTORY_RETENTION_DAYS);
  const daysFor: Record<HistoryHorizon, number> = {
    notification: NOTIFICATION_LOG_RETENTION_DAYS,
    event: eventDays,
    run: runDays,
  };
  const out: HistoryPurgeResult = { eventDays, runDays, deleted: {}, truncated: false, errors: [] };

  for (const rule of HISTORY_RULES) {
    if (!gate()) throw new LeadershipLost();
    const size = Math.max(1, Math.min(batch, rule.batch ?? batch));
    const days = daysFor[rule.horizon];
    const bindings = [...Array<number>(rule.dayBindings ?? 1).fill(days), size];
    let removed = 0;
    try {
      for (let i = 0; i < maxBatches; i++) {
        if (!gate()) throw new LeadershipLost();
        const res = (await db.raw(
          `DELETE FROM ${rule.table} WHERE id IN (${rule.select})`,
          bindings,
        )) as { rowCount?: number | null };
        const n = Number(res.rowCount ?? 0);
        removed += n;
        if (n < size) break;
        if (i === maxBatches - 1) out.truncated = true;
      }
    } catch (err) {
      if (err instanceof LeadershipLost) throw err;
      // One table failing never skips the others; the pass reports it.
      out.errors.push(`${rule.table}: ${err instanceof Error ? err.message : String(err)}`);
      logger.error({ err, table: rule.table }, 'retention: history purge of one table failed; the others ran');
    } finally {
      if (removed > 0) {
        out.deleted[rule.table] = removed;
        logger.info({ table: rule.table, retentionDays: days, deleted: removed }, 'retention: history rows removed');
      }
    }
  }
  return out;
}

// ============================================================================
// The pass
// ============================================================================

/** One pass. Never throws; what failed is in the report and in the log. */
export async function runDataRetentionPass(options: RetentionOptions = {}): Promise<RetentionReport> {
  const gate = options.isLeader ?? processIsLeader;
  const report: RetentionReport = {
    leader: gate(),
    completed: false,
    timeseries: null,
    config: null,
    audit: null,
    history: null,
    errors: [],
  };
  if (!report.leader) return report;

  const part = async <T>(name: string, fn: () => Promise<T>): Promise<T | null> => {
    try {
      return await fn();
    } catch (err) {
      if (err instanceof LeadershipLost) throw err;
      report.errors.push(`${name}: ${err instanceof Error ? err.message : String(err)}`);
      logger.error({ err }, `retention: the ${name} part failed; the others ran`);
      return null;
    }
  };

  try {
    report.timeseries = await part('timeseries', () => syncTimeseriesRetention());
    report.config = await part('config', () => purgeConfigSnapshots({ ...options, isLeader: gate }));
    report.audit = await part('audit', () => purgeAudit({ ...options, isLeader: gate }));
    report.history = await part('history', () => purgeHistories({ ...options, isLeader: gate }));
    for (const e of report.history?.errors ?? []) report.errors.push(`history ${e}`);
    report.completed = report.errors.length === 0;
  } catch (err) {
    if (!(err instanceof LeadershipLost)) throw err;
    report.leader = false; // the new leader carries on
  }

  logger.info(
    {
      timeseriesDays: report.timeseries?.days ?? null,
      configDeleted: report.config?.deleted ?? null,
      auditLogDeleted: report.audit?.auditLogDeleted ?? null,
      commandAuditDeleted: report.audit?.commandAuditDeleted ?? null,
      historyDeleted: report.history?.deleted ?? null,
      truncated: Boolean(report.config?.truncated || report.audit?.truncated || report.history?.truncated),
      errors: report.errors.length,
      completed: report.completed,
    },
    'data retention pass done',
  );
  return report;
}

// ============================================================================
// The runtime — same shape as the backup retention runtime
// ============================================================================

let tickTimer: NodeJS.Timeout | null = null;
let firstTimer: NodeJS.Timeout | null = null;
let running: Promise<unknown> | null = null;
let lastPassAt = 0;

export interface StartRetentionOptions extends RetentionOptions {
  tickMs?: number;
  periodMs?: number;
  firstDelayMs?: number;
}

/**
 * Arm the daily pass on this process. Every process may call it: a tick on a
 * process that is not the leader does nothing. A pass that did not complete
 * (an error, a lost leadership, a backlog cut at `maxBatches`) is tried again
 * at the next hourly tick rather than a day later. Idempotent.
 */
export function startDataRetentionRuntime(options: StartRetentionOptions = {}): void {
  if (tickTimer) return;
  const gate = options.isLeader ?? processIsLeader;
  const periodMs = Math.max(1, options.periodMs ?? RETENTION_PERIOD_MS);
  const tick = (): void => {
    if (running || !gate()) return;
    if (lastPassAt !== 0 && Date.now() - lastPassAt < periodMs) return;
    const startedAt = Date.now();
    running = runDataRetentionPass({ ...options, isLeader: gate })
      .then((report) => {
        const backlog = Boolean(report.config?.truncated || report.audit?.truncated || report.history?.truncated);
        if (report.completed && !backlog) lastPassAt = startedAt;
      })
      .catch((err: unknown) => {
        logger.error({ err }, 'data retention pass failed');
      })
      .finally(() => {
        running = null;
      });
  };
  tickTimer = setInterval(tick, Math.max(10, options.tickMs ?? RETENTION_TICK_MS));
  tickTimer.unref?.();
  firstTimer = setTimeout(tick, Math.max(0, options.firstDelayMs ?? RETENTION_FIRST_DELAY_MS));
  firstTimer.unref?.();
  logger.info(
    { periodMs },
    'Data retention armed (leader-only; config snapshots, audit, time-series policy, event/run histories; daily)',
  );
}

/** Disarm, and wait for a pass in flight so it cannot write after shutdown. */
export async function stopDataRetentionRuntime(): Promise<void> {
  if (tickTimer) clearInterval(tickTimer);
  if (firstTimer) clearTimeout(firstTimer);
  tickTimer = null;
  firstTimer = null;
  if (running) await running.catch(() => undefined);
  lastPassAt = 0;
}
