import type { Knex } from 'knex';

/**
 * Migration 078 — indexes for the event / run history purge
 * (`services/retention/dataRetention.service.ts`, `HISTORY_RULES`).
 *
 * 1. The AGE column of each purged table, where no index led on it (the
 *    existing ones lead on tenant or device, which a fleet-wide "older than N
 *    days" scan cannot use). Partial where the purge only ever looks at part of
 *    the table.
 *
 * 2. The columns that REFERENCE a purged table and are tested by the purge's
 *    "is it still named as evidence" clause, or walked by PostgreSQL itself on
 *    each deletion (SET NULL / CASCADE), and had no index leading on them.
 *
 * Already covered, so not repeated here: notification_log (created_at),
 * baseline_runs (tenant_id, status, created_at), drift_findings (run_id, ...),
 * drift_attributions (run_id UNIQUE), device_identity_events (observation_id,
 * kind) UNIQUE, change_plans (render_id), drift_runs (render_id),
 * sim_balance_samples (sim_id, zone, observed_at DESC).
 *
 * Literals only in the SQL below: knex rewrites a question mark inside raw()
 * as a binding placeholder (a known trap).
 */

const INDEXES: ReadonlyArray<readonly [index: string, ddl: string]> = [
  // 1. Age columns.
  ['reachability_verdicts_ts_idx', 'reachability_verdicts (ts)'],
  ['wan_path_events_at_idx', 'wan_path_events (at)'],
  ['device_identity_events_detected_idx', 'device_identity_events (detected_at)'],
  ['device_identity_observations_last_seen_idx', 'device_identity_observations (last_seen_at)'],
  ['device_route_transitions_at_idx', 'device_route_transitions (at)'],
  ['intervention_events_at_idx', 'intervention_events (at)'],
  ['sim_balance_samples_observed_idx', 'sim_balance_samples (observed_at)'],
  ['sim_sync_runs_started_idx', 'sim_sync_runs (started_at)'],
  ['cwmp_sessions_closed_seen_idx', "cwmp_sessions (last_seen_at) WHERE state <> 'open'"],
  ['drift_runs_no_findings_started_idx', 'drift_runs (started_at) WHERE findings_count = 0'],
  ['change_job_steps_created_idx', 'change_job_steps (created_at)'],
  ['config_renders_rendered_idx', 'config_renders (rendered_at)'],
  ['discoveries_pending_seen_idx', "discoveries (last_seen_at) WHERE state = 'pending'"],
  // 2. References into purged tables.
  ['oim_event_idx', 'operator_incident_members (event_id) WHERE event_id IS NOT NULL'],
  ['interventions_drift_run_idx', 'interventions (drift_run_id) WHERE drift_run_id IS NOT NULL'],
  ['intervention_drift_links_run_idx', 'intervention_drift_links (drift_run_id)'],
  ['change_jobs_device_kind_idx', 'change_jobs (device_id, kind, id)'],
];

export async function up(knex: Knex): Promise<void> {
  for (const [index, ddl] of INDEXES) {
    await knex.schema.raw(`CREATE INDEX IF NOT EXISTS ${index} ON ${ddl}`);
  }
}

export async function down(knex: Knex): Promise<void> {
  for (const [index] of INDEXES) {
    await knex.schema.raw(`DROP INDEX IF EXISTS ${index}`);
  }
}
