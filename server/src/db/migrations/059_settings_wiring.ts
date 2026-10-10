import type { Knex } from 'knex';

/**
 * Migration 059 — what wiring the ten unread settings needs from the schema.
 *
 * 1. `snmp_targets.timeout_ms` / `retries` become NULLABLE, with no default:
 *    NULL means "inherit the `snmp_timeout` / `snmp_retries` setting", exactly
 *    like `poll_interval_sec` and `credential_id` already do. As NOT NULL
 *    columns with defaults of 2000 and 1, every target carried a value and the
 *    two settings could never apply to anything.
 *
 *    Rows holding exactly the old column defaults are moved to NULL. No screen
 *    has ever written either column (the client sends neither), so a 2000 or a
 *    1 there is the default, not a decision — and the settings' defaults are
 *    now those same two numbers, so the value each target polls with does not
 *    move. A row holding anything else was set through the API on purpose and
 *    keeps its pin. The existing CHECKs pass NULL untouched.
 *
 * 2. Indexes on the columns that reference `config_snapshots`, for the
 *    retention purge (`services/retention/dataRetention.service.ts`). Each
 *    deleted snapshot makes PostgreSQL look for referencing rows in every one
 *    of these tables — to cascade, to set NULL, and for the purge's own "is it
 *    still referenced" test — and none of them had an index leading on the
 *    column, so each deletion was a sequential scan of each table.
 *
 * Literals only in the SQL below: knex rewrites a `?` inside raw() as a binding
 * placeholder (a known trap).
 */

const SNAPSHOT_REFS: ReadonlyArray<readonly [index: string, table: string, column: string]> = [
  ['change_plans_snapshot_idx', 'change_plans', 'snapshot_id'],
  ['drift_runs_snapshot_idx', 'drift_runs', 'snapshot_id'],
  ['interventions_snapshot_before_idx', 'interventions', 'snapshot_before_id'],
  ['interventions_snapshot_after_idx', 'interventions', 'snapshot_after_id'],
  ['policy_results_snapshot_idx', 'policy_results', 'snapshot_id'],
  ['baseline_cluster_members_snapshot_idx', 'baseline_cluster_members', 'snapshot_id'],
  ['bench_conformity_checks_snapshot_idx', 'bench_conformity_checks', 'snapshot_id'],
];

export async function up(knex: Knex): Promise<void> {
  await knex.schema.raw('ALTER TABLE snmp_targets ALTER COLUMN timeout_ms DROP NOT NULL');
  await knex.schema.raw('ALTER TABLE snmp_targets ALTER COLUMN timeout_ms DROP DEFAULT');
  await knex.schema.raw('ALTER TABLE snmp_targets ALTER COLUMN retries DROP NOT NULL');
  await knex.schema.raw('ALTER TABLE snmp_targets ALTER COLUMN retries DROP DEFAULT');
  // A value equal to the old column default cannot be told from it: those
  // targets now inherit (whose default is that same value, so nothing moves
  // today). Counted, so the conversion is on record.
  const timeouts = await knex('snmp_targets').where('timeout_ms', 2000).update({ timeout_ms: null });
  const retries = await knex('snmp_targets').where('retries', 1).update({ retries: null });
  // eslint-disable-next-line no-console
  console.log(`059_settings_wiring: ${timeouts} SNMP target timeout(s) of 2000 ms and ${retries} retry count(s) of 1 now inherit the settings`);

  for (const [index, table, column] of SNAPSHOT_REFS) {
    await knex.schema.raw(
      `CREATE INDEX IF NOT EXISTS ${index} ON ${table} (${column}) WHERE ${column} IS NOT NULL`,
    );
  }
}

export async function down(knex: Knex): Promise<void> {
  for (const [index] of SNAPSHOT_REFS) {
    await knex.schema.raw(`DROP INDEX IF EXISTS ${index}`);
  }

  // Back to the columns as migration 005 made them: an inherited value becomes
  // the old default again, which is the value it inherited by default anyway.
  await knex.schema.raw('UPDATE snmp_targets SET timeout_ms = 2000 WHERE timeout_ms IS NULL');
  await knex.schema.raw('UPDATE snmp_targets SET retries = 1 WHERE retries IS NULL');
  await knex.schema.raw('ALTER TABLE snmp_targets ALTER COLUMN timeout_ms SET DEFAULT 2000');
  await knex.schema.raw('ALTER TABLE snmp_targets ALTER COLUMN timeout_ms SET NOT NULL');
  await knex.schema.raw('ALTER TABLE snmp_targets ALTER COLUMN retries SET DEFAULT 1');
  await knex.schema.raw('ALTER TABLE snmp_targets ALTER COLUMN retries SET NOT NULL');
}
