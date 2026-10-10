import type { Knex } from 'knex';

/**
 * 093_access_check_nightly.ts — the NIGHTLY verification of the management
 * access and the template fixes, its alerts grouped by cause and its optional
 * automatic re-apply (operator GO 2026-10-09; shared/src/accessCheck.ts,
 * services/fleet/accessCheckNightly.service.ts, accessCheckAlerts.service.ts).
 *
 *  1. `access_check_runs` WIDENED:
 *     - `trigger`             manual | nightly. A nightly run is the whole
 *                             workspace (`scope = 'tenant'`), names nobody
 *                             (`requested_by` NULL) and carries its NIGHT
 *                             (`night_date`, the Europe/Paris date of the hour
 *                             it was due at). At most one nightly run per
 *                             workspace and night that is running or done
 *                             (partial unique index): a run a restart killed
 *                             reads `interrupted` and the night is taken up by
 *                             a new one.
 *     - `reapply_trigger`     who re-applied it: the operator's click or the
 *                             night. Backfilled `manual` where a run was
 *                             already re-applied; the night re-applies only a
 *                             nightly run.
 *     - `auto_reapply`        what the automatic re-apply decided (shared
 *                             `AccessCheckAutoReapplySummary`); NULL until it
 *                             ran — the post-run sweep takes up a run whose
 *                             process died before.
 *     - `alerts_evaluated_at` when the run's alerts were evaluated; NULL until
 *                             then (same sweep).
 *
 *  2. `access_check_alerts` — ONE open row per workspace and cause (partial
 *     unique index): the routers that have it (`device_ids`, as of `last_run`),
 *     when it opened, the live alert that shows it. Closed (`closed_at`,
 *     `closed_run`) by the first complete run that no longer finds it. The run
 *     numbers are plain numbers, NOT foreign keys: runs are pruned per
 *     workspace (ACCESS_CHECK_RUNS_KEPT) and an alert outlives them.
 *
 *  3. `access_check_auto_jobs` — the jobs the AUTOMATIC re-apply queued: the
 *     run number (the Changes page and the audit say "automatic re-apply
 *     (nightly verification #n)"), the cause it acted on (a router whose
 *     previous automatic job of a kind failed for the SAME cause is never
 *     re-applied by the night again), the consent it carried. Cascades with
 *     its job and device.
 *
 *  4. `access_check_auto_consents` — the platform administrator who turned the
 *     automatic re-apply ON for a workspace, and when: the standing safety-net
 *     confirmation of the degraded level the jobs carry
 *     (`degraded_confirmed_by`). Written by the settings write itself; deleted
 *     when the setting is turned off or reset, and with its user.
 *
 * No `?` anywhere in the SQL below (knex binding trap, migration 032), no
 * regex in a CHECK: IN lists of literals and IS NULL tests only.
 */

const TRIGGERS = ['manual', 'nightly'] as const;
const AUTO_KINDS = ['management_access', 'legacy_compliance'] as const;
const list = (values: readonly string[]): string => values.map((v) => `'${v}'`).join(', ');

export async function up(knex: Knex): Promise<void> {
  // ── 1. access_check_runs ────────────────────────────────────────────────
  await knex.schema.alterTable('access_check_runs', (t) => {
    t.string('trigger', 8).notNullable().defaultTo('manual');
    t.date('night_date').nullable();
    t.string('reapply_trigger', 8).nullable();
    t.jsonb('auto_reapply').nullable();
    t.timestamp('alerts_evaluated_at', { useTz: true }).nullable();
  });
  await knex('access_check_runs').whereNotNull('reapplied_at').update({ reapply_trigger: 'manual' });
  await knex.schema.raw(
    'ALTER TABLE access_check_runs ADD CONSTRAINT access_check_runs_trigger_chk CHECK (' +
      `trigger IN (${list(TRIGGERS)}) ` +
      "AND ((trigger = 'nightly') = (night_date IS NOT NULL)) " +
      "AND (trigger = 'manual' OR (requested_by IS NULL AND scope = 'tenant')) " +
      `AND (reapply_trigger IS NULL OR reapply_trigger IN (${list(TRIGGERS)})) ` +
      'AND ((reapplied_at IS NULL) = (reapply_trigger IS NULL)) ' +
      "AND (reapply_trigger IS NULL OR reapply_trigger = 'manual' OR trigger = 'nightly') " +
      "AND (auto_reapply IS NULL OR trigger = 'nightly'))",
  );
  await knex.schema.raw(
    'CREATE UNIQUE INDEX access_check_runs_one_night_uq ON access_check_runs (tenant_id, night_date) ' +
      "WHERE trigger = 'nightly' AND status IN ('running', 'done')",
  );

  // ── 2. access_check_alerts ──────────────────────────────────────────────
  await knex.schema.createTable('access_check_alerts', (t) => {
    t.bigIncrements('id').primary();
    t.integer('tenant_id').notNullable().references('id').inTable('tenants').onDelete('CASCADE');
    t.string('cause', 64).notNullable();
    t.timestamp('opened_at', { useTz: true }).notNullable();
    t.bigInteger('opened_run').notNullable();
    t.bigInteger('last_run').notNullable();
    t.jsonb('device_ids').notNullable();
    t.integer('device_count').notNullable();
    t.timestamp('notified_at', { useTz: true }).notNullable();
    t.integer('live_alert_id').nullable().references('id').inTable('live_alerts').onDelete('SET NULL');
    t.timestamp('closed_at', { useTz: true }).nullable();
    t.bigInteger('closed_run').nullable();
    t.index(['tenant_id', 'closed_at']);
  });
  await knex.schema.raw(
    'ALTER TABLE access_check_alerts ADD CONSTRAINT access_check_alerts_shape_chk CHECK (' +
      'device_count >= 0 ' +
      'AND last_run >= opened_run ' +
      'AND ((closed_at IS NULL) = (closed_run IS NULL)))',
  );
  await knex.schema.raw(
    'CREATE UNIQUE INDEX access_check_alerts_one_open_uq ON access_check_alerts (tenant_id, cause) WHERE closed_at IS NULL',
  );

  // ── 3. access_check_auto_jobs ───────────────────────────────────────────
  await knex.schema.createTable('access_check_auto_jobs', (t) => {
    t.bigInteger('job_id').primary().references('id').inTable('change_jobs').onDelete('CASCADE');
    t.integer('tenant_id').notNullable().references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('device_id').notNullable().references('id').inTable('devices').onDelete('CASCADE');
    t.bigInteger('run_number').notNullable();
    t.string('kind', 24).notNullable();
    t.string('cause', 64).notNullable();
    t.integer('confirmed_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.index(['device_id', 'kind']);
  });
  await knex.schema.raw(
    `ALTER TABLE access_check_auto_jobs ADD CONSTRAINT access_check_auto_jobs_kind_chk CHECK (kind IN (${list(AUTO_KINDS)}))`,
  );

  // ── 4. access_check_auto_consents ───────────────────────────────────────
  await knex.schema.createTable('access_check_auto_consents', (t) => {
    t.integer('tenant_id').primary().references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
    t.timestamp('consented_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists('access_check_auto_consents');
  await knex.schema.dropTableIfExists('access_check_auto_jobs');
  await knex.schema.dropTableIfExists('access_check_alerts');
  await knex.schema.raw('DROP INDEX IF EXISTS access_check_runs_one_night_uq');
  await knex.schema.raw('ALTER TABLE access_check_runs DROP CONSTRAINT IF EXISTS access_check_runs_trigger_chk');
  // A nightly run cannot be told apart once the columns are gone: drop them
  // (the runs are a cache of verdicts, re-made by the next verification).
  await knex('access_check_runs').where({ trigger: 'nightly' }).delete();
  await knex.schema.alterTable('access_check_runs', (t) => {
    t.dropColumn('alerts_evaluated_at');
    t.dropColumn('auto_reapply');
    t.dropColumn('reapply_trigger');
    t.dropColumn('night_date');
    t.dropColumn('trigger');
  });
}
