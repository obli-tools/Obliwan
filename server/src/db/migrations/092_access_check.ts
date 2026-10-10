import type { Knex } from 'knex';

/**
 * 092_access_check.ts — "verify, then re-apply, the management access and the
 * template fixes" over a whole workspace (written for a customer onboarding;
 * shared/src/accessCheck.ts, services/fleet/accessCheck.service.ts).
 *
 * WHY A TABLE, NOT MEMORY. A verification dials every router of a workspace
 * (two hundred, eight at a time): minutes. The page must show it after a
 * reload, and the operator's re-apply must act on exactly the verdicts the
 * operator READ — by run id, refused once stale. Memory (the infra analysis's
 * way) loses all of it on every deploy (`000-RegularUpdate.bat`), which this
 * onboarding does several times a day, and cannot tell the next run "a
 * verification is already running" across a restart. Two small tables:
 *
 *  1. `access_check_runs` — one row per verification: the workspace, who ran
 *     it and over what (`scope`: the whole workspace, or the devices the
 *     caller's teams grant `rw` on), `status` (running / done / interrupted),
 *     `heartbeat_at` (moves with every router verified: a `running` row whose
 *     heartbeat is old is a run a restart killed, and reads `interrupted`),
 *     and when and by whom it was re-applied — ONCE (`reapplied_at`): a second
 *     re-apply needs a new verification. At most one `running` row per
 *     workspace (partial unique index).
 *
 *  2. `access_check_results` — one row per (run, device): `pending` until the
 *     router was verified, then `done` with the verdict (`result`, the shape
 *     of shared `AccessCheckRow` without the device's live name) and the
 *     `action` the re-apply would take; `reapply` records what the re-apply
 *     did for it (the job queued, or the door's refusal).
 *
 * WIDENED: `change_job_followups.source` gains `access_check` — the re-apply
 * promises the template fixes after a management_access job exactly like the
 * bulk attach does (jobFollowup.service.ts). `down()` deletes the promises of
 * that source before narrowing the CHECK back.
 *
 * FOREIGN KEYS point from these leaves only: to tenants and devices ON DELETE
 * CASCADE (a verification of a device that no longer exists is nothing), to
 * users ON DELETE SET NULL. Nothing references them.
 *
 * No `?` anywhere in the SQL below (knex binding trap, migration 032), no
 * regex in a CHECK: IN lists of literals and IS NULL tests only.
 */

const RUN_STATUSES = ['running', 'done', 'interrupted'] as const;
const SCOPES = ['tenant', 'teams'] as const;
const RESULT_STATES = ['pending', 'done'] as const;
const ACTIONS = ['management_access', 'legacy_compliance', 'none', 'skip'] as const;
const FOLLOWUP_SOURCES_BEFORE = ['reconcile_attach'] as const;
const FOLLOWUP_SOURCES_AFTER = ['reconcile_attach', 'access_check'] as const;

const list = (values: readonly string[]): string => values.map((v) => `'${v}'`).join(', ');

export async function up(knex: Knex): Promise<void> {
  await knex.schema.createTable('access_check_runs', (t) => {
    t.bigIncrements('id').primary();
    t.uuid('run_id').notNullable().unique();
    t.integer('tenant_id').notNullable().references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('requested_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.string('scope', 8).notNullable();
    t.string('status', 16).notNullable();
    t.integer('total').notNullable();
    t.timestamp('started_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('heartbeat_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('finished_at', { useTz: true }).nullable();
    t.timestamp('reapplied_at', { useTz: true }).nullable();
    t.integer('reapplied_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.index(['tenant_id', 'id']);
  });
  await knex.schema.raw(
    'ALTER TABLE access_check_runs ADD CONSTRAINT access_check_runs_shape_chk CHECK (' +
      `status IN (${list(RUN_STATUSES)}) ` +
      `AND scope IN (${list(SCOPES)}) ` +
      'AND total >= 0 ' +
      "AND ((status = 'running') = (finished_at IS NULL)) " +
      "AND (reapplied_at IS NULL OR status = 'done'))",
  );
  // One verification running per workspace at a time.
  await knex.schema.raw(
    "CREATE UNIQUE INDEX access_check_runs_one_running_uq ON access_check_runs (tenant_id) WHERE status = 'running'",
  );

  await knex.schema.createTable('access_check_results', (t) => {
    t.bigIncrements('id').primary();
    t.bigInteger('run_id').notNullable().references('id').inTable('access_check_runs').onDelete('CASCADE');
    t.integer('tenant_id').notNullable().references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('device_id').notNullable().references('id').inTable('devices').onDelete('CASCADE');
    t.string('state', 8).notNullable();
    t.jsonb('result').nullable();
    t.string('action', 24).nullable();
    t.timestamp('checked_at', { useTz: true }).nullable();
    t.jsonb('reapply').nullable();
    t.unique(['run_id', 'device_id'], { indexName: 'access_check_results_run_device_uq' });
  });
  await knex.schema.raw(
    'ALTER TABLE access_check_results ADD CONSTRAINT access_check_results_shape_chk CHECK (' +
      `state IN (${list(RESULT_STATES)}) ` +
      `AND (action IS NULL OR action IN (${list(ACTIONS)})) ` +
      "AND ((state = 'done') = (result IS NOT NULL)) " +
      "AND ((state = 'done') = (action IS NOT NULL)) " +
      "AND ((state = 'done') = (checked_at IS NOT NULL)) " +
      "AND (reapply IS NULL OR state = 'done'))",
  );

  await knex.schema.raw('ALTER TABLE change_job_followups DROP CONSTRAINT IF EXISTS change_job_followups_source_chk');
  await knex.schema.raw(
    `ALTER TABLE change_job_followups ADD CONSTRAINT change_job_followups_source_chk CHECK (source IN (${list(FOLLOWUP_SOURCES_AFTER)}))`,
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex('change_job_followups').where({ source: 'access_check' }).delete();
  await knex.schema.raw('ALTER TABLE change_job_followups DROP CONSTRAINT IF EXISTS change_job_followups_source_chk');
  await knex.schema.raw(
    `ALTER TABLE change_job_followups ADD CONSTRAINT change_job_followups_source_chk CHECK (source IN (${list(FOLLOWUP_SOURCES_BEFORE)}))`,
  );
  await knex.schema.dropTableIfExists('access_check_results');
  await knex.schema.dropTableIfExists('access_check_runs');
}
