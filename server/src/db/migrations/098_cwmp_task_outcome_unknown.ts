import type { Knex } from 'knex';

/**
 * 098 — a dispatched CWMP write whose answer never came back is `unknown`,
 * never re-sent on its own.
 *
 * ┌─ WHY ─────────────────────────────────────────────────────────────────────┐
 * │ A task in `sent` whose session died (abandoned, superseded by a new      │
 * │ Inform, reaped after the idle timeout, or the CPE gave the floor back    │
 * │ instead of answering) went back to `queued` and was handed to the CPE    │
 * │ AGAIN at its next session — up to `max_attempts` times. For a read that  │
 * │ is harmless. For a Reboot or a SetParameterValues it is a second write   │
 * │ nobody approved, on a box that may well have applied the first one: the │
 * │ answer is what was lost, not necessarily the command.                    │
 * │                                                                          │
 * │ A mutating task now lands in `unknown`: terminal, never re-sent, and its │
 * │ change job is failed with "outcome unknown — check the device". A human  │
 * │ re-queues it explicitly, as a NEW task under a NEW change job; the new   │
 * │ row points at the old one through `requeued_from_task_id`.               │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * `change_job_id` is the link the ACS never stored: `enqueueTask()` CHECKED
 * the change job and then forgot it, so nothing could say which job a
 * task belonged to. BIGINT because `change_jobs.id` is a bigIncrements.
 * Both foreign keys are SET NULL: a task row is history and outlives the job
 * or the task it points at.
 *
 * No `?` in any raw statement (the knex binding trap of migration 032); the
 * state whitelist is an IN list of literals.
 */

const STATES_098 = "'queued','sent','done','failed','expired','cancelled','unknown'";
const TERMINAL_098 = "'done','failed','expired','cancelled','unknown'";
const STATES_015 = "'queued','sent','done','failed','expired','cancelled'";
const TERMINAL_015 = "'done','failed','expired','cancelled'";

export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable('cwmp_tasks', (t) => {
    t.bigInteger('change_job_id').nullable()
      .references('id').inTable('change_jobs').onDelete('SET NULL');
    t.integer('requeued_from_task_id').nullable()
      .references('id').inTable('cwmp_tasks').onDelete('SET NULL');
  });

  await knex.schema.raw('ALTER TABLE cwmp_tasks DROP CONSTRAINT cwmp_tasks_state_chk');
  await knex.schema.raw(
    `ALTER TABLE cwmp_tasks ADD CONSTRAINT cwmp_tasks_state_chk CHECK (state IN (${STATES_098}))`,
  );
  await knex.schema.raw('ALTER TABLE cwmp_tasks DROP CONSTRAINT cwmp_tasks_terminal_time_chk');
  await knex.schema.raw(
    'ALTER TABLE cwmp_tasks ADD CONSTRAINT cwmp_tasks_terminal_time_chk ' +
      `CHECK ((state IN (${TERMINAL_098})) = (completed_at IS NOT NULL))`,
  );
  // "Was this unknown task already re-queued?" — asked under a row lock on
  // every human re-queue, so it must not scan the table.
  await knex.schema.raw(
    'CREATE INDEX cwmp_tasks_requeued_from_idx ON cwmp_tasks (requeued_from_task_id) ' +
      'WHERE requeued_from_task_id IS NOT NULL',
  );
}

export async function down(knex: Knex): Promise<void> {
  // An `unknown` row cannot survive the old CHECK. `failed` is the nearest
  // honest state (terminal, completed_at already set), and the fault already
  // says the outcome is unknown.
  await knex.raw("UPDATE cwmp_tasks SET state = 'failed' WHERE state = 'unknown'");

  await knex.schema.raw('DROP INDEX IF EXISTS cwmp_tasks_requeued_from_idx');
  await knex.schema.raw('ALTER TABLE cwmp_tasks DROP CONSTRAINT cwmp_tasks_terminal_time_chk');
  await knex.schema.raw(
    'ALTER TABLE cwmp_tasks ADD CONSTRAINT cwmp_tasks_terminal_time_chk ' +
      `CHECK ((state IN (${TERMINAL_015})) = (completed_at IS NOT NULL))`,
  );
  await knex.schema.raw('ALTER TABLE cwmp_tasks DROP CONSTRAINT cwmp_tasks_state_chk');
  await knex.schema.raw(
    `ALTER TABLE cwmp_tasks ADD CONSTRAINT cwmp_tasks_state_chk CHECK (state IN (${STATES_015}))`,
  );

  await knex.schema.alterTable('cwmp_tasks', (t) => {
    t.dropColumn('requeued_from_task_id');
    t.dropColumn('change_job_id');
  });
}
