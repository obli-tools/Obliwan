import type { Knex } from 'knex';

/**
 * 054 — the bench server's records of device-mode, split files and the
 * bench's own checks (services/bench/compile.service.ts).
 *
 * `bench_provisionings`:
 *  - `device_mode_override` — the compile was made under the bench's declared
 *    device-mode override (an operator's decision for a remote test). NOT NULL
 *    DEFAULT false is a TRUE statement about every earlier row: no compile
 *    before this migration could be made under an override.
 *  - `device_mode_features` / `device_mode_denied` — the device-mode features
 *    the rendered revision uses, and those the box's reading denied (JSON
 *    arrays of feature names). NULL on earlier rows: never computed then.
 *  - `files` — the split files delivered beside the legacy one: name, role,
 *    SHA-256 and size of each, NEVER the content (it holds credentials).
 *  - `local_check` / `reported_device_mode_override` — what the bench reported
 *    with its result. NULL: not reported.
 *
 * `devices.bench_device_mode_override` — the device's latest bench
 * preparation was compiled under a device-mode override. DEFAULT false is,
 * again, true of every existing device.
 *
 * The override columns, `local_check` and `reported_device_mode_override` are
 * an AUDIT record: no decision reads them when this migration lands (see
 * `recordBenchResult` in services/bench/compile.service.ts). The five `device_mode*` columns of
 * migration 033 are reused as they are: the compile writes the bench's
 * reading there as one observation.
 *
 * No `?` anywhere in raw SQL (knex rewrites it as a binding), and no jsonb
 * `?` operator: `jsonb_typeof` says what is needed.
 */

const BP = 'bench_provisionings';

export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable(BP, (t) => {
    t.boolean('device_mode_override').notNullable().defaultTo(false);
    t.jsonb('device_mode_features').nullable();
    t.jsonb('device_mode_denied').nullable();
    t.jsonb('files').nullable();
    t.jsonb('local_check').nullable();
    t.boolean('reported_device_mode_override').nullable();
  });
  await knex.schema.raw(
    `ALTER TABLE ${BP} ADD CONSTRAINT ${BP}_json_shapes_chk CHECK (`
      + "(device_mode_features IS NULL OR jsonb_typeof(device_mode_features) = 'array') "
      + "AND (device_mode_denied IS NULL OR jsonb_typeof(device_mode_denied) = 'array') "
      + "AND (files IS NULL OR jsonb_typeof(files) = 'array') "
      + "AND (local_check IS NULL OR jsonb_typeof(local_check) = 'object'))",
  );
  // A local check is a report: it exists only once the outcome is reported.
  await knex.schema.raw(
    `ALTER TABLE ${BP} ADD CONSTRAINT ${BP}_reported_chk CHECK (`
      + "outcome <> 'compiled' OR (local_check IS NULL AND reported_device_mode_override IS NULL))",
  );
  await knex.schema.alterTable('devices', (t) => {
    t.boolean('bench_device_mode_override').notNullable().defaultTo(false);
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.alterTable('devices', (t) => {
    t.dropColumn('bench_device_mode_override');
  });
  await knex.schema.raw(`ALTER TABLE ${BP} DROP CONSTRAINT IF EXISTS ${BP}_reported_chk`);
  await knex.schema.raw(`ALTER TABLE ${BP} DROP CONSTRAINT IF EXISTS ${BP}_json_shapes_chk`);
  await knex.schema.alterTable(BP, (t) => {
    t.dropColumn('reported_device_mode_override');
    t.dropColumn('local_check');
    t.dropColumn('files');
    t.dropColumn('device_mode_denied');
    t.dropColumn('device_mode_features');
    t.dropColumn('device_mode_override');
  });
}
