import type { Knex } from 'knex';

/**
 * 042 — bench_provisionings: one row per configuration file the bench API
 * released (POST /api/bench/v1/compile), and the bench's report on it.
 *
 * Why a table and not a column on `devices`:
 *  - a site may be prepared several times (a retry, a replacement box), and
 *    "which file went onto which box, from which workstation, and what did the
 *    bench say afterwards" is a history, not a current value;
 *  - `POST /api/bench/v1/devices/:id/result` must only accept a report from
 *    the workstation that compiled the file for that device. Without a record
 *    of who compiled what, any approved station could write an outcome on any
 *    device of any tenant.
 *
 * What it never holds: the file itself or any secret in it. `content_sha256`
 * is the digest the bench verifies before it uploads (over a text that holds a
 * freshly generated 24-character password, so it does not reveal the text);
 * `redacted_sha256` is the digest of the template render with its secrets as
 * placeholders — the form that may be compared and shown.
 *
 * No DEFAULT on `outcome` or `concentrator_state`: both are stated by the
 * insert, from what the compile observed. `compiled_at` defaults to now()
 * because the row is written by the compile itself, at that instant.
 *
 * `concentrator_state` admits only 'provisioned' and 'pending': a compile
 * whose concentrator account FAILED releases no file, so it has no row here.
 */
export async function up(knex: Knex): Promise<void> {
  await knex.schema.createTable('bench_provisionings', (t) => {
    t.bigIncrements('id').primary();
    t.integer('tenant_id').notNullable().references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('site_id').notNullable();
    t.integer('device_id').notNullable();
    t.integer('station_id').notNullable().references('id').inTable('bench_stations').onDelete('RESTRICT');
    t.bigInteger('revision_id').nullable().references('id').inTable('template_revisions').onDelete('SET NULL');
    t.string('tag', 64).notNullable().unique();
    t.string('file_name', 100).notNullable();
    t.specificType('content_sha256', 'char(64)').notNullable();
    t.specificType('redacted_sha256', 'char(64)').notNullable();
    t.string('concentrator_state', 12).notNullable();
    t.bigInteger('concentrator_job_id').nullable().references('id').inTable('change_jobs').onDelete('SET NULL');
    t.string('outcome', 12).notNullable();
    t.text('outcome_detail').nullable();
    t.timestamp('outcome_at', { useTz: true }).nullable();
    t.timestamp('compiled_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.index(['tenant_id', 'site_id']);
    t.index('device_id');
    t.index('station_id');
  });

  await knex.schema.raw(
    'ALTER TABLE bench_provisionings ADD CONSTRAINT bench_provisionings_site_fk ' +
      'FOREIGN KEY (site_id, tenant_id) REFERENCES sites (id, tenant_id) ON DELETE CASCADE',
  );
  await knex.schema.raw(
    'ALTER TABLE bench_provisionings ADD CONSTRAINT bench_provisionings_device_fk ' +
      'FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE',
  );
  await knex.schema.raw(
    'ALTER TABLE bench_provisionings ADD CONSTRAINT bench_provisionings_outcome_chk ' +
      "CHECK (outcome IN ('compiled', 'applied', 'failed'))",
  );
  await knex.schema.raw(
    'ALTER TABLE bench_provisionings ADD CONSTRAINT bench_provisionings_concentrator_chk ' +
      "CHECK (concentrator_state IN ('provisioned', 'pending'))",
  );
  // A reported outcome carries its instant; an unreported one has none.
  await knex.schema.raw(
    'ALTER TABLE bench_provisionings ADD CONSTRAINT bench_provisionings_outcome_at_chk ' +
      "CHECK ((outcome = 'compiled') = (outcome_at IS NULL))",
  );
  await knex.schema.raw(
    'ALTER TABLE bench_provisionings ADD CONSTRAINT bench_provisionings_sha_chk ' +
      "CHECK (content_sha256 ~ '^[0-9a-f]{64}$' AND redacted_sha256 ~ '^[0-9a-f]{64}$')",
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists('bench_provisionings');
}
