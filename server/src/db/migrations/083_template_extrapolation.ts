import type { Knex } from 'knex';

/**
 * 083_template_extrapolation.ts — brick 10: the template extrapolator.
 *
 * The miner (017) clusters a tenant's routers; the extrapolator turns each
 * cluster into a PROPOSED RouterOS template — a Nunjucks body, a var_schema
 * with levels, the formulas, the per-site values — proves it by rendering it
 * for every site and diffing against the router's own export, and waits for an
 * operator to approve or reject it. The TypeScript contract is
 * `shared/src/extrapolator.ts`.
 *
 * ┌─ FIVE DECISIONS ──────────────────────────────────────────────────────────┐
 * │ 1. EVERY TABLE CARRIES `tenant_id` NOT NULL, kept honest by composite     │
 * │    foreign keys `(parent_id, tenant_id)`, exactly as 017 does: a          │
 * │    proposal mined from customer A's routers can never be filed under     │
 * │    customer B's run.                                                     │
 * │ 2. A RUN STANDS ON A MINER RUN, and survives its deletion: the link is    │
 * │    `ON DELETE SET NULL (baseline_run_id)` — PostgreSQL 15+'s column list, │
 * │    so the tenant column of the composite key is left alone.              │
 * │ 3. NO SECRET VALUE IS EVER STORED. The extrapolator never reads one (the  │
 * │    exports are redacted); a secret variable is a NAME in                 │
 * │    `variables` and `var_schema`, with no value and no default. There is   │
 * │    nothing for a CHECK to inspect, and the harness asserts it.           │
 * │ 4. A DECISION IS SIGNED. `approved` and `rejected` carry who and when;    │
 * │    a rejection carries its reason (`extrapolation_proposals_decision_chk`).│
 * │ 5. APPROVAL WRITES A DRAFT. The template and revision ids point at a      │
 * │    `template_revisions` row with status 'draft' — never published here.  │
 * │    Deleting the template later leaves the proposal (SET NULL).           │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * No `?` in any raw statement (knex binding trap, migration 032).
 */
export async function up(knex: Knex): Promise<void> {
  // ==========================================================================
  // 1. extrapolation_runs
  // ==========================================================================
  await knex.schema.createTable('extrapolation_runs', (t) => {
    t.bigIncrements('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();
    t.integer('tenant_id').notNullable().references('id').inTable('tenants').onDelete('CASCADE');
    t.bigInteger('baseline_run_id').nullable();
    t.string('status', 16).notNullable().defaultTo('running');
    t.integer('model_version').notNullable();
    t.jsonb('params').notNullable().defaultTo(knex.raw("'{}'::jsonb"));
    t.integer('device_count').notNullable().defaultTo(0);
    t.integer('skipped_count').notNullable().defaultTo(0);
    t.integer('proposal_count').notNullable().defaultTo(0);
    t.jsonb('warnings').notNullable().defaultTo(knex.raw("'[]'::jsonb"));
    t.text('error').nullable();
    t.timestamp('started_at', { useTz: true }).nullable();
    t.timestamp('finished_at', { useTz: true }).nullable();
    t.integer('created_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.timestamps(true, true);
  });
  await knex.schema.raw(
    'ALTER TABLE extrapolation_runs ADD CONSTRAINT extrapolation_runs_baseline_fk ' +
      'FOREIGN KEY (baseline_run_id, tenant_id) REFERENCES baseline_runs (id, tenant_id) ' +
      'ON DELETE SET NULL (baseline_run_id)',
  );
  await knex.schema.raw(
    "ALTER TABLE extrapolation_runs ADD CONSTRAINT extrapolation_runs_status_chk CHECK (status IN ('running','succeeded','failed'))",
  );
  await knex.schema.raw(
    `ALTER TABLE extrapolation_runs ADD CONSTRAINT extrapolation_runs_terminal_chk CHECK (
       (status IN ('succeeded','failed') AND finished_at IS NOT NULL)
       OR (status = 'running' AND finished_at IS NULL))`,
  );
  await knex.schema.raw(
    `ALTER TABLE extrapolation_runs ADD CONSTRAINT extrapolation_runs_error_chk CHECK (
       (status = 'failed' AND error IS NOT NULL) OR (status <> 'failed' AND error IS NULL))`,
  );
  await knex.schema.raw(
    `ALTER TABLE extrapolation_runs ADD CONSTRAINT extrapolation_runs_counts_chk CHECK (
       device_count >= 0 AND skipped_count >= 0 AND proposal_count >= 0)`,
  );
  await knex.schema.raw(
    'ALTER TABLE extrapolation_runs ADD CONSTRAINT extrapolation_runs_id_tenant_uq UNIQUE (id, tenant_id)',
  );
  await knex.schema.raw(
    'CREATE INDEX extrapolation_runs_tenant_idx ON extrapolation_runs (tenant_id, created_at DESC)',
  );

  // ==========================================================================
  // 2. extrapolation_proposals — one per cluster
  // ==========================================================================
  await knex.schema.createTable('extrapolation_proposals', (t) => {
    t.bigIncrements('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();
    t.bigInteger('run_id').notNullable();
    t.integer('tenant_id').notNullable();
    t.bigInteger('baseline_cluster_id').nullable();
    t.integer('cluster_index').notNullable();
    t.string('label', 64).notNullable();
    t.string('brand', 24).notNullable().defaultTo('mikrotik');
    t.integer('member_count').notNullable();
    t.integer('line_count').notNullable();
    t.integer('variable_count').notNullable();
    t.integer('deviation_count').notNullable();
    t.text('body').notNullable();
    t.string('body_sha256', 64).notNullable();
    t.jsonb('var_schema').notNullable();
    t.jsonb('variables').notNullable().defaultTo(knex.raw("'[]'::jsonb"));
    t.jsonb('policy').notNullable().defaultTo(knex.raw("'{}'::jsonb"));
    t.jsonb('deviations').notNullable().defaultTo(knex.raw("'[]'::jsonb"));
    t.jsonb('warnings').notNullable().defaultTo(knex.raw("'[]'::jsonb"));
    t.decimal('reproduction_min', 6, 5).notNullable();
    t.decimal('reproduction_mean', 6, 5).notNullable();
    t.boolean('gate_met').notNullable();
    t.string('status', 16).notNullable().defaultTo('proposed');
    t.bigInteger('template_id').nullable().references('id').inTable('templates').onDelete('SET NULL');
    t.bigInteger('template_revision_id').nullable()
      .references('id').inTable('template_revisions').onDelete('SET NULL');
    t.integer('decided_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.timestamp('decided_at', { useTz: true }).nullable();
    t.text('decision_note').nullable();
    t.timestamps(true, true);
  });
  await knex.schema.raw(
    'ALTER TABLE extrapolation_proposals ADD CONSTRAINT extrapolation_proposals_run_fk ' +
      'FOREIGN KEY (run_id, tenant_id) REFERENCES extrapolation_runs (id, tenant_id) ON DELETE CASCADE',
  );
  await knex.schema.raw(
    'ALTER TABLE extrapolation_proposals ADD CONSTRAINT extrapolation_proposals_cluster_fk ' +
      'FOREIGN KEY (baseline_cluster_id, tenant_id) REFERENCES baseline_clusters (id, tenant_id) ' +
      'ON DELETE SET NULL (baseline_cluster_id)',
  );
  await knex.schema.raw(
    "ALTER TABLE extrapolation_proposals ADD CONSTRAINT extrapolation_proposals_status_chk CHECK (status IN ('proposed','approved','rejected'))",
  );
  await knex.schema.raw(
    `ALTER TABLE extrapolation_proposals ADD CONSTRAINT extrapolation_proposals_decision_chk CHECK (
       (status = 'proposed' AND decided_at IS NULL)
       OR (status = 'approved' AND decided_at IS NOT NULL)
       OR (status = 'rejected' AND decided_at IS NOT NULL AND decision_note IS NOT NULL))`,
  );
  await knex.schema.raw(
    "ALTER TABLE extrapolation_proposals ADD CONSTRAINT extrapolation_proposals_brand_chk CHECK (brand IN ('mikrotik','draytek','zyxel','sonicwall'))",
  );
  await knex.schema.raw(
    `ALTER TABLE extrapolation_proposals ADD CONSTRAINT extrapolation_proposals_ranges_chk CHECK (
       cluster_index >= 0 AND member_count >= 1 AND line_count >= 0 AND variable_count >= 0
       AND deviation_count >= 0
       AND reproduction_min BETWEEN 0 AND 1 AND reproduction_mean BETWEEN 0 AND 1)`,
  );
  await knex.schema.raw(
    'ALTER TABLE extrapolation_proposals ADD CONSTRAINT extrapolation_proposals_id_tenant_uq UNIQUE (id, tenant_id)',
  );
  await knex.schema.raw(
    'CREATE UNIQUE INDEX extrapolation_proposals_index_uq ON extrapolation_proposals (tenant_id, run_id, cluster_index)',
  );

  // ==========================================================================
  // 3. extrapolation_site_results — the proof, one row per router
  // ==========================================================================
  await knex.schema.createTable('extrapolation_site_results', (t) => {
    t.bigIncrements('id').primary();
    t.bigInteger('proposal_id').notNullable();
    t.integer('tenant_id').notNullable();
    t.integer('device_id').notNullable();
    t.string('device_name', 255).notNullable();
    t.integer('site_id').nullable();
    t.string('site_code', 64).nullable();
    t.bigInteger('snapshot_id').nullable();
    t.integer('lines_actual').notNullable();
    t.integer('lines_rendered').notNullable();
    t.integer('lines_reproduced').notNullable();
    t.decimal('score', 6, 5).notNullable();
    t.jsonb('not_reproduced').notNullable().defaultTo(knex.raw("'[]'::jsonb"));
    t.jsonb('would_add').notNullable().defaultTo(knex.raw("'[]'::jsonb"));
    t.text('render_error').nullable();
    t.timestamps(true, true);
  });
  await knex.schema.raw(
    'ALTER TABLE extrapolation_site_results ADD CONSTRAINT extrapolation_site_results_proposal_fk ' +
      'FOREIGN KEY (proposal_id, tenant_id) REFERENCES extrapolation_proposals (id, tenant_id) ON DELETE CASCADE',
  );
  // A device of ANOTHER tenant can never be filed here (017 gave devices
  // UNIQUE (id, tenant_id)). Deleting a device drops its proof rows.
  await knex.schema.raw(
    'ALTER TABLE extrapolation_site_results ADD CONSTRAINT extrapolation_site_results_device_fk ' +
      'FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE',
  );
  await knex.schema.raw(
    `ALTER TABLE extrapolation_site_results ADD CONSTRAINT extrapolation_site_results_ranges_chk CHECK (
       lines_actual >= 0 AND lines_rendered >= 0 AND lines_reproduced >= 0
       AND lines_reproduced <= lines_actual AND lines_reproduced <= lines_rendered
       AND score BETWEEN 0 AND 1)`,
  );
  await knex.schema.raw(
    'CREATE UNIQUE INDEX extrapolation_site_results_uq ON extrapolation_site_results (tenant_id, proposal_id, device_id)',
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists('extrapolation_site_results');
  await knex.schema.dropTableIfExists('extrapolation_proposals');
  await knex.schema.dropTableIfExists('extrapolation_runs');
}
