import type { Knex } from 'knex';

/**
 * 049 — bench_conformity_checks: the closed loop of a bench-prepared router.
 *
 * One row per `bench_provisionings` row (one compiled file), written by
 * `services/fleet/autoConfirm.service.ts` and by nothing else. It records the
 * automatic conformity check that runs when the box first comes up through its
 * tunnel: the identity proved on a fresh connection, the configuration
 * collected through the frozen export, the plan compiled from the desired
 * state of the SAME template revision the bench compiled, and the verdict.
 *
 * WHY A TABLE AND NOT COLUMNS ON `bench_provisionings`: that table is the
 * bench's account of what it released and what it saw, written under the
 * station's authority. This one is ObliWAN's own account of what it observed
 * afterwards, written under nobody's but its own, and it changes on every
 * retry. Two writers on one row would make each the other's race.
 *
 * `state` and its instants move together (CHECKs below):
 *   waiting         no verdict yet: never contacted, or a transient failure
 *                   with a retry scheduled (`next_attempt_at`).
 *   conformant      the plan came out EMPTY and the device was confirmed:
 *                   `confirmed_at` and `method` are set, and only here.
 *   non_conformant  the plan was not empty (or the box reported its own
 *                   preparation failed): the device stays `pending`, and
 *                   `difference_count` > 0 with the list in `differences`.
 *   anomaly         no verdict can be reached without a human: an identity
 *                   contradiction (the device was quarantined), retries
 *                   exhausted, a revision that can no longer be rendered…
 *   superseded      the device stopped being `pending` by another hand before
 *                   a verdict was reached; nothing was decided here.
 *
 * WHAT IS NEVER STORED: a secret. `differences` carries resource kinds,
 * semantic keys, field names and field values of the NCM — which holds
 * fingerprints, never a credential — and values of fields whose name speaks of
 * a secret are masked before they are written.
 *
 * `snapshot_id` is ON DELETE SET NULL and takes part in NO CHECK: snapshot
 * retention may remove the row it names, and a CHECK over a SET NULL column
 * would make that delete fail. The snapshot id is also written into the audit
 * entry of a confirmation, which outlives both rows.
 *
 * No DEFAULT on `state`: the insert states it. `attempts` defaults to 0
 * because a row that was just inserted has, as a fact, made no attempt.
 *
 * Literals only in the SQL below: knex rewrites a `?` inside raw() as a
 * binding placeholder (a known trap).
 */

const T = 'bench_conformity_checks';
const STATES = "'waiting','conformant','non_conformant','anomaly','superseded'";

export async function up(knex: Knex): Promise<void> {
  await knex.schema.createTable(T, (t) => {
    t.bigIncrements('id').primary();
    t.integer('tenant_id').notNullable().references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('device_id').notNullable();
    t.bigInteger('provisioning_id').notNullable().unique()
      .references('id').inTable('bench_provisionings').onDelete('CASCADE');
    t.string('state', 16).notNullable();
    t.string('reason_code', 40).nullable();
    t.text('reason').nullable();
    t.integer('attempts').notNullable().defaultTo(0);
    t.timestamp('first_attempt_at', { useTz: true }).nullable();
    t.timestamp('last_attempt_at', { useTz: true }).nullable();
    t.timestamp('next_attempt_at', { useTz: true }).nullable();
    // The claim of the process working on the row right now: a random token
    // and its instant. A claim older than the lease is presumed dead.
    t.uuid('claim_token').nullable();
    t.timestamp('claimed_at', { useTz: true }).nullable();
    t.text('last_error').nullable();
    t.bigInteger('revision_id').nullable().references('id').inTable('template_revisions').onDelete('SET NULL');
    t.bigInteger('snapshot_id').nullable().references('id').inTable('config_snapshots').onDelete('SET NULL');
    t.specificType('observed_ncm_hash', 'char(64)').nullable();
    t.boolean('render_matches_compile').nullable();
    t.integer('difference_count').nullable();
    t.jsonb('differences').nullable();
    t.jsonb('excluded').nullable();
    t.jsonb('plan_summary').nullable();
    t.string('method', 24).nullable();
    t.timestamp('confirmed_at', { useTz: true }).nullable();
    t.timestamp('decided_at', { useTz: true }).nullable();
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.index(['tenant_id', 'state']);
    t.index('device_id');
    t.index(['state', 'next_attempt_at']);
  });

  await knex.schema.raw(
    `ALTER TABLE ${T} ADD CONSTRAINT ${T}_device_fk ` +
      'FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE',
  );
  await knex.schema.raw(`ALTER TABLE ${T} ADD CONSTRAINT ${T}_state_chk CHECK (state IN (${STATES}))`);
  await knex.schema.raw(`ALTER TABLE ${T} ADD CONSTRAINT ${T}_attempts_chk CHECK (attempts >= 0)`);
  // A confirmation carries its instant and its method, and only a
  // confirmation does.
  await knex.schema.raw(
    `ALTER TABLE ${T} ADD CONSTRAINT ${T}_confirmed_chk CHECK (` +
      "(state = 'conformant') = (confirmed_at IS NOT NULL) " +
      "AND (confirmed_at IS NULL) = (method IS NULL) " +
      "AND (method IS NULL OR method = 'auto_conformity'))",
  );
  // A non-conformity names at least one difference; nothing else counts any.
  await knex.schema.raw(
    `ALTER TABLE ${T} ADD CONSTRAINT ${T}_differences_chk CHECK (` +
      "(state <> 'non_conformant' OR difference_count > 0) " +
      'AND (difference_count IS NULL OR difference_count >= 0))',
  );
  // A verdict has an instant; a row still waiting has none.
  await knex.schema.raw(
    `ALTER TABLE ${T} ADD CONSTRAINT ${T}_decided_chk CHECK ((state = 'waiting') = (decided_at IS NULL))`,
  );
  // A claim is a token AND an instant, or neither.
  await knex.schema.raw(
    `ALTER TABLE ${T} ADD CONSTRAINT ${T}_claim_chk CHECK ((claim_token IS NULL) = (claimed_at IS NULL))`,
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists(T);
}
