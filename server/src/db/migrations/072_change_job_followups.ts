import type { Knex } from 'knex';

/**
 * 072 — a change job queued by the worker once ANOTHER one has succeeded on
 * the same device (`change_job_followups`, services/change/jobFollowup.service.ts).
 *
 * WHY A TABLE. The bulk attach of the reconciliation (fleet/reconcileAttach
 * .service.ts) queues `management_access` on each router it attaches — the job
 * that creates ObliWAN's `obliwan` account, opens api-ssl and switches the
 * device's transports to it — and the operator wants the template fixes
 * (`legacy_compliance`) to follow. Both cannot be queued at once:
 * `change_jobs_one_in_flight_uq` holds ONE active job per device, and that is a
 * safety property, not a policy (two jobs judged against the same router state).
 * So the second one is a PROMISE, written beside the first and kept by the
 * worker when the first settles: queued if it SUCCEEDED, closed without a job
 * otherwise. One row per promise:
 *
 *   tenant_id, device_id   whose router; the second job is enqueued for that
 *                          tenant and that device only (the enqueue re-reads
 *                          the device under the tenant, so a device that moved
 *                          is refused by the enqueue's own rules).
 *   after_job_id           the job that must SUCCEED first.
 *   then_kind              what follows it. `legacy_compliance` only (CHECK).
 *   requested_by           who asked (the attaching operator).
 *   confirmed_by/_at       the safety-net rule's explicit confirmation of the DEGRADED safety
 *                          level, given once for the whole attach batch and
 *                          carried to the job the worker enqueues — that job
 *                          arms no dead-man either. `confirmed_at` is NOT NULL:
 *                          no promise exists without a confirmation. A user
 *                          deleted since leaves `confirmed_by` NULL, and the
 *                          worker then REFUSES to enqueue (`confirmation_lost`)
 *                          rather than queue a degraded job nobody confirmed —
 *                          `change_jobs_degraded_confirm_chk` would refuse it.
 *                          `confirmed_at` is the queued job's
 *                          `degraded_confirmed_at` (the operator's instant, not
 *                          the worker's); older than 24 h when the first job
 *                          settles, nothing is queued (`skipped`,
 *                          `confirmation_stale`).
 *   source, correlation_id what created the promise, and that request's id
 *                          (the attach's command audit and audit entries).
 *   done_at, outcome       when and how it was kept, both or neither:
 *                            queued   the job was enqueued (`then_job_id`);
 *                            refused  the first job succeeded, the enqueue of
 *                                     the second was refused (kill switch,
 *                                     another job on the device, the device's
 *                                     own refusals...);
 *                            skipped  the first job did not succeed (failed,
 *                                     aborted, rolled back), or the
 *                                     confirmation is stale: nothing queued.
 *   outcome_reason/_detail the refusal's code and sentence — NOT NULL exactly
 *                          for `refused` and `skipped`.
 *   then_job_id            the job enqueued; only with `queued`.
 *   attempts               enqueues of the second job that failed for no named
 *                          reason (a dropped connection, a deadlock): the
 *                          promise stays OPEN and the sweep tries again, up to
 *                          `FOLLOWUP_MAX_ATTEMPTS`, then closes it `refused`.
 *                          A named refusal (kill switch, another job on the
 *                          device, the device's own rules) closes it at once.
 *
 * FOREIGN KEYS, AND WHICH WAY THEY POINT. Every key goes FROM this table: to
 * tenants, devices, change_jobs (ON DELETE CASCADE: a promise about a job or a
 * device that no longer exists is nothing) and users (ON DELETE SET NULL, see
 * above); `then_job_id` is SET NULL. Nothing references this table, so a
 * `TRUNCATE change_jobs … CASCADE` (the m6-queue harness) empties it and stops
 * there: no path from change_jobs reaches `devices` through it (068's comment,
 * where such a path emptied the device table). For the same reason the CHECK
 * on `then_job_id` is one-sided (`then_job_id` only with `queued`, never the
 * converse): a SET NULL fired by a deleted job must not violate it.
 *
 * The CHECKs are IN lists of literals and IS NULL tests only — no regular
 * expression and no `?` (knex rewrites it inside `raw()`; project convention).
 */

const THEN_KINDS = ['legacy_compliance'] as const;
const OUTCOMES = ['queued', 'refused', 'skipped'] as const;
const SOURCES = ['reconcile_attach'] as const;

const list = (values: readonly string[]): string => values.map((v) => `'${v}'`).join(', ');

const CHECKS: Array<[string, string]> = [
  ['then_kind_chk', `then_kind IN (${list(THEN_KINDS)})`],
  ['source_chk', `source IN (${list(SOURCES)})`],
  ['outcome_chk', `outcome IS NULL OR outcome IN (${list(OUTCOMES)})`],
  ['done_chk', '(done_at IS NULL) = (outcome IS NULL)'],
  ['reason_chk', "(coalesce(outcome, '') IN ('refused', 'skipped')) = (outcome_reason IS NOT NULL)"],
  ['detail_chk', 'outcome_detail IS NULL OR outcome_reason IS NOT NULL'],
  ['then_job_chk', "then_job_id IS NULL OR outcome = 'queued'"],
];

export async function up(knex: Knex): Promise<void> {
  await knex.schema.createTable('change_job_followups', (t) => {
    t.bigIncrements('id').primary();
    t.integer('tenant_id').notNullable().references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('device_id').notNullable().references('id').inTable('devices').onDelete('CASCADE');
    t.bigInteger('after_job_id').notNullable().references('id').inTable('change_jobs').onDelete('CASCADE');
    t.string('then_kind', 24).notNullable();
    t.integer('requested_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.integer('confirmed_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.timestamp('confirmed_at', { useTz: true }).notNullable();
    t.string('source', 32).notNullable();
    t.uuid('correlation_id').nullable();
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('done_at', { useTz: true }).nullable();
    t.string('outcome', 16).nullable();
    t.string('outcome_reason', 64).nullable();
    t.text('outcome_detail').nullable();
    t.bigInteger('then_job_id').nullable().references('id').inTable('change_jobs').onDelete('SET NULL');
    t.integer('attempts').notNullable().defaultTo(0);
    // One promise of a kind per job.
    t.unique(['after_job_id', 'then_kind'], { indexName: 'change_job_followups_after_kind_uq' });
  });
  for (const [name, expr] of CHECKS) {
    await knex.schema.raw(`ALTER TABLE change_job_followups ADD CONSTRAINT change_job_followups_${name} CHECK (${expr})`);
  }
  // The worker's sweep: the promises still open, by the job they wait on.
  await knex.schema.raw(
    'CREATE INDEX change_job_followups_open_idx ON change_job_followups (after_job_id) WHERE done_at IS NULL',
  );
  await knex.schema.raw('CREATE INDEX change_job_followups_device_idx ON change_job_followups (device_id, id DESC)');
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists('change_job_followups');
}
