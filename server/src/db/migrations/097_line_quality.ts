import type { Knex } from 'knex';

/**
 * 097 — line quality of a store's fixed line (fleet/lineQuality.service.ts).
 *
 * ┌─ WHY ─────────────────────────────────────────────────────────────────────┐
 * │ A fixed line that degrades (loss, latency, drops) used to be found when  │
 * │ the store called. Outside opening hours each store's router now pings two │
 * │ stable targets THROUGH ITS FIXED LINE, the day's reconnections are       │
 * │ counted, and the night is judged against inherited thresholds and the    │
 * │ store's own baseline.                                                     │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ line_quality_nights — ONE ROW PER SITE AND NIGHT ────────────────────────┐
 * │ Keyed on the SITE, not the router: the line belongs to the store, and a  │
 * │ router swapped under warranty keeps the line's baseline. `device_id`     │
 * │ says which router measured (SET NULL when it is deleted).                │
 * │ `night` is the site's LOCAL date the night began on (the measurement     │
 * │ instant minus twelve hours, in `sites.timezone`): one label per night    │
 * │ whatever window the measurement ran in.                                  │
 * │ No DEFAULT on any figure: a figure not measured is NULL, never 0 (a 0 %  │
 * │ loss that nobody measured is a healthy line nobody saw).                 │
 * │ `carrier` says which link carried the figures; only `fixed` rows enter   │
 * │ the baseline and the latency / loss rules — a 4G-carried figure is never │
 * │ a fixed-line one.                                                        │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ line_quality_alerts — THE GROUPED ALERT OF A WORKSPACE ──────────────────┐
 * │ At most one row per tenant: the sites its open alert lists. Written after │
 * │ the live alert exists; deleted when every listed line recovered.        │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * No `?` in any raw statement (the knex binding trap of migration 032); the
 * whitelists are IN lists of literals.
 */
export async function up(knex: Knex): Promise<void> {
  await knex.schema.createTable('line_quality_nights', (t) => {
    t.bigIncrements('id').primary();
    t.integer('tenant_id').notNullable().references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('site_id').notNullable().references('id').inTable('sites').onDelete('CASCADE');
    t.integer('device_id').nullable().references('id').inTable('devices').onDelete('SET NULL');
    t.date('night').notNullable();
    t.text('status').notNullable();
    t.text('skip_reason').nullable();
    t.boolean('final').notNullable().defaultTo(false);
    t.smallint('attempts').notNullable().defaultTo(0);
    t.timestamp('last_attempt_at', { useTz: true }).nullable();
    t.text('schedule_source').nullable();
    t.timestamp('measured_at', { useTz: true }).nullable();
    t.text('carrier').nullable();
    t.text('uplink_iface').nullable();
    t.text('method').nullable();
    t.text('wan_shape').nullable();
    t.jsonb('targets').notNullable().defaultTo(knex.raw("'[]'::jsonb"));
    t.integer('sent').nullable();
    t.integer('received').nullable();
    t.decimal('loss_pct', 6, 2).nullable();
    t.decimal('rtt_min_ms', 10, 2).nullable();
    t.decimal('rtt_avg_ms', 10, 2).nullable();
    t.decimal('rtt_max_ms', 10, 2).nullable();
    t.decimal('jitter_ms', 10, 2).nullable();
    t.boolean('fixed_down').notNullable().defaultTo(false);
    t.timestamp('counters_from', { useTz: true }).nullable();
    t.timestamp('counters_to', { useTz: true }).nullable();
    t.text('link_downs_iface').nullable();
    t.bigInteger('link_downs_total').nullable();
    t.timestamp('boot_at', { useTz: true }).nullable();
    t.integer('link_downs').nullable();
    t.integer('failovers').nullable();
    t.integer('mgmt_reconnects').nullable();
    t.bigInteger('wan1_errors').nullable();
    t.integer('reconnections').nullable();
    t.text('verdict').notNullable().defaultTo('unknown');
    t.jsonb('reasons').notNullable().defaultTo(knex.raw("'[]'::jsonb"));
    t.jsonb('baseline').nullable();
    t.jsonb('thresholds').nullable();
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.unique(['site_id', 'night']);
  });
  const chk = (name: string, expr: string) =>
    knex.schema.raw(`ALTER TABLE line_quality_nights ADD CONSTRAINT ${name} CHECK (${expr})`);
  await chk('line_quality_nights_status_chk', "status IN ('pending', 'measured', 'skipped')");
  await chk('line_quality_nights_skip_chk', "status <> 'skipped' OR skip_reason IS NOT NULL");
  await chk('line_quality_nights_measured_chk', "status <> 'measured' OR measured_at IS NOT NULL");
  await chk('line_quality_nights_carrier_chk', "carrier IS NULL OR carrier IN ('fixed', 'cellular', 'unknown')");
  await chk('line_quality_nights_source_chk', "schedule_source IS NULL OR schedule_source IN ('opening_hours', 'night_window')");
  await chk('line_quality_nights_verdict_chk', "verdict IN ('ok', 'exceeded', 'unknown')");
  await chk('line_quality_nights_loss_chk', 'loss_pct IS NULL OR (loss_pct >= 0 AND loss_pct <= 100)');
  await chk('line_quality_nights_counts_chk', 'sent IS NULL OR received IS NULL OR (received >= 0 AND received <= sent)');
  await chk('line_quality_nights_attempts_chk', 'attempts >= 0');
  await knex.schema.raw('CREATE INDEX line_quality_nights_tenant_night ON line_quality_nights (tenant_id, night DESC)');
  await knex.schema.raw('CREATE INDEX line_quality_nights_device_night ON line_quality_nights (device_id, night DESC)');

  await knex.schema.createTable('line_quality_alerts', (t) => {
    t.integer('tenant_id').primary().references('id').inTable('tenants').onDelete('CASCADE');
    t.timestamp('opened_at', { useTz: true }).notNullable();
    t.jsonb('site_ids').notNullable();
    t.integer('live_alert_id').nullable();
    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists('line_quality_alerts');
  await knex.schema.dropTableIfExists('line_quality_nights');
}
