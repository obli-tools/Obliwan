import type { Knex } from 'knex';

/**
 * 096 — store OPENING HOURS ("a store down at 03:00 is not an emergency; at
 * 15:00 it is"). shared/src/openingHours.ts
 * holds the model, services/fleet/openingHours.service.ts the reads and
 * services/fleet/closedStoreAlerts.service.ts the alert effects.
 *
 * ┌─ THE HOURS ───────────────────────────────────────────────────────────────┐
 * │ `tenants.opening_hours` — a workspace's usual hours, set once.            │
 * │ `sites.opening_hours`   — a site's override: its own week (null = the     │
 * │                           workspace's) and its own dated exceptions       │
 * │                           (merged with the workspace's; the site's wins   │
 * │                           on a date). NULL = inherit everything.          │
 * │ Both NULL by default and with NO default: hours nobody stated are not     │
 * │ known, and unknown hours change nothing anywhere (alerts, notifications   │
 * │ and pushes behave exactly as before 096). The shape is validated by the   │
 * │ API (validateOpeningHours); the CHECK only keeps it an object.            │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ `store_closed_alerts` — an alert raised while the store was closed ─────┐
 * │ One row per (device, kind, episode): the down alert of an outage that    │
 * │ started at `episode_at` (device_health_checks.down_since), or the 4G      │
 * │ backup alert of the episode that started at `episode_at`                  │
 * │ (devices.default_route_since). It was raised one level LOWER and marked   │
 * │ « magasin fermé »; `notified_at_raise` says whether the channels heard of │
 * │ it then (setting closed_store_notify = notify anyway) or not (= wait for  │
 * │ the opening). When the store opens with the problem still there, the      │
 * │ leader's sweep raises it again at its normal severity and notifies with   │
 * │ the stored `notification` payload (`escalated_at`). When the problem     │
 * │ ends first the row is closed (`resolved_at`, 'cleared') — and a recovery │
 * │ of an episode nobody was notified of is not notified either.             │
 * │ FKs point from this leaf only, ON DELETE CASCADE to tenants and devices,  │
 * │ SET NULL to sites. Nothing references it.                                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * No `?` in any raw statement (the knex binding trap of migration 032).
 */
export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable('tenants', (t) => {
    t.jsonb('opening_hours').nullable();
  });
  await knex.schema.alterTable('sites', (t) => {
    t.jsonb('opening_hours').nullable();
  });
  await knex.schema.raw(
    'ALTER TABLE tenants ADD CONSTRAINT tenants_opening_hours_chk CHECK (' +
      "opening_hours IS NULL OR jsonb_typeof(opening_hours) = 'object')",
  );
  await knex.schema.raw(
    'ALTER TABLE sites ADD CONSTRAINT sites_opening_hours_chk CHECK (' +
      "opening_hours IS NULL OR jsonb_typeof(opening_hours) = 'object')",
  );

  await knex.schema.createTable('store_closed_alerts', (t) => {
    t.increments('id').primary();
    t.integer('tenant_id').notNullable().references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('device_id').notNullable().references('id').inTable('devices').onDelete('CASCADE');
    t.integer('site_id').nullable().references('id').inTable('sites').onDelete('SET NULL');
    t.text('kind').notNullable();
    t.timestamp('episode_at', { useTz: true }).notNullable();
    t.timestamp('raised_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    // What the alert would have been with the store open: raised again with
    // these at the opening.
    t.text('normal_severity').notNullable();
    t.text('title').notNullable();
    t.text('message').notNullable();
    t.text('navigate_to').nullable();
    t.text('stable_key').notNullable();
    t.jsonb('notification').notNullable();
    t.boolean('notified_at_raise').notNullable();
    // The next opening as computed at the raise; informative (the sweep
    // re-evaluates the hours, which may have been edited since).
    t.timestamp('opens_at', { useTz: true }).nullable();
    t.timestamp('escalated_at', { useTz: true }).nullable();
    t.timestamp('resolved_at', { useTz: true }).nullable();
    t.text('resolution').nullable();
    t.unique(['device_id', 'kind', 'episode_at']);
    t.index(['tenant_id']);
  });
  await knex.schema.raw(
    'ALTER TABLE store_closed_alerts ADD CONSTRAINT store_closed_alerts_kind_chk CHECK (' +
      "kind IN ('health_down', 'backup_4g'))",
  );
  await knex.schema.raw(
    'ALTER TABLE store_closed_alerts ADD CONSTRAINT store_closed_alerts_severity_chk CHECK (' +
      "normal_severity IN ('down', 'warning', 'info', 'up'))",
  );
  await knex.schema.raw(
    'ALTER TABLE store_closed_alerts ADD CONSTRAINT store_closed_alerts_resolution_chk CHECK (' +
      "(resolved_at IS NULL AND resolution IS NULL) OR " +
      "(resolved_at IS NOT NULL AND resolution IN ('escalated', 'cleared')))",
  );
  await knex.schema.raw(
    'ALTER TABLE store_closed_alerts ADD CONSTRAINT store_closed_alerts_escalated_chk CHECK (' +
      "escalated_at IS NULL OR resolution = 'escalated')",
  );
  await knex.schema.raw(
    'CREATE INDEX store_closed_alerts_open_idx ON store_closed_alerts (raised_at) WHERE resolved_at IS NULL',
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists('store_closed_alerts');
  await knex.schema.raw('ALTER TABLE sites DROP CONSTRAINT IF EXISTS sites_opening_hours_chk');
  await knex.schema.raw('ALTER TABLE tenants DROP CONSTRAINT IF EXISTS tenants_opening_hours_chk');
  await knex.schema.alterTable('sites', (t) => {
    t.dropColumn('opening_hours');
  });
  await knex.schema.alterTable('tenants', (t) => {
    t.dropColumn('opening_hours');
  });
}
