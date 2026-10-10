import type { Knex } from 'knex';

/**
 * 075 — the 4G backup watch: WHEN the active default route last moved, and
 * the moves themselves.
 *
 * ┌─ WHY ─────────────────────────────────────────────────────────────────────┐
 * │ Migration 073 stores the router's ACTIVE default route at an instant. It  │
 * │ says "lte1 now" and never "lte1 since Friday 18:40": a fixed line down on │
 * │ a Friday evening was seen on the SIM invoice. `default_route_since` is    │
 * │ the instant the stored interface last CHANGED, written by the health      │
 * │ check (fleet/backup4g.service.ts, `recordDefaultRoute`) and read by the   │
 * │ backup alert, the uplink card and the dashboard.                          │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE RULES THE SCHEMA KEEPS ──────────────────────────────────────────────┐
 * │ · `default_route_since` is set ONLY together with `default_route_iface`:  │
 * │   "since" counts how long the route has been on ONE interface, and an     │
 * │   unknown interface (no active route, or one the router did not name)    │
 * │   has no such duration. A reading that goes unknown resets it; the next  │
 * │   named interface starts a new count — the quiet direction.             │
 * │ · No DEFAULT anywhere: a device never read has no "since", and a row     │
 * │   migrated with a route already on record gets its first "since" at its │
 * │   next reading, never a guessed past.                                    │
 * │ · `backup4g_alerted_at` is the ONE open backup alert of the device: set  │
 * │   by the check that raised it, cleared by the check that saw the route    │
 * │   back on a fixed line. It survives an unknown reading on purpose: lte1   │
 * │   → unknown → lte1 is the same episode, not a second alert.              │
 * │ · `device_route_transitions` is the history (from → to, at), kept        │
 * │   ROUTE_TRANSITION_RETENTION_DAYS (90) and pruned per device at insert.  │
 * │   `from` and `to` may be NULL (unknown), never equal.                    │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * No `?` in any raw statement (the knex binding trap of migration 032).
 */
export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable('devices', (t) => {
    t.timestamp('default_route_since', { useTz: true }).nullable();
    t.timestamp('backup4g_alerted_at', { useTz: true }).nullable();
  });
  await knex.schema.raw(
    'ALTER TABLE devices ADD CONSTRAINT devices_default_route_since_chk CHECK (' +
      'default_route_since IS NULL OR default_route_iface IS NOT NULL)',
  );

  await knex.schema.createTable('device_route_transitions', (t) => {
    t.bigIncrements('id').primary();
    t.integer('tenant_id').notNullable().references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('device_id').notNullable().references('id').inTable('devices').onDelete('CASCADE');
    t.text('from_iface').nullable();
    t.text('to_iface').nullable();
    t.timestamp('at', { useTz: true }).notNullable();
  });
  await knex.schema.raw(
    'ALTER TABLE device_route_transitions ADD CONSTRAINT device_route_transitions_change_chk ' +
      'CHECK (from_iface IS DISTINCT FROM to_iface)',
  );
  await knex.schema.raw(
    'CREATE INDEX device_route_transitions_device_at ON device_route_transitions (device_id, at DESC)',
  );
  // The dashboard's read: every device currently on a route, by tenant.
  await knex.schema.raw(
    'CREATE INDEX devices_default_route_since_idx ON devices (tenant_id, default_route_since) ' +
      'WHERE default_route_since IS NOT NULL',
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.raw('DROP INDEX IF EXISTS devices_default_route_since_idx');
  await knex.schema.dropTableIfExists('device_route_transitions');
  await knex.schema.raw('ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_default_route_since_chk');
  await knex.schema.alterTable('devices', (t) => {
    t.dropColumn('backup4g_alerted_at');
    t.dropColumn('default_route_since');
  });
}
