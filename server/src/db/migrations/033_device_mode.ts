import type { Knex } from 'knex';

/**
 * `devices.device_mode*` — what RouterOS 7.13+ currently ALLOWS on this unit.
 *
 * ┌─ WHY THIS IS AN INVENTORY COLUMN AND NOT AN ERROR PATH ──────────────────┐
 * │ ObliWAN's dead-man installs `/system/scheduler … start-                  │
 * │ time=startup` so a router that a change cuts off restores itself on the   │
 * │ next boot. Since 7.13 `/system/device-mode` can DENY the scheduler        │
 * │ menu, and on a unit in `home` mode it does.                              │
 * │                                                                          │
 * │ What makes that an inventory fact rather than a retryable failure: the    │
 * │ mode cannot be widened remotely. MikroTik requires a reset-button press   │
 * │ or a cold power cycle within five minutes of the request, deliberately,   │
 * │ so that no remote attacker can lift the gate. There is no code path, no   │
 * │ credential and no queue job that fixes it — only somebody standing in     │
 * │ front of the box.                                                        │
 * │                                                                          │
 * │ Before these columns, ObliWAN met the denial inside `armDeadman()`: plan  │
 * │ frozen, pre-change backup already taken, one device at a time. The        │
 * │ refusal was correct and the moment was the worst available. Stored here,  │
 * │ the same fact is a column, a fleet-query field and a line on the device   │
 * │ page, readable while a change is still being PLANNED.                     │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ EVERY COLUMN IS NULLABLE, AND NULL IS NOT "ALLOWED" ────────────────────┐
 * │ Three distinguishable states, and the schema keeps them apart:            │
 * │                                                                          │
 * │  · `device_mode_observed_at IS NULL` — nobody has ever asked this router. │
 * │    Every device starts here, including the whole existing fleet after     │
 * │    this migration, and it means precisely what ObliWAN knew yesterday.    │
 * │  · `observed_at` set, `device_mode IS NULL` — we asked and got no answer. │
 * │    Pre-7.13 firmware has no such menu; a service account without the      │
 * │    policy gets a trap on one that does. Those two look identical from     │
 * │    here, which is why this is "unknown" and NOT "ungated, therefore       │
 * │    fine".                                                                │
 * │  · `device_mode` set, a flag NULL — the menu answered without printing    │
 * │    that flag. `deadmanReadiness()` (shared/src/deviceMode.ts) may infer a │
 * │    DENIAL from `home` and never an ALLOWANCE from the other two modes.    │
 * │                                                                          │
 * │ Hence no DEFAULT on any of them. A `DEFAULT true` on                     │
 * │ `device_mode_scheduler` would tell the planner, about three hundred       │
 * │ never-probed routers, that they can all carry a dead-man.                │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * On `devices` rather than in `device_capabilities.observed_overrides`: that
 * jsonb is `Partial<Record<DeviceCapabilityFlag, boolean>>`, a two-valued
 * present/absent map measured against a FAMILY baseline. Device-mode is a
 * three-valued per-unit state with its own timestamp and a mode string, and the
 * fleet query has to sort and range over it — the wrong shape and the wrong
 * home.
 */
export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable('devices', (t) => {
    t.string('device_mode', 16).nullable();
    t.boolean('device_mode_scheduler').nullable();
    t.boolean('device_mode_fetch').nullable();
    // The row as the menu printed it, for the ten-odd flags this model does not
    // name (container, romon, socks, traffic-gen …). Feature toggles only: the
    // menu carries no credential, so the secrets rule is not in play.
    t.jsonb('device_mode_raw').nullable();
    t.timestamp('device_mode_observed_at', { useTz: true }).nullable();
  });

  // An IN list of literals, not a regex: there is no `?` to be rewritten as a
  // positional binding here (the trap that cost migration 032 a whole sweep).
  await knex.schema.raw(
    'ALTER TABLE devices ADD CONSTRAINT devices_device_mode_chk ' +
      "CHECK (device_mode IS NULL OR device_mode IN ('home', 'advanced', 'enterprise'))",
  );

  // A reading with no reading TIME is not a reading. Without this, a future
  // writer that sets the mode and forgets the timestamp produces a row that
  // `deadmanReadiness()` reads as "never observed" while the page shows a mode
  // — the two halves disagreeing, silently, forever.
  await knex.schema.raw(
    'ALTER TABLE devices ADD CONSTRAINT devices_device_mode_observed_chk CHECK (' +
      'device_mode_observed_at IS NOT NULL OR (' +
      'device_mode IS NULL AND device_mode_scheduler IS NULL ' +
      'AND device_mode_fetch IS NULL AND device_mode_raw IS NULL))',
  );

  // "Show me every router that cannot be armed" — the question this feature
  // exists to answer, and the one the fleet query will ask most. Partial: on a
  // fresh install every row is NULL and a full index would be all of them.
  await knex.schema.raw(
    'CREATE INDEX devices_device_mode_idx ON devices (device_mode) ' +
      'WHERE device_mode IS NOT NULL',
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.raw('DROP INDEX IF EXISTS devices_device_mode_idx');
  await knex.schema.raw(
    'ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_device_mode_observed_chk',
  );
  await knex.schema.raw(
    'ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_device_mode_chk',
  );
  await knex.schema.alterTable('devices', (t) => {
    t.dropColumn('device_mode_observed_at');
    t.dropColumn('device_mode_raw');
    t.dropColumn('device_mode_fetch');
    t.dropColumn('device_mode_scheduler');
    t.dropColumn('device_mode');
  });
}
