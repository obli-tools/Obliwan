import type { Knex } from 'knex';

/**
 * 080 — the SIM card in each LTE modem of a router, as the FLEET reads it,
 * and the SIM line links that reading could not make.
 *
 * ┌─ device_lte_modems ──────────────────────────────────────────────────────┐
 * │ One row per (device, LTE interface): `lte1`, `lte2`… as the router lists │
 * │ them. Read by the health check on the API session it already holds      │
 * │ (`fleet/lteModem.service.ts`), so a router that never went through the   │
 * │ bench — or whose card was swapped after it — still says which card it    │
 * │ carries. The bench's own reading stays on `devices.sim_iccid` (063).     │
 * │ · `iccid`, `imsi`, `imei` are NULL when the modem did not print them:     │
 * │   NOT READ, never "no SIM". No DEFAULT on any of them, and none on        │
 * │   `observed_at` either: a row exists only because a modem answered, at   │
 * │   the instant written by the code that heard it.                         │
 * │ · `iccid` keeps the shape `sim_lines.iccid` holds (18 to 22 digits).     │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ sim_link_conflicts ─────────────────────────────────────────────────────┐
 * │ A card read in a router matched a line that could NOT be linked to it:   │
 * │ the line is another tenant's (`other_tenant`), already linked to another │
 * │ router (`linked_elsewhere`), or the card was read in several routers     │
 * │ (`ambiguous`). Nothing is moved; the row is what the SIM reconciliation  │
 * │ shows a platform operator. A later pass that finds the conflict gone      │
 * │ deletes its row.                                                         │
 * │ · `dismissed_at` / `dismissed_by` / `dismissed_note`: an operator looked  │
 * │   and decided nothing should move (a card left in a router in stock…).   │
 * │   A later pass that finds the SAME conflict (same kind, same card read)  │
 * │   keeps the dismissal; a different one reopens it — a dismissal answers  │
 * │   the situation that was shown, not the next one. `dismissed_by` is SET  │
 * │   NULL with its user, the instant stays (081's `decided_by` rule).       │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * No `?` in any raw statement (the knex binding trap, migration 032): the
 * shapes are written with `{n,m}` quantifiers and the kinds as an IN list.
 */
export async function up(knex: Knex): Promise<void> {
  await knex.schema.createTable('device_lte_modems', (t) => {
    t.increments('id').primary();
    t.integer('device_id').notNullable().references('id').inTable('devices').onDelete('CASCADE');
    t.text('interface').notNullable();
    t.string('iccid', 22).nullable();
    t.string('imsi', 15).nullable();
    t.string('imei', 17).nullable();
    t.timestamp('observed_at', { useTz: true }).notNullable();
    t.unique(['device_id', 'interface']);
  });
  await knex.raw(
    `ALTER TABLE device_lte_modems ADD CONSTRAINT device_lte_modems_iccid_chk `
      + `CHECK (iccid IS NULL OR iccid ~ '^[0-9]{18,22}$')`,
  );
  await knex.raw(
    `ALTER TABLE device_lte_modems ADD CONSTRAINT device_lte_modems_imsi_chk `
      + `CHECK (imsi IS NULL OR imsi ~ '^[0-9]{6,15}$')`,
  );
  await knex.raw(
    `ALTER TABLE device_lte_modems ADD CONSTRAINT device_lte_modems_imei_chk `
      + `CHECK (imei IS NULL OR imei ~ '^[0-9]{14,17}$')`,
  );
  await knex.raw(
    `ALTER TABLE device_lte_modems ADD CONSTRAINT device_lte_modems_iface_chk `
      + `CHECK (length(interface) BETWEEN 1 AND 64)`,
  );
  await knex.raw('CREATE INDEX device_lte_modems_iccid_idx ON device_lte_modems (iccid) WHERE iccid IS NOT NULL');

  await knex.schema.createTable('sim_link_conflicts', (t) => {
    t.increments('id').primary();
    t.integer('line_id').notNullable().references('id').inTable('sim_lines').onDelete('CASCADE');
    t.integer('device_id').notNullable().references('id').inTable('devices').onDelete('CASCADE');
    t.text('kind').notNullable();
    t.string('iccid_read', 22).notNullable();
    /** True when the two ICCIDs matched on their first 19 digits only. */
    t.boolean('prefix_match').notNullable();
    t.timestamp('detected_at', { useTz: true }).notNullable();
    t.timestamp('last_seen_at', { useTz: true }).notNullable();
    t.timestamp('dismissed_at', { useTz: true }).nullable();
    t.integer('dismissed_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.text('dismissed_note').nullable();
    t.unique(['line_id', 'device_id']);
  });
  await knex.raw(
    `ALTER TABLE sim_link_conflicts ADD CONSTRAINT sim_link_conflicts_kind_chk `
      + `CHECK (kind IN ('other_tenant', 'linked_elsewhere', 'ambiguous'))`,
  );
  // Nobody and no note without an instant; a note is a sentence, not a file.
  await knex.raw(
    `ALTER TABLE sim_link_conflicts ADD CONSTRAINT sim_link_conflicts_dismissed_chk `
      + `CHECK (dismissed_at IS NOT NULL OR (dismissed_by IS NULL AND dismissed_note IS NULL))`,
  );
  await knex.raw(
    `ALTER TABLE sim_link_conflicts ADD CONSTRAINT sim_link_conflicts_note_chk `
      + `CHECK (dismissed_note IS NULL OR length(dismissed_note) BETWEEN 1 AND 500)`,
  );
  await knex.raw('CREATE INDEX sim_link_conflicts_device_idx ON sim_link_conflicts (device_id)');
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists('sim_link_conflicts');
  await knex.schema.dropTableIfExists('device_lte_modems');
}
