import type { Knex } from 'knex';

/**
 * 063 — what the bench learns about a box that the fleet needs after it left
 * the bench: what to render its template again with (1, 2), and the SIM card
 * in its modem (3).
 *
 * The bench compile renders a revision with three kinds of values nothing
 * stored: the allocation's (`computed` — `site_provisioning` already holds
 * them), the box's facts (`box.wifi_stack`, `box.board`, `box.model`,
 * `box.ros_version`) and what the clerk typed (`bench`). The fleet render
 * (`template/render.service.ts`) read none of them, so a plan, a preview or a
 * rollout of the revision a box was prepared with ended on a variables error.
 * Model and RouterOS version are already on the device row (the compile
 * writes them); this adds the rest:
 *
 *  1. `devices.board` and `devices.wifi_stack` — read off the box by the bench
 *     and written by the compile (`persistDevice`). `wifi_stack` is what a
 *     bench template branches on (`/interface wifi` against the legacy
 *     `/interface wireless`); its CHECK is the same pair the bench accepts,
 *     written as an IN list of literals. Both nullable with NO default: a
 *     device the bench never prepared has no reading, and a default `wifi`
 *     would render the wrong Wi-Fi menu for every legacy box at once.
 *
 *  2. `bench_provisionings.bench_values` — the NON-secret values typed at the
 *     bench for that compile, as the compile typed them (`benchValuesFor`),
 *     keyed by variable — and `bench_secret_keys`, the NAMES of the secret
 *     ones that were typed. A secret's value (a SIM PIN) is NEVER stored —
 *     The secrets rule, the compile's own banner; the fleet render declares it withheld
 *     and it renders as its placeholder. Its name is kept because an
 *     optional secret typed at the bench and one left empty render
 *     differently (`{% if sim_pin %}`), and the fleet render must take the
 *     branch the box was compiled with. The audit entry of the compile already
 *     carries the same names (`substitutedSecrets`).
 *     Both NULL on a row compiled before this migration: nothing was kept
 *     then, and NULL says "unknown", never "nothing typed".
 *
 *  3. `devices.sim_iccid`, `sim_imsi`, `sim_read_at` — the SIM card the bench
 *     read in the box's modem (`lte1`) just before its reset, reported with
 *     the bench's result (`recordBenchResult`). The ICCID is what links a
 *     mobile line (`sim_lines.iccid`) to the router and the store it went
 *     into; matched on the ICCID alone, never guessed from anything else.
 *     `sim_read_at` set with no ICCID means "read, and no SIM was found";
 *     all three NULL means "never read". The ICCID CHECK is the one
 *     `sim_lines_iccid_chk` (migration 032) applies, so a reading this column
 *     holds can always be compared with a line's. NOT unique: a SIM moved from
 *     one box to another leaves the first box's reading as it was read.
 *
 * Literals only in the SQL below: knex rewrites a `?` inside raw() as a
 * binding placeholder (a known trap).
 */

export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable('devices', (t) => {
    t.string('board', 64).nullable();
    t.string('wifi_stack', 16).nullable();
  });
  await knex.schema.raw(
    'ALTER TABLE devices ADD CONSTRAINT devices_wifi_stack_chk ' +
      "CHECK (wifi_stack IS NULL OR wifi_stack IN ('wifi', 'wireless'))",
  );

  await knex.schema.alterTable('bench_provisionings', (t) => {
    t.jsonb('bench_values').nullable();
    t.jsonb('bench_secret_keys').nullable();
  });
  await knex.schema.raw(
    'ALTER TABLE bench_provisionings ADD CONSTRAINT bench_provisionings_bench_values_chk ' +
      "CHECK (bench_values IS NULL OR jsonb_typeof(bench_values) = 'object')",
  );
  await knex.schema.raw(
    'ALTER TABLE bench_provisionings ADD CONSTRAINT bench_provisionings_bench_secret_keys_chk ' +
      "CHECK (bench_secret_keys IS NULL OR jsonb_typeof(bench_secret_keys) = 'array')",
  );
  // The two are written together by the same compile, or not at all.
  await knex.schema.raw(
    'ALTER TABLE bench_provisionings ADD CONSTRAINT bench_provisionings_bench_kept_together_chk ' +
      'CHECK ((bench_values IS NULL) = (bench_secret_keys IS NULL))',
  );

  await knex.schema.alterTable('devices', (t) => {
    t.string('sim_iccid', 22).nullable();
    t.string('sim_imsi', 15).nullable();
    t.timestamp('sim_read_at', { useTz: true }).nullable();
  });
  await knex.schema.raw(
    'ALTER TABLE devices ADD CONSTRAINT devices_sim_iccid_chk ' +
      "CHECK (sim_iccid IS NULL OR sim_iccid ~ '^[0-9]{18,22}$')",
  );
  await knex.schema.raw(
    'ALTER TABLE devices ADD CONSTRAINT devices_sim_imsi_chk ' +
      "CHECK (sim_imsi IS NULL OR sim_imsi ~ '^[0-9]{6,15}$')",
  );
  // An ICCID is a reading, and a reading has its time; an IMSI without the
  // card it was read on is no reading at all.
  await knex.schema.raw(
    'ALTER TABLE devices ADD CONSTRAINT devices_sim_read_chk ' +
      'CHECK ((sim_iccid IS NULL OR sim_read_at IS NOT NULL) AND (sim_imsi IS NULL OR sim_iccid IS NOT NULL))',
  );
  // The line side's lookup ("which router holds this card"): partial, as the
  // column is NULL on every router without a modem.
  await knex.schema.raw(
    'CREATE INDEX devices_sim_iccid_idx ON devices (tenant_id, sim_iccid) WHERE sim_iccid IS NOT NULL',
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.raw('DROP INDEX IF EXISTS devices_sim_iccid_idx');
  for (const c of ['devices_sim_read_chk', 'devices_sim_imsi_chk', 'devices_sim_iccid_chk']) {
    await knex.schema.raw(`ALTER TABLE devices DROP CONSTRAINT IF EXISTS ${c}`);
  }
  await knex.schema.alterTable('devices', (t) => {
    t.dropColumn('sim_read_at');
    t.dropColumn('sim_imsi');
    t.dropColumn('sim_iccid');
  });
  for (const c of [
    'bench_provisionings_bench_kept_together_chk',
    'bench_provisionings_bench_secret_keys_chk',
    'bench_provisionings_bench_values_chk',
  ]) {
    await knex.schema.raw(`ALTER TABLE bench_provisionings DROP CONSTRAINT IF EXISTS ${c}`);
  }
  await knex.schema.alterTable('bench_provisionings', (t) => {
    t.dropColumn('bench_secret_keys');
    t.dropColumn('bench_values');
  });
  await knex.schema.raw('ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_wifi_stack_chk');
  await knex.schema.alterTable('devices', (t) => {
    t.dropColumn('wifi_stack');
    t.dropColumn('board');
  });
}
