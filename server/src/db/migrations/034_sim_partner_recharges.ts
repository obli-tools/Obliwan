import type { Knex } from 'knex';

/**
 * ObliWAN — what the PARTNER says was bought, beside what ObliWAN decided.
 *
 * ┌─ TWO LEDGERS, AND WHY THEY ARE NOT MERGED ────────────────────────────────┐
 * │ `sim_recharges` is ObliWAN's own record: a proposal, a human decision,     │
 * │ a completion. `sim_partner_recharges` is an OBSERVATION: one row per line  │
 * │ of the partner's "Historique des recharges data", read by the sweep.      │
 * │                                                                          │
 * │ They are different facts from different authorities, and folding the    │
 * │ second into the first would let a partner row rewrite a billing record   │
 * │ nobody approved. So the observation is stored verbatim and LINKED to a    │
 * │ decision (`recharge_id`) only when the match is unambiguous — see        │
 * │ `recharge.service.reconcilePartnerRecharges`. An unlinked row is not an  │
 * │ error: it is a top-up bought on the portal without a proposal, and the    │
 * │ line screen shows it as exactly that.                                     │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * `partner_ref` is the partner's own row id when it sends one, otherwise a key
 * synthesised from the row's own fields by the connector. UNIQUE per account,
 * so a history re-read every sweep inserts nothing new — the same contract as
 * `UNIQUE(device_id, ncm_hash)` on snapshots.
 *
 * `outcome` is OUR interpretation of the partner's `etat`/`statut`; both raw
 * values are kept beside it, because the interpretation is reasoned from one
 * screenshot ("1" / "OK") and will be wrong for some value nobody has seen yet.
 * An unrecognised value is `unknown`, never `ok`: an `ok` is what links a row to
 * a billing record.
 *
 * No regex anywhere in this file: knex rewrites `?` inside `raw()`.
 */

const OUTCOMES = `'ok','pending','failed','unknown'`;

export async function up(knex: Knex): Promise<void> {
  // The two line attributes the partner's volume catalogue is keyed on. Filled
  // by the sweep when the listing carries them; never cleared by a listing
  // that omits them (same rule as `iccid`).
  await knex.schema.alterTable('sim_lines', (t) => {
    t.string('offer_type', 80).nullable();
    t.string('purchase_tariff_code', 80).nullable();
    t.timestamp('partner_history_read_at', { useTz: true }).nullable();
  });

  await knex.schema.createTable('sim_partner_recharges', (t) => {
    t.bigIncrements('id').primary();
    t.integer('account_id')
      .notNullable()
      .references('id')
      .inTable('sim_accounts')
      .onDelete('CASCADE');
    t.integer('sim_id').nullable().references('id').inTable('sim_lines').onDelete('SET NULL');
    t.string('msisdn', 24).notNullable();
    t.string('partner_ref', 190).notNullable();

    t.timestamp('requested_at', { useTz: true }).nullable();
    /** 'YYYY-MM', the partner's "Mois / Année". */
    t.string('period', 7).nullable();
    t.string('zone_code', 40).nullable();
    t.integer('volume_mb').nullable();
    t.string('product_code', 40).nullable();
    t.string('partner_state', 40).nullable();
    t.string('partner_status', 40).nullable();
    t.string('outcome', 16).notNullable();

    t.bigInteger('recharge_id')
      .nullable()
      .references('id')
      .inTable('sim_recharges')
      .onDelete('SET NULL');

    t.timestamp('first_seen_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('last_seen_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.raw(
    `ALTER TABLE sim_partner_recharges ADD CONSTRAINT sim_partner_recharges_outcome_chk ` +
      `CHECK (outcome IN (${OUTCOMES}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE sim_partner_recharges ADD CONSTRAINT sim_partner_recharges_volume_chk ` +
      `CHECK (volume_mb IS NULL OR volume_mb > 0)`,
  );
  await knex.schema.raw(
    `ALTER TABLE sim_partner_recharges ADD CONSTRAINT sim_partner_recharges_ref_chk ` +
      `CHECK (btrim(partner_ref) <> '')`,
  );
  await knex.schema.raw(
    `ALTER TABLE sim_partner_recharges ADD CONSTRAINT sim_partner_recharges_ref_uq ` +
      `UNIQUE (account_id, partner_ref)`,
  );
  // One partner purchase settles at most one decision, and one decision is
  // settled by at most one purchase. Without the second index a re-read could
  // link two history rows to the same approval and the report would bill the
  // first one twice.
  await knex.schema.raw(
    `CREATE UNIQUE INDEX sim_partner_recharges_recharge_uq ` +
      `ON sim_partner_recharges (recharge_id) WHERE recharge_id IS NOT NULL`,
  );
  await knex.schema.raw(
    `CREATE INDEX sim_partner_recharges_sim_idx ` +
      `ON sim_partner_recharges (sim_id, requested_at DESC)`,
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists('sim_partner_recharges');
  await knex.schema.alterTable('sim_lines', (t) => {
    t.dropColumn('partner_history_read_at');
    t.dropColumn('purchase_tariff_code');
    t.dropColumn('offer_type');
  });
}
