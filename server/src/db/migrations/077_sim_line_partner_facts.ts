import type { Knex } from 'knex';

/**
 * 077 — everything the partner's inventory listing says about a SIM line.
 *
 * ┌─ WHY ─────────────────────────────────────────────────────────────────────┐
 * │ The production Phenix extranet was observed on 2026-10-06 (a HAR of the   │
 * │ operator's session). Its line listing — client by client, paged — carries │
 * │ far more than the MSISDN / operator / client code `sim_lines` kept: the    │
 * │ SIM serial (an ICCID when it is 20 digits), the IMSI, the plan, the       │
 * │ activation and termination dates, the APN, the fixed IP, the RADIUS login,│
 * │ this month's and last month's consumption — and three secrets: `puk1`,    │
 * │ `puk2`, `radiusPassword`.                                                 │
 * │                                                                          │
 * │ OPERATOR DECISION (2026-10-06): « ObliWAN doit avoir toutes les infos ».  │
 * │ Every field is kept: typed columns for what the product reads, and        │
 * │ `partner_details` (jsonb) carrying the remaining NON-SECRET fields        │
 * │ verbatim, so nothing observed is lost.                                    │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE RULES THE SCHEMA KEEPS ──────────────────────────────────────────────┐
 * │ · The three secrets are VAULT BLOBS (`secretVault.encrypt`, AES-256-GCM,  │
 * │   `OBLIWAN_ENCRYPTION_KEY`) with the key generation in                    │
 * │   `secrets_key_version`, like every other encrypted column. A CHECK       │
 * │   refuses anything that is not a `v1:` blob, so a plaintext cannot be     │
 * │   stored here by a defect — the database says no, not a reviewer. They    │
 * │   are NEVER in `partner_details`.                                         │
 * │ · Consumption is `numeric(14,3)` MB, nullable, no DEFAULT: the partner    │
 * │   prints "1234,56" (decimal MB) and "" when it does not know, and "" is   │
 * │   NULL — never 0 (the SIM rule). It is what was USED; no column here is a  │
 * │   remaining balance, because the listing carries none.                    │
 * │ · Partner-provided strings are `text`: a width CHECK on data we do not    │
 * │   own makes one long value abort the line's upsert (sync.service's own    │
 * │   warning about migration 032's widths).                                  │
 * │ · `partner_details` is a JSON OBJECT and is dated: a set of partner facts │
 * │   always carries the instant a listing said them (`partner_observed_at`). │
 * │ · `status` gains `terminated` — the partner's "Deleted" / « Résiliée ».   │
 * │   A terminated line is KEPT, with its `terminated_at`.                    │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * No `?` in any raw statement (the knex binding trap of migration 032): the
 * statuses are an IN list of literals and the blob test is a LIKE.
 */

const CONSUMPTION_COLUMNS = ['data_nat_mb', 'data_roam_mb', 'data_nat_prev_mb', 'data_roam_prev_mb'] as const;
const SECRET_COLUMNS = ['puk1_enc', 'puk2_enc', 'radius_password_enc'] as const;

export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable('sim_lines', (t) => {
    t.text('partner_line_id').nullable();
    t.text('sim_serial').nullable();
    t.text('imsi').nullable();
    t.text('customer_name').nullable();
    t.text('partner_site_label').nullable();
    t.text('internal_ref').nullable();
    t.text('partner_state').nullable();
    t.text('partner_state_label').nullable();
    t.text('sim_type').nullable();
    t.text('plan_label').nullable();
    t.text('plan_code').nullable();
    t.timestamp('activated_at', { useTz: true }).nullable();
    t.timestamp('terminated_at', { useTz: true }).nullable();
    t.boolean('data_only').nullable();
    t.text('apn').nullable();
    t.text('fixed_ip').nullable();
    t.boolean('has_fixed_ip').nullable();
    t.text('radius_login').nullable();
    for (const c of CONSUMPTION_COLUMNS) t.decimal(c, 14, 3).nullable();
    t.jsonb('partner_details').nullable();
    t.timestamp('partner_observed_at', { useTz: true }).nullable();
    for (const c of SECRET_COLUMNS) t.text(c).nullable();
    t.integer('secrets_key_version').nullable();
  });

  await knex.schema.raw('ALTER TABLE sim_lines DROP CONSTRAINT IF EXISTS sim_lines_status_chk');
  await knex.schema.raw(
    'ALTER TABLE sim_lines ADD CONSTRAINT sim_lines_status_chk ' +
      "CHECK (status IN ('active','suspended','terminated','unknown'))",
  );

  await knex.schema.raw(
    'ALTER TABLE sim_lines ADD CONSTRAINT sim_lines_consumption_chk CHECK (' +
      CONSUMPTION_COLUMNS.map((c) => `(${c} IS NULL OR ${c} >= 0)`).join(' AND ') +
      ')',
  );

  // A stored secret is a vault blob, and a blob always says which key made it.
  await knex.schema.raw(
    'ALTER TABLE sim_lines ADD CONSTRAINT sim_lines_secret_blob_chk CHECK (' +
      SECRET_COLUMNS.map((c) => `(${c} IS NULL OR ${c} LIKE 'v1:%')`).join(' AND ') +
      ')',
  );
  await knex.schema.raw(
    'ALTER TABLE sim_lines ADD CONSTRAINT sim_lines_secret_key_chk CHECK (' +
      '(secrets_key_version IS NULL OR secrets_key_version >= 1) AND (' +
      SECRET_COLUMNS.map((c) => `${c} IS NULL`).join(' AND ') +
      ' OR secrets_key_version IS NOT NULL))',
  );

  await knex.schema.raw(
    'ALTER TABLE sim_lines ADD CONSTRAINT sim_lines_partner_details_chk CHECK (' +
      "partner_details IS NULL OR (jsonb_typeof(partner_details) = 'object' " +
      'AND partner_observed_at IS NOT NULL))',
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.raw('ALTER TABLE sim_lines DROP CONSTRAINT IF EXISTS sim_lines_partner_details_chk');
  await knex.schema.raw('ALTER TABLE sim_lines DROP CONSTRAINT IF EXISTS sim_lines_secret_key_chk');
  await knex.schema.raw('ALTER TABLE sim_lines DROP CONSTRAINT IF EXISTS sim_lines_secret_blob_chk');
  await knex.schema.raw('ALTER TABLE sim_lines DROP CONSTRAINT IF EXISTS sim_lines_consumption_chk');
  await knex.schema.raw('ALTER TABLE sim_lines DROP CONSTRAINT IF EXISTS sim_lines_status_chk');
  // The pre-077 vocabulary has no `terminated`: such a line goes back to
  // `unknown`, which is what migration 032 called a state it could not read.
  await knex('sim_lines').where('status', 'terminated').update({ status: 'unknown' });
  await knex.schema.raw(
    'ALTER TABLE sim_lines ADD CONSTRAINT sim_lines_status_chk ' +
      "CHECK (status IN ('active','suspended','unknown'))",
  );
  await knex.schema.alterTable('sim_lines', (t) => {
    t.dropColumn('secrets_key_version');
    for (const c of SECRET_COLUMNS) t.dropColumn(c);
    t.dropColumn('partner_observed_at');
    t.dropColumn('partner_details');
    for (const c of CONSUMPTION_COLUMNS) t.dropColumn(c);
    t.dropColumn('radius_login');
    t.dropColumn('has_fixed_ip');
    t.dropColumn('fixed_ip');
    t.dropColumn('apn');
    t.dropColumn('data_only');
    t.dropColumn('terminated_at');
    t.dropColumn('activated_at');
    t.dropColumn('plan_code');
    t.dropColumn('plan_label');
    t.dropColumn('sim_type');
    t.dropColumn('partner_state_label');
    t.dropColumn('partner_state');
    t.dropColumn('internal_ref');
    t.dropColumn('partner_site_label');
    t.dropColumn('customer_name');
    t.dropColumn('imsi');
    t.dropColumn('sim_serial');
    t.dropColumn('partner_line_id');
  });
}
