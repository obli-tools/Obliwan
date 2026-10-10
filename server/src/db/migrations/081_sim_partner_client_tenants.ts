import type { Knex } from 'knex';

/**
 * 081 — which customer tenant a partner's CLIENT belongs to.
 *
 * ┌─ WHY ─────────────────────────────────────────────────────────────────────┐
 * │ The Phenix account lives in the Default (master) tenant and lists every   │
 * │ customer's lines, client by client (`sim_lines.client_code`). A new line  │
 * │ lands in the POOL (tenant_id NULL) and used to wait for somebody to move  │
 * │ it by hand, one line at a time. This table records the decision ONCE per  │
 * │ partner client — "Phenix client C0001 is tenant B" — and the sweep        │
 * │ applies it to the client's lines, now and on every later sweep           │
 * │ (`services/sim/clientTenant.service.ts`), CHR-reconciliation style.       │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * · One row per (account, client code): two accounts are two partner
 *   namespaces, and the same code on both is not the same customer.
 * · `decided_by` NULL means the automatic rule applied it (the only automatic
 *   case: exactly one tenant matched strongly by BOTH name and site codes) —
 *   never "unknown operator"; the audit ledger names the actor either way.
 * · Deleting a tenant deletes its mappings (the lines go back to being
 *   unmapped; `sim_lines.tenant_id` is SET NULL by migration 032 already).
 *
 * No `?` in any raw statement (knex binding trap, migration 032).
 */
export async function up(knex: Knex): Promise<void> {
  await knex.schema.createTable('sim_partner_client_tenants', (t) => {
    t.increments('id').primary();
    t.integer('account_id').notNullable().references('id').inTable('sim_accounts').onDelete('CASCADE');
    t.text('client_code').notNullable();
    t.integer('tenant_id').notNullable().references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('decided_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.timestamp('decided_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.unique(['account_id', 'client_code']);
    t.index(['tenant_id']);
  });
  await knex.schema.raw(
    'ALTER TABLE sim_partner_client_tenants ADD CONSTRAINT sim_partner_client_tenants_code_chk ' +
      "CHECK (btrim(client_code) <> '')",
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists('sim_partner_client_tenants');
}
