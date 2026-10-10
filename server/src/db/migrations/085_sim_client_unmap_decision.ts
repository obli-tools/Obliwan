import type { Knex } from 'knex';

/**
 * 085 — removing a partner client's workspace mapping is a DECISION, recorded.
 *
 * ┌─ WHY ─────────────────────────────────────────────────────────────────────┐
 * │ Un-mapping a client used to DELETE its `sim_partner_client_tenants` row.  │
 * │ The automatic rule (`listSimClients` `autoTenantId`: no row, exactly one   │
 * │ strong candidate) then saw an unmapped client and the next sweep          │
 * │ (`applyClientMappingsForAccount`) mapped it straight back — an operator's │
 * │ removal of an auto-mapped client was undone within hours.                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * A row with `tenant_id` NULL now records a HUMAN decision: "this partner
 * client belongs to no workspace" — `decided_by` the operator, `decided_at`
 * when — written by `setClientMapping` when a mapping is removed. The
 * automatic rule and the sweep never map or move that client again until a
 * human maps it (which overwrites the row).
 *
 * Unchanged: the FK to `tenants` ON DELETE CASCADE (a NULL row references no
 * tenant, so a tenant purge never touches it), UNIQUE (account_id,
 * client_code), and the code CHECK.
 *
 * down() forgets the "do not re-suggest" decisions (it deletes the NULL rows)
 * and restores NOT NULL; it never invents a tenant.
 *
 * No `?` in any raw statement (knex binding trap, migration 032).
 */
export async function up(knex: Knex): Promise<void> {
  await knex.schema.raw('ALTER TABLE sim_partner_client_tenants ALTER COLUMN tenant_id DROP NOT NULL');
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.raw('DELETE FROM sim_partner_client_tenants WHERE tenant_id IS NULL');
  await knex.schema.raw('ALTER TABLE sim_partner_client_tenants ALTER COLUMN tenant_id SET NOT NULL');
}
