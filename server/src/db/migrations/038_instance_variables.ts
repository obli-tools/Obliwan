import type { Knex } from 'knex';

/**
 * 038_instance_variables.ts — an INSTANCE level in the template-variable chain:
 * one value shared by every tenant of the installation.
 *
 * ┌─ WHY A LEVEL BELOW `global` ─────────────────────────────────────────────┐
 * │ `global` is not global. The chain query filters every level on           │
 * │ `tenant_id`, so a `global` row is one tenant's widest value, and a       │
 * │ fleet-wide secret — the management L2TP password every CPE dials the    │
 * │ concentrator with, the SNMP community, the hotline account's password —  │
 * │ had to be typed again into every tenant, and rotated again in every      │
 * │ tenant, with nothing to say they had drifted apart.                      │
 * │                                                                          │
 * │ Precedence becomes instance < global < tenant < group < site < device:   │
 * │ the platform offers a value, any tenant that sets the same key anywhere  │
 * │ in its own chain overrides it for its own routers only.                  │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHAT CHANGES IN THE TABLE, AND WHAT DOES NOT ───────────────────────────┐
 * │ `tenant_id` loses its NOT NULL — and ONLY for `scope = 'instance'`: the  │
 * │ new CHECK `config_variables_instance_tenant_chk` says a row has a NULL   │
 * │ tenant exactly when it is an instance row, both ways. Every tenant-level │
 * │ row is therefore exactly as constrained as before, and an instance row   │
 * │ cannot quietly acquire a tenant (which would make it one customer's).    │
 * │                                                                          │
 * │ An instance row has a NULL `scope_id`, like `global` and `tenant`.       │
 * │                                                                          │
 * │ Uniqueness needs an index of its own. `config_variables_unscoped_uq` is  │
 * │ `(tenant_id, scope, key) WHERE scope_id IS NULL`, and PostgreSQL 16 is   │
 * │ NULLS DISTINCT: with a NULL `tenant_id`, two instance rows for the same  │
 * │ key would both fit in it. `config_variables_instance_uq` is `(key)       │
 * │ WHERE scope = 'instance'`, the partial-unique-index shape 008 uses, and  │
 * │ the resolver's upsert names that WHERE clause in its conflict target.    │
 * │                                                                          │
 * │ The tenant foreign key stays: a NULL satisfies it, and a non-NULL tenant │
 * │ still has to exist and still cascades.                                   │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ `computed` AND `bench` ARE NOT HERE, ON PURPOSE ─────────────────────────┐
 * │ Templates may declare a variable at those two levels too, but neither is │
 * │ ever STORED: a computed value is supplied by ObliWAN at render time (the │
 * │ allocator), a bench value is typed at the bench for one box and kept in  │
 * │ memory only. The scope CHECK below keeps them out of the table,          │
 * │ so "never writable" is a constraint, not only a route that happens not   │
 * │ to exist.                                                                │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * No `?` anywhere in the SQL below: knex rewrites it into a positional binding
 * (the trap that cost migration 032 a whole sweep).
 */

// Inlined literals rather than imports, as 008 and 035 do: a migration keeps
// describing the schema as it was on the day it ran.
const SCOPES_035 = "'global','tenant','group','site','device'";
const SCOPES_038 = "'instance','global','tenant','group','site','device'";

export async function up(knex: Knex): Promise<void> {
  await knex.schema.raw('ALTER TABLE config_variables DROP CONSTRAINT config_variables_scope_chk');
  await knex.schema.raw(
    'ALTER TABLE config_variables ADD CONSTRAINT config_variables_scope_chk ' +
      `CHECK (scope IN (${SCOPES_038}))`,
  );

  await knex.schema.raw(
    'ALTER TABLE config_variables DROP CONSTRAINT config_variables_scope_id_chk',
  );
  await knex.schema.raw(
    'ALTER TABLE config_variables ADD CONSTRAINT config_variables_scope_id_chk CHECK (' +
      "(scope IN ('instance','global','tenant') AND scope_id IS NULL) OR " +
      "(scope IN ('group','site','device') AND scope_id IS NOT NULL))",
  );

  await knex.schema.raw('ALTER TABLE config_variables ALTER COLUMN tenant_id DROP NOT NULL');
  // Both directions in one expression: an instance row has no tenant, and a
  // row with no tenant is an instance row. Neither side can be NULL (`scope` is
  // NOT NULL, `IS NULL` never is), so the CHECK cannot pass by being unknown.
  await knex.schema.raw(
    'ALTER TABLE config_variables ADD CONSTRAINT config_variables_instance_tenant_chk ' +
      "CHECK ((scope = 'instance') = (tenant_id IS NULL))",
  );

  await knex.schema.raw(
    'CREATE UNIQUE INDEX config_variables_instance_uq ' +
      "ON config_variables (key) WHERE scope = 'instance'",
  );
}

export async function down(knex: Knex): Promise<void> {
  // The NOT NULL and the narrower CHECKs cannot come back while an instance
  // row exists, so the instance values go first. They are DELETED, not copied
  // into each tenant's `global` level: that would invent per-tenant values
  // nobody typed, secrets included, in every customer's name at once.
  await knex('config_variables').where('scope', 'instance').del();

  await knex.schema.raw('DROP INDEX IF EXISTS config_variables_instance_uq');
  await knex.schema.raw(
    'ALTER TABLE config_variables DROP CONSTRAINT config_variables_instance_tenant_chk',
  );
  await knex.schema.raw('ALTER TABLE config_variables ALTER COLUMN tenant_id SET NOT NULL');

  await knex.schema.raw(
    'ALTER TABLE config_variables DROP CONSTRAINT config_variables_scope_id_chk',
  );
  await knex.schema.raw(
    'ALTER TABLE config_variables ADD CONSTRAINT config_variables_scope_id_chk CHECK (' +
      "(scope IN ('global','tenant') AND scope_id IS NULL) OR " +
      "(scope IN ('group','site','device') AND scope_id IS NOT NULL))",
  );
  await knex.schema.raw('ALTER TABLE config_variables DROP CONSTRAINT config_variables_scope_chk');
  await knex.schema.raw(
    'ALTER TABLE config_variables ADD CONSTRAINT config_variables_scope_chk ' +
      `CHECK (scope IN (${SCOPES_035}))`,
  );
}
