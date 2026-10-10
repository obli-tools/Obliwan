import type { Knex } from 'knex';

/**
 * 035_site_variables.ts — a SITE level in the template-variable chain.
 *
 * ┌─ WHY A SITE LEVEL, AND WHY BETWEEN GROUP AND DEVICE ─────────────────────┐
 * │ A customer premises has values of its own — a VLAN id, a LAN subnet, a   │
 * │ site code — and before this migration the only place to put them was the │
 * │ DEVICE. That fails exactly when it matters: on the provisioning bench    │
 * │ the router does not exist in the fleet yet, so there is no device row to │
 * │ hang a value on, and a router swap would lose every value it carried.    │
 * │ The site outlives the box, so the site holds the value.                  │
 * │                                                                          │
 * │ Precedence becomes global < tenant < group (root .. leaf) < SITE <       │
 * │ device. A group is a fleet-wide grouping and states a POLICY ("our       │
 * │ branches use VLAN 10"); a site is one premises and states a FACT about it │
 * │ ("this branch uses VLAN 835"), so the fact wins over the policy. A       │
 * │ device override still beats both: it is the one escape hatch for a      │
 * │ router that must differ from its own premises.                           │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHAT THIS MIGRATION DOES NOT ADD, AND WHY ──────────────────────────────┐
 * │ No new unique index. Migration 008's decision 3 already covers a site    │
 * │ row: `config_variables_scoped_uq` is `(tenant_id, scope, scope_id, key)  │
 * │ WHERE scope_id IS NOT NULL`, `scope` is IN the key, and a site row has a │
 * │ non-NULL `scope_id` by the CHECK below. A second index on the same       │
 * │ columns for `scope = 'site'` would constrain nothing the first does not, │
 * │ double the write cost, and be one more thing a later reader takes for a  │
 * │ rule of its own. The resolver's upsert already names that index's WHERE  │
 * │ clause for every scoped level, the site included.                        │
 * │                                                                          │
 * │ No foreign key on `scope_id` either — it is polymorphic (group, site or  │
 * │ device id depending on `scope`), the trade-off 008 made for the other    │
 * │ levels. The resolver joins `sites` with `tenant_id = :tenantId`, so a    │
 * │ dangling or foreign site id resolves to nothing, never to another        │
 * │ customer's values; the controller refuses to write one in the first      │
 * │ place.                                                                   │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The `permission_sets` rows seeded by migration 001 for `admin` and
 * `operator` are given `site_variables.write`, so that the bundles exposed to
 * Obligate say what the runtime matrix (`BUILTIN_PERMISSION_SETS` in
 * `@obliwan/shared`) already grants. Only the two DEFAULT rows, and only when
 * the value is absent: a fresh install seeds 001 from the current shared
 * package and already carries it.
 *
 * No `?` anywhere in the raw SQL below: knex rewrites it into a positional
 * binding (the trap that cost migration 032 a whole sweep). The jsonb tests use
 * `@>` for that reason, not the `?` key-exists operator.
 */

// Inlined literals rather than imports, exactly as 008 does: a migration keeps
// describing the schema as it was on the day it ran.
const SCOPES_008 = "'global','tenant','group','device'";
const SCOPES_035 = "'global','tenant','group','site','device'";

const CAPABILITY = 'site_variables.write';

export async function up(knex: Knex): Promise<void> {
  await knex.schema.raw('ALTER TABLE config_variables DROP CONSTRAINT config_variables_scope_chk');
  await knex.schema.raw(
    'ALTER TABLE config_variables ADD CONSTRAINT config_variables_scope_chk ' +
      `CHECK (scope IN (${SCOPES_035}))`,
  );

  // `scope_id` stays NULL for exactly the two levels whose identity is the
  // tenant itself, and is REQUIRED for every other one. A site row with a NULL
  // scope_id would fall into the UNSCOPED unique index and behave, silently, as
  // a tenant-wide variable for the whole fleet.
  await knex.schema.raw(
    'ALTER TABLE config_variables DROP CONSTRAINT config_variables_scope_id_chk',
  );
  await knex.schema.raw(
    'ALTER TABLE config_variables ADD CONSTRAINT config_variables_scope_id_chk CHECK (' +
      "(scope IN ('global','tenant') AND scope_id IS NULL) OR " +
      "(scope IN ('group','site','device') AND scope_id IS NOT NULL))",
  );

  await knex.schema.raw(
    'UPDATE permission_sets ' +
      `SET capabilities = capabilities || '["${CAPABILITY}"]'::jsonb ` +
      "WHERE slug IN ('admin','operator') AND is_default = true " +
      `AND NOT (capabilities @> '["${CAPABILITY}"]'::jsonb)`,
  );
}

export async function down(knex: Knex): Promise<void> {
  // The narrower CHECK cannot be re-added while a site row exists, so the site
  // values go first. They are DELETED, not moved: there is no lower level that
  // means the same thing, and copying them onto every device of the site would
  // invent device overrides nobody typed.
  await knex('config_variables').where('scope', 'site').del();

  await knex.schema.raw(
    'ALTER TABLE config_variables DROP CONSTRAINT config_variables_scope_id_chk',
  );
  await knex.schema.raw(
    'ALTER TABLE config_variables ADD CONSTRAINT config_variables_scope_id_chk CHECK (' +
      "(scope IN ('global','tenant') AND scope_id IS NULL) OR " +
      "(scope IN ('group','device') AND scope_id IS NOT NULL))",
  );
  await knex.schema.raw('ALTER TABLE config_variables DROP CONSTRAINT config_variables_scope_chk');
  await knex.schema.raw(
    'ALTER TABLE config_variables ADD CONSTRAINT config_variables_scope_chk ' +
      `CHECK (scope IN (${SCOPES_008}))`,
  );

  // `jsonb - text` drops every array element equal to the string.
  await knex.schema.raw(
    `UPDATE permission_sets SET capabilities = capabilities - '${CAPABILITY}' ` +
      "WHERE slug IN ('admin','operator') AND is_default = true",
  );
}
