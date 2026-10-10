import type { Knex } from 'knex';

/**
 * 062 — the `reconcile.read` capability in the `permission_sets` catalogue.
 *
 * RECONCILE_READ (`@obliwan/shared` capabilities.ts) lets a tenant user see
 * her OWN tenant's CHR <-> sites reconciliation, redacted, and re-read the
 * concentrator behind it — the operator's "view + re-read" decision for the
 * account manager. The runtime matrix lives in code (permission.service
 * `TENANT_ROLE_CAPABILITIES`, built from `BUILTIN_PERMISSION_SETS`); this
 * table is the catalogue Obligate and the admin screens read, and it must say
 * the same thing. Two rows, each only when the value is ABSENT:
 *
 *  1. the `account_manager` default row (seeded by 051 with five
 *     capabilities) gets `reconcile.read`, the sixth;
 *  2. the `admin` default row — "every capability", 001 — gets it too, the
 *     same repair 035 and 051 made for the capabilities they introduced.
 *
 * A fresh install seeds 001 from the CURRENT shared package, whose sets
 * already carry it (and 051 then inserts nothing over the existing row), so
 * the `@>` test is the whole idempotence story. A hand-made set is left as
 * typed.
 *
 * No `?` anywhere in the raw SQL: knex rewrites it into a positional binding
 * (the trap that cost 032 a sweep). The jsonb tests use `@>` for that reason.
 */

const CAPABILITY = 'reconcile.read';
const ROWS = "('admin', 'account_manager')";

export async function up(knex: Knex): Promise<void> {
  await knex.schema.raw(
    'UPDATE permission_sets ' +
      `SET capabilities = capabilities || '["${CAPABILITY}"]'::jsonb ` +
      `WHERE slug IN ${ROWS} AND is_default = true ` +
      `AND NOT (capabilities @> '["${CAPABILITY}"]'::jsonb)`,
  );
}

export async function down(knex: Knex): Promise<void> {
  // `jsonb - text` drops every array element equal to the string. Only the two
  // default rows, mirroring `up()`; a pinned grant naming `reconcile.read` is
  // dropped at read time by the pre-062 code (`sanitizeCapabilities` keeps
  // only values it knows), so nothing widens on a rollback.
  await knex.schema.raw(
    `UPDATE permission_sets SET capabilities = capabilities - '${CAPABILITY}' ` +
      `WHERE slug IN ${ROWS} AND is_default = true`,
  );
}
