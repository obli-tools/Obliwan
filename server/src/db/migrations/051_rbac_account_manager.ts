import type { Knex } from 'knex';

/**
 * 051 — the `account_manager` tenant role, its builtin permission set, and the
 * `site.write` capability (no role fitted an account
 * manager).
 *
 * Three changes, one per line of `up()`:
 *
 *  1. `user_tenants.role` accepts a THIRD value. The capability matrix
 *     (permission.service `TENANT_ROLE_CAPABILITIES`) reads that column, and
 *     001's CHECK exists precisely so it can hold nothing the matrix does not
 *     know. It had to be a ROLE rather than a pinned grant:
 *     pinned team capabilities and Obligate assertions are UNIONED with the
 *     role, so they can widen a member and never narrow one — and the account
 *     manager must NOT hold most of what a member holds (CONFIG_READ,
 *     DEVICE_WRITE, DEVICE_DISCOVER, PLAN_CREATE, DRIFT_MANAGE, QUERY_RUN).
 *
 *  2. The `permission_sets` catalogue gets the `account_manager` row, the way
 *     001 seeded the others (`is_default = true`). Only when ABSENT: a fresh
 *     install runs 001 against the current `@obliwan/shared`, whose
 *     `BUILTIN_PERMISSION_SETS` already carries it, so `ON CONFLICT (slug) DO
 *     NOTHING` is the whole idempotence story. The list is inlined as literals,
 *     like 035 and 008 do: a migration keeps describing the vocabulary as it
 *     was on the day it ran, and the harness compares the two.
 *
 *  3. The `admin` default row — "every capability", 001 — gets `site.write`,
 *     the same repair 035 made for `site_variables.write`. Nothing grants it
 *     to a role through this table (`permission_sets` is a catalogue: the
 *     runtime matrix lives in code), but a catalogue that omits a capability
 *     from "everything" is a catalogue that lies.
 *
 * SIM_RECHARGE stays out of the new row, as it is out of every builtin set,
 * and so does SIM_MANAGE: the role SEES the SIM lines and attaches none.
 *
 * No `?` anywhere in the raw SQL: knex rewrites it into a positional binding
 * (the trap that cost 032 a sweep). The jsonb tests use `@>` for that reason.
 */

const ROLES_001 = "'admin','member'";
const ROLES_051 = "'admin','member','account_manager'";

const ROLE = 'account_manager';
const SITE_WRITE = 'site.write';

/** `BUILTIN_PERMISSION_SETS` → `account_manager`, as of this migration. */
const ACCOUNT_MANAGER_CAPABILITIES = [
  'device.read',
  'site.write',
  'site_variables.write',
  'snmp.read',
  'sim.read',
];

export async function up(knex: Knex): Promise<void> {
  await knex.schema.raw('ALTER TABLE user_tenants DROP CONSTRAINT user_tenants_role_chk');
  await knex.schema.raw(
    'ALTER TABLE user_tenants ADD CONSTRAINT user_tenants_role_chk ' +
      `CHECK (role IN (${ROLES_051}))`,
  );

  await knex('permission_sets')
    .insert({
      name: 'Account manager',
      slug: ROLE,
      capabilities: JSON.stringify(ACCOUNT_MANAGER_CAPABILITIES),
      is_default: true,
    })
    .onConflict('slug')
    .ignore();

  await knex.schema.raw(
    'UPDATE permission_sets ' +
      `SET capabilities = capabilities || '["${SITE_WRITE}"]'::jsonb ` +
      "WHERE slug = 'admin' AND is_default = true " +
      `AND NOT (capabilities @> '["${SITE_WRITE}"]'::jsonb)`,
  );
}

export async function down(knex: Knex): Promise<void> {
  // The narrower CHECK cannot be re-added while an `account_manager` row
  // exists, so those memberships go first. They are DELETED, not turned into
  // `member`: a member holds what an account manager was deliberately denied
  // (configuration snapshots, device writes, discovery binding, plan
  // compilation), and a rollback must never widen anybody's access. Losing
  // the membership is the fail-closed outcome; `requireTenant` re-checks
  // membership on its short cache, so open sessions lose the tenant too.
  await knex('user_tenants').where({ role: ROLE }).del();

  await knex.schema.raw('ALTER TABLE user_tenants DROP CONSTRAINT user_tenants_role_chk');
  await knex.schema.raw(
    'ALTER TABLE user_tenants ADD CONSTRAINT user_tenants_role_chk ' +
      `CHECK (role IN (${ROLES_001}))`,
  );

  await knex('permission_sets').where({ slug: ROLE, is_default: true }).del();

  // `jsonb - text` drops every array element equal to the string. Only the
  // default row, mirroring `up()`; a hand-made set or a pinned grant that
  // names `site.write` is left as typed, and the pre-051 code drops it at
  // read time (`sanitizeCapabilities` keeps only values it knows).
  await knex.schema.raw(
    `UPDATE permission_sets SET capabilities = capabilities - '${SITE_WRITE}' ` +
      "WHERE slug = 'admin' AND is_default = true",
  );
}
