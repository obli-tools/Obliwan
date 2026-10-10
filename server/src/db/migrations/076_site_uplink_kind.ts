import type { Knex } from 'knex';

/**
 * 076 — the ACCESS LINK a site is declared with: "this store is 4G only".
 *
 * ┌─ WHY ─────────────────────────────────────────────────────────────────────┐
 * │ Whole customers run stores with no fixed line by design. ObliWAN INFERRED │
 * │ the access link from the router (a WAN-class interface in the snapshot or │
 * │ among the SNMP interfaces, backup4g.service `fixedUplinksFor`), and the   │
 * │ 4G backup watch, the uplink card and the fleet anomalies presented a     │
 * │ store on its only link as abnormal. The operator now SAYS it, per site,   │
 * │ from the site form, a bulk action on the sites list, or the CSV import.   │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE RULES THE SCHEMA KEEPS ──────────────────────────────────────────────┐
 * │ · `uplink_kind` is TRI-STATE and has NO DEFAULT: NULL = not declared,     │
 * │   ObliWAN infers as before 076; 'fixed' = a fixed line with a 4G backup;  │
 * │   'cellular_only' = 4G only. A default would declare 400 sites nobody     │
 * │   declared.                                                              │
 * │ · `uplink_kind_set_at` / `uplink_kind_set_by` record the LAST declaration │
 * │   (setting it back to "automatic" is one too, so a site returned to       │
 * │   inference still says who did it and when). A declared value always     │
 * │   carries its instant, and a "by" never exists without one — the second  │
 * │   CHECK. `set_by` may be NULL on its own: a declaration written by no     │
 * │   session user (none today) is still dated.                              │
 * │ · `uplink_kind_set_by` is a users.id with NO foreign key: deleting a user │
 * │   must neither cascade into the sites nor be refused by them, and a       │
 * │   SET NULL would erase who declared it (audit_log keeps the same id as    │
 * │   text, for the same reason).                                            │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * No `?` in any raw statement (the knex binding trap of migration 032): the
 * kinds are an IN list of literals.
 */
export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable('sites', (t) => {
    t.text('uplink_kind').nullable();
    t.timestamp('uplink_kind_set_at', { useTz: true }).nullable();
    t.integer('uplink_kind_set_by').nullable();
  });
  await knex.schema.raw(
    'ALTER TABLE sites ADD CONSTRAINT sites_uplink_kind_chk CHECK (' +
      "uplink_kind IS NULL OR uplink_kind IN ('fixed', 'cellular_only'))",
  );
  await knex.schema.raw(
    'ALTER TABLE sites ADD CONSTRAINT sites_uplink_kind_set_chk CHECK (' +
      'uplink_kind_set_at IS NOT NULL OR (uplink_kind IS NULL AND uplink_kind_set_by IS NULL))',
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.raw('ALTER TABLE sites DROP CONSTRAINT IF EXISTS sites_uplink_kind_set_chk');
  await knex.schema.raw('ALTER TABLE sites DROP CONSTRAINT IF EXISTS sites_uplink_kind_chk');
  await knex.schema.alterTable('sites', (t) => {
    t.dropColumn('uplink_kind_set_by');
    t.dropColumn('uplink_kind_set_at');
    t.dropColumn('uplink_kind');
  });
}
