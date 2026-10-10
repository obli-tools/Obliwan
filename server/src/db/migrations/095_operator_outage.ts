import type { Knex } from 'knex';

/**
 * 095_operator_outage.ts — ONE alert when an access provider takes several
 * stores down at once (shared/src/operatorOutage.ts,
 * services/fleet/operatorOutage.service.ts).
 *
 * When fourteen stores of the same provider fail over to 4G inside ten
 * minutes, the supervision got fourteen 4G backup alerts two hours later
 * (backup4g.service.ts, `backup_4g_alert_delay`). It now gets one
 * « Panne opérateur probable : <fournisseur> — 14 magasins en 4G » within
 * minutes, and the fourteen per-store alerts are FOLDED under it: still
 * created (visible as its children), not sent to the channels.
 *
 *  1. `sites.fixed_provider` — « Opérateur du lien fixe », declared by the
 *     operator (site form, bulk, CSV column `operateur`). The BEST evidence of
 *     who carries a store's fixed line. Free text (a provider list would be a
 *     guess about every customer's contracts), trimmed, 1–64 characters, NULL
 *     = not declared. No default: a default would declare 400 sites.
 *
 *  2. `device_fixed_link` — the MEMORY of the fixed line. During the outage
 *     the store is on 4G and its current public address (the PPP caller-id,
 *     `devices.wan_public_ip`) is the MOBILE operator's: inferring the fixed
 *     provider from it would label an Orange outage "Bouygues". So the address
 *     seen while the store was demonstrably on its fixed link is kept here,
 *     with the ASN it resolved to (when a lookup was allowed), and only this
 *     row is read for the ASN and prefix evidence. One row per device,
 *     overwritten when the fixed line's address changes.
 *
 *  3. `operator_outages` — one row per grouped outage, FLEET-WIDE (an ISP
 *     outage hits several customers: the god view sees one group spanning
 *     tenants). At most one OPEN group per provider key (partial unique
 *     index). `threshold` / `window_minutes` are frozen at opening.
 *     `notified_count` is the count of the last god-view notification: a
 *     growth re-notifies only on doubling.
 *
 *  4. `operator_outage_members` — one row per (group, store). `recovered_at`
 *     NULL = still out; a relapse inside the group clears it again.
 *     `released_at`: the group closed while this store was still out — from
 *     then on it is followed individually. `folded_alert_at` = the store's
 *     `devices.backup4g_alerted_at` when its per-store 4G alert was raised
 *     FOLDED (not sent to the channels): its recovery is then folded too,
 *     unless the store was released first (its alert is then sent at release
 *     and its recovery is sent as usual).
 *
 *  5. `operator_outage_slices` — what each customer tenant was told: its own
 *     stores only (a tenant never sees another customer's stores or counts),
 *     opened when its first store joins, re-notified on doubling, closed when
 *     its stores are back.
 *
 *  6. `operator_outage_points` — the count over time, per scope (tenant_id
 *     NULL = the god view), one point per change.
 *
 *  7. `live_alerts.outage_id` / `outage_role` — the alerts of a group:
 *     'global' (the god view's, filed in the master tenant, shown ONLY in the
 *     god view), 'tenant' (a customer tenant's slice, never shown in the god
 *     view, which has the global one), 'member' (a per-store alert folded
 *     under the group). Both NULL for every other alert.
 *
 * FOREIGN KEYS point from the leaves: to tenants / devices ON DELETE CASCADE,
 * to sites ON DELETE SET NULL, live_alerts → operator_outages ON DELETE SET
 * NULL (the role stays: the row is still the alert it was, and the CHECK
 * accepts a role whose group is gone, never a group without a role).
 *
 * No `?` anywhere in the SQL below (knex binding trap, migration 032), no
 * regex in a CHECK: IN lists of literals, lengths and IS NULL tests only.
 */

const STATUSES = ['open', 'closed'] as const;
const CLOSE_REASONS = ['recovered', 'receded'] as const;
const EVIDENCE = ['declared', 'pppoe_realm', 'asn', 'prefix', 'none'] as const;
const KINDS = ['cellular', 'offline'] as const;
const ROLES = ['global', 'tenant', 'member'] as const;
const ASN_SOURCES = ['local_table', 'lookup'] as const;

const list = (values: readonly string[]): string => values.map((v) => `'${v}'`).join(', ');

export async function up(knex: Knex): Promise<void> {
  // ── 1. The declared provider of a site's fixed line ───────────────────────
  await knex.schema.alterTable('sites', (t) => {
    t.text('fixed_provider').nullable();
  });
  await knex.schema.raw(
    'ALTER TABLE sites ADD CONSTRAINT sites_fixed_provider_chk CHECK (' +
      'fixed_provider IS NULL OR (char_length(fixed_provider) BETWEEN 1 AND 64 ' +
      'AND fixed_provider = btrim(fixed_provider)))',
  );

  // ── 2. The memory of the fixed line ───────────────────────────────────────
  await knex.schema.createTable('device_fixed_link', (t) => {
    t.integer('device_id').primary().references('id').inTable('devices').onDelete('CASCADE');
    t.integer('tenant_id').notNullable().references('id').inTable('tenants').onDelete('CASCADE');
    t.specificType('public_ip', 'inet').notNullable();
    /** Since when this address is the fixed line's (first seen). */
    t.timestamp('first_seen_at', { useTz: true }).notNullable();
    /** Last time it was confirmed while the store was on its fixed link. */
    t.timestamp('observed_at', { useTz: true }).notNullable();
    t.integer('asn').nullable();
    t.text('asn_name').nullable();
    t.string('asn_source', 16).nullable();
    t.timestamp('asn_at', { useTz: true }).nullable();
    t.index(['tenant_id']);
  });
  await knex.schema.raw(
    'ALTER TABLE device_fixed_link ADD CONSTRAINT device_fixed_link_asn_chk CHECK (' +
      '(asn IS NULL AND asn_name IS NULL AND asn_source IS NULL) OR ' +
      `(asn > 0 AND asn_source IN (${list(ASN_SOURCES)}) AND asn_at IS NOT NULL))`,
  );

  // ── 3. The grouped outages ────────────────────────────────────────────────
  await knex.schema.createTable('operator_outages', (t) => {
    t.bigIncrements('id').primary();
    t.text('provider_key').notNullable();
    t.text('provider_label').notNullable();
    t.boolean('unknown_provider').notNullable();
    t.string('status', 8).notNullable();
    t.timestamp('started_at', { useTz: true }).notNullable();
    t.timestamp('opened_at', { useTz: true }).notNullable();
    t.timestamp('closed_at', { useTz: true }).nullable();
    t.string('close_reason', 12).nullable();
    t.integer('threshold').notNullable();
    t.integer('window_minutes').notNullable();
    t.integer('peak_count').notNullable();
    t.integer('notified_count').notNullable();
    t.timestamp('last_change_at', { useTz: true }).notNullable();
    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.index(['status', 'opened_at']);
  });
  await knex.schema.raw(
    'ALTER TABLE operator_outages ADD CONSTRAINT operator_outages_shape_chk CHECK (' +
      `status IN (${list(STATUSES)}) ` +
      "AND ((status = 'open') = (closed_at IS NULL)) " +
      "AND ((status = 'open') = (close_reason IS NULL)) " +
      `AND (close_reason IS NULL OR close_reason IN (${list(CLOSE_REASONS)})) ` +
      'AND threshold >= 2 AND window_minutes >= 1 ' +
      'AND peak_count >= 0 AND notified_count >= 0 ' +
      'AND char_length(provider_key) BETWEEN 1 AND 200 AND char_length(provider_label) BETWEEN 1 AND 200)',
  );
  // One live group per provider: two sweeps racing open one.
  await knex.schema.raw(
    "CREATE UNIQUE INDEX operator_outages_open_uq ON operator_outages (provider_key) WHERE status = 'open'",
  );

  await knex.schema.createTable('operator_outage_members', (t) => {
    t.bigIncrements('id').primary();
    t.bigInteger('outage_id').notNullable().references('id').inTable('operator_outages').onDelete('CASCADE');
    t.integer('tenant_id').notNullable().references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('device_id').notNullable().references('id').inTable('devices').onDelete('CASCADE');
    t.integer('site_id').nullable().references('id').inTable('sites').onDelete('SET NULL');
    t.string('evidence', 12).notNullable();
    t.text('evidence_detail').nullable();
    t.string('kind', 10).notNullable();
    t.timestamp('lost_at', { useTz: true }).notNullable();
    t.timestamp('joined_at', { useTz: true }).notNullable();
    t.timestamp('recovered_at', { useTz: true }).nullable();
    t.timestamp('released_at', { useTz: true }).nullable();
    t.timestamp('folded_alert_at', { useTz: true }).nullable();
    t.unique(['outage_id', 'device_id']);
    t.index(['device_id']);
    t.index(['tenant_id', 'outage_id']);
  });
  await knex.schema.raw(
    'ALTER TABLE operator_outage_members ADD CONSTRAINT operator_outage_members_shape_chk CHECK (' +
      `evidence IN (${list(EVIDENCE)}) AND kind IN (${list(KINDS)}) ` +
      'AND (recovered_at IS NULL OR released_at IS NULL))',
  );

  await knex.schema.createTable('operator_outage_slices', (t) => {
    t.bigInteger('outage_id').notNullable().references('id').inTable('operator_outages').onDelete('CASCADE');
    t.integer('tenant_id').notNullable().references('id').inTable('tenants').onDelete('CASCADE');
    t.string('status', 8).notNullable();
    t.timestamp('opened_at', { useTz: true }).notNullable();
    t.timestamp('closed_at', { useTz: true }).nullable();
    t.integer('notified_count').notNullable();
    t.integer('peak_count').notNullable();
    t.primary(['outage_id', 'tenant_id']);
  });
  await knex.schema.raw(
    'ALTER TABLE operator_outage_slices ADD CONSTRAINT operator_outage_slices_shape_chk CHECK (' +
      `status IN (${list(STATUSES)}) AND ((status = 'open') = (closed_at IS NULL)) ` +
      'AND notified_count >= 0 AND peak_count >= 0)',
  );

  await knex.schema.createTable('operator_outage_points', (t) => {
    t.bigIncrements('id').primary();
    t.bigInteger('outage_id').notNullable().references('id').inTable('operator_outages').onDelete('CASCADE');
    /** NULL = the god view's count (every tenant); else one tenant's. */
    t.integer('tenant_id').nullable().references('id').inTable('tenants').onDelete('CASCADE');
    t.timestamp('at', { useTz: true }).notNullable();
    t.integer('active_count').notNullable();
    t.index(['outage_id', 'tenant_id', 'at']);
  });
  await knex.schema.raw(
    'ALTER TABLE operator_outage_points ADD CONSTRAINT operator_outage_points_count_chk CHECK (active_count >= 0)',
  );

  // ── 7. The alerts of a group ──────────────────────────────────────────────
  await knex.schema.alterTable('live_alerts', (t) => {
    t.bigInteger('outage_id').nullable().references('id').inTable('operator_outages').onDelete('SET NULL');
    t.string('outage_role', 8).nullable();
  });
  // A role names a group's alert. The FK's SET NULL clears `outage_id` alone
  // when a group row is deleted, so the CHECK accepts a role whose group is
  // gone (the row is still the folded alert it was); it refuses a group
  // without a role, and an unknown role.
  await knex.schema.raw(
    'ALTER TABLE live_alerts ADD CONSTRAINT live_alerts_outage_role_chk CHECK (' +
      `(outage_role IS NULL OR outage_role IN (${list(ROLES)})) ` +
      'AND (outage_id IS NULL OR outage_role IS NOT NULL))',
  );
  await knex.schema.raw('CREATE INDEX live_alerts_outage_id ON live_alerts (outage_id) WHERE outage_id IS NOT NULL');
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.raw('DROP INDEX IF EXISTS live_alerts_outage_id');
  await knex.schema.raw('ALTER TABLE live_alerts DROP CONSTRAINT IF EXISTS live_alerts_outage_role_chk');
  await knex.schema.alterTable('live_alerts', (t) => {
    t.dropColumn('outage_role');
    t.dropColumn('outage_id');
  });
  await knex.schema.dropTableIfExists('operator_outage_points');
  await knex.schema.dropTableIfExists('operator_outage_slices');
  await knex.schema.dropTableIfExists('operator_outage_members');
  await knex.schema.dropTableIfExists('operator_outages');
  await knex.schema.dropTableIfExists('device_fixed_link');
  await knex.schema.raw('ALTER TABLE sites DROP CONSTRAINT IF EXISTS sites_fixed_provider_chk');
  await knex.schema.alterTable('sites', (t) => {
    t.dropColumn('fixed_provider');
  });
}
