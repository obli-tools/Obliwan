import type { Knex } from 'knex';

/**
 * 039_allocation_v3.ts — the allocator on the operator's real rules. Migration
 * 036 is deployed and is never edited; everything below is additive or a
 * constraint replaced by a wider one.
 *
 * tenant_allocation_policies
 *  - `identity_template`   the RouterOS system identity, a template of its own
 *                          (same placeholders as the PPP login). NULL = this
 *                          tenant's identity is not computed by ObliWAN.
 *  - `ppp_password_mode`   'shared' (the fleet-wide password, read at use time
 *                          from the INSTANCE variable `ppp_password`; no
 *                          per-site copy is stored) or 'per_site' (generated,
 *                          vaulted). Rows that exist before this migration are
 *                          backfilled 'per_site', because that is what 036 did
 *                          for them. No column DEFAULT: the API applies the
 *                          operator's default ('shared') to a new policy.
 *  - LAN modes widen from incremental | formula to also:
 *      'fixed'   `lan_fixed_subnet`, the same LAN on every site of the tenant;
 *      'manual'  `lan_variable`, the SITE variable that holds each site's LAN.
 *    Neither has a pool, so the "pool iff mode" check is restated.
 *  - `derived_values`      JSON object { key: expression } of further computed
 *                          values (cidrHost(lan_subnet, n), formulas on id,
 *                          site placeholders). Judged by services/allocation.
 *
 * site_provisioning
 *  - `lan_source`          'pool' | 'fixed' | 'manual', NULL iff no LAN. Rows
 *                          holding a LAN before this migration are 'pool': the
 *                          036 CHECK tied every lan_subnet to a lan_pool_id.
 *  - The per-tenant LAN unique index no longer covers 'fixed' rows: a fixed
 *    LAN is by definition held by every site of the tenant.
 *  - `ppp_password_mode`   copied from the policy at allocation; a 'shared'
 *                          row carries NO password (enc and key_version NULL).
 *                          Existing rows are 'per_site' (they hold a vault blob).
 *  - `system_identity`     rendered once from `identity_template`, unique
 *                          without regard to case.
 *
 * config_variables
 *  - The installation domain moves from `app_config` (key 'instance_domain')
 *    to an INSTANCE variable of the same key, so {instance.domain} reads the
 *    level migration 038 added. down() moves it back.
 *
 * No "?" anywhere in raw SQL (knex rewrites it); alphabets are written with
 * translate() as in 036.
 */

const LAN_MODES_036 = "'incremental','formula'";
const LAN_MODES_039 = "'incremental','formula','fixed','manual'";
const PASSWORD_MODES = "'shared','per_site'";
const LAN_SOURCES = "'pool','fixed','manual'";
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const IDENTITY_CHARS = `${UPPER}abcdefghijklmnopqrstuvwxyz0123456789._-`;
const VARIABLE_CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789_';
const DOMAIN_KEY = 'instance_domain';

const P = 'tenant_allocation_policies';
const S = 'site_provisioning';

async function addCheck(knex: Knex, table: string, name: string, expr: string): Promise<void> {
  await knex.schema.raw(`ALTER TABLE ${table} ADD CONSTRAINT ${table}_${name} CHECK (${expr})`);
}

async function dropCheck(knex: Knex, table: string, name: string): Promise<void> {
  await knex.schema.raw(`ALTER TABLE ${table} DROP CONSTRAINT IF EXISTS ${table}_${name}`);
}

export async function up(knex: Knex): Promise<void> {
  // ── policies ──────────────────────────────────────────────────────────────
  await knex.schema.alterTable(P, (t) => {
    t.text('identity_template').nullable();
    t.string('ppp_password_mode', 16).nullable();
    t.specificType('lan_fixed_subnet', 'cidr').nullable();
    t.string('lan_variable', 120).nullable();
    t.jsonb('derived_values').nullable();
  });
  await knex(P).update({ ppp_password_mode: 'per_site' });
  await knex.schema.raw(`ALTER TABLE ${P} ALTER COLUMN ppp_password_mode SET NOT NULL`);

  for (const name of ['lan_group_chk', 'lan_mode_chk', 'lan_fields_chk']) await dropCheck(knex, P, name);
  await addCheck(
    knex,
    P,
    'lan_group_chk',
    '(lan_pool_id IS NULL) = (lan_pool_purpose IS NULL) AND ' +
      `(lan_pool_id IS NOT NULL) = (lan_mode IS NOT NULL AND lan_mode IN (${LAN_MODES_036}))`,
  );
  await addCheck(knex, P, 'lan_mode_chk', `lan_mode IS NULL OR lan_mode IN (${LAN_MODES_039})`);
  const none = (except: string[]): string =>
    ['lan_prefix', 'lan_formula', 'lan_fixed_subnet', 'lan_variable']
      .filter((c) => !except.includes(c))
      .map((c) => `${c} IS NULL`)
      .join(' AND ');
  await addCheck(
    knex,
    P,
    'lan_fields_chk',
    `(lan_mode IS NULL AND ${none([])}) OR ` +
      `(lan_mode = 'incremental' AND lan_prefix IS NOT NULL AND ${none(['lan_prefix'])}) OR ` +
      `(lan_mode = 'formula' AND lan_formula IS NOT NULL AND ${none(['lan_formula'])}) OR ` +
      `(lan_mode = 'fixed' AND lan_fixed_subnet IS NOT NULL AND ${none(['lan_fixed_subnet'])}) OR ` +
      `(lan_mode = 'manual' AND lan_variable IS NOT NULL AND ${none(['lan_variable'])})`,
  );
  await addCheck(
    knex,
    P,
    'lan_fixed_chk',
    'lan_fixed_subnet IS NULL OR (family(lan_fixed_subnet) = 4 AND masklen(lan_fixed_subnet) BETWEEN 8 AND 30)',
  );
  await addCheck(
    knex,
    P,
    'lan_variable_chk',
    `lan_variable IS NULL OR (lan_variable <> '' AND translate(lan_variable, '${VARIABLE_CHARS}', '') = '')`,
  );
  await addCheck(knex, P, 'password_mode_chk', `ppp_password_mode IN (${PASSWORD_MODES})`);
  await addCheck(knex, P, 'identity_template_chk', `identity_template IS NULL OR btrim(identity_template) <> ''`);
  await addCheck(knex, P, 'derived_chk', `derived_values IS NULL OR jsonb_typeof(derived_values) = 'object'`);

  // ── site_provisioning ─────────────────────────────────────────────────────
  await knex.schema.alterTable(S, (t) => {
    t.string('lan_source', 8).nullable();
    t.string('ppp_password_mode', 16).nullable();
    t.string('system_identity', 128).nullable();
  });
  await knex(S).whereNotNull('lan_subnet').update({ lan_source: 'pool' });
  await knex(S).update({ ppp_password_mode: 'per_site' });
  await knex.schema.raw(`ALTER TABLE ${S} ALTER COLUMN ppp_password_mode SET NOT NULL`);
  await knex.schema.raw(`ALTER TABLE ${S} ALTER COLUMN ppp_password_enc DROP NOT NULL`);
  await knex.schema.raw(`ALTER TABLE ${S} ALTER COLUMN ppp_password_key_version DROP NOT NULL`);

  await dropCheck(knex, S, 'lan_pool_chk');
  await addCheck(knex, S, 'lan_source_chk', `lan_source IS NULL OR lan_source IN (${LAN_SOURCES})`);
  await addCheck(knex, S, 'lan_source_subnet_chk', '(lan_subnet IS NULL) = (lan_source IS NULL)');
  await addCheck(knex, S, 'lan_pool_chk', `(lan_pool_id IS NOT NULL) = (lan_source IS NOT DISTINCT FROM 'pool')`);
  await addCheck(knex, S, 'password_mode_chk', `ppp_password_mode IN (${PASSWORD_MODES})`);
  await addCheck(
    knex,
    S,
    'password_presence_chk',
    `(ppp_password_mode = 'per_site') = (ppp_password_enc IS NOT NULL) AND ` +
      '(ppp_password_enc IS NULL) = (ppp_password_key_version IS NULL)',
  );
  await addCheck(
    knex,
    S,
    'identity_chk',
    `system_identity IS NULL OR (system_identity <> '' AND ` +
      `translate(system_identity, '${IDENTITY_CHARS}', '') = '' AND strpos(system_identity, '..') = 0)`,
  );

  await knex.schema.raw('DROP INDEX IF EXISTS site_provisioning_tenant_lan_uq');
  await knex.schema.raw(
    `CREATE UNIQUE INDEX site_provisioning_tenant_lan_uq ON ${S} (tenant_id, lan_subnet) ` +
      `WHERE lan_subnet IS NOT NULL AND lan_source <> 'fixed'`,
  );
  await knex.schema.raw(
    `CREATE UNIQUE INDEX site_provisioning_identity_ci_uq ON ${S} (lower(system_identity)) ` +
      'WHERE system_identity IS NOT NULL',
  );

  // ── the installation domain becomes an instance variable ──────────────────
  const old = (await knex('app_config').where({ key: DOMAIN_KEY }).first('value')) as
    | { value: string }
    | undefined;
  const domain = old ? old.value.trim() : '';
  if (domain !== '') {
    const exists = await knex('config_variables')
      .where({ scope: 'instance', key: DOMAIN_KEY })
      .first('id');
    if (!exists) {
      await knex('config_variables').insert({
        tenant_id: null,
        scope: 'instance',
        scope_id: null,
        key: DOMAIN_KEY,
        value: JSON.stringify(domain),
        is_secret: false,
        secret_enc: null,
        description: 'Installation domain, spliced into allocation templates by {instance.domain}.',
      });
    }
  }
  await knex('app_config').where({ key: DOMAIN_KEY }).del();
}

export async function down(knex: Knex): Promise<void> {
  // Refuse rather than destroy: these rows have no 036 representation, and a
  // shared-password or fixed/manual-LAN allocation may be live on a CHR.
  const shared = await knex(S).where({ ppp_password_mode: 'shared' }).count<{ n: string }[]>('* as n');
  const nonPool = await knex(S).whereIn('lan_source', ['fixed', 'manual']).count<{ n: string }[]>('* as n');
  if (Number(shared[0].n) > 0 || Number(nonPool[0].n) > 0) {
    throw new Error(
      `039 down refused: ${shared[0].n} site allocation(s) use the shared PPP password and ` +
        `${nonPool[0].n} hold a fixed or manual LAN; migration 036 cannot represent them. ` +
        'Release those allocations first.',
    );
  }

  // The domain goes back to app_config.
  const row = (await knex('config_variables')
    .where({ scope: 'instance', key: DOMAIN_KEY })
    .first('value')) as { value: unknown } | undefined;
  const raw = row?.value;
  const parsed = typeof raw === 'string' ? (raw.startsWith('"') ? (JSON.parse(raw) as unknown) : raw) : raw;
  if (typeof parsed === 'string' && parsed.trim() !== '') {
    await knex('app_config')
      .insert({ key: DOMAIN_KEY, value: parsed.trim() })
      .onConflict('key')
      .merge({ value: parsed.trim() });
  }
  await knex('config_variables').where({ scope: 'instance', key: DOMAIN_KEY }).del();

  await knex.schema.raw('DROP INDEX IF EXISTS site_provisioning_identity_ci_uq');
  await knex.schema.raw('DROP INDEX IF EXISTS site_provisioning_tenant_lan_uq');
  await knex.schema.raw(
    `CREATE UNIQUE INDEX site_provisioning_tenant_lan_uq ON ${S} (tenant_id, lan_subnet) ` +
      'WHERE lan_subnet IS NOT NULL',
  );
  for (const name of [
    'identity_chk',
    'password_presence_chk',
    'password_mode_chk',
    'lan_pool_chk',
    'lan_source_subnet_chk',
    'lan_source_chk',
  ]) {
    await dropCheck(knex, S, name);
  }
  await addCheck(knex, S, 'lan_pool_chk', '(lan_pool_id IS NULL) = (lan_subnet IS NULL)');
  await knex.schema.raw(`ALTER TABLE ${S} ALTER COLUMN ppp_password_key_version SET NOT NULL`);
  await knex.schema.raw(`ALTER TABLE ${S} ALTER COLUMN ppp_password_enc SET NOT NULL`);
  await knex.schema.alterTable(S, (t) => {
    t.dropColumn('system_identity');
    t.dropColumn('ppp_password_mode');
    t.dropColumn('lan_source');
  });

  // Policies whose LAN rule 036 cannot hold lose that rule (sites keep what
  // they were given; the check above refused if any site held such a LAN).
  await knex(P)
    .whereIn('lan_mode', ['fixed', 'manual'])
    .update({ lan_mode: null, lan_fixed_subnet: null, lan_variable: null });
  for (const name of [
    'derived_chk',
    'identity_template_chk',
    'password_mode_chk',
    'lan_variable_chk',
    'lan_fixed_chk',
    'lan_fields_chk',
    'lan_mode_chk',
    'lan_group_chk',
  ]) {
    await dropCheck(knex, P, name);
  }
  await addCheck(
    knex,
    P,
    'lan_group_chk',
    '(lan_pool_id IS NULL) = (lan_mode IS NULL) AND (lan_pool_id IS NULL) = (lan_pool_purpose IS NULL)',
  );
  await addCheck(knex, P, 'lan_mode_chk', `lan_mode IS NULL OR lan_mode IN (${LAN_MODES_036})`);
  await addCheck(
    knex,
    P,
    'lan_fields_chk',
    '(lan_mode IS NULL AND lan_prefix IS NULL AND lan_formula IS NULL) OR ' +
      `(lan_mode = 'incremental' AND lan_prefix IS NOT NULL AND lan_formula IS NULL) OR ` +
      `(lan_mode = 'formula' AND lan_formula IS NOT NULL AND lan_prefix IS NULL)`,
  );
  await knex.schema.alterTable(P, (t) => {
    t.dropColumn('derived_values');
    t.dropColumn('lan_variable');
    t.dropColumn('lan_fixed_subnet');
    t.dropColumn('ppp_password_mode');
    t.dropColumn('identity_template');
  });
}
