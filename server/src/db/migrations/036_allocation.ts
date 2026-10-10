import type { Knex } from 'knex';

/**
 * 036_allocation.ts — per-tenant address allocation for L2TP sites (bench
 * provisioning), on the operator's rules. services/allocation/ is the only
 * writer of every table here except `concentrator_ppp_secrets` and
 * `concentrator_secret_reads`, which the CHR secret reader writes
 * (fleet/concentratorDiscovery.service.ts: the discovery scan, and the
 * allocator's re-read of a CHR whose last read is too old).
 *
 *  - `sites.country`              ISO 3166-1 alpha-2, optional; feeds the PPP
 *                                 login placeholder {site.country}.
 *  - `address_pools`              named IPv4 blocks, purpose 'tunnel' or 'lan',
 *                                 shared by reference between tenants.
 *  - `tenant_allocation_policies` HOW a tenant's sites are numbered: a tunnel
 *                                 rule and an optional LAN rule, each
 *                                 'incremental' or 'formula' over a pool, the
 *                                 PPP login template, the CHR.
 *  - `site_provisioning`          WHAT a site was given: PPP login + vaulted
 *                                 password, tunnel /32, optional LAN subnet,
 *                                 the CHR and PPP profile it was allocated
 *                                 for, and where the concentrator side stands.
 *  - `concentrator_ppp_secrets`   the SEED: every secret each CHR declares in
 *                                 /ppp/secret, with its remote-address and
 *                                 local-address, as of the last read.
 *  - `concentrator_secret_reads`  when each CHR's /ppp/secret was last read
 *                                 successfully. No row = never read, and the
 *                                 allocator refuses (NOT_SEEDED); a row older
 *                                 than its bound that cannot be refreshed is
 *                                 refused too (STALE_SEED).
 *
 * ┌─ AN ALLOCATION IS A FACT, A POLICY IS AN INTENTION ──────────────────────┐
 * │ Changing a policy changes the NEXT allocation and nothing else. A row in  │
 * │ `site_provisioning` is what was handed to a router and written on a CHR;  │
 * │ re-deriving it from today's policy would move a live customer to another  │
 * │ address without anybody touching the box. So the row carries, frozen,    │
 * │ everything the CHR side needs: the CHR the allocation was checked        │
 * │ against and the PPP profile, not a pointer to today's policy. It also    │
 * │ records which LAN pool its subnet was drawn from (`lan_pool_id`), because │
 * │ LAN uniqueness is per pool and per tenant. No trigger recomputes         │
 * │ anything. An allocation the CHR has not taken yet ('pending', 'failed')  │
 * │ can be RELEASED (row deleted) and allocated again; a 'provisioned' one    │
 * │ cannot.                                                                  │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHAT THE DATABASE GUARANTEES, AND WHAT IT CANNOT ───────────────────────┐
 * │ GUARANTEED HERE: tunnel pools never overlap one another (a partial        │
 * │ EXCLUDE); a policy's tunnel rule names a 'tunnel' pool and its LAN rule   │
 * │ a 'lan' pool (composite FKs on (id, purpose)); a mode is never stored    │
 * │ without its fields; one tunnel address per site and never two sites on  │
 * │ one, across every tenant (UNIQUE); no tenant holds the same LAN subnet    │
 * │ twice (UNIQUE); no two sites share a PPP login, compared WITHOUT CASE     │
 * │ (UNIQUE on lower()); a login and a profile that never need quoting on a  │
 * │ RouterOS command line.                                                    │
 * │                                                                          │
 * │ NOT GUARANTEED HERE, enforced by services/allocation under its advisory  │
 * │ lock (lock.ts): that a LAN pool never overlaps a tunnel pool (pools.ts —  │
 * │ LAN pools MAY overlap each other, which is how two tenants reuse one LAN │
 * │ plan); that LAN subnets of one tenant, or drawn from one pool, do not     │
 * │ OVERLAP (an exclusion keyed on tenant or pool needs the btree_gist       │
 * │ extension, which this schema does not require); that an incremental      │
 * │ start lies inside its pool and a formula renders inside it; that no      │
 * │ tunnel address lies inside a LAN subnet; that a formula pool belongs to  │
 * │ one tenant. Every INSERT into `site_provisioning` and `address_pools`    │
 * │ runs under that lock.                                                    │
 * │                                                                          │
 * │ Checked at READ TIME ONLY, because those tables' writers do not take the │
 * │ lock: that a login or a tunnel address is not already held by a device   │
 * │ or a live PPP session.                                                   │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * IPv4 only, and the CHECKs say so: the allocator does its arithmetic on
 * 32-bit addresses and a v6 pool stored here would be a policy no code can run.
 *
 * NO QUESTION MARK in any SQL text below: knex rewrites it inside raw() as a
 * binding placeholder (see migration 032). Character sets are checked
 * with translate(), which takes a literal list and no metacharacters, and every
 * enumeration is an IN list of literals.
 */

// Kept in lockstep with ADDRESS_MODES and POOL_PURPOSES in
// services/allocation/policy.ts and CONCENTRATOR_STATES in allocator.ts.
// Inlined so this migration keeps describing the schema as it was on the day it
// ran — a migration must never change meaning retroactively.
const MODES = "'incremental','formula'";
const PURPOSES = "'tunnel','lan'";
const CONCENTRATOR_STATES = "'pending','provisioned','failed'";

const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
// The PPP login alphabet (services/allocation/pppIdentity.ts). Every character
// is inert in a RouterOS argument, which is the point: the concentrator job
// splices the login into `/ppp secret add name=...`. Literal template text
// keeps its case, hence the capitals.
const LOGIN_CHARS = `${UPPER}abcdefghijklmnopqrstuvwxyz0123456789._-`;
// A PPP profile NAME as RouterOS spells them ('default-encryption'), with case.
const PROFILE_CHARS = `${UPPER}abcdefghijklmnopqrstuvwxyz0123456789._-`;

export async function up(knex: Knex): Promise<void> {
  // ==========================================================================
  // 0. sites.country — optional ISO 3166-1 alpha-2, stored uppercase.
  //    No DEFAULT: a country is a fact about a site nobody has stated yet.
  //    The CHECK judges the SHAPE only (two letters A-Z); whether the pair is
  //    an assigned code is not a schema question — the list changes.
  // ==========================================================================
  await knex.schema.alterTable('sites', (t) => {
    t.string('country', 2).nullable();
  });
  await knex.schema.raw(
    'ALTER TABLE sites ADD CONSTRAINT sites_country_chk CHECK (country IS NULL OR ' +
      `(char_length(country) = 2 AND translate(country, '${UPPER}', '') = ''))`,
  );

  // `sites_id_tenant_uq` is the target of site_provisioning's composite FK.
  // Re-asserted idempotently, the same shape 026 and 032 use, so this migration
  // is correct on a database where those were rolled back; never dropped in
  // down() — other tables' foreign keys rely on it.
  await knex.schema.raw(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'sites_id_tenant_uq'
      ) THEN
        ALTER TABLE sites ADD CONSTRAINT sites_id_tenant_uq UNIQUE (id, tenant_id);
      END IF;
    END $$;
  `);

  // ==========================================================================
  // 1. address_pools
  // ==========================================================================
  await knex.schema.createTable('address_pools', (t) => {
    t.increments('id').primary();
    t.string('name', 64).notNullable();
    t.specificType('cidr', 'cidr').notNullable();
    t.string('purpose', 8).notNullable();
    t.timestamps(true, true);
    // Target of the policies' composite FKs: (pool id, purpose) pins the
    // purpose a policy column may reference.
    t.unique(['id', 'purpose']);
  });
  const poolChecks: Array<[string, string]> = [
    ['purpose_chk', `purpose IN (${PURPOSES})`],
    // Same bounds as POOL_PREFIX_MIN / POOL_PREFIX_MAX in policy.ts.
    ['cidr_chk', 'family("cidr") = 4 AND masklen("cidr") BETWEEN 8 AND 30'],
    ['name_chk', `btrim(name) <> ''`],
  ];
  for (const [name, expr] of poolChecks) {
    await knex.schema.raw(`ALTER TABLE address_pools ADD CONSTRAINT address_pools_${name} CHECK (${expr})`);
  }
  await knex.schema.raw('CREATE UNIQUE INDEX address_pools_name_ci_uq ON address_pools (lower(name))');
  // Tunnel pools never overlap one another: tunnel addresses are unique across
  // the installation, and an overlap is one address with two pools to hand it
  // out. inet_ops is PostgreSQL's built-in GiST operator class for inet/cidr
  // and supports && (overlap). The predicate makes it apply between TUNNEL
  // pools only: LAN pools may overlap each other (two tenants reusing one LAN
  // plan), and "a LAN pool never overlaps a tunnel pool" compares rows of the
  // two purposes, which a partial exclusion cannot express — pools.ts checks
  // it under the allocation lock.
  await knex.schema.raw(
    'ALTER TABLE address_pools ADD CONSTRAINT address_pools_tunnel_no_overlap ' +
      `EXCLUDE USING gist ("cidr" inet_ops WITH &&) WHERE (purpose = 'tunnel')`,
  );

  // ==========================================================================
  // 2. tenant_allocation_policies — one row per tenant, or none. No row means
  //    "this tenant's sites cannot be allocated", and the allocator says so.
  // ==========================================================================
  await knex.schema.createTable('tenant_allocation_policies', (t) => {
    t.integer('tenant_id').primary().references('id').inTable('tenants').onDelete('CASCADE');

    // ── tunnel rule (required) ────────────────────────────────────────────
    t.integer('tunnel_pool_id').notNullable();
    // Always 'tunnel' (CHECK below): the second half of the composite FK that
    // makes a LAN pool on this side unrepresentable. No DEFAULT — the service
    // writes it, so a row written around the service fails the FK loudly.
    t.string('tunnel_pool_purpose', 8).notNullable();
    t.string('tunnel_mode', 16).notNullable();
    // incremental: the first address handed out. No DEFAULT: where a tenant's
    // numbering starts is the operator's decision (the pool's first hosts are
    // often the CHR's), not a fact this schema knows.
    t.specificType('tunnel_start', 'inet').nullable();
    // formula: e.g. "100.65.{id/100}.{id%100}" (services/allocation/formula.ts).
    t.text('tunnel_formula').nullable();

    // ── LAN rule (optional: all null = no LAN subnet per site) ────────────
    t.integer('lan_pool_id').nullable();
    t.string('lan_pool_purpose', 8).nullable();
    t.string('lan_mode', 16).nullable();
    // incremental: the block size handed to each site.
    t.integer('lan_prefix').nullable();
    // formula: e.g. "10.{100+id/100}.{id%100}.0/24" — the prefix is in it.
    t.text('lan_formula').nullable();

    // e.g. "{site.slug}.{site.country}.{tenant.slug}.{instance.domain}".
    // Judged by the service (pppIdentity.ts): its placeholders' VALUES are
    // what need checking, and those exist only at allocation.
    t.text('ppp_login_template').notNullable();
    t.string('ppp_profile', 64).nullable();

    // The CHR that terminates this tenant's tunnels, and whose /ppp/secret must
    // have been read before anything is allocated. NOT NULL: a policy with no
    // CHR could not be seeded, and its sites could not be written anywhere.
    // RESTRICT, same reason as `devices.concentrator_id`. That the row IS a
    // concentrator, of this tenant or the master tenant, is the service's
    // check — a CHECK cannot read another table.
    t.integer('concentrator_id').notNullable().references('id').inTable('devices').onDelete('RESTRICT');

    t.timestamps(true, true);
  });
  await knex.schema.raw(
    'ALTER TABLE tenant_allocation_policies ADD CONSTRAINT tenant_allocation_policies_tunnel_pool_fk ' +
      'FOREIGN KEY (tunnel_pool_id, tunnel_pool_purpose) REFERENCES address_pools (id, purpose) ' +
      'ON DELETE RESTRICT',
  );
  // MATCH SIMPLE (the default) skips the check when either column is NULL;
  // lan_group_chk below makes the pair both-or-neither.
  await knex.schema.raw(
    'ALTER TABLE tenant_allocation_policies ADD CONSTRAINT tenant_allocation_policies_lan_pool_fk ' +
      'FOREIGN KEY (lan_pool_id, lan_pool_purpose) REFERENCES address_pools (id, purpose) ' +
      'ON DELETE RESTRICT',
  );
  const policyChecks: Array<[string, string]> = [
    ['tunnel_purpose_chk', `tunnel_pool_purpose = 'tunnel'`],
    ['tunnel_mode_chk', `tunnel_mode IN (${MODES})`],
    [
      'tunnel_fields_chk',
      `(tunnel_mode = 'incremental' AND tunnel_start IS NOT NULL AND tunnel_formula IS NULL) OR ` +
        `(tunnel_mode = 'formula' AND tunnel_formula IS NOT NULL AND tunnel_start IS NULL)`,
    ],
    ['tunnel_start_chk', 'tunnel_start IS NULL OR (family(tunnel_start) = 4 AND masklen(tunnel_start) = 32)'],
    ['tunnel_formula_chk', `tunnel_formula IS NULL OR btrim(tunnel_formula) <> ''`],
    [
      'lan_group_chk',
      '(lan_pool_id IS NULL) = (lan_mode IS NULL) AND (lan_pool_id IS NULL) = (lan_pool_purpose IS NULL)',
    ],
    ['lan_purpose_chk', `lan_pool_purpose IS NULL OR lan_pool_purpose = 'lan'`],
    ['lan_mode_chk', `lan_mode IS NULL OR lan_mode IN (${MODES})`],
    [
      'lan_fields_chk',
      '(lan_mode IS NULL AND lan_prefix IS NULL AND lan_formula IS NULL) OR ' +
        `(lan_mode = 'incremental' AND lan_prefix IS NOT NULL AND lan_formula IS NULL) OR ` +
        `(lan_mode = 'formula' AND lan_formula IS NOT NULL AND lan_prefix IS NULL)`,
    ],
    ['lan_prefix_chk', 'lan_prefix IS NULL OR lan_prefix BETWEEN 8 AND 30'],
    ['lan_formula_chk', `lan_formula IS NULL OR btrim(lan_formula) <> ''`],
    ['login_template_chk', `btrim(ppp_login_template) <> ''`],
    [
      'profile_chk',
      `ppp_profile IS NULL OR (ppp_profile <> '' AND translate(ppp_profile, '${PROFILE_CHARS}', '') = '')`,
    ],
  ];
  for (const [name, expr] of policyChecks) {
    await knex.schema.raw(
      `ALTER TABLE tenant_allocation_policies ADD CONSTRAINT tenant_allocation_policies_${name} CHECK (${expr})`,
    );
  }
  await knex.schema.raw(
    'CREATE INDEX tenant_allocation_policies_tunnel_pool_idx ON tenant_allocation_policies (tunnel_pool_id)',
  );
  await knex.schema.raw(
    'CREATE INDEX tenant_allocation_policies_lan_pool_idx ON tenant_allocation_policies (lan_pool_id) ' +
      'WHERE lan_pool_id IS NOT NULL',
  );
  await knex.schema.raw(
    'CREATE INDEX tenant_allocation_policies_concentrator_idx ON tenant_allocation_policies (concentrator_id)',
  );

  // ==========================================================================
  // 3. site_provisioning — what one site was given. One row per site, or none.
  // ==========================================================================
  await knex.schema.createTable('site_provisioning', (t) => {
    t.integer('site_id').primary();
    // Carried so the composite FK below makes a row of tenant A pointing at a
    // site of tenant B unrepresentable, rather than merely unlikely.
    t.integer('tenant_id').notNullable();

    // The PPP login, case as rendered. Unique WITHOUT CASE (index below).
    t.string('ppp_username', 128).notNullable();
    // Vault blob (secretVault.service.ts), never a plaintext. The generation
    // that wrote it travels beside it, as on `device_transports`: a key
    // rotation must find the rows still on an old key without decrypting a
    // single one. No DEFAULT — it is a fact about the blob.
    t.text('ppp_password_enc').notNullable();
    t.integer('ppp_password_key_version').notNullable();

    t.specificType('tunnel_ip', 'inet').notNullable().unique();
    t.specificType('lan_subnet', 'cidr').nullable();
    // The LAN pool the subnet was drawn from: LAN uniqueness is per tenant AND
    // per pool, and a pool's other tenants must see this block. RESTRICT, not
    // SET NULL: losing the link would silently turn "shared, disjoint" into
    // "free to reuse" for the pool's other tenants. A LAN pool can be deleted
    // once no allocation holds a block drawn from it (released, or its site
    // deleted).
    t.integer('lan_pool_id').nullable().references('id').inTable('address_pools').onDelete('RESTRICT');

    // FROZEN at allocation, from the tenant's policy of that moment: the CHR
    // whose /ppp/secret this allocation was checked against and that must
    // carry its secret, and the PPP profile to give it there. Re-pointing the
    // policy at another CHR does not move a site already allocated — that
    // allocation was never checked against the new CHR's secrets. RESTRICT,
    // same reason as `tenant_allocation_policies.concentrator_id`.
    t.integer('concentrator_id').notNullable().references('id').inTable('devices').onDelete('RESTRICT');
    t.string('ppp_profile', 64).nullable();

    // 'pending' is true at insert time: nothing has been written on the CHR.
    t.string('concentrator_state', 16).notNullable().defaultTo('pending');
    // change_jobs.id is a bigint; an int here could not hold every id it points at.
    t.bigInteger('concentrator_job_id').nullable().references('id').inTable('change_jobs').onDelete('SET NULL');
    t.text('concentrator_error').nullable();

    t.timestamp('allocated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });
  await knex.schema.raw(
    'ALTER TABLE site_provisioning ADD CONSTRAINT site_provisioning_site_tenant_fk ' +
      'FOREIGN KEY (site_id, tenant_id) REFERENCES sites (id, tenant_id) ON DELETE CASCADE',
  );
  await knex.schema.raw(
    'CREATE UNIQUE INDEX site_provisioning_login_ci_uq ON site_provisioning (lower(ppp_username))',
  );
  // EQUALITY within a tenant only. Two tenants may hold the same LAN subnet —
  // each from its own LAN pool over one block, a reuse the operator chose by
  // creating that second pool. OVERLAP (a /25 inside a /24 of the same tenant
  // or pool) is the allocator's to refuse, under its lock: an exclusion keyed
  // on tenant_id needs the btree_gist extension (header). This index is the
  // part the database can hold without it.
  await knex.schema.raw(
    'CREATE UNIQUE INDEX site_provisioning_tenant_lan_uq ON site_provisioning (tenant_id, lan_subnet) ' +
      'WHERE lan_subnet IS NOT NULL',
  );
  await knex.schema.raw(
    'CREATE INDEX site_provisioning_lan_pool_idx ON site_provisioning (lan_pool_id) WHERE lan_pool_id IS NOT NULL',
  );
  await knex.schema.raw(
    'CREATE INDEX site_provisioning_concentrator_idx ON site_provisioning (concentrator_id)',
  );
  const siteChecks: Array<[string, string]> = [
    ['state_chk', `concentrator_state IN (${CONCENTRATOR_STATES})`],
    // A failure with no reason is a red badge nobody can act on.
    ['failed_reason_chk', `concentrator_state <> 'failed' OR concentrator_error IS NOT NULL`],
    ['key_version_chk', 'ppp_password_key_version >= 1'],
    ['password_chk', `ppp_password_enc <> ''`],
    // A HOST address, not a network: masklen 32.
    ['tunnel_ip_chk', 'family(tunnel_ip) = 4 AND masklen(tunnel_ip) = 32'],
    ['lan_subnet_chk', 'lan_subnet IS NULL OR family(lan_subnet) = 4'],
    // A subnet always comes from a pool, and a pool link without a subnet
    // means nothing.
    ['lan_pool_chk', '(lan_pool_id IS NULL) = (lan_subnet IS NULL)'],
    // Same alphabet as the policy's profile: spliced bare into
    // `/ppp secret add profile=...` on the CHR.
    [
      'profile_chk',
      `ppp_profile IS NULL OR (ppp_profile <> '' AND translate(ppp_profile, '${PROFILE_CHARS}', '') = '')`,
    ],
    [
      'username_chk',
      `ppp_username <> '' AND translate(ppp_username, '${LOGIN_CHARS}', '') = '' AND ` +
        `strpos(ppp_username, '..') = 0 AND left(ppp_username, 1) <> '.' AND right(ppp_username, 1) <> '.'`,
    ],
  ];
  for (const [name, expr] of siteChecks) {
    await knex.schema.raw(`ALTER TABLE site_provisioning ADD CONSTRAINT site_provisioning_${name} CHECK (${expr})`);
  }
  await knex.schema.raw(
    'CREATE INDEX site_provisioning_state_idx ON site_provisioning (concentrator_state) ' +
      `WHERE concentrator_state <> 'provisioned'`,
  );

  // ==========================================================================
  // 4. concentrator_ppp_secrets — the seed. One row per (CHR, secret name),
  //    written after every SUCCESSFUL /ppp/secret read (the discovery scan,
  //    or the allocator's re-read of a CHR whose last read is too old), bound
  //    or not, in one transaction under the allocation lock. Distinct
  //    from `discoveries`, which is the quarantine of UNKNOWN usernames (bound
  //    ones are skipped there) and whose remote_address is overwritten by the
  //    live session's: this table keeps what the secret itself DECLARES.
  //    A secret that disappears from a later read is stamped `vanished_at`,
  //    never deleted, and no longer counts as held.
  // ==========================================================================
  await knex.schema.createTable('concentrator_ppp_secrets', (t) => {
    t.increments('id').primary();
    t.integer('concentrator_id').notNullable().references('id').inTable('devices').onDelete('CASCADE');
    t.string('name', 128).notNullable();
    // What the secret declares, NULL when it declares none (the CHR then takes
    // the address from a pool, and the live session shows it).
    t.specificType('remote_address', 'inet').nullable();
    t.specificType('local_address', 'inet').nullable();
    t.string('profile', 128).nullable();
    // As read; no DEFAULT — a secret's state is a fact the CHR states.
    t.boolean('disabled').notNullable();
    t.timestamp('first_seen_at', { useTz: true }).notNullable();
    t.timestamp('last_seen_at', { useTz: true }).notNullable();
    t.timestamp('vanished_at', { useTz: true }).nullable();
    t.unique(['concentrator_id', 'name']);
  });
  await knex.schema.raw(
    'CREATE INDEX concentrator_ppp_secrets_name_ci_idx ON concentrator_ppp_secrets (lower(name)) ' +
      'WHERE vanished_at IS NULL',
  );
  await knex.schema.raw(
    'ALTER TABLE concentrator_ppp_secrets ADD CONSTRAINT concentrator_ppp_secrets_name_chk ' +
      `CHECK (btrim(name) <> '')`,
  );

  // ==========================================================================
  // 5. concentrator_secret_reads — one row per CHR whose /ppp/secret has been
  //    read successfully at least once. A failed read writes nothing here, so
  //    "never read" and "read, and empty" stay two different answers. The AGE
  //    of read_at is a decision input, not a display: an allocation re-reads a
  //    gating CHR whose read is older than SEED_MAX_AGE_MS
  //    (services/allocation/seed.ts) and refuses when it cannot.
  // ==========================================================================
  await knex.schema.createTable('concentrator_secret_reads', (t) => {
    t.integer('concentrator_id').primary().references('id').inTable('devices').onDelete('CASCADE');
    t.timestamp('read_at', { useTz: true }).notNullable();
    t.integer('secret_count').notNullable();
  });
  await knex.schema.raw(
    'ALTER TABLE concentrator_secret_reads ADD CONSTRAINT concentrator_secret_reads_count_chk ' +
      'CHECK (secret_count >= 0)',
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists('concentrator_secret_reads');
  await knex.schema.dropTableIfExists('concentrator_ppp_secrets');
  await knex.schema.dropTableIfExists('site_provisioning');
  await knex.schema.dropTableIfExists('tenant_allocation_policies');
  await knex.schema.dropTableIfExists('address_pools');
  await knex.schema.raw('ALTER TABLE sites DROP CONSTRAINT IF EXISTS sites_country_chk');
  await knex.schema.alterTable('sites', (t) => {
    t.dropColumn('country');
  });
  // `sites_id_tenant_uq` is deliberately NOT dropped — see the note in up().
}
