import type { Knex } from 'knex';

/**
 * 074_infra_concentrators.ts — each customer's INFRASTRUCTURE VPN concentrator
 * and the per-site accounts ObliWAN keeps on it (shared/src/infraConcentrator.ts,
 * services/infraConcentrator/).
 *
 * The management concentrator (the shared CHR, 040's `concentrator_secret`)
 * carries ObliWAN's own path to every store. A customer also runs its own
 * concentrator every store connects to for business traffic: a second RouterOS
 * CHR (one L2TP-over-IPsec login per store), or an OPNsense terminating one
 * IPsec tunnel per store.
 *
 *  1. `change_jobs.kind` gains `infra_account` (13 characters; varchar(24)
 *     since 040). 009's write-kind CHECKs, as 066 left them, one by one:
 *       - `change_jobs_kind_chk`             WIDENED.
 *       - `change_jobs_guard_required_chk`   WIDENED: the job carries its own
 *         verdict, written at enqueue.
 *       - `change_jobs_degraded_confirm_chk` NOT widened, like 040: no dead-man
 *         is armed (an added secret cuts no path; a revoke removes only an
 *         entry ObliWAN itself added, under its own comment), so the job is
 *         queued at `degraded`, which is the truth about its net.
 *       - `change_jobs_preflight_backup_chk` NOT widened, like 040: the add is
 *         additive, and the one removal is undone by the same job's `ensure`
 *         from the vault-held password.
 *     Read back and widened like 066, but the kind is inserted right AFTER
 *     `concentrator_secret` rather than appended (see widenKindList);
 *     `down()` removes exactly this kind. NOT admitted by rollouts, and
 *     NOT exempted from the subtree interlock (055): an infra CHR carries
 *     no store's management tunnel, so it has no children to clash with, and
 *     a box that is both would keep the interlock — the conservative side.
 *
 *  2. `infra_concentrators` — one per customer concentrator, in the
 *     customer's tenant. The credential is never in clear:
 *       - routeros_chr: `device_id` names the devices row whose RouterOS API
 *         transport (vault, `device_transports.secret_enc`) ObliWAN dials;
 *         this table holds no secret for it (CHECK).
 *       - opnsense: the REST API key and secret in `api_key_enc` /
 *         `api_secret_enc` (secretVault format, `key_version`), and the API
 *         certificate's pinned SHA-256 in `tls_fingerprint_sha256`.
 *
 *  3. `infra_site_accounts` — one per (concentrator, site): the account
 *     ObliWAN believes the site has there, its state, the last job and when
 *     the concentrator was last read for it.
 *
 *  4. `infra_account_jobs` — one per job: the NON-SECRET attributes frozen at
 *     enqueue and what the job found. The password is in no column.
 *
 * FOREIGN KEYS POINT AWAY FROM THE JOB TABLES' PARENTS (068's lesson: a key
 * from a parent table into anything reachable from `change_jobs` made a
 * TRUNCATE … CASCADE of the job tables empty `devices`). Here every key goes
 * from a leaf to its parent: `infra_account_jobs` → change_jobs / sites /
 * infra_concentrators; `infra_site_accounts` → sites / infra_concentrators;
 * `infra_concentrators` → tenants / devices. `infra_site_accounts.last_job_id`
 * carries NO key: a TRUNCATE of the job history must not empty the account
 * registry, and a reference to a vanished job only loses its status line.
 *
 * No `?` anywhere in the SQL below (knex binding trap, migration 032); the
 * constraint text read back is checked for one before it is executed.
 */

const KIND = 'infra_account';
const CHANGE_JOB_CHECKS = ['change_jobs_kind_chk', 'change_jobs_guard_required_chk'] as const;

const KIND_LIST_RE = /\(kind\)::text (= ANY|<> ALL) \(\(?ARRAY\[/g;
const FIRST_ELEMENT_RE = /ARRAY\[(\('[a-z_]+'::[a-z ]+\)::[a-z ]+|'[a-z_]+'::[a-z ]+)[,\]]/;

async function readConstraint(knex: Knex, table: string, name: string): Promise<string> {
  const row = (await knex('pg_constraint as c')
    .join('pg_class as t', 't.oid', 'c.conrelid')
    .where('t.relname', table)
    .where('c.conname', name)
    .first(knex.raw('pg_get_constraintdef(c.oid) AS def'))) as { def: string } | undefined;
  if (!row) throw new Error(`074: ${table} has no constraint ${name}`);
  return row.def;
}

function element(def: string): string {
  const first = FIRST_ELEMENT_RE.exec(def);
  if (!first) throw new Error(`074: cannot tell how the kind list is spelled in: ${def}`);
  return first[1].replace(/'[a-z_]+'/, `'${KIND}'`);
}

/** This kind, right AFTER its sibling `concentrator_secret` (040) — not at the
 *  end. 058, 065 and 066 append theirs at the end and their harnesses read
 *  their own down-then-up back byte for byte: a kind appended after
 *  066's would make 066's round trip move `legacy_compliance` behind it. At a
 *  fixed anchor, this kind's own round trip is the identity, and so is that of
 *  every later migration that appends. Falls back to the end only on a list
 *  without the anchor (none since 040). */
export function widenKindList(def: string): string {
  if (def.includes(`'${KIND}'::`)) return def;
  const el = element(def);
  const anchor = el.replace(`'${KIND}'`, "'concentrator_secret'");
  if (def.split(anchor).length === 2) return def.replace(anchor, `${anchor}, ${el}`);
  const starts = [...def.matchAll(KIND_LIST_RE)];
  if (starts.length !== 1) throw new Error(`074: expected exactly one kind list, found ${starts.length}, in: ${def}`);
  const from = (starts[0].index as number) + starts[0][0].length;
  const end = def.indexOf(']', from);
  if (end < 0) throw new Error(`074: the kind list does not close in: ${def}`);
  return `${def.slice(0, end)}, ${el}${def.slice(end)}`;
}

export function narrowKindList(def: string): string {
  if (!def.includes(`'${KIND}'::`)) return def;
  const el = element(def);
  return def.split(`${el}, `).join('').split(`, ${el}`).join('');
}

async function rewrite(knex: Knex, table: string, name: string, transform: (def: string) => string): Promise<void> {
  const before = await readConstraint(knex, table, name);
  const after = transform(before);
  if (after === before) return;
  if (after.includes('?')) throw new Error(`074: refusing to execute a constraint containing '?': ${after}`);
  await knex.schema.raw(`ALTER TABLE ${table} DROP CONSTRAINT ${name}`);
  await knex.schema.raw(`ALTER TABLE ${table} ADD CONSTRAINT ${name} ${after}`);
}

export async function up(knex: Knex): Promise<void> {
  // ── 1. The kind ─────────────────────────────────────────────────────────
  for (const name of CHANGE_JOB_CHECKS) await rewrite(knex, 'change_jobs', name, widenKindList);

  // ── 2. infra_concentrators ──────────────────────────────────────────────
  await knex.schema.createTable('infra_concentrators', (t) => {
    t.increments('id').primary();
    t.integer('tenant_id').notNullable().references('id').inTable('tenants').onDelete('CASCADE');
    t.string('kind', 16).notNullable();
    t.string('name', 64).notNullable();
    t.string('host', 253).notNullable();
    t.integer('port').nullable();
    // CHR only: whose RouterOS API transport is dialled. RESTRICT: a device
    // still declared as somebody's infra concentrator is not deleted silently.
    t.integer('device_id').nullable().references('id').inTable('devices').onDelete('RESTRICT');
    t.boolean('enabled').notNullable().defaultTo(true);
    // Variable KEYS and the PPP profile — never a value of a secret.
    t.jsonb('params').notNullable().defaultTo('{}');
    // OPNsense REST credential, secretVault format. Never a plaintext.
    t.text('api_key_enc').nullable();
    t.text('api_secret_enc').nullable();
    t.integer('key_version').nullable();
    t.string('tls_fingerprint_sha256', 64).nullable();
    t.timestamp('last_test_at', { useTz: true }).nullable();
    t.boolean('last_test_ok').nullable();
    t.text('last_test_message').nullable();
    t.integer('created_by').nullable();
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });
  const concentratorChecks: Array<[string, string]> = [
    ['kind_chk', "kind IN ('routeros_chr','opnsense')"],
    ['name_chk', "btrim(name) <> ''"],
    ['host_chk', "btrim(host) <> ''"],
    ['port_chk', 'port IS NULL OR port BETWEEN 1 AND 65535'],
    ['params_chk', "jsonb_typeof(params) = 'object'"],
    // A CHR is dialled through its device row and holds no secret here.
    ['chr_shape_chk',
      "kind <> 'routeros_chr' OR (device_id IS NOT NULL AND api_key_enc IS NULL AND api_secret_enc IS NULL)"],
    // An OPNsense always has its credential, with the key generation beside it.
    ['opnsense_shape_chk',
      "kind <> 'opnsense' OR (api_key_enc IS NOT NULL AND api_secret_enc IS NOT NULL AND key_version IS NOT NULL)"],
    ['key_version_chk', 'key_version IS NULL OR key_version >= 1'],
    ['fingerprint_chk', "tls_fingerprint_sha256 IS NULL OR tls_fingerprint_sha256 ~ '^[0-9a-f]{64}$'"],
    ['test_chk', '(last_test_at IS NULL) = (last_test_ok IS NULL)'],
  ];
  for (const [name, expr] of concentratorChecks) {
    await knex.schema.raw(`ALTER TABLE infra_concentrators ADD CONSTRAINT infra_concentrators_${name} CHECK (${expr})`);
  }
  await knex.schema.raw(
    'CREATE UNIQUE INDEX infra_concentrators_tenant_name_uq ON infra_concentrators (tenant_id, lower(name))',
  );

  // ── 3. infra_site_accounts ──────────────────────────────────────────────
  await knex.schema.createTable('infra_site_accounts', (t) => {
    t.increments('id').primary();
    t.integer('tenant_id').notNullable();
    t.integer('site_id').notNullable().references('id').inTable('sites').onDelete('CASCADE');
    t.integer('concentrator_id').notNullable().references('id').inTable('infra_concentrators').onDelete('CASCADE');
    t.string('account_kind', 16).notNullable();
    t.string('identifier', 128).notNullable();
    t.string('state', 16).notNullable();
    // No foreign key, on purpose (header).
    t.bigInteger('last_job_id').nullable();
    t.timestamp('observed_at', { useTz: true }).nullable();
    t.text('detail').nullable();
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.unique(['concentrator_id', 'site_id']);
  });
  const accountChecks: Array<[string, string]> = [
    ['kind_chk', "account_kind IN ('l2tp_secret','ipsec_tunnel')"],
    ['state_chk', "state IN ('planned','provisioned','revoked','error')"],
    ['identifier_chk', "btrim(identifier) <> ''"],
    // 'provisioned' is only ever said by a job that read the concentrator.
    ['provisioned_observed_chk', "state <> 'provisioned' OR observed_at IS NOT NULL"],
  ];
  for (const [name, expr] of accountChecks) {
    await knex.schema.raw(`ALTER TABLE infra_site_accounts ADD CONSTRAINT infra_site_accounts_${name} CHECK (${expr})`);
  }
  await knex.schema.raw('CREATE INDEX infra_site_accounts_site_idx ON infra_site_accounts (tenant_id, site_id)');

  // ── 4. infra_account_jobs ───────────────────────────────────────────────
  await knex.schema.createTable('infra_account_jobs', (t) => {
    t.bigInteger('job_id').primary().references('id').inTable('change_jobs').onDelete('CASCADE');
    t.integer('tenant_id').notNullable();
    t.integer('site_id').notNullable().references('id').inTable('sites').onDelete('CASCADE');
    t.integer('concentrator_id').notNullable().references('id').inTable('infra_concentrators').onDelete('RESTRICT'); // history outlives nothing: a declaration with jobs is disabled, not deleted
    t.string('action', 8).notNullable();
    t.string('account_kind', 16).notNullable();
    // Frozen at enqueue, never a password.
    t.string('identifier', 128).notNullable();
    t.specificType('remote_address', 'inet').nullable();
    t.string('ppp_profile', 64).nullable();
    t.string('comment', 160).notNullable();
    t.string('outcome', 16).nullable();
    t.text('outcome_detail').nullable();
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });
  const jobChecks: Array<[string, string]> = [
    ['action_chk', "action IN ('ensure','revoke')"],
    ['kind_chk', "account_kind IN ('l2tp_secret','ipsec_tunnel')"],
    ['outcome_chk', "outcome IS NULL OR outcome IN ('added','present','removed','absent','conflict')"],
    ['detail_chk', '(outcome IS NULL) = (outcome_detail IS NULL)'],
    ['outcome_action_chk',
      "outcome IS NULL OR outcome = 'conflict' OR (action = 'ensure' AND outcome IN ('added','present')) " +
        "OR (action = 'revoke' AND outcome IN ('removed','absent'))"],
    ['identifier_chk', "btrim(identifier) <> ''"],
  ];
  for (const [name, expr] of jobChecks) {
    await knex.schema.raw(`ALTER TABLE infra_account_jobs ADD CONSTRAINT infra_account_jobs_${name} CHECK (${expr})`);
  }
  await knex.schema.raw('CREATE INDEX infra_account_jobs_site_idx ON infra_account_jobs (site_id, concentrator_id, job_id DESC)');
}

export async function down(knex: Knex): Promise<void> {
  // A job of this kind cannot be relabelled as another kind without lying
  // about what was done: the jobs go (their steps and infra_account_jobs rows
  // cascade; their commands stay in the append-only `command_audit`).
  await knex('change_jobs').where({ kind: KIND }).del();
  await knex.schema.dropTableIfExists('infra_account_jobs');
  await knex.schema.dropTableIfExists('infra_site_accounts');
  await knex.schema.dropTableIfExists('infra_concentrators');
  for (const name of [...CHANGE_JOB_CHECKS].reverse()) {
    await rewrite(knex, 'change_jobs', name, narrowKindList);
  }
}
