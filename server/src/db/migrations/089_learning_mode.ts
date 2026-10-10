import type { Knex } from 'knex';

/**
 * 089 — learning mode (the one no-secrets exception, 2026-10-04).
 *
 * (1) `devices.learning_since` / `learning_by`: the per-device flag. While it
 *     is set, every template-driven write (a `push` job, a plan compile, a
 *     rollout wave) is refused by name; the targeted jobs stay allowed. No
 *     DEFAULT: a default would put routers in learning nobody chose.
 *
 * (2) `learning_captures`: one capture of one router. Only the REDACTED copy
 *     lives here — every secret replaced by `secret:<ref>`, every line whose
 *     secret sits inside a quoted value withheld whole. The raw export, read
 *     with its secrets over SSH, is parsed in memory and never stored.
 *
 * (3) `learned_secrets`: the vault rows the capture produced, attached to the
 *     SITE. The plaintext is in no column: `secret_enc` is a secretVault blob
 *     (its key version inside it AND in `key_version`), `fingerprint` a
 *     per-tenant HMAC. Revealing one is SECRET_READ.
 *
 * Every CHECK is an IN list or a length test, never a regex, and no `?`
 * appears in any raw SQL (knex rewrites it as a binding placeholder).
 */

const CAPTURE_REASONS = [
  'not_learning', 'not_mikrotik', 'concentrator', 'not_active', 'no_site', 'no_ssh',
  'no_credential', 'concentrator_degraded', 'ppp_down', 'identity_mismatch',
  'identity_unproven', 'auth_failed', 'unreachable', 'timeout', 'ssh_failed',
  'no_sensitive_policy', 'policy_unknown', 'family_mismatch', 'export_failed',
  'export_empty', 'redaction_incomplete', 'interrupted', 'internal',
];

function inList(values: readonly string[]): string {
  return values.map((v) => `'${v}'`).join(',');
}

export async function up(knex: Knex): Promise<void> {
  // ==========================================================================
  // 1. devices — the flag
  // ==========================================================================
  await knex.schema.alterTable('devices', (t) => {
    t.timestamp('learning_since', { useTz: true }).nullable();
    t.integer('learning_by').nullable().references('id').inTable('users').onDelete('SET NULL');
  });
  await knex.schema.raw(
    'ALTER TABLE devices ADD CONSTRAINT devices_learning_by_chk CHECK (learning_by IS NULL OR learning_since IS NOT NULL)',
  );
  await knex.schema.raw(
    'CREATE INDEX devices_learning_idx ON devices (tenant_id) WHERE learning_since IS NOT NULL',
  );

  // ==========================================================================
  // 2. learning_captures
  // ==========================================================================
  await knex.schema.createTable('learning_captures', (t) => {
    t.bigIncrements('id').primary();
    t.integer('tenant_id').notNullable().references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('device_id').notNullable();
    t.integer('site_id').nullable();
    t.uuid('run_id').notNullable();
    t.string('status', 16).notNullable();
    t.string('reason', 32).nullable();
    t.text('detail').nullable();
    t.string('account', 16).nullable();
    t.string('family', 32).nullable();
    t.string('os_version', 64).nullable();
    t.string('model', 128).nullable();
    t.binary('redacted_gz').nullable();
    t.specificType('redacted_sha256', 'char(64)').nullable();
    t.integer('redacted_bytes').nullable();
    t.jsonb('facts').nullable();
    t.integer('secret_count').nullable();
    t.jsonb('withheld').notNullable().defaultTo(knex.raw("'[]'::jsonb"));
    t.bigInteger('snapshot_id').nullable().references('id').inTable('config_snapshots').onDelete('SET NULL');
    t.text('snapshot_error').nullable();
    t.integer('requested_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.timestamp('started_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('finished_at', { useTz: true }).nullable();
  });
  await knex.schema.raw(
    'ALTER TABLE learning_captures ADD CONSTRAINT learning_captures_device_fk ' +
      'FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE',
  );
  await knex.schema.raw(
    'ALTER TABLE learning_captures ADD CONSTRAINT learning_captures_site_fk ' +
      'FOREIGN KEY (site_id, tenant_id) REFERENCES sites (id, tenant_id) ON DELETE SET NULL (site_id)',
  );
  await knex.schema.raw(
    `ALTER TABLE learning_captures ADD CONSTRAINT learning_captures_status_chk CHECK (status IN (${inList(['running', 'succeeded', 'failed', 'skipped'])}))`,
  );
  await knex.schema.raw(
    `ALTER TABLE learning_captures ADD CONSTRAINT learning_captures_reason_chk CHECK (reason IS NULL OR reason IN (${inList(CAPTURE_REASONS)}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE learning_captures ADD CONSTRAINT learning_captures_detail_chk CHECK (detail IS NULL OR char_length(detail) <= 300)',
  );
  await knex.schema.raw(
    `ALTER TABLE learning_captures ADD CONSTRAINT learning_captures_account_chk CHECK (account IS NULL OR account IN (${inList(['legacy_admin', 'device_ssh'])}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE learning_captures ADD CONSTRAINT learning_captures_secret_count_chk CHECK (secret_count IS NULL OR secret_count >= 0)',
  );
  await knex.schema.raw(
    'ALTER TABLE learning_captures ADD CONSTRAINT learning_captures_snapshot_error_chk CHECK (snapshot_error IS NULL OR char_length(snapshot_error) <= 300)',
  );
  await knex.schema.raw(
    `ALTER TABLE learning_captures ADD CONSTRAINT learning_captures_terminal_chk CHECK (
       (status = 'running' AND finished_at IS NULL) OR (status <> 'running' AND finished_at IS NOT NULL))`,
  );
  await knex.schema.raw(
    `ALTER TABLE learning_captures ADD CONSTRAINT learning_captures_redacted_chk CHECK (
       (redacted_gz IS NULL AND redacted_sha256 IS NULL AND redacted_bytes IS NULL)
       OR (redacted_gz IS NOT NULL AND redacted_sha256 IS NOT NULL AND redacted_bytes IS NOT NULL))`,
  );
  await knex.schema.raw(
    `ALTER TABLE learning_captures ADD CONSTRAINT learning_captures_succeeded_chk CHECK (
       status <> 'succeeded'
       OR (redacted_gz IS NOT NULL AND facts IS NOT NULL AND secret_count IS NOT NULL AND reason IS NULL))`,
  );
  await knex.schema.raw(
    `ALTER TABLE learning_captures ADD CONSTRAINT learning_captures_refused_chk CHECK (
       status NOT IN ('failed','skipped')
       OR (reason IS NOT NULL AND redacted_gz IS NULL AND facts IS NULL))`,
  );
  await knex.schema.raw(
    `ALTER TABLE learning_captures ADD CONSTRAINT learning_captures_running_chk CHECK (
       status <> 'running' OR (reason IS NULL AND redacted_gz IS NULL))`,
  );
  await knex.schema.raw(
    'ALTER TABLE learning_captures ADD CONSTRAINT learning_captures_id_tenant_uq UNIQUE (id, tenant_id)',
  );
  await knex.schema.raw(
    'CREATE INDEX learning_captures_device_idx ON learning_captures (device_id, started_at DESC)',
  );
  await knex.schema.raw('CREATE INDEX learning_captures_run_idx ON learning_captures (tenant_id, run_id)');
  await knex.schema.raw(
    "CREATE INDEX learning_captures_running_idx ON learning_captures (tenant_id) WHERE status = 'running'",
  );
  await knex.schema.raw(
    "COMMENT ON TABLE learning_captures IS 'Learning mode (no-secrets exception of 2026-10-04): only the REDACTED copy of a capture lives here, every secret replaced by secret:<ref>; the raw export is never stored.'",
  );

  // ==========================================================================
  // 3. learned_secrets
  // ==========================================================================
  await knex.schema.createTable('learned_secrets', (t) => {
    t.bigIncrements('id').primary();
    t.integer('tenant_id').notNullable().references('id').inTable('tenants').onDelete('CASCADE');
    t.integer('site_id').notNullable();
    t.integer('device_id').notNullable();
    t.bigInteger('capture_id').nullable();
    t.string('ref', 200).notNullable();
    t.string('menu', 128).notNullable();
    t.string('item', 128).nullable();
    t.string('prop', 64).notNullable();
    t.text('secret_enc').notNullable();
    t.integer('key_version').notNullable();
    t.string('fingerprint', 32).nullable();
    t.timestamp('first_seen_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('last_seen_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('vanished_at', { useTz: true }).nullable();
  });
  await knex.schema.raw(
    'ALTER TABLE learned_secrets ADD CONSTRAINT learned_secrets_site_fk ' +
      'FOREIGN KEY (site_id, tenant_id) REFERENCES sites (id, tenant_id) ON DELETE CASCADE',
  );
  await knex.schema.raw(
    'ALTER TABLE learned_secrets ADD CONSTRAINT learned_secrets_device_fk ' +
      'FOREIGN KEY (device_id, tenant_id) REFERENCES devices (id, tenant_id) ON DELETE CASCADE',
  );
  await knex.schema.raw(
    'ALTER TABLE learned_secrets ADD CONSTRAINT learned_secrets_capture_fk ' +
      'FOREIGN KEY (capture_id, tenant_id) REFERENCES learning_captures (id, tenant_id) ON DELETE SET NULL (capture_id)',
  );
  await knex.schema.raw(
    'ALTER TABLE learned_secrets ADD CONSTRAINT learned_secrets_ref_chk CHECK (char_length(ref) >= 1)',
  );
  await knex.schema.raw(
    'ALTER TABLE learned_secrets ADD CONSTRAINT learned_secrets_key_version_chk CHECK (key_version >= 1)',
  );
  await knex.schema.raw(
    'ALTER TABLE learned_secrets ADD CONSTRAINT learned_secrets_seen_chk CHECK (last_seen_at >= first_seen_at)',
  );
  await knex.schema.raw(
    'ALTER TABLE learned_secrets ADD CONSTRAINT learned_secrets_device_ref_uq UNIQUE (device_id, ref)',
  );
  await knex.schema.raw('CREATE INDEX learned_secrets_site_idx ON learned_secrets (site_id)');
  await knex.schema.raw('CREATE INDEX learned_secrets_fingerprint_idx ON learned_secrets (tenant_id, fingerprint)');
  await knex.schema.raw(
    "COMMENT ON TABLE learned_secrets IS 'Learning mode: secrets read off a router in learning, attached to its site. The plaintext is never in any column (secret_enc is a vault blob); revealing one is SECRET_READ only.'",
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists('learned_secrets');
  await knex.schema.dropTableIfExists('learning_captures');
  await knex.schema.raw('DROP INDEX IF EXISTS devices_learning_idx');
  await knex.schema.raw('ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_learning_by_chk');
  await knex.schema.alterTable('devices', (t) => {
    t.dropForeign(['learning_by']);
  });
  await knex.schema.alterTable('devices', (t) => {
    t.dropColumn('learning_by');
    t.dropColumn('learning_since');
  });
}
