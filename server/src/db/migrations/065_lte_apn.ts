import type { Knex } from 'knex';

/**
 * 065_lte_apn.ts — the change job that points ONE MikroTik's lte1 at the APN
 * profile an operator chose in the device's settings (kind `lte_apn`,
 * shared/src/lteApn.ts, services/change/lteApn.service.ts). The NCM does not
 * model `/interface lte`, so no plan can carry it; the job goes through the
 * queue like every other write and travels over SSH, the channel a
 * router in service answers on.
 *
 *  1. `change_jobs.kind` gains `lte_apn` (7 characters; varchar(24) since 040).
 *
 *  2. 009's write-kind CHECKs, as 058 left them, one by one:
 *       - `change_jobs_kind_chk`             WIDENED.
 *       - `change_jobs_guard_required_chk`   WIDENED. The job carries its own
 *         verdict, written at enqueue (ACCEPT: two allow-listed lines, and an
 *         egress check on the router that refuses when the management path
 *         may ride the modem).
 *       - `change_jobs_degraded_confirm_chk` WIDENED. No dead-man is armed
 *         (many Chateaux run device-mode `home`, where the scheduler is
 *         blocked), so the job is queued at `degraded` with the operator's
 *         explicit confirmation.
 *       - `change_jobs_preflight_backup_chk` NOT widened: a router already on
 *         the chosen profile writes nothing and takes no backup. Restated where
 *         it is exact: `lte_apn_jobs_backup_before_write_chk`.
 *     Read back and widened like 058 (`pg_get_constraintdef`, the kind
 *     APPENDED to the single kind list, a definition with no list or several
 *     makes the migration throw); `down()` removes exactly this kind.
 *     `rollouts` are NOT widened: the choice is per device, made on its page.
 *
 *  3. `lte_apn_jobs` — one row per job: the profile and APN frozen at enqueue
 *     (from the catalogue resolved for the device), the SSH address it dials,
 *     the backup, when it first wrote, what it read before (`before`), what
 *     it read back on a fresh session (`observed`), the egress verdict that
 *     allowed or refused the write (`egress`), and the outcome.
 *
 *  4. `devices.lte_apn_profile` — the profile chosen for this device, set
 *     when a job read it back on the router. NULL = never chosen; no DEFAULT
 *     (a default would claim a choice nobody made). The render supplies it as
 *     the bench-level `sim_apn_profile` (template/render.service.ts).
 *
 * No `?` anywhere in the SQL below (knex binding trap, migration 032).
 */

const KIND = 'lte_apn';
const CHANGE_JOB_CHECKS = [
  'change_jobs_kind_chk',
  'change_jobs_guard_required_chk',
  'change_jobs_degraded_confirm_chk',
] as const;
/** `LTE_APN_OUTCOMES` in lteApn.service.ts. */
const OUTCOMES = "'applied','present','refused','failed'";
/** The catalogue's JSON-schema pattern (shared/src/lteApn.ts). */
const TOKEN = "'^[A-Za-z0-9._-]{1,63}$'";

const KIND_LIST_RE = /\(kind\)::text (= ANY|<> ALL) \(\(?ARRAY\[/g;
const FIRST_ELEMENT_RE = /ARRAY\[(\('[a-z_]+'::[a-z ]+\)::[a-z ]+|'[a-z_]+'::[a-z ]+)[,\]]/;

async function readConstraint(knex: Knex, table: string, name: string): Promise<string> {
  const row = (await knex('pg_constraint as c')
    .join('pg_class as t', 't.oid', 'c.conrelid')
    .where('t.relname', table)
    .where('c.conname', name)
    .first(knex.raw('pg_get_constraintdef(c.oid) AS def'))) as { def: string } | undefined;
  if (!row) throw new Error(`065: ${table} has no constraint ${name}`);
  return row.def;
}

function element(def: string): string {
  const first = FIRST_ELEMENT_RE.exec(def);
  if (!first) throw new Error(`065: cannot tell how the kind list is spelled in: ${def}`);
  return first[1].replace(/'[a-z_]+'/, `'${KIND}'`);
}

export function widenKindList(def: string): string {
  if (def.includes(`'${KIND}'::`)) return def;
  const el = element(def);
  const starts = [...def.matchAll(KIND_LIST_RE)];
  if (starts.length !== 1) throw new Error(`065: expected exactly one kind list, found ${starts.length}, in: ${def}`);
  const from = (starts[0].index as number) + starts[0][0].length;
  const end = def.indexOf(']', from);
  if (end < 0) throw new Error(`065: the kind list does not close in: ${def}`);
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
  if (after.includes('?')) throw new Error(`065: refusing to execute a constraint containing '?': ${after}`);
  await knex.schema.raw(`ALTER TABLE ${table} DROP CONSTRAINT ${name}`);
  await knex.schema.raw(`ALTER TABLE ${table} ADD CONSTRAINT ${name} ${after}`);
}

export async function up(knex: Knex): Promise<void> {
  for (const name of CHANGE_JOB_CHECKS) await rewrite(knex, 'change_jobs', name, widenKindList);

  await knex.schema.createTable('lte_apn_jobs', (t) => {
    t.bigInteger('job_id').primary().references('id').inTable('change_jobs').onDelete('CASCADE');
    t.integer('tenant_id').notNullable();
    t.integer('device_id').notNullable().references('id').inTable('devices').onDelete('CASCADE');
    // Frozen at enqueue from the catalogue resolved for the device; the worker
    // refuses when the catalogue says otherwise by then.
    t.string('profile_name', 63).notNullable();
    t.string('apn', 63).notNullable();
    t.string('ssh_host', 255).notNullable();
    t.bigInteger('backup_id').nullable().references('id').inTable('device_backups');
    t.timestamp('wrote_at', { useTz: true }).nullable();
    // NULL until the job has looked: no DEFAULT.
    t.jsonb('before').nullable();
    t.jsonb('observed').nullable();
    t.jsonb('egress').nullable();
    t.string('outcome', 16).nullable();
    t.text('outcome_detail').nullable();
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });
  const jobChecks: Array<[string, string]> = [
    ['outcome_chk', `outcome IS NULL OR outcome IN (${OUTCOMES})`],
    ['detail_chk', '(outcome IS NULL) = (outcome_detail IS NULL)'],
    ['backup_before_write_chk', 'wrote_at IS NULL OR backup_id IS NOT NULL'],
    // No write without the verdict that allowed it on record.
    ['egress_before_write_chk', "wrote_at IS NULL OR (egress IS NOT NULL AND egress->>'state' = 'clear')"],
    ['applied_wrote_chk', "outcome IS DISTINCT FROM 'applied' OR (wrote_at IS NOT NULL AND observed IS NOT NULL)"],
    ['present_unwritten_chk', "outcome IS DISTINCT FROM 'present' OR (wrote_at IS NULL AND observed IS NOT NULL)"],
    ['refused_unwritten_chk', "outcome IS DISTINCT FROM 'refused' OR wrote_at IS NULL"],
    ['profile_chk', `profile_name ~ ${TOKEN}`],
    ['apn_chk', `apn ~ ${TOKEN}`],
    ['before_chk', "before IS NULL OR jsonb_typeof(before) = 'object'"],
    ['observed_chk', "observed IS NULL OR jsonb_typeof(observed) = 'object'"],
    ['egress_chk', "egress IS NULL OR jsonb_typeof(egress) = 'object'"],
    ['ssh_host_chk', "btrim(ssh_host) <> ''"],
  ];
  for (const [name, expr] of jobChecks) {
    await knex.schema.raw(`ALTER TABLE lte_apn_jobs ADD CONSTRAINT lte_apn_jobs_${name} CHECK (${expr})`);
  }
  await knex.schema.raw('CREATE INDEX lte_apn_jobs_device_idx ON lte_apn_jobs (device_id, job_id DESC)');
  await knex.schema.raw('CREATE INDEX lte_apn_jobs_tenant_idx ON lte_apn_jobs (tenant_id, job_id DESC)');

  await knex.schema.alterTable('devices', (t) => {
    t.string('lte_apn_profile', 63).nullable();
  });
  await knex.schema.raw(
    `ALTER TABLE devices ADD CONSTRAINT devices_lte_apn_profile_chk CHECK (lte_apn_profile IS NULL OR lte_apn_profile ~ ${TOKEN})`,
  );
}

export async function down(knex: Knex): Promise<void> {
  // A job of this kind cannot be relabelled as another kind without lying
  // about what was done: the jobs go (their steps and lte_apn_jobs rows
  // cascade; their commands stay in the append-only `command_audit`).
  await knex('change_jobs').where({ kind: KIND }).del();
  await knex.schema.raw('ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_lte_apn_profile_chk');
  await knex.schema.alterTable('devices', (t) => {
    t.dropColumn('lte_apn_profile');
  });
  await knex.schema.dropTableIfExists('lte_apn_jobs');
  for (const name of [...CHANGE_JOB_CHECKS].reverse()) {
    await rewrite(knex, 'change_jobs', name, narrowKindList);
  }
}
