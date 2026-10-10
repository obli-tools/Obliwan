import type { Knex } from 'knex';

/**
 * 088_site_rename.ts — the change job that renames a site's router TOGETHER
 * (kind `site_rename`, shared/src/siteRename.ts,
 * services/change/siteRename.service.ts): the PPP login on the shared CHR (its
 * /ppp/secret), the user of the router's management tunnel (the l2tp-client
 * named l2tp-mgmt), the router's /system identity, the device row and, when
 * asked, the site code. It goes through the queue like every other write,
 * on the ROUTER's device row.
 *
 *  1. `change_jobs.kind` gains `site_rename` (11 characters; varchar(24) since
 *     040). 009's write-kind CHECKs, as the live database holds them, one by
 *     one:
 *       - `change_jobs_kind_chk`             WIDENED.
 *       - `change_jobs_guard_required_chk`   WIDENED: the job carries its own
 *         verdict, written at enqueue.
 *       - `change_jobs_degraded_confirm_chk` WIDENED: no on-box dead-man is
 *         armed (a self-revert started with `:execute` guards the cut line),
 *         so the job is queued at `degraded` with the operator's explicit
 *         confirmation.
 *       - `change_jobs_preflight_backup_chk` NOT widened: a re-run that only
 *         settles the CHR or the device row, or a code-only rename, writes
 *         nothing on the router and takes no backup. Restated where it is
 *         exact: `site_rename_jobs_cut_after_net_chk` and
 *         `site_rename_jobs_identity_after_backup_chk`.
 *     READ BACK at run time (`pg_get_constraintdef`), never written from a
 *     snapshot: other migrations widen the same lists (053 prepends, 058, 065
 *     and 066 append, 074 inserts after `concentrator_secret`, a sibling of
 *     this one after `infra_account`). This kind is inserted RIGHT AFTER
 *     `push`, an anchor no migration removes or moves, so every one of those
 *     round trips (down then up) stays the identity on the live list, and so
 *     does this one's. A definition with no `push`, or several kind lists,
 *     makes the migration throw. `down()` removes exactly this kind.
 *     NOT admitted by rollouts. NOT exempted from the subtree interlock
 *     (055): the job is on the CHILD, a job on its concentrator and this one
 *     exclude each other — wanted, since this one writes on the CHR too;
 *     `concentrator_secret` stays exempt as 040 made it.
 *
 *  2. `site_rename_jobs` — one row per job: what was frozen at enqueue (the
 *     from/to pairs, the tunnel address the new secret must keep, the SSH
 *     address the job dials, the self-revert's delay and the tunnel's return
 *     bound — never a credential), the backup it took, what it read before and
 *     after, how the new login reached the CHR and every instant that decides
 *     what a failure leaves behind. Foreign keys only from this leaf to its
 *     parents (068's lesson).
 *
 * No `?` anywhere in the SQL below (knex binding trap, migration 032), no
 * regular expression in any CHECK (translate() and IN lists only); the
 * constraint text read back is checked for a `?` before it is executed.
 */

const KIND = 'site_rename';
const ANCHOR = 'push';
const CHANGE_JOB_CHECKS = [
  'change_jobs_kind_chk',
  'change_jobs_guard_required_chk',
  'change_jobs_degraded_confirm_chk',
] as const;
/** `SITE_RENAME_OUTCOMES` (shared/src/siteRename.ts). */
const OUTCOMES = "'renamed','present','reverted','unsettled','refused','failed'";
/** `SITE_RENAME_TRANSFORMS`. */
const TRANSFORMS = "'lowercase','explicit'";
/** `SITE_RENAME_CHR_MODES`. */
const CHR_MODES = "'copy','in_place'";
/** The alphabet of a login or an identity this job writes. */
const NAME_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-';

const KIND_LIST_RE = /\(kind\)::text (= ANY|<> ALL) \(\(?ARRAY\[/g;
const FIRST_ELEMENT_RE = /ARRAY\[(\('[a-z_]+'::[a-z ]+\)::[a-z ]+|'[a-z_]+'::[a-z ]+)[,\]]/;

async function readConstraint(knex: Knex, table: string, name: string): Promise<string> {
  const row = (await knex('pg_constraint as c')
    .join('pg_class as t', 't.oid', 'c.conrelid')
    .where('t.relname', table)
    .where('c.conname', name)
    .first(knex.raw('pg_get_constraintdef(c.oid) AS def'))) as { def: string } | undefined;
  if (!row) throw new Error(`088: ${table} has no constraint ${name}`);
  return row.def;
}

/** This kind, spelled like the list's first element. */
function element(def: string, kind: string = KIND): string {
  const first = FIRST_ELEMENT_RE.exec(def);
  if (!first) throw new Error(`088: cannot tell how the kind list is spelled in: ${def}`);
  return first[1].replace(/'[a-z_]+'/, `'${kind}'`);
}

/** This kind right AFTER `push` in the one kind list (header, 1). */
export function widenKindList(def: string): string {
  if (def.includes(`'${KIND}'::`)) return def;
  const starts = [...def.matchAll(KIND_LIST_RE)];
  if (starts.length !== 1) throw new Error(`088: expected exactly one kind list, found ${starts.length}, in: ${def}`);
  const el = element(def);
  const anchor = element(def, ANCHOR);
  if (def.split(anchor).length !== 2) throw new Error(`088: the kind list does not hold '${ANCHOR}' exactly once: ${def}`);
  return def.replace(anchor, `${anchor}, ${el}`);
}

/** The element and the separator next to it go; nothing else moves. */
export function narrowKindList(def: string): string {
  if (!def.includes(`'${KIND}'::`)) return def;
  const el = element(def);
  return def.split(`${el}, `).join('').split(`, ${el}`).join('');
}

async function rewrite(knex: Knex, table: string, name: string, transform: (def: string) => string): Promise<void> {
  const before = await readConstraint(knex, table, name);
  const after = transform(before);
  if (after === before) return;
  if (after.includes('?')) throw new Error(`088: refusing to execute a constraint containing '?': ${after}`);
  await knex.schema.raw(`ALTER TABLE ${table} DROP CONSTRAINT ${name}`);
  await knex.schema.raw(`ALTER TABLE ${table} ADD CONSTRAINT ${name} ${after}`);
}

/** A name in the job's alphabet (the logins as 036 writes them). */
function alphabet(column: string, max: number): string {
  return `${column} <> '' AND char_length(${column}) <= ${max} AND translate(${column}, '${NAME_CHARS}', '') = '' AND ` +
    `strpos(${column}, '..') = 0 AND left(${column}, 1) <> '.' AND right(${column}, 1) <> '.'`;
}

export async function up(knex: Knex): Promise<void> {
  // ── 1. The kind, in the three change_jobs CHECKs ─────────────────────────
  for (const name of CHANGE_JOB_CHECKS) await rewrite(knex, 'change_jobs', name, widenKindList);

  // ── 2. site_rename_jobs ──────────────────────────────────────────────────
  await knex.schema.createTable('site_rename_jobs', (t) => {
    t.bigInteger('job_id').primary().references('id').inTable('change_jobs').onDelete('CASCADE');
    t.integer('tenant_id').notNullable();
    t.integer('device_id').notNullable().references('id').inTable('devices').onDelete('CASCADE');
    t.integer('site_id').nullable().references('id').inTable('sites').onDelete('SET NULL');
    // The CHR whose secret is renamed: frozen at enqueue, the device's own.
    t.integer('concentrator_id').notNullable().references('id').inTable('devices').onDelete('RESTRICT');
    // Frozen at enqueue: the pairs. A re-run of an unsettled job re-enqueues
    // THESE, not the device row's names of the moment.
    t.string('from_login', 128).notNullable();
    t.string('to_login', 128).notNullable();
    t.string('from_identity', 128).notNullable();
    t.string('to_identity', 128).notNullable();
    t.string('from_site_code', 64).nullable();
    t.string('to_site_code', 64).nullable();
    t.string('transform', 16).notNullable();
    // The management client's name, frozen at the first read that found it.
    t.string('tunnel_client', 64).nullable();
    // Where the job dials (an address, never an identity: every session
    // proves the box), and the address the new secret must keep.
    t.string('ssh_host', 255).notNullable();
    t.specificType('tunnel_address', 'inet').notNullable();
    t.integer('revert_after_s').notNullable();
    t.integer('tunnel_wait_s').notNullable();
    // The pre-change backup, restated (header, 1).
    t.bigInteger('backup_id').nullable().references('id').inTable('device_backups');
    // NULL until the job has looked or acted: no DEFAULT anywhere below.
    t.jsonb('before').nullable();
    t.jsonb('sent').nullable();
    t.jsonb('observed').nullable();
    // How the new login reached the CHR, the .id of the secret named <to>,
    // and the .id of the old one (what the cleanup removes, re-read first).
    t.string('chr_mode', 16).nullable();
    t.string('chr_to_id', 32).nullable();
    t.string('chr_from_id', 32).nullable();
    t.timestamp('chr_written_at', { useTz: true }).nullable();
    t.timestamp('chr_undone_at', { useTz: true }).nullable();
    t.timestamp('self_revert_armed_at', { useTz: true }).nullable();
    t.timestamp('db_login_switched_at', { useTz: true }).nullable();
    t.timestamp('cut_sent_at', { useTz: true }).nullable();
    t.timestamp('to_session_seen_at', { useTz: true }).nullable();
    t.timestamp('db_login_restored_at', { useTz: true }).nullable();
    t.timestamp('identity_set_at', { useTz: true }).nullable();
    t.timestamp('finalized_at', { useTz: true }).nullable();
    t.timestamp('chr_old_removed_at', { useTz: true }).nullable();
    t.string('outcome', 16).nullable();
    t.text('outcome_detail').nullable();
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });
  const jobChecks: Array<[string, string]> = [
    ['outcome_chk', `outcome IS NULL OR outcome IN (${OUTCOMES})`],
    ['detail_chk', '(outcome IS NULL) = (outcome_detail IS NULL)'],
    ['transform_chk', `transform IN (${TRANSFORMS})`],
    ['chr_mode_chk', `chr_mode IS NULL OR chr_mode IN (${CHR_MODES})`],
    ['from_login_chk', alphabet('from_login', 128)],
    ['to_login_chk', alphabet('to_login', 128)],
    ['to_identity_chk', alphabet('to_identity', 64)],
    ['from_identity_chk', "btrim(from_identity) <> ''"],
    ['site_code_pair_chk',
      "(from_site_code IS NULL) = (to_site_code IS NULL) AND (to_site_code IS NULL OR btrim(to_site_code) <> '')"],
    ['changes_chk',
      'from_login <> to_login OR from_identity <> to_identity OR from_site_code IS DISTINCT FROM to_site_code'],
    ['tunnel_address_chk', 'family(tunnel_address) = 4 AND masklen(tunnel_address) = 32'],
    ['ssh_host_chk', "btrim(ssh_host) <> ''"],
    ['tunnel_client_chk', "tunnel_client IS NULL OR btrim(tunnel_client) <> ''"],
    // The job must outwait the self-revert to read its decision back.
    ['waits_chk', 'revert_after_s BETWEEN 30 AND 600 AND tunnel_wait_s BETWEEN 60 AND 900 AND revert_after_s < tunnel_wait_s'],
    // In place is the CASE-ONLY fallback, never a general path.
    ['in_place_case_only_chk',
      "chr_mode IS DISTINCT FROM 'in_place' OR (lower(from_login) = lower(to_login) AND from_login <> to_login)"],
    // Stamped BEFORE the write leaves (its mode with it); the new secret's
    // .id comes from the read-back after it.
    ['chr_written_chk', 'chr_written_at IS NULL OR chr_mode IS NOT NULL'],
    ['chr_undone_chk', 'chr_undone_at IS NULL OR chr_written_at IS NOT NULL'],
    // The cut leaves only behind its nets: the backup, the self-revert seen,
    // the device row switched, the new secret on the CHR.
    ['cut_after_net_chk',
      'cut_sent_at IS NULL OR (backup_id IS NOT NULL AND self_revert_armed_at IS NOT NULL AND ' +
        'db_login_switched_at IS NOT NULL AND chr_to_id IS NOT NULL)'],
    ['identity_after_backup_chk', 'identity_set_at IS NULL OR backup_id IS NOT NULL'],
    // The old secret goes only once the new session was seen.
    ['old_removed_after_seen_chk', 'chr_old_removed_at IS NULL OR to_session_seen_at IS NOT NULL'],
    ['restored_after_switch_chk', 'db_login_restored_at IS NULL OR db_login_switched_at IS NOT NULL'],
    ['renamed_chk', "outcome IS DISTINCT FROM 'renamed' OR (finalized_at IS NOT NULL AND observed IS NOT NULL)"],
    ['present_chk',
      "outcome IS DISTINCT FROM 'present' OR (before IS NOT NULL AND chr_written_at IS NULL AND cut_sent_at IS NULL AND " +
        'identity_set_at IS NULL AND db_login_switched_at IS NULL AND chr_old_removed_at IS NULL)'],
    ['refused_unwritten_chk',
      "outcome IS DISTINCT FROM 'refused' OR (chr_written_at IS NULL AND cut_sent_at IS NULL AND identity_set_at IS NULL AND " +
        'db_login_switched_at IS NULL AND chr_old_removed_at IS NULL AND finalized_at IS NULL)'],
    ['before_chk', "before IS NULL OR jsonb_typeof(before) = 'object'"],
    ['sent_chk', "sent IS NULL OR jsonb_typeof(sent) = 'object'"],
    ['observed_chk', "observed IS NULL OR jsonb_typeof(observed) = 'object'"],
  ];
  for (const [name, expr] of jobChecks) {
    if (expr.includes('?')) throw new Error(`088: refusing to execute a CHECK containing '?': ${expr}`);
    await knex.schema.raw(`ALTER TABLE site_rename_jobs ADD CONSTRAINT site_rename_jobs_${name} CHECK (${expr})`);
  }
  await knex.schema.raw('CREATE INDEX site_rename_jobs_device_idx ON site_rename_jobs (device_id, job_id DESC)');
  await knex.schema.raw('CREATE INDEX site_rename_jobs_tenant_idx ON site_rename_jobs (tenant_id, job_id DESC)');
  await knex.schema.raw('CREATE INDEX site_rename_jobs_site_idx ON site_rename_jobs (site_id, job_id DESC)');
}

export async function down(knex: Knex): Promise<void> {
  // A job of this kind cannot be relabelled as another kind without lying
  // about what was done: the jobs go (their steps and site_rename_jobs rows
  // cascade; their commands stay in the append-only `command_audit`). No
  // rollout ever held one.
  await knex('change_jobs').where({ kind: KIND }).del();
  await knex.schema.dropTableIfExists('site_rename_jobs');
  for (const name of [...CHANGE_JOB_CHECKS].reverse()) {
    await rewrite(knex, 'change_jobs', name, narrowKindList);
  }
}
