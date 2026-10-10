import type { Knex } from 'knex';

/**
 * 090_wan_link.ts — the job that switches a store's WAN1 link between a box
 * handing out DHCP, a PPPoE login (ADSL / FTTH / FTTO) and a fixed address
 * (kind `wan_link`, shared/src/wanLink.ts, services/change/wanLink.service.ts).
 * It goes through the queue like every other write, over SSH with the
 * device's existing credential, and the change itself is ONE script started on
 * the router with `:execute`, which reverts by itself unless the new link
 * carries traffic within its delay.
 *
 *  1. `change_jobs.kind` gains `wan_link` (8 characters; varchar(24) since
 *     040). 009's write-kind CHECKs, as the earlier migrations left them:
 *       - `change_jobs_kind_chk`             WIDENED.
 *       - `change_jobs_guard_required_chk`   WIDENED: the job carries its own
 *         verdict, written at enqueue.
 *       - `change_jobs_degraded_confirm_chk` WIDENED: no dead-man is armed
 *         (the script's own revert is the net), so the job is queued at
 *         `degraded` with the operator's explicit confirmation.
 *       - `change_jobs_preflight_backup_chk` NOT widened: a router already on
 *         the target writes nothing and takes no backup. Restated exactly on
 *         `wan_link_jobs` (`backup_before_write_chk`).
 *     Each list is READ BACK at run time (pg_get_constraintdef) and gains only
 *     this kind, inserted immediately BEFORE `push` — an anchor every list has
 *     and no migration removes. Not at the end: 058, 065 and 066 append theirs
 *     and their harnesses read their own down-then-up back byte for byte, and
 *     a kind behind theirs would move them. Not after `push` either: 088
 *     (`site_rename`) anchors there. Before `push`, 053's prepend stays in front
 *     of it and every round trip — this one's included — is the identity.
 *     `down()` removes exactly this kind, from whatever the list holds then.
 *
 *  2. `rollouts` admit the kind (a whole customer by canary waves, the switch
 *     read from each site's declared variables):
 *       - `rollouts_kind_chk` gains it right AFTER `legacy_compliance` (066
 *         prepends that one and 058 appends its own: neither round trip moves
 *         this one), at the start when that anchor is absent;
 *       - `rollouts_kind_shape_chk` gains one flat disjunct right after 066's:
 *         a wan_link rollout names NO template revision and NO version;
 *       - `rollouts.wan_target_mode` (nullable) names the mode a wan_link
 *         rollout switches every site to, and only such a rollout has one.
 *
 *  3. `wan_link_jobs` — one row per job: the modes and the target frozen at
 *     enqueue (the PPPoE password ENCRYPTED, wiped once the job concludes),
 *     where it dials, the script's delay and the job's own bound, the backup,
 *     what it read before, what it sent, the script's id and when it was seen
 *     alive, its decision, the cut window during which the down and 4G alerts
 *     are held, the read-back and the outcome. No DEFAULT on a state column.
 *
 * FOREIGN KEYS point from this leaf to its parents only (068's lesson).
 *
 * No `?` anywhere in the SQL below (knex binding trap, migration 032), no
 * regex in a CHECK (IN lists and length tests only; the shapes are validated
 * in shared/src/wanLink.ts); a constraint text read back is checked for a `?`
 * before it is executed.
 */

const KIND = 'wan_link';
const CHANGE_JOB_CHECKS = [
  'change_jobs_kind_chk',
  'change_jobs_guard_required_chk',
  'change_jobs_degraded_confirm_chk',
] as const;
/** `WAN_LINK_OUTCOMES` in wanLink.service.ts. */
const OUTCOMES = "'applied','present','reverted','refused','failed'";
const MODES = "'dhcp','pppoe','static'";
const SHAPE_DISJUNCT = `(kind = '${KIND}' AND template_revision_id IS NULL AND target_version IS NULL)`;

const KIND_LIST_RE = /\(kind\)::text (= ANY|<> ALL) \(\(?ARRAY\[/g;
const FIRST_ELEMENT_RE = /ARRAY\[(\('[a-z_]+'::[a-z ]+\)::[a-z ]+|'[a-z_]+'::[a-z ]+)[,\]]/;

async function readConstraint(knex: Knex, table: string, name: string): Promise<string> {
  const row = (await knex('pg_constraint as c')
    .join('pg_class as t', 't.oid', 'c.conrelid')
    .where('t.relname', table)
    .where('c.conname', name)
    .first(knex.raw('pg_get_constraintdef(c.oid) AS def'))) as { def: string } | undefined;
  if (!row) throw new Error(`090: ${table} has no constraint ${name}`);
  return row.def;
}

/** This kind, spelled like the list's first element. */
function element(def: string): string {
  const first = FIRST_ELEMENT_RE.exec(def);
  if (!first) throw new Error(`090: cannot tell how the kind list is spelled in: ${def}`);
  return first[1].replace(/'[a-z_]+'/, `'${KIND}'`);
}

function onlyList(def: string): RegExpMatchArray {
  const starts = [...def.matchAll(KIND_LIST_RE)];
  if (starts.length !== 1) throw new Error(`090: expected exactly one kind list, found ${starts.length}, in: ${def}`);
  return starts[0];
}

function prepend(def: string, el: string): string {
  const start = onlyList(def);
  const at = (start.index as number) + start[0].length;
  return `${def.slice(0, at)}${el}, ${def.slice(at)}`;
}

/** change_jobs: this kind immediately BEFORE `push` (header, 1); at the start
 *  of the one list when `push` is absent. */
export function widenJobKindList(def: string): string {
  if (def.includes(`'${KIND}'::`)) return def;
  onlyList(def);
  const el = element(def);
  const anchor = el.replace(`'${KIND}'`, "'push'");
  if (def.split(anchor).length === 2) return def.replace(anchor, `${el}, ${anchor}`);
  return prepend(def, el);
}

/** rollouts: this kind right AFTER `legacy_compliance` (header, 2); at the
 *  start of the one list when that anchor is absent. */
export function widenRolloutKindList(def: string): string {
  if (def.includes(`'${KIND}'::`)) return def;
  onlyList(def);
  const el = element(def);
  const anchor = el.replace(`'${KIND}'`, "'legacy_compliance'");
  if (def.split(anchor).length === 2) return def.replace(anchor, `${anchor}, ${el}`);
  return prepend(def, el);
}

/** Wherever it sits: the element and the separator next to it go. */
export function narrowKindList(def: string): string {
  if (!def.includes(`'${KIND}'::`)) return def;
  const el = element(def);
  return def.split(`${el}, `).join('').split(`, ${el}`).join('');
}

function checkBody(def: string): string {
  const m = /^CHECK \((.*)\)$/s.exec(def.trim());
  if (!m) throw new Error(`090: not a CHECK definition: ${def}`);
  return m[1];
}

function wrappedWhole(s: string): boolean {
  if (!s.startsWith('(') || !s.endsWith(')')) return false;
  let depth = 0;
  let quoted = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "'") quoted = !quoted;
    if (quoted) continue;
    if (c === '(') depth++;
    else if (c === ')') {
      depth--;
      if (depth === 0 && i !== s.length - 1) return false;
    }
  }
  return depth === 0;
}

/** The top-level ` OR ` operands, after stripping parentheses that wrap the
 *  whole expression (066's reader, restated: a migration keeps its own). */
export function topLevelDisjuncts(expr: string): string[] {
  let s = expr.trim();
  while (wrappedWhole(s)) s = s.slice(1, -1).trim();
  const parts: string[] = [];
  let depth = 0;
  let quoted = false;
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "'") quoted = !quoted;
    if (quoted) continue;
    if (c === '(') depth++;
    else if (c === ')') depth--;
    else if (depth === 0 && s.startsWith(' OR ', i)) {
      parts.push(s.slice(start, i).trim());
      start = i + 4;
      i += 3;
    }
  }
  parts.push(s.slice(start).trim());
  return parts;
}

const wrap = (d: string): string => (wrappedWhole(d) ? d : `(${d})`);

/** The disjunct goes right after 066's (`legacy_compliance`), first when
 *  there is none; the others are re-written flat around it. */
export function widenShape(def: string): string {
  if (def.includes(`'${KIND}'`)) return def;
  const parts = topLevelDisjuncts(checkBody(def)).map(wrap);
  const at = parts.findIndex((d) => d.includes("'legacy_compliance'"));
  parts.splice(at + 1, 0, SHAPE_DISJUNCT);
  return `CHECK (${parts.join(' OR ')})`;
}

export function narrowShape(def: string): string {
  if (!def.includes(`'${KIND}'`)) return def;
  const kept = topLevelDisjuncts(checkBody(def)).filter((d) => !d.includes(`'${KIND}'`));
  if (kept.length === 0) throw new Error(`090: the shape CHECK would be left empty: ${def}`);
  return `CHECK (${kept.map(wrap).join(' OR ')})`;
}

async function rewrite(knex: Knex, table: string, name: string, transform: (def: string) => string): Promise<void> {
  const before = await readConstraint(knex, table, name);
  const after = transform(before);
  if (after === before) return;
  if (after.includes('?')) throw new Error(`090: refusing to execute a constraint containing '?': ${after}`);
  await knex.schema.raw(`ALTER TABLE ${table} DROP CONSTRAINT ${name}`);
  await knex.schema.raw(`ALTER TABLE ${table} ADD CONSTRAINT ${name} ${after}`);
}

export async function up(knex: Knex): Promise<void> {
  // ── 1. The kind, in the three change_jobs CHECKs ─────────────────────────
  for (const name of CHANGE_JOB_CHECKS) await rewrite(knex, 'change_jobs', name, widenJobKindList);

  // ── 2. Rollouts admit it ─────────────────────────────────────────────────
  await rewrite(knex, 'rollouts', 'rollouts_kind_chk', widenRolloutKindList);
  await rewrite(knex, 'rollouts', 'rollouts_kind_shape_chk', widenShape);
  await knex.schema.alterTable('rollouts', (t) => {
    t.string('wan_target_mode', 8).nullable();
  });
  await knex.schema.raw(
    'ALTER TABLE rollouts ADD CONSTRAINT rollouts_wan_target_mode_chk CHECK (' +
      `((kind = '${KIND}') = (wan_target_mode IS NOT NULL)) AND (wan_target_mode IS NULL OR wan_target_mode IN (${MODES})))`,
  );

  // ── 3. wan_link_jobs ─────────────────────────────────────────────────────
  await knex.schema.createTable('wan_link_jobs', (t) => {
    t.bigInteger('job_id').primary().references('id').inTable('change_jobs').onDelete('CASCADE');
    t.integer('tenant_id').notNullable();
    t.integer('device_id').notNullable().references('id').inTable('devices').onDelete('CASCADE');
    t.integer('site_id').nullable().references('id').inTable('sites').onDelete('SET NULL');
    // Frozen at enqueue: the modes and the target. The PPPoE password is in
    // the vault format (`secretVault`), never in clear, and wiped once the job
    // concludes (`password_wiped_chk`).
    t.string('from_mode', 8).notNullable();
    t.string('to_mode', 8).notNullable();
    t.string('pppoe_name', 8).nullable();
    t.string('pppoe_username', 64).nullable();
    t.text('pppoe_password_enc').nullable();
    t.integer('pppoe_key_version').nullable();
    t.string('pppoe_password_source', 8).nullable();
    t.string('static_address', 18).nullable();
    t.string('static_gateway', 15).nullable();
    // The FROM parameters the site declared (the router must match them).
    t.jsonb('expect').nullable();
    // Where it dials (an address, never an identity: every session proves the
    // box), the script's delay and the job's own bound.
    t.string('ssh_host', 255).notNullable();
    t.integer('revert_after_s').notNullable();
    t.integer('wait_s').notNullable();
    // The pre-change backup, restated (header, 1).
    t.bigInteger('backup_id').nullable().references('id').inTable('device_backups');
    t.jsonb('before').nullable();
    t.jsonb('sent').nullable();
    t.jsonb('observed').nullable();
    t.string('script_job_id', 16).nullable();
    t.timestamp('wrote_at', { useTz: true }).nullable();
    t.timestamp('script_started_at', { useTz: true }).nullable();
    t.timestamp('script_seen_alive_at', { useTz: true }).nullable();
    t.string('decision', 12).nullable();
    t.timestamp('decided_at', { useTz: true }).nullable();
    t.timestamp('tunnel_returned_at', { useTz: true }).nullable();
    t.timestamp('cut_expected_from', { useTz: true }).nullable();
    t.timestamp('cut_expected_until', { useTz: true }).nullable();
    t.timestamp('vars_written_at', { useTz: true }).nullable();
    t.string('outcome', 16).nullable();
    t.text('outcome_detail').nullable();
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });
  const checks: Array<[string, string]> = [
    ['modes_chk', `from_mode IN (${MODES}) AND to_mode IN (${MODES})`],
    ['pppoe_name_chk', "pppoe_name IS NULL OR pppoe_name IN ('ADSL','FTTH','FTTO')"],
    ['outcome_chk', `outcome IS NULL OR outcome IN (${OUTCOMES})`],
    ['detail_chk', '(outcome IS NULL) = (outcome_detail IS NULL)'],
    ['decision_chk', "(decision IS NULL OR decision IN ('applied','reverted','abandoned')) AND ((decision IS NULL) = (decided_at IS NULL))"],
    ['pppoe_target_chk', "to_mode <> 'pppoe' OR (pppoe_name IS NOT NULL AND pppoe_username IS NOT NULL)"],
    ['static_target_chk', "to_mode <> 'static' OR (static_address IS NOT NULL AND static_gateway IS NOT NULL)"],
    ['password_mode_chk', "pppoe_password_enc IS NULL OR to_mode = 'pppoe'"],
    ['password_key_chk', '(pppoe_password_enc IS NULL) = (pppoe_key_version IS NULL)'],
    ['password_wiped_chk', 'pppoe_password_enc IS NULL OR outcome IS NULL'],
    ['password_source_chk', "pppoe_password_source IS NULL OR pppoe_password_source IN ('typed','site')"],
    ['backup_before_write_chk', 'wrote_at IS NULL OR backup_id IS NOT NULL'],
    ['started_after_write_chk', 'script_started_at IS NULL OR wrote_at IS NOT NULL'],
    ['alive_after_start_chk', 'script_seen_alive_at IS NULL OR script_started_at IS NOT NULL'],
    ['decided_after_start_chk', 'decided_at IS NULL OR script_started_at IS NOT NULL'],
    ['window_pair_chk', '(cut_expected_from IS NULL) = (cut_expected_until IS NULL)'],
    ['window_order_chk', 'cut_expected_from IS NULL OR cut_expected_from <= cut_expected_until'],
    ['window_after_backup_chk', 'cut_expected_from IS NULL OR backup_id IS NOT NULL'],
    ['applied_chk',
      "outcome IS DISTINCT FROM 'applied' OR (wrote_at IS NOT NULL AND observed IS NOT NULL AND vars_written_at IS NOT NULL)"],
    ['present_chk',
      "outcome IS DISTINCT FROM 'present' OR (wrote_at IS NULL AND before IS NOT NULL AND vars_written_at IS NOT NULL)"],
    ['reverted_chk', "outcome IS DISTINCT FROM 'reverted' OR (wrote_at IS NOT NULL AND vars_written_at IS NULL)"],
    ['refused_chk', "outcome IS DISTINCT FROM 'refused' OR (wrote_at IS NULL AND vars_written_at IS NULL)"],
    ['vars_outcome_chk', "vars_written_at IS NULL OR outcome IN ('applied','present')"],
    ['expect_chk', "expect IS NULL OR jsonb_typeof(expect) = 'object'"],
    ['before_chk', "before IS NULL OR jsonb_typeof(before) = 'object'"],
    ['sent_chk', "sent IS NULL OR jsonb_typeof(sent) = 'object'"],
    ['observed_chk', "observed IS NULL OR jsonb_typeof(observed) = 'object'"],
    ['waits_chk', 'revert_after_s BETWEEN 120 AND 1800 AND wait_s > revert_after_s AND wait_s <= 3600'],
    ['ssh_host_chk', "btrim(ssh_host) <> ''"],
    ['script_job_id_chk', 'script_job_id IS NULL OR length(script_job_id) BETWEEN 2 AND 16'],
  ];
  for (const [name, expr] of checks) {
    await knex.schema.raw(`ALTER TABLE wan_link_jobs ADD CONSTRAINT wan_link_jobs_${name} CHECK (${expr})`);
  }
  await knex.schema.raw('CREATE INDEX wan_link_jobs_device_idx ON wan_link_jobs (device_id, job_id DESC)');
  await knex.schema.raw('CREATE INDEX wan_link_jobs_tenant_idx ON wan_link_jobs (tenant_id, job_id DESC)');
  // The alert holds read the open cut window of one device (health check,
  // backup-4G): partial, only the rows that ever opened one.
  await knex.schema.raw(
    'CREATE INDEX wan_link_jobs_cut_idx ON wan_link_jobs (device_id, cut_expected_until) WHERE cut_expected_until IS NOT NULL',
  );
}

export async function down(knex: Knex): Promise<void> {
  // A job of this kind cannot be relabelled as another kind without lying
  // about what was done: the jobs go first (their steps and wan_link_jobs rows
  // cascade; their commands stay in the append-only `command_audit`), because
  // `change_jobs_rollout_fk` (010) has no ON DELETE; any other job attached to
  // such a rollout is detached; then the rollouts, with their waves and
  // targets (ON DELETE CASCADE, 010).
  await knex('change_jobs').where({ kind: KIND }).del();
  await knex('change_jobs')
    .whereIn('rollout_id', knex('rollouts').where({ kind: KIND }).select('id'))
    .update({ rollout_id: null, wave_index: null, canary_rank: null });
  await knex('rollouts').where({ kind: KIND }).del();

  await knex.schema.dropTableIfExists('wan_link_jobs');

  await knex.schema.raw('ALTER TABLE rollouts DROP CONSTRAINT IF EXISTS rollouts_wan_target_mode_chk');
  await knex.schema.alterTable('rollouts', (t) => {
    t.dropColumn('wan_target_mode');
  });
  await rewrite(knex, 'rollouts', 'rollouts_kind_shape_chk', narrowShape);
  await rewrite(knex, 'rollouts', 'rollouts_kind_chk', narrowKindList);
  for (const name of [...CHANGE_JOB_CHECKS].reverse()) {
    await rewrite(knex, 'change_jobs', name, narrowKindList);
  }
}
