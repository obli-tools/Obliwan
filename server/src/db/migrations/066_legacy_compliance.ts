import type { Knex } from 'knex';

/**
 * 066_legacy_compliance.ts — the change job that brings a MikroTik already in
 * service up to the corrected customer templates (kind `legacy_compliance`,
 * shared/src/legacyCompliance.ts, services/change/legacyCompliance.service.ts):
 * mac-server and mac-winbox on every interface, RoMON on, the store LAN added
 * to the ssh and winbox address lists, random-source-port on the l2tp-clients.
 * It goes through the queue like every other write and travels over SSH
 * with the device's existing credential.
 *
 *  1. `change_jobs.kind` gains `legacy_compliance` (17 characters; varchar(24)
 *     since 040).
 *
 *  2. 009's write-kind CHECKs, as 065 left them, one by one:
 *       - `change_jobs_kind_chk`             WIDENED.
 *       - `change_jobs_guard_required_chk`   WIDENED. The job carries its own
 *         verdict, written at enqueue (ACCEPT: six allow-listed statements,
 *         none of which removes an address, a service or an account).
 *       - `change_jobs_degraded_confirm_chk` WIDENED. No on-box dead-man is
 *         armed (only the l2tp line is guarded, by a self-revert started with
 *         `:execute`), so the job is queued at `degraded` with the operator's
 *         explicit confirmation.
 *       - `change_jobs_preflight_backup_chk` NOT widened: a router already
 *         conforming writes nothing and takes no backup. Restated where it is
 *         exact: `legacy_compliance_jobs_backup_before_write_chk`.
 *     Read back and widened like 058/065: the kind APPENDED to the single kind
 *     list (053 prepends its own, and 053's narrow-then-widen must stay the
 *     identity on the live list); a definition with no list or several makes
 *     the migration throw. `down()` removes exactly this kind.
 *
 *  3. `rollouts` admit the kind (a whole customer by canary waves behind the
 *     health gate, like management_access):
 *       - `rollouts_kind_chk` gains it at the START of its list;
 *       - `rollouts_kind_shape_chk` gains one disjunct at the START, the
 *         others re-written flat behind it: a legacy_compliance rollout names
 *         NO template revision and NO target version.
 *     At the start, not the end, for one reason: 058's own down-then-up
 *     appends ITS kind and ITS disjunct at the end again, and with this
 *     kind's in front that round trip still gives back, byte for byte, the
 *     constraints it found (managementAccess.verify.ts asserts it). PostgreSQL
 *     flattens a LEFT-nested OR only, so the disjuncts are written as one flat
 *     `a OR b OR c` and never as `a OR (b OR c)`, which would make 058's
 *     narrowing see a single disjunct holding every kind. `rollouts.kind` is
 *     varchar(24) since 058.
 *
 *  4. `legacy_compliance_jobs` — one row per job: what was frozen at enqueue
 *     (the fixes, the SSH address it dials, the self-revert's delay and the
 *     tunnel's return bound — never a credential), the backup it took, what it
 *     read before (`before`: the reading and the plan), what it sent (`sent`),
 *     when it wrote, armed the self-revert, sent the l2tp line and saw the
 *     tunnel back, what it read back on a fresh session (`observed`), the
 *     per-fix outcome (`fix_outcomes`) and the job's outcome.
 *
 * No `?` anywhere in the SQL below (knex binding trap, migration 032); the
 * constraint text read back is checked for one before it is executed.
 */

const KIND = 'legacy_compliance';
const CHANGE_JOB_CHECKS = [
  'change_jobs_kind_chk',
  'change_jobs_guard_required_chk',
  'change_jobs_degraded_confirm_chk',
] as const;
/** `LEGACY_COMPLIANCE_OUTCOMES` in legacyCompliance.service.ts. */
const OUTCOMES = "'applied','present','refused','failed'";
/** The disjunct `rollouts_kind_shape_chk` gains (header, 3). */
const SHAPE_DISJUNCT = `(kind = '${KIND}' AND template_revision_id IS NULL AND target_version IS NULL)`;

const KIND_LIST_RE = /\(kind\)::text (= ANY|<> ALL) \(\(?ARRAY\[/g;
const FIRST_ELEMENT_RE = /ARRAY\[(\('[a-z_]+'::[a-z ]+\)::[a-z ]+|'[a-z_]+'::[a-z ]+)[,\]]/;

async function readConstraint(knex: Knex, table: string, name: string): Promise<string> {
  const row = (await knex('pg_constraint as c')
    .join('pg_class as t', 't.oid', 'c.conrelid')
    .where('t.relname', table)
    .where('c.conname', name)
    .first(knex.raw('pg_get_constraintdef(c.oid) AS def'))) as { def: string } | undefined;
  if (!row) throw new Error(`066: ${table} has no constraint ${name}`);
  return row.def;
}

/** This kind, spelled like the list's first element. */
function element(def: string): string {
  const first = FIRST_ELEMENT_RE.exec(def);
  if (!first) throw new Error(`066: cannot tell how the kind list is spelled in: ${def}`);
  return first[1].replace(/'[a-z_]+'/, `'${KIND}'`);
}

function onlyList(def: string): RegExpMatchArray {
  const starts = [...def.matchAll(KIND_LIST_RE)];
  if (starts.length !== 1) throw new Error(`066: expected exactly one kind list, found ${starts.length}, in: ${def}`);
  return starts[0];
}

/** change_jobs: this kind APPENDED at the end of the one list (header, 2). */
export function widenKindListAtEnd(def: string): string {
  if (def.includes(`'${KIND}'::`)) return def;
  const el = element(def);
  const start = onlyList(def);
  const from = (start.index as number) + start[0].length;
  const end = def.indexOf(']', from);
  if (end < 0) throw new Error(`066: the kind list does not close in: ${def}`);
  return `${def.slice(0, end)}, ${el}${def.slice(end)}`;
}

/** rollouts: this kind PREPENDED at the start of the one list (header, 3). */
export function widenKindListAtStart(def: string): string {
  if (def.includes(`'${KIND}'::`)) return def;
  const el = element(def);
  const start = onlyList(def);
  const at = (start.index as number) + start[0].length;
  return `${def.slice(0, at)}${el}, ${def.slice(at)}`;
}

/** Either way round: the element and the separator next to it go. */
export function narrowKindList(def: string): string {
  if (!def.includes(`'${KIND}'::`)) return def;
  const el = element(def);
  return def.split(`${el}, `).join('').split(`, ${el}`).join('');
}

function checkBody(def: string): string {
  const m = /^CHECK \((.*)\)$/s.exec(def.trim());
  if (!m) throw new Error(`066: not a CHECK definition: ${def}`);
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
 *  whole expression (058's reader, restated: a migration keeps its own). */
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

export function widenShape(def: string): string {
  if (def.includes(`'${KIND}'`)) return def;
  return `CHECK (${[SHAPE_DISJUNCT, ...topLevelDisjuncts(checkBody(def)).map(wrap)].join(' OR ')})`;
}

export function narrowShape(def: string): string {
  if (!def.includes(`'${KIND}'`)) return def;
  const kept = topLevelDisjuncts(checkBody(def)).filter((d) => !d.includes(`'${KIND}'`));
  if (kept.length === 0) throw new Error(`066: the shape CHECK would be left empty: ${def}`);
  return `CHECK (${kept.map(wrap).join(' OR ')})`;
}

async function rewrite(knex: Knex, table: string, name: string, transform: (def: string) => string): Promise<void> {
  const before = await readConstraint(knex, table, name);
  const after = transform(before);
  if (after === before) return;
  if (after.includes('?')) throw new Error(`066: refusing to execute a constraint containing '?': ${after}`);
  await knex.schema.raw(`ALTER TABLE ${table} DROP CONSTRAINT ${name}`);
  await knex.schema.raw(`ALTER TABLE ${table} ADD CONSTRAINT ${name} ${after}`);
}

export async function up(knex: Knex): Promise<void> {
  // ── 1 + 2. The kind, in the three change_jobs CHECKs ─────────────────────
  for (const name of CHANGE_JOB_CHECKS) await rewrite(knex, 'change_jobs', name, widenKindListAtEnd);

  // ── 3. Rollouts admit it ─────────────────────────────────────────────────
  await rewrite(knex, 'rollouts', 'rollouts_kind_chk', widenKindListAtStart);
  await rewrite(knex, 'rollouts', 'rollouts_kind_shape_chk', widenShape);

  // ── 4. legacy_compliance_jobs ────────────────────────────────────────────
  await knex.schema.createTable('legacy_compliance_jobs', (t) => {
    t.bigInteger('job_id').primary().references('id').inTable('change_jobs').onDelete('CASCADE');
    t.integer('tenant_id').notNullable();
    t.integer('device_id').notNullable().references('id').inTable('devices').onDelete('CASCADE');
    // Frozen at enqueue: the fixes the job may write (all six today), where it
    // dials (an address, never an identity: every session proves the box,
    // never the remembered address), the self-revert's delay and the tunnel's return bound.
    t.jsonb('fixes').notNullable();
    t.string('ssh_host', 255).notNullable();
    t.integer('revert_after_s').notNullable();
    t.integer('tunnel_wait_s').notNullable();
    // The pre-change backup, restated (header, 2).
    t.bigInteger('backup_id').nullable().references('id').inTable('device_backups');
    // NULL until the job has looked or acted: no DEFAULT anywhere below.
    t.jsonb('before').nullable();
    t.jsonb('sent').nullable();
    t.jsonb('observed').nullable();
    t.jsonb('fix_outcomes').nullable();
    t.timestamp('wrote_at', { useTz: true }).nullable();
    t.timestamp('self_revert_armed_at', { useTz: true }).nullable();
    t.timestamp('random_source_port_sent_at', { useTz: true }).nullable();
    t.timestamp('tunnel_returned_at', { useTz: true }).nullable();
    t.string('outcome', 16).nullable();
    t.text('outcome_detail').nullable();
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });
  const jobChecks: Array<[string, string]> = [
    ['outcome_chk', `outcome IS NULL OR outcome IN (${OUTCOMES})`],
    ['detail_chk', '(outcome IS NULL) = (outcome_detail IS NULL)'],
    ['backup_before_write_chk', 'wrote_at IS NULL OR backup_id IS NOT NULL'],
    // Every later instant is part of the write, and comes after its start.
    ['revert_after_write_chk', 'self_revert_armed_at IS NULL OR wrote_at IS NOT NULL'],
    ['l2tp_after_write_chk', 'random_source_port_sent_at IS NULL OR wrote_at IS NOT NULL'],
    ['tunnel_after_l2tp_chk', 'tunnel_returned_at IS NULL OR random_source_port_sent_at IS NOT NULL'],
    ['applied_wrote_chk',
      "outcome IS DISTINCT FROM 'applied' OR (wrote_at IS NOT NULL AND observed IS NOT NULL AND fix_outcomes IS NOT NULL)"],
    ['present_unwritten_chk',
      "outcome IS DISTINCT FROM 'present' OR (wrote_at IS NULL AND before IS NOT NULL AND fix_outcomes IS NOT NULL)"],
    ['refused_unwritten_chk', "outcome IS DISTINCT FROM 'refused' OR wrote_at IS NULL"],
    ['fixes_chk', "jsonb_typeof(fixes) = 'array' AND jsonb_array_length(fixes) >= 1"],
    ['before_chk', "before IS NULL OR jsonb_typeof(before) = 'object'"],
    ['sent_chk', "sent IS NULL OR jsonb_typeof(sent) = 'object'"],
    ['observed_chk', "observed IS NULL OR jsonb_typeof(observed) = 'object'"],
    ['fix_outcomes_chk', "fix_outcomes IS NULL OR jsonb_typeof(fix_outcomes) = 'object'"],
    // The job must outwait the self-revert to read its decision back.
    ['waits_chk', 'revert_after_s BETWEEN 30 AND 600 AND tunnel_wait_s BETWEEN 60 AND 900 AND revert_after_s < tunnel_wait_s'],
    ['ssh_host_chk', "btrim(ssh_host) <> ''"],
  ];
  for (const [name, expr] of jobChecks) {
    await knex.schema.raw(`ALTER TABLE legacy_compliance_jobs ADD CONSTRAINT legacy_compliance_jobs_${name} CHECK (${expr})`);
  }
  await knex.schema.raw('CREATE INDEX legacy_compliance_jobs_device_idx ON legacy_compliance_jobs (device_id, job_id DESC)');
  await knex.schema.raw('CREATE INDEX legacy_compliance_jobs_tenant_idx ON legacy_compliance_jobs (tenant_id, job_id DESC)');
}

export async function down(knex: Knex): Promise<void> {
  // A job of this kind cannot be relabelled as another kind without lying
  // about what was done: the jobs go first (their steps and
  // legacy_compliance_jobs rows cascade; their commands stay in the
  // append-only `command_audit`), because `change_jobs_rollout_fk` (010) has
  // no ON DELETE; any other job attached to such a rollout is detached; then
  // the rollouts, with their waves and targets (ON DELETE CASCADE, 010).
  await knex('change_jobs').where({ kind: KIND }).del();
  await knex('change_jobs')
    .whereIn('rollout_id', knex('rollouts').where({ kind: KIND }).select('id'))
    .update({ rollout_id: null, wave_index: null, canary_rank: null });
  await knex('rollouts').where({ kind: KIND }).del();

  await knex.schema.dropTableIfExists('legacy_compliance_jobs');

  await rewrite(knex, 'rollouts', 'rollouts_kind_shape_chk', narrowShape);
  await rewrite(knex, 'rollouts', 'rollouts_kind_chk', narrowKindList);
  for (const name of [...CHANGE_JOB_CHECKS].reverse()) {
    await rewrite(knex, 'change_jobs', name, narrowKindList);
  }
}
