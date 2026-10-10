import type { Knex } from 'knex';

/**
 * 058_management_access.ts — the change job that opens ObliWAN's management
 * API on a MikroTik already in service: api-ssl on 8729, restricted to the
 * management range, serving a certificate made ON the router (the lines of
 * shared/src/managementAccess.ts, the same the bench compile writes). It goes
 * through the queue like every other write; the service is
 * services/change/managementAccess.service.ts and the job's phases are a branch
 * of `runPhases()` in apply.service.ts. It travels over SSH, the channel such a
 * router answers on today.
 *
 *  1. `change_jobs.kind` gains `management_access` (17 characters: the column
 *     is varchar(24) since 040, no widening needed).
 *
 *  2. 009's write-kind CHECKs (as 040, 047 and 053 left them), one by one:
 *       - `change_jobs_guard_required_chk`   WIDENED. The job always carries a
 *         verdict, its own, written at enqueue (ACCEPT: it sends nothing but
 *         `/certificate` and the api-ssl service, refuses any other line, and
 *         never writes the SSH service it travels on).
 *       - `change_jobs_degraded_confirm_chk` WIDENED. The job arms no dead-man,
 *         so it is queued at `degraded`, which is the truth about its net, and
 *         the request that queues it (one device, or a rollout composed with
 *         the confirmation) carries the operator's explicit confirmation.
 *       - `change_jobs_preflight_backup_chk` NOT widened. A re-run that finds
 *         api-ssl already as the job would leave it writes nothing and takes
 *         no backup (the state machine has no edge that skips the statuses
 *         this CHECK guards). The rule is restated where it is exact:
 *         `management_access_jobs_backup_before_write_chk` — no write recorded
 *         without a backup id beside it.
 *     `apply_outcomes.op_kind` is NOT widened: that corpus records changes made
 *     under a net, and this job writes no row to it (a skipped
 *     `record_outcome` step says so).
 *
 *     Widened like 053 does, by READING EACH CONSTRAINT BACK
 *     (`pg_get_constraintdef`) and adding this one kind to its single kind
 *     list — at the END of it, where 053 puts its own at the start, so each
 *     migration's own narrow-then-widen gives back the list it found — and a
 *     kind another migration added is never dropped by a literal list written
 *     here. A definition with no kind list, or more than one, makes the
 *     migration THROW rather than guess. `down()` removes exactly this kind
 *     and nothing else.
 *
 *  3. `rollouts` admits the kind (a whole customer is done by canary waves
 *     behind a health gate, services/change/rollout.service.ts):
 *       - `rollouts.kind` widens from varchar(16) to varchar(24) — the new
 *         kind is 17 characters;
 *       - `rollouts_kind_chk` gains it, read back and widened like (2);
 *       - `rollouts_kind_shape_chk` gains one disjunct, appended to the
 *         constraint read back: a management_access rollout names NO template
 *         revision and NO target version (the job takes its parameters from
 *         the management range variable, frozen per job at enqueue). `down()`
 *         removes the disjunct that names this kind and keeps every other.
 *
 *  4. The subtree interlock (010, 040, 055) is NOT touched: this job is a
 *     child job like any other on a device behind a concentrator.
 *
 *  5. `management_access_jobs` — one row per job: what was frozen at enqueue
 *     (the management prefixes, the API port, the SSH address the job dials —
 *     never a credential), the backup it took, when it first wrote, what it
 *     read on the router (no secret: certificate NAMES, flags and fingerprints,
 *     the api-ssl service row), what it did to the device's RouterOS API
 *     transport, the fingerprint it pinned, and its outcome.
 *
 * No `?` anywhere in the SQL below: knex rewrites it inside raw() as a binding
 * placeholder (see migration 032). The constraint text read back is
 * checked for one before it is executed.
 */

const KIND = 'management_access';
/** The change_jobs CHECKs this kind joins (header, 2). */
const CHANGE_JOB_CHECKS = [
  'change_jobs_kind_chk',
  'change_jobs_guard_required_chk',
  'change_jobs_degraded_confirm_chk',
] as const;
/** `MANAGEMENT_ACCESS_OUTCOMES` in managementAccess.service.ts. */
const OUTCOMES = "'enabled','present','refused','failed'";
/** `MANAGEMENT_ACCESS_TRANSPORT_ACTIONS` in managementAccess.service.ts. */
const TRANSPORT_ACTIONS = "'created','updated','unchanged'";
/** The disjunct `rollouts_kind_shape_chk` gains (header, 3). */
const SHAPE_DISJUNCT =
  `(kind = '${KIND}' AND template_revision_id IS NULL AND target_version IS NULL)`;

/** The one kind list of a CHECK, as PostgreSQL prints it back (see 053). */
const KIND_LIST_RE = /\(kind\)::text (= ANY|<> ALL) \(\(?ARRAY\[/g;
const FIRST_ELEMENT_RE = /ARRAY\[(\('[a-z_]+'::[a-z ]+\)::[a-z ]+|'[a-z_]+'::[a-z ]+)[,\]]/;

async function readConstraint(knex: Knex, table: string, name: string): Promise<string> {
  const row = (await knex('pg_constraint as c')
    .join('pg_class as t', 't.oid', 'c.conrelid')
    .where('t.relname', table)
    .where('c.conname', name)
    .first(knex.raw('pg_get_constraintdef(c.oid) AS def'))) as { def: string } | undefined;
  if (!row) throw new Error(`058: ${table} has no constraint ${name}`);
  return row.def;
}

/** This kind, spelled like the list's first element. */
function element(def: string): string {
  const first = FIRST_ELEMENT_RE.exec(def);
  if (!first) throw new Error(`058: cannot tell how the kind list is spelled in: ${def}`);
  return first[1].replace(/'[a-z_]+'/, `'${KIND}'`);
}

/**
 * This kind APPENDED to the list's end (053 inserts its own at the start):
 * a migration that narrows and re-widens its own kind — 053's down/up, and
 * link.verify.ts, which asserts that round trip byte for byte — then finds
 * the list exactly as it left it. An element never holds a `]`, so the list
 * ends at the first `]` after `ARRAY[`.
 */
export function widenKindList(def: string): string {
  if (def.includes(`'${KIND}'::`)) return def;
  const el = element(def);
  const starts = [...def.matchAll(KIND_LIST_RE)];
  if (starts.length !== 1) throw new Error(`058: expected exactly one kind list, found ${starts.length}, in: ${def}`);
  const from = (starts[0].index as number) + starts[0][0].length;
  const end = def.indexOf(']', from);
  if (end < 0) throw new Error(`058: the kind list does not close in: ${def}`);
  return `${def.slice(0, end)}, ${el}${def.slice(end)}`;
}

export function narrowKindList(def: string): string {
  if (!def.includes(`'${KIND}'::`)) return def;
  const el = element(def);
  return def.split(`${el}, `).join('').split(`, ${el}`).join('');
}

/** `CHECK (<expr>)` -> `<expr>`; throws on anything else. */
function checkBody(def: string): string {
  const m = /^CHECK \((.*)\)$/s.exec(def.trim());
  if (!m) throw new Error(`058: not a CHECK definition: ${def}`);
  return m[1];
}

/** True when the parenthesis opening at 0 closes at the very end. */
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

/** The top-level ` OR ` operands of an expression (outside parentheses and
 *  quotes), after stripping parentheses that wrap the whole of it. */
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

export function widenShape(def: string): string {
  if (def.includes(`'${KIND}'`)) return def;
  return `CHECK ((${checkBody(def)}) OR ${SHAPE_DISJUNCT})`;
}

export function narrowShape(def: string): string {
  if (!def.includes(`'${KIND}'`)) return def;
  const kept = topLevelDisjuncts(checkBody(def)).filter((d) => !d.includes(`'${KIND}'`));
  if (kept.length === 0) throw new Error(`058: the shape CHECK would be left empty: ${def}`);
  return `CHECK (${kept.map((d) => (wrappedWhole(d) ? d : `(${d})`)).join(' OR ')})`;
}

async function rewrite(
  knex: Knex,
  table: string,
  name: string,
  transform: (def: string) => string,
): Promise<void> {
  const before = await readConstraint(knex, table, name);
  const after = transform(before);
  if (after === before) return;
  // The trap this migration's header names: never hand knex a `?`.
  if (after.includes('?')) throw new Error(`058: refusing to execute a constraint containing '?': ${after}`);
  await knex.schema.raw(`ALTER TABLE ${table} DROP CONSTRAINT ${name}`);
  await knex.schema.raw(`ALTER TABLE ${table} ADD CONSTRAINT ${name} ${after}`);
}

export async function up(knex: Knex): Promise<void> {
  // ── 1 + 2. The kind, in the three change_jobs CHECKs ─────────────────────
  for (const name of CHANGE_JOB_CHECKS) await rewrite(knex, 'change_jobs', name, widenKindList);

  // ── 3. Rollouts admit it ─────────────────────────────────────────────────
  await knex.schema.raw('ALTER TABLE rollouts ALTER COLUMN kind TYPE varchar(24)');
  await rewrite(knex, 'rollouts', 'rollouts_kind_chk', widenKindList);
  await rewrite(knex, 'rollouts', 'rollouts_kind_shape_chk', widenShape);

  // ── 5. management_access_jobs ────────────────────────────────────────────
  await knex.schema.createTable('management_access_jobs', (t) => {
    t.bigInteger('job_id').primary().references('id').inTable('change_jobs').onDelete('CASCADE');
    t.integer('tenant_id').notNullable();
    t.integer('device_id').notNullable().references('id').inTable('devices').onDelete('CASCADE');
    // Frozen at enqueue; the worker refuses when the instance variable says
    // otherwise by then (the range was changed after the job was queued).
    t.jsonb('mgmt_prefixes').notNullable();
    t.integer('api_port').notNullable();
    // Where the job dials (the device's SSH transport host at enqueue). An
    // address, never an identity: the job proves the box on every session.
    t.string('ssh_host', 255).notNullable();
    // The pre-change backup, restated (header, 2).
    t.bigInteger('backup_id').nullable().references('id').inTable('device_backups');
    t.timestamp('wrote_at', { useTz: true }).nullable();
    // What the job found. NULL until it has looked: no DEFAULT.
    t.string('outcome', 16).nullable();
    t.text('outcome_detail').nullable();
    // What was read on the router: certificate names, flags and fingerprints,
    // the api-ssl service row. Never a key, never a password.
    t.jsonb('observed').nullable();
    // The device's RouterOS API transport, as the job left it.
    t.string('transport_action', 16).nullable();
    // The certificate fingerprint seen on the first TLS handshake (SHA-256 of
    // the DER, lowercase hex, transport/routeros/connection.ts), pinned on the
    // transport — and the one the router printed over SSH, kept as it was
    // printed: whether RouterOS prints the same digest is not observed.
    t.string('pinned_fingerprint', 64).nullable();
    t.string('certificate_fingerprint', 128).nullable();
    t.timestamp('api_checked_at', { useTz: true }).nullable();
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });
  const jobChecks: Array<[string, string]> = [
    ['outcome_chk', `outcome IS NULL OR outcome IN (${OUTCOMES})`],
    ['detail_chk', '(outcome IS NULL) = (outcome_detail IS NULL)'],
    ['backup_before_write_chk', 'wrote_at IS NULL OR backup_id IS NOT NULL'],
    ['enabled_wrote_chk', "outcome IS DISTINCT FROM 'enabled' OR wrote_at IS NOT NULL"],
    ['present_unwritten_chk', "outcome IS DISTINCT FROM 'present' OR wrote_at IS NULL"],
    ['refused_unwritten_chk', "outcome IS DISTINCT FROM 'refused' OR wrote_at IS NULL"],
    // "Succeeded" is said by a job that reached the API and pinned it.
    ['success_pinned_chk',
      "outcome IS NULL OR outcome NOT IN ('enabled','present') OR " +
      '(pinned_fingerprint IS NOT NULL AND transport_action IS NOT NULL AND api_checked_at IS NOT NULL)'],
    ['transport_action_chk', `transport_action IS NULL OR transport_action IN (${TRANSPORT_ACTIONS})`],
    ['pinned_chk', "pinned_fingerprint IS NULL OR pinned_fingerprint ~ '^[0-9a-f]{64}$'"],
    ['prefixes_chk', "jsonb_typeof(mgmt_prefixes) = 'array' AND jsonb_array_length(mgmt_prefixes) >= 1"],
    ['observed_chk', "observed IS NULL OR jsonb_typeof(observed) = 'object'"],
    ['api_port_chk', 'api_port BETWEEN 1 AND 65535'],
    ['ssh_host_chk', "btrim(ssh_host) <> ''"],
  ];
  for (const [name, expr] of jobChecks) {
    await knex.schema.raw(
      `ALTER TABLE management_access_jobs ADD CONSTRAINT management_access_jobs_${name} CHECK (${expr})`,
    );
  }
  await knex.schema.raw(
    'CREATE INDEX management_access_jobs_device_idx ON management_access_jobs (device_id, job_id DESC)',
  );
  await knex.schema.raw(
    'CREATE INDEX management_access_jobs_tenant_idx ON management_access_jobs (tenant_id, job_id DESC)',
  );
}

export async function down(knex: Knex): Promise<void> {
  // A row of this kind cannot be relabelled as another kind without lying
  // about what was done, so the rows go — the JOBS first (their steps and
  // their management_access_jobs rows cascade; their commands stay in
  // `command_audit`, which has no foreign key and is append-only), because
  // `change_jobs_rollout_fk` (010) has no ON DELETE: a management_access
  // rollout cannot go while its jobs point at it. Any other job attached to
  // such a rollout (none is ever queued by one) is detached rather than
  // deleted. Then the rollouts, with their waves and targets (ON DELETE
  // CASCADE, 010).
  await knex('change_jobs').where({ kind: KIND }).del();
  await knex('change_jobs')
    .whereIn('rollout_id', knex('rollouts').where({ kind: KIND }).select('id'))
    .update({ rollout_id: null, wave_index: null, canary_rank: null });
  await knex('rollouts').where({ kind: KIND }).del();

  await knex.schema.dropTableIfExists('management_access_jobs');

  await rewrite(knex, 'rollouts', 'rollouts_kind_shape_chk', narrowShape);
  await rewrite(knex, 'rollouts', 'rollouts_kind_chk', narrowKindList);
  await knex.schema.raw('ALTER TABLE rollouts ALTER COLUMN kind TYPE varchar(16)');

  for (const name of [...CHANGE_JOB_CHECKS].reverse()) {
    await rewrite(knex, 'change_jobs', name, narrowKindList);
  }
}
