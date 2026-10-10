import type { Knex } from 'knex';

/**
 * 047_os_upgrade_jobs.ts — the change job that brings ONE RouterOS 7 device to
 * a pinned release, through the queue like every other write. The service
 * is services/firmware/osUpgrade.service.ts; the job's phases are a branch of
 * `runPhases()` in apply.service.ts.
 *
 *  1. `change_jobs.kind` gains `os_upgrade` (10 characters: the column is
 *     varchar(24) since 040, no widening needed).
 *
 *  2. 009's write-kind CHECKs (as 040 left them), one by one:
 *       - `change_jobs_guard_required_chk`   WIDENED. The job always carries a
 *         verdict — INDETERMINATE, because the Management-Path Guard models a
 *         forwarding change and has nothing to say about a reboot into new
 *         code — so every os_upgrade job carries a signed override too
 *         (`change_jobs_override_chk`, unchanged).
 *       - `change_jobs_degraded_confirm_chk` WIDENED. The job arms no dead-man
 *         (a scheduler script cannot un-install a RouterOS release), so it is
 *         queued at `degraded`, which is the truth about its net, and the safety-net rule's
 *         explicit confirmation applies: unlike `concentrator_secret`, an
 *         upgrade CAN leave a site unreachable — a box that does not boot back
 *         is a visit.
 *       - `change_jobs_preflight_backup_chk` NOT widened. A device already at
 *         or above the target ends the job as a no-op `succeeded` that wrote
 *         nothing and therefore backed nothing up, and the state machine has
 *         no edge from `claimed` to `succeeded` that skips the statuses this
 *         CHECK guards. The rule is restated where it can be exact:
 *         `os_upgrade_jobs_backup_before_fetch_chk` below — no package fetch
 *         is recorded without a backup id beside it.
 *     `apply_outcomes.op_kind` is NOT widened: that corpus records changes
 *     made under a net, and its outcomes (`rolled_back`, `lost_contact`) do
 *     not describe "the router refused the package". The job records a
 *     skipped `record_outcome` step saying so; its outcome is on
 *     `os_upgrade_jobs`.
 *
 *  3. The subtree interlock (010, replaced by 040) is NOT touched. The
 *     service refuses a concentrator outright, so an os_upgrade job is never a
 *     concentrator job. On a device behind a concentrator it is a child job
 *     like any other, and the interlock does not make it wait: its INSERT is
 *     REFUSED (restrict_violation, 23001) while a job the interlock counts is
 *     in flight on that concentrator — `enqueueOsUpgradeJob` names that
 *     refusal `subtree_interlock` — and while it is in flight, a concentrator
 *     job the interlock counts is refused the same way, which is right: its
 *     reboot drops the very tunnel a concentrator change would be judged
 *     through.
 *
 *  4. `os_upgrade_jobs` — one row per job: the target frozen at enqueue, what
 *     the job observed (version, architecture, free space, the package list it
 *     fetched), the instants of its three irreversible gestures (first fetch,
 *     reboot, return) and its outcome. No credential column anywhere: the
 *     worker reads the vault at dial time, through `openDeviceSession()`.
 *
 *  5. `rollouts` carries a KIND. A rollout used to be "push revision R"; it is
 *     now that, or "upgrade to RouterOS version V". `template_revision_id`
 *     becomes nullable, and `rollouts_kind_shape_chk` makes the pair exact:
 *     a push names a revision and no version, an os_upgrade names a version
 *     and no revision. Existing rows are all pushes (DEFAULT 'push').
 *
 * No `?` anywhere in the SQL below: knex rewrites it inside raw() as a binding
 * placeholder (see migration 032). Optional groups are written `{0,1}`.
 */

// Inlined literals, as 009, 010, 029 and 040 do: a migration keeps describing
// the schema as it was on the day it ran.
const JOB_KINDS_040 = "'push','export','backup','restore','reboot','firmware','concentrator_secret'";
const JOB_KINDS_047 =
  "'push','export','backup','restore','reboot','firmware','concentrator_secret','os_upgrade'";
const WRITE_KINDS_009 = "'push','restore','reboot','firmware'";
const WRITE_KINDS_040 = "'push','restore','reboot','firmware','concentrator_secret'";
const WRITE_KINDS_047 = "'push','restore','reboot','firmware','concentrator_secret','os_upgrade'";

/** `OS_UPGRADE_OUTCOMES` in osUpgrade.service.ts. */
const OUTCOMES =
  "'already_current','upgraded','refused','fetch_failed','not_rebooted','rejected'," +
  "'incomplete','lost','identity_changed','failed'";
/** `ROUTEROS_PACKAGE_ARCHITECTURES` in shared/src/firmware.ts. */
const ARCHITECTURES = "'arm','arm64','mipsbe','mmips','smips','tile','ppc','x86'";
/** A RELEASE version, as 046 writes it (shared `isRouterOsReleaseVersion`). */
const RELEASE_RE = '^[0-9]{1,4}\\.[0-9]{1,4}(\\.[0-9]{1,4}){0,1}$';
/** Any RouterOS version a box can REPORT, pre-releases included. */
const ANY_VERSION_RE = '^[0-9]{1,4}\\.[0-9]{1,4}(\\.[0-9]{1,4}){0,1}((alpha|beta|rc)[0-9]{1,4}){0,1}$';
const ROLLOUT_KINDS = "'push','os_upgrade'";

export async function up(knex: Knex): Promise<void> {
  // ── 1. The kind ───────────────────────────────────────────────────────────
  await knex.schema.raw('ALTER TABLE change_jobs DROP CONSTRAINT change_jobs_kind_chk');
  await knex.schema.raw(
    `ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_kind_chk CHECK (kind IN (${JOB_KINDS_047}))`,
  );

  // ── 2. Guard required, degraded confirmation required (header, 2) ────────
  await knex.schema.raw('ALTER TABLE change_jobs DROP CONSTRAINT change_jobs_guard_required_chk');
  await knex.schema.raw(
    `ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_guard_required_chk
       CHECK (kind NOT IN (${WRITE_KINDS_047}) OR guard_verdict IS NOT NULL)`,
  );
  // 009 listed its four write kinds here and 040 deliberately left
  // `concentrator_secret` out; this adds `os_upgrade` and keeps that exclusion.
  await knex.schema.raw('ALTER TABLE change_jobs DROP CONSTRAINT change_jobs_degraded_confirm_chk');
  await knex.schema.raw(
    'ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_degraded_confirm_chk CHECK (' +
      `NOT (safety_level = 'degraded' AND kind IN (${WRITE_KINDS_009},'os_upgrade')) OR ` +
      '(degraded_confirmed_by IS NOT NULL AND degraded_confirmed_at IS NOT NULL))',
  );

  // ── 4. os_upgrade_jobs ───────────────────────────────────────────────────
  await knex.schema.createTable('os_upgrade_jobs', (t) => {
    // One row per job, dying with it. change_jobs.id is a bigint.
    t.bigInteger('job_id').primary().references('id').inTable('change_jobs').onDelete('CASCADE');
    t.integer('tenant_id').notNullable().references('id').inTable('tenants').onDelete('CASCADE');
    // Frozen at enqueue. A release, never a pre-release (packageUrl refuses
    // anything else, and so does the CHECK below).
    t.string('target_version', 16).notNullable();
    // Everything below is an OBSERVATION and is NULL until it was made: no
    // DEFAULT anywhere, because a default would state something nobody saw.
    t.string('from_version', 16).nullable();
    t.string('architecture', 16).nullable();
    // [{ name, url, expectedBytes }] — the exact files the router was told to
    // fetch. URLs are public MikroTik download links, never a credential.
    t.jsonb('packages').nullable();
    t.bigInteger('free_bytes').nullable();
    t.bigInteger('preflight_backup_id').nullable();
    // The three irreversible gestures, in order.
    t.timestamp('fetched_at', { useTz: true }).nullable();
    t.timestamp('rebooted_at', { useTz: true }).nullable();
    t.timestamp('returned_at', { useTz: true }).nullable();
    t.string('observed_version', 16).nullable();
    t.string('outcome', 24).nullable();
    t.text('outcome_detail').nullable();
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });
  const checks: Array<[string, string]> = [
    ['outcome_chk', `outcome IS NULL OR outcome IN (${OUTCOMES})`],
    // An outcome without its explanation is a badge nobody can act on.
    ['detail_chk', '(outcome IS NULL) = (outcome_detail IS NULL)'],
    ['target_version_chk', `target_version ~ '${RELEASE_RE}'`],
    ['from_version_chk', `from_version IS NULL OR from_version ~ '${ANY_VERSION_RE}'`],
    ['observed_version_chk', `observed_version IS NULL OR observed_version ~ '${ANY_VERSION_RE}'`],
    ['architecture_chk', `architecture IS NULL OR architecture IN (${ARCHITECTURES})`],
    ['packages_chk', "packages IS NULL OR jsonb_typeof(packages) = 'array'"],
    ['free_bytes_chk', 'free_bytes IS NULL OR free_bytes >= 0'],
    // The pre-change backup rule, restated exactly (header, 2): the first byte written to the router
    // is the first fetch, and it cannot be recorded without a backup.
    ['backup_before_fetch_chk', 'fetched_at IS NULL OR preflight_backup_id IS NOT NULL'],
    ['reboot_after_fetch_chk', 'rebooted_at IS NULL OR fetched_at IS NOT NULL'],
    ['return_after_reboot_chk', 'returned_at IS NULL OR rebooted_at IS NOT NULL'],
    // An upgrade is claimed only for a version read after the box came back.
    [
      'upgraded_chk',
      "outcome IS DISTINCT FROM 'upgraded' OR " +
        '(returned_at IS NOT NULL AND observed_version = target_version)',
    ],
    // These two outcomes mean "nothing was written". Saying so with a fetch on
    // the row would be a lie about the router.
    ['nothing_written_chk', "outcome NOT IN ('already_current','refused') OR fetched_at IS NULL"],
  ];
  for (const [name, expr] of checks) {
    await knex.schema.raw(`ALTER TABLE os_upgrade_jobs ADD CONSTRAINT os_upgrade_jobs_${name} CHECK (${expr})`);
  }
  await knex.schema.raw(
    'CREATE INDEX os_upgrade_jobs_tenant_idx ON os_upgrade_jobs (tenant_id, job_id DESC)',
  );

  // ── 5. Rollouts carry a kind (header, 5) ─────────────────────────────────
  await knex.schema.alterTable('rollouts', (t) => {
    t.string('kind', 16).notNullable().defaultTo('push');
    t.string('target_version', 16).nullable();
  });
  await knex.schema.raw('ALTER TABLE rollouts ALTER COLUMN template_revision_id DROP NOT NULL');
  await knex.schema.raw(
    `ALTER TABLE rollouts ADD CONSTRAINT rollouts_kind_chk CHECK (kind IN (${ROLLOUT_KINDS}))`,
  );
  await knex.schema.raw(
    'ALTER TABLE rollouts ADD CONSTRAINT rollouts_kind_shape_chk CHECK (' +
      "(kind = 'push' AND template_revision_id IS NOT NULL AND target_version IS NULL) OR " +
      "(kind = 'os_upgrade' AND template_revision_id IS NULL AND target_version IS NOT NULL))",
  );
  await knex.schema.raw(
    'ALTER TABLE rollouts ADD CONSTRAINT rollouts_target_version_chk ' +
      `CHECK (target_version IS NULL OR target_version ~ '${RELEASE_RE}')`,
  );
}

export async function down(knex: Knex): Promise<void> {
  // A row of the new kind cannot be relabelled as another kind without lying
  // about what was done, so the rows go — the JOBS first, for the same reason
  // as 040's down() (their steps cascade, `os_upgrade_jobs` with them, and
  // their commands stay in `command_audit`, which has no foreign key and is
  // append-only), and because `change_jobs_rollout_fk` (010) has no ON DELETE:
  // an os_upgrade rollout cannot go while its jobs point at it. Any other job
  // attached to such a rollout (none is ever queued by one) is detached rather
  // than deleted. Then the rollouts, with their waves and targets (ON DELETE
  // CASCADE, 010): one cannot be relabelled as a push of some revision.
  await knex('change_jobs').where({ kind: 'os_upgrade' }).del();
  await knex('change_jobs')
    .whereIn('rollout_id', knex('rollouts').where({ kind: 'os_upgrade' }).select('id'))
    .update({ rollout_id: null, wave_index: null, canary_rank: null });
  await knex('rollouts').where({ kind: 'os_upgrade' }).del();
  await knex.schema.raw('ALTER TABLE rollouts DROP CONSTRAINT rollouts_target_version_chk');
  await knex.schema.raw('ALTER TABLE rollouts DROP CONSTRAINT rollouts_kind_shape_chk');
  await knex.schema.raw('ALTER TABLE rollouts DROP CONSTRAINT rollouts_kind_chk');
  await knex.schema.raw('ALTER TABLE rollouts ALTER COLUMN template_revision_id SET NOT NULL');
  await knex.schema.alterTable('rollouts', (t) => {
    t.dropColumn('target_version');
    t.dropColumn('kind');
  });

  await knex.schema.dropTableIfExists('os_upgrade_jobs');

  await knex.schema.raw('ALTER TABLE change_jobs DROP CONSTRAINT change_jobs_degraded_confirm_chk');
  await knex.schema.raw(
    'ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_degraded_confirm_chk CHECK (' +
      `NOT (safety_level = 'degraded' AND kind IN (${WRITE_KINDS_009})) OR ` +
      '(degraded_confirmed_by IS NOT NULL AND degraded_confirmed_at IS NOT NULL))',
  );
  await knex.schema.raw('ALTER TABLE change_jobs DROP CONSTRAINT change_jobs_guard_required_chk');
  await knex.schema.raw(
    `ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_guard_required_chk
       CHECK (kind NOT IN (${WRITE_KINDS_040}) OR guard_verdict IS NOT NULL)`,
  );
  await knex.schema.raw('ALTER TABLE change_jobs DROP CONSTRAINT change_jobs_kind_chk');
  await knex.schema.raw(
    `ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_kind_chk CHECK (kind IN (${JOB_KINDS_040}))`,
  );
}
