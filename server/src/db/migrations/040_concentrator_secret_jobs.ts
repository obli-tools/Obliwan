import type { Knex } from 'knex';

/**
 * 040_concentrator_secret_jobs.ts — the change job that creates a site's L2TP
 * account on the concentrator (the CHR), through the queue like every other
 * write. The service is services/change/concentratorSecret.service.ts; the
 * job's phases are a branch of `runPhases()` in apply.service.ts.
 *
 *  1. `change_jobs.kind` gains `concentrator_secret`. The column was
 *     varchar(12) and the new value is 19 characters, so it widens to 24
 *     (a metadata-only change in PostgreSQL: no rewrite, no lock held long).
 *
 *  2. 009's write-kind CHECKs, one by one, and why each goes the way it does:
 *       - `change_jobs_guard_required_chk`  WIDENED. The job always carries a
 *         verdict (its own, written at enqueue), so requiring one costs
 *         nothing and keeps "a write kind with no verdict" unrepresentable.
 *       - `change_jobs_preflight_backup_chk` NOT widened. The job is ADDITIVE
 *         ONLY: it adds one `/ppp/secret` entry under a name that does not
 *         exist yet, never sets or removes one, and refuses when the name
 *         exists with different attributes. Its undo is the removal of that
 *         one entry by name, which a full backup of the fleet's concentrator
 *         would not make any safer. The job records the skip as a step.
 *       - `change_jobs_degraded_confirm_chk` NOT widened. The job arms no
 *         dead-man (there is nothing for one to revert: an added secret cuts no
 *         path, and RouterOS does not touch a live session when a secret is
 *         ADDED), so it is queued at `degraded`, which is the truth about its
 *         net. Requiring a human signature on that level would stop the bench,
 *         which runs this job unattended for one box at a time.
 *     `apply_outcomes.op_kind` is NOT widened either: that corpus is about
 *     changes made under a net on customer equipment (outcomes `rolled_back`,
 *     `lost_contact`), and this job writes no row to it.
 *
 *  3. The subtree interlock (010) is REPLACED by a version that exempts
 *     this kind, both ways. Its rule — no concentrator job while a child holds
 *     an armed dead-man, and no child job while the concentrator is written —
 *     exists because a concentrator write can drop the tunnels those dead-men
 *     need to be disarmed through. Adding a secret under an unused name drops
 *     no tunnel. Without the exemption the bench could not provision a box
 *     during any rollout wave on the same CHR, and a bench compile would make
 *     every child enqueue on that CHR fail for the job's duration. The
 *     per-device lock (`change_jobs_one_in_flight_uq`) still applies: one job
 *     at a time on the CHR, whatever its kind. Every other kind keeps the
 *     interlock exactly as 010 wrote it.
 *
 *  4. `concentrator_secret_jobs` — one row per job: the SITE it provisions (the
 *     job itself lives on the CHR's device row and, through it, in the CHR's
 *     tenant), the NON-SECRET attributes frozen at enqueue, and what the job
 *     found. The password is in no column anywhere: the worker fetches it at
 *     apply time and splices it into the API word last.
 *
 * No `?` anywhere in the SQL below: knex rewrites it inside raw() as a binding
 * placeholder (see migration 032).
 */

// Inlined literals, as 009, 010 and 029 do: a migration keeps describing the
// schema as it was on the day it ran.
const JOB_KINDS_009 = "'push','export','backup','restore','reboot','firmware'";
const JOB_KINDS_040 = "'push','export','backup','restore','reboot','firmware','concentrator_secret'";
const WRITE_KINDS_009 = "'push','restore','reboot','firmware'";
const WRITE_KINDS_040 = "'push','restore','reboot','firmware','concentrator_secret'";
const ACTIVE_JOB_STATUSES =
  "'queued','claimed','backing_up','arming','applying','verifying','soaking','disarming'";
/** `CONCENTRATOR_SECRET_OUTCOMES` in concentratorSecret.service.ts. */
const OUTCOMES = "'added','present','conflict'";

/** 010's function body, verbatim (010 said CREATE, this says CREATE OR
 *  REPLACE because the function exists). Restored by down(). */
const INTERLOCK_010 = `
    CREATE OR REPLACE FUNCTION change_jobs_subtree_interlock() RETURNS trigger AS $fn$
    DECLARE
      my_role   text;
      my_parent integer;
      clash     bigint;
      clash_dev integer;
    BEGIN
      IF NEW.status NOT IN (${ACTIVE_JOB_STATUSES}) THEN
        RETURN NEW;
      END IF;
      -- An UPDATE that merely walks the state machine on a job that was
      -- already active has nothing new to serialise: the pair was legal when
      -- the job was queued and no third job can have slipped in since without
      -- passing through this same trigger.
      IF TG_OP = 'UPDATE' AND OLD.status IN (${ACTIVE_JOB_STATUSES})
         AND OLD.device_id = NEW.device_id THEN
        RETURN NEW;
      END IF;

      SELECT role, concentrator_id INTO my_role, my_parent
        FROM devices WHERE id = NEW.device_id;

      IF my_role = 'concentrator' THEN
        PERFORM pg_advisory_xact_lock(20311, NEW.device_id);
        SELECT j.id, j.device_id INTO clash, clash_dev
          FROM change_jobs j
          JOIN devices d ON d.id = j.device_id
         WHERE d.concentrator_id = NEW.device_id
           AND j.status IN (${ACTIVE_JOB_STATUSES})
           AND j.id IS DISTINCT FROM NEW.id
         LIMIT 1;
        IF clash IS NOT NULL THEN
          RAISE EXCEPTION
            'subtree interlock: job % is in flight on device %, a child of concentrator %. A concentrator job cannot run while its children hold armed dead-men.',
            clash, clash_dev, NEW.device_id
            USING ERRCODE = 'restrict_violation';
        END IF;
      ELSIF my_parent IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(20311, my_parent);
        SELECT j.id INTO clash
          FROM change_jobs j
         WHERE j.device_id = my_parent
           AND j.status IN (${ACTIVE_JOB_STATUSES})
           AND j.id IS DISTINCT FROM NEW.id
         LIMIT 1;
        IF clash IS NOT NULL THEN
          RAISE EXCEPTION
            'subtree interlock: job % is in flight on concentrator %, which carries the tunnel to device %. A child job cannot start while its concentrator is being written to.',
            clash, my_parent, NEW.device_id
            USING ERRCODE = 'restrict_violation';
        END IF;
      END IF;

      RETURN NEW;
    END;
    $fn$ LANGUAGE plpgsql
  `;

/** The same function with `concentrator_secret` exempt, both ways (header, 3). */
const INTERLOCK_040 = `
    CREATE OR REPLACE FUNCTION change_jobs_subtree_interlock() RETURNS trigger AS $fn$
    DECLARE
      my_role   text;
      my_parent integer;
      clash     bigint;
      clash_dev integer;
    BEGIN
      IF NEW.status NOT IN (${ACTIVE_JOB_STATUSES}) THEN
        RETURN NEW;
      END IF;
      IF TG_OP = 'UPDATE' AND OLD.status IN (${ACTIVE_JOB_STATUSES})
         AND OLD.device_id = NEW.device_id THEN
        RETURN NEW;
      END IF;
      -- 040: adding a /ppp/secret under an unused name drops no tunnel, so it
      -- neither waits for a child's dead-man nor holds a child back. The
      -- one-job-per-device index still serialises it on the concentrator.
      IF NEW.kind = 'concentrator_secret' THEN
        RETURN NEW;
      END IF;

      SELECT role, concentrator_id INTO my_role, my_parent
        FROM devices WHERE id = NEW.device_id;

      IF my_role = 'concentrator' THEN
        PERFORM pg_advisory_xact_lock(20311, NEW.device_id);
        SELECT j.id, j.device_id INTO clash, clash_dev
          FROM change_jobs j
          JOIN devices d ON d.id = j.device_id
         WHERE d.concentrator_id = NEW.device_id
           AND j.status IN (${ACTIVE_JOB_STATUSES})
           AND j.id IS DISTINCT FROM NEW.id
         LIMIT 1;
        IF clash IS NOT NULL THEN
          RAISE EXCEPTION
            'subtree interlock: job % is in flight on device %, a child of concentrator %. A concentrator job cannot run while its children hold armed dead-men.',
            clash, clash_dev, NEW.device_id
            USING ERRCODE = 'restrict_violation';
        END IF;
      ELSIF my_parent IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(20311, my_parent);
        SELECT j.id INTO clash
          FROM change_jobs j
         WHERE j.device_id = my_parent
           AND j.status IN (${ACTIVE_JOB_STATUSES})
           AND j.kind <> 'concentrator_secret'
           AND j.id IS DISTINCT FROM NEW.id
         LIMIT 1;
        IF clash IS NOT NULL THEN
          RAISE EXCEPTION
            'subtree interlock: job % is in flight on concentrator %, which carries the tunnel to device %. A child job cannot start while its concentrator is being written to.',
            clash, my_parent, NEW.device_id
            USING ERRCODE = 'restrict_violation';
        END IF;
      END IF;

      RETURN NEW;
    END;
    $fn$ LANGUAGE plpgsql
  `;

const INTERLOCK_COMMENT_010 =
  'COMMENT ON FUNCTION change_jobs_subtree_interlock() IS $$' +
  'Never a job on a concentrator while a job is in ' +
  'flight on one of its children, nor the reverse. Takes an advisory lock ' +
  'on the concentrator id first, so the check has no gap to race through.$$';

const INTERLOCK_COMMENT_040 =
  'COMMENT ON FUNCTION change_jobs_subtree_interlock() IS $$' +
  'Never a job on a concentrator while a job is in ' +
  'flight on one of its children, nor the reverse. Takes an advisory lock ' +
  'on the concentrator id first, so the check has no gap to race through. ' +
  'Migration 040 exempts kind concentrator_secret both ways: an additive ' +
  '/ppp/secret entry drops no tunnel.$$';

export async function up(knex: Knex): Promise<void> {
  // ── 1. The kind ───────────────────────────────────────────────────────────
  await knex.schema.raw('ALTER TABLE change_jobs ALTER COLUMN kind TYPE varchar(24)');
  await knex.schema.raw('ALTER TABLE change_jobs DROP CONSTRAINT change_jobs_kind_chk');
  await knex.schema.raw(
    `ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_kind_chk CHECK (kind IN (${JOB_KINDS_040}))`,
  );

  // ── 2. The guard is required of it too (header, 2) ───────────────────────
  await knex.schema.raw('ALTER TABLE change_jobs DROP CONSTRAINT change_jobs_guard_required_chk');
  await knex.schema.raw(
    `ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_guard_required_chk
       CHECK (kind NOT IN (${WRITE_KINDS_040}) OR guard_verdict IS NOT NULL)`,
  );

  // ── 3. The interlock, with the exemption (header, 3) ─────────────────────
  // CREATE OR REPLACE keeps the function's identity, so the trigger 010
  // created keeps pointing at it; nothing else is recreated.
  await knex.schema.raw(INTERLOCK_040);
  await knex.schema.raw(INTERLOCK_COMMENT_040);

  // ── 4. concentrator_secret_jobs ──────────────────────────────────────────
  await knex.schema.createTable('concentrator_secret_jobs', (t) => {
    // One row per job, dying with it: the job is the record, this is its
    // subject. change_jobs.id is a bigint.
    t.bigInteger('job_id').primary().references('id').inTable('change_jobs').onDelete('CASCADE');
    // The SITE's tenant — the requester. The job row itself carries the
    // concentrator's tenant, because the queue loads a job's device scoped by
    // the job's tenant.
    t.integer('tenant_id').notNullable();
    t.integer('site_id').notNullable();
    // Frozen at enqueue; the worker re-reads the allocation at apply time and
    // refuses if it no longer says the same thing. Never a password.
    t.string('ppp_username', 128).notNullable();
    t.specificType('remote_address', 'inet').notNullable();
    t.string('ppp_profile', 64).nullable();
    t.string('comment', 160).notNullable();
    // What the job found on the concentrator. NULL until it has looked: no
    // DEFAULT, because "added" or "present" is an observation nobody has made
    // at insert time.
    t.string('outcome', 16).nullable();
    t.text('outcome_detail').nullable();
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });
  // `sites_id_tenant_uq` is asserted by 026/032/036; a row of tenant A cannot
  // name a site of tenant B.
  await knex.schema.raw(
    'ALTER TABLE concentrator_secret_jobs ADD CONSTRAINT concentrator_secret_jobs_site_tenant_fk ' +
      'FOREIGN KEY (site_id, tenant_id) REFERENCES sites (id, tenant_id) ON DELETE CASCADE',
  );
  const checks: Array<[string, string]> = [
    ['outcome_chk', `outcome IS NULL OR outcome IN (${OUTCOMES})`],
    // An outcome without its explanation is a badge nobody can act on.
    ['detail_chk', '(outcome IS NULL) = (outcome_detail IS NULL)'],
    ['remote_address_chk', 'family(remote_address) = 4 AND masklen(remote_address) = 32'],
    ['username_chk', "ppp_username <> ''"],
    ['comment_chk', "comment <> ''"],
    ['profile_chk', "ppp_profile IS NULL OR ppp_profile <> ''"],
  ];
  for (const [name, expr] of checks) {
    await knex.schema.raw(
      `ALTER TABLE concentrator_secret_jobs ADD CONSTRAINT concentrator_secret_jobs_${name} CHECK (${expr})`,
    );
  }
  await knex.schema.raw(
    'CREATE INDEX concentrator_secret_jobs_site_idx ON concentrator_secret_jobs (site_id, job_id DESC)',
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists('concentrator_secret_jobs');

  // A row of the new kind cannot be relabelled as another kind without lying
  // about what was done, so the rows go. Their steps cascade with them; the
  // commands themselves stay in `command_audit`, which carries no foreign key
  // and is append-only (009, decision 5), and `site_provisioning` keeps its
  // `concentrator_state` (its `concentrator_job_id` is SET NULL).
  await knex('change_jobs').where({ kind: 'concentrator_secret' }).del();

  await knex.schema.raw(INTERLOCK_010);
  await knex.schema.raw(INTERLOCK_COMMENT_010);

  await knex.schema.raw('ALTER TABLE change_jobs DROP CONSTRAINT change_jobs_guard_required_chk');
  await knex.schema.raw(
    `ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_guard_required_chk
       CHECK (kind NOT IN (${WRITE_KINDS_009}) OR guard_verdict IS NOT NULL)`,
  );
  await knex.schema.raw('ALTER TABLE change_jobs DROP CONSTRAINT change_jobs_kind_chk');
  await knex.schema.raw(
    `ALTER TABLE change_jobs ADD CONSTRAINT change_jobs_kind_chk CHECK (kind IN (${JOB_KINDS_009}))`,
  );
  await knex.schema.raw('ALTER TABLE change_jobs ALTER COLUMN kind TYPE varchar(12)');
}
