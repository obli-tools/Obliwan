import type { Knex } from 'knex';

/**
 * 055_subtree_interlock_lock_class.ts — the subtree interlock stops
 * sharing its advisory-lock class with the leader election.
 *
 * THE DEFECT. `change_jobs_subtree_interlock()` (010, replaced by 040)
 * serialises a job on a concentrator and the jobs on its children with
 * `pg_advisory_xact_lock(20311, <concentrator id>)`. The leader election
 * (services/leaderElection.ts) holds the SESSION lock `(0x4F57, 1)` for as
 * long as a process is the leader — and 0x4F57 IS 20311. So on any
 * installation with a leader, every job insert that locks concentrator id 1 —
 * a job on device 1 when it is a concentrator, or on any device whose
 * concentrator is device 1 — waits on a lock the leader's own lock session
 * never releases: the insert hangs until leadership changes hands.
 *
 * Found by m7-rollout.verify.ts once the rollout driver ran under a real
 * election (backlog #14): the seeded concentrator is device 1, the driver
 * started wave 2, and its four job inserts hung until the harness resigned
 * leadership. On a production database whose first device row is the
 * concentrator, the same wait would hit every push, restore, reboot, firmware
 * and os_upgrade job on that concentrator's devices. `concentrator_secret`
 * jobs are not affected: 040 returns before the lock for that kind.
 *
 * THE FIX. The interlock takes its lock in class 80500 ("the concentrator interlock"), used by
 * nothing else in the tree (the others: 0x4F57 leader election, 36036
 * allocation, 730119204 audit chain, 0x6265 bench registration, 0x0f6
 * identity watch). The leader election keeps its class: its own header says
 * that key must stay stable, because two processes on two different keys
 * would both be leader during a rolling restart. The interlock's class has no
 * such constraint — it lives in the database, so every process uses the new
 * one from the moment this migration commits.
 *
 * The body is 040's, VERBATIM except for the two lock calls. CREATE OR
 * REPLACE keeps the function's identity, so the trigger 010 created keeps
 * pointing at it. down() restores 040's body.
 *
 * No `?` anywhere in the SQL below: knex rewrites it inside raw() as a
 * binding placeholder (see migration 032).
 */

// Inlined literals, as 040 does: a migration keeps describing the schema as
// it was on the day it ran.
const ACTIVE_JOB_STATUSES =
  "'queued','claimed','backing_up','arming','applying','verifying','soaking','disarming'";

const CLASS_040 = 20311;
const CLASS_055 = 80500;

function interlock(lockClass: number): string {
  return `
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
        PERFORM pg_advisory_xact_lock(${lockClass}, NEW.device_id);
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
        PERFORM pg_advisory_xact_lock(${lockClass}, my_parent);
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
}

const COMMENT_040 =
  'COMMENT ON FUNCTION change_jobs_subtree_interlock() IS $$' +
  'Never a job on a concentrator while a job is in ' +
  'flight on one of its children, nor the reverse. Takes an advisory lock ' +
  'on the concentrator id first, so the check has no gap to race through. ' +
  'Migration 040 exempts kind concentrator_secret both ways: an additive ' +
  '/ppp/secret entry drops no tunnel.$$';

const COMMENT_055 =
  'COMMENT ON FUNCTION change_jobs_subtree_interlock() IS $$' +
  'Never a job on a concentrator while a job is in ' +
  'flight on one of its children, nor the reverse. Takes an advisory lock ' +
  `(class ${CLASS_055}) on the concentrator id first, so the check has no gap ` +
  'to race through; the class is not the leader election one (migration 055). ' +
  'Migration 040 exempts kind concentrator_secret both ways: an additive ' +
  '/ppp/secret entry drops no tunnel.$$';

export async function up(knex: Knex): Promise<void> {
  await knex.schema.raw(interlock(CLASS_055));
  await knex.schema.raw(COMMENT_055);
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.raw(interlock(CLASS_040));
  await knex.schema.raw(COMMENT_040);
}
