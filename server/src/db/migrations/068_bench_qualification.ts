import type { Knex } from 'knex';

/**
 * 068 — the QUALIFICATION of a bench-prepared router: from when its outages
 * are announced (operator rule of 2026-10-04, `BenchQualificationState` in
 * shared/src/health.ts, services/fleet/benchQualification.service.ts).
 *
 * A router prepared at the bench is unplugged and shipped right after, for a
 * day to three weeks; alerts in that time are noise. It becomes alertable once
 * its PPP session has stayed open without a break — an hour right after the
 * preparation, fifteen minutes later on site. These two columns record that it
 * did, and for WHICH preparation:
 *
 *   `qualified_at`               the instant the tunnel crossed the bar.
 *   `qualified_provisioning_id`  the `bench_provisionings` row (the 'applied'
 *                                report) it qualified after. A later
 *                                preparation of the same device is a new box
 *                                to ship: the qualification no longer matches
 *                                the latest report and counts for nothing.
 *
 * WHY STORED when the deployment view stores nothing: everything else about a
 * box is re-derived from facts that keep their meaning. This one does not stay
 * derivable. A session closed by a reconciliation (`reconciled-missing`)
 * carries the instant presence NOTICED it was gone — an hour or three late
 * after a concentrator outage — so its recorded length cannot qualify anything
 * after the fact; a box that qualified while its session was open, as watched,
 * must not fall back to "in shipping" because its next close happened to be
 * found by a sweep. The evaluator writes it once, on the leader, from a live
 * observation or an observed close, and nothing un-writes it.
 *
 * "In shipping" and "qualifying" are NOT stored: they are the open session (or
 * its absence) read now, and a stored copy would be a second account of the
 * presence history free to disagree with it.
 *
 * NO DEFAULT on either column. NULL means "not qualified" for a device the
 * bench prepared, and means NOTHING for one it never prepared — that device is
 * not concerned and keeps today's rule (a device that answered a check is
 * announced), which is why no backfill is needed and why a default could only
 * be wrong: `now()` would qualify every box in a van this morning.
 *
 * No foreign key on the reference (see up()): a preparation row disappears only
 * with its site or device, and a reference to nothing qualifies nothing (the gate
 * compares it with the device's latest report). The CHECK is one-way for that
 * reason — a reference always carries its instant; an instant whose reference
 * was deleted is inert.
 *
 * No `?` anywhere in the SQL below (knex binding trap, migration 032).
 */
export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable('devices', (t) => {
    t.timestamp('qualified_at', { useTz: true }).nullable();
    // No foreign key, on purpose: bench_provisionings already references
    // change_jobs (concentrator_job_id), so a key from devices would make
    // devices reachable from change_jobs — a TRUNCATE … CASCADE of the job
    // tables emptied the device table (m6-queue harness, 2026-10-04) — and
    // would close a devices <-> bench_provisionings cycle. A reference to a
    // row that no longer exists qualifies nothing (the gate compares it with
    // the device's latest report), so nothing depends on the key.
    t.bigInteger('qualified_provisioning_id').nullable();
  });
  await knex.raw(`
    ALTER TABLE devices ADD CONSTRAINT devices_qualified_chk
      CHECK (qualified_provisioning_id IS NULL OR qualified_at IS NOT NULL)
  `);
}

export async function down(knex: Knex): Promise<void> {
  await knex.raw('ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_qualified_chk');
  await knex.schema.alterTable('devices', (t) => {
    t.dropColumn('qualified_provisioning_id');
    t.dropColumn('qualified_at');
  });
}
