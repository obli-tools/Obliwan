import type { Knex } from 'knex';

/**
 * 099 — the write frontier of a generic change job, PERSISTED.
 *
 * ┌─ WHY ─────────────────────────────────────────────────────────────────────┐
 * │ A `push` arms an on-box dead-man BEFORE its first configuration command. │
 * │ When the job stops between the two, nothing was sent, the net protects    │
 * │ nothing, and left armed it reboots the router at its deadline to reload   │
 * │ the configuration it already has. The live worker takes that net down    │
 * │ (`applyFrontier.ts`). A DEAD one cannot: a crash or a redeploy in that    │
 * │ window left the job for the reaper, which failed an `arming` row and      │
 * │ never touched an `applying` one — and nobody removed the net.             │
 * │                                                                          │
 * │ The reaper needs ONE fact the dead worker took with it: had the first     │
 * │ configuration command been handed to the router? `transmit_started_at`   │
 * │ is that fact. The worker stamps it in the SAME UPDATE that proves it      │
 * │ still holds the lease (`status = 'applying'`, `claimed_by` = itself),     │
 * │ immediately before that command — so the reaper's own UPDATE, which       │
 * │ requires it NULL and the lease expired, and the stamp are serialised by   │
 * │ the row lock: exactly one of them wins, and the loser sends nothing.      │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * NULL means "not crossed" only for a job that reached `applying` under this
 * code. A job already past `applying` when this migration runs crossed it
 * under the old code without a stamp, so it is BACKFILLED as crossed —
 * otherwise the reaper would read an unknown as "nothing sent" and take the
 * net off a change that may have landed. Unknown is treated as sent.
 *
 * No `?` in any raw statement (the knex binding trap of migration 032).
 */

export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable('change_jobs', (t) => {
    t.timestamp('transmit_started_at', { useTz: true }).nullable();
  });
  await knex.schema.raw(
    'UPDATE change_jobs SET transmit_started_at = COALESCE(deadman_armed_at, updated_at, now()) ' +
      "WHERE status IN ('applying','verifying','soaking','disarming')",
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.alterTable('change_jobs', (t) => {
    t.dropColumn('transmit_started_at');
  });
}
