import type { Knex } from 'knex';

/**
 * 091_ppp_session_duplicates.ts — a PPP login holding SEVERAL sessions at once
 * on its concentrator, as the last successful `/ppp/active` read showed it
 * (incident 2026-10-09; shared/src/pppDuplicates.ts,
 * services/fleet/pppDuplicates.service.ts).
 *
 * `ppp_sessions` keeps AT MOST ONE open row per (concentrator, username)
 * (002's `ppp_sessions_open_uniq`), and that invariant is what presence's
 * reconciliation is built on: it is NOT changed here. A second live session
 * for the same login used to be collapsed into that one row and nobody saw it.
 * It is now recorded BESIDE the history, in two tables of its own:
 *
 *  1. `concentrator_active_reads` — one row per concentrator whose
 *     `/ppp/active` was read successfully at least once (presence's 60 s
 *     sweep, the reconciliation's "re-read the CHR"): when, how many sessions,
 *     how many duplicated logins. A failed read writes nothing, so "never
 *     read" and "read, no duplicate" stay two different answers — the same
 *     shape as 036's `concentrator_secret_reads`.
 *
 *  2. `ppp_session_duplicates` — one row per (concentrator, login without
 *     regard to case) that the LAST successful read of that concentrator
 *     listed with two sessions or more: the sessions as printed (name,
 *     caller-id, address, uptime — `/ppp/active` carries no password), when
 *     the duplicate was first seen and when it was last observed. Each read
 *     REPLACES the concentrator's rows: a login the read shows once again is
 *     deleted, so a row present means "the latest read saw it duplicated".
 *
 * FOREIGN KEYS point from these leaves to `devices` only, ON DELETE CASCADE:
 * a concentrator removed takes its observations with it.
 *
 * No `?` anywhere in the SQL below (knex binding trap, migration 032), no
 * regex in a CHECK.
 */

export async function up(knex: Knex): Promise<void> {
  await knex.schema.createTable('concentrator_active_reads', (t) => {
    t.integer('concentrator_id').primary().references('id').inTable('devices').onDelete('CASCADE');
    t.timestamp('read_at', { useTz: true }).notNullable();
    t.integer('session_count').notNullable();
    t.integer('duplicate_count').notNullable();
  });
  await knex.schema.raw(
    'ALTER TABLE concentrator_active_reads ADD CONSTRAINT concentrator_active_reads_counts_chk ' +
      'CHECK (session_count >= 0 AND duplicate_count >= 0 AND duplicate_count * 2 <= session_count)',
  );

  await knex.schema.createTable('ppp_session_duplicates', (t) => {
    t.integer('concentrator_id').notNullable().references('id').inTable('devices').onDelete('CASCADE');
    // The login lower-cased (by the recorder, in JavaScript): sessions are
    // grouped without regard to case.
    t.text('login_key').notNullable();
    // The spelling of the first session the read printed.
    t.text('ppp_username').notNullable();
    t.integer('session_count').notNullable();
    // [{ name, callerId, address, uptime, since }] as the read printed them.
    t.jsonb('sessions').notNullable();
    t.timestamp('first_seen_at', { useTz: true }).notNullable();
    t.timestamp('observed_at', { useTz: true }).notNullable();
    t.primary(['concentrator_id', 'login_key']);
  });
  await knex.schema.raw(
    'ALTER TABLE ppp_session_duplicates ADD CONSTRAINT ppp_session_duplicates_shape_chk CHECK (' +
      'session_count >= 2 ' +
      "AND login_key <> '' " +
      "AND jsonb_typeof(sessions) = 'array' " +
      'AND jsonb_array_length(sessions) = session_count ' +
      'AND observed_at >= first_seen_at)',
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists('ppp_session_duplicates');
  await knex.schema.dropTableIfExists('concentrator_active_reads');
}
