import type { Knex } from 'knex';

/**
 * 043 — device_health_checks: the permanent check of each device's management
 * channel, ONE ROW PER DEVICE, written by
 * `services/fleet/healthCheck.service.ts`.
 *
 * NOT `device_health` (002). That table is the RouterOS pool's circuit breaker,
 * one row per (device, TRANSPORT), and its only writer is the pool
 * (`routerosPool.saveHealth`). It answers "may this channel be dialled now".
 * This one answers "did the device answer when we last asked, since when has it
 * not, and was anybody told". Two questions, two writers, two tables — one
 * writer per row is the rule `routerosPool.ts` already states for the other.
 *
 * Columns, and the reader each timestamp has (a stored instant nothing reads is
 * a guard applied at write time only):
 *   last_check_at   freshness of the whole row: `healthDisplay()` turns a row
 *                   older than two intervals into `stale`, and the reachability verdict of
 *                   a concentrator stops trusting it at the same bound
 *                   (`reachability.readManagementOk`).
 *   last_ok_at      shown on the page; and the reachability read compares it with the
 *                   latest CONCENTRATOR_DEGRADED verdict — newest evidence wins.
 *   down_since      the alert delay is counted from it; shown as "down since".
 *   alerted_at      "already alerted for this outage" (alerted_at >= down_since)
 *                   and the notification cooldown between two outages of the
 *                   same device. Written only once the outage's live alert (or
 *                   the group alert it was folded into) exists, so an alert
 *                   lost on the way is raised again rather than recorded as
 *                   sent. Kept across a recovery on purpose: it is the anchor
 *                   the cooldown needs.
 *   next_check_at   the scheduler's due test, and the page's "next check".
 *   interval_sec    the interval that computed next_check_at, i.e. the
 *                   freshness base for anyone reading the row without resolving
 *                   the settings tree again.
 *
 * No DEFAULT states an unverified fact: `state` starts 'unknown', and 'up' is
 * only ever written by a check that answered (the CHECK below refuses an 'up'
 * with no `last_ok_at`). `consecutive_failures` defaults to 0, which is what a
 * row nobody has checked yet has counted.
 *
 * Every CHECK is written without a `?`: knex rewrites `?` inside raw() as a
 * binding placeholder (the migration 032 trap), so the vocabularies are IN
 * lists of literals, inlined here rather than imported, so this file keeps
 * describing the schema as it was the day it ran.
 */

const STATES = "'up','down','unknown'";
const CHANNELS = "'routeros_api','ssh','rest'";
const SKIP_REASONS = "'no_channel','parent_degraded','quarantined'";

export async function up(knex: Knex): Promise<void> {
  await knex.schema.createTable('device_health_checks', (t) => {
    t.integer('device_id').primary()
      .references('id').inTable('devices').onDelete('CASCADE');
    t.string('state', 8).notNullable().defaultTo('unknown');
    t.integer('consecutive_failures').notNullable().defaultTo(0);
    t.string('channel', 16).nullable();
    t.string('skip_reason', 24).nullable();
    t.integer('interval_sec').nullable();
    t.timestamp('last_check_at', { useTz: true }).nullable();
    t.timestamp('last_ok_at', { useTz: true }).nullable();
    t.timestamp('down_since', { useTz: true }).nullable();
    t.timestamp('alerted_at', { useTz: true }).nullable();
    t.timestamp('next_check_at', { useTz: true }).nullable();
    // Redacted by the transport layer, bounded here. Never a credential.
    t.text('last_error').nullable();
  });

  const chk = (name: string, expr: string) =>
    knex.schema.raw(`ALTER TABLE device_health_checks ADD CONSTRAINT ${name} CHECK (${expr})`);

  await chk('device_health_checks_state_chk', `state IN (${STATES})`);
  await chk('device_health_checks_channel_chk', `channel IS NULL OR channel IN (${CHANNELS})`);
  await chk(
    'device_health_checks_skip_chk',
    `skip_reason IS NULL OR skip_reason IN (${SKIP_REASONS})`,
  );
  await chk('device_health_checks_failures_chk', 'consecutive_failures >= 0');
  // 'down' and its instant travel together, both ways: a down row with no
  // `down_since` could never raise its alert, and a `down_since` on a row that
  // is not down would start the delay of an outage that is not happening.
  await chk('device_health_checks_down_chk', "(state = 'down') = (down_since IS NOT NULL)");
  // Declared down means at least one failure was counted.
  await chk('device_health_checks_down_fail_chk', "state <> 'down' OR consecutive_failures > 0");
  // 'up' is a measured fact: it carries the instant it was measured.
  await chk('device_health_checks_up_chk', "state <> 'up' OR last_ok_at IS NOT NULL");
  await chk(
    'device_health_checks_ok_chk',
    'last_ok_at IS NULL OR (last_check_at IS NOT NULL AND last_ok_at <= last_check_at)',
  );
  // The interval is stored with the schedule it produced, never alone.
  await chk(
    'device_health_checks_interval_chk',
    '(next_check_at IS NULL) = (interval_sec IS NULL) AND (interval_sec IS NULL OR interval_sec > 0)',
  );
  await chk(
    'device_health_checks_error_chk',
    'last_error IS NULL OR char_length(last_error) <= 500',
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists('device_health_checks');
}
