import type { Knex } from 'knex';

/**
 * 046 - the latest RouterOS 7 releases MikroTik publishes, one row per
 * channel (services/firmware/releases.service.ts is the only writer).
 *
 *  - `channel`          'stable' | 'long-term' (shared/src/firmware.ts).
 *  - `version`          the last version SUCCESSFULLY read. A failed check
 *                       never touches it: it stays the last good value, and
 *                       the failure lands in `last_error`. NULL only while no
 *                       check on this channel has ever succeeded.
 *  - `released_at`      the publication time MikroTik sent with the version
 *                       (the second field of NEWESTa7.<channel>), NULL when it
 *                       sent none or an implausible one.
 *  - `first_seen_at`    when THIS installation first read `version` on this
 *                       channel; reset when the channel moves to another
 *                       version.
 *  - `last_checked_at`  the last attempt, successful or not.
 *  - `last_success_at`  the last attempt that produced `version`. Kept apart
 *                       from `last_checked_at` so a watcher failing for a week
 *                       does not show a value "checked an hour ago".
 *  - `last_error`       the last attempt's error, NULL once one succeeds.
 *
 * No DEFAULT on any timestamp: each one states something observed, and a
 * DEFAULT now() would state an observation nobody made.
 *
 * The fleet TARGET (stable / long-term / pinned) is NOT here: it is one
 * instance-level decision, stored in `app_config` under `routeros_target`.
 *
 * Literals only in the SQL below, and the optional third version component is
 * written `{0,1}`: knex rewrites a `?` inside raw() as a binding placeholder
 * (a known trap).
 */

const T = 'routeros_releases';

async function addCheck(knex: Knex, name: string, expr: string): Promise<void> {
  await knex.schema.raw(`ALTER TABLE ${T} ADD CONSTRAINT ${T}_${name} CHECK (${expr})`);
}

export async function up(knex: Knex): Promise<void> {
  await knex.schema.createTable(T, (t) => {
    t.string('channel', 16).primary();
    t.string('version', 16).nullable();
    t.timestamp('released_at', { useTz: true }).nullable();
    t.timestamp('first_seen_at', { useTz: true }).nullable();
    t.timestamp('last_checked_at', { useTz: true }).notNullable();
    t.timestamp('last_success_at', { useTz: true }).nullable();
    t.text('last_error').nullable();
  });
  await addCheck(knex, 'channel_chk', `channel IN ('stable','long-term')`);
  await addCheck(
    knex,
    'version_chk',
    `version IS NULL OR version ~ '^[0-9]{1,4}\\.[0-9]{1,4}(\\.[0-9]{1,4}){0,1}$'`,
  );
  // A version is always accompanied by the instants that produced it, and a
  // publication time never exists without the version it dates.
  await addCheck(
    knex,
    'observed_chk',
    '((version IS NULL) = (first_seen_at IS NULL)) AND ((version IS NULL) = (last_success_at IS NULL)) '
      + 'AND (released_at IS NULL OR version IS NOT NULL)',
  );
  await addCheck(knex, 'last_error_chk', 'last_error IS NULL OR char_length(last_error) <= 500');
}

export async function down(knex: Knex): Promise<void> {
  // Nothing else references this table. Every version is re-read from
  // MikroTik on the next check; what dropping it loses is `first_seen_at` (when
  // this installation first saw each version), not a decision. The target in
  // `app_config` is left alone: 046 did not create that row.
  await knex.schema.dropTableIfExists(T);
}
