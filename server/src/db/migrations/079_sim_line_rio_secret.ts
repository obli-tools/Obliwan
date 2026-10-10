import type { Knex } from 'knex';

/**
 * 079 — a mobile line's RIO is a SECRET, stored like its PUKs.
 *
 * ┌─ WHY ─────────────────────────────────────────────────────────────────────┐
 * │ Migration 077 kept every field of the partner's line listing, and the    │
 * │ RIO — the portability code — went into `partner_details` verbatim, in     │
 * │ clear, readable by every SIM_READ holder. A RIO plus the number is all a  │
 * │ porting request needs: whoever holds both can move the line to another   │
 * │ operator.                                                                 │
 * │                                                                          │
 * │ OPERATOR DECISION (2026-10-06): « RIO => Secret car sensible as fuck ».  │
 * │ It is handled EXACTLY like `puk1`: a vault blob in `rio_enc`, revealed   │
 * │ one line at a time through `POST /sim/lines/:id/reveal` (SECRET_READ +   │
 * │ SIM_READ, audited without the value), never in `partner_details`.        │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHAT THIS DOES ──────────────────────────────────────────────────────────┐
 * │ · `rio_enc`, nullable, with 077's two rules for `puk1_enc`: a stored     │
 * │   value is a `v1:` vault blob, and a blob always has its key generation  │
 * │   in `secrets_key_version`.                                              │
 * │ · The RIO is REMOVED from every stored `partner_details`. SQL cannot      │
 * │   encrypt (the key is not in the database, and must never be): the next  │
 * │   sweep reads it again and stores it in `rio_enc`. A remainder whose RIO  │
 * │   sits in a NESTED object cannot be cleaned key by key here, so that      │
 * │   remainder is emptied (NULL) whole — it is non-secret by construction   │
 * │   otherwise, and the next sweep rewrites it whole anyway.                │
 * │ · A CHECK then refuses a RIO key in `partner_details` at ANY depth, so   │
 * │   a defect that put it back in clear fails the upsert instead of         │
 * │   succeeding. The names it refuses are a prefix (`code`, `numero`,       │
 * │   `num`, `no`, `n`), `rio`, a suffix (`code`, `numero`, `num`), each     │
 * │   joined by at most one `_`, `-` or space, in any case — a SUBSET of     │
 * │   what the connector recognises as the RIO (`RIO_NAME`, on the           │
 * │   normalised name), so it can never refuse a field the connector would   │
 * │   have kept: it can only catch a regression.                            │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * HOW THE CHECK SEES A KEY AT ANY DEPTH WITHOUT A FUNCTION: in jsonb's text
 * form a key is a quoted string that follows `{` or a space (`, ` separates
 * members) and is followed by `:`. A quote INSIDE a string is always escaped,
 * so it follows a backslash, never `{` or a space — and a VALUE is followed by
 * `,`, `}` or `]`, never `:`. So the pattern matches keys, and keys only.
 *
 * No `?` in any raw statement (the knex binding trap of migration 032): the
 * optional parts are written `{0,1}`.
 */

const NAME = '((numero|num|code|no|n)[_ -]{0,1}){0,1}rio([_ -]{0,1}(code|numero|num)){0,1}';
/** One key name, whole (`jsonb_object_keys`). */
const KEY_RE = `^${NAME}$`;
/** A key of that name anywhere in `partner_details::text`. */
const ANY_DEPTH_RE = `[{ ]"${NAME}"[[:space:]]*:`;

export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable('sim_lines', (t) => {
    t.text('rio_enc').nullable();
  });

  // 077's rules for `puk1_enc`, for `rio_enc`.
  await knex.schema.raw(
    "ALTER TABLE sim_lines ADD CONSTRAINT sim_lines_rio_blob_chk CHECK (rio_enc IS NULL OR rio_enc LIKE 'v1:%')",
  );
  await knex.schema.raw(
    'ALTER TABLE sim_lines ADD CONSTRAINT sim_lines_rio_key_chk ' +
      'CHECK (rio_enc IS NULL OR secrets_key_version IS NOT NULL)',
  );

  // The plaintext RIO out of every stored remainder: the top-level keys by name…
  await knex.schema.raw(
    'UPDATE sim_lines SET partner_details = partner_details - ARRAY(' +
      `SELECT k FROM jsonb_object_keys(partner_details) AS k WHERE k ~* '${KEY_RE}') ` +
      `WHERE partner_details IS NOT NULL AND partner_details::text ~* '${ANY_DEPTH_RE}'`,
  );
  // …and a remainder that still carries one (nested) is emptied whole.
  await knex.schema.raw(
    'UPDATE sim_lines SET partner_details = NULL ' +
      `WHERE partner_details IS NOT NULL AND partner_details::text ~* '${ANY_DEPTH_RE}'`,
  );

  await knex.schema.raw(
    'ALTER TABLE sim_lines ADD CONSTRAINT sim_lines_partner_details_rio_chk CHECK (' +
      `partner_details IS NULL OR partner_details::text !~* '${ANY_DEPTH_RE}')`,
  );
}

/**
 * The CHECKs and the column go. The RIO is NOT put back in `partner_details`:
 * the database never held it in clear after `up`, and the code that runs
 * after a rollback (pre-079) re-reads it from the partner on its next sweep.
 * Every RIO blob is lost with the column — the partner still has them all.
 */
export async function down(knex: Knex): Promise<void> {
  await knex.schema.raw('ALTER TABLE sim_lines DROP CONSTRAINT IF EXISTS sim_lines_partner_details_rio_chk');
  await knex.schema.raw('ALTER TABLE sim_lines DROP CONSTRAINT IF EXISTS sim_lines_rio_key_chk');
  await knex.schema.raw('ALTER TABLE sim_lines DROP CONSTRAINT IF EXISTS sim_lines_rio_blob_chk');
  await knex.schema.alterTable('sim_lines', (t) => {
    t.dropColumn('rio_enc');
  });
}
