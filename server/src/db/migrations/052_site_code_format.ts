import type { Knex } from 'knex';

/**
 * 052_site_code_format.ts — the shape a tenant's site codes must have.
 *
 * tenant_allocation_policies
 *  - `site_code_format`  NULL = free (no rule beyond the slug createSiteSchema
 *                        already enforces: what every tenant had before this
 *                        migration), or 'digits:N' = exactly N decimal digits,
 *                        leading zeros significant ("00102"). Read by
 *                        services/allocation/policy.ts `parseSiteCodeFormat`
 *                        and judged by `judgeSiteCode` where a code is created
 *                        or renamed through the CSV import or site.service
 *                        (site form, reconciliation orphans) — NOT by the
 *                        tenant bundle import, which writes codes unjudged.
 *
 * No DEFAULT: an existing policy keeps the behaviour it had, and a format is
 * a decision an operator takes, not one this migration takes for 300 sites.
 * Existing site codes are NOT re-judged — a format applies to the codes
 * written through those paths after it is declared.
 *
 * The CHECK is a list of literals rather than a regex: knex rewrites a "?"
 * inside raw SQL as a binding (see migration 032), and a list cannot
 * meet that trap. N runs from 1 to 15, policy.ts SITE_CODE_DIGITS_MAX
 * (`siteNumber` stays an exact integer up to 15 digits); the two are kept in
 * lockstep by hand.
 */

const P = 'tenant_allocation_policies';
const DIGITS_MAX = 15;
const FORMATS = Array.from({ length: DIGITS_MAX }, (_, i) => `'digits:${i + 1}'`).join(',');

export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable(P, (t) => {
    t.string('site_code_format', 16).nullable();
  });
  await knex.schema.raw(
    `ALTER TABLE ${P} ADD CONSTRAINT ${P}_site_code_format_chk ` +
      `CHECK (site_code_format IS NULL OR site_code_format IN (${FORMATS}))`,
  );
}

export async function down(knex: Knex): Promise<void> {
  // The CHECK names only this column, so PostgreSQL drops it with the column.
  await knex.schema.alterTable(P, (t) => {
    t.dropColumn('site_code_format');
  });
}
