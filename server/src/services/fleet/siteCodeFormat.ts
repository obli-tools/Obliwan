/**
 * ObliWAN — the tenant's site code format, read from the database.
 *
 * The rule itself is pure and lives with the allocation policy
 * (services/allocation/policy.ts: `parseSiteCodeFormat`, `judgeSiteCode`,
 * `siteNumberSiblings`); this file only reads the stored column and the
 * tenant's codes and hands them to that judge. Its callers: the CSV import
 * (siteImport.service), and site.service's createSite / updateSite — the
 * site form, and the reconciliation's orphan sites, which reach createSite.
 *
 * NOT every write of a site code is judged. The tenant bundle import
 * (controllers/importExport.controller.ts) inserts and, on an 'update'
 * decision, rewrites `sites.code` straight from the bundle, without this judge
 * (nor createSiteSchema's slug): a bundle can still bring a code outside the
 * tenant's format, or a second spelling of an existing site number.
 *
 * The format is read on its own column, NOT through the whole policy: a policy
 * that no longer validates (a pool deleted by hand) must not turn a declared
 * 'digits:5' into "no rule" for the next code somebody types.
 */

import type { Knex } from 'knex';
import { AppError } from '../../middleware/errorHandler';
import {
  FREE_SITE_CODE_FORMAT,
  indexBySiteNumber,
  judgeSiteCode,
  parseSiteCodeFormat,
  siteNumberClashMessage,
  siteNumberSiblings,
  type SiteCodeFormat,
} from '../allocation/policy';

/** The tenant's format; free when it has no allocation policy (migration
 *  052: NULL = free). */
export async function loadSiteCodeFormat(
  q: Knex | Knex.Transaction,
  tenantId: number,
): Promise<SiteCodeFormat> {
  const row = (await q('tenant_allocation_policies')
    .where({ tenant_id: tenantId })
    .first('site_code_format')) as { site_code_format: string | null } | undefined;
  if (!row) return FREE_SITE_CODE_FORMAT;
  const parsed = parseSiteCodeFormat(row.site_code_format);
  // Unreachable under the CHECK of migration 052. Refused rather than read as
  // free: an unreadable rule is not the absence of one.
  if (!parsed.ok) throw new Error(`tenant ${tenantId}: the stored site code format does not parse`);
  return parsed.format;
}

/**
 * The tenant's all-digit codes by site number (`indexBySiteNumber`), read
 * only under 'digits:N' — empty under 'free', where nothing is judged against
 * it. `excludeSiteId` leaves out the site being renamed: its own current code
 * is not a second site.
 */
export async function loadSiteNumberIndex(
  q: Knex | Knex.Transaction,
  tenantId: number,
  format: SiteCodeFormat,
  excludeSiteId?: number,
): Promise<Map<number, string[]>> {
  if (format.kind !== 'digits') return new Map();
  const query = q('sites').where('tenant_id', tenantId).select('code');
  if (excludeSiteId !== undefined) query.whereNot('id', excludeSiteId);
  const rows = (await query) as { code: string }[];
  return indexBySiteNumber(rows.map((r) => r.code));
}

export interface SiteCodeAssertOptions {
  /** The site being renamed (updateSite): left out of the sibling lookup. */
  renamingSiteId?: number;
  /**
   * The code is read off a PPP account already live on the CHR (the
   * reconciliation's orphans): the format is NOT judged — that account's
   * login is a fact, and refusing or padding its code cannot change it; it
   * can only make the account impossible to adopt. The site-number sibling
   * check still applies.
   */
  deployedLogin?: boolean;
}

/**
 * The site form's judge (create, and a rename that changes the code): the
 * import's rule without the zero restoration, because nothing on that path
 * shows a correction before it is written; then, under 'digits:N', a code
 * whose site number another site of the tenant already holds under another
 * spelling ("7" created before the format, "00007" typed now) is refused —
 * the CSV import refuses the same create. Throws AppError 400 with the French
 * sentence.
 *
 * Read-then-write, not serialised against a concurrent write of a sibling:
 * under 'digits:N' only an exact N-digit code passes the judge, so a racing
 * sibling can only come from a path that skips it (deployedLogin, the bundle
 * import) or from a write racing a change of the format itself.
 */
export async function assertSiteCodeFormat(
  q: Knex | Knex.Transaction,
  tenantId: number,
  code: string,
  opts: SiteCodeAssertOptions = {},
): Promise<void> {
  const format = await loadSiteCodeFormat(q, tenantId);
  if (opts.deployedLogin !== true) {
    const verdict = judgeSiteCode(code, format, { restoreZeros: false });
    if (!verdict.ok) throw new AppError(400, verdict.error);
  }
  const siblings = siteNumberSiblings(code, await loadSiteNumberIndex(q, tenantId, format, opts.renamingSiteId));
  if (siblings.length > 0) throw new AppError(400, siteNumberClashMessage(code, siblings));
}
