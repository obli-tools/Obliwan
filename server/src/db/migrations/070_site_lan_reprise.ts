import type { Knex } from 'knex';

/**
 * 070 — the LAN of an existing store, recorded from its deployed router.
 *
 * An ADOPTED allocation (044) takes its login and tunnel address from the
 * CHR's secret. The store's LAN is not on the CHR: a LAN rule would hand the
 * store a block that is not its own, and "no LAN" leaves `lan_subnet` empty,
 * so every computed value derived from it (`cidrHost(lan_subnet, 1)`) resolves
 * to nothing. The operator holds a verified table of the deployed LANs;
 * services/allocation/lanReprise.ts records each one on the site's allocation.
 *
 *  - `lan_source` gains 'recorded': the LAN was typed from the store's own
 *    configuration by the platform administrator, not computed by a rule. It
 *    has no pool (`lan_pool_chk` of 039 already ties a pool to 'pool' only),
 *    and the per-tenant unique index of 039 covers it like every non-fixed
 *    LAN. Nothing else changes: the column is varchar(8), and 'recorded'
 *    fits.
 *
 * Literals only in the SQL below: knex rewrites a `?` inside raw() as a
 * binding placeholder (a known trap).
 */

const S = 'site_provisioning';
const SOURCES_039 = "'pool','fixed','manual'";
const SOURCES_070 = "'pool','fixed','manual','recorded'";

async function replaceSourceCheck(knex: Knex, sources: string): Promise<void> {
  await knex.schema.raw(`ALTER TABLE ${S} DROP CONSTRAINT IF EXISTS ${S}_lan_source_chk`);
  await knex.schema.raw(
    `ALTER TABLE ${S} ADD CONSTRAINT ${S}_lan_source_chk CHECK (lan_source IS NULL OR lan_source IN (${sources}))`,
  );
}

export async function up(knex: Knex): Promise<void> {
  await replaceSourceCheck(knex, SOURCES_070);
}

export async function down(knex: Knex): Promise<void> {
  // Refuse rather than destroy: a recorded LAN is the store's real one, typed
  // from its router, and 039's CHECK has no value for it. Turning it into
  // 'manual' would claim a site variable that does not exist.
  const [{ n }] = (await knex(S).where({ lan_source: 'recorded' }).count('* as n')) as Array<{ n: string }>;
  if (Number(n) > 0) {
    throw new Error(
      `070 down refused: ${n} site allocation(s) hold a LAN recorded from the deployed store, which ` +
        'migration 039 cannot represent. Release those allocations first, or set their lan_subnet and ' +
        'lan_source to NULL by hand.',
    );
  }
  await replaceSourceCheck(knex, SOURCES_039);
}
