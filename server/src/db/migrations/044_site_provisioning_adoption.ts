import type { Knex } from 'knex';

/**
 * 044 — ADOPTION: a site already deployed on its concentrator is recorded as it
 * is, not refused (services/allocation/policy.ts, `adoptDeclared`).
 *
 * A store numbered by hand years ago has its L2TP account live on the CHR. When
 * the login the tenant's policy computes for that site is a secret the policy's
 * own CHR already declares, the allocator now ADOPTS it: the allocation takes
 * the CHR's spelling of the login, the secret's remote-address as the tunnel
 * address and its profile, and writes nothing to the CHR. Two columns on
 * `site_provisioning` say so, and one CHECK is widened.
 *
 *  - `source`            'allocated'   login and address computed from the policy;
 *                        'adopted_chr' read from a secret the CHR declared.
 *                        NULL on every row written before this migration, and
 *                        no DEFAULT: those rows were written by the allocator
 *                        (its only writer) or by hand, and a DEFAULT would state
 *                        a provenance nobody verified. The allocator writes one
 *                        of the two values on every new row.
 *  - `formula_tunnel_ip` an ADOPTED row only: the address the tenant's tunnel
 *                        formula rendered at adoption, when it differs from the
 *                        address the CHR declares (the one recorded in
 *                        `tunnel_ip`). Kept so the difference stays visible on
 *                        the allocations screen after the adoption result is
 *                        gone — a site import, for one, shows no warnings.
 *                        NULL otherwise. It holds nothing: no index, no UNIQUE.
 *
 * `password_presence_chk` (039) said "per_site ⇔ a vaulted password". An
 * adopted site in 'per_site' mode has NO password ObliWAN knows: the CHR's is
 * never read, and inventing one would compile a CPE that cannot
 * authenticate. The CHECK becomes "a vaulted password ⇔ per_site AND not
 * adopted", so such a row stores none, and `computedForSite` refuses the
 * compile for it (PASSWORD_UNKNOWN). Every row 039 admitted still passes: its
 * `source` is NULL, i.e. not 'adopted_chr'.
 *
 * Literals only in the SQL below: knex rewrites a `?` inside raw() as a
 * binding placeholder (a known trap).
 */

const S = 'site_provisioning';
const SOURCES = "'allocated','adopted_chr'";

async function addCheck(knex: Knex, name: string, expr: string): Promise<void> {
  await knex.schema.raw(`ALTER TABLE ${S} ADD CONSTRAINT ${S}_${name} CHECK (${expr})`);
}

async function dropCheck(knex: Knex, name: string): Promise<void> {
  await knex.schema.raw(`ALTER TABLE ${S} DROP CONSTRAINT IF EXISTS ${S}_${name}`);
}

export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable(S, (t) => {
    t.string('source', 16).nullable();
    t.specificType('formula_tunnel_ip', 'inet').nullable();
  });
  await addCheck(knex, 'source_chk', `source IS NULL OR source IN (${SOURCES})`);
  await addCheck(
    knex,
    'formula_tunnel_ip_chk',
    'formula_tunnel_ip IS NULL OR (' +
      `source = 'adopted_chr' AND family(formula_tunnel_ip) = 4 AND masklen(formula_tunnel_ip) = 32 ` +
      'AND formula_tunnel_ip <> tunnel_ip)',
  );
  await dropCheck(knex, 'password_presence_chk');
  await addCheck(
    knex,
    'password_presence_chk',
    `((ppp_password_mode = 'per_site' AND source IS DISTINCT FROM 'adopted_chr') = (ppp_password_enc IS NOT NULL)) ` +
      'AND ((ppp_password_enc IS NULL) = (ppp_password_key_version IS NULL))',
  );
}

export async function down(knex: Knex): Promise<void> {
  // Refuse rather than destroy: 039's CHECK cannot hold a 'per_site' row
  // without a password, and such a row may describe an account live on a CHR.
  const [{ n }] = (await knex(S)
    .where({ source: 'adopted_chr', ppp_password_mode: 'per_site' })
    .count('* as n')) as Array<{ n: string }>;
  if (Number(n) > 0) {
    throw new Error(
      `044 down refused: ${n} site allocation(s) were adopted from a concentrator in 'per_site' ` +
        'password mode and hold no password, which migration 039 cannot represent. Release those ' +
        'allocations first.',
    );
  }
  await dropCheck(knex, 'password_presence_chk');
  await addCheck(
    knex,
    'password_presence_chk',
    `(ppp_password_mode = 'per_site') = (ppp_password_enc IS NOT NULL) AND ` +
      '(ppp_password_enc IS NULL) = (ppp_password_key_version IS NULL)',
  );
  await dropCheck(knex, 'formula_tunnel_ip_chk');
  await dropCheck(knex, 'source_chk');
  await knex.schema.alterTable(S, (t) => {
    t.dropColumn('formula_tunnel_ip');
    t.dropColumn('source');
  });
}
