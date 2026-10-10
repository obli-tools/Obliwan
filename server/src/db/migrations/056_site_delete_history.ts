import type { Knex } from 'knex';

/**
 * 056 — a site's bench history outlives the site (readiness backlog #22).
 *
 * 042 tied `bench_provisionings` to its site with ON DELETE CASCADE, so
 * deleting a site erased, without a word, the record of which file went onto
 * which box from which workstation — the very history 042's header says the
 * table exists to keep. From here:
 *
 *  - the composite FK (site_id, tenant_id) becomes ON DELETE SET NULL
 *    (site_id): only the site column is cleared. A plain SET NULL would null
 *    `tenant_id` too, which is NOT NULL, and every site delete would fail. The
 *    column list needs PostgreSQL 15 or later; the stack is 16;
 *  - `site_code` / `site_name`: the site's code and name as they were when the
 *    link was cut, written by a BEFORE DELETE trigger on `sites` — so whichever
 *    path deletes the site (site.service `deleteSite`, a bundle import, a
 *    statement typed by hand), the row keeps saying whose it was. Both stay
 *    NULL while the row has its site: the live values are one join away, and a
 *    copy kept beside them would be free to disagree;
 *  - a CHECK: a row has its site, or the copy of it. Never neither.
 *
 * Refusing the delete in the first place — an account live on the
 * concentrator, or bench history, that the caller did not acknowledge by name
 * — is the service's, not the schema's (services/fleet/site.service.ts).
 *
 * No `?` anywhere in the raw SQL below: knex would rewrite it as a binding
 * (a known trap).
 *
 * down() REFUSES while any row has lost its site: 042's NOT NULL cannot hold
 * it, and deleting history to make room for a rollback is exactly what this
 * migration exists to stop.
 */

const T = 'bench_provisionings';
const FK = 'bench_provisionings_site_fk';
const COPY_CHK = 'bench_provisionings_site_copy_chk';
const FN = 'bench_provisionings_keep_site';
const TRIGGER = 'sites_keep_bench_history';

export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable(T, (t) => {
    // Same widths as sites.code / sites.name (migration 002).
    t.string('site_code', 64).nullable();
    t.string('site_name', 255).nullable();
  });

  await knex.schema.raw(`ALTER TABLE ${T} DROP CONSTRAINT ${FK}`);
  await knex.schema.raw(`ALTER TABLE ${T} ALTER COLUMN site_id DROP NOT NULL`);
  await knex.schema.raw(
    `ALTER TABLE ${T} ADD CONSTRAINT ${FK} ` +
      'FOREIGN KEY (site_id, tenant_id) REFERENCES sites (id, tenant_id) ON DELETE SET NULL (site_id)',
  );

  // Runs BEFORE the site row goes, i.e. before the FK's SET NULL (an AFTER
  // action of the same delete): the copy is always in place by the time the
  // link is cleared, which is what lets the CHECK below hold on every path.
  await knex.schema.raw(
    `CREATE FUNCTION ${FN}() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
  UPDATE ${T}
     SET site_code = OLD.code, site_name = OLD.name
   WHERE site_id = OLD.id AND tenant_id = OLD.tenant_id;
  RETURN OLD;
END;
$fn$`,
  );
  await knex.schema.raw(
    `CREATE TRIGGER ${TRIGGER} BEFORE DELETE ON sites FOR EACH ROW EXECUTE FUNCTION ${FN}()`,
  );

  await knex.schema.raw(
    `ALTER TABLE ${T} ADD CONSTRAINT ${COPY_CHK} ` +
      'CHECK (site_id IS NOT NULL OR (site_code IS NOT NULL AND site_name IS NOT NULL))',
  );
}

export async function down(knex: Knex): Promise<void> {
  const [{ n }] = (await knex(T).whereNull('site_id').count('* as n')) as Array<{ n: string | number }>;
  if (Number(n) > 0) {
    throw new Error(
      `056 down refused: ${n} bench provisioning row(s) outlived their site, and 042's NOT NULL ` +
        'site_id cannot hold them. They are the bench history of deleted sites; decide what to do ' +
        'with them (export, then delete by hand) before rolling this migration back.',
    );
  }
  await knex.schema.raw(`ALTER TABLE ${T} DROP CONSTRAINT IF EXISTS ${COPY_CHK}`);
  await knex.schema.raw(`DROP TRIGGER IF EXISTS ${TRIGGER} ON sites`);
  await knex.schema.raw(`DROP FUNCTION IF EXISTS ${FN}()`);
  await knex.schema.raw(`ALTER TABLE ${T} DROP CONSTRAINT ${FK}`);
  await knex.schema.raw(`ALTER TABLE ${T} ALTER COLUMN site_id SET NOT NULL`);
  await knex.schema.raw(
    `ALTER TABLE ${T} ADD CONSTRAINT ${FK} ` +
      'FOREIGN KEY (site_id, tenant_id) REFERENCES sites (id, tenant_id) ON DELETE CASCADE',
  );
  await knex.schema.alterTable(T, (t) => {
    t.dropColumn('site_name');
    t.dropColumn('site_code');
  });
}
