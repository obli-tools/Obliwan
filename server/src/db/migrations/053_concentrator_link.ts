import type { Knex } from 'knex';

/**
 * 053_concentrator_link.ts — the WireGuard link between the ObliWAN host and a
 * concentrator (the CHR), so the host can reach 100.64.0.0/10, where every
 * customer router's L2TP tunnel address lives. The CHR half is a change job,
 * through the queue like every other write; the service is
 * services/concentratorLink/link.service.ts and the job's phases are a branch
 * of `runPhases()` in apply.service.ts. The host half is the `obliwan-wg`
 * sidecar (src/wgSidecar.ts) and has no table: its state is a file on a volume.
 *
 *  1. `change_jobs.kind` gains `concentrator_link` (17 characters: the column
 *     is varchar(24) since 040, no widening needed).
 *
 *  2. 009's write-kind CHECKs (as 040 and 047 left them), one by one:
 *       - `change_jobs_guard_required_chk`   WIDENED. The job always carries a
 *         verdict, its own, written at enqueue (ACCEPT: every write is an
 *         addition, and none touches the public-address path ObliWAN manages
 *         the CHR through).
 *       - `change_jobs_degraded_confirm_chk` WIDENED. The job arms no dead-man,
 *         so it is queued at `degraded`, which is the truth about its net, and
 *         the request that queues it carries the operator's explicit
 *         confirmation: the CHR is shared by every site.
 *       - `change_jobs_preflight_backup_chk` NOT widened. A re-run that finds
 *         every item already present writes nothing and takes no backup (the
 *         state machine has no edge that skips the statuses this CHECK
 *         guards). The rule is restated where it is exact:
 *         `concentrator_link_jobs_backup_before_write_chk` — no write recorded
 *         without a backup id beside it.
 *     `apply_outcomes.op_kind` is NOT widened: that corpus records changes made
 *     under a net on customer equipment, and this job writes no row to it.
 *
 *     HOW THEY ARE WIDENED, AND WHY NOT WITH INLINED LITERALS like 040/047.
 *     Other features add job kinds in migrations numbered below this one
 *     that were not on disk when it was written; a literal list here would
 *     silently DROP their kind from the CHECK on the day both are deployed. So
 *     each constraint is read back (`pg_get_constraintdef`), this one kind is
 *     inserted into its single kind list, and the constraint is recreated from
 *     that text. A definition with no kind list, or with more than one, makes
 *     the migration THROW rather than guess. `down()` removes exactly this
 *     kind and nothing else.
 *
 *  3. The subtree interlock (010, replaced by 040) is NOT touched. This
 *     job is an ordinary concentrator job for it: it cannot be queued while a
 *     job is in flight on a device behind this CHR, and none can be queued
 *     while it runs. Nothing it adds should drop a tunnel, but the exemption
 *     040 grants `concentrator_secret` was argued for one /ppp/secret entry,
 *     and this job adds firewall rules on the box that carries every site.
 *
 *  4. `concentrator_links` — one row per concentrator: the transit, ObliWAN's
 *     key pair (the PRIVATE key as vault ciphertext, secretVault.service.ts —
 *     never in a job row), what the CHR answered (its public key), the public
 *     endpoint the host dials, and whether the CHR's own RouterOS API transport
 *     was moved into the tunnel (with the public address kept to go back to:
 *     `device_transports` is UNIQUE(device_id, transport) since 002, so the
 *     fallback cannot be a second, disabled routeros_api row).
 *
 *  5. `concentrator_link_jobs` — one row per job: the spec frozen at enqueue
 *     (never a private key), the backup it took, when it first wrote, and what
 *     it found.
 *
 *  6. ONE BOUND LINK PER INSTALLATION (`concentrator_links_one_bound_uq`). The
 *     host half is ONE interface (`wg-obliwan`), ONE config file and ONE peer
 *     whose AllowedIPs is the whole of 100.64.0.0/10: it can follow one CHR,
 *     not two. A link is "bound" from the first write on its CHR
 *     (`first_write_at`) or its provisioning (`provisioned_at`), and at most
 *     one row may be. link.service.ts refuses a second one by name before any
 *     job is queued; this index is the backstop for a race between two
 *     requests, and it fires before the second job's first add.
 *
 *  7. THE TRANSIT IS RESERVED BOTH WAYS. link.service.ts refuses a transit
 *     that overlaps an address pool, at enqueue and again at lint. Nothing on
 *     the allocation side read `concentrator_links`, so a pool created LATER
 *     over the transit would let the allocator hand .1 or .2 of it to a site.
 *       - `address_pools_link_transit_guard` (BEFORE INSERT OR UPDATE OF cidr
 *         on address_pools) refuses a pool, of any purpose, overlapping a
 *         link's transit: SQLSTATE 23514, constraint name
 *         `concentrator_link_transit_reserved`. Every tunnel address the
 *         allocator COMPUTES lies inside a pool (allocation/policy.ts: a
 *         formula result outside it is refused), so no computed allocation
 *         can reach the transit once no pool covers it. An ADOPTED site takes
 *         what the CHR's own /ppp/secret already declares; that is an
 *         observation, covered by the next paragraph.
 *       - `concentrator_links_transit_guard` (BEFORE INSERT OR UPDATE OF
 *         transit on concentrator_links) refuses the reverse, with the same
 *         name, after taking the ALLOCATION advisory lock (36036, 0 —
 *         services/allocation/lock.ts). createPool holds that lock for its
 *         whole transaction, so the two checks cannot pass each other: whichever
 *         commits second sees the first. The pool-side trigger takes no lock;
 *         it runs inside createPool's transaction, which already holds it.
 *     Neither trigger judges `site_provisioning` (a computed address is inside
 *     a pool, an adopted one is observed) or the other observed rows
 *     (`ppp_sessions`, `devices.tunnel_ip`, `concentrator_ppp_secrets`): those
 *     record what a CHR already carries, and refusing to record a fact does
 *     not change it. link.service.ts (`transitCollisions`) checks all of them
 *     at enqueue and again at lint.
 *
 * No `?` anywhere in the SQL below: knex rewrites it inside raw() as a binding
 * placeholder (see migration 032). The constraint text read back is
 * checked for one before it is executed.
 */

const KIND = 'concentrator_link';
/** The change_jobs CHECKs this kind joins (header, 2). */
const WIDENED = [
  'change_jobs_kind_chk',
  'change_jobs_guard_required_chk',
  'change_jobs_degraded_confirm_chk',
] as const;
/** `CONCENTRATOR_LINK_OUTCOMES` in link.service.ts. */
const OUTCOMES = "'added','present','conflict'";

/** The one kind list of a change_jobs CHECK, as PostgreSQL prints it back:
 *  `(kind)::text = ANY ((ARRAY['push'::character varying, ...])::text[])` for
 *  a constraint written `kind IN (...)` (`<> ALL` for NOT IN), and
 *  `(kind)::text = ANY (ARRAY[('push'::character varying)::text, ...])` for one
 *  re-created from that printed text — PostgreSQL 16 normalises the two
 *  spellings differently, so both are read. */
const KIND_LIST_RE = /\(kind\)::text (= ANY|<> ALL) \(\(?ARRAY\[/g;
/** The list's first element exactly as printed: `'push'::character varying`
 *  or `('push'::character varying)::text`. */
const FIRST_ELEMENT_RE = /ARRAY\[(\('[a-z_]+'::[a-z ]+\)::[a-z ]+|'[a-z_]+'::[a-z ]+)[,\]]/;

async function readConstraint(knex: Knex, name: string): Promise<string> {
  const row = (await knex('pg_constraint as c')
    .join('pg_class as t', 't.oid', 'c.conrelid')
    .where('t.relname', 'change_jobs')
    .where('c.conname', name)
    .first(knex.raw('pg_get_constraintdef(c.oid) AS def'))) as { def: string } | undefined;
  if (!row) throw new Error(`053: change_jobs has no constraint ${name}`);
  return row.def;
}

/** This kind, spelled like the list's first element. */
function element(def: string): string {
  const first = FIRST_ELEMENT_RE.exec(def);
  if (!first) throw new Error(`053: cannot tell how the kind list is spelled in: ${def}`);
  return first[1].replace(/'[a-z_]+'/, `'${KIND}'`);
}

export function widenKindList(def: string): string {
  const el = element(def);
  if (def.includes(`'${KIND}'::`)) return def;
  let lists = 0;
  const out = def.replace(KIND_LIST_RE, (m) => {
    lists++;
    return `${m}${el}, `;
  });
  if (lists !== 1) throw new Error(`053: expected exactly one kind list, found ${lists}, in: ${def}`);
  return out;
}

export function narrowKindList(def: string): string {
  if (!def.includes(`'${KIND}'::`)) return def;
  return def.split(`${element(def)}, `).join('').split(`, ${element(def)}`).join('');
}

async function rewrite(knex: Knex, name: string, transform: (def: string) => string): Promise<void> {
  const before = await readConstraint(knex, name);
  const after = transform(before);
  if (after === before) return;
  // The trap this migration's header names: never hand knex a `?`.
  if (after.includes('?')) throw new Error(`053: refusing to execute a constraint containing '?': ${after}`);
  await knex.schema.raw(`ALTER TABLE change_jobs DROP CONSTRAINT ${name}`);
  await knex.schema.raw(`ALTER TABLE change_jobs ADD CONSTRAINT ${name} ${after}`);
}

export async function up(knex: Knex): Promise<void> {
  // ── 1 + 2. The kind, in the three CHECKs (header, 1-2) ───────────────────
  for (const name of WIDENED) await rewrite(knex, name, widenKindList);

  // ── 4. concentrator_links ────────────────────────────────────────────────
  await knex.schema.createTable('concentrator_links', (t) => {
    t.integer('concentrator_id').primary().references('id').inTable('devices').onDelete('CASCADE');
    // The CHR's tenant (the master tenant for a shared CHR).
    t.integer('tenant_id').notNullable();
    t.specificType('transit', 'cidr').notNullable();
    t.specificType('chr_address', 'inet').notNullable();
    t.specificType('host_address', 'inet').notNullable();
    t.integer('listen_port').notNullable();
    // ObliWAN's key pair. The public half goes to the CHR (a peer); the
    // private half is vault ciphertext and leaves the database only into the
    // 0600 config file the sidecar reads.
    t.string('host_public_key', 44).notNullable();
    t.text('host_private_key_enc').notNullable();
    t.integer('key_version').notNullable();
    // What the CHR answered. NULL until a job has read it back.
    t.string('chr_public_key', 44).nullable();
    // The CHR's PUBLIC address (or name), as its routeros_api transport said
    // at enqueue: where the host's WireGuard dials. Frozen once the API itself
    // moves into the tunnel, because the transport then says the tunnel side.
    t.string('endpoint_host', 255).nullable();
    // Set the first time a job writes on the CHR: from then on the transit and
    // the port are what the CHR carries, and a different one is refused.
    t.timestamp('first_write_at', { useTz: true }).nullable();
    t.bigInteger('provisioned_job_id').nullable().references('id').inTable('change_jobs').onDelete('SET NULL');
    t.timestamp('provisioned_at', { useTz: true }).nullable();
    // The second, separate gesture: the CHR's routeros_api transport host was
    // switched to chr_address. The public coordinates are kept to go back.
    t.timestamp('api_via_tunnel_at', { useTz: true }).nullable();
    t.string('api_public_host', 255).nullable();
    t.integer('api_public_port').nullable();
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });
  const linkChecks: Array<[string, string]> = [
    ['transit_chk', "family(transit) = 4 AND masklen(transit) = 30 AND transit <<= '100.64.0.0/10'::cidr"],
    ['chr_address_chk', 'masklen(chr_address) = 32 AND chr_address << transit'],
    ['host_address_chk', 'masklen(host_address) = 32 AND host_address << transit AND host_address <> chr_address'],
    ['listen_port_chk', 'listen_port BETWEEN 1024 AND 65535'],
    ['keys_chk',
      "length(host_public_key) = 44 AND host_private_key_enc <> '' AND key_version >= 1 AND " +
      '(chr_public_key IS NULL OR length(chr_public_key) = 44)'],
    // "Provisioned" is said by the job that read the CHR's key back.
    ['provisioned_chk', '(provisioned_at IS NULL) = (chr_public_key IS NULL)'],
    ['api_tunnel_chk',
      'api_via_tunnel_at IS NULL OR (provisioned_at IS NOT NULL AND api_public_host IS NOT NULL ' +
      'AND api_public_port IS NOT NULL AND endpoint_host IS NOT NULL)'],
    ['api_public_port_chk', 'api_public_port IS NULL OR api_public_port BETWEEN 1 AND 65535'],
  ];
  for (const [name, expr] of linkChecks) {
    await knex.schema.raw(`ALTER TABLE concentrator_links ADD CONSTRAINT concentrator_links_${name} CHECK (${expr})`);
  }
  // Two concentrators never share a transit (built-in GiST inet_ops).
  await knex.schema.raw(
    'ALTER TABLE concentrator_links ADD CONSTRAINT concentrator_links_transit_excl ' +
      'EXCLUDE USING gist (transit inet_ops WITH &&)',
  );

  // ── 5. concentrator_link_jobs ────────────────────────────────────────────
  await knex.schema.createTable('concentrator_link_jobs', (t) => {
    t.bigInteger('job_id').primary().references('id').inTable('change_jobs').onDelete('CASCADE');
    t.integer('concentrator_id').notNullable().references('id').inTable('devices').onDelete('CASCADE');
    t.integer('tenant_id').notNullable();
    // Frozen at enqueue; the worker refuses when the link row says otherwise.
    t.specificType('transit', 'cidr').notNullable();
    t.specificType('chr_address', 'inet').notNullable();
    t.specificType('host_address', 'inet').notNullable();
    t.integer('listen_port').notNullable();
    t.string('host_public_key', 44).notNullable();
    // The pre-change backup rule, restated (header, 2).
    t.bigInteger('backup_id').nullable().references('id').inTable('device_backups');
    t.timestamp('wrote_at', { useTz: true }).nullable();
    // What the job found. NULL until it has looked: no DEFAULT.
    t.string('outcome', 16).nullable();
    t.text('outcome_detail').nullable();
    // Per item: what was found or added. Never a key other than a PUBLIC one.
    t.jsonb('items').nullable();
    t.string('chr_public_key', 44).nullable();
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });
  const jobChecks: Array<[string, string]> = [
    ['outcome_chk', `outcome IS NULL OR outcome IN (${OUTCOMES})`],
    ['detail_chk', '(outcome IS NULL) = (outcome_detail IS NULL)'],
    ['backup_before_write_chk', 'wrote_at IS NULL OR backup_id IS NOT NULL'],
    ['added_wrote_chk', "outcome IS DISTINCT FROM 'added' OR wrote_at IS NOT NULL"],
    ['transit_chk', "family(transit) = 4 AND masklen(transit) = 30 AND transit <<= '100.64.0.0/10'::cidr"],
    ['listen_port_chk', 'listen_port BETWEEN 1024 AND 65535'],
    ['key_chk', 'length(host_public_key) = 44 AND (chr_public_key IS NULL OR length(chr_public_key) = 44)'],
  ];
  for (const [name, expr] of jobChecks) {
    await knex.schema.raw(
      `ALTER TABLE concentrator_link_jobs ADD CONSTRAINT concentrator_link_jobs_${name} CHECK (${expr})`,
    );
  }
  await knex.schema.raw(
    'CREATE INDEX concentrator_link_jobs_concentrator_idx ON concentrator_link_jobs (concentrator_id, job_id DESC)',
  );

  // ── 6. One bound link (header, 6) ────────────────────────────────────────
  await knex.schema.raw(
    'CREATE UNIQUE INDEX concentrator_links_one_bound_uq ON concentrator_links ((true)) ' +
      'WHERE provisioned_at IS NOT NULL OR first_write_at IS NOT NULL',
  );

  // ── 7. The transit, reserved both ways (header, 7) ───────────────────────
  // `%` is RAISE's placeholder; there is no `?` in either body.
  await knex.schema.raw(`
    CREATE FUNCTION address_pools_link_transit_guard() RETURNS trigger
    LANGUAGE plpgsql AS $fn$
    DECLARE
      hit record;
    BEGIN
      SELECT l.concentrator_id, l.transit INTO hit
        FROM concentrator_links l
       WHERE l.transit && NEW.cidr
       LIMIT 1;
      IF FOUND THEN
        RAISE EXCEPTION 'address pool % overlaps %, the WireGuard transit of the ObliWAN link to concentrator %',
            NEW.cidr, hit.transit, hit.concentrator_id
          USING ERRCODE = 'check_violation',
                CONSTRAINT = 'concentrator_link_transit_reserved',
                HINT = 'The transit is reserved for the ObliWAN link: choose a block outside it.';
      END IF;
      RETURN NEW;
    END
    $fn$
  `);
  await knex.schema.raw(
    'CREATE TRIGGER address_pools_link_transit_guard BEFORE INSERT OR UPDATE OF cidr ON address_pools ' +
      'FOR EACH ROW EXECUTE FUNCTION address_pools_link_transit_guard()',
  );
  await knex.schema.raw(`
    CREATE FUNCTION concentrator_links_transit_guard() RETURNS trigger
    LANGUAGE plpgsql AS $fn$
    DECLARE
      hit record;
    BEGIN
      -- The allocation lock (services/allocation/lock.ts): createPool holds it
      -- for its whole transaction, so this read and its check are serialised.
      PERFORM pg_advisory_xact_lock(36036, 0);
      SELECT p.name, p.cidr INTO hit
        FROM address_pools p
       WHERE p.cidr && NEW.transit
       LIMIT 1;
      IF FOUND THEN
        RAISE EXCEPTION 'the transit % overlaps address pool "%" (%)', NEW.transit, hit.name, hit.cidr
          USING ERRCODE = 'check_violation',
                CONSTRAINT = 'concentrator_link_transit_reserved',
                HINT = 'Choose a /30 inside 100.64.0.0/10 that no pool covers.';
      END IF;
      RETURN NEW;
    END
    $fn$
  `);
  await knex.schema.raw(
    'CREATE TRIGGER concentrator_links_transit_guard BEFORE INSERT OR UPDATE OF transit ON concentrator_links ' +
      'FOR EACH ROW EXECUTE FUNCTION concentrator_links_transit_guard()',
  );
}

export async function down(knex: Knex): Promise<void> {
  // The pool-side guard reads concentrator_links: it goes first. The link-side
  // trigger goes with its table, its function after it.
  await knex.schema.raw('DROP TRIGGER IF EXISTS address_pools_link_transit_guard ON address_pools');
  await knex.schema.raw('DROP FUNCTION IF EXISTS address_pools_link_transit_guard()');
  await knex.schema.dropTableIfExists('concentrator_link_jobs');
  await knex.schema.dropTableIfExists('concentrator_links');
  await knex.schema.raw('DROP FUNCTION IF EXISTS concentrator_links_transit_guard()');
  // A row of this kind cannot be relabelled as another kind without lying
  // about what was done, so the rows go (their steps cascade). The commands
  // stay in `command_audit`, which has no foreign key and is append-only.
  await knex('change_jobs').where({ kind: KIND }).del();
  for (const name of [...WIDENED].reverse()) await rewrite(knex, name, narrowKindList);
}
