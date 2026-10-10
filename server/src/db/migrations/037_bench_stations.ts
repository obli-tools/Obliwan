import type { Knex } from 'knex';

/**
 * ObliWAN — authorised bench WORKSTATIONS.
 *
 * ┌─ WHY A STATION IS A ROW AND NOT A SHARED SECRET ─────────────────────────┐
 * │ The bench enrolment route was anonymous by design and unreachable in     │
 * │ fact: it sat under `tenantRouter`, so every bench call died on a 401     │
 * │ before the anonymous middleware ever ran. Making it reachable AND        │
 * │ anonymous would have opened a third unauthenticated ingestion path to     │
 * │ the internet, on the route that phase B turns into "render a customer    │
 * │ config and create an L2TP account on the concentrator". So the route    │
 * │ now demands a workstation a human approved, ONE ROW PER MACHINE: a       │
 * │ leaked token is revoked for that bench alone, and nobody re-keys the     │
 * │ other preparation desks to recover from it.                              │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * `token_hash` is the sha256 hex of a token the WORKSTATION generated. The token
 * itself is never stored, never logged and never sent back. sha256 and not
 * bcrypt: the token carries at least 256 random bits, so there is no dictionary
 * for a slow hash to slow down — and a salted hash could not be looked up by an
 * index, which is the only way a request finds its station.
 *
 * `status` defaults to 'pending', and that default states no unverified fact: a
 * station that has just registered IS pending, by definition. What no default
 * may say is 'approved' — that word is a human's, and the CHECK below refuses
 * an `approved` row that carries no approval instant.
 *
 * `revoked_by` is not in the original spec and was added deliberately: who
 * revoked a bench is the first question after "why did the desk stop working",
 * and `approved_by` alone would record the opposite half of the story.
 *
 * `devices.enrolled_by_station_id` is a COLUMN, not a sentence in `notes`,
 * because `notes` is editable by any DEVICE_WRITE operator (updateDeviceSchema)
 * and provenance an operator can rewrite is not provenance. The question it
 * answers is the one a revocation raises — "this bench's token leaked: which
 * quarantined rows did it create?" — and that must be a query, not a grep over
 * free text. RESTRICT, not SET NULL: a station is revoked, never deleted, and a
 * delete that silently erased the provenance of every device it enrolled would
 * destroy exactly the evidence a revocation needs.
 *
 * No `?` anywhere in the raw SQL below: knex rewrites it as a binding
 * (see migration 032).
 */

const STATUSES = `'pending','approved','revoked'`;

export async function up(knex: Knex): Promise<void> {
  await knex.schema.createTable('bench_stations', (t) => {
    t.increments('id').primary();
    t.uuid('uuid').notNullable().defaultTo(knex.raw('gen_random_uuid()')).unique();
    // What the workstation CALLS itself. A declaration, shown to the approving
    // administrator next to `last_ip`; never an identity.
    t.string('name', 128).notNullable();
    t.string('hostname', 255).nullable();
    t.specificType('token_hash', 'char(64)').notNullable().unique();
    t.string('status', 16).notNullable().defaultTo('pending');
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.timestamp('approved_at', { useTz: true }).nullable();
    // SET NULL: deleting a user must not delete the benches they approved, and
    // `approved_at` keeps the fact that somebody did.
    t.integer('approved_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    t.timestamp('revoked_at', { useTz: true }).nullable();
    t.integer('revoked_by').nullable().references('id').inTable('users').onDelete('SET NULL');
    // Observations of the token holder calling. `registerStation` stamps them
    // first (registration is itself a call made with the token), then the
    // station guard refreshes them at most once a minute. So a row the API
    // created is never NULL here, and "registered but never used since" CANNOT
    // be read from this column: `last_seen_at` close to `created_at` is the
    // nearest reading, and it is approximate. Nullable only for a row written
    // some other way.
    t.timestamp('last_seen_at', { useTz: true }).nullable();
    t.specificType('last_ip', 'inet').nullable();

    t.index('status');
  });

  await knex.schema.raw(
    `ALTER TABLE bench_stations ADD CONSTRAINT bench_stations_status_chk ` +
      `CHECK (status IN (${STATUSES}))`,
  );
  // Lower-case hex, exactly 64. The service only ever writes `digest('hex')`,
  // so anything else here is a write that bypassed it.
  await knex.schema.raw(
    `ALTER TABLE bench_stations ADD CONSTRAINT bench_stations_token_hash_chk ` +
      `CHECK (token_hash ~ '^[0-9a-f]{64}$')`,
  );
  await knex.schema.raw(
    `ALTER TABLE bench_stations ADD CONSTRAINT bench_stations_name_chk ` +
      `CHECK (btrim(name) <> '')`,
  );
  // The status and its instants move together. A revoked station MAY carry an
  // approval instant — it was approved, then revoked, and both are history —
  // but an approved one may not carry a revocation, and a pending one carries
  // neither. Without this, "approved" could be a word with no moment behind it.
  await knex.schema.raw(
    `ALTER TABLE bench_stations ADD CONSTRAINT bench_stations_lifecycle_chk CHECK (` +
      `(status = 'pending' AND approved_at IS NULL AND revoked_at IS NULL)` +
      ` OR (status = 'approved' AND approved_at IS NOT NULL AND revoked_at IS NULL)` +
      ` OR (status = 'revoked' AND revoked_at IS NOT NULL))`,
  );

  await knex.schema.alterTable('devices', (t) => {
    t.integer('enrolled_by_station_id')
      .nullable()
      .references('id')
      .inTable('bench_stations')
      .onDelete('RESTRICT');
    t.index('enrolled_by_station_id');
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.alterTable('devices', (t) => {
    t.dropIndex('enrolled_by_station_id');
    t.dropForeign(['enrolled_by_station_id']);
    t.dropColumn('enrolled_by_station_id');
  });
  await knex.schema.dropTableIfExists('bench_stations');
}
