import type { Knex } from 'knex';

/**
 * 064 — api-ssl as ObliWAN last READ it on the router, without a job.
 *
 * The management-access card's "API-SSL on the router" used to come only from
 * a management_access job's read-back, which only a human queues: a router
 * ObliWAN talked to every minute still said "never read by ObliWAN". The
 * health check now reads `/ip/service` api-ssl on the session it already
 * holds (fleet/healthCheck.service.ts, observeApiSsl) and the bench check
 * records the row it reads; both land here.
 *
 * No DEFAULT on either column, and the two move together: a reading without
 * its instant cannot be compared with a job's, and an instant without a
 * reading claims a read that stored nothing.
 */
export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable('devices', (t) => {
    t.jsonb('api_ssl_observed').nullable();
    t.timestamp('api_ssl_observed_at', { useTz: true }).nullable();
  });
  await knex.raw(`
    ALTER TABLE devices ADD CONSTRAINT devices_api_ssl_observed_chk
      CHECK ((api_ssl_observed IS NULL) = (api_ssl_observed_at IS NULL))
  `);
}

export async function down(knex: Knex): Promise<void> {
  await knex.raw('ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_api_ssl_observed_chk');
  await knex.schema.alterTable('devices', (t) => {
    t.dropColumn('api_ssl_observed_at');
    t.dropColumn('api_ssl_observed');
  });
}
