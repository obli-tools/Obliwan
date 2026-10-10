import type { Knex } from 'knex';

/**
 * 073 — the ACTIVE default route, as the router's own routing table selects it.
 *
 * ┌─ WHY THE CONFIGURATION COULD NOT SAY IT ─────────────────────────────────┐
 * │ The uplink card's "routing says" came only from the latest config        │
 * │ snapshot, and only from a default route whose gateway names an          │
 * │ INTERFACE. On this fleet neither holds: WAN1's default route carries an  │
 * │ IP gateway (the DHCP client's script writes it), and the LTE default     │
 * │ route is DYNAMIC — it is not in an export at all. So the card was empty  │
 * │ on every router, snapshot or not.                                        │
 * │                                                                          │
 * │ The health check now reads `/ip/route` on the API session it already     │
 * │ holds (fleet/healthCheck.service.ts, observeDefaultRoute): the default   │
 * │ route(s) of the main table that RouterOS marks ACTIVE, and the interface │
 * │ the next hop resolves through (`immediate-gw` on RouterOS 7,             │
 * │ `gateway-status` on RouterOS 6). That is a FACT about the routing table  │
 * │ at a given instant, not intent: after a failover it names the backup.    │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THREE STATES, AND THE SCHEMA KEEPS THEM APART ──────────────────────────┐
 * │  · `default_route_observed_at IS NULL` — never read. Every device starts │
 * │    here, and so does every device without a RouterOS API channel.       │
 * │  · `observed_at` set, `gateway` NULL — read, and the main table had NO   │
 * │    active default route. That is a finding, not an absence of one.       │
 * │  · `gateway` set, `iface` NULL — an active default route exists and its  │
 * │    outgoing interface could not be told (an IP next hop printed without  │
 * │    its interface, or several interfaces at once). Unknown stays unknown: │
 * │    nothing guesses an interface from an address.                         │
 * │                                                                          │
 * │ No DEFAULT on any column, and a value is never stored without the time   │
 * │ it was read: a route with no reading time would be shown as current      │
 * │ forever, and a failover is exactly the moment it stops being so.         │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable('devices', (t) => {
    t.text('default_route_iface').nullable();
    t.text('default_route_gateway').nullable();
    t.timestamp('default_route_observed_at', { useTz: true }).nullable();
  });
  // No `?` anywhere in this statement: knex would rewrite it as a positional
  // binding inside raw() (the trap that cost migration 032 a whole sweep).
  await knex.schema.raw(
    'ALTER TABLE devices ADD CONSTRAINT devices_default_route_observed_chk CHECK (' +
      'default_route_observed_at IS NOT NULL OR (' +
      'default_route_iface IS NULL AND default_route_gateway IS NULL))',
  );
  // An interface is only ever named THROUGH a route: an iface without a
  // gateway would claim a route the reading never saw.
  await knex.schema.raw(
    'ALTER TABLE devices ADD CONSTRAINT devices_default_route_iface_chk CHECK (' +
      'default_route_iface IS NULL OR default_route_gateway IS NOT NULL)',
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.raw('ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_default_route_iface_chk');
  await knex.schema.raw('ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_default_route_observed_chk');
  await knex.schema.alterTable('devices', (t) => {
    t.dropColumn('default_route_observed_at');
    t.dropColumn('default_route_gateway');
    t.dropColumn('default_route_iface');
  });
}
