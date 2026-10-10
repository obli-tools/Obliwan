import type { Knex } from 'knex';

/**
 * 069 — the certificate a RouterOS API channel REFUSED, kept on the channel.
 *
 * Incident 2026-10-04: the shared CHR's api-ssl certificate was replaced, the
 * pool refused every session on the pin (as it must), the CHR went degraded,
 * every customer router behind it stopped being checked — and the only place
 * the new fingerprint existed was an error string. The operator re-pinned from
 * the browser console by retyping it.
 *
 * `tls_presented_sha256` is the fingerprint of the certificate the box
 * presented when a handshake was refused against the pin, and
 * `tls_presented_at` when ObliWAN first saw THAT certificate refused (a later
 * refusal of the same certificate does not move it, so it reads as "since").
 * Written by the pool's hook (fleet/tlsPresented.service.ts), cleared when a
 * handshake is accepted again or when an operator re-pins to it. The re-pin
 * endpoint accepts exactly this value and nothing typed: it is the server's
 * own record of what the box showed, never the caller's claim.
 *
 * No DEFAULT on either column, and they move together: a fingerprint without
 * its instant cannot say whether it is still news, and an instant without a
 * fingerprint records a refusal of nothing. The format CHECK is the 64
 * lowercase hex digits `connection.ts` computes — written as `{64}`, without a
 * `?` (knex rewrites a `?` in raw SQL as a binding).
 */
export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable('device_transports', (t) => {
    t.string('tls_presented_sha256', 64).nullable();
    t.timestamp('tls_presented_at', { useTz: true }).nullable();
  });
  await knex.raw(`
    ALTER TABLE device_transports ADD CONSTRAINT device_transports_tls_presented_chk
      CHECK ((tls_presented_sha256 IS NULL) = (tls_presented_at IS NULL))
  `);
  await knex.raw(`
    ALTER TABLE device_transports ADD CONSTRAINT device_transports_tls_presented_fmt_chk
      CHECK (tls_presented_sha256 IS NULL OR tls_presented_sha256 ~ '^[0-9a-f]{64}$')
  `);
}

export async function down(knex: Knex): Promise<void> {
  await knex.raw('ALTER TABLE device_transports DROP CONSTRAINT IF EXISTS device_transports_tls_presented_fmt_chk');
  await knex.raw('ALTER TABLE device_transports DROP CONSTRAINT IF EXISTS device_transports_tls_presented_chk');
  await knex.schema.alterTable('device_transports', (t) => {
    t.dropColumn('tls_presented_at');
    t.dropColumn('tls_presented_sha256');
  });
}
