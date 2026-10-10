/**
 * ObliWAN — the certificate a RouterOS API channel refused: recorded, said
 * once, and forgotten when the pin matches again (migration 069).
 *
 * WHY. On 2026-10-04 the shared CHR's api-ssl certificate was replaced. The
 * pool refused every session on the pin — correctly: TLS pinning exists so an
 * unexplained certificate is never trusted — but the only trace of the new
 * fingerprint was an error string, the CHR went degraded, every customer router
 * behind it stopped being checked, and the operator re-pinned by retyping
 * the fingerprint into the browser console. So:
 *
 *  - every refused handshake of the POOL records, on the channel row, the
 *    fingerprint the box PRESENTED and when that certificate was first refused
 *    (`recordCertificateRefusal`, wired in `routerosPool.ts`);
 *  - ONE live alert says it, with both fingerprints, keyed on the device, the
 *    presented fingerprint and that first instant — deduplicated WHATEVER its
 *    read state, because the breaker re-dials every `authBackoffMs` and an
 *    operator who read the alert must not be told again every fifteen
 *    minutes (`concentratorSecret.service.ts` made the same choice);
 *  - an ACCEPTED handshake forgets the record and marks that alert read
 *    (`recordCertificateAccepted`) — the box presents the pinned certificate
 *    again, or the pin was moved to the one it presents;
 *  - so does an operator's transport write that changes what the record was
 *    about — the address, the port, TLS itself or the pin (`upsertTransport`,
 *    device.service.ts): a cleartext channel never handshakes again, so
 *    nothing else would ever forget it;
 *  - the permanent health check does not add its generic "not answering"
 *    alert on top of this one, but only when the check failed on that same
 *    refusal (`certificateRefusalAnnounced`): a record is a fact about a past
 *    handshake, never the reason for a later failure.
 *
 * The re-pin itself is `tlsRepin.service.ts`: it accepts exactly the value
 * recorded here, never one typed by a caller.
 *
 * Only the pool records: it is what the health check, presence and collectors
 * dial through, so a changed certificate is recorded within one check interval
 * whichever path met it first. The direct dials (the binding assertion, the
 * bench, the change jobs) still refuse as before and record nothing.
 *
 * What makes the alert repeat anyway: the tenant's newest-200 trim or the
 * 30-day cleanup dropping it while the refusal goes on, or the box presenting
 * a THIRD certificate (a new presented fingerprint is a new fact).
 *
 * Never throws: both entry points run from a pool hook, and a bookkeeping
 * failure must not become a session failure.
 */

import { TLS_SHA256_HEX_RE } from '@obliwan/shared';
import type { Knex } from 'knex';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { liveAlertService } from '../liveAlert.service';

const ROUTEROS = 'routeros_api';

/** `pg_advisory_xact_lock(TLS_PIN_LOCK_CLASS, device_id)`: serialises, per
 *  device, the record, its alert and the re-pin, across processes. */
export const TLS_PIN_LOCK_CLASS = 0x7470;

/** `tls-cert-changed:<deviceId>:<presented>:<first refused, epoch ms>`. */
export const CERT_ALERT_PREFIX = 'tls-cert-changed:';

/**
 * The pin as `connection.ts` compares it: colons and whitespace dropped, lower
 * case. The transport form accepts the `AA:BB:…` spelling, so the stored text
 * is not always the compared one — and a refusal reports the compared one.
 */
export function normalisePin(fp: string): string {
  return fp.replace(/[:\s]/g, '').toLowerCase();
}
/** `normalisePin`, in SQL, over the stored pin. No `?` in it: knex would read
 *  one as a binding. */
const PIN_SQL = "regexp_replace(lower(tls_fingerprint_sha256), '[:[:space:]]', '', 'g')";

export function certificateAlertKey(deviceId: number, presented: string, presentedAt: Date): string {
  return `${CERT_ALERT_PREFIX}${deviceId}:${presented}:${presentedAt.getTime()}`;
}

/** Every alert of this device, whatever the fingerprint — for settling them. */
function deviceAlertPattern(deviceId: number): string {
  return `${CERT_ALERT_PREFIX}${deviceId}:%`;
}

export async function lockDeviceTls(trx: Knex.Transaction, deviceId: number): Promise<void> {
  await trx.raw('SELECT pg_advisory_xact_lock(?, ?)', [TLS_PIN_LOCK_CLASS, deviceId]);
}

/** Mark this device's unread certificate alerts read. Matched on the key
 *  alone: the device id in it is global, and a device moved to another tenant
 *  since must not leave the old tenant's alert unread for ever. Whoever clears
 *  the record calls this in the same transaction: once the record is gone,
 *  nothing else ever settles those alerts. */
export async function settleCertificateAlerts(conn: Knex | Knex.Transaction, deviceId: number): Promise<number> {
  return conn('live_alerts')
    .where('stable_key', 'like', deviceAlertPattern(deviceId))
    .whereNull('read_at')
    .update({ read_at: conn.fn.now() });
}

function short(fp: string): string {
  return `${fp.slice(0, 16)}…`;
}

/**
 * A handshake was refused: the box presented `presented`, the pin was
 * `pinned`. Records it on the channel and raises the one alert of this
 * certificate. Never throws.
 */
export async function recordCertificateRefusal(
  deviceId: number,
  pinned: string,
  presented: string,
): Promise<void> {
  const seen = presented.toLowerCase();
  if (!TLS_SHA256_HEX_RE.test(seen)) {
    logger.warn({ deviceId }, 'TLS refusal not recorded: the presented fingerprint is not 64 hex digits');
    return;
  }
  try {
    await db.transaction(async (trx) => {
      await lockDeviceTls(trx, deviceId);
      // Against the pin the dial was judged on, and only that one: a re-pin
      // that landed while this dial was in flight makes the observation stale.
      // So does a switch to cleartext in that window, which `upsertTransport`
      // cleared the record for: a refusal never lands on a non-TLS channel.
      // The instant moves only when the presented certificate changes, so it
      // reads "refused since".
      await trx('device_transports')
        .where({ device_id: deviceId, transport: ROUTEROS, use_tls: true })
        .whereRaw(`${PIN_SQL} = ?`, [normalisePin(pinned)])
        .where((q) => q.whereNull('tls_presented_sha256').orWhereNot('tls_presented_sha256', seen))
        .update({ tls_presented_sha256: seen, tls_presented_at: trx.fn.now(), updated_at: trx.fn.now() });

      const row = (await trx('device_transports as t')
        .join('devices as d', 'd.id', 't.device_id')
        .where({ 't.device_id': deviceId, 't.transport': ROUTEROS })
        .first(
          't.tls_fingerprint_sha256 as pinned',
          't.tls_presented_sha256 as presented',
          't.tls_presented_at as presented_at',
          't.use_tls',
          'd.tenant_id',
          'd.name',
          'd.role',
        )) as
        | {
            pinned: string | null;
            presented: string | null;
            presented_at: Date | null;
            use_tls: boolean | null;
            tenant_id: number;
            name: string;
            role: string;
          }
        | undefined;
      if (!row || row.use_tls !== true) return;
      if (row.pinned === null || normalisePin(row.pinned) !== normalisePin(pinned)) return;
      if (row.presented !== seen || !row.presented_at) return;

      const stableKey = certificateAlertKey(deviceId, seen, row.presented_at);
      // Whatever its read state (see the header). The advisory lock above is
      // held until this transaction commits, and `liveAlertService.add`
      // commits its insert on its own connection before that: a concurrent
      // refusal of the same device waits, then finds it.
      const exists = await trx('live_alerts')
        .where({ tenant_id: row.tenant_id, stable_key: stableKey })
        .first('id');
      if (exists) return;

      let message =
        `${row.name} presented a TLS certificate other than the one pinned for its RouterOS API channel, `
        + 'so every session to it is refused before any login. '
        + `Pinned ${pinned}, presented ${seen} (first refused at ${row.presented_at.toISOString()}). `
        + 'If the certificate was legitimately replaced on the router, re-pin it from the device page '
        + '(Settings, channels: "Replace the fingerprint"); if nobody replaced it, treat it as a possible interception.';
      if (row.role === 'concentrator') {
        const [{ count }] = await trx('devices')
          .where({ concentrator_id: deviceId })
          .count<{ count: string }[]>('id as count');
        if (Number(count) > 0) {
          message += ` The ${Number(count)} device(s) behind it are not checked while its sessions are refused.`;
        }
      }
      await liveAlertService.add(row.tenant_id, {
        severity: 'down',
        title: `Certificate changed on ${row.name}: pinned ${short(pinned)}, presented ${short(seen)}`,
        message,
        navigateTo: `/devices/${deviceId}`,
        deviceId,
        stableKey,
      });
      logger.warn(
        { deviceId, pinned, presented: seen },
        'RouterOS TLS certificate refused against the pin: presented fingerprint recorded and announced',
      );
    });
  } catch (err) {
    logger.warn(
      { err: err instanceof Error ? err.message : String(err), deviceId },
      'Could not record a refused RouterOS TLS certificate',
    );
  }
}

/**
 * A handshake was accepted with `fingerprint`: whatever refusal is recorded is
 * over — the box presents the pinned certificate again, or there is no pin and
 * this one is being pinned on first use. Forgets the record and marks the
 * device's certificate alerts read. Never throws.
 */
export async function recordCertificateAccepted(deviceId: number, fingerprint: string): Promise<void> {
  try {
    await db.transaction(async (trx) => {
      await lockDeviceTls(trx, deviceId);
      const n = await trx('device_transports')
        .where({ device_id: deviceId, transport: ROUTEROS })
        .whereNotNull('tls_presented_sha256')
        .where((q) => q.whereRaw(`${PIN_SQL} = ?`, [normalisePin(fingerprint)]).orWhereNull('tls_fingerprint_sha256'))
        .update({ tls_presented_sha256: null, tls_presented_at: null, updated_at: trx.fn.now() });
      if (n === 0) return;
      await settleCertificateAlerts(trx, deviceId);
      logger.info({ deviceId, fingerprint }, 'RouterOS TLS certificate accepted again: refused-certificate record cleared');
    });
  } catch (err) {
    logger.warn(
      { err: err instanceof Error ? err.message : String(err), deviceId },
      'Could not clear a recorded RouterOS TLS refusal',
    );
  }
}

/**
 * True when the refusal a check just failed on — the box presented `presented`
 * and the pool refused it against the pin (`refusedCertificateOf`) — is the
 * one recorded on this device's enabled TLS API channel AND the alert saying
 * so exists (read or not). The health check then raises no generic "not
 * answering" alert for the outage: the certificate alert is the live record
 * of it, with the one fact that tells an operator what to do.
 *
 * The caller passes what THIS failure was, because a record outlives the
 * refusal it describes: disabling the channel keeps it, a switch to cleartext
 * written by anything but `upsertTransport` (the bench, a direct write) keeps
 * it, and so does a box that later dies of something else. A record alone
 * answering this question silenced the alert of such a later, unrelated
 * outage. False whenever that alert does not exist — a failed insert must
 * leave the generic alert in place rather than nothing.
 */
export async function certificateRefusalAnnounced(
  deviceId: number,
  tenantId: number,
  presented: string,
): Promise<boolean> {
  const row = (await db('device_transports')
    .where({
      device_id: deviceId,
      transport: ROUTEROS,
      use_tls: true,
      enabled: true,
      tls_presented_sha256: presented.toLowerCase(),
    })
    .first('tls_fingerprint_sha256', 'tls_presented_sha256', 'tls_presented_at')) as
    | { tls_fingerprint_sha256: string | null; tls_presented_sha256: string; tls_presented_at: Date }
    | undefined;
  if (!row) return false;
  if (row.tls_fingerprint_sha256 !== null && normalisePin(row.tls_fingerprint_sha256) === row.tls_presented_sha256) return false;
  const key = certificateAlertKey(deviceId, row.tls_presented_sha256, row.tls_presented_at);
  return (await db('live_alerts').where({ tenant_id: tenantId, stable_key: key }).first('id')) !== undefined;
}
