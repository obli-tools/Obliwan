/**
 * ObliWAN — re-pinning a RouterOS API channel to the certificate the box
 * PRESENTED, from the device page (`POST /devices/:id/transports/routeros_api/repin`).
 *
 * The pin exists so that a certificate nobody vouched for is refused. A
 * re-pin is therefore a human vouching for one, and this module keeps that
 * gesture as narrow as it can be:
 *
 *  - the only fingerprint it will pin is the one the SERVER recorded when the
 *    pool refused the handshake (`device_transports.tls_presented_sha256`,
 *    tlsPresented.service.ts). The request names it, and a value that differs
 *    is refused, never stored: no caller can make ObliWAN trust a certificate
 *    the box did not actually present to ObliWAN;
 *  - the request also names the pin the operator was SHOWN, and a pin that
 *    moved since is refused rather than overwritten — the confirmation the
 *    operator read named both;
 *  - a concentrator is shared by every workspace (the master tenant's CHR
 *    carries every customer's tunnel), so re-pinning one is a platform
 *    administrator's act whatever capability the caller holds; the route
 *    itself asks CREDENTIAL_MANAGE, the capability of every transport write;
 *  - it is written to `audit_log` inside the same transaction as the pin, so
 *    a re-pin the ledger did not record did not happen.
 *
 * Then the old target's session and breaker verdict are dropped, presence is
 * restarted on a concentrator, and ONE health check runs at once — the
 * scheduler's own code — so the page shows whether the box answers over the
 * new pin instead of waiting for the next interval. If the scheduler happened
 * to be checking the device at that very instant, the check run is that one
 * (`checkDevice` shares an in-flight check), which may still carry the old
 * target; the next interval settles it.
 */

import {
  TLS_SHA256_HEX_RE,
  type TlsRepinRefusal,
  type TlsRepinResult,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { appendAudit } from '../attestation/auditLog.service';
import { syncConcentratorPresence } from './device.service';
import { checkDeviceNow } from './healthCheck.service';
import { getRouterOsPool } from './routerosPool';
import { lockDeviceTls, settleCertificateAlerts } from './tlsPresented.service';

const ROUTEROS = 'routeros_api';

export class TlsRepinError extends Error {
  readonly code: TlsRepinRefusal;
  readonly httpStatus: number;
  constructor(code: TlsRepinRefusal, httpStatus: number, message: string) {
    super(message);
    this.name = 'TlsRepinError';
    this.code = code;
    this.httpStatus = httpStatus;
  }
}

export interface TlsRepinInput {
  tenantId: number;
  deviceId: number;
  presented: string;
  pinned: string | null;
  actor: { userId: number | null; username: string | null; platformAdmin: boolean };
}

export async function repinToPresented(input: TlsRepinInput): Promise<TlsRepinResult> {
  const presented = input.presented;
  if (!TLS_SHA256_HEX_RE.test(presented)) {
    // The validator already refuses this shape; restated here because this is
    // the function that writes the pin.
    throw new TlsRepinError('presented_mismatch', 400, 'The fingerprint must be 64 lowercase hex digits.');
  }

  const device = (await db('devices')
    .where({ id: input.deviceId, tenant_id: input.tenantId })
    .first('id', 'tenant_id', 'name', 'role')) as
    | { id: number; tenant_id: number; name: string; role: string }
    | undefined;
  if (!device) throw new TlsRepinError('not_found', 404, 'Device not found');
  if (device.role === 'concentrator' && !input.actor.platformAdmin) {
    throw new TlsRepinError(
      'platform_admin_required',
      403,
      'A concentrator carries every workspace\'s tunnels: only a platform administrator re-pins its certificate.',
    );
  }

  const previous = await db.transaction(async (trx) => {
    // The same lock as the pool's record of a refusal: a refusal being
    // recorded and this re-pin never interleave.
    await lockDeviceTls(trx, device.id);
    const row = (await trx('device_transports')
      .where({ device_id: device.id, transport: ROUTEROS })
      .forUpdate()
      .first('tls_fingerprint_sha256', 'tls_presented_sha256', 'tls_presented_at')) as
      | { tls_fingerprint_sha256: string | null; tls_presented_sha256: string | null; tls_presented_at: Date | null }
      | undefined;
    if (!row) throw new TlsRepinError('no_channel', 404, 'This device has no RouterOS API channel.');
    if (row.tls_presented_sha256 === null) {
      throw new TlsRepinError(
        'nothing_recorded',
        409,
        'No refused certificate is recorded on this channel: either no handshake was refused, or one was accepted since.',
      );
    }
    if (row.tls_presented_sha256 !== presented) {
      throw new TlsRepinError(
        'presented_mismatch',
        409,
        'This is not the fingerprint ObliWAN recorded as presented by the device. Only that one can be pinned here.',
      );
    }
    if ((row.tls_fingerprint_sha256 ?? null) !== input.pinned) {
      throw new TlsRepinError(
        'pin_changed',
        409,
        'The pinned fingerprint changed since this page was loaded. Reload it and confirm again.',
      );
    }

    await trx('device_transports')
      .where({ device_id: device.id, transport: ROUTEROS })
      .update({
        tls_fingerprint_sha256: presented,
        tls_presented_sha256: null,
        tls_presented_at: null,
        updated_at: trx.fn.now(),
      });
    await appendAudit(
      {
        tenantId: device.tenant_id,
        actorType: 'user',
        actorId: input.actor.userId,
        actorName: input.actor.username ? input.actor.username.slice(0, 128) : null,
        action: 'device_transport.tls_repinned',
        entityType: 'device',
        entityId: device.id,
        before: {
          transport: ROUTEROS,
          pinnedFingerprint: row.tls_fingerprint_sha256,
          presentedFingerprint: row.tls_presented_sha256,
          presentedSince: row.tls_presented_at ? row.tls_presented_at.toISOString() : null,
        },
        after: { transport: ROUTEROS, pinnedFingerprint: presented },
      },
      trx,
    );
    await settleCertificateAlerts(trx, device.id);
    return row.tls_fingerprint_sha256;
  });

  logger.warn(
    { deviceId: device.id, previous, pinned: presented, by: input.actor.userId },
    'RouterOS TLS certificate re-pinned to the fingerprint the device presented',
  );

  // The old target's session (if any) and breaker verdict describe a pin that
  // no longer exists; presence on a concentrator holds its listen on that
  // session and must be restarted onto the new one.
  try {
    await getRouterOsPool().forgetTarget(String(device.id));
    if (device.role === 'concentrator') await syncConcentratorPresence(device.id, { restart: true });
  } catch (err) {
    logger.warn({ err, deviceId: device.id }, 'Re-pinned, but the pooled session could not be reset; the next dial will');
  }

  let check: TlsRepinResult['check'];
  try {
    const outcome = await checkDeviceNow(input.tenantId, device.id);
    if (outcome.kind === 'done') {
      const o = outcome.result.outcome;
      check = o === 'ok' || o === 'fail' || o === 'skip'
        ? { kind: 'done', outcome: o, state: outcome.view.state, lastError: outcome.view.lastError }
        : { kind: 'not_run', reason: `The check ended as '${o}'.` };
    } else if (outcome.kind === 'aborted') {
      check = { kind: 'not_run', reason: outcome.reason };
    } else if (outcome.kind === 'disabled') {
      check = { kind: 'not_run', reason: "This device's status is 'disabled', so it is never checked." };
    } else {
      check = { kind: 'not_run', reason: 'Device not found' };
    }
  } catch (err) {
    check = { kind: 'not_run', reason: err instanceof Error ? err.message.slice(0, 300) : String(err) };
  }

  return { pinned: presented, previous, check };
}
