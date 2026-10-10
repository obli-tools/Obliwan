// ============================================================================
// @obliwan/shared — a RouterOS API certificate that changed, and its re-pin
// ============================================================================
//
// The pool refuses a session whose certificate does not match the pin,
// and must: an unexplained new certificate may be an interception. When it IS
// a legitimate replacement (2026-10-04: the shared CHR's api-ssl moved from
// `local-ca` to its own `api-ssl` certificate), the operator re-pins — to the
// fingerprint the SERVER recorded as presented
// (`device_transports.tls_presented_sha256`, migration 069), never to one
// typed in. This file is the request, the answer and the closed refusal codes
// of `POST /api/devices/:id/transports/routeros_api/repin`.

/** A fingerprint as `connection.ts` computes it: the SHA-256 of the DER
 *  certificate, 64 lowercase hex digits, no separators. */
export const TLS_SHA256_HEX_RE = /^[0-9a-f]{64}$/;

export interface TlsRepinRequest {
  /** Must equal the fingerprint the server recorded as presented. The only
   *  value the endpoint will pin: anything else is refused, not stored. */
  presented: string;
  /** The pin the operator was shown beside it. A pin that changed since the
   *  screen was drawn is refused rather than overwritten: the confirmation the
   *  operator read named it. */
  pinned: string | null;
}

/** Why a re-pin was refused. The server's `error` sentence is English; the
 *  screen translates the code. */
export const TLS_REPIN_REFUSALS = [
  /** No such device in the session's workspace. */
  'not_found',
  /** The device has no RouterOS API channel. */
  'no_channel',
  /** No refused certificate is recorded on the channel: either no handshake
   *  was ever refused, or one was accepted again since. */
  'nothing_recorded',
  /** The fingerprint sent is not the one recorded as presented. */
  'presented_mismatch',
  /** The pin is no longer the one the operator was shown. */
  'pin_changed',
  /** A concentrator is shared by every workspace: only a platform
   *  administrator re-pins it. */
  'platform_admin_required',
] as const;
export type TlsRepinRefusal = (typeof TLS_REPIN_REFUSALS)[number];

export interface TlsRepinResult {
  /** The new pin — the recorded presented fingerprint. */
  pinned: string;
  /** The pin it replaced. */
  previous: string | null;
  /** The health check run right after the re-pin. `done` carries its outcome
   *  (`ok`: the box answered over the new pin) and the state it left;
   *  `not_run` says why no check could run. The re-pin stands either way. */
  check:
    | { kind: 'done'; outcome: 'ok' | 'fail' | 'skip'; state: string | null; lastError: string | null }
    | { kind: 'not_run'; reason: string };
}
