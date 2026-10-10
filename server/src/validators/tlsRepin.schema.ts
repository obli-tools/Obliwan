import { z } from 'zod';
import { TLS_SHA256_HEX_RE } from '@obliwan/shared';

/**
 * `POST /devices/:id/transports/routeros_api/repin`. `presented` must be the
 * exact form `connection.ts` computes (64 lowercase hex digits) — the service
 * then compares it with the value recorded server-side, and only that value
 * can be pinned. `pinned` is the pin the operator was shown, compared as
 * stored (the transport form accepts colons and upper case, so it is not
 * narrowed here beyond that form's own bound).
 */
export const tlsRepinSchema = z
  .object({
    presented: z.string().regex(TLS_SHA256_HEX_RE, 'expected 64 lowercase hex digits'),
    pinned: z.string().min(1).max(95).nullable(),
  })
  .strict();
