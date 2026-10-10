import { z } from 'zod';
import { SITE_UPLINK_BULK_MAX, parseOpeningHoursText, validateOpeningHours, type OpeningHours } from '@obliwan/shared';

/**
 * Store opening hours (migration 096, shared/src/openingHours.ts) as the API
 * takes them: the structured value `{ week, exceptions }`, or its readable
 * text ("lun-ven 09:00-19:00; dim fermé; 2026-12-25 fermé"). Either way the
 * result is the validated, normalised value — the one rule lives in shared.
 */
export const openingHoursValueSchema = z
  .union([z.string().max(4000), z.record(z.unknown())])
  .transform((raw, ctx): OpeningHours => {
    const parsed = typeof raw === 'string' ? parseOpeningHoursText(raw) : validateOpeningHours(raw);
    if (!parsed.ok) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: parsed.error });
      return z.NEVER;
    }
    return parsed.value;
  });

/** `PUT /sites/opening-hours` — the workspace's hours; null clears them. */
export const tenantOpeningHoursSchema = z
  .object({ openingHours: openingHoursValueSchema.nullable() })
  .strict();

/** `POST /sites/bulk/opening-hours` — many sites at once (all of the tenant, or nothing). */
export const bulkSiteOpeningHoursSchema = z
  .object({
    ids: z
      .array(z.number().int().positive())
      .min(1)
      .max(SITE_UPLINK_BULK_MAX)
      .refine((ids) => new Set(ids).size === ids.length, 'each site id once'),
    openingHours: openingHoursValueSchema.nullable(),
    mode: z.enum(['replace', 'merge']).default('replace'),
  })
  .strict();

export type TenantOpeningHoursInput = z.infer<typeof tenantOpeningHoursSchema>;
export type BulkSiteOpeningHoursInput = z.infer<typeof bulkSiteOpeningHoursSchema>;
