import { z } from 'zod';
import { SITE_UPLINK_BULK_MAX, SITE_UPLINK_KINDS } from '@obliwan/shared';
import { SITE_FIXED_PROVIDER_BULK_MAX, normalizeFixedProvider } from '@obliwan/shared';
import { normalizeCountry } from '../services/allocation/pppIdentity';
import { openingHoursValueSchema } from './openingHours.schema';

/**
 * Sites — validation.
 *
 * `code` is the operator-facing short key (unique per tenant, see migration
 * 002). It is constrained to a slug so that it can safely appear in a bundle
 * filename, a template variable and a URL without escaping rules diverging
 * between the three.
 *
 * The SHAPE of a code (below) is the same for every tenant. What a code of a
 * given tenant must look like on top of it — "exactly 5 digits" — is the
 * tenant's site code format (migration 052), which a schema cannot know: it
 * is judged by services/allocation/policy.ts `judgeSiteCode`, called from
 * site.service (create, rename) and from the CSV import.
 */

/** Exported so the CSV import reports the very same rule per row and column
 *  instead of keeping a copy of it. */
export const SITE_CODE_MAX = 64;
export const SITE_CODE_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
export const SITE_CODE_SHAPE_MESSAGE = 'letters, digits, dot, dash and underscore only';

const timeOfDay = z
  .string()
  .regex(/^([01]\d|2[0-3]):[0-5]\d$/, 'expected HH:MM');

/**
 * An IANA zone name ("Europe/Paris", "UTC"). Offsets such as "+01:00" are
 * refused on shape even where Intl would accept them: a fixed offset does not
 * follow daylight saving, and a maintenance window judged in one is wrong half
 * the year. change/jobQueue.service.ts reads a zone it cannot use as a CLOSED
 * window, so a typo would silently hold every push to the site's routers:
 * the site's `timezone` and its window's own `tz` (which the scheduler reads
 * first) both pass this rule.
 *
 * The same rule as the CSV import's `isIanaTimeZone`
 * (services/fleet/siteImport.service.ts), which still keeps its own identical
 * copy: that service imports this file, so this file cannot import it back.
 */
export const SITE_TIMEZONE_MAX = 64;
const TIMEZONE_SHAPE = /^[A-Za-z][A-Za-z0-9_+-]*(\/[A-Za-z0-9_+-]+)*$/;
export function isIanaTimeZoneName(tz: string): boolean {
  if (tz.length > SITE_TIMEZONE_MAX || !TIMEZONE_SHAPE.test(tz)) return false;
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

/** The window that will gate every push. Kept deliberately small and
 *  explicit rather than an opaque blob: the change scheduler has to be able to
 *  reason about it without a parser of its own. Its own `tz`, when present, is
 *  read BEFORE the site's timezone, so it passes the same IANA rule. */
export const maintenanceWindowSchema = z
  .object({
    // 0 = Sunday, matching JS `Date.getDay()`.
    days: z.array(z.number().int().min(0).max(6)).min(1).max(7),
    start: timeOfDay,
    end: timeOfDay,
    tz: z
      .string()
      .min(1)
      .max(SITE_TIMEZONE_MAX)
      .refine(isIanaTimeZoneName, 'an IANA time zone name (e.g. Europe/Paris)')
      .optional(),
  })
  .strict();

/**
 * ISO 3166-1 alpha-2, by the allocator's own rule (`normalizeCountry`,
 * services/allocation/pppIdentity.ts — also the CSV import's): trimmed, an
 * empty text is null ("not stated"), two letters stored uppercase, which is
 * what migration 036's CHECK accepts. The country can be a `{site.country}`
 * placeholder of the PPP login formula; a login already allocated is frozen in
 * `site_provisioning` and is not re-rendered by a later edit.
 */
const countrySchema = z
  .string()
  .max(16)
  .nullable()
  .transform((raw, ctx) => {
    const parsed = normalizeCountry(raw);
    if (!parsed.ok) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'an ISO 3166-1 alpha-2 code (two letters)' });
      return z.NEVER;
    }
    return parsed.country;
  });

/** « Opérateur du lien fixe », by shared `normalizeFixedProvider` (the CSV
 *  import's rule too): trimmed, inner spaces collapsed, '' → null, ≤ 64. */
const fixedProviderSchema = z
  .string()
  .max(256)
  .nullable()
  .transform((raw, ctx) => {
    const parsed = normalizeFixedProvider(raw);
    if (!parsed.ok) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: parsed.error });
      return z.NEVER;
    }
    return parsed.value;
  });

export const createSiteSchema = z.object({
  code: z
    .string()
    .min(1)
    .max(SITE_CODE_MAX)
    .regex(SITE_CODE_RE, SITE_CODE_SHAPE_MESSAGE),
  name: z.string().min(1).max(255),
  country: countrySchema.optional(),
  address: z.string().max(2000).nullable().optional(),
  contact: z.string().max(500).nullable().optional(),
  timezone: z
    .string()
    .min(1)
    .max(SITE_TIMEZONE_MAX)
    .refine(isIanaTimeZoneName, 'an IANA time zone name (e.g. Europe/Paris)')
    .optional(),
  maintenanceWindow: maintenanceWindowSchema.nullable().optional(),
  /** The declared access link (migration 076, shared/src/siteUplink.ts):
   *  null = not declared (ObliWAN infers it). Same capability as the rest of
   *  the record: it changes what is ALERTED about the site, never what is
   *  written to a router. */
  uplinkKind: z.enum(SITE_UPLINK_KINDS).nullable().optional(),
  /** The site's own opening hours (migration 096): the value or its readable
   *  text; null = inherit the workspace's. SITE_WRITE, like the rest of the
   *  record: it changes what is alerted and when, never a router. */
  openingHours: openingHoursValueSchema.nullable().optional(),
  /** « Opérateur du lien fixe » (migration 095): who carries the store's
   *  fixed line, the best evidence of the grouped operator outage. Trimmed;
   *  empty = null = not declared. */
  fixedProvider: fixedProviderSchema.optional(),
});

/**
 * The edit is the creation's rules, every field optional. What a schema
 * cannot judge is site.service `updateSite`'s: the tenant's code format on a
 * rename, and the code LOCK — a site with an allocation or a bench
 * preparation keeps its code.
 */
export const updateSiteSchema = createSiteSchema.partial();

/**
 * What a site delete leaves behind, or takes with it, and must be
 * acknowledged BY NAME (site.service `deleteSite`):
 *   - `chr_account`    the site's L2TP account is on the concentrator
 *                      (allocation provisioned there, or adopted from it), or
 *                      may be (a claimed job adding it, an earlier add whose
 *                      answer was lost); ObliWAN never removes it;
 *   - `bench_history`  bench preparations of the site, kept as history with a
 *                      copy of the site's code and name (migration 056);
 *   - `sla_history`    SLA reports of the site, DELETED with it (migration
 *                      026, ON DELETE CASCADE).
 * Naming each one, rather than a single "force" flag, means a confirmation
 * given for what the screen showed does not cover something that appeared
 * since.
 */
export const SITE_DELETE_ACKNOWLEDGEMENTS = ['chr_account', 'bench_history', 'sla_history'] as const;
export type SiteDeleteAcknowledgement = (typeof SITE_DELETE_ACKNOWLEDGEMENTS)[number];

/** `DELETE /sites/:id?acknowledge=chr_account,bench_history,sla_history` — a
 *  comma-separated subset; absent is none. */
export const deleteSiteQuerySchema = z.object({
  acknowledge: z
    .string()
    .max(100)
    .optional()
    .transform((raw, ctx) => {
      const parts = (raw ?? '')
        .split(',')
        .map((s) => s.trim())
        .filter((s) => s !== '');
      const out: SiteDeleteAcknowledgement[] = [];
      for (const p of parts) {
        if (!(SITE_DELETE_ACKNOWLEDGEMENTS as readonly string[]).includes(p)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: `a comma-separated list of: ${SITE_DELETE_ACKNOWLEDGEMENTS.join(', ')}`,
          });
          return z.NEVER;
        }
        if (!out.includes(p as SiteDeleteAcknowledgement)) out.push(p as SiteDeleteAcknowledgement);
      }
      return out;
    }),
});

/**
 * `POST /sites/bulk/uplink-kind` — one declaration for many sites (a whole
 * customer in one gesture). Every id must be a site of the caller's tenant or
 * NOTHING is written (site.service `bulkSetSiteUplinkKind`). `uplinkKind`
 * is required and may be null ("automatic": back to inference).
 */
export const bulkSiteUplinkKindSchema = z
  .object({
    ids: z
      .array(z.number().int().positive())
      .min(1)
      .max(SITE_UPLINK_BULK_MAX)
      .refine((ids) => new Set(ids).size === ids.length, 'each site id once'),
    uplinkKind: z.enum(SITE_UPLINK_KINDS).nullable(),
  })
  .strict();

/**
 * `POST /sites/bulk/fixed-provider` — one « Opérateur du lien fixe » for many
 * sites. All ids of the caller's tenant or NOTHING is written (site.service
 * `bulkSetSiteFixedProvider`). `fixedProvider` is required; null or '' =
 * back to "not declared".
 */
export const bulkSiteFixedProviderSchema = z
  .object({
    ids: z
      .array(z.number().int().positive())
      .min(1)
      .max(SITE_FIXED_PROVIDER_BULK_MAX)
      .refine((ids) => new Set(ids).size === ids.length, 'each site id once'),
    fixedProvider: fixedProviderSchema,
  })
  .strict();

export const listSitesQuerySchema = z.object({
  search: z.string().max(255).optional(),
});

export type CreateSiteInput = z.infer<typeof createSiteSchema>;
export type UpdateSiteInput = z.infer<typeof updateSiteSchema>;
export type DeleteSiteQuery = z.infer<typeof deleteSiteQuerySchema>;
export type BulkSiteUplinkKindInput = z.infer<typeof bulkSiteUplinkKindSchema>;
export type BulkSiteFixedProviderInput = z.infer<typeof bulkSiteFixedProviderSchema>;
