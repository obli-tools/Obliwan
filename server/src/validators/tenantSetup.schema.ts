/**
 * Quick Setup Tenant — the request bodies (routes/tenantSetup.routes.ts).
 *
 * A variable row's `key` and `value` are deliberately NOT judged here: a bad
 * key or value is a ROW issue of the check (reported on its line, beside the
 * others), not a 400 for the whole request — and zod never sees a value it
 * could echo in an error. The same for the template file and the rule, which
 * their own services judge. What this file holds is the envelope: which
 * parts, their types, and the bounds.
 */

import { z } from 'zod';
import {
  MAX_SETUP_BODY_CHARS,
  MAX_SETUP_REFERENCE_REVISIONS,
  MAX_SETUP_VARIABLE_ROWS,
} from '@obliwan/shared';

const setupRow = z
  .object({
    level: z.string().max(32),
    scopeRef: z.string().max(64).nullable().optional(),
    key: z.string().max(200),
    value: z.unknown().optional(),
    secret: z.boolean().default(false),
    line: z.number().int().positive().optional(),
  })
  .strict();

/** The workspace the body was prepared for; compared with the session's,
 *  never used to choose one (shared SETUP_TENANT_MISMATCH). */
const expectedTenantId = z.number().int().positive();

/** Revision ids are bigints, sent as decimal text. */
const referenceRevisionIds = z
  .array(z.string().regex(/^[0-9]{1,19}$/))
  .max(MAX_SETUP_REFERENCE_REVISIONS)
  .default([]);

export const tenantSetupRequestSchema = z
  .object({
    expectedTenantId,
    parts: z
      .object({
        variables: z.object({ rows: z.array(setupRow).max(MAX_SETUP_VARIABLE_ROWS) }).strict().optional(),
        template: z.object({ file: z.unknown(), publish: z.boolean().default(false) }).strict().optional(),
        allocationPolicy: z.object({ policy: z.record(z.unknown()) }).strict().optional(),
        sites: z
          .object({ csv: z.string().min(1).max(MAX_SETUP_BODY_CHARS), allocate: z.boolean().default(false) })
          .strict()
          .optional(),
      })
      .strict()
      .refine(
        (p) => p.variables !== undefined || p.template !== undefined || p.allocationPolicy !== undefined || p.sites !== undefined,
        { message: 'select at least one part' },
      ),
    referenceRevisionIds,
    acknowledgeInstanceScope: z.boolean().default(false),
  })
  .strict();

export const tenantSetupContextSchema = z
  .object({
    expectedTenantId,
    template: z.unknown().optional(),
    referenceRevisionIds,
  })
  .strict();

export type TenantSetupRequestInput = z.infer<typeof tenantSetupRequestSchema>;
export type TenantSetupContextInput = z.infer<typeof tenantSetupContextSchema>;
