import { z } from 'zod';
import { INFRA_ANALYSIS_MAX_APPLY_ROWS, INFRA_ANALYSIS_MAX_DEVICES } from '@obliwan/shared';

/**
 * The infrastructure analysis — request bodies (infraAnalysis.routes.ts).
 * A refusal names field PATHS only (the controller never forwards zod's
 * messages), so a credential typed for the run is never echoed.
 */

// eslint-disable-next-line no-control-regex
const NO_CONTROL = /^[^\u0000-\u001f\u007f]*$/;

const credentialSchema = z
  .object({
    // An SSH login name. It IS spliced into the policy read
    // (`SSH_ACCOUNT_READS.group`), which refuses any name outside its own
    // safe set — so a name with a quote reads no policy and no secret.
    username: z.string().trim().min(1).max(64).regex(NO_CONTROL),
    // Not trimmed: a password's spaces are part of it.
    password: z.string().min(1).max(256).regex(NO_CONTROL),
  })
  .strict();

const id = z.number().int().positive().max(2_147_483_647);
const siteCode = z.string().trim().min(1).max(64).regex(NO_CONTROL);

const selectionSchema = z.union([
  z.object({ all: z.literal(true) }).strict(),
  z.object({ deviceIds: z.array(id).min(1).max(INFRA_ANALYSIS_MAX_DEVICES) }).strict(),
  z
    .object({ siteCodeFrom: siteCode.optional(), siteCodeTo: siteCode.optional() })
    .strict()
    .refine((v) => v.siteCodeFrom !== undefined || v.siteCodeTo !== undefined, {
      message: 'a site range names at least one bound',
    }),
]);

export const infraAnalysisPreviewSchema = z
  .object({
    selection: selectionSchema,
    revisionId: z.string().regex(/^\d{1,18}$/).optional(),
    credential: credentialSchema.optional(),
    readSecrets: z.boolean(),
    // An interface name compared with what the router prints, never sent to it.
    lanInterface: z.string().trim().min(1).max(64).regex(NO_CONTROL).optional(),
  })
  .strict();

export const infraAnalysisApplySchema = z
  .object({
    analysisId: z.string().uuid(),
    rows: z
      .array(z.object({ siteId: id, key: z.string().regex(/^[a-z][a-zA-Z0-9_]{0,119}$/) }).strict())
      .min(1)
      .max(INFRA_ANALYSIS_MAX_APPLY_ROWS),
  })
  .strict();

export const infraAnalysisIdSchema = z.string().uuid();
