import { z } from 'zod';
import { LEARNING_MAX_DEVICES } from '@obliwan/shared';

/**
 * Learning mode — request bodies and query strings (learning.routes.ts).
 * A refusal names field PATHS only.
 */

const id = z.number().int().positive().max(2_147_483_647);
const ids = z.array(id).min(1).max(LEARNING_MAX_DEVICES);

export const learningToggleSchema = z.object({ learning: z.boolean() }).strict();

export const learningBulkStateSchema = z.object({ deviceIds: ids, learning: z.boolean() }).strict();

export const learningCaptureSchema = z.object({ deviceIds: ids }).strict();

export const learningDatasetSchema = z.object({ deviceIds: ids }).strict();

export const learningListQuerySchema = z
  .object({
    learningOnly: z.enum(['true', 'false']).optional(),
    search: z.string().max(120).optional(),
    filterTenantId: z.string().optional(),
  })
  .passthrough();

export const learningBreakRiskQuerySchema = z
  .object({ revisionId: z.string().regex(/^[1-9][0-9]{0,17}$/).optional() })
  .passthrough();

export const runIdSchema = z.string().uuid();
export const numericIdSchema = z.string().regex(/^[1-9][0-9]{0,17}$/);
