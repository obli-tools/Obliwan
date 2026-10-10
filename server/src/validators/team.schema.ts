import { z } from 'zod';

export const createTeamSchema = z.object({
  name: z.string().min(1).max(255),
  description: z.string().max(1000).nullable().optional(),
  canCreate: z.boolean().optional(),
});

export const updateTeamSchema = z.object({
  name: z.string().min(1).max(255).optional(),
  description: z.string().max(1000).nullable().optional(),
  canCreate: z.boolean().optional(),
});

export const setTeamMembersSchema = z.object({
  userIds: z.array(z.number().int().positive()),
});

/**
 * A grant: 'ro' (consultation) or 'rw' (modification) on a group — inherited
 * by its sub-groups and their devices — on a device, or on the ungrouped
 * devices of the tenant (`ungrouped`, scopeId 0; migration 084).
 */
export const setTeamPermissionsSchema = z.object({
  permissions: z.array(
    z.object({
      scope: z.enum(['group', 'device', 'ungrouped']),
      scopeId: z.number().int().nonnegative(),
      level: z.enum(['ro', 'rw']),
    }).refine(
      (p) => (p.scope === 'ungrouped' ? p.scopeId === 0 : p.scopeId > 0),
      { message: "scopeId is 0 for 'ungrouped' and a positive id otherwise", path: ['scopeId'] },
    ),
  ),
});

export type CreateTeamInput = z.infer<typeof createTeamSchema>;
export type UpdateTeamInput = z.infer<typeof updateTeamSchema>;
export type SetTeamMembersInput = z.infer<typeof setTeamMembersSchema>;
export type SetTeamPermissionsInput = z.infer<typeof setTeamPermissionsSchema>;
