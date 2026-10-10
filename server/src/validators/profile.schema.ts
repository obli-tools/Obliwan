import { z } from 'zod';

const userPreferencesSchema = z.object({
  toastEnabled: z.boolean(),
  toastPosition: z.enum(['top-center', 'bottom-right']),
  // Without this key zod STRIPS the theme the ProfilePage sends, so the choice
  // never reached the DB and the next /auth/me re-applied the enrollment theme.
  // Keep in sync with AppTheme (shared/src/types.ts) and enrollment.controller.ts.
  preferredTheme: z.enum(['obli-operator', 'obli-daylight', 'obli-dim', 'modern', 'neon']).optional(),
}).nullable().optional();

export const updateProfileSchema = z.object({
  displayName: z.string().max(100).nullable().optional(),
  preferences: userPreferencesSchema,
  email: z.string().email().max(255).nullable().optional(),
  preferredLanguage: z.string().max(10).optional(),
});

export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword: z.string().min(6).max(128),
});

/** First local password of an SSO-created account (#30). Same bounds as a
 *  change, with the 8-character floor the enrolment screen states. */
export const setLocalPasswordSchema = z.object({
  password: z.string().min(8).max(128),
});

export type UpdateProfileInput = z.infer<typeof updateProfileSchema>;
export type ChangePasswordInput = z.infer<typeof changePasswordSchema>;
