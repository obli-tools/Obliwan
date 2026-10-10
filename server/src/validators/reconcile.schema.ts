import { z } from 'zod';
import { RECONCILE_ATTACH_APPLY_MAX_SITES, RECONCILE_ATTACH_FOLLOWUP_DEFAULTS } from '@obliwan/shared';

/**
 * Bulk attach of the reconciliation's online routers — request bodies
 * (reconcile.routes.ts). The credential is optional: absent, the server logs
 * in as `admin` with the vault's `admin_password`. A validation error names
 * the field, never its value (zod's messages carry none), so a refused
 * password is not echoed.
 */

// eslint-disable-next-line no-control-regex
const NO_CONTROL = /^[^\u0000-\u001f\u007f]*$/;

const credentialsSchema = z
  .object({
    // An SSH login name; never spliced into a router command.
    username: z.string().trim().min(1).max(64).regex(NO_CONTROL),
    // Not trimmed: a password's spaces are part of it.
    password: z.string().min(1).max(256).regex(NO_CONTROL),
  })
  .strict();

const siteId = z.number().int().positive().max(2_147_483_647);

/** What follows each attached router (fleet/reconcileAttach.service.ts, "WHAT
 *  FOLLOWS THE ATTACH"). Absent = the defaults, both: the operator's decision
 *  (2026-10-05). `applyCompliance` without `openManagementAccess` means
 *  nothing and is dropped by the service. */
const followUpFields = {
  openManagementAccess: z.boolean().default(RECONCILE_ATTACH_FOLLOWUP_DEFAULTS.openManagementAccess),
  applyCompliance: z.boolean().default(RECONCILE_ATTACH_FOLLOWUP_DEFAULTS.applyCompliance),
};

/** The dry run: every site of the workspace when `siteIds` is absent. */
export const reconcileAttachPreviewSchema = z
  .object({
    siteIds: z.array(siteId).min(1).max(5000).optional(),
    credentials: credentialsSchema.optional(),
    ...followUpFields,
  })
  .strict();

/** The act: a slice of the selection (each site is dialled). */
export const reconcileAttachApplySchema = z
  .object({
    siteIds: z.array(siteId).min(1).max(RECONCILE_ATTACH_APPLY_MAX_SITES),
    credentials: credentialsSchema.optional(),
    ...followUpFields,
    /** The follow-up jobs arm no dead-man; asking for one needs this
     *  explicit confirmation of the degraded level, once for the batch (the
     *  service refuses the request without it, before any dial). */
    confirmNoDeadman: z.boolean().default(false),
    /** Put each router attached by this request in learning mode (operator
     *  request 2026-10-09: checked by default). Learning refuses template
     *  pushes only; the follow-ups above still run. */
    learning: z.boolean().default(true),
  })
  .strict();

export type ReconcileAttachPreviewInput = z.infer<typeof reconcileAttachPreviewSchema>;
export type ReconcileAttachApplyInput = z.infer<typeof reconcileAttachApplySchema>;
