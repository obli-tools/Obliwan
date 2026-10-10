import type { Request } from 'express';
import { appendAudit } from './attestation/auditLog.service';
import { logger } from '../utils/logger';
import type { TenantBatch } from '../utils/globalView';

/**
 * The master tenant's half of Obliance's `auditPerTenant` pattern.
 *
 * A bulk action launched from the god view (utils/globalView.ts
 * `fanOutByTenant`) runs one ordinary per-tenant batch per owning tenant, and
 * each batch writes its own audit rows IN ITS TENANT — that is what a
 * customer's admin reads, and those rows carry
 * `godView.initiatedFromTenantId`. This writes the OTHER half: one summary row
 * in the tenant the operator stood on (the master tenant), naming every tenant
 * the gesture touched, so the master's ledger shows the fleet-wide act as one
 * line rather than not at all.
 *
 * Best effort by design: the per-tenant rows — the ones each batch wrote
 * inside its own transaction, under the "no audit, no write" rule — are the
 * record. A failed summary is logged, never turned into a failed request
 * after every tenant has already committed.
 */
export async function auditGodViewFanOut(
  req: Request,
  action: string,
  batches: ReadonlyArray<TenantBatch<unknown>>,
  extra: Record<string, unknown> = {},
): Promise<void> {
  try {
    await appendAudit({
      tenantId: req.tenantId,
      actorType: 'user',
      actorId: req.session?.userId ?? null,
      actorName: req.session?.username ?? null,
      action: action.slice(0, 64),
      entityType: 'god_view',
      after: {
        scope: 'all_tenants',
        tenants: batches.map((b) => ({ tenantId: b.tenantId, ids: b.ids.length })),
        ...extra,
      },
    });
  } catch (err) {
    logger.warn({ err, action }, 'God view: the master tenant summary audit row could not be written');
  }
}
