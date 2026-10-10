import type { Knex } from 'knex';

/**
 * The allocation lock — ONE key for the whole address space.
 *
 * Every writer that changes what the allocator considers "taken" takes it,
 * inside its own transaction, and holds it until commit:
 *
 *   - allocateForSite        (inserts into site_provisioning)
 *   - releaseAllocation      (deletes from site_provisioning)
 *   - upsertPolicy           (judges a policy against every other tenant's)
 *   - createPool             (judges a pool against every other pool: the
 *                            tunnel-against-LAN overlap rule is not a
 *                            constraint)
 *   - fillIdentity           (allocator.ts: writes a missing system_identity
 *                            once, judged against every identity held)
 *   - setInstanceDomain      (judges the domain against every login and
 *                            identity template)
 *   - the CHR secret inventory writer in fleet/concentratorDiscovery.service.ts
 *                            (rewrites concentrator_ppp_secrets after a read)
 *
 * A per-tenant key would not hold the guarantee it is for: tunnel addresses
 * and PPP logins are unique ACROSS tenants, and a pool may be shared by
 * several small tenants. Writers of `devices` and `ppp_sessions` do NOT take
 * it; the allocator reads those tables once, inside its transaction, and a row
 * written there between that read and the commit is not seen (allocator.ts,
 * "WHAT THE LOCK DOES NOT COVER").
 *
 * Nothing dials a router while holding it: the allocator re-reads a CHR's
 * /ppp/secret BEFORE it opens its transaction, and the inventory writer takes
 * the lock only once that read has returned.
 *
 * Distinct from every other advisory-lock class in the tree (20311 rollouts,
 * 730119204 audit chain, 0x0f6 identity watch, 0x4f57 leader election).
 */
export const ALLOCATION_LOCK_CLASS = 36_036;
export const ALLOCATION_LOCK_KEY = 0;

export async function takeAllocationLock(trx: Knex.Transaction): Promise<void> {
  await trx.raw('SELECT pg_advisory_xact_lock(?, ?)', [ALLOCATION_LOCK_CLASS, ALLOCATION_LOCK_KEY]);
}
