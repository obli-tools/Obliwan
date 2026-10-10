/**
 * seed.ts — which concentrators the allocator believes, and how fresh their
 * reading must be. PURE: no database, no clock (the caller passes `now`), no
 * socket. allocator.ts loads the rows; these functions decide.
 *
 * ┌─ WHOSE CHR COUNTS ───────────────────────────────────────────────────────┐
 * │ A CHR's /ppp/secret and /ppp/active are claims made by whatever answers   │
 * │ on that device's RouterOS API. A tenant user holding DEVICE_WRITE,        │
 * │ CREDENTIAL_MANAGE and DEVICE_DISCOVER (the builtin 'engineer' set) can    │
 * │ declare a concentrator in their own tenant, point it at any endpoint,     │
 * │ fake or real, and scan it. If every CHR's secrets and sessions held       │
 * │ addresses and logins for every tenant, that user could fill another       │
 * │ tenant's formula pool with holders and stop its allocations, or punch     │
 * │ holes in a shared incremental pool, until somebody found the CHR.         │
 * │                                                                          │
 * │ So the secrets and live sessions of a CHR hold addresses and logins:     │
 * │   - for EVERY tenant, when the CHR is named by some tenant's allocation   │
 * │     policy (only a platform admin writes one) or belongs to the master    │
 * │     tenant (shared infrastructure);                                      │
 * │   - for its OWN tenant only, otherwise: a tenant can get in its own way,  │
 * │     never in another's.                                                  │
 * │                                                                          │
 * │ The price, stated: a CHR of tenant X that no policy names and that really │
 * │ holds addresses inside another tenant's pool is not seen by that other    │
 * │ tenant's allocations. Name it in a policy, or keep it in the master       │
 * │ tenant, and it is. And the limit, stated: a policy naming a CHR that      │
 * │ belongs to tenant X makes it believed by everyone, while X's users can    │
 * │ still edit that device and its transport — naming it trusts X. Shared     │
 * │ infrastructure belongs in the master tenant. `devices` rows are NOT       │
 * │ filtered this way at all; allocator.ts says why.                          │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHOSE READ GATES AN ALLOCATION, AND HOW OLD IT MAY BE ──────────────────┐
 * │ A tunnel pool may be shared by tenants that terminate on different CHRs,  │
 * │ and a tunnel address is unique across the installation. An allocation    │
 * │ from a pool therefore needs a current read of EVERY CHR named by a policy │
 * │ on that pool, not only its own tenant's. (A formula pool has one tenant — │
 * │ a policy save refuses a second — so there the set is the tenant's CHR.)   │
 * │                                                                          │
 * │ "Current" means read within SEED_MAX_AGE_MS. A read is a snapshot: a      │
 * │ secret typed by hand on the CHR after it is invisible, and an allocation  │
 * │ is a fact the bench renders into a CPE before any concentrator job runs.  │
 * │ The allocator re-reads a gating CHR whose last read is older — BEFORE its │
 * │ transaction, never inside it — and refuses (NOT_SEEDED, STALE_SEED) when  │
 * │ that read fails. What the bound leaves open — a secret typed by hand      │
 * │ within the last SEED_MAX_AGE_MS — is the concentrator job's to catch:     │
 * │ it must look for the name and the remote-address on the CHR before its    │
 * │ `/ppp secret add`, and a clash it finds is undone with                    │
 * │ `releaseAllocation` (allocator.ts).                                       │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

/** How old a CHR's /ppp/secret read may be for an allocation to rest on it.
 *  A bulk import of a few hundred sites re-reads each gating CHR at most once
 *  per this interval, not once per site. */
export const SEED_MAX_AGE_MS = 5 * 60 * 1000;

export type SeedFreshness = 'never' | 'stale' | 'fresh';

/**
 * Whether a read made at `readAtMs` (epoch ms; null = never read) still
 * counts at `nowMs`. A read stamped slightly in the future (another process's
 * clock) is fresh: its age is not positive.
 */
export function seedFreshness(readAtMs: number | null, nowMs: number): SeedFreshness {
  if (readAtMs === null) return 'never';
  return nowMs - readAtMs <= SEED_MAX_AGE_MS ? 'fresh' : 'stale';
}

/** The pool side of a stored policy, as far as seeding goes. */
export interface PolicySeedRef {
  tenantId: number;
  tunnelPoolId: number;
  concentratorId: number;
}

/**
 * The CHRs whose read gates an allocation for `own`'s tenant: its own CHR, and
 * the CHR of every policy whose tunnel rule draws from the same pool. Sorted,
 * without duplicates.
 */
export function seedConcentrators(own: PolicySeedRef, all: readonly PolicySeedRef[]): number[] {
  const ids = new Set<number>([own.concentratorId]);
  for (const p of all) if (p.tunnelPoolId === own.tunnelPoolId) ids.add(p.concentratorId);
  return Array.from(ids).sort((a, b) => a - b);
}

/**
 * The CHRs whose declared secrets and live sessions hold addresses and logins
 * for an allocation in `tenantId` — see "WHOSE CHR COUNTS". `chrs` is every
 * concentrator device; `policyConcentratorIds` every CHR a policy names (kept
 * even if that device's role has since changed: a policy naming it is the
 * platform admin's word that it matters).
 */
export function trustedConcentrators(
  chrs: ReadonlyArray<{ id: number; tenantId: number }>,
  policyConcentratorIds: Iterable<number>,
  tenantId: number,
  masterTenantId: number,
): Set<number> {
  const out = new Set<number>(policyConcentratorIds);
  for (const c of chrs) {
    if (c.tenantId === masterTenantId || c.tenantId === tenantId) out.add(c.id);
  }
  return out;
}

/** Keep only the rows a trusted CHR produced. The one filter every
 *  CHR-sourced holder goes through, so the rule has a single spelling. */
export function fromTrusted<T extends { concentratorId: number }>(
  rows: readonly T[],
  trusted: ReadonlySet<number>,
): T[] {
  return rows.filter((r) => trusted.has(r.concentratorId));
}
