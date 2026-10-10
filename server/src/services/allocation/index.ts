/**
 * Per-tenant address allocation for L2TP sites: tunnel /32, optional LAN
 * subnet, PPP login and password.
 *
 *   formula.ts     the operator's address formulas — own parser, never eval
 *   pppIdentity.ts PPP login and system identity templates, site
 *                  slug/number/country, password
 *   derived.ts     further computed values (cidrHost on the LAN, formulas on
 *                  id, site placeholders) — pure
 *   policy.ts      the engine — pure; pools, policy validation, planning
 *   seed.ts        which CHRs are believed, which gate an allocation, and
 *                  how old their /ppp/secret read may be — pure
 *   allocator.ts   the database side: lock, idempotency, vault, seed re-read,
 *                  reads, release
 *   lanReprise.ts  the deployed LAN of existing sites, recorded on their
 *                  allocation from the operator's table (migration 070);
 *                  imported directly, not through this index (it reads the
 *                  site import's CSV parser, which imports this index)
 *   pools.ts       address pools, the installation domain, seed status
 *   lock.ts        the one advisory lock every writer of "taken" holds
 *   errors.ts      AllocationError (reason, not code) and its HTTP statuses
 *
 * `revealPppCredential` and `computedForSite` are exported for the server-side
 * compile path and the concentrator job, and `readPppAccount` (the same read,
 * whose password is null for a site adopted from its CHR in 'per_site' mode)
 * for that job alone. They return a plaintext password and no route may call
 * them. `previewForSite` is their non-committing twin, without the password.
 */
export {
  CONCENTRATOR_STATES,
  PREVIEW_MAX,
  allocateForSite,
  type AllocationResult,
  computedForSite,
  readPppAccount,
  type PppAccount,
  listAllocations,
  listConcentrators,
  previewForSite,
  previewNextAllocations,
  type AllocatedSiteView,
  type ComputedSiteValues,
  type ConcentratorOption,
  type LanRuleView,
  type SiteComputedPreview,
  getPolicy,
  getSiteProvisioning,
  previewAllocation,
  recordConcentratorOutcome,
  releaseAllocation,
  renameAllocationNames,
  revealPppCredential,
  siteExists,
  tenantExists,
  upsertPolicy,
  checkPolicy,
  validateDrafts,
  type AllocationPolicyView,
  type AllocationPreview,
  type ConcentratorState,
  type PolicyRuleView,
  type PppCredential,
  type PreviewEntry,
  type SeedStatus,
  type SiteDraft,
  type SiteProvisioningView,
} from './allocator';
export {
  allocationOwnedInstanceKey,
  createPool,
  deletePool,
  getInstanceDomain,
  getPool,
  getSeedStatus,
  listPools,
  renamePool,
  setInstanceDomain,
  type AddressPoolView,
} from './pools';
export { AllocationError, type AllocationErrorReason } from './errors';
export { ALLOCATION_LOCK_CLASS, ALLOCATION_LOCK_KEY, takeAllocationLock } from './lock';
export {
  DEFAULT_PPP_PASSWORD_MODE,
  LAN_MODES,
  PPP_PASSWORD_MODES,
  SHARED_PPP_PASSWORD_KEY,
  type LanMode,
  type PppPasswordMode,
  ADDRESS_MODES,
  FORMULA_PROBE_MAX,
  PG_INT_MAX,
  PLAN_REFUSAL_REASONS,
  PLAN_SOURCES,
  POOL_PURPOSES,
  planSites,
  policyConflicts,
  poolOverlapConflict,
  validatePolicyInput,
  type AddressHolder,
  type AddressMode,
  type AllocationPolicy,
  type AllocationPolicyInput,
  type AllocationRefusal,
  type DeclaredSecret,
  type LoginHolder,
  type PlanRefusalReason,
  type PlanSource,
  type PoolPurpose,
  type SiteFacts,
  type SitePlan,
} from './policy';
export {
  LOGIN_PLACEHOLDERS,
  PPP_LOGIN_MAX,
  PPP_PASSWORD_ALPHABET,
  PPP_PASSWORD_LENGTH,
  minimalLoginLength,
  parseIdentityTemplate,
  renderSystemIdentity,
  normalizeCountry,
  siteNumber,
  siteSlug,
} from './pppIdentity';
export {
  DERIVED_MAX,
  DERIVED_RESERVED_KEYS,
  evaluateDerived,
  parseDerivedExpression,
  parseDerivedValues,
  type DerivedValue,
} from './derived';
export {
  SEED_MAX_AGE_MS,
  seedConcentrators,
  seedFreshness,
  trustedConcentrators,
  type PolicySeedRef,
  type SeedFreshness,
} from './seed';
