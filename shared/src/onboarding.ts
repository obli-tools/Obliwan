// ============================================================================
// @obliwan/shared — the onboarding assistant (brick 14, operator GO 2026-10-09)
// ============================================================================
//
// One resumable assistant on the Quick Setup Tenant page that walks a big
// customer (two hundred routers) from "its accounts are on the CHR" to "its
// sites carry every value their templates need", proposing at each step and
// asking only for approvals. Server: services/tenantSetup/onboarding.service.ts
// (the step statuses, recomputed from the database at every read) and
// services/tenantSetup/ruleInference.ts (the allocation rule read off the CHR
// accounts, pure).
//
// Nothing here is a sentence: the server answers in closed codes and counts,
// the screen translates them. Names (account names, site codes, variable
// KEYS) may be listed; a variable VALUE never is.

import type { SetupPolicyFile } from './tenantSetup';

/** The steps, in the order an onboarding takes them. */
export const ONBOARDING_STEP_KEYS = [
  'chr',
  'rule',
  'sites',
  'attach',
  'access',
  'configs',
  'infra',
  'templates',
  'variables',
] as const;
export type OnboardingStepKey = (typeof ONBOARDING_STEP_KEYS)[number];

/**
 * - `done`     nothing left to do for this step as far as the database shows;
 * - `todo`     something is left, and the step's action does it;
 * - `blocked`  an earlier step (or a missing prerequisite) must come first —
 *              `reason` says which;
 * - `running`  a background job of this step is running now.
 */
export const ONBOARDING_STEP_STATES = ['done', 'todo', 'blocked', 'running'] as const;
export type OnboardingStepState = (typeof ONBOARDING_STEP_STATES)[number];

/** Why a step is in its state. One closed list for every step: the screen
 *  has one sentence per code (`onboarding.reasons.<code>`). */
export const ONBOARDING_REASONS = [
  // chr
  'no_concentrator',
  'never_read',
  'no_slug_accounts',
  'chr_read',
  // rule
  'chr_not_read',
  'no_policy',
  'policy_saved',
  // sites
  'policy_unreadable',
  'no_match',
  'orphans',
  'to_adopt',
  'sites_done',
  // attach
  'no_sites',
  'canary',
  'batch',
  'attached',
  // access
  'no_devices',
  'never_verified',
  'verification_running',
  'verification_stale',
  'access_missing',
  'verified',
  // configs
  'no_collectable',
  'collect_running',
  'configs_missing',
  'configs_done',
  // infra
  'no_probe_template',
  'never_analysed',
  'analysis_partial',
  'analysis_not_applied',
  'analysed',
  // templates
  'no_configs',
  'never_extrapolated',
  'proposals_pending',
  'not_published',
  'not_assigned',
  'templates_done',
  // variables
  'no_published_template',
  'variables_missing',
  'variables_done',
] as const;
export type OnboardingReason = (typeof ONBOARDING_REASONS)[number];

/** A remark beside a step, whatever its state. */
export const ONBOARDING_WARNINGS = [
  // the CHR was read more than ONBOARDING_CHR_STALE_MS ago
  'read_stale',
  // the stored rule does not explain every account naming the tenant
  'rule_partial',
  // routers were attached after the last verification / analysis
  'new_devices_since',
  // matched sites whose router is offline (never attachable while it is)
  'offline_sites',
  // the bulk collect left routers for a next run (its cap)
  'collect_deferred',
] as const;
export type OnboardingWarning = (typeof ONBOARDING_WARNINGS)[number];

/** A CHR read older than this is shown as stale (the assistant still counts
 *  it as read: the reconciliation reads what was recorded). */
export const ONBOARDING_CHR_STALE_MS = 24 * 60 * 60_000;
/** Names listed under one step, at most (the counts stay exact). */
export const ONBOARDING_ITEMS_MAX = 50;

export interface OnboardingStep {
  key: OnboardingStepKey;
  state: OnboardingStepState;
  reason: OnboardingReason;
  warning: OnboardingWarning | null;
  /** The numbers the step's sentence interpolates. */
  counts: Record<string, number>;
  /** Names listed under the step (site codes, variable keys…), capped. */
  items: string[];
  /** Variables step: the SECRET keys still without a value, by name only. */
  secrets: string[];
  /** The instant the step's evidence dates from (a CHR read, a run). */
  at: string | null;
  /** chr step: the concentrator its re-read targets. */
  concentratorId: number | null;
}

export interface OnboardingStatus {
  tenant: { id: number; name: string; slug: string };
  generatedAt: string;
  steps: OnboardingStep[];
  /** The first step that is not done, in order; null when all are. */
  next: OnboardingStepKey | null;
}

// ============================================================================
// The allocation rule, read off the CHR accounts
// ============================================================================

/** The shortest search text accepted: one letter finds half the CHR. */
export const RULE_INFERENCE_SLUG_MIN = 2;
export const RULE_INFERENCE_SLUG_MAX = 64;
/** Outliers listed per facet, at most (`outliersTotal` stays exact). */
export const RULE_INFERENCE_OUTLIERS_MAX = 200;

/**
 * Why an account (or a site) is listed beside a facet:
 *  - `uppercase`        its name carries capitals (the allocator compares
 *                       without case and adopts the CHR's spelling; the
 *                       operator lowercases them on the router and the CHR);
 *  - `missingCountry`   the login model carries {site.country} and this
 *                       account none, while most do;
 *  - `oldNaming`        it names the tenant, and the model does not produce it;
 *  - `codeFormat`       its site code does not have the proposed format;
 *  - `noAddress`        its secret declares no IPv4 remote-address;
 *  - `formulaMismatch`  its address is not the one the formula renders
 *                       (`detail`: address → formula's);
 *  - `outsideBlock`     its address lies outside the block most addresses
 *                       share;
 *  - `otherProfile`     another PPP profile than the majority's;
 *  - `disabled`         the secret is disabled on the CHR;
 *  - `otherConcentrator` on another CHR than the one most accounts are on;
 *  - `otherTenant`      held by another customer's allocation or router:
 *                       never counted as this tenant's;
 *  - `noAccount`        a site of the tenant whose login (under the model)
 *                       is on no account;
 *  - `identityMismatch` a router's identity the identity model does not give.
 */
export const RULE_OUTLIER_REASONS = [
  'uppercase',
  'missingCountry',
  'oldNaming',
  'codeFormat',
  'noAddress',
  'formulaMismatch',
  'outsideBlock',
  'otherProfile',
  'disabled',
  'otherConcentrator',
  'otherTenant',
  'noAccount',
  'identityMismatch',
] as const;
export type RuleOutlierReason = (typeof RULE_OUTLIER_REASONS)[number];

export interface RuleOutlier {
  /** The account name (or the site code for `noAccount`, the router's
   *  identity for `identityMismatch`). */
  name: string;
  reason: RuleOutlierReason;
  /** A short fact: the code read, the address, the profile. Never a secret. */
  detail: string | null;
}

/** One proposed field of the rule, and how much of the CHR it explains. */
export interface RuleFacet {
  explained: number;
  total: number;
  outliers: RuleOutlier[];
  outliersTotal: number;
}

/** Why no rule can be proposed (or saved) as it stands. */
export const RULE_BLOCKERS = [
  'no_accounts',
  'no_login',
  'no_concentrator',
  'no_tunnel',
  'pool_conflict',
  'pool_shared',
] as const;
export type RuleBlocker = (typeof RULE_BLOCKERS)[number];

/** The proposal's fields that differ from the stored rule. */
export const RULE_FIELDS = ['login', 'identity', 'tunnel', 'profile', 'codeFormat', 'concentrator'] as const;
export type RuleField = (typeof RULE_FIELDS)[number];

export interface RuleInference {
  tenant: { id: number; name: string; slug: string };
  /** The text searched for in account names (lowercase). */
  searchSlug: string;
  instanceDomain: string;
  generatedAt: string;
  /** The CHRs searched, with what they hold for this search. */
  concentrators: Array<{
    id: number;
    name: string;
    readAt: string | null;
    freshness: 'never' | 'stale' | 'fresh';
    accounts: number;
  }>;
  accounts: {
    /** Accounts naming the search text, not held by another customer. */
    total: number;
    online: number;
    disabled: number;
    /** Held by another customer: listed, never counted. */
    excluded: RuleOutlier[];
  };
  login: RuleFacet & {
    template: string | null;
    /** The template with the tenant's fixed values substituted. */
    display: string | null;
    alternatives: Array<{ template: string; explained: number }>;
  };
  codeFormat: RuleFacet & { format: string };
  tunnel: RuleFacet & {
    mode: 'formula' | 'incremental' | null;
    formula: string | null;
    /** incremental: the start proposed (the block's first free address). */
    start: string | null;
    /** The smallest block holding the explained accounts' addresses. */
    block: string | null;
    firstFree: string | null;
    pool: {
      action: 'existing' | 'create' | 'conflict' | 'none';
      id: number | null;
      name: string | null;
      cidr: string | null;
      /** conflict: the pool the block would overlap, or share. */
      conflictWith: string | null;
    };
  };
  profile: RuleFacet & { value: string | null };
  identity: RuleFacet & {
    template: string | null;
    /** Router identities known (attached routers of the tenant). */
    known: number;
  };
  /** Sites of the tenant whose login is on no account. */
  sitesWithoutAccount: { total: number; codes: string[] };
  /** The stored rule, when there is one: which proposed fields differ. */
  stored: { exists: boolean; differs: RuleField[] };
  proposal: {
    /** The rule as a Quick Setup rule file (pools and CHR by NAME). */
    file: SetupPolicyFile | null;
    /** The PUT /allocation/tenants/:id/policy body (ids); its tunnel poolId
     *  is null while the pool is still to be created. */
    body: Record<string, unknown> | null;
    createPool: { name: string; cidr: string } | null;
    blockers: RuleBlocker[];
    /** The allocator's own dry run of `body` (`checkPolicy`); not run while
     *  the pool is still to be created. */
    allocator: { checked: boolean; ok: boolean; reason: string | null; message: string | null };
    /** What the approval must quote: a proposal that changed since it was
     *  shown is refused, never saved in its new form. */
    fingerprint: string;
  };
}

/** POST /tenant-setup/onboarding/rule/approve */
export interface RuleApproveRequest {
  slug?: string;
  fingerprint: string;
}

export interface RuleApproveResult {
  saved: true;
  poolCreated: { id: number; name: string; cidr: string } | null;
  loginTemplate: string;
}
