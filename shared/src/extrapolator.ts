// ============================================================================
// Brick 10 — the template extrapolator: a fleet in, a RouterOS template out
// ============================================================================
//
// The miner (`baseline.ts`) clusters a tenant's routers and states, per
// fact, how many sites agree. What it does NOT produce is the thing an operator
// writes by hand for every new customer: a RouterOS Nunjucks body, a
// `var_schema` with levels, the formulas that turn a site code into a login or
// a LAN, and the per-site values. The extrapolator produces exactly that, ON
// TOP of a miner run (its clusters, its snapshots), from the REDACTED raw
// exports the collector keeps (`config_snapshots.raw_gz`), and it proves its
// own proposal by rendering it for every site in the template worker and
// diffing the result against what the router actually runs.
//
// ┌─ FOUR THINGS THIS CONTRACT REFUSES ───────────────────────────────────────┐
// │ 1. A SECRET VALUE. The exports are redacted and the extrapolator          │
// │    never reads a secret: a secret-bearing property becomes a variable     │
// │    marked `x-obliwan-secret`, with no value and no default, anywhere —    │
// │    proposal, site values, evidence, approval.                             │
// │ 2. A PUBLICATION. Approving writes a template, a DRAFT revision and the   │
// │    non-secret tenant/site values. A draft cannot be assigned, rendered    │
// │    into a plan or applied; publishing stays the template-engine gesture.  │
// │ 3. A SILENT OVERWRITE. A variable value already stored with a different   │
// │    value is reported as a conflict and left alone.                        │
// │ 4. A FLATTERING SCORE. Each site is RENDERED and DIFFED; a cluster whose  │
// │    weakest site stays under the threshold says so (`gateMet: false`).     │
// └───────────────────────────────────────────────────────────────────────────┘
//
// PURE: types, the run parameters and their validation. No I/O.

import { z } from 'zod';
import type { TenantCollectState } from './tenantCollect';

/**
 * 2: the standard WAN1 block (wan1_mode dhcp | pppoe | static and its five
 * companions) is emitted when a cluster mixes WAN1 modes, instead of per-site
 * deviations and literals; a pure-DHCP cluster is proposed exactly as by 1.
 */
export const EXTRAPOLATOR_MODEL_VERSION = 2;

export const EXTRAPOLATION_RUN_STATUSES = ['running', 'succeeded', 'failed'] as const;
export type ExtrapolationRunStatus = (typeof EXTRAPOLATION_RUN_STATUSES)[number];

export const EXTRAPOLATION_PROPOSAL_STATUSES = ['proposed', 'approved', 'rejected'] as const;
export type ExtrapolationProposalStatus = (typeof EXTRAPOLATION_PROPOSAL_STATUSES)[number];

/**
 * How a value of the template is obtained, for one variable.
 *
 *   formula            computed by ObliWAN from the site (the allocator's own
 *                      grammars: login template, address formula over the site
 *                      number, `cidrHost(lan_subnet, n)`), declared `computed`
 *   site_code          the site code inlined in the body (`LAN-{{ site_code }}`)
 *   lan                the site LAN itself (`lan_subnet`), computed by the
 *                      allocator from its LAN rule or the recorded LAN
 *   default_exceptions a value most sites share, plus the sites that differ
 *   site               one value per site, read from its snapshot
 *   secret             a credential the export does not carry: vault only
 *   presence           lines present at some sites only (a boolean)
 *   existing           a constant equal to a variable the operator already
 *                      stores (instance / tenant level), reused by name
 */
export const EXTRAPOLATED_RULE_KINDS = [
  'formula', 'site_code', 'lan', 'default_exceptions', 'site', 'secret', 'presence', 'existing',
] as const;
export type ExtrapolatedRuleKind = (typeof EXTRAPOLATED_RULE_KINDS)[number];

/** The `x-obliwan-level` a proposed variable is declared at. */
export const EXTRAPOLATED_LEVELS = ['computed', 'instance', 'tenant', 'site'] as const;
export type ExtrapolatedLevel = (typeof EXTRAPOLATED_LEVELS)[number];

/** What an operator may force on one variable before re-running. */
export const EXTRAPOLATION_FORCED_RULES = ['auto', 'site', 'default_exceptions', 'literal'] as const;
export type ExtrapolationForcedRule = (typeof EXTRAPOLATION_FORCED_RULES)[number];

const VARIABLE_NAME_RE = /^[a-z][a-z0-9_]{0,59}$/;

/**
 * One operator correction, keyed by the SLOT (stable across runs on the same
 * fleet: `<menu>#<row identity>#<property>`), never by a database id.
 */
export const ExtrapolationOverride = z.object({
  slot: z.string().min(1).max(400),
  /** `auto` = let the inference decide (an override that only renames). */
  rule: z.enum(EXTRAPOLATION_FORCED_RULES).default('auto'),
  /** Rename the variable. */
  name: z.string().regex(VARIABLE_NAME_RE, 'lowercase letters, digits and _ (max 60), starting with a letter')
    .nullable().default(null),
  /** Secrets only: tenant-wide or one per site. */
  secretLevel: z.enum(['instance', 'tenant', 'site']).nullable().default(null),
  /** Lines only: keep a line present at too few sites as a per-site option
   *  instead of reporting it as a hand edit. */
  keepLine: z.boolean().default(false),
}).strict();
export type ExtrapolationOverride = z.infer<typeof ExtrapolationOverride>;

export const ExtrapolationParams = z.object({
  /** The miner run whose clusters are extrapolated. `null` = mine first (a
   *  fresh baseline run with the miner's defaults, narrowed to MikroTik). */
  baselineRunId: z.number().int().positive().nullable().default(null),
  /** A cluster is `gateMet` when EVERY site reproduces at least this share of
   *  its lines (matched / (device lines + template lines - matched)). */
  minReproduction: z.number().min(0.5).max(1).default(0.95),
  /** A value or a line shared by at most this many sites of a cluster is a
   *  DEVIATION (a hand edit to look at), not an exception the template keeps.
   *  0 keeps every difference in the template. */
  deviationMaxSites: z.number().int().min(0).max(20).default(1),
  /** Up to this many distinct values, a variable is "a default plus the sites
   *  that differ"; above, it is one value per site. */
  smallSetMax: z.number().int().min(2).max(64).default(8),
  /** A formula is kept with exceptions when it fits at least this share of the
   *  sites; below, the value is per site. */
  formulaMinFit: z.number().min(0.5).max(1).default(0.8),
  overrides: z.array(ExtrapolationOverride).max(500).default([]),
  /**
   * With no `baselineRunId`, how the fresh mining groups the routers:
   * `model` = one proposal per router MODEL (devices.model, else the export's
   * `# model =`), concentrators excluded; `profile` = the historical
   * structural clustering of the whole MikroTik fleet. Ignored when a miner
   * run is named: its clusters are what they are.
   */
  groupBy: z.enum(['model', 'profile']).default('model'),
  /** `groupBy: 'model'` only: a model whose routers differ splits into at
   *  most this many profiles (1 = exactly one template per model). */
  maxProfilesPerModel: z.number().int().min(1).max(4).default(1),
}).strict();
export type ExtrapolationParams = z.infer<typeof ExtrapolationParams>;

export const EXTRAPOLATION_DEFAULT_PARAMS: ExtrapolationParams = ExtrapolationParams.parse({});

/** One site's value of a variable (a site variable, an exception, a value a
 *  formula does not reproduce). NEVER for a secret. */
export interface ExtrapolatedSiteValue {
  deviceId: number;
  siteId: number | null;
  siteCode: string | null;
  /** '' means "the property is absent at this site". */
  value: string;
}

export interface ExtrapolatedVariable {
  name: string;
  /** Stable slot of the FIRST use — what an override targets. */
  slot: string;
  kind: ExtrapolatedRuleKind;
  level: ExtrapolatedLevel;
  type: 'string' | 'boolean';
  secret: boolean;
  /** French. */
  label: string;
  /** French: the rule, the evidence, where it is used. */
  description: string;
  /** The formula / pattern, in the allocator's own grammar when there is one. */
  expression: string | null;
  /** Tenant-wide value (default_exceptions, presence). Never for a secret. */
  defaultValue: string | boolean | null;
  /** 0..1 — how much the evidence supports the rule. */
  confidence: number;
  /** French sentences an operator can check. */
  evidence: string[];
  /** Where the variable appears in the body. */
  uses: string[];
  /** Per-site values: every site for `site`, the differing sites for
   *  `default_exceptions` / `presence`, the misfits for a `formula`. */
  siteValues: ExtrapolatedSiteValue[];
  fit: { matched: number; total: number } | null;
  /** `x-obliwan-discover`, when the infra analysis can re-read it. */
  probe: Record<string, unknown> | null;
  /** Where the name came from when it is not invented here. */
  reusedFrom: string | null;
}

export const EXTRAPOLATED_DEVIATION_KINDS = [
  'extra_line', 'missing_line', 'value', 'extra_property', 'missing_property', 'untemplatable',
] as const;
export type ExtrapolatedDeviationKind = (typeof EXTRAPOLATED_DEVIATION_KINDS)[number];

/** A difference one site (or a handful) carries and the template does NOT. */
export interface ExtrapolatedDeviation {
  deviceId: number;
  siteId: number | null;
  siteCode: string | null;
  kind: ExtrapolatedDeviationKind;
  slot: string;
  /** The device's line (redacted export) or the template's line. */
  line: string;
  /** French. */
  detail: string;
}

export interface ExtrapolatedSiteResult {
  deviceId: number;
  deviceName: string;
  siteId: number | null;
  siteCode: string | null;
  snapshotId: number | null;
  linesActual: number;
  linesRendered: number;
  linesReproduced: number;
  /** matched / (actual + rendered - matched). */
  score: number;
  /** Device lines the template does not reproduce (capped). */
  notReproduced: string[];
  /** Template lines the device does not carry (capped, redacted). */
  wouldAdd: string[];
  renderError: string | null;
}

/** What the tenant's allocation policy would need for the computed values. */
export interface ExtrapolatedPolicyFragment {
  pppLoginTemplate: string | null;
  systemIdentityTemplate: string | null;
  lanFormula: string | null;
  derived: Record<string, string>;
  /** Sites whose LAN must be RECORDED (LAN reprise) because no formula
   *  reproduces it. */
  lanRecorded: Array<{ siteId: number | null; siteCode: string | null; lan: string }>;
  /** Sites whose login / identity the allocator must hold as adopted. */
  adopted: Array<{ key: string; siteId: number | null; siteCode: string | null; value: string }>;
  /** Filled by the service: the tenant's current policy, compared. */
  current: {
    present: boolean;
    pppLoginTemplate: string | null;
    systemIdentityTemplate: string | null;
    lanFormula: string | null;
    derived: Record<string, string>;
  } | null;
}

export interface ExtrapolationRun {
  id: number;
  uuid: string;
  status: ExtrapolationRunStatus;
  modelVersion: number;
  baselineRunId: number | null;
  params: ExtrapolationParams;
  deviceCount: number;
  skippedCount: number;
  proposalCount: number;
  error: string | null;
  warnings: string[];
  startedAt: string | null;
  finishedAt: string | null;
}

export interface ExtrapolationProposalSummary {
  id: number;
  runId: number;
  clusterIndex: number;
  label: string;
  /** The router model the proposal was mined for (`groupBy: 'model'`); null
   *  when the run grouped by profile, or the model is unknown (the label then
   *  says so). */
  model: string | null;
  baselineClusterId: number | null;
  memberCount: number;
  lineCount: number;
  variableCount: number;
  deviationCount: number;
  reproductionMin: number;
  reproductionMean: number;
  gateMet: boolean;
  status: ExtrapolationProposalStatus;
  templateId: number | null;
  templateRevisionId: number | null;
  decidedAt: string | null;
  decisionNote: string | null;
}

export interface ExtrapolationProposal extends ExtrapolationProposalSummary {
  body: string;
  bodySha256: string;
  varSchema: Record<string, unknown>;
  variables: ExtrapolatedVariable[];
  policy: ExtrapolatedPolicyFragment;
  deviations: ExtrapolatedDeviation[];
  sites: ExtrapolatedSiteResult[];
  warnings: string[];
}

export const ExtrapolationApproveBody = z.object({
  name: z.string().trim().min(1).max(120),
  description: z.string().max(2000).nullable().default(null),
  /** Write the non-secret tenant/site values the proposal carries. */
  writeValues: z.boolean().default(true),
  /**
   * `templates.model_pattern` of the created template (a glob, `*` and `?`):
   * the template then applies to this router model only. Prefilled with the
   * proposal's model; empty or null = any model. A router whose model is not
   * recorded never matches a pattern — counted in `unmatchedMembers`.
   */
  modelPattern: z.string().trim().max(64).nullable().default(null)
    .transform((v) => (v === null || v === '' ? null : v)),
}).strict();
export type ExtrapolationApproveBody = z.infer<typeof ExtrapolationApproveBody>;

export const ExtrapolationRejectBody = z.object({
  note: z.string().trim().min(1).max(2000),
}).strict();
export type ExtrapolationRejectBody = z.infer<typeof ExtrapolationRejectBody>;

export interface ExtrapolationApproveResult {
  templateId: number;
  revisionId: number;
  valuesWritten: number;
  valuesAlreadySet: number;
  /** Values left alone because a different value is stored there. */
  conflicts: Array<{ scope: 'tenant' | 'site'; siteId: number | null; key: string }>;
  /** Values that could not be written (a device filed under no site). */
  skipped: number;
  /** With a model pattern: the proposal's routers whose `devices.model` is
   *  not recorded, which the pattern therefore does not match. */
  unmatchedMembers: number;
}

// ============================================================================
// Readiness — which of a client's routers the extrapolator can read
// ============================================================================

/** Why a client's MikroTik router gives the extrapolator nothing, in the
 *  order the checks run (the first one that applies is reported). */
export const EXTRAPOLATION_BLOCKED_REASONS = [
  /** Not `active` (pending, disabled, quarantined): never collected. */
  'not_active',
  /** A family the collector does not read (only RouterOS is collected). */
  'not_collectable',
  /** No enabled SSH transport with a host and a username. */
  'no_ssh',
  /** No configuration snapshot (`detail` = the last scheduled failure). */
  'no_snapshot',
  /** A snapshot, but no raw export kept (or older than a year). */
  'no_raw_export',
] as const;
export type ExtrapolationBlockedReason = (typeof EXTRAPOLATION_BLOCKED_REASONS)[number];

export interface ExtrapolationReadinessModel {
  /** Case-folded grouping key; null = model unknown. */
  model: string | null;
  /** The first spelling seen, or 'Modèle inconnu'. */
  label: string;
  devices: number;
  /** A snapshot no older than 365 days, with its raw export kept. */
  usable: number;
  /** Usable, but the snapshot is older than 30 days. */
  stale: number;
  newestSnapshotAt: string | null;
  oldestSnapshotAt: string | null;
}

export interface ExtrapolationReadinessBlocked {
  deviceId: number;
  deviceName: string;
  siteCode: string | null;
  model: string | null;
  reason: ExtrapolationBlockedReason;
  /** The collector's last error, when there is one (no_snapshot). */
  detail: string | null;
  lastFailedAt: string | null;
}

export interface ExtrapolationReadiness {
  totals: { mikrotik: number; usable: number; blocked: number };
  models: ExtrapolationReadinessModel[];
  blocked: ExtrapolationReadinessBlocked[];
  /** The tenant-wide collection in progress or last finished (null: none
   *  since the process started). */
  collect: TenantCollectState | null;
}
