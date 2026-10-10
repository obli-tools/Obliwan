// ============================================================================
// ObliWAN — learning mode (the no-secrets exception of 2026-10-04)
// ============================================================================
//
// A router in LEARNING mode is one whose production configuration ObliWAN is
// learning from, before any template is allowed to write to it:
//
//  - while the flag is set, every TEMPLATE-DRIVEN write (a `push` change job,
//    and therefore a plan compile, a rollout wave) is refused by name; the
//    targeted jobs (management access, compliance, APN, OS upgrade, restore…)
//    stay allowed (`learningBlocksJob`);
//  - a CAPTURE reads the export WITH its secrets (the one operator-approved
//    exception to the no-secrets rule), over SSH, with the legacy administrator account when
//    the site's vault holds it. The export is parsed IN MEMORY: every secret
//    goes to the vault, encrypted, attached to the site; the copies kept carry
//    `secret:<ref>` in its place, and a line whose secret cannot be cut out (a
//    script source, a comment) is withheld whole. The raw export is never
//    stored, logged or written to disk;
//  - each capture yields the site's learned FACTS (WAN1 mode, PPPoE name, LAN,
//    time zone, APN…), a redacted dataset an operator can hand over, and a
//    break-risk report: a template against what production runs.
//
// Shared by the server (which enforces every rule) and the client (which only
// renders): codes are closed unions the screen translates.

/** What a vaulted value is replaced with in every stored copy. */
export const LEARNING_PLACEHOLDER_PREFIX = 'secret:';

export function learningPlaceholder(ref: string): string {
  return `${LEARNING_PLACEHOLDER_PREFIX}${ref}`;
}

/**
 * The grammar of a secret reference: `<menu path, dotted>.<item>.<prop>`,
 * lower case, e.g. `interface.l2tp-client.l2tp-mgmt.password`. A collision
 * inside one export gets `~2`, `~3`. Enforced in code (never by a database
 * CHECK: no regex in a CHECK, knex rewrites `?`).
 */
export const LEARNING_REF_RE = /^[a-z0-9][a-z0-9._~-]{0,199}$/;

/** Devices per capture run, per state change, per dataset. */
export const LEARNING_MAX_DEVICES = 500;
/** Captures kept per device; older ones are pruned. */
export const LEARNING_CAPTURES_KEPT = 5;
/** A `running` capture older than this reads as `interrupted` (a restart). */
export const LEARNING_STALE_RUN_MS = 15 * 60_000;

export const LEARNING_CAPTURE_STATUSES = ['running', 'succeeded', 'failed', 'skipped'] as const;
export type LearningCaptureStatus = (typeof LEARNING_CAPTURE_STATUSES)[number];

/** Which account dialled: the site's legacy administrator (`admin` +
 *  `admin_password` from the vault), or the device's own SSH credential. */
export const LEARNING_ACCOUNTS = ['legacy_admin', 'device_ssh'] as const;
export type LearningAccount = (typeof LEARNING_ACCOUNTS)[number];

/** Why a capture was skipped or failed. Spelled as literals in migration 089. */
export const LEARNING_CAPTURE_REASONS = [
  'not_learning',
  'not_mikrotik',
  'concentrator',
  'not_active',
  'no_site',
  'no_ssh',
  'no_credential',
  'concentrator_degraded',
  'ppp_down',
  'identity_mismatch',
  'identity_unproven',
  'auth_failed',
  'unreachable',
  'timeout',
  'ssh_failed',
  'no_sensitive_policy',
  'policy_unknown',
  'family_mismatch',
  'export_failed',
  'export_empty',
  'redaction_incomplete',
  'interrupted',
  'internal',
] as const;
export type LearningCaptureReason = (typeof LEARNING_CAPTURE_REASONS)[number];

/** The `code` a refused plan, push or rollout carries for a learning router. */
export const LEARNING_REFUSAL_KIND = 'device_learning' as const;

/**
 * Does learning mode refuse a change job of this kind?
 *
 * Only `push` — the one kind that carries a template-compiled plan. Every
 * TARGETED job (management_access, lte_apn, legacy_compliance, os_upgrade,
 * restore, reboot, export, backup, concentrator jobs…) stays allowed: they are
 * the gestures that make a legacy router manageable at all, and none of them
 * applies a template.
 */
export function learningBlocksJob(kind: string): boolean {
  return kind === 'push';
}

// ============================================================================
// Learned facts — per site, from one capture
// ============================================================================

export const LEARNED_WAN1_MODES = ['dhcp', 'pppoe', 'static', 'none', 'ambiguous'] as const;
export type LearnedWan1Mode = (typeof LEARNED_WAN1_MODES)[number];

/** Every array of the facts is capped at this many items. */
export const LEARNED_FACTS_ARRAY_CAP = 32;

export interface LearnedLan {
  status: 'found' | 'not_found' | 'ambiguous' | 'unreadable';
  interface: string | null;
  lan: string | null;
  routerIp: string | null;
  candidates: Array<{ interface: string; address: string }>;
}

export interface LearnedSiteFacts {
  factsVersion: 1;
  identity: string | null;
  osVersion: string | null;
  model: string | null;
  wan1: {
    /** The name given to the port whose default-name is ether1. */
    port: string;
    mode: LearnedWan1Mode;
    pppoeName: string | null;
    staticAddress: string | null;
    staticGateway: string | null;
  };
  pppoeClients: Array<{
    name: string;
    interface: string | null;
    disabled: boolean;
    /** ADSL / FTTH / FTTO when the name is one of the fleet's uplink names. */
    uplinkName: string | null;
    inWanList: boolean;
  }>;
  /** Members of the WAN interface list. */
  wanList: string[];
  lan: LearnedLan;
  timezone: string | null;
  lte: {
    interfaces: string[];
    apnProfiles: Array<{ name: string; apn: string | null }>;
    selectedProfiles: string[];
  };
  defaultRoutes: Array<{ gateway: string | null; distance: string | null; comment: string | null; disabled: boolean }>;
  netwatch: Array<{ host: string | null; comment: string | null; disabled: boolean }>;
  l2tpClients: Array<{ name: string; connectTo: string | null; disabled: boolean }>;
  ipsecPeers: Array<{ name: string | null; address: string | null }>;
  dnsServers: string[];
  ntpServers: string[];
  scripts: string[];
  schedulers: string[];
  counts: { lines: number; filter: number; nat: number; mangle: number; addressList: number };
}

// ============================================================================
// Captures, secrets, rows
// ============================================================================

/** A vaulted secret, as the screen sees it: never a value. */
export interface LearnedSecretRef {
  id: number;
  ref: string;
  menu: string;
  item: string | null;
  prop: string;
  /** Per-tenant HMAC of the value: equal secrets compare equal within one
   *  workspace, never across workspaces. Null when the vault key is absent. */
  fingerprint: string | null;
  /** How many distinct sites of the workspace hold the same value. */
  sharedWithSites: number;
  lastSeenAt: string;
  vanishedAt: string | null;
}

/** A line withheld from the stored copies: its secret sits inside a quoted
 *  value (a script source, a comment) and could not be cut out. */
export interface LearningWithheldLine {
  /** 1-based line number in the redacted copy. */
  line: number;
  menu: string;
  props: string[];
}

export interface LearningCaptureSummary {
  id: number;
  runId: string;
  status: LearningCaptureStatus;
  reason: LearningCaptureReason | null;
  detail: string | null;
  account: LearningAccount | null;
  startedAt: string;
  finishedAt: string | null;
  wan1Mode: LearnedWan1Mode | null;
  pppoeName: string | null;
  timezone: string | null;
  apns: string[];
  secretCount: number | null;
  withheldCount: number;
  snapshotId: string | null;
  snapshotError: string | null;
}

export interface LearningDeviceRow {
  deviceId: number;
  deviceName: string;
  tenantId?: number;
  tenantName?: string | null;
  site: { id: number; code: string; name: string } | null;
  status: string;
  learning: { since: string; byUserId: number | null } | null;
  lastCapture: LearningCaptureSummary | null;
}

export interface LearningRunRow {
  captureId: number;
  deviceId: number;
  deviceName: string;
  status: LearningCaptureStatus;
  reason: LearningCaptureReason | null;
  detail: string | null;
  startedAt: string;
  finishedAt: string | null;
}

export interface LearningRunView {
  runId: string;
  status: 'running' | 'done';
  total: number;
  counts: Record<LearningCaptureStatus, number>;
  rows: LearningRunRow[];
}

export interface LearningCaptureDetail {
  captureId: number;
  deviceId: number;
  deviceName: string;
  status: LearningCaptureStatus;
  reason: LearningCaptureReason | null;
  detail: string | null;
  account: LearningAccount | null;
  family: string | null;
  osVersion: string | null;
  model: string | null;
  startedAt: string;
  finishedAt: string | null;
  facts: LearnedSiteFacts | null;
  secrets: LearnedSecretRef[];
  withheld: LearningWithheldLine[];
  snapshotId: string | null;
  snapshotError: string | null;
  redactedBytes: number | null;
  redactedSha256: string | null;
}

export interface LearningStateResult {
  changed: number[];
  skipped: Array<{ deviceId: number; reason: 'not_mikrotik' | 'concentrator' | 'not_found' }>;
}

export interface LearningCaptureStart {
  runId: string;
  total: number;
}

// ============================================================================
// Break-risk report — a template against production
// ============================================================================

export const BREAK_RISK_DOMAINS = [
  'uplink', 'interfaces', 'addresses', 'routes', 'nat', 'firewall', 'address_lists',
  'ipsec', 'ppp', 'dhcp', 'dns', 'bridge_vlan', 'management', 'users', 'scripts',
  'netwatch', 'lte', 'wireless', 'qos', 'snmp', 'time', 'logging', 'other',
] as const;
export type BreakRiskDomain = (typeof BREAK_RISK_DOMAINS)[number];

export const BREAK_RISK_REASONS = [
  'plan_op', 'uplink_preserved', 'blocked', 'management_path', 'deletion',
  'comment_selector', 'production_only', 'template_only', 'unmodeled',
  'inert_addition', 'verify_only',
] as const;
export type BreakRiskReason = (typeof BREAK_RISK_REASONS)[number];

export interface BreakRiskRow {
  source: 'plan' | 'text';
  verdict: 'flagged' | 'harmless';
  domain: BreakRiskDomain;
  side: 'production_only' | 'template_only' | null;
  line: string;
  opSeq: number | null;
  risk: 'low' | 'medium' | 'high' | null;
  reasons: BreakRiskReason[];
  /** A server sentence (English), shown verbatim. */
  detail: string | null;
}

export interface BreakRiskReport {
  deviceId: number;
  deviceName: string;
  revision: { id: string; templateName: string | null; revision: number } | null;
  snapshot: { id: string; capturedAt: string } | null;
  renderError: string | null;
  counts: { flagged: number; harmless: number; identicalLines: number };
  rows: BreakRiskRow[];
}

// ============================================================================
// The redacted dataset an operator hands over
// ============================================================================

/**
 * NOT pseudonymised (operator decision): logins, public addresses and store
 * names stay readable so the analysis stays readable. Never versioned — it is
 * kept outside the repository. Secrets never appear: `secret:<ref>` only.
 */
export interface LearningDataset {
  format: 'obliwan-learning-dataset';
  version: 1;
  notice: string;
  tenant: { id: number; name: string | null };
  generatedAt: string;
  templates: Array<{ revisionId: string; name: string; revision: number; body: string | null }>;
  devices: Array<{
    site: { id: number; code: string; name: string } | null;
    device: { id: number; name: string; model: string | null; osVersion: string | null };
    template: { revisionId: string; name: string; revision: number } | null;
    capturedAt: string;
    account: LearningAccount | null;
    facts: LearnedSiteFacts | null;
    secrets: Array<{ ref: string; menu: string; item: string | null; prop: string; fingerprint: string | null }>;
    withheld: LearningWithheldLine[];
    export: string;
  }>;
  summary: {
    wan1Modes: Record<string, number>;
    pppoeNames: Record<string, number>;
    timezones: Record<string, number>;
    apns: Record<string, number>;
    models: Record<string, number>;
    osVersions: Record<string, number>;
    staticSites: Array<{ code: string | null; device: string; address: string | null; gateway: string | null }>;
    secretSharing: Array<{ menu: string; prop: string; distinctValues: number; sites: number }>;
  };
}
