// ObliWAN — each customer's INFRASTRUCTURE VPN concentrator (migration 074).
//
// The management concentrator (the shared CHR, `concentrator_secret`) carries
// ObliWAN's own path to every store. A customer ALSO runs its own
// infrastructure concentrator that every store connects to for business
// traffic: a second RouterOS CHR (one L2TP-over-IPsec login per store) or an
// OPNsense firewall terminating one IPsec tunnel per store. This file is the
// vocabulary both sides share: the closed kinds and states, the views the API
// answers in, and the change-job kind that is the ONLY way ObliWAN writes on
// such a concentrator.
//
// What is real and what is not, as of 2026-10-05:
//   - routeros_chr  read, plan, apply (one additive /ppp/secret) and revoke
//                   (only an entry ObliWAN itself added), through the queue;
//   - opnsense      connection test only (REST API, pinned certificate). Its
//                   plan/apply/revoke REFUSE with `NOT_IMPLEMENTED_YET` until the
//                   operator's mass-provisioning PowerShell scripts have been
//                   analysed — the tunnel model is not invented here.

/** The change-job kind (shared/src/change.ts CHANGE_JOB_KINDS, migration 074). */
export const INFRA_ACCOUNT_KIND = 'infra_account' as const;

export const INFRA_CONCENTRATOR_KINDS = ['routeros_chr', 'opnsense'] as const;
export type InfraConcentratorKind = (typeof INFRA_CONCENTRATOR_KINDS)[number];

export const INFRA_ACCOUNT_KINDS = ['l2tp_secret', 'ipsec_tunnel'] as const;
export type InfraAccountKind = (typeof INFRA_ACCOUNT_KINDS)[number];

/** Mirrors `infra_site_accounts_state_chk` (074). */
export const INFRA_ACCOUNT_STATES = ['planned', 'provisioned', 'revoked', 'error'] as const;
export type InfraAccountState = (typeof INFRA_ACCOUNT_STATES)[number];

/** What one `infra_account` job does. Mirrors `infra_account_jobs_action_chk`. */
export const INFRA_ACCOUNT_ACTIONS = ['ensure', 'revoke'] as const;
export type InfraAccountAction = (typeof INFRA_ACCOUNT_ACTIONS)[number];

/** What a job found. Mirrors `infra_account_jobs_outcome_chk`. */
export const INFRA_ACCOUNT_OUTCOMES = ['added', 'present', 'removed', 'absent', 'conflict'] as const;
export type InfraAccountOutcome = (typeof INFRA_ACCOUNT_OUTCOMES)[number];

/** The account a concentrator kind carries per site. */
export function infraAccountKindFor(kind: InfraConcentratorKind): InfraAccountKind {
  return kind === 'routeros_chr' ? 'l2tp_secret' : 'ipsec_tunnel';
}

/**
 * Where a site's account values come from: KEYS of the tenant's template
 * variables (computed, stored, or secret), never values. The defaults are the
 * names used by customer A's conversion (`infra_ppp_username` = the site code,
 * `infra_ppp_password` a tenant secret). `remoteAddressKey` null = the add sends
 * no `remote-address=` and none is compared (the CHR's pool decides);
 * `pppProfile` null = the CHR's `default` profile, not compared on an entry
 * found already present.
 */
export interface InfraConcentratorParams {
  usernameKey: string;
  passwordKey: string;
  remoteAddressKey: string | null;
  pppProfile: string | null;
}

export const DEFAULT_INFRA_CONCENTRATOR_PARAMS: Readonly<InfraConcentratorParams> = Object.freeze({
  usernameKey: 'infra_ppp_username',
  passwordKey: 'infra_ppp_password',
  remoteAddressKey: null,
  pppProfile: null,
});

/** A concentrator as the API shows it. Never a credential: `hasCredential`
 *  says whether the vault holds one. */
export interface InfraConcentratorView {
  id: number;
  tenantId: number;
  kind: InfraConcentratorKind;
  name: string;
  /** The address the stores dial (CHR), or the REST API host (OPNsense). */
  host: string;
  port: number | null;
  /** CHR: the devices row whose RouterOS API transport ObliWAN uses. */
  deviceId: number | null;
  deviceName: string | null;
  enabled: boolean;
  params: InfraConcentratorParams;
  hasCredential: boolean;
  /** OPNsense: the pinned SHA-256 of the API certificate (lowercase hex). */
  tlsFingerprint: string | null;
  lastTestAt: string | null;
  lastTestOk: boolean | null;
  lastTestMessage: string | null;
  accountCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface InfraSiteAccountView {
  id: number;
  tenantId: number;
  siteId: number;
  concentratorId: number;
  concentratorName: string;
  concentratorKind: InfraConcentratorKind;
  accountKind: InfraAccountKind;
  identifier: string;
  state: InfraAccountState;
  lastJobId: number | null;
  /** The last job's status, when there is one. */
  lastJobStatus: string | null;
  observedAt: string | null;
  detail: string | null;
  updatedAt: string;
}

/** One driver answer, in French for the operator, with a closed code. */
export interface InfraDriverResult {
  ok: boolean;
  /** e.g. OK, NOT_IMPLEMENTED_YET, AUTH_REFUSED, TLS_PIN_MISMATCH, UNREACHABLE. */
  code: string;
  message: string;
  /** Further facts, one French sentence each. Never a credential. */
  details: string[];
}

/** The plan for one site: what is desired against what was read. */
export type InfraPlanAction = 'add' | 'present' | 'remove' | 'absent' | 'conflict' | 'refused';

export interface InfraPlanView {
  concentratorId: number;
  siteId: number;
  action: InfraAccountAction;
  decision: InfraPlanAction;
  identifier: string | null;
  /** French. */
  message: string;
  reasons: string[];
  /** What was read for this site on the concentrator (never a password). */
  observed: Array<Record<string, string | boolean | null>>;
  code: string;
}

/** Where an `infra_account` job stands. */
export interface InfraAccountJobState {
  jobId: number | null;
  state: 'pending' | 'succeeded' | 'failed';
  outcome: InfraAccountOutcome | null;
  message: string;
  code?: string;
}
