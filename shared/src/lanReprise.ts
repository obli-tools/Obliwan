// ============================================================================
// @obliwan/shared — recording the real LAN of existing (adopted) sites
// ============================================================================
//
// A store already deployed on its concentrator is ADOPTED by the allocator:
// its login and its tunnel address are read from the CHR's secret. Its LAN is
// not on the CHR, so the adoption cannot take it, and a LAN rule would hand
// out a block that is not the store's. `POST /api/allocation/tenants/:id/
// lan-reprise` records each listed site's deployed LAN on its allocation
// instead (server: services/allocation/lanReprise.ts), as `lan_source`
// 'recorded' (migration 070). It writes nothing to any router.
//
// This file is the vocabulary the server answers in and the screen
// translates: closed reason codes with their parameters, never a sentence the
// client would have to show untranslated.

/** `site_provisioning.lan_source` of a LAN recorded this way. */
export const RECORDED_LAN_SOURCE = 'recorded';

/** Every value `site_provisioning.lan_source` may hold (CHECK of 070). */
export const SITE_LAN_SOURCES = ['pool', 'fixed', 'manual', RECORDED_LAN_SOURCE] as const;
export type SiteLanSource = (typeof SITE_LAN_SOURCES)[number];

/** Rows one request may carry. A tenant of a few hundred stores fits; a
 *  file of another shape (a whole inventory export) is refused as a file. */
export const LAN_REPRISE_MAX_ROWS = 2000;
/** Characters of CSV one request may carry — under `express.json`'s 1 MB. */
export const LAN_REPRISE_MAX_CHARS = 800_000;

/** Why a row is refused. Nothing is written for a refused row. */
export const LAN_REPRISE_REFUSALS = [
  /** The row has `cells` cells and the header `expected`: an unquoted
   *  delimiter inside a cell (a store name with a comma) shifts every column
   *  after it, so the LAN read from it would be another column's. */
  'row_malformed',
  /** The `code` cell is empty. */
  'code_missing',
  /** The `code` cell is a spreadsheet's number ("12.0", "1,2E+01"): its
   *  digits, and maybe its leading zeros, are lost. */
  'code_spreadsheet',
  /** No site of this workspace has this code, nor — for an all-digit cell —
   *  this site number. */
  'site_unknown',
  /** An all-digit cell whose site number several sites share ("7", "007"):
   *  a spreadsheet strips leading zeros, so the cell does not say which. */
  'site_ambiguous',
  /** Several rows name the same site: none of them is applied. */
  'site_duplicate',
  /** The site has no allocation: adopt or allocate it first. */
  'not_allocated',
  /** The `lan` cell is empty. */
  'lan_missing',
  /** The `lan` cell is not an IPv4 block a.b.c.d/nn. */
  'lan_invalid',
  /** The block has host bits set; `network` is the block it lies in. */
  'lan_not_aligned',
  /** The prefix is outside /8../30 (the allocator's LAN bounds). */
  'lan_prefix',
  /** The site already carries another LAN, and `overwrite` was not asked. */
  'lan_differs',
  /** The LAN overlaps a pool of the tenant's allocation policy, or any tunnel
   *  pool of the installation. */
  'lan_overlaps_pool',
  /** The LAN contains the tunnel address of a site allocation. */
  'lan_contains_tunnel_ip',
  /** The LAN overlaps another row of the same request: both are refused. */
  'lan_overlaps_row',
  /** The LAN overlaps the LAN another site of the workspace keeps. */
  'lan_overlaps_site',
  /** The `router_ip` cell is not an IPv4 address. */
  'router_ip_invalid',
  /** The router address is outside the LAN. */
  'router_ip_outside_lan',
  /** The router address is the LAN's network or broadcast address. */
  'router_ip_not_host',
] as const;
export type LanRepriseRefusal = (typeof LAN_REPRISE_REFUSALS)[number];

/** What an operator must read before trusting a row that is not refused. */
export const LAN_REPRISE_WARNINGS = [
  /** `overwrite`: the site's previous LAN (`current`, from `currentSource`)
   *  is replaced. A router already prepared with it keeps it. */
  'replaces_lan',
  /** The policy derives addresses inside the LAN (`derived`), and none of
   *  them is the router address given: a render of this site would move the
   *  router's LAN address. */
  'router_ip_not_derived',
  /** The policy derives no address inside the LAN yet, and the router is not
   *  on the LAN's first host: a rule cidrHost(lan_subnet, 1) would not give
   *  it. */
  'router_ip_not_first_host',
  /** One of the policy's derived values (`key`, `expression`) cannot be
   *  computed for this site with this LAN: its compile and its renders will
   *  refuse until the policy or the LAN changes. */
  'derived_invalid',
] as const;
export type LanRepriseWarningCode = (typeof LAN_REPRISE_WARNINGS)[number];

/**
 *  record     the site has no LAN; this one is (or would be) recorded.
 *  replace    the site has another LAN and `overwrite` was asked.
 *  unchanged  the site already carries exactly this LAN: nothing is written.
 *  refused    see `refusal`.
 */
export type LanRepriseVerdict = 'record' | 'replace' | 'unchanged' | 'refused';

export interface LanRepriseRefusalView {
  reason: LanRepriseRefusal;
  /** The values the sentence is built from (another site's code, a pool's
   *  name and block, the network a misaligned block lies in…). */
  params: Record<string, string>;
}

export interface LanRepriseWarning {
  code: LanRepriseWarningCode;
  params: Record<string, string>;
}

export interface LanRepriseRowResult {
  /** 1-based line of the CSV the row starts on (the header is line 1). */
  line: number;
  /** The cells as given (trimmed). */
  code: string;
  lan: string;
  routerIp: string | null;
  /** The site the row names, or null when none could be matched. */
  site: { id: number; code: string; name: string } | null;
  /** The cell matched the site by its NUMBER, its leading zeros restored
   *  ("2" -> "00002"). */
  codeRestored: boolean;
  /** The site's allocation as it stands before this request (null when it has
   *  none, or when no site was matched). */
  current: { lanSubnet: string | null; lanSource: SiteLanSource | null } | null;
  verdict: LanRepriseVerdict;
  refusal: LanRepriseRefusalView | null;
  /** The block as recorded (network address / prefix), null when refused. */
  lanSubnet: string | null;
  /** What the site's computed values resolve to with this LAN: `lan_subnet`
   *  and the policy's derived values (e.g. `lan_router_ip`). Null when the row
   *  is refused or the policy cannot be read. */
  values: Record<string, string> | null;
  warnings: LanRepriseWarning[];
}

export interface LanRepriseResult {
  tenantId: number;
  /** True: nothing was written. */
  dryRun: boolean;
  overwrite: boolean;
  counts: Record<LanRepriseVerdict, number>;
  /** Columns of the file this request does not read (e.g. `name`). */
  ignoredColumns: string[];
  /** Set when the tenant's allocation policy cannot be used ('no_policy',
   *  'invalid_policy'): rows are still judged and recorded, but no derived
   *  value is computed for them. Its pools are still read from the stored
   *  row, valid or not, and checked. */
  policyProblem: 'no_policy' | 'invalid_policy' | null;
  /** The `audit_log.correlation_id` shared by every row this request wrote;
   *  null on a dry run or when nothing was written. */
  correlationId: string | null;
  rows: LanRepriseRowResult[];
}
