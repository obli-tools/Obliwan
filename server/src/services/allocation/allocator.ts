import type { Knex } from 'knex';
import { INSTANCE_SETTINGS_KEYS, MASTER_TENANT_ID, RECORDED_LAN_SOURCE, type SiteLanSource } from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { refreshSecretInventory } from '../fleet/concentratorDiscovery.service';
import { currentKeyVersion, decrypt, encrypt } from '../secretVault.service';
import { AllocationError, assertId, isPgError } from './errors';
import { takeAllocationLock } from './lock';
import {
  PG_INT_MAX,
  cidrContains,
  describeHolder,
  formatCidr,
  formatIpv4,
  parseCidr,
  parseIpv4,
  planSites,
  policyConflicts,
  siteLabel,
  validatePolicyInput,
  SHARED_PPP_PASSWORD_KEY,
  adoptedPasswordWarning,
  siteCodeFormatColumn,
  type LanMode,
  type PppPasswordMode,
  type AddressMode,
  type AddressPool,
  type AllocationPolicy,
  type AllocationRefusal,
  type AllocationState,
  type DeclaredSecret,
  type ForeignAllocation,
  type PlanSource,
  type LoginContext,
  type LoginHolder,
  type PolicyPoolRef,
  type SiteFacts,
  type SitePlan,
  type TakenAddress,
  type TakenBlock,
} from './policy';
import {
  PPP_LOGIN_MAX,
  generatePppPassword,
  minimalLoginLength,
  normalizeCountry,
  renderPppLogin,
  renderSystemIdentity,
} from './pppIdentity';
import { derivedToJson, evaluateDerived } from './derived';
import {
  SEED_MAX_AGE_MS,
  fromTrusted,
  seedConcentrators,
  seedFreshness,
  trustedConcentrators,
  type PolicySeedRef,
} from './seed';

/**
 * allocator.ts — hands a site its PPP identity and its addresses, once.
 *
 * ┌─ ONE LOCK FOR THE WHOLE ADDRESS SPACE ───────────────────────────────────┐
 * │ Allocations, releases, policy saves, pool creations, instance-domain     │
 * │ saves and the CHR secret inventory writer all take `takeAllocationLock`  │
 * │ (lock.ts): one key, held until commit. Tunnel addresses and PPP logins    │
 * │ are unique ACROSS tenants and a pool may be shared, so a per-tenant key  │
 * │ would let two clerks read the same free address. The cost is nil at     │
 * │ this scale.                                                              │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ IDEMPOTENT, BECAUSE A BENCH RETRIES ────────────────────────────────────┐
 * │ `allocateForSite` on a site that already has a row returns THAT row and  │
 * │ `created: false`. Never a second address: the first one may already be   │
 * │ on a CPE, or on the CHR. The check runs once before the lock (the cheap   │
 * │ answer for a retry) and once after it (the one that is actually true      │
 * │ when two requests race). Undoing an allocation is a separate, explicit   │
 * │ gesture: `releaseAllocation`, refused once the CHR has taken it.         │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ SEEDED FROM THE CONCENTRATORS, NEVER DIALLED UNDER THE LOCK ────────────┐
 * │ Incremental pools already hold deployed sites, numbered by hand long     │
 * │ before this module. An allocation rests on a CURRENT read of the         │
 * │ /ppp/secret of every GATING CHR — the tenant's own, and the CHR of every │
 * │ policy sharing its tunnel pool (seed.ts) — which persists each declared  │
 * │ secret's name, remote-address and local-address in                       │
 * │ `concentrator_ppp_secrets`, and the read itself in                       │
 * │ `concentrator_secret_reads`. "Current" is SEED_MAX_AGE_MS: a gating CHR  │
 * │ read longer ago is re-read by `refreshSecretInventory` BEFORE the        │
 * │ allocation's transaction opens — never inside it, and with no lock held  │
 * │ across the dial — and the transaction then refuses NOT_SEEDED (never     │
 * │ read) or STALE_SEED (too old) for any gating CHR that is still not       │
 * │ current. A walk over a pool whose deployed sites are unknown would hand  │
 * │ their addresses out again.                                               │
 * │                                                                          │
 * │ The bound leaves a window: a secret typed by hand on the CHR within the  │
 * │ last SEED_MAX_AGE_MS is invisible here. The concentrator job must look    │
 * │ for the name and the remote-address on the CHR before its                │
 * │ `/ppp secret add`, and a clash it finds is undone with                   │
 * │ `releaseAllocation`, then allocated again (which re-reads the CHR).      │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ A DEPLOYED SITE IS ADOPTED, NOT REFUSED ────────────────────────────────┐
 * │ When the login the policy computes for a site is a secret the policy's   │
 * │ OWN CHR declares (as of the same current read), the site is deployed:    │
 * │ the engine ADOPTS it (policy.ts, `adoptDeclared`) and the row records    │
 * │ the CHR's spelling of the login, the secret's remote-address and its     │
 * │ profile, with `source` = 'adopted_chr' (migration 044). The LAN, the     │
 * │ identity and the derived values still come from the policy. Nothing is   │
 * │ written to the CHR, and its password is never read: a 'shared'           │
 * │ row needs none stored; a 'per_site' row stores NONE, and every reader of │
 * │ the password refuses it by name (PASSWORD_UNKNOWN) rather than invent    │
 * │ one or fall back to the shared one. The row starts 'pending' like any    │
 * │ other: "provisioned" is said only by a concentrator job that read the CHR │
 * │ (concentratorSecret.service finds the secret present and writes nothing).│
 * │ Released, an adopted row frees nothing on the CHR: the secret still holds │
 * │ its login and address there, and the next allocation adopts it again.    │
 * │ What cannot be this site's is REFUSED by name, nothing written: a        │
 * │ dynamic secret, an address another holder has or that lies in another    │
 * │ tenant's tunnel pool, a login held elsewhere (`adoptDeclared` lists      │
 * │ them).                                                                   │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ "FREE" MEANS FREE EVERYWHERE THIS SERVER CAN BELIEVE ───────────────────┐
 * │ A tunnel address is held if a `site_provisioning` row has it, if a        │
 * │ device's `tunnel_ip` is it, or — for a CHR this tenant's allocation       │
 * │ believes (seed.ts, "WHOSE CHR COUNTS": one a policy names, one of the    │
 * │ master tenant, or one of the tenant's own) — if a LIVE PPP session there │
 * │ carries it or a secret there declares it, as remote-address or           │
 * │ local-address, and has not vanished from the CHR's last read. The same   │
 * │ sources, by name and WITHOUT REGARD TO CASE, decide whether a PPP login   │
 * │ is taken. A CHR nobody vouches for cannot hold another tenant's values:  │
 * │ any tenant user may declare a concentrator and scan it.                  │
 * │                                                                          │
 * │ `devices` is NOT filtered that way, on purpose: a device's tunnel_ip is  │
 * │ how the hand-numbered legacy fleet is protected, and filtering it by      │
 * │ tenant would hand a live address out again. The price is stated: a      │
 * │ tenant user with DEVICE_WRITE can hold an address of any pool by writing │
 * │ it as a device's tunnel_ip (and a login, through a concentrator of its   │
 * │ own tenant — device.service.ts states that gap). The refusal names       │
 * │ "another tenant's device", and a platform administrator can correct it. │
 * │                                                                          │
 * │ `discoveries` is NOT a source: its rows are never retired, so a stale    │
 * │ one held its address for good — in formula mode a site refused forever,  │
 * │ with nothing able to free it. Every holder that remains has an operation │
 * │ that frees it (policy.ts, `holderRemedy`): a site allocation is released,│
 * │ a device corrected, a stale secret removed from the CHR (seen at the     │
 * │ next re-read), a session ends. A stale holder costs one address in       │
 * │ incremental mode and one refused site in formula mode until that is done;│
 * │ the opposite mistake costs a customer.                                   │
 * │                                                                          │
 * │ Tunnel addresses and LAN subnets are ONE address space: no tunnel        │
 * │ address is taken from inside any site's LAN subnet. A LAN drawn from a   │
 * │ LAN pool is never carved over a held tunnel address. A FIXED or MANUAL   │
 * │ LAN (no pool) is refused when it contains the site's own tunnel address  │
 * │ or one held in the tenant's tunnel pool (policy.ts, `tunnelInsideLan`);  │
 * │ it is NOT checked against other tenants' tunnel pools at allocation —    │
 * │ only a fixed LAN is, against every tunnel pool, when the policy is       │
 * │ saved. LAN subnets do not overlap within a tenant, nor within the pool   │
 * │ they are drawn from (policy.ts, UNIQUENESS) — except a tenant's FIXED    │
 * │ LAN, which every site of that tenant holds by design (migration 039      │
 * │ takes those rows out of the unique index).                               │
 * │                                                                          │
 * │ WHAT THE LOCK DOES NOT COVER. Writers of `devices` and `ppp_sessions` do │
 * │ not take it. Those tables are read ONCE, inside the transaction, so a    │
 * │ device saved or a session opened between that read and the commit is    │
 * │ not seen — and no constraint fires either, because every UNIQUE involved │
 * │ is local to `site_provisioning`. Two allocations can never collide with  │
 * │ each other; an allocation and one of those writers can. Closing it means │
 * │ those writers taking the same lock; until they do, the check is          │
 * │ read-time only.                                                          │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * A 'per_site' PPP password is generated, encrypted and inserted inside
 * one expression and is never bound to a name that outlives it. A 'shared' one
 * is never copied per site: it is read from the INSTANCE variable
 * SHARED_PPP_PASSWORD_KEY when it is needed. Neither is logged, and neither is
 * returned except by `revealPppCredential` and `computedForSite`, which are
 * for the server-side compile path and the concentrator job ONLY.
 */

/** Upper bound on a preview batch — a bulk import of a few hundred sites fits,
 *  a typo in a script does not make the server plan ten thousand. */
export const PREVIEW_MAX = 500;

/** Longest `concentrator_error` kept. The text is shown on an operator's
 *  screen; a full RouterOS trace is the job log's business. */
const CONCENTRATOR_ERROR_MAX = 2000;

export const CONCENTRATOR_STATES = ['pending', 'provisioned', 'failed'] as const;
export type ConcentratorState = (typeof CONCENTRATOR_STATES)[number];

// ============================================================================
// Rows and views
// ============================================================================

interface PoolRow {
  id: number;
  name: string;
  cidr: string;
  purpose: string;
}

interface PolicyRow {
  tenant_id: number;
  tunnel_pool_id: number;
  tunnel_mode: string;
  tunnel_start: string | null;
  tunnel_formula: string | null;
  lan_pool_id: number | null;
  lan_mode: string | null;
  lan_prefix: number | null;
  lan_formula: string | null;
  lan_fixed_subnet: string | null;
  lan_variable: string | null;
  ppp_login_template: string;
  identity_template: string | null;
  ppp_password_mode: string;
  derived_values: Record<string, unknown> | null;
  ppp_profile: string | null;
  concentrator_id: number;
  /** Migration 052: NULL = free, 'digits:N'. */
  site_code_format: string | null;
  created_at: Date;
  updated_at: Date;
}

const POLICY_COLUMNS = [
  'tenant_id',
  'tunnel_pool_id',
  'tunnel_mode',
  // host() drops the /32 an inet carries, so the text parses as an address.
  db.raw('host(tunnel_start) AS tunnel_start'),
  'tunnel_formula',
  'lan_pool_id',
  'lan_mode',
  'lan_prefix',
  'lan_formula',
  'lan_fixed_subnet',
  'lan_variable',
  'ppp_login_template',
  'identity_template',
  'ppp_password_mode',
  'derived_values',
  'ppp_profile',
  'concentrator_id',
  'site_code_format',
  'created_at',
  'updated_at',
];

interface ProvisioningRow {
  site_id: number;
  tenant_id: number;
  ppp_username: string;
  tunnel_ip: string;
  lan_subnet: string | null;
  lan_source: SiteLanSource | null;
  ppp_password_mode: PppPasswordMode;
  /** Whether a per-site password is vaulted — never the blob itself. */
  ppp_password_stored: boolean;
  system_identity: string | null;
  concentrator_id: number;
  ppp_profile: string | null;
  concentrator_state: ConcentratorState;
  // bigint: node-pg returns it as a string.
  concentrator_job_id: string | number | null;
  concentrator_error: string | null;
  source: PlanSource | null;
  formula_tunnel_ip: string | null;
  allocated_at: Date;
  updated_at: Date;
}

/** The columns a view is built from, for `site_provisioning` aliased as
 *  `alias` (none, or e.g. 'p'). No password blob: only whether one exists. */
function publicColumns(alias = ''): Array<string | Knex.Raw> {
  const c = (name: string): string => (alias ? `${alias}.${name}` : name);
  return [
    c('site_id'),
    c('tenant_id'),
    c('ppp_username'),
    db.raw(`host(${c('tunnel_ip')}) AS tunnel_ip`),
    c('lan_subnet'),
    c('lan_source'),
    c('ppp_password_mode'),
    db.raw(`(${c('ppp_password_enc')} IS NOT NULL) AS ppp_password_stored`),
    c('system_identity'),
    c('concentrator_id'),
    c('ppp_profile'),
    c('concentrator_state'),
    c('concentrator_job_id'),
    c('concentrator_error'),
    c('source'),
    db.raw(`host(${c('formula_tunnel_ip')}) AS formula_tunnel_ip`),
    c('allocated_at'),
    c('updated_at'),
  ];
}

export interface PolicyRuleView {
  poolId: number;
  poolName: string | null;
  poolCidr: string | null;
  mode: AddressMode;
  /** incremental tunnel only */
  start: string | null;
  /** incremental LAN only */
  prefix: number | null;
  /** formula only */
  formula: string | null;
}

/** A LAN rule as the API shows it. `poolId` is null for 'fixed' and 'manual'. */
export interface LanRuleView {
  mode: LanMode;
  poolId: number | null;
  poolName: string | null;
  poolCidr: string | null;
  prefix: number | null;
  formula: string | null;
  subnet: string | null;
  variable: string | null;
}

export interface AllocationPolicyView {
  tenantId: number;
  tunnel: PolicyRuleView;
  lan: LanRuleView | null;
  pppLoginTemplate: string;
  systemIdentityTemplate: string | null;
  pppPasswordMode: PppPasswordMode;
  derived: Record<string, string>;
  pppProfile: string | null;
  concentratorId: number;
  /** 'free' or 'digits:N' (migration 052), the spelling the PUT body takes. */
  siteCodeFormat: string;
  createdAt: string;
  updatedAt: string;
}

/** A site's allocation as the API shows it. There is no password field, not
 *  even a masked one: the only reader of the password is server-side. */
export interface SiteProvisioningView {
  siteId: number;
  tenantId: number;
  pppUsername: string;
  tunnelIp: string;
  lanSubnet: string | null;
  /** 'recorded' (migration 070): typed from the deployed store by the LAN
   *  reprise (lanReprise.ts), not computed by a rule. */
  lanSource: SiteLanSource | null;
  pppPasswordMode: PppPasswordMode;
  systemIdentity: string | null;
  /** Frozen at allocation (migration 036): the CHR this allocation was checked
   *  against and must be written on, whatever the policy says today. */
  concentratorId: number;
  /** Frozen at allocation, from the policy of that moment. */
  pppProfile: string | null;
  concentratorState: ConcentratorState;
  concentratorJobId: number | null;
  concentratorError: string | null;
  /** 'allocated' (computed from the policy), 'adopted_chr' (read from a
   *  secret the CHR already declared — a deployed site), or null for a row
   *  written before provenance was recorded (migration 044). */
  source: PlanSource | null;
  /** Adopted rows only: what the tunnel formula rendered at adoption when it
   *  differed from the CHR's address (`tunnelIp` is the CHR's). */
  formulaTunnelIp: string | null;
  /** false only for a 'per_site' row with no vaulted password — an adopted
   *  one: the password is on the CHR, never read, and nothing can be
   *  compiled for that site. Says nothing about the shared password. */
  pppPasswordKnown: boolean;
  allocatedAt: string;
  updatedAt: string;
}

/**
 * IN MEMORY ONLY. The PPP credential of one site, for the server-side
 * CPE render and the concentrator job. Never put it in a response, a log line,
 * a PlanOp, `change_job_steps.output_redacted` or an error message.
 */
export interface PppCredential {
  siteId: number;
  tenantId: number;
  pppUsername: string;
  pppPassword: string;
  tunnelIp: string;
  lanSubnet: string | null;
  /** FROZEN at allocation, never read from today's policy: re-pointing a
   *  tenant at another CHR moves no site already allocated — that allocation
   *  was checked against its own CHR's secrets only. To move a site that the
   *  CHR has not taken yet, release it and allocate it again. */
  pppProfile: string | null;
  concentratorId: number;
}

/** Where the seeding of one concentrator stands. */
export interface SeedStatus {
  concentratorId: number;
  /** Last SUCCESSFUL read of its /ppp/secret; null = never read. */
  readAt: string | null;
  /** Secrets that read returned; null = never read. */
  secretCount: number | null;
  /** Read within SEED_MAX_AGE_MS of the moment this status was computed: an
   *  allocation may rest on it without re-reading the CHR. */
  fresh: boolean;
}

/** One site of a preview batch, as the caller described it. */
export interface SiteDraft {
  code: string;
  name: string;
  country?: string | null;
  /** The site's LAN, for a tenant in manual LAN mode. */
  lanSubnet?: string | null;
}

export interface PreviewEntry {
  /** Position in the request. */
  index: number;
  /** The site row previewed, or null for a draft. */
  siteId: number | null;
  code: string;
  name: string;
  plan: SitePlan | null;
  refusal: AllocationRefusal | null;
}

export interface AllocationPreview {
  tenantId: number;
  policy: AllocationPolicyView;
  /** Every GATING concentrator (seed.ts): the tenant's own CHR, and the CHR of
   *  every policy sharing its tunnel pool, after the preview re-read the ones
   *  that were not fresh. */
  seeds: SeedStatus[];
  /** Set when an allocation made now would be refused whatever the site,
   *  because a gating CHR is still not fresh after the re-read attempt
   *  (NOT_SEEDED: never read; STALE_SEED: read too long ago). The entries are
   *  still computed, on what is known. */
  blockedBy: { reason: 'NOT_SEEDED' | 'STALE_SEED'; concentratorIds: number[]; message: string } | null;
  /** In request order, each planned as if every earlier success had been
   *  allocated first. */
  entries: PreviewEntry[];
}

function iso(d: Date | string): string {
  return d instanceof Date ? d.toISOString() : new Date(d).toISOString();
}

function toProvisioningView(row: ProvisioningRow): SiteProvisioningView {
  return {
    siteId: row.site_id,
    tenantId: row.tenant_id,
    pppUsername: row.ppp_username,
    tunnelIp: row.tunnel_ip,
    lanSubnet: row.lan_subnet,
    lanSource: row.lan_source,
    pppPasswordMode: row.ppp_password_mode,
    systemIdentity: row.system_identity,
    concentratorId: row.concentrator_id,
    pppProfile: row.ppp_profile,
    concentratorState: row.concentrator_state,
    concentratorJobId: row.concentrator_job_id === null ? null : Number(row.concentrator_job_id),
    concentratorError: row.concentrator_error,
    source: row.source,
    formulaTunnelIp: row.formula_tunnel_ip,
    pppPasswordKnown: row.ppp_password_mode !== 'per_site' || row.ppp_password_stored === true,
    allocatedAt: iso(row.allocated_at),
    updatedAt: iso(row.updated_at),
  };
}

function toPolicyView(row: PolicyRow, pools: ReadonlyMap<number, AddressPool>): AllocationPolicyView {
  const rule = (
    poolId: number,
    mode: string,
    start: string | null,
    prefix: number | null,
    formula: string | null,
  ): PolicyRuleView => {
    const pool = pools.get(poolId);
    return {
      poolId,
      poolName: pool?.name ?? null,
      poolCidr: pool ? formatCidr(pool.cidr) : null,
      mode: mode as AddressMode,
      start,
      prefix,
      formula,
    };
  };
  return {
    tenantId: row.tenant_id,
    tunnel: rule(row.tunnel_pool_id, row.tunnel_mode, row.tunnel_start, null, row.tunnel_formula),
    lan:
      row.lan_mode === null
        ? null
        : {
            mode: row.lan_mode as LanMode,
            poolId: row.lan_pool_id,
            poolName: row.lan_pool_id === null ? null : (pools.get(row.lan_pool_id)?.name ?? null),
            poolCidr:
              row.lan_pool_id === null || !pools.get(row.lan_pool_id)
                ? null
                : formatCidr(pools.get(row.lan_pool_id)!.cidr),
            prefix: row.lan_prefix,
            formula: row.lan_formula,
            subnet: row.lan_fixed_subnet,
            variable: row.lan_variable,
          },
    pppLoginTemplate: row.ppp_login_template,
    systemIdentityTemplate: row.identity_template,
    pppPasswordMode: row.ppp_password_mode as PppPasswordMode,
    derived: stringRecord(row.derived_values),
    pppProfile: row.ppp_profile,
    concentratorId: row.concentrator_id,
    // NULL is 'free'; any other value is one the CHECK of 052 admitted.
    siteCodeFormat: row.site_code_format ?? 'free',
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

function rowToInput(row: PolicyRow): Record<string, unknown> {
  return {
    tunnel: {
      poolId: row.tunnel_pool_id,
      mode: row.tunnel_mode,
      start: row.tunnel_start,
      formula: row.tunnel_formula,
    },
    lan:
      row.lan_mode === null
        ? null
        : {
            poolId: row.lan_pool_id,
            mode: row.lan_mode,
            prefix: row.lan_prefix,
            formula: row.lan_formula,
            subnet: row.lan_fixed_subnet,
            variable: row.lan_variable,
          },
    pppLoginTemplate: row.ppp_login_template,
    systemIdentityTemplate: row.identity_template,
    pppPasswordMode: row.ppp_password_mode,
    derived: row.derived_values,
    pppProfile: row.ppp_profile,
    concentratorId: row.concentrator_id,
    siteCodeFormat: row.site_code_format,
  };
}

// ============================================================================
// Shared reads
// ============================================================================

/** Every address pool, by id. A row whose block no longer parses (impossible
 *  under the CHECKs, possible by hand) is left out, so a policy naming it
 *  fails validation by name instead of allocating from a guess. */
export async function loadPools(q: Knex): Promise<Map<number, AddressPool>> {
  const rows = (await q('address_pools').select('id', 'name', 'cidr', 'purpose')) as PoolRow[];
  const out = new Map<number, AddressPool>();
  for (const row of rows) {
    const parsed = parseCidr(row.cidr);
    if (!parsed.ok || (row.purpose !== 'tunnel' && row.purpose !== 'lan')) continue;
    out.set(row.id, { id: row.id, name: row.name, cidr: parsed.cidr, purpose: row.purpose });
  }
  return out;
}

async function readPolicyRow(q: Knex, tenantId: number): Promise<PolicyRow | undefined> {
  return (await q('tenant_allocation_policies')
    .select(POLICY_COLUMNS)
    .where({ tenant_id: tenantId })
    .first()) as PolicyRow | undefined;
}

/** The stored policy, run through the SAME validator as the API body (without
 *  the save-time formula probe), so a row edited by hand is judged by the rule
 *  that admits rows rather than trusted. Exported for the LAN reprise
 *  (lanReprise.ts), which evaluates the policy's derived values. */
export async function loadPolicy(
  q: Knex,
  tenantId: number,
  pools: ReadonlyMap<number, AddressPool>,
): Promise<{ policy: AllocationPolicy; row: PolicyRow }> {
  const row = await readPolicyRow(q, tenantId);
  if (!row) {
    throw new AllocationError(
      'NO_POLICY',
      `tenant ${tenantId} has no allocation policy, so its sites cannot be given addresses. Set ` +
        `one with PUT /api/allocation/tenants/${tenantId}/policy, then retry the allocation.`,
    );
  }
  const result = validatePolicyInput(rowToInput(row), { tenantId, pools, probe: false });
  if (!result.ok) {
    throw new AllocationError(
      'INVALID_POLICY',
      `the stored allocation policy of tenant ${tenantId} no longer validates. Correct it with ` +
        `PUT /api/allocation/tenants/${tenantId}/policy, then retry the allocation.`,
      result.errors,
    );
  }
  return { policy: result.policy, row };
}

/** Where one CHR's seed stands at `nowMs`. */
export async function readSeedStatus(q: Knex, concentratorId: number, nowMs: number): Promise<SeedStatus> {
  const row = (await q('concentrator_secret_reads')
    .where({ concentrator_id: concentratorId })
    .first('read_at', 'secret_count')) as { read_at: Date; secret_count: number } | undefined;
  const readAtMs = row ? new Date(row.read_at).getTime() : null;
  return {
    concentratorId,
    readAt: row ? iso(row.read_at) : null,
    secretCount: row ? row.secret_count : null,
    fresh: seedFreshness(readAtMs, nowMs) === 'fresh',
  };
}

/** The seeding side of every stored policy. Read from the raw rows, valid or
 *  not: a policy that no longer validates still names its pool and its CHR. */
async function loadSeedRefs(q: Knex): Promise<PolicySeedRef[]> {
  const rows = (await q('tenant_allocation_policies').select('tenant_id', 'tunnel_pool_id', 'concentrator_id')) as Array<{
    tenant_id: number;
    tunnel_pool_id: number;
    concentrator_id: number;
  }>;
  return rows.map((r) => ({ tenantId: r.tenant_id, tunnelPoolId: r.tunnel_pool_id, concentratorId: r.concentrator_id }));
}

/** The CHRs whose current read an allocation of `tenantId` rests on, from its
 *  stored policy row — before the policy is validated, so the re-read can run
 *  outside the transaction. [] when the tenant has no policy (the allocation
 *  then refuses NO_POLICY by itself). */
async function gatingFromStoredPolicy(tenantId: number): Promise<number[]> {
  const refs = await loadSeedRefs(db);
  const own = refs.find((r) => r.tenantId === tenantId);
  return own ? seedConcentrators(own, refs) : [];
}

function gatingFor(policy: AllocationPolicy, refs: readonly PolicySeedRef[]): number[] {
  return seedConcentrators(
    { tenantId: policy.tenantId, tunnelPoolId: policy.tunnel.pool.id, concentratorId: policy.concentratorId },
    refs,
  );
}

/**
 * Re-read every CHR of `concentratorIds` whose last read is not fresh. MUST be
 * called with no transaction open: it dials the CHR, and each re-read takes
 * the allocation lock for its own write. Best effort — a CHR that cannot be
 * read is logged and left as it was; the caller's freshness check, inside its
 * own transaction, is what refuses. One CHR at a time.
 */
async function refreshStaleSeeds(concentratorIds: readonly number[]): Promise<void> {
  const now = Date.now();
  for (const id of concentratorIds) {
    const status = await readSeedStatus(db, id, now);
    if (status.fresh) continue;
    try {
      const result = await refreshSecretInventory(id);
      logger.info({ concentratorId: id, ...result }, 'Allocation seed re-read from the concentrator');
    } catch (err) {
      logger.warn(
        { err, concentratorId: id, lastReadAt: status.readAt },
        'Allocation seed re-read failed; allocations gated by this concentrator are refused until it is read',
      );
    }
  }
}

async function readSeeds(q: Knex, concentratorIds: readonly number[], nowMs: number): Promise<SeedStatus[]> {
  const out: SeedStatus[] = [];
  for (const id of concentratorIds) out.push(await readSeedStatus(q, id, nowMs));
  return out;
}

/** Why the seeds that are not fresh block an allocation, in words, or null. */
function seedBlock(
  seeds: readonly SeedStatus[],
  ownConcentratorId: number,
): { reason: 'NOT_SEEDED' | 'STALE_SEED'; concentratorIds: number[]; message: string } | null {
  const blocked = seeds.filter((s) => !s.fresh);
  if (blocked.length === 0) return null;
  const minutes = Math.round(SEED_MAX_AGE_MS / 60_000);
  const parts = blocked.map((s) => {
    const role =
      s.concentratorId === ownConcentratorId
        ? "this tenant's CHR"
        : 'the CHR of another policy that shares this tunnel pool';
    const when = s.readAt === null ? 'has never been read' : `was last read at ${s.readAt}`;
    return `concentrator ${s.concentratorId} (${role}) ${when}`;
  });
  return {
    reason: blocked.some((s) => s.readAt === null) ? 'NOT_SEEDED' : 'STALE_SEED',
    concentratorIds: blocked.map((s) => s.concentratorId),
    message:
      `the /ppp/secret of ${parts.join('; ')}, and it could not be re-read just now (the server log ` +
      'has the cause). Until it is, the addresses and logins already declared there are unknown and ' +
      'could be handed out again. Check that the concentrator answers on its RouterOS API, then ' +
      `retry the allocation: it re-reads any gating CHR whose last read is more than ${minutes} ` +
      'minutes old. (A discovery scan of the CHR, POST /api/discoveries/scan, records the same read.)',
  };
}

/** The string-valued entries of a jsonb object column; anything else is dropped. */
function stringRecord(raw: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return out;
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) if (typeof v === 'string') out[k] = v;
  return out;
}

interface InstanceVariableRow {
  value: unknown;
  is_secret: boolean;
  secret_enc: string | null;
}

/** One INSTANCE-level variable (config_variables, scope 'instance', migration
 *  038): the level every tenant inherits, stored once. */
async function readInstanceVariable(q: Knex, key: string): Promise<InstanceVariableRow | undefined> {
  return (await q('config_variables')
    .whereNull('tenant_id')
    .whereNull('scope_id')
    .where({ scope: 'instance', key })
    .first('value', 'is_secret', 'secret_enc')) as InstanceVariableRow | undefined;
}

/** {instance.domain}: the INSTANCE variable `instance_domain` (moved there
 *  from app_config by migration 039). '' when unset, secret or not a string. */
export async function readInstanceDomain(q: Knex): Promise<string> {
  const row = await readInstanceVariable(q, INSTANCE_SETTINGS_KEYS.INSTANCE_DOMAIN);
  if (!row || row.is_secret || typeof row.value !== 'string') return '';
  return row.value.trim();
}

/**
 * The fleet-wide PPP password of 'shared' mode, decrypted. Refuses when the
 * instance variable is absent or stored as a plain (non-secret) value: a
 * password shown in clear on the variables screen is a leak the allocator must
 * not normalise by using it.
 */
async function readSharedPppPassword(q: Knex, label: string): Promise<string> {
  return decrypt(await sharedPasswordCiphertext(q, label));
}

/**
 * The precondition of every 'shared' allocation, judged WITHOUT decrypting:
 * the instance variable exists and is stored as a secret. Checked before the
 * INSERT (allocateForSite), by every preview and when a 'shared' policy is
 * saved — not only when the password is read, because by then the row, its
 * tunnel address and its login are already taken by an allocation no CHR job
 * can ever complete.
 */
async function sharedPasswordCiphertext(q: Knex, label: string): Promise<string> {
  const row = await readInstanceVariable(q, SHARED_PPP_PASSWORD_KEY);
  if (!row) {
    throw new AllocationError(
      'SHARED_PASSWORD_MISSING',
      `${label}: this allocation uses the shared PPP password, and the instance variable ` +
        `"${SHARED_PPP_PASSWORD_KEY}" is not set. Set it (variables, level Instance, as a secret), then retry.`,
    );
  }
  if (!row.is_secret || !row.secret_enc) {
    throw new AllocationError(
      'SHARED_PASSWORD_MISSING',
      `${label}: the instance variable "${SHARED_PPP_PASSWORD_KEY}" is stored as a plain value. ` +
        'Store it again as a secret, then retry.',
    );
  }
  return row.secret_enc;
}

async function assertSharedPasswordReady(q: Knex, policy: AllocationPolicy, label: string): Promise<void> {
  if (policy.passwordMode === 'shared') await sharedPasswordCiphertext(q, label);
}

export async function loadLoginContext(q: Knex, tenantId: number): Promise<LoginContext> {
  const tenant = (await q('tenants').where({ id: tenantId }).first('slug')) as { slug: string } | undefined;
  if (!tenant) throw new AllocationError('TENANT_NOT_FOUND', `tenant ${tenantId} does not exist.`);
  return { tenantSlug: tenant.slug, instanceDomain: await readInstanceDomain(q) };
}

/** The CHRs whose secrets and sessions hold values for an allocation in
 *  `tenantId` (seed.ts, "WHOSE CHR COUNTS"). */
async function loadTrusted(q: Knex, tenantId: number, refs: readonly PolicySeedRef[]): Promise<Set<number>> {
  const chrs = (await q('devices').where({ role: 'concentrator' }).select('id', 'tenant_id')) as Array<{
    id: number;
    tenant_id: number;
  }>;
  return trustedConcentrators(
    chrs.map((c) => ({ id: c.id, tenantId: c.tenant_id })),
    refs.map((r) => r.concentratorId),
    tenantId,
    MASTER_TENANT_ID,
  );
}

/**
 * Every address held inside `block` (CIDR text) by a holder this allocation
 * believes. See the "FREE MEANS FREE" box.
 *
 * Columns this module does not write go through `set_masklen(x, 32)` before the
 * containment test: an `inet` may carry a netmask, and
 * `10.20.0.5/24 <<= 10.20.0.0/28` is FALSE although the address is inside the
 * block. An IPv6 value is simply not contained in an IPv4 block.
 */
async function loadHeldAddresses(q: Knex, block: string, trusted: ReadonlySet<number>): Promise<TakenAddress[]> {
  const sites = (await q('site_provisioning')
    .select(q.raw('host(tunnel_ip) AS address'), 'tenant_id', 'site_id')
    .whereRaw('tunnel_ip <<= CAST(? AS cidr)', [block])) as Array<{
    address: string;
    tenant_id: number;
    site_id: number;
  }>;

  // The username and the site of a device, and the username of a session, let
  // ADOPTION recognise the deployed account it is adopting (policy.ts).
  const devices = (await q('devices')
    .select(q.raw('host(tunnel_ip) AS address'), 'tenant_id', 'id', 'ppp_username', 'site_id')
    .whereNotNull('tunnel_ip')
    .whereRaw('set_masklen(tunnel_ip, 32) <<= CAST(? AS cidr)', [block])) as Array<{
    address: string;
    tenant_id: number;
    id: number;
    ppp_username: string | null;
    site_id: number | null;
  }>;

  // A live session whose device is unknown (a quarantined account) still holds
  // its address on the CHR; its tenant is simply not known.
  const sessionRows = (await q('ppp_sessions as s')
    .leftJoin('devices as d', 'd.id', 's.device_id')
    .select(q.raw('host(s.tunnel_ip) AS address'), 'd.tenant_id', 's.concentrator_id', 's.ppp_username')
    .whereNull('s.ended_at')
    .whereNotNull('s.tunnel_ip')
    .whereRaw('set_masklen(s.tunnel_ip, 32) <<= CAST(? AS cidr)', [block])) as Array<{
    address: string;
    tenant_id: number | null;
    concentrator_id: number;
    ppp_username: string | null;
  }>;
  const sessions = fromTrusted(
    sessionRows.map((r) => ({
      address: r.address,
      tenantId: r.tenant_id ?? null,
      concentratorId: r.concentrator_id,
      username: r.ppp_username,
    })),
    trusted,
  );

  // The seed: what each believed CHR declares, as of its last read. Both ends
  // of the tunnel count — a secret's local-address is the CHR's own side.
  const declaredRows: Array<{ address: string; concentrator_id: number; name: string }> = [];
  for (const column of ['remote_address', 'local_address'] as const) {
    const rows = (await q('concentrator_ppp_secrets')
      .select(q.raw(`host(${column}) AS address`), 'concentrator_id', 'name')
      .whereNull('vanished_at')
      .whereNotNull(column)
      .whereRaw(`set_masklen(${column}, 32) <<= CAST(? AS cidr)`, [block])) as typeof declaredRows;
    declaredRows.push(...rows);
  }
  const declared = fromTrusted(
    declaredRows.map((r) => ({ address: r.address, name: r.name, concentratorId: r.concentrator_id })),
    trusted,
  );

  return [
    ...sites.map((r) => ({ address: r.address, tenantId: r.tenant_id, source: 'site' as const, ref: r.site_id, name: null })),
    ...devices.map((r) => ({
      address: r.address,
      tenantId: r.tenant_id,
      source: 'device' as const,
      ref: r.id,
      name: r.ppp_username,
      siteId: r.site_id,
    })),
    ...sessions.map((r) => ({
      address: r.address,
      tenantId: r.tenantId,
      source: 'session' as const,
      ref: r.concentratorId,
      name: r.username,
    })),
    ...declared.map((r) => ({
      address: r.address,
      tenantId: null,
      source: 'concentrator_secret' as const,
      ref: r.concentratorId,
      name: r.name,
    })),
  ];
}

/**
 * Site LAN subnets overlapping `block`. With `scope`, only those of that
 * tenant or drawn from that pool — the LAN uniqueness rule (policy.ts,
 * UNIQUENESS); without it, every tenant's — what a TUNNEL address must stay
 * out of.
 *
 * A LAN RECORDED from a deployed store (lan_source 'recorded', migration 070,
 * lanReprise.ts) has no pool, so `lan_pool_id` cannot carry it to the pool's
 * other tenants. It is part of its tenant's plan: the tenant's own rows are
 * read by `tenant_id` above, and the tenants that share a pool with it — every
 * tenant whose policy draws its LANs from this pool — read it here too, so no
 * allocation from that pool is ever carved over a store's real LAN.
 */
async function loadLanSubnets(
  q: Knex,
  block: string,
  scope: { tenantId: number; poolId: number } | null,
): Promise<TakenBlock[]> {
  const query = q('site_provisioning')
    .select('lan_subnet', 'tenant_id', 'site_id')
    .whereNotNull('lan_subnet')
    .whereRaw('lan_subnet && CAST(? AS cidr)', [block]);
  if (scope) {
    query.where((w) => {
      w.where('tenant_id', scope.tenantId)
        .orWhere('lan_pool_id', scope.poolId)
        .orWhere((r) => {
          r.where('lan_source', RECORDED_LAN_SOURCE).whereIn(
            'tenant_id',
            q('tenant_allocation_policies').select('tenant_id').where('lan_pool_id', scope.poolId),
          );
        });
    });
  }
  const rows = (await query) as Array<{ lan_subnet: string; tenant_id: number; site_id: number }>;
  return rows.map((r) => ({ block: r.lan_subnet, tenantId: r.tenant_id, source: 'site' as const, ref: r.site_id, name: null }));
}

/** Holders of any of `logins`, compared without regard to case. Only the
 *  NUMBER of placeholders is interpolated; every value is bound. */
async function loadLoginHolders(
  q: Knex,
  logins: readonly string[],
  trusted: ReadonlySet<number>,
): Promise<LoginHolder[]> {
  const lowered = Array.from(new Set(logins.map((l) => l.toLowerCase())));
  if (lowered.length === 0) return [];
  const marks = lowered.map(() => '?').join(', ');

  const sites = (await q('site_provisioning')
    .select('ppp_username', 'tenant_id', 'site_id')
    .whereRaw(`lower(ppp_username) IN (${marks})`, lowered)) as Array<{
    ppp_username: string;
    tenant_id: number;
    site_id: number;
  }>;
  const devices = (await q('devices')
    .select('ppp_username', 'tenant_id', 'id', 'site_id')
    .whereNotNull('ppp_username')
    .whereRaw(`lower(ppp_username) IN (${marks})`, lowered)) as Array<{
    ppp_username: string;
    tenant_id: number;
    id: number;
    site_id: number | null;
  }>;
  const declared = fromTrusted(
    ((await q('concentrator_ppp_secrets')
      .select('name', 'concentrator_id')
      .whereNull('vanished_at')
      .whereRaw(`lower(name) IN (${marks})`, lowered)) as Array<{ name: string; concentrator_id: number }>).map(
      (r) => ({ login: r.name, concentratorId: r.concentrator_id }),
    ),
    trusted,
  );
  // A live session's username, declared as a secret or not (RADIUS).
  const sessions = fromTrusted(
    ((await q('ppp_sessions as s')
      .leftJoin('devices as d', 'd.id', 's.device_id')
      .select('s.ppp_username', 's.concentrator_id', 'd.tenant_id')
      .whereNull('s.ended_at')
      .whereRaw(`lower(s.ppp_username) IN (${marks})`, lowered)) as Array<{
      ppp_username: string;
      concentrator_id: number;
      tenant_id: number | null;
    }>).map((r) => ({ login: r.ppp_username, tenantId: r.tenant_id ?? null, concentratorId: r.concentrator_id })),
    trusted,
  );

  return [
    ...sites.map((r) => ({ login: r.ppp_username, source: 'site' as const, tenantId: r.tenant_id, ref: r.site_id })),
    ...devices.map((r) => ({
      login: r.ppp_username,
      source: 'device' as const,
      tenantId: r.tenant_id,
      ref: r.id,
      siteId: r.site_id,
    })),
    ...declared.map((r) => ({
      login: r.login,
      source: 'concentrator_secret' as const,
      tenantId: null,
      ref: r.concentratorId,
    })),
    ...sessions.map((r) => ({
      login: r.login,
      source: 'session' as const,
      tenantId: r.tenantId,
      ref: r.concentratorId,
    })),
  ];
}

/** Everything held inside the policy's pools, plus the holders of the logins
 *  about to be handed out. See the "FREE MEANS FREE" box. */
async function loadState(
  q: Knex,
  policy: AllocationPolicy,
  candidateLogins: readonly string[],
  trusted: ReadonlySet<number>,
  candidateIdentities: readonly string[] = [],
): Promise<AllocationState> {
  const tunnelBlock = formatCidr(policy.tunnel.pool.cidr);
  const tunnelTaken = await loadHeldAddresses(q, tunnelBlock, trusted);
  const tunnelBlocked = await loadLanSubnets(q, tunnelBlock, null);

  let lanTaken: TakenBlock[] = [];
  const lan = policy.lan;
  if (lan && (lan.mode === 'incremental' || lan.mode === 'formula')) {
    const lanBlock = formatCidr(lan.pool.cidr);
    const subnets = await loadLanSubnets(q, lanBlock, { tenantId: policy.tenantId, poolId: lan.pool.id });
    const hosts = await loadHeldAddresses(q, lanBlock, trusted);
    lanTaken = [...subnets, ...hosts.map((h) => ({ ...h, block: `${h.address}/32` }))];
  } else if (lan && lan.mode === 'manual') {
    // A manual LAN is the customer's own plan: unique inside the tenant (the
    // index of migration 039), never judged against another tenant's.
    const rows = (await q('site_provisioning')
      .select('lan_subnet', 'tenant_id', 'site_id')
      .where({ tenant_id: policy.tenantId })
      .whereNotNull('lan_subnet')
      .whereNot({ lan_source: 'fixed' })) as Array<{ lan_subnet: string; tenant_id: number; site_id: number }>;
    lanTaken = rows.map((r) => ({ block: r.lan_subnet, tenantId: r.tenant_id, source: 'site' as const, ref: r.site_id, name: null }));
  }

  const loginsTaken = await loadLoginHolders(q, candidateLogins, trusted);
  const identitiesTaken = await loadIdentityHolders(q, candidateIdentities);

  // ADOPTION's input: what the policy's own CHR declares under these logins.
  // A declared address OUTSIDE the tunnel pool was not covered by the reads
  // above, yet the engine must still know who else holds it (a site of any
  // tenant, a device, another secret, a session, a LAN subnet around it), so
  // that one address is read the same way.
  const declaredSecrets = await loadDeclaredSecrets(q, policy.concentratorId, candidateLogins);
  const outside = new Set<string>();
  for (const d of declaredSecrets) {
    const host = d.remoteAddress === null ? null : parseIpv4(d.remoteAddress);
    if (host !== null && !cidrContains(policy.tunnel.pool.cidr, host)) outside.add(formatIpv4(host));
  }
  for (const host of outside) {
    tunnelTaken.push(...(await loadHeldAddresses(q, `${host}/32`, trusted)));
    tunnelBlocked.push(...(await loadLanSubnets(q, `${host}/32`, null)));
  }
  // ...and whether it lies in ANOTHER tenant's address plan (ADOPT_FOREIGN_POOL).
  // Only an address outside this policy's tunnel pool can: tunnel pools never
  // overlap (migration 036's exclusion constraint).
  const foreignTunnelPools = outside.size === 0 ? [] : await loadForeignTunnelPools(q, policy);
  return { tunnelTaken, tunnelBlocked, lanTaken, loginsTaken, identitiesTaken, declaredSecrets, foreignTunnelPools };
}

/** The tunnel pools another tenant's stored policy points at and this policy
 *  does not, as CIDR text. From the raw policy rows, valid or not, like
 *  `loadSeedRefs`: a policy that no longer validates still claims its pool. */
async function loadForeignTunnelPools(q: Knex, policy: AllocationPolicy): Promise<string[]> {
  const rows = (await q('address_pools as p')
    .join('tenant_allocation_policies as t', 't.tunnel_pool_id', 'p.id')
    .whereNot('t.tenant_id', policy.tenantId)
    .whereNot('p.id', policy.tunnel.pool.id)
    .distinct('p.cidr as cidr')) as Array<{ cidr: string }>;
  return rows.map((r) => String(r.cidr));
}

/**
 * The secrets `concentratorId` declares, as of its last read, whose name equals
 * one of `logins` without regard to case — every case variant, so the engine
 * can refuse an ambiguous adoption. Not vanished. The remote-address comes back
 * as host text, or null when the secret declares none.
 */
async function loadDeclaredSecrets(
  q: Knex,
  concentratorId: number,
  logins: readonly string[],
): Promise<DeclaredSecret[]> {
  const lowered = Array.from(new Set(logins.map((l) => l.toLowerCase())));
  if (lowered.length === 0) return [];
  const marks = lowered.map(() => '?').join(', ');
  const rows = (await q('concentrator_ppp_secrets')
    .select('name', q.raw('host(remote_address) AS remote_address'), 'profile', 'disabled')
    .where({ concentrator_id: concentratorId })
    .whereNull('vanished_at')
    .whereRaw(`lower(name) IN (${marks})`, lowered)
    .orderBy('name')) as Array<{ name: string; remote_address: string | null; profile: string | null; disabled: boolean }>;
  return rows.map((r) => ({
    concentratorId,
    name: r.name,
    remoteAddress: r.remote_address,
    profile: r.profile,
    disabled: r.disabled,
  }));
}

/** Site allocations already holding one of `identities` (case-insensitive). */
async function loadIdentityHolders(q: Knex, identities: readonly string[]): Promise<LoginHolder[]> {
  const lowered = Array.from(new Set(identities.map((l) => l.toLowerCase())));
  if (lowered.length === 0) return [];
  const marks = lowered.map(() => '?').join(', ');
  const rows = (await q('site_provisioning')
    .select('system_identity', 'tenant_id', 'site_id')
    .whereNotNull('system_identity')
    .whereRaw(`lower(system_identity) IN (${marks})`, lowered)) as Array<{
    system_identity: string;
    tenant_id: number;
    site_id: number;
  }>;
  return rows.map((r) => ({ login: r.system_identity, source: 'site' as const, tenantId: r.tenant_id, ref: r.site_id }));
}

function candidateIdentities(policy: AllocationPolicy, sites: readonly SiteFacts[], ctx: LoginContext): string[] {
  if (!policy.identity) return [];
  const out: string[] = [];
  for (const site of sites) {
    const r = renderSystemIdentity(
      policy.identity,
      {
        siteName: site.name,
        siteCode: site.code,
        siteCountry: site.country,
        tenantSlug: ctx.tenantSlug,
        instanceDomain: ctx.instanceDomain,
      },
      siteLabel(site),
    );
    if (r.ok) out.push(r.identity);
  }
  return out;
}

/** The site variables holding the LAN of each site, for a manual-LAN policy. */
async function loadManualLans(
  q: Knex,
  policy: AllocationPolicy,
  siteIds: readonly number[],
): Promise<Map<number, string>> {
  const out = new Map<number, string>();
  const lan = policy.lan;
  if (!lan || lan.mode !== 'manual' || siteIds.length === 0) return out;
  const rows = (await q('config_variables')
    .where({ tenant_id: policy.tenantId, scope: 'site', key: lan.variable, is_secret: false })
    .whereIn('scope_id', siteIds as number[])
    .select('scope_id', 'value')) as Array<{ scope_id: number; value: unknown }>;
  for (const r of rows) if (typeof r.value === 'string') out.set(r.scope_id, r.value);
  return out;
}

/** The logins a batch WOULD get, before anything is looked up — the holders
 *  of exactly those names are then read in one query per table. A site whose
 *  login does not render contributes nothing; planSites refuses it again. */
function candidateLogins(policy: AllocationPolicy, sites: readonly SiteFacts[], ctx: LoginContext): string[] {
  const out: string[] = [];
  for (const site of sites) {
    const r = renderPppLogin(
      policy.login,
      {
        siteName: site.name,
        siteCode: site.code,
        siteCountry: site.country,
        tenantSlug: ctx.tenantSlug,
        instanceDomain: ctx.instanceDomain,
      },
      siteLabel(site),
    );
    if (r.ok) out.push(r.login);
  }
  return out;
}

export async function tenantExists(tenantId: number): Promise<boolean> {
  assertId(tenantId, 'tenantId', PG_INT_MAX);
  return !!(await db('tenants').where({ id: tenantId }).first('id'));
}

export async function siteExists(siteId: number): Promise<boolean> {
  assertId(siteId, 'siteId', PG_INT_MAX);
  return !!(await db('sites').where({ id: siteId }).first('id'));
}

async function readProvisioning(q: Knex, siteId: number): Promise<ProvisioningRow | undefined> {
  return (await q('site_provisioning')
    .select(publicColumns())
    .where({ site_id: siteId })
    .first()) as ProvisioningRow | undefined;
}

/** A site's allocation without its password, or null when it has none. With
 *  `tenantId`, a row of another tenant is reported as absent, not as foreign. */
export async function getSiteProvisioning(
  siteId: number,
  opts: { tenantId?: number } = {},
): Promise<SiteProvisioningView | null> {
  assertId(siteId, 'siteId', PG_INT_MAX);
  const row = await readProvisioning(db, siteId);
  if (!row) return null;
  if (opts.tenantId !== undefined && row.tenant_id !== opts.tenantId) return null;
  return toProvisioningView(row);
}

// ============================================================================
// Policy
// ============================================================================

export async function getPolicy(tenantId: number): Promise<AllocationPolicyView | null> {
  assertId(tenantId, 'tenantId', PG_INT_MAX);
  const row = await readPolicyRow(db, tenantId);
  return row ? toPolicyView(row, await loadPools(db)) : null;
}

/**
 * Create or replace a tenant's policy. Affects the NEXT allocation only;
 * nothing already allocated moves — not even to another CHR (migration 036's
 * header: the CHR and the profile are frozen on each allocation).
 *
 * Judged on its own first (`validatePolicyInput`, with the formula probe),
 * then — under the allocation lock, so two operators saving conflicting
 * policies at once cannot both pass — against every other tenant's policy and
 * allocations (`policyConflicts`), and against the installation domain and the
 * tenant's slug: a template whose SHORTEST possible login is already longer
 * than PPP_LOGIN_MAX could never allocate a single site.
 */
export async function upsertPolicy(tenantId: number, input: unknown): Promise<AllocationPolicyView> {
  const saved = await savePolicy(tenantId, input, { dryRun: false, assumeSharedPassword: false });
  if (!saved) throw new Error(`allocation policy of tenant ${tenantId} vanished after being saved`);
  return saved;
}

/**
 * Every judgement `upsertPolicy` makes, and nothing written: the Quick Setup
 * check (services/tenantSetup), which must say whether a rule WOULD be saved
 * before it saves anything. Throws the same AllocationError the save would.
 *
 * `assumeSharedPassword`: the same request stores the instance secret
 * `ppp_password` before it saves the rule (the setup's apply order), so a
 * 'shared' rule is not refused for a password that does not exist YET. The
 * real save, later, probes it as always.
 */
export async function checkPolicy(
  tenantId: number,
  input: unknown,
  opts: { assumeSharedPassword?: boolean } = {},
): Promise<void> {
  await savePolicy(tenantId, input, { dryRun: true, assumeSharedPassword: opts.assumeSharedPassword === true });
}

/** Thrown at the last statement of a dry run, so its transaction rolls back
 *  having written nothing. Never leaves `savePolicy`. */
class PolicyCheckRollback extends Error {
  constructor() {
    super('allocation policy dry run');
    this.name = 'PolicyCheckRollback';
  }
}

/** `upsertPolicy`'s body. null exactly for a dry run. */
async function savePolicy(
  tenantId: number,
  input: unknown,
  mode: { dryRun: boolean; assumeSharedPassword: boolean },
): Promise<AllocationPolicyView | null> {
  assertId(tenantId, 'tenantId', PG_INT_MAX);
  if (!(await tenantExists(tenantId))) {
    throw new AllocationError('TENANT_NOT_FOUND', `tenant ${tenantId} does not exist.`);
  }
  const pools = await loadPools(db);
  const result = validatePolicyInput(input ?? {}, { tenantId, pools, probe: true });
  if (!result.ok) {
    throw new AllocationError(
      'INVALID_POLICY',
      'the allocation policy is invalid; correct the listed fields and save it again.',
      result.errors,
    );
  }
  const p = result.policy;

  // Same rule as device.service: a concentrator of this tenant, or shared
  // infrastructure in the master tenant — never another customer's.
  const chr = (await db('devices')
    .where({ id: p.concentratorId })
    .whereIn('tenant_id', [tenantId, MASTER_TENANT_ID])
    .first('role')) as { role: string } | undefined;
  if (!chr || chr.role !== 'concentrator') {
    throw new AllocationError(
      'CONCENTRATOR_INVALID',
      `device ${p.concentratorId} is not a concentrator of tenant ${tenantId} or of the shared ` +
        'infrastructure. Pick a CHR from the concentrator list and save the policy again.',
      { concentratorId: ['not a concentrator this tenant may use'] },
    );
  }

  const lanPool = p.lan && (p.lan.mode === 'incremental' || p.lan.mode === 'formula') ? p.lan.pool : null;
  // The site code format (052) is written only when the body CARRIES the key:
  // the policy editor predates it, and a save from that editor must not
  // silently put a 'digits:5' tenant back to free. A new policy saved without
  // the key gets NULL (free); `null` or 'free' clears it explicitly.
  const carriesCodeFormat =
    typeof input === 'object' && input !== null && !Array.isArray(input) && 'siteCodeFormat' in input;
  const codeFormatColumn: { site_code_format?: string | null } = carriesCodeFormat
    ? { site_code_format: siteCodeFormatColumn(p.siteCodeFormat) }
    : {};
  const columns = {
    tunnel_pool_id: p.tunnel.pool.id,
    // The composite FK (pool id, purpose) makes a LAN pool on the tunnel side
    // unrepresentable; this column is that FK's second half.
    tunnel_pool_purpose: 'tunnel',
    tunnel_mode: p.tunnel.mode,
    tunnel_start: p.tunnel.mode === 'incremental' ? formatIpv4(p.tunnel.start) : null,
    tunnel_formula: p.tunnel.mode === 'formula' ? p.tunnel.formula.source : null,
    lan_pool_id: lanPool ? lanPool.id : null,
    lan_pool_purpose: lanPool ? 'lan' : null,
    lan_mode: p.lan ? p.lan.mode : null,
    lan_prefix: p.lan && p.lan.mode === 'incremental' ? p.lan.prefix : null,
    lan_formula: p.lan && p.lan.mode === 'formula' ? p.lan.formula.source : null,
    lan_fixed_subnet: p.lan && p.lan.mode === 'fixed' ? formatCidr(p.lan.subnet) : null,
    lan_variable: p.lan && p.lan.mode === 'manual' ? p.lan.variable : null,
    ppp_login_template: p.login.source,
    identity_template: p.identity ? p.identity.source : null,
    ppp_password_mode: p.passwordMode,
    derived_values: p.derived.length > 0 ? JSON.stringify(derivedToJson(p.derived)) : null,
    ppp_profile: p.pppProfile,
    concentrator_id: p.concentratorId,
    ...codeFormatColumn,
  };

  try {
    await db.transaction(async (trx) => {
      // The dry run takes the allocation lock like the save: the conflict
      // check below is only meaningful under it, and a verdict reached
      // without it could pass a rule another save is committing right now.
      await takeAllocationLock(trx);

      const ctx = await loadLoginContext(trx, tenantId);
      if (p.passwordMode === 'shared' && !(mode.dryRun && mode.assumeSharedPassword)) {
        try {
          await sharedPasswordCiphertext(trx, `tenant ${tenantId}`);
        } catch (err) {
          if (!(err instanceof AllocationError)) throw err;
          throw new AllocationError(
            'INVALID_POLICY',
            'the policy uses the shared PPP password and the instance variable that holds it is not usable.',
            {
              pppPasswordMode: [
                `"shared" reads the instance variable "${SHARED_PPP_PASSWORD_KEY}", which is missing or not ` +
                  'stored as a secret: set it first (variables, level Instance, as a secret), or choose "per_site".',
              ],
            },
          );
        }
      }
      if (p.login.uses.has('instance.domain') && ctx.instanceDomain === '') {
        throw new AllocationError(
          'INVALID_POLICY',
          'the login template uses {instance.domain} and this installation has no domain set.',
          {
            pppLoginTemplate: [
              'uses {instance.domain}, which is empty: set it first with PUT ' +
                '/api/allocation/instance-domain, or take it out of the template.',
            ],
          },
        );
      }
      if (p.identity && p.identity.uses.has('instance.domain') && ctx.instanceDomain === '') {
        throw new AllocationError(
          'INVALID_POLICY',
          'the identity template uses {instance.domain} and this installation has no domain set.',
          {
            systemIdentityTemplate: [
              'uses {instance.domain}, which is empty: set it first with PUT ' +
                '/api/allocation/instance-domain, or take it out of the template.',
            ],
          },
        );
      }
      if (p.identity && minimalLoginLength(p.identity, ctx) > PPP_LOGIN_MAX) {
        throw new AllocationError(
          'INVALID_POLICY',
          `the identity template can never fit within ${PPP_LOGIN_MAX} characters.`,
          {
            systemIdentityTemplate: [
              `renders at least ${minimalLoginLength(p.identity, ctx)} characters (limit ${PPP_LOGIN_MAX}).`,
            ],
          },
        );
      }
      const shortest = minimalLoginLength(p.login, ctx);
      if (shortest > PPP_LOGIN_MAX) {
        throw new AllocationError(
          'INVALID_POLICY',
          `the login template can never fit: even a site with a one-character name and no country ` +
            `would get a ${shortest}-character login, and the limit is ${PPP_LOGIN_MAX}.`,
          {
            pppLoginTemplate: [
              `renders at least ${shortest} characters with this tenant's slug and the installation ` +
                `domain (limit ${PPP_LOGIN_MAX}): drop literal text or a placeholder.`,
            ],
          },
        );
      }

      const otherRows = (await trx('tenant_allocation_policies')
        .whereNot({ tenant_id: tenantId })
        .select('tenant_id', 'tunnel_pool_id', 'tunnel_mode', 'lan_pool_id', 'lan_mode')) as Array<{
        tenant_id: number;
        tunnel_pool_id: number;
        tunnel_mode: string;
        lan_pool_id: number | null;
        lan_mode: string | null;
      }>;
      const others: PolicyPoolRef[] = [];
      for (const o of otherRows) {
        others.push({ tenantId: o.tenant_id, side: 'tunnel', poolId: o.tunnel_pool_id, mode: o.tunnel_mode as AddressMode });
        if (o.lan_pool_id !== null && o.lan_mode !== null) {
          others.push({ tenantId: o.tenant_id, side: 'lan', poolId: o.lan_pool_id, mode: o.lan_mode as AddressMode });
        }
      }

      const foreign: ForeignAllocation[] = [];
      if (p.tunnel.mode === 'formula') {
        // Tunnel addresses are global: anything inside the block counts.
        const rows = (await trx('site_provisioning')
          .whereNot({ tenant_id: tenantId })
          .whereRaw('tunnel_ip <<= CAST(? AS cidr)', [formatCidr(p.tunnel.pool.cidr)])
          .select(trx.raw('host(tunnel_ip) AS value'), 'tenant_id')) as Array<{ value: string; tenant_id: number }>;
        for (const r of rows) foreign.push({ tenantId: r.tenant_id, side: 'tunnel', poolId: p.tunnel.pool.id, value: r.value });
      }
      if (lanPool && p.lan && p.lan.mode === 'formula') {
        // LAN subnets are per pool: only blocks drawn FROM this pool count. A
        // block another tenant drew from its own overlapping pool is a reuse.
        const lanPoolId = lanPool.id;
        const rows = (await trx('site_provisioning')
          .whereNot({ tenant_id: tenantId })
          .where({ lan_pool_id: lanPoolId })
          .select('lan_subnet as value', 'tenant_id')) as Array<{ value: string; tenant_id: number }>;
        for (const r of rows) foreign.push({ tenantId: r.tenant_id, side: 'lan', poolId: lanPoolId, value: r.value });
      }

      const conflicts = policyConflicts(p, others, foreign);
      if (Object.keys(conflicts).length > 0) {
        throw new AllocationError(
          'POLICY_CONFLICT',
          "the allocation policy collides with another tenant's policy or allocations; correct " +
            "the listed fields (or the other tenant's policy) and save it again.",
          conflicts,
        );
      }

      if (mode.dryRun) throw new PolicyCheckRollback();
      await trx('tenant_allocation_policies')
        .insert({ tenant_id: tenantId, ...columns })
        .onConflict('tenant_id')
        .merge({ ...columns, updated_at: trx.fn.now() });
    });
  } catch (err) {
    if (err instanceof PolicyCheckRollback) return null;
    // A pool deleted, or a concentrator deleted, between the validation above
    // and the insert: the composite FKs refuse the row.
    if (isPgError(err, '23503')) {
      throw new AllocationError(
        'INVALID_POLICY',
        'a pool or the concentrator this policy names was deleted while it was being saved; ' +
          'reload and save it again.',
      );
    }
    throw err;
  }

  logger.info(
    {
      tenantId,
      tunnel: { poolId: p.tunnel.pool.id, mode: p.tunnel.mode },
      lan: p.lan ? { poolId: lanPool ? lanPool.id : null, mode: p.lan.mode } : null,
      identity: p.identity !== null,
      passwordMode: p.passwordMode,
    },
    'Allocation policy saved',
  );
  const saved = await getPolicy(tenantId);
  if (!saved) throw new Error(`allocation policy of tenant ${tenantId} vanished after being saved`);
  return saved;
}

// ============================================================================
// Preview (dry run)
// ============================================================================

const DRAFT_CODE_MAX = 64;
const DRAFT_NAME_MAX = 255;

/** Validate a preview batch into site facts. Errors are per entry
 *  (`sites[3].country`) so a bulk-import screen can point at the row. */
export function validateDrafts(raw: unknown): SiteFacts[] {
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > PREVIEW_MAX) {
    throw new AllocationError(
      'INVALID_INPUT',
      `sites must be an array of 1 to ${PREVIEW_MAX} entries { code, name, country? }.`,
    );
  }
  const errors: Record<string, string[]> = {};
  const out: SiteFacts[] = [];
  raw.forEach((entry: unknown, i) => {
    const e = typeof entry === 'object' && entry !== null ? (entry as Record<string, unknown>) : {};
    const at = `sites[${i}]`;
    const code = typeof e.code === 'string' ? e.code.trim() : '';
    const name = typeof e.name === 'string' ? e.name.trim() : '';
    if (code === '' || code.length > DRAFT_CODE_MAX) {
      (errors[`${at}.code`] ??= []).push(`code is required (1-${DRAFT_CODE_MAX} characters).`);
    }
    if (name === '' || name.length > DRAFT_NAME_MAX) {
      (errors[`${at}.name`] ??= []).push(`name is required (1-${DRAFT_NAME_MAX} characters).`);
    }
    const country = normalizeCountry(e.country);
    if (!country.ok) (errors[`${at}.country`] ??= []).push(country.error);
    const lan = typeof e.lanSubnet === 'string' && e.lanSubnet.trim() !== '' ? e.lanSubnet.trim() : null;
    out.push({ siteId: null, code, name, country: country.ok ? country.country : null, manualLan: lan });
  });
  if (Object.keys(errors).length > 0) {
    throw new AllocationError('INVALID_INPUT', 'some sites of the batch are invalid; see details.', errors);
  }
  return out;
}

/**
 * What allocating `drafts`, in order, would give each of them. Writes NO
 * allocation. It does re-read, first and outside any transaction, every gating
 * CHR whose last read is not fresh — exactly what the allocation would do —
 * so the plans rest on what the CHRs declare now; that re-read writes only the
 * CHR secret inventory, and is read-only towards the router. Then every read
 * runs in a READ ONLY transaction, at REPEATABLE READ so they all see one
 * instant. No advisory lock — a preview must never queue behind, or in front
 * of, a clerk's real allocation. It is therefore a forecast.
 *
 * The drafts are sites that do not exist yet (a bulk import): their codes are
 * not checked against existing sites, and {site.id} is the code's number, as
 * at allocation.
 */
export async function previewAllocation(tenantId: number, drafts: unknown): Promise<AllocationPreview> {
  assertId(tenantId, 'tenantId', PG_INT_MAX);
  return previewSites(tenantId, validateDrafts(drafts));
}

/**
 * Plan `given` read-only, in order, as allocating them one after another
 * would. Sites that are rows already (siteId set) have their manual-LAN site
 * variable read here; drafts carry theirs as `manualLan`.
 */
async function previewSites(tenantId: number, given: SiteFacts[]): Promise<AllocationPreview> {
  if (!(await tenantExists(tenantId))) {
    throw new AllocationError('TENANT_NOT_FOUND', `tenant ${tenantId} does not exist.`);
  }
  await refreshStaleSeeds(await gatingFromStoredPolicy(tenantId));

  return db.transaction(async (trx) => {
    await trx.raw('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const pools = await loadPools(trx);
    const { policy, row } = await loadPolicy(trx, tenantId, pools);
    // Refused here as allocateForSite would refuse it: a preview that answers
    // normally and an allocation that then fails is the plan the bench trusts.
    await assertSharedPasswordReady(trx, policy, `tenant ${tenantId}`);
    const ids = given.flatMap((s) => (s.siteId === null ? [] : [s.siteId]));
    const manual = await loadManualLans(trx, policy, ids);
    const sites = given.map((s) =>
      s.siteId !== null && manual.has(s.siteId) ? { ...s, manualLan: manual.get(s.siteId) ?? null } : s,
    );
    const refs = await loadSeedRefs(trx);
    const seeds = await readSeeds(trx, gatingFor(policy, refs), Date.now());
    const trusted = await loadTrusted(trx, tenantId, refs);
    const ctx = await loadLoginContext(trx, tenantId);
    const state = await loadState(
      trx,
      policy,
      candidateLogins(policy, sites, ctx),
      trusted,
      candidateIdentities(policy, sites, ctx),
    );
    const results = planSites(policy, state, sites, ctx);
    return {
      tenantId,
      policy: toPolicyView(row, pools),
      seeds,
      blockedBy: seedBlock(seeds, policy.concentratorId),
      entries: results.map((r, index) => ({
        index,
        siteId: sites[index].siteId,
        code: sites[index].code,
        name: sites[index].name,
        plan: r.ok ? r.plan : null,
        refusal: r.ok ? null : r.refusal,
      })),
    };
  });
}

// ============================================================================
// Allocation
// ============================================================================

export interface AllocationResult {
  provisioning: SiteProvisioningView;
  created: boolean;
  /** What the operator must read: on a new allocation the plan's warnings
   *  (every difference ADOPTION found between the CHR and the policy); on an
   *  existing one what its row still says (a formula difference recorded at
   *  adoption, a per-site password ObliWAN does not hold). Empty otherwise. */
  warnings: string[];
}

/** The refusal of every reader of the password of an allocation adopted in
 *  'per_site' mode (migration 044: such a row stores none). */
function passwordUnknown(siteId: number, concentratorId: number): AllocationError {
  return new AllocationError(
    'PASSWORD_UNKNOWN',
    `site ${siteId}: its PPP account was adopted from concentrator ${concentratorId}, where its ` +
      'password is never read, and its allocation uses a per-site password: ObliWAN holds NO ' +
      'password for it and will not invent one, so no CPE configuration can be compiled for it. If ' +
      "that account uses the fleet's shared PPP password, set the tenant's policy to the shared " +
      `password, release this allocation (DELETE /api/allocation/sites/${siteId}, possible while its ` +
      "concentrator state is not 'provisioned') and allocate it again; otherwise configure this " +
      "router's PPP password by hand.",
  );
}

function storedWarnings(view: SiteProvisioningView): string[] {
  const out: string[] = [];
  if (view.source === 'adopted_chr' && view.formulaTunnelIp !== null) {
    out.push(
      `site ${view.siteId}: adopted from concentrator ${view.concentratorId}; the tunnel formula gave ` +
        `${view.formulaTunnelIp}, the CHR declared ${view.tunnelIp}, and the deployed ${view.tunnelIp} ` +
        'is the one recorded.',
    );
  }
  if (!view.pppPasswordKnown) out.push(passwordUnknown(view.siteId, view.concentratorId).message);
  // The shared-password ASSUMPTION of an adoption, restated on every read of
  // the row: it was true at adoption only if somebody made it so.
  if (view.source === 'adopted_chr' && view.pppPasswordMode === 'shared') out.push(adoptedPasswordWarning('shared'));
  return out;
}

function idempotent(row: ProvisioningRow): AllocationResult {
  const provisioning = toProvisioningView(row);
  return { provisioning, created: false, warnings: storedWarnings(provisioning) };
}

/**
 * Give a site its PPP login and password, its tunnel address and (if the
 * policy says so) its LAN subnet. Idempotent: a site that already has an
 * allocation gets it back with `created: false`.
 *
 * A site whose login the policy's own CHR already declares is ADOPTED (header
 * box, and policy.ts `adoptDeclared`): its row records what the CHR declares,
 * `source` 'adopted_chr', and `warnings` says every way that differs from the
 * policy. In 'per_site' mode such a row holds no password, and the result says
 * so in `warnings` and `provisioning.pppPasswordKnown`.
 *
 * Before its transaction, it re-reads every gating CHR whose last /ppp/secret
 * read is older than SEED_MAX_AGE_MS (it DIALS the CHR then — read-only, no
 * lock held, bounded by the RouterOS pool's connect and request timeouts);
 * inside, it refuses if any gating CHR is still not fresh. A bulk import pays
 * that dial at most once per CHR per SEED_MAX_AGE_MS, not once per site.
 *
 * `opts.tenantId`, when given, must be the site's tenant; any other site is
 * reported as not found rather than as somebody else's.
 *
 * Throws AllocationError — every per-site refusal of the engine (policy.ts,
 * PLAN_REFUSAL_REASONS, the adoption refusals among them) with its `holder`
 * when one is involved, NO_POLICY, INVALID_POLICY, NOT_SEEDED, STALE_SEED,
 * SITE_NOT_FOUND, CONFLICT — or VaultError when OBLIWAN_ENCRYPTION_KEY is
 * unusable.
 */
export async function allocateForSite(
  siteId: number,
  opts: { tenantId?: number } = {},
): Promise<AllocationResult> {
  assertId(siteId, 'siteId', PG_INT_MAX);
  const notFound = (): AllocationError =>
    new AllocationError('SITE_NOT_FOUND', `site ${siteId} does not exist.`);

  const existing = await readProvisioning(db, siteId);
  if (existing) {
    if (opts.tenantId !== undefined && existing.tenant_id !== opts.tenantId) throw notFound();
    return idempotent(existing);
  }

  // Outside any transaction: the seed re-read dials the CHR. Its tenant is read
  // here only to know WHICH CHRs to re-read; the transaction reads it again.
  const owner = (await db('sites').where({ id: siteId }).first('tenant_id')) as { tenant_id: number } | undefined;
  if (!owner) throw notFound();
  if (opts.tenantId !== undefined && owner.tenant_id !== opts.tenantId) throw notFound();
  await refreshStaleSeeds(await gatingFromStoredPolicy(owner.tenant_id));

  try {
    return await db.transaction(async (trx) => {
      await takeAllocationLock(trx);

      // The answer that is actually true: another request may have allocated
      // this very site while we waited for the lock.
      const raced = await readProvisioning(trx, siteId);
      if (raced) {
        if (opts.tenantId !== undefined && raced.tenant_id !== opts.tenantId) throw notFound();
        return idempotent(raced);
      }

      // FOR SHARE: the site cannot be deleted, renamed or re-coded under us
      // between this read and the insert that names it.
      const site = (await trx('sites')
        .where({ id: siteId })
        .forShare()
        .first('id', 'tenant_id', 'code', 'name', 'country')) as
        | { id: number; tenant_id: number; code: string; name: string; country: string | null }
        | undefined;
      if (!site) throw notFound();
      if (opts.tenantId !== undefined && site.tenant_id !== opts.tenantId) throw notFound();

      const pools = await loadPools(trx);
      const { policy } = await loadPolicy(trx, site.tenant_id, pools);
      // Before the INSERT: a 'shared' row without the instance password would
      // hold its login and addresses for a CHR job that can never complete.
      await assertSharedPasswordReady(trx, policy, `site ${siteId}`);

      // The seeds are judged on what THIS transaction reads: the policy may
      // have changed since the re-read above, and the re-read may have failed.
      const refs = await loadSeedRefs(trx);
      const block = seedBlock(await readSeeds(trx, gatingFor(policy, refs), Date.now()), policy.concentratorId);
      if (block) throw new AllocationError(block.reason, `site ${siteId}: ${block.message}`);

      const trusted = await loadTrusted(trx, site.tenant_id, refs);
      const ctx = await loadLoginContext(trx, site.tenant_id);
      const manual = await loadManualLans(trx, policy, [site.id]);
      const facts: SiteFacts = {
        siteId: site.id,
        code: site.code,
        name: site.name,
        country: site.country,
        manualLan: manual.get(site.id) ?? null,
      };
      const state = await loadState(
        trx,
        policy,
        candidateLogins(policy, [facts], ctx),
        trusted,
        candidateIdentities(policy, [facts], ctx),
      );
      const [result] = planSites(policy, state, [facts], ctx);
      if (!result.ok) {
        throw new AllocationError(result.refusal.reason, result.refusal.message, undefined, result.refusal.holder);
      }
      const plan = result.plan;
      // An adopted account's password is on the CHR and is never read:
      // no password is generated for it, whatever the mode — one generated
      // here would be a password the CHR does not hold.
      const generates = policy.passwordMode === 'per_site' && plan.source === 'allocated';

      await trx('site_provisioning').insert({
        site_id: site.id,
        tenant_id: site.tenant_id,
        ppp_username: plan.pppLogin,
        // 'per_site': generated, encrypted and bound in one expression.
        // 'shared': nothing stored; read from the instance variable when needed.
        ppp_password_mode: policy.passwordMode,
        ppp_password_enc: generates ? encrypt(generatePppPassword()) : null,
        ppp_password_key_version: generates ? currentKeyVersion() : null,
        source: plan.source,
        formula_tunnel_ip: plan.formulaTunnelIp,
        system_identity: plan.systemIdentity,
        tunnel_ip: plan.tunnelIp,
        lan_subnet: plan.lanSubnet,
        lan_source: plan.lanSource,
        lan_pool_id:
          plan.lanSource === 'pool' && policy.lan && (policy.lan.mode === 'incremental' || policy.lan.mode === 'formula')
            ? policy.lan.pool.id
            : null,
        // Frozen: the CHR whose secrets this allocation was checked against.
        concentrator_id: policy.concentratorId,
        // The policy's profile, or — adopted — the one the CHR secret carries,
        // so the concentrator job finds the deployed secret as it is.
        ppp_profile: plan.pppProfile,
      });

      const row = await readProvisioning(trx, siteId);
      if (!row) throw new Error(`site ${siteId} allocation vanished inside its own transaction`);
      const logged = {
        siteId,
        tenantId: site.tenant_id,
        siteNumber: plan.siteNumber,
        tunnelIp: plan.tunnelIp,
        lanSubnet: plan.lanSubnet,
        pppUsername: plan.pppLogin,
        systemIdentity: plan.systemIdentity,
        passwordMode: policy.passwordMode,
        concentratorId: policy.concentratorId,
        tunnelMode: policy.tunnel.mode,
        lanMode: policy.lan?.mode ?? null,
        source: plan.source,
      };
      if (plan.source === 'adopted_chr') {
        logger.warn(
          { ...logged, formulaTunnelIp: plan.formulaTunnelIp, warnings: plan.warnings },
          'Site allocation ADOPTED from the concentrator (deployed site recorded as it is)',
        );
      } else {
        logger.info(logged, 'Site allocated');
      }
      return { provisioning: toProvisioningView(row), created: true, warnings: plan.warnings };
    });
  } catch (err) {
    // Every UNIQUE or EXCLUDE that can fire on that INSERT is local to
    // site_provisioning, and every INSERT into it in this tree runs under the
    // lock (recordConcentratorOutcome only UPDATEs columns none of them
    // covers; releaseAllocation only DELETEs). So this is a row written by
    // something that bypassed the lock — hand-made SQL, or a future writer. It
    // is NOT the race with `devices` or `ppp_sessions` described in the header
    // box: a write there violates nothing on this table, and that race passes
    // silently. Nothing was committed; the retry reads the new state.
    if (isPgError(err, '23505') || isPgError(err, '23P01')) {
      throw new AllocationError(
        'CONFLICT',
        `site ${siteId}: an address, subnet or PPP login was taken by a concurrent write. Nothing ` +
          'was allocated; retry the allocation.',
      );
    }
    throw err;
  }
}

/**
 * Undo an allocation the CHR has not taken: delete the row of a site whose
 * concentrator state is 'pending' or 'failed', so the site can be allocated
 * again. For a clash found AFTER allocation — the concentrator job finding the
 * login or the remote-address already on the CHR (a secret typed by hand
 * inside the seed's age bound) — or an operator undoing a mistake before the
 * CHR is written. The next allocation re-reads the gating CHRs if their read
 * is not fresh, so a clash the job found is then seen.
 *
 * Refused (ALREADY_PROVISIONED) once the state is 'provisioned': the secret is
 * on the CHR, and freeing its address here would hand it to the next site
 * while that secret still holds it. The state is tested by the DELETE itself,
 * so a job marking the site provisioned at the same moment wins.
 *
 * What it does NOT undo: a CPE already configured at the bench keeps the
 * login, password and address it was given — re-render it after the new
 * allocation. A 'per_site' password goes with the row and a new allocation
 * generates a new one; a 'shared' row holds no password, and a new allocation
 * reads the same instance password again. An ADOPTED row frees nothing on the
 * CHR: its secret still holds the login and the address there, so the next
 * allocation of the site adopts it again — under the policy of that moment
 * (which is how a 'per_site' adoption becomes a 'shared' one). `tenantId` is
 * REQUIRED, as for `revealPppCredential`.
 *
 * Returns the allocation as it was.
 */
export async function releaseAllocation(siteId: number, tenantId: number): Promise<SiteProvisioningView> {
  assertId(siteId, 'siteId', PG_INT_MAX);
  assertId(tenantId, 'tenantId', PG_INT_MAX);
  const released = await db.transaction(async (trx) => {
    await takeAllocationLock(trx);
    const row = await readProvisioning(trx, siteId);
    if (!row || row.tenant_id !== tenantId) {
      throw new AllocationError(
        'NOT_ALLOCATED',
        `site ${siteId} has no allocation in tenant ${tenantId}; there is nothing to release.`,
      );
    }
    const deleted = await trx('site_provisioning')
      .where({ site_id: siteId, tenant_id: tenantId })
      .whereNot({ concentrator_state: 'provisioned' })
      .delete();
    if (deleted === 0) {
      throw new AllocationError(
        'ALREADY_PROVISIONED',
        `site ${siteId}: its allocation is provisioned on concentrator ${row.concentrator_id}, so its ` +
          'PPP secret is live there and is not released here. Release is for allocations whose ' +
          "concentrator state is 'pending' or 'failed'.",
      );
    }
    return row;
  });
  logger.info(
    {
      siteId,
      tenantId,
      tunnelIp: released.tunnel_ip,
      lanSubnet: released.lan_subnet,
      pppUsername: released.ppp_username,
      concentratorState: released.concentrator_state,
    },
    'Site allocation released',
  );
  return toProvisioningView(released);
}

// ============================================================================
// Server-side only
// ============================================================================

/**
 * The PPP credential of one site, decrypted. FOR THE SERVER-SIDE CPE RENDER AND
 * THE CONCENTRATOR JOB ONLY — no route calls this, and none may.
 *
 * `tenantId` is REQUIRED and scopes the read: a credential fetched by site id
 * alone is a cross-tenant read on the provisioning path, and a barrier that is
 * optional is one the second caller forgets.
 *
 * The CHR and the profile are the ones FROZEN on the allocation, never today's
 * policy: a retry, a re-render or a rotation of a site already written on CHR
 * 42 must not declare it a second time on CHR 43 because the tenant was
 * re-pointed meanwhile.
 *
 * Throws PASSWORD_UNKNOWN for an allocation ADOPTED in 'per_site' mode: it
 * holds no password (the CHR's is never read), and falling back to the shared
 * one would hand a CPE a password the CHR may well not hold.
 */
export async function revealPppCredential(siteId: number, tenantId: number): Promise<PppCredential> {
  const account = await readPppAccount(siteId, tenantId);
  if (account.pppPassword === null) throw passwordUnknown(siteId, account.concentratorId);
  return { ...account, pppPassword: account.pppPassword };
}

/** `PppCredential` whose password may be unknown. IN MEMORY ONLY. */
export interface PppAccount extends Omit<PppCredential, 'pppPassword'> {
  /** null ONLY for an allocation adopted in 'per_site' mode (migration 044):
   *  the password is on the CHR, never read. */
  pppPassword: string | null;
  /** The row's provenance (migration 044): 'adopted_chr' = recorded from a
   *  secret the CHR already declared, which ObliWAN never wrote; null = a row
   *  older than 044, every one of them computed by ObliWAN. */
  source: PlanSource | null;
}

/**
 * `revealPppCredential` for the CONCENTRATOR JOB, which needs a password only
 * to ADD a secret: finding an adopted account present on the CHR needs none.
 * Same scoping, same secrets rules — no route calls it. `pppPassword` is null
 * only for an adopted 'per_site' allocation; a 'shared' one still refuses
 * SHARED_PASSWORD_MISSING when the instance password is not usable.
 */
export async function readPppAccount(siteId: number, tenantId: number): Promise<PppAccount> {
  assertId(siteId, 'siteId', PG_INT_MAX);
  assertId(tenantId, 'tenantId', PG_INT_MAX);
  const row = (await db('site_provisioning')
    .where({ site_id: siteId, tenant_id: tenantId })
    .first(
      'ppp_username',
      'ppp_password_mode',
      'ppp_password_enc',
      db.raw('host(tunnel_ip) AS tunnel_ip'),
      'lan_subnet',
      'ppp_profile',
      'concentrator_id',
      'source',
    )) as
    | {
        ppp_username: string;
        ppp_password_mode: PppPasswordMode;
        ppp_password_enc: string | null;
        tunnel_ip: string;
        lan_subnet: string | null;
        ppp_profile: string | null;
        concentrator_id: number;
        source: PlanSource | null;
      }
    | undefined;
  if (!row) {
    throw new AllocationError(
      'NOT_ALLOCATED',
      `site ${siteId} has no allocation in tenant ${tenantId}. Allocate the site first, then retry.`,
    );
  }
  let pppPassword: string | null;
  if (row.ppp_password_mode === 'per_site') {
    // VaultError on failure names the key generation and nothing else. A
    // 'per_site' row without a blob is an adopted one (044's CHECK admits no
    // other): its password is unknown, NEVER the shared one.
    pppPassword = row.ppp_password_enc ? decrypt(row.ppp_password_enc) : null;
  } else {
    pppPassword = await readSharedPppPassword(db, `site ${siteId}`);
  }
  return {
    siteId,
    tenantId,
    pppUsername: row.ppp_username,
    pppPassword,
    tunnelIp: row.tunnel_ip,
    lanSubnet: row.lan_subnet,
    pppProfile: row.ppp_profile,
    concentratorId: row.concentrator_id,
    source: row.source,
  };
}

/**
 * Record where the concentrator side of a site stands. For the concentrator
 * job; kept here so `site_provisioning` has exactly one module that writes it.
 *
 * `error` is REQUIRED for 'failed' (the CHECK in migration 036 refuses a
 * failure without a reason) and cleared for the other states. It is shown on
 * an operator's screen: never pass a text that contains the PPP password — a
 * RouterOS echo of the `/ppp secret add` line does.
 * `jobId` left undefined keeps the stored one; `null` clears it.
 *
 * A job that finds the login or the address already declared on the CHR
 * records 'failed' with that reason, and the site is then released
 * (`releaseAllocation`) and allocated again.
 */
export async function recordConcentratorOutcome(
  siteId: number,
  tenantId: number,
  outcome: { state: ConcentratorState; jobId?: number | null; error?: string | null },
): Promise<SiteProvisioningView> {
  assertId(siteId, 'siteId', PG_INT_MAX);
  assertId(tenantId, 'tenantId', PG_INT_MAX);
  if (!(CONCENTRATOR_STATES as readonly string[]).includes(outcome.state)) {
    throw new AllocationError(
      'INVALID_INPUT',
      `concentrator state must be one of ${CONCENTRATOR_STATES.join(', ')}.`,
    );
  }
  const error = typeof outcome.error === 'string' ? outcome.error.trim() : '';
  if (outcome.state === 'failed' && error === '') {
    throw new AllocationError('INVALID_INPUT', "a 'failed' concentrator state needs an error text.");
  }
  const patch: Record<string, unknown> = {
    concentrator_state: outcome.state,
    concentrator_error: outcome.state === 'failed' ? error.slice(0, CONCENTRATOR_ERROR_MAX) : null,
    updated_at: db.fn.now(),
  };
  if (outcome.jobId !== undefined) {
    // change_jobs.id is a bigint: the int4 bound would refuse a real job id.
    if (outcome.jobId !== null) assertId(outcome.jobId, 'jobId', Number.MAX_SAFE_INTEGER);
    patch.concentrator_job_id = outcome.jobId;
  }
  const updated = await db('site_provisioning')
    .where({ site_id: siteId, tenant_id: tenantId })
    .update(patch);
  if (updated === 0) {
    throw new AllocationError(
      'NOT_ALLOCATED',
      `site ${siteId} has no allocation in tenant ${tenantId}. Allocate the site first, then retry.`,
    );
  }
  const row = await readProvisioning(db, siteId);
  if (!row) throw new Error(`site ${siteId} allocation vanished after its update`);
  return toProvisioningView(row);
}

/**
 * The `site_rename` job's write on `site_provisioning` (services/change/
 * siteRename.service.ts): the PPP login, and the identity when the allocation
 * recorded the old one. Kept here so `site_provisioning` keeps exactly one
 * module that writes it. Runs in the CALLER's transaction, which holds the
 * allocation lock (the login is unique without case across every tenant, and
 * the allocator reads it under that lock).
 *
 * OPTIMISTIC: the row must still hold `from` (or already `to`, a re-run);
 * a login that moved to anything else since the job was queued throws, and
 * nothing is written. An identity is changed only when the row holds the old
 * one (case-folded); an allocation with no identity, or another one, is left
 * alone. A site without an allocation is `none`.
 */
export async function renameAllocationNames(
  trx: Knex.Transaction,
  siteId: number,
  tenantId: number,
  change: { login?: { from: string; to: string }; identity?: { from: string; to: string } },
): Promise<{ login: 'renamed' | 'already' | 'none'; identity: 'renamed' | 'already' | 'none' }> {
  assertId(siteId, 'siteId', PG_INT_MAX);
  assertId(tenantId, 'tenantId', PG_INT_MAX);
  const row = (await trx('site_provisioning')
    .where({ site_id: siteId, tenant_id: tenantId })
    .forUpdate()
    .first('ppp_username', 'system_identity')) as { ppp_username: string; system_identity: string | null } | undefined;
  if (!row) return { login: 'none', identity: 'none' };
  const patch: Record<string, unknown> = {};
  let login: 'renamed' | 'already' | 'none' = 'none';
  if (change.login) {
    if (row.ppp_username === change.login.to) login = 'already';
    else if (row.ppp_username === change.login.from) {
      patch.ppp_username = change.login.to;
      login = 'renamed';
    } else {
      throw new AllocationError(
        'CONFLICT',
        `site ${siteId}: its allocation holds the PPP login "${row.ppp_username}", neither "${change.login.from}" nor "${change.login.to}"; nothing was renamed.`,
      );
    }
  }
  let identity: 'renamed' | 'already' | 'none' = 'none';
  if (change.identity && row.system_identity !== null) {
    if (row.system_identity === change.identity.to) identity = 'already';
    else if (row.system_identity.toLowerCase() === change.identity.from.toLowerCase()) {
      patch.system_identity = change.identity.to;
      identity = 'renamed';
    }
  }
  if (Object.keys(patch).length > 0) {
    await trx('site_provisioning')
      .where({ site_id: siteId, tenant_id: tenantId })
      .update({ ...patch, updated_at: trx.fn.now() });
  }
  return { login, identity };
}

// ============================================================================
// Computed values for the compile path, previews and listings (allocation v3)
// ============================================================================

/** The keys the converted customer templates declare at level 'computed' and
 *  that the allocator itself produces. The policy's derived values come on
 *  top, under their own keys. */
export interface ComputedSiteValues {
  siteId: number;
  tenantId: number;
  /** true when this call created the allocation. */
  created: boolean;
  site_code: string;
  ppp_username: string;
  /** PLAINTEXT, memory only: for the server-side compile path and the
   *  concentrator job. Never logged, never stored, never sent to a browser. */
  ppp_password: string;
  ppp_password_mode: PppPasswordMode;
  tunnel_ip: string;
  lan_subnet: string | null;
  system_identity: string | null;
  concentrator_id: number;
  ppp_profile: string | null;
  /** Every NON-secret computed value by template key: site_code,
   *  ppp_username, tunnel_ip, lan_subnet and system_identity when set, then
   *  the policy's derived values. ppp_password is deliberately not in it. */
  values: Record<string, string>;
  /** 'adopted_chr' when the allocation was read from a secret the CHR already
   *  declared; null for a row older than migration 044. */
  source: PlanSource | null;
  /** As in `AllocationResult.warnings` — for an adopted 'shared' site, among
   *  others, that the shared password is ASSUMED to be the CHR secret's. */
  warnings: string[];
}

/** What `computedForSite` would return, without committing and without the
 *  password. `committed` = an allocation exists and these are its values. */
export interface SiteComputedPreview {
  siteId: number;
  tenantId: number;
  committed: boolean;
  site_code: string;
  ppp_username: string;
  ppp_password_mode: PppPasswordMode;
  tunnel_ip: string;
  lan_subnet: string | null;
  system_identity: string | null;
  concentrator_id: number;
  values: Record<string, string>;
  /** Not committed only: the seed gate that would refuse the allocation now. */
  blockedBy: AllocationPreview['blockedBy'];
  /** 'adopted_chr' when the values are (or would be) read from a secret the
   *  CHR already declares; null for a committed row older than migration 044. */
  source: PlanSource | null;
  /** As in `AllocationResult.warnings`. */
  warnings: string[];
}

interface SiteRow {
  id: number;
  tenant_id: number;
  code: string;
  name: string;
  country: string | null;
}

async function readSiteInTenant(q: Knex, tenantId: number, siteId: number): Promise<SiteRow> {
  const site = (await q('sites')
    .where({ id: siteId, tenant_id: tenantId })
    .first('id', 'tenant_id', 'code', 'name', 'country')) as SiteRow | undefined;
  if (!site) throw new AllocationError('SITE_NOT_FOUND', `site ${siteId} does not exist in tenant ${tenantId}.`);
  return site;
}

function loginVarsOf(site: SiteRow, ctx: LoginContext) {
  return {
    siteName: site.name,
    siteCode: site.code,
    siteCountry: site.country,
    tenantSlug: ctx.tenantSlug,
    instanceDomain: ctx.instanceDomain,
  };
}

function computedValues(
  site: SiteRow,
  ctx: LoginContext,
  policy: AllocationPolicy,
  given: { pppUsername: string; tunnelIp: string; lanSubnet: string | null; systemIdentity: string | null },
): Record<string, string> {
  const label = siteLabel({ code: site.code, name: site.name });
  const derived = evaluateDerived(policy.derived, {
    lanSubnet: given.lanSubnet,
    login: loginVarsOf(site, ctx),
    siteLabel: label,
  });
  if (!derived.ok) throw new AllocationError('DERIVED_INVALID', derived.message);
  const values: Record<string, string> = {
    site_code: site.code,
    ppp_username: given.pppUsername,
    tunnel_ip: given.tunnelIp,
  };
  if (given.lanSubnet !== null) values.lan_subnet = given.lanSubnet;
  if (given.systemIdentity !== null) values.system_identity = given.systemIdentity;
  return { ...values, ...derived.values };
}

/** Render the identity of an allocated site whose row predates identity
 *  templates (or whose policy gained one since). Throws on a refusal. */
function renderIdentityFor(site: SiteRow, ctx: LoginContext, policy: AllocationPolicy): string | null {
  if (!policy.identity) return null;
  const r = renderSystemIdentity(policy.identity, loginVarsOf(site, ctx), siteLabel(site));
  if (!r.ok) throw new AllocationError(r.reason, r.message);
  return r.identity;
}

/**
 * Fill `system_identity` on an allocation that has none, ONCE: an identity is
 * what assertTargetBinding later compares against, so a filled one is
 * never rewritten here, whatever the template says today.
 */
async function fillIdentity(site: SiteRow, ctx: LoginContext, policy: AllocationPolicy): Promise<string | null> {
  const identity = renderIdentityFor(site, ctx, policy);
  if (identity === null) return null;
  return db.transaction(async (trx) => {
    await takeAllocationLock(trx);
    const current = (await trx('site_provisioning').where({ site_id: site.id }).first('system_identity')) as
      | { system_identity: string | null }
      | undefined;
    if (current?.system_identity) return current.system_identity;
    const holders = (await loadIdentityHolders(trx, [identity])).filter((h) => h.ref !== site.id);
    if (holders.length > 0) {
      throw new AllocationError(
        'IDENTITY_TAKEN',
        `site ${siteLabel(site)}: the system identity "${identity}" is already given to ` +
          `${describeHolder(holders[0], site.tenant_id)}. Change the tenant's identity template or the ` +
          "site's code, then retry.",
        undefined,
        holders[0],
      );
    }
    await trx('site_provisioning')
      .where({ site_id: site.id })
      .whereNull('system_identity')
      .update({ system_identity: identity, updated_at: trx.fn.now() });
    return identity;
  });
}

/**
 * Every value the converted templates declare at level 'computed', for one
 * site, plus the PPP password in plaintext for the compile path. IDEMPOTENT:
 * the first call allocates (allocateForSite), every later call returns the
 * same allocation. Derived values are recomputed from what is stored.
 *
 * REFUSES PASSWORD_UNKNOWN for a site ADOPTED in 'per_site' mode: the
 * allocation stands (it is what the CHR declares — the first call commits it,
 * like any other), but no password is known for it and none is invented, so
 * nothing the compile path would render could authenticate.
 */
export async function computedForSite(tenantId: number, siteId: number): Promise<ComputedSiteValues> {
  assertId(tenantId, 'tenantId', PG_INT_MAX);
  assertId(siteId, 'siteId', PG_INT_MAX);
  const site = await readSiteInTenant(db, tenantId, siteId);
  const { provisioning, created, warnings } = await allocateForSite(siteId, { tenantId });
  if (!provisioning.pppPasswordKnown) throw passwordUnknown(siteId, provisioning.concentratorId);

  const pools = await loadPools(db);
  const { policy } = await loadPolicy(db, tenantId, pools);
  const ctx = await loadLoginContext(db, tenantId);
  const systemIdentity = provisioning.systemIdentity ?? (await fillIdentity(site, ctx, policy));
  const values = computedValues(site, ctx, policy, { ...provisioning, systemIdentity });
  const credential = await revealPppCredential(siteId, tenantId);

  return {
    siteId,
    tenantId,
    created,
    site_code: site.code,
    ppp_username: provisioning.pppUsername,
    ppp_password: credential.pppPassword,
    ppp_password_mode: provisioning.pppPasswordMode,
    tunnel_ip: provisioning.tunnelIp,
    lan_subnet: provisioning.lanSubnet,
    system_identity: systemIdentity,
    concentrator_id: provisioning.concentratorId,
    ppp_profile: provisioning.pppProfile,
    values,
    source: provisioning.source,
    warnings,
  };
}

/**
 * NON-COMMITTING: what `computedForSite` would give this site, without the
 * password and without writing anything. An allocated site shows its stored
 * allocation (`committed: true`); any other site the plan the allocator would
 * make now, against the same state (a refusal is thrown as the allocation
 * would throw it, and PASSWORD_UNKNOWN as `computedForSite` would for a site
 * adopted, or about to be, in 'per_site' mode). Like a preview, it may re-read
 * a stale CHR seed first.
 */
export async function previewForSite(tenantId: number, siteId: number): Promise<SiteComputedPreview> {
  assertId(tenantId, 'tenantId', PG_INT_MAX);
  assertId(siteId, 'siteId', PG_INT_MAX);
  const site = await readSiteInTenant(db, tenantId, siteId);
  const existing = await readProvisioning(db, siteId);
  if (existing) {
    if (existing.tenant_id !== tenantId) throw new AllocationError('SITE_NOT_FOUND', `site ${siteId} does not exist.`);
    // The compile step reads the shared password; say so at plan time.
    if (existing.ppp_password_mode === 'shared') await sharedPasswordCiphertext(db, `site ${siteId}`);
    const view = toProvisioningView(existing);
    // ...and it refuses an adopted site whose password nobody holds.
    if (!view.pppPasswordKnown) throw passwordUnknown(siteId, view.concentratorId);
    const pools = await loadPools(db);
    const { policy } = await loadPolicy(db, tenantId, pools);
    const ctx = await loadLoginContext(db, tenantId);
    const systemIdentity = view.systemIdentity ?? renderIdentityFor(site, ctx, policy);
    return {
      siteId,
      tenantId,
      committed: true,
      site_code: site.code,
      ppp_username: view.pppUsername,
      ppp_password_mode: view.pppPasswordMode,
      tunnel_ip: view.tunnelIp,
      lan_subnet: view.lanSubnet,
      system_identity: systemIdentity,
      concentrator_id: view.concentratorId,
      values: computedValues(site, ctx, policy, { ...view, systemIdentity }),
      blockedBy: null,
      source: view.source,
      warnings: storedWarnings(view),
    };
  }

  const preview = await previewSites(tenantId, [
    { siteId: site.id, code: site.code, name: site.name, country: site.country },
  ]);
  const entry = preview.entries[0];
  if (!entry.plan) {
    const r = entry.refusal as AllocationRefusal;
    throw new AllocationError(r.reason, r.message, undefined, r.holder);
  }
  const plan = entry.plan;
  if (plan.source === 'adopted_chr' && preview.policy.pppPasswordMode === 'per_site') {
    // What computedForSite would do right after committing this adoption.
    throw new AllocationError(
      'PASSWORD_UNKNOWN',
      `site ${siteId}: concentrator ${preview.policy.concentratorId} declares this site's PPP login ` +
        `"${plan.pppLogin}", so its allocation would be ADOPTED from the CHR, and this tenant's policy ` +
        "gives each site its own password: the CHR's is never read, so ObliWAN would hold NO " +
        'password for it and will not invent one — the compile would be refused. If that account uses ' +
        "the fleet's shared PPP password, set the tenant's policy to the shared password first; " +
        "otherwise configure this router's PPP password by hand.",
    );
  }
  const values: Record<string, string> = { site_code: site.code, ppp_username: plan.pppLogin, tunnel_ip: plan.tunnelIp };
  if (plan.lanSubnet !== null) values.lan_subnet = plan.lanSubnet;
  if (plan.systemIdentity !== null) values.system_identity = plan.systemIdentity;
  return {
    siteId,
    tenantId,
    committed: false,
    site_code: site.code,
    ppp_username: plan.pppLogin,
    ppp_password_mode: preview.policy.pppPasswordMode,
    tunnel_ip: plan.tunnelIp,
    lan_subnet: plan.lanSubnet,
    system_identity: plan.systemIdentity,
    concentrator_id: preview.policy.concentratorId,
    values: { ...values, ...plan.derived },
    blockedBy: preview.blockedBy,
    source: plan.source,
    warnings: plan.warnings,
  };
}

/**
 * The next `limit` allocations of a tenant: its sites that have none yet, in
 * code order, planned read-only one after another. Nothing is written.
 */
export async function previewNextAllocations(tenantId: number, limit: number): Promise<AllocationPreview> {
  assertId(tenantId, 'tenantId', PG_INT_MAX);
  if (!Number.isInteger(limit) || limit < 1 || limit > PREVIEW_MAX) {
    throw new AllocationError('INVALID_INPUT', `limit must be an integer from 1 to ${PREVIEW_MAX}.`);
  }
  const rows = (await db('sites as s')
    .leftJoin('site_provisioning as p', 'p.site_id', 's.id')
    .where('s.tenant_id', tenantId)
    .whereNull('p.site_id')
    .orderBy('s.code')
    .limit(limit)
    .select('s.id', 's.code', 's.name', 's.country')) as Array<{
    id: number;
    code: string;
    name: string;
    country: string | null;
  }>;
  if (rows.length === 0) {
    if (!(await tenantExists(tenantId))) {
      throw new AllocationError('TENANT_NOT_FOUND', `tenant ${tenantId} does not exist.`);
    }
    const pools = await loadPools(db);
    const { row } = await loadPolicy(db, tenantId, pools);
    return { tenantId, policy: toPolicyView(row, pools), seeds: [], blockedBy: null, entries: [] };
  }
  return previewSites(
    tenantId,
    rows.map((r) => ({ siteId: r.id, code: r.code, name: r.name, country: r.country })),
  );
}

export interface AllocatedSiteView extends SiteProvisioningView {
  siteCode: string;
  siteName: string;
}

/** A tenant's allocated sites, in code order. No password. */
export async function listAllocations(tenantId: number): Promise<AllocatedSiteView[]> {
  assertId(tenantId, 'tenantId', PG_INT_MAX);
  const rows = (await db('site_provisioning as p')
    .join('sites as s', 's.id', 'p.site_id')
    .where('p.tenant_id', tenantId)
    .orderBy('s.code')
    .select(
      ...publicColumns('p'),
      's.code as site_code',
      's.name as site_name',
    )) as Array<ProvisioningRow & { site_code: string; site_name: string }>;
  return rows.map((r) => ({ ...toProvisioningView(r), siteCode: r.site_code, siteName: r.site_name }));
}

export interface ConcentratorOption {
  id: number;
  name: string;
  tenantId: number;
}

/** Devices declared as concentrators, for the policy form. */
export async function listConcentrators(): Promise<ConcentratorOption[]> {
  const rows = (await db('devices')
    .where({ role: 'concentrator' })
    .orderBy('name')
    .select('id', 'name', 'tenant_id')) as Array<{ id: number; name: string; tenant_id: number }>;
  return rows.map((r) => ({ id: r.id, name: r.name, tenantId: r.tenant_id }));
}
