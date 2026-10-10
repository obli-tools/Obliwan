import {
  formulaUsesId,
  parseAddressFormula,
  renderAddressFormula,
  type AddressFormula,
} from './formula';
import {
  parseIdentityTemplate,
  parseLoginTemplate,
  renderPppLogin,
  renderSystemIdentity,
  siteNumber,
  type LoginTemplate,
} from './pppIdentity';
import { evaluateDerived, parseDerivedValues, type DerivedValue } from './derived';
import { SEED_MAX_AGE_MS } from './seed';

/**
 * policy.ts — the allocation engine. PURE: no database, no clock, no
 * randomness. The allocator reads the state, hands it here, and writes what
 * comes back; the preview calls the very same `planSites`, so on the same state
 * a preview and an allocation give the same answer. (Between the two another
 * allocation can change the state — a preview is a forecast.)
 *
 * ┌─ THE OPERATOR'S RULES ───────────────────────────────────────────────────┐
 * │ A site gets a TUNNEL address (a /32, the CHR secret's remote-address)     │
 * │ and, optionally, a LAN subnet. Each comes from an ADDRESS POOL — a named  │
 * │ block with a purpose, 'tunnel' or 'lan' — by one of two mechanisms, set  │
 * │ per tenant and per side:                                                 │
 * │                                                                          │
 * │   incremental  tunnel: the lowest free host from the tenant's START      │
 * │                address up to the end of the pool, skipping the .0 and    │
 * │                .255 of every /24. Pool 100.68.0.0/16, start 100.68.1.1:  │
 * │                1st site 100.68.1.1, 90th 100.68.1.90, 255th 100.68.2.1.  │
 * │                LAN: the lowest free block of the configured prefix.      │
 * │   formula      an expression per octet over the site NUMBER `id`         │
 * │                (formula.ts): "100.65.{id/100}.{id%100}", site 1091 ->    │
 * │                100.65.10.91. A ".0" host is valid: a /32 has no network. │
 * │                Every octet 0-255 and the result inside the pool, or the  │
 * │                site is REFUSED by name. Never skipped past: the formula  │
 * │                IS the site's address, so a held one is a refusal.        │
 * │                                                                          │
 * │ A site already DEPLOYED — its login declared as a secret on the tenant's │
 * │ own CHR — is ADOPTED rather than refused (`adoptDeclared`): the CHR is   │
 * │ its source of truth, so its login and tunnel address are what that       │
 * │ secret declares, whatever either mechanism would have computed.          │
 * │                                                                          │
 * │ Pools are shared by reference: several small tenants may point their     │
 * │ incremental rule at the same pool, and the walk passes over whatever any │
 * │ of them holds. A FORMULA pool belongs to one tenant — two tenants' site 1 │
 * │ would compute the same address — and `policyConflicts` refuses a policy  │
 * │ that would share one.                                                    │
 * │                                                                          │
 * │ UNIQUENESS. A tunnel address is unique across the installation, and a    │
 * │ tunnel pool overlaps no other pool. A LAN subnet is unique within its    │
 * │ tenant and within the pool it was drawn from — tenants pointing at ONE   │
 * │ LAN pool share its space and get disjoint blocks — but two tenants that  │
 * │ each own a LAN pool over the same block REUSE one plan: LAN pools may    │
 * │ overlap each other for exactly that. Reuse is the operator's choice,      │
 * │ made by creating that second pool; it is the wrong one when the LANs are │
 * │ routed side by side on a shared CHR (`routes=` on the secret).           │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * IPv4 only. Addresses are plain numbers in [0, 2^32) and NEVER go through
 * JavaScript's bitwise operators, which are signed 32-bit and turn 128.0.0.0
 * and above into negative numbers.
 */

// ============================================================================
// IPv4 arithmetic
// ============================================================================

/** Strict dotted quad: four decimal octets, no leading zero (a leading zero is
 *  octal to some parsers, and "010" meaning 8 on one tool and 10 on another is
 *  the kind of disagreement that puts two routers on one address). */
export function parseIpv4(text: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (!m) return null;
  let value = 0;
  for (let i = 1; i <= 4; i += 1) {
    const part = m[i];
    if (part.length > 1 && part[0] === '0') return null;
    const n = Number(part);
    if (n > 255) return null;
    value = value * 256 + n;
  }
  return value;
}

export function formatIpv4(value: number): string {
  return [
    Math.floor(value / 16777216) % 256,
    Math.floor(value / 65536) % 256,
    Math.floor(value / 256) % 256,
    value % 256,
  ].join('.');
}

export interface Cidr {
  /** First address of the block (the network address). */
  network: number;
  prefix: number;
  /** Number of addresses in the block, 2^(32 - prefix). */
  size: number;
}

export function cidrLast(c: Cidr): number {
  return c.network + c.size - 1;
}

export function formatCidr(c: Cidr): string {
  return `${formatIpv4(c.network)}/${c.prefix}`;
}

export function cidrContains(c: Cidr, address: number): boolean {
  return address >= c.network && address <= cidrLast(c);
}

export function rangesOverlap(aStart: number, aEnd: number, bStart: number, bEnd: number): boolean {
  return aStart <= bEnd && bStart <= aEnd;
}

export type CidrParse = { ok: true; cidr: Cidr } | { ok: false; error: string };

/**
 * Parse `a.b.c.d/nn`. Refuses — with a sentence an operator can act on — a bare
 * address, an IPv6 block, and a block with host bits set. The last one is
 * refused rather than masked because PostgreSQL's `cidr` refuses it too, and
 * silently turning 10.20.7.1/16 into 10.20.0.0/16 would hand out an address
 * range the operator did not type.
 */
export function parseCidr(text: string): CidrParse {
  const trimmed = text.trim();
  if (trimmed.includes(':')) {
    return { ok: false, error: 'IPv6 blocks are not supported; tunnel and LAN allocation is IPv4.' };
  }
  const slash = trimmed.indexOf('/');
  if (slash < 0) {
    return { ok: false, error: `"${trimmed}" has no prefix length; write it as a.b.c.d/nn.` };
  }
  const address = parseIpv4(trimmed.slice(0, slash));
  const prefixText = trimmed.slice(slash + 1);
  if (address === null || !/^\d{1,2}$/.test(prefixText)) {
    return { ok: false, error: `"${trimmed}" is not an IPv4 block (a.b.c.d/nn).` };
  }
  const prefix = Number(prefixText);
  if (prefix > 32) return { ok: false, error: `"${trimmed}": the prefix length must be 0..32.` };
  const size = 2 ** (32 - prefix);
  const network = address - (address % size);
  if (network !== address) {
    return {
      ok: false,
      error:
        `"${trimmed}" has host bits set; the block it lies in is ${formatIpv4(network)}/${prefix}. ` +
        'Write the network address.',
    };
  }
  return { ok: true, cidr: { network, prefix, size } };
}

/** Largest value of a PostgreSQL `integer` — the type of every id this module
 *  is handed (tenants, sites, devices, pools). A larger one is refused as a 400
 *  here: sent to PostgreSQL it raises 22003 "out of range", which no handler
 *  maps and which reaches the caller as a bare 500. */
export const PG_INT_MAX = 2_147_483_647;

function isBlank(v: unknown): boolean {
  return v === undefined || v === null || (typeof v === 'string' && v.trim() === '');
}

/** An integer field: a JS integer, or a string of digits (query strings and
 *  form posts). `Number(' ')` is 0, hence the trim-and-test first. */
function readInt(v: unknown): number | null {
  if (typeof v === 'number') return Number.isInteger(v) ? v : null;
  if (typeof v === 'string') {
    const t = v.trim();
    return /^-?\d{1,15}$/.test(t) ? Number(t) : null;
  }
  return null;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

type FieldErrors = Record<string, string[]>;

function collector(): { errors: FieldErrors; fail: (field: string, message: string) => void } {
  const errors: FieldErrors = {};
  return {
    errors,
    fail: (field, message) => {
      (errors[field] ??= []).push(message);
    },
  };
}

// ============================================================================
// Address pools
// ============================================================================

export const POOL_PURPOSES = ['tunnel', 'lan'] as const;
export type PoolPurpose = (typeof POOL_PURPOSES)[number];

/** Pool size bounds, restated by the CHECK in migration 036. /8 as a floor keeps
 *  an incremental walk over a nearly full pool inside numbers nobody has to
 *  think about; /30 as a ceiling keeps at least one usable block. */
export const POOL_PREFIX_MIN = 8;
export const POOL_PREFIX_MAX = 30;
export const POOL_NAME_MAX = 64;

export interface AddressPool {
  id: number;
  name: string;
  cidr: Cidr;
  purpose: PoolPurpose;
}

export type PoolNameParse = { ok: true; name: string } | { ok: false; error: string };

export function validatePoolName(raw: unknown): PoolNameParse {
  if (typeof raw !== 'string' || raw.trim() === '') return { ok: false, error: 'name is required.' };
  const name = raw.trim();
  if (name.length > POOL_NAME_MAX) return { ok: false, error: `name is longer than ${POOL_NAME_MAX} characters.` };
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(name)) return { ok: false, error: 'name may not hold control characters.' };
  return { ok: true, name };
}

export type PoolValidation =
  | { ok: true; pool: { name: string; cidr: Cidr; purpose: PoolPurpose } }
  | { ok: false; errors: FieldErrors };

/** A pool as POSTed: `{ name, cidr, purpose }`. Overlap with other pools is the
 *  database's to judge (an exclusion constraint), not this function's. */
export function validatePoolInput(raw: unknown): PoolValidation {
  const { errors, fail } = collector();
  const body = isRecord(raw) ? raw : {};
  const name = validatePoolName(body.name);
  if (!name.ok) fail('name', name.error);

  let cidr: Cidr | null = null;
  if (typeof body.cidr !== 'string' || body.cidr.trim() === '') {
    fail('cidr', 'cidr is required (an IPv4 block such as 100.68.0.0/16).');
  } else {
    const parsed = parseCidr(body.cidr);
    if (!parsed.ok) fail('cidr', parsed.error);
    else if (parsed.cidr.prefix < POOL_PREFIX_MIN || parsed.cidr.prefix > POOL_PREFIX_MAX) {
      fail('cidr', `a pool must be between /${POOL_PREFIX_MIN} and /${POOL_PREFIX_MAX}.`);
    } else cidr = parsed.cidr;
  }

  const purpose = typeof body.purpose === 'string' ? body.purpose.trim() : '';
  if (!(POOL_PURPOSES as readonly string[]).includes(purpose)) {
    fail('purpose', `purpose must be one of ${POOL_PURPOSES.join(', ')}.`);
  }

  if (!name.ok || cidr === null || Object.keys(errors).length > 0) return { ok: false, errors };
  return { ok: true, pool: { name: name.name, cidr, purpose: purpose as PoolPurpose } };
}

/**
 * The first existing pool `candidate` may not overlap, or null. A TUNNEL pool
 * overlaps nothing: a tunnel /32 inside another pool is one address with two
 * owners. A LAN pool may overlap another LAN pool — that is how two tenants
 * reuse one LAN plan (the UNIQUENESS paragraph above) — but never a tunnel
 * pool. Migration 036 enforces the tunnel-against-tunnel half itself; the
 * tunnel-against-LAN half is this function's, called by `createPool` under
 * the allocation lock.
 */
export function poolOverlapConflict(
  candidate: { cidr: Cidr; purpose: PoolPurpose },
  pools: Iterable<AddressPool>,
): AddressPool | null {
  const start = candidate.cidr.network;
  const end = cidrLast(candidate.cidr);
  for (const p of pools) {
    if (candidate.purpose === 'lan' && p.purpose === 'lan') continue;
    if (rangesOverlap(start, end, p.cidr.network, cidrLast(p.cidr))) return p;
  }
  return null;
}

// ============================================================================
// Policy
// ============================================================================

/** Values of `tunnel_mode` / `lan_mode`. Kept in lockstep with the CHECKs in
 *  migration 036. */
export const ADDRESS_MODES = ['incremental', 'formula'] as const;
export type AddressMode = (typeof ADDRESS_MODES)[number];

export type TunnelRule =
  | { mode: 'incremental'; pool: AddressPool; start: number }
  | { mode: 'formula'; pool: AddressPool; formula: AddressFormula };

/** LAN modes. 'fixed' = the same LAN on every site of the tenant (never
 *  unique, never from a pool); 'manual' = each site's LAN is supplied as a
 *  SITE variable (e.g. by the CSV import), judged but not chosen here. */
export const LAN_MODES = ['incremental', 'formula', 'fixed', 'manual'] as const;
export type LanMode = (typeof LAN_MODES)[number];

export type LanRule =
  | { mode: 'incremental'; pool: AddressPool; prefix: number }
  | { mode: 'formula'; pool: AddressPool; formula: AddressFormula }
  | { mode: 'fixed'; subnet: Cidr }
  | { mode: 'manual'; variable: string };

/** 'shared' (the operator's default): every site uses the fleet-wide PPP
 *  password held by the INSTANCE variable SHARED_PPP_PASSWORD_KEY, and no
 *  per-site copy is stored. 'per_site': generated and vaulted per site. */
export const PPP_PASSWORD_MODES = ['shared', 'per_site'] as const;
export type PppPasswordMode = (typeof PPP_PASSWORD_MODES)[number];
export const DEFAULT_PPP_PASSWORD_MODE: PppPasswordMode = 'shared';
/** The instance variable the converted templates declare for the fleet-wide
 *  PPP password (x-obliwan-level 'instance', secret). */
export const SHARED_PPP_PASSWORD_KEY = 'ppp_password';

/** A policy as the engine uses it: validated, normalised, pools resolved. */
export interface AllocationPolicy {
  tenantId: number;
  tunnel: TunnelRule;
  /** `null` = this tenant's sites get no LAN subnet. */
  lan: LanRule | null;
  login: LoginTemplate;
  /** `null` = the system identity is not computed for this tenant. */
  identity: LoginTemplate | null;
  passwordMode: PppPasswordMode;
  derived: DerivedValue[];
  pppProfile: string | null;
  /** The CHR that terminates this tenant's tunnels, and whose declared
   *  secrets must have been read before anything is allocated. */
  concentratorId: number;
  /** The shape a NEW site code of this tenant must have (migration 052,
   *  `judgeSiteCode`). Judged by the CSV import and by site.service's
   *  createSite / updateSite (the site form, and the reconciliation's orphan
   *  sites, which reach createSite). NOT judged by the tenant bundle import
   *  (importExport.controller), which writes codes as the bundle carries them,
   *  and NOT by `planSite`: a site whose code predates the format is still
   *  allocated, and an adopted one has to be. */
  siteCodeFormat: SiteCodeFormat;
}

/**
 * The body PUT /api/allocation/tenants/:tenantId/policy accepts, and the shape
 * the row mapper produces:
 *
 *   {
 *     tunnel: { poolId, mode: 'incremental', start: '100.68.1.1' }
 *           | { poolId, mode: 'formula',     formula: '100.65.{id/100}.{id%100}' },
 *     lan?:   null
 *           | { poolId, mode: 'incremental', prefix: 24 }
 *           | { poolId, mode: 'formula',     formula: '10.{100+id/100}.{id%100}.0/24' }
 *           | { mode: 'fixed',  subnet: '192.168.88.0/24' }
 *           | { mode: 'manual', variable: 'lan_subnet' },
 *     pppLoginTemplate: '{site.slug}.{site.country}.{tenant.slug}.{instance.domain}',
 *     systemIdentityTemplate?: string | null,
 *     pppPasswordMode?: 'shared' | 'per_site'      (absent = 'shared'),
 *     derived?: { [key]: expression } | null,
 *     pppProfile?: string | null,
 *     concentratorId: number,
 *     siteCodeFormat?: 'free' | 'digits:5' | null   (null or 'free' = no rule;
 *                      ABSENT = the stored format is kept, see upsertPolicy),
 *   }
 */
export interface AllocationPolicyInput {
  tunnel?: unknown;
  lan?: unknown;
  pppLoginTemplate?: unknown;
  systemIdentityTemplate?: unknown;
  pppPasswordMode?: unknown;
  derived?: unknown;
  pppProfile?: unknown;
  concentratorId?: unknown;
  siteCodeFormat?: unknown;
}

const LAN_VARIABLE_RE = /^[a-z][a-z0-9_]{0,119}$/;

export type PolicyValidation =
  | { ok: true; policy: AllocationPolicy }
  | { ok: false; errors: FieldErrors };

const PPP_PROFILE_RE = /^[A-Za-z0-9._-]{1,64}$/;

/**
 * Site numbers tried when a formula is SAVED, to refuse one that can never
 * render an address inside its pool (a typo in the first octets, a pool picked
 * from the wrong row). It does not judge any particular site: that happens at
 * allocation, where each site's own number is rendered.
 */
export const FORMULA_PROBE_MAX = 99_999;

function blockFits(pool: Cidr, network: number, prefix: number): boolean {
  const size = 2 ** (32 - prefix);
  return network % size === 0 && network >= pool.network && network + size - 1 <= cidrLast(pool);
}

/** True when some site number in [0, FORMULA_PROBE_MAX] renders a result the
 *  allocator could hand out from `pool`. */
function formulaReachesPool(f: AddressFormula, pool: Cidr): boolean {
  for (let id = 0; id <= FORMULA_PROBE_MAX; id += 1) {
    const r = renderAddressFormula(f, id);
    if (!r.ok) continue;
    if (r.prefix === null ? cidrContains(pool, r.address) : blockFits(pool, r.address, r.prefix)) return true;
  }
  return false;
}

function resolvePool(
  raw: unknown,
  field: string,
  purpose: PoolPurpose,
  pools: ReadonlyMap<number, AddressPool>,
  fail: (field: string, message: string) => void,
): AddressPool | null {
  const id = readInt(raw);
  if (id === null || id <= 0 || id > PG_INT_MAX) {
    fail(field, `poolId must be an address pool id (an integer from 1 to ${PG_INT_MAX}).`);
    return null;
  }
  const pool = pools.get(id);
  if (!pool) {
    fail(field, `address pool ${id} does not exist.`);
    return null;
  }
  if (pool.purpose !== purpose) {
    fail(field, `address pool "${pool.name}" is a ${pool.purpose} pool; this rule needs a ${purpose} pool.`);
    return null;
  }
  return pool;
}

function readMode(raw: unknown, field: string, fail: (f: string, m: string) => void): AddressMode | null {
  const mode = typeof raw === 'string' ? raw.trim() : '';
  if (!(ADDRESS_MODES as readonly string[]).includes(mode)) {
    fail(field, `mode must be one of ${ADDRESS_MODES.join(', ')}.`);
    return null;
  }
  return mode as AddressMode;
}

function validateTunnel(
  raw: unknown,
  pools: ReadonlyMap<number, AddressPool>,
  probe: boolean,
  fail: (f: string, m: string) => void,
): TunnelRule | null {
  if (!isRecord(raw)) {
    fail('tunnel', 'tunnel is required: { poolId, mode, start | formula }.');
    return null;
  }
  const pool = resolvePool(raw.poolId, 'tunnel.poolId', 'tunnel', pools, fail);
  const mode = readMode(raw.mode, 'tunnel.mode', fail);
  if (!pool || !mode) return null;

  if (mode === 'incremental') {
    if (!isBlank(raw.formula)) fail('tunnel.formula', 'only a formula rule takes a formula; remove it.');
    if (typeof raw.start !== 'string' || raw.start.trim() === '') {
      fail('tunnel.start', 'an incremental rule needs its start address, e.g. 100.68.1.1.');
      return null;
    }
    const start = parseIpv4(raw.start.trim());
    if (start === null) {
      fail('tunnel.start', `"${raw.start.trim()}" is not an IPv4 address.`);
      return null;
    }
    if (!cidrContains(pool.cidr, start)) {
      fail('tunnel.start', `${formatIpv4(start)} is outside pool "${pool.name}" (${formatCidr(pool.cidr)}).`);
      return null;
    }
    if (start % 256 === 0 || start % 256 === 255) {
      fail(
        'tunnel.start',
        `${formatIpv4(start)} ends in .0 or .255, which an incremental rule never hands out; ` +
          'start on the first address you want given.',
      );
      return null;
    }
    return { mode, pool, start };
  }

  if (!isBlank(raw.start)) fail('tunnel.start', 'only an incremental rule takes a start address; remove it.');
  if (typeof raw.formula !== 'string' || raw.formula.trim() === '') {
    fail('tunnel.formula', 'a formula rule needs its formula, e.g. 100.65.{id/100}.{id%100}.');
    return null;
  }
  const parsed = parseAddressFormula(raw.formula, { prefix: 'forbidden' });
  if (!parsed.ok) {
    fail('tunnel.formula', parsed.error);
    return null;
  }
  if (!formulaUsesId(parsed.formula)) {
    fail('tunnel.formula', 'the formula never uses id, so every site would get the same address.');
    return null;
  }
  if (probe && !formulaReachesPool(parsed.formula, pool.cidr)) {
    fail(
      'tunnel.formula',
      `for no site number from 0 to ${FORMULA_PROBE_MAX} does the formula render an address ` +
        `inside pool "${pool.name}" (${formatCidr(pool.cidr)}). Check its literal octets against the pool.`,
    );
    return null;
  }
  return { mode, pool, formula: parsed.formula };
}

function validateLan(
  raw: unknown,
  pools: ReadonlyMap<number, AddressPool>,
  probe: boolean,
  fail: (f: string, m: string) => void,
): LanRule | null | 'invalid' {
  if (raw === undefined || raw === null) return null;
  if (!isRecord(raw)) {
    fail('lan', 'lan is null (no LAN subnet) or { mode, poolId?, prefix | formula | subnet | variable }.');
    return 'invalid';
  }
  const lanMode = typeof raw.mode === 'string' ? raw.mode.trim() : '';
  if (lanMode === 'fixed' || lanMode === 'manual') {
    let bad = false;
    const refuse = (field: string, message: string): void => {
      bad = true;
      fail(field, message);
    };
    for (const k of ['poolId', 'prefix', 'formula'] as const) {
      if (!isBlank(raw[k])) refuse(`lan.${k}`, `a ${lanMode} LAN rule takes no ${k}; remove it.`);
    }
    if (lanMode === 'fixed') {
      if (!isBlank(raw.variable)) refuse('lan.variable', 'only a manual LAN rule takes a variable; remove it.');
      if (typeof raw.subnet !== 'string' || raw.subnet.trim() === '') {
        refuse('lan.subnet', 'a fixed LAN rule needs its subnet, e.g. 192.168.88.0/24.');
        return 'invalid';
      }
      const parsed = parseCidr(raw.subnet);
      if (!parsed.ok) {
        refuse('lan.subnet', parsed.error);
        return 'invalid';
      }
      if (parsed.cidr.prefix < POOL_PREFIX_MIN || parsed.cidr.prefix > POOL_PREFIX_MAX) {
        refuse('lan.subnet', `the subnet must be a /${POOL_PREFIX_MIN} to /${POOL_PREFIX_MAX}.`);
      }
      // A fixed LAN is carried by every site of the tenant, so one overlapping
      // a tunnel pool would put a router's tunnel address inside its own LAN.
      const fEnd = cidrLast(parsed.cidr);
      for (const pool of pools.values()) {
        if (pool.purpose !== 'tunnel') continue;
        if (rangesOverlap(parsed.cidr.network, fEnd, pool.cidr.network, cidrLast(pool.cidr))) {
          refuse('lan.subnet', `overlaps tunnel ${poolLabel(pool)}; a fixed LAN must stay outside every tunnel pool.`);
        }
      }
      return bad ? 'invalid' : { mode: 'fixed', subnet: parsed.cidr };
    }
    if (!isBlank(raw.subnet)) refuse('lan.subnet', 'only a fixed LAN rule takes a subnet; remove it.');
    const variable = typeof raw.variable === 'string' ? raw.variable.trim() : '';
    if (!LAN_VARIABLE_RE.test(variable)) {
      refuse(
        'lan.variable',
        "a manual LAN rule names the SITE variable holding each site's LAN, e.g. lan_subnet " +
          '(lowercase letters, digits and "_").',
      );
    }
    return bad ? 'invalid' : { mode: 'manual', variable };
  }
  if (!isBlank(raw.subnet)) fail('lan.subnet', 'only a fixed LAN rule takes a subnet; remove it.');
  if (!isBlank(raw.variable)) fail('lan.variable', 'only a manual LAN rule takes a variable; remove it.');
  const pool = resolvePool(raw.poolId, 'lan.poolId', 'lan', pools, fail);
  if (!(LAN_MODES as readonly string[]).includes(lanMode)) {
    fail('lan.mode', `mode must be one of ${LAN_MODES.join(', ')}.`);
    return 'invalid';
  }
  const mode = lanMode as 'incremental' | 'formula';
  if (!pool) return 'invalid';

  if (mode === 'incremental') {
    if (!isBlank(raw.formula)) fail('lan.formula', 'only a formula rule takes a formula; remove it.');
    const prefix = readInt(raw.prefix);
    if (prefix === null || prefix < POOL_PREFIX_MIN || prefix > POOL_PREFIX_MAX) {
      fail('lan.prefix', `an incremental LAN rule needs its block size, /${POOL_PREFIX_MIN} to /${POOL_PREFIX_MAX}.`);
      return 'invalid';
    }
    if (prefix < pool.cidr.prefix) {
      fail('lan.prefix', `a /${prefix} block does not fit in pool "${pool.name}" (${formatCidr(pool.cidr)}).`);
      return 'invalid';
    }
    return { mode, pool, prefix };
  }

  if (!isBlank(raw.prefix)) {
    fail('lan.prefix', 'a formula LAN rule carries its prefix in the formula ("…/24"); remove prefix.');
  }
  if (typeof raw.formula !== 'string' || raw.formula.trim() === '') {
    fail('lan.formula', 'a formula rule needs its formula, e.g. 10.{100+id/100}.{id%100}.0/24.');
    return 'invalid';
  }
  const parsed = parseAddressFormula(raw.formula, { prefix: 'required' });
  if (!parsed.ok) {
    fail('lan.formula', parsed.error);
    return 'invalid';
  }
  const prefix = parsed.formula.prefix ?? 0;
  if (prefix < POOL_PREFIX_MIN || prefix > POOL_PREFIX_MAX) {
    fail('lan.formula', `the formula's prefix must be /${POOL_PREFIX_MIN} to /${POOL_PREFIX_MAX}.`);
    return 'invalid';
  }
  if (prefix < pool.cidr.prefix) {
    fail('lan.formula', `a /${prefix} block does not fit in pool "${pool.name}" (${formatCidr(pool.cidr)}).`);
    return 'invalid';
  }
  if (!formulaUsesId(parsed.formula)) {
    fail('lan.formula', 'the formula never uses id, so every site would get the same subnet.');
    return 'invalid';
  }
  if (probe && !formulaReachesPool(parsed.formula, pool.cidr)) {
    fail(
      'lan.formula',
      `for no site number from 0 to ${FORMULA_PROBE_MAX} does the formula render a block inside ` +
        `pool "${pool.name}" (${formatCidr(pool.cidr)}). Check its literal octets against the pool.`,
    );
    return 'invalid';
  }
  return { mode, pool, formula: parsed.formula };
}

/**
 * Validate and normalise a policy. The SAME function reads the API body and the
 * stored row, so there is exactly one interpretation of a policy; the CHECKs in
 * migration 036 restate the structural half so a row written around this
 * function still cannot hold a mode without its fields.
 *
 * `probe` runs the save-time reachability test of each formula (FORMULA_PROBE_MAX
 * renders). The allocator re-validates the stored row WITHOUT it: the test
 * judges the policy, not a site, and it would otherwise run once per site under
 * the global lock.
 *
 * Errors are per field (`tunnel.start`, `lan.formula`, …), in the shape
 * `validate()` already sends, so a form can put each sentence under its input.
 */
export function validatePolicyInput(
  raw: unknown,
  ctx: { tenantId: number; pools: ReadonlyMap<number, AddressPool>; probe: boolean },
): PolicyValidation {
  const { errors, fail } = collector();
  const body = isRecord(raw) ? raw : {};
  if (!isRecord(raw)) fail('body', 'the policy must be a JSON object.');

  const tunnel = validateTunnel(body.tunnel, ctx.pools, ctx.probe, fail);
  const lan = validateLan(body.lan, ctx.pools, ctx.probe, fail);

  const login = parseLoginTemplate(body.pppLoginTemplate);
  if (!login.ok) fail('pppLoginTemplate', login.error);

  let identity: LoginTemplate | null = null;
  if (!isBlank(body.systemIdentityTemplate)) {
    const parsed = parseIdentityTemplate(body.systemIdentityTemplate);
    if (!parsed.ok) fail('systemIdentityTemplate', parsed.error);
    else identity = parsed.template;
  }

  let passwordMode: PppPasswordMode = DEFAULT_PPP_PASSWORD_MODE;
  if (!isBlank(body.pppPasswordMode)) {
    const m = typeof body.pppPasswordMode === 'string' ? body.pppPasswordMode.trim() : '';
    if (!(PPP_PASSWORD_MODES as readonly string[]).includes(m)) {
      fail('pppPasswordMode', `pppPasswordMode must be one of ${PPP_PASSWORD_MODES.join(', ')}.`);
    } else passwordMode = m as PppPasswordMode;
  }

  const derived = parseDerivedValues(body.derived);
  if (!derived.ok) {
    for (const [field, messages] of Object.entries(derived.errors)) for (const m of messages) fail(field, m);
  }

  let pppProfile: string | null = null;
  if (!isBlank(body.pppProfile)) {
    const p = typeof body.pppProfile === 'string' ? body.pppProfile.trim() : '';
    // Spliced bare into `/ppp secret add profile=...` on the CHR: no quoting.
    if (!PPP_PROFILE_RE.test(p)) {
      fail('pppProfile', 'pppProfile may only hold letters, digits, ".", "_" and "-" (1-64).');
    } else pppProfile = p;
  }

  let concentratorId: number | null = null;
  const c = readInt(body.concentratorId);
  if (c === null || c <= 0 || c > PG_INT_MAX) {
    fail(
      'concentratorId',
      `concentratorId is required: the device id of the CHR that terminates this tenant's tunnels ` +
        `(an integer from 1 to ${PG_INT_MAX}).`,
    );
  } else concentratorId = c;

  const codeFormat = parseSiteCodeFormat(body.siteCodeFormat);
  if (!codeFormat.ok) fail('siteCodeFormat', codeFormat.error);

  if (
    !tunnel ||
    lan === 'invalid' ||
    !login.ok ||
    !derived.ok ||
    concentratorId === null ||
    !codeFormat.ok ||
    Object.keys(errors).length > 0
  ) {
    return { ok: false, errors };
  }
  return {
    ok: true,
    policy: {
      tenantId: ctx.tenantId,
      tunnel,
      lan,
      login: login.template,
      identity,
      passwordMode,
      derived: derived.values,
      pppProfile,
      concentratorId,
      siteCodeFormat: codeFormat.format,
    },
  };
}

// ============================================================================
// Site code format (migration 052)
// ============================================================================

/**
 * What a site code of a tenant must look like. A code becomes the PPP login
 * and the system identity ({site.code}) and the site NUMBER of a formula
 * (`siteNumber`); once allocated it is on the CHR, and renaming the site does
 * not take it back. The commonest wrong code is a spreadsheet's: Excel reads
 * "00102" as the number 102 and writes it back as "102", "102.0" or "1,02E+02".
 *
 *   free       no rule beyond createSiteSchema's slug — what every tenant had
 *              before migration 052 (stored NULL).
 *   digits:N   exactly N decimal digits; leading zeros are significant.
 *
 * Stored in `tenant_allocation_policies.site_code_format`, NULL = free. The
 * CHECK of migration 052 admits 'digits:1' to 'digits:15' and nothing else.
 */
export type SiteCodeFormat = { kind: 'free' } | { kind: 'digits'; length: number };

/** `siteNumber`'s bound: 15 digits are still an exact JavaScript integer.
 *  Kept in lockstep with the CHECK of migration 052. */
export const SITE_CODE_DIGITS_MAX = 15;

export const FREE_SITE_CODE_FORMAT: SiteCodeFormat = Object.freeze({ kind: 'free' }) as SiteCodeFormat;

export type SiteCodeFormatParse = { ok: true; format: SiteCodeFormat } | { ok: false; error: string };

/** Reads the API spelling ('free', 'digits:5'; null or '' = free) and the
 *  stored one (NULL or 'digits:N') — one reader for both, so the column and
 *  the API cannot drift apart. */
export function parseSiteCodeFormat(raw: unknown): SiteCodeFormatParse {
  if (isBlank(raw)) return { ok: true, format: FREE_SITE_CODE_FORMAT };
  const text = typeof raw === 'string' ? raw.trim().toLowerCase() : '';
  if (text === 'free') return { ok: true, format: FREE_SITE_CODE_FORMAT };
  const m = /^digits:([0-9]{1,2})$/.exec(text);
  const n = m ? Number(m[1]) : NaN;
  if (Number.isInteger(n) && n >= 1 && n <= SITE_CODE_DIGITS_MAX) {
    return { ok: true, format: { kind: 'digits', length: n } };
  }
  return {
    ok: false,
    error:
      `siteCodeFormat must be "free" or "digits:N" with N from 1 to ${SITE_CODE_DIGITS_MAX} ` +
      '(e.g. "digits:5" for codes such as 00102).',
  };
}

/** The stored spelling: NULL for free. */
export function siteCodeFormatColumn(format: SiteCodeFormat): string | null {
  return format.kind === 'digits' ? `digits:${format.length}` : null;
}

/** The API spelling, as `parseSiteCodeFormat` reads it back. */
export function siteCodeFormatText(format: SiteCodeFormat): string {
  return format.kind === 'digits' ? `digits:${format.length}` : 'free';
}

/** What a spreadsheet makes of a number. Neither shape is a code anybody
 *  typed: scientific notation has lost digits for good, and a ".0" says the
 *  column was read as numbers, so its leading zeros are gone as well. Excel
 *  always writes the exponent's sign, which keeps a code such as "2E5" out. */
const SCIENTIFIC_RE = /^[0-9]+(?:[.,][0-9]+)?[eE][+-][0-9]+$/;
const TRAILING_ZERO_RE = /^[0-9]+([.,]0+)$/;
const DIGITS_RE = /^[0-9]+$/;

export type SiteCodeVerdict =
  | { ok: true; code: string; restoredFrom: string | null }
  | { ok: false; error: string };

/**
 * Judge one site code against the tenant's format. The code is expected
 * trimmed and non-empty (every caller refuses an empty one first); the slug
 * and length rules of createSiteSchema stay the caller's, applied to the code
 * this returns.
 *
 * Spreadsheet artefacts (scientific notation, a trailing ".0") are refused
 * under EVERY format, free included. Under digits:N, `restoreZeros` — the CSV
 * import only — left-pads a purely numeric code SHORTER than N with the zeros
 * Excel stripped, and `restoredFrom` says so, for the dry-run to show before
 * anything is written. Nothing else is ever corrected: every other mismatch is
 * refused, in French, saying what to change. The site form passes false,
 * because nothing there shows a correction before it is written: "102" is
 * refused there, with "00102" suggested.
 */
export function judgeSiteCode(
  code: string,
  format: SiteCodeFormat,
  opts: { restoreZeros: boolean },
): SiteCodeVerdict {
  const redo =
    'Formatez la colonne « code » en Texte dans le tableur, ressaisissez les codes, puis exportez à nouveau.';
  if (SCIENTIFIC_RE.test(code)) {
    return {
      ok: false,
      error: `code : « ${code} » est une notation scientifique écrite par le tableur ; les chiffres du code sont perdus. ${redo}`,
    };
  }
  const tail = TRAILING_ZERO_RE.exec(code);
  if (tail) {
    return {
      ok: false,
      error:
        `code : « ${code} » se termine par « ${tail[1]} », ajouté par un tableur qui a lu la colonne comme des ` +
        `nombres (et qui a pu supprimer des zéros en tête). ${redo}`,
    };
  }
  if (format.kind === 'free') return { ok: true, code, restoredFrom: null };

  const n = format.length;
  const shape = `exactement ${n} chiffre${n > 1 ? 's' : ''}`;
  if (!DIGITS_RE.test(code)) {
    return {
      ok: false,
      error: `code : « ${code} » ne respecte pas le format des codes de ce client (${shape}, zéros en tête compris).`,
    };
  }
  if (code.length > n) {
    return {
      ok: false,
      error: `code : « ${code} » compte ${code.length} chiffres ; le format des codes de ce client en impose ${shape}.`,
    };
  }
  if (code.length < n) {
    const padded = code.padStart(n, '0');
    if (opts.restoreZeros) return { ok: true, code: padded, restoredFrom: code };
    return {
      ok: false,
      error:
        `code : « ${code} » compte ${code.length} chiffre${code.length > 1 ? 's' : ''} ; le format des codes de ` +
        `ce client en impose ${shape}. S'il s'agit d'un nouveau site, saisissez « ${padded} ». Si « ${code} » ` +
        `reprend le code d'un compte PPP déjà déployé, ne le complétez pas : un identifiant calculé à partir de ` +
        `« ${padded} » ne serait plus celui de ce compte.`,
    };
  }
  return { ok: true, code, restoredFrom: null };
}

/** The dry-run's sentence for a restored code: "102 -> 00102 (zéros rétablis)". */
export function restoredCodeNote(from: string, to: string): string {
  return `${from} -> ${to} (zéros rétablis)`;
}

/**
 * The tenant's all-digit site codes, grouped by site number. "7", "007" and
 * "00007" are ONE site number (`siteNumber` drops the leading zeros), so an
 * address formula gives them the same tunnel address and LAN, and two sites
 * holding them may be one physical site entered twice, each with its own PPP
 * login. Codes that are not all digits have no site number and are left out.
 */
export function indexBySiteNumber(codes: Iterable<string>): Map<number, string[]> {
  const index = new Map<number, string[]>();
  for (const c of codes) {
    const n = siteNumber(c);
    if (n === null) continue;
    const list = index.get(n);
    if (list) list.push(c);
    else index.set(n, [c]);
  }
  return index;
}

/** The OTHER spellings of `code`'s site number in `index`, sorted. Under
 *  'digits:N' every code judged since the format is exactly N digits, so a
 *  sibling there is always a code that predates the format. */
export function siteNumberSiblings(code: string, index: ReadonlyMap<number, readonly string[]>): string[] {
  const n = siteNumber(code);
  if (n === null) return [];
  return [...new Set((index.get(n) ?? []).filter((c) => c !== code))].sort();
}

const quotedList = (codes: readonly string[]): string => codes.map((c) => `« ${c} »`).join(', ');

/** Refusal: `code` would be a second site for a site number the tenant
 *  already holds under another spelling (`siteNumberSiblings`). Said the same
 *  way for a create and for a rename. */
export function siteNumberClashMessage(code: string, siblings: readonly string[]): string {
  const one = siblings.length === 1;
  return (
    `code : ce client a déjà ${one ? 'un site' : 'des sites'} ${quotedList(siblings)} au même numéro de site ` +
    `(${siteNumber(code)}) que « ${code} » ; « ${code} » ferait un second site pour ce numéro, qu'une formule ` +
    `d'adressage confondrait avec ${one ? 'lui' : 'eux'}. S'il s'agit du même site, travaillez sur le site ` +
    `existant depuis sa page ; sinon, corrigez l'un des codes.`
  );
}

/** Refusal (CSV import): a cell whose zeros were restored to the code of an
 *  existing site, while another existing site holds the same site number
 *  under another spelling. Excel strips the zeros of both, so the cell does
 *  not say which of them it means. */
export function ambiguousRestoredCodeMessage(cell: string, restored: string, siblings: readonly string[]): string {
  return (
    `code : la cellule « ${cell} » peut désigner le site « ${restored} » comme ${quotedList(siblings)} (hors ` +
    `format), au même numéro de site ; elle ne dit pas lequel. Pour « ${restored} », saisissez « ${restored} » ` +
    `avec la colonne au format Texte ; pour l'autre, modifiez-le depuis sa page.`
  );
}

// ============================================================================
// State, holders, refusals
// ============================================================================

/**
 * Who holds an address, a block or a login. `ref` is the id that source is
 * keyed by: a site id ('site'), a device id ('device'), a concentrator id
 * ('session', 'concentrator_secret'). `planned` is a site placed earlier in
 * the same preview batch, named by `name`.
 *
 * There is no 'discovery' source. The quarantine (`discoveries`) is never
 * retired — no scan deletes a row and no route does — so a holder read from
 * it held its address forever, and in formula mode that refused a site for
 * good with no operation able to free it. What it knew is held by sources
 * that DO end: a declared secret by `concentrator_ppp_secrets` (stamped
 * vanished when a later read lacks it), a live session by `ppp_sessions`.
 */
export type HolderSource = 'site' | 'device' | 'session' | 'concentrator_secret' | 'planned';

export interface AddressHolder {
  source: HolderSource;
  tenantId: number | null;
  ref: number | null;
  /** A CHR secret name, the PPP username of a live session or of a device
   *  (null when the device has none), or a planned site's label. Server-side
   *  detail: messages do not repeat it for a holder of another tenant. */
  name: string | null;
  /** 'device' only: the site the device is bound to (`devices.site_id`), null
   *  when it is bound to none. Adoption reads it to recognise the deployed
   *  router of the very site being adopted; absent on every other source. */
  siteId?: number | null;
}

export interface TakenAddress extends AddressHolder {
  address: string;
}

export interface TakenBlock extends AddressHolder {
  /** CIDR text: a LAN subnet, or a held host as /32. */
  block: string;
}

export interface LoginHolder {
  login: string;
  /** 'session': the username of a live PPP session on a CHR. */
  source: HolderSource;
  tenantId: number | null;
  ref: number | null;
  /** A planned site's label; null otherwise. */
  name?: string | null;
  /** 'device' only: the site the device is bound to, null when none. */
  siteId?: number | null;
}

/**
 * A secret the tenant's OWN concentrator (the policy's) declares under a name
 * equal, without regard to case, to a login this batch would hand out — as the
 * last /ppp/secret read stored it in `concentrator_ppp_secrets`. The input of
 * ADOPTION (`planSite`): such a secret is a site already deployed on the CHR,
 * and the allocation records it instead of refusing the login.
 */
export interface DeclaredSecret {
  concentratorId: number;
  /** The CHR's own spelling. */
  name: string;
  /** Host text as declared; null when the secret declares none (the CHR then
   *  takes the address from one of its pools) or declares something that is
   *  not an address (a pool NAME — the inventory stores no such value). */
  remoteAddress: string | null;
  /** As read; null when the CHR printed none. */
  profile: string | null;
  disabled: boolean;
}

/** Everything the engine needs to know about the world, as the DB returns it.
 *  Holders read from a CHR are already restricted to the CHRs this tenant's
 *  allocation believes (seed.ts, "WHOSE CHR COUNTS"). */
export interface AllocationState {
  /** Held addresses inside the TUNNEL pool, by anyone. */
  tunnelTaken: readonly TakenAddress[];
  /** LAN subnets of any site, of any tenant, reaching into the tunnel pool.
   *  No tunnel address is taken from inside one. Normally empty — a LAN pool
   *  never overlaps a tunnel pool (`poolOverlapConflict`) — but a LAN pool
   *  deleted and its block re-created as a tunnel pool leaves its sites'
   *  subnets behind (an allocation outlives its pool), and a row may be
   *  written by hand. */
  tunnelBlocked: readonly TakenBlock[];
  /** Blocks a new LAN subnet must not overlap: every LAN subnet inside the LAN
   *  pool's block that belongs to THIS tenant or was drawn from THIS pool
   *  (the UNIQUENESS paragraph at the top), and every held tunnel host there
   *  as a /32. */
  lanTaken: readonly TakenBlock[];
  /** Logins whose lowercase form equals a candidate's. */
  loginsTaken: readonly LoginHolder[];
  /** System identities already given (compared without case). Optional so a
   *  state built before identities existed still plans. */
  identitiesTaken?: readonly LoginHolder[];
  /** The secrets of the policy's own CHR whose name matches a candidate login
   *  (see DeclaredSecret). Optional: absent, nothing is adopted, and a login
   *  that CHR declares is refused as taken, exactly as before adoption. */
  declaredSecrets?: readonly DeclaredSecret[];
  /** CIDR text of every tunnel pool ANOTHER tenant's stored policy hands
   *  addresses from and this policy does not. Tunnel pools never overlap
   *  (migration 036), so an address inside one belongs to that other tenant's
   *  address plan, and ADOPTION refuses it (ADOPT_FOREIGN_POOL). Optional:
   *  absent, no address is judged foreign. */
  foreignTunnelPools?: readonly string[];
}

export interface SiteFacts {
  /** null for a draft that is not a row yet (bulk-import preview). */
  siteId: number | null;
  code: string;
  name: string;
  /** Stored form: two uppercase letters, or null. */
  country: string | null;
  /** The site's LAN as supplied by its site variable (manual LAN mode only);
   *  null/absent = not supplied. */
  manualLan?: string | null;
}

export interface LoginContext {
  tenantSlug: string;
  /** '' when the installation has none. */
  instanceDomain: string;
}

export interface SitePlan {
  /** The number formulas and {site.id} used; null when the code is not numeric
   *  and nothing needed it. */
  siteNumber: number | null;
  tunnelIp: string;
  lanSubnet: string | null;
  /** How the LAN was obtained; null iff lanSubnet is null. */
  lanSource: 'pool' | 'fixed' | 'manual' | null;
  /** For an adopted plan, the CHR secret's own spelling of the login. */
  pppLogin: string;
  systemIdentity: string | null;
  /** The policy's derived values for this site, already evaluated. */
  derived: Record<string, string>;
  /** 'allocated': login and tunnel address computed from the policy.
   *  'adopted_chr': both read from a secret the policy's CHR already declares
   *  under this site's login — a deployed site, recorded as it is (ADOPTION in
   *  `planSite`). The LAN, the identity and the derived values come from the
   *  policy either way: none of them is on the CHR. */
  source: PlanSource;
  /** The PPP profile the allocation freezes: the policy's when allocated, the
   *  CHR secret's own when adopted (null = none printed, i.e. `default`). */
  pppProfile: string | null;
  /** Adopted only: what the tenant's tunnel formula renders for this site,
   *  when that differs from the address the CHR declares (the CHR's is the
   *  one recorded). Null otherwise — and always null in incremental mode,
   *  where no address is "the formula's". */
  formulaTunnelIp: string | null;
  /** What an operator must read before trusting the plan. Every difference
   *  adoption finds between the CHR and the policy is here, never only in a
   *  log. Empty for an ordinary allocation. */
  warnings: string[];
}

export const PLAN_SOURCES = ['allocated', 'adopted_chr'] as const;
export type PlanSource = (typeof PLAN_SOURCES)[number];

export const PLAN_REFUSAL_REASONS = [
  'SITE_CODE_NOT_NUMERIC',
  'LOGIN_INVALID',
  'INSTANCE_DOMAIN_MISSING',
  'INSTANCE_DOMAIN_INVALID',
  'LOGIN_TAKEN',
  'FORMULA_OUT_OF_RANGE',
  'FORMULA_OUT_OF_POOL',
  'TUNNEL_IP_TAKEN',
  'POOL_EXHAUSTED',
  'LAN_SUBNET_TAKEN',
  'LAN_POOL_EXHAUSTED',
  'IDENTITY_INVALID',
  'IDENTITY_TAKEN',
  'LAN_MANUAL_MISSING',
  'LAN_MANUAL_INVALID',
  'DERIVED_INVALID',
  // Adoption (`planSite`): the policy's CHR declares this site's login, and
  // what it declares cannot be recorded as this site's allocation.
  'ADOPT_NO_ADDRESS',
  'ADOPT_AMBIGUOUS',
  'ADOPT_PROFILE_INVALID',
  'ADOPT_FOREIGN_POOL',
] as const;
/** Every LoginRefusalReason is one of these: `planSite` returns a login
 *  refusal's reason as a plan refusal, and the compiler checks the assignment. */
export type PlanRefusalReason = (typeof PLAN_REFUSAL_REASONS)[number];

export interface AllocationRefusal {
  reason: PlanRefusalReason;
  /** Names the site, says what is wrong and what to change, then "retry". */
  message: string;
  holder?: AddressHolder | LoginHolder;
}

export type SitePlanResult = { ok: true; plan: SitePlan } | { ok: false; refusal: AllocationRefusal };

/** How a site is named in every refusal: its code, then its name. */
export function siteLabel(site: Pick<SiteFacts, 'code' | 'name'>): string {
  return `"${site.code}" (${site.name})`;
}

/**
 * A holder in words, for a message. A holder of ANOTHER tenant is described by
 * kind only — no id, no secret name — because a refusal may be relayed to a
 * tenant user by a server-side caller (the bench). The structured `holder` on
 * the refusal keeps the detail for code that is entitled to it.
 */
export function describeHolder(h: AddressHolder | LoginHolder, viewerTenantId: number): string {
  const mine = h.tenantId === viewerTenantId;
  switch (h.source) {
    case 'site':
      return mine ? `the allocation of site ${h.ref}` : "another tenant's site allocation";
    case 'device':
      return mine ? `device ${h.ref}` : "another tenant's device";
    case 'session':
      return `a live PPP session on concentrator ${h.ref}`;
    case 'concentrator_secret':
      return `a secret already declared on concentrator ${h.ref} (read from its /ppp/secret)`;
    case 'planned':
      return `${h.name ? `site ${h.name}` : 'a site'} earlier in this same batch`;
  }
}

/** When a change made on a CHR reaches the allocator — the tail of every remedy
 *  that asks for one. */
function rereadClause(): string {
  return (
    "the allocation sees the change at its next re-read of the CHR's /ppp/secret (automatic once " +
    `the last read is more than ${Math.round(SEED_MAX_AGE_MS / 60_000)} minutes old, immediate with ` +
    'a discovery scan of that CHR, POST /api/discoveries/scan)'
  );
}

/**
 * What frees a value `h` holds, as a clause ("release …"): an operation that
 * exists, because a refusal that names a remedy nobody can perform is a dead
 * end. Same discretion as `describeHolder` for a holder
 * of another tenant.
 */
export function holderRemedy(h: AddressHolder | LoginHolder, viewerTenantId: number): string {
  const mine = h.tenantId === viewerTenantId;
  switch (h.source) {
    case 'site':
      return mine
        ? `release the allocation of site ${h.ref} (a platform administrator: DELETE ` +
            `/api/allocation/sites/${h.ref}) if it was never written on a CHR`
        : 'have a platform administrator release that allocation if it was never written on a CHR';
    case 'device':
      return mine
        ? `correct device ${h.ref} if its tunnel address or PPP username is stale`
        : 'have a platform administrator correct that device if it is stale';
    case 'session':
      return 'wait for that session to end — the value is in use right now';
    case 'concentrator_secret':
      return `remove or change that secret on concentrator ${h.ref} if it is stale; ${rereadClause()}`;
    case 'planned':
      return 'change that earlier site of the batch, or take it out';
  }
}

interface Range {
  start: number;
  end: number;
  holder: AddressHolder;
}

/** Mutable working copy of the state, so a multi-site plan never hands the
 *  same address, block or login twice. */
export interface WorkingState {
  /** One holder per address — the most informative — for the refusals. */
  taken: Map<number, AddressHolder>;
  tunnelBlocked: Range[];
  lanTaken: Range[];
  /** One holder per lowercase login — the most informative. */
  logins: Map<string, LoginHolder>;
  identities: Map<string, LoginHolder>;
  /** EVERY holder of each address and of each lowercase login. Adoption must
   *  tell the adopted account itself (its secret, its live session, its own
   *  router) from anybody else, and `taken` / `logins` keep only one. */
  addressHolders: Map<number, AddressHolder[]>;
  loginHolders: Map<string, LoginHolder[]>;
  /** The secrets of the policy's CHR under a candidate login, by lowercase
   *  name (several when the CHR has names differing only by case). */
  declared: Map<string, DeclaredSecret[]>;
  /** `AllocationState.foreignTunnelPools`, parsed. */
  foreignPools: Cidr[];
}

function holderOf(h: AddressHolder): AddressHolder {
  const out: AddressHolder = { source: h.source, tenantId: h.tenantId, ref: h.ref, name: h.name };
  if (h.siteId !== undefined) out.siteId = h.siteId;
  return out;
}

function pushTo<K, V>(map: Map<K, V[]>, key: K, value: V): void {
  const list = map.get(key);
  if (list) list.push(value);
  else map.set(key, [value]);
}

function toRanges(blocks: readonly TakenBlock[]): Range[] {
  const out: Range[] = [];
  for (const b of blocks) {
    const parsed = parseCidr(b.block);
    if (parsed.ok) out.push({ start: parsed.cidr.network, end: cidrLast(parsed.cidr), holder: holderOf(b) });
  }
  return out;
}

export function toWorkingState(state: AllocationState): WorkingState {
  const taken = new Map<number, AddressHolder>();
  const addressHolders = new Map<number, AddressHolder[]>();
  for (const t of state.tunnelTaken) {
    const address = parseIpv4(t.address.split('/')[0]);
    if (address === null) continue;
    pushTo(addressHolders, address, holderOf(t));
    // A site allocation is the most informative holder; keep it when several
    // sources hold the same address.
    const prior = taken.get(address);
    if (!prior || (t.source === 'site' && prior.source !== 'site')) taken.set(address, holderOf(t));
  }
  const logins = new Map<string, LoginHolder>();
  const loginHolders = new Map<string, LoginHolder[]>();
  for (const l of state.loginsTaken) {
    const key = l.login.toLowerCase();
    pushTo(loginHolders, key, l);
    const prior = logins.get(key);
    if (!prior || (l.source === 'site' && prior.source !== 'site')) logins.set(key, l);
  }
  const identities = new Map<string, LoginHolder>();
  for (const l of state.identitiesTaken ?? []) identities.set(l.login.toLowerCase(), l);
  const declared = new Map<string, DeclaredSecret[]>();
  for (const d of state.declaredSecrets ?? []) pushTo(declared, d.name.toLowerCase(), d);
  const foreignPools: Cidr[] = [];
  for (const text of state.foreignTunnelPools ?? []) {
    const parsed = parseCidr(text);
    if (parsed.ok) foreignPools.push(parsed.cidr);
  }
  return {
    taken,
    tunnelBlocked: toRanges(state.tunnelBlocked),
    lanTaken: toRanges(state.lanTaken),
    logins,
    identities,
    addressHolders,
    loginHolders,
    declared,
    foreignPools,
  };
}

function rangeAt(ranges: readonly Range[], address: number): Range | undefined {
  return ranges.find((r) => address >= r.start && address <= r.end);
}

function poolLabel(pool: AddressPool): string {
  return `pool "${pool.name}" (${formatCidr(pool.cidr)})`;
}

const RETRY = 'then retry the allocation.';

function pickTunnel(
  policy: AllocationPolicy,
  work: WorkingState,
  label: string,
  number: number | null,
  login: string,
): number | AllocationRefusal {
  const rule = policy.tunnel;
  if (rule.mode === 'incremental') {
    const end = cidrLast(rule.pool.cidr);
    let a = rule.start;
    while (a <= end) {
      const blocked = rangeAt(work.tunnelBlocked, a);
      if (blocked) {
        a = blocked.end + 1;
        continue;
      }
      const last = a % 256;
      if (last !== 0 && last !== 255 && !work.taken.has(a)) return a;
      a += 1;
    }
    return {
      reason: 'POOL_EXHAUSTED',
      message:
        `site ${label}: tunnel ${poolLabel(rule.pool)} has no free address left from ` +
        `${formatIpv4(rule.start)} (the .0 and .255 of every /24 are never handed out). A pool's ` +
        `block never changes: create another tunnel pool and point the tenant's policy at it, ${RETRY}`,
    };
  }

  // formula — `number` is non-null here: planSite refused a non-numeric code.
  const n = number ?? 0;
  const r = renderAddressFormula(rule.formula, n);
  if (!r.ok) {
    return {
      reason: 'FORMULA_OUT_OF_RANGE',
      message: `site ${label}: tunnel formula "${rule.formula.source}": ${r.error} Correct the formula or the site code, ${RETRY}`,
    };
  }
  if (!cidrContains(rule.pool.cidr, r.address)) {
    return {
      reason: 'FORMULA_OUT_OF_POOL',
      message:
        `site ${label}: tunnel formula "${rule.formula.source}" renders ${r.text} for site number ` +
        `${n}, outside tunnel ${poolLabel(rule.pool)}. Correct the formula in the tenant's policy, ` +
        `point it at another pool, or change the site code, ${RETRY}`,
    };
  }
  const blocked = rangeAt(work.tunnelBlocked, r.address);
  const holder = blocked ? blocked.holder : work.taken.get(r.address);
  if (holder) {
    return {
      reason: 'TUNNEL_IP_TAKEN',
      message:
        `site ${label}: tunnel formula "${rule.formula.source}" renders ${r.text} for site number ` +
        `${n}, and that address is already held by ${describeHolder(holder, policy.tenantId)}` +
        `${blocked ? ' (inside its LAN subnet)' : ''}. A formula gives a site exactly one address ` +
        'and never skips to another. A deployed site is adopted only through a secret of ' +
        `concentrator ${policy.concentratorId} (this tenant's) named with its PPP login, "${login}" ` +
        'without regard to case; a holder under any other name is not recognised as this site. ' +
        `To free it: ${holderRemedy(holder, policy.tenantId)}; or correct the formula, ${RETRY}`,
      holder,
    };
  }
  return r.address;
}

/**
 * A fixed or manual LAN is not drawn from a LAN pool, so nothing upstream
 * keeps it out of the tunnel address space: refuse it when it contains the
 * tunnel address this very site was just given, or any address held in the
 * tenant's tunnel pool (`work.taken`).
 */
function tunnelInsideLan(
  policy: AllocationPolicy,
  c: Cidr,
  work: WorkingState,
  tunnel: number,
  label: string,
  what: string,
): AllocationRefusal | null {
  const end = cidrLast(c);
  if (tunnel >= c.network && tunnel <= end) {
    return {
      reason: 'LAN_SUBNET_TAKEN',
      message:
        `site ${label}: ${what} contains the tunnel address ${formatIpv4(tunnel)} this site would get. ` +
        `A router's tunnel address must stay outside its LAN: change the LAN or the tunnel rule, ${RETRY}`,
    };
  }
  for (const [address, holder] of work.taken) {
    if (address < c.network || address > end) continue;
    return {
      reason: 'LAN_SUBNET_TAKEN',
      message:
        `site ${label}: ${what} contains the tunnel address ${formatIpv4(address)}, held by ` +
        `${describeHolder(holder, policy.tenantId)}. Change the LAN or the tunnel rule, ${RETRY}`,
      holder,
    };
  }
  return null;
}

function pickLan(
  policy: AllocationPolicy,
  rule: LanRule,
  work: WorkingState,
  label: string,
  number: number | null,
  manualLan: string | null,
  tunnel: number,
): Cidr | AllocationRefusal {
  if (rule.mode === 'fixed') {
    const c = { ...rule.subnet };
    return tunnelInsideLan(policy, c, work, tunnel, label, `the tenant's fixed LAN ${formatCidr(c)}`) ?? c;
  }
  if (rule.mode === 'manual') {
    if (manualLan === null || manualLan.trim() === '') {
      return {
        reason: 'LAN_MANUAL_MISSING',
        message:
          `site ${label}: this tenant's LAN is supplied per site, and the site variable ` +
          `"${rule.variable}" is not set. Set it on the site (or in the import file), ${RETRY}`,
      };
    }
    const text = manualLan.trim();
    const parsed = parseCidr(text);
    if (!parsed.ok || parsed.cidr.prefix < POOL_PREFIX_MIN || parsed.cidr.prefix > POOL_PREFIX_MAX) {
      return {
        reason: 'LAN_MANUAL_INVALID',
        message:
          `site ${label}: the site variable "${rule.variable}" holds "${text}", which is not a usable ` +
          `LAN (${parsed.ok ? `a /${POOL_PREFIX_MIN} to /${POOL_PREFIX_MAX} is required` : parsed.error}). ` +
          `Correct it, ${RETRY}`,
      };
    }
    const c = parsed.cidr;
    const end = cidrLast(c);
    const clash = work.lanTaken.find((x) => rangesOverlap(c.network, end, x.start, x.end));
    if (clash) {
      return {
        reason: 'LAN_SUBNET_TAKEN',
        message:
          `site ${label}: its LAN ${formatCidr(c)} (site variable "${rule.variable}") overlaps a subnet ` +
          `held by ${describeHolder(clash.holder, policy.tenantId)}. Either ` +
          `${holderRemedy(clash.holder, policy.tenantId)}, or correct the site variable, ${RETRY}`,
        holder: clash.holder,
      };
    }
    return (
      tunnelInsideLan(policy, c, work, tunnel, label, `its LAN ${formatCidr(c)} (site variable "${rule.variable}")`) ??
      c
    );
  }
  if (rule.mode === 'incremental') {
    const size = 2 ** (32 - rule.prefix);
    const poolEnd = cidrLast(rule.pool.cidr);
    let candidate = rule.pool.cidr.network;
    while (candidate + size - 1 <= poolEnd) {
      const end = candidate + size - 1;
      const clash = work.lanTaken.find((r) => rangesOverlap(candidate, end, r.start, r.end));
      if (!clash) return { network: candidate, prefix: rule.prefix, size };
      // Jump past the clash to the next block boundary, so a /16 already in
      // use costs one step instead of 256.
      const next = clash.end + 1;
      candidate = next + ((size - ((next - rule.pool.cidr.network) % size)) % size);
    }
    return {
      reason: 'LAN_POOL_EXHAUSTED',
      message:
        `site ${label}: LAN ${poolLabel(rule.pool)} has no free /${rule.prefix} left. A pool's ` +
        `block never changes: create another LAN pool and point the tenant's policy at it, ${RETRY}`,
    };
  }

  const n = number ?? 0;
  const r = renderAddressFormula(rule.formula, n);
  if (!r.ok) {
    return {
      reason: 'FORMULA_OUT_OF_RANGE',
      message: `site ${label}: LAN formula "${rule.formula.source}": ${r.error} Correct the formula or the site code, ${RETRY}`,
    };
  }
  const prefix = r.prefix ?? 32;
  const size = 2 ** (32 - prefix);
  if (r.address % size !== 0) {
    return {
      reason: 'FORMULA_OUT_OF_RANGE',
      message:
        `site ${label}: LAN formula "${rule.formula.source}" renders ${r.text} for site number ${n}, ` +
        `which has host bits set — not a /${prefix} network address. Correct the formula, ${RETRY}`,
    };
  }
  if (!blockFits(rule.pool.cidr, r.address, prefix)) {
    return {
      reason: 'FORMULA_OUT_OF_POOL',
      message:
        `site ${label}: LAN formula "${rule.formula.source}" renders ${r.text} for site number ` +
        `${n}, outside LAN ${poolLabel(rule.pool)}. Correct the formula in the tenant's policy, point ` +
        `it at another pool, or change the site code, ${RETRY}`,
    };
  }
  const end = r.address + size - 1;
  const clash = work.lanTaken.find((x) => rangesOverlap(r.address, end, x.start, x.end));
  if (clash) {
    return {
      reason: 'LAN_SUBNET_TAKEN',
      message:
        `site ${label}: LAN formula "${rule.formula.source}" renders ${r.text} for site number ` +
        `${n}, which overlaps an address or subnet held by ${describeHolder(clash.holder, policy.tenantId)}. ` +
        `Either ${holderRemedy(clash.holder, policy.tenantId)}, or correct the formula, ${RETRY}`,
      holder: clash.holder,
    };
  }
  return { network: r.address, prefix, size };
}

/** Which holder a refusal names first when several hold one value. */
const HOLDER_RANK: Readonly<Record<HolderSource, number>> = {
  site: 0,
  planned: 1,
  device: 2,
  session: 3,
  concentrator_secret: 4,
};

function firstOther<T extends { source: HolderSource }>(holders: readonly T[], isSelf: (h: T) => boolean): T | undefined {
  return holders.filter((h) => !isSelf(h)).sort((a, b) => HOLDER_RANK[a.source] - HOLDER_RANK[b.source])[0];
}

interface Adoption {
  secret: DeclaredSecret;
  address: number;
  formulaTunnelIp: string | null;
  warnings: string[];
}

/**
 * ADOPTION — "reproduire l'existant". A site whose login the policy's OWN CHR
 * already declares as a secret is a site already deployed: its L2TP account
 * is live there, and a CPE somewhere authenticates with it. The CHR is the
 * source of truth for such a site, so its allocation RECORDS what the CHR
 * declares instead of refusing the login (LOGIN_TAKEN) or computing another
 * address: the login in the CHR's own spelling, the secret's remote-address as
 * the tunnel address (even when the formula says otherwise — a warning, never
 * silence), the secret's profile. Nothing is written to the CHR, and nothing
 * is read from it here but the stored inventory (never its password).
 *
 * Returns null when the policy's CHR declares no secret under this login: the
 * site is then allocated the ordinary way. Only the policy's CHR is adopted
 * from — a secret of any other CHR stays a holder like any other.
 *
 * REFUSED, nothing written, when what the CHR declares cannot be this site's:
 *   - ADOPT_AMBIGUOUS        several secrets of that CHR differ only by case;
 *   - LOGIN_TAKEN            the login is also held by anybody but the adopted
 *                            account itself — another site (of this tenant or
 *                            another), a site earlier in the batch, another
 *                            CHR's secret or session, another tenant's device;
 *   - ADOPT_NO_ADDRESS       the secret declares no IPv4 remote-address (the
 *                            CHR hands that account a pool address: there is
 *                            no deployed address to record);
 *   - TUNNEL_IP_TAKEN        its remote-address is held by anybody but the
 *                            adopted account (another site, another secret,
 *                            another session, a device that is not this
 *                            site's), or lies inside a site's LAN subnet;
 *   - ADOPT_FOREIGN_POOL     its remote-address lies inside a tunnel pool
 *                            another tenant's policy hands addresses from and
 *                            this tenant's does not. A CHR may serve several
 *                            tenants, and nothing in a secret says whose site
 *                            it is: an address in another tenant's plan is
 *                            evidence the account is that tenant's, so it is
 *                            never adopted on a guess;
 *   - ADOPT_PROFILE_INVALID  its profile cannot be stored (alphabet of 036).
 *
 * "The adopted account itself", tolerated as a holder: the secret (on the
 * policy's CHR, under this login), its live session there (same username),
 * and its router as inventoried — a device of THIS tenant carrying this login
 * as its PPP username (bound to no site or to this one), or, when the device
 * records no username, bound to this very site.
 *
 * What is NOT evidence either way, and stays a residual: on a CHR several
 * tenants share, under a login template without {tenant.slug}, an address in
 * no other tenant's tunnel pool — outside every pool (a deployment older than
 * any policy), or inside an incremental pool this tenant shares with others.
 * Such a secret is adopted by the first of those tenants whose site renders
 * its login (outside every pool, with the "outside the tenant's tunnel pool"
 * warning).
 */
function adoptDeclared(
  policy: AllocationPolicy,
  work: WorkingState,
  site: SiteFacts,
  label: string,
  login: string,
): Adoption | AllocationRefusal | null {
  const key = login.toLowerCase();
  const matches = (work.declared.get(key) ?? []).filter((d) => d.concentratorId === policy.concentratorId);
  if (matches.length === 0) return null;
  const chr = `concentrator ${policy.concentratorId} (this tenant's)`;
  if (matches.length > 1) {
    return {
      reason: 'ADOPT_AMBIGUOUS',
      message:
        `site ${label}: ${chr} declares ${matches.length} secrets whose names equal this site's PPP ` +
        `login "${login}" without regard to case (${matches.map((m) => `"${m.name}"`).join(', ')}), so ` +
        "which one is this site's deployed account cannot be told. Remove the stale one on the CHR; " +
        `${rereadClause()}; ${RETRY}`,
    };
  }
  const secret = matches[0];
  const sameName = (name: string | null | undefined): boolean => typeof name === 'string' && name.toLowerCase() === key;
  const ownRouter = (h: { tenantId: number | null; siteId?: number | null }, username: string | null | undefined): boolean => {
    if (h.tenantId !== policy.tenantId) return false;
    const bound = h.siteId ?? null;
    if (username !== null && username !== undefined) return sameName(username) && (bound === null || bound === site.siteId);
    return site.siteId !== null && bound === site.siteId;
  };

  const loginHolder = firstOther(work.loginHolders.get(key) ?? [], (h) => {
    if (h.source === 'concentrator_secret' || h.source === 'session') return h.ref === policy.concentratorId;
    if (h.source === 'device') return ownRouter(h, h.login);
    return false;
  });
  if (loginHolder) {
    return {
      reason: 'LOGIN_TAKEN',
      message:
        `site ${label}: ${chr} declares a secret "${secret.name}" under this site's PPP login, which ` +
        'would be adopted as this deployed site, but that login is also used by ' +
        `${describeHolder(loginHolder, policy.tenantId)} (logins are compared without regard to case), ` +
        'and adoption never gives one login to two holders. Rename the site or change the tenant\'s ' +
        `login template; or ${holderRemedy(loginHolder, policy.tenantId)}; ${RETRY}`,
      holder: loginHolder,
    };
  }

  const declaredText = secret.remoteAddress === null ? null : secret.remoteAddress.split('/')[0];
  if (declaredText === null) {
    return {
      reason: 'ADOPT_NO_ADDRESS',
      message:
        `site ${label}: ${chr} declares a secret "${secret.name}" under this site's PPP login with no ` +
        'fixed remote-address: the CHR gives that account an address from one of its pools, so there ' +
        'is no deployed tunnel address to adopt, and the login cannot be handed out again beside it. ' +
        'Give the secret a fixed remote-address on the CHR, or remove it there if it is stale; ' +
        `${rereadClause()}; ${RETRY}`,
    };
  }
  const address = parseIpv4(declaredText);
  if (address === null) {
    return {
      reason: 'ADOPT_NO_ADDRESS',
      message:
        `site ${label}: ${chr} declares a secret "${secret.name}" under this site's PPP login with the ` +
        `remote-address ${declaredText}, which is not an IPv4 host address; a tunnel address is IPv4. ` +
        `Correct the secret on the CHR; ${rereadClause()}; ${RETRY}`,
    };
  }
  const text = formatIpv4(address);

  const blocked = rangeAt(work.tunnelBlocked, address);
  if (blocked) {
    return {
      reason: 'TUNNEL_IP_TAKEN',
      message:
        `site ${label}: ${chr} declares this site's PPP login "${secret.name}" with remote-address ` +
        `${text}, and that address lies inside the LAN subnet held by ` +
        `${describeHolder(blocked.holder, policy.tenantId)}. Adoption records what the CHR declares, ` +
        `never an address another holder has: ${holderRemedy(blocked.holder, policy.tenantId)}, or ` +
        `correct the secret's remote-address on the CHR, ${RETRY}`,
      holder: blocked.holder,
    };
  }
  const addressHolder = firstOther(work.addressHolders.get(address) ?? [], (h) => {
    if (h.source === 'concentrator_secret' || h.source === 'session') {
      return h.ref === policy.concentratorId && sameName(h.name);
    }
    if (h.source === 'device') return ownRouter(h, h.name);
    return false;
  });
  if (addressHolder) {
    return {
      reason: 'TUNNEL_IP_TAKEN',
      message:
        `site ${label}: ${chr} declares this site's PPP login "${secret.name}" with remote-address ` +
        `${text}, and that address is already held by ${describeHolder(addressHolder, policy.tenantId)}. ` +
        'Adoption records what the CHR declares, never an address another holder has: ' +
        `${holderRemedy(addressHolder, policy.tenantId)}, or correct the secret's remote-address on ` +
        `the CHR, ${RETRY}`,
      holder: addressHolder,
    };
  }

  if (work.foreignPools.some((p) => cidrContains(p, address))) {
    return {
      reason: 'ADOPT_FOREIGN_POOL',
      message:
        `site ${label}: ${chr} declares a secret "${secret.name}" under this site's PPP login with ` +
        `remote-address ${text}, which lies inside a tunnel pool that another tenant's allocation ` +
        "policy hands addresses from, and this tenant's does not. Nothing in a CHR secret says whose " +
        "site it is, so an account whose address belongs to another tenant's plan is never adopted " +
        "as this one's. If it is the other tenant's account, rename this site or change this tenant's " +
        "login template; if it really is this site's, correct the secret's remote-address on the CHR " +
        `into this tenant's plan (${rereadClause()}), or have a platform administrator correct the ` +
        `tenants' pools; ${RETRY}`,
    };
  }

  if (secret.profile !== null && !PPP_PROFILE_RE.test(secret.profile)) {
    return {
      reason: 'ADOPT_PROFILE_INVALID',
      message:
        `site ${label}: ${chr} declares this site's PPP login "${secret.name}" with the PPP profile ` +
        `"${secret.profile}", which an allocation cannot record: a profile is spliced bare into a ` +
        'RouterOS command line ([A-Za-z0-9._-], at most 64 characters). Rename that profile on the CHR; ' +
        `${rereadClause()}; ${RETRY}`,
    };
  }

  const warnings: string[] = [];
  let formulaTunnelIp: string | null = null;
  const rule = policy.tunnel;
  if (rule.mode === 'formula') {
    const n = siteNumber(site.code);
    if (n === null) {
      warnings.push(
        `the tunnel formula "${rule.formula.source}" cannot be evaluated for code "${site.code}" (not ` +
          `all digits), so the address ${text} the CHR declares was not compared with it; it is ` +
          'recorded as deployed.',
      );
    } else {
      const r = renderAddressFormula(rule.formula, n);
      if (!r.ok) {
        warnings.push(
          `the tunnel formula "${rule.formula.source}" gives no address for site number ${n} ` +
            `(${r.error}); the address ${text} the CHR declares is recorded as deployed.`,
        );
      } else if (r.address !== address) {
        formulaTunnelIp = formatIpv4(r.address);
        warnings.push(
          `the tunnel formula "${rule.formula.source}" gives ${formulaTunnelIp} for site number ${n}, ` +
            `but the CHR declares ${text}: the deployed address ${text} is recorded, the formula's is ` +
            'not used.',
        );
      }
    }
  }
  if (!cidrContains(rule.pool.cidr, address)) {
    warnings.push(
      `${text} is outside the tenant's tunnel ${poolLabel(rule.pool)}; it is recorded as deployed ` +
        "(the pool's own allocations never reach it).",
    );
  }
  const chrProfile = secret.profile ?? 'default';
  const policyProfile = policy.pppProfile ?? 'default';
  if (chrProfile !== policyProfile) {
    warnings.push(
      `the secret uses the PPP profile "${chrProfile}" and the tenant's policy names ` +
        `"${policyProfile}": the CHR's is recorded for this site.`,
    );
  }
  if (secret.disabled) {
    warnings.push(
      `the secret is DISABLED on concentrator ${policy.concentratorId}. ObliWAN never enables a ` +
        'secret: the concentrator job reports it as a conflict until it is enabled on the CHR.',
    );
  }
  warnings.push(adoptedPasswordWarning(policy.passwordMode));
  return { secret, address, formulaTunnelIp, warnings };
}

/**
 * What an ADOPTED allocation says about its PPP password, in `mode`. Said at
 * adoption AND on every later read of the stored row (allocator.ts
 * `storedWarnings`): the shared-password case is an ASSUMPTION nothing can
 * check — the CHR's password is never read, and the concentrator job
 * finds the account present without comparing one — so it must not be stated
 * once and then forgotten.
 */
export function adoptedPasswordWarning(mode: PppPasswordMode): string {
  return mode === 'per_site'
    ? "this tenant gives each site its own PPP password, and the CHR's is never read: ObliWAN " +
        'holds NO password for this site and will not invent one, so no CPE configuration can be ' +
        'compiled for it (refused as PASSWORD_UNKNOWN).'
    : "this account was adopted from the CHR, whose password is never read: a CPE compiled " +
        "for this site is given the fleet's shared PPP password, which must be the one this secret " +
        'holds. Nothing checks it — the concentrator job finds the account present without comparing ' +
        'passwords — so a different one shows only as a CPE that cannot authenticate.';
}

/**
 * Plan ONE site against the working state, without recording it. Order: the
 * login (its refusals are about the site's own data), ADOPTION when the
 * policy's CHR already declares that login (`adoptDeclared`), the site number
 * when a formula needs it, the tunnel address, the LAN subnet. A LAN drawn from
 * a LAN pool is not checked against the tunnel address just picked: the two
 * come from different pools, and a LAN pool never overlaps a tunnel pool
 * (`poolOverlapConflict`, applied by createPool under the allocation lock). An
 * ADOPTED address may lie outside the tunnel pool, but the CHR secret holds it,
 * so where it falls inside the LAN pool it is already in `lanTaken` as a /32
 * when the allocator loads the state. A fixed or manual LAN has no pool, so
 * `tunnelInsideLan` checks it.
 */
export function planSite(
  policy: AllocationPolicy,
  work: WorkingState,
  site: SiteFacts,
  ctx: LoginContext,
): SitePlanResult {
  const label = siteLabel(site);

  const login = renderPppLogin(
    policy.login,
    {
      siteName: site.name,
      siteCode: site.code,
      siteCountry: site.country,
      tenantSlug: ctx.tenantSlug,
      instanceDomain: ctx.instanceDomain,
    },
    label,
  );
  if (!login.ok) return { ok: false, refusal: { reason: login.reason, message: login.message } };

  let systemIdentity: string | null = null;
  if (policy.identity) {
    const identity = renderSystemIdentity(
      policy.identity,
      {
        siteName: site.name,
        siteCode: site.code,
        siteCountry: site.country,
        tenantSlug: ctx.tenantSlug,
        instanceDomain: ctx.instanceDomain,
      },
      label,
    );
    if (!identity.ok) return { ok: false, refusal: { reason: identity.reason, message: identity.message } };
    const holder = work.identities.get(identity.identity.toLowerCase());
    if (holder) {
      return {
        ok: false,
        refusal: {
          reason: 'IDENTITY_TAKEN',
          message:
            `site ${label}: the system identity "${identity.identity}" is already given to ` +
            `${describeHolder(holder, policy.tenantId)} (compared without regard to case). Change the ` +
            `tenant's identity template or the site's code; or ${holderRemedy(holder, policy.tenantId)}; ${RETRY}`,
          holder,
        },
      };
    }
    systemIdentity = identity.identity;
  }

  const adoption = adoptDeclared(policy, work, site, label, login.login);
  if (adoption !== null && 'reason' in adoption) return { ok: false, refusal: adoption };

  const loginHolder = adoption === null ? work.logins.get(login.login.toLowerCase()) : undefined;
  if (loginHolder) {
    // A secret of ANOTHER CHR: adoption reads only the policy's own.
    const elsewhere =
      loginHolder.source === 'concentrator_secret' && loginHolder.ref !== policy.concentratorId
        ? ` A deployed site is adopted only from concentrator ${policy.concentratorId}, the one this ` +
          "tenant's policy names."
        : '';
    return {
      ok: false,
      refusal: {
        reason: 'LOGIN_TAKEN',
        message:
          `site ${label}: the PPP login "${login.login}" is already used by ` +
          `${describeHolder(loginHolder, policy.tenantId)} (logins are compared without regard to ` +
          `case).${elsewhere} Rename the site or change the tenant's login template; or ` +
          `${holderRemedy(loginHolder, policy.tenantId)}; ${RETRY}`,
        holder: loginHolder,
      },
    };
  }

  const number = siteNumber(site.code);
  const formulaSides: string[] = [];
  // An adopted tunnel address is the CHR's, not the formula's.
  if (policy.tunnel.mode === 'formula' && adoption === null) formulaSides.push('tunnel address');
  if (policy.lan?.mode === 'formula') formulaSides.push('LAN subnet');
  if (formulaSides.length > 0 && number === null) {
    return {
      ok: false,
      refusal: {
        reason: 'SITE_CODE_NOT_NUMERIC',
        message:
          `site ${label}: this tenant's ${formulaSides.join(' and ')} ${formulaSides.length > 1 ? 'are' : 'is'} ` +
          `computed from the site number, and code "${site.code}" is not all digits (leading zeros ` +
          `are allowed: "0001" is site 1). Give the site a numeric code, ${RETRY}`,
      },
    };
  }

  let tunnel: number;
  if (adoption !== null) {
    tunnel = adoption.address;
  } else {
    const picked = pickTunnel(policy, work, label, number, login.login);
    if (typeof picked !== 'number') return { ok: false, refusal: picked };
    tunnel = picked;
  }

  let lan: Cidr | null = null;
  if (policy.lan) {
    const block = pickLan(policy, policy.lan, work, label, number, site.manualLan ?? null, tunnel);
    if ('reason' in block) return { ok: false, refusal: block };
    lan = block;
  }
  const lanSubnet = lan ? formatCidr(lan) : null;

  const derived = evaluateDerived(policy.derived, {
    lanSubnet,
    siteLabel: label,
    login: {
      siteName: site.name,
      siteCode: site.code,
      siteCountry: site.country,
      tenantSlug: ctx.tenantSlug,
      instanceDomain: ctx.instanceDomain,
    },
  });
  if (!derived.ok) return { ok: false, refusal: { reason: 'DERIVED_INVALID', message: derived.message } };

  return {
    ok: true,
    plan: {
      siteNumber: number,
      tunnelIp: formatIpv4(tunnel),
      lanSubnet,
      lanSource: !policy.lan || !lan ? null : lanSourceOf(policy.lan),
      pppLogin: adoption !== null ? adoption.secret.name : login.login,
      systemIdentity,
      derived: derived.values,
      source: adoption !== null ? 'adopted_chr' : 'allocated',
      pppProfile: adoption !== null ? adoption.secret.profile : policy.pppProfile,
      formulaTunnelIp: adoption !== null ? adoption.formulaTunnelIp : null,
      warnings: adoption !== null ? adoption.warnings : [],
    },
  };
}

export function lanSourceOf(rule: LanRule): 'pool' | 'fixed' | 'manual' {
  return rule.mode === 'fixed' || rule.mode === 'manual' ? rule.mode : 'pool';
}

/** Record a plan in the working state the way the state loader would read it
 *  back after the insert, so the next site of a batch cannot be given any of
 *  it. */
export function recordPlan(
  work: WorkingState,
  policy: AllocationPolicy,
  site: SiteFacts,
  plan: SitePlan,
): void {
  const holder: AddressHolder = {
    source: 'planned',
    tenantId: policy.tenantId,
    ref: site.siteId,
    name: siteLabel(site),
  };
  const tunnel = parseIpv4(plan.tunnelIp);
  if (tunnel !== null) {
    work.taken.set(tunnel, holder);
    pushTo(work.addressHolders, tunnel, holder);
    work.lanTaken.push({ start: tunnel, end: tunnel, holder });
  }
  if (plan.lanSubnet) {
    const parsed = parseCidr(plan.lanSubnet);
    if (parsed.ok) {
      const range = { start: parsed.cidr.network, end: cidrLast(parsed.cidr), holder };
      // A fixed LAN is everybody's in this tenant; it never makes the next
      // site's LAN "taken" (pickLan does not look), but it does keep a tunnel
      // pool that overlaps it from handing those addresses out.
      if (plan.lanSource !== 'fixed') work.lanTaken.push(range);
      work.tunnelBlocked.push(range);
    }
  }
  if (plan.systemIdentity) {
    work.identities.set(plan.systemIdentity.toLowerCase(), {
      login: plan.systemIdentity,
      source: 'planned',
      tenantId: policy.tenantId,
      ref: site.siteId,
      name: siteLabel(site),
    });
  }
  const planned: LoginHolder = {
    login: plan.pppLogin,
    source: 'planned',
    tenantId: policy.tenantId,
    ref: site.siteId,
    name: siteLabel(site),
  };
  work.logins.set(plan.pppLogin.toLowerCase(), planned);
  pushTo(work.loginHolders, plan.pppLogin.toLowerCase(), planned);
}

/**
 * Plan a batch, in order. Each site is judged on its own — a refusal does not
 * stop the batch — and every site that succeeds is recorded before the next
 * one is planned, so the result is what allocating them one after another, in
 * this order, would give on the same state.
 */
export function planSites(
  policy: AllocationPolicy,
  state: AllocationState,
  sites: readonly SiteFacts[],
  ctx: LoginContext,
): SitePlanResult[] {
  const work = toWorkingState(state);
  return sites.map((site) => {
    const result = planSite(policy, work, site, ctx);
    if (result.ok) recordPlan(work, policy, site, result.plan);
    return result;
  });
}

// ============================================================================
// Between tenants — checked when a policy is SAVED
// ============================================================================

/** One side of another tenant's stored policy, as far as pools go. Read from
 *  the raw row, valid or not: a stored policy that no longer validates still
 *  names its pools. */
export interface PolicyPoolRef {
  tenantId: number;
  side: 'tunnel' | 'lan';
  poolId: number;
  mode: AddressMode;
}

/** An address another tenant's site holds inside a tunnel pool's block, or a
 *  subnet another tenant's site drew FROM a LAN pool (`lan_pool_id`; a subnet
 *  drawn from that tenant's own overlapping LAN pool is a deliberate reuse and
 *  is not listed). */
export interface ForeignAllocation {
  tenantId: number;
  side: 'tunnel' | 'lan';
  poolId: number;
  value: string;
}

/**
 * Compare a policy about to be saved with every OTHER tenant's. Same error
 * shape as `validatePolicyInput`. Refuses:
 *
 *   - a FORMULA rule on a pool another tenant's policy also uses, whatever its
 *     mode: a formula computes the address from the site number, and two
 *     tenants' site 1 would compute the same one;
 *   - an INCREMENTAL rule on another tenant's formula pool, for the same
 *     reason seen from the other side;
 *   - a FORMULA rule on a pool where another tenant's sites already hold
 *     addresses: the formula would stop on them, site after site.
 *
 * Incremental rules sharing a pool are NOT refused: that is the shared pool of
 * small tenants, and the walk passes over whatever any of them holds.
 *
 * Everything here is by pool ID. Two tenants wanting the same LAN FORMULA each
 * create their own LAN pool over the same block — LAN pools may overlap — and
 * nothing here objects: that is a reuse of one plan, which the operator chose
 * by creating the second pool.
 */
export function policyConflicts(
  candidate: AllocationPolicy,
  others: readonly PolicyPoolRef[],
  foreign: readonly ForeignAllocation[],
): FieldErrors {
  const { errors, fail } = collector();
  const sides: Array<{ side: 'tunnel' | 'lan'; pool: AddressPool; mode: AddressMode }> = [
    { side: 'tunnel', pool: candidate.tunnel.pool, mode: candidate.tunnel.mode },
  ];
  const lan = candidate.lan;
  if (lan && (lan.mode === 'incremental' || lan.mode === 'formula')) {
    sides.push({ side: 'lan', pool: lan.pool, mode: lan.mode });
  }

  for (const mine of sides) {
    const field = `${mine.side}.poolId`;
    const sharers = others.filter((o) => o.tenantId !== candidate.tenantId && o.poolId === mine.pool.id);
    for (const other of sharers) {
      if (mine.mode === 'formula') {
        fail(
          field,
          `${poolLabel(mine.pool)} is also used by tenant ${other.tenantId} (${other.mode}). A formula ` +
            "pool belongs to one tenant: two tenants' site 1 would compute the same address. Give " +
            'this tenant its own pool.',
        );
      } else if (other.mode === 'formula') {
        fail(
          field,
          `${poolLabel(mine.pool)} is the formula pool of tenant ${other.tenantId}; an incremental ` +
            "walk there would take the addresses that tenant's sites compute. Pick another pool.",
        );
      }
    }
    if (mine.mode === 'formula') {
      const held = foreign.filter(
        (f) => f.tenantId !== candidate.tenantId && f.poolId === mine.pool.id && f.side === mine.side,
      );
      if (held.length > 0) {
        fail(
          field,
          `${held.length} address(es) of ${poolLabel(mine.pool)} are already allocated to other ` +
            `tenants' sites (e.g. ${held[0].value}). A formula pool must be this tenant's alone.`,
        );
      }
    }
  }
  return errors;
}
