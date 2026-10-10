/**
 * ObliWAN — the allocation rule, read off the CHR accounts (brick 14).
 *
 * Before a single router of a big customer is attached, its stores are
 * already on the concentrator: two hundred `/ppp/secret` entries whose names,
 * addresses and profiles say how somebody numbered them years ago. This file
 * reads that numbering back as an allocation rule — the login model, the site
 * code format, the tunnel mode with its pool, the PPP profile and, when
 * router identities are known, the identity model — and says, for each,
 * how many accounts it explains and which ones it does not.
 *
 * ┌─ THE VERIFIER IS NEVER OURS ─────────────────────────────────────────────┐
 * │ Candidates come from closed shapes (a label read as {site.code},          │
 * │ {site.id}, {site.country}_{site.code}, the tenant slug and the            │
 * │ installation domain as their placeholders); what decides is the           │
 * │ allocator's own code. A login model "explains" an account when the        │
 * │ reconciliation's reader (`deriveLoginMatcher` + `readLogin`, which        │
 * │ re-renders with `renderPppLogin`) gives the account back; a tunnel        │
 * │ formula explains an address when `renderAddressFormula` renders it for    │
 * │ the site number read from the login (the extrapolator's                   │
 * │ `findAddressFormula`); an identity model when `renderSystemIdentity`      │
 * │ gives the router's identity back. So a proposed rule cannot be one the    │
 * │ allocator would evaluate differently from the way it was found — and the  │
 * │ service still dry-runs the whole proposal through `checkPolicy` before    │
 * │ showing it.                                                               │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * PURE: no database, no clock, no socket. The service loads the accounts and
 * hands them here; the harness feeds it synthetic CHRs.
 *
 * What is NOT inferred, and why: the LAN (a CHR secret carries none — the
 * LAN reprise records it from the routers), the derived values and the
 * password mode (nothing on the CHR says them). A stored rule's values for
 * those are kept as they are; without one the LAN is null and the password
 * mode the allocator's default ('shared').
 */

import crypto from 'crypto';
import {
  POLICY_FILE_FORMAT,
  RULE_INFERENCE_OUTLIERS_MAX,
  type RuleBlocker,
  type RuleFacet,
  type RuleField,
  type RuleInference,
  type RuleOutlier,
  type RuleOutlierReason,
  type SetupPolicyFile,
} from '@obliwan/shared';
import {
  POOL_NAME_MAX,
  POOL_PREFIX_MAX,
  POOL_PREFIX_MIN,
  cidrLast,
  formatCidr,
  formatIpv4,
  parseCidr,
  parseIpv4,
  rangesOverlap,
  type Cidr,
} from '../allocation/policy';
import {
  parseIdentityTemplate,
  parseLoginTemplate,
  renderPppLogin,
  renderSystemIdentity,
  siteNumber,
  type LoginTemplate,
} from '../allocation/pppIdentity';
import { deriveLoginMatcher, readLogin, type LoginMatcher, type ParsedLogin } from '../allocation/reconcile.service';
import { evaluateExpression, parseAddressFormula, parseExpression, renderAddressFormula } from '../allocation/formula';
import type { AllocationPolicyView } from '../allocation/allocator';
import { findAddressFormula, siteFactsOf } from '../baseline/extrapolator/formulas';

// ============================================================================
// Input
// ============================================================================

export interface InferenceAccount {
  concentratorId: number;
  /** As the CHR spells it. */
  name: string;
  /** What the secret DECLARES (host text), null when none. */
  remoteAddress: string | null;
  profile: string | null;
  disabled: boolean;
  online: boolean;
}

export interface InferenceIdentity {
  identity: string;
  pppUsername: string | null;
  site: { code: string; name: string; country: string | null } | null;
}

export interface InferenceSite {
  code: string;
  name: string;
  country: string | null;
}

export interface InferencePool {
  id: number;
  name: string;
  cidr: string;
  purpose: 'tunnel' | 'lan';
  policies: Array<{ tenantId: number; mode: string }>;
}

export interface InferenceInput {
  tenantId: number;
  tenantSlug: string;
  searchSlug: string;
  instanceDomain: string;
  /** The accounts naming the search text, minus those held by another
   *  customer (the service lists those apart). */
  accounts: InferenceAccount[];
  identities: InferenceIdentity[];
  sites: InferenceSite[];
  pools: InferencePool[];
  /** Every tunnel address held installation-wide (secrets, allocations,
   *  routers, open sessions), as numbers. */
  held: ReadonlySet<number>;
  concentratorNames: ReadonlyMap<number, string>;
  stored: AllocationPolicyView | null;
}

/** What `inferRule` decides; the service adds the tenant, the CHRs, the
 *  excluded accounts and the allocator's dry run. */
export type InferenceCore = Omit<
  RuleInference,
  'tenant' | 'generatedAt' | 'concentrators' | 'accounts' | 'searchSlug' | 'instanceDomain'
> & {
  accounts: { total: number; online: number; disabled: number };
  concentratorId: number | null;
};

// ============================================================================
// Small helpers
// ============================================================================

const PPP_PROFILE_RE = /^[A-Za-z0-9._-]{1,64}$/;
const SITE_PLACEHOLDERS = ['{site.code}', '{site.id}', '{site.slug}', '{site.country}'];
const FIXED_PLACEHOLDERS = ['{tenant.slug}', '{instance.domain}'];
/** Candidates evaluated against every account, at most. */
const CANDIDATES_EVALUATED = 120;

function countOf(text: string, parts: readonly string[]): number {
  let n = 0;
  for (const p of parts) n += text.split(p).length - 1;
  return n;
}

function hasUpper(text: string): boolean {
  return /[A-Z]/.test(text);
}

class Outliers {
  readonly list: RuleOutlier[] = [];
  total = 0;
  add(name: string, reason: RuleOutlierReason, detail: string | null = null): void {
    this.total += 1;
    if (this.list.length < RULE_INFERENCE_OUTLIERS_MAX) this.list.push({ name, reason, detail });
  }
}

function facet(explained: number, total: number, o: Outliers): RuleFacet {
  return { explained, total, outliers: o.list, outliersTotal: o.total };
}

/** Lexicographic "a ranks before b" on number tuples (higher first). */
function ranksBefore(a: readonly number[], b: readonly number[]): boolean {
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return a[i] > b[i];
  return false;
}

// ============================================================================
// Login model — candidates
// ============================================================================

/** The ways ONE label may stand for the site. */
function siteReadings(label: string, slugLower: string): string[] {
  const out: string[] = [];
  if (!/^[A-Za-z0-9_-]+$/.test(label)) return out;
  const lower = label.toLowerCase();
  // The tenant's own label is the tenant, never a store.
  if (slugLower !== '' && lower === slugLower) return out;
  const at = slugLower.length > 0 ? lower.indexOf(slugLower) : -1;
  if (at >= 0 && lower !== slugLower) {
    // "acme-0102", "0102_acme": the slug and the site in one label.
    const pre = label.slice(0, at);
    const post = label.slice(at + slugLower.length);
    const after = /^([-_])(.+)$/.exec(post);
    if (pre === '' && after) out.push(`{tenant.slug}${after[1]}{site.code}`);
    const before = /^(.+)([-_])$/.exec(pre);
    if (post === '' && before) out.push(`{site.code}${before[2]}{tenant.slug}`);
    return out;
  }
  out.push('{site.code}');
  if (/^[0-9]+$/.test(label)) out.push('{site.id}');
  const country = /^([A-Za-z]{2})_(.+)$/.exec(label);
  if (country) {
    out.push('{site.country}_{site.code}');
    out.push(`${country[1]}_{site.code}`);
  }
  const lettersDigits = /^([A-Za-z]+)([0-9][A-Za-z0-9_-]*)$/.exec(label);
  if (lettersDigits && !country) out.push(`${lettersDigits[1]}{site.code}`);
  if (!/[0-9]/.test(label) && /^[A-Za-z0-9-]+$/.test(label)) out.push('{site.slug}');
  return out;
}

/** The ways one label may stay fixed. */
function fixedReadings(label: string, slugLower: string): string[] {
  const lower = label.toLowerCase();
  if (slugLower !== '' && lower === slugLower) return ['{tenant.slug}'];
  if (/^[A-Za-z]{2}$/.test(label)) return [label, '{site.country}'];
  return [label];
}

/**
 * Every login model one account name suggests: one label read as the site,
 * the others fixed (the tenant slug and the installation domain as their
 * placeholders). Only models `parseLoginTemplate` accepts.
 */
export function loginCandidates(name: string, tenantSlug: string, instanceDomain: string): string[] {
  const slugLower = tenantSlug.toLowerCase();
  const domain = instanceDomain.trim();
  let body = name;
  let tail = '';
  if (domain !== '' && name.toLowerCase().endsWith(`.${domain.toLowerCase()}`) && name.length > domain.length + 1) {
    body = name.slice(0, name.length - domain.length - 1);
    tail = '.{instance.domain}';
  }
  const labels = body.split('.');
  if (labels.some((l) => l === '')) return [];
  const out = new Set<string>();
  for (let k = 0; k < labels.length; k += 1) {
    const sites = siteReadings(labels[k], slugLower);
    if (sites.length === 0) continue;
    // The fixed labels' combinations, bounded.
    let combos: string[][] = [[]];
    for (let i = 0; i < labels.length; i += 1) {
      if (i === k) continue;
      const opts = fixedReadings(labels[i], slugLower);
      const next: string[][] = [];
      for (const c of combos) for (const o of opts) if (next.length < 16) next.push([...c, o]);
      combos = next;
    }
    for (const s of sites) {
      for (const c of combos) {
        const parts = [...c];
        parts.splice(k, 0, s);
        const t = parts.join('.') + tail;
        if (parseLoginTemplate(t).ok) out.add(t);
      }
    }
  }
  return [...out];
}

// ============================================================================
// Login model — evaluation
// ============================================================================

interface LoginEvaluation {
  source: string;
  template: LoginTemplate;
  matcher: LoginMatcher;
  /** Index of every explained account -> what it reads back as. */
  parsed: Map<number, ParsedLogin>;
  exact: number;
  homogeneity: number;
  rank: number[];
}

/** The site code a parsed login stands for. */
function codeOf(p: ParsedLogin): string | null {
  if (p.code !== null) return p.code;
  if (p.number !== null) return String(p.number);
  return null;
}

/** The size of the largest group of all-digit codes of one length. */
function digitHomogeneity(codes: readonly (string | null)[]): { length: number; count: number } {
  const byLen = new Map<number, number>();
  for (const c of codes) if (c !== null && /^[0-9]+$/.test(c)) byLen.set(c.length, (byLen.get(c.length) ?? 0) + 1);
  let best = { length: 0, count: 0 };
  for (const [length, count] of byLen) {
    if (count > best.count || (count === best.count && length < best.length)) best = { length, count };
  }
  return best;
}

function evaluateLogin(
  source: string,
  accounts: readonly InferenceAccount[],
  tenantSlug: string,
  instanceDomain: string,
): LoginEvaluation | null {
  const parsedT = parseLoginTemplate(source);
  if (!parsedT.ok) return null;
  const d = deriveLoginMatcher(parsedT.template, { tenantSlug, instanceDomain });
  if (!d.ok) return null;
  const parsed = new Map<number, ParsedLogin>();
  let exact = 0;
  accounts.forEach((a, i) => {
    const p = readLogin(d.matcher, a.name);
    if (!p) return;
    parsed.set(i, p);
    const r = renderPppLogin(parsedT.template, {
      siteName: p.slug ?? 'x',
      siteCode: codeOf(p) ?? '1',
      siteCountry: p.country,
      tenantSlug,
      instanceDomain,
    }, `"${a.name}"`);
    if (r.ok && r.login === a.name) exact += 1;
  });
  const homogeneity = digitHomogeneity([...parsed.values()].map(codeOf)).count;
  return {
    source,
    template: parsedT.template,
    matcher: d.matcher,
    parsed,
    exact,
    homogeneity,
    // Homogeneity before exact case: a model that reads every store's code
    // the same way ("0006" under {site.country}_{site.code}) beats one that
    // reproduces a capitalised account letter for letter by swallowing its
    // country into the code ("FR_0006" under {site.code}).
    rank: [
      parsed.size,
      homogeneity,
      exact,
      countOf(source, FIXED_PLACEHOLDERS),
      -countOf(source, SITE_PLACEHOLDERS),
      -source.length,
    ],
  };
}

function chooseLogin(
  accounts: readonly InferenceAccount[],
  tenantSlug: string,
  instanceDomain: string,
): { best: LoginEvaluation | null; alternatives: Array<{ template: string; explained: number }> } {
  const freq = new Map<string, number>();
  for (const a of accounts) {
    for (const c of loginCandidates(a.name, tenantSlug, instanceDomain)) freq.set(c, (freq.get(c) ?? 0) + 1);
  }
  const ordered = [...freq.entries()]
    .sort((x, y) => y[1] - x[1] || (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0))
    .slice(0, CANDIDATES_EVALUATED)
    .map(([t]) => t);
  const evaluated: LoginEvaluation[] = [];
  for (const t of ordered) {
    const e = evaluateLogin(t, accounts, tenantSlug, instanceDomain);
    if (e && e.parsed.size > 0) evaluated.push(e);
  }
  evaluated.sort((a, b) => (ranksBefore(a.rank, b.rank) ? -1 : ranksBefore(b.rank, a.rank) ? 1 : a.source < b.source ? -1 : 1));
  return {
    best: evaluated[0] ?? null,
    alternatives: evaluated.slice(1, 4).map((e) => ({ template: e.source, explained: e.parsed.size })),
  };
}

// ============================================================================
// Tunnel
// ============================================================================

interface TunnelItem {
  name: string;
  code: string | null;
  country: string | null;
  address: number | null;
  addressText: string | null;
}

function cidrOf(network: number, prefix: number): Cidr {
  return { network, prefix, size: 2 ** (32 - prefix) };
}

/** The smallest CIDR holding [lo, hi], clamped to the pool bounds. */
export function smallestBlock(lo: number, hi: number): Cidr {
  let prefix = 32;
  while (prefix > 0) {
    const size = 2 ** (32 - prefix);
    if (Math.floor(lo / size) === Math.floor(hi / size)) break;
    prefix -= 1;
  }
  prefix = Math.min(Math.max(prefix, POOL_PREFIX_MIN), POOL_PREFIX_MAX);
  const size = 2 ** (32 - prefix);
  return cidrOf(Math.floor(lo / size) * size, prefix);
}

function blockContains(outer: Cidr, inner: Cidr): boolean {
  return inner.network >= outer.network && cidrLast(inner) <= cidrLast(outer);
}

/** The block a formula's literal leading octets fix ("100.66.{…}.{…}" ->
 *  100.66.0.0/16), or null. */
function formulaLiteralBlock(source: string): Cidr | null {
  const p = parseAddressFormula(source, { prefix: 'forbidden' });
  if (!p.ok) return null;
  const literal: number[] = [];
  for (const o of p.formula.octets) {
    if (o.kind !== 'literal') break;
    literal.push(o.value);
  }
  const prefix = literal.length * 8;
  if (prefix < POOL_PREFIX_MIN || prefix > POOL_PREFIX_MAX) return null;
  while (literal.length < 4) literal.push(0);
  return cidrOf(literal[0] * 16777216 + literal[1] * 65536 + literal[2] * 256 + literal[3], prefix);
}

/** No two site numbers in [0, maxId] render the same address (the ones a
 *  formula renders at all). A formula the observed accounts all fit can
 *  still fold the future onto the past: "100.77.1.{id%100}" fits every store
 *  of a tenant whose codes all lie between 101 and 199, and gives store 201
 *  the address of store 101. */
export function formulaInjective(source: string, maxId: number): boolean {
  const p = parseAddressFormula(source, { prefix: 'forbidden' });
  if (!p.ok) return false;
  const seen = new Set<number>();
  for (let id = 0; id <= maxId; id += 1) {
    const r = renderAddressFormula(p.formula, id);
    if (!r.ok) continue;
    if (seen.has(r.address)) return false;
    seen.add(r.address);
  }
  return true;
}

/** The quotients tried, in order, for the literal octet left of the
 *  formula's first site-number octet. */
const CARRY_BASES = ['id/100', 'id/256', 'id/10', 'id/1000', 'id/100%100', 'id/256%256', 'id/10000'];

function splitOctets(source: string): string[] {
  const out: string[] = [];
  let cur = '';
  let inside = false;
  for (const ch of source) {
    if (ch === '{') inside = true;
    else if (ch === '}') inside = false;
    if (ch === '.' && !inside) {
      out.push(cur);
      cur = '';
    } else cur += ch;
  }
  out.push(cur);
  return out;
}

/**
 * The extrapolator's search keeps an octet literal whenever every observed
 * account agrees on it (simplest first). For a rule meant to number FUTURE
 * sites, that literal is a carry the observed codes never exercised. While
 * the formula is not injective over [0, maxId], the literal octet just left
 * of its first site-number octet is replaced by the first quotient that
 * still renders EVERY fitted account exactly; the allocator's own renderer
 * is the judge. Unchanged when no quotient fits.
 */
export function generalizeFormula(
  source: string,
  fitted: ReadonlyArray<{ id: number; text: string }>,
  maxId: number,
): string {
  let octs = splitOctets(source);
  for (let guard = 0; guard < 3; guard += 1) {
    const text = octs.join('.');
    if (formulaInjective(text, maxId)) return text;
    const k = octs.findIndex((o) => o.startsWith('{')) - 1;
    if (k < 0 || fitted.length === 0) return source;
    const sample = fitted[0];
    const sampleOctet = Number(sample.text.split('.')[k]);
    let next: string[] | null = null;
    for (const base of CARRY_BASES) {
      const e = parseExpression(base);
      if (!e.ok) continue;
      const v = evaluateExpression(e.node, sample.id);
      if (!v.ok) continue;
      const c = sampleOctet - v.value;
      const octet = c === 0 ? `{${base}}` : c > 0 ? `{${c}+${base}}` : `{${base}-${-c}}`;
      const candidate = [...octs];
      candidate[k] = octet;
      const p = parseAddressFormula(candidate.join('.'), { prefix: 'forbidden' });
      if (!p.ok) continue;
      const all = fitted.every((f) => {
        const r = renderAddressFormula(p.formula, f.id);
        return r.ok && r.text === f.text;
      });
      if (all) {
        next = candidate;
        break;
      }
    }
    if (!next) return source;
    octs = next;
  }
  const last = octs.join('.');
  return formulaInjective(last, maxId) ? last : source;
}

/** The lowest host an incremental walk would hand out from `from` to `to`
 *  (never a .0 or a .255), not held by anybody; null when none is left. */
function firstFreeIn(from: number, to: number, held: ReadonlySet<number>): number | null {
  for (let a = from; a <= to; a += 1) {
    const last = a % 256;
    if (last === 0 || last === 255 || held.has(a)) continue;
    return a;
  }
  return null;
}

interface TunnelInference {
  facet: RuleFacet;
  mode: 'formula' | 'incremental' | null;
  formula: string | null;
  start: string | null;
  block: string | null;
  firstFree: string | null;
  pool: RuleInference['tunnel']['pool'];
  createPool: { name: string; cidr: string } | null;
  blocker: RuleBlocker | null;
}

function inferTunnel(
  items: readonly TunnelItem[],
  input: Pick<InferenceInput, 'pools' | 'held' | 'tenantId' | 'tenantSlug'>,
): TunnelInference {
  const o = new Outliers();
  const none: TunnelInference['pool'] = { action: 'none', id: null, name: null, cidr: null, conflictWith: null };
  const withAddress = items.filter((i) => i.address !== null);
  for (const i of items) if (i.address === null) o.add(i.name, 'noAddress', i.addressText);
  if (withAddress.length === 0) {
    return { facet: facet(0, items.length, o), mode: null, formula: null, start: null, block: null, firstFree: null, pool: none, createPool: null, blocker: 'no_tunnel' };
  }

  // The /16 most addresses share; the others are named, not followed.
  const by16 = new Map<number, number>();
  for (const i of withAddress) {
    const k = Math.floor((i.address as number) / 65536);
    by16.set(k, (by16.get(k) ?? 0) + 1);
  }
  const dominant = [...by16.entries()].sort((a, b) => b[1] - a[1] || a[0] - b[0])[0][0];
  const inBlock = withAddress.filter((i) => Math.floor((i.address as number) / 65536) === dominant);
  for (const i of withAddress) if (Math.floor((i.address as number) / 65536) !== dominant) o.add(i.name, 'outsideBlock', i.addressText);
  const lo = Math.min(...inBlock.map((i) => i.address as number));
  const hi = Math.max(...inBlock.map((i) => i.address as number));
  const block = smallestBlock(lo, hi);

  // A formula over the site number, verified by the allocator's renderer.
  const facts = inBlock.map((i) => siteFactsOf({ code: i.code, name: null, country: i.country }));
  const numeric = inBlock.filter((_, k) => facts[k].id !== null);
  const found = findAddressFormula(inBlock.map((i) => i.addressText), facts);
  let mode: 'formula' | 'incremental' = 'incremental';
  let formula: string | null = null;
  let explained = inBlock.length;
  if (found && found.fits.length >= 2 && found.fits.length * 2 > numeric.length) {
    mode = 'formula';
    // The future sites' numbers: every number the longest code seen can
    // spell ("0001" -> up to 9 999), 99 999 at most (the allocator's own
    // probe bound).
    const maxLen = Math.max(...numeric.map((i) => (i.code as string).length));
    const maxId = Math.min(99_999, 10 ** maxLen - 1);
    formula = generalizeFormula(
      found.formula.source,
      found.fits.map((k) => ({ id: facts[k].id as number, text: inBlock[k].addressText as string })),
      maxId,
    );
    const fits = new Set(found.fits);
    explained = fits.size;
    const parsedF = parseAddressFormula(formula, { prefix: 'forbidden' });
    inBlock.forEach((i, k) => {
      if (fits.has(k)) return;
      if (facts[k].id === null) {
        o.add(i.name, 'codeFormat', i.code);
        return;
      }
      // What formula.ts's renderer gives for this site number.
      const r = parsedF.ok ? renderAddressFormula(parsedF.formula, facts[k].id as number) : null;
      o.add(i.name, 'formulaMismatch', `${i.addressText} ≠ ${r && r.ok ? r.text : '—'}`);
    });
  }

  // The pool: an existing tunnel pool holding the block, else one to create.
  const pools = input.pools
    .map((p) => ({ ...p, parsed: parseCidr(p.cidr) }))
    .filter((p): p is typeof p & { parsed: { ok: true; cidr: Cidr } } => p.parsed.ok);
  const holding = pools
    .filter((p) => p.purpose === 'tunnel' && blockContains(p.parsed.cidr, block))
    .sort((a, b) => b.parsed.cidr.prefix - a.parsed.cidr.prefix)[0];
  let pool: TunnelInference['pool'] = none;
  let createPool: TunnelInference['createPool'] = null;
  let blocker: RuleBlocker | null = null;
  let poolCidr: Cidr = block;
  if (holding) {
    poolCidr = holding.parsed.cidr;
    const others = holding.policies.filter((p) => p.tenantId !== input.tenantId);
    const shared = mode === 'formula' ? others.length > 0 : others.some((p) => p.mode === 'formula');
    if (shared) {
      pool = { action: 'conflict', id: holding.id, name: holding.name, cidr: holding.cidr, conflictWith: holding.name };
      blocker = 'pool_shared';
    } else {
      pool = { action: 'existing', id: holding.id, name: holding.name, cidr: holding.cidr, conflictWith: null };
    }
  } else {
    const overlapping = (c: Cidr) =>
      pools.find((p) => rangesOverlap(c.network, cidrLast(c), p.parsed.cidr.network, cidrLast(p.parsed.cidr)));
    let wanted: Cidr = block;
    if (mode === 'formula' && formula) {
      const lit = formulaLiteralBlock(formula);
      if (lit && blockContains(lit, block)) wanted = lit;
    } else if (block.prefix > 24) {
      wanted = cidrOf(Math.floor(block.network / 256) * 256, 24);
    }
    if (overlapping(wanted) && !overlapping(block)) wanted = block;
    const clash = overlapping(wanted);
    if (clash) {
      pool = { action: 'conflict', id: null, name: null, cidr: formatCidr(wanted), conflictWith: clash.name };
      blocker = 'pool_conflict';
    } else {
      poolCidr = wanted;
      const taken = new Set(input.pools.map((p) => p.name.toLowerCase()));
      const base = `${input.tenantSlug.toUpperCase()}-tunnel`.slice(0, POOL_NAME_MAX - 3);
      let name = base;
      for (let n = 2; taken.has(name.toLowerCase()); n += 1) name = `${base}-${n}`;
      createPool = { name, cidr: formatCidr(wanted) };
      pool = { action: 'create', id: null, name, cidr: createPool.cidr, conflictWith: null };
    }
  }

  const free = firstFreeIn(block.network, cidrLast(block), input.held)
    ?? firstFreeIn(cidrLast(block) + 1, cidrLast(poolCidr), input.held);
  const firstFree = free === null ? null : formatIpv4(free);
  return {
    facet: facet(explained, items.length, o),
    mode,
    formula,
    start: mode === 'incremental' ? firstFree : null,
    block: formatCidr(block),
    firstFree,
    pool,
    createPool,
    blocker: blocker ?? (mode === 'incremental' && firstFree === null ? 'no_tunnel' : null),
  };
}

// ============================================================================
// Identity
// ============================================================================

function identityCandidates(
  identity: string,
  site: { code: string; country: string | null },
  tenantSlug: string,
  instanceDomain: string,
): string[] {
  const domain = instanceDomain.trim();
  const out = new Set<string>();
  const domains: Array<(s: string) => string> = [(s) => s];
  if (domain !== '' && identity.toLowerCase().endsWith(`.${domain.toLowerCase()}`)) {
    domains.push((s) => `${s.slice(0, s.length - domain.length - 1)}.{instance.domain}`);
  }
  const slugs: Array<(s: string) => string> = [(s) => s];
  if (tenantSlug.length >= 2) {
    const re = new RegExp(tenantSlug.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
    slugs.push((s) => s.replace(re, '{tenant.slug}'));
  }
  const codes: Array<(s: string) => string | null> = [
    (s) => (s.includes(site.code) ? s.replace(site.code, '{site.code}') : null),
  ];
  const n = siteNumber(site.code);
  if (n !== null && String(n) !== site.code) {
    codes.push((s) => {
      const re = new RegExp(`(^|[^0-9])${n}($|[^0-9])`);
      return re.test(s) ? s.replace(re, `$1{site.id}$2`) : null;
    });
  }
  const countries: Array<(s: string) => string> = [(s) => s];
  if (site.country) {
    const c = site.country.toLowerCase();
    countries.push((s) => s.replace(new RegExp(`(^|[._])${c}([._])`, 'i'), `$1{site.country}$2`));
  }
  for (const d of domains) {
    for (const sl of slugs) {
      for (const co of codes) {
        for (const cn of countries) {
          // The code first: it is the only placeholder that must appear.
          const withCode = co(identity);
          if (withCode === null) continue;
          const t = cn(sl(d(withCode)));
          if (parseIdentityTemplate(t).ok) out.add(t);
        }
      }
    }
  }
  return [...out];
}

interface IdentityKnown {
  identity: string;
  vars: { siteName: string; siteCode: string; siteCountry: string | null };
}

function inferIdentity(
  known: readonly IdentityKnown[],
  tenantSlug: string,
  instanceDomain: string,
): { template: string | null; facet: RuleFacet } {
  const o = new Outliers();
  if (known.length === 0) return { template: null, facet: facet(0, 0, o) };
  const candidates = new Set<string>();
  for (const k of known) {
    for (const c of identityCandidates(k.identity, { code: k.vars.siteCode, country: k.vars.siteCountry }, tenantSlug, instanceDomain)) {
      candidates.add(c);
    }
  }
  let best: { source: string; explained: Set<number>; rank: number[] } | null = null;
  for (const source of candidates) {
    const parsed = parseIdentityTemplate(source);
    if (!parsed.ok) continue;
    const explained = new Set<number>();
    let exact = 0;
    known.forEach((k, i) => {
      const r = renderSystemIdentity(parsed.template, { ...k.vars, tenantSlug, instanceDomain }, k.vars.siteCode);
      if (!r.ok) return;
      if (r.identity.toLowerCase() === k.identity.toLowerCase()) explained.add(i);
      if (r.identity === k.identity) exact += 1;
    });
    const rank = [
      explained.size,
      exact,
      countOf(source, FIXED_PLACEHOLDERS),
      -countOf(source, SITE_PLACEHOLDERS),
      -source.length,
    ];
    if (!best || ranksBefore(rank, best.rank) || (!ranksBefore(best.rank, rank) && source < best.source)) {
      best = { source, explained, rank };
    }
  }
  if (!best || best.explained.size === 0 || best.explained.size * 2 < known.length) {
    for (const k of known) o.add(k.identity, 'identityMismatch', k.vars.siteCode);
    return { template: null, facet: facet(0, known.length, o) };
  }
  known.forEach((k, i) => {
    if (!best!.explained.has(i)) o.add(k.identity, 'identityMismatch', k.vars.siteCode);
  });
  return { template: best.source, facet: facet(best.explained.size, known.length, o) };
}

// ============================================================================
// The whole rule
// ============================================================================

function lanBody(stored: AllocationPolicyView | null): { body: unknown; file: SetupPolicyFile['lan'] } {
  const l = stored?.lan ?? null;
  if (!l) return { body: null, file: null };
  switch (l.mode) {
    case 'fixed':
      return { body: { mode: 'fixed', subnet: l.subnet }, file: { mode: 'fixed', subnet: l.subnet ?? undefined } };
    case 'manual':
      return { body: { mode: 'manual', variable: l.variable }, file: { mode: 'manual', variable: l.variable ?? undefined } };
    case 'incremental':
      return {
        body: { mode: 'incremental', poolId: l.poolId, prefix: l.prefix },
        file: { mode: 'incremental', ...(l.poolName ? { poolName: l.poolName } : { poolId: l.poolId ?? undefined }), prefix: l.prefix ?? undefined },
      };
    case 'formula':
    default:
      return {
        body: { mode: 'formula', poolId: l.poolId, formula: l.formula },
        file: { mode: 'formula', ...(l.poolName ? { poolName: l.poolName } : { poolId: l.poolId ?? undefined }), formula: l.formula ?? undefined },
      };
  }
}

/**
 * Read the rule off the accounts. Deterministic: the same input gives the
 * same proposal and the same fingerprint.
 */
export function inferRule(input: InferenceInput): InferenceCore {
  const { accounts, tenantSlug, instanceDomain } = input;
  const loginOut = new Outliers();
  const codeOut = new Outliers();
  const profileOut = new Outliers();

  const { best, alternatives } = chooseLogin(accounts, tenantSlug, instanceDomain);
  const explainedIdx = best ? [...best.parsed.keys()].sort((a, b) => a - b) : [];
  const explained = explainedIdx.map((i) => ({ a: accounts[i], p: best!.parsed.get(i)! }));

  // ── login outliers ──────────────────────────────────────────────────────
  const withCountry = explained.filter((e) => e.p.country !== null).length;
  const usesCountry = best?.template.uses.has('site.country') === true;
  accounts.forEach((a, i) => {
    if (!best || !best.parsed.has(i)) loginOut.add(a.name, 'oldNaming');
  });
  for (const e of explained) {
    if (hasUpper(e.a.name)) loginOut.add(e.a.name, 'uppercase');
    if (usesCountry && e.p.country === null && withCountry * 2 > explained.length) {
      loginOut.add(e.a.name, 'missingCountry', codeOf(e.p));
    }
  }
  for (const a of accounts) if (a.disabled) loginOut.add(a.name, 'disabled');

  // ── the concentrator most explained accounts are on ─────────────────────
  const byChr = new Map<number, number>();
  for (const e of explained) byChr.set(e.a.concentratorId, (byChr.get(e.a.concentratorId) ?? 0) + 1);
  const concentratorId = [...byChr.entries()].sort((x, y) => y[1] - x[1] || x[0] - y[0])[0]?.[0] ?? null;
  for (const e of explained) {
    if (concentratorId !== null && e.a.concentratorId !== concentratorId) {
      loginOut.add(e.a.name, 'otherConcentrator', input.concentratorNames.get(e.a.concentratorId) ?? String(e.a.concentratorId));
    }
  }
  const onChr = explained.filter((e) => e.a.concentratorId === concentratorId);

  // ── site code format ────────────────────────────────────────────────────
  const codes = onChr.map((e) => ({ name: e.a.name, code: codeOf(e.p) }));
  const dominant = digitHomogeneity(codes.map((c) => c.code));
  let format = 'free';
  let formatExplained = codes.length;
  if (best && (best.template.uses.has('site.code') || best.template.uses.has('site.id')) && dominant.count * 2 > codes.length) {
    format = `digits:${dominant.length}`;
    formatExplained = dominant.count;
    for (const c of codes) {
      if (c.code === null || !/^[0-9]+$/.test(c.code) || c.code.length !== dominant.length) codeOut.add(c.name, 'codeFormat', c.code);
    }
  }

  // ── tunnel ──────────────────────────────────────────────────────────────
  const tunnel = inferTunnel(
    onChr.map((e) => ({
      name: e.a.name,
      code: codeOf(e.p),
      country: e.p.country,
      address: e.a.remoteAddress === null ? null : parseIpv4(e.a.remoteAddress),
      addressText: e.a.remoteAddress,
    })),
    input,
  );

  // ── PPP profile ─────────────────────────────────────────────────────────
  const byProfile = new Map<string, number>();
  for (const e of onChr) if (e.a.profile !== null) byProfile.set(e.a.profile, (byProfile.get(e.a.profile) ?? 0) + 1);
  const topProfile = [...byProfile.entries()]
    .filter(([p]) => PPP_PROFILE_RE.test(p))
    .sort((x, y) => y[1] - x[1] || (x[0] < y[0] ? -1 : 1))[0];
  const profile = topProfile ? topProfile[0] : null;
  for (const e of onChr) if (e.a.profile !== profile) profileOut.add(e.a.name, 'otherProfile', e.a.profile);

  // ── identity, when routers are known ────────────────────────────────────
  const known: IdentityKnown[] = [];
  for (const id of input.identities) {
    if (id.site) {
      known.push({ identity: id.identity, vars: { siteName: id.site.name, siteCode: id.site.code, siteCountry: id.site.country } });
      continue;
    }
    if (!best || !id.pppUsername) continue;
    const p = readLogin(best.matcher, id.pppUsername);
    const code = p ? codeOf(p) : null;
    if (p && code !== null) known.push({ identity: id.identity, vars: { siteName: p.slug ?? code, siteCode: code, siteCountry: p.country } });
  }
  const identity = inferIdentity(known, tenantSlug, instanceDomain);

  // ── sites of the tenant with no account ─────────────────────────────────
  const names = new Set(accounts.map((a) => a.name.toLowerCase()));
  const noAccount: string[] = [];
  let noAccountTotal = 0;
  if (best) {
    for (const s of input.sites) {
      const r = renderPppLogin(best.template, {
        siteName: s.name, siteCode: s.code, siteCountry: s.country, tenantSlug, instanceDomain,
      }, s.code);
      if (r.ok && names.has(r.login.toLowerCase())) continue;
      noAccountTotal += 1;
      if (noAccount.length < RULE_INFERENCE_OUTLIERS_MAX) noAccount.push(s.code);
    }
  }

  // ── the proposal ────────────────────────────────────────────────────────
  const blockers: RuleBlocker[] = [];
  if (accounts.length === 0) blockers.push('no_accounts');
  else if (!best) blockers.push('no_login');
  if (accounts.length > 0 && concentratorId === null) blockers.push('no_concentrator');
  if (best && tunnel.blocker) blockers.push(tunnel.blocker);

  const stored = input.stored;
  const identityTemplate = identity.template ?? stored?.systemIdentityTemplate ?? null;
  const lan = lanBody(stored);
  const passwordMode = stored?.pppPasswordMode ?? 'shared';
  const derived = stored && Object.keys(stored.derived ?? {}).length > 0 ? stored.derived : null;
  let file: SetupPolicyFile | null = null;
  let body: Record<string, unknown> | null = null;
  if (blockers.length === 0 && best && concentratorId !== null && tunnel.mode !== null) {
    const tunnelBody = tunnel.mode === 'formula'
      ? { poolId: tunnel.pool.id, mode: 'formula', formula: tunnel.formula }
      : { poolId: tunnel.pool.id, mode: 'incremental', start: tunnel.start };
    body = {
      tunnel: tunnelBody,
      lan: lan.body,
      pppLoginTemplate: best.source,
      systemIdentityTemplate: identityTemplate,
      pppPasswordMode: passwordMode,
      derived,
      pppProfile: profile,
      concentratorId,
      siteCodeFormat: format,
    };
    file = {
      format: POLICY_FILE_FORMAT,
      tunnel: tunnel.mode === 'formula'
        ? { poolName: tunnel.pool.name ?? undefined, mode: 'formula', formula: tunnel.formula ?? undefined }
        : { poolName: tunnel.pool.name ?? undefined, mode: 'incremental', start: tunnel.start ?? undefined },
      lan: lan.file,
      pppLoginTemplate: best.source,
      systemIdentityTemplate: identityTemplate,
      pppPasswordMode: passwordMode,
      derived,
      pppProfile: profile,
      concentratorName: input.concentratorNames.get(concentratorId),
      siteCodeFormat: format,
    };
  }

  const differs: RuleField[] = [];
  if (stored && body) {
    if (stored.pppLoginTemplate !== best?.source) differs.push('login');
    if ((stored.systemIdentityTemplate ?? null) !== identityTemplate) differs.push('identity');
    const st = stored.tunnel;
    if (
      st.mode !== tunnel.mode || st.poolId !== tunnel.pool.id ||
      (tunnel.mode === 'formula' ? st.formula !== tunnel.formula : st.start !== tunnel.start)
    ) differs.push('tunnel');
    if ((stored.pppProfile ?? null) !== profile) differs.push('profile');
    if (stored.siteCodeFormat !== format) differs.push('codeFormat');
    if (stored.concentratorId !== concentratorId) differs.push('concentrator');
  }

  const fingerprint = crypto
    .createHash('sha256')
    .update(JSON.stringify({ body, createPool: tunnel.createPool, file }))
    .digest('hex');

  return {
    accounts: {
      total: accounts.length,
      online: accounts.filter((a) => a.online).length,
      disabled: accounts.filter((a) => a.disabled).length,
    },
    concentratorId,
    login: {
      ...facet(explained.length, accounts.length, loginOut),
      template: best?.source ?? null,
      display: best?.matcher.display ?? null,
      alternatives,
    },
    codeFormat: { ...facet(formatExplained, codes.length, codeOut), format },
    tunnel: {
      ...tunnel.facet,
      mode: tunnel.mode,
      formula: tunnel.formula,
      start: tunnel.start,
      block: tunnel.block,
      firstFree: tunnel.firstFree,
      pool: tunnel.pool,
    },
    profile: { ...facet(profile === null ? 0 : (byProfile.get(profile) ?? 0), onChr.length, profileOut), value: profile },
    identity: { ...identity.facet, template: identity.template, known: known.length },
    sitesWithoutAccount: { total: noAccountTotal, codes: noAccount },
    stored: { exists: stored !== null, differs },
    proposal: {
      file,
      body,
      createPool: blockers.length === 0 ? tunnel.createPool : null,
      blockers,
      allocator: { checked: false, ok: false, reason: null, message: null },
      fingerprint,
    },
  };
}
