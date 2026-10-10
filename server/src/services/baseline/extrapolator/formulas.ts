// ============================================================================
// Brick 10 — formulas: is this value a function of the site?
// ============================================================================
//
// The operator's templates turn a site code into a PPP login
// (`{site.code}.acme.cust.example`), an identity, a LAN
// (`10.{id/100}.{id%100}.0/24`), a loopback, a router address inside the LAN
// (`cidrHost(lan_subnet, 1)`). Each of those is a value that differs at every
// site and is nevertheless NOT a per-site variable: it is one rule.
//
// The search here is a CANDIDATE GENERATOR followed by a VERIFIER, and the
// verifier is never ours: a text pattern is re-rendered by the allocator's
// `renderPppLogin`, an address formula by `renderAddressFormula`, a LAN host by
// the same arithmetic as `derived.ts` — the very functions that will compute the
// value once the operator has adopted the rule. A formula "fits" a site when
// THAT evaluation gives back the value the router runs, character for
// character. So a proposed formula cannot be one the allocator would evaluate
// differently from the way it was found.
//
// No `eval`, no expression built from data: candidates come from closed lists
// (four placeholders, a fixed family of octet expressions), and the allocator's
// own parser judges the final text (the template-injection lesson applied to formulas).

import { parseAddressFormula, renderAddressFormula, formulaUsesId } from '../../allocation/formula';
import { parseLoginTemplate, renderPppLogin, siteNumber, siteSlug } from '../../allocation/pppIdentity';
import { cidrLast, formatIpv4, parseCidr, parseIpv4 } from '../../allocation/policy';

// ============================================================================
// Site facts
// ============================================================================

export interface SiteFacts {
  code: string | null;
  /** The site NUMBER (`siteNumber(code)`), the `id` of the address formulas. */
  id: number | null;
  name: string | null;
  slug: string | null;
  /** Lowercase ISO alpha-2, or null. */
  country: string | null;
  /** The site LAN (CIDR) and its network address, once the LAN is known —
   *  values that EMBED it (an address list, a routing rule) are patterns too. */
  lan: string | null;
  lanNetwork: string | null;
}

export function siteFactsOf(site: { code: string | null; name: string | null; country: string | null } | null): SiteFacts {
  const code = site?.code ?? null;
  const slug = site?.name ? siteSlug(site.name) : '';
  const country = site?.country && /^[A-Za-z]{2}$/.test(site.country) ? site.country.toLowerCase() : null;
  return {
    code,
    id: code !== null ? siteNumber(code) : null,
    name: site?.name ?? null,
    slug: slug === '' ? null : slug,
    country,
    lan: null,
    lanNetwork: null,
  };
}

// ============================================================================
// Text patterns (the login-template grammar)
// ============================================================================

export type Placeholder = 'site.code' | 'site.id' | 'site.slug' | 'site.country' | 'lan' | 'lan.network';

/** What the BODY can inline: the site code and the site LAN. */
const INLINE_PLACEHOLDERS: ReadonlySet<Placeholder> = new Set<Placeholder>(['site.code', 'lan', 'lan.network']);

/** Preference order: the code first (it is what the hand-made templates use),
 *  the number next, the slug, the country last. */
const PLACEHOLDER_RANK: Record<Placeholder, number> = {
  'site.code': 0, 'site.id': 1, 'site.slug': 2, 'site.country': 3, 'lan': 4, 'lan.network': 5,
};

export type TextSegment = { kind: 'lit'; text: string } | { kind: 'ph'; name: Placeholder };

export interface TextPattern {
  segments: TextSegment[];
  /** `{site.code}.acme.example` — the login-template spelling. */
  source: string;
  /** Uses `{site.code}` and nothing else. */
  codeOnly: boolean;
  /** Uses only what the body can inline: the site code, the site LAN. */
  inline: boolean;
  /** Uses the site LAN. */
  usesLan: boolean;
  /** The allocator's login grammar accepts it (a derived `text` value). */
  loginGrammar: boolean;
}

function factText(f: SiteFacts, ph: Placeholder): string | null {
  switch (ph) {
    case 'site.code': return f.code;
    case 'site.id': return f.id === null ? null : String(f.id);
    case 'site.slug': return f.slug;
    case 'site.country': return f.country;
    case 'lan': return f.lan;
    case 'lan.network': return f.lanNetwork;
  }
}

export function renderSegments(segments: readonly TextSegment[], f: SiteFacts): string | null {
  let out = '';
  for (const s of segments) {
    if (s.kind === 'lit') { out += s.text; continue; }
    const t = factText(f, s.name);
    if (t === null || t === '') return null;
    out += t;
  }
  return out;
}

function sourceOf(segments: readonly TextSegment[]): string {
  return segments.map((s) => (s.kind === 'lit' ? s.text : `{${s.name}}`)).join('');
}

/** Every way of reading `value` as literals and site placeholders (≤ 3 of
 *  them, ≤ 64 readings). */
function candidatesFor(value: string, f: SiteFacts): TextSegment[][] {
  const occ: Array<{ name: Placeholder; start: number; end: number }> = [];
  for (const name of Object.keys(PLACEHOLDER_RANK) as Placeholder[]) {
    const t = factText(f, name);
    if (!t) continue;
    // A one-character fact ("7") is found everywhere and means nothing,
    // unless it is the whole value.
    if (t.length < 2 && t !== value) continue;
    let from = 0;
    for (;;) {
      const at = value.indexOf(t, from);
      if (at < 0) break;
      occ.push({ name, start: at, end: at + t.length });
      from = at + 1;
    }
  }
  occ.sort((a, b) => a.start - b.start || PLACEHOLDER_RANK[a.name] - PLACEHOLDER_RANK[b.name]);
  const out: TextSegment[][] = [];
  const build = (chosen: typeof occ): TextSegment[] => {
    const segs: TextSegment[] = [];
    let at = 0;
    for (const o of chosen) {
      if (o.start > at) segs.push({ kind: 'lit', text: value.slice(at, o.start) });
      segs.push({ kind: 'ph', name: o.name });
      at = o.end;
    }
    if (at < value.length) segs.push({ kind: 'lit', text: value.slice(at) });
    return segs;
  };
  const rec = (from: number, chosen: typeof occ): void => {
    if (out.length >= 64) return;
    if (chosen.length > 0) out.push(build(chosen));
    if (chosen.length === 3) return;
    for (let k = from; k < occ.length; k++) {
      const o = occ[k];
      if (chosen.length > 0 && o.start < chosen[chosen.length - 1].end) continue;
      rec(k + 1, [...chosen, o]);
    }
  };
  rec(0, []);
  return out;
}

export interface FormulaFit<T> {
  formula: T;
  /** Indexes (into the values array) of the sites the formula reproduces. */
  fits: number[];
}

/**
 * The best text pattern for `values[i]` at `facts[i]`, or null. A pattern
 * must use a site placeholder (or it is a constant, not a formula) and must
 * fit at least two sites.
 */
export function findTextPattern(
  values: readonly (string | null)[],
  facts: readonly SiteFacts[],
): FormulaFit<TextPattern> | null {
  const seeds: number[] = [];
  const seenValues = new Set<string>();
  for (let i = 0; i < values.length && seeds.length < 4; i++) {
    const v = values[i];
    if (v === null || v === '' || seenValues.has(v)) continue;
    seenValues.add(v);
    seeds.push(i);
  }
  const tried = new Set<string>();
  let best: { pattern: TextPattern; fits: number[]; rank: number[] } | null = null;
  for (const s of seeds) {
    for (const segs of candidatesFor(values[s]!, facts[s])) {
      const source = sourceOf(segs);
      if (tried.has(source)) continue;
      tried.add(source);
      const fits: number[] = [];
      for (let i = 0; i < values.length; i++) {
        if (values[i] !== null && renderSegments(segs, facts[i]) === values[i]) fits.push(i);
      }
      if (fits.length < 2) continue;
      const phs = segs.filter((x): x is { kind: 'ph'; name: Placeholder } => x.kind === 'ph');
      const rank = [
        -fits.length,
        phs.length,
        phs.reduce((a, p) => a + PLACEHOLDER_RANK[p.name], 0),
        source.length,
      ];
      if (best === null || lexLess(rank, best.rank) || (sameRank(rank, best.rank) && source < best.pattern.source)) {
        const codeOnly = phs.every((p) => p.name === 'site.code');
        const inline = phs.every((p) => INLINE_PLACEHOLDERS.has(p.name));
        const usesLan = phs.some((p) => p.name === 'lan' || p.name === 'lan.network');
        best = {
          pattern: {
            segments: segs, source, codeOnly, inline, usesLan,
            loginGrammar: !usesLan && parseLoginTemplate(source).ok,
          },
          fits,
          rank,
        };
      }
    }
  }
  if (!best) return null;
  // The allocator's renderer is the judge of a pattern it would evaluate.
  if (best.pattern.loginGrammar) {
    const parsed = parseLoginTemplate(best.pattern.source);
    if (parsed.ok) {
      best.fits = best.fits.filter((i) => {
        const f = facts[i];
        const r = renderPppLogin(parsed.template, {
          siteName: f.name ?? '',
          siteCode: f.code ?? '',
          siteCountry: f.country,
          tenantSlug: 'x',
          instanceDomain: '',
        }, f.code ?? '?');
        return r.ok && r.login === values[i];
      });
    }
  }
  return { formula: best.pattern, fits: best.fits };
}

function lexLess(a: number[], b: number[]): boolean {
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] < b[i];
  return false;
}

function sameRank(a: number[], b: number[]): boolean {
  return a.every((x, i) => x === b[i]);
}

// ============================================================================
// Address formulas over the site number
// ============================================================================

interface OctetBase { name: string; f: (id: number) => number }

const tr = (x: number): number => Math.trunc(x);

/** Simplest first. Every one is spelled in formula.ts's grammar. */
const OCTET_BASES: readonly OctetBase[] = [
  { name: '', f: () => 0 },
  { name: 'id%100', f: (id) => id % 100 },
  { name: 'id/100', f: (id) => tr(id / 100) },
  { name: 'id/100%100', f: (id) => tr(id / 100) % 100 },
  { name: 'id%256', f: (id) => id % 256 },
  { name: 'id/256', f: (id) => tr(id / 256) },
  { name: 'id/256%256', f: (id) => tr(id / 256) % 256 },
  { name: 'id%10', f: (id) => id % 10 },
  { name: 'id/10', f: (id) => tr(id / 10) },
  { name: 'id/10%10', f: (id) => tr(id / 10) % 10 },
  { name: 'id/10%100', f: (id) => tr(id / 10) % 100 },
  { name: 'id%1000', f: (id) => id % 1000 },
  { name: 'id/1000', f: (id) => tr(id / 1000) },
  { name: 'id/1000%100', f: (id) => tr(id / 1000) % 100 },
  { name: 'id/10000', f: (id) => tr(id / 10000) },
  { name: 'id/10000%100', f: (id) => tr(id / 10000) % 100 },
  { name: 'id', f: (id) => id },
];

function octetSource(base: string, c: number): string {
  if (base === '') return String(c);
  if (c === 0) return `{${base}}`;
  return c > 0 ? `{${c}+${base}}` : `{${base}-${-c}}`;
}

export interface AddressFormulaProposal {
  /** In formula.ts's grammar: `10.{id/100}.{id%100}.0/24`. */
  source: string;
  prefix: number | null;
}

/** `a.b.c.d` or `a.b.c.d/nn`, as octets + prefix, or null. */
function splitAddress(v: string): { octets: number[]; prefix: number | null } | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/.exec(v);
  if (!m) return null;
  const octets = [m[1], m[2], m[3], m[4]].map(Number);
  if (octets.some((o) => o > 255)) return null;
  if ([m[1], m[2], m[3], m[4]].some((p) => p.length > 1 && p[0] === '0')) return null;
  const prefix = m[5] === undefined ? null : Number(m[5]);
  if (prefix !== null && prefix > 32) return null;
  return { octets, prefix };
}

export function findAddressFormula(
  values: readonly (string | null)[],
  facts: readonly SiteFacts[],
): FormulaFit<AddressFormulaProposal> | null {
  const parsed = values.map((v) => (v === null ? null : splitAddress(v)));
  const usable: number[] = [];
  for (let i = 0; i < values.length; i++) if (parsed[i] && facts[i].id !== null) usable.push(i);
  if (usable.length < 2) return null;

  // One prefix for the formula: the most common one.
  const prefixCount = new Map<string, number>();
  for (const i of usable) {
    const k = String(parsed[i]!.prefix);
    prefixCount.set(k, (prefixCount.get(k) ?? 0) + 1);
  }
  const prefixKey = [...prefixCount.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0][0];
  const prefix = prefixKey === 'null' ? null : Number(prefixKey);

  const octetSources: string[] = [];
  for (let k = 0; k < 4; k++) {
    let best: { source: string; count: number } | null = null;
    for (const base of OCTET_BASES) {
      const byC = new Map<number, number>();
      for (const i of usable) {
        const c = parsed[i]!.octets[k] - base.f(facts[i].id!);
        if (c < -255 || c > 255) continue;
        byC.set(c, (byC.get(c) ?? 0) + 1);
      }
      for (const [c, count] of [...byC.entries()].sort((a, b) => b[1] - a[1] || a[0] - b[0])) {
        if (base.name === '' && (c < 0 || c > 255)) continue;
        if (best === null || count > best.count) best = { source: octetSource(base.name, c), count };
        break;
      }
    }
    if (!best) return null;
    octetSources.push(best.source);
  }
  const source = octetSources.join('.') + (prefix === null ? '' : `/${prefix}`);
  const p = parseAddressFormula(source, { prefix: prefix === null ? 'forbidden' : 'required' });
  if (!p.ok || !formulaUsesId(p.formula)) return null;
  const fits: number[] = [];
  for (let i = 0; i < values.length; i++) {
    const id = facts[i].id;
    if (values[i] === null || id === null) continue;
    const r = renderAddressFormula(p.formula, id);
    if (r.ok && r.text === values[i]) fits.push(i);
  }
  if (fits.length < 2) return null;
  return { formula: { source, prefix }, fits };
}

/** The allocator's evaluation of an address formula for one site. */
export function evaluateAddressFormula(source: string, id: number | null): string | null {
  if (id === null) return null;
  // derived.ts's own rule: a '/' OUTSIDE the braces is the prefix.
  const outsideBraces = source.replace(/\{[^}]*\}/g, '');
  const p = parseAddressFormula(source, { prefix: outsideBraces.includes('/') ? 'required' : 'forbidden' });
  if (!p.ok) return null;
  const r = renderAddressFormula(p.formula, id);
  return r.ok ? r.text : null;
}

/** The allocator's evaluation of a login-grammar text pattern. */
export function evaluateTextPattern(pattern: TextPattern, f: SiteFacts): string | null {
  return renderSegments(pattern.segments, f);
}

// ============================================================================
// Addresses relative to the site LAN
// ============================================================================

export interface LanBlock { network: number; prefix: number; size: number; text: string }

export function lanBlockOf(cidr: string | null): LanBlock | null {
  if (!cidr) return null;
  const c = parseCidr(cidr);
  if (!c.ok) return null;
  return { network: c.cidr.network, prefix: c.cidr.prefix, size: c.cidr.size, text: cidr };
}

/** `10.1.2.7/24` -> the LAN `10.1.2.0/24` it sits in (host bits allowed). */
export function lanOfInterfaceAddress(v: string): string | null {
  const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(v);
  if (!m) return null;
  const addr = parseIpv4(m[1]);
  const prefix = Number(m[2]);
  if (addr === null || prefix > 30 || prefix < 8) return null;
  const size = 2 ** (32 - prefix);
  const network = addr - (addr % size);
  return `${formatIpv4(network)}/${prefix}`;
}

/**
 * One component of a value expressed against the site LAN:
 *   'lan'      the block itself (`lan_subnet`)
 *   'network'  its first address (`lan_subnet | network`)
 *   'host'     `lan_subnet | cidrHost(n)` (n < 0 counts back from the end,
 *              -1 being the broadcast — the worker's and derived.ts's rule)
 *   'prefix'   the prefix length
 */
export type LanPart =
  | { kind: 'lan' }
  | { kind: 'network' }
  | { kind: 'host'; index: number }
  | { kind: 'prefix' }
  | { kind: 'lit'; text: string };

/** A value as LanParts, using the SAME template at every fitting site. */
export interface LanRelation { parts: LanPart[]; source: string }

function hostIndexes(addr: number, lan: LanBlock): { pos: number; neg: number } | null {
  if (addr < lan.network || addr > cidrLast({ network: lan.network, prefix: lan.prefix, size: lan.size })) return null;
  const pos = addr - lan.network;
  return { pos, neg: pos - lan.size };
}

/** Candidate relations of `v` to `lan` (several: host 1 = negative -254…). */
/**
 * Candidate relations of `v` to `lan`: the value itself as an address, a
 * block or a range of the LAN — or, failing that, ONE address embedded in a
 * longer value (`my-id=address:10.7.56.1`, `comment="GW 10.7.56.1"`), the rest
 * kept as literal text that must then be the same at every fitting site.
 */
function relationsOf(v: string, lan: LanBlock): LanPart[][] {
  const direct = directRelationsOf(v, lan);
  if (direct.length > 0) return direct;
  const out: LanPart[][] = [];
  const re = /(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2}|-\d{1,3}(?:\.\d{1,3}){3})?(?![\d.])/g;
  let m: RegExpExecArray | null;
  let seen = 0;
  while ((m = re.exec(v)) !== null && seen < 3) {
    seen++;
    const before = v.slice(0, m.index);
    const after = v.slice(m.index + m[0].length);
    for (const parts of directRelationsOf(m[0], lan)) {
      out.push([
        ...(before ? [{ kind: 'lit' as const, text: before }] : []),
        ...parts,
        ...(after ? [{ kind: 'lit' as const, text: after }] : []),
      ]);
    }
  }
  return out;
}

function directRelationsOf(v: string, lan: LanBlock): LanPart[][] {
  if (v === lan.text) return [[{ kind: 'lan' }]];
  const range = /^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$/.exec(v);
  if (range) {
    const a = parseIpv4(range[1]);
    const b = parseIpv4(range[2]);
    if (a === null || b === null) return [];
    const ia = hostIndexes(a, lan);
    const ib = hostIndexes(b, lan);
    if (!ia || !ib) return [];
    const out: LanPart[][] = [];
    for (const x of [ia.pos, ia.neg]) {
      for (const y of [ib.pos, ib.neg]) {
        out.push([{ kind: 'host', index: x }, { kind: 'lit', text: '-' }, { kind: 'host', index: y }]);
      }
    }
    return out;
  }
  const cidr = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(v);
  if (cidr) {
    const a = parseIpv4(cidr[1]);
    if (a === null) return [];
    const ia = hostIndexes(a, lan);
    if (!ia) return [];
    const prefixPart: LanPart = Number(cidr[2]) === lan.prefix
      ? { kind: 'prefix' }
      : { kind: 'lit', text: cidr[2] };
    if (ia.pos === 0) return [[{ kind: 'network' }, { kind: 'lit', text: '/' }, prefixPart]];
    return [ia.pos, ia.neg].map((x) => [{ kind: 'host', index: x }, { kind: 'lit', text: '/' }, prefixPart]);
  }
  const a = parseIpv4(v);
  if (a === null) return [];
  const ia = hostIndexes(a, lan);
  if (!ia) return [];
  if (ia.pos === 0) return [[{ kind: 'network' }]];
  return [[{ kind: 'host', index: ia.pos }], [{ kind: 'host', index: ia.neg }]];
}

function lanPartsSource(parts: readonly LanPart[]): string {
  return parts.map((p) => {
    switch (p.kind) {
      case 'lan': return 'lan_subnet';
      case 'network': return 'network(lan_subnet)';
      case 'host': return `cidrHost(lan_subnet, ${p.index})`;
      case 'prefix': return 'prefixLen(lan_subnet)';
      case 'lit': return p.text;
    }
  }).join('');
}

/** Evaluates a relation for one LAN, exactly as the worker's filters do. */
export function evaluateLanParts(parts: readonly LanPart[], lan: LanBlock): string | null {
  let out = '';
  for (const p of parts) {
    switch (p.kind) {
      case 'lan': out += lan.text; break;
      case 'network': out += formatIpv4(lan.network); break;
      case 'prefix': out += String(lan.prefix); break;
      case 'lit': out += p.text; break;
      case 'host': {
        const i = p.index < 0 ? lan.size + p.index : p.index;
        if (i < 0 || i >= lan.size) return null;
        out += formatIpv4(lan.network + i);
        break;
      }
    }
  }
  return out;
}

/** The relation to the LAN that reproduces the most sites, or null. A
 *  relation that is only `lit` parts is not one (it is a constant). */
export function findLanRelation(
  values: readonly (string | null)[],
  lans: readonly (LanBlock | null)[],
): FormulaFit<LanRelation> | null {
  const tried = new Set<string>();
  let best: FormulaFit<LanRelation> | null = null;
  let bestCost = Number.POSITIVE_INFINITY;
  for (let s = 0; s < values.length && tried.size < 32; s++) {
    const v = values[s];
    const lan = lans[s];
    if (v === null || lan === null) continue;
    for (const parts of relationsOf(v, lan)) {
      if (parts.every((p) => p.kind === 'lit')) continue;
      const source = lanPartsSource(parts);
      if (tried.has(source)) continue;
      tried.add(source);
      const fits: number[] = [];
      for (let i = 0; i < values.length; i++) {
        const l = lans[i];
        if (values[i] === null || l === null) continue;
        if (evaluateLanParts(parts, l) === values[i]) fits.push(i);
      }
      // Equal fits: the smaller index wins — `cidrHost(-2)` over `cidrHost(254)`
      // (the last usable host whatever the LAN size), `cidrHost(10)` over
      // `cidrHost(-246)`.
      const cost = parts.reduce((a, p) => a + (p.kind === 'host' ? Math.abs(p.index) : 0), 0);
      if (best === null || fits.length > best.fits.length || (fits.length === best.fits.length && cost < bestCost)) {
        best = { formula: { parts, source }, fits };
        bestCost = cost;
      }
    }
  }
  return best && best.fits.length >= 2 ? best : null;
}
