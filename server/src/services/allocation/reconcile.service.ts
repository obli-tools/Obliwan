import { instanceDomainError, MASTER_TENANT_ID, type PppDuplicateSession } from '@obliwan/shared';
import type { Knex } from 'knex';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { createSiteSchema } from '../../validators/site.schema';
import { createSite } from '../fleet/site.service';
import { buildXlsx, isoDateIn, type XlsxColumn, type XlsxValue } from '../fleet/xlsx';
import { readPppActive, refreshSecretInventory, type SecretInventoryResult } from '../fleet/concentratorDiscovery.service';
import { readActiveReads, readRecordedDuplicates, recordActiveRead } from '../fleet/pppDuplicates.service';
import { readInstanceDomain } from './allocator';
import { AllocationError, assertId, isPgError } from './errors';
import { PG_INT_MAX, cidrContains, parseCidr, parseIpv4, type Cidr } from './policy';
import {
  normalizeCountry,
  parseLoginTemplate,
  renderPppLogin,
  siteNumber,
  siteSlug,
  type LoginPlaceholder,
  type LoginTemplate,
} from './pppIdentity';
import { seedFreshness, trustedConcentrators, type SeedFreshness } from './seed';

/**
 * reconcile.service.ts — the CHR <-> sites reconciliation of ONE tenant.
 *
 * Asked before a few hundred stores that are already live are entered for a
 * tenant: which L2TP accounts on the concentrator are this tenant's and have NO
 * site (an ORPHAN — a store missing from the import, or a closed one), and
 * which sites match NO account although their store may be live. The second is
 * the costly one: the login template and the stored code disagree (a country
 * prefix, leading zeros), so the allocator cannot ADOPT the deployed account,
 * hands the site a NEW login and address, and the concentrator job later writes
 * a SECOND account for a store that already has one.
 *
 * ┌─ READ-ONLY ──────────────────────────────────────────────────────────────┐
 * │ `reconcileTenant` runs in one REPEATABLE READ READ ONLY transaction, so  │
 * │ PostgreSQL itself refuses a write inside it, and it dials nothing. It    │
 * │ reads what was RECORDED: the secret inventory (`concentrator_ppp_secrets`│
 * │ and `concentrator_secret_reads`, written by the discovery scan and by    │
 * │ the allocator's re-read) and the sessions presence keeps                 │
 * │ (`ppp_sessions`). It is exactly as current as those — the report says    │
 * │ when each CHR was last read, and what presence recorded for it. Two      │
 * │ writes live in this file, each its own explicit gesture and neither      │
 * │ called by the reconciliation: `rereadConcentratorInventory` (the         │
 * │ allocator's own /ppp/secret re-read, plus one /ppp/active read recorded  │
 * │ for the duplicated logins; `rereadForTenant` is the same read on the     │
 * │ caller's own tenant's CHRs) and `createSiteForTenant` (one `sites` row,  │
 * │ nothing allocated). The duplicated logins (a login holding several live │
 * │ sessions, pppDuplicates.service.ts) are read as RECORDED too.            │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THREE READERS OF ONE REPORT ────────────────────────────────────────────┐
 * │ - the platform admin's screen (allocation.routes.ts, the tenant a path   │
 * │   parameter): `reconcileTenant`, whole;                                  │
 * │ - the site import's dry run: `classifyProposedSites` lays the file's     │
 * │   rows over the stored sites and builds the SAME report, so a row is     │
 * │   "takes over <login>", "new" or "suspect" by exactly the rules a site   │
 * │   is — one classifier, not a second one free to disagree. It reads the   │
 * │   last recorded inventory and dials nothing;                             │
 * │ - a tenant user holding RECONCILE_READ (reconcile.routes.ts, the tenant  │
 * │   the session's): `tenantReconcileView`, refused when the template names │
 * │   no tenant and REDACTED otherwise (`redactReport` says what is kept).   │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHICH ACCOUNTS ARE THIS TENANT'S ───────────────────────────────────────┐
 * │ Those its login template could have produced. `deriveLoginMatcher` turns │
 * │ the template into an anchored, case-insensitive pattern — the tenant     │
 * │ slug and the installation domain substituted, one capture per site       │
 * │ placeholder, an optional {site.country} taking ONE adjacent "." or "_"   │
 * │ with it exactly as the renderer drops it — and `readLogin` then          │
 * │ RE-RENDERS what the pattern captured and keeps the name only if the      │
 * │ template gives that name back. The pattern proposes, the renderer        │
 * │ decides: "0042" is not a {site.id} login (the renderer writes 42), so a  │
 * │ zero-padded account under a {site.id} template is not counted as one.    │
 * │                                                                          │
 * │ An account the pattern does not read is not listed as this tenant's      │
 * │ orphan. An account that is read is still NOT this tenant's when it is    │
 * │ held by another tenant's allocation or device, or when another tenant    │
 * │ could have produced it too — that tenant's own template, or, for a       │
 * │ tenant with no policy yet, THIS template under that tenant's slug        │
 * │ ("{site.code}-{tenant.slug}" reads "0042-big-acme" as acme's code        │
 * │ "0042-big" and as big-acme's code "0042"). Such an account is counted    │
 * │ and never listed as an orphan, an off-pattern account or a near-match:   │
 * │ the screen must not hand one customer's store to another. One exception: │
 * │ a router of THIS tenant dialling the account outranks "another template  │
 * │ could have produced it" (not "another tenant holds it") — it is then     │
 * │ listed, off-pattern or orphan, like any account of this tenant.          │
 * │                                                                          │
 * │ A site whose OWN computed login is an excluded account is still matched  │
 * │ to it, with the blocker `otherTenant` when another tenant holds it: that │
 * │ name is the site's login, not a discovery.                               │
 * │                                                                          │
 * │ A template that names no tenant ("{site.code}.customers.example")        │
 * │ proves nothing about ownership: on a CHR several customers share, it     │
 * │ reads theirs as well. The report says so (`pattern.namesTenant`) and     │
 * │ still lists the orphans; the screen asks before creating a site.         │
 * │                                                                          │
 * │ The {site.code} capture takes letters, digits, "_" and "-" but NOT ".":  │
 * │ logins are dot-separated, and a code capture that spans dots would read  │
 * │ "0042.acme.customers.example" as a {site.code}.customers.example login   │
 * │ with code "0042.acme". The price: an orphan whose code itself holds a    │
 * │ dot is not read back. A SITE whose code holds one is unaffected: sites   │
 * │ are matched by rendering their login, never through the pattern.         │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHEN THE TEMPLATE DOES NOT DESCRIBE THE CHR ────────────────────────────┐
 * │ A template whose FIXED part is wrong (another slug spelling, another     │
 * │ domain, a missing "fr_") reads none of the live accounts: every site     │
 * │ then looks new, and no orphan exists. Three things keep that visible:    │
 * │   - OFF-PATTERN accounts: those carrying the template's fixed suffix (or │
 * │     prefix) when it names the tenant, those whose name contains the      │
 * │     tenant slug (three characters or more), and those a router of this   │
 * │     tenant dials. They are searched for near-matches, never offered as   │
 * │     orphans;                                                             │
 * │   - UNEXPLAINED accounts: on the CHRs read, those no tenant's template,  │
 * │     allocation or device accounts for — counted, with how many are       │
 * │     online, and listed;                                                  │
 * │   - the screen warns when no site matched while off-pattern accounts     │
 * │     exist or unexplained accounts are online.                            │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ NEAR-MATCHES: WHY A SITE IS "SUSPECT" ──────────────────────────────────┐
 * │ A site whose login is on no CHR account is NEW (normal) unless an        │
 * │ unclaimed account of this tenant names the same store differently:       │
 * │   country   the template's {site.country} reads differently (a site      │
 * │             without a country, an account "fr_0042...", or the reverse); │
 * │   prefix    a two-letter prefix before a digit on one side only          │
 * │             ("fr_0042" / "0042", "FR0042" / "0042");                     │
 * │   zeros     the same numbers once leading zeros are dropped ("42" /      │
 * │             "0042");                                                     │
 * │   separator the same letters and digits, separated differently           │
 * │             ("FR-0042" / "fr_0042" / "FR0042");                          │
 * │   name      {site.slug} differs while the code agrees;                   │
 * │   template  the site's code (or a near spelling of it) is one dot-       │
 * │             separated label of an account that contains the tenant slug  │
 * │             but whose fixed part the template does not produce;          │
 * │   device    a router of THIS site is bound to that account (its          │
 * │             ppp_username), whatever the account's shape.                 │
 * │ Case alone is never a reason: logins are compared without regard to      │
 * │ case, like the allocator, so a case difference is a MATCH (noted         │
 * │ `caseDiffers`), and the allocator adopts the CHR's spelling.             │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ "ADOPTABLE": THE ALLOCATOR'S RULES, ON THE SAME RECORDED STATE ─────────┐
 * │ For a matched site not yet allocated, and for a site that would be       │
 * │ created from an orphan, `judgeAdoption` applies the refusals of the      │
 * │ allocator's adoption (policy.ts `adoptDeclared`), restated over the same │
 * │ tables and the same trusted CHRs (seed.ts): case variants                │
 * │ (ADOPT_AMBIGUOUS), the login's other holders (LOGIN_TAKEN), a secret     │
 * │ with no IPv4 remote-address (ADOPT_NO_ADDRESS), that address held by     │
 * │ anybody but the account itself or inside a site's LAN (TUNNEL_IP_TAKEN), │
 * │ inside another tenant's tunnel pool (ADOPT_FOREIGN_POOL), a profile an   │
 * │ allocation cannot store (ADOPT_PROFILE_INVALID). It is a RESTATEMENT,    │
 * │ and the harness holds it to the allocator's real verdict scenario by     │
 * │ scenario. What it does not judge: an inventory the allocator would       │
 * │ re-read first (the report shows each CHR's read time), and every refusal │
 * │ that is not adoption's — the system identity, the LAN, the derived       │
 * │ values, the shared password. The allocation preview stays the verdict.   │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

// ============================================================================
// The login template, read backwards
// ============================================================================

export type SiteCapture = 'code' | 'id' | 'slug' | 'country';

const CAPTURE_OF: Partial<Record<LoginPlaceholder, SiteCapture>> = {
  'site.code': 'code',
  'site.id': 'id',
  'site.slug': 'slug',
  'site.country': 'country',
};

/** See the box above for why the code class has no ".". */
const CAPTURE_CLASS: Record<SiteCapture, string> = {
  code: '[A-Za-z0-9_-]+',
  id: '[0-9]+',
  slug: '[A-Za-z0-9-]+',
  country: '[A-Za-z]{2}',
};

/** The separators an absent {site.country} takes with it (pppIdentity.ts). */
const COUNTRY_SEPARATORS = ['.', '_'];
const LOGIN_TEXT_RE = /^[A-Za-z0-9._-]+$/;
/** A slug shorter than this is not searched for inside names: "fr" or "ab"
 *  would be found in half the CHR. */
const SLUG_SEARCH_MIN = 3;

export interface MatcherContext {
  tenantSlug: string;
  /** '' when the installation has none. */
  instanceDomain: string;
}

export interface LoginMatcher {
  template: LoginTemplate;
  ctx: MatcherContext;
  /** The template with the tenant's fixed values substituted, e.g.
   *  "{site.country}_{site.code}.acme.customers.example". */
  display: string;
  regex: RegExp;
  /** The site placeholders the pattern reads back. */
  captures: SiteCapture[];
  /** The fixed text after the last (or before the first) site placeholder,
   *  when it names the tenant; null otherwise. Near-matches only. */
  anchor: { kind: 'suffix' | 'prefix'; text: string } | null;
  /** The template names the tenant somewhere: {tenant.slug}, or the slug
   *  spelled in a literal. When false, a name it reads may be any customer's
   *  on a shared CHR. */
  namesTenant: boolean;
}

export type MatcherDerivation =
  | { ok: true; matcher: LoginMatcher }
  | { ok: false; reason: 'LOGIN_INVALID' | 'INSTANCE_DOMAIN_MISSING' | 'INSTANCE_DOMAIN_INVALID'; message: string };

function escapeRegex(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * The pattern of every login `t` can render for a tenant whose slug and
 * installation domain are `ctx`. Refuses what the allocator would refuse for
 * every site of the tenant (no domain while the template uses it, a slug no
 * login can carry): no pattern can be read off a template no site can render.
 */
export function deriveLoginMatcher(t: LoginTemplate, ctx: MatcherContext): MatcherDerivation {
  const fixed = new Map<LoginPlaceholder, string>();
  if (t.uses.has('tenant.slug')) {
    if (!LOGIN_TEXT_RE.test(ctx.tenantSlug)) {
      return {
        ok: false,
        reason: 'LOGIN_INVALID',
        message: `the tenant slug "${ctx.tenantSlug}" holds characters a PPP login cannot carry, so its login template renders no login at all.`,
      };
    }
    fixed.set('tenant.slug', ctx.tenantSlug);
  }
  if (t.uses.has('instance.domain')) {
    const d = ctx.instanceDomain.trim();
    if (d === '') {
      return {
        ok: false,
        reason: 'INSTANCE_DOMAIN_MISSING',
        message:
          'the login template uses {instance.domain} and this installation has no domain set, so no login ' +
          'can be computed and no CHR account can be recognised. Set the installation domain first.',
      };
    }
    const err = instanceDomainError(d);
    if (err !== null) {
      return { ok: false, reason: 'INSTANCE_DOMAIN_INVALID', message: `the installation domain is invalid (${err}).` };
    }
    fixed.set('instance.domain', d);
  }

  const segs = t.segments;
  // An absent {site.country} drops the FOLLOWING separator when there is a
  // following segment (parseLoginTemplate guarantees it is a literal starting
  // with one), else the PRECEDING one — assembleLogin's rule, restated so the
  // separator becomes part of the optional group.
  const trimFirst = new Set<number>();
  const trimLast = new Set<number>();
  const countrySep = new Map<number, { side: 'after' | 'before'; sep: string }>();
  segs.forEach((s, i) => {
    if (s.kind !== 'placeholder' || s.name !== 'site.country') return;
    const after = segs[i + 1];
    const before = segs[i - 1];
    if (after && after.kind === 'literal' && COUNTRY_SEPARATORS.includes(after.text[0])) {
      countrySep.set(i, { side: 'after', sep: after.text[0] });
      trimFirst.add(i + 1);
    } else if (before && before.kind === 'literal' && COUNTRY_SEPARATORS.includes(before.text.slice(-1))) {
      countrySep.set(i, { side: 'before', sep: before.text.slice(-1) });
      trimLast.add(i - 1);
    }
  });

  let body = '';
  const named = new Set<SiteCapture>();
  segs.forEach((s, i) => {
    if (s.kind === 'literal') {
      let text = s.text;
      if (trimFirst.has(i)) text = text.slice(1);
      if (trimLast.has(i)) text = text.slice(0, -1);
      body += escapeRegex(text);
      return;
    }
    const value = fixed.get(s.name);
    if (value !== undefined) {
      body += escapeRegex(value);
      return;
    }
    const cap = CAPTURE_OF[s.name];
    if (cap === undefined) return; // every placeholder is fixed or a site capture
    // A placeholder named twice is captured unnamed the second time;
    // readLogin's re-render is what checks the two agree.
    const group = named.has(cap) ? `(?:${CAPTURE_CLASS[cap]})` : `(?<${cap}>${CAPTURE_CLASS[cap]})`;
    named.add(cap);
    if (cap !== 'country') {
      body += group;
      return;
    }
    const sep = countrySep.get(i);
    if (!sep) body += `(?:${group})?`;
    else if (sep.side === 'after') body += `(?:${group}${escapeRegex(sep.sep)})?`;
    else body += `(?:${escapeRegex(sep.sep)}${group})?`;
  });

  const display = segs
    .map((s) => (s.kind === 'literal' ? s.text : (fixed.get(s.name) ?? `{${s.name}}`)))
    .join('');

  // The anchor: fixed text on the far side of every site placeholder, kept
  // only when it NAMES the tenant (its slug placeholder, or the slug spelled
  // literally, three characters or more) — a suffix such as the installation
  // domain alone is shared by every tenant and would pull theirs in.
  const siteIdx = segs.flatMap((s, i) => (s.kind === 'placeholder' && CAPTURE_OF[s.name] !== undefined ? [i] : []));
  const textOf = (part: typeof segs): string =>
    part.map((s) => (s.kind === 'literal' ? s.text : (fixed.get(s.name) ?? ''))).join('');
  const slugLower = ctx.tenantSlug.toLowerCase();
  const literalNamesSlug = (part: typeof segs): boolean =>
    slugLower.length >= SLUG_SEARCH_MIN &&
    part.some((s) => s.kind === 'literal' && s.text.toLowerCase().includes(slugLower));
  const namesTenant = (part: typeof segs): boolean =>
    part.some((s) => s.kind === 'placeholder' && s.name === 'tenant.slug') || literalNamesSlug(part);
  let anchor: LoginMatcher['anchor'] = null;
  if (siteIdx.length > 0) {
    const suffix = segs.slice(siteIdx[siteIdx.length - 1] + 1);
    const prefix = segs.slice(0, siteIdx[0]);
    if (suffix.length > 0 && namesTenant(suffix)) anchor = { kind: 'suffix', text: textOf(suffix) };
    else if (prefix.length > 0 && namesTenant(prefix)) anchor = { kind: 'prefix', text: textOf(prefix) };
  }

  return {
    ok: true,
    matcher: {
      template: t,
      ctx: { tenantSlug: ctx.tenantSlug, instanceDomain: ctx.instanceDomain.trim() },
      display,
      regex: new RegExp(`^${body}$`, 'i'),
      captures: Array.from(named),
      anchor,
      namesTenant: namesTenant(segs),
    },
  };
}

export interface ParsedLogin {
  /** {site.code} as written in the account name. */
  code: string | null;
  /** {site.id}. */
  number: number | null;
  /** {site.slug}, lowercased. */
  slug: string | null;
  /** {site.country}, uppercased as `sites.country` stores it; null when the
   *  name carries none (or the template has none). */
  country: string | null;
}

/**
 * The site values behind `name` if the matcher's template could have produced
 * it for its tenant, else null. Case-insensitive, like the allocator's login
 * comparisons.
 */
export function readLogin(m: LoginMatcher, name: string): ParsedLogin | null {
  const r = m.regex.exec(name);
  if (!r) return null;
  const g = r.groups ?? {};
  const idDigits = g.id ?? null;
  const parsed: ParsedLogin = {
    code: g.code ?? null,
    number: idDigits === null ? null : siteNumber(idDigits),
    slug: g.slug === undefined ? null : g.slug.toLowerCase(),
    country: g.country === undefined ? null : g.country.toUpperCase(),
  };
  if (idDigits !== null && parsed.number === null) return null;
  const rendered = renderPppLogin(
    m.template,
    {
      siteName: parsed.slug ?? 'x',
      siteCode: parsed.code ?? idDigits ?? '1',
      siteCountry: parsed.country,
      tenantSlug: m.ctx.tenantSlug,
      instanceDomain: m.ctx.instanceDomain,
    },
    `"${name}"`,
  );
  if (!rendered.ok || rendered.login.toLowerCase() !== name.toLowerCase()) return null;
  return parsed;
}

/** The part of `name` outside the anchor, or null when `name` does not carry
 *  it (case-insensitive) or carries nothing else. */
function outsideAnchor(anchor: NonNullable<LoginMatcher['anchor']>, name: string): string | null {
  const a = anchor.text.toLowerCase();
  const n = name.toLowerCase();
  if (n.length <= a.length) return null;
  if (anchor.kind === 'suffix') return n.endsWith(a) ? name.slice(0, name.length - a.length) : null;
  return n.startsWith(a) ? name.slice(a.length) : null;
}

// ============================================================================
// Near-matches
// ============================================================================

export type NearReason = 'country' | 'prefix' | 'zeros' | 'separator' | 'name' | 'template' | 'device';

/** Lowercased, every run of digits without its leading zeros ("0042" -> "42",
 *  "fr_007" -> "fr_7", "000" -> "0"). */
function zeroless(text: string): string {
  return text.toLowerCase().replace(/[0-9]+/g, (d) => d.replace(/^0+(?=[0-9])/, ''));
}

/** The runs of letters and of digits, in order: "FR-0042" and "fr0042" are
 *  both ["fr", "0042"]; "10-2" and "1-02" are not the same. */
function alnumRuns(lower: string): string[] {
  return lower.match(/[a-z]+|[0-9]+/g) ?? [];
}

/** Two letters, then at most one separator, then a digit: "fr_0042", "fr0042". */
const LETTER_PREFIX_RE = /^[a-z]{2}[._-]?(?=[0-9])/;

function stripLetterPrefix(lower: string): string | null {
  const m = LETTER_PREFIX_RE.exec(lower);
  return m ? lower.slice(m[0].length) : null;
}

/**
 * How two spellings of a store's identifier differ, when they name the same
 * store; null when they are equal (case aside) or name different stores.
 * Pure. Letters are never dropped from both sides: "LY01" and "PA01" are two
 * stores, not one store spelled twice — a two-letter prefix is stripped from
 * ONE side only, and the separator rule keeps every letter.
 */
export function nearReasons(siteSide: string, accountSide: string): NearReason[] | null {
  const a = siteSide.toLowerCase();
  const b = accountSide.toLowerCase();
  if (a === b) return null;
  if (zeroless(a) === zeroless(b)) return ['zeros'];
  const ra = alnumRuns(a);
  const rb = alnumRuns(b);
  if (ra.length > 0 && ra.join('|') === rb.join('|')) return ['separator'];
  if (ra.length > 0 && ra.map(zeroless).join('|') === rb.map(zeroless).join('|')) return ['separator', 'zeros'];
  const sa = stripLetterPrefix(a);
  const sb = stripLetterPrefix(b);
  const viaPrefix = (stripped: string, other: string): NearReason[] | null => {
    if (stripped === other) return ['prefix'];
    if (zeroless(stripped) === zeroless(other)) return ['prefix', 'zeros'];
    return null;
  };
  if (sa !== null && sb === null) return viaPrefix(sa, b);
  if (sb !== null && sa === null) return viaPrefix(sb, a);
  return null;
}

interface SiteFactsLite {
  id: number;
  code: string;
  name: string;
  country: string | null;
}

/** Near-match between a site and an account the template DOES produce,
 *  compared field by field. */
function parsedNear(site: SiteFactsLite, p: ParsedLogin, uses: ReadonlySet<LoginPlaceholder>): NearReason[] | null {
  const reasons = new Set<NearReason>();
  let identified = false;
  if (uses.has('site.code')) {
    identified = true;
    if (p.code === null) return null;
    if (p.code.toLowerCase() !== site.code.toLowerCase()) {
      const r = nearReasons(site.code, p.code);
      if (!r) return null;
      for (const x of r) reasons.add(x);
    }
  }
  if (uses.has('site.id')) {
    identified = true;
    const n = siteNumber(site.code);
    if (n === null || p.number === null || n !== p.number) return null;
  }
  if (uses.has('site.slug')) {
    const slug = siteSlug(site.name);
    if (!identified) {
      if (p.slug === null || p.slug !== slug) return null;
    } else if (p.slug !== null && p.slug !== slug) {
      reasons.add('name');
    }
  }
  if (uses.has('site.country')) {
    const a = site.country === null ? null : site.country.toLowerCase();
    const b = p.country === null ? null : p.country.toLowerCase();
    if (a !== b) reasons.add('country');
  }
  return reasons.size > 0 ? Array.from(reasons) : null;
}

/** Near-match between a site and an account whose FIXED part the template
 *  does not produce: the site's code (or a near spelling of it) is one of the
 *  account's dot-separated labels. */
function labelNear(site: SiteFactsLite, accountName: string): NearReason[] | null {
  const code = site.code.toLowerCase();
  for (const label of accountName.toLowerCase().split('.')) {
    if (label === '') continue;
    if (label === code) return ['template'];
    const r = nearReasons(code, label);
    if (r) return [...r, 'template'];
  }
  return null;
}

// ============================================================================
// The report
// ============================================================================

export type MatchStatus = 'allocated' | 'adopted' | 'adoptable';

/**
 * What, restated from the allocator's adoption (see the "ADOPTABLE" box),
 * would stop it adopting the account. The engine refusal each one stands for
 * is in brackets.
 */
export type AdoptBlocker =
  | 'ambiguous' // several secrets of this name without regard to case on the CHR [ADOPT_AMBIGUOUS]
  | 'noAddress' // the secret declares no IPv4 remote-address (a dynamic secret) [ADOPT_NO_ADDRESS]
  | 'sessionOnly' // a live session with no /ppp/secret entry (RADIUS?): nothing to adopt [LOGIN_TAKEN]
  | 'otherTenant' // the login is held by another tenant's allocation or device [LOGIN_TAKEN]
  | 'sharedLogin' // another site of this tenant computes or holds the same login [LOGIN_TAKEN]
  | 'loginTaken' // another holder of the login: a router of another site, another CHR's account [LOGIN_TAKEN]
  | 'addressTaken' // the remote-address is held by another site, router, session or secret [TUNNEL_IP_TAKEN]
  | 'addressInLan' // the remote-address lies inside a site's LAN subnet [TUNNEL_IP_TAKEN]
  | 'foreignPool' // the remote-address lies in another tenant's tunnel pool [ADOPT_FOREIGN_POOL]
  | 'profileInvalid' // the secret's profile cannot be stored by an allocation [ADOPT_PROFILE_INVALID]
  | 'otherConcentrator'; // on a CHR other than the one the tenant's policy names (adoption reads only that one)

/** Who holds what a blocker is about. */
export interface BlockingHolder {
  kind: 'site' | 'lan' | 'device' | 'session' | 'secret';
  /** site / lan: the site's code; device: its name; session / secret: the
   *  account name. */
  name: string;
  /** lan: the subnet; session / secret: the CHR's device id; null otherwise. */
  detail: string | null;
  /** The holder's tenant when recorded (a CHR secret records none). */
  tenantSlug: string | null;
}

export type AccountNote = 'disabled' | 'caseDiffers' | 'addressDiffers';

export interface ChrAccountView {
  concentratorId: number;
  name: string;
  /** false: an open session with no /ppp/secret entry. */
  declared: boolean;
  /** As the SECRET declares it (host text), never the session's. */
  remoteAddress: string | null;
  profile: string | null;
  /** null when not declared. */
  disabled: boolean | null;
  firstSeenAt: string | null;
  /** The last read of the CHR that listed this secret. */
  lastReadAt: string | null;
  session: {
    /** An open `ppp_sessions` row: the router is connected, as presence last
     *  recorded it (see `ConcentratorInventory.presence` for how current that
     *  record is). */
    up: boolean;
    /** `started_at` of the open row: when PRESENCE FIRST SAW the session —
     *  pppPresence stamps its own clock then, not the CHR's uptime — so for a
     *  router connected before monitoring began it is the first sighting, not
     *  the dial-up. */
    since: string | null;
    address: string | null;
    /** When the last closed session ended; null when none is recorded. */
    lastEndedAt: string | null;
  };
  /** A device of THIS tenant whose ppp_username is this account. */
  device: { id: number; name: string; siteId: number | null } | null;
}

export interface ReconcileSiteRef {
  siteId: number;
  code: string;
  name: string;
  country: string | null;
}

export interface AllocationRef {
  source: 'allocated' | 'adopted_chr' | null;
  state: string;
  tunnelIp: string;
  concentratorId: number;
}

export interface MatchedRow extends ReconcileSiteRef {
  /** The allocated login, or the one the policy computes. */
  login: string;
  /** 'adoptable': not allocated yet, and the account is this site's login —
   *  whether the allocator would actually adopt it is `blockers` (empty = no
   *  refusal this report can see, see the "ADOPTABLE" box). */
  status: MatchStatus;
  account: ChrAccountView;
  /** Other names on the same CHR equal to `login` without regard to case. */
  variants: string[];
  allocation: AllocationRef | null;
  /** 'adoptable' rows only. */
  blockers: AdoptBlocker[];
  /** Who holds the address or the login a blocker is about. */
  holders: BlockingHolder[];
  notes: AccountNote[];
}

export type NearSite = ReconcileSiteRef & { reasons: NearReason[] };

export interface OrphanRow {
  account: ChrAccountView;
  /** The site values read back from the account name. */
  parsed: ParsedLogin;
  /** What a site created for this account needs: `name` is set only when the
   *  template uses {site.slug} (the name then decides the login). */
  prefill: { code: string | null; name: string | null; country: string | null };
  blockers: AdoptBlocker[];
  holders: BlockingHolder[];
  /** A site created with `prefill` renders exactly this name, on the policy's
   *  CHR, and nothing in `blockers`: as far as the restated adoption rules
   *  see, its allocation would adopt this account. Not a promise — see the
   *  "ADOPTABLE" box for what is not judged. */
  creationAdopts: boolean;
  nearSites: NearSite[];
}

export interface NearMatch {
  account: ChrAccountView;
  /** null when the template cannot produce the account's name. */
  parsed: ParsedLogin | null;
  reasons: NearReason[];
}

export interface SiteOnlyRow extends ReconcileSiteRef {
  kind: 'new' | 'suspect';
  login: string | null;
  /** The renderer's refusal (an English sentence, like the preview's). */
  loginError: { reason: string; message: string } | null;
  allocation: AllocationRef | null;
  nearMatches: NearMatch[];
}

/** Why an account the template cannot produce is still listed. */
export type OffPatternVia = 'anchor' | 'slug' | 'device';

export interface OffPatternRow {
  account: ChrAccountView;
  via: OffPatternVia;
  nearSites: NearSite[];
}

export interface ConcentratorInventory {
  concentratorId: number;
  name: string | null;
  /** The concentrator the tenant's policy names (the one adoption reads). */
  policy: boolean;
  readAt: string | null;
  secretCount: number | null;
  freshness: SeedFreshness;
  /** What presence has recorded for this CHR — the only evidence that the
   *  "online" column is being kept. No session ever recorded means presence
   *  may not be watching this CHR at all: "never seen online" proves nothing
   *  there. */
  presence: {
    sessionsRecorded: number;
    openSessions: number;
    /** The latest session start or end recorded. */
    lastEventAt: string | null;
    /** Set when the CHR's latest reachability verdict is
     *  CONCENTRATOR_DEGRADED (its RouterOS API stopped answering presence or
     *  the health check). Presence closes no session on that verdict, so the
     *  open sessions are the ones it last saw before. */
    degradedSince: string | null;
  };
  /** The last SUCCESSFUL `/ppp/active` read recorded for this CHR (presence's
   *  sweep, the re-read): the evidence the `duplicates` list is as current as.
   *  null: never recorded — "no duplicate" then proves nothing. */
  activeRead: { readAt: string; sessionCount: number; duplicateCount: number } | null;
}

/**
 * A login of this report holding SEVERAL live sessions at once on its CHR, as
 * the last recorded `/ppp/active` read showed it (pppDuplicates.service.ts):
 * its tunnel address reaches whichever session the CHR routes to, so the
 * attach and the tunnel jobs refuse it. Listed so the operator finds every
 * such store at once.
 */
export interface DuplicateSessionsRow {
  concentratorId: number;
  /** The account's name, as the report lists it. */
  account: string;
  /** Where the report lists the account. */
  group: 'matched' | 'orphan' | 'offPattern' | 'unexplained';
  /** offPattern rows: why it is listed. */
  via: OffPatternVia | null;
  /** matched rows: the site. */
  site: ReconcileSiteRef | null;
  /** A device of THIS tenant dialling the account. */
  device: ChrAccountView['device'];
  sessions: PppDuplicateSession[];
  firstSeenAt: string;
  observedAt: string;
}

export interface ReconcileReport {
  tenantId: number;
  tenantSlug: string;
  tenantName: string;
  generatedAt: string;
  loginTemplate: string;
  policyConcentratorId: number;
  pattern: {
    display: string;
    regex: string;
    captures: SiteCapture[];
    anchor: { kind: 'suffix' | 'prefix'; text: string } | null;
    namesTenant: boolean;
  };
  inventory: ConcentratorInventory[];
  counts: {
    sites: number;
    matched: number;
    orphans: number;
    orphansOnline: number;
    siteOnly: number;
    siteOnlyNew: number;
    siteOnlySuspect: number;
    offPattern: number;
    /** Accounts of the CHRs read that no tenant accounts for. */
    unexplained: number;
    unexplainedOnline: number;
    /** Read as this tenant's, but held by another tenant's allocation or device. */
    excludedOtherTenant: number;
    /** Read as this tenant's, and produced by another tenant's template too. */
    excludedSharedPattern: number;
    /** Logins listed below holding several live sessions at once. */
    duplicates: number;
  };
  matched: MatchedRow[];
  orphans: OrphanRow[];
  siteOnly: SiteOnlyRow[];
  offPattern: OffPatternRow[];
  /** Online first. Not this tenant's as far as anything shows — listed so a
   *  template that misses the CHR's naming can be seen. */
  unexplained: ChrAccountView[];
  /** The accounts listed above (matched, orphan, off-pattern, unexplained)
   *  that hold several live sessions at once, by account name. */
  duplicates: DuplicateSessionsRow[];
}

interface SecretRow {
  concentrator_id: number;
  name: string;
  remote_address: string | null;
  profile: string | null;
  disabled: boolean;
  first_seen_at: Date | string;
  last_seen_at: Date | string;
}
interface OpenSessionRow {
  concentrator_id: number;
  ppp_username: string;
  tunnel_ip: string | null;
  started_at: Date | string;
}
interface ProvisioningRow {
  site_id: number;
  tenant_id: number;
  site_code: string;
  ppp_username: string;
  tunnel_ip: string;
  lan_subnet: string | null;
  concentrator_id: number;
  concentrator_state: string;
  source: 'allocated' | 'adopted_chr' | null;
}
interface DeviceRow {
  id: number;
  name: string;
  tenant_id: number;
  site_id: number | null;
  ppp_username: string | null;
  tunnel_ip: string | null;
}
interface PolicyRow {
  tenant_id: number;
  ppp_login_template: string;
  concentrator_id: number;
  tunnel_pool_id: number;
}

interface Account {
  view: ChrAccountView;
  lower: string;
  key: string;
  claimed: boolean;
  parsed: ParsedLogin | null;
  /** The part outside the anchor, when the name carries the anchor. */
  family: string | null;
  /** The name contains the tenant slug, and the template cannot produce it. */
  loose: boolean;
  excluded: boolean;
}

function iso(value: Date | string | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  return new Date(value).toISOString();
}

function keyOf(concentratorId: number, name: string): string {
  return `${concentratorId}|${name.toLowerCase()}`;
}

function isIpv4Host(text: string | null): text is string {
  return text !== null && parseIpv4(text) !== null;
}

function siteRef(s: SiteFactsLite): ReconcileSiteRef {
  return { siteId: s.id, code: s.code, name: s.name, country: s.country };
}

function bySiteCode(a: ReconcileSiteRef, b: ReconcileSiteRef): number {
  return a.code.localeCompare(b.code) || a.siteId - b.siteId;
}

function pushTo<K, V>(map: Map<K, V[]>, key: K, value: V): void {
  const list = map.get(key);
  if (list) list.push(value);
  else map.set(key, [value]);
}

// ============================================================================
// Adoption, restated (see the "ADOPTABLE" box)
// ============================================================================

/** policy.ts PPP_PROFILE_RE (not exported there): the alphabet migration 036
 *  admits for a stored profile. */
const PPP_PROFILE_RE = /^[A-Za-z0-9._-]{1,64}$/;

/** Everything `judgeAdoption` reads, indexed. CHR-sourced holders (secrets,
 *  sessions) are kept only for the CHRs the tenant's allocation trusts. */
interface HolderIndex {
  sitesByLogin: Map<string, ProvisioningRow[]>;
  sitesByAddress: Map<string, ProvisioningRow[]>;
  lans: Array<{ cidr: Cidr; row: ProvisioningRow }>;
  devicesByLogin: Map<string, DeviceRow[]>;
  devicesByAddress: Map<string, DeviceRow[]>;
  secretsByLogin: Map<string, Array<{ concentratorId: number; name: string }>>;
  secretsByAddress: Map<string, Array<{ concentratorId: number; name: string }>>;
  sessionsByLogin: Map<string, Array<{ concentratorId: number; name: string }>>;
  sessionsByAddress: Map<string, Array<{ concentratorId: number; name: string }>>;
  ownPool: Cidr | null;
  foreignPools: Cidr[];
  slugOf: Map<number, string>;
}

interface AdoptionCandidate {
  /** The account's own spelling. */
  name: string;
  concentratorId: number;
  declared: boolean;
  remoteAddress: string | null;
  profile: string | null;
  /** Accounts of that CHR equal to `name` without regard to case. */
  variants: number;
  /** The site adopting; null for a site still to be created. */
  siteId: number | null;
  /** Another site of this tenant computes the same login. */
  sharedBySites: boolean;
}

const IN_CHUNK = 500;

function chunks<T>(list: readonly T[]): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < list.length; i += IN_CHUNK) out.push(list.slice(i, i + IN_CHUNK));
  return out;
}

async function loadHolderIndex(
  q: Knex,
  tenantId: number,
  own: PolicyRow,
  allPolicies: readonly PolicyRow[],
  allProv: readonly ProvisioningRow[],
  devices: readonly DeviceRow[],
  slugOf: Map<number, string>,
  logins: readonly string[],
  addresses: readonly string[],
): Promise<HolderIndex> {
  const chrs = (await q('devices').where({ role: 'concentrator' }).select('id', 'tenant_id')) as Array<{
    id: number;
    tenant_id: number;
  }>;
  const trusted = trustedConcentrators(
    chrs.map((c) => ({ id: c.id, tenantId: c.tenant_id })),
    allPolicies.map((p) => p.concentrator_id),
    tenantId,
    MASTER_TENANT_ID,
  );

  const sitesByLogin = new Map<string, ProvisioningRow[]>();
  const sitesByAddress = new Map<string, ProvisioningRow[]>();
  const lans: HolderIndex['lans'] = [];
  for (const p of allProv) {
    pushTo(sitesByLogin, p.ppp_username.toLowerCase(), p);
    pushTo(sitesByAddress, p.tunnel_ip, p);
    if (p.lan_subnet !== null) {
      const c = parseCidr(p.lan_subnet);
      if (c.ok) lans.push({ cidr: c.cidr, row: p });
    }
  }
  const devicesByLogin = new Map<string, DeviceRow[]>();
  const devicesByAddress = new Map<string, DeviceRow[]>();
  for (const d of devices) {
    if (d.ppp_username !== null) pushTo(devicesByLogin, d.ppp_username.toLowerCase(), d);
    if (d.tunnel_ip !== null) pushTo(devicesByAddress, d.tunnel_ip, d);
  }

  const lowered = Array.from(new Set(logins.map((l) => l.toLowerCase())));
  const addrs = Array.from(new Set(addresses));
  const secretsByLogin: HolderIndex['secretsByLogin'] = new Map();
  const secretsByAddress: HolderIndex['secretsByAddress'] = new Map();
  const sessionsByLogin: HolderIndex['sessionsByLogin'] = new Map();
  const sessionsByAddress: HolderIndex['sessionsByAddress'] = new Map();
  for (const part of chunks(lowered)) {
    const marks = part.map(() => '?').join(', ');
    const secrets = (await q('concentrator_ppp_secrets')
      .whereNull('vanished_at')
      .whereRaw(`lower(name) IN (${marks})`, part)
      .select('concentrator_id', 'name')) as Array<{ concentrator_id: number; name: string }>;
    for (const s of secrets) {
      if (trusted.has(s.concentrator_id)) {
        pushTo(secretsByLogin, s.name.toLowerCase(), { concentratorId: s.concentrator_id, name: s.name });
      }
    }
    const sessions = (await q('ppp_sessions')
      .whereNull('ended_at')
      .whereRaw(`lower(ppp_username) IN (${marks})`, part)
      .select('concentrator_id', 'ppp_username')) as Array<{ concentrator_id: number; ppp_username: string }>;
    for (const s of sessions) {
      if (trusted.has(s.concentrator_id)) {
        pushTo(sessionsByLogin, s.ppp_username.toLowerCase(), { concentratorId: s.concentrator_id, name: s.ppp_username });
      }
    }
  }
  for (const part of chunks(addrs)) {
    const marks = part.map(() => '?').join(', ');
    // Both ends of a secret count, as for the allocator: a secret's
    // local-address is the CHR's own side of that tunnel.
    for (const column of ['remote_address', 'local_address'] as const) {
      const rows = (await q('concentrator_ppp_secrets')
        .whereNull('vanished_at')
        .whereRaw(`host(${column}) IN (${marks})`, part)
        .select('concentrator_id', 'name', q.raw(`host(${column}) AS address`))) as Array<{
        concentrator_id: number;
        name: string;
        address: string;
      }>;
      for (const r of rows) {
        if (trusted.has(r.concentrator_id)) pushTo(secretsByAddress, r.address, { concentratorId: r.concentrator_id, name: r.name });
      }
    }
    const sessions = (await q('ppp_sessions')
      .whereNull('ended_at')
      .whereRaw(`host(tunnel_ip) IN (${marks})`, part)
      .select('concentrator_id', 'ppp_username', q.raw('host(tunnel_ip) AS address'))) as Array<{
      concentrator_id: number;
      ppp_username: string;
      address: string;
    }>;
    for (const s of sessions) {
      if (trusted.has(s.concentrator_id)) {
        pushTo(sessionsByAddress, s.address, { concentratorId: s.concentrator_id, name: s.ppp_username });
      }
    }
  }

  // The tunnel pools: this policy's, and every one another tenant's policy
  // hands addresses from (raw policy rows, valid or not, like the allocator).
  const pools = (await q('address_pools').select('id', q.raw('"cidr"::text AS cidr'))) as Array<{ id: number; cidr: string }>;
  const poolCidr = new Map<number, Cidr>();
  for (const p of pools) {
    const c = parseCidr(p.cidr);
    if (c.ok) poolCidr.set(p.id, c.cidr);
  }
  const foreignIds = new Set(
    allPolicies.filter((p) => p.tenant_id !== tenantId && p.tunnel_pool_id !== own.tunnel_pool_id).map((p) => p.tunnel_pool_id),
  );
  const foreignPools = Array.from(foreignIds).flatMap((id) => {
    const c = poolCidr.get(id);
    return c ? [c] : [];
  });

  return {
    sitesByLogin,
    sitesByAddress,
    lans,
    devicesByLogin,
    devicesByAddress,
    secretsByLogin,
    secretsByAddress,
    sessionsByLogin,
    sessionsByAddress,
    ownPool: poolCidr.get(own.tunnel_pool_id) ?? null,
    foreignPools,
    slugOf,
  };
}

/**
 * The refusals the allocator's adoption (policy.ts `adoptDeclared`) would
 * raise for `c`, restated over `idx` — every one that applies, not only the
 * first the allocator would stop at, so the operator sees everything to fix
 * at once (the address rules need an address, on the policy's CHR, to judge).
 * "The adopted account itself"
 * is tolerated as a holder exactly as there: its secret and its session on
 * the policy's CHR under this login, and its router (a device of THIS tenant
 * carrying this login, bound to no site or to this one; or, recording no
 * login, bound to this very site).
 */
function judgeAdoption(
  c: AdoptionCandidate,
  idx: HolderIndex,
  tenantId: number,
  policyChr: number,
): { blockers: AdoptBlocker[]; holders: BlockingHolder[] } {
  const blockers = new Set<AdoptBlocker>();
  const holders = new Map<string, BlockingHolder>();
  const hold = (h: BlockingHolder): void => {
    holders.set(`${h.kind}|${h.name}|${h.detail ?? ''}`, h);
  };
  const key = c.name.toLowerCase();
  const same = (n: string | null): boolean => n !== null && n.toLowerCase() === key;
  const ownRouter = (d: DeviceRow): boolean => {
    if (d.tenant_id !== tenantId) return false;
    if (d.ppp_username !== null) return same(d.ppp_username) && (d.site_id === null || d.site_id === c.siteId);
    return c.siteId !== null && d.site_id === c.siteId;
  };
  const siteHolder = (p: ProvisioningRow): BlockingHolder => ({
    kind: 'site',
    name: p.site_code,
    detail: null,
    tenantSlug: idx.slugOf.get(p.tenant_id) ?? null,
  });
  const deviceHolder = (d: DeviceRow): BlockingHolder => ({
    kind: 'device',
    name: d.name,
    detail: null,
    tenantSlug: idx.slugOf.get(d.tenant_id) ?? null,
  });
  const chrHolder = (kind: 'session' | 'secret', s: { concentratorId: number; name: string }): BlockingHolder => ({
    kind,
    name: s.name,
    detail: String(s.concentratorId),
    tenantSlug: null,
  });
  const finish = (): { blockers: AdoptBlocker[]; holders: BlockingHolder[] } => ({
    blockers: Array.from(blockers),
    holders: Array.from(holders.values()),
  });

  if (c.concentratorId !== policyChr) blockers.add('otherConcentrator');
  if (c.variants > 1) blockers.add('ambiguous');
  if (c.sharedBySites) blockers.add('sharedLogin');

  // LOGIN_TAKEN: the login's holders other than the account itself.
  for (const p of idx.sitesByLogin.get(key) ?? []) {
    if (p.site_id === c.siteId) continue;
    blockers.add(p.tenant_id === tenantId ? 'sharedLogin' : 'otherTenant');
    hold(siteHolder(p));
  }
  for (const d of idx.devicesByLogin.get(key) ?? []) {
    if (ownRouter(d)) continue;
    blockers.add(d.tenant_id === tenantId ? 'loginTaken' : 'otherTenant');
    hold(deviceHolder(d));
  }
  for (const kind of ['secret', 'session'] as const) {
    const list = (kind === 'secret' ? idx.secretsByLogin : idx.sessionsByLogin).get(key) ?? [];
    for (const s of list) {
      // The policy's CHR is the account's own; the CHR the account was found
      // on, when another, is what `otherConcentrator` already says.
      if (s.concentratorId === policyChr || s.concentratorId === c.concentratorId) continue;
      blockers.add('loginTaken');
      hold(chrHolder(kind, s));
    }
  }
  // Adoption reads only the policy's CHR: an account elsewhere is not
  // adopted at all, so its address is nobody's business here.
  if (blockers.has('otherConcentrator')) return finish();

  if (!c.declared) {
    blockers.add('sessionOnly');
    return finish();
  }
  if (!isIpv4Host(c.remoteAddress)) {
    blockers.add('noAddress');
    return finish();
  }
  const address = c.remoteAddress;
  const host = parseIpv4(address) as number;

  // TUNNEL_IP_TAKEN: inside a site's LAN, or held by anybody but the account.
  for (const lan of idx.lans) {
    if (!cidrContains(lan.cidr, host)) continue;
    blockers.add('addressInLan');
    hold({
      kind: 'lan',
      name: lan.row.site_code,
      detail: lan.row.lan_subnet,
      tenantSlug: idx.slugOf.get(lan.row.tenant_id) ?? null,
    });
  }
  for (const p of idx.sitesByAddress.get(address) ?? []) {
    if (p.site_id === c.siteId) continue;
    blockers.add('addressTaken');
    hold(siteHolder(p));
  }
  for (const d of idx.devicesByAddress.get(address) ?? []) {
    if (ownRouter(d)) continue;
    blockers.add('addressTaken');
    hold(deviceHolder(d));
  }
  for (const kind of ['secret', 'session'] as const) {
    const list = (kind === 'secret' ? idx.secretsByAddress : idx.sessionsByAddress).get(address) ?? [];
    for (const s of list) {
      if (s.concentratorId === policyChr && same(s.name)) continue;
      blockers.add('addressTaken');
      hold(chrHolder(kind, s));
    }
  }
  // ADOPT_FOREIGN_POOL: tunnel pools never overlap (migration 036), so an
  // address inside this policy's own pool is in no other tenant's.
  const inOwn = idx.ownPool !== null && cidrContains(idx.ownPool, host);
  if (!inOwn && idx.foreignPools.some((p) => cidrContains(p, host))) blockers.add('foreignPool');
  if (c.profile !== null && !PPP_PROFILE_RE.test(c.profile)) blockers.add('profileInvalid');
  return finish();
}

// ============================================================================
// The reconciliation
// ============================================================================

/**
 * The reconciliation of `tenantId`. Read-only (see the header). Throws
 * AllocationError: TENANT_NOT_FOUND, NO_POLICY, INVALID_POLICY (a stored login
 * template that no longer parses), INSTANCE_DOMAIN_MISSING / _INVALID or
 * LOGIN_INVALID (no login of this tenant can be rendered, so none can be
 * recognised).
 */
export async function reconcileTenant(tenantId: number, nowMs: number = Date.now()): Promise<ReconcileReport> {
  assertId(tenantId, 'tenantId', PG_INT_MAX);
  return db.transaction(async (trx) => {
    await trx.raw('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
    return buildReport(trx, tenantId, nowMs);
  });
}

/** The id a proposed site to be CREATED carries inside the report: negative,
 *  so it can never equal a real `sites.id` (or a holder's `site_id`). */
function proposedSiteId(index: number): number {
  return -(index + 1);
}

/**
 * The tenant's stored sites with `proposed` laid over them: a proposed row
 * naming one of these sites replaces its name and country (the code is the
 * site's own — the caller found the site BY its code), any other row is added
 * as a site to be created, under `proposedSiteId`. A `siteId` that is not one
 * of this tenant's sites is treated as a creation, never as a reason to read
 * another tenant's site. An ALLOCATED site keeps its allocated login whatever
 * is laid over it (`buildReport` reads the login off the allocation).
 */
function overlayProposed(stored: SiteFactsLite[], proposed: readonly ProposedSite[]): {
  sites: SiteFactsLite[];
  idOf: Map<number, number>;
} {
  const idOf = new Map<number, number>();
  if (proposed.length === 0) return { sites: stored, idOf };
  const ownIds = new Set(stored.map((s) => s.id));
  const over = new Map<number, ProposedSite>();
  const sites = [...stored];
  proposed.forEach((p, i) => {
    if (p.siteId !== null && ownIds.has(p.siteId) && !over.has(p.siteId)) {
      over.set(p.siteId, p);
      idOf.set(p.ref, p.siteId);
      return;
    }
    const id = proposedSiteId(i);
    sites.push({ id, code: p.code, name: p.name, country: p.country });
    idOf.set(p.ref, id);
  });
  return {
    sites: sites.map((s) => {
      const p = over.get(s.id);
      return p ? { ...s, name: p.name, country: p.country } : s;
    }),
    idOf,
  };
}

async function buildReport(
  q: Knex,
  tenantId: number,
  nowMs: number,
  proposed: readonly ProposedSite[] = [],
  idOf: Map<number, number> = new Map(),
): Promise<ReconcileReport> {
  const tenants = (await q('tenants').select('id', 'slug', 'name')) as Array<{ id: number; slug: string; name: string }>;
  const tenant = tenants.find((t) => t.id === tenantId);
  if (!tenant) throw new AllocationError('TENANT_NOT_FOUND', `tenant ${tenantId} does not exist.`);
  const slugOf = new Map(tenants.map((t) => [t.id, t.slug]));
  const allPolicies = (await q('tenant_allocation_policies').select(
    'tenant_id',
    'ppp_login_template',
    'concentrator_id',
    'tunnel_pool_id',
  )) as PolicyRow[];
  const policyRow = allPolicies.find((p) => p.tenant_id === tenantId);
  if (!policyRow) {
    throw new AllocationError(
      'NO_POLICY',
      `tenant ${tenantId} has no allocation policy, so no login of its sites can be computed and no CHR ` +
        'account can be recognised as its own. Set its policy first.',
    );
  }
  const parsedTemplate = parseLoginTemplate(policyRow.ppp_login_template);
  if (!parsedTemplate.ok) {
    throw new AllocationError(
      'INVALID_POLICY',
      `the stored login template of tenant ${tenantId} no longer parses: ${parsedTemplate.error}`,
    );
  }
  const template = parsedTemplate.template;
  const instanceDomain = await readInstanceDomain(q);
  const ctx: MatcherContext = { tenantSlug: tenant.slug, instanceDomain };
  const derived = deriveLoginMatcher(template, ctx);
  if (!derived.ok) throw new AllocationError(derived.reason, `tenant ${tenantId}: ${derived.message}`);
  const matcher = derived.matcher;
  const policyChr = policyRow.concentrator_id;

  // What other tenants could have produced: each one's own template, and —
  // for a tenant with no policy yet — THIS template under its slug, when the
  // template carries the slug (without it, the same pattern would be read
  // twice and exclude everything).
  const otherMatchers: LoginMatcher[] = [];
  for (const o of allPolicies) {
    if (o.tenant_id === tenantId) continue;
    const pt = parseLoginTemplate(o.ppp_login_template);
    if (!pt.ok) continue;
    const d = deriveLoginMatcher(pt.template, { tenantSlug: slugOf.get(o.tenant_id) ?? '', instanceDomain });
    if (d.ok) otherMatchers.push(d.matcher);
  }
  if (template.uses.has('tenant.slug')) {
    const withPolicy = new Set(allPolicies.map((p) => p.tenant_id));
    for (const t of tenants) {
      if (t.id === tenantId || withPolicy.has(t.id)) continue;
      const d = deriveLoginMatcher(template, { tenantSlug: t.slug, instanceDomain });
      if (d.ok) otherMatchers.push(d.matcher);
    }
  }

  const stored = (await q('sites')
    .where({ tenant_id: tenantId })
    .orderBy('code')
    .select('id', 'code', 'name', 'country')) as SiteFactsLite[];
  const overlaid = overlayProposed(stored, proposed);
  const sites = overlaid.sites;
  for (const [ref, id] of overlaid.idOf) idOf.set(ref, id);
  const allProv = (await q('site_provisioning as p')
    .join('sites as s', 's.id', 'p.site_id')
    .select(
      'p.site_id',
      'p.tenant_id',
      's.code as site_code',
      'p.ppp_username',
      q.raw('host(p.tunnel_ip) AS tunnel_ip'),
      q.raw('p.lan_subnet::text AS lan_subnet'),
      'p.concentrator_id',
      'p.concentrator_state',
      'p.source',
    )) as ProvisioningRow[];
  const provisioning = allProv.filter((p) => p.tenant_id === tenantId);
  const provBySite = new Map(provisioning.map((p) => [p.site_id, p]));

  // The CHRs read: the policy's, and every CHR an allocation of this tenant
  // was frozen on (a site allocated before the policy moved stays there).
  const chrIds = Array.from(new Set([policyChr, ...provisioning.map((p) => p.concentrator_id)])).sort((a, b) => a - b);

  const chrRows = (await q('devices').whereIn('id', chrIds).select('id', 'name')) as Array<{ id: number; name: string }>;
  const reads = (await q('concentrator_secret_reads')
    .whereIn('concentrator_id', chrIds)
    .select('concentrator_id', 'read_at', 'secret_count')) as Array<{
    concentrator_id: number;
    read_at: Date | string;
    secret_count: number;
  }>;
  const secrets = (await q('concentrator_ppp_secrets')
    .whereIn('concentrator_id', chrIds)
    .whereNull('vanished_at')
    .orderBy(['concentrator_id', 'name'])
    .select(
      'concentrator_id',
      'name',
      q.raw('host(remote_address) AS remote_address'),
      'profile',
      'disabled',
      'first_seen_at',
      'last_seen_at',
    )) as SecretRow[];
  const openSessions = (await q('ppp_sessions')
    .whereIn('concentrator_id', chrIds)
    .whereNull('ended_at')
    .orderBy('started_at')
    .select('concentrator_id', 'ppp_username', q.raw('host(tunnel_ip) AS tunnel_ip'), 'started_at')) as OpenSessionRow[];
  const ended = (await q('ppp_sessions')
    .whereIn('concentrator_id', chrIds)
    .whereNotNull('ended_at')
    .groupByRaw('concentrator_id, lower(ppp_username)')
    .select('concentrator_id', q.raw('lower(ppp_username) AS login'), q.raw('max(ended_at) AS last_ended'))) as Array<{
    concentrator_id: number;
    login: string;
    last_ended: Date | string | null;
  }>;
  const presenceRows = (await q('ppp_sessions')
    .whereIn('concentrator_id', chrIds)
    .groupBy('concentrator_id')
    .select(
      'concentrator_id',
      q.raw('count(*)::int AS total'),
      q.raw('(count(*) FILTER (WHERE ended_at IS NULL))::int AS open_count'),
      q.raw('max(greatest(started_at, coalesce(ended_at, started_at))) AS last_event'),
    )) as Array<{ concentrator_id: number; total: number; open_count: number; last_event: Date | string | null }>;
  const verdictRows = (await q('reachability_verdicts')
    .whereIn('device_id', chrIds)
    .distinctOn('device_id')
    .orderBy([
      { column: 'device_id' },
      { column: 'ts', order: 'desc' },
      { column: 'id', order: 'desc' },
    ])
    .select('device_id', 'verdict', 'ts')) as Array<{ device_id: number; verdict: string; ts: Date | string }>;
  // What the last recorded /ppp/active read of each CHR showed beyond
  // `ppp_sessions`' one open row per login: the logins holding several.
  const recordedDuplicates = await readRecordedDuplicates(q, chrIds);
  const activeReads = await readActiveReads(q, chrIds);

  // Holders that make a login ANOTHER tenant's.
  const otherHeld = new Set<string>();
  for (const p of allProv) if (p.tenant_id !== tenantId) otherHeld.add(p.ppp_username.toLowerCase());
  const devices = (await q('devices')
    .where((w) => {
      void w.whereNotNull('ppp_username').orWhereNotNull('tunnel_ip');
    })
    .select('id', 'name', 'tenant_id', 'site_id', 'ppp_username', q.raw('host(tunnel_ip) AS tunnel_ip'))) as DeviceRow[];
  const ourDeviceByLogin = new Map<string, DeviceRow>();
  const ourDevicesBySite = new Map<number, DeviceRow[]>();
  for (const d of devices) {
    if (d.ppp_username === null) continue;
    const lower = d.ppp_username.toLowerCase();
    if (d.tenant_id !== tenantId) {
      otherHeld.add(lower);
      continue;
    }
    if (!ourDeviceByLogin.has(lower)) ourDeviceByLogin.set(lower, d);
    if (d.site_id !== null) pushTo(ourDevicesBySite, d.site_id, d);
  }

  // ── The CHR accounts ──────────────────────────────────────────────────────
  const openByKey = new Map<string, OpenSessionRow>();
  for (const s of openSessions) {
    const k = keyOf(s.concentrator_id, s.ppp_username);
    if (!openByKey.has(k)) openByKey.set(k, s);
  }
  const endedByKey = new Map<string, string | null>();
  for (const e of ended) endedByKey.set(`${e.concentrator_id}|${e.login}`, iso(e.last_ended));

  const accounts: Account[] = [];
  const byKey = new Map<string, Account[]>();
  const makeAccount = (view: Omit<ChrAccountView, 'session' | 'device'>): Account => {
    const lower = view.name.toLowerCase();
    const key = keyOf(view.concentratorId, view.name);
    const open = openByKey.get(key);
    const device = ourDeviceByLogin.get(lower);
    const account: Account = {
      view: {
        ...view,
        session: {
          up: open !== undefined,
          since: open ? iso(open.started_at) : null,
          address: open ? open.tunnel_ip : null,
          lastEndedAt: endedByKey.get(key) ?? null,
        },
        device: device ? { id: device.id, name: device.name, siteId: device.site_id } : null,
      },
      lower,
      key,
      claimed: false,
      parsed: null,
      family: null,
      loose: false,
      excluded: false,
    };
    accounts.push(account);
    pushTo(byKey, key, account);
    return account;
  };
  for (const s of secrets) {
    makeAccount({
      concentratorId: s.concentrator_id,
      name: s.name,
      declared: true,
      remoteAddress: s.remote_address,
      profile: s.profile,
      disabled: s.disabled,
      firstSeenAt: iso(s.first_seen_at),
      lastReadAt: iso(s.last_seen_at),
    });
  }
  // A live session with no declared secret (RADIUS, or a secret removed while
  // the session stayed up) is still a router in production on that CHR.
  for (const s of openSessions) {
    if (byKey.has(keyOf(s.concentrator_id, s.ppp_username))) continue;
    makeAccount({
      concentratorId: s.concentrator_id,
      name: s.ppp_username,
      declared: false,
      remoteAddress: null,
      profile: null,
      disabled: null,
      firstSeenAt: null,
      lastReadAt: null,
    });
  }

  // ── Sites: their login, and the account that carries it ─────────────────
  interface SiteState {
    site: SiteFactsLite;
    login: string | null;
    loginError: { reason: string; message: string } | null;
    chr: number;
    prov: ProvisioningRow | null;
  }
  const states: SiteState[] = sites.map((site) => {
    const prov = provBySite.get(site.id) ?? null;
    if (prov) return { site, login: prov.ppp_username, loginError: null, chr: prov.concentrator_id, prov };
    const r = renderPppLogin(
      template,
      { siteName: site.name, siteCode: site.code, siteCountry: site.country, tenantSlug: tenant.slug, instanceDomain },
      `"${site.code}" (${site.name})`,
    );
    return r.ok
      ? { site, login: r.login, loginError: null, chr: policyChr, prov: null }
      : { site, login: null, loginError: { reason: r.reason, message: r.message }, chr: policyChr, prov: null };
  });
  const loginUse = new Map<string, number>();
  for (const s of states) if (s.login !== null) loginUse.set(s.login.toLowerCase(), (loginUse.get(s.login.toLowerCase()) ?? 0) + 1);

  const matched: MatchedRow[] = [];
  const unmatched: SiteState[] = [];
  // Adoptable rows, judged once every candidate's login and address is known.
  const toJudge: Array<{ apply: (v: ReturnType<typeof judgeAdoption>) => void; candidate: AdoptionCandidate }> = [];
  for (const st of states) {
    if (st.login === null) {
      unmatched.push(st);
      continue;
    }
    let found = byKey.get(keyOf(st.chr, st.login));
    if (!found && !st.prov) {
      // Not on the policy's CHR: on another CHR this tenant's allocations use?
      for (const id of chrIds) {
        if (id === st.chr) continue;
        const other = byKey.get(keyOf(id, st.login));
        if (other) {
          found = other;
          break;
        }
      }
    }
    if (!found) {
      unmatched.push(st);
      continue;
    }
    // Prefer the exact spelling; the others are case variants.
    const exact = found.find((a) => a.view.name === st.login) ?? found[0];
    for (const a of found) a.claimed = true;
    const notes: AccountNote[] = [];
    if (exact.view.disabled === true) notes.push('disabled');
    if (exact.view.name !== st.login) notes.push('caseDiffers');
    if (st.prov && exact.view.remoteAddress !== null && exact.view.remoteAddress !== st.prov.tunnel_ip) {
      notes.push('addressDiffers');
    }
    const row: MatchedRow = {
      ...siteRef(st.site),
      login: st.login,
      status: st.prov ? (st.prov.source === 'adopted_chr' ? 'adopted' : 'allocated') : 'adoptable',
      account: exact.view,
      variants: found.filter((a) => a !== exact).map((a) => a.view.name),
      allocation: st.prov ? allocationRef(st.prov) : null,
      blockers: [],
      holders: [],
      notes,
    };
    matched.push(row);
    if (!st.prov) {
      toJudge.push({
        candidate: {
          name: exact.view.name,
          concentratorId: exact.view.concentratorId,
          declared: exact.view.declared,
          remoteAddress: exact.view.remoteAddress,
          profile: exact.view.profile,
          variants: found.length,
          siteId: st.site.id,
          sharedBySites: (loginUse.get(st.login.toLowerCase()) ?? 0) > 1,
        },
        apply: (v) => {
          row.blockers = v.blockers;
          row.holders = v.holders;
        },
      });
    }
  }

  // ── Unclaimed accounts: this tenant's, someone else's, or nobody's ───────
  const slugLower = tenant.slug.toLowerCase();
  const mentionsSlug = (lower: string): boolean => slugLower.length >= SLUG_SEARCH_MIN && lower.includes(slugLower);
  let excludedOtherTenant = 0;
  let excludedSharedPattern = 0;
  const unexplainedAccounts: Account[] = [];
  for (const a of accounts) {
    if (a.claimed) continue;
    a.parsed = readLogin(matcher, a.view.name);
    a.family = matcher.anchor ? outsideAnchor(matcher.anchor, a.view.name) : null;
    a.loose = a.parsed === null && a.family === null && mentionsSlug(a.lower);
    const ourRouter = a.view.device !== null;
    const ours = a.parsed !== null || a.family !== null || a.loose || ourRouter;
    const otherReads = (): boolean => otherMatchers.some((m) => readLogin(m, a.view.name) !== null);
    if (!ours) {
      if (!otherHeld.has(a.lower) && !otherReads()) unexplainedAccounts.push(a);
      continue;
    }
    if (otherHeld.has(a.lower)) {
      a.excluded = true;
      excludedOtherTenant += 1;
    } else if (!ourRouter && otherReads()) {
      // A router of THIS tenant dialling it outranks "another template could
      // have produced it too".
      a.excluded = true;
      excludedSharedPattern += 1;
    }
  }
  const candidates = accounts.filter(
    (a) => !a.claimed && !a.excluded && (a.parsed !== null || a.family !== null || a.loose || a.view.device !== null),
  );

  // ── Sites with no account: new, or suspect ───────────────────────────────
  const nearSitesOf = new Map<Account, NearSite[]>();
  const siteOnly: SiteOnlyRow[] = unmatched.map((st) => {
    const nearMatches: NearMatch[] = [];
    const sitePart = matcher.anchor && st.login !== null ? outsideAnchor(matcher.anchor, st.login) : null;
    const reasonsFor = new Map<Account, Set<NearReason>>();
    const add = (a: Account, reasons: readonly NearReason[]): void => {
      const set = reasonsFor.get(a) ?? new Set<NearReason>();
      for (const r of reasons) set.add(r);
      reasonsFor.set(a, set);
    };
    for (const a of candidates) {
      let r: NearReason[] | null = null;
      if (a.parsed !== null) r = parsedNear(st.site, a.parsed, template.uses);
      else if (a.family !== null) r = nearReasons(sitePart ?? st.site.code, a.family);
      else if (a.loose) r = labelNear(st.site, a.view.name);
      if (r) add(a, r);
    }
    // A router of THIS site already dials an account: whatever its shape,
    // that account is this store's.
    for (const d of ourDevicesBySite.get(st.site.id) ?? []) {
      if (d.ppp_username === null) continue;
      for (const id of chrIds) {
        for (const a of byKey.get(keyOf(id, d.ppp_username)) ?? []) {
          if (!a.claimed && !a.excluded) add(a, ['device']);
        }
      }
    }
    for (const [a, set] of reasonsFor) {
      const reasons = Array.from(set);
      nearMatches.push({ account: a.view, parsed: a.parsed, reasons });
      const back = nearSitesOf.get(a) ?? [];
      back.push({ ...siteRef(st.site), reasons });
      nearSitesOf.set(a, back);
    }
    nearMatches.sort((x, y) => x.account.name.localeCompare(y.account.name));
    return {
      ...siteRef(st.site),
      kind: nearMatches.length > 0 ? 'suspect' : 'new',
      login: st.login,
      loginError: st.loginError,
      allocation: st.prov ? allocationRef(st.prov) : null,
      nearMatches,
    };
  });

  // ── Orphans (the template produces them) and off-pattern accounts ────────
  const orphans: OrphanRow[] = [];
  const offPattern: OffPatternRow[] = [];
  const needsCode = template.uses.has('site.code') || template.uses.has('site.id');
  for (const a of candidates) {
    const nearSites = (nearSitesOf.get(a) ?? []).sort(bySiteCode);
    if (a.parsed === null) {
      const via: OffPatternVia = a.family !== null ? 'anchor' : a.loose ? 'slug' : 'device';
      offPattern.push({ account: a.view, via, nearSites });
      continue;
    }
    const p = a.parsed;
    const prefill = {
      code: p.code ?? (p.number === null ? null : String(p.number)),
      name: template.uses.has('site.slug') ? p.slug : null,
      country: p.country,
    };
    const row: OrphanRow = {
      account: a.view,
      parsed: p,
      prefill,
      blockers: [],
      holders: [],
      creationAdopts: false,
      nearSites,
    };
    orphans.push(row);
    toJudge.push({
      candidate: {
        name: a.view.name,
        concentratorId: a.view.concentratorId,
        declared: a.view.declared,
        remoteAddress: a.view.remoteAddress,
        profile: a.view.profile,
        variants: (byKey.get(a.key) ?? []).length,
        siteId: null,
        sharedBySites: false,
      },
      apply: (v) => {
        row.blockers = v.blockers;
        row.holders = v.holders;
        row.creationAdopts = v.blockers.length === 0 && (!needsCode || prefill.code !== null);
      },
    });
  }

  // ── Adoption, judged for every candidate at once ─────────────────────────
  if (toJudge.length > 0) {
    const idx = await loadHolderIndex(
      q,
      tenantId,
      policyRow,
      allPolicies,
      allProv,
      devices,
      slugOf,
      toJudge.map((j) => j.candidate.name),
      toJudge.flatMap((j) => (isIpv4Host(j.candidate.remoteAddress) ? [j.candidate.remoteAddress] : [])),
    );
    for (const j of toJudge) j.apply(judgeAdoption(j.candidate, idx, tenantId, policyChr));
  }

  // Routers in production first: those are the stores that exist.
  const byLiveThenName = (x: ChrAccountView, y: ChrAccountView): number =>
    Number(y.session.up) - Number(x.session.up) || x.name.localeCompare(y.name);
  orphans.sort((x, y) => byLiveThenName(x.account, y.account));
  offPattern.sort((x, y) => byLiveThenName(x.account, y.account));
  const unexplained = unexplainedAccounts.map((a) => a.view).sort(byLiveThenName);
  siteOnly.sort((x, y) => Number(y.kind === 'suspect') - Number(x.kind === 'suspect') || bySiteCode(x, y));
  matched.sort(bySiteCode);

  // ── Logins holding several live sessions (pppDuplicates.service.ts) ──────
  // Only the accounts this report lists: an account excluded as another
  // tenant's is that tenant's report's business.
  const dupByKey = new Map(recordedDuplicates.map((d) => [`${d.concentratorId}|${d.loginKey}`, d]));
  const duplicates: DuplicateSessionsRow[] = [];
  const listedDuplicate = new Set<string>();
  const addDuplicate = (
    a: ChrAccountView,
    group: DuplicateSessionsRow['group'],
    extra: { via?: OffPatternVia; site?: ReconcileSiteRef } = {},
  ): void => {
    const key = keyOf(a.concentratorId, a.name);
    const d = dupByKey.get(key);
    if (!d || listedDuplicate.has(key)) return;
    listedDuplicate.add(key);
    duplicates.push({
      concentratorId: a.concentratorId,
      account: a.name,
      group,
      via: extra.via ?? null,
      site: extra.site ?? null,
      device: a.device,
      sessions: d.sessions,
      firstSeenAt: d.firstSeenAt,
      observedAt: d.observedAt,
    });
  };
  for (const m of matched) addDuplicate(m.account, 'matched', { site: { siteId: m.siteId, code: m.code, name: m.name, country: m.country } });
  for (const o of orphans) addDuplicate(o.account, 'orphan');
  for (const x of offPattern) addDuplicate(x.account, 'offPattern', { via: x.via });
  for (const u of unexplained) addDuplicate(u, 'unexplained');

  const chrName = new Map(chrRows.map((c) => [c.id, c.name]));
  const readOf = new Map(reads.map((r) => [r.concentrator_id, r]));
  const presenceOf = new Map(presenceRows.map((r) => [r.concentrator_id, r]));
  const verdictOf = new Map(verdictRows.map((r) => [r.device_id, r]));
  const inventory: ConcentratorInventory[] = chrIds.map((id) => {
    const r = readOf.get(id);
    const readAtMs = r ? new Date(r.read_at).getTime() : null;
    const pr = presenceOf.get(id);
    const v = verdictOf.get(id);
    return {
      concentratorId: id,
      name: chrName.get(id) ?? null,
      policy: id === policyChr,
      readAt: r ? iso(r.read_at) : null,
      secretCount: r ? r.secret_count : null,
      freshness: seedFreshness(readAtMs, nowMs),
      presence: {
        sessionsRecorded: pr ? Number(pr.total) : 0,
        openSessions: pr ? Number(pr.open_count) : 0,
        lastEventAt: pr ? iso(pr.last_event) : null,
        degradedSince: v && v.verdict === 'CONCENTRATOR_DEGRADED' ? iso(v.ts) : null,
      },
      activeRead: activeReads.get(id) ?? null,
    };
  });

  const suspects = siteOnly.filter((s) => s.kind === 'suspect').length;
  return {
    tenantId,
    tenantSlug: tenant.slug,
    tenantName: tenant.name,
    generatedAt: new Date(nowMs).toISOString(),
    loginTemplate: template.source,
    policyConcentratorId: policyChr,
    pattern: {
      display: matcher.display,
      regex: matcher.regex.source,
      captures: matcher.captures,
      anchor: matcher.anchor,
      namesTenant: matcher.namesTenant,
    },
    inventory,
    counts: {
      sites: sites.length,
      matched: matched.length,
      orphans: orphans.length,
      orphansOnline: orphans.filter((o) => o.account.session.up).length,
      siteOnly: siteOnly.length,
      siteOnlyNew: siteOnly.length - suspects,
      siteOnlySuspect: suspects,
      offPattern: offPattern.length,
      unexplained: unexplained.length,
      unexplainedOnline: unexplained.filter((a) => a.session.up).length,
      excludedOtherTenant,
      excludedSharedPattern,
      duplicates: duplicates.length,
    },
    matched,
    orphans,
    siteOnly,
    offPattern,
    unexplained,
    duplicates,
  };
}

function allocationRef(p: ProvisioningRow): AllocationRef {
  return { source: p.source, state: p.concentrator_state, tunnelIp: p.tunnel_ip, concentratorId: p.concentrator_id };
}

// ============================================================================
// One row at a time: the classifier the site import shares
// ============================================================================

/** A site as a caller is about to write it — a site-import row, before
 *  anything is written. */
export interface ProposedSite {
  /** The caller's own handle for the row (the import's line number); unique. */
  ref: number;
  /** The tenant's existing site the row updates; null for a creation. */
  siteId: number | null;
  code: string;
  name: string;
  country: string | null;
}

/**
 *   takesOver  the row's login IS an account on the CHR, not yet allocated:
 *              the site's next allocation adopts it — unless `blocked`;
 *   allocated  the row's site already holds an allocation (its login is the
 *              allocated one, whatever the row changes);
 *   new        no account, nothing resembling one: the allocation will create
 *              the account;
 *   suspect    no account, but an unclaimed account of this tenant names the
 *              same store differently. A WARNING, never a refusal: the
 *              allocator adopts an account only when the login is that
 *              account's exact name (case aside), so a suspect site gets a new
 *              address and, later, a second CHR account — which is what the
 *              operator must decide about before allocating;
 *   noLogin    the login cannot be rendered for this row (`loginError`).
 */
export type ChrRowKind = 'takesOver' | 'allocated' | 'new' | 'suspect' | 'noLogin';

export interface ChrNearAccount {
  name: string;
  online: boolean;
  reasons: NearReason[];
  /** Listed only because the account's name CONTAINS the tenant slug (no
   *  template of this tenant produces it, no router of this tenant dials it).
   *  The weakest claim the report makes about ownership: `redactVerdict` and
   *  `redactReport` withhold these. */
  slugOnly: boolean;
}

export interface ChrRowVerdict {
  ref: number;
  kind: ChrRowKind;
  /** The login the row's site computes, or the one already allocated. */
  login: string | null;
  /** takesOver: the account that IS the row's login; allocated: the account
   *  the allocation holds, when the CHR's last read lists it. */
  account: { name: string; online: boolean } | null;
  /** takesOver: the restated adoption rules (see the "ADOPTABLE" box) see
   *  something in the way — its allocation would NOT take the account over. */
  blocked: boolean;
  /** What is in the way. Emptied by `redactVerdict` (the codes speak of other
   *  holders, pools and CHRs). */
  blockers: AdoptBlocker[];
  /** suspect: the accounts naming the same store differently. */
  nearMatches: ChrNearAccount[];
  /** Near-matches `redactVerdict` withheld: still a reason to look, not named. */
  withheld: number;
  /** noLogin: the renderer's sentence. */
  loginError: string | null;
}

export interface ChrComparison {
  generatedAt: string;
  /** See `LoginMatcher.namesTenant`. */
  namesTenant: boolean;
  /** The login pattern, the tenant's fixed values substituted. */
  pattern: string;
  /** The policy CHR's last /ppp/secret read; null: never read, and every
   *  verdict would say "new" for want of an inventory. */
  readAt: string | null;
  freshness: SeedFreshness;
  /** In `proposed` order. */
  verdicts: ChrRowVerdict[];
}

function nearAccount(n: NearMatch): ChrNearAccount {
  return {
    name: n.account.name,
    online: n.account.session.up,
    reasons: n.reasons,
    // `labelNear` is the only rule that says 'template', and it runs only on
    // an account kept for containing the slug; a router of this tenant
    // dialling it makes it this tenant's.
    slugOnly: n.parsed === null && n.account.device === null && n.reasons.includes('template') && !n.reasons.includes('device'),
  };
}

/**
 * Each proposed row's verdict, read off a report built WITH the rows laid over
 * the stored sites (`buildReport`'s `proposed`): the rows claim their accounts
 * exactly as stored sites do, two rows (or a row and a stored site) computing
 * the same login block each other (`sharedLogin`), and the near-matches are
 * searched among the accounts nobody claims. Pure.
 */
export function verdictsFromReport(
  report: ReconcileReport,
  proposed: readonly ProposedSite[],
  idOf: ReadonlyMap<number, number>,
): ChrRowVerdict[] {
  const matchedBy = new Map(report.matched.map((m) => [m.siteId, m]));
  const onlyBy = new Map(report.siteOnly.map((s) => [s.siteId, s]));
  return proposed.map((p) => {
    const id = idOf.get(p.ref);
    const base: ChrRowVerdict = {
      ref: p.ref,
      kind: 'new',
      login: null,
      account: null,
      blocked: false,
      blockers: [],
      nearMatches: [],
      withheld: 0,
      loginError: null,
    };
    const m = id === undefined ? undefined : matchedBy.get(id);
    if (m) {
      const account = { name: m.account.name, online: m.account.session.up };
      if (m.status !== 'adoptable') return { ...base, kind: 'allocated', login: m.login, account };
      return { ...base, kind: 'takesOver', login: m.login, account, blocked: m.blockers.length > 0, blockers: m.blockers };
    }
    const s = id === undefined ? undefined : onlyBy.get(id);
    if (!s) throw new Error(`reconcile: proposed row ${p.ref} is missing from its own report`);
    if (s.allocation) return { ...base, kind: 'allocated', login: s.login };
    if (s.login === null) return { ...base, kind: 'noLogin', loginError: s.loginError?.message ?? null };
    return { ...base, kind: s.kind, login: s.login, nearMatches: s.nearMatches.map(nearAccount) };
  });
}

/**
 * Compare sites ABOUT TO BE WRITTEN with the CHR, as the reconciliation
 * would once they exist — the site import's dry run. ONE classifier: the very
 * report `reconcileTenant` builds (the same login matcher, the same
 * `readLogin` / `nearReasons`, the same exclusion of what another tenant
 * holds or could have produced), with the rows laid over the stored sites.
 * Read-only like the report (REPEATABLE READ READ ONLY), and it dials
 * nothing: it reads the LAST recorded /ppp/secret read, whose time it
 * returns. Throws what `reconcileTenant` throws.
 */
export async function classifyProposedSites(
  tenantId: number,
  proposed: readonly ProposedSite[],
  nowMs: number = Date.now(),
): Promise<ChrComparison> {
  assertId(tenantId, 'tenantId', PG_INT_MAX);
  if (new Set(proposed.map((p) => p.ref)).size !== proposed.length) {
    throw new AllocationError('INVALID_INPUT', 'every proposed site needs its own ref.');
  }
  const idOf = new Map<number, number>();
  const report = await db.transaction(async (trx) => {
    await trx.raw('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
    return buildReport(trx, tenantId, nowMs, proposed, idOf);
  });
  const policyChr = report.inventory.find((i) => i.policy) ?? null;
  return {
    generatedAt: report.generatedAt,
    namesTenant: report.pattern.namesTenant,
    pattern: report.pattern.display,
    readAt: policyChr?.readAt ?? null,
    freshness: policyChr?.freshness ?? 'never',
    verdicts: verdictsFromReport(report, proposed, idOf),
  };
}

/** A verdict for a caller who is not a platform admin: no blocker codes (they
 *  speak of other holders, pools and CHRs — `blocked` still says whether the
 *  account would be taken over), and no near-match listed only for containing
 *  the slug (counted in `withheld`). The kind is kept: "suspect" stays a
 *  reason to look. Pure. */
export function redactVerdict(v: ChrRowVerdict): ChrRowVerdict {
  const kept = v.nearMatches.filter((n) => !n.slugOnly);
  return { ...v, blockers: [], nearMatches: kept, withheld: v.withheld + v.nearMatches.length - kept.length };
}

// ============================================================================
// The tenant's own view (RECONCILE_READ): redacted, and only when provable
// ============================================================================

/** Why a tenant user's reconciliation is refused. */
export class TenantReconcileRefused extends Error {
  constructor(
    readonly reason: 'TEMPLATE_NAMES_NO_TENANT',
    message: string,
  ) {
    super(message);
    this.name = 'TenantReconcileRefused';
  }
}

export const TEMPLATE_NAMES_NO_TENANT_MESSAGE =
  "This workspace's PPP login rule does not name the workspace (no {tenant.slug}, and the slug is " +
  'not spelled in it): on a concentrator several customers share, the accounts it matches may ' +
  "belong to other customers, so comparing them with your sites would show you other customers' " +
  'stores. Only a platform administrator can reconcile this workspace.';

/** Refuses a report whose template names no tenant (see RECONCILE_READ). */
export function assertTenantMayReconcile(report: Pick<ReconcileReport, 'pattern'>): void {
  if (!report.pattern.namesTenant) {
    throw new TenantReconcileRefused('TEMPLATE_NAMES_NO_TENANT', TEMPLATE_NAMES_NO_TENANT_MESSAGE);
  }
}

/** An account as a tenant user sees it: no address, profile or CHR identity. */
export interface TenantChrAccount {
  name: string;
  declared: boolean;
  disabled: boolean | null;
  session: { up: boolean; since: string | null; lastEndedAt: string | null };
  /** A device of THIS tenant dialling it. */
  device: { id: number; name: string; siteId: number | null } | null;
}

export interface TenantReconcileView {
  tenantName: string;
  generatedAt: string;
  /** The login pattern read, the tenant's own values substituted. */
  pattern: string;
  /** The CHRs read — no id, no name, no account count (the CHR is shared). */
  inventory: Array<{
    policy: boolean;
    readAt: string | null;
    freshness: SeedFreshness;
    /** Presence has recorded at least one session there: "never seen online"
     *  means something only then. */
    presenceRecorded: boolean;
    degradedSince: string | null;
    /** The last recorded /ppp/active read: what `duplicates` is as current
     *  as. null: never recorded. */
    activeReadAt: string | null;
  }>;
  counts: {
    sites: number;
    matched: number;
    orphans: number;
    orphansOnline: number;
    siteOnly: number;
    siteOnlyNew: number;
    siteOnlySuspect: number;
    offPattern: number;
    duplicates: number;
  };
  /** This tenant's accounts holding several live sessions at once: matched,
   *  orphans and off-pattern accounts (never an unexplained one, never one
   *  listed for its slug alone). Each session's caller-id — the store's own
   *  public address — and uptime are kept; the tunnel address is dropped
   *  like every address of this view. */
  duplicates: Array<{
    account: string;
    group: 'matched' | 'orphan' | 'offPattern';
    site: ReconcileSiteRef | null;
    device: TenantChrAccount['device'];
    sessions: Array<{ callerId: string | null; uptime: string | null; since: string | null }>;
    firstSeenAt: string;
    observedAt: string;
  }>;
  matched: Array<
    ReconcileSiteRef & {
      login: string;
      status: MatchStatus;
      account: TenantChrAccount;
      /** adoptable only: the allocation would NOT take the account over. */
      blocked: boolean;
      notes: Array<Exclude<AccountNote, 'addressDiffers'>>;
    }
  >;
  orphans: Array<{
    account: TenantChrAccount;
    prefill: OrphanRow['prefill'];
    blocked: boolean;
    creationAdopts: boolean;
    nearSites: NearSite[];
  }>;
  siteOnly: Array<
    ReconcileSiteRef & {
      kind: 'new' | 'suspect';
      login: string | null;
      loginError: string | null;
      allocated: boolean;
      nearMatches: Array<{ account: TenantChrAccount; reasons: NearReason[] }>;
      withheld: number;
    }
  >;
  offPattern: Array<{ account: TenantChrAccount; via: Exclude<OffPatternVia, 'slug'>; nearSites: NearSite[] }>;
}

function tenantAccount(a: ChrAccountView): TenantChrAccount {
  return {
    name: a.name,
    declared: a.declared,
    disabled: a.disabled,
    session: { up: a.session.up, since: a.session.since, lastEndedAt: a.session.lastEndedAt },
    device: a.device,
  };
}

/**
 * The report as a tenant user may read it. KEPT: this tenant's sites, the
 * accounts the report attributes to this tenant (its matched sites' accounts,
 * its orphans, the off-pattern accounts carrying its fixed part or dialled by
 * its routers, the near-matches), presence's session dates, and those
 * accounts' duplicated sessions (caller-id and uptime only). DROPPED: the
 * accounts nobody explains (another customer's, by definition), the counts of
 * what another tenant holds or could have produced, every holder, blocker
 * code, address, profile, pool, CHR id, CHR name and CHR account count, the
 * stored template and its regex, and anything listed only because its name
 * contains the slug (an off-pattern 'slug' row, a 'slugOnly' near-match):
 * the slug of "acme" is inside "acme-north", and that is the one listing
 * whose ownership the report does not establish. Pure; the caller has
 * already refused a template that names no tenant.
 */
export function redactReport(r: ReconcileReport): TenantReconcileView {
  const offPattern = r.offPattern.flatMap((x) =>
    x.via === 'slug' ? [] : [{ account: tenantAccount(x.account), via: x.via, nearSites: x.nearSites }],
  );
  const siteOnly = r.siteOnly.map((s) => {
    const near = s.nearMatches.map((n) => ({ n, slugOnly: nearAccount(n).slugOnly }));
    const kept = near.filter((x) => !x.slugOnly);
    return {
      siteId: s.siteId,
      code: s.code,
      name: s.name,
      country: s.country,
      kind: s.kind,
      login: s.login,
      loginError: s.loginError ? s.loginError.message : null,
      allocated: s.allocation !== null,
      nearMatches: kept.map((x) => ({ account: tenantAccount(x.n.account), reasons: x.n.reasons })),
      withheld: near.length - kept.length,
    };
  });
  const duplicates: TenantReconcileView['duplicates'] = r.duplicates.flatMap((d) =>
    d.group === 'unexplained' || (d.group === 'offPattern' && d.via === 'slug')
      ? []
      : [
          {
            account: d.account,
            group: d.group,
            site: d.site,
            device: d.device,
            sessions: d.sessions.map((s) => ({ callerId: s.callerId, uptime: s.uptime, since: s.since })),
            firstSeenAt: d.firstSeenAt,
            observedAt: d.observedAt,
          },
        ],
  );
  return {
    tenantName: r.tenantName,
    generatedAt: r.generatedAt,
    pattern: r.pattern.display,
    inventory: r.inventory.map((c) => ({
      policy: c.policy,
      readAt: c.readAt,
      freshness: c.freshness,
      presenceRecorded: c.presence.sessionsRecorded > 0,
      degradedSince: c.presence.degradedSince,
      activeReadAt: c.activeRead?.readAt ?? null,
    })),
    counts: {
      sites: r.counts.sites,
      matched: r.counts.matched,
      orphans: r.counts.orphans,
      orphansOnline: r.counts.orphansOnline,
      siteOnly: r.counts.siteOnly,
      siteOnlyNew: r.counts.siteOnlyNew,
      siteOnlySuspect: r.counts.siteOnlySuspect,
      offPattern: offPattern.length,
      duplicates: duplicates.length,
    },
    matched: r.matched.map((m) => ({
      siteId: m.siteId,
      code: m.code,
      name: m.name,
      country: m.country,
      login: m.login,
      status: m.status,
      account: tenantAccount(m.account),
      blocked: m.status === 'adoptable' && m.blockers.length > 0,
      notes: m.notes.filter((n): n is Exclude<AccountNote, 'addressDiffers'> => n !== 'addressDiffers'),
    })),
    orphans: r.orphans.map((o) => ({
      account: tenantAccount(o.account),
      prefill: o.prefill,
      blocked: o.blockers.length > 0,
      creationAdopts: o.creationAdopts,
      nearSites: o.nearSites,
    })),
    siteOnly,
    offPattern,
    duplicates,
  };
}

/** The reconciliation of the caller's OWN tenant (the controller passes
 *  `req.tenantId`), redacted. Throws what `reconcileTenant` throws, and
 *  TenantReconcileRefused for a template that names no tenant. */
export async function tenantReconcileView(tenantId: number, nowMs: number = Date.now()): Promise<TenantReconcileView> {
  const report = await reconcileTenant(tenantId, nowMs);
  assertTenantMayReconcile(report);
  return redactReport(report);
}

/**
 * "Re-read the CHR" for a tenant user: `rereadConcentratorInventory` — the
 * allocator's own re-read, through the shared RouterOS pool, its write under
 * the allocation lock — on each CHR this tenant's reconciliation reads (the
 * policy's, and any its allocations were frozen on), never on a CHR the caller
 * names. Refused BEFORE any dial when the template names no tenant: a read
 * the caller may not look at is a read she has no reason to trigger. Returns
 * how many CHRs were read; the first failure propagates (the reads before it
 * stay recorded, as they would from the admin screen).
 */
export async function rereadForTenant(tenantId: number): Promise<number> {
  const report = await reconcileTenant(tenantId);
  assertTenantMayReconcile(report);
  for (const c of report.inventory) await rereadConcentratorInventory(c.concentratorId);
  return report.inventory.length;
}

// ============================================================================
// The orphans, as rows the site import takes back
// ============================================================================

/** One orphan as a site-import row: what the account name reads back. `name`
 *  is set only under a {site.slug} template (where the name decides the
 *  login); otherwise the operator types it. */
export interface OrphanImportRow {
  code: string | null;
  name: string | null;
  country: string | null;
}

/**
 * The orphans as site-import rows, in the report's order (routers online
 * first). Every orphan is listed, blocked or not: the re-import's dry run is
 * where each row says whether it takes its account over (and, if not, why) —
 * judged THEN, on the inventory of that moment, because an orphan exported
 * today may have been claimed by tomorrow. Nothing here decides an adoption.
 * Pure.
 */
export function orphanImportRows(report: Pick<ReconcileReport, 'orphans'>): OrphanImportRow[] {
  return report.orphans.map((o) => ({ code: o.prefill.code, name: o.prefill.name, country: o.prefill.country }));
}

// ============================================================================
// Export
// ============================================================================

/**
 * The export is an .xlsx written by fleet/xlsx.ts, not a CSV: Excel re-reads
 * a CSV on open, and "0042" becomes the number 42 — the leading zeros are
 * exactly what this report is about. That writer stores every value as text
 * (never a formula) and dates as real dates.
 *
 * Headers and labels are FRENCH, like the site deployment export the same
 * operator opens (siteDeployment.service.ts): a workbook is read outside the
 * application, where no i18n runs. The coded values the screen translates
 * (group, status, reasons) are spelled out here once, in French.
 */
const EXPORT_COLUMNS: XlsxColumn[] = [
  { header: 'Groupe', width: 26, type: 'text' },
  { header: 'Code site', width: 12, type: 'text' },
  { header: 'Site', width: 28, type: 'text' },
  { header: 'Pays', width: 6, type: 'text' },
  { header: 'Login attendu', width: 38, type: 'text' },
  { header: 'Compte CHR', width: 38, type: 'text' },
  { header: 'Code lu', width: 12, type: 'text' },
  { header: 'Pays lu', width: 8, type: 'text' },
  { header: 'CHR (id)', width: 9, type: 'text' },
  { header: 'Adresse déclarée', width: 16, type: 'text' },
  { header: 'Secret déclaré', width: 9, type: 'text' },
  { header: 'Désactivé', width: 9, type: 'text' },
  { header: 'Session', width: 11, type: 'text' },
  // Presence's own observations: "en ligne" since it FIRST SAW the session
  // (not the dial-up), "hors ligne" since the last session it saw end.
  { header: 'Observé depuis', width: 17, type: 'date' },
  { header: 'Dernière lecture CHR', width: 17, type: 'date' },
  { header: 'Statut', width: 28, type: 'text' },
  { header: 'Détail', width: 48, type: 'text' },
  { header: 'Ressemble à', width: 48, type: 'text' },
];

const GROUP_FR = {
  matched: 'Rapproché',
  orphan: 'Compte CHR sans site',
  suspect: 'Site sans compte : SUSPECT',
  new: 'Site sans compte : nouveau',
  offPattern: 'Compte hors modèle',
  unexplained: 'Compte CHR non attribué',
} as const;
const STATUS_FR: Record<MatchStatus, string> = { allocated: 'alloué', adopted: 'adopté', adoptable: 'adoptable' };
const BLOCKER_FR: Record<AdoptBlocker, string> = {
  ambiguous: 'plusieurs orthographes sur le CHR',
  noAddress: 'pas de remote-address fixe',
  sessionOnly: 'aucun /ppp/secret',
  otherTenant: 'login détenu par un autre client',
  sharedLogin: 'un autre site a le même login',
  loginTaken: 'login détenu ailleurs',
  addressTaken: 'adresse détenue ailleurs',
  addressInLan: "adresse dans le LAN d'un site",
  foreignPool: "adresse dans le plan d'un autre client",
  profileInvalid: 'profil PPP non enregistrable',
  otherConcentrator: 'sur un autre CHR que celui de la politique',
};
const NOTE_FR: Record<AccountNote, string> = {
  disabled: 'désactivé sur le CHR',
  caseDiffers: 'orthographe du CHR différente (casse)',
  addressDiffers: "adresse du CHR différente de l'allocation",
};
const REASON_FR: Record<NearReason, string> = {
  country: 'pays',
  prefix: 'préfixe',
  zeros: 'zéros de tête',
  separator: 'séparateur',
  name: 'nom',
  template: 'partie fixe différente',
  device: 'routeur du site',
};
const VIA_FR: Record<OffPatternVia, string> = {
  anchor: 'porte la partie fixe du client, mais le modèle ne le produit pas',
  slug: 'contient le nom du client, mais le modèle ne le produit pas',
  device: 'un routeur du client compose ce compte',
};
const HOLDER_FR: Record<BlockingHolder['kind'], string> = {
  site: 'site',
  lan: 'LAN du site',
  device: 'routeur',
  session: 'session',
  secret: 'compte CHR',
};
const STATE_FR: Record<string, string> = { pending: 'en attente', provisioned: 'provisionné', failed: 'en échec' };

function date(isoText: string | null): Date | null {
  return isoText === null ? null : new Date(isoText);
}

function accountCells(a: ChrAccountView): XlsxValue[] {
  return [
    a.name,
    null,
    null,
    String(a.concentratorId),
    a.remoteAddress,
    a.declared ? 'oui' : 'non',
    a.disabled === null ? null : a.disabled ? 'oui' : 'non',
    a.session.up ? 'en ligne' : 'hors ligne',
    date(a.session.up ? a.session.since : a.session.lastEndedAt),
    date(a.lastReadAt),
  ];
}

function nearText(list: ReadonlyArray<{ reasons: NearReason[] } & ({ code: string } | { account: ChrAccountView })>): string {
  return list
    .map((n) => `${'code' in n ? n.code : n.account.name} (${n.reasons.map((r) => REASON_FR[r]).join(', ')})`)
    .join(' | ');
}

function holderText(h: BlockingHolder): string {
  const what = h.kind === 'lan' ? `${HOLDER_FR.lan} ${h.name} (${h.detail ?? ''})` : `${HOLDER_FR[h.kind]} ${h.name}`;
  const chr = (h.kind === 'session' || h.kind === 'secret') && h.detail !== null ? ` sur le CHR ${h.detail}` : '';
  const who = h.tenantSlug !== null ? ` [${h.tenantSlug}]` : '';
  return `${what}${chr}${who}`;
}

function blockerDetail(blockers: readonly AdoptBlocker[], holders: readonly BlockingHolder[]): string[] {
  const out = blockers.map((b) => BLOCKER_FR[b]);
  if (holders.length > 0) out.push(`détenu par : ${holders.map(holderText).join(', ')}`);
  return out;
}

/** The rows of the workbook, in EXPORT_COLUMNS order: matched sites, orphans,
 *  sites without an account (suspects first), off-pattern accounts,
 *  unexplained accounts. Pure. */
export function reconcileRows(report: ReconcileReport): XlsxValue[][] {
  const rows: XlsxValue[][] = [];
  const noAccount: XlsxValue[] = [null, null, null, null, null, null, null, null, null, null];
  for (const m of report.matched) {
    const a = accountCells(m.account);
    rows.push([
      GROUP_FR.matched,
      m.code,
      m.name,
      m.country,
      m.login,
      ...a,
      m.status === 'adoptable' && m.blockers.length > 0 ? 'adoptable : NON, voir le détail' : STATUS_FR[m.status],
      [
        ...blockerDetail(m.blockers, m.holders),
        ...m.notes.map((n) => NOTE_FR[n]),
        ...m.variants.map((v) => `variante : ${v}`),
      ].join(' ; '),
      null,
    ]);
  }
  for (const o of report.orphans) {
    const a = accountCells(o.account);
    a[1] = o.parsed.code ?? (o.parsed.number === null ? o.parsed.slug : String(o.parsed.number));
    a[2] = o.parsed.country;
    rows.push([
      GROUP_FR.orphan,
      o.prefill.code,
      o.prefill.name,
      o.prefill.country,
      null,
      ...a,
      // "devrait": the restated adoption rules, not the allocator's verdict
      // (reconcile.service.ts, "ADOPTABLE" box).
      o.creationAdopts
        ? "créer le site : son allocation devrait reprendre ce compte (l'aperçu des allocations confirme)"
        : 'créer le site : son allocation ne reprendrait PAS ce compte',
      blockerDetail(o.blockers, o.holders).join(' ; '),
      nearText(o.nearSites),
    ]);
  }
  for (const s of report.siteOnly) {
    rows.push([
      s.kind === 'suspect' ? GROUP_FR.suspect : GROUP_FR.new,
      s.code,
      s.name,
      s.country,
      s.login,
      ...noAccount,
      s.allocation ? `alloué (${STATE_FR[s.allocation.state] ?? s.allocation.state})` : 'non alloué',
      s.loginError ? s.loginError.message : null,
      nearText(s.nearMatches),
    ]);
  }
  for (const x of report.offPattern) {
    rows.push([GROUP_FR.offPattern, null, null, null, null, ...accountCells(x.account), null, VIA_FR[x.via], nearText(x.nearSites)]);
  }
  for (const u of report.unexplained) {
    rows.push([GROUP_FR.unexplained, null, null, null, null, ...accountCells(u), null, null, null]);
  }
  return rows;
}

/** A tenant slug as a file name fragment: [a-z0-9-] only, never empty. */
function fileSlug(raw: string): string {
  const slug = raw.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48);
  return slug || 'tenant';
}

/** The report as a one-sheet workbook. `timeZone` (IANA) is the zone the
 *  dates are written in: an Excel date carries none. */
export function reconcileToXlsx(report: ReconcileReport, timeZone: string): { buffer: Buffer; fileName: string } {
  const buffer = buildXlsx({ sheetName: 'Rapprochement', columns: EXPORT_COLUMNS, rows: reconcileRows(report), timeZone });
  const day = isoDateIn(new Date(report.generatedAt), timeZone);
  return { buffer, fileName: `rapprochement-chr-${fileSlug(report.tenantSlug)}-${day}.xlsx` };
}

/** The file name of the orphans workbook (siteImport.service
 *  `orphansImportXlsx`), from the same slug and day as the report's. */
export function orphansFileName(report: Pick<ReconcileReport, 'tenantSlug' | 'generatedAt'>, timeZone: string): string {
  const day = isoDateIn(new Date(report.generatedAt), timeZone);
  return `orphelins-chr-${fileSlug(report.tenantSlug)}-${day}.xlsx`;
}

// ============================================================================
// The two gestures the reconciliation screen offers
// ============================================================================

/**
 * Re-read one concentrator's /ppp/secret and record it as the inventory this
 * report reads — `refreshSecretInventory`, the allocator's own re-read: one
 * `/ppp/secret/print` with the `.proplist` allow-list (no password crosses the
 * wire), nothing written to the router. Unlike the discovery scan it puts
 * nothing in the PPP quarantine and does not depend on the caller's session
 * tenant: the concentrator is named by id — by a platform admin, or by
 * `rereadForTenant` from the caller's own tenant's reconciliation, never by a
 * tenant user. A read that fails records nothing. Throws CONCENTRATOR_NOT_FOUND /
 * CONCENTRATOR_INVALID before dialling; a transport failure propagates as is.
 */
export async function rereadConcentratorInventory(concentratorId: number): Promise<SecretInventoryResult> {
  assertId(concentratorId, 'concentratorId', PG_INT_MAX);
  const row = (await db('devices').where({ id: concentratorId }).first('id', 'role')) as
    | { id: number; role: string }
    | undefined;
  if (!row) throw new AllocationError('CONCENTRATOR_NOT_FOUND', `device ${concentratorId} does not exist.`);
  if (row.role !== 'concentrator') {
    throw new AllocationError('CONCENTRATOR_INVALID', `device ${concentratorId} is not a concentrator.`);
  }
  const result = await refreshSecretInventory(concentratorId);
  // The live sessions too, for the duplicated logins the report lists
  // (pppDuplicates.service.ts): one `/ppp/active/print`, a read like the
  // secret's, nothing written to the router. Best effort — presence records
  // the same every 60 s, and a failure here must not fail the secret re-read
  // that already succeeded.
  try {
    const readAt = new Date();
    await recordActiveRead(concentratorId, await readPppActive(concentratorId), readAt);
  } catch (err) {
    logger.warn({ err, concentratorId }, 'Re-read: /ppp/active could not be read or recorded; the duplicate sessions are as presence last recorded them');
  }
  return result;
}

/**
 * Whether `code` is READ OFF an account live on the tenant's CHR — the only
 * case in which `createSiteForTenant` waives the site code format. True only
 * when ALL of these hold:
 *
 *   - the tenant has an allocation policy whose login template parses AND
 *     carries {site.code}, so the code is literally part of the login. Under
 *     {site.id} alone the login holds the site NUMBER, and a code padded to
 *     the format renders the same login, so nothing needs waiving; under
 *     {site.slug} alone the code is not in the login at all;
 *   - the login rendered for this code, name and country (the allocator's own
 *     `renderPppLogin`) is valid;
 *   - a non-vanished `concentrator_ppp_secrets` row of the policy's CHR has
 *     that name, compared case-insensitively like the allocator's adoption;
 *   - that account is an ORPHAN of this tenant's own reconciliation
 *     (`reconcileTenant`), declared, on the policy's CHR, and carrying none
 *     of the login-ownership blockers (`LOGIN_OWNERSHIP_BLOCKERS`). Equality
 *     alone is not ownership: the account may already be claimed by another
 *     site of this tenant (a case variant of its code, say), be held by
 *     another tenant's allocation or router, or be one another tenant's
 *     template reads too; the reconciliation excludes all of those from its
 *     orphans, and the waiver uses that ONE definition rather than a second
 *     one free to disagree. A reconciliation that cannot be built (an
 *     AllocationError: no instance domain, a template that no longer parses)
 *     waives nothing.
 *
 * What it does NOT prove: under a template that names no tenant
 * (`pattern.namesTenant` false) the reconciliation lists every account the
 * pattern reads and nobody else claims, a non-site account included. That is
 * the same unproven ownership the reconciliation screen states before it
 * offers "Créer le site", and the creation is a platform-admin gesture.
 *
 * Anything else is false and the format judge applies, exactly as on
 * POST /api/sites: the waiver must not turn this endpoint into a format-free
 * creation path for an arbitrary code. Reads the inventory as RECORDED and
 * dials nothing; a row vanishing between this read and the INSERT only means
 * a code was admitted on the strength of a read a moment old.
 */
async function codeIsDeployedLogin(
  tenantId: number,
  tenantSlug: string,
  code: string,
  name: string,
  country: string | null,
): Promise<boolean> {
  const policy = (await db('tenant_allocation_policies')
    .where({ tenant_id: tenantId })
    .first('ppp_login_template', 'concentrator_id')) as
    | Pick<PolicyRow, 'ppp_login_template' | 'concentrator_id'>
    | undefined;
  if (!policy) return false;
  const parsed = parseLoginTemplate(policy.ppp_login_template);
  if (!parsed.ok || !parsed.template.uses.has('site.code')) return false;
  const rendered = renderPppLogin(
    parsed.template,
    { siteName: name, siteCode: code, siteCountry: country, tenantSlug, instanceDomain: await readInstanceDomain(db) },
    `"${code}" (${name})`,
  );
  if (!rendered.ok) return false;
  const login = rendered.login.toLowerCase();
  // The cheap read first: with no such account, there is no report to build.
  const live = await db('concentrator_ppp_secrets')
    .where({ concentrator_id: policy.concentrator_id })
    .whereNull('vanished_at')
    .whereRaw('lower(name) = ?', [login])
    .first('name');
  if (live === undefined) return false;
  let report: ReconcileReport;
  try {
    report = await reconcileTenant(tenantId);
  } catch (err) {
    if (err instanceof AllocationError) return false;
    throw err;
  }
  return report.orphans.some(
    (o) =>
      o.account.declared &&
      Number(o.account.concentratorId) === Number(policy.concentrator_id) &&
      o.account.name.toLowerCase() === login &&
      !o.blockers.some((b) => LOGIN_OWNERSHIP_BLOCKERS.has(b)),
  );
}

/** The adoption blockers that say the login is not (only) this orphan's to
 *  claim. Address and profile blockers are left out on purpose: they stop the
 *  ALLOCATION from adopting the account (the reconciliation shows them, and
 *  `allocateForSite` refuses by name), but they say nothing about whose
 *  store the code names. */
const LOGIN_OWNERSHIP_BLOCKERS: ReadonlySet<AdoptBlocker> = new Set<AdoptBlocker>([
  'ambiguous',
  'sessionOnly',
  'otherTenant',
  'sharedLogin',
  'loginTaken',
  'otherConcentrator',
]);

export interface CreatedSite {
  id: number;
  tenantId: number;
  code: string;
  name: string;
  country: string | null;
}

/**
 * Create one site in `tenantId` — the tenant named by the caller, NOT the
 * caller's session tenant — with a code, a name and an optional country. For
 * an orphan of the reconciliation: the site the next allocation adopts the
 * account for. It allocates nothing and writes nothing to a CHR.
 *
 * The country is why this is not POST /api/sites: that route takes no country
 * (createSiteSchema has none), and under a "{site.country}_{site.code}"
 * template a site created without one renders "0042..." instead of the live
 * "fr_0042..." — the exact mismatch this screen exists to catch. Code and name
 * are judged by createSiteSchema itself, so the two creation paths cannot
 * disagree on what a code may LOOK like; the tenant's site code format
 * (migration 052) is judged by `createSite`, as on POST /api/sites, except
 * for a code whose login a live account carries that this tenant's
 * reconciliation lists as its orphan (`codeIsDeployedLogin`): that one is
 * created with `deployedLogin`, the format waived and the site-number
 * sibling check kept.
 */
export async function createSiteForTenant(tenantId: number, input: unknown): Promise<CreatedSite> {
  assertId(tenantId, 'tenantId', PG_INT_MAX);
  const body = typeof input === 'object' && input !== null && !Array.isArray(input) ? (input as Record<string, unknown>) : {};
  const parsed = createSiteSchema.pick({ code: true, name: true }).safeParse({ code: body.code, name: body.name });
  const details: Record<string, string[]> = {};
  if (!parsed.success) {
    for (const [k, v] of Object.entries(parsed.error.flatten().fieldErrors)) if (v && v.length > 0) details[k] = v;
  }
  const country = normalizeCountry(body.country);
  if (!country.ok) details.country = [country.error];
  if (!parsed.success || !country.ok) {
    throw new AllocationError('INVALID_INPUT', 'the site cannot be created as described.', details);
  }
  const tenant = (await db('tenants').where({ id: tenantId }).first('id', 'slug')) as
    | { id: number; slug: string }
    | undefined;
  if (!tenant) {
    throw new AllocationError('TENANT_NOT_FOUND', `tenant ${tenantId} does not exist.`);
  }
  const deployedLogin = await codeIsDeployedLogin(tenantId, tenant.slug, parsed.data.code, parsed.data.name, country.country);
  try {
    const row = await createSite(
      tenantId,
      { code: parsed.data.code, name: parsed.data.name, country: country.country },
      { deployedLogin },
    );
    return { id: row.id, tenantId: row.tenant_id, code: row.code, name: row.name, country: row.country };
  } catch (err) {
    if (isPgError(err, '23505')) {
      throw new AllocationError('CONFLICT', `tenant ${tenantId} already has a site with code "${parsed.data.code}".`);
    }
    throw err;
  }
}
