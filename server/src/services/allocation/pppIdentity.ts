import crypto from 'crypto';
import { instanceDomainError } from '@obliwan/shared';

/**
 * pppIdentity.ts — the PPP login and password a provisioned site is given.
 *
 * PURE. No database, no vault, no socket: the harness runs it without either,
 * and a module that cannot read a secret cannot leak one. The allocator owns
 * the duplicate lookups and the encryption; this file owns the SPELLING.
 *
 * Both values end up on a RouterOS command line — the login in
 * `/ppp secret add name=...` on the concentrator and in the CPE's L2TP client,
 * the password beside it — so both are built only from characters that need no
 * quoting: `[A-Za-z0-9._-]` for the login, base62 for the password. No escaper
 * ever has to be right about them. Migration 036 restates the login alphabet as
 * a CHECK; the password is vaulted and cannot be checked there, which is why
 * the harness asserts its alphabet against the change renderer's own secret
 * guard.
 *
 * ┌─ THE LOGIN TEMPLATE ─────────────────────────────────────────────────────┐
 * │ Per tenant, e.g. "{site.slug}.{site.country}.{tenant.slug}.{instance.domain}" │
 * │ -> "lyon-part-dieu.fr.acme.customers.example".                           │
 * │                                                                          │
 * │   {site.slug}       the site NAME, lowercased, accents folded, spaces    │
 * │                     and underscores turned into '-', everything outside  │
 * │                     [a-z0-9-] dropped, dashes collapsed and trimmed.     │
 * │   {site.country}    ISO 3166-1 alpha-2, lowercased. OPTIONAL: a site     │
 * │                     with no country drops the placeholder AND one        │
 * │                     adjacent '.' or '_', so the result never holds "..", │
 * │                     nor a leading or trailing separator. The template is │
 * │                     refused unless the placeholder is bounded by '.' or  │
 * │                     '_' or by the template's ends: "fr_0042.acme" with a │
 * │                     country, "0042.acme" without.                        │
 * │   {site.id}         the site NUMBER: the site code read as an integer    │
 * │                     ("0001" -> 1) — the same `id` the address formulas   │
 * │                     use. Not the database row id. A non-numeric code is  │
 * │                     refused, naming the site.                            │
 * │   {site.code}       the site code exactly as stored.                     │
 * │   {tenant.slug}     the tenant's slug exactly as stored.                 │
 * │   {instance.domain} ONE value per installation (shared/src/settings.ts,  │
 * │                     INSTANCE_SETTINGS_KEYS). Empty while the template    │
 * │                     uses it is a refusal, never a silent omission.       │
 * │                                                                          │
 * │ Literal text keeps its CASE: "{site.slug}.VPN" renders ".VPN". Nothing   │
 * │ here lowercases a whole login; duplicate detection is case-INSENSITIVE   │
 * │ instead, in the allocator, because "Lyon.VPN" and "lyon.vpn" are two     │
 * │ strings and one confusion on a CHR screen.                               │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

// ============================================================================
// Site facts
// ============================================================================

/**
 * The site NUMBER behind a code: all digits, leading zeros allowed ("0001" is
 * 1). `null` for any other code — a formula tenant refuses such a site by name
 * rather than inventing a number. Bounded to 15 significant digits so the value
 * is an exact JavaScript integer.
 */
export function siteNumber(code: string): number | null {
  if (!/^[0-9]+$/.test(code)) return null;
  const significant = code.replace(/^0+(?=[0-9])/, '');
  if (significant.length > 15) return null;
  return Number(significant);
}

/** Letters NFKD does not decompose, folded by hand so they keep a letter. */
const HAND_FOLDS: ReadonlyArray<[RegExp, string]> = [
  [/œ/g, 'oe'],
  [/æ/g, 'ae'],
  [/ß/g, 'ss'],
  [/ø/g, 'o'],
  [/ł/g, 'l'],
  [/đ/g, 'd'],
];

/**
 * A site name as a login component: "Lyon Part-Dieu" -> "lyon-part-dieu",
 * "Saint-Étienne_Centre" -> "saint-etienne-centre", "St. Denis" -> "st-denis".
 * '' when nothing usable is left — the caller refuses rather than inventing.
 */
export function siteSlug(name: string): string {
  let s = name.normalize('NFKD').replace(/[̀-ͯ]/g, '').toLowerCase();
  for (const [re, to] of HAND_FOLDS) s = s.replace(re, to);
  return s
    .replace(/[\s_]+/g, '-')
    .replace(/[^a-z0-9-]/g, '')
    .replace(/-{2,}/g, '-')
    .replace(/^-+|-+$/g, '');
}

export type CountryParse = { ok: true; country: string | null } | { ok: false; error: string };

/**
 * A site's country as stored in `sites.country`: two UPPERCASE letters, or
 * null. Accepts either case on input ('fr' -> 'FR'); refuses anything that is
 * not two ASCII letters. Whether the pair is an ASSIGNED ISO 3166-1 code is not
 * judged — the list changes, and the CHECK in migration 036 judges the shape
 * only, the same way.
 */
export function normalizeCountry(raw: unknown): CountryParse {
  if (raw === undefined || raw === null) return { ok: true, country: null };
  if (typeof raw !== 'string') return { ok: false, error: 'country must be a string or null.' };
  const t = raw.trim();
  if (t === '') return { ok: true, country: null };
  if (!/^[A-Za-z]{2}$/.test(t)) {
    return { ok: false, error: `country "${t}" is not an ISO 3166-1 alpha-2 code (two letters).` };
  }
  return { ok: true, country: t.toUpperCase() };
}

// ============================================================================
// Login template
// ============================================================================

export const LOGIN_PLACEHOLDERS = [
  'site.slug',
  'site.country',
  'site.id',
  'site.code',
  'tenant.slug',
  'instance.domain',
] as const;
export type LoginPlaceholder = (typeof LOGIN_PLACEHOLDERS)[number];

/** Placeholders that differ from one site to the next. A template must hold
 *  one, or every site of the tenant would render the same login. */
export const LOGIN_SITE_PLACEHOLDERS: readonly LoginPlaceholder[] = ['site.slug', 'site.id', 'site.code'];

/**
 * Upper bound on a rendered login. The column holds 128; 64 is a conservative
 * bound chosen here, NOT a measured RouterOS or CPE limit — a CPE whose L2TP
 * username field is shorter would truncate it silently and the tunnel would
 * never come up. A longer login is REFUSED, never truncated: a truncated login
 * that ends inside the domain is a different identity, not a shorter one.
 *
 * `INSTANCE_DOMAIN_MAX_LENGTH` (shared/src/settings.ts, which cannot import
 * this file) is PPP_LOGIN_MAX - 2, the room "a." leaves; the harness asserts
 * the two stay in step. `minimalLoginLength` judges each template against it.
 */
export const PPP_LOGIN_MAX = 64;

export const LOGIN_TEMPLATE_MAX = 200;

const LOGIN_CHAR_RE = /^[A-Za-z0-9._-]$/;

/** The separators an absent {site.country} takes with it: "." in
 *  "{site.slug}.{site.country}.acme", "_" in "{site.country}_{site.code}.acme".
 *  `includes('')` is false, so an empty neighbour never counts as one. */
const COUNTRY_SEPARATORS = ['.', '_'];
const LOGIN_RE = /^[A-Za-z0-9._-]+$/;
const ALNUM_RE = /^[A-Za-z0-9]$/;

export type LoginSegment =
  | { kind: 'literal'; text: string }
  | { kind: 'placeholder'; name: LoginPlaceholder };

export interface LoginTemplate {
  source: string;
  segments: LoginSegment[];
  uses: ReadonlySet<LoginPlaceholder>;
}

export type LoginTemplateParse = { ok: true; template: LoginTemplate } | { ok: false; error: string };

function isPlaceholder(name: string): name is LoginPlaceholder {
  return (LOGIN_PLACEHOLDERS as readonly string[]).includes(name);
}

/** Parse and judge a login template. Every rule here is one a site could
 *  otherwise break at the bench; see the box at the top of this file. */
export function parseLoginTemplate(text: unknown): LoginTemplateParse {
  if (typeof text !== 'string' || text.trim() === '') {
    return {
      ok: false,
      error: 'the PPP login template is required, e.g. {site.slug}.{site.country}.{tenant.slug}.{instance.domain}.',
    };
  }
  const src = text.trim();
  if (src.length > LOGIN_TEMPLATE_MAX) {
    return { ok: false, error: `the PPP login template is longer than ${LOGIN_TEMPLATE_MAX} characters.` };
  }

  const segments: LoginSegment[] = [];
  let literal = '';
  for (let i = 0; i < src.length; i += 1) {
    const ch = src[i];
    if (ch === '{') {
      const close = src.indexOf('}', i + 1);
      const open = src.indexOf('{', i + 1);
      if (close < 0 || (open >= 0 && open < close)) {
        return { ok: false, error: `the "{" at position ${i + 1} is never closed.` };
      }
      const name = src.slice(i + 1, close);
      if (!isPlaceholder(name)) {
        return {
          ok: false,
          error: `unknown placeholder {${name}}; allowed: ${LOGIN_PLACEHOLDERS.map((p) => `{${p}}`).join(', ')}.`,
        };
      }
      if (literal !== '') segments.push({ kind: 'literal', text: literal });
      literal = '';
      segments.push({ kind: 'placeholder', name });
      i = close;
      continue;
    }
    if (ch === '}') return { ok: false, error: `the "}" at position ${i + 1} closes nothing.` };
    if (!LOGIN_CHAR_RE.test(ch)) {
      return {
        ok: false,
        error: `"${ch}" cannot appear in a PPP login; literal text may hold letters, digits, ".", "_" and "-".`,
      };
    }
    literal += ch;
  }
  if (literal !== '') segments.push({ kind: 'literal', text: literal });

  const uses = new Set<LoginPlaceholder>();
  for (const s of segments) if (s.kind === 'placeholder') uses.add(s.name);

  if (!LOGIN_SITE_PLACEHOLDERS.some((p) => uses.has(p))) {
    return {
      ok: false,
      error:
        'the PPP login template must contain {site.slug}, {site.id} or {site.code}, or every site ' +
        'of the tenant would get the same login.',
    };
  }
  for (const s of segments) {
    if (s.kind === 'literal' && s.text.includes('..')) {
      return { ok: false, error: 'the PPP login template contains "..".' };
    }
  }
  const first = segments[0];
  const last = segments[segments.length - 1];
  if (first.kind === 'literal' && !ALNUM_RE.test(first.text[0])) {
    return { ok: false, error: 'the PPP login template must start with a letter, a digit or a placeholder.' };
  }
  if (last.kind === 'literal' && !ALNUM_RE.test(last.text[last.text.length - 1])) {
    return { ok: false, error: 'the PPP login template must end with a letter, a digit or a placeholder.' };
  }
  // {site.country} may vanish, and takes ONE '.' with it: it must therefore be
  // bounded by a '.' or by an end of the template on each side.
  for (let i = 0; i < segments.length; i += 1) {
    const s = segments[i];
    if (s.kind !== 'placeholder' || s.name !== 'site.country') continue;
    const before = segments[i - 1];
    const after = segments[i + 1];
    const okBefore = !before || (before.kind === 'literal' && COUNTRY_SEPARATORS.includes(before.text.slice(-1)));
    const okAfter = !after || (after.kind === 'literal' && COUNTRY_SEPARATORS.includes(after.text[0]));
    if (!okBefore || !okAfter) {
      return {
        ok: false,
        error:
          '{site.country} is optional and drops itself with one adjacent "." or "_" when a site has ' +
          'no country, so it must sit between such separators (or at an end of the template), e.g. ' +
          '{site.slug}.{site.country}.{tenant.slug} or {site.country}_{site.code}.{tenant.slug}.',
      };
    }
  }
  return { ok: true, template: { source: src, segments, uses } };
}

export interface LoginVars {
  siteName: string;
  siteCode: string;
  /** Stored form (uppercase) or null. */
  siteCountry: string | null;
  tenantSlug: string;
  /** '' when the installation has none. */
  instanceDomain: string;
}

export type LoginRefusalReason =
  | 'LOGIN_INVALID'
  | 'SITE_CODE_NOT_NUMERIC'
  | 'INSTANCE_DOMAIN_MISSING'
  | 'INSTANCE_DOMAIN_INVALID';

export type LoginRender =
  | { ok: true; login: string }
  | { ok: false; reason: LoginRefusalReason; message: string };

/**
 * Join a template's segments with their values, dropping an empty
 * {site.country} together with ONE adjacent separator ("." or "_"): the
 * following one if there is one, else the preceding one. `parseLoginTemplate` refused the template unless
 * both neighbours of that placeholder are a dot or an end.
 */
function assembleLogin(t: LoginTemplate, values: ReadonlyMap<LoginPlaceholder, string>): string {
  const parts: string[] = t.segments.map((s) =>
    s.kind === 'literal' ? s.text : (values.get(s.name) ?? ''),
  );
  const drop = t.segments.map(
    (s) => s.kind === 'placeholder' && s.name === 'site.country' && values.get(s.name) === '',
  );
  for (let i = 0; i < parts.length; i += 1) {
    if (!drop[i]) continue;
    const next = i + 1 < parts.length && !drop[i + 1] ? i + 1 : -1;
    const prev = i - 1 >= 0 && !drop[i - 1] ? i - 1 : -1;
    if (next >= 0 && COUNTRY_SEPARATORS.includes(parts[next][0])) parts[next] = parts[next].slice(1);
    else if (prev >= 0 && COUNTRY_SEPARATORS.includes(parts[prev].slice(-1))) parts[prev] = parts[prev].slice(0, -1);
  }
  return parts.filter((_, i) => !drop[i]).join('');
}

/**
 * The length of the SHORTEST login `t` can render for any site of a tenant
 * whose slug is `ctx.tenantSlug`: a one-character site name, code and number,
 * and no country. Checked where a template or the installation domain is
 * SAVED, so that a combination no site can ever fit under PPP_LOGIN_MAX is
 * refused at the operator's desk — not at every allocation, with a message
 * telling the operator to shorten a site name that is not the problem.
 */
export function minimalLoginLength(
  t: LoginTemplate,
  ctx: { tenantSlug: string; instanceDomain: string },
): number {
  const values = new Map<LoginPlaceholder, string>([
    ['site.slug', 'a'],
    ['site.id', '1'],
    ['site.code', '1'],
    ['site.country', ''],
    ['tenant.slug', ctx.tenantSlug],
    ['instance.domain', ctx.instanceDomain.trim()],
  ]);
  return assembleLogin(t, values).length;
}

/**
 * Render a login for one site. `siteLabel` names the site in every refusal
 * (e.g. `"0042" (Lyon Part-Dieu)`), because a bulk import of three hundred
 * sites must say WHICH one is wrong.
 */
export function renderPppLogin(t: LoginTemplate, vars: LoginVars, siteLabel: string): LoginRender {
  const refuse = (reason: LoginRefusalReason, message: string): LoginRender => ({
    ok: false,
    reason,
    message: `site ${siteLabel}: ${message}`,
  });

  const values = new Map<LoginPlaceholder, string>();
  for (const name of t.uses) {
    switch (name) {
      case 'site.slug': {
        const slug = siteSlug(vars.siteName);
        if (slug === '') {
          return refuse(
            'LOGIN_INVALID',
            `its name "${vars.siteName}" keeps no letter or digit once normalised, so {site.slug} ` +
              'would be empty. Rename the site, then retry the allocation.',
          );
        }
        values.set(name, slug);
        break;
      }
      case 'site.country': {
        const c = normalizeCountry(vars.siteCountry);
        if (!c.ok) return refuse('LOGIN_INVALID', c.error);
        values.set(name, c.country === null ? '' : c.country.toLowerCase());
        break;
      }
      case 'site.id': {
        const n = siteNumber(vars.siteCode);
        if (n === null) {
          return refuse(
            'SITE_CODE_NOT_NUMERIC',
            `{site.id} is the site number, and code "${vars.siteCode}" is not all digits. Give the ` +
              "site a numeric code, or take {site.id} out of the tenant's login template.",
          );
        }
        values.set(name, String(n));
        break;
      }
      case 'site.code':
        if (vars.siteCode === '' || !LOGIN_RE.test(vars.siteCode)) {
          return refuse(
            'LOGIN_INVALID',
            `code "${vars.siteCode}" holds characters a PPP login cannot carry (allowed: letters, ` +
              'digits, ".", "_" and "-"). Use {site.slug} in the template, or change the code.',
          );
        }
        values.set(name, vars.siteCode);
        break;
      case 'tenant.slug':
        if (vars.tenantSlug === '' || !LOGIN_RE.test(vars.tenantSlug)) {
          return refuse(
            'LOGIN_INVALID',
            `the tenant slug "${vars.tenantSlug}" holds characters a PPP login cannot carry ` +
              '(allowed: letters, digits, ".", "_" and "-"). Change the tenant slug, then retry.',
          );
        }
        values.set(name, vars.tenantSlug);
        break;
      case 'instance.domain': {
        const d = vars.instanceDomain.trim();
        if (d === '') {
          return refuse(
            'INSTANCE_DOMAIN_MISSING',
            'the login template uses {instance.domain} and this installation has no domain set. Set ' +
              'it with PUT /api/allocation/instance-domain, then retry the allocation.',
          );
        }
        const err = instanceDomainError(d);
        if (err !== null) {
          return refuse(
            'INSTANCE_DOMAIN_INVALID',
            `the installation domain is invalid (${err}). Correct it with PUT ` +
              '/api/allocation/instance-domain, then retry the allocation.',
          );
        }
        values.set(name, d);
        break;
      }
    }
  }

  const login = assembleLogin(t, values);

  if (login === '' || !LOGIN_RE.test(login)) {
    return refuse('LOGIN_INVALID', `the template renders "${login}", which is not a usable PPP login.`);
  }
  if (login.includes('..') || !ALNUM_RE.test(login[0]) || !ALNUM_RE.test(login[login.length - 1])) {
    return refuse(
      'LOGIN_INVALID',
      `the template renders "${login}", which has "..", or starts or ends with something other ` +
        'than a letter or a digit.',
    );
  }
  if (login.length > PPP_LOGIN_MAX) {
    return refuse(
      'LOGIN_INVALID',
      `the template renders "${login}" (${login.length} characters), longer than the ` +
        `${PPP_LOGIN_MAX} allowed. Shorten the site's name or code, or the tenant's login template, ` +
        'then retry.',
    );
  }
  return { ok: true, login };
}

// ============================================================================
// System identity — a second template over the same placeholders
// ============================================================================

/**
 * The RouterOS system identity is a template of its own (e.g. login
 * "{site.code}.acme.customers", identity "{site.country}_{site.code}.acme.cust.example").
 * Same placeholders, same alphabet, same length bound and the same
 * country-drop rule as the login, because it is spliced into the same kind of
 * command line (`/system identity set name=...`) and must need no quoting
 * either. Only the vocabulary of the messages differs, so the operator reads
 * which of the two templates is wrong.
 */
function asIdentityMessage(message: string): string {
  return message
    .replace(/PPP login template/g, 'system identity template')
    .replace(/login template/g, 'identity template')
    .replace(/a PPP login/g, 'a system identity')
    .replace(/PPP login/g, 'system identity');
}

export function parseIdentityTemplate(text: unknown): LoginTemplateParse {
  if (typeof text !== 'string' || text.trim() === '') {
    return {
      ok: false,
      error: 'the system identity template is empty, e.g. {site.code}.{tenant.slug}.cust.example.',
    };
  }
  const r = parseLoginTemplate(text);
  return r.ok ? r : { ok: false, error: asIdentityMessage(r.error) };
}

export type IdentityRender =
  | { ok: true; identity: string }
  | { ok: false; reason: Exclude<LoginRefusalReason, 'LOGIN_INVALID'> | 'IDENTITY_INVALID'; message: string };

export function renderSystemIdentity(t: LoginTemplate, vars: LoginVars, siteLabel: string): IdentityRender {
  const r = renderPppLogin(t, vars, siteLabel);
  if (r.ok) return { ok: true, identity: r.login };
  return {
    ok: false,
    reason: r.reason === 'LOGIN_INVALID' ? 'IDENTITY_INVALID' : r.reason,
    message: asIdentityMessage(r.message),
  };
}

// ============================================================================
// Password
// ============================================================================

/**
 * Base62. Not one character here is special to RouterOS — no quote, no `$`,
 * no `\`, no `;`, no bracket or brace, no backtick, no whitespace — so the
 * password can sit bare in `password=` on the CHR and on the CPE and no quoting
 * rule has to be right about it. The harness checks this against the change
 * renderer's own secret guard rather than trusting this sentence.
 */
export const PPP_PASSWORD_ALPHABET =
  '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

/** 20 base62 characters ≈ 119 bits. */
export const PPP_PASSWORD_LENGTH = 20;

/**
 * Largest multiple of 62 that fits in a byte. A byte at or above it is thrown
 * away instead of being reduced modulo 62, which would make the first eight
 * characters of the alphabet slightly likelier than the rest.
 */
const REJECTION_BOUND = Math.floor(256 / PPP_PASSWORD_ALPHABET.length) * PPP_PASSWORD_ALPHABET.length;

/**
 * A fresh PPP password from the OS CSPRNG. The randomness source is injectable
 * ONLY so the harness can prove the rejection sampling; production callers pass
 * nothing.
 *
 * The returned string is a plaintext: the allocator encrypts it before
 * it leaves the function that asked for it, and it is never logged.
 */
export function generatePppPassword(
  randomBytes: (size: number) => Buffer = crypto.randomBytes,
): string {
  let out = '';
  while (out.length < PPP_PASSWORD_LENGTH) {
    const chunk = randomBytes(32);
    for (const byte of chunk) {
      if (byte >= REJECTION_BOUND) continue;
      out += PPP_PASSWORD_ALPHABET[byte % PPP_PASSWORD_ALPHABET.length];
      if (out.length === PPP_PASSWORD_LENGTH) break;
    }
  }
  return out;
}
