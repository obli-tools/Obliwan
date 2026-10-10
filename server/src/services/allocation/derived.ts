import { formulaUsesId, parseAddressFormula, renderAddressFormula, type AddressFormula } from './formula';
import { cidrLast, formatIpv4, parseCidr } from './policy';
import { parseLoginTemplate, renderPppLogin, siteNumber, type LoginTemplate, type LoginVars } from './pppIdentity';

/**
 * derived.ts — further values a tenant's templates declare at level
 * 'computed', derived from what the allocator gave a site. PURE.
 *
 * The converted customer templates consume more than the login, the identity
 * and the LAN: a router address inside the LAN (`cidrHost(lan_subnet, 70)`), a
 * probe address (`cidrHost(lan_subnet, 1)`), a DHCP range
 * (`cidrHost(lan_subnet, 10)-cidrHost(lan_subnet, -2)`), a loopback computed
 * from the site number (`10.255.{id/100%100}.{id%100}`), a second login equal
 * to the code (`{site.code}`). Each tenant's policy maps a key to ONE of these
 * four closed forms; nothing else parses:
 *
 *   cidrHost(lan_subnet, N)                        a host of the site's LAN; N < 0
 *                                                  counts back from the broadcast
 *                                                  (-2 = the last usable host)
 *   cidrHost(lan_subnet, A)-cidrHost(lan_subnet, B) a range "first-last"
 *   an address formula on id                       formula.ts's own parser
 *   a template of the login placeholders           pppIdentity.ts's own parser
 *
 * Values are recomputed on every read from what is STORED (the site's LAN, its
 * code), never stored themselves: a derived value is a function of the
 * allocation, and a second copy of it would be free to disagree with the first.
 */

export const DERIVED_MAX = 20;
export const DERIVED_EXPR_MAX = 200;
/** Keys the allocator itself produces; a derived value may not shadow one. */
export const DERIVED_RESERVED_KEYS = [
  'site_code',
  'ppp_username',
  'ppp_password',
  'tunnel_ip',
  'lan_subnet',
  'system_identity',
] as const;
const KEY_RE = /^[a-z][a-z0-9_]{0,63}$/;
const HOST_RE = /^cidrHost\(\s*lan_subnet\s*,\s*(-?\d{1,10})\s*\)$/;
const RANGE_RE =
  /^cidrHost\(\s*lan_subnet\s*,\s*(-?\d{1,10})\s*\)\s*-\s*cidrHost\(\s*lan_subnet\s*,\s*(-?\d{1,10})\s*\)$/;

export type DerivedExpr =
  | { kind: 'host'; source: string; index: number }
  | { kind: 'range'; source: string; from: number; to: number }
  | { kind: 'address'; source: string; formula: AddressFormula }
  | { kind: 'text'; source: string; template: LoginTemplate };

export interface DerivedValue {
  key: string;
  expr: DerivedExpr;
}

export type DerivedExprParse = { ok: true; expr: DerivedExpr } | { ok: false; error: string };

export function parseDerivedExpression(raw: unknown): DerivedExprParse {
  if (typeof raw !== 'string' || raw.trim() === '') return { ok: false, error: 'the expression is empty.' };
  const src = raw.trim();
  if (src.length > DERIVED_EXPR_MAX) {
    return { ok: false, error: `the expression is longer than ${DERIVED_EXPR_MAX} characters.` };
  }
  if (src.startsWith('cidrHost')) {
    const range = RANGE_RE.exec(src);
    if (range) return { ok: true, expr: { kind: 'range', source: src, from: Number(range[1]), to: Number(range[2]) } };
    const host = HOST_RE.exec(src);
    if (host) return { ok: true, expr: { kind: 'host', source: src, index: Number(host[1]) } };
    return {
      ok: false,
      error:
        'cidrHost takes the LAN and one integer: cidrHost(lan_subnet, 1), or a range ' +
        'cidrHost(lan_subnet, 10)-cidrHost(lan_subnet, -2).',
    };
  }
  if (/\{(site|tenant|instance)\./.test(src)) {
    const t = parseLoginTemplate(src);
    return t.ok
      ? { ok: true, expr: { kind: 'text', source: src, template: t.template } }
      : { ok: false, error: t.error.replace(/PPP login template/g, 'text template') };
  }
  const outsideBraces = src.replace(/\{[^}]*\}/g, '');
  const f = parseAddressFormula(src, { prefix: outsideBraces.includes('/') ? 'required' : 'forbidden' });
  if (!f.ok) return { ok: false, error: f.error };
  if (!formulaUsesId(f.formula)) {
    return {
      ok: false,
      error: 'the formula never uses id, so it is the same on every site: make it a tenant variable instead.',
    };
  }
  return { ok: true, expr: { kind: 'address', source: src, formula: f.formula } };
}

export type DerivedValuesParse =
  | { ok: true; values: DerivedValue[] }
  | { ok: false; errors: Record<string, string[]> };

/** `raw` is null/undefined (none) or an object { key: expression }. */
export function parseDerivedValues(raw: unknown): DerivedValuesParse {
  if (raw === undefined || raw === null) return { ok: true, values: [] };
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, errors: { derived: ['derived must be an object { key: expression }.'] } };
  }
  const entries = Object.entries(raw as Record<string, unknown>);
  const errors: Record<string, string[]> = {};
  if (entries.length > DERIVED_MAX) errors.derived = [`at most ${DERIVED_MAX} derived values.`];
  const values: DerivedValue[] = [];
  for (const [key, source] of entries) {
    const field = `derived.${key}`;
    if (!KEY_RE.test(key)) {
      (errors[field] ??= []).push('a key is lowercase letters, digits and "_", starting with a letter (max 64).');
      continue;
    }
    if ((DERIVED_RESERVED_KEYS as readonly string[]).includes(key)) {
      (errors[field] ??= []).push(`"${key}" is produced by the allocator itself and cannot be redefined.`);
      continue;
    }
    const p = parseDerivedExpression(source);
    if (!p.ok) (errors[field] ??= []).push(p.error);
    else values.push({ key, expr: p.expr });
  }
  return Object.keys(errors).length > 0 ? { ok: false, errors } : { ok: true, values };
}

/** The stored (JSON) form: { key: source }. */
export function derivedToJson(values: readonly DerivedValue[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const v of values) out[v.key] = v.expr.source;
  return out;
}

export interface DerivedContext {
  lanSubnet: string | null;
  login: LoginVars;
  siteLabel: string;
}

export type DerivedEvaluation =
  | { ok: true; values: Record<string, string> }
  | { ok: false; key: string; message: string };

function lanHost(lan: string | null, index: number): { ok: true; text: string } | { ok: false; error: string } {
  if (lan === null) return { ok: false, error: 'this site has no LAN subnet, so cidrHost(lan_subnet, …) has nothing to count in.' };
  const c = parseCidr(lan);
  if (!c.ok) return { ok: false, error: `the site's LAN "${lan}" is not a CIDR block.` };
  const size = cidrLast(c.cidr) - c.cidr.network + 1;
  const address = index >= 0 ? c.cidr.network + index : c.cidr.network + size + index;
  const inside = address > c.cidr.network && address < cidrLast(c.cidr);
  if (!inside || c.cidr.prefix > 30) {
    return {
      ok: false,
      error: `host ${index} of ${lan} is not a usable host (the network, the broadcast or outside the block).`,
    };
  }
  return { ok: true, text: formatIpv4(address) };
}

export function evaluateDerived(values: readonly DerivedValue[], ctx: DerivedContext): DerivedEvaluation {
  const out: Record<string, string> = {};
  for (const { key, expr } of values) {
    const refuse = (message: string): DerivedEvaluation => ({
      ok: false,
      key,
      message: `site ${ctx.siteLabel}: derived value "${key}" (${expr.source}): ${message}`,
    });
    switch (expr.kind) {
      case 'host': {
        const h = lanHost(ctx.lanSubnet, expr.index);
        if (!h.ok) return refuse(h.error);
        out[key] = h.text;
        break;
      }
      case 'range': {
        const a = lanHost(ctx.lanSubnet, expr.from);
        if (!a.ok) return refuse(a.error);
        const b = lanHost(ctx.lanSubnet, expr.to);
        if (!b.ok) return refuse(b.error);
        out[key] = `${a.text}-${b.text}`;
        break;
      }
      case 'address': {
        const n = siteNumber(ctx.login.siteCode);
        if (n === null) return refuse(`it is computed from the site number, and code "${ctx.login.siteCode}" is not all digits.`);
        const r = renderAddressFormula(expr.formula, n);
        if (!r.ok) return refuse(r.error);
        out[key] = r.text;
        break;
      }
      case 'text': {
        const r = renderPppLogin(expr.template, ctx.login, ctx.siteLabel);
        if (!r.ok) return refuse(r.message.replace(/^site [^:]*: /, ''));
        out[key] = r.login;
        break;
      }
    }
  }
  return { ok: true, values: out };
}
