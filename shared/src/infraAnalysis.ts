// ============================================================================
// @obliwan/shared — infrastructure analysis: reading a template's SITE
// variables off the routers already in service
// ============================================================================
//
// A customer's routers were configured long before ObliWAN, and what they run
// is the truth: a generator's output is not (a fleet "all on DHCP, all in
// Europe/Paris" on paper turns out to carry dozens of PPPoE stores and a few
// DOM-TOM time zones on the routers). The analysis (server:
// services/infraAnalysis/) reads, READ-ONLY and over each router's existing
// SSH transport, the values of the site-level variables a template declares,
// and proposes them per site.
//
// WHAT TO READ IS DATA, NOT CODE. A template author states, on each site-level
// property of the `var_schema`, how its value appears on a router, with the
// `x-obliwan-discover` keyword below. The server holds no per-customer rule:
// the same reader serves every template that carries probes.
//
// ┌─ THE PROBE GRAMMAR (`x-obliwan-discover`) ───────────────────────────────┐
// │ An object with these fields, and no other:                               │
// │                                                                          │
// │   menu      REQUIRED. One of DISCOVER_MENUS, written with slashes        │
// │             ("/interface/pppoe-client"). An allow-list: a probe can only │
// │             ever make the server PRINT a property of one of these menus │
// │             — no command, no `find` expression, no path of its own.     │
// │   where     A LIST menu only. { property: value, … } (1..8 entries):     │
// │             the items whose property, as RouterOS's `:tostr` prints it, │
// │             EQUALS the value (a boolean is "true"/"false"). Judged by   │
// │             the server on what the router printed — never spliced into │
// │             a router command. Never a sensitive property.               │
// │   property  The property to read: of the ONE matching item (list menu)  │
// │             or of the menu itself (singleton menu). None matching is    │
// │             "not found", several is "ambiguous" — never the first one.  │
// │   present   Instead of `property`: the value when at least one item     │
// │             matches. A JSON scalar; when the variable declares an       │
// │             `enum`, it must be in it.                                   │
// │   absent    Only beside `present`: the value when NO item matches (same │
// │             rules). Leave it out unless an absence really proves that   │
// │             value — see PRESENT-ONLY below.                             │
// │   sensitive true when `property` is a secret (a password, a key, a PIN).│
// │             Required for every property DISCOVER_MENUS or               │
// │             SENSITIVE_PROPERTY_RE call sensitive, and allowed exactly   │
// │             on a variable declared `x-obliwan-secret`: the value goes to│
// │             the vault, is read only when the operator asks for secrets  │
// │             AND the SSH account's group holds RouterOS's `sensitive`    │
// │             policy, and is never sent to a browser.                     │
// │   omitWhenEquals  A key declared in the same var_schema. When the value │
// │             read equals what that key resolves to for the site, the     │
// │             site needs no value of its own (it inherits): nothing is    │
// │             proposed, and a site value already stored is proposed for   │
// │             removal. Never with `sensitive`.                            │
// │                                                                          │
// │ Only a property declared `x-obliwan-level: "site"` may carry a probe:   │
// │ the analysis writes site values, and only site values.                  │
// │                                                                          │
// │ PRESENT-ONLY (`present` without `absent`) — ASYMMETRIC, like             │
// │ deadmanReadiness() (deviceMode.ts): a POSITIVE observation may propose a │
// │ value, an ABSENCE never does. When no item matches, the probe has NO     │
// │ reading (`not_seen`): nothing proposed, nothing confirmed — never "same",│
// │ never a write — and a value stored for the site is left alone. Use it   │
// │ whenever "no such item" fits SEVERAL values: no enabled PPPoE client on  │
// │ ether1-WAN1 is a DHCP store, a fixed-IP store and a client on a VLAN     │
// │ alike. The pair form `"present": "pppoe", "absent": "dhcp"` read a       │
// │ fixed-IP store as dhcp — "same" against the dhcp default, and a static  │
// │ set by hand proposed back to dhcp, which cuts the store on the next      │
// │ render.                                                                  │
// │                                                                          │
// │ CONDITIONS AND ALTERNATIVES — positive-only, like present-only:          │
// │   unless  [ { menu, where }, … ] (1..4, list menus): selections that    │
// │           must match NOTHING. One item matching any of them and the     │
// │           probe has no reading (`not_seen`). On a property read or a    │
// │           present-only probe, never beside `absent`.                    │
// │   single  true, present-only only: the item must be the ONLY match;     │
// │           several are `ambiguous`, never "present".                     │
// │   else    present-only only: the next present-only probe, tried ONLY    │
// │           when this one has no reading (an unreadable or ambiguous      │
// │           probe stops the chain). First reading wins; at most 4 probes; │
// │           `omitWhenEquals` on the first one only.                       │
// │ E.g. wan1_mode = pppoe when an enabled client sits on the port, else    │
// │ static when ONE enabled non-dynamic address sits on it, unless a DHCP   │
// │ client is enabled on the port or any PPPoE client is enabled:           │
// │   { …pppoe probe…, "present": "pppoe", "else": { "menu": "/ip/address",  │
// │     "where": { "interface": "ether1-WAN1", "disabled": false,           │
// │                "dynamic": false }, "present": "static", "single": true, │
// │     "unless": [ { "menu": "/ip/dhcp-client", "where": { "interface":    │
// │                   "ether1-WAN1", "disabled": false } },                  │
// │                 { "menu": "/interface/pppoe-client",                    │
// │                   "where": { "disabled": false } } ] } }                 │
// │ Every other outcome reads nothing: never "dhcp" by absence.             │
// │                                                                          │
// │ Example — a WAN mode, its PPPoE login, password and interface name, the  │
// │ selection keyed on the PORT the client sits on, never on its name:       │
// │   wan1_mode: { "menu": "/interface/pppoe-client",                        │
// │                "where": { "interface": "ether1-WAN1",                    │
// │                           "disabled": false },                           │
// │                "present": "pppoe" }               (present-only)         │
// │   wan1_pppoe_name: { …same menu and where…, "property": "name" }         │
// │   wan1_pppoe_password: { …, "property": "password", "sensitive": true }  │
// │   site_timezone: { "menu": "/system/clock", "property": "time-zone-name" }│
// │                                                                          │
// │ `where` selects on exactly what it names and nothing else: a DISABLED    │
// │ item matches unless `where` says `"disabled": false`. Say it whenever    │
// │ the probe means "the item in service" — a store moved from PPPoE to DHCP │
// │ that kept its old client disabled would otherwise read as PPPoE, with   │
// │ the old login, and a disabled client beside the live one would make    │
// │ every read of that port `ambiguous`. The disabled item is then reported │
// │ in `elsewhere`, named.                                                   │
// └──────────────────────────────────────────────────────────────────────────┘
//
// Items of a list menu that do NOT satisfy `where` are reported beside the
// finding (`elsewhere`, named by their `name` and their `where` properties):
// a PPPoE client sitting on another port than the one the template expects is
// a finding in itself, not a silent "absent".
//
// This file holds the grammar, its validator (run by the template validator
// at authoring and import time, and by the server again before a read), and
// the types the API answers in. PURE: no I/O.

import type { JsonValue } from './tenantSetup';

/** The `var_schema` keyword a probe lives under. */
export const DISCOVER_KEYWORD = 'x-obliwan-discover' as const;

export type DiscoverMenuKind = 'list' | 'singleton';

export interface DiscoverMenuSpec {
  /** A list menu has items (`find`); a singleton menu is one set of
   *  properties (`/system clock`). */
  kind: DiscoverMenuKind;
  /** The menu as the console spells it, with spaces: the slash form is
   *  RouterOS 7 only, the spaced one is read by 6 and 7 alike. */
  console: string;
  /** Properties of this menu that are secrets on RouterOS (printed only to an
   *  account holding the `sensitive` policy). A probe reading one must say
   *  `sensitive: true`. */
  sensitive: readonly string[];
}

/**
 * The menus a probe may read — the whole reach of the grammar. Adding one is
 * a code change reviewed like any other: each entry is a menu the server will
 * `:foreach … find` and `get` over the console of a router in service.
 */
export const DISCOVER_MENUS: Readonly<Record<string, DiscoverMenuSpec>> = Object.freeze({
  '/interface/pppoe-client': { kind: 'list', console: '/interface pppoe-client', sensitive: ['password'] },
  '/interface/l2tp-client': { kind: 'list', console: '/interface l2tp-client', sensitive: ['password', 'ipsec-secret'] },
  '/interface/lte': { kind: 'list', console: '/interface lte', sensitive: ['pin'] },
  '/interface/lte/apn': { kind: 'list', console: '/interface lte apn', sensitive: ['password'] },
  '/interface/ethernet': { kind: 'list', console: '/interface ethernet', sensitive: [] },
  '/interface/bridge': { kind: 'list', console: '/interface bridge', sensitive: [] },
  '/interface/vlan': { kind: 'list', console: '/interface vlan', sensitive: [] },
  '/interface/list/member': { kind: 'list', console: '/interface list member', sensitive: [] },
  '/interface/wireless': { kind: 'list', console: '/interface wireless', sensitive: [] },
  '/interface/wifi': { kind: 'list', console: '/interface wifi', sensitive: ['security.passphrase'] },
  '/ip/address': { kind: 'list', console: '/ip address', sensitive: [] },
  '/ip/dhcp-client': { kind: 'list', console: '/ip dhcp-client', sensitive: [] },
  '/ip/dhcp-server': { kind: 'list', console: '/ip dhcp-server', sensitive: [] },
  '/ip/dhcp-server/network': { kind: 'list', console: '/ip dhcp-server network', sensitive: [] },
  '/ip/route': { kind: 'list', console: '/ip route', sensitive: [] },
  '/ip/dns': { kind: 'singleton', console: '/ip dns', sensitive: [] },
  '/system/clock': { kind: 'singleton', console: '/system clock', sensitive: [] },
  '/system/identity': { kind: 'singleton', console: '/system identity', sensitive: [] },
  '/system/ntp/client': { kind: 'singleton', console: '/system ntp client', sensitive: [] },
  '/snmp': { kind: 'singleton', console: '/snmp', sensitive: [] },
});

/** The fields a probe may carry. Any other is refused by name. */
export const DISCOVER_PROBE_FIELDS = [
  'menu', 'where', 'property', 'present', 'absent', 'sensitive', 'omitWhenEquals',
  'unless', 'single', 'else',
] as const;

/** The fields of one `unless` selection. */
export const DISCOVER_UNLESS_FIELDS = ['menu', 'where'] as const;
/** Selections one `unless` may list. */
export const MAX_UNLESS_ENTRIES = 4;
/** Probes one `else` chain may hold, the first one included. */
export const MAX_ELSE_CHAIN = 4;

/**
 * A RouterOS property name: lowercase words joined by `-`, optionally dotted
 * (`security.passphrase` on the wifi stack). It is the only text of a probe
 * that reaches a router command, so it admits nothing a console would read as
 * syntax.
 */
export const DISCOVER_PROPERTY_RE = /^[a-z][a-z0-9-]{0,63}(\.[a-z][a-z0-9-]{0,63}){0,2}$/;

/**
 * A property name that LOOKS like a secret, whatever the menu: a password, a
 * pre-shared key, a passphrase, a PIN, any `*-key` or `*-secret`. Wider than
 * RouterOS's own list on purpose — an over-match only forces the author to
 * write `sensitive: true` (fail closed), an under-match would send a secret
 * to a browser.
 */
export const SENSITIVE_PROPERTY_RE = /(^|[-.])(password|passwd|secret|psk|passphrase|pin|key)($|[-.])/;

/** A `where` value, an `absent`/`present` value: printable, bounded. */
const MAX_PROBE_TEXT = 128;
const MAX_WHERE_ENTRIES = 8;
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u001f\u007f]/;
const VARIABLE_KEY_RE = /^[a-z][a-zA-Z0-9_]{0,119}$/;

export type DiscoverScalar = string | number | boolean;

export interface DiscoverProbe {
  menu: string;
  where?: Record<string, DiscoverScalar>;
  property?: string;
  present?: DiscoverScalar;
  absent?: DiscoverScalar;
  sensitive?: boolean;
  omitWhenEquals?: string;
  /** Selections that must match NOTHING for the probe to have a reading: one
   *  item matching any of them and the probe reads nothing (`not_seen`). On a
   *  property read or a present-only probe — never beside `absent`. */
  unless?: DiscoverSelection[];
  /** Present-only: the item must be the ONLY match — several are ambiguous. */
  single?: boolean;
  /** Present-only: the next alternative, tried only when this one has no
   *  reading (`not_seen`). Itself present-only. First reading wins. */
  else?: DiscoverProbe;
}

/** A selection of a list menu: the items whose properties equal `where`. */
export interface DiscoverSelection {
  menu: string;
  where: Record<string, DiscoverScalar>;
}

/** One refusal, located inside the probe (`path` is relative to it). */
export interface DiscoverProblem {
  path: string[];
  message: string;
}

/** Is this property a secret on this menu (by RouterOS's list or by name)? */
export function isSensitiveDiscoverProperty(menu: string, property: string): boolean {
  const spec = Object.prototype.hasOwnProperty.call(DISCOVER_MENUS, menu) ? DISCOVER_MENUS[menu] : undefined;
  if (spec && spec.sensitive.includes(property)) return true;
  return SENSITIVE_PROPERTY_RE.test(property);
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function scalarProblem(v: unknown): string | null {
  if (typeof v === 'string') {
    if (v.length === 0 || v.length > MAX_PROBE_TEXT) return `must be a text of 1 to ${MAX_PROBE_TEXT} characters`;
    if (CONTROL_RE.test(v)) return 'must not contain a control character';
    return null;
  }
  if (typeof v === 'number') return Number.isFinite(v) ? null : 'must be a finite number';
  if (typeof v === 'boolean') return null;
  return 'must be a text, a number or a boolean';
}

/** How a `where` value or a printed value is compared: RouterOS's `:tostr`. */
export function discoverText(v: DiscoverScalar): string {
  return typeof v === 'string' ? v : String(v);
}

/**
 * A PRESENT-ONLY probe: it tests for an item and states only what a MATCH
 * means (`present` without `absent`, no `property`). When nothing matches it
 * has no reading at all — see the grammar header.
 */
export function isPresentOnlyProbe(probe: Pick<DiscoverProbe, 'property' | 'present' | 'absent'>): boolean {
  return probe.property === undefined && probe.present !== undefined && probe.absent === undefined;
}

/** The problems of one `where` object (of a probe or of an `unless` entry). */
function whereProblems(
  where: unknown,
  menuText: string,
  path: string[],
  add: (path: string[], message: string) => void,
): void {
  if (!isPlainObject(where)) {
    add(path, 'where must be an object { property: value }');
    return;
  }
  const entries = Object.entries(where);
  if (entries.length === 0 || entries.length > MAX_WHERE_ENTRIES) {
    add(path, `where must name 1 to ${MAX_WHERE_ENTRIES} properties`);
  }
  for (const [p, v] of entries) {
    if (!DISCOVER_PROPERTY_RE.test(p)) {
      add([...path, p], `"${p}" is not a RouterOS property name (lowercase words joined by "-")`);
    } else if (isSensitiveDiscoverProperty(menuText, p)) {
      add([...path, p], `"${p}" is a sensitive property: a probe never selects items by a secret`);
    }
    const problem = scalarProblem(v);
    if (problem) add([...path, p], `the value of "${p}" ${problem}`);
  }
}

/**
 * Everything wrong with one probe, or [] when it is well formed.
 *
 * `property` is the variable's own JSON Schema (the one carrying the probe);
 * `declared(key)` answers whether the same var_schema declares `key`. Every
 * message starts with the keyword, so a refusal read out of context still
 * names what it is about.
 */
export function discoverProbeProblems(
  raw: unknown,
  ctx: { key: string; property: Record<string, unknown>; declared: (key: string) => boolean },
  /** Internal: the position of this probe in an `else` chain (1 = the top). */
  depth = 1,
): DiscoverProblem[] {
  const out: DiscoverProblem[] = [];
  const add = (path: string[], message: string): void => {
    out.push({ path, message: `${DISCOVER_KEYWORD}: ${message}` });
  };
  if (!isPlainObject(raw)) {
    add([], 'must be an object (menu, where, property | present [+ absent], sensitive, omitWhenEquals)');
    return out;
  }
  for (const k of Object.keys(raw)) {
    if (!(DISCOVER_PROBE_FIELDS as readonly string[]).includes(k)) {
      add([k], `unknown field "${k}" — a probe carries ${DISCOVER_PROBE_FIELDS.join(', ')} only`);
    }
  }

  const level = ctx.property['x-obliwan-level'];
  if (level !== 'site') {
    add([], 'only a variable declared "x-obliwan-level": "site" may carry a probe — the analysis proposes site values and nothing else');
  }
  const secret = ctx.property['x-obliwan-secret'] === true;

  const menu = raw.menu;
  let spec: DiscoverMenuSpec | null = null;
  if (typeof menu !== 'string' || !Object.prototype.hasOwnProperty.call(DISCOVER_MENUS, menu)) {
    add(['menu'], `menu must be one of ${Object.keys(DISCOVER_MENUS).join(', ')}`);
  } else {
    spec = DISCOVER_MENUS[menu];
  }
  const menuText = typeof menu === 'string' ? menu : '';

  // where
  if (raw.where !== undefined) {
    if (spec && spec.kind === 'singleton') {
      add(['where'], `"${menuText}" is a single set of properties, not a list: "where" has nothing to select`);
    }
    whereProblems(raw.where, menuText, ['where'], add);
  }

  // the mode: property XOR present (with absent beside it, or alone: the
  // present-only, asymmetric form). An absent WITHOUT present is refused: it
  // would make an absence the only thing the probe can say.
  const hasProperty = raw.property !== undefined;
  const hasPresent = raw.present !== undefined;
  const hasAbsent = raw.absent !== undefined;
  if (hasProperty && (hasPresent || hasAbsent)) {
    add([], 'give either "property" (read a value) or "present" (test for an item, "absent" beside it only when an absence proves a value), not both');
  } else if (!hasProperty && !hasPresent) {
    add([], hasAbsent
      ? '"absent" needs "present": the value when an item matches comes first, and an absence alone proves nothing'
      : 'say what to read: "property", or "present" (with "absent" only when an absence proves a value)');
  }

  if (hasProperty) {
    const p = raw.property;
    if (typeof p !== 'string' || !DISCOVER_PROPERTY_RE.test(p)) {
      add(['property'], 'property must be a RouterOS property name (lowercase words joined by "-")');
    } else if (isSensitiveDiscoverProperty(menuText, p) && raw.sensitive !== true) {
      add(['sensitive'], `"${p}" is a sensitive property: the probe must say "sensitive": true, so the value is read only on request and never shown`);
    }
  }
  if (hasPresent || hasAbsent) {
    if (spec && spec.kind === 'singleton') {
      add([], `"${menuText}" is a single set of properties: it is always there, "present"/"absent" cannot tell anything`);
    }
    for (const f of ['present', 'absent'] as const) {
      if (raw[f] === undefined) continue;
      const problem = scalarProblem(raw[f]);
      if (problem) add([f], `${f} ${problem}`);
    }
    if (hasPresent && hasAbsent && raw.present === raw.absent) {
      add([], '"present" and "absent" are the same value: the probe could not tell anything');
    }
    const en = ctx.property.enum;
    if (Array.isArray(en)) {
      for (const f of ['present', 'absent'] as const) {
        if (raw[f] !== undefined && !en.some((e) => e === raw[f])) {
          add([f], `${f} must be one of the variable's enum (${en.map((e) => JSON.stringify(e)).join(', ')})`);
        }
      }
    }
  }

  // sensitive
  if (raw.sensitive !== undefined && typeof raw.sensitive !== 'boolean') {
    add(['sensitive'], 'sensitive must be true or false');
  }
  if (raw.sensitive === true) {
    if (!hasProperty) add(['sensitive'], '"sensitive" applies to a property read, never to a present/absent test');
    if (!secret) {
      add(['sensitive'], 'a sensitive value goes to the vault: the variable must be declared "x-obliwan-secret": true');
    }
  }
  if (secret && raw.sensitive !== true) {
    add(['sensitive'], 'the variable is declared "x-obliwan-secret": its probe must say "sensitive": true');
  }

  // omitWhenEquals
  if (raw.omitWhenEquals !== undefined) {
    const k = raw.omitWhenEquals;
    if (typeof k !== 'string' || !VARIABLE_KEY_RE.test(k)) {
      add(['omitWhenEquals'], 'omitWhenEquals must name a variable');
    } else if (k === ctx.key) {
      add(['omitWhenEquals'], 'omitWhenEquals must name ANOTHER variable (the one the site inherits from)');
    } else if (!ctx.declared(k)) {
      add(['omitWhenEquals'], `omitWhenEquals names "${k}", which this template does not declare`);
    }
    if (raw.sensitive === true || secret) {
      add(['omitWhenEquals'], 'omitWhenEquals compares a value with another variable\'s: never on a secret');
    }
    if (depth > 1) add(['omitWhenEquals'], 'omitWhenEquals belongs to the first probe of an "else" chain only');
  }

  const presentOnly = !hasProperty && hasPresent && !hasAbsent;

  // unless — selections that must match nothing, else the probe reads nothing
  if (raw.unless !== undefined) {
    if (hasAbsent) {
      add(['unless'], '"unless" turns a match into NO reading: it cannot sit beside "absent", which would read that as a value');
    }
    if (!Array.isArray(raw.unless) || raw.unless.length === 0 || raw.unless.length > MAX_UNLESS_ENTRIES) {
      add(['unless'], `unless must be a list of 1 to ${MAX_UNLESS_ENTRIES} selections { menu, where }`);
    } else {
      raw.unless.forEach((sel: unknown, i: number) => {
        const at = ['unless', String(i)];
        if (!isPlainObject(sel)) {
          add(at, 'each "unless" entry must be an object { menu, where }');
          return;
        }
        for (const k of Object.keys(sel)) {
          if (!(DISCOVER_UNLESS_FIELDS as readonly string[]).includes(k)) {
            add([...at, k], `unknown field "${k}" — an "unless" entry carries ${DISCOVER_UNLESS_FIELDS.join(', ')} only`);
          }
        }
        const m = sel.menu;
        if (typeof m !== 'string' || !Object.prototype.hasOwnProperty.call(DISCOVER_MENUS, m) || DISCOVER_MENUS[m].kind !== 'list') {
          add([...at, 'menu'], 'an "unless" menu must be one of the LIST menus of DISCOVER_MENUS');
        }
        if (sel.where === undefined) add([...at, 'where'], 'an "unless" entry needs "where": it names the items that must not exist');
        else whereProblems(sel.where, typeof m === 'string' ? m : '', [...at, 'where'], add);
      });
    }
  }

  // single — a present-only probe whose item must be the only match
  if (raw.single !== undefined) {
    if (typeof raw.single !== 'boolean') add(['single'], 'single must be true or false');
    else if (raw.single && !presentOnly) {
      add(['single'], '"single" applies to a present-only probe (a property read is already single by construction)');
    }
  }

  // else — the next alternative, tried only when this one reads nothing
  if (raw.else !== undefined) {
    if (!presentOnly) {
      add(['else'], '"else" follows a present-only probe only: no other probe has a "no reading" to fall through');
    }
    if (depth >= MAX_ELSE_CHAIN) {
      add(['else'], `an "else" chain holds at most ${MAX_ELSE_CHAIN} probes`);
    } else if (!isPlainObject(raw.else)) {
      add(['else'], 'else must be a probe object');
    } else {
      const next = raw.else;
      if (!(next.property === undefined && next.present !== undefined && next.absent === undefined)) {
        add(['else'], 'the "else" probe must itself be present-only ("present", no "absent", no "property")');
      }
      for (const p of discoverProbeProblems(next, ctx, depth + 1)) {
        out.push({ path: ['else', ...p.path], message: p.message });
      }
    }
  }
  return out;
}

/**
 * Every probe problem of a whole `var_schema` (`properties.<key>.x-obliwan-discover`),
 * with the path from the schema root. The template validator and the import
 * validator both reach it through `varSchemaSchema`.
 */
export function varSchemaDiscoverProblems(varSchema: unknown): DiscoverProblem[] {
  if (!isPlainObject(varSchema) || !isPlainObject(varSchema.properties)) return [];
  const props = varSchema.properties;
  const declared = (k: string): boolean => Object.prototype.hasOwnProperty.call(props, k);
  const out: DiscoverProblem[] = [];
  for (const key of Object.keys(props)) {
    const p = props[key];
    if (!isPlainObject(p) || !Object.prototype.hasOwnProperty.call(p, DISCOVER_KEYWORD)) continue;
    for (const problem of discoverProbeProblems(p[DISCOVER_KEYWORD], { key, property: p, declared })) {
      out.push({ path: ['properties', key, DISCOVER_KEYWORD, ...problem.path], message: problem.message });
    }
  }
  return out;
}

/** The probes of a `var_schema`, well-formed ones only, in declaration order. */
export function probesOf(varSchema: unknown): Array<{ key: string; probe: DiscoverProbe; property: Record<string, unknown> }> {
  if (!isPlainObject(varSchema) || !isPlainObject(varSchema.properties)) return [];
  const props = varSchema.properties;
  const declared = (k: string): boolean => Object.prototype.hasOwnProperty.call(props, k);
  const out: Array<{ key: string; probe: DiscoverProbe; property: Record<string, unknown> }> = [];
  for (const key of Object.keys(props)) {
    const p = props[key];
    if (!isPlainObject(p) || !Object.prototype.hasOwnProperty.call(p, DISCOVER_KEYWORD)) continue;
    const raw = p[DISCOVER_KEYWORD];
    if (discoverProbeProblems(raw, { key, property: p, declared }).length > 0) continue;
    out.push({ key, probe: raw as DiscoverProbe, property: p });
  }
  return out;
}

// ============================================================================
// The API: /api/infra-analysis (platform admin, the session's workspace)
// ============================================================================

/** Devices one analysis may read. A workspace of a few hundred stores fits. */
export const INFRA_ANALYSIS_MAX_DEVICES = 500;
/** How long an analysis — and the secrets it read — stays in memory after
 *  its run ends. */
export const INFRA_ANALYSIS_TTL_MS = 15 * 60_000;
/** Rows one apply may carry. */
export const INFRA_ANALYSIS_MAX_APPLY_ROWS = 5000;

/** Which devices to read. `all`: every device of the workspace; a site
 *  range: the devices of the sites whose code lies between the bounds
 *  (inclusive; compared as numbers when both sides are all digits). */
export type InfraAnalysisSelection =
  | { all: true }
  | { deviceIds: number[] }
  | { siteCodeFrom?: string; siteCodeTo?: string };

export interface InfraAnalysisPreviewRequest {
  selection: InfraAnalysisSelection;
  /** The revision whose probes to run; absent: each device's own (its
   *  template assignment). */
  revisionId?: string;
  /** For this run only — never stored. Absent: each device's SSH transport. */
  credential?: { username: string; password: string };
  /** Read sensitive properties (PPPoE passwords…) too. They stay on the
   *  server, for this analysis, and are never sent back. */
  readSecrets: boolean;
  /** The interface carrying the store LAN (the built-in LAN probe). Absent:
   *  the one bridge with an address, preferring a member of the LAN list. */
  lanInterface?: string;
}

/** Why a device was not read (`skipped`) or its read failed (`failed`). */
export const INFRA_DEVICE_REASONS = [
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
  'internal',
] as const;
export type InfraDeviceReason = (typeof INFRA_DEVICE_REASONS)[number];

/** Why a value could not be read. */
export const INFRA_UNREADABLE_REASONS = [
  /** The menu does not exist on this router (no LTE package, the other Wi-Fi
   *  stack, a RouterOS without it): the read printed nothing it asked for. */
  'menu_unavailable',
  /** The router refused to print this property for this item. */
  'property_error',
  /** What came back is not what was printed (its length disagrees): a value
   *  with a line break, a character the transport could not carry. */
  'garbled',
  /** A sensitive property came back empty or masked: the account may not see
   *  it, whatever its group says. Never taken for a real empty value. */
  'hidden',
  /** The SSH account's group lacks RouterOS's `sensitive` policy. */
  'no_sensitive_policy',
  /** The account's policy could not be read: no sensitive read is attempted. */
  'policy_unknown',
] as const;
export type InfraUnreadableReason = (typeof INFRA_UNREADABLE_REASONS)[number];

export type InfraFound =
  /** A value, typed against the variable's schema. */
  | { status: 'found'; value: JsonValue }
  /** A secret was read: it is held server-side for this analysis only. */
  | { status: 'secret_found' }
  /** The value equals what `equalsKey` resolves to: the site inherits it. */
  | { status: 'omitted'; equalsKey: string }
  | { status: 'not_found' }
  /** A present-only probe (`present` without `absent`) saw no matching item.
   *  An absence proves no value: nothing is proposed or confirmed, and what
   *  the site stores is left alone. */
  | { status: 'not_seen' }
  /** Several items match `where`: no value is guessed. */
  | { status: 'ambiguous'; count: number }
  /** A sensitive property, and the operator did not ask for secrets. */
  | { status: 'not_read' }
  | { status: 'unreadable'; reason: InfraUnreadableReason };

/**
 *  same     the router agrees with what the site resolves to.
 *  differs  something resolves (a stored value or the schema default) and the
 *           router says otherwise.
 *  new      nothing resolves for the site, the router has a value.
 *  invalid  the value read does not satisfy the variable's schema.
 *  conflict two routers of the same site disagree.
 *  none     nothing read to compare — including the absence a present-only
 *           probe saw (`not_seen`), which is never compared with anything.
 */
export type InfraVerdict = 'same' | 'differs' | 'new' | 'invalid' | 'conflict' | 'none';

/** What the site resolves to today, at which level. A secret's value is never
 *  sent — `present` says whether one is stored. */
export interface InfraStoredView {
  present: boolean;
  /** Absent for a secret, and when nothing resolves. */
  value?: JsonValue;
  /** 'instance' | 'global' | 'tenant' | 'group' | 'site' | 'device' | 'default'. */
  level: string | null;
  isSecret: boolean;
}

/** An item of the probe's menu that does NOT satisfy its `where`. */
export interface InfraElsewhereItem {
  name: string | null;
  /** The item's value of each `where` property, as printed. */
  values: Record<string, string>;
}

export interface InfraVariableResult {
  key: string;
  label: string | null;
  secret: boolean;
  found: InfraFound;
  elsewhere: InfraElsewhereItem[];
  stored: InfraStoredView;
  verdict: InfraVerdict;
  /** Why the value read does not satisfy the schema (a secret: ajv's
   *  keyword only, never anything derived from the value). */
  invalidReasons: string[];
  /** What an apply of this row would do. */
  action: 'write' | 'unset' | null;
  /** Set once an apply wrote this row. */
  appliedAt?: string;
}

export interface InfraLanFinding {
  status: 'found' | 'not_found' | 'ambiguous' | 'unreadable';
  interface: string | null;
  /** network/prefix, e.g. 10.20.30.0/27 */
  lan: string | null;
  routerIp: string | null;
  /** The addresses considered, when the choice was ambiguous (at most 8). */
  candidates: Array<{ interface: string; address: string }>;
}

export interface InfraDeviceResult {
  deviceId: number;
  deviceName: string;
  site: { id: number; code: string; name: string } | null;
  state: 'pending' | 'done' | 'skipped' | 'failed';
  reason: InfraDeviceReason | null;
  /** The transport's own words, scrubbed of every credential. */
  detail: string | null;
  revision: { id: string; templateName: string; revision: number; status: string } | null;
  /** The device has no template assignment and no revision was named: only
   *  the built-in LAN probe ran. */
  noRevision: boolean;
  credentialSource: 'device' | 'operator' | null;
  /** The SSH account's `sensitive` policy, read only when secrets were asked
   *  for and a probe needed it. */
  sensitivePolicy: 'not_needed' | 'granted' | 'missing' | 'unknown' | null;
  variables: InfraVariableResult[];
  lan: InfraLanFinding | null;
}

export interface InfraAnalysisCounts {
  devices: number;
  done: number;
  skipped: number;
  failed: number;
  /** Rows an apply would write or unset. */
  proposals: number;
  /** Secrets held server-side for this analysis. */
  secretsHeld: number;
  lanFound: number;
  /** Devices where at least one probe saw items of its menu that its `where`
   *  did not select (a PPPoE client on another port, a disabled one): a
   *  finding the verdicts alone do not show — a "dhcp, same" row can sit
   *  beside a PPPoE client on ether2. */
  elsewhere: number;
}

export interface InfraAnalysisSnapshot {
  analysisId: string;
  tenantId: number;
  status: 'running' | 'done';
  readSecrets: boolean;
  credentialSource: 'device' | 'operator';
  /** The revision named for every device, or null (each device's own). */
  revisionId: string | null;
  lanInterface: string | null;
  startedAt: string;
  finishedAt: string | null;
  /** When the analysis and its secrets are forgotten. */
  expiresAt: string;
  progress: { total: number; done: number };
  counts: InfraAnalysisCounts;
  devices: InfraDeviceResult[];
}

/** A device the page offers, with why it would be skipped. */
export interface InfraAnalysisCandidate {
  deviceId: number;
  deviceName: string;
  site: { id: number; code: string; name: string } | null;
  status: string;
  hasSsh: boolean;
  /** null: it would be read. */
  skip: InfraDeviceReason | null;
}

/** A revision visible to the workspace that carries probes. */
export interface InfraAnalysisRevisionOption {
  id: string;
  templateName: string;
  revision: number;
  status: string;
  library: boolean;
  probeKeys: string[];
}

export interface InfraAnalysisCandidates {
  devices: InfraAnalysisCandidate[];
  revisions: InfraAnalysisRevisionOption[];
}

export interface InfraAnalysisApplyRequest {
  analysisId: string;
  rows: Array<{ siteId: number; key: string }>;
}

export const INFRA_APPLY_REFUSALS = [
  /** No such site/key in this analysis. */
  'unknown_row',
  /** Nothing to write for this row (same, not found, unreadable…). */
  'not_applicable',
  /** Two routers of the site disagree. */
  'conflict',
  /** The value does not satisfy a declaration of the key. */
  'invalid',
  /** The site's write was refused by the variable store (all its rows). */
  'write_failed',
] as const;
export type InfraApplyRefusal = (typeof INFRA_APPLY_REFUSALS)[number];

export interface InfraAnalysisApplyResult {
  analysisId: string;
  written: Array<{ siteId: number; code: string; keys: string[]; unset: string[] }>;
  refused: Array<{ siteId: number; key: string; reason: InfraApplyRefusal; detail: string | null }>;
}

export interface InfraAnalysisExport {
  variables: { filename: string; csv: string; rows: number };
  lan: { filename: string; csv: string; rows: number };
}
