import {
  DISCOVER_MENUS,
  DISCOVER_PROPERTY_RE,
  MAX_ELSE_CHAIN,
  coerceVariableCell,
  discoverText,
  isPresentOnlyProbe,
  isSensitiveDiscoverProperty,
  type DiscoverProbe,
  type DiscoverScalar,
  type InfraElsewhereItem,
  type InfraLanFinding,
  type InfraUnreadableReason,
  type JsonValue,
} from '@obliwan/shared';

/**
 * probes.ts — the console side of the infrastructure analysis: the READ
 * commands a probe turns into, the parse of what they print, and the verdict
 * of a probe on that parse. PURE: no socket, no database — the harness drives
 * every function here with printed text.
 *
 * ┌─ WHAT REACHES A ROUTER ──────────────────────────────────────────────────┐
 * │ Only text built HERE, from three kinds of token:                          │
 * │  - a menu, as DISCOVER_MENUS spells it for the console (an allow-list);  │
 * │  - property names matching DISCOVER_PROPERTY_RE (lowercase words, `-`,  │
 * │    `.`): nothing a console could read as syntax;                         │
 * │  - an item id the router itself printed, re-checked as `*<hex>`.         │
 * │ A probe's `where` VALUES never reach a router: every item is printed and │
 * │ the selection is judged on the printed text, here. So a template cannot  │
 * │ make the server send a quote, a bracket or a `;`.                        │
 * │ Every command is a `:put` of values: none changes the router.            │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ A SENSITIVE PROPERTY IS NEVER IN A MENU READ ───────────────────────────┐
 * │ `menuReadCommand` refuses one. A secret is read by `sensitiveReadCommand`│
 * │ alone, for the ONE item the probe selected, and only once the caller has │
 * │ checked that secrets were asked for and that the account's group holds  │
 * │ the `sensitive` policy. So "no sensitive read happened" is provable from │
 * │ the command audit: no audited line names the property.                  │
 * │                                                                          │
 * │ The read is a script `get`, not `print show-sensitive`: `print` formats  │
 * │ for a terminal (columns, quoting, wrapping) and its flag is spelt        │
 * │ differently on RouterOS 6 and 7 (cf. the export's `hide-sensitive` /    │
 * │ `show-sensitive`, drivers/mikrotik/driver.ts), while `get` hands the     │
 * │ script the value itself, which RouterOS gives only to an account whose  │
 * │ group holds `sensitive`. An empty or all-`*` answer is `hidden`, never a │
 * │ value. That `get` behaves so on both majors is REASONED, not observed.  │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * THE PRINTED FORMAT, and what keeps it honest. Every value is printed as
 * `pv|<id>|<property>|<length>|<value>` with `:len` of the value, so a value
 * holding a line break (or a character the transport mangled) reads as
 * `garbled`, never as a shorter value. Each menu read first prints how many
 * items `find` returned (`n|<count>`), and the parse refuses the read when it
 * saw another number of items or another number of value lines per item: a
 * value that spans lines cannot forge an item. A sentinel `end|` is printed
 * last; its absence means the script did not run (a menu this RouterOS does
 * not have is a syntax error, which runs nothing) — `menu_unavailable`.
 * That RouterOS prints `:tostr` of a boolean as true/false and of a list
 * joined with `;`, and that `get` on a missing property is a runtime error
 * `on-error` catches, is REASONED from the RouterOS manual, not observed.
 */

/** Items one menu read keeps. A store router has a handful per menu. */
export const MENU_READ_MAX_ITEMS = 256;

/** An item id as RouterOS prints it (`*1`, `*1A`). */
const ITEM_ID_RE = /^\*[0-9A-Fa-f]{1,8}$/;
/** The id the singleton reads print instead of an item id. */
export const SINGLETON_ID = '-';

export class ProbeCommandError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProbeCommandError';
  }
}

function specOf(menu: string) {
  if (!Object.prototype.hasOwnProperty.call(DISCOVER_MENUS, menu)) {
    throw new ProbeCommandError(`menu "${menu}" is not one a probe may read`);
  }
  return DISCOVER_MENUS[menu];
}

function assertProperty(menu: string, property: string): void {
  if (!DISCOVER_PROPERTY_RE.test(property)) {
    throw new ProbeCommandError(`"${property}" is not a RouterOS property name`);
  }
}

/** One `get` of `property`, printed as a length-checked `pv` line. */
function valueLine(consoleMenu: string, ref: string, idExpr: string, property: string): string {
  return (
    `:do { :local v [:tostr [${consoleMenu} get${ref === '' ? '' : ' ' + ref} ${property}]]; ` +
    `:put ("pv|" . ${idExpr} . "|${property}|" . [:len $v] . "|" . $v) } ` +
    `on-error={ :put ("pe|" . ${idExpr} . "|${property}") }`
  );
}

/**
 * The read of `properties` on every item of a list menu, or of the menu
 * itself for a singleton. Throws on a sensitive property — those are read
 * one by one, on request (`sensitiveReadCommand`).
 */
export function menuReadCommand(menu: string, properties: readonly string[]): string {
  const spec = specOf(menu);
  const props = [...new Set(properties)];
  if (props.length === 0) throw new ProbeCommandError('a menu read names at least one property');
  for (const p of props) {
    assertProperty(menu, p);
    if (isSensitiveDiscoverProperty(menu, p)) {
      throw new ProbeCommandError(`"${p}" is sensitive: it is never part of a menu read`);
    }
  }
  if (spec.kind === 'singleton') {
    const lines = props.map((p) => valueLine(spec.console, '', `"${SINGLETON_ID}"`, p));
    return `${lines.join('; ')}; :put "end|"`;
  }
  const per = props.map((p) => valueLine(spec.console, '$i', '$i', p)).join('; ');
  return (
    `:put ("n|" . [:len [${spec.console} find]]); ` +
    `:foreach i in=[${spec.console} find] do={ :put ("it|" . $i); ${per} }; :put "end|"`
  );
}

/** The read of ONE sensitive property: of the item `itemId` (a list menu) or
 *  of the menu (a singleton, `itemId` null). */
export function sensitiveReadCommand(menu: string, itemId: string | null, property: string): string {
  const spec = specOf(menu);
  assertProperty(menu, property);
  let ref = '';
  if (spec.kind === 'list') {
    if (itemId === null || !ITEM_ID_RE.test(itemId)) {
      throw new ProbeCommandError('a sensitive read of a list menu names one item id the router printed');
    }
    ref = ` ${itemId}`;
  }
  return (
    `:do { :local v [:tostr [${spec.console} get${ref} ${property}]]; ` +
    ':put ("sv|" . [:len $v] . "|" . $v) } on-error={ :put "se|" }; :put "end|"'
  );
}

// ============================================================================
// Parse
// ============================================================================

export type PropReading = { ok: true; value: string } | { ok: false; why: 'error' | 'garbled' };

export interface MenuReading {
  /** The script ran to its end. False: the menu does not exist here, or the
   *  script failed to parse — nothing of it can be trusted. */
  ended: boolean;
  /** The output contradicts its own counts: refused as a whole. */
  garbled: boolean;
  /** Item ids in `find` order (`[SINGLETON_ID]` for a singleton). */
  order: string[];
  items: Map<string, Map<string, PropReading>>;
}

function lines(out: string): string[] {
  return out.split('\n').map((l) => (l.endsWith('\r') ? l.slice(0, -1) : l));
}

/** `:len` counts bytes. */
function byteLength(text: string): number {
  return Buffer.byteLength(text, 'utf8');
}

/**
 * The parse of `menuReadCommand(menu, properties)`'s output. Strict on
 * structure (see the header): any contradiction makes the whole reading
 * `garbled`, never a partial one somebody would act on.
 */
export function parseMenuRead(menu: string, properties: readonly string[], out: string): MenuReading {
  const spec = specOf(menu);
  const props = [...new Set(properties)];
  const reading: MenuReading = { ended: false, garbled: false, order: [], items: new Map() };
  let announced: number | null = null;
  let current: string | null = spec.kind === 'singleton' ? SINGLETON_ID : null;
  if (spec.kind === 'singleton') {
    reading.order.push(SINGLETON_ID);
    reading.items.set(SINGLETON_ID, new Map());
  }
  const bad = (): MenuReading => ({ ended: reading.ended, garbled: true, order: [], items: new Map() });

  for (const line of lines(out)) {
    if (line === 'end|') {
      reading.ended = true;
      continue;
    }
    if (reading.ended) {
      if (line.trim() !== '') return bad(); // nothing is printed after the sentinel
      continue;
    }
    if (line.startsWith('n|')) {
      if (spec.kind !== 'list' || announced !== null || !/^\d{1,6}$/.test(line.slice(2))) return bad();
      announced = Number(line.slice(2));
      continue;
    }
    if (line.startsWith('it|')) {
      const id = line.slice(3);
      if (spec.kind !== 'list' || !ITEM_ID_RE.test(id) || reading.items.has(id)) return bad();
      reading.order.push(id);
      reading.items.set(id, new Map());
      current = id;
      continue;
    }
    if (line.startsWith('pv|') || line.startsWith('pe|')) {
      const parts = line.split('|');
      const id = parts[1];
      const prop = parts[2];
      if (current === null || id !== current || !props.includes(prop)) return bad();
      const item = reading.items.get(current)!;
      if (item.has(prop)) return bad();
      if (parts[0] === 'pe') {
        if (parts.length !== 3) return bad();
        item.set(prop, { ok: false, why: 'error' });
        continue;
      }
      if (parts.length < 5 || !/^\d{1,7}$/.test(parts[3])) return bad();
      const value = parts.slice(4).join('|');
      item.set(prop, byteLength(value) === Number(parts[3]) ? { ok: true, value } : { ok: false, why: 'garbled' });
      continue;
    }
    // Anything else before the sentinel: a continuation of a multi-line value
    // (its `pv` line is already `garbled` by its length), or the router's
    // error text when the script did not run (then there is no sentinel).
  }

  if (!reading.ended) return { ended: false, garbled: false, order: [], items: new Map() };
  if (spec.kind === 'list') {
    if (announced === null || announced !== reading.order.length) return bad();
    if (reading.order.length > MENU_READ_MAX_ITEMS) return bad();
  }
  for (const id of reading.order) {
    if (reading.items.get(id)!.size !== props.length) return bad();
  }
  return reading;
}

export type SensitiveReading =
  | { ok: true; value: string }
  | { ok: false; reason: Extract<InfraUnreadableReason, 'property_error' | 'garbled' | 'hidden' | 'menu_unavailable'> };

/**
 * The parse of `sensitiveReadCommand`'s output, judged: an EMPTY value or one
 * made only of `*` is `hidden` — RouterOS masks a secret for an account it
 * will not show it to, and an empty password read back is indistinguishable
 * from a masked one, so neither is ever taken for a real value.
 */
export function parseSensitiveRead(out: string): SensitiveReading {
  let ended = false;
  let found: SensitiveReading | null = null;
  let count = 0;
  for (const line of lines(out)) {
    if (line === 'end|') {
      ended = true;
      continue;
    }
    if (ended) continue;
    if (line === 'se|') {
      count += 1;
      found = { ok: false, reason: 'property_error' };
      continue;
    }
    if (line.startsWith('sv|')) {
      count += 1;
      const parts = line.split('|');
      if (parts.length < 3 || !/^\d{1,7}$/.test(parts[1])) {
        found = { ok: false, reason: 'garbled' };
        continue;
      }
      const value = parts.slice(2).join('|');
      if (byteLength(value) !== Number(parts[1])) found = { ok: false, reason: 'garbled' };
      else if (value === '' || /^\*+$/.test(value)) found = { ok: false, reason: 'hidden' };
      else found = { ok: true, value };
    }
  }
  if (!ended) return { ok: false, reason: 'menu_unavailable' };
  if (count !== 1 || !found) return { ok: false, reason: 'garbled' };
  return found;
}

// ============================================================================
// What a probe needs, and what it concludes
// ============================================================================

/** List menus whose items have NO `name` property. It is never asked of
 *  them: a `get` of a property the menu lacks may be refused when the script
 *  is parsed, which would sink the whole menu read (the LAN probe's
 *  `/ip/address` included). Their `elsewhere` items are named null. */
const NAMELESS_MENUS: ReadonlySet<string> = new Set([
  '/ip/address', '/ip/dhcp-client', '/ip/route', '/ip/dhcp-server/network', '/interface/list/member',
]);

/** The non-sensitive properties a probe needs printed from its menu. `name`
 *  is asked of every list menu that has one, to name the items `elsewhere`
 *  reports. */
export function propertiesFor(probe: DiscoverProbe): string[] {
  const spec = specOf(probe.menu);
  const out = new Set<string>();
  if (spec.kind === 'list' && !NAMELESS_MENUS.has(probe.menu)) out.add('name');
  for (const k of Object.keys(probe.where ?? {})) out.add(k);
  if (probe.property !== undefined && probe.sensitive !== true) out.add(probe.property);
  return [...out].filter((p) => !isSensitiveDiscoverProperty(probe.menu, p));
}

/**
 * Every menu read a probe needs: its own menu (`propertiesFor`), each
 * `unless` selection's (`name` and its `where` properties) and, down an
 * `else` chain, each alternative's. Never a sensitive property.
 */
export function readsFor(probe: DiscoverProbe): Array<{ menu: string; properties: string[] }> {
  const out: Array<{ menu: string; properties: string[] }> = [];
  let cur: DiscoverProbe | undefined = probe;
  for (let i = 0; cur !== undefined && i < MAX_ELSE_CHAIN; i += 1) {
    out.push({ menu: cur.menu, properties: propertiesFor(cur) });
    for (const sel of cur.unless ?? []) {
      specOf(sel.menu);
      // Only the selection's own properties: an `unless` item is never named.
      const props = Object.keys(sel.where ?? {}).filter((p) => !isSensitiveDiscoverProperty(sel.menu, p));
      if (props.length > 0) out.push({ menu: sel.menu, properties: [...new Set(props)] });
    }
    cur = cur.else;
  }
  return out;
}

export type ProbeOutcome =
  | { kind: 'value'; text: string; elsewhere: InfraElsewhereItem[] }
  /** A present/absent PAIR: `present` false means its `absent` value. A
   *  present-only probe is `presence` only when an item matched. `value`:
   *  the value of the `else` alternative that matched (absent: the probe's
   *  own `present`). */
  | { kind: 'presence'; present: boolean; value?: DiscoverScalar; elsewhere: InfraElsewhereItem[] }
  /** A PRESENT-ONLY probe matched nothing: no reading at all — an absence it
   *  was not allowed to interpret. */
  | { kind: 'not_seen'; elsewhere: InfraElsewhereItem[] }
  /** A sensitive property of exactly one item (or of a singleton): read it
   *  with `sensitiveReadCommand(probe.menu, itemId, probe.property)`. */
  | { kind: 'secret_target'; itemId: string | null; elsewhere: InfraElsewhereItem[] }
  | { kind: 'not_found'; elsewhere: InfraElsewhereItem[] }
  | { kind: 'ambiguous'; count: number; elsewhere: InfraElsewhereItem[] }
  | { kind: 'unreadable'; reason: InfraUnreadableReason; elsewhere: InfraElsewhereItem[] };

const MAX_ELSEWHERE = 10;

/**
 * A probe judged on its menu's reading. Fail closed throughout: an item whose
 * `where` property could not be read makes the whole probe unreadable (the
 * item may or may not match — counting it either way would invent a
 * presence or an absence), and several matching items are `ambiguous`, never
 * the first one.
 */
export function evaluateProbe(
  probe: DiscoverProbe,
  reading: MenuReading | undefined | ReadonlyMap<string, MenuReading>,
): ProbeOutcome {
  // A single reading serves the probe's own menu only; a probe with `unless`
  // or `else` on other menus needs the session's map (`readsFor`).
  const lookup = (menu: string): MenuReading | undefined =>
    reading instanceof Map ? reading.get(menu) : menu === probe.menu ? (reading as MenuReading | undefined) : undefined;
  const first = evaluateOne(probe, lookup);
  if (first.kind !== 'not_seen' || probe.else === undefined) return first;
  // `else`: the next alternative, ONLY when this one read nothing. An
  // unreadable or ambiguous alternative stops the chain (fail closed). The
  // `elsewhere` reported stays the first probe's.
  let next: DiscoverProbe | undefined = probe.else;
  for (let i = 1; next !== undefined && i < MAX_ELSE_CHAIN; i += 1) {
    const o = evaluateOne(next, lookup);
    if (o.kind === 'not_seen') {
      next = next.else;
      continue;
    }
    if (o.kind === 'presence' && o.present) return { kind: 'presence', present: true, value: next.present, elsewhere: first.elsewhere };
    return { ...o, elsewhere: first.elsewhere } as ProbeOutcome;
  }
  return first;
}

type Selection = { matched: string[]; elsewhere: InfraElsewhereItem[] } | Extract<ProbeOutcome, { kind: 'unreadable' }>;

/** The items of `reading` whose `where` properties equal the probe's. */
function select(reading: MenuReading | undefined, whereObj: Record<string, unknown> | undefined): Selection {
  if (!reading || !reading.ended) return { kind: 'unreadable', reason: 'menu_unavailable', elsewhere: [] };
  if (reading.garbled) return { kind: 'unreadable', reason: 'garbled', elsewhere: [] };
  const where = Object.entries(whereObj ?? {}) as Array<[string, string | number | boolean]>;
  const matched: string[] = [];
  const elsewhere: InfraElsewhereItem[] = [];
  for (const id of reading.order) {
    const item = reading.items.get(id)!;
    let matches = true;
    const values: Record<string, string> = {};
    for (const [prop, want] of where) {
      const got = item.get(prop);
      if (!got || !got.ok) {
        return { kind: 'unreadable', reason: got && got.why === 'garbled' ? 'garbled' : 'property_error', elsewhere: [] };
      }
      values[prop] = got.value;
      if (got.value !== discoverText(want)) matches = false;
    }
    if (matches) matched.push(id);
    else if (elsewhere.length < MAX_ELSEWHERE) {
      const name = item.get('name');
      elsewhere.push({ name: name && name.ok ? name.value : null, values });
    }
  }
  return { matched, elsewhere };
}

function evaluateOne(probe: DiscoverProbe, lookup: (menu: string) => MenuReading | undefined): ProbeOutcome {
  const spec = specOf(probe.menu);
  const reading = lookup(probe.menu);
  const own = select(reading, probe.where);
  if ('kind' in own) return own;
  const { matched, elsewhere } = own;

  // `unless`: one item matching any selection and the probe reads NOTHING. An
  // unreadable selection makes the probe unreadable — never a guess either way.
  for (const sel of probe.unless ?? []) {
    specOf(sel.menu);
    const hit = select(lookup(sel.menu), sel.where);
    if ('kind' in hit) return { ...hit, elsewhere };
    if (hit.matched.length > 0) return { kind: 'not_seen', elsewhere };
  }

  if (probe.present !== undefined || probe.absent !== undefined) {
    // ASYMMETRIC (the grammar header): a present-only probe says what a match
    // means and nothing about an absence — no item is no reading, never its
    // own value and never somebody's default.
    if (matched.length === 0 && isPresentOnlyProbe(probe)) return { kind: 'not_seen', elsewhere };
    if (probe.single === true && matched.length > 1) return { kind: 'ambiguous', count: matched.length, elsewhere };
    return { kind: 'presence', present: matched.length > 0, elsewhere };
  }
  if (matched.length === 0) return { kind: 'not_found', elsewhere };
  if (matched.length > 1) return { kind: 'ambiguous', count: matched.length, elsewhere };
  const id = matched[0];
  if (probe.sensitive === true) {
    return { kind: 'secret_target', itemId: spec.kind === 'list' ? id : null, elsewhere };
  }
  const got = reading!.items.get(id)!.get(probe.property as string);
  if (!got) return { kind: 'unreadable', reason: 'property_error', elsewhere };
  if (!got.ok) return { kind: 'unreadable', reason: got.why === 'garbled' ? 'garbled' : 'property_error', elsewhere };
  return { kind: 'value', text: got.value, elsewhere };
}

/** The value a probe found, typed the way the variables table types a cell
 *  (`coerceVariableCell`: converted only when unambiguously of the declared
 *  type, otherwise the text, which the schema then refuses by its type). */
export function typedValue(text: string, property: Record<string, unknown>): JsonValue {
  return coerceVariableCell(text, property);
}

// ============================================================================
// The built-in LAN probe
// ============================================================================

/** The three menu reads the LAN probe needs. */
export const LAN_READS = [
  { menu: '/ip/address', properties: ['address', 'interface', 'disabled'] },
  { menu: '/interface/bridge', properties: ['name'] },
  { menu: '/interface/list/member', properties: ['interface', 'list'] },
] as const;

/** The interface list a LAN bridge belongs to, by RouterOS's own default. */
const LAN_LIST = 'LAN';

function parseIfaceAddress(text: string): { ip: number; prefix: number } | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(text.trim());
  if (!m) return null;
  const octets = m.slice(1, 5).map(Number);
  const prefix = Number(m[5]);
  if (octets.some((o) => o > 255) || prefix > 32) return null;
  return { ip: ((octets[0] << 24) >>> 0) + (octets[1] << 16) + (octets[2] << 8) + octets[3], prefix };
}

function ipText(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

function value(item: Map<string, PropReading> | undefined, prop: string): string | null {
  const got = item?.get(prop);
  return got && got.ok ? got.value : null;
}

/**
 * The store LAN: an ENABLED address of prefix /8../30 on the LAN interface.
 * Which interface that is: `lanInterface` when the operator named it;
 * otherwise a BRIDGE carrying an address — the only one, or the only one that
 * is a member of the `LAN` interface list. Anything else is `ambiguous` and
 * lists what it saw: a guess here would record another network's block as the
 * store's LAN.
 */
export function judgeLan(
  readings: { address?: MenuReading; bridge?: MenuReading; member?: MenuReading },
  lanInterface: string | null,
): InfraLanFinding {
  const none = (status: InfraLanFinding['status']): InfraLanFinding => ({
    status, interface: null, lan: null, routerIp: null, candidates: [],
  });
  const addr = readings.address;
  if (!addr || !addr.ended || addr.garbled) return none('unreadable');

  const bridges = new Set<string>();
  const bridgeReading = readings.bridge;
  if (!lanInterface) {
    if (!bridgeReading || !bridgeReading.ended || bridgeReading.garbled) return none('unreadable');
    for (const id of bridgeReading.order) {
      const n = value(bridgeReading.items.get(id), 'name');
      if (n) bridges.add(n);
    }
  }

  const candidates: Array<{ interface: string; address: string; ip: number; prefix: number }> = [];
  for (const id of addr.order) {
    const item = addr.items.get(id);
    const iface = value(item, 'interface');
    const text = value(item, 'address');
    const disabled = value(item, 'disabled');
    if (iface === null || text === null || disabled === null) return none('unreadable');
    if (disabled !== 'false') continue;
    const parsed = parseIfaceAddress(text);
    if (!parsed || parsed.prefix < 8 || parsed.prefix > 30) continue;
    if (lanInterface ? iface !== lanInterface : !bridges.has(iface)) continue;
    candidates.push({ interface: iface, address: text.trim(), ...parsed });
  }

  let chosen = candidates;
  if (!lanInterface && candidates.length > 1) {
    const member = readings.member;
    if (member && member.ended && !member.garbled) {
      const inLan = new Set<string>();
      for (const id of member.order) {
        const it = member.items.get(id);
        if (value(it, 'list') === LAN_LIST) {
          const i = value(it, 'interface');
          if (i) inLan.add(i);
        }
      }
      const preferred = candidates.filter((c) => inLan.has(c.interface));
      if (preferred.length > 0) chosen = preferred;
    }
  }
  if (chosen.length === 0) return none('not_found');
  if (chosen.length > 1) {
    return {
      ...none('ambiguous'),
      candidates: chosen.slice(0, 8).map((c) => ({ interface: c.interface, address: c.address })),
    };
  }
  const c = chosen[0];
  const mask = c.prefix === 0 ? 0 : (0xffffffff << (32 - c.prefix)) >>> 0;
  const network = (c.ip & mask) >>> 0;
  return {
    status: 'found',
    interface: c.interface,
    lan: `${ipText(network)}/${c.prefix}`,
    routerIp: ipText(c.ip),
    candidates: [],
  };
}
