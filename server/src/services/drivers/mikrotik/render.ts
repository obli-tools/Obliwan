// ============================================================================
// ObliWAN — RouterOS: PlanOp[] -> console script lines
// ============================================================================
//
// ┌─ WHAT THIS FILE IS, AND THE ONE THING IT IS NOT ──────────────────────────┐
// │ `intent/renderers.ts` renders a WHOLE NCM document into a brand artefact  │
// │ for a human to read. This file renders a FROZEN PLAN — the ops an          │
// │ operator approved, and nothing else — into the lines that will actually    │
// │ be sent. The two are not interchangeable: an artefact describes a final    │
// │ state, a plan describes a transition, and a transition has to locate       │
// │ records that already exist on the box.                                    │
// │                                                                           │
// │ It is a PURE function. No database, no vault, no socket. A secret cannot   │
// │ leak from a module that has no way to read one — what leaves here may      │
// │ still contain a `__OBLIWAN_SECRET_<KEY>__` placeholder, which the change   │
// │ renderer substitutes in memory one layer up.                               │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ THE SHAPE OF THE OUTPUT IS DICTATED BY `buildApplyScriptSource` ─────────┐
// │ Every line produced here is interpolated, raw, into                       │
// │                                                                           │
// │   :do={  <line>;  <line>;  … } on-error={ … run the rollback … }          │
// │                                                                           │
// │ so it is a RouterOS CONSOLE line, never an API word array, and one         │
// │ newline or one stray `}` in it closes the `:do` block early, orphans the   │
// │ error handler and produces exactly the half-configured router with no      │
// │ rollback that backups and the ban on `/import` exist to prevent.           │
// │                                                                           │
// │ `assertConsoleLine()` below is the hard stop. It REFUSES — it does not     │
// │ sanitise and it does not truncate: a line that reached it dirty means an   │
// │ interpolation escaped `rosQuote`/`token`, and shipping a mangled version   │
// │ of that line hides the bug instead of stopping it. That is the opposite    │
// │ trade from `intent/renderers.ts`, and deliberately: that file renders a    │
// │ document a human will read before anything happens, this one renders       │
// │ commands that go straight onto a customer's firewall.                      │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ WHY SO MUCH OF THIS FILE IS A REFUSAL ───────────────────────────────────┐
// │ A PlanOp carries the NCM value, and the NCM deliberately carries no        │
// │ secret (the secrets rule): `ipsecPeer.pskFingerprint`,                     │
// │ `localUser.passwordFingerprint` and `service.communityFingerprint` are     │
// │ irreversible HMACs, and the MikroTik parser drops `secretProps` outright.  │
// │ So a rendering built from plan ops is STRUCTURALLY incapable of carrying   │
// │ those three values, and `/user add password=""` from a fingerprint would   │
// │ set an EMPTY administrator password on a customer box — a fake success,    │
// │ and the worst outcome available here.                                      │
// │                                                                           │
// │ The same argument covers every place where one `NcmResourceKind` maps to   │
// │ several RouterOS sections. `firewallRule` covers `/ip/firewall/filter`,    │
// │ `/mangle` and `/raw`, and the model DOES say which — `chainName` carries   │
// │ the table — so the refusal is `refuseNonFilterTable()` reading that field, │
// │ at every one of the five sites that writes to `/filter`. It is not the     │
// │ `action=passthrough` check, which only ever caught mangle's mark-*         │
// │ actions and let a raw `drop` or a mangle `accept` through as a live filter │
// │ rule.                                                                     │
// │                                                                           │
// │ Every one of those cases produces a NAMED refusal carrying the op's `seq`  │
// │ and `semKey`, and the change renderer turns the list into one error the    │
// │ operator can read. A named refusal is a meeting; a plausible command is a  │
// │ van.                                                                      │
// └───────────────────────────────────────────────────────────────────────────┘

import {
  NcmDhcpClient,
  NcmDhcpScope,
  NcmFirewallRule,
  NcmInterface,
  NcmIpsecPeer,
  NcmLocalUser,
  NcmNatRule,
  NcmQosRule,
  NcmRoute,
  NcmService,
  NcmVlan,
  routerOsServiceSet,
  type NcmMatch,
  type NcmResourceKind,
  type PlanOp,
  type PortSet,
  type Selector,
  type SelectorAtom,
} from '@obliwan/shared';
import { rosQuote, token } from '../../intent/renderers';
import { SERVICE_NAME_MAP } from './quirks';

// ============================================================================
// The vocabulary of a refusal
// ============================================================================

/**
 * Why an op could not be turned into a command. Closed on purpose: the change
 * renderer maps these onto `ChangeErrorKind`, and a free-text reason would make
 * "we could not get the secret" indistinguishable from "RouterOS cannot do
 * this" at the only place that decision matters.
 */
export const RENDER_REFUSAL_CODES = [
  /** The plan still carries a `blocked` op. A plan that was not fully compiled
   *  is not half-applicable: applying the rest silently drops the part the
   *  planner could not express. */
  'plan_contains_blocked_op',
  /** The command needs a secret VALUE, and the NCM carries only a fingerprint. */
  'secret_not_in_model',
  /** An intent-compiler `<<secret:label>>` placeholder reached the plan. No
   *  label -> vault resolver exists anywhere in the repo. */
  'intent_secret_placeholder',
  /** One NcmResourceKind, several RouterOS sections, and the model does not say
   *  which one this record came from. */
  'section_ambiguous',
  /** RouterOS needs a field the NCM does not model (a VLAN tag on an
   *  interface-typed record, the src/dst side of an address list, …). */
  'field_not_in_model',
  /** The selector holds two atoms that would need the same RouterOS property,
   *  or an atom RouterOS cannot express at all. */
  'selector_not_expressible',
  /** The value is a multi-line script body. It cannot be interpolated into the
   *  `:do={}` wrapper without destroying the error handler. */
  'multiline_field',
  /** The record cannot be located on the box: no `obliwan:` marker and no
   *  natural name, and `matchHash` is not computable by a router. */
  'identity_too_weak',
  /** The write exists on RouterOS but spans objects the plan does not describe
   *  (renaming a DHCP scope, re-proposing an IPsec tunnel, a VRF route). */
  'unrenderable_resource',
  /** The RouterOS spelling depends on the major version and the renderer has
   *  none (`routing-table=` on 7 against `routing-mark=` on 6). */
  'version_dependent_field',
  /** `op.before` / `op.after` did not validate against its NCM schema. */
  'malformed_resource',
] as const;
export type RenderRefusalCode = (typeof RENDER_REFUSAL_CODES)[number];

/** Codes whose cause is a missing secret. The change renderer reports these as
 *  `SECRET_LEAK_REFUSED` and everything else as `BRAND_UNSUPPORTED`. */
export const SECRET_REFUSAL_CODES: ReadonlySet<RenderRefusalCode> = new Set<RenderRefusalCode>([
  'secret_not_in_model',
  'intent_secret_placeholder',
]);

export interface RenderRefusal {
  seq: number;
  kind: PlanOp['kind'];
  resource: NcmResourceKind;
  semKey: string;
  code: RenderRefusalCode;
  /** Operator-facing, shown verbatim next to the op. Names what is missing. */
  reason: string;
}

/** A console line and the op it came from, so the audit trail can say which
 *  approved op produced which command. */
export interface RouterOsLine {
  seq: number;
  text: string;
}

export interface RouterOsRendering {
  lines: RouterOsLine[];
  refusals: RenderRefusal[];
}

// ============================================================================
// The hard stop
// ============================================================================

/**
 * Refuse a line that would break out of the `:do={}` wrapper.
 *
 * Two properties, and both are about the wrapper rather than about RouterOS:
 *  - no CR/LF: `buildApplyScriptSource` joins lines with `\n`, so an embedded
 *    newline turns one reviewed command into two;
 *  - brace depth never goes negative and ends at zero: a leading `}` closes our
 *    `:do` block and hands the rest of the plan to the error handler's scope.
 *
 * Braces are permitted rather than banned because the `verify` rendering needs
 * `:if (…) do={ :error … }` on one line. They can only ever come from this
 * file's own templates: every operator-supplied string goes through `rosQuote`
 * (which substitutes `{`, `}`, `;`, `"`, `$`, `[`, `]`, `` ` `` and `\`) or
 * `token` (a whitelist). This assertion is what turns a call site somebody
 * FORGOT into a failed render instead of a silent injection.
 */
export function assertConsoleLine(line: string): string {
  if (/[\r\n]/.test(line)) {
    throw new Error(
      'RouterOS change renderer produced a line containing a line break. It would close the ' +
        ':do{} wrapper of buildApplyScriptSource() early and orphan the on-error handler — ' +
        'refusing to render. A free-text field reached the line without rosQuote()/token().',
    );
  }
  let depth = 0;
  for (const ch of line) {
    if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth < 0) {
        throw new Error(
          'RouterOS change renderer produced a line with an unbalanced "}". It would close the ' +
            ':do{} wrapper of buildApplyScriptSource() — refusing to render.',
        );
      }
    }
  }
  if (depth !== 0) {
    throw new Error(
      'RouterOS change renderer produced a line with an unclosed "{" — refusing to render.',
    );
  }
  return line;
}

/**
 * The intent compiler's own secret placeholder. It is NOT the template path's
 * `__OBLIWAN_SECRET_<KEY>__`: that one names a `config_variables` key the vault
 * can resolve, this one names a label for which no resolver exists anywhere in
 * the repo. Pushing it literally would write the eight characters `<<secret:` as
 * a PSK.
 */
const INTENT_SECRET_RE = /<<secret:[^>]*>>/;

// ============================================================================
// Value helpers
// ============================================================================

function atomTag(atom: SelectorAtom): string {
  if (atom === 'any') return 'any';
  const i = atom.indexOf(':');
  return i < 0 ? 'any' : atom.slice(0, i);
}

function atomValue(atom: SelectorAtom): string {
  if (atom === 'any') return '';
  const i = atom.indexOf(':');
  return i < 0 ? atom : atom.slice(i + 1);
}

function isAny(selector: Selector | null | undefined): boolean {
  return !selector || selector.length === 0 || selector.includes('any');
}

function portExpression(set: PortSet): string | null {
  if (!set || set.length === 0) return null;
  return set.map(([a, b]) => (a === b ? `${a}` : `${a}-${b}`)).join(',');
}

function yesNo(value: boolean): string {
  return value ? 'yes' : 'no';
}

/** The comment a record carries ON THE BOX: the `obliwan:` marker the parser
 *  split off, put back in front of the free text. Rebuilt from the record so the
 *  two halves can never drift apart — the same reconstruction
 *  `intent/renderers.ts` uses, and the one `findByComment` depends on. */
function fullComment(record: { managedSlug: string | null; comment: string | null }): string {
  const marker = record.managedSlug ? `obliwan:${record.managedSlug}` : '';
  return [marker, record.comment ?? ''].filter((s) => s.length > 0).join(' ').trim();
}

// ============================================================================
// Locating a record on the box
// ============================================================================

/**
 * `[<section> find where comment="<exact comment>"]`.
 *
 * ┌─ WHY EXACT EQUALITY AND NOT A REGEX ON THE MARKER ────────────────────────┐
 * │ `find where comment~"obliwan:lan"` is a REGEX match, so `.` and the slug   │
 * │ alphabet's `-` become metacharacters, and `obliwan:lan` also matches       │
 * │ `obliwan:lan-guest`. An over-match here does not fail: it moves or         │
 * │ DELETES the wrong firewall rule, silently, on a live customer box.         │
 * │                                                                           │
 * │ Exact equality can under-match instead — a comment whose whitespace the    │
 * │ parser normalised differently yields an empty `find`, RouterOS refuses     │
 * │ the `move`/`remove`, the on-error branch fires and the dead-man's backup   │
 * │ goes back. That is a loud, recoverable failure, and it is the direction    │
 * │ this product is allowed to fail in.                                       │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
function findByComment(section: string, comment: string): string {
  return `[${section} find where comment="${rosQuote(comment)}"]`;
}

function findByProp(section: string, prop: string, value: string): string {
  return `[${section} find where ${prop}="${rosQuote(value)}"]`;
}

// ============================================================================
// Sections
// ============================================================================

const SEC_ROUTE = '/ip route';
const SEC_FILTER = '/ip firewall filter';
const SEC_NAT = '/ip firewall nat';
const SEC_ADDRESS = '/ip address';
const SEC_BRIDGE = '/interface bridge';
const SEC_VLAN = '/interface vlan';
const SEC_LIST_MEMBER = '/interface list member';
const SEC_POOL = '/ip pool';
const SEC_DHCP_SERVER = '/ip dhcp-server';
const SEC_DHCP_NETWORK = '/ip dhcp-server network';
const SEC_DHCP_LEASE = '/ip dhcp-server lease';
const SEC_DHCP_CLIENT = '/ip dhcp-client';
// `/ip service` has no section constant: it is never written by NAME here.
// `routerOsServiceSet` writes the CONFIGURED row, because RouterOS 7.24.5
// lists every open connection to a service — the push's own api-ssl session,
// a technician's winbox — as a dynamic entry of the same name, and a write
// that reaches one fails ("this is configured elsewhere") [prod, 2026-10-05].
// Whether a bare `set <name>` picks the service or that entry is not
// observed; it is not used. shared/src/routerOsService.ts holds the construct
// and what of it is REASONED.
const SEC_USER = '/user';
const SEC_IPSEC_PEER = '/ip ipsec peer';
const SEC_IPSEC_IDENTITY = '/ip ipsec identity';
const SEC_IPSEC_POLICY = '/ip ipsec policy';
const SEC_QUEUE_SIMPLE = '/queue simple';
const SEC_QUEUE_TREE = '/queue tree';

/** `/ip service` spellings, the inverse of `SERVICE_NAME_MAP`. Derived rather
 *  than written out twice: `www`/`www-ssl` against `http`/`https` is exactly the
 *  kind of table that rots when it is duplicated. */
const ROUTEROS_SERVICE_NAME: Readonly<Record<string, string>> = Object.freeze(
  Object.fromEntries(Object.entries(SERVICE_NAME_MAP).map(([ros, ncm]) => [ncm, ros])),
);

/**
 * NCM firewall action -> RouterOS `action=`, for the actions `/ip firewall
 * filter` actually accepts. `passthrough`, `addToList` and `other` are absent on
 * purpose and produce a refusal — see `renderFirewallAction`.
 */
const ROUTEROS_FILTER_ACTION: Readonly<Record<string, string>> = {
  accept: 'accept',
  drop: 'drop',
  reject: 'reject',
  log: 'log',
  jump: 'jump',
  return: 'return',
  tarpit: 'tarpit',
  fasttrack: 'fasttrack-connection',
};

const ROUTEROS_NAT_ACTION: Readonly<Record<string, string>> = {
  masquerade: 'masquerade',
  srcnat: 'src-nat',
  dstnat: 'dst-nat',
  netmap: 'netmap',
  redirect: 'redirect',
  accept: 'accept',
};

/** RouterOS names the NAT chains after the translation, not after the netfilter
 *  hook the NCM records. */
function natChainName(chain: string, chainName: string | null): string | null {
  if (chain === 'prerouting') return 'dstnat';
  if (chain === 'postrouting') return 'srcnat';
  if (chain === 'custom') return chainName;
  return null;
}

function filterChainName(chain: string, chainName: string | null): string | null {
  return chain === 'custom' ? chainName : chain;
}

/**
 * Which RouterOS firewall TABLE a `firewallRule` was read from.
 *
 * ┌─ THE TABLE IS IN THE MODEL, AND THROWING IT AWAY IS A FIREWALL BYPASS ────┐
 * │ `buildFirewallRules` walks /ip/firewall/filter, /mangle and /raw into ONE  │
 * │ `firewallRule` kind and records which one in `chainName`: `null` for       │
 * │ filter, `'mangle'` / `'raw'` for a standard chain of those tables, and     │
 * │ `'<table>:<chain>'` for a custom one. `filterChainName()` above then       │
 * │ returns the netfilter hook for every standard chain and DROPS the table.   │
 * │                                                                           │
 * │ For a while everything downstream read `SEC_FILTER` regardless, and the    │
 * │ `action=passthrough` refusal was believed to cover it. It does not: it     │
 * │ only catches mangle's mark-* actions. A raw `drop` and a mangle `accept`   │
 * │ are ordinary filter verbs, so they rendered with ZERO refusals — a         │
 * │ /raw bogon filter re-created as a filter user-chain called "prerouting"    │
 * │ that nothing jumps to (the protection silently stops existing), and a      │
 * │ mangle marking rule re-created as a real `accept` in the live forward      │
 * │ chain, which the accompanying `move` then put at index 0, ahead of every   │
 * │ drop. Delete and update pointed at the wrong table for the same records,   │
 * │ and the planner's `targetIndex` was computed against the chain key         │
 * │ `'forward:mangle'` while the move indexed `[/ip firewall filter find       │
 * │ chain="forward"]` — a different list entirely.                            │
 * │                                                                           │
 * │ So the table is read here, and anything but `filter` REFUSES. Dispatching  │
 * │ on it is not the fix either: NCM v1 has no field for mangle's payload      │
 * │ (`new-routing-mark` and friends live in `unmodeledMatch`, i.e. in the      │
 * │ identity), so a mangle rule re-created from the model would be a marking   │
 * │ rule that marks nothing — a fake success on the write path. Covering       │
 * │ /mangle and /raw means modelling them, which is an NCM version, not an     │
 * │ `if`.                                                                     │
 * │                                                                           │
 * │ A custom FILTER chain literally named `mangle` or `raw` is read as the     │
 * │ table and refused. That errs toward a refusal on a pathological name,      │
 * │ which is the right direction: the alternative is writing to the wrong      │
 * │ table on the strength of a chain name.                                     │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
function firewallTable(chainName: string | null): 'filter' | 'mangle' | 'raw' {
  if (chainName === null) return 'filter';
  if (chainName === 'mangle' || chainName.startsWith('mangle:')) return 'mangle';
  if (chainName === 'raw' || chainName.startsWith('raw:')) return 'raw';
  return 'filter';
}

/**
 * Refuse a rule that does not belong to /ip/firewall/filter. Returns true when
 * it refused, so every call site reads `if (refuseNonFilterTable(…)) return;`.
 *
 * Called on the `before` side of a delete, an update and a move as well as on
 * the `after` side of a create: a rule in the wrong table is unlocatable in all
 * four directions, and `locateOrderedRule` matches on a comment, which exists in
 * every table.
 */
function refuseNonFilterTable(
  emitter: OpEmitter,
  rule: { chain: string; chainName: string | null },
): boolean {
  const table = firewallTable(rule.chainName);
  if (table === 'filter') return false;
  emitter.refuse(
    'unrenderable_resource',
    `this rule lives in /ip/firewall/${table}, not in /ip/firewall/filter — \`chainName\` says ` +
      `so ("${rule.chainName ?? ''}"). This renderer writes the filter table only, and NCM v1 ` +
      `does not model what a ${table} rule does with a packet (a mangle rule's ` +
      '`new-routing-mark` is carried as part of its identity, not as a payload), so re-creating ' +
      `it in /filter would install a rule that forwards or drops traffic instead of the ${table} ` +
      'rule the operator is looking at. Change it on the router, or model the table first.',
  );
  return true;
}

// ============================================================================
// The per-op emitter
// ============================================================================

/**
 * Collects lines and refusals for one plan. An op either produces lines or a
 * refusal, never both: a partially rendered op is a command set that does
 * something OTHER than what was approved.
 */
class OpEmitter {
  readonly lines: RouterOsLine[] = [];
  readonly refusals: RenderRefusal[] = [];
  private pending: string[] = [];
  private refusedThisOp = false;

  constructor(private op: PlanOp) {}

  begin(op: PlanOp): void {
    this.op = op;
    this.pending = [];
    this.refusedThisOp = false;
  }

  add(line: string): void {
    this.pending.push(line);
  }

  refuse(code: RenderRefusalCode, reason: string): void {
    // First refusal wins: the later ones are consequences of the same gap, and
    // an operator reading twelve lines about one missing PSK learns less than
    // one reading a single line about it.
    if (this.refusedThisOp) return;
    this.refusedThisOp = true;
    this.pending = [];
    this.refusals.push({
      seq: this.op.seq,
      kind: this.op.kind,
      resource: this.op.resource,
      semKey: this.op.semKey,
      code,
      reason,
    });
  }

  /** Flush the op's lines, once it is known that nothing refused it. */
  commit(): void {
    if (this.refusedThisOp) return;
    for (const text of this.pending) {
      const trimmed = text.trim();
      if (trimmed.length === 0) continue;
      if (INTENT_SECRET_RE.test(trimmed)) {
        this.refuse(
          'intent_secret_placeholder',
          'the rendering carries an intent-compiler `<<secret:label>>` placeholder, and no ' +
            'label -> vault resolver exists in this codebase. Pushing it would write the ' +
            'literal placeholder where a credential belongs.',
        );
        return;
      }
      this.lines.push({ seq: this.op.seq, text: assertConsoleLine(trimmed) });
    }
    this.pending = [];
  }

  get refused(): boolean {
    return this.refusedThisOp;
  }
}

/**
 * Parse `op.before` / `op.after` against its NCM schema, or refuse.
 *
 * Migration 009 is explicit that `change_plans.ops` is validated on the way in
 * AND on the way out; this is the same discipline one level deeper. A resource
 * body that does not validate is a plan compiled by another server version, and
 * rendering half-understood fields into a firewall is not a recovery.
 */
const RESOURCE_SCHEMA = {
  interface: NcmInterface,
  vlan: NcmVlan,
  route: NcmRoute,
  firewallRule: NcmFirewallRule,
  natRule: NcmNatRule,
  dhcpScope: NcmDhcpScope,
  ipsecPeer: NcmIpsecPeer,
  localUser: NcmLocalUser,
  service: NcmService,
  qosRule: NcmQosRule,
  dhcpClient: NcmDhcpClient,
} as const;

type ResourceOf<K extends NcmResourceKind> = ReturnType<(typeof RESOURCE_SCHEMA)[K]['parse']>;

function resourceOf<K extends NcmResourceKind>(
  emitter: OpEmitter,
  kind: K,
  side: 'before' | 'after',
  value: unknown,
): ResourceOf<K> | null {
  if (value === null || value === undefined) {
    emitter.refuse(
      'malformed_resource',
      `the op carries no \`${side}\` value, and rendering it needs one.`,
    );
    return null;
  }
  const parsed = RESOURCE_SCHEMA[kind].safeParse(value);
  if (!parsed.success) {
    emitter.refuse(
      'malformed_resource',
      `the \`${side}\` value does not validate against the ${kind} schema ` +
        `(${parsed.error.issues.slice(0, 3).map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}). ` +
        'This plan was compiled by a different NCM version; recompile it.',
    );
    return null;
  }
  return parsed.data as ResourceOf<K>;
}

// ============================================================================
// Match rendering
// ============================================================================

/**
 * The RouterOS property each selector atom tag lands on, per match field.
 *
 * Straight from `normalize.service.ts`'s forward direction — an address list is
 * a `ref:`, an interface list is `ifaceList:`, a source MAC is `mac:`. A tag
 * absent from a field's table is a selector RouterOS cannot express THERE
 * (there is no `dst-mac-address=`, and no firewall match takes an FQDN), and it
 * refuses rather than being dropped.
 */
const MATCH_PROPS: Readonly<Record<string, Readonly<Record<string, string>>>> = {
  srcAddress: {
    ip: 'src-address',
    cidr: 'src-address',
    range: 'src-address-range',
    ref: 'src-address-list',
    mac: 'src-mac-address',
  },
  dstAddress: {
    ip: 'dst-address',
    cidr: 'dst-address',
    range: 'dst-address-range',
    ref: 'dst-address-list',
  },
  inInterface: { iface: 'in-interface', ifaceList: 'in-interface-list' },
  outInterface: { iface: 'out-interface', ifaceList: 'out-interface-list' },
};

/**
 * One selector -> zero or more `prop=value` clauses.
 *
 * ┌─ WHY THIS IS NOT `one(selector)` ─────────────────────────────────────────┐
 * │ `intent/renderers.ts` has a helper that takes the FIRST atom of a         │
 * │ selector and ignores the rest. That is safe there, because the intent     │
 * │ compiler only ever emits single-atom selectors. It is not safe here: a    │
 * │ selector that came off a real box through `normalize.service` can hold    │
 * │ `src-address` AND `src-address-list` at once (two atoms, two properties,  │
 * │ one legal RouterOS rule), and it can hold two `cidr:` atoms (two atoms,   │
 * │ ONE property, no legal RouterOS rule). Dropping the second atom in the    │
 * │ first case loses a restriction; dropping it in the second WIDENS the      │
 * │ rule. A firewall rule that matches more traffic than the one the operator │
 * │ approved is the failure this function exists to make impossible.          │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
function selectorClauses(
  emitter: OpEmitter,
  field: keyof typeof MATCH_PROPS | string,
  selector: Selector,
): string[] {
  if (isAny(selector)) return [];
  const table = MATCH_PROPS[field];
  const byProp = new Map<string, string>();
  for (const atom of selector) {
    const prop = table?.[atomTag(atom)];
    if (!prop) {
      emitter.refuse(
        'selector_not_expressible',
        `\`${field}\` carries the selector atom "${atom}", which RouterOS has no match ` +
          'property for. Rendering the rule without it would widen what it matches.',
      );
      return [];
    }
    if (byProp.has(prop)) {
      emitter.refuse(
        'selector_not_expressible',
        `\`${field}\` needs RouterOS \`${prop}=\` twice ("${byProp.get(prop)}" and ` +
          `"${atomValue(atom)}"). One rule cannot carry both; the record has to be split, ` +
          'which is a planner decision and not a rendering one.',
      );
      return [];
    }
    byProp.set(prop, atomValue(atom));
  }
  return [...byProp].map(([prop, value]) => `${prop}=${token(value)}`);
}

function matchClauses(emitter: OpEmitter, m: NcmMatch): string[] {
  if (m.unmodeledMatch.length > 0) {
    emitter.refuse(
      'field_not_in_model',
      `the rule matches on ${m.unmodeledMatch.join(', ')}, which NCM v1 does not model. ` +
        'Writing the rule without those selectors would make it match MORE traffic than the ' +
        'rule that was reviewed.',
    );
    return [];
  }
  const out: string[] = [];
  if (m.protocol) out.push(`protocol=${token(m.protocol)}`);
  out.push(...selectorClauses(emitter, 'srcAddress', m.srcAddress));
  out.push(...selectorClauses(emitter, 'dstAddress', m.dstAddress));
  out.push(...selectorClauses(emitter, 'inInterface', m.inInterface));
  out.push(...selectorClauses(emitter, 'outInterface', m.outInterface));
  const sp = portExpression(m.srcPort);
  if (sp) out.push(`src-port=${sp}`);
  const dp = portExpression(m.dstPort);
  if (dp) out.push(`dst-port=${dp}`);
  if (m.connectionState.length > 0) out.push(`connection-state=${m.connectionState.join(',')}`);
  if (m.connectionNat.length > 0) out.push(`connection-nat-state=${m.connectionNat.join(',')}`);
  if (m.tcpFlags.length > 0) out.push(`tcp-flags=${m.tcpFlags.join(',')}`);
  if (m.icmpType) out.push(`icmp-options=${token(m.icmpType)}`);
  if (m.ipsecPolicy) out.push(`ipsec-policy=${token(m.ipsecPolicy)}`);
  // `srcZone` / `dstZone` are always null on MikroTik (it has no zone model),
  // so there is nothing to render and nothing to refuse.
  return out;
}

// ============================================================================
// Ordered rules: firewallRule / natRule
// ============================================================================

interface OrderedSpec {
  section: string;
  chainName: string | null;
  actionClause: string[] | null;
}

function firewallSpec(emitter: OpEmitter, rule: ResourceOf<'firewallRule'>): OrderedSpec | null {
  // Before the chain, because `filterChainName` is what discards the table.
  if (refuseNonFilterTable(emitter, rule)) return null;
  const chain = filterChainName(rule.chain, rule.chainName);
  if (!chain) {
    emitter.refuse('field_not_in_model', 'the rule is on a custom chain with no `chainName`.');
    return null;
  }
  const action = ROUTEROS_FILTER_ACTION[rule.action];
  if (!action) {
    // The three that are missing are missing for three different reasons, and
    // an operator is owed the right one.
    if (rule.action === 'passthrough') {
      // `refuseNonFilterTable` runs first, so the TABLE is no longer what is
      // missing here — the old wording blamed it and was wrong twice over
      // (/filter does accept `action=passthrough`, and `chainName` does record
      // the table). What is genuinely ambiguous is the verb: `buildFirewallRules`
      // writes `passthrough` both for a literal `action=passthrough` and for any
      // RouterOS action it has no NCM verb for, and those two need opposite
      // commands.
      emitter.refuse(
        'section_ambiguous',
        'the NCM records this filter rule as `action=passthrough`, which the normalizer writes ' +
          'both for a real counter-only rule and for any RouterOS action it has no verb for. The ' +
          'two are indistinguishable in the model, so rendering one of them would either drop the ' +
          "rule's real action or replace a working rule with a packet counter.",
      );
    } else if (rule.action === 'addToList') {
      emitter.refuse(
        'field_not_in_model',
        `the rule adds to the address list "${rule.addToList ?? '?'}", but the NCM does not ` +
          'record whether it was `add-src-to-address-list` or `add-dst-to-address-list`. ' +
          'Guessing picks the wrong address to blacklist.',
      );
    } else {
      emitter.refuse(
        'unrenderable_resource',
        `\`action=${rule.action}\` is outside the RouterOS filter vocabulary this renderer ` +
          'covers.',
      );
    }
    return null;
  }
  const clauses = [`action=${action}`];
  if (rule.action === 'jump') {
    if (!rule.jumpTarget) {
      emitter.refuse('field_not_in_model', '`action=jump` with no `jumpTarget`.');
      return null;
    }
    clauses.push(`jump-target=${token(rule.jumpTarget)}`);
  }
  if (rule.action === 'reject' && rule.rejectWith) {
    clauses.push(`reject-with=${token(rule.rejectWith)}`);
  }
  if (rule.log) {
    clauses.push('log=yes');
    if (rule.logPrefix !== null) clauses.push(`log-prefix="${rosQuote(rule.logPrefix)}"`);
  }
  return { section: SEC_FILTER, chainName: chain, actionClause: clauses };
}

function natSpec(emitter: OpEmitter, rule: ResourceOf<'natRule'>): OrderedSpec | null {
  const chain = natChainName(rule.chain, rule.chainName);
  if (!chain) {
    emitter.refuse('field_not_in_model', 'the NAT rule is on a custom chain with no `chainName`.');
    return null;
  }
  const action = ROUTEROS_NAT_ACTION[rule.action];
  if (!action) {
    emitter.refuse(
      'unrenderable_resource',
      `\`action=${rule.action}\` is outside the RouterOS NAT vocabulary this renderer covers.`,
    );
    return null;
  }
  const clauses = [`action=${action}`];
  if (rule.toAddresses !== null && !isAny(rule.toAddresses)) {
    if (rule.toAddresses.length > 1) {
      emitter.refuse(
        'selector_not_expressible',
        `\`toAddresses\` holds ${rule.toAddresses.length} atoms; RouterOS \`to-addresses=\` is ` +
          'one address or one range.',
      );
      return null;
    }
    const tag = atomTag(rule.toAddresses[0]);
    if (tag !== 'ip' && tag !== 'cidr' && tag !== 'range') {
      emitter.refuse(
        'selector_not_expressible',
        `\`toAddresses\` is "${rule.toAddresses[0]}"; RouterOS \`to-addresses=\` takes an ` +
          'address or a range, never a named object.',
      );
      return null;
    }
    clauses.push(`to-addresses=${token(atomValue(rule.toAddresses[0]))}`);
  }
  const toPorts = portExpression(rule.toPorts);
  if (toPorts) clauses.push(`to-ports=${toPorts}`);
  return { section: SEC_NAT, chainName: chain, actionClause: clauses };
}

/**
 * An ordered rule has no natural name, so it can only be located by its
 * `obliwan:` marker. `matchHash` is a keyed HMAC computed by this server — a
 * router cannot evaluate it — and rebuilding the whole match predicate into a
 * `find where` would over-match the day two rules differ only in a field NCM v1
 * does not model. An over-match on a `remove` deletes the wrong rule.
 */
function locateOrderedRule(
  emitter: OpEmitter,
  section: string,
  rule: { managedSlug: string | null; comment: string | null; semKey: string },
): string | null {
  if (!rule.managedSlug) {
    emitter.refuse(
      'identity_too_weak',
      'this rule carries no `obliwan:` marker, so there is no way to point at it on the box: ' +
        'its semKey is a keyed matchHash a router cannot evaluate, and matching it by its ' +
        'selectors would hit any rule that differs only in a field NCM v1 does not model. ' +
        'Adopt the rule first (give it an obliwan: comment), then re-plan.',
    );
    return null;
  }
  return findByComment(section, fullComment(rule));
}

// ============================================================================
// move / verify — the renumbering trap
// ============================================================================

/**
 * ┌─ WHY A MOVE IS RENDERED AS `[:pick [find …] n]` AND NEVER AS `n` ─────────┐
 * │ `op.targetIndex` is an index in the planner's SIMULATED, CHAIN-SCOPED     │
 * │ list (`planner.service.ts`, the order pass). RouterOS numbers the WHOLE   │
 * │ section across every chain and RENUMBERS on each move (the renumbering    │
 * │ trap of the NCM contract). Passing `targetIndex` as `destination=` is     │
 * │ therefore wrong twice: wrong coordinate space, and invalidated by the     │
 * │ previous move.                                                           │
 * │                                                                          │
 * │ `[<section> find chain=<c>]` returns the ids of that chain, in order, AS  │
 * │ THE BOX HAS THEM AT THAT MOMENT. `[:pick … n]` is therefore exactly the   │
 * │ planner's coordinate, re-read op by op — which is also why the moves must │
 * │ be emitted in `seq` order and never coalesced.                           │
 * │                                                                          │
 * │ The planner only ever moves a rule UPWARD (its loop takes `from >= i` and │
 * │ skips `from == i`), so `destination=` — RouterOS places the moved item    │
 * │ BEFORE the destination — lands it on index `n` and shifts the rest down.  │
 * │ A downward move would need `n + 1` and the planner does not emit one; if  │
 * │ it ever does, the `verify` op below is what catches it.                   │
 * │                                                                          │
 * │ UNVERIFIED AGAINST HARDWARE: no RouterOS box exists to test this          │
 * │ against. What is tested is that the coordinate space and the op order     │
 * │ are the planner's — `renderer.verify.ts`.                                │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
function renderMove(emitter: OpEmitter, op: PlanOp): void {
  if (op.targetIndex === null) {
    emitter.refuse('malformed_resource', 'a `move` op with no `targetIndex`.');
    return;
  }

  const coords = moveCoordinates(emitter, op);
  if (!coords) return;
  emitter.add(
    `${coords.section} move numbers=${coords.locator} ` +
      `destination=[:pick ${coords.chainList} ${op.targetIndex}]`,
  );
}

/** Where an ordered record lives, and how to name the list it is ordered in.
 *  Shared by `move` and by the `verify` that follows it, so the two can never
 *  disagree about the coordinate space. */
interface MoveCoordinates {
  section: string;
  /** `[<section> find where comment="…"]` or `… name="…"` — the record itself. */
  locator: string;
  /** `[<section> find chain="…"]` — the list `targetIndex` indexes into. */
  chainList: string;
}

function moveCoordinates(emitter: OpEmitter, op: PlanOp): MoveCoordinates | null {
  if (op.resource === 'firewallRule') {
    const rule = resourceOf(emitter, 'firewallRule', 'before', op.before);
    if (!rule) return null;
    // The planner computed `targetIndex` against the chain key `'<chain>:<table>'`,
    // so a move of a mangle rule indexes the mangle list. `chainList` below can
    // only ever name /filter, and the two lists have nothing to do with each
    // other — the move would put a rule at position 0 of a chain it was never
    // measured in.
    if (refuseNonFilterTable(emitter, rule)) return null;
    const chain = filterChainName(rule.chain, rule.chainName);
    if (!chain) {
      emitter.refuse('field_not_in_model', 'the rule is on a custom chain with no `chainName`.');
      return null;
    }
    const locator = locateOrderedRule(emitter, SEC_FILTER, rule);
    if (!locator) return null;
    return {
      section: SEC_FILTER,
      locator,
      chainList: `[${SEC_FILTER} find chain="${rosQuote(chain)}"]`,
    };
  }

  if (op.resource === 'natRule') {
    const rule = resourceOf(emitter, 'natRule', 'before', op.before);
    if (!rule) return null;
    const chain = natChainName(rule.chain, rule.chainName);
    if (!chain) {
      emitter.refuse('field_not_in_model', 'the NAT rule is on a custom chain with no `chainName`.');
      return null;
    }
    const locator = locateOrderedRule(emitter, SEC_NAT, rule);
    if (!locator) return null;
    return {
      section: SEC_NAT,
      locator,
      chainList: `[${SEC_NAT} find chain="${rosQuote(chain)}"]`,
    };
  }

  if (op.resource === 'qosRule') {
    const queue = resourceOf(emitter, 'qosRule', 'before', op.before);
    if (!queue) return null;
    if (queue.queueClass !== 'simple') {
      emitter.refuse(
        'unrenderable_resource',
        `a \`${queue.queueClass}\` queue has no ordered list to move within — only ` +
          '/queue/simple is evaluated top to bottom.',
      );
      return null;
    }
    if (!queue.name) {
      emitter.refuse('identity_too_weak', 'the queue has no name to locate it by.');
      return null;
    }
    // A queue has a NAME, which is a strong natural key — unlike a firewall
    // rule, it does not need an `obliwan:` marker to be pointed at. And
    // `/queue simple` is one flat ordered list with no chain property, so the
    // planner's "chain" for a queue (its `queueClass`) is that whole list.
    return {
      section: SEC_QUEUE_SIMPLE,
      locator: findByProp(SEC_QUEUE_SIMPLE, 'name', queue.name),
      chainList: `[${SEC_QUEUE_SIMPLE} find]`,
    };
  }

  emitter.refuse(
    'unrenderable_resource',
    `\`${op.resource}\` has no order on RouterOS, so a move of it means nothing.`,
  );
  return null;
}

/**
 * The `verify` op the planner emits after every chain it moved, rendered as a
 * real on-box assertion.
 *
 * `:error` inside the `:do={}` wrapper is caught by its `on-error={}` branch,
 * which runs the rollback script — so a chain that did not land where the plan
 * said restores the pre-change backup instead of leaving a firewall in an order
 * nobody reviewed. That is the whole point of the op: the design asks for the check,
 * and a check that is not executed on the box is an assumption.
 *
 * What is asserted is what the plan actually proves: for each `move` of this
 * chain, the rule named by that move sits at that move's `targetIndex`. The
 * planner's order pass fixes indices `0..i` once it has placed `i` and never
 * revisits them, so each move's target index IS that rule's final position.
 */
function renderOrderVerify(emitter: OpEmitter, op: PlanOp, moves: readonly PlanOp[]): void {
  if (moves.length === 0) {
    // A `verify` with no moves in front of it asserts nothing. Refusing is the
    // honest answer: the planner only emits one after a move, so its absence
    // means the ops were filtered or reordered somewhere between the freeze and
    // here — and then the order this plan promises is not the order it produces.
    emitter.refuse(
      'malformed_resource',
      `the plan carries an order \`verify\` for "${op.semKey}" with no \`move\` op in front of ` +
        'it. Either the ops were filtered after the freeze, or the planner changed; the final ' +
        'order is not proved either way.',
    );
    return;
  }

  for (const move of moves) {
    // The same coordinates the `move` itself used. Re-deriving them here rather
    // than recomputing a section and a chain by hand is the point: a verify that
    // indexes a different list from the move it checks proves nothing, and would
    // do it silently.
    const coords = moveCoordinates(emitter, move);
    if (!coords || move.targetIndex === null) return;
    emitter.add(
      `:if ([:pick ${coords.chainList} ${move.targetIndex}] != [:pick ${coords.locator} 0]) ` +
        // ASCII only in a string the router itself will log: the console is not
        // guaranteed to be UTF-8, and a mangled byte in a diagnostic is a
        // diagnostic nobody trusts.
        `do={ :error "obliwan: ${rosQuote(op.semKey)} did not converge - position ` +
        `${move.targetIndex} is not ${rosQuote(move.semKey)}" }`,
    );
  }
}

// ============================================================================
// route
// ============================================================================

function routeLocator(route: ResourceOf<'route'>): string {
  // `routeKey` is table + dst + gateway, so those three ARE the natural key —
  // this is not a guess, it is the same identity the plan was keyed on.
  const gw = route.gateway === null ? null : atomValue(route.gateway);
  return gw === null
    ? `[${SEC_ROUTE} find where dst-address="${rosQuote(route.dst)}" blackhole=yes]`
    : `[${SEC_ROUTE} find where dst-address="${rosQuote(route.dst)}" gateway="${rosQuote(gw)}"]`;
}

function routeClauses(emitter: OpEmitter, route: ResourceOf<'route'>): string[] | null {
  if (route.table !== 'main') {
    emitter.refuse(
      'version_dependent_field',
      `the route lives in routing table "${route.table}". RouterOS 6 spells that ` +
        '`routing-mark=` and RouterOS 7 spells it `routing-table=`, and the renderer is handed ' +
        'no OS version — emitting either one is a coin flip on half the fleet.',
    );
    return null;
  }
  if (route.vrf !== null) {
    emitter.refuse(
      'unrenderable_resource',
      `the route is in VRF "${route.vrf}". On RouterOS a VRF is interface membership under ` +
        '/ip/vrf, not a property of the route, and the plan describes no VRF object.',
    );
    return null;
  }
  const out: string[] = [`dst-address=${token(route.dst)}`];
  if (route.gateway === null) {
    // `type=blackhole` and no gateway. `intent/renderers.ts` writes
    // `gateway=blackhole`, which RouterOS reads as a host named "blackhole";
    // that artefact is read by a human before anything happens, this line is
    // not.
    out.push('type=blackhole');
  } else {
    const tag = atomTag(route.gateway);
    if (tag !== 'ip' && tag !== 'iface') {
      emitter.refuse(
        'selector_not_expressible',
        `the gateway is "${route.gateway}"; RouterOS \`gateway=\` takes an address or an ` +
          'interface name, never a named object or a prefix.',
      );
      return null;
    }
    out.push(`gateway=${token(atomValue(route.gateway))}`);
  }
  // null is not a default: an unreported distance stays unreported, because
  // writing `distance=1` where the box had 10 changes which uplink wins.
  if (route.distance !== null) out.push(`distance=${route.distance}`);
  if (route.scope !== null) out.push(`scope=${route.scope}`);
  if (route.targetScope !== null) out.push(`target-scope=${route.targetScope}`);
  if (route.checkGateway !== null && route.checkGateway !== 'none') {
    out.push(`check-gateway=${route.checkGateway}`);
  }
  return out;
}

// ============================================================================
// The dispatcher
// ============================================================================

/**
 * Turn a frozen plan into RouterOS console lines.
 *
 * Ops are rendered in ascending `seq` and never reordered: `dependsOn` is
 * expressed by the planner AS that order, and a renderer that sorts differently
 * creates an address before the bridge it sits on.
 */
export function renderPlanOpsForRouterOs(ops: readonly PlanOp[]): RouterOsRendering {
  const sorted = [...ops].sort((a, b) => a.seq - b.seq);
  const emitter = new OpEmitter(sorted[0] ?? ({ seq: -1 } as PlanOp));

  // Moves already emitted, per (resource, chain), so the `verify` op that
  // follows them can assert the positions they claimed.
  const movesByChain = new Map<string, PlanOp[]>();

  for (const op of sorted) {
    emitter.begin(op);

    switch (op.kind) {
      case 'blocked':
        emitter.refuse(
          'plan_contains_blocked_op',
          `the plan is incomplete: op ${op.seq} on ${op.resource} "${op.semKey}" is blocked ` +
            `(${op.blockedReason ?? 'no reason recorded'}) — ${op.reason}. A blocked op is ` +
            'information, not an op to skip: applying the rest of the plan silently drops the ' +
            'part the planner could not express.',
        );
        break;

      case 'move': {
        renderMove(emitter, op);
        if (!emitter.refused) {
          const key = `${op.resource}\u0000${op.chain ?? ''}`;
          const list = movesByChain.get(key);
          if (list) list.push(op);
          else movesByChain.set(key, [op]);
        }
        break;
      }

      case 'verify':
        renderOrderVerify(
          emitter,
          op,
          movesByChain.get(`${op.resource}\u0000${op.chain ?? ''}`) ?? [],
        );
        break;

      case 'create':
        renderCreate(emitter, op);
        break;
      case 'delete':
        renderDelete(emitter, op);
        break;
      case 'update':
        renderUpdate(emitter, op);
        break;
      case 'enable':
      case 'disable':
        renderToggle(emitter, op);
        break;
    }

    emitter.commit();
  }

  return { lines: emitter.lines, refusals: emitter.refusals };
}

// ============================================================================
// create
// ============================================================================

function renderCreate(emitter: OpEmitter, op: PlanOp): void {
  switch (op.resource) {
    case 'route': {
      const route = resourceOf(emitter, 'route', 'after', op.after);
      if (!route) return;
      const clauses = routeClauses(emitter, route);
      if (!clauses) return;
      emitter.add(
        `${SEC_ROUTE} add ${clauses.join(' ')} comment="${rosQuote(fullComment(route))}"` +
          (route.disabled ? ' disabled=yes' : ''),
      );
      return;
    }

    case 'firewallRule': {
      const rule = resourceOf(emitter, 'firewallRule', 'after', op.after);
      if (!rule) return;
      const spec = firewallSpec(emitter, rule);
      if (!spec) return;
      const match = matchClauses(emitter, rule.match);
      if (emitter.refused) return;
      // `add` APPENDS, which is precisely what the planner's order simulation
      // assumes ("plus the ones it creates — RouterOS `add` appends"). Using
      // `place-before=` here would put the rule somewhere the simulation did
      // not, and every subsequent `move` index would be off by one.
      emitter.add(
        `${SEC_FILTER} add chain=${token(spec.chainName as string)} ${[...(spec.actionClause as string[]), ...match].join(' ')} ` +
          `comment="${rosQuote(fullComment(rule))}"${rule.disabled ? ' disabled=yes' : ''}`,
      );
      return;
    }

    case 'natRule': {
      const rule = resourceOf(emitter, 'natRule', 'after', op.after);
      if (!rule) return;
      const spec = natSpec(emitter, rule);
      if (!spec) return;
      const match = matchClauses(emitter, rule.match);
      if (emitter.refused) return;
      emitter.add(
        `${SEC_NAT} add chain=${token(spec.chainName as string)} ${[...(spec.actionClause as string[]), ...match].join(' ')} ` +
          `comment="${rosQuote(fullComment(rule))}"${rule.disabled ? ' disabled=yes' : ''}`,
      );
      return;
    }

    case 'vlan': {
      const vlan = resourceOf(emitter, 'vlan', 'after', op.after);
      if (!vlan) return;
      if (vlan.taggedPorts.length > 0 || vlan.untaggedPorts.length > 0) {
        emitter.refuse(
          'unrenderable_resource',
          'the VLAN declares tagged/untagged ports. On RouterOS that is the bridge VLAN ' +
            'filtering table (/interface/bridge/vlan), a different object from the L3 VLAN ' +
            'interface, and the plan describes only one of the two.',
        );
        return;
      }
      if (!vlan.parent) {
        emitter.refuse(
          'field_not_in_model',
          'the VLAN has no `parent`, so there is no interface to create it on.',
        );
        return;
      }
      emitter.add(
        `${SEC_VLAN} add name=${token(vlan.name ?? `vlan${vlan.vlanId}`)} vlan-id=${vlan.vlanId} ` +
          `interface=${token(vlan.parent)} comment="${rosQuote(fullComment(vlan))}"` +
          (vlan.disabled ? ' disabled=yes' : ''),
      );
      return;
    }

    case 'interface': {
      const iface = resourceOf(emitter, 'interface', 'after', op.after);
      if (!iface) return;
      if (iface.type === 'bridge') {
        emitter.add(
          `${SEC_BRIDGE} add name=${token(iface.name)}` +
            (iface.mtu !== null ? ` mtu=${iface.mtu}` : '') +
            ` comment="${rosQuote(fullComment(iface))}"${iface.disabled ? ' disabled=yes' : ''}`,
        );
        for (const address of iface.addresses) {
          emitter.add(
            `${SEC_ADDRESS} add address=${token(address.cidr)} interface=${token(iface.name)} ` +
              `comment="${rosQuote(fullComment(iface))}"`,
          );
        }
        for (const list of iface.lists) {
          emitter.add(
            `${SEC_LIST_MEMBER} add list=${token(list)} interface=${token(iface.name)} ` +
              `comment="${rosQuote(fullComment(iface))}"`,
          );
        }
        return;
      }
      if (iface.type === 'vlan') {
        emitter.refuse(
          'field_not_in_model',
          'a vlan-typed `interface` record carries no VLAN tag — `NcmInterface` has no ' +
            '`vlanId` field, the `vlan` resource kind does. Creating the interface without a ' +
            'tag would put untagged traffic on the trunk.',
        );
        return;
      }
      emitter.refuse(
        'unrenderable_resource',
        `an interface of type "${iface.type}" cannot be created from an NCM record: a physical ` +
          'port already exists and is never added, and a pppoe/l2tp/wireguard interface needs a ' +
          'credential or a key pair that the NCM does not carry.',
      );
      return;
    }

    case 'dhcpScope': {
      const scope = resourceOf(emitter, 'dhcpScope', 'after', op.after);
      if (!scope) return;
      if (scope.options.length > 0) {
        emitter.refuse(
          'unrenderable_resource',
          `the scope carries ${scope.options.length} DHCP option(s). RouterOS options are named ` +
            'objects under /ip/dhcp-server/option with a declared value TYPE, and the NCM ' +
            'records neither the name nor the type.',
        );
        return;
      }
      if (atomTag(scope.onInterface) !== 'iface') {
        emitter.refuse(
          'selector_not_expressible',
          `the scope listens on "${scope.onInterface}"; a RouterOS DHCP server binds to an ` +
            'interface name.',
        );
        return;
      }
      if (scope.poolFrom === null || scope.poolTo === null) {
        emitter.refuse(
          'field_not_in_model',
          'the scope has no pool range. `null` here means the collector did not report one, ' +
            'not that the pool is empty, and inventing a range hands out addresses nobody chose.',
        );
        return;
      }
      const name = token(scope.name);
      const iface = token(atomValue(scope.onInterface));
      const cmt = rosQuote(fullComment(scope));
      // Four objects, in this order: RouterOS refuses a dhcp-server whose pool
      // does not exist yet, and a network row is meaningless without the server.
      emitter.add(
        `${SEC_POOL} add name=pool-${name} ranges=${token(scope.poolFrom)}-${token(scope.poolTo)} comment="${cmt}"`,
      );
      emitter.add(
        `${SEC_DHCP_SERVER} add name=${name} interface=${iface} address-pool=pool-${name}` +
          (scope.leaseSeconds !== null ? ` lease-time=${scope.leaseSeconds}s` : '') +
          ` disabled=${yesNo(scope.disabled)} comment="${cmt}"`,
      );
      emitter.add(
        `${SEC_DHCP_NETWORK} add address=${token(scope.subnet)}` +
          (scope.gateway !== null ? ` gateway=${token(scope.gateway)}` : '') +
          (scope.dnsServers.length > 0 ? ` dns-server=${scope.dnsServers.map(token).join(',')}` : '') +
          (scope.ntpServers.length > 0 ? ` ntp-server=${scope.ntpServers.map(token).join(',')}` : '') +
          (scope.domain !== null ? ` domain=${token(scope.domain)}` : '') +
          ` comment="${cmt}"`,
      );
      for (const r of scope.reservations) {
        emitter.add(
          `${SEC_DHCP_LEASE} add server=${name} mac-address=${token(r.mac.toUpperCase())} ` +
            `address=${token(r.address)} comment="${rosQuote(reservationComment(r))}"`,
        );
      }
      return;
    }

    case 'dhcpClient': {
      const client = resourceOf(emitter, 'dhcpClient', 'after', op.after);
      if (!client) return;
      const clauses = dhcpClientClauses(emitter, client);
      if (!clauses) return;
      emitter.add(
        `${SEC_DHCP_CLIENT} add interface=${token(client.interfaceName)} ${clauses.join(' ')} ` +
          `comment="${rosQuote(fullComment(client))}"${client.disabled ? ' disabled=yes' : ''}`,
      );
      return;
    }

    case 'qosRule': {
      const queue = resourceOf(emitter, 'qosRule', 'after', op.after);
      if (!queue) return;
      renderQueueCreate(emitter, queue);
      return;
    }

    case 'localUser':
      emitter.refuse(
        'secret_not_in_model',
        'creating a local user needs its PASSWORD, and the NCM carries only ' +
          '`passwordFingerprint` — an irreversible per-tenant HMAC. `/user add` ' +
          'without `password=` creates an account with an EMPTY password on a customer router. ' +
          'The account has to be created through a template render, where the vault value is ' +
          'available on the push path.',
      );
      return;

    case 'ipsecPeer':
      emitter.refuse(
        'secret_not_in_model',
        'creating an IPsec peer needs its PSK or its certificate, and the NCM carries only ' +
          '`pskFingerprint` — the MikroTik collector never reads the secret at all ' +
          '(`/export show-sensitive=no`). `secret=""` would bring a tunnel up with an ' +
          'empty pre-shared key.',
      );
      return;

    case 'service':
      emitter.refuse(
        'unrenderable_resource',
        '`/ip/service` entries and `/snmp` are fixed singletons on RouterOS — they are set, ' +
          'never added. A `create` on a service kind means the collector saw a service this ' +
          'renderer cannot place.',
      );
      return;
  }
}

function reservationComment(r: { comment: string | null; hostname: string | null }): string {
  return [r.comment ?? '', r.hostname ?? ''].filter((s) => s.length > 0).join(' ').trim();
}

/**
 * `/ip/dhcp-client` flags. Each one is `boolean | null`, and `null` is NOT
 * `false`: an unreported flag stays unwritten, because writing
 * `add-default-route=no` where the box had `yes` removes the site's default
 * route — which is the failure `NcmDhcpClient`'s own header describes.
 */
function dhcpClientClauses(
  emitter: OpEmitter,
  client: ResourceOf<'dhcpClient'>,
): string[] | null {
  if (client.bindScript !== null) {
    emitter.refuse(
      'multiline_field',
      `the DHCP client carries a ${client.bindScript.length}-character \`script=\` body. It is ` +
        'kept verbatim including its newlines and braces, and the apply path interpolates every ' +
        'command raw into a `:do={ … } on-error={ … }` wrapper — one of those braces closes the ' +
        'wrapper, orphans the error handler and leaves the router half configured with no ' +
        'rollback. On this site that script is typically the WAN failover that re-points ' +
        'the default route, so it is the last thing to render on a guess.',
    );
    return null;
  }
  const out: string[] = [];
  if (client.addDefaultRoute !== null) out.push(`add-default-route=${yesNo(client.addDefaultRoute)}`);
  if (client.usePeerDns !== null) out.push(`use-peer-dns=${yesNo(client.usePeerDns)}`);
  if (client.usePeerNtp !== null) out.push(`use-peer-ntp=${yesNo(client.usePeerNtp)}`);
  if (client.defaultRouteDistance !== null) {
    out.push(`default-route-distance=${client.defaultRouteDistance}`);
  }
  return out;
}

/**
 * `max-limit` and `limit-at` are PAIRS on RouterOS (`up/down`). One half null
 * and the other set is "we measured one direction and not the other", and there
 * is no honest way to spell that: `0` means UNLIMITED on RouterOS, so a `?? 0`
 * here would silently lift a rate limit.
 */
function bpsPair(
  emitter: OpEmitter,
  prop: string,
  up: number | null,
  down: number | null,
): string | null | undefined {
  if (up === null && down === null) return undefined;
  if (up === null || down === null) {
    emitter.refuse(
      'field_not_in_model',
      `\`${prop}\` has only one direction (up=${up ?? 'unknown'}, down=${down ?? 'unknown'}). ` +
        'RouterOS takes it as a pair, and `0` there means UNLIMITED — filling the missing half ' +
        'with a zero would remove the limit instead of recording that we do not know it.',
    );
    return null;
  }
  return `${prop}=${up}/${down}`;
}

function renderQueueCreate(emitter: OpEmitter, queue: ResourceOf<'qosRule'>): void {
  if (queue.queueClass !== 'simple' && queue.queueClass !== 'tree') {
    emitter.refuse(
      'unrenderable_resource',
      `queue class "${queue.queueClass}" has no RouterOS menu — /queue/simple and /queue/tree ` +
        'are the two this renderer covers.',
    );
    return;
  }
  if (!queue.name) {
    emitter.refuse(
      'identity_too_weak',
      'the queue has no name, so nothing on the box could ever point back at it.',
    );
    return;
  }
  const maxLimit = bpsPair(emitter, 'max-limit', queue.maxLimitUpBps, queue.maxLimitDownBps);
  if (maxLimit === null) return;
  const limitAt = bpsPair(emitter, 'limit-at', queue.limitAtUpBps, queue.limitAtDownBps);
  if (limitAt === null) return;

  const clauses: string[] = [`name=${token(queue.name)}`];
  if (queue.queueClass === 'simple') {
    if (isAny(queue.target)) {
      emitter.refuse(
        'field_not_in_model',
        'a simple queue with no target would shape every packet on the box.',
      );
      return;
    }
    // `/queue simple target=` takes a comma list of interfaces and addresses,
    // so a multi-atom selector is expressible here — unlike a firewall match.
    clauses.push(`target=${queue.target.map((a) => token(atomValue(a))).join(',')}`);
  } else {
    if (!queue.parent) {
      emitter.refuse(
        'field_not_in_model',
        'a queue tree node has no `parent`; RouterOS needs one (an interface, `global`, or ' +
          'another node).',
      );
      return;
    }
    clauses.push(`parent=${token(queue.parent)}`);
  }
  if (queue.queueClass === 'simple' && queue.parent) clauses.push(`parent=${token(queue.parent)}`);
  if (maxLimit) clauses.push(maxLimit);
  if (limitAt) clauses.push(limitAt);
  if (queue.priority !== null) clauses.push(`priority=${queue.priority}`);
  if (queue.queueType !== null) clauses.push(`queue=${token(queue.queueType)}`);
  emitter.add(
    `${queue.queueClass === 'simple' ? SEC_QUEUE_SIMPLE : SEC_QUEUE_TREE} add ${clauses.join(' ')} ` +
      `comment="${rosQuote(fullComment(queue))}"${queue.disabled ? ' disabled=yes' : ''}`,
  );
}

// ============================================================================
// delete
// ============================================================================

function renderDelete(emitter: OpEmitter, op: PlanOp): void {
  switch (op.resource) {
    case 'route': {
      const route = resourceOf(emitter, 'route', 'before', op.before);
      if (!route) return;
      emitter.add(`${SEC_ROUTE} remove ${routeLocator(route)}`);
      return;
    }

    case 'firewallRule': {
      const rule = resourceOf(emitter, 'firewallRule', 'before', op.before);
      if (!rule) return;
      // `locateOrderedRule` matches on the `obliwan:` comment, and a comment
      // exists in every firewall table — so a delete aimed at a mangle rule
      // would remove whatever carries that comment in /filter, or nothing.
      if (refuseNonFilterTable(emitter, rule)) return;
      const locator = locateOrderedRule(emitter, SEC_FILTER, rule);
      if (!locator) return;
      emitter.add(`${SEC_FILTER} remove ${locator}`);
      return;
    }

    case 'natRule': {
      const rule = resourceOf(emitter, 'natRule', 'before', op.before);
      if (!rule) return;
      const locator = locateOrderedRule(emitter, SEC_NAT, rule);
      if (!locator) return;
      emitter.add(`${SEC_NAT} remove ${locator}`);
      return;
    }

    case 'vlan': {
      const vlan = resourceOf(emitter, 'vlan', 'before', op.before);
      if (!vlan) return;
      if (!vlan.name) {
        emitter.refuse(
          'identity_too_weak',
          'the VLAN record has no name, and a bare vlan-id does not identify a RouterOS ' +
            '/interface/vlan row.',
        );
        return;
      }
      emitter.add(`${SEC_VLAN} remove ${findByProp(SEC_VLAN, 'name', vlan.name)}`);
      return;
    }

    case 'interface': {
      const iface = resourceOf(emitter, 'interface', 'before', op.before);
      if (!iface) return;
      if (iface.type !== 'bridge') {
        emitter.refuse(
          'unrenderable_resource',
          `an interface of type "${iface.type}" is not a removable object on RouterOS (a ` +
            'physical port cannot be deleted), or it lives in a menu this renderer does not ' +
            'derive from the NCM record.',
        );
        return;
      }
      for (const list of iface.lists) {
        emitter.add(
          `${SEC_LIST_MEMBER} remove [${SEC_LIST_MEMBER} find where list="${rosQuote(list)}" ` +
            `interface="${rosQuote(iface.name)}"]`,
        );
      }
      for (const address of iface.addresses) {
        emitter.add(
          `${SEC_ADDRESS} remove [${SEC_ADDRESS} find where address="${rosQuote(address.cidr)}" ` +
            `interface="${rosQuote(iface.name)}"]`,
        );
      }
      emitter.add(`${SEC_BRIDGE} remove ${findByProp(SEC_BRIDGE, 'name', iface.name)}`);
      return;
    }

    case 'dhcpScope': {
      const scope = resourceOf(emitter, 'dhcpScope', 'before', op.before);
      if (!scope) return;
      const name = token(scope.name);
      // Reverse of the create order: a pool with a server still bound to it is
      // refused, and a network row outlives its server as dead configuration.
      emitter.add(`${SEC_DHCP_LEASE} remove [${SEC_DHCP_LEASE} find where server="${rosQuote(scope.name)}"]`);
      emitter.add(
        `${SEC_DHCP_NETWORK} remove [${SEC_DHCP_NETWORK} find where address="${rosQuote(scope.subnet)}"]`,
      );
      emitter.add(`${SEC_DHCP_SERVER} remove ${findByProp(SEC_DHCP_SERVER, 'name', scope.name)}`);
      emitter.add(`${SEC_POOL} remove [${SEC_POOL} find where name="pool-${rosQuote(name)}"]`);
      return;
    }

    case 'dhcpClient': {
      const client = resourceOf(emitter, 'dhcpClient', 'before', op.before);
      if (!client) return;
      emitter.add(
        `${SEC_DHCP_CLIENT} remove ${findByProp(SEC_DHCP_CLIENT, 'interface', client.interfaceName)}`,
      );
      return;
    }

    case 'localUser': {
      const user = resourceOf(emitter, 'localUser', 'before', op.before);
      if (!user) return;
      // Deleting an account needs no secret, and removing a vendor-default
      // administrator is one of the most valuable writes in the product.
      emitter.add(`${SEC_USER} remove ${findByProp(SEC_USER, 'name', user.username)}`);
      return;
    }

    case 'ipsecPeer': {
      const peer = resourceOf(emitter, 'ipsecPeer', 'before', op.before);
      if (!peer) return;
      if (!peer.name) {
        emitter.refuse(
          'identity_too_weak',
          'the peer has no name, and /ip/ipsec/identity and /ip/ipsec/policy reference a peer ' +
            'BY NAME — without it the tunnel cannot be taken down as one object.',
        );
        return;
      }
      const name = peer.name;
      emitter.add(`${SEC_IPSEC_POLICY} remove [${SEC_IPSEC_POLICY} find where peer="${rosQuote(name)}"]`);
      emitter.add(
        `${SEC_IPSEC_IDENTITY} remove [${SEC_IPSEC_IDENTITY} find where peer="${rosQuote(name)}"]`,
      );
      emitter.add(`${SEC_IPSEC_PEER} remove ${findByProp(SEC_IPSEC_PEER, 'name', name)}`);
      return;
    }

    case 'qosRule': {
      const queue = resourceOf(emitter, 'qosRule', 'before', op.before);
      if (!queue) return;
      const section = queueSection(emitter, queue);
      if (!section) return;
      emitter.add(`${section} remove ${findByProp(section, 'name', queue.name as string)}`);
      return;
    }

    case 'service':
      emitter.refuse(
        'unrenderable_resource',
        '`/ip/service` entries and `/snmp` are fixed singletons on RouterOS and cannot be ' +
          'removed. Disabling one is an `update`, not a `delete`.',
      );
      return;
  }
}

function queueSection(emitter: OpEmitter, queue: ResourceOf<'qosRule'>): string | null {
  if (!queue.name) {
    emitter.refuse('identity_too_weak', 'the queue has no name to locate it by.');
    return null;
  }
  if (queue.queueClass === 'simple') return SEC_QUEUE_SIMPLE;
  if (queue.queueClass === 'tree') return SEC_QUEUE_TREE;
  emitter.refuse(
    'unrenderable_resource',
    `queue class "${queue.queueClass}" has no RouterOS menu.`,
  );
  return null;
}

// ============================================================================
// update
// ============================================================================

/**
 * `op.fields` is the authority on what changes. Rendering the whole resource
 * with `set` would also rewrite fields nobody reviewed — and on a firewall rule
 * that means re-asserting a match the operator did not touch, from a model that
 * may be a partial reading of it (N5).
 */
function renderUpdate(emitter: OpEmitter, op: PlanOp): void {
  const fields = new Set(op.fields);
  const touches = (...names: string[]): boolean => names.some((n) =>
    fields.has(n) || [...fields].some((f) => f.startsWith(`${n}.`)));

  switch (op.resource) {
    case 'route': {
      const before = resourceOf(emitter, 'route', 'before', op.before);
      const after = resourceOf(emitter, 'route', 'after', op.after);
      if (!before || !after) return;
      if (touches('dst', 'gateway', 'table')) {
        emitter.refuse(
          'unrenderable_resource',
          'this update changes the route\'s own identity (destination, gateway or table), which ' +
            `is what \`routeKey\` is built from. A plan that renames a key is a delete plus a ` +
            'create, and the planner has to say so explicitly — silently `set`ting it would ' +
            'leave the plan unable to find the route again.',
        );
        return;
      }
      const clauses: string[] = [];
      if (fields.has('distance') && after.distance !== null) clauses.push(`distance=${after.distance}`);
      if (fields.has('scope') && after.scope !== null) clauses.push(`scope=${after.scope}`);
      if (fields.has('targetScope') && after.targetScope !== null) {
        clauses.push(`target-scope=${after.targetScope}`);
      }
      if (fields.has('checkGateway')) {
        clauses.push(`check-gateway=${after.checkGateway ?? 'none'}`);
      }
      if (fields.has('comment')) clauses.push(`comment="${rosQuote(fullComment(after))}"`);
      if (clauses.length === 0) {
        emitter.refuse(
          'field_not_in_model',
          `none of the changed fields (${op.fields.join(', ')}) maps to a RouterOS /ip/route ` +
            'property this renderer can set.',
        );
        return;
      }
      emitter.add(`${SEC_ROUTE} set ${routeLocator(before)} ${clauses.join(' ')}`);
      return;
    }

    case 'firewallRule': {
      const before = resourceOf(emitter, 'firewallRule', 'before', op.before);
      const after = resourceOf(emitter, 'firewallRule', 'after', op.after);
      if (!before || !after) return;
      if (touches('match', 'chain', 'chainName')) {
        emitter.refuse(
          'unrenderable_resource',
          'this update changes the rule\'s MATCH side, which is its identity (N1 — `matchHash`). ' +
            'A `set` rewrites only the properties it names, so the edited rule would keep every ' +
            'selector the new match drops; the planner expresses a match change as a delete ' +
            'plus a create instead.',
        );
        return;
      }
      // On `before` as well as inside `firewallSpec(after)`: the update is
      // located from the old record, and `touches('chainName')` above already
      // refuses a plan that tries to change the table under us.
      if (refuseNonFilterTable(emitter, before)) return;
      const locator = locateOrderedRule(emitter, SEC_FILTER, before);
      if (!locator) return;
      const spec = firewallSpec(emitter, after);
      if (!spec) return;
      const clauses = [...(spec.actionClause as string[])];
      if (fields.has('comment')) clauses.push(`comment="${rosQuote(fullComment(after))}"`);
      emitter.add(`${SEC_FILTER} set ${locator} ${clauses.join(' ')}`);
      return;
    }

    case 'natRule': {
      const before = resourceOf(emitter, 'natRule', 'before', op.before);
      const after = resourceOf(emitter, 'natRule', 'after', op.after);
      if (!before || !after) return;
      if (touches('match', 'chain', 'chainName')) {
        emitter.refuse(
          'unrenderable_resource',
          'this update changes the NAT rule\'s MATCH side, which is its identity (N1). The ' +
            'planner has to express it as a delete plus a create.',
        );
        return;
      }
      const locator = locateOrderedRule(emitter, SEC_NAT, before);
      if (!locator) return;
      const spec = natSpec(emitter, after);
      if (!spec) return;
      const clauses = [...(spec.actionClause as string[])];
      if (fields.has('comment')) clauses.push(`comment="${rosQuote(fullComment(after))}"`);
      emitter.add(`${SEC_NAT} set ${locator} ${clauses.join(' ')}`);
      return;
    }

    case 'interface': {
      const before = resourceOf(emitter, 'interface', 'before', op.before);
      const after = resourceOf(emitter, 'interface', 'after', op.after);
      if (!before || !after) return;
      if (touches('name', 'type', 'parent')) {
        emitter.refuse(
          'unrenderable_resource',
          'renaming or re-parenting an interface changes `interfaceKey`, and every other record ' +
            'of the plan refers to the old name. That is a delete plus a create.',
        );
        return;
      }
      let emitted = false;
      if (fields.has('mtu') && after.mtu !== null) {
        emitter.add(`/interface set ${findByProp('/interface', 'name', after.name)} mtu=${after.mtu}`);
        emitted = true;
      }
      if (fields.has('comment') || fields.has('alias')) {
        emitter.add(
          `/interface set ${findByProp('/interface', 'name', after.name)} ` +
            `comment="${rosQuote(fullComment(after))}"`,
        );
        emitted = true;
      }
      if (touches('addresses')) {
        const had = new Set(before.addresses.map((a) => a.cidr));
        const wants = new Set(after.addresses.map((a) => a.cidr));
        for (const cidr of had) {
          if (wants.has(cidr)) continue;
          emitter.add(
            `${SEC_ADDRESS} remove [${SEC_ADDRESS} find where address="${rosQuote(cidr)}" ` +
              `interface="${rosQuote(after.name)}"]`,
          );
          emitted = true;
        }
        for (const cidr of wants) {
          if (had.has(cidr)) continue;
          emitter.add(
            `${SEC_ADDRESS} add address=${token(cidr)} interface=${token(after.name)} ` +
              `comment="${rosQuote(fullComment(after))}"`,
          );
          emitted = true;
        }
      }
      if (touches('lists')) {
        const had = new Set(before.lists);
        const wants = new Set(after.lists);
        for (const list of had) {
          if (wants.has(list)) continue;
          emitter.add(
            `${SEC_LIST_MEMBER} remove [${SEC_LIST_MEMBER} find where list="${rosQuote(list)}" ` +
              `interface="${rosQuote(after.name)}"]`,
          );
          emitted = true;
        }
        for (const list of wants) {
          if (had.has(list)) continue;
          emitter.add(
            `${SEC_LIST_MEMBER} add list=${token(list)} interface=${token(after.name)} ` +
              `comment="${rosQuote(fullComment(after))}"`,
          );
          emitted = true;
        }
      }
      if (!emitted) {
        emitter.refuse(
          'field_not_in_model',
          `none of the changed fields (${op.fields.join(', ')}) maps to a RouterOS interface ` +
            'property this renderer can set. `zone` in particular is null on every MikroTik ' +
            'record — it exists for the brands that have a zone model.',
        );
      }
      return;
    }

    case 'dhcpScope': {
      const before = resourceOf(emitter, 'dhcpScope', 'before', op.before);
      const after = resourceOf(emitter, 'dhcpScope', 'after', op.after);
      if (!before || !after) return;
      if (touches('name', 'onInterface')) {
        emitter.refuse(
          'unrenderable_resource',
          'the scope name and its interface are spread across /ip/pool, /ip/dhcp-server and ' +
            'every lease that names the server. Changing either is a delete plus a create, not ' +
            'a `set`.',
        );
        return;
      }
      if (touches('options')) {
        emitter.refuse(
          'unrenderable_resource',
          'RouterOS DHCP options are named objects with a declared value type under ' +
            '/ip/dhcp-server/option, and the NCM records neither.',
        );
        return;
      }
      const name = token(after.name);
      let emitted = false;
      if (touches('poolFrom', 'poolTo')) {
        if (after.poolFrom === null || after.poolTo === null) {
          emitter.refuse(
            'field_not_in_model',
            'the new pool range is partly unknown (`null` is not an address), and a half-written ' +
              '`ranges=` hands out addresses nobody chose.',
          );
          return;
        }
        emitter.add(
          `${SEC_POOL} set [${SEC_POOL} find where name="pool-${rosQuote(name)}"] ` +
            `ranges=${token(after.poolFrom)}-${token(after.poolTo)}`,
        );
        emitted = true;
      }
      if (fields.has('leaseSeconds') && after.leaseSeconds !== null) {
        emitter.add(
          `${SEC_DHCP_SERVER} set ${findByProp(SEC_DHCP_SERVER, 'name', after.name)} ` +
            `lease-time=${after.leaseSeconds}s`,
        );
        emitted = true;
      }
      if (fields.has('comment')) {
        emitter.add(
          `${SEC_DHCP_SERVER} set ${findByProp(SEC_DHCP_SERVER, 'name', after.name)} ` +
            `comment="${rosQuote(fullComment(after))}"`,
        );
        emitted = true;
      }
      if (fields.has('subnet')) {
        emitter.refuse(
          'unrenderable_resource',
          'the /ip/dhcp-server/network row IS keyed on its address, so re-subnetting a scope is ' +
            'a delete plus a create.',
        );
        return;
      }
      if (touches('gateway', 'dnsServers', 'ntpServers', 'domain')) {
        const clauses: string[] = [];
        if (fields.has('gateway')) clauses.push(`gateway=${token(after.gateway ?? '')}`);
        if (touches('dnsServers')) clauses.push(`dns-server=${after.dnsServers.map(token).join(',')}`);
        if (touches('ntpServers')) clauses.push(`ntp-server=${after.ntpServers.map(token).join(',')}`);
        if (fields.has('domain')) clauses.push(`domain=${token(after.domain ?? '')}`);
        if (clauses.length > 0) {
          emitter.add(
            `${SEC_DHCP_NETWORK} set [${SEC_DHCP_NETWORK} find where ` +
              `address="${rosQuote(before.subnet)}"] ${clauses.join(' ')}`,
          );
          emitted = true;
        }
      }
      if (touches('reservations')) {
        const had = new Map(before.reservations.map((r) => [r.mac, r]));
        const wants = new Map(after.reservations.map((r) => [r.mac, r]));
        for (const mac of had.keys()) {
          if (wants.has(mac)) continue;
          emitter.add(
            `${SEC_DHCP_LEASE} remove [${SEC_DHCP_LEASE} find where ` +
              `server="${rosQuote(after.name)}" mac-address="${rosQuote(mac.toUpperCase())}"]`,
          );
          emitted = true;
        }
        for (const [mac, r] of wants) {
          const old = had.get(mac);
          if (old && old.address === r.address && reservationComment(old) === reservationComment(r)) {
            continue;
          }
          if (old) {
            emitter.add(
              `${SEC_DHCP_LEASE} set [${SEC_DHCP_LEASE} find where server="${rosQuote(after.name)}" ` +
                `mac-address="${rosQuote(mac.toUpperCase())}"] address=${token(r.address)} ` +
                `comment="${rosQuote(reservationComment(r))}"`,
            );
          } else {
            emitter.add(
              `${SEC_DHCP_LEASE} add server=${name} mac-address=${token(mac.toUpperCase())} ` +
                `address=${token(r.address)} comment="${rosQuote(reservationComment(r))}"`,
            );
          }
          emitted = true;
        }
      }
      if (!emitted) {
        emitter.refuse(
          'field_not_in_model',
          `none of the changed fields (${op.fields.join(', ')}) maps to a RouterOS DHCP ` +
            'property this renderer can set.',
        );
      }
      return;
    }

    case 'dhcpClient': {
      const before = resourceOf(emitter, 'dhcpClient', 'before', op.before);
      const after = resourceOf(emitter, 'dhcpClient', 'after', op.after);
      if (!before || !after) return;
      if (touches('interfaceName')) {
        emitter.refuse(
          'unrenderable_resource',
          'a DHCP client is keyed on its interface (`dhcpClientKey`); moving it to another ' +
            'interface is a delete plus a create.',
        );
        return;
      }
      const clauses = dhcpClientClauses(emitter, after);
      if (!clauses) return;
      if (clauses.length === 0) {
        emitter.refuse(
          'field_not_in_model',
          `the changed fields (${op.fields.join(', ')}) left nothing this renderer can set: ` +
            'every flag the op touches is `null`, which means "the collector did not report it", ' +
            'not "off".',
        );
        return;
      }
      emitter.add(
        `${SEC_DHCP_CLIENT} set ${findByProp(SEC_DHCP_CLIENT, 'interface', after.interfaceName)} ` +
          `${clauses.join(' ')}`,
      );
      return;
    }

    case 'service': {
      const after = resourceOf(emitter, 'service', 'after', op.after);
      if (!after) return;
      renderServiceUpdate(emitter, op, after, fields);
      return;
    }

    case 'localUser': {
      const after = resourceOf(emitter, 'localUser', 'after', op.after);
      if (!after) return;
      if (touches('passwordFingerprint', 'sshKeyFingerprints')) {
        emitter.refuse(
          'secret_not_in_model',
          'this update changes the account\'s credential, and the NCM carries only a per-tenant ' +
            'HMAC of it. Writing `password=""` would leave an administrator ' +
            'account with no password at all.',
        );
        return;
      }
      if (touches('username')) {
        emitter.refuse(
          'unrenderable_resource',
          'renaming an account changes `localUserKey`. That is a delete plus a create, and it ' +
            'needs the password the NCM does not carry.',
        );
        return;
      }
      const clauses: string[] = [];
      if (fields.has('group') && after.group !== null) clauses.push(`group=${token(after.group)}`);
      if (touches('allowedFrom')) {
        // `address=""` clears the restriction. Omitting the clause would leave
        // the old one in place, which is the opposite of what the plan says.
        clauses.push(
          `address="${isAny(after.allowedFrom) ? '' : rosQuote(after.allowedFrom.map(atomValue).join(','))}"`,
        );
      }
      if (fields.has('comment')) clauses.push(`comment="${rosQuote(fullComment(after))}"`);
      if (clauses.length === 0) {
        emitter.refuse(
          'field_not_in_model',
          `none of the changed fields (${op.fields.join(', ')}) maps to a RouterOS /user ` +
            'property this renderer can set without the account\'s password.',
        );
        return;
      }
      emitter.add(`${SEC_USER} set ${findByProp(SEC_USER, 'name', after.username)} ${clauses.join(' ')}`);
      return;
    }

    case 'ipsecPeer':
      emitter.refuse(
        'unrenderable_resource',
        'an IPsec tunnel is four RouterOS objects (profile, peer, identity, policy) and the ' +
          '`ipsecPeer` record is a flattened view of all four. Editing one field of it in place ' +
          'cannot be spelled without knowing which object holds it — and any change to the ' +
          'authentication side needs the PSK the NCM does not carry.',
      );
      return;

    case 'qosRule': {
      const before = resourceOf(emitter, 'qosRule', 'before', op.before);
      const after = resourceOf(emitter, 'qosRule', 'after', op.after);
      if (!before || !after) return;
      if (touches('queueClass', 'name')) {
        emitter.refuse(
          'unrenderable_resource',
          'the queue class and the queue name are both part of `qosRuleKey`; changing either is ' +
            'a delete plus a create.',
        );
        return;
      }
      const section = queueSection(emitter, after);
      if (!section) return;
      const maxLimit = bpsPair(emitter, 'max-limit', after.maxLimitUpBps, after.maxLimitDownBps);
      if (maxLimit === null) return;
      const limitAt = bpsPair(emitter, 'limit-at', after.limitAtUpBps, after.limitAtDownBps);
      if (limitAt === null) return;
      const clauses: string[] = [];
      if (touches('maxLimitUpBps', 'maxLimitDownBps') && maxLimit) clauses.push(maxLimit);
      if (touches('limitAtUpBps', 'limitAtDownBps') && limitAt) clauses.push(limitAt);
      if (fields.has('priority') && after.priority !== null) clauses.push(`priority=${after.priority}`);
      if (fields.has('queueType') && after.queueType !== null) {
        clauses.push(`queue=${token(after.queueType)}`);
      }
      if (touches('target') && section === SEC_QUEUE_SIMPLE) {
        if (isAny(after.target)) {
          emitter.refuse(
            'field_not_in_model',
            'a simple queue with no target would shape every packet on the box.',
          );
          return;
        }
        clauses.push(`target=${after.target.map((a) => token(atomValue(a))).join(',')}`);
      }
      if (fields.has('comment')) clauses.push(`comment="${rosQuote(fullComment(after))}"`);
      if (clauses.length === 0) {
        emitter.refuse(
          'field_not_in_model',
          `none of the changed fields (${op.fields.join(', ')}) maps to a RouterOS queue ` +
            'property this renderer can set.',
        );
        return;
      }
      emitter.add(
        `${section} set ${findByProp(section, 'name', after.name as string)} ${clauses.join(' ')}`,
      );
      return;
    }

    case 'vlan': {
      const before = resourceOf(emitter, 'vlan', 'before', op.before);
      const after = resourceOf(emitter, 'vlan', 'after', op.after);
      if (!before || !after) return;
      if (touches('vlanId', 'parent', 'taggedPorts', 'untaggedPorts')) {
        emitter.refuse(
          'unrenderable_resource',
          'the VLAN id and its parent are `vlanKey` itself, and the port lists live in the ' +
            'bridge VLAN filtering table rather than on the /interface/vlan row. Either change ' +
            'is a delete plus a create.',
        );
        return;
      }
      if (!after.name) {
        emitter.refuse('identity_too_weak', 'the VLAN record has no name to locate it by.');
        return;
      }
      if (!fields.has('comment')) {
        emitter.refuse(
          'field_not_in_model',
          `none of the changed fields (${op.fields.join(', ')}) maps to a settable ` +
            '/interface/vlan property.',
        );
        return;
      }
      emitter.add(
        `${SEC_VLAN} set ${findByProp(SEC_VLAN, 'name', after.name)} ` +
          `comment="${rosQuote(fullComment(after))}"`,
      );
      return;
    }
  }
}

/**
 * `/ip/service` is a fixed set of singletons, `/snmp` is one more, and the two
 * are the same `service` kind in the NCM.
 *
 * The SNMP community is the one place where the model deliberately keeps a
 * fingerprint AND a `communityIsWellKnown` flag. Neither gives back the
 * string, so anything that would have to write `community=` refuses.
 */
function renderServiceUpdate(
  emitter: OpEmitter,
  op: PlanOp,
  after: ResourceOf<'service'>,
  fields: ReadonlySet<string>,
): void {
  if (after.service === 'snmp') {
    if (
      fields.has('communityFingerprint') ||
      fields.has('version') ||
      fields.has('allowedFrom') ||
      fields.has('port')
    ) {
      emitter.refuse(
        'secret_not_in_model',
        'every settable property of a RouterOS SNMP community — its name, its version, its ' +
          'allowed addresses — is set on the /snmp/community row, and writing that row means ' +
          'writing `name=<community>`. The NCM carries `communityFingerprint` (an irreversible ' +
          'HMAC) and `communityIsWellKnown`, never the community itself, so this row cannot be ' +
          'rewritten from a plan. Only `enabled` can.',
      );
      return;
    }
    if (!fields.has('enabled')) {
      emitter.refuse(
        'field_not_in_model',
        `none of the changed fields (${op.fields.join(', ')}) maps to a /snmp property this ` +
          'renderer can set.',
      );
      return;
    }
    emitter.add(`/snmp set enabled=${yesNo(after.enabled)}`);
    return;
  }

  const rosName = ROUTEROS_SERVICE_NAME[after.service];
  if (!rosName) {
    emitter.refuse(
      'unrenderable_resource',
      `"${after.service}" is not an /ip/service entry on RouterOS — it lives in its own menu ` +
        `(cwmp, dns, ntp, upnp, romon, bandwidth-test each in a different one), and the NCM ` +
        'record does not say which verb sets it.',
    );
    return;
  }
  const clauses: string[] = [];
  if (fields.has('enabled')) clauses.push(`disabled=${yesNo(!after.enabled)}`);
  if (fields.has('port') && after.port !== null) clauses.push(`port=${after.port}`);
  if (fields.has('allowedFrom')) {
    clauses.push(
      `address="${isAny(after.allowedFrom) ? '' : rosQuote(after.allowedFrom.map(atomValue).join(','))}"`,
    );
  }
  if (fields.has('certificate')) clauses.push(`certificate=${token(after.certificate ?? 'none')}`);
  if (clauses.length === 0) {
    emitter.refuse(
      'field_not_in_model',
      `none of the changed fields (${op.fields.join(', ')}) maps to an /ip/service property ` +
        'this renderer can set.',
    );
    return;
  }
  emitter.add(routerOsServiceSet(rosName, clauses.join(' ')));
}

// ============================================================================
// enable / disable
// ============================================================================

/**
 * RouterOS has an `enable`/`disable` verb in every menu, so this is the one op
 * kind that needs no field mapping — only a locator. `/ip/service` is the
 * exception: there the state is a `disabled=` property, not a verb.
 */
function renderToggle(emitter: OpEmitter, op: PlanOp): void {
  const verb = op.kind === 'enable' ? 'enable' : 'disable';
  const side = op.before ?? op.after;

  switch (op.resource) {
    case 'route': {
      const route = resourceOf(emitter, 'route', op.before ? 'before' : 'after', side);
      if (!route) return;
      emitter.add(`${SEC_ROUTE} ${verb} ${routeLocator(route)}`);
      return;
    }
    case 'firewallRule': {
      const rule = resourceOf(emitter, 'firewallRule', op.before ? 'before' : 'after', side);
      if (!rule) return;
      // A toggle is the cheapest way to get this wrong: `disable` on a mangle
      // rule's comment would disable the /filter rule that happens to carry it.
      if (refuseNonFilterTable(emitter, rule)) return;
      const locator = locateOrderedRule(emitter, SEC_FILTER, rule);
      if (!locator) return;
      emitter.add(`${SEC_FILTER} ${verb} ${locator}`);
      return;
    }
    case 'natRule': {
      const rule = resourceOf(emitter, 'natRule', op.before ? 'before' : 'after', side);
      if (!rule) return;
      const locator = locateOrderedRule(emitter, SEC_NAT, rule);
      if (!locator) return;
      emitter.add(`${SEC_NAT} ${verb} ${locator}`);
      return;
    }
    case 'interface': {
      const iface = resourceOf(emitter, 'interface', op.before ? 'before' : 'after', side);
      if (!iface) return;
      emitter.add(`/interface ${verb} ${findByProp('/interface', 'name', iface.name)}`);
      return;
    }
    case 'vlan': {
      const vlan = resourceOf(emitter, 'vlan', op.before ? 'before' : 'after', side);
      if (!vlan) return;
      if (!vlan.name) {
        emitter.refuse('identity_too_weak', 'the VLAN record has no name to locate it by.');
        return;
      }
      emitter.add(`${SEC_VLAN} ${verb} ${findByProp(SEC_VLAN, 'name', vlan.name)}`);
      return;
    }
    case 'dhcpScope': {
      const scope = resourceOf(emitter, 'dhcpScope', op.before ? 'before' : 'after', side);
      if (!scope) return;
      emitter.add(`${SEC_DHCP_SERVER} ${verb} ${findByProp(SEC_DHCP_SERVER, 'name', scope.name)}`);
      return;
    }
    case 'dhcpClient': {
      const client = resourceOf(emitter, 'dhcpClient', op.before ? 'before' : 'after', side);
      if (!client) return;
      emitter.add(
        `${SEC_DHCP_CLIENT} ${verb} ${findByProp(SEC_DHCP_CLIENT, 'interface', client.interfaceName)}`,
      );
      return;
    }
    case 'localUser': {
      const user = resourceOf(emitter, 'localUser', op.before ? 'before' : 'after', side);
      if (!user) return;
      emitter.add(`${SEC_USER} ${verb} ${findByProp(SEC_USER, 'name', user.username)}`);
      return;
    }
    case 'ipsecPeer': {
      const peer = resourceOf(emitter, 'ipsecPeer', op.before ? 'before' : 'after', side);
      if (!peer) return;
      if (!peer.name) {
        emitter.refuse('identity_too_weak', 'the peer has no name to locate it by.');
        return;
      }
      emitter.add(`${SEC_IPSEC_PEER} ${verb} ${findByProp(SEC_IPSEC_PEER, 'name', peer.name)}`);
      return;
    }
    case 'qosRule': {
      const queue = resourceOf(emitter, 'qosRule', op.before ? 'before' : 'after', side);
      if (!queue) return;
      const section = queueSection(emitter, queue);
      if (!section) return;
      emitter.add(`${section} ${verb} ${findByProp(section, 'name', queue.name as string)}`);
      return;
    }
    case 'service': {
      const svc = resourceOf(emitter, 'service', op.before ? 'before' : 'after', side);
      if (!svc) return;
      if (svc.service === 'snmp') {
        emitter.add(`/snmp set enabled=${yesNo(op.kind === 'enable')}`);
        return;
      }
      const rosName = ROUTEROS_SERVICE_NAME[svc.service];
      if (!rosName) {
        emitter.refuse(
          'unrenderable_resource',
          `"${svc.service}" is not an /ip/service entry on RouterOS, and the NCM record does ` +
            'not say which menu sets it.',
        );
        return;
      }
      emitter.add(routerOsServiceSet(rosName, `disabled=${yesNo(op.kind === 'disable')}`));
      return;
    }
  }
}
