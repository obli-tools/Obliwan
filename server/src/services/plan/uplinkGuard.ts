// ============================================================================
// ObliWAN — uplink preservation, the sibling of the Management-Path Guard
// ============================================================================
//
// PURE. No database, no socket, no clock. One observed NCM document and a list
// of plan ops in, the ops that would take a production uplink away out.
//
// ┌─ THE OPERATOR RULE THIS FILE ENFORCES (2026-10-04) ──────────────────────┐
// │ On a router in production, never destroy what runs there — and above all │
// │ NEVER take the PPPoE interface (named ADSL, FTTH or FTTO across the      │
// │ fleet) out of the uplinks list.                                          │
// │                                                                          │
// │ How it would happen without this file: a template that creates the       │
// │ PPPoE client but never lists it in `/interface list member … list=WAN`   │
// │ renders a desired NCM where `ADSL.lists` is empty. The production box    │
// │ has `ADSL.lists = ['WAN']`. The diff is a `changed` on `lists`, the      │
// │ planner turns it into an `update`, and the RouterOS renderer emits       │
// │ `/interface list member remove [find where list="WAN" interface="ADSL"]` │
// │ — after which `masquerade out-interface-list=WAN` no longer matches the   │
// │ PPPoE and the whole store loses the internet, while the tunnel, the      │
// │ probes and the guard stay green (it checks the MANAGEMENT path, and      │
// │ the management path does not cross the customer's NAT).                 │
// └──────────────────────────────────────────────────────────────────────────┘
//
// A refusal here is NOT a Management-Path Guard verdict. A guard REJECT is overridable with
// CHANGE_APPROVE; this is not, by design, because the operator's rule says
// "whatever the template says". The planner compiles such an op as a `blocked`
// op (`uplink_preserved`), the queue refuses a plan carrying one at the door
// and again at the job's `guard` step, and no signature lifts it. The way
// forward is to change the TEMPLATE or the SITE VARIABLES so the desired state
// keeps the uplink — then recompile.
//
// ── WHAT IS COVERED, PRECISELY ───────────────────────────────────────────────
//
// The NCM has no `/interface/list/member` resource: a membership is folded
// into `NcmInterface.lists` (normalize.service.ts, quirks.ts — the member row
// `ncmResourceKind` IS `interface`). So "delete a member" is one of:
//
//   (i)   `update` on an `interface` whose `fields` touch `lists` and whose
//         `after.lists` drops an UPLINK LIST, or `delete` of an interface that
//         is a member of one.                     → UPLINK_LIST_MEMBER_REMOVED
//         An uplink list is `WAN` (case-insensitive) PLUS every list named by
//         `out-interface-list=` on a srcnat/masquerade NAT rule of the OBSERVED
//         box — enabled or disabled, conservatively. A NEGATED list
//         (`out-interface-list=!LAN`) names no list and is not resolved.
//   (ii)  `delete` / `disable` (or an `update` setting `disabled`) of an
//         interface of NCM type `pppoe` — a `/interface/pppoe-client` row —
//         or of an interface NAMED ADSL / FTTH / FTTO whatever its type
//         (a member row referencing a client the export did not list is typed
//         by `guessType`, i.e. `other`; the name still protects it).
//                                    → PPPOE_UPLINK_REMOVED / _DISABLED
//   (iii) `delete` / `disable` of any other UPLINK INTERFACE: a member of an
//         uplink list, the `out-interface=` of a srcnat rule, the interface a
//         configured default route leaves through, the interface of a DHCP
//         client that installs a default route, and — to a fixpoint — the
//         PARENT of any of those (ether1 under the PPPoE, the VLAN 832 under an
//         FTTH client). Covers `interface` and `vlan` records.
//                                    → UPLINK_INTERFACE_REMOVED / _DISABLED
//   (iv)  `delete` / `disable` / re-key (`gateway`, `dst`, `table`, `vrf`) of a
//         STATIC default route (`0.0.0.0/0`, `::/0`) that has a gateway. Its
//         gateway interface is by definition the interface carrying a default
//         route, i.e. an uplink; an `ip:` gateway is tied to the interface
//         whose STATIC address covers it, and one no static subnet covers
//         (learned by DHCP/PPP — customer A's `WAN1-GW` case) is protected
//         rather than guessed at. A blackhole default (`gateway: null`) carries
//         nothing and is not protected. A DISABLED default route is protected
//         too: a netwatch failover toggles exactly that flag, so "disabled at
//         collection time" is not proof of "unused".
//                                    → UPLINK_DEFAULT_ROUTE_REMOVED
//         Plus the DHCP client that holds an uplink up: `delete` / `disable`,
//         or `addDefaultRoute: true → false`, of a `dhcpClient` on an uplink
//         interface or installing a default route.
//                                    → UPLINK_DHCP_CLIENT_REMOVED
//   (v)   an `update` of an interface's `addresses` that drops the STATIC
//         address an `ip:` gateway of a static default route (disabled or
//         not, as in (iv)) is covered by, and keeps none that covers it — the
//         static-IP uplink (FTTO-style) whose template carries a wrong or
//         missing WAN address. A re-IP that keeps the gateway covered on the
//         same interface passes; one that moves the address to another port
//         is refused (the rule is judged op by op).
//                                    → UPLINK_GATEWAY_ADDRESS_REMOVED
//
// Every rule is judged on every record the op can reach — the box's record
// of its semKey, the box's records of the NAME / dst+gateway / DHCP interface
// either side of the op names, and the op's own sides — because the renderer
// locates a `disable` with `before: null` through its `after`, and an
// interface update's removals through `after.name` (see `uplinkViolationsForOp`).
//
// ── WHAT THE NCM CANNOT EXPRESS (so there is nothing a plan could delete) ───
//
//   - a member row's OWN `disabled=yes`: the normaliser reads `list` and
//     `interface` only, so a disabled member is filed as a member (and is
//     therefore protected here) and no plan op can disable one;
//   - the `/interface/list` object itself: names only, never a resource;
//   - the PPPoE client's `add-default-route`, `user`, `password`, `profile`:
//     consumed by the normaliser, never diffed, never rendered — a template
//     that turns `add-default-route` off produces NO op at all;
//   - the DYNAMIC default routes a PPPoE / DHCP / LTE link installs: state,
//     not configuration, never in the NCM. Which of several default routes is
//     ACTIVE is state too — every configured one is protected;
//   - `/interface/lte/apn … add-default-route`: unmodelled; `lte1` is
//     protected only through the WAN list / NAT / a static default route;
//   - creating a PPPoE client: the renderer refuses it (it needs a credential
//     the NCM never carries), so a template cannot (re)create one either.
//
// Not covered on purpose: a NAT or firewall rule (deleting the masquerade is a
// different rule than "keep the uplink"), a re-parent or rename of the PPPoE
// (`renderUpdate` already refuses both by name), an `enable` or a `create`
// (neither removes anything), a `distance` change on a default route (it
// re-orders uplinks, it removes none), and the address of an interface an
// `iface:` gateway names (the route names the interface, not a subnet). The
// address rule (v) needs the snapshot: with no observed document there are
// no default routes to tie an address to.
//
// ── WHAT A TEMPLATE CAN ACTUALLY PRODUCE TODAY (plan/testing/uplinkGuard.verify.ts)
//
//   - interface DELETES: none on RouterOS. `coverage.interface` is `partial` by
//     construction, so N3 never turns "absent from the template" into a delete:
//     a body that omits the PPPoE client compiles no op on it at all. The
//     delete rules bite on plans the queue receives from anywhere else.
//   - dhcpClient ops: none. `quirks.ts` has no section spec for
//     `/ip/dhcp-client`, so a template cannot claim the kind (N3 again).
//   - what DOES reach the planner: an interface `update` on `lists` (customer A's
//     defect) or on `addresses`, interface / vlan disables, static route
//     deletes and disables.
//
// ── WHERE IT IS ENFORCED ───────────────────────────────────────────────────
//
//   planner.service `buildOps`    the op becomes `blocked` / `uplink_preserved`
//   apply.service `previewChange` `uplinkRefusals`, before anything is armed
//   apply.service `enqueueChangeJob`  `ChangeRefusedError('uplink_preservation')`
//   apply.service `runJob`, step `guard`  the same, before backup and dead-man
//   rollout.service composition   the device is a failure, never a wave target

import type {
  NcmDhcpClient, NcmDocument, NcmInterface, NcmResourceKind, NcmRoute,
  NcmVlan, PlanOp, PlanOpKind, Selector,
} from '@obliwan/shared';
import { parseCidr } from '@obliwan/shared';
import { cidrContains } from './riskScoring';

// ============================================================================
// Vocabulary
// ============================================================================

export const UPLINK_GUARD_CODES = [
  'UPLINK_LIST_MEMBER_REMOVED',
  'PPPOE_UPLINK_REMOVED',
  'PPPOE_UPLINK_DISABLED',
  'UPLINK_INTERFACE_REMOVED',
  'UPLINK_INTERFACE_DISABLED',
  'UPLINK_DEFAULT_ROUTE_REMOVED',
  'UPLINK_GATEWAY_ADDRESS_REMOVED',
  'UPLINK_DHCP_CLIENT_REMOVED',
] as const;
export type UplinkGuardCode = (typeof UPLINK_GUARD_CODES)[number];

/** The `blockedReason` the planner writes. Kept here so the planner, the queue
 *  and the harness name the same string. */
export const UPLINK_BLOCK_REASON = 'uplink_preserved' as const;

/** The refusal kind the queue throws. Distinct from `guard_refused`, which an
 *  override can lift; this one no signature lifts. */
export const UPLINK_REFUSAL_KIND = 'uplink_preservation' as const;

/** The uplinks list every template of the fleet writes. Compared
 *  case-insensitively: a refusal on a list someone called `wan` costs a
 *  template edit, a missed one costs a store. */
export const WAN_LIST_NAME = 'WAN';

/** Production names of the PPPoE uplink across the fleet (operator, 2026-10-04). */
export const PPPOE_UPLINK_NAMES: readonly string[] = ['ADSL', 'FTTH', 'FTTO'];
const PPPOE_NAME_RE = /^(adsl|ftth|ftto)$/i;

export interface UplinkViolation {
  code: UplinkGuardCode;
  resource: NcmResourceKind;
  semKey: string;
  /** What is protected: an interface, `ADSL ∈ WAN`, a route. */
  subject: string;
  /** One clause, brand-neutral, no secret (the NCM carries none). */
  message: string;
  /** `seq` of the op, when judged from a plan. */
  opSeq: number | null;
}

// ============================================================================
// Facts — derived from the OBSERVED document, never from the desired one
// ============================================================================

/** The four kinds this file judges. `NcmResource` (the discriminated union) has
 *  no `dhcpClient` member — v2 added the kind, not the union entry. */
export type UplinkRecord = NcmInterface | NcmVlan | NcmRoute | NcmDhcpClient;

export interface UplinkFacts {
  /** list name -> why it is an uplink list. `WAN` is always there. */
  uplinkLists: ReadonlyMap<string, string>;
  /** interface name -> why it is an uplink (one or more reasons). */
  uplinkInterfaces: ReadonlyMap<string, readonly string[]>;
  /** The observed records the ops are judged against, by semKey. An op's own
   *  `before` is the plan's word; the box's record is the evidence. */
  observedByKey: ReadonlyMap<string, UplinkRecord>;
  /** The same records by the identity the RENDERER locates them by —
   *  `find where name=` / `interface=` / `dst-address= gateway=` — which a
   *  hand-made op is free to pair with a semKey the box does not have. */
  interfacesByName: ReadonlyMap<string, readonly NcmInterface[]>;
  vlansByName: ReadonlyMap<string, readonly NcmVlan[]>;
  dhcpClientsByInterface: ReadonlyMap<string, readonly NcmDhcpClient[]>;
  routes: readonly NcmRoute[];
  /** Every static default route with an `ip:` gateway (disabled ones too, as
   *  in (iv)): the address that covers the gateway is what makes it usable. */
  defaultIpGateways: readonly { dst: string; ip: string }[];
  /** The observed interfaces, for tying an `ip:` gateway to a static subnet. */
  interfaces: readonly NcmInterface[];
  /** Default routes whose `ip:` gateway no static subnet covers. Protected. */
  unresolvedDefaultGateways: readonly string[];
  /** `out-interface-list=!X` on a srcnat rule: names no list, not resolved. */
  negatedNatLists: readonly string[];
}

const SRCNAT_ACTIONS: ReadonlySet<string> = new Set(['masquerade', 'srcnat']);

export function isUplinkListName(facts: UplinkFacts, list: string): boolean {
  return list.toUpperCase() === WAN_LIST_NAME || facts.uplinkLists.has(list);
}

export function isPppoeUplinkName(name: string | null | undefined): boolean {
  return typeof name === 'string' && PPPOE_NAME_RE.test(name);
}

export function isDefaultDst(dst: string | null | undefined): boolean {
  if (typeof dst !== 'string') return false;
  const c = parseCidr(dst);
  return c !== null && c.prefix === 0;
}

function atomsOf(sel: Selector | null | undefined, tag: string): { value: string; negated: boolean }[] {
  const out: { value: string; negated: boolean }[] = [];
  for (const atom of sel ?? []) {
    if (!atom.startsWith(`${tag}:`)) continue;
    const raw = atom.slice(tag.length + 1);
    const negated = raw.startsWith('!');
    out.push({ value: negated ? raw.slice(1) : raw, negated });
  }
  return out;
}

/**
 * Where a route's gateway leaves, as far as the CONFIGURATION can say: an
 * `iface:` gateway names it, an `ip:` gateway is tied to the interface whose
 * STATIC address covers it. A DHCP- or PPP-learned subnet is state and never in
 * the NCM, so such a gateway resolves to nothing — and is protected anyway.
 */
export function resolveGateway(
  interfaces: readonly NcmInterface[],
  gateway: string | null,
): { iface: string | null; label: string } {
  if (gateway === null) return { iface: null, label: 'blackhole' };
  const colon = gateway.indexOf(':');
  const tag = colon < 0 ? '' : gateway.slice(0, colon);
  const value = colon < 0 ? gateway : gateway.slice(colon + 1);
  if (tag === 'iface') return { iface: value, label: `interface "${value}"` };
  if (tag === 'ip') {
    const iface = interfaces.find((i) => i.addresses.some((a) => cidrContains(a.cidr, value)));
    return iface
      ? { iface: iface.name, label: `${value} via "${iface.name}"` }
      : { iface: null, label: `${value} (on no static subnet: learned by DHCP/PPP, protected rather than guessed)` };
  }
  return { iface: null, label: gateway };
}

export function buildUplinkFacts(observed: NcmDocument | null): UplinkFacts {
  const uplinkLists = new Map<string, string>([[WAN_LIST_NAME, 'the uplinks list']]);
  const negatedNatLists: string[] = [];
  const reasons = new Map<string, string[]>();
  const add = (name: string, why: string): void => {
    const list = reasons.get(name);
    if (!list) reasons.set(name, [why]);
    else if (!list.includes(why)) list.push(why);
  };
  const observedByKey = new Map<string, UplinkRecord>();
  const interfacesByName = new Map<string, NcmInterface[]>();
  const vlansByName = new Map<string, NcmVlan[]>();
  const dhcpClientsByInterface = new Map<string, NcmDhcpClient[]>();
  const defaultIpGateways: { dst: string; ip: string }[] = [];
  const index = <T>(map: Map<string, T[]>, key: string | null | undefined, rec: T): void => {
    if (typeof key !== 'string' || key === '') return;
    const list = map.get(key);
    if (list) list.push(rec);
    else map.set(key, [rec]);
  };
  const unresolvedDefaultGateways: string[] = [];
  const interfaces = observed?.resources.interfaces ?? [];

  const res = observed?.resources;
  if (res) {
    for (const r of res.interfaces) { observedByKey.set(r.semKey, r); index(interfacesByName, r.name, r); }
    for (const r of res.vlans) { observedByKey.set(r.semKey, r); index(vlansByName, r.name, r); }
    for (const r of res.routes) {
      observedByKey.set(r.semKey, r);
      if (isDefaultDst(r.dst) && typeof r.gateway === 'string' && r.gateway.startsWith('ip:')) {
        defaultIpGateways.push({ dst: r.dst, ip: r.gateway.slice('ip:'.length) });
      }
    }
    for (const r of res.dhcpClients ?? []) {
      observedByKey.set(r.semKey, r);
      index(dhcpClientsByInterface, r.interfaceName, r);
    }

    // ── which lists, and which interfaces, the box NATs its LAN out of ─────
    for (const rule of res.natRules) {
      if (!SRCNAT_ACTIONS.has(rule.action)) continue;
      for (const a of atomsOf(rule.match.outInterface, 'ifaceList')) {
        if (a.negated) { negatedNatLists.push(a.value); continue; }
        if (!uplinkLists.has(a.value)) {
          uplinkLists.set(a.value, `the out-interface-list of a ${rule.action} rule`);
        }
      }
      for (const a of atomsOf(rule.match.outInterface, 'iface')) {
        if (!a.negated) add(a.value, `the out-interface of a ${rule.action} rule`);
      }
    }

    for (const iface of res.interfaces) {
      if (iface.type === 'pppoe') add(iface.name, 'a PPPoE client');
      else if (isPppoeUplinkName(iface.name)) add(iface.name, 'named like a production PPPoE uplink');
      for (const list of iface.lists) {
        if (list.toUpperCase() === WAN_LIST_NAME || uplinkLists.has(list)) {
          add(iface.name, `a member of "${list}"`);
        }
      }
    }

    // ── what the configured default routes leave through ───────────────────
    for (const route of res.routes) {
      if (!isDefaultDst(route.dst) || route.gateway === null) continue;
      const via = resolveGateway(interfaces, route.gateway);
      if (via.iface) add(via.iface, `the gateway interface of default route ${route.dst}`);
      else unresolvedDefaultGateways.push(via.label);
    }
    for (const client of res.dhcpClients ?? []) {
      if (client.addDefaultRoute === true) add(client.interfaceName, 'a DHCP client that installs a default route');
    }

    // ── the parents an uplink rides, to a fixpoint ─────────────────────────
    const parentOf = new Map<string, string | null>(res.interfaces.map((i) => [i.name, i.parent]));
    for (const v of res.vlans) {
      if (v.name && !parentOf.get(v.name) && v.parent) parentOf.set(v.name, v.parent);
    }
    let grew = true;
    for (let pass = 0; grew && pass <= parentOf.size; pass++) {
      grew = false;
      for (const name of [...reasons.keys()]) {
        const parent = parentOf.get(name);
        if (!parent) continue;
        const why = `the parent of uplink "${name}"`;
        const had = reasons.get(parent);
        if (!had || !had.includes(why)) { add(parent, why); grew = true; }
      }
    }
  }

  return {
    uplinkLists,
    uplinkInterfaces: reasons,
    observedByKey,
    interfacesByName,
    vlansByName,
    dhcpClientsByInterface,
    routes: res?.routes ?? [],
    defaultIpGateways,
    interfaces,
    unresolvedDefaultGateways,
    negatedNatLists,
  };
}

// ============================================================================
// One op
// ============================================================================

/** The parts of a plan op this file reads. A `PlanOp` is one; so is a planner
 *  draft before it has a `seq`. */
export interface UplinkOpView {
  seq?: number | null;
  kind: PlanOpKind;
  resource: NcmResourceKind;
  semKey: string;
  /** Optional like `PlanOp`'s (zod infers `unknown` keys as optional). */
  before?: unknown;
  after?: unknown;
  fields: readonly string[];
}

function asRecord<T>(v: unknown): T | null {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as T) : null;
}

function touches(fields: readonly string[], ...heads: string[]): boolean {
  return fields.some((f) => heads.includes(f.split('.')[0]));
}

/** `disable`, or an `update` whose `disabled` goes to true. */
function isDisabling(op: UplinkOpView, before: { disabled?: boolean } | null): boolean {
  if (op.kind === 'disable') return true;
  if (op.kind !== 'update' || !touches(op.fields, 'disabled')) return false;
  const after = asRecord<{ disabled?: boolean }>(op.after);
  return after?.disabled === true && before?.disabled !== true;
}

/** A route gateway the way `routeLocator` matches it: the atom's value, its
 *  `ip:` / `iface:` tag dropped (`find where dst-address=… gateway=…` — the
 *  table is not part of the locator). */
function gatewayValue(gateway: unknown): string | null {
  if (typeof gateway !== 'string') return null;
  const colon = gateway.indexOf(':');
  return colon < 0 ? gateway : gateway.slice(colon + 1);
}

/** The object records among `values`, each once (by identity). */
function uniqueRecords<T>(values: readonly unknown[]): T[] {
  const out: T[] = [];
  for (const v of values) {
    const r = asRecord<T>(v);
    if (r !== null && !out.includes(r)) out.push(r);
  }
  return out;
}

const nonEmpty = (v: unknown): v is string => typeof v === 'string' && v !== '';

/**
 * The uplink rules this op breaks. Empty when it breaks none. Pure.
 *
 * An op is judged on EVERY record it can reach, because the renderer does not
 * read the same side for every kind: a delete locates `before`, a toggle
 * `before ?? after` (`renderToggle`), an update locates a route by `before`
 * but writes an interface's member and address removals, and a VLAN's or a
 * DHCP client's `set`, against `after`. So:
 *
 *   - the IDENTITY — interface name, VLAN name, route dst + gateway, DHCP-client
 *     interface — is read off the observed record of the op's semKey AND both
 *     sides of the op, and the box is looked up by that identity, the way
 *     `find where name=…` will look it up, not only by a semKey a hand-made op
 *     is free to invent;
 *   - the STATE judged (which lists, which addresses, already disabled?) is
 *     those box records plus the op's `before`, plus its `after` unless the op
 *     is an `update` — an update's `after` is the target, not the state; a
 *     toggle's `after` is the very record a `before: null` toggle locates.
 *
 * A plan handed to the queue is a request body: a `before` that understates
 * the box, a `before: null`, or a box record that understates what the op
 * names, must not understate the refusal.
 */
export function uplinkViolationsForOp(facts: UplinkFacts, op: UplinkOpView): UplinkViolation[] {
  if (op.kind !== 'delete' && op.kind !== 'disable' && op.kind !== 'update') return [];
  const seq = typeof op.seq === 'number' ? op.seq : null;
  const out: UplinkViolation[] = [];
  const push = (code: UplinkGuardCode, subject: string, message: string): void => {
    if (out.some((x) => x.code === code && x.subject === subject)) return;
    out.push({ code, resource: op.resource, semKey: op.semKey, subject, message, opSeq: seq });
  };
  const fromBox = facts.observedByKey.get(op.semKey) ?? null;
  /** Where the renderer may locate the record: both sides, every kind. */
  const sides: readonly unknown[] = [fromBox, op.before, op.after];
  /** What is there BEFORE the op runs. */
  const stateSides: readonly unknown[] = op.kind === 'update' ? [op.before] : [op.before, op.after];

  switch (op.resource) {
    case 'interface': {
      const named = (r: NcmInterface): boolean => nonEmpty(r.name);
      const ident = uniqueRecords<NcmInterface>(sides).filter(named);
      const names = [...new Set(ident.map((r) => r.name))];
      if (names.length === 0) return [];
      const name = names[0];
      const recs = uniqueRecords<NcmInterface>([
        fromBox,
        ...names.flatMap((n) => facts.interfacesByName.get(n) ?? []),
        ...stateSides,
      ]).filter(named);
      const after = asRecord<NcmInterface>(op.after);

      // (i) list membership — whatever interface it is, leaving an uplink list
      //     is the rule the operator named first.
      const had = new Set<string>(recs.flatMap((r) => (Array.isArray(r.lists) ? r.lists : [])));
      const keeps = op.kind === 'delete'
        ? new Set<string>()
        : op.kind === 'update' && touches(op.fields, 'lists')
          ? new Set<string>(Array.isArray(after?.lists) ? after.lists : [])
          : had;
      for (const list of had) {
        if (keeps.has(list) || !isUplinkListName(facts, list)) continue;
        push(
          'UPLINK_LIST_MEMBER_REMOVED',
          `${name} ∈ ${list}`,
          `would take "${name}" out of interface list "${list}" (` +
            `${list.toUpperCase() === WAN_LIST_NAME ? 'the uplinks list' : facts.uplinkLists.get(list) ?? 'an uplink list'})`,
        );
      }

      // (ii) / (iii) the interface itself
      const pppoe = [...recs, ...ident].some((r) => r.type === 'pppoe') || names.some((n) => isPppoeUplinkName(n));
      const why = [...new Set([
        ...names.flatMap((n) => facts.uplinkInterfaces.get(n) ?? []),
        ...[...had].filter((l) => isUplinkListName(facts, l)).map((l) => `a member of "${l}"`),
      ])];
      const whyText = why.slice(0, 3).join(', ');
      const disabled = recs.some((r) => r.disabled === true);
      if (op.kind === 'delete') {
        if (pppoe) push('PPPOE_UPLINK_REMOVED', name, `would delete the PPPoE uplink "${name}"`);
        else if (why.length > 0) push('UPLINK_INTERFACE_REMOVED', name, `would delete uplink interface "${name}" (${whyText})`);
      } else if (isDisabling(op, { disabled })) {
        if (pppoe) push('PPPOE_UPLINK_DISABLED', name, `would disable the PPPoE uplink "${name}"`);
        else if (why.length > 0) push('UPLINK_INTERFACE_DISABLED', name, `would disable uplink interface "${name}" (${whyText})`);
      }

      // (v) the static address a default route's gateway is reached through.
      //     `renderUpdate` removes every cidr of `before.addresses` missing from
      //     `after.addresses` on `after.name`; the static default route then
      //     has no connected subnet for its gateway and the site is cut, while
      //     the interface, its lists and the route all survive untouched. A
      //     re-IP that keeps the gateway covered stays allowed.
      if (op.kind === 'update' && touches(op.fields, 'addresses')) {
        const cidrsOf = (r: NcmInterface | null): string[] =>
          (Array.isArray(r?.addresses) ? r.addresses : [])
            .map((a) => (a && typeof a.cidr === 'string' ? a.cidr : null))
            .filter((c): c is string => c !== null);
        const hadCidrs = [...new Set(recs.flatMap(cidrsOf))];
        const keptCidrs = cidrsOf(after);
        for (const gw of facts.defaultIpGateways) {
          const through = hadCidrs.filter((c) => cidrContains(c, gw.ip));
          if (through.length === 0 || keptCidrs.some((c) => cidrContains(c, gw.ip))) continue;
          push(
            'UPLINK_GATEWAY_ADDRESS_REMOVED',
            `${name}: ${gw.dst} via ${gw.ip}`,
            `would remove from "${name}" the static address ${through.join(', ')} through which default ` +
              `route ${gw.dst} reaches its gateway ${gw.ip}, leaving no address on "${name}" that covers it`,
          );
        }
      }
      return out;
    }

    case 'vlan': {
      // A VLAN under an FTTH PPPoE is an `interface` record too, but the `vlan`
      // record has its own delete (`/interface vlan remove`) — same uplink.
      const vlanNames = [...new Set(uniqueRecords<NcmVlan>(sides).map((r) => r.name).filter(nonEmpty))];
      const vlanRecs = uniqueRecords<NcmVlan>([
        fromBox,
        ...vlanNames.flatMap((n) => facts.vlansByName.get(n) ?? []),
        ...stateSides,
      ]);
      for (const rec of vlanRecs) {
        const name = typeof rec.name === 'string' ? rec.name : null;
        if (!name) continue;
        const why = facts.uplinkInterfaces.get(name)
          ?? (isPppoeUplinkName(name) ? ['named like a production PPPoE uplink'] : []);
        if (why.length === 0) continue;
        if (op.kind === 'delete') {
          push('UPLINK_INTERFACE_REMOVED', name, `would delete uplink VLAN "${name}" (${why.slice(0, 3).join(', ')})`);
        } else if (isDisabling(op, rec)) {
          push('UPLINK_INTERFACE_DISABLED', name, `would disable uplink VLAN "${name}" (${why.slice(0, 3).join(', ')})`);
        }
      }
      return out;
    }

    case 'route': {
      const rekey = op.kind === 'update' && touches(op.fields, 'gateway', 'dst', 'table', 'vrf');
      const routeIdent = uniqueRecords<NcmRoute>(sides).filter((r) => nonEmpty(r.dst));
      const routeRecs = uniqueRecords<NcmRoute>([
        fromBox,
        ...facts.routes.filter((b) => routeIdent.some((r) =>
          r.dst === b.dst && gatewayValue(r.gateway) === gatewayValue(b.gateway))),
        ...stateSides,
      ]);
      for (const rec of routeRecs) {
        if (!isDefaultDst(rec.dst) || rec.gateway === null || rec.gateway === undefined) continue;
        if (!(op.kind === 'delete' || isDisabling(op, rec) || rekey)) continue;
        const resolved = resolveGateway(facts.interfaces, rec.gateway).label;
        const verb = op.kind === 'delete' ? 'delete' : rekey ? 'move' : 'disable';
        push(
          'UPLINK_DEFAULT_ROUTE_REMOVED',
          `${rec.dst} via ${rec.gateway}`,
          `would ${verb} default route ${rec.dst} via ${resolved}` +
            // A toggle's `after` carries the TARGET flag, not a collected one.
            (rec.disabled && rec !== op.after ? ' (disabled at collection — a failover toggles that flag)' : ''),
        );
      }
      return out;
    }

    case 'dhcpClient': {
      const after = asRecord<NcmDhcpClient>(op.after);
      const clientIfaces = [...new Set(uniqueRecords<NcmDhcpClient>(sides).map((r) => r.interfaceName).filter(nonEmpty))];
      const clientRecs = uniqueRecords<NcmDhcpClient>([
        fromBox,
        ...clientIfaces.flatMap((n) => facts.dhcpClientsByInterface.get(n) ?? []),
        ...stateSides,
      ]);
      for (const rec of clientRecs) {
        const name = typeof rec.interfaceName === 'string' ? rec.interfaceName : null;
        if (!name) continue;
        const onUplink = facts.uplinkInterfaces.has(name) || isPppoeUplinkName(name);
        const installsDefault = rec.addDefaultRoute === true;
        if (!onUplink && !installsDefault) continue;
        const dropsDefault = op.kind === 'update' && installsDefault &&
          touches(op.fields, 'addDefaultRoute') && after?.addDefaultRoute !== true;
        const what = op.kind === 'delete' ? 'delete'
          : isDisabling(op, rec) ? 'disable'
            : dropsDefault ? 'stop the default route of'
              : null;
        if (!what) continue;
        push(
          'UPLINK_DHCP_CLIENT_REMOVED',
          `dhcp-client on ${name}`,
          `would ${what} the DHCP client on uplink "${name}"` +
            (installsDefault ? ' (it installs a default route)' : ''),
        );
      }
      return out;
    }

    default:
      return [];
  }
}

// ============================================================================
// Sentences
// ============================================================================

const ADVICE =
  'Production uplinks are never removed by a plan, whatever the template says: change the ' +
  'template or the site variables so the desired state keeps them, then recompile.';

/** The `reason` of a `blocked` op. Capped at `PlanOp.reason`'s 400. */
export function uplinkRefusalSentence(violations: readonly UplinkViolation[]): string {
  const clauses = [...new Set(violations.map((x) => `${x.message} [${x.code}]`))];
  const head = `REFUSED (uplink preservation) — this op ${clauses.join('; ')}. `;
  const text = head + ADVICE;
  return text.length <= 400 ? text : `${head.slice(0, 400 - 3)}...`;
}

// ============================================================================
// A whole plan — the queue's door and the job's guard step
// ============================================================================

export interface PlanUplinkCheck {
  /** One line per refused op, operator-facing. Empty = nothing refused. */
  refusals: string[];
  violations: UplinkViolation[];
  facts: UplinkFacts;
}

/**
 * Judge a plan as the QUEUE receives it.
 *
 * Two kinds of op are refused:
 *  - an executable op (`delete`/`disable`/`update`) that breaks a rule above —
 *    the plan did not come from the planner, or came from an older one;
 *  - a `blocked` op the planner already refused as `uplink_preserved` — so the
 *    queue names the uplink rather than the generic "plan contains a blocked
 *    op" the renderer would answer.
 *
 * `observed` may be null (no snapshot): the ops' own `before` records are then
 * the only evidence, and the PPPoE-name, WAN-list and default-route rules
 * still apply to them.
 */
export function checkPlanUplinks(observed: NcmDocument | null, ops: readonly unknown[]): PlanUplinkCheck {
  const facts = buildUplinkFacts(observed);
  const refusals: string[] = [];
  const violations: UplinkViolation[] = [];
  for (const raw of ops) {
    const op = asRecord<PlanOp>(raw);
    if (!op || typeof op.kind !== 'string' || typeof op.resource !== 'string') continue;
    if (op.kind === 'blocked') {
      if (op.blockedReason === UPLINK_BLOCK_REASON) {
        refusals.push(`op #${op.seq} (blocked ${op.resource} ${op.semKey}): ${op.reason}`);
      }
      continue;
    }
    const found = uplinkViolationsForOp(facts, {
      seq: op.seq,
      kind: op.kind,
      resource: op.resource,
      semKey: String(op.semKey ?? ''),
      before: op.before,
      after: op.after,
      fields: Array.isArray(op.fields) ? op.fields : [],
    });
    if (found.length === 0) continue;
    violations.push(...found);
    refusals.push(
      `op #${op.seq} (${op.kind} ${op.resource} ${op.semKey}): ` +
        found.map((x) => `${x.message} [${x.code}]`).join('; '),
    );
  }
  return { refusals, violations, facts };
}

/** The message of the queue's refusal. */
export function uplinkRefusalMessage(refusals: readonly string[]): string {
  return (
    `This plan would remove ${refusals.length === 1 ? 'a production uplink' : 'production uplinks'}, ` +
    'which is refused whatever the template says — no override lifts it. ' +
    `${refusals.join(' | ')}. ${ADVICE}`
  );
}
