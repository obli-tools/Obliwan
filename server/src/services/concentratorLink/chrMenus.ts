/**
 * ObliWAN — the CHR half of the WireGuard link, as PURE functions.
 *
 * No socket, no database, no vault: the job (link.service.ts) reads six
 * RouterOS menus, hands them to `decideLinkActions`, sends the `/add`s it gets
 * back one at a time, and after each add re-reads that menu and asks
 * `locateItem` whether the item is now there. `verifyLinkSnapshot` is the
 * read-back of the whole set. Everything here is therefore testable against
 * plain rows, and the harness does.
 *
 * ┌─ ADDITIVE ONLY ─────────────────────────────────────────────────────────┐
 * │ The only verb this module ever builds is `add`. An item ObliWAN would    │
 * │ add that already exists DIFFERENTLY (another listen port, a disabled     │
 * │ copy, a peer under ObliWAN's comment with another key, a rule behind a   │
 * │ drop) is a CONFLICT: the job refuses and touches nothing — never `set`,  │
 * │ never `move`, never `remove`, never `enable`. Every other interface,      │
 * │ address, peer and rule on the CHR is read, judged, and left alone.       │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHERE A FIREWALL RULE GOES ────────────────────────────────────────────┐
 * │ An accept is useless behind a drop. The input (and, when needed,        │
 * │ forward) accepts are added with `place-before=<id>` of the FIRST static  │
 * │ rule of their chain whose action is drop, reject, tarpit or JUMP — a      │
 * │ jump is counted because the chain it jumps to may drop, and placing an   │
 * │ accept this narrow before a jump cannot open anything else. No such rule │
 * │ -> appended. DYNAMIC rules (hotspot, for instance) always sit above the   │
 * │ static ones and cannot be placed before; one that drops is reported in   │
 * │ the notes, not worked around. The srcnat rule goes before the first     │
 * │ static srcnat rule: it matches only the ObliWAN transit address, so      │
 * │ first is the one place it cannot change anybody else's traffic.         │
 * │ Rules are found again by EXACT comment equality.                         │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ A RESIDUAL, STATED: AN UNROUTED 100.64.0.0/10 DESTINATION ─────────────┐
 * │ `forward_in` and `srcnat` name no out-interface. A packet from the host  │
 * │ to a tunnel address with NO live PPP session (so no /32 route on the CHR)│
 * │ follows the CHR's default route: accepted, masqueraded to the CHR's      │
 * │ PUBLIC address, and sent upstream, where RFC 6598 space may be routed    │
 * │ inside a provider's network. ObliWAN dials only devices whose session is │
 * │ up, so this takes a stale session row or a dial racing a tunnel         │
 * │ drop. Not closed here, deliberately, because each closure costs more:    │
 * │  - a blackhole 100.64.0.0/10 on the CHR changes the path of EVERYBODY's │
 * │    traffic to that space on a shared box, and some clouds host DNS or   │
 * │    metadata services there;                                              │
 * │  - `out-interface-list=dynamic` would silently exclude every site on a  │
 * │    static /interface/l2tp-server binding (a static interface), and is   │
 * │    a RouterOS construct no lab has checked for this purpose;             │
 * │  - naming the WAN interface means guessing it from the default route.   │
 * │ What leaves is a connection attempt (a management port: API, SSH, SNMP) │
 * │ from the CHR's public address to a host that is not the site ObliWAN    │
 * │ meant, and conntrack carries any answer back to ObliWAN like any other.  │
 * │ If such a host answered on 8728, the cleartext RouterOS API login would │
 * │ send it the site's credentials BEFORE the identity check could refuse   │
 * │ it — the same exposure a plain static route through the CHR has. A lab  │
 * │ that confirms `out-interface-list=dynamic` on RouterOS 7, on a CHR with │
 * │ no static l2tp-server binding, is what would justify closing it here.  │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * No `.proplist` below names a private key or a preshared key. The CHR's
 * interface `private-key` (and the `private-key` that recent RouterOS 7
 * releases also print on a peer) never crosses the wire.
 */

import {
  CHR_WG_INTERFACE,
  LINK_ITEMS,
  LINK_SUPERNET,
  ipv4CidrContains,
  isWireGuardKey,
  linkComment,
  parseIpv4Cidr,
  type Ipv4Cidr,
  type LinkItem,
} from '@obliwan/shared';

export interface LinkSpec {
  /** `100.127.255.252/30` */
  transit: string;
  /** `100.127.255.253` */
  chrAddress: string;
  /** `100.127.255.254` */
  hostAddress: string;
  listenPort: number;
  /** ObliWAN's WireGuard PUBLIC key. */
  hostPublicKey: string;
}

export type Row = Record<string, string>;

export const MENUS = {
  interfaces: {
    path: '/interface/wireguard',
    proplist: '.id,name,listen-port,public-key,disabled,running,comment',
  },
  peers: {
    path: '/interface/wireguard/peers',
    proplist: '.id,interface,public-key,allowed-address,comment,disabled',
  },
  addresses: {
    path: '/ip/address',
    proplist: '.id,address,network,interface,disabled,dynamic,comment',
  },
  routes: {
    path: '/ip/route',
    proplist: '.id,dst-address,gateway,disabled,dynamic',
  },
  filter: {
    path: '/ip/firewall/filter',
    proplist:
      '.id,chain,action,protocol,dst-port,in-interface,out-interface,src-address,dst-address,' +
      'connection-state,jump-target,comment,disabled,dynamic',
  },
  nat: {
    path: '/ip/firewall/nat',
    proplist: '.id,chain,action,src-address,dst-address,comment,disabled,dynamic',
  },
} as const;
export type MenuName = keyof typeof MENUS;
export const MENU_NAMES = Object.keys(MENUS) as MenuName[];

export type ChrLinkSnapshot = Record<MenuName, Row[]>;

export function printWords(menu: MenuName): string[] {
  return [`${MENUS[menu].path}/print`, `=.proplist=${MENUS[menu].proplist}`];
}

// ============================================================================
// What each item is
// ============================================================================

interface ItemSpec {
  item: LinkItem;
  menu: MenuName;
  attrs: Record<string, string>;
  /** The chain an ordered rule must sit in, ahead of its first terminal rule. */
  orderedIn: 'input' | 'forward' | 'srcnat' | null;
}

export function itemSpecs(spec: LinkSpec): ItemSpec[] {
  const port = String(spec.listenPort);
  const out: Record<LinkItem, ItemSpec> = {
    wg_interface: {
      item: 'wg_interface',
      menu: 'interfaces',
      attrs: { name: CHR_WG_INTERFACE, 'listen-port': port, comment: linkComment('wg_interface') },
      orderedIn: null,
    },
    wg_address: {
      item: 'wg_address',
      menu: 'addresses',
      attrs: { address: `${spec.chrAddress}/30`, interface: CHR_WG_INTERFACE, comment: linkComment('wg_address') },
      orderedIn: null,
    },
    wg_peer: {
      item: 'wg_peer',
      menu: 'peers',
      attrs: {
        interface: CHR_WG_INTERFACE,
        'public-key': spec.hostPublicKey,
        'allowed-address': `${spec.hostAddress}/32`,
        comment: linkComment('wg_peer'),
      },
      orderedIn: null,
    },
    input_wg: {
      item: 'input_wg',
      menu: 'filter',
      attrs: { chain: 'input', action: 'accept', protocol: 'udp', 'dst-port': port, comment: linkComment('input_wg') },
      orderedIn: 'input',
    },
    input_mgmt: {
      item: 'input_mgmt',
      menu: 'filter',
      attrs: {
        chain: 'input',
        action: 'accept',
        'in-interface': CHR_WG_INTERFACE,
        'src-address': spec.hostAddress,
        comment: linkComment('input_mgmt'),
      },
      orderedIn: 'input',
    },
    forward_in: {
      item: 'forward_in',
      menu: 'filter',
      attrs: {
        chain: 'forward',
        action: 'accept',
        'in-interface': CHR_WG_INTERFACE,
        'src-address': spec.hostAddress,
        'dst-address': LINK_SUPERNET,
        comment: linkComment('forward_in'),
      },
      orderedIn: 'forward',
    },
    forward_reply: {
      item: 'forward_reply',
      menu: 'filter',
      attrs: {
        chain: 'forward',
        action: 'accept',
        'out-interface': CHR_WG_INTERFACE,
        'dst-address': spec.hostAddress,
        'connection-state': 'established,related',
        comment: linkComment('forward_reply'),
      },
      orderedIn: 'forward',
    },
    srcnat: {
      item: 'srcnat',
      menu: 'nat',
      attrs: {
        chain: 'srcnat',
        action: 'masquerade',
        'src-address': spec.hostAddress,
        'dst-address': LINK_SUPERNET,
        comment: linkComment('srcnat'),
      },
      orderedIn: 'srcnat',
    },
  };
  return LINK_ITEMS.map((i) => out[i]);
}

// ============================================================================
// Reading rows
// ============================================================================

const yes = (v: string | undefined): boolean => v === 'true' || v === 'yes';
const ADDRESS_KEYS = new Set(['address', 'src-address', 'dst-address', 'allowed-address']);
const SET_KEYS = new Set(['connection-state']);

function cidrOf(text: string | undefined): Ipv4Cidr | null {
  return text ? parseIpv4Cidr(text) : null;
}

/** RouterOS prints `src-address=1.2.3.4` back without `/32`, a set in its own
 *  order: compare meaning, not spelling. */
export function sameValue(key: string, want: string, got: string | undefined): boolean {
  if (got === undefined) return false;
  if (ADDRESS_KEYS.has(key)) {
    const a = cidrOf(want);
    const b = cidrOf(got);
    if (!a || !b) return want === got;
    return a.address === b.address && a.prefix === b.prefix;
  }
  if (SET_KEYS.has(key)) {
    const norm = (s: string) => s.split(',').map((x) => x.trim()).filter(Boolean).sort().join(',');
    return norm(want) === norm(got);
  }
  return want === got;
}

function mismatches(spec: ItemSpec, row: Row): string[] {
  const out: string[] = [];
  for (const [k, v] of Object.entries(spec.attrs)) {
    if (!sameValue(k, v, row[k])) out.push(`${k}=${row[k] ?? '(unset)'} (expected ${v})`);
  }
  if (yes(row.disabled)) out.push('disabled=yes');
  return out;
}

const TERMINAL_ACTIONS = new Set(['drop', 'reject', 'tarpit', 'jump']);

/** Index (in the full listing) of the first STATIC rule of `chain` that drops
 *  or may drop, or -1. */
export function firstStaticTerminal(rows: Row[], chain: string): number {
  return rows.findIndex((r) => r.chain === chain && TERMINAL_ACTIONS.has(r.action ?? '') && !yes(r.dynamic));
}

function firstStatic(rows: Row[], chain: string): number {
  return rows.findIndex((r) => r.chain === chain && !yes(r.dynamic));
}

function describeRule(r: Row): string {
  const parts = [`${r['.id'] ?? '?'}`, `chain=${r.chain}`, `action=${r.action}`];
  if (r['jump-target']) parts.push(`jump-target=${r['jump-target']}`);
  if (r.comment) parts.push(`comment="${r.comment}"`);
  return parts.join(' ');
}

export interface Located {
  /** Index in the menu listing, or -1. */
  index: number;
  row: Row | null;
  /** More than one candidate: never guess which one is ours. */
  duplicates: number;
}

/**
 * Find an item on the CHR. The interface by NAME; the address by comment or
 * by the exact (address, interface) pair (RouterOS refuses a second identical
 * address, so one made by hand IS the item); the peer by (interface, public
 * key) — RouterOS refuses a duplicate key on one interface; a rule by EXACT
 * comment.
 */
export function locateItem(spec: ItemSpec, rows: Row[]): Located {
  let hits: number[];
  switch (spec.item) {
    case 'wg_interface':
      hits = rows.flatMap((r, i) => (r.name === CHR_WG_INTERFACE ? [i] : []));
      break;
    case 'wg_address':
      hits = rows.flatMap((r, i) =>
        r.comment === spec.attrs.comment ||
        (r.interface === CHR_WG_INTERFACE && sameValue('address', spec.attrs.address, r.address))
          ? [i]
          : [],
      );
      break;
    case 'wg_peer':
      hits = rows.flatMap((r, i) =>
        r.interface === CHR_WG_INTERFACE && r['public-key'] === spec.attrs['public-key'] ? [i] : [],
      );
      break;
    default:
      hits = rows.flatMap((r, i) => (r.comment === spec.attrs.comment ? [i] : []));
  }
  return { index: hits[0] ?? -1, row: hits.length > 0 ? rows[hits[0]] : null, duplicates: hits.length };
}

// ============================================================================
// The decision
// ============================================================================

export interface PlannedAdd {
  item: LinkItem;
  menu: MenuName;
  words: string[];
  /** The rule this one is placed before, for the audit trail and the step. */
  placeBefore: string | null;
}

export interface LinkDecision {
  conflicts: string[];
  present: LinkItem[];
  adds: PlannedAdd[];
  /** Items not needed on this CHR, and why. */
  skipped: Array<{ item: LinkItem; why: string }>;
  notes: string[];
  /** The CHR's WireGuard public key, when the interface already exists. */
  chrPublicKey: string | null;
}

export function addWords(menu: MenuName, attrs: Record<string, string>, placeBeforeId: string | null): string[] {
  return [
    `${MENUS[menu].path}/add`,
    ...Object.entries(attrs).map(([k, v]) => `=${k}=${v}`),
    ...(placeBeforeId ? [`=place-before=${placeBeforeId}`] : []),
  ];
}

/** Does chain `forward` drop anything? If not, no forward accept is needed. */
export function forwardNeedsAccept(filter: Row[]): boolean {
  return firstStaticTerminal(filter, 'forward') !== -1;
}

function overlapConflicts(snapshot: ChrLinkSnapshot, spec: LinkSpec): string[] {
  const transit = parseIpv4Cidr(spec.transit) as Ipv4Cidr;
  const out: string[] = [];
  const ourAddress = itemSpecs(spec)[1];
  for (const r of snapshot.addresses) {
    const ours = r.interface === CHR_WG_INTERFACE && sameValue('address', ourAddress.attrs.address, r.address);
    if (ours) continue;
    const a = cidrOf(r.address);
    const n = cidrOf(r.network);
    const ipInside = a !== null && ipv4CidrContains(transit, { address: a.address, prefix: 32, network: a.address });
    const netInside = n !== null && n.prefix === 32 && ipv4CidrContains(transit, n);
    if (ipInside || netInside) {
      out.push(
        `the CHR already has address ${r.address}${r.network ? ` (network ${r.network})` : ''} on ` +
          `${r.interface ?? '?'}, inside the transit ${spec.transit}`,
      );
    }
  }
  for (const r of snapshot.routes) {
    const d = cidrOf(r['dst-address']);
    if (!d || r.gateway === CHR_WG_INTERFACE) continue;
    if (ipv4CidrContains(transit, d)) {
      out.push(`the CHR already routes ${r['dst-address']} via ${r.gateway ?? '?'}, inside the transit ${spec.transit}`);
    }
  }
  return out;
}

/**
 * Decide, from a snapshot of the six menus, what the job adds. Pure. A
 * non-empty `conflicts` means: add NOTHING.
 */
export function decideLinkActions(snapshot: ChrLinkSnapshot, spec: LinkSpec): LinkDecision {
  const d: LinkDecision = { conflicts: [], present: [], adds: [], skipped: [], notes: [], chrPublicKey: null };
  if (!isWireGuardKey(spec.hostPublicKey)) {
    d.conflicts.push('ObliWAN\'s public key is not a WireGuard key');
    return d;
  }
  d.conflicts.push(...overlapConflicts(snapshot, spec));

  // A port another WireGuard interface already listens on.
  for (const r of snapshot.interfaces) {
    if (r.name !== CHR_WG_INTERFACE && r['listen-port'] === String(spec.listenPort)) {
      d.conflicts.push(
        `WireGuard interface "${r.name}" already listens on UDP ${spec.listenPort}; choose another port ` +
          '(ObliWAN never modifies an interface it did not create)',
      );
    }
  }

  const forwardNeeded = forwardNeedsAccept(snapshot.filter);
  for (const r of snapshot.filter) {
    if (yes(r.dynamic) && TERMINAL_ACTIONS.has(r.action ?? '') && (r.chain === 'input' || r.chain === 'forward')) {
      d.notes.push(
        `dynamic rule ${describeRule(r)} sits above every static rule and cannot be placed before; ` +
          'if it drops the WireGuard traffic, the link will not come up',
      );
    }
  }

  for (const s of itemSpecs(spec)) {
    if ((s.item === 'forward_in' || s.item === 'forward_reply') && !forwardNeeded) {
      const loc = locateItem(s, snapshot.filter);
      if (loc.row) {
        d.present.push(s.item);
      } else {
        d.skipped.push({ item: s.item, why: 'chain forward drops nothing, so nothing needs opening' });
      }
      continue;
    }
    const rows = snapshot[s.menu];
    const loc = locateItem(s, rows);
    if (loc.duplicates > 1) {
      d.conflicts.push(`${s.item}: ${loc.duplicates} candidates found on the CHR; ObliWAN does not guess which is its own`);
      continue;
    }
    if (loc.row) {
      const diff = mismatches(s, loc.row);
      // A matching address made by hand carries no comment: that is not a
      // difference worth refusing over (the comment is how WE find it).
      const material = diff.filter((m) => !m.startsWith('comment='));
      if (s.item === 'wg_interface' || s.item === 'wg_peer' || s.item === 'wg_address') {
        if (material.length > 0) {
          d.conflicts.push(
            `${s.item} exists on the CHR differently (${material.join(', ')}); ObliWAN never modifies it`,
          );
          continue;
        }
      } else if (diff.length > 0) {
        d.conflicts.push(
          `${s.item}: the rule commented "${s.attrs.comment}" exists differently (${diff.join(', ')}); ` +
            'ObliWAN never modifies it',
        );
        continue;
      }
      if (s.orderedIn === 'input' || s.orderedIn === 'forward') {
        const term = firstStaticTerminal(rows, s.orderedIn);
        if (term !== -1 && term < loc.index) {
          d.conflicts.push(
            `${s.item} is present but BEHIND ${describeRule(rows[term])}, so it never matches; ` +
              'ObliWAN never reorders rules — move it above that rule by hand',
          );
          continue;
        }
      }
      if (s.item === 'wg_interface') {
        const key = loc.row['public-key'];
        d.chrPublicKey = isWireGuardKey(key) ? key : null;
      }
      d.present.push(s.item);
      continue;
    }

    // Absent. A peer under ObliWAN's comment with ANOTHER key is a stale
    // ObliWAN peer: refused, never replaced.
    if (s.item === 'wg_peer') {
      const stale = snapshot.peers.find((r) => r.comment === s.attrs.comment);
      if (stale) {
        d.conflicts.push(
          `a peer commented "${s.attrs.comment}" holds another public key (${stale['public-key'] ?? '?'}); ` +
            'ObliWAN never replaces a peer — remove it by hand if it is no longer used',
        );
        continue;
      }
    }
    let placeBefore: Row | null = null;
    if (s.orderedIn === 'input' || s.orderedIn === 'forward') {
      const term = firstStaticTerminal(rows, s.orderedIn);
      placeBefore = term === -1 ? null : rows[term];
    } else if (s.orderedIn === 'srcnat') {
      const first = firstStatic(rows, 'srcnat');
      placeBefore = first === -1 ? null : rows[first];
    }
    d.adds.push({
      item: s.item,
      menu: s.menu,
      words: addWords(s.menu, s.attrs, placeBefore?.['.id'] ?? null),
      placeBefore: placeBefore ? describeRule(placeBefore) : null,
    });
  }
  if (d.conflicts.length > 0) d.adds = [];
  return d;
}

/** The audit text of an add: the words themselves (nothing in them is secret
 *  — a WireGuard PUBLIC key is public by definition). */
export function auditText(words: string[]): string {
  return words.join(' ');
}

// ============================================================================
// The read-back of the whole set
// ============================================================================

export interface LinkVerification {
  problems: string[];
  chrPublicKey: string | null;
  forwardNeeded: boolean;
}

export function verifyLinkSnapshot(snapshot: ChrLinkSnapshot, spec: LinkSpec): LinkVerification {
  const problems: string[] = [];
  const forwardNeeded = forwardNeedsAccept(snapshot.filter);
  let chrPublicKey: string | null = null;
  for (const s of itemSpecs(spec)) {
    const rows = snapshot[s.menu];
    const loc = locateItem(s, rows);
    const required = !(s.item === 'forward_in' || s.item === 'forward_reply') || forwardNeeded;
    if (!loc.row) {
      if (required) problems.push(`${s.item} is not on the CHR`);
      continue;
    }
    if (loc.duplicates > 1) problems.push(`${s.item}: ${loc.duplicates} candidates`);
    const diff = mismatches(s, loc.row).filter((m) => !m.startsWith('comment=') || s.orderedIn !== null);
    if (diff.length > 0) problems.push(`${s.item}: ${diff.join(', ')}`);
    if (s.orderedIn === 'input' || s.orderedIn === 'forward') {
      const term = firstStaticTerminal(rows, s.orderedIn);
      if (term !== -1 && term < loc.index) problems.push(`${s.item} sits behind ${describeRule(rows[term])}`);
    }
    if (s.item === 'wg_interface') {
      const key = loc.row['public-key'];
      if (isWireGuardKey(key)) chrPublicKey = key;
      else problems.push('the CHR\'s obliwan-wg reports no usable public key');
    }
  }
  return { problems, chrPublicKey, forwardNeeded };
}
