import { networkInterfaces, type NetworkInterfaceInfo } from 'node:os';
import { macOffset, reachableAddress, type MndpCandidate, type MndpNeighbour } from './mndp';

/**
 * ObliWAN bench — this PC's bench LINKS (« prises »), and which one a box is on.
 *
 * ┌─ WHY LINKS, AND WHY THE SOURCE ADDRESS ──────────────────────────────────┐
 * │ Every factory MikroTik answers 192.168.88.1. Two of them on one network │
 * │ are one address with two owners: which one a connection reaches is up  │
 * │ to ARP. To prepare several at once, each sits on its OWN link — one     │
 * │ USB-Ethernet adapter per router, or one VLAN per switch port — and this │
 * │ PC holds its own FIXED address on each, all in 192.168.88.0/24 (.11,    │
 * │ .12, …). A slot IS such an interface; its label is the address's last   │
 * │ number (« Prise 11 »), which is what the technician writes on it.       │
 * │                                                                         │
 * │ Then the destination no longer says which box a connection reaches:     │
 * │ 192.168.88.1 is on every link. The SOURCE does. Windows applies the     │
 * │ strong host model (Microsoft documents it as the default of its TCP/IP  │
 * │ stack since Vista, IPv4 and IPv6): a connection bound to 192.168.88.12  │
 * │ leaves by the interface holding 192.168.88.12 and resolves 192.168.88.1 │
 * │ there — on that link, to that link's box. Unbound, Windows picks ONE    │
 * │ route for the whole subnet by its metric, and every dial reaches the    │
 * │ same box whichever link the technician meant. So every connection to a  │
 * │ box (API, SFTP, the MNDP probe) is bound to the address of the link     │
 * │ where MNDP heard that box (`planBoxRoute`), and the technician never    │
 * │ says which link: a box on « the wrong one » is simply found where it is.│
 * │ The MAC proof (routerosApply.ts) still decides what gets written: a     │
 * │ wrong link reaches a box that refuses the typed MAC.                    │
 * │ Not observed on the bench hardware: the model is Microsoft's documented │
 * │ behaviour, and benchSlots.verify.ts fakes a network that obeys it.      │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHAT IS REFUSED AS A SLOT ──────────────────────────────────────────────┐
 * │ - two interfaces holding the SAME address: neither can be told from the │
 * │   other by its address. It is also what two adapters left on DHCP get  │
 * │   from two factory boxes, whose default pools hand out the same lease. │
 * │ - an interface holding 192.168.88.1 itself (the routers' address), or   │
 * │   the subnet's network or broadcast address.                            │
 * │ Zero slots is a PC holding no address in 192.168.88.0/24 at all (a card │
 * │ left on DHCP, no router plugged in yet): the OS routes, one router at a │
 * │ time, as the bench always did. One slot — a fixed address, or the lease │
 * │ a factory box handed out — is the single-router path too, its           │
 * │ connections bound to that link.                                         │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ A LINK THAT GOES DOWN ──────────────────────────────────────────────────┐
 * │ `up` lists the interfaces the OS reports. On Windows, libuv (behind     │
 * │ os.networkInterfaces) is understood to leave out an adapter whose       │
 * │ operational status is not Up: a pulled cable, and also a box at the     │
 * │ other end that is off or rebooting. So a slot missing from `up` says    │
 * │ « the link is down », never « the box was unplugged » by itself: the    │
 * │ application only calls it unplugged when it happens during a write, or  │
 * │ lasts longer than a reboot would (gui.ts). Reasoned, not observed — on  │
 * │ this repo's machines or on the bench hardware. Should a down adapter    │
 * │ still be listed, a pulled cable is merely never SEEN: the operations    │
 * │ then end by their own deadlines and errors, as they did before.         │
 * │ The same holds BY CONSTRUCTION for a VLAN-per-port switch: the PC's     │
 * │ cable goes to the switch, not to the box, so the PC's interface stays   │
 * │ up whatever happens on the router's port, and only an adapter cabled    │
 * │ straight to the router can ever report its cable pulled. The MAC proof  │
 * │ before every write (and before the compile, gui.ts) still catches a box │
 * │ that is gone or swapped on such a link.                                 │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * No database, no vault, no logger: this runs inside the bench SEA binary.
 */

/** Where every factory box answers, and the network the PC's links sit in. */
export const BENCH_SUBNET = '192.168.88.0/24';
export const FACTORY_ADDRESS = '192.168.88.1';

export interface BenchSlot {
  /** Windows' name for the network card (« Ethernet 3 »): what the slot IS. */
  iface: string;
  /** This PC's address on it, inside 192.168.88.0/24. */
  address: string;
  netmask: string;
  /** What the technician reads and writes on the adapter: « Prise 11 ». */
  label: string;
}

export interface RefusedSlot {
  iface: string;
  address: string;
  /** French, for the « Préparer ce PC » screen: what is wrong and what to do. */
  reason: string;
}

export interface SlotReading {
  /** Usable links, by their address's last number. */
  slots: BenchSlot[];
  refused: RefusedSlot[];
  /** Every interface the OS lists with at least one address (link up). */
  up: string[];
}

function ipv4ToInt(a: string): number | null {
  const p = a.split('.');
  if (p.length !== 4 || p.some((x) => !/^\d{1,3}$/.test(x) || Number(x) > 255)) return null;
  return p.reduce((n, x) => n * 256 + Number(x), 0);
}

/** Is `ip` inside `cidr` (`10.101.2.0/24`)? */
export function ipv4InSubnet(ip: string, cidr: string | null): boolean {
  const m = /^(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})$/.exec(cidr ?? '');
  const a = ipv4ToInt(ip);
  const net = m ? ipv4ToInt(m[1]) : null;
  if (!m || a === null || net === null || Number(m[2]) > 32) return false;
  const size = 2 ** (32 - Number(m[2]));
  return Math.floor(a / size) === Math.floor(net / size);
}

const lastOctet = (ip: string): number => Number(ip.split('.')[3]);

/** « Prise 11 » for 192.168.88.11. */
export function slotLabel(address: string): string {
  return `Prise ${lastOctet(address)}`;
}

/** « Prise 11 (Ethernet 3) » — the label and the card's own name. */
export function describeSlot(slot: Pick<BenchSlot, 'label' | 'iface'>): string {
  return `${slot.label} (${slot.iface})`;
}

/**
 * This PC's bench links, from `os.networkInterfaces()` (or the map given).
 * Pure apart from that default: the harness passes its own map.
 */
export function readBenchSlots(ifaces: NodeJS.Dict<NetworkInterfaceInfo[]> = networkInterfaces()): SlotReading {
  const found: Array<{ iface: string; address: string; netmask: string }> = [];
  const up: string[] = [];
  for (const [iface, list] of Object.entries(ifaces)) {
    const external = (list ?? []).filter((a) => !a.internal);
    if (external.length) up.push(iface);
    // One address per interface: the lowest of the bench subnet, if any.
    const bench = external
      .filter((a) => String(a.family) === 'IPv4' && ipv4InSubnet(a.address, BENCH_SUBNET))
      .sort((x, y) => lastOctet(x.address) - lastOctet(y.address))[0];
    if (bench) found.push({ iface, address: bench.address, netmask: bench.netmask });
  }
  const slots: BenchSlot[] = [];
  const refused: RefusedSlot[] = [];
  for (const f of found) {
    const twins = found.filter((o) => o !== f && o.address === f.address);
    const n = lastOctet(f.address);
    if (twins.length) {
      refused.push({
        ...f,
        reason: `porte la même adresse ${f.address} que ${twins.map((t) => `« ${t.iface} »`).join(', ')} : ce poste ne peut pas savoir laquelle mène à quel routeur. Donnez à chaque carte sa propre adresse fixe (192.168.88.11, .12, .13…), sans DHCP.`,
      });
    } else if (f.address === FACTORY_ADDRESS) {
      refused.push({
        ...f,
        reason: `porte l'adresse des routeurs (${FACTORY_ADDRESS}) : aucun routeur ne pourrait répondre sur cette prise. Donnez-lui une autre adresse fixe (192.168.88.11, .12, .13…).`,
      });
    } else if (n === 0 || n === 255) {
      refused.push({ ...f, reason: `porte une adresse inutilisable (${f.address}). Donnez-lui une adresse fixe entre 192.168.88.11 et 192.168.88.250.` });
    } else {
      slots.push({ ...f, label: slotLabel(f.address) });
    }
  }
  slots.sort((a, b) => lastOctet(a.address) - lastOctet(b.address));
  return { slots, refused, up };
}

/**
 * Are two announcements from ONE box? Every announcement of a box carries the
 * same software ID (MNDP TLV 11, the RouterOS licence's ID, one per device —
 * what Winbox's neighbour list shows; taken from the protocol references in
 * mndp.ts, not from a capture of the bench hardware). When both carry one,
 * it decides: two boxes of one carton have neighbouring MACs, and only their
 * software IDs tell them apart. When either lacks one, the MACs decide: one
 * box announces from each of its interfaces, with MACs from one block
 * (`macOffset`'s window) — which ALSO merges two boxes of one carton, the
 * blind spot of that fallback (the MAC proof still refuses the wrong box).
 */
export function sameAnnouncer(a: MndpNeighbour, b: MndpNeighbour): boolean {
  if (a.softwareId && b.softwareId) return a.softwareId === b.softwareId;
  return macOffset(a.mac, b.mac) !== null || macOffset(b.mac, a.mac) !== null;
}

/** How many DIFFERENT boxes MNDP heard announcing `address` (`sameAnnouncer`). */
export function boxesAnnouncing(neighbours: MndpNeighbour[], address: string): number {
  const groups: MndpNeighbour[] = [];
  for (const n of neighbours) {
    if (reachableAddress(n) !== address) continue;
    if (groups.some((g) => sameAnnouncer(n, g))) continue;
    groups.push(n);
  }
  return groups.length;
}

/** One connection the search may open, in order. */
export interface DialAttempt {
  host: string;
  /** The source address (the link); null: the OS routes (no slot). */
  localAddress: string | null;
  via: 'mndp' | 'address';
  slot: BenchSlot | null;
}

export type RouteRefusal = 'NOT_ISOLATED' | 'TWO_BOXES' | 'SLOT_HELD' | 'NO_FREE_SLOT';

export type BoxRoute =
  | { ok: true; attempts: DialAttempt[]; heardOn: BenchSlot | null }
  | { ok: false; code: RouteRefusal; message: string };

export interface BoxRouteInput {
  /** The bench address typed under « Options avancées » (192.168.88.1). */
  fallbackHost: string;
  slots: BenchSlot[];
  /** MNDP candidates for the typed MAC, closest first (`discoverCandidates`). */
  candidates: MndpCandidate[];
  /** Everything MNDP heard. */
  neighbours: MndpNeighbour[];
  /** Which OTHER card holds that link (its name for the message), or null.
   *  With no slots, `null` stands for « this PC ». */
  heldBy: (slot: BenchSlot | null) => string | null;
  /** Is this MAC one of ANOTHER card's box's own interfaces? Such a
   *  candidate is that card's router, never the typed one: on a bench of one
   *  batch it falls inside the typed MAC's window. Absent: none is. */
  foreign?: (mac: string) => boolean;
}

/**
 * Where to dial for the typed MAC — and from which link. Pure: the address
 * selection the harness pins (`benchSlots.verify.ts`).
 *
 * - Candidates that are another card's router (`foreign`) are dropped first:
 *   the typed box, silent, must not be routed — or refused — by its batch
 *   neighbour's announcement.
 * - No slot: as the bench always did — the address MNDP heard, then the
 *   bench address, the OS choosing the route; one router at a time.
 * - The box heard on a link: that link's address is the SOURCE of every
 *   attempt (see the header); refused when the same announcement is heard on
 *   two links (they are one network: NOT_ISOLATED), when MNDP heard two
 *   boxes announcing the bench address on that link (TWO_BOXES, as far as
 *   `sameAnnouncer` can tell them apart), or when another card holds it.
 * - Not heard (MNDP silent or unavailable): the bench address on every link
 *   no other card holds, one after the other; the MAC proof tells the boxes
 *   apart, and nothing is written by a search.
 */
export function planBoxRoute(input: BoxRouteInput): BoxRoute {
  const { slots, neighbours } = input;
  const candidates = input.foreign ? input.candidates.filter((c) => !input.foreign!(c.mac)) : input.candidates;
  const fallback = input.fallbackHost;
  if (slots.length === 0) {
    // Two factory boxes both answer the factory address, and which one a
    // dial reaches is up to ARP: the MAC proof would refuse the wrong one,
    // it cannot pick the right one. Stop before dialling either.
    if (boxesAnnouncing(neighbours, fallback) >= 2) {
      return {
        ok: false,
        code: 'TWO_BOXES',
        message: `Plusieurs routeurs répondent à l'adresse ${fallback} sur ce poste. Rien n'a été modifié. Débranchez tous les routeurs sauf celui à préparer, puis relancez la recherche.`,
      };
    }
    const holder = input.heldBy(null);
    if (holder) {
      return {
        ok: false,
        code: 'SLOT_HELD',
        message: `Un autre routeur est déjà en préparation sur ce poste (${holder}). Ce poste n'a pas de prise d'établi à adresse fixe : un seul routeur à la fois. Attendez qu'il soit prêt et débranché, ou équipez ce poste pour plusieurs routeurs (bouton « Préparer ce PC »), puis relancez la recherche.`,
      };
    }
    const heard = candidates[0] ? reachableAddress(candidates[0]) : null;
    const attempts: DialAttempt[] = [];
    if (heard) attempts.push({ host: heard, localAddress: null, via: 'mndp', slot: null });
    if (fallback !== heard) attempts.push({ host: fallback, localAddress: null, via: 'address', slot: null });
    return { ok: true, attempts, heardOn: null };
  }

  const slotOf = (address: string | null | undefined): BenchSlot | null =>
    (address ? slots.find((s) => s.address === address) : undefined) ?? null;
  const located = candidates.filter((c) => slotOf(c.localAddress) !== null);
  // The SAME announcement (one MAC, one interface of one box) heard on two
  // links: those links are one network. Two DIFFERENT MACs of the typed
  // window on two links are two boxes of one batch, each on its own link.
  for (const c of located) {
    const twin = located.find((o) => o.mac === c.mac && o.localAddress !== c.localAddress);
    if (twin) {
      const a = slotOf(c.localAddress)!;
      const b = slotOf(twin.localAddress)!;
      return {
        ok: false,
        code: 'NOT_ISOLATED',
        message: `La ${a.label} et la ${b.label} de ce poste sont reliées au même réseau : le routeur ${c.mac} s'annonce sur les deux. Rien n'a été modifié. Chaque routeur doit avoir sa propre prise — un adaptateur USB-Ethernet par routeur, ou un VLAN par port du switch (voir « Préparer ce PC ») — : corrigez le câblage, puis relancez la recherche.`,
      };
    }
  }

  const onLink = (s: BenchSlot) => neighbours.filter((n) => n.localAddress === s.address);
  const best = located[0];
  if (best) {
    const slot = slotOf(best.localAddress)!;
    if (boxesAnnouncing(onLink(slot), fallback) >= 2) {
      return {
        ok: false,
        code: 'TWO_BOXES',
        message: `Plusieurs routeurs répondent à l'adresse ${fallback} sur la ${slot.label} de ce poste. Rien n'a été modifié. Laissez un seul routeur sur cette prise — un routeur par prise —, puis relancez la recherche.`,
      };
    }
    const holder = input.heldBy(slot);
    if (holder) {
      return {
        ok: false,
        code: 'SLOT_HELD',
        message: `Ce routeur est branché sur la ${slot.label}, qui est déjà attribuée à ${holder}. Rien n'a été modifié. Un seul routeur par prise : si le routeur de ${holder} n'est plus branché, fermez ${holder} avec son bouton « Fermer cette carte » ; sinon branchez celui-ci sur une prise libre. Puis relancez la recherche.`,
      };
    }
    const heard = reachableAddress(best);
    const attempts: DialAttempt[] = [];
    if (heard) attempts.push({ host: heard, localAddress: slot.address, via: 'mndp', slot });
    if (fallback !== heard) attempts.push({ host: fallback, localAddress: slot.address, via: 'address', slot });
    return { ok: true, attempts, heardOn: slot };
  }

  // Not heard on any link. A candidate heard WITHOUT a link (a discovery that
  // cannot say where) still gives the address to dial.
  const unlinked = candidates.find((c) => !c.localAddress);
  const host = (unlinked && reachableAddress(unlinked)) || fallback;
  const free = slots.filter((s) => input.heldBy(s) === null);
  if (free.length === 0) {
    return {
      ok: false,
      code: 'NO_FREE_SLOT',
      message: `Toutes les prises de l'établi sont occupées par des routeurs en cours (${slots.map((s) => s.label).join(', ')}). Rien n'a été modifié. Attendez qu'une préparation se termine et débranchez ce routeur-là, puis branchez celui-ci à sa place et relancez la recherche.`,
    };
  }
  const usable = free.filter((s) => boxesAnnouncing(onLink(s), host) < 2);
  if (usable.length === 0) {
    return {
      ok: false,
      code: 'TWO_BOXES',
      message: `Plusieurs routeurs répondent à l'adresse ${host} sur ${free.length > 1 ? 'chaque prise libre' : `la ${free[0].label}`} de ce poste. Rien n'a été modifié. Laissez un seul routeur par prise, puis relancez la recherche.`,
    };
  }
  return {
    ok: true,
    attempts: usable.map((s) => ({ host, localAddress: s.address, via: 'address' as const, slot: s })),
    heardOn: null,
  };
}
