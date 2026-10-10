// ============================================================================
// @obliwan/shared — the LTE APN of ONE router, chosen in its settings and
// applied by a change job (kind `lte_apn`, migration 065)
// ============================================================================
//
// WHY A JOB OF ITS OWN. The NCM does not model `/interface lte` or
// `/interface lte apn` (normalize.service.ts, mikrotik/quirks.ts), so a plan,
// a push or a drift report cannot carry an APN change. The customer templates
// render the whole catalogue (`/interface lte apn add apn=<apn> name=<name>`
// per `lte_apn_catalogue` entry) and point lte1 at one profile
// (`apn-profiles=`); this job brings ONE router in service to the profile an
// operator picked from that same catalogue, and nothing else.
//
// THIS FILE IS THE ONE SOURCE of the lines the job sends and of the
// allow-list that judges them, so the two cannot drift apart. Pure: no
// socket, no database.
//
// WHAT THE LINES DO, in order:
//   1. the profile: `/interface lte apn add name="<n>" apn="<a>"` when the
//      router has no profile of that name, `/interface lte apn set [find
//      where name="<n>"] apn="<a>"` when it has one with another APN, nothing
//      when it already holds that APN;
//   2. `/interface lte set [find default-name=lte1] apn-profiles="<n>"` —
//      by `default-name`, as the templates address it, so a renamed lte1 is
//      still the modem the templates configure.
// Both values are `[A-Za-z0-9._-]{1,63}` — the catalogue's own JSON-schema
// pattern — so they sit between double quotes with nothing to escape.
//
// ┌─ ROUTEROS BEHAVIOUR RELIED ON ────────────────────────────────────────────┐
// │ [docs] `/interface lte apn` holds named profiles (`name`, `apn`), and     │
// │ `/interface lte set … apn-profiles=` names the profile(s) the modem uses. │
// │ REASONED, not observed on a box: that changing `apn-profiles` makes the   │
// │ modem re-attach (the LTE link drops for a few seconds) — which is why     │
// │ the job refuses whenever ObliWAN's management path rides the modem, or    │
// │ would once it has attached; that a profile created by `add name= apn=`    │
// │ adds a default route at distance 2 (`LTE_APN_ADD_DEFAULTS`); that         │
// │ `:tostr` joins an array with `;`. No line of this file has run on a       │
// │ router.                                                                   │
// └───────────────────────────────────────────────────────────────────────────┘

/** The `change_jobs.kind` of the job. */
export const LTE_APN_KIND = 'lte_apn' as const;

/** The interface the templates configure, by its `default-name`. */
export const LTE_DEFAULT_NAME = 'lte1';

/** A profile name or an APN: the catalogue's JSON-schema pattern. */
export const LTE_APN_TOKEN_RE = /^[A-Za-z0-9._-]{1,63}$/;

/** The template variables the job reads (the converted customer templates). */
export const LTE_APN_CATALOGUE_KEY = 'lte_apn_catalogue';
/** The tenant/group default profile name. Older conversions call it `lte_apn`. */
export const LTE_DEFAULT_APN_PROFILE_KEYS = ['lte_default_apn_profile', 'lte_apn'] as const;
/** The bench-level per-box profile a revision may declare: what the device's
 *  choice (`devices.lte_apn_profile`) is supplied as at render time. */
export const LTE_SIM_APN_PROFILE_KEY = 'sim_apn_profile';

export interface LteApnEntry {
  name: string;
  apn: string;
}

/** An entry the lines could not carry unescaped. Names the field, never the value. */
export class LteApnInputError extends Error {
  readonly field: 'name' | 'apn';
  constructor(field: 'name' | 'apn', message: string) {
    super(message);
    this.name = 'LteApnInputError';
    this.field = field;
  }
}

export function assertLteApnEntry(entry: LteApnEntry): void {
  if (typeof entry?.name !== 'string' || !LTE_APN_TOKEN_RE.test(entry.name)) {
    throw new LteApnInputError('name', 'The APN profile name holds characters outside [A-Za-z0-9._-] or is longer than 63.');
  }
  if (typeof entry?.apn !== 'string' || !LTE_APN_TOKEN_RE.test(entry.apn)) {
    throw new LteApnInputError('apn', 'The APN holds characters outside [A-Za-z0-9._-] or is longer than 63.');
  }
}

/** A catalogue as a template variable holds it, reduced to the well-formed
 *  entries (first occurrence of a name wins, like RouterOS refusing a second
 *  `add` of the same name). Anything else is dropped, never repaired. */
export function parseLteApnCatalogue(value: unknown): LteApnEntry[] {
  if (!Array.isArray(value)) return [];
  const out: LteApnEntry[] = [];
  const seen = new Set<string>();
  for (const v of value) {
    if (!v || typeof v !== 'object') continue;
    const { name, apn } = v as Record<string, unknown>;
    if (typeof name !== 'string' || typeof apn !== 'string') continue;
    if (!LTE_APN_TOKEN_RE.test(name) || !LTE_APN_TOKEN_RE.test(apn) || seen.has(name)) continue;
    seen.add(name);
    out.push({ name, apn });
  }
  return out;
}

/** What the router carries now for the chosen profile, as the job read it. */
export type LteApnProfileAction = 'add' | 'set' | 'none';

export function lteApnProfileAction(entry: LteApnEntry, current: { apn: string } | null): LteApnProfileAction {
  if (current === null) return 'add';
  return current.apn === entry.apn ? 'none' : 'set';
}

/** The lines for ONE entry. `selectOnLte1` false = lte1 already names it. */
export function lteApnLines(entry: LteApnEntry, action: LteApnProfileAction, selectOnLte1: boolean): string[] {
  assertLteApnEntry(entry);
  const lines: string[] = [];
  if (action === 'add') lines.push(`/interface lte apn add name="${entry.name}" apn="${entry.apn}"`);
  if (action === 'set') lines.push(`/interface lte apn set [find where name="${entry.name}"] apn="${entry.apn}"`);
  if (selectOnLte1) lines.push(`/interface lte set [find default-name=${LTE_DEFAULT_NAME}] apn-profiles="${entry.name}"`);
  return lines;
}

/** An allow-list refusal. Names what was refused, never a secret (there is none here). */
export class LteApnLineRefused extends Error {
  constructor(readonly offending: string[]) {
    super(`Refused line(s) outside the LTE APN allow-list: ${offending.join(' | ').slice(0, 400)}`);
    this.name = 'LteApnLineRefused';
  }
}

/**
 * The allow-list: every line must be EXACTLY one of the three forms above,
 * for THIS entry — no other menu, no second property, no `;`, no script
 * command, no other profile name. Throws `LteApnLineRefused` naming them.
 */
export function assertLteApnOnlyLines(lines: readonly string[], entry: LteApnEntry): void {
  assertLteApnEntry(entry);
  const allowed = new Set([
    `/interface lte apn add name="${entry.name}" apn="${entry.apn}"`,
    `/interface lte apn set [find where name="${entry.name}"] apn="${entry.apn}"`,
    `/interface lte set [find default-name=${LTE_DEFAULT_NAME}] apn-profiles="${entry.name}"`,
  ]);
  const offending = lines.filter((l) => !allowed.has(l));
  if (offending.length > 0 || lines.length === 0) throw new LteApnLineRefused(offending.length > 0 ? offending : ['(no line)']);
}

// ============================================================================
// The expected state, and how a reading differs from it
// ============================================================================

/** What the router reads back as, for the job's read-back and the card. */
export interface LteApnReading {
  /** lte1 (by default-name) is present. */
  lte1Present: boolean;
  /** lte1's current name (it may have been renamed). */
  lte1Name: string | null;
  /** lte1's `apn-profiles`, as printed (comma-joined when several). */
  apnProfiles: string | null;
  /** Every `/interface lte apn` profile: name -> apn. */
  profiles: LteApnEntry[];
}

export interface LteApnDifference {
  field: 'lte1' | 'profile' | 'apn' | 'apn-profiles';
  expected: string;
  actual: string;
}

/** Empty = the router is as the job would leave it for `entry`. */
export function lteApnStateDifferences(reading: LteApnReading | null, entry: LteApnEntry): LteApnDifference[] {
  if (!reading || !reading.lte1Present) return [{ field: 'lte1', expected: LTE_DEFAULT_NAME, actual: '' }];
  const out: LteApnDifference[] = [];
  const profile = reading.profiles.find((p) => p.name === entry.name) ?? null;
  if (!profile) out.push({ field: 'profile', expected: entry.name, actual: '' });
  else if (profile.apn !== entry.apn) out.push({ field: 'apn', expected: entry.apn, actual: profile.apn });
  const selected = (reading.apnProfiles ?? '').split(',').map((s) => s.trim()).filter((s) => s !== '');
  if (selected.length !== 1 || selected[0] !== entry.name) {
    out.push({ field: 'apn-profiles', expected: entry.name, actual: selected.join(',') });
  }
  return out;
}

// ============================================================================
// The egress guard — does ObliWAN's management path ride the modem?
// ============================================================================

/**
 * Changing the APN re-attaches the modem. When the L2TP tunnel that carries
 * ObliWAN's management traffic leaves through lte1, the write cuts the path
 * the job travels on, and many Chateaux run device-mode `home`, where the
 * scheduler — hence an on-box dead-man — is blocked. So the job arms nothing
 * and REFUSES unless it proved, on the router, that the management path
 * leaves through something else — NOW and ONCE THE MODEM HAS ATTACHED on the
 * new profile. The second half matters because an operator usually changes an
 * APN that does not work: with lte1 detached, the tunnel has fallen back to a
 * wired WAN and every route through the modem is inactive or absent, and the
 * write is precisely what brings them back. `unknown` is a refusal too.
 *  - `clear`    every path judged leaves through a non-LTE interface, and no
 *               route through an LTE interface could take it over;
 *  - `via_lte`  at least one leaves, or could leave, through an LTE interface;
 *  - `unknown`  the router's answer did not let the job decide.
 */
export type LteEgressState = 'clear' | 'via_lte' | 'unknown';

export interface LteEgressPath {
  /** The address routed (`connect-to`, the router's own `:resolve` of it, a
   *  live L2TP flow's remote address), or `0.0.0.0/0`. */
  target: string;
  /** Where that address came from. */
  source: 'connect_to' | 'resolved' | 'flow' | 'default';
  /** The l2tp-client it belongs to, null for a flow or the default route. */
  l2tpClient: string | null;
  /** The active main-table route that wins (longest prefix). */
  route: string | null;
  /** The interface(s) its `immediate-gw` names. */
  interfaces: string[];
  state: LteEgressState;
  why: string;
}

export interface LteEgressVerdict {
  state: LteEgressState;
  paths: LteEgressPath[];
  /** Every LTE interface name read on the router. */
  lteInterfaces: string[];
  /** Policy routing found (`/routing rule`, mangle `mark-routing`): the main
   *  table then does not say where the tunnel goes. */
  policyRouting: 'none' | 'present' | 'unknown';
  /** The default route lte1 installs once attached on the target profile. */
  lteRouteAfterWrite: LteRouteAfterWrite;
  summary: string;
}

/** One enabled route as the job reads it, active or not. */
export interface LteRouteReading {
  dst: string;
  /** `immediate-gw` as printed (`10.0.0.1%ether1`, `ether1`, …); empty on an
   *  inactive route, whose gateway is not resolved. */
  immediateGw: string;
  table: string;
  active: boolean;
  /** `distance` as printed. */
  distance: string;
  /** `gateway` as configured (`192.168.1.1`, `lte1`, `10.0.0.1%ether2`). */
  gateway: string;
}

export interface LteL2tpReading {
  name: string;
  connectTo: string;
  disabled: boolean;
  /** The router's own `:resolve` of `connect-to`; '' when it did not answer. */
  resolved: string;
}

export interface LteEgressReading {
  lteInterfaces: string[];
  /** Every interface name on the router; null = unread. A gateway is only
   *  attributed to an interface this list names. */
  interfaces: string[] | null;
  l2tpClients: LteL2tpReading[];
  /** null = the route read failed. */
  routes: LteRouteReading[] | null;
  /** Count of enabled `/routing rule` + mangle `mark-routing`; null = unread. */
  policyRules: number | null;
  /** Remote addresses of the live L2TP flows (conntrack, udp/1701) — the
   *  address the tunnel actually uses, whatever DNS says now; null = unread. */
  l2tpFlows: string[] | null;
}

/**
 * The default route lte1 will install once it attaches on the target
 * profile: `{ distance }`, null when the profile adds none, `unknown` when
 * the profile's settings could not be read.
 */
export type LteRouteAfterWrite = { distance: number } | null | 'unknown';

/**
 * [docs, not observed] A profile created by `/interface lte apn add name=
 * apn=` — the only add the allow-list lets through — takes RouterOS's
 * defaults: `add-default-route=yes`, `default-route-distance=2`. The fleet's
 * own profiles are created the same way (the exports carry no such
 * property), so a profile already on the router is read, never assumed.
 */
export const LTE_APN_ADD_DEFAULTS = { addDefaultRoute: true, distance: 2 } as const;

/** What `/interface lte apn` holds for the target profile, as printed. */
export interface LteApnRouteSettings {
  addDefaultRoute: string;
  defaultRouteDistance: string;
}

export function lteRouteAfterWrite(existing: LteApnRouteSettings | null): LteRouteAfterWrite {
  if (existing === null) return LTE_APN_ADD_DEFAULTS.addDefaultRoute ? { distance: LTE_APN_ADD_DEFAULTS.distance } : null;
  const add = existing.addDefaultRoute.trim().toLowerCase();
  if (add === 'false' || add === 'no') return null;
  if (add !== 'true' && add !== 'yes') return 'unknown';
  const d = existing.defaultRouteDistance.trim();
  return /^\d{1,3}$/.test(d) && Number(d) <= 255 ? { distance: Number(d) } : 'unknown';
}

function ipv4ToInt(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim());
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function prefixOf(dst: string): { net: number; len: number } | null {
  const m = /^([\d.]+)\/(\d{1,2})$/.exec(dst.trim());
  if (!m) return null;
  const net = ipv4ToInt(m[1]);
  const len = Number(m[2]);
  if (net === null || len > 32) return null;
  return { net, len };
}

function contains(p: { net: number; len: number }, ip: number): boolean {
  if (p.len === 0) return true;
  const mask = (0xffffffff << (32 - p.len)) >>> 0;
  return ((ip & mask) >>> 0) === ((p.net & mask) >>> 0);
}

/** A live L2TP flow's remote address: `203.0.113.10:1701` -> 203.0.113.10;
 *  any other port or spelling -> null. */
export function l2tpFlowAddress(dstAddress: string): string | null {
  const m = /^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$/.exec(dstAddress.trim());
  return m && m[2] === '1701' && ipv4ToInt(m[1]) !== null ? m[1] : null;
}

/**
 * The interfaces a gateway names, or null when ANY part of it cannot be
 * attributed. RouterOS prints one gateway as `10.0.0.1%ether1` or `ether1`;
 * several are joined by `,` in a print and by `;` once `:tostr` has turned
 * the array into text, so both separate. A token is accepted only as
 * `<ipv4>%<interface>` or a bare `<interface>`, the interface being one the
 * router listed; a bare address (no interface — an inactive route's gateway),
 * an empty part or an unlisted name makes the whole gateway unattributable.
 * Null is never read as "not LTE": the guard is the only net.
 */
export function interfacesOfGateway(text: string, interfaces: ReadonlySet<string> | null): string[] | null {
  const tokens = text.split(/[,;]/).map((t) => t.trim());
  if (tokens.some((t) => t === '')) return null;
  const out: string[] = [];
  for (const t of tokens) {
    const pct = t.indexOf('%');
    let iface: string;
    if (pct >= 0) {
      if (ipv4ToInt(t.slice(0, pct)) === null) return null;
      iface = t.slice(pct + 1);
    } else {
      iface = t;
    }
    if (iface === '' || interfaces === null || !interfaces.has(iface)) return null;
    out.push(iface);
  }
  return [...new Set(out)];
}

const DISTANCE_RE = /^\d{1,3}$/;

function judgePath(
  target: string,
  source: LteEgressPath['source'],
  l2tpClient: string | null,
  routes: LteRouteReading[],
  ctx: { lte: Set<string>; interfaces: Set<string>; after: LteRouteAfterWrite },
): LteEgressPath {
  const base = { target, source, l2tpClient };
  const isDefault = target === '0.0.0.0/0';
  const ip = isDefault ? 0 : ipv4ToInt(target);
  if (ip === null) return { ...base, route: null, interfaces: [], state: 'unknown', why: `« ${target} » is not an IPv4 address` };
  const lenCovering = (dst: string): number | null => {
    const p = prefixOf(dst);
    return p !== null && (isDefault ? p.len === 0 : contains(p, ip)) ? p.len : null;
  };
  const isLte = (i: string) => ctx.lte.has(i) || /^lte/i.test(i);
  const main = routes.filter((r) => r.table === 'main');

  // NOW: the active route that wins (longest prefix; every ECMP leg judged).
  const active = main.filter((r) => r.active && lenCovering(r.dst) !== null);
  if (active.length === 0) return { ...base, route: null, interfaces: [], state: 'unknown', why: 'no active main-table route covers it' };
  const best = Math.max(...active.map((r) => lenCovering(r.dst) as number));
  const winners = active.filter((r) => lenCovering(r.dst) === best);
  const route = [...new Set(winners.map((r) => r.dst))].join(',');
  const perWinner = winners.map((r) => interfacesOfGateway(r.immediateGw, ctx.interfaces));
  if (perWinner.some((i) => i === null)) {
    return { ...base, route, interfaces: [], state: 'unknown', why: 'the immediate gateway of its active route names no listed interface' };
  }
  const interfaces = [...new Set((perWinner as string[][]).flat())];
  const viaLte = interfaces.filter(isLte);
  if (viaLte.length > 0) return { ...base, route, interfaces, state: 'via_lte', why: `it leaves through ${viaLte.join(', ')}` };
  if (winners.some((r) => !DISTANCE_RE.test(r.distance.trim()))) {
    return { ...base, route, interfaces, state: 'unknown', why: 'its active route printed no distance' };
  }
  const winDistance = Math.min(...winners.map((r) => Number(r.distance.trim())));

  // ONCE lte1 HAS ATTACHED: a route not active now that could win — a longer
  // prefix, or the same prefix at a distance no greater (ECMP included) —
  // through the modem is `via_lte`, through a gateway that names no listed
  // interface is `unknown`. The default route the target profile installs is
  // one of them; it does not exist yet, so it is not in the route table.
  const couldWin = (len: number, distance: number) => len > best || (len === best && distance <= winDistance);
  if (ctx.after === 'unknown') {
    return { ...base, route, interfaces, state: 'unknown', why: 'whether the target APN profile adds a default route could not be read' };
  }
  if (ctx.after !== null && couldWin(0, ctx.after.distance)) {
    return {
      ...base, route, interfaces, state: 'via_lte',
      why: `once the modem attaches, the target profile's default route (distance ${ctx.after.distance}) would take it over from ` +
        `${interfaces.join(', ')} (distance ${winDistance})`,
    };
  }
  for (const r of main) {
    if (r.active) continue;
    const len = lenCovering(r.dst);
    if (len === null) continue;
    const d = r.distance.trim();
    if (!DISTANCE_RE.test(d)) return { ...base, route, interfaces, state: 'unknown', why: `the inactive route ${r.dst} printed no distance` };
    if (!couldWin(len, Number(d))) continue;
    const via = interfacesOfGateway(r.gateway, ctx.interfaces);
    if (via === null) {
      return {
        ...base, route, interfaces, state: 'unknown',
        why: `the inactive route ${r.dst} via « ${r.gateway} » could take it over through an interface that cannot be named`,
      };
    }
    const lteVia = via.filter(isLte);
    if (lteVia.length > 0) {
      return { ...base, route, interfaces, state: 'via_lte', why: `once the modem attaches, the inactive route ${r.dst} through ${lteVia.join(', ')} would take it over` };
    }
  }
  return { ...base, route, interfaces, state: 'clear', why: `it leaves through ${interfaces.join(', ')}, and no route through the modem could take it over` };
}

/**
 * The verdict, from what the job read and the route the target profile would
 * install. The addresses judged are those of every enabled l2tp-client (the
 * tunnel ObliWAN reaches the router through): its `connect-to` when it is
 * an address, else the router's own `:resolve` of the name — the fleet's
 * concentrators are named, not numbered — plus the remote address of every
 * live L2TP flow, which is the address actually in use. A client whose name
 * did not resolve, with no live flow to stand for it, is `unknown`. On a
 * router with no enabled l2tp-client, the default route is judged. Any path
 * `via_lte` wins; then any `unknown`; policy routing present or unread makes
 * the whole verdict `unknown`.
 */
export function judgeLteEgress(reading: LteEgressReading, after: LteRouteAfterWrite): LteEgressVerdict {
  const policyRouting: LteEgressVerdict['policyRouting'] =
    reading.policyRules === null ? 'unknown' : reading.policyRules > 0 ? 'present' : 'none';
  const common = { lteInterfaces: [...reading.lteInterfaces], policyRouting, lteRouteAfterWrite: after };
  if (reading.routes === null) return { state: 'unknown', paths: [], ...common, summary: 'the routes could not be read' };
  if (reading.interfaces === null) {
    return { state: 'unknown', paths: [], ...common, summary: 'the interface list could not be read: no gateway can be attributed' };
  }
  const routes = reading.routes;
  const ctx = { lte: new Set(reading.lteInterfaces), interfaces: new Set(reading.interfaces), after };
  const flows = [...new Set(reading.l2tpFlows ?? [])];
  const enabled = reading.l2tpClients.filter((c) => !c.disabled);
  const paths: LteEgressPath[] = [];
  for (const c of enabled) {
    if (ipv4ToInt(c.connectTo) !== null) {
      paths.push(judgePath(c.connectTo, 'connect_to', c.name, routes, ctx));
    } else if (ipv4ToInt(c.resolved) !== null) {
      paths.push(judgePath(c.resolved, 'resolved', c.name, routes, ctx));
    } else if (flows.length === 0) {
      paths.push({
        target: c.connectTo, source: 'connect_to', l2tpClient: c.name, route: null, interfaces: [], state: 'unknown',
        why: `« ${c.connectTo} » did not resolve on the router and no live L2TP flow shows the address in use`,
      });
    }
  }
  if (enabled.length > 0) for (const f of flows) paths.push(judgePath(f, 'flow', null, routes, ctx));
  else paths.push(judgePath('0.0.0.0/0', 'default', null, routes, ctx));
  const describe = (p: LteEgressPath) =>
    `${p.source === 'default' ? 'default route' : p.source === 'flow' ? `L2TP flow → ${p.target}` : `${p.l2tpClient} → ${p.target}`}: ${p.why}`;
  const viaLte = paths.filter((p) => p.state === 'via_lte');
  const unknown = paths.filter((p) => p.state === 'unknown');
  if (viaLte.length > 0) return { state: 'via_lte', paths, ...common, summary: viaLte.map(describe).join('; ') };
  if (unknown.length > 0) return { state: 'unknown', paths, ...common, summary: unknown.map(describe).join('; ') };
  if (policyRouting !== 'none') {
    return {
      state: 'unknown',
      paths,
      ...common,
      summary: policyRouting === 'present'
        ? 'policy routing is configured (routing rules or mangle mark-routing): the main table does not say where the tunnel leaves'
        : 'whether policy routing is configured could not be read',
    };
  }
  return { state: 'clear', paths, ...common, summary: paths.map(describe).join('; ') };
}
