// ============================================================================
// @obliwan/shared — bringing a router IN SERVICE up to the corrected customer
// templates (operator decision 2026-10-04): the change job `legacy_compliance`
// (migration 066, server/src/services/change/legacyCompliance.service.ts)
// ============================================================================
//
// WHY A JOB OF ITS OWN. The routers that predate ObliWAN were configured from
// the customer templates as they were, and the templates have since been
// corrected on six points, and the operator added a seventh on 2026-10-04 (the
// DNS-Amp rules) and retired one on 2026-10-05 (random-source-port, below).
// The NCM models none of the first menus involved (`/tool mac-server`,
// `/tool romon`, `/interface l2tp-client`), and the push path refuses to place
// an ordered filter rule that carries no `obliwan:` marker — the DNS-Amp rules
// carry the operator's own comment — so no plan, push or drift report can
// carry them; this job carries exactly those statements and nothing else —
// six written, the retired one read and never written — over SSH, with the
// device's EXISTING credential (no account is ever created on a router in
// service).
//
// THE FIXES, each idempotent, each sent as its own command so that one refusal
// does not cancel the others:
//   mac_server      `/tool mac-server set allowed-interface-list=all`
//   mac_winbox      `/tool mac-server mac-winbox set allowed-interface-list=all`
//   romon           `/tool romon set enabled=yes` — device-mode may deny RoMON
//                   (`home` does, by MikroTik's table): a denial known before
//                   the write skips it by name, a refusal by the router is
//                   recorded and never fails the job.
//   service_ssh     `/ip service set <the configured ssh row> address=<list>`,
//                   the row chosen on the same line by `routerOsServiceSet`
//                   (shared/src/routerOsService.ts): this job rides SSH, and
//                   RouterOS 7.24.5 lists its session as a dynamic
//                   `/ip service` entry named ssh. The first form,
//                   `set [find where name="ssh"]`, matched that entry too:
//                   the service changed, then "failure: this is configured
//                   elsewhere", and the job recorded the line as refused
//                   [prod, 2026-10-05].
//   service_winbox  the same for winbox, sent BEFORE ssh (the ssh line, which
//                   touches the job's own service, is the last of a–e). <list>
//                   is the list AS READ with the store LAN network appended,
//                   only when the list is non-empty (empty = open to every
//                   address: left alone) and does not already cover it.
//                   Nothing is ever removed from it.
//                   The LAN network is READ on the router — the network of the
//                   address on the LAN bridge — and never guessed: no bridge,
//                   several candidates, no address or several networks skip
//                   both by name.
//   dns_amp_protection
//                   the operator's two input rules (2026-10-04), spelled as
//                   customer A's production configurations spell them:
//                   `reject chain=input comment="DNS-Amp Protection"
//                   dst-port=53 in-interface-list=WAN protocol=udp|tcp
//                   reject-with=icmp-host-unreachable`, the missing one(s) in
//                   ONE command, placed at the TOP of the input chain
//                   (`place-before=[:pick [find where chain=input] 0]`), where
//                   no earlier accept can let a query through. It refuses
//                   only NEW queries to port 53 arriving on a WAN-list
//                   interface: the router's own lookups (answers come FROM
//                   port 53) and the job's SSH are untouched. Sent before the
//                   service lines (the ssh one stays the last of a–e). Skipped
//                   by name when the router has no `WAN` list, when a WAN
//                   member is a bridge or a LAN-list member (the store's own
//                   DNS would be refused), and when a rule already carrying
//                   that comment differs or is disabled (the operator's
//                   variant, left alone), and when the router answers DNS and
//                   carries static IPsec policies — or either could not be
//                   read: a decrypted packet keeps the WAN interface as its
//                   in-interface, so a query from across IPsec would be
//                   refused (operator: write nothing that could break the
//                   store). What remains possible is SIGNALLED
//                   (`LEGACY_FIX_WARNINGS`): an L2TP tunnel in the WAN list,
//                   rules that are inert because the router serves no DNS.
//   l2tp_random_source_port
//                   RETIRED (operator decision 2026-10-05,
//                   `LEGACY_RETIRED_FIXES`): read and reported, never written —
//                   the right value depends on the site's operator and box, and
//                   the value of a router that works is never changed. Its
//                   machinery stays DORMANT, still exercised by the harness:
//                   `/interface l2tp-client set [find where name="…"]
//                   random-source-port=yes` on every client lacking it, as ONE
//                   command, sent LAST. RouterOS 6 has no such property: skipped
//                   by name. The change restarts the tunnels — the one the job
//                   travels on included — so it is preceded by a self-revert
//                   started on the router (`legacySelfRevertLine`).
//
// MAC-telnet, MAC-Winbox and RoMON are only ever OPENED here, never
// restricted; nothing touches the IPsec policy or the netwatch entries of the
// templates, and the only firewall statements are the two DNS-Amp adds. The
// allow-list below refuses any other line. A job writes only the fixes frozen
// in its row at enqueue (`legacy_compliance_jobs.fixes`): one queued before a
// fix existed skips it as `not_requested`. A retired fix is skipped as
// `retired` whatever the frozen list says: a job queued before the retirement
// writes nothing for it either.
//
// THIS FILE IS THE ONE SOURCE of the lines the job sends and of the allow-list
// that judges them (spelled twice on purpose, so a builder that drifts is
// caught), of the plan derived from a reading, and of the expected read-back
// state. Pure: no socket, no database.
//
// ┌─ ROUTEROS BEHAVIOUR RELIED ON — REASONED, NOT OBSERVED ───────────────────┐
// │ [docs] `random-source-port` exists on `/interface l2tp-client` in         │
// │ RouterOS 7 only, and changing a client's settings restarts its tunnel.    │
// │ [docs] `:execute` runs a script as a background job and returns that     │
// │ job's id. Device-mode: the feature table this repo re-read from          │
// │ MikroTik's page (server/src/bench/deviceModeGate.ts, `MODE_DENIED`)       │
// │ lists `scheduler` among `home`'s denials and names no scripting command,  │
// │ so `:execute` is not denied by `home` ON THAT TABLE'S SILENCE — inferred, │
// │ not seen on a box. Equally inferred: that the job outlives the SSH        │
// │ session that started it (the l2tp line ends the session when it restarts │
// │ the tunnel). Neither is relied on. The self-revert prints its job id     │
// │ (`LEGACY_GUARD_JOB_TAG`); the l2tp line is sent only from a NEW SSH       │
// │ connection, opened after the one that started the job has ended, on       │
// │ which that id is still listed in `/system script job` — a router where   │
// │ either inference is false gets no l2tp line, by name. After the line, the │
// │ job waits past the guard's decision and reads its log line back, so a     │
// │ guard that left none is REPORTED ("no log line"), never assumed to have   │
// │ run. No line of this file has reached a router.                           │
// │ DNS-Amp: that `[find where chain=input]` lists the rules in the chain's  │
// │ order, so its first item is the chain's first rule, and that a nested    │
// │ `[find]` inside `/ip firewall filter add` is that menu's — REASONED      │
// │ (the common console idiom; the l2tp line nests `[find]` the same way).   │
// │ The read-back judges presence, not position.                              │
// │ Service lines: how the configured row is told from a connection entry,   │
// │ and what of it is REASONED (`get … dynamic` on 7.24.5 and on 7.16), is   │
// │ in shared/src/routerOsService.ts.                                         │
// └───────────────────────────────────────────────────────────────────────────┘

import { routerOsServiceSet } from './routerOsService';

/** The `change_jobs.kind` of the job. */
export const LEGACY_COMPLIANCE_KIND = 'legacy_compliance' as const;

/** The seven fixes, in the order the record and the card list them — the
 *  retired one included (`LEGACY_RETIRED_FIXES`). They are SENT in this order
 *  but for the DNS-Amp rules, which go before the service lines, and winbox,
 *  which goes before ssh (the service the job's own session rides is the last
 *  of a–e); the l2tp one, when not retired, is always last. */
export const LEGACY_FIX_KEYS = [
  'mac_server',
  'mac_winbox',
  'romon',
  'service_ssh',
  'service_winbox',
  'dns_amp_protection',
  'l2tp_random_source_port',
] as const;
export type LegacyFixKey = (typeof LEGACY_FIX_KEYS)[number];

/**
 * The fixes the job no longer writes (operator decision 2026-10-05). Each stays
 * in LEGACY_FIX_KEYS, is still READ and reported (skipped, `retired`), and its
 * machinery stays dormant — exercised by the harness with `retired = []`.
 *   l2tp_random_source_port  a read-only SSH audit of the 380 online routers
 *     found the l2tp-mgmt client at `no` on 276 and `yes` on 31 (46 more run
 *     RouterOS 6, which has no such property), both values working, on 4G
 *     behind operator CGNAT and on fixed lines. In the lab, behind an SFR FTTx
 *     box, a clear L2TP tunnel NOT sourced from UDP 1701 dies every ~84 s (its
 *     hello is never acknowledged) while the CHR answers the right port. The
 *     right value depends on the site's operator and box: `no` is the default,
 *     a customer or a site may differ, and the value of a router that works is
 *     never changed by ObliWAN. The self-revert, which judges `running` once,
 *     120 s after the line, cannot see a tunnel that reconnects every 84 s.
 */
export const LEGACY_RETIRED_FIXES: readonly LegacyFixKey[] = ['l2tp_random_source_port'];

/** The fixes a job may write, from its frozen row (`legacy_compliance_jobs.fixes`):
 *  the known keys it lists, in LEGACY_FIX_KEYS order; null when the value is
 *  not a list of them (the job then refuses rather than guess). */
export function legacyRequestedFixes(frozen: unknown): LegacyFixKey[] | null {
  if (!Array.isArray(frozen) || frozen.length === 0) return null;
  if (!frozen.every((k) => typeof k === 'string')) return null;
  const known = LEGACY_FIX_KEYS.filter((k) => frozen.includes(k));
  return known.length > 0 ? known : null;
}

/** The two services fix d concerns, by their RouterOS name. */
export const LEGACY_LAN_SERVICES = ['ssh', 'winbox'] as const;
export type LegacyLanService = (typeof LEGACY_LAN_SERVICES)[number];
const SERVICE_FIX: Record<LegacyLanService, LegacyFixKey> = { ssh: 'service_ssh', winbox: 'service_winbox' };

/**
 * The self-revert's delay: it reads, this long after it was started, whether
 * every watched l2tp-client is running again. The job freezes it per row
 * (`legacy_compliance_jobs.revert_after_s`).
 */
export const LEGACY_REVERT_AFTER_S = 120;
/**
 * The self-revert's clock starts when IT starts, and the l2tp line leaves
 * later, from a new session that first sees the self-revert's job alive.
 * More than this between the two and the line is not sent: the tunnel would
 * get less than `LEGACY_REVERT_AFTER_S - LEGACY_GUARD_MAX_LEAD_S` seconds to
 * come back before the self-revert judges it.
 */
export const LEGACY_GUARD_MAX_LEAD_S = 30;
/** How long the job waits, from the l2tp write, for the tunnel to come back. */
export const LEGACY_TUNNEL_WAIT_S = 180;
/** After the guard's instant, before the final read: the guard's own
 *  `:delay` started a moment before the l2tp line was sent. */
export const LEGACY_GUARD_MARGIN_S = 15;

/** The interface list the LAN bridge is a member of in the templates
 *  (`/interface list member add interface=<bridge> list=LAN`). */
export const LEGACY_LAN_LIST = 'LAN';

/** The interface list the uplinks are members of in the templates
 *  (ether1-WAN1, lte1, the PPPoE client): what the DNS-Amp rules match. */
export const LEGACY_WAN_LIST = 'WAN';

/** The comment both DNS-Amp rules carry: how the job finds them again. */
export const LEGACY_DNS_AMP_COMMENT = 'DNS-Amp Protection';
/** The two rules, one per protocol, in the order the chain holds them. */
export const LEGACY_DNS_AMP_PROTOCOLS = ['udp', 'tcp'] as const;
export type LegacyDnsAmpProtocol = (typeof LEGACY_DNS_AMP_PROTOCOLS)[number];
/** What a DNS-Amp rule is, property by property, as `:tostr [get]` prints it. */
export const LEGACY_DNS_AMP_SPEC = {
  chain: 'input',
  action: 'reject',
  dstPort: '53',
  inInterfaceList: LEGACY_WAN_LIST,
  rejectWith: 'icmp-host-unreachable',
} as const;
/** Where an added rule goes: the first rule of the input chain, read when the
 *  line runs (header: REASONED). */
export const LEGACY_DNS_AMP_TOP = 'place-before=[:pick [find where chain=input] 0]';

/** The `/ip firewall filter add` statement of one DNS-Amp rule. */
export function legacyDnsAmpStatement(protocol: LegacyDnsAmpProtocol, top: boolean): string {
  if (!LEGACY_DNS_AMP_PROTOCOLS.includes(protocol)) throw new LegacyComplianceInputError('dns', 'Unknown DNS-Amp protocol.');
  return `/ip firewall filter add action=reject chain=input comment="${LEGACY_DNS_AMP_COMMENT}" dst-port=53 ` +
    `in-interface-list=${LEGACY_WAN_LIST} protocol=${protocol} reject-with=icmp-host-unreachable${top ? ` ${LEGACY_DNS_AMP_TOP}` : ''}`;
}

/** A LAN prefix length outside this is not what the templates configure: the
 *  fix is skipped by name rather than opening SSH to an unusual range. */
export const LEGACY_LAN_PREFIX_MIN = 16;
export const LEGACY_LAN_PREFIX_MAX = 30;

/**
 * An interface name the lines can carry between double quotes with nothing to
 * escape: letters, digits, space and `._@:+()-`. Anything else is refused,
 * never escaped — a name outside it skips its fix by name.
 */
export const LEGACY_SAFE_NAME_RE = /^[A-Za-z0-9._@:+() -]{1,64}$/;

/** Marks the self-revert writes in the router's log, so the job can read its
 *  decision back: `obliwan-compliance job=<id>: REVERTED|STOOD-DOWN …`. */
export function legacyGuardLogPrefix(jobId: number): string {
  return `obliwan-compliance job=${jobId}:`;
}
export const LEGACY_GUARD_REVERTED = 'REVERTED';
export const LEGACY_GUARD_STOOD_DOWN = 'STOOD-DOWN';
/** The self-revert line prints `revertjob|<id>`: the id `:execute` returns. */
export const LEGACY_GUARD_JOB_TAG = 'revertjob';

/** An input the lines could not carry unescaped. Names the field. */
export class LegacyComplianceInputError extends Error {
  constructor(readonly field: string, message: string) {
    super(message);
    this.name = 'LegacyComplianceInputError';
  }
}

// ============================================================================
// IPv4 arithmetic (LAN network, coverage)
// ============================================================================

function ipv4ToInt(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim());
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function intToIpv4(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

function maskOf(len: number): number {
  return len === 0 ? 0 : (0xffffffff << (32 - len)) >>> 0;
}

/** `a.b.c.d/len` (or a bare address, /32) -> { ip, len }; null otherwise. */
export function legacyParseIpv4Prefix(text: string): { ip: number; len: number } | null {
  const m = /^([\d.]+)(?:\/(\d{1,2}))?$/.exec(text.trim());
  if (!m) return null;
  const ip = ipv4ToInt(m[1]);
  const len = m[2] === undefined ? 32 : Number(m[2]);
  if (ip === null || len > 32) return null;
  return { ip, len };
}

/** The network a host address sits in: `10.1.2.70/24` -> `10.1.2.0/24`. */
export function legacyNetworkOf(cidr: string): string | null {
  const p = legacyParseIpv4Prefix(cidr);
  if (!p) return null;
  return `${intToIpv4((p.ip & maskOf(p.len)) >>> 0)}/${p.len}`;
}

const IPV4_ENTRY_RE = /^\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?$/;
const IPV6_ENTRY_RE = /^[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*(?:\/\d{1,3})?$/;

/**
 * An `/ip service … address` list as `:tostr` prints it (`;`-joined; `,` is
 * accepted too) -> its entries, in order. NULL when any entry is not an IPv4
 * or IPv6 address/prefix this file can read exactly: rewriting a list with an
 * entry it does not understand could alter it, so the fix is skipped instead.
 * `[]` = the empty list, which RouterOS reads as "every address".
 */
export function legacyParseAddressList(text: string): string[] | null {
  const entries = text.split(/[;,]/).map((e) => e.trim()).filter((e) => e !== '');
  for (const e of entries) {
    if (IPV4_ENTRY_RE.test(e)) {
      if (legacyParseIpv4Prefix(e) === null) return null;
    } else if (!IPV6_ENTRY_RE.test(e)) {
      return null;
    }
  }
  return entries;
}

/** True when an IPv4 entry of the list covers the whole of `network`. */
export function legacyListCovers(entries: readonly string[], network: string): boolean {
  const lan = legacyParseIpv4Prefix(network);
  if (!lan) return false;
  return entries.some((e) => {
    if (!IPV4_ENTRY_RE.test(e)) return false;
    const p = legacyParseIpv4Prefix(e);
    if (!p || p.len > lan.len) return false;
    const mask = maskOf(p.len);
    return ((p.ip & mask) >>> 0) === ((lan.ip & mask) >>> 0);
  });
}

// ============================================================================
// What the job reads on the router
// ============================================================================

export interface LegacyL2tpClientReading {
  name: string;
  /** As printed; `absent` when the property could not be read (RouterOS 6,
   *  or a 7.x build without it). */
  randomSourcePort: string;
  running: boolean;
  disabled: boolean;
}

/** One `/ip firewall filter` rule carrying the DNS-Amp comment, as printed. */
export interface LegacyFilterRuleReading {
  chain: string;
  action: string;
  protocol: string;
  dstPort: string;
  inInterfaceList: string;
  rejectWith: string;
  disabled: boolean;
  /** A matcher the operator's rule does not have is set (src-address,
   *  src-address-list, dst-address, dst-address-type, in-interface,
   *  connection-state — the ones read): a narrower variant. */
  narrowed: boolean;
}

/** What device-mode says of RoMON, judged by the server's one reader of
 *  MikroTik's table (bench/deviceModeGate.ts `featureVerdict`). */
export type LegacyRomonDeviceMode = 'allowed' | 'blocked' | 'unknown';

/** One reading of everything the plan decides on. NULL anywhere = unread. */
export interface LegacyComplianceReading {
  /** `/system resource get version`, as printed. */
  version: string | null;
  macServer: string | null;
  macWinbox: string | null;
  /** `/tool romon get enabled`, as printed. */
  romon: string | null;
  deviceMode: { mode: string | null; romonFlag: string | null; romon: LegacyRomonDeviceMode };
  /** The CONFIGURED ssh and winbox rows — connection entries are skipped by
   *  the read (shared/src/routerOsService.ts); two rows of one name are
   *  judged unread by the plan, never one picked. */
  services: Array<{ name: string; address: string }> | null;
  bridges: string[] | null;
  /** Enabled members of the interface list `LAN`. */
  lanMembers: string[] | null;
  /** Enabled `/ip address` rows: interface + address as printed. */
  addresses: Array<{ interface: string; address: string }> | null;
  l2tpClients: LegacyL2tpClientReading[] | null;
  /** The interface list `WAN`: whether it exists, and its enabled members. */
  wan: { exists: boolean; members: string[] } | null;
  /** The input chain's rule count, and every rule carrying the DNS-Amp comment. */
  dnsAmp: { inputRules: number; rules: LegacyFilterRuleReading[] } | null;
  /** `/ip dns get allow-remote-requests`, as printed. */
  dnsRemote: string | null;
  /** Enabled, static, non-template `/ip ipsec policy` entries. */
  ipsecPolicies: number | null;
}

const truthy = (v: string | null | undefined): boolean => ['true', 'yes'].includes((v ?? '').trim().toLowerCase());
const falsy = (v: string | null | undefined): boolean => ['false', 'no'].includes((v ?? '').trim().toLowerCase());

/** RouterOS major version from `7.16.2 (stable)`; null when unread. */
export function legacyRouterOsMajor(version: string | null): number | null {
  const m = /^(\d+)\./.exec((version ?? '').trim());
  return m ? Number(m[1]) : null;
}

// ============================================================================
// The LAN network — read, never guessed
// ============================================================================

/** Why no LAN network: closed codes the card translates. */
export const LEGACY_LAN_REASONS = [
  'unread',
  'no_bridge',
  'bridge_ambiguous',
  'name_unsafe',
  'no_address',
  'network_ambiguous',
  'prefix_out_of_range',
] as const;
export type LegacyLanReason = (typeof LEGACY_LAN_REASONS)[number];

export interface LegacyLanDerivation {
  network: string | null;
  bridge: string | null;
  reason: LegacyLanReason | null;
  /** How the bridge was chosen, or why none was. */
  detail: string;
}

/**
 * The store LAN network: the bridge that is a member of the `LAN` interface
 * list (the templates' `defconf` convention) — or, when no bridge is, the
 * router's ONLY bridge — and the one network of the enabled IPv4 addresses on
 * it. Two candidate bridges, two networks, none: no network, with the reason.
 */
export function legacyDeriveLan(reading: Pick<LegacyComplianceReading, 'bridges' | 'lanMembers' | 'addresses'>): LegacyLanDerivation {
  const none = (reason: LegacyLanReason, detail: string, bridge: string | null = null): LegacyLanDerivation =>
    ({ network: null, bridge, reason, detail });
  if (!reading.bridges || !reading.lanMembers || !reading.addresses) {
    return none('unread', 'bridges, LAN list members or addresses could not be read');
  }
  const inList = reading.bridges.filter((b) => reading.lanMembers!.includes(b));
  const candidates = inList.length > 0 ? inList : reading.bridges;
  const how = inList.length > 0 ? `member of the interface list ${LEGACY_LAN_LIST}` : 'the only bridge on the router';
  if (candidates.length === 0) return none('no_bridge', 'the router has no bridge');
  if (candidates.length > 1) {
    return none('bridge_ambiguous', `${candidates.length} candidate bridges (${candidates.join(', ')})`);
  }
  const bridge = candidates[0];
  if (!LEGACY_SAFE_NAME_RE.test(bridge)) return none('name_unsafe', 'the bridge name holds characters the job does not read');
  const rows = reading.addresses.filter((a) => a.interface === bridge);
  if (rows.length === 0) return none('no_address', `no enabled address on ${bridge} (${how})`, bridge);
  const networks = rows.map((r) => legacyNetworkOf(r.address));
  if (networks.some((n) => n === null)) return none('network_ambiguous', `an address on ${bridge} could not be read`, bridge);
  const distinct = [...new Set(networks as string[])];
  if (distinct.length > 1) return none('network_ambiguous', `${distinct.length} networks on ${bridge} (${distinct.join(', ')})`, bridge);
  const len = Number(distinct[0].split('/')[1]);
  if (len < LEGACY_LAN_PREFIX_MIN || len > LEGACY_LAN_PREFIX_MAX) {
    return none('prefix_out_of_range', `${distinct[0]} on ${bridge}: /${len} is outside /${LEGACY_LAN_PREFIX_MIN}–/${LEGACY_LAN_PREFIX_MAX}`, bridge);
  }
  return { network: distinct[0], bridge, reason: null, detail: `${bridge} (${how})` };
}

// ============================================================================
// The plan
// ============================================================================

/** Closed reason codes per fix (the card translates them). */
export const LEGACY_FIX_REASONS = [
  // present
  'already_set',
  'list_empty_open',
  'lan_covered',
  'no_l2tp_client',
  // needed
  'to_set',
  'lan_missing',
  // skipped
  'unread',
  'romon_denied_by_device_mode',
  'service_absent',
  'entry_unreadable',
  'lan_unknown',
  'ros6',
  'property_absent',
  'name_unsafe',
  'wan_list_absent',
  'wan_list_holds_lan',
  'rule_customized',
  'rule_disabled',
  'dns_over_ipsec',
  'dns_ipsec_unread',
  'retired',
  'not_requested',
] as const;
export type LegacyFixReason = (typeof LEGACY_FIX_REASONS)[number];

/**
 * What could still break, SIGNALLED beside a fix that is written anyway
 * (operator rule: anything with the slightest chance of breaking is reported).
 * Closed codes the card translates.
 *   wan_holds_tunnel   an L2TP client is a member of the WAN list: DNS asked
 *                      by the far end of that tunnel is refused.
 *   dns_not_served     the router does not answer DNS today: the rules are
 *                      inert until someone turns remote requests on.
 * The IPsec case is NOT a warning but a named skip (operator, 2026-10-04:
 * write nothing where it could break the store): a router that answers DNS
 * and carries static IPsec policies (`dns_over_ipsec` — a decrypted query
 * keeps the WAN in-interface and would be refused), or whose DNS setting or
 * policies could not be read (`dns_ipsec_unread`), gets no DNS-Amp line.
 */
export const LEGACY_FIX_WARNINGS = ['wan_holds_tunnel', 'dns_not_served'] as const;
export type LegacyFixWarning = (typeof LEGACY_FIX_WARNINGS)[number];

/**
 * The skip reasons that say the job did not OBSERVE the fix's state, as
 * opposed to the named skips the design accepts (RouterOS 6, a build without
 * the property, an unknown LAN, RoMON denied by device-mode, an unsafe name,
 * a retired fix):
 * a value the router did not print, a list entry this file cannot read
 * exactly, a service RouterOS always has that the read did not list. Nothing
 * is written for them either, but they never count as conforming: the
 * read-back judges them again and an unestablished state fails the job.
 */
export const LEGACY_UNOBSERVED_REASONS: readonly LegacyFixReason[] = ['unread', 'entry_unreadable', 'service_absent'];
export function legacyReasonUnobserved(reason: LegacyFixReason): boolean {
  return LEGACY_UNOBSERVED_REASONS.includes(reason);
}

export interface LegacyFixPlan {
  state: 'present' | 'needed' | 'skipped';
  reason: LegacyFixReason;
  /** The value read (or a summary of it), for the record. */
  current: string | null;
  /** A sentence for the record; the card shows the reason code translated. */
  detail: string;
  /** What could still break, written anyway and reported (absent on plans
   *  stored before the DNS-Amp fix). */
  warnings?: LegacyFixWarning[];
}

export interface LegacyCompliancePlan {
  fixes: Record<LegacyFixKey, LegacyFixPlan>;
  lan: LegacyLanDerivation;
  /** For each service whose fix is needed: the list as read, and as written. */
  services: Partial<Record<LegacyLanService, { before: string[]; after: string[] }>>;
  /** The l2tp fix when needed: the clients changed, and the ones the
   *  self-revert watches (changed AND running before the write). */
  l2tp: { change: string[]; watch: string[] } | null;
  /** The DNS-Amp fix when needed: the protocols whose rule is missing, and
   *  whether the input chain had a rule to place them before. */
  dnsAmp: { missing: LegacyDnsAmpProtocol[]; top: boolean } | null;
  rosMajor: number | null;
}

/** A rule exactly as the operator's, for one protocol (enabled or not). */
export function legacyDnsAmpExact(r: LegacyFilterRuleReading, protocol: LegacyDnsAmpProtocol): boolean {
  const s = LEGACY_DNS_AMP_SPEC;
  return r.chain === s.chain && r.action === s.action && r.protocol === protocol && r.dstPort === s.dstPort &&
    r.inInterfaceList === s.inInterfaceList && r.rejectWith === s.rejectWith && !r.narrowed;
}

/** What a retired fix reports: the value READ, for the record and the card.
 *  random-source-port per client as printed (`absent` on RouterOS 6). */
function retiredReading(key: LegacyFixKey, reading: LegacyComplianceReading, planned: string | null): { current: string | null; detail: string } {
  const tail = 'no longer written by this job (retired: the right value depends on the site\'s operator and box)';
  if (key !== 'l2tp_random_source_port') return { current: planned, detail: tail };
  const clients = reading.l2tpClients;
  if (clients === null) return { current: null, detail: `/interface l2tp-client could not be read; random-source-port is ${tail}` };
  if (clients.length === 0) return { current: '', detail: `no l2tp-client; random-source-port is ${tail}` };
  const read = clients.map((c) => `${c.name}=${c.randomSourcePort}`).join(',');
  return { current: read, detail: `random-source-port as read: ${read} — ${tail}` };
}

/**
 * From one reading, what each fix needs. Pure; decides nothing it cannot read:
 * an unread value SKIPS its fix by name (writing blind against a menu the
 * router may not have would fail late and say less). A fix in `retired`
 * (`LEGACY_RETIRED_FIXES` unless a caller says otherwise) is skipped as
 * `retired` with what was read, and its plan part cleared — decided BEFORE
 * `requested`, so a frozen list that still names it writes nothing for it. A
 * fix outside `requested` (the job's frozen list) is skipped as `not_requested`.
 */
export function legacyPlan(
  reading: LegacyComplianceReading,
  requested: readonly LegacyFixKey[] = LEGACY_FIX_KEYS,
  retired: readonly LegacyFixKey[] = LEGACY_RETIRED_FIXES,
): LegacyCompliancePlan {
  const fixes = {} as Record<LegacyFixKey, LegacyFixPlan>;
  const set = (key: LegacyFixKey, state: LegacyFixPlan['state'], reason: LegacyFixReason, current: string | null, detail: string,
    warnings?: LegacyFixWarning[]) => {
    fixes[key] = { state, reason, current, detail, ...(warnings && warnings.length > 0 ? { warnings } : {}) };
  };

  for (const [key, value] of [['mac_server', reading.macServer], ['mac_winbox', reading.macWinbox]] as const) {
    if (value === null) set(key, 'skipped', 'unread', null, 'allowed-interface-list could not be read');
    else if (value.trim() === 'all') set(key, 'present', 'already_set', value, 'allowed-interface-list=all');
    else set(key, 'needed', 'to_set', value, `allowed-interface-list=${value || '(none)'} -> all`);
  }

  if (reading.romon === null) set('romon', 'skipped', 'unread', null, 'RoMON could not be read');
  else if (truthy(reading.romon)) set('romon', 'present', 'already_set', reading.romon, 'RoMON enabled');
  else if (reading.deviceMode.romon === 'blocked') {
    set('romon', 'skipped', 'romon_denied_by_device_mode', reading.romon,
      `device-mode ${reading.deviceMode.mode ?? '?'} denies RoMON${reading.deviceMode.romonFlag ? ` (romon=${reading.deviceMode.romonFlag})` : ''}`);
  } else set('romon', 'needed', 'to_set', reading.romon, 'RoMON disabled -> enabled');

  const lan = legacyDeriveLan(reading);
  const services: LegacyCompliancePlan['services'] = {};
  for (const svc of LEGACY_LAN_SERVICES) {
    const key = SERVICE_FIX[svc];
    if (reading.services === null) {
      set(key, 'skipped', 'unread', null, '/ip service could not be read');
      continue;
    }
    const rows = reading.services.filter((s) => s.name === svc);
    // Two rows of one name are not a reading (a connection entry the read
    // failed to skip, shared/src/routerOsService.ts): never pick one.
    if (rows.length > 1) {
      set(key, 'skipped', 'unread', null, `${rows.length} rows named ${svc} in /ip service: not one reading`);
      continue;
    }
    const row = rows[0];
    if (!row) {
      set(key, 'skipped', 'service_absent', null, `no service named ${svc}`);
      continue;
    }
    const entries = legacyParseAddressList(row.address);
    if (entries === null) {
      set(key, 'skipped', 'entry_unreadable', row.address, 'an entry of the address list is not an address this job reads exactly');
      continue;
    }
    if (entries.length === 0) {
      set(key, 'present', 'list_empty_open', '', 'empty address list: open to every address, left alone');
      continue;
    }
    if (lan.network === null) {
      set(key, 'skipped', 'lan_unknown', entries.join(','), `LAN network not established: ${lan.detail}`);
      continue;
    }
    if (legacyListCovers(entries, lan.network)) {
      set(key, 'present', 'lan_covered', entries.join(','), `${lan.network} already allowed`);
      continue;
    }
    services[svc] = { before: entries, after: [...entries, lan.network] };
    set(key, 'needed', 'lan_missing', entries.join(','), `${lan.network} added to ${entries.join(',')}`);
  }

  const rosMajor = legacyRouterOsMajor(reading.version);
  let l2tp: LegacyCompliancePlan['l2tp'] = null;
  const clients = reading.l2tpClients;
  const lacking = (clients ?? []).filter((c) => !truthy(c.randomSourcePort));
  if (clients === null) set('l2tp_random_source_port', 'skipped', 'unread', null, '/interface l2tp-client could not be read');
  else if (clients.length === 0) set('l2tp_random_source_port', 'present', 'no_l2tp_client', '', 'no l2tp-client');
  else if (rosMajor === 6) {
    set('l2tp_random_source_port', 'skipped', 'ros6', reading.version, 'RouterOS 6 has no random-source-port');
  } else if (lacking.length === 0) {
    set('l2tp_random_source_port', 'present', 'already_set', clients.map((c) => c.name).join(','), 'random-source-port=yes on every client');
  } else if (lacking.some((c) => !falsy(c.randomSourcePort))) {
    set('l2tp_random_source_port', 'skipped', 'property_absent', reading.version,
      `random-source-port not offered by this RouterOS build (${reading.version ?? 'version unread'})`);
  } else if (lacking.some((c) => !LEGACY_SAFE_NAME_RE.test(c.name))) {
    set('l2tp_random_source_port', 'skipped', 'name_unsafe', null, 'an l2tp-client name holds characters the job does not write');
  } else {
    const change = lacking.map((c) => c.name);
    const watch = lacking.filter((c) => c.running && !c.disabled).map((c) => c.name);
    l2tp = { change, watch };
    set('l2tp_random_source_port', 'needed', 'to_set', change.join(','),
      `random-source-port=yes on ${change.join(', ')}${watch.length > 0 ? ` (restarts ${watch.join(', ')})` : ''}`);
  }

  let dnsAmp: LegacyCompliancePlan['dnsAmp'] = null;
  const amp = reading.dnsAmp;
  const wan = reading.wan;
  if (amp === null || wan === null) {
    set('dns_amp_protection', 'skipped', 'unread', null, 'the WAN list or the DNS-Amp rules could not be read');
  } else if (!wan.exists) {
    set('dns_amp_protection', 'skipped', 'wan_list_absent', null, `no interface list named ${LEGACY_WAN_LIST}: the rules would match nothing`);
  } else {
    const exact = LEGACY_DNS_AMP_PROTOCOLS.map((p) => amp.rules.filter((r) => legacyDnsAmpExact(r, p)));
    const odd = amp.rules.filter((r) => !LEGACY_DNS_AMP_PROTOCOLS.some((p) => legacyDnsAmpExact(r, p)));
    const missing = LEGACY_DNS_AMP_PROTOCOLS.filter((_, i) => exact[i].length === 0);
    const summary = `${amp.rules.length} rule(s) commented "${LEGACY_DNS_AMP_COMMENT}"`;
    if (odd.length > 0 || exact.some((e) => e.length > 1)) {
      set('dns_amp_protection', 'skipped', 'rule_customized', summary,
        `a rule commented "${LEGACY_DNS_AMP_COMMENT}" is not the operator's rule (or appears twice): the router's variant is left alone`);
    } else if (amp.rules.some((r) => r.disabled)) {
      set('dns_amp_protection', 'skipped', 'rule_disabled', summary,
        `a rule commented "${LEGACY_DNS_AMP_COMMENT}" is disabled: left as the router has it`);
    } else if (missing.length === 0) {
      set('dns_amp_protection', 'present', 'already_set', summary, 'udp and tcp 53 from WAN rejected');
    } else if (reading.bridges === null || reading.lanMembers === null) {
      set('dns_amp_protection', 'skipped', 'unread', wan.members.join(','), 'bridges or LAN list members could not be read: the WAN list cannot be judged');
    } else {
      const lanSide = wan.members.filter((m) => reading.bridges!.includes(m) || reading.lanMembers!.includes(m));
      const remote = reading.dnsRemote;
      if (lanSide.length > 0) {
        set('dns_amp_protection', 'skipped', 'wan_list_holds_lan', wan.members.join(','),
          `${lanSide.join(', ')} is in the ${LEGACY_WAN_LIST} list and on the LAN side: the store's own DNS would be refused`);
      } else if (remote === null || reading.ipsecPolicies === null) {
        set('dns_amp_protection', 'skipped', 'dns_ipsec_unread', remote,
          'allow-remote-requests or the IPsec policies could not be read: a DNS query arriving over IPsec is not ruled out, nothing written');
      } else if (truthy(remote) && reading.ipsecPolicies > 0) {
        set('dns_amp_protection', 'skipped', 'dns_over_ipsec', `${reading.ipsecPolicies} IPsec policies`,
          `the router answers DNS and carries ${reading.ipsecPolicies} static IPsec policies: a query from across IPsec arrives on a WAN interface and would be refused, nothing written`);
      } else {
        const warnings: LegacyFixWarning[] = [];
        const tunnels = wan.members.filter((m) => (reading.l2tpClients ?? []).some((c) => c.name === m));
        if (tunnels.length > 0) warnings.push('wan_holds_tunnel');
        if (remote !== null && falsy(remote)) warnings.push('dns_not_served');
        dnsAmp = { missing, top: amp.inputRules > 0 };
        set('dns_amp_protection', 'needed', 'to_set', wan.members.join(','),
          `reject ${missing.join(' and ')} 53 from ${LEGACY_WAN_LIST} (${wan.members.join(', ') || 'no member yet'}), ` +
            `${dnsAmp.top ? 'at the top of the input chain' : 'the input chain being empty'}` +
            `${warnings.length > 0 ? `; to check: ${warnings.join(', ')}` : ''}`,
          warnings);
      }
    }
  }

  // A retired fix first, whatever the job's frozen list says: reported as
  // read, never planned. Then the frozen list: a fix the job was not queued
  // with writes nothing.
  const services2 = { ...services };
  for (const key of LEGACY_FIX_KEYS) {
    if (retired.includes(key)) {
      const { current, detail } = retiredReading(key, reading, fixes[key]?.current ?? null);
      set(key, 'skipped', 'retired', current, detail);
    } else if (requested.includes(key)) {
      continue;
    } else {
      set(key, 'skipped', 'not_requested', fixes[key]?.current ?? null, 'not among the fixes this job was queued with');
    }
    if (key === 'service_ssh') delete services2.ssh;
    if (key === 'service_winbox') delete services2.winbox;
    if (key === 'l2tp_random_source_port') l2tp = null;
    if (key === 'dns_amp_protection') dnsAmp = null;
  }
  return { fixes, lan, services: services2, l2tp, dnsAmp, rosMajor };
}

/** True when nothing is to be written. Not "conforming": a fix skipped as
 *  unobserved (`legacyReasonUnobserved`) writes nothing either. */
export function legacyPlanIsNoop(plan: LegacyCompliancePlan): boolean {
  return LEGACY_FIX_KEYS.every((k) => plan.fixes[k].state !== 'needed');
}

// ============================================================================
// The lines
// ============================================================================

function assertName(field: string, name: string): void {
  if (!LEGACY_SAFE_NAME_RE.test(name)) {
    throw new LegacyComplianceInputError(field, `The ${field} name holds characters outside the job's safe set.`);
  }
}

function assertEntry(entry: string): void {
  if (legacyParseAddressList(entry)?.length !== 1) {
    throw new LegacyComplianceInputError('address', 'An address list entry is not an address or prefix this job writes.');
  }
}

function assertLanNetwork(network: string): void {
  const p = legacyParseIpv4Prefix(network);
  if (!p || !/\//.test(network) || legacyNetworkOf(network) !== network ||
    p.len < LEGACY_LAN_PREFIX_MIN || p.len > LEGACY_LAN_PREFIX_MAX) {
    throw new LegacyComplianceInputError('lan', 'The LAN network is not a network prefix this job writes.');
  }
}

function nameCondition(names: readonly string[]): string {
  return names.map((n) => `name="${n}"`).join(' or ');
}

/**
 * RouterOS double-quoted string literal for the self-revert's source: `\\`,
 * `\"`, `\$`, `\?` escaped (REASONED from the scripting manual, the same four
 * managementAccess.service's `routerOsQuoted` escapes). The source is built
 * from validated names and integers only, so no control character can occur;
 * one is refused rather than written.
 */
function quoted(text: string): string {
  let out = '';
  for (const ch of text) {
    const code = ch.codePointAt(0) as number;
    if (code < 0x20 || code >= 0x7f) throw new LegacyComplianceInputError('script', 'The self-revert holds a character the job does not write.');
    out += ch === '\\' ? '\\\\' : ch === '"' ? '\\"' : ch === '$' ? '\\$' : ch === '?' ? '\\?' : ch;
  }
  return `"${out}"`;
}
/** The same literal, for the other jobs that start a script on the router
 *  (shared/src/wanLink.ts). */
export { quoted as routerOsScriptLiteral };

/** The self-revert's own source (what `:execute` runs). It counts the watched
 *  clients that run, and reverts unless that count is ALL of them: one tunnel
 *  back must not hide another that is not (two clients is a real shape — a
 *  plain management tunnel beside a `use-ipsec=yes` one). A watched client
 *  renamed or removed meanwhile is not found, so it counts as not running. */
export function legacySelfRevertSource(jobId: number, watch: readonly string[], change: readonly string[], afterS: number): string {
  const prefix = legacyGuardLogPrefix(jobId);
  return (
    `:delay ${afterS}s; :local back 0; ` +
    `:foreach i in=[/interface l2tp-client find where ${nameCondition(watch)}] do={ ` +
    ':if ([/interface l2tp-client get $i running]) do={ :set back ($back + 1) } }; ' +
    `:if ($back < ${watch.length}) do={ /interface l2tp-client set [find where ${nameCondition(change)}] random-source-port=no; ` +
    `:log warning "${prefix} ${LEGACY_GUARD_REVERTED} $back of ${watch.length} watched l2tp-client(s) running ${afterS} s after random-source-port=yes" } ` +
    `else={ :log info "${prefix} ${LEGACY_GUARD_STOOD_DOWN} every watched l2tp-client is running again" }`
  );
}

/**
 * The background self-revert, started on the router before the l2tp line
 * (`:execute`, not `/system scheduler`, which device-mode `home` denies), and
 * printing the job id `:execute` returns (`revertjob|<id>`): the l2tp line
 * leaves only once a new session sees that id listed. After `afterS` seconds,
 * unless EVERY watched client — those the l2tp line changes AND that were
 * running before it — is running, it puts random-source-port back to `no`
 * (its value before: the line only changes clients that read `no`) on every
 * client the line changed, and logs its decision either way. Untouched
 * clients are not watched: one that kept running would otherwise hide a
 * tunnel this job broke.
 */
export function legacySelfRevertLine(jobId: number, watch: readonly string[], change: readonly string[], afterS: number): string {
  if (!Number.isInteger(jobId) || jobId <= 0) throw new LegacyComplianceInputError('job', 'Invalid job id.');
  if (!Number.isInteger(afterS) || afterS < 30 || afterS > 600) throw new LegacyComplianceInputError('delay', 'Invalid self-revert delay.');
  if (watch.length === 0 || change.length === 0) throw new LegacyComplianceInputError('l2tp', 'Nothing to watch or to revert.');
  for (const n of [...watch, ...change]) assertName('l2tp-client', n);
  return `:put ("${LEGACY_GUARD_JOB_TAG}|" . [:execute script=${quoted(legacySelfRevertSource(jobId, watch, change, afterS))}])`;
}

/**
 * The DNS-Amp fix as ONE command: each missing rule's statement, `; `-joined.
 * At the top, the rules are added in reverse so the chain ends up holding udp
 * then tcp (each `place-before` the chain's current first rule); with an empty
 * input chain they are appended in order.
 */
export function legacyDnsAmpLine(missing: readonly LegacyDnsAmpProtocol[], top: boolean): string {
  const set = LEGACY_DNS_AMP_PROTOCOLS.filter((p) => missing.includes(p));
  if (set.length === 0 || set.length !== missing.length) throw new LegacyComplianceInputError('dns', 'No DNS-Amp rule planned, or one planned twice.');
  return (top ? [...set].reverse() : set).map((p) => legacyDnsAmpStatement(p, top)).join('; ');
}

export interface LegacyComplianceLines {
  /** Fixes a–e, one command each, in send order. */
  pre: Array<{ fix: LegacyFixKey; line: string }>;
  /** The self-revert, or null when no watched client exists. */
  guard: string | null;
  /** The l2tp line, or null. ALWAYS sent last. */
  cut: string | null;
}

/** The lines for a plan. Every value carried is validated first. */
export function legacyComplianceLines(plan: LegacyCompliancePlan, jobId: number, revertAfterS: number): LegacyComplianceLines {
  const pre: LegacyComplianceLines['pre'] = [];
  const needed = (k: LegacyFixKey) => plan.fixes[k].state === 'needed';
  if (needed('mac_server')) pre.push({ fix: 'mac_server', line: '/tool mac-server set allowed-interface-list=all' });
  if (needed('mac_winbox')) pre.push({ fix: 'mac_winbox', line: '/tool mac-server mac-winbox set allowed-interface-list=all' });
  if (needed('romon')) pre.push({ fix: 'romon', line: '/tool romon set enabled=yes' });
  if (needed('dns_amp_protection')) {
    if (!plan.dnsAmp) throw new LegacyComplianceInputError('dns', 'No DNS-Amp rule planned.');
    pre.push({ fix: 'dns_amp_protection', line: legacyDnsAmpLine(plan.dnsAmp.missing, plan.dnsAmp.top) });
  }
  // winbox before ssh: the ssh service is the one the job's own session
  // rides, so its line is the last of a–e — legacyCompliance.service.ts
  // sends the l2tp pair on a fresh session when exactly that line lost it.
  for (const svc of ['winbox', 'ssh'] as const) {
    if (!needed(SERVICE_FIX[svc])) continue;
    const s = plan.services[svc];
    if (!s || plan.lan.network === null) throw new LegacyComplianceInputError('service', `No address list planned for ${svc}.`);
    assertLanNetwork(plan.lan.network);
    s.after.forEach(assertEntry);
    // The configured row only: the job's own SSH session is a dynamic entry
    // named ssh (header, service_ssh).
    pre.push({ fix: SERVICE_FIX[svc], line: routerOsServiceSet(svc, `address=${s.after.join(',')}`) });
  }
  let guard: string | null = null;
  let cut: string | null = null;
  if (needed('l2tp_random_source_port')) {
    if (!plan.l2tp || plan.l2tp.change.length === 0) throw new LegacyComplianceInputError('l2tp', 'No l2tp-client planned.');
    plan.l2tp.change.forEach((n) => assertName('l2tp-client', n));
    if (plan.l2tp.watch.length > 0) guard = legacySelfRevertLine(jobId, plan.l2tp.watch, plan.l2tp.change, revertAfterS);
    cut = `/interface l2tp-client set [find where ${nameCondition(plan.l2tp.change)}] random-source-port=yes`;
  }
  return { pre, guard, cut };
}

/** An allow-list refusal: names what was refused. */
export class LegacyComplianceLineRefused extends Error {
  constructor(readonly offending: string[]) {
    super(`Refused line(s) outside the legacy compliance allow-list: ${offending.join(' | ').slice(0, 400)}`);
    this.name = 'LegacyComplianceLineRefused';
  }
}

/**
 * The allow-list, spelled independently of the builder: each line must be
 * EXACTLY one of the statements for THIS plan — the two mac-server
 * lines, the RoMON line, the DNS-Amp adds of exactly the missing protocols
 * (chained statements, all of them that same rule), a service line — the
 * fixed selection of that service's configured row, then one `set` on it —
 * whose list is the list read plus the LAN network (nothing removed, nothing
 * else added) for a service whose fix is needed, the
 * self-revert for the planned clients, the l2tp line for exactly the planned
 * clients — and the l2tp line, when present, must be the LAST and the
 * self-revert, when present, immediately before it. No other menu, no second
 * property, no other chained command. Every statement is admitted only for a
 * fix the plan says is `needed`, so a retired fix (skipped, `retired`) admits
 * neither the l2tp line nor its self-revert. Throws `LegacyComplianceLineRefused`.
 */
export function assertLegacyComplianceOnlyLines(lines: readonly string[], plan: LegacyCompliancePlan, jobId: number, revertAfterS: number): void {
  const allowed = new Map<string, string>();
  const needed = (k: LegacyFixKey) => plan.fixes[k].state === 'needed';
  if (needed('mac_server')) allowed.set('/tool mac-server set allowed-interface-list=all', 'a');
  if (needed('mac_winbox')) allowed.set('/tool mac-server mac-winbox set allowed-interface-list=all', 'b');
  if (needed('romon')) allowed.set('/tool romon set enabled=yes', 'c');
  // The DNS-Amp adds, spelled here again with literals: exactly the missing
  // protocols, each once, nothing but the operator's rule and its placement.
  const amp = plan.dnsAmp;
  if (needed('dns_amp_protection') && amp && amp.missing.length > 0 &&
    amp.missing.every((p) => p === 'udp' || p === 'tcp') && new Set(amp.missing).size === amp.missing.length) {
    const want = (['udp', 'tcp'] as const).filter((p) => amp.missing.includes(p));
    const statement = (p: string): string =>
      `/ip firewall filter add action=reject chain=input comment="DNS-Amp Protection" dst-port=53 in-interface-list=WAN ` +
      `protocol=${p} reject-with=icmp-host-unreachable${amp.top ? ' place-before=[:pick [find where chain=input] 0]' : ''}`;
    allowed.set((amp.top ? [...want].reverse() : want).map(statement).join('; '), 'dns');
  }
  for (const svc of LEGACY_LAN_SERVICES) {
    const s = plan.services[svc];
    const lanNet = plan.lan.network;
    if (!needed(SERVICE_FIX[svc]) || !s || lanNet === null) continue;
    const exact = s.before.length + 1 === s.after.length &&
      s.before.every((e, i) => s.after[i] === e) && s.after[s.after.length - 1] === lanNet;
    if (!exact) continue;
    try {
      assertLanNetwork(lanNet);
      s.after.forEach(assertEntry);
    } catch {
      continue;
    }
    // Spelled with literals, like every other statement here: the configured
    // row of THIS service (a connection entry skipped), then the one write.
    allowed.set(
      `:do { :local obliwanSvc ""; :foreach r in=[/ip service find where name="${svc}"] do={ ` +
        ':do { :if ([:tostr [/ip service get $r dynamic]] != "true") do={ :set obliwanSvc $r } } on-error={ :set obliwanSvc $r } }; ' +
        `/ip service set $obliwanSvc address=${s.after.join(',')} }`,
      'd',
    );
  }
  let guardLine: string | null = null;
  let cutLine: string | null = null;
  if (needed('l2tp_random_source_port') && plan.l2tp && plan.l2tp.change.length > 0 &&
    plan.l2tp.change.every((n) => LEGACY_SAFE_NAME_RE.test(n))) {
    cutLine = `/interface l2tp-client set [find where ${plan.l2tp.change.map((n) => `name="${n}"`).join(' or ')}] random-source-port=yes`;
    allowed.set(cutLine, 'e');
    if (plan.l2tp.watch.length > 0 && plan.l2tp.watch.every((n) => plan.l2tp!.change.includes(n))) {
      try {
        guardLine = legacySelfRevertLine(jobId, plan.l2tp.watch, plan.l2tp.change, revertAfterS);
        allowed.set(guardLine, 'guard');
      } catch {
        guardLine = null;
      }
    }
  }
  const offending = lines.filter((l) => !allowed.has(l));
  if (new Set(lines).size !== lines.length) offending.push('(a line sent twice)');
  const cutAt = cutLine === null ? -1 : lines.indexOf(cutLine);
  if (cutAt >= 0 && cutAt !== lines.length - 1) offending.push('(the l2tp line is not the last)');
  if (cutAt >= 0 && plan.l2tp && plan.l2tp.watch.length > 0 && (guardLine === null || lines[cutAt - 1] !== guardLine)) {
    offending.push('(the l2tp line is not immediately preceded by its self-revert)');
  }
  const guardAt = guardLine === null ? -1 : lines.indexOf(guardLine);
  if (guardAt >= 0 && cutAt !== guardAt + 1) offending.push('(a self-revert with no l2tp line after it)');
  if (offending.length > 0 || lines.length === 0) {
    throw new LegacyComplianceLineRefused(offending.length > 0 ? offending : ['(no line)']);
  }
}

// ============================================================================
// The expected state, read back
// ============================================================================

/**
 * Whether ONE fix holds on a reading: true, false, or null when the reading
 * does not say. For a service the list must also still hold every entry the
 * plan read before (nothing is ever removed); for the l2tp fix every client
 * the plan changed must read `yes`.
 */
export function legacyFixHolds(key: LegacyFixKey, reading: LegacyComplianceReading, plan: LegacyCompliancePlan): boolean | null {
  switch (key) {
    case 'mac_server':
      return reading.macServer === null ? null : reading.macServer.trim() === 'all';
    case 'mac_winbox':
      return reading.macWinbox === null ? null : reading.macWinbox.trim() === 'all';
    case 'romon':
      return reading.romon === null ? null : truthy(reading.romon);
    case 'service_ssh':
    case 'service_winbox': {
      const svc: LegacyLanService = key === 'service_ssh' ? 'ssh' : 'winbox';
      if (reading.services === null) return null;
      const rows = reading.services.filter((s) => s.name === svc);
      if (rows.length !== 1) return null;
      const row = rows[0];
      const entries = legacyParseAddressList(row.address);
      if (entries === null) return null;
      const before = plan.services[svc]?.before ?? [];
      if (!before.every((e) => entries.includes(e))) return false;
      if (entries.length === 0) return before.length === 0;
      return plan.lan.network !== null && legacyListCovers(entries, plan.lan.network);
    }
    case 'dns_amp_protection': {
      // Presence, not position: one enabled operator's rule per protocol.
      if (reading.dnsAmp === null) return null;
      return LEGACY_DNS_AMP_PROTOCOLS.every((p) => reading.dnsAmp!.rules.some((r) => legacyDnsAmpExact(r, p) && !r.disabled));
    }
    case 'l2tp_random_source_port': {
      if (reading.l2tpClients === null) return null;
      const names = plan.l2tp?.change ?? reading.l2tpClients.map((c) => c.name);
      return names.every((n) => {
        const c = reading.l2tpClients!.find((x) => x.name === n);
        return c !== undefined && truthy(c.randomSourcePort);
      });
    }
  }
}

/**
 * The l2tp line's second expectation, beside the property: every client the
 * self-revert watched (changed AND running before the line) runs on the
 * read-back. The names that do not (a client no longer listed counts), `[]`
 * when all run or none was watched, null when the clients were not read.
 */
export function legacyWatchedNotRunning(reading: LegacyComplianceReading, plan: LegacyCompliancePlan): string[] | null {
  const watch = plan.l2tp?.watch ?? [];
  if (watch.length === 0) return [];
  if (reading.l2tpClients === null) return null;
  return watch.filter((n) => !reading.l2tpClients!.some((c) => c.name === n && c.running));
}

/** What happened to one fix, as the job records it at the end. */
export const LEGACY_FIX_OUTCOMES = [
  'present',     // held before, nothing sent, still holds
  'applied',     // sent, accepted, holds on the read-back
  'skipped',     // a named reason the design accepts; nothing sent
  'refused',     // the router refused the line (its words are kept)
  'reverted',    // l2tp: the self-revert put it back
  'tunnel_down', // l2tp: holds, but a client running before the line is not running on the read-back
  'not_applied', // sent (or held before) and does not hold on the read-back
  'not_sent',    // needed, never sent (session lost first, self-revert refused or not seen alive)
  'unverified',  // the read-back did not say, or the fix's state was never observed
] as const;
export type LegacyFixOutcome = (typeof LEGACY_FIX_OUTCOMES)[number];

/** RoMON's refusal is device-mode's to make: recorded, never a failure. */
export function legacyOutcomeFails(key: LegacyFixKey, outcome: LegacyFixOutcome): boolean {
  if (outcome === 'present' || outcome === 'applied' || outcome === 'skipped') return false;
  if (key === 'romon' && outcome === 'refused') return false;
  return true;
}
