// ============================================================================
// Learning mode — the site's learned facts, from one capture
// ============================================================================
//
// PURE. A redacted learning copy in, the facts an operator needs to see the
// fleet as it runs (WAN1 by DHCP, PPPoE or a fixed address; the PPPoE client's
// name — ADSL, FTTH, FTTO; the LAN; the time zone; the APN; the default routes
// and the netwatch probes that fail them over…) out.
//
// It reads through `parseRouterOsExport` (the extrapolator's view of an
// export), whose funnel drops every sensitive value on the spot: a fact can
// never carry a secret, placeholder or not. The LAN is judged by the infra
// analysis's own `judgeLan`, fed from the export instead of a live read.

import {
  LEARNED_FACTS_ARRAY_CAP,
  type LearnedSiteFacts,
} from '@obliwan/shared';
import {
  parseRouterOsExport,
  propValue,
  type ExportEntry,
} from '../baseline/extrapolator/exportText';
import { classifyWan1 } from '../baseline/extrapolator/wan1';
import { judgeLan, type MenuReading, type PropReading } from '../infraAnalysis/probes';
import { PPPOE_UPLINK_NAMES } from '../plan/uplinkGuard';

const CAP = LEARNED_FACTS_ARRAY_CAP;

function cap<T>(list: T[]): T[] {
  return list.slice(0, CAP);
}

function truthy(v: string | undefined): boolean {
  return v === 'yes' || v === 'true';
}

function splitList(v: string | undefined): string[] {
  if (!v) return [];
  return v.split(',').map((s) => s.trim()).filter((s) => s !== '');
}

/**
 * The entries of one menu as the `MenuReading` the infra-analysis judges read:
 * every entry an item, `yes`/`no` read as `true`/`false`, an absent `disabled`
 * read as `false` (an export omits a default).
 */
export function menuReadingFromEntries(
  entries: readonly ExportEntry[],
  path: string,
  props: readonly string[],
): MenuReading {
  const reading: MenuReading = { ended: true, garbled: false, order: [], items: new Map() };
  let n = 0;
  for (const e of entries) {
    if (e.path !== path || e.verb === 'opaque' || e.verb === 'remove') continue;
    const id = `*${++n}`;
    const item = new Map<string, PropReading>();
    for (const prop of props) {
      let v = propValue(e, prop);
      if (v === 'yes') v = 'true';
      else if (v === 'no') v = 'false';
      if (v === undefined && prop === 'disabled') v = 'false';
      if (v !== undefined) item.set(prop, { ok: true, value: v });
    }
    reading.order.push(id);
    reading.items.set(id, item);
  }
  return reading;
}

/** The facts of one learning copy. Never throws on a strange export: what it
 *  cannot read is `none` / null / empty. */
export function learnedSiteFacts(text: string): LearnedSiteFacts {
  const parsed = parseRouterOsExport(text);
  const entries = parsed.entries;
  const of = (path: string, verb?: string): ExportEntry[] =>
    entries.filter((e) => e.path === path && e.verb !== 'opaque' && (verb === undefined || e.verb === verb));
  const firstSet = (path: string): ExportEntry | undefined => of(path, 'set')[0];

  // ── Identity ────────────────────────────────────────────────────────────
  const identity = firstSet('/system/identity') ? propValue(firstSet('/system/identity')!, 'name') ?? null : null;

  // ── WAN1: the port, then what runs on it ────────────────────────────────
  // One classifier for the learning facts and the extrapolator's WAN1 block
  // (baseline/extrapolator/wan1.ts): the port named for default-name=ether1,
  // the VLANs carried on it, then PPPoE / DHCP / a fixed address.
  const wan1 = classifyWan1(entries);
  const { port, mode, pppoeName, staticAddress, staticGateway, defaults } = wan1;
  const wanList = cap(wan1.wanList);
  const pppoeAll = wan1.pppoeAll.map((e) => {
    const name = propValue(e, 'name') ?? '';
    return {
      name,
      interface: propValue(e, 'interface') ?? null,
      disabled: truthy(propValue(e, 'disabled')),
      uplinkName: PPPOE_UPLINK_NAMES.find((u) => u.toLowerCase() === name.toLowerCase()) ?? null,
      inWanList: wanList.includes(name),
    };
  });

  // ── LAN, through the infra analysis's own judge ─────────────────────────
  const lan = judgeLan(
    {
      address: menuReadingFromEntries(entries, '/ip/address', ['address', 'interface', 'disabled']),
      bridge: menuReadingFromEntries(entries, '/interface/bridge', ['name']),
      member: menuReadingFromEntries(entries, '/interface/list/member', ['interface', 'list']),
    },
    null,
  );

  // ── Time ────────────────────────────────────────────────────────────────
  const clock = firstSet('/system/clock');
  const timezone = clock ? propValue(clock, 'time-zone-name') ?? null : null;
  const ntpClient = firstSet('/system/ntp/client');
  const ntpServers = cap([
    ...splitList(ntpClient ? propValue(ntpClient, 'servers') : undefined),
    ...splitList(ntpClient ? propValue(ntpClient, 'server-dns-names') : undefined),
    ...of('/system/ntp/client/servers', 'add').map((e) => propValue(e, 'address')).filter((a): a is string => !!a),
  ]);

  // ── LTE ─────────────────────────────────────────────────────────────────
  const lteIfaces: string[] = [];
  const selected: string[] = [];
  for (const e of [...of('/interface/lte', 'set'), ...of('/interface/lte', 'add')]) {
    const name = propValue(e, 'name')
      ?? (/(^| )default-name=([^ ]+)/.exec(e.selectorCanon)?.[2])
      ?? (e.positional[0] ?? null);
    if (name && !lteIfaces.includes(name)) lteIfaces.push(name);
    for (const p of splitList(propValue(e, 'apn-profiles'))) if (!selected.includes(p)) selected.push(p);
  }
  const apnProfiles = [
    ...of('/interface/lte/apn', 'set').map((e) => ({
      name: propValue(e, 'name') ?? (/(^| )default=yes( |$)/.test(e.selectorCanon) ? 'default' : (e.positional[0] ?? 'default')),
      apn: propValue(e, 'apn') ?? null,
    })),
    ...of('/interface/lte/apn', 'add').map((e) => ({ name: propValue(e, 'name') ?? '', apn: propValue(e, 'apn') ?? null })),
  ];

  // ── DNS ─────────────────────────────────────────────────────────────────
  const dns = firstSet('/ip/dns');

  return {
    factsVersion: 1,
    identity,
    osVersion: parsed.osVersion,
    model: parsed.model,
    wan1: { port, mode, pppoeName, staticAddress, staticGateway },
    pppoeClients: cap(pppoeAll),
    wanList,
    lan: {
      status: lan.status,
      interface: lan.interface,
      lan: lan.lan,
      routerIp: lan.routerIp,
      candidates: lan.candidates.slice(0, CAP),
    },
    timezone,
    lte: { interfaces: cap(lteIfaces), apnProfiles: cap(apnProfiles), selectedProfiles: cap(selected) },
    defaultRoutes: cap(defaults.map((r) => ({
      gateway: propValue(r, 'gateway') ?? null,
      distance: propValue(r, 'distance') ?? null,
      comment: propValue(r, 'comment') ?? null,
      disabled: truthy(propValue(r, 'disabled')),
    }))),
    netwatch: cap(of('/tool/netwatch', 'add').map((e) => ({
      host: propValue(e, 'host') ?? null,
      comment: propValue(e, 'comment') ?? null,
      disabled: truthy(propValue(e, 'disabled')),
    }))),
    l2tpClients: cap(of('/interface/l2tp-client', 'add').map((e) => ({
      name: propValue(e, 'name') ?? '',
      connectTo: propValue(e, 'connect-to') ?? null,
      disabled: truthy(propValue(e, 'disabled')),
    }))),
    ipsecPeers: cap(of('/ip/ipsec/peer', 'add').map((e) => ({
      name: propValue(e, 'name') ?? null,
      address: propValue(e, 'address') ?? null,
    }))),
    dnsServers: cap(splitList(dns ? propValue(dns, 'servers') : undefined)),
    ntpServers,
    scripts: cap(of('/system/script', 'add').map((e) => propValue(e, 'name')).filter((n): n is string => !!n)),
    schedulers: cap(of('/system/scheduler', 'add').map((e) => propValue(e, 'name')).filter((n): n is string => !!n)),
    counts: {
      lines: entries.length,
      filter: of('/ip/firewall/filter', 'add').length,
      nat: of('/ip/firewall/nat', 'add').length,
      mangle: of('/ip/firewall/mangle', 'add').length,
      addressList: of('/ip/firewall/address-list', 'add').length,
    },
  };
}
