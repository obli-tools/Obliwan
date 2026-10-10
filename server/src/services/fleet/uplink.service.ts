/**
 * ObliWAN — "which uplink is this site ACTUALLY running on right now?"
 *
 * ┌─ THE CONFIG CANNOT ANSWER THIS, AND THAT IS THE WHOLE POINT ─────────────┐
 * │ A router can have a perfect default route through ether1 / PPPoE and be  │
 * │ passing every byte over LTE, because the PPPoE session dropped and a     │
 * │ higher-distance route took over exactly as it was designed to. The       │
 * │ failover WORKED. Nothing is broken. And nobody knows — which is the      │
 * │ expensive part, because the customer is on a metered SIM at backup speed │
 * │ and the ticket arrives at the end of the month.                          │
 * │                                                                          │
 * │ So this reports TWO answers and never merges them:                       │
 * │                                                                          │
 * │   CONFIGURED  what the routing says should carry traffic: the snapshot   │
 * │               default route (INTENT), else the router's ACTIVE default   │
 * │               route as last read (a FACT, with its age).                 │
 * │   OBSERVED    the interface that is actually moving bytes — fact.        │
 * │                                                                          │
 * │ THE FAILOVER SIGNAL IS `onBackup`, NOT A DISAGREEMENT. It is true when   │
 * │ the busiest carrying link is cellular, whatever CONFIGURED came          │
 * │ from. What agreement and disagreement mean depends on that source:       │
 * │                                                                          │
 * │   snapshot  intent against fact. Traffic on LTE while the intent names   │
 * │             the primary is the failover the configuration does not say.  │
 * │   live      fact against fact. After a failover the router's own table   │
 * │             names the backup, so AGREEMENT ON A CELLULAR LINK IS THE     │
 * │             FAILOVER, seen from both sides. A disagreement is policy     │
 * │             routing, or a table that changed since it was read.          │
 * │                                                                          │
 * │ "They agree, nothing to say" holds only for agreement on a primary-class │
 * │ link. Collapsing the two into one "status" would destroy the signal      │
 * │ worth having: which link the bytes take, against what was meant or read. │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ── WHY BYTES AND NOT `ifOperStatus` ────────────────────────────────────────
 * An LTE interface is usually UP all the time: the modem is registered, the
 * interface is up, and it carries nothing until the day it carries everything.
 * `operStatus` would report both uplinks up and answer nothing. Traffic is the
 * only signal that distinguishes a standby link from a working one — which is
 * also why this needs two samples and says so rather than showing a zero.
 *
 * ── WHAT "ROUTING SAYS" IS, AND WHERE IT COMES FROM ─────────────────────────
 * The latest snapshot's lowest-distance default route when its gateway names
 * an interface (INTENT); otherwise the default route the router's table has
 * ACTIVE, as the health check last read it (migration 073), with its age and
 * `configuredSource: 'live'`. On this fleet the snapshot rarely answers —
 * WAN1's route has an IP gateway written by the DHCP client's script and the
 * LTE route is dynamic, absent from any export — so without the live reading
 * the card was empty on every router.
 *
 * When there is no live reading, `liveRouteStatus` says WHY: not yet, or
 * never on this device as it stands (no RouterOS API channel, not a RouterOS
 * router, a concentrator, no identity on record). "Not read yet" on a device
 * nothing will ever read is a promise the platform does not keep.
 *
 * Tunnels (`l2tp-mgmt`, `l2tp-infra`, …) are reported apart and are never
 * uplinks. The pure half — classification, the route parser, the sentences —
 * is `uplinkModel.ts`, pinned by `testing/uplink.verify.ts`.
 */

import { db } from '../../db';
import { latestDocument } from '../config/snapshot.service';
import { deviceEgress, type AsnInfo } from './asn.service';
import { declaredUplinkOf } from './backup4g.service';
import { routerOsApiChannelUsable } from './healthCheck.service';
import {
  IDLE_BPS,
  isLiveStale,
  judgeTraffic,
  liveRouteStatus,
  partitionInterfaces,
  routingAnswer,
  snapshotDefaultIface,
  type LiveRouteReading,
  type LiveRouteStatus,
  type TunnelRole,
  type UplinkKind,
} from './uplinkModel';
import type { SiteUplinkKind } from '@obliwan/shared';

export type { LiveRouteStatus, TunnelRole, UplinkKind } from './uplinkModel';

/** How far back to look. Long enough to survive one missed poll, short enough
 *  that "right now" means right now. */
const WINDOW_MINUTES = 15;

export interface UplinkCandidate {
  ifId: number;
  ifName: string;
  alias: string | null;
  kind: UplinkKind;
  /** IF-MIB ifOperStatus. 1 = up. */
  operStatus: number;
  /** Mean over the window. `null` = not enough samples to derive a rate. */
  inBps: number | null;
  outBps: number | null;
  samples: number;
  /** `null` when no rate could be derived — NOT `false`. */
  carrying: boolean | null;
}

/** A tunnel interface: shown, measured, and never an uplink — its bytes
 *  already cross one. */
export interface UplinkTunnel {
  ifId: number;
  ifName: string;
  alias: string | null;
  role: TunnelRole;
  operStatus: number;
  inBps: number | null;
  outBps: number | null;
  samples: number;
}

/** The router's active default route as the health check last read it. */
export interface UplinkLiveRoute {
  /** null = the interface could not be told (see `readActiveDefaultRoute`). */
  iface: string | null;
  /** null = the main table had NO active default route at that instant. */
  gateway: string | null;
  observedAt: string;
  /** Older than 24 h: shown as stale, never as current. */
  stale: boolean;
}

export interface UplinkVerdict {
  deviceId: number;
  /** What the routing says should carry traffic. */
  configured: string | null;
  /** Where `configured` comes from: the configuration (intent), or the
   *  router's active route (a fact as of `configuredAt`). Null = neither
   *  answered. */
  configuredSource: 'snapshot' | 'live' | null;
  /** When that answer was read (ISO). */
  configuredAt: string | null;
  /** True only for a live answer older than 24 h. */
  configuredStale: boolean;
  /** The live reading itself, whatever `configured` came from — it is what
   *  shows a failover from the routing side. Null = never read. */
  liveRoute: UplinkLiveRoute | null;
  /** Why `liveRoute` is null when it is — `not_yet` only when the health
   *  check will actually read it (see `LiveRouteStatus`). */
  liveRouteStatus: LiveRouteStatus;
  /** What the counters say IS carrying traffic. */
  observed: string | null;
  /**
   * True when the busiest carrying link is cellular. `null` = not enough
   * evidence. THE failover signal — not a disagreement between `configured`
   * and `observed`, which on a live answer AGREE during a failover (both name
   * the SIM). A TRAFFIC verdict: the routing answer shapes the sentence and
   * never this flag.
   */
  onBackup: boolean | null;
  /**
   * The site's declared access link (migration 076); null = not declared.
   * 'cellular_only': traffic on the cellular link is the site's NOMINAL path
   * — the sentence says so and the card draws it as nominal, while
   * `onBackup` stays the traffic flag (the bytes ARE on a metered link).
   */
  declaredUplink: SiteUplinkKind | null;
  /** One sentence an operator can act on, or ignore. */
  reason: string;
  candidates: UplinkCandidate[];
  tunnels: UplinkTunnel[];
  windowMinutes: number;
  /** The public address the CONCENTRATOR saw this site dial in from, and who
   *  announces it — the outside view, see `asn.service`. Both null when the
   *  device has no tunnel or the lookup is disabled. */
  publicIp: string | null;
  /** ppp_caller = seen by the concentrator when the site dialled in (strong).
   *  dial_address = the address WE reach it on (weaker: a port forward can
   *  publish a box on an address its own traffic does not leave by). */
  publicIpSource: 'ppp_caller' | 'dial_address' | null;
  asn: AsnInfo | null;
  asnLookupEnabled: boolean;
}

/**
 * The configured default route's outgoing interface, from the latest snapshot
 * (`snapshotDefaultIface`: main table, lowest distance, interface gateways
 * only), with the instant that configuration was last seen. This is INTENT
 * and is reported as such — it is exactly the value that can be wrong while
 * everything else is right.
 */
async function configuredUplink(deviceId: number): Promise<{ iface: string; at: Date | null } | null> {
  const row = await latestDocument(deviceId).catch(() => null);
  if (!row) return null;
  const iface = snapshotDefaultIface(row.doc.resources.routes);
  if (iface === null) return null;

  const seen = await db('config_snapshots')
    .where({ id: row.id })
    .first<{ last_seen_at: Date | null } | undefined>('last_seen_at')
    .catch(() => undefined);
  return { iface, at: seen?.last_seen_at ? new Date(seen.last_seen_at) : null };
}

/** Mean rates of one interface over the window. One sample is a counter, not
 *  a rate: `null`, never 0. */
async function windowRate(
  ifId: number,
): Promise<{ n: number; inBps: number | null; outBps: number | null }> {
  const agg = (await db('snmp_if_samples')
    .where({ if_id: ifId })
    .where('ts', '>', db.raw(`now() - interval '${WINDOW_MINUTES} minutes'`))
    .select(
      db.raw('count(*)::int as n'),
      db.raw('avg(in_bps)::bigint as avg_in'),
      db.raw('avg(out_bps)::bigint as avg_out'),
    )
    .first()) as { n: number; avg_in: string | null; avg_out: string | null } | undefined;
  const n = agg?.n ?? 0;
  return {
    n,
    inBps: n > 0 && agg?.avg_in != null ? Number(agg.avg_in) : null,
    outBps: n > 0 && agg?.avg_out != null ? Number(agg.avg_out) : null,
  };
}

/**
 * Which uplink is carrying traffic, and what the routing says should be.
 *
 * Returns `observed: null` rather than guessing when no candidate has two
 * samples: a rate is a derivative, and the first point of a series cannot
 * produce one. Saying "no traffic" on a link nobody has measured twice yet is
 * how a healthy site is reported as down on the day it is enrolled.
 */
export async function assessUplink(
  tenantId: number,
  deviceId: number,
): Promise<UplinkVerdict | null> {
  const device = (await db('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first(
      'id', 'brand', 'role', 'status', 'system_identity', 'tunnel_ip', 'site_id',
      'default_route_iface', 'default_route_gateway', 'default_route_observed_at',
    )) as
    | {
        id: number;
        brand: string;
        role: string;
        status: string | null;
        system_identity: string | null;
        tunnel_ip: string | null;
        site_id: number | null;
        default_route_iface: string | null;
        default_route_gateway: string | null;
        default_route_observed_at: Date | null;
      }
    | undefined;
  if (!device) return null;
  const now = new Date();

  // The same row the health check would dial (`pickChannel`: enabled, lowest
  // priority first), judged by the same rule.
  const api = (await db('device_transports')
    .where({ device_id: deviceId, transport: 'routeros_api', enabled: true })
    .orderBy('priority')
    .first('host', 'username', 'secret_enc')) as
    | { host: string | null; username: string | null; secret_enc: string | null }
    | undefined;
  const status = liveRouteStatus({
    observed: device.default_route_observed_at !== null,
    brand: device.brand,
    role: device.role,
    apiChannel: !!api && routerOsApiChannelUsable(api, device.tunnel_ip),
    systemIdentity: device.system_identity,
    status: device.status,
  });

  const interfaces = await db('snmp_interfaces')
    .where({ device_id: deviceId, state: 'active' })
    .select<Array<{
      id: number; if_name: string; if_alias: string | null;
      if_type: number | null; oper_status: number;
    }>>('id', 'if_name', 'if_alias', 'if_type', 'oper_status');

  const candidates: UplinkCandidate[] = [];
  const tunnels: UplinkTunnel[] = [];
  const split = partitionInterfaces(interfaces);
  for (const { row: i, role } of split.tunnels) {
    const r = await windowRate(i.id);
    tunnels.push({
      ifId: i.id,
      ifName: i.if_name,
      alias: i.if_alias,
      role,
      operStatus: i.oper_status,
      inBps: r.inBps,
      outBps: r.outBps,
      samples: r.n,
    });
  }
  for (const { row: i, kind } of split.candidates) {
    const r = await windowRate(i.id);
    candidates.push({
      ifId: i.id,
      ifName: i.if_name,
      alias: i.if_alias,
      kind,
      operStatus: i.oper_status,
      inBps: r.inBps,
      outBps: r.outBps,
      samples: r.n,
      carrying: r.inBps === null || r.outBps === null
        ? null
        : Math.max(r.inBps, r.outBps) >= IDLE_BPS,
    });
  }

  const live: LiveRouteReading | null = device.default_route_observed_at
    ? {
        iface: device.default_route_iface,
        gateway: device.default_route_gateway,
        observedAt: new Date(device.default_route_observed_at),
      }
    : null;
  const routing = routingAnswer(await configuredUplink(deviceId), live, now);
  const declared = await declaredUplinkOf(tenantId, device.site_id);
  const { observed, onBackup, reason } = judgeTraffic({ candidates, routing, live, liveStatus: status, now, declared });

  // The egress half is decoration: it asks a third party, and the verdict is
  // complete without it. It may never take the answer down with it.
  const egress = await deviceEgress(tenantId, deviceId).catch(() => ({
    publicIp: null, source: null as null, asn: null, lookupEnabled: false,
  }));

  return {
    deviceId,
    configured: routing.iface,
    configuredSource: routing.source,
    configuredAt: routing.at ? routing.at.toISOString() : null,
    configuredStale: routing.stale,
    liveRoute: live
      ? {
          iface: live.iface,
          gateway: live.gateway,
          observedAt: live.observedAt.toISOString(),
          stale: isLiveStale(live, now),
        }
      : null,
    liveRouteStatus: status,
    observed,
    publicIp: egress.publicIp,
    publicIpSource: egress.source,
    asn: egress.asn,
    asnLookupEnabled: egress.lookupEnabled,
    onBackup,
    declaredUplink: declared,
    reason,
    candidates: candidates.sort((a, b) => a.ifName.localeCompare(b.ifName)),
    tunnels: tunnels.sort((a, b) => a.ifName.localeCompare(b.ifName)),
    windowMinutes: WINDOW_MINUTES,
  };
}
