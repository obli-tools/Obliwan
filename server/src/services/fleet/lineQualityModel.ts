/**
 * ObliWAN — the PURE half of the line quality watch. `lineQuality.service.ts`
 * reads the router and the database; everything that DECIDES lives here, with
 * no database and no socket, so the harness pins it on this fleet's names.
 *
 * ┌─ HOW A PING IS FORCED THROUGH THE FIXED LINE — the templates' own routing ┐
 * │ (shared/src/wanLink.ts, the standard WAN1 block of every customer        │
 * │ template):                                                                │
 * │  pppoe   a pppoe-client ADSL|FTTH|FTTO on ether1-WAN1, add-default-route │
 * │          =yes; the NW-WAN1 / WAN1-GW routes and the WAN1 netwatch        │
 * │          disabled. `/ping … interface=<client>` leaves by the PPP link   │
 * │          itself — FORCED (`interface`). The wan_link job's own "is the   │
 * │          new link up" ping is written the same way.                     │
 * │  dhcp /  the routes NW-WAN1 (the netwatch probe host /32) and WAN1-GW    │
 * │  static  (0.0.0.0/0) through the WAN1 gateway; the netwatch fails WAN1-GW │
 * │          over to the LTE and leaves NW-WAN1 alone. A ping to the PROBE    │
 * │          HOST therefore follows NW-WAN1 while that route is active       │
 * │          through a fixed interface — FORCED (`probe_route`). Any other   │
 * │          target follows the main table's default route, and no ping      │
 * │          parameter forces it: `interface=ether1-WAN1` on an Ethernet port │
 * │          makes RouterOS ARP for the target itself, and there is no WAN1  │
 * │          routing table to name. So it is measured only when the active   │
 * │          default route names a FIXED interface both before and after the │
 * │          ping (`default_route`), and the carrier is recorded either way: │
 * │          a 4G-carried figure is filed as `cellular`, never as the line's. │
 * │ A ping is never sent to "measure" a link the router could not name.      │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * REASONED, NOT OBSERVED (no line of this file has met a real router): the
 * `/ping` API reply shape (one `!re` per packet: `seq`, `time` or `status`,
 * cumulative `sent` / `received`), RouterOS 7's `12ms345us` durations, the
 * `link-downs` property of `/interface`, and `interface=` on a PPPoE client.
 * A field read under another name is UNKNOWN, never a zero: a ping with no
 * packet row is no measurement, a missing `link-downs` is no reconnection
 * count.
 */

import type {
  LineQualityBaseline,
  LineQualityCarrier,
  LineQualityMethod,
  LineQualityReason,
  LineQualityStatus,
  LineQualityTargetResult,
  LineQualityThresholds,
  LineQualityVerdict,
} from '@obliwan/shared';
import { isCellularIface, isFixedUplinkName } from './backup4g.service';
import type { ActiveDefaultRoute } from './uplinkModel';

// ============================================================================
// Constants
// ============================================================================

/** Pings per target. With the default interval (1 s) a target takes ~20 s. */
export const LINE_QUALITY_PING_COUNT = 20;
/** Previous nights a baseline is computed over. */
export const BASELINE_WINDOW_NIGHTS = 14;
/** Fixed-line nights needed before the relative rules apply. */
export const BASELINE_MIN_NIGHTS = 5;
/** A relative rule also needs at least this gap above the baseline. */
export const LATENCY_REL_MIN_DELTA_MS = 10;
export const LOSS_REL_MIN_DELTA_PCT = 3;
export const RECONNECT_REL_MIN_DELTA = 2;
/** A judged night older than this no longer tells where the line stands. */
export const STATUS_STALE_NIGHTS = 7;
/** With known hours: the store must have been closed this long… */
export const CLOSED_SETTLE_MS = 30 * 60_000;
/** …and stay closed at least this long: a lunch break is not a night. */
export const CLOSED_AHEAD_MIN_MS = 3 * 3600_000;
/** No measurement starts in the last half hour of the fallback window. */
export const NIGHT_WINDOW_MARGIN_MIN = 30;

// ============================================================================
// RouterOS values
// ============================================================================

function text(v: unknown): string {
  return v === undefined || v === null ? '' : String(v).trim();
}

/** A whole number read off the router, or null — trimmed first: `Number(' ')`
 *  is 0, not NaN. */
export function routerInt(v: unknown): number | null {
  const s = text(v);
  if (s === '' || !/^\d+$/.test(s)) return null;
  const n = Number(s);
  return Number.isSafeInteger(n) ? n : null;
}

/**
 * A RouterOS duration in MILLISECONDS: `12ms`, `12ms345us` (RouterOS 7),
 * `1s23ms`, `350us`, `0ms`, `1.5ms`. null when nothing parses — never 0.
 */
export function parseRosDurationMs(raw: unknown): number | null {
  const s = text(raw).toLowerCase();
  if (s === '') return null;
  const re = /(\d+(?:\.\d+)?)(ms|us|µs|s|m|h)/g;
  let total = 0;
  let consumed = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s)) !== null) {
    if (m.index !== consumed) return null;
    consumed = m.index + m[0].length;
    const n = Number(m[1]);
    const unit = m[2];
    total += unit === 'h' ? n * 3_600_000 : unit === 'm' ? n * 60_000 : unit === 's' ? n * 1000
      : unit === 'ms' ? n : n / 1000;
  }
  return consumed === s.length && consumed > 0 ? total : null;
}

/**
 * `/system/resource` uptime in SECONDS: `3w1d02:03:04`, `1d02:03:04`,
 * `02:03:04` (RouterOS 6/7 print), or `3w1d2h3m4s`. null when unreadable.
 */
export function parseRosUptimeSec(raw: unknown): number | null {
  const s = text(raw).toLowerCase();
  if (s === '') return null;
  const clock = /^(?:(\d+)w)?(?:(\d+)d)?(\d{1,2}):(\d{2}):(\d{2})$/.exec(s);
  if (clock) {
    const [, w, d, h, mi, se] = clock;
    return Number(w ?? 0) * 604_800 + Number(d ?? 0) * 86_400 + Number(h) * 3600 + Number(mi) * 60 + Number(se);
  }
  const units = /^(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/.exec(s);
  if (units && units.slice(1).some((x) => x !== undefined)) {
    const [, w, d, h, mi, se] = units;
    return Number(w ?? 0) * 604_800 + Number(d ?? 0) * 86_400 + Number(h ?? 0) * 3600 + Number(mi ?? 0) * 60 + Number(se ?? 0);
  }
  return null;
}

// ============================================================================
// Ping — the API reply rows reduced to figures
// ============================================================================

export interface PingSummary {
  sent: number;
  received: number;
  lossPct: number;
  rttMinMs: number | null;
  rttAvgMs: number | null;
  rttMaxMs: number | null;
  /** Mean absolute difference between consecutive replies (RFC 3550's idea,
   *  without its smoothing); null below two replies. */
  jitterMs: number | null;
}

const round2 = (n: number): number => Math.round(n * 100) / 100;

/**
 * The `!re` rows of one `/ping` call. One row per packet (`seq`), a reply
 * carrying `time`, a lost packet carrying `status` (timeout, host
 * unreachable…) and no time. `sent` / `received` are taken as the larger of
 * what the rows count and what the router's cumulative fields say. null when
 * no packet row came back at all: that is no measurement, not 100 % loss.
 */
export function summarisePing(rows: ReadonlyArray<Record<string, unknown>>): PingSummary | null {
  const bySeq = new Map<string, { rtt: number | null }>();
  let sentField = 0;
  let receivedField = 0;
  let unnumbered = 0;
  for (const r of rows) {
    const s = routerInt(r.sent);
    if (s !== null) sentField = Math.max(sentField, s);
    const rc = routerInt(r.received);
    if (rc !== null) receivedField = Math.max(receivedField, rc);
    const status = text(r.status);
    const rtt = status === '' ? parseRosDurationMs(r.time) : null;
    const seq = text(r.seq);
    if (seq === '') {
      // A summary row (no packet of its own), or a reply the router did not
      // number: counted only when it carries a reply.
      if (rtt !== null) bySeq.set(`#${unnumbered++}`, { rtt });
      continue;
    }
    // A packet printed twice (a late reply after its timeout row) counts once,
    // as a reply.
    const prev = bySeq.get(seq);
    if (!prev || (prev.rtt === null && rtt !== null)) bySeq.set(seq, { rtt });
  }
  const rtts = [...bySeq.values()].map((p) => p.rtt).filter((x): x is number => x !== null);
  const sent = Math.max(bySeq.size, sentField);
  if (sent === 0) return null;
  const received = Math.min(sent, Math.max(rtts.length, receivedField));
  const lossPct = round2(((sent - received) / sent) * 100);
  if (rtts.length === 0) {
    return { sent, received, lossPct, rttMinMs: null, rttAvgMs: null, rttMaxMs: null, jitterMs: null };
  }
  let jitter: number | null = null;
  if (rtts.length >= 2) {
    let acc = 0;
    for (let i = 1; i < rtts.length; i++) acc += Math.abs(rtts[i] - rtts[i - 1]);
    jitter = round2(acc / (rtts.length - 1));
  }
  return {
    sent,
    received,
    lossPct,
    rttMinMs: round2(Math.min(...rtts)),
    rttAvgMs: round2(rtts.reduce((a, b) => a + b, 0) / rtts.length),
    rttMaxMs: round2(Math.max(...rtts)),
    jitterMs: jitter,
  };
}

// ============================================================================
// The WAN1 shape, and how each target is sent
// ============================================================================

export interface PppoeClientRow {
  name: string;
  iface: string | null;
  disabled: boolean;
  running: boolean;
}

export interface ProbeRouteReading {
  /** The /32's host, e.g. 8.8.8.8. */
  host: string;
  active: boolean;
  /** The interface its next hop leaves by, when the router named one. */
  iface: string | null;
}

export interface WanShape {
  /** The enabled PPPoE client the fixed line rides, when exactly one exists
   *  (on ether1-WAN1 first). */
  pppoe: PppoeClientRow | null;
  /** Several enabled clients and none on ether1-WAN1: no interface is forced. */
  pppoeAmbiguous: boolean;
  /** The NW-WAN1 route, when the router has one enabled. */
  probe: ProbeRouteReading | null;
  /** The active default route, read before the pings. */
  route: ActiveDefaultRoute;
}

export const WAN1_PORT = 'ether1-WAN1';

/** The enabled PPPoE client of the fixed line: the one on ether1-WAN1, else
 *  the only enabled one. */
export function pickPppoe(clients: readonly PppoeClientRow[]): { client: PppoeClientRow | null; ambiguous: boolean } {
  const enabled = clients.filter((c) => !c.disabled);
  const onWan1 = enabled.filter((c) => c.iface === WAN1_PORT);
  if (onWan1.length === 1) return { client: onWan1[0], ambiguous: false };
  if (onWan1.length > 1) return { client: null, ambiguous: true };
  if (enabled.length === 1) return { client: enabled[0], ambiguous: false };
  return { client: null, ambiguous: enabled.length > 1 };
}

/** A route's / interface's carrier, by the backup watch's own names. */
export function carrierOf(iface: string | null): LineQualityCarrier | null {
  if (iface === null) return null;
  if (isCellularIface(iface)) return 'cellular';
  if (isFixedUplinkName(iface, null)) return 'fixed';
  return null;
}

export type TargetPlan =
  | { kind: 'ping'; method: LineQualityMethod; iface: string | null; carrier: LineQualityCarrier; interfaceParam: string | null }
  | { kind: 'skip'; reason: 'route_unknown' | 'pppoe_ambiguous' };

/** How one target is sent (the header box). */
export function planTarget(target: string, shape: WanShape): TargetPlan {
  if (shape.pppoe && shape.pppoe.running) {
    return { kind: 'ping', method: 'interface', iface: shape.pppoe.name, carrier: 'fixed', interfaceParam: shape.pppoe.name };
  }
  const p = shape.probe;
  if (!shape.pppoe && p && p.host === target && p.active && p.iface !== null && carrierOf(p.iface) === 'fixed') {
    return { kind: 'ping', method: 'probe_route', iface: p.iface, carrier: 'fixed', interfaceParam: null };
  }
  const carrier = carrierOf(shape.route.iface);
  if (carrier === null) {
    return { kind: 'skip', reason: shape.pppoeAmbiguous ? 'pppoe_ambiguous' : 'route_unknown' };
  }
  return { kind: 'ping', method: 'default_route', iface: shape.route.iface, carrier, interfaceParam: null };
}

/** A default-route target whose route moved during the ping: no carrier. */
export function settleCarrier(plan: TargetPlan, after: ActiveDefaultRoute): LineQualityCarrier | null {
  if (plan.kind !== 'ping') return null;
  if (plan.method !== 'default_route') return plan.carrier;
  return after.iface === plan.iface ? plan.carrier : 'unknown';
}

// ============================================================================
// A night's figures
// ============================================================================

export interface NightAggregate {
  carrier: LineQualityCarrier | null;
  uplinkIface: string | null;
  method: string | null;
  sent: number | null;
  received: number | null;
  lossPct: number | null;
  rttMinMs: number | null;
  rttAvgMs: number | null;
  rttMaxMs: number | null;
  jitterMs: number | null;
}

const EMPTY_AGGREGATE: NightAggregate = {
  carrier: null, uplinkIface: null, method: null, sent: null, received: null, lossPct: null,
  rttMinMs: null, rttAvgMs: null, rttMaxMs: null, jitterMs: null,
};

/**
 * The night's figures over its targets: the FIXED-line ones when any target
 * was carried by the fixed line (a cellular one beside it is left out), else
 * the cellular ones (filed `cellular`, kept out of every fixed-line rule),
 * else those of an unknown carrier. Never a mix of two carriers.
 */
export function aggregateTargets(targets: readonly LineQualityTargetResult[]): NightAggregate {
  const measured = targets.filter((t) => t.sent !== null && t.sent > 0 && t.carrier !== null);
  const pick = (c: LineQualityCarrier) => measured.filter((t) => t.carrier === c);
  const set = pick('fixed').length > 0 ? pick('fixed') : pick('cellular').length > 0 ? pick('cellular') : pick('unknown');
  if (set.length === 0) return EMPTY_AGGREGATE;
  const sent = set.reduce((a, t) => a + (t.sent ?? 0), 0);
  const received = set.reduce((a, t) => a + (t.received ?? 0), 0);
  const withRtt = set.filter((t) => t.rttAvgMs !== null && (t.received ?? 0) > 0);
  const jitters = set.map((t) => t.jitterMs).filter((j): j is number => j !== null);
  const uniq = (xs: Array<string | null>) => [...new Set(xs.filter((x): x is string => !!x))].join(', ') || null;
  return {
    carrier: set[0].carrier,
    uplinkIface: uniq(set.map((t) => t.iface)),
    method: uniq(set.map((t) => t.method)),
    sent,
    received,
    lossPct: round2(((sent - received) / sent) * 100),
    rttMinMs: withRtt.length ? Math.min(...withRtt.map((t) => t.rttMinMs as number)) : null,
    rttAvgMs: withRtt.length
      ? round2(withRtt.reduce((a, t) => a + (t.rttAvgMs as number) * (t.received as number), 0)
          / withRtt.reduce((a, t) => a + (t.received as number), 0))
      : null,
    rttMaxMs: withRtt.length ? Math.max(...withRtt.map((t) => t.rttMaxMs as number)) : null,
    jitterMs: jitters.length ? round2(jitters.reduce((a, b) => a + b, 0) / jitters.length) : null,
  };
}

/**
 * The day's link-downs from the router's cumulative counter: the difference
 * with the previous reading of the SAME interface on the SAME boot, or — the
 * router rebooted since — the counter itself (link-downs since the boot).
 * null when there is nothing comparable (first reading, another interface, a
 * previous reading older than `maxSpanMs`, a counter that went backwards).
 */
export function linkDownsDelta(
  prev: { iface: string | null; total: number | null; bootAt: Date | null; at: Date } | null,
  cur: { iface: string | null; total: number | null; bootAt: Date | null; at: Date },
  maxSpanMs = 30 * 3600_000,
): number | null {
  if (cur.total === null || cur.iface === null) return null;
  if (!prev || prev.total === null || prev.iface !== cur.iface || prev.bootAt === null || cur.bootAt === null) return null;
  if (cur.at.getTime() - prev.at.getTime() > maxSpanMs) return null;
  const sameBoot = Math.abs(cur.bootAt.getTime() - prev.bootAt.getTime()) < 5 * 60_000;
  if (sameBoot) return cur.total >= prev.total ? cur.total - prev.total : null;
  return cur.bootAt.getTime() > prev.at.getTime() ? cur.total : null;
}

/** The judged reconnection figure: the higher of the two counts that are known. */
export function reconnectionsOf(linkDowns: number | null, failovers: number | null): number | null {
  if (linkDowns === null && failovers === null) return null;
  return Math.max(linkDowns ?? 0, failovers ?? 0);
}

// ============================================================================
// Judging a night
// ============================================================================

/** What judging needs of a night. */
export interface NightFacts {
  night: string;
  carrier: LineQualityCarrier | null;
  lossPct: number | null;
  rttAvgMs: number | null;
  fixedDown: boolean;
  reconnections: number | null;
}

function median(xs: number[]): number {
  const s = [...xs].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

/** A fixed-line night with figures: the only kind a baseline or a latency /
 *  loss rule ever reads. */
export function isFixedLineNight(n: Pick<NightFacts, 'carrier' | 'lossPct' | 'rttAvgMs'>): boolean {
  return n.carrier === 'fixed' && n.lossPct !== null;
}

/** Medians over the previous fixed-line nights; null below BASELINE_MIN_NIGHTS. */
export function computeBaseline(previous: readonly NightFacts[]): LineQualityBaseline | null {
  const fixed = previous.filter(isFixedLineNight);
  if (fixed.length < BASELINE_MIN_NIGHTS) return null;
  const rtts = fixed.map((n) => n.rttAvgMs).filter((x): x is number => x !== null);
  const recs = previous.map((n) => n.reconnections).filter((x): x is number => x !== null);
  return {
    nights: fixed.length,
    lossPct: round2(median(fixed.map((n) => n.lossPct as number))),
    rttAvgMs: rtts.length ? round2(median(rtts)) : 0,
    reconnections: recs.length ? median(recs) : null,
  };
}

/**
 * One night against the thresholds and the site's baseline.
 *   exceeded  any rule fired (a fixed line DOWN at measurement time is one);
 *   ok        something judgeable was measured (fixed-line figures, or a
 *             reconnection count) and nothing fired;
 *   unknown   nothing judgeable.
 * A threshold at 0 is a rule switched off.
 */
export function judgeNight(
  n: NightFacts,
  base: LineQualityBaseline | null,
  th: LineQualityThresholds,
): { verdict: LineQualityVerdict; reasons: LineQualityReason[] } {
  const reasons: LineQualityReason[] = [];
  const rel = th.relativePct > 0 && base !== null ? 1 + th.relativePct / 100 : null;
  if (n.fixedDown) {
    reasons.push({ metric: 'fixed_down', kind: 'absolute', value: 100, threshold: th.lossPct, baseline: null });
  }
  const fixed = isFixedLineNight(n);
  if (fixed) {
    const loss = n.lossPct as number;
    if (th.lossPct > 0 && loss >= th.lossPct) {
      reasons.push({ metric: 'loss', kind: 'absolute', value: loss, threshold: th.lossPct, baseline: null });
    } else if (rel !== null && base) {
      const t = round2(Math.max(base.lossPct * rel, base.lossPct + LOSS_REL_MIN_DELTA_PCT));
      if (loss >= t) reasons.push({ metric: 'loss', kind: 'relative', value: loss, threshold: t, baseline: base.lossPct });
    }
    if (n.rttAvgMs !== null) {
      const rtt = n.rttAvgMs;
      if (th.latencyMs > 0 && rtt >= th.latencyMs) {
        reasons.push({ metric: 'latency', kind: 'absolute', value: rtt, threshold: th.latencyMs, baseline: null });
      } else if (rel !== null && base && base.rttAvgMs > 0) {
        const t = round2(Math.max(base.rttAvgMs * rel, base.rttAvgMs + LATENCY_REL_MIN_DELTA_MS));
        if (rtt >= t) reasons.push({ metric: 'latency', kind: 'relative', value: rtt, threshold: t, baseline: base.rttAvgMs });
      }
    }
  }
  if (n.reconnections !== null) {
    const r = n.reconnections;
    if (th.reconnections > 0 && r >= th.reconnections) {
      reasons.push({ metric: 'reconnections', kind: 'absolute', value: r, threshold: th.reconnections, baseline: null });
    } else if (rel !== null && base && base.reconnections !== null) {
      const t = Math.max(Math.ceil(base.reconnections * rel), base.reconnections + RECONNECT_REL_MIN_DELTA);
      if (r >= t) reasons.push({ metric: 'reconnections', kind: 'relative', value: r, threshold: t, baseline: base.reconnections });
    }
  }
  if (reasons.length > 0) return { verdict: 'exceeded', reasons };
  return { verdict: fixed || n.reconnections !== null ? 'ok' : 'unknown', reasons };
}

// ============================================================================
// Where a site's line stands
// ============================================================================

/** 'YYYY-MM-DD' + days (calendar arithmetic, UTC). */
export function addDays(night: string, days: number): string {
  const [y, m, d] = night.split('-').map(Number);
  const t = new Date(Date.UTC(y, m - 1, d) + days * 86_400_000);
  return `${t.getUTCFullYear()}-${String(t.getUTCMonth() + 1).padStart(2, '0')}-${String(t.getUTCDate()).padStart(2, '0')}`;
}

/**
 * The site's status from its nights (any order): the streak is the number of
 * consecutive EXCEEDED nights among the JUDGED ones (ok / exceeded), ending at
 * the latest judged night. A night that could not be judged (router offline,
 * nothing measured) neither breaks nor extends a streak. A latest judged night
 * older than STATUS_STALE_NIGHTS before `currentNight` says nothing any more:
 * unknown.
 */
export function siteLineStatus(
  nights: ReadonlyArray<{ night: string; verdict: LineQualityVerdict }>,
  currentNight: string,
  requiredNights: number,
): { status: LineQualityStatus; streak: number; lastJudgedNight: string | null } {
  const judged = nights.filter((n) => n.verdict !== 'unknown').sort((a, b) => (a.night < b.night ? 1 : a.night > b.night ? -1 : 0));
  if (judged.length === 0) return { status: 'unknown', streak: 0, lastJudgedNight: null };
  const last = judged[0].night;
  if (last < addDays(currentNight, -STATUS_STALE_NIGHTS)) return { status: 'unknown', streak: 0, lastJudgedNight: last };
  let streak = 0;
  for (const n of judged) {
    if (n.verdict !== 'exceeded') break;
    streak += 1;
  }
  const status: LineQualityStatus = streak >= Math.max(1, requiredNights) ? 'degraded' : streak >= 1 ? 'watch' : 'ok';
  return { status, streak, lastJudgedNight: last };
}

/** What the grouped alert of a tenant does given its open state and the
 *  sites degraded now. */
export type AlertStep = 'none' | 'open' | 'refresh' | 'shrink' | 'close';

export function alertStep(openSites: readonly number[] | null, degraded: readonly number[]): AlertStep {
  if (openSites === null) return degraded.length > 0 ? 'open' : 'none';
  if (degraded.length === 0) return 'close';
  const open = new Set(openSites);
  if (degraded.some((id) => !open.has(id))) return 'refresh';
  return degraded.length !== openSites.length ? 'shrink' : 'none';
}

// ============================================================================
// Time zones, night labels, the measurement moment
// ============================================================================

const formatters = new Map<string, Intl.DateTimeFormat>();

/** The wall clock of `at` in `tz` (throws a RangeError on an unknown zone). */
export function wallClock(at: Date, tz: string): { date: string; minutes: number } {
  let f = formatters.get(tz);
  if (!f) {
    f = new Intl.DateTimeFormat('en-US', {
      timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false,
    });
    formatters.set(tz, f);
  }
  const parts = f.formatToParts(at);
  const get = (type: string) => parts.find((p) => p.type === type)?.value ?? '';
  const h = Number(get('hour')) % 24;
  return { date: `${get('year')}-${get('month')}-${get('day')}`, minutes: h * 60 + Number(get('minute')) };
}

/** A time zone this runtime knows, else Europe/Paris (the sites' default). */
export function safeZone(tz: string | null | undefined): string {
  const z = (tz ?? '').trim() || 'Europe/Paris';
  try {
    wallClock(new Date(0), z);
    return z;
  } catch {
    return 'Europe/Paris';
  }
}

/** The night an instant belongs to: the site's local date of (at − 12 h).
 *  A measurement at 20:00 and one at 03:00 the next morning are the same
 *  night, whatever window either ran in. */
export function nightOf(at: Date, tz: string): string {
  return wallClock(new Date(at.getTime() - 12 * 3600_000), tz).date;
}

/** Inside the fallback night window [start, end − margin) on the site's
 *  wall clock; a window may cross midnight (22 → 5). Equal hours = no window. */
export function inNightWindow(at: Date, tz: string, startHour: number, endHour: number): boolean {
  const m = wallClock(at, tz).minutes;
  const s = startHour * 60;
  const e = endHour * 60 - NIGHT_WINDOW_MARGIN_MIN;
  if (startHour === endHour) return false;
  if (s < endHour * 60) return m >= s && m < e;
  // Crossing midnight: [s, 24:00) ∪ [00:00, e).
  return m >= s || m < (e < 0 ? e + 1440 : e);
}

export type MomentVerdict =
  | { due: true; source: 'opening_hours' | 'night_window' }
  | { due: false; why: 'open' | 'just_closed' | 'short_closure' | 'outside_window' };

/**
 * Is NOW a measurement moment? Known hours decide (`openNow` not null): the
 * store closed, closed for CLOSED_SETTLE_MS already, and staying closed at
 * least CLOSED_AHEAD_MIN_MS more (a lunch break is not a night). Unknown
 * hours: the fallback night window.
 */
export function decideMoment(i: {
  openNow: boolean | null;
  openSettleAgo: boolean | null;
  closedUntil: Date | null;
  inWindow: boolean;
  now: Date;
}): MomentVerdict {
  if (i.openNow === null) return i.inWindow ? { due: true, source: 'night_window' } : { due: false, why: 'outside_window' };
  if (i.openNow) return { due: false, why: 'open' };
  if (i.openSettleAgo !== false) return { due: false, why: 'just_closed' };
  if (!i.closedUntil || i.closedUntil.getTime() - i.now.getTime() < CLOSED_AHEAD_MIN_MS) {
    return { due: false, why: 'short_closure' };
  }
  return { due: true, source: 'opening_hours' };
}
