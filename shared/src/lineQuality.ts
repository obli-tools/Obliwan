// ============================================================================
// @obliwan/shared — LINE QUALITY of a store's fixed line (migration 097)
// ============================================================================
//
// Outside opening hours, each store's router pings two stable targets THROUGH
// ITS FIXED LINE, and the night's figures (latency, loss, jitter) are filed
// with the day's reconnections. A line whose figures exceed the thresholds —
// absolute, or relative to the store's own 14-night baseline — for several
// consecutive nights is « dégradée »; for one night « à surveiller ».
//
// The server measures and judges (server/src/services/fleet/lineQuality*.ts);
// this file is the vocabulary both sides read. Nothing here does I/O.
//
// A 4G-CARRIED FIGURE IS NEVER A FIXED-LINE FIGURE. Every night says which
// link carried it (`carrier`): only `fixed` nights enter the baseline and the
// latency / loss rules. A store found on its 4G backup during the night has
// its fixed line DOWN — that night counts as exceeded (`fixed_down`), whatever
// the 4G answered.

/** Where a site's line stands, from its judged nights. */
export const LINE_QUALITY_STATUSES = ['degraded', 'watch', 'ok', 'unknown'] as const;
export type LineQualityStatus = (typeof LINE_QUALITY_STATUSES)[number];

/** Which link carried a night's figures. */
export type LineQualityCarrier = 'fixed' | 'cellular' | 'unknown';

/**
 * How a ping was sent through the fixed line:
 *   interface      `/ping … interface=<pppoe client>` — forced (PPPoE stores);
 *   probe_route    the target is the host of the template's `NW-WAN1` /32
 *                  route, active through WAN1 — forced (DHCP / fixed-IP stores);
 *   default_route  not forced: the router's ACTIVE default route was read before
 *                  and after the ping, and the carrier is what it named both
 *                  times (a fixed interface, or the 4G: then never a fixed-line
 *                  figure).
 */
export type LineQualityMethod = 'interface' | 'probe_route' | 'default_route';

/** One night's verdict. `unknown` = nothing judgeable was measured. */
export type LineQualityVerdict = 'ok' | 'exceeded' | 'unknown';

/** A night's row state. */
export type LineQualityRowStatus = 'pending' | 'measured' | 'skipped';

/** Why a night was not measured. */
export const LINE_QUALITY_SKIP_REASONS = [
  // Final for the night (nothing would change by trying again):
  'cellular_only', // the site is declared 4G-only: it has no fixed line
  'no_fixed_line', // no fixed uplink known on this router, and none declared
  'several_routers', // more than one router on the site: which one is the line's?
  'no_api_channel', // no usable RouterOS API channel to send the ping from
  'no_targets', // both targets set to 0 (off)
  'identity_mismatch', // the box that answered is not the recorded router
  'identity_unproven', // no identity attribute could be corroborated
  // Tried again later in the window:
  'ppp_down', // its PPP session is down on the concentrator: never dialled
  'parent_degraded', // its concentrator is degraded
  'busy', // a change job is queued or running on it
  'wan_cut', // a planned WAN link cut is in progress (wan_link job)
  'unreachable', // the API session could not be opened or broke
  'budget_exceeded', // the router did not finish within its budget
  'internal', // ObliWAN failed (see the server log)
] as const;
export type LineQualitySkipReason = (typeof LINE_QUALITY_SKIP_REASONS)[number];

/** A skip that ends the night's attempts. */
export const LINE_QUALITY_FINAL_SKIPS: readonly LineQualitySkipReason[] = [
  'cellular_only', 'no_fixed_line', 'several_routers', 'no_api_channel', 'no_targets',
  'identity_mismatch', 'identity_unproven',
];

/** What made a night exceed. */
export type LineQualityMetric = 'loss' | 'latency' | 'reconnections' | 'fixed_down';

export interface LineQualityReason {
  metric: LineQualityMetric;
  /** absolute: above the inherited threshold; relative: above the site's own
   *  baseline by the inherited percentage (and a minimal delta). */
  kind: 'absolute' | 'relative';
  value: number;
  /** The figure the value was compared with. */
  threshold: number;
  /** The baseline median, for a relative reason. */
  baseline: number | null;
}

/** The thresholds a night was judged with (inherited settings, per device). */
export interface LineQualityThresholds {
  lossPct: number;
  latencyMs: number;
  reconnections: number;
  /** Above the baseline by this percentage (0 = relative rules off). */
  relativePct: number;
  /** Consecutive exceeded nights that make a line « dégradée ». */
  nights: number;
}

/** The site's own reference: medians over its previous fixed-line nights. */
export interface LineQualityBaseline {
  nights: number;
  lossPct: number;
  rttAvgMs: number;
  /** null = no night with a known reconnection count. */
  reconnections: number | null;
}

/** One target of one night. */
export interface LineQualityTargetResult {
  target: string;
  method: LineQualityMethod | null;
  /** The interface the ping left by (forced, or named by the route). */
  iface: string | null;
  carrier: LineQualityCarrier | null;
  /** Why it was not pinged (route unknown, …); null when it was. */
  skipped: string | null;
  sent: number | null;
  received: number | null;
  lossPct: number | null;
  rttMinMs: number | null;
  rttAvgMs: number | null;
  rttMaxMs: number | null;
  jitterMs: number | null;
  /** The router's refusal, when the ping itself failed. */
  error: string | null;
}

export interface LineQualityNightView {
  /** The night, as the site's local date it began on ('YYYY-MM-DD'). */
  night: string;
  status: LineQualityRowStatus;
  skipReason: LineQualitySkipReason | null;
  attempts: number;
  measuredAt: string | null;
  /** opening_hours: in the store's closed window; night_window: hours unknown. */
  scheduleSource: 'opening_hours' | 'night_window' | null;
  carrier: LineQualityCarrier | null;
  uplinkIface: string | null;
  method: string | null;
  lossPct: number | null;
  rttMinMs: number | null;
  rttAvgMs: number | null;
  rttMaxMs: number | null;
  jitterMs: number | null;
  sent: number | null;
  received: number | null;
  /** On its 4G backup at measurement time while the site has a fixed line. */
  fixedDown: boolean;
  /** WAN link-downs of the day (the router's own counter, delta). */
  linkDowns: number | null;
  /** Moves of the active default route onto the 4G during the day. */
  failovers: number | null;
  /** Sessions of the management tunnel the concentrator saw open that day. */
  mgmtReconnects: number | null;
  /** In + out errors of the WAN1 port over the day (SNMP); null = not polled. */
  wan1Errors: number | null;
  /** The judged figure: max(link-downs, failovers). */
  reconnections: number | null;
  verdict: LineQualityVerdict;
  reasons: LineQualityReason[];
  baseline: LineQualityBaseline | null;
  targets: LineQualityTargetResult[];
}

/** The device page's « Qualité de ligne » card. */
export interface LineQualityDeviceView {
  deviceId: number;
  site: { id: number; code: string; name: string } | null;
  /** Why nothing is measured on this device at all (no site, 4G-only, …). */
  notMeasured: 'no_site' | 'not_mikrotik' | 'concentrator' | 'cellular_only' | 'several_routers' | null;
  status: LineQualityStatus;
  /** Consecutive exceeded judged nights ending at the latest one. */
  streak: number;
  lastJudgedNight: string | null;
  thresholds: LineQualityThresholds;
  targets: string[];
  /** The store's opening hours are known (else the night window applies). */
  hoursKnown: boolean | null;
  nightWindow: { startHour: number; endHour: number };
  /** Newest first. */
  nights: LineQualityNightView[];
}

/** One line of « Lignes dégradées ». */
export interface LineQualityFleetItem {
  /** God view only: the owning tenant. */
  tenantId?: number;
  tenantName?: string | null;
  siteId: number;
  siteCode: string;
  siteName: string;
  deviceId: number | null;
  deviceName: string | null;
  status: LineQualityStatus;
  streak: number;
  lastNight: string;
  measuredAt: string | null;
  carrier: LineQualityCarrier | null;
  uplinkIface: string | null;
  lossPct: number | null;
  rttAvgMs: number | null;
  jitterMs: number | null;
  reconnections: number | null;
  fixedDown: boolean;
  reasons: LineQualityReason[];
  /** The last nights, oldest first: the fixed line's average RTT (null = not
   *  a fixed-line night: never a 4G figure) and whether the night exceeded. */
  trend: Array<{ night: string; rttAvgMs: number | null; exceeded: boolean }>;
}

// ============================================================================
// IPv4 targets stored as numeric settings
// ============================================================================
//
// Settings are numeric (settings.ts header): a target is stored as its 32-bit
// value, 0 meaning "no target". The settings screen shows and accepts the
// dotted form (`SettingField`, unit 'IPv4').

export const IPV4_SETTING_UNIT = 'IPv4';

/** '8.8.8.8' -> 134744072; null when not a dotted IPv4 address. */
export function ipv4ToInt(text: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text.trim());
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3];
}

/** 134744072 -> '8.8.8.8'; null for 0 (no target) or out of range. */
export function intToIpv4(value: number): string | null {
  if (!Number.isInteger(value) || value <= 0 || value > 0xffffffff) return null;
  return [24, 16, 8, 0].map((s) => Math.floor(value / 2 ** s) % 256).join('.');
}

/** A unicast address a router may usefully ping: not 0/8, 127/8, multicast,
 *  reserved or broadcast. */
export function isPingableIpv4(text: string): boolean {
  const n = ipv4ToInt(text);
  if (n === null) return false;
  const first = Math.floor(n / 2 ** 24);
  return first !== 0 && first !== 127 && first < 224;
}
