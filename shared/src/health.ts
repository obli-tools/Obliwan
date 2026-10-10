// ============================================================================
// @obliwan/shared — the permanent management-channel health check
// ============================================================================
//
// One row per device in `device_health_checks` (migration 043), written by
// `server/src/services/fleet/healthCheck.service.ts`. NOT to be confused with
// `device_health` (migration 002), which is the RouterOS pool's per-TRANSPORT
// circuit breaker: that one says "may this channel be dialled right now", this
// one says "did the device's management channel answer the last time we asked,
// and for how long has it not".
//
// The vocabularies below are mirrored by CHECK constraints in migration 043.
// A migration keeps describing the schema as it was the day it ran, so it
// inlines its own literals; a value added here needs a migration too.

/** `unknown` until a check has CONFIRMED something. Never a default for `up`. */
export const DEVICE_HEALTH_STATES = ['up', 'down', 'unknown'] as const;
export type DeviceHealthState = (typeof DEVICE_HEALTH_STATES)[number];

/**
 * The channel a check went through. Only management channels: `snmp` is
 * telemetry with its own poller and its own state, and `cwmp` is a channel the
 * CPE opens towards us — ObliWAN never dials it (decision 6 of migration 015).
 */
export const HEALTH_CHECK_CHANNELS = ['routeros_api', 'ssh', 'rest'] as const;
export type HealthCheckChannel = (typeof HEALTH_CHECK_CHANNELS)[number];

/**
 * What the check DOES on each channel.
 *
 *   routeros_api  a read over the pooled API session — `/system/identity/print`
 *                 on a CPE, `/ppp/active/print` (`.id` only) on a concentrator,
 *                 because the concentrator's job is presence and that is the
 *                 menu presence needs.
 *   ssh, rest     a TCP connect to the channel's port, nothing more. No login:
 *                 an SSH login every minute fills the device's own log and the
 *                 login-event attribution with ObliWAN's own sessions, and a
 *                 SonicOS REST login costs one of the unit's management slots.
 */
export const HEALTH_CHECK_METHOD: Readonly<Record<HealthCheckChannel, 'api_read' | 'tcp_connect'>> = {
  routeros_api: 'api_read',
  ssh: 'tcp_connect',
  rest: 'tcp_connect',
};

/**
 * Why a scheduled pass did NOT check a device. A failed check is not a skip:
 * a CPE whose PPP session is down is a FAILURE that dialled nothing.
 *
 *   no_channel       no enabled, complete management channel (TR-069-only
 *                    CPE, SNMP-only device, RouterOS API row without a
 *                    credential, …).
 *   parent_degraded  its concentrator is degraded: everything behind it is
 *                    suppressed — one alert, not three hundred.
 *   quarantined      the box at its address failed an identity assertion
 *                    An "OK" from it would be an OK about somebody else.
 */
export const HEALTH_SKIP_REASONS = ['no_channel', 'parent_degraded', 'quarantined'] as const;
export type HealthSkipReason = (typeof HEALTH_SKIP_REASONS)[number];

/** What a screen shows, derived from the stored row and the clock. */
export type HealthDisplay =
  | 'ok'            // last check answered
  | 'failing'       // failed its last check(s), not yet confirmed down
  | 'down'          // confirmed: retries + 1 consecutive failures
  | 'unknown'       // nothing confirmed yet
  | 'stale'         // the checker has not spoken within its freshness bound
  | 'not_checkable' // skip_reason no_channel / quarantined
  | 'suppressed';   // skip_reason parent_degraded

/**
 * How long a stored check result stays evidence.
 *
 * Two intervals plus thirty seconds: one missed check is tolerated (a busy
 * cycle, a restart), two are not. Beyond it, the result says something about
 * the CHECKER — the leader died, the scheduler stalled — and nothing about the
 * device, so every consumer must read it as "not measured", never as its last
 * value. The reachability verdict of a concentrator uses this bound too.
 */
export function healthFreshnessMs(intervalSec: number): number {
  return (2 * intervalSec + 30) * 1000;
}

/**
 * ALERT GROUPING, per workspace: once this many individual down alerts (or
 * recovery notices) of the permanent check have been raised in a workspace
 * within the window, the next ones are grouped into ONE alert for the window
 * instead of one per device. A degraded concentrator already silences what is
 * behind it; this covers the mass failures that are NOT a concentrator —
 * the host route to the tunnel subnet lost, the L2TP service down while
 * the CHR's API still answers — where three hundred devices fail at once and
 * three hundred messages would mute the channel that carries them.
 *
 * The `health_alert_delay` setting's description states these two numbers:
 * change them together.
 */
export const HEALTH_ALERT_GROUP_AFTER = 10;
export const HEALTH_ALERT_GROUP_WINDOW_SEC = 600;

/**
 * Whether a confirmed outage may be announced at all.
 *
 * A device the bench never prepared (`benchQualification` absent or null):
 * only once it has ANSWERED a check (`last_ok_at` set). One that never did is
 * shown down but never alerted: there is no outage to announce, only a device
 * that was never reachable — every site already offline the day this feature
 * is deployed, a pending device whose API service is still disabled.
 * Announcing those would be a storm of messages about nothing that changed.
 *
 * A device the bench DID prepare: only once it is QUALIFIED for its latest
 * preparation (see `BenchQualificationState`), whatever `last_ok_at` says. An
 * answer at the bench proves nothing about the site — the box is unplugged and
 * shipped right after — and qualification is the stronger evidence the other
 * rule stands in for: its tunnel stayed up, without a break, long enough to
 * say it is installed. So a qualified box whose API never answered is
 * announced when its tunnel drops, and a box in shipping that answered at the
 * bench is not.
 */
export function outageIsAnnounceable(
  lastOkAt: string | Date | null,
  benchQualification?: BenchQualificationState | null,
): boolean {
  if (benchQualification !== undefined && benchQualification !== null) {
    return benchQualification === 'qualified';
  }
  return lastOkAt !== null && lastOkAt !== '';
}

export interface HealthRowFacts {
  state: DeviceHealthState;
  consecutiveFailures: number;
  skipReason: HealthSkipReason | null;
  lastCheckAt: string | null;
  /** The interval that scheduled the row's next check — the freshness base. */
  intervalSec: number | null;
}

/**
 * The one interpretation of a stored row, shared by the list and the page.
 * A disabled device is never checked, whatever its row still says.
 */
export function healthDisplay(
  row: HealthRowFacts | null,
  nowMs: number,
  deviceDisabled = false,
): HealthDisplay {
  if (deviceDisabled) return 'not_checkable';
  if (!row) return 'unknown';
  if (row.skipReason === 'parent_degraded') return 'suppressed';
  if (row.skipReason === 'no_channel' || row.skipReason === 'quarantined') return 'not_checkable';
  if (!row.lastCheckAt || !row.intervalSec) return 'unknown';
  if (nowMs - new Date(row.lastCheckAt).getTime() > healthFreshnessMs(row.intervalSec)) return 'stale';
  if (row.state === 'down') return 'down';
  // Failing but not yet confirmed — whether it answered before ('up') or has
  // never answered at all ('unknown'): it WAS checked, and it did not answer.
  if (row.consecutiveFailures > 0) return 'failing';
  if (row.state === 'up') return 'ok';
  return 'unknown';
}

/** The list endpoint's compact form: enough for a dot and a tooltip. */
export interface DeviceHealthSummary {
  display: HealthDisplay;
  consecutiveFailures: number;
  downSince: string | null;
  lastCheckAt: string | null;
}

// ============================================================================
// Bench qualification — when a bench-prepared router becomes alertable
// ============================================================================
//
// Operator rule of 2026-10-04. A router prepared at the bench is usually
// unplugged right after and SHIPPED — a day to three weeks, longer to the
// overseas departments — and every alert about it in that time is noise for
// the supervision teams. So such a router is not alertable until it has proved
// it is installed, by its PPP session staying open on its concentrator
// WITHOUT A BREAK:
//
//   - right after the preparation, for BENCH_QUALIFY_AFTER_PREP_MIN: a box
//     kept powered that long was not put in a van;
//   - later — on site — for BENCH_QUALIFY_ON_SITE_MIN.
//
// "Right after the preparation" is a session STARTED within
// BENCH_TUNNEL_WINDOW_MIN of the bench's 'applied' report (or open at it):
// inside that window the tunnel may still be the bench's own test of the box,
// so only the longer bar can tell a box left running from one being packed.
// A session started after the window is the box at its site.
//
// Before qualification nothing about the device is announced — not a tunnel
// loss, not a failed health check — however long it lasts, and there is no
// time-based "never installed" alert either. Once qualified, its outages are
// announced like any other device's, and the qualification holds until the
// bench prepares the device again.
//
// Only PPP PRESENCE qualifies. A health-check answer never does: behind a
// concentrator a check can only succeed while the session is open, so it
// adds nothing about CONTINUITY, and the bench's own answer says nothing about
// the site. A health-check failure never disqualifies either: the API can fail
// for reasons that have nothing to do with the box being installed (service
// disabled, certificate pin, credential, breaker) — and a qualified box whose
// API fails while its tunnel is up is precisely what an armed alert is for.
//
// A device the bench never prepared is not concerned: its outages follow the
// rule they always followed (`outageIsAnnounceable`).

/** Continuous PPP presence that qualifies a box right after its preparation. */
export const BENCH_QUALIFY_AFTER_PREP_MIN = 60;
/** Continuous PPP presence that qualifies a box later, on site. */
export const BENCH_QUALIFY_ON_SITE_MIN = 15;
/**
 * After a bench 'applied' report, a session STARTED within this window may
 * still be the bench's own test of the box: it must last
 * BENCH_QUALIFY_AFTER_PREP_MIN. One started after it is the box at its site.
 */
export const BENCH_TUNNEL_WINDOW_MIN = 120;

/**
 *   qualified    its tunnel stayed up long enough without a break: outages are
 *                announced (`qualifiedAt` is when it crossed the bar).
 *   qualifying   its tunnel is up now, not yet for long enough.
 *   in_shipping  its tunnel is not up and it never qualified since its
 *                preparation — dropped before the bar, or never came up at
 *                all. Nothing about it is announced, however long it lasts.
 */
export const BENCH_QUALIFICATION_STATES = ['qualified', 'qualifying', 'in_shipping'] as const;
export type BenchQualificationState = (typeof BENCH_QUALIFICATION_STATES)[number];

/** The device page's account of the rule, for a bench-prepared device. */
export interface BenchQualificationView {
  state: BenchQualificationState;
  /** When the bench reported the latest preparation applied. */
  benchAppliedAt: string;
  /** `qualified`: the instant the tunnel crossed the bar. */
  qualifiedAt: string | null;
  /** `in_shipping`: the end of its last session since the preparation, or the
   *  preparation itself when the tunnel never came up. */
  inShippingSince: string | null;
  /** `qualifying`: since when the tunnel has been up, counted from the
   *  preparation at the earliest. */
  upSince: string | null;
  /** `qualifying`: the bar that session must reach, in minutes. */
  requiredMinutes: number | null;
  /** `qualifying`: when it qualifies if the tunnel stays up. */
  qualifiesAt: string | null;
  /** `qualifying` past its bar, but its concentrator is degraded: the open
   *  session is a memory presence could not refresh, so it does not qualify
   *  until the concentrator answers again. */
  observerBlind: boolean;
}

/** The detail endpoint's form, and the answer of "Check now". */
export interface DeviceHealthCheckView {
  display: HealthDisplay;
  state: DeviceHealthState;
  /** Null when the device has no usable management channel. */
  channel: HealthCheckChannel | null;
  method: 'api_read' | 'tcp_connect' | null;
  skipReason: HealthSkipReason | null;
  consecutiveFailures: number;
  lastCheckAt: string | null;
  lastOkAt: string | null;
  downSince: string | null;
  /** The down alert of the CURRENT outage, when one was raised. */
  alertedAt: string | null;
  nextCheckAt: string | null;
  /** Redacted, bounded. Never a credential. */
  lastError: string | null;
  /** RESOLVED now, through the settings inheritance chain — what applies. */
  intervalSec: number;
  retries: number;
  alertDelaySec: number;
  /** False for disabled devices: they are never checked. */
  scheduled: boolean;
  /** Non-null for a device the bench prepared: where it stands on the
   *  qualification rule (see `BenchQualificationState`). Until `qualified`, no
   *  outage of it is announced. Null for a device the bench never prepared:
   *  `outageIsAnnounceable`'s other rule applies. */
  qualification: BenchQualificationView | null;
}
