/**
 * ObliWAN — the permanent health check of every device's management channel.
 *
 * WHAT IT IS FOR, IN ONE SENTENCE: knowing — without anybody pressing "Test
 * connection" — that a device has stopped answering, being told once when it
 * has been down long enough to matter, and being told when it comes back.
 *
 * It exists because of a concentrator. The production CHR's API failed for
 * three hours; presence wrote CONCENTRATOR_DEGRADED on every failed `listen`
 * and sweep, nothing ever wrote the recovery, and the page read "degraded" for
 * ever after the API was fixed. The check below is what proves, every interval,
 * that the CHR answers again — and the recovery it writes is what ends the
 * degraded-concentrator suppression of the devices behind it.
 *
 * ┌─ WHAT A CHECK IS, PER DEVICE ─────────────────────────────────────────────┐
 * │ Read-only, through channels that already exist, never a write, and never  │
 * │ a host taken from a request: the address comes from the device's own      │
 * │ transport row (or its tunnel_ip), exactly as `resolveRouterOsTarget` and  │
 * │ `diagnose.service.ts` take it.                                            │
 * │                                                                           │
 * │ The CHANNEL decides the method, not the brand: an enabled, complete       │
 * │ RouterOS API row first, then SSH / REST by the operator's priority —      │
 * │ except on a concentrator, which is judged by an API read or not at all.   │
 * │  concentrator   `/ppp/active/print` (`.id` only) over the pooled API      │
 * │                 session — the menu presence depends on, so "the check     │
 * │                 passes" and "presence can read" are the same statement.   │
 * │                 With no usable API row it is `no_channel`: a TCP answer   │
 * │                 on its SSH port would write UP over a presence that       │
 * │                 cannot read, and the two would overwrite each other's     │
 * │                 verdict every minute.                                     │
 * │  API channel    `/system/identity/print` over the pooled API session.     │
 * │  SSH / REST     a TCP connect to the SSH (22) or REST (443) port of the   │
 * │                 channel row. No login: the other brands' CLIs have no     │
 * │                 command this product has confirmed side-effect free (see  │
 * │                 `testTransport`), an SSH login per minute would flood the │
 * │                 device's log and the login attribution with our own       │
 * │                 sessions, and a SonicOS login costs a management slot.    │
 * │                 A REFUSED connection is a FAILURE here — the box is       │
 * │                 alive but its management service is not — which is the    │
 * │                 opposite of `tcpProbe()`, whose question is "is the SITE  │
 * │                 alive".                                                   │
 * │  behind a CHR   A device whose PPP session is down per presence is        │
 * │                 NEVER dialled. The check counts as FAILED, with the       │
 * │                 reason, and dials nothing; its reachability verdict keeps │
 * │                 coming from presence, exactly as before.                  │
 * │  no channel     TR-069-only CPE, SNMP-only device, an API row without a   │
 * │                 credential: not checked, and the page says so.            │
 * │  quarantined    not checked: it failed an identity assertion, so an       │
 * │                 "OK" from the box at its address is an OK about somebody  │
 * │                 else.                                                     │
 * │  disabled       never, and no row is written.                             │
 * │  pending        checked like an active device. The check asserts nothing  │
 * │                 about identity and writes nothing to the box; dialling a  │
 * │                 pending device is what "Test connection" already does,    │
 * │                 and no identity rule forbids a read.                      │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ STATE, VERDICTS AND ALERTS ──────────────────────────────────────────────┐
 * │ `device_health_checks` (migration 043), one row per device. `retries + 1` │
 * │ consecutive failures declare a device down (`down_since`); its alert is   │
 * │ raised once `down_since + health_alert_delay` has passed, ONCE per        │
 * │ outage, and never sooner than `notification_cooldown` after the previous  │
 * │ alert of the same device. A device that has never answered is shown down  │
 * │ and never announced (`outageIsAnnounceable`) — unless the bench prepared  │
 * │ it, in which case its QUALIFICATION decides instead (below). A recovery   │
 * │ notice follows only an outage that was announced.                         │
 * │                                                                           │
 * │ A REFUSED CERTIFICATE is not "not answering": when the check that makes   │
 * │ the outage due failed on the pool refusing the box's certificate against  │
 * │ the pin (directly, or through the breaker that refusal opened), and the   │
 * │ alert raised at that refusal — same presented fingerprint, on an enabled  │
 * │ TLS channel — exists (tlsPresented.service.ts, with both fingerprints),   │
 * │ the outage raises no live alert of its own: that one is its record. Any   │
 * │ other failure raises the generic alert, whatever certificate record the   │
 * │ channel still carries. The stamp and the channel message proceed as for   │
 * │ any outage.                                                               │
 * │                                                                           │
 * │ DELIVERY. The live alert is the durable record, and `alerted_at` is       │
 * │ stamped only AFTER it exists: a process killed between the state commit   │
 * │ and the alert, or a database error on the insert, leaves the outage       │
 * │ unannounced, and the next check raises it again (the live alert's stable  │
 * │ key keeps that from doubling while it is unread). The channel message     │
 * │ (Teams, e-mail, …) is sent by whichever check stamped, DETACHED from the  │
 * │ check: a hung SMTP relay delays a message, never the checking of the      │
 * │ fleet. It is at most once, like every other `sendForDevice` caller — a    │
 * │ failed channel is written to the notification log and not retried,        │
 * │ because `sendForDevice` cannot target one channel and a retry would       │
 * │ resend to every channel that did get it. A recovery notice is decided     │
 * │ once, under the row lock, and raised at most once.                        │
 * │                                                                           │
 * │ GROUPING. Past `HEALTH_ALERT_GROUP_AFTER` individual alerts in one        │
 * │ workspace within `HEALTH_ALERT_GROUP_WINDOW_SEC`, the next ones are       │
 * │ grouped into ONE alert per window (recovery notices are counted apart).   │
 * │ A degraded concentrator is covered; this covers the mass failure that is  │
 * │ not one — the host route to the tunnel subnet lost, L2TP down while       │
 * │ the CHR's API still answers.                                              │
 * │                                                                           │
 * │ Reachability verdicts are written for the CONCENTRATOR only, and only on  │
 * │ a transition (`recordVerdict` writes on change): UP when it answers,      │
 * │ CONCENTRATOR_DEGRADED via the existing degraded path when the failure is  │
 * │ confirmed. Every other device keeps its own verdict: the management check │
 * │ is not one of its four signals.                                           │
 * │                                                                           │
 * │ BENCH QUALIFICATION (operator rule 2026-10-04, benchQualification.        │
 * │ service.ts; it replaced the "in transit" rule of #28): a device whose     │
 * │ latest bench preparation was reported 'applied' is checked and recorded   │
 * │ like any other, and NOTHING about it is announced until it is QUALIFIED   │
 * │ for that preparation — its PPP session open without a break for an hour  │
 * │ right after the preparation, or fifteen minutes later on site. A box in   │
 * │ shipping answered at the bench (so `last_ok_at` is set) and then stopped, │
 * │ which is not an outage; a box on site whose API never answered but whose │
 * │ tunnel held is installed, and its outage is one. Each check evaluates     │
 * │ the rule before deciding (and stores a fresh qualification), and the view │
 * │ says where the device stands (`qualification`). An outage the box carried │
 * │ from before its qualification — its API failing while the tunnel was     │
 * │ qualifying — is re-dated to the qualification, so the alert delay and the │
 * │ "down since" of the message count from the moment it became alertable.    │
 * │                                                                           │
 * │ A device behind a degraded concentrator is not checked at all             │
 * │ (`skip_reason = 'parent_degraded'`), so it neither counts failures nor    │
 * │ raises anything — one alert on the CHR, not three hundred. The failures   │
 * │ it had counted before are DROPPED, unless they had already confirmed it   │
 * │ down: two failures taken through a dying tunnel and one taken while the   │
 * │ sessions re-dial hours later are not "consecutive".                       │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * LEADERSHIP: the scheduler runs on the leader only — two replicas would
 * double every dial and race every alert. "Check now" may run on any process,
 * like "Test connection"; the row lock below serialises it with the scheduler.
 *
 * THE BREAKER: every RouterOS read goes through `withConnection`, so an open
 * circuit refuses the dial (`CircuitOpenError`) and the check records a
 * failure with the breaker's own reason — it never hammers a box the pool has
 * given up on.
 *
 * NOT A DEVICE FAILURE: an error that belongs to ObliWAN — the target cannot
 * be resolved or its credential decrypted, the pool is shutting down, the
 * runtime is stopping — says nothing about the device. Such a check is
 * `aborted`: the device's state and failure count are left alone, the reason
 * goes to `last_error`, and the next check is scheduled as usual. Once
 * `stopHealthCheckRuntime()` has begun, nothing new is dispatched at all.
 *
 * THROUGHPUT: concentrators have their own lane and are planned every tick, so
 * a fleet-wide backlog never leaves the CHR's row stale (its verdict and the degraded-concentrator rule
 * read it). Everything else shares `HEALTH_CONCURRENCY` slots and is
 * dispatched without waiting for the previous tick's stragglers. Capacity is
 * slots / check duration: far beyond a few hundred devices at 10 s on warm API
 * sessions, but a mass timeout costs `device_timeout` per device per slot.
 * When the queue falls behind, the scheduler says so in the log, and the page
 * shows the consequence for what it is — `stale`, never a guess.
 */

import net from 'net';
import pLimit from 'p-limit';
import {
  HEALTH_ALERT_GROUP_AFTER,
  HEALTH_ALERT_GROUP_WINDOW_SEC,
  HEALTH_CHECK_METHOD,
  SETTINGS_KEYS,
  clampSetting,
  healthDisplay,
  outageIsAnnounceable,
  routerOsServiceRowNamed,
  type DeviceHealthCheckView,
  type DeviceHealthState,
  type HealthCheckChannel,
  type HealthSkipReason,
  type BenchQualificationView,
  type SettingsKey,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { leaderElection } from '../leaderElection';
import { settingsService } from '../settings.service';
import { liveAlertService } from '../liveAlert.service';
import { notificationService } from '../notification.service';
import { getRouterOsPool, resolveRouterOsTarget } from './routerosPool';
import { refusedCertificateOf } from '../transport/routeros';
import {
  assessDevice,
  isConcentratorDegraded,
  markConcentratorDegraded,
} from './reachability.service';
import { pppPresence } from './pppPresence.service';
import {
  armCrossing,
  benchQualificationView,
  resolveBenchQualification,
  startBenchQualificationRuntime,
  stopBenchQualificationRuntime,
  type BenchQualification,
} from './benchQualification.service';
import { certificateRefusalAnnounced } from './tlsPresented.service';
import { readActiveDefaultRoute } from './uplinkModel';
import { evaluateBackup4g, recordDefaultRoute } from './backup4g.service';
import { observeLteModems } from './lteModem.service';
import { downAlertDueAt, expectedCutUntil } from '../change/wanLinkWindow';
import {
  closedStoreRecoveryNotify,
  judgeClosedStore,
  recordClosedStoreAlert,
  type ChannelSeverity,
  type ClosedStoreVerdict,
} from './closedStoreAlerts.service';

// ============================================================================
// Tunables (not settings: they bound the SCHEDULER, not a device's policy)
// ============================================================================

/** How often the scheduler looks for due devices. Below the 10 s minimum
 *  interval, so a due device waits at most one tick plus its place in the
 *  queue. */
export const HEALTH_TICK_MS = 5_000;
/** Checks of non-concentrators in flight at once. Most are a read on a warm
 *  pooled session or a bare TCP connect, i.e. sockets waiting; the RouterOS
 *  pool's own dial budget (2/s) still paces every NEW session underneath,
 *  and a dial waiting for it is not a failure. */
const HEALTH_CONCURRENCY = 32;
/** The concentrators' own lane: a slow fleet must never delay them. */
const CONCENTRATOR_CONCURRENCY = 4;
/** Channel messages (Teams, e-mail, …) in flight at once, detached from the
 *  checks. A burst of alerts queues here, not in front of the next check. */
const DELIVERY_CONCURRENCY = 2;
/** How long shutdown waits for channel messages still being sent. */
const DELIVERY_DRAIN_MS = 10_000;
/** A queued check older than this means the scheduler is not keeping up. */
const BACKLOG_WARN_MS = 30_000;
/** At most one backlog warning per this period. */
const BACKLOG_WARN_EVERY_MS = 5 * 60_000;
/** Upper bound on how long a resolved setting is reused. A settings WRITE
 *  invalidates the cache at the next tick (see the fingerprint); this bound
 *  only covers what the fingerprint cannot see, e.g. a group re-parented. */
const SETTINGS_CACHE_TTL_MS = 5 * 60_000;
/** Jitter on each next check: at most 10 % of the interval, at most 15 s.
 *  Without it, 300 devices enrolled the same afternoon are checked in the same
 *  100 ms for ever. */
const JITTER_MAX_MS = 15_000;
const ERROR_MAX = 500;
const TCP_DEFAULT_PORT: Readonly<Record<'ssh' | 'rest', number>> = { ssh: 22, rest: 443 };

const PPP_DOWN_ERROR =
  'PPP session down on the concentrator: the device was not dialled.';

// ============================================================================
// Settings — resolved through the existing inheritance chain, cached briefly
// ============================================================================

export interface HealthSettings {
  intervalSec: number;
  retries: number;
  alertDelaySec: number;
  cooldownSec: number;
  /** `device_timeout`: the budget of one read or one TCP connect. */
  timeoutMs: number;
  /** `backup_4g_alert_delay`, minutes (0 = off). Optional so a caller that
   *  hands in its own settings need not know it: absent, it is resolved. */
  backup4gAlertMin?: number;
}

const HEALTH_SETTING_KEYS: SettingsKey[] = [
  SETTINGS_KEYS.HEALTH_CHECK_INTERVAL,
  SETTINGS_KEYS.HEALTH_CHECK_RETRIES,
  SETTINGS_KEYS.HEALTH_ALERT_DELAY,
  SETTINGS_KEYS.NOTIFICATION_COOLDOWN,
  SETTINGS_KEYS.DEVICE_TIMEOUT,
  SETTINGS_KEYS.BACKUP_4G_ALERT_DELAY,
];

/** Default → tenant global → group chain → device, via `settingsService`. */
export async function resolveHealthSettings(
  tenantId: number,
  deviceId: number,
  groupId: number | null,
): Promise<HealthSettings> {
  const resolved = await settingsService.resolveForDevice(tenantId, deviceId, groupId);
  const num = (key: SettingsKey): number => clampSetting(key, Number(resolved[key]?.value));
  return {
    intervalSec: num(SETTINGS_KEYS.HEALTH_CHECK_INTERVAL),
    retries: num(SETTINGS_KEYS.HEALTH_CHECK_RETRIES),
    alertDelaySec: num(SETTINGS_KEYS.HEALTH_ALERT_DELAY),
    cooldownSec: num(SETTINGS_KEYS.NOTIFICATION_COOLDOWN),
    timeoutMs: num(SETTINGS_KEYS.DEVICE_TIMEOUT),
    backup4gAlertMin: num(SETTINGS_KEYS.BACKUP_4G_ALERT_DELAY),
  };
}

const settingsCache = new Map<
  number,
  { tenantId: number; groupId: number | null; at: number; value: HealthSettings }
>();
let settingsFingerprint: string | null = null;

/**
 * One cheap query per tick: has any of the five keys been written or removed
 * anywhere since the last tick? If so the whole cache goes. That is what makes
 * "a settings change takes effect within one cycle" a property rather than a
 * hope — without it a 5-minute cache would be a 5-minute lag.
 */
async function refreshSettingsFingerprint(): Promise<void> {
  const row = await db('settings')
    .whereIn('key', HEALTH_SETTING_KEYS)
    .count<{ n: string | number; m: Date | null }[]>('id as n')
    .max('updated_at as m')
    .first();
  const fp = `${Number(row?.n ?? 0)}:${row?.m ? new Date(row.m).getTime() : 0}`;
  if (fp !== settingsFingerprint) {
    settingsCache.clear();
    settingsFingerprint = fp;
  }
}

async function settingsFor(d: {
  id: number;
  tenant_id: number;
  group_id: number | null;
}): Promise<HealthSettings> {
  const hit = settingsCache.get(d.id);
  if (
    hit &&
    hit.tenantId === d.tenant_id &&
    hit.groupId === d.group_id &&
    Date.now() - hit.at < SETTINGS_CACHE_TTL_MS
  ) {
    return hit.value;
  }
  const value = await resolveHealthSettings(d.tenant_id, d.id, d.group_id);
  settingsCache.set(d.id, { tenantId: d.tenant_id, groupId: d.group_id, at: Date.now(), value });
  return value;
}

// ============================================================================
// The probe — what a check DOES
// ============================================================================

/** How long an automatic api-ssl reading stays current (migration 064). */
const API_SSL_OBSERVE_EVERY_MS = 24 * 3600_000;

/**
 * api-ssl as the router serves it, read on the session the check already
 * holds, so the management-access card says what is on the router without
 * anybody queueing a job. Read-only, at most once a day per device. Filed
 * ONLY when the identity just read is this device's own: a tunnel
 * address answered by another box must never describe this one — so a device
 * whose identity is not on record yet is not observed. Never changes the
 * check's verdict: the caller swallows any failure.
 */
async function observeApiSsl(
  deviceId: number,
  conn: { query: (words: string[], opts?: { timeoutMs?: number }) => Promise<unknown> },
  identityRows: unknown,
  timeoutMs: number,
): Promise<void> {
  const row = (await db('devices').where({ id: deviceId }).first('system_identity', 'api_ssl_observed_at')) as
    | { system_identity: string | null; api_ssl_observed_at: Date | null }
    | undefined;
  if (!row || !row.system_identity) return;
  if (row.api_ssl_observed_at && Date.now() - new Date(row.api_ssl_observed_at).getTime() < API_SSL_OBSERVE_EVERY_MS) return;
  const first = Array.isArray(identityRows) ? (identityRows[0] as Record<string, unknown> | undefined) : undefined;
  if (String(first?.name ?? '') !== row.system_identity) return;

  const rows = await conn.query(['/ip/service/print', '?name=api-ssl'], { timeoutMs });
  // This read rides api-ssl: on RouterOS 7.24.5 its own session is listed as
  // a dynamic `/ip service` entry named api-ssl, with no address list and no
  // certificate. The CONFIGURED row only (shared/src/routerOsService.ts);
  // two of them are no reading, and nothing is filed.
  const pick = routerOsServiceRowNamed(Array.isArray(rows) ? (rows as Array<Record<string, unknown>>) : [], 'api-ssl');
  if (pick.kind === 'ambiguous') return;
  const r = pick.kind === 'row' ? pick.row : undefined;
  // Same shape as a management_access job's read-back (ServiceReading), so
  // both are judged by the same apiSslStateDifferences. No row = absent. The
  // list is `available-from` on recent RouterOS 7 (7.24.5), `address`
  // before: reading only the old name filed every 7.24.5 list as empty, i.e.
  // "open to every address".
  const service = r
    ? {
      disabled: String(r.disabled ?? ''),
      port: String(r.port ?? ''),
      address: String(r['available-from'] ?? r.address ?? ''),
      certificate: String(r.certificate ?? ''),
    }
    : null;
  const readAt = new Date();
  await db('devices').where({ id: deviceId }).update({
    api_ssl_observed: JSON.stringify({ service, readAt: readAt.toISOString() }),
    api_ssl_observed_at: readAt,
  });
}

/** A box whose Wi-Fi stack could not be read is not asked again before this. */
const WIFI_STACK_RETRY_MS = 24 * 3600_000;
const wifiStackAskedAt = new Map<number, number>();

/**
 * The Wi-Fi stack of a router that never went through a bench build that
 * records it (migration 063): a template reading `box.wifi_stack` refuses to
 * render without it. Read the way the bench reads it — `/interface/wifi`
 * answering means the wifi package, else `/interface/wireless` — on the
 * session the check already holds, ONLY while the column is empty and the
 * identity just read is this device's own. Never overwrites: the bench
 * owns the value once it has written one. Read-only on the router.
 */
export async function observeWifiStack(
  deviceId: number,
  conn: { query: (words: string[], opts?: { timeoutMs?: number }) => Promise<unknown> },
  identityRows: unknown,
  timeoutMs: number,
): Promise<void> {
  const last = wifiStackAskedAt.get(deviceId);
  if (last !== undefined && Date.now() - last < WIFI_STACK_RETRY_MS) return;
  const row = (await db('devices').where({ id: deviceId }).first('system_identity', 'wifi_stack')) as
    | { system_identity: string | null; wifi_stack: string | null }
    | undefined;
  if (!row || row.wifi_stack !== null || !row.system_identity) return;
  const first = Array.isArray(identityRows) ? (identityRows[0] as Record<string, unknown> | undefined) : undefined;
  if (String(first?.name ?? '') !== row.system_identity) return;

  wifiStackAskedAt.set(deviceId, Date.now());
  const answers = async (menu: string): Promise<boolean> => {
    try {
      await conn.query([`/interface/${menu}/print`, '=.proplist=name'], { timeoutMs });
      return true;
    } catch {
      return false; // a trap: the menu does not exist on this box
    }
  };
  const stack = (await answers('wifi')) ? 'wifi' : (await answers('wireless')) ? 'wireless' : null;
  if (stack === null) return;
  await db('devices').where({ id: deviceId }).whereNull('wifi_stack').update({ wifi_stack: stack });
  logger.info({ deviceId, wifiStack: stack }, 'Wi-Fi stack learned from the router');
}

/** How long a live default-route reading stays current (migration 073). Short
 *  on purpose: the reading exists to show a FAILOVER, and a failover is the
 *  moment an old reading stops being true. */
export const DEFAULT_ROUTE_OBSERVE_EVERY_MS = 5 * 60_000;
/** A box whose route table could not be read is not asked again before this. */
const defaultRouteFailedAt = new Map<number, number>();

/**
 * The default route the router's table has ACTIVE, read on the session the
 * check already holds, so the uplink card's "routing says" answers on a fleet
 * whose WAN1 route has an IP gateway and whose LTE route is dynamic (neither
 * names an interface in a snapshot). Read-only, at most every five minutes per
 * device. Filed ONLY when the identity just read is this device's own,
 * exactly like `observeApiSsl`. Never changes the check's verdict: the caller
 * swallows any failure, and a failed read stores NOTHING — the previous
 * reading keeps its own, older, time.
 *
 * No `.proplist` and no `?active=` word: the properties differ between
 * RouterOS 6 (`gateway-status`, `routing-mark`) and 7 (`immediate-gw`,
 * `routing-table`), the default routes are a handful of rows, and
 * `readActiveDefaultRoute` filters active / table / distance locally.
 */
export async function observeDefaultRoute(
  deviceId: number,
  conn: { query: (words: string[], opts?: { timeoutMs?: number }) => Promise<unknown> },
  identityRows: unknown,
  timeoutMs: number,
): Promise<void> {
  const failed = defaultRouteFailedAt.get(deviceId);
  if (failed !== undefined && Date.now() - failed < DEFAULT_ROUTE_OBSERVE_EVERY_MS) return;
  const row = (await db('devices').where({ id: deviceId }).first('system_identity', 'default_route_observed_at')) as
    | { system_identity: string | null; default_route_observed_at: Date | null }
    | undefined;
  if (!row || !row.system_identity) return;
  if (
    row.default_route_observed_at &&
    Date.now() - new Date(row.default_route_observed_at).getTime() < DEFAULT_ROUTE_OBSERVE_EVERY_MS
  ) {
    return;
  }
  const first = Array.isArray(identityRows) ? (identityRows[0] as Record<string, unknown> | undefined) : undefined;
  if (String(first?.name ?? '') !== row.system_identity) return;

  let rows: unknown;
  try {
    rows = await conn.query(['/ip/route/print', '?dst-address=0.0.0.0/0'], { timeoutMs });
  } catch (err) {
    defaultRouteFailedAt.set(deviceId, Date.now());
    throw err;
  }
  defaultRouteFailedAt.delete(deviceId);
  const route = readActiveDefaultRoute(rows);
  // Also dates the route (`default_route_since`) and records a move in the
  // transition history (migration 075, backup4g.service.ts).
  await recordDefaultRoute(deviceId, route);
}

interface DeviceFacts {
  id: number;
  tenant_id: number;
  group_id: number | null;
  name: string;
  status: string;
  role: string;
  concentrator_id: number | null;
  ppp_username: string | null;
  tunnel_ip: string | null;
  /** The store whose opening hours lower an alert raised while it is closed. */
  site_id: number | null;
}

type Outcome =
  | { kind: 'skip'; reason: HealthSkipReason; detail: string | null }
  | { kind: 'ok'; channel: HealthCheckChannel; ms: number }
  | {
      kind: 'fail';
      channel: HealthCheckChannel;
      error: string;
      dialled: boolean;
      /** The fingerprint the box presented, when THIS failure is the pool
       *  refusing its certificate against the pin (`refusedCertificateOf`);
       *  null for every other failure. */
      refusedCertificate: string | null;
    }
  /** ObliWAN could not run the check (see the header): not the device's fault. */
  | { kind: 'aborted'; reason: string };

/** Set once `stopHealthCheckRuntime()` has begun. Never reset: a stopped
 *  runtime is a process on its way out. */
let stopping = false;

interface ChannelChoice {
  channel: HealthCheckChannel;
  host: string;
  port: number | null;
}

function bound(message: string): string {
  return message.length > ERROR_MAX ? `${message.slice(0, ERROR_MAX - 1)}…` : message;
}

function errorText(err: unknown): string {
  // The transport layer never puts a credential in an Error string (its own
  // self-test proves it); this only bounds the length.
  return bound(err instanceof Error ? err.message : String(err));
}

/**
 * An enabled `routeros_api` row the check would actually dial: a host (or the
 * device's tunnel IP), a username and a credential in the vault. The ONE rule
 * — `pickChannel` and the uplink verdict's "why the live route is not read"
 * (`uplink.service.ts`) both call it, so they cannot disagree.
 */
export function routerOsApiChannelUsable(
  row: { host: string | null; username: string | null; secret_enc: string | null },
  tunnelIp: string | null,
): boolean {
  return !!((row.host ?? tunnelIp) && row.username && row.secret_enc);
}

/**
 * The management channel to check, or why there is none.
 *
 * RouterOS API first: it is a real read on a session the pool keeps open
 * anyway. Then SSH and REST by the operator's priority. A channel counts only
 * when it is enabled and complete enough to be dialled — an API row without a
 * credential would fail every check and page somebody about a form left half
 * filled in, which is not an outage.
 *
 * A CONCENTRATOR gets no fallback: it is judged by an API read or not at all
 * (see the header).
 */
async function pickChannel(
  device: DeviceFacts,
): Promise<{ choice: ChannelChoice | null; why: string | null }> {
  const rows = await db('device_transports')
    .where({ device_id: device.id, enabled: true })
    .whereIn('transport', ['routeros_api', 'ssh', 'rest'])
    .orderBy('priority')
    .select<
      Array<{
        transport: HealthCheckChannel;
        host: string | null;
        port: number | null;
        username: string | null;
        secret_enc: string | null;
      }>
    >('transport', 'host', 'port', 'username', 'secret_enc');

  const reasons: string[] = [];
  const api = rows.find((r) => r.transport === 'routeros_api');
  if (api) {
    const host = api.host ?? device.tunnel_ip;
    if (host && routerOsApiChannelUsable(api, device.tunnel_ip)) {
      return { choice: { channel: 'routeros_api', host, port: api.port }, why: null };
    }
    reasons.push(
      `routeros_api is incomplete (${[
        host ? null : 'no host and no tunnel IP',
        api.username ? null : 'no username',
        api.secret_enc ? null : 'no credential in the vault',
      ].filter(Boolean).join(', ')})`,
    );
  }
  if (device.role === 'concentrator') {
    return {
      choice: null,
      why:
        'A concentrator is checked only by a RouterOS API read — presence reads /ppp/active '
        + 'through it, and an answer on another port would prove nothing about that. '
        + (reasons.length > 0 ? `${reasons.join('; ')}.` : 'It has no enabled RouterOS API channel.'),
    };
  }
  for (const r of rows) {
    if (r.transport === 'routeros_api') continue;
    const host = r.host ?? device.tunnel_ip;
    if (host) return { choice: { channel: r.transport, host, port: r.port }, why: null };
    reasons.push(`${r.transport} has no host and the device no tunnel IP`);
  }
  return {
    choice: null,
    why: reasons.length > 0
      ? `No usable management channel: ${reasons.join('; ')}.`
      : 'No management channel: no enabled RouterOS API, SSH or REST channel.',
  };
}

/** A TCP connect and nothing else. Refused is a FAILURE here (see the header). */
function tcpConnect(
  host: string,
  port: number,
  timeoutMs: number,
): Promise<{ ok: boolean; error: string | null; ms: number }> {
  const started = Date.now();
  return new Promise((resolve) => {
    let settled = false;
    const socket = net.createConnection({ host, port, timeout: timeoutMs });
    const done = (ok: boolean, error: string | null): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ ok, error, ms: Date.now() - started });
    };
    socket.on('connect', () => done(true, null));
    socket.on('timeout', () => done(false, `TCP ${host}:${port}: no answer within ${timeoutMs} ms`));
    socket.on('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'ECONNREFUSED') {
        done(false, `TCP ${host}:${port}: connection refused — the box answered, but nothing listens on that port`);
      } else {
        done(false, `TCP ${host}:${port}: ${err.code ?? err.message}`);
      }
    });
  });
}

async function pppSessionOpen(device: DeviceFacts): Promise<boolean> {
  // The same predicate `assessDevice()` uses for `pppUp`.
  const open = await db('ppp_sessions')
    .where({ concentrator_id: device.concentrator_id, ppp_username: device.ppp_username })
    .whereNull('ended_at')
    .first('id');
  return !!open;
}

async function probe(device: DeviceFacts, settings: HealthSettings): Promise<Outcome> {
  if (device.status === 'quarantined') {
    return {
      kind: 'skip',
      reason: 'quarantined',
      detail: 'Quarantined: the box at this address failed an identity check, so its answer would not be about this device.',
    };
  }

  const { choice, why } = await pickChannel(device);
  if (!choice) return { kind: 'skip', reason: 'no_channel', detail: why };

  // Behind a concentrator, presence decides whether we may dial at all.
  // A device with a concentrator but no PPP account has no presence to ask and
  // is checked directly, like a standalone one.
  if (device.role !== 'concentrator' && device.concentrator_id !== null && device.ppp_username) {
    if (await isConcentratorDegraded(device.concentrator_id)) {
      return {
        kind: 'skip',
        reason: 'parent_degraded',
        detail: 'Its concentrator is degraded: devices behind it are not checked.',
      };
    }
    if (!(await pppSessionOpen(device))) {
      return { kind: 'fail', channel: choice.channel, error: PPP_DOWN_ERROR, dialled: false, refusedCertificate: null };
    }
  }

  if (choice.channel === 'routeros_api') {
    // Resolving the target reads the row again and DECRYPTS the credential.
    // Nothing has been sent to the device yet, so whatever fails here — a
    // vault that cannot decrypt, a row edited since `pickChannel` — is ours.
    let target: Awaited<ReturnType<typeof resolveRouterOsTarget>>;
    try {
      target = await resolveRouterOsTarget(device.id);
    } catch (err) {
      return { kind: 'aborted', reason: `ObliWAN could not prepare the check: ${errorText(err)}` };
    }
    const pool = getRouterOsPool();
    const started = Date.now();
    try {
      const words = device.role === 'concentrator'
        ? ['/ppp/active/print', '=.proplist=.id']
        : ['/system/identity/print'];
      let ms = 0;
      await pool.withConnection(target, async (conn) => {
        const rows = await conn.query(words, { timeoutMs: settings.timeoutMs });
        ms = Date.now() - started;
        if (device.role !== 'concentrator') {
          await observeApiSsl(device.id, conn, rows, settings.timeoutMs).catch((err: unknown) => {
            logger.debug({ err, deviceId: device.id }, 'api-ssl observation skipped');
          });
          await observeWifiStack(device.id, conn, rows, settings.timeoutMs).catch((err: unknown) => {
            logger.debug({ err, deviceId: device.id }, 'Wi-Fi stack observation skipped');
          });
          await observeDefaultRoute(device.id, conn, rows, settings.timeoutMs).catch((err: unknown) => {
            logger.debug({ err, deviceId: device.id }, 'default route observation skipped');
          });
          // The SIM card in every LTE modem (migration 080, lteModem.service.ts).
          await observeLteModems(device.id, conn, rows, settings.timeoutMs).catch((err: unknown) => {
            logger.debug({ err, deviceId: device.id }, 'LTE modem observation skipped');
          });
        }
      });
      return { kind: 'ok', channel: 'routeros_api', ms };
    } catch (err) {
      // A pool that began shutting down refuses or tears down the session:
      // that is the process stopping, not the device failing.
      if (pool.isShuttingDown || stopping) {
        return { kind: 'aborted', reason: `ObliWAN was stopping: ${errorText(err)}` };
      }
      // An open breaker lands here too, as a failure carrying the breaker's own
      // reason: no socket was opened, which is the breaker's whole point.
      return {
        kind: 'fail',
        channel: 'routeros_api',
        error: errorText(err),
        dialled: true,
        refusedCertificate: refusedCertificateOf(err),
      };
    }
  }

  const port = choice.port ?? TCP_DEFAULT_PORT[choice.channel];
  const r = await tcpConnect(choice.host, port, settings.timeoutMs);
  return r.ok
    ? { kind: 'ok', channel: choice.channel, ms: r.ms }
    : {
        kind: 'fail',
        channel: choice.channel,
        error: bound(r.error ?? 'unknown error'),
        dialled: true,
        refusedCertificate: null,
      };
}

// ============================================================================
// State — one row per device, under a row lock
// ============================================================================

interface HealthRow {
  device_id: number;
  state: DeviceHealthState;
  consecutive_failures: number;
  channel: HealthCheckChannel | null;
  skip_reason: HealthSkipReason | null;
  interval_sec: number | null;
  last_check_at: Date | null;
  last_ok_at: Date | null;
  down_since: Date | null;
  alerted_at: Date | null;
  next_check_at: Date | null;
  last_error: string | null;
}

interface Applied {
  before: HealthRow;
  after: HealthRow;
  /** `down` / `up` when the state crossed that edge on this check. */
  transition: 'down' | 'up' | null;
  /**
   * What is DUE to be announced once the transaction has committed. A `down`
   * is not yet stamped: `alerted_at` is written by `announce()` only after
   * the live alert exists, so an announcement lost on the way is raised again
   * by the next check instead of being recorded as sent.
   */
  announce: 'down' | 'up' | null;
  /** The device is a bench-prepared router not yet qualified for its latest
   *  preparation: nothing about it is announced (benchQualification). */
  alertsHeld: boolean;
}

function nextCheckAt(now: Date, intervalSec: number): Date {
  const jitter = Math.floor(Math.random() * Math.min(JITTER_MAX_MS, intervalSec * 100));
  return new Date(now.getTime() + intervalSec * 1000 + jitter);
}

/** The down alert of THIS outage was raised (as opposed to a previous one). */
function alertedThisOutage(row: Pick<HealthRow, 'alerted_at' | 'down_since'>): boolean {
  return !!row.alerted_at && !!row.down_since && row.alerted_at.getTime() >= row.down_since.getTime();
}

async function applyOutcome(
  device: DeviceFacts,
  settings: HealthSettings,
  outcome: Exclude<Outcome, { kind: 'aborted' }>,
  clock: Date,
  /** Null for a device the qualification rule does not concern. */
  qualification: BenchQualification | null = null,
  /** The end of a planned WAN link cut covering this check (wanLinkWindow.ts):
   *  the down alert is not due before it. Null = no planned cut. */
  cutUntil: Date | null = null,
): Promise<Applied> {
  return db.transaction(async (trx) => {
    await trx('device_health_checks').insert({ device_id: device.id }).onConflict('device_id').ignore();
    const before = await trx('device_health_checks')
      .where({ device_id: device.id })
      .forUpdate()
      .first<HealthRow>();

    // Never record a check BEFORE the last one. "Check now" may run on another
    // process than the scheduler, and two clocks (or one NTP step) disagree by
    // a little; the row's own CHECK (last_ok_at <= last_check_at) would refuse
    // the write and the observation would be lost.
    const floor = Math.max(before.last_check_at?.getTime() ?? 0, before.last_ok_at?.getTime() ?? 0);
    const now = clock.getTime() < floor ? new Date(floor) : clock;

    let next = nextCheckAt(now, settings.intervalSec);
    let after: HealthRow;
    let transition: Applied['transition'] = null;
    let announce: Applied['announce'] = null;
    const qualificationState = qualification?.verdict.state ?? null;
    const alertsHeld = qualificationState !== null && qualificationState !== 'qualified';

    if (outcome.kind === 'skip') {
      if (outcome.reason === 'parent_degraded') {
        // Suppressed, not judged. A CONFIRMED outage stays as it was — its
        // clock, its count, its alert — because it was confirmed before the
        // parent failed. Failures that had not confirmed anything are dropped:
        // they were most likely taken through the dying tunnel, and adding
        // them to a failure taken hours later, while the sessions re-dial,
        // would declare the site down on evidence from both ends of an outage
        // that was not its own.
        after = {
          ...before,
          consecutive_failures: before.state === 'down' ? before.consecutive_failures : 0,
          skip_reason: 'parent_degraded',
          next_check_at: next,
          interval_sec: settings.intervalSec,
        };
      } else {
        // We can no longer ask, so we no longer know. An outage in progress is
        // dropped WITHOUT a recovery notice: nothing says it recovered.
        if (before.state === 'down') {
          logger.warn(
            { deviceId: device.id, reason: outcome.reason },
            'Health check: a down device became uncheckable; its outage is closed without a recovery notice',
          );
        }
        after = {
          ...before,
          state: 'unknown',
          consecutive_failures: 0,
          down_since: null,
          channel: null,
          skip_reason: outcome.reason,
          last_error: outcome.detail ? bound(outcome.detail) : null,
          next_check_at: next,
          interval_sec: settings.intervalSec,
        };
      }
    } else if (outcome.kind === 'ok') {
      transition = before.state !== 'up' ? 'up' : null;
      if (before.state === 'down' && alertedThisOutage(before)) announce = 'up';
      after = {
        ...before,
        state: 'up',
        consecutive_failures: 0,
        channel: outcome.channel,
        skip_reason: null,
        last_check_at: now,
        last_ok_at: now,
        down_since: null,
        last_error: null,
        next_check_at: next,
        interval_sec: settings.intervalSec,
      };
    } else {
      const failures = before.consecutive_failures + 1;
      const confirmed = before.state === 'down' || failures >= settings.retries + 1;
      const state: DeviceHealthState = confirmed ? 'down' : before.state;
      let downSince = confirmed ? (before.state === 'down' && before.down_since ? before.down_since : now) : null;
      if (confirmed && before.state !== 'down') transition = 'down';

      // A bench router not yet qualified is not announced. One that qualified
      // while this outage was already running — its API failing while its
      // tunnel held — carries an outage that began before it was alertable:
      // re-dated to the qualification (header box, BENCH QUALIFICATION).
      const qualifiedAt = qualification?.verdict.state === 'qualified' ? qualification.verdict.qualifiedAt : null;
      if (
        qualifiedAt &&
        downSince &&
        before.state === 'down' &&
        downSince.getTime() < qualifiedAt.getTime() &&
        qualifiedAt.getTime() <= now.getTime()
      ) {
        downSince = qualifiedAt;
      }

      if (
        confirmed &&
        downSince &&
        outageIsAnnounceable(before.last_ok_at, qualificationState) &&
        !alertedThisOutage({ alerted_at: before.alerted_at, down_since: downSince })
      ) {
        // A planned WAN link cut holds the alert until it ends, never the
        // outage's own start (down_since stays the truth).
        const dueAt = downAlertDueAt(downSince, settings.alertDelaySec, cutUntil);
        const cooldownEnds = before.alerted_at
          ? before.alerted_at.getTime() + settings.cooldownSec * 1000
          : 0;
        if (now.getTime() >= dueAt && now.getTime() >= cooldownEnds) {
          // Due. NOT stamped here: see `Applied.announce`.
          announce = 'down';
        } else {
          // Come back when the alert becomes due rather than a whole interval
          // later: with a one-hour interval and a five-minute delay, the alert
          // would otherwise be fifty-five minutes late.
          const wakeAt = Math.max(dueAt, cooldownEnds, now.getTime() + 1000);
          if (wakeAt < next.getTime()) next = new Date(wakeAt);
        }
      }

      after = {
        ...before,
        state,
        consecutive_failures: failures,
        channel: outcome.channel,
        skip_reason: null,
        last_check_at: now,
        down_since: downSince,
        last_error: bound(outcome.error),
        next_check_at: next,
        interval_sec: settings.intervalSec,
      };
    }

    await trx('device_health_checks')
      .where({ device_id: device.id })
      .update({
        state: after.state,
        consecutive_failures: after.consecutive_failures,
        channel: after.channel,
        skip_reason: after.skip_reason,
        interval_sec: after.interval_sec,
        last_check_at: after.last_check_at,
        last_ok_at: after.last_ok_at,
        down_since: after.down_since,
        alerted_at: after.alerted_at,
        next_check_at: after.next_check_at,
        last_error: after.last_error,
      });
    return { before, after, transition, announce, alertsHeld };
  });
}

// ============================================================================
// Announcements — the existing live-alert + notification pipeline
// ============================================================================

/** Serialises the RAISING of alerts in this process, so the grouping count
 *  read before an alert is the count that alert is added to. Database work
 *  only — the channel messages are not in here. */
const announceLimit = pLimit(1);
/** Channel messages, detached from the checks (see the header, DELIVERY). */
const deliveryLimit = pLimit(DELIVERY_CONCURRENCY);
const pendingDeliveries = new Set<Promise<void>>();

function deliverDetached(what: string, deviceId: number | null, send: () => Promise<void>): void {
  const p: Promise<void> = deliveryLimit(send)
    .catch((err: unknown) => {
      // `sendForDevice` already logs each failed channel in the notification
      // log; this only catches what fails before it gets that far.
      logger.warn({ err, deviceId, what }, 'Health notification failed (the live alert is raised)');
    })
    .finally(() => {
      pendingDeliveries.delete(p);
    });
  pendingDeliveries.add(p);
}

/**
 * Wait for every channel message already handed to the delivery queue. For
 * shutdown and for a harness; nothing on the check path awaits it.
 */
export async function flushHealthNotifications(): Promise<void> {
  while (pendingDeliveries.size > 0) {
    await Promise.allSettled(Array.from(pendingDeliveries));
  }
}

/** Individual health alerts of one kind raised in a workspace within the
 *  grouping window — on the DATABASE clock, the one `created_at` was set by. */
async function individualAlertsInWindow(tenantId: number, kind: 'down' | 'up'): Promise<number> {
  const row = await db('live_alerts')
    .where({ tenant_id: tenantId })
    .where('stable_key', 'like', `health-${kind}:%`)
    .whereRaw('created_at > now() - make_interval(secs => ?)', [HEALTH_ALERT_GROUP_WINDOW_SEC])
    .count<{ n: string | number }[]>('id as n')
    .first();
  return Number(row?.n ?? 0);
}

/**
 * The open workspace-wide incident per tenant, for ticketing channels: each
 * mass outage gets its OWN key (its first window), and the mass recovery that
 * follows closes that one. A constant key made every later outage dedupe into
 * a ticket that, when recoveries trickled back one by one, was never closed.
 * In memory: after a restart the next mass recovery closes nothing, and the
 * open ticket is closed by hand — no worse than before.
 */
const openGroupIncident = new Map<number, string>();

/** The ONE alert of a grouping window, and its one workspace-level message. */
function groupIncidentKey(tenantId: number, kind: 'down' | 'up', bucket: number): string {
  if (kind === 'down') {
    const open = openGroupIncident.get(tenantId) ?? `obliwan:tenant:${tenantId}:health-group:${bucket}`;
    openGroupIncident.set(tenantId, open);
    return open;
  }
  const open = openGroupIncident.get(tenantId) ?? `obliwan:tenant:${tenantId}:health-group`;
  openGroupIncident.delete(tenantId);
  return open;
}

async function raiseGroupAlert(tenantId: number, kind: 'down' | 'up'): Promise<void> {
  const bucket = Math.floor(Date.now() / (HEALTH_ALERT_GROUP_WINDOW_SEC * 1000));
  const minutes = Math.round(HEALTH_ALERT_GROUP_WINDOW_SEC / 60);
  const title = kind === 'down' ? 'Many devices stopped answering' : 'Many devices are answering again';
  const message = kind === 'down'
    ? `More than ${HEALTH_ALERT_GROUP_AFTER} devices of this workspace were announced down within `
      + `${minutes} minutes. The next ones are grouped into this alert instead of one message each, `
      + 'until the rate falls. Each device page shows its own state, and the device list shows '
      + 'which devices are down.'
    : `More than ${HEALTH_ALERT_GROUP_AFTER} devices of this workspace were announced back within `
      + `${minutes} minutes. The next recoveries are grouped into this notice instead of one message each.`;
  const raised = await liveAlertService.add(tenantId, {
    severity: kind,
    title,
    message,
    // No subject: "many devices came back" names no equipment, so it is a
    // tenant-level alert, visible to every member of the workspace.
    navigateTo: '/devices',
    stableKey: `health-group-${kind}:${tenantId}:${bucket}`,
  });
  if (raised === null) return;
  deliverDetached(`group-${kind}`, null, () =>
    notificationService.sendForTenant(tenantId, `health_group_${kind}`, {
      entityName: 'Permanent check',
      entityUrl: '/devices',
      oldStatus: kind === 'down' ? 'up' : 'down',
      newStatus: kind,
      message,
      timestamp: new Date().toISOString(),
      // One ticket for the workspace-wide incident: opened by the grouped
      // down, closed by the grouped up (sent only when recoveries are mass).
      stableKey: groupIncidentKey(tenantId, kind, bucket),
      severity: 'critical',
      isRecovery: kind === 'up',
      entityId: tenantId,
      entityType: 'tenant',
    }),
  );
}

/**
 * Raise what `applyOutcome` found due, AFTER its transaction committed.
 * Returns what was actually announced (individually or grouped).
 *
 * A `down` is stamped (`alerted_at`) only once its live alert exists, and only
 * by the check whose conditional UPDATE wins — that check, and no other, sends
 * the channel message. If the insert throws, nothing is stamped and the next
 * check tries again.
 *
 * `refusedCertificate` is what THIS check failed on, when it failed on the
 * pool refusing the box's certificate (the fingerprint presented), else null.
 */
async function announce(
  device: DeviceFacts,
  applied: Applied,
  refusedCertificate: string | null,
): Promise<'down' | 'up' | null> {
  const kind = applied.announce;
  if (!kind) return null;
  // The outage's own instant keys both messages, so the down alert and its
  // recovery pair up, and a new outage is always a new key.
  const downSince = kind === 'down' ? applied.after.down_since : applied.before.down_since;
  if (!downSince) return null;
  // The instant of this check as recorded (never before the previous one).
  const at = applied.after.last_check_at ?? new Date();
  const key = `health-${kind}:${device.id}:${downSince.getTime()}`;

  let message: string;
  let title: string;
  if (kind === 'down') {
    title = `${device.name} is not answering`;
    message =
      `${device.name} has been down since ${downSince.toISOString()} ` +
      `(${applied.after.consecutive_failures} consecutive failed checks). ` +
      `Last error: ${applied.after.last_error ?? 'none recorded'}`;
    if (device.role === 'concentrator') {
      const [{ count }] = await db('devices')
        .where({ concentrator_id: device.id })
        .count<{ count: string }[]>('id as count');
      if (Number(count) > 0) {
        message += ` — the ${Number(count)} device(s) behind it are not checked while it is down.`;
      }
    }
  } else {
    title = `${device.name} is answering again`;
    message =
      `${device.name} answered its management channel at ${at.toISOString()}, ` +
      `after an outage that started at ${downSince.toISOString()}.`;
  }

  return announceLimit(async () => {
    const grouped =
      (await individualAlertsInWindow(device.tenant_id, kind)) >= HEALTH_ALERT_GROUP_AFTER;
    let raisedNew = false;
    // Opening hours (migration 096): a down alert raised while the store is
    // closed is one level lower, marked « magasin fermé », and raised again
    // at the opening if the outage is still there (closedStoreAlerts.service).
    let closed: ClosedStoreVerdict = { closed: false };
    if (grouped) {
      await raiseGroupAlert(device.tenant_id, kind);
    } else if (
      kind === 'down' &&
      refusedCertificate !== null &&
      (await certificateRefusalAnnounced(device.id, device.tenant_id, refusedCertificate))
    ) {
      // This check failed because the box answered with a certificate other
      // than the pinned one, and the alert raised at that refusal already says
      // so, with both fingerprints and what to do. "Not answering" on top of it
      // would be a second, vaguer alert about the same fact. That alert is
      // this outage's durable record, so the stamp below proceeds. Any other
      // failure — a dead box, a timeout, a cleartext channel — raises the
      // generic alert whatever certificate record the channel still carries:
      // the record says what a past handshake met, not why this check failed.
    } else {
      if (kind === 'down') {
        closed = await judgeClosedStore({
          tenantId: device.tenant_id,
          deviceId: device.id,
          groupId: device.group_id,
          siteId: device.site_id,
          severity: 'down',
          channelSeverity: 'critical',
          title,
          message,
          at,
        });
      }
      const raised = await liveAlertService.add(device.tenant_id, {
        severity: closed.closed ? closed.liveSeverity : kind,
        title: closed.closed ? closed.title : title,
        message: closed.closed ? closed.message : message,
        navigateTo: `/devices/${device.id}`,
        deviceId: device.id,
        stableKey: key,
      });
      raisedNew = raised !== null;
    }

    if (kind === 'down') {
      // THE STAMP, now that the alert exists. Conditional on the outage still
      // being this one and still unannounced: a recovery, or another check
      // that got here first, leaves nothing to stamp and nothing to send.
      const stamped = await db('device_health_checks')
        .where({ device_id: device.id, state: 'down', down_since: downSince })
        .where((q) => q.whereNull('alerted_at').orWhere('alerted_at', '<', downSince))
        .update({ alerted_at: at });
      if (stamped === 0) return null;
      // Sent by the stamper, whether or not its live-alert insert was the
      // first: a previous attempt that inserted and then died never reached
      // its send, because the send comes after the stamp.
      if (!grouped && closed.closed) {
        // Recorded for the opening; the channels hear of it now (lowered) or
        // at the opening, per `closed_store_notify`.
        await recordClosedStoreAlert({
          tenantId: device.tenant_id,
          deviceId: device.id,
          siteId: device.site_id,
          kind: 'health_down',
          episodeAt: downSince,
          normalSeverity: 'down',
          title,
          message,
          navigateTo: `/devices/${device.id}`,
          stableKey: key,
          notification: deviceMessagePayload(device, kind, message, at, downSince),
          notifiedAtRaise: closed.notify === 'now',
          opensAt: closed.opensAt,
        }).catch((err: unknown) =>
          logger.warn({ err, deviceId: device.id }, 'Closed store: the lowered alert was not recorded, it will not be raised again at the opening'),
        );
        if (closed.notify === 'now') {
          sendDeviceMessage(device, kind, closed.message, at, downSince, undefined, closed.channelSeverity);
        }
      } else if (!grouped) {
        sendDeviceMessage(device, kind, message, at, downSince);
      }
      return 'down';
    }
    // A recovery is decided under the row lock, so exactly one check gets
    // here per outage; the live alert's novelty still guards the channel. A
    // store-closed outage the channels never heard of (wait for the opening)
    // has its recovery kept off them too.
    if (!grouped && raisedNew && (await closedStoreRecoveryNotify(device.id, 'health_down', downSince))) {
      sendDeviceMessage(device, kind, message, at, downSince);
    }
    // Folded into the grouped notice: the other channels hear nothing, but a
    // ticket this device's own down opened must still be closed.
    else if (grouped) sendDeviceMessage(device, kind, message, at, downSince, ['oblidesk']);
    return 'up';
  });
}

/** The channel message of a down or a recovery (also stored, for a store
 *  closed at the raise, to be sent at its opening). */
function deviceMessagePayload(
  device: DeviceFacts,
  kind: 'down' | 'up',
  message: string,
  at: Date,
  downSince: Date,
  onlyChannelTypes?: string[],
  severity: ChannelSeverity = 'critical',
) {
  return {
    entityName: device.name,
    entityUrl: `/devices/${device.id}`,
    oldStatus: kind === 'down' ? 'up' : 'down',
    newStatus: kind,
    message,
    timestamp: at.toISOString(),
    // The incident is the device being down: the same key opens and closes it.
    stableKey: `obliwan:device:${device.id}:down`,
    severity,
    isRecovery: kind === 'up',
    occurredAt: downSince.toISOString(),
    ...(kind === 'up' ? { recoveredAt: at.toISOString() } : {}),
    entityId: device.id,
    entityType: 'device' as const,
    ...(onlyChannelTypes ? { onlyChannelTypes } : {}),
  };
}

function sendDeviceMessage(
  device: DeviceFacts,
  kind: 'down' | 'up',
  message: string,
  at: Date,
  downSince: Date,
  onlyChannelTypes?: string[],
  severity: ChannelSeverity = 'critical',
): void {
  deliverDetached(kind, device.id, () =>
    notificationService.sendForDevice(
      device.tenant_id,
      device.id,
      device.group_id,
      deviceMessagePayload(device, kind, message, at, downSince, onlyChannelTypes, severity),
    ),
  );
}

// ============================================================================
// One check
// ============================================================================

export interface HealthCheckResult {
  deviceId: number;
  /**
   * `never`: disabled, nothing written. `gone`: the device does not exist.
   * `aborted`: ObliWAN could not run the check (see the header) — the
   * device's state and failure count were not touched.
   */
  outcome: 'ok' | 'fail' | 'skip' | 'never' | 'gone' | 'aborted';
  /** True when a socket was opened or a pooled session was used. */
  dialled: boolean;
  transition: 'down' | 'up' | null;
  /** What was actually announced — raised and, for a down, stamped. */
  announced: 'down' | 'up' | null;
  state: DeviceHealthState | null;
  /** Set when `outcome` is `aborted`. */
  abortReason?: string;
  /** True when the device is a bench-prepared router not yet qualified: no
   *  outage of it is announced (benchQualification). */
  alertsHeld?: boolean;
  /** Where a bench-prepared device stands on the qualification rule as this
   *  check found it; null for a device the rule does not concern. */
  qualification?: BenchQualification['verdict']['state'] | null;
}

const inFlight = new Map<number, Promise<HealthCheckResult>>();

async function loadDevice(deviceId: number): Promise<DeviceFacts | undefined> {
  return db('devices')
    .where({ id: deviceId })
    .first<DeviceFacts | undefined>(
      'id', 'tenant_id', 'group_id', 'name', 'status', 'role',
      'concentrator_id', 'ppp_username', 'tunnel_ip', 'site_id',
    );
}

/**
 * A check that could not be run: the state, the failure count and the outage
 * clock stay as they were — a vault that cannot decrypt is not a site that
 * went down. The reason is kept for the page and the next check is scheduled
 * as usual, so a fault on our side is neither hammered nor hidden; the row
 * turns `stale` on the page if it lasts.
 */
async function recordAborted(
  device: DeviceFacts,
  settings: HealthSettings,
  reason: string,
  clock: Date,
): Promise<void> {
  await db('device_health_checks').insert({ device_id: device.id }).onConflict('device_id').ignore();
  await db('device_health_checks')
    .where({ device_id: device.id })
    .update({
      next_check_at: nextCheckAt(clock, settings.intervalSec),
      interval_sec: settings.intervalSec,
      last_error: bound(`Not checked: ${reason}`),
    });
}

async function runCheck(
  deviceId: number,
  opts: { now?: Date; settings?: HealthSettings },
): Promise<HealthCheckResult> {
  const device = await loadDevice(deviceId);
  const base = { deviceId, dialled: false, transition: null, announced: null, state: null };
  if (!device) return { ...base, outcome: 'gone' };
  // Disabled: never dialled, and no row written — "never" means never.
  if (device.status === 'disabled') return { ...base, outcome: 'never' };
  if (stopping) {
    return { ...base, outcome: 'aborted', abortReason: 'ObliWAN is stopping' };
  }

  const settings = opts.settings ?? (await settingsFor(device));
  let outcome = await probe(device, settings);
  // A failure observed while the runtime was being stopped is a statement
  // about the shutdown (sockets torn down under the check), not the device.
  if (stopping && outcome.kind === 'fail') {
    outcome = { kind: 'aborted', reason: `ObliWAN was stopping: ${outcome.error}` };
  }
  // The clock is read AFTER the probe, so `last_check_at` is when the answer
  // was known, unless a caller (a harness) drives the clock itself.
  const now = opts.now ?? new Date();

  if (outcome.kind === 'aborted') {
    logger.warn({ deviceId: device.id, reason: outcome.reason }, 'Health check not run (ObliWAN side)');
    if (!stopping) {
      await recordAborted(device, settings, outcome.reason, now).catch((err) =>
        logger.error({ err, deviceId: device.id }, 'Could not record an aborted health check'),
      );
    }
    return { ...base, outcome: 'aborted', abortReason: outcome.reason };
  }

  // The bench qualification, decided where the alert is. Evaluated on EVERY
  // outcome, not only on a failure: a healthy box on site must get qualified
  // while its session is open, because the session's close may later be one
  // only a sweep found, whose length qualifies nothing (benchQualification
  // header). One indexed read for a device the bench never prepared or that is
  // already qualified; three more only for a bench box not yet qualified. A
  // failure to read it is ours, not the device's: the check is aborted like
  // any other ObliWAN-side fault (state and count untouched) rather than
  // recorded on a guess — "not concerned" would announce a box in a van,
  // "held" would silence a router in service.
  let qualification: BenchQualification | null;
  try {
    qualification = await resolveBenchQualification(device, now, { persist: true });
  } catch (err) {
    const reason = `ObliWAN could not read the bench qualification: ${errorText(err)}`;
    logger.warn({ deviceId: device.id, err }, 'Health check not run (bench qualification unreadable)');
    if (!stopping) {
      await recordAborted(device, settings, reason, now).catch((e) =>
        logger.error({ err: e, deviceId: device.id }, 'Could not record an aborted health check'),
      );
    }
    return { ...base, outcome: 'aborted', abortReason: reason };
  }
  if (qualification?.verdict.state === 'qualifying' && qualification.verdict.qualifiesAt) {
    armCrossing(device.id, qualification.verdict.qualifiesAt);
  }
  // A planned WAN link cut (wan_link job): read only on a failure, the one
  // branch it changes.
  const cutUntil = outcome.kind === 'fail' ? await expectedCutUntil(device.id, now) : null;
  const applied = await applyOutcome(device, settings, outcome, now, qualification, cutUntil);

  // ── The concentrator: its verdict and presence follow its check ─────────
  // Only an API read is evidence about a concentrator (`pickChannel` offers
  // it nothing else; the channel test keeps that true here too).
  if (device.role === 'concentrator') {
    if (outcome.kind === 'ok' && outcome.channel === 'routeros_api') {
      // THE RECOVERY WRITE. `recordVerdict` writes only on change, so a healthy
      // CHR checked every minute adds nothing, and a degraded one becomes UP —
      // which is also what lifts the suppression of every device behind it.
      await assessDevice(device.id, {}, { managementOk: true }).catch((err) =>
        logger.error({ err, deviceId: device.id }, 'Could not record the concentrator verdict'),
      );
      const presence = await pppPresence.ensureStreaming(device.id).catch((err) => {
        logger.warn({ err, deviceId: device.id }, 'Could not (re)start presence on the concentrator');
        return 'error' as const;
      });
      if (presence === 'started' || presence === 'kicked') {
        logger.info({ concentratorId: device.id, presence }, 'Health check: presence re-opened on the concentrator');
      }
    } else if (applied.transition === 'down') {
      await markConcentratorDegraded(device.id, applied.after.last_error ?? undefined).catch((err) =>
        logger.error({ err, deviceId: device.id }, 'Could not record CONCENTRATOR_DEGRADED'),
      );
    }
  }

  if (applied.transition) {
    logger.info(
      {
        deviceId: device.id,
        from: applied.before.state,
        to: applied.after.state,
        failures: applied.after.consecutive_failures,
        error: applied.after.last_error,
        alertsHeld: applied.alertsHeld,
      },
      'Health check: state changed',
    );
  }
  let announced: 'down' | 'up' | null = null;
  try {
    announced = await announce(device, applied, outcome.kind === 'fail' ? outcome.refusedCertificate : null);
  } catch (err) {
    // The state is committed; a failed announcement must not undo it. A down
    // alert that failed here was not stamped, so the next check raises it.
    logger.error({ err, deviceId: device.id }, 'Health announcement failed');
  }
  // The 4G backup watch (backup4g.service.ts): reads the route this check may
  // just have filed. Never changes the check's verdict.
  if (device.role !== 'concentrator') {
    await evaluateBackup4g(device.id, {
      checkOk: outcome.kind === 'ok',
      alertsHeld: applied.alertsHeld,
      delayMin: settings.backup4gAlertMin,
      now,
    }).catch((err: unknown) => logger.error({ err, deviceId: device.id }, '4G backup evaluation failed'));
  }

  return {
    deviceId,
    outcome: outcome.kind,
    dialled: outcome.kind === 'ok' || (outcome.kind === 'fail' && outcome.dialled),
    transition: applied.transition,
    announced,
    state: applied.after.state,
    alertsHeld: applied.alertsHeld,
    qualification: qualification?.verdict.state ?? null,
  };
}

/**
 * Check one device now. Concurrent calls for the same device share one check:
 * "Check now" pressed while the scheduler is on the same box dials once.
 */
export function checkDevice(
  deviceId: number,
  opts: { now?: Date; settings?: HealthSettings } = {},
): Promise<HealthCheckResult> {
  const existing = inFlight.get(deviceId);
  if (existing) return existing;
  const p = runCheck(deviceId, opts).finally(() => inFlight.delete(deviceId));
  inFlight.set(deviceId, p);
  return p;
}

// ============================================================================
// The scheduler
// ============================================================================

export interface HealthCycleStats {
  candidates: number;
  due: number;
  checked: number;
  ok: number;
  failed: number;
  skipped: number;
  aborted: number;
}

/** Lets the timer abandon a pass it no longer owns (leadership lost, stop). */
export interface CycleSignal {
  aborted: boolean;
}

/** Devices this process's scheduler has queued or is checking, each with the
 *  real instant it was queued — the backlog `warnOnBacklog` measures. */
const queued = new Map<number, number>();
const concentratorLimit = pLimit(CONCENTRATOR_CONCURRENCY);
const deviceLimit = pLimit(HEALTH_CONCURRENCY);
/** The non-concentrator halves of passes the timer did not wait for. */
const outstanding = new Set<Promise<unknown>>();
let lastBacklogWarnAt = 0;

/**
 * "The configured intervals are not being met" must be said by somebody: the
 * page can only show its consequence (`stale`). Rate-limited, real clock.
 */
function warnOnBacklog(): void {
  if (queued.size === 0) return;
  let oldest = Infinity;
  for (const at of queued.values()) oldest = Math.min(oldest, at);
  const now = Date.now();
  const waitedMs = now - oldest;
  if (waitedMs < BACKLOG_WARN_MS || now - lastBacklogWarnAt < BACKLOG_WARN_EVERY_MS) return;
  lastBacklogWarnAt = now;
  logger.warn(
    { queued: queued.size, oldestWaitSec: Math.round(waitedMs / 1000), concurrency: HEALTH_CONCURRENCY },
    'Health check scheduler is not keeping up: checks wait for a slot longer than their interval '
      + 'allows, and devices will read stale. Look for checks timing out (device_timeout) or a '
      + 'health_check_interval too short for the size of the fleet.',
  );
}

/**
 * One pass: every non-disabled device whose check is due.
 *
 * DUE means `next_check_at` has passed — pulled EARLIER by however much the
 * resolved interval is now shorter than the one that computed it, so an
 * operator shortening the interval does not wait out the old one. A longer
 * interval applies from the next check on.
 *
 * Concentrators run first, in their own lane, and to completion: a child's
 * "is my parent degraded?" must read its parent's state of THIS pass. And a
 * child that was skipped because its parent was degraded is due AT ONCE when
 * the parent no longer is — so a CHR that recovers un-suppresses its children
 * in the same pass instead of leaving them on their old schedule for a whole
 * interval.
 *
 * Everything else is queued on the shared slots. With `wait: false` (the
 * timer) the pass returns once it is queued: the next tick plans again,
 * skipping what is still queued, so one slow device delays nobody's planning
 * and the concentrators are re-planned every tick whatever the backlog. A
 * caller that wants the whole pass done (a harness) leaves `wait` alone.
 */
export async function runHealthCycle(
  opts: { now?: Date; signal?: CycleSignal; wait?: boolean } = {},
): Promise<HealthCycleStats> {
  const nowMs = (opts.now ?? new Date()).getTime();
  const halted = (): boolean => stopping || opts.signal?.aborted === true;
  const stats: HealthCycleStats = {
    candidates: 0, due: 0, checked: 0, ok: 0, failed: 0, skipped: 0, aborted: 0,
  };
  if (halted()) return stats;
  warnOnBacklog();
  await refreshSettingsFingerprint();

  const rows = await db('devices as d')
    .leftJoin('device_health_checks as h', 'h.device_id', 'd.id')
    .whereNot('d.status', 'disabled')
    .select<
      Array<{
        id: number;
        tenant_id: number;
        group_id: number | null;
        role: string;
        concentrator_id: number | null;
        next_check_at: Date | null;
        interval_sec: number | null;
        skip_reason: HealthSkipReason | null;
      }>
    >(
      'd.id', 'd.tenant_id', 'd.group_id', 'd.role', 'd.concentrator_id',
      'h.next_check_at', 'h.interval_sec', 'h.skip_reason',
    );
  stats.candidates = rows.length;

  type Due = { id: number; dueAt: number; settings: HealthSettings };
  const dueAtOf = (r: (typeof rows)[number], settings: HealthSettings): number => {
    if (!r.next_check_at) return 0;
    const shortenedBy = Math.max(0, (r.interval_sec ?? settings.intervalSec) - settings.intervalSec);
    return r.next_check_at.getTime() - shortenedBy * 1000;
  };
  const busy = (id: number): boolean => queued.has(id) || inFlight.has(id);

  const dispatch = (d: Due, limiter: typeof deviceLimit): Promise<void> => {
    queued.set(d.id, Date.now());
    return limiter(async () => {
      // Stopping, or the pass was abandoned while this waited for a slot:
      // nothing new goes on the wire.
      if (halted()) return;
      try {
        const r = await checkDevice(d.id, { now: opts.now, settings: d.settings });
        stats.checked += 1;
        if (r.outcome === 'ok') stats.ok += 1;
        else if (r.outcome === 'fail') stats.failed += 1;
        else if (r.outcome === 'skip') stats.skipped += 1;
        else if (r.outcome === 'aborted') stats.aborted += 1;
      } catch (err) {
        logger.warn({ err, deviceId: d.id }, 'Health check failed unexpectedly');
      }
    }).finally(() => {
      queued.delete(d.id);
    });
  };

  // ── 1. Concentrators, in their own lane, to completion ──────────────────
  const concentrators: Due[] = [];
  for (const r of rows) {
    if (r.role !== 'concentrator' || busy(r.id)) continue;
    const settings = await settingsFor(r);
    const dueAt = dueAtOf(r, settings);
    if (dueAt <= nowMs) concentrators.push({ id: r.id, dueAt, settings });
  }
  await Promise.all(concentrators.map((d) => dispatch(d, concentratorLimit)));
  if (halted()) return stats;

  // ── 2. Everything else, with the parents' state of THIS pass ─────────────
  const parentDegraded = new Map<number, boolean>();
  const others: Due[] = [];
  for (const r of rows) {
    if (r.role === 'concentrator' || busy(r.id)) continue;
    const settings = await settingsFor(r);
    let dueAt = dueAtOf(r, settings);
    if (dueAt > nowMs && r.skip_reason === 'parent_degraded' && r.concentrator_id !== null) {
      let degraded = parentDegraded.get(r.concentrator_id);
      if (degraded === undefined) {
        degraded = await isConcentratorDegraded(r.concentrator_id);
        parentDegraded.set(r.concentrator_id, degraded);
      }
      if (!degraded) dueAt = 0;
    }
    if (dueAt <= nowMs) others.push({ id: r.id, dueAt, settings });
  }
  // Most overdue first: the queue is first in, first out.
  others.sort((a, b) => a.dueAt - b.dueAt);
  stats.due = concentrators.length + others.length;
  const rest = Promise.all(others.map((d) => dispatch(d, deviceLimit)));
  if (opts.wait === false) {
    outstanding.add(rest);
    void rest.finally(() => outstanding.delete(rest));
    return stats;
  }
  await rest;
  return stats;
}

let unsubscribe: (() => void) | null = null;
let timer: NodeJS.Timeout | null = null;
let ticking = false;
let timerSignal: CycleSignal | null = null;
let currentPass: Promise<unknown> | null = null;

function startTimer(): void {
  if (timer || stopping) return;
  const signal: CycleSignal = { aborted: false };
  timerSignal = signal;
  const tick = (): void => {
    // Never two PLANNINGS at once. The checks a pass queued may still be
    // running; the next planning skips them (`queued`).
    if (ticking || signal.aborted) return;
    ticking = true;
    currentPass = runHealthCycle({ signal, wait: false })
      .catch((err) => logger.error({ err }, 'Health check cycle failed'))
      .finally(() => {
        ticking = false;
      });
  };
  timer = setInterval(tick, HEALTH_TICK_MS);
  timer.unref();
  tick();
  logger.info({ tickMs: HEALTH_TICK_MS }, 'Health check scheduler armed (leader)');
}

function stopTimer(): void {
  if (timer) clearInterval(timer);
  timer = null;
  // Checks this process queued but has not started are abandoned: another
  // leader plans them now, and two would double every dial.
  if (timerSignal) timerSignal.aborted = true;
  timerSignal = null;
}

/** Idempotent. Safe on every role: a `web` replica never campaigns, so it never
 *  receives a `true` and never starts the scheduler. */
export function startHealthCheckRuntime(): void {
  if (unsubscribe) return;
  unsubscribe = leaderElection.onChange((isLeader) => {
    if (isLeader) startTimer();
    else stopTimer();
  });
  // The qualification that gates this check's alerts has its own trigger: a
  // timer at the crossing of a qualifying session, armed from presence's
  // session-up seam (leader only, like presence itself).
  startBenchQualificationRuntime();
  logger.info('Health check runtime wired to leadership');
}

/**
 * Stop for good (process shutdown). From here on nothing new is dispatched —
 * queued checks return at once, "Check now" answers `aborted` — and a failure
 * observed under the shutdown is not recorded as the device's. Waits for the
 * checks already on the wire, so they record what they saw while the pool is
 * still open (`index.ts` calls this BEFORE `stopFleetRuntime()`), then gives
 * the channel messages still being sent a bounded grace.
 */
export async function stopHealthCheckRuntime(): Promise<void> {
  stopping = true;
  unsubscribe?.();
  unsubscribe = null;
  stopTimer();
  if (currentPass) await currentPass;
  await Promise.allSettled(Array.from(outstanding));
  await Promise.allSettled(Array.from(inFlight.values()));
  await stopBenchQualificationRuntime();
  if (pendingDeliveries.size === 0) return;
  let graceTimer: NodeJS.Timeout | undefined;
  const drained = await Promise.race([
    flushHealthNotifications().then(() => true),
    new Promise<boolean>((resolve) => {
      graceTimer = setTimeout(() => resolve(false), DELIVERY_DRAIN_MS);
    }),
  ]);
  if (graceTimer) clearTimeout(graceTimer);
  if (!drained) {
    logger.warn(
      { pending: pendingDeliveries.size },
      'Health notifications still being sent at shutdown; not waiting for them any longer',
    );
  }
}

// ============================================================================
// Read side — the API
// ============================================================================

function iso(d: Date | null): string | null {
  return d ? d.toISOString() : null;
}

function toView(
  device: { status: string },
  row: HealthRow | undefined,
  settings: HealthSettings,
  nowMs: number,
  qualification: BenchQualificationView | null = null,
): DeviceHealthCheckView {
  const scheduled = device.status !== 'disabled';
  const display = healthDisplay(
    row
      ? {
        state: row.state,
        consecutiveFailures: row.consecutive_failures,
        skipReason: row.skip_reason,
        lastCheckAt: iso(row.last_check_at),
        intervalSec: row.interval_sec,
      }
      : null,
    nowMs,
    !scheduled,
  );
  return {
    display,
    state: row?.state ?? 'unknown',
    channel: row?.channel ?? null,
    method: row?.channel ? HEALTH_CHECK_METHOD[row.channel] : null,
    skipReason: row?.skip_reason ?? null,
    consecutiveFailures: row?.consecutive_failures ?? 0,
    lastCheckAt: iso(row?.last_check_at ?? null),
    lastOkAt: iso(row?.last_ok_at ?? null),
    downSince: iso(row?.down_since ?? null),
    alertedAt: row && alertedThisOutage(row) ? iso(row.alerted_at) : null,
    nextCheckAt: scheduled ? iso(row?.next_check_at ?? null) : null,
    lastError: row?.last_error ?? null,
    intervalSec: settings.intervalSec,
    retries: settings.retries,
    alertDelaySec: settings.alertDelaySec,
    scheduled,
    // A disabled device is never checked, so no rule about its alerts applies.
    qualification: scheduled ? qualification : null,
  };
}

/** The device page's view: the stored row plus the settings that apply NOW. */
export async function healthCheckView(
  tenantId: number,
  deviceId: number,
): Promise<DeviceHealthCheckView | null> {
  const device = await db('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first<{
      id: number;
      tenant_id: number;
      group_id: number | null;
      status: string;
      concentrator_id: number | null;
      ppp_username: string | null;
    } | undefined>(
      'id', 'tenant_id', 'group_id', 'status', 'concentrator_id', 'ppp_username',
    );
  if (!device) return null;
  const [row, settings, qualification] = await Promise.all([
    db('device_health_checks').where({ device_id: deviceId }).first<HealthRow | undefined>(),
    resolveHealthSettings(device.tenant_id, device.id, device.group_id),
    benchQualificationView(device),
  ]);
  return toView(device, row, settings, Date.now(), qualification);
}

/**
 * "Check now". Tenant-scoped; the settings are resolved fresh rather than
 * taken from the scheduler's cache, so an operator who has just changed one
 * and presses the button sees it applied.
 */
export async function checkDeviceNow(
  tenantId: number,
  deviceId: number,
): Promise<
  | { kind: 'not_found' }
  | { kind: 'disabled' }
  | { kind: 'aborted'; reason: string }
  | { kind: 'done'; result: HealthCheckResult; view: DeviceHealthCheckView }
> {
  const device = await db('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first<{ id: number; tenant_id: number; group_id: number | null; status: string } | undefined>(
      'id', 'tenant_id', 'group_id', 'status',
    );
  if (!device) return { kind: 'not_found' };
  if (device.status === 'disabled') return { kind: 'disabled' };
  const settings = await resolveHealthSettings(device.tenant_id, device.id, device.group_id);
  const result = await checkDevice(deviceId, { settings });
  if (result.outcome === 'aborted') {
    return { kind: 'aborted', reason: result.abortReason ?? 'ObliWAN could not run the check' };
  }
  const view = await healthCheckView(tenantId, deviceId);
  if (!view) return { kind: 'not_found' };
  return { kind: 'done', result, view };
}
