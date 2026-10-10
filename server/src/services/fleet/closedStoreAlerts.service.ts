/**
 * ObliWAN — what a CLOSED store does to its alerts (opening hours, migration
 * 096).
 *
 * A store down at 03:00 is not an emergency; at 15:00 it is. Two producers
 * consult this file, and only for their alert about ONE device: the health
 * check's "is not answering" (healthCheck.service.ts `announce`) and the 4G
 * backup alert (backup4g.service.ts `evaluateBackup4g`). Nothing else changes.
 *
 * ┌─ AT THE RAISE — `judgeClosedStore` ──────────────────────────────────────┐
 * │ The store's hours known and CLOSED at that instant (siteOpenAt === false):│
 * │  · the live alert is one level LOWER (down -> warning, warning -> info)   │
 * │    and its title says « magasin fermé »;                                  │
 * │  · the channels (setting `closed_store_notify`, read per device): 0 =     │
 * │    notified at once, at the lowered severity (critical -> warning,        │
 * │    warning -> info) — what happened before 096; 1 = NOT notified now,     │
 * │    notified at the opening if the problem is still there;                 │
 * │  · the producer records the alert here (`recordClosedStoreAlert`), with   │
 * │    the alert and the channel message it WOULD have raised with the store  │
 * │    open.                                                                  │
 * │ Hours unknown, open, no site, or unreadable: NOTHING changes — today's    │
 * │ behaviour. An alert is never lost because the hours could not be read.  │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ AT THE OPENING — `runClosedStoreEscalations`, the leader, every minute ─┐
 * │ For each recorded alert not yet resolved:                                 │
 * │  · the problem is over (the outage that started at `episode_at` is no     │
 * │    longer the device's current one; the 4G episode stamped at             │
 * │    `episode_at` is no longer open) -> resolved 'cleared', nothing raised; │
 * │  · the store still closed -> wait;                                        │
 * │  · open (or its hours removed since: unknown = today's behaviour) -> the  │
 * │    alert is raised AGAIN at its normal severity (a new live alert,        │
 * │    « magasin ouvert, toujours en panne »), then the row is claimed by a   │
 * │    conditional UPDATE and the claimer sends the normal channel message —  │
 * │    the health check's "raise, stamp, the stamper sends" pattern.          │
 * │ A RECOVERY of an episode the channels never heard of (wait-for-opening,  │
 * │ recovered before the opening) is not sent to the channels either:         │
 * │ `closedStoreRecoveryNotify` answers false and closes the row.             │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
import {
  CLOSED_STORE_MARK,
  CLOSED_STORE_NOTIFY_AT_OPENING,
  SETTINGS_KEYS,
  nextChangeIn,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { leaderElection } from '../leaderElection';
import { liveAlertService } from '../liveAlert.service';
import { notificationService } from '../notification.service';
import type { NotificationPayload } from '../../notifications/types';
import { settingsService } from '../settings.service';
import { loadSiteHours, openAt } from './openingHours.service';

export type ClosedStoreKind = 'health_down' | 'backup_4g';
export type LiveSeverity = 'down' | 'up' | 'warning' | 'info';
export type ChannelSeverity = NonNullable<NotificationPayload['severity']>;

const LOWER_LIVE: Record<LiveSeverity, LiveSeverity> = { down: 'warning', warning: 'info', info: 'info', up: 'up' };
const LOWER_CHANNEL: Record<ChannelSeverity, ChannelSeverity> = { critical: 'warning', warning: 'info', info: 'info' };

export function lowerLiveSeverity(s: LiveSeverity): LiveSeverity {
  return LOWER_LIVE[s];
}
export function lowerChannelSeverity(s: ChannelSeverity): ChannelSeverity {
  return LOWER_CHANNEL[s];
}

export interface ClosedStoreInput {
  tenantId: number;
  deviceId: number;
  groupId: number | null;
  siteId: number | null;
  severity: LiveSeverity;
  channelSeverity: ChannelSeverity;
  title: string;
  message: string;
  at: Date;
}

export type ClosedStoreVerdict =
  | { closed: false }
  | {
      closed: true;
      liveSeverity: LiveSeverity;
      channelSeverity: ChannelSeverity;
      title: string;
      message: string;
      /** 'now' = the channels hear of it at once (lowered); 'at_opening' = not now. */
      notify: 'now' | 'at_opening';
      /** The next opening, when it is within the look-ahead. */
      opensAt: Date | null;
      timezone: string;
    };

function localHhmm(at: Date, tz: string): string {
  try {
    return new Intl.DateTimeFormat('fr-FR', { timeZone: tz, weekday: 'short', hour: '2-digit', minute: '2-digit' }).format(at);
  } catch {
    return at.toISOString();
  }
}

/** `closed_store_notify` for one device (0 = notify anyway, the default). */
async function notifySetting(tenantId: number, deviceId: number, groupId: number | null): Promise<number> {
  const resolved = await settingsService.resolveForDevice(tenantId, deviceId, groupId);
  return Number(resolved[SETTINGS_KEYS.CLOSED_STORE_NOTIFY]?.value ?? 0);
}

/**
 * Is the store closed right now, and if so, how is this alert raised? Never
 * throws: an unreadable answer is `{ closed: false }`, today's behaviour.
 */
export async function judgeClosedStore(input: ClosedStoreInput): Promise<ClosedStoreVerdict> {
  if (input.siteId === null || input.siteId === undefined) return { closed: false };
  try {
    const hours = await loadSiteHours(input.siteId);
    if (openAt(hours, input.at) !== false || !hours) return { closed: false };
    const notify =
      (await notifySetting(input.tenantId, input.deviceId, input.groupId)) === CLOSED_STORE_NOTIFY_AT_OPENING
        ? 'at_opening'
        : 'now';
    const opensAt = nextChangeIn(hours.hours, hours.timezone, input.at);
    const when = opensAt ? `réouverture ${localHhmm(opensAt, hours.timezone)} (${hours.timezone})` : 'pas de réouverture prévue dans les jours qui viennent';
    return {
      closed: true,
      liveSeverity: LOWER_LIVE[input.severity],
      channelSeverity: LOWER_CHANNEL[input.channelSeverity],
      title: `${input.title} (${CLOSED_STORE_MARK})`,
      message:
        `Magasin fermé : alerte abaissée d'un niveau, ${when}` +
        (notify === 'at_opening' ? ', notification à l’ouverture si le problème persiste' : '') +
        `. ${input.message}`,
      notify,
      opensAt,
      timezone: hours.timezone,
    };
  } catch (err) {
    logger.warn({ err, deviceId: input.deviceId, siteId: input.siteId }, 'Closed store: hours unreadable, the alert is raised as usual');
    return { closed: false };
  }
}

export interface ClosedStoreRecord {
  tenantId: number;
  deviceId: number;
  siteId: number | null;
  kind: ClosedStoreKind;
  /** The episode: the outage's down_since, or the 4G alert's stamp. */
  episodeAt: Date;
  /** The alert as it would have been raised with the store open. */
  normalSeverity: LiveSeverity;
  title: string;
  message: string;
  navigateTo: string | null;
  stableKey: string;
  notification: NotificationPayload;
  notifiedAtRaise: boolean;
  opensAt: Date | null;
}

/** Record a lowered alert (idempotent per device, kind and episode). */
export async function recordClosedStoreAlert(r: ClosedStoreRecord): Promise<void> {
  await db('store_closed_alerts')
    .insert({
      tenant_id: r.tenantId,
      device_id: r.deviceId,
      site_id: r.siteId,
      kind: r.kind,
      episode_at: r.episodeAt,
      normal_severity: r.normalSeverity,
      title: r.title,
      message: r.message,
      navigate_to: r.navigateTo,
      stable_key: r.stableKey,
      notification: JSON.stringify(r.notification),
      notified_at_raise: r.notifiedAtRaise,
      opens_at: r.opensAt,
    })
    .onConflict(['device_id', 'kind', 'episode_at'])
    .ignore();
}

/**
 * The problem of this episode is over. Returns whether its RECOVERY goes to
 * the channels: false when the channels never heard of the episode (wait for
 * the opening, recovered before it) — the row is closed either way. No row:
 * true, today's behaviour. A read failure: true (a recovery notice too many is
 * the lesser fault).
 */
export async function closedStoreRecoveryNotify(
  deviceId: number,
  kind: ClosedStoreKind,
  episodeAt: Date,
): Promise<boolean> {
  try {
    const row = (await db('store_closed_alerts')
      .where({ device_id: deviceId, kind, episode_at: episodeAt })
      .first('id', 'notified_at_raise', 'resolution', 'resolved_at')) as
      | { id: number; notified_at_raise: boolean; resolution: string | null; resolved_at: Date | null }
      | undefined;
    if (!row) return true;
    if (row.resolved_at === null) {
      await db('store_closed_alerts')
        .where({ id: row.id })
        .whereNull('resolved_at')
        .update({ resolved_at: new Date(), resolution: 'cleared' });
      return row.notified_at_raise;
    }
    return row.resolution === 'escalated' || row.notified_at_raise;
  } catch (err) {
    logger.warn({ err, deviceId, kind }, 'Closed store: could not read the lowered alert, the recovery is notified');
    return true;
  }
}

// ============================================================================
// The opening — leader sweep
// ============================================================================

interface PendingRow {
  id: number;
  tenant_id: number;
  device_id: number;
  site_id: number | null;
  kind: ClosedStoreKind;
  episode_at: Date;
  normal_severity: LiveSeverity;
  title: string;
  message: string;
  navigate_to: string | null;
  stable_key: string;
  notification: unknown;
}

/** Is the problem of this episode still the device's current one? */
async function stillThere(row: PendingRow): Promise<boolean> {
  if (row.kind === 'health_down') {
    const h = (await db('device_health_checks')
      .where({ device_id: row.device_id })
      .first('state', 'down_since')) as { state: string; down_since: Date | null } | undefined;
    return !!h && h.state === 'down' && h.down_since !== null && new Date(h.down_since).getTime() === new Date(row.episode_at).getTime();
  }
  const d = (await db('devices').where({ id: row.device_id }).first('backup4g_alerted_at')) as
    | { backup4g_alerted_at: Date | null }
    | undefined;
  return !!d && d.backup4g_alerted_at !== null && new Date(d.backup4g_alerted_at).getTime() === new Date(row.episode_at).getTime();
}

export interface EscalationReport {
  examined: number;
  escalated: number;
  cleared: number;
  waiting: number;
}

/**
 * One pass: every lowered alert whose store has opened with the problem still
 * there is raised again at its normal severity and notified. `now` for a
 * harness; the runtime passes the clock.
 */
export async function runClosedStoreEscalations(now: Date = new Date()): Promise<EscalationReport> {
  const report: EscalationReport = { examined: 0, escalated: 0, cleared: 0, waiting: 0 };
  const rows = (await db('store_closed_alerts')
    .whereNull('resolved_at')
    .orderBy('raised_at')
    .limit(1000)
    .select('*')) as PendingRow[];
  for (const row of rows) {
    report.examined += 1;
    try {
      if (!(await stillThere(row))) {
        await db('store_closed_alerts')
          .where({ id: row.id })
          .whereNull('resolved_at')
          .update({ resolved_at: now, resolution: 'cleared' });
        report.cleared += 1;
        continue;
      }
      const hours = row.site_id === null ? null : await loadSiteHours(row.site_id);
      // Closed: wait. Open, or hours no longer known: the normal alert now.
      if (openAt(hours, now) === false) {
        report.waiting += 1;
        continue;
      }
      const device = (await db('devices').where({ id: row.device_id }).first('group_id', 'name')) as
        | { group_id: number | null; name: string }
        | undefined;
      if (!device) continue;
      await liveAlertService.add(row.tenant_id, {
        severity: row.normal_severity,
        title: `${row.title} — magasin ouvert`,
        message:
          `Le magasin a ouvert et le problème est toujours là : alerte remontée à sa sévérité normale. ${row.message}`,
        navigateTo: row.navigate_to,
        deviceId: row.device_id,
        stableKey: `store-open:${row.stable_key}`,
      });
      // THE CLAIM, after the live alert exists; the claimer sends.
      const claimed = await db('store_closed_alerts')
        .where({ id: row.id })
        .whereNull('resolved_at')
        .update({ escalated_at: now, resolved_at: now, resolution: 'escalated' });
      if (claimed === 0) continue;
      report.escalated += 1;
      const stored = (typeof row.notification === 'string' ? JSON.parse(row.notification) : row.notification) as NotificationPayload;
      const payload: NotificationPayload = {
        ...stored,
        message: `Magasin ouvert, problème toujours présent. ${stored.message ?? row.message}`,
        timestamp: now.toISOString(),
      };
      deliver(row.device_id, () =>
        notificationService.sendForDevice(row.tenant_id, row.device_id, device.group_id, payload),
      );
    } catch (err) {
      logger.warn({ err, id: row.id, deviceId: row.device_id }, 'Closed store: escalation at opening failed, retried next pass');
    }
  }
  return report;
}

const pending = new Set<Promise<void>>();

function deliver(deviceId: number, send: () => Promise<void>): void {
  const p: Promise<void> = send()
    .catch((err: unknown) => logger.warn({ err, deviceId }, 'Closed store: notification at opening failed (the live alert is raised)'))
    .finally(() => {
      pending.delete(p);
    });
  pending.add(p);
}

/** For shutdown and harnesses: wait for the channel messages already sent. */
export async function flushClosedStoreNotifications(): Promise<void> {
  while (pending.size > 0) await Promise.allSettled(Array.from(pending));
}

// ============================================================================
// Runtime — the leader, every minute
// ============================================================================

const SWEEP_MS = 60_000;
let timer: NodeJS.Timeout | null = null;
let running: Promise<unknown> | null = null;

export function startClosedStoreRuntime(): void {
  if (timer) return;
  const tick = (): void => {
    if (running || !leaderElection.isLeader()) return;
    running = runClosedStoreEscalations()
      .then((r) => {
        if (r.escalated > 0 || r.cleared > 0) logger.info(r, 'Closed store: lowered alerts examined at opening');
      })
      .catch((err: unknown) => logger.warn({ err }, 'Closed store sweep failed — retried next minute'))
      .finally(() => {
        running = null;
      });
  };
  timer = setInterval(tick, SWEEP_MS);
  timer.unref?.();
}

export async function stopClosedStoreRuntime(): Promise<void> {
  if (timer) clearInterval(timer);
  timer = null;
  if (running) await running.catch(() => undefined);
  await flushClosedStoreNotifications();
}
