/**
 * ObliWAN — PPP presence.
 *
 * The concentrator is the source of truth for "is this site reachable", not
 * ping. Two mechanisms, and BOTH are required:
 *
 *   1. `/ppp/active/listen` — a single streaming command on the single socket
 *      the pool holds to the CHR. This is what makes the state flip in under
 *      two seconds instead of on the next poll tick.
 *
 *   2. A full `/ppp/active` reconciliation every 60 s. Not a fallback, a
 *      correction: a `listen` can miss an event, can be silently cancelled by
 *      the router, or can survive as a TCP connection that no longer carries
 *      anything. Presence that only ever hears about deltas drifts, and drifts
 *      quietly — the failure mode is a device shown online for a week.
 *
 * The reconciliation is also what makes a restart correct: on start the
 * in-memory view is empty and the database may hold sessions the CHR forgot
 * about during the outage. The first sweep closes them.
 *
 * A drop is RECORDED at once and REPORTED (verdict + event) once the device's
 * `presence_grace_period` has passed with the session still down — at once by
 * default (presenceGrace.ts). An `up` is always reported at once.
 *
 * WHY `.id` IS KEPT IN MEMORY AND NEVER STORED
 * A `listen` teardown event carries `.id` and `.dead=true` — and often nothing
 * else, not even the username. So the monitor keeps a `.id -> username` map
 * built from the sessions it has seen. RouterOS `.id` values are recycled
 * across reboots, which is precisely why the map is per-stream, in memory, and
 * thrown away when the stream dies. An unknown `.id` does not guess: it forces
 * an immediate reconciliation.
 *
 * LEADERSHIP: only the leader may run this. Two replicas would
 * open two `listen` commands on the same CHR and double-write session history.
 * The gate lives in `./index.ts`; this service exposes plain start/stop.
 */

import { SOCKET_EVENTS, type SitePresenceEvent } from '@obliwan/shared';
import type { RouterOsStream } from '../transport/routeros';
import type { Sentence } from '../transport/routeros';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { getRouterOsPool, resolveRouterOsTarget } from './routerosPool';
import { emitSitePresence } from './scopedEmit';
import { asInetOrNull, parseActiveRow, requireConcentrator, type PppActiveEntry } from './concentratorDiscovery.service';
import {
  assessDevice,
  markConcentratorDegraded,
  recordConcentratorRecovery,
  recordVerdict,
} from './reachability.service';
import { presenceGraceSec, withinGrace } from './presenceGrace';
import { recordActiveRead } from './pppDuplicates.service';

/** How often the full sweep runs. The spec fixes this at 60 s. */
export const RECONCILE_INTERVAL_MS = 60_000;

/** How long to wait before re-opening a `listen` that died. */
const STREAM_RETRY_MS = 5_000;

// ============================================================================
// Session bookkeeping
// ============================================================================

interface DeviceRef {
  id: number;
  tenant_id: number;
  group_id: number | null;
  site_id: number | null;
  wan_public_ip: string | null;
}

/**
 * The device a PPP username belongs to — ON THIS CONCENTRATOR.
 *
 * `concentratorId` is not optional and the filter is not cosmetic. `ppp_username`
 * is UNIQUE GLOBALLY (migration 002), so a lookup by name alone resolves a name
 * seen on ANY concentrator to a device that may belong to a different tenant
 * entirely — and `applySessionUp` then writes `tunnel_ip` on it. That address is
 * what `assertTargetBinding` dials on a write, with that customer's decrypted RouterOS
 * password: whoever published the session gets handed the credential.
 *
 * A name seen on a concentrator the device is not attached to yields null. The
 * session is still recorded without a device_id — the same shape as an unclaimed
 * account — and the collision is logged, because it is itself a signal.
 */
async function deviceForUsername(
  username: string,
  concentratorId: number,
): Promise<DeviceRef | null> {
  const row = await db('devices')
    .where({ ppp_username: username, concentrator_id: concentratorId })
    .first<DeviceRef | undefined>('id', 'tenant_id', 'group_id', 'site_id', 'wan_public_ip');
  if (row) return row;

  const elsewhere = await db('devices')
    .where({ ppp_username: username })
    .first<{ id: number; concentrator_id: number | null } | undefined>('id', 'concentrator_id');
  if (elsewhere) {
    logger.warn(
      { username, concentratorId, deviceId: elsewhere.id, attachedTo: elsewhere.concentrator_id },
      'PPP session refused: this username belongs to a device attached to ANOTHER concentrator. ' +
        'Session recorded without a device. Either the device was re-homed and its ' +
        'concentrator_id is stale, or two concentrators declare the same account name.',
    );
  }
  return null;
}

export interface PresenceChange {
  concentratorId: number;
  pppUsername: string;
  up: boolean;
  deviceId: number | null;
  siteId: number | null;
  tunnelIp: string | null;
  callerIp: string | null;
  /** True when the database actually changed state (a duplicate `up` for an
   *  already-open session is not a change and must not emit). */
  changed: boolean;
  at: string;
}

/**
 * A session came up.
 *
 * Idempotent: `ppp_sessions` carries a partial unique index guaranteeing at
 * most one open row per (concentrator, username), so a duplicate event from the
 * listen and the sweep racing each other refreshes the row instead of forking
 * the history.
 */
export async function applySessionUp(
  concentratorId: number,
  entry: { username: string; tunnelIp: string | null; callerIp: string | null },
  options: { emit?: boolean } = {},
): Promise<PresenceChange> {
  const now = new Date();
  const device = await deviceForUsername(entry.username, concentratorId);
  const tunnelIp = asInetOrNull(entry.tunnelIp);
  const callerIp = asInetOrNull(entry.callerIp);

  const open = await db('ppp_sessions')
    .where({ concentrator_id: concentratorId, ppp_username: entry.username })
    .whereNull('ended_at')
    .first<{ id: string; tunnel_ip: string | null } | undefined>('id', 'tunnel_ip');

  let changed = false;
  if (open) {
    // Already up. Refresh addressing only — re-opening would lose the real
    // start time and inflate the flap count.
    await db('ppp_sessions')
      .where({ id: open.id })
      .update({ tunnel_ip: tunnelIp, caller_ip: callerIp, device_id: device?.id ?? null });
  } else {
    await db('ppp_sessions').insert({
      concentrator_id: concentratorId,
      device_id: device?.id ?? null,
      ppp_username: entry.username,
      tunnel_ip: tunnelIp,
      caller_ip: callerIp,
      started_at: now,
    });
    changed = true;
  }

  if (device) {
    await db('devices')
      .where({ id: device.id })
      .update({
        last_seen_at: now,
        // "Where to dial today". Never used as an identity: every write
        // path goes through assertTargetBinding() first.
        tunnel_ip: tunnelIp,
        wan_public_ip: callerIp ?? device.wan_public_ip,
        first_seen_at: db.raw('COALESCE(first_seen_at, ?)', [now]),
        updated_at: now,
      });
  }

  const change: PresenceChange = {
    concentratorId,
    pppUsername: entry.username,
    up: true,
    deviceId: device?.id ?? null,
    siteId: device?.site_id ?? null,
    tunnelIp,
    callerIp,
    changed,
    at: now.toISOString(),
  };

  // A drop still inside its grace window is not reported now and never will
  // be: the session came back. Its history row stays — the flap happened.
  if (changed) cancelPendingDown(concentratorId, entry.username);

  if (changed && options.emit !== false) {
    await publish(change, device, {
      // A session that comes back from a different public address is a silent
      // WAN failover. Only meaningful when we had a baseline to compare to.
      publicPathChanged:
        device?.wan_public_ip && callerIp ? device.wan_public_ip !== callerIp : null,
    });
  }
  // Told AFTER the session row and the device's addressing are written, so a
  // listener that dials the device reads where to dial today. Only a NEW
  // session (`changed`) and only one bound to a device on this concentrator.
  if (changed && device) {
    notifySessionUp({
      concentratorId,
      deviceId: device.id,
      tenantId: device.tenant_id,
      pppUsername: entry.username,
      tunnelIp,
      at: change.at,
    });
  }
  return change;
}

// ============================================================================
// Session-up listeners
// ============================================================================
//
// A narrow seam for the duties that must react to a box's FIRST contact —
// today the automatic conformity check of a bench-prepared router
// (`autoConfirm.service.ts`). This file does not know them: it imports nothing
// of theirs, and they register here.
//
// A listener is called fire-and-forget. Presence is the source of truth for
// "is this site reachable" and must not wait on, nor fail with, whatever
// a listener does: a throw or a rejection is logged and dropped. Presence runs
// on the leader only (`./index.ts`), so listeners are only ever called there;
// a listener with background effects re-checks leadership itself anyway.

/** A NEW PPP session for a username bound to a device on this concentrator. */
export interface PppSessionUpEvent {
  concentratorId: number;
  deviceId: number;
  tenantId: number;
  pppUsername: string;
  tunnelIp: string | null;
  at: string;
}

export type PppSessionUpListener = (event: PppSessionUpEvent) => void | Promise<void>;

const sessionUpListeners = new Set<PppSessionUpListener>();

/** Register a listener. Returns its unsubscribe function. */
export function onPppSessionUp(listener: PppSessionUpListener): () => void {
  sessionUpListeners.add(listener);
  return () => {
    sessionUpListeners.delete(listener);
  };
}

function notifySessionUp(event: PppSessionUpEvent): void {
  for (const listener of sessionUpListeners) {
    try {
      void Promise.resolve(listener(event)).catch((err: unknown) => {
        logger.warn({ err, deviceId: event.deviceId }, 'A PPP session-up listener failed');
      });
    } catch (err) {
      logger.warn({ err, deviceId: event.deviceId }, 'A PPP session-up listener failed');
    }
  }
}

/** A session went away. */
export async function applySessionDown(
  concentratorId: number,
  username: string,
  reason: string | null,
  options: { emit?: boolean } = {},
): Promise<PresenceChange> {
  const now = new Date();
  const device = await deviceForUsername(username, concentratorId);

  const open = await db('ppp_sessions')
    .where({ concentrator_id: concentratorId, ppp_username: username })
    .whereNull('ended_at')
    .first<{ id: string; started_at: Date; tunnel_ip: string | null; caller_ip: string | null } | undefined>(
      'id',
      'started_at',
      'tunnel_ip',
      'caller_ip',
    );

  let changed = false;
  if (open) {
    const duration = Math.max(0, Math.round((now.getTime() - open.started_at.getTime()) / 1000));
    await db('ppp_sessions').where({ id: open.id }).update({
      ended_at: now,
      duration_seconds: duration,
      disconnect_reason: reason ? reason.slice(0, 128) : null,
    });
    changed = true;
  }

  const change: PresenceChange = {
    concentratorId,
    pppUsername: username,
    up: false,
    deviceId: device?.id ?? null,
    siteId: device?.site_id ?? null,
    tunnelIp: open?.tunnel_ip ?? null,
    callerIp: open?.caller_ip ?? null,
    changed,
    at: now.toISOString(),
  };

  if (changed && options.emit !== false) {
    // `presence_grace_period` (presenceGrace.ts): the drop is RECORDED above
    // and REPORTED only once the device's window has closed with the session
    // still down. A username bound to no device has no window and nothing to
    // colour — its event (for the discoveries screen) goes at once.
    const graceSec = device
      ? await presenceGraceSec(device.tenant_id, device.id, device.group_id).catch((err) => {
          // A settings read that fails must not swallow an outage: report now.
          logger.warn({ err, deviceId: device.id }, 'Presence grace unreadable; reporting the drop at once');
          return 0;
        })
      : 0;
    if (device && graceSec > 0) {
      deferDown(change, device, graceSec);
    } else {
      await publish(change, device, {});
    }
  }
  return change;
}

// ============================================================================
// The grace window — deferred reports of a drop
// ============================================================================
//
// One timer per (concentrator, username), in memory, on the leader. Losing it
// (a restart, a leadership change) loses nothing: `reportExpiredGraces()` runs
// after every reconciliation and reports any drop whose window has closed and
// whose device still reads as up. The timer only makes the report punctual.

const pendingDowns = new Map<string, NodeJS.Timeout>();

function pendingKey(concentratorId: number, username: string): string {
  return `${concentratorId}\u0000${username}`;
}

function cancelPendingDown(concentratorId: number, username: string): void {
  const key = pendingKey(concentratorId, username);
  const timer = pendingDowns.get(key);
  if (timer) {
    clearTimeout(timer);
    pendingDowns.delete(key);
  }
}

function cancelAllPendingDowns(): void {
  for (const timer of pendingDowns.values()) clearTimeout(timer);
  pendingDowns.clear();
}

function deferDown(change: PresenceChange, device: DeviceRef, graceSec: number): void {
  cancelPendingDown(change.concentratorId, change.pppUsername);
  const key = pendingKey(change.concentratorId, change.pppUsername);
  const timer = setTimeout(() => {
    pendingDowns.delete(key);
    void reportDownIfStillDown(change, device).catch((err) =>
      logger.warn({ err, deviceId: device.id }, 'Deferred PPP down report failed; the sweep will retry'),
    );
  }, graceSec * 1000);
  timer.unref();
  pendingDowns.set(key, timer);
  logger.info(
    { concentratorId: change.concentratorId, pppUsername: change.pppUsername, deviceId: device.id, graceSec },
    'PPP session down — report held for the presence grace period',
  );
}

/** The window closed: report the drop, unless the session is back. */
async function reportDownIfStillDown(
  change: PresenceChange,
  device: DeviceRef,
  options: { emitOnlyIfWritten?: boolean } = {},
): Promise<boolean> {
  const open = await db('ppp_sessions')
    .where({ concentrator_id: change.concentratorId, ppp_username: change.pppUsername })
    .whereNull('ended_at')
    .first('id');
  if (open) return false;
  return publish(change, device, {}, options);
}

/**
 * Report every drop on this concentrator whose grace window has closed while
 * its device's latest verdict still says the tunnel is up — the drops a lost
 * timer would otherwise leave reported as UP for ever. Run after every
 * reconciliation; the common answer is one query and no row.
 *
 * Emits only when a verdict row was actually written, so a device whose
 * report is suppressed (its concentrator is degraded) is not announced
 * again every minute.
 */
export async function reportExpiredGraces(concentratorId: number): Promise<number> {
  const rows = (await db.raw(
    `SELECT d.id, d.tenant_id, d.group_id, d.site_id, host(d.wan_public_ip) AS wan_public_ip,
            d.ppp_username, s.ended_at, host(s.tunnel_ip) AS tunnel_ip, host(s.caller_ip) AS caller_ip
       FROM devices d
       JOIN LATERAL (
         SELECT ended_at, tunnel_ip, caller_ip FROM ppp_sessions
          WHERE concentrator_id = d.concentrator_id AND ppp_username = d.ppp_username
          ORDER BY started_at DESC, id DESC
          LIMIT 1
       ) s ON true
       JOIN LATERAL (
         SELECT ppp_up FROM reachability_verdicts
          WHERE device_id = d.id
          ORDER BY ts DESC, id DESC
          LIMIT 1
       ) v ON true
      WHERE d.concentrator_id = ?
        AND d.ppp_username IS NOT NULL
        AND s.ended_at IS NOT NULL
        AND v.ppp_up IS TRUE`,
    [concentratorId],
  )) as {
    rows: Array<DeviceRef & {
      ppp_username: string;
      ended_at: Date;
      tunnel_ip: string | null;
      caller_ip: string | null;
    }>;
  };

  let reported = 0;
  for (const row of rows.rows ?? []) {
    if (pendingDowns.has(pendingKey(concentratorId, row.ppp_username))) continue; // its timer will
    const graceSec = await presenceGraceSec(row.tenant_id, row.id, row.group_id);
    if (withinGrace(new Date(row.ended_at), graceSec)) continue;
    const change: PresenceChange = {
      concentratorId,
      pppUsername: row.ppp_username,
      up: false,
      deviceId: row.id,
      siteId: row.site_id,
      tunnelIp: row.tunnel_ip,
      callerIp: row.caller_ip,
      changed: true,
      at: new Date(row.ended_at).toISOString(),
    };
    if (await reportDownIfStillDown(change, row, { emitOnlyIfWritten: true })) reported++;
  }
  if (reported > 0) {
    logger.info({ concentratorId, reported }, 'PPP drops reported after their grace period (sweep)');
  }
  return reported;
}

/**
 * Verdict + socket, in that order.
 *
 * The verdict is computed BEFORE the event is emitted so the payload carries a
 * verdict the UI can trust rather than a "we will tell you later". When the
 * username is not bound to any device there is nothing to assess — the history
 * row is still written, and the event still fires for the discoveries screen.
 */
async function publish(
  change: PresenceChange,
  device: DeviceRef | null,
  context: { publicPathChanged?: boolean | null },
  /** `emitOnlyIfWritten`: the grace sweep's report — say nothing unless the
   *  verdict actually moved. Returns whether a verdict row was written. */
  options: { emitOnlyIfWritten?: boolean } = {},
): Promise<boolean> {
  let verdict: SitePresenceEvent['verdict'] = 'UNREACHABLE';
  let written = false;

  if (device) {
    try {
      const recorded = await recordVerdict(
        device.id,
        { pppUp: change.up },
        { publicPathChanged: context.publicPathChanged ?? null },
      );
      verdict = recorded.verdict;
      written = recorded.written;
    } catch (err) {
      logger.error({ err, deviceId: device.id }, 'Verdict evaluation failed; reporting UNREACHABLE');
    }
  }
  if (options.emitOnlyIfWritten && !written) return false;

  const event: SitePresenceEvent = {
    deviceId: change.deviceId,
    siteId: change.siteId,
    concentratorId: change.concentratorId,
    pppUsername: change.pppUsername,
    up: change.up,
    tunnelIp: change.tunnelIp,
    callerIp: change.callerIp,
    verdict,
    at: change.at,
  };

  if (device) {
    emitSitePresence(device.tenant_id, event);
  } else {
    // Unbound username: the concentrator's tenant is the only audience that
    // could act on it.
    const chr = await db('devices')
      .where({ id: change.concentratorId })
      .first<{ tenant_id: number } | undefined>('tenant_id');
    if (chr) emitSitePresence(chr.tenant_id, event);
  }

  logger.info(
    {
      concentratorId: change.concentratorId,
      pppUsername: change.pppUsername,
      up: change.up,
      deviceId: change.deviceId,
      verdict,
    },
    'PPP presence change',
  );
  return written;
}

// ============================================================================
// Reconciliation
// ============================================================================

export interface ReconcileResult {
  concentratorId: number;
  activeOnChr: number;
  openInDb: number;
  opened: number;
  closed: number;
  at: string;
}

/**
 * Make the database agree with the concentrator. This is the correction pass;
 * it is the reason a missed `listen` event costs at most 60 seconds of
 * staleness rather than an indefinite lie.
 */
async function assessUnjudgedOpenSessions(concentratorId: number): Promise<void> {
  const ids = (await db('ppp_sessions as p')
    .join('devices as d', 'd.id', 'p.device_id')
    .where('p.concentrator_id', concentratorId)
    .whereNull('p.ended_at')
    .where('d.concentrator_id', concentratorId)
    .whereNotExists(db('reachability_verdicts as v').whereRaw('v.device_id = d.id').select(db.raw('1')))
    .distinct('d.id')
    .pluck('d.id')) as number[];
  for (const id of ids) await assessDevice(id);
}

export async function reconcile(
  concentratorId: number,
  activeEntries?: PppActiveEntry[],
): Promise<ReconcileResult> {
  let entries: PppActiveEntry[];
  if (activeEntries) {
    entries = activeEntries;
  } else {
    const target = await resolveRouterOsTarget(concentratorId);
    const rows = await getRouterOsPool().withConnection(target, (conn) =>
      conn.query(['/ppp/active/print']),
    );
    entries = rows.map(parseActiveRow).filter((e): e is PppActiveEntry => e !== null);
  }

  // ONE entry per username: `ppp_sessions` holds at most one open row per
  // (concentrator, username), and that invariant stays. When a login holds
  // several sessions, the LAST one printed wins here (RouterOS prints by `.id`,
  // the newest last — the one the CHR routes the address to); the duplicate
  // itself is recorded beside, by `recordActiveRead` below, and the attach and
  // the tunnel jobs refuse that login (pppDuplicates.service.ts).
  const byName = new Map<string, PppActiveEntry>(entries.map((e) => [e.name, e]));

  const openRows = await db('ppp_sessions')
    .where({ concentrator_id: concentratorId })
    .whereNull('ended_at')
    .select<Array<{ ppp_username: string }>>('ppp_username');
  const openNames = new Set(openRows.map((r) => r.ppp_username));

  let opened = 0;
  let closed = 0;

  for (const [name, entry] of byName) {
    if (openNames.has(name)) continue;
    await applySessionUp(concentratorId, {
      username: name,
      tunnelIp: entry.address,
      callerIp: entry.callerId,
    });
    opened++;
  }

  for (const name of openNames) {
    if (byName.has(name)) continue;
    // The CHR no longer lists it and never told us. That is exactly the event
    // a `listen` can drop, and exactly why this sweep exists.
    await applySessionDown(concentratorId, name, 'reconciled-missing');
    closed++;
  }

  // The read succeeded: record what it showed that `ppp_sessions` cannot hold —
  // a login with several live sessions at once. A failure here costs the
  // duplicate listing one sweep, never the presence view.
  await recordActiveRead(concentratorId, entries).catch((err) =>
    logger.warn({ err, concentratorId }, 'Recording the /ppp/active read (duplicate sessions) failed; retried at the next reconciliation'),
  );

  // The grace period's guarantee: a drop whose window closed with no timer to
  // report it (lost to a restart or a leadership change) is reported here.
  await reportExpiredGraces(concentratorId).catch((err) =>
    logger.warn({ err, concentratorId }, 'Grace-period sweep failed; retried at the next reconciliation'),
  );

  // A session that came up while its login was bound to no device published
  // no verdict, and an attach (reconcile or discovery) binds it without one:
  // the device then read "Indéterminé" for as long as the session stayed up.
  // Any device behind this concentrator with an open session and no verdict
  // at all is assessed here.
  await assessUnjudgedOpenSessions(concentratorId).catch((err) =>
    logger.warn({ err, concentratorId }, 'Assessing bound sessions without a verdict failed; retried at the next reconciliation'),
  );

  const result: ReconcileResult = {
    concentratorId,
    activeOnChr: byName.size,
    openInDb: openNames.size,
    opened,
    closed,
    at: new Date().toISOString(),
  };
  if (opened || closed) {
    logger.info(result, 'PPP reconciliation corrected the presence view');
  } else {
    logger.debug(result, 'PPP reconciliation: no drift');
  }
  return result;
}

// ============================================================================
// The live monitor
// ============================================================================

interface TrackedSession {
  username: string;
  address: string | null;
  callerId: string | null;
}

class ConcentratorMonitor {
  private stream: RouterOsStream | null = null;
  private reconcileTimer: NodeJS.Timeout | null = null;
  private retryTimer: NodeJS.Timeout | null = null;
  private stopped = false;
  /** RouterOS `.id` -> session. Per-stream, in memory, never persisted. */
  private readonly byRouterId = new Map<string, TrackedSession>();
  /** Serialises DB work so a burst of listen events cannot interleave an
   *  up and a down for the same username. */
  private queue: Promise<void> = Promise.resolve();

  constructor(readonly concentratorId: number) {}

  async start(): Promise<void> {
    this.stopped = false;
    await this.openStream();
    // The first sweep runs immediately: on a cold start the database may hold
    // sessions from before the process died.
    await this.safeReconcile();
    this.reconcileTimer = setInterval(() => void this.safeReconcile(), RECONCILE_INTERVAL_MS);
    this.reconcileTimer.unref();
  }

  async stop(): Promise<void> {
    this.stopped = true;
    if (this.reconcileTimer) clearInterval(this.reconcileTimer);
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.reconcileTimer = null;
    this.retryTimer = null;
    const stream = this.stream;
    this.stream = null;
    // Never leave a `listen` registered on the router: an abandoned one stays
    // there forever and the next leader will add a second.
    if (stream) await stream.cancel().catch(() => undefined);
    await this.queue.catch(() => undefined);
  }

  get isStreaming(): boolean {
    return this.stream !== null && !this.stream.isClosed;
  }

  private enqueue(fn: () => Promise<void>): void {
    this.queue = this.queue.then(fn).catch((err) => {
      logger.error({ err, concentratorId: this.concentratorId }, 'Presence task failed');
    });
  }

  private async openStream(): Promise<void> {
    if (this.stopped || this.stream) return;
    try {
      const target = await resolveRouterOsTarget(this.concentratorId);
      const conn = await getRouterOsPool().acquire(target);
      this.byRouterId.clear();
      this.stream = conn.stream(['/ppp/active/listen'], {
        onRow: (row) => this.onListenRow(row),
        onDone: () => this.onStreamGone(null),
        onError: (err) => this.onStreamGone(err),
      });
      logger.info(
        { concentratorId: this.concentratorId, tag: this.stream.tag },
        'PPP listen established on the concentrator',
      );
    } catch (err) {
      logger.warn(
        { err, concentratorId: this.concentratorId },
        'Could not open /ppp/active/listen; will retry',
      );
      this.enqueue(async () => {
        await markConcentratorDegraded(
          this.concentratorId,
          err instanceof Error ? err.message : String(err),
        );
      });
      this.scheduleRetry();
    }
  }

  private onStreamGone(err: Error | null): void {
    if (this.stopped) return;
    this.stream = null;
    this.byRouterId.clear();
    logger.warn(
      { concentratorId: this.concentratorId, err: err?.message },
      'PPP listen ended; re-opening',
    );
    this.scheduleRetry();
  }

  /**
   * Re-open the `listen` NOW instead of at the next retry tick. Called by the
   * permanent health check when it has just proved the CHR answers: the stream
   * may be sitting out a retry, and presence is what the "never dial a down session" rule runs on. A no-op when
   * the stream is already up or the monitor was stopped.
   */
  kick(): void {
    if (this.stopped || this.isStreaming) return;
    if (this.retryTimer) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
    void this.openStream().then(() => this.safeReconcile());
  }

  private scheduleRetry(): void {
    if (this.stopped || this.retryTimer) return;
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      void this.openStream().then(() => this.safeReconcile());
    }, STREAM_RETRY_MS);
    this.retryTimer.unref();
  }

  /**
   * One `!re` from the listen.
   *
   * RouterOS pushes an add event with the full attribute set, and a teardown
   * event that carries `.id` plus `.dead=true` and frequently nothing else.
   * That asymmetry is why the `.id` map exists.
   */
  private onListenRow(row: Sentence): void {
    const attrs = row.attrs;
    const routerId = attrs['.id'] ?? null;
    const dead = attrs['.dead'] === 'true' || attrs['.dead'] === 'yes';

    if (dead) {
      const known = routerId ? this.byRouterId.get(routerId) : undefined;
      const username = attrs.name ?? known?.username ?? null;
      if (routerId) this.byRouterId.delete(routerId);
      if (!username) {
        // We were told a session died and cannot say which. Guessing would be
        // worse than useless: sweep instead.
        logger.warn(
          { concentratorId: this.concentratorId, routerId },
          'PPP teardown for an unknown .id — forcing a reconciliation',
        );
        this.enqueue(() => this.safeReconcile());
        return;
      }
      // ONE of several sessions of this login ended (pppDuplicates.service.ts):
      // the login is still up through the other one. Closing its open row
      // would report a store down that is not; the row is refreshed with the
      // remaining session's addressing instead, and a sweep re-records the
      // duplicates (this one may be gone).
      const remaining = this.otherSession(username, routerId, false);
      if (remaining) {
        this.enqueue(async () => {
          await applySessionUp(this.concentratorId, {
            username,
            tunnelIp: remaining.address,
            callerIp: remaining.callerId,
          });
        });
        this.enqueue(() => this.safeReconcile());
        return;
      }
      this.enqueue(async () => {
        await applySessionDown(this.concentratorId, username, attrs['disconnect-reason'] ?? 'listen');
      });
      return;
    }

    const entry = parseActiveRow(attrs);
    if (!entry) {
      // An add event with no name is unusable on its own; the sweep will pick
      // the session up within 60 s.
      logger.debug({ concentratorId: this.concentratorId, attrs: Object.keys(attrs) }, 'PPP listen row without a name');
      return;
    }
    if (routerId) {
      this.byRouterId.set(routerId, {
        username: entry.name,
        address: entry.address,
        callerId: entry.callerId,
      });
    }
    this.enqueue(async () => {
      await applySessionUp(this.concentratorId, {
        username: entry.name,
        tunnelIp: entry.address,
        callerIp: entry.callerId,
      });
    });
    // A SECOND live session for a login this stream already tracks (without
    // regard to case): the login just became ambiguous. A sweep now, rather
    // than in up to 60 s, records it, so the attach and the tunnel jobs see it.
    if (this.otherSession(entry.name, routerId, true)) {
      this.enqueue(() => this.safeReconcile());
    }
  }

  /** Another session this stream tracks for `username` than `exceptRouterId`
   *  — the exact spelling (one `ppp_sessions` row), or any case. */
  private otherSession(username: string, exceptRouterId: string | null, anyCase: boolean): TrackedSession | null {
    const key = anyCase ? username.toLowerCase() : username;
    for (const [id, s] of this.byRouterId) {
      if (id === exceptRouterId) continue;
      if ((anyCase ? s.username.toLowerCase() : s.username) === key) return s;
    }
    return null;
  }

  private async safeReconcile(): Promise<void> {
    if (this.stopped) return;
    try {
      const entries = await this.readActive();
      // Refresh the `.id` map from ground truth so a teardown that arrives
      // after a stream restart still resolves to a username.
      this.byRouterId.clear();
      for (const e of entries) {
        if (e.routerId) {
          this.byRouterId.set(e.routerId, {
            username: e.name,
            address: e.address,
            callerId: e.callerId,
          });
        }
      }
      await reconcile(this.concentratorId, entries);
      // The sweep just read `/ppp/active` through the API: the concentrator
      // is answering. If a failed listen or sweep had declared it degraded,
      // that verdict ends here — nothing else used to end it, and the CHR's
      // page read "degraded" for ever after its API came back.
      await recordConcentratorRecovery(this.concentratorId).catch((err) =>
        logger.warn({ err, concentratorId: this.concentratorId }, 'Could not record concentrator recovery'),
      );
    } catch (err) {
      logger.warn(
        { err, concentratorId: this.concentratorId },
        'PPP reconciliation failed; the concentrator is degraded',
      );
      // Degraded concentrator: one alert on the concentrator, and every child verdict suppressed.
      // The sessions in the database are NOT closed — we do not know that they
      // ended, and inventing 300 outages is the failure this guards against.
      await markConcentratorDegraded(
        this.concentratorId,
        err instanceof Error ? err.message : String(err),
      ).catch(() => undefined);
    }
  }

  private async readActive(): Promise<PppActiveEntry[]> {
    const target = await resolveRouterOsTarget(this.concentratorId);
    const rows = await getRouterOsPool().withConnection(target, (conn) =>
      conn.query(['/ppp/active/print']),
    );
    return rows.map(parseActiveRow).filter((e): e is PppActiveEntry => e !== null);
  }
}

// ============================================================================
// Service facade
// ============================================================================

class PppPresenceService {
  private readonly monitors = new Map<number, ConcentratorMonitor>();
  private running = false;

  get isRunning(): boolean {
    return this.running;
  }

  get watched(): number[] {
    return Array.from(this.monitors.keys());
  }

  isWatching(concentratorId: number): boolean {
    return this.monitors.has(concentratorId);
  }

  /** Watch one concentrator. Idempotent. */
  async watch(concentratorId: number): Promise<void> {
    if (this.monitors.has(concentratorId)) return;
    await requireConcentrator(concentratorId);
    const monitor = new ConcentratorMonitor(concentratorId);
    this.monitors.set(concentratorId, monitor);
    try {
      await monitor.start();
    } catch (err) {
      this.monitors.delete(concentratorId);
      throw err;
    }
  }

  async unwatch(concentratorId: number): Promise<void> {
    const monitor = this.monitors.get(concentratorId);
    if (!monitor) return;
    this.monitors.delete(concentratorId);
    await monitor.stop();
  }

  /**
   * Start watching every enabled concentrator. Called by the leadership gate;
   * a follower never reaches this.
   */
  async startAll(): Promise<number[]> {
    this.running = true;
    const rows = await db('devices')
      .where({ role: 'concentrator' })
      .whereNotIn('status', ['disabled'])
      .select<Array<{ id: number; name: string }>>('id', 'name');

    const started: number[] = [];
    for (const row of rows) {
      try {
        await this.watch(row.id);
        started.push(row.id);
      } catch (err) {
        // One unreachable CHR must not stop the others from being watched.
        logger.error({ err, concentratorId: row.id }, 'Could not start presence on concentrator');
      }
    }
    logger.info({ concentrators: started }, 'PPP presence started');
    return started;
  }

  async stopAll(): Promise<void> {
    this.running = false;
    const ids = Array.from(this.monitors.keys());
    await Promise.all(ids.map((id) => this.unwatch(id)));
    // Held reports belong to this leader's timers; the next leader's sweep
    // reports whatever is still down once its window has closed.
    cancelAllPendingDowns();
    logger.info('PPP presence stopped');
  }

  /**
   * Make sure presence is streaming from this concentrator. Called by the
   * permanent health check after a successful read of the CHR.
   *
   * Leadership is inherited, not re-checked: presence only RUNS on the leader
   * (`startAll()` is called from the leadership gate), so on any other process
   * this returns 'not_running' and dials nothing.
   *
   *   started    the concentrator had no monitor (its start failed earlier,
   *              or it was declared since): it is watched now.
   *   kicked     a monitor exists but its `listen` is down: re-opened now
   *              rather than at the next retry.
   *   streaming  nothing to do.
   */
  async ensureStreaming(
    concentratorId: number,
  ): Promise<'not_running' | 'started' | 'kicked' | 'streaming'> {
    if (!this.running) return 'not_running';
    const monitor = this.monitors.get(concentratorId);
    if (!monitor) {
      await this.watch(concentratorId);
      return 'started';
    }
    if (monitor.isStreaming) return 'streaming';
    monitor.kick();
    return 'kicked';
  }

  /** Force a sweep now (used by the API and by tests). */
  reconcileNow(concentratorId: number): Promise<ReconcileResult> {
    return reconcile(concentratorId);
  }

  /** Re-assess every device of a concentrator without touching the CHR. */
  async assessChildren(concentratorId: number): Promise<number> {
    const children = await db('devices')
      .where({ concentrator_id: concentratorId })
      .pluck<number[]>('id');
    for (const id of children) {
      await assessDevice(id).catch((err) =>
        logger.warn({ err, deviceId: id }, 'Assessment failed'),
      );
    }
    return children.length;
  }
}

export const pppPresence = new PppPresenceService();
