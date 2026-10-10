/**
 * ObliWAN — the alerts of the access verification: ONE per workspace and per
 * CAUSE (operator GO 2026-10-09; shared/src/accessCheck.ts, migration 093,
 * `access_check_alerts`).
 *
 * ┌─ WHICH RUNS ─────────────────────────────────────────────────────────────┐
 * │ A run is evaluated once (`alerts_evaluated_at`), right after it ends     │
 * │ (accessCheck.service `startAccessCheck`), or by the nightly runtime's    │
 * │ post-run sweep when its process died first. Only a run that can say     │
 * │ something about the WHOLE workspace moves the alerts: done (never an     │
 * │ interrupted one), over the workspace (`scope = 'tenant'`: a teams-scoped │
 * │ run saw a part of it), every router verified, and the newest such run —  │
 * │ an older one evaluated late is `superseded`. Nightly or manual alike:    │
 * │ an operator who fixed things and verifies again closes what is fixed.    │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHAT IS ALERTED ────────────────────────────────────────────────────────┐
 * │ `accessCheckAlertCauses` (shared, pure) on each router of the run still  │
 * │ ACTIVE in the workspace: the access missing or broken by its reason, the │
 * │ access unknown, another router's identity, the fixes missing, the fixes  │
 * │ unreadable, a duplicated PPP login. NOT an offline router, a degraded    │
 * │ presence, a router busy with a job (presence is the concentrator's job;  │
 * │ a running job is no state to judge), nor a bench-prepared router not     │
 * │ qualified yet (in shipping: the health check holds its alerts too).      │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ OPEN, WORSEN, SAME, CLOSE ──────────────────────────────────────────────┐
 * │ A cause found and not open      -> OPENED: one live alert (tenant-level,  │
 * │                                    listing its routers, linking to the    │
 * │                                    reconciliation with the verification   │
 * │                                    open) and one notification.            │
 * │ Open, and a router that did NOT -> WORSENED: the live alert is REPLACED   │
 * │ have it at the previous run now    (one per open cause, shown unread     │
 * │ has it                             again) and notified again.            │
 * │ Open, no newcomer (the same, or -> its live alert's title and list are   │
 * │ fewer routers)                     brought up to date in place: NOTHING   │
 * │                                    is notified — not every night.        │
 * │ Open and no longer found        -> CLOSED: the alert is marked read, a   │
 * │                                    "resolved" notice is added and the     │
 * │                                    recovery notified (a ticketing channel │
 * │                                    closes the incident: same stable key). │
 * │ One transaction under a per-workspace advisory lock: two evaluations    │
 * │ never interleave, and the live alerts are written in it (the row an     │
 * │ alert points at is never deleted from another connection while this one │
 * │ holds it); the sockets and the channels are told after the commit.      │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The routers whose previous AUTOMATIC re-apply failed for the cause are named
 * in its alert: the night no longer re-applies them (accessCheckNightly), a
 * human does.
 *
 * Operator-facing sentences are French, like the change jobs' own (the task's
 * own wording: « Accès de gestion : 12 routeurs — certificat refusé »).
 */

import type { Knex } from 'knex';
import {
  ACCESS_CHECK_NIGHTLY_TIME_ZONE,
  SOCKET_EVENTS,
  accessCheckAlertCauses,
  accessCheckCauseKey,
  parseAccessCheckCauseKey,
  socketRooms,
  type AccessCheckAlertCause,
  type AccessCheckOpenAlert,
  type AccessCheckRow,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import type { NotificationPayload } from '../../notifications/types';
import { notificationService } from '../notification.service';
import { emitToTenantAudience } from './scopedEmit';
import { resolveBenchQualification } from './benchQualification.service';
import { autoKindOfCause, lastAutoFailures } from './accessCheckOrigin';

/** Where every alert of the verification leads: the reconciliation page, the
 *  verification dialog open (ReconcilePage reads `accessCheck`). */
export const ACCESS_CHECK_ALERTS_URL = '/reconcile?accessCheck=1';
export const ACCESS_CHECK_NOTIFICATION_EVENT = 'access_check';
/** pg_advisory_xact_lock(class, tenant): one evaluation per workspace. */
const LOCK_CLASS = 930_093;
/** Closed alerts kept, for the history of a cause. */
const CLOSED_KEPT_DAYS = 90;
/** liveAlertService's own trim (newest 200 per workspace). */
const LIVE_ALERTS_KEPT = 200;
/** Router names listed in one alert. */
const NAMES_SHOWN = 20;

// ============================================================================
// Seams
// ============================================================================

export interface AccessCheckAlertDeps {
  notify(tenantId: number, eventType: string, payload: NotificationPayload): Promise<void>;
  now(): number;
}
const DEFAULT_DEPS: AccessCheckAlertDeps = {
  notify: (tenantId, eventType, payload) => notificationService.sendForTenant(tenantId, eventType, payload),
  now: () => Date.now(),
};
let deps: AccessCheckAlertDeps = { ...DEFAULT_DEPS };
export function setAccessCheckAlertDeps(next: Partial<AccessCheckAlertDeps>): void {
  deps = { ...deps, ...next };
}
export function resetAccessCheckAlertDeps(): void {
  deps = { ...DEFAULT_DEPS };
}

const pending = new Set<Promise<void>>();
function deliverDetached(tenantId: number, send: () => Promise<void>): void {
  const p: Promise<void> = send()
    .catch((err: unknown) => logger.warn({ err, tenantId }, 'Access check notification failed (the live alert is raised)'))
    .finally(() => {
      pending.delete(p);
    });
  pending.add(p);
}
/** For shutdown and harnesses: wait for the channel messages already sent. */
export async function flushAccessCheckNotifications(): Promise<void> {
  while (pending.size > 0) await Promise.allSettled(Array.from(pending));
}

// ============================================================================
// Pure: the French sentences
// ============================================================================

const ACCESS_REASON_FR: Record<string, string> = {
  no_transport: 'aucun accès API enregistré',
  transport_disabled: 'accès API désactivé',
  not_tls: 'accès API sans TLS',
  not_8729: 'accès API hors du port 8729',
  no_credential: 'accès API sans identifiant',
  not_pinned: 'certificat non épinglé',
  account_not_switched: 'compte obliwan non utilisé',
  tls: 'poignée de main TLS en échec',
  auth: 'identifiants refusés',
  timeout: 'pas de réponse',
  refused: 'connexion refusée',
  unreachable: 'injoignable',
  cert_mismatch: 'certificat refusé',
  identity_unproven: 'identité non prouvée',
  vault: 'mot de passe du coffre illisible',
  budget_exceeded: 'temps imparti dépassé',
  internal: 'erreur interne',
};
const COMPLIANCE_REASON_FR: Record<string, string> = {
  no_ssh: 'aucun accès SSH utilisable',
  vault: 'mot de passe du coffre illisible',
  auth: 'connexion SSH refusée',
  unreachable: 'SSH injoignable',
  timeout: 'délai SSH dépassé',
  ssh_failed: 'session SSH en échec',
  identity_unproven: 'identité non prouvée',
  budget_exceeded: 'temps imparti dépassé',
  internal: 'erreur interne',
};

function reasonFr(map: Record<string, string>, reason: string | null): string {
  return (reason && map[reason]) || reason || 'raison inconnue';
}

export function routersFr(n: number): string {
  return n === 1 ? '1 routeur' : `${n} routeurs`;
}

/** The cause with its count — the alert's title. */
export function causeTitleFr(cause: AccessCheckAlertCause, count: number): string {
  const n = routersFr(count);
  switch (cause.kind) {
    case 'access':
      return `Accès de gestion : ${n} — ${reasonFr(ACCESS_REASON_FR, cause.reason)}`;
    case 'access_unknown':
      return `Accès de gestion : ${n} — non vérifié (${reasonFr(ACCESS_REASON_FR, cause.reason)})`;
    case 'identity':
      return `Identité discordante : ${n} — un autre routeur a répondu`;
    case 'compliance':
      return `Conformité : ${n} — correctifs manquants`;
    case 'compliance_unknown':
      return `Conformité : ${n} — lecture impossible (${reasonFr(COMPLIANCE_REASON_FR, cause.reason)})`;
    case 'ppp_duplicated':
      return `Doublon de session PPP : ${n}`;
  }
}

/** The cause without its count — the notice that closes it. */
export function causeNameFr(cause: AccessCheckAlertCause): string {
  switch (cause.kind) {
    case 'access':
      return `Accès de gestion — ${reasonFr(ACCESS_REASON_FR, cause.reason)}`;
    case 'access_unknown':
      return `Accès de gestion — non vérifié (${reasonFr(ACCESS_REASON_FR, cause.reason)})`;
    case 'identity':
      return 'Identité discordante';
    case 'compliance':
      return 'Conformité — correctifs manquants';
    case 'compliance_unknown':
      return `Conformité — lecture impossible (${reasonFr(COMPLIANCE_REASON_FR, cause.reason)})`;
    case 'ppp_duplicated':
      return 'Doublon de session PPP';
  }
}

const PARIS = new Intl.DateTimeFormat('fr-FR', { timeZone: ACCESS_CHECK_NIGHTLY_TIME_ZONE, dateStyle: 'short', timeStyle: 'short' });

function nameList(names: readonly string[]): string {
  const shown = names.slice(0, NAMES_SHOWN).join(', ');
  return names.length > NAMES_SHOWN ? `${shown} (et ${names.length - NAMES_SHOWN} autres)` : shown;
}

export function alertMessageFr(
  run: { number: number; trigger: string; startedAt: Date },
  names: readonly string[],
  suspended: readonly string[],
): string {
  const who = run.trigger === 'nightly' ? 'de nuit' : 'manuelle';
  let out = `Vérification ${who} n° ${run.number} du ${PARIS.format(run.startedAt)}. Routeurs : ${nameList(names)}.`;
  if (suspended.length > 0) {
    out +=
      ` Non réappliqués automatiquement (la réapplication automatique précédente a échoué pour cette cause, ` +
      `à reprendre à la main) : ${nameList(suspended)}.`;
  }
  return `${out} Le détail est dans la réconciliation, « Vérifier l’accès de gestion et la conformité ».`;
}

// ============================================================================
// Evaluation
// ============================================================================

export type AlertEvaluationStatus =
  | 'evaluated'
  | 'already'
  | 'not_found'
  | 'not_done'
  | 'partial_scope'
  | 'incomplete'
  | 'superseded';

export interface AlertEvaluation {
  status: AlertEvaluationStatus;
  opened: string[];
  worsened: string[];
  unchanged: string[];
  closed: string[];
}

interface OpenRow {
  id: string | number;
  cause: string;
  opened_at: Date;
  opened_run: string | number;
  last_run: string | number;
  device_ids: number[];
  device_count: number;
  live_alert_id: number | null;
}

async function insertLive(
  trx: Knex.Transaction,
  tenantId: number,
  o: { severity: 'warning' | 'up'; title: string; message: string; stableKey: string },
): Promise<Record<string, unknown>> {
  const [row] = (await trx('live_alerts')
    .insert({
      tenant_id: tenantId,
      severity: o.severity,
      title: o.title,
      message: o.message,
      navigate_to: ACCESS_CHECK_ALERTS_URL,
      stable_key: o.stableKey,
    })
    .returning('*')) as Array<Record<string, unknown>>;
  return row;
}

/**
 * The socket half of liveAlertService.add, for a row inserted in this
 * module's transaction, once committed: a tenant-level alert (no subject), to
 * the workspace's notification room and the god view's.
 */
async function announce(row: Record<string, unknown>): Promise<void> {
  const tenantId = Number(row.tenant_id);
  const tenant = (await db('tenants').where({ id: tenantId }).first('name')) as { name: string } | undefined;
  const alert = {
    id: Number(row.id),
    tenantId,
    tenantName: tenant?.name ?? '',
    severity: row.severity,
    title: row.title,
    message: row.message,
    navigateTo: (row.navigate_to as string | null) ?? null,
    stableKey: (row.stable_key as string | null) ?? null,
    deviceId: null,
    siteId: null,
    simLineId: null,
    read: row.read_at !== null && row.read_at !== undefined,
    createdAt: new Date(row.created_at as Date).toISOString(),
    outageId: null,
    outageRole: null,
  };
  emitToTenantAudience(
    tenantId,
    SOCKET_EVENTS.NOTIFICATION_NEW,
    alert,
    'tenant',
    socketRooms.tenantNotifications(tenantId),
    socketRooms.godViewNotifications(),
  );
}

function incidentKey(tenantId: number, cause: string, openedAt: Date): string {
  return `obliwan:tenant:${tenantId}:access-check:${cause}:${openedAt.getTime()}`;
}

/**
 * Evaluate the alerts after one run (the header). Never called twice on the
 * same run with effect; returns what it did. Throws on a database error — the
 * caller logs it, and the post-run sweep takes the run up again.
 */
export async function evaluateAccessCheckAlerts(tenantId: number, runPk: number): Promise<AlertEvaluation> {
  const ev: AlertEvaluation = { status: 'evaluated', opened: [], worsened: [], unchanged: [], closed: [] };
  const toAnnounce: Array<Record<string, unknown>> = [];
  const toNotify: NotificationPayload[] = [];
  const now = new Date(deps.now());

  await db.transaction(async (trx) => {
    await trx.raw('SELECT pg_advisory_xact_lock(?, ?)', [LOCK_CLASS, tenantId]);
    const run = (await trx('access_check_runs')
      .where({ id: runPk, tenant_id: tenantId })
      .first('id', 'status', 'scope', 'trigger', 'started_at', 'alerts_evaluated_at')) as
      | { id: string | number; status: string; scope: string; trigger: string; started_at: Date; alerts_evaluated_at: Date | null }
      | undefined;
    if (!run) {
      ev.status = 'not_found';
      return;
    }
    if (run.alerts_evaluated_at !== null) {
      ev.status = 'already';
      return;
    }
    if (run.status === 'running') {
      ev.status = 'not_done';
      return;
    }
    const stamp = async (status: AlertEvaluationStatus): Promise<void> => {
      ev.status = status;
      await trx('access_check_runs').where({ id: runPk }).update({ alerts_evaluated_at: now });
    };
    if (run.status !== 'done') return stamp('not_done');
    if (run.scope !== 'tenant') return stamp('partial_scope');
    const left = (await trx('access_check_results').where({ run_id: runPk, state: 'pending' }).first('id')) as unknown;
    if (left) return stamp('incomplete');
    const newer = (await trx('access_check_runs')
      .where({ tenant_id: tenantId, status: 'done', scope: 'tenant' })
      .where('id', '>', runPk)
      .first('id')) as unknown;
    if (newer) return stamp('superseded');

    // ── The causes of this run ────────────────────────────────────────────
    const rows = (await trx('access_check_results as x')
      .join('devices as d', 'd.id', 'x.device_id')
      .where('x.run_id', runPk)
      .where('x.tenant_id', tenantId)
      .where('d.tenant_id', tenantId)
      .where('d.status', 'active')
      .select('x.device_id', 'd.name', 'd.concentrator_id', 'd.ppp_username', 'x.result')) as Array<{
      device_id: number; name: string; concentrator_id: number | null; ppp_username: string | null;
      result: Pick<AccessCheckRow, 'presence' | 'busy' | 'access' | 'compliance'> | null;
    }>;
    const names = new Map<number, string>();
    const found = new Map<string, { cause: AccessCheckAlertCause; ids: Set<number> }>();
    const candidates = new Map<number, (typeof rows)[number]>();
    for (const r of rows) {
      if (!r.result) continue;
      const causes = accessCheckAlertCauses(r.result);
      if (causes.length === 0) continue;
      const id = Number(r.device_id);
      names.set(id, r.name);
      candidates.set(id, r);
      for (const c of causes) {
        const key = accessCheckCauseKey(c);
        const entry = found.get(key) ?? { cause: c, ids: new Set<number>() };
        entry.ids.add(id);
        found.set(key, entry);
      }
    }
    // A bench-prepared router not qualified yet is held, like its health alerts.
    const held = new Set<number>();
    for (const [id, r] of candidates) {
      const q = await resolveBenchQualification(
        { id, concentrator_id: r.concentrator_id === null ? null : Number(r.concentrator_id), ppp_username: r.ppp_username },
        now,
        { persist: false },
      ).catch(() => null);
      if (q && q.verdict.state !== 'qualified') held.add(id);
    }
    for (const [key, entry] of found) {
      for (const id of held) entry.ids.delete(id);
      if (entry.ids.size === 0) found.delete(key);
    }
    const failures = await lastAutoFailures(tenantId, [...candidates.keys()]);
    const suspendedOf = (key: string, ids: readonly number[]): number[] => {
      const kind = autoKindOfCause(key);
      if (!kind) return [];
      return ids.filter((id) => failures.get(`${id}:${kind}`)?.cause === key);
    };
    const byName = (ids: readonly number[]): string[] =>
      ids.map((id) => names.get(id) ?? `#${id}`).sort((a, b) => a.localeCompare(b));
    const runInfo = { number: Number(run.id), trigger: run.trigger, startedAt: new Date(run.started_at) };

    // ── Against what is open ──────────────────────────────────────────────
    const open = (await trx('access_check_alerts')
      .where({ tenant_id: tenantId })
      .whereNull('closed_at')
      .select('id', 'cause', 'opened_at', 'opened_run', 'last_run', 'device_ids', 'device_count', 'live_alert_id')) as OpenRow[];
    const openByCause = new Map(open.map((o) => [o.cause, o]));

    for (const [key, entry] of found) {
      const ids = [...entry.ids].sort((a, b) => a - b);
      const title = causeTitleFr(entry.cause, ids.length);
      const message = alertMessageFr(runInfo, byName(ids), byName(suspendedOf(key, ids)));
      const prev = openByCause.get(key);
      if (!prev) {
        const live = await insertLive(trx, tenantId, { severity: 'warning', title, message, stableKey: `access-check:${tenantId}:${key}:${runPk}` });
        toAnnounce.push(live);
        await trx('access_check_alerts').insert({
          tenant_id: tenantId, cause: key, opened_at: now, opened_run: runPk, last_run: runPk,
          device_ids: JSON.stringify(ids), device_count: ids.length, notified_at: now, live_alert_id: Number(live.id),
        });
        toNotify.push(payload(tenantId, key, entry.cause, title, message, now, now, ids.length, false));
        ev.opened.push(key);
        continue;
      }
      if (Number(prev.last_run) >= runPk) continue;
      const before = new Set((prev.device_ids ?? []).map(Number));
      const newcomers = ids.filter((id) => !before.has(id));
      if (newcomers.length > 0) {
        // Replaced, not added: one live alert per open cause, unread again.
        if (prev.live_alert_id !== null) await trx('live_alerts').where({ id: prev.live_alert_id, tenant_id: tenantId }).delete();
        const live = await insertLive(trx, tenantId, { severity: 'warning', title, message, stableKey: `access-check:${tenantId}:${key}:${runPk}` });
        toAnnounce.push(live);
        await trx('access_check_alerts').where({ id: prev.id }).update({
          last_run: runPk, device_ids: JSON.stringify(ids), device_count: ids.length, notified_at: now, live_alert_id: Number(live.id),
        });
        toNotify.push(payload(tenantId, key, entry.cause, title, message, new Date(prev.opened_at), now, ids.length, false));
        ev.worsened.push(key);
      } else {
        // The same, or better: brought up to date in place, nothing notified.
        if (prev.live_alert_id !== null) {
          await trx('live_alerts').where({ id: prev.live_alert_id, tenant_id: tenantId }).update({ title, message });
        }
        await trx('access_check_alerts').where({ id: prev.id }).update({
          last_run: runPk, device_ids: JSON.stringify(ids), device_count: ids.length,
        });
        ev.unchanged.push(key);
      }
    }

    for (const prev of open) {
      if (found.has(prev.cause)) continue;
      const cause = parseAccessCheckCauseKey(prev.cause) ?? { kind: 'access' as const, reason: prev.cause };
      const openedAt = new Date(prev.opened_at);
      if (prev.live_alert_id !== null) {
        await trx('live_alerts').where({ id: prev.live_alert_id, tenant_id: tenantId }).whereNull('read_at').update({ read_at: now });
      }
      const title = `Résolu — ${causeNameFr(cause)}`;
      const message =
        `La vérification ${runInfo.trigger === 'nightly' ? 'de nuit' : 'manuelle'} n° ${runInfo.number} ne trouve plus cette cause ` +
        `(ouverte le ${PARIS.format(openedAt)} par la vérification n° ${Number(prev.opened_run)}).`;
      const live = await insertLive(trx, tenantId, { severity: 'up', title, message, stableKey: `access-check-end:${tenantId}:${prev.cause}:${Number(prev.opened_run)}` });
      toAnnounce.push(live);
      await trx('access_check_alerts').where({ id: prev.id }).update({ closed_at: now, closed_run: runPk, last_run: Math.max(runPk, Number(prev.last_run)) });
      toNotify.push(payload(tenantId, prev.cause, cause, title, message, openedAt, now, 0, true));
      ev.closed.push(prev.cause);
    }

    // liveAlertService's trim, on this connection (see `insertLive`).
    await trx.raw(
      'DELETE FROM live_alerts WHERE tenant_id = ? AND id NOT IN (SELECT id FROM live_alerts WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?)',
      [tenantId, tenantId, LIVE_ALERTS_KEPT],
    );
    await trx('access_check_alerts')
      .where({ tenant_id: tenantId })
      .whereNotNull('closed_at')
      .where('closed_at', '<', new Date(now.getTime() - CLOSED_KEPT_DAYS * 86_400_000))
      .delete();
    await trx('access_check_runs').where({ id: runPk }).update({ alerts_evaluated_at: now });
  });

  for (const row of toAnnounce) {
    await announce(row).catch((err: unknown) => logger.warn({ err, tenantId }, 'Access check: a live alert could not be announced'));
  }
  for (const p of toNotify) deliverDetached(tenantId, () => deps.notify(tenantId, ACCESS_CHECK_NOTIFICATION_EVENT, p));
  if (ev.opened.length + ev.worsened.length + ev.closed.length > 0) {
    logger.info({ tenantId, runPk, opened: ev.opened, worsened: ev.worsened, closed: ev.closed }, 'Access check alerts moved');
  }
  return ev;
}

function payload(
  tenantId: number,
  key: string,
  cause: AccessCheckAlertCause,
  title: string,
  message: string,
  openedAt: Date,
  now: Date,
  count: number,
  recovery: boolean,
): NotificationPayload {
  return {
    entityName: causeNameFr(cause),
    entityUrl: ACCESS_CHECK_ALERTS_URL,
    oldStatus: recovery ? 'alert' : 'ok',
    newStatus: recovery ? 'ok' : 'alert',
    message: `${title}. ${message}`,
    timestamp: now.toISOString(),
    // One incident per opening: the worsening and the recovery carry its key.
    stableKey: incidentKey(tenantId, key, openedAt),
    severity: 'warning',
    isRecovery: recovery,
    occurredAt: openedAt.toISOString(),
    ...(recovery ? { recoveredAt: now.toISOString() } : { occurrenceCount: count }),
    entityId: tenantId,
    entityType: 'tenant',
  };
}

/** Never throws: the run's own completion logs and moves on, and the
 *  nightly post-run sweep takes the run up again. */
export async function evaluateAccessCheckAlertsSafe(tenantId: number, runPk: number): Promise<AlertEvaluation | null> {
  try {
    return await evaluateAccessCheckAlerts(tenantId, runPk);
  } catch (err) {
    logger.error({ err, tenantId, runPk }, 'Access check: the alerts could not be evaluated (taken up by the next sweep)');
    return null;
  }
}

/** The workspace's open alerts, largest first (the reconciliation page). */
export async function listOpenAccessCheckAlerts(tenantId: number): Promise<AccessCheckOpenAlert[]> {
  const open = (await db('access_check_alerts')
    .where({ tenant_id: tenantId })
    .whereNull('closed_at')
    .select('cause', 'opened_at', 'last_run', 'device_ids', 'device_count')) as Array<{
    cause: string; opened_at: Date; last_run: string | number; device_ids: number[]; device_count: number;
  }>;
  const all = [...new Set(open.flatMap((o) => (o.device_ids ?? []).map(Number)))];
  const failures = await lastAutoFailures(tenantId, all);
  const out: AccessCheckOpenAlert[] = [];
  for (const o of open) {
    const c = parseAccessCheckCauseKey(o.cause);
    if (!c) continue;
    const kind = autoKindOfCause(o.cause);
    const suspended = kind ? (o.device_ids ?? []).filter((id) => failures.get(`${Number(id)}:${kind}`)?.cause === o.cause).length : 0;
    out.push({
      cause: o.cause, kind: c.kind, reason: c.reason, count: Number(o.device_count),
      openedAt: new Date(o.opened_at).toISOString(), lastRun: Number(o.last_run), suspended,
    });
  }
  return out.sort((a, b) => b.count - a.count || a.cause.localeCompare(b.cause));
}
