/**
 * ObliWAN — the NIGHTLY verification of the management access and the template
 * fixes, and its optional AUTOMATIC re-apply (operator GO 2026-10-09;
 * shared/src/accessCheck.ts, migration 093). The verification itself is the
 * button's (accessCheck.service.ts), unchanged; its alerts are
 * accessCheckAlerts.service.ts.
 *
 * ┌─ 1. THE NIGHT — READ-ONLY, ON THE LEADER ────────────────────────────────┐
 * │ Every minute, on the leader only, for every workspace with an           │
 * │ active MikroTik that is not a concentrator, its own inherited settings: │
 * │ `access_check_nightly` (ON by default: it writes nothing to a router)   │
 * │ and `access_check_nightly_hour` (3, Europe/Paris). Due when the hour of │
 * │ the night has passed by less than ACCESS_CHECK_NIGHTLY_CATCHUP_MS (a    │
 * │ night missed longer is given up — no verification, and no re-apply, at  │
 * │ midday) and no run of that night is running or done. Started as a      │
 * │ `nightly` run: the whole workspace, nobody's, its night recorded.        │
 * │  · never two runs of a workspace at once: the run table's own one-      │
 * │    running index — a manual run in progress makes the night WAIT for   │
 * │    it (next minute), and a manual click during the night's run is      │
 * │    refused as it is today (RUN_RUNNING);                                │
 * │  · once a night: at most one nightly run running or done per workspace  │
 * │    and night (partial unique index);                                    │
 * │  · after a restart: the dead run's heartbeat stops, it reads            │
 * │    `interrupted` (ACCESS_CHECK_STALE_RUN_MS) and the night is started   │
 * │    again, at most ACCESS_CHECK_NIGHTLY_MAX_ATTEMPTS times — no run is   │
 * │    left `running`. What a dead process did not finish AFTER its run —   │
 * │    the alerts, the automatic re-apply — the post-run sweep takes up;    │
 * │  · ACCESS_CHECK_NIGHTLY_PARALLEL workspaces at a time.                  │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ 2. THE AUTOMATIC RE-APPLY — OFF BY DEFAULT ─────────────────────────────┐
 * │ `access_check_auto_reapply` (workspace setting, 0 by default). When on,  │
 * │ right after a nightly run, EXACTLY what the button would queue          │
 * │ (`enqueueReapplyRow`, the same doors and refusals: duplicated session,  │
 * │ offline, a job already running, the doors' own rules — decided by the   │
 * │ verification and re-checked by the doors), and on top of them:          │
 * │  · `stale`              a router verified more than ACCESS_CHECK_FRESH_MS │
 * │                         before (the button's 30 minutes, per router);    │
 * │  · `learning`           no template fixes on a router in learning mode   │
 * │                         (and no fixes promised after its access job);    │
 * │                         its management access stays allowed, as on the   │
 * │                         device page;                                     │
 * │  · `bench_unqualified`  a bench-prepared router not qualified yet;       │
 * │  · `auto_failed_before` the LATEST job of that kind on the router is an  │
 * │                         automatic one that failed for the SAME cause:   │
 * │                         no nightly retry loop — a human takes it (it    │
 * │                         stays in the alert, named so);                  │
 * │  · `cap`                `access_check_auto_reapply_cap` (50) queued.     │
 * │ The jobs name no requester; their safety-net confirmation of the         │
 * │ degraded level is the STANDING CONSENT of the platform administrator who │
 * │ turned the setting on (`access_check_auto_consents`, recorded by the    │
 * │ settings write itself, at the level the value is inherited from) — valid │
 * │ while that account is an active platform administrator; without it      │
 * │ nothing is queued (`no_consent`). The kill switch stops it like any     │
 * │ write. The run is marked re-applied FIRST (`reapply_trigger =           │
 * │ 'nightly'`): an operator's click on the same run queues nothing twice,  │
 * │ Each job is recorded (`access_check_auto_jobs`: the run, the cause) and │
 * │ audited as « réapplication automatique (vérification de nuit #n) » —    │
 * │ the Changes page and the job page say the same.                         │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

import crypto from 'crypto';
import {
  ACCESS_CHECK_FRESH_MS,
  ACCESS_CHECK_NIGHTLY_CATCHUP_MS,
  ACCESS_CHECK_NIGHTLY_MAX_ATTEMPTS,
  ACCESS_CHECK_NIGHTLY_PARALLEL,
  ACCESS_CHECK_NIGHTLY_TIME_ZONE,
  MASTER_TENANT_ID,
  SETTINGS_KEYS,
  accessCheckCauseKey,
  type AccessCheckAutoReapplySummary,
  type AccessCheckAutoSkipReason,
  type AccessCheckJobKind,
  type AccessCheckReapplyRow,
  type AccessCheckRow,
  type AccessCheckScheduleView,
  type LegacyFixKey,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { isLeader as processIsLeader } from '../leaderElection';
import { settingsService } from '../settings.service';
import { tenantSettingNumber } from '../settingsRead';
import { appendAudit } from '../attestation/auditLog.service';
import { readKillSwitch } from '../change/killSwitch.service';
import { resolveBenchQualification } from './benchQualification.service';
import { AUTO_COMPLIANCE_CAUSE, lastAutoFailures } from './accessCheckOrigin';
import { evaluateAccessCheckAlertsSafe, listOpenAccessCheckAlerts } from './accessCheckAlerts.service';
import { AccessCheckError, enqueueReapplyRow, markStaleAccessChecks, startAccessCheck } from './accessCheck.service';

/** How often the leader looks. */
export const ACCESS_CHECK_NIGHTLY_TICK_MS = 60_000;
/** A run's post-run work is taken up by the sweep only this long after it
 *  ended (the run's own process does it at once). */
const SETTLE_AFTER_MS = 2 * 60_000;
/** An automatic re-apply still `running` this long after it started died with
 *  its process: the sweep resumes it (the rows it acted on say so). */
const AUTO_STALE_MS = 10 * 60_000;

// ============================================================================
// Seams
// ============================================================================

export interface AccessCheckNightlyDeps {
  now(): number;
  isLeader(): boolean;
}
const DEFAULT_DEPS: AccessCheckNightlyDeps = { now: () => Date.now(), isLeader: () => processIsLeader() };
let deps: AccessCheckNightlyDeps = { ...DEFAULT_DEPS };
export function setAccessCheckNightlyDeps(next: Partial<AccessCheckNightlyDeps>): void {
  deps = { ...deps, ...next };
}
export function resetAccessCheckNightlyDeps(): void {
  deps = { ...DEFAULT_DEPS };
}

// ============================================================================
// Pure: the night, in Europe/Paris
// ============================================================================

const PARTS = new Intl.DateTimeFormat('en-GB', {
  timeZone: ACCESS_CHECK_NIGHTLY_TIME_ZONE,
  year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
});

function zonedParts(ms: number): { year: number; month: number; day: number; hour: number; minute: number; second: number } {
  const p: Record<string, string> = {};
  for (const x of PARTS.formatToParts(new Date(ms))) p[x.type] = x.value;
  return { year: +p.year, month: +p.month, day: +p.day, hour: +p.hour, minute: +p.minute, second: +p.second };
}

/** Wall time minus UTC at an instant, in ms (+1 h / +2 h in Paris). */
function offsetAt(ms: number): number {
  const z = zonedParts(ms);
  const s = Math.floor(ms / 1000) * 1000;
  return Date.UTC(z.year, z.month - 1, z.day, z.hour, z.minute, z.second) - s;
}

/** The instant of `hour`:00 on a Europe/Paris date (the hour after a spring
 *  gap when that wall time does not exist). */
export function zonedInstant(year: number, month: number, day: number, hour: number): number {
  const wall = Date.UTC(year, month - 1, day, hour, 0, 0);
  const first = wall - offsetAt(wall);
  const second = wall - offsetAt(first);
  return second;
}

const pad = (n: number): string => String(n).padStart(2, '0');
const dateOf = (y: number, m: number, d: number): { y: number; m: number; d: number } => {
  const t = new Date(Date.UTC(y, m - 1, d));
  return { y: t.getUTCFullYear(), m: t.getUTCMonth() + 1, d: t.getUTCDate() };
};

/** The latest nightly slot at or before `now`: its night (the Paris date) and
 *  its instant. */
export function nightlySlot(nowMs: number, hour: number): { nightDate: string; scheduledAt: number } {
  const z = zonedParts(nowMs);
  let day = dateOf(z.year, z.month, z.day);
  let at = zonedInstant(day.y, day.m, day.d, hour);
  if (at > nowMs) {
    day = dateOf(day.y, day.m, day.d - 1);
    at = zonedInstant(day.y, day.m, day.d, hour);
  }
  return { nightDate: `${day.y}-${pad(day.m)}-${pad(day.d)}`, scheduledAt: at };
}

/** The slot after the one `nightlySlot` names. */
export function nextNightlyStart(nowMs: number, hour: number): number {
  const { nightDate } = nightlySlot(nowMs, hour);
  const [y, m, d] = nightDate.split('-').map(Number);
  const next = dateOf(y, m, d + 1);
  return zonedInstant(next.y, next.m, next.d, hour);
}

// ============================================================================
// Settings and the standing consent
// ============================================================================

interface NightlySettings {
  enabled: boolean;
  hour: number;
  autoReapply: boolean;
  cap: number;
}

export async function readNightlySettings(tenantId: number): Promise<NightlySettings> {
  const [enabled, hour, auto, cap] = await Promise.all([
    tenantSettingNumber(tenantId, SETTINGS_KEYS.ACCESS_CHECK_NIGHTLY),
    tenantSettingNumber(tenantId, SETTINGS_KEYS.ACCESS_CHECK_NIGHTLY_HOUR),
    tenantSettingNumber(tenantId, SETTINGS_KEYS.ACCESS_CHECK_AUTO_REAPPLY),
    tenantSettingNumber(tenantId, SETTINGS_KEYS.ACCESS_CHECK_AUTO_REAPPLY_CAP),
  ]);
  return { enabled: enabled.value >= 1, hour: Math.trunc(hour.value), autoReapply: auto.value >= 1, cap: Math.trunc(cap.value) };
}

/**
 * Called by the settings write (settings.controller.ts) after it stored a
 * workspace-level value: turning `access_check_auto_reapply` ON records the
 * administrator who did it as the standing safety-net consent of that workspace's
 * automatic jobs; turning it off, or resetting it, deletes the consent.
 */
export async function noteAutoReapplySettingWrite(
  tenantId: number,
  userId: number | null | undefined,
  scope: string,
  writes: ReadonlyArray<{ key: string; value: number | null }>,
): Promise<void> {
  if (scope !== 'global') return;
  const w = [...writes].reverse().find((x) => x.key === SETTINGS_KEYS.ACCESS_CHECK_AUTO_REAPPLY);
  if (!w) return;
  if (w.value !== null && w.value >= 1 && typeof userId === 'number') {
    await db('access_check_auto_consents')
      .insert({ tenant_id: tenantId, user_id: userId, consented_at: new Date(deps.now()) })
      .onConflict('tenant_id')
      .merge({ user_id: userId, consented_at: new Date(deps.now()) });
    logger.warn({ tenantId, userId }, 'Access check: automatic re-apply consented (degraded level confirmed for the nightly jobs)');
  } else {
    await db('access_check_auto_consents').where({ tenant_id: tenantId }).delete();
  }
}

export interface AutoReapplyConsent {
  userId: number;
  username: string;
  at: Date;
  /** The workspace whose setting row the value comes from. */
  sourceTenantId: number;
}

/**
 * The consent the workspace's automatic jobs carry: the one recorded at the
 * level its `access_check_auto_reapply` value is INHERITED from — its own
 * workspace row, else the Default workspace's — while its author is an active
 * platform administrator. Null otherwise (a value nobody turned on through
 * the settings, a deleted or demoted author): nothing is queued.
 */
export async function resolveAutoReapplyConsent(tenantId: number): Promise<AutoReapplyConsent | null> {
  const key = SETTINGS_KEYS.ACCESS_CHECK_AUTO_REAPPLY;
  const own = await settingsService.getByScope(tenantId, 'global', null);
  let source: number | null = null;
  if (own[key] !== undefined) source = tenantId;
  else if (tenantId !== MASTER_TENANT_ID) {
    const general = await settingsService.getByScope(MASTER_TENANT_ID, 'global', null);
    if (general[key] !== undefined) source = MASTER_TENANT_ID;
  }
  if (source === null) return null;
  const row = (await db('access_check_auto_consents as c')
    .join('users as u', 'u.id', 'c.user_id')
    .where('c.tenant_id', source)
    .where('u.is_active', true)
    .where('u.role', 'admin')
    .first('c.user_id', 'u.username', 'c.consented_at')) as { user_id: number; username: string; consented_at: Date } | undefined;
  return row ? { userId: Number(row.user_id), username: row.username, at: new Date(row.consented_at), sourceTenantId: source } : null;
}

// ============================================================================
// The automatic re-apply
// ============================================================================

const HOLD_SENTENCE: Record<AccessCheckAutoSkipReason, string> = {
  stale: `Vérifié il y a plus de ${Math.round(ACCESS_CHECK_FRESH_MS / 60_000)} minutes : non réappliqué automatiquement.`,
  learning: 'Routeur en mode apprentissage : les correctifs des modèles ne sont pas réappliqués automatiquement.',
  bench_unqualified: 'Routeur préparé au banc, pas encore qualifié (en expédition) : non réappliqué automatiquement.',
  auto_failed_before: 'La réapplication automatique précédente a échoué pour la même cause : à reprendre à la main.',
  cap: 'Plafond de la nuit atteint : la nuit suivante le reprendra.',
};

interface AutoRow {
  id: string | number;
  device_id: number;
  name: string;
  learning_since: Date | null;
  concentrator_id: number | null;
  ppp_username: string | null;
  action: AccessCheckJobKind;
  result: Pick<AccessCheckRow, 'access' | 'compliance' | 'followUp'>;
  checked_at: Date;
  reapply: AccessCheckReapplyRow | null;
}

async function storeSummary(runPk: number, s: AccessCheckAutoReapplySummary): Promise<void> {
  await db('access_check_runs').where({ id: runPk }).update({ auto_reapply: JSON.stringify(s) });
}

/**
 * After a nightly run (header, "2."). Decided ONCE per run (`auto_reapply`,
 * claimed first); a decision left `running` by a dead process is resumed
 * after AUTO_STALE_MS on the rows it had not reached. Returns the summary, or
 * null when this call did nothing (not a nightly run, already decided, lost
 * the claim, or failed — then left `running` for the sweep).
 */
export async function autoReapplyAfterNightly(tenantId: number, runPk: number): Promise<AccessCheckAutoReapplySummary | null> {
  const nowMs = deps.now();
  const run = (await db('access_check_runs')
    .where({ id: runPk, tenant_id: tenantId })
    .first('id', 'trigger', 'status', 'auto_reapply', 'reapply_trigger')) as
    | { id: string | number; trigger: string; status: string; auto_reapply: AccessCheckAutoReapplySummary | null; reapply_trigger: string | null }
    | undefined;
  if (!run || run.trigger !== 'nightly' || run.status !== 'done') return null;
  const prev = run.auto_reapply;
  const running: AccessCheckAutoReapplySummary = {
    status: 'running', at: new Date(nowMs).toISOString(), queued: 0, refused: 0, held: {}, consentBy: null, cap: null,
  };
  let claimed: number;
  if (prev === null) {
    claimed = await db('access_check_runs').where({ id: runPk }).whereNull('auto_reapply').update({ auto_reapply: JSON.stringify(running) });
  } else if (prev.status === 'running' && nowMs - Date.parse(prev.at) > AUTO_STALE_MS) {
    claimed = await db('access_check_runs')
      .where({ id: runPk })
      .whereRaw("auto_reapply->>'at' = ?", [prev.at])
      .update({ auto_reapply: JSON.stringify(running) });
  } else {
    return null;
  }
  if (claimed === 0) return null;
  try {
    const summary = await decideAndQueue(tenantId, runPk, prev !== null, run.reapply_trigger === 'nightly', nowMs);
    await storeSummary(runPk, summary);
    if (summary.queued > 0 || summary.refused > 0) {
      logger.warn(
        { tenantId, runPk, queued: summary.queued, refused: summary.refused, held: summary.held, consentBy: summary.consentBy?.id },
        'Access check: automatic re-apply after the nightly verification — management_access / legacy_compliance jobs queued',
      );
    }
    return summary;
  } catch (err) {
    logger.error({ err, tenantId, runPk }, 'Access check: the automatic re-apply stopped (resumed by the sweep)');
    return null;
  }
}

async function decideAndQueue(
  tenantId: number,
  runPk: number,
  resuming: boolean,
  alreadyClaimedByNight: boolean,
  nowMs: number,
): Promise<AccessCheckAutoReapplySummary> {
  const base: AccessCheckAutoReapplySummary = {
    status: 'done', at: new Date(nowMs).toISOString(), queued: 0, refused: 0, held: {}, consentBy: null, cap: null,
  };
  const settings = await readNightlySettings(tenantId);
  if (!settings.autoReapply) return { ...base, status: 'off' };
  const consent = await resolveAutoReapplyConsent(tenantId);
  if (!consent) return { ...base, status: 'no_consent' };
  base.consentBy = { id: consent.userId, username: consent.username };
  base.cap = settings.cap;
  const ks = await readKillSwitch(tenantId);
  if (ks.blocked) return { ...base, status: 'kill_switch' };
  const left = (await db('access_check_results').where({ run_id: runPk, state: 'pending' }).first('id')) as unknown;
  if (left) return { ...base, status: 'incomplete' };

  const rows = (await db('access_check_results as x')
    .join('devices as d', 'd.id', 'x.device_id')
    .where('x.run_id', runPk)
    .where('x.tenant_id', tenantId)
    .where('d.tenant_id', tenantId)
    .where('d.status', 'active')
    .where('x.state', 'done')
    .whereIn('x.action', ['management_access', 'legacy_compliance'])
    .orderBy('d.name')
    .orderBy('d.id')
    .select(
      'x.id', 'x.device_id', 'd.name', 'd.learning_since', 'd.concentrator_id', 'd.ppp_username', 'x.action', 'x.result',
      'x.checked_at', 'x.reapply',
    )) as AutoRow[];
  // Resumed: what the dead pass already queued counts against the cap.
  let queued = rows.filter((r) => r.reapply?.status === 'queued').length;
  let refused = rows.filter((r) => r.reapply?.status === 'refused').length;
  const todo = rows.filter((r) => r.reapply === null);
  const failures = await lastAutoFailures(tenantId, todo.map((r) => Number(r.device_id)));

  type Decision =
    | { row: AutoRow; hold: AccessCheckAutoSkipReason; cause: string }
    | { row: AutoRow; hold: null; cause: string; followUp: boolean; fixes: LegacyFixKey[] };
  const decisions: Decision[] = [];
  for (const r of todo) {
    const id = Number(r.device_id);
    const cause =
      r.action === 'management_access'
        ? accessCheckCauseKey({ kind: 'access', reason: r.result.access?.reason ?? 'internal' })
        : AUTO_COMPLIANCE_CAUSE;
    if (nowMs - new Date(r.checked_at).getTime() > ACCESS_CHECK_FRESH_MS) {
      decisions.push({ row: r, hold: 'stale', cause });
      continue;
    }
    const learning = r.learning_since !== null && r.learning_since !== undefined;
    if (learning && r.action === 'legacy_compliance') {
      decisions.push({ row: r, hold: 'learning', cause });
      continue;
    }
    const q = await resolveBenchQualification(
      { id, concentrator_id: r.concentrator_id === null ? null : Number(r.concentrator_id), ppp_username: r.ppp_username },
      new Date(nowMs),
      { persist: false },
    ).catch(() => null);
    if (q && q.verdict.state !== 'qualified') {
      decisions.push({ row: r, hold: 'bench_unqualified', cause });
      continue;
    }
    if (failures.get(`${id}:${r.action}`)?.cause === cause) {
      decisions.push({ row: r, hold: 'auto_failed_before', cause });
      continue;
    }
    decisions.push({
      row: r,
      hold: null,
      cause,
      followUp: r.result.followUp === true && !learning,
      fixes: r.result.compliance?.fixes ?? [],
    });
  }

  const held: AccessCheckAutoReapplySummary['held'] = {};
  const hold = async (r: AutoRow, reason: AccessCheckAutoSkipReason, detail?: string): Promise<void> => {
    held[reason] = (held[reason] ?? 0) + 1;
    const row: AccessCheckReapplyRow = {
      status: 'skipped', kind: r.action, jobId: null, followupId: null, reason,
      message: detail ?? HOLD_SENTENCE[reason], at: new Date(deps.now()).toISOString(),
    };
    await db('access_check_results').where({ id: r.id }).update({ reapply: JSON.stringify(row) });
  };

  const actable = decisions.filter((d) => d.hold === null);
  if (actable.length === 0) {
    for (const d of decisions) if (d.hold !== null) await hold(d.row, d.hold, holdDetail(d.hold, d.row, failures));
    return { ...base, status: queued + refused > 0 ? 'done' : 'nothing', queued, refused, held };
  }

  // The run, re-applied FIRST and conditionally (an operator's click on the
  // same run queues nothing twice) — unless this pass resumes the night's.
  if (!(resuming && alreadyClaimedByNight)) {
    const claimed = await db('access_check_runs')
      .where({ id: runPk, status: 'done' })
      .whereNull('reapplied_at')
      .update({ reapplied_at: new Date(deps.now()), reapplied_by: null, reapply_trigger: 'nightly' });
    if (claimed === 0) return { ...base, status: 'already_reapplied' };
  }

  const correlationId = crypto.randomUUID();
  const actorName = `réapplication automatique (vérification de nuit #${runPk})`;
  for (const d of decisions) {
    if (d.hold !== null) {
      await hold(d.row, d.hold, holdDetail(d.hold, d.row, failures));
      continue;
    }
    if (queued >= settings.cap) {
      await hold(d.row, 'cap', `Plafond de la nuit atteint (${settings.cap} routeurs) : la nuit suivante le reprendra.`);
      continue;
    }
    const deviceId = Number(d.row.device_id);
    const out = await enqueueReapplyRow(
      tenantId,
      { resultId: Number(d.row.id), deviceId, action: d.row.action, followUp: d.followUp, fixes: d.fixes },
      { requestedBy: null, confirmedBy: consent.userId, correlationId },
    );
    if (out.status !== 'queued' || out.jobId === null) {
      refused += 1;
      continue;
    }
    queued += 1;
    try {
      await db('access_check_auto_jobs').insert({
        job_id: out.jobId, tenant_id: tenantId, device_id: deviceId, run_number: runPk, kind: d.row.action,
        cause: d.cause, confirmed_by: consent.userId,
      });
    } catch (err) {
      logger.error({ err, tenantId, deviceId, jobId: out.jobId }, 'Access check: an automatic job could not be recorded as such');
    }
    try {
      await appendAudit({
        tenantId,
        actorType: 'automation',
        actorId: `access_check_nightly:${runPk}`,
        actorName,
        action: 'access_check.auto_reapply_queued',
        entityType: 'change_job',
        entityId: out.jobId,
        after: {
          deviceId, deviceName: d.row.name, kind: d.row.action, cause: d.cause,
          fixes: d.row.action === 'legacy_compliance' ? d.fixes : null,
          followupId: out.followupId, run: runPk,
          degradedConfirmedBy: consent.userId, consentedAt: consent.at.toISOString(),
        },
        correlationId,
      });
    } catch (err) {
      logger.error({ err, tenantId, jobId: out.jobId }, 'Access check: an automatic job could not be appended to the audit log');
    }
  }
  try {
    await appendAudit({
      tenantId,
      actorType: 'automation',
      actorId: `access_check_nightly:${runPk}`,
      actorName,
      action: 'access_check.auto_reapplied',
      entityType: 'access_check_run',
      entityId: runPk,
      after: { queued, refused, held, cap: settings.cap, degradedConfirmedBy: consent.userId },
      correlationId,
    });
  } catch (err) {
    logger.error({ err, tenantId, runPk }, 'Access check: the automatic re-apply could not be appended to the audit log');
  }
  return { ...base, status: 'done', queued, refused, held };
}

function holdDetail(reason: AccessCheckAutoSkipReason, r: AutoRow, failures: Map<string, { jobId: number }>): string {
  if (reason !== 'auto_failed_before') return HOLD_SENTENCE[reason];
  const f = failures.get(`${Number(r.device_id)}:${r.action}`);
  return f
    ? `La réapplication automatique précédente (tâche #${f.jobId}) a échoué pour la même cause : à reprendre à la main.`
    : HOLD_SENTENCE[reason];
}

// ============================================================================
// The night's scheduler
// ============================================================================

const inFlight = new Map<number, Promise<void>>();

/** Workspaces with an active MikroTik that is not a concentrator. */
async function tenantsWithRouters(): Promise<number[]> {
  const rows = (await db('devices')
    .where({ brand: 'mikrotik', status: 'active' })
    .where((w) => {
      w.whereNull('role').orWhereNot('role', 'concentrator');
    })
    .distinct('tenant_id')
    .orderBy('tenant_id')) as Array<{ tenant_id: number }>;
  return rows.map((r) => Number(r.tenant_id));
}

/** What a dead process left after its run: the alerts of the newest complete
 *  run, the automatic re-apply of a nightly run (header, "1."). */
async function settleFinishedRuns(tenantId: number, nowMs: number): Promise<void> {
  const ended = new Date(nowMs - SETTLE_AFTER_MS);
  const unevaluated = (await db('access_check_runs')
    .where({ tenant_id: tenantId, status: 'done', scope: 'tenant' })
    .whereNull('alerts_evaluated_at')
    .where('finished_at', '<', ended)
    .orderBy('id', 'desc')
    .first('id')) as { id: string | number } | undefined;
  if (unevaluated) await evaluateAccessCheckAlertsSafe(tenantId, Number(unevaluated.id));
  if (inFlight.has(tenantId)) return;
  const undecided = (await db('access_check_runs')
    .where({ tenant_id: tenantId, status: 'done', trigger: 'nightly' })
    .where((w) => {
      w.whereNull('auto_reapply').orWhereRaw("auto_reapply->>'status' = 'running'");
    })
    .where('finished_at', '<', ended)
    .where('started_at', '>', new Date(nowMs - 24 * 3_600_000))
    .orderBy('id', 'desc')
    .first('id')) as { id: string | number } | undefined;
  if (undecided) await autoReapplyAfterNightly(tenantId, Number(undecided.id));
}

export type NightlyDecision =
  | 'started'
  | 'off'
  | 'not_due'
  | 'done_tonight'
  | 'attempts_spent'
  | 'busy'
  | 'in_flight'
  | 'parallel_limit'
  | 'refused';

/** One workspace at one tick. */
async function considerTenant(tenantId: number, nowMs: number): Promise<NightlyDecision> {
  if (inFlight.has(tenantId)) return 'in_flight';
  await markStaleAccessChecks(tenantId);
  await settleFinishedRuns(tenantId, nowMs);
  const s = await readNightlySettings(tenantId);
  if (!s.enabled) return 'off';
  const slot = nightlySlot(nowMs, s.hour);
  if (nowMs - slot.scheduledAt >= ACCESS_CHECK_NIGHTLY_CATCHUP_MS) return 'not_due';
  const tonight = (await db('access_check_runs')
    .where({ tenant_id: tenantId, trigger: 'nightly', night_date: slot.nightDate })
    .select('status')) as Array<{ status: string }>;
  if (tonight.some((r) => r.status === 'running' || r.status === 'done')) return 'done_tonight';
  if (tonight.length >= ACCESS_CHECK_NIGHTLY_MAX_ATTEMPTS) return 'attempts_spent';
  // A manual run in progress: the night waits for it (never two at once).
  if (await db('access_check_runs').where({ tenant_id: tenantId, status: 'running' }).first('id')) return 'busy';
  if (inFlight.size >= ACCESS_CHECK_NIGHTLY_PARALLEL) return 'parallel_limit';
  let started: Awaited<ReturnType<typeof startAccessCheck>>;
  try {
    started = await startAccessCheck(tenantId, null, null, { trigger: 'nightly', nightDate: slot.nightDate });
  } catch (err) {
    if (err instanceof AccessCheckError) {
      if (err.reason !== 'RUN_RUNNING' && err.reason !== 'NIGHT_TAKEN') {
        logger.info({ tenantId, reason: err.reason }, 'Access check: the nightly verification was not started');
      }
      return err.reason === 'RUN_RUNNING' ? 'busy' : err.reason === 'NIGHT_TAKEN' ? 'done_tonight' : 'refused';
    }
    throw err;
  }
  const p = started.done
    .then(() => autoReapplyAfterNightly(tenantId, started.runPk))
    .then(() => undefined)
    .catch((err: unknown) => logger.error({ err, tenantId }, 'Access check: the nightly verification failed after its run'))
    .finally(() => {
      inFlight.delete(tenantId);
    });
  inFlight.set(tenantId, p);
  return 'started';
}

/** One pass over the workspaces (leader only). Exported for the harness. */
export async function tickAccessCheckNightly(nowMs: number = deps.now()): Promise<Map<number, NightlyDecision>> {
  const out = new Map<number, NightlyDecision>();
  if (!deps.isLeader()) return out;
  for (const tenantId of await tenantsWithRouters()) {
    try {
      out.set(tenantId, await considerTenant(tenantId, nowMs));
    } catch (err) {
      logger.warn({ err, tenantId }, 'Access check: the nightly pass failed for this workspace — next tick');
    }
  }
  return out;
}

/** Wait for every nightly run started by this process (harness, shutdown). */
export async function waitAccessCheckNightlyIdle(): Promise<void> {
  while (inFlight.size > 0) await Promise.allSettled([...inFlight.values()]);
}

let tickTimer: NodeJS.Timeout | null = null;
let firstTimer: NodeJS.Timeout | null = null;
let ticking: Promise<unknown> | null = null;

/** Arm the nightly verification on this process; a tick on a process that is
 *  not the leader does nothing. Idempotent. */
export function startAccessCheckNightlyRuntime(options: { tickMs?: number; firstDelayMs?: number } = {}): void {
  if (tickTimer) return;
  const tick = (): void => {
    if (ticking || !deps.isLeader()) return;
    ticking = tickAccessCheckNightly()
      .catch((err: unknown) => logger.error({ err }, 'Access check: nightly tick failed'))
      .finally(() => {
        ticking = null;
      });
  };
  tickTimer = setInterval(tick, Math.max(10, options.tickMs ?? ACCESS_CHECK_NIGHTLY_TICK_MS));
  tickTimer.unref?.();
  firstTimer = setTimeout(tick, Math.max(0, options.firstDelayMs ?? 45_000));
  firstTimer.unref?.();
  logger.info('Nightly access verification armed (leader-only; read-only towards the routers; automatic re-apply per workspace, off by default)');
}

/** Disarm and wait for a tick in flight. A run in progress is abandoned: its
 *  heartbeat stops, it reads `interrupted`, and the next leader takes the
 *  night up again. */
export async function stopAccessCheckNightlyRuntime(): Promise<void> {
  if (tickTimer) clearInterval(tickTimer);
  if (firstTimer) clearTimeout(firstTimer);
  tickTimer = null;
  firstTimer = null;
  if (ticking) await ticking.catch(() => undefined);
}

// ============================================================================
// The reconciliation page's view
// ============================================================================

export async function accessCheckScheduleView(tenantId: number): Promise<AccessCheckScheduleView> {
  const nowMs = deps.now();
  const s = await readNightlySettings(tenantId);
  let nextRunAt: string | null = null;
  if (s.enabled) {
    const slot = nightlySlot(nowMs, s.hour);
    let next = nextNightlyStart(nowMs, s.hour);
    if (nowMs - slot.scheduledAt < ACCESS_CHECK_NIGHTLY_CATCHUP_MS) {
      const tonight = (await db('access_check_runs')
        .where({ tenant_id: tenantId, trigger: 'nightly', night_date: slot.nightDate })
        .whereIn('status', ['running', 'done'])
        .first('id')) as unknown;
      if (!tonight) next = slot.scheduledAt;
    }
    nextRunAt = new Date(next).toISOString();
  }
  const consent = s.autoReapply ? await resolveAutoReapplyConsent(tenantId) : null;
  return {
    nightly: { enabled: s.enabled, hour: s.hour, timeZone: ACCESS_CHECK_NIGHTLY_TIME_ZONE, nextRunAt },
    autoReapply: {
      enabled: s.autoReapply,
      cap: s.cap,
      consent: consent ? { userId: consent.userId, username: consent.username, at: consent.at.toISOString() } : null,
    },
    openAlerts: await listOpenAccessCheckAlerts(tenantId),
  };
}
