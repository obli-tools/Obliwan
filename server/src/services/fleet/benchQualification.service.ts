/**
 * ObliWAN — bench qualification: from when a bench-prepared router's outages
 * are announced.
 *
 * The rule, its constants and its vocabulary are in shared/src/health.ts
 * (`BenchQualificationState`, operator rule of 2026-10-04): a router prepared
 * at the bench is unplugged and shipped right after, for a day to three weeks,
 * and becomes alertable only once its PPP session has stayed open without a
 * break — BENCH_QUALIFY_AFTER_PREP_MIN right after the preparation,
 * BENCH_QUALIFY_ON_SITE_MIN later, on site. This file decides it and records
 * it; the health check (healthCheck.service.ts) obeys it, and the Sites
 * deployment view (siteDeployment.service.ts) reads what it recorded.
 *
 * It REPLACES the "in transit" notion of backlog #28, which held a box's
 * alerts until a session STARTED after the bench window, or a session was open
 * now, or a check answered after the window. That rule had no notion of
 * continuity: a box plugged in on site for ten minutes and unplugged again (a
 * site visit, a box moved between two rooms) became alertable for good, and a
 * box left running at the bench was held until its bench window had passed.
 * The window survives, with a narrower job: it says which bar a session must
 * reach (BENCH_TUNNEL_WINDOW_MIN).
 *
 * ┌─ WHAT IS READ ────────────────────────────────────────────────────────────┐
 * │ The device's LATEST 'applied' bench report — the preparation, as #28 read │
 * │ it; a compile still waiting for its report is not yet one. Its PPP        │
 * │ sessions, found by `device_id` and by its login on its concentrator (a    │
 * │ session observed before the login was bound to the device carries no     │
 * │ `device_id`). Its stored qualification (migration 068).                   │
 * │ A device the bench prepared but which has no PPP account on a             │
 * │ concentrator has no presence that could ever qualify it: it is NOT held   │
 * │ — holding it would silence it for good — and keeps the other rule.        │
 * │                                                                           │
 * │ Only sessions that STARTED AFTER that preparation's COMPILE are the box's.│
 * │ The bench applies the file through `/system/reset-configuration`          │
 * │ (bench/routerosApply.ts): the box reboots after its compile, so every     │
 * │ session it holds under the prepared file begins after `compiled_at`. A    │
 * │ session already open at the compile is ANOTHER box on the same login:    │
 * │ in a bench replacement the compile moves the site's login to the new      │
 * │ device and retires the old one in ObliWAN only (compile.service.ts        │
 * │ `persistDevice`) — the old router is still on site, dialling with the     │
 * │ same login, and its row would otherwise qualify the new box an hour after │
 * │ the report, while it is in its van. `device_id` cannot tell the two       │
 * │ apart: presence rewrites it to the login's current holder every time it  │
 * │ refreshes an open row (pppPresence `applySessionUp`), so within one sweep │
 * │ the predecessor's row is filed under the new device. The cost, accepted   │
 * │ because it is the quiet direction: if presence misses a teardown and the  │
 * │ box re-dials within one reconciliation, the row keeps its old start and   │
 * │ the box stays in shipping until its next session.                         │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE VERDICT — `evaluateBenchQualification`, pure ───────────────────────┐
 * │ 1. Stored for THIS preparation → qualified. Nothing un-qualifies a box    │
 * │    but a new preparation.                                                 │
 * │ 2. Every session started after the compile and open at, or ended after,   │
 * │    the report is a candidate (WHAT IS READ says why not one before).      │
 * │    Its presence counts from max(start, report); its bar is the after-prep │
 * │    one when it started within the bench window, the on-site one when it   │
 * │    started later; it crosses at upSince + bar. It qualifies the box when: │
 * │     - it is OPEN, its crossing has passed, and its concentrator is not    │
 * │       degraded. On a degraded concentrator presence leaves every session │
 * │       open on purpose ("we do not know that they ended"): the row is a    │
 * │       memory, not presence, and the box waits for the concentrator.       │
 * │     - it is CLOSED with an OBSERVED end at or after its crossing — the    │
 * │       `listen` teardown, written as it happened. A close written by a    │
 * │       reconciliation (`reconciled-missing`) is when presence NOTICED the  │
 * │       session was gone: up to a minute late in the normal case, hours    │
 * │       late after a concentrator outage or a restart, so its recorded      │
 * │       length proves nothing and never qualifies after the fact.           │
 * │    The earliest crossing wins: it is `qualified_at`, whenever the         │
 * │    evaluation happens to run.                                             │
 * │ 3. Otherwise an open session → qualifying; none → in shipping, since the │
 * │    end of the box's last session after the report (or the report itself  │
 * │    when its tunnel never came up).                                        │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHO WRITES, WHEN ────────────────────────────────────────────────────────┐
 * │ `resolveBenchQualification(…, { persist: true })` stores a fresh          │
 * │ qualification with ONE conditional UPDATE: only if the device is not      │
 * │ already qualified for that preparation AND that preparation is still its │
 * │ latest report — a report arriving meanwhile is a new box to ship, and an │
 * │ old verdict must not land on it. It is called:                            │
 * │  - by every health check of the device (healthCheck.service.ts): the      │
 * │    verdict gates that check's alert, so it is decided where the alert is. │
 * │    The scheduler runs on the leader; "Check now" may run on any process,  │
 * │    and its write is the same monotone fact computed from the same rows.  │
 * │  - at the CROSSING of a qualifying session, on a timer the LEADER arms    │
 * │    when presence reports a new session (`onPppSessionUp`, a leader-only   │
 * │    seam) or when a check finds the device qualifying. The timer is what  │
 * │    qualifies a box that crosses its bar and then loses its session        │
 * │    between two checks with a close only a sweep found (rule 2, second     │
 * │    bullet): without it, a long check interval would leave such a box "in │
 * │    shipping" for ever. Timers live in memory; a restart loses them and   │
 * │    the next check re-arms.                                                │
 * │ The page's read (`benchQualificationView`) never writes.                  │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import type { Knex } from 'knex';
import {
  BENCH_QUALIFY_AFTER_PREP_MIN,
  BENCH_QUALIFY_ON_SITE_MIN,
  BENCH_TUNNEL_WINDOW_MIN,
  type BenchQualificationState,
  type BenchQualificationView,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { isLeader } from '../leaderElection';
import { onPppSessionUp, type PppSessionUpEvent } from './pppPresence.service';
import { isConcentratorDegraded } from './reachability.service';

const MIN_MS = 60_000;

/** The disconnect reason presence writes when a reconciliation, not the
 *  concentrator's own teardown event, closed the session. */
export const INFERRED_CLOSE_REASON = 'reconciled-missing';

/** Closed candidates read per evaluation, oldest first. Only sessions that
 *  lasted at least the shorter bar since the report are candidates, so a box
 *  that flapped a thousand times costs nothing here; a box that has this many
 *  long sessions after its preparation without one of them qualifying is one
 *  whose closes were all found by sweeps, and the open one (read apart) or
 *  the crossing timer is what qualifies it. */
const CLOSED_CANDIDATES_MAX = 200;

/** A timer fires this long after the crossing, so the open session is past
 *  its bar on the database clock too. */
const CROSSING_SLACK_MS = 2_000;
/** A device still qualifying when its timer fired (a degraded concentrator)
 *  is looked at again no sooner than this. */
const REARM_FLOOR_MS = 60_000;

// ============================================================================
// The verdict — pure
// ============================================================================

export interface QualificationSession {
  startedAt: Date;
  /** Null while the session is open. */
  endedAt: Date | null;
  /** The end was written as it happened (the concentrator's teardown), not
   *  inferred by a reconciliation. Meaningless while open. */
  endObserved: boolean;
}

export interface BenchQualificationInput {
  /** The compile of that preparation: a session started at or before it is
   *  another box's (header box WHAT IS READ) and is ignored. */
  compiledAt: Date;
  /** The latest 'applied' report of the device's preparation. */
  appliedAt: Date;
  /** Candidate sessions: open, or closed after the report (any order). */
  sessions: readonly QualificationSession[];
  /** The latest end, after the report, of ANY session started after the
   *  compile, short ones included. */
  lastEndedAt: Date | null;
  /** The stored qualification instant, when it is for THIS preparation. */
  storedQualifiedAt: Date | null;
  /** The device's concentrator is degraded now. */
  observerBlind: boolean;
  now: Date;
}

export interface BenchQualificationVerdict {
  state: BenchQualificationState;
  qualifiedAt: Date | null;
  /** Qualified by this evaluation and not stored yet. */
  fresh: boolean;
  /** The fresh qualification rests on an OPEN session (the one case the
   *  degraded-concentrator rule applies to). */
  viaOpenSession: boolean;
  inShippingSince: Date | null;
  upSince: Date | null;
  requiredMin: number | null;
  qualifiesAt: Date | null;
  observerBlind: boolean;
}

/** The bar a session must reach: the after-preparation one if it started
 *  within the bench window (or between the compile and the report), the
 *  on-site one after. */
export function qualificationBarMin(appliedAt: Date, startedAt: Date): number {
  return startedAt.getTime() <= appliedAt.getTime() + BENCH_TUNNEL_WINDOW_MIN * MIN_MS
    ? BENCH_QUALIFY_AFTER_PREP_MIN
    : BENCH_QUALIFY_ON_SITE_MIN;
}

/** The rule of the header box THE VERDICT. Pure: the clock is a parameter. */
export function evaluateBenchQualification(input: BenchQualificationInput): BenchQualificationVerdict {
  const base: BenchQualificationVerdict = {
    state: 'in_shipping',
    qualifiedAt: null,
    fresh: false,
    viaOpenSession: false,
    inShippingSince: null,
    upSince: null,
    requiredMin: null,
    qualifiesAt: null,
    observerBlind: false,
  };
  if (input.storedQualifiedAt) {
    return { ...base, state: 'qualified', qualifiedAt: input.storedQualifiedAt };
  }

  const compiledMs = input.compiledAt.getTime();
  const appliedMs = input.appliedAt.getTime();
  const nowMs = input.now.getTime();
  let best: { at: number; open: boolean } | null = null;
  let open: { upSince: number; bar: number; crossing: number } | null = null;
  let lastEnd = input.lastEndedAt && input.lastEndedAt.getTime() > appliedMs ? input.lastEndedAt.getTime() : null;

  for (const s of input.sessions) {
    // Open at the compile: the box was at the bench about to be reset, so
    // this is another router holding the login (a predecessor on site).
    if (s.startedAt.getTime() <= compiledMs) continue;
    if (s.endedAt && s.endedAt.getTime() <= appliedMs) continue;
    const upSince = Math.max(s.startedAt.getTime(), appliedMs);
    const bar = qualificationBarMin(input.appliedAt, s.startedAt);
    const crossing = upSince + bar * MIN_MS;
    if (s.endedAt === null) {
      if (crossing <= nowMs && !input.observerBlind) {
        if (!best || crossing < best.at) best = { at: crossing, open: true };
      }
      // At most one open session per login (ppp_sessions_open_uniq); two
      // logins of one device would be two rows: the earliest presence counts.
      if (!open || upSince < open.upSince) open = { upSince, bar, crossing };
      continue;
    }
    const endMs = s.endedAt.getTime();
    if (lastEnd === null || endMs > lastEnd) lastEnd = endMs;
    if (s.endObserved && endMs >= crossing) {
      if (!best || crossing < best.at) best = { at: crossing, open: false };
    }
  }

  if (best) {
    return { ...base, state: 'qualified', qualifiedAt: new Date(best.at), fresh: true, viaOpenSession: best.open };
  }
  if (open) {
    return {
      ...base,
      state: 'qualifying',
      upSince: new Date(open.upSince),
      requiredMin: open.bar,
      qualifiesAt: new Date(open.crossing),
      observerBlind: input.observerBlind && open.crossing <= nowMs,
    };
  }
  return { ...base, state: 'in_shipping', inShippingSince: new Date(lastEnd ?? appliedMs) };
}

// ============================================================================
// Facts
// ============================================================================

export interface QualificationSubject {
  id: number;
  concentrator_id: number | null;
  ppp_username: string | null;
}

export interface BenchQualificationFacts {
  /** `bench_provisionings.id` of the latest 'applied' report (bigint, as text). */
  provisioningId: string;
  /** That row's `compiled_at`: the box's own sessions all start after it. */
  compiledAt: Date;
  appliedAt: Date;
  storedQualifiedAt: Date | null;
}

/**
 * The device's latest 'applied' report and its stored qualification, in one
 * indexed read; null for a device the rule does not concern (never prepared
 * at the bench, or no PPP account to measure — see the header box).
 */
export async function loadBenchQualificationFacts(
  device: QualificationSubject,
): Promise<BenchQualificationFacts | null> {
  if (device.concentrator_id === null || !device.ppp_username) return null;
  const row = (await db('devices as d')
    .joinRaw(
      'LEFT JOIN LATERAL (SELECT b.id, b.compiled_at, b.outcome_at FROM bench_provisionings b '
        + "WHERE b.device_id = d.id AND b.outcome = 'applied' "
        + 'ORDER BY b.outcome_at DESC, b.id DESC LIMIT 1) lb ON true',
    )
    .where('d.id', device.id)
    .first(
      'lb.id as provisioning_id',
      'lb.compiled_at as compiled_at',
      'lb.outcome_at as applied_at',
      'd.qualified_at',
      'd.qualified_provisioning_id',
    )) as {
      provisioning_id: string | number | null;
      compiled_at: Date | null;
      applied_at: Date | null;
      qualified_at: Date | null;
      qualified_provisioning_id: string | number | null;
    } | undefined;
  if (!row || row.provisioning_id === null || !row.applied_at || !row.compiled_at) return null;
  const provisioningId = String(row.provisioning_id);
  const storedFor = row.qualified_provisioning_id === null ? null : String(row.qualified_provisioning_id);
  return {
    provisioningId,
    compiledAt: new Date(row.compiled_at),
    appliedAt: new Date(row.applied_at),
    storedQualifiedAt: storedFor === provisioningId && row.qualified_at ? new Date(row.qualified_at) : null,
  };
}

function ofDevice(device: QualificationSubject): (w: Knex.QueryBuilder) => void {
  return (w) => {
    void w.where('device_id', device.id);
    if (device.concentrator_id !== null && device.ppp_username) {
      void w.orWhere({ concentrator_id: device.concentrator_id, ppp_username: device.ppp_username });
    }
  };
}

/** The sessions the verdict needs: every open one, the closed ones long
 *  enough to be candidates, and the latest end after the report — all of
 *  them started after the compile (the header box WHAT IS READ; the pure
 *  rule skips an earlier one too, this filter keeps it out of the latest
 *  end, which would otherwise date "in shipping" from a predecessor's swap). */
async function loadSessions(
  device: QualificationSubject,
  compiledAt: Date,
  appliedAt: Date,
): Promise<{ sessions: QualificationSession[]; lastEndedAt: Date | null }> {
  type Row = { started_at: Date; ended_at: Date | null; disconnect_reason: string | null };
  const [openRows, closedRows, last] = await Promise.all([
    db('ppp_sessions')
      .where(ofDevice(device))
      .where('started_at', '>', compiledAt)
      .whereNull('ended_at')
      .select<Row[]>('started_at', 'ended_at', 'disconnect_reason'),
    db('ppp_sessions')
      .where(ofDevice(device))
      .where('started_at', '>', compiledAt)
      .where('ended_at', '>', appliedAt)
      .whereRaw(
        'ended_at >= GREATEST(started_at, CAST(? AS timestamptz)) + make_interval(mins => ?)',
        [appliedAt, BENCH_QUALIFY_ON_SITE_MIN],
      )
      .orderBy('started_at', 'asc')
      .limit(CLOSED_CANDIDATES_MAX)
      .select<Row[]>('started_at', 'ended_at', 'disconnect_reason'),
    db('ppp_sessions')
      .where(ofDevice(device))
      .where('started_at', '>', compiledAt)
      .where('ended_at', '>', appliedAt)
      .max('ended_at as m')
      .first() as Promise<{ m: Date | null } | undefined>,
  ]);
  const toSession = (r: Row): QualificationSession => ({
    startedAt: new Date(r.started_at),
    endedAt: r.ended_at ? new Date(r.ended_at) : null,
    endObserved: r.ended_at !== null && r.disconnect_reason !== INFERRED_CLOSE_REASON,
  });
  return {
    sessions: [...openRows, ...closedRows].map(toSession),
    lastEndedAt: last?.m ? new Date(last.m) : null,
  };
}

// ============================================================================
// Resolve, store, view
// ============================================================================

export interface BenchQualification {
  provisioningId: string;
  appliedAt: Date;
  verdict: BenchQualificationVerdict;
  /** This call wrote the qualification. */
  stored: boolean;
}

/**
 * Where the device stands, or null when the rule does not concern it. With
 * `persist`, a fresh qualification is stored (see the header box WHO WRITES).
 * Never throws for a device that is gone: it is simply not concerned.
 */
export async function resolveBenchQualification(
  device: QualificationSubject,
  now: Date,
  opts: { persist: boolean },
): Promise<BenchQualification | null> {
  const facts = await loadBenchQualificationFacts(device);
  if (!facts) return null;
  if (facts.storedQualifiedAt) {
    return {
      provisioningId: facts.provisioningId,
      appliedAt: facts.appliedAt,
      verdict: evaluateBenchQualification({
        compiledAt: facts.compiledAt, appliedAt: facts.appliedAt, sessions: [], lastEndedAt: null,
        storedQualifiedAt: facts.storedQualifiedAt, observerBlind: false, now,
      }),
      stored: false,
    };
  }
  const { sessions, lastEndedAt } = await loadSessions(device, facts.compiledAt, facts.appliedAt);
  const input: BenchQualificationInput = {
    compiledAt: facts.compiledAt, appliedAt: facts.appliedAt, sessions, lastEndedAt,
    storedQualifiedAt: null, observerBlind: false, now,
  };
  let verdict = evaluateBenchQualification(input);
  // The concentrator is read only when its state could change the answer:
  // an open session is past its bar (one indexed read or two, rarely).
  const openPastBar = sessions.some((s) => s.endedAt === null)
    && ((verdict.state === 'qualified' && verdict.viaOpenSession)
      || (verdict.state === 'qualifying' && verdict.qualifiesAt !== null && verdict.qualifiesAt.getTime() <= now.getTime()));
  if (openPastBar && device.concentrator_id !== null && await isConcentratorDegraded(device.concentrator_id)) {
    verdict = evaluateBenchQualification({ ...input, observerBlind: true });
  }

  let stored = false;
  if (opts.persist && verdict.state === 'qualified' && verdict.fresh && verdict.qualifiedAt) {
    stored = await storeQualification(device.id, facts.provisioningId, verdict.qualifiedAt);
  }
  return { provisioningId: facts.provisioningId, appliedAt: facts.appliedAt, verdict, stored };
}

async function storeQualification(deviceId: number, provisioningId: string, qualifiedAt: Date): Promise<boolean> {
  const n = await db('devices')
    .where({ id: deviceId })
    .where((w) => {
      void w.whereNull('qualified_provisioning_id').orWhereNot('qualified_provisioning_id', provisioningId);
    })
    .whereRaw(
      'CAST(? AS bigint) = (SELECT b.id FROM bench_provisionings b WHERE b.device_id = devices.id '
        + "AND b.outcome = 'applied' ORDER BY b.outcome_at DESC, b.id DESC LIMIT 1)",
      [provisioningId],
    )
    .update({ qualified_at: qualifiedAt, qualified_provisioning_id: provisioningId });
  if (n === 1) {
    logger.info(
      { deviceId, provisioningId, qualifiedAt: qualifiedAt.toISOString() },
      'Bench-prepared router qualified: its tunnel stayed up long enough, its outages are announced from now on',
    );
  }
  return n === 1;
}

export function toQualificationView(q: BenchQualification): BenchQualificationView {
  const v = q.verdict;
  const iso = (d: Date | null): string | null => (d ? d.toISOString() : null);
  return {
    state: v.state,
    benchAppliedAt: q.appliedAt.toISOString(),
    qualifiedAt: iso(v.qualifiedAt),
    inShippingSince: iso(v.inShippingSince),
    upSince: iso(v.upSince),
    requiredMinutes: v.requiredMin,
    qualifiesAt: iso(v.qualifiesAt),
    observerBlind: v.observerBlind,
  };
}

/** The device page's read. Never writes: a verdict not yet stored is shown as
 *  the evaluation finds it, and stored by the next check or crossing timer. */
export async function benchQualificationView(
  device: QualificationSubject,
  now: Date = new Date(),
): Promise<BenchQualificationView | null> {
  const q = await resolveBenchQualification(device, now, { persist: false });
  return q ? toQualificationView(q) : null;
}

// ============================================================================
// The crossing timer — leader only
// ============================================================================

const crossingTimers = new Map<number, { at: number; timer: NodeJS.Timeout }>();
const pendingWork = new Set<Promise<unknown>>();
let unsubscribe: (() => void) | null = null;
let stopping = false;
/** Leadership as this process knows it; replaceable by a harness only. */
let leaderNow: () => boolean = isLeader;

function track<T>(p: Promise<T>): Promise<T> {
  pendingWork.add(p);
  void p.finally(() => pendingWork.delete(p)).catch(() => undefined);
  return p;
}

async function loadSubject(deviceId: number): Promise<QualificationSubject | null> {
  const row = (await db('devices')
    .where({ id: deviceId })
    .whereNot('status', 'disabled')
    .first('id', 'concentrator_id', 'ppp_username')) as QualificationSubject | undefined;
  return row ?? null;
}

async function onCrossing(deviceId: number): Promise<void> {
  crossingTimers.delete(deviceId);
  if (stopping || !leaderNow()) return;
  const device = await loadSubject(deviceId);
  if (!device) return;
  const q = await resolveBenchQualification(device, new Date(), { persist: true });
  if (q?.verdict.state === 'qualifying' && q.verdict.qualifiesAt) {
    armCrossing(deviceId, new Date(Math.max(q.verdict.qualifiesAt.getTime(), Date.now() + REARM_FLOOR_MS)));
  }
}

/**
 * Re-evaluate the device when its open session crosses its bar. Leader only
 * (a no-op elsewhere): two processes would only race to write the same fact,
 * but the timer is the leader's duty like every scheduled one. A later call
 * for the same device replaces an armed timer only with a different instant.
 */
export function armCrossing(deviceId: number, at: Date): void {
  if (stopping || !leaderNow()) return;
  const atMs = at.getTime() + CROSSING_SLACK_MS;
  const existing = crossingTimers.get(deviceId);
  if (existing && existing.at === atMs) return;
  if (existing) clearTimeout(existing.timer);
  const timer = setTimeout(() => {
    void track(onCrossing(deviceId).catch((err: unknown) => {
      logger.warn({ err, deviceId }, 'Bench qualification: the crossing evaluation failed (the next check retries)');
    }));
  }, Math.max(0, atMs - Date.now()));
  timer.unref?.();
  crossingTimers.set(deviceId, { at: atMs, timer });
}

/** A NEW session of a device: if it is a bench box not yet qualified, arm the
 *  timer at the crossing of the session that just opened. */
export async function handleSessionUpForQualification(event: PppSessionUpEvent): Promise<void> {
  if (stopping || !leaderNow()) return;
  const device = await loadSubject(event.deviceId);
  if (!device) return;
  const q = await resolveBenchQualification(device, new Date(), { persist: true });
  if (q?.verdict.state === 'qualifying' && q.verdict.qualifiesAt) armCrossing(device.id, q.verdict.qualifiesAt);
}

/** Wire the session-up listener. Idempotent. Called by the health check
 *  runtime, whose alerts this gates. */
export function startBenchQualificationRuntime(): void {
  if (unsubscribe) return;
  stopping = false;
  unsubscribe = onPppSessionUp((event) =>
    track(handleSessionUpForQualification(event)).catch((err: unknown) => {
      logger.warn({ err, deviceId: event.deviceId }, 'Bench qualification: session-up handling failed');
    }),
  );
}

export async function stopBenchQualificationRuntime(): Promise<void> {
  stopping = true;
  unsubscribe?.();
  unsubscribe = null;
  for (const { timer } of crossingTimers.values()) clearTimeout(timer);
  crossingTimers.clear();
  await Promise.allSettled(Array.from(pendingWork));
}

/** Harness only: the timers armed now, by device. */
export function armedCrossingsForTests(): Map<number, Date> {
  return new Map(Array.from(crossingTimers, ([id, t]) => [id, new Date(t.at - CROSSING_SLACK_MS)]));
}

/** Harness only: clear timers and re-arm after a stop; `leader` stands in
 *  for the advisory-lock election, which a harness does not run. */
export function resetBenchQualificationRuntimeForTests(leader: () => boolean = isLeader): void {
  for (const { timer } of crossingTimers.values()) clearTimeout(timer);
  crossingTimers.clear();
  stopping = false;
  leaderNow = leader;
}
