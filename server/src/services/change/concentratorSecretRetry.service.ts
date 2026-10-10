/**
 * ObliWAN — the bounded, leader-only retry of a site's concentrator account.
 *
 *   sweepConcentratorSecretRetries(options)   one pass; returns what it did
 *   startConcentratorSecretRetry(options)     arm the periodic pass
 *   stopConcentratorSecretRetry()             disarm it, wait for a pass in flight
 *
 * A `concentrator_secret` job is queued with `max_attempts: 1` on purpose: the
 * queue never re-runs a write by itself. Before this file, a job that failed
 * because the CHR did not answer stayed failed until somebody asked again, and
 * nobody was told. The alert is concentratorSecret.service's
 * (`settleConcentratorSecret`); this is the retry.
 *
 * ┌─ WHAT IS RETRIED, AND WHAT NEVER IS ─────────────────────────────────────┐
 * │ A pass looks at each site whose LATEST job failed within the window and  │
 * │ walks its failure episode (`failureEpisode`, the same rule the alert     │
 * │ keys on). It queues a NEW job, through `ensureConcentratorSecret` like   │
 * │ any other request, only when ALL of these hold:                          │
 * │   - the failure is RETRYABLE (`classifyConcentratorFailure`): the CHR    │
 * │     did not answer, timed out, dropped the session (an add whose answer  │
 * │     was lost included), or the worker died. A refusal — the account      │
 * │     present with other attributes, an allocation that moved, a RouterOS  │
 * │     `!trap`, the CHR's identity, the kill switch — is never retried: it  │
 * │     needs a human, and its alert says so;                                │
 * │   - the episode has made at most `maxRetries` attempts after its first   │
 * │     failure — a provisioning requested meanwhile counts as one;          │
 * │   - the backoff since the last failure has elapsed, on the DATABASE      │
 * │     clock (the one `finished_at` was written by);                        │
 * │   - the site's allocation is still the one the failed job was queued     │
 * │     for (same CHR, login, address, profile) — a released or re-made      │
 * │     allocation is somebody else's decision;                              │
 * │   - the CHR is still a managed, writable concentrator, and no kill       │
 * │     switch holds the site's tenant or the CHR's. A pass that skips for   │
 * │     one of these spends no attempt.                                      │
 * │ The new job is the same additive job as any other: it reads the CHR      │
 * │ first and writes nothing when the account is already there.              │
 * │ An episode found with every attempt made is EXHAUSTED: the pass raises   │
 * │ its one `exhausted` alert (`announceConcentratorSecretExhausted`, a      │
 * │ no-op when the failure that spent the last attempt raised it already)    │
 * │ and logs it the one time it is raised, then leaves the site alone.       │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * LEADER-ONLY. Two replicas would each see the same failed job and race to
 * queue its retry; `ensureConcentratorSecret` would hand the loser the
 * winner's job, so the harm is noise, not a double write — but the attempt
 * count is only meaningful when one process makes the attempts. Leadership is
 * read at every tick and again before every retry.
 *
 * Wiring (index.ts, not edited here): `startConcentratorSecretRetry()` after
 * the change worker is armed, `await stopConcentratorSecretRetry()` in the
 * graceful shutdown before `stopChangeWorker()`. Until it is wired, nothing
 * retries, and the failure alert says exactly that: it reads the policy this
 * module arms (`setConcentratorSecretRetryPolicy`), never a constant.
 */

import { db } from '../../db';
import { logger } from '../../utils/logger';
import { isLeader as processIsLeader } from '../leaderElection';
import {
  DEFAULT_CONCENTRATOR_SECRET_RETRY,
  announceConcentratorSecretExhausted,
  classifyConcentratorFailure,
  ensureConcentratorSecret,
  failureEpisode,
  hostAddress,
  loadSecretJobHistory,
  readConcentratorSecretSpec,
  retryDelayMs,
  setConcentratorSecretRetryPolicy,
  type ConcentratorSecretRetryPolicy,
  type ConcentratorSecretSpec,
  type SecretJobHistoryEntry,
} from './concentratorSecret.service';
import { readKillSwitch } from './killSwitch.service';

// ============================================================================
// Options and report
// ============================================================================

/** How often a pass runs. A minute is the shortest backoff; half of it keeps
 *  the actual wait within 30 s of the stated one. */
export const CONCENTRATOR_SECRET_RETRY_INTERVAL_MS = 30_000;
/** A site whose latest job failed longer ago than this is not looked at: its
 *  episode ended (retried out, or refused) long before. Bounds every pass. */
export const CONCENTRATOR_SECRET_RETRY_WINDOW_HOURS = 24;

export interface RetrySweepOptions extends Partial<ConcentratorSecretRetryPolicy> {
  /** Injected by a harness; the process's own leadership otherwise. */
  isLeader?: () => boolean;
  windowHours?: number;
}

export interface RetrySweepReport {
  /** false: this process is not the leader, and the pass did nothing. */
  leader: boolean;
  /** Sites whose latest job failed within the window. */
  examined: number;
  retried: Array<{ siteId: number; tenantId: number; failedJobId: number; jobId: number; attempt: number }>;
  /** Retryable, backoff not elapsed yet. */
  waiting: Array<{ siteId: number; failedJobId: number }>;
  /** Retryable, every automatic attempt made. `announced`: this pass raised
   *  its `exhausted` alert (false on every later pass: it is raised once). */
  exhausted: Array<{ siteId: number; failedJobId: number; attempts: number; announced: boolean }>;
  /** A refusal: never retried. */
  refused: Array<{ siteId: number; failedJobId: number; errorKind: string | null }>;
  /** Retryable but not retried on this pass, and why (no attempt spent). */
  skipped: Array<{ siteId: number; failedJobId: number; reason: string }>;
}

function policyOf(options: Partial<ConcentratorSecretRetryPolicy>): ConcentratorSecretRetryPolicy {
  const pick = (value: number | undefined, fallback: number): number =>
    Number.isFinite(value) && (value as number) >= 0 ? Math.floor(value as number) : fallback;
  return {
    maxRetries: pick(options.maxRetries, DEFAULT_CONCENTRATOR_SECRET_RETRY.maxRetries),
    baseDelayMs: pick(options.baseDelayMs, DEFAULT_CONCENTRATOR_SECRET_RETRY.baseDelayMs),
    maxDelayMs: pick(options.maxDelayMs, DEFAULT_CONCENTRATOR_SECRET_RETRY.maxDelayMs),
  };
}

/** The allocation the failed job was queued for is still the site's. */
function sameAllocation(spec: ConcentratorSecretSpec, job: SecretJobHistoryEntry): boolean {
  return (
    spec.concentratorId === job.deviceId &&
    spec.pppUsername === job.pppUsername &&
    hostAddress(spec.tunnelIp) === hostAddress(job.remoteAddress) &&
    (spec.pppProfile ?? null) === (job.pppProfile ?? null)
  );
}

// ============================================================================
// One pass
// ============================================================================

export async function sweepConcentratorSecretRetries(options: RetrySweepOptions = {}): Promise<RetrySweepReport> {
  const gate = options.isLeader ?? processIsLeader;
  const policy = policyOf(options);
  const windowHours = Math.max(1, Math.floor(options.windowHours ?? CONCENTRATOR_SECRET_RETRY_WINDOW_HOURS));
  const report: RetrySweepReport = {
    leader: gate(),
    examined: 0,
    retried: [],
    waiting: [],
    exhausted: [],
    refused: [],
    skipped: [],
  };
  if (!report.leader) return report;

  // Each site's LATEST job (a site id is global: one site, one tenant), kept
  // only when it failed within the window. The inner set is limited to sites
  // that have such a failure at all, so a pass does not sort the whole history
  // (040's `concentrator_secret_jobs_site_idx` is (site_id, job_id DESC)).
  const recentlyFailed = db('concentrator_secret_jobs as rc')
    .join('change_jobs as rj', 'rj.id', 'rc.job_id')
    .where('rj.status', 'failed')
    .whereRaw('rj.finished_at > now() - make_interval(hours => ?)', [windowHours])
    .select('rc.site_id');
  const latest = db('concentrator_secret_jobs as c')
    .join('change_jobs as j', 'j.id', 'c.job_id')
    .whereIn('c.site_id', recentlyFailed)
    .distinctOn('c.site_id')
    .select('c.tenant_id', 'c.site_id', 'c.job_id', 'j.status', 'j.finished_at')
    .orderBy([
      { column: 'c.site_id' },
      { column: 'c.job_id', order: 'desc' },
    ])
    .as('latest');
  const candidates = (await db
    .from(latest)
    .where('latest.status', 'failed')
    .whereNotNull('latest.finished_at')
    .whereRaw('latest.finished_at > now() - make_interval(hours => ?)', [windowHours])
    .select(
      'latest.tenant_id',
      'latest.site_id',
      'latest.job_id',
      db.raw('extract(epoch from (now() - latest.finished_at)) AS age_s'),
    )
    .orderBy('latest.job_id')) as Array<{
    tenant_id: number;
    site_id: number;
    job_id: string | number;
    age_s: string | number;
  }>;
  report.examined = candidates.length;

  for (const c of candidates) {
    const siteId = Number(c.site_id);
    const tenantId = Number(c.tenant_id);
    const failedJobId = Number(c.job_id);
    try {
      // Enough history to tell "one more attempt allowed" from "exhausted".
      const episode = failureEpisode(await loadSecretJobHistory(siteId, tenantId, policy.maxRetries + 2));
      const head = episode[0];
      if (!head || head.jobId !== failedJobId) continue; // a newer job appeared meanwhile
      if (classifyConcentratorFailure(head) !== 'retryable') {
        report.refused.push({ siteId, failedJobId, errorKind: head.errorKind });
        continue;
      }
      if (episode.length > policy.maxRetries) {
        const announced = await announceConcentratorSecretExhausted(head, siteId, tenantId, policy);
        report.exhausted.push({ siteId, failedJobId, attempts: episode.length, announced });
        if (announced) {
          logger.info(
            { siteId, tenantId, failedJobId, attempts: episode.length },
            'concentrator secret: automatic retries EXHAUSTED for this site; announced, it needs a human',
          );
        }
        continue;
      }
      if (Number(c.age_s) * 1000 < retryDelayMs(policy, episode.length)) {
        report.waiting.push({ siteId, failedJobId });
        continue;
      }

      const skip = (reason: string): void => {
        report.skipped.push({ siteId, failedJobId, reason });
      };
      let spec: ConcentratorSecretSpec;
      try {
        spec = await readConcentratorSecretSpec(siteId, tenantId);
      } catch {
        skip('not_allocated');
        continue;
      }
      if (!sameAllocation(spec, head)) {
        skip('allocation_changed');
        continue;
      }
      const chr = (await db('devices')
        .where({ id: spec.concentratorId })
        .first('tenant_id', 'role', 'status', 'is_managed')) as
        | { tenant_id: number; role: string; status: string; is_managed: boolean }
        | undefined;
      if (!chr || chr.role !== 'concentrator') {
        skip('not_a_concentrator');
        continue;
      }
      if (!chr.is_managed) {
        skip('concentrator_not_managed');
        continue;
      }
      if (chr.status === 'disabled' || chr.status === 'quarantined') {
        skip('concentrator_not_writable');
        continue;
      }
      const [siteSwitch, chrSwitch] = await Promise.all([readKillSwitch(tenantId), readKillSwitch(chr.tenant_id)]);
      if (siteSwitch.blocked || chrSwitch.blocked) {
        skip('kill_switch');
        continue;
      }
      if (!gate()) {
        report.leader = false; // leadership lost mid-pass: the new leader carries on
        break;
      }

      const state = await ensureConcentratorSecret({ tenantId, siteId, requestedBy: null }, { busyWaitMs: 0 });
      if (state.state === 'pending' && state.jobId !== null) {
        const attempt = episode.length + 1;
        report.retried.push({ siteId, tenantId, failedJobId, jobId: state.jobId, attempt });
        logger.info(
          { siteId, tenantId, failedJobId, jobId: state.jobId, attempt, maxAttempts: policy.maxRetries + 1 },
          'concentrator secret: transient failure RETRIED (a new additive job, which reads the CHR first)',
        );
      } else {
        // Busy CHR (the next pass tries again), or a refusal ensure() made
        // without queueing. No attempt was spent either way.
        skip(state.reason ?? state.state);
      }
    } catch (err) {
      logger.warn(
        { err: err instanceof Error ? err.message : String(err), siteId, failedJobId },
        'concentrator secret retry: this site could not be examined on this pass',
      );
    }
  }

  // Only a pass that DID something logs: an exhausted site stays in the window
  // for a day, and a line per pass for it would be a line every 30 s.
  if (report.retried.length > 0 || report.exhausted.some((e) => e.announced)) {
    logger.info(
      {
        examined: report.examined,
        retried: report.retried.length,
        waiting: report.waiting.length,
        exhausted: report.exhausted.length,
        refused: report.refused.length,
        skipped: report.skipped.length,
      },
      'concentrator secret retry pass',
    );
  }
  return report;
}

// ============================================================================
// The periodic pass
// ============================================================================

let timer: NodeJS.Timeout | null = null;
let running: Promise<unknown> | null = null;

export interface StartRetryOptions extends RetrySweepOptions {
  intervalMs?: number;
}

/**
 * Arm the periodic pass on this process. Every process may call it: a tick on
 * a process that is not the leader does nothing. Arming also tells the failure
 * alert which policy runs here; idempotent.
 */
export function startConcentratorSecretRetry(options: StartRetryOptions = {}): void {
  if (timer) return;
  const policy = policyOf(options);
  setConcentratorSecretRetryPolicy(policy);
  const intervalMs = Math.max(10, Math.floor(options.intervalMs ?? CONCENTRATOR_SECRET_RETRY_INTERVAL_MS));
  timer = setInterval(() => {
    if (running) return; // a slow pass is never stacked under the next one
    running = sweepConcentratorSecretRetries({ ...options, ...policy })
      .catch((err: unknown) => {
        logger.error({ err }, 'concentrator secret retry pass failed');
      })
      .finally(() => {
        running = null;
      });
  }, intervalMs);
  timer.unref?.();
  logger.info(
    { intervalMs, ...policy },
    'Concentrator secret retry armed (leader-only; transient failures, bounded, with backoff)',
  );
}

/** Disarm, and wait for a pass in flight so it cannot queue after shutdown. */
export async function stopConcentratorSecretRetry(): Promise<void> {
  if (timer) clearInterval(timer);
  timer = null;
  setConcentratorSecretRetryPolicy(null);
  if (running) await running.catch(() => undefined);
}
