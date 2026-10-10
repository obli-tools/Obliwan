import { logger } from '../../utils/logger';
import { leaderElection } from '../leaderElection';
import { ReleaseCheckCancelled, checkRouterOsReleases } from './releases.service';

/**
 * The RouterOS release watcher: reads MikroTik's latest stable and long-term
 * RouterOS 7 versions once every 24 h (hourly after a failure, until one
 * succeeds), on the LEADER only: two replicas would read the same two
 * files twice for no extra information.
 *
 * Meant to be armed from the composition root, server/src/index.ts, like every
 * other runtime there:
 *   startRouterOsReleaseWatcher();          // next to startSimRuntime()
 *   await stopRouterOsReleaseWatcher();     // in the graceful shutdown
 * Nothing else calls this module: until those two lines are in index.ts, no
 * release is ever read and the settings card says "Never read yet".
 *
 * PUBLIC-INTERNET EGRESS. This watcher (https://upgrade.mikrotik.com) and the
 * pin probe in target.service.ts (https://download.mikrotik.com) go out over
 * ordinary outbound HTTPS to the open internet, NOT through the L2TP tunnel:
 * a second exception beside the SIM sweep. On an installation whose egress
 * is limited to the tunnel subnet, the settings card shows "Never read yet" or
 * "Stale", every pin is refused with a 502, and each channel logs one warning
 * an hour (the retry cadence) naming the host it could not reach.
 *
 * The cadence lives in the DATABASE, not in this timer: every tick asks
 * `isReleaseCheckDue()` against `last_checked_at` / `last_success_at`, so a
 * restart, or a change of leader, neither resets the 24 h nor skips a check.
 * The tick that runs on winning leadership is the "at startup, if the last
 * check is older" case. The tick is short so a due check starts within
 * RELEASE_WATCH_TICK_MS of becoming due; a tick with nothing due reads two
 * rows and sends nothing.
 *
 * LEADERSHIP is enforced twice, on purpose. The subscription arms the timer on
 * winning and disarms it on losing (and cancels a check in flight); and every
 * tick re-reads `isLeader()` before it sends anything, so a tick that fires
 * between the lock being lost and the loss being announced sends nothing.
 *
 * STOPPING cancels a check in flight (its request is aborted, and a cancelled
 * check records nothing, see ReleaseCheckCancelled) and then waits for that
 * tick to settle, for at most STOP_GRACE_MS. A tick that outlasts the grace
 * (a database that does not answer) is logged and left behind; its write may
 * then fail on the pool the caller closes next.
 *
 * Both behaviours are exercised by testing/releases.verify.ts through the
 * harness-only options below.
 */

export const RELEASE_WATCH_TICK_MS = 15 * 60_000;

/** How long stop waits for a cancelled tick. Well inside index.ts's 10 s forced exit. */
export const STOP_GRACE_MS = 3_000;

/** What the watcher needs from leadership: exactly `leaderElection`'s surface. */
export interface LeadershipSource {
  isLeader(): boolean;
  onChange(listener: (isLeader: boolean) => void): () => void;
}

export interface ReleaseWatcherOptions {
  /** Harness only: a fake leadership. Default: the advisory-lock election. */
  leadership?: LeadershipSource;
  /** Harness only: what a tick runs. Default: the DUE channels, against MikroTik. */
  check?: (signal: AbortSignal) => Promise<unknown>;
  /** Harness only. */
  tickMs?: number;
}

interface InFlightTick {
  abort: AbortController;
  promise: Promise<void>;
}

interface WatcherState {
  leadership: LeadershipSource;
  check: (signal: AbortSignal) => Promise<unknown>;
  tickMs: number;
  timer: NodeJS.Timeout | null;
  unsubscribe: () => void;
  stopped: boolean;
  current: InFlightTick | null;
}

let state: WatcherState | null = null;

function defaultCheck(signal: AbortSignal): Promise<unknown> {
  return checkRouterOsReleases({ force: false, signal });
}

function tick(s: WatcherState): void {
  // The second leadership gate (header): re-read at every tick.
  if (s.stopped || s.current || !s.leadership.isLeader()) return;
  const abort = new AbortController();
  const run = async (): Promise<void> => {
    try {
      // Each failed channel is logged (and recorded) by checkReleaseChannel.
      await s.check(abort.signal);
    } catch (err) {
      if (err instanceof ReleaseCheckCancelled || abort.signal.aborted) {
        logger.info('RouterOS release watcher: check cancelled (stop or leadership lost); nothing recorded for it');
      } else {
        // A database error, not a MikroTik one (those are recorded, not thrown).
        logger.error({ err }, 'RouterOS release watcher: tick failed');
      }
    }
  };
  // Started on the next microtask so `entry` exists before `finally` can run.
  const entry: InFlightTick = {
    abort,
    promise: Promise.resolve()
      .then(run)
      .finally(() => {
        if (s.current === entry) s.current = null;
      }),
  };
  s.current = entry;
}

function disarm(s: WatcherState): void {
  if (s.timer) {
    clearInterval(s.timer);
    s.timer = null;
  }
}

/**
 * Wire the watcher to leadership. Idempotent: a second call while it is armed
 * does nothing (and ignores its options).
 */
export function startRouterOsReleaseWatcher(opts: ReleaseWatcherOptions = {}): void {
  if (state) return;
  const s: WatcherState = {
    leadership: opts.leadership ?? leaderElection,
    check: opts.check ?? defaultCheck,
    tickMs: opts.tickMs ?? RELEASE_WATCH_TICK_MS,
    timer: null,
    unsubscribe: () => undefined,
    stopped: false,
    current: null,
  };
  state = s;
  // onChange calls back at once with the current state (leaderElection.ts).
  s.unsubscribe = s.leadership.onChange((isLeader) => {
    if (s.stopped) return;
    if (isLeader) {
      if (s.timer) return;
      logger.info({ tickMs: s.tickMs }, 'RouterOS release watcher started (leader)');
      s.timer = setInterval(() => tick(s), s.tickMs);
      s.timer.unref?.();
      tick(s);
    } else if (s.timer) {
      disarm(s);
      s.current?.abort.abort();
      logger.info('RouterOS release watcher stopped (leadership lost)');
    }
  });
}

/**
 * Disarm the watcher, cancel a check in flight and wait (at most
 * STOP_GRACE_MS) for it to settle. Idempotent.
 */
export async function stopRouterOsReleaseWatcher(): Promise<void> {
  const s = state;
  if (!s) return;
  state = null;
  s.stopped = true;
  disarm(s);
  s.unsubscribe();
  const current = s.current;
  if (!current) return;
  current.abort.abort();
  let grace: NodeJS.Timeout | undefined;
  const outcome = await Promise.race([
    current.promise.then(() => 'settled' as const),
    new Promise<'grace'>((resolve) => {
      grace = setTimeout(() => resolve('grace'), STOP_GRACE_MS);
      grace.unref?.();
    }),
  ]);
  if (grace) clearTimeout(grace);
  if (outcome === 'grace') {
    logger.warn({ graceMs: STOP_GRACE_MS }, 'RouterOS release watcher: a tick outlasted the stop grace period and was left behind');
  }
}
