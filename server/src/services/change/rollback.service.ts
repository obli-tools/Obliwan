/**
 * ObliWAN. The dead-man itself, and reading what it did.
 *
 * THE PROPERTY THIS FILE EXISTS TO PROTECT
 * The dead-man lives ON THE EQUIPMENT. It must restore the device even if the
 * ObliWAN server is dead, even if the network is cut, even if the process that
 * launched the apply no longer exists. A rollback driven from ObliWAN is NOT a
 * dead-man — it is precisely the thing that does not work when you have just
 * shot your own leg off. Everything in this file is either (a) the on-box
 * mechanism, or (b) our attempt to find out afterwards what the on-box
 * mechanism did without us.
 *
 * THE MECHANISM (MikroTik)
 *   /system/script   obliwan-rollback-<job>   loads the preflight binary backup
 *   /system/scheduler obliwan-deadman-<job>   start-time=startup + interval=<T>
 *
 * `start-time=startup` and an interval are ONE entry doing TWO jobs, and both
 * are needed:
 *   - at every boot, the script runs. A change that hangs the router and gets
 *     it power-cycled by the customer comes back to the pre-change config.
 *   - every T minutes, the script runs. A change that cuts the tunnel without
 *     rebooting anything is undone at the deadline, because nobody disarmed.
 *
 * WHY WE DO NOT USE `/import` TO APPLY (rejected in the spec, restated here
 * because this file is where the alternative lives): `/import` stops at the
 * first failing line and leaves the router half-configured with no handler.
 * The apply goes through `/system/script` wrapped in `:do{} on-error={}` so the
 * failure branch calls the very script above.
 *
 * WHAT A ROLLBACK DESTROYS — THE HONEST PART
 * `/system/backup/load` restores the configuration AND REBOOTS. The scheduler
 * and the script are configuration, so a successful dead-man ERASES ITS OWN
 * EVIDENCE. There is therefore no on-box flag saying "I fired". What we can do
 * is INFER it, from three facts that are individually weak and jointly strong:
 *   1. the scheduler and the script are gone (they were created after the
 *      backup, so a restore removes them);
 *   2. the device rebooted since we armed (uptime < time since arming);
 *   3. a fresh canonical `.rsc` export hashes to the same value as the
 *      preflight `.rsc` backup.
 * (3) is a PROOF and is reported as `confidence: 'proved'`. (1)+(2) alone are
 * reported as `'inferred'`. We never report a rollback we did not observe.
 *
 * ACCEPTED, BOUNDED EXPOSURE, WRITTEN DOWN RATHER THAN HIDDEN: the rollback
 * script contains the backup's password, so for the length of the change window
 * a secret sits in the device's configuration. The alternative is an
 * unencrypted backup blob on the same device, which is worse. The password is
 * random, per-backup, useless anywhere else, and both the script and the blob
 * are removed at disarm.
 */

import {
  ChangeError,
  assertBoxSpeaksRecordedFamily,
  assertRscCarriesNoSecret,
  buildExportWords,
  canonicalRscHash,
  getBackup,
  planBackupPull,
  pullDeviceFile,
  readRscBackup,
  removeBackupFromDevice,
  type DeviceSession,
} from './backup.service';
import { logger } from '../../utils/logger';
import {
  redactTransferUrl,
  removeDeviceFile,
  verifyArtefact,
  waitForDeviceFile,
  type TransferReceiver,
} from './transfer.service';
import fsp from 'fs/promises';

// ============================================================================
// Names — one function, so nothing is ever spelled twice
// ============================================================================

export interface DeadmanNames {
  scriptName: string;
  schedulerName: string;
  backupFileBase: string;
  backupFileName: string;
  /** What goes into `change_jobs.deadman_handle` (128 chars). Everything else
   *  is derivable from it, so a job that died mid-flight can still be cleaned
   *  up by hand from the value on the row. */
  handle: string;
}

export function deadmanNames(jobId: number | string): DeadmanNames {
  const suffix = String(jobId);
  const base = `obliwan-deadman-${suffix}`;
  return {
    scriptName: `obliwan-rollback-${suffix}`,
    schedulerName: base,
    backupFileBase: base,
    backupFileName: `${base}.backup`,
    handle: base,
  };
}

export function deadmanNamesFromHandle(handle: string): DeadmanNames {
  const suffix = handle.replace(/^obliwan-deadman-/, '');
  return deadmanNames(suffix);
}

// ============================================================================
// RouterOS interval formatting
// ============================================================================

/** `600` -> `00:10:00`. RouterOS accepts `HH:MM:SS` and rejects a bare number
 *  for `interval`, which is the sort of thing that fails at 2 a.m. */
export function formatRouterOsInterval(seconds: number): string {
  const s = Math.max(1, Math.floor(seconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${pad(h)}:${pad(m)}:${pad(sec)}`;
}

/** Accepts `00:10:00`, `10m`, `1h30m`, `600`. Returns null when unreadable —
 *  and "unreadable" must never be read as "correct". */
export function parseRouterOsInterval(raw: string | null | undefined): number | null {
  if (!raw) return null;
  const text = raw.trim();
  if (/^\d+$/.test(text)) return Number(text);
  const clock = /^(\d+):(\d{1,2}):(\d{1,2})$/.exec(text);
  if (clock) return Number(clock[1]) * 3600 + Number(clock[2]) * 60 + Number(clock[3]);
  const units = /^(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/.exec(text);
  if (!units || units.slice(1).every((u) => u === undefined)) return null;
  const [, w, d, h, m, s] = units;
  return (
    Number(w ?? 0) * 604800 +
    Number(d ?? 0) * 86400 +
    Number(h ?? 0) * 3600 +
    Number(m ?? 0) * 60 +
    Number(s ?? 0)
  );
}

/** `1w2d3h4m5s` -> seconds. RouterOS uptime format. */
export function parseUptime(raw: string | null | undefined): number | null {
  return parseRouterOsInterval(raw);
}

// ============================================================================
// The on-box script sources
// ============================================================================

export interface RollbackScriptSpec {
  jobId: number | string;
  backupFileName: string;
  backupPassword: string;
  schedulerName: string;
  /** Give up after this many failed loads rather than reboot-loop a customer's
   *  router forever. */
  maxAttempts?: number;
}

/**
 * The script the router runs on itself when nobody disarmed it.
 *
 * Read it as a safety argument, top to bottom:
 *  - a global attempt counter, so a backup that cannot be loaded produces three
 *    tries and then a permanent stop, not an endless reboot cycle on a site
 *    that is otherwise merely unreachable;
 *  - the give-up branch removes the scheduler, so the router is left alone;
 *  - the log lines are at `warning`, so they survive the default log topics and
 *    an engineer arriving later can see what happened even though the restore
 *    erased the scheduler that did it;
 *  - `/system/backup/load` is LAST, because it never returns: it restores and
 *    reboots.
 */
export function buildRollbackScriptSource(spec: RollbackScriptSpec): string {
  const id = String(spec.jobId).replace(/[^A-Za-z0-9]/g, '');
  const counter = `obliwanRb${id}`;
  const max = spec.maxAttempts ?? 3;
  return [
    `:global ${counter};`,
    `:if ([:typeof $${counter}] = "nothing") do={ :set ${counter} 0; }`,
    `:set ${counter} ($${counter} + 1);`,
    `:log warning "obliwan: dead-man firing for job ${spec.jobId}, attempt $${counter}";`,
    `:if ($${counter} > ${max}) do={`,
    `  :log error "obliwan: dead-man gave up after ${max} attempts on job ${spec.jobId}";`,
    `  /system/scheduler remove [/system/scheduler find name="${spec.schedulerName}"];`,
    `} else={`,
    `  /system/backup/load name="${spec.backupFileName}" password="${spec.backupPassword}";`,
    `}`,
  ].join('\n');
}

/**
 * The apply wrapper, and the reason `/import` was rejected.
 *
 * `:do={...} on-error={...}` gives the change an error handler that runs ON THE
 * ROUTER. If line 40 of 60 fails, the handler fires immediately and calls the
 * rollback script — the box does not sit half-configured waiting for a server
 * that may no longer be able to reach it.
 *
 * The success marker is a global variable rather than a file: `/file/add` does
 * not exist on RouterOS 6, and a global costs nothing. It is read back through
 * `/system/script/environment/print` after the run, because `/system/script/run`
 * itself answers `!done` whether the body succeeded or the on-error branch ran
 * — that is the whole point of an error handler, and it is also why a naive
 * caller would believe a failed apply succeeded.
 */
export function buildApplyScriptSource(spec: {
  jobId: number | string;
  commands: readonly string[];
  rollbackScriptName: string;
  markerGlobal: string;
}): string {
  const body = spec.commands.map((c) => (c.trim().endsWith(';') ? c.trim() : `${c.trim()};`));
  return [
    `:global ${spec.markerGlobal} "running";`,
    ':do={',
    ...body.map((l) => `  ${l}`),
    `  :set ${spec.markerGlobal} "ok";`,
    `  :log info "obliwan: apply ${spec.jobId} ok";`,
    '} on-error={',
    `  :set ${spec.markerGlobal} "failed";`,
    `  :log error "obliwan: apply ${spec.jobId} FAILED, running ${spec.rollbackScriptName}";`,
    `  /system/script/run [/system/script find name="${spec.rollbackScriptName}"];`,
    '}',
  ].join('\n');
}

export function applyMarkerGlobal(jobId: number | string): string {
  return `obliwanApply${String(jobId).replace(/[^A-Za-z0-9]/g, '')}`;
}

// ============================================================================
// Reading the dead-man's state off the box
// ============================================================================

export interface DeadmanState {
  scriptPresent: boolean;
  scriptId: string | null;
  scriptRunCount: number | null;
  schedulerPresent: boolean;
  schedulerId: string | null;
  schedulerDisabled: boolean | null;
  schedulerStartTime: string | null;
  schedulerIntervalSeconds: number | null;
  schedulerOnEvent: string | null;
  schedulerRunCount: number | null;
  /** `next-run` as the router printed it (its own clock and format), or null. */
  schedulerNextRun: string | null;
  /** The blob the script loads. Absent = the dead-man has nothing to restore. */
  backupPresent: boolean;
  backupBytes: number | null;
}

/**
 * What the router shows of one job's dead-man.
 *
 * TWO READINGS OF A FAILED PRINT, and the caller picks by what it concludes:
 *  - LENIENT (default): a print that fails reads as "not present". That is
 *    the SAFE reading for the arming verdict — `judgeArming()` then says NOT
 *    armed, and nothing is applied.
 *  - `strict`: a print that fails THROWS. That is the only honest reading for
 *    a caller that concludes something is GONE — `removeDeadmanEntries()`
 *    (which removes only what it sees), the post-removal re-reads of
 *    `disarmWithRetry()` and `cleanupDeadmanArtefacts()`, and
 *    `inspectDeadman()`. Read leniently, a timed-out scheduler print removed
 *    nothing and then "proved" it gone, and the job reported a net removed
 *    that was still counting on the router.
 */
export async function readDeadmanState(
  session: DeviceSession,
  names: DeadmanNames,
  opts: { strict?: boolean } = {},
): Promise<DeadmanState> {
  const read = (words: string[]): Promise<Record<string, string>[]> => {
    const rows = session.run(words, { isWrite: false, skipAudit: true });
    return opts.strict ? rows : rows.catch(() => [] as Record<string, string>[]);
  };
  const scripts = await read(['/system/script/print', `?name=${names.scriptName}`]);
  const schedulers = await read(['/system/scheduler/print', `?name=${names.schedulerName}`]);
  const files = await read(['/file/print', `?name=${names.backupFileName}`]);

  const script = scripts.find((r) => r.name === names.scriptName) ?? null;
  const sched = schedulers.find((r) => r.name === names.schedulerName) ?? null;
  const file = files.find((r) => r.name === names.backupFileName) ?? null;

  return {
    scriptPresent: script !== null,
    scriptId: script?.['.id'] ?? null,
    scriptRunCount: script?.['run-count'] !== undefined ? Number(script['run-count']) : null,
    schedulerPresent: sched !== null,
    schedulerId: sched?.['.id'] ?? null,
    schedulerDisabled: sched ? sched.disabled === 'true' : null,
    schedulerStartTime: sched?.['start-time'] ?? null,
    schedulerIntervalSeconds: parseRouterOsInterval(sched?.interval),
    schedulerOnEvent: sched?.['on-event'] ?? null,
    schedulerRunCount: sched?.['run-count'] !== undefined ? Number(sched['run-count']) : null,
    schedulerNextRun: sched?.['next-run'] ? String(sched['next-run']).trim() || null : null,
    backupPresent: file !== null,
    backupBytes: file?.size !== undefined ? Number(file.size) || null : null,
  };
}

// ============================================================================
// When does the dead-man FIRST fire? Read off the router, never assumed
// ============================================================================
//
// ┌─ WHY THIS IS READ ────────────────────────────────────────────────────────┐
// │ `start-time=startup` + `interval=T` is added at RUNTIME, minutes or days  │
// │ after the boot. Every deadline this product computes — `confirm_deadline`,│
// │ the soak budget, the « redémarrage prévu vers … » alert — assumed the     │
// │ first run is "now + T". Whether RouterOS anchors such a scheduler on the  │
// │ moment it is added or on the boot (boot + k·T, i.e. anywhere in (0, T]    │
// │ from now) has NOT been observed on hardware. If it is the boot, the       │
// │ dead-man can fire in the middle of the apply or the soak — a reboot that  │
// │ reverts the change while it is being verified. So the arming is judged on │
// │ the router's own `next-run`, against the router's own clock (no clock    │
// │ skew between us and it enters the subtraction), and a first run that is  │
// │ unreadable or too early REFUSES the arming — before anything is applied,  │
// │ so the queue takes the net back down.                                     │
// └───────────────────────────────────────────────────────────────────────────┘

const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];

interface CivilDate {
  y: number;
  m: number; // 1-12
  d: number;
}

/** `2026-10-09` (RouterOS 7.10+) or `oct/09/2026` (older). */
function parseRouterOsDate(raw: string): CivilDate | null {
  const iso = /^(\d{4})-(\d{2})-(\d{2})$/.exec(raw);
  if (iso) return { y: Number(iso[1]), m: Number(iso[2]), d: Number(iso[3]) };
  const old = /^([a-z]{3})\/(\d{1,2})\/(\d{4})$/i.exec(raw);
  if (old) {
    const m = MONTHS.indexOf(old[1].toLowerCase()) + 1;
    return m > 0 ? { y: Number(old[3]), m, d: Number(old[2]) } : null;
  }
  return null;
}

function parseHms(raw: string): number | null {
  const t = /^(\d{1,2}):(\d{2}):(\d{2})$/.exec(raw);
  if (!t) return null;
  const [h, mi, s] = [Number(t[1]), Number(t[2]), Number(t[3])];
  return h < 24 && mi < 60 && s < 60 ? h * 3600 + mi * 60 + s : null;
}

/** Seconds since an arbitrary epoch, on the router's civil clock (no zone). */
function civilSeconds(d: CivilDate, secondsOfDay: number): number {
  return Date.UTC(d.y, d.m - 1, d.d) / 1000 + secondsOfDay;
}

/**
 * Seconds from the router's `now` (`/system/clock/print`: `date`, `time`) to
 * a scheduler's `next-run`. Accepts a full date-time in either RouterOS
 * spelling, a date without its year (`oct/09 14:23:00`, `10-09 14:23:00`:
 * the clock's year), or a bare time (today, or tomorrow when already past).
 * Null when either side cannot be read — which the caller treats as "not
 * proven", never as "a full interval away".
 */
export function firstRunDelaySeconds(
  nextRun: string | null,
  clock: { date?: string | null; time?: string | null } | null,
): number | null {
  if (!nextRun || !clock?.date || !clock.time) return null;
  const today = parseRouterOsDate(clock.date.trim());
  const nowSod = parseHms(clock.time.trim());
  if (!today || nowSod === null) return null;
  const now = civilSeconds(today, nowSod);

  const parts = nextRun.trim().split(/\s+/);
  const timePart = parts[parts.length - 1];
  const sod = parseHms(timePart);
  if (sod === null || parts.length > 2) return null;
  if (parts.length === 1) {
    let at = civilSeconds(today, sod);
    if (at < now) at += 86_400;
    return at - now;
  }
  const datePart = parts[0];
  let day = parseRouterOsDate(datePart);
  if (!day) {
    const md = /^(\d{2})-(\d{2})$/.exec(datePart);
    const mon = /^([a-z]{3})\/(\d{1,2})$/i.exec(datePart);
    if (md) day = { y: today.y, m: Number(md[1]), d: Number(md[2]) };
    else if (mon && MONTHS.includes(mon[1].toLowerCase())) {
      day = { y: today.y, m: MONTHS.indexOf(mon[1].toLowerCase()) + 1, d: Number(mon[2]) };
    }
  }
  if (!day) return null;
  return civilSeconds(day, sod) - now;
}

export interface ArmingVerdict {
  armed: boolean;
  /** Every reason the arming is NOT trustworthy. Empty when `armed`. */
  problems: string[];
  state: DeadmanState;
}

/**
 * Prove the dead-man is really armed BEFORE anything is applied.
 *
 * "Un dead-man qu'on croit armé et qui ne l'est pas est pire que pas de
 * dead-man du tout, parce qu'on pousse alors avec une confiance injustifiée."
 * So this checks six separate things, and any one of them failing means we do
 * not apply:
 *
 *   1. the script exists;
 *   2. the scheduler exists;
 *   3. the scheduler is ENABLED (a disabled scheduler is a decoration);
 *   4. `start-time=startup` — the boot half of the net;
 *   5. an interval within tolerance of what we asked — the timed half;
 *   6. `on-event` actually names OUR script, not some other one;
 *   7. the backup blob the script loads is present and non-trivial. A perfectly
 *      armed scheduler pointed at a missing file restores nothing;
 *   8. when the caller passes `firstRun`: the scheduler's FIRST run, read off
 *      the router (`next-run` against its own clock), is far enough away for
 *      the change to be applied, verified and disarmed (see
 *      `firstRunDelaySeconds`).
 *
 * Note that this reads the state back off the device on the SESSION IT IS
 * GIVEN. `safeApply` gives it a fresh one, deliberately: verifying the arming
 * on the same socket that did the arming proves the router accepted our
 * sentences, not that the configuration is there.
 */
export function judgeArming(
  state: DeadmanState,
  expected: {
    schedulerName: string;
    scriptName: string;
    intervalSeconds: number;
    /**
     * 8. The FIRST RUN, when the caller can say how soon is too soon: the
     * delay `firstRunDelaySeconds()` read off the router, and the minimum the
     * job needs before the dead-man may fire (apply, verify, soak, disarm).
     * Unreadable is refused like too early: an unproven deadline is not one.
     */
    firstRun?: { seconds: number | null; minimumSeconds: number };
  },
): ArmingVerdict {
  const problems: string[] = [];
  if (expected.firstRun && state.schedulerPresent) {
    const { seconds, minimumSeconds } = expected.firstRun;
    if (seconds === null) {
      problems.push(
        `the router did not report when the scheduler first fires (next-run '${state.schedulerNextRun ?? 'absent'}') ` +
          '— refusing to assume it is a full interval away: a scheduler anchored on the boot could ' +
          'fire in the middle of the change',
      );
    } else if (seconds < minimumSeconds) {
      problems.push(
        `the scheduler first fires in ${Math.round(seconds)}s (next-run '${state.schedulerNextRun}'), ` +
          `before the ${Math.round(minimumSeconds)}s the change needs to be applied, verified and ` +
          'disarmed — it would revert the change with a reboot while it is being watched',
      );
    }
  }
  if (!state.scriptPresent) problems.push(`the script '${expected.scriptName}' is not on the device`);
  if (!state.schedulerPresent) {
    problems.push(`the scheduler '${expected.schedulerName}' is not on the device`);
  }
  if (state.schedulerPresent && state.schedulerDisabled === true) {
    problems.push('the scheduler exists but is DISABLED — it would never fire');
  }
  if (state.schedulerPresent && state.schedulerStartTime !== 'startup') {
    problems.push(
      `start-time is '${state.schedulerStartTime ?? 'unset'}' and not 'startup' — ` +
        'the router would not repair itself after a reboot',
    );
  }
  if (state.schedulerPresent) {
    const seen = state.schedulerIntervalSeconds;
    if (seen === null) {
      problems.push('the scheduler interval could not be read — refusing to assume it is armed');
    } else if (Math.abs(seen - expected.intervalSeconds) > 2) {
      problems.push(
        `the scheduler interval is ${seen}s, not the ${expected.intervalSeconds}s we asked for`,
      );
    }
  }
  if (state.schedulerPresent && !(state.schedulerOnEvent ?? '').includes(expected.scriptName)) {
    problems.push(
      `on-event does not reference '${expected.scriptName}' — the scheduler would fire something else`,
    );
  }
  if (!state.backupPresent) {
    problems.push(
      'the backup blob the rollback script loads is not on the device — ' +
        'the dead-man would fire and restore nothing',
    );
  }
  return { armed: problems.length === 0, problems, state };
}

// ============================================================================
// Arming and disarming
// ============================================================================

export interface ArmOptions {
  jobId: number | string;
  backupFileName: string;
  backupPassword: string;
  intervalSeconds: number;
  /** Replace an entry left behind by a previous attempt. Default true. */
  clearExisting?: boolean;
}

/**
 * Install the dead-man. Returns the names so the caller can persist the handle
 * BEFORE it is used — a job that crashes between arming and recording the
 * handle leaves a router that will revert itself and an operator with no idea
 * why, which is the worst of both worlds.
 */
export async function armDeadman(
  session: DeviceSession,
  options: ArmOptions,
): Promise<DeadmanNames> {
  const names = deadmanNames(options.jobId);
  session.protect(options.backupPassword);

  if (options.clearExisting !== false) {
    await removeDeadmanEntries(session, names).catch(() => undefined);
  }

  const source = buildRollbackScriptSource({
    jobId: options.jobId,
    backupFileName: options.backupFileName,
    backupPassword: options.backupPassword,
    schedulerName: names.schedulerName,
  });
  await session.run(
    ['/system/script/add', `=name=${names.scriptName}`, '=policy=read,write,policy,test', `=source=${source}`],
    { isWrite: true, secretValues: [options.backupPassword] },
  );
  await session.run(
    [
      '/system/scheduler/add',
      `=name=${names.schedulerName}`,
      '=start-time=startup',
      `=interval=${formatRouterOsInterval(options.intervalSeconds)}`,
      '=policy=read,write,policy,test',
      `=on-event=/system/script/run ${names.scriptName}`,
    ],
    { isWrite: true },
  );
  return names;
}

/** Removes what a STRICT read shows; a read that fails throws rather than
 *  being taken for "nothing to remove". */
export async function removeDeadmanEntries(
  session: DeviceSession,
  names: DeadmanNames,
): Promise<void> {
  const state = await readDeadmanState(session, names, { strict: true });
  if (state.schedulerPresent) {
    await session.run(
      ['/system/scheduler/remove', `=numbers=${state.schedulerId ?? names.schedulerName}`],
      { isWrite: true },
    );
  }
  if (state.scriptPresent) {
    await session.run(['/system/script/remove', `=numbers=${state.scriptId ?? names.scriptName}`], {
      isWrite: true,
    });
  }
}

export interface DisarmResult {
  disarmed: boolean;
  attempts: number;
  /** True when a re-read PROVED both entries are gone. */
  verified: boolean;
  backupRemoved: boolean;
  lastError: string | null;
  elapsedMs: number;
}

/**
 * Disarm, with retry until it succeeds.
 *
 * "Un désarmement raté = un équipement qui va se restaurer tout seul dans 10
 * minutes alors que le changement était bon." So this does not give up after
 * one polite attempt: it re-opens a session per attempt (the caller supplies
 * the factory), removes both entries, RE-READS to prove they are gone, and only
 * then removes the backup blob.
 *
 * The order matters: entries first, blob last. If we removed the blob first and
 * then failed to remove the scheduler, the dead-man would still fire and would
 * restore nothing — a reboot loop with no recovery.
 */
export async function disarmWithRetry(options: {
  openSession: () => Promise<DeviceSession>;
  names: DeadmanNames;
  attempts?: number;
  backoffMs?: number;
  onAttempt?: (attempt: number, error: string | null) => void;
}): Promise<DisarmResult> {
  const attempts = options.attempts ?? 6;
  const backoffMs = options.backoffMs ?? 3_000;
  const started = Date.now();
  let lastError: string | null = null;

  for (let i = 1; i <= attempts; i++) {
    let session: DeviceSession | null = null;
    try {
      session = await options.openSession();
      await removeDeadmanEntries(session, options.names);
      // STRICT: `verified` means a re-read that completed, never a failed one.
      const after = await readDeadmanState(session, options.names, { strict: true });
      if (after.schedulerPresent || after.scriptPresent) {
        lastError = 'the scheduler or script is still present after removal';
      } else {
        const removal = await removeBackupFromDevice(session, options.names.backupFileName);
        return {
          disarmed: true,
          attempts: i,
          verified: true,
          backupRemoved: removal.verified,
          lastError: removal.verified ? null : removal.lastError,
          elapsedMs: Date.now() - started,
        };
      }
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err);
    } finally {
      session?.close();
    }
    options.onAttempt?.(i, lastError);
    if (i < attempts) await new Promise<void>((r) => setTimeout(r, backoffMs * i));
  }

  // THIS IS AN INCIDENT, NOT A WARNING. A live router carries a scheduler that
  // will revert a good change at its next tick, and we cannot reach it to stop
  // that. Whoever consumes this log line should page a human.
  logger.fatal(
    { handle: options.names.handle, attempts, lastError },
    'DISARM FAILED — the equipment still carries an armed dead-man and WILL revert the change ' +
      'at the next interval. Manual intervention required.',
  );
  return {
    disarmed: false,
    attempts,
    verified: false,
    backupRemoved: false,
    lastError,
    elapsedMs: Date.now() - started,
  };
}

// ============================================================================
// Server-driven rollback — when we CAN still talk to the box
// ============================================================================

export interface ServerRollbackResult {
  triggered: boolean;
  method: 'script' | 'backup_load' | 'none';
  error: string | null;
}

/**
 * Ask the device to run its own rollback script.
 *
 * This is the fast path, used when the change went wrong but the management
 * path survived: rather than wait out the dead-man's interval, we fire it now.
 * It is deliberately the SAME script — one restore procedure, exercised by both
 * paths, so the rarely-used one is not the untested one.
 *
 * The call is expected to die mid-flight: `/system/backup/load` reboots the
 * router, so the socket drops before any `!done`. A dropped socket here is a
 * SUCCESS signal, not a failure, and treating it as an error would make every
 * successful rollback look like a failed one.
 */
export async function rollbackViaScript(
  session: DeviceSession,
  names: DeadmanNames,
): Promise<ServerRollbackResult> {
  try {
    await session.run(
      ['/system/script/run', `=number=${names.scriptName}`],
      { isWrite: true, timeoutMs: 15_000 },
    );
    return { triggered: true, method: 'script', error: null };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    // The reboot cutting our socket is the expected outcome.
    if (/closed|reset|timed out|ECONNRESET|EPIPE|not established/i.test(message)) {
      return { triggered: true, method: 'script', error: null };
    }
    return { triggered: false, method: 'none', error: message };
  }
}

/** Load a backup blob directly. Used when the script is gone but the blob is
 *  not — a job that crashed between the backup and the arming. */
export async function rollbackViaBackupLoad(
  session: DeviceSession,
  fileName: string,
  password: string,
): Promise<ServerRollbackResult> {
  session.protect(password);
  try {
    await session.run(
      ['/system/backup/load', `=name=${fileName}`, `=password=${password}`],
      { isWrite: true, timeoutMs: 15_000, secretValues: [password] },
    );
    return { triggered: true, method: 'backup_load', error: null };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (/closed|reset|timed out|ECONNRESET|EPIPE|not established/i.test(message)) {
      return { triggered: true, method: 'backup_load', error: null };
    }
    return { triggered: false, method: 'none', error: message };
  }
}

// ============================================================================
// Reading what the dead-man did, after the fact
// ============================================================================

export type RollbackVerdict =
  | 'never_armed'
  | 'still_armed'
  | 'disarmed'
  | 'fired_restored'
  | 'fired_unverified'
  | 'unknown';

export interface DeadmanEvidence {
  verdict: RollbackVerdict;
  /** `proved` = a byte-level comparison against the preflight `.rsc`.
   *  `inferred` = the scheduler is gone and the box rebooted.
   *  `unknown` = we could not read enough to say anything. */
  confidence: 'proved' | 'inferred' | 'unknown';
  state: DeadmanState | null;
  uptimeSeconds: number | null;
  rebootedSinceArming: boolean | null;
  /** Set when a canonical `.rsc` comparison was actually performed. */
  configMatchesPreflight: boolean | null;
  observations: string[];
  at: string;
}

/**
 * Decide, from what the box shows us, whether the dead-man fired.
 *
 * The rules, in order, and the ORDER is the argument:
 *
 *  - If the scheduler is still there and enabled, nothing fired. The change (if
 *    any) is still live and the deadline is still counting.
 *  - If everything is gone AND the box rebooted since we armed, the dead-man
 *    fired: `/system/backup/load` is the only thing in this system that removes
 *    both entries and reboots.
 *  - If everything is gone and the box did NOT reboot, somebody or something
 *    removed our entries without restoring. That is `unknown`, never
 *    `disarmed` — reporting a clean disarm we did not perform is how a router
 *    that silently lost its net gets marked green.
 *
 * `configMatchesPreflight` upgrades an inference to a proof and is the only
 * thing that does.
 */
export function judgeDeadmanEvidence(input: {
  state: DeadmanState | null;
  uptimeSeconds: number | null;
  armedAt: Date | null;
  now?: Date;
  configMatchesPreflight?: boolean | null;
  disarmRequested?: boolean;
}): DeadmanEvidence {
  const now = input.now ?? new Date();
  const observations: string[] = [];
  const state = input.state;
  const configMatches = input.configMatchesPreflight ?? null;

  let rebooted: boolean | null = null;
  if (input.uptimeSeconds !== null && input.armedAt) {
    const sinceArmingS = (now.getTime() - input.armedAt.getTime()) / 1000;
    // 30 s of slack for clock skew and for the seconds between our timestamp
    // and the router's own idea of when it came up.
    rebooted = input.uptimeSeconds + 30 < sinceArmingS;
    observations.push(
      `uptime ${Math.round(input.uptimeSeconds)}s vs ${Math.round(sinceArmingS)}s since arming`,
    );
  }

  if (!state) {
    return {
      verdict: 'unknown',
      confidence: 'unknown',
      state: null,
      uptimeSeconds: input.uptimeSeconds,
      rebootedSinceArming: rebooted,
      configMatchesPreflight: configMatches,
      observations: [...observations, 'the device could not be read at all'],
      at: now.toISOString(),
    };
  }

  if (!input.armedAt) {
    observations.push('no arming timestamp on the job');
    return {
      verdict: state.schedulerPresent ? 'still_armed' : 'never_armed',
      confidence: 'inferred',
      state,
      uptimeSeconds: input.uptimeSeconds,
      rebootedSinceArming: rebooted,
      configMatchesPreflight: configMatches,
      observations,
      at: now.toISOString(),
    };
  }

  if (state.schedulerPresent && state.schedulerDisabled !== true) {
    observations.push('the scheduler is still present and enabled: nothing has fired');
    return {
      verdict: 'still_armed',
      confidence: 'proved',
      state,
      uptimeSeconds: input.uptimeSeconds,
      rebootedSinceArming: rebooted,
      configMatchesPreflight: configMatches,
      observations,
      at: now.toISOString(),
    };
  }

  const gone = !state.schedulerPresent && !state.scriptPresent;
  if (gone && configMatches === true) {
    observations.push(
      'a fresh canonical export is byte-identical to the preflight .rsc backup: the ' +
        'configuration on the box IS the pre-change configuration',
    );
    return {
      verdict: 'fired_restored',
      confidence: 'proved',
      state,
      uptimeSeconds: input.uptimeSeconds,
      rebootedSinceArming: rebooted,
      configMatchesPreflight: configMatches,
      observations,
      at: now.toISOString(),
    };
  }
  if (gone && rebooted === true) {
    observations.push(
      'the scheduler and the script are gone and the device rebooted since arming — ' +
        'a /system/backup/load is the only thing that does both',
    );
    return {
      verdict: 'fired_restored',
      confidence: 'inferred',
      state,
      uptimeSeconds: input.uptimeSeconds,
      rebootedSinceArming: rebooted,
      configMatchesPreflight: configMatches,
      observations,
      at: now.toISOString(),
    };
  }
  if (gone && input.disarmRequested === true) {
    observations.push('we removed the entries ourselves and the device did not reboot');
    return {
      verdict: 'disarmed',
      confidence: 'proved',
      state,
      uptimeSeconds: input.uptimeSeconds,
      rebootedSinceArming: rebooted,
      configMatchesPreflight: configMatches,
      observations,
      at: now.toISOString(),
    };
  }
  if (gone) {
    observations.push(
      'the entries are gone but the device did not reboot and we did not disarm — ' +
        'refusing to call this a clean disarm',
    );
    return {
      verdict: 'unknown',
      confidence: 'unknown',
      state,
      uptimeSeconds: input.uptimeSeconds,
      rebootedSinceArming: rebooted,
      configMatchesPreflight: configMatches,
      observations,
      at: now.toISOString(),
    };
  }

  observations.push('a partial arming remains on the device');
  return {
    verdict: 'fired_unverified',
    confidence: 'unknown',
    state,
    uptimeSeconds: input.uptimeSeconds,
    rebootedSinceArming: rebooted,
    configMatchesPreflight: configMatches,
    observations,
    at: now.toISOString(),
  };
}

/** Read the uptime, in seconds, or null. */
export async function readUptimeSeconds(session: DeviceSession): Promise<number | null> {
  try {
    const rows = await session.run(['/system/resource/print'], {
      isWrite: false,
      skipAudit: true,
    });
    return parseUptime(rows[0]?.uptime ?? null);
  } catch {
    return null;
  }
}

/**
 * Export the running configuration and hash it canonically.
 *
 * This is what turns "we think it restored" into "the configuration on the box
 * is the configuration we backed up". It runs the same export as the preflight
 * `.rsc` — `buildExportWords()`, the one API spelling, read from the driver's
 * per-family table, after `assertBoxSpeaksRecordedFamily()` has checked that
 * family against the version the box reports — pulls it off the box along
 * the SAME roads, chosen by the SAME judgement, as a backup (`planBackupPull`
 * then `pullDeviceFile`: `/file/read` or SFTP over a channel we hold; the
 * router's `/tool/fetch` upload only where `judgeUploadCallback()` allows it),
 * deletes it from the device, and returns the canonical hash. It writes NO
 * `device_backups` row: this is a measurement, not an artefact. It used to
 * hand the router an upload URL unconditionally — this server's loopback in
 * production, so the comparison never completed (`configMatchesPreflight`
 * answered null), and with a callback configured the export would have
 * crossed any path in clear. Production passes neither `receiver` nor
 * `callbackHost` (safeApply.service), so there the plan is exactly
 * `planBackupPull(session)` and no URL is handed to the box; the two options
 * exist for a caller that configures the upload road explicitly, and are
 * judged by `judgeUploadCallback()` like a backup's.
 *
 * No secrets here either — a comparison is not a reason to hold secrets: the pulled text is
 * judged by the same `findSensitiveProps()` as the backup, and a hit throws
 * `SECRET_LEAK_REFUSED` instead of returning `text` (the caller then reports
 * "could not compare", which is the truth). The device copy and the spooled
 * copy are erased on every path out once the export has been requested —
 * including an export sentence that failed or timed out (the router may have
 * written the file anyway), a file that never settled and a transfer that
 * failed verification — and a device copy that cannot be proven gone is logged
 * as an error rather than dropped. The one thing no removal covers: a
 * cancelled export the router completes only AFTER the removal looked. A
 * removal is a look at the flash, not a lock on it.
 */
export async function exportCanonicalHash(options: {
  session: DeviceSession;
  /** Optional: only its spool directory, or the explicit upload road. */
  receiver?: TransferReceiver | null;
  callbackHost?: string;
  timeoutMs?: number;
}): Promise<{ hash: string; bytes: number; text: string }> {
  const { session, receiver } = options;
  const base = `obliwan-verify-${Date.now().toString(36)}`;
  const fileName = `${base}.rsc`;
  // The three refusals come BEFORE the try: no file can exist yet, so there is
  // nothing for the `finally` to erase.
  await assertBoxSpeaksRecordedFamily(session);
  const words = buildExportWords(session.target.family, base);
  const road = await planBackupPull(session, { callbackHost: options.callbackHost, receiver });
  try {
    // INSIDE the try: a timed-out `/export` is cancelled on our side, not
    // necessarily on the router's, and the `finally` must still look for it.
    await session.run(words, { isWrite: false, timeoutMs: options.timeoutMs ?? 60_000 });
    const onDevice = await waitForDeviceFile(session.conn, fileName, {
      timeoutMs: options.timeoutMs ?? 60_000,
    });
    const pulled = await pullDeviceFile(session, road, onDevice, {
      purpose: `verify:${session.target.id}`,
      maxBytes: 32 * 1024 * 1024,
      timeoutMs: options.timeoutMs ?? 60_000,
      receiver,
      callbackHost: options.callbackHost,
    });
    const received = pulled.received;
    let text: string;
    try {
      await verifyArtefact(received, {
        minBytes: 1,
        deviceReportedBytes: onDevice.sizeBytes,
        exactDeviceBytes: onDevice.sizeExact,
      });
      text = await fsp.readFile(received.path, 'utf8');
    } finally {
      await fsp.rm(received.path, { force: true }).catch((err) =>
        logger.error({ err }, 'could not delete the spooled comparison export'),
      );
    }
    assertRscCarriesNoSecret(text, `the comparison export of ${session.target.name}`);
    return { hash: canonicalRscHash(text), bytes: received.bytes, text };
  } finally {
    const removal = await removeDeviceFile(session.conn, fileName);
    if (!removal.verified) {
      logger.error(
        { deviceId: session.target.id, fileName, lastError: removal.lastError },
        'the comparison export could not be proven deleted from the equipment',
      );
    }
  }
}

/**
 * Compare the device's current configuration against the preflight `.rsc`.
 *
 * Returns null when the comparison could not be made (no `.rsc` backup, or the
 * export failed). Null is not `false`: "we could not compare" must never be
 * rendered as "it does not match".
 */
export async function configMatchesPreflight(options: {
  session: DeviceSession;
  receiver?: TransferReceiver | null;
  rscBackupId: number | null;
  callbackHost?: string;
}): Promise<boolean | null> {
  if (!options.rscBackupId) return null;
  try {
    const row = await getBackup(options.rscBackupId);
    if (!row || row.kind !== 'rsc') return null;
    const baseline = canonicalRscHash(await readRscBackup(options.rscBackupId));
    const current = await exportCanonicalHash({
      session: options.session,
      receiver: options.receiver,
      callbackHost: options.callbackHost,
    });
    return current.hash === baseline;
  } catch (err) {
    logger.warn(
      { err, backupId: options.rscBackupId },
      'could not compare the running config against the preflight .rsc',
    );
    return null;
  }
}

/**
 * Everything we can find out about a job's dead-man, in one call.
 *
 * `safeApply` uses it after a lost contact; the job screen uses it to answer
 * "what is still armed on this router?"; and `jobQueue`'s reaper will use it on
 * a job whose worker died in `applying`.
 */
export async function inspectDeadman(options: {
  session: DeviceSession;
  handle: string;
  armedAt: Date | null;
  receiver?: TransferReceiver;
  rscBackupId?: number | null;
  callbackHost?: string;
  disarmRequested?: boolean;
}): Promise<DeadmanEvidence> {
  const names = deadmanNamesFromHandle(options.handle);
  let state: DeadmanState | null = null;
  try {
    // STRICT, so a read that failed becomes `state: null` — "the device could
    // not be read", `unknown` — instead of entries that look gone, which the
    // judge would weigh toward `fired_restored`.
    state = await readDeadmanState(options.session, names, { strict: true });
  } catch (err) {
    logger.warn({ err }, 'could not read the dead-man state');
  }
  const uptimeSeconds = await readUptimeSeconds(options.session);
  let matches: boolean | null = null;
  // No receiver is needed: the comparison export is PULLED like a backup.
  if (options.rscBackupId) {
    matches = await configMatchesPreflight({
      session: options.session,
      receiver: options.receiver,
      rscBackupId: options.rscBackupId,
      callbackHost: options.callbackHost,
    });
  }
  return judgeDeadmanEvidence({
    state,
    uptimeSeconds,
    armedAt: options.armedAt,
    configMatchesPreflight: matches,
    disarmRequested: options.disarmRequested,
  });
}

/**
 * Clean up what a job left on the router and nothing else will remove.
 *
 * Two callers, one inventory:
 *  - after a FIRE: the restore removed the script and the scheduler (they were
 *    configuration) but NOT the backup blob (it is a file);
 *  - after a job that failed BEFORE ITS APPLY (`runSafeApply`): the blob kept
 *    for the dead-man and, if arming got that far, the scheduler and the
 *    script. Nothing was applied, so the net protects nothing — and a
 *    scheduler left behind would fire at its interval, load the blob and
 *    REBOOT a customer's router into the configuration it already had.
 *
 * Leaving the blob is leaving a copy of the customer's configuration on the
 * customer's router, so the failure is reported, never swallowed: `ok` is true
 * only when the blob is proven gone AND a re-read that COMPLETED shows neither
 * entry — every read on that path is strict, so a print that times out is a
 * problem reported, never an absence. The blob
 * is removed even when the entries could not be: without it, a surviving
 * scheduler can only fail to load and give up after its attempt budget
 * (`buildRollbackScriptSource`), instead of rebooting the box.
 *
 * NEVER call this on a job whose apply may have landed and that has not been
 * observed rolled back: there the net is the only thing between the customer
 * and an unverified change, and removing it is `disarmWithRetry`'s decision.
 */
export async function cleanupDeadmanArtefacts(
  session: DeviceSession,
  handle: string,
): Promise<{ ok: boolean; detail: string }> {
  const names = deadmanNamesFromHandle(handle);
  let entriesProblem: string | null = null;
  try {
    await removeDeadmanEntries(session, names);
    const after = await readDeadmanState(session, names, { strict: true });
    if (after.schedulerPresent || after.scriptPresent) {
      entriesProblem =
        `'${names.schedulerName}' / '${names.scriptName}' still present after removal`;
    }
  } catch (err) {
    logger.warn({ err, handle }, 'could not remove the dead-man entries during cleanup');
    entriesProblem = `the dead-man entries could not be removed: ${
      err instanceof Error ? err.message : String(err)
    }`;
  }
  const removal = await removeBackupFromDevice(session, names.backupFileName);
  const blob = removal.verified
    ? `${names.backupFileName} removed and verified absent`
    : `${names.backupFileName} could NOT be proven removed: ${removal.lastError ?? 'unknown'}`;
  return {
    ok: removal.verified && entriesProblem === null,
    detail: entriesProblem ? `${blob}; ${entriesProblem}` : blob,
  };
}

/** Re-exported so callers do not have to reach into transfer.service just to
 *  write an audit line about a fetch URL. */
export { redactTransferUrl };

/** Guard against a caller that hands us a handle we did not mint. */
export function assertOurHandle(handle: string): void {
  if (!/^obliwan-deadman-[A-Za-z0-9_-]{1,100}$/.test(handle)) {
    throw new ChangeError('BACKUP_FAILED', `'${handle}' is not an ObliWAN dead-man handle`);
  }
}
