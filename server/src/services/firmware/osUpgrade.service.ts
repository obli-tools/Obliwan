/**
 * ObliWAN — bring ONE RouterOS 7 device to a pinned RouterOS release, through
 * the change queue (nothing writes to a device outside `change_jobs`).
 *
 *   enqueueOsUpgradeJob(input)        the only door that creates the job
 *   previewOsUpgrade(...)             what the enqueue would decide, nothing written
 *   OsUpgradeRun                      the job's steps, called from `runPhases()`
 *                                     in services/change/apply.service.ts
 *   settleOsUpgrade(job, message)     the failure mirror, called from `failJob()`
 *
 * THE SEQUENCE (each line is a step row of the job):
 *
 *   bind_assert       `runPhases()` re-proves identity on a fresh socket
 *   guard             INDETERMINATE by construction, so the job carries a signed
 *                     override (`osUpgradeGuard`)
 *   lint              READ ONLY, on a socket whose identity is proved on the
 *                     socket itself (`openDeviceSession`): /system/resource
 *                     (version, architecture-name, free-hdd-space),
 *                     /system/package (every installed, enabled package) and
 *                     /file (no foreign .npk waiting for the next boot), then
 *                     the uplink verdict (`uplink.service`, see METERED
 *                     UPLINK below). The DECISION is made here: already at
 *                     or above the target -> a no-op `succeeded`; anything
 *                     that cannot be done safely -> refused, and NOTHING has
 *                     been written.
 *   preflight_backup  the pre-change backup, through the existing `takeDeviceBackup()` path. The
 *                     blob is pulled off, proven and erased: no dead-man loads
 *                     it, so it is not left on the router.
 *   arm_deadman       SKIPPED, and the step says why (OS_UPGRADE_NO_DEADMAN).
 *   apply             the router itself downloads the PINNED files with
 *                     `/tool/fetch` (one per installed package, all of the same
 *                     release — RouterOS disables a package whose version
 *                     differs from the system package), each file is checked
 *                     on the router (present, plausible size, the exact size
 *                     MikroTik's server announces when it announced one), the
 *                     kill switch is read one last time, then `/system/reboot`.
 *   cleanup           on a failure BEFORE the reboot, and when the box is
 *                     PROVEN not to have rebooted (`not_rebooted`, below): the
 *                     files this job fetched are removed and their absence
 *                     re-read, because a .npk left in the router's root is
 *                     INSTALLED at its next boot — a power cut, a technician
 *                     or a scheduled reboot would finish an upgrade long after
 *                     this job, its rollout and its gate are closed.
 *   reconnect         the session drop is expected. Bounded wait, then a fresh
 *                     `assertTargetBinding()`, then proof that the box ACTUALLY
 *                     rebooted (its reported uptime is shorter than the time
 *                     since the reboot command; a box that reports no readable
 *                     uptime is taken as back, and the step says so), so a
 *                     router still shutting down is never mistaken for one that
 *                     came back on the old version. `not_rebooted` needs the
 *                     LAST answer of the bound to be the old boot (a box that
 *                     answered on its old boot and then went silent may have
 *                     rebooted late and is `lost`); it is then a live,
 *                     identity-proved router, which is when removing the files
 *                     is both possible and verifiable.
 *   postcheck         the old version -> `rejected`; anything but the target ->
 *                     `incomplete`. Once the system package RUNS the target,
 *                     `devices.os_version` is rewritten to it
 *                     (`recordUpgradedOsVersion`, the one documented exception
 *                     to "a filled identity column is never overwritten") —
 *                     that is a fact the job proved — and the job SUCCEEDS
 *                     only if every fetched package followed, enabled.
 *   record_outcome    SKIPPED: `apply_outcomes` is the corpus of changes made
 *                     under a net (migration 047, header 2).
 *
 * ┌─ WHY THE ROUTER FETCHES, AND WHY THE URL IS PINNED ──────────────────────┐
 * │ `/system/package/update/install` installs whatever MikroTik calls newest  │
 * │ on the channel at that second; a canary wave and the wave after it could  │
 * │ then get two different releases. `/tool/fetch` of the exact URL that       │
 * │ `packageUrl(version, package, arch)` builds (shared/src/firmware.ts —      │
 * │ allow-listed version, package name and architecture, nothing else ever    │
 * │ reaches the string) pins the release. The CPEs in production reach the    │
 * │ Internet themselves. There is NO fallback that pushes the files from the  │
 * │ server (no SFTP/FTP upload path in this version): a router that cannot    │
 * │ download is refused, by name, before anything is installed.               │
 * │                                                                          │
 * │ Integrity: the fetch does not demand TLS certificate verification         │
 * │ (`check-certificate` keeps RouterOS's default) because many units carry   │
 * │ no trust anchors and would refuse every download. What protects the      │
 * │ install is RouterOS's own check of MikroTik's signature on every .npk at  │
 * │ boot: a tampered file is not installed, the box comes back on its old     │
 * │ release, and this job ends `rejected`. The size check is a plausibility   │
 * │ check against a truncated download, not a cryptographic one.             │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ NO DEAD-MAN, AND WHAT PROTECTS INSTEAD ─────────────────────────────────┐
 * │ The on-box dead-man is a scheduler script that restores a CONFIGURATION. │
 * │ It cannot un-install a RouterOS release, and a box that does not boot     │
 * │ back runs no script at all. So none is armed, the job is queued at        │
 * │ safety level `degraded` (the truth about its net), the safety-net rule's  │
 * │ explicit confirmation is required (migration 047), and the protection is  │
 * │ the rollout's: canary waves, a health gate between them, and a failed     │
 * │ gate STOPS the rollout — it does not "roll back" by restoring a          │
 * │ configuration backup, which would reboot the box once more and leave the  │
 * │ release exactly where it is.                                             │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ METERED UPLINK ─────────────────────────────────────────────────────────┐
 * │ The router downloads over whatever link carries its traffic: roughly 14  │
 * │ MB for `routeros` alone on arm64 7.24.5, plus every extra package. When   │
 * │ `assessUplink()` says the traffic is on a cellular interface the default │
 * │ route does NOT name (a failover in progress, or a route that could not   │
 * │ be read), the job is refused in `lint`, before any write: the download   │
 * │ would spend the customer's mobile data, and the reboot would hit a site  │
 * │ already running on its backup. A site whose configured route IS the      │
 * │ cellular interface (LTE-primary) is upgraded, and the `lint` step says   │
 * │ how much mobile data the download costs. No uplink evidence (no SNMP,    │
 * │ one sample) is not a refusal: absence of evidence of a failover is not   │
 * │ evidence of one, and the step says the uplink was not known.             │
 * │ A site DECLARED 4G-only (`sites.uplink_kind = 'cellular_only'`, 076) is  │
 * │ upgraded whatever its route says: cellular is its nominal path, not a    │
 * │ backup, and its mobile data is billed to the customer (operator,         │
 * │ 2026-10-06). The `lint` step still states what the download costs. A     │
 * │ declaration that was not read is "not declared", never 4G-only.          │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * WHEN THE WORKER DIES MID-JOB: the lease reaper (`reapExpiredLeases`,
 * jobQueue.service) FAILS an os_upgrade job past `claimed` with `worker_lost`
 * and settles its `os_upgrade_jobs` row, instead of leaving it "for human
 * inspection" like a push — a push has an on-box dead-man; this job has none,
 * and an untouched job would hold the device lock and its rollout for good.
 * Fetched files may then still be on the router: the next os_upgrade job's
 * `lint` refuses while a .npk sits in the root, so a retry never stacks on it.
 *
 * NEVER THE ROUTERBOARD FIRMWARE. No command in this file touches
 * `/system/routerboard`. MikroTik documents `auto-upgrade` as "Whether to
 * upgrade firmware automatically after RouterOS upgrade. The latest firmware
 * will be applied after an additional reboot" (help.mikrotik.com, RouterBOARD
 * documentation): a unit with it on rewrites its boot firmware during the
 * first boot on the new release, and RUNS that firmware only from the next
 * reboot, which this job neither sends nor waits for. The documentation does
 * not say that additional reboot happens by itself; nothing here has observed
 * it on hardware either way. That is the box's configuration, read nowhere and
 * changed nowhere here. Because a fresh session can still fail in the first
 * minutes of a boot (a tunnel renegotiating), `postcheck` retries its own
 * session open a bounded number of times rather than failing an upgrade that
 * has already happened.
 *
 * SECRETS: no credential is in any column, step, audit line or log this file
 * writes. The vault is read inside `openDeviceSession()` at dial time; the
 * commands carry public MikroTik URLs and file names only.
 */

import {
  ROUTEROS_DOWNLOAD_ORIGIN,
  SOCKET_EVENTS,
  compareRouterOsVersion,
  isRouterOsReleaseVersion,
  isSiteUplinkKind,
  parseRouterOsVersion,
  routerOsPackageArchFromResource,
  tryRouterOsPackageUrl,
  type RouterOsPackageArch,
  type SiteUplinkKind,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { emitToDevice } from '../fleet/fleetEvents';
import { emitToTenantAudience } from '../fleet/scopedEmit';
import {
  BindingAssertionError,
  assertTargetBinding,
  recordUpgradedOsVersion,
  type BindingAssertion,
} from '../fleet/deviceBinding.service';
import {
  ChangeError,
  openDeviceSession,
  takeDeviceBackup,
  type DeviceSession,
  type DialFn,
} from '../change/backup.service';
import {
  DeviceBusyError,
  LeaseLostError,
  renewLease,
  type ChangeJobRow,
} from '../change/jobQueue.service';
import { KillSwitchEngagedError, assertWritable, readKillSwitch } from '../change/killSwitch.service';
import { assessUplink, type UplinkVerdict } from '../fleet/uplink.service';
import { RouterOsTrapError } from '../transport/routeros';

// ============================================================================
// Vocabulary
// ============================================================================

export const OS_UPGRADE_KIND = 'os_upgrade' as const;

/** What the job concluded. Mirrors `os_upgrade_jobs_outcome_chk` (047). */
export const OS_UPGRADE_OUTCOMES = [
  'already_current', // at or above the target: nothing written, `succeeded`
  'upgraded',        // version == target after the reboot, every package with it
  'refused',         // stopped BEFORE any write
  'fetch_failed',    // a download did not land; fetched files removed (or the note says not)
  'not_rebooted',    // the reboot was sent and the box never restarted within the bound
  'rejected',        // the box rebooted and still runs its old release
  'incomplete',      // the box runs something, but not exactly the target with every package
  'lost',            // the box did not come back within the bound
  'identity_changed',// a box answered after the reboot, and it is not this device
  'failed',          // anything else after the first write
] as const;
export type OsUpgradeOutcome = (typeof OS_UPGRADE_OUTCOMES)[number];

/** The refusal of this service. apply.service turns it into a
 *  `ChangeRefusedError` with the same `kind`, so `error_kind` carries it. */
export class OsUpgradeError extends Error {
  constructor(readonly kind: string, message: string) {
    super(message);
    this.name = 'OsUpgradeError';
  }
}

export const OS_UPGRADE_NO_DEADMAN =
  "'os_upgrade' arms no dead-man: the on-box dead-man is a scheduler script that restores a " +
  'configuration, and it can neither un-install a RouterOS release nor run on a box that does ' +
  'not boot back. The job is queued at safety level degraded with an explicit confirmation; ' +
  "the protection is the rollout's canary waves and health gate.";

export const OS_UPGRADE_NO_APPLY_OUTCOME =
  "No row written to apply_outcomes: that corpus records changes made under a net, and its " +
  "outcomes (rolled_back, lost_contact) do not describe a RouterOS upgrade. This job's outcome " +
  'is on os_upgrade_jobs.';

/** The step text of the no-op ending, for the three skipped steps. */
export function osUpgradeNoopReason(current: string, target: string): string {
  return (
    `The router already runs RouterOS ${current}, which is at or above the target ${target}: ` +
    'nothing is fetched, nothing is rebooted and therefore nothing is backed up. This job never ' +
    'downgrades.'
  );
}

/**
 * The guard verdict for this kind: INDETERMINATE, by construction. The
 * Management-Path Guard simulates a PLAN against a forwarding model; an upgrade
 * carries no plan, and its hazard — a reboot into new code — is outside that
 * model. Pretending it accepted would be a green tick on a guess, so a signed
 * override is required, like every non-ACCEPT verdict (migration 009).
 */
export function osUpgradeGuard(): {
  verdict: 'INDETERMINATE';
  reasons: unknown[];
  summary: string;
  unavailable: false;
} {
  return {
    verdict: 'INDETERMINATE',
    reasons: [
      {
        code: 'OS_UPGRADE_OUTSIDE_MODEL',
        effect: 'indeterminate',
        message:
          'A RouterOS upgrade changes no forwarding rule the guard can simulate: its hazard is the ' +
          'reboot and the new release. The guard cannot prove the management path survives it, ' +
          'and does not pretend to.',
      },
    ],
    summary:
      "Management-Path Guard: INDETERMINATE — 'os_upgrade' is a reboot into a new release, " +
      'outside the forwarding model.',
    unavailable: false,
  };
}

/** The net this kind gets: none, said in the words the safety-net rule uses. */
export function osUpgradeSafetyNet(): {
  level: 'degraded';
  peerDeviceId: null;
  peerDeviceName: null;
  rationale: string;
  unverified: false;
  requiresConfirmation: true;
} {
  return {
    level: 'degraded',
    peerDeviceId: null,
    peerDeviceName: null,
    rationale:
      'DEGRADED — a RouterOS upgrade arms no dead-man: no scheduler script can un-install a ' +
      'release, and a router that does not boot back runs none. Detection WITHOUT recovery: if ' +
      'the router does not come back we will know, and repairing it means a visit (netinstall). ' +
      'an explicit, recorded confirmation is required.',
    unverified: false,
    requiresConfirmation: true,
  };
}

// ============================================================================
// Timings and dependencies (both injectable for the harness)
// ============================================================================

export interface OsUpgradeTimings {
  /** Budget of ONE `/tool/fetch` (one package) on the router. */
  fetchTimeoutMs: number;
  /** Budget for the reply to `/system/reboot` before the drop is assumed. */
  rebootAckTimeoutMs: number;
  /** Wait after the reboot command before the first probe. */
  firstProbeDelayMs: number;
  /** Between two probes. */
  probeIntervalMs: number;
  /** Total bound, from the reboot command, for the router to come back. */
  returnTimeoutMs: number;
  /** Connect budget of each probe. */
  probeConnectTimeoutMs: number;
  /** Budget of every print. */
  requestTimeoutMs: number;
}

/** A positive integer from the environment, or the default. Trimmed first:
 *  `Number(' ')` is 0, not NaN (a known trap). */
function envMs(name: string, fallback: number): number {
  const raw = process.env[name]?.trim();
  if (!raw || !/^[0-9]{1,10}$/.test(raw)) return fallback;
  const n = Number(raw);
  return n > 0 ? n : fallback;
}

function defaultTimings(): OsUpgradeTimings {
  return {
    fetchTimeoutMs: envMs('OBLIWAN_OS_UPGRADE_FETCH_TIMEOUT_MS', 15 * 60_000),
    rebootAckTimeoutMs: envMs('OBLIWAN_OS_UPGRADE_REBOOT_ACK_MS', 10_000),
    firstProbeDelayMs: envMs('OBLIWAN_OS_UPGRADE_FIRST_PROBE_MS', 60_000),
    probeIntervalMs: envMs('OBLIWAN_OS_UPGRADE_PROBE_INTERVAL_MS', 15_000),
    returnTimeoutMs: envMs('OBLIWAN_OS_UPGRADE_RETURN_TIMEOUT_MS', 20 * 60_000),
    probeConnectTimeoutMs: envMs('OBLIWAN_OS_UPGRADE_PROBE_CONNECT_MS', 8_000),
    requestTimeoutMs: envMs('OBLIWAN_OS_UPGRADE_REQUEST_TIMEOUT_MS', 30_000),
  };
}

let timings: OsUpgradeTimings = defaultTimings();

export function setOsUpgradeTimings(next: Partial<OsUpgradeTimings>): OsUpgradeTimings {
  timings = { ...timings, ...next };
  return timings;
}
export function resetOsUpgradeTimings(): void {
  timings = defaultTimings();
}

export interface OsUpgradeDeps {
  /** Returns the `device_backups.id` the job records. */
  takeBackup(args: {
    deviceId: number;
    jobId: number;
    correlationId: string;
    createdBy: number | null;
  }): Promise<{ backupId: number; summary: string }>;
  /** The byte size MikroTik's server announces for a package URL, or null
   *  when it announced none (or could not be asked). */
  packageSize(url: string): Promise<number | null>;
  /** The uplink verdict (`assessUplink`), read-only from the database. Null
   *  when it could not be formed; never a reason to refuse by itself. */
  uplink(tenantId: number, deviceId: number): Promise<UpgradeUplinkFacts | null>;
  /** Socket factory handed to `openDeviceSession` (test seam; production
   *  leaves it undefined and dials the device's transport row). */
  dial?: DialFn;
  sleep(ms: number): Promise<void>;
}

async function defaultTakeBackup(args: {
  deviceId: number;
  jobId: number;
  correlationId: string;
  createdBy: number | null;
}): Promise<{ backupId: number; summary: string }> {
  const set = await takeDeviceBackup({
    deviceId: args.deviceId,
    trigger: 'preflight',
    kinds: ['binary', 'rsc'],
    jobId: args.jobId,
    correlationId: args.correlationId,
    createdBy: args.createdBy,
    // NO `keepOnDeviceKinds`: nothing loads this blob unattended (no dead-man),
    // so it is pulled off, proven against our own disk and ERASED from the box.
  });
  if (!set.binary) {
    throw new OsUpgradeError(
      'backup_failed',
      'the router produced no binary backup; refusing to upgrade a box whose configuration ' +
        'nothing could restore.',
    );
  }
  const removed = set.artefacts.every((a) => a.onDeviceRemoved);
  return {
    backupId: set.binary.id,
    summary:
      `pre-change backup #${set.binary.id} stored (${set.artefacts.length} artefact(s)` +
      `${removed ? ', erased from the router' : ', NOT all proven erased from the router'})`,
  };
}

/** HEAD of a package URL. Only ever called with a URL `packageUrl` built, and
 *  refuses any other origin outright (no request input ever reaches here). */
export async function packageSizeOverHttps(url: string): Promise<number | null> {
  if (!url.startsWith(ROUTEROS_DOWNLOAD_ORIGIN)) return null;
  try {
    const res = await fetch(url, {
      method: 'HEAD',
      redirect: 'error',
      signal: AbortSignal.timeout(8_000),
    });
    if (res.status !== 200) return null;
    return parseByteCount(res.headers.get('content-length'));
  } catch {
    return null;
  }
}

/** The fields of `UplinkVerdict` the job decides on. */
export interface UpgradeUplinkFacts {
  /** The interface the routing configuration names, or null when unread. */
  configured: string | null;
  /** The interface actually carrying traffic, or null when unmeasured. */
  observed: string | null;
  /** True = the carrying interface is cellular. Null = not enough evidence. */
  onBackup: boolean | null;
  /** The site's declared access link (migration 076); null = not declared.
   *  'cellular_only' lets a download over the cellular link through (its data
   *  is billed to the customer); 'fixed' and null change nothing. */
  declared: SiteUplinkKind | null;
  reason: string;
}

/**
 * The verdict reduced to what the job decides on, PURE.
 *
 * `configured` is INTENT here and nothing else: `judgeUplink` reads
 * "configured === observed" on a cellular link as LTE-PRIMARY and allows the
 * download. A LIVE answer (the router's active route, migration 073) names the
 * cellular interface during every failover, so handing it over would wave
 * through exactly the case the refusal exists for.
 */
export function upgradeUplinkFacts(
  v: Pick<
    UplinkVerdict,
    'configured' | 'configuredSource' | 'observed' | 'onBackup' | 'declaredUplink' | 'reason'
  >,
): UpgradeUplinkFacts {
  return {
    configured: v.configuredSource === 'snapshot' ? v.configured : null,
    observed: v.observed,
    onBackup: v.onBackup,
    // Only a value of the vocabulary is a declaration; anything else is "not
    // declared" — never 4G-only by accident.
    declared: isSiteUplinkKind(v.declaredUplink) ? v.declaredUplink : null,
    reason: v.reason,
  };
}

async function defaultUplink(tenantId: number, deviceId: number): Promise<UpgradeUplinkFacts | null> {
  const v = await assessUplink(tenantId, deviceId);
  return v ? upgradeUplinkFacts(v) : null;
}

/**
 * What the uplink means for a download of `bytes`, PURE.
 *
 * Refused only on POSITIVE evidence: the traffic is on a cellular interface
 * and the default route does not name it (a failover in progress, or a route
 * nobody could read). LTE-primary (the route names the cellular interface) is
 * allowed with the cost stated; no evidence is allowed and said so. A site
 * DECLARED 4G-only is never refused for being on cellular — it is its nominal
 * path, and its data is billed to the customer — and the note states the cost.
 */
export function judgeUplink(
  facts: UpgradeUplinkFacts | null,
  bytes: number,
): { ok: true; note: string } | { ok: false; why: string } {
  const declared4g = facts?.declared === 'cellular_only';
  if (!facts || facts.onBackup === null) {
    return {
      ok: true,
      note: declared4g
        ? 'uplink not known (no SNMP rate yet), the site is declared 4G-only: this download ' +
          `spends about ${mib(bytes)} of mobile data`
        : 'uplink not known (no SNMP rate yet): the download link was not checked',
    };
  }
  if (facts.onBackup === false) {
    return { ok: true, note: `uplink ${facts.observed ?? '?'} (not cellular)` };
  }
  if (declared4g) {
    return {
      ok: true,
      note:
        `uplink ${facts.observed ?? '?'} is CELLULAR and the site is declared 4G-only (its nominal ` +
        `path, data billed to the customer): this download spends about ${mib(bytes)} of mobile data`,
    };
  }
  if (facts.observed !== null && facts.configured === facts.observed) {
    return {
      ok: true,
      note:
        `uplink ${facts.observed} is CELLULAR and is the configured route (LTE-primary site): this ` +
        `download spends about ${mib(bytes)} of mobile data`,
    };
  }
  return {
    ok: false,
    why:
      `the site's traffic is on the cellular interface ${facts.observed ?? '?'} while the default ` +
      `route ${facts.configured === null ? 'could not be read' : `names ${facts.configured}`}: the ` +
      `download (about ${mib(bytes)}) would spend the customer's mobile data, and the reboot would ` +
      'hit a site already running on its backup. Queue it again once the primary link carries the ' +
      'traffic. Nothing was written.',
  };
}

const DEFAULT_DEPS: OsUpgradeDeps = {
  takeBackup: defaultTakeBackup,
  packageSize: packageSizeOverHttps,
  uplink: defaultUplink,
  dial: undefined,
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
};
let deps: OsUpgradeDeps = { ...DEFAULT_DEPS };

export function setOsUpgradeDeps(next: Partial<OsUpgradeDeps>): OsUpgradeDeps {
  deps = { ...deps, ...next };
  return deps;
}
export function resetOsUpgradeDeps(): void {
  deps = { ...DEFAULT_DEPS };
}

// ============================================================================
// Pure helpers — exported so the harness can pin them
// ============================================================================

/** Margin kept free on top of the packages themselves. A heuristic, stated as
 *  one: RouterOS needs working room to unpack at boot. */
export const FREE_SPACE_MARGIN_BYTES = 2 * 1024 * 1024;
/** Assumed size of a package whose size MikroTik's server did not announce.
 *  Deliberately pessimistic (the arm64 system package of 7.24.5 is 13.9 MB):
 *  an unknown size is not a small one. */
export const UNKNOWN_PACKAGE_BYTES = 16 * 1024 * 1024;
/** Plausibility floors when no size was announced. */
export const MIN_PACKAGE_BYTES = 16 * 1024;
/** How many times `postcheck` opens a session and reads before it gives up. */
export const POSTCHECK_READ_ATTEMPTS = 3;
export const MIN_SYSTEM_PACKAGE_BYTES = 4 * 1024 * 1024;

/** `7.14.3 (stable)` -> `7.14.3`; null when no RouterOS version is there. */
export function cleanRouterOsVersion(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const head = raw.trim().split(/\s+/)[0] ?? '';
  return parseRouterOsVersion(head) ? head : null;
}

/** A byte count as RouterOS or HTTP writes it: digits only, trimmed. */
export function parseByteCount(raw: unknown): number | null {
  if (typeof raw !== 'string') return null;
  const v = raw.trim();
  if (!/^[0-9]{1,15}$/.test(v)) return null;
  return Number(v);
}

/**
 * RouterOS uptime in seconds: `1w2d3h4m5s`, `3h4m5s`, `45s`, and the older
 * `2d03:04:05` / `03:04:05` shapes. Null when it is neither.
 */
export function parseUptimeSeconds(raw: unknown): number | null {
  if (typeof raw !== 'string') return null;
  const v = raw.trim();
  if (!v) return null;
  const units = /^(?:([0-9]+)w)?(?:([0-9]+)d)?(?:([0-9]+)h)?(?:([0-9]+)m)?(?:([0-9]+)s)?$/.exec(v);
  if (units && units.slice(1).some((g) => g !== undefined)) {
    const [w, d, h, m, s] = units.slice(1).map((g) => (g === undefined ? 0 : Number(g)));
    return (((w * 7 + d) * 24 + h) * 60 + m) * 60 + s;
  }
  const clock = /^(?:([0-9]+)w)?(?:([0-9]+)d)?([0-9]{1,2}):([0-9]{2}):([0-9]{2})$/.exec(v);
  if (clock) {
    const [w, d, h, m, s] = clock.slice(1).map((g) => (g === undefined ? 0 : Number(g)));
    return (((w * 7 + d) * 24 + h) * 60 + m) * 60 + s;
  }
  return null;
}

export interface InstalledPackage {
  name: string;
  version: string | null;
  disabled: boolean;
  scheduled: string | null;
}

/** `/system/package/print` rows -> the installed packages. A row the router
 *  lists as merely `available` is not installed and is left out. */
export function parsePackages(rows: Array<Record<string, string>>): InstalledPackage[] {
  const out: InstalledPackage[] = [];
  for (const r of rows) {
    const name = (r.name ?? '').trim();
    if (!name) continue;
    if ((r.available ?? '').trim() === 'true') continue;
    const scheduled = (r.scheduled ?? '').trim();
    out.push({
      name,
      version: cleanRouterOsVersion(r.version ?? ''),
      disabled: (r.disabled ?? '').trim() === 'true',
      scheduled: scheduled ? scheduled : null,
    });
  }
  return out;
}

export interface PlannedPackage {
  name: string;
  url: string;
  /** The file name on the router: the URL's last segment. */
  fileName: string;
  /** What MikroTik's server announced; null when it announced nothing. */
  expectedBytes: number | null;
}

export interface UpgradeFacts {
  version: string | null;
  architectureName: string | null;
  freeBytes: number | null;
  packages: InstalledPackage[];
  /** `.npk` files sitting in the router's root, i.e. waiting for the next boot. */
  pendingNpkFiles: string[];
}

export type UpgradeDecision =
  | { action: 'noop'; current: string }
  | {
    action: 'upgrade';
    current: string;
    arch: RouterOsPackageArch;
    packages: Array<{ name: string; url: string; fileName: string }>;
  }
  | { action: 'refuse'; kind: string; message: string; current: string | null };

/**
 * The decision, made on what the router said and nothing else. Pure: the
 * sizes (which need the network) are judged afterwards by `judgeSpace`.
 */
export function decideUpgrade(facts: UpgradeFacts, target: string): UpgradeDecision {
  const current = facts.version;
  if (!current) {
    return {
      action: 'refuse',
      kind: 'version_unreadable',
      message: 'the router did not report a RouterOS version this job can compare. Nothing was written.',
      current: null,
    };
  }
  if (compareRouterOsVersion(current, target) >= 0) return { action: 'noop', current };

  const from = parseRouterOsVersion(current)!;
  const to = parseRouterOsVersion(target)!;
  if (from.major !== to.major) {
    return {
      action: 'refuse',
      kind: 'cross_major',
      message:
        `the router runs RouterOS ${current} and the target is ${target}: crossing a major ` +
        'version converts the configuration and changes the device family, and is not this job. ' +
        'Plan it as its own operation. Nothing was written.',
      current,
    };
  }
  const arch = routerOsPackageArchFromResource(facts.architectureName);
  if (!arch) {
    return {
      action: 'refuse',
      kind: 'architecture_unsupported',
      message:
        'the router reported an architecture outside the allow-list, so no package URL is built ' +
        'for it. Nothing was written.',
      current,
    };
  }
  const scheduled = facts.packages.filter((p) => p.scheduled !== null);
  if (scheduled.length > 0) {
    return {
      action: 'refuse',
      kind: 'package_action_scheduled',
      message:
        `a package action is already scheduled for the next boot on this router ` +
        `(${scheduled.map((p) => `${p.name}: ${p.scheduled}`).join(', ')}). It would run together ` +
        'with this upgrade; resolve it first. Nothing was written.',
      current,
    };
  }
  if (facts.pendingNpkFiles.length > 0) {
    return {
      action: 'refuse',
      kind: 'foreign_package_file',
      message:
        `${facts.pendingNpkFiles.length} .npk file(s) already sit in the router's root ` +
        `(${facts.pendingNpkFiles.join(', ')}) and would be installed at the reboot alongside ` +
        'this release. Remove them, or find out who put them there. Nothing was written.',
      current,
    };
  }
  const enabled = facts.packages.filter((p) => !p.disabled);
  if (!enabled.some((p) => p.name === 'routeros')) {
    return {
      action: 'refuse',
      kind: 'no_system_package',
      message:
        "the router lists no enabled 'routeros' package, which every RouterOS 7 system has. " +
        'Refusing to guess what to upgrade. Nothing was written.',
      current,
    };
  }
  const ordered = [...enabled].sort((a, b) =>
    a.name === 'routeros' ? -1 : b.name === 'routeros' ? 1 : a.name.localeCompare(b.name),
  );
  const packages: Array<{ name: string; url: string; fileName: string }> = [];
  for (const p of ordered) {
    const built = tryRouterOsPackageUrl(target, p.name, arch);
    if (!built.ok) {
      return {
        action: 'refuse',
        kind: 'package_url_refused',
        message:
          `no download URL can be built for installed package '${p.name.slice(0, 40)}' ` +
          `(${built.code}: ${built.reason}). Every installed package must be upgraded together, ` +
          'or RouterOS disables the one left behind. Nothing was written.',
        current,
      };
    }
    packages.push({ name: p.name, url: built.url, fileName: built.url.slice(built.url.lastIndexOf('/') + 1) });
  }
  return { action: 'upgrade', current, arch, packages };
}

/** Free space versus what the files need. */
export function judgeSpace(
  freeBytes: number | null,
  packages: ReadonlyArray<{ expectedBytes: number | null }>,
): { ok: boolean; requiredBytes: number; assumedCount: number } {
  const assumedCount = packages.filter((p) => p.expectedBytes === null).length;
  const requiredBytes =
    packages.reduce((sum, p) => sum + (p.expectedBytes ?? UNKNOWN_PACKAGE_BYTES), 0) +
    FREE_SPACE_MARGIN_BYTES;
  return { ok: freeBytes !== null && freeBytes >= requiredBytes, requiredBytes, assumedCount };
}

/** Is this file, as the router lists it, plausibly the package we asked for? */
export function judgeLandedFile(
  pkg: PlannedPackage,
  sizeBytes: number | null,
): { ok: true } | { ok: false; why: string } {
  if (sizeBytes === null) return { ok: false, why: 'the router reports no size for it' };
  if (pkg.expectedBytes !== null) {
    return sizeBytes === pkg.expectedBytes
      ? { ok: true }
      : {
        ok: false,
        why: `it is ${sizeBytes} bytes on the router and MikroTik's server announced ${pkg.expectedBytes}`,
      };
  }
  const floor = pkg.name === 'routeros' ? MIN_SYSTEM_PACKAGE_BYTES : MIN_PACKAGE_BYTES;
  return sizeBytes >= floor
    ? { ok: true }
    : { ok: false, why: `it is only ${sizeBytes} bytes, below the ${floor}-byte floor for this package` };
}

function mib(bytes: number): string {
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

// ============================================================================
// Rows
// ============================================================================

interface DeviceRow {
  id: number;
  uuid: string;
  tenant_id: number;
  name: string;
  brand: string;
  family: string;
  role: string | null;
  status: string;
  is_managed: boolean;
  os_version: string | null;
  device_mode_fetch: boolean | null;
}

async function loadDevice(tenantId: number, deviceId: number): Promise<DeviceRow | null> {
  const row = (await db('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first(
      'id', 'uuid', 'tenant_id', 'name', 'brand', 'family', 'role', 'status', 'is_managed',
      'os_version', 'device_mode_fetch',
    )) as DeviceRow | undefined;
  return row ?? null;
}

export interface OsUpgradeJobRow {
  job_id: number;
  tenant_id: number;
  target_version: string;
  from_version: string | null;
  architecture: string | null;
  packages: unknown;
  free_bytes: string | number | null;
  preflight_backup_id: string | number | null;
  fetched_at: Date | null;
  rebooted_at: Date | null;
  returned_at: Date | null;
  observed_version: string | null;
  outcome: OsUpgradeOutcome | null;
  outcome_detail: string | null;
  created_at: Date;
  updated_at: Date;
}

/** One job's upgrade record, tenant-scoped. No credential column exists. */
export async function getOsUpgradeJob(tenantId: number, jobId: number): Promise<OsUpgradeJobRow | null> {
  const row = (await db('os_upgrade_jobs')
    .where({ job_id: jobId, tenant_id: tenantId })
    .first('*')) as OsUpgradeJobRow | undefined;
  return row ?? null;
}

async function patchJob(jobId: number, patch: Record<string, unknown>): Promise<void> {
  await db('os_upgrade_jobs').where({ job_id: jobId }).update({ ...patch, updated_at: db.fn.now() });
}

/** Record the outcome once; a later, vaguer settle never overwrites it. */
async function recordOutcome(jobId: number, outcome: OsUpgradeOutcome, detail: string): Promise<void> {
  await db('os_upgrade_jobs')
    .where({ job_id: jobId })
    .whereNull('outcome')
    .update({ outcome, outcome_detail: detail.slice(0, 4000), updated_at: db.fn.now() });
}

/**
 * The failure mirror, called by `failJob()` for every failure of this kind —
 * including the ones before its branch (bind_assert, kill switch, guard).
 * An outcome already recorded by the step that failed is kept. Never throws.
 */
export async function settleOsUpgrade(job: Pick<ChangeJobRow, 'id'>, message: string): Promise<void> {
  try {
    const row = (await db('os_upgrade_jobs')
      .where({ job_id: Number(job.id) })
      .first('fetched_at', 'outcome')) as { fetched_at: Date | null; outcome: string | null } | undefined;
    if (!row || row.outcome !== null) return;
    await recordOutcome(Number(job.id), row.fetched_at === null ? 'refused' : 'failed', message);
  } catch (err) {
    logger.error({ err, jobId: Number(job.id) }, 'os_upgrade: could not record the failure outcome');
  }
}

// ============================================================================
// Enqueue — the only door that creates an os_upgrade job
// ============================================================================

/** Same convention as apply.service: a plan-less job records no base state. */
const NO_BASE_STATE = '0'.repeat(64);

export interface EnqueueOsUpgradeInput {
  tenantId: number;
  deviceId: number;
  /** A RouterOS 7 RELEASE (`7.24.5`), never a pre-release. */
  targetVersion: string;
  requestedBy: number | null;
  /** The guard is INDETERMINATE by construction: a signed override is required. */
  override: { reason: string; userId: number | null } | null;
  /** The job has no net, so the explicit confirmation is required. */
  confirmDegraded: { userId: number | null } | null;
  scheduledFor?: Date | null;
  windowStart?: Date | null;
  windowEnd?: Date | null;
}

export interface EnqueueOsUpgradeResult {
  jobId: number;
  guard: ReturnType<typeof osUpgradeGuard>;
  safetyNet: ReturnType<typeof osUpgradeSafetyNet>;
}

/** Null when `targetVersion` is a RouterOS 7 release; the refusal otherwise. */
export function osUpgradeTargetProblem(targetVersion: unknown): { kind: string; message: string } | null {
  if (!isRouterOsReleaseVersion(targetVersion) || parseRouterOsVersion(targetVersion)!.major !== 7) {
    return {
      kind: 'target_invalid',
      message: 'the target must be a RouterOS 7 release such as 7.24.5 (never a release candidate).',
    };
  }
  return null;
}

/** The inventory facts the device-level refusals read. */
export interface OsUpgradeDeviceFacts {
  name: string;
  brand: string;
  family: string;
  role: string | null | undefined;
  status: string;
  is_managed: boolean;
}

/** Every reason the enqueue would refuse this device, as `{ kind, message }`. */
function enqueueRefusals(device: DeviceRow | null, deviceId: number, targetVersion: string): Array<{
  kind: string;
  message: string;
}> {
  const out: Array<{ kind: string; message: string }> = [];
  const target = osUpgradeTargetProblem(targetVersion);
  if (target) out.push(target);
  if (!device) {
    out.push({ kind: 'device_not_found', message: `Device ${deviceId} not found.` });
    return out;
  }
  return [...out, ...osUpgradeDeviceRefusals(device)];
}

/** Every reason this DEVICE cannot get an os_upgrade job, whatever the target.
 *  Exported for the rollout composition, which lists them per device. */
export function osUpgradeDeviceRefusals(device: OsUpgradeDeviceFacts): Array<{
  kind: string;
  message: string;
}> {
  const out: Array<{ kind: string; message: string }> = [];
  if (device.status === 'disabled' || device.status === 'quarantined') {
    out.push({
      kind: 'device_not_writable',
      message: `Device ${device.name} is '${device.status}'. No job may be queued against it.`,
    });
  }
  if (!device.is_managed) {
    out.push({ kind: 'device_not_managed', message: `Device ${device.name} is not managed.` });
  }
  if (device.brand !== 'mikrotik') {
    out.push({
      kind: 'brand_unsupported',
      message:
        `Device ${device.name} is a ${device.brand}: os_upgrade installs RouterOS packages and ` +
        'serves MikroTik only.',
    });
  } else if (device.family !== 'mikrotik_routeros7') {
    out.push({
      kind: 'cross_major',
      message:
        `Device ${device.name} is recorded as '${device.family}': only RouterOS 7 is upgraded by ` +
        'this job (a 6 -> 7 upgrade converts the configuration and is not this job).',
    });
  }
  if (device.role === 'concentrator') {
    out.push({
      kind: 'concentrator_refused',
      message:
        `Device ${device.name} is a concentrator. Its reboot drops every site's tunnel at once, ` +
        'and if it does not come back ObliWAN loses the whole fleet behind it: upgrade it by hand, ' +
        'with console access, not through this job.',
    });
  }
  return out;
}

/** What `enqueueOsUpgradeJob` would decide, with nothing written. */
export async function previewOsUpgrade(input: {
  tenantId: number;
  deviceId: number;
  targetVersion: string;
}): Promise<{
  device: { id: number; name: string; brand: string; family: string; osVersion: string | null } | null;
  targetVersion: string;
  guard: ReturnType<typeof osUpgradeGuard>;
  safetyNet: ReturnType<typeof osUpgradeSafetyNet>;
  killSwitch: Awaited<ReturnType<typeof readKillSwitch>>;
  refusals: Array<{ kind: string; message: string }>;
  /** From the RECORDED os_version, which may be stale; the job decides on what
   *  the router says. Null when nothing is recorded or it is unreadable. */
  recordedAtOrAboveTarget: boolean | null;
  requiresOverride: true;
  requiresDegradedConfirmation: true;
}> {
  const device = await loadDevice(input.tenantId, input.deviceId);
  const recorded = cleanRouterOsVersion(device?.os_version ?? null);
  let recordedAtOrAboveTarget: boolean | null = null;
  if (recorded && isRouterOsReleaseVersion(input.targetVersion)) {
    recordedAtOrAboveTarget = compareRouterOsVersion(recorded, input.targetVersion) >= 0;
  }
  return {
    device: device
      ? { id: device.id, name: device.name, brand: device.brand, family: device.family, osVersion: device.os_version }
      : null,
    targetVersion: input.targetVersion,
    guard: osUpgradeGuard(),
    safetyNet: osUpgradeSafetyNet(),
    killSwitch: await readKillSwitch(input.tenantId),
    refusals: enqueueRefusals(device, input.deviceId, input.targetVersion),
    recordedAtOrAboveTarget,
    requiresOverride: true,
    requiresDegradedConfirmation: true,
  };
}

/**
 * Create one os_upgrade job and its `os_upgrade_jobs` row in ONE transaction,
 * so no worker can ever claim a job whose target it cannot read.
 *
 * The one-job-per-device rule is the index `change_jobs_one_in_flight_uq`; its
 * 23505 becomes a `DeviceBusyError`, exactly as in `enqueueChangeJob`. The
 * The subtree interlock's 23001 becomes `OsUpgradeError('subtree_interlock')`.
 */
export async function enqueueOsUpgradeJob(input: EnqueueOsUpgradeInput): Promise<EnqueueOsUpgradeResult> {
  const killSwitch = await readKillSwitch(input.tenantId);
  if (killSwitch.blocked) throw new KillSwitchEngagedError(killSwitch);

  const device = await loadDevice(input.tenantId, input.deviceId);
  const refusals = enqueueRefusals(device, input.deviceId, input.targetVersion);
  if (refusals.length > 0 || !device) {
    const first = refusals[0] ?? { kind: 'device_not_found', message: `Device ${input.deviceId} not found.` };
    throw new OsUpgradeError(first.kind, refusals.map((r) => r.message).join(' '));
  }

  const guard = osUpgradeGuard();
  const safetyNet = osUpgradeSafetyNet();
  const reason = input.override?.reason?.trim() ?? '';
  if (!input.override || !reason) {
    throw new OsUpgradeError(
      'guard_refused',
      `${guard.summary} Upgrading requires an explicit override with a written reason ` +
        '(capability CHANGE_APPROVE), recorded against your name.',
    );
  }
  if (!input.confirmDegraded) {
    throw new OsUpgradeError(
      'degraded_unconfirmed',
      `${safetyNet.rationale} This job needs an explicit confirmation before it can be queued.`,
    );
  }

  const now = new Date();
  let jobId: number;
  try {
    jobId = await db.transaction(async (trx) => {
      const inserted = (await trx('change_jobs')
        .insert({
          tenant_id: input.tenantId,
          device_id: device.id,
          plan_id: null,
          kind: OS_UPGRADE_KIND,
          status: 'queued',
          attempt: 0,
          // A reboot into new code is not retried silently.
          max_attempts: 1,
          // Plan-less: the job decides on what the router says at run time.
          base_state_hash: NO_BASE_STATE,
          safety_level: safetyNet.level,
          safety_peer_device_id: null,
          guard_verdict: guard.verdict,
          guard_reasons: JSON.stringify(guard.reasons),
          override_reason: reason,
          overridden_by: input.override!.userId,
          overridden_at: now,
          degraded_confirmed_by: input.confirmDegraded!.userId,
          degraded_confirmed_at: now,
          scheduled_for: input.scheduledFor ?? null,
          window_start: input.windowStart ?? null,
          window_end: input.windowEnd ?? null,
          requested_by: input.requestedBy,
        })
        .returning('id')) as Array<{ id: string | number }>;
      const id = Number(inserted[0].id);
      await trx('os_upgrade_jobs').insert({
        job_id: id,
        tenant_id: input.tenantId,
        target_version: input.targetVersion,
      });
      return id;
    });
  } catch (err) {
    const pg = err as { code?: string; constraint?: string };
    if (pg.code === '23505' && pg.constraint === 'change_jobs_one_in_flight_uq') {
      throw new DeviceBusyError(device.id);
    }
    // The subtree interlock (`change_jobs_subtree_interlock()`, 010/040) does not
    // make this job WAIT: it refuses the INSERT while a job is in flight on
    // this device's concentrator. Named, so the caller is told to retry later
    // rather than handed a 500.
    if (pg.code === '23001' && /subtree interlock/i.test(errText(err))) {
      throw new OsUpgradeError(
        'subtree_interlock',
        `a job is in flight on the concentrator that carries this device's tunnel, and the subtree interlock ` +
          'refuses a job on a device while its concentrator is being written to. Nothing was ' +
          `queued; queue it again once that job has ended. (${errText(err).slice(0, 300)})`,
      );
    }
    throw err;
  }

  logger.warn(
    {
      jobId,
      deviceId: device.id,
      kind: OS_UPGRADE_KIND,
      targetVersion: input.targetVersion,
      recordedVersion: device.os_version,
      requestedBy: input.requestedBy,
    },
    'os_upgrade job QUEUED — a RouterOS upgrade of a customer equipment has been authorised',
  );
  const summary = { jobId, deviceId: device.id, kind: OS_UPGRADE_KIND, status: 'queued' };
  emitToTenantAudience(input.tenantId, SOCKET_EVENTS.JOB_QUEUED, summary, { deviceId: device.id });
  emitToDevice(device.id, SOCKET_EVENTS.JOB_QUEUED, summary);
  return { jobId, guard, safetyNet };
}

// ============================================================================
// The health gate and the ONE reboot this job asked for
// ============================================================================

/**
 * Tolerance between the instant the job saw the box back (`returned_at`, the
 * API answering) and the instant the SNMP agent's uptime counts from: the
 * agent may start a little after the API on the same boot.
 */
export const UPGRADE_BOOT_SLACK_MS = 120_000;

/**
 * The smallest sysUpTime (TimeTicks, 1/100 s) a sample taken at `sampleAt` may
 * report if the box booted ONCE, before the job saw it back at `returnedAt`.
 * A smaller value is a boot AFTER the return — a crash, a watchdog — and that
 * is still an UNEXPECTED_BOOT. PURE.
 */
export function upgradeUptimeFloorTicks(
  returnedAt: Date,
  sampleAt: Date,
  slackMs: number = UPGRADE_BOOT_SLACK_MS,
): number {
  return Math.max(0, Math.floor((sampleAt.getTime() - returnedAt.getTime() - slackMs) / 10));
}

export interface UpgradeBootRebase {
  /** The uptime floor that replaced the pre-wave baseline uptime. */
  floorTicks: number;
  returnedAt: Date;
  sampleAt: Date;
}

/**
 * The health gate's `UNEXPECTED_BOOT` compares the latest sysUpTime with the
 * one captured BEFORE the wave. For an os_upgrade wave the reboot is the point
 * of the job, so that comparison would fail every wave that worked. This
 * returns the baseline to judge the device against instead: identical, except
 * that `uptimeTicks` is the floor of a box that booted once before the job saw
 * it back (`upgradeUptimeFloorTicks`), so a SECOND boot still fails the gate.
 *
 * Null (keep the baseline as captured) when the job never saw the box back
 * from a reboot (a no-op, a refusal, lost: any boot then is unexpected), or
 * when no device sample since the baseline postdates that return (the latest
 * sample then shows no boot at all). Read-only, tenant-scoped.
 */
export async function rebaseBaselineForUpgradeBoot<B extends { capturedAt: string; uptimeTicks: number | null }>(
  tenantId: number,
  deviceId: number,
  jobId: number | null,
  baseline: B | null,
): Promise<{ baseline: B; rebase: UpgradeBootRebase } | null> {
  if (jobId === null || !baseline || baseline.uptimeTicks === null) return null;
  const job = (await db('os_upgrade_jobs as u')
    .join('change_jobs as j', 'j.id', 'u.job_id')
    .where({ 'u.job_id': jobId, 'u.tenant_id': tenantId, 'j.device_id': deviceId })
    .first('u.returned_at')) as { returned_at: Date | null } | undefined;
  if (!job?.returned_at) return null;
  const sample = (await db('snmp_device_samples')
    .where({ device_id: deviceId })
    .where('ts', '>=', new Date(baseline.capturedAt))
    .orderBy('ts', 'desc')
    .first('ts')) as { ts: Date } | undefined;
  if (!sample) return null;
  const returnedAt = new Date(job.returned_at);
  const sampleAt = new Date(sample.ts);
  if (sampleAt.getTime() < returnedAt.getTime()) return null;
  const floorTicks = upgradeUptimeFloorTicks(returnedAt, sampleAt);
  return { baseline: { ...baseline, uptimeTicks: floorTicks }, rebase: { floorTicks, returnedAt, sampleAt } };
}

/** The gate's own sentence is about a boot nobody asked for; on an os_upgrade
 *  wave the one that remains is a boot AFTER the upgrade's own. */
export function upgradeSecondBootMessage(rebase: UpgradeBootRebase, afterTicks: number | null): string {
  return (
    `the router booted AGAIN after this upgrade's own reboot: at ${rebase.sampleAt.toISOString()} ` +
    `it reported ${afterTicks === null ? 'an unreadable' : Math.round(afterTicks / 100) + ' s of'} ` +
    `uptime, and a box that booted once before the job saw it back (${rebase.returnedAt.toISOString()}) ` +
    `would report at least ${Math.round(rebase.floorTicks / 100)} s. A crash or a watchdog reset on ` +
    'the new release is the likely reading.'
  );
}

// ============================================================================
// The run — one object per job, its steps called by apply.service in order
// ============================================================================

export interface OsUpgradeStepResult {
  output: string;
  detail: Record<string, unknown>;
}

export interface OsUpgradeRunContext {
  job: ChangeJobRow;
  device: { id: number; tenant_id: number; name?: string | null };
  correlationId: string;
  workerId: string;
}

/** Renews the lease while one long command (a download) is in flight. */
function keepLease(jobId: number, workerId: string): { lost: () => boolean; stop: () => void } {
  let lost = false;
  const timer = setInterval(() => {
    void renewLease(jobId, workerId)
      .then((ok) => {
        if (!ok) lost = true;
      })
      .catch(() => undefined);
  }, 30_000);
  timer.unref?.();
  return { lost: () => lost, stop: () => clearInterval(timer) };
}

function errText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export class OsUpgradeRun {
  private readonly jobId: number;
  private target = '';
  private from: string | null = null;
  private plan: PlannedPackage[] = [];
  private noop = false;
  /** Files this job asked the router to write and has not proven gone. */
  private readonly pendingFiles = new Set<string>();
  private rebootSentAt: number | null = null;
  /** The reboot was sent and the LAST answer of the bound was the old boot. */
  private provenNotRebooted = false;
  private returnProof: BindingAssertion | null = null;
  /** Appended to the job's error when the cleanup left something behind. */
  leftoverNote = '';

  constructor(private readonly ctx: OsUpgradeRunContext) {
    this.jobId = Number(ctx.job.id);
  }

  get isNoop(): boolean {
    return this.noop;
  }
  get currentVersion(): string | null {
    return this.from;
  }
  get targetVersion(): string {
    return this.target;
  }
  /** True when files may sit on the router and nothing installed them: the
   *  reboot was not sent, or the box was proven still on its old boot. */
  get needsCleanup(): boolean {
    return (this.rebootSentAt === null || this.provenNotRebooted) && this.pendingFiles.size > 0;
  }

  private async session(purpose: string): Promise<DeviceSession> {
    try {
      return await openDeviceSession(this.ctx.device.id, {
        purpose: `os_upgrade:${purpose}`,
        jobId: this.jobId,
        correlationId: this.ctx.correlationId,
        requestTimeoutMs: timings.requestTimeoutMs,
        dial: deps.dial,
      });
    } catch (err) {
      if (err instanceof ChangeError) {
        // `IDENTITY_MISMATCH` covers both "the box contradicts the record" and
        // "the identity could not be read"; only the first is a different box.
        const checks = Array.isArray(err.detail.checks)
          ? (err.detail.checks as Array<{ outcome?: string }>)
          : [];
        const contradicts = checks.some((c) => c.outcome === 'mismatch');
        const kind = err.kind === 'IDENTITY_MISMATCH'
          ? (contradicts ? 'identity_mismatch' : 'identity_unproven')
          : err.kind.toLowerCase();
        throw new OsUpgradeError(kind, err.message);
      }
      throw err;
    }
  }

  private async assertLeaseHeld(): Promise<void> {
    if (!(await renewLease(this.jobId, this.ctx.workerId))) throw new LeaseLostError(this.jobId);
  }

  /** Sleep in slices, renewing the lease, so a long wait never loses the job. */
  private async waitWithLease(ms: number): Promise<void> {
    let remaining = ms;
    while (remaining > 0) {
      const slice = Math.min(remaining, 15_000);
      await deps.sleep(slice);
      remaining -= slice;
      await this.assertLeaseHeld();
    }
  }

  private async refuse(kind: string, message: string, outcome: OsUpgradeOutcome): Promise<never> {
    await recordOutcome(this.jobId, outcome, message);
    throw new OsUpgradeError(kind, message);
  }

  // ── lint: read, decide, write nothing ─────────────────────────────────────
  async inspect(): Promise<OsUpgradeStepResult> {
    const spec = (await db('os_upgrade_jobs')
      .where({ job_id: this.jobId, tenant_id: this.ctx.job.tenant_id })
      .first('target_version')) as { target_version: string } | undefined;
    if (!spec) {
      throw new OsUpgradeError(
        'upgrade_spec_missing',
        `job ${this.jobId} has no os_upgrade_jobs row, so it has no target version. Nothing was written.`,
      );
    }
    this.target = spec.target_version;

    const device = await loadDevice(this.ctx.job.tenant_id, this.ctx.device.id);
    if (!device) throw new OsUpgradeError('device_not_found', `Device ${this.ctx.device.id} not found.`);
    if (device.brand !== 'mikrotik') {
      return this.refuse('brand_unsupported', `os_upgrade serves MikroTik only; this is a ${device.brand}.`, 'refused');
    }
    if (device.role === 'concentrator') {
      return this.refuse(
        'concentrator_refused',
        'this device is a concentrator: its reboot drops every tunnel at once. Upgrade it by hand.',
        'refused',
      );
    }
    // Recorded denial, before any socket: authoritative (deviceMode.ts reads a
    // DENIAL as a fact). An unread flag is not a permission — the fetch itself
    // will answer, and its refusal is handled below.
    if (device.device_mode_fetch === false) {
      return this.refuse(
        'device_mode_refused',
        "this router's /system/device-mode DENIES /tool/fetch, so it cannot download its packages. " +
          'Re-enabling it needs physical access: `/system/device-mode/update fetch=yes`, then the ' +
          'reset button or a cold power cycle within five minutes. Nothing was written.',
        'refused',
      );
    }

    const session = await this.session('inspect');
    let facts: UpgradeFacts;
    let uptime: number | null;
    try {
      const resource = (await session.run(['/system/resource/print'], { isWrite: false }))[0] ?? {};
      const packages = parsePackages(
        await session.run(
          ['/system/package/print', '=.proplist=name,version,disabled,scheduled,available'],
          { isWrite: false },
        ),
      );
      const files = await session.run(['/file/print', '=.proplist=name,type'], { isWrite: false });
      facts = {
        version: cleanRouterOsVersion(resource.version),
        architectureName: (resource['architecture-name'] ?? '').trim() || null,
        freeBytes: parseByteCount(resource['free-hdd-space']),
        packages,
        // Root only: a `.npk` under a sub-directory is not installed at boot.
        pendingNpkFiles: files
          .map((f) => (f.name ?? '').trim())
          .filter((n) => n && !n.includes('/') && n.toLowerCase().endsWith('.npk')),
      };
      uptime = parseUptimeSeconds(resource.uptime);
    } finally {
      session.close();
    }
    this.from = facts.version;

    const decision = decideUpgrade(facts, this.target);
    await patchJob(this.jobId, {
      from_version: facts.version,
      architecture: decision.action === 'upgrade' ? decision.arch : null,
      free_bytes: facts.freeBytes,
    });

    if (decision.action === 'noop') {
      this.noop = true;
      const why = osUpgradeNoopReason(decision.current, this.target);
      await recordOutcome(this.jobId, 'already_current', why);
      return {
        output: why,
        detail: { action: 'noop', current: decision.current, target: this.target },
      };
    }
    if (decision.action === 'refuse') {
      return this.refuse(decision.kind, decision.message, 'refused');
    }

    // Sizes: what MikroTik's server announces for each pinned URL.
    const sizes = await Promise.all(decision.packages.map((p) => deps.packageSize(p.url).catch(() => null)));
    this.plan = decision.packages.map((p, i) => ({ ...p, expectedBytes: sizes[i] ?? null }));
    await patchJob(this.jobId, { packages: JSON.stringify(this.plan) });

    const space = judgeSpace(facts.freeBytes, this.plan);
    if (!space.ok) {
      return this.refuse(
        'insufficient_space',
        `the router has ${facts.freeBytes === null ? 'an unreadable amount of' : mib(facts.freeBytes)} ` +
          `free storage and the ${this.plan.length} package(s) of ${this.target} need ` +
          `${mib(space.requiredBytes)}` +
          (space.assumedCount > 0
            ? ` (${space.assumedCount} size(s) not announced by MikroTik's server, assumed ` +
              `${mib(UNKNOWN_PACKAGE_BYTES)} each)`
            : '') +
          '. Free some space (old files, an unused package) and queue it again. Nothing was written.',
        'refused',
      );
    }

    // The link the router will download over (header, METERED UPLINK). Read
    // from the database only; a failure to form a verdict is "not known".
    const downloadBytes = this.plan.reduce((n, p) => n + (p.expectedBytes ?? UNKNOWN_PACKAGE_BYTES), 0);
    const uplinkFacts = await deps
      .uplink(this.ctx.job.tenant_id, this.ctx.device.id)
      .catch(() => null);
    const uplink = judgeUplink(uplinkFacts, downloadBytes);
    if (!uplink.ok) {
      return this.refuse('uplink_on_backup', uplink.why, 'refused');
    }

    return {
      output:
        `RouterOS ${decision.current} on ${decision.arch}, ${this.plan.length} package(s) ` +
        `[${this.plan.map((p) => p.name).join(', ')}], ${mib(facts.freeBytes ?? 0)} free, ` +
        `${mib(space.requiredBytes)} needed; ${uplink.note} — will fetch ${this.target}`,
      detail: {
        action: 'upgrade',
        current: decision.current,
        target: this.target,
        architecture: decision.arch,
        packages: this.plan.map((p) => ({ name: p.name, expectedBytes: p.expectedBytes })),
        freeBytes: facts.freeBytes,
        requiredBytes: space.requiredBytes,
        uptimeSeconds: uptime,
        uplink: uplinkFacts
          ? {
              configured: uplinkFacts.configured,
              observed: uplinkFacts.observed,
              onBackup: uplinkFacts.onBackup,
              declared: uplinkFacts.declared,
            }
          : null,
      },
    };
  }

  // ── preflight_backup ─────────────────────────────────────────────────────
  async backup(): Promise<OsUpgradeStepResult & { backupId: number }> {
    const { backupId, summary } = await deps.takeBackup({
      deviceId: this.ctx.device.id,
      jobId: this.jobId,
      correlationId: this.ctx.correlationId,
      createdBy: this.ctx.job.requested_by ?? null,
    });
    await patchJob(this.jobId, { preflight_backup_id: backupId });
    return { backupId, output: summary, detail: { backupId } };
  }

  // ── apply: fetch every package, check it landed, last kill-switch read, reboot
  async apply(onWrite: () => void): Promise<OsUpgradeStepResult> {
    const session = await this.session('apply');
    const landed: Array<{ name: string; bytes: number }> = [];
    try {
      for (const pkg of this.plan) {
        // The intent is recorded BEFORE the first byte can land: the CHECK
        // `os_upgrade_jobs_backup_before_fetch_chk` refuses this update on a
        // job without a backup, which stops the fetch from ever being sent.
        if (landed.length === 0) await patchJob(this.jobId, { fetched_at: new Date() });
        this.pendingFiles.add(pkg.fileName);
        onWrite();

        const keeper = keepLease(this.jobId, this.ctx.workerId);
        let progress: Array<Record<string, string>>;
        try {
          progress = await session.run(
            ['/tool/fetch', `=url=${pkg.url}`, `=dst-path=${pkg.fileName}`],
            { isWrite: true, timeoutMs: timings.fetchTimeoutMs },
          );
        } catch (err) {
          const message = errText(err);
          if (err instanceof RouterOsTrapError && /device-mode/i.test(message)) {
            return await this.refuse(
              'device_mode_refused',
              `the router refused /tool/fetch for ${pkg.name}: ${message}. Its /system/device-mode ` +
                'denies fetch; re-enabling it needs physical access (reset button or cold power ' +
                'cycle within five minutes of `/system/device-mode/update fetch=yes`).',
              'fetch_failed',
            );
          }
          return await this.refuse(
            'fetch_failed',
            `the router could not download ${pkg.name} from ${pkg.url}: ${message}. ` +
              'ObliWAN does not push packages from the server in this version (no SFTP/FTP upload ' +
              'path): the router must reach download.mikrotik.com itself.',
            'fetch_failed',
          );
        } finally {
          keeper.stop();
        }
        if (keeper.lost()) throw new LeaseLostError(this.jobId);

        const last = progress[progress.length - 1];
        const status = (last?.status ?? '').trim();
        if (status && status !== 'finished') {
          return await this.refuse(
            'fetch_failed',
            `the download of ${pkg.name} ended with status '${status.slice(0, 40)}', not 'finished'.`,
            'fetch_failed',
          );
        }

        const rows = await session.run(
          ['/file/print', '=.proplist=.id,name,size', `?name=${pkg.fileName}`],
          { isWrite: false },
        );
        const row = rows.find((r) => (r.name ?? '').trim() === pkg.fileName);
        const size = parseByteCount(row?.size);
        const judged = row ? judgeLandedFile(pkg, size) : { ok: false as const, why: 'it is not on the router' };
        if (!judged.ok) {
          return await this.refuse(
            'package_file_implausible',
            `the downloaded ${pkg.fileName} is not plausible: ${judged.why}.`,
            'fetch_failed',
          );
        }
        landed.push({ name: pkg.name, bytes: size ?? 0 });
      }

      // ── The last statement before the reboot: the kill switch, again ──────
      // A download can take minutes; the switch is read NOW because now is
      // when somebody would have engaged it. The files fetched are removed by
      // the `cleanup` step that follows a failure here.
      try {
        await assertWritable(this.ctx.job.tenant_id);
      } catch (err) {
        if (err instanceof KillSwitchEngagedError) {
          await recordOutcome(
            this.jobId,
            'failed',
            `the kill switch was engaged after the download and before the reboot: ${errText(err)}.`,
          );
        }
        throw err;
      }
      await this.assertLeaseHeld();

      const sentAt = new Date();
      await patchJob(this.jobId, { rebooted_at: sentAt });
      try {
        await session.run(['/system/reboot'], { isWrite: true, timeoutMs: timings.rebootAckTimeoutMs });
      } catch (err) {
        if (err instanceof RouterOsTrapError) {
          // The router ANSWERED and refused: it is not rebooting.
          await patchJob(this.jobId, { rebooted_at: null });
          return await this.refuse(
            'reboot_refused',
            `the router refused /system/reboot: ${errText(err)}.`,
            'failed',
          );
        }
        // Silence or a dropped socket is what a reboot looks like from here.
      }
      this.rebootSentAt = sentAt.getTime();
    } finally {
      session.close();
    }

    return {
      output:
        `fetched ${landed.length} package(s) of RouterOS ${this.target} ` +
        `(${landed.map((l) => `${l.name} ${mib(l.bytes)}`).join(', ')}) and sent /system/reboot`,
      detail: { packages: landed, rebootSentAt: new Date(this.rebootSentAt).toISOString() },
    };
  }

  // ── cleanup: only when files may be on the router and no reboot was sent ─
  async cleanup(): Promise<OsUpgradeStepResult> {
    const names = [...this.pendingFiles];
    const leftover: string[] = [];
    let session: DeviceSession | null = null;
    try {
      session = await this.session('cleanup');
      for (const name of names) {
        const before = await session.run(['/file/print', '=.proplist=.id,name', `?name=${name}`], {
          isWrite: false,
        });
        const row = before.find((r) => (r.name ?? '').trim() === name);
        if (row?.['.id']) {
          await session.run(['/file/remove', `=.id=${row['.id']}`], { isWrite: true });
        }
        const after = await session.run(['/file/print', '=.proplist=name', `?name=${name}`], {
          isWrite: false,
        });
        if (after.some((r) => (r.name ?? '').trim() === name)) leftover.push(name);
        else this.pendingFiles.delete(name);
      }
    } catch (err) {
      for (const n of names) if (this.pendingFiles.has(n) && !leftover.includes(n)) leftover.push(n);
      this.leftoverNote = this.leftoverNoteFor(leftover, errText(err));
    } finally {
      session?.close();
    }
    if (leftover.length > 0) {
      if (!this.leftoverNote) this.leftoverNote = this.leftoverNoteFor(leftover, null);
      await this.appendDetail(this.leftoverNote);
      throw new OsUpgradeError('cleanup_incomplete', this.leftoverNote.trim());
    }
    const note = ` The ${names.length} file(s) this job asked the router to fetch were removed where ` +
      'they had landed, and their absence re-read: nothing of this job will be installed at its ' +
      'next reboot.';
    await this.appendDetail(note);
    return { output: note.trim(), detail: { removed: names } };
  }

  private leftoverNoteFor(leftover: string[], cause: string | null): string {
    return (
      ` WARNING: ${leftover.length} .npk file(s) are STILL on the router (${leftover.join(', ')})` +
      (cause ? ` — the cleanup could not finish: ${cause}` : '') +
      '. RouterOS installs a .npk from its root at the NEXT REBOOT, power cut included: remove ' +
      'them by hand (/file/remove) or the upgrade will happen unattended.'
    );
  }

  private async appendDetail(note: string): Promise<void> {
    await db('os_upgrade_jobs')
      .where({ job_id: this.jobId })
      .whereNotNull('outcome_detail')
      .update({ outcome_detail: db.raw('left(outcome_detail || ?, 4000)', [note]), updated_at: db.fn.now() });
  }

  // ── reconnect: bounded wait, identity, and proof of an actual reboot ──────
  async awaitReturn(): Promise<OsUpgradeStepResult> {
    if (this.rebootSentAt === null) {
      throw new OsUpgradeError('reboot_not_sent', 'awaitReturn() was reached without a reboot.');
    }
    const deadline = this.rebootSentAt + timings.returnTimeoutMs;
    await this.waitWithLease(Math.min(timings.firstProbeDelayMs, Math.max(0, deadline - Date.now())));

    let lastSilence = 'no probe was made';
    let sawOldBoot = false;
    // Only the LAST answer decides `not_rebooted`: a box that answered on its
    // old boot and then went silent may have rebooted late and not come back.
    let lastWasOldBoot = false;
    let attempts = 0;
    while (Date.now() <= deadline) {
      attempts++;
      await this.assertLeaseHeld();
      let proof: BindingAssertion | null = null;
      try {
        proof = await assertTargetBinding(this.ctx.device.id, {
          throwOnFailure: true,
          connectTimeoutMs: timings.probeConnectTimeoutMs,
        });
      } catch (err) {
        if (err instanceof BindingAssertionError && err.assertion.mismatched > 0) {
          // A box answered and it is NOT this device. Final: retrying
          // cannot change it, and `assertTargetBinding` has quarantined it.
          await recordOutcome(
            this.jobId,
            'identity_changed',
            `after the reboot the box at this device's address is not this device: ${err.assertion.reason}. ` +
              'The device was quarantined; its os_version was not touched.',
          );
          throw err;
        }
        lastSilence = errText(err);
        lastWasOldBoot = false;
      }

      if (proof) {
        const seen = await this.readAfterReboot();
        if (seen.kind === 'identity_changed') {
          await recordOutcome(this.jobId, 'identity_changed', seen.message);
          throw new OsUpgradeError('identity_changed', seen.message);
        }
        if (seen.kind === 'silent') {
          lastSilence = seen.message;
          lastWasOldBoot = false;
        } else if (seen.kind === 'old_boot') {
          sawOldBoot = true;
          lastWasOldBoot = true;
          lastSilence = seen.message;
        } else {
          this.returnProof = proof;
          await patchJob(this.jobId, { returned_at: new Date() });
          const backAfter = Math.round((Date.now() - this.rebootSentAt) / 1000);
          return {
            output:
              `back ${backAfter}s after the reboot command; identity re-proved on a fresh socket ` +
              `(${proof.matched} attribute(s)), uptime ${seen.uptime === null ? 'unreadable' : `${seen.uptime}s`}`,
            detail: { attempts, dialled: proof.dialled, matched: proof.matched, uptimeSeconds: seen.uptime },
          };
        }
      }

      const left = deadline - Date.now();
      if (left <= 0) break;
      await this.waitWithLease(Math.min(timings.probeIntervalMs, left));
    }

    const bound = timings.returnTimeoutMs >= 120_000
      ? `${Math.round(timings.returnTimeoutMs / 60_000)} min`
      : `${Math.round(timings.returnTimeoutMs / 1000)} s`;
    if (lastWasOldBoot) {
      // A live, identity-proved router that never restarted: the files would
      // install at ITS next reboot, unreviewed. The `cleanup` step that
      // follows (apply.service) removes them and says what it could not.
      this.provenNotRebooted = true;
      const msg =
        `the router kept answering on the boot that PRECEDES the reboot command for ${bound}: ` +
        `it did not reboot. The ${this.plan.length} .npk file(s) fetched would be installed at its ` +
        'next reboot, power cut included, so they are removed now (see the cleanup step). ' +
        'Its os_version was not touched.';
      await recordOutcome(this.jobId, 'not_rebooted', msg);
      throw new OsUpgradeError('not_rebooted', msg);
    }
    const msg =
      `the router did not come back within ${bound} of the reboot command (last: ` +
      `${lastSilence.slice(0, 300)})` +
      (sawOldBoot
        ? '; it first answered on its OLD boot, then went silent, so it may have rebooted late'
        : '') +
      '. It may still be installing, or it may not boot: a router ' +
      'that does not boot back needs a visit (netinstall). Its os_version was not touched.';
    await recordOutcome(this.jobId, 'lost', msg);
    throw new OsUpgradeError('device_lost', msg);
  }

  /** One read on a socket whose identity is proved on the socket itself. */
  private async readAfterReboot(): Promise<
    | { kind: 'returned'; uptime: number | null }
    | { kind: 'old_boot'; message: string }
    | { kind: 'silent'; message: string }
    | { kind: 'identity_changed'; message: string }
  > {
    let session: DeviceSession;
    try {
      session = await this.session('return');
    } catch (err) {
      if (err instanceof OsUpgradeError && err.kind === 'identity_mismatch') {
        return { kind: 'identity_changed', message: `after the reboot: ${err.message}` };
      }
      return { kind: 'silent', message: errText(err) };
    }
    try {
      const resource = (await session.run(['/system/resource/print'], { isWrite: false }))[0] ?? {};
      const uptime = parseUptimeSeconds(resource.uptime);
      const sinceReboot = Date.now() - (this.rebootSentAt ?? Date.now());
      // Booted BEFORE the reboot command (two seconds of rounding allowed):
      // this is the old boot, still shutting down or never told.
      if (uptime !== null && uptime * 1000 > sinceReboot + 2_000) {
        return {
          kind: 'old_boot',
          message: `answered with an uptime of ${uptime}s, ${Math.round(sinceReboot / 1000)}s after the reboot command`,
        };
      }
      return { kind: 'returned', uptime };
    } catch (err) {
      return { kind: 'silent', message: errText(err) };
    } finally {
      session.close();
    }
  }

  /**
   * The version and the packages, read on a fresh identity-proved session. A
   * box that has just come back may still drop a session (a tunnel
   * renegotiating in its first minutes), and failing here would fail an
   * upgrade that has already happened and leave os_version behind: so the
   * open-and-read is retried `POSTCHECK_READ_ATTEMPTS` times, renewing the
   * lease between tries. A box that CONTRADICTS the record is final.
   */
  private async readVersionAndPackages(): Promise<{ version: string | null; packages: InstalledPackage[] }> {
    let last: unknown = null;
    for (let attempt = 0; attempt < POSTCHECK_READ_ATTEMPTS; attempt++) {
      if (attempt > 0) await this.waitWithLease(timings.probeIntervalMs);
      let session: DeviceSession;
      try {
        session = await this.session('verify');
      } catch (err) {
        if (err instanceof OsUpgradeError && err.kind === 'identity_mismatch') throw err;
        last = err;
        continue;
      }
      try {
        const resource = (await session.run(['/system/resource/print'], { isWrite: false }))[0] ?? {};
        const packages = parsePackages(
          await session.run(
            ['/system/package/print', '=.proplist=name,version,disabled,scheduled,available'],
            { isWrite: false },
          ),
        );
        return { version: cleanRouterOsVersion(resource.version), packages };
      } catch (err) {
        last = err;
      } finally {
        session.close();
      }
    }
    throw last instanceof Error ? last : new OsUpgradeError('postcheck_unreadable', String(last));
  }

  // ── postcheck: the version, and every package with it ────────────────────
  async verify(): Promise<OsUpgradeStepResult> {
    const { version, packages } = await this.readVersionAndPackages();
    await patchJob(this.jobId, { observed_version: version });

    if (version !== null && version === this.from) {
      return this.refuse(
        'package_rejected',
        `the router rebooted and still runs RouterOS ${version}: it did not install ${this.target}. ` +
          'Its /log says why (not enough space at boot, a signature or dependency refusal). ' +
          'Nothing else was changed; its os_version was not touched.',
        'rejected',
      );
    }
    if (version !== this.target) {
      return this.refuse(
        'unexpected_version',
        `after the reboot the router reports ${version ?? 'no readable version'}, which is neither ` +
          `the release it ran (${this.from}) nor the target (${this.target}). It needs a human; ` +
          'its os_version was not touched.',
        'incomplete',
      );
    }

    // The system package is at the target: the box RUNS it, whatever follows.
    // The record says so now — the identity was proved after the reboot on the
    // assertion's socket and again on this one.
    if (!this.returnProof) {
      throw new OsUpgradeError('return_unproven', 'verify() was reached without an identity proof.');
    }
    await recordUpgradedOsVersion({
      tenantId: this.ctx.job.tenant_id,
      deviceId: this.ctx.device.id,
      jobId: this.jobId,
      version,
      proof: this.returnProof,
    });

    const behind = this.plan
      .map((p) => {
        const now = packages.find((q) => q.name === p.name);
        if (!now) return `${p.name} (gone)`;
        if (now.disabled) return `${p.name} (disabled)`;
        if (now.version !== this.target) return `${p.name} (${now.version ?? 'no version'})`;
        return null;
      })
      .filter((x): x is string => x !== null);
    if (behind.length > 0) {
      return this.refuse(
        'package_mismatch',
        `RouterOS is at ${this.target}, but not every package followed: ${behind.join(', ')}. ` +
          'RouterOS disables a package whose version differs from the system package. The device ' +
          `record now says ${this.target} (that is what it runs); the package(s) above need a human.`,
        'incomplete',
      );
    }

    await recordOutcome(
      this.jobId,
      'upgraded',
      `RouterOS ${this.from} -> ${this.target}, ${this.plan.length} package(s), identity re-proved after the reboot.`,
    );
    return {
      output: `RouterOS ${this.target} running, ${this.plan.length} package(s) at ${this.target}; os_version recorded`,
      detail: { from: this.from, to: version, packages: packages.map((p) => ({ name: p.name, version: p.version })) },
    };
  }
}
