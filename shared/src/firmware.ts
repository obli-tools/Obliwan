/**
 * RouterOS releases and the fleet's TARGET version.
 *
 * Pure: no I/O. The server (`services/firmware/`) is the only writer of the
 * release table and the only resolver the bench and the fleet updater consult;
 * this file is the vocabulary both sides share, so the client cannot spell a
 * channel, an architecture or a version differently from the server.
 *
 * WHAT WAS VERIFIED, AND HOW (real HTTPS requests):
 *  - `https://upgrade.mikrotik.com/routeros/NEWESTa7.stable` answered
 *    `7.24.5 1790691687\n` (text/plain): a version, one space, a Unix time in
 *    SECONDS (2026-09-29T14:21:27Z), a newline. `NEWESTa7.long-term` answered
 *    `7.23.7 1789561155\n` in the same shape. An unknown channel answers 404.
 *  - `https://download.mikrotik.com/routeros/7.24.5/routeros-7.24.5-arm64.npk`
 *    answered 200, and so did `-arm`, `-mipsbe`, `-mmips`, `-smips`, `-tile`
 *    and `-ppc`. `routeros-7.24.5-x86.npk` answered 404 while
 *    `routeros-7.24.5.npk` answered 200: the x86 package carries NO
 *    architecture suffix (same for `container-7.24.5.npk`). `packageUrl` encodes
 *    that, it is not a guess.
 *  - RouterOS 6 lays its packages out differently
 *    (`routeros-mipsbe-6.49.22.npk`), so `packageUrl` refuses any major
 *    version other than 7 rather than building a URL in the wrong shape.
 */

// -- Channels -----------------------------------------------------------------

/** The two channels watched. `testing`/`development` are deliberately absent:
 *  a fleet target is never a release candidate. */
export const ROUTEROS_RELEASE_CHANNELS = ['stable', 'long-term'] as const;
export type RouterOsReleaseChannel = (typeof ROUTEROS_RELEASE_CHANNELS)[number];

/** Once every 24 h after a successful read. */
export const ROUTEROS_RELEASE_CHECK_INTERVAL_HOURS = 24;
/** After a FAILED read, retry this often until one succeeds: a transient
 *  outage must not leave the watcher blind for a whole day. */
export const ROUTEROS_RELEASE_RETRY_INTERVAL_HOURS = 1;
/** A channel whose last SUCCESSFUL read is older than this is `stale`: its
 *  version is kept (never blanked) but is no longer fresh evidence. */
export const ROUTEROS_RELEASE_STALE_AFTER_HOURS = 72;

// -- Versions -----------------------------------------------------------------

export type RouterOsVersionStage = 'alpha' | 'beta' | 'rc' | 'release';

export interface RouterOsVersion {
  major: number;
  minor: number;
  /** `7.21` and `7.21.0` compare equal: an absent third component is 0. */
  patch: number;
  stage: RouterOsVersionStage;
  /** The N of `rcN` / `betaN`; 0 for a release. */
  stageNumber: number;
}

/** Leading zeros refused, at most four digits per component. */
const VERSION_RE =
  /^(0|[1-9]\d{0,3})\.(0|[1-9]\d{0,3})(?:\.(0|[1-9]\d{0,3}))?(?:(alpha|beta|rc)([1-9]\d{0,3}))?$/;
/** A RELEASE version: `^\d+\.\d+(\.\d+)?$`, with the same two refinements. */
const RELEASE_VERSION_RE = /^(0|[1-9]\d{0,3})\.(0|[1-9]\d{0,3})(?:\.(0|[1-9]\d{0,3}))?$/;

const STAGE_RANK: Record<RouterOsVersionStage, number> = { alpha: 0, beta: 1, rc: 2, release: 3 };

/** `null` for anything that is not a RouterOS version string. */
export function parseRouterOsVersion(input: unknown): RouterOsVersion | null {
  if (typeof input !== 'string') return null;
  const m = VERSION_RE.exec(input);
  if (!m) return null;
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: m[3] === undefined ? 0 : Number(m[3]),
    stage: (m[4] as RouterOsVersionStage | undefined) ?? 'release',
    stageNumber: m[5] === undefined ? 0 : Number(m[5]),
  };
}

/** True only for a release version (`7.24`, `7.24.5`), never `7.25rc1`. */
export function isRouterOsReleaseVersion(input: unknown): input is string {
  return typeof input === 'string' && RELEASE_VERSION_RE.test(input);
}

/**
 * Total order on RouterOS versions: numeric per component (7.9 < 7.10 <
 * 7.20.6 < 7.21), and a pre-release ranks BELOW its release
 * (7.25alpha1 < 7.25beta3 < 7.25rc1 < 7.25). Returns -1, 0 or 1.
 *
 * Throws a RangeError on an unparseable input instead of ordering it somehow:
 * a comparator that silently sorts garbage is how an updater decides that
 * "7.x" is newer than what a router runs.
 */
export function compareRouterOsVersion(a: string, b: string): -1 | 0 | 1 {
  const pa = parseRouterOsVersion(a);
  const pb = parseRouterOsVersion(b);
  if (!pa) throw new RangeError('Not a RouterOS version (left operand)');
  if (!pb) throw new RangeError('Not a RouterOS version (right operand)');
  const keys: Array<[number, number]> = [
    [pa.major, pb.major],
    [pa.minor, pb.minor],
    [pa.patch, pb.patch],
    [STAGE_RANK[pa.stage], STAGE_RANK[pb.stage]],
    [pa.stageNumber, pb.stageNumber],
  ];
  for (const [x, y] of keys) {
    if (x < y) return -1;
    if (x > y) return 1;
  }
  return 0;
}

// -- Package URLs -------------------------------------------------------------

export const ROUTEROS_DOWNLOAD_ORIGIN = 'https://download.mikrotik.com/routeros/';

/** STRICT allow-list. Anything else is refused, whatever its spelling. */
export const ROUTEROS_PACKAGE_ARCHITECTURES = [
  'arm', 'arm64', 'mipsbe', 'mmips', 'smips', 'tile', 'ppc', 'x86',
] as const;
export type RouterOsPackageArch = (typeof ROUTEROS_PACKAGE_ARCHITECTURES)[number];

/** `^[a-z0-9-]+$`, at most 40 characters, and not starting with a hyphen. */
const PACKAGE_NAME_RE = /^[a-z0-9][a-z0-9-]{0,39}$/;

export const ROUTEROS_PACKAGE_URL_REFUSALS = [
  'VERSION_INVALID',
  'MAJOR_UNSUPPORTED',
  'PACKAGE_INVALID',
  'ARCH_INVALID',
] as const;
export type RouterOsPackageUrlRefusal = (typeof ROUTEROS_PACKAGE_URL_REFUSALS)[number];

export type RouterOsPackageUrlResult =
  | { ok: true; url: string }
  | { ok: false; code: RouterOsPackageUrlRefusal; reason: string };

export function isRouterOsPackageArch(input: unknown): input is RouterOsPackageArch {
  return typeof input === 'string'
    && (ROUTEROS_PACKAGE_ARCHITECTURES as readonly string[]).includes(input);
}

/**
 * The download URL of one RouterOS 7 package, or a named refusal. Every
 * input is checked BEFORE any string is assembled, so no URL is ever built
 * from an unchecked value. Refusal reasons never echo the input back.
 */
export function tryRouterOsPackageUrl(
  version: unknown,
  packageName: unknown,
  arch: unknown,
): RouterOsPackageUrlResult {
  if (!isRouterOsReleaseVersion(version)) {
    return { ok: false, code: 'VERSION_INVALID', reason: 'version must be a release such as 7.24.5' };
  }
  if (parseRouterOsVersion(version)!.major !== 7) {
    return {
      ok: false,
      code: 'MAJOR_UNSUPPORTED',
      reason: 'only RouterOS 7 packages follow <package>-<version>-<arch>.npk',
    };
  }
  if (typeof packageName !== 'string' || !PACKAGE_NAME_RE.test(packageName)) {
    return { ok: false, code: 'PACKAGE_INVALID', reason: 'package name must match ^[a-z0-9-]+$' };
  }
  if (!isRouterOsPackageArch(arch)) {
    return {
      ok: false,
      code: 'ARCH_INVALID',
      reason: `architecture must be one of ${ROUTEROS_PACKAGE_ARCHITECTURES.join(', ')}`,
    };
  }
  // x86 is the one architecture published WITHOUT a suffix (verified, header).
  const suffix = arch === 'x86' ? '' : `-${arch}`;
  return { ok: true, url: `${ROUTEROS_DOWNLOAD_ORIGIN}${version}/${packageName}-${version}${suffix}.npk` };
}

export class RouterOsPackageUrlError extends Error {
  constructor(public readonly code: RouterOsPackageUrlRefusal, message: string) {
    super(message);
    this.name = 'RouterOsPackageUrlError';
  }
}

/** `tryRouterOsPackageUrl`, throwing `RouterOsPackageUrlError` on refusal. */
export function packageUrl(version: string, packageName: string, arch: string): string {
  const r = tryRouterOsPackageUrl(version, packageName, arch);
  if (!r.ok) throw new RouterOsPackageUrlError(r.code, r.reason);
  return r.url;
}

/**
 * The package architecture for a `/system/resource` `architecture-name`.
 * An exact allow-list match, plus exactly two renames:
 *  - `x86_64` -> `x86`: what a CHR is understood to report on RouterOS 7.
 *  - `powerpc` -> `ppc`: what PowerPC RouterBOARDs (the RB1100AHx2 family)
 *    report in public RouterOS 5/6 outputs, including MikroTik's own manual
 *    example on an RB1100. RouterOS 7 publishes their package as `-ppc`.
 * BOTH renames are reasoned from public outputs and NOT observed on this fleet
 * or on a RouterOS 7 PowerPC board. Neither can pick the wrong package: there
 * is one x86 and one PowerPC package per RouterOS 7 release. Anything else is
 * `null`, never a best guess.
 */
export function routerOsPackageArchFromResource(architectureName: unknown): RouterOsPackageArch | null {
  if (typeof architectureName !== 'string') return null;
  if (architectureName === 'x86_64') return 'x86';
  if (architectureName === 'powerpc') return 'ppc';
  return isRouterOsPackageArch(architectureName) ? architectureName : null;
}

// -- The fleet target ---------------------------------------------------------

/** Instance-level decision (platform admin). Default `stable`. */
export const ROUTEROS_TARGET_MODES = ['stable', 'long-term', 'pinned'] as const;
export type RouterOsTargetMode = (typeof ROUTEROS_TARGET_MODES)[number];

export interface RouterOsTargetSetting {
  mode: RouterOsTargetMode;
  /** A release version iff `mode === 'pinned'`, otherwise null. */
  pinned: string | null;
}

export const DEFAULT_ROUTEROS_TARGET: Readonly<RouterOsTargetSetting> = Object.freeze({
  mode: 'stable',
  pinned: null,
});

export type RouterOsTargetValidation =
  | { ok: true; value: RouterOsTargetSetting }
  | { ok: false; reason: string };

/**
 * Validate a target as received from a client OR read back from storage.
 * Refuses rather than repairs: a pinned version on a channel mode, a missing
 * pin, a release candidate or a RouterOS 6 version are all errors.
 */
export function validateRouterOsTarget(input: unknown): RouterOsTargetValidation {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    return { ok: false, reason: 'target must be an object { mode, pinned }' };
  }
  const { mode, pinned } = input as { mode?: unknown; pinned?: unknown };
  if (typeof mode !== 'string' || !(ROUTEROS_TARGET_MODES as readonly string[]).includes(mode)) {
    return { ok: false, reason: `mode must be one of ${ROUTEROS_TARGET_MODES.join(', ')}` };
  }
  if (mode === 'pinned') {
    if (!isRouterOsReleaseVersion(pinned)) {
      return { ok: false, reason: 'a pinned target needs a release version such as 7.24.5' };
    }
    if (parseRouterOsVersion(pinned)!.major !== 7) {
      return { ok: false, reason: 'only a RouterOS 7 version can be pinned' };
    }
    return { ok: true, value: { mode: 'pinned', pinned } };
  }
  if (pinned !== null && pinned !== undefined) {
    return { ok: false, reason: 'pinned must be null unless mode is pinned' };
  }
  return { ok: true, value: { mode: mode as RouterOsTargetMode, pinned: null } };
}

export const ROUTEROS_TARGET_UNRESOLVED = ['NO_RELEASE_KNOWN', 'TARGET_UNREADABLE'] as const;
export type RouterOsTargetUnresolved = (typeof ROUTEROS_TARGET_UNRESOLVED)[number];

export interface RouterOsTargetResolution {
  /** The version the bench and the fleet updater must aim at; null = do not. */
  resolved: string | null;
  unresolvedReason: RouterOsTargetUnresolved | null;
}

/**
 * Resolve a target against the latest known versions. `setting === null`
 * means the stored decision could not be read: that resolves to NOTHING, never
 * to the default, because silently replacing a pin an administrator chose with
 * "latest stable" is an unrequested fleet upgrade.
 */
export function resolveRouterOsTarget(
  setting: RouterOsTargetSetting | null,
  latest: { stable: string | null; longTerm: string | null },
): RouterOsTargetResolution {
  if (setting === null) return { resolved: null, unresolvedReason: 'TARGET_UNREADABLE' };
  const resolved = setting.mode === 'pinned'
    ? setting.pinned
    : setting.mode === 'long-term' ? latest.longTerm : latest.stable;
  if (!isRouterOsReleaseVersion(resolved)) {
    return {
      resolved: null,
      unresolvedReason: setting.mode === 'pinned' ? 'TARGET_UNREADABLE' : 'NO_RELEASE_KNOWN',
    };
  }
  return { resolved, unresolvedReason: null };
}

// -- Wire shapes (GET /api/firmware/routeros) ---------------------------------

export interface RouterOsReleaseInfo {
  channel: RouterOsReleaseChannel;
  /** Last value successfully read; KEPT when a later check fails. */
  version: string | null;
  /** The publication time MikroTik gave, if it gave a plausible one. */
  releasedAt: string | null;
  /** When THIS installation first saw `version` on this channel. */
  firstSeenAt: string | null;
  /** Last attempt, successful or not. */
  lastCheckedAt: string | null;
  /** Last attempt that produced `version`. */
  lastSuccessAt: string | null;
  /** Error of the LAST attempt; null once an attempt succeeds again. */
  lastError: string | null;
  /** True when `lastSuccessAt` is null or older than the stale threshold. */
  stale: boolean;
}

export interface RouterOsTargetStatus extends RouterOsTargetResolution {
  /** null when the stored decision could not be read (`TARGET_UNREADABLE`). */
  mode: RouterOsTargetMode | null;
  pinned: string | null;
  /** True when no decision was ever stored and the default applies. */
  isDefault: boolean;
  /** True when `resolved` comes from a stale channel reading (never for a pin). */
  stale: boolean;
  updatedAt: string | null;
  updatedBy: number | null;
}

export interface RouterOsFirmwareStatus {
  stable: RouterOsReleaseInfo;
  longTerm: RouterOsReleaseInfo;
  /** Most recent attempt across both channels. */
  lastCheckedAt: string | null;
  /** The channels' current errors joined, or null when the last attempts succeeded. */
  lastError: string | null;
  target: RouterOsTargetStatus;
  checkIntervalHours: number;
}

export interface RouterOsReleaseCheckOutcome {
  channel: RouterOsReleaseChannel;
  ok: boolean;
  version: string | null;
  /** True when the read version differs from the one previously recorded. */
  changed: boolean;
  error: string | null;
}

export interface RouterOsReleaseCheckResult {
  outcomes: RouterOsReleaseCheckOutcome[];
  status: RouterOsFirmwareStatus;
}
