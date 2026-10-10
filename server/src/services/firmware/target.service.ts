import {
  DEFAULT_ROUTEROS_TARGET,
  ROUTEROS_DOWNLOAD_ORIGIN,
  packageUrl,
  validateRouterOsTarget,
  type RouterOsTargetSetting,
} from '@obliwan/shared';
import { AppError } from '../../middleware/errorHandler';
import { logger } from '../../utils/logger';
import { appConfigService } from '../appConfig.service';

/**
 * The fleet's TARGET RouterOS version: one instance-level decision, taken by a
 * platform admin, stored in `app_config` under `routeros_target` as
 * `{ mode, pinned, updatedAt, updatedBy }`.
 *
 * app_config rather than a table: it is one value for the whole installation,
 * like `asn_lookup_enabled`. The generic `PUT /api/app-config/:key` cannot
 * write it (the key is not in that controller's ALLOWED_KEYS), so the only
 * writer is `setRouterOsTarget`, which validates first.
 *
 * No row = nobody decided: the default ('latest stable') applies and the API
 * says so (`isDefault`). A row that cannot be read back is NOT the default: it
 * resolves to nothing (`TARGET_UNREADABLE`), because silently replacing a pin
 * with "latest stable" would upgrade a fleet nobody asked to upgrade.
 */

export const ROUTEROS_TARGET_CONFIG_KEY = 'routeros_target';

/** Bounded probe of download.mikrotik.com before a pin is accepted. */
export const PIN_PROBE_TIMEOUT_MS = 10_000;

export interface StoredRouterOsTarget {
  /** null = a row exists and could not be read back. */
  setting: RouterOsTargetSetting | null;
  isDefault: boolean;
  updatedAt: string | null;
  updatedBy: number | null;
}

export async function readRouterOsTarget(): Promise<StoredRouterOsTarget> {
  const raw = await appConfigService.get(ROUTEROS_TARGET_CONFIG_KEY);
  if (raw === null) {
    return { setting: { ...DEFAULT_ROUTEROS_TARGET }, isDefault: true, updatedAt: null, updatedBy: null };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    logger.warn({ key: ROUTEROS_TARGET_CONFIG_KEY }, 'RouterOS target is not valid JSON; resolving to nothing');
    return { setting: null, isDefault: false, updatedAt: null, updatedBy: null };
  }
  const v = validateRouterOsTarget(parsed);
  const meta = (typeof parsed === 'object' && parsed !== null ? parsed : {}) as {
    updatedAt?: unknown;
    updatedBy?: unknown;
  };
  const updatedAt = typeof meta.updatedAt === 'string' && !Number.isNaN(Date.parse(meta.updatedAt))
    ? meta.updatedAt
    : null;
  const updatedBy = typeof meta.updatedBy === 'number' && Number.isInteger(meta.updatedBy) ? meta.updatedBy : null;
  if (!v.ok) {
    logger.warn({ key: ROUTEROS_TARGET_CONFIG_KEY, reason: v.reason }, 'RouterOS target is unreadable; resolving to nothing');
    return { setting: null, isDefault: false, updatedAt, updatedBy };
  }
  return { setting: v.value, isDefault: false, updatedAt, updatedBy };
}

export type PublishedProbe = 'published' | 'absent' | 'unknown';

/**
 * The only shape a probed URL may have after ROUTEROS_DOWNLOAD_ORIGIN: what
 * `packageUrl` builds, `<version>/<package>-<version>[-<arch>].npk`.
 */
const PROBE_PATH_RE = /^[0-9]+\.[0-9]+(\.[0-9]+)*\/[a-z0-9][a-z0-9-]*-[0-9]+\.[0-9]+(\.[0-9]+)*(-[a-z0-9]+)*\.npk$/;

export interface ProbeOptions {
  /**
   * Harness only: the fake origin that replaces ROUTEROS_DOWNLOAD_ORIGIN, AFTER
   * the URL has passed the host check below. Must end with '/'. Never read from
   * the environment or a request.
   */
  origin?: string;
  timeoutMs?: number;
}

/**
 * HEAD of a package URL: 200 published, 404 absent, anything else unknown
 * (a redirect is refused, never followed: it is "unknown", so the pin is
 * refused rather than confirmed by another host).
 *
 * It does its OWN host check rather than trusting its caller: a URL that is
 * not a download.mikrotik.com package URL, as `packageUrl` builds them, throws
 * before anything is sent. Today's only caller passes `packageUrl` output, so
 * the throw is a programming error, never an operator one.
 *
 * This is public-internet egress (see releaseWatcher.ts): one HEAD per pin
 * attempt, bounded by the global MikroTik bucket in firmware.routes.ts.
 */
export async function probePackagePublished(url: string, opts: ProbeOptions = {}): Promise<PublishedProbe> {
  if (!url.startsWith(ROUTEROS_DOWNLOAD_ORIGIN) || !PROBE_PATH_RE.test(url.slice(ROUTEROS_DOWNLOAD_ORIGIN.length))) {
    // The URL is not echoed: it is not ours to repeat.
    throw new Error('probePackagePublished: refusing a URL that is not a download.mikrotik.com package URL');
  }
  const target = opts.origin ? `${opts.origin}${url.slice(ROUTEROS_DOWNLOAD_ORIGIN.length)}` : url;
  try {
    const res = await fetch(target, {
      method: 'HEAD',
      redirect: 'error',
      signal: AbortSignal.timeout(opts.timeoutMs ?? PIN_PROBE_TIMEOUT_MS),
    });
    if (res.status === 200) return 'published';
    if (res.status === 404) return 'absent';
    return 'unknown';
  } catch {
    return 'unknown';
  }
}

export interface SetTargetOptions {
  /**
   * Harness only: replaces the HEAD request to download.mikrotik.com (the
   * harness passes either a canned answer or `probePackagePublished` aimed at
   * its fake origin).
   */
  probe?: (url: string) => Promise<PublishedProbe>;
  now?: () => Date;
}

/**
 * Validate and store a target. A pin is accepted only once MikroTik is seen to
 * publish that version (its x86 `routeros` package answers 200): a typo such
 * as 7.42.5 would otherwise become the target of every router in the fleet.
 * If download.mikrotik.com cannot be reached the pin is refused, not accepted
 * unverified; the target is left as it was.
 */
export async function setRouterOsTarget(
  input: unknown,
  userId: number | null,
  opts: SetTargetOptions = {},
): Promise<RouterOsTargetSetting> {
  const v = validateRouterOsTarget(input);
  if (!v.ok) throw new AppError(400, v.reason);
  const setting = v.value;
  if (setting.mode === 'pinned') {
    const version = setting.pinned!;
    // Validated above, so packageUrl cannot refuse; built from checked input only.
    const url = packageUrl(version, 'routeros', 'x86');
    const probe = await (opts.probe ?? probePackagePublished)(url);
    if (probe === 'absent') {
      throw new AppError(400, `RouterOS ${version} is not published on download.mikrotik.com`);
    }
    if (probe === 'unknown') {
      throw new AppError(
        502,
        `Could not confirm on download.mikrotik.com that RouterOS ${version} is published; the target was not changed`,
      );
    }
  }
  const now = opts.now?.() ?? new Date();
  await appConfigService.set(
    ROUTEROS_TARGET_CONFIG_KEY,
    JSON.stringify({ mode: setting.mode, pinned: setting.pinned, updatedAt: now.toISOString(), updatedBy: userId }),
  );
  logger.info({ userId, mode: setting.mode, pinned: setting.pinned }, 'RouterOS fleet target changed');
  return setting;
}
