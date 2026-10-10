import crypto from 'crypto';
import { appConfigService } from './appConfig.service';
import { db } from '../db';
import { logger } from '../utils/logger';

/** ObliWAN's accent colour, announced to Obligate (the suite's app switchers use it). */
export const APP_ACCENT_COLOR = '#90A4AE';

/** The `app_type` this instance is registered under in Obligate. */
const OWN_APP_TYPE = 'obliwan';

/**
 * Public OAuth client id of this app for Obligate: lowercase hex SHA-256 of
 * the API key. Cross-repo contract with Obligate (`publicClientId()` in its
 * app.service.ts) and with every other Obli* app (Obliance's
 * `obligatePublicClientId`): change it everywhere or nowhere.
 */
export function obligatePublicClientId(apiKey: string): string {
  return crypto.createHash('sha256').update(apiKey, 'utf8').digest('hex');
}

/**
 * One entry of the app switcher, as Obligate's `GET /api/apps/connected`
 * answers it once SHAPED (see `shapeConnectedApps`). Order is Obligate's
 * (`sort_order`, then name) and is never re-sorted here.
 */
export interface ConnectedAppEntry {
  appType: string;
  name: string;
  baseUrl: string;
  icon: string | null;
  color: string | null;
  /** The caller's own registration, resolved by Obligate from our Bearer key. */
  self?: true;
  /** Filed under "More…" in Obligate (not an Obli* app). */
  thirdParty: boolean;
}

const HEX_COLOR_RE = /^#[0-9a-fA-F]{3,8}$/;

/**
 * Remote JSON → switcher entries, dropping anything the browser must not act on.
 *
 * Obliance passes Obligate's answer through verbatim; ObliWAN does not. The
 * client turns `baseUrl` into `window.location.href = new URL(baseUrl + '/auth/sso-redirect')`,
 * and `new URL('javascript:…/auth/sso-redirect')` parses — so an entry whose
 * base URL is not http(s) (an Obligate admin typo, or a compromised Obligate)
 * would be script execution on THIS origin, the one holding the fleet's
 * credentials, from one click on a pill. `color` lands in an inline style:
 * only a hex colour (the same rule Obligate's own self-info applies) gets
 * through, so a `url(…)` cannot turn the switcher into a tracking beacon.
 */
function shapeConnectedApps(raw: unknown): ConnectedAppEntry[] {
  if (!Array.isArray(raw)) return [];
  const out: ConnectedAppEntry[] = [];
  let dropped = 0;
  for (const item of raw) {
    const o = (item && typeof item === 'object' ? item : {}) as Record<string, unknown>;
    const appType = typeof o.appType === 'string' ? o.appType.trim() : '';
    const baseUrl = typeof o.baseUrl === 'string' ? o.baseUrl.trim().replace(/\/+$/, '') : '';
    if (!appType || appType.length > 64 || !baseUrl || baseUrl.length > 2048 || !toHttpOrigin(baseUrl)) {
      dropped += 1;
      continue;
    }
    const name = typeof o.name === 'string' && o.name.trim() ? o.name.trim().slice(0, 128) : appType;
    out.push({
      appType,
      name,
      baseUrl,
      icon: typeof o.icon === 'string' && o.icon.length > 0 && o.icon.length <= 2048 ? o.icon : null,
      color: typeof o.color === 'string' && HEX_COLOR_RE.test(o.color) ? o.color : null,
      thirdParty: o.thirdParty === true,
      ...(o.self === true ? { self: true as const } : {}),
    });
  }
  if (dropped > 0) {
    logger.warn({ dropped }, 'Obligate connected-apps: entries without an app type or an http(s) base URL were dropped from the switcher');
  }
  return out;
}

/** Normalised `scheme://host[:port]` of an http(s) URL (lower-case host, no default port), or null. */
function toHttpOrigin(value: string): string | null {
  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:' ? url.origin : null;
  } catch {
    return null;
  }
}

/** localhost / loopback origin: for another machine's browser, that is itself. */
function isLoopbackOrigin(origin: string): boolean {
  const { hostname } = new URL(origin);
  return hostname === 'localhost' || hostname.endsWith('.localhost') || hostname === '[::1]' || /^127\./.test(hostname);
}

/**
 * Public origin set by the operator (APP_URL / CLIENT_ORIGIN), or null when
 * unset. Read at call time and never from `config.clientOrigin`, whose
 * `http://localhost:5173` default is a development value nobody set.
 */
function envOrigin(name: 'APP_URL' | 'CLIENT_ORIGIN'): string | null {
  const value = process.env[name]?.trim();
  return value ? toHttpOrigin(value) : null;
}

const ORIGIN_CACHE_TTL_MS = 5 * 60 * 1000;
const ORIGIN_CACHE_MIN_REFRESH_MS = 30 * 1000;
const CONNECTED_APPS_TIMEOUT_MS = 5_000;

/** Warn once per process, not on every sign-in. */
let warnedClientIdIsApiKey = false;

export interface ObligateUserAssertion {
  obligateUserId: number;
  username: string;
  email: string | null;
  displayName: string | null;
  role: string;
  tenants: Array<{ slug: string; role: string; capabilities?: string[] }>;
  teams: string[];
  capabilities?: string[];
  authSource: 'local' | 'ldap';
  linkedLocalUserId: number | null;
  preferences?: {
    preferredTheme?: string;
    toastEnabled?: boolean;
    toastPosition?: string;
    profilePhotoUrl?: string | null;
    preferredLanguage?: string;
    anonymousMode?: boolean;
    appSpecific?: Record<string, string>;
  };
}

/**
 * Shape the remote answer before anything downstream reads it.
 *
 * `exchangeCode` used to hand `data.data` to `/auth/callback` verbatim, with
 * the `ObligateUserAssertion` type as the only guarantee — and a TypeScript
 * interface guarantees nothing about JSON that arrived over the wire from
 * another process. Two consequences the callback had to defend against on its
 * own, and one it could not:
 *
 *   - `tenants` / `teams` / `capabilities` sent as something other than an
 *     array made `for (const t of ...)` or `sanitizeCapabilities(...).filter`
 *     throw, and the callback's outer catch turns any throw into
 *     `/login?error=sso_failed`: an unexplained login failure.
 *   - `linkedLocalUserId` sent as a string ("1") or a float slipped past
 *     `if (assertion.linkedLocalUserId)` into a `where({ id })`.
 *
 * Normalising here means the callback reasons about values whose TYPE it can
 * trust, and keeps every "is this really an array" check in one place. It does
 * NOT make the content trustworthy: `linkedLocalUserId` remains an untrusted
 * claim, checked against our own records in obligateCallback.routes.ts.
 */
function toStringOrNull(v: unknown): string | null {
  return typeof v === 'string' && v.length > 0 ? v : null;
}

function normaliseAssertion(raw: unknown): ObligateUserAssertion | null {
  if (!raw || typeof raw !== 'object') return null;
  const a = raw as Record<string, unknown>;

  const obligateUserId = Number(a.obligateUserId);
  if (!Number.isInteger(obligateUserId) || obligateUserId <= 0) {
    logger.warn({ obligateUserId: a.obligateUserId }, 'Obligate exchange: assertion has no usable obligateUserId');
    return null;
  }
  const username = typeof a.username === 'string' ? a.username.trim() : '';
  if (!username) {
    logger.warn({ obligateUserId }, 'Obligate exchange: assertion has no username');
    return null;
  }

  const rawLinked = Number(a.linkedLocalUserId);
  const linkedLocalUserId = Number.isInteger(rawLinked) && rawLinked > 0 ? rawLinked : null;

  const tenants = (Array.isArray(a.tenants) ? a.tenants : [])
    .map((t) => {
      const o = (t && typeof t === 'object' ? t : {}) as Record<string, unknown>;
      const slug = typeof o.slug === 'string' ? o.slug.trim() : '';
      if (!slug) return null;
      return {
        slug,
        // The RAW slug (trimmed, lower-cased): a permission-set slug since
        // migration 084, resolved by services/obligateRoles.ts — never
        // collapsed here to admin/member, which turned an Obligate `viewer`
        // into a full operator.
        role: typeof o.role === 'string' ? o.role.trim().toLowerCase().slice(0, 64) : '',
        // Left as unknown strings on purpose: sanitizeCapabilities() is the
        // single vocabulary gate and runs at the point of WRITE.
        capabilities: (Array.isArray(o.capabilities) ? o.capabilities : []).map((c) => String(c)),
      };
    })
    .filter((t): t is { slug: string; role: string; capabilities: string[] } => t !== null);

  const teams = (Array.isArray(a.teams) ? a.teams : []).map((t) => String(t));

  return {
    obligateUserId,
    username,
    email: toStringOrNull(a.email),
    displayName: toStringOrNull(a.displayName),
    role: a.role === 'admin' ? 'admin' : 'user',
    tenants,
    teams,
    capabilities: (Array.isArray(a.capabilities) ? a.capabilities : []).map((c) => String(c)),
    authSource: a.authSource === 'ldap' ? 'ldap' : 'local',
    linkedLocalUserId,
    preferences: (a.preferences && typeof a.preferences === 'object'
      ? a.preferences
      : undefined) as ObligateUserAssertion['preferences'],
  };
}

export const obligateService = {
  /**
   * Check if Obligate is configured and reachable.
   */
  async getSsoConfig(): Promise<{ obligateUrl: string | null; obligateReachable: boolean; obligateEnabled: boolean }> {
    const cfg = await appConfigService.getObligateConfig();
    if (!cfg.url || !cfg.enabled) {
      return { obligateUrl: cfg.url, obligateReachable: false, obligateEnabled: cfg.enabled };
    }

    // ┌─ THE TIMEOUT WAS 2 SECONDS, AND THAT WAS THE BUG ────────────────────┐
    // │ This probe decides whether the login page shows "centralised auth is  │
    // │ UNAVAILABLE, degraded local mode". Two seconds is fine on a LAN and   │
    // │ far too short for the real deployment: Obligate sits behind Oblihub,  │
    // │ so the first call of the day pays DNS, a cold TCP connect and a full  │
    // │ TLS handshake through a reverse proxy. Exceeding 2 s there is normal, │
    // │ not a failure — and the operator was told SSO was down while the      │
    // │ redirect itself worked perfectly.                                     │
    // │                                                                      │
    // │ A banner that cries wolf on a healthy system is worse than no banner: │
    // │ it is the one people learn to ignore before the day it is right.      │
    // └──────────────────────────────────────────────────────────────────────┘
    const PROBE_TIMEOUT_MS = 8000;
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS);
      const res = await fetch(`${cfg.url}/health`, { signal: controller.signal });
      clearTimeout(timeout);
      if (!res.ok) {
        logger.warn(
          { url: cfg.url, status: res.status },
          'Obligate /health answered but not OK — the login page will offer degraded local mode',
        );
      }
      return { obligateUrl: cfg.url, obligateReachable: res.ok, obligateEnabled: true };
    } catch (err) {
      // Logged, because "unreachable" used to be silent and an operator had no
      // way to tell a DNS failure from a timeout from a wrong URL. This runs on
      // a public, unauthenticated route: the reason goes to the log, never to
      // the response.
      logger.warn(
        { url: cfg.url, err: err instanceof Error ? err.message : String(err), timeoutMs: PROBE_TIMEOUT_MS },
        'Obligate reachability probe failed — check that the server CONTAINER can reach this URL, '
          + 'not just your browser',
      );
      return { obligateUrl: cfg.url, obligateReachable: false, obligateEnabled: true };
    }
  },

  /**
   * Exchange an authorization code with Obligate for user info.
   */
  async exchangeCode(code: string, redirectUri: string): Promise<ObligateUserAssertion | null> {
    const raw = await appConfigService.getObligateRaw();
    if (!raw.url || !raw.apiKey) {
      logger.warn('Obligate exchange failed: not configured');
      return null;
    }

    try {
      const res = await fetch(`${raw.url}/api/oauth/token/exchange`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${raw.apiKey}`,
        },
        body: JSON.stringify({ code, redirect_uri: redirectUri }),
      });

      if (!res.ok) {
        // ┌─ THE REASON IS IN THE BODY, AND IT USED TO BE THROWN AWAY ───────┐
        // │ Obligate answers with a NAMED cause — 'Invalid API key',          │
        // │ 'Missing code or redirect_uri', 'Invalid, expired, or already     │
        // │ used code' — and this logged only "HTTP 401". Those three have    │
        // │ completely different fixes (wrong key in the vault / a bug here / │
        // │ a redirect_uri mismatch), and the operator was handed a number    │
        // │ that cannot distinguish them.                                     │
        // │                                                                  │
        // │ `redirectUri` goes in too: a mismatch is the most common cause    │
        // │ and it is invisible without seeing what we actually sent. It is a │
        // │ URL, not a secret. The API key is NOT logged.                     │
        // └──────────────────────────────────────────────────────────────────┘
        const body = await res.text().catch(() => '');
        logger.warn(
          { status: res.status, redirectUri, obligateSaid: body.slice(0, 300) },
          'Obligate exchange REFUSED. 401 with "Invalid API key" means the key stored here is '
            + 'not the one Obligate issued for this app; 401 with "Invalid, expired, or already '
            + 'used code" usually means the redirect_uri above is not the callback URL registered '
            + 'in Obligate.',
        );
        return null;
      }

      const data = await res.json() as { success?: unknown; data?: unknown };
      if (!data.success || !data.data) return null;

      // Never return the remote object verbatim — see normaliseAssertion above.
      return normaliseAssertion(data.data);
    } catch (err) {
      logger.error(err, 'Obligate exchange error');
      return null;
    }
  },

  /**
   * Report a provisioned user back to Obligate.
   */
  async reportProvision(obligateUserId: number, remoteUserId: number): Promise<void> {
    const raw = await appConfigService.getObligateRaw();
    if (!raw.url || !raw.apiKey) return;

    try {
      await fetch(`${raw.url}/api/apps/report-provision`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${raw.apiKey}`,
        },
        body: JSON.stringify({ obligateUserId, remoteUserId }),
      });
    } catch (err) {
      logger.error(err, 'Failed to report provision to Obligate');
    }
  },

  /**
   * Announce this app's own branding to Obligate (POST /api/apps/self-info).
   * Obligate stores the announced accent colour as the source of truth, so
   * every app switcher across the suite shows ObliWAN in its own colour with
   * nothing to set by hand. Best-effort: never throws, never blocks startup.
   */
  async announceSelfInfo(): Promise<void> {
    const raw = await appConfigService.getObligateRaw();
    if (!raw.url || !raw.apiKey) return;
    try {
      const res = await fetch(`${raw.url}/api/apps/self-info`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${raw.apiKey}` },
        body: JSON.stringify({ color: APP_ACCENT_COLOR }),
        signal: AbortSignal.timeout(5000),
      });
      if (!res.ok) logger.warn({ status: res.status }, 'Obligate self-info announce refused');
    } catch (err) {
      logger.warn({ err: err instanceof Error ? err.message : String(err) }, 'Obligate self-info announce failed');
    }
  },

  /**
   * NOTE - syncCapabilitySchemas() is deliberately ABSENT.
   *
   * Obliguard called POST /api/apps/sync-capability-schemas at every boot with
   * a hard-coded list ('monitor_rw', 'bans', 'whitelist'...). That endpoint does
   * not exist on Obligate, so the call always failed and was swallowed; and the
   * list it pushed is no longer ObliWAN's vocabulary anyway (see
   * @obliwan/shared/capabilities.ts). Spec 3.1 lists it among the things not to
   * carry over. The capability catalogue is served to Obligate through
   * GET /api/auth/app-info instead.
   */

  /**
   * Fetch latest preferences from Obligate and sync to local DB.
   * Throttled: once per 60s per user. Runs in background, never throws.
   */
  _prefThrottle: new Map<number, number>(),
  async syncUserPreferences(localUserId: number, obligateUserId: number): Promise<void> {
    const now = Date.now();
    if (now - (this._prefThrottle.get(localUserId) ?? 0) < 60 * 1000) return;

    const raw = await appConfigService.getObligateRaw();
    if (!raw.url || !raw.apiKey) return;

    try {
      const res = await fetch(`${raw.url}/api/apps/user-preferences/${obligateUserId}`, {
        headers: { 'Authorization': `Bearer ${raw.apiKey}` },
      });
      if (!res.ok) return;
      this._prefThrottle.set(localUserId, now);

      const { success, data } = await res.json() as { success: boolean; data?: {
        preferredTheme?: string; toastEnabled?: boolean; toastPosition?: string;
        preferredLanguage?: string; anonymousMode?: boolean; profilePhotoUrl?: string | null;
      } };
      if (!success || !data) return;

      // Sync language + avatar columns
      const colUpdate: Record<string, unknown> = {};
      if (data.preferredLanguage) colUpdate.preferred_language = data.preferredLanguage;
      if (data.profilePhotoUrl !== undefined) colUpdate.avatar = data.profilePhotoUrl;
      if (Object.keys(colUpdate).length > 0) {
        await db('users').where({ id: localUserId }).update(colUpdate);
      }

      // Sync UI prefs into preferences JSON
      const uiPrefs: Record<string, unknown> = {};
      if (data.preferredTheme) uiPrefs.preferredTheme = data.preferredTheme;
      if (data.toastEnabled !== undefined) uiPrefs.toastEnabled = data.toastEnabled;
      if (data.toastPosition) uiPrefs.toastPosition = data.toastPosition;
      if (data.anonymousMode !== undefined) uiPrefs.anonymousMode = data.anonymousMode;
      if (Object.keys(uiPrefs).length > 0) {
        const row = await db('users').where({ id: localUserId }).select('preferences').first() as { preferences: unknown } | undefined;
        const existing = (typeof row?.preferences === 'string' ? JSON.parse(row.preferences) : row?.preferences) ?? {};
        await db('users').where({ id: localUserId }).update({
          preferences: JSON.stringify({ ...existing, ...uiPrefs }),
        });
      }
    } catch { /* non-critical */ }
  },

  /**
   * Get the list of connected apps from Obligate (for cross-app nav buttons).
   */
  async getConnectedApps(obligateUserId?: number | null): Promise<ConnectedAppEntry[]> {
    const raw = await appConfigService.getObligateRaw();
    if (!raw.url || !raw.apiKey) return [];

    // Scope to the user's Obligate entitlements when we know who they are.
    // Without the userId, Obligate returns EVERY connected app, so the
    // header app switcher would show apps the user has no access to.
    const url = obligateUserId
      ? `${raw.url}/api/apps/connected?userId=${encodeURIComponent(obligateUserId)}`
      : `${raw.url}/api/apps/connected`;
    try {
      const res = await fetch(url, {
        headers: { 'Authorization': `Bearer ${raw.apiKey}` },
        // Every open tab asks every 5 min, and the SSO redirect asks too
        // (getRegisteredAppOrigin): a hung Obligate must not hang either.
        signal: AbortSignal.timeout(CONNECTED_APPS_TIMEOUT_MS),
      });
      if (!res.ok) return [];
      const data = await res.json() as { success?: unknown; data?: unknown };
      return shapeConnectedApps(data.data);
    } catch {
      return [];
    }
  },

  /**
   * client_id for the browser-facing `/authorize` URL. That URL goes through
   * the browser (Location header, history, Referer, proxy logs): the value is
   * PUBLIC, so it is `obligatePublicClientId(apiKey)` and never the key.
   *
   * Obligate resolves the public form first and still accepts the raw key as a
   * legacy form — but records every raw use on the app, flags it "Clé API
   * exposée" on its Connected Apps page, mints it no delegation token, and
   * refuses it outright where `OAUTH_ACCEPT_RAW_CLIENT_ID` excludes the type.
   * Sending the hash does NOT clear that flag: only regenerating the key in
   * Obligate does (the old one has been through browsers).
   *
   * A configured `clientId` (setting or OBLIGATE_CLIENT_ID) still takes
   * precedence — that is the seam for a provider-issued public id — EXCEPT
   * when it is the API key itself. The previous header of /sso-redirect told
   * operators to set `OBLIGATE_CLIENT_ID=<key>` to get SSO working; an install
   * that followed it would keep publishing the key through every hop.
   */
  authorizeClientId(raw: { apiKey: string | null; clientId: string | null }): string | null {
    if (!raw.apiKey) return null;
    if (raw.clientId && raw.clientId !== raw.apiKey) return raw.clientId;
    if (raw.clientId && !warnedClientIdIsApiKey) {
      warnedClientIdIsApiKey = true;
      logger.warn(
        'Obligate SSO: the configured client_id IS the API key — ignored, sha256(api key) is sent instead. '
          + 'Clear the client id setting / OBLIGATE_CLIENT_ID, and regenerate the key in Obligate: it has been through browsers.',
      );
    }
    return obligatePublicClientId(raw.apiKey);
  },

  /**
   * Origin of this instance's own registration in Obligate (the base URL
   * Obligate and the other apps' switchers send browsers to).
   *
   * Obliance picks "the only app of my type" and gives up when there are two.
   * ObliWAN reads Obligate's `self` marker first — resolved by Obligate from
   * our Bearer key, so it names THIS registration even beside a staging
   * ObliWAN on the same Obligate — and falls back to the single-app-of-type
   * rule only for an Obligate too old to send `self`.
   * Cached 5 min; `refresh` bypasses the cache unless it is under 30 s old.
   */
  _originCache: null as { origin: string | null; at: number } | null,
  async getRegisteredAppOrigin(refresh = false): Promise<string | null> {
    const now = Date.now();
    const cached = this._originCache;
    if (cached && now - cached.at < (refresh ? ORIGIN_CACHE_MIN_REFRESH_MS : ORIGIN_CACHE_TTL_MS)) {
      return cached.origin;
    }
    const apps = await this.getConnectedApps();
    // No app at all is a failed fetch (we are registered ourselves): not cached.
    if (apps.length === 0) return null;
    const selfEntries = apps.filter((a) => a.self === true);
    let origin: string | null = null;
    if (selfEntries.length === 1) {
      origin = toHttpOrigin(selfEntries[0].baseUrl);
    } else {
      const own = apps.filter((a) => a.appType === OWN_APP_TYPE);
      if (own.length > 1) {
        logger.error(
          { baseUrls: own.map((a) => a.baseUrl) },
          'Obligate SSO: several ObliWAN apps are registered and Obligate does not say which one is this instance — set APP_URL to its public URL',
        );
      }
      origin = own.length === 1 ? toHttpOrigin(own[0].baseUrl) : null;
    }
    this._originCache = { origin, at: now };
    return origin;
  },

  /**
   * Check the public origin a browser reached us through — derived from the
   * Host / X-Forwarded-* headers, which any client can forge, and which the
   * client nginx forwards as `$host`, i.e. WITHOUT the port — against the
   * origins this app is really published under: APP_URL / CLIENT_ORIGIN when
   * set, then its base URL in Obligate. Matches on host[:port], or on the
   * hostname alone when the candidate carries no port. Only a TRUSTED origin
   * is ever returned — its scheme and port win over the headers — so a forged
   * Host can at most pick another of our own origins. Null when the host is
   * none of them. Same contract as Obliance's verifyPublicOrigin.
   *
   * The redirect_uri is built from this. Obligate already refuses a
   * redirect_uri outside the app's registered origin, so this is the second
   * barrier on that side; on this side it is the first, and it is also what
   * puts the PORT back that nginx's `$host` dropped (an instance on :3004
   * used to send Obligate `http://host/auth/callback`).
   */
  async verifyPublicOrigin(candidate: string): Promise<string | null> {
    const origin = toHttpOrigin(candidate);
    if (!origin) return null;
    const { host, hostname, port } = new URL(origin);
    const match = (trusted: Array<string | null>): string | null => {
      const list = trusted.filter((o): o is string => o !== null);
      if (list.includes(origin)) return origin;
      return list.find((o) => new URL(o).host === host)
        ?? (port === '' ? list.find((o) => new URL(o).hostname === hostname) : undefined)
        ?? null;
    };
    return match([envOrigin('APP_URL'), envOrigin('CLIENT_ORIGIN')])
      ?? match([await this.getRegisteredAppOrigin()])
      // The base URL may just have been changed in Obligate — retry uncached.
      ?? match([await this.getRegisteredAppOrigin(true)]);
  },

  /**
   * Where to restart the SSO flow when the browser reached us through a host
   * this app is not published under (LAN IP, second DNS name…): APP_URL, else
   * the base URL in Obligate, else CLIENT_ORIGIN. Loopback origins are skipped
   * (they would send the browser to its own machine). Null when none is known.
   */
  async getCanonicalOrigin(): Promise<string | null> {
    const usable = (o: string | null): o is string => o !== null && !isLoopbackOrigin(o);
    const appUrl = envOrigin('APP_URL');
    if (usable(appUrl)) return appUrl;
    const registered = await this.getRegisteredAppOrigin();
    if (usable(registered)) return registered;
    const clientOrigin = envOrigin('CLIENT_ORIGIN');
    return usable(clientOrigin) ? clientOrigin : null;
  },
};
