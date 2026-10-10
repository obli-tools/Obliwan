import './env';

/**
 * `APP_URL`, else an explicitly set `CLIENT_ORIGIN`, else nothing.
 *
 * Ported from Obliance's `publicUrlFromEnv()` so the five Obli* instances agree
 * on one rule instead of each inventing its own. The localhost rejection is the
 * load-bearing half: `CLIENT_ORIGIN` legitimately holds a dev address, and a
 * dev address in a password-reset mail is a link to the RECIPIENT's machine.
 * Empty is the honest answer, and the caller refuses to send on it.
 */
function publicUrlFromEnv(): string {
  const appUrl = (process.env.APP_URL || '').trim();
  if (appUrl) return appUrl.replace(/\/+$/, '');

  const clientOrigin = (process.env.CLIENT_ORIGIN || '').trim();
  try {
    const host = new URL(clientOrigin).hostname;
    if (
      host === 'localhost'
      || host.endsWith('.localhost')
      || host === '[::1]'
      || /^127\./.test(host)
    ) {
      return '';
    }
  } catch {
    // Unparseable or absent. Not a public URL either way.
    return '';
  }
  return clientOrigin.replace(/\/+$/, '');
}

/**
 * Execution role.
 *   web    : serves HTTP + Socket.io only. Never runs pollers or job runners.
 *   worker : background duties only (pollers, job queue, drift runs). No HTTP
 *            listener beyond /health.
 *   all    : single process doing both. The default, and what `docker compose
 *            up` gives you.
 *
 * Several `web` replicas may run side by side; the background duties are held
 * by ONE leader elected through a PostgreSQL advisory lock (leaderElection.ts).
 */
export const OBLIWAN_ROLES = ['web', 'worker', 'all'] as const;
export type ObliwanRole = (typeof OBLIWAN_ROLES)[number];

function readRole(): ObliwanRole {
  const raw = (process.env.OBLIWAN_ROLE || 'all').trim().toLowerCase();
  if (!(OBLIWAN_ROLES as readonly string[]).includes(raw)) {
    // Refuse to start rather than silently degrade: a typo'd OBLIWAN_ROLE that
    // fell back to 'all' would give two leaders pushing config to the same
    // fleet, which is exactly the failure mode leader election exists to prevent.
    throw new Error(
      `Invalid OBLIWAN_ROLE="${process.env.OBLIWAN_ROLE}". ` +
        `Expected one of: ${OBLIWAN_ROLES.join(' | ')}. ` +
        'Fix the value in your .env (see .env.example) and restart.',
    );
  }
  return raw as ObliwanRole;
}

/**
 * Dedicated credential-vault key.
 *
 * NOT USED YET: the vault itself (`secretVault.service.ts`, the `*_enc` columns
 * and the `key_version` column) arrives with migration 002. It
 * is read and validated HERE, from day one, so that an operator discovers a
 * missing or malformed key at first boot — not on the day the first device
 * credential fails to decrypt.
 *
 * Expected format: 64 hex characters (32 bytes). Generate with
 * `openssl rand -hex 32`.
 */
/**
 * Read the vault key and say WHAT is wrong with it, never what it is.
 *
 * "not 64 hexadecimal characters" describes two completely different mistakes
 * — a key of the wrong length, and a key generated in the wrong alphabet — and
 * an operator staring at a 44-character base64 string reads that message as
 * "but it IS a key". `openssl rand -base64 32` and a password generator both
 * produce something that looks exactly like a secret and is not hex.
 *
 * `flaw` therefore carries the shape of the error and NOTHING derived from the
 * value beyond its length: not the offending character, not its position, not a
 * prefix. A diagnostic that quotes the secret is a diagnostic that ends up in a
 * log aggregator.
 *
 * Non-hex is not a pedantry: `Buffer.from(key, 'hex')` does not throw on a bad
 * alphabet, it stops at the first invalid pair and silently returns a SHORTER
 * key. A base64 key beginning "3v" yields one byte.
 */
function readEncryptionKey(): {
  raw: string | null;
  valid: boolean;
  flaw: 'absent' | 'not-hex' | 'wrong-length' | null;
} {
  const raw = (process.env.OBLIWAN_ENCRYPTION_KEY || '').trim();
  if (!raw) return { raw: null, valid: false, flaw: 'absent' };
  if (/^[0-9a-fA-F]{64}$/.test(raw)) return { raw, valid: true, flaw: null };
  // Charset first: it is the mistake that reads as correct.
  const flaw = /^[0-9a-fA-F]*$/.test(raw) ? 'wrong-length' : 'not-hex';
  return { raw, valid: false, flaw };
}

const role = readRole();
const encryptionKey = readEncryptionKey();

export const config = {
  port: parseInt(process.env.PORT || '3001', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  isDev: (process.env.NODE_ENV || 'development') === 'development',

  // Execution role
  role,
  /** True when this process serves HTTP / Socket.io. */
  servesHttp: role === 'web' || role === 'all',
  /** True when this process is ALLOWED to run background duties — it still has
   *  to win the leader election before it actually does any. */
  runsBackground: role === 'worker' || role === 'all',

  // Database
  databaseUrl: process.env.DATABASE_URL || 'postgres://obliwan:changeme@localhost:5432/obliwan',

  // Session
  sessionSecret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  sessionMaxAge: 7 * 24 * 60 * 60 * 1000, // 7 days

  // Credential vault — see readEncryptionKey() above.
  encryptionKey: encryptionKey.raw,
  encryptionKeyValid: encryptionKey.valid,
  /** Which mistake, so the message can name it. Never the value. */
  encryptionKeyFlaw: encryptionKey.flaw,
  /** Length only — enough to tell 44-char base64 from a truncated hex key. */
  encryptionKeyLength: encryptionKey.raw?.length ?? 0,

  // CORS
  clientOrigin: process.env.CLIENT_ORIGIN || 'http://localhost:5173',

  // HTTPS — set to "true" if behind an HTTPS reverse proxy
  forceHttps: process.env.FORCE_HTTPS === 'true',

  // App name (used as prefix in SMS/push notifications)
  appName: process.env.APP_NAME || 'ObliWAN',

  // Default admin
  defaultAdminUsername: process.env.DEFAULT_ADMIN_USERNAME || 'admin',
  defaultAdminPassword: process.env.DEFAULT_ADMIN_PASSWORD || 'admin123',

  // 2FA bypass — set DISABLE_2FA_FORCE=true to skip forced 2FA requirement
  disable2faForce: process.env.DISABLE_2FA_FORCE === 'true',

  /**
   * The public address of this instance, for links that leave the server.
   *
   * ┌─ THE SUITE CONVENTION, PORTED FROM OBLIANCE RATHER THAN RE-INVENTED ────┐
   * │ `APP_URL` wins; an explicitly set `CLIENT_ORIGIN` is the fallback; and   │
   * │ the answer is EMPTY when neither yields a public address. In the Docker  │
   * │ deployment both name the same origin — nginx serves the web client and   │
   * │ proxies the API — so `CLIENT_ORIGIN` alone is the normal case and        │
   * │ `APP_URL` is the override for an instance published under a different    │
   * │ hostname than the one CORS checks.                                       │
   * │                                                                          │
   * │ NEVER the dev default, and never derived from a request header. A        │
   * │ localhost `CLIENT_ORIGIN` is a development value, not a public URL, so   │
   * │ it is rejected rather than stamped into a password-reset mail — which is │
   * │ exactly the bug this replaced: `appUrl` fell back to                     │
   * │ `http://localhost:5173`, `APP_URL` was set in no compose file, and every │
   * │ reset link in production pointed at the recipient's own machine.         │
   * │ Returning '' makes the caller REFUSE to send rather than send a broken   │
   * │ link, which is the difference between a visible failure and a silent one.│
   * │                                                                          │
   * │ A header-derived origin would be worse than either: `Host` is attacker-  │
   * │ controlled, and a reset link is the one mail where that matters.         │
   * └──────────────────────────────────────────────────────────────────────────┘
   */
  publicUrl: publicUrlFromEnv(),

  /**
   * ACS TR-069 / CWMP.
   *
   * ┌─ WHY THESE PORTS ARE NOT `config.port` ──────────────────────────────┐
   * │ The ACS is a SEPARATE Express app on a SEPARATE listener, and         │
   * │ it is the one thing in the suite that is not behind the client's      │
   * │ nginx. Two reasons, both structural:                                  │
   * │  - HTTP Digest. A reverse proxy that touches the request line or the  │
   * │    URI invalidates HA2 = MD5(method:uri) and every CPE fails to       │
   * │    authenticate, with no error anyone can read.                       │
   * │  - Long sessions. A CWMP session is a dozen POSTs over up to a few    │
   * │    minutes, and proxy buffering plus idle timeouts cut it in the      │
   * │    middle, which the CPE reports as a transfer failure days later.    │
   * │                                                                       │
   * │ 7547 and 7548 are ALREADY published by the compose files, and         │
   * │ nothing has been listening on them until now.                         │
   * └───────────────────────────────────────────────────────────────────────┘
   */
  cwmp: {
    /** Master switch. On by default: the ports are published, and a published
     *  port with nothing behind it is worse than an open one — it answers
     *  RST and the CPE logs "ACS unreachable" forever. */
    enabled: process.env.CWMP_ENABLED !== 'false',
    port: parseInt(process.env.CWMP_PORT || '7547', 10),
    bind: process.env.CWMP_BIND || '0.0.0.0',

    /**
     * TLS listener for CPEs provisioned with an `https://` ACS URL.
     * OPTIONAL and off unless a certificate is provided: a TLS server with a
     * self-signed certificate is worse than no TLS server at all, because a
     * CPE that cannot validate it retries forever instead of falling back.
     */
    tlsPort: parseInt(process.env.CWMP_TLS_PORT || '7548', 10),
    tlsCertPath: process.env.CWMP_TLS_CERT || '',
    tlsKeyPath: process.env.CWMP_TLS_KEY || '',

    /**
     * Public base URL the CPE is told to fetch firmware from.
     *
     * It is a SEPARATE knob from `clientOrigin` — and this one genuinely is
     * separate, unlike the `appUrl` that was just folded into it: the CPE
     * reaches the ACS from the CUSTOMER'S LINE, over CWMP on 7547, while
     * `clientOrigin` is where an operator's browser reaches the web UI. Those
     * two addresses are almost never the same, and on a fleet behind an L2TP
     * concentrator they are not even on the same network. Empty means "derive
     * it from the
     * Host header the CPE used", which is right in a single-homed deployment
     * and wrong the moment there is a NAT in front — hence the explicit knob.
     */
    publicBaseUrl: process.env.CWMP_PUBLIC_BASE_URL || '',

    /** Largest envelope the listener accepts. A GetParameterValuesResponse on
     *  a full TR-181 subtree is genuinely large; 8 MB is roughly ten times the
     *  worst real one and still small enough to bound memory at 300 sessions. */
    maxBodyBytes: parseInt(process.env.CWMP_MAX_BODY_BYTES || String(8 * 1024 * 1024), 10),

    /** A session with no POST for this long is abandoned and its in-flight
     *  task is returned to the queue. CPEs disappear mid-session constantly
     *  (the line drops, the box reboots); without a reaper each one would pin
     *  a task in `sent` forever. */
    sessionIdleSeconds: parseInt(process.env.CWMP_SESSION_IDLE_SECONDS || '180', 10),

    /** How long a download URL token stays fetchable. */
    downloadTokenTtlSeconds: parseInt(process.env.CWMP_DOWNLOAD_TTL_SECONDS || '3600', 10),

    /** Where firmware images and vendor config files live on disk. */
    fileStorageDir: process.env.CWMP_FILE_DIR || './data/cwmp-files',

    /** What a "please call back sooner" request lowers the interval to. This is
     *  the ONLY refresh mechanism the product has, and the UI says so
     *  (`CWMP_NO_CONNECTION_REQUEST_EXPLANATION`). */
    refreshIntervalSeconds: parseInt(process.env.CWMP_REFRESH_INTERVAL_SECONDS || '60', 10),
  },
};

/**
 * Startup validation. Called once from index.ts BEFORE anything connects.
 * Throws on a fatal misconfiguration; returns the non-fatal warnings so the
 * caller can log them through pino rather than console.
 */
/** Name the mistake. Reports the key's LENGTH and nothing else about it. */
function encryptionKeyFlawMessage(): string {
  const tail =
    'Generate one with: openssl rand -hex 32 — or, without openssl: '
    + 'node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))". '
    + 'Nothing is lost by replacing a key the vault has always refused: it never '
    + 'encrypted anything, so this is a correction, not a rotation.';

  if (config.encryptionKeyFlaw === 'not-hex') {
    return (
      `OBLIWAN_ENCRYPTION_KEY is ${config.encryptionKeyLength} characters long and `
      + 'contains characters outside the hexadecimal alphabet (0-9 and a-f only). It '
      + 'looks like a secret, which is why this is easy to miss: `openssl rand -base64 32` '
      + 'and password generators both produce one that is not hex. The vault needs base 16, '
      + `because Buffer.from(key, 'hex') does not reject a bad alphabet — it stops at the `
      + `first invalid pair and silently returns a much shorter key. ${tail}`
    );
  }
  return (
    `OBLIWAN_ENCRYPTION_KEY is valid hexadecimal but ${config.encryptionKeyLength} `
    + `characters long; the vault needs exactly 64 (32 bytes, AES-256). ${tail}`
  );
}

export function validateConfig(): string[] {
  const warnings: string[] = [];

  // Every placeholder this repository ships, not just the one the code happens to
  // default to. `docker-compose.yml` defaults to `change-this-in-production` and
  // `.env.example` to `change-this-to-a-random-secret`: a `docker compose up` with
  // no `.env` therefore started in PRODUCTION with a session secret printed in a
  // public repository, and this guard — which exists for exactly that case —
  // said nothing because it compared against a single literal.
  //
  // The length floor is the second half: a placeholder nobody thought to list is
  // still almost always short.
  const SHIPPED_PLACEHOLDERS = new Set([
    'dev-secret-change-me',
    'dev-secret',
    'change-this-in-production',
    'change-this-to-a-random-secret',
    'changeme',
    'secret',
  ]);
  const MIN_SESSION_SECRET_LENGTH = 32;

  if (!config.isDev) {
    const s = config.sessionSecret.trim();
    if (SHIPPED_PLACEHOLDERS.has(s.toLowerCase())) {
      throw new Error(
        `SESSION_SECRET is still the placeholder "${s}" shipped in this repository. `
          + 'Anyone can forge a session cookie against it. Generate one with: '
          + 'openssl rand -hex 32',
      );
    }
    if (s.length < MIN_SESSION_SECRET_LENGTH) {
      throw new Error(
        `SESSION_SECRET is ${s.length} characters; at least ${MIN_SESSION_SECRET_LENGTH} are `
          + 'required outside development. Generate one with: openssl rand -hex 32',
      );
    }
  }

  // ── The credential vault is not optional any more ─────────────────────────
  //
  // This was a WARNING, written when nothing was encrypted yet and the vault was
  // still ahead ("it WILL be fatal"). The vault shipped, and the warning outlived the
  // condition it described. The consequence was not theoretical: a production
  // instance with no key booted cleanly, served every page, listed the fleet —
  // and then failed the FIRST gesture that stores a password with a bare
  // `500 Internal server error`, because `VaultError` is neither an `AppError`
  // nor a driver error and fell through to the generic handler. Everything
  // looked healthy except the one thing the product is for.
  //
  // A fleet manager that cannot hold a credential cannot manage a fleet. It
  // says so at boot, where an operator is already reading the logs, rather than
  // in a toast three screens deep. This is the same treatment SESSION_SECRET
  // gets above, for the same reason.
  //
  // Development keeps the warning: a contributor running the UI against
  // fixtures has no business generating a key to look at a page.
  if (!config.isDev) {
    if (!config.encryptionKey) {
      throw new Error(
        'OBLIWAN_ENCRYPTION_KEY is not set. The credential vault cannot encrypt or '
          + 'decrypt anything, so no device password can be stored and no device can be '
          + 'reached. Generate one with: openssl rand -hex 32 — and keep it: losing it '
          + 'is unrecoverable, which is precisely why it is not derived from '
          + 'SESSION_SECRET.',
      );
    }
    if (!config.encryptionKeyValid) throw new Error(encryptionKeyFlawMessage());
  } else if (!config.encryptionKey) {
    warnings.push(
      'OBLIWAN_ENCRYPTION_KEY is not set. No device credential can be stored, and '
        + 'enrolling a device with a password will be refused. '
        + 'Generate one with: openssl rand -hex 32',
    );
  } else if (!config.encryptionKeyValid) {
    warnings.push(encryptionKeyFlawMessage());
  }

  return warnings;
}
