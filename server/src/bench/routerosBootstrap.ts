import {
  RouterOsPool,
  type RouterOsConnection,
  type RouterOsTarget,
} from '../services/transport/routeros';
import {
  registerRouterOsChannelFactory,
  routerOsChannelFactoryFromPool,
  type RouterOsChannel,
} from '../services/drivers/mikrotik/routerosChannel';

/**
 * ObliWAN bench tool — the RouterOS channel factory, which nothing registered.
 *
 * ┌─ WHY EVERY MIKROTIK READ FAILED ON THE BENCH ────────────────────────────┐
 * │ The MikroTik driver never dials by itself: it asks                       │
 * │ `openRouterOsChannel()` for a channel, and that seam answers             │
 * │ `NO_TRANSPORT — RouterOS API pool is not wired` until a composition      │
 * │ root registers a factory. On the server, `fleet/routerosPool.ts` does    │
 * │ it. The bench never imports that file — it reads `device_health` and     │
 * │ the vault, i.e. the database — so in the bench process the factory was   │
 * │ null and "Lire l'identité" refused every RouterOS box before a single    │
 * │ packet left, CLI and GUI alike. MikroTik is the production brand.        │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Same two lines as `fleet/routerosPool.ts` — a `RouterOsPool`, wrapped by
 * `routerOsChannelFactoryFromPool` — so the bench speaks the protocol, the
 * login, and the error translation (`UNREACHABLE`, `AUTH_FAILED`, `TIMEOUT`…)
 * of the server, not a second implementation of them. What differs is the
 * lifetime, and each difference is deliberate:
 *
 *  - NO HOOKS. No `device_health`, no fingerprint pinning, no session fan-out:
 *    those are database writes about a device row that does not exist yet.
 *    Nothing here imports `db`, and the bundle's db stub would refuse if
 *    anything did.
 *
 *  - ONE POOL PER CHANNEL, shut down when the driver releases it. The server's
 *    pool is a process-wide singleton because it owns the single socket to the
 *    CHR and a breaker that must survive between polls. Neither exists
 *    here, and both would be wrong. The pool keys its session and its breaker
 *    on a target fingerprint (host, port, TLS, account, sha256 of the password)
 *    under one device id — and every bench read has the same device id, 0, and
 *    usually the same factory address and account:
 *      · a SHARED SESSION would be reused for the next box. Same address, same
 *        factory account, same password: same fingerprint, so the pool's
 *        "same target, session still ready" test would send the next box's read
 *        down the session opened to the PREVIOUS one — at best a dead socket
 *        and a confusing timeout, at worst an identity read off a router that
 *        is not the one in front of the preparer, which is exactly what the
 *        identity rule exists to prevent;
 *      · a SHARED BREAKER would carry one box's verdict to the next box with
 *        the SAME credentials. A box that refused the factory password opens
 *        it at once for `authBackoffMs` (15 minutes), so the next unit at the
 *        same address with the same sticker password would be refused without
 *        being dialled. Four connect failures in a row (a box still booting, a
 *        cable not yet plugged) open it for an exponential backoff of up to
 *        five minutes, so the click after the box comes up would be refused
 *        too. What it would NOT do is block a CORRECTED password: a different
 *        password is a different fingerprint, and the pool resets the breaker
 *        for a new target. So "the preparer fixes a typo" is not the reason;
 *        "the next box looks identical to the last one" is. The person at the
 *        bench is the breaker.
 *    The driver opens one channel per inventory (four menus on it), so this is
 *    one login per "Lire l'identité" — which is what a bench should cost.
 *
 *  - NO KEEPALIVE TIMER (`keepaliveMs: 0`): nothing outlives the read.
 *
 *  - AN EMPTY FACTORY PASSWORD IS A PASSWORD. Pre-2021 RouterBOARDs, every CHR,
 *    and any unit reset without a sticker password answer `admin` with an EMPTY
 *    password. `routerOsChannelFactoryFromPool` refuses an empty one before any
 *    dial ("no username/password in the vault"), which is right on the server —
 *    an empty vault secret there is a misconfiguration — and wrong here, where
 *    the preparer typed nothing because there is nothing to type. The adapter is
 *    shared with the server and stays as it is; the bench gets around its
 *    precondition, not around its protocol: see `BenchRouterOsPool`.
 */

/**
 * What the adapter's precondition is shown in place of an EMPTY password. It is
 * never sent: `BenchRouterOsPool` puts the real password into every target the
 * adapter builds, so this string exists only between the adapter's `if` and the
 * pool. Readable on purpose — if a future adapter ever printed the password it
 * holds, this is what would appear, and it is no secret.
 */
const EMPTY_PASSWORD_STAND_IN = '(empty factory password)';

/**
 * A pool that dials with the password the PREPARER typed, whatever the adapter
 * handed it. Subclassed rather than wrapped so `routerOsChannelFactoryFromPool`
 * receives a real `RouterOsPool` and keeps doing everything else — the query
 * words, `rowsOf`, the trap/auth/timeout translation the driver branches on.
 */
class BenchRouterOsPool extends RouterOsPool {
  constructor(private readonly factoryPassword: string) {
    super({}, { keepaliveMs: 0 });
  }

  override withConnection<T>(
    target: RouterOsTarget,
    fn: (conn: RouterOsConnection) => Promise<T>,
  ): Promise<T> {
    return super.withConnection({ ...target, password: this.factoryPassword }, fn);
  }
}

export function registerBenchRouterOsChannel(): void {
  registerRouterOsChannelFactory(async (channel, opts): Promise<RouterOsChannel> => {
    const typed = channel.credentials.password ?? '';
    const pool = new BenchRouterOsPool(typed);
    const shown = typed === ''
      ? { ...channel, credentials: { ...channel.credentials, password: EMPTY_PASSWORD_STAND_IN } }
      : channel;
    let inner: RouterOsChannel;
    try {
      inner = await routerOsChannelFactoryFromPool(pool)(shown, opts);
    } catch (err) {
      await pool.shutdown();
      throw err;
    }
    return {
      query: (path, options) => inner.query(path, options),
      async release() {
        try {
          await inner.release();
        } finally {
          await pool.shutdown();
        }
      },
    };
  });
}
