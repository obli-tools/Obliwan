import { reachableAddress, type MndpCandidate } from './mndp';
import {
  FactoryProvisioningError,
  identifyFactoryBox,
  type DialFn,
  type FactoryBoxIdentification,
  type FactoryIdentifyRequest,
} from './routerosApply';

/**
 * ObliWAN bench — wait for a box that is rebooting, and take its MAC proof
 * again when it is back.
 *
 * ┌─ WHAT COMES BACK IS PROVEN, NOT ASSUMED ─────────────────────────────────┐
 * │ A box that reboots (a RouterOS upgrade, a device-mode change) is gone    │
 * │ for a minute and then something answers at its address again. That      │
 * │ something is only "the box" once it has passed the SAME proof as before  │
 * │ the reboot: login, then the typed MAC among the router's own interfaces  │
 * │ (`identifyFactoryBox`). MNDP-by-MAC says where to dial, as at the first  │
 * │ search; the address the box had is the fallback. A box that answers     │
 * │ there with ANOTHER MAC ends the wait at once (`OTHER_BOX`): two boxes    │
 * │ on the bench, and waiting longer would not make the right one answer.    │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The wait is bounded (`deadline`), and every attempt is short (3 s to open
 * the session), so the elapsed time the screen shows moves while it waits.
 * Reading only: nothing is written to the box from here.
 *
 * ┌─ ON A PC WITH SEVERAL BENCH LINKS (slots.ts) ────────────────────────────┐
 * │ Every factory box answers 192.168.88.1: where a box is, is the LINK it  │
 * │ was heard on (`MndpCandidate.localAddress`), and each attempt leaves    │
 * │ FROM that link's address. A box heard on another link than before (the  │
 * │ technician moved its cable) is dialled there: the MAC proof decides, as │
 * │ everywhere. Nothing heard: the link the box was last on, again.         │
 * │ `deadline` may be a function: the application lengthens the wait by the │
 * │ time the box's link spent DOWN (a cable pulled and put back), so that a │
 * │ box plugged in again on its port is still waited for.                   │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

export type BoxWaitVerdict = 'done' | 'wait' | { fail: string };

export interface BoxWaitOptions {
  req: FactoryIdentifyRequest;
  /** Absolute time (ms, `now()` clock) after which the wait gives up; a
   *  function is asked again at every attempt (a deadline that moves). */
  deadline: number | (() => number);
  /** Pause between two attempts. Default 5 s. */
  pollMs?: number;
  dial?: DialFn;
  discover?: (mac: string) => Promise<MndpCandidate | null>;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  /**
   * Called with every box that passed the proof. `sawItGo` is true once an
   * attempt failed to reach it — the reboot was observed. `done` ends the
   * wait with this identity, `wait` keeps polling, `{ fail }` ends it with
   * `BoxWaitError('REFUSED', fail)`.
   */
  accept: (identity: FactoryBoxIdentification, sawItGo: boolean) => BoxWaitVerdict;
  /** After every attempt: elapsed ms since the wait started, what was seen,
   *  and — for an attempt that failed — why (the router's or transport's own
   *  words when there are some), so that a wait never just counts in silence. */
  onTick?: (elapsedMs: number, seen: 'absent' | 'present', lastError?: string | null) => void;
}

export type BoxWaitErrorCode = 'TIMEOUT' | 'OTHER_BOX' | 'AUTH' | 'REFUSED' | 'UNVERIFIABLE';

export class BoxWaitError extends Error {
  constructor(
    readonly code: BoxWaitErrorCode,
    message: string,
    /** The last box that passed the proof, if one did. */
    readonly lastSeen: FactoryBoxIdentification | null,
    readonly sawItGo: boolean,
  ) {
    super(message);
    this.name = 'BoxWaitError';
  }
}

const defaultSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export async function waitForBox(o: BoxWaitOptions): Promise<{
  identity: FactoryBoxIdentification;
  sawItGo: boolean;
  waitedMs: number;
  /** The bench link the proof was taken over (null: the OS routed it). */
  localAddress: string | null;
  /** The address the box answered on — MNDP's, or the request's. */
  host: string;
}> {
  const now = o.now ?? Date.now;
  const sleep = o.sleep ?? defaultSleep;
  const pollMs = o.pollMs ?? 5_000;
  const deadline = typeof o.deadline === 'function' ? o.deadline : () => o.deadline as number;
  const started = now();
  let sawItGo = false;
  let lastSeen: FactoryBoxIdentification | null = null;
  const tick = (seen: 'absent' | 'present', lastError: string | null = null) => {
    try {
      o.onTick?.(now() - started, seen, lastError);
    } catch {
      /* a broken progress callback must not end the wait */
    }
  };
  let localAddress = o.req.localAddress ?? null;
  for (;;) {
    let host = o.req.host;
    try {
      const c = o.discover ? await o.discover(o.req.expectedMac) : null;
      host = (c && reachableAddress(c)) || o.req.host;
      // Heard on a bench link: dial from it (it may be another one than
      // before — the box is found where it is, and proven there).
      if (c?.localAddress) localAddress = c.localAddress;
    } catch {
      /* no MNDP on this machine: the known address decides */
    }
    try {
      const identity = await identifyFactoryBox(
        { ...o.req, host, localAddress, timeouts: { connectMs: 3_000, requestMs: 10_000 } },
        { dial: o.dial },
      );
      lastSeen = identity;
      tick('present');
      const verdict = o.accept(identity, sawItGo);
      if (verdict === 'done') return { identity, sawItGo, waitedMs: now() - started, localAddress, host };
      if (verdict !== 'wait') throw new BoxWaitError('REFUSED', verdict.fail, identity, sawItGo);
    } catch (err) {
      if (err instanceof BoxWaitError) throw err;
      if (!(err instanceof FactoryProvisioningError)) throw err;
      if (err.code === 'MAC_MISMATCH') {
        const where = localAddress ? ` sur la prise de ce poste ${localAddress}` : '';
        throw new BoxWaitError(
          'OTHER_BOX',
          `Un autre routeur répond à l'adresse ${host}${where} : ce n'est pas celui de l'étiquette. Débranchez tous les autres routeurs de ${localAddress ? 'cette prise' : 'ce poste'}, laissez seulement celui-ci, puis recommencez.`,
          lastSeen,
          sawItGo,
        );
      }
      if (err.code === 'AUTH_FAILED') {
        throw new BoxWaitError(
          'AUTH',
          `Le routeur à l'adresse ${host} refuse maintenant le mot de passe de l'étiquette. Ne le débranchez pas et appelez un technicien.`,
          lastSeen,
          sawItGo,
        );
      }
      if (err.code === 'MAC_UNVERIFIABLE' || err.code === 'INVALID_INPUT') {
        throw new BoxWaitError('UNVERIFIABLE', err.message, lastSeen, sawItGo);
      }
      // CONNECT_FAILED / SESSION_LOST: not there (yet). That IS the reboot.
      sawItGo = true;
      tick('absent', `${host} : ${err.routerMessage ?? err.code}`);
    }
    if (now() + pollMs > deadline()) {
      throw new BoxWaitError(
        'TIMEOUT',
        lastSeen
          ? 'Le routeur n\'est pas revenu dans l\'état attendu dans le temps prévu.'
          : 'Le routeur n\'a plus répondu dans le temps prévu.',
        lastSeen,
        sawItGo,
      );
    }
    await sleep(pollMs);
  }
}

/** `7.21.1 (stable)` → `7.21.1`; `null` for anything else. */
export function bareVersion(version: string | null | undefined): string | null {
  const t = (version ?? '').trim().split(/\s+/)[0] ?? '';
  return t !== '' ? t : null;
}

/** `1 min 05 s` — what the screen shows for an elapsed time. */
export function frenchDuration(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  const m = Math.floor(s / 60);
  const r = s % 60;
  return m > 0 ? `${m} min ${String(r).padStart(2, '0')} s` : `${r} s`;
}
