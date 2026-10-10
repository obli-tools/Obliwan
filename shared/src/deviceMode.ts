// ObliWAN — RouterOS device-mode, and what it means for the dead-man.
//
// ┌─ WHY THIS IS AN INVENTORY FACT AND NOT A RUNTIME SURPRISE ────────────────┐
// │ Since RouterOS 7.13 MikroTik gates a handful of features behind           │
// │ `/system/device-mode`. One of them is `scheduler` — and `/system/         │
// │ scheduler … start-time=startup` is exactly how ObliWAN's dead-man         │
// │ reinstalls the pre-change config after a cut.                             │
// │                                                                          │
// │ On a unit in `home` mode that install is impossible, and — this is the    │
// │ part that makes it an inventory concern rather than an error path — it    │
// │ CANNOT BE FIXED REMOTELY. MikroTik requires a physical reset-button       │
// │ press, or a cold power cycle, within five minutes of the mode-change      │
// │ request. Deliberately: the whole point of the gate is that a remote       │
// │ attacker cannot lift it.                                                 │
// │                                                                          │
// │ Discovered at arming time, that is the right refusal at the worst         │
// │ possible moment: the plan is frozen, the pre-change backup has already    │
// │ been taken, and the operator learns one device at a time. Read as part    │
// │ of the inventory, the same fact is a column, a fleet query and a line on  │
// │ the device page — available while a change is still being PLANNED.        │
// └──────────────────────────────────────────────────────────────────────────┘
//
// This file holds the vocabulary and the interpretation. The RouterOS row is
// parsed in the MikroTik driver; nothing here knows the API wire format.

/**
 * The modes RouterOS prints. MikroTik's "Device-mode" page documents four:
 * `home`, `basic`, `advanced` (the default, "previously called
 * enterprise") and `rose`; `enterprise` stays because the builds that
 * predate the rename print it. Anything else a future firmware prints parses
 * to `null`. Knowing a mode is not inferring from it: only `home` yields a
 * verdict without its flag (`deadmanReadiness()`); every other mode needs the
 * `scheduler` flag printed.
 */
export const ROUTEROS_DEVICE_MODES = ['home', 'basic', 'advanced', 'enterprise', 'rose'] as const;
export type RouterOsDeviceMode = (typeof ROUTEROS_DEVICE_MODES)[number];

/**
 * Narrow an arbitrary string — a RouterOS row, a `varchar` coming back from
 * Postgres — to a mode this product has characterised, or to `null`.
 *
 * The one gate, used by the driver that reads the menu AND by the serialiser
 * that puts a stored row on the wire, so a value that got past the CHECK
 * constraint by some future path still cannot reach `deadmanReadiness()` as a
 * mode nobody has reasoned about.
 */
export function asRouterOsDeviceMode(raw: string | null | undefined): RouterOsDeviceMode | null {
  const value = (raw ?? '').trim().toLowerCase();
  return (ROUTEROS_DEVICE_MODES as readonly string[]).includes(value)
    ? (value as RouterOsDeviceMode)
    : null;
}

/**
 * What one read of `/system/device-mode/print` learned.
 *
 * THREE LEVELS OF "WE DO NOT KNOW", and collapsing any two of them is the bug
 * this shape exists to prevent:
 *
 *  1. The whole object is `null` — nobody asked, or the channel cannot ask
 *     (SNMP, or any of the three non-MikroTik brands). The concept does not
 *     apply and the UI shows nothing at all.
 *  2. `observedAt` is set but `mode` is `null` — we ASKED and the router did
 *     not answer. Pre-7.13 firmware has no such menu, and a service account
 *     without the right policy gets a trap on one that does. Those two are
 *     indistinguishable from here, which is why this is `unknown` and not
 *     "ungated".
 *  3. `mode` is known but a flag is `null` — the menu answered without
 *     printing that flag. See `deadmanReadiness()` for the asymmetry that
 *     follows.
 */
export interface RouterOsDeviceModeFacts {
  mode: RouterOsDeviceMode | null;
  /** `/system/scheduler` — the dead-man's own mechanism. */
  schedulerAllowed: boolean | null;
  /** `/tool/fetch` — how a RouterOS box pulls a file from the server. */
  fetchAllowed: boolean | null;
  /** The row as printed, verbatim, for the flags this model does not name.
   *  Feature toggles only: the menu carries no credential. */
  raw: Record<string, string> | null;
  /** When the question was PUT to the router — not when an answer arrived, so a
   *  refusing menu still timestamps the attempt. */
  observedAt: string;
}

/**
 * What a READER of a stored reading needs, and no more.
 *
 * `raw` is evidence, not input: it stays in the database and never crosses the
 * API, so the client holds this shape while the driver holds the full one. Both
 * therefore call the same `deadmanReadiness()` — the alternative is two copies
 * of the arming rule, which is exactly how `isPollable` drifted on the SIM fleet.
 */
export type DeviceModeReading =
  Pick<RouterOsDeviceModeFacts, 'mode' | 'schedulerAllowed' | 'fetchAllowed' | 'observedAt'>;

/**
 * Beyond this, a stored device-mode is reported as stale.
 *
 * `enterprise` -> `home` needs no physical access (only the permissive
 * direction does), so a mode read months ago is a claim about the past. Thirty
 * days is the same order as the config-collection cadence: long enough that a
 * quiet fleet is not permanently yellow, short enough that "we checked" still
 * means something.
 */
export const DEVICE_MODE_MAX_AGE_DAYS = 30;

/** Can this unit carry an on-device dead-man? */
export type DeadmanFeasibility = 'capable' | 'blocked' | 'unknown';

export interface DeadmanReadiness {
  feasibility: DeadmanFeasibility;
  /** Observed, but longer ago than `DEVICE_MODE_MAX_AGE_DAYS`. Orthogonal to
   *  `feasibility`: a stale `blocked` is still the best evidence we have. */
  stale: boolean;
  /** Days since the read, or `null` when there has never been one. The reason
   *  `observedAt` is stored at all — a timestamp no decision consults is not a
   *  guard. */
  ageDays: number | null;
}

/**
 * Turn one read into the answer the planner and the device page both need.
 *
 * ┌─ THE ASYMMETRY, AND IT IS THE WHOLE RULE ────────────────────────────────┐
 * │ A DENIAL may be inferred from the mode. An ALLOWANCE may not.            │
 * │                                                                          │
 * │ `home` mode denies the scheduler — that is what the mode IS, documented, │
 * │ and the mode was READ off the router. So `home` with no `scheduler` flag │
 * │ printed yields `blocked`.                                                │
 * │                                                                          │
 * │ The reverse move is forbidden. `enterprise` "allows everything", and     │
 * │ MikroTik's device-mode table leaves `scheduler` out of what `basic`,     │
 * │ `advanced` and `rose` deny (`advanced` denies traffic-gen, container,    │
 * │ partitions, install-any-version and routerboard; see                     │
 * │ `MODE_DENIED` in server/src/bench/deviceModeGate.ts), so it is tempting  │
 * │ to read any of them as `capable` without the flag. That is defaulting a  │
 * │ missing answer to the permissive value, and the cost of being wrong is   │
 * │ not symmetric: a wrong `blocked` sends somebody on a site visit that was │
 * │ not needed, a wrong `capable` puts a change into the queue believing it  │
 * │ has a net it does not have, the project's first risk. So an              │
 * │ allowance needs the flag, printed, by the router.                        │
 * │                                                                          │
 * │ `unknown` is therefore NOT a failure state: it is the state every        │
 * │ device is in before the first probe, and it means exactly what ObliWAN   │
 * │ knew before this feature existed.                                        │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
export function deadmanReadiness(
  facts: DeviceModeReading | null,
  now: Date = new Date(),
): DeadmanReadiness {
  if (facts === null) return { feasibility: 'unknown', stale: false, ageDays: null };

  const observed = new Date(facts.observedAt).getTime();
  const ageDays = Number.isFinite(observed)
    ? Math.max(0, (now.getTime() - observed) / 86_400_000)
    : null;

  const feasibility: DeadmanFeasibility =
    facts.schedulerAllowed === false ? 'blocked'
      : facts.schedulerAllowed === true ? 'capable'
        : facts.mode === 'home' ? 'blocked'
          : 'unknown';

  return {
    feasibility,
    stale: ageDays !== null && ageDays > DEVICE_MODE_MAX_AGE_DAYS,
    ageDays,
  };
}
