// ============================================================================
// @obliwan/shared — WHICH l2tp-client is the management tunnel
// ============================================================================
//
// The identity check compares the PPP login a router dials with against the device's
// `ppp_username`. A router may carry several l2tp-clients (a store with
// `l2tp-infra` beside `l2tp-mgmt`, created in either order), and only ONE of
// them is the tunnel ObliWAN reaches the box through. Every customer names
// that one `l2tp-mgmt`, ON PURPOSE (operator decision, 2026-10-04): the name
// is what tells it apart, so the name is the rule.
//
//   1. The l2tp-client NAMED exactly `l2tp-mgmt` is the management tunnel and
//      its `user` IS the login, whatever it says: another account there is a
//      CONTRADICTION (the box at this address dials as somebody else, which
//      `compareIdentity` scores as a mismatch), a blank one is unreadable.
//   2. No client of that name (a box configured before the convention, a
//      bench file naming it otherwise): the ONE client whose user equals the
//      recorded login, when exactly one does — the box itself says it dials
//      with this device's account.
//   3. Anything else — no client at all, none carrying the recorded login,
//      several carrying it, no recorded login to look for — is NO READING:
//      the login is unknown, neither a match nor a mismatch, and the identity
//      rests on the other attributes (`compareIdentity` fails closed when
//      nothing else corroborates).
//
// Rule 2 never yields a mismatch: it finds the recorded login or nothing.
// That is deliberate. Without the name, a client carrying another login is
// not evidence about the management tunnel — it is whatever other tunnel the
// store runs — and a proven mismatch QUARANTINES the device.
//
// What this replaces: every reader took THE FIRST l2tp-client (`queryFirst`
// on the API, the first `l2tp|` line on the console). `find` order is
// creation order, not meaning, so a store whose other tunnel was created
// first read as another account's router: the reconciliation's attach
// refused it, and any later identity check would have quarantined it.
//
// PURE: no I/O. The API path (`deviceBinding.readRouterOsIdentity`) and the
// console path (`managementAccess` `SSH_READS.l2tp` + `parseL2tpClients`, the
// reconciliation's attach proof) read the clients their own way and decide
// HERE, so the two transports cannot disagree about which tunnel is meant.

/** The name every customer gives its management tunnel, on purpose. */
export const MANAGEMENT_TUNNEL_NAME = 'l2tp-mgmt';

/** One `/interface l2tp-client` entry, as either transport read it. */
export interface L2tpClientReading {
  /** The interface name, as the box printed it. */
  name: string | null;
  /** The client's `user`: the PPP login it dials with. */
  user: string | null;
}

export type ManagementTunnelLogin =
  /** Rule 1: the client named `l2tp-mgmt`; `login` is its user (null when
   *  blank), to be COMPARED — it may well be another account. */
  | { found: 'named'; login: string | null }
  /** Rule 2: no `l2tp-mgmt`, and exactly one client carries the recorded
   *  login; `login` is that client's spelling of it. */
  | { found: 'sole_match'; login: string }
  /** Rule 3: no reading. `no_client`: the box has no l2tp-client;
   *  `no_match`: none named `l2tp-mgmt` and none carries the recorded login;
   *  `ambiguous`: several carry it (or, impossibly on RouterOS, several
   *  clients are named `l2tp-mgmt`); `unrecorded`: no `l2tp-mgmt`, and no
   *  recorded login to look for. */
  | { found: 'none'; login: null; why: 'no_client' | 'no_match' | 'ambiguous' | 'unrecorded' };

/** `compareIdentity`'s normalisation: trimmed, case-folded, blank = none. */
function folded(value: string | null | undefined): string | null {
  const v = value?.trim();
  return v ? v.toLowerCase() : null;
}

/**
 * The login the box's management tunnel dials with, by the rule above.
 * `recordedLogin` is the device's `ppp_username` (or, before a device exists,
 * the login the site's allocation froze); it is used ONLY by rule 2, to find
 * the one client carrying it — never to judge the named client.
 */
export function managementTunnelLogin(
  clients: readonly L2tpClientReading[],
  recordedLogin: string | null | undefined,
): ManagementTunnelLogin {
  if (clients.length === 0) return { found: 'none', login: null, why: 'no_client' };
  const named = clients.filter((c) => (c.name ?? '').trim() === MANAGEMENT_TUNNEL_NAME);
  if (named.length === 1) {
    const user = named[0].user?.trim();
    return { found: 'named', login: user ? user : null };
  }
  if (named.length > 1) return { found: 'none', login: null, why: 'ambiguous' };
  const want = folded(recordedLogin);
  if (want === null) return { found: 'none', login: null, why: 'unrecorded' };
  const carrying = clients.filter((c) => folded(c.user) === want);
  if (carrying.length === 0) return { found: 'none', login: null, why: 'no_match' };
  if (carrying.length > 1) return { found: 'none', login: null, why: 'ambiguous' };
  return { found: 'sole_match', login: (carrying[0].user as string).trim() };
}
