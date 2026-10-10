// ============================================================================
// ObliWAN — a PPP login with SEVERAL sessions at once on its concentrator
// ============================================================================
//
// Incident 2026-10-09: on the shared CHR, `/ppp/active` listed TWO sessions for
// one store's login, both handed the same remote address — the store's router,
// up for three days, and a forgotten router in the shop, on 4G, up for two
// hours. The CHR routes that address to the NEWEST session, so whatever ObliWAN
// dialled at the tunnel address was the forgotten box, and the bulk attach
// proved it and attached it as the store's router.
//
// Such a login is AMBIGUOUS: its tunnel address reaches whichever session the
// concentrator routes to, and nothing on ObliWAN's side can tell which box will
// answer. So ObliWAN says so (the reconciliation lists every such login, with
// each session's caller-id and uptime) and refuses to act on it: the bulk attach
// does not attach it, and the jobs that dial the router through the tunnel
// refuse before their preflight backup (`PPP_DUPLICATE_REFUSAL`). Nothing is
// ever written to the concentrator about it — kicking a session or changing the
// profile is the operator's gesture, made on the CHR.
//
// Shared by the server (which records and enforces) and the client (which only
// renders).

/** The refusal's code: a job's `error_kind`, an attach row's reason. */
export const PPP_DUPLICATE_REFUSAL = 'duplicate_sessions' as const;

/** One of the sessions a duplicated login holds, as `/ppp/active` printed it.
 *  Never carries a password: `/ppp/active` has none to give. */
export interface PppDuplicateSession {
  /** The session's own spelling of the login (sessions are grouped without
   *  regard to case, like every login comparison in ObliWAN). */
  name: string;
  /** `caller-id`: the peer's public address for L2TP (a MAC for PPPoE),
   *  exactly as printed. */
  callerId: string | null;
  /** The tunnel address the session was handed. */
  address: string | null;
  /** RouterOS's own uptime text at the read (`3d02:11:05`, `2h1m4s`). */
  uptime: string | null;
  /** The read's instant minus that uptime: when the CHR says this session
   *  came up. Null when the uptime could not be read. */
  since: string | null;
}

/**
 * RouterOS uptime in seconds: `1w2d3h4m5s`, `3h4m5s`, `45s`, and the older
 * `2d03:04:05` / `03:04:05` shapes. Null when it is neither — never 0: an
 * unreadable uptime is unknown, not "just came up".
 */
export function parseRouterOsUptimeSeconds(raw: string | null | undefined): number | null {
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

/** "caller 203.0.113.7 (up 3d02:11:05), caller 198.51.100.4 (up 02:01:00)" —
 *  the sessions as a refusal names them: caller-ids and uptimes, nothing else. */
export function describeDuplicateSessions(sessions: readonly PppDuplicateSession[]): string {
  return sessions
    .map((s) => `caller ${s.callerId ?? 'unknown'}${s.uptime ? ` (up ${s.uptime})` : ''}`)
    .join(', ');
}
