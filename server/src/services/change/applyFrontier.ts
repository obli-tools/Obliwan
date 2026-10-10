// ============================================================================
// ObliWAN — the write frontier of a generic change job, as a fact both halves read
// ============================================================================
//
// `apply.service.ts` drives a job; `safeApply.service.ts` (the executor) does
// the I/O. Between the dead-man being armed and the first configuration command
// leaving for the router there is a window in which a job can still fail —
// a render refusal, a vault value the barriers refuse, a session that does not
// open, the kill switch read again. In that window NOTHING has been sent, and
// the on-box net protects nothing: left armed, its scheduler fires at the
// deadline and `/system/backup/load` reboots the router into the configuration
// it already had. A reboot nobody decided, for a write that never happened.
//
// So the queue takes the net down in that window — and only in that window.
// The question "may a configuration command have reached the router?" must
// therefore be answered by the code that sends, at the line where it sends.
//
// ┌─ THE MARKER IS AN EXONERATION, NEVER AN ACCUSATION ───────────────────────┐
// │ An executor marks an error `nothingTransmitted` only on a path where it   │
// │ is CERTAIN no configuration was executed: before the first command that   │
// │ runs configuration (RouterOS: `/system/script/run` of the staged apply    │
// │ script; staging that script configures nothing). Every other error —      │
// │ including a timeout AFTER that command was handed to the socket, an       │
// │ executor that does not know this module, a fake in a harness — reads as   │
// │ "may have landed", and the net stays armed exactly as it always did.      │
// │ Unknown is treated as sent.                                               │
// │                                                                          │
// │ `DeviceSession.run` uses the same marker for ONE sentence: an error it    │
// │ raised before handing the sentence to the socket (an audit row it could   │
// │ not write, a secret assertion). The executor alone turns that into "the   │
// │ job transmitted nothing", and only for its frontier command.              │
// └───────────────────────────────────────────────────────────────────────────┘
//
// THE FRONTIER IS ALSO PERSISTED (migration 099, `crossWriteFrontier` in
// `apply.service.ts`): one UPDATE, immediately before that command, proves the
// job is still this worker's and stamps `change_jobs.transmit_started_at`. A
// worker that dies with the stamp still NULL leaves the reaper certain that
// nothing was sent, and the leader then takes the net down in its place.

const NOTHING_TRANSMITTED = Symbol.for('obliwan.change.nothingTransmitted');

/**
 * Mark `err` as raised before any configuration command was transmitted, and
 * return it (a non-Error is wrapped). The error keeps its class, kind and
 * message: the marker is an extra, non-enumerable property, so a refusal still
 * reads as itself in the job's trace.
 */
export function markNothingTransmitted(err: unknown): Error {
  const e = err instanceof Error ? err : new Error(String(err));
  try {
    Object.defineProperty(e, NOTHING_TRANSMITTED, { value: true, enumerable: false });
  } catch {
    // A frozen error cannot carry the marker; it then reads as "may have
    // landed", which is the safe reading.
  }
  return e;
}

/** True only for an error an executor marked with `markNothingTransmitted`. */
export function wasNothingTransmitted(err: unknown): boolean {
  return (
    err instanceof Error &&
    (err as unknown as Record<symbol, unknown>)[NOTHING_TRANSMITTED] === true
  );
}

/**
 * What `releaseUnusedNet()` proved. Two facts, never folded into one: the
 * scheduler and script gone means the router will not reboot; the blob gone
 * means no copy of the customer's configuration is left on it. The blob is only
 * removed once the entries are proven gone (`disarmWithRetry`'s order), so
 * `blobRemoved` without `entriesRemoved` does not occur.
 */
export interface NetRelease {
  entriesRemoved: boolean;
  blobRemoved: boolean;
  /** Redacted, one sentence an operator can act on. */
  detail: string;
}
