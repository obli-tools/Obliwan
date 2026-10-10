// ============================================================================
// @obliwan/shared — reading a stored NCM document forward
// ============================================================================
//
// WE NEVER REWRITE STORED ROWS. The version bump happens AT READ TIME. Adding a
// resource to the model on 200 000 existing snapshots must be a new table plus
// a resumable backfill job, never a blocking migration that saturates the WAL
// and stops the collection.
//
// THE RULE THAT AVOIDS A FLEET-WIDE DRIFT STORM : an upgrader that
// adds a resource kind MUST set, on old documents,
//   coverage.<newKind> = { state: 'unsupported', reason: 'resource added in ncmVersion N' }
// and NEVER an empty array with `state: 'complete'`. Thanks to N3, the diff then
// refuses to emit a single `missing` for that kind on old snapshots. The
// coverage mechanism is therefore ALSO the anti-version-skew net — which is why
// it is a field of the document and not metadata on the SQL row.
//
// Verification owed by the drift engine: upgrading v1 -> v2 across 30 snapshots must produce
// ZERO findings.

import { NCM_VERSION, NcmDocument, NcmDocumentStored } from './model';

export class NcmVersionAheadError extends Error {
  readonly documentVersion: number;
  readonly supportedVersion: number;

  constructor(documentVersion: number, supportedVersion: number) {
    super(
      `NCM document is version ${documentVersion} but this build supports ${supportedVersion}. ` +
        'The row was written by a newer server (rollback in progress).',
    );
    this.name = 'NcmVersionAheadError';
    this.documentVersion = documentVersion;
    this.supportedVersion = supportedVersion;
  }
}

/** `drift_runs.status = 'error'` carries this reason when the above is thrown.
 *  A version-ahead document is NEVER diffed and NEVER stripped. */
export const NCM_VERSION_AHEAD_REASON = 'ncm_version_ahead';

export type Upgrader = (doc: Record<string, unknown>) => Record<string, unknown>;

/**
 * v1 -> v2: the `dhcpClient` resource kind (`resources.dhcpClients`, coverage
 * key `dhcpClient`).
 *
 * ┌─ THIS WAS MISSING WHILE NCM_VERSION WAS ALREADY 2 ───────────────────────┐
 * │ The kind was added and NCM_VERSION bumped to 2, but this table stayed     │
 * │ empty — so `upgradeNcm()` threw "missing NCM upgrader for v1 -> v2" on    │
 * │ EVERY snapshot stored before the bump, and drift, the intervention judge  │
 * │ and baseline mining all failed on them. The schema had been made          │
 * │ tolerant (optional coverage key, defaulted collection), which is why      │
 * │ nothing looked broken until a v1 document was actually read.             │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * It follows the rule at the top of this file to the letter: the new kind is
 * marked 'unsupported' on an old document — the parser that would have filled
 * it did not exist when the snapshot was taken — and NEVER an empty array with
 * 'complete'. Thanks to N3 the diff then emits no `missing` dhcpClient for any
 * old snapshot; 'complete' here would announce the disappearance of every DHCP
 * client in the fleet. Pure and idempotent: an already-present key is kept.
 */
const v1ToV2: Upgrader = (doc) => {
  const coverage = { ...((doc.coverage as Record<string, unknown> | undefined) ?? {}) };
  if (coverage.dhcpClient === undefined) {
    coverage.dhcpClient = {
      state: 'unsupported',
      via: null,
      reason: 'resource added in ncmVersion 2',
      recordCount: 0,
    };
  }
  const resources = { ...((doc.resources as Record<string, unknown> | undefined) ?? {}) };
  if (resources.dhcpClients === undefined) resources.dhcpClients = [];
  return { ...doc, ncmVersion: 2, coverage, resources };
};

/**
 * Pure, total, ordered. `UPGRADERS[n - 1]` takes a v(n) document to v(n+1).
 * Each one must be safe to re-run and must never throw on a valid v(n).
 * Its length must always be NCM_VERSION - 1.
 */
export const UPGRADERS: readonly Upgrader[] = [v1ToV2];

/**
 * Reads a stored document and brings it to the current version.
 *
 * Two documents of different `ncmVersion` are NEVER diffed directly — that is
 * the non-negotiable corollary of the design. Both sides go through this function
 * first.
 */
export function upgradeNcm(raw: unknown): NcmDocument {
  const stored = NcmDocumentStored.parse(raw);
  const version = stored.ncmVersion;

  if (version > NCM_VERSION) {
    throw new NcmVersionAheadError(version, NCM_VERSION);
  }
  if (version < 1 || !Number.isInteger(version)) {
    throw new Error(`NCM document carries an invalid ncmVersion (${String(version)})`);
  }

  let cur = stored as unknown as Record<string, unknown>;
  for (let v = version; v < NCM_VERSION; v++) {
    const up = UPGRADERS[v - 1];
    if (!up) throw new Error(`missing NCM upgrader for v${v} -> v${v + 1}`);
    cur = up(cur);
  }
  // Re-validated strictly: an upgrader that produced a malformed document must
  // fail here, in a job, and not three layers down inside the diff engine.
  return NcmDocument.parse(cur);
}

/** True when `raw` can be read at all by this build. Lets the collector decide
 *  between "skip this snapshot" and "fail the run" without a try/catch. */
export function isReadableNcm(raw: unknown): boolean {
  const v = (raw as { ncmVersion?: unknown } | null)?.ncmVersion;
  return typeof v === 'number' && Number.isInteger(v) && v >= 1 && v <= NCM_VERSION;
}
