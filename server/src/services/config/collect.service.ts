// ============================================================================
// ObliWAN — L0/L1 acquisition: getting a config off a box, safely.
// ============================================================================
//
// Implements the target pipeline ("Le pipeline cible") and the frozen
// acquisition command of the RouterOS normalisation design, under two rules:
// identity is proven before any operation, and no secret may enter a snapshot.
//
// ┌─ FOUR THINGS THIS FILE REFUSES TO MAKE CONFIGURABLE ──────────────────────┐
// │                                                                           │
// │ 1. THE EXPORT COMMAND IS FROZEN PER FAMILY, AND IT ASKS FOR NO SECRET.    │
// │    `routerOsExportCommand(family)` (one table, in the driver) spells it:  │
// │    `/export terse hide-sensitive` on RouterOS 6, which prints secrets     │
// │    unless told not to, and `/export terse` on RouterOS 7, which hides     │
// │    them unless told to show them. Nothing here — no parameter, option or  │
// │    column — can change it, and a family the table does not know is        │
// │    refused before any socket. Our rule: a secret must never enter a       │
// │    snapshot, a diff, the UI or a log; a flag someone can flip is a flag   │
// │    someone will flip. Before the command, the box is asked its version on │
// │    the same SSH connection and a major that contradicts the family is     │
// │    refused before any export is requested. Behind it,                     │
// │    `assertNoSensitiveMaterial()` below REFUSES any export that still      │
// │    carries a secret (a script source, a comment, a stale family the box   │
// │    would not say) before anything is written anywhere.                    │
// │                                                                           │
// │ 2. NO PTY. `ssh2.exec()` without `pty: true`. RouterOS wraps long lines   │
// │    with `\` continuations as a function of terminal width when it thinks  │
// │    it is talking to a human; the export then depends on the width of a    │
// │    terminal that does not exist. `terse` plus no pty is what makes the    │
// │    text reproducible (N13).                                               │
// │                                                                           │
// │ 3. IDENTITY FIRST, ALWAYS. Every path into this file goes through         │
// │    `withAssertedDevice()`. Reading is not writing, but a snapshot         │
// │    attributed to the wrong device is a lie stored forever, and the drift  │
// │    engine will later compare customer A's firewall to customer B's        │
// │    template. A PPP pool rotation is all it takes.                         │
// │                                                                           │
// │ 4. THE PARSER IS BOUND LATE, NOT IMPORTED. `normalize.service.ts` is a    │
// │    separate module and a separate file; a static import would make        │
// │    the whole collection path, the snapshot store and the drift engine     │
// │    fail to compile whenever it is mid-edit. The binding is a registry     │
// │    with a `require`-based fallback and a FAIL-CLOSED default: with no     │
// │    parser the collector REFUSES rather than storing an empty document.    │
// │    A collector that silently produced an empty NCM would hand the diff    │
// │    engine a device whose firewall "disappeared".                          │
// └───────────────────────────────────────────────────────────────────────────┘

import type { DeviceFamily, NcmDocument, TransportKind } from '@obliwan/shared';
import {
  FAMILY_BRAND,
  type NormalizationRule,
  type NormalizationTrace,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { decrypt } from '../secretVault.service';
import { DriverError } from '../drivers/types';
import { withSsh, type SshTransport } from '../transport/ssh.transport';
import {
  createRouterOsConnection,
  RouterOsTrapError,
  type RouterOsConnection,
} from '../transport/routeros';
import { withAssertedDevice, type BindingAssertion } from '../fleet/deviceBinding.service';
import { storeSnapshot, latestDocument, type StoreSnapshotResult } from './snapshot.service';
import {
  assertSshBoxSpeaksFamily,
  exportDialectWarning,
  findSensitiveProps,
  routerOsExportCommand,
  SENSITIVE_REFUSAL_HINT,
  stripLearningPlaceholders,
} from '../drivers/mikrotik/driver';

// ============================================================================
// The frozen L0 command
// ============================================================================

/**
 * The normalisation design: `terse` — one entry per line, no
 * width-dependent continuations — plus, on RouterOS 6 only, `hide-sensitive`.
 *
 * ┌─ IMPORTED, NOT RE-DECLARED ──────────────────────────────────────────────┐
 * │ This file used to carry its OWN copy of the literal, and the driver      │
 * │ carried another. Two constants, one contract, free to drift — and the    │
 * │ comment right here even explained the copy by saying it existed "so a    │
 * │ test can assert on the literal rather than on a re-typed copy of it,     │
 * │ which is how these things drift apart". It WAS the re-typed copy.        │
 * │                                                                          │
 * │ Both said `show-sensitive=no`, which no RouterOS accepts, so both were   │
 * │ wrong in the same way and fixing one would have left the other. The one  │
 * │ that replaced them, a bare `/export terse` for every family, was wrong   │
 * │ the other way: RouterOS 6 prints secrets unless told `hide-sensitive`.   │
 * │ There is now one table, `ROUTEROS_EXPORT_FLAGS` in the driver that owns  │
 * │ the dialect, and this file only asks it for the family's spelling. See   │
 * │ the driver for why the two majors need two spellings.                    │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
export { routerOsExportCommand };

/**
 * The families this file can actually read.
 *
 * ┌─ WHY THE REFUSAL IS HERE AND NOT AT THE CALL SITES ───────────────────────┐
 * │ Everything below is RouterOS: the frozen command is a RouterOS menu path, │
 * │ and the only normaliser that exists is `normalizeRouterOsExport`. Nothing │
 * │ in the acquisition path checked the BRAND, so before this guard a         │
 * │ collection aimed at a Vigor, a USG or a TZ opened an SSH session to a     │
 * │ customer's firewall, typed the RouterOS export command at it, and         │
 * │ failed forty seconds later as a PROTOCOL_ERROR — indistinguishable, from  │
 * │ the operator's seat, from a router that has broken. The other outcome is  │
 * │ worse: a CLI that answers something the RouterOS parser tolerates files a │
 * │ document describing a device that does not exist, and the drift engine    │
 * │ then compares it to a template with the full confidence of a machine.     │
 * │                                                                           │
 * │ So the refusal is BEFORE the connection, it names the family, and it      │
 * │ lives in the collector rather than in the controller: the scheduled drift │
 * │ collection and the intervention snapshot come through this same door, and │
 * │ a guard only the button honours is not a guard.                           │
 * │                                                                           │
 * │ Adding a family here is not a list edit. It means another brand's export  │
 * │ command, another normaliser and another set of normalisation rules —      │
 * │ which is why the list is the honest statement of what was built, not a    │
 * │ policy.                                                                   │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
export const COLLECTABLE_FAMILIES: readonly DeviceFamily[] = [
  'mikrotik_routeros6',
  'mikrotik_routeros7',
];

/**
 * Narrows `devices.family` to a family this collector understands, or refuses.
 *
 * The `null` branch is unreachable through the schema — `devices.family` is
 * `NOT NULL` with a CHECK over the seven families (migration 002) — and is kept
 * because the row type here is nullable and a silently-guessed family would
 * file a snapshot against the wrong model.
 */
export function assertCollectableFamily(deviceId: number, family: string | null): DeviceFamily {
  if (family === null || family === '') {
    throw new DriverError(
      `device ${deviceId} has no family recorded; the collector cannot know which export ` +
        'dialect to speak and will not guess one',
      'NOT_IMPLEMENTED',
      { retryable: false },
    );
  }
  if (!(COLLECTABLE_FAMILIES as readonly string[]).includes(family)) {
    throw new DriverError(
      `ObliWAN has no configuration collector for family '${family}'. The RouterOS ` +
        "'/export terse' (with 'hide-sensitive' on RouterOS 6) is the only acquisition path " +
        'this build carries, and it is RouterOS-only — the device was not dialled',
      'NOT_IMPLEMENTED',
      { retryable: false },
    );
  }
  return family as DeviceFamily;
}

/**
 * Thrown when an export carries a NON-EMPTY value for a property RouterOS
 * classes as sensitive: the redaction did not happen (the export was spelled
 * for the wrong major because `devices.family` is stale, or a firmware ignored
 * its flag), or a secret sits where RouterOS never redacts (a script source, a
 * comment).
 *
 * When it fires the collection is ABORTED and nothing is stored. Not "stored
 * with a warning": the whole point of the no-secrets rule is that the secret never reaches the
 * store, and a snapshot we then have to scrub is a snapshot that already
 * existed.
 *
 * `cause` is the dialect sentence (`exportDialectWarning()`) when the export's
 * own preamble contradicts the family it was spelled for. It travels IN the
 * refusal because the refusal is all the caller gets: the collection's
 * `warnings` are never returned once this is thrown.
 */
export class SensitiveMaterialError extends Error {
  /** The first offending prop, kept for callers that read one. */
  readonly prop: string;
  readonly props: readonly string[];
  constructor(props: readonly string[], deviceId: number, cause?: string | null) {
    super(
      `Export for device ${deviceId} carries a value for sensitive prop(s) ` +
        `[${props.join(', ')}]. ${cause ? `${cause} ` : ''}${SENSITIVE_REFUSAL_HINT}`,
    );
    this.name = 'SensitiveMaterialError';
    this.prop = props[0] ?? '';
    this.props = props;
  }
}

/**
 * The no-secrets rule's last gate before the store. Reports PROP NAMES and never a value — an
 * error message is a log line, and a log line is exactly what that rule forbids a
 * secret from reaching.
 *
 * ┌─ ONE DETECTOR, THE DRIVER'S ──────────────────────────────────────────────┐
 * │ The detection is `findSensitiveProps()` from the driver that owns the     │
 * │ dialect — the same rule `backup.service.ts` runs over each pulled `.rsc`. │
 * │ This file used to carry its OWN list: thirteen names, matched only after  │
 * │ whitespace or `;`, so `ipsec-secret=`, `tcp-md5-key=`, `preshared-key=`,  │
 * │ the SNMPv3 `authentication-password=` / `encryption-password=` all        │
 * │ passed — while the driver's header credited it to a different list that   │
 * │ ran nowhere on this path. Two lists for one rule is how that happened.    │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
export function assertNoSensitiveMaterial(
  raw: string,
  deviceId: number,
  cause?: string | null,
): void {
  const props = findSensitiveProps(raw);
  if (props.length > 0) throw new SensitiveMaterialError(props, deviceId, cause);
}

// ============================================================================
// The normaliser registry (fail closed)
// ============================================================================

/**
 * The context frozen by the normalisation design, restated structurally
 * rather than imported from `normalize.service.ts`.
 *
 * The shape is the parser's, field for field, so the late binding below can
 * hand it straight through. Restating it is what keeps the dependency one-way
 * and OPTIONAL — and what keeps the absence of a parser a loud failure instead
 * of an empty document.
 */
export interface NormalizeContextInput {
  /** The device the document will be attributed to. The parser needs it to
   *  fill `NcmDocument.device`, which carries the identity triple. */
  deviceId: number;
  tenantId: number;
  family: DeviceFamily;
  osVersion: string | null;
  /** Already ordered by the frozen comparison. The engine must not
   *  re-sort: two sorts is two orders waiting to disagree. */
  rules: NormalizationRule[];
  /** `'<sectionPath>|<prop>' -> value`, from `routeros_defaults`. */
  defaults: Map<string, string>;
  via: TransportKind;
  capturedAt?: string;
  /** The design case 2 — the pairing reference for ordinal assignment. */
  previous?: NcmDocument | null;
}

/** Structurally what the normalisation design froze. Declared as a local
 *  shape rather than imported so this module carries no compile-time dependency
 *  on the parser (see below). */
export interface NormalizeOutput {
  ncm: NcmDocument;
  osVersion: string | null;
  model: string | null;
  serial: string | null;
  traces: NormalizationTrace[];
  unknownProps: Array<{ sectionPath: string; prop: string }>;
  warnings: string[];
}

export type NormalizeFn = (raw: string, ctx: NormalizeContextInput) => NormalizeOutput;

let normalizeImpl: NormalizeFn | null = null;
let autoBindAttempted = false;

/** Called at boot, or by a test that wants a double. The last registration
 *  wins, and an explicit registration always beats the auto-binding below. */
export function registerNormalizer(fn: NormalizeFn): void {
  normalizeImpl = fn;
  autoBindAttempted = true;
}

/** For tests that registered a double and must not leak it into the next one. */
export function clearNormalizer(): void {
  normalizeImpl = null;
  autoBindAttempted = false;
}

/**
 * Late binding to `normalize.service.ts`, ON PURPOSE, through `require` rather
 * than an `import`.
 *
 * The parser is a separate module and a separate file. A static import
 * would make this module — and therefore the whole collection path, the
 * snapshot store and the drift engine — fail to compile whenever the parser is
 * mid-edit. A late binding keeps the dependency one-way and OPTIONAL, and the
 * fail-closed default below keeps its absence loud instead of turning it into
 * an empty document.
 */
function autoBind(): NormalizeFn | null {
  if (autoBindAttempted) return normalizeImpl;
  autoBindAttempted = true;
  try {

    const mod = require('./normalize.service') as Record<string, unknown>;
    const fn = mod.normalizeRouterOsExport ?? mod.normalize;
    if (typeof fn === 'function') normalizeImpl = fn as NormalizeFn;
  } catch {
    normalizeImpl = null;
  }
  return normalizeImpl;
}

export function hasNormalizer(): boolean {
  return autoBind() !== null;
}

export class NoNormalizerError extends Error {
  constructor() {
    super(
      'No NCM normaliser is registered. Refusing to build a document: an empty NCM would ' +
        'read, to the diff engine, as a device whose entire configuration vanished.',
    );
    this.name = 'NoNormalizerError';
  }
}

function requireNormalizer(): NormalizeFn {
  const fn = autoBind();
  if (!fn) throw new NoNormalizerError();
  return fn;
}

// ============================================================================
// Loading the normalisation ruleset for one device
// ============================================================================

interface RuleRow {
  id: number;
  uuid: string;
  builtin_key: string | null;
  scope: string;
  scope_id: number | null;
  brand: string | null;
  family: string | null;
  os_min: string | null;
  os_max: string | null;
  name: string;
  description: string;
  rationale: string;
  false_negative: string;
  layer: number;
  kind: string;
  section_path: string | null;
  section_ordered: boolean;
  prop: string | null;
  pattern: string | null;
  replacement: string | null;
  predicate: unknown;
  value: unknown;
  target_path: string | null;
  severity: string | null;
  apply_order: number;
  enabled: boolean;
}

function toRule(r: RuleRow): NormalizationRule {
  return {
    id: Number(r.id),
    uuid: r.uuid,
    builtinKey: r.builtin_key,
    scope: r.scope as NormalizationRule['scope'],
    scopeId: r.scope_id === null ? null : Number(r.scope_id),
    brand: r.brand as NormalizationRule['brand'],
    family: r.family as NormalizationRule['family'],
    osMin: r.os_min,
    osMax: r.os_max,
    name: r.name,
    description: r.description,
    rationale: r.rationale,
    falseNegative: r.false_negative,
    layer: r.layer as NormalizationRule['layer'],
    kind: r.kind as NormalizationRule['kind'],
    sectionPath: r.section_path,
    sectionOrdered: r.section_ordered,
    prop: r.prop,
    pattern: r.pattern,
    replacement: r.replacement,
    predicate: (r.predicate ?? null) as NormalizationRule['predicate'],
    value: r.value ?? null,
    targetPath: r.target_path,
    severity: r.severity as NormalizationRule['severity'],
    applyOrder: Number(r.apply_order),
    enabled: r.enabled,
  };
}

/**
 * The EFFECTIVE rule set for one device, already ordered.
 *
 * The ORDER BY duplicates `compareNormalizationRules()` from the shared
 * package on purpose — the study froze it in SQL and in TypeScript, and the
 * ordering must be identical whichever side sorts. `normalizationEpoch` is
 * computed from this exact list, so a difference between the two would produce
 * an epoch that does not describe what was applied.
 *
 * Scope resolution: `global` always, `brand` on a brand match, `device` on this
 * device, `group` on any group the device belongs to.
 */
export async function loadNormalizationRules(
  deviceId: number,
  tenantId: number,
  family: DeviceFamily | null,
): Promise<NormalizationRule[]> {
  const brand = family ? FAMILY_BRAND[family] : null;

  const rows = await db<RuleRow>('normalization_rules as nr')
    // THE TENANT'S OWN RULES **PLUS THE SHARED LIBRARY**.
    //
    // `tenant_id IS NULL` is the shipped doctrine (N01..N16 and the ~150
    // generated state/sort/default rules), seeded tenant-less by
    // `db/seeds/002_ncm_doctrine.ts` since migration
    // `013_normalization_shared.ts`. The same convention 008 froze for
    // `templates` / `template_partials`.
    //
    // This predicate used to be a bare `.where(tenant_id, tenantId)` against
    // a doctrine seeded to tenant #1, which meant EVERY OTHER TENANT
    // NORMALISED WITH AN EMPTY RULE SET. Not a degraded
    // mode: an unnormalised export changes its `ncm_hash` on every
    // collection, so `config_snapshots` gained a row per collect and every
    // drift run reported that churn as findings.
    //
    // NOTE FOR ANY FUTURE EDIT: this must stay a GROUPED `OR`. Written flat
    // it would bind against the `andWhere` chain below and let a rule of
    // ANOTHER tenant through on the `IS NULL` alternative.
    .where((qb) => {
      void qb.where('nr.tenant_id', tenantId).orWhereNull('nr.tenant_id');
    })
    .andWhere('nr.enabled', true)
    .andWhere((qb) => {
      // No orWhere when there is no brand to match: the whereNull above already
      // covers "rule applies to every brand", and a NUL sentinel cannot travel
      // to a PostgreSQL text column (the driver rejects the parameter).
      void qb.whereNull('nr.brand');
      if (brand !== null) void qb.orWhere('nr.brand', brand);
    })
    .andWhere((qb) => {
      void qb.whereNull('nr.family');
      if (family !== null) void qb.orWhere('nr.family', family);
    })
    .andWhere((qb) => {
      void qb
        .where('nr.scope', 'global')
        .orWhere((b) => {
          void b.where('nr.scope', 'brand').whereNotNull('nr.brand');
        })
        .orWhere((b) => {
          void b.where('nr.scope', 'device').andWhere('nr.scope_id', deviceId);
        })
        .orWhere((b) => {
          // `devices.group_id` is a single nullable column (migration 002), not
          // a membership table. Only the DIRECT group matches: inheriting down
          // the `device_groups` tree would silently apply a parent's rule to a
          // device nobody scoped it to, and a normalisation rule is allowed to
          // HIDE a change. Widening this is a deliberate act, not a default.
          void b.where('nr.scope', 'group').whereIn(
            'nr.scope_id',
            db('devices').select('group_id').where('id', deviceId).whereNotNull('group_id'),
          );
        });
    })
    // layer, then scope specificity, then apply_order, then id — the design, frozen.
    .orderByRaw(
      "nr.layer ASC, CASE nr.scope WHEN 'global' THEN 0 WHEN 'brand' THEN 1 " +
        "WHEN 'group' THEN 2 ELSE 3 END ASC, nr.apply_order ASC, nr.id ASC",
    )
    .select('nr.*');

  return rows.map(toRule);
}

/**
 * The learned default-value oracle of N09, keyed `'<sectionPath>|<prop>'`.
 *
 * NEVER EXTRAPOLATED ACROSS VERSIONS. The dictionary is indexed by EXACT
 * `os_version` because RouterOS changes which defaults it emits between minor
 * releases (N15); filling a prop with a 7.14 default on a 7.15 box is a
 * fleet-wide false negative — the diff would stop seeing a real change on
 * every device at once. With no `osVersion` the map is empty and
 * `default_fill` simply does not run, which is the safe direction.
 *
 * `conflicting = true` rows are excluded: a default two devices disagree about
 * is not a default, it is a configuration.
 */
export async function loadDefaults(
  family: DeviceFamily | null,
  osVersion: string | null,
): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  if (!family || !osVersion) return out;
  const rows = await db('routeros_defaults')
    .where({ family, os_version: osVersion, conflicting: false })
    .select('section_path', 'prop', 'default_value');
  for (const r of rows as { section_path: string; prop: string; default_value: unknown }[]) {
    const v = r.default_value;
    out.set(
      `${r.section_path}|${r.prop}`,
      typeof v === 'string' ? v : typeof v === 'number' || typeof v === 'boolean' ? String(v) : JSON.stringify(v),
    );
  }
  return out;
}

// ============================================================================
// The raw read
// ============================================================================

export interface CollectedRaw {
  /** The export EXACTLY as the box produced it, header included. Never
   *  normalised on disk — `config_snapshots.raw_gz` is the recoverable proof
   *  the day a normalisation rule turns out to be wrong. */
  raw: string;
  via: 'ssh' | 'routeros_api';
  /** Facts the API gave us that the redacted export does not state reliably.
   *  This is the whole of "API en complément": it never SUBSTITUTES for the
   *  export, because the API returns counters, `.id`s and computed flags that
   *  are noise source number one (N03-N06). */
  osVersion: string | null;
  model: string | null;
  serial: string | null;
  warnings: string[];
  durationMs: number;
}

interface TransportRow {
  transport: string;
  host: string | null;
  port: number | null;
  username: string | null;
  secret_enc: string | null;
  use_tls: boolean | null;
  tls_fingerprint_sha256: string | null;
  enabled: boolean;
  priority: number;
  params: Record<string, unknown> | null;
}

interface DeviceRow {
  id: number;
  tenant_id: number;
  name: string;
  family: string | null;
  tunnel_ip: string | null;
}

async function loadDevice(deviceId: number, tenantId: number): Promise<DeviceRow> {
  const row = await db<DeviceRow>('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first('id', 'tenant_id', 'name', 'family', 'tunnel_ip');
  // Not "device not found in this tenant": the two answers must be the same
  // string, or the message itself is a cross-tenant existence oracle.
  if (!row) throw new DriverError(`Device ${deviceId} not found`, 'UNKNOWN', { retryable: false });
  return row;
}

async function loadTransports(deviceId: number): Promise<TransportRow[]> {
  return db<TransportRow>('device_transports')
    .where('device_id', deviceId)
    .andWhere('enabled', true)
    .orderBy('priority', 'asc')
    .select(
      'transport', 'host', 'port', 'username', 'secret_enc', 'use_tls',
      'tls_fingerprint_sha256', 'enabled', 'priority', 'params',
    );
}

/**
 * Run the family's frozen export command over an already-open SSH channel.
 *
 * Split out from the connection so the command, the pty decision, the exit-code
 * handling and the continuation check can all be tested against a double
 * without a router — which is the only way any of this is testable at all,
 * since there is no MikroTik in this environment.
 *
 * `family` only SELECTS the spelling (`routerOsExportCommand()`), and an
 * unknown one throws before `exec()` is reached. Then the box is asked its
 * version on this same connection (`assertSshBoxSpeaksFamily()`, two execs on
 * one session), and a major that contradicts `family` — or a version read that
 * fails — is refused before the export is requested: on RouterOS 6 the wrong
 * spelling would print every secret into this process before the read-back
 * could refuse to store it.
 */
export async function runExport(
  ssh: Pick<SshTransport, 'exec'>,
  family: DeviceFamily,
  opts: { timeoutMs?: number } = {},
): Promise<{ raw: string; warnings: string[] }> {
  const command = routerOsExportCommand(family);
  await assertSshBoxSpeaksFamily(ssh, family, { timeoutMs: opts.timeoutMs });
  const result = await ssh.exec(command, {
    // NEVER a pty. See the header of this file, and N13.
    pty: false,
    timeoutMs: opts.timeoutMs ?? 60_000,
    maxOutputBytes: 16 * 1024 * 1024,
  });

  if (result.code !== null && result.code !== 0) {
    // The family is named because the likeliest cause after a firmware upgrade
    // is the inventory: the two majors take different flags, and a box that
    // moved from 6 to 7 (or was enrolled under the wrong one) is asked in the
    // other dialect. stderr is RouterOS's own complaint about the command line
    // — the same text the warnings below already surface.
    throw new DriverError(
      `'${command}' (the ${family} spelling) exited with code ${result.code}: ` +
        `${result.stderr.trim().slice(0, 200) || 'no stderr'}. If this device runs another ` +
        'RouterOS major than its recorded family, correct the family.',
      'PROTOCOL_ERROR',
      { transport: 'ssh', retryable: false },
    );
  }

  const raw = result.stdout;
  if (raw.trim().length === 0) {
    // An empty export is NOT an empty router. Treating it as one would hand the
    // diff engine a device whose entire configuration disappeared, and — but
    // for N3 — a plan to recreate it.
    throw new DriverError(
      'export returned no output; refusing to treat that as an empty configuration',
      'PARSE_ERROR',
      { transport: 'ssh', retryable: true },
    );
  }

  const warnings: string[] = [];
  // N13: a `\` at end of line means the box wrapped the output, which means a
  // pty was allocated somewhere. The text is then terminal-width dependent and
  // will produce phantom drift the day the width changes.
  if (/\\\r?\n/.test(raw)) {
    warnings.push(
      'export contains line continuations (\\): a pty was allocated on the export channel — ' +
        'the text is terminal-width dependent (N13)',
    );
  }
  if (result.stderr.trim().length > 0) {
    warnings.push(`export channel wrote to stderr: ${result.stderr.trim().slice(0, 200)}`);
  }
  // The SECOND check of the family, from the export's own preamble. It can
  // disagree only when the version read above stated nothing usable, and it is
  // then the one sign the export was spelled for the wrong major. The read-back
  // in `collectRaw()` decides whether the text may be stored and carries this
  // same sentence in its refusal; here it is the warning for the case where
  // nothing was refused.
  const dialect = exportDialectWarning(raw, family);
  if (dialect) warnings.push(dialect);
  return { raw, warnings };
}

/** `!trap` = "this menu does not exist here". An answer, not a failure. */
async function optionalRow(
  conn: RouterOsConnection,
  path: string,
): Promise<Record<string, string> | null> {
  try {
    return await conn.queryFirst([path]);
  } catch (err) {
    if (err instanceof RouterOsTrapError) return null;
    return null;
  }
}

/**
 * The API COMPLEMENT — and nothing more.
 *
 * Three facts the redacted export header states inconsistently across RouterOS
 * 6 and 7 (N01), and which we need OUTSIDE the hash: `os_version` and `model`
 * are `config_snapshots` columns precisely because a firmware upgrade must be
 * visible without creating a snapshot, and `serial` is one leg of the
 * identity triple carried inside the document.
 *
 * Deliberately NOT used to enrich the resources themselves. The API returns
 * counters, `.id`s and computed flags — noise source number one the moment it
 * touches configuration.
 */
async function readApiComplement(
  device: DeviceRow,
  transports: TransportRow[],
): Promise<{ osVersion: string | null; model: string | null; serial: string | null; warning: string | null }> {
  const api = transports.find((t) => t.transport === 'routeros_api');
  const host = api?.host ?? device.tunnel_ip;
  if (!api || !host || !api.username || !api.secret_enc) {
    return { osVersion: null, model: null, serial: null, warning: null };
  }
  let conn: RouterOsConnection | null = null;
  try {
    conn = await createRouterOsConnection({
      host,
      port: api.port ?? undefined,
      tls: api.use_tls === true,
      username: api.username,
      password: decrypt(api.secret_enc),
      expectedFingerprint: api.tls_fingerprint_sha256,
      connectTimeoutMs: 10_000,
      label: `collect:${device.name}`,
    });
    const resource = await optionalRow(conn, '/system/resource/print');
    const board = await optionalRow(conn, '/system/routerboard/print');
    return {
      osVersion: resource?.version ?? null,
      model: resource?.['board-name'] ?? board?.model ?? null,
      serial: board?.['serial-number'] ?? null,
      warning: null,
    };
  } catch (err) {
    // A missing complement is a degraded collection, never a failed one: the
    // export is the source of truth and it already succeeded.
    return {
      osVersion: null,
      model: null,
      serial: null,
      warning: `API complement unavailable: ${err instanceof Error ? err.message : String(err)}`,
    };
  } finally {
    conn?.close();
  }
}

export interface CollectOptions {
  timeoutMs?: number;
  /** Skip the API complement (used by tests and by a device with no API
   *  transport). The export alone is a valid collection. */
  skipApiComplement?: boolean;
}

/**
 * Read the configuration off one device.
 *
 * IDENTITY IS ASSERTED FIRST, on a fresh connection, through the one sanctioned
 * door (`withAssertedDevice`). A snapshot filed against the wrong device is not
 * a cosmetic error: the drift engine will compare it to a template it was never
 * meant to obey, and every finding after that is nonsense with the confidence
 * of a machine behind it.
 */
export async function collectRaw(
  deviceId: number,
  tenantId: number,
  options: CollectOptions = {},
): Promise<CollectedRaw & { assertion: BindingAssertion }> {
  const device = await loadDevice(deviceId, tenantId);
  // Before the transports, and before any socket: "we have not written this
  // collector" is a different answer from "this device has no SSH channel", and
  // the operator fixes them in different places. The narrowed family is also
  // what spells the export (`runExport` → `routerOsExportCommand`).
  const family = assertCollectableFamily(deviceId, device.family);
  const transports = await loadTransports(deviceId);

  const ssh = transports.find((t) => t.transport === 'ssh');
  if (!ssh || !ssh.host || !ssh.username) {
    // ── Honest refusal, and it stays a refusal ─────────────────────────────
    // The API cannot substitute for `/export`: the design is explicit that it returns
    // much more than the export (counters, `.id`s, computed flags) and that
    // using it as the source is noise source number one — i.e. drift noise, the risk
    // that kills the product, and the reason drift detection carries a hard "fewer than 3
    // noise findings per device" criterion.
    //
    // What changed is only the SENTENCE. The old one stated the doctrine —
    // "the API is a complement, never a substitute" — which is a note to
    // whoever maintains this file and tells the operator reading it on a
    // screen nothing they can act on. A refusal an operator cannot act on is
    // indistinguishable from a broken product.
    const hasApi = transports.some((t) => t.transport === 'routeros_api');
    throw new DriverError(
      `Configuration collection needs an SSH channel on device ${deviceId}, and it has `
      + `${ssh ? 'one that is incomplete (no host or no username)' : 'none enabled'}. `
      + 'Add it on the device page, Settings tab, "Add a channel" — SSH on port 22, with the '
      + 'same service account.'
      + (hasApi
        // Said explicitly, because the operator is looking at a device whose
        // RouterOS API works and will reasonably expect it to be enough.
        ? ' The RouterOS API channel this device already has cannot stand in: it returns far '
          + 'more than `/export` — counters, internal `.id`s, computed flags — and normalising '
          + 'that would report a changed byte-counter as configuration drift on every run.'
        : ''),
      'NO_TRANSPORT',
      { transport: 'ssh', retryable: false },
    );
  }

  return withAssertedDevice(deviceId, async (assertion) => {
    const startedAt = Date.now();
    const warnings: string[] = [];

    const params = (ssh.params ?? {}) as { legacyAlgorithms?: boolean };
    const { raw, warnings: exportWarnings } = await withSsh(
      {
        host: ssh.host as string,
        port: ssh.port ?? 22,
        username: ssh.username as string,
        password: ssh.secret_enc ? decrypt(ssh.secret_enc) : null,
        timeoutMs: options.timeoutMs ?? 30_000,
        legacyAlgorithms: params.legacyAlgorithms === true,
      },
      (channel) => runExport(channel, family, { timeoutMs: options.timeoutMs }),
    );
    warnings.push(...exportWarnings);

    // The secrets gate, before anything is written anywhere — and carrying the dialect
    // cause, if any: thrown here, `warnings` is never returned or logged.
    assertNoSensitiveMaterial(raw, deviceId, exportDialectWarning(raw, family));

    let osVersion: string | null = null;
    let model: string | null = null;
    let serial: string | null = null;
    if (!options.skipApiComplement) {
      const complement = await readApiComplement(device, transports);
      osVersion = complement.osVersion;
      model = complement.model;
      serial = complement.serial;
      if (complement.warning) warnings.push(complement.warning);
    }

    return {
      raw,
      via: 'ssh' as const,
      osVersion,
      model,
      serial,
      warnings,
      durationMs: Date.now() - startedAt,
      assertion,
    };
  });
}

// ============================================================================
// The whole L0 -> L3 path
// ============================================================================

export interface CollectAndStoreResult {
  snapshot: StoreSnapshotResult;
  warnings: string[];
  /** N05 of the normalisation study: props the parser saw and does not know.
   *  Surfaced, not swallowed — it is the model's own backlog. */
  unknownProps: Array<{ sectionPath: string; prop: string }>;
  durationMs: number;
}

/**
 * Collect -> normalise -> store, in one call, for one device.
 *
 * The three stages are separate functions so each is testable on its own, and
 * they are joined here so no caller can do the store without the secrets gate or
 * the normalisation without the identity assertion.
 */
export async function collectAndStore(
  deviceId: number,
  tenantId: number,
  options: CollectOptions & { source?: string } = {},
): Promise<CollectAndStoreResult> {
  const normalize = requireNormalizer();
  const collected = await collectRaw(deviceId, tenantId, options);

  const device = await loadDevice(deviceId, tenantId);
  // Re-asserted rather than carried over from `collectRaw`: this is the argument
  // that selects the normalisation ruleset, and one narrowing that both the
  // acquisition and the normalisation read is one rule, not two copies of it.
  const family = assertCollectableFamily(deviceId, device.family);

  const stored = await normalizeAndStore(normalize, {
    deviceId,
    tenantId,
    family,
    raw: collected.raw,
    osVersion: collected.osVersion,
    model: collected.model,
    source: (options.source as StoreSnapshotResult['source']) ?? 'ssh',
  });

  if (collected.warnings.length > 0 || stored.warnings.length > 0) {
    logger.warn(
      { deviceId, warnings: [...collected.warnings, ...stored.warnings] },
      'Configuration collected with warnings',
    );
  }

  return {
    snapshot: stored.snapshot,
    warnings: [...collected.warnings, ...stored.warnings],
    unknownProps: stored.unknownProps,
    durationMs: collected.durationMs,
  };
}

/**
 * The normalise + store tail every entry into `config_snapshots` from this file
 * shares. Private: its callers have already run the secrets gate on `raw`.
 */
async function normalizeAndStore(
  normalize: NormalizeFn,
  input: {
    deviceId: number;
    tenantId: number;
    family: DeviceFamily;
    raw: string;
    osVersion: string | null;
    model: string | null;
    source: StoreSnapshotResult['source'];
  },
): Promise<{ snapshot: StoreSnapshotResult; warnings: string[]; unknownProps: NormalizeOutput['unknownProps'] }> {
  const { deviceId, tenantId, family } = input;
  const [rules, defaults, previous] = await Promise.all([
    loadNormalizationRules(deviceId, tenantId, family),
    loadDefaults(family, input.osVersion),
    // The design case 2: the parser assigns ordinals by pairing with the PREVIOUS
    // document. `storeSnapshot` re-runs the same reconciliation at the store
    // boundary — idempotent, and the guarantee does not then depend on which
    // parser produced the document.
    latestDocument(deviceId),
  ]);

  const result = normalize(input.raw, {
    deviceId,
    tenantId,
    family,
    osVersion: input.osVersion,
    rules,
    defaults,
    via: 'ssh',
    previous: previous?.doc ?? null,
  });

  const snapshot = await storeSnapshot({
    deviceId,
    tenantId,
    source: input.source,
    raw: input.raw,
    doc: result.ncm as NcmDocument,
    osVersion: input.osVersion ?? result.osVersion,
    model: input.model ?? result.model,
    normalizationTraces: result.traces,
  });
  return { snapshot, warnings: result.warnings, unknownProps: result.unknownProps };
}

// ============================================================================
// Learning mode — the observed state from a capture
// ============================================================================

/**
 * A snapshot from a LEARNING capture (services/learning/capture.service.ts):
 * the second, and only other, entry into `config_snapshots` from this file.
 *
 * ┌─ WHAT IS STORED, AND THROUGH WHICH GATE ─────────────────────────────────┐
 * │ `text` is the learning copy (`secret:<ref>` in place of every vaulted     │
 * │ value, withheld lines as comments). `stripLearningPlaceholders()` turns  │
 * │ it into what the ordinary collection would have stored — the props       │
 * │ removed, as RouterOS 7 prints them without `show-sensitive` — and the    │
 * │ UNCHANGED gate (`assertNoSensitiveMaterial`, no placeholder allowed)     │
 * │ judges the result before anything is normalised or written. So the       │
 * │ `ncm_hash` equals the one a normal collect of the same box would give,   │
 * │ and the two dedupe on `UNIQUE(device_id, ncm_hash)`.                      │
 * │                                                                          │
 * │ IDENTITY is proven by the caller, on the SAME SSH session that exported  │
 * │ (identity, serial and management-tunnel login against the record),      │
 * │ not here through `withAssertedDevice()` — there is no second socket and  │
 * │ no RouterOS API binding. That is what gives a legacy router without the   │
 * │ API an observed state at all, which the miner and the extrapolator then  │
 * │ read like any other snapshot. A line withheld for a secret inside a       │
 * │ script is absent from it.                                                │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
export async function storeSnapshotFromLearning(input: {
  deviceId: number;
  tenantId: number;
  family: string | null;
  text: string;
  osVersion: string | null;
  model: string | null;
}): Promise<StoreSnapshotResult> {
  const normalize = requireNormalizer();
  const family = assertCollectableFamily(input.deviceId, input.family);
  const raw = stripLearningPlaceholders(input.text);
  assertNoSensitiveMaterial(raw, input.deviceId);
  if (raw.trim() === '') {
    throw new DriverError('the learning copy is empty once its placeholders are removed', 'PARSE_ERROR', {
      transport: 'ssh',
      retryable: false,
    });
  }
  const stored = await normalizeAndStore(normalize, {
    deviceId: input.deviceId,
    tenantId: input.tenantId,
    family,
    raw,
    osVersion: input.osVersion,
    model: input.model,
    source: 'ssh',
  });
  return stored.snapshot;
}
