/**
 * ObliWAN — `assertTargetBinding()`.
 *
 * THE PROBLEM, STATED PLAINLY
 * The platform reaches a router at a tunnel address handed out by a PPP pool.
 * Pools reassign. If we push configuration to "10.66.0.11 because that is where
 * device 42 was yesterday", then one lease rotation is all it takes to write
 * customer A's firewall onto customer B's router. Nothing else in the stack
 * catches that: the connection succeeds, the credentials work, the commands
 * apply. It is a silent, total, cross-tenant failure.
 *
 * THE ANSWER
 * Identity is `ppp_username` + `system_identity` + `serial` — never an address.
 * Before any operation that targets a specific box, we open a FRESH connection
 * (not a pooled one that was established minutes or hours ago, possibly before
 * the lease moved) and ask the box who it is. If the answer does not match the
 * record, the operation is refused and the device is quarantined.
 *
 * THREE RULES THAT MAKE THIS WORTH HAVING
 *  1. FAIL CLOSED. If nothing could be verified — no identity channel, a
 *     brand with no probe path yet — the assertion FAILS. "We could not check"
 *     never means "go ahead".
 *  2. A FRESH SOCKET. Reusing the pool would prove the identity of whatever
 *     answered when the pool dialled, which is the very thing in question.
 *  3. ONE MISMATCH IS FATAL. Two matching attributes do not outvote one
 *     contradicting attribute: a box that agrees on `system_identity` (an
 *     operator-typed string, easily duplicated across a template fleet) and
 *     disagrees on `serial` is a different box.
 *
 * When this was written nothing wrote to a device. This function existed anyway, tested and
 * exported, so that when the write paths arrived there was exactly one door and
 * it was already locked.
 *
 * ┌─ ONE EXCEPTION TO THE IDENTITY RULE: CONFIRMED WITHOUT A HUMAN ───────────┐
 * │ By default a `pending` device becomes `active` only when a human approves │
 * │ it (`POST /devices/:id/approve`). One path is excepted,                   │
 * │ by explicit design: a device that passes plan conformity at the config    │
 * │ level confirms itself.                                                    │
 * │ `confirmBenchDeviceByConformity()` at the bottom of this file is the ONLY │
 * │ code that acts on that decision, and `autoConfirm.service.ts` the only    │
 * │ caller. Its conditions, all of them, every time:                          │
 * │  1. the device is `pending` and its LATEST `bench_provisionings` row was  │
 * │     compiled by a bench station that is `approved` NOW, with an outcome   │
 * │     of `applied` or not yet reported (`compiled`) — never `failed`;       │
 * │  2. the bench READ a serial off the box for that file (the compile's own │
 * │     `bench.compiled` audit entry carries it) and the device row still    │
 * │     holds it. A serial this file's opportunistic learning wrote — i.e.   │
 * │     one the box reported about itself — never carries a confirmation:   │
 * │     the PPP login and the system identity are imposed by the compiled    │
 * │     file, so the serial is the only attribute that tells the box apart;  │
 * │  3. its PPP session is up on its concentrator (never dialled down);       │
 * │  4. `assertTargetBinding()` on a FRESH connection, with the device's own  │
 * │     vaulted credential, MATCHES all three of `ppp_username`,              │
 * │     `system_identity` and `serial` — the general rule's "one match and no │
 * │     contradiction" is not enough here, and a contradiction quarantines;  │
 * │  5. the box carries the compile's own success marker for that file;      │
 * │  6. the configuration, collected through the frozen export, and         │
 * │     the desired state of the SAME template revision with the SAME        │
 * │     allocation compile into a plan with NO operation, every claimed kind │
 * │     compared in both directions — a kind that could not be compared     │
 * │     completely stops the check for a human. The exclusions are named    │
 * │     and justified in `autoConfirm.service.ts` and recorded on the check │
 * │     row — never counted as conformity, never hidden.                     │
 * │ The update is ONE statement, conditional on `status = 'pending'`, on the │
 * │ identity columns the assertion compared, on the file judged still being │
 * │ the device's LATEST bench file and on its station still being approved │
 * │ (a re-preparation or a revocation during the check confirms nothing).  │
 * │ It sets `status` only — `is_managed` stays false, exactly as a human     │
 * │ approval leaves it. Any other `pending` device (an enrolment, a hand-    │
 * │ declared one, a bench box whose station was revoked or whose serial the │
 * │ bench did not read) still waits for a human, and the whole path is off  │
 * │ when the installation sets BENCH_AUTO_CONFIRM_ENABLED=false.            │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

import {
  FAMILY_BRAND,
  managementTunnelLogin,
  parseRouterOsVersion,
  type DeviceFamily,
  type RouterOsDeviceModeFacts,
} from '@obliwan/shared';
import {
  createRouterOsConnection,
  RouterOsTrapError,
  type RouterOsConnection,
} from '../transport/routeros';
import type { Knex } from 'knex';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { decrypt } from '../secretVault.service';
import { appendAudit } from '../attestation/auditLog.service';
import { getDriver } from '../drivers/registry';
import type { DriverContext, ResolvedTransport } from '../drivers/types';
import { renameIdentityAlternates, type IdentityAlternates } from './identityAlternates';
import type { TransportKind } from '@obliwan/shared';

/**
 * Which transport carries the IDENTITY assertion, per brand.
 *
 * Deliberately NOT the arbiter's choice. The arbiter optimises for a working
 * channel; this one answers a different question — "which channel can tell me
 * what box this is on a socket nobody has used yet" — and it must be stable,
 * because an assertion that silently changes transport is an assertion whose
 * failures nobody can compare across time.
 *
 * SonicOS rides `rest`, and its freshness is structural rather than a promise:
 * `withSonicOsSession` logs in, works, and logs out in a `finally` on EVERY
 * unit of work, because the appliance allows very few concurrent admin
 * sessions and leaks them on timeout. There is no pooled session to reuse
 * here even by accident — which is exactly the property the identity rule asks for.
 */
const BINDING_TRANSPORT: Partial<Record<string, TransportKind>> = {
  mikrotik: 'routeros_api',
  draytek: 'ssh',
  zyxel: 'ssh',
  sonicwall: 'rest',
};

// ============================================================================
// Result shapes
// ============================================================================

export type IdentityAttribute = 'ppp_username' | 'system_identity' | 'serial';

export interface AttributeCheck {
  attribute: IdentityAttribute;
  expected: string | null;
  observed: string | null;
  /** `match` the two agree · `mismatch` they contradict · `unknown` the box
   *  could not tell us · `unrecorded` we had nothing to compare against. */
  outcome: 'match' | 'mismatch' | 'unknown' | 'unrecorded';
}

export interface BindingAssertion {
  deviceId: number;
  ok: boolean;
  checks: AttributeCheck[];
  /** How many attributes actually corroborated the identity. */
  matched: number;
  mismatched: number;
  /** Address the fresh connection actually dialled. Reported for the audit
   *  trail; deliberately NOT part of the identity. */
  dialled: string;
  reason: string;
  at: string;
}

export class BindingAssertionError extends Error {
  readonly assertion: BindingAssertion;
  constructor(assertion: BindingAssertion) {
    super(`Identity assertion failed for device ${assertion.deviceId}: ${assertion.reason}`);
    this.name = 'BindingAssertionError';
    this.assertion = assertion;
  }
}

/** What a fresh connection managed to read off the box. */
export interface ObservedIdentity {
  systemIdentity: string | null;
  serial: string | null;
  pppUsername: string | null;
}

// ============================================================================
// Comparison — pure, therefore testable without a router
// ============================================================================

function normalise(value: string | null | undefined): string | null {
  const v = value?.trim();
  return v ? v.toLowerCase() : null;
}

/**
 * Compare recorded identity against observed identity.
 *
 * Exported separately from the network path so the DECISION can be tested
 * exhaustively (it is the part that must never be wrong) without a device.
 *
 * `accept` (optional): for the login and the identity only, more spellings an
 * observed value may match besides the record — the frozen old/new pair of a
 * rename in flight or unsettled (fleet/identityAlternates.ts). Same
 * normalisation. The serial is never in it: it still decides when recorded,
 * and a value outside the record AND the pair is a mismatch as before.
 */
export function compareIdentity(
  expected: Partial<Record<IdentityAttribute, string | null>>,
  observed: ObservedIdentity,
  accept?: Partial<IdentityAlternates> | null,
): { checks: AttributeCheck[]; ok: boolean; matched: number; mismatched: number; reason: string } {
  const pairs: Array<[IdentityAttribute, string | null | undefined, string | null]> = [
    ['ppp_username', expected.ppp_username, observed.pppUsername],
    ['system_identity', expected.system_identity, observed.systemIdentity],
    ['serial', expected.serial, observed.serial],
  ];

  const checks: AttributeCheck[] = pairs.map(([attribute, exp, obs]) => {
    const e = normalise(exp);
    const o = normalise(obs);
    const alternates = attribute === 'serial' ? [] : (accept?.[attribute] ?? []).map(normalise).filter((v): v is string => v !== null);
    let outcome: AttributeCheck['outcome'];
    if (e === null) outcome = 'unrecorded';
    else if (o === null) outcome = 'unknown';
    else outcome = e === o || alternates.includes(o) ? 'match' : 'mismatch';
    return {
      attribute,
      expected: exp ?? null,
      observed: obs,
      outcome,
    };
  });

  const matched = checks.filter((c) => c.outcome === 'match').length;
  const mismatched = checks.filter((c) => c.outcome === 'mismatch').length;

  if (mismatched > 0) {
    const names = checks.filter((c) => c.outcome === 'mismatch').map((c) => c.attribute);
    return {
      checks,
      ok: false,
      matched,
      mismatched,
      reason: `identity mismatch on ${names.join(', ')} — this is NOT the recorded device`,
    };
  }
  if (matched === 0) {
    // Fail closed. Either we recorded no identity at all (a device that has
    // never been probed) or the box answered nothing. Both mean "unproven",
    // and unproven must not authorise a write.
    return {
      checks,
      ok: false,
      matched,
      mismatched,
      reason:
        'no identity attribute could be corroborated — the device is unproven, ' +
        'not confirmed (fail closed)',
    };
  }
  return { checks, ok: true, matched, mismatched, reason: `identity confirmed on ${matched} attribute(s)` };
}

// ============================================================================
// Reading identity off a live RouterOS box
// ============================================================================

/** `!trap` = "this menu does not exist here" (a CHR has no RouterBOARD). It is
 *  an answer, not a failure: null, and carry on. */
async function optionalRow(
  conn: RouterOsConnection,
  path: string,
): Promise<Record<string, string> | null> {
  try {
    return await conn.queryFirst([path]);
  } catch (err) {
    if (err instanceof RouterOsTrapError) return null;
    throw err;
  }
}

/** Every row of a menu, or null on `!trap` (same meaning as `optionalRow`). */
async function optionalRows(
  conn: RouterOsConnection,
  words: string[],
): Promise<Array<Record<string, string>> | null> {
  try {
    return await conn.query(words);
  } catch (err) {
    if (err instanceof RouterOsTrapError) return null;
    throw err;
  }
}

/**
 * The three identity attributes, off one connection.
 *
 * `recordedPppUsername` is the device's `ppp_username`. It does not decide
 * which tunnel is the management one when the box names it (`l2tp-mgmt`):
 * it only lets `managementTunnelLogin` (shared/src/managementTunnel.ts) find
 * the sole client carrying it on a box that names none. REQUIRED, so that no
 * caller silently loses that fallback.
 */
export async function readRouterOsIdentity(
  conn: RouterOsConnection,
  recordedPppUsername: string | null,
): Promise<ObservedIdentity> {
  const identity = await optionalRow(conn, '/system/identity/print');
  const routerboard = await optionalRow(conn, '/system/routerboard/print');
  // The device's own view of its PPP account. On a CPE the management tunnel
  // is an l2tp-client — the one NAMED l2tp-mgmt, not the first one: a store
  // may carry another tunnel created before it. Every client is read, and
  // only its name and user (the `.proplist` names no password). The CHR
  // itself has none, which is correct — a concentrator is asserted on
  // identity + serial.
  const l2tp = await optionalRows(conn, ['/interface/l2tp-client/print', '=.proplist=name,user']);
  const tunnel = l2tp === null
    ? null
    : managementTunnelLogin(l2tp.map((r) => ({ name: r.name ?? null, user: r.user ?? null })), recordedPppUsername);

  return {
    systemIdentity: identity?.name ?? null,
    serial: routerboard?.['serial-number'] ?? null,
    pppUsername: tunnel?.login ?? null,
  };
}

// ============================================================================
// The assertion
// ============================================================================

interface TargetRow {
  id: number;
  tenant_id: number;
  name: string;
  family: string;
  status: string;
  ppp_username: string | null;
  system_identity: string | null;
  serial: string | null;
  tunnel_ip: string | null;
  host: string | null;
  port: number | null;
  username: string | null;
  secret_enc: string | null;
  use_tls: boolean | null;
  tls_fingerprint_sha256: string | null;
  enabled: boolean | null;
  params: Record<string, unknown> | null;
}

/**
 * Read the identity over the family's own driver, on a session that did not
 * exist a moment ago.
 *
 * WHY THE DRIVER AND NOT A COMMAND TYPED HERE: the driver already knows that a
 * Vigor answers `sys ver` on every train and puts the serial in `sys info` on
 * some of them, and that a failure of the second must not invalidate the
 * first. Re-typing those commands in this file would create two versions of
 * "what this box says its serial is" — and the day they disagree, the one that
 * guards the write path is the one nobody tested. One reader, one truth.
 *
 * The freshness the identity rule demands is satisfied by construction: the SSH inventory
 * paths open their own `withSsh()` session and close it on the way out. No
 * pool, no reuse, no arbiter — the arbiter picks a channel that WORKS, which
 * is not the same question as "prove to me what you are".
 */
async function readIdentityViaDriver(
  target: TargetRow,
  transport: TransportKind,
  timeoutMs: number,
): Promise<ObservedIdentity> {
  const resolved: ResolvedTransport = {
    transport,
    enabled: true,
    priority: 0,
    host: target.host ?? target.tunnel_ip,
    port: target.port,
    useTls: target.use_tls === true,
    tlsFingerprintSha256: target.tls_fingerprint_sha256,
    params: target.params ?? {},
    credentials: {
      username: target.username,
      // Decrypted here, held for the length of one call, never persisted
      // and never logged — `secretsOf()` is what redacts it downstream.
      password: target.secret_enc ? decrypt(target.secret_enc) : null,
    },
  };

  const ctx: DriverContext = {
    deviceId: target.id,
    tenantId: target.tenant_id,
    family: target.family as DeviceFamily,
    transports: [resolved],
    timeoutMs,
  };

  const inventory = await getDriver(target.family).getInventory(ctx);
  return {
    systemIdentity: inventory.systemIdentity ?? null,
    serial: inventory.serial ?? null,
    // No PPP username is readable from the box itself on these families: the
    // CHR is the only thing that knows it. Left null so `compareIdentity`
    // scores it `unrecorded` instead of inventing a mismatch.
    pppUsername: null,
  };
}

async function loadTarget(deviceId: number, transport: TransportKind): Promise<TargetRow> {
  const row = await db('devices as d')
    .leftJoin('device_transports as t', function joinBindingTransport(this: any) {
      this.on('t.device_id', '=', 'd.id').andOn('t.transport', '=', db.raw('?', [transport]));
    })
    .where('d.id', deviceId)
    .first<TargetRow | undefined>(
      'd.id',
      'd.tenant_id',
      'd.name',
      'd.family',
      'd.status',
      'd.ppp_username',
      'd.system_identity',
      'd.serial',
      'd.tunnel_ip',
      't.host',
      't.port',
      't.username',
      't.secret_enc',
      't.use_tls',
      't.tls_fingerprint_sha256',
      't.enabled',
      't.params',
    );
  if (!row) throw new Error(`Device ${deviceId} does not exist`);
  return row;
}

// ============================================================================
// Learning what the box says about itself
// ============================================================================

export interface LearnedFacts {
  /** Columns that were empty and are now filled. */
  filled: Record<string, string>;
  /** Columns whose stored value CONTRADICTS what the box reported. Never
   *  written — see the doctrine below. */
  conflicts: Array<{ field: string; stored: string; observed: string }>;
}

const LEARNABLE = ['model', 'serial', 'os_version', 'system_identity'] as const;

/**
 * Fill in what we did not know, and refuse to change what we did.
 *
 * ┌─ THE ONE RULE, AND IT IS NOT A DETAIL ───────────────────────────────────┐
 * │ An EMPTY column means "we have never been told". A FILLED one is a claim  │
 * │ that `assertTargetBinding()` checks before every write.                   │
 * │                                                                          │
 * │ So this fills blanks and NEVER overwrites. A probe that reports a serial  │
 * │ different from the stored one is not an update — it is the exact event    │
 * │ the binding check exists to catch: the box at this address is not the box │
 * │ we think. Silently writing the new value would make ObliWAN helpfully     │
 * │ rewrite its own records to match an impostor, and the guard would then    │
 * │ pass forever. The conflict is RETURNED and logged instead.                │
 * │ (`os_version` has ONE writer that overwrites: `recordUpgradedOsVersion`   │
 * │ below, called only by the os_upgrade job that changed it.)                │
 * │                                                                          │
 * │ `ppp_username` is deliberately not learnable here: none of these families │
 * │ can be asked what account they dial with — only the concentrator knows    │
 * │ — so a null from the box is ignorance, not an answer.                     │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Called after a SUCCESSFUL connection test. That is the moment an operator
 * expects the page to stop saying "—" about a device the server just talked to:
 * the round trip has already happened and the facts were already on the wire.
 */
export async function learnDeviceFacts(
  tenantId: number,
  deviceId: number,
  timeoutMs = 15_000,
): Promise<LearnedFacts> {
  const out: LearnedFacts = { filled: {}, conflicts: [] };

  const device = await db('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first<{ family: string } | undefined>('family');
  if (!device) return out;

  const transport = BINDING_TRANSPORT[FAMILY_BRAND[device.family as DeviceFamily] ?? ''];
  if (!transport) return out;

  const target = await loadTarget(deviceId, transport);
  if (!target.username || !target.secret_enc) return out;

  const resolved: ResolvedTransport = {
    transport,
    enabled: true,
    priority: 0,
    host: target.host ?? target.tunnel_ip,
    port: target.port,
    useTls: target.use_tls === true,
    tlsFingerprintSha256: target.tls_fingerprint_sha256,
    params: target.params ?? {},
    credentials: {
      username: target.username,
      password: decrypt(target.secret_enc),
    },
  };

  const inventory = await getDriver(target.family).getInventory({
    deviceId: target.id,
    tenantId: target.tenant_id,
    family: target.family as DeviceFamily,
    transports: [resolved],
    timeoutMs,
  } as DriverContext);

  const observed: Record<string, string | null> = {
    model: inventory.model ?? inventory.boardName ?? null,
    serial: inventory.serial ?? null,
    os_version: inventory.osVersion ?? null,
    system_identity: inventory.systemIdentity ?? null,
  };

  const current = await db('devices')
    .where({ id: deviceId })
    .first<Record<string, string | null>>('model', 'serial', 'os_version', 'system_identity');

  const patch: Record<string, string> = {};
  for (const field of LEARNABLE) {
    const seen = observed[field]?.trim();
    if (!seen) continue;
    const stored = current?.[field]?.trim();
    if (!stored) {
      patch[field] = seen;
      out.filled[field] = seen;
    } else if (stored !== seen) {
      out.conflicts.push({ field, stored, observed: seen });
    }
  }

  if (Object.keys(patch).length > 0) {
    await db('devices').where({ id: deviceId }).update({ ...patch, updated_at: db.fn.now() });
    logger.info({ deviceId, learned: Object.keys(patch) }, 'Device facts learned from a live probe');
  }

  await recordDeviceMode(deviceId, inventory.deviceMode);

  if (out.conflicts.length > 0) {
    // Not an error here — `assertTargetBinding` is what refuses the write. This
    // is the early warning, recorded where somebody reading logs will see it.
    logger.warn(
      { deviceId, conflicts: out.conflicts },
      'The device reported facts that CONTRADICT its record. Nothing was overwritten: this is '
        + 'either a replaced unit or an address that now belongs to another box.',
    );
  }

  return out;
}

/**
 * Store what RouterOS said `/system/device-mode` currently allows.
 *
 * ┌─ WHY THIS IS NOT IN `LEARNABLE`, AND WHY IT OVERWRITES ──────────────────┐
 * │ Everything in `LEARNABLE` is an IDENTITY claim. A serial that changes is  │
 * │ not an update, it is the impostor `assertTargetBinding()` exists to       │
 * │ catch, so blanks are filled and nothing is ever rewritten.                │
 * │                                                                          │
 * │ A device-mode is not a claim about WHICH box this is — it is a STATE the  │
 * │ box is in, and a state an operator can legitimately change. Tightening    │
 * │ the mode (`enterprise` -> `home`) needs no physical access at all; only   │
 * │ widening it does. Under the fill-blanks rule the first read would be      │
 * │ frozen forever, so the day somebody locked a router down ObliWAN would    │
 * │ keep promising the planner a dead-man it can no longer install,           │
 * │ reached by being careful in the wrong direction.                          │
 * │                                                                          │
 * │ So: newest read wins, and the five columns move TOGETHER as one           │
 * │ observation. Half of Tuesday's answer beside half of March's is the real  │
 * │ defect here — a page that reads "read today: home" when today's read      │
 * │ returned nothing at all.                                                  │
 * │                                                                          │
 * │ Going BACKWARDS to unknown is therefore accepted: a router that stops     │
 * │ answering the menu returns to `unknown`, which is honest and which        │
 * │ `deadmanReadiness()` never reads as `capable`. Losing a `blocked` verdict │
 * │ costs an unnecessary confirmation; keeping a `capable` one we can no      │
 * │ longer verify costs the net itself.                                      │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * `facts === null` means the channel could not ask — SNMP, or any of the three
 * brands with no such notion. Nothing is written at all then: a DrayTek probe
 * must not blank a MikroTik's stored mode.
 *
 * Exported for fleet/testing/deviceMode-db.verify.ts, which writes every
 * documented mode through it against the CHECK on `devices.device_mode`; the
 * only production caller is `learnDeviceFacts()` above.
 */
export async function recordDeviceMode(
  deviceId: number,
  facts: RouterOsDeviceModeFacts | null,
): Promise<void> {
  if (facts === null) return;

  const before = await db('devices')
    .where({ id: deviceId })
    .first<{ device_mode: string | null } | undefined>('device_mode');

  await db('devices').where({ id: deviceId }).update({
    device_mode: facts.mode,
    device_mode_scheduler: facts.schedulerAllowed,
    device_mode_fetch: facts.fetchAllowed,
    device_mode_raw: facts.raw === null ? null : JSON.stringify(facts.raw),
    device_mode_observed_at: facts.observedAt,
    updated_at: db.fn.now(),
  });

  // A mode that MOVED is operationally significant in both directions: one way
  // a router just lost its ability to carry a dead-man, the other way somebody
  // stood in front of it and pressed the button. Neither should be discoverable
  // only by diffing two screenshots of the device page.
  if ((before?.device_mode ?? null) !== facts.mode) {
    logger.info(
      { deviceId, from: before?.device_mode ?? null, to: facts.mode },
      'RouterOS device-mode changed. `home` denies /system/scheduler, which is how the dead-man '
        + 'is installed; widening the mode again needs physical access to the unit.',
    );
  }
}

/**
 * THE ONE PLACE `devices.os_version` IS OVERWRITTEN — and only by the job that
 * changed it.
 *
 * ┌─ WHY AN EXCEPTION TO "NEVER OVERWRITE", AND WHY IT IS NARROW ────────────┐
 * │ `os_version` is in `LEARNABLE`, so a probe fills it once and never        │
 * │ rewrites it. After an `os_upgrade` job that rule would leave the column   │
 * │ stating the PREVIOUS release forever, and `learnDeviceFacts` would log a  │
 * │ "contradicts its record" warning on every connection test from then on —  │
 * │ the impostor alarm, crying wolf about an upgrade we performed.            │
 * │                                                                          │
 * │ The overwrite is safe for a reason that is specific to this column:       │
 * │ `assertTargetBinding()` NEVER compares `os_version` (identity is          │
 * │ `ppp_username` + `system_identity` + `serial`), so rewriting it cannot    │
 * │ weaken the test an impostor has to pass. The fill-blanks rule still       │
 * │ holds for every PROBE: a box reporting another version than the record    │
 * │ is either an upgrade nobody told us about or another box, and a probe     │
 * │ cannot tell which.                                                        │
 * │                                                                          │
 * │ So this writes ONLY when all of these hold, and refuses otherwise:        │
 * │  - the caller hands in a successful assertion FOR THIS DEVICE, made after │
 * │    the reboot, that matched at least one identity attribute and          │
 * │    contradicted none;                                                    │
 * │  - an `os_upgrade` job of this tenant, on this device, is in flight       │
 * │    (`verifying`) — the job that caused the change, not a bystander;      │
 * │  - the value is a RouterOS version string.                               │
 * │ It writes `os_version` and nothing else: never `serial`, never            │
 * │ `system_identity`, never `model`.                                        │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
export async function recordUpgradedOsVersion(input: {
  tenantId: number;
  deviceId: number;
  jobId: number;
  version: string;
  proof: BindingAssertion;
}): Promise<{ previous: string | null; recorded: string }> {
  const { tenantId, deviceId, jobId, version, proof } = input;
  if (!proof.ok || proof.deviceId !== deviceId || proof.mismatched > 0 || proof.matched < 1) {
    throw new Error(
      `os_version of device ${deviceId} not recorded: the identity proof handed in is not a ` +
        'successful assertion of this device',
    );
  }
  if (!parseRouterOsVersion(version)) {
    throw new Error(`os_version of device ${deviceId} not recorded: not a RouterOS version`);
  }
  const job = await db('change_jobs')
    .where({ id: jobId, tenant_id: tenantId, device_id: deviceId, kind: 'os_upgrade', status: 'verifying' })
    .first<{ id: number } | undefined>('id');
  if (!job) {
    throw new Error(
      `os_version of device ${deviceId} not recorded: no os_upgrade job ${jobId} of this tenant ` +
        'is verifying this device',
    );
  }
  const before = await db('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first<{ os_version: string | null } | undefined>('os_version');
  if (!before) throw new Error(`Device ${deviceId} does not exist in tenant ${tenantId}`);
  await db('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .update({ os_version: version, updated_at: db.fn.now() });
  logger.info(
    { deviceId, jobId, from: before.os_version, to: version },
    'os_version recorded by the os_upgrade job that changed it (identity re-proved after the reboot)',
  );
  return { previous: before.os_version, recorded: version };
}

export interface AssertOptions {
  /** Quarantine the device on mismatch. Default true — a box that answered
   *  with the wrong identity must not stay targetable. */
  quarantineOnMismatch?: boolean;
  /** Throw instead of returning a failed assertion. Default true: callers on
   *  the write path must not be able to ignore a returned `ok: false`. */
  throwOnFailure?: boolean;
  connectTimeoutMs?: number;
}

/**
 * Prove that the box currently at the device's address IS the device.
 *
 * ALWAYS opens a new socket, and always closes it. Nothing is cached: a cached
 * assertion is a stale assertion, and a stale assertion is the bug.
 */
export async function assertTargetBinding(
  deviceId: number,
  options: AssertOptions = {},
): Promise<BindingAssertion> {
  const quarantineOnMismatch = options.quarantineOnMismatch ?? true;
  const throwOnFailure = options.throwOnFailure ?? true;
  const at = new Date().toISOString();

  // The family decides which channel proves identity, so it has to be read
  // before the transport row can be joined. One extra round trip, once per
  // assertion, on the path that guards every write there will ever be.
  const familyRow = await db('devices')
    .where({ id: deviceId })
    .first<{ family: string | null } | undefined>('family');
  if (!familyRow) throw new Error(`Device ${deviceId} does not exist`);
  const bindingBrand = FAMILY_BRAND[familyRow.family as DeviceFamily];
  const bindingTransport = BINDING_TRANSPORT[bindingBrand ?? ''];

  const target = await loadTarget(deviceId, bindingTransport ?? 'routeros_api');

  const fail = async (reason: string, checks: AttributeCheck[] = [], dialled = '-'): Promise<BindingAssertion> => {
    const assertion: BindingAssertion = {
      deviceId,
      ok: false,
      checks,
      matched: checks.filter((c) => c.outcome === 'match').length,
      mismatched: checks.filter((c) => c.outcome === 'mismatch').length,
      dialled,
      reason,
      at,
    };
    if (assertion.mismatched > 0 && quarantineOnMismatch) {
      await db('devices')
        .where({ id: deviceId })
        .update({ status: 'quarantined', is_managed: false, updated_at: db.fn.now() });
      logger.error(
        { deviceId, reason, checks },
        'Device quarantined: the box at its address is not the recorded device',
      );
    }
    if (throwOnFailure) throw new BindingAssertionError(assertion);
    return assertion;
  };

  if (target.status === 'disabled') {
    return fail("device status is 'disabled'; no transport may be opened");
  }

  const brand = bindingBrand;
  if (!bindingTransport) {
    // Honest refusal rather than a silent pass. SonicOS identity rides a REST
    // call whose fresh-session semantics are not built: returning `ok: true`
    // here would hand the write path an unlocked door.
    return fail(
      `no fresh-connection identity path for family '${target.family}' yet — ` +
        'refusing rather than assuming',
    );
  }

  if (!target.enabled) return fail(`${bindingTransport} transport is absent or disabled`);
  const host = target.host ?? target.tunnel_ip;
  if (!host) return fail('no address to dial');
  if (!target.username || !target.secret_enc) return fail('no credential in the vault');

  const connectTimeoutMs = options.connectTimeoutMs ?? 10_000;
  let observed: ObservedIdentity;

  if (brand === 'mikrotik') {
    let conn: RouterOsConnection | null = null;
    try {
      conn = await createRouterOsConnection({
        host,
        port: target.port ?? undefined,
        tls: target.use_tls === true,
        username: target.username,
        password: decrypt(target.secret_enc),
        expectedFingerprint: target.tls_fingerprint_sha256,
        connectTimeoutMs,
        label: `assert:${target.name}`,
      });
      observed = await readRouterOsIdentity(conn, target.ppp_username);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return fail(`fresh connection to ${host} failed: ${message}`, [], host);
    } finally {
      // The socket exists for this assertion and dies with it. It is deliberately
      // NOT handed to the pool: a connection opened to prove identity must not
      // become the connection used to act on it minutes later.
      conn?.close();
    }
  } else {
    // DrayTek and Zyxel. The driver owns the commands and owns the
    // session; this file owns only the comparison. Any throw is a refusal —
    // an identity we could not read is never an identity that matched.
    try {
      observed = await readIdentityViaDriver(target, bindingTransport, connectTimeoutMs);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return fail(`fresh ${bindingTransport} session to ${host} failed: ${message}`, [], host);
    }
  }

  // An identity read that returned NOTHING is not a match, and must not fall
  // through to `compareIdentity` where a device with a blank `serial` and a
  // blank `system_identity` would score zero mismatches and pass. The identity rule asks for
  // a positive proof; silence is not one.
  if (!observed.systemIdentity && !observed.serial && !observed.pppUsername) {
    return fail(
      `${bindingTransport} answered but reported no identity attribute at all — ` +
        'refusing rather than treating silence as agreement',
      [],
      host,
    );
  }

  // A rename in flight or unsettled (site_rename) accepts its frozen pair on
  // the login and the identity (fleet/identityAlternates.ts); never the serial.
  const comparison = compareIdentity(
    {
      ppp_username: target.ppp_username,
      system_identity: target.system_identity,
      serial: target.serial,
    },
    observed,
    await renameIdentityAlternates(deviceId),
  );

  if (!comparison.ok) {
    return fail(comparison.reason, comparison.checks, host);
  }

  // Opportunistic learning: fill in what was blank, never overwrite what was
  // recorded (that would let a wrong box rewrite the identity it failed). A
  // serial learned here is the box's own claim: it may corroborate later
  // assertions, but it never carries the identity rule's automatic exception (header box,
  // condition 2 — `autoConfirm.service.ts` reads the bench's own record).
  const learn: Record<string, unknown> = {};
  if (!target.system_identity && observed.systemIdentity) {
    learn.system_identity = observed.systemIdentity;
  }
  if (!target.serial && observed.serial) learn.serial = observed.serial;
  if (Object.keys(learn).length > 0) {
    await db('devices').where({ id: deviceId }).update({ ...learn, updated_at: db.fn.now() });
  }

  const assertion: BindingAssertion = {
    deviceId,
    ok: true,
    checks: comparison.checks,
    matched: comparison.matched,
    mismatched: 0,
    dialled: host,
    reason: comparison.reason,
    at,
  };
  logger.info(
    { deviceId, dialled: host, matched: comparison.matched },
    'Target binding asserted on a fresh connection',
  );
  return assertion;
}

/**
 * The ONLY sanctioned way to act on a device.
 *
 * `assertTargetBinding()` first, work second. Exported as one call so that no
 * future caller can accidentally do the work and forget the proof — the shape
 * of the API makes the safe order the only order.
 */
export async function withAssertedDevice<T>(
  deviceId: number,
  work: (assertion: BindingAssertion) => Promise<T>,
  options: AssertOptions = {},
): Promise<T> {
  const assertion = await assertTargetBinding(deviceId, { ...options, throwOnFailure: true });
  return work(assertion);
}

// ============================================================================
// The identity rule's one exception — see the box in this file's header
// ============================================================================

export interface ConformityConfirmation {
  tenantId: number;
  deviceId: number;
  /** The RECORDED values the fresh assertion matched, all three. The update
   *  is conditional on them, so an edit of the identity between the assertion
   *  and this call confirms nothing. */
  recorded: { pppUsername: string; systemIdentity: string; serial: string };
  provisioningId: number;
  provisioningTag: string;
  revisionId: string | null;
  snapshotId: string;
  observedNcmHash: string;
  /** What the check compared and found — counts and names, never a value. */
  summary: Record<string, unknown>;
}

/**
 * Turn a `pending` bench-prepared device `active` on the strength of an
 * automatic conformity check, inside the caller's transaction, with its audit
 * entry in the same transaction.
 *
 * The ONLY function that confirms a device without a human, and it decides
 * nothing: the six conditions of the header box are established by
 * `autoConfirm.service.ts` before it calls. What this function guarantees is
 * narrower and is enforced here, in ONE SQL statement, because the check that
 * established them takes tens of seconds: the row is still `pending`, still
 * this tenant's, still carries the identity that was just proved; the file
 * judged (`provisioningId`) is still the device's LATEST bench file, with an
 * outcome that is not `failed`; and the station that compiled it is still
 * `approved`. It sets `status` and nothing else — `is_managed` stays as it
 * was (false for a bench box), exactly as `POST /devices/:id/approve` leaves
 * it.
 *
 * Returns false, having written nothing, when the conditional update matched
 * no row: somebody approved, disabled or edited the device in between, the box
 * was prepared again, or the station was revoked. The caller says which.
 */
export async function confirmBenchDeviceByConformity(
  trx: Knex.Transaction,
  c: ConformityConfirmation,
): Promise<boolean> {
  const updated = await trx('devices')
    .where({
      id: c.deviceId,
      tenant_id: c.tenantId,
      status: 'pending',
      ppp_username: c.recorded.pppUsername,
      system_identity: c.recorded.systemIdentity,
      serial: c.recorded.serial,
    })
    .whereExists(function stillTheLatestApprovedFile(this: Knex.QueryBuilder) {
      void this.select(trx.raw('1'))
        .from('bench_provisionings as b')
        .join('bench_stations as s', 's.id', 'b.station_id')
        .where('b.id', c.provisioningId)
        .whereRaw('b.device_id = devices.id')
        .whereRaw('b.tenant_id = devices.tenant_id')
        .whereIn('b.outcome', ['applied', 'compiled'])
        .where('s.status', 'approved')
        .whereNotExists(function noNewerFile(this: Knex.QueryBuilder) {
          void this.select(trx.raw('1'))
            .from('bench_provisionings as b2')
            .whereRaw('b2.device_id = b.device_id')
            .whereRaw('(b2.compiled_at, b2.id) > (b.compiled_at, b.id)');
        });
    })
    .update({ status: 'active', updated_at: trx.fn.now() });
  if (updated !== 1) return false;

  await appendAudit({
    tenantId: c.tenantId,
    actorType: 'automation',
    actorId: 'auto-conformity',
    actorName: 'Automatic conformity check',
    action: 'device.auto_confirmed',
    entityType: 'device',
    entityId: c.deviceId,
    before: { status: 'pending' },
    after: {
      status: 'active',
      method: 'auto_conformity',
      statement:
        `auto-confirmed by conformity check: revision ${c.revisionId ?? 'unknown'}, ` +
        `snapshot ${c.snapshotId}, plan empty`,
      provisioningId: c.provisioningId,
      provisioningTag: c.provisioningTag,
      revisionId: c.revisionId,
      snapshotId: c.snapshotId,
      observedNcmHash: c.observedNcmHash,
      identity: {
        ppp_username: c.recorded.pppUsername,
        system_identity: c.recorded.systemIdentity,
        serial: c.recorded.serial,
      },
      summary: c.summary,
    },
  }, trx);
  logger.info(
    { deviceId: c.deviceId, provisioningId: c.provisioningId, snapshotId: c.snapshotId },
    'Pending bench device confirmed by the automatic conformity check (identity-rule exception)',
  );
  return true;
}
