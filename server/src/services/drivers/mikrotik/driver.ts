/**
 * ObliWAN — RouterOS configuration acquisition (layer L0).
 *
 * ONE JOB: get the text off the box, without ever letting the acquisition
 * itself become a variable of the diff. Everything semantic is downstream
 * (`parse.ts`, `quirks.ts`, `config/normalize.service.ts`).
 *
 * ┌─ THE THREE THINGS THAT ARE HARD-WIRED, AND WHY ───────────────────────────┐
 * │                                                                           │
 * │ THE COMMAND ASKS FOR NO SECRET, AND A GUARD REFUSES ANY THAT COMES.       │
 * │   The export is spelled by ONE table keyed on the family                  │
 * │   (`ROUTEROS_EXPORT_FLAGS`, read through `routerOsExportCommand()` for    │
 * │   SSH and `routerOsExportApiFlagWords()` for the API): RouterOS 6 PRINTS  │
 * │   secrets unless told `hide-sensitive`, RouterOS 7 hides them unless      │
 * │   told `show-sensitive`, so the request that asks for no secret is a      │
 * │   different command on each. A family the table does not know is          │
 * │   REFUSED, never given a guessed spelling. There is no parameter, option  │
 * │   object, environment variable or per-device override that can add        │
 * │   `show-sensitive`. A boolean would eventually be flipped by someone      │
 * │   debugging "why can't I see the PSK", and from that moment the PSKs of   │
 * │   the fleet are in a jsonb column, in a diff, in the UI and in a log.     │
 * │   Behind the command, `findSensitiveProps()` (bottom of this file)        │
 * │   re-reads every export and the caller REFUSES it on any hit: it is what  │
 * │   catches a secret no flag hides (a script source, a comment) and an      │
 * │   export taken in the wrong dialect because `devices.family` is stale.    │
 * │   Belt and braces, on purpose: this is the one place in the product       │
 * │   where a mistake is irreversible, because a secret that reached the      │
 * │   snapshot store has to be assumed to have leaked.                        │
 * │                                                                           │
 * │ N13 — NO PTY. `exec()` without `pty: true`. With a pty RouterOS wraps     │
 * │   long lines at the terminal width, which makes the width an input to     │
 * │   `ncm_hash`: the same unchanged router produces two different documents  │
 * │   depending on who collected it. The parser unfolds continuations anyway  │
 * │   as a safety net, but it WARNS, because absorbing the symptom here would │
 * │   hide the acquisition defect instead of fixing it.                       │
 * │                                                                           │
 * │ `terse` — one entry per line, full menu path on each line. Without it the │
 * │   output is the sectioned form and long lines are wrapped.                │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * CAPABILITY. Calling this is `CONFIG_READ`, which is deliberately a DIFFERENT
 * capability from `DEVICE_READ` (`shared/src/capabilities.ts`): a
 * config export contains the whole security posture of a site, and the person
 * allowed to see that a device is up is not automatically allowed to read its
 * firewall. The check belongs to the route layer (not owned by this file); this
 * module states the requirement and the route that calls it must enforce
 * `CONFIG_READ`, never `DEVICE_READ`.
 */

import type { DeviceFamily } from '@obliwan/shared';
import { LEARNING_PLACEHOLDER_PREFIX, LEARNING_REF_RE, learningPlaceholder } from '@obliwan/shared';
import { withSsh, type SshTarget, type SshTransport } from '../../transport/ssh.transport';
import {
  DriverError,
  requireTransport,
  type DriverContext,
  type ResolvedTransport,
} from '../types';
import { familyFromVersion } from './mikrotik.driver';
import {
  parsePreamble,
  canonicalizeText,
  canonicalSectionPath,
  tokenize,
  unfoldLines,
  unquote,
  type RouterOsPreamble,
} from './parse';

/** The families the export table speaks. Every other family is refused. */
export type RouterOsExportFamily = 'mikrotik_routeros6' | 'mikrotik_routeros7';

/**
 * The acquisition command, per family. A frozen table, exported so a test can
 * assert on the literals and so a reviewer can see the whole L0 contract in one
 * place. The SSH command and the API words are both READ from it: one table,
 * two spellings of the same request, so they cannot drift apart again.
 *
 * NOT a template, NOT built from anything a caller passes: the family selects a
 * row and contributes no text. A command assembled from parts is a command
 * someone can inject a part into.
 *
 * ┌─ IT USED TO SAY `show-sensitive=no`, AND NO ROUTER ACCEPTS THAT ─────────┐
 * │ A real MikroTik answered:                                                │
 * │                                                                          │
 * │     expected end of command (line 1 column 29)                           │
 * │                                                                          │
 * │ Column 29 is the `=`. `show-sensitive` is a FLAG, not a named parameter: │
 * │ RouterOS reads the flag, then finds an `=` where the command should have │
 * │ ended. Every collection failed on this, with exit code 1 — the first     │
 * │ time this path met hardware instead of a fake.                           │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHY THE SPELLING DEPENDS ON THE FAMILY ─────────────────────────────────┐
 * │ The two majors redact in OPPOSITE directions:                            │
 * │                                                                          │
 * │  - RouterOS 6 PRINTS every sensitive value unless `hide-sensitive` is    │
 * │    given, and has no `show-sensitive` at all.                            │
 * │  - RouterOS 7 omits them unless `show-sensitive` is given. Naming no     │
 * │    flag is the safe form there.                                          │
 * │                                                                          │
 * │ This file used to say "since 6.43 the export redacts by default". That   │
 * │ is false, and believing it is what made a bare `/export terse` look safe │
 * │ everywhere. On RouterOS 6 that command writes every L2TP, IPsec and SNMP │
 * │ secret into the export (for an account holding the `sensitive` policy,   │
 * │ as the default `full` group does): over SSH into our process, and on the │
 * │ API path into a `.rsc` on the router's flash that `/tool/fetch` then     │
 * │ POSTs to us over plain HTTP, all BEFORE any read-back can refuse it. So  │
 * │ the RouterOS 6 row carries `hide-sensitive` and the RouterOS 7 row       │
 * │ carries nothing.                                                         │
 * │ `hide-sensitive` is not sent to RouterOS 7: nothing says every 7.x       │
 * │ accepts it, and a token that breaks the command on some firmware is      │
 * │ exactly the defect the box above records.                                │
 * │                                                                          │
 * │ The family is an INVENTORY claim (`devices.family`), and it goes stale:  │
 * │ an operator who upgrades a hEX from 6.49 to 7.x changes the dialect. So  │
 * │ BOTH paths ask the box its version BEFORE they export and refuse on a    │
 * │ contradiction — the API with `assertBoxSpeaksRecordedFamily()`           │
 * │ (`backup.service.ts`), SSH with `assertSshBoxSpeaksFamily()` below, on   │
 * │ the connection it already holds — and both fail CLOSED when that read    │
 * │ does not complete. The SSH path also checks the export's own preamble    │
 * │ afterwards (`exportDialectWarning()`), for a box whose version read      │
 * │ stated nothing usable, and the read-back (`findSensitiveProps()`)        │
 * │ refuses whatever got through anyway.                                     │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
export const ROUTEROS_EXPORT_FLAGS: Readonly<Record<RouterOsExportFamily, readonly string[]>> =
  Object.freeze({
    mikrotik_routeros6: Object.freeze(['terse', 'hide-sensitive']),
    mikrotik_routeros7: Object.freeze(['terse']),
  });

/**
 * The export flags for one family, or a refusal.
 *
 * REFUSES rather than defaulting: between two families that redact in opposite
 * directions, a guessed spelling is, half of the time, the one that prints the
 * fleet's secrets. The two tripwires make an edit of the table that removes
 * `hide-sensitive` from RouterOS 6, or adds the one flag that reveals, a thrown
 * error on the first call instead of a quiet change of what the no-secrets rule rests on.
 */
export function routerOsExportFlags(family: string | null | undefined): readonly string[] {
  if (family !== 'mikrotik_routeros6' && family !== 'mikrotik_routeros7') {
    throw new DriverError(
      `no RouterOS export spelling for family '${family ?? 'none'}': the flag that keeps ` +
        'secrets out of an export differs between RouterOS 6 and 7, and an unknown family is ' +
        'refused rather than given a guessed one',
      'NOT_IMPLEMENTED',
      { retryable: false },
    );
  }
  const flags = ROUTEROS_EXPORT_FLAGS[family];
  if (flags.some((f) => f.startsWith('show-sensitive'))) {
    throw new DriverError(`The ${family} export carries show-sensitive`, 'PROTOCOL_ERROR', {
      retryable: false,
    });
  }
  if (family === 'mikrotik_routeros6' && !flags.includes('hide-sensitive')) {
    throw new DriverError(
      'A RouterOS 6 export without hide-sensitive prints every secret',
      'PROTOCOL_ERROR',
      { retryable: false },
    );
  }
  return flags;
}

/**
 * The SSH (CLI) spelling: `/export terse hide-sensitive` on RouterOS 6,
 * `/export terse` on RouterOS 7. `verbose` adds the N09 oracle's flag; RouterOS
 * does not care about the order of flags.
 */
export function routerOsExportCommand(
  family: string | null | undefined,
  opts: { verbose?: boolean } = {},
): string {
  return ['/export', ...routerOsExportFlags(family), ...(opts.verbose ? ['verbose'] : [])].join(' ');
}

/**
 * The API spelling of the same flags — `=terse=`, `=hide-sensitive=`: on the
 * API a flag is an attribute with an empty value. The caller adds `=file=`.
 */
export function routerOsExportApiFlagWords(family: string | null | undefined): string[] {
  return routerOsExportFlags(family).map((f) => `=${f}=`);
}

// ============================================================================
// THE ONE NO-SECRETS EXCEPTION — learning mode (operator decision, 2026-10-04)
// ============================================================================
//
// ┌─ A SECOND TABLE, NOT A FLAG ON THE FIRST ────────────────────────────────┐
// │ `ROUTEROS_EXPORT_FLAGS` above and its two tripwires are UNTOUCHED: no    │
// │ parameter, option or override of the collection can add the flag that   │
// │ reveals. The learning capture spells its export from THIS table, which  │
// │ is the only place in the tree `show-sensitive` is spelled as a flag, and │
// │ whose only importer is `services/learning/capture.service.ts` (a source │
// │ scan in the learning harness keeps it that way).                         │
// │                                                                          │
// │ What the capture does with the text is the rest of the exception:       │
// │ `redactSensitiveExport()` below runs on it IN MEMORY, every secret goes  │
// │ to the vault, the copies kept carry `secret:<ref>`, and a text that      │
// │ could not be fully redacted is refused whole. The raw export is never    │
// │ stored, logged or written to disk.                                       │
// │                                                                          │
// │ RouterOS 6 prints every secret on a bare `/export terse` (it has no      │
// │ `show-sensitive`); RouterOS 7 needs `show-sensitive`. Reasoned from the  │
// │ documentation, as the main table is; the first real capture is the test. │
// └──────────────────────────────────────────────────────────────────────────┘
export const ROUTEROS_LEARNING_EXPORT_FLAGS: Readonly<Record<RouterOsExportFamily, readonly string[]>> =
  Object.freeze({
    mikrotik_routeros6: Object.freeze(['terse']),
    mikrotik_routeros7: Object.freeze(['terse', 'show-sensitive']),
  });

/** The learning capture's SSH command, or a refusal for an unknown family. */
export function routerOsLearningExportCommand(family: string | null | undefined): string {
  if (family !== 'mikrotik_routeros6' && family !== 'mikrotik_routeros7') {
    throw new DriverError(
      `no RouterOS learning export spelling for family '${family ?? 'none'}': an unknown family is ` +
        'refused rather than given a guessed one',
      'NOT_IMPLEMENTED',
      { retryable: false },
    );
  }
  return ['/export', ...ROUTEROS_LEARNING_EXPORT_FLAGS[family]].join(' ');
}

/**
 * The version read every SSH export is preceded by. It runs on the SAME
 * connection as the export — `SshTransport.exec()` opens one more channel on
 * the session it already holds — so asking first costs a round trip, not a
 * second login. Standard RouterOS scripting on 6 and 7; like most of this tree
 * it has been reasoned and faked, not yet observed on hardware.
 */
export const ROUTEROS_SSH_VERSION_COMMAND = ':put [/system resource get version]';

/**
 * A refusal decided by the version read, before any export was requested. A
 * class of its own so a caller that tolerates a FAILED export (the verbose
 * oracle) can still tell "the firmware has no such command" from "the
 * inventory is wrong and nothing was asked".
 */
export class ExportDialectRefusal extends DriverError {
  constructor(message: string) {
    super(message, 'PROTOCOL_ERROR', { transport: 'ssh', retryable: false });
    this.name = 'ExportDialectRefusal';
  }
}

/**
 * The SSH twin of `assertBoxSpeaksRecordedFamily()` (`backup.service.ts`): ask
 * the box its version BEFORE the export is spelled for `family`, and refuse
 * when the major contradicts it. That is what keeps a RouterOS 6 box recorded
 * as RouterOS 7 from being sent the bare `/export terse` that makes it print
 * every L2TP, IPsec and SNMP secret into this process — the read-back would
 * refuse to STORE them, but only after they had crossed the tunnel.
 *
 * Fails CLOSED on a read that did not complete: a transport error (timeout,
 * dropped session) propagates as it is, and a non-zero exit refuses. Only a
 * read that COMPLETED and states no usable version (empty, unparsable) is "no
 * claim": the recorded family then spells the export, `exportDialectWarning()`
 * checks the export's own preamble afterwards, and the read-back refuses
 * whatever got through. Returns the family the box claimed, or null.
 */
export async function assertSshBoxSpeaksFamily(
  ssh: Pick<SshTransport, 'exec'>,
  family: string,
  opts: { timeoutMs?: number } = {},
): Promise<DeviceFamily | null> {
  const result = await ssh.exec(ROUTEROS_SSH_VERSION_COMMAND, {
    pty: false,
    timeoutMs: opts.timeoutMs ?? 60_000,
    maxOutputBytes: 4096,
  });
  if (result.code !== null && result.code !== 0) {
    throw new ExportDialectRefusal(
      `the version read that precedes the export ('${ROUTEROS_SSH_VERSION_COMMAND}') exited with ` +
        `code ${result.code}: ${result.stderr.trim().slice(0, 200) || 'no stderr'}. Without it ` +
        `'${family}' cannot be checked against the box, so no export was requested.`,
    );
  }
  const version = (result.stdout.trim().split(/\r?\n/)[0] ?? '').trim().slice(0, 64);
  const observed = familyFromVersion(version || null);
  if (observed !== null && observed !== family) {
    throw new ExportDialectRefusal(
      `devices.family is '${family}' but the box reports RouterOS ${version}. The export is ` +
        'spelled differently on RouterOS 6 (hide-sensitive) and RouterOS 7 (no flag), so it was ' +
        "refused rather than requested in the wrong dialect. Correct the device's family; " +
        'nothing was exported.',
    );
  }
  return observed;
}

/**
 * The check made AFTER the fact, from the export's own preamble ("by RouterOS
 * 6.49.10"). The SSH paths ask the box first (`assertSshBoxSpeaksFamily()`),
 * so this can disagree only when that read stated no usable version and the
 * preamble does — and it is then the one sign that the export was spelled for
 * the wrong major. Returns the sentence, or null when the preamble agrees or
 * names no version.
 *
 * Not a refusal on its own: the text is already in memory, and
 * `findSensitiveProps()` is what decides whether it may be stored. When that
 * guard refuses, this sentence is carried INTO the refusal
 * (`assertNoSensitiveMaterial(raw, cause)`, and collect.service's twin) —
 * that is where an operator needs the CAUSE, so they fix the inventory instead
 * of the router. When it does not refuse, the sentence is a warning.
 */
export function exportDialectWarning(raw: string, family: string): string | null {
  const { preamble } = parsePreamble(canonicalizeText(raw));
  const observed = familyFromVersion(preamble.osVersion);
  if (observed === null || observed === family) return null;
  return (
    `devices.family is '${family}' but the export says RouterOS ${preamble.osVersion}, so it was ` +
    `requested in the wrong dialect ('${routerOsExportCommand(family)}')` +
    (observed === 'mikrotik_routeros6'
      ? ' — WITHOUT hide-sensitive on a RouterOS 6 box, which leaves the no-secrets rule to the read-back alone'
      : '') +
    ". Correct the device's family."
  );
}

export interface RouterOsExport {
  /** The export EXACTLY as the router produced it, preamble included. This is
   *  what `config_snapshots.raw_gz` stores and what `raw_sha256` covers. The
   *  raw is never normalised on disk: it is the only recoverable evidence the
   *  day a normalization rule turns out to be wrong, and it lets the whole
   *  corpus be replayed against a corrected ruleset without revisiting 300
   *  routers. */
  raw: string;
  preamble: RouterOsPreamble;
  /** From the preamble, and authoritative over `devices.family`: an operator
   *  who upgraded a hEX from 6.49 to 7.x changed the dialect. */
  observedFamily: DeviceFamily | null;
  collectedVia: 'ssh';
  collectedAt: string;
  durationMs: number;
  /** L0-level problems. A non-empty list is an acquisition defect to fix, not
   *  a diff to normalise. */
  warnings: string[];
}

/**
 * Runs the export over SSH.
 *
 * Not a method on `MikrotikRouterOsDriver`: `DeviceDriver.exportConfig` is
 * declared `Promise<never>` in `drivers/types.ts` (a file outside this
 * module), so widening its signature is a driver interface change, and
 * `exportConfig()` keeps throwing its dated `NotImplementedError` until that
 * signature moves. Loud and honest beats a method that lies about its return
 * type.
 *
 * IT HAS NO CALLER. The collection that runs is `collect.service.ts`
 * (`collectRaw()` → `runExport()`), which spells the export from the same
 * `routerOsExportCommand()`, asks the box the same version first
 * (`assertSshBoxSpeaksFamily()`) and refuses on the same `findSensitiveProps()`.
 * So this function is NOT where the no-secrets rule is held, and a fix made only here changes
 * nothing that runs.
 */
export async function collectRouterOsExport(ctx: DriverContext): Promise<RouterOsExport> {
  const channel = requireTransport(ctx, 'ssh');
  // Spelled (or refused) BEFORE the dial: an unknown family is not worth a socket.
  const command = routerOsExportCommand(ctx.family);
  const startedAt = Date.now();
  const raw = await runExportCommand(ctx, channel, command);
  const durationMs = Date.now() - startedAt;

  const warnings: string[] = [];
  const dialect = exportDialectWarning(raw, ctx.family as string);
  if (dialect) warnings.push(dialect);
  // Judged BEFORE the other warnings are worked out: a refusal must carry the
  // dialect cause itself, or it is lost with the `warnings` it never returns.
  assertNoSensitiveMaterial(raw, dialect);
  const lines = canonicalizeText(raw);
  const { unfolded } = unfoldLines(lines);
  if (unfolded > 0) {
    warnings.push(
      `the export contains ${unfolded} wrapped line(s): a pty was allocated on the export channel. ` +
        'The terminal width must never be an input to ncm_hash (N13) — fix the transport, ' +
        'do not rely on the parser unfolding it.',
    );
  }
  const { preamble } = parsePreamble(lines);
  if (!preamble.osVersion) {
    warnings.push(
      'no "by RouterOS <version>" preamble line: the os_version of this snapshot is unknown, ' +
        'so the N09 default dictionary cannot be applied and default_fill is skipped for it.',
    );
  }

  return {
    raw,
    preamble,
    observedFamily: familyFromVersion(preamble.osVersion),
    collectedVia: 'ssh',
    collectedAt: new Date().toISOString(),
    durationMs,
    warnings,
  };
}

/**
 * The verbose oracle of N09 — `verbose − terse` is the set of that firmware's
 * default values, learned instead of typed in. Like every other export, it is
 * spelled from `ROUTEROS_EXPORT_FLAGS` (so RouterOS 6 gets `hide-sensitive`)
 * and judged by `findSensitiveProps()` before it is returned.
 *
 * It is NEVER the source of a drift snapshot: verbose output is far more
 * volatile between versions, and using it as the snapshot would trade the
 * defaults problem for a much bigger one. It is an oracle, run at first contact
 * with a device, on any `os_version` change, and at most weekly.
 *
 * Whether it exists and what it returns on 6.49 and on 7.14 is question 1 of
 * The design, and it is UNRESOLVED: no MikroTik was available. So it
 * returns `null` when the COMMAND fails on this firmware — `verbose` is an
 * optimisation of the defaults dictionary, and losing it must not lose the
 * snapshot. It still THROWS on the three refusals — an unknown family, a box
 * whose version contradicts it (`ExportDialectRefusal`) and a text carrying a
 * secret: none of those is "the firmware has no verbose".
 *
 * Like `collectRouterOsExport()`, it has no caller yet.
 */
export async function collectRouterOsVerboseExport(ctx: DriverContext): Promise<string | null> {
  const channel = requireTransport(ctx, 'ssh');
  const command = routerOsExportCommand(ctx.family, { verbose: true });
  let raw: string;
  try {
    raw = await runExportCommand(ctx, channel, command);
  } catch (err) {
    if (err instanceof ExportDialectRefusal) throw err;
    return null;
  }
  assertNoSensitiveMaterial(raw, exportDialectWarning(raw, ctx.family as string));
  return raw;
}

async function runExportCommand(
  ctx: DriverContext,
  channel: ResolvedTransport,
  command: string,
): Promise<string> {
  if (!channel.host) {
    throw new DriverError('SSH transport row has no host', 'NO_TRANSPORT', {
      transport: 'ssh',
      retryable: false,
    });
  }
  const { username } = channel.credentials;
  if (!username) {
    throw new DriverError('SSH transport row has no username in the vault', 'AUTH_FAILED', {
      transport: 'ssh',
      retryable: false,
    });
  }

  const target: SshTarget = {
    host: channel.host,
    port: channel.port ?? undefined,
    username,
    password: channel.credentials.password ?? null,
    privateKey: channel.credentials.privateKey ?? null,
    passphrase: channel.credentials.passphrase ?? null,
    timeoutMs: ctx.timeoutMs ?? 60_000,
    legacyAlgorithms: channel.params?.['legacyAlgorithms'] === true,
  };

  return withSsh(target, async (ssh) => {
    // The box is asked its major BEFORE the export, on this same connection.
    await assertSshBoxSpeaksFamily(ssh, ctx.family as string, { timeoutMs: ctx.timeoutMs });
    const result = await ssh.exec(command, {
      // N13: the whole point.
      pty: false,
      timeoutMs: ctx.timeoutMs ?? 60_000,
    });
    if (result.code !== null && result.code !== 0) {
      throw new DriverError(
        `RouterOS "${command}" exited with code ${result.code}: ${result.stderr.trim().slice(0, 200)}`,
        'PROTOCOL_ERROR',
        { transport: 'ssh' },
      );
    }
    if (/not enough permissions|no such command/i.test(result.stderr)) {
      throw new DriverError(
        `RouterOS refused "${command}": ${result.stderr.trim().slice(0, 200)}`,
        'PERMISSION_DENIED',
        { transport: 'ssh', retryable: false },
      );
    }
    if (result.stdout.trim() === '') {
      // An empty export read as "this router has no configuration" is how a
      // drift engine invents a full-fleet wipe. Never return it as a document.
      throw new DriverError(
        `RouterOS "${command}" returned an empty document`,
        'PROTOCOL_ERROR',
        { transport: 'ssh' },
      );
    }
    return result.stdout;
  });
}

// ============================================================================
// The secrets guard. ONE rule, and it is the one that runs.
// ============================================================================
//
// `collect.service.ts` runs it over every SSH export before anything is
// stored; `backup.service.ts` over every `.rsc` it pulls off a router;
// `rollback.service.ts` over the comparison export; and
// `test/fixtures/configs/mikrotik/goldenCheck.ts` over every committed fixture.
// There used to be two lists — a narrower one on the live path, and this one,
// which ran nowhere on it while the header above credited it with the rule. The
// live one listed thirteen exact names, each matched only after whitespace or
// `;`, so `ipsec-secret=`, `tcp-md5-key=`, `preshared-key=` and the SNMPv3
// passwords all passed it.

/**
 * Every property name RouterOS classes as sensitive somewhere.
 *
 * SOURCE: MikroTik's "List of menus with sensitive parameters" (Configuration
 * Management, help.mikrotik.com, read WITH its per-row page
 * links, which say which submenu each name belongs to) — i.e. the values
 * RouterOS itself classes as sensitive — plus the RouterOS 6 spellings of the
 * same settings that list no longer names. By menu, as MikroTik lists them
 * (its list also names command arguments that never appear in an export, such
 * as `/password` or `/system backup`; they are left out here):
 *
 *   ppp/secret                       password
 *   ppp/l2tp-secret                  secret
 *   interface/{l2tp-server,l2tp-client,l2tp-ether}   password, ipsec-secret
 *   interface/{pptp,sstp,ovpn,pppoe}-client          password
 *   interface/ppp-client             password, pin
 *   interface/{gre,gre6,ipip,ipipv6,eoip,eoipv6,6to4}   ipsec-secret
 *   ip/ipsec  identity               secret, password
 *             peer                   ppk-secret
 *             key                    key, passphrase     (`key`: menu-scoped)
 *             installed-sa           auth-key, enc-key   (runtime, never exported)
 *   interface/wireguard              private-key, preshared-key
 *   interface/wireless               wpa-pre-shared-key, wpa2-pre-shared-key,
 *                                    private-pre-shared-key, private-key,
 *                                    static-key-0..3, static-sta-private-key,
 *                                    management-protection-key,
 *                                    nv2-preshared-key, mschapv2-password
 *   interface/wifi                   passphrase, eap-password (also dotted,
 *                                    `security.passphrase=` on the interface)
 *   caps-man                         passphrase, private-passphrase
 *   interface/{vrrp,dot1x,w60g}      password
 *   interface/macsec                 cak
 *   interface/lte                    pin, password
 *   snmp/community                   authentication-password, encryption-password
 *   routing   rip                    password
 *             bgp connection         tcp-md5-key
 *             ospf interface-template   auth-key         (`auth-key`: menu-scoped)
 *             rip keys               key      NOT on MikroTik's list — see below
 *   radius                           secret
 *   ip/hotspot                       password, otp-secret
 *   ip/smb, socks/users, container   password
 *   ip/cloud                         private-key, vpn-private-key,
 *                                    vpn-peer-private-key
 *   system/ntp/key                   key-val
 *   tool/romon                       secrets
 *   tool/sms                         secret, sim-pin
 *   tool/email, system/ssh-exec      password
 *   tr069-client                     password, connection-request-password
 *   user-manager                     password, shared-secret, otp-secret,
 *                                    web-private-password, paypal-password
 *   user                             password, passphrase
 *   disk                             encryption-key, *-password
 *   certificate                      passphrase, pin, *-passphrase,
 *                                    challenge-password
 *   iot       mqtt brokers           password
 *             lora servers           key                 (`key`: menu-scoped)
 *   zerotier                         identity            (menu-scoped)
 *   RouterOS 6 only                  authentication-key (OSPF, RIP),
 *                                    xauth-password (IPsec peer) — from the v6
 *                                    manual as remembered, NOT re-read; the
 *                                    suffix rule below covers both anyway
 *
 * TWO RULES, AND WHICH ONE A NAME FALLS UNDER IS THE POINT.
 *
 *  1. A name that is a secret wherever it is spelled — `password`, `secret`,
 *     `ipsec-secret`, `preshared-key`, … — is judged by NAME, in every menu,
 *     on the LAST dotted segment, exact OR by suffix (`-password`, `-secret`,
 *     `-passphrase`, `-key`, `-pin`, `-psk`), so a name this table missed but
 *     spelled like its neighbours is refused too. That is also what catches a
 *     `password=` written inside a script source or a comment.
 *  2. A name that RouterOS ALSO uses for something that is not a secret is
 *     judged by MENU, and rule 1 is never consulted for it
 *     (`MENU_SCOPED_PROPS`). There are three. `key` is a secret in
 *     `/ip ipsec key`, `/iot` and `/routing` (below), and a NAME in
 *     `/ip ipsec identity` (the private key to use, from the keys menu) and
 *     `/container envs` (the variable). `auth-key` is a secret in `/routing`
 *     (OSPF) and `/ip ipsec`, and an integer KEY ID in `/system ntp server` and
 *     `/system ntp client servers` (MikroTik's NTP page: "Key Identifier (Key
 *     ID)"). `identity` is a private key in `/zerotier` and a name everywhere
 *     else (dot1x). Inside a QUOTED value — a script source, a comment — the
 *     menu is not the one holding the value but one INFERRED from the commands
 *     written inside it (`isSensitiveAt()`), so the burden flips: there only a
 *     documented homonym's menu clears the name, and anything else refuses.
 *
 * ONE SCOPE THE LIST DOES NOT GIVE: `key` under `/routing`. MikroTik's routing
 * row is `password, tcp-md5-key, auth-key` (read off the raw
 * page) and does NOT name `key`. But `/routing rip keys` holds RIP's MD5
 * authentication keys in a property called `key`, which MikroTik's RIP page
 * documents as "authentication key" WITHOUT the `sensitive` marker it puts on
 * the RIP `password` (RouterOS 7; RouterOS 6 has the same
 * menu as remembered from the v6 manual, NOT re-read). Not being classed
 * sensitive means no flag hides it, on either major — so the guard is the
 * only thing between those keys and the snapshot store, and it judges `key` a
 * secret anywhere under `/routing`, where no non-secret `key` is known. Its
 * cost is the one rule 1 already accepts: a box with RIP MD5 authentication is
 * refused, naming `key`, until the key leaves the export.
 *
 * Judging those three by name everywhere was a defect, not caution: a healthy
 * RouterOS 7 export of a box with an RSA-key IPsec identity or NTP
 * authentication had every collection refused and every push stopped at the
 * preflight `.rsc`, with no remedy short of reconfiguring the customer's box.
 * Rule 1 still fails CLOSED for every other name — a false alarm costs one
 * refused collection naming the prop; a miss costs the fleet's secrets — which
 * is why a name only moves to rule 2 when MikroTik's own list and a documented
 * non-secret homonym both say so.
 *
 * NOT JUDGED HERE, on purpose:
 *  - `/snmp community name=` — for v1/v2c the community IS the secret, but it
 *    is not on MikroTik's list, so every export carries it, and the NCM keeps
 *    it deliberately (whether it is literally `public` is the audit).
 *  - free-text values RouterOS never classifies (`/container envs value=`,
 *    a DHCP option `value=`). A `password=` written INSIDE a script source or
 *    a comment IS caught, because the scan reads the raw text, quotes
 *    included — and so is a scoped name there (`auth-key=` after a
 *    `/routing ospf …` inside a script), which only a documented homonym's
 *    menu written before it inside the value can clear.
 *
 * Also the list `goldenCheck.ts` scans normalised documents for, which is why
 * it still names `key` and `auth-key`: in an NCM document neither should
 * appear at all. In an EXPORT, `isSensitiveProp()` judges both by menu.
 */
export const SENSITIVE_PROPS: readonly string[] = [
  'password', 'secret', 'secrets', 'passphrase', 'key', 'key-val', 'pin', 'cak', 'psk',
  'ipsec-secret', 'ppk-secret', 'shared-secret', 'otp-secret',
  'pre-shared-key', 'wpa-pre-shared-key', 'wpa2-pre-shared-key', 'private-pre-shared-key',
  'preshared-key', 'nv2-preshared-key', 'private-key', 'static-sta-private-key',
  'vpn-private-key', 'vpn-peer-private-key', 'management-protection-key',
  'auth-key', 'enc-key', 'tcp-md5-key', 'authentication-key', 'encryption-key',
  'authentication-password', 'encryption-password', 'mschapv2-password', 'eap-password',
  'xauth-password', 'connection-request-password', 'challenge-password',
  'private-passphrase', 'sim-pin',
];

const SENSITIVE_PROP_SET: ReadonlySet<string> = new Set(SENSITIVE_PROPS);

const SENSITIVE_SUFFIX_RE = /-(?:password|secret|passphrase|key|pin|psk)$/;

/** `/interface wireless security-profiles` WEP keys: `static-key-0` .. `-3`. */
const STATIC_WEP_KEY_RE = /^static-key-\d$/;

/**
 * Names that END like a secret and are not one. Each entry is a public value or
 * a reference to something stored elsewhere, and each would otherwise refuse a
 * healthy export.
 */
const NOT_SENSITIVE_PROPS: ReadonlySet<string> = new Set([
  // `/interface wireguard peers`: the PEER's public key. Public by definition.
  'public-key',
  // `/ip ipsec identity`: the NAME of a public key in `/ip ipsec key`.
  'remote-key',
  // `/interface wireless security-profiles`: WHICH of key-0..3 to transmit
  // with — an index, not a key.
  'static-transmit-key',
]);

/**
 * Rule 2 of the table above: the names whose verdict is the MENU's, and the
 * menus where each one is a secret. Where the export states the menu, a scoped
 * name is sensitive in those menus and NOWHERE else — neither the exact-name
 * set nor the `-key` suffix is consulted for it, or `auth-key` would be
 * refused under `/system ntp` by the suffix after being cleared by its menu.
 * Where the menu has to be inferred (inside a quoted value), see
 * `isSensitiveAt()`.
 *
 * `menu` is matched against the line's own menu path (terse export), the last
 * section header (sectioned export), or — for an assignment inside a quoted
 * value — a menu written inside that value (`findSensitiveProps()`). The scope
 * is the row of MikroTik's list (`routing`, `ip/ipsec`, `iot`), narrowed to
 * the submenu only where a non-secret homonym lives inside that same row:
 * `key` is a name under `/ip ipsec identity`, so it is a secret under
 * `/ip ipsec key` only. `key` under `/routing` is the one scope the list does
 * not give (the RIP key chain; see the table above).
 */
const MENU_SCOPED_PROPS: ReadonlyMap<string, readonly RegExp[]> = new Map([
  ['key', [/^\/ip[\s/]+ipsec[\s/]+key(?![\w-])/, /^\/iot(?![\w-])/, /^\/routing(?![\w-])/]],
  ['auth-key', [/^\/routing(?![\w-])/, /^\/ip[\s/]+ipsec(?![\w-])/]],
  ['identity', [/^\/zerotier(?![\w-])/]],
]);

/** The verdict for one property name in one menu. Exported for the harness. */
export function isSensitiveProp(name: string, menu: string): boolean {
  const prop = name.slice(name.lastIndexOf('.') + 1).toLowerCase();
  const scopedTo = MENU_SCOPED_PROPS.get(prop);
  if (scopedTo) return scopedTo.some((re) => re.test(menu));
  if (NOT_SENSITIVE_PROPS.has(prop)) return false;
  return (
    SENSITIVE_PROP_SET.has(prop) || SENSITIVE_SUFFIX_RE.test(prop) || STATIC_WEP_KEY_RE.test(prop)
  );
}

/**
 * A property assignment: a name starting at the beginning of the line or after
 * whitespace, `;`, an opening bracket or a quote. Dots are part of the name, so
 * `security.passphrase=` is read whole and judged on `passphrase`. The quote is
 * there for an assignment that OPENS a quoted value (`comment="psk=…"`, or a
 * script whose first word is one), which every other separator missed.
 */
const PROP_ASSIGNMENT_RE = /(?:^|[\s;{("\[])([A-Za-z][\w.-]*)=/g;

/** `prop=` followed by nothing, or by `""`. Whether RouterOS omits a redacted
 *  prop or prints it blank, menu by menu, is unobserved (an open question);
 *  both read as "no secret here". Anything else — including an escaped `\"\"`
 *  inside a script — counts as a value. */
const EMPTY_VALUE_RE = /^(?:"")?(?:[\s;})\]]|$)/;

/**
 * A menu path written INSIDE a quoted value: a `/` and a letter, at the start
 * of the value or after a separator — whitespace, a quote, a bracket, a brace,
 * a parenthesis, `;` — or after the `\r` / `\n` / `\t` escapes an exported
 * script writes its line breaks with (`…\r\n/ip ipsec key add …`, where the
 * character before the `/` is an `n`). A `/` after `=`, `:` or a letter
 * (`src-path=/flash`, `https://host/x`) is a path, not a menu.
 */
const MENU_IN_VALUE_RE = /(?<=^|[\s"[\]{}();]|\\[rnt])\/[A-Za-z]/g;

/**
 * The index of the `"` that opens the quoted value position `at` sits in, or
 * -1 when it sits in none. A backslash escapes the next character, so a `\"`
 * inside a script source is a quote IN the script, not the end of the value.
 */
function openingQuoteBefore(text: string, at: number): number {
  let open = -1;
  for (let i = 0; i < at; i++) {
    const c = text[i];
    if (c === '\\') {
      i++;
      continue;
    }
    if (c === '"') open = open < 0 ? i : -1;
  }
  return open;
}

/**
 * For a scoped name inside a QUOTED value only: the menus where it is
 * documented as NOT a secret — the homonyms that moved it to rule 2. Nothing
 * else clears it there (`isSensitiveAt()`).
 */
const DOCUMENTED_HOMONYMS: ReadonlyMap<string, readonly RegExp[]> = new Map([
  ['key', [/^\/ip[\s/]+ipsec[\s/]+identity(?![\w-])/, /^\/container[\s/]+envs(?![\w-])/]],
  ['auth-key', [/^\/system[\s/]+ntp(?![\w-])/]],
  ['identity', [/^\/interface[\s/]+dot1x(?![\w-])/]],
]);

/**
 * The verdict for one assignment WHERE IT STANDS.
 *
 * A rule-1 name is judged by name, wherever it is. A scoped name in a line's
 * own arguments is judged by the line's menu, which the export states. A
 * scoped name inside a QUOTED value — a script source, a comment — is NOT
 * judged by the menu holding the value: `/system script add source="/routing
 * ospf interface-template set [find] auth-key=…"` is an OSPF key, and
 * `/system script` says nothing about it. There the menu has to be INFERRED
 * from the text, so the burden flips:
 *  - every menu written inside the value before the assignment is a candidate
 *    (the rest of the value from there, `\r\n` read as a space, so
 *    `/ip ipsec\r\nkey add` reads as the keys menu), and ANY candidate in
 *    which the name is a secret makes it one;
 *  - otherwise the name is cleared only by a candidate that is one of its
 *    DOCUMENTED non-secret homonyms (`DOCUMENTED_HOMONYMS`);
 *  - a value that names no menu, or only menus that are neither (a comment
 *    that mentions `/flash/…`), says nothing about which homonym this is, and
 *    the name is judged a secret — rule 1's fail-closed reasoning, applied
 *    where the menu is a guess.
 */
function isSensitiveAt(name: string, text: string, at: number, section: string): boolean {
  const prop = name.slice(name.lastIndexOf('.') + 1).toLowerCase();
  if (!MENU_SCOPED_PROPS.has(prop)) return isSensitiveProp(name, section);
  const open = openingQuoteBefore(text, at);
  if (open < 0) return isSensitiveProp(name, section);
  const value = text.slice(open + 1, at);
  const menus = [...value.matchAll(MENU_IN_VALUE_RE)].map((m) =>
    value.slice(m.index ?? 0).replace(/\\[rnt]/g, ' '),
  );
  if (menus.some((menu) => isSensitiveProp(name, menu))) return true;
  const homonyms = DOCUMENTED_HOMONYMS.get(prop) ?? [];
  return !menus.some((menu) => homonyms.some((re) => re.test(menu)));
}

/**
 * The names of every sensitive property that carries a NON-EMPTY value in a
 * RouterOS export, sorted and lower-cased. NEVER a value: the result ends up
 * in an error message, an error message is a log line, and a log line is what
 * the no-secrets rule forbids a secret from reaching.
 *
 * Works on terse and sectioned exports alike, and unfolds `\` continuations
 * first so a value wrapped onto the next line is judged as the value it is.
 *
 * `allowPlaceholders` is for the learning copies ONLY: a TOP-LEVEL value that
 * is exactly `secret:<ref>` (what `redactSensitiveExport()` leaves in place of
 * a vaulted value) is then not a hit. The default is unchanged, so every secrets
 * gate of the collection, the backup and the rollback still REFUSES a
 * placeholdered text — a learning copy cannot slip into the ordinary store.
 */
export function findSensitiveProps(raw: string, opts: { allowPlaceholders?: boolean } = {}): string[] {
  const hits = new Set<string>();
  let section = '';
  for (const line of unfoldLines(canonicalizeText(raw)).lines) {
    const text = line.trimStart();
    if (text.startsWith('/')) section = text;
    for (const m of text.matchAll(PROP_ASSIGNMENT_RE)) {
      const name = m[1];
      // Where the NAME starts: the match may begin with its separator.
      const at = (m.index ?? 0) + m[0].length - name.length - 1;
      if (!isSensitiveAt(name, text, at, section)) continue;
      const rest = text.slice((m.index ?? 0) + m[0].length);
      if (EMPTY_VALUE_RE.test(rest)) continue;
      if (opts.allowPlaceholders === true && isPlaceholderValue(rest) && openingQuoteBefore(text, at) < 0) continue;
      hits.add(name.toLowerCase());
    }
  }
  return [...hits].sort();
}

/** `rest` (the text after `prop=`) starts with exactly `secret:<ref>` as a
 *  bare token. */
function isPlaceholderValue(rest: string): boolean {
  if (!rest.startsWith(LEARNING_PLACEHOLDER_PREFIX)) return false;
  const end = rest.search(/[\s;})\]]/);
  const token = end < 0 ? rest : rest.slice(0, end);
  return LEARNING_REF_RE.test(token.slice(LEARNING_PLACEHOLDER_PREFIX.length));
}

/**
 * The operator-facing half of every refusal, shared so the collection, the
 * backup and the rollback check all say the same true thing.
 */
export const SENSITIVE_REFUSAL_HINT =
  'It was REFUSED, not redacted: nothing was stored. Either the value sits where RouterOS ' +
  'never redacts (a script source, a comment, a RIP key chain) and has to be removed from the ' +
  'device, or the export was requested in the wrong dialect — RouterOS 6 prints these values ' +
  'unless asked for hide-sensitive, RouterOS 7 hides them unasked — so check that the device\'s ' +
  'family matches the RouterOS major it actually runs. No value is reproduced in this message.';

/**
 * Throwing form of `findSensitiveProps()`, for the driver-level collector and
 * the fixture check. `collect.service.ts` and `backup.service.ts` wrap the same
 * detector in their own error types.
 *
 * REFUSING IS THE POINT. The alternative — strip it and carry on — would let
 * the fleet run for months one refactor away from persisting every PSK it owns,
 * and hide from the operator a service account or a firmware that needs fixing.
 *
 * `cause` is the dialect sentence (`exportDialectWarning()`) when the export's
 * preamble contradicts the family it was spelled for: carried in the refusal
 * because the refusal is the only thing the caller gets back.
 */
export function assertNoSensitiveMaterial(raw: string, cause?: string | null): void {
  const hits = findSensitiveProps(raw);
  if (hits.length === 0) return;
  throw new DriverError(
    `the export carries a value for sensitive prop(s) [${hits.join(', ')}]. ` +
      `${cause ? `${cause} ` : ''}${SENSITIVE_REFUSAL_HINT}`,
    'PROTOCOL_ERROR',
    { transport: 'ssh', retryable: false },
  );
}

// ============================================================================
// Learning mode — the redaction that runs on a show-sensitive export IN MEMORY
// ============================================================================
//
// `redactSensitiveExport()` is the other half of the learning-mode exception above. It
// takes the export the learning capture read WITH its secrets and returns:
//
//  - `text`: the same export with every TOP-LEVEL sensitive value replaced by
//    `secret:<ref>` — the copy that is stored, handed over and compared;
//  - `secrets`: each value with its ref, for the vault, and nowhere else;
//  - `withheld`: the lines whose secret sits INSIDE a quoted value (a script
//    source, a comment). Such a value cannot be cut out without rewriting the
//    script, so the whole line becomes `# obliwan: line withheld (...)` and
//    its secret is NOT vaulted (it is not a property RouterOS knows).
//
// It is built on the SAME detector as the secrets gate (`PROP_ASSIGNMENT_RE`,
// `isSensitiveAt`, `EMPTY_VALUE_RE`, `openingQuoteBefore`), so what it cuts
// is exactly what the ordinary gate would have refused. Every output line is
// judged again (`findSensitiveProps(line, { allowPlaceholders: true })`) and a
// line still dirty is withheld; a whole text that is still dirty after that
// THROWS `RedactionIncompleteError`, which names props and never a value, and
// the capture then stores nothing at all.

/** The comment a withheld line becomes. */
export const LEARNING_WITHHELD_PREFIX = '# obliwan: line withheld';

export interface LearningSecret {
  ref: string;
  /** Canonical menu path, `/interface/l2tp-client`. */
  menu: string;
  /** The item's name (`name=` / `peer=` / `[ find default-name= ]`), `n<k>`
   *  for an unnamed `add`, or null for a singleton. */
  item: string | null;
  prop: string;
  /** THE PLAINTEXT. For the vault only: never logged, never in an error. */
  value: string;
}

export interface RedactedLearningExport {
  text: string;
  secrets: LearningSecret[];
  withheld: Array<{ line: number; menu: string; props: string[] }>;
}

/** The text could not be fully redacted. Names props only, never a value. */
export class RedactionIncompleteError extends Error {
  readonly props: readonly string[];
  constructor(props: readonly string[]) {
    super(
      `the learning export could not be fully redacted: sensitive prop(s) [${props.join(', ')}] ` +
        'still carry a value after redaction. Nothing was stored. No value is reproduced in this message.',
    );
    this.name = 'RedactionIncompleteError';
    this.props = props;
  }
}

const LEARNING_VERBS = new Set(['add', 'set', 'remove', 'unset']);

/** RouterOS prints a non-ASCII byte as `\XX`; `unquote` turns each into
 *  U+00XX. Re-read as UTF-8 when the bytes ARE valid UTF-8. */
function repairLatin1Utf8(s: string): string {
  if (!/[\u0080-ÿ]/.test(s) || /[^\u0000-ÿ]/.test(s)) return s;
  const bytes = Buffer.from(s, 'latin1');
  const text = bytes.toString('utf8');
  if (text.includes('�') || !Buffer.from(text, 'utf8').equals(bytes)) return s;
  return text;
}

function refSlug(s: string): string {
  const out = s.toLowerCase().replace(/[^a-z0-9_-]/g, '_').slice(0, 48);
  return out === '' ? '_' : out;
}

function menuSlug(path: string): string {
  const parts = path.split('/').filter((p) => p !== '').map((p) => p.toLowerCase().replace(/[^a-z0-9_-]/g, '_'));
  return parts.length === 0 ? 'root' : parts.join('.');
}

/** End of the value token that starts at `start`: quoted (backslash escapes)
 *  or bare up to whitespace. */
function valueTokenEnd(text: string, start: number): number {
  if (text[start] === '"') {
    let i = start + 1;
    while (i < text.length) {
      if (text[i] === '\\') { i += 2; continue; }
      if (text[i] === '"') return i + 1;
      i++;
    }
    return text.length;
  }
  let i = start;
  while (i < text.length && text[i] !== ' ' && text[i] !== '\t') i += text[i] === '\\' ? 2 : 1;
  return Math.min(i, text.length);
}

interface LineShape {
  /** Canonical menu path of the line. */
  path: string;
  verb: string | null;
  tokens: string[];
  verbAt: number;
  /** A sectioned header (`/ip address`), which carries no assignment. */
  header: boolean;
}

function lineShape(text: string, section: string): LineShape {
  const tokens = tokenize(text);
  if (text.startsWith('/')) {
    for (let i = 1; i < tokens.length; i++) {
      const t = tokens[i];
      if (t.includes('=') || t === '[') break;
      if (LEARNING_VERBS.has(t)) return { path: canonicalSectionPath(tokens.slice(0, i)), verb: t, tokens, verbAt: i, header: false };
    }
    if (!tokens.some((t) => t.includes('='))) {
      return { path: canonicalSectionPath(tokens), verb: null, tokens, verbAt: -1, header: true };
    }
    return { path: section || '/', verb: null, tokens, verbAt: -1, header: false };
  }
  if (tokens.length > 0 && LEARNING_VERBS.has(tokens[0])) {
    return { path: section || '/', verb: tokens[0], tokens, verbAt: 0, header: false };
  }
  return { path: section || '/', verb: null, tokens, verbAt: -1, header: false };
}

/** The item of a line, for its secrets' refs. */
function itemOf(shape: LineShape, addIndex: number): string | null {
  const { tokens, verbAt, verb } = shape;
  if (verb === 'add') {
    for (const key of ['name', 'peer']) {
      const tok = tokens.slice(verbAt + 1).find((t) => t.startsWith(`${key}=`));
      if (tok) {
        const v = repairLatin1Utf8(unquote(tok.slice(key.length + 1)));
        if (v !== '') return v.slice(0, 128);
      }
    }
    return `n${addIndex}`;
  }
  if (verb === 'set') {
    const next = tokens[verbAt + 1];
    if (next === '[') {
      const inner: string[] = [];
      for (let i = verbAt + 2; i < tokens.length && tokens[i] !== ']'; i++) {
        if (tokens[i] !== 'find' && tokens[i] !== 'where') inner.push(tokens[i]);
      }
      for (const key of ['default-name', 'name']) {
        const tok = inner.find((t) => t.startsWith(`${key}=`));
        if (tok) return repairLatin1Utf8(unquote(tok.slice(key.length + 1))).slice(0, 128) || '_';
      }
      if (inner.includes('default=yes')) return 'default';
      const first = inner.find((t) => t.includes('='));
      if (first) {
        const eq = first.indexOf('=');
        return `${first.slice(0, eq)}-${repairLatin1Utf8(unquote(first.slice(eq + 1)))}`.slice(0, 128);
      }
      return null;
    }
    if (next !== undefined && !next.includes('=')) return repairLatin1Utf8(unquote(next)).slice(0, 128);
  }
  return null;
}

/**
 * Redact a learning export (see the block above). Pure: no I/O, no log.
 * Refs are deterministic — the same export gives the same refs — and a
 * collision inside one export gets `~2`, `~3`.
 */
export function redactSensitiveExport(raw: string): RedactedLearningExport {
  const lines = unfoldLines(canonicalizeText(raw)).lines;
  const out: string[] = [];
  const secrets: LearningSecret[] = [];
  const withheld: RedactedLearningExport['withheld'] = [];
  const usedRefs = new Set<string>();
  const addCounters = new Map<string, number>();
  let section = '';
  let sectionPath = '';

  for (const line of lines) {
    const text = line.trimStart();
    if (text.startsWith('/')) section = text;
    if (text === '' || text.startsWith('#')) {
      // A preamble or comment line can still carry an assignment: it is not a
      // property RouterOS knows, so it is withheld, never vaulted.
      const props = findSensitiveProps(text);
      if (props.length === 0) {
        out.push(line);
      } else {
        out.push(`${LEARNING_WITHHELD_PREFIX} (${sectionPath || '/'}; ${props.join(', ')})`);
        withheld.push({ line: out.length, menu: sectionPath || '/', props });
      }
      continue;
    }
    const shape = lineShape(text, sectionPath);
    if (shape.header) sectionPath = shape.path;
    let addIndex = 0;
    if (shape.verb === 'add') {
      addIndex = (addCounters.get(shape.path) ?? 0) + 1;
      addCounters.set(shape.path, addIndex);
    }

    const hits: Array<{ name: string; valueStart: number; inside: boolean }> = [];
    for (const m of text.matchAll(PROP_ASSIGNMENT_RE)) {
      const name = m[1];
      const at = (m.index ?? 0) + m[0].length - name.length - 1;
      if (!isSensitiveAt(name, text, at, section)) continue;
      const valueStart = (m.index ?? 0) + m[0].length;
      if (EMPTY_VALUE_RE.test(text.slice(valueStart))) continue;
      hits.push({ name, valueStart, inside: openingQuoteBefore(text, at) >= 0 });
    }
    if (hits.length === 0) {
      out.push(line);
      continue;
    }

    const props = [...new Set(hits.map((h) => h.name.toLowerCase()))].sort();
    const withhold = (): void => {
      out.push(`${LEARNING_WITHHELD_PREFIX} (${shape.path}; ${props.join(', ')})`);
      withheld.push({ line: out.length, menu: shape.path, props });
    };
    if (hits.some((h) => h.inside)) {
      withhold();
      continue;
    }

    const item = itemOf(shape, addIndex);
    const lineSecrets: LearningSecret[] = [];
    const lineRefs: string[] = [];
    let rebuilt = text;
    // Right to left, so earlier offsets stay valid.
    for (const hit of [...hits].sort((a, b) => b.valueStart - a.valueStart)) {
      const end = valueTokenEnd(rebuilt, hit.valueStart);
      const token = rebuilt.slice(hit.valueStart, end);
      const prop = hit.name.toLowerCase();
      const propSlug = prop.replace(/[^a-z0-9._-]/g, '_');
      const base = `${menuSlug(shape.path)}.${item === null ? '_' : refSlug(item)}.${propSlug}`.slice(0, 190);
      let ref = base;
      for (let k = 2; usedRefs.has(ref) || lineRefs.includes(ref); k++) ref = `${base}~${k}`;
      if (!LEARNING_REF_RE.test(ref)) {
        lineSecrets.length = 0;
        rebuilt = '';
        break;
      }
      lineRefs.push(ref);
      lineSecrets.push({
        ref,
        menu: shape.path,
        item,
        prop,
        value: repairLatin1Utf8(unquote(token)),
      });
      rebuilt = rebuilt.slice(0, hit.valueStart) + learningPlaceholder(ref) + rebuilt.slice(end);
    }
    const header = text.startsWith('/') ? '' : `${section}\n`;
    if (rebuilt === '' || findSensitiveProps(`${header}${rebuilt}`, { allowPlaceholders: true }).length > 0) {
      withhold();
      continue;
    }
    for (const r of lineRefs) usedRefs.add(r);
    secrets.push(...lineSecrets.reverse());
    out.push(line.slice(0, line.length - text.length) + rebuilt);
  }

  const result = out.join('\n');
  const left = findSensitiveProps(result, { allowPlaceholders: true });
  if (left.length > 0) throw new RedactionIncompleteError(left);
  return { text: result, secrets, withheld };
}

const PLACEHOLDER_ASSIGNMENT_RE = /[ \t]+[A-Za-z][\w.-]*=secret:[a-z0-9][a-z0-9._~-]{0,199}(?=[ \t]|$)/g;

/**
 * A learning copy as the ORDINARY store would hold it: every ` prop=secret:<ref>`
 * assignment removed (the redacted form RouterOS 7 prints without
 * `show-sensitive`), and every withheld-line comment dropped. What is left
 * goes through the unchanged secrets gate before it may become a snapshot.
 */
export function stripLearningPlaceholders(text: string): string {
  const kept: string[] = [];
  for (const line of text.split('\n')) {
    if (line.trimStart().startsWith(LEARNING_WITHHELD_PREFIX)) continue;
    let rebuilt = '';
    let last = 0;
    for (const m of line.matchAll(PLACEHOLDER_ASSIGNMENT_RE)) {
      const start = m.index ?? 0;
      if (openingQuoteBefore(line, start) >= 0) continue;
      rebuilt += line.slice(last, start);
      last = start + m[0].length;
    }
    kept.push(rebuilt + line.slice(last));
  }
  return kept.join('\n');
}
