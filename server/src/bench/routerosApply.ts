/**
 * ObliWAN — first configuration of a factory MikroTik on the bench.
 *
 * ┌─ WHAT THIS DOES, IN THE ORDER IT DOES IT ────────────────────────────────┐
 * │ 1. log in over the RouterOS API with the factory credential;              │
 * │ 2. read the router's OWN interface MACs and refuse unless the MAC the     │
 * │    preparer typed is among them;                                         │
 * │ 3. read version and board, for the caller and for step 4;                 │
 * │ 3b. read the SIM card in `lte1` (ICCID, IMSI) — read-only, waiting a      │
 * │    bounded minute for a modem that has just booted; a box with no modem   │
 * │    or no card is an answer, never a refusal (`readSimCard`);              │
 * │ 4. put TWO files on the box — the rendered configuration (the "body")     │
 * │    and the runner that imports it (`/file/add` on RouterOS 7; SFTP when   │
 * │    that is refused or the box runs RouterOS 6) — and refuse unless the    │
 * │    sizes the router reports agree with what was sent;                     │
 * │ 5. `/system/reset-configuration no-defaults=yes skip-backup=yes           │
 * │    run-after-reset=<runner>` — the box wipes itself, reboots, and runs    │
 * │    the runner on first boot. The session dropping is the EXPECTED         │
 * │    outcome.                                                               │
 * │                                                                          │
 * │ Steps 1-3 alone are `identifyFactoryBox()`: read-only, for the screen     │
 * │ that shows "found: RB5009, RouterOS 7.15" before anything is chosen.      │
 * │ `applyFactoryProvisioning()` takes the proof again on its own session —   │
 * │ the box at an address can change between two clicks.                     │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ STEP 2 IS THE ONE THAT MATTERS ─────────────────────────────────────────┐
 * │ The change queue exists so nothing reaches a customer router outside a    │
 * │ queue with a backup and a dead-man. This module sits outside it by        │
 * │ design — a bench box has no tunnel, no inventory row, nothing to queue —  │
 * │ and what it does is WORSE than any queued push: it erases the whole       │
 * │ configuration. Aimed at a live router (the bench is not isolated from the │
 * │ office LAN, MNDP heard the wrong box, the preparer typed the address of   │
 * │ the box beside it), that is a site down with nothing left to roll back.  │
 * │                                                                          │
 * │ So the identity check is taken AFTER login, on the router's own           │
 * │ interface table — not on the MNDP announcement, which anything on the    │
 * │ LAN can forge and which on a factory box is not even the sticker MAC     │
 * │ (mndp.ts), and not on the address, which is merely where something       │
 * │ answered. `orig-mac-address` (the burned-in MAC) is read as well as       │
 * │ `mac-address`, so a factory box whose MACs were never touched and a box   │
 * │ whose interface MAC was overridden both prove themselves the same way.    │
 * │ Nothing is written to the router before the check passes.                 │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHY TWO FILES ──────────────────────────────────────────────────────────┐
 * │ RouterOS compiles a statement before it runs any of it. With the body     │
 * │ inline in the run-after-reset file, a body that does not parse — a       │
 * │ property renamed between two 7.x minors, `/interface wifi` on a build     │
 * │ that only has `wireless` — rejected the whole `:do`, the import stopped   │
 * │ there, and nothing after it ran: no mark, and not the line deleting a     │
 * │ file that holds the L2TP secret and the new admin password, on a box that │
 * │ no longer had an IP to reach it by.                                       │
 * │                                                                          │
 * │ Now the run-after-reset file is the RUNNER: fixed text built here from    │
 * │ the tag alone, which always parses. It imports the body inside its own    │
 * │ `:do {} on-error={}` — a body that does not parse is then a runtime       │
 * │ failure of `/import`, not a syntax error of the runner — and decides on   │
 * │ a global the body sets as its LAST statement, so "did not parse", "was    │
 * │ cut short on upload" and "stopped on an error" all read as not-done,      │
 * │ whether or not `/import` reports its failure to the caller. Then the      │
 * │ runner marks the outcome and deletes both files unconditionally.          │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHAT IS REASONED, NOT OBSERVED ─────────────────────────────────────────┐
 * │ No line of this module has run against a MikroTik. Built against a        │
 * │ connection double (`testing/routerosApply.verify.ts`). The first lab      │
 * │ run should check, in this order: what `/file/print` reports as `size`     │
 * │ over the API (bytes, or `15.1KiB`) and that `/file/add` stores            │
 * │ `contents` intact — the size check refuses outside the display            │
 * │ precision, before the reset, and a cut smaller than that precision is     │
 * │ caught on the box by the sentinel; that `/system/reset-configuration`     │
 * │ over the API runs with no prompt; that `/import` runs from inside a       │
 * │ run-after-reset script and that a `:global` the imported file sets is     │
 * │ visible to the runner afterwards; that a `:do {}` block carries an        │
 * │ export-style menu line (`/ip address` then `add ...`) to the lines after  │
 * │ it; and that the recovery block (bridge + 192.168.88.1/24) runs on a box  │
 * │ reset with no-defaults.                                                   │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE BENCH APPLICATION UPLOADS A SERVER-COMPILED FILE, AS IT IS ─────────┐
 * │ The two-file wrapper above was this module's own. The run-after-reset    │
 * │ file is now compiled by the ObliWAN SERVER (`POST /api/bench/v1/compile`: │
 * │ interface-wait prelude, customer template, ObliWAN access block, success  │
 * │ marker, tail) and the bench must not assemble anything around it. So     │
 * │ `applyFactoryProvisioning()` takes `compiled: { fileName, content,        │
 * │ sha256 }` and then uploads ONE file byte for byte, under the server's    │
 * │ own name, refuses before dialling unless the SHA-256 of the content is   │
 * │ the one announced, and points `run-after-reset` at it. Everything else is │
 * │ unchanged and shared with the legacy path: the MAC proof on the router's │
 * │ own interfaces before any write, `flash/` when the box has one, the      │
 * │ stale-file removal, `/file/add` then the SFTP fallback, the size check,  │
 * │ the clean-up of a refused upload, the reset.                             │
 * │ `buildRunAfterResetScript()` and the `script` request field remain,      │
 * │ exported and covered by `testing/routerosApply.verify.ts`, but the bench │
 * │ application no longer calls them.                                        │
 * │ A SPLIT compile (`compiledFiles`: a runner and the bodies it imports)   │
 * │ is uploaded the same way, bodies first and the runner last, each file   │
 * │ checked against its own SHA-256 and required to be removed from the box │
 * │ by a line of the set. Every `obliwan-*.rsc` an earlier attempt left is  │
 * │ removed first. After the size check, each file is READ BACK            │
 * │ (`contents`) and its SHA-256 compared when RouterOS shows it whole      │
 * │ (`upload.contentCheck`) — how much of a file RouterOS shows over the    │
 * │ API is not observed, so a shorter read-back leaves the size as the      │
 * │ check.                                                                  │
 * │                                                                          │
 * │ `identifyFactoryBox()` also reads, read-only, the Wi-Fi stack            │
 * │ (`/interface/wifi` or `/interface/wireless`) and `/system/device-mode`,   │
 * │ which the server's plan needs and which decides whether the compiled     │
 * │ file could run at all (see `deviceModeGate.ts`), then the system        │
 * │ identity, the local accounts and the installed packages (factory state, │
 * │ and what a RouterOS upgrade must replace).                              │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Secrets: the factory password and the body (which carries whatever the
 * template rendered — an L2TP secret, the new admin password) enter this
 * module and never leave it. Every router- or transport-provided sentence that
 * can reach an error goes through `scrub()` first, and no error carries its
 * cause: a `cause` is an object graph nobody reviews before it is printed.
 *
 * No database, no vault, no logger: this runs inside the bench SEA binary.
 */

import { createHash } from 'node:crypto';
import { isSecretAttribute } from '../services/transport/routeros/protocol';
import { isUnicastMac, normalizeMac } from './mndp';

// ============================================================================
// Names shared by the builder and the uploader
// ============================================================================

/** Stable prefix of every log line and note the runner writes on the box. */
export const PROVISION_LOG_PREFIX = 'obliwan-provision';

/**
 * A tag is embedded verbatim in file names, in RouterOS string literals and
 * in a `:parse` string nested inside one. Restricting it to characters none of
 * those contexts treats specially is the whole escaping strategy — so it is
 * REFUSED outside this set, never sanitised into it.
 */
export const PROVISION_TAG_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/**
 * Where a box whose body failed is put back, so the bench can read the mark
 * and try again: the address a factory box answered on before the reset.
 */
export const RECOVERY_ADDRESS = '192.168.88.1/24';
/** The bridge the recovery creates when the body did not leave one. */
export const RECOVERY_BRIDGE = 'obliwan-recovery';

const WRAPPER_VERSION = 'v2';

/**
 * The global the body sets as its last statement. Its value is the tag on
 * success and `!stopped` when the body's own on-error ran: `!` is outside the
 * tag alphabet, so no tag can ever read as a failure or the reverse, and the
 * runner's initial `""` is shorter than any tag.
 */
const SENTINEL = 'obliwanProvisionDone';
const SENTINEL_STOPPED = '!stopped';

export class ProvisioningScriptError extends Error {
  readonly code:
    | 'INVALID_TAG'
    | 'EMPTY_BODY'
    | 'CONTROL_CHARACTER'
    | 'RESERVED_NAME'
    | 'UNBALANCED'
    | 'UNTERMINATED_STRING';
  /** 1-based line of the rendered body, when the fault has one. */
  readonly line: number | null;
  constructor(code: ProvisioningScriptError['code'], message: string, line: number | null = null) {
    super(message);
    this.name = 'ProvisioningScriptError';
    this.code = code;
    this.line = line;
  }
}

function assertTag(tag: string): void {
  if (typeof tag !== 'string' || !PROVISION_TAG_PATTERN.test(tag)) {
    throw new ProvisioningScriptError(
      'INVALID_TAG',
      `Étiquette de provisionnement invalide (« ${String(tag).slice(0, 70)} ») : seuls lettres, chiffres, « . », « _ » et « - » sont admis, 64 caractères au plus. Rien n'a été envoyé au routeur ; relancez l'écriture de la configuration.`,
    );
  }
}

/**
 * The runner's on-box name: what `run-after-reset` points at. `flash/` is
 * prefixed at upload time when the box has one.
 */
export function provisioningFileName(tag: string): string {
  assertTag(tag);
  return `${PROVISION_LOG_PREFIX}-${tag}.rsc`;
}

/**
 * The body's on-box name. A different PREFIX, not a suffix: the tag may
 * contain `.`, so `<tag>.body.rsc` would let the body of tag `x` and the
 * runner of tag `x.body` share a name.
 */
export function provisioningBodyFileName(tag: string): string {
  assertTag(tag);
  return `obliwan-body-${tag}.rsc`;
}

/** The exact log lines the runner writes, for whoever checks the box afterwards. */
export function provisioningMarkers(tag: string): {
  start: string;
  ok: string;
  failed: string;
  /** Logged after `failed`: the body ran and its own on-error fired. */
  bodyStopped: string;
  /** Logged after `failed`: the body did not reach its end — did not parse, missing, or cut short. */
  bodyNotRun: string;
  /** Comment on the recovery address and bridge, and the log line that announces them. */
  recovery: string;
  recoveryFailed: string;
} {
  assertTag(tag);
  return {
    start: `${PROVISION_LOG_PREFIX} start tag=${tag}`,
    ok: `${PROVISION_LOG_PREFIX} ok tag=${tag}`,
    failed: `${PROVISION_LOG_PREFIX} FAILED tag=${tag}`,
    bodyStopped: `${PROVISION_LOG_PREFIX} detail tag=${tag} reason=body-stopped-on-error`,
    bodyNotRun: `${PROVISION_LOG_PREFIX} detail tag=${tag} reason=body-did-not-run-to-its-end`,
    recovery: `${PROVISION_LOG_PREFIX} recovery tag=${tag}`,
    recoveryFailed: `${PROVISION_LOG_PREFIX} recovery-failed tag=${tag}`,
  };
}

function runnerHeader(tag: string, wait: number, settle: number): string {
  return `# ${PROVISION_LOG_PREFIX} ${WRAPPER_VERSION} tag=${tag} wait=${wait} settle=${settle}`;
}
const RUNNER_HEADER = /^# obliwan-provision v2 tag=(\S+) wait=(\d+) settle=(\d+)$/;

function runnerFooter(tag: string): string {
  return `# ${PROVISION_LOG_PREFIX} end tag=${tag}`;
}

function bodyHeader(tag: string): string {
  return `# ${PROVISION_LOG_PREFIX} ${WRAPPER_VERSION} body tag=${tag}`;
}

function bodyFooter(tag: string): string {
  return `# ${PROVISION_LOG_PREFIX} body end tag=${tag}`;
}

// ============================================================================
// Structure of a RouterOS script
// ============================================================================

const CLOSER: Record<string, string> = { '{': '}', '[': ']', '(': ')' };

/**
 * Brackets balanced outside strings and comment lines, strings terminated,
 * and no line continuation with no line after it.
 *
 * Not a RouterOS parser and not trying to be one. The body is wrapped in a
 * `:do { }` and followed by the sentinel: a stray `}` would close that `:do`
 * early and run the rest outside its error handler, and a trailing `\` would
 * glue the sentinel onto the body's last command. Neither can mark a box
 * `ok` falsely any more (the sentinel would not be set), but both would fail
 * every box built from that template, so they are refused here instead.
 *
 * Rules, as RouterOS scripts use them: `"` opens a string and `\` escapes the
 * next character inside it; outside a string `\` escapes the next character
 * too (a trailing `\` is a line continuation, as `/export` writes them); `#`
 * starts a comment only as the first non-blank character of a line.
 */
export function checkScriptStructure(
  src: string,
): { ok: true } | { ok: false; code: 'UNBALANCED' | 'UNTERMINATED_STRING'; line: number; detail: string } {
  const stack: { ch: string; line: number }[] = [];
  let inString = false;
  let stringLine = 0;
  let line = 1;
  let atLineStart = true;

  for (let i = 0; i < src.length; i++) {
    const c = src[i];

    if (inString) {
      if (c === '\\') {
        if (src[i + 1] === '\n') line++;
        i++;
      } else if (c === '"') {
        inString = false;
      } else if (c === '\n') {
        line++;
      }
      continue;
    }

    if (c === '\n') {
      line++;
      atLineStart = true;
      continue;
    }
    if (atLineStart && (c === ' ' || c === '\t' || c === '\r')) continue;
    if (atLineStart && c === '#') {
      while (i + 1 < src.length && src[i + 1] !== '\n') i++;
      continue;
    }
    atLineStart = false;

    if (c === '\\') {
      if (i + 1 >= src.length) {
        return { ok: false, code: 'UNBALANCED', line, detail: '« \\ » de continuation sans ligne suivante' };
      }
      if (src[i + 1] === '\n') line++;
      i++;
      continue;
    }
    if (c === '"') {
      inString = true;
      stringLine = line;
      continue;
    }
    if (c === '{' || c === '[' || c === '(') {
      stack.push({ ch: c, line });
      continue;
    }
    if (c === '}' || c === ']' || c === ')') {
      const top = stack.pop();
      if (!top) {
        return { ok: false, code: 'UNBALANCED', line, detail: `« ${c} » fermant sans ouvrant` };
      }
      if (CLOSER[top.ch] !== c) {
        return {
          ok: false,
          code: 'UNBALANCED',
          line,
          detail: `« ${c} » ferme un « ${top.ch} » ouvert ligne ${top.line}`,
        };
      }
    }
  }

  if (inString) {
    return { ok: false, code: 'UNTERMINATED_STRING', line: stringLine, detail: 'chaîne entre guillemets jamais refermée' };
  }
  if (stack.length > 0) {
    const top = stack[stack.length - 1];
    return { ok: false, code: 'UNBALANCED', line: top.line, detail: `« ${top.ch} » jamais refermé` };
  }
  return { ok: true };
}

// ============================================================================
// The two files
// ============================================================================

export interface RunAfterResetOptions {
  /**
   * Upper bound, in seconds, of the wait for the ethernet interfaces to exist
   * (polled once a second). Default 60.
   */
  interfaceWaitSeconds?: number;
  /** Fixed `:delay` after that wait, before the body. Default 15. */
  settleSeconds?: number;
}

function boundedSeconds(v: number | undefined, fallback: number, max: number): number {
  if (v === undefined) return fallback;
  if (!Number.isInteger(v) || v < 0 || v > max) {
    throw new RangeError(`delay out of range: expected an integer in [0, ${max}], got ${String(v)}`);
  }
  return v;
}

/** The rendered configuration, normalised and judged. Throws `ProvisioningScriptError`. */
function acceptBody(rendered: string): string {
  if (typeof rendered !== 'string' || rendered.trim() === '') {
    throw new ProvisioningScriptError(
      'EMPTY_BODY',
      "La configuration à écrire est vide : il n'y a rien à appliquer après la réinitialisation. Rien n'a été envoyé au routeur ; relancez le rendu de la configuration.",
    );
  }
  const body = rendered.replace(/\r\n?/g, '\n').replace(/\n+$/, '');

  // A NUL or a stray control byte has no business in a RouterOS script and is
  // the classic signature of a binary or mis-decoded payload. Tab and newline
  // are the only ones a script legitimately carries.
  const ctl = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.exec(body);
  if (ctl) {
    const line = body.slice(0, ctl.index).split('\n').length;
    throw new ProvisioningScriptError(
      'CONTROL_CHARACTER',
      `La configuration reçue contient un caractère de contrôle ligne ${line} : elle n'a pas été envoyée au routeur. Relancez le rendu de la configuration ; si l'erreur revient, signalez-la à l'administrateur du modèle.`,
      line,
    );
  }

  // The header and footer lines are how the uploader tells the two files
  // apart, and the sentinel is how the runner tells success from failure. A
  // body that wrote either could split the package wrongly or mark itself ok
  // before its last line — so both are reserved, and refused by name.
  const lines = body.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    if (t.startsWith(`# ${PROVISION_LOG_PREFIX}`) || lines[i].includes(SENTINEL)) {
      throw new ProvisioningScriptError(
        'RESERVED_NAME',
        `La configuration reçue utilise ligne ${i + 1} un nom réservé à ObliWAN (« # ${PROVISION_LOG_PREFIX} » ou « ${SENTINEL} ») : elle n'a pas été envoyée au routeur. Signalez-le à l'administrateur du modèle.`,
        i + 1,
      );
    }
  }

  const structure = checkScriptStructure(body);
  if (!structure.ok) {
    throw new ProvisioningScriptError(
      structure.code,
      `La configuration reçue est mal formée ligne ${structure.line} (${structure.detail}) : elle sortirait du garde-fou d'erreur et n'a pas été envoyée au routeur. Signalez-le à l'administrateur du modèle.`,
      structure.line,
    );
  }
  return body;
}

/**
 * The body file: the rendered configuration inside `:do { } on-error={ }`,
 * with the sentinel as the last statement of the `:do`. The sentinel is set
 * only when every line before it ran — so a body cut short on upload, one that
 * does not parse, and one that stops on an error all leave it unset.
 */
function bodyFile(body: string, tag: string): string {
  return `${[
    bodyHeader(tag),
    ':do {',
    body,
    `:global ${SENTINEL} "${tag}"`,
    '} on-error={',
    `:global ${SENTINEL} "${SENTINEL_STOPPED}"`,
    '}',
    bodyFooter(tag),
  ].join('\n')}\n`;
}

/**
 * The recovery, run only on failure. The box was reset with no-defaults, so
 * unless the lines that ran before the failure added a reachable address it
 * has none: MNDP hears it with no IPv4, the bench cannot read the FAILED mark,
 * and nothing short of Winbox-by-MAC or Netinstall can retry it.
 *
 * The address goes on the first bridge when the body made one, since a port
 * that is a bridge member cannot carry it. Otherwise a bridge is made of every
 * ethernet port except ether1, because the bench cable is in one of them and
 * which one is not known here (by `default-name`, so a body that renamed
 * ether1 before failing does not bridge the WAN port with the LAN ports). It
 * is in its own `:do`, so a recovery that fails is logged and the runner still
 * reaches the lines that delete the files.
 *
 * What it cannot undo: a body that changed the admin password before failing
 * leaves a box the factory credential no longer opens.
 */
function recoveryLines(tag: string): string[] {
  const marks = provisioningMarkers(tag);
  return [
    ':do {',
    ':local obliwanIf ""',
    ':foreach b in=[/interface bridge find] do={ :if ($obliwanIf = "") do={ :set obliwanIf [/interface bridge get $b name] } }',
    ':if ($obliwanIf = "") do={',
    `/interface bridge add name=${RECOVERY_BRIDGE} comment="${marks.recovery}"`,
    `:foreach e in=[/interface ethernet find where default-name!="ether1"] do={ :do { /interface bridge port add bridge=${RECOVERY_BRIDGE} interface=[/interface ethernet get $e name] } on-error={} }`,
    `:set obliwanIf "${RECOVERY_BRIDGE}"`,
    '}',
    `:if ([:len [/ip address find where address="${RECOVERY_ADDRESS}"]] = 0) do={ /ip address add address=${RECOVERY_ADDRESS} interface=$obliwanIf comment="${marks.recovery}" }`,
    `:log warning "${marks.recovery} address=${RECOVERY_ADDRESS}"`,
    `} on-error={ :log error "${marks.recoveryFailed}" }`,
  ];
}

/**
 * The runner: the file `run-after-reset` executes. Built from the tag and the
 * two delays ALONE — no template text reaches it — so it parses on every box
 * that parses anything, and its last lines always run. Every statement that
 * could fail at run time is inside its own `:do`, because an import stops at
 * the first error and the deletion lines must not be behind one.
 *
 * - A WAIT first. `run-after-reset` starts the script early in boot, before
 *   the ports are ready, and a body that configures `ether1` before `ether1`
 *   exists fails on its first line. The wait polls for the ethernet
 *   interfaces (bounded), then sleeps a fixed settle delay — the poll alone is
 *   not enough, since the first interface appearing says nothing about the
 *   last.
 * - The body through `/import`, inside `:do { } on-error={ }`. A project rule
 *   forbids applying with a plain `/import` because it stops at the first
 *   error and leaves the router half configured with nothing saying so; here
 *   the import is guarded, the body's own `:do` catches its run-time errors,
 *   and the outcome is decided on the sentinel, never on whether `/import`
 *   reported anything.
 * - The body file is deleted as soon as the import returns: it holds the
 *   rendered secrets, on a box that is about to leave the building.
 * - Marks, both ways, with a stable `obliwan-provision` prefix and the tag:
 *   `:log` always, and `/system note` where it exists. The note goes through
 *   `[:parse]` at RUN time because RouterOS compiles a statement before it
 *   runs any of it: on a build without `/system note`, a literal one would
 *   fail the whole decision block as a syntax error.
 * - On failure, the recovery address (see `recoveryLines`).
 * - The runner deletes itself last. It holds no secret; a leftover one is
 *   clutter, not exposure.
 *
 * What the runner CANNOT mark: a box that loses power mid-run, a body that
 * never returns, and a runner that was itself cut short on upload — which is
 * why the uploader refuses a size it cannot reconcile, before the reset. The
 * absence of the `ok` mark is therefore the failure signal, never the absence
 * of the `FAILED` one.
 */
function runnerFile(tag: string, waitSeconds: number, settleSeconds: number): string {
  const marks = provisioningMarkers(tag);
  const runner = provisioningFileName(tag);
  const body = provisioningBodyFileName(tag);
  const note = (text: string, atLogin: boolean) =>
    `:do { :local obliwanNote [:parse "/system note set show-at-login=${atLogin ? 'yes' : 'no'} note=\\"${text}\\""]; $obliwanNote } on-error={}`;
  const remove = (name: string) =>
    `:do { /file remove [find where name="${name}" or name="flash/${name}"] } on-error={}`;

  const lines: string[] = [
    runnerHeader(tag, waitSeconds, settleSeconds),
    `# Run once by /system reset-configuration run-after-reset: imports ${body}, marks the outcome, deletes both files.`,
    `:log info "${marks.start}"`,
    `:global ${SENTINEL} ""`,
  ];
  if (waitSeconds > 0) {
    lines.push(
      ':do {',
      ':local obliwanWait 0',
      `:while (([:len [/interface ethernet find]] = 0) && ($obliwanWait < ${waitSeconds})) do={ :delay 1s; :set obliwanWait ($obliwanWait + 1) }`,
      '} on-error={}',
    );
  }
  if (settleSeconds > 0) lines.push(`:delay ${settleSeconds}s`);
  lines.push(
    ':do {',
    `:local obliwanBody "${body}"`,
    ':if ([:len [/file find where name=("flash/" . $obliwanBody)]] > 0) do={ :set obliwanBody ("flash/" . $obliwanBody) }',
    '/import file-name=$obliwanBody',
    '} on-error={}',
    remove(body),
    ':do {',
    `:global ${SENTINEL}`,
    `:if ($${SENTINEL} = "${tag}") do={`,
    `:log info "${marks.ok}"`,
    note(marks.ok, false),
    '} else={',
    `:log error "${marks.failed}"`,
    `:if ($${SENTINEL} = "${SENTINEL_STOPPED}") do={ :log error "${marks.bodyStopped}" } else={ :log error "${marks.bodyNotRun}" }`,
    note(marks.failed, true),
    ...recoveryLines(tag),
    '}',
    '} on-error={}',
    remove(runner),
    runnerFooter(tag),
  );
  return `${lines.join('\n')}\n`;
}

/** The two files of a provisioning, as the uploader puts them on the box. */
export interface ProvisioningFiles {
  /** What `run-after-reset` executes. Fixed text; no secret. */
  runner: string;
  /** The rendered configuration, wrapped. Holds the secrets. */
  body: string;
}

/** The two files for a rendered configuration. Throws `ProvisioningScriptError`. */
export function buildProvisioningFiles(
  rendered: string,
  tag: string,
  options: RunAfterResetOptions = {},
): ProvisioningFiles {
  assertTag(tag);
  const body = acceptBody(rendered);
  const waitSeconds = boundedSeconds(options.interfaceWaitSeconds, 60, 600);
  const settleSeconds = boundedSeconds(options.settleSeconds, 15, 600);
  return { runner: runnerFile(tag, waitSeconds, settleSeconds), body: bodyFile(body, tag) };
}

/**
 * Wrap a rendered RouterOS configuration for `run-after-reset`.
 *
 * Returns the PROVISIONING PACKAGE: the runner followed by the body file, as
 * one string, which is what `applyFactoryProvisioning({ script })` takes and
 * splits back into two files. One string, so a caller cannot upload one file
 * without the other, and so this signature did not change when the body moved
 * to a file of its own (see "WHY TWO FILES" in the header).
 */
export function buildRunAfterResetScript(
  rendered: string,
  tag: string,
  options: RunAfterResetOptions = {},
): string {
  const files = buildProvisioningFiles(rendered, tag, options);
  return files.runner + files.body;
}

/**
 * The two files of a package built by `buildRunAfterResetScript()` for THIS
 * tag, or `null`. Exact, not approximate: the rendered body and the delays are
 * read back out of the package, rebuilt, and the result must be byte-identical
 * — so nothing that did not come out of the builder (a raw configuration,
 * which `run-after-reset` would run as a plain `/import`; a package with a
 * line appended; another tag's) passes.
 */
export function splitProvisioningPackage(script: string, tag: string): ProvisioningFiles | null {
  if (typeof script !== 'string' || typeof tag !== 'string' || !PROVISION_TAG_PATTERN.test(tag)) return null;
  const text = script.replace(/\r\n?/g, '\n');
  const lines = text.split('\n');
  const head = RUNNER_HEADER.exec(lines[0] ?? '');
  if (!head || head[1] !== tag) return null;
  const at = lines.indexOf(bodyHeader(tag));
  // header, :do {, at least one body line, sentinel, on-error, set, }, footer, ''
  if (at < 1 || lines.length - at < 9) return null;
  const rendered = lines.slice(at + 2, lines.length - 6).join('\n');
  let rebuilt: ProvisioningFiles;
  try {
    rebuilt = buildProvisioningFiles(rendered, tag, {
      interfaceWaitSeconds: Number(head[2]),
      settleSeconds: Number(head[3]),
    });
  } catch {
    return null;
  }
  return rebuilt.runner + rebuilt.body === text ? rebuilt : null;
}

/**
 * True when `script` is a `buildRunAfterResetScript()` output for THIS tag.
 * The uploader refuses anything else.
 */
export function isWrappedProvisioningScript(script: string, tag: string): boolean {
  return splitProvisioningPackage(script, tag) !== null;
}

// ============================================================================
// What the router says a file weighs
// ============================================================================

const SIZE_UNITS: Record<string, number> = { b: 1, kib: 1024, mib: 1024 ** 2, gib: 1024 ** 3 };

/**
 * Compare the `size` `/file/print` reports with the bytes that were sent.
 *
 * - `match`: a plain byte count (or `<n>B`) equal to what was sent.
 * - `rounded`: a unit size (`15.1KiB`) within ONE display step of what was
 *   sent, on either side — the union of what rounding to nearest and
 *   truncation can produce, since which one RouterOS does is not observed.
 *   Not a proof of integrity: a cut smaller than a step passes, and is caught
 *   on the box instead (the body's sentinel is its last statement).
 * - `short` / `long`: off by more than that. `short` may be a write still in
 *   progress; the caller polls before believing it.
 * - `unreadable`: neither shape. NOT a pass: a size nobody can read proves
 *   nothing, and the reset that follows erases the box.
 */
export function judgeReportedSize(
  raw: string | null | undefined,
  sent: number,
): 'match' | 'rounded' | 'short' | 'long' | 'unreadable' {
  const s = (raw ?? '').trim();
  const exact = (n: number) => (n === sent ? 'match' : n < sent ? 'short' : 'long');
  if (/^\d+$/.test(s)) return exact(Number(s));
  const m = /^(\d+)(?:\.(\d+))?\s*(B|KiB|MiB|GiB)$/i.exec(s);
  if (!m) return 'unreadable';
  const mult = SIZE_UNITS[m[3].toLowerCase()];
  const decimals = m[2]?.length ?? 0;
  if (mult === 1 && decimals === 0) return exact(Number(m[1]));
  const shown = Number(`${m[1]}.${m[2] ?? '0'}`) * mult;
  const step = mult / 10 ** decimals;
  if (Math.abs(sent - shown) <= step) return 'rounded';
  return shown < sent ? 'short' : 'long';
}

// ============================================================================
// Collaborators (injected by the harness, real by default)
// ============================================================================

/** The slice of `RouterOsConnection` this module uses. */
export interface RouterOsApiSession {
  query(words: string[], options?: { timeoutMs?: number }): Promise<Record<string, string>[]>;
  close(): void;
}

export interface DialRequest {
  host: string;
  port: number;
  username: string;
  password: string;
  connectTimeoutMs: number;
  requestTimeoutMs: number;
  label: string;
  /**
   * This PC's address on the bench link the box sits on (`slots.ts`), the
   * connection's SOURCE. Present only when the bench knows the link: every
   * factory box answers 192.168.88.1, and on a PC with several bench links
   * the destination alone does not say which box a dial reaches.
   */
  localAddress?: string;
}

export type DialFn = (req: DialRequest) => Promise<RouterOsApiSession>;

export interface SftpUploadRequest {
  host: string;
  port: number;
  username: string;
  password: string;
  /**
   * RouterOS file path (`flash/...` on boxes that have one). The upload must
   * REPLACE any file already there: a truncated `/file/add` result may be.
   */
  remotePath: string;
  content: Buffer;
  timeoutMs: number;
  /** The source address of the SSH connection: the same bench link as the
   *  API session's (`DialRequest.localAddress`). Absent: the OS chooses. */
  localAddress?: string;
}

export type SftpUploadFn = (req: SftpUploadRequest) => Promise<void>;

export interface FactoryProvisioningDeps {
  dial?: DialFn;
  /**
   * Absent by default HERE (no SFTP fallback). The bench application passes
   * `sftpUploadOverSsh` (`sftp.ts`, over ssh2, also the RouterOS upgrade's
   * uploader): when `/file/add` is refused, or keeps a file shorter than or
   * different from what was sent, the files are put again over SFTP —
   * opened with truncation, so a cut copy is replaced, never appended to —
   * and checked again on this session before the reset. It is also how a
   * RouterOS 6 box (no `/file/add`) gets its files.
   */
  sftpUpload?: SftpUploadFn | null;
  sleep?: (ms: number) => Promise<void>;
  /** The clock the SIM wait is bounded by. Default `Date.now`. */
  now?: () => number;
}

/**
 * The real dial. Cleartext 8728, on purpose: a factory image has no
 * certificate provisioned that could be pinned, and the only credential on
 * the wire is the factory one, on the bench's own LAN. The connection module
 * is loaded lazily so that importing this file (the harness, the builder
 * alone) does not drag the transport and its logger in.
 */
const defaultDial: DialFn = async (req) => {
  const { createRouterOsConnection } = await import('../services/transport/routeros/connection');
  return createRouterOsConnection({
    host: req.host,
    port: req.port,
    tls: false,
    username: req.username,
    password: req.password,
    connectTimeoutMs: req.connectTimeoutMs,
    loginTimeoutMs: req.connectTimeoutMs,
    requestTimeoutMs: req.requestTimeoutMs,
    allowLegacyLogin: true,
    label: req.label,
    // Bound to the bench link's own address: see `slots.ts` for why the
    // source, and not the destination, picks the box.
    ...(req.localAddress ? { sourceAddress: req.localAddress } : {}),
  });
};

const defaultSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

// ============================================================================
// Request, result, refusal
// ============================================================================

export type ProvisioningStep = 'connecting' | 'checking-mac' | 'reading-router' | 'reading-sim' | 'uploading' | 'resetting';

export const PROVISIONING_STEP_LABELS: Record<ProvisioningStep, string> = {
  connecting: 'Connexion au routeur…',
  'checking-mac': "Vérification de l'adresse MAC du boîtier…",
  'reading-router': 'Lecture du modèle et de la version…',
  'reading-sim': 'Lecture de la carte SIM du modem…',
  uploading: 'Dépôt du script de configuration sur le routeur…',
  resetting: 'Réinitialisation : le routeur redémarre et applique la configuration…',
};

export interface FactoryIdentifyRequest {
  /** IPv4 literal on the bench LAN (typically `reachableAddress()` of an MNDP candidate). */
  host: string;
  /** RouterOS API port. Default 8728. */
  port?: number;
  username: string;
  /** Factory password. May be empty: older factory images ship without one. */
  password: string;
  /** The MAC on the sticker, in any notation `normalizeMac()` accepts. */
  expectedMac: string;
  /**
   * This PC's address on the bench link where MNDP heard the box (`slots.ts`):
   * every connection to the box — API and SFTP — leaves FROM it. `null` or
   * absent: the OS picks the route, as on a PC with no declared bench link.
   */
  localAddress?: string | null;
  timeouts?: { connectMs?: number; requestMs?: number };
  onProgress?: (step: ProvisioningStep) => void;
}

/**
 * A run-after-reset file compiled by the ObliWAN server. Uploaded byte for
 * byte: nothing is added, removed or re-wrapped here.
 */
export interface CompiledProvisioningFile {
  /** A bare RouterOS file name ending in `.rsc` (`COMPILED_FILE_NAME_PATTERN`);
   *  `flash/` is prepended here when the box has one. */
  fileName: string;
  content: string;
  /** Hex SHA-256 of `content` (UTF-8) as the server announced it. */
  sha256: string;
  /**
   * In a split compile (`files[]`), `runner` is the file run-after-reset
   * executes and `body` a file it imports. A lone file is the runner.
   */
  role?: 'runner' | 'body';
}

/** Files a previous attempt may have left: every bench and compiled script
 *  carries this prefix, and a leftover one holds that attempt's secrets. */
export const STALE_PROVISIONING_FILE = /^(?:flash\/)?obliwan-[A-Za-z0-9._-]*\.rsc$/;

/** No directory, no space, no quote: the name is spliced into
 *  `run-after-reset=` and into `/file/add name=`. */
export const COMPILED_FILE_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,95}\.rsc$/;

/**
 * Does a compiled file delete ITSELF from the box? It carries the L2TP secret
 * and the ObliWAN account's password in plaintext, and a file left in
 * flash/ is readable through /file, FTP or SFTP by any account holding the
 * ftp or read policy — the exposure the no-secrets rule forbids for an export. Whether
 * RouterOS removes a run-after-reset file by itself is NOT observed, so the
 * bench does not rely on it: the server's text must carry a `/file remove`
 * (either spelling) on a non-comment line that names this file, and a file
 * that does not is refused before any dial. Textual on purpose: it proves the
 * statement is in the file, not that RouterOS ran it.
 */
export function compiledRemovesItself(content: string, fileName: string): boolean {
  return content.split(/\r?\n/).some((raw) => {
    const line = raw.trim();
    return !line.startsWith('#') && /\/file[ /]remove\b/.test(line) && line.includes(fileName);
  });
}

/** Lower-case hex SHA-256 of a text, as UTF-8 — the digest the server announces. */
export function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

export interface FactoryProvisioningRequest extends FactoryIdentifyRequest {
  /**
   * Legacy: the PACKAGE `buildRunAfterResetScript(rendered, tag)` returned,
   * nothing else. Ignored when `compiled` is set.
   */
  script?: string;
  /** The server-compiled file. When present it is the ONLY thing uploaded. */
  compiled?: CompiledProvisioningFile;
  /**
   * A SPLIT compile (`files[]` of `POST /api/bench/v1/compile`): every file,
   * in the server's order. The bodies are uploaded first, in that order, and
   * the runner LAST — it is what run-after-reset executes, and a runner on the
   * box with a body missing beside it would reset into nothing. Takes
   * precedence over `compiled`.
   */
  compiledFiles?: CompiledProvisioningFile[];
  /** Labels the session; with `script`, also names the two wrapper files. */
  tag: string;
  /** SSH port for the SFTP fallback. Default 22. */
  sshPort?: number;
  timeouts?: { connectMs?: number; requestMs?: number; resetMs?: number };
  /** The SIM wait (`readSimCard`): its budget and the pause between two
   *  reads. Defaults `SIM_WAIT_BUDGET_MS` and `SIM_RETRY_MS`. */
  simWait?: { budgetMs?: number; retryMs?: number };
  /** After every SIM read that found no card yet, before the pause: what the
   *  wait is for and how long it may still take, so that it never just
   *  counts in silence (the bench draws it like its other waits). */
  onSimWait?: (tick: SimWaitTick) => void;
}

export interface RouterFacts {
  version: string | null;
  /** `null` when the version string did not parse — never guessed as 7. */
  majorVersion: number | null;
  board: string | null;
  architecture: string | null;
  model: string | null;
  serial: string | null;
}

/** What `identifyFactoryBox()` proved. Nothing was written to get it. */
export interface FactoryIdentification {
  matchedMac: string;
  interfaceMacs: string[];
  router: RouterFacts;
}

/** Which Wi-Fi menu the box has: `wifi` (the 7.13+ stack) or legacy `wireless`. */
export type WifiStack = 'wifi' | 'wireless';

/**
 * `/system/device-mode/print`, as printed. Nothing is inferred here — the one
 * inference the bench makes (`home` denies what MikroTik documents it to deny)
 * lives in `deviceModeGate.ts`.
 */
export interface DeviceModeReadout {
  /** False when the menu did not answer (RouterOS before 7.13, or refused). */
  answered: boolean;
  /** Lower-cased, verbatim; `null` when not printed. */
  mode: string | null;
  /** Every flag printed as yes/no (or true/false), by its RouterOS name. */
  flags: Record<string, boolean>;
  /** When the question was PUT (ISO-8601), stamped before the query — so
   *  "asked and got nothing" keeps its time, as in shared/src/deviceMode.ts. */
  observedAt: string;
}

/** One row of `/system/package/print`. */
export interface InstalledPackage {
  name: string;
  version: string | null;
  disabled: boolean;
}

/** `identifyFactoryBox()`'s answer: the MAC proof plus read-only facts. */
export interface FactoryBoxIdentification extends FactoryIdentification {
  /** `null` when neither menu exists — the box has no Wi-Fi package. */
  wifiStack: WifiStack | null;
  deviceMode: DeviceModeReadout;
  /** `/system/identity` name; `MikroTik` on a box out of the factory. `null`
   *  when the read was refused. */
  systemIdentity: string | null;
  /** Local account names (`/user/print`); `null` when the read was refused. */
  userNames: string[] | null;
  /** Installed packages; `null` when the read was refused. */
  packages: InstalledPackage[] | null;
  /** `/ip/address` entries (one more sign of an earlier configuration);
   *  `null` when the read was refused. */
  addresses: BoxAddress[] | null;
}

/** One row of `/ip/address/print`. */
export interface BoxAddress {
  /** `192.168.88.1/24`, as printed. */
  address: string;
  interface: string | null;
  comment: string | null;
  /** Put there by RouterOS itself (DHCP client, PPP), not by a configuration line. */
  dynamic: boolean;
}

/**
 * What the router said to the reset command. NONE of these proves the reset
 * happened or that the configuration was applied: `acknowledged` is a
 * `!done`, the other two are what a reboot looks like from here and also what
 * a pulled cable looks like. The proof is the box coming back (MNDP) carrying
 * the `ok` mark.
 */
export type ResetOutcome = 'acknowledged' | 'session-dropped' | 'no-answer';

export interface FactoryProvisioningResult extends FactoryIdentification {
  upload: {
    method: 'file-add' | 'sftp';
    /** What run-after-reset executes: the runner, or the compiled file. */
    path: string;
    /** The (first) body the runner imports: the legacy wrapper's, or a split
     *  compile's. `null` for a single compiled file — there is one. */
    bodyPath: string | null;
    /** Every path written, in upload order (the runner last). */
    paths: string[];
    /** Bytes sent, every file together. */
    bytes: number;
    /**
     * `match`: every size the router reported equals the bytes sent.
     * `rounded`: at least one was a unit size within its display precision
     * (see `judgeReportedSize`). Anything else was refused before the reset.
     */
    sizeCheck: 'match' | 'rounded';
    /**
     * `sha256`: every file was read back off the box (`contents`) at its full
     * length and its SHA-256 is the one sent. `size-only`: at least one could
     * not be read back whole (RouterOS shows a file's contents only up to a
     * size this module does not know), so its size is all that was checked.
     * A read-back that DIFFERS was refused before the reset.
     */
    contentCheck: 'sha256' | 'size-only';
    /** Why `/file/add` was not used, when it was not. Scrubbed. */
    fileAddRefusal: string | null;
    /** A file from an earlier attempt was removed first. */
    staleFileRemoved: boolean;
    /** Which ones: the same names, and any `obliwan-*.rsc` left behind. */
    staleFiles: string[];
  };
  reset: { outcome: ResetOutcome; runAfterReset: string };
  /** The marks the legacy runner writes. `null` for a compiled file: its
   *  success marker is the server's, and this module does not know it. */
  markers: ReturnType<typeof provisioningMarkers> | null;
  /** The SIM card read in `lte1` before the upload; null: no SIM found
   *  (no modem, no card, or a read that did not answer — `readSimCard`). */
  sim: SimCardReading | null;
  /** How that read ended and how long it waited for the modem: what the
   *  bench says when `sim` is null, so that "no card" can be told apart
   *  from "no modem". */
  simRead: Omit<SimReadReport, 'sim'>;
}

export type ProvisioningRefusalCode =
  | 'INVALID_INPUT'
  | 'CONNECT_FAILED'
  | 'AUTH_FAILED'
  | 'MAC_UNVERIFIABLE'
  | 'MAC_MISMATCH'
  | 'SESSION_LOST'
  | 'UPLOAD_REFUSED'
  | 'SFTP_UNAVAILABLE'
  | 'RESET_REFUSED'
  | 'DEVICE_MODE_REFUSED';

export type ProvisioningStage = 'validate' | 'connect' | 'identify' | 'upload' | 'reset' | 'device-mode';

/**
 * Every refusal. Thrown only BEFORE the router accepted a reset — including
 * `RESET_REFUSED`, which is a `!trap` on the reset itself — so catching one
 * always means the box still holds the configuration it had. The message is
 * French, names the operation to retry, and never contains the password or
 * the script.
 */
export class FactoryProvisioningError extends Error {
  readonly code: ProvisioningRefusalCode;
  readonly stage: ProvisioningStage;
  readonly routerReset = false as const;
  /** The router's own words, scrubbed. */
  readonly routerMessage: string | null;
  readonly facts: { interfaceMacs?: string[]; router?: RouterFacts };
  constructor(
    code: ProvisioningRefusalCode,
    stage: ProvisioningStage,
    message: string,
    extra: { routerMessage?: string | null; facts?: FactoryProvisioningError['facts'] } = {},
  ) {
    super(message);
    this.name = 'FactoryProvisioningError';
    this.code = code;
    this.stage = stage;
    this.routerMessage = extra.routerMessage ?? null;
    this.facts = extra.facts ?? {};
  }
}

// ============================================================================
// Helpers
// ============================================================================

const MASK = '«masqué»';
const MAX_ROUTER_TEXT = 240;

type Scrub = (text: unknown) => string;

/**
 * Replace every occurrence of the password, of the script, of any script line
 * long enough to be distinctive, and of the VALUE of every secret-named
 * attribute in the script (`password=`, `secret=`, `psk=`... — the one
 * definition in `protocol.ts`), BEFORE truncating: truncating first could cut
 * a secret in half and leave the half that is not masked. The attribute pass
 * exists because a router that echoes a bad value echoes the value alone, not
 * the line it came from.
 */
function makeScrubber(password: string, script: string): Scrub {
  const needles = new Set<string>();
  if (password) needles.add(password);
  if (script) {
    needles.add(script);
    for (const l of script.split(/\r?\n/)) {
      const t = l.trim();
      if (t.length >= 8) needles.add(t);
    }
    const pair = /([A-Za-z0-9-]+)=("(?:[^"\\]|\\.)*"|[^\s"{}\[\];]+)/g;
    for (let m = pair.exec(script); m !== null; m = pair.exec(script)) {
      if (!isSecretAttribute(m[1])) continue;
      const raw = m[2];
      const value = raw.startsWith('"') ? raw.slice(1, -1).replace(/\\(.)/g, '$1') : raw;
      if (value.length >= 4) {
        needles.add(value);
        needles.add(raw);
      }
    }
  }
  const ordered = Array.from(needles).sort((a, b) => b.length - a.length);
  return (text: unknown) => {
    let out = typeof text === 'string' ? text : text instanceof Error ? text.message : String(text);
    for (const n of ordered) if (out.includes(n)) out = out.split(n).join(MASK);
    return out.length > MAX_ROUTER_TEXT ? `${out.slice(0, MAX_ROUTER_TEXT)}…` : out;
  };
}

export type ErrKind = 'trap' | 'timeout' | 'closed' | 'fatal' | 'auth' | 'other';

/** Duck-typed on the `kind` the transport's error classes carry, so the real
 *  connection and the harness double are classified by the same rule. */
function errKind(err: unknown): ErrKind {
  const k = (err as { kind?: unknown } | null)?.kind;
  if (k === 'trap' || k === 'timeout' || k === 'closed' || k === 'fatal' || k === 'auth') return k;
  return 'other';
}

/** `errKind`, for the other bench modules that drive a proven session. */
export const routerErrorKind = errKind;

/** The scrubber `identifyFactoryBox()` uses: the factory password masked out
 *  of any router- or transport-provided sentence, then truncated. */
export function passwordScrubber(password: string): (text: unknown) => string {
  return makeScrubber(password, '');
}

function parseMajor(version: string | null): number | null {
  const m = /^\s*(\d+)\.\d+/.exec(version ?? '');
  return m ? Number(m[1]) : null;
}

function isBenchAddress(host: string): boolean {
  if (typeof host !== 'string' || !/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return false;
  const o = host.split('.').map(Number);
  if (o.some((n) => n > 255)) return false;
  if (o[0] === 10 || o[0] === 127) return true;
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true;
  if (o[0] === 192 && o[1] === 168) return true;
  if (o[0] === 169 && o[1] === 254) return true;
  return false;
}

function positive(v: number | undefined, fallback: number): number {
  return typeof v === 'number' && Number.isFinite(v) && v > 0 ? v : fallback;
}

function validPort(p: number): boolean {
  return Number.isInteger(p) && p >= 1 && p <= 65535;
}

export interface FileRow {
  id: string | null;
  name: string;
  type: string | null;
  size: string | null;
}

export async function listFiles(session: RouterOsApiSession, timeoutMs: number): Promise<FileRow[]> {
  const rows = await session.query(['/file/print', '=.proplist=.id,name,type,size'], { timeoutMs });
  return rows.map((r) => ({
    id: r['.id'] ?? null,
    name: r.name ?? '',
    type: r.type ?? null,
    size: r.size ?? null,
  }));
}

export async function removeFile(session: RouterOsApiSession, row: FileRow, timeoutMs: number): Promise<void> {
  if (!row.id) return;
  await session.query(['/file/remove', `=.id=${row.id}`], { timeoutMs });
}

/**
 * The inputs both operations share, refused before anything is dialled.
 * `retry` is the operation the message tells the preparer to run again.
 */
function validateTarget(
  req: FactoryIdentifyRequest,
  retry: string,
): { expected: string; port: number } {
  const invalid = (message: string) => new FactoryProvisioningError('INVALID_INPUT', 'validate', message);
  const expected = normalizeMac(req.expectedMac);
  if (!expected || !isUnicastMac(expected)) {
    throw invalid(
      `L'adresse MAC attendue (« ${String(req.expectedMac).slice(0, 40)} ») n'est pas celle d'un routeur : 12 caractères hexadécimaux sont attendus, par exemple B8:69:F4:12:34:56. Rien n'a été envoyé ; corrigez-la puis relancez la recherche du routeur.`,
    );
  }
  if (!isBenchAddress(req.host)) {
    throw invalid(
      `L'adresse « ${String(req.host).slice(0, 60)} » n'est pas une adresse IPv4 de réseau local. Un routeur neuf sur l'établi répond toujours sur une adresse privée (192.168.88.1 avec la configuration usine MikroTik) ; rien n'a été envoyé. Relancez la recherche du routeur.`,
    );
  }
  if (req.localAddress !== undefined && req.localAddress !== null && !isBenchAddress(req.localAddress)) {
    throw invalid(
      `L'adresse de ce poste sur la prise de l'établi (« ${String(req.localAddress).slice(0, 60)} ») n'est pas une adresse IPv4 de réseau local : rien n'a été envoyé. Relancez la recherche du routeur.`,
    );
  }
  const port = req.port ?? 8728;
  if (!validPort(port)) {
    throw invalid(
      `Port de l'API RouterOS invalide (« ${String(req.port).slice(0, 12)} ») : un entier entre 1 et 65535 est attendu. Rien n'a été envoyé au routeur ; ${retry}.`,
    );
  }
  if (typeof req.username !== 'string' || req.username.trim() === '') {
    throw invalid("Aucun identifiant de connexion n'a été fourni (« admin » en sortie d'usine). Rien n'a été envoyé ; relancez la recherche du routeur.");
  }
  if (typeof req.password !== 'string') {
    throw invalid("Aucun mot de passe n'a été fourni. Rien n'a été envoyé ; relancez la recherche du routeur.");
  }
  return { expected, port };
}

interface SessionContext {
  host: string;
  port: number;
  username: string;
  password: string;
  connectMs: number;
  requestMs: number;
  label: string;
  scrub: Scrub;
  progress: (step: ProvisioningStep) => void;
  /** `FactoryIdentifyRequest.localAddress`, validated; `null`: the OS routes. */
  localAddress: string | null;
}

function progressOf(cb: ((step: ProvisioningStep) => void) | undefined): (step: ProvisioningStep) => void {
  return (step) => {
    try {
      cb?.(step);
    } catch {
      /* a broken progress callback must not abort a reset half-way */
    }
  };
}

/** The username appears in messages only when it cannot be the password. */
function who(ctx: SessionContext): string {
  return ctx.username !== ctx.password ? ` « ${ctx.username} »` : '';
}

async function connect(dial: DialFn, ctx: SessionContext): Promise<RouterOsApiSession> {
  const target = `${ctx.host}:${ctx.port}${ctx.localAddress ? ` (depuis ${ctx.localAddress})` : ''}`;
  ctx.progress('connecting');
  try {
    return await dial({
      host: ctx.host,
      port: ctx.port,
      username: ctx.username,
      password: ctx.password,
      connectTimeoutMs: ctx.connectMs,
      requestTimeoutMs: ctx.requestMs,
      label: ctx.label,
      ...(ctx.localAddress ? { localAddress: ctx.localAddress } : {}),
    });
  } catch (err) {
    if (errKind(err) === 'auth') {
      throw new FactoryProvisioningError(
        'AUTH_FAILED',
        'connect',
        `Le routeur ${target} a refusé l'identifiant${who(ctx)}. Vérifiez le mot de passe usine imprimé sur l'étiquette, puis relancez la recherche du routeur. Rien n'a été modifié.`,
        { routerMessage: ctx.scrub(err) },
      );
    }
    throw new FactoryProvisioningError(
      'CONNECT_FAILED',
      'connect',
      `Impossible d'ouvrir l'API RouterOS sur ${target} (${ctx.scrub(err)}). Vérifiez le câble, l'adresse IP du poste et que le service « api » du routeur est actif, puis relancez la recherche du routeur. Rien n'a été modifié.`,
      { routerMessage: ctx.scrub(err) },
    );
  }
}

function lostFactory(scrub: Scrub, retry: string) {
  return (stage: ProvisioningStage, what: string, err: unknown, facts: FactoryProvisioningError['facts'] = {}) => {
    if (err instanceof FactoryProvisioningError) return err;
    return new FactoryProvisioningError(
      'SESSION_LOST',
      stage,
      `La session avec le routeur s'est interrompue pendant ${what} (${scrub(err)}). Le routeur n'a pas été réinitialisé ; ${retry}.`,
      { routerMessage: scrub(err), facts },
    );
  };
}

/** Steps 2 and 3 on an open session. Read-only. */
async function identifyOnSession(
  session: RouterOsApiSession,
  ctx: SessionContext,
  expected: string,
  retry: string,
): Promise<FactoryIdentification> {
  const lost = lostFactory(ctx.scrub, retry);
  const target = `${ctx.host}:${ctx.port}`;

  ctx.progress('checking-mac');
  const macs = new Set<string>();
  try {
    for (const r of await session.query(['/interface/print', '=.proplist=name,mac-address'], { timeoutMs: ctx.requestMs })) {
      const m = normalizeMac(r['mac-address']);
      if (m && m !== '00:00:00:00:00:00') macs.add(m);
    }
  } catch (err) {
    if (errKind(err) !== 'trap') throw lost('identify', 'la lecture des interfaces', err);
    throw new FactoryProvisioningError(
      'MAC_UNVERIFIABLE',
      'identify',
      `Le routeur a refusé la lecture de ses interfaces (${ctx.scrub(err)}) : impossible de vérifier qu'il s'agit bien du boîtier ${expected}. Rien n'a été modifié ; vérifiez que le compte utilisé est administrateur, puis relancez la recherche du routeur.`,
      { routerMessage: ctx.scrub(err) },
    );
  }
  try {
    const eth = await session.query(
      ['/interface/ethernet/print', '=.proplist=name,mac-address,orig-mac-address'],
      { timeoutMs: ctx.requestMs },
    );
    for (const r of eth) {
      for (const v of [r['mac-address'], r['orig-mac-address']]) {
        const m = normalizeMac(v);
        if (m && m !== '00:00:00:00:00:00') macs.add(m);
      }
    }
  } catch (err) {
    // The burned-in MAC is a second witness, not the only one: a trap here
    // leaves the /interface reading to decide. A dead session does not.
    if (errKind(err) !== 'trap') throw lost('identify', 'la lecture des interfaces Ethernet', err);
  }
  const interfaceMacs = Array.from(macs).sort();

  if (interfaceMacs.length === 0) {
    throw new FactoryProvisioningError(
      'MAC_UNVERIFIABLE',
      'identify',
      `Le routeur ${target} n'a présenté aucune adresse MAC : impossible de vérifier qu'il s'agit bien du boîtier ${expected}. Rien n'a été modifié ; relancez la recherche du routeur.`,
      { facts: { interfaceMacs } },
    );
  }
  if (!macs.has(expected)) {
    const shown = interfaceMacs.slice(0, 6).join(', ') + (interfaceMacs.length > 6 ? ', …' : '');
    throw new FactoryProvisioningError(
      'MAC_MISMATCH',
      'identify',
      `Ce routeur n'est pas le boîtier attendu : l'adresse ${expected} ne figure sur aucune de ses interfaces (il présente ${shown}). Rien n'a été modifié. Vérifiez l'étiquette du boîtier branché et l'adresse ${ctx.host}, puis relancez la recherche du routeur.`,
      { facts: { interfaceMacs } },
    );
  }

  ctx.progress('reading-router');
  let resource: Record<string, string> | null = null;
  let board: Record<string, string> | null = null;
  try {
    resource = (await session.query(['/system/resource/print'], { timeoutMs: ctx.requestMs }))[0] ?? null;
  } catch (err) {
    if (errKind(err) !== 'trap') throw lost('identify', 'la lecture de la version', err, { interfaceMacs });
  }
  try {
    board = (await session.query(['/system/routerboard/print'], { timeoutMs: ctx.requestMs }))[0] ?? null;
  } catch (err) {
    if (errKind(err) !== 'trap') throw lost('identify', 'la lecture du modèle', err, { interfaceMacs });
  }
  const version = resource?.version?.trim() || null;
  const router: RouterFacts = {
    version,
    majorVersion: parseMajor(version),
    board: resource?.['board-name']?.trim() || null,
    architecture: resource?.['architecture-name']?.trim() || null,
    model: board?.model?.trim() || null,
    serial: board?.['serial-number']?.trim() || null,
  };
  return { matchedMac: expected, interfaceMacs, router };
}

// ============================================================================
// Identify (read-only)
// ============================================================================

/** yes/no as RouterOS prints it (true/false over some API builds); anything
 *  else — absent, blank, a word a future firmware adds — is not a flag. */
function routerFlag(raw: string | undefined): boolean | null {
  const v = (raw ?? '').trim().toLowerCase();
  if (v === 'yes' || v === 'true') return true;
  if (v === 'no' || v === 'false') return false;
  return null;
}

/**
 * The read-only facts beyond the MAC proof: Wi-Fi stack, device-mode, system
 * identity, local accounts, installed packages and IP addresses (identity,
 * accounts and addresses say whether the box is still in its factory state;
 * the packages, what a RouterOS upgrade must replace). A `!trap` is an answer
 * (the menu does not exist on this build, or
 * the account may not read it); a dead session is not, and aborts like any
 * other read of the identification.
 */
async function readBoxExtras(
  session: RouterOsApiSession,
  ctx: SessionContext,
  retry: string,
  facts: FactoryProvisioningError['facts'],
): Promise<Pick<FactoryBoxIdentification, 'wifiStack' | 'deviceMode' | 'systemIdentity' | 'userNames' | 'packages' | 'addresses'>> {
  const lost = lostFactory(ctx.scrub, retry);
  const ask = async (words: string[], what: string): Promise<Record<string, string>[] | null> => {
    try {
      return await session.query(words, { timeoutMs: ctx.requestMs });
    } catch (err) {
      if (errKind(err) !== 'trap') throw lost('identify', what, err, facts);
      return null;
    }
  };
  let wifiStack: WifiStack | null = null;
  if ((await ask(['/interface/wifi/print', '=.proplist=name'], 'la lecture du Wi-Fi')) !== null) {
    wifiStack = 'wifi';
  } else if ((await ask(['/interface/wireless/print', '=.proplist=name'], 'la lecture du Wi-Fi')) !== null) {
    wifiStack = 'wireless';
  }
  const observedAt = new Date().toISOString();
  const rows = await ask(['/system/device-mode/print'], 'la lecture du mode appareil');
  const row = rows?.[0] ?? null;
  const deviceMode: DeviceModeReadout = { answered: row !== null, mode: null, flags: {}, observedAt };
  if (row) {
    deviceMode.mode = (row.mode ?? '').trim().toLowerCase() || null;
    for (const [k, v] of Object.entries(row)) {
      if (k === 'mode' || k.startsWith('.')) continue;
      const flag = routerFlag(v);
      if (flag !== null) deviceMode.flags[k] = flag;
    }
  }
  const idRows = await ask(['/system/identity/print'], "la lecture du nom du routeur");
  const systemIdentity = idRows ? (idRows[0]?.name ?? '').trim() || null : null;
  const userRows = await ask(['/user/print', '=.proplist=name'], 'la lecture des comptes');
  const userNames = userRows ? userRows.map((r) => (r.name ?? '').trim()).filter((n) => n !== '') : null;
  const pkgRows = await ask(['/system/package/print', '=.proplist=name,version,disabled'], 'la lecture des paquets');
  const packages = pkgRows
    ? pkgRows
      .map((r) => ({ name: (r.name ?? '').trim(), version: (r.version ?? '').trim() || null, disabled: routerFlag(r.disabled) === true }))
      .filter((p) => p.name !== '')
    : null;
  const addrRows = await ask(['/ip/address/print', '=.proplist=address,interface,comment,dynamic'], 'la lecture des adresses IP');
  const addresses = addrRows
    ? addrRows
      .map((r) => ({
        address: (r.address ?? '').trim(),
        interface: (r.interface ?? '').trim() || null,
        comment: (r.comment ?? '').trim() || null,
        dynamic: routerFlag(r.dynamic) === true,
      }))
      .filter((a) => a.address !== '')
    : null;
  return { wifiStack, deviceMode, systemIdentity, userNames, packages, addresses };
}

// ============================================================================
// The SIM card in the modem (read-only)
// ============================================================================

/**
 * Each single query of a SIM read (the LTE list, `info`, `monitor`, the
 * uptime). Reads after the first are also cut to what is left of the budget.
 */
export const SIM_READ_TIMEOUT_MS = 8_000;

/**
 * How long the bench waits for the modem to show a card before it concludes
 * "no SIM". A box read right after a boot — the router-first RouterOS update
 * reboots it just before the preparation, and a factory box is often prepared
 * a minute after it was plugged in — may not list `lte1` yet, or list it
 * before its modem has read the card: the ONE read the bench used to take
 * then printed "aucune lue" for a card that was in the slot. A minute is a
 * guess at what a modem needs after boot (NOT observed); being wrong costs
 * little either way, since no SIM is never a refusal — the line is only not
 * linked to the router by itself.
 */
export const SIM_WAIT_BUDGET_MS = 60_000;

/** The pause between two SIM reads. */
export const SIM_RETRY_MS = 5_000;

/**
 * An EMPTY `/interface/lte/print` is waited on only while the box has been up
 * for less than this. On RouterOS 7 the LTE menu exists on every box, so an
 * empty list is also exactly what a box with NO modem answers, and waiting
 * the whole budget on every RB5009 would cost a minute per box for nothing:
 * a modem that has not appeared once the box has been up two minutes is
 * taken as absent. REASONED, not observed: how long a modem takes to show up
 * after boot, and the uptime format `parseRouterOsDurationMs` reads.
 */
export const SIM_MODEM_APPEAR_UPTIME_MS = 120_000;

/** The SIM card the bench read in the box's `lte1` modem. */
export interface SimCardReading {
  /** 18 to 22 digits: the shape `sim_lines.iccid` holds (migration 032). */
  iccid: string;
  /** 6 to 15 digits, or null when the modem printed none — a card still
   *  locked by its PIN shows its ICCID and no IMSI. */
  imsi: string | null;
}

/**
 * What a SIM wait is waiting for. `lte1`: the box listed no LTE interface yet
 * (just booted); `card`: `lte1` is listed and has shown no ICCID yet;
 * `answer`: the modem's menus did not answer in time.
 */
export type SimWaitFor = 'lte1' | 'card' | 'answer';

/**
 * How a SIM read ended. `read`: an ICCID. `no-modem`: concluded at once —
 * the LTE menu traps (no LTE support on the box), lists interfaces but no
 * `lte1`, or is empty on a box up long enough for a modem to have appeared.
 * The other three: the wait ran out still waiting for that `SimWaitFor`.
 */
export type SimReadOutcome = 'read' | 'no-modem' | 'no-lte1' | 'no-card' | 'no-answer';

export interface SimReadReport {
  sim: SimCardReading | null;
  outcome: SimReadOutcome;
  /** Reads taken: 1 when the first one decided. */
  attempts: number;
  /** From the first read to the conclusion, on the `now` clock. */
  waitedMs: number;
}

/** One SIM read found no card yet, and the wait goes on. */
export interface SimWaitTick {
  waitingFor: SimWaitFor;
  /** Reads taken so far. */
  attempt: number;
  elapsedMs: number;
  /** When the wait started, and when it gives up (on the `now` clock):
   *  sooner than the budget when only `lte1` is awaited on a box that has
   *  already been up for a while. */
  startedAt: number;
  deadline: number;
}

export interface SimReadOptions {
  /** Per query. Default `SIM_READ_TIMEOUT_MS`. */
  timeoutMs?: number;
  /** Default `SIM_WAIT_BUDGET_MS`; 0 reads exactly once. */
  budgetMs?: number;
  /** Default `SIM_RETRY_MS`. */
  retryMs?: number;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  /** After every read that found no card yet, before the pause. */
  onTick?: (tick: SimWaitTick) => void;
}

const SIM_OUTCOME_OF: Record<SimWaitFor, SimReadOutcome> = { lte1: 'no-lte1', card: 'no-card', answer: 'no-answer' };

/** An ICCID as a modem prints it, or null. Blanks are dropped, and a trailing
 *  `F` — the BCD filler some modems print after a 19-digit ICCID — with them;
 *  anything else that is not 18 to 22 digits is not an ICCID. */
export function parseIccid(raw: string | undefined): string | null {
  let v = (raw ?? '').replace(/\s+/g, '').toUpperCase();
  if (v.endsWith('F')) v = v.slice(0, -1);
  return /^[0-9]{18,22}$/.test(v) ? v : null;
}

/** An IMSI (6 to 15 digits), or null. */
export function parseImsi(raw: string | undefined): string | null {
  const v = (raw ?? '').replace(/\s+/g, '');
  return /^[0-9]{6,15}$/.test(v) ? v : null;
}

/**
 * A RouterOS duration in milliseconds — `1w2d3h4m5s` (any subset of the
 * units, `ms` included) or one ending in a clock, `1d03:04:05` — or null for
 * anything else. Which of the two shapes the API prints `uptime` in is not
 * observed, so both are read, and a shape neither covers is unknown, never 0.
 */
export function parseRouterOsDurationMs(raw: string | undefined): number | null {
  let v = (raw ?? '').trim().toLowerCase();
  if (v === '') return null;
  let ms = 0;
  const clock = /(\d+):(\d{2}):(\d{2})$/.exec(v);
  if (clock) {
    ms += ((Number(clock[1]) * 60 + Number(clock[2])) * 60 + Number(clock[3])) * 1_000;
    v = v.slice(0, clock.index);
  }
  const unit: Record<string, number> = { w: 604_800_000, d: 86_400_000, h: 3_600_000, m: 60_000, s: 1_000, ms: 1 };
  let at = 0;
  for (const t of v.matchAll(/(\d+)(ms|w|d|h|m|s)/g)) {
    if (t.index !== at) return null;
    ms += Number(t[1]) * unit[t[2]];
    at += t[0].length;
  }
  if (at !== v.length || (!clock && at === 0)) return null;
  return ms;
}

/** One look at the modem. `empty`: the LTE list answered, with no interface. */
type SimProbe =
  | { kind: 'card'; sim: SimCardReading }
  | { kind: 'no-modem' }
  | { kind: 'empty' }
  | { kind: 'wait'; waitingFor: 'card' | 'answer'; lte1Listed: boolean };

/** `timeoutMs` is asked again before every query: a round of three slow
 *  queries must not run past the budget by three timeouts. */
async function probeSimCard(session: RouterOsApiSession, timeoutMs: () => number): Promise<SimProbe> {
  const answer = async (words: string[]): Promise<Record<string, string>[] | 'trap' | 'timeout'> => {
    try {
      return await session.query(words, { timeoutMs: timeoutMs() });
    } catch (err) {
      const kind = errKind(err);
      if (kind === 'trap' || kind === 'timeout') return kind;
      throw err;
    }
  };
  const ifaces = await answer(['/interface/lte/print', '=.proplist=name']);
  if (ifaces === 'timeout') return { kind: 'wait', waitingFor: 'answer', lte1Listed: false };
  if (ifaces === 'trap') return { kind: 'no-modem' };
  if (ifaces.length === 0) return { kind: 'empty' };
  if (!ifaces.some((r) => (r.name ?? '').trim() === 'lte1')) return { kind: 'no-modem' };
  let answered = false;
  let timedOut = false;
  for (const menu of ['/interface/lte/info', '/interface/lte/monitor']) {
    const rows = await answer([menu, '=numbers=lte1', '=once=']);
    if (rows === 'timeout') {
      timedOut = true;
      continue;
    }
    if (rows === 'trap') continue;
    answered = true;
    for (const row of rows) {
      // Each name judged on its own: `row.uicc ?? row.iccid` kept an EMPTY
      // `uicc` (`??` only skips undefined) and read a card as "none".
      const iccid = parseIccid(row.uicc) ?? parseIccid(row.iccid);
      if (iccid) return { kind: 'card', sim: { iccid, imsi: parseImsi(row.imsi) } };
    }
  }
  return { kind: 'wait', waitingFor: !answered && timedOut ? 'answer' : 'card', lte1Listed: true };
}

/** The box's uptime in ms, or null when it could not be read. */
async function readUptimeMs(session: RouterOsApiSession, timeoutMs: number): Promise<number | null> {
  try {
    const rows = await session.query(['/system/resource/print', '=.proplist=uptime'], { timeoutMs });
    return parseRouterOsDurationMs(rows[0]?.uptime);
  } catch (err) {
    const kind = errKind(err);
    if (kind === 'trap' || kind === 'timeout') return null;
    throw err;
  }
}

/**
 * The SIM card in `lte1`: `/interface/lte/info` with `=numbers=lte1` and
 * `=once=`, then `/interface/lte/monitor` with the same words when `info`
 * gives no ICCID (RouterOS 7 moved what `info` printed to `monitor`). The
 * ICCID is read from `uicc` — the name RouterOS prints it under — or
 * `iccid`. Read-only.
 *
 * ┌─ A CARD NOT SHOWN YET IS WAITED FOR, WITHIN ONE BUDGET ──────────────────┐
 * │ `lte1` listed and no ICCID yet: read again every `SIM_RETRY_MS`, for up │
 * │ to `SIM_WAIT_BUDGET_MS` — a modem lists itself before it has read its   │
 * │ card. The LTE list EMPTY: `lte1` is waited for within the same budget,  │
 * │ but only while the box is young (`SIM_MODEM_APPEAR_UPTIME_MS`, by its  │
 * │ own `uptime`; an uptime that cannot be read leaves the budget alone to  │
 * │ bound it). A read that times out is waited past the same way.           │
 * │ Concluded AT ONCE: a menu that traps (no LTE support), a list with      │
 * │ interfaces but no `lte1`, an empty list on a box up for a while.        │
 * │ `onTick` reports every read that found nothing yet, before the pause.   │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * NO SIM is an answer, never a refusal: every way of finding none returns
 * `sim: null` with its `outcome`, and the preparation goes on. Only a DEAD
 * session (closed, fatal) is thrown: nothing after it could be sent on it
 * either.
 *
 * REASONED, not observed on a box: the field names (`uicc`, `imsi`), that
 * `once` makes `info` / `monitor` answer one reply and finish over the API,
 * how long a modem takes after boot to list itself and to show its card, and
 * the `uptime` format.
 */
export async function readSimCard(session: RouterOsApiSession, o: SimReadOptions = {}): Promise<SimReadReport> {
  const now = o.now ?? Date.now;
  const sleep = o.sleep ?? defaultSleep;
  const perRead = positive(o.timeoutMs, SIM_READ_TIMEOUT_MS);
  const budgetMs = typeof o.budgetMs === 'number' && Number.isFinite(o.budgetMs) && o.budgetMs >= 0 ? o.budgetMs : SIM_WAIT_BUDGET_MS;
  const retryMs = positive(o.retryMs, SIM_RETRY_MS);
  const startedAt = now();
  const deadline = startedAt + budgetMs;
  // Set at the first EMPTY list on a box that never listed `lte1`: when a
  // modem stops being plausible on THIS box (SIM_MODEM_APPEAR_UPTIME_MS).
  let lte1Until: number | null = null;
  let sawLte1 = false;
  let attempts = 0;
  const end = (outcome: SimReadOutcome, sim: SimCardReading | null = null): SimReadReport =>
    ({ sim, outcome, attempts, waitedMs: now() - startedAt });
  for (;;) {
    attempts++;
    // The first round has the whole per-query time, as the single read always
    // had; later queries no more than what is left (1 s at least), so a modem
    // that never answers costs about the budget, not the budget plus timeouts.
    const first = attempts === 1;
    const timeoutMs = () => (first ? perRead : Math.min(perRead, Math.max(1_000, deadline - now())));
    const probe = await probeSimCard(session, timeoutMs);
    if (probe.kind === 'card') return end('read', probe.sim);
    if (probe.kind === 'no-modem') return end('no-modem');
    let waitingFor: SimWaitFor;
    let until = deadline;
    if (probe.kind === 'empty') {
      waitingFor = 'lte1';
      // A box that listed `lte1` a moment ago has a modem re-enumerating:
      // the budget alone bounds that. Otherwise the box's age decides.
      if (!sawLte1) {
        if (lte1Until === null) {
          const uptimeMs = await readUptimeMs(session, timeoutMs());
          if (uptimeMs !== null && uptimeMs >= SIM_MODEM_APPEAR_UPTIME_MS) return end('no-modem');
          lte1Until = uptimeMs === null ? deadline : now() + (SIM_MODEM_APPEAR_UPTIME_MS - uptimeMs);
        }
        until = Math.min(deadline, lte1Until);
      }
    } else {
      waitingFor = probe.waitingFor;
      if (probe.lte1Listed) sawLte1 = true;
    }
    if (now() + retryMs > until) return end(SIM_OUTCOME_OF[waitingFor]);
    try {
      o.onTick?.({ waitingFor, attempt: attempts, elapsedMs: now() - startedAt, startedAt, deadline: until });
    } catch {
      /* a broken progress callback must not end the wait */
    }
    await sleep(retryMs);
  }
}

/**
 * Log in, prove the box carries `expectedMac`, read its model and version,
 * then its Wi-Fi stack and device-mode. Writes nothing. This is what turns an
 * MNDP candidate (`discoverByMac`, which is only where to dial) into a box the
 * screen may call found; it throws `FactoryProvisioningError` — `MAC_MISMATCH`
 * for the neighbouring box of the same batch — exactly as the provisioning
 * would.
 */
export async function identifyFactoryBox(
  req: FactoryIdentifyRequest,
  deps: Pick<FactoryProvisioningDeps, 'dial'> = {},
): Promise<FactoryBoxIdentification> {
  return withProvenSession(req, deps, { label: 'bench:identify', retry: 'relancez la recherche du routeur' }, async (_s, identity) => identity);
}

/**
 * Log in and take EXACTLY the proof `identifyFactoryBox()` takes — the typed
 * MAC on the router's own interfaces, then model, version, Wi-Fi stack and
 * device-mode — and only then hand the still-open session to `use`. The
 * session is closed afterwards, whatever `use` did.
 *
 * For a caller that must WRITE to the box (the RouterOS upgrade): every write
 * it makes goes through this session, i.e. through the box that proved itself
 * on it, and nothing reaches `use` before the proof passed. A refusal of the
 * proof is a `FactoryProvisioningError` naming `retry`; what `use` throws is
 * passed through untouched.
 */
export async function withProvenSession<T>(
  req: FactoryIdentifyRequest,
  deps: Pick<FactoryProvisioningDeps, 'dial'>,
  opts: { label: string; retry: string },
  use: (session: RouterOsApiSession, identity: FactoryBoxIdentification) => Promise<T>,
): Promise<T> {
  const retry = opts.retry;
  const { expected, port } = validateTarget(req, retry);
  const ctx: SessionContext = {
    host: req.host,
    port,
    username: req.username,
    password: req.password,
    connectMs: positive(req.timeouts?.connectMs, 8_000),
    requestMs: positive(req.timeouts?.requestMs, 15_000),
    label: opts.label,
    scrub: makeScrubber(req.password, ''),
    progress: progressOf(req.onProgress),
    localAddress: req.localAddress ?? null,
  };
  const session = await connect(deps.dial ?? defaultDial, ctx);
  try {
    let identity: FactoryBoxIdentification;
    try {
      const proven = await identifyOnSession(session, ctx, expected, retry);
      const extras = await readBoxExtras(session, ctx, retry, {
        interfaceMacs: proven.interfaceMacs,
        router: proven.router,
      });
      identity = { ...proven, ...extras };
    } catch (err) {
      if (err instanceof FactoryProvisioningError) throw err;
      throw lostFactory(ctx.scrub, retry)('identify', "l'identification", err);
    }
    return await use(session, identity);
  } finally {
    try {
      session.close();
    } catch {
      /* already gone */
    }
  }
}

// ============================================================================
// Device-mode: ask the router to allow a feature (the human confirms)
// ============================================================================

/** A RouterOS device-mode flag name (`l2tp`, `bandwidth-test`…). */
const DEVICE_MODE_FEATURE = /^[a-z][a-z0-9-]{1,30}$/;

/**
 * How the request ended. None of them means the feature is allowed — only a
 * fresh identification after the reboot says that:
 *  - `acknowledged`: the router answered `!done`;
 *  - `session-dropped`: the session died while the request was pending —
 *    what the reboot that follows a confirmation looks like from here (and
 *    also what a pulled cable looks like);
 *  - `window-expired`: nothing came back before `waitMs` (the activation
 *    window). `awaiting-confirmation` is the same outcome under its old name,
 *    kept for the callers that test it.
 */
export type DeviceModeUpdateOutcome = 'acknowledged' | 'session-dropped' | 'window-expired' | 'awaiting-confirmation';

/** MikroTik's default activation window for a device-mode change (5 min),
 *  plus the margin the bench waits beyond it before giving up. */
export const DEVICE_MODE_ACTIVATION_MS = 5 * 60_000;
const DEVICE_MODE_REQUEST_WAIT_MS = DEVICE_MODE_ACTIVATION_MS + 30_000;

/**
 * `/system/device-mode/update <feature>=yes …` on the box that carries
 * `expectedMac` — the MAC proof is taken first, on this session, exactly as
 * for the provisioning. RouterOS only applies a device-mode change after a
 * physical confirmation (a press on the reset or mode button, or a power
 * cycle, within the activation window — 5 min by default); nothing here can
 * stand in for it.
 *
 * ┌─ THE REQUEST IS NEVER CANCELLED BY THE BENCH ────────────────────────────┐
 * │ The CLI waits on this command until the press ("please activate by       │
 * │ turning power off or pressing reset or mode button in 5m00s"). Over the  │
 * │ API it may answer at once or only then — not observed — and the          │
 * │ transport `/cancel`s a request whose own timeout expires. A short        │
 * │ timeout (this function used one) would therefore cancel, from the bench  │
 * │ side, the very change the preparer is about to confirm with the button.  │
 * │ So the request waits for the whole window (`waitMs`), the session stays  │
 * │ open across it, and the session dying is read as the reboot it is.       │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * `onSent` is called right before the request leaves (the window starts
 * there), after the MAC proof.
 */
export async function requestDeviceModeUpdate(
  req: FactoryIdentifyRequest & { features: string[]; waitMs?: number; onSent?: () => void },
  deps: Pick<FactoryProvisioningDeps, 'dial'> = {},
): Promise<{ outcome: DeviceModeUpdateOutcome; features: string[] }> {
  const retry = 'relancez la recherche du routeur';
  const { expected, port } = validateTarget(req, retry);
  const features = Array.from(new Set(Array.isArray(req.features) ? req.features : []));
  if (features.length === 0 || !features.every((f) => typeof f === 'string' && DEVICE_MODE_FEATURE.test(f))) {
    throw new FactoryProvisioningError(
      'INVALID_INPUT',
      'validate',
      "Aucune fonction valide à autoriser n'a été demandée. Rien n'a été envoyé ; relancez la recherche du routeur.",
    );
  }
  const ctx: SessionContext = {
    host: req.host,
    port,
    username: req.username,
    password: req.password,
    connectMs: positive(req.timeouts?.connectMs, 8_000),
    requestMs: positive(req.timeouts?.requestMs, 15_000),
    label: 'bench:device-mode',
    scrub: makeScrubber(req.password, ''),
    progress: progressOf(req.onProgress),
    localAddress: req.localAddress ?? null,
  };
  const session = await connect(deps.dial ?? defaultDial, ctx);
  const waitMs = positive(req.waitMs, DEVICE_MODE_REQUEST_WAIT_MS);
  try {
    await identifyOnSession(session, ctx, expected, retry);
    try {
      try {
        req.onSent?.();
      } catch {
        /* a broken callback must not stop the request */
      }
      await session.query(['/system/device-mode/update', ...features.map((f) => `=${f}=yes`)], { timeoutMs: waitMs });
      return { outcome: 'acknowledged', features };
    } catch (err) {
      const kind = errKind(err);
      if (kind === 'trap') {
        throw new FactoryProvisioningError(
          'DEVICE_MODE_REFUSED',
          'device-mode',
          `Le routeur a refusé la demande de changement de mode appareil (${ctx.scrub(err)}). Rien n'a été modifié ; ${retry}.`,
          { routerMessage: ctx.scrub(err) },
        );
      }
      return { outcome: kind === 'timeout' ? 'window-expired' : 'session-dropped', features };
    }
  } catch (err) {
    if (err instanceof FactoryProvisioningError) throw err;
    throw lostFactory(ctx.scrub, retry)('device-mode', 'la demande de changement de mode appareil', err);
  } finally {
    try {
      session.close();
    } catch {
      /* already gone */
    }
  }
}

// ============================================================================
// The operation
// ============================================================================

/**
 * Identify, upload, reset. See the file header for the order and the reasons.
 * Resolves once the reset command has been sent and answered (or the session
 * dropped, which is what a reboot looks like); throws
 * `FactoryProvisioningError` otherwise, always before the box was reset.
 */
export async function applyFactoryProvisioning(
  req: FactoryProvisioningRequest,
  deps: FactoryProvisioningDeps = {},
): Promise<FactoryProvisioningResult> {
  const retry = "relancez l'écriture de la configuration";
  const password = typeof req.password === 'string' ? req.password : '';
  const compiledSet: CompiledProvisioningFile[] | null = Array.isArray(req.compiledFiles) && req.compiledFiles.length > 0
    ? req.compiledFiles
    : req.compiled ? [{ ...req.compiled, role: 'runner' }] : null;
  const compiled = compiledSet !== null;
  // The compiled files carry the same secrets the legacy body did (the L2TP
  // secret, the ObliWAN account): they are scrubbed out of every message alike.
  const script = compiledSet
    ? compiledSet.map((f) => (typeof f?.content === 'string' ? f.content : '')).join('\n')
    : (typeof req.script === 'string' ? req.script : '');
  const scrub = makeScrubber(password, script);
  const dial = deps.dial ?? defaultDial;
  const sleep = deps.sleep ?? defaultSleep;
  const resetMs = positive(req.timeouts?.resetMs, 10_000);

  // ---- validate: nothing is dialled until every input is acceptable --------

  const invalid = (message: string) => new FactoryProvisioningError('INVALID_INPUT', 'validate', message);
  const { expected, port } = validateTarget(req, retry);
  if (typeof req.tag !== 'string' || !PROVISION_TAG_PATTERN.test(req.tag)) {
    throw invalid(
      `Étiquette de provisionnement invalide (« ${String(req.tag).slice(0, 70)} ») : seuls lettres, chiffres, « . », « _ » et « - » sont admis. Rien n'a été envoyé au routeur ; ${retry}.`,
    );
  }
  const sshPort = req.sshPort ?? 22;
  if (!validPort(sshPort)) {
    throw invalid(
      `Port SSH invalide (« ${String(req.sshPort).slice(0, 12)} ») : un entier entre 1 et 65535 est attendu. Rien n'a été envoyé au routeur ; ${retry}.`,
    );
  }
  // What goes on the box, in upload order; the LAST entry is what
  // run-after-reset executes.
  let toUpload: Array<{ name: string; content: string }>;
  if (compiledSet) {
    const seen = new Set<string>();
    const accepted: Array<{ name: string; content: string; role: 'runner' | 'body' }> = [];
    for (const f of compiledSet) {
      const fileName = f?.fileName;
      if (typeof fileName !== 'string' || !COMPILED_FILE_NAME_PATTERN.test(fileName)) {
        throw invalid(
          `Le nom de fichier fourni par ObliWAN (« ${String(fileName).slice(0, 70)} ») n'est pas un nom de script RouterOS sans dossier (lettres, chiffres, « . », « _ », « - », terminé par .rsc). Rien n'a été envoyé au routeur ; ${retry}.`,
        );
      }
      if (seen.has(fileName.toLowerCase())) {
        throw invalid(`ObliWAN a fourni deux fichiers du même nom (« ${fileName} »). Rien n'a été envoyé au routeur ; ${retry}.`);
      }
      seen.add(fileName.toLowerCase());
      const content = typeof f.content === 'string' ? f.content : '';
      if (!content) {
        throw invalid(`Le fichier de configuration « ${fileName} » fourni par ObliWAN est vide. Rien n'a été envoyé au routeur ; ${retry}.`);
      }
      const announced = typeof f.sha256 === 'string' ? f.sha256.trim().toLowerCase() : '';
      if (!/^[0-9a-f]{64}$/.test(announced) || sha256Hex(content) !== announced) {
        throw invalid(
          `Le fichier de configuration reçu ne correspond pas à l'empreinte SHA-256 annoncée par ObliWAN : il a pu être altéré ou tronqué en route. Rien n'a été envoyé au routeur ; ${retry}.`,
        );
      }
      const role = compiledSet.length === 1 ? 'runner' : f.role;
      if (role !== 'runner' && role !== 'body') {
        throw invalid(`ObliWAN n'a pas dit quel fichier lancer après la réinitialisation (« ${fileName} »). Rien n'a été envoyé au routeur ; ${retry}.`);
      }
      accepted.push({ name: fileName, content, role });
    }
    const runners = accepted.filter((f) => f.role === 'runner');
    if (runners.length !== 1) {
      throw invalid(
        `ObliWAN a fourni ${runners.length} fichiers à lancer après la réinitialisation au lieu d'un seul. Rien n'a été envoyé au routeur ; ${retry}.`,
      );
    }
    // Each file carries secrets in plaintext: each must be removed from the
    // box by a line of the set (the runner usually removes both).
    for (const f of accepted) {
      if (!accepted.some((g) => compiledRemovesItself(g.content, f.name))) {
        throw invalid(
          `Le fichier de configuration « ${f.name} » fourni par ObliWAN ne s'efface pas du routeur : il contient des mots de passe en clair et resterait lisible dans sa mémoire. Rien n'a été envoyé au routeur ; signalez-le à un administrateur d'ObliWAN.`,
        );
      }
    }
    // Bodies first, in the server's order; the runner last.
    toUpload = [...accepted.filter((f) => f.role === 'body'), runners[0]].map((f) => ({ name: f.name, content: f.content }));
  } else {
    const files = splitProvisioningPackage(script, req.tag);
    if (!files) {
      throw invalid(
        `Le script à déposer n'a pas été préparé pour l'étiquette « ${req.tag} » par buildRunAfterResetScript() : exécuté tel quel après la réinitialisation, il s'arrêterait à la première erreur sans rien signaler sur le routeur. Rien n'a été envoyé ; ${retry}.`,
      );
    }
    // Body first: a runner on the box with no body beside it is a box that
    // would reset into nothing, however briefly.
    toUpload = [
      { name: provisioningBodyFileName(req.tag), content: files.body },
      { name: provisioningFileName(req.tag), content: files.runner },
    ];
  }

  const ctx: SessionContext = {
    host: req.host,
    port,
    username: req.username,
    password,
    connectMs: positive(req.timeouts?.connectMs, 8_000),
    requestMs: positive(req.timeouts?.requestMs, 15_000),
    label: `bench:${req.tag}`,
    scrub,
    progress: progressOf(req.onProgress),
    localAddress: req.localAddress ?? null,
  };
  const requestMs = ctx.requestMs;
  const lost = lostFactory(scrub, retry);

  // ---- connect ---------------------------------------------------------------

  const session = await connect(dial, ctx);

  // Every path written, or possibly half-written, on the box. Cleared once
  // the reset is accepted (from then on the legacy runner deletes both files,
  // and a compiled file deletes itself: `compiledRemovesItself` refused it
  // before the dial otherwise). A refusal in between
  // removes them: the content carries the rendered secrets.
  const placed = new Set<string>();
  // Only read by the catch-all below, for an error no branch anticipated.
  let stage: ProvisioningStage = 'identify';

  try {
    // ---- identify ------------------------------------------------------------

    const identity = await identifyOnSession(session, ctx, expected, retry);
    const facts = { interfaceMacs: identity.interfaceMacs, router: identity.router };
    const router = identity.router;

    // ---- the SIM card ----------------------------------------------------------
    // Read on the proven session, because after the reset the factory
    // credential no longer opens the box, and the ObliWAN account it gets
    // answers the management range only; the card in the slot is the same
    // before and after the reset. Read BEFORE the upload rather than just
    // before the reset: the read may wait up to `SIM_WAIT_BUDGET_MS` for a
    // modem that has just booted, and a cable pulled during a wait with the
    // site's files on flash would leave their plaintext secrets on a box
    // nobody resets. No SIM is never a refusal (`readSimCard`); a dead
    // session is, as for every read.

    ctx.progress('reading-sim');
    let simRead: SimReadReport;
    try {
      simRead = await readSimCard(session, {
        timeoutMs: Math.min(requestMs, SIM_READ_TIMEOUT_MS),
        budgetMs: req.simWait?.budgetMs,
        retryMs: req.simWait?.retryMs,
        sleep,
        now: deps.now,
        onTick: req.onSimWait,
      });
    } catch (err) {
      throw lost('identify', 'la lecture de la carte SIM', err, facts);
    }

    // ---- upload ----------------------------------------------------------------

    stage = 'upload';
    ctx.progress('uploading');
    let listing: FileRow[];
    try {
      listing = await listFiles(session, requestMs);
    } catch (err) {
      if (errKind(err) !== 'trap') throw lost('upload', 'la lecture des fichiers', err, facts);
      throw new FactoryProvisioningError(
        'UPLOAD_REFUSED',
        'upload',
        `Le routeur a refusé la lecture de ses fichiers (${scrub(err)}). Rien n'a été modifié ; ${retry}.`,
        { routerMessage: scrub(err), facts },
      );
    }
    // Boxes with a separate NAND keep only `flash/` across a reboot; a file
    // written beside it would be gone by the time run-after-reset looks for it.
    const flash = listing.some((f) => f.name === 'flash' && (f.type === null || /disk|dir/i.test(f.type)));
    const prefix = flash ? 'flash/' : '';
    // In `toUpload` order (see above): the last one is what run-after-reset runs.
    const uploads = toUpload.map((u) => ({
      path: `${prefix}${u.name}`,
      content: u.content,
      bytes: Buffer.byteLength(u.content, 'utf8'),
    }));
    const runnerPath = uploads[uploads.length - 1].path;
    const bodyPath = uploads.length > 1 ? uploads[0].path : null;
    const bytes = uploads.reduce((n, u) => n + u.bytes, 0);

    // A file of the same name, and any `obliwan-*.rsc` an earlier attempt left
    // (another tag, another compile): each holds that attempt's secrets, and a
    // second runner on the box is one more thing that could run.
    const staleFiles: string[] = [];
    for (const stale of listing.filter((f) => uploads.some((u) => u.path === f.name) || STALE_PROVISIONING_FILE.test(f.name))) {
      try {
        await removeFile(session, stale, requestMs);
        staleFiles.push(stale.name);
      } catch (err) {
        if (errKind(err) !== 'trap') throw lost('upload', "la suppression d'un ancien script", err, facts);
        throw new FactoryProvisioningError(
          'UPLOAD_REFUSED',
          'upload',
          `Un script d'une tentative précédente (${stale.name}) est sur le routeur et il refuse de le supprimer (${scrub(err)}). Rien n'a été modifié ; ${retry}.`,
          { routerMessage: scrub(err), facts },
        );
      }
    }
    const staleFileRemoved = staleFiles.length > 0;

    /**
     * Poll for every file and judge the sizes the router reports. A file
     * still being written grows, so `short` and `missing` get the remaining
     * attempts; `long` and `unreadable` are final at once.
     */
    type Verified =
      | { ok: true; sizeCheck: 'match' | 'rounded'; contentCheck: 'sha256' | 'size-only' }
      | { ok: false; detail: string };

    /**
     * Read every file back (`contents`) and compare its SHA-256 with what was
     * sent. RouterOS shows a file's contents only up to some size (not
     * observed which), so a read-back SHORTER than what was sent proves
     * nothing either way and leaves the size as the check; one of the full
     * length that differs, or a longer one, is a corrupted file.
     */
    const readBack = async (): Promise<Verified> => {
      let whole = true;
      for (const u of uploads) {
        let rows: Record<string, string>[];
        try {
          rows = await session.query(['/file/print', '=.proplist=name,contents', `?name=${u.path}`], { timeoutMs: requestMs });
        } catch (err) {
          if (errKind(err) !== 'trap') throw err;
          whole = false; // a build that will not show contents: the size is the check
          continue;
        }
        const contents = rows.find((r) => r.name === u.path)?.contents;
        if (typeof contents !== 'string') {
          whole = false;
          continue;
        }
        const len = Buffer.byteLength(contents, 'utf8');
        if (len === u.bytes) {
          if (sha256Hex(contents) !== sha256Hex(u.content)) {
            return { ok: false, detail: `le contenu relu de ${u.path} n'est pas celui qui a été envoyé (empreinte différente)` };
          }
          continue;
        }
        if (len > u.bytes) return { ok: false, detail: `le routeur montre pour ${u.path} plus d'octets que ceux envoyés` };
        whole = false;
      }
      return { ok: true, sizeCheck: 'match', contentCheck: whole ? 'sha256' : 'size-only' };
    };

    const verify = async (): Promise<Verified> => {
      const sized = await verifySizes();
      if (!sized.ok) return sized;
      const read = await readBack();
      return read.ok ? { ...read, sizeCheck: sized.sizeCheck } : read;
    };

    const verifySizes = async (): Promise<{ ok: true; sizeCheck: 'match' | 'rounded' } | { ok: false; detail: string }> => {
      let detail = "les fichiers ne sont pas apparus sur le routeur";
      for (let attempt = 0; attempt < 5; attempt++) {
        if (attempt > 0) await sleep(300);
        const rows = await listFiles(session, requestMs);
        let pending = false;
        let rounded = false;
        for (const u of uploads) {
          const row = rows.find((f) => f.name === u.path);
          if (!row) {
            pending = true;
            detail = `le fichier ${u.path} n'est pas apparu sur le routeur`;
            continue;
          }
          placed.add(u.path);
          const verdict = judgeReportedSize(row.size, u.bytes);
          if (verdict === 'match') continue;
          if (verdict === 'rounded') {
            rounded = true;
            continue;
          }
          const shown = scrub(row.size ?? '').slice(0, 24);
          if (verdict === 'unreadable') {
            return {
              ok: false,
              detail: `le routeur indique pour ${u.path} une taille illisible (« ${shown} ») : impossible de vérifier que le fichier est intact`,
            };
          }
          detail = `le routeur indique ${shown} pour ${u.path} au lieu de ${u.bytes} octets`;
          if (verdict === 'long') return { ok: false, detail };
          pending = true;
        }
        if (!pending) return { ok: true, sizeCheck: rounded ? 'rounded' : 'match' };
      }
      return { ok: false, detail };
    };

    /** `verify()`, with a refusal to read the file list turned into a refusal. */
    const verified = async (via: string) => {
      try {
        return await verify();
      } catch (err) {
        if (errKind(err) !== 'trap') throw lost('upload', 'la vérification du script', err, facts);
        throw new FactoryProvisioningError(
          'UPLOAD_REFUSED',
          'upload',
          `Le script a été déposé (${via}) mais le routeur refuse d'en montrer la taille (${scrub(err)}). Il a été retiré et rien n'a été modifié ; ${retry}.`,
          { routerMessage: scrub(err), facts },
        );
      }
    };

    let method: 'file-add' | 'sftp' | null = null;
    let sizeCheck: 'match' | 'rounded' = 'match';
    let contentCheck: 'sha256' | 'size-only' = 'size-only';
    let fileAddRefusal: string | null = null;

    if (router.majorVersion === 6) {
      fileAddRefusal = `RouterOS ${router.version} n'a pas de commande /file/add`;
    } else {
      // RouterOS 7, or a version that did not parse: asking costs one trap.
      // Each path joins `placed` BEFORE its call: a timeout half-way through
      // may leave a partial file holding the rendered secrets, and the
      // clean-up below only removes what it was told might exist.
      let accepted = true;
      for (const u of uploads) {
        placed.add(u.path);
        try {
          await session.query(['/file/add', `=name=${u.path}`, `=contents=${u.content}`], { timeoutMs: requestMs });
        } catch (err) {
          if (errKind(err) !== 'trap') throw lost('upload', 'le dépôt du script', err, facts);
          fileAddRefusal = `/file/add refusé : ${scrub(err)}`;
          accepted = false;
          break;
        }
      }
      if (accepted) {
        const v = await verified('/file/add');
        if (v.ok) {
          method = 'file-add';
          sizeCheck = v.sizeCheck;
          contentCheck = v.contentCheck;
        } else {
          // A cut file is worse than none: the box would reset into it. It is
          // NOT used: SFTP overwrites it below, or the clean-up removes it
          // with the refusal (`placed` holds it for exactly that).
          fileAddRefusal = `/file/add accepté mais ${v.detail}`;
        }
      }
    }

    if (method === null) {
      if (!deps.sftpUpload) {
        const remedy =
          router.majorVersion === 6
            ? 'Mettez le routeur à jour en RouterOS 7'
            : 'Préparez ce routeur à la main ou mettez à jour son RouterOS';
        throw new FactoryProvisioningError(
          'SFTP_UNAVAILABLE',
          'upload',
          `Impossible de déposer le script sur ce routeur (RouterOS ${router.version ?? 'de version inconnue'}) : ${fileAddRefusal}, et aucun dépôt par SFTP n'est disponible ici. Rien n'a été modifié. ${remedy}, puis ${retry}.`,
          { facts },
        );
      }
      for (const u of uploads) {
        placed.add(u.path); // a partial upload may exist; the catch-all below removes it
        try {
          await deps.sftpUpload({
            host: req.host,
            port: sshPort,
            username: req.username,
            password,
            remotePath: u.path,
            content: Buffer.from(u.content, 'utf8'),
            timeoutMs: requestMs,
            ...(ctx.localAddress ? { localAddress: ctx.localAddress } : {}),
          });
        } catch (err) {
          throw new FactoryProvisioningError(
            'UPLOAD_REFUSED',
            'upload',
            `Le dépôt du script par SFTP a échoué (${scrub(err)}). Rien n'a été modifié ; ${retry}.`,
            { routerMessage: scrub(err), facts },
          );
        }
      }
      const v = await verified('SFTP');
      if (!v.ok) {
        throw new FactoryProvisioningError(
          'UPLOAD_REFUSED',
          'upload',
          `Le script déposé par SFTP n'a pas pu être vérifié : ${v.detail}. Il a été retiré et rien n'a été modifié ; ${retry}.`,
          { facts },
        );
      }
      method = 'sftp';
      sizeCheck = v.sizeCheck;
      contentCheck = v.contentCheck;
    }

    // ---- reset -----------------------------------------------------------------

    stage = 'reset';
    ctx.progress('resetting');
    const runAfterReset = runnerPath;
    let outcome: ResetOutcome;
    try {
      await session.query(
        [
          '/system/reset-configuration',
          '=no-defaults=yes',
          '=skip-backup=yes',
          `=run-after-reset=${runAfterReset}`,
        ],
        { timeoutMs: resetMs },
      );
      outcome = 'acknowledged';
    } catch (err) {
      const kind = errKind(err);
      if (kind === 'trap') {
        throw new FactoryProvisioningError(
          'RESET_REFUSED',
          'reset',
          `Le routeur a refusé la réinitialisation (${scrub(err)}). Les fichiers déposés ont été retirés et rien n'a été modifié ; ${retry}.`,
          { routerMessage: scrub(err), facts },
        );
      }
      // A reboot ends the session without a goodbye: either the socket dies
      // (closed / fatal / a raw ECONNRESET) or nothing comes back at all.
      outcome = kind === 'timeout' ? 'no-answer' : 'session-dropped';
    }
    placed.clear();

    return {
      ...identity,
      upload: {
        method, path: runnerPath, bodyPath, paths: uploads.map((u) => u.path), bytes, sizeCheck, contentCheck,
        fileAddRefusal, staleFileRemoved, staleFiles,
      },
      reset: { outcome, runAfterReset },
      markers: compiled ? null : provisioningMarkers(req.tag),
      sim: simRead.sim,
      simRead: { outcome: simRead.outcome, attempts: simRead.attempts, waitedMs: simRead.waitedMs },
    };
  } catch (err) {
    if (placed.size > 0) {
      try {
        const rows = await listFiles(session, requestMs);
        for (const p of placed) {
          const row = rows.find((f) => f.name === p);
          if (row) await removeFile(session, row, requestMs);
        }
      } catch {
        /* best effort: the refusal below is what the preparer must see */
      }
    }
    if (err instanceof FactoryProvisioningError) throw err;
    throw lost(stage, 'la préparation', err);
  } finally {
    try {
      session.close();
    } catch {
      /* already gone — after a reset that is the normal case */
    }
  }
}
