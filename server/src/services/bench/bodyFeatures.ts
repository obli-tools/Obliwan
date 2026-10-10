// ============================================================================
// ObliWAN — bench: what a rendered body NEEDS from the box's device-mode
// ============================================================================
//
// Pure: no database, no I/O. Three things live here because the plan, the
// compile and the split file (`splitFile.ts`) must read a body the same way:
//
//   1. `splitUnits` — a rendered RouterOS body cut into top-level STATEMENTS,
//      each with the menu path in effect before it. A statement spans every
//      physical line it needs: a `\` continuation, a `{ … }` / `[ … ]` /
//      `( … )` opened and not yet closed, a quoted string not yet closed. The
//      split file never cuts a body anywhere else.
//   2. `deviceModeFeaturesOf` — the RouterOS 7 device-mode features the
//      statements USE when they run (the table below).
//   3. the box's device-mode reading as the bench sends it, and the one
//      judgement made on it (`featureVerdict`), with the asymmetry of
//      shared/src/deviceMode.ts.
//
// ┌─ THE TABLE, AND WHERE IT COMES FROM ──────────────────────────────────────┐
// │ MikroTik, RouterOS documentation, "Device-mode" (help.mikrotik.com/docs/ │
// │ spaces/ROS/pages/93749258/Device-mode):                                  │
// │  - modes: home, basic, advanced ("Advanced (previously called           │
// │    enterprise)"), ROSE; `advanced` is the default;                       │
// │  - HOME denies: bandwidth-test, container, email, fetch, hotspot,       │
// │    install-any-version, partitions, proxy, romon, routerboard,          │
// │    scheduler, sniffer, socks, traffic-gen, zerotier. HOME ALLOWS ipsec, │
// │    l2tp, pptp and smb: an older list (the one the bench application     │
// │    carried in bench/deviceModeGate.ts) denied them, the page does not;  │
// │  - `routerboard` gates "/system routerboard settings (except            │
// │    auto-upgrade option)": `/system routerboard mode-button` is another  │
// │    menu and is not gated, nor is `auto-upgrade`.                        │
// │ Only what a statement EXECUTES counts: a command inside a quoted string │
// │ (a netwatch or scheduler script source) does not run during the         │
// │ provisioning, and `/tool romon set enabled=no` asks for nothing. The    │
// │ matching is a heuristic over text, not a RouterOS parser: a command      │
// │ built at run time (`[:parse …]`, `$x`) is not seen.                      │
// └──────────────────────────────────────────────────────────────────────────┘

import { asRouterOsDeviceMode } from '@obliwan/shared';
import { BenchApiError } from './benchApiError';

// ============================================================================
// 1. Statements
// ============================================================================

export type BodyUnitKind = 'blank' | 'comment' | 'path' | 'declaration' | 'command';

export interface BodyUnit {
  /** The physical lines, verbatim. */
  lines: string[];
  kind: BodyUnitKind;
  /** The path line in effect BEFORE this statement, trimmed, or null at the root. */
  menuLine: string | null;
  /** A command written relative to `menuLine` (`add …`, `set …`). */
  relative: boolean;
  /** The device-mode features this statement uses when it runs, sorted. */
  features: string[];
}

/** The SHAPE of a line that only changes the menu (`/ip address`,
 *  `/system/scheduler`). The shape alone cannot tell a menu from an absolute
 *  command given no argument (`/system reboot`, `/ip dns cache flush`,
 *  `/system script run bootstrap`): `isMenuLine` also requires that no word of
 *  it be a command. */
const PATH_LINE_RE = /^\/[A-Za-z0-9_\- /]*$/;
const DECLARATION_RE = /^:(local|global|set)(\s|$)/;
/** Words that end a menu path: the verbs `readCommand` knows (below), and
 *  commands of their own that a template could write with no argument. A
 *  menu word missing from this list is harmless; a COMMAND missing from it
 *  is taken for a menu — still a heuristic over text, not a RouterOS parser. */
const MENU_ENDING_WORDS: ReadonlySet<string> = new Set([
  'add', 'set', 'remove', 'print', 'enable', 'disable', 'start', 'stop', 'find', 'get', 'edit', 'export',
  'reset', 'send', 'quick', 'move', 'unset', 'upgrade', 'monitor', 'setup', 'release', 'renew', 'comment',
  'run', 'flush', 'reboot', 'shutdown', 'save', 'load', 'sign', 'import', 'reset-configuration', 'check-for-updates',
  'download', 'install', 'cancel', 'clear', 'ping', 'blink', 'reset-counters', 'reset-counters-all', 'make-static',
  'execute', 'beep', 'delay', 'quit', 'put', 'apply-changes', 'check-installation', 'downgrade', 'uninstall',
]);

/** A line that only changes the menu: the shape, and no command word. */
export function isMenuLine(line: string): boolean {
  const t = line.trim();
  if (!PATH_LINE_RE.test(t)) return false;
  return !t.replace(/^\//, '').split(/[/ ]+/).some((w) => MENU_ENDING_WORDS.has(w));
}

/**
 * Cut `lines` into top-level statements. A statement left open at the end
 * (an unbalanced brace, an unterminated string) takes every remaining line:
 * on the box it fails to parse, and the split file confines that failure to
 * the section holding it. A `#` line is a comment only at the start of a
 * statement or inside one; braces in it are not counted.
 */
export function splitUnits(lines: string[]): BodyUnit[] {
  const out: BodyUnit[] = [];
  let menuLine: string | null = null;
  let cur: string[] | null = null;
  let depth = 0;
  let inQuote = false;

  const push = (unitLines: string[], kind: BodyUnitKind, relative: boolean): void => {
    const unit: BodyUnit = { lines: unitLines, kind, menuLine, relative, features: [] };
    unit.features = kind === 'command' || kind === 'declaration' || kind === 'path' ? featuresOfUnit(unit) : [];
    out.push(unit);
    if (kind === 'path') menuLine = unitLines[0].trim();
  };
  const close = (): void => {
    const unitLines = cur as string[];
    cur = null;
    const first = unitLines[0].trim();
    if (unitLines.length === 1 && isMenuLine(first)) push(unitLines, 'path', false);
    else if (DECLARATION_RE.test(first)) push(unitLines, 'declaration', false);
    else push(unitLines, 'command', /^[a-z]/.test(first));
  };

  for (const raw of lines) {
    const t = raw.trim();
    if (cur === null) {
      if (t === '') { push([raw], 'blank', false); continue; }
      if (t.startsWith('#')) { push([raw], 'comment', false); continue; }
      cur = [];
      depth = 0;
      inQuote = false;
    }
    cur.push(raw);
    if (!inQuote && t.startsWith('#')) continue;
    let escaped = false;
    for (let i = 0; i < raw.length; i++) {
      const ch = raw[i];
      if (inQuote) {
        if (escaped) { escaped = false; continue; }
        if (ch === '\\') { escaped = true; continue; }
        if (ch === '"') inQuote = false;
        continue;
      }
      if (ch === '"') inQuote = true;
      else if (ch === '{' || ch === '[' || ch === '(') depth += 1;
      else if (ch === '}' || ch === ']' || ch === ')') depth = Math.max(0, depth - 1);
    }
    const continued = /\\\s*$/.test(raw) || depth > 0 || inQuote;
    if (!continued) close();
  }
  if (cur !== null) close();
  return out;
}

// ============================================================================
// 2. Commands and features
// ============================================================================

export interface BodyCommand {
  /** Menu words joined by one space: `system scheduler`, `tool fetch`. */
  path: string;
  verb: string | null;
  /** `key=value` arguments at the command's own level, quotes emptied. */
  args: Record<string, string>;
}

const VERBS: ReadonlySet<string> = new Set([
  'add', 'set', 'remove', 'print', 'enable', 'disable', 'start', 'stop', 'find', 'get', 'edit', 'export',
  'reset', 'send', 'quick', 'move', 'unset', 'upgrade', 'monitor', 'setup', 'release', 'renew', 'comment',
]);
const PLAIN_WORD_RE = /^[a-z][a-z0-9-]*$/;
const ARG_RE = /^([A-Za-z0-9][A-Za-z0-9.-]*)=(.*)$/;

/** Quoted strings emptied, continuations joined, comment lines dropped. */
function executableText(unit: BodyUnit): string {
  const text = unit.lines.filter((l) => !l.trim().startsWith('#')).join('\n').replace(/\\[ \t]*\n/g, ' ');
  let out = '';
  let inQuote = false;
  let escaped = false;
  for (const ch of text) {
    if (inQuote) {
      if (escaped) { escaped = false; continue; }
      if (ch === '\\') { escaped = true; continue; }
      if (ch === '"') { inQuote = false; out += '"'; }
      continue;
    }
    if (ch === '"') inQuote = true;
    out += ch;
  }
  return out;
}

function tokens(text: string): string[] {
  return text.replace(/([[\]{}();\n])/g, ' $1 ').split(/[ \t]+/).filter((t) => t !== '');
}

function readCommand(toks: string[], start: number, base: string[], verbFromPath: string | null): BodyCommand {
  const words = [...base];
  let verb = verbFromPath;
  let j = start;
  while (verb === null && j < toks.length && PLAIN_WORD_RE.test(toks[j])) {
    if (VERBS.has(toks[j])) { verb = toks[j]; j += 1; break; }
    words.push(toks[j]);
    j += 1;
  }
  const args: Record<string, string> = {};
  let depth = 0;
  for (; j < toks.length; j++) {
    const t = toks[j];
    if (t === '[' || t === '{' || t === '(') { depth += 1; continue; }
    if (t === ']' || t === '}' || t === ')') { if (depth === 0) break; depth -= 1; continue; }
    if (t === ';' || t === '\n') { if (depth === 0) break; continue; }
    if (depth > 0) continue;
    const m = ARG_RE.exec(t);
    if (m) args[m[1].toLowerCase()] = m[2].replace(/^"|"$/g, '');
  }
  return { path: words.join(' '), verb, args };
}

function pathWords(pathText: string): string[] {
  return pathText.replace(/^\//, '').split(/[/ ]+/).filter((w) => w !== '');
}

/** Every command a statement runs: the relative one it starts with, and each
 *  absolute `/menu …` it contains (in `[ … ]`, after `;`, in a block). */
export function commandsOf(unit: BodyUnit): BodyCommand[] {
  const toks = tokens(executableText(unit));
  const out: BodyCommand[] = [];
  if (unit.relative && unit.menuLine !== null) out.push(readCommand(toks, 0, pathWords(unit.menuLine), null));
  toks.forEach((t, i) => {
    if (!t.startsWith('/') || t.length < 2) return;
    const parts = pathWords(t);
    const last = parts[parts.length - 1];
    if (parts.length > 1 && VERBS.has(last)) out.push(readCommand(toks, i + 1, parts.slice(0, -1), last));
    else out.push(readCommand(toks, i + 1, parts, null));
  });
  return out;
}

const enabledYes = (c: BodyCommand): boolean => ['yes', 'true'].includes((c.args.enabled ?? '').toLowerCase());
const under = (c: BodyCommand, menu: string): boolean => c.path === menu || c.path.startsWith(`${menu} `);
const verbIn = (c: BodyCommand, ...verbs: string[]): boolean => c.verb !== null && verbs.includes(c.verb);
/** A service switched on (`set enabled=yes`), or an entry added under it. */
const serviceOn = (c: BodyCommand, menu: string): boolean =>
  (c.path === menu && c.verb === 'set' && enabledYes(c)) || (c.path.startsWith(`${menu} `) && c.verb === 'add');

/** feature -> does this command use it. Feature names are RouterOS's own
 *  `/system/device-mode` property names. `install-any-version` concerns a
 *  downgrade, never a configuration line, and has no entry. */
const FEATURE_RULES: ReadonlyArray<{ feature: string; uses: (c: BodyCommand) => boolean }> = [
  { feature: 'scheduler', uses: (c) => c.path === 'system scheduler' && c.verb === 'add' },
  { feature: 'fetch', uses: (c) => c.path === 'tool fetch' },
  { feature: 'romon', uses: (c) => c.path === 'tool romon' && c.verb === 'set' && enabledYes(c) },
  {
    feature: 'routerboard',
    uses: (c) => c.path === 'system routerboard settings' && c.verb === 'set' && Object.keys(c.args).some((k) => k !== 'auto-upgrade'),
  },
  { feature: 'socks', uses: (c) => serviceOn(c, 'ip socks') },
  { feature: 'proxy', uses: (c) => serviceOn(c, 'ip proxy') },
  { feature: 'smb', uses: (c) => serviceOn(c, 'ip smb') },
  { feature: 'hotspot', uses: (c) => under(c, 'ip hotspot') && verbIn(c, 'add', 'setup') },
  {
    feature: 'bandwidth-test',
    uses: (c) => c.path === 'tool bandwidth-test' || (c.path === 'tool bandwidth-server' && c.verb === 'set' && enabledYes(c)),
  },
  { feature: 'traffic-gen', uses: (c) => under(c, 'tool traffic-generator') && verbIn(c, 'add', 'set', 'start', 'quick') },
  { feature: 'sniffer', uses: (c) => under(c, 'tool sniffer') && verbIn(c, 'start', 'quick') },
  { feature: 'email', uses: (c) => c.path === 'tool e-mail' && verbIn(c, 'send', 'set') },
  { feature: 'zerotier', uses: (c) => under(c, 'zerotier') && verbIn(c, 'add', 'enable') },
  { feature: 'container', uses: (c) => under(c, 'container') && verbIn(c, 'add', 'set', 'start') },
  { feature: 'ipsec', uses: (c) => c.path.startsWith('ip ipsec ') && verbIn(c, 'add', 'set', 'enable') },
  {
    feature: 'l2tp',
    uses: (c) => (c.path === 'interface l2tp-client' && verbIn(c, 'add', 'set', 'enable'))
      || (c.path === 'interface l2tp-server server' && c.verb === 'set' && enabledYes(c))
      || (c.path === 'interface l2tp-server' && c.verb === 'add'),
  },
  {
    feature: 'pptp',
    uses: (c) => (c.path === 'interface pptp-client' && verbIn(c, 'add', 'set', 'enable'))
      || (c.path === 'interface pptp-server server' && c.verb === 'set' && enabledYes(c))
      || (c.path === 'interface pptp-server' && c.verb === 'add'),
  },
  {
    feature: 'partitions',
    uses: (c) => under(c, 'partitions') && c.verb !== null && !['print', 'export', 'find', 'get', 'monitor'].includes(c.verb),
  },
];

function featuresOfUnit(unit: BodyUnit): string[] {
  const found = new Set<string>();
  for (const c of commandsOf(unit)) {
    for (const r of FEATURE_RULES) if (r.uses(c)) found.add(r.feature);
  }
  return [...found].sort();
}

/** The device-mode features a rendered text uses, sorted, once each. */
export function deviceModeFeaturesOf(text: string): string[] {
  const lines = text.replace(/\r\n?/g, '\n').split('\n');
  return [...new Set(splitUnits(lines).flatMap((u) => u.features))].sort();
}

/**
 * The same scan over a template's SOURCES (entry and partials), for when no
 * render can be made yet (the plan, before the bench values are typed).
 * Template tags are blanked, so both branches of an `{% if %}` count: it
 * over-approximates what the template's own text can produce — except a
 * command a variable's VALUE would inject, which only a render shows.
 */
export function deviceModeFeaturesOfSources(sources: Record<string, string>): string[] {
  const found = new Set<string>();
  for (const src of Object.values(sources)) {
    const text = src
      .replace(/\{#[\s\S]*?#\}/g, '')
      .replace(/\{%[\s\S]*?%\}/g, '')
      .replace(/\{\{[\s\S]*?\}\}/g, 'x');
    for (const f of deviceModeFeaturesOf(text)) found.add(f);
  }
  return [...found].sort();
}

/** French, for the bench operator. */
export const FEATURE_LABELS: Readonly<Record<string, string>> = {
  scheduler: 'le planificateur (scheduler)',
  fetch: 'les téléchargements (fetch)',
  romon: 'RoMON',
  routerboard: 'les réglages RouterBOARD (routerboard)',
  socks: 'le proxy SOCKS',
  proxy: 'le proxy web',
  smb: 'le partage SMB',
  hotspot: 'le hotspot',
  'bandwidth-test': 'le test de débit (bandwidth-test)',
  'traffic-gen': 'le générateur de trafic',
  sniffer: 'la capture de paquets (sniffer)',
  email: 'l’envoi d’e-mails',
  zerotier: 'ZeroTier',
  container: 'les conteneurs',
  ipsec: 'IPsec',
  l2tp: 'L2TP',
  pptp: 'PPTP',
  partitions: 'les partitions',
};

export function featureList(features: readonly string[]): string {
  const names = features.map((f) => FEATURE_LABELS[f] ?? f);
  return names.length > 1 ? `${names.slice(0, -1).join(', ')} et ${names[names.length - 1]}` : names[0] ?? '';
}

// ============================================================================
// 3. The box's reading, and the one judgement made on it
// ============================================================================

/** What `/system/device-mode/print` printed, as the bench read it. */
export interface BenchDeviceModeReading {
  /** Lower-cased as printed; null when the menu printed no mode (or did not answer). */
  mode: string | null;
  /** RouterOS flag name -> printed yes (true), printed no (false), not printed (null). */
  flags: Record<string, boolean | null>;
  /** When the bench PUT the question, ISO 8601. */
  observedAt: string;
}

/** What HOME denies, by MikroTik's current documentation (header). */
export const HOME_MODE_DENIED: ReadonlySet<string> = new Set([
  'bandwidth-test', 'container', 'email', 'fetch', 'hotspot', 'install-any-version', 'partitions',
  'proxy', 'romon', 'routerboard', 'scheduler', 'sniffer', 'socks', 'traffic-gen', 'zerotier',
]);

/** A bench clock a few minutes ahead is tolerated; further is a bad reading. */
const OBSERVED_SKEW_MS = 5 * 60_000;

/**
 * `box.deviceMode`, or null when the bench sent none (a bench built before
 * the field, or one that did not read the menu). Judged, never repaired: a
 * malformed block is a 400 naming the field.
 */
export function parseBenchDeviceMode(raw: unknown, now: Date = new Date()): BenchDeviceModeReading | null {
  if (raw === undefined || raw === null) return null;
  const bad = (field: string): never => {
    throw new BenchApiError(400, `Description du routeur invalide : le champ « box.deviceMode${field} » est illisible.`, 'bad_input');
  };
  if (typeof raw !== 'object' || Array.isArray(raw)) return bad('');
  const r = raw as Record<string, unknown>;
  let mode: string | null = null;
  if (r.mode !== undefined && r.mode !== null) {
    if (typeof r.mode !== 'string') return bad('.mode');
    const m = r.mode.trim().toLowerCase();
    if (m !== '' && !/^[a-z][a-z0-9-]{0,31}$/.test(m)) return bad('.mode');
    mode = m === '' ? null : m;
  }
  const flags: Record<string, boolean | null> = {};
  if (r.flags !== undefined && r.flags !== null) {
    if (typeof r.flags !== 'object' || Array.isArray(r.flags)) return bad('.flags');
    const entries = Object.entries(r.flags as Record<string, unknown>);
    if (entries.length > 64) return bad('.flags');
    for (const [k, v] of entries) {
      if (!/^[a-z][a-z0-9-]{0,39}$/.test(k)) return bad('.flags');
      if (v !== null && typeof v !== 'boolean') return bad(`.flags.${k}`);
      flags[k] = v;
    }
  }
  if (typeof r.observedAt !== 'string') return bad('.observedAt');
  const at = Date.parse(r.observedAt);
  if (!Number.isFinite(at) || at > now.getTime() + OBSERVED_SKEW_MS) return bad('.observedAt');
  return { mode, flags, observedAt: new Date(at).toISOString() };
}

export type FeatureVerdict = 'allowed' | 'blocked' | 'unknown';

/**
 * The asymmetry of shared/src/deviceMode.ts: a flag printed `no` is
 * `blocked` whatever the mode, a flag printed `yes` is `allowed`, and a flag
 * NOT printed is `blocked` only when the mode is `home` and MikroTik
 * documents home as denying it. Nothing is ever inferred as allowed, and no
 * other mode is used for an inference (shared characterises `home` only).
 * No reading at all is `unknown`: a box before 7.13 has no menu and gates
 * nothing, and the bench cannot tell it from a refused read.
 */
export function featureVerdict(reading: BenchDeviceModeReading | null, feature: string): FeatureVerdict {
  if (reading === null) return 'unknown';
  const printed = reading.flags[feature];
  if (printed === true) return 'allowed';
  if (printed === false) return 'blocked';
  if (reading.mode === 'home' && HOME_MODE_DENIED.has(feature)) return 'blocked';
  return 'unknown';
}

export function deniedFeatures(reading: BenchDeviceModeReading | null, features: readonly string[]): string[] {
  return [...new Set(features)].filter((f) => featureVerdict(reading, f) === 'blocked').sort();
}

/**
 * The five `devices.device_mode*` columns as ONE observation, by the rules
 * of `recordDeviceMode` (fleet/deviceBinding.service.ts): null when there is
 * no reading (nothing is written, an earlier reading stays); otherwise every
 * column moves together, an unanswered menu included (`observed_at` set, the
 * rest null). The mode is narrowed by `asRouterOsDeviceMode`, so a mode the
 * shared vocabulary does not know (anything beyond home, basic, advanced,
 * enterprise and rose) is stored null and kept in `device_mode_raw`. `device_mode_raw` is the bench's readout
 * re-spelled the way RouterOS prints it (`yes`/`no`; the bench sends booleans,
 * not the printed text), the flags it did not print left out.
 */
export function deviceModeColumns(reading: BenchDeviceModeReading | null): {
  device_mode: string | null;
  device_mode_scheduler: boolean | null;
  device_mode_fetch: boolean | null;
  device_mode_raw: string | null;
  device_mode_observed_at: string;
} | null {
  if (reading === null) return null;
  const printed = Object.entries(reading.flags).filter((e): e is [string, boolean] => e[1] !== null);
  const answered = reading.mode !== null || printed.length > 0;
  const raw: Record<string, string> = {};
  if (reading.mode !== null) raw.mode = reading.mode;
  for (const [k, v] of printed) raw[k] = v ? 'yes' : 'no';
  return {
    device_mode: asRouterOsDeviceMode(reading.mode),
    device_mode_scheduler: reading.flags.scheduler ?? null,
    device_mode_fetch: reading.flags.fetch ?? null,
    device_mode_raw: answered ? JSON.stringify(raw) : null,
    device_mode_observed_at: reading.observedAt,
  };
}
