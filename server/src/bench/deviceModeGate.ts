import type { DeviceModeReadout } from './routerosApply';

/**
 * ObliWAN bench — can the compiled configuration run on THIS box at all?
 *
 * ┌─ WHY THE BENCH ASKS BEFORE IT RESETS ────────────────────────────────────┐
 * │ RouterOS 7.13+ has a device-mode: features the box refuses until someone │
 * │ with physical access confirms a change (a press on the reset or mode     │
 * │ button, or a power cycle, within the activation window — 5 min by        │
 * │ default). A run-after-reset file that enables RoMON on a box whose       │
 * │ device-mode denies `romon` is a box that resets, stops at that line, and │
 * │ leaves the bench with half its configuration. Finding it out at the      │
 * │ bench costs one button press; finding it out after the reset costs a     │
 * │ trip back to the box.                                                    │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE SAME ASYMMETRY AS shared/src/deviceMode.ts ─────────────────────────┐
 * │ A DENIAL may be inferred from the mode: each mode denies, by MikroTik's  │
 * │ own documentation, the features in `MODE_DENIED`, so `home` with the     │
 * │ `romon` flag not printed is `blocked`. An ALLOWANCE is never inferred: a │
 * │ flag printed `no` is `blocked` whatever the mode, a flag printed `yes`   │
 * │ is `allowed`, and anything else is `unknown`. `unknown` does not stop    │
 * │ the bench: a box before 7.13 has no device-mode menu at all and gates    │
 * │ nothing, and the bench cannot tell it from a refused read.               │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ SOURCE, AND WHAT CHANGED WHEN IT WAS RE-READ ───────────────────────────┐
 * │ `MODE_DENIED` and the menu table below were re-read from                 │
 * │ MikroTik's device-mode page (`DEVICE_MODE_DOCUMENTATION`). Its feature   │
 * │ table marks `l2tp`, `pptp`, `ipsec` and `smb` allowed in EVERY mode, and │
 * │ lists `home` as denying exactly: scheduler, socks, fetch, bandwidth-test, │
 * │ traffic-gen, sniffer, romon, proxy, hotspot, email, zerotier, container, │
 * │ install-any-version, partitions, routerboard. The list this file carried │
 * │ before also denied l2tp, pptp, ipsec and smb in `home`; it stopped every │
 * │ home-mode box at the search for an L2TP denial the current page does not │
 * │ document. A box whose flag is PRINTED `no` is still blocked: the printed │
 * │ flag outranks any table, which is what keeps an older firmware that did  │
 * │ deny L2TP in `home` from being waved through.                            │
 * │ The page also narrows two features: `routerboard` gates                 │
 * │ `/system routerboard settings` EXCEPT its `auto-upgrade` property (and   │
 * │ not `/system routerboard mode-button`, which it does not mention), and   │
 * │ the table rows name a menu, not the act of switching it off.             │
 * │ REASONED, NOT OBSERVED: no box has been driven against this table. In   │
 * │ particular, that a line which only turns a gated feature OFF            │
 * │ (`/tool romon set enabled=no`, `/ip proxy set enabled=no`) runs under a  │
 * │ denying mode is inferred, not seen; the post-apply check (the box comes │
 * │ back under its new name) is what would show a body that stopped early.  │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

/** Where the table below was read. */
export const DEVICE_MODE_DOCUMENTATION = 'https://help.mikrotik.com/docs/spaces/ROS/pages/93749258/Device-mode';

/** What each documented mode denies by default (MikroTik documentation, see the header). */
export const MODE_DENIED: Readonly<Record<string, readonly string[]>> = {
  home: [
    'scheduler', 'socks', 'fetch', 'bandwidth-test', 'traffic-gen', 'sniffer', 'romon', 'proxy', 'hotspot',
    'email', 'zerotier', 'container', 'install-any-version', 'partitions', 'routerboard',
  ],
  basic: [
    'bandwidth-test', 'container', 'hotspot', 'install-any-version', 'partitions', 'proxy', 'routerboard',
    'socks', 'traffic-gen', 'zerotier',
  ],
  advanced: ['traffic-gen', 'container', 'partitions', 'install-any-version', 'routerboard'],
  rose: ['traffic-gen', 'partitions', 'install-any-version', 'routerboard'],
  // `enterprise` is the earlier name of `advanced` (same page). Nothing is
  // inferred from it: the builds that print it predate the table above.
};

/** `home`'s list, kept under its old name for the callers that read it. */
export const HOME_DENIED: readonly string[] = MODE_DENIED.home;

/**
 * What every provisioning needs whatever the template says:
 *  - `l2tp`: the tunnel to the concentrator, opened by every compiled file;
 *  - `scheduler`: ObliWAN's dead-man (`/system scheduler … start-time=startup`,
 *    shared/src/deviceMode.ts) is how every later guarded push on this box
 *    rolls itself back. A box that leaves the bench without it can never take
 *    such a push, and allowing it later needs somebody at the box again.
 */
export const ALWAYS_NEEDED: readonly string[] = ['l2tp', 'scheduler'];

/** French, for the clerk. Unknown names fall back to the RouterOS name. */
const FEATURE_LABELS: Readonly<Record<string, string>> = {
  l2tp: 'le tunnel L2TP vers ObliWAN',
  pptp: 'les tunnels PPTP',
  scheduler: 'le planificateur de tâches',
  fetch: 'les téléchargements (fetch)',
  romon: 'RoMON',
  routerboard: 'les réglages RouterBOARD',
  ipsec: 'IPsec',
  socks: 'le proxy SOCKS',
  proxy: 'le proxy web',
  hotspot: 'le hotspot',
  smb: 'le partage SMB',
  email: "l'envoi d'e-mails",
  sniffer: 'la capture de paquets',
  zerotier: 'ZeroTier',
  container: 'les conteneurs',
  'bandwidth-test': 'le test de débit',
  'traffic-gen': 'le générateur de trafic',
  partitions: 'les partitions',
  'install-any-version': "l'installation d'une version plus ancienne",
};

export function featureLabel(feature: string): string {
  return FEATURE_LABELS[feature] ?? feature;
}

export type FeatureVerdict = 'allowed' | 'blocked' | 'unknown';

export function featureVerdict(dm: DeviceModeReadout, feature: string): FeatureVerdict {
  if (!dm.answered) return 'unknown';
  const printed = dm.flags[feature];
  if (printed === true) return 'allowed';
  if (printed === false) return 'blocked';
  const denied = dm.mode ? MODE_DENIED[dm.mode] : undefined;
  if (denied && denied.includes(feature)) return 'blocked';
  return 'unknown';
}

// ============================================================================
// Which device-mode features a RouterOS script uses
// ============================================================================

/** Words that end a menu path in a RouterOS command line. */
const VERBS: ReadonlySet<string> = new Set([
  'add', 'set', 'unset', 'remove', 'enable', 'disable', 'print', 'find', 'get', 'export', 'edit',
  'move', 'comment', 'reset', 'reset-counters', 'monitor', 'send', 'start', 'stop', 'save', 'update',
]);

/** Verbs that read or switch something off: they never need the feature. */
const PASSIVE_VERBS: ReadonlySet<string> = new Set(['remove', 'disable', 'print', 'find', 'get', 'export', 'monitor', 'stop']);

interface Command {
  /** Menu words, lower-cased, `/a/b` and `/a b` alike. */
  menu: string;
  /** The verb, or '' for a command that is the menu itself (`/tool fetch url=…`). */
  verb: string;
  /** `key=value` arguments, key lower-cased, values unquoted. */
  args: Map<string, string>;
}

/** `key=value` / `key="value with spaces"` pairs of a command line. */
function parseArgs(text: string): Map<string, string> {
  const args = new Map<string, string>();
  const pair = /([A-Za-z0-9.-]+)=("(?:[^"\\]|\\.)*"|[^\s"]*)/g;
  for (let m = pair.exec(text); m !== null; m = pair.exec(text)) {
    const v = m[2].startsWith('"') ? m[2].slice(1, -1) : m[2];
    args.set(m[1].toLowerCase(), v);
  }
  return args;
}

/** Splits `/a b c verb args` (or `/a/b/c/verb args`) at its verb. */
function splitCommand(path: string, rest: string): { menu: string; verb: string; tail: string } {
  const words = `${path.replace(/\//g, ' ')} ${rest}`.trim().split(/\s+/);
  const menu: string[] = [];
  let i = 0;
  for (; i < words.length; i++) {
    const w = words[i];
    if (w.includes('=') || w.startsWith('[') || w.startsWith('"') || w.startsWith(':') || w.startsWith('{')) break;
    if (VERBS.has(w.toLowerCase())) {
      return { menu: menu.join(' ').toLowerCase(), verb: w.toLowerCase(), tail: words.slice(i + 1).join(' ') };
    }
    menu.push(w);
  }
  return { menu: menu.join(' ').toLowerCase(), verb: '', tail: words.slice(i).join(' ') };
}

/**
 * Every command of a script, with the menu a bare `add …` line inherits from
 * the last `/menu` line (export style). Comment lines are dropped, `\`
 * continuations joined, and a command nested in `:do { … }` or `[ … ]` is
 * found by its leading `/`.
 */
function commandsOf(text: string): Command[] {
  const lines = text.replace(/\r\n?/g, '\n').replace(/\\\n\s*/g, '').split('\n');
  const out: Command[] = [];
  let current = '';
  for (const raw of lines) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) continue;
    // A line that IS a menu (export style): `/ip proxy`, or `/ip proxy set …`.
    const lead = /^\/([A-Za-z0-9/ -]+?)(?:\s+(.*))?$/.exec(line);
    if (lead) {
      const c = splitCommand(lead[1], lead[2] ?? '');
      if (c.verb === '' && c.tail === '') {
        current = c.menu;
        continue;
      }
      out.push({ menu: c.menu, verb: c.verb, args: parseArgs(c.tail) });
      continue;
    }
    // A bare verb line inherits the current menu.
    const bare = /^([a-z-]+)(?:\s+(.*))?$/.exec(line);
    if (bare && VERBS.has(bare[1]) && current) {
      out.push({ menu: current, verb: bare[1], args: parseArgs(bare[2] ?? '') });
      continue;
    }
    // Commands nested anywhere else (`:do { /tool romon set enabled=yes }`).
    const nested = /(?:^|[{\[;\s])\/([a-z][a-z0-9 /-]*?)(?=\s+[a-z-]+[=\s\]}]|\s*[\]};]|$)([^\]};]*)/g;
    for (let m = nested.exec(line); m !== null; m = nested.exec(line)) {
      const c = splitCommand(m[1], m[2] ?? '');
      out.push({ menu: c.menu, verb: c.verb, args: parseArgs(c.tail) });
    }
  }
  return out;
}

const turnsOn = (args: Map<string, string>): boolean =>
  args.get('enabled') === 'yes' || args.get('disabled') === 'no';
const turnsOff = (args: Map<string, string>): boolean =>
  args.get('enabled') === 'no' || args.get('disabled') === 'yes';

/**
 * "Does this command use the feature?" — the general rule, for a menu the
 * feature gates: an `add` or an `enable` does; a read (`print`, `find`…), a
 * `remove` or a `disable` does not; a `set` does unless it only switches the
 * feature off. A menu that IS a command (`/tool fetch url=…`) does.
 */
function usesMenu(c: Command): boolean {
  if (PASSIVE_VERBS.has(c.verb)) return false;
  if (c.verb === 'set' || c.verb === 'unset' || c.verb === 'edit') return !turnsOff(c.args) || turnsOn(c.args);
  return true;
}

const menuIs = (...menus: string[]) => (c: Command) => menus.some((m) => c.menu === m || c.menu.startsWith(`${m} `));

/** Feature → the commands that use it. The corrections the header names are
 *  `scheduler`, `romon`, `routerboard` and `fetch`. */
const FEATURE_RULES: ReadonlyArray<{ feature: string; uses: (c: Command) => boolean }> = [
  { feature: 'l2tp', uses: (c) => menuIs('interface l2tp-client', 'interface l2tp-server')(c) && usesMenu(c) },
  { feature: 'pptp', uses: (c) => menuIs('interface pptp-client', 'interface pptp-server')(c) && usesMenu(c) },
  // A scheduler entry is created by `add`; reading or removing one is not.
  { feature: 'scheduler', uses: (c) => menuIs('system scheduler')(c) && c.verb === 'add' },
  // A command: used when it is RUN, wherever the line puts it.
  { feature: 'fetch', uses: (c) => c.menu === 'tool fetch' && !PASSIVE_VERBS.has(c.verb) },
  // Only switching RoMON ON (task decision, see the header).
  { feature: 'romon', uses: (c) => c.menu === 'tool romon' && (c.verb === 'set' || c.verb === 'enable') && (c.verb === 'enable' || c.args.get('enabled') === 'yes') },
  // `/system routerboard settings` except `auto-upgrade`; never `mode-button`.
  {
    feature: 'routerboard',
    uses: (c) => c.menu === 'system routerboard settings' && (c.verb === 'set' || c.verb === 'unset')
      && Array.from(c.args.keys()).some((k) => k !== 'auto-upgrade' && k !== 'numbers'),
  },
  { feature: 'ipsec', uses: (c) => menuIs('ip ipsec')(c) && usesMenu(c) },
  { feature: 'socks', uses: (c) => menuIs('ip socks')(c) && usesMenu(c) },
  { feature: 'proxy', uses: (c) => menuIs('ip proxy')(c) && usesMenu(c) },
  { feature: 'hotspot', uses: (c) => menuIs('ip hotspot')(c) && usesMenu(c) },
  { feature: 'smb', uses: (c) => menuIs('ip smb')(c) && usesMenu(c) },
  { feature: 'email', uses: (c) => menuIs('tool e-mail')(c) && usesMenu(c) },
  { feature: 'sniffer', uses: (c) => menuIs('tool sniffer')(c) && usesMenu(c) },
  { feature: 'zerotier', uses: (c) => menuIs('zerotier')(c) && usesMenu(c) },
  { feature: 'container', uses: (c) => menuIs('container')(c) && usesMenu(c) },
  { feature: 'bandwidth-test', uses: (c) => menuIs('tool bandwidth-server', 'tool bandwidth-test', 'tool speed-test')(c) && usesMenu(c) },
  { feature: 'traffic-gen', uses: (c) => menuIs('tool traffic-generator', 'tool flood-ping', 'tool ping-speed')(c) && usesMenu(c) },
  { feature: 'partitions', uses: (c) => menuIs('partitions')(c) && usesMenu(c) },
];

/** The device-mode features a script uses, in table order. */
export function featuresUsedBy(content: string): string[] {
  const cmds = commandsOf(content);
  return FEATURE_RULES.filter((r) => cmds.some(r.uses)).map((r) => r.feature);
}

export function blockedFeatures(dm: DeviceModeReadout, features: readonly string[]): string[] {
  return Array.from(new Set(features)).filter((f) => featureVerdict(dm, f) === 'blocked');
}

/** The French list `a, b et c`. */
export function featureList(features: readonly string[]): string {
  const names = features.map(featureLabel);
  return names.length > 1 ? `${names.slice(0, -1).join(', ')} et ${names[names.length - 1]}` : (names[0] ?? '');
}

/** The one-line explanation the wizard opens with. */
export function deviceModeExplanation(blocked: readonly string[], dm: DeviceModeReadout): string {
  return (
    `Ce routeur bloque ${featureList(blocked)} (mode « ${dm.mode ?? 'inconnu'} »), dont sa configuration a besoin. `
    + 'Rien n\'a été modifié : il faut l\'autoriser sur le routeur lui-même, avec un appui sur son bouton.'
  );
}
