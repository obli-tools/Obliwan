import { spawn, execFileSync, type ChildProcess } from 'node:child_process';
import { existsSync, mkdirSync, openSync, closeSync, readFileSync, writeFileSync, unlinkSync, appendFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

/**
 * ObliWAN bench — the desktop half: the window, the message box, one instance.
 *
 * ┌─ AN APPLICATION WINDOW, NOT A BROWSER TAB ───────────────────────────────┐
 * │ The UI is still served by a loopback HTTP server (127.0.0.1, a per-run    │
 * │ token), but it opens in Microsoft Edge's APP mode: `--app=<url>` gives a │
 * │ window with no address bar, no tabs and its own taskbar entry. A         │
 * │ dedicated `--user-data-dir` (%LOCALAPPDATA%\ObliWAN\bench-ui) makes that │
 * │ Edge a separate browser process from the one the preparer browses with,  │
 * │ so the process this module spawns IS the window, and its exit is the     │
 * │ window closing. Edge is found through the registry's App Paths, then the │
 * │ standard install folders.                                                │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ NO BROWSER FALLBACK — operator decision 2026-10-07 ─────────────────────┐
 * │ A tab of the default browser is NOT this application's window: no app    │
 * │ title in the taskbar, an address bar a preparer can wander off from, a   │
 * │ tab closed with the rest of a browsing session, and nothing like the     │
 * │ screenshots of the guide. It used to be the fallback when Edge was not   │
 * │ found or failed to start, and nothing logged why — so each "the bench   │
 * │ opened in Edge" report was undiagnosable. Now Edge is tried THREE times, │
 * │ 1.5 s apart (re-finding it each time: an Edge mid-update has its        │
 * │ msedge.exe briefly absent), every failed attempt goes to bench-error.log │
 * │ with its cause, and after the third the answer is `none`: the caller     │
 * │ says so in a message box and stops. Nothing here may ever spawn `cmd     │
 * │ start`, `open` or `xdg-open` again (benchApp.verify.ts checks it).       │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE PROCESS ENDS WITH THE WINDOW ───────────────────────────────────────┐
 * │ Two witnesses, because each can lie alone. The page holds an             │
 * │ EventSource open and also posts a heartbeat every 5 s: the stream closes │
 * │ the moment the window does, and is not subject to the timer throttling   │
 * │ a minimised window's heartbeats are. The Edge child's exit is the other: │
 * │ an exit after it ran for a while is the window closing; an exit within   │
 * │ seconds is Edge handing the URL to an Edge already running on the same  │
 * │ profile, and says nothing. `WindowWatch` exits ~15 s after the last sign │
 * │ of life, or 2 s after the Edge child exits with no stream open.          │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

// ============================================================================
// Where things live
// ============================================================================

/** %LOCALAPPDATA%\ObliWAN (machine-local, per user), or the nearest equivalent. */
export function localDataDir(env: NodeJS.ProcessEnv = process.env): string {
  const local = (env.LOCALAPPDATA ?? '').trim();
  if (local) return join(local, 'ObliWAN');
  if (process.platform === 'win32') return join(homedir(), 'AppData', 'Local', 'ObliWAN');
  const xdg = (env.XDG_STATE_HOME ?? '').trim();
  return join(xdg || join(homedir(), '.local', 'state'), 'ObliWAN');
}

export const ERROR_LOG = 'bench-error.log';

/** Appends to %LOCALAPPDATA%\ObliWAN\bench-error.log. Never throws. */
export function logError(text: string, env: NodeJS.ProcessEnv = process.env): string | null {
  try {
    const path = join(localDataDir(env), ERROR_LOG);
    mkdirSync(dirname(path), { recursive: true });
    appendFileSync(path, `[${new Date().toISOString()}] ${text}\n`, 'utf8');
    return path;
  } catch {
    return null;
  }
}

// ============================================================================
// The native message box — for failures before (or without) a window
// ============================================================================

function powershellExe(env: NodeJS.ProcessEnv = process.env): string {
  const root = (env.SystemRoot ?? env.windir ?? 'C:\\Windows').trim();
  return join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
}

/**
 * A Windows message box, from a process that has no console and may have no
 * window. PowerShell is started with `windowsHide` (CREATE_NO_WINDOW: no
 * console window flashes up) and stdin closed, and the text travels in
 * environment variables, never on the command line: no quoting, nothing a
 * message could inject. The box is owned by an invisible top-most form so it
 * is not buried under other windows. Resolves when the box is closed (or could
 * not be shown). Off Windows it writes to stderr.
 *
 * OBSERVED on Windows Server 2025 (PowerShell 5.1), each variant checked for a
 * visible `#32770` dialog: with `windowsHide` and stdin ignored, the box shows;
 * DETACHED, PowerShell exited within a second and showed nothing; with stdin
 * left as a pipe, it never got as far as the box.
 */
export function showMessageBox(title: string, text: string, kind: 'error' | 'info' = 'error'): Promise<void> {
  if (process.platform !== 'win32') {
    try {
      process.stderr.write(`\n${title}\n${text}\n`);
    } catch {
      /* nowhere to write */
    }
    return Promise.resolve();
  }
  const icon = kind === 'error' ? 'Error' : 'Information';
  const script =
    'Add-Type -AssemblyName System.Windows.Forms; '
    + '$f = New-Object System.Windows.Forms.Form; $f.TopMost = $true; $f.ShowInTaskbar = $false; '
    + '[void][System.Windows.Forms.MessageBox]::Show($f, $env:OBLIWAN_BENCH_MSG, $env:OBLIWAN_BENCH_TITLE, '
    + `[System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::${icon}); $f.Dispose()`;
  return new Promise((resolve) => {
    let child: ChildProcess;
    try {
      child = spawn(powershellExe(), ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], {
        windowsHide: true,
        stdio: 'ignore',
        env: { ...process.env, OBLIWAN_BENCH_MSG: text.slice(0, 4000), OBLIWAN_BENCH_TITLE: title.slice(0, 200) },
      });
    } catch {
      resolve();
      return;
    }
    child.once('error', () => resolve());
    child.once('exit', () => resolve());
  });
}

/**
 * Flash this application's window in the taskbar until it comes to the
 * foreground (`FlashWindowEx`, FLASHW_ALL | FLASHW_TIMERNOFG): a router card
 * needs the technician. Best effort and Windows only; never throws, never
 * waits. PowerShell finds every top-level window whose title contains
 * `titlePart` (the page's <title>; Edge's app window carries it) — the text
 * travels in an environment variable, as in `showMessageBox`, and the
 * script as -EncodedCommand (it holds double quotes, which a command line
 * would have to escape). The script was run on Windows Server 2025 against
 * a title no window carries (it loads and exits cleanly); the flash itself
 * on Edge's window is reasoned from the Win32 documentation, not observed.
 */
export const FLASH_SCRIPT =
  '$t = Add-Type -Name FlashW -Namespace ObliwanBench -PassThru -MemberDefinition @"\n'
  + '[StructLayout(LayoutKind.Sequential)] public struct FLASHWINFO { public uint cbSize; public System.IntPtr hwnd; public uint dwFlags; public uint uCount; public uint dwTimeout; }\n'
  + '[DllImport("user32.dll")] public static extern bool FlashWindowEx(ref FLASHWINFO pwfi);\n'
  + '"@\n'
  + 'Get-Process | Where-Object { $_.MainWindowHandle -ne 0 -and $_.MainWindowTitle -like (\'*\' + $env:OBLIWAN_BENCH_TITLE + \'*\') } | ForEach-Object {\n'
  + '  $i = New-Object ObliwanBench.FlashW+FLASHWINFO\n'
  + '  $i.cbSize = [System.Runtime.InteropServices.Marshal]::SizeOf($i); $i.hwnd = $_.MainWindowHandle; $i.dwFlags = 15; $i.uCount = 0; $i.dwTimeout = 0\n'
  + '  [void][ObliwanBench.FlashW]::FlashWindowEx([ref]$i)\n'
  + '}\n';

export function flashWindow(titlePart: string): void {
  if (process.platform !== 'win32') return;
  try {
    const encoded = Buffer.from(FLASH_SCRIPT, 'utf16le').toString('base64');
    const child = spawn(powershellExe(), ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded], {
      windowsHide: true,
      stdio: 'ignore',
      env: { ...process.env, OBLIWAN_BENCH_TITLE: titlePart.slice(0, 200) },
    });
    child.once('error', () => undefined);
    child.unref();
  } catch {
    /* nothing to flash with */
  }
}

// ============================================================================
// Edge, in app mode
// ============================================================================

const APP_PATHS = [
  'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe',
  'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe',
  'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe',
];

/** `reg query <key> /ve` — the key's default value, or null. */
function registryDefault(key: string): string | null {
  try {
    const out = execFileSync('reg', ['query', key, '/ve'], { encoding: 'utf8', windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'], timeout: 5_000 });
    const m = /REG_(?:EXPAND_)?SZ\s+(.+?)\s*$/m.exec(out);
    if (!m) return null;
    return m[1].replace(/^"|"$/g, '').replace(/%([^%]+)%/g, (_, name: string) => process.env[name] ?? `%${name}%`);
  } catch {
    return null;
  }
}

/** msedge.exe: the registry's App Paths first, then the standard folders. */
export function findEdge(env: NodeJS.ProcessEnv = process.env): string | null {
  if (process.platform !== 'win32') return null;
  for (const key of APP_PATHS) {
    const p = registryDefault(key);
    if (p && /msedge\.exe$/i.test(p) && existsSync(p)) return p;
  }
  const roots = [env['ProgramFiles(x86)'], env.ProgramFiles, env.ProgramW6432, env.LOCALAPPDATA]
    .filter((r): r is string => typeof r === 'string' && r.trim() !== '');
  for (const root of roots) {
    const p = join(root, 'Microsoft', 'Edge', 'Application', 'msedge.exe');
    if (existsSync(p)) return p;
  }
  return null;
}

/** `edge-app`: the application window is open. `none`: it could not be, and
 *  there is deliberately no third answer (see "NO BROWSER FALLBACK"). */
export type WindowMode = 'edge-app' | 'none';

export interface OpenedWindow {
  mode: WindowMode;
  /** The Edge process when `mode === 'edge-app'`. */
  child: ChildProcess | null;
  /** `edge-app`: the msedge.exe used. `none`: why, in French, for the preparer. */
  detail: string | null;
}

/** How many times Edge is tried, and how long apart. */
export const EDGE_ATTEMPTS = 3;
export const EDGE_RETRY_MS = 1_500;

/** The Edge command line: an app window on a profile of its own. */
export function edgeArguments(url: string, userDataDir: string): string[] {
  return [
    `--app=${url}`,
    `--user-data-dir=${userDataDir}`,
    '--window-size=1100,860',
    '--no-first-run',
    '--no-default-browser-check',
    // The page beeps when a router card needs the technician, possibly
    // before anybody clicked in this window.
    '--autoplay-policy=no-user-gesture-required',
  ];
}

type Spawned = { ok: true } | { ok: false; code: string };

function spawned(child: ChildProcess): Promise<Spawned> {
  return new Promise((resolve) => {
    child.once('spawn', () => resolve({ ok: true }));
    child.once('error', (err: NodeJS.ErrnoException) => resolve({ ok: false, code: err?.code ?? err?.message ?? 'erreur inconnue' }));
  });
}

export interface OpenWindowOptions {
  attempts?: number;
  retryMs?: number;
  sleep?: (ms: number) => Promise<void>;
}

/**
 * Open the UI: Edge in app mode, up to `EDGE_ATTEMPTS` times. Never the
 * default browser (see "NO BROWSER FALLBACK"); every failed attempt is
 * written to bench-error.log with its cause, and after the last the answer
 * is `none` with the cause in `detail`.
 * NOT `windowsHide` for Edge: that sets SW_HIDE in its startup information,
 * and a GUI program honours it on its first window.
 */
export async function openAppWindow(url: string, env: NodeJS.ProcessEnv = process.env, opts: OpenWindowOptions = {}): Promise<OpenedWindow> {
  const attempts = Math.max(1, opts.attempts ?? EDGE_ATTEMPTS);
  const retryMs = opts.retryMs ?? EDGE_RETRY_MS;
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const profile = join(localDataDir(env), 'bench-ui');
  let cause = 'raison inconnue';
  for (let attempt = 1; attempt <= attempts; attempt++) {
    if (attempt > 1) await sleep(retryMs);
    // Found again on every attempt: an Edge being updated has its msedge.exe
    // briefly absent or replaced.
    const edge = findEdge(env);
    if (!edge) {
      cause = 'Microsoft Edge est introuvable sur ce poste';
    } else {
      try {
        mkdirSync(profile, { recursive: true });
      } catch {
        /* Edge creates it itself if it can */
      }
      try {
        const child = spawn(edge, edgeArguments(url, profile), { stdio: 'ignore', detached: false });
        const r = await spawned(child);
        if (r.ok) return { mode: 'edge-app', child, detail: edge };
        cause = `Microsoft Edge n'a pas pu être lancé (${r.code})`;
      } catch (err) {
        cause = `Microsoft Edge n'a pas pu être lancé (${(err as NodeJS.ErrnoException)?.code ?? (err instanceof Error ? err.message : String(err))})`;
      }
    }
    // Never the URL: it carries the per-run token.
    logError(`fenêtre de l'application, tentative ${attempt}/${attempts} : ${cause}${edge ? ` [${edge}]` : ''}`, env);
  }
  return { mode: 'none', child: null, detail: `${cause} (${attempts} tentatives)` };
}

// ============================================================================
// When to exit
// ============================================================================

export interface WindowWatchOptions {
  /** Silence after which the window is presumed closed. Default 15 s. */
  idleMs?: number;
  /** How long the first window may take to appear. Default 120 s. */
  startupGraceMs?: number;
  /** An Edge exit sooner than this after launch is a hand-off, not a close. */
  handoffMs?: number;
  now?: () => number;
}

export type WatchVerdict = 'alive' | 'window-closed' | 'never-opened';

/** Pure bookkeeping; the caller ticks it and acts on the verdict. */
export class WindowWatch {
  private streams = 0;
  private lastSign: number;
  private connected = false;
  private readonly started: number;
  private readonly idleMs: number;
  private readonly startupGraceMs: number;
  private readonly handoffMs: number;
  private readonly now: () => number;

  constructor(opts: WindowWatchOptions = {}) {
    this.now = opts.now ?? Date.now;
    this.idleMs = opts.idleMs ?? 15_000;
    this.startupGraceMs = opts.startupGraceMs ?? 120_000;
    this.handoffMs = opts.handoffMs ?? 10_000;
    this.started = this.now();
    this.lastSign = this.started;
  }

  streamOpened(): void {
    this.streams++;
    this.connected = true;
    this.lastSign = this.now();
  }

  streamClosed(): void {
    this.streams = Math.max(0, this.streams - 1);
    this.lastSign = this.now();
  }

  heartbeat(): void {
    this.connected = true;
    this.lastSign = this.now();
  }

  /** The window was (re)opened on request: give it the startup grace again. */
  reopened(): void {
    this.lastSign = this.now();
  }

  /** The Edge child exited after `ranMs`. */
  edgeExited(ranMs: number): void {
    if (ranMs < this.handoffMs || this.streams > 0) return;
    // The window closed: do not wait the full idle delay for the stream to say so.
    this.lastSign = Math.min(this.lastSign, this.now() - this.idleMs + 2_000);
  }

  verdict(): WatchVerdict {
    if (this.streams > 0) return 'alive';
    const t = this.now();
    if (!this.connected) return t - this.lastSign > this.startupGraceMs ? 'never-opened' : 'alive';
    return t - this.lastSign > this.idleMs ? 'window-closed' : 'alive';
  }
}

// ============================================================================
// One instance per user
// ============================================================================

export interface InstanceLock {
  pid: number;
  port: number | null;
  token: string | null;
  startedAt: string;
}

export function instanceLockPath(env: NodeJS.ProcessEnv = process.env): string {
  return join(localDataDir(env), 'bench.lock');
}

function readLock(path: string): InstanceLock | null {
  try {
    const v = JSON.parse(readFileSync(path, 'utf8')) as Partial<InstanceLock>;
    if (typeof v.pid !== 'number' || !Number.isInteger(v.pid)) return null;
    return {
      pid: v.pid,
      port: typeof v.port === 'number' && Number.isInteger(v.port) && v.port > 0 && v.port < 65536 ? v.port : null,
      token: typeof v.token === 'string' && /^[0-9a-f]{32,128}$/.test(v.token) ? v.token : null,
      startedAt: typeof v.startedAt === 'string' ? v.startedAt : '',
    };
  } catch {
    return null;
  }
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === 'EPERM';
  }
}

export type InstanceClaim =
  | { owner: true; publish(port: number, token: string): void; release(): void }
  | { owner: false; running: InstanceLock & { port: number; token: string } };

/**
 * Become THE instance, or find the one that is. The lock file is created
 * exclusively (`wx`); a lock left by a dead process, or one whose server does
 * not answer `probe` with its own token, is stale and replaced. `probe` must
 * prove the server at `port` is an ObliWAN bench holding `token` — a port
 * number alone could be anything listening by then.
 */
export async function claimInstance(
  path: string,
  probe: (lock: InstanceLock & { port: number; token: string }) => Promise<boolean>,
  opts: { waitMs?: number; sleep?: (ms: number) => Promise<void> } = {},
): Promise<InstanceClaim> {
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const deadline = Date.now() + (opts.waitMs ?? 6_000);
  mkdirSync(dirname(path), { recursive: true });
  for (;;) {
    try {
      const fd = openSync(path, 'wx');
      const mine: InstanceLock = { pid: process.pid, port: null, token: null, startedAt: new Date().toISOString() };
      writeFileSync(fd, JSON.stringify(mine));
      closeSync(fd);
      return {
        owner: true,
        publish(port: number, token: string) {
          writeFileSync(path, JSON.stringify({ ...mine, port, token }), { encoding: 'utf8', mode: 0o600 });
        },
        release() {
          try {
            const now = readLock(path);
            if (now && now.pid === process.pid) unlinkSync(path);
          } catch {
            /* already gone */
          }
        },
      };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;
    }
    const lock = readLock(path);
    if (lock && lock.port !== null && lock.token !== null) {
      const running = { ...lock, port: lock.port, token: lock.token };
      if (await probe(running)) return { owner: false, running };
    }
    // Unparseable and brand new: another instance is between its `wx` and its write.
    let fresh = false;
    try {
      fresh = lock === null && Date.now() - statSync(path).mtimeMs < 2_000;
    } catch {
      /* gone meanwhile: the next `wx` decides */
    }
    const starting = fresh || (lock !== null && lock.port === null && lock.pid !== process.pid && pidAlive(lock.pid));
    if (starting && Date.now() < deadline) {
      await sleep(250); // another instance is between its lock and its listen
      continue;
    }
    try {
      unlinkSync(path); // stale: a dead owner, a server that does not answer, or garbage
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
    }
    if (Date.now() > deadline + 5_000) throw new Error(`impossible de prendre le verrou ${path}`);
  }
}
