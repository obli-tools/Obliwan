/**
 * ObliWAN — entrypoint of the `obliwan-wg` sidecar (compiled to
 * dist/src/wgSidecar.js, run from the SERVER image by the compose service of
 * the same name, with `network_mode: host` and `cap_add: NET_ADMIN`).
 *
 * It does one thing: keep the host's `wg-obliwan` interface matching the
 * config the ObliWAN server wrote on the shared volume, and report what it
 * sees there. The logic, and what it will and will not touch, is in
 * services/concentratorLink/sidecar.ts. This file is the loop:
 *
 *   OBLIWAN_WG_ENABLED    'true' (or '1') to act; an explicit 'false' (or '0')
 *                         removes only what it created earlier; anything else
 *                         (unset, empty) configures and removes NOTHING, so a
 *                         redeploy that lost the line cannot cut the link.
 *   OBLIWAN_WG_DIR        the shared volume's mount point (same in both
 *                         containers).
 *   OBLIWAN_WG_INTERVAL_MS  pass interval, default 5000 — the status file's age
 *                         is the heartbeat the server reads.
 *
 * A change of the config file triggers a pass at once (fs.watch where the
 * platform supports it); the interval runs regardless, so a missed
 * notification costs at most one interval.
 *
 * It imports no database module and needs no DATABASE_URL: the image's own
 * entrypoint script is bypassed by the compose service (`entrypoint:`).
 * SIGTERM ends the loop and leaves the interface UP on purpose (see sidecar.ts).
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawn } from 'child_process';
import { HOST_CONFIG_FILE, defaultWgDir } from './services/concentratorLink/wgConfig';
import { reconcileOnce, sidecarModeOf, type CommandRunner, type RunResult } from './services/concentratorLink/sidecar';

const COMMAND_TIMEOUT_MS = 15_000;

/**
 * A command that reads a file named `/dev/stdin` (wg syncconf) gets a real
 * file instead. Node gives a child's stdin as a SOCKET (libuv uses a
 * socketpair), and fopen("/dev/stdin") on a socket fails with ENXIO — "fopen:
 * No such device or address", seen in production. The input (it holds the
 * host's private key) goes to a fresh 0600 file in a 0700 directory created for
 * this one call, removed as soon as the command ends, whatever its outcome.
 */
const run: CommandRunner = async (cmd, args, stdin) => {
  if (stdin === undefined || !args.includes('/dev/stdin')) return spawnOnce(cmd, args, stdin);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'obliwan-wg-'));
  const file = path.join(tmp, 'input.conf');
  try {
    fs.writeFileSync(file, stdin, { mode: 0o600 });
    return await spawnOnce(cmd, args.map((a) => (a === '/dev/stdin' ? file : a)), undefined);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
};

const spawnOnce = (cmd: string, args: string[], stdin: string | undefined): Promise<RunResult> =>
  new Promise<RunResult>((resolve) => {
    // stdin is a pipe ONLY when the command is given input. Piping to a command
    // that exits before reading it — most `ip …`/`wg show` calls finish in
    // milliseconds — raises EPIPE on the write; unhandled, that 'error' event
    // killed the sidecar on every pass. A command given input may still exit
    // first: its exit code and stderr already say whether it failed, so the
    // write error itself is swallowed.
    const child = spawn(cmd, args, { stdio: [stdin === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), COMMAND_TIMEOUT_MS);
    child.stdout?.on('data', (b: Buffer) => { stdout += b.toString('utf8'); });
    child.stderr?.on('data', (b: Buffer) => { stderr += b.toString('utf8'); });
    child.on('error', (err) => {
      clearTimeout(timer);
      resolve({ code: 127, stdout, stderr: `${cmd}: ${err.message}` });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? 1, stdout, stderr });
    });
    if (child.stdin) {
      child.stdin.on('error', () => { /* EPIPE: see above */ });
      child.stdin.end(stdin);
    }
  });

function log(message: string): void {
  // eslint-disable-next-line no-console
  console.log(`[obliwan-wg] ${new Date().toISOString()} ${message}`);
}

async function main(): Promise<void> {
  const mode = sidecarModeOf(process.env.OBLIWAN_WG_ENABLED);
  const dir = defaultWgDir();
  const interval = Math.max(1000, Number(process.env.OBLIWAN_WG_INTERVAL_MS) || 5000);
  fs.mkdirSync(dir, { recursive: true });
  log(`starting: mode=${mode} dir=${dir} interval=${interval}ms`);

  let stopping = false;
  let running = false;
  let again = false;
  let last = '';
  const pass = async (): Promise<void> => {
    if (running) {
      again = true;
      return;
    }
    running = true;
    try {
      do {
        again = false;
        const s = await reconcileOnce({ dir, mode, run });
        // Log a change of state, not every heartbeat. The message never holds
        // a key (sidecar.ts scrubs it).
        const line = `${s.state}: ${s.message}${s.warnings.length ? ` | ${s.warnings.join(' | ')}` : ''}`;
        const key = line.replace(/\d+ s ago/, '');
        if (key !== last) log(line);
        last = key;
      } while (again && !stopping);
    } finally {
      running = false;
    }
  };

  try {
    // Only the server's config file: the pass itself rewrites status.json in
    // this same directory, and reacting to that would loop.
    fs.watch(dir, (_event, filename) => {
      if (filename === HOST_CONFIG_FILE) void pass();
    });
  } catch {
    log('fs.watch unavailable on this volume; relying on the interval');
  }
  const timer = setInterval(() => { void pass(); }, interval);
  const stop = (): void => {
    stopping = true;
    clearInterval(timer);
    log('stopping (the interface is left as it is)');
    process.exit(0);
  };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
  await pass();
}

void main().catch((err: unknown) => {
  log(`fatal: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
