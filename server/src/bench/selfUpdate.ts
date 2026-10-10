import { createHash } from 'node:crypto';
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawn, execFile } from 'node:child_process';

/**
 * ObliWAN bench tool — checking for, and applying, its own update.
 *
 * ┌─ PORTED FROM OBLIANCE'S AGENT, NOT INVENTED ─────────────────────────────┐
 * │ Obliance updates through exactly two endpoints and three checks:          │
 * │   GET /api/agent/version         -> { version }                           │
 * │   GET /api/agent/download/<file> -> the artefact + X-Content-SHA256       │
 * │ then Content-Length, then the hash, then msiexec. This is the same        │
 * │ sequence under /api/bench, so a fix to either product is legible in the   │
 * │ other instead of two update paths drifting apart.                         │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ── AND ONE CHECK OBLIANCE DOES ELSEWHERE, KEPT HERE ────────────────────────
 * Obliance verifies Authenticode before it lets `msiexec` run a downloaded
 * package (`authenticode_windows.go`). That check belongs here even more: this
 * binary writes administrator accounts onto brand-new routers, and an update
 * path that runs whatever the server sent is a way to replace it with
 * something that does the same thing differently.
 *
 * The hash and the signature answer DIFFERENT questions and neither replaces
 * the other. The hash proves the bytes are the ones the server meant to send —
 * it catches a truncated or corrupted download. The signature proves WHO built
 * them, and it is the only one of the two that survives a compromised server:
 * an attacker serving a malicious MSI serves its matching hash just as easily.
 * So the signature is the anchor, and it is verified against the publisher of
 * the RUNNING binary — a certificate renewal keeps working, a different signer
 * does not.
 */

/**
 * The ONE artefact this tool will download and hand to `msiexec`, by name.
 *
 * A constant, not something the server chooses. The version answer used to
 * carry a `file` that went straight into `join(tmpdir(), file)`, and `join`
 * follows `..` — so a compromised server (or anyone in the middle of a plain
 * `http://` bench URL) could name any path the operator can write, have its
 * bytes written THERE, and then watch the failed signature check `unlink` the
 * same path. The signature is the trust anchor, and a write that happens before
 * the anchor is consulted is a write the anchor does not protect. A server that
 * names a different file is answered as one that publishes no update.
 */
export const BENCH_MSI = 'obliwan-bench.msi';

export interface UpdateCheck {
  /** `null` when the server does not publish, or could not be reached. */
  available: string | null;
  current: string;
  sha256: string | null;
  /** Always `BENCH_MSI`: kept for the URL, never taken from the server. */
  file: typeof BENCH_MSI;
}

/** Compare `1.0.10` against `1.0.9` numerically, not lexically. */
export function isNewer(candidate: string, current: string): boolean {
  const parse = (v: string) => v.trim().split('.').map((n) => Number.parseInt(n, 10) || 0);
  const a = parse(candidate);
  const b = parse(current);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x !== y) return x > y;
  }
  return false;
}

/**
 * Ask the server what it publishes. NEVER throws: a bench with no network, or
 * pointed at an older server, must still enrol the router in front of it. An
 * update check that could block the real work would be the tail wagging the dog.
 */
export async function checkForUpdate(baseUrl: string, current: string): Promise<UpdateCheck> {
  const none: UpdateCheck = { available: null, current, sha256: null, file: BENCH_MSI };
  // No URL configured: nothing to ask. Without this the relative fetch below
  // throws at once and lands in `none` anyway — this just says so.
  if (!baseUrl) return none;
  try {
    const res = await fetch(`${baseUrl.replace(/\/+$/, '')}/api/bench/version`, {
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return none;
    const body = (await res.json()) as {
      data?: { version?: string; available?: boolean; sha256?: string; file?: string };
    };
    const d = body.data;
    // `available` is distinct from a version being named: the server may know
    // its version and hold no artefact, and offering an update it cannot serve
    // would send the preparer into a download that 404s.
    if (!d?.version || d.available !== true) return none;
    // Absent is the older server's shape and means the default; anything else
    // is a server proposing an artefact this tool will not install. See
    // `BENCH_MSI`.
    if (d.file !== undefined && d.file !== BENCH_MSI) return none;
    return {
      available: isNewer(d.version, current) ? d.version : null,
      current,
      sha256: d.sha256 ?? null,
      file: BENCH_MSI,
    };
  } catch {
    return none;
  }
}

/**
 * One PowerShell command, its stdout. ASYNCHRONOUS and HIDDEN on purpose: the
 * bench is a GUI-subsystem executable with no console, so a console child
 * started without `windowsHide` gets a console window of its own that flashes
 * on the clerk's screen; and a synchronous call would freeze the event loop
 * (the local server, its heartbeat and the instance probe) for up to 30 s.
 */
function powershellOut(command: string): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(
      'powershell',
      ['-NoProfile', '-NonInteractive', '-Command', command],
      { encoding: 'utf8', timeout: 30_000, windowsHide: true },
      (err, stdout) => (err ? reject(err) : resolve(stdout)),
    );
  });
}

/** The publisher of the currently running executable — the trust anchor. */
async function runningSignerSubject(exe: string): Promise<string | null> {
  try {
    const out = await powershellOut(
      `$s = Get-AuthenticodeSignature -LiteralPath '${exe.replace(/'/g, "''")}';`
      + 'if ($s.Status -ne \'Valid\') { exit 2 }; $s.SignerCertificate.Subject',
    );
    return out.trim() || null;
  } catch {
    return null;
  }
}

/**
 * Verify the downloaded package: signature VALID, and signed by the same
 * publisher as the running tool.
 *
 * Refuses when the running binary is itself unsigned, rather than falling back
 * to "any valid signature will do". An unsigned build is a development build;
 * letting one self-update from an arbitrary publisher would turn a dev
 * convenience into the exact hole the signing requirement exists to close.
 */
async function verifySignature(msi: string, exe: string): Promise<{ ok: boolean; reason: string }> {
  const expected = await runningSignerSubject(exe);
  if (!expected) {
    return {
      ok: false,
      reason:
        'the running tool is not validly signed, so there is no publisher to compare against. '
        + 'Update it by running the MSI by hand.',
    };
  }
  try {
    const out = await powershellOut(
      `$s = Get-AuthenticodeSignature -LiteralPath '${msi.replace(/'/g, "''")}';`
      + '"$($s.Status)|$($s.SignerCertificate.Subject)"',
    );
    const [status, subject] = out.trim().split('|');
    if (status !== 'Valid') return { ok: false, reason: `the download's signature is ${status}` };
    // Subject, not thumbprint: a certificate renewal keeps the same subject and
    // must keep working, where pinning a thumbprint would break every bench on
    // the day the certificate is renewed.
    if ((subject ?? '').trim() !== expected) {
      return { ok: false, reason: 'the download is signed by a DIFFERENT publisher' };
    }
    return { ok: true, reason: 'signature valid, same publisher as this tool' };
  } catch (err) {
    return { ok: false, reason: `the signature could not be read (${String(err).slice(0, 120)})` };
  }
}

/**
 * What `applyUpdate` can actually know. `launched` is NOT "installed": once
 * Windows Installer has the package, the outcome is its own (see below), and
 * this tool says where to read it rather than claiming it.
 */
export type ApplyResult =
  | { launched: true; message: string; logPath: string }
  | { launched: false; message: string };

/**
 * The `msiexec` command line. Exported so the choice of switches is tested,
 * not just read.
 *
 * `/qb+`, NOT `/qn`. The package is per-machine (product.wxs), so installing it
 * needs elevation, and with no UI (`/qn`) Windows Installer has no way to ask
 * for it: started from a preparer's ordinary session the install simply fails,
 * and nothing on screen says so. That is what this used to do, while the tool
 * printed a check mark. Basic UI lets Windows ask for an administrator's
 * approval (UAC), shows progress and errors, and `+` ends on a dialog that
 * states the outcome — the one place that outcome can be read once this
 * process has exited. `/l*v` keeps a full log beside the package for whoever
 * has to find out afterwards why it did not take.
 *
 * `OBLIWANURL` is passed only when the URL came from the installer's own .ini
 * (`installerUrl`): the new package remembers the URL through the registry,
 * but a package installed BEFORE that fix never wrote it there, so its first
 * upgrade would otherwise reset the URL to nothing. A URL taken from the
 * environment is not written into the .ini behind the technician's back; one
 * that would need quoting on msiexec's command line is not passed at all, and
 * the package's remembered value applies.
 */
export function msiexecArguments(msi: string, logPath: string, installerUrl: string | null): string[] {
  const url = installerUrl && /^https?:\/\/[^\s"]+$/i.test(installerUrl) ? installerUrl : null;
  return ['/i', msi, '/qb+', '/norestart', '/l*v', logPath, ...(url ? [`OBLIWANURL=${url}`] : [])];
}

/**
 * Start `msiexec` detached and resolve once the OPERATING SYSTEM has said
 * whether it started — Node's `spawn` event, or its `error` event (no such
 * command, access denied). The old code returned "installing" without waiting
 * for either, so even a missing `msiexec` was announced as an installation.
 * `command` is a parameter so that refusal path can be exercised without
 * running an installer.
 */
export function launchInstaller(
  args: string[],
  command = 'msiexec',
): Promise<{ launched: true } | { launched: false; reason: string }> {
  return new Promise((resolve) => {
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(command, args, { detached: true, stdio: 'ignore' });
    } catch (err) {
      resolve({ launched: false, reason: err instanceof Error ? err.message : String(err) });
      return;
    }
    child.once('error', (err) => resolve({ launched: false, reason: err.message }));
    child.once('spawn', () => {
      child.unref();
      resolve({ launched: true });
    });
  });
}

/**
 * Download, verify, and hand the package to `msiexec`.
 *
 * Detached, and NOT waited on: `msiexec` replaces the very executable running
 * this code, and a running executable cannot be replaced — waiting for its exit
 * code from here would hold the file the installer has to overwrite. So this
 * process can know only that Windows Installer STARTED, and that is all it
 * reports. The outcome is shown by the installer itself (`/qb+`) and written to
 * its log; the caller says so and exits rather than pretending to continue on
 * a binary being swapped underneath it.
 */
export async function applyUpdate(
  baseUrl: string,
  check: UpdateCheck,
  exePath: string,
  opts: { installerUrl?: string | null } = {},
): Promise<ApplyResult> {
  // Re-checked here although `checkForUpdate` already enforces it: `UpdateCheck`
  // is an exported shape, and the guard belongs to the function that writes.
  if (check.file !== BENCH_MSI) {
    return { launched: false, message: `refused — the server named "${String(check.file).slice(0, 80)}", not ${BENCH_MSI}` };
  }
  const url = `${baseUrl.replace(/\/+$/, '')}/api/bench/download/${BENCH_MSI}`;

  let bytes: Buffer;
  let headerHash: string | null;
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(300_000) });
    if (!res.ok) return { launched: false, message: `download refused (HTTP ${res.status})` };
    headerHash = res.headers.get('x-content-sha256');
    const declared = Number(res.headers.get('content-length') ?? '0');
    bytes = Buffer.from(await res.arrayBuffer());
    // Length first, hash second: a truncated download is the common failure and
    // saying "truncated" is more useful than "hash mismatch", which reads as
    // tampering and sends somebody hunting the wrong thing.
    if (declared > 0 && bytes.length !== declared) {
      return { launched: false, message: `download truncated (${bytes.length}/${declared} bytes)` };
    }
  } catch (err) {
    return { launched: false, message: `download failed: ${err instanceof Error ? err.message : String(err)}` };
  }

  const expected = (check.sha256 ?? headerHash ?? '').toLowerCase();
  if (!expected) {
    // No hash means no integrity claim. Refused rather than installed on trust:
    // the server always sends one, so its absence is itself a signal.
    return { launched: false, message: 'the server sent no SHA-256 — refusing to install unverified bytes' };
  }
  const actual = createHash('sha256').update(bytes).digest('hex');
  if (actual !== expected) {
    return { launched: false, message: 'SHA-256 mismatch — the download does not match what the server declared' };
  }

  // A FRESH directory, created by us, named by us: the only place this function
  // writes. `mkdtemp` always creates a new directory (random suffix, never an
  // existing one) and `wx` refuses to open a file that already exists, so
  // nothing that was already on disk — the operator's or anyone else's — can be
  // overwritten here, and the cleanup below only ever removes what this call
  // created. The directory is left behind on success: `msiexec` reads from it
  // after this process has exited.
  let dir: string;
  let msi: string;
  try {
    dir = mkdtempSync(join(tmpdir(), 'obliwan-bench-update-'));
    msi = join(dir, BENCH_MSI);
    writeFileSync(msi, bytes, { flag: 'wx' });
  } catch (err) {
    return { launched: false, message: `cannot stage the download: ${err instanceof Error ? err.message : String(err)}` };
  }

  const sig = await verifySignature(msi, exePath);
  if (!sig.ok) {
    try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
    return { launched: false, message: `refused — ${sig.reason}` };
  }

  // `/norestart` is deliberate: nothing on a preparation bench justifies
  // rebooting somebody's workstation mid-session. The UI level is the point of
  // `msiexecArguments` — read it before changing it.
  const logPath = join(dir, 'install.log');
  const started = await launchInstaller(msiexecArguments(msi, logPath, opts.installerUrl ?? null));
  if (!started.launched) {
    try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
    return { launched: false, message: `Windows Installer could not be started: ${started.reason}` };
  }
  return {
    launched: true,
    logPath,
    message:
      `Windows Installer started for ${check.available}. It asks for an administrator's approval, `
      + 'then shows the outcome in its own window — this tool cannot see it from here. If it did not '
      + `install, the reason is in ${logPath}. Relaunch the tool once the installer window has closed.`,
  };
}

/** Injected by esbuild via `define`. The SEA has no VERSION file beside it,
 *  and a tool that cannot state its own version cannot decide whether the
 *  server publishes a newer one. */
declare const __BENCH_VERSION__: string | undefined;

export function currentVersion(): string {
  return typeof __BENCH_VERSION__ === "string" ? __BENCH_VERSION__ : "0.0.0";
}
