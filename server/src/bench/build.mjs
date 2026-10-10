/**
 * ObliWAN — build the bench tool as a single Windows executable.
 *
 *   node src/bench/build.mjs                    # a developer build, into dist-bench/
 *   node src/bench/build.mjs --out <staging>    # what the release script runs
 *   node src/bench/build.mjs --check-sea <exe> [--blob <blob>]
 *                                               # is <exe> an injected SEA? exit 0/1
 *
 * ┌─ WHY SEA AND NOT `pkg` ──────────────────────────────────────────────────┐
 * │ Node 24 ships Single Executable Applications in core. `pkg` is archived   │
 * │ and pins its own Node build, which would mean the bench tool ran a        │
 * │ different runtime from the server it shares driver code with — and that   │
 * │ divergence is the exact risk this tool was written in TypeScript to       │
 * │ avoid. One language, one runtime, one renderer.                           │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE SIGNING ORDER IS LOAD-BEARING ──────────────────────────────────────┐
 * │ This script stops at the unsigned `.exe`. The rest belongs in             │
 * │ the release script (outside the repo — it hard-codes the internal build   │
 * │ host), and the ORDER is the part that matters, copied from the agent      │
 * │ release step of the suite:                                                │
 * │                                                                          │
 * │   1. node src/bench/build.mjs --out <stg>   -> <stg>/obliwan-bench.exe    │
 * │   2. <sign> -Targets '<stg>\obliwan-bench.exe'     then VERIFIED          │
 * │   3. wix build ...                          -> <stg>/obliwan-bench.msi    │
 * │   4. <sign> -Targets '<stg>\obliwan-bench.msi'     then VERIFIED          │
 * │   5. exe, MSI and VERSION moved into dist-bench — and only now            │
 * │                                                                          │
 * │ The exe is signed BEFORE the MSI is built so the binary embedded in the   │
 * │ installer is itself signed; the MSI is then signed separately.            │
 * │                                                                          │
 * │ WHY A STAGING DIRECTORY: dist-bench is what the server image COPIES and   │
 * │ serves. Building straight into it meant the wipe below destroyed the last │
 * │ signed release before anything could fail, and a signature failure left  │
 * │ an UNSIGNED exe there — which the next server-only release then baked     │
 * │ into its image and served on /api/bench/download. With `--out`, nothing   │
 * │ in dist-bench moves until both signatures have been checked by the        │
 * │ release script itself (the signer exits 0 on a target it cannot find).    │
 * │ A build WITHOUT `--out` still writes into dist-bench unsigned; the        │
 * │ release script refuses to build a server image over that.                 │
 * │                                                                          │
 * │ ONE DEVIATION FROM OBLIVIEW, DELIBERATE: there, a failed signature is     │
 * │ logged and the pipeline continues. Here it must ABORT. This binary writes │
 * │ administrator accounts onto brand-new routers; an unsigned copy landing   │
 * │ on a preparation workstation is precisely what the signature exists to    │
 * │ prevent, and "Sign:ECHEC" in a summary nobody reads is not a control.     │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The signing identity is a Certum SimplySign CLOUD certificate unlocked by a
 * TOTP — there is no `.pfx` anywhere, and the signing step's configuration (outside every repo)
 * holds the OTP URI. Nothing in this repository can sign anything, which is the
 * intended property.
 */

import { build } from 'esbuild';
import { execFileSync } from 'child_process';
import { mkdirSync, copyFileSync, writeFileSync, rmSync, readFileSync, existsSync, readdirSync, renameSync } from 'fs';
import { readSubsystem, setSubsystem, SUBSYSTEM_CUI, SUBSYSTEM_GUI } from './peSubsystem.mjs';
import { join, dirname, resolve } from 'path';
import { fileURLToPath } from 'url';

const here = dirname(fileURLToPath(import.meta.url));
const serverRoot = join(here, '..', '..');

/** The fuse Node's own SEA loader reads, and the one postject is told to flip. */
const SEA_FUSE = 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2';

const args = process.argv.slice(2);
function argValue(flag) {
  const i = args.indexOf(flag);
  if (i === -1) return undefined;
  const v = args[i + 1];
  if (!v || v.startsWith('--')) {
    console.error(`  ${flag} needs a value`);
    process.exit(2);
  }
  return v;
}

// `--check-sea <exe>`: run the very guard the build runs, on any binary, and
// nothing else — no wipe, no bundle. It is how the guard itself is tested
// (against a bare node.exe it must FAIL), and how an operator can ask whether
// an exe somebody handed them is the tool or a Node runtime.
const checkTarget = argValue('--check-sea');
if (checkTarget !== undefined) {
  const blobArg = argValue('--blob');
  const problem = seaInjectionProblem(
    readFileSync(checkTarget),
    blobArg ? readFileSync(blobArg) : null,
  );
  console.log(problem ? `NOT an injected SEA: ${problem}` : 'injected SEA: fuse flipped' + (blobArg ? ', blob present' : ''));
  process.exit(problem ? 1 : 0);
}

const outArg = argValue('--out');
const dist = outArg ? resolve(outArg) : join(serverRoot, 'dist-bench');
const bundle = join(dist, 'bench.cjs');
const blob = join(dist, 'bench.blob');
const exe = join(dist, 'obliwan-bench.exe');

/**
 * Locate `signtool.exe` in the Windows SDK, preferring x64.
 *
 * Same search the signing step performs — duplicated rather than shared
 * because that script lives outside every repository, and a build that depends
 * on a file nobody can see from here is a build nobody can reproduce.
 */
function findSigntool() {
  const roots = [
    'C:\\Program Files (x86)\\Windows Kits\\10\\bin',
    'C:\\Program Files\\Windows Kits\\10\\bin',
  ];
  const found = [];
  for (const root of roots) {
    if (!existsSync(root)) continue;
    for (const ver of readdirSync(root)) {
      for (const arch of ['x64', 'x86']) {
        const p = join(root, ver, arch, 'signtool.exe');
        if (existsSync(p)) found.push({ p, arch, ver });
      }
    }
  }
  if (found.length === 0) return null;
  found.sort((a, b) => (a.arch === b.arch ? b.ver.localeCompare(a.ver) : a.arch === 'x64' ? -1 : 1));
  return found[0].p;
}

/**
 * Why `exeBytes` is NOT an injected bench tool — or `null` when it is.
 *
 * ┌─ THE FUSE, NOT THE RESOURCE NAME ────────────────────────────────────────┐
 * │ The first version of this guard looked for the string `NODE_SEA_BLOB`,   │
 * │ and every official node.exe already contains it: it is the resource name │
 * │ Node's own SEA loader asks Windows for. So the guard passed on the bare  │
 * │ runtime and could never fire — measured on node v24.14.0.                │
 * │                                                                          │
 * │ What postject actually changes is the sentinel fuse. Node ships it as    │
 * │ `<SEA_FUSE>:0`; postject injects the resource, then flips the byte after │
 * │ the colon to `1`, and refuses a binary in which the fuse appears more    │
 * │ than once. Node checks that byte at startup to decide whether it is a    │
 * │ SEA or a REPL. So "exactly one fuse, and it reads `:1`" is postject's    │
 * │ own post-condition and the very bit the runtime will read.               │
 * │                                                                          │
 * │ Given `blobBytes`, it also proves THIS build's blob is the payload: the  │
 * │ fuse says a resource was injected, not that it was ours.                 │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
function seaInjectionProblem(exeBytes, blobBytes) {
  const fuse = Buffer.from(SEA_FUSE, 'latin1');
  const at = exeBytes.indexOf(fuse);
  if (at === -1) {
    return 'no SEA sentinel fuse in this binary — it is not a node.exe postject can patch';
  }
  if (exeBytes.indexOf(fuse, at + 1) !== -1) {
    return 'the SEA sentinel fuse appears more than once — postject refuses such a binary, so it did not produce this one';
  }
  const state = exeBytes.subarray(at + fuse.length, at + fuse.length + 2).toString('latin1');
  if (state !== ':1') {
    return `the SEA fuse still reads "${state}" — postject never flipped it, this is the bare Node runtime`;
  }
  if (blobBytes && exeBytes.indexOf(blobBytes) === -1) {
    return "the fuse is flipped but this build's SEA blob is not inside the binary";
  }
  return null;
}

// Read from `src/bench/VERSION`, the same convention Obliview and Obliance use
// for their agents. A file rather than a field in package.json because the
// bench tool versions on its OWN cadence: it follows the CLI dialects it
// speaks, not the server's release train. It does NOT ship on its own,
// though: the installer reaches a workstation only inside the server image
// (server/Dockerfile copies dist-bench), so a bench release always rebuilds
// that image — the release script imposes a server bump for it. What the
// separate number buys is the reverse direction: a server release that did not
// touch the tool does not make every bench on the fleet update itself.
const version = readFileSync(join(here, 'VERSION'), 'utf8').trim();
console.log(`obliwan-bench v${version}` + (outArg ? `  ->  ${dist}` : ''));

if (outArg) {
  // A directory the CALLER named is never wiped here: a mistyped `--out` must
  // not be able to delete anything. The release script empties its staging
  // directory itself; a non-empty one would mix this build with an old one.
  if (existsSync(dist) && readdirSync(dist).length > 0) {
    console.error(`\n  REFUSED: ${dist} is not empty. Empty it (or name a new directory) and retry.\n`);
    process.exit(1);
  }
  mkdirSync(dist, { recursive: true });
} else {
  rmSync(dist, { recursive: true, force: true });
  mkdirSync(dist, { recursive: true });
  // The wipe above deletes .gitkeep with everything else, and .gitkeep is what
  // keeps this directory present in a fresh clone — the server Dockerfile COPYs
  // it, and Docker fails a COPY whose source does not exist. Put it back.
  writeFileSync(join(dist, '.gitkeep'), '');
}

console.log('[1/5] bundling…');
await build({
  entryPoints: [join(here, 'main.ts')],
  bundle: true,
  platform: 'node',
  target: 'node24',
  format: 'cjs',
  // Baked in, not read from disk at run time: the SEA has no VERSION file
  // beside it, and a tool that cannot state its own version cannot decide
  // whether the server publishes a newer one.
  define: {
    __BENCH_VERSION__: JSON.stringify(version),
    // Belt as well as braces. The logger stub above removes the fatal path;
    // this removes the REASON it was taken. `config.ts:112` reads
    // `(process.env.NODE_ENV || 'development') === 'development'`, so an unset
    // variable put every operator machine in dev mode — which also selected
    // debug-level logging and dev-only branches elsewhere in the shared code
    // this binary drags in. A preparation workstation is production.
    'process.env.NODE_ENV': JSON.stringify('production'),
  },
  outfile: bundle,
  // The drivers reach for `ssh2` and friends at run time. Bundling them is the
  // point: a preparation workstation has no npm install and no network to the
  // registry.
  external: [],
  plugins: [
    {
      // ┌─ THE DATABASE IS REPLACED BY A MODULE THAT THROWS ─────────────────┐
      // │ The bench tool must not carry a database, and the import graph      │
      // │ disagreed: `registry` -> `draytek.driver` -> `cwmpInventory` ->     │
      // │ `cwmp/inventory.service` -> `cwmp/paramMap.service` -> `db`, which  │
      // │ drags in knex and its nine SQL drivers. The build died on           │
      // │ `oracledb`, which is how the coupling was found at all.             │
      // │                                                                    │
      // │ That path is REAL on a server — a Vigor's inventory can come from   │
      // │ its stored TR-069 parameters — and MEANINGLESS on a bench, where    │
      // │ the router has never informed an ACS. So it is not excluded, it is  │
      // │ STUBBED: reaching it raises a sentence naming the tool and the      │
      // │ path, instead of a `Cannot find module 'pg'` at a customer site.    │
      // │                                                                    │
      // │ Marking it `external` would have been one word shorter and would    │
      // │ have failed silently the first time somebody wired a query into a   │
      // │ shared helper. A stub that throws is the version that stays true.   │
      // └────────────────────────────────────────────────────────────────────┘
      // ┌─ PINO IS REPLACED, AND THIS IS THE BUG THAT KILLED THE TOOL ───────┐
      // │ `utils/logger.ts:4` builds its pino instance AT MODULE LOAD with   │
      // │ `transport: { target: 'pino-pretty' }` whenever `config.isDev` is  │
      // │ true — and `config.ts:112` makes isDev true whenever NODE_ENV is   │
      // │ UNSET, which is the state of every machine the MSI installs on.    │
      // │                                                                    │
      // │ pino's transport spawns a worker thread resolved from a RUNTIME    │
      // │ STRING: `join(__dirname, 'lib', 'worker.js')`. esbuild cannot      │
      // │ follow a runtime string, so pino-pretty is not in the bundle and   │
      // │ never could be; in the SEA `__dirname` is the folder holding the   │
      // │ .exe, so the worker resolves to `<install folder>\lib\worker.js`,  │
      // │ which the installer does not create. MODULE_NOT_FOUND is rethrown  │
      // │ from `process.nextTick`, i.e. an UNCAUGHT EXCEPTION that           │
      // │ `main().catch()` structurally cannot see — the console flashed for │
      // │ ~480 ms and vanished with no message at all.                       │
      // │                                                                    │
      // │ The import is unavoidable: gui -> ./routerosApply -> (dynamic)     │
      // │ transport/routeros/connection -> utils/logger, the RouterOS API    │
      // │ client every router dial goes through. So the module is replaced  │
      // │ rather than avoided.                                               │
      // │                                                                    │
      // │ NOT a throwing stub like the database above: drivers log on normal │
      // │ paths, and refusing would turn a working tool into a crashing one  │
      // │ for a debug line. It keeps pino's API shape and writes to stderr   │
      // │ (unseen when the GUI-subsystem exe starts from its shortcut: no    │
      // │ console; a pipe, as in the build's own run, does receive it).      │
      // └────────────────────────────────────────────────────────────────────┘
      name: 'no-pino-transport-on-a-bench',
      setup(b) {
        b.onResolve({ filter: /utils\/logger$/ }, (args) => {
          if (!args.importer.includes('src')) return null;
          return { path: 'obliwan-bench-logger', namespace: 'benchlog' };
        });
        b.onLoad({ filter: /.*/, namespace: 'benchlog' }, () => ({
          contents: `
            const emit = (level) => (...args) => {
              if (!process.env.OBLIWAN_BENCH_DEBUG) return;
              const first = args[0];
              const text = typeof first === 'string' ? first
                : (first && typeof first === 'object' && typeof args[1] === 'string') ? args[1]
                : '';
              if (text) process.stderr.write('[' + level + '] ' + text + '\\n');
            };
            const logger = {
              fatal: emit('fatal'), error: emit('error'), warn: emit('warn'),
              info: emit('info'), debug: emit('debug'), trace: emit('trace'),
              silent: () => {},
              level: 'info',
            };
            logger.child = () => logger;
            module.exports = { logger, default: logger };
          `,
          loader: 'js',
        }));
      },
    },
    {
      name: 'no-database-on-a-bench',
      setup(b) {
        b.onResolve({ filter: /(^|\/)db(\/index)?$/ }, (args) => {
          if (!args.importer.includes(`${'src'}`)) return null;
          return { path: 'obliwan-bench-no-db', namespace: 'stub' };
        });
        b.onLoad({ filter: /.*/, namespace: 'stub' }, () => ({
          // Inert on IMPORT, loud on USE. The first version threw during the
          // CJS/ESM interop shim, which probes `__esModule`/`default` on every
          // module it wraps — so the tool died at startup instead of at the
          // query it was meant to catch. The interop keys are answered; every
          // other access refuses.
          contents: `
            const refuse = () => {
              throw new Error(
                'The ObliWAN bench tool has no database. Something reached a query path — most ' +
                'likely the CWMP inventory fallback, which is meaningless for a router that has ' +
                'never informed an ACS. Read the identity over the device transport instead.'
              );
            };
            const INTEROP = new Set(['__esModule', 'default', 'then', 'prototype', 'name', 'length']);
            const stub = new Proxy(function () { refuse(); }, {
              get(target, prop) {
                if (typeof prop === 'symbol') return Reflect.get(target, prop);
                if (prop === '__esModule') return false;
                if (INTEROP.has(prop)) return undefined;
                refuse();
              },
              apply: refuse,
            });
            module.exports = stub;
          `,
          loader: 'js',
        }));
      },
    },
  ],
  // Not minified. A tool that writes administrator accounts should stay
  // readable to whoever has to audit the binary they were handed.
  minify: false,
  sourcemap: false,
  logLevel: 'info',
});

console.log('[2/5] sea-config…');
const seaConfig = join(dist, 'sea-config.json');
writeFileSync(seaConfig, JSON.stringify({
  main: bundle,
  output: blob,
  disableExperimentalSEAWarning: true,
  // No snapshot: it forbids `require()` at run time, and the drivers resolve
  // transports dynamically.
  useSnapshot: false,
  useCodeCache: true,
}, null, 2));

execFileSync(process.execPath, ['--experimental-sea-config', seaConfig], { stdio: 'inherit' });

console.log('[3/5] copying the node runtime…');
// Remove first, then copy. `copyFileSync` onto an existing exe fails with EBUSY
// the moment anything holds it open — an antivirus scan, Explorer's preview, or
// simply the tool still running from a previous test — and a failure HERE used
// to leave the PREVIOUS build sitting in place with its old timestamp, which is
// how a seven-month-old binary came to be shipped as today's.
try {
  rmSync(exe, { force: true });
} catch (err) {
  console.error(`\n  cannot replace ${exe}: ${err.message}`);
  console.error('  Close anything holding it (a running obliwan-bench.exe, an AV scan) and retry.\n');
  process.exit(1);
}
copyFileSync(process.execPath, exe);

// ┌─ STRIP NODE'S OWN AUTHENTICODE SIGNATURE BEFORE INJECTING ───────────────┐
// │ `process.execPath` is the official node.exe and it ships SIGNED. Injecting│
// │ the SEA blob invalidates that signature — postject says so out loud       │
// │ ("warning: The signature seems corrupted!") — and it leaves a certificate │
// │ table that no longer matches the file. `signtool` then REFUSES to re-sign │
// │ it, which is what made the release fail after SimplySign had already      │
// │ accepted the TOTP: the session was fine, the binary was not.             │
// │                                                                          │
// │ Node's own SEA documentation prescribes exactly this: remove the          │
// │ signature, inject, sign. Doing it here rather than in the .bat keeps the  │
// │ build self-contained — a binary this script produces is always signable.  │
// │                                                                          │
// │ Non-fatal: an unsigned node.exe (a custom or nightly build) has nothing   │
// │ to remove, and that is not an error.                                      │
// └──────────────────────────────────────────────────────────────────────────┘
if (process.platform === 'win32') {
  const signtool = findSigntool();
  if (!signtool) {
    console.log('  ! signtool.exe not found — skipping signature removal.');
    console.log('    If the release then fails at "Signing exe", this is why.');
  } else {
    try {
      execFileSync(signtool, ['remove', '/s', exe], { stdio: 'pipe' });
      console.log("  node's own signature removed");
    } catch {
      console.log('  (no signature to remove)');
    }
  }
}

console.log('[4/5] injecting…');
// `postject` is invoked through npx so the build host needs no global install.
//
// Wrapped, because a bare throw here is what shipped a REPL: the exe is ALREADY
// on disk at this point — a pristine copy of node.exe — so a crash in this one
// step leaves a 91 MB binary that looks finished, carries today's build beside
// it, and opens `Welcome to Node.js` when double-clicked. The failure has to
// name itself, and nothing may survive it.
try {
  execFileSync('npx', [
    '--yes', 'postject', exe, 'NODE_SEA_BLOB', blob,
    '--sentinel-fuse', SEA_FUSE,
  ], { stdio: 'inherit', shell: process.platform === 'win32' });
} catch (err) {
  console.error(`\n  INJECTION FAILED: ${err.message}`);
  console.error('  Common causes: no network (npx fetches postject on first use),');
  console.error('  or the exe is held open by an antivirus or a running instance.');
  console.error('  The half-built binary has been deleted — nothing is published.\n');
  rmSync(exe, { force: true });
  process.exit(1);
}

// ┌─ PROVE THE INJECTION HAPPENED, OR FAIL ────────────────────────────────────┐
// │ Without this the script could print "built:" over an untouched node.exe —  │
// │ and it did. A SEA that was never injected does not crash and does not warn:│
// │ it starts the Node REPL. So the operator copies 91 MB to a preparation     │
// │ workstation, double-clicks, and gets `Welcome to Node.js`. Nothing in the  │
// │ chain says anything is wrong until a human is standing in front of it.     │
// │                                                                            │
// │ The proof is the sentinel fuse reading `:1` plus this build's blob inside  │
// │ the binary — see seaInjectionProblem() for why the resource NAME is no     │
// │ proof at all. Checked before anything else is written beside the exe.      │
// └────────────────────────────────────────────────────────────────────────────┘
const injectionProblem = seaInjectionProblem(readFileSync(exe), readFileSync(blob));
if (injectionProblem) {
  console.error(`\n  REFUSED: the injection did not take — ${injectionProblem}.`);
  console.error('  Running it would open a Node REPL instead of the bench tool.');
  console.error('  Check the [4/5] postject output above; the binary has been deleted, nothing is published.\n');
  rmSync(exe, { force: true });
  process.exit(1);
}

// ┌─ NO CONSOLE WINDOW: THE GUI SUBSYSTEM, PROVEN ON A COPY ───────────────────┐
// │ node.exe is a console program, so the SEA opened a console window beside   │
// │ the application window. The Subsystem field of the PE optional header is  │
// │ set to WINDOWS_GUI (peSubsystem.mjs) — after postject, which rewrites the  │
// │ file, and before the signature, which must cover the patched bytes (the    │
// │ signing happens in the release script, after this build).                  │
// │                                                                            │
// │ The patch is made on a COPY, and the copy must prove it still runs before  │
// │ it replaces the exe: `--version` through a pipe, then `--self-test`        │
// │ started through `cmd /c start /wait`, i.e. with no console and no          │
// │ inherited standard handles — the way Explorer starts it — writing to       │
// │ stdout and stderr on the way. Any failure deletes both: nothing that has   │
// │ not run is left to be signed.                                              │
// └────────────────────────────────────────────────────────────────────────────┘
console.log('[5/5] Windows GUI subsystem…');
{
  const guiCopy = join(dist, 'obliwan-bench.gui-check.exe');
  const proof = join(dist, 'gui-self-test.txt');
  const refuse = (why) => {
    console.error(`\n  REFUSED: the GUI-subsystem binary did not prove itself — ${why}.`);
    console.error('  The binaries have been deleted, nothing is published.\n');
    rmSync(guiCopy, { force: true });
    rmSync(exe, { force: true });
    process.exit(1);
  };
  try {
    rmSync(guiCopy, { force: true });
    rmSync(proof, { force: true });
    const bytes = readFileSync(exe);
    const before = setSubsystem(bytes, SUBSYSTEM_GUI);
    if (before !== SUBSYSTEM_CUI && before !== SUBSYSTEM_GUI) refuse(`unexpected subsystem ${before} in the injected binary`);
    writeFileSync(guiCopy, bytes);
    if (readSubsystem(readFileSync(guiCopy)) !== SUBSYSTEM_GUI) refuse('the subsystem did not read back as GUI');
  } catch (err) {
    refuse(err.message);
  }
  if (process.platform === 'win32') {
    let printed = '';
    try {
      printed = execFileSync(guiCopy, ['--version'], { encoding: 'utf8', timeout: 60_000, windowsHide: true }).trim();
    } catch (err) {
      refuse(`--version failed: ${err.message}`);
    }
    if (printed !== version) refuse(`--version printed "${printed.slice(0, 60)}", expected "${version}"`);
    try {
      // Verbatim: `start`'s first quoted argument is a window title, and Node's
      // own quoting of `""` would not survive cmd's parser.
      execFileSync('cmd', ['/d', '/s', '/c', `"start "" /wait "${guiCopy}" --self-test "${proof}""`], {
        timeout: 60_000, windowsHide: true, stdio: 'ignore', windowsVerbatimArguments: true,
      });
    } catch (err) {
      refuse(`--self-test failed: ${err.message}`);
    }
    const said = existsSync(proof) ? readFileSync(proof, 'utf8').trim() : '';
    rmSync(proof, { force: true });
    if (said !== `ok ${version}`) refuse(`--self-test wrote "${said.slice(0, 60)}" with no console attached`);
  } else {
    console.log('  (not on Windows: the patched copy was not started)');
  }
  rmSync(exe, { force: true });
  renameSync(guiCopy, exe);
  console.log('  subsystem: WINDOWS_GUI — started without a console, answered --version and --self-test');
}

// The MSI manifest carries `BENCH_VERSION_PLACEHOLDER`. Substituting it here
// keeps the version in ONE file instead of two that drift apart — the same
// trick Obliview uses for `AGENT_VERSION_PLACEHOLDER`.
const wxsOut = join(dist, 'product.wxs');
writeFileSync(
  wxsOut,
  readFileSync(join(here, 'installer', 'product.wxs'), 'utf8')
    .replace('BENCH_VERSION_PLACEHOLDER', version),
);

// ┌─ THE VERSION HAS TO TRAVEL WITH THE ARTEFACT ──────────────────────────────┐
// │ `GET /api/bench/version` used to read `<artefacts>/../src/bench/VERSION`,  │
// │ which exists on a dev checkout and NOWHERE in production: the server image │
// │ ships `dist/`, never `src/`. So a correctly deployed instance, with the    │
// │ MSI mounted and downloadable, still answered `version: null` — and a bench │
// │ comparing `null` against its own build can never decide an update is       │
// │ available. Writing it beside the binary makes the published directory      │
// │ self-describing: whoever copies the MSI copies the version with it.        │
// └────────────────────────────────────────────────────────────────────────────┘
const versionOut = join(dist, 'VERSION');
writeFileSync(versionOut, version + '\n');

console.log(`\n  built: ${exe}  (v${version})`);
console.log(`  wxs:   ${wxsOut}`);
console.log('  NOT SIGNED. Sign it before building the MSI — see the box at the top.\n');
