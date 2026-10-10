import { Router } from 'express';
import { createHash } from 'node:crypto';
import { existsSync, statSync, createReadStream } from 'node:fs';
import { join, resolve } from 'node:path';
import { readFileSync } from 'node:fs';
import { logger } from '../utils/logger';

/**
 * ObliWAN — the bench tool's version check and download.
 *
 * ┌─ PORTED FROM OBLIANCE, NOT INVENTED ─────────────────────────────────────┐
 * │ Obliance's agent updates through exactly two endpoints:                   │
 * │   GET /api/agent/version            -> { version }                        │
 * │   GET /api/agent/download/<file>    -> the artefact + X-Content-SHA256    │
 * │ and the agent checks Content-Length, then the hash, before running it.    │
 * │ This is the same pair under /api/bench, so the two products' update       │
 * │ paths stay the same shape and a fix to one is legible in the other.       │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ── UNAUTHENTICATED ON PURPOSE — AND DEVICE ENROLMENT IS NOT ────────────────
 * A workstation being set up has no session, and cannot hold a station token
 * before it even has the tool: these two routes are how it gets the tool. What
 * they expose is a SIGNED, PUBLISHED installer and its version, which is not a
 * secret: the same file is handed to preparers by whatever means today. There
 * is no directory listing, no path the caller controls, and nothing here reads
 * the fleet.
 *
 * This header used to call that "the same decision as the enrolment", from the
 * days enrolment was designed to be anonymous. It is not any more:
 * `POST /api/devices/enroll` demands the `Bench <token>` of a workstation a
 * platform administrator approved (`requireApprovedBenchStation`, mounted in
 * routes/index.ts). The workstation registers that token under
 * `/api/bench/stations` (benchStations.routes.ts, a separate router mounted
 * before this one), and the token does not open enrolment until the station
 * is approved. Everything in THIS router is open, and it is only the
 * installer and its version.
 *
 * ── THE ALLOW-LIST IS THE PATH TRAVERSAL DEFENCE ────────────────────────────
 * `:filename` is never joined to a directory. It is looked up in a fixed map,
 * and anything absent from it is a 404 before a single filesystem call — so
 * `../../.env` is not a traversal to sanitise, it is a key that does not exist.
 */
const router = Router();

/**
 * The server package root (`server/` in a checkout, `/app/server` in the image),
 * derived from where THIS file sits — and that differs by one level between the
 * two ways the server runs:
 *
 *   tsx (dev)        <root>/src/routes/bench.routes.ts        -> two levels up
 *   node (compiled)  <root>/dist/src/routes/bench.routes.js   -> three levels up
 *
 * because `tsconfig.json` has `rootDir: "."` and `outDir: "dist"`, so tsc keeps
 * the `src/` segment UNDER `dist/`. A fixed `'..', '..'` was right only under
 * tsx: in the image it named `/app/server/dist/dist-bench`, one level below the
 * `/app/server/dist-bench` the Dockerfile copies the installer into, and every
 * Docker deployment answered `available: false` over a perfectly good MSI.
 * `.js` vs `.ts` is the same compiled-or-source test `knexfile.ts` uses.
 */
const SERVER_ROOT = __filename.endsWith('.js')
  ? resolve(__dirname, '..', '..', '..')
  : resolve(__dirname, '..', '..');

/**
 * The artefact directory: `<server root>/dist-bench`, which is where `build.mjs`
 * writes and where the Dockerfile copies it — so neither a dev checkout nor the
 * image needs a setting. `BENCH_ARTEFACT_DIR` overrides it (the compose files'
 * optional `/bench-override` mount).
 *
 * EMPTY counts as unset, and that is not a nicety: every compose file passes
 * `BENCH_ARTEFACT_DIR: ${BENCH_ARTEFACT_DIR:-}`, so an operator who set nothing
 * hands the process an empty string, never an absent variable. Resolving `''`
 * would point at the working directory.
 */
const ARTEFACT_DIR_OVERRIDE = (process.env.BENCH_ARTEFACT_DIR ?? '').trim();
const ARTEFACT_DIR = ARTEFACT_DIR_OVERRIDE
  ? resolve(ARTEFACT_DIR_OVERRIDE)
  : join(SERVER_ROOT, 'dist-bench');

/** Fixed map, not a pattern. See the header. */
const ALLOWED: Readonly<Record<string, string>> = {
  'obliwan-bench.msi': 'obliwan-bench.msi',
  'obliwan-bench.exe': 'obliwan-bench.exe',
};

/**
 * Hash cache keyed on (size, mtime). Hashing 28 MB per request would make a
 * fleet of benches checking for updates an I/O problem; re-stat'ing is cheap
 * and catches a rebuild in place.
 */
const hashCache = new Map<string, { key: string; sha256: string }>();

function sha256Of(path: string): string | null {
  try {
    const st = statSync(path);
    const key = `${st.size}:${st.mtimeMs}`;
    const hit = hashCache.get(path);
    if (hit && hit.key === key) return hit.sha256;
    const sha256 = createHash('sha256').update(readFileSync(path)).digest('hex');
    hashCache.set(path, { key, sha256 });
    return sha256;
  } catch {
    return null;
  }
}

/**
 * `GET /api/bench/version`
 *
 * The version is read from the VERSION file the build stamps into the binary,
 * NOT from `package.json`: the bench tool and the server version independently,
 * and answering with the server's version would make every workstation update
 * itself on a server release that did not touch the tool.
 */
router.get('/version', (_req, res) => {
  // Beside the artefact first, `src/` only as a dev fallback. The old order was
  // src-only, and `src/` does not exist in the server image — so a production
  // instance serving a perfectly good MSI still answered `version: null`, and a
  // bench comparing against null can never conclude anything. The fallback is
  // anchored on the server root, not on `ARTEFACT_DIR/..`: with an override in
  // place, the artefact directory's parent is not the server at all.
  let version: string | null = null;
  for (const candidate of [
    join(ARTEFACT_DIR, 'VERSION'),
    join(SERVER_ROOT, 'src', 'bench', 'VERSION'),
  ]) {
    try {
      version = readFileSync(candidate, 'utf8').trim() || null;
      if (version) break;
    } catch {
      /* try the next one */
    }
  }

  const msi = join(ARTEFACT_DIR, ALLOWED['obliwan-bench.msi']);
  const available = existsSync(msi);

  res.json({
    success: true,
    data: {
      version,
      // Distinct from `version === null`: the tool may know a version exists
      // and still have nothing to download, which is a deployment problem the
      // preparer should not experience as a silent no-op.
      available,
      sha256: available ? sha256Of(msi) : null,
      file: 'obliwan-bench.msi',
    },
  });
});

/** `GET /api/bench/download/:filename` */
router.get('/download/:filename', (req, res) => {
  const name = ALLOWED[req.params.filename];
  if (!name) {
    res.status(404).json({ success: false, error: 'Not found' });
    return;
  }

  const path = join(ARTEFACT_DIR, name);
  if (!existsSync(path)) {
    res.status(404).json({
      success: false,
      error:
        'The bench artefact is not published on this instance. Build it '
        + '(node src/bench/build.mjs), sign it, and place it in BENCH_ARTEFACT_DIR.',
    });
    return;
  }

  const sha256 = sha256Of(path);
  if (!sha256) {
    // Unreadable but present. A download whose integrity cannot be asserted is
    // refused rather than served bare: the tool's whole update safety rests on
    // that header, and an absent header would read as "no check needed".
    res.status(500).json({ success: false, error: 'Artefact unreadable' });
    return;
  }

  logger.info({ file: name, ip: req.ip }, 'Bench artefact downloaded');
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="${name}"`);
  res.setHeader('Content-Length', String(statSync(path).size));
  res.setHeader('X-Content-SHA256', sha256);
  createReadStream(path).pipe(res);
});

export default router;
