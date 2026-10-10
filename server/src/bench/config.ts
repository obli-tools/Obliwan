import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { execPath } from 'node:process';
import { lastRegisteredUrl } from './station';

/**
 * ObliWAN bench tool — where its two settings come from.
 *
 * ┌─ THE PREPARER OPENS NO COMMAND PROMPT ───────────────────────────────────┐
 * │ The URL was asked at every launch, with `https://obliwan.local` — a       │
 * │ hostname that exists on no network anybody deployed — offered as the      │
 * │ default. A preparer with twenty routers to do presses Enter on a default, │
 * │ so one that is always wrong costs a failed enrolment and a phone call,    │
 * │ every time. The environment-variable workaround was worse: it is still a  │
 * │ manipulation, and a step done by hand before every session is a step that │
 * │ stops happening under pressure.                                           │
 * │                                                                          │
 * │ So the MSI writes it ONCE, at install, into `obliwan-bench.ini` beside    │
 * │ the executable. The preparer double-clicks a shortcut and answers         │
 * │ questions about the ROUTER, never about ObliWAN.                          │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Precedence, and each level earns its place:
 *   1. the .ini      — what the installer was told; the normal case. It WINS:
 *                        nothing below overrides a URL the installer wrote.
 *   2. the environment — `OBLIWAN_URL`, read ONLY when the .ini has no URL: a
 *                        bench installed without one (the MSI property left
 *                        empty), or the tool run outside the MSI (a copied
 *                        executable, the harnesses). It is not an override,
 *                        and on an installed bench setting it changes nothing.
 *   3. the station file — the address whose platform last ANSWERED for this
 *                        user's station (`lastRegisteredUrl`, %APPDATA%): an
 *                        address the preparer typed into the application on
 *                        an earlier run. An address nobody answered at (a
 *                        typo) is not remembered.
 *   4. nothing found  — the application's ONLY screen asks for the address,
 *                        with NO invented default. A tool that does not know
 *                        where the server is must say so.
 *
 * While the station is not approved, the application lets the preparer type
 * another address ONLY when the current one came from the station file or was
 * typed: an address the installer or the environment set is the
 * administrator's, and letting the person the gate constrains repoint it at a
 * server of their choosing would let that server approve them (gui.ts refuses
 * `POST /api/url` then; never in the revoked phase either). A reinstall with
 * another URL, or editing the .ini, changes an installer address.
 *
 * ── NOTHING HERE IS A SECRET ────────────────────────────────────────────────
 * The .ini holds a URL and nothing else, and an unreadable or absent one is not
 * an error — it simply means the question gets asked. The workstation DOES hold
 * a credential now — the station token the platform's enrolment route demands —
 * but not here: it is drawn on first use and kept per user under %APPDATA%
 * (`station.ts`), because this file sits under Program Files, which a
 * preparer's account cannot write, and because a token beside the executable
 * would be every account's on a shared desk.
 */
export interface BenchConfig {
  /** Public URL of the ObliWAN instance, no trailing slash. `null` = unknown. */
  baseUrl: string | null;
  /** Where the value came from, so the tool can say so rather than imply it. */
  source: 'installer' | 'environment' | 'station' | null;
}

/** Beside the executable. In a Node SEA, `execPath` IS the tool, not `node`. */
export function configPath(): string {
  return join(dirname(execPath), 'obliwan-bench.ini');
}

/**
 * A deliberately tiny INI reader: one flat section, `key = value`.
 *
 * Not a dependency — the whole file is three keys at most, and adding a parser
 * to a 94 MB single-file binary to read `url=` would be weight for nothing.
 * Unknown sections and keys are ignored rather than rejected: a future
 * installer adding a setting must not break an older tool.
 */
function readIni(path: string): Record<string, string> {
  const out: Record<string, string> = {};
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    return out; // Absent is normal — see the header.
  }
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith(';') || line.startsWith('#') || line.startsWith('[')) continue;
    const eq = line.indexOf('=');
    if (eq < 0) continue;
    out[line.slice(0, eq).trim().toLowerCase()] = line.slice(eq + 1).trim();
  }
  return out;
}

function normaliseUrl(value: string | undefined): string | null {
  const v = (value ?? '').trim().replace(/\/+$/, '');
  // An MSI property nobody supplied writes an EMPTY value, not a missing key —
  // so empty must read as absent or the tool would "know" a URL of "".
  if (!v) return null;
  return /^https?:\/\//i.test(v) ? v : null;
}

export function loadBenchConfig(): BenchConfig {
  const fromIni = normaliseUrl(readIni(configPath()).url);
  if (fromIni) return { baseUrl: fromIni, source: 'installer' };

  const fromEnv = normaliseUrl(process.env.OBLIWAN_URL);
  if (fromEnv) return { baseUrl: fromEnv, source: 'environment' };

  const fromStation = normaliseUrl(lastRegisteredUrl() ?? undefined);
  if (fromStation) return { baseUrl: fromStation, source: 'station' };

  return { baseUrl: null, source: null };
}

/** Exported for the application's own "address" field: the same rule. */
export function normaliseBenchUrl(value: string | undefined): string | null {
  return normaliseUrl(value);
}
