import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { homedir, hostname, userInfo } from 'node:os';
import { dirname, join } from 'node:path';

/**
 * ObliWAN bench tool — this workstation's own credential towards the platform.
 *
 * ┌─ WHAT THE SERVER ASKS FOR ───────────────────────────────────────────────┐
 * │ `POST /api/devices/enroll` answers only to                               │
 * │ `Authorization: Bench <token>` from a workstation a platform             │
 * │ administrator has APPROVED                                               │
 * │ (server/src/middleware/benchStation.ts). The contract, read off the      │
 * │ server and not re-derived here:                                          │
 * │   POST /api/bench/stations/register  {name, hostname, token}             │
 * │     public; 201 created / 200 already known; data {stationId, status,    │
 * │     verificationCode}; idempotent on the token; a revoked token stays    │
 * │     revoked — the bench must draw a new one.                             │
 * │   GET  /api/bench/stations/me        with the header                     │
 * │     200 data {stationId, status: pending|approved, name,                 │
 * │     verificationCode}; 401 token unknown; 403 revoked.                   │
 * │ The token is drawn HERE (32 random bytes, hex); the server keeps only    │
 * │ its sha256 and never sees it again except in that header.                │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ ONE TOKEN PER SERVER URL, AND NEVER SENT TO ANOTHER ────────────────────┐
 * │ The file maps a normalised URL to the token registered THERE. A bench    │
 * │ pointed at a second instance draws a second token for it. (The way to    │
 * │ point an installed bench elsewhere is the URL field of the graphical     │
 * │ mode: `OBLIWAN_URL` is read only when the installer wrote no URL — see   │
 * │ config.ts.) Sending instance A's token to instance B would hand B a      │
 * │ credential that opens A's enrolment route, so the lookup is by URL and   │
 * │ nothing hands out a token without one. `submitEnrolment` takes the URL   │
 * │ FROM the station for the same reason: there is no second argument that  │
 * │ could disagree with it.                                                  │
 * │                                                                          │
 * │ For the same reason no request carrying the token FOLLOWS a redirect     │
 * │ (`redirect: 'manual'`). `fetch` follows a 307/308 by re-sending the      │
 * │ body — the registration body holds the token — to wherever `Location`    │
 * │ points, while dropping `Authorization` on a cross-origin hop: the token  │
 * │ reached the redirect target and the next `/me` came back 401, which read │
 * │ as "registered, then not recognised". A 3xx is now its own answer        │
 * │ (`redirected`), naming the address to configure instead.                 │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHERE IT LIVES: %APPDATA%\ObliWAN\bench-station.json ───────────────────┐
 * │ Not beside the executable, unlike `obliwan-bench.ini`: the MSI installs  │
 * │ per machine under Program Files, which a preparer's account cannot       │
 * │ write. And not machine-wide on purpose: the token is a bearer            │
 * │ credential, the other ordinary accounts on the desk cannot read a        │
 * │ user's profile (the machine's administrators can), and two people        │
 * │ sharing a desk are two stations the administrator can revoke             │
 * │ separately — the name sent with the registration carries the Windows     │
 * │ account for that reason.                                                 │
 * │ The token is written to disk BEFORE it is registered, so a               │
 * │ registration whose answer is lost leaves a token this bench still        │
 * │ holds, not a pending row on the platform nobody can authenticate as.     │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Nothing here returns the token to a caller except `authHeader()`, and the
 * GUI never forwards that to the page: the page gets the status, the name, the
 * station number and the verification code — what a human compares, and the
 * number the administrator's approval call takes.
 */

export const STATION_FILE = 'bench-station.json';

/** Per request. A bench on a LAN that cannot reach the platform must say so
 *  in seconds, not hang a form. */
const STATION_TIMEOUT_MS = 10_000;

const ME_PATH = '/api/bench/stations/me';
const REGISTER_PATH = '/api/bench/stations/register';

/** How often the application asks again. The "unreachable" sentence below
 *  names the second, so it is taken from here. */
export const STATION_POLL_PENDING_MS = 5_000;
export const STATION_POLL_UNREACHABLE_MS = 15_000;

/** `%APPDATA%\ObliWAN\bench-station.json`, or the XDG equivalent off Windows.
 *  Trimmed before it is tested: a blank `APPDATA` is no `APPDATA`. */
export function stationFilePath(env: NodeJS.ProcessEnv = process.env): string {
  const appData = (env.APPDATA ?? '').trim();
  if (appData) return join(appData, 'ObliWAN', STATION_FILE);
  if (process.platform === 'win32') return join(homedir(), 'AppData', 'Roaming', 'ObliWAN', STATION_FILE);
  const xdg = (env.XDG_CONFIG_HOME ?? '').trim();
  return join(xdg || join(homedir(), '.config'), 'ObliWAN', STATION_FILE);
}

/**
 * The key a token is filed under: scheme, host (lower-cased by `URL`, default
 * port dropped) and path, no trailing slash, no query, no credentials. So
 * `https://Obliwan.example.fr/` and `https://obliwan.example.fr` are one
 * station, and `http://` and `https://` to the same host are two — a token that
 * has travelled in clear is not the same secret as one that has not.
 */
export function stationUrlKey(baseUrl: string): string {
  let u: URL;
  try {
    u = new URL(baseUrl.trim());
  } catch {
    throw new Error(`"${baseUrl}" n'est pas une URL — attendu http(s)://hôte[:port].`);
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new Error(`"${baseUrl}" n'est pas une URL http(s).`);
  }
  return `${u.protocol}//${u.host}${u.pathname.replace(/\/+$/, '')}`;
}

interface StationRecord {
  url: string;
  token: string;
  /** What was registered. Kept so a re-registration sends the same thing. */
  name: string;
  hostname: string | null;
  createdAt: string;
  /** When a platform at `url` first ANSWERED for this token (pending,
   *  approved or revoked). A record is drawn before any network call, so a
   *  mistyped address leaves one too; only an answered record is offered back
   *  as the remembered address (`lastRegisteredUrl`). */
  answeredAt?: string;
}

interface StationFile {
  version: 1;
  stations: StationRecord[];
}

const TOKEN_RE = /^[0-9a-f]{64,256}$/;

function isRecord(v: unknown): v is StationRecord {
  const r = v as Partial<StationRecord> | null;
  return !!r
    && typeof r.url === 'string'
    && typeof r.token === 'string' && TOKEN_RE.test(r.token)
    && typeof r.name === 'string'
    && (r.hostname === null || typeof r.hostname === 'string')
    && typeof r.createdAt === 'string';
}

/**
 * Read the file. Absent is normal (first run). Unreadable JSON is set ASIDE,
 * never overwritten: it may hold the only copy of an approved token, and a
 * bench that silently drew a new one would turn an approved desk into a new
 * pending row with no explanation. The aside copy keeps it for whoever looks.
 */
function readStationFile(path: string): StationFile {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return { version: 1, stations: [] };
    throw new StationFileError(`le fichier de poste ${path} est illisible : ${(err as Error).message}`);
  }
  let parsed: { stations?: unknown };
  try {
    parsed = JSON.parse(text) as { stations?: unknown };
    if (typeof parsed !== 'object' || parsed === null) throw new Error('not an object');
  } catch {
    const aside = `${path}.illisible-${Date.now()}`;
    try {
      renameSync(path, aside);
    } catch (err) {
      throw new StationFileError(
        `le fichier de poste ${path} est illisible et n'a pas pu être mis de côté : ${(err as Error).message}`,
      );
    }
    return { version: 1, stations: [] };
  }
  const stations = Array.isArray(parsed.stations) ? parsed.stations.filter(isRecord) : [];
  return { version: 1, stations };
}

/** Write-then-rename, so a crash mid-write leaves the previous file, not half
 *  of one. `0o600` is honoured off Windows; on Windows the profile's own ACL is
 *  what keeps another account out. A failure says it is THIS file — a bare
 *  `ENOTDIR: mkdir …` used to reach the enrolment call and be reported as
 *  "ObliWAN injoignable". */
function writeStationFile(path: string, file: StationFile): void {
  try {
    mkdirSync(dirname(path), { recursive: true });
    const tmp = `${path}.${process.pid}.tmp`;
    writeFileSync(tmp, `${JSON.stringify(file, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
    renameSync(tmp, path);
  } catch (err) {
    throw new StationFileError(`le fichier de poste ${path} n'a pas pu être écrit : ${(err as Error).message}`);
  }
}

/** The station file could not be read or written — a problem on THIS
 *  workstation, never an answer from the platform. */
export class StationFileError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StationFileError';
  }
}

// eslint-disable-next-line no-control-regex
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f]/g;

/** "PREP-01 (jdupont)": the machine AND the account, because the file is per
 *  user — see the header. The server refuses control characters and caps the
 *  name at 128, so both are dealt with before it is sent rather than after a
 *  400. */
function defaultStationName(): { name: string; hostname: string | null } {
  const host = hostname().replace(CONTROL_CHARACTERS, '').trim();
  let user = '';
  try {
    user = userInfo().username.replace(CONTROL_CHARACTERS, '').trim();
  } catch {
    /* No account entry (a service context): the machine name alone. */
  }
  const name = (host && user ? `${host} (${user})` : host || user || 'Poste d\'établi').slice(0, 128);
  return { name, hostname: host ? host.slice(0, 255) : null };
}

export type StationStatus =
  | { state: 'approved' | 'pending'; stationId: number; name: string; verificationCode: string | null }
  /** The platform knows this token and refuses it for good. */
  | { state: 'revoked'; message: string }
  /** No answer: network, DNS, timeout. Nothing is known about the station. */
  | { state: 'unreachable'; message: string }
  /** The configured address answered with a 3xx. Not followed — see the
   *  header — so nothing is known about the station either. `suggestedUrl` is
   *  the instance root the redirect points at, when it can be read off. */
  | { state: 'redirected'; status: number; location: string | null; suggestedUrl: string | null }
  /** The station file on THIS workstation could not be read or written.
   *  Nothing was sent to the platform. */
  | { state: 'localError'; message: string }
  /** An answer, but not one this contract describes (400, 429, a 5xx…). */
  | { state: 'refused'; message: string };

interface Answer {
  status: number;
  data: Record<string, unknown> | null;
  error: string | null;
}

/**
 * A 3xx from a request made with `redirect: 'manual'`, as a status — or null
 * for any other answer. `Location` is resolved against the URL that was asked,
 * and when it ends with the same API path the instance root is suggested: an
 * `http://` URL in front of an edge that answers 308 to `https://` is the
 * common case, and the fix is to configure the `https://` root.
 */
export function redirectedStatus(res: Response, requested: string, apiPath: string): StationStatus | null {
  if (res.status < 300 || res.status > 399) return null;
  const raw = res.headers.get('location');
  let location: string | null = null;
  let suggestedUrl: string | null = null;
  if (raw) {
    try {
      const u = new URL(raw, requested);
      location = u.toString();
      if ((u.protocol === 'http:' || u.protocol === 'https:') && u.pathname.endsWith(apiPath)) {
        suggestedUrl = `${u.protocol}//${u.host}${u.pathname.slice(0, -apiPath.length).replace(/\/+$/, '')}`;
      }
    } catch {
      location = raw.slice(0, 300);
    }
  }
  return { state: 'redirected', status: res.status, location, suggestedUrl };
}

/** The house envelope, read defensively: `{ success, data }` / `{ success:false, error }`. */
async function readAnswer(res: Response): Promise<Answer> {
  const text = await res.text();
  let body: { data?: unknown; error?: unknown } | null = null;
  try {
    body = JSON.parse(text) as { data?: unknown; error?: unknown };
  } catch {
    body = null;
  }
  const data = body && typeof body.data === 'object' && body.data !== null
    ? (body.data as Record<string, unknown>)
    : null;
  const error = body && typeof body.error === 'string' ? body.error : (res.ok ? null : text.slice(0, 300));
  return { status: res.status, data, error };
}

function unreachable(err: unknown): StationStatus {
  const e = err as Error & { cause?: { code?: string; message?: string } };
  const detail = e?.name === 'TimeoutError'
    ? `pas de réponse en ${STATION_TIMEOUT_MS / 1000} s`
    : e?.cause?.code ?? e?.cause?.message ?? e?.message ?? String(err);
  return { state: 'unreachable', message: detail };
}

/** A station that is pending or approved, as `/me` describes it — or null when
 *  the answer is not that shape (it is then reported, never guessed at). */
function knownStation(data: Record<string, unknown> | null): StationStatus | null {
  if (!data) return null;
  const { stationId, status, name, verificationCode } = data;
  if (typeof stationId !== 'number' || !Number.isInteger(stationId) || stationId <= 0) return null;
  if (status !== 'pending' && status !== 'approved') return null;
  return {
    state: status,
    stationId,
    name: typeof name === 'string' ? name : '',
    verificationCode: typeof verificationCode === 'string' && verificationCode ? verificationCode : null,
  };
}

/**
 * This workstation, as known to ONE ObliWAN instance.
 *
 * `authHeader()` is synchronous and local: it draws and files the token on
 * first use and never talks to the network. `status()` is the network half:
 * it asks `/me`, registers when the platform does not know the token yet, and
 * asks again.
 */
export class BenchStation {
  /** Normalised — see `stationUrlKey`. The ONLY URL this station's token is
   *  ever sent to. */
  readonly baseUrl: string;

  private constructor(baseUrl: string, private readonly file: string) {
    this.baseUrl = baseUrl;
  }

  static forUrl(baseUrl: string, opts: { file?: string } = {}): BenchStation {
    return new BenchStation(stationUrlKey(baseUrl), opts.file ?? stationFilePath());
  }

  /** The record for this URL, drawn and written on first use. Re-read from
   *  disk every time: a second instance of the tool may have drawn it. */
  private record(): StationRecord {
    const file = readStationFile(this.file);
    const existing = file.stations.find((s) => s.url === this.baseUrl);
    if (existing) return existing;
    const { name, hostname: host } = defaultStationName();
    const fresh: StationRecord = {
      url: this.baseUrl,
      token: randomBytes(32).toString('hex'),
      name,
      hostname: host,
      createdAt: new Date().toISOString(),
    };
    writeStationFile(this.file, { version: 1, stations: [...file.stations, fresh] });
    return fresh;
  }

  /** `{ authorization: 'Bench <token>' }` for THIS station's URL only. Throws
   *  `StationFileError` when the station file cannot be read or written. */
  authHeader(): { authorization: string } {
    return { authorization: `Bench ${this.record().token}` };
  }

  private async me(rec: StationRecord): Promise<StationStatus | 'unknown'> {
    const url = `${this.baseUrl}${ME_PATH}`;
    let answer: Answer;
    try {
      const res = await fetch(url, {
        headers: { authorization: `Bench ${rec.token}`, 'cache-control': 'no-store' },
        // Never followed: see the header. A 3xx is answered below.
        redirect: 'manual',
        signal: AbortSignal.timeout(STATION_TIMEOUT_MS),
      });
      const moved = redirectedStatus(res, url, ME_PATH);
      if (moved) {
        await res.text().catch(() => '');
        return moved;
      }
      answer = await readAnswer(res);
    } catch (err) {
      return unreachable(err);
    }
    if (answer.status === 401) return 'unknown';
    if (answer.status === 403) {
      return { state: 'revoked', message: answer.error ?? 'refusé par la plateforme (403)' };
    }
    const known = answer.status === 200 ? knownStation(answer.data) : null;
    if (known) return known;
    return {
      state: 'refused',
      message: `réponse inattendue de /api/bench/stations/me (${answer.status})${answer.error ? ` : ${answer.error}` : ''}`,
    };
  }

  private async register(rec: StationRecord): Promise<StationStatus | null> {
    const url = `${this.baseUrl}${REGISTER_PATH}`;
    let answer: Answer;
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name: rec.name, hostname: rec.hostname, token: rec.token }),
        // A followed 307/308 would re-send this body — the token — to the
        // redirect target. Never followed: see the header.
        redirect: 'manual',
        signal: AbortSignal.timeout(STATION_TIMEOUT_MS),
      });
      const moved = redirectedStatus(res, url, REGISTER_PATH);
      if (moved) {
        await res.text().catch(() => '');
        return moved;
      }
      answer = await readAnswer(res);
    } catch (err) {
      return unreachable(err);
    }
    if (answer.status === 200 || answer.status === 201) {
      if (answer.data?.status === 'revoked') {
        return { state: 'revoked', message: 'ce jeton a été révoqué par un administrateur' };
      }
      return null; // registered (or already was): `/me` gives the full picture
    }
    return {
      state: 'refused',
      message: `l'enregistrement du poste a été refusé (${answer.status})${answer.error ? ` : ${answer.error}` : ''}`,
    };
  }

  /** Where this workstation stands. Registers on the way when needed. Never
   *  throws: a station file that cannot be read or written is `localError`,
   *  so no caller can report it as the platform's answer. */
  async status(): Promise<StationStatus> {
    let rec: StationRecord;
    try {
      rec = this.record();
    } catch (err) {
      return { state: 'localError', message: err instanceof Error ? err.message : String(err) };
    }
    const answer = await this.ask(rec);
    if (answer.state === 'pending' || answer.state === 'approved' || answer.state === 'revoked') this.markAnswered(rec);
    return answer;
  }

  private async ask(rec: StationRecord): Promise<StationStatus> {
    const first = await this.me(rec);
    if (first !== 'unknown') return first;
    const registered = await this.register(rec);
    if (registered) return registered;
    const second = await this.me(rec);
    if (second !== 'unknown') return second;
    return {
      state: 'refused',
      message: 'la plateforme a accepté l\'enregistrement puis ne reconnaît pas le jeton',
    };
  }

  /** Best effort: failing to note the answer only means the address is asked
   *  again at the next launch. */
  private markAnswered(rec: StationRecord): void {
    if (rec.answeredAt) return;
    try {
      const file = readStationFile(this.file);
      const at = new Date().toISOString();
      const stations = file.stations.map((s) => (s.url === rec.url && s.token === rec.token ? { ...s, answeredAt: at } : s));
      writeStationFile(this.file, { version: 1, stations });
    } catch {
      /* see above */
    }
  }

  /**
   * After a revocation, and only then: drop the revoked token, draw a new one,
   * register it. The answer is a NEW pending station that an administrator
   * approves again — the platform keeps a revoked token revoked by design. A
   * station that is not revoked is returned as it is: renewing an approved
   * token would throw away an authorisation somebody gave.
   */
  async renew(): Promise<StationStatus> {
    const current = await this.status();
    if (current.state !== 'revoked') return current;
    try {
      const file = readStationFile(this.file);
      writeStationFile(this.file, {
        version: 1,
        stations: file.stations.filter((s) => s.url !== this.baseUrl),
      });
    } catch (err) {
      return { state: 'localError', message: err instanceof Error ? err.message : String(err) };
    }
    return this.status();
  }
}

/**
 * The URL of the station in this user's station file whose platform answered
 * most recently, or null. This is how an address the preparer typed into the
 * application is remembered. A record nobody answered for (a mistyped or dead
 * address) is never offered back: the address screen asks again. Never
 * throws — an unreadable file simply means no remembered address.
 */
export function lastRegisteredUrl(file: string = stationFilePath()): string | null {
  try {
    const stations = readStationFile(file).stations.filter((s) => typeof s.answeredAt === 'string');
    if (stations.length === 0) return null;
    const newest = stations.reduce((a, b) => (Date.parse(b.answeredAt as string) > Date.parse(a.answeredAt as string) ? b : a));
    return newest.url;
  } catch {
    return null;
  }
}

/**
 * The one sentence the bench application shows for each state. (The console
 * mode that used to print it too is gone: the application is a GUI-subsystem
 * executable with no console — see main.ts.)
 *
 * ── "pending" NAMES THE SCREEN THE ADMINISTRATOR USES ──────────────────────
 * The administrator's half is the page Administration → Postes de préparation
 * (`/manage/bench-stations`, platform admin role), which lists every station
 * with its number and verification code and carries the Approve button. The
 * sentence names that page, the station NUMBER and the code the administrator
 * must check — the name alone proves nothing, anybody can type it. It used to
 * name the raw API because no page existed; that page shipped with this text.
 *
 * ── "unreachable" PROMISES ONLY WHAT THE APPLICATION DOES ──────────────────
 * Until the platform answers AND the station is approved, the application
 * shows no router screen at all and its local server refuses every
 * router-facing request; it asks again every `STATION_POLL_UNREACHABLE_MS`.
 * (It used to say the equipment could still be read meanwhile, which was true
 * of the old engineer form and is not of the gated application.)
 */
export function describeStation(s: StationStatus): string {
  switch (s.state) {
    case 'approved':
      return `Poste autorisé : « ${s.name} » (n° ${s.stationId}${s.verificationCode ? `, code ${s.verificationCode}` : ''}).`;
    case 'pending':
      return (
        `Ce poste attend l'autorisation d'un administrateur. Poste « ${s.name} », n° ${s.stationId}, `
        + (s.verificationCode
          ? `code de vérification ${s.verificationCode}. `
          : '(la plateforme n\'a pas fourni de code de vérification). ')
        + 'Un administrateur de la plateforme l\'approuve dans ObliWAN, menu Administration → '
        + `Postes de préparation, sur le poste n° ${s.stationId}`
        + (s.verificationCode
          ? ` après avoir vérifié qu'il porte ce même code (le nom peut être recopié par n'importe qui)`
          : '')
        + '.'
      );
    case 'revoked':
      return (
        `Ce poste a été révoqué (${s.message}). Son jeton ne servira plus : demandez une nouvelle `
        + 'autorisation — un nouveau jeton sera tiré et devra être approuvé à son tour.'
      );
    case 'unreachable':
      return (
        `ObliWAN ne répond pas (${s.message}). Aucun routeur ne peut être préparé et rien ne sera envoyé `
        + 'tant que la plateforme ne répond pas et que ce poste n\'est pas autorisé. '
        + `Nouvel essai toutes les ${STATION_POLL_UNREACHABLE_MS / 1000} s.`
      );
    case 'redirected':
      return (
        `L'adresse configurée pour ObliWAN répond par une redirection (${s.status}`
        + `${s.location ? ` vers ${s.location}` : ''}). Ce poste ne suit pas de redirection : son `
        + 'jeton ne part qu\'à l\'adresse où il a été enregistré. '
        + (s.suggestedUrl
          ? `Indiquez directement « ${s.suggestedUrl} » comme URL d'ObliWAN.`
          : 'Indiquez directement l\'adresse finale d\'ObliWAN comme URL.')
      );
    case 'localError':
      return (
        `Le jeton de ce poste n'a pas pu être lu ou enregistré sur cet ordinateur (${s.message}). `
        + 'Rien n\'a été envoyé à ObliWAN.'
      );
    case 'refused':
      return `ObliWAN refuse ce poste : ${s.message}`;
  }
}
