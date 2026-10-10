/**
 * ObliWAN — Phenix Partner connector.
 *
 * ┌─ WHERE THESE ENDPOINTS COME FROM, AND WHY THAT MATTERS ───────────────────┐
 * │ Phenix publishes no partner API documentation. The four calls below were  │
 * │ RECONSTRUCTED FROM THE ANGULAR BUNDLE of its extranet, and a field        │
 * │ prototype exercised them against a real account:                          │
 * │                                                                          │
 * │   POST /Auth/authenticate                      {username,password}        │
 * │   POST /Auth/authenticateWithCodeConfirmation  {username,password,code}   │
 * │   GET  /GsmApi/GetCodeClientList               ?partenaireId=<GUID>       │
 * │   GET  /GsmApi/GetLigneGsmByFilterPaged        ?…&codeClient=&pageNumber= │
 * │   POST /GsmApi/GetSdtrConso                    ?partenaireId&msisdn, []   │
 * │                                                                          │
 * │ THE LISTING IS NO LONGER A GUESS: the two listing calls, their parameter  │
 * │ set and their answers were OBSERVED on the production extranet on         │
 * │ 2026-10-06 (a HAR of the operator's session) — see `listLines`. Without a │
 * │ client filter the line endpoint answers 400; with an API-only role, 403.  │
 * │ Its rows carry PUK1, PUK2, the RADIUS password and the RIO, which this    │
 * │ connector hands to the sweep in a `SimLineSecrets` box and to nothing     │
 * │ else.                                                                     │
 * │                                                                          │
 * │ THE FIELD NAMES INSIDE THE RESPONSES ARE NOT CONFIRMED. `restValueGo`,    │
 * │ `usedValueGo`, `libelleZoneText` and the rest were read off the front-end │
 * │ that consumes them, not off a response anybody captured. Everything in    │
 * │ this file is therefore written to survive being wrong about a name:       │
 * │ `pickNumber` tries the known spellings and returns `null` when none       │
 * │ matches, and `null` becomes `unknown`, which never triggers a purchase.   │
 * │                                                                          │
 * │ The failure mode being designed out is specific and was live in the       │
 * │ prototype: `(float) ($row['restValueGo'] ?? 0)` turns a renamed field     │
 * │ into "0 Go left" ON EVERY LINE AT ONCE — a fleet-wide, perfectly          │
 * │ plausible, entirely false emergency.                                      │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE OTP PROBLEM, WHICH IS A PRODUCT PROBLEM AND NOT A BUG ───────────────┐
 * │ A Phenix account may require a one-time code. `authenticate` then fails   │
 * │ and the only way through is `authenticateWithCodeConfirmation`, which     │
 * │ needs a code from a human — and a sweep that runs at 04:00 has no human.  │
 * │                                                                          │
 * │ `token` mode was meant to be the mode that survives that, and it is not:  │
 * │ a Phenix token lives four hours (`expires_in: 14400`, observed) and the   │
 * │ sweep runs every four hours, so a pasted token is stale by the next run.  │
 * │ `password` mode re-authenticates on every `open()`, which makes it the    │
 * │ only mode that sustains itself — once the account's sign-in goes through  │
 * │ from this server at all (see `readAuthenticateResponse`). The token's own │
 * │ `exp` claim is still read and persisted, so the account screen can warn   │
 * │ BEFORE a pasted token dies: an expired token presents exactly like a      │
 * │ healthy fleet with no news.                                               │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * §8.2 — the username, password and token are passed to `RestTransport` as
 * `secrets` and to `SimConnectorError` as `secrets`, so neither a partner error
 * body nor a network failure can carry them into a log or into
 * `sim_sync_runs.error`. Nothing in this file logs a URL: the MSISDN is in the
 * query string and is customer data.
 */

import {
  MB_PER_GB,
  SIM_LINE_SECRET_FIELDS,
  UNKNOWN_ZONE,
  gbToMb,
  type SimIngestionKind,
  type SimLineSecretField,
  type SimLineStatus,
  type SimPartnerRechargeOutcome,
} from '@obliwan/shared';
import { RestTransport } from '../transport/rest.transport';
import { DriverError } from '../drivers/types';
import {
  SimConnectorError,
  SimLineSecrets,
  credentialSecrets,
  scrub,
  type RawPartnerRecharge,
  type RawRechargeOffer,
  type RawSimBalance,
  type RawSimLine,
  type RechargeOfferQuery,
  type SimConnector,
  type SimConnectorContext,
  type SimErrorCode,
  type SimLineListing,
  type SimSession,
} from './types';

const PLATFORM = 'phenix' as const;

/** The host the extranet's own bundle targets. Overridable per account. */
export const PHENIX_DEFAULT_BASE_URL = 'https://phenix-mb-api.netcom-group.fr';

/**
 * Response envelopes seen in the wild for this API, in the order the prototype
 * tried them. A payload matching NONE of these is `UNREADABLE` — deliberately
 * not "zero lines". An empty fleet and an unparseable answer look identical on
 * a dashboard, and only one of them means the sweep should stop.
 */
const LIST_KEYS = ['lines', 'items', 'data', 'result', 'results', 'value', 'lignes'] as const;

// ============================================================================
// Defensive field access
// ============================================================================

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** First present key among the candidates. Absent is `undefined`, never ''. */
function pick(row: Record<string, unknown>, keys: readonly string[]): unknown {
  for (const k of keys) {
    if (Object.prototype.hasOwnProperty.call(row, k)) return row[k];
  }
  return undefined;
}

/**
 * A trimmed string, or `null`.
 *
 * `''` collapses to `null` on purpose: an operator field the partner returned
 * empty is an operator we do not know, and storing `''` would make it match a
 * `skip_operators` entry of `''` and silently stop polling the line.
 */
function pickString(row: Record<string, unknown>, keys: readonly string[]): string | null {
  return asString(pick(row, keys));
}

/** `pickString`'s reading of one value. */
function asString(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  if (typeof v === 'number') return String(v);
  if (typeof v !== 'string') return null;
  const t = v.trim();
  return t === '' ? null : t;
}

/**
 * A quantity in gigabytes → integer MB, or `null` WHEN ANY DOUBT EXISTS.
 *
 * This is the single most consequential function in the file. Returning 0 for
 * a field that is missing, null, empty, non-numeric or negative would announce
 * an exhausted line; returning `null` announces that we do not know, which is
 * what is actually true. There is no fallback value and there must never be.
 */
function pickGb(row: Record<string, unknown>, keys: readonly string[]): number | null {
  const v = pick(row, keys);
  if (typeof v === 'number' || typeof v === 'string') return gbToMb(v);
  return null;
}

/**
 * Rows out of an envelope, or a refusal.
 *
 * The prototype's last resort was `return [$res]` — treat the envelope itself
 * as one row. That turns an error object into a line with no MSISDN and, worse,
 * turns an unrecognised shape into a plausible-looking result. Here an
 * unrecognised shape throws, which the sweep records as a failed run against
 * the account instead of as a fleet that shrank.
 */
function rowsFrom(payload: unknown, what: string): Record<string, unknown>[] {
  if (Array.isArray(payload)) return payload.filter(isRecord);
  if (isRecord(payload)) {
    for (const k of LIST_KEYS) {
      const v = payload[k];
      if (Array.isArray(v)) return v.filter(isRecord);
      // A single-object envelope is legitimate for a one-element page — but
      // ONLY if the object actually looks like a row. `{data: {}}` or
      // `{result: {error: ...}}` would otherwise become one unusable row,
      // which `listLines` then skips for want of an MSISDN: an unreadable
      // answer silently rendered as an EMPTY FLEET, which is the one thing
      // this function's own header says it refuses to do.
      if (isRecord(v) && Object.keys(v).length > 0) return [v];
    }
  }
  throw new SimConnectorError(
    `Phenix ${what}: unrecognised response envelope. The API answered something ` +
      `that is neither a list nor a known wrapper (${LIST_KEYS.join(', ')}), so the ` +
      `result cannot be read. Reporting this as an error rather than as an empty ` +
      `fleet is deliberate.`,
    'UNREADABLE',
    PLATFORM,
  );
}

/**
 * The partner's declared total for a paged listing, when it reports one.
 *
 * Best effort over the spellings these .NET APIs use. `null` means the partner
 * said nothing — which is NOT evidence that the page was complete, and the
 * sweep records that difference rather than assuming the happier reading.
 */
const TOTAL_KEYS = [
  'totalCount', 'TotalCount', 'total', 'Total',
  'totalRecords', 'totalItems', 'recordsTotal', 'nbTotal', 'count',
] as const;

function totalFrom(payload: unknown): number | null {
  if (!isRecord(payload)) return null;
  for (const k of TOTAL_KEYS) {
    const v = payload[k];
    if (typeof v === 'number' && Number.isInteger(v) && v >= 0) return v;
    if (typeof v === 'string' && /^[0-9]+$/.test(v.trim())) return Number(v.trim());
  }
  return null;
}

/** A partner error body as text: a string, or a JSON object's `message`. */
function bodyText(body: unknown): string {
  if (typeof body === 'string') return body;
  if (isRecord(body)) {
    for (const k of ['message', 'Message', 'error', 'errorDescription']) {
      const v = body[k];
      if (typeof v === 'string' && v.trim() !== '') return v;
    }
  }
  return '';
}

// ============================================================================
// Listing pace and bounds
// ============================================================================

/**
 * Lines per page: 300, the largest size the extranet's own page-size selector
 * offers (operator, 2026-10-06; the HAR only showed its default, 25), so a
 * client of up to 300 lines is ONE request and page 2 — never observed — is
 * reached only beyond that. The reasoning kept below was written for 25. 100 would mean four times fewer requests, and it
 * was not chosen: a partner that silently caps a larger size while computing
 * its offset from the size ASKED would serve rows 1-25, 101-125, … The
 * shortfall check would catch it, as a sweep that is `partial` forever. A
 * client with a few hundred lines costs a dozen requests at 25; that is the
 * price of the proven value.
 */
export const PHENIX_PAGE_SIZE = 300;

/** The size the listing asks for. Harnesses set a smaller one so a synthetic
 *  client spans several pages; production never calls the setter. */
let pageSize = PHENIX_PAGE_SIZE;
export function setPhenixPageSizeForTests(size: number | null): void {
  pageSize = size === null ? PHENIX_PAGE_SIZE : size;
}

/**
 * Ceiling on the requests ONE listing may make (the client list included):
 * 2 000 pages of 25 is 50 000 rows, far above any partner fleet this product
 * is meant to read. Above it the listing stops with a named error rather than
 * looping on a partner that does not page.
 */
export const PHENIX_MAX_LIST_REQUESTS = 2000;

/**
 * Pause between two listing requests. Phenix publishes no rate limit, and a
 * sweep is one request per client page — sequential, and polite about it.
 */
export const PHENIX_LIST_PAUSE_MS = 150;

/** The listing ceiling's own refusal: already names where it stopped. */
class ListingCeilingError extends SimConnectorError {}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ============================================================================
// JWT (best effort — a claim we cannot read is a claim we do not use)
// ============================================================================

function b64urlDecode(part: string): string | null {
  try {
    const s = part.replace(/-/g, '+').replace(/_/g, '/');
    const pad = s.length % 4 === 0 ? s : s + '='.repeat(4 - (s.length % 4));
    return Buffer.from(pad, 'base64').toString('utf8');
  } catch {
    return null;
  }
}

function jwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split('.');
  if (parts.length < 2) return null;
  const json = b64urlDecode(parts[1]);
  if (!json) return null;
  try {
    const parsed: unknown = JSON.parse(json);
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * The partner id the token was issued for.
 *
 * Read from the TOKEN rather than trusted from the account row when both exist:
 * a token minted for partner A cannot list partner B's lines, and silently
 * querying with a mismatched id returns an empty page that reads as "this
 * customer has no SIMs".
 */
/** A Phenix partner id: a GUID on the production extranet (observed
 *  2026-10-06: `GetDashboardData?partenaireId=<GUID>`), digits in the older
 *  shape this connector was first written against. */
const PARTNER_REF_RE = /^(?:[0-9]+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;

export function partnerRefFromJwt(token: string): string | null {
  const payload = jwtPayload(token);
  if (!payload) return null;
  // `idPartenaire` is the spelling the extranet itself sends (GetPartenaireParam).
  for (const k of ['PartenaireId', 'partenaireId', 'partner_id', 'PartnerId', 'idPartenaire', 'IdPartenaire']) {
    const v = payload[k];
    if (typeof v === 'number' && Number.isFinite(v)) return String(v);
    if (typeof v === 'string' && PARTNER_REF_RE.test(v.trim())) return v.trim();
  }
  return null;
}

/** `exp` is seconds since the epoch. Null when the token does not carry one. */
export function expiryFromJwt(token: string): string | null {
  const payload = jwtPayload(token);
  const exp = payload?.exp;
  if (typeof exp !== 'number' || !Number.isFinite(exp)) return null;
  return new Date(exp * 1000).toISOString();
}

// ============================================================================
// Session
// ============================================================================

class PhenixSession implements SimSession {
  constructor(
    private readonly rest: RestTransport,
    private readonly token: string,
    readonly partnerRef: string | null,
    readonly tokenExpiresAt: string | null,
    private readonly secrets: string[],
  ) {}

  /** What `learnSecrets` already added to `secrets`: a fleet is thousands of
   *  literals, and an `includes` per literal would be quadratic. */
  private readonly learnt = new Set<string>();

  /**
   * The bearer header, applied to EVERY authenticated request.
   *
   * This getter existed with no caller in the first draft, so both reads went
   * out with no `Authorization` at all and the partner answered 401 on every
   * line — §11.1 motif 2, "a function states a rule and has no caller", caught
   * by `fakePhenixApi` on the first run of `f9-rules.verify.ts`. Both call
   * sites below spread it, and the harness asserts the fake actually SAW a
   * token (`fake.tokensSeen`), so removing it again fails the verification
   * rather than failing silently against a real account.
   */
  private get authHeaders(): Record<string, string> {
    return { Authorization: `Bearer ${this.token}` };
  }

  /**
   * Every session read goes through here, and nothing calls `this.rest.request`
   * directly. See the block in `listLines`: the transport throws on 429 and 5xx
   * instead of returning, so a bare call leaks the request path — MSISDN and
   * all — into the log and into `sim_sync_runs.error`.
   */
  private async request<T>(
    method: 'GET' | 'POST',
    path: string,
    opts: Parameters<RestTransport['request']>[2],
  ): Promise<{ statusCode: number; body: T }> {
    try {
      return await this.rest.request<T>(method, path, opts);
    } catch (err) {
      throw asSimError(err, this.secrets);
    }
  }

  /**
   * Maps a partner HTTP status onto the vocabulary the sweep reasons with.
   *
   * 401/403 is `AUTH_FAILED`, which stops the whole account: continuing would
   * produce one identical failure per line, a `lines_failed` count equal to the
   * fleet size, and an account that looks flaky rather than logged out.
   */
  private fail(status: number, body: string, what: string): never {
    if (status === 401 || status === 403) {
      throw new SimConnectorError(
        `Phenix ${what}: HTTP ${status}. The token is expired or revoked, or the account lacks ` +
          `the role this call needs — an API-only account was observed answering 403 on the line ` +
          `listing, where the partner 'admin' role works (2026-10-06). Check the account's role ` +
          `at Phenix, then sign in again from the account screen.`,
        'AUTH_FAILED',
        PLATFORM,
        { statusCode: status, secrets: this.secrets },
      );
    }
    throw new SimConnectorError(
      // `stripQuery` on the partner's own body too: a 400 from this API has
      // been known to echo the submitted request line back.
      stripQuery(`Phenix ${what}: HTTP ${status} ${body.slice(0, 200)}`),
      'PARTNER_ERROR',
      PLATFORM,
      { statusCode: status, secrets: this.secrets },
    );
  }

  /**
   * The whole inventory, CLIENT BY CLIENT, exactly as the production extranet
   * lists it (HAR of the operator's session, 2026-10-06):
   *
   *   1. `GET /GsmApi/GetCodeClientList?partenaireId=<GUID>` — a JSON array of
   *      client codes (strings shaped like "ZZ0001").
   *   2. for each code, `GET /GsmApi/GetLigneGsmByFilterPaged` with the
   *      extranet's own parameter set, page after page —
   *      `{totalCount, pageNumber, pageSize, lines: [...]}` — until the
   *      client's `totalCount` is collected or a page comes back empty. Only
   *      a PAGE-1 request was observed; see `listClientLines` for what that
   *      leaves unproven.
   *
   * ┌─ WHY NOT ONE CALL ───────────────────────────────────────────────────────┐
   * │ Without a filter the endpoint answers HTTP 400 « Veuillez saisir au      │
   * │ moins un filtre de recherche (Client, MSISDN, SIM SN) ! » (observed). The │
   * │ first draft of this method made exactly that call. So a client code is   │
   * │ ALWAYS sent, a blank one is never queried, and the harness asserts that  │
   * │ no unfiltered call ever reaches the fake.                                │
   * └──────────────────────────────────────────────────────────────────────────┘
   *
   * ┌─ ONE CLIENT FAILING DOES NOT BLIND THE OTHERS — AND IS NAMED ────────────┐
   * │ A failure on one client's page — HTTP, transport, shape — no longer      │
   * │ abandons the account: one broken client among many would otherwise      │
   * │ leave EVERY line unrefreshed, every sweep, for as long as it stays       │
   * │ broken. The other clients are still listed, and the failure is returned │
   * │ by name (`failedClients`: client and page), which makes the sweep        │
   * │ `partial` and says which. That is safe because absence updates nothing:  │
   * │ a line the listing did not carry keeps its row and its last-seen         │
   * │ instant, and is never retired by it. Nothing partial is presented as     │
   * │ complete.                                                                │
   * │                                                                          │
   * │ Three things still stop the whole listing: an AUTH_FAILED (it flags the   │
   * │ account, and the next client would only fail the same way), the request  │
   * │ ceiling, and EVERY client failing — an answer with nothing in it is an   │
   * │ error, not a partial success.                                            │
   * └──────────────────────────────────────────────────────────────────────────┘
   *
   * Requests are SEQUENTIAL with a pause between them (Phenix publishes no
   * rate limit) and bounded (`PHENIX_MAX_LIST_REQUESTS`, a named refusal when
   * exceeded). The page size is 300, the extranet selector's largest — see `PHENIX_PAGE_SIZE`.
   */
  async listLines(): Promise<SimLineListing> {
    if (!this.partnerRef) {
      throw new SimConnectorError(
        'Phenix listLines: no partner id. Set it on the account, or supply a token ' +
          'whose claims carry one — querying without it returns an empty page, which ' +
          'is indistinguishable from a partner with no lines.',
        'CONFIG_ERROR',
        PLATFORM,
      );
    }
    const partnerRef = this.partnerRef;
    const budget = { used: 0 };
    const { codes, blank } = await this.listClientCodes(partnerRef, budget);

    let declaredTotal: number | null = 0;
    let rowsReturned = 0;
    const setAside = { noMsisdn: 0, sameMsisdn: 0, blankClientCodes: blank, withheldFields: [] as string[] };
    const withheld = new Set<string>();
    const kept = new Map<string, RawSimLine>();
    const failedClients: NonNullable<SimLineListing['failedClients']> = [];
    let firstFailed: { code: string; page: number; error: SimConnectorError } | null = null;

    for (const code of codes) {
      const client = await this.listClientLines(partnerRef, code, budget);
      if (client.failed) {
        // Reported apart, and kept OUT of both totals: its declared total was
        // never fully read, and its served rows would offset another client's
        // shortfall (`SimLineListing`). The rows it did serve are still read.
        failedClients.push({
          clientCode: code,
          page: client.failed.page,
          errorCode: client.failed.error.code,
          error: client.failed.error.message,
        });
        firstFailed ??= { code, page: client.failed.page, error: client.failed.error };
      } else {
        rowsReturned += client.rows.length;
        declaredTotal = declaredTotal === null || client.total === null ? null : declaredTotal + client.total;
      }

      for (const r of client.rows) {
        const read = readPhenixLine(r, code);
        for (const f of read.withheldFields) withheld.add(f);
        // Already learnt page by page (`listClientLines`); kept here so no
        // row read into a line can ever skip the scrub list.
        this.learnSecrets(read.secrets);
        if (!read.line) {
          // A row with no number is not a line we can ask about. Skipped rather
          // than stored with a placeholder: a placeholder MSISDN would violate
          // the CHECK on `sim_lines.msisdn` and abort the sweep at that row.
          setAside.noMsisdn += 1;
          continue;
        }
        const other = kept.get(read.line.msisdn);
        if (other) {
          setAside.sameMsisdn += 1;
          if (preferLine(read.line, other)) kept.set(read.line.msisdn, read.line);
          continue;
        }
        kept.set(read.line.msisdn, read.line);
      }
    }

    // ┌─ A FAILED PAGE MAY ECHO A SECRET THE LISTING SERVED AFTER IT ─────────┐
    // │ Each page's secrets are learnt as the page arrives, so an error is    │
    // │ scrubbed of everything served BEFORE it. A partner echoing a PUK or a │
    // │ RIO from a client listed later would still slip through — so every    │
    // │ failure is scrubbed again here, with everything the listing saw, and  │
    // │ the all-failed error is only built now, for the same reason.          │
    // └───────────────────────────────────────────────────────────────────────┘
    for (const f of failedClients) f.error = scrub(f.error, this.secrets);

    // Every client failed: nothing was answered, and "partial" must not cover
    // "nothing worked". The first failure, by name, with its own code.
    if (firstFailed && failedClients.length === codes.length) {
      throw this.clientFailure(
        firstFailed.code,
        firstFailed.page,
        firstFailed.error,
        `and every client's listing failed (${codes.length} of ${codes.length}), so the whole ` +
          `listing is an error rather than an empty fleet`,
      );
    }

    setAside.withheldFields = [...withheld].sort();
    return { lines: [...kept.values()], declaredTotal, rowsReturned, setAside, failedClients };
  }

  /**
   * One listing request, counted against the listing's budget and paced.
   * The ceiling is checked HERE, before the request, so it is one refusal with
   * one sentence wherever it trips.
   */
  private async listingRequest(
    path: string,
    budget: { used: number },
    where: string,
  ): Promise<{ statusCode: number; body: unknown }> {
    if (budget.used >= PHENIX_MAX_LIST_REQUESTS) {
      throw new ListingCeilingError(
        `Phenix listLines: stopped at ${where} after ${PHENIX_MAX_LIST_REQUESTS} requests, the ` +
          `ceiling one listing may make. Either the partner's inventory has outgrown it or the ` +
          `partner is not paging; the listing is abandoned rather than presented as complete.`,
        'PARTNER_ERROR',
        PLATFORM,
        { secrets: this.secrets },
      );
    }
    if (budget.used > 0) await sleep(PHENIX_LIST_PAUSE_MS);
    budget.used += 1;
    return this.request<unknown>('GET', path, { headers: this.authHeaders, expect: 'json' });
  }

  /** `GetCodeClientList`: the partner's client codes, trimmed and distinct. */
  private async listClientCodes(
    partnerRef: string,
    budget: { used: number },
  ): Promise<{ codes: string[]; blank: number }> {
    const qs = new URLSearchParams({ partenaireId: partnerRef });
    const res = await this.listingRequest(`/GsmApi/GetCodeClientList?${qs.toString()}`, budget, 'the client list');
    if (res.statusCode >= 400) {
      this.fail(res.statusCode, bodyText(res.body), 'listLines (GetCodeClientList)');
    }
    if (!Array.isArray(res.body)) {
      throw new SimConnectorError(
        'Phenix listLines: GetCodeClientList answered something that is not a list of client ' +
          'codes. Without that list no line can be listed (the line endpoint refuses a call ' +
          'without a filter), so this is an error rather than an empty fleet.',
        'UNREADABLE',
        PLATFORM,
        { secrets: this.secrets },
      );
    }
    const codes: string[] = [];
    let blank = 0;
    for (const v of res.body) {
      if (typeof v !== 'string' && typeof v !== 'number') {
        throw new SimConnectorError(
          'Phenix listLines: GetCodeClientList carries an entry that is neither a string nor a ' +
            'number. The observed answer is an array of strings; nothing is guessed from another shape.',
          'UNREADABLE',
          PLATFORM,
          { secrets: this.secrets },
        );
      }
      const code = String(v).trim();
      if (code === '') {
        blank += 1;
        continue;
      }
      if (!codes.includes(code)) codes.push(code);
    }
    return { codes, blank };
  }

  /**
   * Every row of ONE client, page by page.
   *
   * A page that is not clean — HTTP, transport, shape, a repeated page — ends
   * THIS client: what it served so far is returned with `failed` saying where
   * and why, and the caller lists the next client. An AUTH_FAILED and the
   * request ceiling are THROWN instead: they end the whole listing.
   */
  private async listClientLines(
    partnerRef: string,
    code: string,
    budget: { used: number },
  ): Promise<{
    rows: Record<string, unknown>[];
    total: number | null;
    failed: { page: number; error: SimConnectorError } | null;
  }> {
    const rows: Record<string, unknown>[] = [];
    const seen = new Set<string>();
    let total: number | null = null;

    for (let pageNumber = 1; ; pageNumber += 1) {
      const where = `client ${code}, page ${pageNumber}`;
      // ┌─ WHAT WAS OBSERVED IS PAGE 1, AND ONLY PAGE 1 ───────────────────────┐
      // │ The parameter set below is the one the extranet sent for a PAGE-1    │
      // │ request (HAR, 2026-10-06), in its order — including the literal      │
      // │ string "undefined" for the unused filters, which is what its Angular │
      // │ client puts on the wire — with `fromPagination=false`. No page-2     │
      // │ request was captured: the extranet may well send                     │
      // │ `fromPagination=true` when the operator turns a page, and nothing    │
      // │ here proves the partner honours `pageNumber` without it. The         │
      // │ observed value is sent on EVERY page because it is the only one      │
      // │ observed; a partner that ignores `pageNumber` unless it is `true`    │
      // │ serves page 1 again, which the repeated-page guard below refuses by  │
      // │ name rather than reading as a complete client.                       │
      // └──────────────────────────────────────────────────────────────────────┘
      // Through URLSearchParams: a client code is partner data, and an
      // unescaped one is a query-string injection into somebody else's API.
      const qs = new URLSearchParams({
        partenaireId: partnerRef,
        partenaireIdFor: partnerRef,
        partenaireFilterId: 'undefined',
        codeClient: code,
        msisdn: 'undefined',
        simsn: 'undefined',
        includeTotalCount: 'true',
        fromPagination: 'false',
        pageNumber: String(pageNumber),
        pageSize: String(pageSize),
      });

      let page: Record<string, unknown>[];
      try {
        const res = await this.listingRequest(`/GsmApi/GetLigneGsmByFilterPaged?${qs.toString()}`, budget, where);
        if (res.statusCode >= 400) {
          this.fail(res.statusCode, bodyText(res.body), `listLines (${where})`);
        }
        // A client the partner DECLARES empty (`totalCount: 0`) is an empty
        // page whatever it puts beside the count — `lines: []` or `lines:
        // null`, the empty answer has not been observed. That is the partner
        // saying "none", not a shape we are guessing at; any other envelope
        // still goes through `rowsFrom`, which refuses what it cannot read.
        page =
          isRecord(res.body) && totalFrom(res.body) === 0 && (res.body.lines === null || res.body.lines === undefined)
            ? []
            : rowsFrom(res.body, `listLines (${where})`);
        // The echoed `pageNumber` / `pageSize` are NOT checked: their meaning
        // (the page asked for? the rows served?) has not been observed, and a
        // wrong guess would refuse every client's last page. A partner that
        // ignores `pageNumber` is caught below by what it serves instead.
        const declared = totalFrom(res.body);
        if (declared !== null) total = declared;
      } catch (err) {
        // The ceiling's own sentence already names where it stopped, and it
        // ends the whole listing.
        if (err instanceof ListingCeilingError) throw err;
        const base = asSimError(err, this.secrets);
        // A dead credential or a missing role fails every client the same way
        // and must flag the account: the whole listing stops, by name.
        if (base.code === 'AUTH_FAILED') {
          throw this.clientFailure(code, pageNumber, base, 'and the whole listing is abandoned');
        }
        return { rows, total, failed: { page: pageNumber, error: base } };
      }

      if (page.length === 0) break;

      // ┌─ THE PAGE'S SECRETS JOIN THE SCRUB LIST NOW, NOT WITH THE CLIENT ──────┐
      // │ Every PUK, RADIUS password and RIO this page served — on a row with a │
      // │ number or without, a duplicate or not — is scrubbed from any LATER     │
      // │ error of this session (§8.2). Learnt when the client was finished,    │
      // │ they came too late for the one error that matters most: page 2 of the │
      // │ same client failing and echoing what page 1 served (seen in the       │
      // │ f9-sim harness, 2026-10-06, with a RIO).                               │
      // └────────────────────────────────────────────────────────────────────────┘
      for (const r of page) this.learnSecrets(readPhenixLine(r, code).secrets);

      // ┌─ A PARTNER THAT IGNORES `pageNumber` MUST NOT LOOK LIKE A FLEET ──────┐
      // │ It would answer page one again and again, and with a `totalCount` of  │
      // │ a few hundred the loop would collect page one ten times and call it   │
      // │ complete. A page that brings nothing new therefore ends the client as │
      // │ a failure, by name. A PARTIAL overlap (a line inserted while we page  │
      // │ shifts the offsets) is deduplicated, and any line that shift hid      │
      // │ shows up as a shortfall against `totalCount` instead of vanishing.    │
      // └──────────────────────────────────────────────────────────────────────┘
      let fresh = 0;
      for (const r of page) {
        const key = rowKey(r, rows.length);
        if (seen.has(key)) continue;
        seen.add(key);
        rows.push(r);
        fresh += 1;
      }
      if (fresh === 0) {
        const repeated = pageNumber === 2 ? 'page 1' : `rows of pages 1-${pageNumber - 1}`;
        return {
          rows,
          total,
          failed: {
            page: pageNumber,
            error: new SimConnectorError(
              `Phenix listLines (${where}): page ${pageNumber} repeated ${repeated}: the partner may ` +
                `expect fromPagination=true beyond page 1 — capture a page-2 request.`,
              'UNREADABLE',
              PLATFORM,
              { secrets: this.secrets },
            ),
          },
        };
      }
      if (total !== null && rows.length >= total) break;
    }
    return { rows, total, failed: null };
  }

  /** A row's secret literals, into this session's scrub list. */
  private learnSecrets(secrets: SimLineSecrets | null): void {
    if (!secrets) return;
    for (const s of secrets.literals()) {
      if (this.learnt.has(s)) continue;
      this.learnt.add(s);
      this.secrets.push(s);
    }
  }

  /** A failure that ends the whole listing, with the client and page named. */
  private clientFailure(code: string, page: number, base: SimConnectorError, outcome: string): SimConnectorError {
    return new SimConnectorError(
      `Phenix listLines stopped at client ${code} (page ${page}), ${outcome}: ${base.message}`,
      base.code,
      PLATFORM,
      { statusCode: base.statusCode, secrets: this.secrets },
    );
  }

  async fetchBalances(msisdn: string): Promise<RawSimBalance[]> {
    if (!this.partnerRef) {
      throw new SimConnectorError(
        'Phenix fetchBalances: no partner id resolved for this account.',
        'CONFIG_ERROR',
        PLATFORM,
      );
    }
    const qs = new URLSearchParams({ partenaireId: this.partnerRef, msisdn });

    // The extranet POSTs an empty consumption list and reads the zones back.
    // `idempotent: false` is not a formality: this is a POST, and
    // `RestTransport` would otherwise replay it on a 429 or a 502.
    const res = await this.request<unknown>(
      'POST',
      `/GsmApi/GetSdtrConso?${qs.toString()}`,
      { headers: this.authHeaders, body: [], expect: 'json', idempotent: false },
    );
    if (res.statusCode >= 400) {
      this.fail(res.statusCode, typeof res.body === 'string' ? res.body : '', 'fetchBalances');
    }

    const rows = rowsFrom(res.body, 'fetchBalances');
    return rows.map((r) => ({
      zone:
        pickString(r, ['libelleZoneText', 'libelleZone', 'zone', 'Zone', 'zoneLabel']) ??
        UNKNOWN_ZONE,
      rechargeMb: pickGb(r, ['rechargeGo', 'RechargeGo', 'rechargeValueGo']),
      usedMb: pickGb(r, ['usedValueGo', 'UsedValueGo', 'consoGo', 'ConsoGo']),
      restMb: pickGb(r, ['restValueGo', 'RestValueGo', 'resteGo', 'ResteGo']),
      // The extranet's zone dropdown is fed from these same rows, and its
      // selected value is what `GetRechargesDataByZone` receives as `codeZone`.
      zoneCode: pickString(r, ['codeZone', 'CodeZone', 'zoneCode', 'idZone']),
    }));
  }

  /**
   * READ-ONLY: the partner's "Historique des recharges data" for one line.
   *
   * `GET /GsmApi/GetRechargeRequests?partenaireId=&msisdn=` — read off the
   * extranet's bundle, where it fills a table whose columns are
   * `dateRecharge, moisAnnee, codeZone, volumeEnMo, codeProduit, etat, statut`.
   * The row shape has not been captured from a live response; every field is
   * read defensively and an unreadable one is `null`.
   *
   * An EMPTY list is a legitimate answer here (a line nobody ever topped up),
   * unlike the inventory listing — but an unrecognised ENVELOPE still throws.
   */
  async listRechargeHistory(msisdn: string): Promise<RawPartnerRecharge[]> {
    if (!this.partnerRef) {
      throw new SimConnectorError(
        'Phenix listRechargeHistory: no partner id resolved for this account.',
        'CONFIG_ERROR',
        PLATFORM,
      );
    }
    const qs = new URLSearchParams({ partenaireId: this.partnerRef, msisdn });
    const res = await this.request<unknown>(
      'GET',
      `/GsmApi/GetRechargeRequests?${qs.toString()}`,
      { headers: this.authHeaders, expect: 'json' },
    );
    if (res.statusCode >= 400) {
      this.fail(res.statusCode, typeof res.body === 'string' ? res.body : '', 'listRechargeHistory');
    }
    // `null`/`''` bodies: the extranet binds the answer straight into a table,
    // so "nothing" plausibly arrives as nothing rather than as `[]`.
    if (res.body === null || res.body === undefined || res.body === '') return [];
    return rowsFrom(res.body, 'listRechargeHistory').map((r) => readPartnerRecharge(r, msisdn));
  }

  /**
   * READ-ONLY: the volumes the partner would sell for one line and zone — the
   * extranet's "Volume" dropdown. Buys nothing.
   *
   * `GET /GsmApi/GetRechargesDataByZone?operateur=&codeZone=&typeOffre=&msisdn=&codeTarifAchat=`
   * — the exact parameter list the extranet sends. A missing offer attribute is
   * sent as '' rather than omitted, because omitting a parameter changes the
   * request and '' is the closest thing to what an unset form field produces.
   */
  async listRechargeOffers(q: RechargeOfferQuery): Promise<RawRechargeOffer[]> {
    const qs = new URLSearchParams({
      operateur: q.operator ?? '',
      codeZone: q.zoneCode,
      typeOffre: q.offerType ?? '',
      msisdn: q.msisdn,
      codeTarifAchat: q.purchaseTariffCode ?? '',
    });
    const res = await this.request<unknown>(
      'GET',
      `/GsmApi/GetRechargesDataByZone?${qs.toString()}`,
      { headers: this.authHeaders, expect: 'json' },
    );
    if (res.statusCode >= 400) {
      this.fail(res.statusCode, typeof res.body === 'string' ? res.body : '', 'listRechargeOffers');
    }
    if (res.body === null || res.body === undefined || res.body === '') return [];
    const out: RawRechargeOffer[] = [];
    for (const r of rowsFrom(res.body, 'listRechargeOffers')) {
      // Without its code an entry cannot be bought, so it cannot be offered.
      const code = pickString(r, ['code', 'Code', 'codeRecharge', 'CodeRecharge', 'id', 'Id']);
      if (!code) continue;
      const label = pickString(r, ['libelle', 'Libelle', 'label', 'libelleRecharge']);
      out.push({ code, label, volumeMb: readOfferVolumeMb(r, label) });
    }
    return out;
  }

  async close(): Promise<void> {
    await this.rest.close();
  }
}

// ============================================================================
// One line of the listing — pure, exported for the harness
// ============================================================================

/**
 * The spellings each typed field is read under. The first of each list is the
 * one observed on the production extranet (2026-10-06); the others are the
 * casings these .NET APIs are known to switch to.
 */
const K = {
  msisdn: ['msisdn', 'Msisdn', 'numero', 'numeroLigne', 'NumeroLigne'],
  operator: ['operateur', 'Operateur', 'operator', 'Operator'],
  clientCode: ['codeClient', 'CodeClient', 'code_client'],
  legacyStatus: ['statut', 'Statut', 'status', 'Status'],
  state: ['etat', 'Etat'],
  stateLabel: ['etatLibelle', 'EtatLibelle'],
  offerType: ['typeOffre', 'TypeOffre', 'offerType'],
  purchaseTariffCode: ['codeTarifAchat', 'CodeTarifAchat', 'tariffCode'],
  partnerLineId: ['id', 'Id', 'idLigne', 'IdLigne'],
  simSerial: ['simsn', 'simSn', 'SimSn', 'simSN'],
  imsi: ['imsi', 'Imsi', 'IMSI'],
  customerName: ['nomClient', 'NomClient'],
  siteLabel: ['siteLibelle', 'SiteLibelle'],
  internalRef: ['refInterne', 'RefInterne'],
  simType: ['typeSim', 'TypeSim'],
  planLabel: ['forfaitGsmLibelle', 'ForfaitGsmLibelle'],
  planCode: ['forfaitGsmCode', 'ForfaitGsmCode'],
  activatedAt: ['dateActivation', 'DateActivation'],
  terminatedAt: ['dateResiliation', 'DateResiliation'],
  dataOnly: ['isDataOnly', 'IsDataOnly'],
  apn: ['apn', 'Apn', 'APN'],
  fixedIp: ['ipFixe', 'IpFixe'],
  hasFixedIp: ['hasIpFixe', 'HasIpFixe'],
  radiusLogin: ['radiusLogin', 'RadiusLogin'],
  nationalMb: ['dataConsoNatEnMo', 'DataConsoNatEnMo'],
  roamingMb: ['dataConsoRomEnMo', 'DataConsoRomEnMo'],
  nationalPrevMonthMb: ['dataConsoNatEnMo_M1', 'DataConsoNatEnMo_M1'],
  roamingPrevMonthMb: ['dataConsoRomEnMo_M1', 'DataConsoRomEnMo_M1'],
} as const;

/** The fields the listing carried before 2026-10-06: a row with nothing else
 *  produces no partner facts, so it does not blank the stored ones. */
const LEGACY_KEYS = new Set<string>(
  [K.msisdn, K.operator, K.clientCode, K.legacyStatus, K.offerType, K.purchaseTariffCode].flat(),
);

type MappedField = keyof typeof K;

/** The typed field each mapped spelling belongs to. A mapped key is kept OUT
 *  of `partner_details` when its value was read into the typed field, so the
 *  jsonb is the remainder and never a second account of a typed column (see
 *  `readPhenixLine` for the values that ARE kept there). */
const FIELD_OF_KEY = new Map<string, MappedField>(
  (Object.entries(K) as Array<[MappedField, readonly string[]]>).flatMap(([field, keys]) =>
    keys.map((k): [string, MappedField] => [k, field]),
  ),
);

/**
 * A field NAME as the secret filter compares it: accents folded, lower-cased,
 * every non-alphanumeric stripped — so `Puk_1`, `PUK-1` and `puk1` are one
 * name, and `Mot_de_passe` is `motdepasse`. A filter that compared raw names
 * let a casing or a separator walk a PUK into `partner_details` in clear.
 */
function secretName(key: string): string {
  return key
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '');
}

/** The four secrets, by NORMALISED name (`secretName`). NEVER in `partner_details`. */
const SECRET_KEYS: Record<string, SimLineSecretField> = {
  puk1: 'puk1',
  puk2: 'puk2',
  radiuspassword: 'radiusPassword',
  rio: 'rio',
};

/**
 * The RIO under any spelling a partner may give it, on the NORMALISED name:
 * `rio`, `RIO`, `codeRio`, `Numero_RIO`, `N° RIO` (→ `nrio`), `rioCode`…
 *
 * OPERATOR DECISION (2026-10-06): « RIO => Secret car sensible as fuck ». A
 * RIO plus the number is all a porting request needs, so it is handled
 * EXACTLY like a PUK — read into the box, encrypted by the sweep, never in
 * `partner_details` — and a second spelling must not walk it into the jsonb
 * in clear. Anchored at both ends on purpose: `scenario` or `rioja` is not a
 * RIO, and a pattern that matched them would move a legitimate field into the
 * vault. Migration 079's CHECK refuses a SUBSET of these names (an optional
 * prefix, `rio`, an optional suffix, at most one `_`, `-` or space between,
 * any case) — never more than this accepts, so the database only ever refuses
 * what this filter would already have caught.
 */
const RIO_NAME = /^(code|numero|num|no|n)?rio(code|numero|num)?$/;

/** The known secret a field NAME carries, or `undefined`. */
function secretFieldOf(key: string): SimLineSecretField | undefined {
  const k = secretName(key);
  return SECRET_KEYS[k] ?? (RIO_NAME.test(k) ? 'rio' : undefined);
}

/**
 * A field NAME that looks like a secret and is not one of the known four.
 * Such a field is WITHHELD — not stored in clear in `partner_details` — and its
 * name is reported, so the day Phenix adds `pin1` it is a decision to take
 * rather than a PIN sitting in a jsonb column readable by every SIM_READ holder.
 * Judged on the NORMALISED name, like `SECRET_KEYS`.
 */
function looksSecret(key: string): boolean {
  const k = secretName(key);
  return /puk/.test(k)
    || /(^|code|sim|num|numero)pin[0-9]*(code)?$/.test(k)
    || /pass(e)?[0-9]*$/.test(k)
    || /(password|passwd|pwd|mdp|motdepasse|secret|token)/.test(k);
}

/** One of the four secrets, or any other secret-looking name. */
function isSecretName(key: string): boolean {
  return secretFieldOf(key) !== undefined || looksSecret(key);
}

/** Past this depth a nested partner value is withheld whole rather than walked. */
const MAX_DETAIL_DEPTH = 16;

/**
 * A partner value bound for `partner_details`, with every secret-looking field
 * of every NESTED object or array withheld — `{ sim: { puk1 } }` would
 * otherwise carry a PUK into the jsonb in clear under an innocent top-level
 * name. Withheld names are reported as paths (`sim.puk1`, array indices folded
 * to `[]`), never with a value. `undefined` means "withhold the whole value".
 */
function withholdNested(value: unknown, path: string, withheld: string[], depth = 0): unknown {
  if (value === null || typeof value !== 'object') return value;
  if (depth >= MAX_DETAIL_DEPTH) {
    withheld.push(`${path} (too deep to inspect)`);
    return undefined;
  }
  if (Array.isArray(value)) {
    const out: unknown[] = [];
    for (const v of value) {
      const kept = withholdNested(v, `${path}[]`, withheld, depth + 1);
      out.push(kept === undefined ? null : kept);
    }
    return out;
  }
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    const p = `${path}.${k}`;
    if (isSecretName(k)) {
      withheld.push(p);
      continue;
    }
    const kept = withholdNested(v, p, withheld, depth + 1);
    if (kept !== undefined) out[k] = kept;
  }
  return out;
}

/** Absent, null, or a string of nothing but whitespace (`Number(' ')` is 0). */
function isBlank(v: unknown): boolean {
  return v === null || v === undefined || (typeof v === 'string' && v.trim() === '');
}

/**
 * A partner consumption figure in MB → number, or `null`.
 *
 * The extranet prints "1234,56" / "0,25" — a FRENCH decimal comma — and ""
 * when it does not know. The string is TRIMMED before anything else, because
 * `Number(' ')` is 0 and a blanked field must not become "0 Mo used" (the SIM
 * trap). Anything that is not a plain non-negative decimal — a thousands
 * separator, a unit, a sign — is `null`: a figure we cannot read is not one we
 * get to guess at. Kept to three decimals, which is what the column stores.
 */
export function parseFrenchDecimalMb(v: unknown): number | null {
  let n: number;
  if (typeof v === 'number') {
    n = v;
  } else if (typeof v === 'string') {
    const t = v.trim();
    if (!/^[0-9]+(?:[.,][0-9]+)?$/.test(t)) return null;
    n = Number(t.replace(',', '.'));
  } else {
    return null;
  }
  if (!Number.isFinite(n) || n < 0) return null;
  return Math.round(n * 1000) / 1000;
}

/** A full ICCID out of a partner serial: 19 or 20 digits, nothing else. */
export function iccidFromSerial(serial: string | null): string | null {
  return serial !== null && /^[0-9]{19,20}$/.test(serial) ? serial : null;
}

/** `true` / `false`, or `null` — never a truthiness guess. */
function pickBool(row: Record<string, unknown>, keys: readonly string[]): boolean | null {
  return asBool(pick(row, keys));
}

/** `pickBool`'s reading of one value. */
function asBool(v: unknown): boolean | null {
  if (typeof v === 'boolean') return v;
  if (typeof v === 'string') {
    const t = v.trim().toLowerCase();
    if (t === 'true') return true;
    if (t === 'false') return false;
  }
  return null;
}

/** One state word → our vocabulary. Accents folded, NEGATIONS FIRST: "inactif"
 *  and "désactivée" contain "actif"/"active", and the first draft read both as
 *  active. */
function statusWord(raw: string | null): SimLineStatus {
  if (!raw) return 'unknown';
  const v = raw.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().trim();
  if (/(deleted|resili|termin|supprim|cancel)/.test(v)) return 'terminated';
  if (/(suspend|inactif|inactive|desactiv|disabled|bloqu)/.test(v)) return 'suspended';
  if (/(actif|active|enabled|en service)/.test(v)) return 'active';
  return 'unknown';
}

/**
 * A line's state, from the code (`etat`: "Active" | "Suspended" | "Deleted"),
 * the label (`etatLibelle`: "Active" | "Suspendue" | "Résiliée") and the older
 * `statut`, whichever the row carries.
 *
 * Defaults to `unknown` rather than `active`: an inactive line reported as
 * active is a line whose zero balance is treated as an emergency for months.
 * Two readings that CONTRADICT each other are `unknown` too — which one is
 * wrong is not ours to pick.
 */
function readStatus(row: Record<string, unknown>): SimLineStatus {
  const known = [K.state, K.stateLabel, K.legacyStatus]
    .map((keys) => statusWord(pickString(row, keys)))
    .filter((s) => s !== 'unknown');
  if (known.length === 0) return 'unknown';
  return known.every((s) => s === known[0]) ? known[0] : 'unknown';
}

/**
 * How each typed field reads ONE raw value — `null` when it cannot. Used to
 * decide whether a mapped key's value made it into its typed field; when it
 * did not, the raw value is kept in `partner_details` (`readPhenixLine`).
 * The older `statut` has no column of its own: it is "read" only when it is a
 * word the status vocabulary recognises.
 */
const FIELD_PARSERS: Record<MappedField, (v: unknown) => unknown> = {
  msisdn: asString,
  operator: asString,
  clientCode: asString,
  legacyStatus: (v) => (statusWord(asString(v)) === 'unknown' ? null : v),
  state: asString,
  stateLabel: asString,
  offerType: asString,
  purchaseTariffCode: asString,
  partnerLineId: asString,
  simSerial: asString,
  imsi: asString,
  customerName: asString,
  siteLabel: asString,
  internalRef: asString,
  simType: asString,
  planLabel: asString,
  planCode: asString,
  activatedAt: parsePartnerDate,
  terminatedAt: parsePartnerDate,
  dataOnly: asBool,
  apn: asString,
  fixedIp: asString,
  hasFixedIp: asBool,
  radiusLogin: asString,
  nationalMb: parseFrenchDecimalMb,
  roamingMb: parseFrenchDecimalMb,
  nationalPrevMonthMb: parseFrenchDecimalMb,
  roamingPrevMonthMb: parseFrenchDecimalMb,
};

/** The spelling `pick` reads for a field: the first one present in the row. */
function pickedKey(row: Record<string, unknown>, keys: readonly string[]): string | undefined {
  return keys.find((k) => Object.prototype.hasOwnProperty.call(row, k));
}

export interface PhenixLineReading {
  /** Null when the row carries no MSISDN. */
  line: RawSimLine | null;
  /** The row's secrets, read even when it has no number (to be scrubbed). */
  secrets: SimLineSecrets | null;
  /** Secret-looking field NAMES withheld from `partner_details`. */
  withheldFields: string[];
}

/**
 * One row of `GetLigneGsmByFilterPaged` → a line, KEEPING EVERYTHING
 * (operator decision, 2026-10-06): typed facts for what the product reads,
 * `details` for every other non-secret field verbatim, and the four secrets
 * (PUK1, PUK2, RADIUS password, RIO) in a `SimLineSecrets` box the sweep
 * encrypts.
 *
 * ┌─ NOTHING OBSERVED IS LOST, NOTHING SECRET IS KEPT IN CLEAR ──────────────┐
 * │ · A mapped field whose raw value is NOT blank but does not read into its │
 * │   typed column — `isDataOnly: 1` or "Oui", a consumption "1 024,50", a   │
 * │   date in an unknown form — keeps its raw value in `details`, under its  │
 * │   own key: a typed `null` beside a discarded value would be a reading    │
 * │   the partner gave and nobody can see. So does a second spelling of a    │
 * │   field that `pick` did not read (its first spelling won).               │
 * │ · Secret names are compared NORMALISED (`secretName`), and every nested  │
 * │   object or array headed for `details` is walked: a secret-looking field │
 * │   at any depth is withheld and only its NAME reported.                    │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * `queriedClientCode` fills the client code when the row omits it: the row
 * was listed under that client.
 */
export function readPhenixLine(row: Record<string, unknown>, queriedClientCode: string | null): PhenixLineReading {
  const secretValues = Object.fromEntries(SIM_LINE_SECRET_FIELDS.map((f) => [f, null])) as Record<
    SimLineSecretField,
    string | null
  >;
  let anySecret = false;
  const withheldFields: string[] = [];
  const details: Record<string, unknown> = {};
  let extended = false;
  /** Into `details`, with any nested secret withheld on the way. */
  const keep = (key: string, value: unknown): void => {
    const kept = withholdNested(value, key, withheldFields);
    if (kept !== undefined) details[key] = kept;
  };

  for (const key of Object.keys(row)) {
    const secret = secretFieldOf(key);
    if (secret) {
      const v = row[key];
      const s = typeof v === 'string' ? v.trim() : typeof v === 'number' ? String(v) : '';
      if (s !== '') {
        // Two spellings of one secret: the first non-empty one is the value.
        if (secretValues[secret] === null) secretValues[secret] = s;
        anySecret = true;
      } else if (!isBlank(v)) {
        // A secret field holding something that is not a plain value (an
        // object, a boolean): not read, not stored — reported by name.
        withheldFields.push(key);
      }
      extended = true;
      continue;
    }
    if (!LEGACY_KEYS.has(key)) extended = true;
    if (looksSecret(key)) {
      withheldFields.push(key);
      continue;
    }
    const field = FIELD_OF_KEY.get(key);
    if (field === undefined) {
      keep(key, row[key]);
      continue;
    }
    // A mapped key: out of `details` only when its value really reached the
    // typed field — it is the spelling `pick` reads, and it was blank or read.
    const raw = row[key];
    if (isBlank(raw)) continue;
    const consumed = pickedKey(row, K[field]) === key;
    if (!consumed || FIELD_PARSERS[field](raw) === null) keep(key, raw);
  }
  const secrets = anySecret ? new SimLineSecrets(secretValues) : null;

  const msisdn = pickString(row, K.msisdn);
  if (!msisdn) return { line: null, secrets, withheldFields };

  const simSerial = pickString(row, K.simSerial);
  const line: RawSimLine = {
    msisdn,
    operator: pickString(row, K.operator),
    clientCode: pickString(row, K.clientCode) ?? queriedClientCode,
    iccid: iccidFromSerial(simSerial),
    status: readStatus(row),
    // The two keys the extranet passes to `GetRechargesDataByZone`, read
    // off the same line object its "Recharger" panel uses.
    offerType: pickString(row, K.offerType),
    purchaseTariffCode: pickString(row, K.purchaseTariffCode),
  };
  if (secrets) line.secrets = secrets;
  if (extended) {
    line.partner = {
      partnerLineId: pickString(row, K.partnerLineId),
      simSerial,
      imsi: pickString(row, K.imsi),
      customerName: pickString(row, K.customerName),
      siteLabel: pickString(row, K.siteLabel),
      internalRef: pickString(row, K.internalRef),
      state: pickString(row, K.state),
      stateLabel: pickString(row, K.stateLabel),
      simType: pickString(row, K.simType),
      planLabel: pickString(row, K.planLabel),
      planCode: pickString(row, K.planCode),
      activatedAt: parsePartnerDate(pick(row, K.activatedAt)),
      terminatedAt: parsePartnerDate(pick(row, K.terminatedAt)),
      dataOnly: pickBool(row, K.dataOnly),
      apn: pickString(row, K.apn),
      fixedIp: pickString(row, K.fixedIp),
      hasFixedIp: pickBool(row, K.hasFixedIp),
      radiusLogin: pickString(row, K.radiusLogin),
      consumption: {
        nationalMb: parseFrenchDecimalMb(pick(row, K.nationalMb)),
        roamingMb: parseFrenchDecimalMb(pick(row, K.roamingMb)),
        nationalPrevMonthMb: parseFrenchDecimalMb(pick(row, K.nationalPrevMonthMb)),
        roamingPrevMonthMb: parseFrenchDecimalMb(pick(row, K.roamingPrevMonthMb)),
      },
      details,
    };
  }
  return { line, secrets, withheldFields };
}

/**
 * Two rows for one MSISDN (a number re-let after a termination, listed under
 * two clients): which one is the line. A live subscription beats an unknown
 * one, which beats a terminated one; then the later activation; then the row
 * already kept.
 */
function preferLine(candidate: RawSimLine, current: RawSimLine): boolean {
  const rank = (l: RawSimLine): number =>
    l.status === 'active' || l.status === 'suspended' ? 3 : l.status === 'unknown' ? 2 : 1;
  if (rank(candidate) !== rank(current)) return rank(candidate) > rank(current);
  const a = candidate.partner?.activatedAt ?? null;
  const b = current.partner?.activatedAt ?? null;
  return a !== null && (b === null || a > b);
}

/** The identity of a row within one client's pages, for the paging guard. */
function rowKey(r: Record<string, unknown>, position: number): string {
  const id = pickString(r, K.partnerLineId);
  if (id !== null) return `id:${id}`;
  const msisdn = pickString(r, K.msisdn);
  if (msisdn !== null) return `ms:${msisdn}|${pickString(r, K.simSerial) ?? ''}`;
  return `row:${position}`;
}

// ============================================================================
// Recharge history and catalogue — pure readers, exported for the harness
// ============================================================================

/**
 * A volume label as the extranet prints it — "250 Mo", "5 GO", "1,5 Go" — to
 * integer MB. `null` for anything else: a label we cannot read is a volume we
 * do not know, and a guessed volume on a purchase screen is a wrong purchase.
 */
export function parseVolumeLabelMb(label: string | null | undefined): number | null {
  if (!label) return null;
  const m = /^\s*([0-9]+(?:[.,][0-9]+)?)\s*(mo|mb|go|gb|to|tb)\s*$/i.exec(label);
  if (!m) return null;
  const n = Number(m[1].replace(',', '.'));
  if (!Number.isFinite(n) || n <= 0) return null;
  const unit = m[2].toLowerCase();
  const mb = unit === 'mo' || unit === 'mb' ? n : unit === 'go' || unit === 'gb' ? n * MB_PER_GB : n * MB_PER_GB * MB_PER_GB;
  const r = Math.round(mb);
  return r > 0 ? r : null;
}

function readOfferVolumeMb(r: Record<string, unknown>, label: string | null): number | null {
  const v = pick(r, ['volumeEnMo', 'VolumeEnMo', 'volumeMo', 'volume']);
  const n = typeof v === 'number' ? v : typeof v === 'string' && v.trim() !== '' ? Number(v.trim()) : NaN;
  if (Number.isFinite(n) && n > 0) return Math.round(n);
  return parseVolumeLabelMb(label);
}

/** Offset of Europe/Paris from UTC, in minutes, at a given UTC instant. */
function parisOffsetMinutes(utcMs: number): number {
  try {
    const part = new Intl.DateTimeFormat('en-US', {
      timeZone: 'Europe/Paris',
      timeZoneName: 'shortOffset',
    })
      .formatToParts(new Date(utcMs))
      .find((p) => p.type === 'timeZoneName')?.value;
    const m = part ? /GMT([+-])(\d{1,2})(?::(\d{2}))?/.exec(part) : null;
    if (!m) return 0;
    const sign = m[1] === '-' ? -1 : 1;
    return sign * (Number(m[2]) * 60 + Number(m[3] ?? 0));
  } catch {
    return 0;
  }
}

/**
 * A partner timestamp to ISO, or `null`.
 *
 * Accepts ISO 8601, the .NET `/Date(ms)/` form, and the French wall-clock the
 * extranet displays ("22/08/2026 17:30:16"). The last one carries no zone; it
 * is read as Europe/Paris, which is where the partner's clock is.
 */
export function parsePartnerDate(v: unknown): string | null {
  if (typeof v !== 'string') return null;
  const t = v.trim();
  if (t === '') return null;
  const dotnet = /^\/Date\((-?\d+)\)\/$/.exec(t);
  if (dotnet) {
    const d = new Date(Number(dotnet[1]));
    return Number.isNaN(d.getTime()) ? null : d.toISOString();
  }
  const fr = /^(\d{2})\/(\d{2})\/(\d{4})(?:[ T](\d{2}):(\d{2})(?::(\d{2}))?)?$/.exec(t);
  if (fr) {
    const [, dd, mm, yyyy, hh = '00', mi = '00', ss = '00'] = fr;
    return parisWallClock(yyyy, mm, dd, hh, mi, ss);
  }
  // ┌─ AN ISO DATE WITH NO OFFSET IS PARIS WALL-CLOCK, NOT SERVER-LOCAL ─────┐
  // │ The listing says `dateActivation: "2021-03-04T10:20:30"` (the shape    │
  // │ observed 2026-10-06): a .NET DateTime with no zone. `new Date()` reads │
  // │ that in the SERVER's zone, so the same row gave one instant in a UTC   │
  // │ container and another on a Paris workstation. It is the partner's      │
  // │ clock, like the French form above. A string WITH an offset or a `Z` is │
  // │ unchanged.                                                             │
  // └────────────────────────────────────────────────────────────────────────┘
  const isoLocal = /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?)?$/.exec(t);
  if (isoLocal) {
    const [, yyyy, mm, dd, hh = '00', mi = '00', ss = '00'] = isoLocal;
    return parisWallClock(yyyy, mm, dd, hh, mi, ss);
  }
  if (/^\d{4}-\d{2}-\d{2}/.test(t)) {
    const d = new Date(t);
    return Number.isNaN(d.getTime()) ? null : d.toISOString();
  }
  return null;
}

/** A Europe/Paris wall-clock reading → ISO UTC, or null for an impossible one. */
function parisWallClock(yyyy: string, mm: string, dd: string, hh: string, mi: string, ss: string): string | null {
  const [y, mo, da, h, mn, se] = [yyyy, mm, dd, hh, mi, ss].map(Number);
  if (h > 23 || mn > 59 || se > 59) return null;
  const wall = Date.UTC(y, mo - 1, da, h, mn, se);
  // Reject 31/02 and friends rather than letting Date roll them forward.
  const check = new Date(wall);
  if (check.getUTCFullYear() !== y || check.getUTCMonth() !== mo - 1 || check.getUTCDate() !== da) {
    return null;
  }
  // Two passes so an instant near a DST change resolves to the right offset.
  let utc = wall - parisOffsetMinutes(wall) * 60_000;
  utc = wall - parisOffsetMinutes(utc) * 60_000;
  return new Date(utc).toISOString();
}

/** "08/2026" or "2026-08" → "2026-08"; anything else → null. */
export function parsePartnerPeriod(v: unknown): string | null {
  if (typeof v !== 'string' && typeof v !== 'number') return null;
  const t = String(v).trim();
  let m = /^(\d{1,2})\/(\d{4})$/.exec(t);
  if (m) {
    const mo = Number(m[1]);
    return mo >= 1 && mo <= 12 ? `${m[2]}-${String(mo).padStart(2, '0')}` : null;
  }
  m = /^(\d{4})-(\d{2})$/.exec(t);
  if (m) {
    const mo = Number(m[2]);
    return mo >= 1 && mo <= 12 ? `${m[1]}-${m[2]}` : null;
  }
  return null;
}

/**
 * Our reading of the partner's status column.
 *
 * Only an explicit "OK" is `ok` — observed on the extranet next to every
 * purchase that went through. Anything that says it is waiting is `pending`
 * (the partner has its own manager-validation step, whose answer to a top-up is
 * `Validation-Recharge-En-Attente`). An explicit refusal is `failed`. Every
 * other value, including a blank, is `unknown` — and `unknown` never settles a
 * billing record.
 */
export function partnerRechargeOutcome(status: string | null): SimPartnerRechargeOutcome {
  if (!status) return 'unknown';
  const v = status.trim().toLowerCase();
  if (v === 'ok' || v === 'valide' || v === 'validé' || v === 'effectue' || v === 'effectué') return 'ok';
  if (/attente|pending|en cours|waiting/.test(v)) return 'pending';
  if (/^ko$|erreur|error|echec|échec|refus|annul|rejet|fail/.test(v)) return 'failed';
  return 'unknown';
}

function readPartnerRecharge(r: Record<string, unknown>, msisdn: string): RawPartnerRecharge {
  const requestedAt = parsePartnerDate(pick(r, ['dateRecharge', 'DateRecharge', 'dateCreation', 'date']));
  const period = parsePartnerPeriod(pick(r, ['moisAnnee', 'MoisAnnee', 'periode']));
  const zoneCode = pickString(r, ['codeZone', 'CodeZone', 'zone']);
  const rawVol = pick(r, ['volumeEnMo', 'VolumeEnMo', 'volume']);
  const volNum =
    typeof rawVol === 'number' ? rawVol : typeof rawVol === 'string' && rawVol.trim() !== '' ? Number(rawVol.trim()) : NaN;
  const volumeMb = Number.isFinite(volNum) && volNum > 0 ? Math.round(volNum) : null;
  const productCode = pickString(r, ['codeProduit', 'CodeProduit', 'typeVolume', 'option']);
  const partnerState = pickString(r, ['etat', 'Etat']);
  const partnerStatus = pickString(r, ['statut', 'Statut', 'status']);
  const id = pickString(r, ['id', 'Id', 'idRecharge', 'rechargeId']);
  // No id: a key built from the row's own content, so the same row re-read on
  // the next sweep lands on the same key and inserts nothing.
  const partnerRef =
    id !== null
      ? `id:${id}`
      : `row:${[msisdn, requestedAt ?? '', period ?? '', zoneCode ?? '', volumeMb ?? '', productCode ?? ''].join('|')}`;
  return {
    partnerRef,
    requestedAt,
    period,
    zoneCode,
    volumeMb,
    productCode,
    partnerState,
    partnerStatus,
    outcome: partnerRechargeOutcome(partnerStatus),
  };
}

// ============================================================================
// Connector
// ============================================================================

class PhenixConnector implements SimConnector {
  readonly platform = PLATFORM;
  readonly ingestion: readonly SimIngestionKind[] = ['pull'];

  async open(ctx: SimConnectorContext): Promise<SimSession> {
    const secrets = credentialSecrets(ctx.credential);
    const host = ctx.baseUrl ?? PHENIX_DEFAULT_BASE_URL;
    const rest = new RestTransport({
      baseUrl: host,
      timeoutMs: ctx.timeoutMs ?? 30_000,
      retries: 2,
      // Public CA-signed host: verification on, nothing pinned. This is NOT the
      // on-box appliance case `rest.transport` pins for.
      tls: { rejectUnauthorized: true },
      secrets,
    });

    try {
      const token =
        ctx.credential.authMode === 'token'
          ? ctx.credential.token
          : await authenticateWithPassword(rest, host, ctx.credential.username, ctx.credential.password, secrets);

      // ┌─ THE OBTAINED TOKEN IS A SECRET TOO ────────────────────────────────┐
      // │ In `token` mode it is already in `secrets` (it IS the credential).  │
      // │ In `password` mode the first draft's `secrets` held only the        │
      // │ username and password, so the bearer token minted by                │
      // │ `/Auth/authenticate` — which grants the same access — was NOT       │
      // │ scrubbed from any later error, and this file's own §8.2 header was  │
      // │ therefore false for exactly one of its two modes. Added here rather │
      // │ than at each throw site, for the same reason `SimConnectorError`    │
      // │ scrubs in its constructor: a rule nobody can forget.                │
      // └────────────────────────────────────────────────────────────────────┘
      const sessionSecrets = secrets.includes(token) ? secrets : [...secrets, token];

      // The token's own claim wins over the stored partner id when it has one.
      const partnerRef = partnerRefFromJwt(token) ?? ctx.partnerRef;
      return new PhenixSession(rest, token, partnerRef, expiryFromJwt(token), sessionSecrets);
    } catch (err) {
      // The session never took ownership of the pool, so close it here or the
      // undici agent leaks one socket set per failed sweep — on a broken
      // account that is one leak every four hours, forever.
      await rest.close().catch(() => undefined);
      throw asSimError(err, secrets);
    }
  }
}

// ============================================================================
// /Auth/authenticate — ONE reading, for the sweep and for the sign-in screen
// ============================================================================

/** The top-level keys a token is looked for under. See the block below. */
const TOKEN_KEYS = ['access_token', 'accessToken', 'token'] as const;

/**
 * The token, read the one way every sign-in call reads it: the first of
 * `TOKEN_KEYS` that is present and not null, if it is a non-blank string.
 */
function tokenFrom(body: unknown): string | null {
  if (!isRecord(body)) return null;
  const v = TOKEN_KEYS.map((k) => body[k]).find((x) => x !== undefined && x !== null);
  return typeof v === 'string' && v.trim() !== '' ? v.trim() : null;
}

/**
 * A response body by its SHAPE — field names, never values: a value could be
 * the token itself (§8.2). Lets the first unexpected answer document itself
 * instead of leaving the next reader to guess again.
 */
function describeAuthBody(body: unknown): string {
  if (body === undefined) return 'an empty body';
  if (isRecord(body)) {
    const keys = Object.keys(body);
    return keys.length === 0 ? 'an empty JSON object' : `fields: ${keys.slice(0, 12).join(', ')}`;
  }
  if (Array.isArray(body)) return 'a JSON array';
  return body === null ? 'JSON null' : `a JSON ${typeof body}`;
}

type AuthenticateReading =
  | { kind: 'token'; token: string }
  | { kind: 'challenge'; statusCode: number; observed: string };

/**
 * What `/Auth/authenticate` answered, read ONCE for both of its callers.
 *
 * ┌─ WHY ONE READER ──────────────────────────────────────────────────────────┐
 * │ The sweep and Test (`open()` → `authenticateWithPassword`) and the        │
 * │ interactive sign-in (`phenixAuthenticateAttempt`) make the SAME call with │
 * │ the SAME body, and they used to read its answer in opposite ways. A 400   │
 * │ was a generic partner error on the sweep — so a rotated password left the │
 * │ account `active`, dialled with a dead credential every four hours, with   │
 * │ no alert — while the sign-in screen called it a refusal of the            │
 * │ credentials. A 204 was a one-time-code challenge on the sweep, which sent │
 * │ the operator to a sign-in screen that then called the same 204 "no code   │
 * │ is sent". Two readings of one answer are free to disagree, and they did.  │
 * │                                                                          │
 * │ The ONE divergence left is deliberate and lives in the callers: a 401 or  │
 * │ 403 is a dead end for an unattended sweep and a code field for a human.   │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE THREE ANSWERS, OBSERVED ON THE LIVE API ─────────────────────────────┐
 * │ Against the live API at netcom-group, with the request body the extranet  │
 * │ itself sends ({username, password} — confirmed byte for byte from the     │
 * │ browser's payload):                                                       │
 * │                                                                          │
 * │   200 + body  the real account, signing in from the operator's BROWSER:   │
 * │               the token is in a 7 937-byte body, `expires_in: 14400`.     │
 * │   204 empty   the SAME account, signing in from THIS SERVER: no token, no │
 * │               error — and NO EMAIL IS SENT. The account holder's mailbox  │
 * │               was checked.                                                │
 * │   400 + body  {"message":"Une erreur technique est survenue!",            │
 * │               "errorDescription":""} — an account Phenix does not know.   │
 * │                                                                          │
 * │ The 400 was reproduced from a second machine with a deliberately invalid │
 * │ account, which is how it was separated from the 204: the same request    │
 * │ differs ONLY in whether the account exists. Whether a WRONG PASSWORD on a │
 * │ real account also answers 400 has not been observed. It is read as a     │
 * │ refusal of the credentials anyway, because the only other 400s seen came  │
 * │ from malformed bodies, and the body sent here is fixed.                   │
 * │                                                                          │
 * │ `publicKey` — a GUID header the extranet sends — was tested and changes   │
 * │ nothing: the API answers identically with and without it, and a real 204 │
 * │ was obtained without ever sending it. It is not required, so it is not    │
 * │ sent.                                                                     │
 * │                                                                          │
 * │ The KEY the browser's token sits under has not been recorded. Only the    │
 * │ three top-level spellings in `TOKEN_KEYS` are looked for, and a 2xx that  │
 * │ carries none of them is UNREADABLE, with its field names in the message.  │
 * │ It is never reported as "a code was sent": the one 2xx-without-a-token    │
 * │ ever observed — the 204 — sent nothing.                                   │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE EMPTY 204, AND EVERYTHING THAT HAS BEEN RULED OUT ───────────────────┐
 * │ Phenix answers `204 No Content`, with no body and no headers beyond       │
 * │ `server: nginx` and an `x-correlation-id`, to a VALID account signing in  │
 * │ from this server. Established by elimination, each step run against the   │
 * │ live API:                                                                 │
 * │                                                                          │
 * │  · Not the request shape — an unknown account, `{}`, no body and a        │
 * │    chunked body answer 400, 400, 411, 400. The body we send is            │
 * │    byte-for-byte the extranet's own, read from its network panel.         │
 * │  · Not the host — same URL the browser calls, confirmed from its Request  │
 * │    URL.                                                                   │
 * │  · Not a header — `publicKey`, Origin, Referer and a browser User-Agent   │
 * │    change nothing.                                                        │
 * │  · Not the network — the same call FROM THE CONTAINER gets 400 for an     │
 * │    unknown account, so the request reaches netcom-group.                  │
 * │  · Not our HTTP client — Node's `fetch` IS undici, the same engine        │
 * │    `RestTransport` uses, and it gets the same 204.                        │
 * │                                                                          │
 * │ What is left is the account's own state at Phenix: the credentials look  │
 * │ accepted (an unknown account gets 400) and nothing is issued. The browser │
 * │ gets 200 and a full payload with the same body, so the difference is the  │
 * │ CALLER, not the call. A device-trust gate is the working hypothesis; only │
 * │ Phenix can confirm it, and `x-correlation-id` is what lets them find this │
 * │ exact call.                                                               │
 * │                                                                          │
 * │ So the 204 is a PARTNER_ERROR on both paths, never AUTH_FAILED: nothing   │
 * │ says the credentials are wrong, and re-typing them changes nothing. On    │
 * │ the sweep that keeps the account `active`: every run records this message │
 * │ in `sim_sync_runs` and on the account, and polling resumes by itself the  │
 * │ day Phenix lifts the gate. The price is that tenants get no alert, only   │
 * │ lines whose readings go stale.                                            │
 * │                                                                          │
 * │ Only an empty 204 gets that diagnosis. The elimination above was run on a │
 * │ 204; a 200 with a body nobody can read, or a redirect, was not part of    │
 * │ it, and telling an operator "the network and the host are fine" about a  │
 * │ redirect blames Phenix for what is exactly a host problem.                │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * A 3xx is CONFIGURATION: `RestTransport` follows no redirect, and a redirect
 * says nothing about the credentials — only that the account's base URL is not
 * the API itself.
 */
function readAuthenticateResponse(
  res: { statusCode: number; headers: Record<string, string | string[] | undefined>; body: unknown },
  host: string,
  secrets: string[],
): AuthenticateReading {
  const status = res.statusCode;
  const shape = describeAuthBody(res.body);
  const refusal = (message: string, code: SimErrorCode): SimConnectorError =>
    new SimConnectorError(message, code, PLATFORM, { statusCode: status, secrets });

  if (status >= 200 && status < 300) {
    const token = tokenFrom(res.body);
    if (token !== null) return { kind: 'token', token };

    if (status === 204 && res.body === undefined) {
      const correlation = res.headers['x-correlation-id'];
      const ref = typeof correlation === 'string' ? ` Phenix call reference: ${correlation}.` : '';
      throw refusal(
        `Phenix answered HTTP 204 with an empty body from ${host}: no token, and no refusal either ` +
          `(an account Phenix does not know gets HTTP 400 here). The credentials look accepted and ` +
          `nothing was issued, and no one-time code is sent. This exact answer has been observed for ` +
          `a valid account that got a token from Phenix's own extranet in a browser, with no code ` +
          `reaching its holder's mailbox: the difference is on Phenix's side, and only they can ` +
          `explain it.${ref}`,
        'PARTNER_ERROR',
      );
    }
    throw refusal(
      `Phenix answered HTTP ${status} from ${host} with ${shape}, and no usable token under ` +
        `${TOKEN_KEYS.join(', ')}. That is neither a sign-in nor a code challenge anyone has ` +
        `observed from this API, so nothing is inferred from it.`,
      'UNREADABLE',
    );
  }

  if (status >= 300 && status < 400) {
    const location = res.headers.location;
    const target =
      typeof location === 'string' && location.trim() !== ''
        ? `, redirecting to ${stripQuery(location.trim())}`
        : '';
    throw refusal(
      `Phenix authenticate: HTTP ${status} from ${host}${target}. A redirect says nothing about the ` +
        `credentials: the account's base URL is not answering as the API itself (an http:// ` +
        `address, a wrong path, or a proxy in the way). Correct the base URL on the account.`,
      'CONFIG_ERROR',
    );
  }

  if (status === 400) {
    throw refusal(
      `Phenix refused these credentials (HTTP 400 from ${host}). That is how it refuses an account ` +
        `it does not know, with a reply ("a technical error occurred") that says nothing more ` +
        `precise: check the username and password.`,
      'AUTH_FAILED',
    );
  }

  if (status === 401 || status === 403) {
    return { kind: 'challenge', statusCode: status, observed: `HTTP ${status}; ${shape}` };
  }

  throw refusal(`Phenix authenticate: HTTP ${status} from ${host}`, 'PARTNER_ERROR');
}

/**
 * `password` mode's sign-in, run by `open()` — so by every sweep and every Test.
 *
 * The answer is read by `readAuthenticateResponse`, exactly as the sign-in
 * screen reads it. The one decision taken here is that a 401/403 is a dead end:
 * nobody is present to type a code.
 */
async function authenticateWithPassword(
  rest: RestTransport,
  host: string,
  username: string,
  password: string,
  secrets: string[],
): Promise<string> {
  const res = await rest.request<unknown>('POST', '/Auth/authenticate', {
    body: { username, password },
    expect: 'json',
    idempotent: false,
  });
  const reading = readAuthenticateResponse(res, host, secrets);
  if (reading.kind === 'challenge') {
    throw new SimConnectorError(
      `Phenix authenticate: HTTP ${reading.statusCode} from ${host}. Either the credentials are ` +
        `wrong, or this account requires a one-time code, which an unattended sweep cannot answer. ` +
        `Complete the sign-in from the account's credential screen: it asks for the code when the ` +
        `partner wants one.`,
      'AUTH_FAILED',
      PLATFORM,
      { statusCode: reading.statusCode, secrets },
    );
  }
  return reading.token;
}

/**
 * The FIRST half of the interactive sign-in: try the credentials, and report
 * whether the partner answered with a token or with a challenge.
 *
 * ┌─ WHY THIS EXISTS, AND WHY IT COULD NOT BE ONE CALL ──────────────────────┐
 * │ The one-time code arrives BY EMAIL, and an email is only sent once       │
 * │ somebody asks to sign in. So a screen that asks for username, password   │
 * │ AND code in one go is unusable: the operator has no code yet, and        │
 * │ nothing in this product had ever triggered the message. That form works  │
 * │ for a TOTP authenticator — which mints a code offline — and for nothing  │
 * │ else. `/Auth/authenticate` IS the trigger, so it has to be reachable on  │
 * │ its own.                                                                 │
 * │                                                                          │
 * │ The challenge is understood to be a DEVICE-TRUST bootstrap — first       │
 * │ sign-in from an unknown machine — rather than a per-login requirement.   │
 * │ If that holds, this flow is walked ONCE and `password` mode then runs    │
 * │ unattended forever. It matters because a Phenix token lives 4 h          │
 * │ (`expires_in: 14400`, observed) while the sweep runs every 4 h: a        │
 * │ hand-pasted token is stale by the next sweep, so `password` is the only  │
 * │ mode that sustains itself.                                              │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ── THE 401 IS GENUINELY AMBIGUOUS, AND IS REPORTED AS SUCH ─────────────────
 * Nobody has ever observed what this endpoint answers when it wants a code. A
 * refusal may equally mean "wrong password" or "now confirm with the code we
 * just mailed you", and guessing either way is wrong in a different direction:
 * claiming "bad credentials" hides the only path forward, while claiming
 * "code sent" leaves an operator waiting for a message that will never arrive.
 * So the ambiguity is RETURNED, not resolved, and the screen states both
 * readings. `observed` carries the status and the response's FIELD NAMES — not
 * their values (§8.2) — so the first real exchange documents the shape instead
 * of leaving the next reader to guess again.
 *
 * ── NOTHING IS EVER REPORTED AS "A CODE WAS SENT" ──────────────────────────
 * This used to return `certain: true` for any 2xx without a token, on the
 * reasoning that such an answer could only mean a code had been dispatched.
 * The one such answer ever observed — the 204 — sent nothing, so the inference
 * had nothing behind it and the flag is gone: a 401/403 is the only
 * `code_required`, and it is always the ambiguous one.
 */
export type PhenixAuthAttempt =
  | { kind: 'token'; token: string; partnerRef: string | null; expiresAt: string | null }
  | { kind: 'code_required'; observed: string };

export async function phenixAuthenticateAttempt(
  baseUrl: string | null,
  username: string,
  password: string,
): Promise<PhenixAuthAttempt> {
  const secrets = [password, username];
  // Named in the failure messages. A base URL is configuration, not a
  // credential, and "which host answered" is the one thing a 204 does not say.
  const host = baseUrl ?? PHENIX_DEFAULT_BASE_URL;
  const rest = new RestTransport({
    baseUrl: host,
    timeoutMs: 30_000,
    retries: 0,
    tls: { rejectUnauthorized: true },
    secrets,
  });
  try {
    const res = await rest.request<unknown>('POST', '/Auth/authenticate', {
      body: { username, password },
      expect: 'json',
      idempotent: false,
    });
    const reading = readAuthenticateResponse(res, host, secrets);
    if (reading.kind === 'challenge') return { kind: 'code_required', observed: reading.observed };
    const t = reading.token;
    return { kind: 'token', token: t, partnerRef: partnerRefFromJwt(t), expiresAt: expiryFromJwt(t) };
  } catch (err) {
    throw asSimError(err, secrets);
  } finally {
    await rest.close().catch(() => undefined);
  }
}

/**
 * Authenticates with a one-time code and returns the bearer token.
 *
 * The SECOND half, after `phenixAuthenticateAttempt` has triggered the message.
 * Used by ONE interactive endpoint, never by the sweep — the whole point of the
 * OTP flow is that a human is present.
 */
export async function phenixAuthenticateWithCode(
  baseUrl: string | null,
  username: string,
  password: string,
  code: string,
): Promise<{ token: string; partnerRef: string | null; expiresAt: string | null }> {
  const secrets = [password, username, code];
  const host = baseUrl ?? PHENIX_DEFAULT_BASE_URL;
  const rest = new RestTransport({
    baseUrl: host,
    timeoutMs: 30_000,
    retries: 0,
    tls: { rejectUnauthorized: true },
    secrets,
  });
  try {
    const res = await rest.request<unknown>('POST', '/Auth/authenticateWithCodeConfirmation', {
      body: { username, password, code },
      expect: 'json',
      idempotent: false,
    });
    if (res.statusCode >= 400) {
      // 400 is how `/Auth/authenticate` refuses what it is sent (see
      // `readAuthenticateResponse`), so a 400 here is read the same way: a
      // refusal of what the operator typed, not an upstream fault, and the
      // controller answers it with a 400 rather than a 502. How THIS endpoint
      // refuses a wrong code has never been observed — the fake's 401 is an
      // assumption, from a fake that was already wrong once about how this API
      // refuses — so all three are read as a refusal.
      const refused = res.statusCode === 400 || res.statusCode === 401 || res.statusCode === 403;
      throw new SimConnectorError(
        refused
          ? `Phenix refused the code confirmation (HTTP ${res.statusCode} from ${host}). Check the ` +
              `code — it may be mistyped or expired — and the username and password.`
          : `Phenix authenticateWithCodeConfirmation: HTTP ${res.statusCode} from ${host}`,
        refused ? 'AUTH_FAILED' : 'PARTNER_ERROR',
        PLATFORM,
        { statusCode: res.statusCode, secrets },
      );
    }
    const t = tokenFrom(res.body);
    if (t === null) {
      throw new SimConnectorError(
        'Phenix authenticateWithCodeConfirmation: no access token in the response.',
        'AUTH_FAILED',
        PLATFORM,
        { secrets },
      );
    }
    return { token: t, partnerRef: partnerRefFromJwt(t), expiresAt: expiryFromJwt(t) };
  } catch (err) {
    throw asSimError(err, secrets);
  } finally {
    await rest.close().catch(() => undefined);
  }
}

/**
 * Removes the query string from anything that looks like a path in a message.
 *
 * ┌─ THE MSISDN TRAVELS IN THE QUERY STRING, AND IT IS CUSTOMER DATA ────────┐
 * │ `RestTransport.httpError` builds its message as `${path} -> HTTP ${n}`,  │
 * │ and this connector's paths are                                           │
 * │ `/GsmApi/GetSdtrConso?partenaireId=4242&msisdn=33600000001`. That        │
 * │ message propagates through `asSimError` into `logger.warn` and into      │
 * │ `sim_sync_runs.error`, which the account screen renders — so a partner   │
 * │ 429 quietly published a subscriber's number into the application log and │
 * │ a database column, two lines below the header that forbids exactly that. │
 * │                                                                         │
 * │ The path is kept (it says WHICH call failed, which is the diagnostic     │
 * │ value); everything after the `?` is replaced.                            │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
export function stripQuery(message: string): string {
  return message.replace(/(\/[A-Za-z0-9_\-./]*)\?[^\s]*/g, '$1?…');
}

/** Transport-level failures become connector-level ones, still scrubbed. */
function asSimError(err: unknown, secrets: string[]): SimConnectorError {
  if (err instanceof SimConnectorError) return err;
  const message = err instanceof Error ? err.message : String(err);
  return new SimConnectorError(stripQuery(message), 'PARTNER_ERROR', PLATFORM, { secrets });
}

export const phenixConnector: SimConnector = new PhenixConnector();
