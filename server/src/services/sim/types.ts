/**
 * ObliWAN — what a mobile partner must be able to do, and what it may not.
 *
 * ┌─ ONE INTERFACE, THREE INGESTION SHAPES, BECAUSE THE PARTNERS DIFFER ──────┐
 * │ Phenix answers an HTTP API we poll. CFAST's portal exposes "Connexions    │
 * │ partenaires → Webhooks / Comptes externes", so the shape to expect there  │
 * │ is a PUSH we receive, not a poll we run. And any partner at all can be    │
 * │ fed from a file exported off its portal.                                  │
 * │                                                                          │
 * │ Writing the interface around `open()` + `listLines()` + `fetchBalances()` │
 * │ — a poll — and bolting push on later would mean rewriting every caller    │
 * │ the day CFAST is understood. `SimConnector.ingestion` declares which of   │
 * │ the three a connector actually implements, the sweep only ever calls a    │
 * │ `pull` connector, and a `push` connector is fed by its own route.         │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ A CONNECTOR REPORTS ABSENCE. IT NEVER INVENTS A ZERO. ───────────────────┐
 * │ Every `*Mb` field below is `number | null`, and `null` is the value a     │
 * │ connector MUST produce when the partner did not answer, answered with a   │
 * │ field it does not recognise, or answered something unparseable.           │
 * │                                                                          │
 * │ This is not defensive style, it is the core requirement. The prototype    │
 * │ this feature replaces read the partner with `(float) ($r['restValueGo']   │
 * │ ?? 0)`, so a renamed field or a partial response became "0 Go remaining"  │
 * │ on every line at once — and 0 remaining is the input that says "buy". A   │
 * │ connector that cannot read a value says so; `evaluateBalance` turns that  │
 * │ into `unknown`, and `unknown` never spends.                               │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * A connector receives decrypted credentials and must ensure they never
 * reach a log, an error message or a stored `sim_sync_runs.error`. `scrub()`
 * below is how, and `SimConnectorError` applies it in its constructor so the
 * discipline does not depend on every throw site remembering.
 */

import {
  SIM_LINE_SECRET_FIELDS,
  type SimAuthMode,
  type SimIngestionKind,
  type SimLineConsumption,
  type SimLineSecretField,
  type SimLineStatus,
  type SimPartnerRechargeOutcome,
  type SimPlatform,
} from '@obliwan/shared';

// ============================================================================
// Errors
// ============================================================================

/**
 * `auth_failed` is separated from `partner_error` on purpose, and the sweep
 * treats them very differently: a bad token means every remaining line in this
 * account will fail the same way, so the sweep STOPS and the account is flagged
 * for a human. A single line erroring is skipped and counted.
 */
export type SimErrorCode =
  | 'AUTH_FAILED'
  | 'PARTNER_ERROR'
  | 'UNREADABLE'
  | 'NOT_IMPLEMENTED'
  | 'CONFIG_ERROR';

/**
 * Removes credential material from a string before it can be logged or stored.
 *
 * Literal replacement rather than a pattern: the only strings we can be sure
 * are secret are the ones we were handed. Short values are skipped — replacing
 * every occurrence of a two-character password would mangle the message into
 * something unreadable, and a two-character password has a bigger problem.
 */
export function scrub(text: string, secrets: ReadonlyArray<string | null | undefined>): string {
  let out = text;
  for (const s of secrets) {
    if (!s || s.length < 6) continue;
    out = out.split(s).join('***');
  }
  // A partner body is cut to a fixed length BEFORE it reaches this function
  // (`body.slice(0, 200)` and the transport's own cuts), so a secret can end
  // the text half-written, where the literal replacement above cannot see it.
  // A trailing START of a secret (3+ characters, before any trailing dots or
  // spaces) is replaced too.
  const tail = /[\s.…]*$/.exec(out)?.[0] ?? '';
  const body = out.slice(0, out.length - tail.length);
  for (const s of secrets) {
    if (!s || s.length < 6) continue;
    for (let k = s.length - 1; k >= 3; k--) {
      if (body.endsWith(s.slice(0, k))) {
        return `${body.slice(0, body.length - k)}***${tail}`;
      }
    }
  }
  return out;
}

export class SimConnectorError extends Error {
  readonly code: SimErrorCode;
  readonly platform: SimPlatform;
  /** HTTP status when the partner produced one. Diagnostic only. */
  readonly statusCode: number | null;

  constructor(
    message: string,
    code: SimErrorCode,
    platform: SimPlatform,
    opts: { statusCode?: number | null; secrets?: ReadonlyArray<string | null | undefined> } = {},
  ) {
    // Scrubbed HERE rather than at each throw site: a rule nobody can forget
    // beats a rule everybody must remember.
    super(scrub(message, opts.secrets ?? []));
    this.name = 'SimConnectorError';
    this.code = code;
    this.platform = platform;
    this.statusCode = opts.statusCode ?? null;
  }
}

/**
 * The one predicate the sweep reasons with when deciding whether to STOP.
 *
 * Used by `sync.service` at both decision points — the per-line catch and the
 * account-level catch. It existed with no caller in the first draft while both
 * sites hand-rolled `err instanceof SimConnectorError && err.code === ...`,
 * which is two copies of a rule that must not disagree.
 */
export function isAuthFailure(err: unknown): boolean {
  return err instanceof SimConnectorError && err.code === 'AUTH_FAILED';
}

// ============================================================================
// Credentials (decrypted — in memory, for the duration of one sweep)
// ============================================================================

export type SimCredential =
  | { authMode: 'password'; username: string; password: string }
  | { authMode: 'token'; token: string };

/** Every literal a connector must keep out of its own error messages. */
export function credentialSecrets(cred: SimCredential | null): string[] {
  if (!cred) return [];
  return cred.authMode === 'password' ? [cred.password, cred.username] : [cred.token];
}

// ============================================================================
// What a connector returns
// ============================================================================

export interface RawSimLine {
  msisdn: string;
  /** Null when the partner did not report one. NEVER ''. */
  operator: string | null;
  clientCode: string | null;
  /** A full ICCID (19-20 digits) when the partner reported one, else null —
   *  see `SimLine.iccid`. A shorter serial is in `partner.simSerial`. */
  iccid: string | null;
  status: SimLineStatus;
  /**
   * The two attributes the partner keys its volume catalogue on (Phenix:
   * `typeOffre`, `codeTarifAchat`). Optional because not every partner has
   * them; `null` when the listing did not carry them.
   */
  offerType?: string | null;
  purchaseTariffCode?: string | null;
  /**
   * Everything else the listing said about the line (migration 077). Absent
   * when the listing carried nothing more than the fields above — and then
   * the sweep leaves the stored facts alone instead of blanking them.
   */
  partner?: RawSimLinePartnerFacts;
  /** The line's secrets, in memory only, until the sweep encrypts them. */
  secrets?: SimLineSecrets;
}

/** See `SimLinePartnerFacts` (shared) — the same facts, as read. */
export interface RawSimLinePartnerFacts {
  partnerLineId: string | null;
  simSerial: string | null;
  imsi: string | null;
  customerName: string | null;
  siteLabel: string | null;
  internalRef: string | null;
  state: string | null;
  stateLabel: string | null;
  simType: string | null;
  planLabel: string | null;
  planCode: string | null;
  activatedAt: string | null;
  terminatedAt: string | null;
  dataOnly: boolean | null;
  apn: string | null;
  fixedIp: string | null;
  hasFixedIp: boolean | null;
  radiusLogin: string | null;
  consumption: SimLineConsumption;
  /** Every other NON-SECRET field of the partner's row, verbatim. */
  details: Record<string, unknown>;
}

// ============================================================================
// A line's secrets — a box that does not open by accident
// ============================================================================

const SECRET_VALUES = new WeakMap<SimLineSecrets, Readonly<Record<SimLineSecretField, string | null>>>();

/**
 * A line's secrets (PUK1, PUK2, RADIUS password, RIO) between the partner's answer
 * and `secretVault.encrypt` — the only moment they exist in clear here.
 *
 * ┌─ WHY A CLASS AND NOT A PLAIN OBJECT ─────────────────────────────────────┐
 * │ A `RawSimLine` is the kind of object somebody logs while debugging a     │
 * │ sweep: `logger.warn({ line })`. With the values on a plain property,     │
 * │ that one line of debugging puts every PUK of the fleet in the log. Here  │
 * │ the values live in a module WeakMap — not an own property, so neither    │
 * │ `JSON.stringify`, pino, `Object.keys` nor `util.inspect` can reach them   │
 * │ — and the only way out is `value(field)`, which a reader has to mean.     │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
export class SimLineSecrets {
  constructor(values: Record<SimLineSecretField, string | null>) {
    SECRET_VALUES.set(this, Object.freeze({ ...values }));
  }

  /** The plaintext. For the vault and for nothing else. */
  value(field: SimLineSecretField): string | null {
    return SECRET_VALUES.get(this)?.[field] ?? null;
  }

  /** Which secrets are present — never what they are. */
  present(): Record<SimLineSecretField, boolean> {
    return Object.fromEntries(
      SIM_LINE_SECRET_FIELDS.map((f) => [f, this.value(f) !== null]),
    ) as Record<SimLineSecretField, boolean>;
  }

  /** Every non-null value, for a scrub list (`SimConnectorError`'s `secrets`). */
  literals(): string[] {
    return SIM_LINE_SECRET_FIELDS.map((f) => this.value(f)).filter((v): v is string => v !== null);
  }

  toJSON(): Record<SimLineSecretField, boolean> {
    return this.present();
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return 'SimLineSecrets [redacted]';
  }
}

export interface RawSimBalance {
  /** Never ''. A connector that cannot read a zone label uses `UNKNOWN_ZONE`. */
  zone: string;
  rechargeMb: number | null;
  usedMb: number | null;
  /** THE value the whole feature turns on. `null` = not answered, never 0. */
  restMb: number | null;
  /** The partner's code for this zone, when it sends one. Needed to ask for
   *  the zone's volume catalogue; never used to identify a zone in ObliWAN. */
  zoneCode?: string | null;
}

/**
 * One row of a partner's own recharge history, as read. Every field but
 * `partnerRef` and `outcome` may be null: the shape was read off the partner's
 * web client, not off a captured response.
 */
export interface RawPartnerRecharge {
  /** The partner's row id, or a key synthesised from the row. Never ''. */
  partnerRef: string;
  requestedAt: string | null;
  /** 'YYYY-MM'. */
  period: string | null;
  zoneCode: string | null;
  volumeMb: number | null;
  productCode: string | null;
  partnerState: string | null;
  partnerStatus: string | null;
  outcome: SimPartnerRechargeOutcome;
}

export interface RawRechargeOffer {
  code: string;
  label: string | null;
  volumeMb: number | null;
}

export interface RechargeOfferQuery {
  msisdn: string;
  operator: string | null;
  zoneCode: string;
  offerType: string | null;
  purchaseTariffCode: string | null;
}

// ============================================================================
// Session
// ============================================================================

export interface SimConnectorContext {
  accountId: number;
  /** Null = the connector's own default host. */
  baseUrl: string | null;
  partnerRef: string | null;
  authMode: SimAuthMode;
  credential: SimCredential;
  timeoutMs?: number;
}

/**
 * What a listing call actually returned, and whether it was all of it.
 *
 * ┌─ A PAGED LISTING IS COMPLETE ONLY IF THE PARTNER SAYS SO ────────────────┐
 * │ Phenix's `GetLigneGsmByFilterPaged` is paged, and the connector now pages │
 * │ it (client by client, observed 2026-10-06). Paging can still come up     │
 * │ short — a partner that stops serving pages before its own total — and     │
 * │ the remainder would then be SILENTLY absent: never inserted, never       │
 * │ balance-read, never alerted on, never invoiced, with the sweep reporting │
 * │ `ok`. Silent, permanent, growing with the customer.                      │
 * │                                                                        │
 * │ So the listing reports the partner's own total next to the number of     │
 * │ rows it actually served, and the sweep compares the two                  │
 * │ (`listingShortfall`). `declaredTotal` is `null` when the partner said    │
 * │ nothing for at least one page set, which is not evidence that the        │
 * │ listing was complete — only that we cannot tell.                         │
 * │                                                                        │
 * │ A client whose pages FAILED is reported apart (`failedClients`) and is   │
 * │ in neither count: its total was never fully read, and its few served     │
 * │ rows would otherwise offset another client's shortfall.                  │
 * └────────────────────────────────────────────────────────────────────────┘
 */
export interface SimLineListing {
  lines: RawSimLine[];
  /** The partner's own count of matching rows, when it reports one — over the
   *  clients whose pages were all read (`failedClients` excluded). */
  declaredTotal: number | null;
  /**
   * Rows the partner actually served (distinct), BEFORE any was set aside for
   * want of a number or as a duplicate of another row's number — over the same
   * clients as `declaredTotal`. Compared with it; absent = `lines.length`.
   */
  rowsReturned?: number;
  /**
   * Clients whose listing failed part-way, and where — a partner error, a
   * transport failure or an unreadable page, but NEVER an auth failure or the
   * request ceiling, which abandon the whole listing. The rows such a client
   * served before failing ARE in `lines` (they are real answers); its other
   * lines are simply absent, and absence updates nothing. A non-empty list
   * makes the sweep `partial`, naming them. `error` is already scrubbed.
   */
  failedClients?: Array<{ clientCode: string; page: number; errorCode: SimErrorCode; error: string }>;
  /** Rows set aside, by reason — counts and field NAMES only, never values. */
  setAside?: {
    /** A row with no MSISDN: not a line anybody can ask about. */
    noMsisdn: number;
    /** A second row for an MSISDN already listed (a terminated subscription of
     *  a number now live elsewhere): the live one is kept. */
    sameMsisdn: number;
    /** Blank entries in the partner's client list: nothing can be listed for them. */
    blankClientCodes: number;
    /** Field names that LOOK secret and are not one of the known four:
     *  withheld from `partner_details` rather than stored in clear. */
    withheldFields: string[];
  };
}

/**
 * Rows the partner declared and did not serve. 0 when it served at least what
 * it declared, or declared nothing (see `SimLineListing`). ONE reading for the
 * sweep and the connection test, which used to each spell it.
 */
export function listingShortfall(listing: SimLineListing): number {
  if (listing.declaredTotal === null) return 0;
  const served = listing.rowsReturned ?? listing.lines.length;
  return Math.max(0, listing.declaredTotal - served);
}

/** How many failed clients a gap sentence names before summarising the rest. */
const FAILED_CLIENTS_NAMED = 10;

/**
 * Every way this listing is known to be INCOMPLETE, one English sentence each
 * (server-side, like every operator message), or `[]` when nothing is known
 * to be missing. Any entry makes a sweep `partial`, and the connection test
 * shows the same sentences: ONE reading for both, like `listingShortfall`.
 *
 * Counts and client codes only — never a number, never a value.
 */
export function listingGaps(listing: SimLineListing): string[] {
  const out: string[] = [];
  const failed = listing.failedClients ?? [];
  if (failed.length > 0) {
    const named = failed
      .slice(0, FAILED_CLIENTS_NAMED)
      .map((f) => `${f.clientCode} (page ${f.page})`)
      .join(', ');
    const more = failed.length > FAILED_CLIENTS_NAMED ? ` and ${failed.length - FAILED_CLIENTS_NAMED} more` : '';
    out.push(
      `The partner's listing failed for ${failed.length} client(s): ${named}${more}. Their unlisted ` +
        `lines were not refreshed (none was retired either). First failure: ${failed[0].error}`,
    );
  }
  const short = listingShortfall(listing);
  if (short > 0) {
    out.push(
      `The partner reports ${short} more line(s) than it served, every page of ` +
        `${failed.length > 0 ? 'the other clients' : 'every client'} read: the remainder is not ` +
        `tracked, not alerted on and not invoiced.`,
    );
  }
  const aside = listing.setAside;
  if (aside && aside.noMsisdn > 0) {
    out.push(`${aside.noMsisdn} row(s) of the listing carried no number and were set aside: they cannot be tracked.`);
  }
  if (aside && aside.blankClientCodes > 0) {
    out.push(
      `${aside.blankClientCodes} blank entr${aside.blankClientCodes === 1 ? 'y' : 'ies'} in the partner's ` +
        `client list: nothing could be listed for ${aside.blankClientCodes === 1 ? 'it' : 'them'}.`,
    );
  }
  return out;
}

export interface SimSession {
  /**
   * The partner reference the session actually resolved to — decoded from a
   * token when the account did not carry one. Persisted so the next sweep does
   * not have to decode it again, and so a screen can show which partner account
   * a token really belongs to rather than which one somebody typed.
   */
  readonly partnerRef: string | null;
  /** From the token's own expiry claim when it has one. Null when unknown. */
  readonly tokenExpiresAt: string | null;

  listLines(): Promise<SimLineListing>;
  fetchBalances(msisdn: string): Promise<RawSimBalance[]>;
  /**
   * READ-ONLY. The partner's record of top-ups already bought on a line —
   * including those bought by hand on its portal. Optional: a partner that
   * cannot say is a partner whose purchases are recorded by a human.
   */
  listRechargeHistory?(msisdn: string): Promise<RawPartnerRecharge[]>;
  /**
   * READ-ONLY. The volumes the partner would sell for this line and zone. It
   * buys nothing; the call that buys is NOT on this interface, and belongs to
   * `SimRechargeAdapter` below, which stays empty.
   */
  listRechargeOffers?(query: RechargeOfferQuery): Promise<RawRechargeOffer[]>;
  close(): Promise<void>;
}

export interface SimConnector {
  readonly platform: SimPlatform;
  readonly ingestion: readonly SimIngestionKind[];
  /**
   * Opens an authenticated session.
   *
   * Throws `SimConnectorError('NOT_IMPLEMENTED')` for a partner ObliWAN cannot
   * read yet. That refusal is deliberate and is surfaced on the account screen:
   * an account configured against an unimplemented partner must look broken,
   * because a fleet of lines nobody is reading must never look watched.
   */
  open(ctx: SimConnectorContext): Promise<SimSession>;
}

// ============================================================================
// Recharge execution — the registry that is empty ON PURPOSE
// ============================================================================

export interface RechargeRequest {
  msisdn: string;
  zone: string;
  planMb: number | null;
}

export interface RechargeOutcome {
  /** The partner's own reference for the purchase, for the billing report. */
  reference: string | null;
  costCents: number | null;
  currency: string | null;
}

export interface SimRechargeAdapter {
  readonly platform: SimPlatform;
  execute(ctx: SimConnectorContext, req: RechargeRequest): Promise<RechargeOutcome>;
}

/**
 * EMPTY, ON PURPOSE. Do not add an entry to make a screen look finished.
 *
 * ┌─ WHY THIS IS A DELIBERATE STATE AND NOT A TODO ───────────────────────────┐
 * │ An entry here is what makes `executed` reachable — the state in which     │
 * │ ObliWAN itself buys data, with nobody in the loop, against a real         │
 * │ account, for real money that no rollback returns. The identical           │
 * │ construction guards on-device peer recovery in                            │
 * │ `safeApply.service.PEER_RECOVERY_ADAPTERS`, for the identical reason:     │
 * │ populating a registry changes what a human is being asked to approve.     │
 * │                                                                          │
 * │ Today it is empty because NO TOP-UP HAS EVER BEEN MADE THROUGH AN API.    │
 * │ The Phenix call that buys IS known — read off the                         │
 * │ extranet's bundle, not observed: `GET /GsmApi/RechargerDataGsm?msisdn=    │
 * │ &codeRecharge=&codeZone=&typeOffre=`. A GET that spends money, so a proxy │
 * │ or a transport retry can buy twice; and its answer can be                 │
 * │ `Validation-Recharge-En-Attente` (the partner's own manager validation),  │
 * │ so "sent" is not "bought". The read side is built — the history           │
 * │ (`GetRechargeRequests`) is stored and reconciled, the catalogue           │
 * │ (`GetRechargesDataByZone`) is readable — see `partnerRecharge.service`.   │
 * │ An adapter needs: a "pending at the partner" state, a history read BEFORE │
 * │ any retry, and a first real purchase made with the operator watching.     │
 * │                                                                          │
 * │ Everything upstream of this registry is built and works: detection,       │
 * │ proposal, four-eyes approval, caps, audit and the billing report. An      │
 * │ approved top-up is bought on the partner's portal and RECORDED here,      │
 * │ which is a different terminal state precisely so that the day this        │
 * │ registry is populated, the report can still answer "which of these did    │
 * │ the machine buy".                                                         │
 * │                                                                          │
 * │ THE BAR FOR ADDING AN ENTRY: an endpoint confirmed against a real         │
 * │ partner account, an idempotency story that survives a retry (buying the   │
 * │ same top-up twice is the failure this whole design exists to avoid), and  │
 * │ a caps check proven to run BEFORE the call. Until then this stays `{}`    │
 * │ and `SIM_PLATFORM_CATALOG[].rechargeImplemented` stays `false`.           │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
export const SIM_RECHARGE_ADAPTERS: Partial<Record<SimPlatform, SimRechargeAdapter>> = {};
