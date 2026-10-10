/**
 * ObliWAN — the SIM sweep: read a partner, store what it said, announce what
 * changed.
 *
 * ┌─ WHAT THIS FUNCTION IS ALLOWED TO CONCLUDE ───────────────────────────────┐
 * │ Three things, and nothing else:                                           │
 * │                                                                          │
 * │   "this line exists"            → insert or refresh `last_seen_at`        │
 * │   "this zone has N MB left"     → upsert `sim_balances`, sample on change │
 * │   "this zone is below its bar"  → open an episode, alert, maybe propose   │
 * │                                                                          │
 * │ It NEVER deletes a line, NEVER writes a balance it could not read as      │
 * │ zero, and NEVER buys anything.                                            │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHY A LINE THE PARTNER DID NOT LIST IS NOT A LINE THAT IS GONE ──────────┐
 * │ `GetLigneGsmByFilterPaged` is paged, client by client, and a partner can  │
 * │ come up short of its own total. If this sweep deleted — or even marked    │
 * │ inactive — every line absent from the answer, one short page would retire │
 * │ half a customer's fleet, and the dashboard would show a smaller inventory │
 * │ that looks perfectly healthy. So absence updates nothing at all;          │
 * │ `last_seen_at` is the signal, and retiring a line is a human act. A line  │
 * │ the partner LISTS as terminated ("Deleted") is a different fact: it is    │
 * │ stored as `terminated`, kept, no longer balance-read, and its open        │
 * │ top-up proposals are expired (`settleOpenWorkOnTermination`).             │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ AUTH FAILURE STOPS THE ACCOUNT. ONE LINE FAILING DOES NOT. ──────────────┐
 * │ A dead token fails identically on every line, so continuing produces a    │
 * │ `lines_failed` count equal to the fleet size and an account that reads as │
 * │ flaky rather than logged out. `AUTH_FAILED` therefore aborts the sweep,   │
 * │ flips the account to `auth_failed` (taking it out of the poll list) and   │
 * │ raises one alert. Any other per-line error is counted and skipped.        │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * `sim_sync_runs.error` is written from `SimConnectorError.message`,
 * which was scrubbed of credential literals in its constructor. Nothing here
 * logs a URL — the MSISDN travels in the query string and is customer data.
 *
 * No equipment is contacted. This talks to a partner's web API and to our
 * own Postgres.
 */

import {
  SETTINGS_KEYS,
  SIM_LINE_SECRET_FIELDS,
  canonicalZone,
  simMsisdnSchema,
  effectiveThresholdMb,
  evaluateBalance,
  formatData,
  worstZone,
  type SimLineSecretField,
  type SimPlatform,
  type SimZoneBalance,
  evaluateZoneUsage,
  simLineUsageVerdict,
  type SimLowDataPolicy,
} from '@obliwan/shared';
import pLimit from 'p-limit';
import type { Knex } from 'knex';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { liveAlertService } from '../liveAlert.service';
import { reconcilePartnerRecharges, storePartnerRecharges } from './partnerRecharge.service';
import { notificationService } from '../notification.service';
import {
  loadCredential,
  markAuthFailed,
  type SimAccountRow,
} from './account.service';
import { globalLowPercent, globalNumber, globalThresholdMb, lowDataPolicy } from './line.service';
import { proposeForLowZone, settleOpenWorkOnTermination } from './recharge.service';
import { stripQuery } from './phenix.connector';
import { getConnector } from './registry';
import { currentKeyVersion, decrypt, encrypt } from '../secretVault.service';
import { linkDeviceByLineIccid, relinkAccountLines } from './deviceLink.service';
import { applyClientMappingsForAccount } from './clientTenant.service';
import {
  SimConnectorError,
  isAuthFailure,
  scrub,
  listingGaps,
  listingShortfall,
  type RawSimBalance,
  type RawSimLine,
  type RawSimLinePartnerFacts,
  type SimLineSecrets,
  type SimSession,
} from './types';

/**
 * Concurrent balance reads per account.
 *
 * One request PER LINE is the shape of this API, so a 400-line fleet is 400
 * calls. Four at a time keeps a sweep to a couple of minutes without looking
 * like a scraper to a partner that publishes no rate limit — and a partner that
 * rate-limits us produces an empty balance column, which is the one failure
 * this feature cannot afford because it is indistinguishable from good news.
 */
const BALANCE_CONCURRENCY = 4;

export interface SyncOutcome {
  accountId: number;
  outcome: 'ok' | 'partial' | 'auth_failed' | 'error';
  linesSeen: number;
  linesNew: number;
  balancesUpdated: number;
  linesFailed: number;
  proposalsCreated: number;
  error: string | null;
}

interface LineRow {
  id: number;
  tenant_id: number | null;
  msisdn: string;
  operator: string | null;
  site_id: number | null;
  device_id: number | null;
  low_threshold_mb: number | null;
  auto_recharge_enabled: boolean;
  recharge_plan_mb: number | null;
  /** The partner's plan label: its « Data 10 Go » is a zone envelope (brick 6). */
  plan_label?: string | null;
}

// ============================================================================
// Entry point
// ============================================================================

export async function syncAccount(account: SimAccountRow): Promise<SyncOutcome> {
  const [run] = await db('sim_sync_runs')
    .insert({ account_id: account.id })
    .returning<Array<{ id: string }>>('id');

  const result: SyncOutcome = {
    accountId: account.id,
    outcome: 'ok',
    linesSeen: 0,
    linesNew: 0,
    balancesUpdated: 0,
    linesFailed: 0,
    proposalsCreated: 0,
    error: null,
  };

  const connector = getConnector(account.platform);
  let session: SimSession | null = null;
  /** What the listing is known to be missing, one sentence each. See below. */
  let gaps: string[] = [];

  try {
    session = await connector.open({
      accountId: account.id,
      baseUrl: account.base_url,
      partnerRef: account.partner_ref,
      authMode: account.auth_mode,
      credential: loadCredential(account),
    });

    // The token knows its own partner id and expiry; persist what it told us so
    // the account screen can warn before it dies.
    await db('sim_accounts')
      .where({ id: account.id })
      .update({
        partner_ref: session.partnerRef ?? account.partner_ref,
        token_expires_at: session.tokenExpiresAt ?? account.token_expires_at,
        updated_at: db.fn.now(),
      });

    const listing = await session.listLines();
    const remote = listing.lines;
    result.linesSeen = remote.length;

    // ┌─ A SHORT LISTING IS NOT A SMALLER FLEET ───────────────────────────────┐
    // │ The listing is paged. If the partner declares more rows than it served │
    // │ — a partner that stops serving pages before its own total — the        │
    // │ remainder is invisible: never inserted, never balance-read, never      │
    // │ proposed for, never invoiced. Reporting `ok` over that is the silent,  │
    // │ permanent, grows-with-the-customer failure the interface note          │
    // │ describes — so the run is marked `partial` and says what is missing.   │
    // └────────────────────────────────────────────────────────────────────────┘
    if (listingShortfall(listing) > 0) {
      logger.warn(
        { accountId: account.id, served: listing.rowsReturned ?? remote.length, declared: listing.declaredTotal },
        'SIM inventory listing is short: the partner reports more lines than it served',
      );
    }
    // Clients whose pages failed: the others were listed all the same, and
    // this sweep processes them — absence updates nothing, so a line of a
    // failed client is neither refreshed nor retired. Client codes and pages
    // only.
    const failedClients = listing.failedClients ?? [];
    if (failedClients.length > 0) {
      logger.warn(
        {
          accountId: account.id,
          failedClients: failedClients.map((f) => ({ clientCode: f.clientCode, page: f.page, code: f.errorCode })),
        },
        'SIM inventory: the partner listing failed for some clients; the others were processed',
      );
    }
    // Rows the connector set aside, by reason. Counts and field NAMES only —
    // never a number, never a value.
    const aside = listing.setAside;
    if (aside && (aside.noMsisdn + aside.sameMsisdn + aside.blankClientCodes > 0 || aside.withheldFields.length > 0)) {
      logger.warn(
        { accountId: account.id, ...aside },
        'SIM inventory: the partner listing carried rows or fields that were set aside',
      );
    }
    // Everything known to be missing from this listing — a shortfall, failed
    // clients, numberless rows, blank client codes — each makes the run
    // `partial` and is named in its journal entry (`listingGaps`).
    gaps = listingGaps(listing);

    const skip = new Set(
      (Array.isArray(account.skip_operators) ? account.skip_operators : [])
        .filter((s): s is string => typeof s === 'string')
        .map((s) => s.trim().toLowerCase()),
    );

    // ┌─ 1. INVENTORY — ONE BAD ROW MUST NOT BLIND THE WHOLE ACCOUNT ─────────┐
    // │ `sim_lines` carries CHECK constraints the partner knows nothing about │
    // │ (migration 032: the MSISDN pattern, the ICCID pattern, the column     │
    // │ widths). The first draft awaited every upsert in a bare loop, so one  │
    // │ malformed row — a test line, a placeholder, a number with an          │
    // │ extension — threw a constraint violation that aborted the ENTIRE      │
    // │ sweep. Every subsequent line went unread, every balance went stale,   │
    // │ and it recurred on every sweep forever, because the partner keeps     │
    // │ returning that row.                                                   │
    // │                                                                      │
    // │ So the row is validated against the SAME schema the API boundary uses │
    // │ — `simMsisdnSchema`, which until now stated a rule and had no caller  │
    // │ at all — and a row that fails is counted and skipped                  │
    // │ rather than thrown. The count reaches `sim_sync_runs.lines_failed`,   │
    // │ so "why is this line missing" has an answer.                          │
    // └──────────────────────────────────────────────────────────────────────┘
    // Live lines first, terminated ones last: an ICCID is unique across the
    // inventory (migration 032's partial index) and filled only when no other
    // line holds it, so the line that holds the card TODAY must claim it before
    // the terminated subscription it replaced.
    const ordered = [...remote].sort(
      (a, b) => (a.status === 'terminated' ? 1 : 0) - (b.status === 'terminated' ? 1 : 0),
    );
    for (const line of ordered) {
      const parsed = simMsisdnSchema.safeParse(line.msisdn);
      if (!parsed.success) {
        result.linesFailed += 1;
        // The MSISDN itself is NOT logged: it is customer data, and this branch
        // is reached precisely when it is malformed rather than identifying.
        logger.warn(
          { accountId: account.id },
          'SIM inventory: skipped a line whose number the partner reported in an unusable shape',
        );
        continue;
      }
      try {
        const created = await upsertLine(account.id, { ...line, msisdn: parsed.data });
        if (created) result.linesNew += 1;
      } catch (err) {
        result.linesFailed += 1;
        // The line's own secrets (PUKs, RADIUS password, RIO) are scrubbed from
        // the message: a database error is free to quote what it was handed.
        logger.warn(
          { accountId: account.id },
          `SIM inventory upsert failed for one line: ${scrub(
            err instanceof Error ? err.message : String(err),
            line.secrets?.literals() ?? [],
          )}`,
        );
      }
    }

    // ── 1b. Client → tenant distribution (migration 081) ─────────────────────
    // A mapped partner client's POOL lines go to its tenant (and to the site
    // their partner label names), and the automatic rule maps the clients it
    // holds for — BEFORE the balance pass, so alerts and proposals already
    // reach the right customer. Never throws (clientTenant.service.ts).
    await applyClientMappingsForAccount(account.id);

    // ── 2. Balances ─────────────────────────────────────────────────────────
    const stored = await db<LineRow>('sim_lines')
      .where('account_id', account.id)
      .select(
        'id',
        'tenant_id',
        'msisdn',
        'operator',
        'site_id',
        'device_id',
        'low_threshold_mb',
        'auto_recharge_enabled',
        'recharge_plan_mb',
        'plan_label',
      );
    const byMsisdn = new Map(stored.map((r) => [r.msisdn, r]));

    const limit = pLimit(BALANCE_CONCURRENCY);
    let authFailure: SimConnectorError | null = null;
    // Lines deliberately not polled are not lines that failed: counting them in
    // would make an account whose whole fleet is on a skipped operator look
    // like a total failure on every sweep.
    let skippedByOperator = 0;
    let skippedTerminated = 0;
    // The partner's purchase history. Counted apart from `linesFailed`: a line
    // whose balance was read but whose history was not is a line we ARE
    // watching, and folding it into the failure count would turn a missing
    // convenience into a red account.
    const history = { newRows: 0, recorded: 0, linked: 0, ambiguous: 0, failed: 0 };

    await Promise.all(
      remote.map((line) =>
        limit(async () => {
          // A partner error on one line must not stop the sweep, but an auth
          // failure must — checked here so the remaining queued tasks return
          // immediately instead of producing N identical 401s.
          if (authFailure) return;
          if (line.operator && skip.has(line.operator.trim().toLowerCase())) {
            skippedByOperator += 1;
            return;
          }
          // A terminated subscription has no allowance left to watch and no
          // top-up to propose: it is KEPT in the inventory (its dates, plan
          // and last consumption are history) and not balance-read. Counted
          // apart from failures, like a skipped operator.
          if (line.status === 'terminated') {
            skippedTerminated += 1;
            return;
          }

          const row = byMsisdn.get(line.msisdn);
          if (!row) return;

          try {
            const zones = await session!.fetchBalances(line.msisdn);
            const outcome = await applyBalances(row, zones);
            result.balancesUpdated += outcome.updated;
            result.proposalsCreated += outcome.proposals;
          } catch (err) {
            // `isAuthFailure` rather than a hand-rolled `instanceof` + code
            // comparison: the same predicate the rest of the module reasons
            // with, so the two cannot drift apart.
            if (isAuthFailure(err)) {
              authFailure = err as SimConnectorError;
              return;
            }
            result.linesFailed += 1;
            // Logged with the line id, never the MSISDN: the id is ours, the
            // number is the customer's (the secrets rule spirit — log what identifies the
            // row for us, not what identifies the subscriber).
            // `stripQuery` here as well as in the connector: this log line's
            // own comment promises no MSISDN, and a promise that depends on
            // every upstream throw site remembering is not one.
            logger.warn(
              { accountId: account.id, simId: row.id },
              `SIM balance read failed: ${stripQuery(
                err instanceof Error ? err.message : String(err),
              )}`,
            );
          }

          // ── The partner's own record of what was bought on this line ──────
          // Only for ASSIGNED lines: a pooled line belongs to nobody and cannot
          // be re-invoiced, so its history would be stored for no reader. And
          // only when the connector can say — a partner that cannot is one
          // whose purchases a human records, exactly as before.
          if (authFailure || row.tenant_id === null || !session!.listRechargeHistory) return;
          try {
            const rows = await session!.listRechargeHistory(line.msisdn);
            history.newRows += await storePartnerRecharges(account.id, row, rows);
            const rec = await reconcilePartnerRecharges(row.id);
            history.recorded += rec.recorded;
            history.linked += rec.linked;
            history.ambiguous += rec.ambiguous;
          } catch (err) {
            if (isAuthFailure(err)) {
              authFailure = err as SimConnectorError;
              return;
            }
            history.failed += 1;
            logger.warn(
              { accountId: account.id, simId: row.id },
              `SIM partner recharge history read failed: ${stripQuery(
                err instanceof Error ? err.message : String(err),
              )}`,
            );
          }
        }),
      ),
    );

    if (history.newRows + history.recorded + history.linked + history.ambiguous + history.failed > 0) {
      logger.info({ accountId: account.id, ...history }, 'SIM partner recharge history read');
    }

    if (authFailure) throw authFailure;

    // ┌─ "PARTIAL" MUST NOT COVER "NOTHING WORKED" ────────────────────────────┐
    // │ A 429 is thrown by the transport rather than returned, so it lands in  │
    // │ the per-line catch and is counted — for every line, four at a time.    │
    // │ The first draft then reported `partial` whether ONE line failed or ALL │
    // │ FOUR HUNDRED did, wrote no `last_sync_error`, and set                  │
    // │ `last_sync_line_count` to the number of lines LISTED — so the account  │
    // │ screen stayed green and `fleetSummary.failedAccounts` stayed 0 while   │
    // │ not a single balance had been read.                                     │
    // │                                                                        │
    // │ `BALANCE_CONCURRENCY`'s own comment calls that "the one failure this   │
    // │ feature cannot afford, because it is indistinguishable from good       │
    // │ news". It was, and this is what makes it distinguishable. The stale-   │
    // │ reading horizon (`readingFreshness`) is the second half: the balances  │
    // │ themselves stop reading as answers.                                     │
    // └────────────────────────────────────────────────────────────────────────┘
    const attempted = result.linesSeen - skippedByOperator - skippedTerminated;
    if (attempted > 0 && result.linesFailed >= attempted) {
      result.outcome = 'error';
      result.error =
        `Every balance read failed (${result.linesFailed} of ${attempted}). The partner is ` +
        `refusing or throttling this account; no remaining data was updated.`;
    } else if (gaps.length > 0) {
      // Recorded on the run itself (`sim_sync_runs.error`, shown on the
      // account screen): which clients failed and where, how many rows were
      // set aside and why — counts and client codes, never a number.
      result.outcome = 'partial';
      result.error = gaps.join(' ');
    } else {
      result.outcome = result.linesFailed > 0 ? 'partial' : 'ok';
    }
  } catch (err) {
    const isAuth = isAuthFailure(err);
    const notImplemented = err instanceof SimConnectorError && err.code === 'NOT_IMPLEMENTED';
    result.outcome = isAuth ? 'auth_failed' : 'error';
    result.error = err instanceof Error ? err.message : String(err);

    if (isAuth) {
      await markAuthFailed(account.id, result.error);
      await announceAccountProblem(account, result.error);
    } else if (notImplemented) {
      // Not an incident: this account is a container for lines loaded from a
      // file. Recorded so the journal explains the lack of fresh balances, and
      // deliberately not alerted — an alert every interval for something nobody
      // can fix is how a channel gets muted.
      logger.debug({ accountId: account.id }, 'SIM account platform is not pollable');
    } else {
      logger.error({ accountId: account.id }, `SIM sweep failed: ${result.error}`);
    }
  } finally {
    await session?.close().catch(() => undefined);
  }

  // Offer this account's unlinked lines to the routers whose modem holds
  // their card (deviceLink.service, migration 080). Never throws.
  if (result.outcome === 'ok' || result.outcome === 'partial') await relinkAccountLines(db, account.id);

  await db('sim_sync_runs')
    .where({ id: run.id })
    .update({
      finished_at: db.fn.now(),
      outcome: result.outcome,
      lines_seen: result.linesSeen,
      lines_new: result.linesNew,
      balances_updated: result.balancesUpdated,
      lines_failed: result.linesFailed,
      proposals_created: result.proposalsCreated,
      error: result.error,
    });

  await db('sim_accounts')
    .where({ id: account.id })
    .update({
      last_sync_at: db.fn.now(),
      last_sync_error: result.error,
      // Not updated on a failed sweep: `last_sync_line_count` is read on the
      // account screen as "lines seen on the last sweep", and overwriting it
      // with the number LISTED during a sweep that read no balance at all is
      // the green tick this whole block exists to remove.
      last_sync_line_count: result.outcome === 'error' ? account.last_sync_line_count : result.linesSeen,
      updated_at: db.fn.now(),
    });

  return result;
}

// ============================================================================
// Inventory
// ============================================================================

interface ExistingLineRow {
  id: number;
  tenant_id: number | null;
  device_id: number | null;
  iccid: string | null;
  puk1_enc: string | null;
  puk2_enc: string | null;
  radius_password_enc: string | null;
  rio_enc: string | null;
}

type SecretColumn = 'puk1_enc' | 'puk2_enc' | 'radius_password_enc' | 'rio_enc';

/** The stored blob column of each line secret (migration 077; `rio_enc`, 079). */
const SECRET_COLUMN: Record<SimLineSecretField, SecretColumn> = {
  puk1: 'puk1_enc',
  puk2: 'puk2_enc',
  radiusPassword: 'radius_password_enc',
  rio: 'rio_enc',
};

/**
 * The typed columns of what the partner's listing said (migration 077). Written
 * WHOLE when the listing carried them — a field the partner now leaves empty
 * becomes NULL, because these are a current reading (this month's consumption,
 * today's plan), not an identity to protect — and not touched at all when the
 * listing carried nothing beyond the number (`line.partner` absent).
 */
function partnerColumns(p: RawSimLinePartnerFacts): Record<string, unknown> {
  return {
    partner_line_id: p.partnerLineId,
    sim_serial: p.simSerial,
    imsi: p.imsi,
    customer_name: p.customerName,
    partner_site_label: p.siteLabel,
    internal_ref: p.internalRef,
    partner_state: p.state,
    partner_state_label: p.stateLabel,
    sim_type: p.simType,
    plan_label: p.planLabel,
    plan_code: p.planCode,
    activated_at: p.activatedAt,
    terminated_at: p.terminatedAt,
    data_only: p.dataOnly,
    apn: p.apn,
    fixed_ip: p.fixedIp,
    has_fixed_ip: p.hasFixedIp,
    radius_login: p.radiusLogin,
    // MB, decimal, `null` when the partner left the field empty — never 0.
    data_nat_mb: p.consumption.nationalMb,
    data_roam_mb: p.consumption.roamingMb,
    data_nat_prev_mb: p.consumption.nationalPrevMonthMb,
    data_roam_prev_mb: p.consumption.roamingPrevMonthMb,
    // A string, so `pg` sends JSON and never mistakes it for a Postgres array.
    partner_details: JSON.stringify(p.details),
    partner_observed_at: db.fn.now(),
  };
}

/** A stored secret in clear, or `undefined` when there is none or the vault
 *  cannot open it (another key generation, a damaged blob). */
function openStored(blob: string | null): string | undefined {
  if (!blob) return undefined;
  try {
    return decrypt(blob);
  } catch {
    return undefined;
  }
}

/**
 * The secret columns to write, or `{}` when nothing changed.
 *
 * ┌─ ENCRYPTED HERE, AND ONLY HERE ──────────────────────────────────────────┐
 * │ This is the one place a PUK, a RADIUS password or a RIO crosses from the │
 * │ partner's answer into the database, and it crosses as a vault blob       │
 * │ (`encrypt`, AES-256-GCM, `OBLIWAN_ENCRYPTION_KEY`). The CHECKs of        │
 * │ migrations 077 and 079 refuse anything that is not one, so a defect that │
 * │ tried to store a plaintext would fail the upsert rather than succeed.    │
 * │                                                                         │
 * │ Filled and replaced, NEVER cleared by the feed — the ICCID's rule: a     │
 * │ listing that stops carrying a PUK (a role change at the partner) does    │
 * │ not mean the SIM lost it. A value that did not change is not re-written: │
 * │ a fresh IV per sweep would rewrite every blob of the fleet every four    │
 * │ hours for nothing. When one changes, all present ones are re-written     │
 * │ under the current key, so `secrets_key_version` describes every blob.     │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
function secretColumns(secrets: SimLineSecrets, existing: ExistingLineRow | undefined): Record<string, unknown> {
  const stored = Object.fromEntries(
    SIM_LINE_SECRET_FIELDS.map((f) => [f, openStored(existing?.[SECRET_COLUMN[f]] ?? null)]),
  ) as Record<SimLineSecretField, string | undefined>;
  const changed = SIM_LINE_SECRET_FIELDS.some((f) => {
    const v = secrets.value(f);
    return v !== null && v !== stored[f];
  });
  if (!changed) return {};
  const out: Record<string, unknown> = { secrets_key_version: currentKeyVersion() };
  for (const f of SIM_LINE_SECRET_FIELDS) {
    const next = secrets.value(f) ?? stored[f];
    // A blob the vault cannot open and the feed did not replace is left as it
    // is: overwriting it with nothing would destroy the one copy there is.
    if (next !== undefined && next !== null) out[SECRET_COLUMN[f]] = encrypt(next);
  }
  return out;
}

/** Returns true when the line was created by this call. */
async function upsertLine(accountId: number, line: RawSimLine): Promise<boolean> {
  const existing = await db('sim_lines')
    .where('account_id', accountId)
    .where('msisdn', line.msisdn)
    .first<ExistingLineRow | undefined>(
      'id', 'tenant_id', 'device_id', 'iccid', ...SIM_LINE_SECRET_FIELDS.map((f) => SECRET_COLUMN[f]),
    );

  // ┌─ THE PARTNER'S ICCID ONLY FILLS AN EMPTY ONE ──────────────────────────┐
  // │ A stored ICCID was typed by an operator or read in the router's modem  │
  // │ by the bench — the card actually in the box. When the partner's serial │
  // │ DISAGREES with it, the partner does not win: the stored value is kept  │
  // │ (the partner's stays in `sim_serial`, so nothing is lost) and the      │
  // │ disagreement is logged for somebody to look at — a card swapped in the │
  // │ field, or a partner record that is wrong. Overwriting would silently   │
  // │ unlink the line from the router that holds it (deviceLink.service).     │
  // └────────────────────────────────────────────────────────────────────────┘
  let iccid = line.iccid;
  if (iccid && existing?.iccid && iccid !== existing.iccid) {
    logger.warn(
      { accountId, lineId: existing.id },
      'SIM inventory: the partner reports an ICCID that differs from the one stored on this line ' +
        '(typed by an operator or read at the bench); the stored one is kept, the partner\'s is in sim_serial',
    );
    iccid = null;
  }

  // ┌─ AN ICCID IS FILLED ONLY WHEN NO OTHER LINE CARRIES IT ────────────────┐
  // │ `sim_lines_iccid_uq` is a GLOBAL partial unique index (migration 032). │
  // │ A card the partner lists on two lines — a terminated subscription and  │
  // │ the live one that replaced it — would otherwise fail this upsert with  │
  // │ a constraint violation and lose the WHOLE line, every sweep. Live lines │
  // │ are upserted first (see the caller), so the line holding the card      │
  // │ today claims it. The serial itself is kept on every line (`sim_serial`).│
  // └────────────────────────────────────────────────────────────────────────┘
  if (iccid && iccid !== existing?.iccid) {
    const holderQuery = db('sim_lines').where('iccid', iccid);
    if (existing) holderQuery.whereNot('id', existing.id);
    const holder = await holderQuery.first<{ id: number } | undefined>('id');
    if (holder) {
      logger.warn(
        { accountId, lineId: existing?.id ?? null, holderLineId: holder.id },
        'SIM inventory: the partner reports an ICCID another line already carries; not filled on this one',
      );
      iccid = null;
    }
  }

  const facts = line.partner ? partnerColumns(line.partner) : {};
  const secretCols = line.secrets ? secretColumns(line.secrets, existing) : {};

  if (existing) {
    // `tenant_id`, `site_id`, `device_id`, the threshold and the auto-recharge
    // flag are NOT in this patch, and must never be: they are an operator's
    // decisions, and a partner's inventory feed has no business overwriting
    // them on every sweep.
    // Filled only into an EMPTY column (see above): a stored value is never
    // replaced by the feed.
    const iccidFilled = iccid !== null && existing.iccid === null;
    await db.transaction(async (trx) => {
      await trx('sim_lines')
        .where('id', existing.id)
        .update({
          operator: line.operator,
          client_code: line.clientCode,
          status: line.status,
          // An ICCID is only ever FILLED, never cleared and never replaced: a
          // null from the feed means "not reported" (a 13-digit serial is not
          // an ICCID), not "this SIM has no serial" — and clearing or
          // overwriting it would destroy a value an operator typed or the
          // bench read.
          ...(iccidFilled ? { iccid } : {}),
          // Same rule as the ICCID: refreshed when the listing carries them, kept
          // when it does not — a listing that omits the offer does not mean the
          // line lost it, and clearing it would empty the volume catalogue.
          ...(line.offerType ? { offer_type: line.offerType } : {}),
          ...(line.purchaseTariffCode ? { purchase_tariff_code: line.purchaseTariffCode } : {}),
          ...facts,
          ...secretCols,
          last_seen_at: trx.fn.now(),
          updated_at: trx.fn.now(),
        });
      // The partner lists the line as terminated: its open top-up proposals
      // are expired and its episodes closed, in the transaction that stores
      // the status, so no approval outlives the subscription it was for.
      // Idempotent — on a line already settled it changes nothing.
      if (line.status === 'terminated') await settleOpenWorkOnTermination(trx, existing.id);
      // The partner just gave an assigned line its card: link it to the ONE
      // router of its tenant whose modem was read with it, exactly as an
      // operator typing the ICCID does (`updateLine`, deviceLink.service).
      if (iccidFilled && existing.tenant_id !== null && existing.device_id === null) {
        const linked = await linkDeviceByLineIccid(trx, existing.id);
        if (linked.linked) {
          logger.info({ lineId: existing.id, deviceId: linked.deviceId }, 'SIM line linked to the router whose modem holds its ICCID');
        }
      }
    });
    return false;
  }

  await db('sim_lines').insert({
    account_id: accountId,
    // NULL — the pool. A new line is never guessed into a tenant.
    tenant_id: null,
    msisdn: line.msisdn,
    operator: line.operator,
    client_code: line.clientCode,
    iccid,
    status: line.status,
    offer_type: line.offerType ?? null,
    purchase_tariff_code: line.purchaseTariffCode ?? null,
    ...facts,
    ...secretCols,
  });
  return true;
}

// ============================================================================
// Balances, episodes and proposals
// ============================================================================

interface BalanceStateRow {
  id: string;
  zone: string;
  recharge_mb: number | null;
  used_mb: number | null;
  rest_mb: number | null;
  low_since: Date | string | null;
}

/**
 * Exported ONLY for `f9-sim.verify.ts`, which needs to drive one zone at a
 * time to prove the casing invariant — a full `syncAccount` goes through the
 * fake partner and cannot vary a single label. Nothing in production calls the
 * exported name; the sweep calls it directly.
 */
export const applyBalancesForTest = (
  line: Parameters<typeof applyBalances>[0],
  zones: RawSimBalance[],
): Promise<{ updated: number; proposals: number }> => applyBalances(line, zones);

async function applyBalances(
  line: LineRow,
  zones: RawSimBalance[],
): Promise<{ updated: number; proposals: number }> {
  // ┌─ THE LOW RULE IS THE SCREENS' RULE (brick 6) ─────────────────────────┐
  // │ Percent of each zone's own envelope when it is known, the MB remaining │
  // │ otherwise — `evaluateZoneUsage`, the same function the listing uses, so │
  // │ the episode marker and the dashboard cannot disagree. `thresholdMb`   │
  // │ stays the recorded `threshold_mb_at_proposal` (the MB fallback).        │
  // └────────────────────────────────────────────────────────────────────────┘
  const policy = lowDataPolicy(
    line,
    await globalThresholdMb(line.tenant_id),
    await globalLowPercent(line.tenant_id),
  );
  const thresholdMb = policy.thresholdMb;

  let updated = 0;
  let proposals = 0;
  const nowIso = new Date().toISOString();
  const applied: SimZoneBalance[] = [];

  for (const z of zones) {
    // Canonicalised ONCE, here: `sim_balances` is keyed on (sim_id, zone) and
    // each row carries its own episode marker, so two spellings of one zone
    // are two episodes and two proposals for one shortage.
    const zone = canonicalZone(z.zone);
    const state = await db.transaction(async (trx) => upsertZone(trx, line, zone, z, policy, zones.length));
    if (state.changed) updated += 1;
    applied.push({
      zone,
      rechargeMb: z.rechargeMb,
      usedMb: z.usedMb,
      restMb: z.restMb,
      observedAt: nowIso,
      lowSince: state.lowSince,
    });

    // A proposal is only ever created for a zone that is DEFINITELY low, on a
    // line somebody opted in, in a workspace that can be re-invoiced. `unknown`
    // never reaches here — `evaluateBalance` returns it for a null reading and
    // this branch requires `low`.
    if (
      state.verdict === 'low' &&
      state.lowSince !== null &&
      line.auto_recharge_enabled &&
      line.tenant_id !== null
    ) {
      const created = await proposeForLowZone({
        simId: line.id,
        accountId: await accountIdOf(line.id),
        platform: await platformOf(line.id),
        tenantId: line.tenant_id,
        tenantName: await tenantNameOf(line.tenant_id),
        msisdn: line.msisdn,
        operator: line.operator,
        siteId: line.site_id,
        siteName: await siteNameOf(line.site_id, line.tenant_id),
        deviceName: await deviceNameOf(line.device_id, line.tenant_id),
        zone,
        restMb: z.restMb,
        thresholdMb,
        planMb: line.recharge_plan_mb,
        lowSince: state.lowSince,
      });
      if (created) proposals += 1;
    }
  }

  await announceLineIfLow(line, applied, policy);
  return { updated, proposals };
}

/**
 * Upserts one zone and maintains its episode marker.
 *
 * `low_since` is the load-bearing column (migration 032, decision 6):
 *   - not low → cleared, which ENDS the episode and makes the next fall a new
 *     one with a new idempotency key;
 *   - low and no marker → set to now, which OPENS the episode;
 *   - low with a marker → left exactly as it is. Touching it here would mint a
 *     new key on every sweep and propose a top-up every four hours.
 *
 * `unknown` leaves the marker ALONE rather than clearing it: a partner that
 * stops answering for one sweep must not silently close an open episode and
 * then reopen it as a duplicate proposal on the next reading.
 */
async function upsertZone(
  trx: Knex.Transaction,
  line: LineRow,
  zone: string,
  z: RawSimBalance,
  policy: SimLowDataPolicy,
  zoneCount: number,
): Promise<{ changed: boolean; lowSince: string | null; verdict: 'ok' | 'low' | 'unknown' }> {
  // ┌─ THE READ MUST MATCH THE INDEX THE WRITE CONFLICTS ON ──────────────────┐
  // │ Row identity in `sim_balances` is `(sim_id, lower(zone))` — a FUNCTIONAL │
  // │ unique index (migration 032). A `.where('zone', zone)` is Postgres `=`,  │
  // │ which is case-SENSITIVE, so the two disagreed the moment the partner     │
  // │ changed a label's casing, which migration 032 itself calls "one backend  │
  // │ deployment on their side":                                               │
  // │                                                                         │
  // │   the read misses        -> `existing` undefined -> a NEW `low_since`    │
  // │   the write conflicts    -> MERGEs into the very row the read missed,    │
  // │                             overwriting the open episode                 │
  // │   `zone` was not merged  -> the stored casing stayed frozen, so the      │
  // │                             next sweep missed again, and the next...     │
  // │                                                                         │
  // │ Result: a fresh episode, a fresh idempotency key and therefore a FRESH   │
  // │ PROPOSAL on every sweep — six a day at the default interval — with the   │
  // │ unique index intact and doing nothing, plus a notification on each and a │
  // │ history row on each. Precisely decision 5's stated failure, reached      │
  // │ through the fix that was meant to prevent it.                            │
  // │                                                                         │
  // │ `zone` is now in the merge as well, so the stored label follows the      │
  // │ partner's current casing instead of being frozen at first insert.        │
  // └─────────────────────────────────────────────────────────────────────────┘
  const existing = await trx<BalanceStateRow>('sim_balances')
    .where('sim_id', line.id)
    .whereRaw('lower(zone) = lower(?)', [zone])
    .forUpdate()
    .first();

  const verdict = evaluateZoneUsage({ zone, usedMb: z.usedMb, restMb: z.restMb }, policy, zoneCount).verdict;

  let lowSince: Date | null = existing?.low_since ? new Date(existing.low_since) : null;
  if (verdict === 'ok') lowSince = null;
  else if (verdict === 'low' && lowSince === null) lowSince = new Date();

  const changed =
    !existing ||
    existing.rest_mb !== z.restMb ||
    existing.used_mb !== z.usedMb ||
    existing.recharge_mb !== z.rechargeMb;

  const now = new Date();
  await trx('sim_balances')
    .insert({
      sim_id: line.id,
      zone,
      recharge_mb: z.rechargeMb,
      used_mb: z.usedMb,
      rest_mb: z.restMb,
      observed_at: now,
      low_since: lowSince,
    })
    // The conflict target is the FUNCTIONAL index `(sim_id, lower(zone))`, not
    // a plain column pair — see migration 032. Expressed as raw because that is
    // the only form knex can point at a functional index with.
    .onConflict(db.raw('(sim_id, lower(zone))') as unknown as string)
    .merge({
      // `zone` IS merged: the stored label follows the partner's current
      // casing. Frozen at first insert, it made every later read miss.
      zone,
      recharge_mb: z.rechargeMb,
      used_mb: z.usedMb,
      rest_mb: z.restMb,
      observed_at: now,
      // ┌─ THE EPISODE IS SETTLED BY THE DATABASE, NOT BY THE READ ──────────┐
      // │ Two sweeps can reach a zone with no row yet — the timer and the    │
      // │ manual `POST /accounts/:id/sync` — and both would then compute     │
      // │ their own `now()` as the episode start, producing two markers and  │
      // │ two idempotency keys for one shortage. Written as a CASE over the  │
      // │ EXISTING row so the earliest start always wins, whoever lands      │
      // │ second: not low clears it, low keeps whatever is already there.    │
      // └────────────────────────────────────────────────────────────────────┘
      low_since:
        lowSince === null
          ? null
          : db.raw('COALESCE(sim_balances.low_since, EXCLUDED.low_since)'),
      updated_at: now,
    });

  // History is written ONLY on change (migration 032, decision 5). A row per
  // sweep would be 1.3 M rows a year carrying no information on the days
  // nothing moved. `onConflict().ignore()` covers a retried sweep landing on
  // the same instant.
  if (changed) {
    await trx('sim_balance_samples')
      .insert({
        sim_id: line.id,
        zone,
        recharge_mb: z.rechargeMb,
        used_mb: z.usedMb,
        rest_mb: z.restMb,
        observed_at: now,
      })
      .onConflict(['sim_id', 'zone', 'observed_at'])
      .ignore();
  }

  // Re-read the settled marker: with the COALESCE above, the row may carry an
  // EARLIER `low_since` than this sweep proposed (a concurrent sweep won the
  // race). Returning the local guess would build the idempotency key on an
  // episode that is not the stored one — the exact mismatch this whole section
  // is about.
  const settled = await trx<BalanceStateRow>('sim_balances')
    .where('sim_id', line.id)
    .whereRaw('lower(zone) = lower(?)', [zone])
    .first();

  return {
    changed,
    lowSince: settled?.low_since ? new Date(settled.low_since).toISOString() : null,
    verdict,
  };
}

// ============================================================================
// Announcements
// ============================================================================

/**
 * Raises the in-browser alert and the notification-channel message for a line
 * that is low.
 *
 * ┌─ ONE ALERT PER EPISODE PER REMINDER WINDOW, COMPUTED NOT REMEMBERED ──────┐
 * │ `stableKey` carries the episode start AND a bucket index derived from     │
 * │ `SIM_ALERT_REMIND_HOURS`. `liveAlertService.add` skips an insert when an  │
 * │ UNREAD alert with the same key already exists, so:                        │
 * │   - within one reminder window the operator is told once;                 │
 * │   - the window after, the bucket changes and a still-low line says so     │
 * │     again;                                                                │
 * │   - a new episode has a new `lowSince` and is therefore always new.       │
 * │ No state table, nothing to reconcile, and a restarted worker behaves      │
 * │ identically — which the prototype's `state.json` did not.                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
async function announceLineIfLow(
  line: LineRow,
  zones: SimZoneBalance[],
  policy: SimLowDataPolicy,
): Promise<void> {
  // A pooled line has no tenant to notify. It is still shown as low on the
  // platform dashboard; it just has nobody to tell.
  if (line.tenant_id === null) return;

  const judged = simLineUsageVerdict('active', zones, policy);
  const worst = judged.zone;
  if (!worst || judged.verdict !== 'low' || !worst.lowSince) return;
  const usage = judged.worst;

  const remindHours = await globalNumber(line.tenant_id, SETTINGS_KEYS.SIM_ALERT_REMIND_HOURS);
  const elapsedMs = Date.now() - new Date(worst.lowSince).getTime();
  const bucket = Math.floor(elapsedMs / (remindHours * 3_600_000));

  const title = 'Mobile data running out';
  const message =
    usage && usage.basis === 'percent' && usage.envelopeMb !== null
      ? `${line.msisdn} has used ${usage.usedPercent} % of ${formatData(usage.envelopeMb)} in ${worst.zone} ` +
        `(alert at ${policy.thresholdPercent} %).`
      : `${line.msisdn} has ${formatData(worst.restMb)} left in ${worst.zone} ` +
        `(threshold ${formatData(policy.thresholdMb)}).`;

  const raised = await liveAlertService.add(line.tenant_id, {
    severity: 'warning',
    title,
    message,
    navigateTo: `/mobile/lines/${line.id}`,
    simLineId: line.id,
    stableKey: `sim-low:${line.id}:${worst.zone}:${worst.lowSince}:${bucket}`,
  });

  // ┌─ THE CHANNEL MESSAGE RIDES ON THE BROWSER ALERT'S DEDUPLICATION ────────┐
  // │ `liveAlertService.add` returns the inserted row, or `null` when an      │
  // │ unread alert with the same `stableKey` already exists. Sending the      │
  // │ channel message unconditionally would put a Teams/Slack/e-mail message  │
  // │ on EVERY sweep for a line that is still low — six a day at the default  │
  // │ four-hour interval, against one browser alert per 24-hour reminder      │
  // │ window. That is how a notification channel gets muted, and a muted      │
  // │ channel is how the one that mattered gets missed.                       │
  // └────────────────────────────────────────────────────────────────────────┘
  if (raised === null) return;

  await notificationService
    .sendForTenant(line.tenant_id, 'sim_low_data', {
      entityName: line.msisdn,
      entityUrl: `/mobile/lines/${line.id}`,
      oldStatus: 'ok',
      newStatus: 'low',
      message,
      timestamp: new Date().toISOString(),
      // One incident per line while it is low; the 24 h reminders repeat it.
      // No 'resolved' is ever sent: nothing marks a line as no longer low.
      stableKey: `obliwan:sim:${line.id}:low`,
      severity: 'warning',
      isRecovery: false,
      ...(worst.lowSince && !Number.isNaN(Date.parse(String(worst.lowSince))) ? { occurredAt: new Date(worst.lowSince).toISOString() } : {}),
      entityId: line.id,
      entityType: 'sim_line',
    })
    .catch((err: unknown) => {
      // A notification failure must never abort a sweep: the balance is already
      // stored and the browser alert already raised.
      logger.warn({ simId: line.id }, `SIM low-data notification failed: ${String(err)}`);
    });
}

async function announceAccountProblem(account: SimAccountRow, reason: string): Promise<void> {
  // An account is platform-level and has no tenant, so the alert goes to every
  // tenant that has lines on it — they are the ones whose balances just went
  // stale, and a silent staleness is the failure this feature cannot afford.
  const tenants = await db('sim_lines')
    .where('account_id', account.id)
    .whereNotNull('tenant_id')
    .distinct<Array<{ tenant_id: number }>>('tenant_id');

  // ┌─ WHAT A TENANT IS TOLD, AND WHAT STAYS ON THE ADMIN SCREEN ────────────┐
  // │ `sim_accounts` is PLATFORM-scoped (migration 032, decision 2): its name │
  // │ is the operator's own contract label ("CFAST — Nexytel"), its           │
  // │ `last_sync_error` is the partner's raw response, and neither is a       │
  // │ customer's business. The first draft interpolated both into every       │
  // │ affected tenant's alert feed, which is the same over-sharing            │
  // │ `fleetSummary` deliberately avoids by reporting only a COUNT of         │
  // │ unhealthy accounts.                                                     │
  // │                                                                        │
  // │ A tenant is told the thing that is true for them and actionable by      │
  // │ them: their SIM balances are no longer being read. The name, the host   │
  // │ and the partner's error stay in `sim_accounts` and `sim_sync_runs`,     │
  // │ behind `requireRole('admin')`, where the person who can fix it looks.   │
  // └────────────────────────────────────────────────────────────────────────┘
  logger.error({ accountId: account.id, reason }, 'SIM partner account cannot authenticate');
  for (const t of tenants) {
    await liveAlertService.add(t.tenant_id, {
      severity: 'down',
      title: 'Mobile data is no longer being read',
      message:
        'Remaining data can no longer be read for some of the SIM lines in this workspace: ' +
        'the mobile partner connection needs attention. Those lines show as not readable ' +
        'until it is restored.',
      navigateTo: '/mobile',
      // No bucket: this is not a reminder, it is a standing fault. One unread
      // alert until somebody reads it or fixes the token.
      stableKey: `sim-account-auth:${account.id}`,
    });
  }
}

// ============================================================================
// Small lookups
// ============================================================================
//
// Read per proposal rather than joined into the sweep's main query on purpose:
// a proposal is rare (one per low episode) and its fields are FROZEN into the
// row, so they must be read at the instant the proposal is made rather than
// from a snapshot taken at the top of a sweep that may have run for minutes.

async function accountIdOf(simId: number): Promise<number> {
  const row = await db('sim_lines')
    .where('id', simId)
    .first<{ account_id: number } | undefined>('account_id');
  return row!.account_id;
}

async function platformOf(simId: number): Promise<SimPlatform> {
  const row = await db('sim_lines as l')
    .join('sim_accounts as a', 'a.id', 'l.account_id')
    .where('l.id', simId)
    .first<{ platform: SimPlatform } | undefined>('a.platform');
  return row!.platform;
}

async function tenantNameOf(tenantId: number): Promise<string | null> {
  const row = await db('tenants').where('id', tenantId).first<{ name: string } | undefined>('name');
  return row?.name ?? null;
}

async function siteNameOf(siteId: number | null, tenantId: number): Promise<string | null> {
  if (siteId === null) return null;
  // Matched on id AND tenant: `site_id` is nullable with SET NULL semantics, so
  // the pair really can go stale, and a borrowed site name on an invoice line
  // is a customer reading another customer's site.
  const row = await db('sites')
    .where('id', siteId)
    .where('tenant_id', tenantId)
    .first<{ name: string } | undefined>('name');
  return row?.name ?? null;
}

async function deviceNameOf(deviceId: number | null, tenantId: number): Promise<string | null> {
  if (deviceId === null) return null;
  const row = await db('devices')
    .where('id', deviceId)
    .where('tenant_id', tenantId)
    .first<{ name: string } | undefined>('name');
  return row?.name ?? null;
}
