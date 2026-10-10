/**
 * ObliWAN — the partner's own recharge history: stored, and reconciled.
 *
 * ┌─ WHAT THIS MODULE MAY DO, AND WHAT IT MAY NOT ───────────────────────────┐
 * │ It READS what the partner says was bought and LINKS it to ObliWAN's own  │
 * │ decisions. It never buys (the call that buys is not on any interface it  │
 * │ can reach), never creates a proposal, and never invents a billing row.   │
 * │                                                                          │
 * │ The one state change it makes is `approved → recorded`, and only when    │
 * │ ONE partner purchase and ONE approval match without ambiguity. That is   │
 * │ the transition a human makes today by hand after buying on the portal —  │
 * │ same state, same columns — so the report cannot tell the two apart       │
 * │ except through `completed_by` (NULL = the sweep) and the audit ledger.   │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHY AMBIGUITY LINKS NOTHING ────────────────────────────────────────────┐
 * │ Two approvals open on the same line, one purchase observed: linking the  │
 * │ purchase to either would bill a decision nobody executed and leave the   │
 * │ other one open forever. So an ambiguous match stays unlinked, visible on │
 * │ the line screen, and the human who made the purchase records it. A      │
 * │ wrong automatic link is worse than a missing one, because it is believed.│
 * └──────────────────────────────────────────────────────────────────────────┘
 */

import {
  canRechargeTransition,
  type SimPartnerRecharge,
  type SimPartnerRechargeOutcome,
  type SimRechargeOffers,
  type SimRechargeStatus,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { appendAudit } from '../attestation/auditLog.service';
import { SimAccountError, loadCredential, type SimAccountRow } from './account.service';
import { getLine, type SimScope } from './line.service';
import { stripQuery } from './phenix.connector';
import { getConnector } from './registry';
import { SimConnectorError, type RawPartnerRecharge, type SimSession } from './types';

/**
 * How far a partner timestamp may precede the approval it settles. The
 * partner's wall clock is parsed as Europe/Paris and has never been compared
 * against ours; an hour absorbs a zone mistake without letting a purchase
 * from the previous day settle today's approval.
 */
const CLOCK_TOLERANCE_MS = 60 * 60_000;
/** A purchase more than this long after the approval is not "the" purchase. */
const APPROVAL_WINDOW_MS = 31 * 24 * 60 * 60_000;
/** Matching a partner row to a top-up a HUMAN already recorded. */
const RECORDED_WINDOW_MS = 3 * 24 * 60 * 60_000;

interface PartnerRow {
  id: string;
  account_id: number;
  sim_id: number | null;
  msisdn: string;
  partner_ref: string;
  requested_at: Date | string | null;
  period: string | null;
  zone_code: string | null;
  volume_mb: number | null;
  product_code: string | null;
  partner_state: string | null;
  partner_status: string | null;
  outcome: SimPartnerRechargeOutcome;
  recharge_id: string | null;
  first_seen_at: Date | string;
}

interface CandidateRow {
  id: string;
  status: SimRechargeStatus;
  tenant_id: number | null;
  decided_at: Date | string | null;
  completed_at: Date | string | null;
  billing_reference: string | null;
  plan_mb: number | null;
}

function iso(v: Date | string | null): string | null {
  if (v === null) return null;
  return v instanceof Date ? v.toISOString() : new Date(v).toISOString();
}

function toApi(r: PartnerRow): SimPartnerRecharge {
  return {
    id: Number(r.id),
    simId: r.sim_id,
    msisdn: r.msisdn,
    requestedAt: iso(r.requested_at),
    period: r.period,
    zoneCode: r.zone_code,
    volumeMb: r.volume_mb,
    productCode: r.product_code,
    partnerState: r.partner_state,
    partnerStatus: r.partner_status,
    outcome: r.outcome,
    rechargeId: r.recharge_id === null ? null : Number(r.recharge_id),
    firstSeenAt: iso(r.first_seen_at)!,
  };
}

/**
 * Upserts one line's history as read. Returns how many rows were NEW.
 *
 * On a re-read, only what the partner may legitimately change is refreshed —
 * its state and status, and therefore our outcome (a pending top-up becomes OK
 * once the partner's manager validates it). The volume, the date and the zone
 * of a purchase do not change, and a later read disagreeing about them is a
 * different row, which is what the synthesised key makes it.
 */
export async function storePartnerRecharges(
  accountId: number,
  line: { id: number; msisdn: string },
  rows: RawPartnerRecharge[],
): Promise<number> {
  if (rows.length === 0) return 0;
  // A partner that lists the same row twice in one answer must not abort the
  // upsert with "ON CONFLICT DO UPDATE command cannot affect row a second time".
  const unique = new Map<string, RawPartnerRecharge>();
  for (const r of rows) unique.set(r.partnerRef, r);

  const inserted = await db('sim_partner_recharges')
    .insert(
      [...unique.values()].map((r) => ({
        account_id: accountId,
        sim_id: line.id,
        msisdn: line.msisdn,
        partner_ref: r.partnerRef,
        requested_at: r.requestedAt,
        period: r.period,
        zone_code: r.zoneCode,
        volume_mb: r.volumeMb,
        product_code: r.productCode,
        partner_state: r.partnerState,
        partner_status: r.partnerStatus,
        outcome: r.outcome,
      })),
    )
    .onConflict(['account_id', 'partner_ref'])
    .merge(['partner_state', 'partner_status', 'outcome', 'sim_id', 'last_seen_at'])
    // `xmax = 0` is PostgreSQL's own tell for "this row was inserted, not
    // updated" — the only way to count new rows in one round trip.
    .returning<Array<{ inserted: boolean }>>(db.raw('(xmax = 0) AS inserted'));

  await db('sim_lines').where('id', line.id).update({ partner_history_read_at: db.fn.now() });
  return inserted.filter((r) => r.inserted).length;
}

export interface ReconcileOutcome {
  /** Approvals moved to `recorded` by a matching partner purchase. */
  recorded: number;
  /** Partner purchases linked to a top-up a human had already recorded. */
  linked: number;
  /** Partner purchases left unlinked because more than one decision matched. */
  ambiguous: number;
}

/**
 * Links this line's unlinked, successful partner purchases to ObliWAN's
 * decisions. Oldest purchase first, so two purchases and two approvals pair
 * up in order rather than both reaching for the newest approval.
 */
export async function reconcilePartnerRecharges(simId: number): Promise<ReconcileOutcome> {
  const out: ReconcileOutcome = { recorded: 0, linked: 0, ambiguous: 0 };

  const pending = await db<PartnerRow>('sim_partner_recharges')
    .where('sim_id', simId)
    .where('outcome', 'ok')
    .whereNull('recharge_id')
    .whereNotNull('requested_at')
    .orderBy('requested_at', 'asc');

  for (const p of pending) {
    const at = new Date(p.requested_at as Date | string).getTime();
    try {
      const result = await db.transaction(async (trx) => {
        // Every candidate is locked, and re-checked for an existing link inside
        // the lock: two sweeps reconciling the same line must not both link.
        const candidates = await trx<CandidateRow>('sim_recharges as r')
          .where('r.sim_id', simId)
          .whereIn('r.status', ['approved', 'recorded'])
          .whereNotExists(
            trx('sim_partner_recharges as p').whereRaw('p.recharge_id = r.id'),
          )
          .select('r.id', 'r.status', 'r.tenant_id', 'r.decided_at', 'r.completed_at', 'r.billing_reference', 'r.plan_mb')
          .forUpdate();

        const approvals = candidates.filter((c) => {
          if (c.status !== 'approved' || c.decided_at === null) return false;
          const decided = new Date(c.decided_at).getTime();
          return at >= decided - CLOCK_TOLERANCE_MS && at <= decided + APPROVAL_WINDOW_MS;
        });
        const recorded = candidates.filter((c) => {
          if (c.status !== 'recorded' || c.completed_at === null) return false;
          return Math.abs(new Date(c.completed_at).getTime() - at) <= RECORDED_WINDOW_MS;
        });

        // An open approval wins over a past record: a purchase that follows an
        // approval IS that approval being carried out. Only when there is no
        // open approval do we look for a human record of the same purchase.
        const pool = approvals.length > 0 ? approvals : recorded;
        if (pool.length !== 1) return pool.length === 0 ? 'none' : 'ambiguous';

        const target = pool[0];
        const ref = `phenix:${p.partner_ref}`;
        await trx('sim_partner_recharges').where('id', p.id).update({ recharge_id: target.id });

        if (target.status === 'approved') {
          if (!canRechargeTransition('approved', 'recorded')) return 'none';
          await trx('sim_recharges')
            .where('id', target.id)
            .update({
              status: 'recorded',
              // The partner's own purchase instant, not the sweep's: the report
              // bills by month, and a purchase on the 31st read on the 1st
              // belongs to the month it was bought in.
              completed_at: p.requested_at,
              completed_by: null,
              failure_reason: null,
              billing_reference: target.billing_reference ?? ref,
              // What was ACTUALLY bought wins over what was proposed: the
              // report must invoice the partner's volume, not our intention.
              plan_mb: p.volume_mb ?? target.plan_mb,
              updated_at: trx.fn.now(),
            });
        } else if (target.billing_reference === null) {
          await trx('sim_recharges')
            .where('id', target.id)
            .update({ billing_reference: ref, updated_at: trx.fn.now() });
        }

        if (target.tenant_id !== null) {
          await appendAudit(
            {
              tenantId: target.tenant_id,
              actorType: 'automation',
              actorId: 'sim-sweep',
              actorName: 'SIM balance sweep',
              action:
                target.status === 'approved'
                  ? 'sim_recharge.recorded_from_partner'
                  : 'sim_recharge.linked_to_partner',
              entityType: 'sim_recharge',
              entityId: String(target.id),
              before: { status: target.status },
              after: {
                status: 'recorded',
                partnerRef: p.partner_ref,
                partnerVolumeMb: p.volume_mb,
                partnerRequestedAt: iso(p.requested_at),
              },
            },
            trx,
          );
        }
        return target.status === 'approved' ? 'recorded' : 'linked';
      });

      if (result === 'recorded') out.recorded += 1;
      else if (result === 'linked') out.linked += 1;
      else if (result === 'ambiguous') out.ambiguous += 1;
    } catch (err) {
      // 23505 = another sweep linked the same decision first. Not an error: the
      // purchase is settled, just not by us.
      if ((err as { code?: string } | null)?.code === '23505') continue;
      logger.warn(
        { simId, partnerRechargeId: p.id },
        `SIM partner-recharge reconciliation failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  if (out.ambiguous > 0) {
    logger.info(
      { simId, ambiguous: out.ambiguous },
      'SIM partner purchases left unlinked: more than one ObliWAN decision matched',
    );
  }
  return out;
}

/** The partner history of one line, newest first, tenant-scoped. */
export async function listPartnerRecharges(
  scope: SimScope,
  simId: number,
): Promise<SimPartnerRecharge[]> {
  // `getLine` applies the tenant predicate; a line the caller cannot see is a
  // 404, never an empty history (which would confirm the line exists).
  const line = await getLine(scope, simId);
  if (!line) throw new SimAccountError('Line not found', 404);

  const q = db<PartnerRow>('sim_partner_recharges')
    .where('sim_id', simId)
    .orderByRaw('requested_at DESC NULLS LAST, id DESC')
    .limit(200);
  // Same cut as `getLineHistory`: a line re-assigned from customer A to
  // customer B must not show B what A bought. A row with no readable date
  // cannot be placed on either side of the move, so it is withheld from the
  // tenant view rather than guessed into it.
  if (!scope.masterView) {
    const owned = await db('sim_lines')
      .where('id', simId)
      .first<{ tenant_assigned_at: Date | string | null } | undefined>('tenant_assigned_at');
    if (owned?.tenant_assigned_at) {
      q.whereNotNull('requested_at').where('requested_at', '>=', owned.tenant_assigned_at);
    }
  }
  return (await q).map(toApi);
}

// ============================================================================
// The partner's volume catalogue — read live, on demand, never on the sweep
// ============================================================================

/**
 * Why not on the sweep: the catalogue is one request per line AND per zone,
 * for a list that changes when the partner changes its price list, not every
 * four hours. It is asked for when somebody opens a line, and kept briefly.
 */
const OFFERS_TTL_MS = 10 * 60_000;
const offersCache = new Map<number, { at: number; value: SimRechargeOffers }>();

export async function fetchRechargeOffers(scope: SimScope, simId: number): Promise<SimRechargeOffers> {
  const line = await getLine(scope, simId);
  if (!line) throw new SimAccountError('Line not found', 404);

  const cached = offersCache.get(simId);
  if (cached && Date.now() - cached.at < OFFERS_TTL_MS) return cached.value;

  const account = await db<SimAccountRow>('sim_accounts').where('id', line.accountId).first();
  if (!account) throw new SimAccountError('Partner account not found', 404);
  const attrs = await db('sim_lines')
    .where('id', simId)
    .first<{ offer_type: string | null; purchase_tariff_code: string | null } | undefined>(
      'offer_type',
      'purchase_tariff_code',
    );

  const connector = getConnector(account.platform);
  let session: SimSession | null = null;
  try {
    session = await connector.open({
      accountId: account.id,
      baseUrl: account.base_url,
      partnerRef: account.partner_ref,
      authMode: account.auth_mode,
      credential: loadCredential(account),
    });
    if (!session.listRechargeOffers) {
      throw new SimAccountError(
        `${account.platform} does not expose a volume catalogue ObliWAN can read.`,
        409,
      );
    }
    // The zone codes come from the same consumption read the extranet uses to
    // fill its zone dropdown; ObliWAN's stored zones are labels, not codes.
    const zones = await session.fetchBalances(line.msisdn);
    const out: SimRechargeOffers = { simId, fetchedAt: new Date().toISOString(), zones: [] };
    for (const z of zones) {
      if (!z.zoneCode) {
        out.zones.push({
          zone: z.zone,
          zoneCode: null,
          offers: [],
          error: 'The partner did not give a code for this zone, so its catalogue cannot be asked for.',
        });
        continue;
      }
      try {
        const offers = await session.listRechargeOffers({
          msisdn: line.msisdn,
          operator: line.operator,
          zoneCode: z.zoneCode,
          offerType: attrs?.offer_type ?? null,
          purchaseTariffCode: attrs?.purchase_tariff_code ?? null,
        });
        out.zones.push({ zone: z.zone, zoneCode: z.zoneCode, offers, error: null });
      } catch (err) {
        if (err instanceof SimConnectorError && err.code === 'AUTH_FAILED') throw err;
        out.zones.push({
          zone: z.zone,
          zoneCode: z.zoneCode,
          offers: [],
          error: stripQuery(err instanceof Error ? err.message : String(err)),
        });
      }
    }
    offersCache.set(simId, { at: Date.now(), value: out });
    return out;
  } catch (err) {
    if (err instanceof SimAccountError) throw err;
    if (err instanceof SimConnectorError) {
      // 502, never 401/403: the partner refusing the VAULT's token says nothing
      // about the operator's own session, and the client logs out on a 401.
      throw new SimAccountError(
        err.code === 'NOT_IMPLEMENTED'
          ? err.message
          : `The partner did not answer: ${stripQuery(err.message)}`,
        err.code === 'NOT_IMPLEMENTED' ? 409 : 502,
      );
    }
    throw err;
  } finally {
    await session?.close().catch(() => undefined);
  }
}
