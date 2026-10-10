import apiClient from './client';
import type {
  ApiResponse,
  SimAccount,
  SimAccountInput,
  SimCredentialInput,
  SimFleetSummary,
  SimLine,
  SimLinePartnerFacts,
  SimLineUpdate,
  SimLineVerdict,
  SimPartnerRecharge,
  SimPlatformInfo,
  SimRecharge,
  SimRechargeCompletionInput,
  SimRechargeOffers,
  SimRechargeReport,
  SimRechargeStatus,
  SimZoneBalance,
  SimZoneUsage,
} from '@obliwan/shared';
import { SIM_PARTNER_RECHARGE_OUTCOMES } from '@obliwan/shared';
import { accessField } from '../utils/objectAccess';

/**
 * Mobile data lines.
 *
 * ┌─ EVERY NUMBER THAT CROSSES THIS BOUNDARY CAN BE `null`, AND `null` IS NOT  ┐
 * │ ZERO. `restMb === null` means the partner did not tell us. Rendering it as │
 * │ "0 Mo" would show an operator a fleet-wide emergency that does not exist,  │
 * │ and `??  0` anywhere in this file or in a component reading it recreates   │
 * │ exactly the defect the whole feature was designed around (see              │
 * │ `shared/src/sim.ts`, decision 2). Use `formatData`, which renders an       │
 * │ absent reading as "—".                                                     │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * `cost_cents` arrives as a STRING for the same reason the SNMP thresholds do:
 * PostgreSQL `bigint` is serialised as text by `pg` to avoid losing precision.
 * `num()` is applied on every money and data field rather than trusting the
 * wire — a string silently coerced by `+` elsewhere in a component would sort
 * "9" after "10".
 */

function statusOf(err: unknown): number | undefined {
  return (err as { response?: { status?: number } }).response?.status;
}

/** A route this build does not serve, or a capability the session lacks. */
export function isRouteAbsent(err: unknown): boolean {
  const s = statusOf(err);
  return s === 404 || s === 403;
}

export function errorMessageOf(err: unknown): string {
  const data = (err as { response?: { data?: { error?: string; message?: string } } }).response
    ?.data;
  return data?.error ?? data?.message ?? (err instanceof Error ? err.message : 'Unknown error');
}

type Raw = Record<string, unknown>;

function rows(payload: unknown): Raw[] {
  return Array.isArray(payload) ? (payload as Raw[]) : [];
}

/** Number, or null. NEVER a zero fallback — see the header. */
function num(v: unknown): number | null {
  if (v === null || v === undefined || v === '') return null;
  const n = typeof v === 'number' ? v : Number(v);
  return Number.isFinite(n) ? n : null;
}

function str(v: unknown): string | null {
  return typeof v === 'string' && v !== '' ? v : null;
}

function normalizeZone(raw: Raw): SimZoneBalance {
  return {
    zone: String(raw.zone ?? 'unknown'),
    rechargeMb: num(raw.rechargeMb),
    usedMb: num(raw.usedMb),
    restMb: num(raw.restMb),
    observedAt: String(raw.observedAt ?? ''),
    lowSince: str(raw.lowSince),
  };
}

/** `GET /sim/devices/:id`. `reading` null: the bench never read this router's
 *  modem; `reading.iccid` null: it read it and found no card. */
export interface DeviceSimView {
  reading: { iccid: string | null; imsi: string | null; readAt: string } | null;
  lines: SimLineListItem[];
  /** The card read is on a line linked to ANOTHER router. */
  cardLineElsewhere: { lineId: number; msisdn: string; deviceId: number; deviceName: string | null } | null;
  /** Every LTE modem the fleet read in this router (migration 080). A null
   *  field is NOT READ, never "no SIM". */
  modems: DeviceLteModem[];
  /** Links the cards read here could not make. lineId / msisdn null:
   *  the line is another customer's and is not named. */
  conflicts: DeviceSimConflict[];
}

export interface DeviceLteModem {
  interface: string;
  iccid: string | null;
  imsi: string | null;
  imei: string | null;
  observedAt: string;
}

export interface DeviceSimConflict {
  kind: 'other_tenant' | 'linked_elsewhere' | 'ambiguous';
  iccid: string;
  prefixMatch: boolean;
  lineId: number | null;
  msisdn: string | null;
  detectedAt: string;
}

export interface SimLineListItem extends SimLine {
  /** `terminated`: the partner lists the line as terminated — its own verdict,
   *  never `unknown` (`simLineVerdict`). */
  verdict: SimLineVerdict;
  thresholdMb: number;
  worstZone: SimZoneBalance | null;
  /** `unknown` because the readings aged out, not because there were none. */
  stale: boolean;
  /** Each zone against its own envelope (brick 6). */
  usage: SimZoneUsage[];
  worstUsage: SimZoneUsage | null;
  thresholdPercent: number;
  planEnvelopeMb: number | null;
}

function normalizeUsage(raw: Raw): SimZoneUsage {
  const basis = raw.basis === 'percent' || raw.basis === 'mb' ? raw.basis : null;
  const src = raw.envelopeSource === 'partner' || raw.envelopeSource === 'plan' ? raw.envelopeSource : null;
  return {
    zone: String(raw.zone ?? ''),
    envelopeMb: num(raw.envelopeMb),
    envelopeSource: src,
    usedMb: num(raw.usedMb),
    restMb: num(raw.restMb),
    usedPercent: num(raw.usedPercent),
    verdict: raw.verdict === 'ok' || raw.verdict === 'low' ? raw.verdict : 'unknown',
    basis,
    stale: raw.stale === true,
    observedAt: str(raw.observedAt),
  };
}

function normalizeLine(raw: Raw): SimLineListItem {
  const zones = Array.isArray(raw.zones) ? (raw.zones as Raw[]).map(normalizeZone) : [];
  return {
    id: Number(raw.id),
    // The caller's level on the line (migration 087), read once, here.
    ...accessField(raw.access),
    accountId: Number(raw.accountId),
    platform: raw.platform as SimLineListItem['platform'],
    accountName: String(raw.accountName ?? ''),
    tenantId: num(raw.tenantId),
    msisdn: String(raw.msisdn ?? ''),
    iccid: str(raw.iccid),
    operator: str(raw.operator),
    clientCode: str(raw.clientCode),
    label: str(raw.label),
    siteId: num(raw.siteId),
    siteName: str(raw.siteName),
    deviceId: num(raw.deviceId),
    deviceName: str(raw.deviceName),
    status: (raw.status as SimLine['status']) ?? 'unknown',
    lowThresholdMb: num(raw.lowThresholdMb),
    autoRechargeEnabled: raw.autoRechargeEnabled === true,
    rechargePlanMb: num(raw.rechargePlanMb),
    firstSeenAt: String(raw.firstSeenAt ?? ''),
    lastSeenAt: String(raw.lastSeenAt ?? ''),
    zones,
    verdict: (raw.verdict as SimLineListItem['verdict']) ?? 'unknown',
    // The only field with a fallback, and it is a THRESHOLD, not a reading:
    // a missing threshold would make `evaluateBalance` compare against NaN and
    // report every line as ok. 1024 MB is the shared hardcoded default.
    thresholdMb: num(raw.thresholdMb) ?? 1024,
    worstZone: raw.worstZone ? normalizeZone(raw.worstZone as Raw) : null,
    stale: raw.stale === true,
    usage: Array.isArray(raw.usage) ? (raw.usage as Raw[]).map(normalizeUsage) : [],
    worstUsage: raw.worstUsage && typeof raw.worstUsage === 'object' ? normalizeUsage(raw.worstUsage as Raw) : null,
    // A threshold, not a reading: the shared hardcoded default (80 %).
    thresholdPercent: num(raw.thresholdPercent) ?? 80,
    planEnvelopeMb: num(raw.planEnvelopeMb),
    tenantName: raw.tenantName === undefined ? undefined : str(raw.tenantName),
    partner: raw.partner && typeof raw.partner === 'object' ? normalizePartner(raw.partner as Raw) : null,
  };
}

function bool(v: unknown): boolean | null {
  return typeof v === 'boolean' ? v : null;
}

/**
 * What the partner's listing said (migration 077). The consumption figures go
 * through `num()` like every quantity here: `null` is "the partner left it
 * empty", and it is drawn as "—", never as 0. The secrets are PRESENCE ONLY —
 * the values never cross this boundary on a read (see `secretsApi`).
 */
function normalizePartner(raw: Raw): SimLinePartnerFacts {
  const c = (raw.consumption && typeof raw.consumption === 'object' ? raw.consumption : {}) as Raw;
  const s = (raw.secretsStored && typeof raw.secretsStored === 'object' ? raw.secretsStored : {}) as Raw;
  const d = raw.details;
  return {
    partnerLineId: str(raw.partnerLineId),
    simSerial: str(raw.simSerial),
    imsi: str(raw.imsi),
    customerName: str(raw.customerName),
    siteLabel: str(raw.siteLabel),
    internalRef: str(raw.internalRef),
    state: str(raw.state),
    stateLabel: str(raw.stateLabel),
    simType: str(raw.simType),
    planLabel: str(raw.planLabel),
    planCode: str(raw.planCode),
    activatedAt: str(raw.activatedAt),
    terminatedAt: str(raw.terminatedAt),
    dataOnly: bool(raw.dataOnly),
    apn: str(raw.apn),
    fixedIp: str(raw.fixedIp),
    hasFixedIp: bool(raw.hasFixedIp),
    radiusLogin: str(raw.radiusLogin),
    offerType: str(raw.offerType),
    purchaseTariffCode: str(raw.purchaseTariffCode),
    consumption: {
      nationalMb: num(c.nationalMb),
      roamingMb: num(c.roamingMb),
      nationalPrevMonthMb: num(c.nationalPrevMonthMb),
      roamingPrevMonthMb: num(c.roamingPrevMonthMb),
    },
    observedAt: String(raw.observedAt ?? ''),
    secretsStored: {
      puk1: s.puk1 === true,
      puk2: s.puk2 === true,
      radiusPassword: s.radiusPassword === true,
      rio: s.rio === true,
    },
    details: d && typeof d === 'object' && !Array.isArray(d) ? (d as Record<string, unknown>) : d === undefined ? undefined : null,
  };
}

function normalizeRecharge(raw: Raw): SimRecharge {
  return {
    id: Number(raw.id),
    // The caller's level on the top-up's line (migration 087).
    ...accessField(raw.access),
    simId: num(raw.simId),
    accountId: num(raw.accountId),
    platform: raw.platform as SimRecharge['platform'],
    tenantId: num(raw.tenantId),
    tenantName: str(raw.tenantName),
    msisdn: String(raw.msisdn ?? ''),
    operator: str(raw.operator),
    siteId: num(raw.siteId),
    siteName: str(raw.siteName),
    deviceName: str(raw.deviceName),
    status: raw.status as SimRechargeStatus,
    trigger: raw.trigger as SimRecharge['trigger'],
    zone: String(raw.zone ?? ''),
    restMbAtProposal: num(raw.restMbAtProposal),
    thresholdMbAtProposal: num(raw.thresholdMbAtProposal) ?? 0,
    planMb: num(raw.planMb),
    costCents: num(raw.costCents),
    currency: str(raw.currency),
    billingReference: str(raw.billingReference),
    idempotencyKey: String(raw.idempotencyKey ?? ''),
    proposedAt: String(raw.proposedAt ?? ''),
    proposedBy: num(raw.proposedBy),
    proposedByName: str(raw.proposedByName),
    decidedAt: str(raw.decidedAt),
    decidedBy: num(raw.decidedBy),
    decidedByName: str(raw.decidedByName),
    decisionNote: str(raw.decisionNote),
    completedAt: str(raw.completedAt),
    completedBy: num(raw.completedBy),
    failureReason: str(raw.failureReason),
  };
}

export interface SimSyncRun {
  id: number;
  startedAt: string;
  finishedAt: string | null;
  outcome: string | null;
  linesSeen: number;
  linesNew: number;
  balancesUpdated: number;
  linesFailed: number;
  proposalsCreated: number;
  error: string | null;
}

/** `sim_sync_runs` is served as raw knex rows — snake_case, bigint as text. */
function normalizeRun(raw: Raw): SimSyncRun {
  return {
    id: Number(raw.id),
    startedAt: String(raw.started_at ?? ''),
    finishedAt: str(raw.finished_at),
    outcome: str(raw.outcome),
    linesSeen: num(raw.lines_seen) ?? 0,
    linesNew: num(raw.lines_new) ?? 0,
    balancesUpdated: num(raw.balances_updated) ?? 0,
    linesFailed: num(raw.lines_failed) ?? 0,
    proposalsCreated: num(raw.proposals_created) ?? 0,
    error: str(raw.error),
  };
}

export interface SimCapUsage {
  monthlyRechargeCap: number | null;
  monthlyCostCapCents: number | null;
  rechargesThisMonth: number;
  /** Priced rows only — an unpriced top-up is counted below, never added here. */
  costThisMonthCents: number;
  unpricedThisMonth: number;
}

export interface SimConnectionTest {
  ok: boolean;
  partnerRef: string | null;
  tokenExpiresAt: string | null;
  lineCount: number | null;
  error: string | null;
  errorCode: string | null;
}

/**
 * What step 1 of the interactive sign-in answers.
 *
 * `code_required` comes from a 401/403 and from nothing else, and it is
 * genuinely ambiguous: it fits "wrong password" exactly as well as "now confirm
 * with the code we mailed you", and nobody has ever observed which one Phenix
 * sends. The screen must therefore state both readings rather than pick one,
 * which is why the ambiguity travels to the client instead of being resolved
 * on the server.
 *
 * There used to be a `certain` flag, set for any 2xx without a token on the
 * reasoning that such an answer could only mean a code had gone out. The one
 * such answer ever observed — Phenix's empty 204 — sent no code at all, so the
 * server no longer reports one as sent; every other non-token answer reaches
 * the screen as an error with the connector's own explanation.
 */
export type SimAuthAttempt =
  | { status: 'authenticated'; tokenExpiresAt: string | null; account: SimAccount }
  | { status: 'code_required'; observed: string; account: SimAccount };

export interface SimAuthResolved {
  status: 'authenticated';
  tokenExpiresAt: string | null;
  account: SimAccount;
}

export const simApi = {
  // ── Coverage matrix ───────────────────────────────────────────────────────
  async platforms(): Promise<SimPlatformInfo[]> {
    const res = await apiClient.get<ApiResponse<unknown>>('/sim/platforms');
    return rows(res.data.data) as unknown as SimPlatformInfo[];
  },

  // ── Fleet ─────────────────────────────────────────────────────────────────
  async summary(params: { tenantId?: number } = {}): Promise<SimFleetSummary> {
    const res = await apiClient.get<ApiResponse<SimFleetSummary>>('/sim/summary', { params });
    return res.data.data as SimFleetSummary;
  },

  async lines(params: {
    accountId?: number;
    assignment?: 'assigned' | 'pool';
    verdict?: 'ok' | 'low' | 'unknown' | 'terminated';
    search?: string;
    limit?: number;
    /** Master god view only. */
    tenantId?: number;
    status?: SimLine['status'];
    withoutDevice?: boolean;
    onBackup4g?: boolean;
    /** The lines linked to this router. */
    deviceId?: number;
    /** The lines of this site (attributed to it, or on a router of it). */
    siteId?: number;
  } = {}): Promise<SimLineListItem[]> {
    const res = await apiClient.get<ApiResponse<unknown>>('/sim/lines', { params });
    return rows(res.data.data).map(normalizeLine);
  },

  /** A router's SIM block: the card the bench read in its modem, and its lines. */
  async deviceSim(deviceId: number): Promise<DeviceSimView> {
    const res = await apiClient.get<ApiResponse<unknown>>(`/sim/devices/${deviceId}`);
    const raw = (res.data.data ?? {}) as Raw;
    const reading = raw.reading && typeof raw.reading === 'object' ? (raw.reading as Raw) : null;
    const elsewhere = raw.cardLineElsewhere && typeof raw.cardLineElsewhere === 'object' ? (raw.cardLineElsewhere as Raw) : null;
    return {
      reading: reading
        ? { iccid: str(reading.iccid), imsi: str(reading.imsi), readAt: String(reading.readAt ?? '') }
        : null,
      lines: rows(raw.lines).map(normalizeLine),
      cardLineElsewhere: elsewhere
        ? { lineId: Number(elsewhere.lineId), msisdn: String(elsewhere.msisdn ?? ''), deviceId: Number(elsewhere.deviceId), deviceName: str(elsewhere.deviceName) }
        : null,
      modems: rows(raw.modems).map((m) => ({
        interface: String(m.interface ?? ''),
        iccid: str(m.iccid),
        imsi: str(m.imsi),
        imei: str(m.imei),
        observedAt: String(m.observedAt ?? ''),
      })),
      conflicts: rows(raw.conflicts).map((c) => ({
        kind: (c.kind === 'other_tenant' || c.kind === 'linked_elsewhere' ? c.kind : 'ambiguous') as DeviceSimConflict['kind'],
        iccid: String(c.iccid ?? ''),
        prefixMatch: c.prefixMatch === true,
        lineId: num(c.lineId),
        msisdn: str(c.msisdn),
        detectedAt: String(c.detectedAt ?? ''),
      })),
    };
  },

  async line(id: number): Promise<SimLineListItem> {
    const res = await apiClient.get<ApiResponse<unknown>>(`/sim/lines/${id}`);
    return normalizeLine((res.data.data ?? {}) as Raw);
  },

  async lineHistory(
    id: number,
    days = 90,
  ): Promise<Array<{ zone: string; restMb: number | null; usedMb: number | null; observedAt: string }>> {
    const res = await apiClient.get<ApiResponse<unknown>>(`/sim/lines/${id}/history`, {
      params: { days },
    });
    return rows(res.data.data).map((r) => ({
      zone: String(r.zone ?? ''),
      restMb: num(r.restMb),
      usedMb: num(r.usedMb),
      observedAt: String(r.observedAt ?? ''),
    }));
  },

  /** The partner's own purchase history for a line, as stored by the sweep. */
  async partnerRecharges(id: number): Promise<SimPartnerRecharge[]> {
    const res = await apiClient.get<ApiResponse<unknown>>(`/sim/lines/${id}/partner-recharges`);
    return rows(res.data.data).map((r) => {
      const outcome = str(r.outcome);
      return {
        id: num(r.id) ?? 0,
        simId: num(r.simId),
        msisdn: String(r.msisdn ?? ''),
        requestedAt: str(r.requestedAt),
        period: str(r.period),
        zoneCode: str(r.zoneCode),
        volumeMb: num(r.volumeMb),
        productCode: str(r.productCode),
        partnerState: str(r.partnerState),
        partnerStatus: str(r.partnerStatus),
        // An outcome the client does not know is `unknown`, never `ok`.
        outcome: (SIM_PARTNER_RECHARGE_OUTCOMES as readonly string[]).includes(outcome ?? '')
          ? (outcome as SimPartnerRecharge['outcome'])
          : 'unknown',
        rechargeId: num(r.rechargeId),
        firstSeenAt: String(r.firstSeenAt ?? ''),
      };
    });
  },

  /** The partner's volume catalogue for a line — a LIVE partner read. Buys nothing. */
  async rechargeOffers(id: number): Promise<SimRechargeOffers> {
    const res = await apiClient.get<ApiResponse<unknown>>(`/sim/lines/${id}/recharge-offers`);
    const d = (res.data.data ?? {}) as Raw;
    return {
      simId: num(d.simId) ?? id,
      fetchedAt: String(d.fetchedAt ?? ''),
      zones: rows(d.zones).map((z) => ({
        zone: String(z.zone ?? ''),
        zoneCode: str(z.zoneCode),
        error: str(z.error),
        offers: rows(z.offers).map((o) => ({
          code: String(o.code ?? ''),
          label: str(o.label),
          volumeMb: num(o.volumeMb),
        })),
      })),
    };
  },

  async updateLine(id: number, patch: SimLineUpdate): Promise<SimLineListItem> {
    const res = await apiClient.patch<ApiResponse<unknown>>(`/sim/lines/${id}`, patch);
    return normalizeLine((res.data.data ?? {}) as Raw);
  },

  // ── Top-ups ───────────────────────────────────────────────────────────────
  async recharges(params: { status?: string; simId?: number; limit?: number } = {}): Promise<SimRecharge[]> {
    const res = await apiClient.get<ApiResponse<unknown>>('/sim/recharges', { params });
    return rows(res.data.data).map(normalizeRecharge);
  },

  async propose(input: {
    simId: number;
    zone: string;
    planMb?: number | null;
    note?: string | null;
  }): Promise<SimRecharge> {
    const res = await apiClient.post<ApiResponse<unknown>>('/sim/recharges', input);
    return normalizeRecharge((res.data.data ?? {}) as Raw);
  },

  async approve(id: number, note?: string | null): Promise<SimRecharge> {
    const res = await apiClient.post<ApiResponse<unknown>>(`/sim/recharges/${id}/approve`, { note });
    return normalizeRecharge((res.data.data ?? {}) as Raw);
  },

  async reject(id: number, note?: string | null): Promise<SimRecharge> {
    const res = await apiClient.post<ApiResponse<unknown>>(`/sim/recharges/${id}/reject`, { note });
    return normalizeRecharge((res.data.data ?? {}) as Raw);
  },

  async record(id: number, input: SimRechargeCompletionInput): Promise<SimRecharge> {
    const res = await apiClient.post<ApiResponse<unknown>>(`/sim/recharges/${id}/record`, input);
    return normalizeRecharge((res.data.data ?? {}) as Raw);
  },

  /** Fills in the invoice after the fact. Moves no state; changes what is billed. */
  async price(id: number, input: SimRechargeCompletionInput): Promise<SimRecharge> {
    const res = await apiClient.post<ApiResponse<unknown>>(`/sim/recharges/${id}/price`, input);
    return normalizeRecharge((res.data.data ?? {}) as Raw);
  },

  // ── Re-invoicing report ───────────────────────────────────────────────────
  async report(from: string, to: string): Promise<SimRechargeReport> {
    const res = await apiClient.get<ApiResponse<SimRechargeReport>>('/sim/report', {
      params: { from, to },
    });
    return res.data.data as SimRechargeReport;
  },

  /** The CSV URL, opened by the browser so the download carries the session
   *  cookie. Built here so the screen and its export cannot drift apart. */
  reportCsvUrl(from: string, to: string): string {
    const qs = new URLSearchParams({ from, to });
    return `/api/sim/report.csv?${qs.toString()}`;
  },

  // ── Partner accounts — platform admin only ────────────────────────────────
  async accounts(): Promise<SimAccount[]> {
    const res = await apiClient.get<ApiResponse<unknown>>('/sim/accounts');
    return rows(res.data.data) as unknown as SimAccount[];
  },

  async createAccount(input: SimAccountInput): Promise<SimAccount> {
    const res = await apiClient.post<ApiResponse<SimAccount>>('/sim/accounts', input);
    return res.data.data as SimAccount;
  },

  async updateAccount(id: number, input: Partial<SimAccountInput>): Promise<SimAccount> {
    const res = await apiClient.patch<ApiResponse<SimAccount>>(`/sim/accounts/${id}`, input);
    return res.data.data as SimAccount;
  },

  async deleteAccount(id: number): Promise<void> {
    await apiClient.delete(`/sim/accounts/${id}`);
  },

  async setCredential(id: number, cred: SimCredentialInput): Promise<SimAccount> {
    const res = await apiClient.put<ApiResponse<SimAccount>>(`/sim/accounts/${id}/credential`, cred);
    return res.data.data as SimAccount;
  },

  /**
   * Step 1 — try the credentials. This is the call that makes the partner SEND
   * the one-time code, so it has to exist on its own: the code cannot be typed
   * before anything asked for it.
   */
  async tryAuth(
    id: number,
    input: { username: string; password: string },
  ): Promise<SimAuthAttempt> {
    const res = await apiClient.post<ApiResponse<SimAuthAttempt>>(
      `/sim/accounts/${id}/try-auth`,
      input,
    );
    return res.data.data as SimAuthAttempt;
  },

  /** Step 2 — clear the challenge with the code that has now arrived. */
  async authenticateWithCode(
    id: number,
    input: { username: string; password: string; code: string },
  ): Promise<SimAuthResolved> {
    const res = await apiClient.post<ApiResponse<SimAuthResolved>>(`/sim/accounts/${id}/otp`, input);
    return res.data.data as SimAuthResolved;
  },

  async testAccount(id: number): Promise<SimConnectionTest> {
    const res = await apiClient.post<ApiResponse<SimConnectionTest>>(`/sim/accounts/${id}/test`);
    return res.data.data as SimConnectionTest;
  },

  async syncAccount(id: number): Promise<Record<string, unknown>> {
    const res = await apiClient.post<ApiResponse<Record<string, unknown>>>(
      `/sim/accounts/${id}/sync`,
    );
    return (res.data.data ?? {}) as Record<string, unknown>;
  },

  async runs(id: number): Promise<SimSyncRun[]> {
    const res = await apiClient.get<ApiResponse<unknown>>(`/sim/accounts/${id}/runs`);
    return rows(res.data.data).map(normalizeRun);
  },

  async caps(id: number): Promise<SimCapUsage> {
    const res = await apiClient.get<ApiResponse<SimCapUsage>>(`/sim/accounts/${id}/caps`);
    return res.data.data as SimCapUsage;
  },
};
