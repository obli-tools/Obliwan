/**
 * ObliWAN — the GROUPED OPERATOR OUTAGE (migration 095).
 *
 * When fourteen stores of the same access provider fail over to 4G at the
 * same time, the supervision gets ONE alert — « Panne opérateur probable :
 * Orange — 14 magasins en 4G » — within minutes, instead of fourteen 4G backup
 * alerts two hours later (backup4g.service.ts). Nothing here writes to a
 * router; presence comes from the concentrator and the route from
 * the permanent check.
 *
 * ┌─ A STORE THAT LOST ITS FIXED LINE — `classifyStore`, pure ────────────────┐
 * │ 'out', kind 'cellular': its active default route, read during its current │
 * │   PPP session and fresh (< ROUTE_FRESH_MS), is on its cellular interface, │
 * │   and the site has a fixed line (declared 'fixed', or a fixed interface  │
 * │   found — backup4g's premise). Lost at `default_route_since`.             │
 * │ 'out', kind 'offline': behind a concentrator, no open PPP session for     │
 * │   OFFLINE_MIN_MS at least (a flap is not a loss), and the route read      │
 * │   shortly before the drop was a FIXED interface. Lost at the drop.        │
 * │ 'fixed': a fresh reading of this session names a non-cellular interface. │
 * │ 'unknown': anything else — never a loss, never a recovery (a store we     │
 * │   cannot read is not "back").                                             │
 * │ 'ignored': not a store to follow (declared 4G-only, no fixed line, not    │
 * │   active, a concentrator).                                                │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE GROUP — `planOutageSweep`, pure; the sweep every minute (leader) ────┐
 * │ · Provider of each store: fixedProvider.service (declared → PPPoE realm → │
 * │   ASN → /24, from the fixed line's MEMORY, never from the 4G address).    │
 * │ · OPEN: at least N stores (`operator_outage_min_stores`, default 3) of    │
 * │   the same provider lost their fixed line within W minutes                │
 * │   (`operator_outage_window`, default 10). Both platform-wide: the group   │
 * │   is FLEET-WIDE — an operator outage hits several customers.              │
 * │ · UNKNOWN PROVIDER: stores whose provider is not named (prefix or         │
 * │   nothing) and that formed no group of their own open « Bascule 4G        │
 * │   simultanée — N magasins (opérateur inconnu) » under the same rule.      │
 * │ · JOIN: a store of the same provider losing its line later joins the open │
 * │   group (no earlier than W before the group's start). Re-notified only   │
 * │   when the count DOUBLES since the last notification.                     │
 * │ · RECOVERY / RELAPSE: a member is back when a fresh reading of its        │
 * │   session names a fixed interface; out again later = back in the group.   │
 * │ · CLOSE 'recovered': every member is back — one notice with the count.    │
 * │   CLOSE 'receded': fewer than N still out, at most half the peak, and no │
 * │   movement for W minutes — the outage is over and the stragglers have a  │
 * │   problem of their own: they are RELEASED, followed individually, and a  │
 * │   folded 4G alert of theirs is sent then (backup4g `sendReleasedBackup4g`).│
 * │ · CONCENTRATOR LOSS is not an operator outage: when the offline stores of │
 * │   a concentrator number N or more (dropped within the 6 h horizon) and   │
 * │   at most 10 % of its stores still hold a session, its offline stores are │
 * │   'unknown' — never grouped, never labelled as a provider's, for as long │
 * │   as the loss lasts.                                                      │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHO IS TOLD WHAT ────────────────────────────────────────────────────────┐
 * │ · The GOD VIEW: one alert per group spanning every tenant (live alert     │
 * │   filed in the master tenant, `outage_role = 'global'`, shown only in the │
 * │   god view; message to the master workspace's channels).                 │
 * │ · Each CUSTOMER TENANT: its own slice — its stores and its count only,    │
 * │   never another customer's (`outage_role = 'tenant'`, its channels). A   │
 * │   channel shared with several workspaces gets each event once.            │
 * │ · The per-store 4G alerts of the members are FOLDED (operatorOutageFold): │
 * │   created as children of the group, never sent while grouped.             │
 * │ Server sentences are French here, as the operator worded them.            │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import {
  MASTER_TENANT_ID,
  SETTINGS_KEYS,
  UNKNOWN_PROVIDER_KEY,
  UNKNOWN_PROVIDER_LABEL,
  isSiteUplinkKind,
  type FixedProviderInference,
  type OperatorOutageDetailDto,
  type OperatorOutageMemberDto,
  type OperatorOutageMemberKind,
  type OperatorOutagePoint,
  type OperatorOutageSummaryDto,
  type ProviderEvidence,
  type SiteUplinkKind,
  type StoreProviderDto,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { tenantNames } from '../../utils/globalView';
import { leaderElection } from '../leaderElection';
import { liveAlertService } from '../liveAlert.service';
import { notificationService } from '../notification.service';
import { platformSettingNumber } from '../settingsRead';
import { ROUTE_FRESH_MS, fixedUplinksFor, isCellularIface, sendReleasedBackup4g } from './backup4g.service';
import { providersFor, refreshFixedLinkMemory } from './fixedProvider.service';
import { activeOutagesOf } from './operatorOutageFold';

/** How often the sweep runs (leader only). */
export const OUTAGE_SWEEP_INTERVAL_MS = 60_000;
/** A PPP session down for less than this is a flap, not a lost line. */
export const OFFLINE_MIN_MS = 2 * 60_000;
/** An episode older than this never OPENS a group (it may still join one). */
export const DETECTION_HORIZON_MS = 6 * 3600_000;
/** A concentrator holding at most this share of its stores' sessions while
 *  N or more dropped within W has lost them all: not an operator outage. */
export const CONCENTRATOR_LOSS_MAX_OPEN_SHARE = 0.1;

// ============================================================================
// Pure — a store's state
// ============================================================================

export interface StoreFacts {
  status: string;
  role: string;
  concentratorId: number | null;
  uplinkKind: SiteUplinkKind | null;
  iface: string | null;
  since: Date | null;
  observedAt: Date | null;
  /** The open PPP session's start, or null (none open). */
  sessionStartedAt: Date | null;
  /** The latest closed PPP session's end, or null. */
  lastEndedAt: Date | null;
  /** Fixed uplinks found (backup4g `fixedUplinksFor`); read for cellular only. */
  fixedUplinks: readonly string[];
}

export type StoreUnknown =
  | 'no_reading'
  | 'reading_old'
  | 'reading_before_session'
  | 'never_connected'
  | 'just_dropped'
  | 'dropped_on_cellular'
  | 'route_unknown_at_drop'
  | 'concentrator_loss';

export type StoreIgnored = 'not_active' | 'concentrator' | 'declared_cellular_only' | 'no_fixed_uplink' | 'gone';

export type StoreState =
  | { state: 'out'; kind: OperatorOutageMemberKind; lostAt: Date }
  | { state: 'fixed' }
  | { state: 'unknown'; why: StoreUnknown }
  | { state: 'ignored'; why: StoreIgnored };

export function classifyStore(f: StoreFacts, now: Date): StoreState {
  if (f.role === 'concentrator') return { state: 'ignored', why: 'concentrator' };
  if (f.status !== 'active') return { state: 'ignored', why: 'not_active' };
  if (f.uplinkKind === 'cellular_only') return { state: 'ignored', why: 'declared_cellular_only' };
  const behindChr = f.concentratorId !== null;
  const online = !behindChr || f.sessionStartedAt !== null;
  if (online) {
    if (!f.iface || !f.observedAt) return { state: 'unknown', why: 'no_reading' };
    if (now.getTime() - f.observedAt.getTime() > ROUTE_FRESH_MS) return { state: 'unknown', why: 'reading_old' };
    // A reading from before this session says nothing about the path it was
    // dialled over: a store that reconnected through its 4G is not "fixed".
    if (behindChr && f.sessionStartedAt && f.observedAt.getTime() < f.sessionStartedAt.getTime()) {
      return { state: 'unknown', why: 'reading_before_session' };
    }
    if (isCellularIface(f.iface)) {
      if (f.uplinkKind !== 'fixed' && f.fixedUplinks.length === 0) return { state: 'ignored', why: 'no_fixed_uplink' };
      return { state: 'out', kind: 'cellular', lostAt: f.since ?? f.observedAt };
    }
    return { state: 'fixed' };
  }
  if (!f.lastEndedAt) return { state: 'unknown', why: 'never_connected' };
  if (now.getTime() - f.lastEndedAt.getTime() < OFFLINE_MIN_MS) return { state: 'unknown', why: 'just_dropped' };
  if (!f.iface || !f.observedAt) return { state: 'unknown', why: 'no_reading' };
  // Dropped while on its 4G: the BACKUP failed, not the fixed line.
  if (isCellularIface(f.iface)) return { state: 'unknown', why: 'dropped_on_cellular' };
  if (f.observedAt.getTime() < f.lastEndedAt.getTime() - ROUTE_FRESH_MS) {
    return { state: 'unknown', why: 'route_unknown_at_drop' };
  }
  return { state: 'out', kind: 'offline', lostAt: f.lastEndedAt };
}

/**
 * The concentrators that lost (nearly) every session: N or more of their
 * stores dropped within the detection horizon and are still down, and at
 * most 10 % still hold one. Their offline stores say nothing about any
 * provider — for as long as the loss lasts, not only during its first W
 * minutes: a guard that lifted after W would label a ten-minute-old
 * concentrator loss an operator outage on the next sweep.
 */
export function lostConcentrators(
  stores: ReadonlyArray<{ concentratorId: number | null; sessionStartedAt: Date | null; lastEndedAt: Date | null }>,
  now: Date,
  threshold: number,
  horizonMs: number = DETECTION_HORIZON_MS,
): Set<number> {
  const by = new Map<number, { open: number; dropped: number }>();
  for (const s of stores) {
    if (s.concentratorId === null) continue;
    const c = by.get(s.concentratorId) ?? { open: 0, dropped: 0 };
    if (s.sessionStartedAt !== null) c.open += 1;
    else if (s.lastEndedAt && now.getTime() - s.lastEndedAt.getTime() <= horizonMs) c.dropped += 1;
    by.set(s.concentratorId, c);
  }
  const out = new Set<number>();
  for (const [id, c] of by) {
    if (c.dropped >= threshold && c.open <= CONCENTRATOR_LOSS_MAX_OPEN_SHARE * (c.open + c.dropped)) out.add(id);
  }
  return out;
}

// ============================================================================
// Pure — the plan of one sweep
// ============================================================================

export interface PlannerStore {
  deviceId: number;
  tenantId: number;
  concentratorId: number | null;
  state: StoreState;
  provider: FixedProviderInference;
}

export interface PlannerMember {
  deviceId: number;
  tenantId: number;
  kind: OperatorOutageMemberKind;
  lostAt: Date;
  recoveredAt: Date | null;
}

export interface PlannerOutage {
  id: number;
  key: string;
  unknownProvider: boolean;
  startedAt: Date;
  peak: number;
  lastChangeAt: Date;
  threshold: number;
  windowMs: number;
  /** Members not released. */
  members: PlannerMember[];
}

export interface PlannerInput {
  now: Date;
  threshold: number;
  windowMs: number;
  stores: PlannerStore[];
  outages: PlannerOutage[];
  lostConcentrators: ReadonlySet<number>;
}

export interface PlannedOpen {
  key: string;
  label: string;
  unknownProvider: boolean;
  startedAt: Date;
  stores: PlannerStore[];
}

export interface OutagePlan {
  recoveries: Array<{ outageId: number; deviceId: number }>;
  relapses: Array<{ outageId: number; deviceId: number; kind: OperatorOutageMemberKind; lostAt: Date }>;
  kindChanges: Array<{ outageId: number; deviceId: number; kind: OperatorOutageMemberKind }>;
  joins: Array<{ outageId: number; store: PlannerStore }>;
  opens: PlannedOpen[];
  closes: Array<{ outageId: number; reason: 'recovered' | 'receded'; released: number[] }>;
  /** Per open outage after the plan: its active members and whether anything moved. */
  after: Map<number, { active: number; changed: boolean }>;
}

/** The first start t_i such that at least `n` of the sorted times fall in
 *  [t_i, t_i + windowMs], or null. */
export function clusterStart(sorted: readonly Date[], n: number, windowMs: number): Date | null {
  for (let i = 0; i + n - 1 < sorted.length; i++) {
    if (sorted[i + n - 1].getTime() - sorted[i].getTime() <= windowMs) return sorted[i];
  }
  return null;
}

function effectiveState(s: PlannerStore, lost: ReadonlySet<number>): StoreState {
  if (s.state.state === 'out' && s.state.kind === 'offline' && s.concentratorId !== null && lost.has(s.concentratorId)) {
    return { state: 'unknown', why: 'concentrator_loss' };
  }
  return s.state;
}

export function planOutageSweep(input: PlannerInput): OutagePlan {
  const { now } = input;
  const plan: OutagePlan = { recoveries: [], relapses: [], kindChanges: [], joins: [], opens: [], closes: [], after: new Map() };
  const storeOf = new Map(input.stores.map((s) => [s.deviceId, s]));
  const stateOf = (deviceId: number): StoreState => {
    const s = storeOf.get(deviceId);
    return s ? effectiveState(s, input.lostConcentrators) : { state: 'ignored', why: 'gone' };
  };
  const active = new Map<number, Set<number>>(); // outageId -> active device ids
  const changed = new Set<number>();
  const memberOf = new Map<number, Set<number>>(); // deviceId -> outage ids (any member row)
  const activeMember = new Set<number>();

  for (const o of input.outages) {
    const set = new Set<number>();
    active.set(o.id, set);
    for (const m of o.members) {
      const mo = memberOf.get(m.deviceId) ?? new Set<number>();
      mo.add(o.id);
      memberOf.set(m.deviceId, mo);
      const st = stateOf(m.deviceId);
      if (m.recoveredAt === null) {
        if (st.state === 'fixed' || st.state === 'ignored') {
          plan.recoveries.push({ outageId: o.id, deviceId: m.deviceId });
          changed.add(o.id);
          continue;
        }
        if (st.state === 'out' && st.kind !== m.kind) plan.kindChanges.push({ outageId: o.id, deviceId: m.deviceId, kind: st.kind });
        set.add(m.deviceId);
        activeMember.add(m.deviceId);
      } else if (st.state === 'out' && st.lostAt.getTime() > m.recoveredAt.getTime() && !activeMember.has(m.deviceId)) {
        plan.relapses.push({ outageId: o.id, deviceId: m.deviceId, kind: st.kind, lostAt: st.lostAt });
        changed.add(o.id);
        set.add(m.deviceId);
        activeMember.add(m.deviceId);
      }
    }
  }

  const candidates = input.stores
    .filter((s) => !activeMember.has(s.deviceId) && effectiveState(s, input.lostConcentrators).state === 'out')
    .map((s) => ({ store: s, lostAt: (effectiveState(s, input.lostConcentrators) as { lostAt: Date }).lostAt }))
    .sort((a, b) => a.lostAt.getTime() - b.lostAt.getTime());

  // ── Joins: a store of an open group's provider, lost no earlier than W
  //    before the group's start. A store already a member of a group (it
  //    recovered and its new loss is not newer) never re-joins it.
  const left: typeof candidates = [];
  for (const c of candidates) {
    const eligible = (o: PlannerOutage) =>
      c.lostAt.getTime() >= o.startedAt.getTime() - o.windowMs && !(memberOf.get(c.store.deviceId)?.has(o.id) ?? false);
    let target = input.outages.find((o) => !o.unknownProvider && o.key === c.store.provider.key && eligible(o));
    if (!target && !c.store.provider.known) target = input.outages.find((o) => o.unknownProvider && eligible(o));
    if (target) {
      plan.joins.push({ outageId: target.id, store: c.store });
      active.get(target.id)!.add(c.store.deviceId);
      changed.add(target.id);
      activeMember.add(c.store.deviceId);
    } else {
      left.push(c);
    }
  }

  // ── Opens: N of one provider within W (episodes within the horizon).
  const fresh = left.filter((c) => now.getTime() - c.lostAt.getTime() <= DETECTION_HORIZON_MS);
  const byKey = new Map<string, typeof fresh>();
  for (const c of fresh) {
    if (c.store.provider.key === UNKNOWN_PROVIDER_KEY) continue;
    const list = byKey.get(c.store.provider.key) ?? [];
    list.push(c);
    byKey.set(c.store.provider.key, list);
  }
  const consumed = new Set<number>();
  const openKeys = new Set(input.outages.map((o) => o.key));
  for (const [key, list] of byKey) {
    if (openKeys.has(key)) continue;
    const start = clusterStart(list.map((c) => c.lostAt), input.threshold, input.windowMs);
    if (!start) continue;
    const stores = list.filter((c) => c.lostAt.getTime() >= start.getTime()).map((c) => c.store);
    for (const s of stores) consumed.add(s.deviceId);
    plan.opens.push({ key, label: stores[0].provider.label, unknownProvider: false, startedAt: start, stores });
  }
  // ── The unknown-provider mass failover: the stores whose provider is not
  //    named and that formed no group of their own.
  if (!openKeys.has(UNKNOWN_PROVIDER_KEY)) {
    const weak = fresh.filter((c) => !consumed.has(c.store.deviceId) && !c.store.provider.known);
    const start = clusterStart(weak.map((c) => c.lostAt), input.threshold, input.windowMs);
    if (start) {
      const stores = weak.filter((c) => c.lostAt.getTime() >= start.getTime()).map((c) => c.store);
      plan.opens.push({ key: UNKNOWN_PROVIDER_KEY, label: UNKNOWN_PROVIDER_LABEL, unknownProvider: true, startedAt: start, stores });
    }
  }

  // ── Closes.
  for (const o of input.outages) {
    const set = active.get(o.id)!;
    const moved = changed.has(o.id);
    plan.after.set(o.id, { active: set.size, changed: moved });
    if (set.size === 0) {
      plan.closes.push({ outageId: o.id, reason: 'recovered', released: [] });
      continue;
    }
    const peak = Math.max(o.peak, set.size);
    const lastChange = moved ? now : o.lastChangeAt;
    if (set.size < o.threshold && set.size * 2 <= peak && now.getTime() - lastChange.getTime() >= o.windowMs) {
      plan.closes.push({ outageId: o.id, reason: 'receded', released: [...set].sort((a, b) => a - b) });
    }
  }
  return plan;
}

// ============================================================================
// Pure — what the alerts say (French, as the operator worded them)
// ============================================================================

export interface OutageCounts {
  active: number;
  cellular: number;
  offline: number;
}

function plural(n: number, one: string, many: string): string {
  return `${n} ${n > 1 ? many : one}`;
}

/** "14 magasins en 4G", "2 magasins hors ligne", "5 magasins (3 en 4G, 2 hors ligne)". */
export function countPhrase(c: OutageCounts): string {
  if (c.offline === 0) return `${plural(c.active, 'magasin', 'magasins')} en 4G`;
  if (c.cellular === 0) return `${plural(c.active, 'magasin', 'magasins')} hors ligne`;
  return `${plural(c.active, 'magasin', 'magasins')} (${c.cellular} en 4G, ${c.offline} hors ligne)`;
}

export function outageTitle(
  o: { providerLabel: string; unknownProvider: boolean },
  c: OutageCounts,
  event: 'open' | 'grow',
): string {
  const now = event === 'grow' ? 'désormais ' : '';
  if (o.unknownProvider) {
    const detail = c.offline === 0 ? '' : c.cellular === 0 ? ', hors ligne' : ` ; ${c.cellular} en 4G, ${c.offline} hors ligne`;
    return `Bascule 4G simultanée — ${now}${plural(c.active, 'magasin', 'magasins')} (opérateur inconnu${detail})`;
  }
  return `Panne opérateur probable : ${o.providerLabel} — ${now}${countPhrase(c)}`;
}

export function outageCloseTitle(
  o: { providerLabel: string; unknownProvider: boolean },
  recovered: number,
  released: number,
): string {
  const back = `${plural(recovered, 'magasin revenu', 'magasins revenus')} sur le lien fixe`;
  const rest = released > 0 ? ` ; ${plural(released, 'encore coupé', 'encore coupés')}, suivis individuellement` : '';
  return o.unknownProvider
    ? `Fin de la bascule 4G simultanée — ${back}${rest}`
    : `Fin de panne opérateur : ${o.providerLabel} — ${back}${rest}`;
}

function parisTime(d: Date): string {
  return d.toLocaleString('fr-FR', {
    timeZone: 'Europe/Paris', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit',
  });
}

function durationText(ms: number): string {
  const min = Math.max(0, Math.round(ms / 60_000));
  if (min < 60) return `${min} min`;
  return `${Math.floor(min / 60)} h ${String(min % 60).padStart(2, '0')}`;
}

const EVIDENCE_FR: Record<ProviderEvidence, string> = {
  declared: 'déclaré sur le site',
  pppoe_realm: 'identifiant PPPoE',
  asn: 'ASN de l’adresse du lien fixe',
  prefix: 'préfixe de l’adresse du lien fixe',
  none: 'aucun indice',
};

export function evidenceSentence(counts: Partial<Record<ProviderEvidence, number>>): string {
  const parts = (Object.keys(EVIDENCE_FR) as ProviderEvidence[])
    .filter((e) => (counts[e] ?? 0) > 0)
    .map((e) => `${EVIDENCE_FR[e]} (${counts[e]})`);
  return parts.length > 0 ? parts.join(', ') : EVIDENCE_FR.none;
}

// ============================================================================
// Loading
// ============================================================================

interface StoreRow {
  id: number;
  tenant_id: number;
  site_id: number | null;
  name: string;
  status: string;
  role: string;
  concentrator_id: number | null;
  default_route_iface: string | null;
  default_route_since: Date | null;
  default_route_observed_at: Date | null;
  site_uplink_kind: string | null;
  site_fixed_provider: string | null;
  session_started_at: Date | null;
  last_ended_at: Date | null;
}

const d = (v: Date | string | null | undefined): Date | null => (v === null || v === undefined ? null : new Date(v));

async function loadStoreRows(): Promise<StoreRow[]> {
  const { rows } = (await db.raw(
    `SELECT dv.id, dv.tenant_id, dv.site_id, dv.name, dv.status, dv.role, dv.concentrator_id,
            dv.default_route_iface, dv.default_route_since, dv.default_route_observed_at,
            s.uplink_kind AS site_uplink_kind, s.fixed_provider AS site_fixed_provider,
            o.started_at AS session_started_at, l.ended_at AS last_ended_at
       FROM devices dv
       LEFT JOIN sites s ON s.id = dv.site_id AND s.tenant_id = dv.tenant_id
       LEFT JOIN LATERAL (
         SELECT p.started_at FROM ppp_sessions p
          WHERE p.device_id = dv.id AND p.ended_at IS NULL
          ORDER BY p.started_at DESC LIMIT 1) o ON true
       LEFT JOIN LATERAL (
         SELECT p.ended_at FROM ppp_sessions p
          WHERE p.device_id = dv.id AND p.ended_at IS NOT NULL
          ORDER BY p.started_at DESC LIMIT 1) l ON true
      WHERE dv.status = 'active' AND dv.role <> 'concentrator'`,
  )) as { rows: StoreRow[] };
  return rows;
}

interface OutageRow {
  id: string | number;
  provider_key: string;
  provider_label: string;
  unknown_provider: boolean;
  status: 'open' | 'closed';
  started_at: Date;
  opened_at: Date;
  closed_at: Date | null;
  close_reason: 'recovered' | 'receded' | null;
  threshold: number;
  window_minutes: number;
  peak_count: number;
  notified_count: number;
  last_change_at: Date;
}

interface MemberRow {
  id: string | number;
  outage_id: string | number;
  tenant_id: number;
  device_id: number;
  site_id: number | null;
  evidence: ProviderEvidence;
  evidence_detail: string | null;
  kind: OperatorOutageMemberKind;
  lost_at: Date;
  joined_at: Date;
  recovered_at: Date | null;
  released_at: Date | null;
  folded_alert_at: Date | null;
}

export interface OutageSettings {
  threshold: number;
  windowMs: number;
}

export async function outageSettings(): Promise<OutageSettings> {
  const [n, w] = await Promise.all([
    platformSettingNumber(SETTINGS_KEYS.OPERATOR_OUTAGE_MIN_STORES),
    platformSettingNumber(SETTINGS_KEYS.OPERATOR_OUTAGE_WINDOW),
  ]);
  return { threshold: Math.max(2, Math.round(n.value)), windowMs: Math.max(1, Math.round(w.value)) * 60_000 };
}

// ============================================================================
// Delivery (detached, like the health check's)
// ============================================================================

const pending = new Set<Promise<void>>();

function deliverDetached(what: string, send: () => Promise<void>): void {
  const p: Promise<void> = send()
    .catch((err: unknown) => logger.warn({ err, what }, 'Operator outage notification failed (the live alert is raised)'))
    .finally(() => {
      pending.delete(p);
    });
  pending.add(p);
}

/** For shutdown and harnesses: wait for the channel messages already sent. */
export async function flushOperatorOutageNotifications(): Promise<void> {
  while (pending.size > 0) await Promise.allSettled(Array.from(pending));
}

// ============================================================================
// The sweep
// ============================================================================

export interface SweepOutcome {
  ran: boolean;
  stores: number;
  out: number;
  lostConcentrators: number[];
  opened: number[];
  joined: number;
  recovered: number;
  closed: Array<{ id: number; reason: 'recovered' | 'receded' }>;
  grew: number[];
  memory: { written: number; changed: number; asnResolved: number } | null;
}

let running = false;

/**
 * One sweep: refresh the fixed-line memory, classify every store, plan,
 * apply, tell. Idempotent: a second run with nothing new changes nothing
 * (membership is keyed (group, store), one open group per provider is a
 * partial unique index, notifications follow recorded counts).
 */
export async function runOperatorOutageSweep(opts: { now?: Date; skipMemory?: boolean } = {}): Promise<SweepOutcome> {
  const empty: SweepOutcome = {
    ran: false, stores: 0, out: 0, lostConcentrators: [], opened: [], joined: 0, recovered: 0, closed: [], grew: [], memory: null,
  };
  if (running) return empty;
  running = true;
  try {
    return await sweepOnce(opts.now ?? new Date(), opts.skipMemory === true);
  } finally {
    running = false;
  }
}

async function sweepOnce(now: Date, skipMemory: boolean): Promise<SweepOutcome> {
  const memory = skipMemory
    ? null
    : await refreshFixedLinkMemory(now).catch((err: unknown) => {
        logger.warn({ err }, 'Fixed-line memory refresh failed; the providers are inferred from what is stored');
        return null;
      });
  const settings = await outageSettings();
  const rows = await loadStoreRows();

  // The fixed-line premise is only needed for a store on its cellular link
  // whose site does not declare it.
  const cellularIds = rows
    .filter((r) => isCellularIface(r.default_route_iface) && r.site_uplink_kind === null)
    .map((r) => Number(r.id));
  const fixed = await fixedUplinksFor(cellularIds);

  const facts = rows.map((r) => ({
    row: r,
    facts: {
      status: r.status,
      role: r.role,
      concentratorId: r.concentrator_id === null ? null : Number(r.concentrator_id),
      uplinkKind: isSiteUplinkKind(r.site_uplink_kind) ? r.site_uplink_kind : null,
      iface: r.default_route_iface,
      since: d(r.default_route_since),
      observedAt: d(r.default_route_observed_at),
      sessionStartedAt: d(r.session_started_at),
      lastEndedAt: d(r.last_ended_at),
      fixedUplinks: fixed.get(Number(r.id)) ?? [],
    } satisfies StoreFacts,
  }));
  const lost = lostConcentrators(facts.map((f) => f.facts), now, settings.threshold);

  const outageRows = (await db('operator_outages').where({ status: 'open' }).select('*')) as OutageRow[];
  const outageIds = outageRows.map((o) => Number(o.id));
  const memberRows = outageIds.length === 0
    ? []
    : ((await db('operator_outage_members').whereIn('outage_id', outageIds).whereNull('released_at').select('*')) as MemberRow[]);

  // The provider is needed for the stores out and for the members.
  const states = new Map<number, StoreState>();
  for (const f of facts) states.set(Number(f.row.id), classifyStore(f.facts, now));
  const memberIds = new Set(memberRows.map((m) => Number(m.device_id)));
  const needProvider = facts.filter((f) => states.get(Number(f.row.id))?.state === 'out' || memberIds.has(Number(f.row.id)));
  const providers = await providersFor(
    needProvider.map((f) => ({
      deviceId: Number(f.row.id),
      tenantId: Number(f.row.tenant_id),
      siteId: f.row.site_id === null ? null : Number(f.row.site_id),
      declared: f.row.site_id === null ? null : f.row.site_fixed_provider,
    })),
  );
  const unknownProvider: FixedProviderInference = {
    key: UNKNOWN_PROVIDER_KEY, label: UNKNOWN_PROVIDER_LABEL, evidence: 'none', detail: null, known: false,
  };
  const stores: PlannerStore[] = facts.map((f) => ({
    deviceId: Number(f.row.id),
    tenantId: Number(f.row.tenant_id),
    concentratorId: f.facts.concentratorId,
    state: states.get(Number(f.row.id))!,
    provider: providers.get(Number(f.row.id)) ?? unknownProvider,
  }));

  const plan = planOutageSweep({
    now,
    threshold: settings.threshold,
    windowMs: settings.windowMs,
    stores,
    lostConcentrators: lost,
    outages: outageRows.map((o) => ({
      id: Number(o.id),
      key: o.provider_key,
      unknownProvider: o.unknown_provider,
      startedAt: new Date(o.started_at),
      peak: o.peak_count,
      lastChangeAt: new Date(o.last_change_at),
      threshold: o.threshold,
      windowMs: o.window_minutes * 60_000,
      members: memberRows
        .filter((m) => Number(m.outage_id) === Number(o.id))
        .map((m) => ({
          deviceId: Number(m.device_id),
          tenantId: Number(m.tenant_id),
          kind: m.kind,
          lostAt: new Date(m.lost_at),
          recoveredAt: d(m.recovered_at),
        })),
    })),
  });

  const siteOf = new Map(rows.map((r) => [Number(r.id), r.site_id === null ? null : Number(r.site_id)]));
  const outcome: SweepOutcome = {
    ran: true,
    stores: stores.length,
    out: stores.filter((s) => s.state.state === 'out').length,
    lostConcentrators: [...lost].sort((a, b) => a - b),
    opened: [],
    joined: plan.joins.length,
    recovered: plan.recoveries.length,
    closed: [],
    grew: [],
    memory,
  };
  if (lost.size > 0) {
    logger.warn(
      { concentrators: [...lost] },
      'Operator outage sweep: a concentrator lost (nearly) every session — its offline stores are not an operator outage',
    );
  }

  // ── Apply: members first, then the new groups, then the closes.
  for (const r of plan.recoveries) {
    await db('operator_outage_members')
      .where({ outage_id: r.outageId, device_id: r.deviceId })
      .whereNull('recovered_at')
      .update({ recovered_at: now });
  }
  for (const r of plan.relapses) {
    await db('operator_outage_members')
      .where({ outage_id: r.outageId, device_id: r.deviceId })
      .update({ recovered_at: null, lost_at: r.lostAt, kind: r.kind });
  }
  for (const k of plan.kindChanges) {
    await db('operator_outage_members').where({ outage_id: k.outageId, device_id: k.deviceId }).update({ kind: k.kind });
  }
  const touched = new Set<number>();
  const joinedByOutage = new Map<number, number[]>();
  for (const j of plan.joins) {
    await insertMember(j.outageId, j.store, siteOf.get(j.store.deviceId) ?? null, now);
    touched.add(j.outageId);
    joinedByOutage.set(j.outageId, [...(joinedByOutage.get(j.outageId) ?? []), j.store.deviceId]);
  }
  for (const r of [...plan.recoveries, ...plan.relapses]) touched.add(r.outageId);

  const opened: number[] = [];
  for (const o of plan.opens) {
    const inserted = (await db.raw(
      `INSERT INTO operator_outages
         (provider_key, provider_label, unknown_provider, status, started_at, opened_at, threshold,
          window_minutes, peak_count, notified_count, last_change_at)
       VALUES (?, ?, ?, 'open', ?, ?, ?, ?, 0, 0, ?)
       ON CONFLICT (provider_key) WHERE status = 'open' DO NOTHING
       RETURNING id`,
      [
        o.key.slice(0, 200), o.label.slice(0, 200), o.unknownProvider, o.startedAt, now,
        settings.threshold, Math.round(settings.windowMs / 60_000), now,
      ],
    )) as { rows: Array<{ id: string }> };
    let id: number;
    if (inserted.rows[0]) {
      id = Number(inserted.rows[0].id);
      opened.push(id);
    } else {
      // Lost a race on the partial unique index: join the winner.
      const existing = (await db('operator_outages').where({ provider_key: o.key, status: 'open' }).first('id')) as
        | { id: string }
        | undefined;
      if (!existing) continue;
      id = Number(existing.id);
      touched.add(id);
    }
    for (const s of o.stores) await insertMember(id, s, siteOf.get(s.deviceId) ?? null, now);
    await db('operator_outages')
      .where({ id })
      .update({ peak_count: db.raw('GREATEST(peak_count, ?)', [o.stores.length]), last_change_at: now });
    joinedByOutage.set(id, [...(joinedByOutage.get(id) ?? []), ...o.stores.map((s) => s.deviceId)]);
  }
  outcome.opened = opened;

  // Per-store 4G alerts already raised (and sent) before their store joined:
  // shown under the group from now on — their recovery stays individual.
  for (const [outageId, deviceIds] of joinedByOutage) await adoptRaisedAlerts(outageId, deviceIds);

  for (const [id, a] of plan.after) {
    await db('operator_outages')
      .where({ id })
      .update({
        peak_count: db.raw('GREATEST(peak_count, ?)', [a.active]),
        ...(a.changed ? { last_change_at: now } : {}),
        updated_at: now,
      });
  }
  const closedIds = new Map<number, { reason: 'recovered' | 'receded'; released: number[] }>();
  for (const c of plan.closes) {
    const n = await db('operator_outages')
      .where({ id: c.outageId, status: 'open' })
      .update({ status: 'closed', closed_at: now, close_reason: c.reason, updated_at: now });
    if (n === 0) continue;
    if (c.released.length > 0) {
      await db('operator_outage_members')
        .where({ outage_id: c.outageId })
        .whereIn('device_id', c.released)
        .whereNull('recovered_at')
        .update({ released_at: now });
    }
    closedIds.set(c.outageId, c);
    outcome.closed.push({ id: c.outageId, reason: c.reason });
  }

  // ── Tell: the god view, then each customer's slice.
  for (const id of new Set([...opened, ...touched, ...closedIds.keys()])) {
    try {
      const grew = await announce(id, now, opened.includes(id), closedIds.get(id) ?? null);
      if (grew) outcome.grew.push(id);
    } catch (err) {
      logger.error({ err, outageId: id }, 'Operator outage: announcing failed (the group is recorded)');
    }
  }
  if (opened.length > 0 || closedIds.size > 0) {
    logger.info(
      { opened, closed: outcome.closed, joined: outcome.joined, recovered: outcome.recovered },
      'Operator outage sweep changed the groups',
    );
  }
  return outcome;
}

async function insertMember(outageId: number, s: PlannerStore, siteId: number | null, now: Date): Promise<void> {
  const st = s.state as { kind: OperatorOutageMemberKind; lostAt: Date };
  await db('operator_outage_members')
    .insert({
      outage_id: outageId,
      tenant_id: s.tenantId,
      device_id: s.deviceId,
      site_id: siteId,
      evidence: s.provider.evidence,
      evidence_detail: s.provider.detail ? s.provider.detail.slice(0, 200) : null,
      kind: st.kind,
      lost_at: st.lostAt,
      joined_at: now,
    })
    .onConflict(['outage_id', 'device_id'])
    .ignore();
}

async function adoptRaisedAlerts(outageId: number, deviceIds: readonly number[]): Promise<void> {
  if (deviceIds.length === 0) return;
  const devices = (await db('devices')
    .whereIn('id', deviceIds as number[])
    .whereNotNull('backup4g_alerted_at')
    .select('id', 'tenant_id', 'backup4g_alerted_at')) as Array<{ id: number; tenant_id: number; backup4g_alerted_at: Date }>;
  for (const dv of devices) {
    await db('live_alerts')
      .where({ tenant_id: dv.tenant_id, device_id: dv.id })
      .whereNull('outage_id')
      .where('stable_key', 'like', `backup4g:${Number(dv.id)}:%`)
      .where('created_at', '>=', new Date(new Date(dv.backup4g_alerted_at).getTime() - 5 * 60_000))
      .update({ outage_id: outageId, outage_role: 'member' });
  }
}

// ============================================================================
// Announcing
// ============================================================================

interface CountedMember {
  tenantId: number;
  deviceId: number;
  kind: OperatorOutageMemberKind;
  recovered: boolean;
  released: boolean;
  foldedAlertAt: Date | null;
  evidence: ProviderEvidence;
}

function countsOf(ms: readonly CountedMember[]): OutageCounts {
  const out = ms.filter((m) => !m.recovered && !m.released);
  return {
    active: out.length,
    cellular: out.filter((m) => m.kind === 'cellular').length,
    offline: out.filter((m) => m.kind === 'offline').length,
  };
}

function evidenceCounts(ms: readonly CountedMember[]): Partial<Record<ProviderEvidence, number>> {
  const out: Partial<Record<ProviderEvidence, number>> = {};
  for (const m of ms) out[m.evidence] = (out[m.evidence] ?? 0) + 1;
  return out;
}

async function recordPoint(outageId: number, tenantId: number | null, count: number, at: Date): Promise<void> {
  const q = db('operator_outage_points').where({ outage_id: outageId }).orderBy('at', 'desc').orderBy('id', 'desc');
  if (tenantId === null) q.whereNull('tenant_id');
  else q.where({ tenant_id: tenantId });
  const last = (await q.first('active_count')) as { active_count: number } | undefined;
  if (last && last.active_count === count) return;
  await db('operator_outage_points').insert({ outage_id: outageId, tenant_id: tenantId, at, active_count: count });
}

/**
 * Says what changed about one group, once: the god view's alert and message,
 * then each customer tenant's slice. Returns whether the god view's count
 * grew enough to be re-notified.
 */
async function announce(
  outageId: number,
  now: Date,
  opened: boolean,
  closed: { reason: 'recovered' | 'receded'; released: number[] } | null,
): Promise<boolean> {
  const o = (await db('operator_outages').where({ id: outageId }).first('*')) as OutageRow | undefined;
  if (!o) return false;
  const rows = (await db('operator_outage_members').where({ outage_id: outageId }).select('*')) as MemberRow[];
  const members: CountedMember[] = rows.map((m) => ({
    tenantId: Number(m.tenant_id),
    deviceId: Number(m.device_id),
    kind: m.kind,
    recovered: m.recovered_at !== null,
    released: m.released_at !== null,
    foldedAlertAt: d(m.folded_alert_at),
    evidence: m.evidence,
  }));
  const label = { providerLabel: o.provider_label, unknownProvider: o.unknown_provider };
  const started = new Date(o.started_at);
  const sent = new Set<number>();
  // The messages of ONE event, sent IN ORDER (the god view first, then each
  // tenant): a channel shared with several workspaces gets the widest one.
  const sends: Array<() => Promise<void>> = [];
  const incident = `obliwan:operator-outage:${outageId}`;
  const evidence = evidenceSentence(evidenceCounts(members));
  const nav = `/alerts?outage=${outageId}`;

  // ── The god view.
  const all = countsOf(members);
  await recordPoint(outageId, null, all.active, now);
  let grew = false;
  const body = (c: OutageCounts, where: string, ev: string = evidence): string =>
    `Depuis le ${parisTime(started)}, ${plural(c.active, 'magasin', 'magasins')}${where} ` +
    `${c.active > 1 ? 'ont' : 'a'} perdu ${c.active > 1 ? 'leur' : 'son'} lien fixe ` +
    `(${c.cellular} en 4G, ${c.offline} hors ligne). Opérateur établi par : ${ev}. ` +
    'Les alertes de secours 4G de ces magasins sont regroupées sous celle-ci (elles ne sont pas envoyées séparément).';
  if (closed) {
    const recovered = members.filter((m) => m.recovered).length;
    const released = members.filter((m) => m.released).length;
    const title = outageCloseTitle(label, recovered, released);
    const message =
      `${title}. Durée : ${durationText(now.getTime() - started.getTime())} (depuis le ${parisTime(started)}). ` +
      (released > 0
        ? 'Les magasins encore coupés ont un problème qui leur est propre : leurs alertes de secours 4G sont désormais envoyées individuellement.'
        : '');
    await liveAlertService.add(MASTER_TENANT_ID, {
      severity: 'up', title, message, navigateTo: nav,
      stableKey: `opout:${outageId}:global:close`, outage: { id: outageId, role: 'global' },
    });
    sends.push(() =>
      notificationService.sendForTenant(MASTER_TENANT_ID, 'operator_outage_closed', {
        entityName: o.unknown_provider ? 'Bascule 4G simultanée' : `Panne opérateur — ${o.provider_label}`,
        entityUrl: nav, oldStatus: 'alert', newStatus: 'up', message, timestamp: now.toISOString(),
        stableKey: incident, severity: 'warning', isRecovery: true, occurredAt: started.toISOString(),
        recoveredAt: now.toISOString(), occurrenceCount: members.length, entityId: outageId, entityType: 'tenant',
      }, { sentChannelIds: sent }),
    );
  } else if (opened || (all.active > 0 && all.active >= 2 * Math.max(1, o.notified_count))) {
    const event = opened ? 'open' : 'grow';
    grew = !opened;
    const title = outageTitle(label, all, event);
    const message = `${title}. ${body(all, '')}`;
    await liveAlertService.add(MASTER_TENANT_ID, {
      severity: 'warning', title, message, navigateTo: nav,
      stableKey: `opout:${outageId}:global:${event}:${all.active}`, outage: { id: outageId, role: 'global' },
    });
    await db('operator_outages').where({ id: outageId }).update({ notified_count: all.active });
    sends.push(() =>
      notificationService.sendForTenant(MASTER_TENANT_ID, `operator_outage_${event}`, {
        entityName: o.unknown_provider ? 'Bascule 4G simultanée' : `Panne opérateur — ${o.provider_label}`,
        entityUrl: nav, oldStatus: 'up', newStatus: 'alert', message, timestamp: now.toISOString(),
        stableKey: incident, severity: 'warning', isRecovery: false, occurredAt: started.toISOString(),
        occurrenceCount: all.active, entityId: outageId, entityType: 'tenant',
      }, { sentChannelIds: sent }),
    );
  }

  // ── Each customer tenant: its own stores, its own count.
  const tenants = [...new Set(members.map((m) => m.tenantId))].sort((a, b) => a - b);
  const slices = (await db('operator_outage_slices').where({ outage_id: outageId }).select('*')) as Array<{
    tenant_id: number; status: 'open' | 'closed'; opened_at: Date; notified_count: number; peak_count: number;
  }>;
  for (const tenantId of tenants) {
    const own = members.filter((m) => m.tenantId === tenantId);
    const c = countsOf(own);
    await recordPoint(outageId, tenantId, c.active, now);
    const slice = slices.find((s) => Number(s.tenant_id) === tenantId);
    const tenantIncident = `${incident}:tenant:${tenantId}`;
    const ownEvidence = evidenceSentence(evidenceCounts(own));
    const tBody = (cc: OutageCounts): string => body(cc, ' de cet espace', ownEvidence);
    const sliceOpen = slice?.status === 'open';
    if (sliceOpen && (closed || c.active === 0)) {
      const recovered = own.filter((m) => m.recovered).length;
      const released = own.filter((m) => m.released).length;
      const title = outageCloseTitle(label, recovered, released);
      const message = `${title}. Durée : ${durationText(now.getTime() - started.getTime())}.`;
      await db('operator_outage_slices')
        .where({ outage_id: outageId, tenant_id: tenantId, status: 'open' })
        .update({ status: 'closed', closed_at: now });
      await liveAlertService.add(tenantId, {
        severity: 'up', title, message, navigateTo: nav,
        stableKey: `opout:${outageId}:t${tenantId}:close:${new Date(slice!.opened_at).getTime()}`,
        outage: { id: outageId, role: 'tenant' },
      });
      sends.push(() =>
        notificationService.sendForTenant(tenantId, 'operator_outage_closed', {
          entityName: o.unknown_provider ? 'Bascule 4G simultanée' : `Panne opérateur — ${o.provider_label}`,
          entityUrl: nav, oldStatus: 'alert', newStatus: 'up', message, timestamp: now.toISOString(),
          stableKey: tenantIncident, severity: 'warning', isRecovery: true, occurredAt: started.toISOString(),
          recoveredAt: now.toISOString(), entityId: tenantId, entityType: 'tenant',
        }, { sentChannelIds: sent }),
      );
      continue;
    }
    if (closed || c.active === 0) continue;
    let event: 'open' | 'grow' | null = null;
    if (!sliceOpen) event = 'open';
    else if (c.active >= 2 * Math.max(1, slice!.notified_count)) event = 'grow';
    if (sliceOpen) {
      await db('operator_outage_slices')
        .where({ outage_id: outageId, tenant_id: tenantId })
        .update({ peak_count: db.raw('GREATEST(peak_count, ?)', [c.active]) });
    }
    if (!event) continue;
    const title = outageTitle(label, c, event);
    const message = `${title}. ${tBody(c)}`;
    if (event === 'open') {
      await db('operator_outage_slices')
        .insert({ outage_id: outageId, tenant_id: tenantId, status: 'open', opened_at: now, closed_at: null, notified_count: c.active, peak_count: c.active })
        .onConflict(['outage_id', 'tenant_id'])
        .merge({ status: 'open', opened_at: now, closed_at: null, notified_count: c.active, peak_count: c.active });
    } else {
      await db('operator_outage_slices').where({ outage_id: outageId, tenant_id: tenantId }).update({ notified_count: c.active });
    }
    await liveAlertService.add(tenantId, {
      severity: 'warning', title, message, navigateTo: nav,
      stableKey: `opout:${outageId}:t${tenantId}:${event}:${c.active}:${now.getTime()}`,
      outage: { id: outageId, role: 'tenant' },
    });
    sends.push(() =>
      notificationService.sendForTenant(tenantId, `operator_outage_${event}`, {
        entityName: o.unknown_provider ? 'Bascule 4G simultanée' : `Panne opérateur — ${o.provider_label}`,
        entityUrl: nav, oldStatus: 'up', newStatus: 'alert', message, timestamp: now.toISOString(),
        stableKey: tenantIncident, severity: 'warning', isRecovery: false, occurredAt: started.toISOString(),
        occurrenceCount: c.active, entityId: tenantId, entityType: 'tenant',
      }, { sentChannelIds: sent }),
    );
  }

  deliverDetached(`outage-${outageId}`, async () => {
    for (const send of sends) {
      await send().catch((err: unknown) => logger.warn({ err, outageId }, 'Operator outage notification failed (the live alert is raised)'));
    }
  });

  // ── Released stores: their folded 4G alert is sent now.
  if (closed && closed.released.length > 0) {
    for (const m of members) {
      if (!m.released || !m.foldedAlertAt || !closed.released.includes(m.deviceId)) continue;
      await sendReleasedBackup4g(m.deviceId, m.foldedAlertAt, o.provider_label, now).catch((err: unknown) =>
        logger.warn({ err, deviceId: m.deviceId }, 'Operator outage: the released store\'s 4G alert was not sent'),
      );
    }
  }
  return grew;
}

// ============================================================================
// Runtime — leader only
// ============================================================================

let timer: NodeJS.Timeout | null = null;
let unsubscribe: (() => void) | null = null;

export function startOperatorOutageRuntime(): void {
  if (unsubscribe) return;
  unsubscribe = leaderElection.onChange((isLeader) => {
    if (isLeader) {
      if (timer) return;
      const tick = (): void => {
        void runOperatorOutageSweep().catch((err: unknown) => logger.error({ err }, 'Operator outage sweep failed'));
      };
      timer = setInterval(tick, OUTAGE_SWEEP_INTERVAL_MS);
      timer.unref?.();
      tick();
      logger.info({ intervalMs: OUTAGE_SWEEP_INTERVAL_MS }, 'Operator outage grouping started (leader)');
    } else if (timer) {
      clearInterval(timer);
      timer = null;
    }
  });
}

export async function stopOperatorOutageRuntime(): Promise<void> {
  if (timer) clearInterval(timer);
  timer = null;
  unsubscribe?.();
  unsubscribe = null;
  await flushOperatorOutageNotifications();
}

// ============================================================================
// Read models — GET /api/operator-outages[/:id]
// ============================================================================

export interface OutageScope {
  /** The god view: every tenant's stores, with tenant names. */
  godView: boolean;
  /** The tenant read for (ignored in the god view). */
  tenantId: number;
  /** Team scope: the devices the caller may see; null = the whole tenant. */
  deviceIdsIn: number[] | null;
}

function inScope(m: MemberRow, scope: OutageScope): boolean {
  if (scope.godView) return true;
  if (Number(m.tenant_id) !== scope.tenantId) return false;
  return scope.deviceIdsIn === null || scope.deviceIdsIn.includes(Number(m.device_id));
}

function summaryOf(o: OutageRow, members: readonly MemberRow[], scope: OutageScope): OperatorOutageSummaryDto {
  const counted: CountedMember[] = members.map((m) => ({
    tenantId: Number(m.tenant_id), deviceId: Number(m.device_id), kind: m.kind,
    recovered: m.recovered_at !== null, released: m.released_at !== null,
    foldedAlertAt: d(m.folded_alert_at), evidence: m.evidence,
  }));
  const c = countsOf(counted);
  return {
    id: Number(o.id),
    providerKey: o.provider_key,
    providerLabel: o.provider_label,
    unknownProvider: o.unknown_provider,
    status: o.status,
    scope: scope.godView ? 'global' : 'tenant',
    startedAt: new Date(o.started_at).toISOString(),
    openedAt: new Date(o.opened_at).toISOString(),
    closedAt: o.closed_at ? new Date(o.closed_at).toISOString() : null,
    closeReason: o.close_reason,
    activeCount: c.active,
    cellularCount: c.cellular,
    offlineCount: c.offline,
    totalCount: members.length,
    // The god view's peak is the group's; a tenant's is its slice's, which
    // the caller fills in (a tenant never reads another customer's peak).
    peakCount: scope.godView ? o.peak_count : Math.max(c.active, 0),
    evidence: evidenceCounts(counted),
    threshold: o.threshold,
    windowMinutes: o.window_minutes,
  };
}

export async function listOperatorOutages(
  scope: OutageScope,
  opts: { status?: 'open' | 'closed'; limit?: number } = {},
): Promise<OperatorOutageSummaryDto[]> {
  const q = db('operator_outages as o').orderBy('o.opened_at', 'desc').limit(Math.min(Math.max(opts.limit ?? 50, 1), 200));
  if (opts.status) void q.where('o.status', opts.status);
  if (!scope.godView) {
    const sub = db('operator_outage_members as m')
      .select(db.raw('1'))
      .whereRaw('m.outage_id = o.id')
      .where('m.tenant_id', scope.tenantId);
    if (scope.deviceIdsIn !== null) void sub.whereIn('m.device_id', scope.deviceIdsIn);
    void q.whereExists(sub);
  }
  const outages = (await q.select('o.*')) as OutageRow[];
  if (outages.length === 0) return [];
  const members = (await db('operator_outage_members').whereIn('outage_id', outages.map((o) => Number(o.id))).select('*')) as MemberRow[];
  const slices = scope.godView
    ? []
    : ((await db('operator_outage_slices').whereIn('outage_id', outages.map((o) => Number(o.id))).where({ tenant_id: scope.tenantId }).select('outage_id', 'peak_count')) as Array<{ outage_id: string; peak_count: number }>);
  return outages.map((o) => {
    const own = members.filter((m) => Number(m.outage_id) === Number(o.id) && inScope(m, scope));
    const s = summaryOf(o, own, scope);
    const slice = slices.find((x) => Number(x.outage_id) === Number(o.id));
    // The slice's peak counts the whole tenant: a team-scoped caller gets its own count only.
    if (slice && scope.deviceIdsIn === null) s.peakCount = Math.max(s.peakCount, slice.peak_count);
    return s;
  });
}

export async function getOperatorOutage(scope: OutageScope, id: number): Promise<OperatorOutageDetailDto | null> {
  const o = (await db('operator_outages').where({ id }).first('*')) as OutageRow | undefined;
  if (!o) return null;
  const all = (await db('operator_outage_members as m')
    .join('devices as dv', 'dv.id', 'm.device_id')
    .leftJoin('sites as s', 's.id', 'm.site_id')
    .where('m.outage_id', id)
    .orderBy('m.lost_at')
    .select('m.*', 'dv.name as device_name', 's.name as site_name')) as Array<MemberRow & { device_name: string; site_name: string | null }>;
  const own = all.filter((m) => inScope(m, scope));
  // A group none of whose stores the caller may see does not exist for it.
  if (own.length === 0 && !scope.godView) return null;
  const summary = summaryOf(o, own, scope);
  const pq = db('operator_outage_points').where({ outage_id: id }).orderBy('at').orderBy('id');
  if (scope.godView) void pq.whereNull('tenant_id');
  else void pq.where({ tenant_id: scope.tenantId });
  const points = ((await pq.select('at', 'active_count')) as Array<{ at: Date; active_count: number }>).map(
    (p): OperatorOutagePoint => ({ at: new Date(p.at).toISOString(), count: p.active_count }),
  );
  if (!scope.godView) {
    const slice = (await db('operator_outage_slices').where({ outage_id: id, tenant_id: scope.tenantId }).first('peak_count')) as
      | { peak_count: number }
      | undefined;
    if (slice && scope.deviceIdsIn === null) summary.peakCount = Math.max(summary.peakCount, slice.peak_count);
    // Team-scoped callers: the points are the tenant's, which may count
    // stores outside their teams — they get their own members' count only.
    if (scope.deviceIdsIn !== null) points.splice(0, points.length);
  }
  const names = scope.godView ? await tenantNames(own.map((m) => Number(m.tenant_id))) : null;
  const members: OperatorOutageMemberDto[] = own.map((m) => ({
    deviceId: Number(m.device_id),
    deviceName: m.device_name,
    siteId: m.site_id === null ? null : Number(m.site_id),
    siteName: m.site_name,
    ...(names ? { tenantId: Number(m.tenant_id), tenantName: names.get(Number(m.tenant_id)) ?? null } : {}),
    kind: m.kind,
    lostAt: new Date(m.lost_at).toISOString(),
    joinedAt: new Date(m.joined_at).toISOString(),
    recoveredAt: m.recovered_at ? new Date(m.recovered_at).toISOString() : null,
    releasedAt: m.released_at ? new Date(m.released_at).toISOString() : null,
    evidence: m.evidence,
    evidenceDetail: m.evidence_detail,
    alertFolded: m.folded_alert_at !== null,
  }));
  return { ...summary, members, points };
}

// ============================================================================
// The 4G backup fleet list: provider column
// ============================================================================

/**
 * Adds the fixed line's provider (with its evidence) and the open group a
 * store belongs to, to each item of the "sites on 4G backup" list.
 */
export async function withStoreProviders<T extends { deviceId: number; siteId: number | null; tenantId?: number }>(
  items: T[],
  defaultTenantId: number,
): Promise<Array<T & { provider: StoreProviderDto | null; outageId: number | null }>> {
  if (items.length === 0) return [];
  const providers = await providersFor(
    items.map((i) => ({ deviceId: i.deviceId, tenantId: i.tenantId ?? defaultTenantId, siteId: i.siteId })),
  );
  const outages = await activeOutagesOf(items.map((i) => i.deviceId));
  return items.map((i) => {
    const p = providers.get(i.deviceId);
    return {
      ...i,
      provider: p ? { key: p.key, label: p.label, evidence: p.evidence, detail: p.detail, known: p.known } : null,
      outageId: outages.get(i.deviceId) ?? null,
    };
  });
}
