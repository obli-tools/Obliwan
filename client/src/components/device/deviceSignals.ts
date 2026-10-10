import type { TFunction } from 'i18next';
import {
  deadmanReadiness,
  type DeviceHealthCheckView,
  type ReachabilityVerdict,
  type SimLineVerdict,
} from '@obliwan/shared';
import type { DeviceModeInfo } from '@/types/fleet';
import type { DriftRunSummary } from '@/types/config';
import type { DeviceSimView, SimLineListItem } from '@/api/sim.api';
import type { DeviceTemplateResolution } from '@/api/templates.api';
import type { ManagementAccessView } from '@/components/fleet/managementAccess.api';
import {
  LEGACY_FIX_BAD,
  LEGACY_FIX_GOOD,
  type LegacyComplianceView,
} from '@/components/fleet/legacyCompliance.api';
import { isCellularOnly, type UplinkVerdict } from '@/components/telemetry/DeviceUplinkCard';
import type { WanLinkView } from '@/components/fleet/wanLink.api';
import { verdictLabelKey } from '@/utils/verdict';

/**
 * The device page's answer to « is it OK? », one short value per topic.
 *
 * ┌─ ONE READING PER FACT ────────────────────────────────────────────────────┐
 * │ Every value here is DERIVED from the view the card below already loaded  │
 * │ (the cards report it through `onView`), never from a second fetch: a     │
 * │ chip reading "API-SSL ouvert" above a card reading "échec" would be one   │
 * │ page telling an operator two things, and the stale half is the one that  │
 * │ looks official.                                                          │
 * │                                                                          │
 * │ `undefined` is "not loaded yet" and draws as `loading`; `null` is "could  │
 * │ not be read" and draws as `unknown`. Neither is ever folded into `ok`: a │
 * │ calm chip over an unread fact is how a dead feed looks healthy.           │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * A function returning `null` means the topic does not apply to this device
 * (no chip, no section) — not that it is fine.
 */

export type SignalTone = 'ok' | 'warn' | 'bad' | 'info' | 'unknown' | 'loading';

export interface Signal {
  tone: SignalTone;
  /** Chip-sized: « ouvert », « 2 correctifs à appliquer ». */
  value: string;
}

/** Not loaded yet / could not be read / the view. */
export type Loaded<T> = T | null | undefined;

const LOADING: Signal = { tone: 'loading', value: '…' };

const TONE_RANK: Record<SignalTone, number> = { bad: 5, warn: 4, unknown: 3, loading: 2, info: 1, ok: 0 };

/** The worst of several tones — a section is as healthy as its worst fact. */
export function worstTone(...tones: Array<SignalTone | null | undefined>): SignalTone {
  let worst: SignalTone = 'ok';
  for (const tone of tones) if (tone && TONE_RANK[tone] > TONE_RANK[worst]) worst = tone;
  return worst;
}

/** A problem is shown unfolded; a healthy (or unread) topic is folded. */
export function needsAttention(tone: SignalTone): boolean {
  return tone === 'bad' || tone === 'warn';
}

// ── Presence ────────────────────────────────────────────────────────────────

const VERDICT_TONE: Record<ReachabilityVerdict, SignalTone> = {
  UP: 'ok',
  TUNNEL_DOWN_SITE_UP: 'warn',
  WAN_FAILOVER: 'warn',
  SITE_DOWN: 'bad',
  CONCENTRATOR_DEGRADED: 'bad',
  // « We cannot tell » — an observability gap, never an outage.
  UNREACHABLE: 'unknown',
};

export function presenceSignal(t: TFunction, verdict: ReachabilityVerdict | null | undefined): Signal {
  const effective = verdict ?? 'UNREACHABLE';
  return { tone: VERDICT_TONE[effective] ?? 'unknown', value: t(verdictLabelKey(effective)) };
}

// ── Permanent health check ──────────────────────────────────────────────────

const HEALTH_TONE: Record<DeviceHealthCheckView['display'], SignalTone> = {
  ok: 'ok',
  failing: 'warn',
  down: 'bad',
  suppressed: 'info',
  stale: 'unknown',
  unknown: 'unknown',
  not_checkable: 'unknown',
};

/** `undefined`: the server sent no block at all (older server). */
export function healthSignal(t: TFunction, view: DeviceHealthCheckView | null | undefined): Signal {
  if (!view) return { tone: 'unknown', value: t('devices.page.health.absent') };
  return { tone: HEALTH_TONE[view.display] ?? 'unknown', value: t(`devices.page.health.${view.display}`) };
}

// ── Management access (API-SSL) ─────────────────────────────────────────────

export function managementSignal(t: TFunction, view: Loaded<ManagementAccessView>): Signal | null {
  if (view === undefined) return LOADING;
  if (view === null) return { tone: 'unknown', value: t('devices.page.unreadable') };
  if (view.state === 'unsupported') return null;
  // A password carried to the wrong certificate outranks everything else.
  if (view.job?.account?.disclosedAt) return { tone: 'bad', value: t('devices.page.management.disclosed') };
  switch (view.state) {
    case 'in_progress':
      return { tone: 'info', value: t('devices.page.management.inProgress') };
    case 'failed':
      return { tone: 'bad', value: t('devices.page.management.failed') };
    case 'not_enabled':
      return { tone: 'warn', value: t('devices.page.management.notEnabled') };
    default:
      if (view.apiSsl.state === 'different') return { tone: 'warn', value: t('devices.page.management.sslDifferent') };
      if (view.api && !view.api.pinned) return { tone: 'warn', value: t('devices.page.management.notPinned') };
      return { tone: 'ok', value: t('devices.page.management.enabled') };
  }
}

// ── Legacy compliance (the corrected customer templates) ────────────────────


export function complianceSignal(t: TFunction, view: Loaded<LegacyComplianceView>): Signal | null {
  if (view === undefined) return LOADING;
  if (view === null) return { tone: 'unknown', value: t('devices.page.unreadable') };
  if (!view.supported) return null;
  if (view.job?.active) return { tone: 'info', value: t('devices.page.compliance.running') };
  if (view.job?.status === 'failed') return { tone: 'bad', value: t('devices.page.compliance.failed') };
  if (view.readAt === null) return { tone: 'unknown', value: t('devices.page.compliance.neverRead') };
  // The card's own classes (legacyCompliance.api), counted.
  const broken = view.fixes.filter((f) => LEGACY_FIX_BAD.has(f.state)).length;
  if (broken > 0) return { tone: 'bad', value: t('devices.page.compliance.broken', { count: broken }) };
  const pending = view.fixes.filter((f) => f.state === 'needed').length;
  if (pending > 0) return { tone: 'warn', value: t('devices.page.compliance.pending', { count: pending }) };
  // Refused by the router: failing, in the card's warning colour (not red).
  const refused = view.fixes.filter((f) => f.state === 'refused').length;
  if (refused > 0) return { tone: 'warn', value: t('devices.page.compliance.broken', { count: refused }) };
  // `unknown` fixes on a read device: the read did not cover them.
  if (view.fixes.some((f) => !LEGACY_FIX_GOOD.has(f.state) && f.state !== 'skipped')) {
    return { tone: 'unknown', value: t('devices.page.compliance.partial') };
  }
  return { tone: 'ok', value: t('devices.page.compliance.ok') };
}

// ── Uplink (configured vs observed, never merged) ───────────────────────────

export function uplinkSignal(t: TFunction, v: Loaded<UplinkVerdict>): Signal {
  if (v === undefined) return LOADING;
  if (v === null) return { tone: 'unknown', value: t('devices.page.unreadable') };
  const iface = v.observed ?? v.backup4g?.iface ?? '—';
  // Declared 4G-only: the cellular link is the nominal path, not a failover.
  if (isCellularOnly(v)) return { tone: 'info', value: t('devices.page.uplink.cellularOnly', { iface }) };
  if (v.onBackup) return { tone: 'warn', value: t('devices.page.uplink.onBackup', { iface }) };
  if (v.backup4g?.alertedAt) return { tone: 'warn', value: t('devices.page.uplink.backupAlerted') };
  if (v.observed) return { tone: 'ok', value: v.observed };
  if (v.configured) return { tone: 'unknown', value: t('devices.page.uplink.configuredOnly', { iface: v.configured }) };
  return { tone: 'unknown', value: t('devices.page.uplink.unmeasured') };
}

// ── SIM ─────────────────────────────────────────────────────────────────────

export type SimState =
  | { status: 'off' }
  | { status: 'loading' }
  | { status: 'error' }
  | { status: 'ready'; view: DeviceSimView };

const LINE_RANK: Record<SimLineVerdict, number> = { low: 3, unknown: 2, terminated: 1, ok: 0 };

/** The line the router's verdict is about: the worst of those linked to it. */
export function worstLine(lines: readonly SimLineListItem[]): SimLineListItem | null {
  let worst: SimLineListItem | null = null;
  for (const l of lines) if (!worst || LINE_RANK[l.verdict] > LINE_RANK[worst.verdict]) worst = l;
  return worst;
}

/** Cards read in this router's modems (the fleet's and the bench's). */
export function cardsRead(view: DeviceSimView): string[] {
  const cards = new Set<string>();
  for (const m of view.modems) if (m.iccid) cards.add(m.iccid);
  if (view.reading?.iccid) cards.add(view.reading.iccid);
  return [...cards];
}

/** Why no line is linked, as a code the SIM tab explains and acts on. */
export type SimNoLineReason = 'noModem' | 'notRead' | 'conflict' | 'elsewhere' | 'noLine';

export function simNoLineReason(view: DeviceSimView): SimNoLineReason {
  if (view.conflicts.length > 0) return 'conflict';
  if (view.cardLineElsewhere) return 'elsewhere';
  if (cardsRead(view).length > 0) return 'noLine';
  if (view.modems.length === 0 && view.reading === null) return 'noModem';
  return 'notRead';
}

export function simSignal(t: TFunction, sim: SimState): Signal | null {
  if (sim.status === 'off') return null;
  if (sim.status === 'loading') return LOADING;
  if (sim.status === 'error') return { tone: 'unknown', value: t('devices.page.unreadable') };
  const { view } = sim;
  const line = worstLine(view.lines);
  if (line) {
    // A conflict stands even beside a linked line: another card was read here.
    const conflictTone: SignalTone | null = view.conflicts.length > 0 ? 'warn' : null;
    if (line.verdict === 'terminated') {
      return { tone: 'warn', value: t('devices.page.sim.terminated', { msisdn: line.msisdn }) };
    }
    const pct = line.worstUsage?.usedPercent ?? null;
    const lineTone: SignalTone = line.verdict === 'low' ? 'warn'
      : line.verdict === 'ok' ? 'ok'
        // `unknown` because readings stopped is somebody's job today.
        : line.stale ? 'warn' : 'unknown';
    return {
      tone: worstTone(lineTone, conflictTone),
      value: pct !== null
        ? t('devices.page.sim.linkedPct', { msisdn: line.msisdn, pct: pct.toLocaleString(undefined, { maximumFractionDigits: 0 }) })
        : t('devices.page.sim.linked', {
          msisdn: line.msisdn,
          verdict: t(line.verdict === 'unknown' && line.stale ? 'mobile.verdict.stale' : `mobile.verdict.${line.verdict}`),
        }),
    };
  }
  const reason = simNoLineReason(view);
  // A router with no modem ever read is most often a fixed-line one: no chip.
  if (reason === 'noModem') return null;
  return {
    tone: reason === 'notRead' ? 'unknown' : 'warn',
    value: t(`devices.page.sim.${reason}`),
  };
}

// ── Drift ───────────────────────────────────────────────────────────────────

export type DriftState =
  | { status: 'off' }
  | { status: 'loading' }
  | { status: 'error' }
  /** `last` null: never compared. */
  | { status: 'ready'; last: DriftRunSummary | null };

export function driftSignal(t: TFunction, drift: DriftState): Signal | null {
  if (drift.status === 'off') return null;
  if (drift.status === 'loading') return LOADING;
  if (drift.status === 'error') return { tone: 'unknown', value: t('devices.page.unreadable') };
  const last = drift.last;
  if (!last) return { tone: 'unknown', value: t('devices.page.drift.never') };
  switch (last.status) {
    case 'in_sync':
      return { tone: 'ok', value: t('devices.page.drift.inSync') };
    case 'drifted':
      return { tone: 'warn', value: t('devices.page.drift.drifted', { count: last.findingsCount }) };
    case 'unreachable':
      return { tone: 'unknown', value: t('devices.page.drift.unreachable') };
    default:
      return { tone: 'unknown', value: t('devices.page.drift.error') };
  }
}

// ── Template ────────────────────────────────────────────────────────────────

export function templateSignal(t: TFunction, resolution: Loaded<DeviceTemplateResolution>): Signal {
  if (resolution === undefined) return LOADING;
  if (resolution === null) return { tone: 'unknown', value: t('devices.page.unreadable') };
  const applied = resolution.selected[0];
  if (!applied) return { tone: 'unknown', value: t('devices.page.template.none') };
  return {
    tone: 'ok',
    value: applied.revision !== null
      ? t('devices.page.template.applied', { name: applied.templateName, n: applied.revision })
      : applied.templateName,
  };
}

// ── RouterOS device-mode (can a dead-man be armed?) ─────────────────────────

/** The verdict is `deadmanReadiness()`'s, the one the server reads too. */
export function deadmanSignal(t: TFunction, reading: DeviceModeInfo | null): Signal {
  const { feasibility } = deadmanReadiness(reading);
  if (feasibility === 'blocked') {
    return { tone: 'bad', value: t('devices.page.deadman.blocked', { mode: reading?.mode ?? '—' }) };
  }
  if (feasibility === 'capable') return { tone: 'ok', value: t('devices.page.deadman.capable') };
  return { tone: 'unknown', value: t('devices.page.deadman.unknown') };
}

// ── WAN link (the mode the site declares, the last read, the last job) ──────

export function wanLinkSignal(t: TFunction, view: Loaded<WanLinkView>): Signal | null {
  if (view === undefined) return LOADING;
  if (view === null) return { tone: 'unknown', value: t('devices.page.unreadable') };
  if (!view.supported) return null;
  if (view.job?.active) return { tone: 'info', value: t('wanLink.summary.running') };
  const mode = view.declared.mode;
  const label = mode ? t(`wanLink.summary.${mode}`) : t('wanLink.summary.unknown');
  if (view.job?.status === 'failed' && view.job.outcome !== 'refused') return { tone: 'bad', value: label };
  // The router read in another mode than the site declares: worth a look.
  if (view.observed && view.observed.mode !== null && mode !== null && view.observed.mode !== mode) {
    return { tone: 'warn', value: label };
  }
  return { tone: mode ? 'ok' : 'unknown', value: label };
}
