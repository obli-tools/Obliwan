import { Fragment, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import {
  ArrowDown,
  ArrowUp,
  ChevronDown,
  ChevronRight,
  Hourglass,
  RefreshCcwDot,
  Router,
  ShieldAlert,
  Unplug,
} from 'lucide-react';
import { cn } from '@/utils/cn';
import { anonHostname } from '@/utils/anonymize';
import { formatBps, formatCount, formatPct, utilPct } from '@/utils/series';
import type { NetInterface } from '@/types/telemetry';
import { OperStatusBadge } from './OperStatusBadge';
import { UtilizationBar } from './UtilizationBar';
import { InterfaceSeriesPanel } from './InterfaceSeriesPanel';
import { TenantBadge } from '@/components/common/TenantBadge';

export type InterfaceSortKey =
  | 'saturation'
  | 'name'
  | 'device'
  | 'inBps'
  | 'outBps'
  | 'errors'
  | 'speed';

interface InterfacesTableProps {
  interfaces: NetInterface[];
  /** The device column is dropped on a device's own tab. */
  showDevice?: boolean;
  emptyLabel?: string;
}

/**
 * Peak utilisation of a link: the busier of the two directions.
 *
 * `null` propagates — an interface whose speed we never read has NO
 * saturation, and is sorted LAST in descending order rather than being given a
 * fabricated 0 % that would bury it at the bottom of the list where a broken
 * link hides.
 */
export function peakUtil(iface: NetInterface): number | null {
  const s = iface.lastSample;
  if (!s) return null;
  const inPct = utilPct(s.inBps, iface.speedBps);
  const outPct = utilPct(s.outBps, iface.speedBps);
  if (inPct === null && outPct === null) return null;
  return Math.max(inPct ?? 0, outPct ?? 0);
}

/**
 * ┌─ AN EMPTY RATE CELL IS FOUR DIFFERENT ANSWERS ─────────────────────────────┐
 * │ A throughput is a DERIVATIVE: one counter reading is not a rate, two       │
 * │ subtracted are. So a blank In/Out column can mean opposite things, and one │
 * │ dash for all of them either sends an operator to debug a working system,   │
 * │ or lets a fleet nobody polls look merely quiet.                            │
 * │                                                                            │
 * │   measured       a real sample exists.                                     │
 * │   awaitingSecond one counter was read (`baselineAt`); the rate lands at    │
 * │                  the next cycle. NORMAL: muted and informative.            │
 * │   pollingOff     nobody asked for this interface (monitoring off) or it    │
 * │                  has left the ifTable. Absence is BY DESIGN, and marking   │
 * │                  it as a failure teaches operators to ignore the colour.   │
 * │   neverPolled    no counter has EVER been read on an interface we are      │
 * │                  supposed to poll. The only one of the four that is a bug. │
 * │                                                                            │
 * │ A sample COUNT would be 0 for the last three alike, which is exactly why   │
 * │ the server sends two nullable timestamps instead.                          │
 * └────────────────────────────────────────────────────────────────────────────┘
 */
export type RateState = 'measured' | 'awaitingSecond' | 'pollingOff' | 'neverPolled';

export function rateState(iface: NetInterface): RateState {
  if (iface.lastSample) return 'measured';
  if (iface.baselineAt) return 'awaitingSecond';
  if (iface.monitored === false || iface.state === 'vanished') return 'pollingOff';
  return 'neverPolled';
}

function errorTotal(iface: NetInterface): number | null {
  const s = iface.lastSample;
  if (!s) return null;
  return s.inErrs + s.outErrs + s.inDiscards + s.outDiscards;
}

/** `null` always sorts last, in BOTH directions: absence of measurement is not
 *  a small value and must never win a "least saturated" query either. */
function nullsLast(a: number | null, b: number | null, dir: 1 | -1): number {
  if (a === null && b === null) return 0;
  if (a === null) return 1;
  if (b === null) return -1;
  return (a - b) * dir;
}

function stamp(iso: string | null | undefined): string {
  return iso ? new Date(iso).toLocaleString() : '';
}

/** The tooltip of the two non-measured states worth explaining. Shared so the
 *  rate columns and the "last sample" column cannot end up saying different
 *  things about the same interface. */
function samplingHint(iface: NetInterface, state: RateState, t: TFunction): string | undefined {
  if (state === 'awaitingSecond') {
    return t('interfaces.sampling.awaitingHint', {
      at: stamp(iface.baselineAt),
      seconds: iface.effectivePollSec,
    });
  }
  if (state === 'pollingOff') return t('interfaces.sampling.offHint');
  if (state === 'neverPolled') return t('interfaces.sampling.neverHint');
  return undefined;
}

/** One direction of one interface. `bps` is only ever read in the `measured`
 *  state — the other three have no number to show and must not borrow one. */
function RateCell({
  iface,
  state,
  bps,
}: {
  iface: NetInterface;
  state: RateState;
  bps: number | null;
}) {
  const { t } = useTranslation();
  const hint = samplingHint(iface, state, t);

  if (state === 'measured') {
    return (
      <span className="font-mono text-[12px] tabular-nums text-text-secondary">
        {formatBps(bps)}
      </span>
    );
  }
  if (state === 'awaitingSecond') {
    return (
      <span
        className="inline-flex items-center gap-1 text-[11px] italic text-text-muted"
        title={hint}
      >
        <Hourglass size={10} className="shrink-0" />
        {t('interfaces.sampling.awaiting')}
      </span>
    );
  }
  if (state === 'pollingOff') {
    return (
      <span className="text-[11px] text-text-muted" title={hint}>
        {t('interfaces.sampling.off')}
      </span>
    );
  }
  return (
    <span
      className="inline-flex items-center gap-1 text-[11px] text-status-ssl-warning"
      title={hint}
    >
      <Unplug size={10} className="shrink-0" />
      {t('interfaces.sampling.never')}
    </span>
  );
}

/** The same four states, dated. It reads `baselineAt` for the middle one and
 *  labels it as a COUNTER read, never as a sample: the row would otherwise
 *  claim a measurement the samples table does not contain. */
function LastSampleCell({ iface, state }: { iface: NetInterface; state: RateState }) {
  const { t } = useTranslation();
  const hint = samplingHint(iface, state, t);

  if (state === 'measured') return <>{stamp(iface.lastSample?.ts)}</>;
  if (state === 'awaitingSecond') {
    return (
      <span className="italic" title={hint}>
        {t('interfaces.sampling.awaitingAt', { at: stamp(iface.baselineAt) })}
      </span>
    );
  }
  if (state === 'pollingOff') return <span title={hint}>{t('interfaces.sampling.off')}</span>;
  return (
    <span className="text-status-ssl-warning" title={hint}>
      {t('interfaces.neverSampled')}
    </span>
  );
}

export function InterfacesTable({
  interfaces,
  showDevice = true,
  emptyLabel,
}: InterfacesTableProps) {
  const { t } = useTranslation();
  const [sortKey, setSortKey] = useState<InterfaceSortKey>('saturation');
  const [desc, setDesc] = useState(true);
  const [expanded, setExpanded] = useState<number | null>(null);

  const sorted = useMemo(() => {
    const dir: 1 | -1 = desc ? -1 : 1;
    const rows = [...interfaces];
    rows.sort((a, b) => {
      switch (sortKey) {
        case 'name':
          return a.ifName.localeCompare(b.ifName) * dir;
        case 'device':
          return (a.deviceName ?? '').localeCompare(b.deviceName ?? '') * dir;
        case 'inBps':
          return nullsLast(a.lastSample?.inBps ?? null, b.lastSample?.inBps ?? null, dir);
        case 'outBps':
          return nullsLast(a.lastSample?.outBps ?? null, b.lastSample?.outBps ?? null, dir);
        case 'errors':
          return nullsLast(errorTotal(a), errorTotal(b), dir);
        case 'speed':
          return nullsLast(a.speedBps, b.speedBps, dir);
        case 'saturation':
        default:
          return nullsLast(peakUtil(a), peakUtil(b), dir);
      }
    });
    return rows;
  }, [interfaces, sortKey, desc]);

  const toggleSort = (key: InterfaceSortKey) => {
    if (key === sortKey) setDesc((v) => !v);
    else {
      setSortKey(key);
      setDesc(key !== 'name' && key !== 'device');
    }
  };

  const Th = ({ label, sort }: { label: string; sort?: InterfaceSortKey }) => (
    <th className="px-3 py-2 font-medium">
      {sort ? (
        <button
          onClick={() => toggleSort(sort)}
          className={cn(
            'inline-flex items-center gap-1 transition-colors hover:text-text-primary',
            sortKey === sort && 'text-text-primary',
          )}
        >
          {label}
          {sortKey === sort &&
            (desc ? <ArrowDown size={10} /> : <ArrowUp size={10} />)}
        </button>
      ) : (
        label
      )}
    </th>
  );

  if (interfaces.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
        <Router size={28} className="mx-auto mb-2 text-text-muted" />
        <p className="text-sm text-text-muted">{emptyLabel ?? t('interfaces.empty')}</p>
      </div>
    );
  }

  const colCount = showDevice ? 9 : 8;

  return (
    <div className="overflow-x-auto rounded-lg border border-border bg-bg-secondary">
      <table className="w-full min-w-[980px] text-left text-sm">
        <thead>
          <tr className="border-b border-border text-[11px] uppercase tracking-wider text-text-muted">
            <th className="w-8 px-3 py-2" />
            <Th label={t('interfaces.columns.state')} />
            <Th label={t('interfaces.columns.name')} sort="name" />
            {showDevice && <Th label={t('interfaces.columns.device')} sort="device" />}
            <Th label={t('interfaces.columns.speed')} sort="speed" />
            <Th label={t('interfaces.columns.in')} sort="inBps" />
            <Th label={t('interfaces.columns.out')} sort="outBps" />
            <Th label={t('interfaces.columns.saturation')} sort="saturation" />
            <Th label={t('interfaces.columns.errors')} sort="errors" />
            <Th label={t('interfaces.columns.lastSample')} />
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {sorted.map((iface) => {
            const sample = iface.lastSample;
            const rate = rateState(iface);
            const pct = peakUtil(iface);
            const errs = errorTotal(iface);
            const open = expanded === iface.id;
            return (
              <Fragment key={iface.id}>
                <tr
                  className={cn(
                    'group cursor-pointer transition-colors hover:bg-bg-hover',
                    open && 'bg-bg-hover',
                    // A vanished interface is kept forever (its history is
                    // exactly what somebody will ask about) but it is not a
                    // live row and must not read as one.
                    iface.state === 'vanished' && 'opacity-55',
                  )}
                  onClick={() => setExpanded(open ? null : iface.id)}
                >
                  <td className="px-3 py-2 text-text-muted">
                    {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                  </td>
                  <td className="px-3 py-2">
                    <OperStatusBadge
                      operStatus={iface.operStatus}
                      adminStatus={iface.adminStatus}
                    />
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-1.5">
                      <span className="font-mono text-[13px] font-medium text-text-primary">
                        {iface.ifName}
                      </span>
                      {iface.needsRediscovery && (
                        <span title={t('interfaces.needsRediscoveryHint')} className="inline-flex">
                          <RefreshCcwDot size={11} className="shrink-0 text-status-ssl-warning" />
                        </span>
                      )}
                      {/* Collection health. An interface whose samples are all
                          being discarded shows blank rate columns — exactly
                          like an idle link. This marker is what separates the
                          two without opening the row.

                          It stays silent on the single NO_BASELINE discard that
                          EVERY interface records on its first poll: the rate
                          columns already say "awaiting the second reading", and
                          a warning triangle next to it would make the normal
                          first cycle of a healthy fleet look like a fault. A
                          STREAK of NO_BASELINE is different — the baseline is
                          not persisting — so only a streak of one is hidden. */}
                      {(iface.consecutiveDiscards ?? 0) > 0 &&
                        !(
                          rate === 'awaitingSecond' &&
                          iface.lastDiscard === 'NO_BASELINE' &&
                          (iface.consecutiveDiscards ?? 0) <= 1
                        ) && (
                        <span
                          className="inline-flex"
                          title={t('interfaces.discardStreak', {
                            count: iface.consecutiveDiscards,
                            reason: iface.lastDiscard
                              ? t(`interfaces.discard.${iface.lastDiscard}`, {
                                  defaultValue: iface.lastDiscard,
                                })
                              : t('interfaces.discard.unknown'),
                          })}
                        >
                          <ShieldAlert size={11} className="shrink-0 text-status-ssl-warning" />
                        </span>
                      )}
                      {iface.state === 'vanished' && (
                        <span className="rounded-full border border-dashed border-text-muted/50 px-1.5 py-px text-[9px] text-text-muted">
                          {t('interfaces.state.vanished')}
                        </span>
                      )}
                    </div>
                    {iface.ifAlias && (
                      <div className="truncate text-[10px] text-text-muted">{iface.ifAlias}</div>
                    )}
                  </td>
                  {showDevice && (
                    <td className="px-3 py-2 text-text-secondary" onClick={(e) => e.stopPropagation()}>
                      <Link to={`/devices/${iface.deviceId}`} className="hover:text-accent">
                        {anonHostname(iface.deviceName ?? `#${iface.deviceId}`)}
                      </Link>
                      {iface.siteName && (
                        <div className="text-[10px] text-text-muted">{iface.siteName}</div>
                      )}
                      {/* God view: whose router this interface is on. */}
                      <TenantBadge name={iface.tenantName} />
                    </td>
                  )}
                  <td className="px-3 py-2 font-mono text-[12px] text-text-secondary">
                    {iface.speedBps === null ? (
                      <span className="text-text-muted" title={t('interfaces.speedUnknownHint')}>
                        {t('interfaces.speedUnknown')}
                      </span>
                    ) : (
                      formatBps(iface.speedBps, 0)
                    )}
                  </td>
                  <td className="px-3 py-2">
                    <RateCell iface={iface} state={rate} bps={sample?.inBps ?? null} />
                  </td>
                  <td className="px-3 py-2">
                    <RateCell iface={iface} state={rate} bps={sample?.outBps ?? null} />
                  </td>
                  <td className="px-3 py-2">
                    <UtilizationBar pct={pct} />
                  </td>
                  <td
                    className={cn(
                      'px-3 py-2 font-mono text-[12px] tabular-nums',
                      errs && errs > 0 ? 'text-status-ssl-expired' : 'text-text-muted',
                    )}
                  >
                    {formatCount(errs)}
                  </td>
                  <td className="px-3 py-2 font-mono text-[11px] text-text-muted">
                    <LastSampleCell iface={iface} state={rate} />
                  </td>
                </tr>
                {open && (
                  <tr>
                    <td colSpan={colCount + 1} className="bg-bg-primary/40 p-3">
                      <InterfaceSeriesPanel iface={iface} />
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/** Re-exported so the fleet page can print the same figure in its header. */
export function formatPeakUtil(iface: NetInterface): string {
  return formatPct(peakUtil(iface), 0);
}
