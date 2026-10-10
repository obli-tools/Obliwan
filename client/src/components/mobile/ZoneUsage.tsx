import { useTranslation } from 'react-i18next';
import { formatData, type SimZoneUsage } from '@obliwan/shared';
import { cn } from '@/utils/cn';

/**
 * One zone's usage against its own envelope (brick 6):
 * « 72 % utilisés · 7,2 Go / 10 Go ». With no known envelope it shows the
 * consumption only, and says the MB threshold is what judges it — never a
 * 0 Go envelope, never a percentage of a threshold.
 */
export function ZoneUsageLine({
  usage,
  thresholdPercent,
  thresholdMb,
  compact = false,
}: {
  usage: SimZoneUsage | null;
  thresholdPercent: number;
  thresholdMb: number;
  compact?: boolean;
}) {
  const { t } = useTranslation();
  if (!usage) return <span className="text-text-muted">—</span>;
  const pct = usage.usedPercent;
  const bar = pct === null ? null : Math.min(100, Math.max(0, pct));
  const tone =
    usage.verdict === 'low' ? 'bg-status-ssl-warning' : usage.verdict === 'ok' ? 'bg-status-up' : 'bg-text-muted';
  return (
    <div className={cn('min-w-[150px]', compact ? 'text-xs' : 'text-sm')}>
      {pct !== null && usage.envelopeMb !== null ? (
        <>
          <div className="tabular-nums text-text-primary">
            {t('mobile.usage.percentUsed', {
              pct: pct.toLocaleString(undefined, { maximumFractionDigits: 1 }),
              used: formatData(usage.usedMb),
              envelope: formatData(usage.envelopeMb),
            })}
          </div>
          <div className="mt-1 h-1.5 w-full overflow-hidden rounded bg-bg-tertiary">
            <div className={cn('h-full', tone)} style={{ width: `${bar}%` }} />
          </div>
          {!compact ? (
            <div className="mt-0.5 text-[11px] text-text-muted">
              {t(usage.envelopeSource === 'plan' ? 'mobile.usage.envelopeFromPlan' : 'mobile.usage.envelopeFromPartner')}
              {' · '}
              {t('mobile.usage.alertAt', { pct: thresholdPercent })}
            </div>
          ) : null}
        </>
      ) : (
        <>
          <div className="tabular-nums text-text-primary">
            {usage.usedMb !== null
              ? t('mobile.usage.usedOnly', { used: formatData(usage.usedMb) })
              : usage.restMb !== null
                ? t('mobile.usage.restOnly', { rest: formatData(usage.restMb) })
                : '—'}
          </div>
          <div className="mt-0.5 text-[11px] text-text-muted">
            {t('mobile.usage.envelopeUnknown', { value: formatData(thresholdMb) })}
          </div>
        </>
      )}
    </div>
  );
}
