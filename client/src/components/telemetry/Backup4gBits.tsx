import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import type { SimLineVerdict } from '@obliwan/shared';
import { DataAmount, VerdictBadge } from '@/components/mobile/SimBits';

/**
 * The 4G backup watch's shared pieces (uplink card, dashboard). A SIM balance
 * the partner did not report is UNKNOWN: drawn as "—" with its own words,
 * never as a zero.
 */

/** The SIM line of the router (server `Backup4gSim`): `restMb` null is an
 *  UNKNOWN balance, never a zero. */
export interface Backup4gSim {
  lineId: number; msisdn: string; operator: string | null; label: string | null;
  restMb: number | null; zone: string | null; observedAt: string | null;
  verdict: SimLineVerdict; stale: boolean;
}

/** "3 minutes ago" / "il y a 3 minutes", from Intl so no string needs translating. */
export function relativeTime(iso: string | null | undefined, lang: string): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  const diffS = Math.round((d.getTime() - Date.now()) / 1000);
  const a = Math.abs(diffS);
  const rtf = new Intl.RelativeTimeFormat(lang, { numeric: 'auto' });
  return a < 60 ? rtf.format(diffS, 'second')
    : a < 3600 ? rtf.format(Math.round(diffS / 60), 'minute')
      : a < 86_400 ? rtf.format(Math.round(diffS / 3600), 'hour')
        : rtf.format(Math.round(diffS / 86_400), 'day');
}

/** "12/10/2026 18:40", in the reader's language. */
export function shortDate(iso: string, lang: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(lang, { dateStyle: 'short', timeStyle: 'short' });
}

/** The SIM lines of a router, with their LAST KNOWN balance. */
export function Backup4gSims({ sims, lang }: { sims: Backup4gSim[]; lang: string }) {
  const { t } = useTranslation();
  if (sims.length === 0) return <p className="text-[11px] text-text-muted">{t('uplink.backup4g.noSim')}</p>;
  return (
    <ul className="space-y-1">
      {sims.map((s) => (
        <li key={s.lineId} className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs">
          <Link to={`/mobile/lines/${s.lineId}`} className="font-mono text-accent hover:underline">{s.msisdn}</Link>
          {s.operator && <span className="text-text-secondary">{s.operator}</span>}
          <DataAmount mb={s.restMb} />
          {s.zone && <span className="text-[11px] text-text-muted">{s.zone}</span>}
          {s.restMb === null
            ? <span className="text-[11px] text-text-muted">{t('uplink.backup4g.balanceUnknown')}</span>
            : s.observedAt && (
              <span className="text-[11px] text-text-muted">
                {t('uplink.backup4g.balanceRead', { ago: relativeTime(s.observedAt, lang) ?? s.observedAt })}
              </span>
            )}
          <VerdictBadge verdict={s.verdict} stale={s.stale} />
        </li>
      ))}
    </ul>
  );
}

