import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Smartphone } from 'lucide-react';
import { simApi, type DeviceSimView, type SimLineListItem } from '@/api/sim.api';
import { DataAmount, VerdictBadge, When } from '@/components/mobile/SimBits';

/**
 * The mobile lines of one router (device page) or one site (site page): which
 * MSISDN, which operator, what is left and its verdict, each a link to the
 * line's own screen. A balance nobody read is `—` and `unknown`, never a zero
 * (`DataAmount`, `VerdictBadge`). Read-only: nothing here proposes, approves or
 * buys anything. Shown to SIM_READ only — the caller decides.
 *
 * On a device it also shows the card the bench read in the router's modem:
 * that ICCID is what linked the line (`services/sim/deviceLink.service.ts`),
 * and when no line carries it, or a line carrying it is linked to another
 * router, it says so rather than leaving an empty block.
 */

function LineRows({ lines }: { lines: SimLineListItem[] }) {
  const { t } = useTranslation();
  return (
    <ul className="space-y-1.5">
      {lines.map((l) => (
        <li key={l.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
          <Link to={`/mobile/lines/${l.id}`} className="font-mono text-accent hover:underline">{l.msisdn}</Link>
          <span className="text-text-secondary">{l.operator ?? '—'}</span>
          <span className="text-xs text-text-muted">
            {t('simBlock.remaining', { defaultValue: 'Remaining' })}{' '}
            <DataAmount mb={l.worstZone?.restMb ?? null} />
          </span>
          <VerdictBadge verdict={l.verdict} stale={l.stale} />
          {l.deviceName && <span className="text-xs text-text-muted">{l.deviceName}</span>}
        </li>
      ))}
    </ul>
  );
}

function Frame({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation();
  return (
    <section className="rounded-lg border border-border bg-bg-secondary p-4">
      <h2 className="mb-3 flex items-center gap-1.5 text-sm font-semibold uppercase tracking-wide text-text-secondary">
        <Smartphone size={14} />
        {t('simBlock.title', { defaultValue: 'Mobile line' })}
      </h2>
      {children}
    </section>
  );
}

export function DeviceSimBlock({ deviceId }: { deviceId: number }) {
  const { t } = useTranslation();
  const [view, setView] = useState<DeviceSimView | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let live = true;
    simApi.deviceSim(deviceId)
      .then((v) => { if (live) { setView(v); setFailed(false); } })
      .catch(() => { if (live) setFailed(true); });
    return () => { live = false; };
  }, [deviceId]);

  if (failed) {
    return <Frame><p className="text-sm text-text-muted">{t('simBlock.loadError', { defaultValue: 'The mobile lines could not be read.' })}</p></Frame>;
  }
  if (!view) return <Frame><p className="text-sm text-text-muted">…</p></Frame>;
  // A router with no modem and no line: nothing to show, no empty block.
  if (view.reading === null && view.lines.length === 0) return null;

  const r = view.reading;
  return (
    <Frame>
      <div className="space-y-3">
        <p className="text-xs text-text-muted">
          {r === null
            ? t('simBlock.neverRead', { defaultValue: 'The bench never read this router\'s modem.' })
            : r.iccid === null
              ? <>{t('simBlock.noCard', { defaultValue: 'No SIM card was read at the bench' })} (<When iso={r.readAt} />)</>
              : <>
                  {t('simBlock.iccidRead', { defaultValue: 'SIM card read at the bench' })}{' '}
                  <span className="font-mono text-text-secondary">{r.iccid}</span>
                  {r.imsi && <> · IMSI <span className="font-mono text-text-secondary">{r.imsi}</span></>}
                  {' '}(<When iso={r.readAt} />)
                </>}
        </p>
        {view.lines.length > 0 ? (
          <LineRows lines={view.lines} />
        ) : r?.iccid && !view.cardLineElsewhere ? (
          <p className="text-sm text-text-muted">
            {t('simBlock.noLine', { defaultValue: 'No mobile line of this workspace carries this card yet. It is linked as soon as a line with this ICCID is assigned here.' })}
          </p>
        ) : null}
        {view.cardLineElsewhere && (
          <p className="rounded-md border border-status-ssl-warning/30 bg-status-ssl-warning/10 px-3 py-2 text-xs text-status-ssl-warning">
            {t('simBlock.linkedElsewhere', {
              msisdn: view.cardLineElsewhere.msisdn,
              defaultValue: 'The line {{msisdn}} carries this card but is linked to another router:',
            })}{' '}
            <Link to={`/devices/${view.cardLineElsewhere.deviceId}`} className="underline">
              {view.cardLineElsewhere.deviceName ?? `#${view.cardLineElsewhere.deviceId}`}
            </Link>
            {'. '}
            <Link to={`/mobile/lines/${view.cardLineElsewhere.lineId}`} className="underline">
              {t('simBlock.openLine', { defaultValue: 'Open the line' })}
            </Link>
          </p>
        )}
      </div>
    </Frame>
  );
}

export function SiteSimBlock({ siteId }: { siteId: number }) {
  const { t } = useTranslation();
  const [lines, setLines] = useState<SimLineListItem[] | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let live = true;
    simApi.lines({ siteId })
      .then((ls) => { if (live) { setLines(ls); setFailed(false); } })
      .catch(() => { if (live) setFailed(true); });
    return () => { live = false; };
  }, [siteId]);

  if (failed) {
    return <Frame><p className="text-sm text-text-muted">{t('simBlock.loadError', { defaultValue: 'The mobile lines could not be read.' })}</p></Frame>;
  }
  if (!lines) return <Frame><p className="text-sm text-text-muted">…</p></Frame>;
  // A site with no mobile line (most fixed-line stores): no empty block.
  if (lines.length === 0) return null;
  return (
    <Frame>
      <LineRows lines={lines} />
    </Frame>
  );
}
