import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Smartphone } from 'lucide-react';
import { simApi, type DeviceSimView, type DeviceSimConflict } from '@/api/sim.api';
import { DataAmount, VerdictBadge, When } from '@/components/mobile/SimBits';

/**
 * « Carte SIM / ligne mobile » — the device page's view of the card in each
 * LTE modem of the router and of the mobile line it carries.
 *
 * The cards come from two readers: the fleet (every modem, re-read by the
 * health check — migration 080) and the bench (its `lte1`, once, at
 * preparation — migration 063). A field nobody printed is « non lu », never
 * "no SIM". The linked line is the one whose ICCID is the card's
 * (`services/sim/deviceLink.service.ts`): exact, or equal on the first 19
 * digits when one side carries the check digit and the other does not.
 * When nothing is linked, the panel SAYS WHY rather than staying empty.
 * Read-only: nothing here proposes, approves or buys anything.
 */

function Frame({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation();
  return (
    <section className="rounded-lg border border-border bg-bg-secondary p-4">
      <h2 className="mb-3 flex items-center gap-1.5 text-sm font-semibold uppercase tracking-wide text-text-secondary">
        <Smartphone size={14} />
        {t('simPanel.title', { defaultValue: 'SIM card / mobile line' })}
      </h2>
      {children}
    </section>
  );
}

function Val({ v }: { v: string | null }) {
  const { t } = useTranslation();
  return v === null
    ? <span className="text-text-muted">{t('simPanel.notRead', { defaultValue: 'not read' })}</span>
    : <span className="font-mono text-text-secondary">{v}</span>;
}

function ConflictNote({ c }: { c: DeviceSimConflict }) {
  const { t } = useTranslation();
  const text = c.kind === 'other_tenant'
    ? t('simPanel.conflict.otherTenant', { defaultValue: 'The card {{iccid}} belongs to a line of another customer. Nothing was moved: the platform settles it in the SIM reconciliation.', iccid: c.iccid })
    : c.kind === 'linked_elsewhere'
      ? t('simPanel.conflict.linkedElsewhere', { defaultValue: 'The line carrying the card {{iccid}} is already linked to another router. Nothing was moved.', iccid: c.iccid })
      : t('simPanel.conflict.ambiguous', { defaultValue: 'The card {{iccid}} was read in several routers: no link was made.', iccid: c.iccid });
  return (
    <p className="rounded-md border border-status-ssl-warning/30 bg-status-ssl-warning/10 px-3 py-2 text-xs text-status-ssl-warning">
      {text}
      {c.lineId !== null && (
        <>
          {' '}
          <Link to={`/mobile/lines/${c.lineId}`} className="underline">{c.msisdn ?? `#${c.lineId}`}</Link>
        </>
      )}
      {c.prefixMatch && (
        <> {t('simPanel.prefixMatch', { defaultValue: '(ICCIDs equal on their first 19 digits only)' })}</>
      )}
    </p>
  );
}

export function DeviceSimPanel({ deviceId }: { deviceId: number }) {
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
  // A router with no modem, no bench reading and no line: nothing to show.
  if (view.modems.length === 0 && view.reading === null && view.lines.length === 0 && view.conflicts.length === 0) {
    return null;
  }

  const bench = view.reading;
  const cards = new Set<string>();
  for (const m of view.modems) if (m.iccid) cards.add(m.iccid);
  if (bench?.iccid) cards.add(bench.iccid);

  // Why nothing is linked, when nothing is.
  let reason: string | null = null;
  if (view.lines.length === 0) {
    if (cards.size === 0) {
      reason = t('simPanel.reason.notRead', { defaultValue: 'The ICCID has not been read yet: no modem of this router has shown its SIM card. This is not "no SIM".' });
    } else if (view.conflicts.length === 0 && !view.cardLineElsewhere) {
      reason = t('simPanel.reason.noLine', { defaultValue: 'No mobile line carries this card yet. It is linked automatically as soon as a line with this ICCID appears (partner sweep or manual entry).' });
    }
  }

  return (
    <Frame>
      <div className="space-y-3">
        {view.modems.length > 0 && (
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left text-text-muted">
                <th className="py-1 pr-3 font-medium">{t('simPanel.interface', { defaultValue: 'Modem' })}</th>
                <th className="py-1 pr-3 font-medium">ICCID</th>
                <th className="py-1 pr-3 font-medium">IMSI</th>
                <th className="py-1 pr-3 font-medium">IMEI</th>
                <th className="py-1 font-medium">{t('simPanel.readAt', { defaultValue: 'Read' })}</th>
              </tr>
            </thead>
            <tbody>
              {view.modems.map((m) => (
                <tr key={m.interface} className="border-t border-border">
                  <td className="py-1 pr-3 font-mono">{m.interface}</td>
                  <td className="py-1 pr-3"><Val v={m.iccid} /></td>
                  <td className="py-1 pr-3"><Val v={m.imsi} /></td>
                  <td className="py-1 pr-3"><Val v={m.imei} /></td>
                  <td className="py-1 text-text-muted"><When iso={m.observedAt} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {bench && (
          <p className="text-xs text-text-muted">
            {bench.iccid === null
              ? <>{t('simBlock.noCard', { defaultValue: 'No SIM card was read at the bench' })} (<When iso={bench.readAt} />)</>
              : <>
                  {t('simBlock.iccidRead', { defaultValue: 'SIM card read at the bench' })}{' '}
                  <span className="font-mono text-text-secondary">{bench.iccid}</span>
                  {bench.imsi && <> · IMSI <span className="font-mono text-text-secondary">{bench.imsi}</span></>}
                  {' '}(<When iso={bench.readAt} />)
                </>}
          </p>
        )}

        {view.lines.length > 0 && (
          <ul className="space-y-2">
            {view.lines.map((l) => (
              <li key={l.id} className="space-y-0.5 text-sm">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <Link to={`/mobile/lines/${l.id}`} className="font-mono text-accent hover:underline">{l.msisdn}</Link>
                  <span className="text-text-secondary">{l.operator ?? '—'}</span>
                  <VerdictBadge verdict={l.verdict} stale={l.stale} />
                </div>
                <div className="flex flex-wrap gap-x-4 gap-y-0.5 text-xs text-text-muted">
                  <span>{t('simPanel.plan', { defaultValue: 'Plan' })} : {l.partner?.planLabel ?? '—'}</span>
                  <span>{t('simPanel.status', { defaultValue: 'Status' })} : {l.partner?.stateLabel ?? l.status}</span>
                  <span>
                    {t('simPanel.usedThisMonth', { defaultValue: 'Used this month' })} :{' '}
                    <DataAmount mb={l.partner?.consumption.nationalMb ?? null} />
                  </span>
                  <span>
                    {t('simBlock.remaining', { defaultValue: 'Remaining' })}{' '}
                    <DataAmount mb={l.worstZone?.restMb ?? null} />
                  </span>
                </div>
              </li>
            ))}
          </ul>
        )}

        {reason && <p className="text-sm text-text-muted">{reason}</p>}

        {view.cardLineElsewhere && (
          <p className="rounded-md border border-status-ssl-warning/30 bg-status-ssl-warning/10 px-3 py-2 text-xs text-status-ssl-warning">
            {t('simBlock.linkedElsewhere', {
              msisdn: view.cardLineElsewhere.msisdn,
              defaultValue: 'The line {{msisdn}} carries this card but is linked to another router:',
            })}{' '}
            <Link to={`/devices/${view.cardLineElsewhere.deviceId}`} className="underline">
              {view.cardLineElsewhere.deviceName ?? `#${view.cardLineElsewhere.deviceId}`}
            </Link>
          </p>
        )}
        {view.conflicts.map((c) => <ConflictNote key={`${c.kind}-${c.iccid}-${c.lineId ?? 'x'}`} c={c} />)}
      </div>
    </Frame>
  );
}
