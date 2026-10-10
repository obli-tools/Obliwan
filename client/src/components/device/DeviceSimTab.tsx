import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, Cpu, RefreshCw, Search, ShieldAlert, Smartphone } from 'lucide-react';
import { CAPABILITIES } from '@obliwan/shared';
import { useAuthStore } from '@/store/authStore';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { When } from '@/components/mobile/SimBits';
import { DeviceApnCard } from '@/components/fleet/DeviceApnCard';
import { Backup4gSection, type UplinkVerdict } from '@/components/telemetry/DeviceUplinkCard';
import type { DeviceSimConflict, DeviceSimView } from '@/api/sim.api';
import type { DeviceDetail } from '@/types/fleet';
import { cardsRead, simNoLineReason, uplinkSignal, type Loaded, type SimState } from './deviceSignals';
import { SimLineDetail } from './SimLineDetail';
import { TONE_TEXT, ToneDot } from './StatusSection';

/**
 * « 4G / SIM » — the card in the router's LTE modem(s), the mobile line it
 * carries with everything the line's page knows, the 4G backup watch and the
 * LTE APN, on the router's own page.
 *
 * The SIM view is the page's (`useDeviceSignals`, one read for the overview
 * summary, the chip and this tab); the backup watch is the uplink card's
 * (reported by the overview, which stays mounted). When no line is linked the
 * tab says WHY and WHAT TO DO — an empty tab reads as "this router has no
 * SIM", which is a statement nobody made.
 */

function Card({ title, icon, children, aside }: { title: string; icon: ReactNode; children: ReactNode; aside?: ReactNode }) {
  return (
    <section className="rounded-lg border border-border bg-bg-secondary p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h2 className="flex items-center gap-2 text-sm font-semibold text-text-primary">
          <span className="text-text-secondary">{icon}</span>
          {title}
        </h2>
        {aside}
      </div>
      {children}
    </section>
  );
}

function Val({ v }: { v: string | null }) {
  const { t } = useTranslation();
  // A field nobody printed is « non lu », never "no SIM".
  return v === null
    ? <span className="text-text-muted">{t('simPanel.notRead')}</span>
    : <span className="font-mono text-text-secondary">{v}</span>;
}

/** A link the automatic match could not make, and what to do about it. */
function ConflictNote({ c }: { c: DeviceSimConflict }) {
  const { t } = useTranslation();
  const isAdmin = useAuthStore((s) => s.isAdmin)();
  const what = c.kind === 'other_tenant' ? t('simPanel.conflict.otherTenant', { iccid: c.iccid })
    : c.kind === 'linked_elsewhere' ? t('simPanel.conflict.linkedElsewhere', { iccid: c.iccid })
      : t('simPanel.conflict.ambiguous', { iccid: c.iccid });
  return (
    <div className="rounded-md border border-status-ssl-warning/30 bg-status-ssl-warning/10 px-3 py-2 text-xs">
      <p className="text-status-ssl-warning">
        {what}
        {c.lineId !== null && (
          <> <Link to={`/mobile/lines/${c.lineId}`} className="underline">{c.msisdn ?? `#${c.lineId}`}</Link></>
        )}
        {c.prefixMatch && <> {t('simPanel.prefixMatch')}</>}
      </p>
      <p className="mt-1 text-text-secondary">
        {t(`devices.sim.todoConflict.${c.kind}`)}
        {c.kind === 'other_tenant' && isAdmin && (
          <> <Link to="/mobile/reconcile" className="text-accent hover:underline">{t('devices.sim.openReconcile')}</Link></>
        )}
      </p>
    </div>
  );
}

/** No line linked: the reason, and the operator's next move. */
function NoLineCard({ view }: { view: DeviceSimView }) {
  const { t } = useTranslation();
  const reason = simNoLineReason(view);
  const cards = cardsRead(view);
  const elsewhere = view.cardLineElsewhere;
  return (
    <Card title={t('devices.sim.noLineTitle')} icon={<Smartphone size={15} />}>
      <div className="space-y-2 text-sm">
        <p className="text-text-primary">{t(`devices.sim.reasonLong.${reason}`)}</p>
        {reason === 'elsewhere' && elsewhere && (
          <p className="text-text-secondary">
            {t('simBlock.linkedElsewhere', { msisdn: elsewhere.msisdn })}{' '}
            <Link to={`/devices/${elsewhere.deviceId}`} className="text-accent hover:underline">
              {elsewhere.deviceName ?? `#${elsewhere.deviceId}`}
            </Link>
            {' · '}
            <Link to={`/mobile/lines/${elsewhere.lineId}`} className="text-accent hover:underline">{t('simBlock.openLine')}</Link>
          </p>
        )}
        <p className="rounded-md border border-accent/20 bg-accent/5 px-3 py-2 text-[13px] text-text-secondary">
          <span className="font-medium text-text-primary">{t('devices.sim.todoLabel')} </span>
          {t(`devices.sim.todo.${reason}`)}
        </p>
        {reason === 'noLine' && cards.length > 0 && (
          <ul className="flex flex-wrap gap-2">
            {cards.map((iccid) => (
              <li key={iccid}>
                <Link
                  to={`/mobile/lines?search=${encodeURIComponent(iccid)}`}
                  className="inline-flex items-center gap-1.5 rounded-full border border-border px-2.5 py-0.5 text-xs text-accent hover:bg-bg-hover"
                >
                  <Search size={12} />
                  {t('devices.sim.searchLine', { iccid })}
                </Link>
              </li>
            ))}
          </ul>
        )}
      </div>
    </Card>
  );
}

/** The card(s) the fleet and the bench read in this router. */
function ModemsCard({ view }: { view: DeviceSimView }) {
  const { t } = useTranslation();
  const bench = view.reading;
  return (
    <Card title={t('devices.sim.modemsTitle')} icon={<Cpu size={15} />}>
      <div className="space-y-3">
        {view.modems.length === 0 ? (
          <p className="text-sm text-text-muted">{t('devices.sim.noModem')}</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-text-muted">
                  <th className="py-1 pr-3 font-medium">{t('simPanel.interface')}</th>
                  <th className="py-1 pr-3 font-medium">ICCID</th>
                  <th className="py-1 pr-3 font-medium">IMSI</th>
                  <th className="py-1 pr-3 font-medium">IMEI</th>
                  <th className="py-1 font-medium">{t('simPanel.readAt')}</th>
                </tr>
              </thead>
              <tbody>
                {view.modems.map((m) => (
                  <tr key={m.interface} className="border-t border-border">
                    <td className="py-1.5 pr-3 font-mono">{m.interface}</td>
                    <td className="py-1.5 pr-3"><Val v={m.iccid} /></td>
                    <td className="py-1.5 pr-3"><Val v={m.imsi} /></td>
                    <td className="py-1.5 pr-3"><Val v={m.imei} /></td>
                    <td className="py-1.5 text-text-muted"><When iso={m.observedAt} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <p className="text-xs text-text-muted">
          {bench === null
            ? t('simBlock.neverRead')
            : bench.iccid === null
              ? <>{t('simBlock.noCard')} (<When iso={bench.readAt} />)</>
              : (
                <>
                  {t('simBlock.iccidRead')}{' '}
                  <span className="font-mono text-text-secondary">{bench.iccid}</span>
                  {bench.imsi && <> · IMSI <span className="font-mono text-text-secondary">{bench.imsi}</span></>}
                  {' '}(<When iso={bench.readAt} />)
                </>
              )}
        </p>

        {view.conflicts.map((c) => <ConflictNote key={`${c.kind}-${c.iccid}-${c.lineId ?? 'x'}`} c={c} />)}
      </div>
    </Card>
  );
}

/** Where the 4G backup watch stands — the uplink card's own reading. */
function BackupCard({ uplink }: { uplink: Loaded<UplinkVerdict> }) {
  const { t, i18n } = useTranslation();
  const signal = uplinkSignal(t, uplink);
  const b = uplink?.backup4g ?? null;
  const quiet = b !== null && !b.cellular && !b.alertedAt && b.transitions.length === 0;
  return (
    <Card
      title={t('uplink.backup4g.title')}
      icon={<ShieldAlert size={15} />}
      aside={(
        <span className={`inline-flex items-center gap-1.5 text-xs ${TONE_TEXT[signal.tone]}`}>
          <ToneDot tone={signal.tone} />
          <span className="opacity-75">{t('devices.page.chips.uplink')}</span>
          {signal.value}
        </span>
      )}
    >
      {uplink === undefined ? (
        <p className="text-sm text-text-muted">…</p>
      ) : uplink === null ? (
        <p className="text-sm text-text-muted">{t('devices.page.uplinkUnreadable')}</p>
      ) : b === null ? (
        <p className="text-sm text-text-muted">{t('devices.sim.backupNotServed')}</p>
      ) : quiet ? (
        <div className="space-y-1 text-xs text-text-muted">
          <p className="text-sm text-text-secondary">{t('devices.sim.backupQuiet')}</p>
          {b.fixedUplinks.length > 0 && <p>{t('uplink.backup4g.fixed', { names: b.fixedUplinks.join(', ') })}</p>}
          <p>
            {b.declaredUplink === 'cellular_only'
              ? t('uplink.backup4g.declaredCellularOnly')
              : b.delayMin <= 0 ? t('uplink.backup4g.off') : t('uplink.backup4g.due', { minutes: b.delayMin })}
          </p>
        </div>
      ) : (
        <Backup4gSection b={b} lang={i18n.language} className="" />
      )}
    </Card>
  );
}

export function DeviceSimTab({
  device,
  sim,
  uplink,
  onReloadSim,
}: {
  device: DeviceDetail;
  sim: SimState;
  uplink: Loaded<UplinkVerdict>;
  onReloadSim: () => void;
}) {
  const { t } = useTranslation();
  const isAdmin = useAuthStore((s) => s.isAdmin)();
  const hasCapability = useAuthStore((s) => s.hasCapability);
  const canApplyChange = isAdmin || hasCapability(CAPABILITIES.CHANGE_APPLY);

  let lines: ReactNode;
  if (sim.status === 'off') {
    lines = (
      <div className="rounded-lg border border-border bg-bg-secondary px-4 py-8 text-center">
        <ShieldAlert size={22} className="mx-auto mb-2 text-text-muted" />
        <p className="text-sm text-text-muted">{t('devices.sim.noCapability')}</p>
      </div>
    );
  } else if (sim.status === 'loading') {
    lines = <div className="flex justify-center py-10"><LoadingSpinner /></div>;
  } else if (sim.status === 'error') {
    lines = (
      <div className="flex flex-wrap items-center gap-3 rounded-lg border border-border bg-bg-secondary p-4 text-sm text-text-muted">
        <AlertTriangle size={16} className="text-status-ssl-warning" />
        {t('simBlock.loadError')}
        <Button size="sm" variant="secondary" onClick={onReloadSim}>
          <RefreshCw size={14} className="mr-1.5" />
          {t('common.refresh')}
        </Button>
      </div>
    );
  } else {
    const { view } = sim;
    lines = (
      <>
        {view.lines.length === 0
          ? <NoLineCard view={view} />
          // This view's lines carry no `access` of their own: a line attached to
          // a router is writable exactly as far as that router is (migration 087).
          : view.lines.map((l) => <SimLineDetail key={l.id} line={l.access ? l : { ...l, access: device.access }} />)}
      </>
    );
  }

  return (
    <div className="space-y-4">
      {lines}
      <div className="grid grid-cols-1 items-start gap-4 lg:grid-cols-2">
        {sim.status === 'ready' && <ModemsCard view={sim.view} />}
        <BackupCard uplink={uplink} />
      </div>
      {/* The LTE APN chosen for this router, applied by an lte_apn job. */}
      {device.brand === 'mikrotik' && device.role !== 'concentrator' && (
        <DeviceApnCard deviceId={device.id} canLaunch={canApplyChange} />
      )}
    </div>
  );
}
