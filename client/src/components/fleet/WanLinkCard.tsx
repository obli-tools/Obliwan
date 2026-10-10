import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { AlertTriangle, CheckCircle2, Circle, Globe, Loader2, MinusCircle, XCircle } from 'lucide-react';
import type { Wan1Mode } from '@obliwan/shared';
import { Button } from '@/components/common/Button';
import { Hint } from '@/components/ui/Hint';
import { cn } from '@/utils/cn';
import { managementAccessErrorMessage } from './managementAccess.api';
import { wanLinkApi, wanLinkHoldUntil, type WanLinkRequestBody, type WanLinkStep, type WanLinkView } from './wanLink.api';

/**
 * « Lien WAN » on a MikroTik in service, on its device page: the WAN1 mode
 * the site declares, what the router showed at the last read (mode, 4G
 * signal, warnings), the last `wan_link` job, and the dialog that queues one
 * (server: services/change/wanLink.service.ts). The switch cuts the fixed line
 * on purpose: the dialog says until when the down and 4G alerts are held and
 * asks for that confirmation. The server's sentences are shown as they are;
 * modes, warnings and verdicts are translated here.
 */

const MACHINERY_ERRORS = new Set(['binding_mismatch', 'kill_switch', 'worker_lost', 'guard_refused', 'guard_worsened']);

function StepIcon({ status }: { status: string }) {
  if (status === 'succeeded') return <CheckCircle2 size={13} className="text-status-up" />;
  if (status === 'failed') return <XCircle size={13} className="text-status-down" />;
  if (status === 'skipped') return <MinusCircle size={13} className="text-text-muted" />;
  if (status === 'running') return <Loader2 size={13} className="animate-spin text-accent" />;
  return <Circle size={13} className="text-text-muted" />;
}

const inputClass =
  'mt-1 block w-full rounded-md border border-border bg-bg-primary px-2 py-1.5 font-mono text-[13px] text-text-primary sm:w-80';

export function WanLinkCard({
  deviceId,
  canLaunch,
  embedded = false,
  onView,
  onOpenCompliance,
}: {
  deviceId: number;
  /** CHANGE_APPLY and SITE_VARIABLES_WRITE: the job writes the site's variables. */
  canLaunch: boolean;
  embedded?: boolean;
  /** Every view as it loads (`null`: unreadable): the page's status chip. */
  onView?: (view: WanLinkView | null) => void;
  /** Bring the template-fixes section (DNS-Amp) into view. */
  onOpenCompliance?: () => void;
}) {
  const { t } = useTranslation();
  const [view, setView] = useState<WanLinkView | null>(null);
  const [loadError, setLoadError] = useState(false);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [toMode, setToMode] = useState<Wan1Mode>('pppoe');
  const [pppoeName, setPppoeName] = useState('FTTH');
  const [pppoeUser, setPppoeUser] = useState('');
  const [pppoePassword, setPppoePassword] = useState('');
  const [keepVault, setKeepVault] = useState(false);
  const [address, setAddress] = useState('');
  const [gateway, setGateway] = useState('');
  const [minutes, setMinutes] = useState(5);
  const [confirmed, setConfirmed] = useState(false);

  const load = useCallback(async () => {
    try {
      setView(await wanLinkApi.get(deviceId));
      setLoadError(false);
    } catch {
      setLoadError(true);
    }
  }, [deviceId]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (view) onView?.(view);
    else if (loadError) onView?.(null);
  }, [view, loadError, onView]);

  const active = view?.job?.active ?? false;
  useEffect(() => {
    const id = setInterval(() => void load(), active ? 3000 : 30000);
    return () => clearInterval(id);
  }, [load, active]);

  if (loadError && !view) {
    return <div className={cn('text-sm text-text-muted', !embedded && 'rounded-lg border border-border bg-bg-secondary p-4')}>{t('wanLink.loadError')}</div>;
  }
  if (!view || !view.supported) return null;

  const d = view.declared;
  const c = view.constants;
  const modeLabel = (m: Wan1Mode | null) => (m ? t(`wanLink.mode.${m}`) : t('wanLink.mode.unknown'));

  const openDialog = () => {
    // The first mode that is not the declared one; the site's own values as
    // the starting point (never a guess: empty when the site has none).
    const next = (c.modes as Wan1Mode[]).find((m) => m !== d.mode) ?? 'pppoe';
    setToMode(next);
    setPppoeName(d.pppoeName ?? 'FTTH');
    setPppoeUser(d.pppoeUsername ?? '');
    setPppoePassword('');
    setKeepVault(d.passwordSet);
    setAddress(d.mode === 'static' ? '' : d.address ?? '');
    setGateway(d.mode === 'static' ? '' : d.gateway ?? '');
    setMinutes(Math.round(c.revertAfterS / 60));
    setConfirmed(false);
    setOpen(true);
  };

  const revertAfterS = Math.min(c.revertMaxS, Math.max(c.revertMinS, Math.round(minutes * 60)));
  const holdUntil = wanLinkHoldUntil(view, revertAfterS);
  const formOk =
    toMode === 'dhcp' ||
    (toMode === 'pppoe' && pppoeUser.trim() !== '' && (keepVault || pppoePassword !== '')) ||
    (toMode === 'static' && address.trim() !== '' && gateway.trim() !== '');

  const launch = async () => {
    setBusy(true);
    try {
      const body: WanLinkRequestBody = { toMode, revertAfterS };
      if (toMode === 'pppoe') {
        body.pppoe = { name: pppoeName, username: pppoeUser.trim(), ...(keepVault ? {} : { password: pppoePassword }) };
      }
      if (toMode === 'static') body.static = { address: address.trim(), gateway: gateway.trim() };
      const r = await wanLinkApi.enqueue(deviceId, body);
      toast.success(r.alreadyQueued ? t('wanLink.alreadyQueued', { id: r.jobId }) : t('wanLink.queued', { id: r.jobId }));
      setOpen(false);
      setPppoePassword('');
      await load();
    } catch (err) {
      toast.error(managementAccessErrorMessage(err, t('wanLink.launchError')));
      await load();
    } finally {
      setBusy(false);
    }
  };

  const job = view.job;
  const errorHeadline = job?.errorKind
    ? MACHINERY_ERRORS.has(job.errorKind)
      ? t(`managementAccess.error.${job.errorKind}`, { defaultValue: job.errorKind })
      : t(`wanLink.error.${job.errorKind}`, { defaultValue: t('wanLink.error.generic') })
    : null;
  const o = view.observed;
  const lteTone = o?.lte?.state === 'ready' ? 'text-status-up' : o?.lte?.state === 'not_ready' ? 'text-status-down' : 'text-text-muted';

  const declaredParams =
    d.mode === 'pppoe'
      ? `${d.pppoeName ?? '—'} · ${d.pppoeUsername ?? '—'} · ${d.passwordSet ? t('wanLink.password.set') : t('wanLink.password.unset')}`
      : d.mode === 'static'
        ? `${d.address ?? '—'} → ${d.gateway ?? '—'}`
        : '';
  const observedParams =
    o?.mode === 'pppoe'
      ? `${o.params.pppoeName ?? '—'} · ${o.params.pppoeUser ?? '—'}`
      : o?.mode === 'static'
        ? `${o.params.address ?? '—'} → ${o.params.gateway ?? '—'}`
        : '';

  return (
    <div className={embedded ? undefined : 'rounded-lg border border-border bg-bg-secondary p-4'}>
      {!embedded && (
        <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold text-text-primary">
          <Globe size={15} /> {t('wanLink.title')}
        </h3>
      )}
      <Hint className="mb-3 mt-0">{t('wanLink.intro')}</Hint>

      <dl className="mb-3 grid grid-cols-1 gap-x-4 gap-y-1 text-[12px] sm:grid-cols-[10rem_1fr]">
        <dt className="text-text-muted">{t('wanLink.declared')}</dt>
        <dd className="text-text-primary">
          {d.ok ? (
            <>
              <span className="font-medium">{modeLabel(d.mode)}</span>
              {declaredParams && <span className="ml-2 font-mono text-text-secondary">{declaredParams}</span>}
              {d.modeSource === 'default' && <span className="ml-2 text-text-muted">{t('wanLink.declaredDefault')}</span>}
            </>
          ) : (
            <span className="text-status-ssl-warning">{d.message ?? t('wanLink.notDeclared')}</span>
          )}
        </dd>
        <dt className="text-text-muted">{t('wanLink.observed')}</dt>
        <dd className="text-text-primary">
          {o ? (
            <>
              <span className="font-medium">{o.mode ? modeLabel(o.mode) : t('wanLink.mode.nonStandard')}</span>
              {observedParams && <span className="ml-2 font-mono text-text-secondary">{observedParams}</span>}
              <span className="ml-2 text-text-muted">
                {t('wanLink.readAt', { date: new Date(o.readAt).toLocaleString(), by: t(`wanLink.readBy.${o.readBy}`) })}
              </span>
              {o.mode === null && o.reasons.length > 0 && (
                <span className="block font-mono text-[11px] text-text-muted">{o.reasons.join(', ')}</span>
              )}
            </>
          ) : (
            <span className="text-text-muted">{t('wanLink.neverRead')}</span>
          )}
        </dd>
        {o?.lte && (
          <>
            <dt className="text-text-muted">{t('wanLink.lte.title')}</dt>
            <dd className={lteTone}>
              {t(`wanLink.lte.${o.lte.state === 'not_ready' ? 'notReady' : o.lte.state}`)}
              <span className="ml-2 font-mono text-text-secondary">
                {t('wanLink.lte.signal', {
                  rsrp: o.lte.rsrp ?? '—', sinr: o.lte.sinr ?? '—', minRsrp: c.minRsrpDbm, minSinr: c.minSinrDb,
                })}
              </span>
            </dd>
          </>
        )}
        {o?.takeover && o.takeover.state !== 'via_lte' && (
          <>
            <dt className="text-text-muted">{t('wanLink.takeover')}</dt>
            <dd className="break-words text-status-ssl-warning">{o.takeover.summary}</dd>
          </>
        )}
      </dl>

      {o && o.warnings.length > 0 && (
        <div className="mb-3 rounded-md border border-status-ssl-warning/40 bg-status-ssl-warning/5 p-3">
          <p className="mb-1 flex items-center gap-1.5 text-[12px] font-medium text-status-ssl-warning">
            <AlertTriangle size={13} /> {t('wanLink.warnings.title')}
          </p>
          <ul className="space-y-1 text-[12px] text-text-secondary">
            {o.warnings.map((w) => (
              <li key={w}>
                {t(`wanLink.warnings.${w}`, { defaultValue: w })}
                {w === 'dns_open_on_wan' && onOpenCompliance && (
                  <button type="button" className="ml-2 text-accent underline" onClick={onOpenCompliance}>
                    {t('wanLink.warnings.openCompliance')}
                  </button>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      {!view.eligible && !active && view.refusals.length > 0 && (
        <div className="mb-3 rounded-md border border-status-ssl-warning/40 bg-status-ssl-warning/5 p-3">
          <p className="mb-1 flex items-center gap-1.5 text-[12px] font-medium text-status-ssl-warning">
            <AlertTriangle size={13} /> {t('wanLink.refusalsTitle')}
          </p>
          <ul className="space-y-1 text-[12px] text-text-secondary">
            {view.refusals.map((r) => <li key={r.kind}>{r.message}</li>)}
          </ul>
        </div>
      )}

      {job && (
        <div className="mb-3 rounded-md border border-border bg-bg-tertiary p-3">
          <p className="mb-2 flex flex-wrap items-center gap-2 text-[12px] text-text-secondary">
            <span className="font-medium text-text-primary">
              {t('wanLink.lastJob', { id: job.id, from: modeLabel(job.from), to: modeLabel(job.to) })}
            </span>
            <span>{t(`change.status.label.${job.status}`, { defaultValue: job.status })}</span>
            {job.outcome && <span className="font-medium">{t(`wanLink.outcome.${job.outcome}`)}</span>}
            {job.rolloutId !== null && <span className="text-text-muted">{t('wanLink.inRollout', { id: job.rolloutId })}</span>}
            <span className="ml-auto font-mono text-[11px] text-text-muted">{new Date(job.createdAt).toLocaleString()}</span>
          </p>
          {job.active && job.cutExpectedUntil && (
            <p className="mb-2 flex items-center gap-1.5 text-[12px] text-accent">
              <Loader2 size={13} className="animate-spin" />
              {t('wanLink.cutUntil', { time: new Date(job.cutExpectedUntil).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) })}
            </p>
          )}
          {job.steps.length > 0 && (
            <ol className="space-y-1">
              {job.steps.map((s: WanLinkStep) => (
                <li key={`${s.seq}-${s.kind}`} className="flex items-start gap-2 text-[12px]">
                  <span className="mt-0.5"><StepIcon status={s.status} /></span>
                  <span className="w-32 shrink-0 text-text-secondary">{t(`change.step.${s.kind}`, { defaultValue: s.kind })}</span>
                  <span className={cn('min-w-0 break-words', s.status === 'failed' ? 'text-status-down' : 'text-text-muted')}>
                    {s.status === 'failed' ? s.error : s.output}
                  </span>
                </li>
              ))}
            </ol>
          )}
          {job.outcomeDetail && job.status === 'succeeded' && (
            <p className="mt-2 flex items-start gap-1.5 text-[12px] text-status-up">
              <CheckCircle2 size={13} className="mt-0.5 shrink-0" /> {job.outcomeDetail}
            </p>
          )}
          {job.status === 'succeeded' && job.outcome === 'applied' && (
            <p className="mt-1 text-[12px] text-text-muted">{t('wanLink.leftoverNote')}</p>
          )}
          {job.status === 'failed' && (
            <div className="mt-2 rounded border border-status-down/40 bg-status-down/5 p-2 text-[12px]">
              {errorHeadline && <p className="font-medium text-status-down">{errorHeadline}</p>}
              {job.errorMessage && <p className="mt-0.5 text-text-secondary">{job.errorMessage}</p>}
              {job.wroteAt && job.backupId !== null && <p className="mt-1 text-text-muted">{t('wanLink.backupKept', { id: job.backupId })}</p>}
            </div>
          )}
        </div>
      )}

      {canLaunch && !open && (
        <Button size="sm" variant="secondary" disabled={!view.eligible || active || busy} onClick={openDialog}>
          <Globe size={14} className="mr-1.5" /> {t('wanLink.button')}
        </Button>
      )}

      {canLaunch && open && (
        <div className="space-y-3 rounded-md border border-border bg-bg-primary p-3">
          <p className="text-[13px] font-medium text-text-primary">{t('wanLink.dialog.title')}</p>
          <fieldset className="flex flex-wrap gap-4 text-[12px] text-text-secondary">
            <legend className="mb-1 text-text-muted">{t('wanLink.dialog.target')}</legend>
            {(c.modes as Wan1Mode[]).map((m) => (
              <label key={m} className="inline-flex items-center gap-1.5">
                <input type="radio" name={`wan-mode-${deviceId}`} checked={toMode === m} onChange={() => setToMode(m)} disabled={busy} />
                {modeLabel(m)}
              </label>
            ))}
          </fieldset>

          {toMode === 'pppoe' && (
            <div className="space-y-2">
              <label className="block text-[12px] text-text-secondary">
                {t('wanLink.dialog.pppoeName')}
                <select className={inputClass} value={pppoeName} onChange={(e) => setPppoeName(e.target.value)} disabled={busy}>
                  {c.pppoeNames.map((n) => <option key={n} value={n}>{n}</option>)}
                </select>
              </label>
              <label className="block text-[12px] text-text-secondary">
                {t('wanLink.dialog.pppoeUsername')}
                <input className={inputClass} value={pppoeUser} onChange={(e) => setPppoeUser(e.target.value)} autoComplete="off" disabled={busy} />
              </label>
              {d.passwordSet && (
                <label className="inline-flex items-center gap-1.5 text-[12px] text-text-secondary">
                  <input type="checkbox" checked={keepVault} onChange={(e) => setKeepVault(e.target.checked)} disabled={busy} />
                  {t('wanLink.dialog.pppoePasswordKeep')}
                </label>
              )}
              {!keepVault && (
                <label className="block text-[12px] text-text-secondary">
                  {t('wanLink.dialog.pppoePassword')}
                  <input
                    className={inputClass}
                    type="password"
                    value={pppoePassword}
                    onChange={(e) => setPppoePassword(e.target.value)}
                    autoComplete="new-password"
                    disabled={busy}
                  />
                </label>
              )}
            </div>
          )}

          {toMode === 'static' && (
            <div className="space-y-2">
              <label className="block text-[12px] text-text-secondary">
                {t('wanLink.dialog.staticAddress')}
                <input className={inputClass} value={address} placeholder="192.0.2.10/29" onChange={(e) => setAddress(e.target.value)} disabled={busy} />
              </label>
              <label className="block text-[12px] text-text-secondary">
                {t('wanLink.dialog.staticGateway')}
                <input className={inputClass} value={gateway} placeholder="192.0.2.9" onChange={(e) => setGateway(e.target.value)} disabled={busy} />
              </label>
            </div>
          )}

          <label className="block text-[12px] text-text-secondary">
            {t('wanLink.dialog.revertAfter', { min: c.revertMinS / 60, max: c.revertMaxS / 60 })}
            <input
              className={cn(inputClass, 'sm:w-24')}
              type="number"
              min={c.revertMinS / 60}
              max={c.revertMaxS / 60}
              value={minutes}
              onChange={(e) => setMinutes(Number(e.target.value))}
              disabled={busy}
            />
          </label>

          <div className="rounded-md border border-status-ssl-warning/50 bg-status-ssl-warning/5 p-3">
            <p className="mb-2 text-[12px] text-text-secondary">
              {t('wanLink.dialog.confirm', {
                to: modeLabel(toMode),
                time: holdUntil.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
                minutes: Math.round(revertAfterS / 60),
              })}
            </p>
            <label className="inline-flex items-center gap-1.5 text-[12px] font-medium text-text-primary">
              <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} disabled={busy} />
              {t('wanLink.dialog.confirmCheck')}
            </label>
          </div>

          <div className="flex gap-2">
            <Button size="sm" variant="danger" disabled={busy || !confirmed || !formOk} loading={busy} onClick={() => void launch()}>
              {t('wanLink.dialog.launch')}
            </Button>
            <Button size="sm" variant="secondary" disabled={busy} onClick={() => { setOpen(false); setPppoePassword(''); }}>
              {t('wanLink.dialog.cancel')}
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
