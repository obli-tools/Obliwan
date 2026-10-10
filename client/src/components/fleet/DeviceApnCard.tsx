import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { AlertTriangle, CheckCircle2, Circle, Loader2, MinusCircle, Signal, XCircle } from 'lucide-react';
import { Button } from '@/components/common/Button';
import { cn } from '@/utils/cn';
import { Hint } from '@/components/ui/Hint';
import { deviceApnApi, deviceApnErrorMessage, type DeviceApnStep, type DeviceApnView } from './deviceApn.api';

/**
 * The LTE APN of a MikroTik, in its device page's « 4G / SIM » tab (beside the
 * card in the modem and the line it carries): the catalogue resolved for THIS
 * device (its applicable template revision), the profile chosen, the one the
 * router was last read on, and the button that applies the choice — an
 * `lte_apn` change job over SSH (server: services/change/lteApn.service.ts).
 * No dead-man is armed, so the button asks for that confirmation first, as
 * the management access card does. The server's sentences (refusals,
 * outcome, error) are French and shown as they are.
 */

/** Error codes raised outside the job's own service: their headline is the
 *  management access card's (same machinery, same words). */
const MACHINERY_ERRORS = new Set(['binding_mismatch', 'kill_switch', 'worker_lost', 'guard_refused', 'guard_worsened']);

function StepIcon({ status }: { status: string }) {
  if (status === 'succeeded') return <CheckCircle2 size={13} className="text-status-up" />;
  if (status === 'failed') return <XCircle size={13} className="text-status-down" />;
  if (status === 'skipped') return <MinusCircle size={13} className="text-text-muted" />;
  if (status === 'running') return <Loader2 size={13} className="animate-spin text-accent" />;
  return <Circle size={13} className="text-text-muted" />;
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-[11px] uppercase tracking-wider text-text-muted">{label}</dt>
      <dd className="mt-0.5 text-[13px] text-text-primary">{children}</dd>
    </div>
  );
}

export function DeviceApnCard({ deviceId, canLaunch }: { deviceId: number; canLaunch: boolean }) {
  const { t } = useTranslation();
  const [view, setView] = useState<DeviceApnView | null>(null);
  const [loadError, setLoadError] = useState(false);
  const [selected, setSelected] = useState('');
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const v = await deviceApnApi.get(deviceId);
      setView(v);
      setLoadError(false);
      // Only ever a name the <select> offers: a stale or unknown one would be
      // drawn as the first option while another is confirmed and sent.
      const offered = (n: string | null | undefined): n is string => !!n && v.catalogue.entries.some((e) => e.name === n);
      setSelected((cur) => [cur, v.chosenProfile, v.catalogue.defaultProfile].find(offered) ?? v.catalogue.entries[0]?.name ?? '');
    } catch {
      setLoadError(true);
    }
  }, [deviceId]);

  useEffect(() => {
    void load();
  }, [load]);

  const active = view?.job?.active ?? false;
  useEffect(() => {
    const id = setInterval(() => void load(), active ? 3000 : 30000);
    return () => clearInterval(id);
  }, [load, active]);

  if (loadError && !view) {
    return (
      <div className="rounded-lg border border-border bg-bg-secondary p-4 text-sm text-text-muted lg:col-span-2">
        {t('deviceApn.loadError')}
      </div>
    );
  }
  if (!view || !view.supported) return null;

  const apply = async () => {
    setBusy(true);
    try {
      const r = await deviceApnApi.apply(deviceId, selected);
      toast.success(r.alreadyQueued ? t('deviceApn.alreadyQueued', { id: r.jobId }) : t('deviceApn.queued', { id: r.jobId }));
      setConfirming(false);
      await load();
    } catch (err) {
      toast.error(deviceApnErrorMessage(err, t('deviceApn.applyError')));
      await load();
    } finally {
      setBusy(false);
    }
  };

  const job = view.job;
  const entries = view.catalogue.entries;
  const label = (name: string | null) => {
    if (!name) return '—';
    const e = entries.find((x) => x.name === name);
    return e ? `${e.name} — ${e.apn}` : name;
  };
  const errorHeadline = job?.errorKind
    ? MACHINERY_ERRORS.has(job.errorKind)
      ? t(`managementAccess.error.${job.errorKind}`, { defaultValue: job.errorKind })
      : t('deviceApn.errorGeneric')
    : null;

  return (
    <div className="rounded-lg border border-border bg-bg-secondary p-4 lg:col-span-2">
      <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold text-text-primary">
        <Signal size={15} /> {t('deviceApn.title')}
        {active && (
          <span className="ml-auto inline-flex items-center gap-1 text-[12px] font-medium text-accent">
            <Loader2 size={13} className="animate-spin" /> {t('deviceApn.inProgress')}
          </span>
        )}
      </h3>
      <Hint className="mb-3 mt-0">{t('deviceApn.intro')}</Hint>

      {!view.catalogue.ok ? (
        <p className="mb-3 text-[12px] text-status-ssl-warning">{view.catalogue.message ?? t('deviceApn.noCatalogue')}</p>
      ) : (
        <dl className="mb-3 grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Row label={t('deviceApn.chosenRow')}>
            {view.chosenProfile
              ? <span className="font-mono">{label(view.chosenProfile)}</span>
              : <span className="text-text-muted">{t('deviceApn.neverChosen')}</span>}
          </Row>
          <Row label={t('deviceApn.observedRow')}>
            {job?.observedApnProfiles
              ? (
                <span className="font-mono">
                  {label(job.observedApnProfiles)}
                  {job.observedAt && (
                    <span className="ml-2 font-sans text-[12px] text-text-muted">{new Date(job.observedAt).toLocaleString()}</span>
                  )}
                </span>
              )
              : <span className="text-text-muted">{t('deviceApn.neverRead')}</span>}
          </Row>
          <Row label={t('deviceApn.defaultRow')}>
            <span className="font-mono">{label(view.catalogue.defaultProfile)}</span>
          </Row>
          {!view.catalogue.feedsRender && (
            <Row label={t('deviceApn.renderRow')}>
              <span className="text-[12px] text-status-ssl-warning">{t('deviceApn.notInRender')}</span>
            </Row>
          )}
        </dl>
      )}

      {!view.eligible && !active && view.refusals.length > 0 && (
        <div className="mb-3 rounded-md border border-status-ssl-warning/40 bg-status-ssl-warning/5 p-3">
          <p className="mb-1 flex items-center gap-1.5 text-[12px] font-medium text-status-ssl-warning">
            <AlertTriangle size={13} /> {t('deviceApn.refusalsTitle')}
          </p>
          <ul className="space-y-1 text-[12px] text-text-secondary">
            {view.refusals.map((r) => <li key={r.kind}>{r.message}</li>)}
          </ul>
        </div>
      )}

      {job && (
        <div className="mb-3 rounded-md border border-border bg-bg-tertiary p-3">
          <p className="mb-2 flex flex-wrap items-center gap-2 text-[12px] text-text-secondary">
            <span className="font-medium text-text-primary">{t('deviceApn.lastJob', { id: job.id, profile: label(job.profile) })}</span>
            <span>{t(`change.status.label.${job.status}`, { defaultValue: job.status })}</span>
            <span className="ml-auto font-mono text-[11px] text-text-muted">{new Date(job.createdAt).toLocaleString()}</span>
          </p>
          {job.steps.length > 0 && (
            <ol className="space-y-1">
              {job.steps.map((s: DeviceApnStep) => (
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
          {job.status === 'failed' && (
            <div className="mt-2 rounded border border-status-down/40 bg-status-down/5 p-2 text-[12px]">
              {errorHeadline && <p className="font-medium text-status-down">{errorHeadline}</p>}
              {job.errorMessage && <p className="mt-0.5 text-text-secondary">{job.errorMessage}</p>}
              {job.wroteAt && job.backupId !== null && (
                <p className="mt-1 text-text-muted">{t('deviceApn.backupKept', { id: job.backupId })}</p>
              )}
            </div>
          )}
        </div>
      )}

      {canLaunch && view.catalogue.ok && (
        <div className="space-y-2">
          <label className="block text-[12px] text-text-secondary">
            {t('deviceApn.selectLabel')}
            <select
              className="mt-1 block w-full rounded-md border border-border bg-bg-primary px-2 py-1.5 font-mono text-[13px] text-text-primary sm:w-96"
              value={selected}
              disabled={active || busy || confirming}
              onChange={(e) => setSelected(e.target.value)}
            >
              {entries.map((e) => (
                <option key={e.name} value={e.name}>{`${e.name} — ${e.apn}`}</option>
              ))}
            </select>
          </label>
          {confirming ? (
            <div className="rounded-md border border-status-ssl-warning/50 bg-status-ssl-warning/5 p-3">
              <p className="mb-2 text-[12px] text-text-secondary">{t('deviceApn.confirmText', { profile: label(selected) })}</p>
              <div className="flex gap-2">
                <Button size="sm" variant="danger" disabled={busy} loading={busy} onClick={() => void apply()}>
                  {t('deviceApn.confirm')}
                </Button>
                <Button size="sm" variant="secondary" disabled={busy} onClick={() => setConfirming(false)}>
                  {t('common.cancel')}
                </Button>
              </div>
            </div>
          ) : (
            <Button
              size="sm"
              variant="secondary"
              disabled={!view.eligible || active || busy || selected === ''}
              onClick={() => setConfirming(true)}
            >
              {t('deviceApn.apply')}
            </Button>
          )}
        </div>
      )}
    </div>
  );
}
