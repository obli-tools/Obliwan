import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { AlertTriangle, CheckCircle2, Circle, ListChecks, Loader2, MinusCircle, XCircle } from 'lucide-react';
import { Button } from '@/components/common/Button';
import { cn } from '@/utils/cn';
import { Hint } from '@/components/ui/Hint';
import {
  LEGACY_FIX_BAD,
  LEGACY_FIX_GOOD,
  legacyComplianceApi,
  type LegacyComplianceStep,
  type LegacyComplianceView,
  type LegacyFixState,
} from './legacyCompliance.api';
import { managementAccessErrorMessage } from './managementAccess.api';

/**
 * The corrected customer templates on a MikroTik in service, on its device
 * page (overview, « Conformité » section):
 * the seven fixes as the last job READ them on the router (never guessed by the
 * page), and the button that applies them — a `legacy_compliance` change job
 * over SSH with the router's existing account (server:
 * services/change/legacyCompliance.service.ts). No dead-man is armed, so the
 * button asks for that confirmation first, as the management access card does.
 * The server's sentences (refusals, outcome, error, per-fix detail) are shown
 * as they are; states and reason codes are translated here.
 */

/** Error codes raised outside the job's own service: their headline is the
 *  management access card's (same machinery, same words). */
const MACHINERY_ERRORS = new Set(['binding_mismatch', 'kill_switch', 'worker_lost', 'guard_refused', 'guard_worsened']);

const GOOD = LEGACY_FIX_GOOD;
const BAD = LEGACY_FIX_BAD;

function StepIcon({ status }: { status: string }) {
  if (status === 'succeeded') return <CheckCircle2 size={13} className="text-status-up" />;
  if (status === 'failed') return <XCircle size={13} className="text-status-down" />;
  if (status === 'skipped') return <MinusCircle size={13} className="text-text-muted" />;
  if (status === 'running') return <Loader2 size={13} className="animate-spin text-accent" />;
  return <Circle size={13} className="text-text-muted" />;
}

function FixIcon({ state }: { state: LegacyFixState }) {
  if (GOOD.has(state)) return <CheckCircle2 size={13} className="text-status-up" />;
  if (BAD.has(state)) return <XCircle size={13} className="text-status-down" />;
  if (state === 'needed' || state === 'refused') return <AlertTriangle size={13} className="text-status-ssl-warning" />;
  if (state === 'skipped') return <MinusCircle size={13} className="text-text-muted" />;
  return <Circle size={13} className="text-text-muted" />;
}

export function LegacyComplianceCard({
  deviceId,
  canLaunch,
  embedded = false,
  onView,
}: {
  deviceId: number;
  canLaunch: boolean;
  /** Drawn inside a device-page section that already carries the frame and
   *  the title: the card then draws neither. */
  embedded?: boolean;
  /** Every view as it loads (`null`: it could not be read). The device page
   *  builds its status chip from it, so the chip never disagrees with the card. */
  onView?: (view: LegacyComplianceView | null) => void;
}) {
  const { t } = useTranslation();
  const [view, setView] = useState<LegacyComplianceView | null>(null);
  const [loadError, setLoadError] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setView(await legacyComplianceApi.get(deviceId));
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
    return (
      <div className={cn('text-sm text-text-muted', !embedded && 'rounded-lg border border-border bg-bg-secondary p-4 lg:col-span-2')}>
        {t('legacyCompliance.loadError')}
      </div>
    );
  }
  if (!view || !view.supported) return null;

  const apply = async () => {
    setBusy(true);
    try {
      const r = await legacyComplianceApi.apply(deviceId);
      toast.success(r.alreadyQueued ? t('legacyCompliance.alreadyQueued', { id: r.jobId }) : t('legacyCompliance.queued', { id: r.jobId }));
      setConfirming(false);
      await load();
    } catch (err) {
      toast.error(managementAccessErrorMessage(err, t('legacyCompliance.applyError')));
      await load();
    } finally {
      setBusy(false);
    }
  };

  const job = view.job;
  // What became of the fixes promised after another job (the bulk attach's,
  // after its management access job). A refusal or a skip is moot once a later
  // job of this kind exists: the operator already relaunched them.
  const followUp = view.followUp ?? null;
  const followUpMissed = followUp !== null && (followUp.state === 'refused' || followUp.state === 'skipped');
  const followUpMoot =
    followUpMissed && job !== null && followUp.doneAt !== null && Date.parse(job.createdAt) > Date.parse(followUp.doneAt);
  const followUpText = followUp === null
    ? null
    : followUp.state === 'pending'
      ? t('legacyCompliance.followUp.pending', { id: followUp.afterJobId })
      : followUp.state === 'queued'
        ? t('legacyCompliance.followUp.queued', { id: followUp.thenJobId ?? '—' })
        : t('legacyCompliance.followUp.notLaunched', { detail: followUp.detail ?? followUp.reason ?? '' });
  const errorHeadline = job?.errorKind
    ? MACHINERY_ERRORS.has(job.errorKind)
      ? t(`managementAccess.error.${job.errorKind}`, { defaultValue: job.errorKind })
      : t(`legacyCompliance.error.${job.errorKind}`, { defaultValue: t('legacyCompliance.error.generic') })
    : null;
  const lan = view.lan;

  return (
    <div className={embedded ? undefined : 'rounded-lg border border-border bg-bg-secondary p-4 lg:col-span-2'}>
      {!embedded && (
        <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold text-text-primary">
          <ListChecks size={15} /> {t('legacyCompliance.title')}
          {active && (
            <span className="ml-auto inline-flex items-center gap-1 text-[12px] font-medium text-accent">
              <Loader2 size={13} className="animate-spin" /> {t('legacyCompliance.inProgress')}
            </span>
          )}
        </h3>
      )}
      <Hint className="mb-3 mt-0">{t('legacyCompliance.intro')}</Hint>

      <p className="mb-2 text-[12px] text-text-muted">
        {view.readAt
          ? t('legacyCompliance.readAt', {
            date: new Date(view.readAt).toLocaleString(),
            by: t(`legacyCompliance.readBy.${view.readBy ?? 'lint'}`),
          })
          : t('legacyCompliance.neverRead')}
      </p>

      <ul className="mb-3 divide-y divide-border rounded-md border border-border">
        {view.fixes.map((f) => (
          <li key={f.key} className="flex flex-wrap items-start gap-2 px-3 py-2 text-[12px]">
            <span className="mt-0.5"><FixIcon state={f.state} /></span>
            <span className="min-w-0 flex-1 text-text-primary">{t(`legacyCompliance.fix.${f.key}`)}</span>
            <span
              className={cn(
                'shrink-0 font-medium',
                GOOD.has(f.state) ? 'text-status-up' : BAD.has(f.state) ? 'text-status-down'
                  : f.state === 'needed' || f.state === 'refused' ? 'text-status-ssl-warning' : 'text-text-muted',
              )}
            >
              {t(`legacyCompliance.state.${f.state}`)}
            </span>
            {f.reason && f.state !== 'unknown' && (
              <span className="w-full pl-5 text-text-muted" title={f.detail ?? undefined}>
                {t(`legacyCompliance.reason.${f.reason}`, { defaultValue: f.detail ?? f.reason })}
                {f.current !== null && f.current !== '' && <span className="ml-1 font-mono">({f.current})</span>}
              </span>
            )}
            {(f.warnings ?? []).length > 0 && f.state !== 'unknown' && (
              <ul className="w-full space-y-0.5 pl-5">
                {(f.warnings ?? []).map((w) => (
                  <li key={w} className="flex items-start gap-1.5 text-status-ssl-warning">
                    <AlertTriangle size={12} className="mt-0.5 shrink-0" />
                    <span>{t(`legacyCompliance.warning.${w}`, { defaultValue: w })}</span>
                  </li>
                ))}
              </ul>
            )}
          </li>
        ))}
      </ul>

      {lan && (
        <p className="mb-3 text-[12px] text-text-secondary">
          <span className="text-text-muted">{t('legacyCompliance.lanRow')} </span>
          {lan.network
            ? <span className="font-mono">{lan.network}{lan.bridge ? ` — ${lan.bridge}` : ''}</span>
            : (
              <span className="text-status-ssl-warning" title={lan.detail}>
                {t('legacyCompliance.lanUnknown', {
                  reason: t(`legacyCompliance.lanReason.${lan.reason ?? 'unread'}`, { defaultValue: lan.detail }),
                })}
              </span>
            )}
        </p>
      )}

      {!view.eligible && !active && view.refusals.length > 0 && (
        <div className="mb-3 rounded-md border border-status-ssl-warning/40 bg-status-ssl-warning/5 p-3">
          <p className="mb-1 flex items-center gap-1.5 text-[12px] font-medium text-status-ssl-warning">
            <AlertTriangle size={13} /> {t('legacyCompliance.refusalsTitle')}
          </p>
          <ul className="space-y-1 text-[12px] text-text-secondary">
            {view.refusals.map((r) => <li key={r.kind}>{r.message}</li>)}
          </ul>
        </div>
      )}

      {job && (
        <div className="mb-3 rounded-md border border-border bg-bg-tertiary p-3">
          <p className="mb-2 flex flex-wrap items-center gap-2 text-[12px] text-text-secondary">
            <span className="font-medium text-text-primary">{t('legacyCompliance.lastJob', { id: job.id })}</span>
            <span>{t(`change.status.label.${job.status}`, { defaultValue: job.status })}</span>
            {job.rolloutId !== null && (
              <span className="text-text-muted">{t('legacyCompliance.inRollout', { id: job.rolloutId })}</span>
            )}
            <span className="ml-auto font-mono text-[11px] text-text-muted">{new Date(job.createdAt).toLocaleString()}</span>
          </p>
          {job.steps.length > 0 && (
            <ol className="space-y-1">
              {job.steps.map((s: LegacyComplianceStep) => (
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
          {job.randomSourcePortSentAt && (
            <p className="mt-2 text-[12px] text-text-muted">
              {job.tunnelReturnedAt
                ? t('legacyCompliance.tunnelBack', {
                  seconds: Math.max(0, Math.round((Date.parse(job.tunnelReturnedAt) - Date.parse(job.randomSourcePortSentAt)) / 1000)),
                })
                : t('legacyCompliance.tunnelNotSeen')}
            </p>
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
                <p className="mt-1 text-text-muted">{t('legacyCompliance.backupKept', { id: job.backupId })}</p>
              )}
            </div>
          )}
        </div>
      )}

      {followUpText !== null && !followUpMoot && (
        <p
          className={cn(
            'mb-2 flex items-start gap-1.5 text-[12px]',
            followUpMissed ? 'text-status-ssl-warning' : 'text-text-muted',
          )}
        >
          {followUpMissed && <AlertTriangle size={13} className="mt-0.5 shrink-0" />}
          <span className="min-w-0 break-words">{followUpText}</span>
        </p>
      )}

      {canLaunch && (
        confirming ? (
          <div className="rounded-md border border-status-ssl-warning/50 bg-status-ssl-warning/5 p-3">
            <p className="mb-2 text-[12px] text-text-secondary">{t('legacyCompliance.confirmText')}</p>
            <div className="flex gap-2">
              <Button size="sm" variant="danger" disabled={busy} loading={busy} onClick={() => void apply()}>
                {t('legacyCompliance.confirm')}
              </Button>
              <Button size="sm" variant="secondary" disabled={busy} onClick={() => setConfirming(false)}>
                {t('common.cancel')}
              </Button>
            </div>
          </div>
        ) : (
          <Button size="sm" variant="secondary" disabled={!view.eligible || active || busy} onClick={() => setConfirming(true)}>
            <ListChecks size={14} className="mr-1.5" />
            {view.readAt ? t('legacyCompliance.reapply') : t('legacyCompliance.apply')}
          </Button>
        )
      )}
    </div>
  );
}
