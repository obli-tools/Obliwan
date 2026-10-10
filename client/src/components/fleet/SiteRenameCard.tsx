import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { AlertTriangle, CaseLower, CheckCircle2, Circle, Loader2, MinusCircle, PenLine, RotateCcw, XCircle } from 'lucide-react';
import { isRenameIdentity, isRenameLogin, lowercaseRename, type SiteRenameOutcome } from '@obliwan/shared';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { Hint } from '@/components/ui/Hint';
import { cn } from '@/utils/cn';
import { StatusSection } from '@/components/device/StatusSection';
import { siteRenameApi, siteRenameErrorMessage, type SiteRenameStep, type SiteRenameView } from './siteRename.api';

/**
 * Renaming a site's router, on its device page (overview, « Renommage »
 * section): the PPP login on the shared concentrator, the user of the
 * router's management tunnel, its identity and, when asked, the site code —
 * together, by a `site_rename` change job (server:
 * services/change/siteRename.service.ts). Platform admins only (the job writes
 * on the shared CHR): the server says so in `canLaunch`, the form is drawn
 * only then. No dead-man is armed, so the button asks for that confirmation
 * first. A rename left `unsettled` offers only « Relancer » (the same pair);
 * one that left its old secret on the CHR offers to finish. The server's
 * sentences are shown verbatim; outcomes and step kinds are translated here.
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

const OUTCOME_TONE: Record<SiteRenameOutcome, string> = {
  renamed: 'text-status-up',
  present: 'text-status-up',
  reverted: 'text-status-ssl-warning',
  unsettled: 'text-status-down',
  refused: 'text-text-muted',
  failed: 'text-status-down',
};

/** The one-line summary the device page's section header shows. */
export function siteRenameSummary(t: (k: string, o?: Record<string, unknown>) => string, view: SiteRenameView | null): {
  tone: 'ok' | 'warn' | 'bad' | 'info';
  text: string;
} {
  if (!view) return { tone: 'info', text: '' };
  if (view.job?.active) return { tone: 'info', text: t('siteRename.summary.running', { id: view.job.id }) };
  if (view.unsettled) return { tone: 'bad', text: t('siteRename.summary.unsettled') };
  if (view.oldSecretLeft) return { tone: 'warn', text: t('siteRename.summary.oldSecretLeft') };
  if (view.job?.outcome === 'renamed') return { tone: 'ok', text: t('siteRename.summary.renamed', { login: view.current.login ?? '—' }) };
  return { tone: 'info', text: t('siteRename.summary.idle', { login: view.current.login ?? '—' }) };
}

export function SiteRenameCard({
  deviceId,
  embedded = false,
  onView,
}: {
  deviceId: number;
  embedded?: boolean;
  onView?: (view: SiteRenameView | null) => void;
}) {
  const { t } = useTranslation();
  const [view, setView] = useState<SiteRenameView | null>(null);
  const [loadError, setLoadError] = useState(false);
  const [login, setLogin] = useState('');
  const [identity, setIdentity] = useState('');
  const [siteCode, setSiteCode] = useState('');
  const [touched, setTouched] = useState(false);
  const [confirming, setConfirming] = useState<'rename' | 'relaunch' | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const v = await siteRenameApi.get(deviceId);
      setView(v);
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

  // The form follows the device's current names until the operator types.
  useEffect(() => {
    if (!view || touched) return;
    setLogin(view.current.login ?? '');
    setIdentity(view.current.identity ?? '');
    setSiteCode(view.current.siteCode ?? '');
  }, [view, touched]);

  const active = view?.job?.active ?? false;
  useEffect(() => {
    const id = setInterval(() => void load(), active ? 3000 : 30000);
    return () => clearInterval(id);
  }, [load, active]);

  if (loadError && !view) {
    return (
      <div className={cn('text-sm text-text-muted', !embedded && 'rounded-lg border border-border bg-bg-secondary p-4')}>
        {t('siteRename.loadError')}
      </div>
    );
  }
  if (!view || !view.supported) return null;

  const cur = view.current;
  const changes = (login.trim() !== '' && login.trim() !== cur.login) || (identity.trim() !== '' && identity.trim() !== cur.identity) ||
    (cur.siteCode !== null && siteCode.trim() !== '' && siteCode.trim() !== cur.siteCode);
  const loginOk = login.trim() === '' || isRenameLogin(login.trim());
  const identityOk = identity.trim() === '' || isRenameIdentity(identity.trim());
  const canSubmit = view.canLaunch && view.eligible && !active && !view.unsettled && changes && loginOk && identityOk && !busy;

  const lowercase = () => {
    setTouched(true);
    setLogin(lowercaseRename(cur.login ?? login));
    setIdentity(lowercaseRename(cur.identity ?? identity));
  };

  const submit = async (relaunch: boolean) => {
    setBusy(true);
    try {
      const r = await siteRenameApi.launch(deviceId, relaunch
        ? { relaunch: true }
        : {
          ...(login.trim() !== cur.login ? { login: login.trim() } : {}),
          ...(identity.trim() !== cur.identity ? { identity: identity.trim() } : {}),
          ...(cur.siteCode !== null && siteCode.trim() !== cur.siteCode ? { siteCode: siteCode.trim() } : {}),
        });
      toast.success(r.alreadyQueued ? t('siteRename.alreadyQueued', { id: r.jobId }) : t('siteRename.queued', { id: r.jobId }));
      setConfirming(null);
      setTouched(false);
      await load();
    } catch (err) {
      toast.error(siteRenameErrorMessage(err, t('siteRename.launchError')));
      await load();
    } finally {
      setBusy(false);
    }
  };

  const job = view.job;
  const errorHeadline = job?.errorKind
    ? MACHINERY_ERRORS.has(job.errorKind)
      ? t(`managementAccess.error.${job.errorKind}`, { defaultValue: job.errorKind })
      : t(`siteRename.error.${job.errorKind}`, { defaultValue: t('siteRename.error.generic') })
    : null;
  const pair = (from: string | null, to: string | null) => (from === to ? from ?? '—' : `${from ?? '—'} → ${to ?? '—'}`);

  return (
    <div className={embedded ? undefined : 'rounded-lg border border-border bg-bg-secondary p-4'}>
      {!embedded && (
        <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold text-text-primary">
          <PenLine size={15} /> {t('siteRename.title')}
          {active && (
            <span className="ml-auto inline-flex items-center gap-1 text-[12px] font-medium text-accent">
              <Loader2 size={13} className="animate-spin" /> {t('siteRename.inProgress')}
            </span>
          )}
        </h3>
      )}
      <Hint className="mb-3 mt-0">{t('siteRename.intro')}</Hint>

      <dl className="mb-3 grid grid-cols-[auto,1fr] gap-x-4 gap-y-1 text-[12px]">
        <dt className="text-text-muted">{t('siteRename.current.login')}</dt>
        <dd className="break-all font-mono text-text-primary">{cur.login ?? '—'}</dd>
        <dt className="text-text-muted">{t('siteRename.current.identity')}</dt>
        <dd className="break-all font-mono text-text-primary">{cur.identity ?? '—'}</dd>
        <dt className="text-text-muted">{t('siteRename.current.siteCode')}</dt>
        <dd className="break-all font-mono text-text-primary">{cur.siteCode ?? '—'}</dd>
      </dl>

      {view.unsettled && (
        <div className="mb-3 rounded-md border border-status-down/40 bg-status-down/5 p-3 text-[12px]">
          <p className="mb-1 flex items-center gap-1.5 font-medium text-status-down">
            <AlertTriangle size={13} /> {t('siteRename.unsettledTitle')}
          </p>
          <p className="text-text-secondary">{t('siteRename.unsettledHint')}</p>
        </div>
      )}
      {view.oldSecretLeft && !view.unsettled && (
        <p className="mb-3 flex items-start gap-1.5 text-[12px] text-status-ssl-warning">
          <AlertTriangle size={13} className="mt-0.5 shrink-0" /> {t('siteRename.oldSecretLeft')}
        </p>
      )}

      {!view.eligible && !active && view.refusals.length > 0 && (
        <div className="mb-3 rounded-md border border-status-ssl-warning/40 bg-status-ssl-warning/5 p-3">
          <p className="mb-1 flex items-center gap-1.5 text-[12px] font-medium text-status-ssl-warning">
            <AlertTriangle size={13} /> {t('siteRename.refusalsTitle')}
          </p>
          <ul className="space-y-1 text-[12px] text-text-secondary">
            {view.refusals.map((r) => <li key={r.kind}>{r.message}</li>)}
          </ul>
        </div>
      )}

      {job && (
        <div className="mb-3 rounded-md border border-border bg-bg-tertiary p-3">
          <p className="mb-2 flex flex-wrap items-center gap-2 text-[12px] text-text-secondary">
            <span className="font-medium text-text-primary">{t('siteRename.lastJob', { id: job.id })}</span>
            <span>{t(`change.status.label.${job.status}`, { defaultValue: job.status })}</span>
            {job.outcome && (
              <span className={cn('font-medium', OUTCOME_TONE[job.outcome])}>{t(`siteRename.state.${job.outcome}`)}</span>
            )}
            {job.chrMode && <span className="text-text-muted">{t(`siteRename.chrMode.${job.chrMode}`)}</span>}
            <span className="ml-auto font-mono text-[11px] text-text-muted">{new Date(job.createdAt).toLocaleString()}</span>
          </p>
          <ul className="mb-2 space-y-0.5 font-mono text-[11px] text-text-secondary">
            <li>{t('siteRename.current.login')} : {pair(job.from.login, job.to.login)}</li>
            <li>{t('siteRename.current.identity')} : {pair(job.from.identity, job.to.identity)}</li>
            {job.from.siteCode !== job.to.siteCode && <li>{t('siteRename.current.siteCode')} : {pair(job.from.siteCode, job.to.siteCode)}</li>}
          </ul>
          {job.steps.length > 0 && (
            <ol className="space-y-1">
              {job.steps.map((s: SiteRenameStep) => (
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
              {job.backupId !== null && <p className="mt-1 text-text-muted">{t('siteRename.backupKept', { id: job.backupId })}</p>}
            </div>
          )}
        </div>
      )}

      {view.canLaunch && (view.unsettled || view.oldSecretLeft) && !active && (
        confirming === 'relaunch' ? (
          <div className="rounded-md border border-status-ssl-warning/50 bg-status-ssl-warning/5 p-3">
            <p className="mb-2 text-[12px] text-text-secondary">{t('siteRename.confirmText')}</p>
            <div className="flex gap-2">
              <Button size="sm" variant="danger" disabled={busy} loading={busy} onClick={() => void submit(true)}>
                {t('siteRename.confirm')}
              </Button>
              <Button size="sm" variant="secondary" disabled={busy} onClick={() => setConfirming(null)}>{t('common.cancel')}</Button>
            </div>
          </div>
        ) : (
          <Button size="sm" variant="secondary" disabled={busy} onClick={() => setConfirming('relaunch')}>
            <RotateCcw size={14} className="mr-1.5" /> {t('siteRename.relaunch')}
          </Button>
        )
      )}

      {view.canLaunch && !view.unsettled && (
        <div className="space-y-2">
          <div className="grid grid-cols-1 gap-2 md:grid-cols-3">
            <Input
              label={t('siteRename.form.login')}
              value={login}
              onChange={(e) => { setTouched(true); setLogin(e.target.value); }}
              disabled={active || busy}
              className={cn(!loginOk && 'border-status-down')}
            />
            <Input
              label={t('siteRename.form.identity')}
              value={identity}
              onChange={(e) => { setTouched(true); setIdentity(e.target.value); }}
              disabled={active || busy}
              className={cn(!identityOk && 'border-status-down')}
            />
            <Input
              label={t('siteRename.form.siteCode')}
              value={siteCode}
              onChange={(e) => { setTouched(true); setSiteCode(e.target.value); }}
              disabled={active || busy || cur.siteCode === null}
            />
          </div>
          {(!loginOk || !identityOk) && <p className="text-[12px] text-status-down">{t('siteRename.form.alphabet')}</p>}
          {confirming === 'rename' ? (
            <div className="rounded-md border border-status-ssl-warning/50 bg-status-ssl-warning/5 p-3">
              <p className="mb-2 text-[12px] text-text-secondary">{t('siteRename.confirmText')}</p>
              <div className="flex gap-2">
                <Button size="sm" variant="danger" disabled={!canSubmit} loading={busy} onClick={() => void submit(false)}>
                  {t('siteRename.confirm')}
                </Button>
                <Button size="sm" variant="secondary" disabled={busy} onClick={() => setConfirming(null)}>{t('common.cancel')}</Button>
              </div>
            </div>
          ) : (
            <div className="flex flex-wrap gap-2">
              <Button size="sm" variant="ghost" disabled={active || busy} onClick={lowercase}>
                <CaseLower size={14} className="mr-1.5" /> {t('siteRename.form.lowercase')}
              </Button>
              <Button size="sm" variant="secondary" disabled={!canSubmit} onClick={() => setConfirming('rename')}>
                <PenLine size={14} className="mr-1.5" /> {t('siteRename.launch')}
              </Button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * The card inside its device-page section, with the section's tone and
 * one-line summary built from the card's own view — so DeviceOverview mounts
 * one element and the header never disagrees with the card. Hidden (but kept
 * mounted) on a device the job does not rename.
 */
export function SiteRenameSection({ deviceId }: { deviceId: number }) {
  const { t } = useTranslation();
  const [view, setView] = useState<SiteRenameView | null>(null);
  const [failed, setFailed] = useState(false);
  const onView = useCallback((v: SiteRenameView | null) => {
    setView(v);
    setFailed(v === null);
  }, []);
  const summary = siteRenameSummary(t, view);
  return (
    <StatusSection
      title={t('siteRename.title')}
      icon={<PenLine size={15} />}
      tone={failed ? 'unknown' : view === null ? 'loading' : summary.tone}
      summary={failed ? t('siteRename.loadError') : summary.text}
      hidden={view !== null && !view.supported}
    >
      <SiteRenameCard deviceId={deviceId} embedded onView={onView} />
    </StatusSection>
  );
}
