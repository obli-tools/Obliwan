import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { OBLIWAN_ACCOUNT } from '@obliwan/shared';
import { AlertTriangle, CheckCircle2, Circle, KeyRound, Loader2, MinusCircle, UserCheck, XCircle } from 'lucide-react';
import { Button } from '@/components/common/Button';
import { cn } from '@/utils/cn';
import { Hint } from '@/components/ui/Hint';
import {
  managementAccessApi,
  managementAccessErrorMessage,
  type ManagementAccessStep,
  type ManagementAccessView,
} from './managementAccess.api';

/**
 * The management API of a MikroTik in service, on its device page: is api-ssl
 * open on the router (as the last job READ it), does ObliWAN hold a TLS API
 * channel with a pinned certificate, and the button that opens it — a
 * `management_access` change job over SSH (server:
 * services/change/managementAccess.service.ts). The job arms no dead-man, so
 * the button asks for that confirmation first. The sentences the server sends
 * (refusals, outcome, error) are French and shown as they are; failures that
 * come from the shared change machinery get a French headline here, by code.
 *
 * It also shows WHICH ACCOUNT ObliWAN logs in with (operator decision
 * 2026-10-04: its own `obliwan`, which the job creates on a router that lacks
 * it and switches to once a login with it is proven), and what the last job
 * did about that account: created, already present, already in use, or
 * refused — with the server's reason — and, when the job's API login carried
 * its password to a certificate that was not the expected one, that the
 * password is held disclosed and the account must be removed.
 */

function AccountIcon({ action }: { action: string | null }) {
  if (action === 'refused') return <XCircle size={13} className="text-status-down" />;
  if (action === 'created' || action === 'present' || action === 'in_use') return <UserCheck size={13} className="text-status-up" />;
  return <Circle size={13} className="text-text-muted" />;
}

/** Error codes raised outside the job's own service, whose server sentence
 *  is not French: they get a translated headline. */
const MACHINERY_ERRORS = new Set(['binding_mismatch', 'kill_switch', 'worker_lost', 'guard_refused', 'guard_worsened']);

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-[11px] uppercase tracking-wider text-text-muted">{label}</dt>
      <dd className="mt-0.5 text-[13px] text-text-primary">{children}</dd>
    </div>
  );
}

function StepIcon({ status }: { status: string }) {
  if (status === 'succeeded') return <CheckCircle2 size={13} className="text-status-up" />;
  if (status === 'failed') return <XCircle size={13} className="text-status-down" />;
  if (status === 'skipped') return <MinusCircle size={13} className="text-text-muted" />;
  if (status === 'running') return <Loader2 size={13} className="animate-spin text-accent" />;
  return <Circle size={13} className="text-text-muted" />;
}

function shortFingerprint(fp: string | null): string {
  return fp ? `${fp.slice(0, 16)}…` : '—';
}

export function ManagementAccessCard({
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
  onView?: (view: ManagementAccessView | null) => void;
}) {
  const { t } = useTranslation();
  const [view, setView] = useState<ManagementAccessView | null>(null);
  const [loadError, setLoadError] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setView(await managementAccessApi.get(deviceId));
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
        {t('managementAccess.loadError', { defaultValue: 'The management access state could not be read.' })}
      </div>
    );
  }
  if (!view) return null;

  const open = async () => {
    setBusy(true);
    try {
      const r = await managementAccessApi.open(deviceId);
      toast.success(
        r.alreadyQueued
          ? t('managementAccess.alreadyQueued', { id: r.jobId, defaultValue: 'Job #{{id}} is already running' })
          : t('managementAccess.queued', { id: r.jobId, defaultValue: 'Job #{{id}} queued' }),
      );
      setConfirming(false);
      await load();
    } catch (err) {
      toast.error(managementAccessErrorMessage(err, t('managementAccess.openError', { defaultValue: 'The job could not be queued.' })));
      await load();
    } finally {
      setBusy(false);
    }
  };

  const job = view.job;
  const stateTone =
    view.state === 'enabled' ? 'text-status-up'
      : view.state === 'failed' ? 'text-status-down'
        : view.state === 'in_progress' ? 'text-accent'
          : 'text-text-secondary';

  const apiSslText =
    view.apiSsl.state === 'conformant'
      ? t('managementAccess.apiSslConformant', {
        date: view.apiSsl.readAt ? new Date(view.apiSsl.readAt).toLocaleString() : '—',
        defaultValue: 'enabled on 8729, management range only, obliwan-api (read {{date}})',
      })
      : view.apiSsl.state === 'different'
        ? t('managementAccess.apiSslDifferent', {
          fields: view.apiSsl.differences.map((d) => d.field).join(', '),
          defaultValue: 'not as expected ({{fields}})',
        })
        : t('managementAccess.apiSslUnknown', { defaultValue: 'never read by ObliWAN' });
  const apiSslLine = view.apiSsl.source === 'automatic' && view.apiSsl.state !== 'unknown'
    ? `${apiSslText} · ${t('managementAccess.readAutomatically')}`
    : apiSslText;

  const api = view.api;
  const apiText = !api
    ? t('managementAccess.apiNone', { defaultValue: 'none' })
    : `${api.tls ? 'TLS' : t('managementAccess.plain', { defaultValue: 'cleartext' })} ${api.host ?? '—'}:${api.port ?? '—'}` +
      (api.enabled ? '' : ` (${t('managementAccess.disabled', { defaultValue: 'disabled' })})`);

  // Which account ObliWAN logs in with: the SSH channel's (the job's own, and
  // the one a switch moves), the API's named apart when the two differ.
  const sshUser = view.ssh?.username ?? null;
  const apiUser = api?.username ?? null;
  const usesObliwan = sshUser === OBLIWAN_ACCOUNT && (apiUser === null || apiUser === OBLIWAN_ACCOUNT);
  const accountUsers = sshUser && apiUser && apiUser !== sshUser
    ? t('managementAccess.accountSplit', { ssh: sshUser, api: apiUser, defaultValue: 'SSH: {{ssh}} · API: {{api}}' })
    : (sshUser ?? apiUser);
  const jobAccount = job?.account ?? null;

  const errorHeadline = job?.errorKind
    ? MACHINERY_ERRORS.has(job.errorKind)
      ? t(`managementAccess.error.${job.errorKind}`, { defaultValue: job.errorKind })
      : t('managementAccess.error.generic', { defaultValue: 'The job stopped.' })
    : null;

  const buttonLabel = view.state === 'enabled'
    ? t('managementAccess.recheck', { defaultValue: 'Check and re-apply the management access (API-SSL)' })
    : t('managementAccess.open', { defaultValue: 'Open the management access (API-SSL)' });

  return (
    <div className={embedded ? undefined : 'rounded-lg border border-border bg-bg-secondary p-4 lg:col-span-2'}>
      {!embedded && (
        <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold text-text-primary">
          <KeyRound size={15} /> {t('managementAccess.title', { defaultValue: 'Management access (API-SSL)' })}
          <span className={cn('ml-auto inline-flex items-center gap-1 text-[12px] font-medium', stateTone)}>
            {view.state === 'in_progress' && <Loader2 size={13} className="animate-spin" />}
            {t(`managementAccess.state.${view.state}`, { defaultValue: view.state })}
          </span>
        </h3>
      )}
      <Hint className="mb-3 mt-0">
        {t('managementAccess.intro', {
          defaultValue:
            'ObliWAN manages this router through its RouterOS API over TLS: api-ssl on 8729, open to the management range only, ' +
            'serving a certificate generated on the router, whose fingerprint ObliWAN pins on first contact. The job goes ' +
            'through SSH with the existing account; where the router lacks ObliWAN\'s own account "obliwan", it creates it ' +
            '(restricted to the management range) and switches ObliWAN\'s API and SSH channels to it once a login with it ' +
            'is proven. No other user is touched.',
        })}
      </Hint>

      <dl className="mb-3 grid grid-cols-1 gap-4 sm:grid-cols-2">
        <Row label={t('managementAccess.apiSslRow', { defaultValue: 'API-SSL on the router' })}>
          <span className={cn(view.apiSsl.state === 'conformant' ? 'text-status-up' : view.apiSsl.state === 'different' ? 'text-status-ssl-warning' : 'text-text-secondary')}>
            {apiSslLine}
          </span>
        </Row>
        <Row label={t('managementAccess.apiChannelRow', { defaultValue: "ObliWAN's API channel" })}>
          <span className="font-mono">{apiText}</span>
          {api && (
            <span className={cn('ml-2 text-[12px]', api.pinned ? 'text-status-up' : 'text-status-ssl-warning')}>
              {api.pinned
                ? t('managementAccess.pinned', { fp: shortFingerprint(api.fingerprint), defaultValue: 'pinned {{fp}}' })
                : t('managementAccess.notPinned', { defaultValue: 'no pinned certificate' })}
            </span>
          )}
        </Row>
        <Row label={t('managementAccess.sshRow', { defaultValue: 'SSH channel (used by the job)' })}>
          {view.ssh
            ? (
              <span className="font-mono">
                {`${view.ssh.host ?? '—'}:${view.ssh.port ?? 22}`}
                <span className="ml-2 font-sans text-[12px] text-text-muted">
                  {t(`managementAccess.sshAuth.${view.ssh.auth}`, { defaultValue: view.ssh.auth })}
                </span>
              </span>
            )
            : <span className="text-text-muted">{t('managementAccess.sshNone', { defaultValue: 'none' })}</span>}
        </Row>
        <Row label={t('managementAccess.rangeRow', { defaultValue: 'Management range' })}>
          {view.range.ok
            ? <span className="font-mono">{view.range.prefixes.join(', ')}</span>
            : <span className="text-status-ssl-warning">{t('managementAccess.rangeUnset', { defaultValue: 'not set' })}</span>}
        </Row>
        <Row label={t('managementAccess.accountRow', { defaultValue: 'Account used by ObliWAN' })}>
          {accountUsers
            ? (
              <>
                <span className="font-mono">{accountUsers}</span>
                <span className={cn('ml-2 text-[12px]', usesObliwan ? 'text-status-up' : 'text-status-ssl-warning')}>
                  {usesObliwan
                    ? t('managementAccess.accountOwn', { defaultValue: "ObliWAN's own account" })
                    : t('managementAccess.accountLegacy', {
                      account: OBLIWAN_ACCOUNT,
                      defaultValue: 'not ObliWAN\'s own account: the job creates "{{account}}" and switches to it',
                    })}
                </span>
              </>
            )
            : <span className="text-text-muted">{t('managementAccess.accountNone', { defaultValue: 'none' })}</span>}
        </Row>
      </dl>

      {!view.eligible && !active && view.refusals.length > 0 && (
        <div className="mb-3 rounded-md border border-status-ssl-warning/40 bg-status-ssl-warning/5 p-3">
          <p className="mb-1 flex items-center gap-1.5 text-[12px] font-medium text-status-ssl-warning">
            <AlertTriangle size={13} />
            {t('managementAccess.refusalsTitle', { defaultValue: 'The job cannot be queued on this router:' })}
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
              {t('managementAccess.lastJob', { id: job.id, defaultValue: 'Job #{{id}}' })}
            </span>
            <span>{t(`change.status.label.${job.status}`, { defaultValue: job.status })}</span>
            {job.rolloutId !== null && (
              <span className="text-text-muted">
                {t('managementAccess.inRollout', { id: job.rolloutId, defaultValue: 'rollout #{{id}}' })}
              </span>
            )}
            <span className="ml-auto font-mono text-[11px] text-text-muted">{new Date(job.createdAt).toLocaleString()}</span>
          </p>
          {job.steps.length > 0 && (
            <ol className="space-y-1">
              {job.steps.map((s: ManagementAccessStep) => (
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
          {jobAccount?.action && (
            <div className="mt-2 flex items-start gap-2 text-[12px]">
              <span className="mt-0.5"><AccountIcon action={jobAccount.action} /></span>
              <div className="min-w-0">
                <p className={cn('font-medium', jobAccount.action === 'refused' ? 'text-status-down' : 'text-text-primary')}>
                  {t(`managementAccess.account.${jobAccount.action}`, { account: OBLIWAN_ACCOUNT, defaultValue: jobAccount.action })}
                  {(jobAccount.action === 'created' || jobAccount.action === 'present') && (
                    <span className={cn('ml-2 font-normal', jobAccount.switchedAt ? 'text-status-up' : 'text-status-ssl-warning')}>
                      {jobAccount.switchedAt
                        ? t('managementAccess.accountSwitched', {
                          date: new Date(jobAccount.switchedAt).toLocaleString(),
                          defaultValue: 'ObliWAN switched to it ({{date}})',
                        })
                        : t('managementAccess.accountNotSwitched', {
                          user: sshUser ?? '—',
                          defaultValue: 'not used yet: ObliWAN still logs in as {{user}}',
                        })}
                    </span>
                  )}
                </p>
                {jobAccount.detail && <p className="mt-0.5 break-words text-text-muted">{jobAccount.detail}</p>}
                {jobAccount.disclosedAt && (
                  <p className="mt-0.5 break-words font-medium text-status-down">
                    {t('managementAccess.accountDisclosed', {
                      account: OBLIWAN_ACCOUNT,
                      date: new Date(jobAccount.disclosedAt).toLocaleString(),
                      defaultValue:
                        'Password considered disclosed ({{date}}): discarded, never reused. Remove "{{account}}" from the router; the next run recreates it with a new password.',
                    })}
                  </p>
                )}
              </div>
            </div>
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
                <p className="mt-1 text-text-muted">
                  {t('managementAccess.backupKept', { id: job.backupId, defaultValue: 'The pre-change backup #{{id}} is kept.' })}
                </p>
              )}
            </div>
          )}
        </div>
      )}

      {canLaunch && view.state !== 'unsupported' && (
        confirming ? (
          <div className="rounded-md border border-status-ssl-warning/50 bg-status-ssl-warning/5 p-3">
            <p className="mb-2 text-[12px] text-text-secondary">
              {t('managementAccess.confirmText', {
                defaultValue:
                  'No dead-man is armed: the job only writes /certificate, the api-ssl service, ObliWAN\'s own "obliwan" ' +
                  'group and user when they are missing, and — the one existing account or group it changes — the "sensitive" policy, ' +
                  'added to the "obliwan" group ObliWAN made when it is the only policy that group lacks (on a router ' +
                  'already reached as "obliwan", by the historical "admin" account from the vault, admin_password, on a ' +
                  'separate session that also pulls the pre-change backup and writes nothing else). Never SSH, the ' +
                  'firewall, addresses, routes or any existing user. A pre-change backup is pulled first; without one ' +
                  'nothing is written.',
              })}
            </p>
            <div className="flex gap-2">
              <Button size="sm" variant="danger" disabled={busy} loading={busy} onClick={() => void open()}>
                {t('managementAccess.confirm', { defaultValue: 'Confirm and queue' })}
              </Button>
              <Button size="sm" variant="secondary" disabled={busy} onClick={() => setConfirming(false)}>
                {t('managementAccess.cancel', { defaultValue: 'Cancel' })}
              </Button>
            </div>
          </div>
        ) : (
          <Button size="sm" variant="secondary" disabled={!view.eligible || active || busy} onClick={() => setConfirming(true)}>
            <KeyRound size={14} className="mr-1.5" />
            {buttonLabel}
          </Button>
        )
      )}
    </div>
  );
}
