import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { CHANGE_JOB_STATUSES, type ChangeJobStatus } from '@obliwan/shared';
import { JobStatusBadge } from '@/components/change/JobStatusBadge';
import { cn } from '@/utils/cn';
import type { UpgradeDevice, UpgradeJobRef } from '@/api/osUpgrade.api';

/**
 * What is happening to one router, and where to look.
 *
 * ── THE PHASE IS READ FROM WHAT THE JOB RECORDED ───────────────────────────
 * An `os_upgrade` job writes the instant of each irreversible gesture on its
 * `os_upgrade_jobs` row (migration 047): package fetch, reboot, return. The
 * strip below follows those instants first and the job status second, so it
 * never shows "rebooting" for a box nothing has rebooted yet.
 *
 * Every cell links to the job (`/changes/:id`) or the rollout
 * (`/rollouts/:id`) - the place with the full timeline and the abort button -
 * unless the listing withheld the queue details (`showLinks` false: the
 * caller lacks PLAN_CREATE, which those pages require, and the ids are null).
 */

const PHASES = ['queued', 'backup', 'fetch', 'reboot', 'verify'] as const;
type Phase = (typeof PHASES)[number];

const DEFAULT_PHASE: Record<Phase, string> = {
  queued: 'Waiting',
  backup: 'Backup',
  fetch: 'Downloading',
  reboot: 'Rebooting',
  verify: 'Checking',
};

const KNOWN_STATUS: ReadonlySet<string> = new Set(CHANGE_JOB_STATUSES);

export function phaseOf(job: UpgradeJobRef): number {
  const u = job.upgrade;
  if (u?.returnedAt) return 4;
  if (u?.rebootedAt) return 3;
  if (u?.fetchedAt) return 2;
  if (job.status === 'queued') return 0;
  if (job.status === 'claimed' || job.status === 'backing_up' || job.status === 'arming') return 1;
  if (job.status === 'applying') return 2;
  return 4;
}

function StatusBadge({ status }: { status: string }) {
  if (KNOWN_STATUS.has(status)) return <JobStatusBadge status={status as ChangeJobStatus} />;
  return <span className="font-mono text-[11px] text-text-muted">{status}</span>;
}

function PhaseStrip({ job }: { job: UpgradeJobRef }) {
  const { t } = useTranslation();
  const current = phaseOf(job);
  return (
    <div className="flex items-center gap-1">
      {PHASES.map((p, i) => (
        <span
          key={p}
          className={cn(
            'rounded px-1.5 py-0.5 text-[10px]',
            i < current && 'bg-status-up/10 text-status-up',
            i === current && 'bg-accent/15 font-semibold text-accent',
            i > current && 'text-text-muted',
          )}
        >
          {t(`fleetUpgrade.phase.${p}`, { defaultValue: DEFAULT_PHASE[p] })}
        </span>
      ))}
    </div>
  );
}

export function UpgradeProgressCell({
  device,
  dateFmt,
  showLinks,
}: {
  device: UpgradeDevice;
  dateFmt: Intl.DateTimeFormat;
  showLinks: boolean;
}) {
  const { t } = useTranslation();
  const active = device.activeJob;
  const jobLink = (job: UpgradeJobRef) =>
    showLinks && job.id !== null ? (
      <Link to={`/changes/${job.id}`} className="font-mono text-[11px] text-accent hover:underline">
        {t('fleetUpgrade.progress.viewJob', { id: job.id, defaultValue: 'Job #{{id}}' })}
      </Link>
    ) : null;
  const rolloutLink = (id: number | null) =>
    showLinks && id !== null ? (
      <Link to={`/rollouts/${id}`} className="font-mono text-[11px] text-accent hover:underline">
        {t('fleetUpgrade.progress.inRollout', { id, defaultValue: 'Rollout #{{id}}' })}
      </Link>
    ) : null;

  if (active && active.kind === 'os_upgrade') {
    return (
      <div className="space-y-1">
        <PhaseStrip job={active} />
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge status={active.status} />
          {jobLink(active)}
          {active.rolloutId !== null && rolloutLink(active.rolloutId)}
        </div>
      </div>
    );
  }

  if (active) {
    return (
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[11px] text-text-secondary">
          {active.kind === 'other'
            ? t('fleetUpgrade.progress.busyUnnamed', { defaultValue: 'Busy: another operation' })
            : t('fleetUpgrade.progress.busyOther', { kind: active.kind, defaultValue: 'Busy: {{kind}} operation' })}
        </span>
        {jobLink(active)}
      </div>
    );
  }

  if (device.heldByRollout) {
    return (
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[11px] text-text-secondary">
          {device.heldByRollout.status === 'draft'
            ? t('fleetUpgrade.progress.draftRollout', {
                defaultValue: 'Held by a rollout that was never launched (draft)',
              })
            : device.heldByRollout.kind === 'os_upgrade'
              ? t('fleetUpgrade.progress.waitingWave', { defaultValue: 'Waiting for its wave' })
              : t('fleetUpgrade.progress.inOtherRollout', { defaultValue: 'Held by another rollout' })}
        </span>
        {rolloutLink(device.heldByRollout.id)}
      </div>
    );
  }

  const last = device.lastUpgradeJob;
  if (last) {
    const failed = last.status === 'failed' || last.status === 'rolled_back' || last.status === 'aborted';
    const detail = last.upgrade?.outcomeDetail ?? last.errorMessage ?? undefined;
    return (
      <div className="flex flex-wrap items-center gap-2" title={detail}>
        <span className={cn('text-[11px]', failed ? 'text-status-ssl-expired' : 'text-text-muted')}>
          {t('fleetUpgrade.progress.lastAttempt', { defaultValue: 'Last attempt' })}
        </span>
        <StatusBadge status={last.status} />
        {last.upgrade?.targetVersion && (
          <span className="font-mono text-[11px] text-text-muted">{last.upgrade.targetVersion}</span>
        )}
        {last.finishedAt && (
          <span className="font-mono text-[10px] text-text-muted">{dateFmt.format(new Date(last.finishedAt))}</span>
        )}
        {jobLink(last)}
      </div>
    );
  }

  return <span className="text-[11px] text-text-muted">—</span>;
}
