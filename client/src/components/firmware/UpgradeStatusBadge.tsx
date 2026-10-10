import { useTranslation } from 'react-i18next';
import { ArrowUpCircle, CheckCircle2, HelpCircle, Loader2 } from 'lucide-react';
import { cn } from '@/utils/cn';
import type { UpgradeStatus, UpgradeStatusReason } from '@/api/osUpgrade.api';

/**
 * The four answers of the fleet update screen, in the words an operator who is
 * not a network engineer reads them: up to date, behind, unknown, in progress.
 *
 * `unknown` is drawn MUTED, never amber: it is not a problem to fix by
 * updating, it is a fact ObliWAN could not establish (no version read, no
 * target known, another major line). The reason is in the tooltip.
 */

const TONE: Record<UpgradeStatus, string> = {
  up_to_date: 'text-status-up border-status-up/50 bg-status-up/10',
  behind: 'text-status-ssl-warning border-status-ssl-warning/50 bg-status-ssl-warning/10',
  unknown: 'text-text-muted border-border bg-bg-tertiary',
  in_progress: 'text-accent border-accent/50 bg-accent/10',
};

const DEFAULT_LABEL: Record<UpgradeStatus, string> = {
  up_to_date: 'Up to date',
  behind: 'Behind',
  unknown: 'Unknown',
  in_progress: 'In progress',
};

export const DEFAULT_REASON: Record<UpgradeStatusReason, string> = {
  job_active: 'An update is running on this router.',
  rollout_active: 'This router is part of an update rollout; its turn has not come yet.',
  version_missing: "No version is known for this router yet. Use 'Re-read versions' above the table.",
  version_unparseable: 'The version reported by this router could not be read.',
  no_target: 'No target version is known yet (the RouterOS release watch has not read one).',
  major_differs:
    'Runs another major RouterOS line than the target (e.g. RouterOS 6). Moving to RouterOS 7 is a migration, not offered here.',
  at_target: 'Runs the target version.',
  ahead_of_target: 'Runs a newer version than the target.',
  below_target: 'Runs an older version than the target.',
};

export function useUpgradeStatusLabel(): (status: UpgradeStatus) => string {
  const { t } = useTranslation();
  return (status) => t(`fleetUpgrade.status.${status}`, { defaultValue: DEFAULT_LABEL[status] });
}

export function UpgradeStatusBadge({
  status,
  reason,
  className,
}: {
  status: UpgradeStatus;
  reason: UpgradeStatusReason;
  className?: string;
}) {
  const { t } = useTranslation();
  const label = useUpgradeStatusLabel();
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider',
        TONE[status],
        className,
      )}
      title={t(`fleetUpgrade.reason.${reason}`, { defaultValue: DEFAULT_REASON[reason] })}
    >
      {status === 'up_to_date' && <CheckCircle2 size={11} />}
      {status === 'behind' && <ArrowUpCircle size={11} />}
      {status === 'unknown' && <HelpCircle size={11} />}
      {status === 'in_progress' && <Loader2 size={11} className="animate-spin" />}
      {label(status)}
    </span>
  );
}
