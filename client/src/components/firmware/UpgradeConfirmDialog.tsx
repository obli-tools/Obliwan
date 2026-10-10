import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, PenLine, Power, Rocket, ShieldCheck, X } from 'lucide-react';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { anonHostname } from '@/utils/anonymize';
import { cn } from '@/utils/cn';
import {
  launchErrorOf,
  osUpgradeApi,
  type DeviceRefusal,
  type LaunchError,
  type LaunchPreview,
  type LaunchProblem,
  type LaunchResult,
  type UpgradeDevice,
} from '@/api/osUpgrade.api';
import { useRefusalText } from './refusals';

/**
 * The last screen before routers reboot.
 *
 * ── IT STATES FOUR THINGS, IN THIS ORDER ───────────────────────────────────
 *  1. the version and the number of routers (in the title, and again in the
 *     button: the number an operator reads last is the number he signs);
 *  2. that EACH router reboots - a few minutes without connectivity per site;
 *  3. for several routers, the waves, and that the rollout stops at the first
 *     failure;
 *  4. that there is no automatic way back (no dead-man can un-install a
 *     RouterOS release, migration 047): a box that does not boot is a visit.
 *
 * ── IT NAMES EVERY ROUTER ──────────────────────────────────────────────────
 * The count alone is not what is signed: the selection may hold routers the
 * filters hide. So the dialog lists each router by name, wave by wave, and
 * marks the test router. The membership comes from the server's preview,
 * which asks the rollout service how it will compose (`waveMembers`), never
 * from a copy of that rule here.
 *
 * ── THE VERSION SENT IS THE VERSION SHOWN ──────────────────────────────────
 * The dialog asks the server for its decision first (`/preview`, nothing
 * written) and launches with THAT version explicitly. Leaving it implicit
 * would let the release watch move the fleet target between the moment the
 * operator read "7.24.5" and the moment he clicked.
 *
 * ── THE SIGNATURE IS NOT A CHECKBOX ────────────────────────────────────────
 * Every upgrade carries a written reason (the Management-Path Guard cannot
 * model a reboot into new code, so its verdict is INDETERMINATE and needs a
 * signed override, CHANGE_APPROVE) and an explicit confirmation that there is
 * no remote recovery. The confirmation is typing the number of routers - the
 * same gesture as typing a hostname in the single-device dialog, and one that
 * cannot be performed by reflex.
 */

const DEFAULT_PROBLEM: Record<string, string> = {
  version_invalid: 'This version cannot be installed (a published RouterOS 7 release is required).',
  waves_invalid: 'The wave sizes do not fit the selection.',
  waves_mismatch: 'The rollout would run other waves than the ones stated here.',
  override_required: 'A written reason is required.',
  degraded_confirmation_required: 'The number of routers must be confirmed.',
};

const DEFAULT_ERROR: Record<string, string> = {
  backend_unwired: 'Updates cannot be launched on this server yet.',
  kill_switch: 'Writes are stopped (kill switch engaged).',
};

export function UpgradeConfirmDialog({
  deviceIds,
  devices,
  canApprove,
  canRollout,
  onClose,
  onLaunched,
}: {
  deviceIds: number[];
  /** The listing's views, for the names; a selected id missing here is shown as `#id`. */
  devices: UpgradeDevice[];
  canApprove: boolean;
  canRollout: boolean;
  onClose: () => void;
  onLaunched: (result: LaunchResult) => void;
}) {
  const { t } = useTranslation();
  const refusalText = useRefusalText();
  const nameOf = useMemo(() => {
    const byId = new Map(devices.map((d) => [d.id, d.name]));
    return (id: number) => anonHostname(byId.get(id) ?? `#${id}`);
  }, [devices]);

  const [decision, setDecision] = useState<LaunchPreview | null>(null);
  const [previewError, setPreviewError] = useState<LaunchError | null>(null);
  const [reason, setReason] = useState('');
  const [typed, setTyped] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [launchError, setLaunchError] = useState<LaunchError | null>(null);

  const count = deviceIds.length;

  useEffect(() => {
    let cancelled = false;
    osUpgradeApi
      .preview({ deviceIds })
      .then((d) => { if (!cancelled) setDecision(d); })
      .catch((err) => { if (!cancelled) setPreviewError(launchErrorOf(err)); });
    return () => { cancelled = true; };
  }, [deviceIds]);

  const problemText = (p: LaunchProblem) =>
    t(`fleetUpgrade.problem.${p.code}`, { defaultValue: DEFAULT_PROBLEM[p.code] ?? p.message });

  const blockingProblems = useMemo(
    () => (decision?.problems ?? []).filter((p) => !p.code.endsWith('_required')),
    [decision],
  );
  const refusals: DeviceRefusal[] = launchError?.refusals.length ? launchError.refusals : decision?.refusals ?? [];

  const multi = count > 1;
  const rightsOk = canApprove && (!multi || canRollout);
  const signed = reason.trim().length >= 8 && typed.trim() === String(count);
  const canSubmit =
    decision !== null &&
    decision.version !== null &&
    decision.refusals.length === 0 &&
    blockingProblems.length === 0 &&
    rightsOk &&
    signed &&
    !submitting;

  const submit = async () => {
    if (!decision?.version) return;
    setSubmitting(true);
    setLaunchError(null);
    try {
      const result = await osUpgradeApi.launch({
        deviceIds,
        version: decision.version,
        overrideReason: reason.trim(),
        confirmDegraded: true,
      });
      onLaunched(result);
    } catch (err) {
      setLaunchError(launchErrorOf(err));
    } finally {
      setSubmitting(false);
    }
  };

  const versionLabel = decision?.version ?? '…';

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/70 p-4">
      <div className="my-8 w-full max-w-2xl rounded-xl border border-border bg-bg-secondary shadow-2xl">
        <div className="flex items-start gap-3 border-b border-border px-5 py-4">
          <Rocket size={20} className="mt-0.5 shrink-0 text-accent" />
          <h2 className="flex-1 text-base font-semibold text-text-primary">
            {t('fleetUpgrade.confirm.title', {
              count,
              version: versionLabel,
              defaultValue: 'Update {{count}} router(s) to RouterOS {{version}}',
            })}
          </h2>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary" aria-label="close">
            <X size={18} />
          </button>
        </div>

        <div className="space-y-4 p-5">
          {decision === null && previewError === null && (
            <div className="flex items-center gap-2 text-sm text-text-muted">
              <LoadingSpinner size="sm" />
              {t('fleetUpgrade.confirm.loading', { defaultValue: 'Checking the selection…' })}
            </div>
          )}

          {previewError && (
            <p className="rounded-md border border-status-ssl-expired/40 bg-status-ssl-expired/5 p-3 text-[13px] text-status-ssl-expired">
              {previewError.message ?? t('fleetUpgrade.loadFailed', { defaultValue: 'Could not load the fleet.' })}
            </p>
          )}

          {decision && (
            <>
              <ul className="space-y-2 text-[13px] text-text-primary">
                <li className="flex gap-2">
                  <Power size={15} className="mt-0.5 shrink-0 text-status-ssl-warning" />
                  {t('fleetUpgrade.confirm.factReboot', {
                    defaultValue:
                      'Each router downloads the new version and reboots: its site loses connectivity for a few minutes.',
                  })}
                </li>
                <li className="flex gap-2">
                  <ShieldCheck size={15} className="mt-0.5 shrink-0 text-status-up" />
                  {t('fleetUpgrade.confirm.factBackup', {
                    defaultValue: 'A backup of each router is taken before anything is written to it.',
                  })}
                </li>
                <li className="flex gap-2">
                  <Rocket size={15} className="mt-0.5 shrink-0 text-accent" />
                  {multi
                    ? t('fleetUpgrade.confirm.factWaves', {
                        defaultValue:
                          'Routers are updated in waves, starting with a single test router. The rollout stops at the first failure.',
                      })
                    : t('fleetUpgrade.confirm.factSingle', { defaultValue: 'Only this router is updated.' })}
                </li>
                <li className="flex gap-2">
                  <AlertTriangle size={15} className="mt-0.5 shrink-0 text-status-ssl-expired" />
                  <span className="font-medium">
                    {t('fleetUpgrade.confirm.factNoRollback', {
                      defaultValue:
                        'There is no automatic way back: a router that does not boot again needs someone on site.',
                    })}
                  </span>
                </li>
              </ul>

              <div className="rounded-md border border-border bg-bg-tertiary p-3 text-[12px] text-text-secondary">
                <p className="mb-1.5 font-medium text-text-primary">
                  {t('fleetUpgrade.confirm.routersTitle', {
                    count,
                    defaultValue: 'The {{count}} router(s) that will reboot:',
                  })}
                </p>
                <div className="max-h-48 overflow-y-auto">
                  {multi && decision.waves.length > 0 && (
                    <ol className="space-y-1.5">
                      {decision.waves.map((w) => {
                        const members = decision.waveMembers?.find((m) => m.index === w.index)?.deviceIds ?? null;
                        return (
                          <li key={w.index}>
                            <span className="font-mono">
                              {t('fleetUpgrade.confirm.wave', {
                                n: w.index + 1,
                                size: w.size,
                                defaultValue: 'Wave {{n}}: {{size}} router(s)',
                              })}
                              {w.label === 'canary' &&
                                ` (${t('fleetUpgrade.confirm.canaryTag', { defaultValue: 'test' })})`}
                            </span>
                            {members && (
                              <span className="block pl-3 font-mono text-text-muted">{members.map(nameOf).join(', ')}</span>
                            )}
                          </li>
                        );
                      })}
                    </ol>
                  )}
                  {(!multi || !decision.waveMembers) && (
                    <p className={cn('font-mono text-text-muted', multi && 'mt-1.5')}>{deviceIds.map(nameOf).join(', ')}</p>
                  )}
                </div>
              </div>

              {(refusals.length > 0 || blockingProblems.length > 0) && (
                <div className="rounded-md border border-status-ssl-expired/40 bg-status-ssl-expired/5 p-3 text-[13px]">
                  {blockingProblems.map((p) => (
                    <p key={p.code} className="text-status-ssl-expired">{problemText(p)}</p>
                  ))}
                  {refusals.length > 0 && (
                    <>
                      <p className="font-medium text-status-ssl-expired">
                        {t('fleetUpgrade.confirm.refusedTitle', {
                          defaultValue: 'These routers cannot be updated now:',
                        })}
                      </p>
                      <ul className="mt-1 list-disc space-y-0.5 pl-5 text-text-secondary">
                        {refusals.map((r) => (
                          <li key={`${r.deviceId}-${r.code}`}>
                            <span className="font-mono">{anonHostname(r.deviceName ?? `#${r.deviceId}`)}</span>
                            {' — '}
                            {refusalText(r.code)}
                          </li>
                        ))}
                      </ul>
                      <p className="mt-2 text-[12px] text-text-muted">
                        {t('fleetUpgrade.confirm.refusedHint', {
                          defaultValue: 'Deselect them and try again. Nothing was started.',
                        })}
                      </p>
                    </>
                  )}
                </div>
              )}

              {/* The signature: visually its own block, never next to a bare button. */}
              <div className="space-y-3 rounded-md border border-status-ssl-warning/50 bg-status-ssl-warning/5 p-4">
                <div className="flex items-center gap-2 text-[13px] font-semibold text-status-ssl-warning">
                  <PenLine size={15} />
                  {t('fleetUpgrade.confirm.signTitle', { defaultValue: 'Your signature' })}
                </div>
                <p className="text-[12px] text-text-secondary">
                  {t('fleetUpgrade.confirm.signHint', {
                    defaultValue:
                      'ObliWAN cannot prove in advance that a router comes back after rebooting into a new version. Launching therefore needs a written reason, recorded under your name.',
                  })}
                </p>
                {!canApprove && (
                  <p className="text-[12px] font-medium text-status-ssl-expired">
                    {t('fleetUpgrade.confirm.needApprove', {
                      defaultValue:
                        'Signing an update needs the approval right (change.approve). Ask an administrator.',
                    })}
                  </p>
                )}
                {multi && !canRollout && (
                  <p className="text-[12px] font-medium text-status-ssl-expired">
                    {t('fleetUpgrade.confirm.needRollout', {
                      defaultValue: 'Updating several routers at once needs the rollout right (rollout.manage).',
                    })}
                  </p>
                )}
                <label className="block text-[12px] text-text-secondary">
                  {t('fleetUpgrade.confirm.reasonLabel', { defaultValue: 'Reason (at least 8 characters)' })}
                  <textarea
                    value={reason}
                    onChange={(e) => setReason(e.target.value)}
                    disabled={!rightsOk}
                    rows={2}
                    maxLength={2000}
                    placeholder={t('fleetUpgrade.confirm.reasonPlaceholder', {
                      defaultValue: 'e.g. security fix, maintenance agreed with the customer',
                    })}
                    className="mt-1 w-full rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent disabled:opacity-50"
                  />
                </label>
                <label className="block text-[12px] text-text-secondary">
                  {t('fleetUpgrade.confirm.typeLabel', {
                    count,
                    defaultValue: 'Type {{count}} to confirm the number of routers that will reboot',
                  })}
                  <input
                    type="text"
                    inputMode="numeric"
                    value={typed}
                    onChange={(e) => setTyped(e.target.value)}
                    disabled={!rightsOk}
                    className="mt-1 w-28 rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 font-mono text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent disabled:opacity-50"
                  />
                </label>
              </div>
            </>
          )}

          {launchError && (
            <div className="rounded-md border border-status-ssl-expired/40 bg-status-ssl-expired/5 p-3 text-[13px] text-status-ssl-expired">
              <p className="font-medium">
                {t('fleetUpgrade.confirm.failed', { defaultValue: 'The update was not started.' })}
              </p>
              <p className="mt-1 text-[12px]">
                {launchError.code && DEFAULT_ERROR[launchError.code]
                  ? t(`fleetUpgrade.error.${launchError.code}`, { defaultValue: DEFAULT_ERROR[launchError.code] })
                  : launchError.problems.length > 0
                    ? launchError.problems.map(problemText).join(' ')
                    : launchError.message}
              </p>
            </div>
          )}
        </div>

        <div className="flex justify-end gap-2 border-t border-border px-5 py-3">
          <Button variant="secondary" size="sm" onClick={onClose}>
            {t('fleetUpgrade.confirm.cancel', { defaultValue: 'Cancel' })}
          </Button>
          <Button variant="primary" size="sm" disabled={!canSubmit} loading={submitting} onClick={() => void submit()}>
            {t('fleetUpgrade.confirm.submit', { count, defaultValue: 'Update {{count}} router(s)' })}
          </Button>
        </div>
      </div>
    </div>
  );
}
