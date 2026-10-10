import { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ShieldCheck, RefreshCw } from 'lucide-react';
import toast from 'react-hot-toast';
import { CAPABILITIES } from '@obliwan/shared';
import { Button } from '@/components/common/Button';
import { getSocket } from '@/socket/socketClient';
import { useAuthStore } from '@/store/authStore';
import { cn } from '@/utils/cn';
import {
  AUTO_CONFIRM_EVENT,
  autoConfirmApi,
  type ConformityDifference,
  type ConformityView,
} from './autoConfirm.api';

/**
 * "Validation automatique" — the closed loop of a bench-prepared router, on
 * its device page (`server/src/services/fleet/autoConfirm.service.ts`).
 *
 * It states one of: waiting for the first contact, waiting for the tunnel
 * (an attempt was made, and the next one needs the PPP session back — it has
 * no date to give, so none is shown), retrying (with the attempt count and the
 * next try), differences found on a first look and a second look scheduled,
 * conformant on a date (the device was confirmed by the check), not conformant
 * with N differences listed, or a human is needed and why. What the check did NOT compare is one click away and never hidden: an
 * operator who trusts an automatic confirmation must be able to see where it
 * stopped looking — unless the reader may not read configuration
 * (CONFIG_READ), in which case the server withholds it and the panel says so.
 *
 * "Re-check now" needs DEVICE_WRITE on the device (the `canRecheck` prop: it
 * may confirm the device) AND CONFIG_WRITE (read from the store, as the
 * configuration tab does: it makes the platform dial the box and collect).
 *
 * The server's sentences (`reason`, `lastError`) are shown verbatim: server
 * messages are not localised in this product yet.
 */

const DOT: Record<string, string> = {
  waiting: 'bg-transparent border-2 border-text-muted/60',
  conformant: 'bg-status-up',
  non_conformant: 'bg-status-down',
  anomaly: 'bg-status-pending',
  superseded: 'bg-transparent border-2 border-text-muted/40',
};

const TEXT: Record<string, string> = {
  waiting: 'text-text-secondary',
  conformant: 'text-status-up',
  non_conformant: 'text-status-down',
  anomaly: 'text-status-pending',
  superseded: 'text-text-muted',
};

function when(iso: string | null | undefined): string {
  return iso ? new Date(iso).toLocaleString() : '—';
}

function DifferenceRow({ d }: { d: ConformityDifference }) {
  const { t } = useTranslation();
  return (
    <li className="py-1.5">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="rounded border border-border px-1.5 py-0.5 font-mono text-[10px] uppercase text-text-muted">
          {t(`autoConfirm.op.${d.op}`, { defaultValue: d.op })}
        </span>
        <span className="text-text-secondary">{d.resource}</span>
        {d.semKey && <span className="break-all font-mono text-text-primary">{d.semKey}</span>}
      </div>
      {d.values.length > 0 && (
        <ul className="ml-2 mt-1 space-y-0.5">
          {d.values.map((v) => (
            <li key={v.field} className="break-all font-mono text-[11px] text-text-secondary">
              {v.field}: {t('autoConfirm.diff.planned', { defaultValue: 'plan' })} {v.intent} · {t('autoConfirm.diff.onBox', { defaultValue: 'box' })} {v.actual}
            </li>
          ))}
        </ul>
      )}
      {d.reason && d.values.length === 0 && (
        <p className="ml-2 mt-1 break-words text-[11px] text-text-muted">{d.reason}</p>
      )}
    </li>
  );
}

export function AutoConfirmPanel({
  deviceId,
  canRecheck,
  onConfirmed,
}: {
  deviceId: number;
  /** DEVICE_WRITE on this device. CONFIG_WRITE is checked here. */
  canRecheck: boolean;
  /** Called once when a check confirmed the device, so the page reloads its status. */
  onConfirmed?: () => void;
}) {
  const { t } = useTranslation();
  const { hasCapability, isAdmin } = useAuthStore();
  const canCollect = isAdmin() || hasCapability(CAPABILITIES.CONFIG_WRITE);
  const [view, setView] = useState<ConformityView | null>(null);
  const [failed, setFailed] = useState(false);
  const [checking, setChecking] = useState(false);
  const [showExcluded, setShowExcluded] = useState(false);
  const confirmedRef = useRef(onConfirmed);
  confirmedRef.current = onConfirmed;
  /** The state last shown — `undefined` until the first read. The transition
   *  to `conformant` is detected here, outside any state updater, so the
   *  page is told once whether it came from the button, the live event or
   *  both. */
  const lastStateRef = useRef<ConformityView['state'] | undefined>(undefined);

  const applyView = useCallback((next: ConformityView) => {
    const previous = lastStateRef.current;
    lastStateRef.current = next.state;
    setView(next);
    if (previous !== undefined && previous !== 'conformant' && next.state === 'conformant') confirmedRef.current?.();
  }, []);

  const load = useCallback(async () => {
    try {
      applyView(await autoConfirmApi.get(deviceId));
      setFailed(false);
    } catch {
      setFailed(true);
    }
  }, [deviceId, applyView]);

  useEffect(() => {
    lastStateRef.current = undefined;
    void load();
  }, [load]);

  // Live: the server emits after every check of a device of this tenant.
  useEffect(() => {
    const socket = getSocket();
    if (!socket) return;
    const onEvent = (payload: unknown) => {
      const id = (payload as { deviceId?: unknown } | null)?.deviceId;
      if (Number(id) === deviceId) void load();
    };
    socket.on(AUTO_CONFIRM_EVENT, onEvent);
    return () => {
      socket.off(AUTO_CONFIRM_EVENT, onEvent);
    };
  }, [deviceId, load]);

  if (failed && !view) {
    return (
      <p className="text-xs text-text-muted">
        {t('autoConfirm.unavailable', { defaultValue: 'The automatic validation could not be read.' })}
      </p>
    );
  }
  if (!view) return null;
  // A device no bench compiled has nothing to show here: say nothing rather
  // than a permanent "not applicable" panel on every hand-declared device.
  if (!view.applicable && view.notApplicableReason === 'not_bench') return null;

  const handleRecheck = async () => {
    setChecking(true);
    try {
      const result = await autoConfirmApi.recheck(deviceId);
      applyView(result.view);
      if (result.outcome === 'confirmed') {
        toast.success(t('autoConfirm.toast.confirmed', { defaultValue: 'Conformant: the device was confirmed automatically.' }));
      } else if (result.outcome === 'non_conformant') {
        toast.error(t('autoConfirm.toast.nonConformant', { defaultValue: 'Not conformant: see the differences.' }));
      } else if (result.outcome === 'not_contacted') {
        toast(t('autoConfirm.toast.notContacted', { defaultValue: 'The tunnel is down: the box was not contacted.' }));
      } else {
        toast(result.message || t('autoConfirm.toast.done', { defaultValue: 'Check finished.' }), { duration: 8000 });
      }
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(message ?? t('autoConfirm.toast.failed', { defaultValue: 'The check could not be run.' }), { duration: 10_000 });
    } finally {
      setChecking(false);
    }
  };

  const state = view.state ?? 'waiting';
  let headline: string;
  if (!view.applicable) {
    headline = t('autoConfirm.state.benchFailed', {
      defaultValue: 'The bench reported this preparation as failed — a human confirms this device',
    });
  } else if (!view.enabled && view.state !== 'conformant') {
    headline = t('autoConfirm.state.disabled', {
      defaultValue: 'Automatic validation is switched off on this installation — a human confirms this device',
    });
  } else if (view.state === null || (view.state === 'waiting' && view.attempts === 0)) {
    headline = view.sessionUp
      ? t('autoConfirm.state.firstContact', { defaultValue: 'First contact — check scheduled' })
      : t('autoConfirm.state.waitingFirstContact', { defaultValue: 'Waiting for first contact' });
  } else if (view.state === 'waiting' && view.waitingForTunnel) {
    // Before the settling and retry branches: both would print the stored
    // next attempt, which is not when anything happens while the tunnel is
    // down (it was a date in the past more often than not).
    headline = t('autoConfirm.state.waitingTunnel', {
      defaultValue: 'Waiting for the tunnel ({{attempts}}/{{max}} attempts so far) — the next one runs once it is back up',
      attempts: view.attempts,
      max: view.maxAttempts,
    });
  } else if (view.state === 'waiting' && view.reasonCode === 'settling') {
    headline = t('autoConfirm.state.settling', {
      defaultValue: '{{count}} differences on a first look — looking again {{at}}',
      count: view.differenceCount ?? view.differences.length,
      at: when(view.nextAttemptAt),
    });
  } else if (view.state === 'waiting') {
    headline = t('autoConfirm.state.retrying', {
      defaultValue: 'Retrying ({{attempts}}/{{max}}), next attempt {{at}}',
      attempts: view.attempts,
      max: view.maxAttempts,
      at: when(view.nextAttemptAt),
    });
  } else if (view.state === 'conformant') {
    headline = t('autoConfirm.state.conformant', {
      defaultValue: 'Conformant on {{date}} — confirmed automatically',
      date: when(view.confirmedAt),
    });
  } else if (view.state === 'non_conformant') {
    headline = t('autoConfirm.state.nonConformant', {
      defaultValue: 'Not conformant ({{count}} differences)',
      count: view.differenceCount ?? view.differences.length,
    });
  } else if (view.state === 'anomaly') {
    headline = t('autoConfirm.state.anomaly', { defaultValue: 'A human must confirm this device' });
  } else {
    headline = t('autoConfirm.state.superseded', { defaultValue: 'Not decided: the device or its bench file changed meanwhile' });
  }

  const canRun = canRecheck && canCollect && view.enabled && view.applicable && view.deviceStatus === 'pending';
  const ex = view.excluded;
  const excludedCount = ex
    ? ex.accessBlock.length + ex.benchFed.length + ex.benchFedKinds.length + ex.secretBearing.length
      + ex.unmodelledSections.length + ex.limitations.length + (ex.nonConfigLines?.length ?? 0)
      + (ex.factoryInterfaces?.length ?? 0) + (ex.readOnBox?.length ?? 0)
    : 0;

  return (
    <div className="rounded-md border border-border bg-bg-tertiary/40 p-3">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className={cn('inline-block shrink-0 rounded-full', DOT[state])} style={{ width: 9, height: 9 }} />
          <ShieldCheck size={14} className="text-text-muted" />
          <span className="text-[11px] uppercase tracking-wider text-text-muted">
            {t('autoConfirm.title', { defaultValue: 'Automatic validation' })}
          </span>
          <span className={cn('text-sm font-medium', TEXT[state])}>{headline}</span>
        </div>
        {canRun && (
          <Button variant="secondary" size="sm" onClick={handleRecheck} loading={checking}>
            <RefreshCw size={14} className="mr-1.5" />
            {t('autoConfirm.recheck', { defaultValue: 'Re-check now' })}
          </Button>
        )}
      </div>

      {view.reasonCode && view.state !== 'conformant' && (
        <p className="mb-2 text-xs text-text-secondary">
          {t(`autoConfirm.reason.${view.reasonCode}`, { defaultValue: view.reasonCode })}
          {view.reason ? <span className="block break-words font-mono text-[11px] text-text-muted">{view.reason}</span> : null}
        </p>
      )}

      <dl className="grid grid-cols-2 gap-3 text-sm">
        <div>
          <dt className="text-[11px] uppercase tracking-wider text-text-muted">
            {t('autoConfirm.fields.preparation', { defaultValue: 'Bench file' })}
          </dt>
          <dd className="mt-0.5 break-all font-mono text-[12px] text-text-primary">
            {view.provisioning ? `${view.provisioning.tag} · ${when(view.provisioning.compiledAt)}` : '—'}
          </dd>
        </div>
        <div>
          <dt className="text-[11px] uppercase tracking-wider text-text-muted">
            {t('autoConfirm.fields.lastAttempt', { defaultValue: 'Last attempt' })}
          </dt>
          <dd className="mt-0.5 text-text-primary">{when(view.lastAttemptAt)}</dd>
        </div>
        {view.snapshotId && (
          <div>
            <dt className="text-[11px] uppercase tracking-wider text-text-muted">
              {t('autoConfirm.fields.snapshot', { defaultValue: 'Compared snapshot' })}
            </dt>
            <dd className="mt-0.5 font-mono text-[12px] text-text-primary">#{view.snapshotId}</dd>
          </div>
        )}
        {view.renderMatchesCompile !== null && (
          <div>
            <dt className="text-[11px] uppercase tracking-wider text-text-muted">
              {t('autoConfirm.fields.renderMatches', { defaultValue: 'Plan identical to the bench file' })}
            </dt>
            <dd className="mt-0.5 text-text-primary">
              {view.renderMatchesCompile
                ? t('autoConfirm.yes', { defaultValue: 'yes' })
                : t('autoConfirm.renderChanged', { defaultValue: 'no — variables or allocation changed since the bench' })}
            </dd>
          </div>
        )}
      </dl>

      {view.lastError && view.state === 'waiting' && view.reasonCode !== 'settling' && (
        <p className="mt-2 break-words font-mono text-[11px] text-text-muted">{view.lastError}</p>
      )}

      {view.differences.length > 0 && (
        <div className="mt-3">
          <div className="text-[11px] uppercase tracking-wider text-text-muted">
            {t('autoConfirm.differences', { defaultValue: 'Differences with the plan' })}
          </div>
          <ul className="divide-y divide-border">
            {view.differences.map((d, i) => <DifferenceRow key={`${d.op}:${d.semKey}:${i}`} d={d} />)}
          </ul>
        </div>
      )}

      {!view.configDetail && view.state !== null && (
        <p className="mt-2 text-[11px] text-text-muted">
          {t('autoConfirm.configDetailWithheld', {
            defaultValue: 'Configuration details (keys, values, what was not compared) need the configuration read permission.',
          })}
        </p>
      )}

      {ex && excludedCount > 0 && (
        <div className="mt-3">
          <button
            type="button"
            className="text-xs text-accent hover:underline"
            onClick={() => setShowExcluded((v) => !v)}
          >
            {showExcluded
              ? t('autoConfirm.excluded.hide', { defaultValue: 'Hide what was not compared' })
              : t('autoConfirm.excluded.show', { defaultValue: 'What was not compared ({{count}})', count: excludedCount })}
          </button>
          {showExcluded && (
            <ul className="mt-1 space-y-1 text-[11px] text-text-secondary">
              {ex.limitations.map((l) => (
                <li key={`lim:${l.resource}`}>
                  {t('autoConfirm.excluded.readBack', {
                    defaultValue: '{{resource}}: compared both ways — what the export omits was read on the box',
                    resource: l.resource,
                  })}
                </li>
              ))}
              {(ex.readOnBox ?? []).length > 0 && (
                <li className="font-mono">
                  {t('autoConfirm.excluded.readOnBox', { defaultValue: 'Read on the box (absent from its export): {{list}}', list: ex.readOnBox.join(', ') })}
                </li>
              )}
              {ex.accessBlock.map((a) => (
                <li key={`acc:${a.semKey}`} className="font-mono">
                  {a.fields && a.fields.length > 0
                    ? t('autoConfirm.excluded.accessFields', {
                        defaultValue: 'ObliWAN access block, only {{fields}} (the value the block wrote; everything else compared)',
                        fields: a.fields.join(', '),
                      })
                    : t('autoConfirm.excluded.access', { defaultValue: 'ObliWAN access block' })}
                  : {a.semKey}
                </li>
              ))}
              {ex.benchFed.map((b) => (
                <li key={`bench:${b.semKey}`} className="font-mono">
                  {t('autoConfirm.excluded.bench', { defaultValue: 'Typed at the bench ({{keys}})', keys: b.benchKeys.join(', ') })}: {b.semKey}
                </li>
              ))}
              {ex.benchFedKinds.map((b) => (
                <li key={`benchkind:${b.resource}`}>
                  {t('autoConfirm.excluded.benchKind', { defaultValue: '{{resource}}: written only for some bench values ({{keys}})', resource: b.resource, keys: b.benchKeys.join(', ') })}
                </li>
              ))}
              {ex.secretBearing.map((s) => (
                <li key={`secret:${s.semKey}`} className="font-mono">
                  {t('autoConfirm.excluded.secret', { defaultValue: 'Carries a secret' })}: {s.semKey}
                </li>
              ))}
              {(ex.factoryInterfaces ?? []).length > 0 && (
                <li>
                  {t('autoConfirm.excluded.factory', {
                    defaultValue: 'Interfaces named with nothing modelled (at factory or absent, the export cannot tell): {{list}}',
                    list: ex.factoryInterfaces.join(', '),
                  })}
                </li>
              )}
              {(ex.nonConfigLines ?? []).map((l) => (
                <li key={`line:${l.line}`}>
                  {t('autoConfirm.excluded.nonConfig', { defaultValue: 'Line {{line}} is not configuration: {{what}}', line: l.line, what: l.what })}
                </li>
              ))}
              {ex.unmodelledSections.length > 0 && (
                <li>
                  {t('autoConfirm.excluded.unmodelled', { defaultValue: 'Sections not modelled: {{list}}', list: ex.unmodelledSections.join(', ') })}
                </li>
              )}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
