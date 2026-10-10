import { useTranslation } from 'react-i18next';
import { ShieldAlert, Stethoscope, X } from 'lucide-react';
import { Button } from '@/components/common/Button';
import { cn } from '@/utils/cn';
import type { DeviceDiagnosis, TransportTestResult } from '@/types/fleet';

/**
 * Why the channel failed, laid out worst-question-first.
 *
 * The verdict comes at the top and in prose, because it is the only part most
 * operators need: the port table below is the evidence for it, not a substitute
 * for reading it. The ports are shown with their MEANING (`8728 RouterOS API`)
 * rather than as bare numbers — the person diagnosing a site at 2am should not
 * also have to remember which MikroTik service lives on which port.
 *
 * `refused` is rendered as a POSITIVE signal, which looks wrong for half a
 * second and is right: a refusal is the host talking. It proves the box exists,
 * is routed and is reachable, and narrows the fault to one service. A timeout
 * on the same port would be strictly worse news.
 */
function DiagnosisPanel({ d }: { d: DeviceDiagnosis }) {
  const { t } = useTranslation();

  const stateStyle: Record<string, string> = {
    open: 'border-status-up/30 bg-status-up/10 text-status-up',
    refused: 'border-status-ssl-warning/40 bg-status-ssl-warning/10 text-status-ssl-warning',
    reset: 'border-status-ssl-warning/40 bg-status-ssl-warning/10 text-status-ssl-warning',
    unreachable: 'border-status-down/40 bg-status-down/10 text-status-down',
    timeout: 'border-status-down/40 bg-status-down/10 text-status-down',
  };

  const outcomeStyle: Record<string, string> = {
    ok: 'text-status-up',
    fail: 'text-status-down',
    unknown: 'text-text-muted',
    skipped: 'text-text-muted',
  };

  return (
    <div className="mt-3 border-t border-border pt-3">
      <div className="mb-3 flex items-start gap-2">
        {d.hostAnswered
          ? <Stethoscope size={16} className="mt-0.5 shrink-0 text-status-ssl-warning" />
          : <ShieldAlert size={16} className="mt-0.5 shrink-0 text-status-down" />}
        <p className="text-sm text-text-primary">{d.verdict}</p>
      </div>

      <p className="mb-2 text-xs uppercase tracking-wide text-text-muted">
        {t('devices.diagnosePorts', { host: d.target.host })}
      </p>
      <div className="mb-3 flex flex-wrap gap-1.5">
        {d.ports.map((p) => (
          <span
            key={p.port}
            title={`${p.service} — ${p.ms} ms`}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px]',
              stateStyle[p.state] ?? 'border-border text-text-muted',
            )}
          >
            <span className="font-mono">{p.port}</span>
            <span className="opacity-70">{p.service}</span>
            <span className="font-medium">{t(`devices.portState.${p.state}`)}</span>
          </span>
        ))}
      </div>

      <ul className="space-y-1.5">
        {d.steps.map((s, i) => (
          <li key={`${s.step}-${i}`} className="text-xs">
            <span className={cn('font-medium', outcomeStyle[s.outcome] ?? 'text-text-muted')}>
              {s.label}
            </span>
            {s.ms !== null && <span className="ml-1.5 font-mono text-text-muted">{s.ms} ms</span>}
            <span className="ml-1.5 text-text-secondary">{s.detail}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/**
 * What « Tester la connexion » found, above every tab: the operator clicked a
 * header button and must see its answer whatever tab he is on.
 */
export function DeviceTestResults({
  results,
  hasChannels,
  canDiagnose,
  diagnosing,
  diagnosis,
  onDiagnose,
  onDismiss,
}: {
  results: TransportTestResult[];
  /** The device has at least one channel row (enabled or not). */
  hasChannels: boolean;
  canDiagnose: boolean;
  diagnosing: boolean;
  diagnosis: DeviceDiagnosis | null;
  onDiagnose: () => void;
  onDismiss: () => void;
}) {
  const { t } = useTranslation();
  return (
    <div className="mb-5 rounded-lg border border-border bg-bg-secondary p-4">
      <div className="mb-2 flex items-center justify-between gap-2">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-text-secondary">
          {t('devices.testResults')}
        </h2>
        <button
          type="button"
          onClick={onDismiss}
          aria-label={t('common.close')}
          className="rounded p-1 text-text-muted hover:bg-bg-hover hover:text-text-primary"
        >
          <X size={14} />
        </button>
      </div>
      {results.length === 0 ? (
        // An empty result is not "the test came back blank" — the device
        // simply has no channel to test, and saying so names the fix. The
        // generic sentence sent an operator looking for a network problem
        // that did not exist: a device created without a credential (or one
        // whose credential failed to store) has no `device_transports` row
        // at all, so the loop had nothing to walk.
        <p className="text-sm text-text-muted">
          {hasChannels ? t('devices.testAllChannelsDisabled') : t('devices.testNoChannel')}
        </p>
      ) : (
        <ul className="space-y-1.5">
          {results.map((r, i) => (
            <li key={`${r.transport}-${i}`} className="flex flex-wrap items-center gap-2 text-sm">
              <span className={cn(
                'inline-flex w-24 justify-center rounded-full border px-2 py-0.5 text-[10px] font-medium',
                r.ok
                  ? 'border-status-up/30 bg-status-up/10 text-status-up'
                  : 'border-status-down/40 bg-status-down/10 text-status-down',
              )}>
                {t(`fleet.transport.${r.transport}`)}
              </span>
              <span className={r.ok ? 'text-status-up' : 'text-status-down'}>
                {r.ok ? t('devices.testOk') : t('devices.testKo')}
              </span>
              {r.rttMs != null && <span className="font-mono text-xs text-text-muted">{r.rttMs} ms</span>}
              {r.error && <span className="break-all font-mono text-xs text-text-muted">{r.error}</span>}
            </li>
          ))}
        </ul>
      )}

      {/* A failed test raises exactly one question, so offer exactly that. */}
      {results.some((r) => !r.ok) && canDiagnose && (
        <div className="mt-3 border-t border-border pt-3">
          <Button size="sm" variant="secondary" onClick={onDiagnose} disabled={diagnosing}>
            <Stethoscope size={14} className={cn('mr-1.5', diagnosing && 'animate-pulse')} />
            {diagnosing ? t('devices.diagnoseRunning') : t('devices.diagnose')}
          </Button>
          <p className="mt-1.5 text-xs text-text-muted">{t('devices.diagnoseHint')}</p>
        </div>
      )}

      {diagnosis && <DiagnosisPanel d={diagnosis} />}
    </div>
  );
}
