import { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { AlertTriangle, Moon, Settings, ShieldCheck } from 'lucide-react';
import type { AccessCheckOpenAlert, AccessCheckRunView, AccessCheckScheduleView } from '@obliwan/shared';
import { Button } from '@/components/common/Button';
import { accessCheckApi } from '@/api/accessCheck.api';
import { reconcileError } from '@/api/reconcile.api';

interface Props {
  /** Opens the verification dialog (ReconcilePage). */
  onOpen: () => void;
  /** Changes when the dialog closes: the card reads again. */
  refreshKey: number;
  /** A platform administrator: the settings screen is theirs. */
  canEditSettings: boolean;
}

/** The anchor of the nightly settings on the settings screen (SettingField). */
export const NIGHTLY_SETTINGS_URL = '/manage/settings#setting-access_check_nightly';

/**
 * The nightly verification of the management access, on the reconciliation
 * page (server: GET /reconcile/access-check[/schedule], CHANGE_APPLY —
 * fleet/accessCheckNightly.service.ts). Read-only: the latest verification
 * whoever started it (the night, or an operator), the workspace's nightly
 * settings as they resolve, the open alerts by cause, and the way to the
 * settings (platform administrators) and to the verification itself.
 */
export function AccessCheckNightlyCard({ onOpen, refreshKey, canEditSettings }: Props) {
  const { t, i18n } = useTranslation();
  const [run, setRun] = useState<AccessCheckRunView | null>(null);
  const [schedule, setSchedule] = useState<AccessCheckScheduleView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const latest = useRef(0);

  const load = useCallback(async () => {
    const ticket = ++latest.current;
    try {
      const [r, s] = await Promise.all([accessCheckApi.latest(), accessCheckApi.schedule()]);
      if (ticket !== latest.current) return;
      setRun(r);
      setSchedule(s);
      setError(null);
    } catch (err) {
      if (ticket === latest.current) setError(reconcileError(err).message);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load, refreshKey]);

  const fmt = (iso: string | null): string => (iso ? new Date(iso).toLocaleString(i18n.language) : '—');

  const causeText = (a: AccessCheckOpenAlert): string => {
    const reason =
      a.kind === 'access' || a.kind === 'access_unknown'
        ? t(`accessCheck.accessReason.${a.reason}`, { defaultValue: a.reason ?? '' })
        : a.kind === 'compliance_unknown'
          ? t(`accessCheck.complianceReason.${a.reason}`, { defaultValue: a.reason ?? '' })
          : '';
    const label = t(`accessCheck.alertCause.${a.kind}`, { defaultValue: a.kind });
    return reason ? `${label} — ${reason}` : label;
  };

  const autoLine = (): string => {
    if (!schedule) return '';
    const a = schedule.autoReapply;
    if (!a.enabled) return t('accessCheck.nightly.autoOff', { defaultValue: 'Automatic re-apply: off.' });
    if (!a.consent) {
      return t('accessCheck.nightly.autoNoConsent', {
        defaultValue:
          'Automatic re-apply: on, but no platform administrator’s confirmation is on record for it, so nothing is queued. Save the setting again to confirm it.',
      });
    }
    return t('accessCheck.nightly.autoOn', {
      defaultValue: 'Automatic re-apply: on, at most {{cap}} routers a night — degraded level confirmed by {{user}} on {{date}}.',
      cap: a.cap,
      user: a.consent.username,
      date: fmt(a.consent.at),
    });
  };

  return (
    <div className="mb-4 rounded-xl border border-border bg-bg-secondary p-4">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <Moon size={16} className="text-accent" />
        <h2 className="flex-1 text-sm font-semibold text-text-primary">
          {t('accessCheck.nightly.title', { defaultValue: 'Nightly verification of the management access' })}
        </h2>
        {canEditSettings && (
          <Link to={NIGHTLY_SETTINGS_URL} className="flex items-center gap-1 text-xs text-accent hover:underline">
            <Settings size={12} /> {t('accessCheck.nightly.settings', { defaultValue: 'Settings' })}
          </Link>
        )}
        <Button size="sm" variant="secondary" onClick={onOpen}>
          <ShieldCheck size={14} /> {t('accessCheck.nightly.open', { defaultValue: 'Open the verification' })}
        </Button>
      </div>

      {error && <p className="text-xs text-status-down">{error}</p>}

      {schedule && (
        <div className="space-y-0.5 text-xs text-text-secondary">
          <p>
            {schedule.nightly.enabled
              ? t('accessCheck.nightly.on', {
                  defaultValue: 'Every night at {{hour}}:00 ({{tz}}), read-only towards the routers — next: {{next}}.',
                  hour: String(schedule.nightly.hour).padStart(2, '0'),
                  tz: schedule.nightly.timeZone,
                  next: fmt(schedule.nightly.nextRunAt),
                })
              : t('accessCheck.nightly.off', { defaultValue: 'Off for this workspace.' })}
          </p>
          <p>{autoLine()}</p>
          {!canEditSettings && (
            <p className="text-text-muted">
              {t('accessCheck.nightly.settingsAdmin', {
                defaultValue: 'These settings are changed by a platform administrator (Settings, Change jobs).',
              })}
            </p>
          )}
        </div>
      )}

      <div className="mt-3 border-t border-border pt-3 text-xs">
        {run ? (
          <>
            <p className="text-text-primary">
              {t('accessCheck.nightly.latest', {
                defaultValue: 'Latest verification: {{date}} — {{who}}',
                date: fmt(run.startedAt),
                who:
                  run.trigger === 'nightly'
                    ? t('accessCheck.nightly.byNight', { defaultValue: 'automatic (nightly verification #{{number}})', number: run.number })
                    : t('accessCheck.nightly.byUser', { defaultValue: 'by {{user}}', user: run.requestedBy?.username ?? '—' }),
              })}
              {run.status === 'running' && ` — ${t('accessCheck.nightly.running', { defaultValue: 'in progress' })}`}
              {run.status === 'interrupted' && ` — ${t('accessCheck.interrupted', { defaultValue: 'interrupted (server restart): verify again' })}`}
              {run.scope === 'teams' && ` — ${t('accessCheck.scopeTeams', { defaultValue: 'your teams’ routers only' })}`}
            </p>
            <p className="mt-0.5 text-text-muted">
              {t('accessCheck.nightly.counts', {
                defaultValue: '{{access}} access to restore · {{fixes}} fixes to apply · {{ok}} in order · {{skipped}} skipped, of which {{offline}} offline',
                access: run.counts.needsAccess,
                fixes: run.counts.needsFixes,
                ok: run.counts.ok,
                skipped: run.counts.skipped,
                offline: run.offline,
              })}
            </p>
            {run.autoReapply && (
              <p className="mt-0.5 text-text-muted">
                {t(`accessCheck.autoStatus.${run.autoReapply.status}`, { defaultValue: run.autoReapply.status })}
                {run.autoReapply.status === 'done' &&
                  ` — ${t('accessCheck.autoSummary', {
                    defaultValue: '{{queued}} job(s) queued, {{refused}} refused, {{held}} held',
                    queued: run.autoReapply.queued,
                    refused: run.autoReapply.refused,
                    held: Object.values(run.autoReapply.held).reduce((a, b) => a + (b ?? 0), 0),
                  })}`}
              </p>
            )}
          </>
        ) : (
          !error && <p className="text-text-muted">{t('accessCheck.nightly.none', { defaultValue: 'No verification yet.' })}</p>
        )}
      </div>

      {schedule && (
        <div className="mt-3 text-xs">
          <h3 className="mb-1 font-semibold text-text-primary">
            {t('accessCheck.nightly.alertsTitle', { defaultValue: 'Open alerts' })} ({schedule.openAlerts.length})
          </h3>
          {schedule.openAlerts.length === 0 ? (
            <p className="text-text-muted">{t('accessCheck.nightly.noAlerts', { defaultValue: 'No open alert.' })}</p>
          ) : (
            <ul className="space-y-0.5">
              {schedule.openAlerts.map((a) => (
                <li key={a.cause} className="flex flex-wrap items-center gap-1.5">
                  <AlertTriangle size={12} className="text-amber-400" />
                  <span className="text-text-primary">{causeText(a)}</span>
                  <span className="text-text-muted">
                    {t('accessCheck.nightly.alertCount', {
                      defaultValue: '{{count}} router(s), since {{date}}',
                      count: a.count,
                      date: fmt(a.openedAt),
                    })}
                  </span>
                  {a.suspended > 0 && (
                    <span className="text-amber-400">
                      {t('accessCheck.nightly.suspended', {
                        defaultValue: '{{count}} not re-applied automatically any more (the previous automatic re-apply failed): for a human',
                        count: a.suspended,
                      })}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

export default AccessCheckNightlyCard;
