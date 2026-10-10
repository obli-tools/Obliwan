import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Activity } from 'lucide-react';
import toast from 'react-hot-toast';
import type {
  BenchQualificationView,
  DeviceHealthCheckView,
  DeviceHealthSummary,
  HealthDisplay,
} from '@obliwan/shared';
import {
  BENCH_QUALIFY_AFTER_PREP_MIN,
  BENCH_QUALIFY_ON_SITE_MIN,
  outageIsAnnounceable,
} from '@obliwan/shared';
import { devicesApi } from '@/api/devices.api';
import { Button } from '@/components/common/Button';
import { cn } from '@/utils/cn';

/**
 * The permanent health check of one device (migration 043), on its page,
 * next to the reachability verdict.
 *
 * Every number shown under "applied settings" is what the SERVER resolved for
 * this device through the settings chain — not the defaults, and not what a
 * settings screen elsewhere says — so a group override is visible where it
 * takes effect.
 *
 * "Not checkable" is said plainly, in words, never drawn as an outage: a
 * TR-069-only CPE has no channel ObliWAN may dial, and a red dot there would
 * teach an operator to ignore the red dot.
 *
 * A router prepared at the bench also shows where it stands on the
 * qualification rule (server: benchQualification.service.ts) — in shipping,
 * qualifying, or qualified on a date — because until it is qualified no
 * outage of it is announced, and an operator waiting for an alert must be
 * told why none will come.
 */

const DOT: Record<HealthDisplay, string> = {
  ok: 'bg-status-up',
  failing: 'bg-status-pending',
  down: 'bg-status-down',
  suppressed: 'bg-transparent border-2 border-status-maintenance',
  unknown: 'bg-transparent border-2 border-text-muted/60',
  stale: 'bg-transparent border-2 border-text-muted/60',
  not_checkable: 'bg-transparent border-2 border-text-muted/40',
};

const TEXT: Record<HealthDisplay, string> = {
  ok: 'text-status-up',
  failing: 'text-status-pending',
  down: 'text-status-down',
  suppressed: 'text-text-secondary',
  unknown: 'text-text-muted',
  stale: 'text-text-muted',
  not_checkable: 'text-text-muted',
};

function when(iso: string | null): string | null {
  return iso ? new Date(iso).toLocaleString() : null;
}

/** One sentence for the state, shared by the panel and the list tooltip. */
function useDisplayLabel() {
  const { t } = useTranslation();
  return (
    display: HealthDisplay,
    ctx: {
      downSince: string | null;
      lastCheckAt: string | null;
      failures?: number;
      skipReason?: string | null;
      disabled?: boolean;
    },
  ): string => {
    switch (display) {
      case 'ok':
        return t('healthCheck.display.ok', { defaultValue: 'OK' });
      case 'failing':
        return t('healthCheck.display.failing', {
          defaultValue: '{{count}} failed check(s) in a row — not yet declared down',
          count: ctx.failures ?? 1,
        });
      case 'down':
        return t('healthCheck.display.down', {
          defaultValue: 'Down since {{since}}',
          since: when(ctx.downSince) ?? '—',
        });
      case 'suppressed':
        return t('healthCheck.display.suppressed', {
          defaultValue: 'Not checked: its concentrator is degraded (one alert, on the concentrator)',
        });
      case 'stale':
        return t('healthCheck.display.stale', {
          defaultValue: 'No recent check (last one: {{at}})',
          at: when(ctx.lastCheckAt) ?? '—',
        });
      case 'not_checkable':
        if (ctx.disabled) {
          return t('healthCheck.display.disabled', {
            defaultValue: 'Never checked: the device is disabled',
          });
        }
        if (ctx.skipReason === 'quarantined') {
          return t('healthCheck.display.quarantined', {
            defaultValue: 'Not checked: the device is quarantined (identity in question)',
          });
        }
        return t('healthCheck.display.notCheckable', {
          defaultValue: 'Not checkable: no management channel',
        });
      default:
        return t('healthCheck.display.unknown', { defaultValue: 'Not checked yet' });
    }
  };
}

/** The list's pastille. Hollow means "no verdict", never "down". */
export function HealthDot({
  summary,
  disabled,
  size = 8,
}: {
  summary: DeviceHealthSummary | undefined;
  disabled?: boolean;
  size?: number;
}) {
  const { t } = useTranslation();
  const label = useDisplayLabel();
  if (!summary) return null;
  const text = label(summary.display, {
    downSince: summary.downSince,
    lastCheckAt: summary.lastCheckAt,
    failures: summary.consecutiveFailures,
    disabled,
  });
  const last = when(summary.lastCheckAt);
  return (
    <span
      role="img"
      aria-label={text}
      title={`${t('healthCheck.title', { defaultValue: 'Permanent check' })}: ${text}${
        last ? `\n${t('healthCheck.fields.lastCheck', { defaultValue: 'Last check' })}: ${last}` : ''
      }`}
      className={cn('inline-block shrink-0 rounded-full', DOT[summary.display])}
      style={{ width: size, height: size }}
    />
  );
}

/** Where a bench-prepared router stands: one sentence, plus what happens next
 *  while it is qualifying. */
function QualificationText({ q }: { q: BenchQualificationView }) {
  const { t } = useTranslation();
  if (q.state === 'qualified') {
    return (
      <span className="text-status-up">
        {t('healthCheck.qualification.qualified', {
          defaultValue: 'Qualified on {{at}} — down alerts armed',
          at: when(q.qualifiedAt) ?? '—',
        })}
      </span>
    );
  }
  if (q.state === 'in_shipping') {
    return (
      <span className="text-text-secondary">
        {t('healthCheck.qualification.inShipping', {
          defaultValue: 'In shipping since {{at}} — no alert until it qualifies',
          at: when(q.inShippingSince) ?? '—',
        })}
      </span>
    );
  }
  // The minutes are read off the clock at render, from the instant the server
  // counted the tunnel up from (the preparation at the earliest).
  const minutes = q.upSince ? Math.max(0, Math.floor((Date.now() - new Date(q.upSince).getTime()) / 60_000)) : 0;
  return (
    <span className="text-status-pending">
      {t('healthCheck.qualification.qualifying', {
        defaultValue: 'Qualification in progress ({{minutes}} min online)',
        minutes,
      })}
      <span className="block text-[11px] text-text-muted">
        {q.observerBlind
          ? t('healthCheck.qualification.observerBlind', {
            defaultValue: 'On hold: its concentrator is degraded, so the time online cannot be confirmed',
          })
          : t('healthCheck.qualification.qualifiesAt', {
            defaultValue: 'Qualified at {{at}} if the tunnel stays up ({{required}} min in a row)',
            at: when(q.qualifiesAt) ?? '—',
            required: q.requiredMinutes ?? '—',
          })}
      </span>
    </span>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-[11px] uppercase tracking-wider text-text-muted">{label}</dt>
      <dd className="mt-0.5 text-sm text-text-primary">
        {children === null || children === undefined || children === ''
          ? <span className="text-text-muted">—</span>
          : children}
      </dd>
    </div>
  );
}

export function HealthCheckPanel({
  deviceId,
  view,
  canCheck,
  onChecked,
}: {
  deviceId: number;
  /** `undefined`: the server did not send the block at all. */
  view: DeviceHealthCheckView | null | undefined;
  canCheck: boolean;
  onChecked: (view: DeviceHealthCheckView) => void;
}) {
  const { t } = useTranslation();
  const label = useDisplayLabel();
  const [checking, setChecking] = useState(false);

  if (!view) {
    return (
      <p className="text-xs text-text-muted">
        {t('healthCheck.unavailable', { defaultValue: 'The server did not return the permanent check for this device.' })}
      </p>
    );
  }

  const handleCheck = async () => {
    setChecking(true);
    try {
      const next = await devicesApi.checkHealth(deviceId);
      onChecked(next);
      if (next.display === 'ok' || next.display === 'failing') {
        if (next.consecutiveFailures === 0) {
          toast.success(t('healthCheck.checkOk', { defaultValue: 'The device answered.' }));
        } else {
          toast.error(t('healthCheck.checkKo', {
            defaultValue: 'The device did not answer: {{error}}',
            error: next.lastError ?? '—',
          }));
        }
      } else if (next.display === 'down') {
        toast.error(t('healthCheck.checkKo', {
          defaultValue: 'The device did not answer: {{error}}',
          error: next.lastError ?? '—',
        }));
      } else {
        toast(label(next.display, {
          downSince: next.downSince,
          lastCheckAt: next.lastCheckAt,
          failures: next.consecutiveFailures,
          skipReason: next.skipReason,
          disabled: !next.scheduled,
        }));
      }
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(message ?? t('healthCheck.checkFailed', { defaultValue: 'The check could not be run.' }));
    } finally {
      setChecking(false);
    }
  };

  const headline = label(view.display, {
    downSince: view.downSince,
    lastCheckAt: view.lastCheckAt,
    failures: view.consecutiveFailures,
    skipReason: view.skipReason,
    disabled: !view.scheduled,
  });

  const method = view.channel && view.method
    ? view.method === 'api_read'
      ? t('healthCheck.method.apiRead', { defaultValue: 'RouterOS API read' })
      : t('healthCheck.method.tcpConnect', {
        defaultValue: 'TCP connection ({{channel}})',
        channel: t(`fleet.transport.${view.channel}`, { defaultValue: view.channel }),
      })
    : null;

  // A device that has never answered is shown down and never announced — the
  // server's rule (`outageIsAnnounceable`), stated here rather than leaving
  // the operator to wait for an alert that will not come. A bench-prepared
  // router is held by its qualification instead, whatever it answered.
  const qualification = view.qualification ?? null;
  const benchHeld = qualification !== null && qualification.state !== 'qualified';
  const neverAnswered = view.display === 'down'
    && !benchHeld
    && !outageIsAnnounceable(view.lastOkAt, qualification?.state ?? null);
  // When the alert of a confirmed outage will go out at the earliest. The
  // notification cooldown can push it later; the server is the one that knows.
  const alertDueAt = view.display === 'down' && view.downSince && !view.alertedAt && !neverAnswered && !benchHeld
    ? new Date(new Date(view.downSince).getTime() + view.alertDelaySec * 1000).toISOString()
    : null;
  const alertText = view.alertedAt
    ? t('healthCheck.alerted', { defaultValue: 'Sent at {{at}}', at: when(view.alertedAt) })
    : benchHeld
      ? t('healthCheck.alertHeldBench', {
        defaultValue: 'None: a bench-prepared router announces no outage before it is qualified',
      })
      : neverAnswered
        ? t('healthCheck.alertNeverAnswered', {
          defaultValue: 'None: this device has never answered a check, so no outage is announced',
        })
        : alertDueAt
          ? t('healthCheck.alertDue', {
            defaultValue: 'Not before {{at}}, if it is still down',
            at: when(alertDueAt),
          })
          : null;

  return (
    <div className="rounded-md border border-border bg-bg-tertiary/40 p-3">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span
            className={cn('inline-block shrink-0 rounded-full', DOT[view.display])}
            style={{ width: 9, height: 9 }}
          />
          <span className="text-[11px] uppercase tracking-wider text-text-muted">
            {t('healthCheck.title', { defaultValue: 'Permanent check' })}
          </span>
          <span className={cn('text-sm font-medium', TEXT[view.display])}>{headline}</span>
        </div>
        {canCheck && view.scheduled && (
          <Button variant="secondary" size="sm" onClick={handleCheck} loading={checking}>
            <Activity size={14} className="mr-1.5" />
            {t('healthCheck.checkNow', { defaultValue: 'Check now' })}
          </Button>
        )}
      </div>

      <dl className="grid grid-cols-2 gap-3">
        <Row label={t('healthCheck.fields.lastCheck', { defaultValue: 'Last check' })}>
          {when(view.lastCheckAt)}
        </Row>
        <Row label={t('healthCheck.fields.lastOk', { defaultValue: 'Last answer' })}>
          {when(view.lastOkAt)}
        </Row>
        <Row label={t('healthCheck.fields.method', { defaultValue: 'Method' })}>
          {method}
        </Row>
        <Row label={t('healthCheck.fields.nextCheck', { defaultValue: 'Next check' })}>
          {when(view.nextCheckAt)}
        </Row>
        <Row label={t('healthCheck.fields.policy', { defaultValue: 'Applied settings' })}>
          {t('healthCheck.policy', {
            defaultValue: 'every {{interval}} s · down after {{failures}} failed check(s) · alert {{delay}} s later',
            interval: view.intervalSec,
            failures: view.retries + 1,
            delay: view.alertDelaySec,
          })}
        </Row>
        <Row label={t('healthCheck.fields.alert', { defaultValue: 'Alert' })}>
          {alertText}
        </Row>
        {qualification && (
          <div className="col-span-2">
            <dt className="text-[11px] uppercase tracking-wider text-text-muted">
              {t('healthCheck.fields.qualification', { defaultValue: 'Bench qualification' })}
            </dt>
            <dd className="mt-0.5 text-sm">
              <QualificationText q={qualification} />
              <span className="mt-0.5 block text-[11px] text-text-muted">
                {t('healthCheck.qualification.rule', {
                  defaultValue: 'Prepared at the bench on {{prepared}}. No down alert until its tunnel stays up '
                    + '{{afterPrep}} min in a row right after the preparation, or {{onSite}} min in a row later, on site.',
                  prepared: when(qualification.benchAppliedAt) ?? '—',
                  afterPrep: BENCH_QUALIFY_AFTER_PREP_MIN,
                  onSite: BENCH_QUALIFY_ON_SITE_MIN,
                })}
              </span>
            </dd>
          </div>
        )}
      </dl>

      {view.lastError && (
        <div className="mt-3">
          <div className="text-[11px] uppercase tracking-wider text-text-muted">
            {t('healthCheck.fields.lastError', { defaultValue: 'Last error' })}
          </div>
          <p className="mt-0.5 break-words font-mono text-[12px] text-text-secondary">{view.lastError}</p>
        </div>
      )}
    </div>
  );
}
