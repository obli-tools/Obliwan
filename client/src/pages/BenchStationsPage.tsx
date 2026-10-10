import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { ChevronDown, ChevronRight, MonitorCheck, RotateCw, ShieldCheck, ShieldOff } from 'lucide-react';
import {
  benchStationsApi,
  type BenchStation,
  type BenchStationStatus,
} from '@/api/benchStations.api';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { StationDecisionDialog } from '@/components/bench/StationDecisionDialog';
import { cn } from '@/utils/cn';

/**
 * Bench workstations — platform administrators only (the server guards every
 * route with `requireRole('admin')`; the route must be mounted behind
 * `ProtectedRoute requiredRole="admin"`).
 *
 * Pending stations come first and carry the verification code in large type:
 * the administrator approves the row whose code the person at the desk reads
 * off the bench screen, and the approval dialog makes them type it.
 *
 * The list refreshes itself every 15 seconds while the tab is visible, because
 * the usual flow is "the bench registers, somebody phones, the administrator
 * approves" and a stale list would hide the new row.
 */

const STATUS_ORDER: Record<BenchStationStatus, number> = { pending: 0, approved: 1, revoked: 2 };
const POLL_MS = 15_000;

export function BenchStationsPage() {
  const { t, i18n } = useTranslation();
  const [stations, setStations] = useState<BenchStation[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  /** At least one list read succeeded. Until then an empty `stations` means
   *  "not known", not "none registered", and no empty state is drawn. */
  const [loaded, setLoaded] = useState(false);
  const [decision, setDecision] = useState<{ station: BenchStation; action: 'approve' | 'revoke' } | null>(null);
  const [busy, setBusy] = useState(false);
  const [showRevoked, setShowRevoked] = useState(false);

  const load = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const list = await benchStationsApi.list();
      setStations(list);
      setLoaded(true);
      setLoadError(null);
    } catch (err) {
      setLoadError(errorText(err) ?? t('benchStations.loadFailed', {
        defaultValue: 'Could not load the workstations.',
      }));
    } finally {
      if (!quiet) setLoading(false);
    }
  }, [t]);

  useEffect(() => { void load(); }, [load]);

  useEffect(() => {
    const id = window.setInterval(() => {
      if (document.visibilityState === 'visible' && !decision) void load(true);
    }, POLL_MS);
    return () => window.clearInterval(id);
  }, [load, decision]);

  const sorted = useMemo(
    () => [...stations].sort((a, b) =>
      (STATUS_ORDER[a.status] ?? 9) - (STATUS_ORDER[b.status] ?? 9)
      || b.createdAt.localeCompare(a.createdAt)),
    [stations],
  );
  const active = sorted.filter((s) => s.status !== 'revoked');
  const revoked = sorted.filter((s) => s.status === 'revoked');
  const pendingCount = sorted.filter((s) => s.status === 'pending').length;

  const confirmDecision = async () => {
    if (!decision) return;
    setBusy(true);
    try {
      const { station, action } = decision;
      const result = action === 'approve'
        ? await benchStationsApi.approve(station.id)
        : await benchStationsApi.revoke(station.id);
      toast.success(
        action === 'approve'
          ? t('benchStations.approved', { defaultValue: '"{{name}}" is approved.', name: station.name })
          : t('benchStations.revoked', { defaultValue: '"{{name}}" is revoked.', name: station.name }),
      );
      setStations((prev) => prev.map((s) => (s.id === result.station.id ? result.station : s)));
      setDecision(null);
    } catch (err) {
      toast.error(errorText(err) ?? t('benchStations.decisionFailed', {
        defaultValue: 'The decision could not be recorded. Reload the list and try again.',
      }));
      void load(true);
    } finally {
      setBusy(false);
    }
  };

  const fmt = (iso: string | null) => formatWhen(iso, i18n.language);

  const renderRow = (s: BenchStation) => (
    <tr key={s.id} className={cn(s.status === 'pending' && 'bg-status-pending/5')}>
      <td className="px-4 py-3 align-top">
        <div className="font-medium text-text-primary">{s.name}</div>
        <div className="text-xs text-text-muted">{s.hostname ?? '—'}</div>
      </td>
      <td className="px-4 py-3 align-top">
        <StatusBadge status={s.status} />
        {s.status === 'approved' && s.approvedAt && (
          <div className="mt-1 text-xs text-text-muted">
            {t('benchStations.approvedBy', {
              defaultValue: 'by {{user}}, {{when}}',
              user: s.approvedByUsername ?? '—',
              when: fmt(s.approvedAt),
            })}
          </div>
        )}
        {s.status === 'revoked' && s.revokedAt && (
          <div className="mt-1 text-xs text-text-muted">
            {t('benchStations.approvedBy', {
              defaultValue: 'by {{user}}, {{when}}',
              user: s.revokedByUsername ?? '—',
              when: fmt(s.revokedAt),
            })}
          </div>
        )}
      </td>
      <td className="px-4 py-3 align-top">
        <span
          className={cn(
            'font-mono tracking-widest',
            s.status === 'pending' ? 'text-base font-semibold text-text-primary' : 'text-sm text-text-secondary',
          )}
        >
          {s.verificationCode ?? '—'}
        </span>
      </td>
      <td className="px-4 py-3 align-top text-xs text-text-secondary">{fmt(s.createdAt)}</td>
      <td className="px-4 py-3 align-top text-xs text-text-secondary">
        {s.lastSeenAt ? fmt(s.lastSeenAt) : t('benchStations.neverSeen', { defaultValue: 'never' })}
      </td>
      <td className="px-4 py-3 align-top font-mono text-xs text-text-secondary">{s.lastIp ?? '—'}</td>
      <td className="px-4 py-3 align-top text-right text-xs text-text-secondary">{s.enrolledDeviceCount}</td>
      <td className="px-4 py-3 align-top">
        <div className="flex justify-end gap-2">
          {s.status === 'pending' && (
            <Button size="sm" onClick={() => setDecision({ station: s, action: 'approve' })}>
              <ShieldCheck size={14} className="mr-1.5" />
              {t('benchStations.approve', { defaultValue: 'Approve' })}
            </Button>
          )}
          {s.status !== 'revoked' && (
            <Button size="sm" variant="secondary" onClick={() => setDecision({ station: s, action: 'revoke' })}>
              <ShieldOff size={14} className="mr-1.5" />
              {t('benchStations.revoke', { defaultValue: 'Revoke' })}
            </Button>
          )}
        </div>
      </td>
    </tr>
  );

  const header = (
    <thead className="border-b border-border text-left text-xs uppercase tracking-wide text-text-muted">
      <tr>
        <th className="px-4 py-2 font-medium">{t('benchStations.col.name', { defaultValue: 'Workstation' })}</th>
        <th className="px-4 py-2 font-medium">{t('benchStations.col.status', { defaultValue: 'Status' })}</th>
        <th className="px-4 py-2 font-medium">{t('benchStations.col.code', { defaultValue: 'Verification code' })}</th>
        <th className="px-4 py-2 font-medium">{t('benchStations.col.created', { defaultValue: 'Registered' })}</th>
        <th className="px-4 py-2 font-medium">{t('benchStations.col.lastSeen', { defaultValue: 'Last seen' })}</th>
        <th className="px-4 py-2 font-medium">{t('benchStations.col.lastIp', { defaultValue: 'Last address' })}</th>
        <th className="px-4 py-2 text-right font-medium">{t('benchStations.col.devices', { defaultValue: 'Routers prepared' })}</th>
        <th className="px-4 py-2" />
      </tr>
    </thead>
  );

  return (
    <div className="p-6">
      <div className="mb-2 flex items-center justify-between gap-4">
        <h1 className="flex items-center gap-2 text-2xl font-semibold text-text-primary">
          <MonitorCheck size={22} /> {t('benchStations.title', { defaultValue: 'Bench workstations' })}
        </h1>
        <Button size="sm" variant="secondary" onClick={() => void load()}>
          <RotateCw size={14} className="mr-1.5" />{t('common.refresh')}
        </Button>
      </div>
      <p className="mb-5 max-w-3xl text-sm text-text-secondary">
        {t('benchStations.intro', {
          defaultValue:
            'A bench workstation prepares routers before they leave for a customer site. A new workstation '
            + 'registers itself and waits here. Approve it only if the code on its screen matches the code '
            + 'on its row.',
        })}
      </p>

      {pendingCount > 0 && (
        <div className="mb-4 rounded-lg border border-status-pending/40 bg-status-pending/10 px-4 py-3 text-sm text-text-primary">
          {t('benchStations.pendingBanner', {
            defaultValue: '{{count}} workstation(s) waiting for approval.',
            count: pendingCount,
          })}
        </div>
      )}

      {loadError && (
        <div className="mb-4 rounded-lg border border-status-down/40 bg-status-down/10 px-4 py-3 text-sm text-status-down">
          {loadError}
        </div>
      )}

      {loading ? <LoadingSpinner /> : !loaded ? null : (
        <>
          <div className="overflow-x-auto rounded-lg border border-border bg-bg-secondary">
            {active.length === 0 && revoked.length > 0 ? (
              <div className="px-6 py-8 text-center">
                <p className="text-sm font-medium text-text-primary">
                  {t('benchStations.noActiveTitle', { defaultValue: 'No active workstation' })}
                </p>
                <p className="mx-auto mt-1 max-w-md text-xs text-text-secondary">
                  {t('benchStations.noActiveHint', {
                    defaultValue:
                      'Every workstation registered so far has been revoked (listed below). To use a bench again, '
                      + 'it must register again and be approved here as a new workstation.',
                  })}
                </p>
              </div>
            ) : active.length === 0 ? (
              <div className="px-6 py-12 text-center">
                <MonitorCheck size={28} className="mx-auto mb-3 text-text-muted" />
                <p className="text-sm font-medium text-text-primary">
                  {t('benchStations.emptyTitle', { defaultValue: 'No workstation yet' })}
                </p>
                <p className="mx-auto mt-1 max-w-md text-xs text-text-secondary">
                  {t('benchStations.emptyHint', {
                    defaultValue:
                      'Install the bench application on the preparation PC and start it: it registers itself '
                      + 'and appears here, waiting for your approval.',
                  })}
                </p>
              </div>
            ) : (
              <table className="w-full text-sm">
                {header}
                <tbody className="divide-y divide-border">{active.map(renderRow)}</tbody>
              </table>
            )}
          </div>

          {revoked.length > 0 && (
            <div className="mt-6">
              <button
                type="button"
                onClick={() => setShowRevoked((v) => !v)}
                className="mb-2 flex items-center gap-1 text-sm text-text-secondary hover:text-text-primary"
              >
                {showRevoked ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                {t('benchStations.revokedSection', {
                  defaultValue: 'Revoked workstations ({{count}})',
                  count: revoked.length,
                })}
              </button>
              {showRevoked && (
                <div className="overflow-x-auto rounded-lg border border-border bg-bg-secondary opacity-80">
                  <table className="w-full text-sm">
                    {header}
                    <tbody className="divide-y divide-border">{revoked.map(renderRow)}</tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </>
      )}

      {decision && (
        <StationDecisionDialog
          station={decision.station}
          action={decision.action}
          busy={busy}
          onConfirm={() => void confirmDecision()}
          onCancel={() => setDecision(null)}
        />
      )}
    </div>
  );
}

function StatusBadge({ status }: { status: BenchStationStatus }) {
  const { t } = useTranslation();
  const styles: Record<BenchStationStatus, string> = {
    pending: 'border-status-pending/40 bg-status-pending/10 text-status-pending',
    approved: 'border-status-up/40 bg-status-up/10 text-status-up',
    revoked: 'border-status-down/40 bg-status-down/10 text-status-down',
  };
  const labels: Record<BenchStationStatus, string> = {
    pending: t('benchStations.status.pending', { defaultValue: 'Waiting for approval' }),
    approved: t('benchStations.status.approved', { defaultValue: 'Approved' }),
    revoked: t('benchStations.status.revoked', { defaultValue: 'Revoked' }),
  };
  return (
    <span className={cn('inline-block rounded-full border px-2 py-0.5 text-[11px] font-medium', styles[status])}>
      {labels[status] ?? status}
    </span>
  );
}

/** Absolute date plus a relative hint, both from `Intl` so no string needs a
 *  translation. */
function formatWhen(iso: string | null, lang: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  const abs = d.toLocaleString(lang, { dateStyle: 'short', timeStyle: 'short' });
  const diffS = Math.round((d.getTime() - Date.now()) / 1000);
  const abs1 = Math.abs(diffS);
  const rtf = new Intl.RelativeTimeFormat(lang, { numeric: 'auto' });
  const rel =
    abs1 < 60 ? rtf.format(diffS, 'second')
      : abs1 < 3600 ? rtf.format(Math.round(diffS / 60), 'minute')
        : abs1 < 86_400 ? rtf.format(Math.round(diffS / 3600), 'hour')
          : rtf.format(Math.round(diffS / 86_400), 'day');
  return `${abs} (${rel})`;
}

function errorText(err: unknown): string | null {
  const m = (err as { response?: { data?: { error?: unknown } } }).response?.data?.error;
  return typeof m === 'string' && m.trim() !== '' ? m : null;
}
