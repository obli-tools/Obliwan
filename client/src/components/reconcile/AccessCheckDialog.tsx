import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { CheckCircle2, MinusCircle, RefreshCw, ShieldCheck, Wrench, X, XCircle } from 'lucide-react';
import {
  ACCESS_CHECK_FRESH_MS,
  type AccessCheckReapplyResult,
  type AccessCheckRow,
  type AccessCheckRunView,
} from '@obliwan/shared';
import { Button } from '@/components/common/Button';
import { accessCheckApi } from '@/api/accessCheck.api';
import { reconcileError } from '@/api/reconcile.api';

interface Props {
  onClose: () => void;
}

const TH = 'px-2 py-1.5 text-left text-xs font-medium text-text-muted';
const TD = 'px-2 py-1.5 text-sm text-text-primary align-top';
const POLL_MS = 3_000;

type Filter = 'all' | 'access' | 'fixes' | 'ok' | 'skipped';

/**
 * "Verify management access and compliance" of the reconciliation (server:
 * `/api/reconcile/access-check`, fleet/accessCheck.service.ts — CHANGE_APPLY,
 * narrowed to the routers the caller's teams grant `rw` on).
 *
 * Two steps, each saying what it does:
 *   1. the verification — read-only towards every router: presence, a live
 *      API-SSL proof of ObliWAN's access, the template fixes still missing, and
 *      the last failed management_access / legacy_compliance job, whose causes
 *      are grouped at the top. It runs in the background on the server and is
 *      kept there, so this dialog polls it and finds it again after a reload;
 *   2. the re-apply — offered only on a verification that is done, not
 *      re-applied yet and younger than ACCESS_CHECK_FRESH_MS, behind the
 *      attach dialog's own explicit confirmation of the degraded level
 *      (neither job arms a dead-man). The server queues, per marked router,
 *      management_access (the template fixes promised after it) or
 *      legacy_compliance with exactly the fixes found missing, and skips the
 *      rest, saying why.
 */
export function AccessCheckDialog({ onClose }: Props) {
  const { t, i18n } = useTranslation();
  const [run, setRun] = useState<AccessCheckRunView | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState<'start' | 'reapply' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>('all');
  const [confirmNoDeadman, setConfirmNoDeadman] = useState(false);
  const [result, setResult] = useState<AccessCheckReapplyResult | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const live = useRef(true);

  const load = useCallback(async () => {
    try {
      const v = await accessCheckApi.latest();
      if (live.current) {
        setRun(v);
        setError(null);
      }
    } catch (err) {
      if (live.current) setError(reconcileError(err).message);
    } finally {
      if (live.current) setLoaded(true);
    }
  }, []);

  useEffect(() => {
    live.current = true;
    void load();
    return () => {
      live.current = false;
    };
  }, [load]);

  // While a verification runs, poll it; the clock ticks for the freshness.
  useEffect(() => {
    const timer = setInterval(() => {
      setNow(Date.now());
      if (run?.status === 'running') void load();
    }, POLL_MS);
    return () => clearInterval(timer);
  }, [run?.status, load]);

  const start = async () => {
    setBusy('start');
    setError(null);
    setResult(null);
    setConfirmNoDeadman(false);
    try {
      setRun(await accessCheckApi.start());
    } catch (err) {
      setError(reconcileError(err).message);
    } finally {
      setBusy(null);
    }
  };

  const toReapply = useMemo(
    () => (run?.rows ?? []).filter((r) => r.action === 'management_access' || r.action === 'legacy_compliance'),
    [run],
  );
  const fresh = run !== null && run.status === 'done' && run.reappliedAt === null && now < Date.parse(run.freshUntil);

  const reapply = async () => {
    if (!run) return;
    setBusy('reapply');
    setError(null);
    try {
      const out = await accessCheckApi.reapply({ runId: run.runId, confirmNoDeadman: true });
      setResult(out);
      await load();
    } catch (err) {
      setError(reconcileError(err).message);
      await load();
    } finally {
      setBusy(null);
    }
  };

  const fmt = (iso: string | null): string => (iso ? new Date(iso).toLocaleString(i18n.language) : '—');

  const rows = useMemo(() => {
    const all = run?.rows ?? [];
    switch (filter) {
      case 'access':
        return all.filter((r) => r.action === 'management_access');
      case 'fixes':
        return all.filter((r) => r.action === 'legacy_compliance');
      case 'ok':
        return all.filter((r) => r.action === 'none');
      case 'skipped':
        return all.filter((r) => r.action === 'skip' || r.action === null);
      default:
        return all;
    }
  }, [run, filter]);

  const jobKind = (k: string | null) =>
    k === 'management_access'
      ? t('accessCheck.kind.management_access', { defaultValue: 'Management access' })
      : k === 'legacy_compliance'
        ? t('accessCheck.kind.legacy_compliance', { defaultValue: 'Template fixes' })
        : '—';
  const stepText = (s: string | null) => (s ? t(`accessCheck.step.${s}`, { defaultValue: s }) : '—');

  const presenceCell = (r: AccessCheckRow) => {
    if (!r.presence) return <span className="text-text-muted">—</span>;
    const cls = r.presence.state === 'up' || r.presence.state === 'not_applicable' ? 'text-text-primary' : 'text-amber-400';
    return (
      <span className={cls}>
        {t(`accessCheck.presence.${r.presence.state}`, { defaultValue: r.presence.state })}
        {r.presence.state === 'duplicated' && r.presence.sessions.length > 0 && (
          <span className="block text-xs text-text-muted">
            {r.presence.sessions.map((s) => s.callerId ?? '?').join(', ')}
          </span>
        )}
        {r.busy && (
          <span className="block text-xs text-amber-400">
            {t('accessCheck.busy', { defaultValue: 'job #{{id}} ({{kind}}) in progress', id: r.busy.jobId, kind: r.busy.kind })}
          </span>
        )}
      </span>
    );
  };

  const accessCell = (r: AccessCheckRow) => {
    const a = r.access;
    if (!a) return <span className="text-text-muted">{t('accessCheck.pending', { defaultValue: 'pending…' })}</span>;
    const cls = a.state === 'ok' ? 'text-green-400' : a.state === 'missing' || a.state === 'broken' ? 'text-status-down' : 'text-text-muted';
    return (
      <span className={cls}>
        {t(`accessCheck.access.${a.state}`, { defaultValue: a.state })}
        {a.reason && (
          <span className="block text-xs text-text-muted">{t(`accessCheck.accessReason.${a.reason}`, { defaultValue: a.reason })}</span>
        )}
        {a.detail && <span className="block max-w-xs truncate text-xs text-text-muted" title={a.detail}>{a.detail}</span>}
      </span>
    );
  };

  const complianceCell = (r: AccessCheckRow) => {
    const c = r.compliance;
    if (!c) return <span className="text-text-muted">—</span>;
    const cls = c.state === 'ok' ? 'text-green-400' : c.state === 'fixes_needed' ? 'text-amber-400' : 'text-text-muted';
    return (
      <span className={cls}>
        {t(`accessCheck.compliance.${c.state}`, { defaultValue: c.state })}
        {c.fixes.length > 0 && (
          <span className="block text-xs text-text-muted">{c.fixes.map((f) => t(`legacyCompliance.fix.${f}`, { defaultValue: f })).join(' ; ')}</span>
        )}
        {c.reason && (
          <span className="block text-xs text-text-muted">{t(`accessCheck.complianceReason.${c.reason}`, { defaultValue: c.reason })}</span>
        )}
        {c.unobserved.length > 0 && (
          <span className="block text-xs text-text-muted">
            {t('accessCheck.unobserved', {
              defaultValue: 'not established: {{list}}',
              list: c.unobserved.map((f) => t(`legacyCompliance.fix.${f}`, { defaultValue: f })).join(' ; '),
            })}
          </span>
        )}
      </span>
    );
  };

  const actionCell = (r: AccessCheckRow) => {
    if (r.action === null) return <span className="text-text-muted">—</span>;
    if (r.action === 'management_access' || r.action === 'legacy_compliance') {
      return (
        <span className="text-accent">
          {jobKind(r.action)}
          {r.action === 'management_access' && r.followUp && (
            <span className="block text-xs text-text-muted">
              {t('accessCheck.followUp', { defaultValue: 'then the template fixes' })}
            </span>
          )}
        </span>
      );
    }
    if (r.action === 'none') return <span className="text-green-400">{t('accessCheck.action.none', { defaultValue: 'nothing to do' })}</span>;
    return (
      <span className="text-text-muted">
        {t(`accessCheck.skip.${r.skipReason ?? 'access_unknown'}`, { defaultValue: r.skipReason ?? '' })}
        {r.refusal && (
          <span className="block max-w-xs text-xs" title={r.refusal.message}>
            {r.refusal.message}
          </span>
        )}
      </span>
    );
  };

  const reapplyCell = (r: AccessCheckRow) => {
    const x = r.reapply;
    if (!x) return null;
    // Held by the night's automatic re-apply (cap, learning, bench, a failed
    // previous automatic job): said why, in the server's own sentence too.
    if (x.status === 'skipped') {
      return (
        <span className="text-amber-400">
          {t(`accessCheck.autoSkip.${x.reason ?? 'cap'}`, { defaultValue: x.reason ?? '' })}
          {x.message && <span className="block max-w-xs text-xs text-text-muted">{x.message}</span>}
        </span>
      );
    }
    return (
      <span className={x.status === 'queued' ? 'text-green-400' : 'text-status-down'}>
        {x.status === 'queued'
          ? t('accessCheck.reapplied.queued', { defaultValue: 'job #{{id}} queued', id: x.jobId })
          : t('accessCheck.reapplied.refused', { defaultValue: 'refused' })}
        {x.message && <span className="block max-w-xs text-xs text-text-muted">{x.message}</span>}
      </span>
    );
  };

  const failuresCell = (r: AccessCheckRow) =>
    r.failures.length === 0 ? (
      <span className="text-text-muted">—</span>
    ) : (
      <>
        {r.failures.map((f) => (
          <span key={f.jobId} className="block text-xs">
            <Link to={`/changes/${f.jobId}`} className="text-accent hover:underline" onClick={onClose}>
              #{f.jobId}
            </Link>{' '}
            {jobKind(f.kind)} · {stepText(f.step)}
            {f.message && (
              <span className="block max-w-xs truncate text-text-muted" title={f.message}>
                {f.message}
              </span>
            )}
          </span>
        ))}
      </>
    );

  const counts = run?.counts;
  const tabs: Array<[Filter, string, number]> = counts
    ? [
        ['all', t('accessCheck.filter.all', { defaultValue: 'All' }), counts.total],
        ['access', t('accessCheck.filter.access', { defaultValue: 'Access to restore' }), counts.needsAccess],
        ['fixes', t('accessCheck.filter.fixes', { defaultValue: 'Fixes to apply' }), counts.needsFixes],
        ['ok', t('accessCheck.filter.ok', { defaultValue: 'In order' }), counts.ok],
        ['skipped', t('accessCheck.filter.skipped', { defaultValue: 'Skipped' }), counts.skipped + counts.pending],
      ]
    : [];

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4">
      <div className="my-8 w-full max-w-6xl rounded-xl border border-border bg-bg-secondary shadow-2xl">
        <div className="flex items-center gap-2 border-b border-border px-5 py-4">
          <ShieldCheck size={18} className="text-accent" />
          <h2 className="flex-1 text-base font-semibold text-text-primary">
            {t('accessCheck.title', { defaultValue: 'Verify management access and compliance' })}
          </h2>
          <button
            type="button"
            onClick={onClose}
            disabled={busy === 'reapply'}
            className="rounded p-1 text-text-muted hover:text-text-primary disabled:opacity-50"
            aria-label={t('accessCheck.close', { defaultValue: 'Close' })}
          >
            <X size={16} />
          </button>
        </div>

        <div className="space-y-4 p-5">
          <p className="text-sm text-text-muted">
            {t('accessCheck.intro', {
              defaultValue:
                "The verification writes nothing to any router. For each active MikroTik of the workspace it checks the PPP session (offline, login used by several sessions, a job already running), opens a fresh API-SSL session with the recorded account and the pinned certificate and checks the router's identity, reads over SSH which template fixes are still missing (the compliance job's own reading), and shows why the last management access or compliance job failed. The re-apply then queues, only for the routers that need it, the management access job (the template fixes following once it has succeeded) or the compliance job with exactly the missing fixes.",
            })}
          </p>

          {!loaded && <p className="text-sm text-text-muted">{t('accessCheck.loading', { defaultValue: 'Reading…' })}</p>}

          {loaded && (
            <div className="flex flex-wrap items-center gap-3">
              <Button size="sm" onClick={() => void start()} loading={busy === 'start'} disabled={busy !== null || run?.status === 'running'}>
                <RefreshCw size={14} />{' '}
                {run
                  ? t('accessCheck.rerun', { defaultValue: 'Verify again' })
                  : t('accessCheck.run', { defaultValue: 'Run the verification' })}
              </Button>
              {run && (
                <span className="text-xs text-text-muted">
                  {run.trigger === 'nightly'
                    ? t('accessCheck.runInfoNightly', {
                        defaultValue: 'Nightly verification #{{number}} of {{date}} (automatic)',
                        number: run.number,
                        date: fmt(run.startedAt),
                      })
                    : t('accessCheck.runInfo', {
                        defaultValue: 'Verification of {{date}} by {{user}}',
                        date: fmt(run.startedAt),
                        user: run.requestedBy?.username ?? '—',
                      })}
                  {run.scope === 'teams' && ` — ${t('accessCheck.scopeTeams', { defaultValue: 'your teams’ routers only' })}`}
                  {run.status === 'interrupted' && ` — ${t('accessCheck.interrupted', { defaultValue: 'interrupted (server restart): verify again' })}`}
                  {run.reappliedAt &&
                    ` — ${
                      run.reapplyTrigger === 'nightly'
                        ? t('accessCheck.reappliedByNight', { defaultValue: 're-applied automatically {{date}}', date: fmt(run.reappliedAt) })
                        : t('accessCheck.reappliedAt', { defaultValue: 're-applied {{date}}', date: fmt(run.reappliedAt) })
                    }`}
                </span>
              )}
            </div>
          )}

          {run?.status === 'running' && counts && (
            <div>
              <div className="mb-1 text-xs text-text-muted">
                {t('accessCheck.progress', {
                  defaultValue: '{{done}} / {{total}} routers verified…',
                  done: counts.total - counts.pending,
                  total: counts.total,
                })}
              </div>
              <div className="h-2 w-full overflow-hidden rounded bg-bg-primary">
                <div
                  className="h-2 bg-accent transition-all"
                  style={{ width: `${counts.total === 0 ? 0 : Math.round(((counts.total - counts.pending) / counts.total) * 100)}%` }}
                />
              </div>
            </div>
          )}

          {run && run.status !== 'running' && (run.offline > 0 || run.autoReapply) && (
            <div className="space-y-0.5 text-xs text-text-muted">
              {run.offline > 0 && (
                <p>
                  {t('accessCheck.offlineCount', {
                    defaultValue: '{{count}} router(s) offline: not verified and not alerted here (presence is the concentrator’s job).',
                    count: run.offline,
                  })}
                </p>
              )}
              {run.autoReapply && (
                <p>
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
            </div>
          )}

          {/* ── Why the last jobs failed ─────────────────────────────── */}
          {run && run.causes.length > 0 && (
            <div>
              <h3 className="mb-2 text-sm font-semibold text-text-primary">
                {t('accessCheck.causes.title', { defaultValue: 'Why the last jobs failed' })}
              </h3>
              <div className="max-h-60 overflow-auto rounded-md border border-border">
                <table className="w-full">
                  <thead className="sticky top-0 bg-bg-secondary">
                    <tr>
                      <th className={TH}>{t('accessCheck.causes.count', { defaultValue: 'Routers' })}</th>
                      <th className={TH}>{t('accessCheck.causes.job', { defaultValue: 'Job' })}</th>
                      <th className={TH}>{t('accessCheck.causes.step', { defaultValue: 'Failed step' })}</th>
                      <th className={TH}>{t('accessCheck.causes.message', { defaultValue: 'Message' })}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {run.causes.map((c, i) => (
                      <tr key={i} className="border-t border-border">
                        <td className={`${TD} font-semibold`}>{c.count}</td>
                        <td className={TD}>{jobKind(c.kind)}</td>
                        <td className={TD}>
                          {stepText(c.step)}
                          {c.errorKind && <span className="block text-xs text-text-muted">{c.errorKind}</span>}
                        </td>
                        <td className={`${TD} text-xs text-text-secondary`}>{c.message ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ── The routers ──────────────────────────────────────────── */}
          {run && (
            <div>
              <div className="mb-2 flex flex-wrap gap-1">
                {tabs.map(([k, label, n]) => (
                  <button
                    key={k}
                    type="button"
                    onClick={() => setFilter(k)}
                    className={`rounded-md px-2.5 py-1 text-xs ${filter === k ? 'bg-accent text-white' : 'bg-bg-primary text-text-secondary hover:text-text-primary'}`}
                  >
                    {label} ({n})
                  </button>
                ))}
              </div>
              <div className="max-h-[28rem] overflow-auto rounded-md border border-border">
                <table className="w-full">
                  <thead className="sticky top-0 bg-bg-secondary">
                    <tr>
                      <th className={TH}>{t('accessCheck.col.device', { defaultValue: 'Router' })}</th>
                      <th className={TH}>{t('accessCheck.col.presence', { defaultValue: 'Presence' })}</th>
                      <th className={TH}>{t('accessCheck.col.access', { defaultValue: 'Management access' })}</th>
                      <th className={TH}>{t('accessCheck.col.compliance', { defaultValue: 'Template fixes' })}</th>
                      <th className={TH}>{t('accessCheck.col.failures', { defaultValue: 'Last failure' })}</th>
                      <th className={TH}>{t('accessCheck.col.action', { defaultValue: 'Re-apply' })}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((r) => (
                      <tr key={r.deviceId} className="border-t border-border">
                        <td className={TD}>
                          <Link to={`/devices/${r.deviceId}`} className="text-accent hover:underline" onClick={onClose}>
                            {r.deviceName}
                          </Link>
                          {r.site && <span className="block text-xs text-text-muted font-mono">{r.site.code}</span>}
                        </td>
                        <td className={TD}>{presenceCell(r)}</td>
                        <td className={TD}>{accessCell(r)}</td>
                        <td className={TD}>{complianceCell(r)}</td>
                        <td className={TD}>{failuresCell(r)}</td>
                        <td className={TD}>
                          {actionCell(r)}
                          {reapplyCell(r)}
                        </td>
                      </tr>
                    ))}
                    {rows.length === 0 && (
                      <tr>
                        <td className={`${TD} text-text-muted`} colSpan={6}>
                          {t('accessCheck.none', { defaultValue: 'No router in this list.' })}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ── The re-apply ─────────────────────────────────────────── */}
          {run && run.status === 'done' && run.reappliedAt === null && toReapply.length > 0 && (
            <div className="rounded-md border border-border p-3">
              {!fresh && (
                <p className="mb-2 text-xs text-amber-400">
                  {t('accessCheck.stale', {
                    defaultValue: 'This verification is more than {{minutes}} minutes old: verify again before re-applying.',
                    minutes: Math.round(ACCESS_CHECK_FRESH_MS / 60_000),
                  })}
                </p>
              )}
              <label className="flex items-start gap-2 rounded-md border border-status-ssl-warning/50 bg-status-ssl-warning/5 p-3 text-[12px] text-text-secondary">
                <input
                  type="checkbox"
                  className="mt-0.5"
                  checked={confirmNoDeadman}
                  disabled={!fresh}
                  onChange={(e) => setConfirmNoDeadman(e.target.checked)}
                />
                <span>
                  {t('reconcileAttach.followUps.confirm', {
                    defaultValue:
                      'I confirm the degraded safety level of these jobs, for the whole batch: no dead-man is armed. ' +
                      'Management access only writes /certificate, the api-ssl service and, when missing, ObliWAN\'s own ' +
                      '"obliwan" group and user — and, the one existing account or group it changes, adds the "sensitive" policy to an ' +
                      '"obliwan" group ObliWAN made earlier when it is the only policy that group lacks — then switches ' +
                      'ObliWAN to that account once a login with it is proven; the ' +
                      'template fixes only open mac-server, mac-winbox and RoMON, add the DNS-Amp rules and add the store ' +
                      'LAN to the ssh and winbox lists. Each job pulls a pre-change backup first; without one nothing is written.',
                  })}
                </span>
              </label>
            </div>
          )}

          {result && (
            <div className="rounded-md border border-border p-3 text-sm">
              <div className="mb-1 flex flex-wrap items-center gap-3">
                <span className="flex items-center gap-1 text-green-400">
                  <CheckCircle2 size={14} />
                  {t('accessCheck.result.queued', { defaultValue: '{{count}} job(s) queued', count: result.counts.queued })}
                </span>
                <span className="flex items-center gap-1 text-status-down">
                  <XCircle size={14} />
                  {t('accessCheck.result.refused', { defaultValue: '{{count}} refused', count: result.counts.refused })}
                </span>
                <span className="flex items-center gap-1 text-text-muted">
                  <MinusCircle size={14} />
                  {t('accessCheck.result.skipped', { defaultValue: '{{count}} skipped', count: result.counts.skipped })}
                </span>
              </div>
              <p className="text-xs text-text-muted">
                {t('accessCheck.result.help', {
                  defaultValue:
                    'Follow the jobs on the Changes page. The template fixes promised after a management access job are queued by ObliWAN once that job has succeeded.',
                })}
              </p>
            </div>
          )}

          {error && <p className="text-sm text-status-down">{error}</p>}
        </div>

        <div className="flex flex-wrap items-center justify-end gap-2 border-t border-border px-5 py-3">
          <span className="mr-auto flex items-center gap-1 text-xs text-text-muted">
            <Wrench size={12} />
            {t('accessCheck.footer', { defaultValue: 'The verification is read-only; only the re-apply queues jobs.' })}
          </span>
          <Button size="sm" variant="secondary" onClick={onClose} disabled={busy === 'reapply'}>
            {t('accessCheck.close', { defaultValue: 'Close' })}
          </Button>
          {run && run.status === 'done' && run.reappliedAt === null && toReapply.length > 0 && (
            <Button
              size="sm"
              onClick={() => void reapply()}
              loading={busy === 'reapply'}
              disabled={busy !== null || !fresh || !confirmNoDeadman}
            >
              {t('accessCheck.reapply', { defaultValue: 'Re-apply on {{count}} router(s)', count: toReapply.length })}
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}

export default AccessCheckDialog;
