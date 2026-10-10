import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { PlayCircle, RotateCw, Search, ShieldX, Unplug, X } from 'lucide-react';
import { ACTIVE_CHANGE_JOB_STATUSES, CHANGE_JOB_STATUSES, type ChangeJobStatus } from '@obliwan/shared';
import { changeApi, errorMessageOf, safetyNetOfLevel } from '@/api/change.api';
import { useChangeStore } from '@/store/changeStore';
import { useSocketStore } from '@/store/socketStore';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { JobKindChip, JobStatusBadge } from '@/components/change/JobStatusBadge';
import { SafetyNetBadge } from '@/components/change/SafetyNetBadge';
import { GuardVerdictBadge } from '@/components/plan/RiskBadge';
import { KillSwitchBanner, KillSwitchButton } from '@/components/change/KillSwitch';
import { useJobSocket } from '@/hooks/useJobSocket';
import { anonHostname } from '@/utils/anonymize';
import { cn } from '@/utils/cn';
import type { ChangeJobView } from '@/types/change';
import { GodViewMarker, GodViewTenantCell, GodViewTenantHeader } from '@/components/common/TenantBadge';
import { GodViewTenantFilter } from '@/components/common/GodViewTenantFilter';

/**
 * `ChangesPage` — the fleet-wide change queue.
 *
 * ── THE KILL SWITCH IS IN THE HEADER, NOT IN THE SETTINGS ───────────────────
 * This is the screen an operator is looking at when a change starts going
 * wrong, so this is where the stop button has to be. It is the first control in
 * the header, it is red, and it never scrolls away. Burying it three clicks
 * deep in an admin page is how a thirty-second incident becomes a five-minute
 * one.
 *
 * ── ACTIVE JOBS FIRST, ALWAYS ───────────────────────────────────────────────
 * `ACTIVE_CHANGE_JOB_STATUSES` is the same set the partial unique index
 * `change_jobs_one_in_flight_uq` is built on: a job in one of those states
 * HOLDS its device. Those rows are pinned to the top in their own section, with
 * live socket updates, because "what is touching my fleet right now" is the
 * only question this page exists to answer instantly. History is below and can
 * wait for a scroll.
 *
 * ── A JOB THAT ROLLED BACK IS NOT AN ERROR ──────────────────────────────────
 * The counters count `rolled_back` on its own line and never inside "failed".
 * The dead-man firing IS the machinery working, and a dashboard that reports it
 * as a failure teaches operators to disable the thing that saved them.
 */

const selectClass =
  'rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent';

const ACTIVE: ReadonlySet<string> = new Set(ACTIVE_CHANGE_JOB_STATUSES);

/** Page sizes offered; the server caps one request at 1000 (jobQuerySchema). */
const PAGE_SIZES = [25, 50, 100, 250, 500, 1000] as const;
const PAGE_SIZE_KEY = 'obliwan.changes.pageSize';
function storedPageSize(): number {
  try {
    const v = Number(window.localStorage.getItem(PAGE_SIZE_KEY));
    return (PAGE_SIZES as readonly number[]).includes(v) ? v : 100;
  } catch {
    return 100;
  }
}

export function ChangesPage() {
  const { t, i18n } = useTranslation();
  const fetchKillSwitch = useChangeStore((s) => s.fetchKillSwitch);
  const fetchPlanConfig = useChangeStore((s) => s.fetchPlanConfig);
  const socketStatus = useSocketStore((s) => s.status);

  const [jobs, setJobs] = useState<ChangeJobView[]>([]);
  const [loading, setLoading] = useState(true);
  const [unavailable, setUnavailable] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [search, setSearch] = useState('');
  const [status, setStatus] = useState<ChangeJobStatus | ''>('');
  // The search goes to the server (every job, not only the loaded page),
  // debounced so typing a site code is one request.
  const [searchQuery, setSearchQuery] = useState('');
  useEffect(() => {
    const h = window.setTimeout(() => setSearchQuery(search.trim()), 300);
    return () => window.clearTimeout(h);
  }, [search]);
  const [total, setTotal] = useState(0);
  const [statusCounts, setStatusCounts] = useState<Record<string, number> | null>(null);
  const [pageSize, setPageSize] = useState<number>(storedPageSize);
  const [page, setPage] = useState(0);
  // A new filter or page size starts again from the first page.
  useEffect(() => { setPage(0); }, [status, searchQuery, pageSize]);
  const pageCount = Math.max(1, Math.ceil(total / pageSize));

  const dateFmt = useMemo(
    () => new Intl.DateTimeFormat(i18n.language, { dateStyle: 'short', timeStyle: 'short' }),
    [i18n.language],
  );

  // One page of the list, filtered by the server over every job.
  const filterParams = useMemo(
    () => ({ limit: pageSize, offset: page * pageSize, status: status || undefined, search: searchQuery || undefined }),
    [status, searchQuery, pageSize, page],
  );
  const filterRef = useRef(filterParams);
  filterRef.current = filterParams;

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const page = await changeApi.listJobsPage(filterParams);
      if (page === null) { setUnavailable(true); setJobs([]); setTotal(0); setStatusCounts(null); }
      else { setUnavailable(false); setJobs(page.rows); setTotal(page.total); setStatusCounts(page.statusCounts); }
    } catch (err) {
      setLoadError(errorMessageOf(err) ?? t('change.loadFailed'));
    } finally {
      setLoading(false);
    }
  }, [t, filterParams]);

  const choosePageSize = (n: number): void => {
    setPageSize(n);
    try { window.localStorage.setItem(PAGE_SIZE_KEY, String(n)); } catch { /* a convenience only */ }
  };

  useEffect(() => {
    void load();
  }, [load]);
  useEffect(() => {
    void fetchKillSwitch();
    void fetchPlanConfig();
  }, [fetchKillSwitch, fetchPlanConfig]);

  // A job the list has not seen yet arrives by socket without its device and
  // site names (a frame carries neither): re-read the list quietly, once per
  // burst — a bulk attach queues dozens of jobs in a second.
  const jobsRef = useRef(jobs);
  jobsRef.current = jobs;
  const refreshTimer = useRef<number | null>(null);
  const refreshSoon = useCallback(() => {
    if (refreshTimer.current !== null) return;
    refreshTimer.current = window.setTimeout(() => {
      refreshTimer.current = null;
      // The page on screen again, with the same filters.
      changeApi.listJobsPage(filterRef.current)
        .then((res) => {
          if (res === null) return;
          setJobs(res.rows);
          setTotal(res.total);
          setStatusCounts(res.statusCounts);
        })
        .catch(() => { /* the next frame or a manual reload re-reads it */ });
    }, 1500);
  }, []);
  useEffect(() => () => {
    if (refreshTimer.current !== null) window.clearTimeout(refreshTimer.current);
  }, []);

  // Live: `wan:job:*` frames fold into the list in place. The tenant room is
  // already joined, so no per-job subscription is needed for the list view.
  // A frame never carries the device or site name: an empty one must not
  // overwrite the name the list already shows.
  useJobSocket({
    onJob: (job) => {
      // Decided on the rendered list, not inside the updater: React runs an
      // updater later, during render, so a flag set there is read too early.
      const unseen = !jobsRef.current.some((j) => j.id === job.id);
      setJobs((prev) => {
        const idx = prev.findIndex((j) => j.id === job.id);
        if (idx === -1) return [job, ...prev];
        const next = prev.slice();
        const was = next[idx];
        next[idx] = { ...was, ...job, deviceName: job.deviceName || was.deviceName, siteName: job.siteName || was.siteName, siteId: job.siteId ?? was.siteId };
        return next;
      });
      if (unseen) refreshSoon();
    },
  });

  // The server already filtered the page (status, search over device name,
  // site name and code); only a job a live frame moved to another status is
  // filtered here, so the table never shows a row its filter excludes.
  const filtered = useMemo(() => {
    const rows = jobs.filter((j) => !status || j.status === status);
    rows.sort((a, b) => {
      const aActive = ACTIVE.has(a.status) ? 1 : 0;
      const bActive = ACTIVE.has(b.status) ? 1 : 0;
      if (aActive !== bActive) return bActive - aActive;
      return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
    });
    return rows;
  }, [jobs, search, status]);

  const active = filtered.filter((j) => ACTIVE.has(j.status));
  const history = filtered.filter((j) => !ACTIVE.has(j.status));

  const counts = useMemo(() => {
    let succeeded = 0, rolledBack = 0, failed = 0, overridden = 0;
    for (const j of jobs) {
      if (j.status === 'succeeded') succeeded++;
      if (j.status === 'rolled_back') rolledBack++;
      if (j.status === 'failed') failed++;
      if (j.overrideReason) overridden++;
    }
    // The server's totals cover every matching job, beyond the loaded pages.
    if (statusCounts) {
      succeeded = statusCounts.succeeded ?? 0;
      rolledBack = statusCounts.rolled_back ?? 0;
      failed = statusCounts.failed ?? 0;
    }
    const active = statusCounts
      ? [...ACTIVE].reduce((n, s) => n + (statusCounts[s] ?? 0), 0)
      : jobs.filter((j) => ACTIVE.has(j.status)).length;
    return { active, succeeded, rolledBack, failed, overridden };
  }, [jobs, statusCounts]);

  return (
    <div className="p-6">
      <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 font-display text-2xl font-semibold text-text-primary">
            {t('nav.changes')}
            <GodViewMarker />
          </h1>
          <p className="mt-1 text-sm text-text-muted">{t('change.subtitle')}</p>
        </div>
        <div className="flex items-center gap-2">
          {/* The panic button. First, red, permanent. */}
          <KillSwitchButton />
          <GodViewTenantFilter onChange={() => void load()} />
          <Button variant="secondary" size="sm" onClick={() => void load()}>
            <RotateCw size={14} className={cn('mr-1.5', loading && 'animate-spin')} />
            {t('devices.refresh')}
          </Button>
        </div>
      </div>

      <KillSwitchBanner className="mb-4" />

      {socketStatus !== 'connected' && !unavailable && (
        <p className="mb-4 rounded-md border border-status-ssl-warning/40 bg-status-ssl-warning/5 p-2.5 text-[12px] text-status-ssl-warning">
          {t('change.socketDown')}
        </p>
      )}

      {!unavailable && jobs.length > 0 && (
        <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-5">
          <SummaryCard label={t('change.summary.active')} value={String(counts.active)} tone="muted" hint={t('change.summary.activeHint')} />
          <SummaryCard label={t('change.summary.succeeded')} value={String(counts.succeeded)} tone="ok" hint={t('change.summary.succeededHint')} />
          {/* Its own tile, never folded into "failed". */}
          <SummaryCard label={t('change.summary.rolledBack')} value={String(counts.rolledBack)} tone="warn" hint={t('change.summary.rolledBackHint')} />
          <SummaryCard label={t('change.summary.failed')} value={String(counts.failed)} tone={counts.failed > 0 ? 'bad' : 'ok'} hint={t('change.summary.failedHint')} />
          <SummaryCard label={t('change.summary.overridden')} value={String(counts.overridden)} tone={counts.overridden > 0 ? 'bad' : 'muted'} hint={t('change.summary.overriddenHint')} />
        </div>
      )}

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="relative">
          <Search size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t('change.searchPlaceholder')}
            className="w-64 rounded-md border border-border bg-bg-tertiary py-1.5 pl-8 pr-2.5 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
          />
        </div>
        <select
          className={selectClass}
          value={status}
          onChange={(e) => setStatus(e.target.value as ChangeJobStatus | '')}
        >
          <option value="">{t('change.filters.allStatuses')}</option>
          {CHANGE_JOB_STATUSES.map((s) => (
            <option key={s} value={s}>{t(`change.status.label.${s}`)}</option>
          ))}
        </select>
        {(search || status) && (
          <button
            onClick={() => { setSearch(''); setStatus(''); }}
            className="inline-flex items-center gap-1 rounded-md px-2 py-1.5 text-[12px] text-text-muted hover:bg-bg-hover hover:text-text-primary"
          >
            <X size={12} />
            {t('devices.filters.clear')}
          </button>
        )}
        <span className="ml-auto font-mono text-[11px] text-text-muted">
          {t('devices.showing', { shown: filtered.length, total: Math.max(total, jobs.length) })}
        </span>
      </div>

      {unavailable ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <Unplug size={28} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">{t('change.endpointUnavailable')}</p>
          <p className="mx-auto mt-1 max-w-xl text-xs text-text-muted">
            {t('change.endpointUnavailableHint')}
          </p>
        </div>
      ) : loadError ? (
        <div className="rounded-lg border border-status-ssl-expired/40 bg-status-ssl-expired/5 p-4 text-sm text-status-ssl-expired">
          {t('change.loadFailed')} — <span className="font-mono text-xs">{loadError}</span>
        </div>
      ) : loading && jobs.length === 0 ? (
        <div className="flex justify-center py-16"><LoadingSpinner size="lg" /></div>
      ) : jobs.length === 0 ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <PlayCircle size={28} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">{t('change.empty')}</p>
          <p className="mt-1 text-xs text-text-muted">{t('change.emptyHint')}</p>
        </div>
      ) : (
        <div className="space-y-6">
          {active.length > 0 && (
            <JobTable
              title={t('change.activeTitle')}
              hint={t('change.activeHint')}
              jobs={active}
              dateFmt={dateFmt}
              highlight
            />
          )}
          <JobTable
            title={t('change.historyTitle')}
            hint={t('change.historyHint')}
            jobs={history}
            dateFmt={dateFmt}
          />
          <div className="flex flex-wrap items-center justify-center gap-2 text-[12px] text-text-muted">
            <Button variant="ghost" size="sm" onClick={() => setPage(0)} disabled={page === 0 || loading}>«</Button>
            <Button variant="ghost" size="sm" onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={page === 0 || loading}>‹</Button>
            <span className="font-mono">
              {t('change.pager.page', {
                defaultValue: 'Page {{page}} / {{pages}} — {{total}} job(s)',
                page: page + 1,
                pages: pageCount,
                total,
              })}
            </span>
            <Button variant="ghost" size="sm" onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))} disabled={page >= pageCount - 1 || loading}>›</Button>
            <Button variant="ghost" size="sm" onClick={() => setPage(pageCount - 1)} disabled={page >= pageCount - 1 || loading}>»</Button>
            <select
              className={selectClass}
              value={pageSize}
              onChange={(e) => choosePageSize(Number(e.target.value))}
              aria-label={t('change.pager.size', { defaultValue: 'Jobs per page' })}
            >
              {PAGE_SIZES.map((n) => (
                <option key={n} value={n}>
                  {t('change.pager.perPage', { defaultValue: '{{count}} per page', count: n })}
                </option>
              ))}
            </select>
          </div>
        </div>
      )}
    </div>
  );
}

function JobTable({
  title,
  hint,
  jobs,
  dateFmt,
  highlight,
}: {
  title: string;
  hint: string;
  jobs: ChangeJobView[];
  dateFmt: Intl.DateTimeFormat;
  highlight?: boolean;
}) {
  const { t } = useTranslation();
  return (
    <section>
      <div className="mb-2">
        <h2 className="text-sm font-semibold text-text-primary">{title}</h2>
        <p className="text-[11px] text-text-muted">{hint}</p>
      </div>
      {jobs.length === 0 ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-8 text-center text-[13px] text-text-muted">
          {t('change.noneHere')}
        </div>
      ) : (
        <div
          className={cn(
            'overflow-x-auto rounded-lg border bg-bg-secondary',
            highlight ? 'border-accent/40' : 'border-border',
          )}
        >
          <table className="w-full min-w-[64rem] text-left text-[13px]">
            <thead className="border-b border-border text-[11px] uppercase tracking-wider text-text-muted">
              <tr>
                <th className="px-3 py-2 font-medium">{t('change.columns.device')}</th>
                <GodViewTenantHeader />
                <th className="px-3 py-2 font-medium">{t('change.columns.kind')}</th>
                <th className="px-3 py-2 font-medium">{t('change.columns.status')}</th>
                <th className="px-3 py-2 font-medium">{t('change.columns.safetyNet')}</th>
                <th className="px-3 py-2 font-medium">{t('change.columns.guard')}</th>
                <th className="px-3 py-2 font-medium">{t('change.columns.override')}</th>
                <th className="px-3 py-2 font-medium">{t('change.columns.created')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {jobs.map((j) => (
                <tr key={j.id} className="hover:bg-bg-hover">
                  <td className="px-3 py-2">
                    <Link to={`/changes/${j.id}`} className="block">
                      <span className="text-text-primary hover:text-accent">
                        {anonHostname(j.deviceName || `#${j.deviceId}`)}
                      </span>
                      <span className="block text-[11px] text-text-muted">{j.siteName ?? '—'}</span>
                    </Link>
                  </td>
                  <GodViewTenantCell name={j.tenantName} tenantId={j.tenantId} />
                  <td className="px-3 py-2">
                    <JobKindChip kind={j.kind} />
                    {j.origin && (
                      <span className="mt-0.5 block text-[11px] text-text-muted">
                        {t('change.origin.accessCheckNightly', {
                          defaultValue: 'automatic re-apply (nightly verification #{{run}})',
                          run: j.origin.run,
                        })}
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2"><JobStatusBadge status={j.status} /></td>
                  <td className="px-3 py-2">
                    <SafetyNetBadge level={safetyNetOfLevel(j.armedLevel ?? j.safetyLevel)} />
                  </td>
                  <td className="px-3 py-2">
                    {j.guardVerdict ? (
                      <GuardVerdictBadge state={j.guardVerdict} />
                    ) : (
                      <span className="text-[11px] text-text-muted">
                        {t('change.noGuardRecorded')}
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    {j.overrideReason ? (
                      <span
                        className="inline-flex items-center gap-1 rounded border border-status-ssl-expired/50 bg-status-ssl-expired/10 px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-status-ssl-expired"
                        title={j.overrideReason}
                      >
                        <ShieldX size={10} />
                        {t('change.overridden')}
                      </span>
                    ) : (
                      <span className="text-[11px] text-text-muted">—</span>
                    )}
                  </td>
                  <td className="px-3 py-2 font-mono text-[11px] text-text-muted">
                    {j.createdAt ? dateFmt.format(new Date(j.createdAt)) : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

const TONES = {
  ok: 'text-status-up',
  warn: 'text-status-ssl-warning',
  bad: 'text-status-ssl-expired',
  muted: 'text-text-primary',
};

function SummaryCard({
  label,
  value,
  tone,
  hint,
}: {
  label: string;
  value: string;
  tone: keyof typeof TONES;
  hint: string;
}) {
  return (
    <div className="rounded-lg border border-border bg-bg-secondary p-3" title={hint}>
      <div className="text-[11px] uppercase tracking-wider text-text-muted">{label}</div>
      <div className={cn('mt-1 font-display text-xl font-semibold tabular-nums', TONES[tone])}>
        {value}
      </div>
    </div>
  );
}
