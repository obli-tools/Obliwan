import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  Info,
  RefreshCcw,
  Rocket,
  RotateCw,
  Search,
  Unplug,
  X,
} from 'lucide-react';
import { CAPABILITIES } from '@obliwan/shared';
import { useAuthStore } from '@/store/authStore';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { UpgradeStatusBadge, useUpgradeStatusLabel } from '@/components/firmware/UpgradeStatusBadge';
import { UpgradeProgressCell } from '@/components/firmware/UpgradeProgressCell';
import { UpgradeConfirmDialog } from '@/components/firmware/UpgradeConfirmDialog';
import { useRefusalText } from '@/components/firmware/refusals';
import { anonHostname } from '@/utils/anonymize';
import { cn } from '@/utils/cn';
import {
  MAX_UPGRADE_DEVICES,
  UPGRADE_STATUSES,
  isUpgradeRouteAbsent,
  launchErrorOf,
  osUpgradeApi,
  type LaunchResult,
  type UpgradeDevice,
  type UpgradeListing,
  type UpgradeStatus,
} from '@/api/osUpgrade.api';
import { GodViewMarker, TenantBadge } from '@/components/common/TenantBadge';
import { GodViewTenantFilter } from '@/components/common/GodViewTenantFilter';

/**
 * `FleetUpgradePage` - "mise a jour du parc".
 *
 * Built for somebody who is not a network engineer. The page answers one
 * question first, in one sentence ("12 routers behind RouterOS 7.24.5"), then
 * offers one gesture: tick, "Update", read, sign.
 *
 * ── WHAT THE PAGE DECIDES, AND WHAT IT DOES NOT ────────────────────────────
 * Every status, every "cannot be selected" and every refusal comes from the
 * server (`/api/os-upgrade`), which is the only place they are computed. The
 * page filters and selects; it never decides that a router is behind, and it
 * never selects a router the server marked as blocked.
 *
 * ── LIVE ───────────────────────────────────────────────────────────────────
 * While any update or version re-read is running (or for two minutes after a
 * launch, the time it takes a rollout's first job to appear), the listing is
 * re-read every five seconds. Otherwise it is read once and on demand: polling
 * an idle fleet is load for nothing. A poll never starts while the previous
 * read is still in flight, and only the NEWEST read is applied, so a slow
 * answer can never step a row back. A failed poll says so above the table
 * instead of leaving frozen progress on screen.
 *
 * ── HOW OLD IS WHAT THE TABLE SAYS ─────────────────────────────────────────
 * A status is only as true as the version reading behind it, and nothing
 * re-reads versions on a timer. Each row marks a reading that is undated or
 * older than the server's threshold, and "Re-read versions" (DEVICE_WRITE)
 * asks the routers again; the refresh button only re-reads the database.
 *
 * ── SELECTION ──────────────────────────────────────────────────────────────
 * The bulk gestures act on the rows SHOWN. A selection that the filters now
 * hide is announced with a way to drop it, and the confirmation dialog names
 * every router anyway: what is signed is a list, not a count.
 */

const POLL_MS = 5_000;
const LAUNCH_WATCH_MS = 120_000;

const selectClass =
  'rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent';

/** `7.24.5 (stable)` -> `7.24.5`, for display and for the version filter. */
function shortVersion(v: string | null): string | null {
  if (!v) return null;
  return v.replace(/\s*\([^)]*\)\s*$/, '').trim() || null;
}

const NO_VERSION = '__none__';

export function FleetUpgradePage() {
  const { t, i18n } = useTranslation();
  const statusLabel = useUpgradeStatusLabel();
  const refusalText = useRefusalText();
  const hasCapability = useAuthStore((s) => s.hasCapability);
  const canApply = hasCapability(CAPABILITIES.CHANGE_APPLY);
  const canRollout = hasCapability(CAPABILITIES.ROLLOUT_MANAGE);
  const canApprove = hasCapability(CAPABILITIES.CHANGE_APPROVE);
  const canReread = hasCapability(CAPABILITIES.DEVICE_WRITE);

  const [listing, setListing] = useState<UpgradeListing | null>(null);
  const [loading, setLoading] = useState(true);
  const [unavailable, setUnavailable] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [loadedAt, setLoadedAt] = useState<number | null>(null);
  const [refreshStarting, setRefreshStarting] = useState(false);
  const [refreshError, setRefreshError] = useState<string | null>(null);
  const inFlight = useRef(false);
  const readSeq = useRef(0);

  const [search, setSearch] = useState('');
  const [client, setClient] = useState('');
  const [site, setSite] = useState('');
  const [version, setVersion] = useState('');
  const [status, setStatus] = useState<UpgradeStatus | ''>('');

  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [confirming, setConfirming] = useState(false);
  const [launched, setLaunched] = useState<LaunchResult | null>(null);
  const [watchingLaunch, setWatchingLaunch] = useState(false);

  const dateFmt = useMemo(
    () => new Intl.DateTimeFormat(i18n.language, { dateStyle: 'short', timeStyle: 'short' }),
    [i18n.language],
  );

  /** `full` shows the spinner; `quiet` does not; `poll` is also skipped while
   *  another read is in flight. Only the newest read's answer is applied. */
  const load = useCallback(
    async (mode: 'full' | 'quiet' | 'poll' = 'full') => {
      if (mode === 'poll' && inFlight.current) return;
      const mine = ++readSeq.current;
      inFlight.current = true;
      if (mode === 'full') setLoading(true);
      try {
        const data = await osUpgradeApi.listDevices();
        if (mine !== readSeq.current) return;
        setListing(data);
        setLoadedAt(Date.now());
        setUnavailable(false);
        setLoadError(null);
        // A router that became blocked (a job started, it reached the target)
        // leaves the selection: the button must never count a box the server
        // would refuse.
        setSelected((prev) => {
          const selectable = new Set(data.devices.filter((d) => d.blockedReason === null).map((d) => d.id));
          const next = new Set([...prev].filter((id) => selectable.has(id)));
          return next.size === prev.size ? prev : next;
        });
      } catch (err) {
        if (mine !== readSeq.current) return;
        if (isUpgradeRouteAbsent(err)) setUnavailable(true);
        else setLoadError(launchErrorOf(err).message ?? t('fleetUpgrade.loadFailed', { defaultValue: 'Could not load the fleet.' }));
      } finally {
        if (mine === readSeq.current) inFlight.current = false;
        if (mode === 'full') setLoading(false);
      }
    },
    [t],
  );

  useEffect(() => {
    void load();
  }, [load]);

  const anyRunning = useMemo(
    () =>
      listing
        ? listing.counts.in_progress > 0 ||
          listing.devices.some((d) => d.activeJob !== null) ||
          listing.refresh?.running === true
        : false,
    [listing],
  );
  const polling = anyRunning || watchingLaunch;

  useEffect(() => {
    if (!polling) return;
    const id = window.setInterval(() => void load('poll'), POLL_MS);
    return () => window.clearInterval(id);
  }, [polling, load]);

  const startReread = async () => {
    setRefreshStarting(true);
    setRefreshError(null);
    try {
      await osUpgradeApi.refreshVersions();
    } catch (err) {
      const e = launchErrorOf(err);
      setRefreshError(
        e.code === 'nothing_to_read'
          ? t('fleetUpgrade.reread.nothing', { defaultValue: 'No router needs its version re-read.' })
          : e.code === 'refresh_running'
            ? t('fleetUpgrade.reread.alreadyRunning', { defaultValue: 'A re-read is already running.' })
            : e.message ?? t('fleetUpgrade.reread.failed', { defaultValue: 'The re-read could not be started.' }),
      );
    } finally {
      setRefreshStarting(false);
      void load('quiet');
    }
  };

  useEffect(() => {
    if (!watchingLaunch) return;
    const id = window.setTimeout(() => setWatchingLaunch(false), LAUNCH_WATCH_MS);
    return () => window.clearTimeout(id);
  }, [watchingLaunch]);

  const devices = listing?.devices ?? [];

  const clients = useMemo(
    () => [...new Set(devices.map((d) => d.clientName).filter((v): v is string => !!v))].sort(),
    [devices],
  );
  const sites = useMemo(
    () => [...new Set(devices.map((d) => d.siteName).filter((v): v is string => !!v))].sort(),
    [devices],
  );
  const versions = useMemo(
    () =>
      [...new Set(devices.map((d) => shortVersion(d.currentVersion)).filter((v): v is string => !!v))].sort((a, b) =>
        b.localeCompare(a, undefined, { numeric: true }),
      ),
    [devices],
  );

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return devices.filter((d) => {
      if (status && d.status !== status) return false;
      if (client && d.clientName !== client) return false;
      if (site && d.siteName !== site) return false;
      if (version) {
        const v = shortVersion(d.currentVersion);
        if (version === NO_VERSION ? v !== null : v !== version) return false;
      }
      if (!needle) return true;
      return [d.name, d.model, d.siteName, d.clientName, d.groupName]
        .filter(Boolean)
        .some((v) => String(v).toLowerCase().includes(needle));
    });
  }, [devices, search, status, client, site, version]);

  const selectableVisible = filtered.filter((d) => d.blockedReason === null);
  const allVisibleSelected = selectableVisible.length > 0 && selectableVisible.every((d) => selected.has(d.id));
  const hiddenSelected = useMemo(() => {
    const shown = new Set(filtered.map((d) => d.id));
    return [...selected].filter((id) => !shown.has(id));
  }, [filtered, selected]);
  const behindVisible = selectableVisible.filter((d) => d.status === 'behind');
  const tooMany = selected.size > MAX_UPGRADE_DEVICES;

  const toggle = (id: number) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  const toggleVisible = () =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (allVisibleSelected) selectableVisible.forEach((d) => next.delete(d.id));
      else selectableVisible.forEach((d) => next.add(d.id));
      return next;
    });
  // The routers behind among those SHOWN, never past the server's ceiling.
  const selectBehind = () => setSelected(new Set(behindVisible.slice(0, MAX_UPGRADE_DEVICES).map((d) => d.id)));
  const deselectHidden = () =>
    setSelected((prev) => {
      const next = new Set(prev);
      hiddenSelected.forEach((id) => next.delete(id));
      return next;
    });

  const filtersActive = !!(search || client || site || version || status);
  const clearFilters = () => {
    setSearch('');
    setClient('');
    setSite('');
    setVersion('');
    setStatus('');
  };

  const launchBlocked = !listing || !listing.launch.available || listing.killSwitch.blocked || !canApply;
  const selectedIds = useMemo(() => [...selected].sort((a, b) => a - b), [selected]);

  const onLaunched = (result: LaunchResult) => {
    setConfirming(false);
    setLaunched(result);
    setSelected(new Set());
    setWatchingLaunch(true);
    void load('quiet');
  };

  const nameOf = (id: number) => anonHostname(devices.find((d) => d.id === id)?.name ?? `#${id}`);
  const refresh = listing?.refresh ?? null;

  // ── Render ──────────────────────────────────────────────────────────────

  const target = listing?.target ?? null;

  return (
    <div className="p-6">
      <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 font-display text-2xl font-semibold text-text-primary">
            {t('fleetUpgrade.title', { defaultValue: 'Fleet update' })}
            <GodViewMarker />
          </h1>
          <p className="mt-1 text-sm text-text-muted">
            {t('fleetUpgrade.subtitle', {
              defaultValue: 'The RouterOS version of every router, compared with the fleet target.',
            })}
          </p>
        </div>
        <GodViewTenantFilter onChange={() => void load()} className="ml-auto" />
        <Button variant="secondary" size="sm" onClick={() => void load()}>
          <RotateCw size={14} className={cn('mr-1.5', loading && 'animate-spin')} />
          {t('fleetUpgrade.refresh', { defaultValue: 'Refresh' })}
        </Button>
      </div>

      {unavailable ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <Unplug size={28} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">
            {t('fleetUpgrade.endpointUnavailable', {
              defaultValue: 'This server does not offer the fleet update yet.',
            })}
          </p>
        </div>
      ) : loadError && !listing ? (
        <div className="rounded-lg border border-status-ssl-expired/40 bg-status-ssl-expired/5 p-4 text-sm text-status-ssl-expired">
          {t('fleetUpgrade.loadFailed', { defaultValue: 'Could not load the fleet.' })} —{' '}
          <span className="font-mono text-xs">{loadError}</span>
        </div>
      ) : !listing ? (
        <div className="flex justify-center py-16">
          <LoadingSpinner size="lg" />
        </div>
      ) : (
        <>
          {/* ── The one sentence ─────────────────────────────────────────── */}
          <div className="mb-4 rounded-lg border border-border bg-bg-secondary p-4">
            {target?.version ? (
              <>
                <p
                  className={cn(
                    'font-display text-xl font-semibold',
                    listing.counts.behind > 0 ? 'text-status-ssl-warning' : 'text-status-up',
                  )}
                >
                  {listing.counts.behind > 0
                    ? t('fleetUpgrade.summary.behind', {
                        count: listing.counts.behind,
                        version: target.version,
                        defaultValue: '{{count}} router(s) behind RouterOS {{version}}',
                      })
                    : t('fleetUpgrade.summary.noneBehind', {
                        version: target.version,
                        defaultValue: 'No router behind RouterOS {{version}}',
                      })}
                </p>
                {listing.counts.behind > 0 && listing.counts.behindSelectable !== listing.counts.behind && (
                  <p className="mt-1 text-[13px] text-text-secondary">
                    {t('fleetUpgrade.summary.selectable', {
                      count: listing.counts.behindSelectable,
                      defaultValue:
                        '{{count}} of them can be updated now; each of the others says why on its row.',
                    })}
                  </p>
                )}
                <p className="mt-1 text-[12px] text-text-muted">
                  {target.mode &&
                    t(`fleetUpgrade.summary.mode.${target.mode}`, {
                      defaultValue:
                        target.mode === 'pinned'
                          ? 'version pinned by an administrator'
                          : target.mode === 'long-term'
                            ? 'latest long-term release'
                            : 'latest stable release',
                    })}
                  {target.observedAt &&
                    ` · ${t('fleetUpgrade.summary.readAt', {
                      date: dateFmt.format(new Date(target.observedAt)),
                      defaultValue: 'read {{date}}',
                    })}`}
                </p>
                {target.stale && (
                  <p className="mt-2 flex items-center gap-1.5 text-[12px] text-status-ssl-warning">
                    <AlertTriangle size={13} />
                    {t('fleetUpgrade.summary.stale', {
                      defaultValue:
                        "The last successful read of MikroTik's releases is old: a newer version may exist.",
                    })}
                  </p>
                )}
              </>
            ) : (
              <>
                <p className="font-display text-xl font-semibold text-text-secondary">
                  {t('fleetUpgrade.summary.noTarget', { defaultValue: 'No target version known yet' })}
                </p>
                <p className="mt-1 text-[12px] text-text-muted">
                  {target?.unresolvedReason === 'TARGET_UNREADABLE'
                    ? t('fleetUpgrade.summary.noTargetHint.TARGET_UNREADABLE', {
                        defaultValue:
                          'The stored target setting could not be read. An administrator must set it again in Settings.',
                      })
                    : t('fleetUpgrade.summary.noTargetHint.NO_RELEASE_KNOWN', {
                        defaultValue:
                          'The RouterOS release watch has not read a version from MikroTik yet. It checks once every 24 hours; an administrator can force a check in Settings.',
                      })}
                </p>
              </>
            )}

            {/* ── How old the readings are, and the way to renew them ───────── */}
            {(listing.counts.needsReading > 0 || refresh) && (
              <div className="mt-3 space-y-1.5 border-t border-border pt-3 text-[12px]">
                {listing.counts.needsReading > 0 && (
                  <div className="flex flex-wrap items-center gap-2">
                    <Clock size={13} className="shrink-0 text-status-ssl-warning" />
                    <span className="text-text-secondary">
                      {t('fleetUpgrade.reread.needed', {
                        count: listing.counts.needsReading,
                        days: listing.versionMaxAgeDays,
                        defaultValue:
                          '{{count}} router(s) have no version reading, or one older than {{days}} days: their status may be out of date.',
                      })}
                    </span>
                    {canReread && (
                      <Button
                        variant="secondary"
                        size="sm"
                        disabled={refreshStarting || refresh?.running === true}
                        loading={refreshStarting}
                        onClick={() => void startReread()}
                      >
                        <RefreshCcw size={13} className="mr-1.5" />
                        {t('fleetUpgrade.reread.button', { defaultValue: 'Re-read versions' })}
                      </Button>
                    )}
                  </div>
                )}
                {refresh?.running && (
                  <p className="flex items-center gap-1.5 text-text-muted">
                    <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-accent" />
                    {t('fleetUpgrade.reread.running', {
                      done: refresh.done,
                      total: refresh.total,
                      defaultValue: 'Re-reading versions off the routers: {{done}} of {{total}}…',
                    })}
                  </p>
                )}
                {refresh && !refresh.running && refresh.finishedAt && (
                  <p className="text-text-muted">
                    {t('fleetUpgrade.reread.done', {
                      date: dateFmt.format(new Date(refresh.finishedAt)),
                      ok: refresh.ok,
                      failed: refresh.failed,
                      defaultValue: 'Last re-read {{date}}: {{ok}} answered, {{failed}} did not answer.',
                    })}
                    {refresh.failedDeviceIds.length > 0 && (
                      <span className="ml-1 font-mono text-[11px]">
                        {refresh.failedDeviceIds.slice(0, 8).map(nameOf).join(', ')}
                        {refresh.failedDeviceIds.length > 8 ? ', …' : ''}
                      </span>
                    )}
                  </p>
                )}
                {refreshError && <p className="text-status-ssl-expired">{refreshError}</p>}
              </div>
            )}

            <div className="mt-4 grid grid-cols-2 gap-2 md:grid-cols-4">
              {UPGRADE_STATUSES.map((s) => (
                <button
                  key={s}
                  onClick={() => setStatus(status === s ? '' : s)}
                  className={cn(
                    'rounded-md border px-3 py-2 text-left transition-colors hover:bg-bg-hover',
                    status === s ? 'border-accent' : 'border-border',
                  )}
                >
                  <div className="text-[11px] uppercase tracking-wider text-text-muted">{statusLabel(s)}</div>
                  <div className="font-display text-lg font-semibold tabular-nums text-text-primary">
                    {listing.counts[s]}
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* ── A read that failed after a good one: say the table is old ─── */}
          {loadError && (
            <p className="mb-3 flex flex-wrap items-center gap-1.5 rounded-md border border-status-ssl-warning/40 bg-status-ssl-warning/5 p-2.5 text-[13px] text-status-ssl-warning">
              <AlertTriangle size={14} />
              {t('fleetUpgrade.staleListing', {
                time: loadedAt ? dateFmt.format(new Date(loadedAt)) : '—',
                defaultValue: 'The last refresh failed: the table shows what was read at {{time}}.',
              })}
              <span className="font-mono text-[11px] text-text-muted">{loadError}</span>
            </p>
          )}

          {/* ── Why the button may be off ────────────────────────────────── */}
          {listing.killSwitch.blocked && (
            <p className="mb-3 rounded-md border border-status-ssl-expired/50 bg-status-ssl-expired/10 p-2.5 text-[13px] text-status-ssl-expired">
              {t('fleetUpgrade.error.kill_switch', { defaultValue: 'Writes are stopped (kill switch engaged).' })}
              {listing.killSwitch.reason && <span className="ml-1 font-mono text-[12px]">{listing.killSwitch.reason}</span>}
            </p>
          )}
          {!listing.launch.available && (
            <div className="mb-3 rounded-md border border-status-ssl-warning/40 bg-status-ssl-warning/5 p-2.5 text-[13px] text-status-ssl-warning">
              {t('fleetUpgrade.launchUnavailable', {
                defaultValue: 'Launching updates is not available on this server yet.',
              })}
              {listing.launch.reason && (
                <p className="mt-1 font-mono text-[11px] text-text-muted">{listing.launch.reason}</p>
              )}
            </div>
          )}
          {!canApply && (
            <p className="mb-3 flex items-center gap-1.5 text-[12px] text-text-muted">
              <Info size={13} />
              {t('fleetUpgrade.rights.noApply', {
                defaultValue: 'You can view this screen; launching an update needs the change.apply right.',
              })}
            </p>
          )}
          {launched && (
            <div className="mb-3 flex flex-wrap items-center gap-2 rounded-md border border-status-up/50 bg-status-up/10 p-2.5 text-[13px] text-status-up">
              <CheckCircle2 size={14} />
              {launched.mode === 'rollout' && launched.rolloutId !== null ? (
                <>
                  {t('fleetUpgrade.launched.rollout', {
                    id: launched.rolloutId,
                    defaultValue: 'Update started: rollout #{{id}}.',
                  })}
                  <Link to={`/rollouts/${launched.rolloutId}`} className="underline">
                    {t('fleetUpgrade.launched.open', { defaultValue: 'Open' })}
                  </Link>
                </>
              ) : launched.jobId !== null ? (
                <>
                  {t('fleetUpgrade.launched.job', { id: launched.jobId, defaultValue: 'Update started: job #{{id}}.' })}
                  <Link to={`/changes/${launched.jobId}`} className="underline">
                    {t('fleetUpgrade.launched.open', { defaultValue: 'Open' })}
                  </Link>
                </>
              ) : launched.mode === 'multi_tenant' && launched.byTenant ? (
                // God view: one job or rollout per workspace of the selection.
                <span className="flex flex-col gap-0.5">
                  <span>{t('godView.launchedAcrossTenants', { count: launched.byTenant.length })}</span>
                  {launched.byTenant.map((b) => (
                    <span key={b.tenantId} className={b.error ? 'text-status-down' : undefined}>
                      {b.error
                        ? t('godView.launchFailed', { tenant: b.tenantName ?? `#${b.tenantId}`, error: b.error })
                        : b.rolloutId !== null
                          ? <Link to={`/rollouts/${b.rolloutId}`} className="underline">{t('godView.launchedRollout', { tenant: b.tenantName ?? `#${b.tenantId}`, id: b.rolloutId })}</Link>
                          : <Link to={`/changes/${b.jobId}`} className="underline">{t('godView.launchedJob', { tenant: b.tenantName ?? `#${b.tenantId}`, id: b.jobId })}</Link>}
                    </span>
                  ))}
                </span>
              ) : null}
              <button onClick={() => setLaunched(null)} className="ml-auto text-text-muted hover:text-text-primary" aria-label="close">
                <X size={13} />
              </button>
            </div>
          )}

          {/* ── Filters ──────────────────────────────────────────────────── */}
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder={t('fleetUpgrade.filters.search', { defaultValue: 'Search a router…' })}
                className="w-56 rounded-md border border-border bg-bg-tertiary py-1.5 pl-8 pr-2.5 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
              />
            </div>
            <select className={selectClass} value={client} onChange={(e) => setClient(e.target.value)}>
              <option value="">{t('fleetUpgrade.filters.allClients', { defaultValue: 'All customers' })}</option>
              {clients.map((c) => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
            <select className={selectClass} value={site} onChange={(e) => setSite(e.target.value)}>
              <option value="">{t('fleetUpgrade.filters.allSites', { defaultValue: 'All sites' })}</option>
              {sites.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
            <select className={selectClass} value={version} onChange={(e) => setVersion(e.target.value)}>
              <option value="">{t('fleetUpgrade.filters.allVersions', { defaultValue: 'All versions' })}</option>
              {versions.map((v) => (
                <option key={v} value={v}>{v}</option>
              ))}
              <option value={NO_VERSION}>{t('fleetUpgrade.filters.noVersion', { defaultValue: 'No version' })}</option>
            </select>
            <select
              className={selectClass}
              value={status}
              onChange={(e) => setStatus(e.target.value as UpgradeStatus | '')}
            >
              <option value="">{t('fleetUpgrade.filters.allStatuses', { defaultValue: 'All statuses' })}</option>
              {UPGRADE_STATUSES.map((s) => (
                <option key={s} value={s}>{statusLabel(s)}</option>
              ))}
            </select>
            {filtersActive && (
              <button
                onClick={clearFilters}
                className="inline-flex items-center gap-1 rounded-md px-2 py-1.5 text-[12px] text-text-muted hover:bg-bg-hover hover:text-text-primary"
              >
                <X size={12} />
                {t('fleetUpgrade.filters.clear', { defaultValue: 'Clear' })}
              </button>
            )}
            <span className="ml-auto font-mono text-[11px] text-text-muted">
              {t('fleetUpgrade.showing', {
                shown: filtered.length,
                total: devices.length,
                defaultValue: '{{shown}} of {{total}}',
              })}
            </span>
          </div>

          {/* ── The action bar ───────────────────────────────────────────── */}
          <div className="mb-3 flex flex-wrap items-center gap-2 rounded-md border border-border bg-bg-secondary px-3 py-2">
            <Button variant="secondary" size="sm" onClick={selectBehind} disabled={behindVisible.length === 0}>
              {t('fleetUpgrade.selectBehind', { defaultValue: 'Select the behind routers shown' })}
            </Button>
            <span className="text-[13px] text-text-secondary">
              {t('fleetUpgrade.selectedCount', { count: selected.size, defaultValue: '{{count}} selected' })}
            </span>
            {selected.size > 0 && (
              <button
                onClick={() => setSelected(new Set())}
                className="text-[12px] text-text-muted hover:text-text-primary"
              >
                {t('fleetUpgrade.clearSelection', { defaultValue: 'Clear selection' })}
              </button>
            )}
            {hiddenSelected.length > 0 && (
              <span className="flex items-center gap-1.5 text-[12px] text-status-ssl-warning">
                <AlertTriangle size={12} />
                {t('fleetUpgrade.hiddenSelected', {
                  count: hiddenSelected.length,
                  defaultValue: '{{count}} selected router(s) are hidden by the filters',
                })}
                <button onClick={deselectHidden} className="underline hover:text-text-primary">
                  {t('fleetUpgrade.deselectHidden', { defaultValue: 'Deselect them' })}
                </button>
              </span>
            )}
            {tooMany && (
              <span className="text-[12px] text-status-ssl-expired">
                {t('fleetUpgrade.tooMany', {
                  max: MAX_UPGRADE_DEVICES,
                  defaultValue: 'At most {{max}} routers per update.',
                })}
              </span>
            )}
            {polling && (
              <span className="flex items-center gap-1.5 text-[11px] text-text-muted">
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-accent" />
                {t('fleetUpgrade.liveHint', {
                  defaultValue: 'Refreshing every 5 seconds while updates are running.',
                })}
              </span>
            )}
            <Button
              variant="primary"
              size="sm"
              className="ml-auto"
              disabled={selected.size === 0 || launchBlocked || tooMany}
              onClick={() => setConfirming(true)}
            >
              <Rocket size={14} className="mr-1.5" />
              {t('fleetUpgrade.update', { defaultValue: 'Update' })}
            </Button>
          </div>

          {/* ── The table ────────────────────────────────────────────────── */}
          {devices.length === 0 ? (
            <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center text-sm text-text-muted">
              {t('fleetUpgrade.empty', { defaultValue: 'No RouterOS router in this fleet.' })}
            </div>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-border bg-bg-secondary">
              <table className="w-full min-w-[64rem] text-left text-[13px]">
                <thead className="border-b border-border text-[11px] uppercase tracking-wider text-text-muted">
                  <tr>
                    <th className="w-8 px-3 py-2">
                      <input
                        type="checkbox"
                        checked={allVisibleSelected}
                        disabled={selectableVisible.length === 0}
                        onChange={toggleVisible}
                        aria-label="select all"
                      />
                    </th>
                    <th className="px-3 py-2 font-medium">{t('fleetUpgrade.columns.router', { defaultValue: 'Router' })}</th>
                    <th className="px-3 py-2 font-medium">
                      {t('fleetUpgrade.columns.customerSite', { defaultValue: 'Customer / site' })}
                    </th>
                    <th className="px-3 py-2 font-medium">
                      {t('fleetUpgrade.columns.version', { defaultValue: 'Current version' })}
                    </th>
                    <th className="px-3 py-2 font-medium">{t('fleetUpgrade.columns.target', { defaultValue: 'Target' })}</th>
                    <th className="px-3 py-2 font-medium">{t('fleetUpgrade.columns.status', { defaultValue: 'Status' })}</th>
                    <th className="px-3 py-2 font-medium">
                      {t('fleetUpgrade.columns.progress', { defaultValue: 'Progress' })}
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {filtered.map((d) => (
                    <DeviceRow
                      key={d.id}
                      device={d}
                      checked={selected.has(d.id)}
                      onToggle={() => toggle(d.id)}
                      blockedText={d.blockedReason ? refusalText(d.blockedReason) : null}
                      dateFmt={dateFmt}
                      showLinks={listing.queueDetail}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      {confirming && (
        <UpgradeConfirmDialog
          deviceIds={selectedIds}
          devices={devices}
          canApprove={canApprove}
          canRollout={canRollout}
          onClose={() => setConfirming(false)}
          onLaunched={onLaunched}
        />
      )}
    </div>
  );
}

function DeviceRow({
  device: d,
  checked,
  onToggle,
  blockedText,
  dateFmt,
  showLinks,
}: {
  device: UpgradeDevice;
  checked: boolean;
  onToggle: () => void;
  blockedText: string | null;
  dateFmt: Intl.DateTimeFormat;
  showLinks: boolean;
}) {
  const { t } = useTranslation();
  const sourceText =
    d.versionSource === 'observed' && d.versionObservedAt
      ? t('fleetUpgrade.versionSource.observed', {
          date: dateFmt.format(new Date(d.versionObservedAt)),
          defaultValue: 'Read from the router {{date}}',
        })
      : d.versionSource === 'upgrade_job' && d.versionObservedAt
        ? t('fleetUpgrade.versionSource.upgrade_job', {
            date: dateFmt.format(new Date(d.versionObservedAt)),
            defaultValue: 'Read by an ObliWAN update job {{date}}',
          })
        : d.versionSource === 'inventory'
          ? t('fleetUpgrade.versionSource.inventory', { defaultValue: 'From the inventory (no reading date)' })
          : undefined;
  const ageText =
    d.versionStale && d.currentVersion
      ? d.versionAgeDays !== null
        ? t('fleetUpgrade.versionAge.days', {
            count: d.versionAgeDays,
            defaultValue: 'Read {{count}} day(s) ago: may be out of date',
          })
        : t('fleetUpgrade.versionAge.undated', { defaultValue: 'Reading date unknown: may be out of date' })
      : null;

  return (
    <tr className={cn('hover:bg-bg-hover', checked && 'bg-accent/5')}>
      <td className="px-3 py-2" title={blockedText ?? undefined}>
        <input type="checkbox" checked={checked} disabled={blockedText !== null} onChange={onToggle} />
      </td>
      <td className="px-3 py-2">
        <Link to={`/devices/${d.id}`} className="text-text-primary hover:text-accent">
          {anonHostname(d.name)}
        </Link>
        {/* God view: whose router this is. */}
        <TenantBadge name={d.tenantName} className="ml-1.5 align-middle" />
        <span className="block text-[11px] text-text-muted">
          {d.model ?? ''}
          {d.role === 'concentrator' && (
            <span className="ml-1 rounded border border-border px-1 text-[10px] uppercase">
              {t('fleetUpgrade.concentratorTag', { defaultValue: 'concentrator' })}
            </span>
          )}
        </span>
      </td>
      <td className="px-3 py-2">
        <span className="block text-text-secondary">{d.clientName ?? '—'}</span>
        <span className="block text-[11px] text-text-muted">{d.siteName ?? ''}</span>
      </td>
      <td className="px-3 py-2 font-mono text-[12px]" title={[sourceText, ageText].filter(Boolean).join(' · ') || undefined}>
        <span className="text-text-primary">{shortVersion(d.currentVersion) ?? '—'}</span>
        {d.architecture && <span className="ml-1.5 text-[10px] text-text-muted">{d.architecture}</span>}
        {ageText && (
          <span className="ml-1.5 inline-flex items-center gap-0.5 align-middle text-[10px] text-status-ssl-warning">
            <Clock size={11} />
            {d.versionAgeDays !== null
              ? t('fleetUpgrade.versionAge.short', { count: d.versionAgeDays, defaultValue: '{{count}}d' })
              : '?'}
          </span>
        )}
      </td>
      <td className="px-3 py-2 font-mono text-[12px] text-text-secondary">{d.targetVersion ?? '—'}</td>
      <td className="px-3 py-2">
        <UpgradeStatusBadge status={d.status} reason={d.statusReason} />
        {blockedText && d.status !== 'up_to_date' && d.status !== 'in_progress' && (
          <span className="mt-0.5 block max-w-[16rem] text-[10px] text-text-muted">{blockedText}</span>
        )}
      </td>
      <td className="px-3 py-2">
        <UpgradeProgressCell device={d} dateFmt={dateFmt} showLinks={showLinks} />
      </td>
    </tr>
  );
}
