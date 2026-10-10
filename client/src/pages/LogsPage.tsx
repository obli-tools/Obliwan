import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  AlertTriangle,
  Bell,
  Radio,
  RotateCw,
  ScrollText,
  Search,
  ShieldAlert,
  Terminal,
  Unplug,
  X,
} from 'lucide-react';
import { logsApi } from '@/api/logs.api';
import { errorMessageOf } from '@/api/change.api';
import { devicesApi } from '@/api/devices.api';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { scanTextForSecrets } from '@/utils/secretScan';
import { anonHostname, anonIp, anonLog, anonUsername } from '@/utils/anonymize';
import { cn } from '@/utils/cn';
import type { Device } from '@/types/fleet';
import type { LogEntryView, LogSeverity, LogSource, LogSourceCount } from '@/types/logs';
import { LOG_SEVERITIES, LOG_SEVERITY_RANK, LOG_SOURCES, logSourceKey } from '@/types/logs';
import type { UnattributedSource } from '@obliwan/shared';
import { useAuthStore } from '@/store/authStore';
import { GodViewMarker, GodViewTenantCell, GodViewTenantHeader } from '@/components/common/TenantBadge';
import { GodViewTenantFilter } from '@/components/common/GodViewTenantFilter';

/**
 * `LogsPage` — syslog + SNMP traps + RouterOS `/log`, in ONE list.
 *
 * ┌─ WHY THE THREE SOURCES SHARE A SCREEN, AND STILL CARRY A LABEL ──────────┐
 * │ An operator asking "what happened on this box at 02:14" does not care    │
 * │ which wire a line arrived on. Splitting them across three screens means  │
 * │ correlating three clocks by hand, at 02:14.                              │
 * │                                                                          │
 * │ They keep their badge because their trustworthiness is NOT the same:     │
 * │  · `routeros_log` we PULLED, over an authenticated channel, from a     │
 * │    we identified. Origin vouched for.                                    │
 * │  · `syslog` arrived unsolicited over UDP/TCP 514.                        │
 * │  · `trap` arrived over UDP with a source address the Docker bridge NAT   │
 * │    rewrote. The page says so, in the header, once — and                  │
 * │    the source-IP column shows a dash rather than the gateway's address,  │
 * │    because a confidently wrong address is worse than a missing one.      │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ── TWO CLOCKS, ON PURPOSE ──────────────────────────────────────────────────
 * `timestamp` is what the DEVICE said; `receivedAt` is when our ingest saw it.
 * A router with no NTP has a fantasy clock, and a log screen that shows only
 * the device's time will sort an incident into the wrong century. Both are
 * shown; sorting uses `receivedAt` when it exists, because it is the only clock
 * we control.
 *
 * ── The secrets rule ────────────────────────────────────────────────────────
 * A log line is the ONE data path in this product where redaction cannot be a
 * server guarantee: we did not author the string, a device did. Every line is
 * therefore scanned before it is painted, and a hit is replaced by a chip that
 * names the KEY and never the value.
 */

const selectClass =
  'rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent';

const SOURCE_ICON: Record<LogSource, React.ReactNode> = {
  syslog: <ScrollText size={11} />,
  trap: <Radio size={11} />,
  routeros_log: <Terminal size={11} />,
};

const SOURCE_TONE: Record<LogSource, string> = {
  syslog: 'text-text-secondary border-border bg-bg-tertiary',
  // Amber: it is the least identifiable of the three.
  trap: 'text-status-ssl-warning border-status-ssl-warning/40 bg-status-ssl-warning/10',
  routeros_log: 'text-accent border-accent/40 bg-accent/10',
};

const SEVERITY_TONE: Record<LogSeverity, string> = {
  emerg: 'text-status-ssl-expired border-status-ssl-expired/60 bg-status-ssl-expired/15',
  alert: 'text-status-ssl-expired border-status-ssl-expired/60 bg-status-ssl-expired/15',
  crit: 'text-status-ssl-expired border-status-ssl-expired/50 bg-status-ssl-expired/10',
  err: 'text-status-down border-status-down/50 bg-status-down/10',
  warning: 'text-status-ssl-warning border-status-ssl-warning/50 bg-status-ssl-warning/10',
  notice: 'text-text-secondary border-border bg-bg-tertiary',
  info: 'text-text-muted border-border bg-bg-tertiary',
  debug: 'text-text-muted border-border bg-bg-tertiary',
};

export function LogsPage() {
  const { t, i18n } = useTranslation();
  const [searchParams, setSearchParams] = useSearchParams();
  const isPlatformAdmin = useAuthStore((s) => s.user?.role === 'admin');

  const [entries, setEntries] = useState<LogEntryView[]>([]);
  const [sources, setSources] = useState<LogSourceCount[] | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [unavailable, setUnavailable] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [search, setSearch] = useState(searchParams.get('q') ?? '');
  const [source, setSource] = useState<LogSource | ''>(
    (searchParams.get('source') as LogSource | null) ?? '',
  );
  const [severity, setSeverity] = useState<LogSeverity | ''>(
    (searchParams.get('severity') as LogSeverity | null) ?? '',
  );
  const deviceIdParam = Number(searchParams.get('deviceId'));
  const [deviceId, setDeviceId] = useState<number | ''>(
    Number.isFinite(deviceIdParam) && deviceIdParam > 0 ? deviceIdParam : '',
  );

  // The text filter is applied SERVER-side (a fleet's log does not fit in the
  // browser), so it is debounced. Without this, a fifteen-character search is
  // fifteen full-text queries against a partitioned table, and the last four
  // answers race each other into the list.
  const [searchDebounced, setSearchDebounced] = useState(search);
  useEffect(() => {
    const timer = setTimeout(() => setSearchDebounced(search), 400);
    return () => clearTimeout(timer);
  }, [search]);

  const dateFmt = useMemo(
    () => new Intl.DateTimeFormat(i18n.language, { dateStyle: 'short', timeStyle: 'medium' }),
    [i18n.language],
  );

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const rows = await logsApi.list({
        source: source || undefined,
        severity: severity || undefined,
        deviceId: deviceId === '' ? undefined : deviceId,
        q: searchDebounced.trim() || undefined,
        limit: 500,
      });
      if (rows === null) { setUnavailable(true); setEntries([]); }
      else { setUnavailable(false); setEntries(rows); }
      setSources(await logsApi.sources());
    } catch (err) {
      setLoadError(errorMessageOf(err) ?? t('logs.loadFailed'));
    } finally {
      setLoading(false);
    }
  }, [source, severity, deviceId, searchDebounced, t]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    void devicesApi.list().then(setDevices).catch(() => setDevices([]));
  }, []);

  // The filters live in the URL so an attribution banner can deep-link into
  // "the logs of this box" and so a shared link reproduces the same view.
  useEffect(() => {
    const next = new URLSearchParams();
    if (search.trim()) next.set('q', search.trim());
    if (source) next.set('source', source);
    if (severity) next.set('severity', severity);
    if (deviceId !== '') next.set('deviceId', String(deviceId));
    setSearchParams(next, { replace: true });
  }, [search, source, severity, deviceId, setSearchParams]);

  const sorted = useMemo(() => {
    const rows = entries.slice();
    rows.sort((a, b) => {
      const at = new Date(a.receivedAt ?? a.timestamp).getTime();
      const bt = new Date(b.receivedAt ?? b.timestamp).getTime();
      if (Number.isNaN(at) || Number.isNaN(bt)) return 0;
      return bt - at;
    });
    return rows;
  }, [entries]);

  const worst = useMemo(() => {
    let best = 8;
    for (const e of entries) best = Math.min(best, LOG_SEVERITY_RANK[e.severity]);
    return best;
  }, [entries]);

  const deviceOptions = useMemo(
    () => devices.slice().sort((a, b) => a.name.localeCompare(b.name)),
    [devices],
  );

  return (
    <div className="p-6">
      <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 font-display text-2xl font-semibold text-text-primary">
            {t('nav.logs')}
            <GodViewMarker />
          </h1>
          <p className="mt-1 text-sm text-text-muted">{t('logs.subtitle')}</p>
        </div>
        <div className="flex items-center gap-2">
          <GodViewTenantFilter onChange={() => void load()} />
          <Button variant="secondary" size="sm" onClick={() => void load()}>
            <RotateCw size={14} className={cn('mr-1.5', loading && 'animate-spin')} />
            {t('devices.refresh')}
          </Button>
        </div>
      </div>

      {/* The bridge-NAT constraint, said once, at the top, where it changes how the table is
          read rather than in a tooltip nobody opens. */}
      <p className="mb-4 flex items-start gap-2 rounded-md border border-border bg-bg-tertiary px-3 py-2 text-[12px] text-text-muted">
        <ShieldAlert size={14} className="mt-0.5 shrink-0" />
        {t('logs.trapSourceWarning')}
      </p>

      {isPlatformAdmin && <IngestCard dateFmt={dateFmt} />}

      {sources && sources.length > 0 && (
        <div className="mb-4 grid grid-cols-1 gap-3 md:grid-cols-3">
          {LOG_SOURCES.map((src) => {
            const row = sources.find((s) => s.source === src);
            return <SourceCard key={src} source={src} row={row ?? null} dateFmt={dateFmt} />;
          })}
        </div>
      )}

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="relative">
          <Search size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t('logs.searchPlaceholder')}
            className="w-72 rounded-md border border-border bg-bg-tertiary py-1.5 pl-8 pr-2.5 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
          />
        </div>

        <select className={selectClass} value={source} onChange={(e) => setSource(e.target.value as LogSource | '')}>
          <option value="">{t('logs.filters.allSources')}</option>
          {LOG_SOURCES.map((s) => (
            <option key={s} value={s}>{t(`logs.source.${logSourceKey(s)}`)}</option>
          ))}
        </select>

        <select className={selectClass} value={severity} onChange={(e) => setSeverity(e.target.value as LogSeverity | '')}>
          <option value="">{t('logs.filters.allSeverities')}</option>
          {LOG_SEVERITIES.map((s) => (
            <option key={s} value={s}>{t(`logs.severity.${s}`)}</option>
          ))}
        </select>

        <select
          className={selectClass}
          value={deviceId === '' ? '' : String(deviceId)}
          onChange={(e) => setDeviceId(e.target.value === '' ? '' : Number(e.target.value))}
        >
          <option value="">{t('logs.filters.allDevices')}</option>
          {deviceOptions.map((d) => (
            <option key={d.id} value={d.id}>{anonHostname(d.name)}</option>
          ))}
        </select>

        {(search || source || severity || deviceId !== '') && (
          <button
            onClick={() => { setSearch(''); setSource(''); setSeverity(''); setDeviceId(''); }}
            className="inline-flex items-center gap-1 rounded-md px-2 py-1.5 text-[12px] text-text-muted hover:bg-bg-hover hover:text-text-primary"
          >
            <X size={12} />
            {t('devices.filters.clear')}
          </button>
        )}

        <span className="ml-auto font-mono text-[11px] text-text-muted">
          {t('logs.lineCount', { count: sorted.length })}
          {worst <= LOG_SEVERITY_RANK.err && (
            <span className="ml-2 text-status-ssl-expired">
              {t('logs.hasCritical')}
            </span>
          )}
        </span>
      </div>

      {unavailable ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <Unplug size={28} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">{t('logs.endpointUnavailable')}</p>
          <p className="mx-auto mt-1 max-w-xl text-xs text-text-muted">
            {t('logs.endpointUnavailableHint')}
          </p>
        </div>
      ) : loadError ? (
        <div className="rounded-lg border border-status-ssl-expired/40 bg-status-ssl-expired/5 p-4 text-sm text-status-ssl-expired">
          {t('logs.loadFailed')} — <span className="font-mono text-xs">{loadError}</span>
        </div>
      ) : loading && entries.length === 0 ? (
        <div className="flex justify-center py-16"><LoadingSpinner size="lg" /></div>
      ) : sorted.length === 0 ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <Bell size={28} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">{t('logs.empty')}</p>
          <p className="mt-1 text-xs text-text-muted">{t('logs.emptyHint')}</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border bg-bg-secondary">
          <table className="w-full min-w-[68rem] text-left text-[13px]">
            <thead className="border-b border-border text-[11px] uppercase tracking-wider text-text-muted">
              <tr>
                <th className="px-3 py-2 font-medium">{t('logs.columns.time')}</th>
                <th className="px-3 py-2 font-medium">{t('logs.columns.source')}</th>
                <th className="px-3 py-2 font-medium">{t('logs.columns.severity')}</th>
                <th className="px-3 py-2 font-medium">{t('logs.columns.device')}</th>
                <GodViewTenantHeader />
                <th className="px-3 py-2 font-medium">{t('logs.columns.who')}</th>
                <th className="px-3 py-2 font-medium">{t('logs.columns.message')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {sorted.map((entry) => (
                <LogRow key={entry.id} entry={entry} dateFmt={dateFmt} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function LogRow({ entry, dateFmt }: { entry: LogEntryView; dateFmt: Intl.DateTimeFormat }) {
  const { t } = useTranslation();

  const fmt = (iso: string | null) => {
    if (!iso) return null;
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? null : dateFmt.format(d);
  };
  const deviceTime = fmt(entry.timestamp);
  const ingestTime = fmt(entry.receivedAt);
  // A device clock more than five minutes away from our ingest clock is a box
  // with no NTP, and every timestamp it prints is a lie of that size.
  const skewed = Boolean(
    entry.receivedAt &&
    entry.timestamp &&
    Math.abs(new Date(entry.receivedAt).getTime() - new Date(entry.timestamp).getTime()) > 300_000,
  );

  const hits = scanTextForSecrets(entry.message, 3);

  return (
    <tr className="align-top hover:bg-bg-hover">
      <td className="whitespace-nowrap px-3 py-2 font-mono text-[11px]">
        <span className="block text-text-primary">{ingestTime ?? deviceTime ?? '—'}</span>
        {skewed && (
          <span
            className="mt-0.5 inline-flex items-center gap-1 text-[10px] text-status-ssl-warning"
            title={t('logs.clockSkewHint', { deviceTime: deviceTime ?? '—' })}
          >
            <AlertTriangle size={9} />
            {t('logs.clockSkew')}
          </span>
        )}
      </td>

      <td className="px-3 py-2">
        <span
          className={cn(
            'inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-wider',
            SOURCE_TONE[entry.source],
          )}
          title={t(`logs.sourceHint.${logSourceKey(entry.source)}`)}
        >
          {SOURCE_ICON[entry.source]}
          {t(`logs.source.${logSourceKey(entry.source)}`)}
        </span>
        {entry.facility && (
          <span className="mt-0.5 block font-mono text-[10px] text-text-muted">{entry.facility}</span>
        )}
      </td>

      <td className="px-3 py-2">
        <span
          className={cn(
            'inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-wider',
            SEVERITY_TONE[entry.severity],
          )}
        >
          {t(`logs.severity.${entry.severity}`)}
        </span>
      </td>

      <td className="px-3 py-2">
        {entry.deviceId !== null ? (
          <Link to={`/devices/${entry.deviceId}`} className="text-text-primary hover:text-accent">
            {anonHostname(entry.deviceName ?? `#${entry.deviceId}`)}
          </Link>
        ) : (
          // An unbound line is shown as unbound. It is NOT hidden and it is NOT
          // guessed onto the nearest device: the identity-binding check and the bridge-NAT constraint both say
          // an address is not an identity.
          <span className="text-[12px] text-text-muted">{t('logs.unboundDevice')}</span>
        )}
        <span className="block text-[11px] text-text-muted">
          {entry.siteName ?? '—'}
          {entry.sourceIp && entry.source !== 'trap' && (
            <span className="ml-1 font-mono">{anonIp(entry.sourceIp)}</span>
          )}
        </span>
      </td>
      <GodViewTenantCell name={entry.tenantName} tenantId={entry.tenantId} />

      <td className="px-3 py-2">
        {entry.username ? (
          <span className="font-mono text-[12px] text-text-secondary">
            {anonUsername(entry.username)}
          </span>
        ) : (
          <span className="text-[11px] text-text-muted">—</span>
        )}
      </td>

      <td className="px-3 py-2">
        {hits.length > 0 ? (
          // The value is NOT rendered, not even masked. A masked secret
          // still leaks its length and its shape.
          <span className="inline-flex items-center gap-1.5 rounded border border-status-ssl-expired/60 bg-status-ssl-expired/15 px-2 py-1 text-[11px] text-status-ssl-expired">
            <ShieldAlert size={12} />
            {t('logs.secretRedacted', { keys: hits.map((h) => h.label).join(', ') })}
          </span>
        ) : (
          <span className="whitespace-pre-wrap break-words font-mono text-[12px] text-text-secondary">
            {anonLog(entry.message)}
          </span>
        )}
      </td>
    </tr>
  );
}

function SourceCard({
  source,
  row,
  dateFmt,
}: {
  source: LogSource;
  row: LogSourceCount | null;
  dateFmt: Intl.DateTimeFormat;
}) {
  const { t } = useTranslation();
  // The router's own log keeps only account lines: its liveness is the last
  // successful READ, not the last line (a quiet box is not a silent pull).
  const readBased = source === 'routeros_log';
  const lastIso = readBased ? row?.lastReadAt ?? null : row?.lastSeenAt ?? null;
  const last = lastIso ? new Date(lastIso) : null;
  const ageMs = last && !Number.isNaN(last.getTime()) ? Date.now() - last.getTime() : null;
  // An ingest with nothing in the last hour is an ingest to look at. It is the
  // failure a log LIST cannot show: a dead receiver simply produces fewer rows.
  const stale = ageMs === null || ageMs > 3_600_000;

  return (
    <div className="rounded-lg border border-border bg-bg-secondary p-3">
      <div className="flex items-center gap-1.5 text-[11px] uppercase tracking-wider text-text-muted">
        {SOURCE_ICON[source]}
        {t(`logs.source.${logSourceKey(source)}`)}
      </div>
      <div className="mt-1 font-display text-xl font-semibold tabular-nums text-text-primary">
        {row ? row.count : 0}
      </div>
      <div className={cn('mt-0.5 font-mono text-[11px]', stale ? 'text-status-ssl-warning' : 'text-text-muted')}>
        {last && !Number.isNaN(last.getTime())
          ? t(readBased ? 'logs.lastRead' : 'logs.lastSeen', { when: dateFmt.format(last) })
          : t('logs.neverSeen')}
      </div>
    </div>
  );
}

/**
 * « Réception syslog » — PLATFORM ADMINISTRATORS ONLY (the server answers
 * `quota` and /logs/unattributed to nobody else: hostnames of every customer).
 *
 * The screen a fleet-wide silence needed and did not have: until 2026-10-07
 * the daily quota was keyed on the bridge address, i.e. ONE quota for every
 * router, and when it was spent the whole fleet's syslog stopped until the UTC
 * day changed with nothing anywhere saying so. Each router that spent its own
 * quota is listed in red with the time it comes back; the senders nobody can
 * place are listed with the name they announce, which is what fixes them.
 */
function IngestCard({ dateFmt }: { dateFmt: Intl.DateTimeFormat }) {
  const { t } = useTranslation();
  const [health, setHealth] = useState<Awaited<ReturnType<typeof logsApi.health>>>(null);
  const [unplaced, setUnplaced] = useState<UnattributedSource[] | null>(null);

  useEffect(() => {
    void logsApi.health().then(setHealth).catch(() => setHealth(null));
    void logsApi.unattributed(24).then(setUnplaced).catch(() => setUnplaced(null));
  }, []);

  if (!health) return null;
  const quota = health.quota;
  const fmt = (iso: string | null | undefined) => {
    if (!iso) return '—';
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? '—' : dateFmt.format(d);
  };
  const spent = (quota?.routers ?? []).filter((r) => r.exhausted);
  const counters: Array<[string, number]> = [
    ['received', health.received],
    ['stored', health.stored],
    ['belowFloor', health.belowFloor],
    ['rateLimited', health.rateLimited],
    ['quotaSuppressed', health.quotaSuppressed + (health.fleetQuotaSuppressed ?? 0)],
  ];

  return (
    <div className="mb-4 rounded-lg border border-border bg-bg-secondary p-3">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="flex items-center gap-1.5 text-[12px] font-semibold uppercase tracking-wider text-text-muted">
          <ScrollText size={12} />
          {t('logs.ingest.title')}
        </h2>
        <span className="text-[11px] text-text-muted">{t('logs.ingest.hint')}</span>
      </div>

      <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-5">
        {counters.map(([key, value]) => (
          <div key={key} className="rounded-md bg-bg-tertiary px-2 py-1.5">
            <div className="text-[10px] uppercase tracking-wider text-text-muted">{t(`logs.ingest.${key}`)}</div>
            <div className={cn(
              'font-mono text-sm tabular-nums',
              key === 'quotaSuppressed' && value > 0 ? 'text-status-ssl-expired' : 'text-text-primary',
            )}>
              {value.toLocaleString()}
            </div>
          </div>
        ))}
      </div>

      {quota && (
        <p className="mt-2 font-mono text-[11px] text-text-muted">
          {t('logs.ingest.quotaLine', {
            perRouter: quota.perRouterQuota.toLocaleString(),
            kept: quota.fleetKeptToday.toLocaleString(),
            fleet: quota.fleetQuota.toLocaleString(),
          })}
        </p>
      )}
      {quota?.fleetExhausted && (
        <p className="mt-2 rounded-md border border-status-ssl-expired/50 bg-status-ssl-expired/10 px-2 py-1.5 text-[12px] text-status-ssl-expired">
          {t('logs.ingest.fleetExhausted', { when: fmt(quota.resetsAt) })}
        </p>
      )}
      {quota && (
        spent.length === 0 ? (
          <p className="mt-1 text-[11px] text-text-muted">{t('logs.ingest.noneSuppressed')}</p>
        ) : (
          <ul className="mt-2 space-y-1">
            {spent.map((r) => (
              <li key={r.key} className="flex flex-wrap items-center gap-2 text-[12px] text-status-ssl-expired">
                {r.deviceId !== null ? (
                  <Link to={`/devices/${r.deviceId}`} className="font-mono hover:underline">
                    {anonHostname(r.hostname ?? r.key)}
                  </Link>
                ) : (
                  <span className="font-mono">{r.hostname ? anonHostname(r.hostname) : r.key}</span>
                )}
                <span>{t('logs.ingest.suppressedUntil', { when: fmt(quota.resetsAt) })}</span>
                <span className="font-mono text-[11px] text-text-muted">
                  {r.keptToday.toLocaleString()} / {r.droppedToday.toLocaleString()}
                </span>
              </li>
            ))}
          </ul>
        )
      )}

      {unplaced !== null && (
        <div className="mt-3">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-text-muted">
            {t('logs.ingest.unattributedTitle')}
          </div>
          {unplaced.length === 0 ? (
            <p className="mt-1 text-[11px] text-text-muted">{t('logs.ingest.none')}</p>
          ) : (
            <table className="mt-1 w-full text-left text-[12px]">
              <thead className="text-[10px] uppercase tracking-wider text-text-muted">
                <tr>
                  <th className="py-1 pr-3 font-medium">{t('logs.ingest.claimedHostname')}</th>
                  <th className="py-1 pr-3 font-medium">{t('logs.ingest.sourceIp')}</th>
                  <th className="py-1 pr-3 font-medium">{t('logs.ingest.count')}</th>
                  <th className="py-1 font-medium">{t('logs.ingest.lastSeen')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {unplaced.slice(0, 50).map((u) => (
                  <tr key={`${u.sourceIp}|${u.hostname ?? ''}`}>
                    <td className="py-1 pr-3 font-mono">{u.hostname ? anonHostname(u.hostname) : '—'}</td>
                    <td className="py-1 pr-3 font-mono text-text-muted">{anonIp(u.sourceIp)}</td>
                    <td className="py-1 pr-3 font-mono tabular-nums">{u.count.toLocaleString()}</td>
                    <td className="py-1 font-mono text-text-muted">{fmt(u.lastSeen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}

