import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { MapPin, RefreshCw, Search, Sparkles, X } from 'lucide-react';
import toast from 'react-hot-toast';
import { SIM_LINE_STATUSES, isMasterTenant, type SimLineStatus } from '@obliwan/shared';
import { simApi, errorMessageOf, type SimLineListItem } from '@/api/sim.api';
import { useAuthStore } from '@/store/authStore';
import { useTenantStore } from '@/store/tenantStore';
import { useSiteStore } from '@/store/siteStore';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { EmptyState, VerdictBadge, When } from '@/components/mobile/SimBits';
import { ZoneUsageLine } from '@/components/mobile/ZoneUsage';
import { cn } from '@/utils/cn';

const selectClass =
  'rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent';

/**
 * ObliWAN — the SIM inventory.
 *
 * ┌─ THE POOL IS A FIRST-CLASS FILTER, NOT A HIDDEN STATE ────────────────────┐
 * │ A line the partner reported and nobody has attached to a customer sits in │
 * │ the pool (`tenant_id IS NULL`). It is only visible from the master        │
 * │ workspace — the server decides that, not this screen — and it is the      │
 * │ queue of work: every pooled line is a SIM somebody is paying for that no  │
 * │ customer is being billed for. Hiding it behind a default filter is how it │
 * │ stays unbilled.                                                           │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * Filtering by verdict is done SERVER-SIDE for `verdict` and client-side for
 * nothing: the threshold that produces a verdict is resolved per line from a
 * setting plus an override, and duplicating that resolution here would be a
 * second implementation of the rule that decides whether money gets spent.
 */
export function MobileLinesPage() {
  const { t } = useTranslation();
  const [lines, setLines] = useState<SimLineListItem[]>([]);
  const [loading, setLoading] = useState(true);
  // Quick filters live in the URL, so a dashboard tile is a link to a list.
  const [params, setParams] = useSearchParams();
  const initialVerdict = params.get('verdict');
  const initialAssignment = params.get('assignment');
  const initialStatus = params.get('status');
  const [search, setSearch] = useState(params.get('search') ?? '');
  const [verdict, setVerdict] = useState<'' | 'ok' | 'low' | 'unknown' | 'terminated'>(
    initialVerdict === 'ok' || initialVerdict === 'low' || initialVerdict === 'unknown' || initialVerdict === 'terminated'
      ? initialVerdict
      : '',
  );
  const [assignment, setAssignment] = useState<'' | 'assigned' | 'pool'>(
    initialAssignment === 'assigned' || initialAssignment === 'pool' ? initialAssignment : '',
  );
  const [status, setStatus] = useState<'' | SimLineStatus>(
    (SIM_LINE_STATUSES as readonly string[]).includes(initialStatus ?? '') ? (initialStatus as SimLineStatus) : '',
  );
  const [tenantId, setTenantId] = useState<number | ''>(Number(params.get('tenantId')) || '');
  // `?siteId=` — the Sites list's SIM count links here: the lines of that site
  // (attributed to it, or on one of its routers), the server's own filter.
  const [siteId, setSiteId] = useState<number | ''>(() => {
    const n = Number(params.get('siteId'));
    return Number.isInteger(n) && n > 0 ? n : '';
  });
  const [withoutDevice, setWithoutDevice] = useState(params.get('withoutDevice') === 'true');
  const [onBackup4g, setOnBackup4g] = useState(params.get('onBackup4g') === 'true');
  // The tenant names seen on the god view, kept across filtered reloads.
  const [tenants, setTenants] = useState<Map<number, string>>(new Map());

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setLines(
        await simApi.lines({
          verdict: verdict || undefined,
          assignment: assignment || undefined,
          search: search.trim() || undefined,
          status: status || undefined,
          tenantId: tenantId || undefined,
          siteId: siteId || undefined,
          withoutDevice: withoutDevice || undefined,
          onBackup4g: onBackup4g || undefined,
          limit: 2000,
        }),
      );
    } catch (err) {
      toast.error(errorMessageOf(err));
    } finally {
      setLoading(false);
    }
  }, [verdict, assignment, search, status, tenantId, siteId, withoutDevice, onBackup4g]);

  useEffect(() => {
    void load();
  }, [load]);

  const poolCount = useMemo(() => lines.filter((l) => l.tenantId === null).length, [lines]);
  // ┌─ THE TENANT FILTER LISTS EVERY WORKSPACE, NOT THE ONES ON SCREEN ───────┐
  // │ The god view (`tenantName` on every line) is the server's verdict:      │
  // │ platform admin on the master workspace. The first draft built the       │
  // │ filter's options from the tenants already present in the RESULT, so a  │
  // │ page opened on `?tenantId=` — or any filter that emptied the list —     │
  // │ offered only what it was already showing. The options come from the     │
  // │ tenant list when this session may read it; the names seen on lines are  │
  // │ kept as a fallback (a listing that fails, an older server).             │
  // └────────────────────────────────────────────────────────────────────────┘
  const storeTenants = useTenantStore((s) => s.tenants);
  const fetchTenants = useTenantStore((s) => s.fetchTenants);
  const currentTenantId = useTenantStore((s) => s.currentTenantId);
  const isPlatformAdmin = useAuthStore((s) => s.isAdmin)();
  const masterSession = isPlatformAdmin && isMasterTenant(currentTenantId);
  useEffect(() => {
    if (masterSession && storeTenants.length === 0) void fetchTenants();
  }, [masterSession, storeTenants.length, fetchTenants]);
  const godView =
    useMemo(() => lines.some((l) => l.tenantName !== undefined), [lines]) || tenants.size > 0 || masterSession;
  useEffect(() => {
    setTenants((prev) => {
      let next: Map<number, string> | null = null;
      for (const l of lines) {
        if (l.tenantId !== null && l.tenantName && !prev.has(l.tenantId)) {
          next = next ?? new Map(prev);
          next.set(l.tenantId, l.tenantName);
        }
      }
      return next ?? prev;
    });
  }, [lines]);
  const tenantOptions = useMemo(() => {
    const all = new Map(tenants);
    if (masterSession) for (const tn of storeTenants) all.set(tn.id, tn.name);
    // A filter set from the URL stays selectable even before its name is known.
    if (tenantId !== '' && !all.has(tenantId)) all.set(tenantId, `#${tenantId}`);
    return [...all.entries()].sort((a, b) => a[1].localeCompare(b[1]));
  }, [tenants, storeTenants, masterSession, tenantId]);
  // Shareable: the filter is in the URL, like the dashboard tiles' links.
  useEffect(() => {
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (tenantId === '') next.delete('tenantId');
        else next.set('tenantId', String(tenantId));
        if (siteId === '') next.delete('siteId');
        else next.set('siteId', String(siteId));
        return next;
      },
      { replace: true },
    );
  }, [tenantId, siteId, setParams]);
  // The site filter's name: the site store, else a listed line attributed to
  // it, else its number (a site of another workspace, or not loaded yet).
  const storeSite = useSiteStore((s) => (siteId === '' ? undefined : s.getSite(siteId)));
  const siteLabel = useMemo(() => {
    if (siteId === '') return '';
    return storeSite?.name ?? lines.find((l) => l.siteId === siteId && l.siteName)?.siteName ?? `#${siteId}`;
  }, [siteId, storeSite, lines]);
  const chip = (active: boolean) =>
    cn(
      'rounded-full border px-2.5 py-1 text-xs',
      active ? 'border-accent bg-accent/10 text-accent' : 'border-border text-text-secondary hover:bg-bg-hover',
    );

  return (
    <div className="p-6">
      <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold text-text-primary">{t('mobile.lines.title')}</h1>
          <p className="mt-1 text-sm text-text-secondary">
            {t('mobile.lines.count', { count: lines.length })}
            {poolCount > 0 ? ` · ${t('mobile.lines.poolCount', { count: poolCount })}` : ''}
          </p>
        </div>
        <Button variant="secondary" size="sm" onClick={() => void load()}>
          <RefreshCw size={14} className="mr-1.5" />
          {t('common.refresh')}
        </Button>
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-2">
        {siteId !== '' ? (
          <span className="inline-flex items-center gap-1.5 rounded-full border border-accent bg-accent/10 px-2.5 py-1 text-xs text-accent">
            <MapPin size={12} />
            {t('mobile.lines.filterSite', { name: siteLabel, defaultValue: 'Site: {{name}}' })}
            <button
              type="button"
              onClick={() => setSiteId('')}
              className="rounded-full p-0.5 hover:bg-accent/20"
              title={t('mobile.lines.clearSiteFilter', { defaultValue: 'Show every site' })}
              aria-label={t('mobile.lines.clearSiteFilter', { defaultValue: 'Show every site' })}
            >
              <X size={12} />
            </button>
          </span>
        ) : null}
        <div className="relative">
          <Search
            size={14}
            className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted"
          />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t('mobile.lines.searchPlaceholder')}
            className="pl-8"
          />
        </div>
        <select
          className={selectClass}
          value={verdict}
          onChange={(e) => setVerdict(e.target.value as typeof verdict)}
        >
          <option value="">{t('mobile.lines.allVerdicts')}</option>
          <option value="low">{t('mobile.verdict.low')}</option>
          <option value="ok">{t('mobile.verdict.ok')}</option>
          <option value="unknown">{t('mobile.verdict.unknown')}</option>
          <option value="terminated">{t('mobile.verdict.terminated')}</option>
        </select>
        <select
          className={selectClass}
          value={status}
          onChange={(e) => setStatus(e.target.value as typeof status)}
        >
          <option value="">{t('mobile.lines.allStatuses')}</option>
          {SIM_LINE_STATUSES.map((st) => (
            <option key={st} value={st}>
              {t(`mobile.lineStatus.${st}`, { defaultValue: st })}
            </option>
          ))}
        </select>
        {godView ? (
          <select
            className={selectClass}
            value={tenantId}
            onChange={(e) => setTenantId(Number(e.target.value) || '')}
          >
            <option value="">{t('mobile.lines.allTenants')}</option>
            {tenantOptions.map(([id, name]) => (
              <option key={id} value={id}>
                {name}
              </option>
            ))}
          </select>
        ) : null}
        <button type="button" className={chip(withoutDevice)} onClick={() => setWithoutDevice((v) => !v)}>
          {t('mobile.lines.filterWithoutRouter')}
        </button>
        <button
          type="button"
          className={chip(verdict === 'low')}
          onClick={() => setVerdict((v) => (v === 'low' ? '' : 'low'))}
        >
          {t('mobile.lines.filterLow')}
        </button>
        <button type="button" className={chip(onBackup4g)} onClick={() => setOnBackup4g((v) => !v)}>
          {t('mobile.lines.filterOnBackup')}
        </button>
        <select
          className={selectClass}
          value={assignment}
          onChange={(e) => setAssignment(e.target.value as typeof assignment)}
        >
          <option value="">{t('mobile.lines.allAssignments')}</option>
          <option value="assigned">{t('mobile.lines.assigned')}</option>
          <option value="pool">{t('mobile.lines.pool')}</option>
        </select>
      </div>

      <div className="overflow-hidden rounded-lg border border-border bg-bg-secondary">
        {loading ? (
          <div className="flex h-48 items-center justify-center">
            <LoadingSpinner />
          </div>
        ) : lines.length === 0 ? (
          <EmptyState message={t('mobile.lines.empty')} />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-border text-left text-xs text-text-muted">
                <tr>
                  <th className="px-4 py-2 font-medium">{t('mobile.lines.msisdn')}</th>
                  {godView ? <th className="px-4 py-2 font-medium">{t('mobile.lines.tenant')}</th> : null}
                  <th className="px-4 py-2 font-medium">{t('mobile.lines.site')}</th>
                  <th className="px-4 py-2 font-medium">{t('mobile.lines.router')}</th>
                  <th className="px-4 py-2 font-medium">{t('mobile.lines.operator')}</th>
                  <th className="px-4 py-2 font-medium">{t('mobile.lines.plan')}</th>
                  <th className="px-4 py-2 font-medium">{t('mobile.lines.status')}</th>
                  <th className="px-4 py-2 font-medium">{t('mobile.lines.used')}</th>
                  <th className="px-4 py-2 font-medium">{t('mobile.lines.zone')}</th>
                  <th className="px-4 py-2 font-medium">{t('mobile.lines.state')}</th>
                  <th className="px-4 py-2 font-medium">{t('mobile.lines.auto')}</th>
                  <th className="px-4 py-2 font-medium">{t('mobile.lines.seen')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {lines.map((l) => (
                  <tr key={l.id} className="hover:bg-bg-hover">
                    <td className="px-4 py-2">
                      <Link
                        to={`/mobile/lines/${l.id}`}
                        className="font-mono text-text-primary hover:text-accent"
                      >
                        {l.msisdn}
                      </Link>
                      {l.label ? (
                        <span className="ml-2 text-xs text-text-muted">{l.label}</span>
                      ) : null}
                    </td>
                    {godView ? (
                      <td className="px-4 py-2 text-text-secondary">
                        {l.tenantName ?? <span className="text-text-muted">—</span>}
                      </td>
                    ) : null}
                    <td className="px-4 py-2">
                      {l.tenantId === null ? (
                        // The pool badge. Loud on purpose: an unassigned line is
                        // a SIM being paid for and billed to nobody.
                        <span className="rounded-full border border-accent/30 bg-accent/10 px-2 py-0.5 text-[11px] text-accent">
                          {t('mobile.lines.pool')}
                        </span>
                      ) : (
                        <span className="text-text-secondary">
                          {l.siteName ?? t('mobile.noSite')}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-text-secondary">
                      {l.deviceId !== null && l.deviceName ? (
                        <Link to={`/devices/${l.deviceId}`} className="hover:text-accent">
                          {l.deviceName}
                        </Link>
                      ) : (
                        <span className="text-text-muted">{t('mobile.lines.noRouter')}</span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-text-secondary">
                      {l.operator ?? <span className="text-text-muted">—</span>}
                    </td>
                    <td className="px-4 py-2 text-xs text-text-secondary">
                      {l.partner?.planLabel ?? <span className="text-text-muted">—</span>}
                    </td>
                    <td className="px-4 py-2 text-xs text-text-secondary">
                      {t(`mobile.lineStatus.${l.status}`, { defaultValue: l.status })}
                    </td>
                    <td className="px-4 py-2">
                      <ZoneUsageLine
                        usage={l.worstUsage}
                        thresholdPercent={l.thresholdPercent}
                        thresholdMb={l.thresholdMb}
                        compact
                      />
                    </td>
                    <td className="px-4 py-2 text-text-secondary">
                      {l.worstZone?.zone ?? <span className="text-text-muted">—</span>}
                      {l.usage.length > 1 ? (
                        <span className="block text-[11px] text-text-muted">
                          {t('mobile.lines.zonesCount', { count: l.usage.length })}
                        </span>
                      ) : null}
                    </td>
                    <td className="px-4 py-2">
                      <VerdictBadge verdict={l.verdict} stale={l.stale} />
                    </td>
                    <td className="px-4 py-2">
                      <span
                        className={cn(
                          'text-xs',
                          l.autoRechargeEnabled ? 'text-status-up' : 'text-text-muted',
                        )}
                      >
                        {l.autoRechargeEnabled ? (
                          <>
                            <Sparkles size={12} className="mr-1 inline" />
                            {t('mobile.lines.autoOn')}
                          </>
                        ) : (
                          t('mobile.lines.autoOff')
                        )}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-xs">
                      <When iso={l.lastSeenAt} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
