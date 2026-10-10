import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { ArrowLeft, ArrowRight, Info, RefreshCw, Save, Smartphone, Wallet } from 'lucide-react';
import toast from 'react-hot-toast';
import {
  CAPABILITIES,
  MB_PER_GB,
  formatData,
  isMasterTenant,
  type SimPartnerRecharge,
  type SimPartnerRechargeOutcome,
  type SimRecharge,
  type SimRechargeOffers,
  type SimZoneUsage,
} from '@obliwan/shared';
import { simApi, errorMessageOf, type SimLineListItem } from '@/api/sim.api';
import { sitesApi } from '@/api/sites.api';
import { devicesApi } from '@/api/devices.api';
import { useAuthStore } from '@/store/authStore';
import { useTenantStore } from '@/store/tenantStore';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import {
  DataAmount,
  EmptyState,
  Money,
  Panel,
  RechargeStatusBadge,
  VerdictBadge,
  When,
} from '@/components/mobile/SimBits';
import { LineStatusBadge, SimPartnerFactsPanel } from '@/components/mobile/SimPartnerFacts';
import { ZoneUsageLine } from '@/components/mobile/ZoneUsage';
import type { Device, Site } from '@/types/fleet';
import { cn } from '@/utils/cn';

const selectClass =
  'w-full rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent';

/**
 * ObliWAN — one SIM line.
 *
 * ┌─ WHAT THE SCREEN SAYS, TOP TO BOTTOM ─────────────────────────────────────┐
 * │ 1. WHO the line is: number, ICCID (or "unknown" — never blank), status,   │
 * │    and where it is attached — workspace (god view), site, router, each a  │
 * │    link. A pooled line says so in the header, not three panels down.      │
 * │ 2. EACH ZONE against ITS OWN envelope (brick 6): « 72 % utilisés ·         │
 * │    7,2 Go / 10 Go », its own verdict, which rule judged it (the % of the  │
 * │    envelope, or the MB fallback when no envelope is known) and which zone │
 * │    decides the line. A zone with no envelope shows its consumption and   │
 * │    the MB rule — never a 0 Go envelope, never 100 % (null is not 0).      │
 * │ 3. The consumption history, the partner's facts (secrets behind an       │
 * │    audited reveal), the top-ups: the open proposals apart from the past. │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE THRESHOLD FIELD IS IN MEGABYTES, AND THE SCREEN SAYS SO ─────────────┐
 * │ The same reason `ThresholdsPage` prints its unit next to every box: an    │
 * │ operator who types "1" meaning one gigabyte into a field that means       │
 * │ megabytes has just armed an alert at 1 Mo, which fires the day the line   │
 * │ is already dead. The field shows the equivalent in Go live, underneath.   │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE AUTO TOGGLE DOES NOT BUY ANYTHING ───────────────────────────────────┐
 * │ It decides whether this line may PRODUCE a proposal. The proposal is then │
 * │ approved by somebody holding SIM_RECHARGE, and the top-up itself is       │
 * │ bought on the partner's portal — ObliWAN has no endpoint to buy with. The │
 * │ note under the toggle says exactly that, because a switch labelled        │
 * │ "automatic top-up" that quietly means "automatic proposal" is a switch    │
 * │ somebody will believe.                                                    │
 * └───────────────────────────────────────────────────────────────────────────┘
 */
export function MobileLineDetailPage() {
  const { t } = useTranslation();
  const { id } = useParams<{ id: string }>();
  const lineId = Number(id);
  const hasCapability = useAuthStore((s) => s.hasCapability);
  const canWriteObject = useAuthStore((s) => s.canWriteObject);
  const canManageCapability = hasCapability(CAPABILITIES.SIM_MANAGE);

  // ┌─ THE WORKSPACE PICKER IS WHAT MAKES SIM LINES DO ANYTHING AT ALL ──────┐
  // │ A line arrives from the partner in the POOL (`tenant_id IS NULL`), and │
  // │ a pooled line raises no alert, produces no proposal and appears on no  │
  // │ re-invoicing report — every one of those paths requires a tenant. The  │
  // │ first draft of this page offered a site and a router picker and NO     │
  // │ workspace picker, and `updateLine` refuses a tenant change from a      │
  // │ non-master caller, so on a fresh install nothing could ever leave the  │
  // │ pool: the detection, approval and billing halves of the feature were   │
  // │ unreachable through the product.                                       │
  // │                                                                        │
  // │ Shown only in the master workspace, because that is the only scope the │
  // │ server accepts a re-assignment from — a picker that always 403s is     │
  // │ worse than none.                                                       │
  // └────────────────────────────────────────────────────────────────────────┘
  const tenants = useTenantStore((s) => s.tenants);
  const fetchTenants = useTenantStore((s) => s.fetchTenants);
  const currentTenantId = useTenantStore((s) => s.currentTenantId);
  const isPlatformAdmin = useAuthStore((s) => s.isAdmin)();
  const canAssignWorkspace = isPlatformAdmin && isMasterTenant(currentTenantId);

  const [line, setLine] = useState<SimLineListItem | null>(null);
  // SIM_MANAGE says what the caller may do; their teams say on which lines
  // (`line.access`, migration 087): a line they only read is not editable.
  const lineWritable = canWriteObject(line);
  const canManage = canManageCapability && lineWritable;
  // The site and router pickers list the inventory of the workspace chosen in
  // the form — never the session's. In the god view the session sees every
  // tenant, and a line of customer E was offered customer D's sites and routers.
  const [sites, setSites] = useState<Site[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [history, setHistory] = useState<
    Array<{ zone: string; restMb: number | null; usedMb: number | null; observedAt: string }>
  >([]);
  const [historyZone, setHistoryZone] = useState('');
  const [recharges, setRecharges] = useState<SimRecharge[]>([]);
  // What the partner itself says was bought on this line (stored by the sweep).
  const [partnerHistory, setPartnerHistory] = useState<SimPartnerRecharge[]>([]);
  // The partner's volume catalogue: a LIVE partner read, so only on request.
  const [offers, setOffers] = useState<SimRechargeOffers | null>(null);
  const [offersLoading, setOffersLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  // Draft state for the editable fields.
  const [siteId, setSiteId] = useState<string>('');
  const [deviceId, setDeviceId] = useState<string>('');
  const [label, setLabel] = useState('');
  const [iccid, setIccid] = useState('');
  const [tenantId, setTenantId] = useState<string>('');
  const [thresholdMb, setThresholdMb] = useState('');
  const [planMb, setPlanMb] = useState('');
  const [auto, setAuto] = useState(false);

  const load = useCallback(async () => {
    if (!Number.isInteger(lineId) || lineId <= 0) return;
    setLoading(true);
    try {
      const [l, h, r] = await Promise.all([
        simApi.line(lineId),
        simApi.lineHistory(lineId, 90),
        simApi.recharges({ simId: lineId, limit: 50 }),
      ]);
      setLine(l);
      setHistory(h);
      setRecharges(r);
      // Loaded apart and allowed to fail on its own: an older server without
      // the route must not blank the whole line screen.
      simApi
        .partnerRecharges(lineId)
        .then(setPartnerHistory)
        .catch(() => setPartnerHistory([]));
      setTenantId(l.tenantId === null ? '' : String(l.tenantId));
      setSiteId(l.siteId === null ? '' : String(l.siteId));
      setDeviceId(l.deviceId === null ? '' : String(l.deviceId));
      setLabel(l.label ?? '');
      setIccid(l.iccid ?? '');
      setThresholdMb(l.lowThresholdMb === null ? '' : String(l.lowThresholdMb));
      setPlanMb(l.rechargePlanMb === null ? '' : String(l.rechargePlanMb));
      setAuto(l.autoRechargeEnabled);
    } catch (err) {
      toast.error(errorMessageOf(err));
    } finally {
      setLoading(false);
    }
  }, [lineId]);

  useEffect(() => {
    void load();
    if (canAssignWorkspace) void fetchTenants();
  }, [load, fetchTenants, canAssignWorkspace]);

  // Reloaded whenever the form's workspace changes. `filterTenantId` narrows a
  // god-view list to that tenant (the server ignores it for anyone else, whose
  // session already IS the line's tenant), and the rows are filtered on their
  // tenant again here, so a list that came back wider never offers a foreign
  // site. The server refuses a cross-tenant pair anyway (`assertBelongs`).
  useEffect(() => {
    const target = tenantId === '' ? null : Number(tenantId);
    if (target === null) {
      setSites([]);
      setDevices([]);
      return;
    }
    let live = true;
    const byName = <T extends { name: string }>(a: T, b: T) =>
      a.name.localeCompare(b.name, undefined, { numeric: true });
    sitesApi
      .list({ filterTenantId: target })
      .then((rows) => live && setSites(rows.filter((r) => r.tenantId === target).sort(byName)))
      .catch(() => live && setSites([]));
    devicesApi
      .list({ filterTenantId: target })
      .then((rows) => live && setDevices(rows.filter((r) => r.tenantId === target).sort(byName)))
      .catch(() => live && setDevices([]));
    return () => {
      live = false;
    };
  }, [tenantId]);

  // Changing the workspace in the form drops a site and router that belong to
  // the previous one; coming back to the stored workspace restores the stored
  // pair.
  const pickTenant = (next: string) => {
    setTenantId(next);
    const stored = line?.tenantId === null || line === null ? '' : String(line.tenantId);
    setSiteId(next === stored && line?.siteId != null ? String(line.siteId) : '');
    setDeviceId(next === stored && line?.deviceId != null ? String(line.deviceId) : '');
  };

  // Each zone's judged usage, by zone name (the server builds both lists from
  // the same rows; the name is the join, not the position).
  const usageByZone = useMemo(
    () => new Map<string, SimZoneUsage>((line?.usage ?? []).map((u) => [u.zone, u])),
    [line],
  );
  const historyZones = useMemo(() => [...new Set(history.map((h) => h.zone))].sort(), [history]);
  const shownHistory = historyZone === '' ? history : history.filter((h) => h.zone === historyZone);
  const openRecharges = recharges.filter((r) => r.status === 'proposed' || r.status === 'approved');
  const pastRecharges = recharges.filter((r) => r.status !== 'proposed' && r.status !== 'approved');

  const loadOffers = async () => {
    if (!line) return;
    setOffersLoading(true);
    try {
      setOffers(await simApi.rechargeOffers(line.id));
    } catch (err) {
      toast.error(errorMessageOf(err));
    } finally {
      setOffersLoading(false);
    }
  };

  const save = async () => {
    if (!line) return;
    setSaving(true);
    try {
      const nextTenant = tenantId === '' ? null : Number(tenantId);

      // The pickers list the inventory of the workspace chosen in the form
      // (reset when it changes), so on a move the site and router sent belong
      // to the DESTINATION — the server checks them against it. Returning a
      // line to the pool clears both.
      const updated = await simApi.updateLine(line.id, {
        // Only sent when this session may actually change it, and only when it
        // differs — so an ordinary edit by a tenant admin never carries a
        // `tenantId` the server would refuse.
        ...(movingWorkspace ? { tenantId: nextTenant } : {}),
        siteId: nextTenant === null || siteId === '' ? null : Number(siteId),
        deviceId: nextTenant === null || deviceId === '' ? null : Number(deviceId),
        label: label.trim() === '' ? null : label.trim(),
        iccid: iccid.trim() === '' ? null : iccid.trim(),
        // An empty box means "use the global default", which is `null` — not 0.
        // Sending 0 would arm an alert at zero remaining, i.e. never.
        lowThresholdMb: thresholdMb.trim() === '' ? null : Number(thresholdMb),
        rechargePlanMb: planMb.trim() === '' ? null : Number(planMb),
        autoRechargeEnabled: auto,
      });
      // A PATCH answer may carry no `access`: saving does not change the caller's level.
      setLine((prev) => ({ ...updated, access: updated.access ?? prev?.access }));
      toast.success(t('mobile.detail.saved'));
    } catch (err) {
      toast.error(errorMessageOf(err));
    } finally {
      setSaving(false);
    }
  };

  const propose = async (zone: string) => {
    if (!line) return;
    try {
      await simApi.propose({
        simId: line.id,
        zone,
        planMb: planMb.trim() === '' ? null : Number(planMb),
      });
      toast.success(t('mobile.detail.proposed'));
      setRecharges(await simApi.recharges({ simId: line.id, limit: 50 }));
    } catch (err) {
      toast.error(errorMessageOf(err));
    }
  };

  if (loading && !line) {
    return (
      <div className="flex h-64 items-center justify-center">
        <LoadingSpinner />
      </div>
    );
  }
  if (!line) {
    return <div className="p-6 text-sm text-text-secondary">{t('mobile.detail.notFound')}</div>;
  }

  // True while the form proposes a DIFFERENT workspace from the stored one: the
  // pickers then list the destination's inventory, and the hint says what the
  // move closes.
  const movingWorkspace =
    canAssignWorkspace && (tenantId === '' ? null : Number(tenantId)) !== line.tenantId;

  const gbHint =
    thresholdMb.trim() === '' || Number.isNaN(Number(thresholdMb))
      ? null
      : (Number(thresholdMb) / MB_PER_GB).toFixed(2);

  // The server sends `tenantName` on the master god view only.
  const godView = line.tenantName !== undefined;
  const terminated = line.status === 'terminated';
  // The zone the line's verdict comes from. None on a terminated or unreadable line.
  const decidingZone = line.verdict === 'terminated' ? null : (line.worstUsage?.zone ?? line.worstZone?.zone ?? null);

  return (
    <div className="p-6">
      <Link
        to="/mobile/lines"
        className="mb-4 inline-flex items-center gap-1.5 text-sm text-text-secondary hover:text-text-primary"
      >
        <ArrowLeft size={14} />
        {t('mobile.detail.back')}
      </Link>

      {/* ── Header: who the line is, and where it is attached ─────────────── */}
      <section className="mb-6 rounded-lg border border-border bg-bg-secondary p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <Smartphone size={18} className="text-text-muted" />
              <h1 className="font-mono text-2xl font-semibold text-text-primary">{line.msisdn}</h1>
              <LineStatusBadge status={line.status} />
              {/* A terminated line's verdict IS its status: one badge, not two. */}
              {line.verdict !== 'terminated' ? <VerdictBadge verdict={line.verdict} stale={line.stale} /> : null}
              {line.tenantId === null ? (
                // Loud on purpose: a pooled line is a SIM paid for and billed to nobody.
                <span className="rounded-full border border-accent/30 bg-accent/10 px-2 py-0.5 text-[11px] text-accent">
                  {t('mobile.lines.pool')}
                </span>
              ) : null}
            </div>
            {line.label ? <p className="mt-1 text-sm text-text-secondary">{line.label}</p> : null}
          </div>
          <Button variant="secondary" size="sm" onClick={() => void load()}>
            <RefreshCw size={14} className="mr-1.5" />
            {t('common.refresh')}
          </Button>
        </div>

        <dl className="mt-4 grid grid-cols-1 gap-x-6 gap-y-3 sm:grid-cols-2 lg:grid-cols-4">
          <Fact label={t('mobile.detail.facts.iccid')} mono>
            {line.iccid ?? <span className="font-sans text-text-muted">{t('mobile.detail.iccidUnknown')}</span>}
          </Fact>
          {godView || line.tenantId === null ? (
            <Fact label={t('mobile.detail.facts.tenant')}>
              {line.tenantId === null ? (
                <span className="text-text-muted">{t('mobile.detail.unassignedPool')}</span>
              ) : (
                (line.tenantName ?? `#${line.tenantId}`)
              )}
            </Fact>
          ) : null}
          <Fact label={t('mobile.detail.facts.site')}>
            {line.siteId !== null ? (
              <Link to={`/sites/${line.siteId}`} className="hover:text-accent">
                {line.siteName ?? `#${line.siteId}`}
              </Link>
            ) : (
              <span className="text-text-muted">{t('mobile.noSite')}</span>
            )}
          </Fact>
          <Fact label={t('mobile.detail.facts.router')}>
            {line.deviceId !== null ? (
              <Link to={`/devices/${line.deviceId}`} className="hover:text-accent">
                {line.deviceName ?? `#${line.deviceId}`}
              </Link>
            ) : (
              <span className="text-text-muted">{t('mobile.detail.noRouterLinked')}</span>
            )}
          </Fact>
          <Fact label={t('mobile.detail.facts.operator')}>
            {line.operator ?? <span className="text-text-muted">{t('mobile.noOperator')}</span>}
          </Fact>
          <Fact label={t('mobile.detail.facts.plan')}>
            {line.partner?.planLabel ?? <span className="text-text-muted">—</span>}
          </Fact>
          <Fact label={t('mobile.detail.facts.account')}>{line.accountName || '—'}</Fact>
          <Fact label={t('mobile.detail.facts.lastSeen')}>
            <When iso={line.lastSeenAt} />
          </Fact>
        </dl>
      </section>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          {/* ── Zones, each against its own envelope ───────────────────────── */}
          <Panel title={t('mobile.detail.zonesTitle')}>
            <div className="flex flex-wrap gap-x-4 gap-y-1 border-b border-border px-4 py-2 text-[12px] text-text-secondary">
              <span>{t('mobile.detail.alertPercent', { pct: line.thresholdPercent })}</span>
              <span>
                {line.planEnvelopeMb !== null
                  ? t('mobile.detail.envelopeFromPlanLabel', { value: formatData(line.planEnvelopeMb) })
                  : t('mobile.detail.noPlanEnvelope')}
              </span>
              <span>{t('mobile.detail.fallbackThreshold', { value: formatData(line.thresholdMb) })}</span>
            </div>
            {line.zones.length === 0 ? (
              <EmptyState message={t('mobile.detail.noZones')} />
            ) : (
              <ul className="divide-y divide-border">
                {line.zones.map((z) => {
                  const u = usageByZone.get(z.zone) ?? null;
                  const deciding = decidingZone !== null && z.zone === decidingZone && line.zones.length > 1;
                  return (
                    <li key={z.zone} className={cn('px-4 py-3', deciding && 'bg-bg-tertiary/40')}>
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-medium text-text-primary">{z.zone}</span>
                          {u && !terminated ? <VerdictBadge verdict={u.verdict} stale={u.stale} /> : null}
                          {deciding ? (
                            <span className="rounded-full border border-border px-2 py-0.5 text-[11px] text-text-secondary">
                              {t('mobile.detail.worstZone')}
                            </span>
                          ) : null}
                        </div>
                        {canManage && !terminated ? (
                          <Button variant="ghost" size="sm" onClick={() => void propose(z.zone)}>
                            <Wallet size={13} className="mr-1" />
                            {t('mobile.detail.propose')}
                          </Button>
                        ) : null}
                      </div>
                      <div className="mt-2 grid gap-4 md:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
                        <ZoneUsageLine usage={u} thresholdPercent={line.thresholdPercent} thresholdMb={line.thresholdMb} />
                        <dl className="grid grid-cols-2 gap-x-4 gap-y-1.5 sm:grid-cols-3">
                          <Fact small label={t('mobile.detail.used')}>
                            <DataAmount mb={u ? u.usedMb : z.usedMb} />
                          </Fact>
                          <Fact small label={t('mobile.lines.remaining')}>
                            <DataAmount mb={z.restMb} />
                          </Fact>
                          <Fact small label={t('mobile.detail.bought')}>
                            <DataAmount mb={z.rechargeMb} />
                          </Fact>
                          <Fact small label={t('mobile.detail.lowSince')}>
                            <When iso={z.lowSince} />
                          </Fact>
                          {/* A zone the partner stopped returning keeps its last
                              row forever (`applyBalances` only upserts the zones
                              present): without the date a four-month-old reading
                              looks like a fresh one. */}
                          <Fact small label={t('mobile.detail.observedAt')}>
                            <When iso={z.observedAt} />
                          </Fact>
                        </dl>
                      </div>
                      {u && !terminated ? (
                        <p className={cn('mt-1.5 text-[11px]', u.stale ? 'text-status-ssl-warning' : 'text-text-muted')}>
                          {u.stale
                            ? t('mobile.detail.basis.stale')
                            : u.basis === 'percent'
                              ? t('mobile.detail.basis.percent', { pct: line.thresholdPercent })
                              : u.basis === 'mb'
                                ? t('mobile.detail.basis.mb', { value: formatData(line.thresholdMb) })
                                : t('mobile.detail.basis.none')}
                        </p>
                      ) : null}
                    </li>
                  );
                })}
              </ul>
            )}
          </Panel>

          {/* ── Consumption history ───────────────────────────────────────── */}
          <Panel
            title={t('mobile.detail.history')}
            action={
              historyZones.length > 1 ? (
                <select
                  className="rounded-md border border-border bg-bg-tertiary px-2 py-1 text-xs text-text-primary"
                  value={historyZone}
                  onChange={(e) => setHistoryZone(e.target.value)}
                >
                  <option value="">{t('mobile.detail.allZones')}</option>
                  {historyZones.map((z) => (
                    <option key={z} value={z}>
                      {z}
                    </option>
                  ))}
                </select>
              ) : undefined
            }
          >
            {shownHistory.length === 0 ? (
              <EmptyState message={t('mobile.detail.noHistory')} />
            ) : (
              <div className="max-h-80 overflow-y-auto">
                <table className="w-full text-sm">
                  <thead className="sticky top-0 border-b border-border bg-bg-secondary text-left text-xs text-text-muted">
                    <tr>
                      <th className="px-4 py-2 font-medium">{t('mobile.detail.observedAt')}</th>
                      <th className="px-4 py-2 font-medium">{t('mobile.lines.zone')}</th>
                      <th className="px-4 py-2 text-right font-medium">{t('mobile.detail.used')}</th>
                      <th className="px-4 py-2 text-right font-medium">{t('mobile.lines.remaining')}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {shownHistory.map((h, i) => (
                      <tr key={`${h.observedAt}-${h.zone}-${i}`}>
                        <td className="px-4 py-1.5 text-xs">
                          <When iso={h.observedAt} />
                        </td>
                        <td className="px-4 py-1.5 text-text-secondary">{h.zone}</td>
                        <td className="px-4 py-1.5 text-right">
                          <DataAmount mb={h.usedMb} />
                        </td>
                        <td className="px-4 py-1.5 text-right">
                          <DataAmount mb={h.restMb} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <p className="flex items-start gap-2 border-t border-border px-4 py-2 text-[11px] text-text-muted">
              <Info size={12} className="mt-0.5 shrink-0" />
              {t('mobile.detail.historyHint')}
            </p>
          </Panel>
        </div>

        {/* ── Assignment and policy ───────────────────────────────────────── */}
        <Panel title={t('mobile.detail.policy')} className="self-start">
          <div className="space-y-3 p-4">
            {canAssignWorkspace ? (
              <label className="block">
                <span className="mb-1 block text-xs text-text-secondary">
                  {t('mobile.detail.workspace')}
                </span>
                <select
                  className={selectClass}
                  value={tenantId}
                  disabled={!canManage}
                  onChange={(e) => pickTenant(e.target.value)}
                >
                  <option value="">{t('mobile.detail.unassignedPool')}</option>
                  {tenants.map((tn) => (
                    <option key={tn.id} value={tn.id}>
                      {tn.name}
                    </option>
                  ))}
                </select>
                <span className="mt-1 block text-[11px] text-text-muted">
                  {t('mobile.detail.workspaceHint')}
                </span>
              </label>
            ) : null}

            <label className="block">
              <span className="mb-1 block text-xs text-text-secondary">
                {t('mobile.lines.site')}
              </span>
              <select
                className={selectClass}
                value={siteId}
                disabled={!canManage || tenantId === ''}
                onChange={(e) => setSiteId(e.target.value)}
              >
                <option value="">{t('mobile.detail.none')}</option>
                {sites.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name}
                  </option>
                ))}
              </select>
            </label>

            <label className="block">
              <span className="mb-1 block text-xs text-text-secondary">
                {t('mobile.detail.router')}
              </span>
              <select
                className={selectClass}
                value={deviceId}
                disabled={!canManage || tenantId === ''}
                onChange={(e) => setDeviceId(e.target.value)}
              >
                <option value="">{t('mobile.detail.none')}</option>
                {devices.map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.name}
                  </option>
                ))}
              </select>
              <span className="mt-1 block text-[11px] text-text-muted">
                {t('mobile.detail.routerHint')}
              </span>
            </label>

            {tenantId === '' ? (
              <p className="rounded-md border border-accent/30 bg-accent/5 px-3 py-2 text-[11px] text-text-secondary">
                {canAssignWorkspace
                  ? t('mobile.detail.poolHintAdmin')
                  : t('mobile.detail.poolHint')}
              </p>
            ) : movingWorkspace ? (
              <p className="rounded-md border border-status-ssl-warning/30 bg-status-ssl-warning/5 px-3 py-2 text-[11px] text-text-secondary">
                {t('mobile.detail.movingHint')}
              </p>
            ) : null}

            <label className="block">
              <span className="mb-1 block text-xs text-text-secondary">
                {t('mobile.detail.label')}
              </span>
              <Input value={label} disabled={!canManage} onChange={(e) => setLabel(e.target.value)} />
            </label>

            <label className="block">
              <span className="mb-1 block text-xs text-text-secondary">
                {t('mobile.detail.iccid')}
              </span>
              <Input
                value={iccid}
                disabled={!canManage}
                placeholder={t('mobile.detail.iccidPlaceholder')}
                onChange={(e) => setIccid(e.target.value)}
              />
              <span className="mt-1 block text-[11px] text-text-muted">
                {t('mobile.detail.iccidHint')}
              </span>
            </label>

            <label className="block">
              <span className="mb-1 block text-xs text-text-secondary">
                {t('mobile.detail.threshold')}
              </span>
              <Input
                value={thresholdMb}
                disabled={!canManage}
                inputMode="numeric"
                placeholder={t('mobile.detail.thresholdPlaceholder', {
                  value: formatData(line.thresholdMb),
                })}
                onChange={(e) => setThresholdMb(e.target.value)}
              />
              {/* The unit, next to the box — see the header. */}
              <span className="mt-1 block text-[11px] text-text-muted">
                {gbHint === null
                  ? t('mobile.detail.thresholdUnit')
                  : t('mobile.detail.thresholdEquals', { gb: gbHint })}
              </span>
            </label>

            <label className="block">
              <span className="mb-1 block text-xs text-text-secondary">
                {t('mobile.detail.planMb')}
              </span>
              <Input
                value={planMb}
                disabled={!canManage}
                inputMode="numeric"
                onChange={(e) => setPlanMb(e.target.value)}
              />
            </label>

            <label className="flex items-start gap-2">
              <input
                type="checkbox"
                className="mt-0.5"
                checked={auto}
                disabled={!canManage}
                onChange={(e) => setAuto(e.target.checked)}
              />
              <span className="text-xs">
                <span className="block text-text-primary">{t('mobile.detail.auto')}</span>
                <span className="mt-0.5 block text-text-muted">{t('mobile.detail.autoHint')}</span>
              </span>
            </label>

            {canManage ? (
              <Button className="w-full" loading={saving} onClick={() => void save()}>
                <Save size={14} className="mr-1.5" />
                {t('common.save')}
              </Button>
            ) : canManageCapability ? (
              <p className="text-xs italic text-text-muted">{t('teamScope.readOnlyHint')}</p>
            ) : null}
          </div>
        </Panel>
      </div>

      {/* ── What the partner's listing says: every field, secrets behind a reveal ── */}
      <SimPartnerFactsPanel line={line} />

      {/* ── Open proposals: decided on the top-up queue, shown here ───────── */}
      <Panel
        className="mt-6"
        title={t('mobile.detail.openProposals')}
        action={
          <Link to="/mobile/recharges" className="inline-flex items-center gap-1 text-xs text-text-secondary hover:text-accent">
            {t('mobile.detail.goToQueue')}
            <ArrowRight size={12} />
          </Link>
        }
      >
        {openRecharges.length === 0 ? (
          <EmptyState message={t('mobile.detail.noOpenProposals')} />
        ) : (
          <RechargeTable rows={openRecharges} open />
        )}
      </Panel>

      {/* ── Top-ups on this line, past ────────────────────────────────────── */}
      <Panel className="mt-6" title={t('mobile.detail.rechargeHistory')}>
        {pastRecharges.length === 0 ? (
          <EmptyState message={t(recharges.length === 0 ? 'mobile.detail.noRecharges' : 'mobile.detail.noPastRecharges')} />
        ) : (
          <RechargeTable rows={pastRecharges} open={false} />
        )}
      </Panel>

      {/* ── What the partner says was bought ──────────────────────────────── */}
      <Panel className="mt-6" title={t('mobile.detail.partnerHistory')}>
        {partnerHistory.length === 0 ? (
          <EmptyState message={t('mobile.detail.noPartnerHistory')} />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-border text-left text-xs text-text-muted">
                <tr>
                  <th className="px-4 py-2 font-medium">{t('mobile.detail.partnerDate')}</th>
                  <th className="px-4 py-2 text-right font-medium">{t('mobile.detail.partnerVolume')}</th>
                  <th className="px-4 py-2 font-medium">{t('mobile.detail.partnerZone')}</th>
                  <th className="px-4 py-2 font-medium">{t('mobile.detail.partnerProduct')}</th>
                  <th className="px-4 py-2 font-medium">{t('mobile.detail.partnerStatus')}</th>
                  <th className="px-4 py-2 font-medium">{t('mobile.detail.partnerLink')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {partnerHistory.map((p) => (
                  <tr key={p.id}>
                    <td className="px-4 py-2 text-xs">
                      {p.requestedAt ? <When iso={p.requestedAt} /> : <span className="text-text-muted">{p.period ?? '—'}</span>}
                    </td>
                    <td className="px-4 py-2 text-right">
                      <DataAmount mb={p.volumeMb} />
                    </td>
                    <td className="px-4 py-2 text-text-secondary">{p.zoneCode ?? '—'}</td>
                    <td className="px-4 py-2 text-text-secondary">{p.productCode ?? '—'}</td>
                    <td className="px-4 py-2">
                      <PartnerOutcomeBadge outcome={p.outcome} raw={p.partnerStatus} />
                    </td>
                    <td className="px-4 py-2 text-xs text-text-secondary">
                      {p.rechargeId !== null
                        ? t('mobile.detail.partnerLinked', { id: p.rechargeId })
                        : p.outcome === 'ok'
                          ? t('mobile.detail.partnerUnlinked')
                          : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="flex items-start gap-2 border-t border-border px-4 py-2 text-[11px] text-text-muted">
          <Info size={12} className="mt-0.5 shrink-0" />
          {t('mobile.detail.partnerHistoryHint')}
        </p>
      </Panel>

      {/* ── The partner's volume catalogue — read on request, buys nothing ──── */}
      <Panel className="mt-6" title={t('mobile.detail.offers')}>
        {offers === null ? (
          <div className="flex items-center gap-3 px-4 py-3">
            <Button variant="secondary" size="sm" onClick={() => void loadOffers()} disabled={offersLoading}>
              <RefreshCw size={14} className={offersLoading ? 'animate-spin' : ''} />
              <span className="ml-1.5">{t('mobile.detail.offersLoad')}</span>
            </Button>
          </div>
        ) : (
          <div className="divide-y divide-border">
            {offers.zones.length === 0 ? (
              <EmptyState message={t('mobile.detail.offersNone')} />
            ) : (
              offers.zones.map((z) => (
                <div key={`${z.zone}-${z.zoneCode ?? ''}`} className="px-4 py-3">
                  <div className="mb-2 text-xs font-medium text-text-secondary">{z.zone}</div>
                  {z.error ? (
                    <p className="text-xs text-status-down">{z.error}</p>
                  ) : z.offers.length === 0 ? (
                    <p className="text-xs text-text-muted">{t('mobile.detail.offersNone')}</p>
                  ) : (
                    <div className="flex flex-wrap gap-2">
                      {z.offers.map((o) => (
                        <span
                          key={o.code}
                          className="inline-flex items-center rounded-full border border-border px-2.5 py-0.5 text-xs text-text-primary"
                          title={o.code}
                        >
                          {o.label ?? (o.volumeMb !== null ? formatData(o.volumeMb) : o.code)}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        )}
        <p className="flex items-start gap-2 border-t border-border px-4 py-2 text-[11px] text-text-muted">
          <Info size={12} className="mt-0.5 shrink-0" />
          {t('mobile.detail.offersHint')}
        </p>
      </Panel>
    </div>
  );
}

/** One labelled fact. `small` for the per-zone grid. */
function Fact({
  label,
  children,
  mono = false,
  small = false,
}: {
  label: string;
  children: ReactNode;
  mono?: boolean;
  small?: boolean;
}) {
  return (
    <div className="min-w-0">
      <dt className={cn('text-text-muted', small ? 'text-[10px] uppercase tracking-wide' : 'text-[11px]')}>{label}</dt>
      <dd className={cn('mt-0.5 break-words text-text-primary', small ? 'text-xs' : 'text-[13px]', mono && 'font-mono')}>
        {children}
      </dd>
    </div>
  );
}

/**
 * The line's top-ups. `open`: proposed / approved — waiting for a decision or
 * for the purchase to be recorded, which happens on the top-up queue, not here.
 * A cost is "—" until priced, never 0 (an unpriced top-up is the normal state
 * of a fresh row).
 */
function RechargeTable({ rows, open }: { rows: SimRecharge[]; open: boolean }) {
  const { t } = useTranslation();
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="border-b border-border text-left text-xs text-text-muted">
          <tr>
            <th className="px-4 py-2 font-medium">{t('mobile.recharges.proposed')}</th>
            <th className="px-4 py-2 font-medium">{t('mobile.lines.zone')}</th>
            <th className="px-4 py-2 font-medium">{t('mobile.detail.trigger')}</th>
            <th className="px-4 py-2 text-right font-medium">{t('mobile.recharges.atProposal')}</th>
            <th className="px-4 py-2 text-right font-medium">{t('mobile.detail.volume')}</th>
            {open ? null : <th className="px-4 py-2 text-right font-medium">{t('mobile.recharges.cost')}</th>}
            <th className="px-4 py-2 font-medium">{t('mobile.recharges.status')}</th>
            <th className="px-4 py-2 font-medium">{t('mobile.recharges.decidedBy')}</th>
            {open ? null : <th className="px-4 py-2 font-medium">{t('mobile.detail.completedAt')}</th>}
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {rows.map((r) => (
            <tr key={r.id}>
              <td className="px-4 py-2 text-xs">
                <When iso={r.proposedAt} />
              </td>
              <td className="px-4 py-2 text-text-secondary">{r.zone}</td>
              <td className="px-4 py-2 text-xs text-text-secondary">
                {t(`mobile.trigger.${r.trigger}`, { defaultValue: r.trigger })}
              </td>
              <td className="px-4 py-2 text-right">
                <DataAmount mb={r.restMbAtProposal} />
              </td>
              <td className="px-4 py-2 text-right">
                <DataAmount mb={r.planMb} />
              </td>
              {open ? null : (
                <td className="px-4 py-2 text-right">
                  <Money cents={r.costCents} currency={r.currency} />
                </td>
              )}
              <td className="px-4 py-2">
                <RechargeStatusBadge status={r.status} />
              </td>
              <td className="px-4 py-2 text-xs text-text-secondary">
                {r.decidedByName ?? <span className="text-text-muted">—</span>}
              </td>
              {open ? null : (
                <td className="px-4 py-2 text-xs">
                  <When iso={r.completedAt} />
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const OUTCOME_CLASS: Record<SimPartnerRechargeOutcome, string> = {
  ok: 'bg-status-up/15 text-status-up border-status-up/30',
  pending: 'bg-status-ssl-warning/15 text-status-ssl-warning border-status-ssl-warning/30',
  failed: 'bg-status-down/15 text-status-down border-status-down/30',
  unknown: 'bg-text-muted/10 text-text-secondary border-border',
};

/** Our reading of the partner's status, with the partner's raw value on hover. */
function PartnerOutcomeBadge({ outcome, raw }: { outcome: SimPartnerRechargeOutcome; raw: string | null }) {
  const { t } = useTranslation();
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium ${OUTCOME_CLASS[outcome]}`}
      title={raw ?? undefined}
    >
      {t(`mobile.detail.partnerOutcome.${outcome}`)}
    </span>
  );
}
