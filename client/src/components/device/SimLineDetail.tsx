import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { ArrowRight, Info, RefreshCw, Smartphone, Wallet } from 'lucide-react';
import {
  CAPABILITIES,
  formatData,
  type SimPartnerRecharge,
  type SimPartnerRechargeOutcome,
  type SimRecharge,
  type SimRechargeOffers,
  type SimZoneUsage,
} from '@obliwan/shared';
import { simApi, errorMessageOf, type SimLineListItem } from '@/api/sim.api';
import { useAuthStore } from '@/store/authStore';
import { Button } from '@/components/common/Button';
import {
  DataAmount, EmptyState, Panel, RechargeStatusBadge, VerdictBadge, When,
} from '@/components/mobile/SimBits';
import { LineStatusBadge, SimPartnerFactsPanel } from '@/components/mobile/SimPartnerFacts';
import { ZoneUsageLine } from '@/components/mobile/ZoneUsage';
import { cn } from '@/utils/cn';
import { LINK_BUTTON } from './StatusSection';

/**
 * One mobile line, as the device page's « 4G / SIM » tab shows it: everything
 * the line's own page says, read here so the operator does not leave the
 * router to know what its SIM is doing.
 *
 * ┌─ NOTHING HERE SPENDS MONEY ───────────────────────────────────────────────┐
 * │ The two writes this block offers are the line page's own, behind the same │
 * │ gates: « Proposer une recharge » (SIM_MANAGE) creates a PROPOSAL, which   │
 * │ somebody holding SIM_RECHARGE approves on the Recharges page, and the     │
 * │ top-up itself is bought on the partner's portal (`SIM_RECHARGE_ADAPTERS`  │
 * │ is empty). The catalogue is a live partner READ, on request. Editing the  │
 * │ line (workspace, router, threshold, auto proposal) stays on its page: the │
 * │ workspace-move rules live there and are not restated here.                │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * `null` is never 0 on this block either: every quantity goes through
 * `DataAmount` / `formatData`, which draw an absent reading as « — ».
 */

type History = Array<{ zone: string; restMb: number | null; usedMb: number | null; observedAt: string }>;

function Fact({ label, children, mono }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] text-text-muted">{label}</dt>
      <dd className={cn('mt-0.5 break-words text-[13px] text-text-primary', mono && 'font-mono')}>
        {children === null || children === undefined || children === ''
          ? <span className="text-text-muted">—</span>
          : children}
      </dd>
    </div>
  );
}

function Tile({ label, mb }: { label: string; mb: number | null }) {
  return (
    <div className="rounded-md border border-border bg-bg-tertiary/40 px-3 py-2">
      <div className="text-[11px] text-text-muted">{label}</div>
      <DataAmount mb={mb} className="text-base font-semibold" />
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
      className={cn('inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium', OUTCOME_CLASS[outcome])}
      title={raw ?? undefined}
    >
      {t(`mobile.detail.partnerOutcome.${outcome}`)}
    </span>
  );
}

const TH = 'px-4 py-2 font-medium';
const TD = 'px-4 py-2';

export function SimLineDetail({ line }: { line: SimLineListItem }) {
  const { t } = useTranslation();
  const hasCapability = useAuthStore((s) => s.hasCapability);
  const canWriteObject = useAuthStore((s) => s.canWriteObject);
  // SIM_MANAGE says what the caller may do; their teams say on which lines.
  const canManage = hasCapability(CAPABILITIES.SIM_MANAGE) && canWriteObject(line);

  const [recharges, setRecharges] = useState<SimRecharge[] | null>(null);
  // A failed read is said, never drawn as « no top-up on this line ».
  const [rechargesFailed, setRechargesFailed] = useState(false);
  const [partnerHistory, setPartnerHistory] = useState<SimPartnerRecharge[] | null>(null);
  const [history, setHistory] = useState<History | null>(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [offers, setOffers] = useState<SimRechargeOffers | null>(null);
  const [offersLoading, setOffersLoading] = useState(false);

  const loadRecharges = useCallback(async () => {
    try {
      setRecharges(await simApi.recharges({ simId: line.id, limit: 50 }));
      setRechargesFailed(false);
    } catch {
      setRechargesFailed(true);
    }
  }, [line.id]);

  useEffect(() => {
    void loadRecharges();
    // Apart, and allowed to fail on its own — as on the line page.
    simApi.partnerRecharges(line.id).then(setPartnerHistory).catch(() => setPartnerHistory([]));
  }, [line.id, loadRecharges]);

  // Each zone's judged usage, joined by zone NAME (the server builds both
  // lists from the same rows; the name is the join, not the position).
  const usageByZone = useMemo(
    () => new Map<string, SimZoneUsage>(line.usage.map((u) => [u.zone, u])),
    [line.usage],
  );

  const propose = async (zone: string) => {
    try {
      await simApi.propose({ simId: line.id, zone, planMb: line.rechargePlanMb });
      toast.success(t('mobile.detail.proposed'));
      await loadRecharges();
    } catch (err) {
      toast.error(errorMessageOf(err));
    }
  };

  const loadHistory = async () => {
    setHistoryLoading(true);
    try {
      setHistory(await simApi.lineHistory(line.id, 90));
    } catch (err) {
      toast.error(errorMessageOf(err));
    } finally {
      setHistoryLoading(false);
    }
  };

  const loadOffers = async () => {
    setOffersLoading(true);
    try {
      setOffers(await simApi.rechargeOffers(line.id));
    } catch (err) {
      toast.error(errorMessageOf(err));
    } finally {
      setOffersLoading(false);
    }
  };

  const p = line.partner;
  const open = (recharges ?? []).filter((r) => r.status === 'proposed' || r.status === 'approved');
  const decidingZone = line.verdict === 'terminated' ? null : (line.worstUsage?.zone ?? line.worstZone?.zone ?? null);

  return (
    <div className="space-y-4">
      {/* ── Who the line is ───────────────────────────────────────────────── */}
      <section className="rounded-lg border border-border bg-bg-secondary">
        <div className="flex flex-wrap items-start justify-between gap-3 p-4">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <Smartphone size={17} className="text-text-muted" />
              <Link to={`/mobile/lines/${line.id}`} className="font-mono text-xl font-semibold text-accent hover:underline">
                {line.msisdn}
              </Link>
              <LineStatusBadge status={line.status} />
              {/* A terminated line's verdict IS its status: one badge, not two. */}
              {line.verdict !== 'terminated' && <VerdictBadge verdict={line.verdict} stale={line.stale} />}
            </div>
            <p className="mt-1 text-sm text-text-secondary">
              {[line.operator ?? t('mobile.noOperator'), line.accountName, line.label].filter(Boolean).join(' · ')}
            </p>
          </div>
          <Link to={`/mobile/lines/${line.id}`} className={LINK_BUTTON}>
            {t('devices.sim.openLine')}
            <ArrowRight size={14} className="ml-1.5" />
          </Link>
        </div>

        <dl className="grid grid-cols-2 gap-x-6 gap-y-3 border-t border-border p-4 md:grid-cols-3 xl:grid-cols-4">
          <Fact label={t('devices.sim.facts.plan')}>{p?.planLabel}</Fact>
          <Fact label={t('devices.sim.facts.partnerStatus')}>{p?.stateLabel ?? p?.state}</Fact>
          <Fact label={t('devices.sim.facts.iccid')} mono>{line.iccid}</Fact>
          <Fact label={t('devices.sim.facts.site')}>
            {line.siteId !== null
              ? <Link to={`/sites/${line.siteId}`} className="text-accent hover:underline">{line.siteName ?? `#${line.siteId}`}</Link>
              : null}
          </Fact>
          <Fact label={t('devices.sim.facts.envelope')}>
            {line.planEnvelopeMb !== null ? formatData(line.planEnvelopeMb) : null}
          </Fact>
          <Fact label={t('devices.sim.facts.alert')}>
            {t('devices.sim.alertRule', { pct: line.thresholdPercent, mb: formatData(line.thresholdMb) })}
          </Fact>
          <Fact label={t('devices.sim.facts.auto')}>
            {line.autoRechargeEnabled ? t('devices.sim.autoOn') : t('devices.sim.autoOff')}
            {line.rechargePlanMb !== null && <span className="text-text-muted"> · {formatData(line.rechargePlanMb)}</span>}
          </Fact>
          <Fact label={t('devices.sim.facts.lastSeen')}><When iso={line.lastSeenAt} /></Fact>
        </dl>

        {/* ── This month / last month, as the partner declares it ──────────── */}
        <div className="border-t border-border p-4">
          <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-text-muted">
            {t('mobile.partner.sections.consumption')}
          </h3>
          <div className="grid grid-cols-2 gap-2 lg:grid-cols-4">
            <Tile label={t('devices.sim.nationalThisMonth')} mb={p?.consumption.nationalMb ?? null} />
            <Tile label={t('devices.sim.nationalLastMonth')} mb={p?.consumption.nationalPrevMonthMb ?? null} />
            <Tile label={t('devices.sim.roamingThisMonth')} mb={p?.consumption.roamingMb ?? null} />
            <Tile label={t('devices.sim.roamingLastMonth')} mb={p?.consumption.roamingPrevMonthMb ?? null} />
          </div>
          <p className="mt-2 flex items-start gap-1.5 text-[11px] text-text-muted">
            <Info size={12} className="mt-0.5 shrink-0" />
            {t('mobile.partner.consumptionHint')}
          </p>
        </div>

        {/* ── Each zone against its own envelope ──────────────────────────── */}
        <div className="border-t border-border">
          <h3 className="px-4 pt-3 text-[11px] font-semibold uppercase tracking-wider text-text-muted">
            {t('mobile.detail.zones')}
          </h3>
          {line.zones.length === 0 ? (
            <EmptyState message={t('mobile.detail.noZones')} />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="border-b border-border text-left text-xs text-text-muted">
                  <tr>
                    <th className={TH}>{t('mobile.lines.zone')}</th>
                    <th className={TH}>{t('devices.sim.usage')}</th>
                    <th className={cn(TH, 'text-right')}>{t('mobile.lines.remaining')}</th>
                    <th className={TH}>{t('mobile.detail.lowSince')}</th>
                    <th className={TH}>{t('mobile.detail.observedAt')}</th>
                    <th className="px-4 py-2" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {line.zones.map((z) => (
                    <tr key={z.zone}>
                      <td className={cn(TD, 'text-text-primary')}>
                        {z.zone}
                        {z.zone === decidingZone && line.zones.length > 1 && (
                          <span className="ml-1.5 text-[11px] text-text-muted">{t('devices.sim.decidingZone')}</span>
                        )}
                      </td>
                      <td className={TD}>
                        <ZoneUsageLine
                          usage={usageByZone.get(z.zone) ?? null}
                          thresholdPercent={line.thresholdPercent}
                          thresholdMb={line.thresholdMb}
                        />
                      </td>
                      <td className={cn(TD, 'text-right')}><DataAmount mb={z.restMb} /></td>
                      <td className={cn(TD, 'text-xs')}><When iso={z.lowSince} /></td>
                      <td className={cn(TD, 'text-xs')}><When iso={z.observedAt} /></td>
                      <td className={cn(TD, 'text-right')}>
                        {canManage && (
                          <Button variant="ghost" size="sm" onClick={() => void propose(z.zone)}>
                            <Wallet size={13} className="mr-1" />
                            {t('mobile.detail.propose')}
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className="border-t border-border px-4 py-2 text-[11px] text-text-muted">
            {t('mobile.detail.thresholdApplied', { value: formatData(line.thresholdMb) })}
          </p>
        </div>
      </section>

      {/* ── Every partner field; PUK1/PUK2/RADIUS/RIO behind the audited reveal ── */}
      <SimPartnerFactsPanel line={line} />

      {/* ── Top-ups: the open proposals first, decided on the Recharges page ── */}
      <Panel
        title={t('mobile.detail.rechargeHistory')}
        action={open.length > 0 ? (
          <Link to="/mobile/recharges" className="inline-flex items-center gap-1 text-xs text-accent hover:underline">
            {t('devices.sim.decide', { count: open.length })}
            <ArrowRight size={12} />
          </Link>
        ) : undefined}
      >
        {recharges === null ? (
          <p className="px-4 py-3 text-sm text-text-muted">{rechargesFailed ? t('devices.page.unreadable') : '…'}</p>
        ) : recharges.length === 0 ? (
          <EmptyState message={t('mobile.detail.noRecharges')} />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-border text-left text-xs text-text-muted">
                <tr>
                  <th className={TH}>{t('mobile.recharges.proposed')}</th>
                  <th className={TH}>{t('mobile.lines.zone')}</th>
                  <th className={cn(TH, 'text-right')}>{t('mobile.recharges.atProposal')}</th>
                  <th className={cn(TH, 'text-right')}>{t('mobile.recharges.volume')}</th>
                  <th className={TH}>{t('mobile.recharges.status')}</th>
                  <th className={TH}>{t('mobile.recharges.decidedBy')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {[...open, ...recharges.filter((r) => !open.includes(r))].map((r) => (
                  <tr key={r.id}>
                    <td className={cn(TD, 'text-xs')}><When iso={r.proposedAt} /></td>
                    <td className={cn(TD, 'text-text-secondary')}>{r.zone}</td>
                    <td className={cn(TD, 'text-right')}><DataAmount mb={r.restMbAtProposal} /></td>
                    <td className={cn(TD, 'text-right')}><DataAmount mb={r.planMb} /></td>
                    <td className={TD}><RechargeStatusBadge status={r.status} /></td>
                    <td className={cn(TD, 'text-xs text-text-secondary')}>
                      {r.decidedByName ?? <span className="text-text-muted">—</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {/* ── What the partner says was bought (its own purchase history) ───── */}
      <Panel title={t('mobile.detail.partnerHistory')}>
        {partnerHistory === null ? (
          <p className="px-4 py-3 text-sm text-text-muted">…</p>
        ) : partnerHistory.length === 0 ? (
          <EmptyState message={t('mobile.detail.noPartnerHistory')} />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-border text-left text-xs text-text-muted">
                <tr>
                  <th className={TH}>{t('mobile.detail.partnerDate')}</th>
                  <th className={cn(TH, 'text-right')}>{t('mobile.detail.partnerVolume')}</th>
                  <th className={TH}>{t('mobile.detail.partnerZone')}</th>
                  <th className={TH}>{t('mobile.detail.partnerProduct')}</th>
                  <th className={TH}>{t('mobile.detail.partnerStatus')}</th>
                  <th className={TH}>{t('mobile.detail.partnerLink')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {partnerHistory.map((ph) => (
                  <tr key={ph.id}>
                    <td className={cn(TD, 'text-xs')}>
                      {ph.requestedAt ? <When iso={ph.requestedAt} /> : <span className="text-text-muted">{ph.period ?? '—'}</span>}
                    </td>
                    <td className={cn(TD, 'text-right')}><DataAmount mb={ph.volumeMb} /></td>
                    <td className={cn(TD, 'text-text-secondary')}>{ph.zoneCode ?? '—'}</td>
                    <td className={cn(TD, 'text-text-secondary')}>{ph.productCode ?? '—'}</td>
                    <td className={TD}><PartnerOutcomeBadge outcome={ph.outcome} raw={ph.partnerStatus} /></td>
                    <td className={cn(TD, 'text-xs text-text-secondary')}>
                      {ph.rechargeId !== null
                        ? t('mobile.detail.partnerLinked', { id: ph.rechargeId })
                        : ph.outcome === 'ok' ? t('mobile.detail.partnerUnlinked') : '—'}
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

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        {/* ── The partner's volume catalogue: a live read, buys nothing ─────── */}
        <Panel title={t('mobile.detail.offers')}>
          {offers === null ? (
            <div className="px-4 py-3">
              <Button variant="secondary" size="sm" onClick={() => void loadOffers()} disabled={offersLoading}>
                <RefreshCw size={14} className={cn('mr-1.5', offersLoading && 'animate-spin')} />
                {t('mobile.detail.offersLoad')}
              </Button>
            </div>
          ) : offers.zones.length === 0 ? (
            <EmptyState message={t('mobile.detail.offersNone')} />
          ) : (
            <div className="divide-y divide-border">
              {offers.zones.map((z) => (
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
                          title={o.code}
                          className="inline-flex items-center rounded-full border border-border px-2.5 py-0.5 text-xs text-text-primary"
                        >
                          {o.label ?? (o.volumeMb !== null ? formatData(o.volumeMb) : o.code)}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
          <p className="flex items-start gap-2 border-t border-border px-4 py-2 text-[11px] text-text-muted">
            <Info size={12} className="mt-0.5 shrink-0" />
            {t('mobile.detail.offersHint')}
          </p>
        </Panel>

        {/* ── Consumption history: on request, it can be long ─────────────── */}
        <Panel title={t('mobile.detail.history')}>
          {history === null ? (
            <div className="px-4 py-3">
              <Button variant="secondary" size="sm" onClick={() => void loadHistory()} disabled={historyLoading}>
                <RefreshCw size={14} className={cn('mr-1.5', historyLoading && 'animate-spin')} />
                {t('devices.sim.showHistory')}
              </Button>
            </div>
          ) : history.length === 0 ? (
            <EmptyState message={t('mobile.detail.noHistory')} />
          ) : (
            <div className="max-h-80 overflow-y-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-0 border-b border-border bg-bg-secondary text-left text-xs text-text-muted">
                  <tr>
                    <th className={TH}>{t('mobile.detail.observedAt')}</th>
                    <th className={TH}>{t('mobile.lines.zone')}</th>
                    <th className={cn(TH, 'text-right')}>{t('mobile.detail.used')}</th>
                    <th className={cn(TH, 'text-right')}>{t('mobile.lines.remaining')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {history.map((h, i) => (
                    <tr key={`${h.observedAt}-${h.zone}-${i}`}>
                      <td className="px-4 py-1.5 text-xs"><When iso={h.observedAt} /></td>
                      <td className="px-4 py-1.5 text-text-secondary">{h.zone}</td>
                      <td className="px-4 py-1.5 text-right"><DataAmount mb={h.usedMb} /></td>
                      <td className="px-4 py-1.5 text-right"><DataAmount mb={h.restMb} /></td>
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

      {canManage && (
        <p className="text-xs text-text-muted">
          {t('devices.sim.editOnLine')}{' '}
          <Link to={`/mobile/lines/${line.id}`} className="text-accent hover:underline">{line.msisdn}</Link>
        </p>
      )}
    </div>
  );
}
