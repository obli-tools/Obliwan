import { Fragment, useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import {
  AlertTriangle, CheckCircle2, ClipboardCopy, FileCode2, Play, RotateCcw, ShieldCheck, Sparkles, X, XCircle,
} from 'lucide-react';
import type {
  ExtrapolatedSiteResult,
  ExtrapolatedVariable,
  ExtrapolationForcedRule,
  ExtrapolationOverride,
  ExtrapolationProposal,
  ExtrapolationProposalSummary,
  ExtrapolationReadiness,
  ExtrapolationRun,
} from '@obliwan/shared';
import { EXTRAPOLATION_FORCED_RULES } from '@obliwan/shared';
import { extrapolatorApi } from '@/api/extrapolator.api';
import { errorMessageOf } from '@/api/change.api';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { ReadinessCard } from './ReadinessCard';
import { anonHostname } from '@/utils/anonymize';
import { cn } from '@/utils/cn';

/**
 * `ExtrapolatorPanel` — brick 10, the template extrapolator.
 *
 * "Tu sais tout le travail qu'on fait toi et moi : il pourrait pas le proposer
 * puis je valide ou non ?" — this is the "proposer" and the "valider".
 *
 * ── WHAT THE SCREEN REFUSES TO HIDE ─────────────────────────────────────────
 * 1. The proof is per router and per line. The score is shown as "41/43
 *    lines", and a click shows the exact lines the template does not
 *    reproduce. A cluster below the threshold says so in red; it can still be
 *    approved, because a 90 % template plus a list of ten hand edits is still
 *    the most useful thing anybody has about that fleet — but nobody can
 *    approve it without having seen that.
 * 2. Every variable shows its rule, its confidence and its evidence. A rule
 *    the operator disagrees with is corrected here (rename, force "per site",
 *    "common value + exceptions", "literal") and the run is re-played with the
 *    corrections — the proposal is never edited by hand in place.
 * 3. Secrets are names, never values. Computed values belong to the
 *    allocation policy: the fragment to report there is shown, never written.
 *
 * ── Change queue ──────────────────────────────────────────────────────────────────────
 * Approving writes a template, a DRAFT revision and non-secret variable values.
 * Nothing here publishes, assigns or reaches a router.
 */

type SubTab = 'body' | 'variables' | 'sites' | 'deviations' | 'policy';

const KIND_STYLES: Record<string, string> = {
  formula: 'border-accent/50 bg-accent/10 text-accent',
  lan: 'border-accent/50 bg-accent/10 text-accent',
  site_code: 'border-accent/50 bg-accent/10 text-accent',
  default_exceptions: 'border-status-up/50 bg-status-up/10 text-status-up',
  presence: 'border-status-up/50 bg-status-up/10 text-status-up',
  site: 'border-border bg-bg-tertiary text-text-secondary',
  secret: 'border-status-ssl-warning/50 bg-status-ssl-warning/10 text-status-ssl-warning',
  existing: 'border-border bg-bg-tertiary text-text-muted',
};

function pct(x: number): string {
  return `${(x * 100).toFixed(x >= 0.9995 ? 0 : 1)} %`;
}

function scoreClass(x: number): string {
  return x >= 0.99 ? 'text-status-up' : x >= 0.9 ? 'text-status-ssl-warning' : 'text-status-ssl-expired';
}

export function ExtrapolatorPanel({
  baselineRunId,
  canApprove,
  dateFmt,
}: {
  baselineRunId: number | null;
  canApprove: boolean;
  dateFmt: Intl.DateTimeFormat;
}) {
  const { t } = useTranslation();
  const [runs, setRuns] = useState<ExtrapolationRun[] | null>(null);
  const [runId, setRunId] = useState<number | null>(null);
  const [detail, setDetail] = useState<{ run: ExtrapolationRun; proposals: ExtrapolationProposalSummary[] } | null>(null);
  const [proposalId, setProposalId] = useState<number | null>(null);
  const [proposal, setProposal] = useState<ExtrapolationProposal | null>(null);
  const [sub, setSub] = useState<SubTab>('body');
  const [minReproduction, setMinReproduction] = useState(0.95);
  const [deviationMaxSites, setDeviationMaxSites] = useState(1);
  const [overrides, setOverrides] = useState<Record<string, ExtrapolationOverride>>({});
  const [starting, setStarting] = useState(false);
  const [loading, setLoading] = useState(false);
  const [siteDetail, setSiteDetail] = useState<ExtrapolatedSiteResult | null>(null);
  const [approveOpen, setApproveOpen] = useState(false);
  const [rejectOpen, setRejectOpen] = useState(false);
  // One proposal per router MODEL by default; the historical structural
  // profiles stay one toggle away.
  const [groupByProfile, setGroupByProfile] = useState(false);
  const [maxProfilesPerModel, setMaxProfilesPerModel] = useState(1);
  const [readiness, setReadiness] = useState<ExtrapolationReadiness | null>(null);
  const [readinessLoading, setReadinessLoading] = useState(false);
  // A collection of the client's configurations in progress holds the start:
  // mining a fleet half re-read would mix old and new (the server says 409).
  const [collectRunning, setCollectRunning] = useState(false);

  const loadReadiness = useCallback(async () => {
    setReadinessLoading(true);
    try {
      setReadiness(await extrapolatorApi.readiness());
    } catch (err) {
      toast.error(errorMessageOf(err) ?? t('baseline.extrapolator.loadFailed'));
    } finally {
      setReadinessLoading(false);
    }
  }, [t]);

  useEffect(() => { void loadReadiness(); }, [loadReadiness]);
  const reloadReadiness = useCallback(() => { void loadReadiness(); }, [loadReadiness]);

  const loadRuns = useCallback(async () => {
    try {
      const rows = await extrapolatorApi.listRuns();
      setRuns(rows);
      setRunId((prev) => (prev !== null && rows.some((r) => r.id === prev) ? prev : rows[0]?.id ?? null));
    } catch (err) {
      toast.error(errorMessageOf(err) ?? t('baseline.extrapolator.loadFailed'));
      setRuns([]);
    }
  }, [t]);

  useEffect(() => { void loadRuns(); }, [loadRuns]);

  const loadDetail = useCallback(async (id: number) => {
    try {
      const d = await extrapolatorApi.getRun(id);
      setDetail(d);
      setProposalId((prev) => (prev !== null && d.proposals.some((p) => p.id === prev) ? prev : d.proposals[0]?.id ?? null));
    } catch (err) {
      toast.error(errorMessageOf(err) ?? t('baseline.extrapolator.loadFailed'));
    }
  }, [t]);

  useEffect(() => {
    if (runId === null) { setDetail(null); setProposalId(null); return; }
    void loadDetail(runId);
  }, [runId, loadDetail]);

  // A running run is polled: the work happens in the background on the server.
  const running = detail?.run.status === 'running' || (runs ?? []).some((r) => r.status === 'running');
  useEffect(() => {
    if (!running) return;
    const timer = window.setInterval(() => {
      void loadRuns();
      if (runId !== null) void loadDetail(runId);
    }, 2500);
    return () => window.clearInterval(timer);
  }, [running, runId, loadRuns, loadDetail]);

  const loadProposal = useCallback(async (id: number) => {
    setLoading(true);
    try {
      setProposal(await extrapolatorApi.getProposal(id));
    } catch (err) {
      toast.error(errorMessageOf(err) ?? t('baseline.extrapolator.loadFailed'));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    if (proposalId === null) { setProposal(null); return; }
    void loadProposal(proposalId);
  }, [proposalId, loadProposal]);

  const start = useCallback(async (fromRun: number | null, withOverrides: boolean) => {
    setStarting(true);
    try {
      const created = await extrapolatorApi.start({
        baselineRunId: fromRun,
        minReproduction,
        deviationMaxSites,
        overrides: withOverrides ? Object.values(overrides) : [],
        groupBy: groupByProfile ? 'profile' : 'model',
        maxProfilesPerModel,
      });
      toast.success(t('baseline.extrapolator.started'));
      if (withOverrides) setOverrides({});
      await loadRuns();
      setRunId(created.id);
    } catch (err) {
      toast.error(errorMessageOf(err) ?? t('baseline.extrapolator.startFailed'));
    } finally {
      setStarting(false);
    }
  }, [minReproduction, deviationMaxSites, overrides, groupByProfile, maxProfilesPerModel, loadRuns, t]);

  const setOverride = useCallback((slot: string, patch: Partial<ExtrapolationOverride>) => {
    setOverrides((prev) => {
      const current: ExtrapolationOverride = prev[slot] ?? { slot, rule: 'auto', name: null, secretLevel: null, keepLine: false };
      const next = { ...current, ...patch };
      const copy = { ...prev };
      if (next.rule === 'auto' && next.name === null && next.secretLevel === null && !next.keepLine) delete copy[slot];
      else copy[slot] = next;
      return copy;
    });
  }, []);

  const pendingCount = Object.keys(overrides).length;

  return (
    <div className="space-y-3">
      <ReadinessCard
        readiness={readiness}
        loading={readinessLoading}
        onReload={reloadReadiness}
        onCollectRunning={setCollectRunning}
        dateFmt={dateFmt}
      />

      <section className="rounded-lg border border-border bg-bg-secondary p-3">
        <div className="flex flex-wrap items-start gap-3">
          <div className="min-w-0 flex-1">
            <h2 className="flex items-center gap-1.5 text-sm font-semibold text-text-primary">
              <Sparkles size={14} className="text-accent" />
              {t('baseline.extrapolator.title')}
            </h2>
            <p className="mt-1 max-w-3xl text-[12px] text-text-muted">{t('baseline.extrapolator.intro')}</p>
          </div>
          <div className="flex flex-wrap items-end gap-3">
            <label className="text-[11px] text-text-secondary">
              {t('baseline.extrapolator.minReproduction')}
              <input
                type="range" min={0.8} max={1} step={0.01} value={minReproduction}
                onChange={(e) => setMinReproduction(Number(e.target.value))}
                className="mt-1 block w-32 accent-accent"
              />
              <span className="font-mono text-[10px] text-text-muted">{pct(minReproduction)}</span>
            </label>
            <label className="text-[11px] text-text-secondary" title={t('baseline.extrapolator.deviationMaxHint')}>
              {t('baseline.extrapolator.deviationMax')}
              <input
                type="number" min={0} max={20} value={deviationMaxSites}
                onChange={(e) => setDeviationMaxSites(Math.max(0, Math.min(20, Number(e.target.value) || 0)))}
                className="mt-1 block w-20 rounded-md border border-border bg-bg-tertiary px-2 py-1 text-[12px] text-text-primary"
              />
            </label>
            <label className="text-[11px] text-text-secondary" title={t('baseline.extrapolator.groupByModel')}>
              {t('baseline.extrapolator.maxProfilesPerModel')}
              <input
                type="number" min={1} max={4} value={maxProfilesPerModel} disabled={groupByProfile}
                onChange={(e) => setMaxProfilesPerModel(Math.max(1, Math.min(4, Number(e.target.value) || 1)))}
                className="mt-1 block w-20 rounded-md border border-border bg-bg-tertiary px-2 py-1 text-[12px] text-text-primary disabled:opacity-50"
              />
            </label>
            <label className="flex items-center gap-1.5 self-center text-[11px] text-text-secondary">
              <input
                type="checkbox" checked={groupByProfile} onChange={(e) => setGroupByProfile(e.target.checked)}
                className="accent-accent"
              />
              {t('baseline.extrapolator.groupByProfile')}
            </label>
            {baselineRunId !== null && (
              <Button
                variant="secondary" size="sm" loading={starting} disabled={collectRunning}
                onClick={() => void start(baselineRunId, false)}
                title={t('baseline.extrapolator.fromRunIgnoresGrouping')}
              >
                <Play size={14} className="mr-1.5" />
                {t('baseline.extrapolator.startFromRun', { id: baselineRunId })}
              </Button>
            )}
            <Button
              variant="primary" size="sm" loading={starting} disabled={collectRunning}
              onClick={() => void start(null, false)}
              title={collectRunning ? t('baseline.extrapolator.collectRunning') : undefined}
            >
              <Play size={14} className="mr-1.5" />
              {t('baseline.extrapolator.startFresh')}
            </Button>
          </div>
        </div>
        <p className="mt-2 text-[11px] text-text-muted">
          {groupByProfile ? t('baseline.extrapolator.fromRunIgnoresGrouping') : t('baseline.extrapolator.groupByModel')}
        </p>
        {collectRunning && (
          <p className="mt-1 text-[11px] text-status-ssl-warning">{t('baseline.extrapolator.collectRunning')}</p>
        )}
        {pendingCount > 0 && detail && (
          <div className="mt-3 flex flex-wrap items-center gap-2 rounded-md border border-accent/40 bg-accent/5 px-3 py-2 text-[12px] text-text-secondary">
            {t('baseline.extrapolator.pendingOverrides', { count: pendingCount })}
            <Button
              variant="primary" size="sm" className="ml-auto" loading={starting}
              onClick={() => void start(detail.run.baselineRunId, true)}
            >
              <RotateCcw size={13} className="mr-1.5" />
              {t('baseline.extrapolator.rerun')}
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setOverrides({})}>{t('common.cancel')}</Button>
          </div>
        )}
      </section>

      {runs === null ? (
        <div className="flex justify-center py-8"><LoadingSpinner /></div>
      ) : runs.length === 0 ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-10 text-center text-sm text-text-muted">
          {t('baseline.extrapolator.noRun')}
        </div>
      ) : (
        <div className="flex flex-wrap gap-2">
          {runs.slice(0, 12).map((r) => (
            <button
              key={r.id}
              onClick={() => setRunId(r.id)}
              className={cn(
                'rounded-md border px-2.5 py-1.5 text-left text-[12px] transition-colors',
                r.id === runId ? 'border-accent/50 bg-accent/10 text-accent' : 'border-border bg-bg-tertiary text-text-secondary hover:text-text-primary',
              )}
            >
              <span className="block font-medium">
                {t('baseline.extrapolator.runLabel', { id: r.id })}
                <span className="ml-2 font-mono text-[10px] uppercase tracking-wider text-text-muted">
                  {t(`baseline.extrapolator.status.${r.status}`)}
                </span>
              </span>
              <span className="block text-[10px] text-text-muted">
                {t('baseline.extrapolator.runSummary', { proposals: r.proposalCount, devices: r.deviceCount })}
                {r.startedAt ? ` · ${dateFmt.format(new Date(r.startedAt))}` : ''}
              </span>
            </button>
          ))}
        </div>
      )}

      {detail && (
        <section className="space-y-2">
          {detail.run.status === 'running' && (
            <div className="flex items-center gap-2 rounded-md border border-border bg-bg-secondary px-3 py-2 text-[12px] text-text-muted">
              <LoadingSpinner /> {t('baseline.extrapolator.running')}
            </div>
          )}
          {detail.run.status === 'failed' && (
            <div className="rounded-md border border-status-ssl-expired/40 bg-status-ssl-expired/5 px-3 py-2 text-[12px] text-status-ssl-expired">
              {t('baseline.extrapolator.failed')} {detail.run.error}
            </div>
          )}
          {detail.run.warnings.map((w, i) => (
            <div key={i} className="flex items-start gap-2 rounded-md border border-status-ssl-warning/40 bg-status-ssl-warning/5 px-3 py-1.5 text-[12px] text-text-secondary">
              <AlertTriangle size={13} className="mt-0.5 shrink-0 text-status-ssl-warning" /> {w}
            </div>
          ))}
          {detail.proposals.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {detail.proposals.map((p) => (
                <button
                  key={p.id}
                  onClick={() => setProposalId(p.id)}
                  className={cn(
                    'rounded-md border px-2.5 py-1.5 text-left text-[12px] transition-colors',
                    p.id === proposalId ? 'border-accent/50 bg-accent/10 text-accent' : 'border-border bg-bg-tertiary text-text-secondary hover:text-text-primary',
                  )}
                >
                  <span className="flex items-center gap-1.5 font-medium">
                    {p.gateMet ? <CheckCircle2 size={12} className="text-status-up" /> : <AlertTriangle size={12} className="text-status-ssl-warning" />}
                    {p.label}
                    <span className="font-mono text-[10px] uppercase text-text-muted">{t(`baseline.extrapolator.proposalStatus.${p.status}`)}</span>
                  </span>
                  <span className="block text-[10px] text-text-muted">
                    {t('baseline.extrapolator.proposalChip', {
                      members: p.memberCount, min: pct(p.reproductionMin), deviations: p.deviationCount,
                    })}
                  </span>
                </button>
              ))}
            </div>
          )}
        </section>
      )}

      {loading && <div className="flex justify-center py-8"><LoadingSpinner /></div>}

      {proposal && !loading && (
        <ProposalView
          proposal={proposal}
          sub={sub}
          onSub={setSub}
          canApprove={canApprove}
          overrides={overrides}
          onOverride={setOverride}
          onSite={async (deviceId) => {
            try { setSiteDetail(await extrapolatorApi.getSite(proposal.id, deviceId)); }
            catch (err) { toast.error(errorMessageOf(err) ?? t('baseline.extrapolator.loadFailed')); }
          }}
          onApprove={() => setApproveOpen(true)}
          onReject={() => setRejectOpen(true)}
        />
      )}

      {siteDetail && <SiteDialog site={siteDetail} onClose={() => setSiteDetail(null)} />}
      {approveOpen && proposal && (
        <ApproveDialog
          proposal={proposal}
          onClose={() => setApproveOpen(false)}
          onDone={async () => {
            setApproveOpen(false);
            await loadProposal(proposal.id);
            if (runId !== null) await loadDetail(runId);
          }}
        />
      )}
      {rejectOpen && proposal && (
        <RejectDialog
          proposalId={proposal.id}
          onClose={() => setRejectOpen(false)}
          onDone={async () => {
            setRejectOpen(false);
            await loadProposal(proposal.id);
            if (runId !== null) await loadDetail(runId);
          }}
        />
      )}
    </div>
  );
}

// ── One proposal ────────────────────────────────────────────────────────────

function ProposalView({
  proposal, sub, onSub, canApprove, overrides, onOverride, onSite, onApprove, onReject,
}: {
  proposal: ExtrapolationProposal;
  sub: SubTab;
  onSub: (s: SubTab) => void;
  canApprove: boolean;
  overrides: Record<string, ExtrapolationOverride>;
  onOverride: (slot: string, patch: Partial<ExtrapolationOverride>) => void;
  onSite: (deviceId: number) => void;
  onApprove: () => void;
  onReject: () => void;
}) {
  const { t } = useTranslation();
  const tabs: Array<{ id: SubTab; label: string }> = [
    { id: 'body', label: t('baseline.extrapolator.tabs.body') },
    { id: 'variables', label: t('baseline.extrapolator.tabs.variables', { count: proposal.variables.length }) },
    { id: 'sites', label: t('baseline.extrapolator.tabs.sites', { count: proposal.sites.length }) },
    { id: 'deviations', label: t('baseline.extrapolator.tabs.deviations', { count: proposal.deviations.length }) },
    { id: 'policy', label: t('baseline.extrapolator.tabs.policy') },
  ];
  const reproduced = proposal.sites.reduce((a, s) => a + s.linesReproduced, 0);
  const actual = proposal.sites.reduce((a, s) => a + s.linesActual, 0);

  return (
    <section className="rounded-lg border border-border bg-bg-secondary">
      <div className="flex flex-wrap items-center gap-3 border-b border-border px-3 py-2">
        <h3 className="flex items-center gap-1.5 text-sm font-semibold text-text-primary">
          <FileCode2 size={14} className="text-text-muted" />
          {proposal.label}
        </h3>
        <span className="text-[11px] text-text-muted">
          {t('baseline.extrapolator.summary', {
            members: proposal.memberCount, lines: proposal.lineCount, variables: proposal.variableCount,
          })}
        </span>
        <span className={cn('font-mono text-[11px]', scoreClass(proposal.reproductionMin))}>
          {t('baseline.extrapolator.reproduction', {
            min: pct(proposal.reproductionMin), mean: pct(proposal.reproductionMean), reproduced, actual,
          })}
        </span>
        <span className="ml-auto flex gap-2">
          {proposal.status === 'proposed' && canApprove && (
            <>
              <Button variant="secondary" size="sm" onClick={onReject}>
                <XCircle size={13} className="mr-1.5" />{t('baseline.extrapolator.reject')}
              </Button>
              <Button variant="primary" size="sm" onClick={onApprove}>
                <ShieldCheck size={13} className="mr-1.5" />{t('baseline.extrapolator.approve')}
              </Button>
            </>
          )}
          {proposal.status === 'approved' && proposal.templateId !== null && (
            <Link to="/templates" className="text-[12px] text-accent hover:underline">
              {t('baseline.extrapolator.approvedLink', { id: proposal.templateId })}
            </Link>
          )}
          {proposal.status === 'rejected' && (
            <span className="text-[12px] text-text-muted">{t('baseline.extrapolator.rejectedNote', { note: proposal.decisionNote ?? '' })}</span>
          )}
        </span>
      </div>
      <div className={cn(
        'border-b border-border px-3 py-2 text-[12px]',
        proposal.gateMet ? 'text-status-up' : 'text-status-ssl-warning',
      )}>
        {proposal.gateMet
          ? t('baseline.extrapolator.gateMet')
          : t('baseline.extrapolator.gateNotMet', { min: pct(proposal.reproductionMin) })}
        {proposal.warnings.map((w, i) => <span key={i} className="block text-text-muted">{w}</span>)}
      </div>

      <div className="flex flex-wrap gap-1 border-b border-border px-2">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => onSub(tab.id)}
            className={cn(
              'border-b-2 px-3 py-2 text-[12px] transition-colors',
              sub === tab.id ? 'border-accent text-text-primary' : 'border-transparent text-text-secondary hover:text-text-primary',
            )}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div className="p-3">
        {sub === 'body' && <BodyView body={proposal.body} />}
        {sub === 'variables' && (
          <VariablesView variables={proposal.variables} overrides={overrides} onOverride={onOverride} editable={proposal.status === 'proposed'} />
        )}
        {sub === 'sites' && <SitesView sites={proposal.sites} onSite={onSite} />}
        {sub === 'deviations' && <DeviationsView proposal={proposal} onOverride={onOverride} overrides={overrides} />}
        {sub === 'policy' && <PolicyView proposal={proposal} />}
      </div>
    </section>
  );
}

/** The body, with every template construct highlighted. */
function BodyView({ body }: { body: string }) {
  const parts = useMemo(() => body.split(/(\{\{[\s\S]*?\}\}|\{%[\s\S]*?%\}|\{#[\s\S]*?#\})/g), [body]);
  return (
    <pre className="max-h-[32rem] overflow-auto whitespace-pre-wrap break-words rounded-md border border-border bg-bg-primary/40 p-2 font-mono text-[11px] text-text-secondary">
      {parts.map((p, i) => {
        if (p.startsWith('{{')) return <span key={i} className="rounded bg-accent/15 text-accent">{p}</span>;
        if (p.startsWith('{%')) return <span key={i} className="text-status-up">{p}</span>;
        if (p.startsWith('{#')) return <span key={i} className="italic text-text-muted">{p}</span>;
        return <Fragment key={i}>{p}</Fragment>;
      })}
    </pre>
  );
}

function VariablesView({
  variables, overrides, onOverride, editable,
}: {
  variables: ExtrapolatedVariable[];
  overrides: Record<string, ExtrapolationOverride>;
  onOverride: (slot: string, patch: Partial<ExtrapolationOverride>) => void;
  editable: boolean;
}) {
  const { t } = useTranslation();
  const [open, setOpen] = useState<string | null>(null);
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[56rem] text-left text-[12px]">
        <thead className="border-b border-border text-[10px] uppercase tracking-wider text-text-muted">
          <tr>
            <th className="px-2 py-1.5 font-medium">{t('baseline.extrapolator.col.name')}</th>
            <th className="px-2 py-1.5 font-medium">{t('baseline.extrapolator.col.rule')}</th>
            <th className="px-2 py-1.5 font-medium">{t('baseline.extrapolator.col.level')}</th>
            <th className="px-2 py-1.5 font-medium">{t('baseline.extrapolator.col.value')}</th>
            <th className="px-2 py-1.5 font-medium">{t('baseline.extrapolator.col.confidence')}</th>
            <th className="px-2 py-1.5 font-medium">{t('baseline.extrapolator.col.sites')}</th>
            {editable && <th className="px-2 py-1.5 font-medium">{t('baseline.extrapolator.col.correct')}</th>}
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {variables.map((v) => {
            const ov = overrides[v.slot];
            // The standard WAN1 block's variables (slot `wan1#…`) keep the
            // block's names, rules and levels: no override applies to them.
            const standardWan1 = v.slot.startsWith('wan1#');
            const editableRule = !v.secret && v.level !== 'computed' && v.kind !== 'existing';
            return (
              <Fragment key={v.name}>
                <tr className="align-top hover:bg-bg-hover">
                  <td className="px-2 py-1.5">
                    <button onClick={() => setOpen(open === v.name ? null : v.name)} className="text-left">
                      <span className="font-mono text-accent">{v.name}</span>
                      <span className="block text-[10px] text-text-muted">{v.label}</span>
                    </button>
                  </td>
                  <td className="px-2 py-1.5">
                    <span className={cn('rounded border px-1.5 py-0.5 text-[10px]', KIND_STYLES[v.kind] ?? KIND_STYLES.site)}>
                      {t(`baseline.extrapolator.kind.${v.kind}`)}
                    </span>
                  </td>
                  <td className="px-2 py-1.5 text-text-secondary">{t(`baseline.extrapolator.level.${v.level}`)}</td>
                  <td className="max-w-[18rem] break-words px-2 py-1.5 font-mono text-[11px] text-text-secondary">
                    {v.secret ? t('baseline.extrapolator.secretValue')
                      : v.expression ?? (v.defaultValue === null ? '—' : v.defaultValue === '' ? t('baseline.extrapolator.absent') : String(v.defaultValue))}
                  </td>
                  <td className={cn('px-2 py-1.5 font-mono', scoreClass(v.confidence))}>{pct(v.confidence)}</td>
                  <td className="px-2 py-1.5 font-mono text-text-muted">
                    {v.fit ? `${v.fit.matched}/${v.fit.total}` : v.siteValues.length > 0 ? String(v.siteValues.length) : '—'}
                  </td>
                  {editable && standardWan1 && <td className="px-2 py-1.5" />}
                  {editable && !standardWan1 && (
                    <td className="px-2 py-1.5">
                      <div className="flex flex-wrap gap-1">
                        <input
                          defaultValue={ov?.name ?? ''}
                          placeholder={t('baseline.extrapolator.rename')}
                          onBlur={(e) => {
                            const name = e.target.value.trim();
                            onOverride(v.slot, { name: /^[a-z][a-z0-9_]{0,59}$/.test(name) ? name : null });
                          }}
                          className="w-28 rounded border border-border bg-bg-tertiary px-1.5 py-0.5 font-mono text-[11px] text-text-primary"
                        />
                        {editableRule && (
                          <select
                            value={ov?.rule ?? 'auto'}
                            onChange={(e) => onOverride(v.slot, { rule: e.target.value as ExtrapolationForcedRule })}
                            className="rounded border border-border bg-bg-tertiary px-1 py-0.5 text-[11px] text-text-primary"
                          >
                            {EXTRAPOLATION_FORCED_RULES.map((r) => (
                              <option key={r} value={r}>{t(`baseline.extrapolator.forced.${r}`)}</option>
                            ))}
                          </select>
                        )}
                        {v.secret && v.name !== 'ppp_password' && (
                          <select
                            value={ov?.secretLevel ?? ''}
                            onChange={(e) => onOverride(v.slot, { secretLevel: (e.target.value || null) as ExtrapolationOverride['secretLevel'] })}
                            className="rounded border border-border bg-bg-tertiary px-1 py-0.5 text-[11px] text-text-primary"
                          >
                            <option value="">{t('baseline.extrapolator.forced.auto')}</option>
                            <option value="tenant">{t('baseline.extrapolator.level.tenant')}</option>
                            <option value="site">{t('baseline.extrapolator.level.site')}</option>
                            <option value="instance">{t('baseline.extrapolator.level.instance')}</option>
                          </select>
                        )}
                      </div>
                    </td>
                  )}
                </tr>
                {open === v.name && (
                  <tr>
                    <td colSpan={editable ? 7 : 6} className="bg-bg-primary/30 px-3 py-2 text-[11px] text-text-secondary">
                      <ul className="list-disc space-y-0.5 pl-4">
                        {v.evidence.map((e, i) => <li key={i}>{e}</li>)}
                      </ul>
                      {v.uses.length > 0 && (
                        <p className="mt-1 font-mono text-[10px] text-text-muted">{v.uses.join(' · ')}</p>
                      )}
                      {v.reusedFrom && <p className="mt-1 text-text-muted">{t('baseline.extrapolator.reusedFrom', { from: v.reusedFrom })}</p>}
                      {v.probe && <p className="mt-1 text-text-muted">{t('baseline.extrapolator.probe')}</p>}
                      {v.siteValues.length > 0 && (
                        <div className="mt-1 max-h-40 overflow-auto font-mono text-[10px]">
                          {v.siteValues.slice(0, 200).map((sv) => (
                            <span key={sv.deviceId} className="mr-3 inline-block">
                              {sv.siteCode ?? `#${sv.deviceId}`} = {sv.value === '' ? t('baseline.extrapolator.absent') : sv.value}
                            </span>
                          ))}
                        </div>
                      )}
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function SitesView({ sites, onSite }: { sites: ExtrapolatedSiteResult[]; onSite: (deviceId: number) => void }) {
  const { t } = useTranslation();
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[40rem] text-left text-[12px]">
        <thead className="border-b border-border text-[10px] uppercase tracking-wider text-text-muted">
          <tr>
            <th className="px-2 py-1.5 font-medium">{t('baseline.extrapolator.col.site')}</th>
            <th className="px-2 py-1.5 font-medium">{t('baseline.extrapolator.col.device')}</th>
            <th className="px-2 py-1.5 font-medium">{t('baseline.extrapolator.col.score')}</th>
            <th className="px-2 py-1.5 font-medium">{t('baseline.extrapolator.col.lines')}</th>
            <th className="px-2 py-1.5 font-medium">{t('baseline.extrapolator.col.gaps')}</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {sites.map((s) => (
            <tr key={s.deviceId} className="cursor-pointer hover:bg-bg-hover" onClick={() => onSite(s.deviceId)}>
              <td className="px-2 py-1.5 font-mono text-text-primary">{s.siteCode ?? '—'}</td>
              <td className="px-2 py-1.5 text-text-secondary">{anonHostname(s.deviceName)}</td>
              <td className={cn('px-2 py-1.5 font-mono', scoreClass(s.score))}>{pct(s.score)}</td>
              <td className="px-2 py-1.5 font-mono text-text-muted">{s.linesReproduced}/{s.linesActual}</td>
              <td className="px-2 py-1.5 text-[11px] text-text-muted">
                {s.renderError
                  ? <span className="text-status-ssl-expired">{s.renderError.slice(0, 90)}</span>
                  : t('baseline.extrapolator.gaps', { missing: s.linesActual - s.linesReproduced, extra: s.linesRendered - s.linesReproduced })}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function DeviationsView({
  proposal, overrides, onOverride,
}: {
  proposal: ExtrapolationProposal;
  overrides: Record<string, ExtrapolationOverride>;
  onOverride: (slot: string, patch: Partial<ExtrapolationOverride>) => void;
}) {
  const { t } = useTranslation();
  if (proposal.deviations.length === 0) {
    return <p className="text-[12px] text-text-muted">{t('baseline.extrapolator.noDeviation')}</p>;
  }
  return (
    <div className="space-y-1.5">
      <p className="text-[11px] text-text-muted">{t('baseline.extrapolator.deviationsHint')}</p>
      {proposal.deviations.map((d, i) => {
        // A WAN1-block finding (wan1#exclu, wan1#preuve) names no line of the
        // template: keeping it as an option would change nothing.
        const keepable = d.kind === 'extra_line' && !d.slot.startsWith('wan1#') && proposal.status === 'proposed';
        const kept = overrides[d.slot]?.keepLine === true;
        return (
          <div key={i} className="rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[12px]">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-text-primary">{d.siteCode ?? `#${d.deviceId}`}</span>
              <span className="rounded border border-status-ssl-warning/40 px-1 text-[10px] text-status-ssl-warning">
                {t(`baseline.extrapolator.deviationKind.${d.kind}`)}
              </span>
              <span className="text-[11px] text-text-secondary">{d.detail}</span>
              {keepable && (
                <button
                  onClick={() => onOverride(d.slot, { keepLine: !kept })}
                  className={cn('ml-auto rounded border px-1.5 py-0.5 text-[10px]', kept ? 'border-accent text-accent' : 'border-border text-text-muted hover:text-text-primary')}
                >
                  {kept ? t('baseline.extrapolator.keptLine') : t('baseline.extrapolator.keepLine')}
                </button>
              )}
            </div>
            <code className="mt-1 block break-words font-mono text-[10px] text-text-muted">{d.line}</code>
          </div>
        );
      })}
    </div>
  );
}

function PolicyView({ proposal }: { proposal: ExtrapolationProposal }) {
  const { t } = useTranslation();
  const p = proposal.policy;
  const current = p.current;
  const row = (label: string, proposed: string | null, now: string | null | undefined) => (
    <tr key={label}>
      <td className="px-2 py-1 text-text-secondary">{label}</td>
      <td className="px-2 py-1 font-mono text-[11px] text-text-primary">{proposed ?? '—'}</td>
      <td className="px-2 py-1 font-mono text-[11px] text-text-muted">
        {!current?.present ? t('baseline.extrapolator.noPolicy')
          : now === proposed ? <span className="text-status-up">{t('baseline.extrapolator.same')}</span>
            : now ?? '—'}
      </td>
    </tr>
  );
  const csv = useMemo(() => ['site_code,lan', ...p.lanRecorded.map((r) => `${r.siteCode ?? ''},${r.lan}`)].join('\n'), [p.lanRecorded]);
  return (
    <div className="space-y-3 text-[12px]">
      <p className="text-text-muted">{t('baseline.extrapolator.policyHint')}</p>
      <table className="w-full text-left">
        <thead className="border-b border-border text-[10px] uppercase tracking-wider text-text-muted">
          <tr>
            <th className="px-2 py-1 font-medium">{t('baseline.extrapolator.col.setting')}</th>
            <th className="px-2 py-1 font-medium">{t('baseline.extrapolator.col.proposed')}</th>
            <th className="px-2 py-1 font-medium">{t('baseline.extrapolator.col.current')}</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {row(t('baseline.extrapolator.policy.login'), p.pppLoginTemplate, current?.pppLoginTemplate)}
          {row(t('baseline.extrapolator.policy.identity'), p.systemIdentityTemplate, current?.systemIdentityTemplate)}
          {row(t('baseline.extrapolator.policy.lan'), p.lanFormula, current?.lanFormula)}
          {Object.entries(p.derived).map(([k, v]) => row(`${t('baseline.extrapolator.policy.derived')} ${k}`, v, current?.derived[k]))}
        </tbody>
      </table>
      {p.lanRecorded.length > 0 && (
        <div>
          <div className="flex items-center gap-2">
            <h4 className="text-[11px] uppercase tracking-wider text-text-muted">
              {t('baseline.extrapolator.lanRecorded', { count: p.lanRecorded.length })}
            </h4>
            <button
              onClick={() => { void navigator.clipboard?.writeText(csv); toast.success(t('baseline.extrapolator.copied')); }}
              className="ml-auto flex items-center gap-1 text-[11px] text-accent hover:underline"
            >
              <ClipboardCopy size={12} />{t('baseline.extrapolator.copyCsv')}
            </button>
          </div>
          <p className="mt-1 max-h-32 overflow-auto font-mono text-[10px] text-text-secondary">
            {p.lanRecorded.map((r) => `${r.siteCode ?? '?'} → ${r.lan}`).join(' · ')}
          </p>
        </div>
      )}
      {p.adopted.length > 0 && (
        <div>
          <h4 className="text-[11px] uppercase tracking-wider text-text-muted">{t('baseline.extrapolator.adopted', { count: p.adopted.length })}</h4>
          <p className="mt-1 font-mono text-[10px] text-text-secondary">
            {p.adopted.map((a) => `${a.siteCode ?? '?'} ${a.key}=${a.value}`).join(' · ')}
          </p>
        </div>
      )}
    </div>
  );
}

// ── Dialogs ─────────────────────────────────────────────────────────────────

function DialogShell({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="max-h-[90vh] w-full max-w-3xl overflow-auto rounded-lg border border-border bg-bg-secondary p-4 shadow-xl">
        <div className="mb-3 flex items-start justify-between gap-2">
          <h2 className="text-sm font-semibold text-text-primary">{title}</h2>
          <button onClick={onClose} className="rounded p-1 text-text-muted hover:bg-bg-hover hover:text-text-primary"><X size={14} /></button>
        </div>
        {children}
      </div>
    </div>
  );
}

function SiteDialog({ site, onClose }: { site: ExtrapolatedSiteResult; onClose: () => void }) {
  const { t } = useTranslation();
  return (
    <DialogShell title={t('baseline.extrapolator.siteTitle', { site: site.siteCode ?? anonHostname(site.deviceName), score: pct(site.score) })} onClose={onClose}>
      <p className="mb-2 text-[12px] text-text-muted">
        {t('baseline.extrapolator.siteSummary', { reproduced: site.linesReproduced, actual: site.linesActual, rendered: site.linesRendered })}
      </p>
      {site.renderError && <p className="mb-2 text-[12px] text-status-ssl-expired">{site.renderError}</p>}
      <h3 className="text-[11px] uppercase tracking-wider text-text-muted">{t('baseline.extrapolator.notReproduced', { count: site.notReproduced.length })}</h3>
      <pre className="mb-3 max-h-56 overflow-auto whitespace-pre-wrap break-words rounded border border-border bg-bg-primary/40 p-2 font-mono text-[10px] text-text-secondary">
        {site.notReproduced.join('\n') || '—'}
      </pre>
      <h3 className="text-[11px] uppercase tracking-wider text-text-muted">{t('baseline.extrapolator.wouldAdd', { count: site.wouldAdd.length })}</h3>
      <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-words rounded border border-border bg-bg-primary/40 p-2 font-mono text-[10px] text-text-secondary">
        {site.wouldAdd.join('\n') || '—'}
      </pre>
    </DialogShell>
  );
}

function ApproveDialog({
  proposal, onClose, onDone,
}: {
  proposal: ExtrapolationProposal;
  onClose: () => void;
  onDone: () => void;
}) {
  const { t } = useTranslation();
  const [name, setName] = useState(`${proposal.label} (extrapolé)`);
  const [description, setDescription] = useState('');
  const [writeValues, setWriteValues] = useState(true);
  // The template applies to this router model only once assigned; prefilled
  // with the model the proposal was mined for, editable, empty = any model.
  const [modelPattern, setModelPattern] = useState(proposal.model ?? '');
  const [busy, setBusy] = useState(false);
  const secrets = proposal.variables.filter((v) => v.secret).length;
  return (
    <DialogShell title={t('baseline.extrapolator.approveTitle')} onClose={onClose}>
      {!proposal.gateMet && (
        <p className="mb-2 rounded border border-status-ssl-warning/40 bg-status-ssl-warning/5 px-2 py-1.5 text-[12px] text-status-ssl-warning">
          {t('baseline.extrapolator.gateNotMet', { min: pct(proposal.reproductionMin) })}
        </p>
      )}
      <p className="mb-2 text-[12px] text-text-muted">{t('baseline.extrapolator.approveHint', { secrets })}</p>
      <label className="block text-[12px] text-text-secondary">
        {t('baseline.extrapolator.templateName')}
        <input
          value={name} onChange={(e) => setName(e.target.value)}
          className="mt-1 w-full rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary"
        />
      </label>
      <label className="mt-2 block text-[12px] text-text-secondary">
        {t('baseline.extrapolator.templateDescription')}
        <textarea
          rows={2} value={description} onChange={(e) => setDescription(e.target.value)}
          className="mt-1 w-full rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary"
        />
      </label>
      <label className="mt-2 block text-[12px] text-text-secondary">
        {t('baseline.extrapolator.modelPattern')}
        <input
          value={modelPattern} onChange={(e) => setModelPattern(e.target.value)} maxLength={64}
          className="mt-1 w-full rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 font-mono text-[13px] text-text-primary"
        />
        <span className="mt-0.5 block text-[11px] text-text-muted">{t('baseline.extrapolator.modelPatternHint')}</span>
      </label>
      <label className="mt-2 flex items-center gap-2 text-[12px] text-text-secondary">
        <input type="checkbox" checked={writeValues} onChange={(e) => setWriteValues(e.target.checked)} className="accent-accent" />
        {t('baseline.extrapolator.writeValues')}
      </label>
      <div className="mt-3 flex justify-end gap-2">
        <Button variant="secondary" size="sm" onClick={onClose}>{t('common.cancel')}</Button>
        <Button
          variant="primary" size="sm" loading={busy} disabled={name.trim() === ''}
          onClick={async () => {
            setBusy(true);
            try {
              const r = await extrapolatorApi.approve(proposal.id, {
                name: name.trim(),
                description: description.trim() || null,
                writeValues,
                modelPattern: modelPattern.trim() === '' ? null : modelPattern.trim(),
              });
              toast.success(t('baseline.extrapolator.approved', {
                written: r.valuesWritten, already: r.valuesAlreadySet, conflicts: r.conflicts.length,
              }));
              if ((r.unmatchedMembers ?? 0) > 0) {
                toast(t('baseline.extrapolator.unmatchedMembers', { count: r.unmatchedMembers }), { icon: '⚠️' });
              }
              onDone();
            } catch (err) {
              toast.error(errorMessageOf(err) ?? t('baseline.extrapolator.approveFailed'));
            } finally {
              setBusy(false);
            }
          }}
        >
          {t('baseline.extrapolator.approve')}
        </Button>
      </div>
    </DialogShell>
  );
}

function RejectDialog({ proposalId, onClose, onDone }: { proposalId: number; onClose: () => void; onDone: () => void }) {
  const { t } = useTranslation();
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  return (
    <DialogShell title={t('baseline.extrapolator.rejectTitle')} onClose={onClose}>
      <textarea
        rows={3} value={note} onChange={(e) => setNote(e.target.value)}
        placeholder={t('baseline.extrapolator.rejectPlaceholder')}
        className="w-full rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary"
      />
      <div className="mt-3 flex justify-end gap-2">
        <Button variant="secondary" size="sm" onClick={onClose}>{t('common.cancel')}</Button>
        <Button
          variant="danger" size="sm" loading={busy} disabled={note.trim() === ''}
          onClick={async () => {
            setBusy(true);
            try {
              await extrapolatorApi.reject(proposalId, note.trim());
              onDone();
            } catch (err) {
              toast.error(errorMessageOf(err) ?? t('baseline.extrapolator.rejectFailed'));
            } finally {
              setBusy(false);
            }
          }}
        >
          {t('baseline.extrapolator.reject')}
        </Button>
      </div>
    </DialogShell>
  );
}
