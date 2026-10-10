import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import {
  AlertTriangle, CheckCircle2, ChevronDown, ChevronRight, Circle, CircleSlash, DownloadCloud, ExternalLink, Loader2,
  RefreshCw, Rocket, Wand2,
} from 'lucide-react';
import type { OnboardingStatus, OnboardingStep, OnboardingStepKey, OnboardingStepState } from '@obliwan/shared';
import { onboardingApi } from '@/api/onboarding.api';
import { allocationApi } from '@/api/allocation.api';
import { configApi } from '@/api/config.api';
import { errorMessageOf } from '@/api/change.api';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { GodViewTenantFilter } from '@/components/common/GodViewTenantFilter';
import { useGodView, useGodViewStore } from '@/store/godViewStore';
import { useTenantStore } from '@/store/tenantStore';
import { cn } from '@/utils/cn';
import { RuleInferencePanel } from './RuleInferencePanel';

/**
 * « Assistant d'arrivée » — a big customer's onboarding as nine ordered
 * steps, each with its state computed by the server FROM THE DATABASE at every
 * read (GET /tenant-setup/onboarding): nothing is remembered here, so the
 * assistant resumes wherever the onboarding stands — after a reload, a
 * deploy, or work done on another screen.
 *
 * Each step offers ONE primary action or a deep link to the screen that does
 * it; nothing here writes to a router. The two gestures run from this page:
 * re-reading the CHR (the allocator's own read) and saving the allocation
 * rule read off the CHR (RuleInferencePanel, on the operator's approval); the
 * bulk collect is the existing `/config/tenant-collect`.
 *
 * God view (Default workspace): the client is the one picked in the workspace
 * filter; every deep link keeps it (the filter is per tab).
 */

const STATE_STYLES: Record<OnboardingStepState, string> = {
  done: 'border-status-up/50 bg-status-up/10 text-status-up',
  todo: 'border-accent/50 bg-accent/10 text-accent',
  blocked: 'border-border bg-bg-tertiary text-text-muted',
  running: 'border-status-ssl-warning/50 bg-status-ssl-warning/10 text-status-ssl-warning',
};

function StateIcon({ state }: { state: OnboardingStepState }) {
  if (state === 'done') return <CheckCircle2 size={16} className="text-status-up" />;
  if (state === 'running') return <Loader2 size={16} className="animate-spin text-status-ssl-warning" />;
  if (state === 'blocked') return <CircleSlash size={16} className="text-text-muted" />;
  return <Circle size={16} className="text-accent" />;
}

/** The screens each step's work is done on. */
const LINKS: Partial<Record<OnboardingStepKey, Array<{ to: string; label: string }>>> = {
  chr: [{ to: '/reconcile', label: 'reconcile' }],
  sites: [{ to: '/reconcile', label: 'reconcile' }, { to: '/sites', label: 'sites' }],
  attach: [{ to: '/reconcile', label: 'reconcile' }, { to: '/manage/learning', label: 'learning' }],
  access: [{ to: '/reconcile', label: 'reconcile' }],
  configs: [{ to: '/manage/learning', label: 'learning' }, { to: '/baseline', label: 'baseline' }],
  infra: [{ to: '/manage/infra-analysis', label: 'infra' }],
  templates: [{ to: '/baseline', label: 'baseline' }, { to: '/templates', label: 'templates' }],
  variables: [{ to: '/variables', label: 'variables' }],
};

export function OnboardingAssistant({ onOpenDesigner }: { onOpenDesigner: (sectionId: string) => void }) {
  const { t, i18n } = useTranslation();
  const godView = useGodView();
  const filterTenantId = useGodViewStore((s) => s.filterTenantId);
  const sessionTenantId = useTenantStore((s) => s.currentTenantId);
  const needsPick = godView && filterTenantId === null;

  const [status, setStatus] = useState<OnboardingStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ruleOpen, setRuleOpen] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setStatus(await onboardingApi.status());
    } catch (err) {
      setStatus(null);
      setError(errorMessageOf(err) ?? t('onboarding.loadFailed'));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    setStatus(null);
    setRuleOpen(false);
    if (needsPick) return;
    void load();
  }, [load, needsPick, filterTenantId, sessionTenantId]);

  // A step that is running (the bulk collect) is followed until it ends.
  const running = status?.steps.some((s) => s.state === 'running') === true;
  useEffect(() => {
    if (!running) return;
    const timer = window.setInterval(() => void load(), 3000);
    return () => window.clearInterval(timer);
  }, [running, load]);

  const reread = async (concentratorId: number): Promise<void> => {
    setBusy('chr');
    try {
      const r = await allocationApi.rereadConcentrator(concentratorId);
      toast.success(t('onboarding.actions.rereadDone', { count: r.recorded }));
      await load();
    } catch (err) {
      toast.error(errorMessageOf(err) ?? t('onboarding.actions.failed'));
    } finally {
      setBusy(null);
    }
  };

  const collect = async (): Promise<void> => {
    setBusy('configs');
    try {
      await configApi.startTenantCollect();
      toast.success(t('onboarding.actions.collectStarted'));
      await load();
    } catch (err) {
      toast.error(errorMessageOf(err) ?? t('onboarding.actions.failed'));
    } finally {
      setBusy(null);
    }
  };

  // The Concepteur acts on the session's workspace: offered only when the
  // assistant's client IS that workspace.
  const sameWorkspace = !godView && status !== null && status.tenant.id === sessionTenantId;
  const dateFmt = new Intl.DateTimeFormat(i18n.language, { dateStyle: 'short', timeStyle: 'short' });

  const actionsOf = (s: OnboardingStep) => {
    const out: JSX.Element[] = [];
    if (s.key === 'chr' && s.concentratorId !== null) {
      out.push(
        <Button key="reread" size="sm" variant={s.state === 'done' ? 'secondary' : 'primary'} loading={busy === 'chr'}
          onClick={() => void reread(s.concentratorId as number)}>
          <RefreshCw size={13} className="mr-1.5" />
          {t('onboarding.actions.reread')}
        </Button>,
      );
    }
    if (s.key === 'rule' && s.state !== 'blocked') {
      out.push(
        <Button key="rule" size="sm" variant={s.state === 'done' ? 'secondary' : 'primary'} onClick={() => setRuleOpen((o) => !o)}>
          <Wand2 size={13} className="mr-1.5" />
          {ruleOpen ? t('onboarding.actions.hideRule') : t('onboarding.actions.proposeRule')}
        </Button>,
      );
    }
    if (s.key === 'configs' && s.state !== 'blocked') {
      out.push(
        <Button key="collect" size="sm" variant={s.state === 'todo' ? 'primary' : 'secondary'} loading={busy === 'configs'}
          disabled={s.state === 'running'} onClick={() => void collect()}>
          <DownloadCloud size={13} className="mr-1.5" />
          {t('onboarding.actions.collect')}
        </Button>,
      );
    }
    if (s.key === 'variables' && sameWorkspace && s.state === 'todo') {
      out.push(
        <Button key="designer" size="sm" variant="secondary" onClick={() => onOpenDesigner('qs-step-variables')}>
          {t('onboarding.actions.designer')}
        </Button>,
      );
    }
    for (const l of LINKS[s.key] ?? []) {
      out.push(
        <Link key={l.to} to={l.to}
          className="inline-flex items-center gap-1 rounded-md border border-border px-2.5 py-1 text-xs text-text-secondary hover:bg-bg-hover hover:text-text-primary">
          <ExternalLink size={12} />
          {t(`onboarding.links.${l.label}`)}
        </Link>,
      );
    }
    return out;
  };

  return (
    <section className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="flex items-center gap-2 text-lg font-semibold text-text-primary">
          <Rocket size={18} className="text-accent" />
          {t('onboarding.title')}
        </h2>
        {status && (
          <span className="rounded-md border border-accent/40 bg-accent/10 px-2 py-0.5 text-xs font-medium text-text-primary">
            {status.tenant.name} ({status.tenant.slug})
          </span>
        )}
        <GodViewTenantFilter allowAll={false} />
        <span className="ml-auto flex items-center gap-2 text-[11px] text-text-muted">
          {status && t('onboarding.generatedAt', { at: dateFmt.format(new Date(status.generatedAt)) })}
          <Button size="sm" variant="ghost" loading={loading} onClick={() => void load()} disabled={needsPick}>
            <RefreshCw size={13} />
          </Button>
        </span>
      </div>
      <p className="text-xs text-text-muted">{t('onboarding.subtitle')}</p>

      {needsPick && (
        <p className="rounded-md border border-amber-500/50 bg-amber-500/10 px-3 py-2 text-sm text-amber-400">
          {t('onboarding.pickTenant')}
        </p>
      )}
      {error && <p className="rounded border border-status-down/50 bg-status-down/10 p-2 text-sm text-status-down">{error}</p>}
      {loading && !status && !needsPick && <div className="py-8"><LoadingSpinner /></div>}

      {status && (
        <ol className="space-y-2">
          {status.steps.map((s, i) => (
            <li
              key={s.key}
              className={cn(
                'rounded-lg border bg-bg-secondary p-3',
                status.next === s.key ? 'border-accent/60' : 'border-border',
              )}
            >
              <div className="flex flex-wrap items-start gap-2">
                <StateIcon state={s.state} />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-semibold text-text-primary">{i + 1} · {t(`onboarding.steps.${s.key}`)}</span>
                    <span className={cn('rounded-full border px-2 py-0.5 text-[10px] font-medium uppercase', STATE_STYLES[s.state])}>
                      {t(`onboarding.state.${s.state}`)}
                    </span>
                    {status.next === s.key && <span className="text-[11px] font-medium text-accent">{t('onboarding.next')}</span>}
                    {s.at && <span className="text-[11px] text-text-muted">{dateFmt.format(new Date(s.at))}</span>}
                  </div>
                  <p className="mt-0.5 text-sm text-text-secondary">
                    {t(`onboarding.reasons.${s.reason}`, { ...s.counts, first: s.items[0] ?? '' })}
                  </p>
                  {s.warning && (
                    <p className="mt-0.5 flex items-start gap-1 text-xs text-status-ssl-warning">
                      <AlertTriangle size={12} className="mt-0.5 shrink-0" />
                      {t(`onboarding.warnings.${s.warning}`, { ...s.counts })}
                    </p>
                  )}
                  {s.secrets.length > 0 && (
                    <p className="mt-1 text-xs text-text-secondary">
                      {t('onboarding.secretsToFill')}{' '}
                      <span className="font-mono text-text-primary">{s.secrets.join(', ')}</span>
                    </p>
                  )}
                  {s.items.length > 0 && s.reason !== 'chr_read' && s.reason !== 'never_read' && s.reason !== 'policy_saved' && (
                    <Items items={s.items} />
                  )}
                  {s.key === 'rule' && s.items[0] && s.reason === 'policy_saved' && (
                    <p className="mt-0.5 font-mono text-xs text-text-primary">{s.items[0]}</p>
                  )}
                </div>
                <div className="flex flex-wrap items-center gap-1.5">{actionsOf(s)}</div>
              </div>
              {s.key === 'rule' && ruleOpen && (
                <RuleInferencePanel
                  tenantSlug={status.tenant.slug}
                  canPrefill={sameWorkspace}
                  onPrefilled={() => onOpenDesigner('qs-step-policy')}
                  onSaved={() => void load()}
                />
              )}
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

function Items({ items }: { items: string[] }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  return (
    <div className="mt-1">
      <button type="button" onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-1 text-[11px] text-text-muted hover:text-text-primary">
        {open ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
        {t('onboarding.items', { count: items.length })}
      </button>
      {open && <p className="mt-1 break-words font-mono text-[11px] text-text-primary">{items.join(', ')}</p>}
    </div>
  );
}
