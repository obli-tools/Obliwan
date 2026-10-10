import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import {
  AlertTriangle, CheckCircle2, ChevronDown, Download, Info, Lock, Play, ShieldCheck, Wand2,
} from 'lucide-react';
import { MAX_SETUP_BODY_CHARS, SETUP_PARTS, type SetupPart } from '@obliwan/shared';
import { Button } from '@/components/common/Button';
import { cn } from '@/utils/cn';
import { useTenantStore } from '@/store/tenantStore';
import { useAuthStore } from '@/store/authStore';
import { isTenantMismatch, tenantSetupApi } from '@/api/tenantSetup.api';
import { apiErrorText } from '@/components/variables/valueKinds';
import { FilesPanel as FilesPanelBase } from '@/components/tenantSetup/FilesPanel';
import { TemplateSection as TemplateSectionBase } from '@/components/tenantSetup/TemplateSection';
import { VariablesDesigner as VariablesDesignerBase } from '@/components/tenantSetup/VariablesDesigner';
import { PolicyForm as PolicyFormBase } from '@/components/tenantSetup/PolicyForm';
import { SitesGrid as SitesGridBase } from '@/components/tenantSetup/SitesGrid';
import { LiveCheckPanel, localProblemText, scrollToTarget } from '@/components/tenantSetup/LiveCheckPanel';
import { ReportPanel, partLabel, stepLabel } from '@/components/tenantSetup/ReportPanel';
import { localProblems } from '@/components/tenantSetup/localChecks';
import { downloadSetup } from '@/components/tenantSetup/exporters';
import { OnboardingAssistant } from '@/components/tenantSetup/OnboardingAssistant';
import {
  buildRequest, hashRequest, isDirty, useQuickSetupStore,
} from '@/components/tenantSetup/quickSetupStore';

/**
 * Quick Setup Tenant — prepare the CURRENT workspace from its files (a
 * variables table, a template, a sites list) and its allocation rule, any one
 * of them or all four, from files or from the designer.
 *
 * ┌─ WHAT THIS SCREEN PROMISES ──────────────────────────────────────────────┐
 * │ • It acts on the session's current workspace, shown in the header, and on │
 * │   nothing else. A bundle naming another workspace is applied HERE, and    │
 * │   the screen says so. A workspace switch while drafts exist freezes the   │
 * │   screen until the operator discards them: a draft prepared for customer  │
 * │   A is never sent under customer B.                                       │
 * │ • The session's workspace lives on the server and every tab shares it,   │
 * │   so a switch in ANOTHER tab is invisible to this one. Every call names   │
 * │   the workspace its drafts belong to (`expectedTenantId`), the server     │
 * │   refuses a mismatch (409) before reading or writing anything, and the   │
 * │   screen then freezes until the session is put back on that workspace.   │
 * │ • "Check" is one server dry run over every selected part together, with   │
 * │   the cross-checks between them; nothing is written. "Apply" is offered   │
 * │   only for the exact body that was checked, and the server re-checks it   │
 * │   anyway (422, nothing written, on any error).                            │
 * │ • Apply writes the parts in the server's order — template (draft) →       │
 * │   variables → rule → publish → sites → site variables — each through the  │
 * │   service that already writes it, and stops at the first failure,         │
 * │   saying what was done.                                                   │
 * │ • Secrets travel in the request only. No response, export or screen of    │
 * │   this page shows a stored secret, and an export leaves every secret      │
 * │   empty.                                                                  │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

type Tab = 'assistant' | 'files' | 'designer';

/** The server's sentence, plus the field paths a 400 names (never zod's
 *  messages: the server sends paths only, so no value can be echoed). */
function requestErrorText(err: unknown): string | null {
  const base = apiErrorText(err);
  const paths = (err as { response?: { data?: { details?: { paths?: unknown } } } }).response?.data?.details?.paths;
  return Array.isArray(paths) && paths.length > 0 ? `${base ?? ''} (${paths.slice(0, 8).join(', ')})` : base;
}

// Each section reads the store through its own selectors; memoised so that a
// keystroke in one of them does not re-render the four (the sites grid alone
// can hold a thousand inputs on a page).
const FilesPanel = memo(FilesPanelBase);
const TemplateSection = memo(TemplateSectionBase);
const VariablesDesigner = memo(VariablesDesignerBase);
const PolicyForm = memo(PolicyFormBase);
const SitesGrid = memo(SitesGridBase);

function PartChip({ state }: { state: 'empty' | 'loaded' | 'edited' | 'errors' }) {
  const { t } = useTranslation();
  return (
    <span
      className={cn(
        'rounded-full px-2 py-0.5 text-[10px] font-medium uppercase',
        state === 'errors' ? 'bg-status-down/15 text-status-down'
          : state === 'edited' ? 'bg-accent/15 text-accent'
            : state === 'loaded' ? 'bg-emerald-500/15 text-emerald-400'
              : 'bg-bg-tertiary text-text-muted',
      )}
    >
      {t(`quickSetup.partState.${state}`, { defaultValue: state })}
    </span>
  );
}

export function QuickSetupTenantPage() {
  const { t } = useTranslation();
  const currentTenantId = useTenantStore((s) => s.currentTenantId);
  const tenants = useTenantStore((s) => s.tenants);
  const userId = useAuthStore((s) => s.user?.id ?? null);

  const state = useQuickSetupStore();
  const {
    tenantId, context, contextLoading, selected, origin, template, lastCheck, lastApply, setContext,
    setContextLoading, setSelected, setLastCheck, setLastApply, reset,
  } = state;

  // The onboarding assistant first: it says which of the other two tabs (and
  // which other screen) the next step happens on.
  const [tab, setTab] = useState<Tab>('assistant');
  const [busy, setBusy] = useState<'check' | 'apply' | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [ackInstance, setAckInstance] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);

  // ── Whose drafts these are ────────────────────────────────────────────────
  useEffect(() => {
    if (currentTenantId === null) return;
    const s = useQuickSetupStore.getState();
    // Another user never inherits a draft; a fresh store or a clean one simply
    // follows the workspace.
    if (s.userId !== userId || s.tenantId === null || (s.tenantId !== currentTenantId && !isDirty(s))) {
      s.reset(currentTenantId, userId);
    }
  }, [currentTenantId, userId]);
  const mismatch = tenantId !== null && currentTenantId !== null && tenantId !== currentTenantId;
  // The server said the SESSION is on another workspace than this tab's
  // drafts (a switch made in another tab). Any switch made in THIS tab posts
  // /tenant/switch, so after one the session agrees with the store again.
  const [sessionMoved, setSessionMoved] = useState(false);
  useEffect(() => setSessionMoved(false), [tenantId, currentTenantId]);
  const frozen = mismatch || sessionMoved;
  const draftTenant = tenants.find((x) => x.id === tenantId);
  const draftName = draftTenant
    ? `${draftTenant.name} (${draftTenant.slug})`
    : context && context.tenant.id === tenantId
      ? `${context.tenant.name} (${context.tenant.slug})`
      : `#${tenantId}`;
  const sessionMovedToast = () =>
    t('quickSetup.sessionMoved.toast', {
      defaultValue: 'The session is no longer on "{{name}}" (switched in another tab?): nothing was checked or written.',
      name: draftName,
    });
  const dirty = isDirty(state);

  // A reload loses every draft (nothing is persisted, on purpose): ask first.
  useEffect(() => {
    if (!dirty) return;
    const handler = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = '';
    };
    window.addEventListener('beforeunload', handler);
    return () => window.removeEventListener('beforeunload', handler);
  }, [dirty]);

  // ── Context: what the designer is generated from ──────────────────────────
  const templateFile = template.source === 'file' ? template.file : null;
  const referenceId = template.source === 'existing' ? template.revisionId : null;
  const seq = useRef(0);
  const loadContext = useCallback(async () => {
    if (tenantId === null) return;
    const mine = ++seq.current;
    setContextLoading(true);
    const referenceRevisionIds = referenceId ? [referenceId] : [];
    const expectedTenantId = tenantId;
    try {
      const ctx = await tenantSetupApi.context(
        templateFile ? { expectedTenantId, template: templateFile, referenceRevisionIds } : { expectedTenantId, referenceRevisionIds },
      );
      if (mine === seq.current) setContext(ctx, null);
    } catch (err) {
      if (mine !== seq.current) return;
      if (isTenantMismatch(err)) {
        // Another workspace's context must not be merged into these drafts:
        // keep what is on screen and freeze.
        setContextLoading(false);
        setSessionMoved(true);
        return;
      }
      const data = (err as { response?: { status?: number; data?: { errors?: unknown } } }).response;
      const lines = Array.isArray(data?.data?.errors) ? (data?.data?.errors as unknown[]).filter((x) => typeof x === 'string') : [];
      const message = [apiErrorText(err) ?? (err as Error).message, ...lines].join('\n');
      if (templateFile && data?.status === 400) {
        // The uploaded template cannot be read: show why, and generate the
        // rest of the screen from what is stored, so the other parts stay
        // usable while the file is fixed. The check will refuse the file too.
        try {
          const ctx = await tenantSetupApi.context({ expectedTenantId, referenceRevisionIds });
          if (mine === seq.current) setContext(ctx, message);
          return;
        } catch (again) {
          if (isTenantMismatch(again) && mine === seq.current) {
            setContextLoading(false);
            setSessionMoved(true);
            return;
          }
          /* fall through */
        }
      }
      if (mine === seq.current) setContext(null, message);
    }
  }, [tenantId, templateFile, referenceId, setContext, setContextLoading]);

  useEffect(() => {
    if (tenantId === null || frozen) return;
    const handle = window.setTimeout(() => void loadContext(), 300);
    return () => window.clearTimeout(handle);
  }, [tenantId, frozen, loadContext]);

  /** Put the session back on the drafts' workspace: an explicit act, because
   *  it moves every tab of this browser. Clearing the flag reloads the
   *  context, and a refused switch shows the 409 — and the banner — again. */
  const restoreSession = async () => {
    if (tenantId === null) return;
    await useTenantStore.getState().setCurrentTenant(tenantId);
    setSessionMoved(false);
  };

  // ── The request on screen ─────────────────────────────────────────────────
  const built = useMemo(() => {
    const { request, siteLines } = buildRequest(state);
    const size = JSON.stringify(request).length;
    return { request, siteLines, hash: hashRequest(request), size };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.context, state.fields, state.extraRows, state.selected, state.template, state.publish, state.policy, state.sites, state.allocate]);
  const maxChars = context?.limits.maxBodyChars ?? MAX_SETUP_BODY_CHARS;
  const problems = useMemo(
    () => localProblems(state, { request: built.request, size: built.size, max: maxChars }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [built, maxChars, state.fields, state.variablesProblems, state.sites, state.selected, state.template],
  );
  const stale = lastCheck !== null && lastCheck.requestHash !== built.hash;
  const instanceRows = (built.request.parts.variables?.rows ?? []).filter((r) => r.level === 'instance' && r.value !== undefined);

  // Not while the context reloads: a field's secrecy in the request comes from
  // the declarations, and a template just loaded may change them.
  const canCheck =
    !frozen && context !== null && !contextLoading && busy === null && !problems.some((p) => p.blocks === 'check');
  const canApply =
    canCheck &&
    lastCheck !== null &&
    !stale &&
    lastCheck.report.canApply &&
    // The server checked THIS workspace (the hash covers expectedTenantId;
    // this says it in so many words).
    lastCheck.report.tenant.id === tenantId &&
    !problems.some((p) => p.blocks !== null);

  const runCheck = async () => {
    setBusy('check');
    try {
      const r = await tenantSetupApi.check(built.request);
      setLastCheck({ requestHash: built.hash, report: r.report, siteLines: built.siteLines });
      setLastApply(null);
      if (r.report.canApply) toast.success(t('quickSetup.report.canApply', { defaultValue: 'Nothing blocks the apply.' }));
    } catch (err) {
      if (isTenantMismatch(err)) {
        setSessionMoved(true);
        toast.error(sessionMovedToast());
        return;
      }
      toast.error(requestErrorText(err) ?? t('quickSetup.check.failed', { defaultValue: 'The check could not run.' }));
    } finally {
      setBusy(null);
    }
  };

  const runApply = async () => {
    setConfirming(false);
    setBusy('apply');
    try {
      const r = await tenantSetupApi.apply({ ...built.request, acknowledgeInstanceScope: ackInstance });
      if (!r.ok) {
        setLastCheck({ requestHash: built.hash, report: r.report, siteLines: built.siteLines });
        setLastApply(null);
        toast.error(t('quickSetup.apply.refused', { defaultValue: 'The check found errors: nothing was written.' }));
        return;
      }
      setLastApply(r.report);
      // The stored state moved: what was checked describes a workspace that
      // no longer exists. The drafts stay, for a re-run or an export.
      setLastCheck(null);
      if (r.report.outcome === 'applied') toast.success(t('quickSetup.apply.done', { defaultValue: 'The setup was applied.' }));
      else toast.error(t('quickSetup.apply.partial', { defaultValue: 'The setup stopped before the end: read the report.' }));
      void loadContext();
    } catch (err) {
      if (isTenantMismatch(err)) {
        setSessionMoved(true);
        toast.error(sessionMovedToast());
        return;
      }
      toast.error(requestErrorText(err) ?? t('quickSetup.apply.error', { defaultValue: 'The apply could not run.' }));
    } finally {
      setBusy(null);
      setAckInstance(false);
    }
  };

  const doExport = (mode: 'bundle' | 'files') => {
    setExportOpen(false);
    const n = downloadSetup(useQuickSetupStore.getState(), mode);
    if (n === 0) {
      toast(t('quickSetup.export.nothing', { defaultValue: 'Nothing to export: tick at least one part.' }));
      return;
    }
    toast.success(t('quickSetup.export.secretsBlank', { defaultValue: 'Exported. Secret values are left empty.' }));
  };

  const openDesigner = useCallback((sectionId: string) => {
    setTab('designer');
    window.setTimeout(() => scrollToTarget(sectionId), 80);
  }, []);

  const partState = (p: SetupPart): 'empty' | 'loaded' | 'edited' | 'errors' => {
    const report = lastApply ?? lastCheck?.report;
    if (
      report?.issues.some((i) => i.part === p && i.severity === 'error') ||
      problems.some((lp) => lp.part === p && lp.blocks !== null)
    ) return 'errors';
    if (origin[p] === 'designer') return 'edited';
    if (origin[p] === 'file') return 'loaded';
    return 'empty';
  };

  const shownReport = lastApply ?? lastCheck?.report ?? null;
  const checkSteps = lastCheck?.report.steps ?? [];

  return (
    <div className="px-6 pt-6">
      {/* ── Header ──────────────────────────────────────────────────────── */}
      <div className="mb-4">
        <h1 className="flex items-center gap-2 text-2xl font-semibold text-text-primary">
          <Wand2 size={22} />
          {t('quickSetup.title', { defaultValue: 'Quick Setup Tenant' })}
        </h1>
        <p className="mt-1 text-sm text-text-muted">
          {t('quickSetup.subtitle', {
            defaultValue: 'Prepare this workspace from its files — variables, template, sites — and its allocation rule.',
          })}
        </p>
        <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
          {context && (
            <span className="rounded-md border border-accent/40 bg-accent/10 px-2 py-1 font-medium text-text-primary">
              {t('quickSetup.workspace', { defaultValue: 'Workspace: {{name}} ({{slug}})', name: context.tenant.name, slug: context.tenant.slug })}
            </span>
          )}
          {context?.tenant.slugFrozen && (
            <span className="inline-flex items-center gap-1 text-text-muted">
              <Lock size={12} />
              {t('quickSetup.slugFrozen', { defaultValue: 'The slug is frozen (an allocation rule or allocations exist).' })}
            </span>
          )}
          {contextLoading && <span className="text-text-muted">…</span>}
        </div>
        {context?.tenant.isMaster && (
          <p className="mt-2 flex items-start gap-1.5 rounded-md border border-amber-500/50 bg-amber-500/10 px-3 py-2 text-sm text-amber-400">
            <AlertTriangle size={15} className="mt-0.5 shrink-0" />
            {t('quickSetup.masterWarning', {
              defaultValue: "This is the Default workspace: templates imported here are never offered to a customer's sites.",
            })}
          </p>
        )}
        {mismatch && (
          <div className="mt-2 flex flex-wrap items-center gap-3 rounded-md border border-status-down/50 bg-status-down/10 px-3 py-2 text-sm text-status-down">
            <AlertTriangle size={15} className="shrink-0" />
            <span className="flex-1">
              {t('quickSetup.tenantChanged', {
                defaultValue:
                  'The workspace changed. These drafts were prepared for "{{from}}": they are not sent to another workspace. Switch back, or discard them.',
                from: draftTenant ? `${draftTenant.name} (${draftTenant.slug})` : `#${tenantId}`,
              })}
            </span>
            <Button type="button" size="sm" variant="danger" onClick={() => reset(currentTenantId, userId)}>
              {t('quickSetup.discardDrafts', { defaultValue: 'Discard the drafts' })}
            </Button>
          </div>
        )}
        {sessionMoved && !mismatch && (
          <div className="mt-2 flex flex-wrap items-center gap-3 rounded-md border border-status-down/50 bg-status-down/10 px-3 py-2 text-sm text-status-down">
            <AlertTriangle size={15} className="shrink-0" />
            <span className="flex-1">
              {t('quickSetup.sessionMoved.body', {
                defaultValue:
                  'The session is no longer on "{{name}}": its workspace was switched, probably in another tab. Nothing is read or sent from this page until the session is back on it. Your drafts are kept.',
                name: draftName,
              })}
            </span>
            <Button type="button" size="sm" variant="secondary" onClick={() => void restoreSession()}>
              {t('quickSetup.sessionMoved.restore', {
                defaultValue: 'Switch the session back (every tab)',
              })}
            </Button>
          </div>
        )}
        {!context && !contextLoading && state.contextError && !frozen && (
          <p className="mt-2 whitespace-pre-wrap rounded border border-status-down/50 bg-status-down/10 p-2 text-xs text-status-down">
            {state.contextError}
          </p>
        )}
      </div>

      {/* ── Tabs ────────────────────────────────────────────────────────── */}
      <div className="mb-4 flex items-center gap-1 border-b border-border">
        {(['assistant', 'files', 'designer'] as const).map((x) => (
          <button
            key={x}
            type="button"
            onClick={() => setTab(x)}
            className={cn(
              'relative px-4 py-2.5 text-[13px]',
              'after:absolute after:inset-x-2 after:-bottom-px after:h-0.5 after:rounded-full',
              tab === x ? 'text-text-primary after:bg-accent' : 'text-text-secondary hover:text-text-primary after:bg-transparent',
            )}
          >
            {x === 'assistant'
              ? t('onboarding.tab')
              : t(`quickSetup.tabs.${x}`, { defaultValue: x === 'files' ? 'Files' : 'Designer' })}
          </button>
        ))}
      </div>

      {/* ── The four parts ──────────────────────────────────────────────── */}
      {tab !== 'assistant' && (
      <div className="mb-4 grid grid-cols-2 gap-2 lg:grid-cols-4">
        {SETUP_PARTS.map((p) => {
          const templateUnavailable = p === 'template' && template.source !== 'file';
          return (
            <label
              key={p}
              className={cn(
                'flex items-center gap-2 rounded-lg border px-3 py-2 text-sm',
                selected[p] ? 'border-accent/60 bg-accent/5' : 'border-border bg-bg-secondary',
                templateUnavailable && 'opacity-70',
              )}
              title={templateUnavailable
                ? t('quickSetup.template.tickNeedsFile', { defaultValue: 'Load a template file to import it; an existing template is only a reference.' })
                : undefined}
            >
              <input
                type="checkbox"
                checked={selected[p]}
                disabled={templateUnavailable && !selected[p]}
                onChange={(e) => setSelected(p, e.target.checked)}
              />
              <span className="flex-1 text-text-primary">{partLabel(t, p)}</span>
              <PartChip state={partState(p)} />
            </label>
          );
        })}
      </div>
      )}

      {tab === 'assistant' ? (
        <OnboardingAssistant onOpenDesigner={openDesigner} />
      ) : tab === 'files' ? (
        <FilesPanel onOpenDesigner={openDesigner} />
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1fr)_300px]">
          <div className="min-w-0 space-y-6">
            <div>
              <h2 className="mb-2 text-sm font-semibold text-text-primary">
                1 · {t('quickSetup.designer.step.template', { defaultValue: 'Template' })}
              </h2>
              <TemplateSection />
            </div>
            <div id="qs-step-variables">
              <h2 className="mb-2 text-sm font-semibold text-text-primary">
                2 · {t('quickSetup.designer.step.variables', { defaultValue: 'Variables' })}
              </h2>
              {context ? <VariablesDesigner /> : <p className="text-xs text-text-muted">…</p>}
            </div>
            <div>
              <h2 className="mb-2 text-sm font-semibold text-text-primary">
                3 · {t('quickSetup.designer.step.allocationPolicy', { defaultValue: 'Allocation rule' })}
              </h2>
              <PolicyForm />
            </div>
            <div>
              <h2 className="mb-2 text-sm font-semibold text-text-primary">
                4 · {t('quickSetup.designer.step.sites', { defaultValue: 'Sites' })}
              </h2>
              <SitesGrid stale={stale} />
            </div>
            <p className="flex items-start gap-1.5 text-xs text-text-muted">
              <Info size={13} className="mt-0.5 shrink-0" />
              {t('quickSetup.notInScope', {
                defaultValue:
                  'Not part of a quick setup: group and router variables (Variables page), the installation domain and the address pools (allocation page), creating the workspace itself.',
              })}
            </p>
          </div>
          <div className="lg:sticky lg:top-4 lg:self-start">
            <LiveCheckPanel problems={problems} />
          </div>
        </div>
      )}

      {/* ── Server verdict ──────────────────────────────────────────────── */}
      {shownReport && tab !== 'assistant' && (
        <div className="mt-6">
          <h2 className="mb-2 flex items-center gap-2 text-sm font-semibold text-text-primary">
            <ShieldCheck size={16} />
            {t('quickSetup.report.title', { defaultValue: 'Server check' })}
          </h2>
          <ReportPanel report={shownReport} stale={lastApply === null && stale} />
        </div>
      )}

      {/* ── Sticky footer ───────────────────────────────────────────────── */}
      {tab !== 'assistant' && (
      <div className="sticky bottom-0 z-30 -mx-6 mt-6 border-t border-border bg-bg-secondary/95 backdrop-blur">
        <div className="flex flex-wrap items-center gap-2 px-6 py-3">
          <Button type="button" variant="secondary" onClick={() => void runCheck()} loading={busy === 'check'} disabled={!canCheck}>
            <CheckCircle2 size={15} className="mr-1.5" />
            {busy === 'check'
              ? t('quickSetup.actions.checking', { defaultValue: 'Checking…' })
              : t('quickSetup.actions.check', { defaultValue: 'Check' })}
          </Button>
          <Button type="button" onClick={() => { setAckInstance(false); setConfirming(true); }} loading={busy === 'apply'} disabled={!canApply}>
            <Play size={15} className="mr-1.5" />
            {busy === 'apply'
              ? t('quickSetup.actions.applying', { defaultValue: 'Applying…' })
              : t('quickSetup.actions.apply', { defaultValue: 'Apply' })}
          </Button>
          <div className="relative">
            <Button type="button" variant="ghost" onClick={() => setExportOpen((o) => !o)} disabled={!context}>
              <Download size={15} className="mr-1.5" />
              {t('quickSetup.actions.export', { defaultValue: 'Export' })}
              <ChevronDown size={13} className="ml-1" />
            </Button>
            {exportOpen && (
              <div className="absolute bottom-full left-0 mb-1 w-56 rounded-lg border border-border bg-bg-secondary p-1 shadow-xl">
                <button type="button" onClick={() => doExport('bundle')} className="block w-full rounded px-3 py-2 text-left text-sm text-text-primary hover:bg-bg-tertiary">
                  {t('quickSetup.actions.exportBundle', { defaultValue: 'One bundle file' })}
                </button>
                <button type="button" onClick={() => doExport('files')} className="block w-full rounded px-3 py-2 text-left text-sm text-text-primary hover:bg-bg-tertiary">
                  {t('quickSetup.actions.exportFiles', { defaultValue: 'Separate files' })}
                </button>
              </div>
            )}
          </div>
          <span className="ml-2 min-w-0 flex-1 truncate text-xs text-text-muted">
            {problems.find((p) => p.blocks === 'check')
              ? localProblemText(t, problems.find((p) => p.blocks === 'check')!)
              : !lastCheck
                ? t('quickSetup.status.notChecked', { defaultValue: 'Not checked yet.' })
                : stale
                  ? t('quickSetup.status.stale', { defaultValue: 'Changed since the last check: check again.' })
                  : lastCheck.report.canApply
                    ? problems.some((p) => p.blocks === 'apply')
                      ? localProblemText(t, problems.find((p) => p.blocks === 'apply')!)
                      : t('quickSetup.status.ready', { defaultValue: 'Checked: ready to apply.' })
                    : t('quickSetup.report.blocked', {
                      defaultValue: '{{count}} error(s) block the apply.',
                      count: lastCheck.report.issues.filter((i) => i.severity === 'error').length,
                    })}
          </span>
        </div>
      </div>
      )}

      {/* ── Apply confirmation ──────────────────────────────────────────── */}
      {confirming && lastCheck && (
        <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4">
          <div role="dialog" aria-modal="true" className="my-16 w-full max-w-lg rounded-xl border border-border bg-bg-secondary shadow-2xl">
            <div className="border-b border-border px-5 py-4">
              <h2 className="text-base font-semibold text-text-primary">
                {t('quickSetup.apply.confirmTitle', { defaultValue: 'Apply the setup' })}
              </h2>
            </div>
            <div className="space-y-3 p-5 text-sm">
              <p className="text-text-secondary">
                {t('quickSetup.apply.confirmBody', {
                  defaultValue:
                    'This writes to the workspace "{{name}}". Each step goes through its usual service; the first failure stops the steps after it, and the report says what was written.',
                  name: context ? `${context.tenant.name} (${context.tenant.slug})` : '',
                })}
              </p>
              <div>
                <p className="mb-1 text-xs text-text-muted">{t('quickSetup.apply.orderTitle', { defaultValue: 'In this order:' })}</p>
                <ol className="list-decimal space-y-0.5 pl-5 text-text-primary">
                  {checkSteps.map((s) => <li key={s}>{stepLabel(t, s)}</li>)}
                </ol>
              </div>
              {instanceRows.length > 0 && (
                <label className="flex items-start gap-2 rounded-md border border-amber-500/50 bg-amber-500/10 p-2 text-amber-400">
                  <input type="checkbox" className="mt-1" checked={ackInstance} onChange={(e) => setAckInstance(e.target.checked)} />
                  <span>
                    {t('quickSetup.options.ackInstance', { defaultValue: 'I understand that instance variables apply to every workspace.' })}
                    <span className="block font-mono text-xs">{instanceRows.map((r) => r.key).join(', ')}</span>
                  </span>
                </label>
              )}
            </div>
            <div className="flex justify-end gap-2 border-t border-border px-5 py-3">
              <Button type="button" size="sm" variant="secondary" onClick={() => setConfirming(false)}>
                {t('common.cancel')}
              </Button>
              <Button
                type="button"
                size="sm"
                onClick={() => void runApply()}
                disabled={instanceRows.length > 0 && !ackInstance}
              >
                <Play size={14} className="mr-1.5" />
                {t('quickSetup.actions.apply', { defaultValue: 'Apply' })}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
