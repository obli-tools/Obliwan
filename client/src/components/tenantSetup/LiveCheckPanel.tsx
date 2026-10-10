import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { CheckCircle2, CircleDot, ListChecks } from 'lucide-react';
import type { RequirementReport } from '@obliwan/shared';
import { cn } from '@/utils/cn';
import { levelLabel } from '@/components/templates/labels';
import { liveRequirements, type LocalProblem } from './localChecks';
import { useQuickSetupStore } from './quickSetupStore';

/**
 * The designer's live panel: which REQUIRED variables would still have no
 * value once this setup is written, by level, recomputed as the operator types
 * — with the server's own `resolveRequirements` — plus what is visibly wrong
 * on screen. Labelled for what it is: a local preview. "Check" is the verdict.
 */

export function scrollToTarget(id: string): void {
  const el = document.getElementById(id);
  if (!el) return;
  el.scrollIntoView({ behavior: 'smooth', block: 'center' });
  el.classList.add('ring-2', 'ring-accent');
  window.setTimeout(() => el.classList.remove('ring-2', 'ring-accent'), 1600);
  const input = el.querySelector('input,select,textarea') as HTMLElement | null;
  input?.focus({ preventScroll: true });
}

export function localProblemText(t: TFunction, p: LocalProblem): string {
  switch (p.code) {
    case 'nothingSelected':
      return t('quickSetup.local.nothingSelected', { defaultValue: 'Select at least one part.' });
    case 'tooLarge':
      return t('quickSetup.local.tooLarge', {
        defaultValue: 'The setup is too large to send in one request ({{size}} characters, limit {{max}}).', ...p.params,
      });
    case 'fieldErrors':
      return t('quickSetup.local.fieldErrors', {
        defaultValue: '{{count}} field(s) cannot be read: they are not sent, and Apply waits until they are fixed.', ...p.params,
      });
    case 'variablesFile':
      return t('quickSetup.local.variablesFile', {
        defaultValue: 'The variables file has {{count}} problem(s): the rows concerned were not loaded.', ...p.params,
      });
    case 'noTemplateFile':
      return t('quickSetup.local.noTemplateFile', { defaultValue: 'The template part is ticked but no template file is loaded.' });
    case 'sitesEmpty':
      return t('quickSetup.local.sitesEmpty', { defaultValue: 'The sites part is ticked but the grid has no row.' });
    case 'gridRows':
    default:
      return t('quickSetup.local.gridRows', {
        defaultValue:
          '{{count}} site row(s) look wrong: {{codeMissing}} without a code, {{nameMissing}} without a name, {{excelCode}} code(s) rewritten by Excel, {{duplicateCode}} duplicated code(s).',
        ...p.params,
      });
  }
}

export function LiveCheckPanel({ problems }: { problems: LocalProblem[] }) {
  const { t } = useTranslation();
  const context = useQuickSetupStore((s) => s.context);
  const fields = useQuickSetupStore((s) => s.fields);
  const extraRows = useQuickSetupStore((s) => s.extraRows);
  const sites = useQuickSetupStore((s) => s.sites);
  const policy = useQuickSetupStore((s) => s.policy);
  const selected = useQuickSetupStore((s) => s.selected);
  const variablesProblems = useQuickSetupStore((s) => s.variablesProblems);
  const template = useQuickSetupStore((s) => s.template);
  const [report, setReport] = useState<RequirementReport | null>(null);

  useEffect(() => {
    const handle = window.setTimeout(() => {
      setReport(liveRequirements({ context, fields, extraRows, sites, policy, selected, variablesProblems, template }));
    }, 300);
    return () => window.clearTimeout(handle);
  }, [context, fields, extraRows, sites, policy, selected, variablesProblems, template]);

  const checked = report?.levels.filter((l) => l.checked && l.missing.length > 0) ?? [];
  const unchecked = report?.levels.filter((l) => !l.checked && l.missing.length > 0) ?? [];

  const reasonText = (reason: string) =>
    reason === 'no_policy'
      ? t('quickSetup.live.noPolicy', { defaultValue: 'no allocation rule' })
      : reason === 'not_supplied'
        ? t('quickSetup.live.notSupplied', { defaultValue: 'not supplied by the rule' })
        : null;

  return (
    <aside className="rounded-xl border border-border bg-bg-secondary p-3 text-xs">
      <h3 className="mb-0.5 flex items-center gap-1.5 text-sm font-semibold text-text-primary">
        <ListChecks size={15} />
        {t('quickSetup.live.title', { defaultValue: 'Live check' })}
      </h3>
      <p className="mb-3 text-[11px] text-text-muted">
        {t('quickSetup.live.note', { defaultValue: 'Local check — the server check is authoritative.' })}
      </p>

      {problems.length > 0 && (
        <ul className="mb-3 space-y-1.5">
          {problems.map((p, i) => (
            <li
              key={`${p.code}-${i}`}
              className={cn(
                'rounded-md border px-2 py-1.5',
                p.blocks ? 'border-status-down/50 bg-status-down/10 text-status-down' : 'border-amber-500/40 bg-amber-500/10 text-amber-400',
              )}
            >
              {localProblemText(t, p)}
              {p.targets && p.targets.length > 0 && (
                <div className="mt-1 flex flex-wrap gap-1">
                  {p.targets.slice(0, 12).map((x) => (
                    <button
                      key={x.id}
                      type="button"
                      onClick={() => scrollToTarget(x.id)}
                      className="rounded bg-bg-tertiary px-1.5 font-mono text-[11px] text-text-primary hover:underline"
                    >
                      {x.label}
                    </button>
                  ))}
                </div>
              )}
            </li>
          ))}
        </ul>
      )}

      {!report ? (
        <p className="text-text-muted">…</p>
      ) : checked.length === 0 ? (
        <p className="flex items-center gap-1.5 text-emerald-400">
          <CheckCircle2 size={13} />
          {t('quickSetup.live.allGood', { defaultValue: 'Every required variable has a value, a default or a source.' })}
        </p>
      ) : (
        <div className="space-y-2">
          {checked.map((l) => (
            <div key={l.level}>
              <p className="font-medium text-text-primary">
                {t('quickSetup.live.missingAt', {
                  defaultValue: 'Missing — {{level}} ({{count}})', level: levelLabel(t, l.level), count: l.missing.length,
                })}
              </p>
              <ul className="mt-0.5 space-y-0.5">
                {l.missing.map((m) => (
                  <li key={m.key} className="flex flex-wrap items-baseline gap-1">
                    <CircleDot size={10} className="shrink-0 text-status-down" />
                    <button
                      type="button"
                      onClick={() => scrollToTarget(l.level === 'site' ? 'qs-step-sites' : `qs-field-${l.level}-${m.key}`)}
                      className="font-mono text-text-primary hover:underline"
                    >
                      {m.key}
                    </button>
                    {m.sitesTotal !== undefined && (
                      <span className="text-text-muted">
                        {t('quickSetup.live.sitesMissing', {
                          defaultValue: '{{count}} site(s): {{codes}}',
                          count: m.sitesTotal,
                          codes: (m.sites ?? []).slice(0, 5).join(', ') + (m.sitesTotal > 5 ? '…' : ''),
                        })}
                      </span>
                    )}
                    {reasonText(m.reason) && <span className="text-text-muted">({reasonText(m.reason)})</span>}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}

      {unchecked.length > 0 && (
        <div className="mt-3 border-t border-border pt-2 text-text-muted">
          <p className="mb-0.5">
            {t('quickSetup.live.unchecked', {
              defaultValue: 'Required at a level a setup cannot fill (set them on the Variables page):',
            })}
          </p>
          {unchecked.map((l) => (
            <p key={l.level}>
              <span className="text-text-secondary">{levelLabel(t, l.level)}:</span>{' '}
              <span className="font-mono">{l.missing.map((m) => m.key).join(', ')}</span>
            </p>
          ))}
        </div>
      )}
    </aside>
  );
}
