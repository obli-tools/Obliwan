import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { Link } from 'react-router-dom';
import {
  AlertTriangle, CheckCircle2, ChevronRight, CircleSlash, Info, KeyRound, MinusCircle, XCircle,
} from 'lucide-react';
import type { IssueSeverity, SetupIssue, SetupPart, SetupStep, TenantSetupReport } from '@obliwan/shared';
import { cn } from '@/utils/cn';
import { levelLabel, issueWhere } from '@/components/templates/labels';
import { asSitesResult, asTemplateReport } from '@/api/tenantSetup.api';
import { issueText } from './issueText';
import { CARD } from './ui';

/**
 * The SERVER's verdict, as returned by Check (a dry run, nothing written) or
 * by Apply (what was written, step by step, and where it stopped).
 *
 * The embedded reports of the reused services — the template import report,
 * the site import result, the allocation validator's details — are shown in
 * their own words, exactly as their own screens show them. Nothing here ever
 * shows a variable VALUE: the report has none to show. A secret row is
 * labelled "secret", and that is all that is known of it.
 */

const SEVERITIES: IssueSeverity[] = ['error', 'warning', 'info'];
const PART_ORDER: Array<SetupPart | 'setup'> = ['setup', 'template', 'variables', 'allocationPolicy', 'sites'];

export function stepLabel(t: TFunction, step: SetupStep): string {
  switch (step) {
    case 'template': return t('quickSetup.steps.template', { defaultValue: 'Import the template (draft)' });
    case 'variables': return t('quickSetup.steps.variables', { defaultValue: 'Write the instance / global / customer variables' });
    case 'allocationPolicy': return t('quickSetup.steps.allocationPolicy', { defaultValue: 'Save the allocation rule' });
    case 'publish': return t('quickSetup.steps.publish', { defaultValue: 'Publish the revision' });
    case 'sites': return t('quickSetup.steps.sites', { defaultValue: 'Import the sites' });
    case 'siteVariables':
    default:
      return t('quickSetup.steps.siteVariables', { defaultValue: 'Write the site variables' });
  }
}

export function partLabel(t: TFunction, part: SetupPart | 'setup'): string {
  if (part === 'setup') return t('quickSetup.parts.setup', { defaultValue: 'Setup' });
  return t(`quickSetup.parts.${part}`, { defaultValue: part });
}

function SeverityIcon({ severity }: { severity: IssueSeverity }) {
  if (severity === 'error') return <XCircle size={13} className="mt-0.5 shrink-0 text-status-down" />;
  if (severity === 'warning') return <AlertTriangle size={13} className="mt-0.5 shrink-0 text-amber-400" />;
  return <Info size={13} className="mt-0.5 shrink-0 text-text-muted" />;
}

function summaryText(summary: Record<string, number>): string {
  return Object.entries(summary)
    .map(([k, v]) => `${k}: ${v}`)
    .join(' · ');
}

export function ReportPanel({ report, stale }: { report: TenantSetupReport; stale: boolean }) {
  const { t } = useTranslation();
  const errors = report.issues.filter((i) => i.severity === 'error').length;

  const grouped = useMemo(() => {
    const out = new Map<IssueSeverity, Map<SetupPart | 'setup', SetupIssue[]>>();
    for (const sev of SEVERITIES) out.set(sev, new Map());
    for (const i of report.issues) {
      const bySev = out.get(i.severity)!;
      bySev.set(i.part, [...(bySev.get(i.part) ?? []), i]);
    }
    return out;
  }, [report]);

  const actionLabel = (a: string) => t(`quickSetup.report.action.${a}`, { defaultValue: a });
  const templateReport = asTemplateReport(report.template?.report);
  const sitesResult = asSitesResult(report.sites?.result);
  const missingLevels = report.requirements.levels.filter((l) => l.missing.length > 0);

  return (
    <div className={cn('space-y-4', stale && 'opacity-80')}>
      {/* ── Verdict ───────────────────────────────────────────────────────── */}
      {report.dryRun ? (
        <div
          className={cn(
            'flex items-start gap-2 rounded-lg border px-3 py-2 text-sm',
            report.canApply
              ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400'
              : 'border-status-down/50 bg-status-down/10 text-status-down',
          )}
        >
          {report.canApply ? <CheckCircle2 size={16} className="mt-0.5" /> : <XCircle size={16} className="mt-0.5" />}
          <div>
            <p className="font-medium">
              {report.canApply
                ? t('quickSetup.report.canApply', { defaultValue: 'Nothing blocks the apply.' })
                : t('quickSetup.report.blocked', { defaultValue: '{{count}} error(s) block the apply.', count: errors })}
            </p>
            {stale && (
              <p className="text-xs text-amber-400">
                {t('quickSetup.report.stale', { defaultValue: 'The setup changed since this check: check again before applying.' })}
              </p>
            )}
            {report.steps.length > 0 && (
              <p className="mt-1 flex flex-wrap items-center gap-1 text-xs text-text-secondary">
                {t('quickSetup.report.order', { defaultValue: 'Apply order:' })}
                {report.steps.map((s, i) => (
                  <span key={s} className="inline-flex items-center gap-1">
                    {i > 0 && <ChevronRight size={11} />}
                    {stepLabel(t, s)}
                  </span>
                ))}
              </p>
            )}
          </div>
        </div>
      ) : (
        <div
          className={cn(
            'rounded-lg border px-3 py-2 text-sm',
            report.outcome === 'applied'
              ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400'
              : 'border-status-down/50 bg-status-down/10 text-status-down',
          )}
        >
          <p className="font-medium">
            {report.outcome === 'applied'
              ? t('quickSetup.apply.done', { defaultValue: 'The setup was applied.' })
              : t('quickSetup.apply.failed', {
                defaultValue: 'Stopped at step "{{step}}": the earlier steps were written, the later ones were not run.',
                step: stepLabel(t, report.stepResults?.find((s) => s.status === 'failed')?.step ?? 'template'),
              })}
          </p>
          {report.stepResults && (
            <ol className="mt-2 space-y-1 text-xs text-text-primary">
              {report.stepResults.map((s) => (
                <li key={s.step} className="flex flex-wrap items-baseline gap-2">
                  {s.status === 'done' ? (
                    <CheckCircle2 size={13} className="shrink-0 text-emerald-400" />
                  ) : s.status === 'failed' ? (
                    <XCircle size={13} className="shrink-0 text-status-down" />
                  ) : (
                    <CircleSlash size={13} className="shrink-0 text-text-muted" />
                  )}
                  <span className="font-medium">{stepLabel(t, s.step)}</span>
                  <span className="text-text-muted">{t(`quickSetup.stepStatus.${s.status}`, { defaultValue: s.status })}</span>
                  {Object.keys(s.summary).length > 0 && (
                    <span className="font-mono text-[11px] text-text-muted">{summaryText(s.summary)}</span>
                  )}
                  {s.message && <span className="w-full pl-5 text-status-down">{s.message}</span>}
                </li>
              ))}
            </ol>
          )}
          <div className="mt-2 flex flex-wrap gap-3 text-xs">
            <Link to="/templates" className="text-accent hover:underline">{t('nav.templates')}</Link>
            <Link to="/variables" className="text-accent hover:underline">{t('nav.variables')}</Link>
            <Link to="/sites" className="text-accent hover:underline">{t('nav.sites')}</Link>
            <Link to="/manage/allocation" className="text-accent hover:underline">
              {t('allocation.title', { defaultValue: 'Address allocation' })}
            </Link>
          </div>
        </div>
      )}

      {/* ── Issues ────────────────────────────────────────────────────────── */}
      {report.issues.length > 0 && (
        <section className={CARD}>
          {SEVERITIES.map((sev) => {
            const byPart = grouped.get(sev)!;
            if (byPart.size === 0) return null;
            return (
              <div key={sev} className="mb-3 last:mb-0">
                <h4 className="mb-1 text-xs font-semibold uppercase tracking-wider text-text-muted">
                  {sev === 'error'
                    ? t('quickSetup.report.errors', { defaultValue: 'Errors' })
                    : sev === 'warning'
                      ? t('quickSetup.report.warnings', { defaultValue: 'Warnings' })
                      : t('quickSetup.report.infos', { defaultValue: 'Information' })}
                </h4>
                {PART_ORDER.filter((p) => byPart.has(p)).map((p) => (
                  <div key={p} className="mb-1.5">
                    <p className="text-[11px] text-text-muted">{partLabel(t, p)}</p>
                    <ul className="space-y-0.5">
                      {byPart.get(p)!.map((i, k) => (
                        <li key={k} className="flex items-start gap-1.5 text-xs text-text-primary">
                          <SeverityIcon severity={sev} />
                          <span className="whitespace-pre-wrap break-words">{issueText(t, i)}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            );
          })}
        </section>
      )}

      {/* ── Requirements ──────────────────────────────────────────────────── */}
      <section className={CARD}>
        <h4 className="mb-1 text-sm font-semibold text-text-primary">
          {t('quickSetup.report.requirements', { defaultValue: 'Required variables' })}
        </h4>
        {report.requirements.complete && missingLevels.every((l) => !l.checked) ? (
          <p className="text-xs text-emerald-400">
            {t('quickSetup.report.complete', { defaultValue: 'Every required variable has a value, a default or a source.' })}
          </p>
        ) : (
          <p className="mb-1 text-xs text-amber-400">
            {t('quickSetup.report.incomplete', {
              defaultValue: 'Some required variables have no value yet. The render and the bench will refuse until they do.',
            })}
          </p>
        )}
        {missingLevels.length > 0 && (
          <table className="mt-1 w-full text-left text-xs">
            <thead className="text-text-muted">
              <tr>
                <th className="py-1 pr-2 font-medium">{t('quickSetup.report.level', { defaultValue: 'Level' })}</th>
                <th className="py-1 font-medium">{t('quickSetup.report.missing', { defaultValue: 'Missing' })}</th>
              </tr>
            </thead>
            <tbody>
              {missingLevels.map((l) => (
                <tr key={l.level} className="border-t border-border align-top">
                  <td className="py-1 pr-2 text-text-secondary">
                    {levelLabel(t, l.level)}
                    {!l.checked && (
                      <span className="block text-[10px] text-text-muted">
                        {t('quickSetup.report.unchecked', { defaultValue: 'not checked here' })}
                      </span>
                    )}
                  </td>
                  <td className="py-1">
                    {l.missing.map((m) => (
                      <div key={m.key}>
                        <code className="text-text-primary">{m.key}</code>
                        {m.sitesTotal !== undefined && (
                          <span className="ml-1 text-text-muted">
                            {t('quickSetup.report.sites', {
                              defaultValue: '{{count}} site(s): {{codes}}',
                              count: m.sitesTotal,
                              codes: (m.sites ?? []).slice(0, 10).join(', ') + (m.sitesTotal > 10 ? '…' : ''),
                            })}
                          </span>
                        )}
                        {m.reason !== 'not_set' && (
                          <span className="ml-1 text-text-muted">
                            ({m.reason === 'policy_refused'
                              ? t('quickSetup.live.policyRefused', { defaultValue: 'the rule in this setup is refused — see its errors' })
                              : m.reason === 'no_policy'
                              ? t('quickSetup.live.noPolicy', { defaultValue: 'no allocation rule' })
                              : t('quickSetup.live.notSupplied', { defaultValue: 'not supplied by the rule' })})
                          </span>
                        )}
                      </div>
                    ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {/* ── Template ──────────────────────────────────────────────────────── */}
      {report.template && (
        <section className={CARD}>
          <h4 className="mb-2 text-sm font-semibold text-text-primary">{partLabel(t, 'template')}</h4>
          {templateReport && (
            <ul className="space-y-2 text-xs">
              {templateReport.items.map((item) => (
                <li key={item.index}>
                  <div className="flex flex-wrap items-baseline gap-2">
                    <span className="font-medium text-text-primary">{item.name || '—'}</span>
                    {item.brand && <span className="text-text-muted">{item.brand}</span>}
                    <span className="text-text-secondary">
                      {item.action === 'create'
                        ? t('templates.import.actionCreate', { defaultValue: 'New template, draft revision 1' })
                        : item.action === 'new-revision'
                          ? t('templates.import.actionRevision', { defaultValue: 'New draft revision of the existing template of the same name' })
                          : t('templates.import.unchanged', { defaultValue: 'Unchanged — not imported' })}
                    </span>
                    {item.outcome && (
                      <span className={cn(item.outcome === 'created' ? 'text-emerald-400' : item.outcome === 'unchanged' ? 'text-text-muted' : 'text-status-down')}>
                        {t(`quickSetup.report.templateOutcome.${item.outcome}`, { defaultValue: item.outcome })}
                        {item.revision !== null ? ` (r${item.revision})` : ''}
                      </span>
                    )}
                  </div>
                  {item.errors.length > 0 && (
                    <ul className="mt-0.5 space-y-0.5 text-[11px] text-status-down">
                      {item.errors.slice(0, 25).map((e, i) => (
                        <li key={i}>
                          <span className="font-medium">{issueWhere(t, e)}</span>
                          {' — '}
                          <span className="text-text-secondary">{e.message}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                  {item.warnings.length > 0 && (
                    <ul className="mt-0.5 space-y-0.5 text-[11px] text-amber-400">
                      {item.warnings.map((w) => <li key={w}>{w}</li>)}
                    </ul>
                  )}
                </li>
              ))}
            </ul>
          )}
          {report.template.publish.requested && (
            <div className="mt-3 text-xs">
              <p className="mb-0.5 text-text-muted">{t('quickSetup.report.publishPlan', { defaultValue: 'Publication' })}</p>
              <ul className="space-y-0.5">
                {report.template.publish.plan.map((p) => {
                  const result = report.template?.publish.results?.find((r) => r.index === p.index);
                  return (
                    <li key={p.index} className="flex flex-wrap items-baseline gap-2">
                      <span className="text-text-primary">{p.name}</span>
                      <span className="text-text-secondary">
                        {t(`quickSetup.report.publish.${p.action}`, { defaultValue: p.action })}
                        {p.revision !== null ? ` (r${p.revision})` : ''}
                      </span>
                      {result && (
                        <span className={result.status === 'published' ? 'text-emerald-400' : 'text-status-down'}>
                          {result.status === 'published'
                            ? t('quickSetup.report.published', { defaultValue: 'published r{{n}}', n: result.revision })
                            : result.message ?? result.status}
                        </span>
                      )}
                    </li>
                  );
                })}
              </ul>
            </div>
          )}
        </section>
      )}

      {/* ── Variables ─────────────────────────────────────────────────────── */}
      {report.variables && report.variables.rows.length > 0 && (
        <section className={CARD}>
          <h4 className="mb-2 text-sm font-semibold text-text-primary">
            {t('quickSetup.report.variablesRows', { defaultValue: 'Variable rows' })}
          </h4>
          <div className="max-h-80 overflow-auto">
            <table className="w-full text-left text-xs">
              <thead className="sticky top-0 bg-bg-secondary text-text-muted">
                <tr>
                  <th className="px-1 py-1 font-medium">#</th>
                  <th className="px-1 py-1 font-medium">{t('quickSetup.report.level', { defaultValue: 'Level' })}</th>
                  <th className="px-1 py-1 font-medium">{t('quickSetup.designer.extra.scopeRef', { defaultValue: 'Site code' })}</th>
                  <th className="px-1 py-1 font-medium">{t('quickSetup.designer.extra.key', { defaultValue: 'Key' })}</th>
                  <th className="px-1 py-1 font-medium">{t('quickSetup.report.actionCol', { defaultValue: 'What happens' })}</th>
                </tr>
              </thead>
              <tbody>
                {report.variables.rows.map((r) => (
                  <tr key={r.index} className="border-t border-border">
                    <td className="px-1 py-1 font-mono text-text-muted">{r.line ?? r.index + 1}</td>
                    <td className="px-1 py-1 text-text-secondary">{levelLabel(t, r.level)}</td>
                    <td className="px-1 py-1 font-mono text-text-secondary">{r.scopeRef ?? ''}</td>
                    <td className="px-1 py-1">
                      <code className="text-text-primary">{r.key}</code>
                      {r.secret && (
                        <span
                          className="ml-1 inline-flex items-center gap-0.5 rounded bg-amber-500/15 px-1 text-[10px] text-amber-400"
                          title={r.secretForced ? t('quickSetup.report.secretForced', { defaultValue: 'Made secret by its declaration, or by the secret already stored there' }) : undefined}
                        >
                          <KeyRound size={9} />
                          {t('quickSetup.report.secret', { defaultValue: 'secret' })}
                          {r.secretForced ? '*' : ''}
                        </span>
                      )}
                    </td>
                    <td className="px-1 py-1">
                      <span
                        className={cn(
                          'rounded px-1.5 py-0.5 text-[10px] font-medium uppercase',
                          r.action === 'invalid' ? 'bg-status-down/15 text-status-down'
                            : r.action === 'create' ? 'bg-emerald-500/15 text-emerald-400'
                              : r.action === 'update' || r.action === 'set_secret' ? 'bg-accent/15 text-accent'
                                : 'bg-bg-tertiary text-text-muted',
                        )}
                      >
                        {actionLabel(r.action)}
                      </span>
                      {r.applied === true && <CheckCircle2 size={12} className="ml-1 inline text-emerald-400" />}
                      {r.applied === false && !report.dryRun && r.action !== 'unchanged' && r.action !== 'keep' && (
                        <MinusCircle size={12} className="ml-1 inline text-text-muted" />
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* ── Allocation rule ───────────────────────────────────────────────── */}
      {report.allocationPolicy && (
        <section className={CARD}>
          <h4 className="mb-1 text-sm font-semibold text-text-primary">{partLabel(t, 'allocationPolicy')}</h4>
          {report.allocationPolicy.ok ? (
            <p className="flex items-center gap-1.5 text-xs text-emerald-400">
              <CheckCircle2 size={13} />
              {report.dryRun
                ? t('quickSetup.report.policyOk', { defaultValue: 'The rule is valid.' })
                : t('quickSetup.report.policySaved', { defaultValue: 'The rule is saved.' })}
            </p>
          ) : report.allocationPolicy.error ? (
            <div className="text-xs text-status-down">
              <p>{report.allocationPolicy.error.message}</p>
              {Object.entries(report.allocationPolicy.error.details).map(([field, msgs]) => (
                <p key={field}>
                  <code>{field}</code>: {msgs.join(' ')}
                </p>
              ))}
            </div>
          ) : (
            <p className="text-xs text-status-down">
              {t('quickSetup.report.policyRefs', { defaultValue: 'A pool or the concentrator could not be found: see the errors above.' })}
            </p>
          )}
        </section>
      )}

      {/* ── Sites ─────────────────────────────────────────────────────────── */}
      {sitesResult && (
        <section className={CARD}>
          <h4 className="mb-1 text-sm font-semibold text-text-primary">{partLabel(t, 'sites')}</h4>
          <p className="text-xs text-text-primary">
            {sitesResult.dryRun
              ? t('sites.import.summary', {
                defaultValue: '{{rows}} rows: {{create}} to create, {{update}} to update, {{skip}} unchanged, {{rejected}} rejected',
                ...sitesResult.summary,
              })
              : t('sites.import.appliedSummary', { defaultValue: '{{applied}} rows written, {{rejected}} rejected', ...sitesResult.summary })}
            {!sitesResult.dryRun && sitesResult.allocate && (
              <> · {t('sites.import.allocSummary', {
                defaultValue: '{{allocated}} allocated, {{failed}} allocation failures',
                allocated: sitesResult.summary.allocated,
                failed: sitesResult.summary.allocationFailed,
              })}</>
            )}
          </p>
          {sitesResult.rows.some((r) => r.errors.length > 0) && (
            <ul className="mt-1 max-h-48 space-y-0.5 overflow-auto text-xs text-status-down">
              {sitesResult.rows.filter((r) => r.errors.length > 0).map((r) => (
                <li key={`${r.line}-${r.code}`}>
                  <span className="font-mono">{t('quickSetup.where.line', { defaultValue: 'line {{n}}', n: r.line })} · {r.code || '—'}</span>
                  {' — '}
                  {r.errors.join(' ')}
                </li>
              ))}
            </ul>
          )}
          <p className="mt-1 text-[11px] text-text-muted">
            {t('quickSetup.report.sitesInGrid', { defaultValue: 'Each row\'s verdict is also drawn in the grid of the designer.' })}
          </p>
        </section>
      )}

      {report.siteVariables && report.siteVariables.sites.length > 0 && (
        <section className={CARD}>
          <h4 className="mb-1 text-sm font-semibold text-text-primary">{stepLabel(t, 'siteVariables')}</h4>
          <ul className="space-y-0.5 text-xs">
            {report.siteVariables.sites.map((s) => (
              <li key={s.code} className="flex flex-wrap items-baseline gap-2">
                <span className="font-mono text-text-primary">{s.code}</span>
                <span className="font-mono text-text-muted">{s.keys.join(', ')}</span>
                {!report.dryRun && (s.applied
                  ? <CheckCircle2 size={12} className="text-emerald-400" />
                  : <MinusCircle size={12} className="text-text-muted" />)}
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
