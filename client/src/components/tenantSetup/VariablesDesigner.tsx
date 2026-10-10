import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { AlertTriangle, Calculator, Plus, Search, Trash2, Wrench } from 'lucide-react';
import type { DeclaredKeyView, SetupIssue, StoredValueView, TenantSetupReport } from '@obliwan/shared';
import { ALLOCATOR_COMPUTED_KEYS, computedSuppliedKeys } from '@obliwan/shared';
import { Button } from '@/components/common/Button';
import { cn } from '@/utils/cn';
import { levelLabel } from '@/components/templates/labels';
import { ValueField } from './ValueField';
import { INPUT, CARD } from './ui';
import { issueText } from './issueText';
import {
  FIELD_LEVELS, declMap, extraRowSecrecy, retypeExtraRow, useQuickSetupStore,
  type ExtraRowDraft, type ExtraRowSecrecy, type FieldLevel,
} from './quickSetupStore';
import {
  EMPTY_POLICY, MAX_DERIVED, newId, policyDraftFromStored, policyShape, storedPolicyShape, type StoredPolicy,
} from './policyModel';

/**
 * Designer step 2 — the variables FORM, generated from the reference
 * templates' `var_schema` and grouped by the level each key is declared at.
 *
 * Only instance / global / tenant keys are typed here. The other levels are
 * shown read-only with WHERE their value comes from, because a required key
 * nobody can see is the commonest reason a first render refuses: site keys are
 * typed per site in the grid (step 4), group and router keys on the Variables
 * page, computed keys come from the allocation rule (step 3) and bench keys are
 * typed at the bench for one box.
 */

type GroupId = FieldLevel | 'site' | 'groupDevice' | 'computed' | 'bench';
const GROUPS: GroupId[] = ['instance', 'global', 'tenant', 'site', 'groupDevice', 'computed', 'bench'];

function groupOf(d: DeclaredKeyView): GroupId {
  switch (d.level) {
    case 'instance':
    case 'global':
    case 'tenant':
    case 'site':
    case 'computed':
    case 'bench':
      return d.level;
    default:
      return 'groupDevice';
  }
}

/** Where a level's values come from, in words. */
function groupTitle(t: TFunction, g: GroupId): string {
  switch (g) {
    case 'groupDevice':
      return t('quickSetup.designer.levels.groupDevice', { defaultValue: 'Group / router' });
    default:
      return t(`quickSetup.designer.levels.${g}`, { defaultValue: levelLabel(t, g) });
  }
}

function groupHint(t: TFunction, g: GroupId): string {
  switch (g) {
    case 'instance':
      return t('quickSetup.designer.levels.instanceHint', { defaultValue: 'Affects every workspace of the installation.' });
    case 'global':
      return t('quickSetup.designer.levels.globalHint', { defaultValue: "This customer's widest level." });
    case 'tenant':
      return t('quickSetup.designer.levels.tenantHint', { defaultValue: 'Set once for this customer.' });
    case 'site':
      return t('quickSetup.designer.levels.siteHint', { defaultValue: 'Set per site, in the sites grid (step 4).' });
    case 'groupDevice':
      return t('quickSetup.designer.levels.groupDeviceHint', {
        defaultValue: 'Set per group or per router, on the Variables page: not part of a quick setup.',
      });
    case 'computed':
      return t('quickSetup.designer.levels.computedHint', {
        defaultValue: 'Never typed: supplied at render by the allocation rule (step 3).',
      });
    case 'bench':
    default:
      return t('quickSetup.designer.levels.benchHint', { defaultValue: 'Typed at the bench for one box; never stored.' });
  }
}

function allocatorLabel(t: TFunction, key: string): string | null {
  switch (key) {
    case 'site_code': return t('quickSetup.designer.computed.site_code', { defaultValue: 'the site code' });
    case 'ppp_username': return t('quickSetup.designer.computed.ppp_username', { defaultValue: 'the allocated PPP login' });
    case 'tunnel_ip': return t('quickSetup.designer.computed.tunnel_ip', { defaultValue: 'the allocated tunnel address' });
    case 'ppp_password':
      return t('quickSetup.designer.computed.ppp_password', {
        defaultValue: 'the PPP password (instance ppp_password, or per site)',
      });
    case 'lan_subnet': return t('quickSetup.designer.computed.lan_subnet', { defaultValue: 'the allocated LAN subnet' });
    case 'system_identity':
      return t('quickSetup.designer.computed.system_identity', { defaultValue: 'the computed system identity' });
    default: return null;
  }
}

/** The server's verdicts that belong to one designer field. */
function fieldIssues(report: TenantSetupReport | undefined, level: string, key: string): SetupIssue[] {
  if (!report) return [];
  const rows = report.variables?.rows ?? [];
  return report.issues.filter((i) => {
    if (i.part !== 'variables' || i.severity !== 'error' || i.params.key !== key) return false;
    if (typeof i.params.index === 'number') {
      const row = rows.find((r) => r.index === i.params.index);
      return row ? row.level === level && row.scopeRef === null : false;
    }
    return true;
  });
}

const EXTRA_LEVELS = ['instance', 'global', 'tenant', 'site'];

export function VariablesDesigner() {
  const { t } = useTranslation();
  const context = useQuickSetupStore((s) => s.context);
  const fields = useQuickSetupStore((s) => s.fields);
  const extraRows = useQuickSetupStore((s) => s.extraRows);
  const variablesProblems = useQuickSetupStore((s) => s.variablesProblems);
  const policy = useQuickSetupStore((s) => s.policy);
  const policySelected = useQuickSetupStore((s) => s.selected.allocationPolicy);
  const lastCheck = useQuickSetupStore((s) => s.lastCheck);
  const setField = useQuickSetupStore((s) => s.setField);
  const resetField = useQuickSetupStore((s) => s.resetField);
  const setExtraRows = useQuickSetupStore((s) => s.setExtraRows);
  const setPolicy = useQuickSetupStore((s) => s.setPolicy);
  const markEdited = useQuickSetupStore((s) => s.markEdited);
  const [search, setSearch] = useState('');

  const declarations = useMemo(() => context?.declarations ?? [], [context]);
  const declIndex = useMemo(() => declMap(declarations), [declarations]);
  const storedPolicy = (context?.policy ?? null) as StoredPolicy | null;

  // The rule the computed keys come from: the one being set up when the part
  // is selected, else the stored one.
  const derivedExpr = useMemo(() => {
    const out = new Map<string, string>();
    if (policySelected && policy) {
      for (const r of policy.derived) if (r.key.trim()) out.set(r.key.trim(), r.expr);
    } else if (storedPolicy) {
      for (const [k, v] of Object.entries(storedPolicy.derived ?? {})) out.set(k, v);
    }
    return out;
  }, [policy, policySelected, storedPolicy]);
  const supplied = useMemo(
    () => computedSuppliedKeys(
      policySelected && policy ? policyShape(policy) : storedPolicy ? storedPolicyShape(storedPolicy) : null,
    ),
    [policy, policySelected, storedPolicy],
  );

  const grouped = useMemo(() => {
    const q = search.trim().toLowerCase();
    const out = new Map<GroupId, DeclaredKeyView[]>(GROUPS.map((g) => [g, []]));
    for (const d of declarations) {
      if (q && !d.key.toLowerCase().includes(q) && !(d.label ?? '').toLowerCase().includes(q)) continue;
      out.get(groupOf(d))!.push(d);
    }
    for (const list of out.values()) list.sort((a, b) => Number(b.required) - Number(a.required) || a.key.localeCompare(b.key));
    return out;
  }, [declarations, search]);

  if (!context) return null;

  const valuesAt = (level: FieldLevel): Record<string, StoredValueView> => context.values[level] ?? {};
  const inheritedFor = (level: FieldLevel, key: string) => {
    const wider: FieldLevel[] = level === 'tenant' ? ['global', 'instance'] : level === 'global' ? ['instance'] : [];
    return wider
      .filter((l) => valuesAt(l)[key] !== undefined)
      .map((l) => ({ level: l, value: valuesAt(l)[key] }));
  };

  const addDerived = (key: string) => {
    const base = policy ?? (storedPolicy ? policyDraftFromStored(storedPolicy) : EMPTY_POLICY);
    if (base.derived.some((r) => r.key.trim() === key) || base.derived.length >= MAX_DERIVED) return;
    setPolicy({ ...base, derived: [...base.derived, { id: newId('d'), key, expr: '' }] });
    markEdited('allocationPolicy');
    window.setTimeout(() => document.getElementById(`qs-derived-${key}`)?.focus(), 50);
  };

  const updateExtra = (id: string, patch: Partial<ExtraRowDraft>) => {
    setExtraRows(extraRows.map((r) => (r.id === id ? retypeExtraRow({ ...r, ...patch }, declarations) : r)));
  };

  return (
    <div className="space-y-4">
      {declarations.length === 0 && (
        <p className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-400">
          {t('quickSetup.designer.noDeclarations', {
            defaultValue:
              'No template declares any variable yet: pick or import a template in step 1 to generate the form. Variables from a file are listed under "Other variables".',
          })}
        </p>
      )}

      {declarations.length > 0 && (
        <div className="relative max-w-sm">
          <Search size={14} className="absolute left-2.5 top-2.5 text-text-muted" />
          <input
            className={cn(INPUT, 'pl-8')}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t('quickSetup.designer.search', { defaultValue: 'Find a variable…' })}
          />
        </div>
      )}

      {GROUPS.map((g) => {
        const list = grouped.get(g) ?? [];
        if (list.length === 0) return null;
        const editable = (FIELD_LEVELS as readonly string[]).includes(g);
        return (
          <section key={g} className={CARD}>
            <header className="mb-3">
              <h3 className="text-sm font-semibold text-text-primary">
                {groupTitle(t, g)}
                <span className="ml-2 text-xs font-normal text-text-muted">({list.length})</span>
              </h3>
              <p className="text-xs text-text-muted">{groupHint(t, g)}</p>
              {g === 'instance' && (
                <p className="mt-2 flex items-start gap-1.5 rounded-md border border-amber-500/50 bg-amber-500/10 px-2 py-1.5 text-xs text-amber-400">
                  <AlertTriangle size={13} className="mt-0.5 shrink-0" />
                  {t('quickSetup.designer.instanceBanner', {
                    defaultValue: 'A value set here applies to EVERY workspace of the installation, not only this one.',
                  })}
                </p>
              )}
            </header>

            {editable ? (
              <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
                {list.map((d) => {
                  const level = g as FieldLevel;
                  return (
                    <div key={d.key} id={`qs-field-${level}-${d.key}`}>
                      <ValueField
                        id={`qs-input-${level}-${d.key}`}
                        decl={d}
                        level={level}
                        draft={fields[level][d.key]}
                        stored={valuesAt(level)[d.key]}
                        inherited={inheritedFor(level, d.key)}
                        serverErrors={fieldIssues(lastCheck?.report, level, d.key).map((i) => issueText(t, i))}
                        onChange={(text, asJson) => setField(level, d.key, text, asJson)}
                        onReset={() => resetField(level, d.key)}
                      />
                    </div>
                  );
                })}
              </div>
            ) : (
              <ul className="divide-y divide-border text-xs">
                {list.map((d) => {
                  const allocator = (ALLOCATOR_COMPUTED_KEYS as readonly string[]).includes(d.key)
                    || d.key === 'lan_subnet' || d.key === 'system_identity'
                    ? allocatorLabel(t, d.key)
                    : null;
                  const expr = derivedExpr.get(d.key);
                  const missingComputed = g === 'computed' && d.required && (supplied === null || !supplied.has(d.key));
                  return (
                    <li key={d.key} id={`qs-field-${g}-${d.key}`} className="flex flex-wrap items-baseline gap-x-2 gap-y-1 py-1.5">
                      <span className="font-medium text-text-primary">{d.label ?? d.key}</span>
                      <code className="text-[11px] text-text-muted">{d.key}</code>
                      {d.required && (
                        <span className="rounded bg-status-down/15 px-1.5 text-[10px] font-medium uppercase text-status-down">
                          {t('quickSetup.designer.field.required', { defaultValue: 'required' })}
                        </span>
                      )}
                      <span className="ml-auto text-text-muted">
                        {g === 'computed' ? (
                          missingComputed ? (
                            <span className="inline-flex flex-wrap items-center gap-2 text-status-down">
                              {t('quickSetup.designer.field.computedMissing', {
                                defaultValue: 'Not supplied by the allocation rule',
                              })}
                              {!allocator && (
                                <Button type="button" size="sm" variant="secondary" onClick={() => addDerived(d.key)}>
                                  <Plus size={12} className="mr-1" />
                                  {t('quickSetup.designer.field.addDerived', { defaultValue: 'Add a derived value' })}
                                </Button>
                              )}
                            </span>
                          ) : allocator ? (
                            <span className="inline-flex items-center gap-1">
                              <Calculator size={12} />
                              {t('quickSetup.designer.field.computedAllocator', {
                                defaultValue: 'Allocator: {{what}}', what: allocator,
                              })}
                            </span>
                          ) : expr !== undefined ? (
                            <span className="inline-flex items-center gap-1">
                              <Calculator size={12} />
                              {t('quickSetup.designer.field.computedDerived', { defaultValue: 'Derived value' })}{' '}
                              <code className="text-text-secondary">{expr || '…'}</code>
                            </span>
                          ) : (
                            t('quickSetup.designer.field.computedOptional', { defaultValue: 'Computed at render' })
                          )
                        ) : g === 'bench' ? (
                          <span className="inline-flex items-center gap-1">
                            <Wrench size={12} />
                            {t('quickSetup.designer.field.benchTyped', { defaultValue: 'Typed at the bench for one box' })}
                          </span>
                        ) : g === 'site' ? (
                          t('quickSetup.designer.field.setPerSite', { defaultValue: 'Set per site in the grid (step 4)' })
                        ) : (
                          t('quickSetup.designer.field.setElsewhere', { defaultValue: 'Edited on the Variables page' })
                        )}
                      </span>
                    </li>
                  );
                })}
              </ul>
            )}
          </section>
        );
      })}

      <ExtraRowsEditor
        rows={extraRows}
        secrecyOf={(r) => extraRowSecrecy(r, context, declIndex)}
        problems={variablesProblems}
        onChange={(rows) => setExtraRows(rows)}
        onUpdate={updateExtra}
      />
    </div>
  );
}

function ExtraRowsEditor({
  rows,
  secrecyOf,
  problems,
  onChange,
  onUpdate,
}: {
  rows: ExtraRowDraft[];
  /** Masked by its own flag, its declaration, or a secret already stored
   *  there — never by `r.secret` alone (see `extraRowSecrecy`). */
  secrecyOf: (r: ExtraRowDraft) => ExtraRowSecrecy;
  problems: Array<{ line: number; code: string; column?: string; message?: string }>;
  onChange: (rows: ExtraRowDraft[]) => void;
  onUpdate: (id: string, patch: Partial<ExtraRowDraft>) => void;
}) {
  const { t } = useTranslation();
  const add = () =>
    onChange([...rows, { id: newId('x'), level: 'tenant', scopeRef: '', key: '', text: '', value: undefined, secret: false }]);
  return (
    <section className={CARD}>
      <header className="mb-2 flex items-center gap-2">
        <h3 className="flex-1 text-sm font-semibold text-text-primary">
          {t('quickSetup.designer.extra.title', { defaultValue: 'Other variables' })}
          <span className="ml-2 text-xs font-normal text-text-muted">({rows.length})</span>
        </h3>
        <Button type="button" size="sm" variant="secondary" onClick={add}>
          <Plus size={13} className="mr-1" />
          {t('quickSetup.designer.extra.add', { defaultValue: 'Add a row' })}
        </Button>
      </header>
      <p className="mb-2 text-xs text-text-muted">
        {t('quickSetup.designer.extra.hint', {
          defaultValue:
            'Site rows, keys no reference template declares, and rows set at another level than declared. Sent as they are: the check says what it thinks of each.',
        })}
      </p>
      {problems.length > 0 && (
        <ul className="mb-2 space-y-0.5 rounded-md border border-status-down/40 bg-status-down/10 p-2 text-xs text-status-down">
          {problems.map((p, i) => (
            <li key={i}>
              {p.message
                ?? t('quickSetup.files.parseError', {
                  defaultValue: 'Line {{line}}: {{problem}}',
                  line: p.line,
                  problem: t(`quickSetup.csvProblem.${p.code}`, { defaultValue: p.code, column: p.column ?? '' }),
                })}
            </li>
          ))}
        </ul>
      )}
      {rows.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] text-left text-xs">
            <thead className="text-text-muted">
              <tr>
                <th className="px-1 py-1 font-medium">{t('quickSetup.designer.extra.level', { defaultValue: 'Level' })}</th>
                <th className="px-1 py-1 font-medium">{t('quickSetup.designer.extra.scopeRef', { defaultValue: 'Site code' })}</th>
                <th className="px-1 py-1 font-medium">{t('quickSetup.designer.extra.key', { defaultValue: 'Key' })}</th>
                <th className="px-1 py-1 font-medium">{t('quickSetup.designer.extra.value', { defaultValue: 'Value' })}</th>
                <th className="px-1 py-1 font-medium">{t('quickSetup.designer.extra.secret', { defaultValue: 'Secret' })}</th>
                <th className="px-1 py-1" />
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => {
                const secrecy = secrecyOf(r);
                return (
                <tr key={r.id} className="border-t border-border align-top">
                  <td className="w-32 px-1 py-1">
                    <select className={cn(INPUT, 'px-2 py-1 text-xs')} value={r.level} onChange={(e) => onUpdate(r.id, { level: e.target.value })}>
                      {!EXTRA_LEVELS.includes(r.level) && <option value={r.level}>{r.level || '—'}</option>}
                      {EXTRA_LEVELS.map((l) => <option key={l} value={l}>{levelLabel(t, l)}</option>)}
                    </select>
                    {r.line !== undefined && (
                      <div className="mt-0.5 text-[10px] text-text-muted">
                        {t('quickSetup.where.line', { defaultValue: 'line {{n}}', n: r.line })}
                      </div>
                    )}
                  </td>
                  <td className="w-28 px-1 py-1">
                    <input
                      className={cn(INPUT, 'px-2 py-1 font-mono text-xs')}
                      value={r.scopeRef}
                      disabled={r.level !== 'site' && r.scopeRef === ''}
                      onChange={(e) => onUpdate(r.id, { scopeRef: e.target.value })}
                    />
                  </td>
                  <td className="w-48 px-1 py-1">
                    <input className={cn(INPUT, 'px-2 py-1 font-mono text-xs')} value={r.key} onChange={(e) => onUpdate(r.id, { key: e.target.value })} />
                  </td>
                  <td className="px-1 py-1">
                    <input
                      type={secrecy.masked ? 'password' : 'text'}
                      autoComplete={secrecy.masked ? 'new-password' : 'off'}
                      className={cn(INPUT, 'px-2 py-1 font-mono text-xs')}
                      value={r.text}
                      placeholder={
                        secrecy.masked
                          ? t('quickSetup.designer.field.secretKeep', { defaultValue: 'Leave empty to keep the stored secret' })
                          : t('quickSetup.designer.extra.emptyKeeps', { defaultValue: 'empty = keep' })
                      }
                      onChange={(e) => onUpdate(r.id, { text: e.target.value })}
                    />
                  </td>
                  <td className="w-16 px-1 py-1 text-center">
                    <input
                      type="checkbox"
                      checked={secrecy.masked}
                      disabled={secrecy.forcedBy !== null}
                      title={
                        secrecy.forcedBy === 'declaration'
                          ? t('quickSetup.designer.extra.secretByDeclaration', { defaultValue: 'Declared secret by a template' })
                          : secrecy.forcedBy === 'stored'
                            ? t('quickSetup.designer.extra.secretByStored', {
                              defaultValue: 'Already stored as a secret here: a quick setup never writes it in clear',
                            })
                            : undefined
                      }
                      onChange={(e) => onUpdate(r.id, { secret: e.target.checked })}
                    />
                  </td>
                  <td className="w-8 px-1 py-1">
                    <button
                      type="button"
                      onClick={() => onChange(rows.filter((x) => x.id !== r.id))}
                      className="rounded p-1 text-text-muted hover:text-status-down"
                      aria-label={t('quickSetup.designer.extra.remove', { defaultValue: 'Remove' })}
                    >
                      <Trash2 size={13} />
                    </button>
                  </td>
                </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
