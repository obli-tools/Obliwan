import {
  computedSuppliedKeys,
  resolveRequirements,
  type RequirementReport,
  type SetupPart,
  type TenantSetupRequest,
} from '@obliwan/shared';
import { gridProblems, type GridProblem } from './gridModel';
import { policyShape, storedPolicyShape, type StoredPolicy } from './policyModel';
import { FIELD_LEVELS, isBlankRow, type QuickSetupState } from './quickSetupStore';

/**
 * What the page can tell BEFORE asking the server — the live panel's half.
 *
 * The requirement report is computed by `resolveRequirements`, the SAME
 * function the server's check calls, fed with what is on screen: the drafts,
 * the stored values the context returned, the grid, and the rule being set up
 * (or the stored one). It is a preview; the server's check is the verdict, and
 * the panel says so.
 */

type State = Pick<
  QuickSetupState,
  'context' | 'fields' | 'extraRows' | 'sites' | 'policy' | 'selected' | 'variablesProblems' | 'template'
>;

export function effectivePolicyShape(s: State) {
  const stored = (s.context?.policy ?? null) as StoredPolicy | null;
  if (s.selected.allocationPolicy && s.policy) return policyShape(s.policy);
  if (stored) return storedPolicyShape(stored);
  return null;
}

export function liveRequirements(s: State): RequirementReport | null {
  const ctx = s.context;
  if (!ctx) return null;
  const wide = new Set<string>();
  for (const level of FIELD_LEVELS) {
    for (const k of Object.keys(ctx.values[level] ?? {})) wide.add(k);
    if (s.selected.variables) {
      for (const [k, f] of Object.entries(s.fields[level])) if (f.value !== undefined && !f.error) wide.add(k);
    }
  }
  const siteRows = new Map<string, Set<string>>();
  if (s.selected.variables) {
    for (const x of s.extraRows) {
      const level = x.level.trim().toLowerCase();
      if (x.value === undefined || x.key.trim() === '') continue;
      if ((FIELD_LEVELS as readonly string[]).includes(level) && x.scopeRef.trim() === '') wide.add(x.key.trim());
      if (level === 'site' && x.scopeRef.trim() !== '') {
        const code = x.scopeRef.trim();
        siteRows.set(code, new Set([...(siteRows.get(code) ?? []), x.key.trim()]));
      }
    }
  }
  // As the server: the sites a requirement is judged for are the FILE's sites.
  const sites: Array<{ code: string; keys: Set<string> }> = [];
  if (s.selected.sites) {
    const ci = s.sites.header.indexOf('code');
    const varCols = s.sites.header
      .map((h, i) => ({ h, i }))
      .filter((c) => c.h.startsWith('var:'))
      .map((c) => ({ key: c.h.slice(4), i: c.i }));
    for (const r of s.sites.rows) {
      if (isBlankRow(r) || ci < 0) continue;
      const code = (r.cells[ci] ?? '').trim();
      if (code === '') continue;
      const keys = new Set<string>(siteRows.get(code) ?? []);
      for (const c of varCols) if ((r.cells[c.i] ?? '').trim() !== '') keys.add(c.key);
      const existing = ctx.sites.find((x) => x.code === code);
      if (existing) for (const k of Object.keys(existing.values)) keys.add(k);
      sites.push({ code, keys });
    }
  }
  return resolveRequirements({
    declarations: ctx.declarations,
    wide,
    sites,
    computed: computedSuppliedKeys(effectivePolicyShape(s)),
  });
}

export type LocalProblemCode =
  | 'nothingSelected'
  | 'tooLarge'
  | 'fieldErrors'
  | 'variablesFile'
  | 'noTemplateFile'
  | 'sitesEmpty'
  | 'gridRows';

export interface LocalProblem {
  code: LocalProblemCode;
  part: SetupPart | 'setup';
  /** 'check': nothing can be sent; 'apply': a check may run, Apply waits. */
  blocks: 'check' | 'apply' | null;
  params: Record<string, string | number>;
  /** Element ids the panel can scroll to. */
  targets?: Array<{ id: string; label: string }>;
}

export function localProblems(
  s: State,
  built: { request: TenantSetupRequest; size: number; max: number },
): LocalProblem[] {
  const out: LocalProblem[] = [];
  if (Object.keys(built.request.parts).length === 0) {
    out.push({ code: 'nothingSelected', part: 'setup', blocks: 'check', params: {} });
  }
  if (built.size > built.max) {
    out.push({ code: 'tooLarge', part: 'setup', blocks: 'check', params: { size: built.size, max: built.max } });
  }
  if (s.selected.variables) {
    const bad: Array<{ id: string; label: string }> = [];
    for (const level of FIELD_LEVELS) {
      for (const [k, f] of Object.entries(s.fields[level])) {
        if (f.error) bad.push({ id: `qs-field-${level}-${k}`, label: k });
      }
    }
    if (bad.length > 0) {
      out.push({ code: 'fieldErrors', part: 'variables', blocks: 'apply', params: { count: bad.length }, targets: bad });
    }
    if (s.variablesProblems.length > 0) {
      out.push({ code: 'variablesFile', part: 'variables', blocks: null, params: { count: s.variablesProblems.length } });
    }
  }
  if (s.selected.template && s.template.source !== 'file') {
    out.push({ code: 'noTemplateFile', part: 'template', blocks: 'apply', params: {} });
  }
  if (s.selected.sites) {
    const rows = s.sites.rows.filter((r) => !isBlankRow(r));
    if (rows.length === 0) out.push({ code: 'sitesEmpty', part: 'sites', blocks: null, params: {} });
    const problems = gridProblems(s.sites);
    if (problems.size > 0) {
      const counts: Record<GridProblem, number> = { codeMissing: 0, nameMissing: 0, excelCode: 0, duplicateCode: 0 };
      for (const list of problems.values()) for (const p of list) counts[p] += 1;
      out.push({ code: 'gridRows', part: 'sites', blocks: null, params: { count: problems.size, ...counts } });
    }
  }
  return out;
}
