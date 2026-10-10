import type { TFunction } from 'i18next';
import type { SetupIssue, SetupIssueParam } from '@obliwan/shared';
import { levelLabel } from '@/components/templates/labels';

/**
 * A Quick Setup issue, in the reader's language.
 *
 * The server sends `code` + `params` and an English `message` built from the
 * same params; the screen translates `quickSetup.issue.<CODE>` with the params
 * as interpolation values and falls back to the English sentence for a code
 * this build has no key for. The params carry key names, levels, site codes
 * and counts — never a value — so nothing here can echo a secret.
 *
 * Arrays are joined with ", "; a field → messages map (the allocation
 * validator's details) is flattened to "field: message; …"; a level is shown
 * by its label ("Customer", "Platform (all customers)"), not its code; and a
 * row is named by its CSV line when it has one, else by its position.
 */

const LEVEL_PARAMS = new Set(['level', 'declared', 'row', 'declaredLevel']);

function flatten(v: SetupIssueParam): string {
  if (v === null || v === undefined) return '';
  if (Array.isArray(v)) return v.join(', ');
  if (typeof v === 'object') {
    return Object.entries(v)
      .map(([field, messages]) => `${field}: ${messages.join(' ')}`)
      .join('; ');
  }
  return String(v);
}

export function issueParams(t: TFunction, issue: SetupIssue): Record<string, string | number> {
  const out: Record<string, string | number> = {};
  for (const [k, v] of Object.entries(issue.params ?? {})) {
    if (typeof v === 'number') out[k] = v;
    else if (typeof v === 'string' && LEVEL_PARAMS.has(k)) out[k] = levelLabel(t, v);
    else out[k] = flatten(v);
  }
  // `where`: "line 12" for a CSV row, "row 3" for a designer row.
  const line = issue.params?.line;
  const index = issue.params?.index;
  if (typeof line === 'number') {
    out.where = t('quickSetup.where.line', { defaultValue: 'line {{n}}', n: line });
  } else if (typeof index === 'number') {
    out.where = t('quickSetup.where.row', { defaultValue: 'row {{n}}', n: index + 1 });
  } else {
    out.where = '';
  }
  if (issue.code === 'POLICY_REF' && typeof issue.params?.problem === 'string') {
    out.problemText = t(`quickSetup.policyRefProblem.${issue.params.problem}`, {
      defaultValue: issue.params.problem,
    });
  }
  return out;
}

export function issueText(t: TFunction, issue: SetupIssue): string {
  return t(`quickSetup.issue.${issue.code}`, {
    ...issueParams(t, issue),
    defaultValue: issue.message,
  });
}
