/**
 * Quick Setup Tenant — one finding of the check, built from its code and its
 * params. The client translates `quickSetup.issue.<code>` with the same
 * params; `message` is the English fallback, built HERE from the params and
 * nothing else, so a sentence can never carry more than the params do — and
 * the params carry key names, levels, site codes, template names and counts,
 * never a value (a secret's least of all).
 *
 * The embedded reports of the reused services (the template ImportReport, the
 * SiteImportResult, an AllocationError's details) keep their own English
 * sentences, verbatim: they are value-free by their own contracts. This does
 * not settle the project-wide question of server-side message localisation;
 * it is local to this feature.
 */

import {
  SETUP_ISSUE_SEVERITY,
  type SetupIssue,
  type SetupIssueCode,
  type SetupIssueParam,
  type SetupPart,
} from '@obliwan/shared';

type Params = Record<string, SetupIssueParam>;

const str = (v: SetupIssueParam | undefined): string => {
  if (v === null || v === undefined) return '';
  if (Array.isArray(v)) return v.join(', ');
  if (typeof v === 'object') return Object.keys(v).join(', ');
  return String(v);
};

/** The allocation validator's field → messages map, appended as " — field: message; …". */
const fieldsText = (v: SetupIssueParam | undefined): string => {
  if (v === null || v === undefined || typeof v !== 'object' || Array.isArray(v)) return '';
  const parts = Object.entries(v).map(([field, msgs]) => `${field}: ${([] as string[]).concat(msgs as string[]).join(' ')}`);
  return parts.length > 0 ? ` — ${parts.join('; ')}` : '';
};

/** "row 12" when the row came from a CSV line, "row #3" otherwise. */
const rowRef = (p: Params): string =>
  typeof p.line === 'number' ? `line ${p.line}` : `row #${Number(p.index ?? 0) + 1}`;

const POLICY_REF_PROBLEMS: Record<string, string> = {
  unknown: 'matches nothing this workspace may use',
  ambiguous: 'matches several entries; use the id',
  wrongPurpose: 'is a pool of the wrong purpose for this rule',
  mismatch: 'does not designate the same entry as the id given with it',
};

const MESSAGES: Record<SetupIssueCode, (p: Params) => string> = {
  VAR_LEVEL_UNSUPPORTED: (p) =>
    `${rowRef(p)}: level "${str(p.level)}" cannot be set here (instance, global, tenant or site; ` +
    'group and device values are edited on the Variables page)',
  VAR_ROW_INVALID: (p) => `${rowRef(p)}: ${str(p.field)}: ${str(p.message)}`,
  VAR_SCOPE_REF_REQUIRED: (p) => `${rowRef(p)}: a site row needs the site code in scope_ref`,
  VAR_SCOPE_REF_FORBIDDEN: (p) => `${rowRef(p)}: scope_ref is only read for level site (this row is ${str(p.level)})`,
  VAR_SITE_UNKNOWN: (p) => `${rowRef(p)}: no site "${str(p.scopeRef)}" in this workspace or in the sites file`,
  VAR_SITE_ROW_REJECTED: (p) => `${rowRef(p)}: the sites file refuses site "${str(p.scopeRef)}"`,
  VAR_DUPLICATE: (p) =>
    `${rowRef(p)}: ${str(p.key)} is set twice at ${str(p.level)}` +
    `${p.scopeRef ? ` for site ${str(p.scopeRef)}` : ''} (first on row #${Number(p.firstIndex ?? 0) + 1})`,
  VAR_SITE_DUP_WITH_CSV: (p) =>
    `${rowRef(p)}: ${str(p.key)} for site ${str(p.scopeRef)} is also set by the sites file (var:${str(p.key)})`,
  VAR_TYPE: (p) => `${str(p.key)}: ${str(p.reasons)} — declared by ${str(p.declaredBy)}`,
  VAR_RENDER_TIME_KEY: (p) =>
    `${str(p.key)} is declared ${str(p.level)}: it is supplied at render time, and a stored value would be discarded`,
  VAR_SECRET_NOT_DECLARED: (p) =>
    `${str(p.key)} is marked secret but ${str(p.declaredBy)} does not declare it secret: every render would refuse it.`,
  VAR_SECRECY_CONFLICT: (p) =>
    `${str(p.key)} is declared secret by some templates and not by others (${str(p.declaredBy)}): ` +
    'a template author must settle it before a value is stored',
  VAR_SECRET_DOWNGRADE: (p) =>
    `${rowRef(p)}: ${str(p.key)} is stored as a secret at the ${str(p.level)} level and ${str(p.declaredBy)} ` +
    'declares it clear: a quick setup never moves a secret to the clear column. Delete the stored value on the ' +
    'Variables page first, then run the setup again.',
  INSTANCE_NOT_ACKNOWLEDGED: (p) =>
    `${str(p.count)} instance variable(s) apply to every workspace of the installation: acknowledge it to apply`,
  TEMPLATE_FORMAT: (p) => str(p.message),
  TEMPLATE_ENTRY_INVALID: (p) =>
    `template entry #${Number(p.index ?? 0) + 1} "${str(p.name)}" has ${str(p.count)} error(s)`,
  PUBLISH_DEPENDENCY: (p) => `${str(p.name)} could not be published: ${str(p.message)}`,
  REFERENCE_REVISION_NOT_FOUND: (p) =>
    `template revision ${str(p.revisionId)} does not exist in this workspace or in the library`,
  POLICY_FIELD_UNKNOWN: (p) => `the allocation rule has an unknown field "${str(p.field)}"`,
  POLICY_REF: (p) =>
    `${str(p.field)}: "${str(p.ref)}" ${POLICY_REF_PROBLEMS[str(p.problem)] ?? 'cannot be resolved'}`,
  POLICY_INVALID: (p) => `${str(p.message)}${fieldsText(p.details)}`,
  SITES_FILE: (p) => `the sites file cannot be read: ${Array.isArray(p.problems) ? p.problems.join('; ') : ''}`,
  SITES_ROWS_REJECTED: (p) => `${str(p.count)} row(s) of the sites file are refused`,
  SITE_VAR_NEEDS_PUBLISH: (p) =>
    `The sites file sets ${str(p.keys)}, declared only by the imported draft: tick “Publish”, or the rows will be refused.`,
  ALLOCATE_WITHOUT_POLICY: () =>
    'addresses cannot be allocated: this workspace has no allocation rule, and this setup saves none',
  MASTER_TENANT: () =>
    "This is the Default workspace: templates imported here are never offered to a customer's sites.",
  INSTANCE_ROWS: (p) =>
    `${str(p.count)} instance variable(s): they apply to EVERY workspace of the installation`,
  SLUG_FREEZES: (p) => `Saving this first rule freezes the slug “${str(p.slug)}”.`,
  VAR_TYPE_UNCHECKABLE: (p) => `${str(p.key)} cannot be type-checked against ${str(p.declaredBy)}`,
  INSTANCE_SHADOWS_DEFAULT: (p) =>
    `${str(p.key)}: the instance value will be used instead of the template default; set it on this workspace if it must differ.`,
  STORED_SECRECY_MISMATCH: (p) =>
    `${str(p.key)} is stored at the ${str(p.level)} level ${p.storedSecret ? 'as a secret' : 'in clear'} ` +
    `but declared ${p.storedSecret ? 'not secret' : 'secret'}: a render refuses it until it is written again`,
  OTHER_PUBLISHED: (p) =>
    `${str(p.templateName)} already has published revision(s) ${str(p.revisions)}: the bench offers every published revision`,
  DERIVED_NOT_COMPUTED: (p) =>
    `${str(p.key)} is derived by the allocation rule but declared at ${str(p.declaredLevel)}: ` +
    'a render uses a derived value only for a key declared computed',
  REQUIREMENTS_INCOMPLETE: (p) => `${str(p.count)} required variable(s) would still be missing`,
  NO_REFERENCE_TEMPLATE: () =>
    'no template to type the values against (no file, no revision picked, nothing published): values are not type-checked',
  VAR_SECRET_FORCED: (p) => `${str(p.key)} is declared secret: it is stored as a secret`,
  VAR_SECRET_KEPT: (p) =>
    `${str(p.key)} is already stored as a secret at the ${str(p.level)} level: the new value is stored as a secret too`,
  VAR_UNDECLARED: (p) => `${str(p.key)} is declared by no reference template`,
  VAR_LEVEL_DIFFERS: (p) => `${str(p.key)} is declared at the ${str(p.declared)} level and set here at ${str(p.row)}`,
  DERIVED_UNDECLARED: (p) => `${str(p.key)} is derived by the allocation rule and declared by no reference template`,
  SITES_CODE_FORMAT_OVERRIDE: (p) =>
    `the sites are judged against the site code format "${str(p.format)}" this setup saves`,
  CHR_COMPARE_STORED_RULE: () =>
    'the CHR column compares the sites with the STORED login rule, not the one this setup saves',
};

export function issue(code: SetupIssueCode, part: SetupPart | 'setup', params: Params = {}): SetupIssue {
  return { severity: SETUP_ISSUE_SEVERITY[code], code, part, params, message: MESSAGES[code](params) };
}
