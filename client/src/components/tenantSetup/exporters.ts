import {
  TENANT_SETUP_FORMAT,
  VARIABLES_FILE_FORMAT,
  toDelimited,
  variablesToCsv,
  type SetupPolicyFile,
  type SetupVariableRow,
  type TenantSetupBundle,
} from '@obliwan/shared';
import { downloadText } from '@/api/query.api';
import { EMPTY_POLICY, policyDraftFromStored, policyFileFromDraft, type StoredPolicy } from './policyModel';
import { FIELD_LEVELS, declMap, extraRowSecrecy, isBlankRow, type QuickSetupState } from './quickSetupStore';

/**
 * "Export": the setup on screen as files another workspace (or a later run of
 * this one) can load back.
 *
 * ┌─ AN EXPORT NEVER CARRIES A SECRET ───────────────────────────────────────┐
 * │ Every secret variable is written as a row with NO value: a declared      │
 * │ secret, a row flagged secret, and a row that would replace a value       │
 * │ stored as a secret (`extraRowSecrecy`). Every secret column of the       │
 * │ sites grid is written empty. On import an empty secret means "keep what  │
 * │ is stored", so a re-import never erases a secret — and a file that      │
 * │ leaves the browser never holds one, whoever typed it in this session.    │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The variables exported are what the setup WOULD leave at each level: the
 * value typed (or loaded) when there is one, else the value stored at that same
 * level — so an export of an untouched form is the workspace as it stands.
 */

type State = Pick<
  QuickSetupState,
  'context' | 'fields' | 'extraRows' | 'sites' | 'policy' | 'selected' | 'template' | 'publish' | 'allocate'
>;

export function exportVariableRows(s: State): SetupVariableRow[] {
  const ctx = s.context;
  const rows: SetupVariableRow[] = [];
  const seen = new Set<string>();
  for (const d of ctx?.declarations ?? []) {
    if (!(FIELD_LEVELS as readonly string[]).includes(d.level ?? '')) continue;
    const level = d.level as (typeof FIELD_LEVELS)[number];
    seen.add(`${level}|${d.key}`);
    if (d.secret) {
      rows.push({ level, scopeRef: null, key: d.key, secret: true });
      continue;
    }
    const stored = ctx?.values[level]?.[d.key];
    // Stored as a secret under a declaration that says clear: the server
    // refuses to replace it in clear (VAR_SECRET_DOWNGRADE), so whatever was
    // typed over it is withheld here too, and the stored one is never known.
    if (stored?.isSecret) continue;
    const draft = s.fields[level][d.key];
    if (draft && draft.value !== undefined && !draft.error) {
      rows.push({ level, scopeRef: null, key: d.key, value: draft.value, secret: false });
      continue;
    }
    if (stored && !stored.redacted) {
      rows.push({ level, scopeRef: null, key: d.key, value: stored.value, secret: false });
    }
  }
  // Fields left over from a file whose key is no longer declared at that level
  // were moved to the extra rows, so this covers everything typed or loaded.
  // An extra row's own flag is not its secrecy: a declared secret (a site row,
  // a key set at another level than declared) or a value stored as a secret
  // there masks it too, and a masked value is never written.
  const decls = declMap(ctx?.declarations ?? []);
  for (const x of s.extraRows) {
    const key = x.key.trim();
    if (key === '') continue;
    const level = x.level.trim().toLowerCase();
    if (seen.has(`${level}|${key}`) && x.scopeRef.trim() === '') continue;
    const secrecy = extraRowSecrecy(x, ctx, decls);
    const row: SetupVariableRow = {
      level,
      scopeRef: x.scopeRef.trim() === '' ? null : x.scopeRef.trim(),
      key,
      secret: secrecy.exportFlag,
    };
    if (!secrecy.masked && x.value !== undefined) row.value = x.value;
    rows.push(row);
  }
  return rows;
}

/** The grid as the site-import CSV (';' + BOM, what a French Excel opens),
 *  with every secret column emptied. */
export function exportSitesCsv(s: State): string {
  const secretCols = new Set(
    s.sites.header
      .map((h, i) => ({ h, i }))
      .filter(({ h }) => h.startsWith('var:') && s.context?.declarations.find((d) => d.key === h.slice(4))?.secret === true)
      .map(({ i }) => i),
  );
  const rows = s.sites.rows
    .filter((r) => !isBlankRow(r))
    .map((r) => s.sites.header.map((_, i) => (secretCols.has(i) ? '' : r.cells[i] ?? '')));
  return toDelimited([s.sites.header, ...rows], ';');
}

export function exportPolicy(s: State): SetupPolicyFile {
  const stored = (s.context?.policy ?? null) as StoredPolicy | null;
  return policyFileFromDraft(s.policy ?? (stored ? policyDraftFromStored(stored) : EMPTY_POLICY));
}

export function exportBundle(s: State): TenantSetupBundle {
  const bundle: TenantSetupBundle = { format: TENANT_SETUP_FORMAT, exportedAt: new Date().toISOString() };
  if (s.context) bundle.tenant = { name: s.context.tenant.name, slug: s.context.tenant.slug };
  if (s.selected.variables) bundle.variables = { format: VARIABLES_FILE_FORMAT, rows: exportVariableRows(s) };
  if (s.selected.template && s.template.source === 'file') {
    bundle.template = s.template.file;
    bundle.publish = s.publish;
  }
  if (s.selected.allocationPolicy) bundle.allocationPolicy = exportPolicy(s);
  if (s.selected.sites) bundle.sites = { csv: exportSitesCsv(s).replace(/^\uFEFF/, ''), allocate: s.allocate };
  return bundle;
}

function prefix(s: State): string {
  const slug = s.context?.tenant.slug ?? 'tenant';
  return slug.replace(/[^a-zA-Z0-9_-]+/g, '-');
}

/** Hand the files to the browser. Several downloads are spaced out: a browser
 *  may silently drop the second of two downloads started in the same tick. */
export function downloadSetup(s: State, mode: 'bundle' | 'files'): number {
  const p = prefix(s);
  const files: Array<{ name: string; mime: string; text: string }> = [];
  if (mode === 'bundle') {
    files.push({ name: `${p}-tenant-setup.json`, mime: 'application/json', text: `${JSON.stringify(exportBundle(s), null, 2)}\n` });
  } else {
    if (s.selected.variables) files.push({ name: `${p}-variables.csv`, mime: 'text/csv', text: variablesToCsv(exportVariableRows(s)) });
    if (s.selected.template && s.template.source === 'file') {
      files.push({ name: `${p}-template.owt.json`, mime: 'application/json', text: `${JSON.stringify(s.template.file, null, 2)}\n` });
    }
    if (s.selected.sites) files.push({ name: `${p}-sites.csv`, mime: 'text/csv', text: exportSitesCsv(s) });
    if (s.selected.allocationPolicy) {
      files.push({ name: `${p}-allocation-policy.json`, mime: 'application/json', text: `${JSON.stringify(exportPolicy(s), null, 2)}\n` });
    }
  }
  files.forEach((f, i) => window.setTimeout(() => downloadText(f.name, f.mime, f.text), i * 400));
  return files.length;
}
