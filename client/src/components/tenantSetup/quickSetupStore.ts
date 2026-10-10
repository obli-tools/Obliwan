import { create } from 'zustand';
import {
  SETUP_PARTS,
  coerceVariableCell,
  parseDelimited,
  toDelimited,
  type DeclaredKeyView,
  type SetupPart,
  type SetupVariableRow,
  type TenantSetupContext,
  type TenantSetupReport,
  type TenantSetupRequest,
} from '@obliwan/shared';
import type { JsonValue } from '@/api/variables.api';
import { fieldSpec, parseField, textOf, valueFitsKind, cellText, type FieldErrorCode } from './fieldModel';
import {
  EMPTY_POLICY, newId, policyDraftFromStored, policyFileFromDraft, type PolicyDraft, type StoredPolicy,
} from './policyModel';

/**
 * Quick Setup Tenant — the page's working state.
 *
 * ┌─ NOT PERSISTED, ON PURPOSE ──────────────────────────────────────────────┐
 * │ The drafts may hold secrets the operator typed or loaded from a local    │
 * │ file. They live in memory only: no localStorage, no sessionStorage. The  │
 * │ state survives a navigation inside the app (an operator who opens the    │
 * │ Templates page to look at something comes back to their work) and dies  │
 * │ with the tab. It belongs to ONE workspace and ONE user: the page resets  │
 * │ it when either changes, because a draft prepared for customer A applied  │
 * │ under customer B is exactly the mistake this screen must not make easy.  │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The variables live in two places. A key a reference template DECLARES at
 * instance / global / tenant is a FIELD of the designer, at its declared
 * level (`fields`). Everything else a file brought — a site row, an
 * undeclared key, a key set at another level than declared, a row whose
 * secrecy contradicts its declaration — is an EXTRA row, shown and edited in
 * "Other variables", and sent as it is so the server can judge it. When the
 * declarations change (a template loaded after the variables file), the two
 * are re-partitioned and every value that came from CSV text is re-typed
 * against the new schema, as the server would type it.
 */

export type FieldLevel = 'instance' | 'global' | 'tenant';
export const FIELD_LEVELS: readonly FieldLevel[] = ['instance', 'global', 'tenant'];

/** A designer field the operator (or a file) set. Absent = untouched: the
 *  field shows what is stored and sends nothing. */
export interface FieldDraft {
  text: string;
  /** undefined = keep what is stored (nothing sent). */
  value: JsonValue | undefined;
  error: FieldErrorCode | null;
  asJson: boolean;
  /** The row's own secret flag, kept when the field moves back to an extra row. */
  secret: boolean;
  /** The CSV cell this value was typed from, re-typed when the declarations change. */
  csvText?: string;
  line?: number;
}

export interface ExtraRowDraft {
  id: string;
  level: string;
  /** '' = none. */
  scopeRef: string;
  key: string;
  text: string;
  value: JsonValue | undefined;
  secret: boolean;
  line?: number;
  csvText?: string;
}

export const SITE_FIXED_COLUMNS = ['code', 'name', 'country', 'timezone', 'address', 'contact'] as const;

export interface GridRow {
  id: string;
  cells: string[];
}

export interface SitesDraft {
  header: string[];
  rows: GridRow[];
}

export type TemplateSource =
  | { source: 'none' }
  | {
      source: 'file';
      fileName: string;
      file: unknown;
      summary: { name: string; brand: string | null; entries: number; format: string };
    }
  | { source: 'existing'; revisionId: string; label: string };

export type PartOrigin = 'none' | 'file' | 'designer';

export interface LoadedFile {
  name: string;
  chars: number;
}

export interface VariablesFileProblem {
  line: number;
  code: string;
  column?: string;
  /** A JSON file's own sentence (server-side wording, English). */
  message?: string;
}

export interface LastCheck {
  requestHash: string;
  report: TenantSetupReport;
  /** Grid row id → the CSV line it was sent on: how a site verdict finds its row. */
  siteLines: Record<string, number>;
}

interface Data {
  tenantId: number | null;
  userId: number | null;
  context: TenantSetupContext | null;
  contextError: string | null;
  contextLoading: boolean;
  selected: Record<SetupPart, boolean>;
  origin: Record<SetupPart, PartOrigin>;
  files: Partial<Record<SetupPart | 'bundle', LoadedFile>>;
  variablesProblems: VariablesFileProblem[];
  template: TemplateSource;
  publish: boolean;
  fields: Record<FieldLevel, Record<string, FieldDraft>>;
  extraRows: ExtraRowDraft[];
  sites: SitesDraft;
  allocate: boolean;
  policy: PolicyDraft | null;
  lastCheck: LastCheck | null;
  lastApply: TenantSetupReport | null;
}

interface Actions {
  reset: (tenantId: number | null, userId: number | null) => void;
  setContext: (ctx: TenantSetupContext | null, error: string | null) => void;
  setContextLoading: (loading: boolean) => void;
  setSelected: (part: SetupPart, on: boolean) => void;
  markEdited: (part: SetupPart) => void;
  setFile: (slot: SetupPart | 'bundle', file: LoadedFile | null) => void;
  setTemplate: (t: TemplateSource) => void;
  setPublish: (on: boolean) => void;
  setField: (level: FieldLevel, key: string, text: string, asJson: boolean) => void;
  resetField: (level: FieldLevel, key: string) => void;
  loadVariableRows: (rows: LoadedRow[], problems: VariablesFileProblem[]) => void;
  clearVariables: () => void;
  setExtraRows: (rows: ExtraRowDraft[]) => void;
  setSites: (sites: SitesDraft) => void;
  setAllocate: (on: boolean) => void;
  setPolicy: (p: PolicyDraft | null) => void;
  setLastCheck: (c: LastCheck | null) => void;
  setLastApply: (r: TenantSetupReport | null) => void;
}

export type QuickSetupState = Data & Actions;

const NO_PARTS: Record<SetupPart, boolean> = { variables: false, template: false, allocationPolicy: false, sites: false };
const NO_ORIGIN: Record<SetupPart, PartOrigin> = { variables: 'none', template: 'none', allocationPolicy: 'none', sites: 'none' };

export function emptySites(): SitesDraft {
  return { header: [...SITE_FIXED_COLUMNS], rows: [] };
}

function initial(tenantId: number | null, userId: number | null): Data {
  return {
    tenantId,
    userId,
    context: null,
    contextError: null,
    contextLoading: false,
    selected: { ...NO_PARTS },
    origin: { ...NO_ORIGIN },
    files: {},
    variablesProblems: [],
    template: { source: 'none' },
    publish: true,
    fields: { instance: {}, global: {}, tenant: {} },
    extraRows: [],
    sites: emptySites(),
    allocate: false,
    policy: null,
    lastCheck: null,
    lastApply: null,
  };
}

// ── Variables: partition between designer fields and extra rows ───────────────

/** One variable row as loaded (from a file) or carried over (from a field). */
export interface LoadedRow {
  id?: string;
  level: string;
  scopeRef: string;
  key: string;
  value: JsonValue | undefined;
  secret: boolean;
  line?: number;
  /** The raw CSV cell: the value is re-typed from it against the declarations. */
  csvText?: string;
  /** A designer field's text, re-parsed against the new declaration. */
  fieldText?: string;
  asJson?: boolean;
}

export function declMap(declarations: readonly DeclaredKeyView[]): Map<string, DeclaredKeyView> {
  return new Map(declarations.map((d) => [d.key, d]));
}

/** A CSV cell typed as the server's parser types it. */
function typedFromCsv(text: string, secret: boolean, decl: DeclaredKeyView | undefined): JsonValue | undefined {
  if (text.trim() === '') return undefined;
  return secret || decl?.secret === true ? text : coerceVariableCell(text, decl?.schema);
}

function extraText(r: LoadedRow): string {
  if (r.csvText !== undefined) return r.csvText;
  if (r.value !== undefined) return cellText(r.value);
  return r.fieldText ?? '';
}

export function partitionRows(
  rows: readonly LoadedRow[],
  declarations: readonly DeclaredKeyView[],
): { fields: Record<FieldLevel, Record<string, FieldDraft>>; extraRows: ExtraRowDraft[] } {
  const decls = declMap(declarations);
  const fields: Record<FieldLevel, Record<string, FieldDraft>> = { instance: {}, global: {}, tenant: {} };
  const extraRows: ExtraRowDraft[] = [];
  for (const r of rows) {
    const decl = decls.get(r.key);
    const secret = r.secret || decl?.secret === true;
    const isFieldLevel = (FIELD_LEVELS as readonly string[]).includes(r.level);
    const fieldOk =
      isFieldLevel &&
      r.scopeRef.trim() === '' &&
      decl !== undefined &&
      decl.level === r.level &&
      // A row that claims secrecy its declaration does not grant stays an
      // extra row, so the server's VAR_SECRET_NOT_DECLARED reaches the screen
      // instead of the flag vanishing into a field.
      !(r.secret && !decl.secret) &&
      !decl.secrecyConflict &&
      !Object.prototype.hasOwnProperty.call(fields[r.level as FieldLevel], r.key);
    if (fieldOk) {
      const spec = fieldSpec(decl);
      if (r.fieldText !== undefined && r.csvText === undefined) {
        const parsed = parseField(r.fieldText, spec, r.asJson === true);
        fields[r.level as FieldLevel][r.key] = {
          text: r.fieldText, value: parsed.value, error: parsed.error, asJson: r.asJson === true, secret: r.secret,
          line: r.line,
        };
      } else {
        const value = r.csvText !== undefined ? typedFromCsv(r.csvText, secret, decl) : r.value;
        // A "keep" row (empty cell, absent value) writes nothing: the field
        // stays untouched and goes on showing what is stored.
        if (value === undefined) continue;
        const asJson = r.asJson === true || !valueFitsKind(value, spec);
        fields[r.level as FieldLevel][r.key] = {
          text: textOf(value, spec, asJson),
          value,
          error: null,
          asJson,
          secret: r.secret,
          csvText: r.csvText,
          line: r.line,
        };
      }
      continue;
    }
    const value = r.csvText !== undefined ? typedFromCsv(r.csvText, secret, decl) : r.value;
    extraRows.push({
      id: r.id ?? newId('x'),
      level: r.level,
      scopeRef: r.scopeRef,
      key: r.key,
      text: extraText(r),
      value,
      // The row's OWN flag (a field's carries the secrecy it was typed under,
      // so a secret typed in the designer stays a secret if it lands here).
      // A declaration or a stored secret masks it on top: `extraRowSecrecy`,
      // which every display and export of an extra row goes through.
      secret: r.secret,
      line: r.line,
      csvText: r.csvText,
    });
  }
  return { fields, extraRows };
}

/** Every loaded or typed variable, as rows — what a re-partition starts from. */
export function currentRows(s: Pick<Data, 'fields' | 'extraRows'>): LoadedRow[] {
  const out: LoadedRow[] = [];
  for (const level of FIELD_LEVELS) {
    for (const [key, f] of Object.entries(s.fields[level])) {
      out.push(
        f.csvText !== undefined
          ? { level, scopeRef: '', key, value: f.value, secret: f.secret, line: f.line, csvText: f.csvText }
          : { level, scopeRef: '', key, value: f.value, secret: f.secret, line: f.line, fieldText: f.text, asJson: f.asJson },
      );
    }
  }
  for (const x of s.extraRows) {
    out.push({
      id: x.id, level: x.level, scopeRef: x.scopeRef, key: x.key, value: x.value, secret: x.secret, line: x.line,
      ...(x.csvText !== undefined ? { csvText: x.csvText } : {}),
    });
  }
  return out;
}

/**
 * How an EXTRA row's secrecy is handled on this screen: the server's rule
 * (variablesPart `judgeRows`) seen from the browser. The row's own `secret`
 * stays the file's or the operator's flag, so the server's report can still
 * say which rows it forced. Everything that SHOWS or EXPORTS a value asks this
 * instead, because an extra row is exactly where a declared secret arrives
 * with its own flag unset: a site row, a key set at another level than
 * declared, a CSV whose `secret` column was left empty.
 *
 *  - `masked`: the value is a secret here. That is its own flag, a
 *    declaration that says secret, or a value already stored as a secret at
 *    the same place (which the server keeps secret, VAR_SECRET_KEPT, or
 *    refuses to replace in clear, VAR_SECRET_DOWNGRADE). It is typed in a
 *    password input and never exported.
 *  - `forcedBy`: why it is masked although its own flag is false.
 *  - `exportFlag`: the `secret` flag an export writes, always with an empty
 *    value. It is false for the one masked case a declaration calls clear (a
 *    stored secret under a clear declaration): flagged true, the exported row
 *    would be refused on re-import (VAR_SECRET_NOT_DECLARED) although it
 *    writes nothing, whereas flagged false and empty it is a plain "keep".
 */
export interface ExtraRowSecrecy {
  masked: boolean;
  forcedBy: 'declaration' | 'stored' | null;
  exportFlag: boolean;
}

function digitsOnly(s: string): boolean {
  return /^[0-9]+$/.test(s);
}

/**
 * Whether the value a row would replace is stored as a secret. A site is
 * found by its exact code, or, for an all-digit code, by the code with its
 * leading zeros ignored: the site import restores zeros a spreadsheet
 * stripped, so "103" may land on site 00103. Over-matching only ever masks
 * MORE, which is the safe direction for this question.
 */
export function storedIsSecret(
  context: TenantSetupContext | null,
  level: string,
  scopeRef: string,
  key: string,
): boolean {
  if (!context || key === '') return false;
  if (level === 'site') {
    const ref = scopeRef.trim();
    if (ref === '') return false;
    const loose = digitsOnly(ref) ? ref.replace(/^0+/, '') : null;
    return context.sites.some(
      (s) =>
        (s.code === ref || (loose !== null && digitsOnly(s.code) && s.code.replace(/^0+/, '') === loose)) &&
        s.values[key]?.isSecret === true,
    );
  }
  if (!(FIELD_LEVELS as readonly string[]).includes(level)) return false;
  return context.values[level as FieldLevel]?.[key]?.isSecret === true;
}

export function extraRowSecrecy(
  row: Pick<ExtraRowDraft, 'level' | 'scopeRef' | 'key' | 'secret'>,
  context: TenantSetupContext | null,
  decls: ReadonlyMap<string, DeclaredKeyView> = declMap(context?.declarations ?? []),
): ExtraRowSecrecy {
  const key = row.key.trim();
  const decl = decls.get(key);
  const stored = storedIsSecret(context, row.level.trim().toLowerCase(), row.scopeRef, key);
  const masked = row.secret || decl?.secret === true || stored;
  return {
    masked,
    forcedBy: row.secret ? null : decl?.secret === true ? 'declaration' : stored ? 'stored' : null,
    exportFlag: row.secret || decl?.secret === true || (stored && decl === undefined),
  };
}

/** An extra row after its text was edited: typed like a CSV cell, so the
 *  value is what the same text in the variables file would have been. */
export function retypeExtraRow(row: ExtraRowDraft, declarations: readonly DeclaredKeyView[]): ExtraRowDraft {
  const decl = declMap(declarations).get(row.key.trim());
  return { ...row, csvText: row.text, value: typedFromCsv(row.text.trim() === '' ? '' : row.text, row.secret, decl) };
}

// ── The request ───────────────────────────────────────────────────────────────

export function isBlankRow(r: GridRow): boolean {
  return r.cells.every((c) => c.trim() === '');
}

/** The grid as the site-import CSV, and the line each sent row lands on. A
 *  blank row is not sent: the server skips blank records, and leaving them
 *  out keeps the line mapping exact. */
export function sitesCsv(sites: SitesDraft): { csv: string; siteLines: Record<string, number> } {
  const sent = sites.rows.filter((r) => !isBlankRow(r));
  const width = sites.header.length;
  const table = [sites.header, ...sent.map((r) => Array.from({ length: width }, (_, i) => r.cells[i] ?? ''))];
  // toDelimited prefixes a BOM for spreadsheets; the request does not need it.
  const csv = toDelimited(table, ',').replace(/^\uFEFF/, '');
  const siteLines: Record<string, number> = {};
  const parsed = parseDelimited(csv, { delimiter: ',' });
  if (!('error' in parsed)) {
    sent.forEach((r, i) => {
      const rec = parsed.records[i + 1];
      if (rec) siteLines[r.id] = rec.line;
    });
  }
  return { csv, siteLines };
}

/** The variable rows the request carries: every field and extra row that has
 *  a value. A field whose text does not parse is NOT sent (its error holds the
 *  Apply button instead). */
export function requestRows(s: Pick<Data, 'fields' | 'extraRows'>, declarations: readonly DeclaredKeyView[]): SetupVariableRow[] {
  const decls = declMap(declarations);
  const rows: SetupVariableRow[] = [];
  for (const level of FIELD_LEVELS) {
    for (const [key, f] of Object.entries(s.fields[level])) {
      if (f.value === undefined || f.error) continue;
      const row: SetupVariableRow = {
        level, scopeRef: null, key, value: f.value, secret: f.secret || decls.get(key)?.secret === true,
      };
      if (f.line !== undefined) row.line = f.line;
      rows.push(row);
    }
  }
  for (const x of s.extraRows) {
    if (x.value === undefined) continue;
    const row: SetupVariableRow = {
      level: x.level.trim().toLowerCase(),
      scopeRef: x.scopeRef.trim() === '' ? null : x.scopeRef.trim(),
      key: x.key.trim(),
      value: x.value,
      secret: x.secret,
    };
    if (x.line !== undefined) row.line = x.line;
    rows.push(row);
  }
  return rows;
}

export function buildRequest(s: Data): { request: TenantSetupRequest; siteLines: Record<string, number> } {
  const declarations = s.context?.declarations ?? [];
  const parts: TenantSetupRequest['parts'] = {};
  let siteLines: Record<string, number> = {};
  if (s.selected.variables) parts.variables = { rows: requestRows(s, declarations) };
  if (s.selected.template && s.template.source === 'file') {
    parts.template = { file: s.template.file, publish: s.publish };
  }
  if (s.selected.allocationPolicy) {
    // Ticked without an edit: the rule on screen is the stored one, and that
    // is what is sent (an empty form when there is none, refused by field).
    const stored = (s.context?.policy ?? null) as StoredPolicy | null;
    const draft = s.policy ?? (stored ? policyDraftFromStored(stored) : EMPTY_POLICY);
    parts.allocationPolicy = { policy: policyFileFromDraft(draft) };
  }
  if (s.selected.sites) {
    const built = sitesCsv(s.sites);
    siteLines = built.siteLines;
    parts.sites = { csv: built.csv, allocate: s.allocate };
  }
  // The workspace these drafts belong to. The server compares it with the
  // session's, which every tab shares, and refuses a mismatch (409): a switch
  // in another tab must not redirect them. Null only before the page has
  // bound the drafts, when Check is not offered; 0 then fails validation.
  const request: TenantSetupRequest = { expectedTenantId: s.tenantId ?? 0, parts };
  if (s.template.source === 'existing') request.referenceRevisionIds = [s.template.revisionId];
  return { request, siteLines };
}

/** A 53-bit hash (cyrb53) of the request, so "Apply" can be offered only for
 *  the exact body that was checked — `expectedTenantId` included, so a check
 *  made for one workspace never opens Apply for another. Not a security
 *  measure; it only has to change when the body does. */
export function hashRequest(req: TenantSetupRequest): string {
  const str = JSON.stringify(req);
  let h1 = 0xdeadbeef;
  let h2 = 0x41c6ce57;
  for (let i = 0; i < str.length; i += 1) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(36);
}

/** Anything the operator would lose by a reset. */
export function isDirty(s: Data): boolean {
  return (
    SETUP_PARTS.some((p) => s.origin[p] !== 'none') ||
    s.template.source !== 'none' ||
    FIELD_LEVELS.some((l) => Object.keys(s.fields[l]).length > 0) ||
    s.extraRows.length > 0 ||
    s.sites.rows.length > 0 ||
    s.policy !== null
  );
}

// ── The store ─────────────────────────────────────────────────────────────────

export const useQuickSetupStore = create<QuickSetupState>((set, get) => ({
  ...initial(null, null),

  reset: (tenantId, userId) => set(initial(tenantId, userId)),

  setContext: (ctx, error) => {
    const prev = get();
    if (!ctx) {
      set({ context: null, contextError: error, contextLoading: false });
      return;
    }
    // The declarations may have changed: re-partition what was loaded or
    // typed, re-typing CSV text against the new schemas.
    const { fields, extraRows } = partitionRows(currentRows(prev), ctx.declarations);
    set({ context: ctx, contextError: error, contextLoading: false, fields, extraRows });
  },

  setContextLoading: (contextLoading) => set({ contextLoading }),

  setSelected: (part, on) => set((s) => ({ selected: { ...s.selected, [part]: on } })),

  markEdited: (part) =>
    set((s) => ({
      origin: s.origin[part] === 'designer' ? s.origin : { ...s.origin, [part]: 'designer' },
      // A designer edit ticks its part: an edit nobody sends is a silent loss.
      // The template part is ticked by setTemplate alone (an existing revision
      // is a reference, not a part).
      selected: s.selected[part] || part === 'template' ? s.selected : { ...s.selected, [part]: true },
    })),

  setFile: (slot, file) =>
    set((s) => {
      const files = { ...s.files };
      if (file) files[slot] = file;
      else delete files[slot];
      if (slot === 'bundle') return { files };
      return {
        files,
        origin: { ...s.origin, [slot]: file ? 'file' : 'none' },
        selected: file ? { ...s.selected, [slot]: true } : s.selected,
      };
    }),

  setTemplate: (template) =>
    set((s) => ({
      template,
      // An existing revision is a REFERENCE for the check, not a part: nothing
      // is imported or published for it.
      selected: { ...s.selected, template: template.source === 'file' },
    })),

  setPublish: (publish) => set({ publish }),

  setField: (level, key, text, asJson) => {
    const s = get();
    const decl = declMap(s.context?.declarations ?? []).get(key);
    const parsed = parseField(text, fieldSpec(decl), asJson);
    const prev = s.fields[level][key];
    set({
      fields: {
        ...s.fields,
        [level]: {
          ...s.fields[level],
          [key]: {
            text, value: parsed.value, error: parsed.error, asJson,
            secret: prev?.secret ?? decl?.secret === true, line: prev?.line,
          },
        },
      },
    });
    get().markEdited('variables');
  },

  resetField: (level, key) =>
    set((s) => {
      const next = { ...s.fields[level] };
      delete next[key];
      return { fields: { ...s.fields, [level]: next } };
    }),

  loadVariableRows: (rows, problems) => {
    const s = get();
    const { fields, extraRows } = partitionRows(rows, s.context?.declarations ?? []);
    set({ fields, extraRows, variablesProblems: problems });
  },

  clearVariables: () =>
    set((s) => ({
      fields: { instance: {}, global: {}, tenant: {} },
      extraRows: [],
      variablesProblems: [],
      origin: { ...s.origin, variables: 'none' },
    })),

  setExtraRows: (extraRows) => {
    set({ extraRows });
    get().markEdited('variables');
  },

  setSites: (sites) => set({ sites }),
  setAllocate: (allocate) => set({ allocate }),
  setPolicy: (policy) => set({ policy }),
  setLastCheck: (lastCheck) => set({ lastCheck }),
  setLastApply: (lastApply) => set({ lastApply }),
}));
