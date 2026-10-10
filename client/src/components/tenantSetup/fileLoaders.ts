import type { TFunction } from 'i18next';
import {
  MAX_SETUP_BODY_CHARS,
  parseDelimited,
  parseSetupBundle,
  parseVariablesCsv,
  parseVariablesFile,
  type DeclaredKeyView,
  type SetupPolicyFile,
  type SetupVariableRow,
} from '@obliwan/shared';
import type { AddressPool, ConcentratorOption } from '@/api/allocation.api';
import { newId, policyDraftFromFile } from './policyModel';
import {
  SITE_FIXED_COLUMNS, useQuickSetupStore, type LoadedRow, type SitesDraft, type TemplateSource,
} from './quickSetupStore';

/**
 * Turning a dropped file into the page's state. One function per kind of file,
 * shared by the Files tab and the designer, so a file reads the same wherever
 * it is dropped. Each returns `null` when it loaded, or the sentence to show.
 *
 * Nothing here judges CONTENT the server judges: the template, the rule and the
 * sites CSV are checked by "Check". What is read here is the SHAPE needed to
 * fill a form — and a CSV's encoding, which only the browser can see.
 */

export type LoadResult = { ok: true; note?: string } | { ok: false; message: string };

/** The chosen file failed a strict UTF-8 decode and was read as Windows-1252
 *  (Excel's "CSV (séparateur : point-virgule)"); `file.text()` would have
 *  turned every accented byte into U+FFFD, written over a correct site name. */
export async function readText(file: File): Promise<{ text: string; legacy: boolean }> {
  const buf = await file.arrayBuffer();
  try {
    return { text: new TextDecoder('utf-8', { fatal: true }).decode(buf), legacy: false };
  } catch {
    return { text: new TextDecoder('windows-1252').decode(buf), legacy: true };
  }
}

function maxChars(): number {
  return useQuickSetupStore.getState().context?.limits.maxBodyChars ?? MAX_SETUP_BODY_CHARS;
}

export function tooLarge(t: TFunction, size: number): LoadResult | null {
  const max = maxChars();
  return size > max
    ? { ok: false, message: t('quickSetup.files.tooLarge', { defaultValue: 'File too large ({{size}} characters, limit {{max}}).', size, max }) }
    : null;
}

function notJson(t: TFunction, err: unknown): LoadResult {
  return {
    ok: false,
    message: t('quickSetup.files.notJson', {
      defaultValue: 'This file is not valid JSON: {{message}}', message: (err as Error).message,
    }),
  };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

// ── Template ──────────────────────────────────────────────────────────────────

export function templateSummary(obj: unknown): { name: string; brand: string | null; entries: number; format: string } {
  if (!isRecord(obj)) return { name: '', brand: null, entries: 0, format: '' };
  const format = typeof obj.format === 'string' ? obj.format : '';
  if (Array.isArray(obj.templates)) {
    const first = obj.templates.find(isRecord);
    return {
      name: first && typeof first.name === 'string' ? first.name : '',
      brand: first && typeof first.brand === 'string' ? first.brand : null,
      entries: obj.templates.length,
      format,
    };
  }
  return {
    name: typeof obj.name === 'string' ? obj.name : '',
    brand: typeof obj.brand === 'string' ? obj.brand : null,
    entries: 1,
    format,
  };
}

export function loadTemplateObject(t: TFunction, obj: unknown, fileName: string, chars: number): LoadResult {
  if (!isRecord(obj)) {
    return { ok: false, message: t('quickSetup.files.notTemplate', { defaultValue: 'This is not a template file (.owt.json).' }) };
  }
  const store = useQuickSetupStore.getState();
  const template: TemplateSource = { source: 'file', fileName, file: obj, summary: templateSummary(obj) };
  store.setTemplate(template);
  store.setFile('template', { name: fileName, chars });
  return { ok: true };
}

export async function loadTemplateFile(t: TFunction, file: File): Promise<LoadResult> {
  const text = await file.text();
  const big = tooLarge(t, text.length);
  if (big) return big;
  let obj: unknown;
  try {
    obj = JSON.parse(text);
  } catch (err) {
    return notJson(t, err);
  }
  return loadTemplateObject(t, obj, file.name, text.length);
}

// ── Variables ─────────────────────────────────────────────────────────────────

function declarationsByKey(): Record<string, DeclaredKeyView> {
  const out: Record<string, DeclaredKeyView> = Object.create(null) as Record<string, DeclaredKeyView>;
  for (const d of useQuickSetupStore.getState().context?.declarations ?? []) out[d.key] = d;
  return out;
}

function fromRow(r: SetupVariableRow, csvText?: string): LoadedRow {
  return {
    level: r.level,
    scopeRef: r.scopeRef ?? '',
    key: r.key,
    value: r.value,
    secret: r.secret,
    ...(r.line !== undefined ? { line: r.line } : {}),
    ...(csvText !== undefined ? { csvText } : {}),
  };
}

/** The raw `value` cell of each CSV line, so the value can be typed again when
 *  a template loaded later declares the key with another type. */
function rawValueCells(text: string): Map<number, string> {
  const out = new Map<number, string>();
  const parsed = parseDelimited(text);
  if ('error' in parsed) return out;
  const records = parsed.records.filter((r) => r.cells.some((c) => c !== ''));
  if (records.length === 0) return out;
  const idx = records[0].cells.findIndex((c) => c.trim().toLowerCase() === 'value');
  if (idx < 0) return out;
  for (const r of records.slice(1)) out.set(r.line, (r.cells[idx] ?? '').trim());
  return out;
}

export function loadVariablesCsvText(text: string, fileName: string): LoadResult {
  const { rows, problems } = parseVariablesCsv(text, declarationsByKey());
  const raw = rawValueCells(text);
  const store = useQuickSetupStore.getState();
  store.loadVariableRows(
    rows.map((r) => fromRow(r, r.line !== undefined ? raw.get(r.line) : undefined)),
    problems.map((p) => ({ line: p.line, code: p.code, ...(p.column !== undefined ? { column: p.column } : {}) })),
  );
  store.setFile('variables', { name: fileName, chars: text.length });
  return { ok: true };
}

export function loadVariablesRows(rows: SetupVariableRow[], fileName: string, chars: number): void {
  const store = useQuickSetupStore.getState();
  store.loadVariableRows(rows.map((r) => fromRow(r)), []);
  store.setFile('variables', { name: fileName, chars });
}

export async function loadVariablesFile(t: TFunction, file: File): Promise<LoadResult> {
  const { text, legacy } = await readText(file);
  const big = tooLarge(t, text.length);
  if (big) return big;
  const trimmed = text.replace(/^\uFEFF/, '').trimStart();
  if (trimmed.startsWith('{')) {
    let obj: unknown;
    try {
      obj = JSON.parse(trimmed);
    } catch (err) {
      return notJson(t, err);
    }
    const parsed = parseVariablesFile(obj);
    if (!parsed.ok) return { ok: false, message: parsed.problem };
    loadVariablesRows(parsed.rows, file.name, text.length);
    return { ok: true };
  }
  const r = loadVariablesCsvText(text, file.name);
  return legacy && r.ok ? { ok: true, note: legacyNote(t) } : r;
}

function legacyNote(t: TFunction): string {
  return t('quickSetup.files.legacyEncoding', {
    defaultValue: 'This file is not UTF-8: it was read as Windows-1252 (Excel). Check the accents.',
  });
}

// ── Sites ─────────────────────────────────────────────────────────────────────

/** A header cell as the site import reads it: fixed names in any case,
 *  `var:<key>` with the key as typed. Anything else is kept as it is, and the
 *  server's verdict names it. */
export function normalizeSitesHeader(raw: string): string {
  const name = raw.trim();
  if (/^var:/i.test(name)) return `var:${name.slice(4).trim()}`;
  const lower = name.toLowerCase();
  return (SITE_FIXED_COLUMNS as readonly string[]).includes(lower) ? lower : name;
}

export function sitesFromText(
  t: TFunction,
  text: string,
): { ok: true; sites: SitesDraft; extraCells: number } | { ok: false; message: string } {
  const parsed = parseDelimited(text);
  if ('error' in parsed) {
    return {
      ok: false,
      message: t('quickSetup.files.parseError', {
        defaultValue: 'Line {{line}}: {{problem}}',
        line: parsed.error.line,
        problem: t('quickSetup.csvProblem.unterminated_quote', { defaultValue: 'a quoted cell is never closed' }),
      }),
    };
  }
  const records = parsed.records.filter((r) => r.cells.some((c) => c !== ''));
  if (records.length === 0) {
    return { ok: false, message: t('quickSetup.files.emptyFile', { defaultValue: 'The file is empty.' }) };
  }
  const header = records[0].cells.map(normalizeSitesHeader);
  let extraCells = 0;
  const rows = records.slice(1).map((r) => {
    if (r.cells.length > header.length && r.cells.slice(header.length).some((c) => c !== '')) extraCells += 1;
    return { id: newId('s'), cells: Array.from({ length: header.length }, (_, i) => r.cells[i] ?? '') };
  });
  return { ok: true, sites: { header, rows }, extraCells };
}

export function loadSitesText(t: TFunction, text: string, fileName: string, allocate?: boolean): LoadResult {
  const r = sitesFromText(t, text);
  if (!r.ok) return r;
  const store = useQuickSetupStore.getState();
  store.setSites(r.sites);
  if (allocate !== undefined) store.setAllocate(allocate);
  store.setFile('sites', { name: fileName, chars: text.length });
  return r.extraCells > 0
    ? {
      ok: true,
      note: t('quickSetup.grid.extraCells', {
        defaultValue: '{{count}} row(s) have more cells than the header has columns: the extra cells were dropped.',
        count: r.extraCells,
      }),
    }
    : { ok: true };
}

export async function loadSitesFile(t: TFunction, file: File): Promise<LoadResult> {
  const { text, legacy } = await readText(file);
  const big = tooLarge(t, text.length);
  if (big) return big;
  const r = loadSitesText(t, text, file.name);
  if (r.ok && legacy) return { ok: true, note: [r.note, legacyNote(t)].filter(Boolean).join(' ') };
  return r;
}

// ── Allocation rule ───────────────────────────────────────────────────────────

function poolsAndChrs(): { pools: AddressPool[]; concentrators: ConcentratorOption[] } {
  const ctx = useQuickSetupStore.getState().context;
  return {
    pools: (ctx?.pools ?? []) as unknown as AddressPool[],
    concentrators: ctx?.concentrators ?? [],
  };
}

export function loadPolicyObject(t: TFunction, obj: unknown, fileName: string, chars: number): LoadResult {
  if (!isRecord(obj)) {
    return { ok: false, message: t('quickSetup.files.notPolicy', { defaultValue: 'This is not an allocation rule (a JSON object).' }) };
  }
  const { pools, concentrators } = poolsAndChrs();
  const store = useQuickSetupStore.getState();
  store.setPolicy(policyDraftFromFile(obj as Partial<SetupPolicyFile> & Record<string, unknown>, pools, concentrators));
  store.setFile('allocationPolicy', { name: fileName, chars });
  const known = new Set([
    'format', 'tunnel', 'lan', 'pppLoginTemplate', 'systemIdentityTemplate', 'pppPasswordMode', 'derived',
    'pppProfile', 'concentratorId', 'concentratorName', 'siteCodeFormat',
  ]);
  const dropped = Object.keys(obj).filter((k) => !known.has(k));
  return dropped.length > 0
    ? {
      ok: true,
      note: t('quickSetup.files.policyDropped', {
        defaultValue: 'Not part of an allocation rule, and not kept: {{fields}}', fields: dropped.join(', '),
      }),
    }
    : { ok: true };
}

export async function loadPolicyFile(t: TFunction, file: File): Promise<LoadResult> {
  const text = await file.text();
  const big = tooLarge(t, text.length);
  if (big) return big;
  try {
    return loadPolicyObject(t, JSON.parse(text), file.name, text.length);
  } catch (err) {
    return notJson(t, err);
  }
}

// ── Bundle ────────────────────────────────────────────────────────────────────

export async function loadBundleFile(t: TFunction, file: File): Promise<LoadResult> {
  const text = await file.text();
  const big = tooLarge(t, text.length);
  if (big) return big;
  let obj: unknown;
  try {
    obj = JSON.parse(text);
  } catch (err) {
    return notJson(t, err);
  }
  const parsed = parseSetupBundle(obj);
  if (!parsed.ok) return { ok: false, message: parsed.problem };
  const b = parsed.bundle;
  const store = useQuickSetupStore.getState();
  const notes: string[] = [];
  const label = (part: string) => `${file.name} › ${part}`;
  if (b.variables) loadVariablesRows(b.variables.rows, label('variables'), 0);
  if (b.template !== undefined) {
    const r = loadTemplateObject(t, b.template, label('template'), 0);
    if (!r.ok) notes.push(r.message);
    if (b.publish !== undefined) store.setPublish(b.publish);
  }
  if (b.allocationPolicy) {
    const r = loadPolicyObject(t, b.allocationPolicy, label('allocationPolicy'), 0);
    if (!r.ok) notes.push(r.message);
    else if (r.note) notes.push(r.note);
  }
  if (b.sites) {
    const r = loadSitesText(t, b.sites.csv, label('sites'), b.sites.allocate);
    if (!r.ok) notes.push(r.message);
    else if (r.note) notes.push(r.note);
  }
  store.setFile('bundle', { name: file.name, chars: text.length });
  // The bundle's tenant is information, never a target: say so when it is
  // not the workspace the setup will act on.
  const current = store.context?.tenant;
  if (b.tenant && current && b.tenant.slug !== current.slug) {
    notes.unshift(
      t('quickSetup.files.bundleOtherTenant', {
        defaultValue: 'This bundle was exported from the workspace "{{from}}"; it will be applied to the CURRENT workspace "{{to}}".',
        from: `${b.tenant.name} (${b.tenant.slug})`,
        to: `${current.name} (${current.slug})`,
      }),
    );
  }
  return notes.length > 0 ? { ok: true, note: notes.join(' ') } : { ok: true };
}
