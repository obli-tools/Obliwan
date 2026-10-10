import type { DeclaredKeyView } from '@obliwan/shared';
import type { JsonValue } from '@/api/variables.api';
import { arrayItemsAreScalar } from '@/components/templates/varSchemaModel';
import { parseDraft } from '@/components/variables/valueKinds';

/**
 * How one declared variable is edited in the Quick Setup designer: the kind of
 * control, the text a value is shown as, and the text → typed JSON parse.
 *
 * The same mapping as the site form (`SiteVariablesPanel.fieldSpec`), re-stated
 * here because that one is private to its panel, plus one kind the site form
 * does not need: a list of scalars typed one item per line.
 *
 * A variable is TYPED JSON on the server (ajv runs with `coerceTypes: false`),
 * so the parse is decided by the declaration, never guessed from the text. An
 * EMPTY field means "keep what is stored" — never "erase", never `""`: the same
 * rule as an empty cell in the variables CSV, so the designer and the file can
 * never disagree about what a blank does.
 */

export type FieldKind = 'secret' | 'enum' | 'boolean' | 'number' | 'text' | 'scalarArray' | 'json';
export type ItemType = 'string' | 'integer' | 'number';

export interface FieldSpec {
  kind: FieldKind;
  integer: boolean;
  options: JsonValue[];
  itemType: ItemType;
  pattern: string | null;
  placeholder: string | null;
}

/** Why a typed text could not become a value. Worded by the screen. */
export type FieldErrorCode = 'jsonInvalid' | 'notNumber' | 'notInteger' | 'notArray' | 'pattern' | 'notInEnum';

function typeOf(schema: Record<string, unknown>): string | undefined {
  const t = schema.type;
  if (Array.isArray(t)) return t.find((x) => x !== 'null') as string | undefined;
  return typeof t === 'string' ? t : undefined;
}

export function fieldSpec(decl: Pick<DeclaredKeyView, 'secret' | 'schema'> | undefined): FieldSpec {
  const s = (decl?.schema ?? {}) as Record<string, unknown>;
  const type = typeOf(s);
  const examples = Array.isArray(s.examples) ? s.examples : [];
  const placeholder =
    examples.length > 0 && (typeof examples[0] === 'string' || typeof examples[0] === 'number')
      ? String(examples[0])
      : typeof s.format === 'string' ? s.format : null;
  const items = (s.items ?? {}) as Record<string, unknown>;
  const base: FieldSpec = {
    kind: 'json',
    integer: type === 'integer',
    options: [],
    itemType: items.type === 'integer' ? 'integer' : items.type === 'number' ? 'number' : 'string',
    pattern: typeof s.pattern === 'string' ? s.pattern : null,
    placeholder,
  };
  if (!decl) return { ...base, kind: 'text' };
  if (decl.secret) return { ...base, kind: 'secret' };
  if (Array.isArray(s.enum) && s.enum.length > 0) return { ...base, kind: 'enum', options: s.enum as JsonValue[] };
  if (type === 'boolean') return { ...base, kind: 'boolean' };
  if (type === 'integer' || type === 'number') return { ...base, kind: 'number' };
  if (type === 'string') return { ...base, kind: 'text' };
  if (type === 'array' && (arrayItemsAreScalar(s) || items.type === 'number')) return { ...base, kind: 'scalarArray' };
  return base;
}

/** Whether `value` is what a control of this kind can show without losing its
 *  type. A value that is not (a number in a text field, from a hand-written
 *  JSON file) is shown in the JSON editor instead, so it is never silently
 *  turned into a string by being displayed. */
export function valueFitsKind(value: JsonValue, spec: FieldSpec): boolean {
  switch (spec.kind) {
    case 'secret': return typeof value === 'string';
    case 'enum': return spec.options.some((o) => JSON.stringify(o) === JSON.stringify(value));
    case 'boolean': return typeof value === 'boolean';
    case 'number': return typeof value === 'number';
    case 'text': return typeof value === 'string';
    case 'scalarArray':
      return Array.isArray(value) && value.every((x) => typeof x === 'string' || typeof x === 'number');
    case 'json': return true;
  }
}

/** The text a value is edited as. `asJson` = the JSON editor. */
export function textOf(value: JsonValue, spec: FieldSpec, asJson: boolean): string {
  if (asJson || spec.kind === 'json') return JSON.stringify(value, null, 2);
  switch (spec.kind) {
    case 'secret':
    case 'text':
      return typeof value === 'string' ? value : JSON.stringify(value);
    case 'enum': return JSON.stringify(value);
    case 'boolean': return value === true ? 'true' : value === false ? 'false' : '';
    case 'number': return typeof value === 'number' ? String(value) : '';
    case 'scalarArray':
      return Array.isArray(value) ? value.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))).join('\n') : '';
  }
}

export interface ParsedField {
  /** undefined = nothing typed: keep what is stored. */
  value: JsonValue | undefined;
  error: FieldErrorCode | null;
}

function patternFails(pattern: string | null, text: string): boolean {
  if (!pattern) return false;
  try {
    return !new RegExp(pattern, 'u').test(text);
  } catch {
    // A pattern this browser cannot compile is the server's to judge.
    return false;
  }
}

/** Typed text → JSON, by the declaration. Trims BEFORE testing emptiness:
 *  `Number(' ')` is 0, and a blank must never become a real zero. */
export function parseField(text: string, spec: FieldSpec, asJson: boolean): ParsedField {
  if (asJson || spec.kind === 'json') {
    if (text.trim() === '') return { value: undefined, error: null };
    try {
      const v = JSON.parse(text) as JsonValue;
      if (spec.kind === 'scalarArray' && !Array.isArray(v)) return { value: undefined, error: 'notArray' };
      return { value: v, error: null };
    } catch {
      return { value: undefined, error: 'jsonInvalid' };
    }
  }
  switch (spec.kind) {
    case 'secret':
      // A secret is taken exactly as typed: trimming it would change it.
      return { value: text === '' ? undefined : text, error: null };
    case 'enum': {
      if (text === '') return { value: undefined, error: null };
      try {
        return { value: JSON.parse(text) as JsonValue, error: null };
      } catch {
        return { value: undefined, error: 'notInEnum' };
      }
    }
    case 'boolean':
      return { value: text === 'true' ? true : text === 'false' ? false : undefined, error: null };
    case 'number': {
      if (text.trim() === '') return { value: undefined, error: null };
      const r = parseDraft(text, 'number', { integer: spec.integer });
      if (r.ok) return { value: r.value, error: null };
      return { value: undefined, error: r.reason === 'notInteger' ? 'notInteger' : 'notNumber' };
    }
    case 'text':
      if (text.trim() === '') return { value: undefined, error: null };
      return { value: text, error: patternFails(spec.pattern, text) ? 'pattern' : null };
    case 'scalarArray': {
      if (text.trim() === '') return { value: undefined, error: null };
      if (text.trim().startsWith('[')) return parseField(text, spec, true);
      const items = text.split('\n').map((s) => s.trim()).filter((s) => s !== '');
      if (spec.itemType === 'string') return { value: items, error: null };
      const numbers: number[] = [];
      for (const s of items) {
        if (spec.itemType === 'integer' && !/^[+-]?\d{1,15}$/.test(s)) return { value: undefined, error: 'notInteger' };
        const n = Number(s);
        if (!Number.isFinite(n)) return { value: undefined, error: 'notNumber' };
        numbers.push(n);
      }
      return { value: numbers, error: null };
    }
  }
  return { value: undefined, error: null };
}

/** One-line rendering of a NON-secret value, for hints and table cells. */
export function shortValue(value: JsonValue, max = 60): string {
  const s = typeof value === 'string' ? value : JSON.stringify(value);
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

/** The first characters of a stored secret's keyed fingerprint, so an operator
 *  can tell two stored secrets apart without anything of the secret itself. */
export function fingerprintText(fp: unknown): string | null {
  const v = (fp as { fp?: unknown } | null)?.fp;
  return typeof v === 'string' && v !== '' ? v.slice(0, 8) : null;
}

/** The text a value takes in a sites-grid cell: a string verbatim, anything
 *  else as JSON — what the site import's `coerceCell` reads back typed. */
export function cellText(value: JsonValue): string {
  return typeof value === 'string' ? value : JSON.stringify(value);
}
