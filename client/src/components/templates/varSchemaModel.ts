import type { VarSchema } from '@/api/templates.api';

/**
 * varSchemaModel — the variables table, as operations on the `var_schema`
 * itself.
 *
 * ┌─ THE ONE RULE: A ROUND TRIP IS LOSSLESS ─────────────────────────────────┐
 * │ The table never holds a parallel model that is converted back into JSON  │
 * │ on save. Each row IS a property object of the schema, and each control   │
 * │ edits exactly the keys it shows (`x-obliwan-label`, `type`, `default`…). │
 * │ A schema opened and saved without a click is sent back exactly as it was │
 * │ read, and the keys the table has no control for — `pattern`, `items`,    │
 * │ `x-obliwan-formula`, a nested `properties` — are carried through intact. │
 * │ A table that "normalised" them on save would silently loosen the        │
 * │ validation a converted template was written with.                        │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The server stays the verdict (`varSchemaSchema` + ajv). What is checked here
 * is what a person typing in a table gets wrong, worded with the variable's
 * name, before a round trip.
 */

export type VarKind = 'string' | 'integer' | 'boolean' | 'enum' | 'ipv4' | 'cidr' | 'array' | 'other';

/** The kinds a person can pick. `other` is shown, never offered. */
export const EDITABLE_KINDS: readonly Exclude<VarKind, 'other'>[] = [
  'string', 'integer', 'boolean', 'enum', 'ipv4', 'cidr', 'array',
];

/** Same rule as the server's `VARIABLE_KEY_RE` (migration 008's CHECK). */
export const VARIABLE_KEY_RE = /^[a-z][a-zA-Z0-9_]{0,119}$/;
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * The CIDR shape written for a new `cidr` variable. ajv-formats has no `cidr`
 * format, so a CIDR is a string with this pattern — the spelling the converted
 * templates already use (`{0,1}` rather than `?`, which no SQL layer can
 * mistake for a binding placeholder).
 */
export const CIDR_PATTERN =
  '^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]{0,1}[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]{0,1}[0-9])){3}/([0-9]|[12][0-9]|3[0-2])$';

const IPV4_RE = /^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$/;
const CIDR_RE = /^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}\/([0-9]|[12][0-9]|3[0-2])$/;

type Prop = Record<string, unknown>;

/** A CIDR pattern as converted templates spell it: an IPv4 octet rule, then a
 *  slash and a prefix length. Recognised, never rewritten. */
function looksLikeCidrPattern(p: unknown): boolean {
  return typeof p === 'string' && p.includes('25[0-5]') && /\/\(?[\[(0-9]/.test(p);
}

export function kindOf(prop: Prop): VarKind {
  const type = prop.type;
  if (type === 'boolean') return 'boolean';
  if (type === 'integer') return 'integer';
  if (type === 'array') return 'array';
  if (type === 'string') {
    if (Array.isArray(prop.enum)) return 'enum';
    if (prop.format === 'ipv4') return 'ipv4';
    if (looksLikeCidrPattern(prop.pattern)) return 'cidr';
    return 'string';
  }
  return 'other';
}

/** Keys that describe the VALUE's shape; dropped when the kind changes. */
const SHAPE_KEYS = [
  'type', 'enum', 'format', 'pattern', 'items', 'minimum', 'maximum', 'exclusiveMinimum',
  'exclusiveMaximum', 'multipleOf', 'minLength', 'maxLength', 'minItems', 'maxItems',
  'uniqueItems', 'properties', 'required', 'additionalProperties', 'default', 'const',
];

/** Change a variable's kind. Its label, level, secrecy and description stay;
 *  everything that described the old value's shape goes, default included —
 *  a default of the old type would be wrong for the new one. */
export function withKind(prop: Prop, kind: Exclude<VarKind, 'other'>): Prop {
  if (kindOf(prop) === kind) return prop;
  const out: Prop = {};
  for (const [k, v] of Object.entries(prop)) if (!SHAPE_KEYS.includes(k)) out[k] = v;
  switch (kind) {
    case 'string': out.type = 'string'; break;
    case 'integer': out.type = 'integer'; break;
    case 'boolean': out.type = 'boolean'; break;
    case 'enum': out.type = 'string'; out.enum = []; break;
    case 'ipv4': out.type = 'string'; out.format = 'ipv4'; break;
    case 'cidr': out.type = 'string'; out.pattern = CIDR_PATTERN; break;
    case 'array': out.type = 'array'; out.items = { type: 'string' }; break;
  }
  return out;
}

/** Set or remove one key, keeping the others in place and in order. */
export function setKey(prop: Prop, key: string, value: unknown): Prop {
  if (value === undefined) {
    if (!(key in prop)) return prop;
    const out: Prop = {};
    for (const [k, v] of Object.entries(prop)) if (k !== key) out[k] = v;
    return out;
  }
  return { ...prop, [key]: value };
}

// ── The schema, as rows ─────────────────────────────────────────────────────

export interface VarRow {
  key: string;
  prop: Prop;
  required: boolean;
}

export function emptySchema(): VarSchema {
  return { type: 'object', properties: {}, required: [] };
}

export function rowsOf(schema: VarSchema): VarRow[] {
  const props = schema.properties ?? {};
  const required = new Set(schema.required ?? []);
  return Object.keys(props).map((key) => ({ key, prop: props[key] ?? {}, required: required.has(key) }));
}

function withProperties(schema: VarSchema, properties: Record<string, Prop>, required: string[]): VarSchema {
  const out: VarSchema = { ...schema, properties };
  // `required` is written only when the schema had one or now needs one, so
  // a schema without it round-trips without one.
  if (required.length > 0 || schema.required !== undefined) out.required = required;
  return out;
}

export function setProp(schema: VarSchema, key: string, prop: Prop): VarSchema {
  const properties: Record<string, Prop> = {};
  for (const [k, v] of Object.entries(schema.properties ?? {})) properties[k] = k === key ? prop : v;
  return withProperties(schema, properties, schema.required ?? []);
}

export function setRequired(schema: VarSchema, key: string, required: boolean): VarSchema {
  const list = (schema.required ?? []).filter((k) => k !== key);
  if (required) {
    // Keep the declaration order rather than appending at the end.
    const order = Object.keys(schema.properties ?? {});
    list.push(key);
    list.sort((a, b) => order.indexOf(a) - order.indexOf(b));
  }
  return withProperties(schema, { ...(schema.properties ?? {}) }, list);
}

export function renameVar(schema: VarSchema, from: string, to: string): VarSchema {
  if (from === to) return schema;
  const properties: Record<string, Prop> = {};
  for (const [k, v] of Object.entries(schema.properties ?? {})) properties[k === from ? to : k] = v;
  const required = (schema.required ?? []).map((k) => (k === from ? to : k));
  return withProperties(schema, properties, required);
}

export function addVar(schema: VarSchema, key: string, prop: Prop): VarSchema {
  return withProperties(schema, { ...(schema.properties ?? {}), [key]: prop }, schema.required ?? []);
}

export function removeVar(schema: VarSchema, key: string): VarSchema {
  const properties: Record<string, Prop> = {};
  for (const [k, v] of Object.entries(schema.properties ?? {})) if (k !== key) properties[k] = v;
  return withProperties(schema, properties, (schema.required ?? []).filter((k) => k !== key));
}

// ── Defaults, as text ───────────────────────────────────────────────────────

/** Arrays of scalars are typed one item per line; anything deeper is JSON. */
export function arrayItemsAreScalar(prop: Prop): boolean {
  const items = prop.items as Prop | undefined;
  return !!items && (items.type === 'string' || items.type === 'integer');
}

export function defaultToText(prop: Prop): string {
  if (!('default' in prop)) return '';
  const v = prop.default;
  const kind = kindOf(prop);
  if (typeof v === 'string') return v;
  if (kind === 'array' && Array.isArray(v) && arrayItemsAreScalar(prop)) {
    return v.map((x) => String(x)).join('\n');
  }
  return JSON.stringify(v);
}

export type ParsedDefault =
  | { ok: true; value: unknown }          // value === undefined: no default
  | { ok: false; error: DefaultError };

/** Why a typed default is refused. The screen words it, naming the variable. */
export type DefaultError =
  | 'notInteger' | 'notBoolean' | 'notInEnum' | 'notIpv4' | 'notCidr' | 'notJson' | 'notArray'
  | 'secretDefault';

export function parseDefault(text: string, prop: Prop): ParsedDefault {
  if (text.trim() === '') return { ok: true, value: undefined };
  if (prop['x-obliwan-secret'] === true) return { ok: false, error: 'secretDefault' };
  const kind = kindOf(prop);
  switch (kind) {
    case 'string':
      return { ok: true, value: text };
    case 'ipv4':
      return IPV4_RE.test(text.trim()) ? { ok: true, value: text.trim() } : { ok: false, error: 'notIpv4' };
    case 'cidr':
      return CIDR_RE.test(text.trim()) ? { ok: true, value: text.trim() } : { ok: false, error: 'notCidr' };
    case 'enum': {
      const values = Array.isArray(prop.enum) ? prop.enum : [];
      return values.includes(text) ? { ok: true, value: text } : { ok: false, error: 'notInEnum' };
    }
    case 'integer': {
      const t = text.trim();
      return /^-?[0-9]+$/.test(t) ? { ok: true, value: Number(t) } : { ok: false, error: 'notInteger' };
    }
    case 'boolean':
      if (text === 'true') return { ok: true, value: true };
      if (text === 'false') return { ok: true, value: false };
      return { ok: false, error: 'notBoolean' };
    case 'array': {
      if (arrayItemsAreScalar(prop) && !text.trim().startsWith('[')) {
        const items = text.split('\n').map((s) => s.trim()).filter((s) => s.length > 0);
        const intItems = (prop.items as Prop).type === 'integer';
        if (intItems) {
          if (!items.every((s) => /^-?[0-9]+$/.test(s))) return { ok: false, error: 'notInteger' };
          return { ok: true, value: items.map(Number) };
        }
        return { ok: true, value: items };
      }
      try {
        const v = JSON.parse(text) as unknown;
        return Array.isArray(v) ? { ok: true, value: v } : { ok: false, error: 'notArray' };
      } catch {
        return { ok: false, error: 'notJson' };
      }
    }
    case 'other':
    default:
      try {
        return { ok: true, value: JSON.parse(text) as unknown };
      } catch {
        return { ok: false, error: 'notJson' };
      }
  }
}

// ── Defaults being typed ────────────────────────────────────────────────────

/**
 * A default as TYPED in the table. It is kept by the editor, not by the row:
 * a row is unmounted when the person switches tab, and a text that only the
 * row knew — an invalid one in particular — would vanish while the schema
 * kept the last value that parsed. Kept here, an invalid text survives the tab
 * switch and HOLDS THE SAVE (`liveDraft(...).error`), so what is saved is
 * never something other than what the screen shows.
 *
 * `base` is the default the draft was typed against (`defaultSig`), and `kind`
 * the kind it was parsed as: when either changes from elsewhere (the advanced
 * JSON, a kind change, ticking "secret"), the draft is stale and the schema's
 * own value is shown again.
 */
export interface DefaultDraft {
  text: string;
  base: string;
  kind: VarKind;
}

const NO_DEFAULT = '\u0000none';

/** The current default of a property, comparable across renders. */
export function defaultSig(prop: Prop): string {
  return 'default' in prop ? JSON.stringify(prop.default) : NO_DEFAULT;
}

/**
 * What the default cell shows for a draft: its text and, when it does not
 * parse, why. Null when there is no draft or it is stale — the cell then shows
 * the schema's value. A draft that parses to a value OTHER than the schema's
 * is stale too (the choices changed under it, say): the screen must not show
 * a value that is not the one saved.
 */
export function liveDraft(
  draft: DefaultDraft | undefined,
  prop: Prop | undefined,
): { text: string; error: DefaultError | null } | null {
  if (!draft || !prop || prop['x-obliwan-secret'] === true) return null;
  if (draft.kind !== kindOf(prop) || draft.base !== defaultSig(prop)) return null;
  const parsed = parseDefault(draft.text, prop);
  if (!parsed.ok) return { text: draft.text, error: parsed.error };
  const sig = parsed.value === undefined ? NO_DEFAULT : JSON.stringify(parsed.value);
  return sig === defaultSig(prop) ? { text: draft.text, error: null } : null;
}

// ── The advanced JSON view ──────────────────────────────────────────────────

export type JsonSchemaShapeError =
  | { kind: 'notObject' }
  | { kind: 'propertiesNotObject' }
  | { kind: 'propNotObject'; key: string }
  | { kind: 'requiredNotList' };

/**
 * Whether a parsed JSON text has the shape every other part of the editor
 * relies on: an object, whose `properties` (when present) is an object of
 * OBJECTS, and whose `required` (when present) is a list of names. A `null`
 * or a string where a variable's description belongs is valid JSON, and the
 * table, the analysis and the preview would all crash on it.
 */
export function jsonSchemaShapeError(v: unknown): JsonSchemaShapeError | null {
  const isObj = (x: unknown): x is Record<string, unknown> =>
    typeof x === 'object' && x !== null && !Array.isArray(x);
  if (!isObj(v)) return { kind: 'notObject' };
  if ('properties' in v) {
    if (!isObj(v.properties)) return { kind: 'propertiesNotObject' };
    for (const [key, prop] of Object.entries(v.properties)) {
      if (!isObj(prop)) return { kind: 'propNotObject', key };
    }
  }
  if ('required' in v && !(Array.isArray(v.required) && v.required.every((r) => typeof r === 'string'))) {
    return { kind: 'requiredNotList' };
  }
  return null;
}

// ── Analysis: the table against the body ────────────────────────────────────

export type SchemaProblem =
  | { kind: 'badKey'; key: string }
  | { kind: 'forbiddenKey'; key: string }
  | { kind: 'secretDefault'; key: string }
  | { kind: 'emptyEnum'; key: string }
  | { kind: 'defaultNotInEnum'; key: string }
  | { kind: 'unknownLevel'; key: string; level: string }
  | { kind: 'factAtStoredLevel'; key: string }
  | { kind: 'requiredUndeclared'; key: string };

export interface SchemaAnalysis {
  /** Refusals: the save is held until they are fixed. */
  problems: SchemaProblem[];
  /** Read by the body, declared nowhere, and not a context fact. */
  undeclared: { key: string; lines: number[] }[];
  /** Declared, never read by the body. Information, not an error. */
  unused: string[];
  /** Context facts the body reads (`device`, `box`, `site`). */
  facts: string[];
}

export function analyseSchema(
  schema: VarSchema,
  used: Map<string, number[]>,
  vocabulary: { levels: string[]; renderTimeLevels: string[]; contextFacts: string[]; reservedFactKeys: string[] } | null,
): SchemaAnalysis {
  const problems: SchemaProblem[] = [];
  const props = schema.properties ?? {};
  for (const [key, prop] of Object.entries(props)) {
    if (FORBIDDEN_KEYS.has(key)) problems.push({ kind: 'forbiddenKey', key });
    else if (!VARIABLE_KEY_RE.test(key)) problems.push({ kind: 'badKey', key });
    if (prop['x-obliwan-secret'] === true && 'default' in prop) problems.push({ kind: 'secretDefault', key });
    if (kindOf(prop) === 'enum') {
      const values = prop.enum as unknown[];
      if (values.length === 0) problems.push({ kind: 'emptyEnum', key });
      else if ('default' in prop && !values.includes(prop.default)) problems.push({ kind: 'defaultNotInEnum', key });
    }
    const level = prop['x-obliwan-level'];
    if (vocabulary && typeof level === 'string' && !vocabulary.levels.includes(level)) {
      problems.push({ kind: 'unknownLevel', key, level });
    }
    if (
      vocabulary && vocabulary.reservedFactKeys.includes(key)
      && !(typeof level === 'string' && vocabulary.renderTimeLevels.includes(level))
    ) {
      problems.push({ kind: 'factAtStoredLevel', key });
    }
  }
  for (const r of schema.required ?? []) {
    if (!(r in props)) problems.push({ kind: 'requiredUndeclared', key: r });
  }

  const facts = new Set(vocabulary?.contextFacts ?? []);
  const undeclared: { key: string; lines: number[] }[] = [];
  const usedFacts: string[] = [];
  for (const [key, lines] of used) {
    if (key in props) continue;
    if (facts.has(key)) usedFacts.push(key);
    else undeclared.push({ key, lines });
  }
  const unused = Object.keys(props).filter((k) => !used.has(k));
  return { problems, undeclared, unused, facts: usedFacts };
}

// ── Sample values for the preview ───────────────────────────────────────────

/** Turn a typed sample into the JSON value the declaration expects. Uses the
 *  same parser as the default column, so "10" for an integer is 10. */
export function parseSample(text: string, prop: Prop | undefined): ParsedDefault {
  if (!prop) {
    // Undeclared name (a context fact such as `box`): JSON when it looks like
    // JSON, otherwise the text itself.
    const t = text.trim();
    if (t.startsWith('{') || t.startsWith('[')) {
      try { return { ok: true, value: JSON.parse(t) as unknown }; } catch { return { ok: false, error: 'notJson' }; }
    }
    return { ok: true, value: text };
  }
  // A declared SECRET is refused here exactly as a secret default is: the
  // preview never sends a typed value for one (see `secretPlaceholder`).
  return parseDefault(text, prop);
}

/** The placeholder a REDACTED render shows for a secret — the resolver's own
 *  spelling (`__OBLIWAN_SECRET_<KEY>__`), so a preview reads like the real
 *  redacted render does. Never a credential: nobody types it. */
export function secretPlaceholder(key: string): string {
  return `__OBLIWAN_SECRET_${key.toUpperCase()}__`;
}
