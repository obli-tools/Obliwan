import type { VarSchema } from '@/api/templates.api';
import { setKey } from './varSchemaModel';

/**
 * Which values the preview asks for, which it lists as already set, and the
 * schema it sends with a scratch render — as pure functions, so the rule can
 * be checked against the server's own resolver without a browser.
 *
 * THE RULE. A preview sample reaches the render as an extra context key, and
 * the server refuses an extra key that collides with anything it resolved for
 * the witness router: a value stored at any level of its chain (declared by
 * the revision or not), or a declaration's default. Two exceptions follow
 * from the resolver itself: a variable declared `computed` or `bench` has any
 * stored row set aside, and a scratch render sends a sampled variable without
 * its `default` and outside `required` (`scratchSchemaFor`). So a sample is
 * offered only where nothing would collide, and what is stored is listed.
 */

/** Every key the witness router's chain resolves before any template applies,
 *  and where it is set. */
export type StoredValues = Map<string, { sourceName: string }>;

/** `GET /variables/devices/:id` answers the resolver's report, whose
 *  `variables` is an object keyed by variable; a list of entries is read too.
 *  Defensive on purpose: the client type of that endpoint is loose. */
export function storedValuesOf(raw: unknown): StoredValues {
  const out: StoredValues = new Map();
  const vars = raw && typeof raw === 'object' ? (raw as { variables?: unknown }).variables : undefined;
  const add = (key: unknown, v: unknown) => {
    if (typeof key !== 'string') return;
    const e = (v && typeof v === 'object' ? v : {}) as Record<string, unknown>;
    const name = [e.sourceName, e.source, e.scope].find((x) => typeof x === 'string') as string | undefined;
    out.set(key, { sourceName: name ?? '' });
  };
  if (Array.isArray(vars)) for (const v of vars) add((v as { key?: unknown } | null)?.key, v);
  else if (vars && typeof vars === 'object') for (const [k, v] of Object.entries(vars)) add(k, v);
  return out;
}

export interface SampleSlot {
  key: string;
  prop?: Record<string, unknown>;
  /** False: shown, but this path cannot take a sample for it. */
  sampleable: boolean;
}

export interface SamplePlan {
  /** Values a router render does not have. */
  needed: SampleSlot[];
  /** Declared values the router has none for (with the right to write only). */
  optional: SampleSlot[];
  /** Already resolved for the router: listed, never sampled. */
  fromStore: { key: string; sourceName: string }[];
  /** Declared secrets the router has no value for — the only ones a
   *  placeholder may be sent for. */
  missingSecrets: string[];
  /** Every key a typed sample may be sent for. */
  sampleKeys: Set<string>;
}

export function planSamples(input: {
  used: Iterable<string>;
  schema: VarSchema;
  deviceRenderFacts: string[];
  renderTimeLevels: string[];
  /** May render an unsaved body (scratch path). */
  canWrite: boolean;
  /** undefined / null: not known — nothing is treated as stored. */
  stored: StoredValues | null | undefined;
}): SamplePlan {
  const { schema, deviceRenderFacts, renderTimeLevels, canWrite, stored } = input;
  const props = schema.properties ?? {};
  const required = new Set(schema.required ?? []);
  const isRenderTime = (k: string): boolean => {
    const level = props[k]?.['x-obliwan-level'];
    return typeof level === 'string' && renderTimeLevels.includes(level);
  };
  const storedFor = (k: string) => (stored && !isRenderTime(k) ? stored.get(k) ?? null : null);

  const needed: SampleSlot[] = [];
  const optional: SampleSlot[] = [];
  const fromStore: { key: string; sourceName: string }[] = [];
  for (const key of input.used) {
    if (key in props || deviceRenderFacts.includes(key)) continue;
    const s = storedFor(key);
    if (s) fromStore.push({ key, sourceName: s.sourceName });
    else needed.push({ key, sampleable: true });       // `box`, `site`, or an undeclared name
  }
  for (const [key, prop] of Object.entries(props)) {
    if (prop['x-obliwan-secret'] === true) continue; // never typed here
    if (isRenderTime(key)) {
      // A saved revision's schema is sent as it is: a required render-time
      // key is reported missing before a sample is looked at, and a default
      // would collide with one.
      if (canWrite) needed.push({ key, prop, sampleable: true });
      else if (required.has(key)) needed.push({ key, prop, sampleable: false });
      else if (!('default' in prop)) needed.push({ key, prop, sampleable: true });
      continue;                                      // else: its default renders
    }
    const s = storedFor(key);
    if (s) fromStore.push({ key, sourceName: s.sourceName });
    else if (canWrite) optional.push({ key, prop, sampleable: true });
  }
  const missingSecrets = Object.entries(props)
    .filter(([k, p]) => p['x-obliwan-secret'] === true && !storedFor(k))
    .map(([k]) => k);
  const sampleKeys = new Set([
    ...needed.filter((s) => s.sampleable).map((s) => s.key),
    ...optional.map((s) => s.key),
  ]);
  return { needed, optional, fromStore, missingSecrets, sampleKeys };
}

/** The schema sent with a scratch render: a sampled variable KEEPS its
 *  declaration (a render-time level must still set a stored row aside) but
 *  nothing that would fill its slot before the sample — no `default`, not
 *  `required`. */
export function scratchSchemaFor(schema: VarSchema, sampled: ReadonlySet<string>): VarSchema {
  const properties: Record<string, Record<string, unknown>> = {};
  for (const [k, p] of Object.entries(schema.properties ?? {})) {
    properties[k] = sampled.has(k) ? setKey(p, 'default', undefined) : p;
  }
  return {
    ...schema,
    properties,
    ...(schema.required ? { required: schema.required.filter((k) => !sampled.has(k)) } : {}),
  };
}
