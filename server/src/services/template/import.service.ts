// ============================================================================
// import.service.ts — template FILES into DRAFT revisions
// ============================================================================
//
// Two file formats, both plain JSON:
//
//   obliwan-template/1        { format, name, description, brand, modelPattern,
//                               osMin, osMax, varSchema, sectionSeverity?,
//                               renderOptions?, notes?, body }
//   obliwan-template-bundle/1 { format, templates: [ obliwan-template/1, ... ] }
//
// ┌─ WHAT AN IMPORT IS, AND WHAT IT IS NOT ──────────────────────────────────┐
// │ An import is AUTHORING. It writes template code that the render worker   │
// │ will later execute on the server that holds every customer's            │
// │ credentials, which is why its route is `TEMPLATE_WRITE` and why          │
// │ every field goes through the SAME validators as a hand-made template:    │
// │ `createTemplateSchema` for the template row, `createRevisionSchema` for  │
// │ the revision, the Nunjucks parse `createDraft` performs, and the ajv     │
// │ compile the resolver will run at render time. Nothing here re-states a   │
// │ rule those four already hold; a file that passes is a file the regular   │
// │ endpoints would have accepted one call at a time.                        │
// │                                                                          │
// │ An import NEVER PUBLISHES. Every revision it writes is a `draft`;        │
// │ publishing freezes a revision and pins its partials, and that stays a    │
// │ human click on a revision somebody has looked at.                        │
// │                                                                          │
// │ An import NEVER EDITS AN EXISTING TEMPLATE ROW. When the tenant already  │
// │ has a template with the same name and brand (the identity of             │
// │ `templates_tenant_name_uq`: tenant, lower(name), brand), the file becomes │
// │ a new draft revision of it, and a description or model pattern that      │
// │ differs from the stored one is REPORTED, not written: the model pattern  │
// │ decides which routers the already-published revisions apply to, and a    │
// │ file is not the place to change that silently.                          │
// │                                                                          │
// │ The tenant is the caller's session tenant, passed in by the controller.  │
// │ A file carries no tenant and no field of it is read as one.              │
// └──────────────────────────────────────────────────────────────────────────┘
//
// ALL-OR-NOTHING PER TEMPLATE. Each entry of a bundle is its own transaction:
// either its template (when new) AND its draft revision exist afterwards, or
// neither does. One broken entry does not stop its siblings, and the report
// says, per entry, what happened and why.
//
// The dry run writes nothing to the database. It runs the same validation and
// the same name lookup as the real import, and it simulates the bundle in
// order — an entry whose name an EARLIER valid entry of the same file creates
// is reported as a new revision, because that is what the real import does
// with it. It does touch PROCESS state in one place, and on purpose: each
// schema is compiled by the resolver's own validator (`compileVarSchema`),
// exactly as the first render will, and that validator keeps what it compiled.
// Which is why a schema that would REGISTER something in that shared compiler
// — a `$id`, or a `$ref` leaving the schema — is refused before it is compiled
// (`schemaReferenceIssues`): one tenant's schema must not be able to claim a
// name that refuses, or answers for, every other tenant's.
//
// AN ENTRY IDENTICAL TO WHAT IT WOULD FOLLOW IS NOT WRITTEN. When the entry's
// body, variables, OS window, section severity and render options are those of
// the template's latest revision (or of an earlier entry of the same file),
// the entry is `unchanged`: importing it again would only stack a second,
// byte-identical draft that somebody then has to sort out before publishing.
// Notes are not compared — they do not change what a router receives.
// ============================================================================

import type { Knex } from 'knex';
import type { z } from 'zod';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { createRevisionSchema, createTemplateSchema } from '../../validators/template.schema';
import { versionService, TemplateVersionError } from './version.service';
import {
  ENTRY_NAME, extractDependencies, sha256, TemplateSyntaxError, DynamicTemplateRefError,
} from './loader';
import { compileVarSchema, VarSchemaError, type VarSchema } from './variableResolver.service';

export const TEMPLATE_FILE_FORMAT = 'obliwan-template/1';
export const TEMPLATE_BUNDLE_FORMAT = 'obliwan-template-bundle/1';

/** A bundle is a handful of customer templates, not a migration. The cap keeps
 *  one request from parsing an unbounded number of executable bodies; with
 *  templates of the size ObliWAN converts (~30 KB each), the global 1 MB JSON
 *  body limit (`app.ts`) is reached first. */
export const MAX_IMPORT_TEMPLATES = 50;

/** The template-row half and the revision half of a file. Everything else but
 *  `format` is refused by name — a misspelt `varschema` silently dropped would
 *  import a template with no declared variables. */
const TEMPLATE_FIELDS = ['name', 'description', 'brand', 'modelPattern'] as const;
const REVISION_FIELDS = [
  'body', 'varSchema', 'sectionSeverity', 'osMin', 'osMax', 'renderOptions', 'notes',
] as const;
const KNOWN_FIELDS: ReadonlySet<string> = new Set<string>([
  'format', ...TEMPLATE_FIELDS, ...REVISION_FIELDS,
]);
const BUNDLE_FIELDS: ReadonlySet<string> = new Set<string>(['format', 'templates']);

/** The request itself is not an import file. A 400 for the whole call. */
export class TemplateImportFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TemplateImportFormatError';
  }
}

/**
 * One refusal, located. `variable` is set when the refusal is about one
 * declared variable (`varSchema.properties.<name>...`), so the screen can name
 * the variable instead of printing a JSON path at somebody who never wrote one.
 */
export interface ImportIssue {
  path: string;
  variable: string | null;
  message: string;
}

export type ImportAction = 'create' | 'new-revision' | 'unchanged';
/** `unchanged`: identical to what it would follow (`sameAs`), so not written. */
export type ImportOutcome = 'created' | 'unchanged' | 'skipped' | 'failed';

/** What an `unchanged` entry is identical to: a stored revision, or an earlier
 *  entry of the same file. */
export type ImportSameAs =
  | { kind: 'revision'; revisionId: string; revision: number; status: string }
  | { kind: 'entry'; index: number };

export interface ImportItemReport {
  /** Position in the file, 0-based. Two entries may share a name. */
  index: number;
  name: string;
  brand: string | null;
  action: ImportAction;
  /** The tenant template this entry lands in, when it already exists. */
  existingTemplateId: string | null;
  /** Set when `action` / `outcome` is `unchanged`. */
  sameAs: ImportSameAs | null;
  errors: ImportIssue[];
  warnings: string[];
  /** null on a dry run. */
  outcome: ImportOutcome | null;
  templateId: string | null;
  revisionId: string | null;
  revision: number | null;
}

export interface ImportReport {
  dryRun: boolean;
  format: typeof TEMPLATE_FILE_FORMAT | typeof TEMPLATE_BUNDLE_FORMAT;
  /** The tenant the import writes into — the session's, never the file's. */
  tenant: { id: number; name: string | null };
  items: ImportItemReport[];
  summary: {
    total: number;
    /** Entries that pass validation — `unchanged` ones included. */
    valid: number;
    invalid: number;
    /** Valid entries that are not written because nothing in them changed. */
    unchanged: number;
    created: number;
    failed: number;
    skipped: number;
  };
}

export interface ExistingTemplate {
  id: string;
  name: string;
  brand: string;
  status: string;
  description: string | null;
  model_pattern: string | null;
}

/** The columns an entry is compared against to decide `unchanged`. */
export interface LatestRevision {
  id: string;
  revision: number;
  status: string;
  body_sha256: string;
  var_schema: unknown;
  section_severity: unknown;
  os_min: string | null;
  os_max: string | null;
  render_options: unknown;
}

/**
 * The two reads an import needs. Injected so the dry run can be exercised
 * without a database; production uses `dbLookup`.
 */
export interface TemplateImportLookup {
  /** The TENANT's template with this name and brand — never a library row: a
   *  library template is read-only through the API, so a same-named library
   *  template is not a target, it is a neighbour. */
  findTemplate(
    tenantId: number,
    name: string,
    brand: string,
    executor: Knex | Knex.Transaction,
  ): Promise<ExistingTemplate | null>;
  /** The highest-numbered revision of a template `findTemplate` returned, or
   *  null when it has none yet. */
  latestRevision(templateId: string, executor: Knex | Knex.Transaction): Promise<LatestRevision | null>;
  tenantName(tenantId: number): Promise<string | null>;
}

export const dbLookup: TemplateImportLookup = {
  async findTemplate(tenantId, name, brand, executor) {
    // `lower(name) = lower(?)` and not a JS `toLowerCase()`: the unique index
    // is on PostgreSQL's `lower(name)`, and only PostgreSQL's own folding is
    // guaranteed to agree with it on a name like "Château".
    const row = (await executor('templates')
      .where('tenant_id', tenantId)
      .andWhere('brand', brand)
      .whereRaw('lower(name) = lower(?)', [name.trim()])
      .first('id', 'name', 'brand', 'status', 'description', 'model_pattern')) as
      ExistingTemplate | undefined;
    return row ? { ...row, id: String(row.id) } : null;
  },
  async latestRevision(templateId, executor) {
    // `templateId` comes from `findTemplate`, which is tenant-scoped.
    const row = (await executor('template_revisions')
      .where('template_id', templateId)
      .orderBy('revision', 'desc')
      .first(
        'id', 'revision', 'status', 'body_sha256', 'var_schema', 'section_severity',
        'os_min', 'os_max', 'render_options',
      )) as LatestRevision | undefined;
    return row ? { ...row, id: String(row.id), revision: Number(row.revision) } : null;
  },
  async tenantName(tenantId) {
    const row = (await db('tenants').where('id', tenantId).first('name')) as
      { name: string } | undefined;
    return row?.name ?? null;
  },
};

// ============================================================================
// Envelope
// ============================================================================

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Split the request into its entries, or refuse the request as a whole. */
export function unpackImportFile(payload: unknown): {
  format: ImportReport['format'];
  entries: unknown[];
} {
  if (!isPlainObject(payload)) {
    throw new TemplateImportFormatError(
      `Expected a JSON object in the "${TEMPLATE_FILE_FORMAT}" or "${TEMPLATE_BUNDLE_FORMAT}" format.`,
    );
  }
  const format = payload.format;
  if (format === TEMPLATE_FILE_FORMAT) return { format, entries: [payload] };
  if (format !== TEMPLATE_BUNDLE_FORMAT) {
    throw new TemplateImportFormatError(
      `Unknown file format ${JSON.stringify(format ?? null)}. Expected "${TEMPLATE_FILE_FORMAT}" ` +
        `(one template) or "${TEMPLATE_BUNDLE_FORMAT}" (several).`,
    );
  }
  const unknown = Object.keys(payload).filter((k) => !BUNDLE_FIELDS.has(k));
  if (unknown.length > 0) {
    throw new TemplateImportFormatError(
      `Unknown field(s) in the bundle: ${unknown.join(', ')}. A bundle carries "format" and "templates" only.`,
    );
  }
  const templates = payload.templates;
  if (!Array.isArray(templates) || templates.length === 0) {
    throw new TemplateImportFormatError('The bundle has no "templates" array, or it is empty.');
  }
  if (templates.length > MAX_IMPORT_TEMPLATES) {
    throw new TemplateImportFormatError(
      `The bundle holds ${templates.length} templates; at most ${MAX_IMPORT_TEMPLATES} are imported in one call.`,
    );
  }
  return { format, entries: templates };
}

// ============================================================================
// Per-entry validation
// ============================================================================

type TemplateInput = z.infer<typeof createTemplateSchema>;
type RevisionInput = z.infer<typeof createRevisionSchema>;

interface ValidatedEntry {
  index: number;
  name: string;
  brand: string | null;
  errors: ImportIssue[];
  warnings: string[];
  template: TemplateInput | null;
  revision: RevisionInput | null;
}

/** `varSchema.properties.<name>.…` names one variable; nothing else does. */
function issueFromPath(path: (string | number)[], message: string): ImportIssue {
  const variable =
    path[0] === 'varSchema' && path[1] === 'properties' && typeof path[2] === 'string'
      ? path[2]
      : null;
  return { path: path.map(String).join('.'), variable, message };
}

function zodIssues(error: z.ZodError): ImportIssue[] {
  return error.issues.map((i) => issueFromPath(i.path, i.message));
}

function pick(entry: Record<string, unknown>, fields: readonly string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const f of fields) if (f in entry) out[f] = entry[f];
  return out;
}

/** Keywords whose value is DATA, not a schema: a `$id` inside a default is a
 *  string in a value, and the compiler never registers it. */
const DATA_KEYWORDS: ReadonlySet<string> = new Set(['default', 'const', 'enum', 'examples']);
/** Keywords whose value maps NAMES to schemas: the names are not keywords (a
 *  nested object may well have a property called `$id`), the values are. */
const MAP_KEYWORDS: ReadonlySet<string> = new Set([
  'properties', 'patternProperties', 'definitions', '$defs', 'dependentSchemas',
]);

/**
 * The places a var_schema would register something in the resolver's SHARED
 * compiler, or reach outside itself through it.
 *
 *  - `$id` — ajv files a schema under its id for the life of the process. A
 *    second schema with the same id (the operator's own corrected file, or
 *    another tenant's) is then refused, at import and at every render, until
 *    the server restarts.
 *  - a `$ref` / `$dynamicRef` that does not start with `#` — it resolves
 *    against whatever other schemas registered under that name, i.e. against
 *    another template's schema, possibly another tenant's.
 *
 * A converted template needs neither: its variables are named properties.
 */
export function schemaReferenceIssues(varSchema: unknown): ImportIssue[] {
  const out: ImportIssue[] = [];
  const walk = (node: unknown, path: string[]): void => {
    if (Array.isArray(node)) {
      node.forEach((n, i) => walk(n, [...path, String(i)]));
      return;
    }
    if (!isPlainObject(node)) return;
    for (const [k, v] of Object.entries(node)) {
      if (k === '$id') {
        out.push(issueFromPath(
          ['varSchema', ...path, k],
          '"$id" is not allowed in a variable schema: the server checks every template\'s variables ' +
            'with one shared validator, and an identifier registered there by one schema would make ' +
            'every other schema using it fail until the server restarts',
        ));
        continue;
      }
      if ((k === '$ref' || k === '$dynamicRef') && !(typeof v === 'string' && v.startsWith('#'))) {
        out.push(issueFromPath(
          ['varSchema', ...path, k],
          `"${k}" may only point inside this schema (a value starting with "#"): a reference to ` +
            'anything else would be resolved against the schemas of other templates',
        ));
        continue;
      }
      if (DATA_KEYWORDS.has(k)) continue;
      if (MAP_KEYWORDS.has(k) && isPlainObject(v)) {
        for (const [name, sub] of Object.entries(v)) walk(sub, [...path, k, name]);
        continue;
      }
      walk(v, [...path, k]);
    }
  };
  walk(varSchema, []);
  return out;
}

export function validateEntry(entry: unknown, index: number): ValidatedEntry {
  const errors: ImportIssue[] = [];
  const warnings: string[] = [];
  if (!isPlainObject(entry)) {
    return {
      index, name: '', brand: null, warnings, template: null, revision: null,
      errors: [{ path: '', variable: null, message: 'this entry is not a JSON object' }],
    };
  }

  const name = typeof entry.name === 'string' ? entry.name.trim() : '';
  const brand = typeof entry.brand === 'string' ? entry.brand : null;

  if (entry.format !== TEMPLATE_FILE_FORMAT) {
    errors.push({
      path: 'format',
      variable: null,
      message: `expected "${TEMPLATE_FILE_FORMAT}", got ${JSON.stringify(entry.format ?? null)}`,
    });
  }
  for (const k of Object.keys(entry)) {
    if (!KNOWN_FIELDS.has(k)) {
      errors.push({
        path: k,
        variable: null,
        message: `unknown field — not part of ${TEMPLATE_FILE_FORMAT}`,
      });
    }
  }

  // The template row: the exact schema `POST /templates` uses. `status` is not
  // picked — an import cannot create an archived template, nor un-archive one.
  const tpl = createTemplateSchema.safeParse(pick(entry, TEMPLATE_FIELDS));
  if (!tpl.success) errors.push(...zodIssues(tpl.error));
  // `min(1)` accepts "   ", which `templates_name_chk` (btrim(name) <> '')
  // refuses — as a 500, if nothing says so first.
  if (typeof entry.name === 'string' && entry.name.length > 0 && name.length === 0) {
    errors.push({ path: 'name', variable: null, message: 'the name is blank' });
  }

  // The revision: the exact schema `POST /templates/:id/revisions` uses.
  const rev = createRevisionSchema.safeParse(pick(entry, REVISION_FIELDS));
  if (!rev.success) errors.push(...zodIssues(rev.error));

  if (rev.success) {
    // What `createDraft` will do: parse the body. Throws on a syntax error and
    // on a computed `{% include %}`, which no loader may ever resolve.
    try {
      const refs = extractDependencies(rev.data.body, ENTRY_NAME);
      const names = [...new Set(refs.map((r) => r.name))];
      if (names.length > 0) {
        warnings.push(
          `the body references ${names.length === 1 ? 'the partial' : 'the partials'} ` +
            `${names.map((n) => `"${n}"`).join(', ')}: ` +
            `${names.length === 1 ? 'it' : 'they'} must exist in this tenant or in the library ` +
            'before this revision can be rendered or published',
        );
      }
    } catch (err) {
      errors.push({ path: 'body', variable: null, message: (err as Error).message });
    }
    // What the resolver will do on the first render: compile the schema with
    // ajv. A schema that only fails there fails on the first router. Never
    // compiled when it would register a name in that shared compiler (see
    // `schemaReferenceIssues`) — a dry run must not be what claims it.
    if (rev.data.varSchema) {
      const references = schemaReferenceIssues(rev.data.varSchema);
      if (references.length > 0) {
        errors.push(...references);
      } else {
        try {
          compileVarSchema(rev.data.varSchema as VarSchema);
        } catch (err) {
          errors.push({ path: 'varSchema', variable: null, message: (err as Error).message });
        }
      }
    }
  }

  return {
    index,
    name,
    brand,
    errors,
    warnings,
    template: tpl.success ? tpl.data : null,
    revision: rev.success ? rev.data : null,
  };
}

function identityKey(name: string, brand: string): string {
  return `${brand}\u0000${name.toLowerCase()}`;
}

/** JSON with object keys sorted: `jsonb` does not keep key order, so a stored
 *  schema and the same schema read from a file must be compared this way. */
function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  if (isPlainObject(v)) {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(',')}}`;
  }
  return JSON.stringify(v ?? null);
}

/** A jsonb column as read back (node-pg parses it; a `json` text is tolerated). */
function storedJson(v: unknown): unknown {
  if (typeof v !== 'string') return v ?? {};
  try { return JSON.parse(v) as unknown; } catch { return v; }
}

/**
 * What decides `unchanged`: everything that changes what a router receives,
 * spelt the way `createDraft` stores it (`?? {}`, `?? null`, and a JSON round
 * trip that drops `undefined`). Notes are left out on purpose.
 */
function revisionFingerprint(r: {
  bodySha256: string;
  varSchema: unknown;
  sectionSeverity: unknown;
  osMin: string | null;
  osMax: string | null;
  renderOptions: unknown;
}): string {
  const json = (v: unknown): string => canonicalJson(JSON.parse(JSON.stringify(v ?? {})) as unknown);
  return [
    r.bodySha256, json(r.varSchema), json(r.sectionSeverity), r.osMin ?? '', r.osMax ?? '', json(r.renderOptions),
  ].join('\u0000');
}

function entryFingerprint(rev: RevisionInput): string {
  return revisionFingerprint({
    bodySha256: sha256(rev.body),
    varSchema: rev.varSchema,
    sectionSeverity: rev.sectionSeverity,
    osMin: rev.osMin ?? null,
    osMax: rev.osMax ?? null,
    renderOptions: rev.renderOptions,
  });
}

function storedFingerprint(row: LatestRevision): string {
  return revisionFingerprint({
    bodySha256: row.body_sha256,
    varSchema: storedJson(row.var_schema),
    sectionSeverity: storedJson(row.section_severity),
    osMin: row.os_min,
    osMax: row.os_max,
    renderOptions: storedJson(row.render_options),
  });
}

/** What the import would do with an entry whose template already exists. */
function existingWarnings(entry: ValidatedEntry, existing: ExistingTemplate): string[] {
  const out: string[] = [];
  if (existing.status !== 'active') {
    out.push(
      `the existing template is ${existing.status}: the new draft will not render until the ` +
        'template is made active again',
    );
  }
  const tpl = entry.template;
  if (tpl) {
    const fileDescription = tpl.description ?? null;
    if (fileDescription !== null && fileDescription !== existing.description) {
      out.push(
        "the file's description differs from the existing template's; the existing one is kept",
      );
    }
    const filePattern = tpl.modelPattern ?? null;
    if (filePattern !== existing.model_pattern) {
      out.push(
        `the file's model pattern (${filePattern ?? 'none'}) differs from the existing template's ` +
          `(${existing.model_pattern ?? 'none'}); the existing one is kept, because it decides ` +
          'which routers the published revisions apply to',
      );
    }
  }
  return out;
}

// ============================================================================
// Dry run
// ============================================================================

/**
 * `valid` / `invalid` count the VALIDATION verdict (on an import, an invalid
 * entry is exactly a skipped one); `unchanged` counts the valid entries that
 * are not written because they repeat what they would follow (planned on a
 * dry run, decided on an import); `created` / `failed` / `skipped` count what
 * the write did, and are all zero on a dry run.
 */
function buildReport(
  dryRun: boolean,
  format: ImportReport['format'],
  tenant: ImportReport['tenant'],
  items: ImportItemReport[],
): ImportReport {
  const count = (p: (i: ImportItemReport) => boolean): number => items.filter(p).length;
  const invalid = dryRun
    ? count((i) => i.errors.length > 0)
    : count((i) => i.outcome === 'skipped');
  return {
    dryRun,
    format,
    tenant,
    items,
    summary: {
      total: items.length,
      valid: items.length - invalid,
      invalid,
      unchanged: dryRun
        ? count((i) => i.errors.length === 0 && i.action === 'unchanged')
        : count((i) => i.outcome === 'unchanged'),
      created: count((i) => i.outcome === 'created'),
      failed: count((i) => i.outcome === 'failed'),
      skipped: count((i) => i.outcome === 'skipped'),
    },
  };
}

/**
 * Validate every entry and decide, for each valid one, whether it creates a
 * template, adds a draft revision to an existing one, or is `unchanged` (it
 * repeats the revision it would follow). Writes nothing.
 */
export async function planImport(
  tenantId: number,
  payload: unknown,
  lookup: TemplateImportLookup = dbLookup,
  executor: Knex | Knex.Transaction = db,
): Promise<{ format: ImportReport['format']; entries: ValidatedEntry[]; items: ImportItemReport[] }> {
  const { format, entries } = unpackImportFile(payload);
  const validated = entries.map((e, i) => validateEntry(e, i));

  /** Per identity: the VALID entry of this file that creates the template. */
  const createdEarlier = new Map<string, number>();
  /** Per identity: the last VALID entry of this file that would write a
   *  revision — what a later entry of the same name would follow. */
  const plannedEarlier = new Map<string, { index: number; fingerprint: string }>();
  const items: ImportItemReport[] = [];
  for (const v of validated) {
    let action: ImportAction = 'create';
    let existingTemplateId: string | null = null;
    let sameAs: ImportSameAs | null = null;
    const warnings = [...v.warnings];

    if (v.brand !== null && v.name.length > 0) {
      const existing = await lookup.findTemplate(tenantId, v.name, v.brand, executor);
      const key = identityKey(v.name, v.brand);
      const earlier = plannedEarlier.get(key);
      const creator = createdEarlier.get(key);

      // Identical to what it would follow: the previous entry of this file
      // with the same identity when there is one (it will be the latest
      // revision by then), else the template's latest stored revision.
      if (v.errors.length === 0 && v.revision) {
        const fingerprint = entryFingerprint(v.revision);
        if (earlier) {
          if (earlier.fingerprint === fingerprint) sameAs = { kind: 'entry', index: earlier.index };
        } else if (existing) {
          const latest = await lookup.latestRevision(existing.id, executor);
          if (latest && storedFingerprint(latest) === fingerprint) {
            sameAs = {
              kind: 'revision', revisionId: latest.id, revision: latest.revision, status: latest.status,
            };
          }
        }
        if (!sameAs) plannedEarlier.set(key, { index: v.index, fingerprint });
      }

      if (existing) {
        action = 'new-revision';
        existingTemplateId = existing.id;
        warnings.push(...existingWarnings(v, existing));
      } else if (creator !== undefined) {
        action = 'new-revision';
        if (!sameAs) {
          warnings.push(
            `entry #${creator + 1} of this file has the same name and brand: ` +
              'it creates the template, and this entry becomes its next draft revision',
          );
        }
      } else if (v.errors.length === 0) {
        createdEarlier.set(key, v.index);
      }
      if (sameAs) action = 'unchanged';
    }

    items.push({
      index: v.index,
      name: v.name,
      brand: v.brand,
      action,
      existingTemplateId,
      sameAs,
      errors: v.errors,
      warnings,
      outcome: null,
      templateId: existingTemplateId,
      revisionId: null,
      revision: null,
    });
  }
  return { format, entries: validated, items };
}

export async function dryRunImport(
  tenantId: number,
  payload: unknown,
  lookup: TemplateImportLookup = dbLookup,
): Promise<ImportReport> {
  const { format, items } = await planImport(tenantId, payload, lookup);
  return buildReport(true, format, { id: tenantId, name: await lookup.tenantName(tenantId) }, items);
}

// ============================================================================
// The import itself
// ============================================================================

/** A refusal from the write path, worded for the operator. `unexpected` marks
 *  an error that is logged in full and reported without its internals. */
function issueFromWriteError(err: unknown): { issue: ImportIssue; unexpected: boolean } {
  if (
    err instanceof TemplateVersionError || err instanceof TemplateSyntaxError
    || err instanceof DynamicTemplateRefError || err instanceof VarSchemaError
  ) {
    return { issue: { path: '', variable: null, message: err.message }, unexpected: false };
  }
  if ((err as { code?: unknown }).code === '23505') {
    return {
      issue: {
        path: '',
        variable: null,
        message:
          'another write created the same template or revision at the same moment; ' +
          'run the import again — it will add a new draft revision',
      },
      unexpected: false,
    };
  }
  return {
    issue: {
      path: '',
      variable: null,
      message: 'the server could not write this template (see the server log); nothing was kept for it',
    },
    unexpected: true,
  };
}

/**
 * Import every valid entry, each in its own transaction, in file order.
 * Never publishes. Entries with validation errors are skipped, untouched; an
 * entry identical to the template's latest revision is `unchanged` and writes
 * nothing.
 */
export async function applyImport(
  tenantId: number,
  payload: unknown,
  createdBy: number | null,
  lookup: TemplateImportLookup = dbLookup,
): Promise<ImportReport> {
  const { format, entries, items } = await planImport(tenantId, payload, lookup);

  for (const item of items) {
    const entry = entries[item.index];
    if (item.errors.length > 0 || !entry.template || !entry.revision) {
      item.outcome = 'skipped';
      continue;
    }
    const tpl = entry.template;
    const rev = entry.revision;
    try {
      const written = await db.transaction(async (trx) => {
        // Looked up AGAIN, inside the transaction: the plan is advice, and an
        // earlier entry of this same file may have just created the template.
        const existing = await lookup.findTemplate(tenantId, entry.name, tpl.brand, trx);
        // `unchanged` is decided here too, not taken from the plan: an earlier
        // entry of this file may have just written the revision this one
        // repeats (it IS the latest by now), or somebody may have added one
        // since the dry run.
        if (existing) {
          const latest = await lookup.latestRevision(existing.id, trx);
          if (latest && storedFingerprint(latest) === entryFingerprint(rev)) {
            return {
              action: 'unchanged' as ImportAction,
              templateId: existing.id,
              revisionId: latest.id,
              revision: latest.revision,
              sameAs: {
                kind: 'revision', revisionId: latest.id, revision: latest.revision, status: latest.status,
              } as ImportSameAs,
            };
          }
        }
        const templateId = existing
          ? existing.id
          : String(
            (await versionService.createTemplate(tenantId, {
              name: entry.name,
              brand: tpl.brand,
              description: tpl.description ?? null,
              modelPattern: tpl.modelPattern ?? null,
              createdBy,
            }, trx)).id,
          );
        const draft = await versionService.createDraft(tenantId, templateId, {
          body: rev.body,
          varSchema: rev.varSchema,
          sectionSeverity: rev.sectionSeverity,
          osMin: rev.osMin ?? null,
          osMax: rev.osMax ?? null,
          renderOptions: rev.renderOptions,
          notes: rev.notes ?? null,
          createdBy,
        }, trx);
        return {
          action: (existing ? 'new-revision' : 'create') as ImportAction,
          templateId,
          revisionId: String(draft.id),
          revision: Number(draft.revision),
          sameAs: null as ImportSameAs | null,
        };
      });
      item.action = written.action;
      item.templateId = written.templateId;
      item.existingTemplateId = written.action === 'create' ? null : written.templateId;
      item.revisionId = written.revisionId;
      item.revision = written.revision;
      item.sameAs = written.sameAs;
      item.outcome = written.action === 'unchanged' ? 'unchanged' : 'created';
    } catch (err) {
      const { issue, unexpected } = issueFromWriteError(err);
      if (unexpected) {
        logger.error({ err, tenantId, entry: item.index, name: item.name }, 'template import: write failed');
      }
      item.errors.push(issue);
      item.outcome = 'failed';
    }
  }

  logger.info(
    {
      tenantId,
      createdBy,
      total: items.length,
      created: items.filter((i) => i.outcome === 'created').length,
      unchanged: items.filter((i) => i.outcome === 'unchanged').length,
      failed: items.filter((i) => i.outcome === 'failed').length,
      skipped: items.filter((i) => i.outcome === 'skipped').length,
    },
    'template import: draft revisions written (none published)',
  );

  return buildReport(false, format, { id: tenantId, name: await lookup.tenantName(tenantId) }, items);
}

export const templateImportService = {
  unpackImportFile,
  validateEntry,
  planImport,
  dryRunImport,
  applyImport,
};
