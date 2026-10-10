/**
 * Quick Setup Tenant — which variables the setup types its values against.
 *
 * A REFERENCE is one revision's `var_schema`: a valid entry of the template
 * file being imported, an existing revision the designer picked, or — when
 * neither is given — every published revision of an active template the
 * tenant can see (the site form's own set, `siteDeclarationsQuery`). The
 * references are merged by the resolver's own `declaredSiteKeys`, NEWEST
 * FIRST, so a key's schema, label and level are its newest declaration's and
 * its secrecy is "secret if ANY declaration says so" — the same merge the
 * site form and the site import judge with. Nothing here re-states a rule.
 *
 * `buildDeclarations` is pure (the harness runs it on fixtures); the two
 * loaders read the database, tenant-scoped.
 */

import type { Knex } from 'knex';
import type { DeclaredKeyView, JsonValue } from '@obliwan/shared';
import { db } from '../../db';
import {
  declaredSiteKeys,
  siteDeclarationsQuery,
  type SiteVariableDeclaration,
  type VarSchema,
} from '../template/variableResolver.service';

export interface SetupReference {
  kind: 'file' | 'revision' | 'published';
  /** What a message calls it: "<template> (file)" or "<template> r<n>". */
  name: string;
  /** null for a file entry: it has no revision yet. */
  revisionId: string | null;
  revision: number | null;
  status: string | null;
  /** The shape the resolver merges. File entries carry zero ids. */
  decl: SiteVariableDeclaration;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function ownProp(schema: VarSchema, key: string): Record<string, unknown> | undefined {
  const props = schema.properties;
  if (!isPlainObject(props) || !Object.prototype.hasOwnProperty.call(props, key)) return undefined;
  const p = props[key];
  return isPlainObject(p) ? p : undefined;
}

function requiredOf(schema: VarSchema): Set<string> {
  return new Set(Array.isArray(schema.required) ? schema.required.filter((k) => typeof k === 'string') : []);
}

/**
 * The declared keys, merged across `refs` (expected NEWEST FIRST), sorted by
 * key. `required` asks every reference; `hasDefault`/`default` and
 * `description` are the newest declaration's; a secret never shows a default
 * (the revision validator refuses one, and a stored row could carry one only
 * behind its back).
 */
export function buildDeclarations(refs: readonly SetupReference[]): DeclaredKeyView[] {
  const merged = declaredSiteKeys(refs.map((r) => r.decl));
  const required = refs.map((r) => requiredOf(r.decl.varSchema));
  const out: DeclaredKeyView[] = [];
  for (const d of merged.values()) {
    const prop = d.schema;
    const declaredBy: DeclaredKeyView['declaredBy'] = [];
    refs.forEach((r) => {
      if (ownProp(r.decl.varSchema, d.key)) {
        declaredBy.push({
          name: r.name,
          revisionId: r.revisionId,
          revision: r.revision,
          source: r.kind === 'file' ? 'file' : 'stored',
        });
      }
    });
    const description = prop.description;
    const view: DeclaredKeyView = {
      key: d.key,
      level: d.level,
      label: d.label,
      description: typeof description === 'string' ? description : null,
      secret: d.secret,
      required: required.some((s) => s.has(d.key)),
      schema: prop,
      hasDefault: !d.secret && Object.prototype.hasOwnProperty.call(prop, 'default'),
      secrecyConflict: d.secrecyConflict,
      consistent: d.consistent,
      declaredBy,
    };
    if (view.hasDefault) view.default = prop.default as JsonValue;
    out.push(view);
  }
  return out.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
}

/** A template-file entry as a reference. */
export function fileReference(name: string, varSchema: unknown): SetupReference {
  return {
    kind: 'file',
    name: `${name} (file)`,
    revisionId: null,
    revision: null,
    status: null,
    decl: {
      templateId: 0,
      templateName: `${name} (file)`,
      revisionId: 0,
      revision: 0,
      library: false,
      varSchema: (isPlainObject(varSchema) ? varSchema : {}) as VarSchema,
    },
  };
}

interface RevisionRow {
  revision_id: string | number;
  revision: number;
  status: string;
  tenant_id: number | null;
  var_schema: unknown;
  template_id: string | number;
  template_name: string;
}

function toReference(kind: 'revision' | 'published', r: RevisionRow): SetupReference {
  return {
    kind,
    name: `${r.template_name} r${Number(r.revision)}`,
    revisionId: String(r.revision_id),
    revision: Number(r.revision),
    status: r.status,
    decl: {
      templateId: Number(r.template_id),
      templateName: r.template_name,
      revisionId: Number(r.revision_id),
      revision: Number(r.revision),
      library: r.tenant_id === null,
      varSchema: (isPlainObject(r.var_schema) ? r.var_schema : {}) as VarSchema,
    },
  };
}

/**
 * The named revisions, in the order given, each visible to the tenant (its
 * own or the library — the variables controller's `schemaOfRevision` rule).
 * `missing` lists the ids that are not.
 */
export async function loadReferenceRevisions(
  tenantId: number,
  revisionIds: readonly string[],
  executor: Knex | Knex.Transaction = db,
): Promise<{ refs: SetupReference[]; missing: string[] }> {
  if (revisionIds.length === 0) return { refs: [], missing: [] };
  const rows = (await executor('template_revisions as r')
    .join('templates as t', 't.id', 'r.template_id')
    .whereIn('r.id', [...revisionIds])
    .andWhere(function visible(this: Knex.QueryBuilder) {
      this.where('r.tenant_id', tenantId).orWhereNull('r.tenant_id');
    })
    .select(
      'r.id as revision_id',
      'r.revision as revision',
      'r.status as status',
      'r.tenant_id as tenant_id',
      'r.var_schema as var_schema',
      't.id as template_id',
      't.name as template_name',
    )) as RevisionRow[];
  const byId = new Map(rows.map((r) => [String(r.revision_id), r]));
  const refs: SetupReference[] = [];
  const missing: string[] = [];
  for (const id of revisionIds) {
    const row = byId.get(String(id));
    if (row) refs.push(toReference('revision', row));
    else missing.push(String(id));
  }
  return { refs, missing };
}

/** Every published revision of an active template the tenant can see, newest
 *  first — the site form's and the site import's set. */
export async function loadPublishedReferences(
  tenantId: number,
  executor: Knex | Knex.Transaction = db,
): Promise<SetupReference[]> {
  const rows = (await siteDeclarationsQuery(executor, tenantId)) as Array<Omit<RevisionRow, 'status'>>;
  return rows.map((r) => toReference('published', { ...r, status: 'published' }));
}
