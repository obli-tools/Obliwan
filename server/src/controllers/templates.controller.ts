// ============================================================================
// ObliWAN — templates, revisions, partials, assignments : HTTP layer
// ============================================================================
//
// ┌─ THE THREE RULES OF THIS FILE ───────────────────────────────────────────┐
// │                                                                          │
// │ 1. THE TENANT IS ALWAYS `req.tenantId`, from the session, and it is      │
// │    passed as the FIRST argument to every service call. It is never read  │
// │    from a body, a query string or a path. `templates` and                │
// │    `template_partials` are the only two tables in this milestone with a  │
// │    NULLABLE tenant — the design defines NULL as the shipped cross-tenant │
// │    library — so every read here is `tenant_id IS NULL OR tenant_id = :t` │
// │    and every WRITE is `tenant_id = :t` with no NULL branch at all.       │
// │                                                                          │
// │    THE LIBRARY IS READ-ONLY THROUGH THIS API. A tenant may render and    │
// │    assign a library template; it may not draft, publish, quarantine or   │
// │    edit one, because that row is shared with every other customer on the │
// │    platform and one tenant editing it would be a cross-tenant write      │
// │    dressed up as a template edit. Seeding the library is a migration or  │
// │    an operator act, not an HTTP one — the endpoint does not exist, so it │
// │    cannot be mis-permissioned.                                           │
// │                                                                          │
// │ 2. A CROSS-TENANT ID IS A 404, NOT A 403. Confirming that revision 812   │
// │    exists somewhere else is already a leak.                              │
// │                                                                          │
// │ 3. `TEMPLATE_WRITE` IS THE SECURITY BOUNDARY, NOT A CRUD PERMISSION.     │
// │    It is the capability that authorises making the server EXECUTE        │
// │    TEMPLATE CODE of the caller's choosing. The line is drawn on "who     │
// │    chose the code", not on "who pressed the button":                     │
// │                                                                          │
// │      POST /templates/preview            arbitrary body -> TEMPLATE_WRITE │
// │      POST /templates/revisions/:id/preview  stored body -> TEMPLATE_READ │
// │                                                                          │
// │    A stored revision's body got into the database under TEMPLATE_WRITE   │
// │    and `loadRevisionBundle` reads nothing else; rendering it is the same │
// │    privilege as reading it. A free-form body is authoring, and it is     │
// │    gated as authoring. `loader.ts` keeps the two as two functions        │
// │    precisely so this difference stays visible at the call site.          │
// └──────────────────────────────────────────────────────────────────────────┘

import type { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import type { Knex } from 'knex';
import { AppError } from '../middleware/errorHandler';
import { assertScopeTargetInTeams } from '../middleware/teamScope';
import { db } from '../db';
import {
  createAssignmentSchema, createPartialRevisionSchema, createPartialSchema,
  createRevisionSchema, createTemplateSchema, publishRevisionSchema,
  renderPreviewSchema, revisionStatusSchema, updateAssignmentSchema,
  updateTemplateSchema, varSchemaSchema, variableKey, variableValue,
  VARIABLE_LEVELS, RENDER_TIME_LEVELS, RESERVED_FACT_KEYS,
} from '../validators/template.schema';
import {
  versionService, TemplateVersionError, ImmutableRevisionError, TemplateDeleteRefusedError,
} from '../services/template/version.service';
import {
  assignmentService, AssignmentInputError, type AssignmentScope,
} from '../services/template/assignment.service';
import {
  renderRevisionForDevice, renderScratchForDevice, latestRender, getRender,
  RenderRefusedError, RenderTargetError, NoParserError,
} from '../services/template/render.service';
import {
  TemplateSyntaxError, DynamicTemplateRefError, TemplateDependencyError,
} from '../services/template/loader';
import {
  variableResolver, VariableResolutionError, VarSchemaError, type JsonValue, type VarSchema,
} from '../services/template/variableResolver.service';
import {
  templateImportService, TemplateImportFormatError,
} from '../services/template/import.service';
import { applyTenantScope, godViewMeta, hasGlobalView, withTenantNames } from '../utils/globalView';

// ============================================================================
// Parsing helpers
// ============================================================================

function parseId(raw: string, what = 'id'): number {
  const id = Number.parseInt(raw, 10);
  if (!Number.isInteger(id) || id <= 0) throw new AppError(400, `Invalid ${what}`);
  return id;
}

/** Template, revision and partial ids are `bigint`. They arrive as strings and
 *  MUST stay strings: a fleet past 2^53 rows would start serving the wrong row
 *  the moment one of them went through `Number`. */
function parseBigId(raw: string, what = 'id'): string {
  if (!/^[0-9]{1,19}$/.test(raw)) throw new AppError(400, `Invalid ${what}`);
  return raw;
}

/** Typed on the schema's OUTPUT, so a schema that transforms (a query-string
 *  boolean) is accepted as well as one whose input and output agree. */
function parse<S extends z.ZodTypeAny>(schema: S, value: unknown): z.output<S> {
  const result = schema.safeParse(value);
  if (!result.success) {
    const flat = result.error.flatten();
    const fields = Object.entries(flat.fieldErrors)
      .map(([f, m]) => `${f}: ${((m as string[] | undefined) ?? []).join(', ')}`)
      .concat(flat.formErrors)
      .filter((s) => s.length > 0)
      .join('; ');
    throw new AppError(400, fields ? `Validation failed — ${fields}` : 'Validation failed');
  }
  return result.data;
}

/**
 * Turn a service-layer refusal into the right status.
 *
 * Kept in ONE function so a new error class cannot quietly become a 500: a
 * template that does not parse is a 400, an immutable revision is a 409, a
 * cross-tenant id is a 404, and a variable that has no value is a 422 with a
 * per-variable payload the form can render.
 */
function rethrow(err: unknown): never {
  if (err instanceof AppError) throw err;
  if (err instanceof ImmutableRevisionError) throw new AppError(409, err.message);
  if (err instanceof RenderTargetError) throw new AppError(404, err.message);
  if (err instanceof RenderRefusedError) throw new AppError(409, err.message);
  if (err instanceof NoParserError) throw new AppError(503, err.message);
  if (err instanceof TemplateSyntaxError) throw new AppError(400, err.message);
  if (err instanceof DynamicTemplateRefError) throw new AppError(400, err.message);
  if (err instanceof TemplateDependencyError) throw new AppError(409, err.message);
  if (err instanceof VarSchemaError) throw new AppError(400, err.message);
  if (err instanceof TemplateImportFormatError) throw new AppError(400, err.message);
  // A revision pinned on the wrong template is a 400 (the pair is incoherent);
  // a scope_id belonging to another tenant is a 404 (rule 2 — never confirm
  // that the row exists somewhere else).
  if (err instanceof AssignmentInputError) {
    throw new AppError(err.kind === 'not_found' ? 404 : 400, err.message);
  }
  if (err instanceof VariableResolutionError) {
    const detail = new AppError(422, err.message) as AppError & { details?: unknown };
    detail.details = { missing: err.missing, typeErrors: err.typeErrors, chain: err.chain };
    throw detail;
  }
  // Before the regex below, on purpose: a delete refusal embeds the template's
  // operator-chosen name, and a name may itself contain "does not exist".
  if (err instanceof TemplateDeleteRefusedError) throw new AppError(409, err.message);
  if (err instanceof TemplateVersionError) {
    // "does not exist for this tenant" is a 404 by rule 2; everything else the
    // version service refuses is a state conflict.
    throw new AppError(/does not exist/.test(err.message) ? 404 : 409, err.message);
  }
  throw err;
}

// ============================================================================
// Preview overrides
// ============================================================================

/**
 * Refuse, with a 422 that names each variable, a preview override the render
 * would refuse with a 500.
 *
 * `render.service` lays an override into the context as an `extra` key, and
 * `contextFromReport` throws a PLAIN `Error` for any `extra` key that collides
 * with a variable it resolved — a value stored anywhere in the router's chain
 * (declared by this revision or not), or a declaration's default. Nothing maps
 * that error, so it reached the caller as "Internal server error". The same
 * resolution is run here first, against the same schema, and the collision is
 * reported as what it is: this router already has a value for that variable.
 *
 * `device` is refused as well: it is the fact object every device render
 * supplies, and an override of that name would replace it without a word.
 *
 * When the resolution itself fails (unknown device, a schema that does not
 * compile), nothing is refused here: the render meets the same failure and
 * maps it to its own status.
 */
async function assertOverridesFree(
  tenantId: number,
  deviceId: number,
  varSchema: VarSchema | null,
  overrides: { key: string }[] | undefined,
): Promise<void> {
  if (!overrides || overrides.length === 0) return;
  let variables: Record<string, { source: string; sourceName: string }>;
  try {
    variables = (await variableResolver.resolveForDevice(tenantId, deviceId, varSchema)).variables;
  } catch {
    return;
  }
  const problems: string[] = [];
  for (const { key } of overrides) {
    if (key === 'device') {
      problems.push('"device" is supplied by the render itself (the witness router\'s own facts)');
      continue;
    }
    if (!Object.prototype.hasOwnProperty.call(variables, key)) continue;
    const v = variables[key];
    problems.push(
      v.source === 'default'
        ? `"${key}" takes its default from the template's variables`
        : `"${key}" already has a value for this router (set at ${v.sourceName})`,
    );
  }
  if (problems.length > 0) {
    throw new AppError(
      422,
      `A sample value cannot replace what the render already resolves: ${problems.join('; ')}. ` +
        'Remove these samples — the preview renders with that value.',
    );
  }
}

// ============================================================================
// Tenant scoping for the two nullable-tenant tables
// ============================================================================

/** `tenant_id IS NOT DISTINCT FROM :t OR tenant_id IS NULL` — a tenant sees its
 *  own templates AND the shipped library, and nothing else. `= NULL` matches
 *  nothing, which is why this is written with `IS NULL` and not with a `where`. */
function visibleTemplates(q: Knex.QueryBuilder, tenantId: number): Knex.QueryBuilder {
  return q.whereRaw('(tenant_id = ? OR tenant_id IS NULL)', [tenantId]);
}

interface TemplateRow {
  id: string; uuid: string; tenant_id: number | null; name: string;
  description: string | null; brand: string; model_pattern: string | null;
  status: string; created_at: Date; updated_at: Date;
}

async function readableTemplate(tenantId: number, templateId: string): Promise<TemplateRow> {
  const row = (await visibleTemplates(db('templates').where('id', templateId), tenantId)
    .first('*')) as TemplateRow | undefined;
  if (!row) throw new AppError(404, `Template ${templateId} not found`);
  return row;
}

/** A template a tenant may MODIFY. The library branch is deliberately absent:
 *  see rule 1. */
async function writableTemplate(tenantId: number, templateId: string): Promise<TemplateRow> {
  const row = (await db('templates')
    .where({ id: templateId, tenant_id: tenantId })
    .first('*')) as TemplateRow | undefined;
  if (!row) {
    const library = await db('templates').where({ id: templateId }).whereNull('tenant_id').first('id');
    if (library) {
      throw new AppError(
        403,
        'This template belongs to the shipped cross-tenant library. It can be assigned and ' +
          'rendered, but not edited: the row is shared with every other customer on the ' +
          'platform. Copy it into your own tenant first.',
      );
    }
    throw new AppError(404, `Template ${templateId} not found`);
  }
  return row;
}

interface RevisionRow {
  id: string; tenant_id: number | null; template_id: string; revision: number;
  status: string;
}

async function readableRevision(tenantId: number, revisionId: string): Promise<RevisionRow> {
  const row = (await visibleTemplates(db('template_revisions').where('id', revisionId), tenantId)
    .first('id', 'tenant_id', 'template_id', 'revision', 'status')) as RevisionRow | undefined;
  if (!row) throw new AppError(404, `Template revision ${revisionId} not found`);
  return row;
}

async function writableRevision(tenantId: number, revisionId: string): Promise<RevisionRow> {
  const row = (await db('template_revisions')
    .where({ id: revisionId, tenant_id: tenantId })
    .first('id', 'tenant_id', 'template_id', 'revision', 'status')) as RevisionRow | undefined;
  if (!row) {
    await readableRevision(tenantId, revisionId);  // 404 unless it is a library row
    throw new AppError(403, 'Library template revisions are read-only.');
  }
  return row;
}

async function readablePartial(tenantId: number, partialId: string): Promise<{ id: string; name: string; tenant_id: number | null }> {
  const row = (await visibleTemplates(db('template_partials').where('id', partialId), tenantId)
    .first('id', 'name', 'tenant_id')) as { id: string; name: string; tenant_id: number | null } | undefined;
  if (!row) throw new AppError(404, `Partial ${partialId} not found`);
  return row;
}

// ============================================================================
// Local schemas — the two shapes `template.schema.ts` does not carry
// ============================================================================

/**
 * The SCRATCH preview: an arbitrary template body rendered against a witness
 * device. Declared here rather than in `template.schema.ts` because it is the
 * only request in the product whose payload IS executable code, and it belongs
 * next to the route that gates it with `TEMPLATE_WRITE`.
 *
 * `mode` is absent for the same reason `renderPreviewSchema` has no `mode`:
 * there is no query parameter, header or admin flag anywhere in this API that
 * turns a render into a credential reader.
 */
const scratchPreviewSchema = z.object({
  deviceId: z.number().int().positive(),
  body: z.string().min(1).max(512 * 1024),
  varSchema: varSchemaSchema.optional(),
  sectionSeverity: z.record(z.enum(['info', 'low', 'medium', 'high', 'critical'])).optional(),
  renderOptions: z
    .object({
      throwOnUndefined: z.literal(true).optional(),
      trimBlocks: z.boolean().optional(),
      lstripBlocks: z.boolean().optional(),
      autoescape: z.boolean().optional(),
    })
    .strict()
    .optional(),
  overrides: z.array(z.object({ key: variableKey, value: variableValue })).max(50).optional(),
});

/**
 * A boolean in a QUERY STRING. Not `z.coerce.boolean()`: that is
 * `Boolean(value)`, and `Boolean('false')` is `true` — `?includeLibrary=false`
 * used to mean "include it".
 */
const queryBoolean = z
  .enum(['true', 'false', '1', '0'])
  .transform((v) => v === 'true' || v === '1');

const listTemplatesQuery = z.object({
  brand: z.string().max(24).optional(),
  status: z.enum(['active', 'archived']).optional(),
  includeLibrary: queryBoolean.optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

/** `POST /templates/import?dryRun=true`. Absent means a real import. */
const importQuery = z.object({
  dryRun: queryBoolean.optional(),
});

// ============================================================================
// DTOs — snake_case in the database, camelCase on the wire
// ============================================================================

function templateDto(r: TemplateRow) {
  return {
    id: String(r.id),
    uuid: r.uuid,
    name: r.name,
    description: r.description,
    brand: r.brand,
    modelPattern: r.model_pattern,
    status: r.status,
    /** true when this row is the shipped library and therefore read-only. */
    isLibrary: r.tenant_id === null,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

function revisionDto(r: Record<string, unknown>) {
  return {
    id: String(r.id),
    uuid: r.uuid,
    templateId: String(r.template_id),
    revision: Number(r.revision),
    bodySha256: r.body_sha256,
    varSchema: r.var_schema,
    sectionSeverity: r.section_severity,
    osMin: r.os_min,
    osMax: r.os_max,
    engine: r.engine,
    renderOptions: r.render_options,
    status: r.status,
    publishedAt: r.published_at,
    depsPinned: r.deps_pinned,
    depsCount: r.deps_count,
    notes: r.notes,
    isLibrary: r.tenant_id === null,
  };
}

/** The body is served only when explicitly asked for. It is not a secret, but
 *  a list endpoint that ships every body turns a template index into a payload
 *  measured in megabytes. */
function revisionDtoWithBody(r: Record<string, unknown>) {
  return { ...revisionDto(r), body: r.body };
}

// ============================================================================
// Controller
// ============================================================================

export const templatesController = {
  // ── Templates ───────────────────────────────────────────────────────────

  async list(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(listTemplatesQuery, req.query);
      let query = db('templates');
      // God view (a platform admin's GET on the master tenant): every tenant's
      // templates (plus the library unless excluded), each tagged with its
      // tenant. Anyone else: its own (plus the library), as before.
      const godView = hasGlobalView(req);
      if (godView) {
        const f = req.godViewTenantFilter;
        if (f !== undefined) query = q.includeLibrary === false ? query.where('tenant_id', f) : visibleTemplates(query, f);
        else if (q.includeLibrary === false) query = query.whereNotNull('tenant_id');
      } else {
        query = q.includeLibrary === false
          ? query.where('tenant_id', req.tenantId)
          : visibleTemplates(query, req.tenantId);
      }
      if (q.brand) query = query.where('brand', q.brand);
      if (q.status) query = query.where('status', q.status);
      const rows = (await query
        .orderBy('name', 'asc')
        .limit(q.limit ?? 100)
        .offset(q.offset ?? 0)
        .select('*')) as TemplateRow[];
      const dtos = rows.map((r) => (godView && r.tenant_id !== null ? { ...templateDto(r), tenantId: Number(r.tenant_id) } : templateDto(r)));
      res.json({
        success: true,
        data: await withTenantNames(dtos as Array<ReturnType<typeof templateDto> & { tenantId?: number }>, 'tenantId', godView),
        ...godViewMeta(godView),
      });
    } catch (err) { next(err); }
  },

  async get(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const row = await readableTemplate(req.tenantId, parseBigId(req.params.id, 'template id'));
      res.json({ success: true, data: templateDto(row) });
    } catch (err) { next(err); }
  },

  async create(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const input = parse(createTemplateSchema, req.body);
      // `req.tenantId`, never a body field, and never NULL: an HTTP caller
      // cannot create a library template.
      const row = await versionService.createTemplate(req.tenantId, {
        name: input.name,
        brand: input.brand,
        description: input.description ?? null,
        modelPattern: input.modelPattern ?? null,
        createdBy: req.session.userId ?? null,
      });
      res.status(201).json({ success: true, data: templateDto(row as unknown as TemplateRow) });
    } catch (err) { next(rethrowSafe(err)); }
  },

  async update(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseBigId(req.params.id, 'template id');
      await writableTemplate(req.tenantId, id);
      const input = parse(updateTemplateSchema, req.body);
      const patch: Record<string, unknown> = { updated_by: req.session.userId ?? null, updated_at: new Date() };
      if (input.name !== undefined) patch.name = input.name;
      if (input.description !== undefined) patch.description = input.description;
      if (input.brand !== undefined) patch.brand = input.brand;
      if (input.modelPattern !== undefined) patch.model_pattern = input.modelPattern;
      if (input.status !== undefined) patch.status = input.status;
      const [row] = (await db('templates')
        .where({ id, tenant_id: req.tenantId })
        .update(patch)
        .returning('*')) as TemplateRow[];
      res.json({ success: true, data: templateDto(row) });
    } catch (err) { next(rethrowSafe(err)); }
  },

  /**
   * `DELETE /templates/:id` — only a template none of whose revisions ever
   * left draft, and that nothing references (`version.service`,
   * TEMPLATE_REFERENCES) except the baseline promotion or the extrapolation
   * approval that created it, which the delete undoes
   * (`baselineDraftsUnpromoted` / `extrapolationProposalsReopened` in the
   * reply). Anything else
   * is a 409 that says to archive instead.
   * `writableTemplate` first: another tenant's id is a 404 (rule 2), a library
   * template a 403 (rule 1). Audited in the delete's own transaction.
   */
  async remove(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseBigId(req.params.id, 'template id');
      await writableTemplate(req.tenantId, id);
      const result = await versionService.deleteDraftTemplate(req.tenantId, id, {
        userId: req.session.userId ?? null,
        username: req.session.username ?? null,
      });
      res.json({ success: true, data: result, message: 'Template deleted' });
    } catch (err) { next(rethrowSafe(err)); }
  },

  /**
   * `DELETE /templates/:id/revisions/:revId` — one DRAFT revision of that
   * template. Refused (409) when it was ever published, when anything
   * references it, or when it is the template's only revision (delete the
   * template instead). A revision of another template is a 404.
   */
  async removeRevision(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseBigId(req.params.id, 'template id');
      const revId = parseBigId(req.params.revId, 'revision id');
      await writableTemplate(req.tenantId, id);
      const result = await versionService.deleteDraftRevision(req.tenantId, id, revId, {
        userId: req.session.userId ?? null,
        username: req.session.username ?? null,
      });
      res.json({ success: true, data: result, message: 'Revision deleted' });
    } catch (err) { next(rethrowSafe(err)); }
  },

  /**
   * The authoring vocabulary, served from the validators that enforce it, so
   * the editor's level list and the server's verdict are ONE list and not two
   * that drift apart. `contextFacts` are names a body may read without
   * declaring them; `deviceRenderFacts` is the subset a render ON A ROUTER
   * (preview included) supplies — the bench's `site` / `box` are not in it.
   */
  async vocabulary(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      // `deviceFacts()` in render.service: the one fact object every device
      // render injects.
      const deviceRenderFacts = ['device'];
      res.json({
        success: true,
        data: {
          levels: VARIABLE_LEVELS,
          renderTimeLevels: RENDER_TIME_LEVELS,
          reservedFactKeys: RESERVED_FACT_KEYS,
          deviceRenderFacts,
          contextFacts: [...deviceRenderFacts, ...RESERVED_FACT_KEYS],
        },
      });
    } catch (err) { next(err); }
  },

  /**
   * Import one `obliwan-template/1` file or an `obliwan-template-bundle/1`.
   * `TEMPLATE_WRITE`: a file is template CODE, exactly like a body typed in the
   * editor.
   *
   * `?dryRun=true` validates every entry and says, per entry, whether it would
   * create a template, add a draft revision to an existing one, or leave it
   * `unchanged` (identical to its latest revision) — and writes nothing to the
   * database. Without it, each valid entry is written in its own transaction
   * (template + draft revision, or neither), invalid ones are skipped and
   * unchanged ones are not written. NOTHING IS PUBLISHED: publication stays a
   * human click per revision.
   *
   * A 200 in both cases, with the per-entry verdict in the body: a bundle where
   * two of six entries are refused is not a failed request, and a status code
   * cannot say which two. A request that is not an import file at all is a 400.
   */
  async importTemplates(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const q = parse(importQuery, req.query);
      const report = q.dryRun === true
        ? await templateImportService.dryRunImport(req.tenantId, req.body)
        : await templateImportService.applyImport(req.tenantId, req.body, req.session.userId ?? null);
      res.json({ success: true, data: report });
    } catch (err) { next(rethrowSafe(err)); }
  },

  // ── Revisions ───────────────────────────────────────────────────────────

  async listRevisions(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseBigId(req.params.id, 'template id');
      await readableTemplate(req.tenantId, id);
      const rows = (await db('template_revisions')
        .where('template_id', id)
        .orderBy('revision', 'desc')
        .select(
          'id', 'uuid', 'tenant_id', 'template_id', 'revision', 'body_sha256', 'var_schema',
          'section_severity', 'os_min', 'os_max', 'engine', 'render_options', 'status',
          'published_at', 'deps_pinned', 'deps_count', 'notes',
        )) as Record<string, unknown>[];
      // How many of THIS tenant's enabled assignments pin each revision. The
      // assignment resolver applies a pinned assignment only while its revision
      // is `published`, so this is the number that stops applying when the
      // revision is deprecated — said in the deprecate dialog before the click.
      const pins = rows.length === 0 ? [] : ((await db('template_assignments')
        .where({ tenant_id: req.tenantId, pin_mode: 'pinned', enabled: true })
        .whereIn('revision_id', rows.map((r) => r.id as string | number))
        .groupBy('revision_id')
        .select('revision_id')
        .count({ n: '*' })) as Array<{ revision_id: string | number; n: string | number }>);
      const pinnedBy = new Map(pins.map((p) => [String(p.revision_id), Number(p.n)]));
      res.json({
        success: true,
        data: rows.map((r) => ({ ...revisionDto(r), pinnedAssignments: pinnedBy.get(String(r.id)) ?? 0 })),
      });
    } catch (err) { next(err); }
  },

  async getRevision(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const revId = parseBigId(req.params.revId, 'revision id');
      await readableRevision(req.tenantId, revId);
      const row = await versionService.getRevision(revId);
      const deps = (await db('template_revision_deps')
        .where('revision_id', revId)
        .select('name', 'ref_kind', 'partial_id', 'partial_revision_id', 'depth')) as Record<string, unknown>[];
      res.json({
        success: true,
        data: {
          ...revisionDtoWithBody(row as unknown as Record<string, unknown>),
          deps: deps.map((d) => ({
            name: d.name,
            refKind: d.ref_kind,
            partialId: String(d.partial_id),
            partialRevisionId: String(d.partial_revision_id),
            depth: Number(d.depth),
          })),
        },
      });
    } catch (err) { next(rethrowSafe(err)); }
  },

  async createRevision(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseBigId(req.params.id, 'template id');
      await writableTemplate(req.tenantId, id);
      const input = parse(createRevisionSchema, req.body);
      const row = await versionService.createDraft(req.tenantId, id, {
        body: input.body,
        varSchema: input.varSchema,
        sectionSeverity: input.sectionSeverity,
        osMin: input.osMin ?? null,
        osMax: input.osMax ?? null,
        renderOptions: input.renderOptions,
        notes: input.notes ?? null,
        createdBy: req.session.userId ?? null,
      });
      res.status(201).json({ success: true, data: revisionDto(row as unknown as Record<string, unknown>) });
    } catch (err) { next(rethrowSafe(err)); }
  },

  async updateRevision(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const revId = parseBigId(req.params.revId, 'revision id');
      await writableRevision(req.tenantId, revId);
      const input = parse(createRevisionSchema.partial(), req.body);
      const row = await versionService.updateDraft(req.tenantId, revId, {
        body: input.body,
        varSchema: input.varSchema,
        sectionSeverity: input.sectionSeverity,
        osMin: input.osMin,
        osMax: input.osMax,
        renderOptions: input.renderOptions,
        notes: input.notes,
      });
      res.json({ success: true, data: revisionDto(row as unknown as Record<string, unknown>) });
    } catch (err) { next(rethrowSafe(err)); }
  },

  /**
   * Publication — the moment a revision becomes immutable and its partial
   * dependencies are PINNED. There is deliberately no body here: you publish a
   * draft that already exists, you do not publish new content in one shot.
   */
  async publishRevision(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const revId = parseBigId(req.params.revId, 'revision id');
      await writableRevision(req.tenantId, revId);
      parse(publishRevisionSchema, req.body ?? {});
      const result = await versionService.publishRevision(
        req.tenantId, revId, req.session.userId ?? null,
      );
      res.json({
        success: true,
        data: {
          revision: revisionDto(result.revision as unknown as Record<string, unknown>),
          deps: result.deps,
          depsFingerprint: result.depsFingerprint,
        },
      });
    } catch (err) { next(rethrowSafe(err)); }
  },

  /** Quarantine or deprecate. There is NO path back to `draft`, here or in the
   *  database trigger: a revision that could be un-published is a revision
   *  whose renders lose their provenance. Nor back to `published`: the schema
   *  accepts `quarantined` and `deprecated` only. A library revision is a 403
   *  (`writableRevision`), another tenant's a 404. The reason is required,
   *  trimmed, refused with a 400 when blank (the schema's `min(1)` admits
   *  "   "), and kept in the `template_revision.status_changed` audit row.
   *  Leaving `quarantined`, and deprecating a revision a rollout still holds,
   *  are 409s from the service. */
  async setRevisionStatus(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const revId = parseBigId(req.params.revId, 'revision id');
      await writableRevision(req.tenantId, revId);
      const input = parse(revisionStatusSchema, req.body);
      const reason = input.reason.trim();
      if (!reason) throw new AppError(400, 'reason must not be blank');
      const row = await versionService.setRevisionStatus(req.tenantId, revId, input.status, db, {
        actor: { userId: req.session.userId ?? null, username: req.session.username ?? null },
        reason,
      });
      res.json({
        success: true,
        data: revisionDto(row as unknown as Record<string, unknown>),
        message: `Revision ${row.revision} is now ${input.status}: ${reason}`,
      });
    } catch (err) { next(rethrowSafe(err)); }
  },

  /**
   * Diff two revisions.
   *
   * Returns `depChanges` alongside the unified patch, and that is not a detail:
   * two revisions can render DIFFERENTLY with a byte-identical body, because a
   * partial was republished between the two publications. A body-only diff
   * would show nothing and the operator would approve a change they never saw.
   */
  async diffRevisions(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const fromId = parseBigId(req.params.fromId, 'revision id');
      const toId = parseBigId(req.params.toId, 'revision id');
      await readableRevision(req.tenantId, fromId);
      await readableRevision(req.tenantId, toId);
      const diff = await versionService.diffRevisions(fromId, toId);
      res.json({ success: true, data: diff });
    } catch (err) { next(rethrowSafe(err)); }
  },

  // ── Preview ─────────────────────────────────────────────────────────────

  /**
   * Render a STORED revision against a witness device. `TEMPLATE_READ`.
   *
   * Never persists a `config_renders` row: an authoring preview is not evidence
   * of an intent, and a plan compiled later must not be able to point at it.
   */
  async previewRevision(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const revId = parseBigId(req.params.revId, 'revision id');
      await readableRevision(req.tenantId, revId);
      const input = parse(renderPreviewSchema, req.body);
      if (input.overrides && input.overrides.length > 0) {
        const stored = (await db('template_revisions').where('id', revId).first('var_schema')) as
          { var_schema: unknown } | undefined;
        await assertOverridesFree(
          req.tenantId, input.deviceId, (stored?.var_schema ?? null) as VarSchema | null, input.overrides,
        );
      }
      const result = await renderRevisionForDevice(req.tenantId, input.deviceId, {
        persist: false,
        revisionId: revId,
        // `variableValue` infers as `unknown` (a recursive `z.lazy` cannot
        // infer a closed union). The parse above already proved the value is
        // JSON — depth-capped, no functions, no cycles — and the render context
        // is proved pure a second time by `assertJsonPure` before it crosses
        // into the worker. This is a naming boundary, not a trust boundary.
        overrides: input.overrides as { key: string; value: JsonValue }[] | undefined,
      });
      res.json({ success: true, data: previewDto(result) });
    } catch (err) { next(rethrowSafe(err)); }
  },

  /**
   * Render an ARBITRARY BODY. `TEMPLATE_WRITE` — this is the template-execution boundary.
   *
   * "Render this string" is the same privilege as "author a template": the
   * server executes code the caller just supplied. The sandbox
   * (`worker_threads` + `resourceLimits` + 5 s + a pure-JSON context) is what
   * makes that survivable; the capability is what makes it authorised.
   */
  async previewScratch(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const input = parse(scratchPreviewSchema, req.body);
      await assertOverridesFree(
        req.tenantId, input.deviceId, (input.varSchema ?? null) as VarSchema | null, input.overrides,
      );
      const result = await renderScratchForDevice(req.tenantId, input.deviceId, input.body, {
        varSchema: input.varSchema,
        sectionSeverity: input.sectionSeverity,
        renderOptions: input.renderOptions,
        // Same boundary cast as `previewRevision` above, same justification.
        overrides: input.overrides as { key: string; value: JsonValue }[] | undefined,
      });
      res.json({
        success: true,
        data: {
          ok: result.ok,
          body: result.body,
          ncmHash: result.ncmHash,
          claimedKinds: result.claimedKinds,
          unclaimedSections: result.unclaimedSections,
          resourceCounts: countResources(result.ncmDesired),
          variables: result.variables,
          variableReport: result.variableReport,
          durationMs: result.durationMs,
          warnings: result.warnings,
          errorKind: result.errorKind,
          errorMessage: result.errorMessage,
        },
      });
    } catch (err) { next(rethrowSafe(err)); }
  },

  /** The last stored render for a device — the desired side a plan was, or
   *  would be, compiled from. */
  async deviceRender(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      const latest = await latestRender(req.tenantId, deviceId);
      if (!latest) { res.json({ success: true, data: null }); return; }
      const full = await getRender(req.tenantId, latest.id);
      res.json({
        success: true,
        data: full && {
          id: full.id,
          deviceId: full.deviceId,
          revisionId: full.revisionId,
          status: full.status,
          bodySha256: full.bodySha256,
          ncmHash: full.ncmHash,
          renderedAt: full.renderedAt,
          body: full.body,
          resourceCounts: countResources(full.ncmDesired),
        },
      });
    } catch (err) { next(rethrowSafe(err)); }
  },

  // ── Partials ────────────────────────────────────────────────────────────

  async listPartials(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const rows = (await visibleTemplates(db('template_partials'), req.tenantId)
        .orderBy('name', 'asc')
        .select('id', 'uuid', 'tenant_id', 'name', 'description', 'brand', 'created_at')) as Record<string, unknown>[];
      res.json({
        success: true,
        data: rows.map((r) => ({
          id: String(r.id), uuid: r.uuid, name: r.name, description: r.description,
          brand: r.brand, isLibrary: r.tenant_id === null, createdAt: r.created_at,
        })),
      });
    } catch (err) { next(err); }
  },

  async createPartial(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const input = parse(createPartialSchema, req.body);
      const row = await versionService.createPartial(req.tenantId, {
        name: input.name,
        description: input.description ?? null,
        brand: input.brand ?? null,
        createdBy: req.session.userId ?? null,
      });
      res.status(201).json({ success: true, data: { id: String(row.id), name: row.name } });
    } catch (err) { next(rethrowSafe(err)); }
  },

  async createPartialRevision(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const partialId = parseBigId(req.params.id, 'partial id');
      const partial = await readablePartial(req.tenantId, partialId);
      if (partial.tenant_id === null) {
        throw new AppError(403, 'Library partials are read-only.');
      }
      const input = parse(createPartialRevisionSchema, req.body);
      const row = await versionService.createPartialDraft(
        req.tenantId, partialId, input.body, req.session.userId ?? null,
      );
      res.status(201).json({
        success: true,
        data: { id: String(row.id), revision: row.revision, status: row.status },
      });
    } catch (err) { next(rethrowSafe(err)); }
  },

  /**
   * Freeze a partial revision so it becomes pinnable.
   *
   * This is the step that makes "editing a partial" a CREATE rather than an
   * UPDATE. Every template revision that already pinned an EARLIER revision of
   * this partial keeps rendering exactly what it rendered yesterday — that is
   * the milestone's recipe (b), and it is enforced by four database objects,
   * not by this endpoint.
   */
  async publishPartialRevision(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const revId = parseBigId(req.params.revId, 'partial revision id');
      const row = (await db('template_partial_revisions')
        .where('id', revId)
        .first('id', 'tenant_id')) as { id: string; tenant_id: number | null } | undefined;
      if (!row) throw new AppError(404, `Partial revision ${revId} not found`);
      if (row.tenant_id !== req.tenantId) {
        throw new AppError(row.tenant_id === null ? 403 : 404,
          row.tenant_id === null
            ? 'Library partials are read-only.'
            : `Partial revision ${revId} not found`);
      }
      const out = await versionService.publishPartialRevision(
        req.tenantId, revId, req.session.userId ?? null,
      );
      res.json({ success: true, data: { id: String(out.id), status: out.status } });
    } catch (err) { next(rethrowSafe(err)); }
  },

  // ── Assignments ─────────────────────────────────────────────────────────

  async listAssignments(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      // God view (a platform admin's GET on the master tenant): every tenant's
      // assignments, each tagged with its tenant.
      const aq = db('template_assignments as a').join('templates as t', 't.id', 'a.template_id');
      const godView = applyTenantScope(aq, 'a.tenant_id', req.tenantId);
      const rows = (await aq
        .orderBy([{ column: 'a.scope' }, { column: 'a.priority' }])
        .select(
          'a.tenant_id as tenant_id',
          'a.id as id', 'a.scope as scope', 'a.scope_id as scope_id',
          'a.template_id as template_id', 'a.revision_id as revision_id',
          'a.pin_mode as pin_mode', 'a.priority as priority', 'a.enabled as enabled',
          'a.reason as reason', 't.name as template_name', 't.brand as brand',
        )) as Record<string, unknown>[];
      const dtos = rows.map((r) => ({
        ...(godView ? { tenantId: Number(r.tenant_id) } : {}),
        id: String(r.id),
        scope: r.scope,
        scopeId: r.scope_id === null ? null : Number(r.scope_id),
        templateId: String(r.template_id),
        templateName: r.template_name,
        brand: r.brand,
        revisionId: r.revision_id === null ? null : String(r.revision_id),
        pinMode: r.pin_mode,
        priority: Number(r.priority),
        enabled: Boolean(r.enabled),
        reason: r.reason,
      }));
      res.json({
        success: true,
        data: await withTenantNames(dtos as Array<(typeof dtos)[number] & { tenantId?: number }>, 'tenantId', godView),
        ...godViewMeta(godView),
      });
    } catch (err) { next(err); }
  },

  async createAssignment(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const input = parse(createAssignmentSchema, req.body);
      // The template must be visible to this tenant — its own, or the library.
      // Assigning a template you cannot see would let an id sweep bind another
      // customer's template to your fleet.
      await readableTemplate(req.tenantId, String(input.templateId));
      if (input.revisionId) {
        // Visibility first — a revision of another tenant is a 404 and must not
        // be distinguishable from one that does not exist. Only then the
        // coherence of the (template, revision) pair, which is a 400: the
        // caller can see both rows, they just do not go together. Doing it in
        // this order is what keeps the two answers from becoming an oracle.
        const rev = await readableRevision(req.tenantId, String(input.revisionId));
        if (String(rev.template_id) !== String(input.templateId)) {
          throw new AppError(
            400,
            `Revision ${input.revisionId} belongs to template ${rev.template_id}, not to ` +
              `template ${input.templateId}. An assignment pins a revision OF the template ` +
              'it assigns; pinning another template\'s revision would render that other ' +
              "template's body under this template's name.",
          );
        }
      }
      // `scope_id` is polymorphic and has no FK. See `assertScopeTargetOwned`.
      await assignmentService.assertScopeTargetOwned(
        req.tenantId, input.scope as AssignmentScope, input.scopeId ?? null,
      );
      // Team scope (087): assigning at a group / site / device needs 'rw' on it.
      await assertScopeTargetInTeams(req, input.scope, input.scopeId ?? null, 'rw');
      const row = await assignmentService.upsertAssignment(req.tenantId, {
        scope: input.scope as AssignmentScope,
        scopeId: input.scopeId ?? null,
        templateId: input.templateId,
        revisionId: input.revisionId ?? null,
        priority: input.priority,
        enabled: input.enabled,
        createdBy: req.session.userId ?? null,
      });
      res.status(201).json({ success: true, data: { id: String(row.id) } });
    } catch (err) { next(rethrowSafe(err)); }
  },

  async updateAssignment(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseBigId(req.params.id, 'assignment id');
      const existing = (await db('template_assignments')
        .where({ id, tenant_id: req.tenantId })
        .first('*')) as Record<string, unknown> | undefined;
      if (!existing) throw new AppError(404, `Assignment ${id} not found`);
      await assertScopeTargetInTeams(
        req, String(existing.scope), existing.scope_id === null ? null : Number(existing.scope_id), 'rw',
      );
      const input = parse(updateAssignmentSchema, req.body);

      // `revision_id` and `pin_mode` are ONE decision, and they used to be
      // written as two: `pin_mode` was derived from `revisionId` and then
      // overwritten by `input.pinMode` a line later, so `PATCH {"pinMode":
      // "pinned"}` on an unpinned assignment sent `pin_mode='pinned',
      // revision_id=NULL` to a table that carries
      // `template_assignments_pin_chk` — a 500 on a request that is simply
      // wrong. Resolve the pair first, refuse
      // the incoherent combinations here, and write once.
      const currentRevision = existing.revision_id === null ? null : String(existing.revision_id);
      let revisionId: string | null =
        input.revisionId === undefined ? currentRevision
          : input.revisionId === null ? null : String(input.revisionId);
      const pinMode =
        input.pinMode ?? (input.revisionId !== undefined
          ? (input.revisionId ? 'pinned' : 'latest_published')
          : String(existing.pin_mode));

      if (pinMode === 'pinned' && revisionId === null) {
        throw new AppError(400, 'pinMode "pinned" requires a revisionId.');
      }
      // Un-pinning is a complete gesture: `latest_published` with a revision
      // still attached is exactly what the CHECK forbids, and silently keeping
      // the column would leave a pin the UI no longer shows.
      if (pinMode === 'latest_published') revisionId = null;

      if (revisionId !== null) {
        const rev = await readableRevision(req.tenantId, revisionId);
        if (String(rev.template_id) !== String(existing.template_id)) {
          throw new AppError(
            400,
            `Revision ${revisionId} belongs to template ${rev.template_id}, not to template ` +
              `${existing.template_id}, which is the one this assignment assigns.`,
          );
        }
      }

      const patch: Record<string, unknown> = {
        updated_at: new Date(),
        revision_id: revisionId,
        pin_mode: pinMode,
      };
      if (input.priority !== undefined) patch.priority = input.priority;
      if (input.enabled !== undefined) patch.enabled = input.enabled;
      await db('template_assignments').where({ id, tenant_id: req.tenantId }).update(patch);
      res.json({ success: true, data: { id } });
    } catch (err) { next(rethrowSafe(err)); }
  },

  async removeAssignment(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = parseBigId(req.params.id, 'assignment id');
      const target = (await db('template_assignments')
        .where({ id, tenant_id: req.tenantId })
        .first('scope', 'scope_id')) as { scope: string; scope_id: number | null } | undefined;
      if (target) {
        await assertScopeTargetInTeams(req, target.scope, target.scope_id === null ? null : Number(target.scope_id), 'rw');
      }
      const ok = await assignmentService.removeAssignment(req.tenantId, id);
      if (!ok) throw new AppError(404, `Assignment ${id} not found`);
      res.json({ success: true, message: 'Assignment removed' });
    } catch (err) { next(rethrowSafe(err)); }
  },

  /**
   * Which template revision applies to this device, and WHY every other
   * candidate lost.
   *
   * The rejected list is the point: "no template applies" and "a template
   * applies but its OS window excludes this box" look identical from the
   * outside, and only one of them is a configuration mistake the operator can
   * fix.
   */
  async deviceResolution(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const deviceId = parseId(req.params.deviceId, 'device id');
      const resolution = await assignmentService.resolveForDevice(req.tenantId, deviceId);
      res.json({ success: true, data: resolution });
    } catch (err) {
      if (err instanceof Error && /does not exist/.test(err.message)) {
        next(new AppError(404, `Device ${req.params.deviceId} not found`));
        return;
      }
      next(err);
    }
  },
};

// ============================================================================
// Shared shaping
// ============================================================================

function previewDto(result: Awaited<ReturnType<typeof renderRevisionForDevice>>) {
  return {
    status: result.status,
    deviceId: result.deviceId,
    revisionId: result.revisionId,
    revision: result.revision,
    templateId: result.templateId,
    /** The REDACTED body. There is no other kind. */
    body: result.body,
    bodySha256: result.bodySha256,
    ncmHash: result.ncmHash,
    claimedKinds: result.claimedKinds,
    unclaimedSections: result.unclaimedSections,
    resourceCounts: countResources(result.ncmDesired),
    variables: result.variables,
    variableReport: result.variableReport,
    secretKeys: result.secretKeys,
    depsFingerprint: result.depsFingerprint,
    durationMs: result.durationMs,
    warnings: result.warnings,
    errorKind: result.errorKind,
    errorMessage: result.errorMessage,
  };
}

/** The desired document itself is large; the preview screen needs counts, not
 *  ten arrays. `GET /api/plan/...` serves the document when it is actually
 *  needed. */
function countResources(doc: { resources: Record<string, unknown[]> } | null): Record<string, number> {
  if (!doc) return {};
  const out: Record<string, number> = {};
  for (const [key, list] of Object.entries(doc.resources)) {
    if (Array.isArray(list) && list.length > 0) out[key] = list.length;
  }
  return out;
}

/** `rethrow` throws; Express handlers need a value to hand to `next`. */
function rethrowSafe(err: unknown): unknown {
  try {
    rethrow(err);
  } catch (mapped) {
    return mapped;
  }
  return err;
}
