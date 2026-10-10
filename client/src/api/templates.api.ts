import apiClient from './client';
import type { ApiResponse, DeviceBrand } from '@obliwan/shared';

/**
 * Templates and their revisions.
 *
 * ┌─ WHAT THE SHAPE OF THIS API TELLS YOU ───────────────────────────────────┐
 * │ `remove()` and `removeRevision()` delete DRAFTS ONLY. A template whose   │
 * │ revisions produced renders that produced plans is PROVENANCE — deleting  │
 * │ it would orphan the answer to "why is this line on this router" — so the │
 * │ server refuses (409, with a sentence to show) a template with a revision │
 * │ that ever left draft, or with anything still pointing at one of its      │
 * │ revisions, except the baseline promotion that created it, which the      │
 * │ delete undoes. Archiving is a PATCH with `status: 'archived'`, which the │
 * │ assignment resolver already honours.                                     │
 * │                                                                          │
 * │ A PUBLISHED revision is never edited. `publish()` freezes it; a change is │
 * │ a NEW revision. That is what makes a plan reproducible six months later.  │
 * │ A DRAFT is edited in place (`updateRevision`) until somebody publishes it.│
 * └──────────────────────────────────────────────────────────────────────────┘
 */

export interface Template {
  /** God view only: the owning workspace (a library template has none). */
  tenantId?: number;
  tenantName?: string | null;
  id: string;
  uuid: string;
  name: string;
  description: string | null;
  brand: DeviceBrand | null;
  modelPattern: string | null;
  status: 'draft' | 'active' | 'archived' | string;
  /** True when this row is the shipped library: read-only for every tenant. */
  isLibrary: boolean;
  createdAt: string;
  updatedAt: string;
}

/** A `var_schema`: a JSON Schema object whose `properties` are the variables. */
export interface VarSchema {
  type?: 'object';
  properties?: Record<string, Record<string, unknown>>;
  required?: string[];
  additionalProperties?: boolean;
  [k: string]: unknown;
}

export interface RenderOptionsInput {
  throwOnUndefined?: true;
  trimBlocks?: boolean;
  lstripBlocks?: boolean;
  autoescape?: boolean;
}

/** What `DELETE /templates/:id` answers. */
export interface DeletedTemplate {
  templateId: string;
  name: string;
  revisionsDeleted: number;
  /** Baseline proposals whose promotion created the template, returned to
   *  review by the delete. 0 for a template made by hand. */
  baselineDraftsUnpromoted: number;
  /** Extrapolator proposals whose approval created the template, set back to
   *  « proposed » by the delete. 0 for a template made by hand. */
  extrapolationProposalsReopened: number;
}

export interface TemplateRevision {
  id: string;
  uuid: string;
  templateId: string;
  revision: number;
  bodySha256: string;
  varSchema: unknown;
  sectionSeverity: unknown;
  osMin: string | null;
  osMax: string | null;
  engine: string;
  renderOptions: unknown;
  status: 'draft' | 'published' | 'quarantined' | 'deprecated' | string;
  publishedAt: string | null;
  depsPinned?: boolean;
  depsCount?: number;
  notes?: string | null;
  isLibrary?: boolean;
  /** `GET /templates/:id/revisions` only: how many of this tenant's ENABLED
   *  assignments pin this revision. A pinned assignment applies its revision
   *  only while it is published, so these stop applying on a deprecation.
   *  Absent from every other read (and from an older server). */
  pinnedAssignments?: number;
}

/** `GET /templates/revisions/:id` — the one read that carries the body. */
export type TemplateRevisionWithBody = TemplateRevision & { body: string };

/**
 * Everything `createRevisionSchema` accepts, under the names the SERVER reads.
 * It used to be `{ body, note }`: the server reads `notes`, so every note typed
 * was dropped, and the variables, OS window and render options could not be
 * sent at all.
 */
export interface RevisionDraftInput {
  body: string;
  varSchema?: VarSchema;
  sectionSeverity?: Record<string, 'info' | 'low' | 'medium' | 'high' | 'critical'>;
  osMin?: string | null;
  osMax?: string | null;
  renderOptions?: RenderOptionsInput;
  notes?: string | null;
}

export interface TemplateListParams {
  brand?: DeviceBrand;
  status?: string;
  includeLibrary?: boolean;
  limit?: number;
  offset?: number;
}

/** `GET /templates/vocabulary` — served from the server's own validators. */
export interface TemplateVocabulary {
  /** Every value `x-obliwan-level` may take. */
  levels: string[];
  /** Levels declared but never stored: supplied by the render's caller. */
  renderTimeLevels: string[];
  /** Fact objects the bench fills (`site`, `box`). */
  reservedFactKeys: string[];
  /** What a render on a ROUTER (preview included) supplies: `device`. */
  deviceRenderFacts: string[];
  /** Names a body may read without declaring them (both of the above). */
  contextFacts: string[];
}

// ── Import ──────────────────────────────────────────────────────────────────

export interface TemplateImportIssue {
  /** Dotted path in the file (`varSchema.properties.wifi_psk.default`). */
  path: string;
  /** The declared variable the refusal is about, when it is about one. */
  variable: string | null;
  message: string;
}

/** What an `unchanged` entry repeats: a stored revision, or an earlier entry
 *  of the same file (`index`, 0-based). */
export type TemplateImportSameAs =
  | { kind: 'revision'; revisionId: string; revision: number; status: string }
  | { kind: 'entry'; index: number };

export interface TemplateImportItem {
  index: number;
  name: string;
  brand: string | null;
  /** `unchanged`: identical to what it would follow (`sameAs`) — not written. */
  action: 'create' | 'new-revision' | 'unchanged';
  existingTemplateId: string | null;
  sameAs: TemplateImportSameAs | null;
  errors: TemplateImportIssue[];
  warnings: string[];
  /** null on a dry run. */
  outcome: 'created' | 'unchanged' | 'skipped' | 'failed' | null;
  templateId: string | null;
  revisionId: string | null;
  revision: number | null;
}

export interface TemplateImportReport {
  dryRun: boolean;
  format: 'obliwan-template/1' | 'obliwan-template-bundle/1';
  tenant: { id: number; name: string | null };
  items: TemplateImportItem[];
  summary: {
    total: number;
    /** Entries that pass validation, `unchanged` ones included. */
    valid: number;
    invalid: number;
    /** Valid entries not written because nothing in them changed. */
    unchanged: number;
    created: number;
    failed: number;
    skipped: number;
  };
}

// ── Preview ─────────────────────────────────────────────────────────────────

export interface PreviewOverride {
  key: string;
  value: unknown;
}

export interface PreviewMissingVariable {
  key: string;
  expectedScope: string;
  reason: string;
}

export interface PreviewTypeError {
  key: string;
  message: string;
  source: string;
  sourceName: string;
}

/**
 * ONE shape for both preview endpoints. The stored-revision preview answers
 * `status: 'ok' | 'error'` and the scratch preview answers `ok: boolean`; the
 * screen reads `ok` and nothing else, from here.
 */
export interface TemplatePreview {
  /** Which endpoint produced it. */
  source: 'stored' | 'scratch';
  ok: boolean;
  /** The REDACTED render: secrets are placeholders. There is no other kind. */
  body: string | null;
  errorKind: string | null;
  errorMessage: string | null;
  warnings: string[];
  unclaimedSections: string[];
  resourceCounts: Record<string, number>;
  missing: PreviewMissingVariable[];
  typeErrors: PreviewTypeError[];
  durationMs: number | null;
}

function normalizePreview(raw: Record<string, unknown>, source: TemplatePreview['source']): TemplatePreview {
  const report = (raw.variableReport ?? null) as
    { missing?: PreviewMissingVariable[]; typeErrors?: PreviewTypeError[] } | null;
  const ok = source === 'stored' ? raw.status === 'ok' : raw.ok === true;
  return {
    source,
    ok,
    body: typeof raw.body === 'string' ? raw.body : null,
    errorKind: typeof raw.errorKind === 'string' ? raw.errorKind : null,
    errorMessage: typeof raw.errorMessage === 'string' ? raw.errorMessage : null,
    warnings: Array.isArray(raw.warnings) ? (raw.warnings as string[]) : [],
    unclaimedSections: Array.isArray(raw.unclaimedSections) ? (raw.unclaimedSections as string[]) : [],
    resourceCounts: (raw.resourceCounts ?? {}) as Record<string, number>,
    missing: Array.isArray(report?.missing) ? report!.missing! : [],
    typeErrors: Array.isArray(report?.typeErrors) ? report!.typeErrors! : [],
    durationMs: typeof raw.durationMs === 'number' ? raw.durationMs : null,
  };
}

function clean(p: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(p)) if (v !== undefined && v !== null && v !== '') out[k] = v;
  return out;
}

export const templatesApi = {
  async list(params: TemplateListParams = {}): Promise<Template[]> {
    const res = await apiClient.get<ApiResponse<Template[]>>('/templates', {
      params: clean(params as Record<string, unknown>),
    });
    return res.data.data ?? [];
  },

  async get(id: string): Promise<Template> {
    const res = await apiClient.get<ApiResponse<Template>>(`/templates/${id}`);
    return res.data.data!;
  },

  async create(data: {
    name: string;
    description?: string | null;
    brand: DeviceBrand;
    modelPattern?: string | null;
  }): Promise<Template> {
    const res = await apiClient.post<ApiResponse<Template>>('/templates', data);
    return res.data.data!;
  },

  async update(id: string, data: Partial<{
    name: string; description: string | null; brand: DeviceBrand;
    modelPattern: string | null; status: string;
  }>): Promise<Template> {
    const res = await apiClient.patch<ApiResponse<Template>>(`/templates/${id}`, data);
    return res.data.data!;
  },

  /**
   * Delete a template none of whose revisions ever left draft, with those
   * revisions. Refused with a 409 (and a sentence to show) when one was
   * published, or when a render, an assignment, a rollout or a bench compile
   * still points at it: archive it instead. The baseline promotion that
   * created a template does NOT refuse: the delete undoes it, and
   * `baselineDraftsUnpromoted` counts the proposals sent back to review.
   */
  async remove(id: string): Promise<DeletedTemplate> {
    const res = await apiClient.delete<ApiResponse<DeletedTemplate>>(`/templates/${id}`);
    const d = res.data.data!;
    // Absent from an older server: 0 means "nothing was sent back", which is
    // what such a server did (it refused a promoted template instead).
    return {
      ...d,
      baselineDraftsUnpromoted: Number(d.baselineDraftsUnpromoted ?? 0) || 0,
      extrapolationProposalsReopened: Number(d.extrapolationProposalsReopened ?? 0) || 0,
    };
  },

  /**
   * Delete ONE draft revision of a template. Refused (409) when it was ever
   * published, when something references it, and when it is the template's
   * only revision — that is `remove()` on the template.
   */
  async removeRevision(
    templateId: string,
    revisionId: string,
  ): Promise<{ templateId: string; revisionId: string; revision: number }> {
    const res = await apiClient.delete<ApiResponse<{ templateId: string; revisionId: string; revision: number }>>(
      `/templates/${templateId}/revisions/${revisionId}`,
    );
    return res.data.data!;
  },

  async revisions(id: string): Promise<TemplateRevision[]> {
    const res = await apiClient.get<ApiResponse<TemplateRevision[]>>(`/templates/${id}/revisions`);
    return res.data.data ?? [];
  },

  /** A new DRAFT revision, numbered after the highest existing one. */
  async createRevision(id: string, data: RevisionDraftInput): Promise<TemplateRevision> {
    const res = await apiClient.post<ApiResponse<TemplateRevision>>(`/templates/${id}/revisions`, data);
    return res.data.data!;
  },

  /** Edit a DRAFT in place. The server refuses (409) once it is published. */
  async updateRevision(revisionId: string, data: Partial<RevisionDraftInput>): Promise<TemplateRevision> {
    const res = await apiClient.patch<ApiResponse<TemplateRevision>>(
      `/templates/revisions/${revisionId}`,
      data,
    );
    return res.data.data!;
  },

  /**
   * Freeze a revision. IRREVERSIBLE by design: a published revision is what a
   * plan pins itself to, and a mutable pin is not a pin.
   *
   * The server answers `{ revision, deps, depsFingerprint }`; this returns the
   * revision. It used to return the envelope as if it were the revision, so
   * the list never showed the publication until a reload.
   */
  async publish(revisionId: string): Promise<TemplateRevision> {
    const res = await apiClient.post<ApiResponse<{ revision: TemplateRevision }>>(
      `/templates/revisions/${revisionId}/publish`,
    );
    return res.data.data!.revision;
  },

  /**
   * Move a revision that left draft along its lifecycle. `deprecated` takes it
   * off the bench's list and out of new rollouts and assignment resolution;
   * renders and plans already made from it keep it. The server accepts
   * `quarantined` and `deprecated` only — there is no way back to `published`
   * — answers 403 on a library revision, and keeps `reason` in its audit log.
   */
  async setStatus(
    revisionId: string,
    status: 'deprecated' | 'quarantined',
    reason: string,
  ): Promise<TemplateRevision> {
    const res = await apiClient.post<ApiResponse<TemplateRevision>>(
      `/templates/revisions/${revisionId}/status`,
      { status, reason },
    );
    return res.data.data!;
  },

  async revision(revisionId: string): Promise<TemplateRevisionWithBody> {
    const res = await apiClient.get<ApiResponse<TemplateRevisionWithBody>>(
      `/templates/revisions/${revisionId}`,
    );
    return res.data.data!;
  },

  async vocabulary(): Promise<TemplateVocabulary> {
    const res = await apiClient.get<ApiResponse<TemplateVocabulary>>('/templates/vocabulary');
    return res.data.data!;
  },

  /**
   * Import one `obliwan-template/1` file or an `obliwan-template-bundle/1`.
   * `dryRun: true` validates and writes nothing. Never publishes.
   */
  async importFile(payload: unknown, opts: { dryRun: boolean }): Promise<TemplateImportReport> {
    const res = await apiClient.post<ApiResponse<TemplateImportReport>>('/templates/import', payload, {
      params: { dryRun: opts.dryRun ? 'true' : 'false' },
    });
    return res.data.data!;
  },

  /** Render a STORED revision on a witness device (TEMPLATE_READ). */
  async previewRevision(
    revisionId: string,
    data: { deviceId: number; overrides?: PreviewOverride[] },
  ): Promise<TemplatePreview> {
    const res = await apiClient.post<ApiResponse<Record<string, unknown>>>(
      `/templates/revisions/${revisionId}/preview`,
      data,
    );
    return normalizePreview(res.data.data ?? {}, 'stored');
  },

  /** Render an UNSAVED body on a witness device (TEMPLATE_WRITE). */
  async previewScratch(data: {
    deviceId: number;
    body: string;
    varSchema?: VarSchema;
    sectionSeverity?: RevisionDraftInput['sectionSeverity'];
    renderOptions?: RenderOptionsInput;
    overrides?: PreviewOverride[];
  }): Promise<TemplatePreview> {
    const res = await apiClient.post<ApiResponse<Record<string, unknown>>>('/templates/preview', data);
    return normalizePreview(res.data.data ?? {}, 'scratch');
  },

  // ── Assignments, as a device page needs them ─────────────────────────────

  /** Which revision applies to this device, and why every other one lost. */
  async deviceResolution(deviceId: number): Promise<DeviceTemplateResolution> {
    const res = await apiClient.get<ApiResponse<DeviceTemplateResolution>>(`/templates/devices/${deviceId}/resolution`);
    const d = res.data.data;
    return { selected: d?.selected ?? [], rejected: d?.rejected ?? [] };
  },

  /** Every assignment of the tenant (the server lists them whole). */
  async listAssignments(): Promise<TemplateAssignment[]> {
    const res = await apiClient.get<ApiResponse<TemplateAssignment[]>>('/templates/assignments');
    return res.data.data ?? [];
  },

  /** Re-pin (a revision id) or follow the latest published revision (null). */
  async setAssignmentRevision(id: string, revisionId: string | null): Promise<void> {
    await apiClient.patch(`/templates/assignments/${id}`, revisionId === null
      ? { pinMode: 'latest_published', revisionId: null }
      : { pinMode: 'pinned', revisionId: Number(revisionId) });
  },

  async removeAssignment(id: string): Promise<void> {
    await apiClient.delete(`/templates/assignments/${id}`);
  },
};

/** One candidate of `GET /templates/devices/:id/resolution` (the fields this
 *  client reads). */
export interface AssignmentCandidate {
  assignmentId: string;
  templateId: string;
  templateName: string;
  scope: 'global' | 'tenant' | 'group' | 'device';
  scopeId: number | null;
  pinMode: 'latest_published' | 'pinned';
  revisionId: string | null;
  revision: number | null;
}

export interface DeviceTemplateResolution {
  selected: AssignmentCandidate[];
  rejected: Array<AssignmentCandidate & { reason: string; detail: string }>;
}

/** One row of `GET /templates/assignments`. */
export interface TemplateAssignment {
  /** God view only: the owning workspace. */
  tenantId?: number;
  tenantName?: string | null;
  id: string;
  scope: 'global' | 'tenant' | 'group' | 'device';
  scopeId: number | null;
  templateId: string;
  templateName: string;
  revisionId: string | null;
  pinMode: 'latest_published' | 'pinned';
  priority: number;
  enabled: boolean;
  reason: string | null;
}
