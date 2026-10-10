import type { Knex } from 'knex';
import { createTwoFilesPatch, structuredPatch } from 'diff';
import { ACTIVE_ROLLOUT_STATUSES } from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { appendAudit } from '../attestation/auditLog.service';
import {
  ENTRY_NAME,
  depsFingerprint,
  extractDependencies,
  resolveLiveClosure,
  sha256,
  type PinnedDep,
} from './loader';

/**
 * version.service.ts — draft, publish, freeze, diff.
 *
 * ┌─ WHAT PUBLICATION ACTUALLY IS ────────────────────────────────────────────┐
 * │ Publishing is not "set status = 'published'". It is, in ONE transaction:  │
 * │                                                                           │
 * │   1. lock the draft (`FOR UPDATE`) so two publishers cannot both compute  │
 * │      a closure against the same partial set and both write pins;          │
 * │   2. parse the body and walk its `{% extends %}` / `{% include %}` /      │
 * │      `{% import %}` graph against the live partial store;                 │
 * │   3. write one `template_revision_deps` row per reached partial, PINNING  │
 * │      the concrete `template_partial_revisions.id` — not the partial;      │
 * │   4. only then flip the status, stamp `published_at`, and set             │
 * │      `deps_pinned` / `deps_count`.                                        │
 * │                                                                           │
 * │ The order is load-bearing. `template_revision_deps_freeze` refuses to     │
 * │ write a pin whose revision has already left `draft`, so steps 3 and 4     │
 * │ cannot be swapped; and `template_revisions_publication_chk` refuses a     │
 * │ non-draft row with `deps_pinned = false`, so step 4 cannot happen without │
 * │ step 3. A publication that crashes between them rolls back whole.         │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * Every refusal in this file is ALSO a database constraint. That is deliberate
 * duplication and not an oversight: the service exists to give an operator a
 * sentence they can act on, the constraint exists because the service is not
 * the only thing that will ever hold a connection to this database.
 */

export type RevisionStatus = 'draft' | 'published' | 'quarantined' | 'deprecated';
export type PartialRevisionStatus = 'draft' | 'published' | 'deprecated';

export class TemplateVersionError extends Error {
  constructor(message: string) { super(message); this.name = 'TemplateVersionError'; }
}

/** Thrown for any attempt to change what a published revision RENDERS. */
export class ImmutableRevisionError extends TemplateVersionError {
  constructor(revisionId: string | number, status: string) {
    super(
      `template revision ${revisionId} is ${status} and immutable; ` +
        'create a new revision instead',
    );
    this.name = 'ImmutableRevisionError';
  }
}

export interface TemplateRecord {
  id: string;
  uuid: string;
  tenant_id: number | null;
  name: string;
  description: string | null;
  brand: string;
  model_pattern: string | null;
  status: string;
}

export interface RevisionRecord {
  id: string;
  uuid: string;
  tenant_id: number | null;
  template_id: string;
  revision: number;
  body: string;
  body_sha256: string;
  var_schema: unknown;
  section_severity: unknown;
  os_min: string | null;
  os_max: string | null;
  engine: string;
  render_options: Record<string, unknown>;
  status: RevisionStatus;
  published_at: Date | null;
  deps_pinned: boolean;
  deps_count: number;
  notes: string | null;
}

/** `tenant_id IS NOT DISTINCT FROM :t` — the only correct way to scope a
 *  nullable tenant column. `= NULL` matches nothing, which would make every
 *  library template invisible to the platform administrator who owns it. */
function whereTenant<T extends Knex.QueryBuilder>(q: T, column: string, tenantId: number | null): T {
  return q.whereRaw(`${column} IS NOT DISTINCT FROM ?`, [tenantId]) as T;
}

// ============================================================================
// Templates
// ============================================================================

export async function createTemplate(
  tenantId: number | null,
  input: {
    name: string;
    brand: string;
    description?: string | null;
    modelPattern?: string | null;
    createdBy?: number | null;
  },
  trx: Knex | Knex.Transaction = db,
): Promise<TemplateRecord> {
  const [row] = await trx('templates')
    .insert({
      tenant_id: tenantId,
      name: input.name.trim(),
      brand: input.brand,
      description: input.description ?? null,
      model_pattern: input.modelPattern ?? null,
      created_by: input.createdBy ?? null,
      updated_by: input.createdBy ?? null,
    })
    .returning('*');
  return row as TemplateRecord;
}

async function loadTemplate(
  trx: Knex | Knex.Transaction,
  tenantId: number | null,
  templateId: string | number,
): Promise<TemplateRecord> {
  const row = await whereTenant(
    trx('templates').where('id', templateId),
    'tenant_id',
    tenantId,
  ).first();
  if (!row) throw new TemplateVersionError(`template ${templateId} does not exist for this tenant`);
  return row as TemplateRecord;
}

// ============================================================================
// Revisions — drafting
// ============================================================================

export interface DraftInput {
  body: string;
  varSchema?: unknown;
  sectionSeverity?: unknown;
  osMin?: string | null;
  osMax?: string | null;
  renderOptions?: Record<string, unknown>;
  notes?: string | null;
  createdBy?: number | null;
}

/**
 * A new draft revision, numbered after the highest existing one.
 *
 * The body is PARSED here, not only at publication. A draft that does not parse
 * is a draft nobody can publish, and finding that out at authoring time costs
 * one round trip while finding it out at rollout time costs a maintenance
 * window. It is not a security check — the sandbox does not trust this parse —
 * it is a courtesy that happens to also stop a computed `{% include %}` from
 * being written at all.
 */
export async function createDraft(
  tenantId: number | null,
  templateId: string | number,
  input: DraftInput,
  trx: Knex | Knex.Transaction = db,
): Promise<RevisionRecord> {
  const template = await loadTemplate(trx, tenantId, templateId);
  extractDependencies(input.body, ENTRY_NAME); // throws on syntax / computed refs

  const [{ max }] = (await trx('template_revisions')
    .where('template_id', template.id)
    .max({ max: 'revision' })) as { max: number | null }[];

  const [row] = await trx('template_revisions')
    .insert({
      template_id: template.id,
      // Overwritten by `template_revisions_tenant_sync`; passed anyway so the
      // INSERT reads the way the table does.
      tenant_id: template.tenant_id,
      revision: (max ?? 0) + 1,
      body: input.body,
      body_sha256: sha256(input.body),
      var_schema: JSON.stringify(input.varSchema ?? {}),
      section_severity: JSON.stringify(input.sectionSeverity ?? {}),
      os_min: input.osMin ?? null,
      os_max: input.osMax ?? null,
      render_options: JSON.stringify(input.renderOptions ?? {}),
      notes: input.notes ?? null,
      status: 'draft',
      created_by: input.createdBy ?? null,
    })
    .returning('*');
  return row as RevisionRecord;
}

export async function getRevision(
  revisionId: string | number,
  trx: Knex | Knex.Transaction = db,
): Promise<RevisionRecord> {
  const row = await trx('template_revisions').where('id', revisionId).first();
  if (!row) throw new TemplateVersionError(`template revision ${revisionId} does not exist`);
  return row as RevisionRecord;
}

/**
 * Edit a DRAFT. Refuses anything else — and the refusal is checked under a row
 * lock, because "read the status, then update" without one is a race that ends
 * with a write landing on a revision that was published a millisecond earlier.
 * The trigger would still catch it; this way the operator gets the right error.
 */
export async function updateDraft(
  tenantId: number | null,
  revisionId: string | number,
  patch: Partial<DraftInput>,
  executor: Knex | Knex.Transaction = db,
): Promise<RevisionRecord> {
  const run = async (trx: Knex.Transaction): Promise<RevisionRecord> => {
    const current = (await whereTenant(
      trx('template_revisions').where('id', revisionId),
      'tenant_id',
      tenantId,
    ).forUpdate().first()) as RevisionRecord | undefined;

    if (!current) {
      throw new TemplateVersionError(`template revision ${revisionId} does not exist for this tenant`);
    }
    if (current.status !== 'draft') {
      throw new ImmutableRevisionError(revisionId, current.status);
    }

    const update: Record<string, unknown> = { updated_at: new Date() };
    if (patch.body !== undefined) {
      extractDependencies(patch.body, ENTRY_NAME);
      update.body = patch.body;
      update.body_sha256 = sha256(patch.body);
    }
    if (patch.varSchema !== undefined) update.var_schema = JSON.stringify(patch.varSchema);
    if (patch.sectionSeverity !== undefined) {
      update.section_severity = JSON.stringify(patch.sectionSeverity);
    }
    if (patch.osMin !== undefined) update.os_min = patch.osMin;
    if (patch.osMax !== undefined) update.os_max = patch.osMax;
    if (patch.renderOptions !== undefined) {
      update.render_options = JSON.stringify(patch.renderOptions);
    }
    if (patch.notes !== undefined) update.notes = patch.notes;

    const [row] = await trx('template_revisions')
      .where('id', revisionId)
      .update(update)
      .returning('*');
    return row as RevisionRecord;
  };

  return isTransaction(executor) ? run(executor) : db.transaction(run);
}

function isTransaction(x: Knex | Knex.Transaction): x is Knex.Transaction {
  return typeof (x as Knex.Transaction).commit === 'function';
}

// ============================================================================
// Publication
// ============================================================================

export interface PublishResult {
  revision: RevisionRecord;
  deps: PinnedDep[];
  depsFingerprint: string;
}

export async function publishRevision(
  tenantId: number | null,
  revisionId: string | number,
  publishedBy: number | null,
  executor: Knex | Knex.Transaction = db,
): Promise<PublishResult> {
  const run = async (trx: Knex.Transaction): Promise<PublishResult> => {
    const current = (await whereTenant(
      trx('template_revisions').where('id', revisionId),
      'tenant_id',
      tenantId,
    ).forUpdate().first()) as RevisionRecord | undefined;

    if (!current) {
      throw new TemplateVersionError(`template revision ${revisionId} does not exist for this tenant`);
    }
    if (current.status !== 'draft') {
      throw new ImmutableRevisionError(revisionId, current.status);
    }

    // Step 2 — resolve the closure against the LIVE partial store. This is the
    // last moment at which "the current partial" means anything for this
    // revision; from the next statement on, it means the pinned one forever.
    const { deps } = await resolveLiveClosure(trx, current.tenant_id, current.body);

    // Step 3 — pin. Written while the row is still a draft, which is the only
    // window `template_revision_deps_freeze` allows.
    if (deps.length > 0) {
      await trx('template_revision_deps').insert(
        deps.map((d) => ({
          revision_id: current.id,
          tenant_id: current.tenant_id,
          name: d.name,
          partial_id: d.partialId,
          partial_revision_id: d.partialRevisionId,
          ref_kind: d.refKind,
          depth: d.depth,
        })),
      );
    }

    // Step 4 — seal.
    const [row] = await trx('template_revisions')
      .where('id', current.id)
      .update({
        status: 'published',
        published_at: new Date(),
        published_by: publishedBy,
        deps_pinned: true,
        deps_count: deps.length,
        updated_at: new Date(),
      })
      .returning('*');

    const fingerprint = depsFingerprint(deps);
    logger.info(
      {
        revisionId: current.id,
        templateId: current.template_id,
        deps: deps.length,
        depsFingerprint: fingerprint,
      },
      'template revision published and its partials pinned',
    );

    return { revision: row as RevisionRecord, deps, depsFingerprint: fingerprint };
  };

  return isTransaction(executor) ? run(executor) : db.transaction(run);
}

/**
 * The lifecycle status of a revision that already left `draft` — the only
 * column of such a row, with `notes`, that this service changes. `quarantined`
 * is also what a failed rollout sets (written directly by
 * `rollout.service.ts`), `deprecated` is what an operator sets: the bench stops
 * offering the revision (`listBenchCandidates` reads `published` only), a new
 * rollout refuses it, and the assignment resolver passes over it.
 *
 * There is no path back to `draft`, here or in the trigger — a revision that
 * could be un-published is a revision whose renders lose their provenance. A
 * return from `deprecated` to `published` is a different matter, and it is NOT
 * refused here: the freeze trigger (migration 008) admits it and so does this
 * function's type.
 * What keeps it out of reach is the HTTP schema (`revisionStatusSchema` accepts
 * `quarantined` and `deprecated` only); nothing in the tree calls this with
 * `published`. Re-offering a deprecated revision's content is a NEW revision
 * started from it, published like any other.
 *
 * Two refusals keep a lifecycle change from loosening a rollout verdict or pulling
 * a revision out from under a rollout in progress:
 *   - NOTHING LEAVES `quarantined`. `render.service` and `siteRender.service`
 *     refuse `quarantined` and accept `deprecated`, so a quarantined → deprecated
 *     move would make renderable again the revision a canary gate proved
 *     harmful. A quarantine set by hand is final in the same way; the content
 *     comes back, if ever, as a new revision.
 *   - No move to anything but `quarantined` while a rollout of the revision is
 *     still active (`ACTIVE_ROLLOUT_STATUSES`, `draft` included). The rollout
 *     path no longer depends on this one for rollout safety: `persistComposition` and
 *     `launchRollout` (change/rollout.service.ts) re-read the revision FOR
 *     SHARE and refuse unless it is `published`, and `failAndRollBack`
 *     quarantines a `published` OR a `deprecated` revision. It stays as
 *     defence in depth, and so that the operator is refused HERE, with the
 *     rollout named, instead of meeting a draft whose launch is refused later
 *     or a running rollout that keeps pushing its pre-compiled plans for a
 *     revision nobody offers any more (nothing re-reads the status once a
 *     rollout runs). Moving TO `quarantined` stays allowed during a rollout:
 *     it is stricter, never looser.
 *   A rollout CREATED concurrently is handled on the rollout side: the FOR
 *   SHARE read in `persistComposition` conflicts with the FOR UPDATE below. A
 *   composition that commits its draft first makes this function wait, and the
 *   active-rollout query, a new READ COMMITTED statement run after the wait,
 *   then sees that draft; one that reads after this commit finds the new status
 *   and refuses with `revision_not_published`.
 *
 * The row is read `FOR UPDATE`, so two operators changing the same revision
 * are serialised and each audit row's `before` is the status it replaced.
 * Asking for the status the row already has writes nothing and audits nothing.
 * `audit`, when given, writes one `template_revision.status_changed` row with
 * the operator's reason, trimmed — the only place that reason is kept, so a
 * blank one is refused rather than stored.
 */
export async function setRevisionStatus(
  tenantId: number | null,
  revisionId: string | number,
  status: Extract<RevisionStatus, 'quarantined' | 'deprecated' | 'published'>,
  trx: Knex | Knex.Transaction = db,
  audit?: { actor: DeleteActor; reason: string },
): Promise<RevisionRecord> {
  const reason = audit ? audit.reason.trim() : null;
  if (audit && !reason) {
    throw new TemplateVersionError('a lifecycle status change needs a non-blank reason');
  }
  const run = async (t: Knex.Transaction): Promise<RevisionRecord> => {
    const current = (await whereTenant(
      t('template_revisions').where('id', revisionId),
      'tenant_id',
      tenantId,
    ).forUpdate().first()) as RevisionRecord | undefined;

    if (!current) {
      throw new TemplateVersionError(`template revision ${revisionId} does not exist for this tenant`);
    }
    if (current.status === 'draft') {
      throw new TemplateVersionError(
        `template revision ${revisionId} is a draft; publish it before changing its lifecycle status`,
      );
    }
    if (current.status === status) return current;
    if (current.status === 'quarantined') {
      throw new TemplateVersionError(
        `template revision ${revisionId} is quarantined, and a quarantine is not lifted by a status change; `
          + 'start a new revision from it if its content is to be offered again',
      );
    }
    if (status !== 'quarantined') {
      const active = (await t('rollouts')
        .where('template_revision_id', current.id)
        .whereIn('status', [...ACTIVE_ROLLOUT_STATUSES])
        .orderBy('id', 'asc')
        .first('id', 'status')) as { id: number | string; status: string } | undefined;
      if (active) {
        throw new TemplateVersionError(
          `template revision ${revisionId} has a rollout that is still ${active.status} (rollout #${active.id}); `
            + `it cannot become ${status} until that rollout finishes or is aborted: `
            + 'a revision stays published while a rollout of it is in progress (quarantining it remains possible)',
        );
      }
    }

    const [row] = await t('template_revisions')
      .where('id', current.id)
      .update({ status, updated_at: new Date() })
      .returning('*');

    if (audit && current.tenant_id !== null) {
      await appendAudit(
        {
          tenantId: current.tenant_id,
          actorType: 'user',
          actorId: audit.actor.userId,
          actorName: audit.actor.username ? audit.actor.username.slice(0, 128) : null,
          action: 'template_revision.status_changed',
          entityType: 'template_revision',
          entityId: String(current.id),
          before: {
            templateId: String(current.template_id),
            revision: Number(current.revision),
            status: current.status,
          },
          after: { status, reason },
        },
        t,
      );
    }
    logger.info(
      { revisionId: String(current.id), templateId: String(current.template_id), from: current.status, to: status },
      'template revision lifecycle status changed',
    );
    return row as RevisionRecord;
  };

  return isTransaction(trx) ? run(trx) : db.transaction(run);
}

// ============================================================================
// Partials
// ============================================================================

export async function createPartial(
  tenantId: number | null,
  input: { name: string; description?: string | null; brand?: string | null; createdBy?: number | null },
  trx: Knex | Knex.Transaction = db,
): Promise<{ id: string; name: string; tenant_id: number | null }> {
  const [row] = await trx('template_partials')
    .insert({
      tenant_id: tenantId,
      name: input.name,
      description: input.description ?? null,
      brand: input.brand ?? null,
      created_by: input.createdBy ?? null,
    })
    .returning('*');
  return row as { id: string; name: string; tenant_id: number | null };
}

export async function createPartialDraft(
  tenantId: number | null,
  partialId: string | number,
  body: string,
  createdBy: number | null = null,
  trx: Knex | Knex.Transaction = db,
): Promise<{ id: string; revision: number; status: PartialRevisionStatus }> {
  const partial = await whereTenant(
    trx('template_partials').where('id', partialId),
    'tenant_id',
    tenantId,
  ).first();
  if (!partial) throw new TemplateVersionError(`partial ${partialId} does not exist for this tenant`);

  extractDependencies(body, (partial as { name: string }).name);

  const [{ max }] = (await trx('template_partial_revisions')
    .where('partial_id', partialId)
    .max({ max: 'revision' })) as { max: number | null }[];

  const [row] = await trx('template_partial_revisions')
    .insert({
      partial_id: partialId,
      tenant_id: (partial as { tenant_id: number | null }).tenant_id,
      revision: (max ?? 0) + 1,
      body,
      body_sha256: sha256(body),
      status: 'draft',
      created_by: createdBy,
    })
    .returning('*');
  return row as { id: string; revision: number; status: PartialRevisionStatus };
}

/**
 * Freeze a partial revision so it becomes pinnable.
 *
 * This is the step that makes "editing a partial" a CREATE rather than an
 * UPDATE: after it, `template_partial_revisions_freeze` refuses every change to
 * the body, and every published template revision that pinned it keeps
 * rendering exactly what it rendered yesterday.
 */
export async function publishPartialRevision(
  tenantId: number | null,
  partialRevisionId: string | number,
  publishedBy: number | null = null,
  trx: Knex | Knex.Transaction = db,
): Promise<{ id: string; status: PartialRevisionStatus }> {
  const current = (await whereTenant(
    trx('template_partial_revisions').where('id', partialRevisionId),
    'tenant_id',
    tenantId,
  ).first()) as { id: string; status: PartialRevisionStatus } | undefined;

  if (!current) {
    throw new TemplateVersionError(
      `partial revision ${partialRevisionId} does not exist for this tenant`,
    );
  }
  if (current.status !== 'draft') {
    throw new TemplateVersionError(
      `partial revision ${partialRevisionId} is already ${current.status} and immutable`,
    );
  }

  const [row] = await trx('template_partial_revisions')
    .where('id', partialRevisionId)
    .update({ status: 'published', published_at: new Date(), published_by: publishedBy, updated_at: new Date() })
    .returning('*');
  return row as { id: string; status: PartialRevisionStatus };
}

// ============================================================================
// Diff
// ============================================================================

export interface RevisionDiff {
  from: { revisionId: string; revision: number; status: string; sha256: string };
  to: { revisionId: string; revision: number; status: string; sha256: string };
  identical: boolean;
  /** Unified patch, ready to be shown verbatim or coloured by the client. */
  patch: string;
  addedLines: number;
  removedLines: number;
  /** Pins that differ between the two revisions. A revision can render
   *  differently from its predecessor WITHOUT a single line of body changing —
   *  it is enough for a partial to have been republished between the two
   *  publications. A body diff alone would show nothing and the operator would
   *  approve a change they never saw. */
  depChanges: {
    name: string;
    fromPartialRevisionId: string | null;
    toPartialRevisionId: string | null;
  }[];
}

export async function diffRevisions(
  fromRevisionId: string | number,
  toRevisionId: string | number,
  trx: Knex | Knex.Transaction = db,
): Promise<RevisionDiff> {
  const [from, to] = await Promise.all([
    getRevision(fromRevisionId, trx),
    getRevision(toRevisionId, trx),
  ]);

  const label = (r: RevisionRecord) => `revision ${r.revision} (${r.status})`;
  const patch = createTwoFilesPatch(
    label(from), label(to),
    from.body, to.body,
    undefined, undefined,
    { context: 3 },
  );

  const structured = structuredPatch(
    label(from), label(to), from.body, to.body, undefined, undefined, { context: 0 },
  );
  let addedLines = 0;
  let removedLines = 0;
  for (const hunk of structured.hunks) {
    for (const line of hunk.lines) {
      if (line.startsWith('+')) addedLines++;
      else if (line.startsWith('-')) removedLines++;
    }
  }

  const pins = (await trx('template_revision_deps')
    .whereIn('revision_id', [from.id, to.id])
    .select('revision_id', 'name', 'partial_revision_id')) as {
    revision_id: string; name: string; partial_revision_id: string;
  }[];

  const fromPins = new Map<string, string>();
  const toPins = new Map<string, string>();
  for (const p of pins) {
    (String(p.revision_id) === String(from.id) ? fromPins : toPins)
      .set(p.name, String(p.partial_revision_id));
  }
  const depChanges: RevisionDiff['depChanges'] = [];
  for (const name of new Set([...fromPins.keys(), ...toPins.keys()])) {
    const a = fromPins.get(name) ?? null;
    const b = toPins.get(name) ?? null;
    if (a !== b) depChanges.push({ name, fromPartialRevisionId: a, toPartialRevisionId: b });
  }
  depChanges.sort((x, y) => x.name.localeCompare(y.name));

  return {
    from: { revisionId: String(from.id), revision: from.revision, status: from.status, sha256: from.body_sha256 },
    to: { revisionId: String(to.id), revision: to.revision, status: to.status, sha256: to.body_sha256 },
    identical: from.body_sha256 === to.body_sha256 && depChanges.length === 0,
    patch,
    addedLines,
    removedLines,
    depChanges,
  };
}

// ============================================================================
// Deletion — a template or a revision that never left `draft`
// ============================================================================
//
// ┌─ WHAT MAY BE DELETED, AND WHY ONLY THAT ─────────────────────────────────┐
// │ A revision that was ever published is PROVENANCE: renders, plans,        │
// │ rollouts and drift verdicts name it, and it is the answer to "why is     │
// │ this line on this router". Status only moves forward (the freeze trigger │
// │ refuses any return to 'draft'), so "status = 'draft'" today means        │
// │ "never published, quarantined or deprecated" — no history column is      │
// │ needed to tell the two apart.                                            │
// │                                                                          │
// │ A draft can still be referenced: a plan compiled from an explicit        │
// │ revision id persists a `config_renders` row, an assignment can pin one,  │
// │ a baseline promotion or a bench compile can name one. Every such column  │
// │ is listed in TEMPLATE_REFERENCES and counted before anything is deleted; │
// │ one hit refuses the whole delete. Several of those FKs are ON DELETE     │
// │ SET NULL or CASCADE, so the database would NOT refuse on its own: it     │
// │ would quietly erase the link. The count is what stops that.              │
// │                                                                          │
// │ TWO references are released instead of refused, both of one shape: a     │
// │ proposal whose decision CREATED the template. (1) The `baseline_drafts`  │
// │ row whose promotion created it (`promoteDraft` in the miner writes a     │
// │ draft-only template and points both columns at it). (2) The              │
// │ `extrapolation_proposals` row whose approval created it                  │
// │ (`approveProposal` in the brick-10 extrapolator does the same; migration │
// │ 083). Refusing on either made every template born of a proposal          │
// │ undeletable, and no endpoint clears that link. Deleting the template     │
// │ undoes the decision instead: a baseline row goes back to 'draft' with    │
// │ its four promotion columns cleared, an extrapolation row back to         │
// │ 'proposed' with its template link and its signed decision cleared. In    │
// │ each case that is the state the decision started from and one the        │
// │ table's own CHECK allows, in the same transaction, and the audit row     │
// │ names it. (The variable values an approval wrote stay: they are the      │
// │ tenant's, and a second approval reports them as already set.) Only a row │
// │ of this tenant pointing at this template AND at one of its revisions is  │
// │ released; any other row is still counted and refuses. Deleting ONE       │
// │ revision never releases either: the revision a decision created stays as │
// │ long as its template does.                                               │
// │                                                                          │
// │ Revisions are deleted EXPLICITLY before their template, never left to    │
// │ the cascade: `template_revisions_freeze` lets a cascaded delete of a     │
// │ published revision through (offboarding a tenant must not be blocked by  │
// │ its own templates), but judges a direct DELETE. Deleting the rows        │
// │ ourselves keeps the trigger as the second wall behind the status check.  │
// │                                                                          │
// │ LOCK ORDER: the template row FOR UPDATE, then its revisions FOR UPDATE.  │
// │ Both deletes take them in that order, so they cannot deadlock each       │
// │ other; `publishRevision` locks only the revision and never the template, │
// │ so a delete waiting on a revision being published re-reads it as         │
// │ published and refuses. An insert that would add a reference (a render,   │
// │ an assignment, a new draft) needs a key-share lock on the row it points  │
// │ at, which FOR UPDATE blocks until this transaction ends.                 │
// └──────────────────────────────────────────────────────────────────────────┘

/** Every column OUTSIDE the template tables that points at a template or a
 *  revision (migrations 008, 010, 017, 042, 049, 083; 014 adds a composite FK on the
 *  assignment pair, covered by the two assignment columns). `testing/
 *  draftDelete.verify.ts` reads the live catalogue and fails if a foreign key
 *  to `templates` or `template_revisions` is missing from this list or from
 *  TEMPLATE_OWNED_CHILDREN, or if an entry's `target` is not the table its
 *  foreign key really points at — a new reference must be counted here or the
 *  delete would erase it. The two `baseline_drafts` and the two
 *  `extrapolation_proposals` entries are still counted after a template delete
 *  has released its own promotion / approval (see above), so a row that does
 *  not match that release refuses like any other. */
export const TEMPLATE_REFERENCES = [
  { table: 'config_renders', column: 'revision_id', target: 'revision', label: 'config render' },
  { table: 'template_assignments', column: 'revision_id', target: 'revision', label: 'assignment' },
  { table: 'template_assignments', column: 'template_id', target: 'template', label: 'assignment' },
  { table: 'rollouts', column: 'template_revision_id', target: 'revision', label: 'rollout' },
  { table: 'baseline_drafts', column: 'template_revision_id', target: 'revision', label: 'baseline promotion' },
  { table: 'baseline_drafts', column: 'template_id', target: 'template', label: 'baseline promotion' },
  { table: 'extrapolation_proposals', column: 'template_revision_id', target: 'revision', label: 'extrapolation approval' },
  { table: 'extrapolation_proposals', column: 'template_id', target: 'template', label: 'extrapolation approval' },
  { table: 'bench_provisionings', column: 'revision_id', target: 'revision', label: 'bench provisioning' },
  { table: 'bench_conformity_checks', column: 'revision_id', target: 'revision', label: 'bench conformity check' },
] as const;

/** Foreign keys to a template or a revision that the deleted row OWNS and that
 *  go with it: the revisions of a template, and a revision's dependency pins
 *  (written only at publication, so a draft has none). */
export const TEMPLATE_OWNED_CHILDREN = [
  { table: 'template_revisions', column: 'template_id' },
  { table: 'template_revision_deps', column: 'revision_id' },
] as const;

/** A delete refused because the row is provenance or still referenced. Always
 *  a 409: the controller maps this class explicitly, BEFORE its "does not
 *  exist" test for TemplateVersionError, because the message embeds the
 *  operator-chosen template name and a name may contain those words. */
export class TemplateDeleteRefusedError extends TemplateVersionError {
  constructor(
    message: string,
    readonly reason: 'not_draft' | 'referenced' | 'last_revision',
    readonly references: Array<{ table: string; column: string; count: number }> = [],
  ) {
    super(message);
    this.name = 'TemplateDeleteRefusedError';
  }
}

export interface DeleteActor {
  userId: number | null;
  username: string | null;
}

export interface DeletedTemplate {
  templateId: string;
  name: string;
  revisionsDeleted: number;
  /** Baseline proposals whose promotion created this template, returned to
   *  'draft' (pending review) by the delete. 0 for a template made by hand. */
  baselineDraftsUnpromoted: number;
  /** Extrapolation proposals whose approval created this template, returned
   *  to 'proposed' (awaiting a decision) by the delete. 0 for a template made
   *  by hand. */
  extrapolationProposalsReopened: number;
}

export interface DeletedRevision {
  templateId: string;
  revisionId: string;
  revision: number;
}

interface LockedRevision {
  id: string;
  revision: number;
  status: string;
  published_at: Date | null;
  body_sha256: string;
}

/** Counts every reference listed in TEMPLATE_REFERENCES. `templateId` null
 *  skips the template-level columns: a single revision's delete leaves an
 *  assignment that follows the template's latest PUBLISHED revision alone. */
async function countReferences(
  trx: Knex.Transaction,
  templateId: string | null,
  revisionIds: string[],
): Promise<Array<{ table: string; column: string; label: string; count: number }>> {
  const hits: Array<{ table: string; column: string; label: string; count: number }> = [];
  for (const ref of TEMPLATE_REFERENCES) {
    if (ref.target === 'template' && templateId === null) continue;
    if (ref.target === 'revision' && revisionIds.length === 0) continue;
    const q = trx(ref.table);
    const [{ n }] = (await (ref.target === 'template'
      ? q.where(ref.column, templateId as string)
      : q.whereIn(ref.column, revisionIds)
    ).count({ n: '*' })) as Array<{ n: string | number }>;
    const count = Number(n);
    if (count > 0) hits.push({ table: ref.table, column: ref.column, label: ref.label, count });
  }
  return hits;
}

/** "2 config renders, 1 assignment". A table counted through two columns (an
 *  assignment by template and by pinned revision, a baseline promotion by
 *  both) can name the same row twice, so each label reports the larger of its
 *  counts rather than their sum: a lower bound, never an inflated one. */
function describeReferences(hits: Array<{ label: string; count: number }>): string {
  const merged = new Map<string, number>();
  for (const h of hits) merged.set(h.label, Math.max(merged.get(h.label) ?? 0, h.count));
  return [...merged].map(([label, n]) => `${n} ${label}${n > 1 ? 's' : ''}`).join(', ');
}

function isRestrictOrFk(e: unknown): boolean {
  const code = (e as { code?: unknown } | null)?.code;
  return code === '23001' || code === '23503';
}

/**
 * Delete a template that never left draft, with all its (draft) revisions.
 *
 * Refused (409) when any revision is or was published, quarantined or
 * deprecated — archive it instead — and when anything in TEMPLATE_REFERENCES
 * still points at the template or one of its revisions, except the baseline
 * promotion that created it, which is undone (the proposal returns to
 * 'draft'), and the extrapolation approval that created it, likewise undone
 * (the proposal returns to 'proposed'). A template with no revision at all is deletable. The audit row is
 * written in the same transaction: a failed ledger write rolls the delete
 * back, release included, and so does any refusal raised after the release.
 *
 * `tenantId` is a number and the predicate is `tenant_id = :t`: a library
 * template (tenant_id NULL) is never matched, whatever id is passed.
 */
export async function deleteDraftTemplate(
  tenantId: number,
  templateId: string | number,
  actor: DeleteActor,
): Promise<DeletedTemplate> {
  return db.transaction(async (trx) => {
    const template = (await trx('templates')
      .where({ id: templateId, tenant_id: tenantId })
      .forUpdate()
      .first()) as TemplateRecord | undefined;
    if (!template) {
      throw new TemplateVersionError(`template ${templateId} does not exist for this tenant`);
    }

    const revisions = (await trx('template_revisions')
      .where('template_id', template.id)
      .orderBy('revision', 'asc')
      .forUpdate()
      .select('id', 'revision', 'status', 'published_at', 'body_sha256')) as LockedRevision[];

    const frozen = revisions.filter((r) => r.status !== 'draft' || r.published_at !== null);
    if (frozen.length > 0) {
      throw new TemplateDeleteRefusedError(
        `Template "${template.name}" cannot be deleted: revision(s) ` +
          `${frozen.map((r) => `#${r.revision} (${r.status})`).join(', ')} left draft, and a ` +
          'revision that was ever published is the provenance of what it rendered. ' +
          'Archive the template instead.',
        'not_draft',
      );
    }

    const ids = revisions.map((r) => String(r.id));

    // The promotion that created this template is undone, not counted (see
    // the box above). The predicate is the exact shape `promoteDraft` writes;
    // a row that does not match it is left alone and refuses below.
    const unpromoted = ids.length === 0
      ? []
      : ((await trx('baseline_drafts')
        .where({ tenant_id: tenantId, status: 'promoted', template_id: template.id })
        .whereIn('template_revision_id', ids)
        .update({
          status: 'draft',
          template_id: null,
          template_revision_id: null,
          promoted_at: null,
          promoted_by: null,
          updated_at: trx.fn.now(),
        })
        .returning(['id', 'run_id', 'cluster_id'])) as Array<{
          id: string | number; run_id: string | number; cluster_id: string | number;
        }>);

    // Same for the extrapolation approval that created it: the proposal goes
    // back to 'proposed' with its template link and its signed decision
    // cleared (`extrapolation_proposals_decision_chk` allows a proposed row
    // only without `decided_at`; the decision itself stays in the audit
    // ledger as `extrapolation.approved`). Exact shape `approveProposal`
    // writes: this tenant, 'approved', this template AND one of its revisions.
    const reopened = ids.length === 0
      ? []
      : ((await trx('extrapolation_proposals')
        .where({ tenant_id: tenantId, status: 'approved', template_id: template.id })
        .whereIn('template_revision_id', ids)
        .update({
          status: 'proposed',
          template_id: null,
          template_revision_id: null,
          decided_by: null,
          decided_at: null,
          decision_note: null,
          updated_at: trx.fn.now(),
        })
        .returning(['id', 'run_id', 'label'])) as Array<{
          id: string | number; run_id: string | number; label: string;
        }>);

    const hits = await countReferences(trx, String(template.id), ids);
    if (hits.length > 0) {
      const onlyAssignments = hits.every((h) => h.table === 'template_assignments');
      throw new TemplateDeleteRefusedError(
        `Template "${template.name}" cannot be deleted: it is still referenced ` +
          `(${describeReferences(hits)}). ` +
          (onlyAssignments
            ? 'Remove those assignments first, or archive the template instead.'
            : 'Archive the template instead.'),
        'referenced',
        hits.map(({ table, column, count }) => ({ table, column, count })),
      );
    }

    try {
      if (ids.length > 0) await trx('template_revisions').whereIn('id', ids).del();
      await trx('templates').where({ id: template.id, tenant_id: tenantId }).del();
    } catch (e) {
      // Unreachable while the locks above hold; mapped anyway so a reference
      // nobody listed surfaces as the refusal it is, not as a 500.
      if (isRestrictOrFk(e)) {
        throw new TemplateDeleteRefusedError(
          `Template "${template.name}" cannot be deleted: the database refused it because ` +
            'something still references it. Archive the template instead.',
          'referenced',
        );
      }
      throw e;
    }

    await appendAudit(
      {
        tenantId,
        actorType: 'user',
        actorId: actor.userId,
        actorName: actor.username ? actor.username.slice(0, 128) : null,
        action: 'template.deleted',
        entityType: 'template',
        entityId: String(template.id),
        before: {
          name: template.name,
          brand: template.brand,
          description: template.description,
          modelPattern: template.model_pattern,
          status: template.status,
          revisions: revisions.map((r) => ({
            id: String(r.id),
            revision: Number(r.revision),
            status: r.status,
            bodySha256: r.body_sha256,
          })),
        },
        // Present only when a promotion or an approval was undone: the side
        // effect on the baseline / extrapolator screen is part of the act, and
        // the ledger says so.
        after: unpromoted.length > 0 || reopened.length > 0
          ? {
            ...(unpromoted.length > 0
              ? {
                baselineDraftsUnpromoted: unpromoted.map((b) => ({
                  id: String(b.id),
                  runId: String(b.run_id),
                  clusterId: String(b.cluster_id),
                })),
              }
              : {}),
            ...(reopened.length > 0
              ? {
                extrapolationProposalsReopened: reopened.map((p) => ({
                  id: String(p.id),
                  runId: String(p.run_id),
                  label: String(p.label),
                })),
              }
              : {}),
          }
          : undefined,
      },
      trx,
    );

    logger.info(
      {
        templateId: String(template.id),
        tenantId,
        revisions: ids.length,
        baselineDraftsUnpromoted: unpromoted.length,
        extrapolationProposalsReopened: reopened.length,
      },
      'draft-only template deleted',
    );
    return {
      templateId: String(template.id),
      name: template.name,
      revisionsDeleted: ids.length,
      baselineDraftsUnpromoted: unpromoted.length,
      extrapolationProposalsReopened: reopened.length,
    };
  });
}

/**
 * Delete ONE draft revision of a template.
 *
 * Refused (409) when the revision is or was published, when anything in
 * TEMPLATE_REFERENCES points at it (a baseline promotion included: unlike the
 * template delete, this one never undoes it), and when it is the template's ONLY
 * revision: this endpoint deletes the row its URL names and nothing else, so
 * removing the last revision is the template's own delete, which audits the
 * template and its revisions as one act. `templateId` must be the revision's
 * template; a mismatched pair is "does not exist" (404), never a guess.
 */
export async function deleteDraftRevision(
  tenantId: number,
  templateId: string | number,
  revisionId: string | number,
  actor: DeleteActor,
): Promise<DeletedRevision> {
  return db.transaction(async (trx) => {
    const template = (await trx('templates')
      .where({ id: templateId, tenant_id: tenantId })
      .forUpdate()
      .first()) as TemplateRecord | undefined;
    const current = template
      ? ((await trx('template_revisions')
        .where({ id: revisionId, template_id: template.id, tenant_id: tenantId })
        .forUpdate()
        .first('id', 'revision', 'status', 'published_at', 'body_sha256', 'notes')) as
        (LockedRevision & { notes: string | null }) | undefined)
      : undefined;
    if (!template || !current) {
      throw new TemplateVersionError(
        `template revision ${revisionId} does not exist for this tenant and template`,
      );
    }

    if (current.status !== 'draft' || current.published_at !== null) {
      throw new TemplateDeleteRefusedError(
        `Revision #${current.revision} of "${template.name}" is ${current.status} and cannot be ` +
          'deleted: a revision that was ever published is the provenance of what it rendered. ' +
          'Deprecate it, or archive the template.',
        'not_draft',
      );
    }

    const [{ n: siblings }] = (await trx('template_revisions')
      .where('template_id', template.id)
      .whereNot('id', current.id)
      .count({ n: '*' })) as Array<{ n: string | number }>;
    if (Number(siblings) === 0) {
      throw new TemplateDeleteRefusedError(
        `Revision #${current.revision} is the only revision of "${template.name}". ` +
          'Delete the template itself instead.',
        'last_revision',
      );
    }

    const hits = await countReferences(trx, null, [String(current.id)]);
    if (hits.length > 0) {
      // A baseline promotion and an extrapolation approval are the references
      // the operator can undo, and only through the template delete: name that
      // operation.
      const promoted = hits.some((h) => h.table === 'baseline_drafts');
      const approved = hits.some((h) => h.table === 'extrapolation_proposals');
      throw new TemplateDeleteRefusedError(
        `Revision #${current.revision} of "${template.name}" cannot be deleted: it is still ` +
          `referenced (${describeReferences(hits)}).` +
          (promoted
            ? ' A baseline promotion created it, and it stays as long as its template does. ' +
              'Deleting the template itself undoes that promotion and returns the proposal ' +
              'to the baseline review; that is only possible while none of its revisions ' +
              'was ever published.'
            : '') +
          (approved
            ? ' An extrapolation approval created it, and it stays as long as its template ' +
              'does. Deleting the template itself undoes that approval and returns the ' +
              'proposal to the extrapolator; that is only possible while none of its ' +
              'revisions was ever published.'
            : ''),
        'referenced',
        hits.map(({ table, column, count }) => ({ table, column, count })),
      );
    }

    try {
      await trx('template_revisions').where('id', current.id).del();
    } catch (e) {
      if (isRestrictOrFk(e)) {
        throw new TemplateDeleteRefusedError(
          `Revision #${current.revision} of "${template.name}" cannot be deleted: the database ` +
            'refused it because something still references it.',
          'referenced',
        );
      }
      throw e;
    }

    await appendAudit(
      {
        tenantId,
        actorType: 'user',
        actorId: actor.userId,
        actorName: actor.username ? actor.username.slice(0, 128) : null,
        action: 'template_revision.deleted',
        entityType: 'template_revision',
        entityId: String(current.id),
        before: {
          templateId: String(template.id),
          templateName: template.name,
          revision: Number(current.revision),
          status: current.status,
          bodySha256: current.body_sha256,
          notes: current.notes,
        },
      },
      trx,
    );

    logger.info(
      { templateId: String(template.id), revisionId: String(current.id), tenantId },
      'draft template revision deleted',
    );
    return {
      templateId: String(template.id),
      revisionId: String(current.id),
      revision: Number(current.revision),
    };
  });
}

export const versionService = {
  createTemplate,
  createDraft,
  updateDraft,
  getRevision,
  publishRevision,
  setRevisionStatus,
  createPartial,
  createPartialDraft,
  publishPartialRevision,
  diffRevisions,
  deleteDraftTemplate,
  deleteDraftRevision,
};
