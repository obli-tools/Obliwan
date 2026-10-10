/**
 * ObliWAN — Quick Setup Tenant: one customer workspace prepared from its files.
 *
 * Up to four optional parts, each SELECTED by being present in the request:
 * a variables table, a template file, the tenant's allocation rule and the
 * site list. `checkSetup` judges every selected part and the cross-checks
 * between them, writing NOTHING; `applySetup` re-runs that check and, when it
 * finds no error, writes the parts one after the other — each through the
 * service that already writes it, under that service's own guards:
 *
 *   template          import.service `applyImport` (DRAFT revisions, never published)
 *   variables         variableResolver `setInstanceBulk` / `setBulk` (vault for secrets)
 *   allocationPolicy  allocator `upsertPolicy` (allocation lock, conflict checks)
 *   publish           version.service `publishRevision` (pins the partials)
 *   sites             siteImport `importSites` (+ the optional allocation)
 *   siteVariables     variableResolver `setBulk` at the site level
 *
 * That ORDER is the point (shared/src/tenantSetup.ts SETUP_STEPS): the site
 * import judges `var:` columns against PUBLISHED declarations only, so the
 * sites follow the publication; site-level rows need their site, so they come
 * last; a 'shared' PPP rule needs the instance secret first; and a revision
 * is published only once the values and the rule it renders with exist,
 * because the bench offers every published revision.
 *
 * ┌─ What this file promises ─────────────────────────────────────────────────┐
 * │ • The tenant is the caller's SESSION workspace, passed in by the        │
 * │   controller; nothing in a file chooses it (a bundle's `tenant` is       │
 * │   informational). Every read is tenant-scoped; instance rows are the    │
 * │   one exception, by definition, and they need an explicit              │
 * │   acknowledgement to be applied.                                         │
 * │ • The session's workspace is shared by every tab of the browser, so    │
 * │   each entry point first compares it with the workspace the request    │
 * │   was prepared for (`expectedTenantId`) and refuses a mismatch before   │
 * │   reading anything (SetupTenantMismatchError → 409).                    │
 * │ • The check writes nothing: the template plan, the site import and the  │
 * │   rule are all judged in their services' own dry-run modes, the rule   │
 * │   inside a transaction that is rolled back.                              │
 * │ • Apply never trusts an earlier dry run: it judges the same body again, │
 * │   and refuses (nothing written) on any error.                            │
 * │ • A step that fails stops the later ones, and the report says which    │
 * │   steps were written. The steps are separate services, each committed   │
 * │   on its own: there is no transaction around the whole setup, and a     │
 * │   re-run of the same files finds the written parts `unchanged`.          │
 * │ • No response, log line or audit entry carries a variable VALUE. Row    │
 * │   reports carry keys and actions; issues carry keys, levels and counts; │
 * │   the reused services' reports are value-free by their own contracts.  │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

import {
  MASTER_TENANT_ID,
  MAX_SETUP_BODY_CHARS,
  MAX_SETUP_VARIABLE_ROWS,
  SETUP_PARTS,
  SETUP_STEPS,
  computedSuppliedKeys,
  resolveRequirements,
  type DeclaredKeyView,
  type SetupIssue,
  type SetupPart,
  type SetupPolicyFile,
  type SetupStep,
  type SetupStepResult,
  type SetupVariableRow,
  type StoredValueView,
  type TenantSetupContext,
  type TenantSetupReport,
  type TenantSetupRequest,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { appendAudit } from '../attestation/auditLog.service';
import {
  applyImport,
  dryRunImport,
  planImport,
  TemplateImportFormatError,
  type ImportItemReport,
  type ImportReport,
} from '../template/import.service';
import { resolveLiveClosure, TemplateDependencyError } from '../template/loader';
import { TemplateVersionError, versionService } from '../template/version.service';
import {
  VARIABLE_SCOPE_RANK,
  declaredSiteKeys,
  foldChain,
  variableResolver,
  type ChainRow,
  type JsonValue,
  type ResolvedVariables,
  type VariableMeta,
} from '../template/variableResolver.service';
import {
  AllocationError,
  SHARED_PPP_PASSWORD_KEY,
  checkPolicy,
  getInstanceDomain,
  getPolicy,
  listConcentrators,
  listPools,
  upsertPolicy,
  validatePolicyInput,
  type AllocationPolicyView,
} from '../allocation';
import { loadPools } from '../allocation/allocator';
import { parseSiteCodeFormat, type SiteCodeFormat } from '../allocation/policy';
import { loadSiteCodeFormat } from '../fleet/siteCodeFormat';
import {
  SITE_IMPORT_MAX_ROWS,
  SiteImportFileError,
  importSites,
  mapHeader,
  parseCsv,
  type SiteImportOptions,
  type SiteImportResult,
} from '../fleet/siteImport.service';
import {
  buildDeclarations,
  fileReference,
  loadPublishedReferences,
  loadReferenceRevisions,
  type SetupReference,
} from './declarations';
import { issue } from './issues';
import { resolvePolicyRefs } from './policyPart';
import { judgeRows, type FileSite, type RowWrite } from './variablesPart';

// ============================================================================
// Errors
// ============================================================================

/** Another quick setup of this workspace is running in this process. */
export class SetupBusyError extends Error {
  constructor() {
    super('A quick setup is already running for this workspace.');
    this.name = 'SetupBusyError';
  }
}

/** The apply's own check found errors: nothing was written. */
export class SetupRefusedError extends Error {
  constructor(readonly report: TenantSetupReport) {
    super('The setup has errors; nothing was written.');
    this.name = 'SetupRefusedError';
  }
}

/** The request was prepared for another workspace than the session's
 *  (shared/src/tenantSetup.ts SETUP_TENANT_MISMATCH). Thrown before anything
 *  is read or written; the controller answers 409. */
export class SetupTenantMismatchError extends Error {
  constructor() {
    super(
      'The session is no longer on the workspace this setup was prepared for (it was switched, ' +
        'perhaps in another tab): nothing was read or written.',
    );
    this.name = 'SetupTenantMismatchError';
  }
}

function assertExpectedTenant(tenantId: number, expectedTenantId: unknown): void {
  if (expectedTenantId !== tenantId) throw new SetupTenantMismatchError();
}

/** The request cannot be judged at all (a context template that does not
 *  import, a revision that does not exist). The controller maps `status`. */
export class SetupInputError extends Error {
  constructor(readonly status: 400 | 404, message: string) {
    super(message);
    this.name = 'SetupInputError';
  }
}

// ============================================================================
// Reads
// ============================================================================

type PlannedImport = Awaited<ReturnType<typeof planImport>>;

function toStoredView(vars: ResolvedVariables): Record<string, StoredValueView> {
  const out: Record<string, StoredValueView> = {};
  for (const [k, v] of Object.entries(vars)) {
    out[k] = { value: v.value, isSecret: v.isSecret, redacted: v.redacted, fingerprint: v.fingerprint };
  }
  return out;
}

/** The three wide levels, REDACTED (the resolver's own reads). */
async function loadWideValues(tenantId: number): Promise<{
  instance: ResolvedVariables;
  global: ResolvedVariables;
  tenant: ResolvedVariables;
}> {
  return {
    instance: await variableResolver.getInstance(tenantId),
    global: await variableResolver.getByScope(tenantId, 'global', null),
    tenant: await variableResolver.getByScope(tenantId, 'tenant', null),
  };
}

/**
 * The values stored AT the site level of each site, redacted, in ONE query
 * (chunked by 1000 ids), folded exactly as `getByScope` folds one site. The
 * fold decrypts a secret to fingerprint it; only the redacted `variables`
 * leave this function, the plaintexts are dropped on the spot.
 */
async function loadSiteValues(tenantId: number, siteIds: readonly number[]): Promise<Map<number, ResolvedVariables>> {
  const out = new Map<number, ResolvedVariables>();
  const ids = [...new Set(siteIds)];
  const bySite = new Map<number, ChainRow[]>();
  for (let i = 0; i < ids.length; i += 1000) {
    const rows = (await db('config_variables')
      .where({ tenant_id: tenantId, scope: 'site' })
      .whereIn('scope_id', ids.slice(i, i + 1000))
      .select('scope_id', 'key', 'value', 'is_secret', 'secret_enc')) as Array<{
      scope_id: number;
      key: string;
      value: unknown;
      is_secret: boolean;
      secret_enc: string | null;
    }>;
    for (const r of rows) {
      const siteId = Number(r.scope_id);
      const list = bySite.get(siteId) ?? [];
      list.push({
        scope: 'site',
        rank: VARIABLE_SCOPE_RANK.site,
        depth: null,
        src_id: siteId,
        src_name: null,
        key: r.key,
        value: r.value,
        is_secret: r.is_secret,
        secret_enc: r.secret_enc,
      });
      bySite.set(siteId, list);
    }
  }
  for (const id of ids) out.set(id, foldChain(tenantId, bySite.get(id) ?? []).variables);
  return out;
}

function formatText(f: SiteCodeFormat): string {
  return f.kind === 'free' ? 'free' : `digits:${f.length}`;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** The rule's shape as the requirements need it. */
interface EffectivePolicy {
  hasLan: boolean;
  hasIdentity: boolean;
  derivedKeys: string[];
}

function effectiveFromView(view: AllocationPolicyView | null): EffectivePolicy | null {
  if (!view) return null;
  return {
    hasLan: view.lan !== null,
    hasIdentity: view.systemIdentityTemplate !== null,
    derivedKeys: Object.keys(view.derived ?? {}),
  };
}

// ============================================================================
// The check
// ============================================================================

interface CheckPlan {
  report: TenantSetupReport;
  /** The writes of the variables part (values: internal, never serialised). */
  writes: RowWrite[];
  /** The rule with ids resolved, when the part is selected and valid. */
  policyInput: Record<string, unknown> | null;
}

async function runCheck(
  tenantId: number,
  req: TenantSetupRequest,
  ctx: { userId: number | null; forApply: boolean },
): Promise<CheckPlan> {
  const parts = req.parts;
  const issues: SetupIssue[] = [];
  const selected = SETUP_PARTS.filter((p) => parts[p] !== undefined);

  // ── 4.1 the workspace ─────────────────────────────────────────────────────
  const tenant = (await db('tenants').where({ id: tenantId }).first('id', 'name', 'slug')) as
    | { id: number; name: string; slug: string }
    | undefined;
  if (!tenant) throw new SetupInputError(404, 'This workspace does not exist.');
  if (tenantId === MASTER_TENANT_ID) issues.push(issue('MASTER_TENANT', 'setup'));

  // ── 4.2 the template ──────────────────────────────────────────────────────
  const tpl = parts.template;
  let planned: PlannedImport | null = null;
  let templateReport: ImportReport | null = null;
  const fileRefs: SetupReference[] = [];
  let publishPlan: NonNullable<TenantSetupReport['template']>['publish']['plan'] = [];
  if (tpl) {
    try {
      planned = await planImport(tenantId, tpl.file);
      templateReport = await dryRunImport(tenantId, tpl.file);
    } catch (err) {
      if (!(err instanceof TemplateImportFormatError)) throw err;
      issues.push(issue('TEMPLATE_FORMAT', 'template', { message: err.message }));
    }
    if (planned) {
      for (const item of planned.items) {
        if (item.errors.length > 0) {
          issues.push(issue('TEMPLATE_ENTRY_INVALID', 'template', {
            index: item.index, name: item.name, count: item.errors.length,
          }));
        }
      }
      // Newest first: a later entry of the file is the newer revision.
      for (const item of [...planned.items].reverse()) {
        const entry = planned.entries[item.index];
        if (item.errors.length === 0 && entry.revision) {
          fileRefs.push(fileReference(item.name, entry.revision.varSchema ?? {}));
        }
      }
      if (tpl.publish) publishPlan = await planPublication(tenantId, planned, issues);
    }
  }

  // ── 4.3 the references ────────────────────────────────────────────────────
  const { refs: picked, missing } = await loadReferenceRevisions(tenantId, req.referenceRevisionIds ?? []);
  for (const id of missing) issues.push(issue('REFERENCE_REVISION_NOT_FOUND', 'setup', { revisionId: id }));
  let refs: SetupReference[] = [...fileRefs, ...picked];
  if (refs.length === 0) refs = await loadPublishedReferences(tenantId);
  if (refs.length === 0) issues.push(issue('NO_REFERENCE_TEMPLATE', 'setup'));
  const declarations = buildDeclarations(refs);
  const declMap = new Map(declarations.map((d) => [d.key, d]));

  // ── 4.4 the allocation rule ───────────────────────────────────────────────
  const storedPolicy = await getPolicy(tenantId);
  const storedFormat = await loadSiteCodeFormat(db, tenantId);
  let policyInput: Record<string, unknown> | null = null;
  let effective: EffectivePolicy | null = null;
  let codeFormatOverride: SiteCodeFormat | undefined;
  let checkedPolicy: NonNullable<TenantSetupReport['allocationPolicy']> | undefined;
  const policyFile = parts.allocationPolicy?.policy as SetupPolicyFile | Record<string, unknown> | undefined;
  if (parts.allocationPolicy) {
    const pools = await listPools();
    const concentrators = (await listConcentrators()).filter(
      (c) => c.tenantId === tenantId || c.tenantId === MASTER_TENANT_ID,
    );
    const resolved = resolvePolicyRefs(policyFile, pools, concentrators);
    issues.push(...resolved.issues);
    const part: NonNullable<TenantSetupReport['allocationPolicy']> = { resolved: resolved.input, ok: false };
    if (resolved.input) {
      try {
        await checkPolicy(tenantId, resolved.input, {
          assumeSharedPassword: suppliesSharedPassword(parts.variables?.rows ?? [], declMap),
        });
        part.ok = true;
        policyInput = resolved.input;
      } catch (err) {
        if (!(err instanceof AllocationError)) throw err;
        // `holder` is never relayed: it carries another tenant's ids.
        part.error = { reason: err.reason, message: err.message, details: err.details ?? {} };
        issues.push(issue('POLICY_INVALID', 'allocationPolicy', {
          reason: err.reason, message: err.message, details: err.details ?? {},
        }));
      }
    }
    // The first rule freezes the slug (tenant.routes `slugFrozenReason`) —
    // unless allocations already froze it.
    if (!storedPolicy) {
      const [alloc] = await db('site_provisioning').where({ tenant_id: tenantId }).count<{ n: string }[]>('* as n');
      if (Number(alloc?.n ?? 0) === 0) issues.push(issue('SLUG_FREEZES', 'allocationPolicy', { slug: tenant.slug }));
    }
    if (policyInput) {
      const v = validatePolicyInput(policyInput, { tenantId, pools: await loadPools(db), probe: false });
      if (v.ok) {
        effective = {
          hasLan: v.policy.lan !== null,
          hasIdentity: v.policy.identity !== null,
          derivedKeys: v.policy.derived.map((d) => d.key),
        };
      }
    }
    if (isRecord(policyFile) && 'siteCodeFormat' in policyFile) {
      const f = parseSiteCodeFormat(policyFile.siteCodeFormat);
      if (f.ok && formatText(f.format) !== formatText(storedFormat)) {
        codeFormatOverride = f.format;
        if (parts.sites) issues.push(issue('SITES_CODE_FORMAT_OVERRIDE', 'sites', { format: formatText(f.format) }));
      }
    }
    checkedPolicy = part;
  }
  // The file carried a rule and it was refused: the requirements below say so
  // rather than "no allocation rule", which reads as if the file had none.
  const fileRuleRefused = parts.allocationPolicy !== undefined && effective === null;
  if (!effective) effective = effectiveFromView(storedPolicy);

  // ── 4.5 the sites ─────────────────────────────────────────────────────────
  const fileSites: FileSite[] = [];
  let sitesResult: SiteImportResult | null = null;
  if (parts.sites) {
    const csv = parts.sites.csv;
    if (tpl && !tpl.publish && fileRefs.length > 0) {
      const keys = await keysNeedingPublication(tenantId, csv, fileRefs);
      if (keys.length > 0) issues.push(issue('SITE_VAR_NEEDS_PUBLISH', 'sites', { keys }));
    }
    try {
      sitesResult = await importSites(tenantId, csv, {
        dryRun: true,
        allocate: parts.sites.allocate,
        canWriteVariables: true,
        canWriteSchedule: true,
        // The comparison with the CHR is advice for the operator's screen; the
        // apply's own re-check does not need it.
        chr: ctx.forApply ? undefined : 'full',
        updatedBy: ctx.userId,
        codeFormatOverride,
        extraDeclarations: tpl?.publish ? fileRefs.map((r) => r.decl) : [],
      });
    } catch (err) {
      if (!(err instanceof SiteImportFileError)) throw err;
      issues.push(issue('SITES_FILE', 'sites', { problems: err.problems }));
    }
    if (sitesResult) {
      if (sitesResult.summary.rejected > 0) {
        issues.push(issue('SITES_ROWS_REJECTED', 'sites', { count: sitesResult.summary.rejected }));
      }
      if (parts.allocationPolicy && sitesResult.chr) issues.push(issue('CHR_COMPARE_STORED_RULE', 'sites'));
      fileSites.push(...fileSitesOf(csv, sitesResult));
    }
    if (parts.sites.allocate && effective === null) issues.push(issue('ALLOCATE_WITHOUT_POLICY', 'sites'));
  }

  // ── 4.6 the variables ─────────────────────────────────────────────────────
  const wideValues = await loadWideValues(tenantId);
  const rows = parts.variables?.rows ?? [];
  const siteRefs = [
    ...new Set(
      rows
        .filter((r) => r.level === 'site' && typeof r.scopeRef === 'string' && r.scopeRef.trim() !== '')
        .map((r) => (r.scopeRef as string).trim()),
    ),
  ];
  const existingSites = new Map<string, number>();
  for (let i = 0; i < siteRefs.length; i += 1000) {
    const found = (await db('sites')
      .where('tenant_id', tenantId)
      .whereIn('code', siteRefs.slice(i, i + 1000))
      .select('id', 'code')) as Array<{ id: number; code: string }>;
    for (const s of found) existingSites.set(s.code, Number(s.id));
  }
  const siteIds = [
    ...existingSites.values(),
    ...fileSites.map((s) => s.existingSiteId).filter((id): id is number => id !== null),
  ];
  const siteValues = await loadSiteValues(tenantId, siteIds);
  const judged = judgeRows({
    rows,
    declarations: declMap,
    refs,
    stored: wideValues,
    siteValues,
    fileSites,
    existingSites,
  });
  issues.push(...judged.issues);
  if (judged.instanceValueRows > 0) {
    issues.push(issue('INSTANCE_ROWS', 'variables', { count: judged.instanceValueRows }));
    if (ctx.forApply && req.acknowledgeInstanceScope !== true) {
      issues.push(issue('INSTANCE_NOT_ACKNOWLEDGED', 'variables', { count: judged.instanceValueRows }));
    }
  }

  // ── 4.7 across the parts ──────────────────────────────────────────────────
  /** Valid rows that carry a value, by level|site code|key. */
  const valued = judged.rows.filter((r) => r.action !== 'invalid' && rows[r.index].value !== undefined);
  const written = new Set<string>();
  for (const r of valued) written.add(`${r.level}\u0000${judged.siteCodes[r.index] ?? ''}\u0000${r.key}`);
  const rowAt = (level: string, key: string, site = ''): boolean => written.has(`${level}\u0000${site}\u0000${key}`);
  const has = (vars: ResolvedVariables, key: string): boolean => Object.prototype.hasOwnProperty.call(vars, key);

  const wide = new Set<string>();
  for (const level of ['instance', 'global', 'tenant'] as const) {
    for (const k of Object.keys(wideValues[level])) wide.add(k);
  }
  for (const r of valued) if (r.level !== 'site') wide.add(r.key);

  for (const d of declarations) {
    if ((d.level === 'tenant' || d.level === 'global') && d.hasDefault) {
      const narrower =
        rowAt('tenant', d.key) || rowAt('global', d.key) ||
        has(wideValues.tenant, d.key) || has(wideValues.global, d.key);
      const atInstance = has(wideValues.instance, d.key) || rowAt('instance', d.key);
      if (!narrower && atInstance) issues.push(issue('INSTANCE_SHADOWS_DEFAULT', 'variables', { key: d.key }));
    }
  }
  for (const level of ['instance', 'global', 'tenant'] as const) {
    for (const [key, v] of Object.entries(wideValues[level])) {
      const d = declMap.get(key);
      if (!d || d.secrecyConflict || v.isSecret === d.secret || rowAt(level, key)) continue;
      issues.push(issue('STORED_SECRECY_MISMATCH', 'variables', { key, level, storedSecret: v.isSecret }));
    }
  }
  for (const key of effective?.derivedKeys ?? []) {
    const d = declMap.get(key);
    if (d && d.level !== 'computed') {
      issues.push(issue('DERIVED_NOT_COMPUTED', 'allocationPolicy', { key, declaredLevel: d.level ?? 'device' }));
    } else if (!d && refs.length > 0) {
      issues.push(issue('DERIVED_UNDECLARED', 'allocationPolicy', { key }));
    }
  }

  const requirementSites = new Map<string, Set<string>>();
  for (const s of fileSites) {
    if (s.rejected || s.writtenCode === '' || requirementSites.has(s.writtenCode)) continue;
    const keys = new Set(s.csvKeys);
    if (s.existingSiteId !== null) for (const k of Object.keys(siteValues.get(s.existingSiteId) ?? {})) keys.add(k);
    requirementSites.set(s.writtenCode, keys);
  }
  for (const r of valued) {
    const code = judged.siteCodes[r.index];
    if (r.level === 'site' && code !== null) requirementSites.get(code)?.add(r.key);
  }
  const requirements = resolveRequirements({
    declarations,
    wide,
    sites: [...requirementSites].map(([code, keys]) => ({ code, keys })),
    computed: computedSuppliedKeys(effective),
    computedRefused: fileRuleRefused && effective === null,
  });
  const missingCount = requirements.levels
    .filter((l) => l.checked)
    .reduce((n, l) => n + l.missing.length, 0);
  if (missingCount > 0) issues.push(issue('REQUIREMENTS_INCOMPLETE', 'setup', { count: missingCount }));

  // ── 4.8 verdict ───────────────────────────────────────────────────────────
  const steps = SETUP_STEPS.filter((s) => {
    switch (s) {
      case 'template': return tpl !== undefined;
      case 'variables': return valued.some((r) => r.level !== 'site');
      case 'allocationPolicy': return parts.allocationPolicy !== undefined;
      case 'publish': return tpl !== undefined && tpl.publish;
      case 'sites': return parts.sites !== undefined;
      case 'siteVariables': return valued.some((r) => r.level === 'site');
    }
  });

  const report: TenantSetupReport = {
    dryRun: true,
    tenant: { id: tenant.id, name: tenant.name, slug: tenant.slug },
    selected,
    steps,
    canApply: !issues.some((i) => i.severity === 'error'),
    issues,
    requirements,
    declarations,
  };
  if (parts.variables) report.variables = { rows: judged.rows };
  if (tpl) {
    report.template = {
      report: templateReport,
      publish: { requested: tpl.publish, plan: publishPlan },
    };
  }
  if (checkedPolicy) report.allocationPolicy = checkedPolicy;
  if (parts.sites && sitesResult) report.sites = { result: sitesResult };
  const siteWrites = judged.writes.filter((w) => w.level === 'site');
  if (siteWrites.length > 0) {
    const bySite = new Map<string, { code: string; siteId: number | null; keys: string[]; applied: boolean }>();
    for (const w of siteWrites) {
      const code = w.siteCode as string;
      const entry = bySite.get(code) ?? {
        code,
        siteId: judged.rows[w.index].siteId,
        keys: [],
        applied: false,
      };
      entry.keys.push(w.key);
      bySite.set(code, entry);
    }
    report.siteVariables = { sites: [...bySite.values()] };
  }
  return { report, writes: judged.writes, policyInput };
}

/** The variables part stores the instance secret a 'shared' rule reads. */
function suppliesSharedPassword(
  rows: readonly SetupVariableRow[],
  declMap: ReadonlyMap<string, DeclaredKeyView>,
): boolean {
  return rows.some(
    (r) =>
      r.level === 'instance' &&
      r.key === SHARED_PPP_PASSWORD_KEY &&
      r.value !== undefined &&
      (r.secret === true || declMap.get(r.key)?.secret === true),
  );
}

/**
 * The publication each valid entry would get, and whether it could happen:
 * a new draft or a stored draft identical to the entry is published; an
 * entry identical to a PUBLISHED revision needs nothing. The partial closure
 * is resolved now, read-only, as `publishRevision` will (a missing partial is
 * named here rather than at step 4). A template that already has published
 * revisions is named: the bench offers every one of them.
 */
async function planPublication(
  tenantId: number,
  planned: PlannedImport,
  issues: SetupIssue[],
): Promise<NonNullable<TenantSetupReport['template']>['publish']['plan']> {
  const plan: NonNullable<TenantSetupReport['template']>['publish']['plan'] = [];
  for (const item of planned.items) {
    const entry = planned.entries[item.index];
    let action: (typeof plan)[number]['action'] = 'none';
    let revisionId: string | null = null;
    let revision: number | null = null;
    if (item.errors.length === 0 && entry.revision) {
      if (item.action === 'create' || item.action === 'new-revision') action = 'publish_new_draft';
      else if (item.sameAs?.kind === 'revision' && item.sameAs.status === 'draft') {
        action = 'publish_existing_draft';
        revisionId = item.sameAs.revisionId;
        revision = item.sameAs.revision;
      } else if (item.sameAs?.kind === 'revision' && item.sameAs.status === 'published') {
        action = 'already_published';
        revisionId = item.sameAs.revisionId;
        revision = item.sameAs.revision;
      }
    }
    plan.push({ index: item.index, name: item.name, action, revisionId, revision });
    if (action !== 'publish_new_draft' && action !== 'publish_existing_draft') continue;

    try {
      await resolveLiveClosure(db, tenantId, entry.revision!.body);
    } catch (err) {
      if (!(err instanceof TemplateDependencyError)) throw err;
      issues.push(issue('PUBLISH_DEPENDENCY', 'template', { index: item.index, name: item.name, message: err.message }));
    }
    if (item.existingTemplateId) {
      const published = (await db('template_revisions')
        .where({ template_id: item.existingTemplateId, status: 'published' })
        .orderBy('revision')
        .select('revision')) as Array<{ revision: number }>;
      if (published.length > 0) {
        issues.push(issue('OTHER_PUBLISHED', 'template', {
          templateName: item.name,
          revisions: published.map((p) => String(p.revision)),
        }));
      }
    }
  }
  return plan;
}

/** The sites file's `var:` keys that only the file template declares (not a
 *  published revision): refused by the site import unless it is published
 *  first. A file that cannot be read is left to the import to report. */
async function keysNeedingPublication(
  tenantId: number,
  csv: string,
  fileRefs: readonly SetupReference[],
): Promise<string[]> {
  let varKeys: string[];
  try {
    const nonBlank = parseCsv(csv).records.filter((r) => r.cells.some((c) => c !== ''));
    if (nonBlank.length === 0) return [];
    varKeys = mapHeader(nonBlank[0].cells).vars.map((v) => v.key);
  } catch (err) {
    if (err instanceof SiteImportFileError) return [];
    throw err;
  }
  if (varKeys.length === 0) return [];
  const published = declaredSiteKeys((await loadPublishedReferences(tenantId)).map((r) => r.decl));
  const fromFile = declaredSiteKeys(fileRefs.map((r) => r.decl));
  return varKeys.filter((k) => fromFile.has(k) && !published.has(k));
}

/**
 * The file's rows as the import judged them: the non-blank records minus the
 * header, index-aligned with `result.rows` (the import builds them in the
 * same order).
 */
function fileSitesOf(csv: string, result: SiteImportResult): FileSite[] {
  const nonBlank = parseCsv(csv).records.filter((r) => r.cells.some((c) => c !== ''));
  if (nonBlank.length === 0) return [];
  const [header, ...body] = nonBlank;
  const cols = mapHeader(header.cells);
  return body.map((rec, i) => {
    const r = result.rows[i];
    const writtenCode = r?.code ?? '';
    return {
      writtenCode,
      originalCode: r?.codeRestored?.from ?? writtenCode,
      rejected: !r || r.errors.length > 0,
      csvKeys: new Set(cols.vars.filter((v) => (rec.cells[v.index] ?? '').trim() !== '').map((v) => v.key)),
      existingSiteId: r?.siteId ?? null,
    };
  });
}

/** POST /tenant-setup/check. Writes nothing. */
export async function checkSetup(
  tenantId: number,
  req: TenantSetupRequest,
  ctx: { userId: number | null },
): Promise<TenantSetupReport> {
  assertExpectedTenant(tenantId, req.expectedTenantId);
  return (await runCheck(tenantId, req, { userId: ctx.userId, forApply: false })).report;
}

// ============================================================================
// The apply
// ============================================================================

type BulkEntry = { key: string; value: JsonValue; isSecret?: boolean; meta?: VariableMeta };

/** The writers each step calls — the real services by default; the DB
 *  harness swaps one to make a step fail. */
export interface TenantSetupDeps {
  applyImport(tenantId: number, file: unknown, userId: number | null): Promise<ImportReport>;
  setInstanceBulk(entries: BulkEntry[]): Promise<void>;
  setBulk(tenantId: number, scope: 'global' | 'tenant' | 'site', scopeId: number | null, entries: BulkEntry[]): Promise<void>;
  upsertPolicy(tenantId: number, input: unknown): Promise<AllocationPolicyView>;
  publishRevision(tenantId: number, revisionId: string, userId: number | null): Promise<unknown>;
  importSites(tenantId: number, csv: string, opts: SiteImportOptions): Promise<SiteImportResult>;
}

export const defaultTenantSetupDeps: TenantSetupDeps = {
  applyImport: (tenantId, file, userId) => applyImport(tenantId, file, userId),
  setInstanceBulk: (entries) => variableResolver.setInstanceBulk(entries),
  setBulk: (tenantId, scope, scopeId, entries) => variableResolver.setBulk(tenantId, scope, scopeId, entries),
  upsertPolicy: (tenantId, input) => upsertPolicy(tenantId, input),
  publishRevision: (tenantId, revisionId, userId) => versionService.publishRevision(tenantId, revisionId, userId),
  importSites: (tenantId, csv, opts) => importSites(tenantId, csv, opts),
};

/** A step's refusal, worded for the operator. The services' own errors carry
 *  sentences written for the operator and never a value; anything else is
 *  logged by name and code only (a database error's `detail` may quote a
 *  row) and reported without its internals. */
function stepMessage(err: unknown, step: SetupStep, tenantId: number): string {
  if (
    err instanceof AllocationError || err instanceof TemplateVersionError ||
    err instanceof TemplateDependencyError || err instanceof SiteImportFileError
  ) {
    return err.message;
  }
  if (err instanceof Error && err.constructor === Error) return err.message;
  logger.error(
    {
      tenantId,
      step,
      err: err instanceof Error
        ? { name: err.name, code: (err as { code?: unknown }).code, constraint: (err as { constraint?: unknown }).constraint }
        : { name: 'unknown' },
    },
    'tenant quick setup: step failed',
  );
  return 'the step could not be written (see the server log)';
}

/** One process-wide guard per workspace: two setups of one tenant at once
 *  would interleave their steps. A second server process is not covered —
 *  each step's own service still holds its own locks. */
const running = new Set<number>();

/** POST /tenant-setup/apply. */
export async function applySetup(
  tenantId: number,
  req: TenantSetupRequest,
  actor: { userId: number | null; username: string | null },
  deps: TenantSetupDeps = defaultTenantSetupDeps,
): Promise<TenantSetupReport> {
  assertExpectedTenant(tenantId, req.expectedTenantId);
  if (running.has(tenantId)) throw new SetupBusyError();
  running.add(tenantId);
  try {
    const plan = await runCheck(tenantId, req, { userId: actor.userId, forApply: true });
    if (!plan.report.canApply) throw new SetupRefusedError(plan.report);
    return await runSteps(tenantId, req, actor, plan, deps);
  } finally {
    running.delete(tenantId);
  }
}

async function runSteps(
  tenantId: number,
  req: TenantSetupRequest,
  actor: { userId: number | null; username: string | null },
  plan: CheckPlan,
  deps: TenantSetupDeps,
): Promise<TenantSetupReport> {
  const report: TenantSetupReport = { ...plan.report, dryRun: false };
  const parts = req.parts;
  const results: SetupStepResult[] = report.steps.map((step) => ({ step, status: 'not_run', summary: {} }));
  const rowReports = report.variables?.rows ?? [];
  const markApplied = (indexes: number[]): void => {
    for (const i of indexes) {
      const r = rowReports.find((x) => x.index === i);
      if (r) r.applied = true;
    }
  };
  let importReport: ImportReport | null = null;

  const runners: Record<SetupStep, () => Promise<Record<string, number>>> = {
    template: async () => {
      importReport = await deps.applyImport(tenantId, parts.template!.file, actor.userId);
      if (report.template) report.template.report = importReport;
      const bad = importReport.items.filter((i) => i.outcome === 'failed' || i.outcome === 'skipped');
      if (bad.length > 0) {
        const first = bad[0];
        throw new StepFailure(
          `${bad.length} template entr${bad.length === 1 ? 'y was' : 'ies were'} not imported — ` +
            `entry #${first.index + 1} "${first.name}": ${first.errors[0]?.message ?? first.outcome}`,
          { created: importReport.summary.created, unchanged: importReport.summary.unchanged, failed: bad.length },
        );
      }
      return { created: importReport.summary.created, unchanged: importReport.summary.unchanged };
    },

    variables: async () => {
      const summary = { instance: 0, global: 0, tenant: 0, unchanged: 0 };
      summary.unchanged = rowReports.filter((r) => r.level !== 'site' && r.action === 'unchanged').length;
      for (const level of ['instance', 'global', 'tenant'] as const) {
        const ws = plan.writes.filter((w) => w.level === level);
        if (ws.length === 0) continue;
        const entries: BulkEntry[] = ws.map((w) => ({
          key: w.key, value: w.value, isSecret: w.isSecret, meta: { updatedBy: actor.userId },
        }));
        try {
          if (level === 'instance') await deps.setInstanceBulk(entries);
          else await deps.setBulk(tenantId, level, null, entries);
        } catch (err) {
          throw new StepFailure(`${level}: ${stepMessage(err, 'variables', tenantId)}`, summary);
        }
        markApplied(ws.map((w) => w.index));
        summary[level] = ws.length;
      }
      return summary;
    },

    allocationPolicy: async () => {
      try {
        const saved = await deps.upsertPolicy(tenantId, plan.policyInput);
        if (report.allocationPolicy) report.allocationPolicy.saved = saved;
      } catch (err) {
        if (err instanceof AllocationError && report.allocationPolicy) {
          report.allocationPolicy.ok = false;
          report.allocationPolicy.error = { reason: err.reason, message: err.message, details: err.details ?? {} };
        }
        throw new StepFailure(stepMessage(err, 'allocationPolicy', tenantId), {});
      }
      return { saved: 1 };
    },

    publish: async () => {
      const summary = { published: 0, alreadyPublished: 0 };
      const done = new Set<string>();
      const publishResults: NonNullable<NonNullable<TenantSetupReport['template']>['publish']['results']> = [];
      if (report.template) report.template.publish.results = publishResults;
      const items: ImportItemReport[] = importReport ? (importReport as ImportReport).items : [];
      for (const item of items) {
        // What step 1 actually did decides, not the check's plan: the import
        // re-decides `unchanged` inside its own transaction.
        let target: { id: string; revision: number } | null = null;
        if (item.outcome === 'created' && item.revisionId) {
          target = { id: item.revisionId, revision: item.revision ?? 0 };
        } else if (item.outcome === 'unchanged' && item.sameAs?.kind === 'revision') {
          if (item.sameAs.status === 'draft') target = { id: item.sameAs.revisionId, revision: item.sameAs.revision };
          else if (item.sameAs.status === 'published') summary.alreadyPublished += 1;
        }
        if (!target) continue;
        // Two entries of one file can land on the same revision.
        if (done.has(target.id)) { summary.alreadyPublished += 1; continue; }
        try {
          await deps.publishRevision(tenantId, target.id, actor.userId);
        } catch (err) {
          const message = stepMessage(err, 'publish', tenantId);
          publishResults.push({ index: item.index, revisionId: target.id, revision: target.revision, status: 'failed', message });
          throw new StepFailure(`"${item.name}" revision ${target.revision}: ${message}`, summary);
        }
        done.add(target.id);
        summary.published += 1;
        publishResults.push({ index: item.index, revisionId: target.id, revision: target.revision, status: 'published' });
      }
      return summary;
    },

    sites: async () => {
      let result: SiteImportResult;
      try {
        result = await deps.importSites(tenantId, parts.sites!.csv, {
          dryRun: false,
          allocate: parts.sites!.allocate,
          canWriteVariables: true,
          canWriteSchedule: true,
          updatedBy: actor.userId,
        });
      } catch (err) {
        throw new StepFailure(stepMessage(err, 'sites', tenantId), {});
      }
      report.sites = { result };
      const s = result.summary;
      const summary = {
        rows: s.rows, create: s.create, update: s.update, skip: s.skip, rejected: s.rejected,
        applied: s.applied, allocated: s.allocated, allocationFailed: s.allocationFailed,
      };
      if (s.rejected > 0 || s.allocationFailed > 0) {
        throw new StepFailure(
          `${s.rejected} site row(s) were refused and ${s.allocationFailed} allocation(s) failed; ` +
            `the other ${s.applied} row(s) were written`,
          summary,
        );
      }
      return summary;
    },

    siteVariables: async () => {
      const ws = plan.writes.filter((w) => w.level === 'site');
      const codes = [...new Set(ws.map((w) => w.siteCode as string))];
      const ids = new Map<string, number>();
      for (let i = 0; i < codes.length; i += 1000) {
        const found = (await db('sites')
          .where('tenant_id', tenantId)
          .whereIn('code', codes.slice(i, i + 1000))
          .select('id', 'code')) as Array<{ id: number; code: string }>;
        for (const s of found) ids.set(s.code, Number(s.id));
      }
      const summary = { sites: 0, written: 0 };
      const sitesReport = report.siteVariables?.sites ?? [];
      for (const code of codes) {
        const siteId = ids.get(code);
        if (siteId === undefined) throw new StepFailure(`site ${code} does not exist in this workspace`, summary);
        const mine = ws.filter((w) => w.siteCode === code);
        try {
          await deps.setBulk(tenantId, 'site', siteId, mine.map((w) => ({
            key: w.key, value: w.value, isSecret: w.isSecret, meta: { updatedBy: actor.userId },
          })));
        } catch (err) {
          throw new StepFailure(`site ${code}: ${stepMessage(err, 'siteVariables', tenantId)}`, summary);
        }
        markApplied(mine.map((w) => w.index));
        const entry = sitesReport.find((s) => s.code === code);
        if (entry) { entry.applied = true; entry.siteId = siteId; }
        summary.sites += 1;
        summary.written += mine.length;
      }
      return summary;
    },
  };

  let failed = false;
  for (const r of results) {
    if (failed) break;
    try {
      r.summary = await runners[r.step]();
      r.status = 'done';
    } catch (err) {
      failed = true;
      r.status = 'failed';
      if (err instanceof StepFailure) {
        r.message = err.message;
        r.summary = err.summary;
      } else {
        r.message = stepMessage(err, r.step, tenantId);
      }
    }
  }
  report.stepResults = results;
  report.outcome = failed ? 'failed' : 'applied';

  // The audit entry records the outcome and the per-step counts — no key list
  // for secrets, no value. Its failure is logged and does NOT undo anything:
  // the steps are separate services, each already committed by now, and a
  // missing ledger line is not a reason to report written parts as unwritten.
  const steps = results.map((s) => ({ step: s.step, status: s.status, summary: s.summary }));
  try {
    await appendAudit({
      tenantId,
      actorType: 'user',
      actorId: actor.userId,
      actorName: actor.username,
      action: 'tenant_setup.applied',
      entityType: 'tenant',
      entityId: tenantId,
      after: { outcome: report.outcome, steps },
    });
  } catch (err) {
    logger.error(
      { tenantId, err: err instanceof Error ? { name: err.name, code: (err as { code?: unknown }).code } : null },
      'tenant quick setup: the audit entry could not be written',
    );
  }
  logger.info({ tenantId, userId: actor.userId, outcome: report.outcome, steps }, 'tenant quick setup applied');
  return report;
}

/** A step stopped, with what it had done so far. */
class StepFailure extends Error {
  constructor(message: string, readonly summary: Record<string, number>) {
    super(message);
    this.name = 'StepFailure';
  }
}

// ============================================================================
// The context
// ============================================================================

/**
 * What the designer is built from: the declarations (from the posted
 * template, the named revisions, or what is published), the tenant's stored
 * values (redacted), its sites with their site values (redacted), the rule,
 * the pools and concentrators it may use, and its templates. Writes nothing.
 * A posted template that does not import is refused (400) with its first
 * errors, so the designer never builds a form from a schema the import would
 * refuse.
 */
export async function getSetupContext(
  tenantId: number,
  input: { expectedTenantId: number; template?: unknown; referenceRevisionIds: string[] },
): Promise<TenantSetupContext> {
  assertExpectedTenant(tenantId, input.expectedTenantId);
  const tenant = (await db('tenants').where({ id: tenantId }).first('id', 'name', 'slug')) as
    | { id: number; name: string; slug: string }
    | undefined;
  if (!tenant) throw new SetupInputError(404, 'This workspace does not exist.');

  const fileRefs: SetupReference[] = [];
  if (input.template !== undefined) {
    let planned: PlannedImport;
    try {
      planned = await planImport(tenantId, input.template);
    } catch (err) {
      if (err instanceof TemplateImportFormatError) throw new SetupInputError(400, err.message);
      throw err;
    }
    const invalid = planned.items.filter((i) => i.errors.length > 0);
    if (invalid.length > 0) {
      const first = invalid[0];
      throw new SetupInputError(
        400,
        `The template file does not import: entry #${first.index + 1} "${first.name}": ` +
          first.errors.slice(0, 3).map((e) => (e.path ? `${e.path}: ${e.message}` : e.message)).join('; '),
      );
    }
    for (const item of [...planned.items].reverse()) {
      const entry = planned.entries[item.index];
      if (entry.revision) fileRefs.push(fileReference(item.name, entry.revision.varSchema ?? {}));
    }
  }
  const { refs: picked, missing } = await loadReferenceRevisions(tenantId, input.referenceRevisionIds);
  if (missing.length > 0) {
    throw new SetupInputError(404, `Template revision ${missing[0]} does not exist in this workspace or in the library.`);
  }
  let refs = [...fileRefs, ...picked];
  if (refs.length === 0) refs = await loadPublishedReferences(tenantId);

  const wide = await loadWideValues(tenantId);
  const siteRows = (await db('sites')
    .where('tenant_id', tenantId)
    .orderBy('code')
    .limit(SITE_IMPORT_MAX_ROWS)
    .select('id', 'code', 'name', 'country', 'timezone', 'address', 'contact')) as Array<{
    id: number;
    code: string;
    name: string;
    country: string | null;
    timezone: string | null;
    address: string | null;
    contact: string | null;
  }>;
  const siteValues = await loadSiteValues(tenantId, siteRows.map((s) => Number(s.id)));

  const policy = await getPolicy(tenantId);
  const allConcentrators = await listConcentrators();
  const [alloc] = await db('site_provisioning').where({ tenant_id: tenantId }).count<{ n: string }[]>('* as n');

  const templateRows = (await db('templates as t')
    .leftJoin('template_revisions as r', 'r.template_id', 't.id')
    .where(function visible(this: import('knex').Knex.QueryBuilder) {
      this.where('t.tenant_id', tenantId).orWhereNull('t.tenant_id');
    })
    .orderBy('t.name')
    .orderBy('t.id')
    .orderBy('r.revision', 'desc')
    .select(
      't.id as template_id', 't.name as name', 't.brand as brand', 't.status as status',
      't.tenant_id as tenant_id', 'r.id as revision_id', 'r.revision as revision',
      'r.status as revision_status', 'r.published_at as published_at',
    )) as Array<{
    template_id: string | number;
    name: string;
    brand: string;
    status: string;
    tenant_id: number | null;
    revision_id: string | number | null;
    revision: number | null;
    revision_status: string | null;
    published_at: Date | string | null;
  }>;
  const templates = new Map<string, TenantSetupContext['templates'][number]>();
  for (const r of templateRows) {
    const id = String(r.template_id);
    const t = templates.get(id) ?? {
      templateId: id, name: r.name, brand: r.brand, status: r.status, library: r.tenant_id === null, revisions: [],
    };
    if (r.revision_id !== null && r.revision !== null) {
      t.revisions.push({
        id: String(r.revision_id),
        revision: Number(r.revision),
        status: r.revision_status ?? 'draft',
        publishedAt: r.published_at === null ? null : new Date(r.published_at).toISOString(),
      });
    }
    templates.set(id, t);
  }

  return {
    tenant: {
      id: tenant.id,
      name: tenant.name,
      slug: tenant.slug,
      slugFrozen: policy !== null || Number(alloc?.n ?? 0) > 0,
      isMaster: tenantId === MASTER_TENANT_ID,
    },
    declarations: buildDeclarations(refs),
    references: refs.map((r) => ({
      kind: r.kind, name: r.name, revisionId: r.revisionId, revision: r.revision, status: r.status,
    })),
    values: { instance: toStoredView(wide.instance), global: toStoredView(wide.global), tenant: toStoredView(wide.tenant) },
    sites: siteRows.map((s) => ({
      id: Number(s.id),
      code: s.code,
      name: s.name,
      country: s.country,
      timezone: s.timezone,
      address: s.address,
      contact: s.contact,
      values: toStoredView(siteValues.get(Number(s.id)) ?? {}),
    })),
    policy: policy
      ? {
          ...(policy as unknown as Record<string, unknown>),
          concentratorName: allConcentrators.find((c) => c.id === policy.concentratorId)?.name ?? null,
        }
      : null,
    pools: (await listPools()) as unknown as TenantSetupContext['pools'],
    concentrators: allConcentrators.filter((c) => c.tenantId === tenantId || c.tenantId === MASTER_TENANT_ID),
    instanceDomain: await getInstanceDomain(),
    templates: [...templates.values()],
    limits: { maxVariableRows: MAX_SETUP_VARIABLE_ROWS, maxSiteRows: SITE_IMPORT_MAX_ROWS, maxBodyChars: MAX_SETUP_BODY_CHARS },
  };
}

export const tenantSetupService = { checkSetup, applySetup, getSetupContext };
