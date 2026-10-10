/**
 * ObliWAN — the onboarding assistant (brick 14, operator GO 2026-10-09).
 *
 * « Couplé au Quick Setup Tenant ça peut être tellement puissant » — onboarding
 * a big customer (two hundred routers) as ONE resumable assistant that
 * proposes everything and asks only for approvals. This file is its server:
 *
 *   getOnboardingStatus   the nine steps, each `done` / `todo` / `blocked` /
 *                         `running` with a closed reason and its counts,
 *                         RECOMPUTED FROM THE DATABASE at every read — the
 *                         assistant keeps no state of its own, so it resumes
 *                         wherever the operator left it (or wherever another
 *                         screen took it), after any restart;
 *   inferRuleForTenant    the allocation rule read off the CHR accounts
 *                         (ruleInference.ts), dry-run through the allocator's
 *                         own `checkPolicy`; writes nothing;
 *   approveInferredRule   the operator's approval: the SAME proposal (its
 *                         fingerprint) saved through the existing services —
 *                         `createPool` when the block needs a pool, then
 *                         `upsertPolicy` under the allocation lock.
 *
 * ┌─ NOTHING HERE TOUCHES A ROUTER ──────────────────────────────────────────┐
 * │ Every step's ACTION is somebody else's door, reached from the screen:    │
 * │ the CHR re-read (allocation), the orphans workbook and the site import,  │
 * │ the bulk attach and its follow-ups (reconciliation), the access check,   │
 * │ the bulk collect (`/config/tenant-collect`, drift/runtime.ts — two at     │
 * │ once, a cap, the collector's one door), the infra analysis, the          │
 * │ extrapolator, the templates and variables screens. This file only READS  │
 * │ what those doors recorded, plus the one write the operator approves: the │
 * │ allocation rule (and its pool). The change queue is untouched.            │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHO, AND WHICH TENANT ──────────────────────────────────────────────────┐
 * │ Platform administrators only (tenantSetup.routes.ts `requireRole`, and   │
 * │ the controller again): the rule reads every account of a SHARED CHR and  │
 * │ writes shared pools. The tenant is the request's: the session's          │
 * │ workspace, or — from the Default workspace's god view — the client       │
 * │ picked in the workspace filter (`adoptGodViewFilterTenant`), never one    │
 * │ named in a body. The Default workspace itself is refused: it is not a     │
 * │ customer.                                                                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * No `?` literal in any raw SQL below (the knex binding trap, migration 032):
 * the only `?` are real bindings.
 */

import {
  ACCESS_CHECK_STALE_RUN_MS,
  MASTER_TENANT_ID,
  ONBOARDING_CHR_STALE_MS,
  ONBOARDING_ITEMS_MAX,
  RULE_INFERENCE_SLUG_MAX,
  RULE_INFERENCE_SLUG_MIN,
  computedSuppliedKeys,
  probesOf,
  resolveRequirements,
  type OnboardingReason,
  type OnboardingStatus,
  type OnboardingStep,
  type OnboardingStepKey,
  type OnboardingStepState,
  type OnboardingWarning,
  type RuleApproveResult,
  type RuleInference,
  type RuleOutlier,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { appendAudit } from '../attestation/auditLog.service';
import {
  AllocationError,
  checkPolicy,
  createPool,
  deletePool,
  getPolicy,
  listPools,
  trustedConcentrators,
  upsertPolicy,
  type AllocationPolicyView,
} from '../allocation';
import { readInstanceDomain } from '../allocation/allocator';
import { parseIpv4 } from '../allocation/policy';
import { parseLoginTemplate } from '../allocation/pppIdentity';
import { deriveLoginMatcher, readLogin, reconcileTenant, type ReconcileReport } from '../allocation/reconcile.service';
import { COLLECTABLE_FAMILIES } from '../config/collect.service';
import { tenantCollectState } from '../drift/runtime';
import { buildDeclarations, loadPublishedReferences } from './declarations';
import { inferRule, type InferenceAccount } from './ruleInference';

// ============================================================================
// Errors
// ============================================================================

/** A refusal of the assistant itself; the controller maps `status`. */
export class OnboardingError extends Error {
  constructor(readonly status: 400 | 404 | 409 | 422, message: string) {
    super(message);
    this.name = 'OnboardingError';
  }
}

interface TenantRow {
  id: number;
  name: string;
  slug: string;
}

async function loadTenant(tenantId: number): Promise<TenantRow> {
  if (tenantId === MASTER_TENANT_ID) {
    throw new OnboardingError(
      400,
      "L'espace Default n'est pas un client : choisissez le client dans le filtre « Espace de travail » " +
        '(ou placez la session sur son espace).',
    );
  }
  const t = (await db('tenants').where({ id: tenantId }).first('id', 'name', 'slug')) as TenantRow | undefined;
  if (!t) throw new OnboardingError(404, 'This workspace does not exist.');
  return { id: Number(t.id), name: t.name, slug: t.slug };
}

function iso(v: Date | string | null | undefined): string | null {
  return v === null || v === undefined ? null : new Date(v).toISOString();
}

function num(v: unknown): number {
  return typeof v === 'number' ? v : Number(v ?? 0);
}

/** The text searched in account names: lowercase, the login alphabet. */
export function normalizeSearchSlug(raw: unknown, fallback: string): string {
  const text = (typeof raw === 'string' && raw.trim() !== '' ? raw : fallback).trim().toLowerCase();
  if (
    text.length < RULE_INFERENCE_SLUG_MIN ||
    text.length > RULE_INFERENCE_SLUG_MAX ||
    !/^[a-z0-9._-]+$/.test(text)
  ) {
    throw new OnboardingError(
      400,
      `The search text must be ${RULE_INFERENCE_SLUG_MIN} to ${RULE_INFERENCE_SLUG_MAX} characters among ` +
        'letters, digits, ".", "_" and "-".',
    );
  }
  return text;
}

// ============================================================================
// The CHRs and the accounts naming the tenant
// ============================================================================

interface ChrContext {
  /** Every CHR whose accounts count for this tenant (seed.ts's rule). */
  trusted: number[];
  names: Map<number, string>;
  reads: Map<number, { readAt: Date; secretCount: number }>;
  policyIds: number[];
}

async function loadChrContext(tenantId: number): Promise<ChrContext> {
  const chrs = (await db('devices')
    .where({ role: 'concentrator' })
    .select('id', 'name', 'tenant_id')) as Array<{ id: number; name: string; tenant_id: number }>;
  const policyIds = ((await db('tenant_allocation_policies').pluck('concentrator_id')) as number[]).map(Number);
  const trusted = [
    ...trustedConcentrators(
      chrs.map((c) => ({ id: Number(c.id), tenantId: Number(c.tenant_id) })),
      policyIds,
      tenantId,
      MASTER_TENANT_ID,
    ),
  ]
    .filter((id) => chrs.some((c) => Number(c.id) === id))
    .sort((a, b) => a - b);
  const reads = new Map<number, { readAt: Date; secretCount: number }>();
  if (trusted.length > 0) {
    const rows = (await db('concentrator_secret_reads')
      .whereIn('concentrator_id', trusted)
      .select('concentrator_id', 'read_at', 'secret_count')) as Array<{
      concentrator_id: number;
      read_at: Date | string;
      secret_count: number;
    }>;
    for (const r of rows) reads.set(Number(r.concentrator_id), { readAt: new Date(r.read_at), secretCount: num(r.secret_count) });
  }
  return {
    trusted,
    names: new Map(chrs.map((c) => [Number(c.id), c.name])),
    reads,
    policyIds,
  };
}

interface SecretRow {
  concentrator_id: number;
  name: string;
  remote_address: string | null;
  profile: string | null;
  disabled: boolean;
}

/** The live secrets of `chrIds` whose name contains `slug` (lowercase). */
async function secretsNaming(chrIds: readonly number[], slug: string): Promise<SecretRow[]> {
  if (chrIds.length === 0) return [];
  const rows = (await db('concentrator_ppp_secrets')
    .whereIn('concentrator_id', chrIds)
    .whereNull('vanished_at')
    .whereRaw('position(? in lower(name)) > 0', [slug])
    .orderBy(['concentrator_id', 'name'])
    .select('concentrator_id', 'name', db.raw('host(remote_address) AS remote_address'), 'profile', 'disabled')) as SecretRow[];
  return rows.map((r) => ({ ...r, concentrator_id: Number(r.concentrator_id) }));
}

// ============================================================================
// Rule inference
// ============================================================================

/**
 * The rule the CHR accounts naming `slug` (default: the tenant's slug)
 * suggest, with the allocator's dry-run verdict. Writes nothing.
 */
export async function inferRuleForTenant(
  tenantId: number,
  opts: { slug?: unknown } = {},
  nowMs: number = Date.now(),
): Promise<RuleInference> {
  const tenant = await loadTenant(tenantId);
  const searchSlug = normalizeSearchSlug(opts.slug, tenant.slug);
  const instanceDomain = await readInstanceDomain(db);
  const chr = await loadChrContext(tenantId);
  const secrets = await secretsNaming(chr.trusted, searchSlug);

  // Logins another customer holds: listed, never this tenant's.
  const tenants = new Map(
    ((await db('tenants').select('id', 'slug')) as Array<{ id: number; slug: string }>).map((t) => [Number(t.id), t.slug]),
  );
  const heldBy = new Map<string, string>();
  const provisioned = (await db('site_provisioning')
    .whereNot('tenant_id', tenantId)
    .select('ppp_username', 'tenant_id')) as Array<{ ppp_username: string; tenant_id: number }>;
  for (const p of provisioned) heldBy.set(p.ppp_username.toLowerCase(), tenants.get(Number(p.tenant_id)) ?? '?');
  const foreignDevices = (await db('devices')
    .whereNot('tenant_id', tenantId)
    .whereNotNull('ppp_username')
    .whereNot('role', 'concentrator')
    .select('ppp_username', 'tenant_id')) as Array<{ ppp_username: string; tenant_id: number }>;
  for (const d of foreignDevices) heldBy.set(d.ppp_username.toLowerCase(), tenants.get(Number(d.tenant_id)) ?? '?');

  const open = new Set<string>();
  if (chr.trusted.length > 0) {
    const sessions = (await db('ppp_sessions')
      .whereIn('concentrator_id', chr.trusted)
      .whereNull('ended_at')
      .select('concentrator_id', 'ppp_username')) as Array<{ concentrator_id: number; ppp_username: string }>;
    for (const s of sessions) open.add(`${Number(s.concentrator_id)}|${s.ppp_username.toLowerCase()}`);
  }

  const accounts: InferenceAccount[] = [];
  const excluded: RuleOutlier[] = [];
  for (const s of secrets) {
    const other = heldBy.get(s.name.toLowerCase());
    if (other !== undefined) {
      excluded.push({ name: s.name, reason: 'otherTenant', detail: other });
      continue;
    }
    accounts.push({
      concentratorId: s.concentrator_id,
      name: s.name,
      remoteAddress: s.remote_address,
      profile: s.profile,
      disabled: s.disabled === true,
      online: open.has(`${s.concentrator_id}|${s.name.toLowerCase()}`),
    });
  }

  // Router identities this tenant already knows (attached routers).
  const identityRows = (await db('devices as d')
    .leftJoin('sites as s', function joinSite() {
      this.on('s.id', '=', 'd.site_id').andOn('s.tenant_id', '=', 'd.tenant_id');
    })
    .where('d.tenant_id', tenantId)
    .whereNot('d.role', 'concentrator')
    .whereNotNull('d.system_identity')
    .orderBy('d.id')
    .select('d.system_identity', 'd.ppp_username', 's.code', 's.name as site_name', 's.country')) as Array<{
    system_identity: string;
    ppp_username: string | null;
    code: string | null;
    site_name: string | null;
    country: string | null;
  }>;
  const sites = (await db('sites')
    .where({ tenant_id: tenantId })
    .orderBy('code')
    .select('code', 'name', 'country')) as Array<{ code: string; name: string; country: string | null }>;

  const pools = (await listPools()).map((p) => ({
    id: p.id, name: p.name, cidr: p.cidr, purpose: p.purpose, policies: p.policies,
  }));

  // Every tunnel address held installation-wide.
  const held = new Set<number>();
  const addAll = (rows: Array<{ a: string | null }>): void => {
    for (const r of rows) {
      const n = r.a === null ? null : parseIpv4(r.a);
      if (n !== null) held.add(n);
    }
  };
  addAll((await db('concentrator_ppp_secrets').whereNull('vanished_at').whereNotNull('remote_address')
    .select(db.raw('host(remote_address) AS a'))) as Array<{ a: string | null }>);
  addAll((await db('site_provisioning').select(db.raw('host(tunnel_ip) AS a'))) as Array<{ a: string | null }>);
  addAll((await db('devices').whereNotNull('tunnel_ip').select(db.raw('host(tunnel_ip) AS a'))) as Array<{ a: string | null }>);
  addAll((await db('ppp_sessions').whereNull('ended_at').whereNotNull('tunnel_ip')
    .select(db.raw('host(tunnel_ip) AS a'))) as Array<{ a: string | null }>);

  const stored = await getPolicy(tenantId);
  const core = inferRule({
    tenantId,
    tenantSlug: tenant.slug,
    searchSlug,
    instanceDomain,
    accounts,
    identities: identityRows.map((r) => ({
      identity: r.system_identity,
      pppUsername: r.ppp_username,
      site: r.code !== null ? { code: r.code, name: r.site_name ?? r.code, country: r.country } : null,
    })),
    sites,
    pools,
    held,
    concentratorNames: chr.names,
    stored,
  });

  // The allocator's own verdict on the proposal, nothing written.
  const proposal = core.proposal;
  if (proposal.body && !proposal.createPool) {
    try {
      await checkPolicy(tenantId, proposal.body);
      proposal.allocator = { checked: true, ok: true, reason: null, message: null };
    } catch (err) {
      if (!(err instanceof AllocationError)) throw err;
      // `holder` is never relayed: it may carry another tenant's ids.
      proposal.allocator = { checked: true, ok: false, reason: err.reason, message: err.message };
    }
  }

  const perChr = new Map<number, number>();
  for (const a of accounts) perChr.set(a.concentratorId, (perChr.get(a.concentratorId) ?? 0) + 1);
  const shownChrs = chr.trusted.filter((id) => (perChr.get(id) ?? 0) > 0 || id === core.concentratorId || id === stored?.concentratorId);
  return {
    tenant,
    searchSlug,
    instanceDomain,
    generatedAt: new Date(nowMs).toISOString(),
    concentrators: shownChrs.map((id) => {
      const read = chr.reads.get(id);
      return {
        id,
        name: chr.names.get(id) ?? String(id),
        readAt: read ? read.readAt.toISOString() : null,
        freshness: !read ? 'never' : nowMs - read.readAt.getTime() > ONBOARDING_CHR_STALE_MS ? 'stale' : 'fresh',
        accounts: perChr.get(id) ?? 0,
      };
    }),
    accounts: { ...core.accounts, excluded },
    login: core.login,
    codeFormat: core.codeFormat,
    tunnel: core.tunnel,
    profile: core.profile,
    identity: core.identity,
    sitesWithoutAccount: core.sitesWithoutAccount,
    stored: core.stored,
    proposal,
  };
}

/** One approval per workspace at a time, in this process. */
const approving = new Set<number>();

/**
 * Save the proposal the operator APPROVED — the one whose fingerprint the
 * request quotes, recomputed now: a CHR re-read, a pool or a policy saved
 * since the proposal was shown changes it, and the approval is then refused
 * (409) rather than saving something nobody saw. The pool is created first
 * when the block needs one, and removed again if the rule is then refused,
 * so a refused approval leaves nothing behind.
 */
export async function approveInferredRule(
  tenantId: number,
  req: { slug?: unknown; fingerprint: string },
  actor: { userId: number | null; username: string | null },
): Promise<RuleApproveResult> {
  if (approving.has(tenantId)) throw new OnboardingError(409, 'An approval of this workspace\'s rule is already running.');
  approving.add(tenantId);
  try {
    const inference = await inferRuleForTenant(tenantId, { slug: req.slug });
    const p = inference.proposal;
    if (p.fingerprint !== req.fingerprint) {
      throw new OnboardingError(
        409,
        'La règle proposée a changé depuis son affichage (CHR relu, pool ou règle enregistrés entre-temps) : ' +
          'rien n\'a été enregistré. Rechargez la proposition, puis approuvez-la de nouveau.',
      );
    }
    if (!p.body || p.blockers.length > 0) {
      throw new OnboardingError(422, `No rule can be saved as it stands (${p.blockers.join(', ') || 'no proposal'}).`);
    }
    if (p.allocator.checked && !p.allocator.ok) {
      throw new OnboardingError(422, p.allocator.message ?? 'The allocator refuses this rule.');
    }
    const body = JSON.parse(JSON.stringify(p.body)) as Record<string, unknown> & { tunnel: Record<string, unknown> };
    let poolCreated: RuleApproveResult['poolCreated'] = null;
    if (p.createPool) {
      const pool = await createPool({ name: p.createPool.name, cidr: p.createPool.cidr, purpose: 'tunnel' });
      poolCreated = { id: pool.id, name: pool.name, cidr: pool.cidr };
      body.tunnel.poolId = pool.id;
    }
    let saved: AllocationPolicyView;
    try {
      saved = await upsertPolicy(tenantId, body);
    } catch (err) {
      if (poolCreated) {
        await deletePool(poolCreated.id).catch((e: unknown) =>
          logger.error({ tenantId, poolId: poolCreated?.id, err: e instanceof Error ? e.name : 'unknown' },
            'onboarding: the pool created for a refused rule could not be removed'));
      }
      throw err;
    }
    try {
      await appendAudit({
        tenantId,
        actorType: 'user',
        actorId: actor.userId,
        actorName: actor.username,
        action: 'onboarding.rule_approved',
        entityType: 'tenant',
        entityId: tenantId,
        after: {
          loginTemplate: saved.pppLoginTemplate,
          tunnelMode: saved.tunnel.mode,
          poolCreated: poolCreated?.name ?? null,
          explained: inference.login.explained,
          total: inference.login.total,
        },
      });
    } catch (err) {
      logger.error({ tenantId, err: err instanceof Error ? err.name : 'unknown' }, 'onboarding: the audit entry could not be written');
    }
    logger.info({ tenantId, userId: actor.userId, poolCreated: poolCreated?.name ?? null }, 'onboarding: inferred allocation rule saved');
    return { saved: true, poolCreated, loginTemplate: saved.pppLoginTemplate };
  } finally {
    approving.delete(tenantId);
  }
}

// ============================================================================
// The steps
// ============================================================================

function step(
  key: OnboardingStepKey,
  state: OnboardingStepState,
  reason: OnboardingReason,
  extra: Partial<Omit<OnboardingStep, 'key' | 'state' | 'reason'>> = {},
): OnboardingStep {
  return {
    key,
    state,
    reason,
    warning: extra.warning ?? null,
    counts: extra.counts ?? {},
    items: (extra.items ?? []).slice(0, ONBOARDING_ITEMS_MAX),
    secrets: extra.secrets ?? [],
    at: extra.at ?? null,
    concentratorId: extra.concentratorId ?? null,
  };
}

interface DeviceFact {
  id: number;
  name: string;
  site_id: number | null;
  status: string;
  brand: string;
  family: string;
  learning: boolean;
  managed: boolean;
  has_snapshot: boolean;
  created_at: Date;
}

async function loadDevices(tenantId: number): Promise<DeviceFact[]> {
  const rows = (await db('devices as d')
    .where('d.tenant_id', tenantId)
    .whereNot('d.role', 'concentrator')
    .orderBy('d.name')
    .select(
      'd.id', 'd.name', 'd.site_id', 'd.status', 'd.brand', 'd.family', 'd.created_at',
      db.raw('(d.learning_since IS NOT NULL) AS learning'),
      db.raw(
        "EXISTS (SELECT 1 FROM device_transports t WHERE t.device_id = d.id AND t.transport = 'routeros_api' " +
          "AND t.enabled = true AND t.username = 'obliwan') AS managed",
      ),
      db.raw('EXISTS (SELECT 1 FROM config_snapshots cs WHERE cs.device_id = d.id) AS has_snapshot'),
    )) as Array<Record<string, unknown>>;
  return rows.map((r) => ({
    id: num(r.id),
    name: String(r.name),
    site_id: r.site_id === null ? null : num(r.site_id),
    status: String(r.status),
    brand: String(r.brand),
    family: String(r.family),
    learning: r.learning === true,
    managed: r.managed === true,
    has_snapshot: r.has_snapshot === true,
    created_at: new Date(r.created_at as string),
  }));
}

/** Step 1 — the CHR holding the tenant's accounts has been read. */
async function chrStep(
  tenant: TenantRow,
  policy: AllocationPolicyView | null,
  chr: ChrContext,
  slugSecrets: SecretRow[],
  nowMs: number,
): Promise<OnboardingStep> {
  if (chr.trusted.length === 0) return step('chr', 'blocked', 'no_concentrator');
  const perChr = new Map<number, number>();
  for (const s of slugSecrets) perChr.set(s.concentrator_id, (perChr.get(s.concentrator_id) ?? 0) + 1);
  const target = policy?.concentratorId
    ?? [...perChr.entries()].sort((a, b) => b[1] - a[1] || a[0] - b[0])[0]?.[0]
    ?? chr.trusted[0];
  const read = chr.reads.get(target);
  const counts = { accounts: slugSecrets.length, chrs: chr.trusted.length };
  if (!read) return step('chr', 'todo', 'never_read', { counts, concentratorId: target, items: [chr.names.get(target) ?? ''] });
  const warning: OnboardingWarning | null = nowMs - read.readAt.getTime() > ONBOARDING_CHR_STALE_MS ? 'read_stale' : null;
  const extra = {
    counts: { ...counts, secrets: read.secretCount },
    at: read.readAt.toISOString(),
    concentratorId: target,
    items: [chr.names.get(target) ?? ''],
    warning,
  };
  if (slugSecrets.length === 0 && !policy) return step('chr', 'todo', 'no_slug_accounts', { ...extra, items: [tenant.slug] });
  return step('chr', 'done', 'chr_read', extra);
}

/** Step 2 — the allocation rule: stored, and how much of the CHR it reads. */
async function ruleStep(
  tenant: TenantRow,
  policy: AllocationPolicyView | null,
  chrDone: boolean,
  slugSecrets: SecretRow[],
): Promise<OnboardingStep> {
  if (!policy) {
    if (!chrDone) return step('rule', 'blocked', 'chr_not_read');
    return step('rule', 'todo', 'no_policy', { counts: { accounts: slugSecrets.length } });
  }
  let explained = 0;
  const parsed = parseLoginTemplate(policy.pppLoginTemplate);
  if (parsed.ok) {
    const d = deriveLoginMatcher(parsed.template, { tenantSlug: tenant.slug, instanceDomain: await readInstanceDomain(db) });
    if (d.ok) for (const s of slugSecrets) if (readLogin(d.matcher, s.name)) explained += 1;
  }
  return step('rule', 'done', 'policy_saved', {
    counts: { explained, accounts: slugSecrets.length },
    items: [policy.pppLoginTemplate],
    warning: explained < slugSecrets.length ? 'rule_partial' : null,
  });
}

/** Steps 3 and 4 — sites from the CHR, then the routers attached. */
function sitesAndAttachSteps(
  report: ReconcileReport | null,
  failure: string | null,
  devices: DeviceFact[],
): [OnboardingStep, OnboardingStep] {
  if (!report) {
    const reason: OnboardingReason = failure === null ? 'no_policy' : 'policy_unreadable';
    const items = failure === null ? [] : [failure];
    return [step('sites', 'blocked', reason, { items }), step('attach', 'blocked', reason, { items })];
  }
  const matched = report.matched;
  const toAdopt = matched.filter((m) => m.status === 'adoptable');
  const addressed = matched.length - toAdopt.length;
  const sitesCounts = {
    matched: matched.length,
    orphans: report.counts.orphans,
    orphansOnline: report.counts.orphansOnline,
    toAdopt: toAdopt.length,
    addressed,
    sites: report.counts.sites,
    duplicates: report.counts.duplicates,
  };
  let sites: OnboardingStep;
  if (matched.length === 0 && report.counts.orphans === 0) {
    sites = step('sites', 'todo', 'no_match', { counts: sitesCounts });
  } else if (report.counts.orphans > 0) {
    sites = step('sites', 'todo', 'orphans', { counts: sitesCounts, items: report.orphans.map((o) => o.account.name) });
  } else if (toAdopt.length > 0) {
    sites = step('sites', 'todo', 'to_adopt', { counts: sitesCounts, items: toAdopt.map((m) => m.code) });
  } else {
    sites = step('sites', 'done', 'sites_done', { counts: sitesCounts });
  }

  const matchedIds = new Set(matched.map((m) => m.siteId));
  const bySite = new Map<number, DeviceFact>();
  for (const d of devices) if (d.site_id !== null && matchedIds.has(d.site_id)) bySite.set(d.site_id, d);
  const attached = matched.filter((m) => bySite.has(m.siteId));
  const attachable = matched.filter((m) => !bySite.has(m.siteId) && m.account.session.up);
  const offline = matched.filter((m) => !bySite.has(m.siteId) && !m.account.session.up);
  const attachedDevices = attached.map((m) => bySite.get(m.siteId) as DeviceFact);
  const attachCounts = {
    matched: matched.length,
    attached: attached.length,
    attachable: attachable.length,
    offline: offline.length,
    learning: attachedDevices.filter((d) => d.learning).length,
    managed: attachedDevices.filter((d) => d.managed).length,
  };
  const warning: OnboardingWarning | null = offline.length > 0 ? 'offline_sites' : null;
  let attach: OnboardingStep;
  if (matched.length === 0) attach = step('attach', 'blocked', 'no_sites', { counts: attachCounts });
  else if (attachable.length > 0 || attached.length === 0) {
    attach = step('attach', 'todo', attached.length === 0 ? 'canary' : 'batch', {
      counts: attachCounts, items: attachable.map((m) => m.code), warning,
    });
  } else {
    attach = step('attach', 'done', 'attached', { counts: attachCounts, warning });
  }
  return [sites, attach];
}

/** Step 5 — the workspace verification of management access and fixes. */
async function accessStep(tenantId: number, devices: DeviceFact[], nowMs: number): Promise<OnboardingStep> {
  const active = devices.filter((d) => d.status === 'active' && d.brand === 'mikrotik');
  if (active.length === 0) return step('access', 'blocked', 'no_devices');
  const run = (await db('access_check_runs')
    .where({ tenant_id: tenantId })
    .orderBy('id', 'desc')
    .first('id', 'status', 'total', 'started_at', 'heartbeat_at', 'finished_at')) as
    | { id: number; status: string; total: number; started_at: Date; heartbeat_at: Date; finished_at: Date | null }
    | undefined;
  if (!run) return step('access', 'todo', 'never_verified', { counts: { devices: active.length } });
  const rows = (await db('access_check_results')
    .where({ run_id: run.id })
    .groupBy('state', 'action')
    .select('state', 'action', db.raw('count(*) AS n'))) as Array<{ state: string; action: string | null; n: string | number }>;
  const counts = { devices: active.length, total: num(run.total), pending: 0, ok: 0, needsAccess: 0, needsFixes: 0, skipped: 0 };
  for (const r of rows) {
    const n = num(r.n);
    if (r.state === 'pending' || r.action === null) counts.pending += n;
    else if (r.action === 'management_access') counts.needsAccess += n;
    else if (r.action === 'legacy_compliance') counts.needsFixes += n;
    else if (r.action === 'none') counts.ok += n;
    else counts.skipped += n;
  }
  const at = iso(run.finished_at ?? run.started_at);
  const alive = run.status === 'running' && nowMs - new Date(run.heartbeat_at).getTime() <= ACCESS_CHECK_STALE_RUN_MS;
  if (alive) return step('access', 'running', 'verification_running', { counts, at });
  const newer = active.some((d) => d.created_at.getTime() > new Date(run.started_at).getTime());
  if (newer) return step('access', 'todo', 'verification_stale', { counts, at, warning: 'new_devices_since' });
  if (counts.needsAccess + counts.needsFixes > 0 || run.status !== 'done') {
    return step('access', 'todo', run.status === 'done' ? 'access_missing' : 'verification_stale', { counts, at });
  }
  return step('access', 'done', 'verified', { counts, at });
}

/** Step 6 — every collectable router has a configuration (collected or captured). */
async function configsStep(tenantId: number, devices: DeviceFact[]): Promise<OnboardingStep> {
  const collectable = devices.filter(
    (d) => d.status === 'active' && (COLLECTABLE_FAMILIES as readonly string[]).includes(d.family),
  );
  if (collectable.length === 0) return step('configs', 'blocked', 'no_collectable');
  const [captured] = (await db('learning_captures')
    .where({ tenant_id: tenantId, status: 'succeeded' })
    .countDistinct<{ n: string }[]>('device_id as n')) as Array<{ n: string }>;
  const ids = collectable.map((d) => d.id);
  const [latest] = (await db('config_snapshots')
    .whereIn('device_id', ids)
    .max<{ at: Date | null }[]>('last_seen_at as at')) as Array<{ at: Date | null }>;
  const missing = collectable.filter((d) => !d.has_snapshot);
  const collect = tenantCollectState(tenantId);
  const counts = {
    devices: collectable.length,
    collected: collectable.length - missing.length,
    missing: missing.length,
    captured: num(captured?.n),
    collectDone: collect?.done ?? 0,
    collectTotal: collect?.total ?? 0,
  };
  const warning: OnboardingWarning | null = collect && collect.deferred > 0 ? 'collect_deferred' : null;
  const at = iso(latest?.at ?? null);
  if (collect?.running) return step('configs', 'running', 'collect_running', { counts, at, warning });
  if (missing.length > 0) return step('configs', 'todo', 'configs_missing', { counts, at, warning, items: missing.map((d) => d.name) });
  return step('configs', 'done', 'configs_done', { counts, at, warning });
}

/** Step 7 — the infra analysis ran over the attached routers and its values were applied. */
async function infraStep(tenantId: number, devices: DeviceFact[]): Promise<OnboardingStep> {
  const revs = (await db('template_revisions as r')
    .join('templates as t', 't.id', 'r.template_id')
    .where('t.status', 'active')
    .whereIn('r.status', ['draft', 'published'])
    .andWhere(function ownOrLibrary(this: import('knex').Knex.QueryBuilder) {
      this.where('r.tenant_id', tenantId).orWhereNull('r.tenant_id');
    })
    .whereRaw("r.var_schema::text like '%x-obliwan-discover%'")
    .limit(100)
    .select('r.var_schema')) as Array<{ var_schema: unknown }>;
  const probeKeys = new Set<string>();
  for (const r of revs) for (const p of probesOf(r.var_schema)) probeKeys.add(p.key);
  if (probeKeys.size === 0) return step('infra', 'blocked', 'no_probe_template');
  const analysable = devices.filter((d) => d.status === 'active' && d.brand === 'mikrotik' && d.site_id !== null);
  if (analysable.length === 0) return step('infra', 'blocked', 'no_devices', { items: [...probeKeys].sort() });
  const run = (await db('audit_log')
    .where({ tenant_id: tenantId, action: 'infra_analysis.run' })
    .orderBy('id', 'desc')
    .first('after', 'correlation_id', 'occurred_at')) as
    | { after: unknown; correlation_id: string | null; occurred_at: Date }
    | undefined;
  const keys = [...probeKeys].sort();
  if (!run) return step('infra', 'todo', 'never_analysed', { counts: { devices: analysable.length }, items: keys });
  const after = (typeof run.after === 'string' ? JSON.parse(run.after) : run.after ?? {}) as Record<string, unknown>;
  const done = num(after.done);
  const proposals = num(after.proposals);
  const [applied] = run.correlation_id
    ? ((await db('audit_log')
      .where({ tenant_id: tenantId, action: 'infra_analysis.applied', correlation_id: run.correlation_id })
      .countDistinct<{ n: string }[]>('entity_id as n')) as Array<{ n: string }>)
    : [{ n: '0' }];
  const counts = { devices: analysable.length, done, proposals, applied: num(applied?.n) };
  const at = iso(run.occurred_at);
  const newer = analysable.some((d) => d.created_at.getTime() > new Date(run.occurred_at).getTime());
  const warning: OnboardingWarning | null = newer ? 'new_devices_since' : null;
  if (done < analysable.length) return step('infra', 'todo', 'analysis_partial', { counts, at, warning, items: keys });
  if (proposals > 0 && counts.applied === 0) return step('infra', 'todo', 'analysis_not_applied', { counts, at, warning, items: keys });
  return step('infra', 'done', 'analysed', { counts, at, warning, items: keys });
}

/** Step 8 — templates extrapolated, approved (drafts), published and assigned. */
async function templatesStep(tenantId: number, devices: DeviceFact[]): Promise<OnboardingStep> {
  const proposals = (await db('extrapolation_proposals')
    .where({ tenant_id: tenantId })
    .groupBy('status')
    .select('status', db.raw('count(*) AS n'))) as Array<{ status: string; n: string | number }>;
  const byStatus = (s: string): number => num(proposals.find((p) => p.status === s)?.n);
  const [runs] = (await db('extrapolation_runs').where({ tenant_id: tenantId }).count<{ n: string }[]>('* as n')) as Array<{ n: string }>;
  const tenantTemplates = (await db('templates as t')
    .where('t.tenant_id', tenantId)
    .where('t.status', 'active')
    .select(
      't.id', 't.name',
      db.raw("EXISTS (SELECT 1 FROM template_revisions r WHERE r.template_id = t.id AND r.status = 'published') AS published"),
    )) as Array<{ id: number; name: string; published: boolean }>;
  const assigned = (await db('template_assignments as a')
    .join('templates as t', 't.id', 'a.template_id')
    .where('a.tenant_id', tenantId)
    .where('t.status', 'active')
    .whereRaw("EXISTS (SELECT 1 FROM template_revisions r WHERE r.template_id = t.id AND r.status = 'published')")
    .countDistinct<{ n: string }[]>('a.template_id as n')) as Array<{ n: string }>;
  const counts = {
    runs: num(runs?.n),
    proposed: byStatus('proposed'),
    approved: byStatus('approved'),
    rejected: byStatus('rejected'),
    templates: tenantTemplates.length,
    published: tenantTemplates.filter((t) => t.published).length,
    assigned: num(assigned[0]?.n),
  };
  const drafts = tenantTemplates.filter((t) => !t.published).map((t) => t.name);
  if (counts.assigned > 0) {
    if (counts.proposed > 0) return step('templates', 'todo', 'proposals_pending', { counts });
    return step('templates', 'done', 'templates_done', { counts });
  }
  if (counts.published > 0) {
    return step('templates', 'todo', 'not_assigned', { counts, items: tenantTemplates.filter((t) => t.published).map((t) => t.name) });
  }
  if (drafts.length > 0) return step('templates', 'todo', 'not_published', { counts, items: drafts });
  if (counts.proposed > 0) return step('templates', 'todo', 'proposals_pending', { counts });
  if (!devices.some((d) => d.has_snapshot)) return step('templates', 'blocked', 'no_configs', { counts });
  return step('templates', 'todo', 'never_extrapolated', { counts });
}

/** Step 9 — every required variable has a value, secrets listed by NAME. */
async function variablesStep(tenantId: number, policy: AllocationPolicyView | null): Promise<OnboardingStep> {
  const refs = await loadPublishedReferences(tenantId);
  if (refs.length === 0) return step('variables', 'blocked', 'no_published_template');
  const declarations = buildDeclarations(refs);
  // Keys only: no value is read, nothing is decrypted.
  const wideRows = (await db('config_variables')
    .where(function wide(this: import('knex').Knex.QueryBuilder) {
      this.where(function inst(this: import('knex').Knex.QueryBuilder) {
        this.whereNull('tenant_id').where('scope', 'instance');
      }).orWhere(function mine(this: import('knex').Knex.QueryBuilder) {
        this.where('tenant_id', tenantId).whereIn('scope', ['global', 'tenant']);
      });
    })
    .distinct('key')) as Array<{ key: string }>;
  const wide = new Set(wideRows.map((r) => r.key));
  const sites = (await db('sites').where({ tenant_id: tenantId }).orderBy('code').select('id', 'code')) as Array<{ id: number; code: string }>;
  const siteKeys = new Map<number, Set<string>>();
  const ids = sites.map((s) => Number(s.id));
  for (let i = 0; i < ids.length; i += 1000) {
    const rows = (await db('config_variables')
      .where({ tenant_id: tenantId, scope: 'site' })
      .whereIn('scope_id', ids.slice(i, i + 1000))
      .select('scope_id', 'key')) as Array<{ scope_id: number; key: string }>;
    for (const r of rows) {
      const set = siteKeys.get(Number(r.scope_id)) ?? new Set<string>();
      set.add(r.key);
      siteKeys.set(Number(r.scope_id), set);
    }
  }
  const computed = computedSuppliedKeys(
    policy
      ? { hasLan: policy.lan !== null, hasIdentity: policy.systemIdentityTemplate !== null, derivedKeys: Object.keys(policy.derived ?? {}) }
      : null,
  );
  const req = resolveRequirements({
    declarations,
    wide,
    sites: sites.map((s) => ({ code: s.code, keys: siteKeys.get(Number(s.id)) ?? new Set<string>() })),
    computed,
  });
  const secretKeys = new Set(declarations.filter((d) => d.secret).map((d) => d.key));
  const missingKeys: string[] = [];
  const secrets: string[] = [];
  let wideMissing = 0;
  let siteMissing = 0;
  let sitesLacking = 0;
  let computedMissing = 0;
  for (const level of req.levels) {
    if (!level.checked) continue;
    for (const m of level.missing) {
      missingKeys.push(m.key);
      if (secretKeys.has(m.key)) secrets.push(m.key);
      if (level.level === 'site') {
        siteMissing += 1;
        sitesLacking = Math.max(sitesLacking, m.sitesTotal ?? 0);
      } else if (level.level === 'computed') computedMissing += 1;
      else wideMissing += 1;
    }
  }
  const counts = { wideMissing, siteMissing, sitesLacking, computedMissing, secrets: secrets.length, sites: sites.length };
  const uniq = [...new Set(missingKeys)].sort();
  const secretList = [...new Set(secrets)].sort();
  if (req.complete) return step('variables', 'done', 'variables_done', { counts });
  return step('variables', 'todo', 'variables_missing', { counts, items: uniq, secrets: secretList });
}

/**
 * The nine steps of the tenant's onboarding, recomputed now. Reads only.
 */
export async function getOnboardingStatus(tenantId: number, nowMs: number = Date.now()): Promise<OnboardingStatus> {
  const tenant = await loadTenant(tenantId);
  const policy = await getPolicy(tenantId);
  const chr = await loadChrContext(tenantId);
  const slugSecrets = tenant.slug.length >= RULE_INFERENCE_SLUG_MIN ? await secretsNaming(chr.trusted, tenant.slug.toLowerCase()) : [];
  const devices = await loadDevices(tenantId);

  const s1 = await chrStep(tenant, policy, chr, slugSecrets, nowMs);
  const s2 = await ruleStep(tenant, policy, s1.state === 'done', slugSecrets);
  let report: ReconcileReport | null = null;
  let failure: string | null = null;
  if (policy) {
    try {
      report = await reconcileTenant(tenantId, nowMs);
    } catch (err) {
      if (!(err instanceof AllocationError)) throw err;
      failure = err.reason;
    }
  }
  const [s3, s4] = sitesAndAttachSteps(report, failure, devices);
  const steps: OnboardingStep[] = [
    s1,
    s2,
    s3,
    s4,
    await accessStep(tenantId, devices, nowMs),
    await configsStep(tenantId, devices),
    await infraStep(tenantId, devices),
    await templatesStep(tenantId, devices),
    await variablesStep(tenantId, policy),
  ];
  return {
    tenant,
    generatedAt: new Date(nowMs).toISOString(),
    steps,
    next: steps.find((s) => s.state !== 'done')?.key ?? null,
  };
}
