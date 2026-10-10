/**
 * ObliWAN — sites.
 *
 * A site is the customer premises. It carries the maintenance window that gates
 * every push, so it exists as a first-class entity.
 *
 * EVERY query in this file is tenant-scoped, and the tenant comes from the
 * SESSION (`req.tenantId`), never from the request body. `sites.code` is unique
 * per tenant, not globally: two MSP customers are both entitled to a site
 * called "SIEGE".
 */

import type { Knex } from 'knex';
import { ACTIVE_CHANGE_JOB_STATUSES, SOCKET_EVENTS, isEmptyOpeningHours, type OpeningHours, type SiteUplinkKind } from '@obliwan/shared';
import { db } from '../../db';
import { AppError } from '../../middleware/errorHandler';
import { logger } from '../../utils/logger';
import { applyTenantScope } from '../../utils/globalView';
import type { SiteDeleteAcknowledgement } from '../../validators/site.schema';
import { takeAllocationLock } from '../allocation/lock';
import { appendAudit } from '../attestation/auditLog.service';
import { closeBackup4gForSites } from './backup4g.service';
import { emitToTenant } from './fleetEvents';
import { emitToTenantAudience } from './scopedEmit';
import { toSiteDto } from './dto';
import { assertSiteCodeFormat } from './siteCodeFormat';

export interface SiteRow {
  id: number;
  uuid: string;
  tenant_id: number;
  code: string;
  name: string;
  /** ISO 3166-1 alpha-2, uppercase, or null (migration 036). */
  country: string | null;
  address: string | null;
  contact: string | null;
  timezone: string;
  maintenance_window: unknown;
  /** The declared access link (migration 076): NULL = not declared, ObliWAN
   *  infers it. The two others record the LAST declaration (auto included). */
  uplink_kind: SiteUplinkKind | null;
  uplink_kind_set_at: Date | null;
  uplink_kind_set_by: number | null;
  /** The site's own opening hours (migration 096); NULL = the workspace's. */
  opening_hours?: unknown;
  /** « Opérateur du lien fixe » (migration 095); NULL = not declared. */
  fixed_provider?: string | null;
  created_at: Date;
  updated_at: Date;
}

export interface SiteWithCounts extends SiteRow {
  device_count: number;
  online_count: number;
  /** God view only: the owning tenant's name. */
  tenant_name?: string | null;
  /** Present only when the caller asked for it (`listSites` `simCount`). */
  sim_count?: number;
}

/**
 * The SIM lines of a site, as the 4G lines page lists them for `?siteId=`
 * (sim/line.service `listLines`: the line's own site OR its router's site,
 * terminated lines included, pool lines never — they carry no site). Each
 * line counted once. `deviceIds` is the caller's team scope (teamScope
 * `deviceListScope`): a line on a router the caller cannot see is not counted,
 * exactly as `filterRowsByDevice` drops it from the list; null = tenant-wide.
 */
export interface SiteSimCountOptions {
  deviceIds: number[] | null;
}

export interface CreateSiteData {
  code: string;
  name: string;
  /** Already normalised by the caller (two uppercase letters, or null); the
   *  CHECK of migration 036 refuses anything else. */
  country?: string | null;
  address?: string | null;
  contact?: string | null;
  timezone?: string;
  maintenanceWindow?: unknown;
  /** The declared access link; null = back to "not declared". Present only
   *  when it is being DECLARED: it stamps `uplink_kind_set_at`/`_by`. */
  uplinkKind?: SiteUplinkKind | null;
  /** Who declares it (users.id), written with `uplinkKind` only. */
  uplinkKindSetBy?: number | null;
  /** The site's own opening hours (validated); null = inherit the workspace's. */
  openingHours?: OpeningHours | null;
  /** « Opérateur du lien fixe » (migration 095), already normalised
   *  (shared `normalizeFixedProvider`); null = not declared. */
  fixedProvider?: string | null;
}

export type UpdateSiteData = Partial<CreateSiteData>;

/** Who acts, for `uplink_kind_set_by` and `audit_log`. */
export interface SiteActor {
  userId: number | null;
  username: string | null;
}

/** The `sites` columns a create/update writes. Exported for the bulk import,
 *  which writes inside its own per-row transaction. */
export function siteDataToColumns(data: UpdateSiteData): Record<string, unknown> {
  const row: Record<string, unknown> = {};
  if (data.uplinkKind !== undefined) {
    // The three move together (076's CHECK): a declaration carries its instant.
    row.uplink_kind = data.uplinkKind;
    row.uplink_kind_set_at = new Date();
    row.uplink_kind_set_by = data.uplinkKindSetBy ?? null;
  }
  if (data.code !== undefined) row.code = data.code;
  if (data.name !== undefined) row.name = data.name;
  if (data.country !== undefined) row.country = data.country;
  if (data.address !== undefined) row.address = data.address;
  if (data.contact !== undefined) row.contact = data.contact;
  if (data.timezone !== undefined) row.timezone = data.timezone;
  if (data.maintenanceWindow !== undefined) {
    row.maintenance_window =
      data.maintenanceWindow === null ? null : JSON.stringify(data.maintenanceWindow);
  }
  if (data.openingHours !== undefined) {
    row.opening_hours = isEmptyOpeningHours(data.openingHours) ? null : JSON.stringify(data.openingHours);
  }
  if (data.fixedProvider !== undefined) row.fixed_provider = data.fixedProvider;
  return row;
}

/**
 * List with the two numbers the fleet tree actually needs: how many devices,
 * and how many of them have an open PPP session right now.
 *
 * "Online" is defined as an open row in `ppp_sessions` — the concentrator's
 * view — and not as a ping, not as `last_seen_at` being recent.
 */
export async function listSites(
  tenantId: number,
  options: { search?: string; simCount?: SiteSimCountOptions } = {},
): Promise<SiteWithCounts[]> {
  const query = db('sites as s');
  // God view (a platform admin's GET on the master tenant): every tenant's
  // sites, each with its tenant's name; anyone else: this tenant's.
  const godView = applyTenantScope(query, 's.tenant_id', tenantId);
  const simScope = options.simCount;
  // `= ANY(?)` is a bound integer array (never spliced); an empty array counts
  // only the lines attached to the site without a router.
  const simCount = simScope
    ? db.raw(
        `(SELECT count(*)::int FROM sim_lines l
           WHERE l.tenant_id = s.tenant_id
             AND (l.site_id = s.id
                  OR EXISTS (SELECT 1 FROM devices sd
                              WHERE sd.id = l.device_id AND sd.tenant_id = l.tenant_id AND sd.site_id = s.id))
             ${simScope.deviceIds === null ? '' : 'AND (l.device_id IS NULL OR l.device_id = ANY(?))'}
         ) AS sim_count`,
        simScope.deviceIds === null ? [] : [simScope.deviceIds],
      )
    : null;
  void query
    .leftJoin('devices as d', 'd.site_id', 's.id')
    .leftJoin('ppp_sessions as p', function joinOpenSession(this: any) {
      this.on('p.device_id', '=', 'd.id').andOnNull('p.ended_at');
    })
    .groupBy('s.id')
    .select<SiteWithCounts[]>(
      's.*',
      db.raw('COUNT(DISTINCT d.id)::int as device_count'),
      db.raw('COUNT(DISTINCT p.device_id)::int as online_count'),
      ...(godView ? [db.raw('(SELECT t.name FROM tenants t WHERE t.id = s.tenant_id) AS tenant_name')] : []),
      ...(simCount ? [simCount] : []),
    )
    .orderBy('s.name');

  if (options.search) {
    const like = `%${options.search}%`;
    query.andWhere((q) => {
      q.whereILike('s.name', like).orWhereILike('s.code', like);
    });
  }

  return query;
}

export async function getSite(tenantId: number, id: number): Promise<SiteRow | undefined> {
  return db('sites').where({ id, tenant_id: tenantId }).first<SiteRow | undefined>();
}

/** INSERT a site through `executor` (the bulk import passes its per-row
 *  transaction). Emits nothing: the caller emits once that has committed. */
export async function insertSiteRow(
  executor: Knex | Knex.Transaction,
  tenantId: number,
  data: CreateSiteData,
): Promise<SiteRow> {
  const [row] = await executor('sites')
    .insert({ ...siteDataToColumns(data), tenant_id: tenantId })
    .returning<SiteRow[]>('*');
  return row;
}

/** UPDATE a site through `executor`, scoped by tenant. Emits nothing. */
export async function updateSiteRow(
  executor: Knex | Knex.Transaction,
  tenantId: number,
  id: number,
  data: UpdateSiteData,
): Promise<SiteRow | undefined> {
  const columns = siteDataToColumns(data);
  if (Object.keys(columns).length === 0) {
    return executor('sites').where({ id, tenant_id: tenantId }).first<SiteRow | undefined>();
  }
  const [row] = await executor('sites')
    .where({ id, tenant_id: tenantId })
    .update({ ...columns, updated_at: db.fn.now() })
    .returning<SiteRow[]>('*');
  return row;
}

export interface CreateSiteOptions {
  /** The code is read off a PPP account already live on the CHR: the format
   *  is not judged, the site-number sibling check still is
   *  (`SiteCodeAssertOptions.deployedLogin`). Meant for the reconciliation's
   *  orphan sites; no caller passes it yet. */
  deployedLogin?: boolean;
  /** Who creates it: `uplink_kind_set_by` when the create declares the link. */
  actor?: SiteActor;
}

/**
 * The tenant's site code format (migration 052) and the site-number sibling
 * check are judged here, for both callers: POST /api/sites and the
 * reconciliation's orphan sites (reconcile.service `createSiteForTenant`).
 * A refusal is an AppError 400 carrying a French sentence.
 *
 * `createSiteForTenant` does not pass `deployedLogin` yet, so under
 * 'digits:N' an orphan whose live login carries a shorter code ("fr_0042")
 * cannot be given a site: "0042" is refused, and padding it would compute
 * another login than the live one — the refusal says not to.
 */
export async function createSite(
  tenantId: number,
  data: CreateSiteData,
  opts: CreateSiteOptions = {},
): Promise<SiteRow> {
  await assertSiteCodeFormat(db, tenantId, data.code, { deployedLogin: opts.deployedLogin === true });
  // A new site is "not declared" already: a null declaration is not one.
  const fields: CreateSiteData = { ...data };
  delete fields.uplinkKind;
  delete fields.uplinkKindSetBy;
  if (data.uplinkKind) {
    fields.uplinkKind = data.uplinkKind;
    fields.uplinkKindSetBy = opts.actor?.userId ?? null;
  }
  const row = await insertSiteRow(db, tenantId, fields);
  emitToTenantAudience(tenantId, SOCKET_EVENTS.SITE_CREATED, { site: toSiteDto(row) }, { siteId: row.id });
  return row;
}

// ============================================================================
// What ties a site to the world outside its own row — the code lock and the
// delete's safety (readiness backlog #22)
// ============================================================================

/** The site's allocation as the edit form and the delete report show it.
 *  Never the password, in any form. */
export interface SiteAllocationSummary {
  pppUsername: string;
  tunnelIp: string;
  lanSubnet: string | null;
  concentratorState: 'pending' | 'provisioned' | 'failed';
  /** 'adopted_chr' = taken over from a secret the concentrator already
   *  declared (migration 044); 'allocated' or null = drawn by ObliWAN. */
  source: 'allocated' | 'adopted_chr' | null;
  /** The concentrator frozen on the allocation (a device id). */
  concentratorId: number | null;
}

/** A concentrator_secret job of the site that a worker has CLAIMED and not
 *  finished: it may be adding the account on the concentrator right now. */
export interface RunningAccountJob {
  jobId: number;
  pppUsername: string;
  tunnelIp: string;
}

export interface SiteBindings {
  allocation: SiteAllocationSummary | null;
  /** `bench_provisionings` rows still linked to the site. */
  benchProvisionings: number;
  /** Devices filed under the site. */
  devices: number;
  runningAccountJob: RunningAccountJob | null;
  /** An earlier concentrator_secret job of this site, for the allocation's
   *  current login, found the account on the concentrator or added it
   *  (`outcome` 'present' / 'added'), or ended without knowing whether its add
   *  went through (`UNCONFIRMED_ADD_KINDS`). Says nothing about a provisioned
   *  or adopted allocation, whose account is known to be there anyway. */
  accountMayExist: boolean;
  /** SLA reports and site objectives: migration 026 deletes them WITH the
   *  site (ON DELETE CASCADE). */
  slaReports: number;
  slaObjectives: number;
}

/**
 * The `change_jobs.error_kind` values after which an add may have reached the
 * concentrator with nobody knowing: the add was sent and the session dropped
 * or timed out before the answer ('concentrator_secret_add_unconfirmed'), the
 * add failed with an error that is neither a refusal nor a known transport
 * failure ('concentrator_secret_add_failed' — "whether it was created is not
 * known"), or the worker died mid-job ('worker_lost', which can be after the
 * add). Copied from change/concentratorSecret.service.ts, which does not
 * export its constants; a kind renamed there makes this list miss it, and a
 * miss here costs the delete one acknowledgement it should have asked for.
 */
const UNCONFIRMED_ADD_KINDS: readonly string[] = [
  'concentrator_secret_add_unconfirmed',
  'concentrator_secret_add_failed',
  'worker_lost',
];

/** Why a site's code can no longer change. */
export type SiteCodeLockReason = 'allocation' | 'bench';

/**
 * Everything below reads through `q`, so the delete and the rename judge what
 * they read under their own locks. Tenant-scoped like the rest (a
 * concentrator_secret job is matched on `concentrator_secret_jobs.tenant_id`,
 * the SITE's tenant; the job row itself carries the concentrator's).
 *
 * `lockAccountJobs`: also lock (FOR UPDATE) this site's concentrator_secret
 * jobs still in flight, for the delete. A job still QUEUED then cannot be
 * claimed before the delete commits (the queue claims with FOR UPDATE SKIP
 * LOCKED), and once it has, the job's concentrator_secret_jobs row is gone
 * with the site (040, ON DELETE CASCADE): the job fails on
 * 'concentrator_secret_missing' without writing anything.
 */
export async function readSiteBindings(
  q: Knex | Knex.Transaction,
  tenantId: number,
  siteId: number,
  opts: { lockAccountJobs?: boolean } = {},
): Promise<SiteBindings> {
  const prov = (await q('site_provisioning')
    .where({ site_id: siteId, tenant_id: tenantId })
    .select(
      'ppp_username',
      q.raw('host(tunnel_ip) AS tunnel_ip'),
      q.raw('lan_subnet::text AS lan_subnet'),
      'concentrator_state',
      'source',
      'concentrator_id',
    )
    .first()) as
    | {
        ppp_username: string;
        tunnel_ip: string;
        lan_subnet: string | null;
        concentrator_state: SiteAllocationSummary['concentratorState'];
        source: SiteAllocationSummary['source'];
        concentrator_id: number | null;
      }
    | undefined;
  const [bench] = (await q('bench_provisionings')
    .where({ site_id: siteId, tenant_id: tenantId })
    .count('* as n')) as Array<{ n: string | number }>;
  const [devices] = (await q('devices')
    .where({ site_id: siteId, tenant_id: tenantId })
    .count('* as n')) as Array<{ n: string | number }>;
  const [slaReports] = (await q('sla_reports')
    .where({ site_id: siteId, tenant_id: tenantId })
    .count('* as n')) as Array<{ n: string | number }>;
  const [slaObjectives] = (await q('sla_objectives')
    .where({ site_id: siteId, tenant_id: tenantId })
    .count('* as n')) as Array<{ n: string | number }>;

  const inFlightQuery = q('concentrator_secret_jobs as c')
    .join('change_jobs as j', 'j.id', 'c.job_id')
    .where('c.site_id', siteId)
    .where('c.tenant_id', tenantId)
    .whereIn('j.status', [...ACTIVE_CHANGE_JOB_STATUSES])
    .orderBy('c.job_id', 'desc')
    .select('c.job_id', 'j.status', 'c.ppp_username', q.raw('host(c.remote_address) AS remote_address'));
  if (opts.lockAccountJobs) inFlightQuery.forUpdate();
  const inFlight = (await inFlightQuery) as Array<{
    job_id: string | number;
    status: string;
    ppp_username: string;
    remote_address: string;
  }>;
  const claimed = inFlight.find((r) => r.status !== 'queued');

  let accountMayExist = false;
  if (prov) {
    const evidence = await q('concentrator_secret_jobs as c')
      .join('change_jobs as j', 'j.id', 'c.job_id')
      .where('c.site_id', siteId)
      .where('c.tenant_id', tenantId)
      .where('c.ppp_username', prov.ppp_username)
      .where((w) => {
        w.whereIn('c.outcome', ['added', 'present']).orWhereIn('j.error_kind', [...UNCONFIRMED_ADD_KINDS]);
      })
      .first('c.job_id');
    accountMayExist = evidence !== undefined;
  }

  return {
    allocation: prov
      ? {
          pppUsername: prov.ppp_username,
          tunnelIp: prov.tunnel_ip,
          lanSubnet: prov.lan_subnet,
          concentratorState: prov.concentrator_state,
          source: prov.source,
          concentratorId: prov.concentrator_id === null ? null : Number(prov.concentrator_id),
        }
      : null,
    benchProvisionings: Number(bench?.n ?? 0),
    devices: Number(devices?.n ?? 0),
    runningAccountJob: claimed
      ? { jobId: Number(claimed.job_id), pppUsername: claimed.ppp_username, tunnelIp: claimed.remote_address }
      : null,
    accountMayExist,
    slaReports: Number(slaReports?.n ?? 0),
    slaObjectives: Number(slaObjectives?.n ?? 0),
  };
}

/**
 * The code is frozen once anything outside the row was computed from it: an
 * allocation in any state, or a file the bench compiled for the site.
 *
 * What an allocation freezes is its PPP login and its system identity, both
 * rendered from the site's data, code included (`site_provisioning`, never
 * re-rendered). What is computed again at every compile and preview — the
 * `site_code` value and the policy's derived values (allocator.ts
 * `computedValues`) — is read from the CURRENT site, so after a new code the
 * two halves would no longer agree. A bench file is a document already
 * delivered. The name and the country feed the same login formula
 * (`{site.slug}`, `{site.country}`) and are NOT locked: the edit form warns
 * instead.
 */
export function siteCodeLockReasons(b: SiteBindings): SiteCodeLockReason[] {
  const out: SiteCodeLockReason[] = [];
  if (b.allocation) out.push('allocation');
  if (b.benchProvisionings > 0) out.push('bench');
  return out;
}

/** The site's L2TP account is KNOWN to be on the concentrator: ObliWAN wrote
 *  it there (provisioned), or adopted it from there. A 'pending' or 'failed'
 *  allocation may have one too — see `chrAccountKept`. */
export function accountLiveOnConcentrator(a: SiteAllocationSummary | null): boolean {
  return a !== null && (a.concentratorState === 'provisioned' || a.source === 'adopted_chr');
}

/**
 * Why the delete reports an L2TP account as staying on the concentrator:
 *   - 'provisioned'      ObliWAN wrote it and read it back;
 *   - 'adopted'          the allocation was taken over from it;
 *   - 'job_running'      a job a worker has claimed may be adding it now;
 *   - 'add_unconfirmed'  an earlier job added or found it, or lost the
 *                        answer to its add (`SiteBindings.accountMayExist`).
 * The first two are certain, the last two are "may be there".
 */
export type ChrAccountBasis = 'provisioned' | 'adopted' | 'job_running' | 'add_unconfirmed';

export interface ChrAccountKept {
  pppUsername: string;
  tunnelIp: string;
  basis: ChrAccountBasis;
}

export interface SiteDeleteImpact {
  /** Stay, detached (devices.site_id ON DELETE SET NULL). */
  devicesDetached: number;
  /** Released with the site (site_provisioning ON DELETE CASCADE). */
  allocationReleased: SiteAllocationSummary | null;
  /** The L2TP account that stays, or may stay, on the concentrator: ObliWAN
   *  never removes one (writes to the CHR are additive only). */
  chrAccountKept: ChrAccountKept | null;
  /** Bench preparations kept as history, detached, with a copy of the
   *  site's code and name (migration 056). */
  benchHistoryKept: number;
  /** Deleted WITH the site (migration 026, ON DELETE CASCADE). */
  slaReportsDeleted: number;
  slaObjectivesDeleted: number;
  /** What a delete must acknowledge by name; empty = nothing. */
  acknowledge: SiteDeleteAcknowledgement[];
}

export function chrAccountKept(b: SiteBindings): ChrAccountKept | null {
  const a = b.allocation;
  if (a && a.concentratorState === 'provisioned') {
    return { pppUsername: a.pppUsername, tunnelIp: a.tunnelIp, basis: 'provisioned' };
  }
  if (a && a.source === 'adopted_chr') return { pppUsername: a.pppUsername, tunnelIp: a.tunnelIp, basis: 'adopted' };
  // The running job's own login and address: what it would write, even if
  // the allocation was released or re-made since it was queued.
  if (b.runningAccountJob) {
    return { pppUsername: b.runningAccountJob.pppUsername, tunnelIp: b.runningAccountJob.tunnelIp, basis: 'job_running' };
  }
  if (a && b.accountMayExist) return { pppUsername: a.pppUsername, tunnelIp: a.tunnelIp, basis: 'add_unconfirmed' };
  return null;
}

export function siteDeleteImpact(b: SiteBindings): SiteDeleteImpact {
  const kept = chrAccountKept(b);
  const acknowledge: SiteDeleteAcknowledgement[] = [];
  if (kept) acknowledge.push('chr_account');
  if (b.benchProvisionings > 0) acknowledge.push('bench_history');
  // A report is a statement already issued about the site's month; an
  // objective alone is a setting, like the site variables, and goes unasked.
  if (b.slaReports > 0) acknowledge.push('sla_history');
  return {
    devicesDetached: b.devices,
    allocationReleased: b.allocation,
    chrAccountKept: kept,
    benchHistoryKept: b.benchProvisionings,
    slaReportsDeleted: b.slaReports,
    slaObjectivesDeleted: b.slaObjectives,
    acknowledge,
  };
}

/**
 * What the site form needs and the site DTO does not carry: the stored
 * country (`toSiteDto` has no `country`), whether the code may still change
 * and why not, and what a delete would leave behind. A forecast — the rename
 * and the delete judge again under their locks.
 */
export interface SiteEditContext {
  siteId: number;
  country: string | null;
  /** Empty = the code may change. */
  codeLock: SiteCodeLockReason[];
  allocation: SiteAllocationSummary | null;
  benchProvisionings: number;
  deletion: SiteDeleteImpact;
}

export async function siteEditContext(tenantId: number, siteId: number): Promise<SiteEditContext | null> {
  const site = await getSite(tenantId, siteId);
  if (!site) return null;
  const b = await readSiteBindings(db, tenantId, siteId);
  return {
    siteId,
    country: site.country,
    codeLock: siteCodeLockReasons(b),
    allocation: b.allocation,
    benchProvisionings: b.benchProvisionings,
    deletion: siteDeleteImpact(b),
  };
}

function codeLockedMessage(code: string, b: SiteBindings): string {
  const why: string[] = [];
  if (b.allocation) why.push(`il a une allocation (login PPP « ${b.allocation.pppUsername} »)`);
  if (b.benchProvisionings > 0) {
    why.push(`le banc l’a déjà préparé (${b.benchProvisionings} fichier(s) compilé(s))`);
  }
  let text =
    `Le code du site « ${code} » ne peut plus être modifié : ${why.join(' et ')}. ` +
    'Ce qui a été calculé à partir des données du site, code compris (login PPP, identité, ' +
    'fichiers du banc), ne serait pas recalculé par un changement de code, alors que le code ' +
    'lui-même et les valeurs dérivées sont relus sur le site à chaque compilation : les deux ne ' +
    'correspondraient plus.';
  // The one operation that unfreezes it, and only while no bench file
  // exists (bench history is never removed).
  if (b.allocation && b.benchProvisionings === 0) {
    text +=
      ' Pour changer le code, un administrateur de la plateforme libère d’abord l’allocation ' +
      '(page Allocation ; une allocation déjà provisionnée demande de saisir son login, et son ' +
      'compte reste sur le concentrateur).';
  }
  return text;
}

function deleteRefusalMessage(
  site: Pick<SiteRow, 'code' | 'name'>,
  impact: SiteDeleteImpact,
  missing: readonly SiteDeleteAcknowledgement[],
): string {
  const parts = [`Suppression du site « ${site.code} » (${site.name}) refusée sans confirmation explicite.`];
  const kept = impact.chrAccountKept;
  if (missing.includes('chr_account') && kept) {
    const account = `Son compte L2TP « ${kept.pppUsername} » (adresse tunnel ${kept.tunnelIp})`;
    parts.push(
      kept.basis === 'provisioned' || kept.basis === 'adopted'
        ? `${account} est sur le concentrateur et y restera : ObliWAN ne le supprime jamais.`
        : kept.basis === 'job_running'
          ? `${account} est peut-être en cours de création sur le concentrateur par une tâche en cours ; ` +
            's’il y est créé, il y restera : ObliWAN ne le supprime jamais.'
          : `${account} est peut-être sur le concentrateur (une tâche précédente l’y a créé ou trouvé, ou ` +
            'n’a pas su si sa création avait abouti) ; s’il y est, il y restera : ObliWAN ne le supprime jamais.',
    );
  }
  if (missing.includes('bench_history')) {
    parts.push(
      `${impact.benchHistoryKept} préparation(s) au banc seront conservées comme historique, ` +
        'détachées du site, avec son code et son nom.',
    );
  }
  if (missing.includes('sla_history')) {
    parts.push(
      `${impact.slaReportsDeleted} rapport(s) SLA du site seront supprimés avec lui` +
        (impact.slaObjectivesDeleted > 0 ? `, ainsi que ${impact.slaObjectivesDeleted} objectif(s) SLA` : '') +
        ' : ils ne seront plus consultables.',
    );
  }
  parts.push(`Pour supprimer quand même, confirmez « je sais » (acknowledge=${missing.join(',')}).`);
  return parts.join(' ');
}

export interface UpdateSiteOptions {
  /** Who edits: `uplink_kind_set_by` and the audit entry of a declaration. */
  actor?: SiteActor;
}

/** The ledger entry of one access-link declaration (unitary or bulk). */
function uplinkAuditEntry(
  tenantId: number,
  actor: SiteActor | undefined,
  entityId: number | null,
  before: Record<string, unknown>,
  after: Record<string, unknown>,
) {
  return {
    tenantId,
    actorType: 'user' as const,
    actorId: actor?.userId ?? null,
    actorName: actor?.username ? actor.username.slice(0, 128) : null,
    action: 'site.uplink_kind_set',
    entityType: 'site',
    entityId,
    before,
    after,
  };
}

/**
 * Edit a site. The access-link declaration (`uplinkKind`, migration 076) is
 * judged on the row read under its lock: restating the stored value is not a
 * declaration (its "who and when" stay), a real change is stamped
 * (`uplink_kind_set_at`/`_by`) and written to `audit_log` in the same
 * transaction. Declaring a site 4G-only closes the open 4G backup alerts of
 * its routers once committed (backup4g.service `closeBackup4gForSites`).
 */
export async function updateSite(
  tenantId: number,
  id: number,
  data: UpdateSiteData,
  opts: UpdateSiteOptions = {},
): Promise<SiteRow | undefined> {
  if (Object.keys(siteDataToColumns(data)).length === 0) return getSite(tenantId, id);
  const declares = data.uplinkKind !== undefined;
  /** Set inside the transaction when the declaration actually changes. */
  const declared: { value: { before: SiteUplinkKind | null; after: SiteUplinkKind | null } | null } = { value: null };

  // A rename is judged like a create, the site itself left out of the
  // sibling lookup (renaming a legacy "7" to "00007" keeps one site for that
  // number, it does not add a second). A body that re-sends the CURRENT code
  // (a form posting every field) is not a rename, so a site whose code
  // predates the format can still have its name or address edited — and the
  // code lock below does not apply to it either.
  //
  // Whether the code CHANGES is decided on the row read under the locks,
  // never on an earlier read: a body carrying a code takes the locked path
  // even when it looks like the current one, or a rename committed in
  // between would be silently undone without the lock being judged.
  const row =
    data.code !== undefined || declares
      ? await db.transaction(async (trx) => {
          // The allocation lock, then the site row: the allocator's own order
          // (allocateForSite takes the lock, then reads the site FOR SHARE).
          // Under both, an allocation cannot appear between the lock check
          // and the rename, nor a bench file (its insert's FK check waits on
          // the row lock). A declaration alone takes the row lock only.
          if (data.code !== undefined) await takeAllocationLock(trx);
          const current = await trx('sites')
            .where({ id, tenant_id: tenantId })
            .forUpdate()
            .first<SiteRow | undefined>();
          if (!current) return undefined;
          if (data.code !== undefined && current.code !== data.code) {
            const bindings = await readSiteBindings(trx, tenantId, id);
            if (siteCodeLockReasons(bindings).length > 0) {
              throw new AppError(409, codeLockedMessage(current.code, bindings));
            }
            await assertSiteCodeFormat(trx, tenantId, data.code as string, { renamingSiteId: id });
          }
          const write: UpdateSiteData = { ...data };
          delete write.uplinkKindSetBy;
          if (declares) {
            if ((current.uplink_kind ?? null) === (data.uplinkKind ?? null)) {
              delete write.uplinkKind;
            } else {
              write.uplinkKindSetBy = opts.actor?.userId ?? null;
              declared.value = { before: current.uplink_kind ?? null, after: data.uplinkKind ?? null };
            }
          }
          const updated = await updateSiteRow(trx, tenantId, id, write);
          if (updated && declared.value) {
            await appendAudit(
              uplinkAuditEntry(
                tenantId,
                opts.actor,
                id,
                { uplinkKind: declared.value.before },
                { uplinkKind: declared.value.after, via: 'site_form', siteCode: current.code },
              ),
              trx,
            );
          }
          return updated;
        })
      : await updateSiteRow(db, tenantId, id, data);
  if (row) emitToTenantAudience(tenantId, SOCKET_EVENTS.SITE_UPDATED, { site: toSiteDto(row) }, { siteId: row.id });
  if (row && declared.value?.after === 'cellular_only') {
    // After the commit, and never undoing it: the next health check would
    // close the alert anyway (decideBackup4g reads the declaration first).
    await closeBackup4gForSites(tenantId, [id]).catch((err: unknown) =>
      logger.warn({ err, tenantId, siteId: id }, 'Site declared 4G-only: its open backup alerts stay until the next check'),
    );
  }
  return row;
}

export interface SiteUplinkBulkResult {
  uplinkKind: SiteUplinkKind | null;
  /** Ids sent. */
  requested: number;
  /** Sites whose declaration changed (and were stamped and audited). */
  changed: number;
  /** Sites that already carried this declaration: untouched, "who and when" kept. */
  unchanged: number;
  changedSiteIds: number[];
  /** Open 4G backup alerts closed because their site is now 4G-only. */
  backupAlertsClosed: number;
}

/**
 * One access-link declaration for many sites — a whole customer in one
 * gesture (`POST /sites/bulk/uplink-kind`).
 *
 * ALL OR NOTHING ON TENANCY: every id must be a site of `tenantId`, read under
 * row locks inside the transaction, or the request is refused with nothing
 * written (404, like a single site of another tenant — and without saying
 * which ids, which the caller sent anyway). No partial cross-tenant write can
 * exist: the UPDATE is scoped by tenant AND by the ids just verified.
 *
 * A site already carrying the value is left alone (its stamp is the
 * declaration that made it so). The changed sites are stamped and the request
 * is written to `audit_log` (one entry: the value, the counts, the previous
 * declarations, the ids) in the same transaction — if the ledger write
 * fails, nothing is declared. Declaring 4G-only closes the open backup alerts
 * of the routers of those sites after the commit.
 */
export async function bulkSetSiteUplinkKind(
  tenantId: number,
  ids: readonly number[],
  kind: SiteUplinkKind | null,
  actor?: SiteActor,
): Promise<SiteUplinkBulkResult> {
  const unique = [...new Set(ids.map(Number))];
  if (unique.length === 0) throw new AppError(400, 'Aucun site sélectionné.');
  const done = await db.transaction(async (trx) => {
    const rows = (await trx('sites')
      .where('tenant_id', tenantId)
      .whereIn('id', unique)
      .forUpdate()
      .select('id', 'uplink_kind')) as Array<{ id: number; uplink_kind: SiteUplinkKind | null }>;
    if (rows.length !== unique.length) {
      throw new AppError(
        404,
        `${unique.length - rows.length} des ${unique.length} site(s) demandés ne sont pas des sites de cet espace ` +
          '(ou n’existent plus) : aucun site n’a été modifié.',
      );
    }
    const toChange = rows.filter((r) => (r.uplink_kind ?? null) !== kind);
    const previous: Record<'auto' | SiteUplinkKind, number> = { auto: 0, fixed: 0, cellular_only: 0 };
    for (const r of toChange) previous[r.uplink_kind ?? 'auto'] += 1;
    let updated: SiteRow[] = [];
    if (toChange.length > 0) {
      updated = (await trx('sites')
        .where('tenant_id', tenantId)
        .whereIn('id', toChange.map((r) => r.id))
        .update({
          uplink_kind: kind,
          uplink_kind_set_at: new Date(),
          uplink_kind_set_by: actor?.userId ?? null,
          updated_at: db.fn.now(),
        })
        .returning('*')) as SiteRow[];
      await appendAudit(
        uplinkAuditEntry(
          tenantId,
          actor,
          null,
          { previous },
          {
            uplinkKind: kind,
            via: 'bulk',
            requested: unique.length,
            changed: updated.length,
            unchanged: rows.length - updated.length,
            siteIds: updated.map((r) => r.id).sort((a, b) => a - b),
          },
        ),
        trx,
      );
    }
    return { updated, unchanged: rows.length - toChange.length };
  });
  for (const r of done.updated) emitToTenantAudience(tenantId, SOCKET_EVENTS.SITE_UPDATED, { site: toSiteDto(r) }, { siteId: r.id });
  const changedSiteIds = done.updated.map((r) => r.id).sort((a, b) => a - b);
  let backupAlertsClosed = 0;
  if (kind === 'cellular_only' && changedSiteIds.length > 0) {
    backupAlertsClosed = await closeBackup4gForSites(tenantId, changedSiteIds).catch((err: unknown) => {
      logger.warn({ err, tenantId }, 'Sites declared 4G-only: their open backup alerts stay until the next check');
      return 0;
    });
  }
  return {
    uplinkKind: kind,
    requested: unique.length,
    changed: changedSiteIds.length,
    unchanged: done.unchanged,
    changedSiteIds,
    backupAlertsClosed,
  };
}

export interface SiteFixedProviderBulkResult {
  fixedProvider: string | null;
  requested: number;
  changed: number;
  unchanged: number;
  changedSiteIds: number[];
}

/**
 * « Opérateur du lien fixe » (migration 095) for many sites at once — a whole
 * customer whose stores share one access provider. Same rules as the bulk
 * access-link declaration: every id must be a site of `tenantId` (read under
 * row locks) or NOTHING is written (404); a site already carrying the value is
 * left alone; the request is written to `audit_log` in the same transaction.
 * `provider` is already normalised (shared `normalizeFixedProvider`); null =
 * back to "not declared" (the provider is then inferred).
 */
export async function bulkSetSiteFixedProvider(
  tenantId: number,
  ids: readonly number[],
  provider: string | null,
  actor?: SiteActor,
): Promise<SiteFixedProviderBulkResult> {
  const unique = [...new Set(ids.map(Number))];
  if (unique.length === 0) throw new AppError(400, 'Aucun site sélectionné.');
  const done = await db.transaction(async (trx) => {
    const rows = (await trx('sites')
      .where('tenant_id', tenantId)
      .whereIn('id', unique)
      .forUpdate()
      .select('id', 'fixed_provider')) as Array<{ id: number; fixed_provider: string | null }>;
    if (rows.length !== unique.length) {
      throw new AppError(
        404,
        `${unique.length - rows.length} des ${unique.length} site(s) demandés ne sont pas des sites de cet espace ` +
          '(ou n’existent plus) : aucun site n’a été modifié.',
      );
    }
    const toChange = rows.filter((r) => (r.fixed_provider ?? null) !== provider);
    let updated: SiteRow[] = [];
    if (toChange.length > 0) {
      updated = (await trx('sites')
        .where('tenant_id', tenantId)
        .whereIn('id', toChange.map((r) => r.id))
        .update({ fixed_provider: provider, updated_at: db.fn.now() })
        .returning('*')) as SiteRow[];
      await appendAudit(
        {
          tenantId,
          actorType: 'user' as const,
          actorId: actor?.userId ?? null,
          actorName: actor?.username ? actor.username.slice(0, 128) : null,
          action: 'site.fixed_provider_set',
          entityType: 'site',
          entityId: null,
          before: { previous: [...new Set(toChange.map((r) => r.fixed_provider ?? null))].slice(0, 20) },
          after: {
            fixedProvider: provider,
            via: 'bulk',
            requested: unique.length,
            changed: updated.length,
            unchanged: rows.length - updated.length,
            siteIds: updated.map((r) => r.id).sort((a, b) => a - b),
          },
        },
        trx,
      );
    }
    return { updated, unchanged: rows.length - toChange.length };
  });
  for (const r of done.updated) emitToTenantAudience(tenantId, SOCKET_EVENTS.SITE_UPDATED, { site: toSiteDto(r) }, { siteId: r.id });
  const changedSiteIds = done.updated.map((r) => r.id).sort((a, b) => a - b);
  return {
    fixedProvider: provider,
    requested: unique.length,
    changed: changedSiteIds.length,
    unchanged: done.unchanged,
    changedSiteIds,
  };
}

export interface SiteDeleteOptions {
  /** What the caller acknowledges will remain (validators/site.schema.ts
   *  `SITE_DELETE_ACKNOWLEDGEMENTS`). Absent = nothing acknowledged. */
  acknowledge?: readonly SiteDeleteAcknowledgement[];
  /** Who deletes, for `audit_log`. Absent = recorded as a user who is not
   *  named (the only caller is the HTTP route, i.e. a user). */
  actor?: { userId: number | null; username: string | null };
}

export interface SiteDeleteReport extends SiteDeleteImpact {
  siteId: number;
  code: string;
  name: string;
}

/**
 * Delete a site. What goes with it, and what does not:
 *   - its SITE-level template variables (config_variables scope 'site'): they
 *     carry no foreign key, so without this they would outlive the site and
 *     land on whatever row reuses nothing — dead values, secrets included;
 *   - its allocation (site_provisioning, ON DELETE CASCADE): ObliWAN stops
 *     holding the login, the tunnel address and the LAN;
 *   - its SLA objectives and SLA reports (migration 026, ON DELETE CASCADE);
 *   - the records of its concentrator jobs (concentrator_secret_jobs, 040,
 *     ON DELETE CASCADE) — the durable link between the site and the logins
 *     ObliWAN wrote on the concentrator, which is why `audit_log` gets a copy
 *     of those logins below;
 *   - its devices stay, detached (devices.site_id ON DELETE SET NULL), and so
 *     do its SIM lines (032), its intents (016) and its weather history (021),
 *     all SET NULL;
 *   - its bench preparations stay as history, detached, with a copy of the
 *     site's code and name (migration 056).
 * No foreign key to `sites` is RESTRICT: nothing in the database refuses the
 * delete, which is why the refusals below are the service's.
 *
 * REFUSED (409) unless the caller names, in `opts.acknowledge`, each thing
 * that will remain outside ObliWAN's hold or be lost:
 *   - `chr_account`: the site's L2TP account is, or may be, on the
 *     concentrator (`chrAccountKept`): the allocation is provisioned there or
 *     was adopted from it, a claimed job may be adding it right now, or an
 *     earlier job added or found it or lost the answer to its add. The account
 *     stays there — ObliWAN never removes one (writes to the CHR are additive
 *     only), and `releaseAllocation` refuses to release a provisioned
 *     allocation for that very reason. While that concentrator gates the
 *     tunnel pool, the allocator still sees the address of an account it has
 *     READ as taken, through its secret inventory (allocator.ts, "SEEDED FROM
 *     THE CONCENTRATORS"); an account a running job creates after its last
 *     read is not in that inventory until the next one;
 *   - `bench_history`: bench preparations exist;
 *   - `sla_history`: SLA reports exist, and are deleted with the site.
 * The judgement is made inside the delete's transaction, under the allocation
 * lock, a row lock on the site and row locks on the site's concentrator jobs
 * still in flight (`readSiteBindings`, `lockAccountJobs`), so what was
 * acknowledged is what is there.
 *
 * Who may do this is the route's business (DEVICE_WRITE today). It is NOT the
 * allocation module's gate: releasing a provisioned allocation there takes a
 * platform administrator who types the login (allocation.controller
 * `releaseProvisioned`). Every delete is written to `audit_log`
 * ('site.deleted') inside the same transaction, with the allocation, the
 * account kept and the logins this site's jobs added on the concentrator: if
 * the ledger write fails, the site stays.
 *
 * Returns what happened (null = no such site in this tenant).
 */
export async function deleteSite(
  tenantId: number,
  id: number,
  opts: SiteDeleteOptions = {},
): Promise<SiteDeleteReport | null> {
  const acknowledged = new Set<SiteDeleteAcknowledgement>(opts.acknowledge ?? []);
  let report: SiteDeleteReport | null = null;
  try {
    report = await db.transaction<SiteDeleteReport | null>(async (trx) => {
      // Same lock order as the rename (updateSite).
      await takeAllocationLock(trx);
      const site = await trx('sites')
        .where({ id, tenant_id: tenantId })
        .forUpdate()
        .first<SiteRow | undefined>();
      if (!site) return null;
      const impact = siteDeleteImpact(await readSiteBindings(trx, tenantId, id, { lockAccountJobs: true }));
      const missing = impact.acknowledge.filter((k) => !acknowledged.has(k));
      if (missing.length > 0) throw new AppError(409, deleteRefusalMessage(site, impact, missing));

      // Read before the cascade erases them: every login a job of this site
      // ADDED on a concentrator, whatever allocation it belonged to.
      const added = (await trx('concentrator_secret_jobs')
        .where({ site_id: id, tenant_id: tenantId, outcome: 'added' })
        .distinct('ppp_username', 'remote_address')) as Array<{
        ppp_username: string;
        remote_address: string;
      }>;
      const a = impact.allocationReleased;
      await appendAudit(
        {
          tenantId,
          actorType: 'user',
          actorId: opts.actor?.userId ?? null,
          actorName: opts.actor?.username ? opts.actor.username.slice(0, 128) : null,
          action: 'site.deleted',
          entityType: 'site',
          entityId: id,
          before: {
            code: site.code,
            name: site.name,
            country: site.country,
            allocation: a
              ? {
                  pppUsername: a.pppUsername,
                  tunnelIp: a.tunnelIp,
                  lanSubnet: a.lanSubnet,
                  concentratorId: a.concentratorId,
                  concentratorState: a.concentratorState,
                  source: a.source,
                }
              : null,
            chrAccountKept: impact.chrAccountKept,
            // remote_address is a /32 (040's CHECK), which inet prints bare.
            accountsAddedOnConcentrator: added.map((r) => ({ pppUsername: r.ppp_username, tunnelIp: String(r.remote_address) })),
            devicesDetached: impact.devicesDetached,
            benchHistoryKept: impact.benchHistoryKept,
            slaReportsDeleted: impact.slaReportsDeleted,
            slaObjectivesDeleted: impact.slaObjectivesDeleted,
          },
          after: { acknowledged: [...acknowledged] },
        },
        trx,
      );

      await trx('config_variables').where({ tenant_id: tenantId, scope: 'site', scope_id: id }).delete();
      await trx('sites').where({ id, tenant_id: tenantId }).delete();
      return { siteId: id, code: site.code, name: site.name, ...impact };
    });
  } catch (err) {
    // No foreign key to `sites` refuses a delete today (see above); this
    // keeps a RESTRICT added later from reaching the caller as a bare 500.
    const pg = err as { code?: string; detail?: string };
    if (pg.code === '23503') {
      const table = /referenced from table "([^"]+)"/.exec(pg.detail ?? '')?.[1] ?? 'another table';
      throw new AppError(
        409,
        `This site is still referenced by "${table}": detach those rows first, then delete the site.`,
      );
    }
    throw err;
  }
  if (report) {
    emitToTenant(tenantId, SOCKET_EVENTS.SITE_DELETED, { siteId: id });
    if (report.chrAccountKept || report.benchHistoryKept > 0 || report.slaReportsDeleted > 0) {
      logger.info(
        {
          tenantId,
          siteId: id,
          siteCode: report.code,
          chrAccountKept: report.chrAccountKept?.pppUsername ?? null,
          chrAccountBasis: report.chrAccountKept?.basis ?? null,
          benchHistoryKept: report.benchHistoryKept,
          slaReportsDeleted: report.slaReportsDeleted,
        },
        'Site deleted with acknowledged consequences: its concentrator account (untouched), its bench history (kept, detached) and/or its SLA reports (deleted)',
      );
    }
  }
  return report;
}

export interface SitePresenceRow {
  deviceId: number;
  name: string;
  pppUsername: string | null;
  up: boolean;
  since: string | null;
  tunnelIp: string | null;
  verdict: string | null;
  verdictAt: string | null;
}

/**
 * Presence of every device on a site, with its latest reachability verdict.
 *
 * The verdict is joined in rather than recomputed: `reachability_verdicts` is a
 * change log, so the latest row IS the current verdict, and re-deriving it here
 * would be a second implementation of the truth table waiting to disagree with
 * the first.
 */
export async function sitePresence(tenantId: number, siteId: number): Promise<SitePresenceRow[]> {
  const rows = await db('devices as d')
    .where({ 'd.tenant_id': tenantId, 'd.site_id': siteId })
    .leftJoin('ppp_sessions as p', function joinOpen(this: any) {
      this.on('p.device_id', '=', 'd.id').andOnNull('p.ended_at');
    })
    .leftJoin(
      db('reachability_verdicts')
        .distinctOn('device_id')
        .select('device_id', 'verdict', 'ts')
        .orderBy('device_id')
        .orderBy('ts', 'desc')
        .as('v'),
      'v.device_id',
      'd.id',
    )
    .select<
      Array<{
        id: number;
        name: string;
        ppp_username: string | null;
        started_at: Date | null;
        tunnel_ip: string | null;
        verdict: string | null;
        ts: Date | null;
      }>
    >('d.id', 'd.name', 'd.ppp_username', 'p.started_at', 'p.tunnel_ip', 'v.verdict', 'v.ts')
    .orderBy('d.name');

  return rows.map((r) => ({
    deviceId: r.id,
    name: r.name,
    pppUsername: r.ppp_username,
    up: r.started_at !== null,
    since: r.started_at ? r.started_at.toISOString() : null,
    tunnelIp: r.tunnel_ip,
    verdict: r.verdict,
    verdictAt: r.ts ? r.ts.toISOString() : null,
  }));
}

// ============================================================================
// PPP timeline
// ============================================================================

export interface SitePppSessionDto {
  id: string;
  concentratorId: number;
  deviceId: number | null;
  deviceName: string | null;
  pppUsername: string;
  tunnelIp: string | null;
  callerIp: string | null;
  startedAt: string;
  /** null = the session is still open. */
  endedAt: string | null;
  durationSeconds: number | null;
  disconnectReason: string | null;
}

/**
 * The site's PPP chronology: every session, open or closed, of
 * every device currently filed under this site.
 *
 * Scoping goes through `devices`, which carries the tenant — `ppp_sessions`
 * does not, because a session is observed on the concentrator before anybody
 * has decided whose it is. The JOIN is therefore the access check, not a
 * convenience: no device row in this tenant, no session row out.
 *
 * A site with no session yet returns `[]`, and that is a real answer meaning
 * "nothing has ever dialled". The client distinguishes it from `null` ("the
 * endpoint does not exist"), which is why this route exists at all rather than
 * leaving the page to guess.
 */
export async function sitePppSessions(
  tenantId: number,
  siteId: number,
  limit = 100,
): Promise<SitePppSessionDto[]> {
  const rows = await db('ppp_sessions as p')
    .join('devices as d', 'd.id', 'p.device_id')
    .where({ 'd.tenant_id': tenantId, 'd.site_id': siteId })
    .orderBy('p.started_at', 'desc')
    .limit(limit)
    .select<
      Array<{
        id: string;
        concentrator_id: number;
        device_id: number | null;
        device_name: string;
        ppp_username: string;
        tunnel_ip: string | null;
        caller_ip: string | null;
        started_at: Date;
        ended_at: Date | null;
        duration_seconds: number | null;
        disconnect_reason: string | null;
      }>
    >(
      'p.id',
      'p.concentrator_id',
      'p.device_id',
      'd.name as device_name',
      'p.ppp_username',
      'p.tunnel_ip',
      'p.caller_ip',
      'p.started_at',
      'p.ended_at',
      'p.duration_seconds',
      'p.disconnect_reason',
    );

  return rows.map((r) => ({
    id: String(r.id),
    concentratorId: r.concentrator_id,
    deviceId: r.device_id,
    deviceName: r.device_name,
    pppUsername: r.ppp_username,
    tunnelIp: r.tunnel_ip,
    callerIp: r.caller_ip,
    startedAt: r.started_at.toISOString(),
    endedAt: r.ended_at ? r.ended_at.toISOString() : null,
    durationSeconds: r.duration_seconds,
    disconnectReason: r.disconnect_reason,
  }));
}
