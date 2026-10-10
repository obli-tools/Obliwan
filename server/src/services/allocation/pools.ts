import { INSTANCE_SETTINGS_KEYS, instanceDomainError } from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { loadPools, readInstanceDomain, readSeedStatus, type SeedStatus } from './allocator';
import { AllocationError, assertId, isPgError } from './errors';
import { takeAllocationLock } from './lock';
import {
  PG_INT_MAX,
  formatCidr,
  poolOverlapConflict,
  validatePoolInput,
  validatePoolName,
  type AddressMode,
  type PoolPurpose,
} from './policy';
import { PPP_LOGIN_MAX, minimalLoginLength, parseLoginTemplate } from './pppIdentity';

/**
 * pools.ts — address pools, the installation domain, and seed status.
 *
 * ┌─ A POOL IS A NAMED BLOCK, SHARED BY REFERENCE ───────────────────────────┐
 * │ `address_pools(id, name, cidr, purpose)`. A tenant policy points its      │
 * │ tunnel rule at a 'tunnel' pool and its optional LAN rule at a 'lan' pool  │
 * │ (a composite FK makes the wrong purpose unrepresentable). Several small   │
 * │ tenants share one pool by pointing at the same row — e.g. one incremental │
 * │ /24 for every customer with fewer than ten routers — and then share its   │
 * │ space: no address or block is handed out twice from it.                  │
 * │                                                                          │
 * │ A TUNNEL pool overlaps no other pool, whatever its purpose: a tunnel /32  │
 * │ inside another pool would be one address with two owners. Migration 036  │
 * │ holds tunnel-against-tunnel with an exclusion constraint; tunnel-against- │
 * │ LAN is `poolOverlapConflict`, checked by `createPool` under the          │
 * │ allocation lock. A LAN pool MAY overlap another LAN pool: that is how two │
 * │ tenants reuse one LAN plan, each with its own pool over the same block   │
 * │ (policy.ts, UNIQUENESS) — an explicit gesture, since sharing ONE pool    │
 * │ gives disjoint blocks instead.                                           │
 * │                                                                          │
 * │ A pool's block and purpose never change once created: sites already hold │
 * │ addresses from it, and a moved block would strand them outside it. Only  │
 * │ the name changes. A pool a policy still names cannot be deleted, nor a   │
 * │ LAN pool some allocation drew a subnet from (both FK RESTRICT): that     │
 * │ link is what keeps the pool's other tenants off the block. Deleting a    │
 * │ tunnel pool leaves the addresses handed out from it untouched — tunnel   │
 * │ addresses are unique installation-wide, pool or no pool.                 │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

export interface AddressPoolView {
  id: number;
  name: string;
  cidr: string;
  purpose: PoolPurpose;
  /** Sites holding a tunnel address inside its block (tunnel pool — tunnel
   *  addresses are global), or a subnet drawn FROM it (LAN pool — an
   *  overlapping LAN pool's subnets are not counted here). */
  allocated: number;
  /** The tenant policies that point at it, and how. */
  policies: Array<{ tenantId: number; mode: AddressMode }>;
  createdAt: string;
  updatedAt: string;
}

interface PoolRow {
  id: number;
  name: string;
  cidr: string;
  purpose: PoolPurpose;
  created_at: Date;
  updated_at: Date;
}

function iso(d: Date | string): string {
  return d instanceof Date ? d.toISOString() : new Date(d).toISOString();
}

async function poolViews(filterId?: number): Promise<AddressPoolView[]> {
  const q = db('address_pools').select('id', 'name', 'cidr', 'purpose', 'created_at', 'updated_at');
  if (filterId !== undefined) q.where({ id: filterId });
  const rows = (await q.orderBy([{ column: 'purpose' }, { column: 'name' }])) as PoolRow[];
  if (rows.length === 0) return [];

  const policies = (await db('tenant_allocation_policies').select(
    'tenant_id',
    'tunnel_pool_id',
    'tunnel_mode',
    'lan_pool_id',
    'lan_mode',
  )) as Array<{
    tenant_id: number;
    tunnel_pool_id: number;
    tunnel_mode: AddressMode;
    lan_pool_id: number | null;
    lan_mode: AddressMode | null;
  }>;

  const out: AddressPoolView[] = [];
  for (const row of rows) {
    const counted = db('site_provisioning');
    if (row.purpose === 'tunnel') counted.whereRaw('tunnel_ip <<= CAST(? AS cidr)', [row.cidr]);
    else counted.where({ lan_pool_id: row.id });
    const [{ count }] = (await counted.count({ count: '*' })) as Array<{ count: string | number }>;
    out.push({
      id: row.id,
      name: row.name,
      cidr: row.cidr,
      purpose: row.purpose,
      allocated: Number(count),
      policies: policies.flatMap((p) => {
        if (p.tunnel_pool_id === row.id) return [{ tenantId: p.tenant_id, mode: p.tunnel_mode }];
        if (p.lan_pool_id === row.id && p.lan_mode !== null) return [{ tenantId: p.tenant_id, mode: p.lan_mode }];
        return [];
      }),
      createdAt: iso(row.created_at),
      updatedAt: iso(row.updated_at),
    });
  }
  return out;
}

export async function listPools(): Promise<AddressPoolView[]> {
  return poolViews();
}

export async function getPool(poolId: number): Promise<AddressPoolView | null> {
  assertId(poolId, 'poolId', PG_INT_MAX);
  const [view] = await poolViews(poolId);
  return view ?? null;
}

function poolNotFound(poolId: number): AllocationError {
  return new AllocationError('POOL_NOT_FOUND', `address pool ${poolId} does not exist.`);
}

/**
 * POST body `{ name, cidr, purpose }`. Under the allocation lock: the
 * tunnel-against-LAN overlap rule is this function's, not a constraint's
 * (header), so two pools created at once must not both pass it.
 */
export async function createPool(input: unknown): Promise<AddressPoolView> {
  const v = validatePoolInput(input);
  if (!v.ok) {
    throw new AllocationError('INVALID_POOL', 'the address pool is invalid; correct the listed fields.', v.errors);
  }
  const cidr = formatCidr(v.pool.cidr);

  let id: number;
  try {
    id = await db.transaction(async (trx) => {
      await takeAllocationLock(trx);
      const clash = poolOverlapConflict(v.pool, (await loadPools(trx)).values());
      if (clash) {
        const clashCidr = formatCidr(clash.cidr);
        throw new AllocationError(
          'POOL_OVERLAP',
          `pool ${cidr} overlaps ${clash.purpose} pool "${clash.name}" (${clashCidr}).`,
          {
            cidr: [
              `overlaps ${clash.purpose} pool "${clash.name}" (${clashCidr}). A tunnel pool overlaps no ` +
                'other pool, and a LAN pool no tunnel pool. To share addresses between tenants, point ' +
                'their policies at the same pool.',
            ],
          },
        );
      }
      const [row] = (await trx('address_pools')
        .insert({ name: v.pool.name, cidr, purpose: v.pool.purpose })
        .returning('id')) as Array<{ id: number }>;
      return row.id;
    });
  } catch (err) {
    // Unreachable through this function while every pool is created under the
    // lock; a pool inserted around it can still trip the constraint.
    if (isPgError(err, '23P01')) {
      throw new AllocationError('POOL_OVERLAP', `pool ${cidr} overlaps a tunnel pool created at the same moment.`, {
        cidr: ['overlaps another tunnel pool; reload the list and pick a free block.'],
      });
    }
    if (isPgError(err, '23505')) {
      throw new AllocationError('POOL_NAME_TAKEN', `a pool named "${v.pool.name}" already exists.`, {
        name: ['already used by another pool (names are compared without regard to case).'],
      });
    }
    // Reachable through this function: migration 053's trigger refuses a pool
    // of any purpose over the /30 transit of an ObliWAN link to a concentrator
    // (concentratorLink/link.service.ts), and the overlap check above does not
    // know about link transits.
    if (
      isPgError(err, '23514') &&
      (err as { constraint?: string }).constraint === 'concentrator_link_transit_reserved'
    ) {
      throw new AllocationError(
        'POOL_OVERLAP',
        `pool ${cidr} overlaps the WireGuard transit reserved for the ObliWAN link to a concentrator.`,
        {
          cidr: [
            'overlaps the /30 transit reserved for the ObliWAN link (inside 100.64.0.0/10); pick a block outside it.',
          ],
        },
      );
    }
    throw err;
  }
  logger.info({ poolId: id, cidr, purpose: v.pool.purpose }, 'Address pool created');
  const view = await getPool(id);
  if (!view) throw new Error(`address pool ${id} vanished after being created`);
  return view;
}

/** PATCH body `{ name }`. A pool's block and purpose are immutable (header). */
export async function renamePool(poolId: number, input: unknown): Promise<AddressPoolView> {
  assertId(poolId, 'poolId', PG_INT_MAX);
  const body = typeof input === 'object' && input !== null ? (input as Record<string, unknown>) : {};
  if ('cidr' in body || 'purpose' in body) {
    throw new AllocationError(
      'INVALID_POOL',
      "a pool's block and purpose cannot change: sites already hold addresses from it. Create a " +
        'new pool and point the tenant policies at it instead.',
      { ...('cidr' in body ? { cidr: ['immutable'] } : {}), ...('purpose' in body ? { purpose: ['immutable'] } : {}) },
    );
  }
  const name = validatePoolName(body.name);
  if (!name.ok) throw new AllocationError('INVALID_POOL', name.error, { name: [name.error] });
  try {
    const updated = await db('address_pools')
      .where({ id: poolId })
      .update({ name: name.name, updated_at: db.fn.now() });
    if (updated === 0) throw poolNotFound(poolId);
  } catch (err) {
    if (isPgError(err, '23505')) {
      throw new AllocationError('POOL_NAME_TAKEN', `a pool named "${name.name}" already exists.`, {
        name: ['already used by another pool (names are compared without regard to case).'],
      });
    }
    throw err;
  }
  const view = await getPool(poolId);
  if (!view) throw poolNotFound(poolId);
  return view;
}

export async function deletePool(poolId: number): Promise<void> {
  assertId(poolId, 'poolId', PG_INT_MAX);
  try {
    const deleted = await db('address_pools').where({ id: poolId }).delete();
    if (deleted === 0) throw poolNotFound(poolId);
  } catch (err) {
    if (isPgError(err, '23503')) {
      // Two FKs can refuse: name the one that did, with the gesture that
      // clears it.
      const [{ count }] = (await db('site_provisioning')
        .where({ lan_pool_id: poolId })
        .count({ count: '*' })) as Array<{ count: string | number }>;
      const held = Number(count);
      throw new AllocationError(
        'POOL_IN_USE',
        held > 0
          ? `address pool ${poolId}: ${held} site allocation(s) hold a LAN subnet drawn from it, and ` +
              "deleting it would let the pool's other tenants be handed those blocks. Release those " +
              'allocations (DELETE /api/allocation/sites/:siteId) or delete their sites first.'
          : `address pool ${poolId} is named by a tenant allocation policy. Point that policy at ` +
              'another pool first, then delete this one.',
      );
    }
    throw err;
  }
  logger.info({ poolId }, 'Address pool deleted');
}

// ============================================================================
// Installation domain — {instance.domain}
// ============================================================================

export async function getInstanceDomain(): Promise<string> {
  return readInstanceDomain(db);
}

/**
 * The refusal for a generic instance-variable write (set, bulk set or remove)
 * of a key this module owns, null for any other key. `instance_domain` is
 * written only by `setInstanceDomain`, whose DOMAIN_IN_USE / DOMAIN_TOO_LONG
 * guards a plain variables write would skip — leaving every tenant whose
 * template uses {instance.domain} unable to allocate.
 */
export function allocationOwnedInstanceKey(key: string): string | null {
  if (key.trim().toLowerCase() !== INSTANCE_SETTINGS_KEYS.INSTANCE_DOMAIN.toLowerCase()) return null;
  return (
    `"${INSTANCE_SETTINGS_KEYS.INSTANCE_DOMAIN}" is the installation domain of the address allocation; ` +
    'set or clear it on the allocation page (PUT /api/allocation/instance-domain), which checks it ' +
    'against every login and identity template.'
  );
}

/**
 * Set the installation domain (the INSTANCE variable INSTANCE_SETTINGS_KEYS.
 * INSTANCE_DOMAIN in config_variables, since migration 039). Case is kept as
 * written. Refused, so that the bench never has to say it instead:
 *   - clearing it while a tenant's login or identity template still uses
 *     {instance.domain} (DOMAIN_IN_USE);
 *   - a value with which some template using it could not render even its
 *     SHORTEST value — a one-character site, no country — within
 *     PPP_LOGIN_MAX (DOMAIN_TOO_LONG): every allocation of that tenant would
 *     be refused, with a message about a site name that is not the problem.
 *
 * These guards hold only for writes that come through here: the generic
 * instance-variable routes (variables.controller) must refuse this key —
 * `allocationOwnedInstanceKey` gives them the refusal.
 *
 * Changing it renames nothing: logins already allocated are facts, and the new
 * value applies to the next allocation only.
 */
export async function setInstanceDomain(raw: unknown): Promise<string> {
  if (typeof raw !== 'string') {
    throw new AllocationError('INVALID_DOMAIN', 'domain must be a string ("" to clear it).', {
      domain: ['must be a string'],
    });
  }
  const value = raw.trim();
  const err = instanceDomainError(value);
  if (err !== null) throw new AllocationError('INVALID_DOMAIN', `invalid domain: ${err}.`, { domain: [err] });

  await db.transaction(async (trx) => {
    await takeAllocationLock(trx);
    // Both templates of a policy may use {instance.domain}: the PPP login and
    // (migration 039) the system identity.
    const rows = (await trx('tenant_allocation_policies as p')
      .join('tenants as t', 't.id', 'p.tenant_id')
      .select('p.tenant_id', 'p.ppp_login_template', 'p.identity_template', 't.slug')) as Array<{
      tenant_id: number;
      ppp_login_template: string;
      identity_template: string | null;
      slug: string;
    }>;
    const users = rows
      .flatMap((r) => [
        { tenant_id: r.tenant_id, slug: r.slug, which: 'login', template: r.ppp_login_template },
        { tenant_id: r.tenant_id, slug: r.slug, which: 'identity', template: r.identity_template ?? '' },
      ])
      .filter((u) => u.template.includes('{instance.domain}'));
    if (value === '' && users.length > 0) {
      throw new AllocationError(
        'DOMAIN_IN_USE',
        `${users.length} tenant template(s) use {instance.domain}; change those ` +
          'templates before clearing the domain.',
        { domain: users.map((u) => `used by the ${u.which} template of tenant ${u.tenant_id}`) },
      );
    }
    const tooLong: string[] = [];
    for (const u of users) {
      // A stored template that no longer parses is the allocator's to refuse
      // (INVALID_POLICY); it says nothing about this domain.
      const t = parseLoginTemplate(u.template);
      if (!t.ok) continue;
      const shortest = minimalLoginLength(t.template, { tenantSlug: u.slug, instanceDomain: value });
      if (shortest > PPP_LOGIN_MAX) {
        tooLong.push(
          `the ${u.which} template of tenant ${u.tenant_id} would render at least ${shortest} characters ` +
            `(limit ${PPP_LOGIN_MAX})`,
        );
      }
    }
    if (tooLong.length > 0) {
      throw new AllocationError(
        'DOMAIN_TOO_LONG',
        `with this domain, ${tooLong.length} tenant template(s) could not fit a single site's ` +
          `login or identity within ${PPP_LOGIN_MAX} characters. Choose a shorter domain, or shorten those templates ` +
          '(PUT /api/allocation/tenants/:tenantId/policy) first.',
        { domain: tooLong },
      );
    }
    // Stored as the INSTANCE variable of the same key (migration 039), which is
    // what {instance.domain} reads. Cleared = no row.
    const key = INSTANCE_SETTINGS_KEYS.INSTANCE_DOMAIN;
    const scope = { scope: 'instance', key };
    const existing = await trx('config_variables').whereNull('tenant_id').where(scope).first('id');
    if (value === '') {
      await trx('config_variables').whereNull('tenant_id').where(scope).del();
    } else if (existing) {
      await trx('config_variables')
        .where({ id: (existing as { id: number }).id })
        .update({ value: JSON.stringify(value), is_secret: false, secret_enc: null, updated_at: trx.fn.now() });
    } else {
      await trx('config_variables').insert({
        tenant_id: null,
        scope_id: null,
        ...scope,
        value: JSON.stringify(value),
        is_secret: false,
        secret_enc: null,
        description: 'Installation domain, spliced into allocation templates by {instance.domain}.',
      });
    }
  });
  logger.info({ domain: value }, 'Installation domain saved');
  return value;
}

// ============================================================================
// Seed status
// ============================================================================

/** Whether a concentrator's /ppp/secret has been read, when, and whether that
 *  read is fresh enough for an allocation to rest on it. A device id that does
 *  not exist is CONCENTRATOR_NOT_FOUND (404); a device that exists and is not
 *  a concentrator is CONCENTRATOR_INVALID (400). Reads only — it never dials
 *  the CHR. */
export async function getSeedStatus(concentratorId: number): Promise<SeedStatus> {
  assertId(concentratorId, 'concentratorId', PG_INT_MAX);
  const chr = (await db('devices').where({ id: concentratorId }).first('role')) as { role: string } | undefined;
  if (!chr) {
    throw new AllocationError('CONCENTRATOR_NOT_FOUND', `device ${concentratorId} does not exist.`);
  }
  if (chr.role !== 'concentrator') {
    throw new AllocationError('CONCENTRATOR_INVALID', `device ${concentratorId} is not a concentrator.`);
  }
  return readSeedStatus(db, concentratorId, Date.now());
}
