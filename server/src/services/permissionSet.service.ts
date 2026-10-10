import { db } from '../db';
import {
  CAPABILITY_CATALOG,
  CAPABILITY_IMPLIES,
  EXPLICIT_ONLY_CAPABILITIES,
  BUILTIN_TENANT_ROLES,
  RESERVED_ROLE_SLUGS,
  ROLE_PERMISSION_SETS,
  MASTER_TENANT_ID,
  expandCapabilities,
  isBuiltinTenantRole,
  isCapability,
  isRoleSlugSyntax,
  setLockReason,
} from '@obliwan/shared';
import type { Capability, CapabilityInfo, PermissionSet } from '@obliwan/shared';
import { appendAudit } from './attestation/auditLog.service';

/**
 * The permission-set matrix — AUTHORITATIVE since migration 084.
 *
 * A set is a tenant role (`user_tenants.role` is its slug, by foreign key) and
 * the runtime grants what its row lists (permission.service). Sets are GLOBAL,
 * shared by every tenant like Obliance's: a tick on `user` is a grant to every
 * `user` of every customer at their next request. Hence:
 *  - every write is platform-admin (routes) and AUDITED, before/after, in the
 *    master tenant's ledger;
 *  - PLATFORM_ONLY and BY_NAME_ONLY capabilities are REFUSED by name (400),
 *    never silently dropped — a silent drop would show the operator a tick the
 *    server does not honour;
 *  - a set's slug never changes once created: it is the wire value Obligate
 *    assigns per tenant;
 *  - the four builtin roles cannot be deleted; a custom set still held by a
 *    membership answers 409 with the count (the foreign key would refuse it
 *    anyway — this says why).
 */

export class PermissionSetError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = 'PermissionSetError';
  }
}

interface PermissionSetRow {
  id: number;
  name: string;
  slug: string;
  capabilities: string[] | string;
  is_default: boolean;
  description: string | null;
  created_at: Date;
  updated_at: Date | null;
}

export interface Actor {
  userId: number | null;
  username?: string | null;
}

/** One row of the matrix catalogue: the capability, and how the matrix may treat it. */
export interface CapabilityMatrixInfo extends CapabilityInfo {
  /** Cannot be ticked into any set, and why. */
  lock: 'platform_only' | 'by_name_only' | null;
  /** Ticking it needs an explicit confirmation (money, secrets in clear, four-eyes). */
  explicitOnly: boolean;
  /** What holding it brings with it at resolution (`CAPABILITY_IMPLIES`, direct). */
  implies: Capability[];
}

function parseCaps(raw: unknown): string[] {
  let v: unknown = raw;
  if (typeof v === 'string') {
    try { v = JSON.parse(v); } catch { return []; }
  }
  return Array.isArray(v) ? v.map((x) => String(x)) : [];
}

function iso(d: Date | string | null | undefined): string | undefined {
  if (!d) return undefined;
  return d instanceof Date ? d.toISOString() : String(d);
}

function rowToPermissionSet(row: PermissionSetRow, counts?: { members: number; tenants: number }): PermissionSet {
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    capabilities: parseCaps(row.capabilities),
    isDefault: row.is_default,
    createdAt: iso(row.created_at) ?? '',
    description: row.description ?? null,
    updatedAt: iso(row.updated_at),
    ...(counts ? { memberCount: counts.members, tenantCount: counts.tenants } : {}),
  };
}

/** Validates a capability list for a SET: known, not locked. Order kept, duplicates dropped. */
export function validateSetCapabilities(values: unknown): Capability[] {
  if (!Array.isArray(values)) throw new PermissionSetError(400, 'capabilities must be an array');
  const out: Capability[] = [];
  for (const v of values) {
    if (!isCapability(v)) throw new PermissionSetError(400, `Unknown capability: ${String(v).slice(0, 64)}`);
    const lock = setLockReason(v);
    if (lock === 'platform_only') {
      throw new PermissionSetError(400, `${v} is reserved to platform administrators and cannot be put in a permission set`);
    }
    if (lock === 'by_name_only') {
      throw new PermissionSetError(400, `${v} is never granted by a role — only by name (team grant or Obligate)`);
    }
    if (!out.includes(v)) out.push(v);
  }
  return out;
}

function slugFromName(name: string): string {
  return name
    .normalize('NFD').replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 64);
}

async function audit(action: string, slug: string, actor: Actor, before: unknown, after: unknown): Promise<void> {
  await appendAudit({
    tenantId: MASTER_TENANT_ID,
    actorType: 'user',
    actorId: actor.userId,
    actorName: actor.username ?? null,
    action,
    entityType: 'permission_set',
    entityId: slug,
    before: before as Record<string, unknown> | null,
    after: after as Record<string, unknown> | null,
  });
}

const BUILTIN_ORDER = new Map<string, number>(BUILTIN_TENANT_ROLES.map((s, i) => [s, i]));

class PermissionSetService {
  /** Builtins first (admin, user, account_manager, viewer), then custom sets by name. */
  async getAll(): Promise<PermissionSet[]> {
    const rows = (await db('permission_sets').select('*')) as PermissionSetRow[];
    const counts = (await db('user_tenants')
      .select('role')
      .count<Array<{ role: string; members: string }>>('user_id as members')
      .countDistinct<Array<{ role: string; tenants: string }>>('tenant_id as tenants')
      .groupBy('role')) as unknown as Array<{ role: string; members: string; tenants: string }>;
    const bySlug = new Map(counts.map((c) => [c.role, { members: Number(c.members), tenants: Number(c.tenants) }]));
    return rows
      .sort((a, b) => {
        const ai = BUILTIN_ORDER.get(a.slug) ?? 99;
        const bi = BUILTIN_ORDER.get(b.slug) ?? 99;
        return ai !== bi ? ai - bi : a.name.localeCompare(b.name);
      })
      .map((r) => rowToPermissionSet(r, bySlug.get(r.slug) ?? { members: 0, tenants: 0 }));
  }

  async getBySlug(slug: string): Promise<PermissionSet | null> {
    const row = (await db('permission_sets').where({ slug }).first()) as PermissionSetRow | undefined;
    return row ? rowToPermissionSet(row) : null;
  }

  /** Is `slug` an existing set — i.e. a role a membership may hold? */
  async exists(slug: unknown): Promise<boolean> {
    if (!isRoleSlugSyntax(slug)) return false;
    return !!(await db('permission_sets').where({ slug }).first('id'));
  }

  async create(
    data: { name: string; slug?: string; description?: string | null; capabilities: unknown },
    actor: Actor,
  ): Promise<PermissionSet> {
    const name = typeof data.name === 'string' ? data.name.trim() : '';
    if (!name || name.length > 64) throw new PermissionSetError(400, 'name is required (64 characters at most)');
    const slug = (data.slug ? String(data.slug).trim() : slugFromName(name)) || '';
    if (!isRoleSlugSyntax(slug)) {
      throw new PermissionSetError(400, 'slug must be lower-case letters, digits, "_" or "-" (64 at most)');
    }
    if (isBuiltinTenantRole(slug) || RESERVED_ROLE_SLUGS.includes(slug)) {
      throw new PermissionSetError(409, `The slug "${slug}" is reserved`);
    }
    const capabilities = validateSetCapabilities(data.capabilities ?? []);
    if (await db('permission_sets').where({ slug }).first('id')) {
      throw new PermissionSetError(409, `A permission set "${slug}" already exists`);
    }
    const [row] = (await db('permission_sets')
      .insert({
        name,
        slug,
        description: data.description ?? null,
        capabilities: JSON.stringify(capabilities),
        is_default: false,
        created_at: new Date(),
        updated_at: new Date(),
      })
      .returning('*')) as PermissionSetRow[];
    await audit('permission_set.created', slug, actor, null, { name, capabilities });
    return rowToPermissionSet(row, { members: 0, tenants: 0 });
  }

  async update(
    id: number,
    data: { name?: string; slug?: string; description?: string | null; capabilities?: unknown },
    actor: Actor,
  ): Promise<PermissionSet & { effective: Capability[] }> {
    const existing = (await db('permission_sets').where({ id }).first()) as PermissionSetRow | undefined;
    if (!existing) throw new PermissionSetError(404, 'Permission set not found');
    if (data.slug !== undefined && data.slug !== existing.slug) {
      throw new PermissionSetError(400, 'A permission set keeps its slug: it is the role value Obligate assigns');
    }
    const updates: Record<string, unknown> = {};
    if (data.name !== undefined) {
      const name = String(data.name).trim();
      if (!name || name.length > 64) throw new PermissionSetError(400, 'name is required (64 characters at most)');
      updates.name = name;
    }
    if (data.description !== undefined) updates.description = data.description === null ? null : String(data.description).slice(0, 1000);
    let nextCaps: Capability[] | null = null;
    if (data.capabilities !== undefined) {
      nextCaps = validateSetCapabilities(data.capabilities);
      updates.capabilities = JSON.stringify(nextCaps);
    }
    if (Object.keys(updates).length === 0) {
      const set = rowToPermissionSet(existing);
      return { ...set, effective: expandCapabilities(set.capabilities.filter(isCapability)) };
    }
    updates.updated_at = new Date();

    const [row] = (await db('permission_sets').where({ id }).update(updates).returning('*')) as PermissionSetRow[];
    const prevCaps = parseCaps(existing.capabilities);
    await audit(
      'permission_set.updated',
      existing.slug,
      actor,
      { name: existing.name, description: existing.description, capabilities: prevCaps },
      {
        name: row.name,
        description: row.description,
        capabilities: parseCaps(row.capabilities),
        ...(nextCaps
          ? {
              added: nextCaps.filter((c) => !prevCaps.includes(c)),
              removed: prevCaps.filter((c) => !(nextCaps as string[]).includes(c)),
            }
          : {}),
      },
    );
    const set = rowToPermissionSet(row);
    return { ...set, effective: expandCapabilities(set.capabilities.filter(isCapability)) };
  }

  /** A builtin set back to what migration 084 seeded (`ROLE_PERMISSION_SETS`). */
  async reset(id: number, actor: Actor): Promise<PermissionSet> {
    const existing = (await db('permission_sets').where({ id }).first()) as PermissionSetRow | undefined;
    if (!existing) throw new PermissionSetError(404, 'Permission set not found');
    const seed = ROLE_PERMISSION_SETS.find((s) => s.slug === existing.slug);
    if (!seed) throw new PermissionSetError(400, 'Only a builtin role can be reset');
    return this.update(id, { name: seed.name, description: seed.description, capabilities: seed.capabilities }, actor);
  }

  async delete(id: number, actor: Actor): Promise<void> {
    const existing = (await db('permission_sets').where({ id }).first()) as PermissionSetRow | undefined;
    if (!existing) throw new PermissionSetError(404, 'Permission set not found');
    if (existing.is_default || isBuiltinTenantRole(existing.slug)) {
      throw new PermissionSetError(400, 'A builtin role cannot be deleted');
    }
    const [{ n }] = (await db('user_tenants').where({ role: existing.slug }).count('* as n')) as Array<{ n: string }>;
    if (Number(n) > 0) {
      throw new PermissionSetError(409, `${Number(n)} membership(s) hold this role: move them to another role first`);
    }
    try {
      await db('permission_sets').where({ id }).del();
    } catch (err) {
      // A membership written between the count and the delete: the key refuses.
      if ((err as { code?: string }).code === '23503') {
        throw new PermissionSetError(409, 'Memberships hold this role: move them to another role first');
      }
      throw err;
    }
    await audit('permission_set.deleted', existing.slug, actor, { name: existing.name, capabilities: parseCaps(existing.capabilities) }, null);
  }

  /** The single source of truth, straight from @obliwan/shared, with the matrix's locks. */
  getAvailableCapabilities(): CapabilityMatrixInfo[] {
    return CAPABILITY_CATALOG.map((c) => ({
      ...c,
      lock: setLockReason(c.key),
      explicitOnly: (EXPLICIT_ONLY_CAPABILITIES as readonly string[]).includes(c.key),
      implies: [...(CAPABILITY_IMPLIES[c.key] ?? [])],
    }));
  }
}

export const permissionSetService = new PermissionSetService();
