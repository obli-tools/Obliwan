import type { Knex } from 'knex';

/**
 * 084 — RBAC aligned on Obliance (« brique 12 », operator decisions of
 * 2026-10-07). Three things change at once, because each one is unsafe
 * without the other two:
 *
 *  1. THE TENANT ROLE IS A PERMISSION SET. `user_tenants.role` becomes a
 *     `permission_sets.slug`, held by a FOREIGN KEY (an unknown role is
 *     impossible, not merely harmless — Obliance 091 left it free text). The
 *     runtime now reads the set's row (permission.service), so the matrix
 *     screen grants for real. Four builtin, global, non-deletable sets:
 *     `admin`, `user` (was `member` / set `operator`), `account_manager`
 *     (« Chargé(e) de compte ») and `viewer`. Their rows are OVERWRITTEN with
 *     literals equal to what each role held in code before this migration —
 *     a row nothing used to read may hold anything, and activating it in the
 *     same breath as making it authoritative would change access silently —
 *     plus the operator's two decisions: `user` gains `reconcile.read`, `admin`
 *     gains `groups.manage` and `reconcile.read`. `engineer` (nobody could hold
 *     it) becomes a custom set, minus `credential.manage`. Every rewritten row
 *     is filed in `audit_log` (tenant 1, actor `system`) with its before/after.
 *
 *  2. `group.write` IS RENAMED `groups.manage` (Obliance's name) in every
 *     stored list — sets, team-pinned capabilities, Obligate per-user grants —
 *     and reduced to reorder + group configuration (shared capabilities.ts).
 *
 *  3. TEAMS SCOPE WHAT A USER SEES, as in Obliance: 'ro'/'rw' on a group
 *     (down the closure), on a device, or on the ungrouped devices (a new
 *     `team_permissions.scope = 'ungrouped'`, scope_id 0). A non-admin with no
 *     team sees nothing. So that nobody loses access on the day it lands, every
 *     tenant that has non-admin members gets ONE team, « Tout le parc (084) »,
 *     holding exactly today's reach: 'rw' on the ungrouped devices (and the
 *     device-less sites) plus 'rw' on each grouped device by DEVICE grant —
 *     deliberately NOT on the groups themselves, because an 'rw' group grant
 *     also lets its holder rename, move and delete the group
 *     (`requireGroupWrite`), which no member could do before. 'rw' widens
 *     nothing: every write still needs its capability, which the role decides.
 *     A device filed later under a group is NOT covered (fail-closed): the
 *     operator re-cuts these teams into real ones.
 *
 * Rule inherited from 051: a migration never widens anybody's access. The two
 * additions above are the operator's, named, and asserted by the harness.
 * `down()` is fail-closed: a `viewer` or custom-set membership is DELETED
 * rather than turned into the wider `member`.
 *
 * No `?` anywhere in raw SQL (knex rewrites it into a binding — migration 032).
 * Lists are inlined as literals, like 051 and 062.
 */

const MASTER_TENANT_ID = 1;

/** The vocabulary of this migration's day (shared ALL_CAPABILITIES at 084). */
const VOCABULARY_084 = [
  'device.read', 'device.write', 'site.write', 'device.discover', 'reconcile.read',
  'config.read', 'config.write', 'template.read', 'template.write', 'site_variables.write',
  'plan.create', 'change.apply', 'change.approve', 'rollout.manage', 'drift.read',
  'drift.manage', 'query.run', 'snmp.read', 'snmp.admin', 'acs.admin', 'sim.read',
  'sim.manage', 'sim.recharge', 'credential.manage', 'secret.read', 'groups.manage',
  'users.manage', 'tenants.manage', 'settings.manage', 'notifications.manage', 'audit.read',
  'export.run', 'import.run',
];
const PLATFORM_ONLY = ['tenants.manage', 'users.manage', 'import.run'];
const BY_NAME_ONLY = ['credential.manage'];

/** shared `ROLE_PERMISSION_SETS`, as of this migration (the harness compares). */
export const ROLE_SETS_084: Record<string, { name: string; description: string; capabilities: string[] }> = {
  admin: {
    name: 'Administrateur',
    description: "Tout le client sans équipe ; applique et approuve les changements, approuve les recharges, révèle les secrets.",
    capabilities: [
      'device.read', 'device.write', 'device.discover', 'reconcile.read', 'config.read',
      'config.write', 'template.read', 'template.write', 'plan.create', 'change.apply',
      'change.approve', 'rollout.manage', 'drift.read', 'drift.manage', 'query.run',
      'snmp.read', 'snmp.admin', 'acs.admin', 'sim.read', 'sim.manage', 'sim.recharge',
      'secret.read', 'groups.manage', 'settings.manage', 'notifications.manage', 'audit.read',
      'export.run',
    ],
  },
  user: {
    name: 'Utilisateur',
    description: 'Exploitation courante : appareils, instantanés de configuration, découvertes, plans, dérive, requêtes. N’applique aucun changement.',
    capabilities: [
      'device.read', 'device.write', 'device.discover', 'reconcile.read', 'config.read',
      'template.read', 'site_variables.write', 'plan.create', 'drift.read', 'drift.manage',
      'query.run', 'snmp.read', 'sim.read',
    ],
  },
  account_manager: {
    name: 'Chargé(e) de compte',
    description: 'Sites et leurs variables, appareils et leur santé, lignes SIM (lecture), rapprochement CHR. N’écrit sur aucun appareil, ne voit aucun secret, n’achète aucune recharge.',
    capabilities: ['device.read', 'site.write', 'site_variables.write', 'snmp.read', 'sim.read', 'reconcile.read'],
  },
  viewer: {
    name: 'Lecteur',
    description: 'Consultation : parc, modèles, dérive, télémétrie, lignes SIM. Aucune configuration, aucune écriture.',
    capabilities: ['device.read', 'template.read', 'drift.read', 'snmp.read', 'sim.read'],
  },
};

/** What `down()` puts back: the rows as 001 + 035 + 051 + 062 left them. */
const PRE_084_SETS: Record<string, { name: string; capabilities: string[] }> = {
  admin: {
    name: 'Administrator',
    capabilities: [
      'device.read', 'device.write', 'site.write', 'device.discover', 'reconcile.read',
      'config.read', 'config.write', 'template.read', 'template.write', 'site_variables.write',
      'plan.create', 'change.apply', 'change.approve', 'rollout.manage', 'drift.read',
      'drift.manage', 'query.run', 'snmp.read', 'snmp.admin', 'acs.admin', 'sim.read',
      'sim.manage', 'sim.recharge', 'credential.manage', 'secret.read', 'group.write',
      'users.manage', 'tenants.manage', 'settings.manage', 'notifications.manage', 'audit.read',
      'export.run', 'import.run',
    ],
  },
  viewer: { name: 'Viewer', capabilities: ['device.read', 'template.read', 'drift.read', 'snmp.read', 'sim.read'] },
  operator: {
    name: 'Operator',
    capabilities: [
      'device.read', 'device.write', 'device.discover', 'config.read', 'template.read',
      'site_variables.write', 'plan.create', 'drift.read', 'drift.manage', 'query.run',
      'snmp.read', 'sim.read',
    ],
  },
  engineer: {
    name: 'Network engineer',
    capabilities: [
      'device.read', 'device.write', 'device.discover', 'config.read', 'config.write',
      'template.read', 'template.write', 'plan.create', 'change.apply', 'rollout.manage',
      'drift.read', 'drift.manage', 'query.run', 'snmp.read', 'snmp.admin', 'credential.manage',
      'sim.read', 'sim.manage',
    ],
  },
  account_manager: {
    name: 'Account manager',
    capabilities: ['device.read', 'site.write', 'site_variables.write', 'snmp.read', 'sim.read', 'reconcile.read'],
  },
};

/** Marker of the transition team, read by `down()`. */
export const LEGACY_TEAM_NAME = 'Tout le parc (084)';
export const LEGACY_TEAM_MARK = '[obliwan:084-legacy]';
const LEGACY_TEAM_DESCRIPTION =
  `${LEGACY_TEAM_MARK} Accès d'avant les équipes (migration 084) : rw sur les appareils ` +
  'sans groupe, sur chaque appareil groupé existant au jour de la migration, et sur les ' +
  "sites sans appareil. Remplacez-la par de vraies équipes : un appareil rangé plus tard " +
  "dans un groupe n'est PAS couvert.";

const ROLES_051 = "'admin','member','account_manager'";

interface SetRow { id: number; slug: string; name: string; capabilities: unknown; is_default: boolean }

function parseList(raw: unknown): string[] {
  let v: unknown = raw;
  if (typeof v === 'string') {
    try { v = JSON.parse(v); } catch { return []; }
  }
  return Array.isArray(v) ? v.map((x) => String(x)) : [];
}

function renameCap(list: string[], from: string, to: string): string[] {
  const out: string[] = [];
  for (const c of list) {
    const v = c === from ? to : c;
    if (!out.includes(v)) out.push(v);
  }
  return out;
}

/** A custom set as 084 accepts it: known values only, nothing locked. */
function sanitize084(list: string[]): string[] {
  return renameCap(list, 'group.write', 'groups.manage')
    .filter((c) => VOCABULARY_084.includes(c) && !PLATFORM_ONLY.includes(c) && !BY_NAME_ONLY.includes(c));
}

async function auditSet(
  knex: Knex,
  action: string,
  slug: string,
  before: unknown,
  after: unknown,
): Promise<void> {
  await knex('audit_log').insert({
    tenant_id: MASTER_TENANT_ID,
    actor_type: 'system',
    actor_id: null,
    actor_name: 'migration 084',
    action,
    entity_type: 'permission_set',
    entity_id: slug,
    before: before === null ? null : JSON.stringify(before),
    after: after === null ? null : JSON.stringify(after),
  });
}

async function renameStoredCapability(knex: Knex, from: string, to: string): Promise<void> {
  const pinned = (await knex('team_permissions').whereNotNull('capabilities').select('id', 'capabilities')) as Array<{ id: number; capabilities: unknown }>;
  for (const r of pinned) {
    const list = parseList(r.capabilities);
    if (!list.includes(from)) continue;
    await knex('team_permissions').where({ id: r.id }).update({ capabilities: JSON.stringify(renameCap(list, from, to)) });
  }
  const fed = (await knex('user_tenant_capabilities').select('user_id', 'tenant_id', 'capabilities')) as Array<{ user_id: number; tenant_id: number; capabilities: unknown }>;
  for (const r of fed) {
    const list = parseList(r.capabilities);
    if (!list.includes(from)) continue;
    await knex('user_tenant_capabilities')
      .where({ user_id: r.user_id, tenant_id: r.tenant_id })
      .update({ capabilities: JSON.stringify(renameCap(list, from, to)) });
  }
}

export async function up(knex: Knex): Promise<void> {
  // ── 1. permission_sets: two columns, the role rows rewritten ────────────
  await knex.schema.alterTable('permission_sets', (t) => {
    t.text('description').nullable();
    t.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  const hasUser = await knex('permission_sets').where({ slug: 'user' }).first('id');
  if (!hasUser) {
    // Same row, same id: `operator` was the set behind the `member` role.
    await knex('permission_sets').where({ slug: 'operator' }).update({ slug: 'user' });
  }

  const before = new Map<string, SetRow>(
    ((await knex('permission_sets').select('id', 'slug', 'name', 'capabilities', 'is_default')) as SetRow[])
      .map((r) => [r.slug, r]),
  );

  for (const [slug, def] of Object.entries(ROLE_SETS_084)) {
    const prev = before.get(slug);
    const row = {
      name: def.name,
      description: def.description,
      capabilities: JSON.stringify(def.capabilities),
      is_default: true,
      updated_at: knex.fn.now(),
    };
    if (prev) await knex('permission_sets').where({ id: prev.id }).update(row);
    else await knex('permission_sets').insert({ slug, ...row });
    await auditSet(
      knex,
      'permission_set.migrated',
      slug,
      prev ? { name: prev.name, isDefault: prev.is_default, capabilities: parseList(prev.capabilities) } : null,
      { name: def.name, isDefault: true, capabilities: def.capabilities },
    );
  }

  // Every other row is a custom set from now on: assignable, deletable when
  // unused, re-sanitised (nobody could hold it, so nothing changes for anyone).
  for (const [slug, prev] of before) {
    if (slug in ROLE_SETS_084) continue;
    const prevList = parseList(prev.capabilities);
    const next = sanitize084(prevList);
    await knex('permission_sets').where({ id: prev.id }).update({
      capabilities: JSON.stringify(next),
      is_default: false,
      updated_at: knex.fn.now(),
    });
    if (JSON.stringify(next) !== JSON.stringify(prevList) || prev.is_default) {
      await auditSet(
        knex,
        'permission_set.migrated',
        slug,
        { name: prev.name, isDefault: prev.is_default, capabilities: prevList },
        { name: prev.name, isDefault: false, capabilities: next },
      );
    }
  }

  // ── 2. group.write → groups.manage in every by-name grant ───────────────
  await renameStoredCapability(knex, 'group.write', 'groups.manage');

  // ── 3. user_tenants.role → a foreign key onto the set's slug ────────────
  await knex.schema.raw('ALTER TABLE user_tenants DROP CONSTRAINT user_tenants_role_chk');
  await knex('user_tenants').where({ role: 'member' }).update({ role: 'user' });
  // varchar(16) DEFAULT 'member' (001): widen to the slug's width and move the
  // default BEFORE the key, or every role-less insert would violate it.
  await knex.schema.raw('ALTER TABLE user_tenants ALTER COLUMN role TYPE varchar(64)');
  await knex.schema.raw("ALTER TABLE user_tenants ALTER COLUMN role SET DEFAULT 'user'");
  await knex.schema.raw(
    'ALTER TABLE user_tenants ADD CONSTRAINT user_tenants_role_fk FOREIGN KEY (role) ' +
      'REFERENCES permission_sets (slug) ON UPDATE CASCADE ON DELETE RESTRICT',
  );

  // ── 4. team_permissions: the `ungrouped` scope ──────────────────────────
  await knex.schema.raw('ALTER TABLE team_permissions DROP CONSTRAINT team_permissions_scope_chk');
  await knex.schema.raw(
    'ALTER TABLE team_permissions ADD CONSTRAINT team_permissions_scope_chk ' +
      "CHECK (scope IN ('group','device','ungrouped'))",
  );

  // ── 5. The transition team: today's reach, kept for today's members ─────
  // Non-admin memberships of accounts that are not platform admins (those see
  // everything anyway). Tenant admins see the whole tenant by role.
  const holders = (await knex('user_tenants as ut')
    .join('users as u', 'u.id', 'ut.user_id')
    .whereNot('ut.role', 'admin')
    .whereNot('u.role', 'admin')
    .select('ut.tenant_id', 'ut.user_id')) as Array<{ tenant_id: number; user_id: number }>;
  const byTenant = new Map<number, number[]>();
  for (const h of holders) {
    const list = byTenant.get(Number(h.tenant_id)) ?? [];
    list.push(Number(h.user_id));
    byTenant.set(Number(h.tenant_id), list);
  }
  for (const [tenantId, userIds] of byTenant) {
    let name = LEGACY_TEAM_NAME;
    for (let n = 2; await knex('user_teams').where({ tenant_id: tenantId, name }).first('id'); n++) {
      name = `${LEGACY_TEAM_NAME} ${n}`;
    }
    const [team] = (await knex('user_teams')
      .insert({ tenant_id: tenantId, name, description: LEGACY_TEAM_DESCRIPTION, can_create: false })
      .returning('id')) as Array<{ id: number }>;
    await knex('team_memberships').insert(userIds.map((uid) => ({ team_id: team.id, user_id: uid })));
    await knex('team_permissions').insert({ team_id: team.id, scope: 'ungrouped', scope_id: 0, level: 'rw' });
    const grouped = (await knex('devices')
      .where({ tenant_id: tenantId })
      .whereNotNull('group_id')
      .pluck('id')) as number[];
    for (let i = 0; i < grouped.length; i += 500) {
      await knex('team_permissions').insert(
        grouped.slice(i, i + 500).map((id) => ({ team_id: team.id, scope: 'device', scope_id: id, level: 'rw' })),
      );
    }
  }
}

export async function down(knex: Knex): Promise<void> {
  // ── 5. the transition teams and the `ungrouped` scope ───────────────────
  await knex('user_teams').where('description', 'like', `${LEGACY_TEAM_MARK}%`).del();
  await knex('team_permissions').where({ scope: 'ungrouped' }).del();
  await knex.schema.raw('ALTER TABLE team_permissions DROP CONSTRAINT team_permissions_scope_chk');
  await knex.schema.raw(
    "ALTER TABLE team_permissions ADD CONSTRAINT team_permissions_scope_chk CHECK (scope IN ('group','device'))",
  );

  // ── 3. user_tenants back to the three-value CHECK ───────────────────────
  await knex.schema.raw('ALTER TABLE user_tenants DROP CONSTRAINT user_tenants_role_fk');
  // A viewer or a custom-set membership has no pre-084 equivalent that is not
  // WIDER (`member`): it is deleted, the fail-closed outcome (051's rule).
  await knex('user_tenants').whereNotIn('role', ['admin', 'user', 'account_manager']).del();
  await knex('user_tenants').where({ role: 'user' }).update({ role: 'member' });
  await knex.schema.raw('ALTER TABLE user_tenants ALTER COLUMN role TYPE varchar(16)');
  await knex.schema.raw("ALTER TABLE user_tenants ALTER COLUMN role SET DEFAULT 'member'");
  await knex.schema.raw(
    `ALTER TABLE user_tenants ADD CONSTRAINT user_tenants_role_chk CHECK (role IN (${ROLES_051}))`,
  );

  // ── 2. groups.manage → group.write ──────────────────────────────────────
  await renameStoredCapability(knex, 'groups.manage', 'group.write');

  // ── 1. the rows as they were, then the two columns ──────────────────────
  if (!(await knex('permission_sets').where({ slug: 'operator' }).first('id'))) {
    await knex('permission_sets').where({ slug: 'user' }).update({ slug: 'operator' });
  }
  const rows = (await knex('permission_sets').select('id', 'slug', 'name', 'capabilities', 'is_default')) as SetRow[];
  for (const r of rows) {
    const def = PRE_084_SETS[r.slug];
    if (def) {
      await knex('permission_sets').where({ id: r.id }).update({
        name: def.name, capabilities: JSON.stringify(def.capabilities), is_default: true,
      });
      await auditSet(knex, 'permission_set.migrated_down', r.slug,
        { capabilities: parseList(r.capabilities) }, { capabilities: def.capabilities });
    } else {
      const list = renameCap(parseList(r.capabilities), 'groups.manage', 'group.write');
      await knex('permission_sets').where({ id: r.id }).update({ capabilities: JSON.stringify(list), is_default: false });
    }
  }
  // A builtin seeded by 001 that 084 found missing is put back too.
  for (const [slug, def] of Object.entries(PRE_084_SETS)) {
    if (!(await knex('permission_sets').where({ slug }).first('id'))) {
      await knex('permission_sets').insert({ slug, name: def.name, capabilities: JSON.stringify(def.capabilities), is_default: true });
    }
  }
  await knex.schema.alterTable('permission_sets', (t) => {
    t.dropColumn('description');
    t.dropColumn('updated_at');
  });
}
