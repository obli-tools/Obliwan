import type { Knex } from 'knex';

/**
 * 087 — the tenant admin is team-scoped, exactly like in Obliance (operator,
 * 2026-10-06: « inspire-toi du RBAC d'Obliance, fais-en ta base pour tout »).
 *
 * In Obliance every WHERE check reads `isAdmin = users.role === 'admin'` — the
 * PLATFORM admin. The tenant role `user_tenants.role = 'admin'` is read only
 * for WHAT (every capability of its set) and a few tenant-config edits. 084
 * kept one ObliWAN divergence: a tenant admin saw its whole tenant without a
 * team (teamScope.service `isTenantWide`). The code that ships with this
 * migration removes it: a tenant admin now sees and writes what its TEAMS
 * cover, and with no team sees nothing. Code and data must land together, so
 * that nobody loses access on the day it lands:
 *
 *  1. THE TRANSITION TEAM. Every tenant whose memberships hold the `admin` role
 *     for accounts that are not platform admins gets ONE team,
 *     « Administrateurs — tout le parc (087) », with exactly those members and
 *     the shape the operator chose (2026-10-07: « l'équipe admin habituelle
 *     d'Obliance ») :
 *       - 'rw' on the ungrouped devices (and the device-less sites, the pool
 *         SIM lines): scope 'ungrouped', scope_id 0;
 *       - 'rw' on every ROOT group of the tenant (parent_id IS NULL), so every
 *         grouped device — including one filed LATER under any group of the
 *         tree — stays writable, and the admins can rename, move and delete
 *         groups (an 'rw' group grant is what `requireGroupWrite` reads);
 *       - can_create = true, so the admins can create groups too (Obliance's
 *         `requireCanCreate`), the new group being granted 'rw' to this team.
 *     Today's whole-tenant 'rw' is kept; the operator's decision adds group
 *     edition and creation on top (a tenant admin had neither without a team).
 *     Every write still needs its capability, which the role decides. One
 *     audit_log row per team, filed in that tenant.
 *     « Tout le parc (084) » (the members' transition team) is NOT touched.
 *
 *  2. THE ROLE'S HINT. If `permission_sets(slug='admin').description` still
 *     holds 084's literal (« Tout le client sans équipe ; … »), it is rewritten
 *     to say what is now true. An operator's own wording is left alone.
 *
 *  3. LIVE ALERTS GET A SUBJECT. `live_alerts` (001) named no object, so the
 *     feed could only be tenant-wide. Three nullable columns — `device_id`,
 *     `site_id`, `sim_line_id`, each ON DELETE CASCADE (an alert about a
 *     deleted object goes with it) and a partial index — let the feed be read
 *     through the caller's teams (teamScope.service `liveAlertScope`). Existing
 *     rows are backfilled from `navigate_to`, requiring the SAME tenant (a
 *     cross-tenant id links nothing). An alert that names none of the three is
 *     a tenant-level alert, visible to every member (operator, 2026-10-07).
 *
 * `down()` is fail-closed: it deletes the transition teams (memberships and
 * grants cascade), puts 084's hint back only where this migration's text is
 * still there, and drops the three columns. The old tenant-admin bypass comes
 * back with the CODE rollback, not with data.
 *
 * No `?` anywhere in raw SQL (knex rewrites it into a binding — migration 032):
 * the backfill regexes spell their repetition `{1,9}`, never an optional mark.
 */

const MIGRATION = '087';
const MASTER_TENANT_ID = 1;

export const ADMIN_TEAM_NAME = 'Administrateurs — tout le parc (087)';
export const ADMIN_TEAM_MARK = '[obliwan:087-admins]';
const ADMIN_TEAM_DESCRIPTION =
  `${ADMIN_TEAM_MARK} Accès des administrateurs de l'espace d'avant l'alignement sur Obliance ` +
  '(migration 087) : rw sur les appareils sans groupe et sur chaque groupe racine (donc sur tout ' +
  'le parc, y compris les appareils rangés plus tard), création de groupes. Remplacez-la par de ' +
  'vraies équipes si les administrateurs ne doivent pas tout voir.';

/** 084's text for the `admin` role (ROLE_SETS_084.admin.description). */
export const ADMIN_DESCRIPTION_084 =
  "Tout le client sans équipe ; applique et approuve les changements, approuve les recharges, révèle les secrets.";
/** shared ROLE_PERMISSION_SETS admin.description as of this migration. */
export const ADMIN_DESCRIPTION_087 =
  "Toutes les capacités de l'espace, sur ce que couvrent ses équipes ; applique et approuve les changements, approuve les recharges, révèle les secrets.";

/** The backfill: `navigate_to` shape → (column, table). Literals, no `?`. */
const BACKFILL: ReadonlyArray<{ column: string; table: string; pattern: string }> = [
  { column: 'device_id', table: 'devices', pattern: '^/devices/([0-9]{1,9})$' },
  { column: 'site_id', table: 'sites', pattern: '^/sites/([0-9]{1,9})$' },
  { column: 'sim_line_id', table: 'sim_lines', pattern: '^/mobile/lines/([0-9]{1,9})$' },
];

export async function up(knex: Knex): Promise<void> {
  // ── 1. The transition team of the tenant admins ─────────────────────────
  const holders = (await knex('user_tenants as ut')
    .join('users as u', 'u.id', 'ut.user_id')
    .where('ut.role', 'admin')
    .whereNot('u.role', 'admin')
    .orderBy(['ut.tenant_id', 'ut.user_id'])
    .select('ut.tenant_id', 'ut.user_id')) as Array<{ tenant_id: number; user_id: number }>;
  const byTenant = new Map<number, number[]>();
  for (const h of holders) {
    const list = byTenant.get(Number(h.tenant_id)) ?? [];
    list.push(Number(h.user_id));
    byTenant.set(Number(h.tenant_id), list);
  }

  for (const [tenantId, userIds] of byTenant) {
    let name = ADMIN_TEAM_NAME;
    for (let n = 2; await knex('user_teams').where({ tenant_id: tenantId, name }).first('id'); n++) {
      name = `${ADMIN_TEAM_NAME} ${n}`;
    }
    const [team] = (await knex('user_teams')
      .insert({ tenant_id: tenantId, name, description: ADMIN_TEAM_DESCRIPTION, can_create: true })
      .returning('id')) as Array<{ id: number }>;
    await knex('team_memberships').insert(userIds.map((uid) => ({ team_id: team.id, user_id: uid })));
    await knex('team_permissions').insert({ team_id: team.id, scope: 'ungrouped', scope_id: 0, level: 'rw' });
    const roots = ((await knex('device_groups')
      .where({ tenant_id: tenantId })
      .whereNull('parent_id')
      .orderBy('id')
      .pluck('id')) as Array<number | string>).map(Number);
    for (let i = 0; i < roots.length; i += 500) {
      await knex('team_permissions').insert(
        roots.slice(i, i + 500).map((id) => ({ team_id: team.id, scope: 'group', scope_id: id, level: 'rw' })),
      );
    }
    await knex('audit_log').insert({
      tenant_id: tenantId,
      actor_type: 'system',
      actor_id: null,
      actor_name: `migration ${MIGRATION}`,
      action: 'team.migrated',
      entity_type: 'user_team',
      entity_id: String(team.id),
      before: null,
      after: JSON.stringify({
        name,
        members: userIds,
        canCreate: true,
        grantCounts: { ungrouped: 1, rootGroups: roots.length },
      }),
    });
  }

  // ── 2. The admin role's hint, only where it is still 084's ──────────────
  const set = (await knex('permission_sets').where({ slug: 'admin' }).first('id', 'description')) as
    | { id: number; description: string | null }
    | undefined;
  if (set && set.description === ADMIN_DESCRIPTION_084) {
    await knex('permission_sets').where({ id: set.id }).update({ description: ADMIN_DESCRIPTION_087, updated_at: knex.fn.now() });
    await knex('audit_log').insert({
      tenant_id: MASTER_TENANT_ID,
      actor_type: 'system',
      actor_id: null,
      actor_name: `migration ${MIGRATION}`,
      action: 'permission_set.migrated',
      entity_type: 'permission_set',
      entity_id: 'admin',
      before: JSON.stringify({ description: ADMIN_DESCRIPTION_084 }),
      after: JSON.stringify({ description: ADMIN_DESCRIPTION_087 }),
    });
  }

  // ── 3. live_alerts: the subject of an alert ─────────────────────────────
  await knex.schema.alterTable('live_alerts', (t) => {
    t.integer('device_id').nullable().references('id').inTable('devices').onDelete('CASCADE');
    t.integer('site_id').nullable().references('id').inTable('sites').onDelete('CASCADE');
    t.integer('sim_line_id').nullable().references('id').inTable('sim_lines').onDelete('CASCADE');
  });
  await knex.schema.raw('CREATE INDEX live_alerts_device_id ON live_alerts (device_id) WHERE device_id IS NOT NULL');
  await knex.schema.raw('CREATE INDEX live_alerts_site_id ON live_alerts (site_id) WHERE site_id IS NOT NULL');
  await knex.schema.raw('CREATE INDEX live_alerts_sim_line_id ON live_alerts (sim_line_id) WHERE sim_line_id IS NOT NULL');
  for (const b of BACKFILL) {
    // The pattern is a literal of this file (no caller input); the target must
    // live in the alert's own tenant, so a cross-tenant id links nothing.
    await knex.schema.raw(
      `UPDATE live_alerts la SET ${b.column} = o.id FROM ${b.table} o ` +
        `WHERE la.navigate_to ~ '${b.pattern}' ` +
        `AND o.id = substring(la.navigate_to from '${b.pattern}')::int ` +
        'AND o.tenant_id = la.tenant_id',
    );
  }
}

export async function down(knex: Knex): Promise<void> {
  // ── 3. ──
  await knex.schema.raw('DROP INDEX IF EXISTS live_alerts_sim_line_id');
  await knex.schema.raw('DROP INDEX IF EXISTS live_alerts_site_id');
  await knex.schema.raw('DROP INDEX IF EXISTS live_alerts_device_id');
  await knex.schema.alterTable('live_alerts', (t) => {
    t.dropColumn('sim_line_id');
    t.dropColumn('site_id');
    t.dropColumn('device_id');
  });

  // ── 2. ──
  const set = (await knex('permission_sets').where({ slug: 'admin' }).first('id', 'description')) as
    | { id: number; description: string | null }
    | undefined;
  if (set && set.description === ADMIN_DESCRIPTION_087) {
    await knex('permission_sets').where({ id: set.id }).update({ description: ADMIN_DESCRIPTION_084, updated_at: knex.fn.now() });
    await knex('audit_log').insert({
      tenant_id: MASTER_TENANT_ID,
      actor_type: 'system',
      actor_id: null,
      actor_name: `migration ${MIGRATION}`,
      action: 'permission_set.migrated_down',
      entity_type: 'permission_set',
      entity_id: 'admin',
      before: JSON.stringify({ description: ADMIN_DESCRIPTION_087 }),
      after: JSON.stringify({ description: ADMIN_DESCRIPTION_084 }),
    });
  }

  // ── 1. ── (memberships and grants cascade; « Tout le parc (084) » untouched)
  await knex('user_teams').where('description', 'like', `${ADMIN_TEAM_MARK}%`).del();
}
