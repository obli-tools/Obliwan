import type { Request, Response, NextFunction } from 'express';
import type { Knex } from 'knex';
import { randomUUID } from 'crypto';
import { MASTER_TENANT_ID, sanitizeCapabilities, isSettingsKey, getSettingDefinition } from '@obliwan/shared';
import type { SettingsKey } from '@obliwan/shared';
import { db } from '../db';
import { AppError } from '../middleware/errorHandler';
import { settingsService } from '../services/settings.service';
import { topoSort, findCycles, CycleError } from '../utils/topoSort';

/**
 * Tenant backup / restore — migrate a customer from one ObliWAN instance to
 * another (design decision: import/export is kept AND levelled up, and
 * "nothing exported may be un-importable").
 *
 * SECTIONS. Every one of them maps to a table that exists in migration 001
 * and is exercised by the same code path in both directions. The Obliguard
 * sections that pointed at tables ObliWAN does not have — monitors, agentGroups,
 * remediationActions, remediationBindings — are NOT stubbed out here: they are
 * gone. The fleet sections (sites, devices, transports, templates, revisions,
 * variables) land with their own migrations and get added to
 * SECTIONS then, not before.
 *
 * SECRETS ARE NEVER EXPORTED. SMTP passwords, the Obligate API key and (from
 * the inventory on) device credentials stay in the instance that owns them: a bundle is a
 * plain JSON file that travels by e-mail and chat. What crosses is structure.
 */
const SECTIONS = [
  'deviceGroups',
  'settings',
  'notificationChannels',
  'teams',
  // Fleet. Ordered AFTER `deviceGroups` on purpose: a device points at a
  // site and at a group, so the import walks the list in this order and every
  // reference is resolvable by the time it is needed.
  'sites',
  'devices',
  'deviceTransports',
] as const;

type ExportSection = (typeof SECTIONS)[number];

function isSection(value: string): value is ExportSection {
  return (SECTIONS as readonly string[]).includes(value);
}

/** Bundle envelope version. Bump on any breaking change to the shape. */
const FORMAT_VERSION = 2;

/**
 * What to do when an imported item's UUID already exists in the database.
 *  - update      : overwrite the existing record with the imported data (default)
 *  - generateNew : create a brand-new copy with a fresh UUID
 *  - ignore      : skip the item entirely
 *
 * A device channel (`deviceTransports`) has no UUID of its own: it follows the
 * strategy its DEVICE was given — see the transport loop in `importData`.
 */
type ConflictStrategy = 'update' | 'generateNew' | 'ignore';

const CONFLICT_STRATEGIES: ConflictStrategy[] = ['update', 'generateNew', 'ignore'];

// -- Helpers -----------------------------------------------------------------

function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}

/**
 * device_groups.slug is UNIQUE (tenant_id, slug) since a later fix:
 * It used to be globally unique, which made one tenant's slugs (and
 * therefore its URLs and its export) depend on another tenant's content: a
 * second tenant importing "Paris" silently got `paris-1`, and the same bundle
 * imported twice on two instances produced two different results.
 */
async function ensureUniqueSlugTrx(
  trx: Knex.Transaction,
  slug: string,
  tenantId: number,
): Promise<string> {
  let candidate = slug || 'group';
  let i = 1;
  for (;;) {
    const exists = await trx('device_groups').where({ slug: candidate, tenant_id: tenantId }).first();
    if (!exists) return candidate;
    candidate = `${slug}-${i++}`;
  }
}

/** Insert closure-table entries for a newly created group. */
async function insertGroupClosure(
  trx: Knex.Transaction,
  groupId: number,
  parentId: number | null,
): Promise<void> {
  await trx('group_closure').insert({ ancestor_id: groupId, descendant_id: groupId, depth: 0 });
  if (parentId !== null) {
    await trx.raw(
      `INSERT INTO group_closure (ancestor_id, descendant_id, depth)
       SELECT gc.ancestor_id, ?, gc.depth + 1
       FROM   group_closure gc
       WHERE  gc.descendant_id = ?`,
      [groupId, parentId],
    );
  }
}

/**
 * Rebuild the closure rows for an EXISTING group whose parent just changed.
 * Skipping this is how an import quietly corrupts settings inheritance and
 * group-scoped permissions: both are resolved through `group_closure`, so a
 * stale closure means a user keeps read access to a subtree that was moved out
 * from under them.
 */
async function reparentGroupClosure(
  trx: Knex.Transaction,
  groupId: number,
  parentId: number | null,
): Promise<void> {
  const subtree = await trx('group_closure').where({ ancestor_id: groupId }).pluck('descendant_id');
  const descIds: number[] = subtree.length > 0 ? subtree : [groupId];

  // Cut every link coming from outside the subtree.
  await trx('group_closure')
    .whereIn('descendant_id', descIds)
    .whereNotIn('ancestor_id', descIds)
    .del();

  if (parentId !== null) {
    await trx.raw(
      `INSERT INTO group_closure (ancestor_id, descendant_id, depth)
       SELECT p.ancestor_id, s.descendant_id, p.depth + s.depth + 1
       FROM   group_closure p
       CROSS JOIN group_closure s
       WHERE  p.descendant_id = ?
         AND  s.ancestor_id  = ?`,
      [parentId, groupId],
    );
  }
}

interface SectionResult { created: number; updated: number; skipped: number; warnings?: string[] }

/**
 * The import used to write `settings` with a raw
 * DELETE + INSERT: no `SETTINGS_DEFINITIONS`, no min/max, no check that the key
 * exists at all. `PUT /api/settings/global` refuses `snmp_timeout = 999999999`
 * (max 60000) and refuses an invented key outright; a JSON file uploaded to
 * `POST /api/admin/import` put both straight into the table. The row is then
 * read by `settingsService.resolveForDevice`, i.e. by the pollers, and shown by
 * a UI whose slider cannot express it — so the operator cannot even correct it
 * from the screen that displays it.
 *
 * Two write paths onto one table, one validated and one not, is the same shape
 * as #19 just below (and as #12). The bundle now goes through the
 * SAME source of truth as the API: `isSettingsKey` / `getSettingDefinition`
 * are the accessors over the very `SETTINGS_DEFINITIONS` array that
 * `settingsService.validate()` reads, and the write itself is delegated to
 * `settingsService._write`, which carries the partial-index conflict target the
 * hand-rolled DELETE+INSERT was working around.
 *
 * A bad value REJECTS THE BUNDLE (400) rather than being skipped: a restore
 * that silently drops half the tuning of a customer is worse than one that
 * refuses and names the line to fix.
 */
function parseSettingValue(rawKey: unknown, rawValue: unknown): { key: SettingsKey; value: number } {
  const key = typeof rawKey === 'string' ? rawKey : String(rawKey);
  if (!isSettingsKey(key)) {
    throw new AppError(
      400,
      `Import aborted: settings contains an unknown key "${key}". ` +
        'Nothing was imported. Remove the entry, or upgrade this instance to a version that defines it.',
    );
  }
  const def = getSettingDefinition(key);

  // The export writes the jsonb value verbatim, so it arrives as a number; a
  // hand-edited bundle may carry "5000". Anything else is a mistake, not a
  // value to coerce.
  const value =
    typeof rawValue === 'number'
      ? rawValue
      : typeof rawValue === 'string' && rawValue.trim() !== ''
        ? Number(rawValue)
        : NaN;

  if (!Number.isFinite(value)) {
    throw new AppError(
      400,
      `Import aborted: setting "${key}" carries a non-numeric value (${JSON.stringify(rawValue)}). ` +
        'Nothing was imported.',
    );
  }
  if (def && (value < def.min || value > def.max)) {
    throw new AppError(
      400,
      `Import aborted: setting "${key}" = ${value} is outside its allowed range ` +
        `[${def.min}, ${def.max}]. Nothing was imported — the pollers read this value.`,
    );
  }
  return { key, value };
}

/**
 * Foreign SMTP references, import side.
 *
 * `notificationsController.createChannel` / `updateChannel` now refuse a
 * `config.smtpServerId` the tenant may not use, but the import writes
 * `notification_channels.config` directly and bypassed that check: a
 * hand-edited (or simply cross-tenant) bundle re-materialised a channel naming
 * ANOTHER customer's private relay. `resolveChannelConfig` refuses it at send
 * time, so no credential is handed over, but the row itself must not exist —
 * an authorisation reference to another tenant's resource is refused at write
 * time, and the operator is told rather than left with a channel that fails
 * only during an outage.
 *
 * The reference is dropped and the channel imported DISABLED, so one bad key
 * does not cost the operator the other forty sections of the bundle.
 */
async function scrubForeignSmtpRef(
  trx: Knex.Transaction,
  config: Record<string, unknown>,
  tenantId: number,
  channelName: string,
  warnings: string[],
): Promise<{ config: Record<string, unknown>; disabled: boolean }> {
  const raw = config.smtpServerId;
  if (raw === undefined || raw === null || raw === '') return { config, disabled: false };

  const id = Number(raw);
  let usable = Number.isInteger(id) && id > 0;
  if (usable) {
    // Own relay or a platform relay (tenant_id IS NULL) — the same rule
    // `smtpServerService.getById` applies outside the transaction.
    const row = await trx('smtp_servers')
      .where({ id })
      .where(function () {
        this.where('tenant_id', tenantId).orWhereNull('tenant_id');
      })
      .first('id');
    usable = !!row;
  }
  if (usable) return { config, disabled: false };

  const { smtpServerId: _dropped, ...rest } = config;
  warnings.push(
    `Channel "${channelName}": smtpServerId ${String(raw)} does not belong to this tenant ` +
      '(and is not a platform relay). The reference was dropped and the channel imported ' +
      'disabled — pick a relay of this tenant before enabling it.',
  );
  return { config: rest, disabled: true };
}

// -- Controller ---------------------------------------------------------------

export const importExportController = {

  // -- EXPORT ----------------------------------------------------------------

  async exportData(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const rawSections = (req.query.sections as string | undefined) ?? '';
      const requested = rawSections ? rawSections.split(',').map((s) => s.trim()).filter(Boolean) : [];

      const unknown = requested.filter((s) => s !== 'all' && !isSection(s));
      if (unknown.length > 0) {
        throw new AppError(400, `Unknown section(s): ${unknown.join(', ')}`);
      }

      const all = requested.length === 0 || requested.includes('all');
      const selected: ExportSection[] = all ? [...SECTIONS] : (requested as ExportSection[]);
      const want = (s: ExportSection) => selected.includes(s);

      // Was `req.session.currentTenantId ?? 1`,
      // i.e. the MASTER tenant for any admin session with no current tenant.
      // `requireTenant` (importExport.routes.ts) now guarantees req.tenantId.
      const tenantId = req.tenantId;
      const tenant = await db('tenants').where({ id: tenantId }).first('slug') as { slug: string } | undefined;

      const entities: Record<string, unknown[]> = {};

      // Group id -> uuid, needed by settings, bindings and team permissions.
      const groupRows = await db('device_groups')
        .where({ tenant_id: tenantId })
        .orderBy('sort_order')
        .orderBy('name')
        .select('id', 'uuid', 'name', 'description', 'parent_id', 'sort_order', 'is_general', 'group_notifications');
      const groupUuidById = new Map<number, string>(groupRows.map((g) => [g.id as number, g.uuid as string]));

      // -- Device groups (the site / equipment tree) ---------------------------
      if (want('deviceGroups')) {
        entities.deviceGroups = groupRows.map((g) => ({
          uuid: g.uuid,
          name: g.name,
          description: g.description,
          parentUuid: g.parent_id != null ? (groupUuidById.get(g.parent_id) ?? null) : null,
          sortOrder: g.sort_order,
          isGeneral: g.is_general,
          groupNotifications: g.group_notifications,
        }));
      }

      // -- Hierarchical settings ------------------------------------------------
      // Device-scoped settings are skipped: `devices` does not exist yet, so a
      // scope='device' row cannot be resolved to a portable uuid. Emitting it
      // would break the "everything exported is importable" rule.
      if (want('settings')) {
        const settings = await db('settings')
          .where({ tenant_id: tenantId })
          .whereIn('scope', ['global', 'group'])
          .orderBy('scope')
          .orderBy('scope_id')
          .orderBy('key');

        entities.settings = settings
          .map((s) => ({
            scope: s.scope,
            scopeUuid: s.scope === 'group' ? (groupUuidById.get(s.scope_id) ?? null) : null,
            key: s.key,
            value: s.value,
          }))
          .filter((s) => s.scope === 'global' || s.scopeUuid !== null);
      }

      // -- Notification channels + their bindings --------------------------------
      // `config` holds webhook URLs and bot tokens, i.e. credentials. It is
      // ALWAYS exported redacted; the import side then keeps whatever the
      // target already had, and creates unknown channels disabled.
      //
      // This used to honour `?includeSecrets=true`, which
      // handed back every Discord/Slack/Teams webhook URL and every bot token
      // of the tenant in one downloadable JSON file. That flag contradicted
      // this file's own contract ("SECRETS ARE NEVER EXPORTED", top of file)
      // and, once `GET /api/notifications/channels` started redacting, it was
      // simply the same leak one route to the left — the identical
      // "two paths, one fixed" shape as #18 and #19 below. It is gone: a
      // bundle is a plain JSON file that travels by e-mail and chat, and no
      // query parameter should turn it into a credential dump.
      if (want('notificationChannels')) {
        const channels = await db('notification_channels').where({ tenant_id: tenantId }).orderBy('id');
        const channelIds = channels.map((c) => c.id as number);
        // `notification_bindings.tenant_id` exists since a later fix. A channel shared to several tenants carries one binding row PER
        // tenant; exporting them all would ship another client's routing.
        const bindings = channelIds.length
          ? await db('notification_bindings')
              .where({ tenant_id: tenantId })
              .whereIn('channel_id', channelIds)
              .orderBy('channel_id')
          : [];

        entities.notificationChannels = channels.map((c) => ({
          uuid: c.uuid,
          name: c.name,
          type: c.type,
          config: null,
          configRedacted: true,
          isEnabled: c.is_enabled,
          bindings: bindings
            .filter((b) => b.channel_id === c.id)
            .map((b) => ({
              scope: b.scope,
              scopeUuid: b.scope === 'group' ? (groupUuidById.get(b.scope_id) ?? null) : null,
              overrideMode: b.override_mode,
            }))
            .filter((b) => b.scope === 'global' || b.scopeUuid !== null),
        }));
      }

      // -- Teams + permissions (memberships excluded: users are never exported) ---
      if (want('teams')) {
        const teams = await db('user_teams').where({ tenant_id: tenantId }).orderBy('id');
        const teamIds = teams.map((t) => t.id as number);
        const permissions = teamIds.length
          ? await db('team_permissions').whereIn('team_id', teamIds).orderBy('team_id')
          : [];

        entities.teams = teams.map((t) => ({
          uuid: t.uuid,
          name: t.name,
          description: t.description,
          canCreate: t.can_create,
          permissions: permissions
            .filter((p) => p.team_id === t.id && p.scope === 'group')
            .map((p) => ({
              scope: 'group',
              scopeUuid: groupUuidById.get(p.scope_id) ?? null,
              level: p.level,
              capabilities: Array.isArray(p.capabilities)
                ? sanitizeCapabilities(p.capabilities as unknown[])
                : null,
            }))
            .filter((p) => p.scopeUuid !== null),
        }));
      }

      // -- Fleet: sites, devices, transports -------------------------------
      //
      // ┌─ WHAT LEAVES AND WHAT NEVER DOES ────────────────────────────────┐
      // │ STRUCTURE leaves: a site, a box, the fact that it is reached over │
      // │ SSH on port 22 as `obliwan-svc`. The SECRET does not — neither    │
      // │ `secret_enc` nor `private_key_enc` is read here, and they are not │
      // │ merely redacted: they are never selected. A bundle is a JSON file │
      // │ that travels by e-mail, and a redacted field is one               │
      // │ refactor away from an un-redacted one.                            │
      // │                                                                  │
      // │ An imported device therefore arrives WITHOUT credentials, which  │
      // │ is why it also arrives `status: 'pending'` and unmanaged: it must │
      // │ be given a secret and bound by a human before anything dials it   │
      // │ (identity rule). Importing a fleet is not adopting one.           │
      // └──────────────────────────────────────────────────────────────────┘
      const siteUuidById = new Map<number, string>();
      const deviceUuidById = new Map<number, string>();
      if (want('sites') || want('devices') || want('deviceTransports')) {
        for (const s of await db('sites').where({ tenant_id: tenantId }).select('id', 'uuid')) {
          siteUuidById.set(Number(s.id), String(s.uuid));
        }
        for (const d of await db('devices').where({ tenant_id: tenantId }).select('id', 'uuid')) {
          deviceUuidById.set(Number(d.id), String(d.uuid));
        }
      }

      if (want('sites')) {
        const sites = await db('sites').where({ tenant_id: tenantId }).orderBy('id');
        entities.sites = sites.map((s) => ({
          uuid: s.uuid,
          code: s.code,
          name: s.name,
          address: s.address,
          contact: s.contact,
          timezone: s.timezone,
          maintenanceWindow: s.maintenance_window,
        }));
      }

      if (want('devices')) {
        const devices = await db('devices').where({ tenant_id: tenantId }).orderBy('id');

        // A CPE may point at a concentrator in its own tenant OR at the
        // operator's shared CHR in the master tenant (assertReferencesInTenant,
        // fleet/device.service.ts). Mapping through `deviceUuidById` alone —
        // this tenant's rows — exported every CPE behind the shared CHR with
        // `concentratorUuid: null`, and a restore of that bundle then detached
        // them from their presence source.
        //
        // A map of its own, NOT an addition to `deviceUuidById`: that map also
        // decides whose transports leave in `deviceTransports`, and the
        // operator's CHR and its channel rows are not this customer's to carry.
        // Only the uuid of a concentrator one of this tenant's CPEs points at
        // leaves — an identifier of our own box, never its address or account.
        const concentratorUuidById = new Map<number, string>(deviceUuidById);
        const sharedIds = [
          ...new Set(
            devices
              .map((d) => (d.concentrator_id === null ? null : Number(d.concentrator_id)))
              .filter((id): id is number => id !== null && !deviceUuidById.has(id)),
          ),
        ];
        if (sharedIds.length > 0) {
          for (const c of await db('devices')
            .whereIn('id', sharedIds)
            .where({ tenant_id: MASTER_TENANT_ID, role: 'concentrator' })
            .select('id', 'uuid')) {
            concentratorUuidById.set(Number(c.id), String(c.uuid));
          }
        }

        entities.devices = devices.map((d) => ({
          uuid: d.uuid,
          name: d.name,
          brand: d.brand,
          family: d.family,
          model: d.model,
          osVersion: d.os_version,
          role: d.role,
          notes: d.notes,
          siteUuid: d.site_id === null ? null : siteUuidById.get(Number(d.site_id)) ?? null,
          groupUuid: d.group_id === null ? null : groupUuidById.get(Number(d.group_id)) ?? null,
          concentratorUuid:
            d.concentrator_id === null ? null : concentratorUuidById.get(Number(d.concentrator_id)) ?? null,
          // Identity travels: it is what lets the far side recognise the
          // same box rather than create a second row for it. `serial` and
          // `system_identity` are observations, not secrets.
          serial: d.serial,
          systemIdentity: d.system_identity,
          pppUsername: d.ppp_username,
          // `status` and `is_managed` are deliberately NOT exported — see the
          // box above. The importer forces `pending` / false.
        }));
      }

      if (want('deviceTransports')) {
        const transports = await db('device_transports')
          .whereIn('device_id', [...deviceUuidById.keys()])
          .orderBy(['device_id', 'priority']);
        entities.deviceTransports = transports.map((t) => ({
          deviceUuid: deviceUuidById.get(Number(t.device_id)) ?? null,
          transport: t.transport,
          enabled: t.enabled,
          priority: t.priority,
          host: t.host,
          port: t.port,
          username: t.username,
          // secret_enc / private_key_enc: never selected. Not redacted — absent.
        })).filter((t) => t.deviceUuid !== null);
      }

      const payload = {
        meta: {
          formatVersion: FORMAT_VERSION,
          producedBy: 'obliwan',
          producedAt: new Date().toISOString(),
          // ── Deliberately null, and deliberately still present ─────────────
          // The bundle format is explicit: a bundle carries
          // no username, no instance URL and no IP address, because it travels
          // by mail and by chat and has no business betraying the sender's
          // topology. This read `process.env.APP_URL`, which was never set in
          // any deployment — so it has always emitted null and the intended
          // leak never happened by accident rather than by design.
          //
          // The FIELD stays because `BundleMeta.sourceInstance` is part of the
          // format (`shared/src/types.ts`) and an importer reading an older
          // bundle must still find the key. Filling it is what is forbidden.
          sourceInstance: null,
          tenantSlug: tenant?.slug ?? 'unknown',
          entityCounts: Object.fromEntries(
            Object.entries(entities).map(([k, v]) => [k, v.length]),
          ),
        },
        sections: selected,
        entities,
        // Kept at the top level too, so an operator can diff two bundles without
        // learning the envelope.
        ...entities,
      };

      const filename = `obliwan-export-${new Date().toISOString().slice(0, 10)}.json`;
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Content-Type', 'application/json');
      res.json(payload);
    } catch (err) {
      next(err);
    }
  },

  // -- IMPORT ----------------------------------------------------------------

  async importData(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const {
        sections,
        data,
        conflictStrategy = 'update',
      } = req.body as {
        sections: string[];
        data: Record<string, unknown>;
        conflictStrategy: ConflictStrategy;
      };

      if (!Array.isArray(sections) || sections.length === 0) {
        throw new AppError(400, 'sections array is required');
      }
      const unknownSections = sections.filter((s) => !isSection(s));
      if (unknownSections.length > 0) {
        throw new AppError(400, `Unknown section(s): ${unknownSections.join(', ')}`);
      }
      if (!data || typeof data !== 'object') {
        throw new AppError(400, 'data object is required');
      }
      if (!CONFLICT_STRATEGIES.includes(conflictStrategy)) {
        throw new AppError(400, `conflictStrategy must be one of: ${CONFLICT_STRATEGIES.join(', ')}`);
      }

      // Accept both the enveloped bundle ({ entities: {...} }) and the flat
      // legacy shape, so an older export still restores.
      const bundle = (data.entities && typeof data.entities === 'object'
        ? data.entities
        : data) as Record<string, unknown>;

      const want = (s: ExportSection) => sections.includes(s);
      // Was `req.session.currentTenantId ?? 1`,
      // i.e. the MASTER tenant for any admin session with no current tenant.
      // `requireTenant` (importExport.routes.ts) now guarantees req.tenantId.
      const tenantId = req.tenantId;
      const results: Record<string, SectionResult> = {};

      await db.transaction(async (trx) => {
        // -- Existing UUID -> id maps, scoped to the target tenant --------------
        const groupIdByUuid = new Map<string, number>();
        const channelIdByUuid = new Map<string, number>();
        const teamIdByUuid = new Map<string, number>();

        for (const r of await trx('device_groups').where({ tenant_id: tenantId }).select('id', 'uuid'))
          groupIdByUuid.set(r.uuid, r.id);
        for (const r of await trx('notification_channels').where({ tenant_id: tenantId }).select('id', 'uuid'))
          channelIdByUuid.set(r.uuid, r.id);
        for (const r of await trx('user_teams').where({ tenant_id: tenantId }).select('id', 'uuid'))
          teamIdByUuid.set(r.uuid, r.id);

        // Original-UUID -> new id for items created in THIS run, so a child can
        // resolve a parent that generateNew just gave a fresh UUID to.
        const batchGroupByOrigUuid = new Map<string, number>();

        const resolveGroup = (uuid: string | null | undefined): number | null => {
          if (!uuid) return null;
          return batchGroupByOrigUuid.get(uuid) ?? groupIdByUuid.get(uuid) ?? null;
        };

        // -- Cross-tenant UUID collision pre-check ------------------------------
        // The uuid columns are UNIQUE across the WHOLE table, not per tenant. If
        // an imported UUID belongs to a DIFFERENT tenant we must neither INSERT
        // it (unique violation -> 500) nor UPDATE it (silently mutating another
        // tenant's data). Those are forced to 'generateNew' whatever the caller
        // asked for.
        const listOf = (key: string): Record<string, unknown>[] =>
          Array.isArray(bundle[key]) ? (bundle[key] as Record<string, unknown>[]) : [];

        const uuidsOf = (key: string): string[] =>
          listOf(key).map((i) => i.uuid).filter((u): u is string => typeof u === 'string');

        const foreignUuids = async (
          table: string,
          uuids: string[],
        ): Promise<Set<string>> => {
          if (uuids.length === 0) return new Set();
          const rows = await trx(table)
            .whereIn('uuid', uuids)
            .whereNot({ tenant_id: tenantId })
            .pluck('uuid');
          return new Set<string>(rows as string[]);
        };

        const foreignGroupUuids = await foreignUuids('device_groups', uuidsOf('deviceGroups'));
        const foreignChannelUuids = await foreignUuids('notification_channels', uuidsOf('notificationChannels'));
        const foreignTeamUuids = await foreignUuids('user_teams', uuidsOf('teams'));

        /**
         * Decide the effective (uuid, action) for one incoming item.
         *   no UUID                    -> create with a fresh one
         *   UUID owned by another tenant -> create with a fresh one (forced)
         *   UUID absent from this tenant -> create, keeping the UUID
         *   UUID already here           -> apply conflictStrategy
         */
        type Decision =
          | { action: 'create'; uuid: string }
          | { action: 'update'; uuid: string; existingId: number }
          | { action: 'skip' };

        function resolveConflict(
          inputUuid: unknown,
          idMap: Map<string, number>,
          foreign: Set<string>,
        ): Decision {
          if (typeof inputUuid !== 'string' || !inputUuid) {
            return { action: 'create', uuid: randomUUID() };
          }
          if (foreign.has(inputUuid)) {
            return { action: 'create', uuid: randomUUID() };
          }
          const existingId = idMap.get(inputUuid);
          if (existingId === undefined) {
            return { action: 'create', uuid: inputUuid };
          }
          if (conflictStrategy === 'update') return { action: 'update', uuid: inputUuid, existingId };
          if (conflictStrategy === 'generateNew') return { action: 'create', uuid: randomUUID() };
          return { action: 'skip' };
        }

        // -- Device groups -------------------------------------------------------
        if (want('deviceGroups')) {
          let created = 0, updated = 0, skipped = 0;

          // A cycle in `parentUuid` used to be ordered
          // arbitrarily and processed anyway, which made `reparentGroupClosure`
          // reinsert a `(g, g)` pair and blow up on `group_closure_pkey`: a bare
          // 500, the WHOLE bundle rolled back, and nothing telling the operator
          // which lines of the JSON to fix. Refuse BEFORE writing anything, and
          // name every offending uuid in one pass rather than one per attempt.
          let sorted: Record<string, unknown>[];
          try {
            sorted = topoSort(listOf('deviceGroups'), 'uuid', 'parentUuid');
          } catch (err) {
            if (!(err instanceof CycleError)) throw err;
            const all = findCycles(listOf('deviceGroups'), 'uuid', 'parentUuid');
            const names = new Map<string, string>();
            for (const g of listOf('deviceGroups')) {
              if (typeof g.uuid === 'string' && typeof g.name === 'string') names.set(g.uuid, g.name);
            }
            const listed = (all.length > 0 ? all : err.allCyclicKeys)
              .map((u) => (names.has(u) ? `"${names.get(u)}" (${u})` : u))
              .join(', ');
            throw new AppError(
              400,
              'Import aborted: deviceGroups contains a circular parentUuid reference, ' +
                'so no group could be placed and nothing was imported. ' +
                `Set parentUuid to null (or to a group outside the loop) on: ${listed}. ` +
                `Shortest loop found: ${err.cycle.join(' -> ')}.`,
            );
          }

          for (const g of sorted) {
            if (!g.name) { skipped++; continue; }

            const decision = resolveConflict(g.uuid, groupIdByUuid, foreignGroupUuids);
            const parentId = resolveGroup(g.parentUuid as string | null | undefined);

            if (decision.action === 'skip') {
              // Still register the mapping so children resolve their parent.
              const existing = groupIdByUuid.get(g.uuid as string);
              if (existing !== undefined) batchGroupByOrigUuid.set(g.uuid as string, existing);
              skipped++;
              continue;
            }

            if (decision.action === 'update') {
              await trx('device_groups').where({ uuid: decision.uuid, tenant_id: tenantId }).update({
                name: g.name,
                description: (g.description as string | null) ?? null,
                sort_order: (g.sortOrder as number) ?? 0,
                is_general: (g.isGeneral as boolean) ?? false,
                group_notifications: (g.groupNotifications as boolean) ?? false,
                parent_id: parentId,
                updated_at: new Date(),
              });
              // A changed parent MUST be reflected in the closure table.
              await reparentGroupClosure(trx, decision.existingId, parentId);
              batchGroupByOrigUuid.set(decision.uuid, decision.existingId);
              if (typeof g.uuid === 'string') batchGroupByOrigUuid.set(g.uuid, decision.existingId);
              updated++;
            } else {
              const slug = await ensureUniqueSlugTrx(trx, slugify(g.name as string), tenantId);
              const [row] = await trx('device_groups').insert({
                uuid: decision.uuid,
                name: g.name,
                slug,
                description: (g.description as string | null) ?? null,
                parent_id: parentId,
                sort_order: (g.sortOrder as number) ?? 0,
                is_general: (g.isGeneral as boolean) ?? false,
                group_notifications: (g.groupNotifications as boolean) ?? false,
                tenant_id: tenantId,
              }).returning('id');

              await insertGroupClosure(trx, row.id, parentId);
              groupIdByUuid.set(decision.uuid, row.id);
              batchGroupByOrigUuid.set(decision.uuid, row.id);
              if (typeof g.uuid === 'string') batchGroupByOrigUuid.set(g.uuid, row.id);
              created++;
            }
          }
          results.deviceGroups = { created, updated, skipped };
        }

        // -- Settings -------------------------------------------------------------
        if (want('settings')) {
          let created = 0, skipped = 0;

          for (const s of listOf('settings')) {
            if (!s.scope || !s.key) { skipped++; continue; }
            const scope = s.scope as string;
            if (scope !== 'global' && scope !== 'group') { skipped++; continue; }

            let scopeId: number | null = null;
            if (scope === 'group') {
              scopeId = resolveGroup(s.scopeUuid as string | null | undefined);
              if (scopeId === null) { skipped++; continue; }
            }

            // Same validation as the API (see
            // parseSettingValue) and the SAME write path: `_write` names the
            // partial unique index explicitly, which is what the previous
            // DELETE-then-INSERT existed to avoid having to do.
            const { key, value } = parseSettingValue(s.key, s.value);
            await settingsService._write(trx, tenantId, scope, scopeId, key, value);
            created++;
          }
          results.settings = { created, updated: 0, skipped };
        }

        // -- Notification channels ------------------------------------------------
        if (want('notificationChannels')) {
          let created = 0, updated = 0, skipped = 0;
          const warnings: string[] = [];

          for (const c of listOf('notificationChannels')) {
            if (!c.name || !c.type) { skipped++; continue; }

            const decision = resolveConflict(c.uuid, channelIdByUuid, foreignChannelUuids);
            if (decision.action === 'skip') { skipped++; continue; }

            // A redacted export carries no config. Updating an existing channel
            // must then LEAVE its secrets alone; creating one yields a disabled
            // channel the operator has to fill in, never a silently broken one.
            const redacted = c.configRedacted === true || c.config == null;
            let parsedConfig: Record<string, unknown> = {};
            if (!redacted) {
              try {
                parsedConfig = (typeof c.config === 'string'
                  ? JSON.parse(c.config)
                  : c.config) as Record<string, unknown>;
              } catch {
                skipped++;
                warnings.push(`Channel "${String(c.name)}": config is not valid JSON, channel skipped.`);
                continue;
              }
              if (!parsedConfig || typeof parsedConfig !== 'object') parsedConfig = {};
            }

            // Import side of the foreign-SMTP rule — see scrubForeignSmtpRef.
            const scrubbed = redacted
              ? { config: parsedConfig, disabled: false }
              : await scrubForeignSmtpRef(trx, parsedConfig, tenantId, String(c.name), warnings);
            const configValue = JSON.stringify(scrubbed.config);

            // Enablement. A redacted bundle says nothing about the config, so
            // what it implies depends on whether the channel already exists:
            //   create + redacted -> DISABLED. There is no config at all; an
            //     enabled channel with an empty config fails on the first
            //     outage, which is the worst moment to discover it.
            //   update + redacted -> the stored config (secret included) is
            //     left untouched a few lines below, so the channel still works.
            //     Forcing it off here would mean "restoring your own backup
            //     silently switches off all your alerting" — and since every
            //     export is redacted (see the note in exportData), that would
            //     be EVERY restore. Honour the flag the bundle carries.
            // `scrubbed.disabled` always wins: a channel whose smtpServerId was
            // dropped must not fire through a relay it no longer names.
            const isCreate = decision.action !== 'update';
            const channelRow: Record<string, unknown> = {
              name: c.name,
              type: c.type,
              is_enabled:
                scrubbed.disabled || (redacted && isCreate)
                  ? false
                  : ((c.isEnabled as boolean) ?? true),
              tenant_id: tenantId,
              updated_at: new Date(),
            };
            if (!redacted) channelRow.config = configValue;

            let channelId: number;
            if (decision.action === 'update') {
              await trx('notification_channels').where({ uuid: decision.uuid, tenant_id: tenantId }).update(channelRow);
              channelId = decision.existingId;
              updated++;
            } else {
              const [inserted] = await trx('notification_channels')
                .insert({ ...channelRow, config: redacted ? '{}' : configValue, uuid: decision.uuid })
                .returning('id');
              channelId = inserted.id;
              channelIdByUuid.set(decision.uuid, channelId);
              if (typeof c.uuid === 'string') channelIdByUuid.set(c.uuid, channelId);
              created++;
            }

            // Rebuild the bindings from the bundle (delete then re-insert).
            if (Array.isArray(c.bindings)) {
              // Scoped to the importing tenant: a channel shared with another
              // tenant keeps ITS bindings.
              await trx('notification_bindings')
                .where({ channel_id: channelId, tenant_id: tenantId })
                .del();
              for (const b of c.bindings as Record<string, unknown>[]) {
                const bScope = b.scope as string;
                if (bScope !== 'global' && bScope !== 'group') continue;

                // `override_mode` used to be taken verbatim.
                // A "Replace" from a hand-edited bundle was stored and then
                // silently treated as a merge: a group meant to alert ONLY its
                // dedicated channel started notifying every inherited one.
                // The CHECK added in migration 001 would now abort the whole
                // import transaction, so filter here and report it as skipped.
                const mode = (b.overrideMode as string) ?? 'merge';
                if (mode !== 'merge' && mode !== 'replace' && mode !== 'exclude') {
                  skipped++;
                  continue;
                }

                let bScopeId: number | null = null;
                if (bScope === 'group') {
                  bScopeId = resolveGroup(b.scopeUuid as string | null | undefined);
                  if (bScopeId === null) continue;
                }

                await trx('notification_bindings').insert({
                  tenant_id: tenantId,
                  channel_id: channelId,
                  scope: bScope,
                  scope_id: bScopeId,
                  override_mode: mode,
                });
              }
            }
          }
          results.notificationChannels = warnings.length
            ? { created, updated, skipped, warnings }
            : { created, updated, skipped };
        }

        // -- Teams ----------------------------------------------------------------
        if (want('teams')) {
          let created = 0, updated = 0, skipped = 0;

          for (const t of listOf('teams')) {
            if (!t.name) { skipped++; continue; }

            const decision = resolveConflict(t.uuid, teamIdByUuid, foreignTeamUuids);
            if (decision.action === 'skip') { skipped++; continue; }

            const teamRow: Record<string, unknown> = {
              name: t.name,
              description: (t.description as string | null) ?? null,
              can_create: (t.canCreate as boolean) ?? false,
              tenant_id: tenantId,
              updated_at: new Date(),
            };

            let teamId: number;
            if (decision.action === 'update') {
              // user_teams.name is globally UNIQUE: a rename onto a name another
              // team already holds must not abort the whole import.
              const nameOwner = await trx('user_teams').where({ name: t.name, tenant_id: tenantId }).first('id') as { id: number } | undefined;
              if (nameOwner && nameOwner.id !== decision.existingId) {
                delete teamRow.name;
              }
              await trx('user_teams').where({ uuid: decision.uuid, tenant_id: tenantId }).update(teamRow);
              teamId = decision.existingId;
              updated++;
            } else {
              const nameConflict = await trx('user_teams').where({ name: t.name, tenant_id: tenantId }).first();
              if (nameConflict) { skipped++; continue; }

              const [inserted] = await trx('user_teams').insert({ ...teamRow, uuid: decision.uuid }).returning('id');
              teamId = inserted.id;
              teamIdByUuid.set(decision.uuid, teamId);
              if (typeof t.uuid === 'string') teamIdByUuid.set(t.uuid, teamId);
              created++;
            }

            if (Array.isArray(t.permissions)) {
              // The DELETE below
              // used to drop `capabilities` on the floor. A bundle whose team
              // entries carry no `capabilities` key (every bundle produced
              // before FORMAT_VERSION 2, and every hand-written one) silently
              // wiped every capability pinned onto that team's grants, on a
              // column no screen displays: the operator restores a backup and
              // discovers weeks later that half his delegated rights are gone.
              //
              // `teamService.setPermissions` solved this exact problem by
              // reading the pinned lists back BEFORE the delete and re-attaching
              // them to the (scope, scope_id) pairs that survive the edit. Two
              // write paths onto `team_permissions`, one corrected and one not,
              // is precisely the divergence this change exists to close — so the
              // import now follows the same rule, with one difference stated
              // explicitly: a bundle that DOES carry `capabilities` is an
              // intentional statement and overrides the pinned list (including
              // an empty array, which clears it).
              const previous = await trx('team_permissions')
                .where({ team_id: teamId })
                .whereNotNull('capabilities')
                .select('scope', 'scope_id', 'capabilities');
              const pinned = new Map<string, unknown>(
                previous.map((p) => [`${p.scope}:${p.scope_id}`, p.capabilities]),
              );

              await trx('team_permissions').where({ team_id: teamId }).del();
              for (const p of t.permissions as Record<string, unknown>[]) {
                if (p.scope !== 'group') continue;
                const scopeId = resolveGroup(p.scopeUuid as string | null | undefined);
                if (scopeId === null) continue;

                let capabilities: string | null;
                if (Array.isArray(p.capabilities)) {
                  // Capabilities are re-validated against the current
                  // vocabulary: a bundle from an older instance may name
                  // capabilities that no longer exist, and those must not be
                  // persisted.
                  const caps = sanitizeCapabilities(p.capabilities as unknown[]);
                  capabilities = caps.length > 0 ? JSON.stringify(caps) : null;
                } else {
                  // Absent (or null) means "the bundle says nothing about
                  // capabilities" — carry what this instance already had.
                  const carried = pinned.get(`group:${scopeId}`);
                  // knex needs a string (or null) for a jsonb column; the pg
                  // driver hands `capabilities` back already parsed.
                  capabilities =
                    carried === undefined || carried === null
                      ? null
                      : typeof carried === 'string'
                        ? carried
                        : JSON.stringify(carried);
                }

                await trx('team_permissions').insert({
                  team_id: teamId,
                  scope: 'group',
                  scope_id: scopeId,
                  level: p.level === 'rw' ? 'rw' : 'ro',
                  capabilities,
                }).onConflict(['team_id', 'scope', 'scope_id']).ignore();
              }
            }
          }
          results.teams = { created, updated, skipped };
        }

        // -- Fleet: sites, devices, transports ------------------------------
        //
        // ┌─ AN IMPORTED DEVICE IS NEVER A MANAGED DEVICE ──────────────────┐
        // │ Every device created here lands `status: 'pending'` and         │
        // │ `is_managed: false`, whatever the bundle says — the exporter    │
        // │ does not even emit those two fields. It is the same quarantine  │
        // │ CHR discovery uses, and for the same reason: a row              │
        // │ that arrived in a JSON file is a CLAIM about a box, and a claim │
        // │ must be confirmed on a fresh connection before anything is      │
        // │ pushed to it. Nothing dials a device this code created.         │
        // │                                                                 │
        // │ No credential crosses either, so an imported device could not   │
        // │ be dialled even if it were managed. Adopting a fleet is a       │
        // │ deliberate act performed per device, not a side effect of a     │
        // │ restore.                                                        │
        // └─────────────────────────────────────────────────────────────────┘
        const siteIdByUuid = new Map<string, number>();
        const deviceIdByUuid = new Map<string, number>();
        // What the device loop did with each device line, keyed on the
        // bundle's uuid: the transport loop gives a channel the same fate as
        // its device. Absent = the device is not in this run's devices section.
        const deviceFateByUuid = new Map<string, 'created' | 'updated' | 'skipped'>();
        // A channel's stored credential, removed in one write. Used by both
        // loops below — see "A STORED CREDENTIAL STAYS WITH ITS DESTINATION".
        const clearedCredential = {
          secret_enc: null,
          private_key_enc: null,
          // Both or neither (device_transports_secret_next_chk).
          secret_next_enc: null,
          secret_next_key_version: null,
          secret_next_at: null,
        };
        if (want('sites') || want('devices') || want('deviceTransports')) {
          for (const s of await trx('sites').where({ tenant_id: tenantId }).select('id', 'uuid')) {
            siteIdByUuid.set(String(s.uuid), Number(s.id));
          }
          for (const d of await trx('devices').where({ tenant_id: tenantId }).select('id', 'uuid')) {
            deviceIdByUuid.set(String(d.uuid), Number(d.id));
          }
        }

        if (want('sites')) {
          let created = 0, updated = 0, skipped = 0;
          const foreignSiteUuids = await foreignUuids('sites', uuidsOf('sites'));

          for (const s of listOf('sites')) {
            if (!s.name || !s.code) { skipped++; continue; }
            const decision = resolveConflict(s.uuid, siteIdByUuid, foreignSiteUuids);
            if (decision.action === 'skip') { skipped++; continue; }

            const fields = {
              code: s.code as string,
              name: s.name as string,
              address: (s.address as string | null) ?? null,
              contact: (s.contact as string | null) ?? null,
              timezone: (s.timezone as string) ?? 'Europe/Paris',
              maintenance_window: (s.maintenanceWindow as unknown) ?? null,
            };

            if (decision.action === 'update') {
              await trx('sites')
                .where({ uuid: decision.uuid, tenant_id: tenantId })
                .update({ ...fields, updated_at: new Date() });
              siteIdByUuid.set(decision.uuid, decision.existingId);
              updated++;
            } else {
              const [row] = await trx('sites')
                .insert({ uuid: decision.uuid, tenant_id: tenantId, ...fields })
                .returning('id');
              siteIdByUuid.set(decision.uuid, Number(row.id));
              if (typeof s.uuid === 'string') siteIdByUuid.set(s.uuid, Number(row.id));
              created++;
            }
          }
          results.sites = { created, updated, skipped };
        }

        if (want('devices')) {
          let created = 0, updated = 0, skipped = 0;
          const foreignDeviceUuids = await foreignUuids('devices', uuidsOf('devices'));

          const warnings: string[] = [];

          // Concentrators first: a CPE points at one, and a forward reference
          // would otherwise resolve to null and silently orphan the site.
          const ordered = [...listOf('devices')].sort(
            (a, b) => (a.role === 'concentrator' ? 0 : 1) - (b.role === 'concentrator' ? 0 : 1),
          );

          // The operator's shared CHRs: a CPE of any tenant may point at a
          // concentrator of the master tenant (assertReferencesInTenant,
          // fleet/device.service.ts), and the exporter now names it. Consulted
          // AFTER this tenant's own rows — those created earlier in this run
          // included — so a bundle carrying its own concentrator keeps pointing
          // at its own copy. Only master-tenant `role = 'concentrator'` rows:
          // another customer's device is never a target, whatever uuid a bundle
          // names.
          //
          // That makes this a path that writes a (shared concentrator,
          // ppp_username) pair directly, which `createDevice` reserves to a
          // platform administrator. It is one: this route is
          // `requireRole('admin')` (importExport.routes.ts).
          const sharedConcentratorIdByUuid = new Map<string, number>();
          for (const c of await trx('devices')
            .where({ tenant_id: MASTER_TENANT_ID, role: 'concentrator' })
            .select('id', 'uuid')) {
            sharedConcentratorIdByUuid.set(String(c.uuid), Number(c.id));
          }

          for (const d of ordered) {
            if (!d.name || !d.brand || !d.family) {
              if (typeof d.uuid === 'string') deviceFateByUuid.set(d.uuid, 'skipped');
              skipped++;
              continue;
            }
            const decision = resolveConflict(d.uuid, deviceIdByUuid, foreignDeviceUuids);
            if (decision.action === 'skip') {
              if (typeof d.uuid === 'string') deviceFateByUuid.set(d.uuid, 'skipped');
              skipped++;
              continue;
            }

            const siteUuid = d.siteUuid as string | null | undefined;
            const concUuid = d.concentratorUuid as string | null | undefined;
            const concentratorId = concUuid
              ? deviceIdByUuid.get(concUuid) ?? sharedConcentratorIdByUuid.get(concUuid) ?? null
              : null;
            // The bundle NAMES a concentrator that cannot be referenced here: a
            // different instance's CHR, one left out of the bundle, or another
            // customer's CHR on THIS instance — deliberately unresolvable, and
            // the warning must not say which of the three it is. That is not an
            // instruction to detach: on an update the device keeps the
            // concentrator it has. Either way a warning goes into
            // `results.devices.warnings` — a CPE with no concentrator has no
            // presence source. The import page shows these warnings under
            // each section's counts (ImportExportPage.tsx, `warningsOf`).
            const concentratorUnresolved = Boolean(concUuid) && concentratorId === null;
            const fields = {
              name: d.name as string,
              brand: d.brand as string,
              family: d.family as string,
              model: (d.model as string | null) ?? null,
              os_version: (d.osVersion as string | null) ?? null,
              role: (d.role as string) ?? 'cpe',
              notes: (d.notes as string | null) ?? null,
              site_id: siteUuid ? siteIdByUuid.get(siteUuid) ?? null : null,
              group_id: resolveGroup(d.groupUuid as string | null | undefined),
              serial: (d.serial as string | null) ?? null,
              system_identity: (d.systemIdentity as string | null) ?? null,
              ppp_username: (d.pppUsername as string | null) ?? null,
            };

            if (decision.action === 'update') {
              // `status` and `is_managed` are NOT touched on update: a device
              // already adopted on this instance must not be sent back to
              // quarantine by a restore, and one still pending must not be
              // promoted by one. Neither is `concentrator_id` when the bundle's
              // reference does not resolve (see above).
              //
              // `serial`, `system_identity` and `ppp_username` ARE overwritten
              // from the file, to NULL where it has none. That rewrites the
              // identity columns `assertTargetBinding` compares against,
              // and it is an open decision, not settled here. The one
              // consequence settled here is the credential's: see the pair
              // check below.
              //
              // The (concentrator, PPP username) pair as it stands BEFORE the
              // write, locked so nothing moves it between this read and the
              // UPDATE.
              const pairBefore = await trx('devices')
                .where({ uuid: decision.uuid, tenant_id: tenantId })
                .forUpdate()
                .first<{ concentrator_id: number | null; ppp_username: string | null } | undefined>(
                  'concentrator_id',
                  'ppp_username',
                );
              await trx('devices')
                .where({ uuid: decision.uuid, tenant_id: tenantId })
                .update({
                  ...fields,
                  ...(concentratorUnresolved ? {} : { concentrator_id: concentratorId }),
                  updated_at: new Date(),
                });
              deviceIdByUuid.set(decision.uuid, decision.existingId);
              deviceFateByUuid.set(decision.uuid, 'updated');
              if (concentratorUnresolved) {
                warnings.push(
                  `Device "${String(d.name)}": concentrator ${String(concUuid)} cannot be ` +
                    'referenced here (it is not in this tenant nor shared infrastructure on this ' +
                    'instance); the device\'s concentrator was left as it was.',
                );
              }

              // A channel with NO host is dialled at `devices.tunnel_ip`
              // (routerosPool: `host ?? tunnel_ip`), and presence writes
              // tunnel_ip onto whichever device carries the (concentrator,
              // ppp_username) pair of a session that comes up
              // (pppPresence.applySessionUp). So when this write MOVES the
              // pair, every host-less channel of the device is re-pointed at
              // another session's address without its own host, port or
              // username changing — the transport loop's comparison cannot
              // see it. A name an old bundle carries may since belong to
              // another customer's site, still in quarantine and so held by no
              // device: no 23505, and the next poll would log in to that site
              // with this device's vault password. Those channels lose their
              // stored credential in this same transaction, with a warning. An
              // unchanged pair — the same bundle restored twice — keeps it.
              const beforeConcentrator =
                pairBefore?.concentrator_id == null ? null : Number(pairBefore.concentrator_id);
              const afterConcentrator = concentratorUnresolved ? beforeConcentrator : concentratorId;
              const pairMoved =
                pairBefore !== undefined &&
                (beforeConcentrator !== afterConcentrator ||
                  (pairBefore.ppp_username ?? null) !== fields.ppp_username);
              if (pairMoved) {
                const cleared = await trx('device_transports')
                  .where({ device_id: decision.existingId })
                  .whereNull('host')
                  .where((q) =>
                    q
                      .whereNotNull('secret_enc')
                      .orWhereNotNull('private_key_enc')
                      .orWhereNotNull('secret_next_enc'),
                  )
                  .update({ ...clearedCredential, updated_at: new Date() })
                  .returning<Array<{ transport: string }>>('transport');
                if (cleared.length > 0) {
                  warnings.push(
                    `Device "${String(d.name)}": its concentrator or PPP username changed, so the ` +
                      `stored credential of its channel(s) with no host of their own ` +
                      `(${cleared.map((c) => `"${c.transport}"`).join(', ')}) was removed: those ` +
                      'channels dial the tunnel address of whichever session carries the new pair. ' +
                      "Enter it again on the device's page.",
                  );
                }
              }
              updated++;
            } else {
              const [row] = await trx('devices')
                .insert({
                  uuid: decision.uuid,
                  tenant_id: tenantId,
                  ...fields,
                  concentrator_id: concentratorId,
                  status: 'pending',
                  is_managed: false,
                })
                .returning('id');
              deviceIdByUuid.set(decision.uuid, Number(row.id));
              deviceFateByUuid.set(decision.uuid, 'created');
              if (typeof d.uuid === 'string') {
                // The bundle's uuid now names the NEW row — for 'generateNew'
                // and for a uuid owned by another tenant, that is a fresh copy,
                // and its channels follow the copy, not the original.
                deviceIdByUuid.set(d.uuid, Number(row.id));
                deviceFateByUuid.set(d.uuid, 'created');
              }
              if (concentratorUnresolved) {
                warnings.push(
                  `Device "${String(d.name)}": concentrator ${String(concUuid)} cannot be ` +
                    'referenced here (it is not in this tenant nor shared infrastructure on this ' +
                    'instance); the device was created without one and has no PPP presence until ' +
                    'one is set.',
                );
              }
              created++;
            }
          }
          results.devices = warnings.length
            ? { created, updated, skipped, warnings }
            : { created, updated, skipped };
        }

        // ┌─ A CHANNEL FOLLOWS ITS DEVICE ──────────────────────────────────┐
        // │ A channel line has no uuid: it is (device, transport), and it   │
        // │ takes the fate the device loop gave its device.                 │
        // │  - device CREATED by this run (a new uuid, a 'generateNew'      │
        // │    copy, a uuid owned by another tenant and re-issued): the     │
        // │    channel goes on that new row;                                │
        // │  - device UPDATED ('update'): the channel is created, or        │
        // │    overwritten when the device already has one of that kind;    │
        // │  - device SKIPPED ('ignore', or a line the device loop          │
        // │    rejected): the channel is skipped, existing or not — a       │
        // │    device the import leaves alone is not re-pointed either.     │
        // │ A device absent from this run's devices section is an EXISTING  │
        // │ one, and the strategy says what may happen to it: 'update' lets │
        // │ its channels be written; 'ignore' and 'generateNew' never       │
        // │ modify an existing item, and no copy was made for the channel   │
        // │ to go on, so it is skipped — with a warning for 'generateNew',  │
        // │ which an operator would otherwise read as "copied".             │
        // │                                                                 │
        // │ This loop used to ignore the strategy: `deviceIdByUuid` is      │
        // │ seeded with the tenant's existing devices, so even 'ignore'     │
        // │ rewrote host, port and username on existing channels.           │
        // └─────────────────────────────────────────────────────────────────┘
        //
        // ┌─ A STORED CREDENTIAL STAYS WITH ITS DESTINATION ────────────────┐
        // │ No secret is read from the bundle, and none is written from it. │
        // │ On 'update' an existing channel KEEPS its stored credential     │
        // │ (`secret_enc`, `private_key_enc`, and a pending rotation        │
        // │ candidate) while its DESTINATION is unchanged, so restoring the │
        // │ same bundle twice does not empty the vault. When the            │
        // │ destination moves, the credential is CLEARED in the same        │
        // │ transaction, and a warning says so. Kept, it would be presented │
        // │ to whatever the file points at: the RouterOS pool dials the     │
        // │ channel's host, or `tunnel_ip` when it has none, with the       │
        // │ decrypted `secret_enc`, and a backup restored after an address  │
        // │ went to somebody else points exactly there.                     │
        // │                                                                 │
        // │ Two writes of this import can move a channel's destination, and │
        // │ each is judged where it is made:                                │
        // │ - its host, port and username: compared in this loop, and a     │
        // │   change to any of the three clears the credential;             │
        // │ - for a channel with NO host, the device's (concentrator, PPP   │
        // │   username) pair, because presence writes `tunnel_ip` from the  │
        // │   session carrying that pair: compared in the device loop       │
        // │   above, which clears the host-less channels of every device    │
        // │   whose pair it moves.                                          │
        // │                                                                 │
        // │ Cleared, the channel is what every imported channel already is: │
        // │ a route with no key, given one again on the device's page.      │
        // │ `tls_fingerprint_sha256` is not touched: it describes the old   │
        // │ destination's certificate and is not a credential, and a pin    │
        // │ that no longer matches can refuse a connection, never widen     │
        // │ one.                                                            │
        // └─────────────────────────────────────────────────────────────────┘
        if (want('deviceTransports')) {
          let created = 0, updated = 0, skipped = 0;
          const warnings: string[] = [];
          const samePort = (a: unknown, b: unknown): boolean =>
            a === null || a === undefined
              ? b === null || b === undefined
              : b !== null && b !== undefined && Number(a) === Number(b);

          for (const t of listOf('deviceTransports')) {
            const deviceUuid = typeof t.deviceUuid === 'string' && t.deviceUuid ? t.deviceUuid : null;
            const deviceId = deviceUuid === null ? undefined : deviceIdByUuid.get(deviceUuid);
            // A transport with no device is not an error worth aborting a whole
            // bundle for — it is a line the operator trimmed. Counted, skipped.
            if (deviceUuid === null || deviceId === undefined || !t.transport) { skipped++; continue; }

            // The channel follows its device: see the first box above.
            const fate =
              deviceFateByUuid.get(deviceUuid) ?? (conflictStrategy === 'update' ? 'updated' : 'skipped');
            if (fate === 'skipped') {
              if (!deviceFateByUuid.has(deviceUuid) && conflictStrategy === 'generateNew') {
                warnings.push(
                  `Channel "${String(t.transport)}" of device ${deviceUuid} was not imported: ` +
                    '"generate new" never modifies an existing device, and this import made no copy ' +
                    'of that device for the channel to go on. Import the device in the same run to ' +
                    'copy both.',
                );
              }
              skipped++;
              continue;
            }

            const key = { device_id: deviceId, transport: t.transport as string };
            const fields = {
              enabled: (t.enabled as boolean) ?? true,
              priority: (t.priority as number) ?? 100,
              host: (t.host as string | null) ?? null,
              port: (t.port as number | null) ?? null,
              username: (t.username as string | null) ?? null,
            };

            // The credential's PRESENCE, never its ciphertext: like the
            // exporter, this code does not select a secret column.
            const existing = await trx('device_transports')
              .where(key)
              .select(
                'id',
                'host',
                'port',
                'username',
                trx.raw(
                  '(secret_enc IS NOT NULL OR private_key_enc IS NOT NULL OR secret_next_enc IS NOT NULL) ' +
                    'AS has_credential',
                ),
              )
              .first<
                | { id: number; host: string | null; port: number | null; username: string | null; has_credential: boolean }
                | undefined
              >();
            if (existing) {
              const sameDestination =
                existing.host === fields.host &&
                samePort(existing.port, fields.port) &&
                existing.username === fields.username;
              await trx('device_transports')
                .where({ id: existing.id })
                .update({
                  ...fields,
                  // See the second box above.
                  ...(sameDestination ? {} : clearedCredential),
                  updated_at: new Date(),
                });
              if (!sameDestination && existing.has_credential) {
                warnings.push(
                  `Channel "${key.transport}" of device ${deviceUuid}: its host, port or username ` +
                    'changed, so its stored credential was removed rather than sent to the new ' +
                    "destination. Enter it again on the device's page.",
                );
              }
              updated++;
            } else {
              await trx('device_transports').insert({ ...key, ...fields });
              created++;
            }
          }
          results.deviceTransports = warnings.length
            ? { created, updated, skipped, warnings }
            : { created, updated, skipped };
        }
      }); // end transaction

      res.json({ success: true, data: results });
    } catch (err) {
      next(err);
    }
  },
};
