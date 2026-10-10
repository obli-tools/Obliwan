// ============================================================================
// ObliWAN — revealing a stored secret in clear (SECRET_READ)
// ============================================================================
//
// ┌─ WHY THIS EXISTS, AND WHY IT DID NOT ─────────────────────────────────────┐
// │ Originally every stored secret was write-only: `SECRET_READ` was a        │
// │ capability with no route, on the argument that an endpoint which does not │
// │ exist cannot be mis-permissioned. That was reversed: an admin             │
// │ must be able to retrieve stored passwords for debugging purposes.         │
// │ A router that refuses the vault's password, an SNMP community nobody      │
// │ remembers typing, a template variable that renders "wrong" — each is      │
// │ debugged by LOOKING at the value, and the alternative was re-typing it    │
// │ blind.                                                                    │
// │                                                                          │
// │ So the door exists, and this module is the whole of it. Three things      │
// │ make it a door rather than a hole, and none of them is optional:          │
// │                                                                          │
// │  1. TENANT-SCOPED EXACTLY LIKE THE ORDINARY READS. Every row is fetched   │
// │     with its tenant in the WHERE clause (or through a parent row that     │
// │     carries it). An id belonging to another tenant answers the SAME 404   │
// │     as an id that does not exist — never the value, never a 403 that      │
// │     confirms the id is real. The INSTANCE level has no tenant at all and  │
// │     is reserved to platform administrators, and so is everything in the   │
// │     MASTER tenant (below) — both checked here as well as at the route,    │
// │     and before any row is read.                                           │
// │  2. AUDITED BEFORE IT ANSWERS. The `audit_log` row is appended after the  │
// │     decryption succeeded and BEFORE the value is returned; if the ledger  │
// │     write fails, the caller gets an error and no value. An untraceable    │
// │     reveal is not a degraded mode, it is the failure (the rule            │
// │     `audit.service.ts` states for `command_audit`). The row names who,    │
// │     what object, when and from which address — and NEVER the plaintext,   │
// │     nor any derivative of it (no length, no hash, no prefix): the ledger  │
// │     is the one table whose purpose is to be handed to somebody else.      │
// │  3. ONE FIELD PER CALL, NOTHING LOGGED. The plaintext is returned to the  │
// │     caller and goes nowhere else: no log line, no error message, no       │
// │     cache. Error texts below name keys, ids and field names only.         │
// └──────────────────────────────────────────────────────────────────────────┘
//
// THE MASTER TENANT (id 1) is shared infrastructure: the L2TP concentrator
// lives there (allocation/seed.ts), and its RouterOS credential controls every
// customer's tunnel. Membership of tenant 1 confers nothing beyond tenant 1's
// own data (middleware/tenant.ts) — and tenant 1 is where
// "for now" accounts are parked. So a reveal in the master tenant needs a
// PLATFORM administrator, exactly like the instance level, whatever the
// caller's tenant role or by-name grants.
//
// What it deliberately does NOT reveal: a mobile-partner account credential
// (`sim_partner_accounts.credential_blob`), the allocator's PPP credential, a
// pending rotation candidate (`device_transports.secret_next_enc`, migration
// 031) and a pre-change backup's archive password. None of them is a value an
// engineer types into a console while debugging a router, and each keeps its
// own, narrower door — or none.
//
// What it DOES reveal besides, since 2026-10-06: a mobile line's PUK1, PUK2,
// RADIUS password (`sim_lines`, migration 077) and RIO (migration 079). Unlike
// the partner account's credential, those ARE typed by hand — into a phone
// unlocking a SIM, into a router's RADIUS client, into a porting form — and
// the operator decided ObliWAN keeps them (`revealSimLineSecret`, at the end
// of this file).

import {
  SIM_LINE_SECRET_FIELDS,
  TRANSPORT_KINDS,
  isMasterTenant,
  type SimLineSecretField,
  type TransportKind,
} from '@obliwan/shared';
import { db } from '../../db';
import { AppError } from '../../middleware/errorHandler';
import { logger } from '../../utils/logger';
import { decrypt } from '../secretVault.service';
import { appendAudit } from '../attestation/auditLog.service';
import { getLine } from '../sim/line.service';
import {
  FORBIDDEN_VARIABLE_KEYS,
  INSTANCE_SCOPE,
  RENDER_TIME_LEVELS,
  STORED_VARIABLE_SCOPES,
  VARIABLE_KEY_RE,
} from '../../validators/template.schema';

// ============================================================================
// Inputs
// ============================================================================

/** Who is asking. Taken from the SESSION by the route, never from the body. */
export interface RevealActor {
  userId: number;
  username: string | null;
  /** `users.role === 'admin'` as re-read by `requireAuth` — the PLATFORM role. */
  platformAdmin: boolean;
  /** `req.ip` (trust proxy = 1). Recorded in the audit row; null when unknown. */
  ip: string | null;
}

/** The two vault columns of a `device_transports` row, by their API names. */
export const TRANSPORT_SECRET_FIELDS = ['secret', 'privateKey'] as const;
export type TransportSecretField = (typeof TRANSPORT_SECRET_FIELDS)[number];

/** The three vault columns of a `snmp_credentials` row, by their API names. */
export const SNMP_SECRET_FIELDS = ['community', 'authKey', 'privKey'] as const;
export type SnmpSecretField = (typeof SNMP_SECRET_FIELDS)[number];

/** The audit action every reveal is recorded under. One verb, three entity types. */
export const SECRET_REVEALED_ACTION = 'secret.revealed';

// ============================================================================
// Shared steps
// ============================================================================

/**
 * Decrypt, or fail with a sentence that carries nothing of the blob. A
 * `VaultError` names the key generation and nothing else, but it is not
 * forwarded anyway: the status is the information an operator needs, and the
 * log line names the row, not the error text.
 */
function openBlob(blob: string, entityType: string, entityId: number | string): string {
  try {
    return decrypt(blob);
  } catch {
    logger.warn({ entityType, entityId }, 'secret reveal: the stored blob could not be decrypted');
    throw new AppError(
      500,
      'The stored secret could not be decrypted with this installation\'s vault key '
        + '(OBLIWAN_ENCRYPTION_KEY / key_version mismatch, or a damaged blob).',
    );
  }
}

/**
 * The ledger row, in the tenant the caller is operating on.
 *
 * `after` carries ONLY descriptors of the object, and its field names are
 * chosen so that `redactEvidence()` — which masks by NAME, with the generous
 * `isSecretName` predicate (`key`, `auth`, `priv`, `credential`, `community`…)
 * — keeps them: `label` and not `credentialName`, `field` and not
 * `secretField`, no `credentialId` (the id is the row's `entity_id`). A masked
 * "what was revealed" is an audit row that says nothing.
 */
async function auditReveal(
  tenantId: number,
  actor: RevealActor,
  entityType: string,
  entityId: number | string,
  after: Record<string, unknown>,
): Promise<void> {
  await appendAudit({
    tenantId,
    actorType: 'user',
    actorId: actor.userId,
    actorName: actor.username ? actor.username.slice(0, 128) : null,
    action: SECRET_REVEALED_ACTION,
    entityType,
    entityId,
    after: { ...after, ip: actor.ip },
  });
}

/** The refusal for a non-platform-admin asking for a master-tenant secret. */
export const MASTER_TENANT_REFUSAL =
  'Secrets of the master tenant (shared infrastructure) are revealed by platform administrators only.';

/**
 * Master tenant → platform administrators only (see the header). Runs before
 * any row is read, so the refusal says nothing about whether the object exists.
 */
function assertMayRevealIn(tenantId: number, actor: RevealActor): void {
  if (isMasterTenant(tenantId) && !actor.platformAdmin) {
    throw new AppError(403, MASTER_TENANT_REFUSAL);
  }
}

function positiveInt(raw: unknown, what: string): number {
  const n = typeof raw === 'string' && /^[0-9]{1,10}$/.test(raw) ? Number(raw) : raw;
  if (typeof n !== 'number' || !Number.isInteger(n) || n <= 0 || n > 2_147_483_647) {
    throw new AppError(400, `Invalid ${what}`);
  }
  return n;
}

// ============================================================================
// Template variables — `config_variables`
// ============================================================================

/** The table a scoped level's `scope_id` points into (the variables controller's map). */
const SCOPE_TABLES: Record<'group' | 'site' | 'device', string> = {
  group: 'device_groups',
  site: 'sites',
  device: 'devices',
};

/**
 * One secret template variable, at exactly one level — no inheritance: the
 * caller names the row it saw marked "set" on the variables screen.
 *
 * `instance` is reserved to platform administrators (every tenant renders
 * with it). Its audit row lands in the ledger of the tenant the administrator
 * is operating on, because `audit_log.tenant_id` is NOT NULL and the instance
 * level has no tenant of its own; `after.scope = 'instance'` says which kind of
 * row it was.
 */
export async function revealVariableSecret(input: {
  tenantId: number;
  scope: string;
  scopeId?: number | string | null;
  key: string;
  actor: RevealActor;
}): Promise<string> {
  const { tenantId, actor, scope } = input;
  assertMayRevealIn(tenantId, actor);

  if ((RENDER_TIME_LEVELS as readonly string[]).includes(scope)) {
    throw new AppError(
      400,
      `Scope "${scope}" is supplied by the caller of a render and never stored: there is nothing to reveal.`,
    );
  }
  if (!(STORED_VARIABLE_SCOPES as readonly string[]).includes(scope)) {
    throw new AppError(400, 'Unknown variable scope.');
  }
  const key = input.key;
  if (typeof key !== 'string' || !VARIABLE_KEY_RE.test(key)
    || (FORBIDDEN_VARIABLE_KEYS as readonly string[]).includes(key)) {
    throw new AppError(400, 'Invalid variable name.');
  }

  const unscoped = scope === INSTANCE_SCOPE || scope === 'global' || scope === 'tenant';
  let scopeId: number | null = null;
  if (unscoped) {
    if (input.scopeId !== null && input.scopeId !== undefined) {
      throw new AppError(400, `Scope "${scope}" must not carry a scope id.`);
    }
  } else {
    if (input.scopeId === null || input.scopeId === undefined) {
      throw new AppError(400, `Scope "${scope}" requires a scope id.`);
    }
    scopeId = positiveInt(input.scopeId, 'scope id');
  }

  type VarRow = { id: string | number; is_secret: boolean; secret_enc: string | null };
  let row: VarRow | undefined;

  if (scope === INSTANCE_SCOPE) {
    // Defence in depth: the route already refused anybody else. An instance
    // value is shared by EVERY tenant, so no tenant capability — however
    // broad — reads it; the same rule as its writes (variables.routes.ts).
    if (!actor.platformAdmin) {
      throw new AppError(403, 'Instance variables are revealed by platform administrators only.');
    }
    row = await db('config_variables')
      .whereNull('tenant_id')
      .andWhere({ scope: INSTANCE_SCOPE, key })
      .whereNull('scope_id')
      .first<VarRow | undefined>('id', 'is_secret', 'secret_enc');
  } else if (scopeId === null) {
    row = await db('config_variables')
      .where({ tenant_id: tenantId, scope, key })
      .whereNull('scope_id')
      .first<VarRow | undefined>('id', 'is_secret', 'secret_enc');
  } else {
    // `config_variables.scope_id` is polymorphic and carries no FK, so the
    // target is proven to be this tenant's first — the same check the
    // variables controller runs before any write (`assertScopeTargetOwned`).
    // The row read below is ALSO filtered on `tenant_id`, so neither check
    // alone stands between two tenants.
    const table = SCOPE_TABLES[scope as 'group' | 'site' | 'device'];
    const owner = await db(table).where({ id: scopeId, tenant_id: tenantId }).first('id');
    if (!owner) throw new AppError(404, `No ${scope} ${scopeId} in this tenant.`);
    row = await db('config_variables')
      .where({ tenant_id: tenantId, scope, scope_id: scopeId, key })
      .first<VarRow | undefined>('id', 'is_secret', 'secret_enc');
  }

  if (!row) throw new AppError(404, `No variable "${key}" is set at this level.`);
  if (!row.is_secret) {
    throw new AppError(
      400,
      `Variable "${key}" is not a secret: its value is already returned by the ordinary read.`,
    );
  }
  if (typeof row.secret_enc !== 'string' || row.secret_enc.length === 0) {
    // Migration 008's `config_variables_secret_chk` forbids it; a row that got
    // here anyway is damaged, and the resolver refuses to render it too.
    throw new AppError(404, `Variable "${key}" is marked secret but carries no stored value.`);
  }

  const value = openBlob(row.secret_enc, 'config_variable', row.id);
  await auditReveal(tenantId, actor, 'config_variable', row.id, {
    kind: 'variable',
    scope,
    scopeId,
    name: key,
  });
  return value;
}

// ============================================================================
// Device transports — `device_transports.secret_enc` / `private_key_enc`
// ============================================================================

/**
 * One secret of one channel of one device. `UNIQUE(device_id, transport)`
 * (migration 002) makes `(deviceId, transport)` name exactly one row.
 */
export async function revealTransportSecret(input: {
  tenantId: number;
  deviceId: number | string;
  transport: string;
  /** Which secret of the channel. Default `secret` (its password / community). */
  field?: string;
  actor: RevealActor;
}): Promise<string> {
  const { tenantId, actor } = input;
  assertMayRevealIn(tenantId, actor);
  const deviceId = positiveInt(input.deviceId, 'device id');
  if (!(TRANSPORT_KINDS as readonly string[]).includes(input.transport)) {
    throw new AppError(400, `Unknown transport (expected ${TRANSPORT_KINDS.join(' | ')}).`);
  }
  const transport = input.transport as TransportKind;
  const field = input.field ?? 'secret';
  if (!(TRANSPORT_SECRET_FIELDS as readonly string[]).includes(field)) {
    throw new AppError(400, `Unknown transport secret field (expected ${TRANSPORT_SECRET_FIELDS.join(' | ')}).`);
  }

  // The device first, by (id, tenant) — device.service.ts's invariant 2. A
  // device of another tenant is "no device", exactly like a missing one.
  const device = await db('devices').where({ id: deviceId, tenant_id: tenantId }).first('id');
  if (!device) throw new AppError(404, `No device ${deviceId} in this tenant.`);

  const row = await db('device_transports')
    .where({ device_id: deviceId, transport })
    .first<{ id: number; secret_enc: string | null; private_key_enc: string | null } | undefined>(
      'id', 'secret_enc', 'private_key_enc',
    );
  if (!row) throw new AppError(404, `Device ${deviceId} has no ${transport} channel.`);

  const blob = field === 'privateKey' ? row.private_key_enc : row.secret_enc;
  if (blob === null || blob === '') {
    throw new AppError(
      404,
      field === 'privateKey'
        ? `The ${transport} channel of device ${deviceId} stores no private key.`
        : `The ${transport} channel of device ${deviceId} stores no password.`,
    );
  }

  const value = openBlob(blob, 'device_transport', row.id);
  await auditReveal(tenantId, actor, 'device_transport', row.id, {
    kind: 'transport',
    deviceId,
    transport,
    field,
  });
  return value;
}

// ============================================================================
// SNMP credentials — `snmp_credentials.community_enc` / `auth_key_enc` / `priv_key_enc`
// ============================================================================

/**
 * One secret of one SNMP credential. Default field: `community` for v1/v2c,
 * `authKey` for v3. Its route also demands CREDENTIAL_MANAGE, the capability
 * the rest of `snmp_credentials` sits behind (secretReveal.routes.ts).
 */
export async function revealSnmpCredential(input: {
  tenantId: number;
  credentialId: number | string;
  field?: string;
  actor: RevealActor;
}): Promise<string> {
  const { tenantId, actor } = input;
  assertMayRevealIn(tenantId, actor);
  const credentialId = positiveInt(input.credentialId, 'credential id');
  if (input.field !== undefined && !(SNMP_SECRET_FIELDS as readonly string[]).includes(input.field)) {
    throw new AppError(400, `Unknown SNMP secret field (expected ${SNMP_SECRET_FIELDS.join(' | ')}).`);
  }

  const row = await db('snmp_credentials')
    .where({ id: credentialId, tenant_id: tenantId })
    .first<{
      id: number;
      name: string;
      version: string;
      community_enc: string | null;
      auth_key_enc: string | null;
      priv_key_enc: string | null;
    } | undefined>('id', 'name', 'version', 'community_enc', 'auth_key_enc', 'priv_key_enc');
  if (!row) throw new AppError(404, `No SNMP credential ${credentialId} in this tenant.`);

  const field: SnmpSecretField = (input.field as SnmpSecretField | undefined)
    ?? (row.version === 'v3' ? 'authKey' : 'community');
  const blob = field === 'community'
    ? row.community_enc
    : field === 'authKey' ? row.auth_key_enc : row.priv_key_enc;
  if (blob === null || blob === '') {
    throw new AppError(404, `SNMP credential ${credentialId} stores no ${field}.`);
  }

  const value = openBlob(blob, 'snmp_credential', row.id);
  await auditReveal(tenantId, actor, 'snmp_credential', row.id, {
    kind: 'snmp',
    label: row.name,
    version: row.version,
    field,
  });
  return value;
}

// ============================================================================
// Learning mode — `learned_secrets.secret_enc` (migration 089)
// ============================================================================

/**
 * One secret a learning capture read off a router and attached to its site.
 * Tenant-scoped row (another workspace's id and an unknown id are the same
 * 404); the audit row names the reference (`menu`, `prop`, the ref) and the
 * site, never the value. A master-tenant secret is platform administrators
 * only (`assertMayRevealIn`).
 */
export async function revealLearnedSecret(input: {
  tenantId: number;
  secretId: number | string;
  actor: RevealActor;
}): Promise<string> {
  const { tenantId, actor } = input;
  assertMayRevealIn(tenantId, actor);
  const secretId = positiveInt(input.secretId, 'secret id');
  const row = await db('learned_secrets')
    .where({ id: secretId, tenant_id: tenantId })
    .first<{
      id: number;
      ref: string;
      menu: string;
      prop: string;
      site_id: number;
      device_id: number;
      secret_enc: string;
    } | undefined>('id', 'ref', 'menu', 'prop', 'site_id', 'device_id', 'secret_enc');
  if (!row) throw new AppError(404, `No learned secret ${secretId} in this tenant.`);
  const value = openBlob(row.secret_enc, 'learned_secret', row.id);
  await auditReveal(tenantId, actor, 'learned_secret', row.id, {
    kind: 'learned_secret',
    label: row.ref,
    menu: row.menu,
    field: row.prop,
    siteId: row.site_id,
    deviceId: row.device_id,
  });
  return value;
}

// ============================================================================
// SIM lines — `sim_lines.puk1_enc` / `puk2_enc` / `radius_password_enc` / `rio_enc`
// ============================================================================

/**
 * One secret of one mobile line: its PUK1, its PUK2, its RADIUS password
 * (migration 077) or its RIO (migration 079 — the portability code: with the
 * number, it is all a porting request needs). OPERATOR DECISION, 2026-10-06:
 * ObliWAN keeps every field the partner's listing carries, these four
 * encrypted, readable one at a time
 * by a SECRET_READ holder — the route ALSO demands SIM_READ, the capability
 * the whole SIM inventory sits behind (secretReveal.routes.ts).
 *
 * ┌─ WHO MAY SEE WHICH LINE IS THE INVENTORY'S OWN RULE ─────────────────────┐
 * │ The line is looked up through `getLine(scope)` — `scopeLines`, the ONE   │
 * │ place the SIM scope predicate is written: a tenant's own lines, and for  │
 * │ the master view (a platform administrator on the master tenant) every    │
 * │ line, the pool included, exactly as the SIM screens show them. A line    │
 * │ outside the scope is the SAME 404 as a line that does not exist.         │
 * │                                                                         │
 * │ The audit row lands in the LINE's tenant when it has one — it is that    │
 * │ customer's SIM, and their ledger is where the reveal of their PUK        │
 * │ belongs — and in the operating tenant for a pooled line, which has none. │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
export async function revealSimLineSecret(input: {
  tenantId: number;
  /** `requireTenant`'s master view, honoured only for a platform administrator. */
  masterView: boolean;
  lineId: number | string;
  field: string;
  actor: RevealActor;
}): Promise<string> {
  const { tenantId, actor } = input;
  assertMayRevealIn(tenantId, actor);
  const lineId = positiveInt(input.lineId, 'line id');
  if (!(SIM_LINE_SECRET_FIELDS as readonly string[]).includes(input.field)) {
    throw new AppError(400, `Unknown SIM line secret field (expected ${SIM_LINE_SECRET_FIELDS.join(' | ')}).`);
  }
  const field = input.field as SimLineSecretField;

  const line = await getLine({ tenantId, masterView: input.masterView && actor.platformAdmin }, lineId);
  if (!line) throw new AppError(404, `No SIM line ${lineId} in this workspace.`);

  const column = SIM_SECRET_COLUMNS[field];
  // By id AND by the tenant `getLine` just proved, so neither check alone
  // stands between two customers.
  const q = db('sim_lines').where({ id: lineId });
  if (line.tenantId === null) q.whereNull('tenant_id');
  else q.where({ tenant_id: line.tenantId });
  const row = await q.first<Record<string, string | null> | undefined>(column);
  const blob = row?.[column] ?? null;
  if (blob === null || blob === '') {
    throw new AppError(404, `SIM line ${lineId} stores no ${field}.`);
  }

  const value = openBlob(blob, 'sim_line', lineId);
  await auditReveal(line.tenantId ?? tenantId, actor, 'sim_line', lineId, {
    kind: 'sim_line',
    field,
  });
  return value;
}

/** The vault column of each SIM line secret (migration 077; `rio_enc`, 079). */
const SIM_SECRET_COLUMNS: Record<SimLineSecretField, string> = {
  puk1: 'puk1_enc',
  puk2: 'puk2_enc',
  radiusPassword: 'radius_password_enc',
  rio: 'rio_enc',
};
