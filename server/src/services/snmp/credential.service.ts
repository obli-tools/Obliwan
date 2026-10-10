/**
 * SNMP credentials and SNMP targets -- the configuration side.
 *
 * ┌─ THE SECRET NEVER COMES BACK OUT OF THIS FILE. ───────────────────────────┐
 * │ There is no "masked" community field, no `community: "pub***"`, no        │
 * │ `communityLength`. The API answers `hasCommunity: true`. A masked         │
 * │ plaintext is still a plaintext on the path that produced it, and it is    │
 * │ how a community string reaches a log, a HAR file attached to a support    │
 * │ ticket, or a browser extension. The one door that returns it is           │
 * │ `POST /api/snmp/credentials/:id/reveal` (secretReveal.routes.ts):         │
 * │ SECRET_READ + CREDENTIAL_MANAGE, one field per call, audited.             │
 * │                                                                          │
 * │ The write path follows from that: a client that GETs then PUTs cannot     │
 * │ send the secret back, so an ABSENT secret field means UNCHANGED, never    │
 * │ "clear it". Same rule as the notification channels.                       │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * The vault blob format is enforced by the DATABASE (`snmp_credentials_vault_
 * fmt_chk`, `^v[0-9]+:[0-9]+:`), so an attempt to store something the legacy
 * `utils/crypto.ts` produced is refused by PostgreSQL itself rather than
 * discovered on the day it fails to decrypt.
 */

import type {
  SnmpAuthProtocol,
  SnmpCredentialSummary,
  SnmpPrivProtocol,
  SnmpSecurityLevel,
  SnmpVersion,
} from '@obliwan/shared';
import { SETTINGS_KEYS, MASTER_TENANT_ID } from '@obliwan/shared';
import { db } from '../../db';
import { applyTenantScope, withTenantNames } from '../../utils/globalView';
import { settingsService } from '../settings.service';
import { currentKeyVersion, encrypt } from '../secretVault.service';
import type { SnmpCredentialRow, SnmpTargetRow } from './targets';
import { resolveSnmpTimings } from './targets';

// ============================================================================
// Credentials
// ============================================================================

export interface CredentialInput {
  name: string;
  version: SnmpVersion;
  /** v1/v2c only. Absent on update = unchanged. */
  community?: string;
  username?: string | null;
  securityLevel?: SnmpSecurityLevel | null;
  authProtocol?: SnmpAuthProtocol | null;
  /** Absent on update = unchanged. */
  authKey?: string;
  privProtocol?: SnmpPrivProtocol | null;
  /** Absent on update = unchanged. */
  privKey?: string;
  context?: string | null;
}

/** The ONLY shape that leaves the server. */
export function toSummary(row: SnmpCredentialRow): SnmpCredentialSummary {
  return {
    id: row.id,
    uuid: row.uuid,
    tenantId: row.tenant_id,
    name: row.name,
    version: row.version,
    username: row.username,
    securityLevel: row.security_level,
    authProtocol: row.auth_proto,
    privProtocol: row.priv_proto,
    context: row.context,
    hasCommunity: row.community_enc !== null,
    hasAuthKey: row.auth_key_enc !== null,
    hasPrivKey: row.priv_key_enc !== null,
  };
}

/**
 * The credentials screen's list. In the god view (a platform admin on
 * Default) every tenant's, each named with its tenant (or the operator's
 * tenant filter's): a summary carries no secret, and revealing one still goes
 * through the audited door, in the credential's own tenant.
 */
export async function listCredentials(tenantId: number): Promise<{
  rows: Array<SnmpCredentialSummary & { tenantName?: string | null }>;
  godView: boolean;
}> {
  const q = db<SnmpCredentialRow>('snmp_credentials').orderBy('name').orderBy('id');
  const godView = applyTenantScope(q, 'tenant_id', tenantId);
  const rows = ((await q) as SnmpCredentialRow[]).map(toSummary);
  return { rows: await withTenantNames(rows, 'tenantId', godView), godView };
}

/**
 * The tenants whose credentials a device of `tenantId` may be polled with:
 * its own, and the Default (master) workspace's — the installation's general
 * configuration (settings.service header). Never a third tenant's: that would
 * hand another customer's community string to this customer's router.
 */
export function usableCredentialTenants(tenantId: number): number[] {
  return tenantId === MASTER_TENANT_ID ? [tenantId] : [tenantId, MASTER_TENANT_ID];
}

/** What a picker may offer: the tenant's own credentials, then the Default
 *  workspace's (their `tenantId` tells the client which is which). */
export async function listUsableCredentials(tenantId: number): Promise<SnmpCredentialSummary[]> {
  const rows = await db<SnmpCredentialRow>('snmp_credentials')
    .whereIn('tenant_id', usableCredentialTenants(tenantId))
    .orderByRaw('(tenant_id = ?) DESC, name', [tenantId]);
  return rows.map(toSummary);
}

export async function getCredential(
  tenantId: number,
  id: number,
): Promise<SnmpCredentialSummary | null> {
  const row = await db<SnmpCredentialRow>('snmp_credentials')
    .where({ id, tenant_id: tenantId })
    .first();
  return row ? toSummary(row) : null;
}

/**
 * The v1/v2c vs v3 shape is ALSO enforced by a database CHECK
 * (`snmp_credentials_shape_chk`). It is re-stated here so the caller gets a
 * 400 with a sentence instead of a 23514 with a constraint name -- not because
 * the check is redundant. Validation in the application is a courtesy;
 * validation in the schema is the guarantee.
 */
function shapeColumns(input: CredentialInput): Record<string, unknown> {
  if (input.version === 'v3') {
    return {
      version: 'v3',
      community_enc: null,
      username: input.username ?? null,
      security_level: input.securityLevel ?? null,
      auth_proto: input.authProtocol ?? null,
      priv_proto: input.privProtocol ?? null,
      context: input.context ?? null,
    };
  }
  return {
    version: input.version,
    username: null,
    security_level: null,
    auth_proto: null,
    priv_proto: null,
    context: input.context ?? null,
  };
}

export async function createCredential(
  tenantId: number,
  input: CredentialInput,
): Promise<SnmpCredentialSummary> {
  const columns: Record<string, unknown> = {
    tenant_id: tenantId,
    name: input.name,
    key_version: currentKeyVersion(),
    ...shapeColumns(input),
  };

  if (input.version === 'v3') {
    columns.auth_key_enc = input.authKey ? encrypt(input.authKey) : null;
    columns.priv_key_enc = input.privKey ? encrypt(input.privKey) : null;
  } else {
    columns.community_enc = input.community ? encrypt(input.community) : null;
  }

  const [row] = await db<SnmpCredentialRow>('snmp_credentials').insert(columns).returning('*');
  return toSummary(row);
}

/**
 * Update. An OMITTED secret is UNCHANGED.
 *
 * That is not a convenience: since the GET never returns the secret, the
 * client cannot echo it back, so reading "absent" as "clear" would wipe the
 * community string of every credential the first time somebody renamed one.
 */
export async function updateCredential(
  tenantId: number,
  id: number,
  input: CredentialInput,
): Promise<SnmpCredentialSummary | null> {
  const current = await db<SnmpCredentialRow>('snmp_credentials')
    .where({ id, tenant_id: tenantId })
    .first();
  if (!current) return null;

  const columns: Record<string, unknown> = {
    name: input.name,
    ...shapeColumns(input),
    updated_at: new Date(),
  };

  if (input.version === 'v3') {
    if (input.authKey !== undefined) {
      columns.auth_key_enc = input.authKey ? encrypt(input.authKey) : null;
      columns.key_version = currentKeyVersion();
    } else {
      columns.auth_key_enc = current.auth_key_enc;
    }
    if (input.privKey !== undefined) {
      columns.priv_key_enc = input.privKey ? encrypt(input.privKey) : null;
      columns.key_version = currentKeyVersion();
    } else {
      columns.priv_key_enc = current.priv_key_enc;
    }
    columns.community_enc = null;
  } else {
    if (input.community !== undefined) {
      columns.community_enc = input.community ? encrypt(input.community) : null;
      columns.key_version = currentKeyVersion();
    } else {
      columns.community_enc = current.community_enc;
    }
    columns.auth_key_enc = null;
    columns.priv_key_enc = null;
  }

  const [row] = await db<SnmpCredentialRow>('snmp_credentials')
    .where({ id, tenant_id: tenantId })
    .update(columns)
    .returning('*');
  return row ? toSummary(row) : null;
}

/**
 * Delete. The FK from `snmp_targets` is ON DELETE RESTRICT, so a credential
 * still in use raises 23503 and the controller turns that into a 409. Deleting
 * it silently and leaving the targets un-pollable would be a fleet-wide outage
 * caused by a tidy-up.
 */
export async function deleteCredential(tenantId: number, id: number): Promise<boolean> {
  const count = await db('snmp_credentials').where({ id, tenant_id: tenantId }).del();
  return count > 0;
}

/**
 * How many SNMP_AUTO_TARGET_CREDENTIAL settings name this credential, at any
 * scope of its tenant or globally (#35). Deleting it would leave them pointing
 * at nothing: auto-provisioned targets would stop being created, and the bench
 * would silently stop writing ObliWAN's community into its files.
 */
export async function autoTargetReferences(tenantId: number, id: number): Promise<number> {
  const row = await db('settings')
    .where('key', SETTINGS_KEYS.SNMP_AUTO_TARGET_CREDENTIAL)
    // A Default-workspace credential can be named by any tenant's settings.
    .where((q) => (tenantId === MASTER_TENANT_ID ? q.whereNotNull('tenant_id') : q.where('tenant_id', tenantId).orWhere('scope', 'global')))
    .whereRaw("value #>> '{}' = ?", [String(id)])
    .count<{ count: string }[]>('* as count');
  return Number(row[0]?.count ?? 0);
}

/** How many targets use this credential -- so the UI can say so BEFORE the
 *  operator clicks delete. */
export async function credentialUsage(tenantId: number, id: number): Promise<number> {
  const row = await db('snmp_targets')
    .join('snmp_credentials', 'snmp_credentials.id', 'snmp_targets.credential_id')
    .where('snmp_credentials.tenant_id', tenantId)
    .where('snmp_targets.credential_id', id)
    .count<{ count: string }[]>('* as count');
  return Number(row[0]?.count ?? 0);
}

// ============================================================================
// Targets
// ============================================================================

export interface TargetInput {
  credentialId?: number | null;
  host?: string | null;
  port?: number;
  enabled?: boolean;
  pollIntervalSec?: number | null;
  /** `null` restores inheritance of the `snmp_timeout` setting. */
  timeoutMs?: number | null;
  /** `null` restores inheritance of the `snmp_retries` setting. */
  retries?: number | null;
  maxRepetitions?: number;
  supportsHcCounters?: boolean;
}

export interface TargetSummary {
  id: number;
  uuid: string;
  deviceId: number;
  credentialId: number | null;
  host: string | null;
  port: number;
  enabled: boolean;
  pollIntervalSec: number | null;
  /** `null` = inherited from the settings tree (migration 059), like the two above. */
  timeoutMs: number | null;
  retries: number | null;
  maxRepetitions: number;
  supportsHcCounters: boolean;
  nextPollAt: string;
  lastPollAt: string | null;
  lastOkAt: string | null;
  consecutiveFailures: number;
  lastError: string | null;
  lastDiscoveryAt: string | null;
}

function toTargetSummary(row: SnmpTargetRow): TargetSummary {
  return {
    id: row.id,
    uuid: row.uuid,
    deviceId: row.device_id,
    credentialId: row.credential_id,
    host: row.host,
    port: row.port,
    enabled: row.enabled,
    pollIntervalSec: row.poll_interval_sec,
    timeoutMs: row.timeout_ms,
    retries: row.retries,
    maxRepetitions: row.max_repetitions,
    supportsHcCounters: row.supports_hc_counters,
    nextPollAt: new Date(row.next_poll_at).toISOString(),
    lastPollAt: row.last_poll_at ? new Date(row.last_poll_at).toISOString() : null,
    lastOkAt: row.last_ok_at ? new Date(row.last_ok_at).toISOString() : null,
    consecutiveFailures: row.consecutive_failures,
    lastError: row.last_error,
    lastDiscoveryAt: row.last_discovery_at ? new Date(row.last_discovery_at).toISOString() : null,
  };
}

/** Tenant check on BOTH the device and the credential: a target is the one
 *  place where a device id and a credential id meet, and accepting a
 *  cross-tenant credential id there would hand another customer's community
 *  string to this customer's router. */
export async function upsertTarget(
  tenantId: number,
  deviceId: number,
  input: TargetInput,
): Promise<TargetSummary | null> {
  const device = await db('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first<{ id: number; group_id: number | null } | undefined>('id', 'group_id');
  if (!device) return null;

  if (input.credentialId != null) {
    const cred = await db('snmp_credentials')
      .where({ id: input.credentialId })
      .whereIn('tenant_id', usableCredentialTenants(tenantId))
      .first('id');
    if (!cred) return null;
  }

  const columns: Record<string, unknown> = { device_id: deviceId, updated_at: new Date() };
  if (input.credentialId !== undefined) columns.credential_id = input.credentialId;
  if (input.host !== undefined) columns.host = input.host;
  if (input.port !== undefined) columns.port = input.port;
  if (input.enabled !== undefined) columns.enabled = input.enabled;
  if (input.pollIntervalSec !== undefined) columns.poll_interval_sec = input.pollIntervalSec;
  if (input.timeoutMs !== undefined) columns.timeout_ms = input.timeoutMs;
  if (input.retries !== undefined) columns.retries = input.retries;
  if (input.maxRepetitions !== undefined) columns.max_repetitions = input.maxRepetitions;
  if (input.supportsHcCounters !== undefined) {
    columns.supports_hc_counters = input.supportsHcCounters;
  }

  const existing = await db<SnmpTargetRow>('snmp_targets').where({ device_id: deviceId }).first();
  if (existing) {
    const [row] = await db<SnmpTargetRow>('snmp_targets')
      .where({ id: existing.id })
      .update(columns)
      .returning('*');
    // Changing the interval changes what "expected" means for the rate window
    // and for `expected_count` in every rollup. The denormalised copy on
    // `snmp_interfaces` has to follow, or the window bounds of study 3.4e are
    // measured against a value nobody uses any more.
    // A pin cleared to NULL means "inherit": the copy follows what the device
    // inherits, not a hard-coded 30 (the poller rediscovers on a mismatch
    // anyway, but there is no reason to write one).
    if (input.pollIntervalSec !== undefined) {
      const effective = input.pollIntervalSec
        ?? (await resolveSnmpTimings(tenantId, deviceId, device.group_id)).pollIntervalSec;
      await db('snmp_interfaces')
        .where({ device_id: deviceId })
        .update({ effective_poll_sec: effective, updated_at: new Date() });
    }
    return toTargetSummary(row);
  }

  const [row] = await db('snmp_targets')
    .insert({ ...columns, created_at: new Date() })
    .returning('*');
  return toTargetSummary(row as SnmpTargetRow);
}

/**
 * This device's target, PLUS what its inheritance actually resolves to.
 *
 * `credentialId === null` means "inherit", and a screen that showed only that
 * would be telling an operator "inherited" without saying inherited FROM WHAT —
 * which is the same non-answer as showing nothing. `effectiveCredentialId` is
 * what the poller will really use, resolved through the same settings tree, and
 * `effectiveCredentialName` is what a human can check against the credential
 * they think they chose.
 *
 * Both are also correct when there is a pin: they then simply echo it, so the
 * UI has one field to render whatever the case.
 */
export async function getTargetSummary(
  tenantId: number,
  deviceId: number,
): Promise<(TargetSummary & {
  effectiveCredentialId: number | null;
  effectiveCredentialName: string | null;
  inherited: boolean;
}) | null> {
  const row = await db<SnmpTargetRow>('snmp_targets')
    .join('devices', 'devices.id', 'snmp_targets.device_id')
    .where('devices.tenant_id', tenantId)
    .where('snmp_targets.device_id', deviceId)
    .first('snmp_targets.*');
  if (!row) return null;

  let effectiveId = row.credential_id;
  const inherited = row.credential_id === null;
  if (inherited) {
    const device = await db('devices')
      .where({ id: deviceId, tenant_id: tenantId })
      .first<{ group_id: number | null } | undefined>('group_id');
    const settings = await settingsService.resolveForDevice(
      tenantId, deviceId, device?.group_id ?? null,
    );
    const id = Number(settings[SETTINGS_KEYS.SNMP_AUTO_TARGET_CREDENTIAL]?.value ?? 0);
    effectiveId = id > 0 ? id : null;
  }

  const cred = effectiveId
    ? await db('snmp_credentials')
      .where({ id: effectiveId })
      .whereIn('tenant_id', usableCredentialTenants(tenantId))
      .first<{ name: string } | undefined>('name')
    : undefined;

  return {
    ...toTargetSummary(row),
    effectiveCredentialId: effectiveId,
    effectiveCredentialName: cred?.name ?? null,
    inherited,
  };
}

export async function deleteTarget(tenantId: number, deviceId: number): Promise<boolean> {
  const device = await db('devices').where({ id: deviceId, tenant_id: tenantId }).first('id');
  if (!device) return false;
  const count = await db('snmp_targets').where({ device_id: deviceId }).del();
  return count > 0;
}
