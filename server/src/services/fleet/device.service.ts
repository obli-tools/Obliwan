/**
 * ObliWAN — devices and their transports.
 *
 * TWO INVARIANTS THIS FILE ENFORCES, BOTH NON-NEGOTIABLE
 *
 * 1. NO SECRET LEAVES THROUGH THIS FILE. `device_transports.secret_enc` and
 *    `private_key_enc` are never selected into a response shape — not for an
 *    operator, not for an admin. `toPublicTransport()` is the ONLY serialiser,
 *    and it emits `hasSecret: boolean` instead of anything derived from the
 *    ciphertext. Revealing a stored secret is a separate capability
 *    (`SECRET_READ`) with its own door, outside this file:
 *    `POST /api/devices/:id/transports/:transport/reveal`
 *    (routes/secretReveal.routes.ts → services/secrets/reveal.service.ts),
 *    one field per call, every reveal audited. (Section 8.2.)
 *
 * 2. EVERY QUERY IS TENANT-SCOPED, from the session. A device id in a URL is
 *    an untrusted integer; it is always paired with `tenant_id` in the WHERE
 *    clause rather than fetched and then checked, so there is no window where
 *    the row exists in a variable before the check runs.
 *
 * On `key_version`: the writer stores `currentKeyVersion()` in the SAME
 * statement as `secret_enc`. The column has a DEFAULT of 1, so an INSERT that
 * forgets it succeeds silently and becomes wrong on the day of the first key
 * rotation. There is one place that writes a secret, and it is below.
 */

import {
  DEVICE_FAMILIES,
  FAMILY_BRAND,
  MASTER_TENANT_ID,
  SOCKET_EVENTS,
  TRANSPORT_KINDS,
  type DeviceFamily,
  type TransportKind,
} from '@obliwan/shared';
import type { Knex } from 'knex';
import { db } from '../../db';
import { AppError } from '../../middleware/errorHandler';
import { withSsh } from '../transport/ssh.transport';
import { logger } from '../../utils/logger';
import { leaderElection } from '../leaderElection';
import { currentKeyVersion, decrypt, encrypt } from '../secretVault.service';
import { emitToTenant } from './fleetEvents';
import { emitToTenantAudience } from './scopedEmit';
import { toDeviceDto } from './dto';
import { getRouterOsPool, resolveRouterOsTarget } from './routerosPool';
import { readRouterOsIdentity } from './deviceBinding.service';
import { lockDeviceTls, normalisePin, settleCertificateAlerts } from './tlsPresented.service';
// Direct import of the service, NOT of `./index`: the barrel re-exports this
// very file, and going through it would close an import cycle whose only
// visible symptom would be an `undefined is not a function` at boot.
import { pppPresence } from './pppPresence.service';
import { applyTenantScope } from '../../utils/globalView';
import { openSnmpConnection, getMany, asText as asSnmpText } from '../transport/snmp.transport';
import { getTargetForDevice as getSnmpTargetForDevice, resolveTarget as resolveSnmpTarget } from '../snmp/targets';
import { SYS_OID as SNMP_SYS_OID } from '../snmp/oids';

// ============================================================================
// Row shapes
// ============================================================================

export interface DeviceRow {
  id: number;
  uuid: string;
  tenant_id: number;
  site_id: number | null;
  group_id: number | null;
  name: string;
  brand: string;
  family: string;
  model: string | null;
  serial: string | null;
  os_version: string | null;
  role: string;
  concentrator_id: number | null;
  ppp_username: string | null;
  system_identity: string | null;
  tunnel_ip: string | null;
  wan_public_ip: string | null;
  source_ip_hint: string | null;
  status: string;
  is_managed: boolean;
  first_seen_at: Date | null;
  last_seen_at: Date | null;
  notes: string | null;
  // RouterOS device-mode (7.13+). All five NULL on every non-MikroTik row and
  // on every MikroTik nobody has probed — see migration 033 for why none of
  // them may carry a default.
  device_mode: string | null;
  device_mode_scheduler: boolean | null;
  device_mode_fetch: boolean | null;
  device_mode_raw: Record<string, string> | null;
  device_mode_observed_at: Date | null;
  /** Learning mode (migration 089): set while ObliWAN learns this router;
   *  template-driven writes are refused meanwhile. */
  learning_since?: Date | null;
  learning_by?: number | null;
  created_at: Date;
  updated_at: Date;
}

/** A transport as the API is allowed to show it. Note what is NOT here. */
export interface PublicTransport {
  id: number;
  uuid: string;
  transport: TransportKind;
  enabled: boolean;
  priority: number;
  host: string | null;
  port: number | null;
  username: string | null;
  /** Whether a credential is stored — never the credential, never its length,
   *  never a masked rendering of it. */
  hasSecret: boolean;
  hasPrivateKey: boolean;
  keyVersion: number;
  useTls: boolean;
  tlsFingerprintSha256: string | null;
  /** The certificate a handshake was REFUSED on against the pin (migration
   *  069), and since when; null when no refusal stands. Public on purpose: a
   *  certificate fingerprint is no secret, and it is the one value the re-pin
   *  endpoint accepts. */
  tlsPresentedSha256: string | null;
  tlsPresentedAt: string | null;
  params: Record<string, unknown>;
  lastOkAt: string | null;
  lastError: string | null;
}

interface TransportRow {
  id: number;
  uuid: string;
  transport: string;
  enabled: boolean;
  priority: number;
  host: string | null;
  port: number | null;
  username: string | null;
  secret_enc: string | null;
  private_key_enc: string | null;
  key_version: number;
  use_tls: boolean;
  tls_fingerprint_sha256: string | null;
  tls_presented_sha256: string | null;
  tls_presented_at: Date | null;
  params: Record<string, unknown> | null;
  last_ok_at: Date | null;
  last_error: string | null;
}

/** The one and only transport serialiser. */
export function toPublicTransport(row: TransportRow): PublicTransport {
  return {
    id: row.id,
    uuid: row.uuid,
    transport: row.transport as TransportKind,
    enabled: row.enabled,
    priority: row.priority,
    host: row.host,
    port: row.port,
    username: row.username,
    hasSecret: row.secret_enc !== null,
    hasPrivateKey: row.private_key_enc !== null,
    keyVersion: row.key_version,
    useTls: row.use_tls,
    tlsFingerprintSha256: row.tls_fingerprint_sha256,
    tlsPresentedSha256: row.tls_presented_sha256 ?? null,
    tlsPresentedAt: row.tls_presented_at ? row.tls_presented_at.toISOString() : null,
    params: row.params ?? {},
    lastOkAt: row.last_ok_at ? row.last_ok_at.toISOString() : null,
    lastError: row.last_error,
  };
}

// ============================================================================
// Listing
// ============================================================================

export interface ListDevicesFilter {
  siteId?: number;
  role?: string;
  status?: string;
  brand?: string;
  family?: string;
  concentratorId?: number;
  search?: string;
  limit?: number;
  offset?: number;
  /**
   * Team scope (migration 084): the device ids the caller's teams reach
   * (teamScope.service `deviceListScope`); null/absent = the whole tenant. Applied in SQL so `limit`/`offset` page over what the caller sees.
   */
  deviceIdsIn?: readonly number[] | null;
}

export interface DeviceListItem extends DeviceRow {
  /** God view only: the owning tenant's name. */
  tenant_name?: string | null;
  site_code: string | null;
  site_name: string | null;
  /** Open PPP session on the concentrator — the definition of online. */
  ppp_up: boolean;
  ppp_since: string | null;
  verdict: string | null;
  /** The permanent health check's row (migration 043), NULL when none yet. */
  health_state: string | null;
  health_failures: number | null;
  health_skip_reason: string | null;
  health_last_check_at: Date | null;
  health_interval_sec: number | null;
  health_down_since: Date | null;
}

export async function listDevices(
  tenantId: number,
  filter: ListDevicesFilter = {},
): Promise<{ items: DeviceListItem[]; total: number; godView: boolean }> {
  const base = db('devices as d');
  // God view (a platform admin's GET on the master tenant): every tenant's
  // devices, each with its tenant's name. Anyone else: this tenant's.
  const godView = applyTenantScope(base, 'd.tenant_id', tenantId);

  if (filter.siteId !== undefined) base.andWhere('d.site_id', filter.siteId);
  if (filter.role) base.andWhere('d.role', filter.role);
  if (filter.status) base.andWhere('d.status', filter.status);
  if (filter.brand) base.andWhere('d.brand', filter.brand);
  if (filter.family) base.andWhere('d.family', filter.family);
  if (filter.concentratorId !== undefined) base.andWhere('d.concentrator_id', filter.concentratorId);
  if (filter.deviceIdsIn) base.whereIn('d.id', [...filter.deviceIdsIn]);
  if (filter.search) {
    const like = `%${filter.search}%`;
    base.andWhere((q) => {
      q.whereILike('d.name', like)
        .orWhereILike('d.ppp_username', like)
        .orWhereILike('d.serial', like)
        .orWhereILike('d.system_identity', like);
    });
  }

  const [{ count }] = await base.clone().count<{ count: string }[]>('d.id as count');

  const rows = await base
    .clone()
    .leftJoin('sites as s', 's.id', 'd.site_id')
    .leftJoin('ppp_sessions as p', function joinOpen(this: any) {
      this.on('p.device_id', '=', 'd.id').andOnNull('p.ended_at');
    })
    .leftJoin(
      db('reachability_verdicts')
        .distinctOn('device_id')
        .select('device_id', 'verdict')
        .orderBy('device_id')
        .orderBy('ts', 'desc')
        .as('v'),
      'v.device_id',
      'd.id',
    )
    // One row per device (its primary key), so the join cannot multiply rows.
    .leftJoin('device_health_checks as hc', 'hc.device_id', 'd.id')
    .select<Array<DeviceRow & {
      site_code: string | null;
      site_name: string | null;
      started_at: Date | null;
      verdict: string | null;
      health_state: string | null;
      health_failures: number | null;
      health_skip_reason: string | null;
      health_last_check_at: Date | null;
      health_interval_sec: number | null;
      health_down_since: Date | null;
    }>>(
      'd.*',
      's.code as site_code',
      's.name as site_name',
      'p.started_at',
      'v.verdict',
      'hc.state as health_state',
      'hc.consecutive_failures as health_failures',
      'hc.skip_reason as health_skip_reason',
      'hc.last_check_at as health_last_check_at',
      'hc.interval_sec as health_interval_sec',
      'hc.down_since as health_down_since',
      ...(godView ? [db.raw('(SELECT t.name FROM tenants t WHERE t.id = d.tenant_id) AS tenant_name')] : []),
    )
    // d.id breaks ties: names are not unique, and OFFSET paging over a
    // non-unique order can repeat or skip a device across pages.
    .orderBy([{ column: 'd.name' }, { column: 'd.id' }])
    .limit(filter.limit ?? 200)
    .offset(filter.offset ?? 0);

  return {
    total: Number(count),
    godView,
    items: rows.map((r) => {
      const { started_at, ...rest } = r;
      return {
        ...rest,
        ppp_up: started_at !== null,
        ppp_since: started_at ? started_at.toISOString() : null,
      } as DeviceListItem;
    }),
  };
}

export async function getDevice(tenantId: number, id: number): Promise<DeviceRow | undefined> {
  return db('devices').where({ id, tenant_id: tenantId }).first<DeviceRow | undefined>();
}

/** Device + its transports (redacted) + health + latest verdict. */
export async function getDeviceDetail(
  tenantId: number,
  id: number,
): Promise<
  | (DeviceRow & {
      transports: PublicTransport[];
      health: Array<{ transport: string; connState: string; circuitState: string; consecutiveFailures: number; nextRetryAt: string | null; lastError: string | null }>;
      pppUp: boolean;
      verdict: string | null;
    })
  | undefined
> {
  const device = await getDevice(tenantId, id);
  if (!device) return undefined;

  const [transports, health, open, verdict] = await Promise.all([
    db('device_transports').where({ device_id: id }).orderBy('priority').select<TransportRow[]>('*'),
    db('device_health')
      .where({ device_id: id })
      .select<Array<{ transport: string; conn_state: string; circuit_state: string; consecutive_failures: number; next_retry_at: Date | null; last_error: string | null }>>('*'),
    db('ppp_sessions').where({ device_id: id }).whereNull('ended_at').first('id'),
    db('reachability_verdicts')
      .where({ device_id: id })
      .orderBy('ts', 'desc')
      .first<{ verdict: string } | undefined>('verdict'),
  ]);

  return {
    ...device,
    transports: transports.map(toPublicTransport),
    health: health.map((h) => ({
      transport: h.transport,
      connState: h.conn_state,
      circuitState: h.circuit_state,
      consecutiveFailures: h.consecutive_failures,
      nextRetryAt: h.next_retry_at ? h.next_retry_at.toISOString() : null,
      lastError: h.last_error,
    })),
    pppUp: !!open,
    verdict: verdict?.verdict ?? null,
  };
}

// ============================================================================
// Create / update / delete
// ============================================================================

export interface CreateDeviceData {
  name: string;
  family: DeviceFamily;
  role?: 'cpe' | 'concentrator';
  siteId?: number | null;
  groupId?: number | null;
  model?: string | null;
  serial?: string | null;
  osVersion?: string | null;
  concentratorId?: number | null;
  pppUsername?: string | null;
  systemIdentity?: string | null;
  tunnelIp?: string | null;
  wanPublicIp?: string | null;
  sourceIpHint?: string | null;
  status?: 'pending' | 'active' | 'quarantined' | 'disabled';
  isManaged?: boolean;
  notes?: string | null;
}

export type UpdateDeviceData = Partial<CreateDeviceData>;

function deviceColumns(data: UpdateDeviceData): Record<string, unknown> {
  const row: Record<string, unknown> = {};
  if (data.name !== undefined) row.name = data.name;
  if (data.family !== undefined) {
    row.family = data.family;
    // brand is DERIVED, never accepted from the client: the client could send
    // a (brand, family) pair that disagrees, and every driver lookup after that
    // would resolve to the wrong dialect.
    row.brand = FAMILY_BRAND[data.family];
  }
  if (data.role !== undefined) row.role = data.role;
  if (data.siteId !== undefined) row.site_id = data.siteId;
  if (data.groupId !== undefined) row.group_id = data.groupId;
  if (data.model !== undefined) row.model = data.model;
  if (data.serial !== undefined) row.serial = data.serial;
  if (data.osVersion !== undefined) row.os_version = data.osVersion;
  if (data.concentratorId !== undefined) row.concentrator_id = data.concentratorId;
  if (data.pppUsername !== undefined) row.ppp_username = data.pppUsername;
  if (data.systemIdentity !== undefined) row.system_identity = data.systemIdentity;
  if (data.tunnelIp !== undefined) row.tunnel_ip = data.tunnelIp;
  if (data.wanPublicIp !== undefined) row.wan_public_ip = data.wanPublicIp;
  if (data.sourceIpHint !== undefined) row.source_ip_hint = data.sourceIpHint;
  if (data.status !== undefined) row.status = data.status;
  if (data.isManaged !== undefined) row.is_managed = data.isManaged;
  if (data.notes !== undefined) row.notes = data.notes;
  return row;
}

/**
 * What a device write needs to know about WHO is writing — one fact, and only
 * the shared-concentrator rule below reads it.
 */
export interface DeviceWriteOptions {
  /**
   * `users.role = 'admin'` (`req.session.role === 'admin'`), as `requireAuth`
   * revalidated it against the database — through its identity cache, so at
   * most REVALIDATE_MS (10 s) old: an administrator demoted in the database
   * keeps this for up to that long. NOT membership of the master tenant:
   * `requireTenant` is explicit that such a membership grants nothing beyond
   * the master tenant's own rows — and the shared concentrators are not the
   * master tenant's own in that sense (see `decidePppClaim`). Absent means
   * false — a caller that does not say who it is writes as a tenant, never as
   * the operator. `devices.controller.ts` passes it on create, update and the
   * UI enrolment.
   */
  platformAdmin?: boolean;
}

/** The (concentrator, PPP account) pair a device carries before the write. */
export interface PresencePair {
  concentrator_id: number | null;
  ppp_username: string | null;
}

/** Cross-tenant references are refused here rather than at the database: the
 *  FKs are tenant-blind by design (a device_group is a tenant-scoped tree, a
 *  site is not reachable from the FK), so the check has to be explicit.
 *
 *  `self` is null for a create; for an update it carries the row's id and its
 *  pair as read UNDER THE ROW LOCK of the update's own transaction (`current`
 *  is undefined when the id is not in this tenant — the scoped UPDATE then
 *  answers 404 and there is no pair to judge). */
async function assertReferencesInTenant(
  conn: Knex | Knex.Transaction,
  tenantId: number,
  data: UpdateDeviceData,
  self: { id: number; current: PresencePair | undefined } | null,
  options: DeviceWriteOptions,
): Promise<void> {
  if (data.siteId) {
    const site = await conn('sites').where({ id: data.siteId, tenant_id: tenantId }).first('id');
    if (!site) throw new Error(`Site ${data.siteId} does not exist in this tenant`);
  }
  if (data.concentratorId) {
    if (self !== null && data.concentratorId === self.id) {
      throw new Error('A device cannot be its own concentrator');
    }
    // ┌─ A CONCENTRATOR MAY BE SHARED. A PPP ACCOUNT ON IT IS NOT FIRST-COME ───┐
    // │ This used to demand `tenant_id = tenantId`, i.e. a concentrator per     │
    // │ tenant. A CHR terminating an L2TP fleet is multi-customer BY            │
    // │ CONSTRUCTION — one box, every client's tunnel — so with a single CHR    │
    // │ that rule forced every customer into one tenant, or `concentrator_id`   │
    // │ NULL for all but one: and a CPE with no concentrator has no presence    │
    // │ source.                                                                 │
    // │                                                                         │
    // │ So a CPE may REFERENCE a concentrator in its own tenant or one in the   │
    // │ MASTER tenant, where the operator's shared infrastructure lives.        │
    // │ Another customer's concentrator stays invisible, and so, to every other │
    // │ tenant, does a master-tenant device that is not a concentrator: both    │
    // │ answer exactly like an id that does not exist, so this refusal is not   │
    // │ an oracle over the operator's inventory or another customer's.          │
    // │                                                                         │
    // │ The reference alone is harmless. A PPP username is not — on the shared  │
    // │ CHR or on no concentrator at all; see `decidePppClaim()` below, which   │
    // │ keeps a device write from taking another customer's session or name.    │
    // │                                                                         │
    // │ Nothing here grants anything on the concentrator itself: it stays       │
    // │ scoped to the master tenant for every write — a change job on a CHR has │
    // │ the whole fleet as its blast radius.                                    │
    // └─────────────────────────────────────────────────────────────────────────┘
    const chr = await conn('devices')
      .where({ id: data.concentratorId })
      .andWhere((q) => {
        q.where({ tenant_id: tenantId }).orWhere({ tenant_id: MASTER_TENANT_ID, role: 'concentrator' });
      })
      .first<{ role: string } | undefined>('role');
    if (!chr) {
      // AppError, not Error: the controllers map a plain Error by matching its
      // text, and a message they do not recognise leaves as a bare 500.
      throw new AppError(
        400,
        `Concentrator ${data.concentratorId} does not exist in this tenant, nor as shared ` +
          'infrastructure. A concentrator belonging to another customer cannot be referenced.',
      );
    }
    if (chr.role !== 'concentrator') throw new Error(`Device ${data.concentratorId} is not a concentrator`);
  }
  if (data.concentratorId !== undefined || data.pppUsername !== undefined) {
    await assertPppAccountClaim(conn, tenantId, data, self, options);
  }
  // This branch used to be missing while `deviceColumns`
  // happily wrote `group_id`, so `POST /api/devices {groupId: <another tenant's
  // group>}` returned 201. The leak is immediate and in READ: the Fleet Query
  // compiler joins `device_groups` on `d.group_id` and scopes on `d.tenant_id`
  // only — as it should — so the device of tenant A displays the group NAME of
  // tenant B, and an id sweep enumerates another customer's group tree.
  // Settings and rights inherit down the group closure as well.
  //
  // Migration 014 poses the composite FK `(group_id, tenant_id) REFERENCES
  // device_groups (id, tenant_id)` that makes this unforgeable from ANY write
  // path. This check stays because it produces the operator-readable message;
  // the constraint stays because this check can be forgotten again.
  if (data.groupId) {
    const group = await conn('device_groups')
      .where({ id: data.groupId, tenant_id: tenantId })
      .first('id');
    if (!group) throw new Error(`Group ${data.groupId} does not exist in this tenant`);
  }
}

/**
 * Who may write a (concentrator, PPP username) pair onto a device.
 *
 * ┌─ THE PAIR IS WHAT ROUTES ANOTHER CUSTOMER'S SESSION ──────────────────────┐
 * │ `pppPresence.deviceForUsername()` resolves a live session by              │
 * │ (ppp_username, concentrator_id) and NOTHING else — no tenant predicate,   │
 * │ no status — then writes that session's tunnel_ip, its caller (public WAN) │
 * │ address and last_seen_at onto the row, files the session history under    │
 * │ it, and emits SITE_PRESENCE to the row's tenant. That filter is           │
 * │ tenant-safe only while whoever writes the pair owns every session on the  │
 * │ concentrator. True of a tenant's own CHR; false of the shared one.        │
 * │                                                                           │
 * │ On the shared CHR, tenant B writing ('siteA-042', <master CHR>) for a     │
 * │ site of tenant A that has dialled in and sits in quarantine — not yet a   │
 * │ device row, so the global UNIQUE on ppp_username does not stop it — would │
 * │ hand B A's tunnel address (somewhere to aim "Test connection"), A's       │
 * │ public WAN address and A's session history. First come, first served.     │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * THE RULE. A write CLAIMS a PPP username when it gives the device a name it
 * did not carry, or attaches the name it carries to a different concentrator.
 * A claim is allowed on a concentrator of the caller's OWN tenant — every
 * session on that box is its own — unless that tenant is the master one (see
 * below), and to a platform administrator, who speaks for the owner of the
 * shared infrastructure: the operator who created the account in the CHR's
 * `/ppp/secret` and knows whose site it is. Every other claim is refused — on
 * a SHARED concentrator (any concentrator of the master tenant, the only kind
 * another tenant can reference) and on NO concentrator alike. A tenant keeps
 * everything that claims nothing: pointing a CPE at the shared CHR with no
 * username, clearing its username, taking the name it already carries off its
 * concentrator, editing every other field, and re-saving the exact pair the
 * device already carries (an edit form sends it back unchanged).
 *
 * ┌─ NO CONCENTRATOR IS NOT NO CLAIM ────────────────────────────────────────┐
 * │ This rule used to let any username through while the concentrator was    │
 * │ NULL — "no pair, nothing for presence to route". Presence routes         │
 * │ nothing then, true, but `devices.ppp_username` is UNIQUE across the      │
 * │ whole platform (migration 002) and two readers key on the name ALONE:    │
 * │  - `runChrDiscovery` skips every name some device holds, so a site of    │
 * │    tenant A whose name tenant B wrote first never reaches quarantine;    │
 * │  - `pppPresence.deviceForUsername` finds no row carrying A's pair,       │
 * │    logs the name as attached "elsewhere" and files A's sessions under    │
 * │    no device.                                                            │
 * │ A platform administrator who then attaches the name to A's device gets a │
 * │ 409 that cannot say which device holds it. And that 409 against a        │
 * │ success was itself an oracle over every customer's PPP accounts. A name  │
 * │ is a claim wherever it is written, so it is judged wherever it is        │
 * │ written.                                                                 │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE MASTER TENANT DOES NOT OWN THE SESSIONS ON ITS OWN CHR ─────────────┐
 * │ The shared CHR is a row of the master tenant, but its sessions are every │
 * │ customer's. This rule used to let a caller whose tenant owns the box     │
 * │ through before asking who the caller was, so ANY member of tenant 1 —    │
 * │ where `requireTenant` parks every "for now" account, and whose           │
 * │ membership "grants nothing beyond the master tenant's own data" — could │
 * │ attach any username on the shared CHR with plain DEVICE_WRITE. Including │
 * │ one that has not dialled yet, e.g. a name the allocator reserved for     │
 * │ tenant A: the day A's site connected, presence filed A's tunnel address, │
 * │ public WAN address and session history under a tenant-1 row. So the      │
 * │ master tenant is never "own" here: a tenant-1 caller is a platform       │
 * │ administrator or is refused, like everybody else.                        │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Why not "refuse a name the CHR has already seen" instead: PPP usernames
 * follow a pattern, so that would only move the race earlier — a tenant could
 * claim a site that has not dialled yet, and be handed it the day it does.
 * Nothing in the username itself says whose it is. One record now could:
 * `site_provisioning` (migration 036) files the tenant a platform-ALLOCATED
 * name was drawn for, so a tenant attaching its own allocated name could be
 * let through. It is NOT consulted here — that would widen this rule rather
 * than repair it, and it is left as a decision, not taken in passing.
 *
 * Fails CLOSED: a concentrator found in neither this tenant nor the master one
 * — no write path produces that, but no constraint forbids it either — counts
 * as foreign, never as own.
 *
 * What it costs: the UI's create and enrolment forms send a PPP username with
 * no concentrator, so for anybody but a platform administrator a username
 * typed there is now a 403, raised before anything is written or stored in
 * the vault. The name reaches the device from a platform administrator, or
 * when the site's discovery is bound on a concentrator the tenant owns.
 *
 * What it does NOT close: a tenant with a concentrator of its OWN still claims
 * a name platform-wide when it attaches one there, so the squat and the 409
 * oracle above stay open to that tenant. That is a schema decision, not a
 * rule: UNIQUE on (concentrator_id, ppp_username) instead of on the name, with
 * `runChrDiscovery`'s global "bound" lookup and `pppPresence`'s "elsewhere"
 * branch rewritten to match. Pairs written before this rule existed are not
 * detected either; re-saving one unchanged is allowed.
 *
 * The flag is the CALLER's to pass (`DeviceWriteOptions.platformAdmin`); a
 * caller that passes nothing is a tenant. The tenant import
 * (`importExport.controller.ts`) writes the pair directly and is reachable by
 * platform administrators only (`requireRole('admin')`). Discovery binding
 * (`bindDiscovery`) also writes the pair directly, from a discovery the
 * caller's tenant can see — a different gate, not this one, and it does not
 * ask for platform-admin authority: every member of the master tenant sees
 * the shared CHR's discoveries, so a plain tenant-1 member can still bind a
 * name that HAS dialled there. Closing that belongs to `bindDiscovery` and
 * its controller, with the same flag.
 */
export type PppClaimVerdict =
  | {
      allow: true;
      reason: 'no_target' | 'no_username' | 'unchanged' | 'detached' | 'own_concentrator' | 'platform_admin';
    }
  | { allow: false; reason: 'shared_concentrator'; concentratorId: number }
  | { allow: false; reason: 'no_concentrator' };

/**
 * The decision of `assertPppAccountClaim`, with the one database read it may
 * need passed in as `concentratorTenant` — so the rule can be exercised
 * without a database. `concentratorTenant` resolves to the tenant of the
 * concentrator as found among (caller's tenant, master tenant), or null when
 * it is in neither; it is only called for a claim that names a concentrator.
 */
export async function decidePppClaim(input: {
  callerTenantId: number;
  data: Pick<UpdateDeviceData, 'concentratorId' | 'pppUsername'>;
  /** null for a create; for an update, the pair read under the row lock
   *  (undefined when the id is not in this tenant). */
  self: { current: PresencePair | undefined } | null;
  platformAdmin: boolean;
  concentratorTenant: (concentratorId: number) => Promise<number | null>;
}): Promise<PppClaimVerdict> {
  const { callerTenantId, data, self } = input;
  // Not in this tenant: the scoped UPDATE answers 404, there is no pair to judge.
  if (self !== null && self.current === undefined) return { allow: true, reason: 'no_target' };
  const before: PresencePair = self?.current ?? { concentrator_id: null, ppp_username: null };
  const after: PresencePair = {
    concentrator_id: data.concentratorId !== undefined ? data.concentratorId : before.concentrator_id,
    ppp_username: data.pppUsername !== undefined ? data.pppUsername : before.ppp_username,
  };

  // No name after the write: the device holds nothing and presence routes nothing.
  if (!after.ppp_username) return { allow: true, reason: 'no_username' };
  const sameName = after.ppp_username === before.ppp_username;
  // The pair the device already has: re-saving it takes nothing from anybody.
  if (sameName && after.concentrator_id === before.concentrator_id) {
    return { allow: true, reason: 'unchanged' };
  }
  // The name this row already holds, taken off its concentrator: presence stops
  // routing to it, and the name was this row's before the write.
  if (sameName && after.concentrator_id === null) return { allow: true, reason: 'detached' };

  // A claim — a name the device did not carry, or the one it carries attached
  // to a different concentrator. With NO concentrator it is a claim all the
  // same: see "NO CONCENTRATOR IS NOT NO CLAIM" above.
  if (after.concentrator_id !== null) {
    const ownerTenant = await input.concentratorTenant(after.concentrator_id);
    // Own concentrator — never the master tenant's: see the box above.
    if (ownerTenant === callerTenantId && callerTenantId !== MASTER_TENANT_ID) {
      return { allow: true, reason: 'own_concentrator' };
    }
  }
  if (input.platformAdmin) return { allow: true, reason: 'platform_admin' };
  return after.concentrator_id === null
    ? { allow: false, reason: 'no_concentrator' }
    : { allow: false, reason: 'shared_concentrator', concentratorId: after.concentrator_id };
}

/** `decidePppClaim` against the database, refusing with a 403. The rule and
 *  its reasons are the block above `PppClaimVerdict`. */
async function assertPppAccountClaim(
  conn: Knex | Knex.Transaction,
  tenantId: number,
  data: UpdateDeviceData,
  self: { id: number; current: PresencePair | undefined } | null,
  options: DeviceWriteOptions,
): Promise<void> {
  const verdict = await decidePppClaim({
    callerTenantId: tenantId,
    data,
    self,
    platformAdmin: options.platformAdmin === true,
    concentratorTenant: async (concentratorId) => {
      const owner = await conn('devices')
        .where({ id: concentratorId })
        .whereIn('tenant_id', [tenantId, MASTER_TENANT_ID])
        .first<{ tenant_id: number } | undefined>('tenant_id');
      return owner ? Number(owner.tenant_id) : null;
    },
  });
  if (verdict.allow) return;

  if (verdict.reason === 'no_concentrator') {
    throw new AppError(
      403,
      'Only a platform administrator can record a PPP username on a device with no ' +
        'concentrator. The name is unique across the whole platform: writing it reserves it ' +
        'against every customer, and a site that really dials with it would never reach the ' +
        'discoveries list. Save the device without a PPP username; a platform administrator ' +
        'attaches it, or binding the site\'s discovery does, on a concentrator of your own tenant.',
    );
  }
  throw new AppError(
    403,
    `Concentrator ${verdict.concentratorId} is shared infrastructure: a PPP account on it ` +
      'belongs to whichever customer the operator created it for, so only a platform ' +
      'administrator can attach a PPP username to a device behind it. The device may still ' +
      'point at this concentrator without one.',
  );
}

// ============================================================================
// PPP presence lifecycle
// ============================================================================

/**
 * Reconcile the presence monitors with what the database now says.
 *
 * `pppPresence.watch()` / `unwatch()` had NO caller outside `startAll()` /
 * `stopAll()` and the self-test recipe. A concentrator declared through the API
 * was therefore not watched until the next process restart or leader
 * failover — `ppp_sessions` stayed empty, `last_seen_at` stayed null, and every
 * CPE behind it was reported `UNREACHABLE`. Symmetrically, deleting a
 * concentrator left its `ConcentratorMonitor` alive, re-opening a stream every
 * 5 s against a device id that no longer resolves, forever.
 *
 * The gestures that change the answer all live in this file, so the hook lives
 * here too. It is:
 *
 *  - IDEMPOTENT — `watch()` returns immediately when already watching and
 *    `unwatch()` when not; calling this after every write is safe.
 *  - GATED ON LEADERSHIP — two replicas each opening
 *    `/ppp/active/listen` on the same CHR would double every session row. A
 *    follower does nothing here; when it wins the election, `startAll()` picks
 *    the whole fleet up.
 *  - CONDITIONED ON A USABLE TRANSPORT — a concentrator with no enabled
 *    `routeros_api` row cannot be listened to, and starting a monitor for it
 *    would only produce a 5-second retry loop and a `markConcentratorDegraded`
 *    per attempt. `createConcentrator()` creates the device BEFORE its
 *    transport, which is exactly that window; the `upsertTransport` call that
 *    follows re-enters here and starts the watch for real.
 *  - NEVER FATAL — presence is a background duty; it must not turn a successful
 *    device write into a 500.
 */
export async function syncConcentratorPresence(
  deviceId: number,
  opts: { restart?: boolean } = {},
): Promise<void> {
  if (!leaderElection.isLeader()) return;

  const row = await db('devices as d')
    .where('d.id', deviceId)
    .first<{ role: string; status: string; transports: string } | undefined>(
      'd.role',
      'd.status',
      db.raw(
        "(SELECT count(*) FROM device_transports t WHERE t.device_id = d.id " +
          "AND t.transport = 'routeros_api' AND t.enabled) as transports",
      ),
    );

  const shouldWatch =
    !!row && row.role === 'concentrator' && row.status !== 'disabled' && Number(row.transports) > 0;

  try {
    if (!shouldWatch) {
      await pppPresence.unwatch(deviceId);
      return;
    }
    // `restart` is for "the target moved under the monitor": the stream is bound
    // to the socket the pool held for the OLD host/credential, and cancelling it
    // before re-opening is what stops a listen from being left registered on the
    // previous box.
    if (opts.restart) await pppPresence.unwatch(deviceId);
    if (!pppPresence.isRunning) return;
    await pppPresence.watch(deviceId);
  } catch (err) {
    logger.warn(
      { err, deviceId },
      'Could not reconcile PPP presence for this concentrator; the next leader ' +
        'election or restart will pick it up',
    );
  }
}

/** Stop watching, whatever the database says. Used on the paths that are about
 *  to make the device un-watchable (delete, transport removal). */
export async function stopConcentratorPresence(deviceId: number): Promise<void> {
  try {
    await pppPresence.unwatch(deviceId);
  } catch (err) {
    logger.warn({ err, deviceId }, 'Could not stop PPP presence for this concentrator');
  }
}

export async function createDevice(
  tenantId: number,
  data: CreateDeviceData,
  options: DeviceWriteOptions = {},
): Promise<DeviceRow> {
  if (!DEVICE_FAMILIES.includes(data.family)) {
    throw new Error(`Unknown device family '${data.family}'`);
  }
  await assertReferencesInTenant(db, tenantId, data, null, options);

  const [row] = await db('devices')
    .insert({
      ...deviceColumns(data),
      tenant_id: tenantId,
      // A hand-declared device starts `pending`: it has not proven its identity
      // yet, and `active` is a statement about a box that answered.
      status: data.status ?? 'pending',
    })
    .returning<DeviceRow[]>('*');

  emitToTenantAudience(tenantId, SOCKET_EVENTS.DEVICE_CREATED, { device: toDeviceDto(row) }, { deviceId: row.id });
  if (row.role === 'concentrator') await syncConcentratorPresence(row.id);
  return row;
}

export async function updateDevice(
  tenantId: number,
  id: number,
  data: UpdateDeviceData,
  options: DeviceWriteOptions = {},
): Promise<DeviceRow | undefined> {
  if (data.family !== undefined && !DEVICE_FAMILIES.includes(data.family)) {
    throw new Error(`Unknown device family '${data.family}'`);
  }

  const columns = deviceColumns(data);

  // The check and the write share one transaction and one row lock. The PPP
  // rule judges the pair the row carries NOW, so without the lock two updates
  // racing on one device — one pointing it at the shared CHR, one setting its
  // username — would each pass against a state the other had not written yet,
  // and together write the pair neither was allowed to.
  const row = await db.transaction(async (trx): Promise<DeviceRow | undefined> => {
    const current = await trx('devices')
      .where({ id, tenant_id: tenantId })
      .forUpdate()
      .first<PresencePair | undefined>('concentrator_id', 'ppp_username');
    await assertReferencesInTenant(trx, tenantId, data, { id, current }, options);

    if (Object.keys(columns).length === 0) {
      return trx('devices').where({ id, tenant_id: tenantId }).first<DeviceRow | undefined>();
    }
    const [updated] = await trx('devices')
      .where({ id, tenant_id: tenantId })
      .update({ ...columns, updated_at: trx.fn.now() })
      .returning<DeviceRow[]>('*');
    return updated;
  });
  if (Object.keys(columns).length === 0) return row;

  if (row) emitToTenantAudience(tenantId, SOCKET_EVENTS.DEVICE_UPDATED, { device: toDeviceDto(row) }, { deviceId: row.id });
  // `role` and `status` are the two columns that decide whether this device is
  // watched. Promotion to `concentrator` starts a monitor, demotion to `cpe` or
  // `disabled` stops one; the call is also made when the row IS a concentrator
  // and neither changed, because it is idempotent and cheaper to reason about
  // than a set of conditions that must stay in sync with `syncConcentratorPresence`.
  if (row && (row.role === 'concentrator' || data.role !== undefined)) {
    await syncConcentratorPresence(row.id);
  }
  return row;
}

/**
 * Delete a device.
 *
 * `devices.concentrator_id` is ON DELETE RESTRICT, so deleting a CHR that still
 * has children fails at the database. That is deliberate — it is the presence
 * source of truth for a whole fleet — and the caller turns the constraint
 * violation into a message an operator can act on.
 */
export async function deleteDevice(tenantId: number, id: number): Promise<boolean> {
  // There used to be a pre-DELETE sweep here, pushing every discovery bound to
  // this device back to `pending` by hand, because the schema's ON DELETE SET
  // NULL contradicted its own `CHECK (state <> 'bound' OR bound_device_id IS
  // NOT NULL)` and Postgres refused the delete. That contradiction was fixed in
  // the schema (migration 002: a BEFORE UPDATE trigger moves the row back to
  // `pending` as the FK NULLs the column), so the sweep is gone.
  //
  // It matters that it is gone rather than kept "for safety": a rule enforced
  // in two places is a rule that will be enforced in one of them after the next
  // edit, and the one that survives is never the one you expected.
  //
  // The presence monitor, on the other hand, IS this file's business: nothing
  // in the schema tears it down, and a monitor whose device has been deleted
  // re-opens a stream every 5 s and calls `markConcentratorDegraded` on a row
  // the CASCADE already removed — a loop that only ends with the process.
  // It is stopped BEFORE the DELETE so that no sweep
  // can run against a half-deleted device, and restored if the DELETE is
  // refused (`concentrator_id` is ON DELETE RESTRICT: a CHR with children
  // cannot be removed, and that attempt must not silently blind the fleet).
  const target = await db('devices')
    .where({ id, tenant_id: tenantId })
    .first<{ role: string } | undefined>('role');
  const wasConcentrator = target?.role === 'concentrator';
  if (wasConcentrator) await stopConcentratorPresence(id);

  let deleted: number;
  try {
    deleted = await db('devices').where({ id, tenant_id: tenantId }).delete();
  } catch (err) {
    if (wasConcentrator) await syncConcentratorPresence(id);
    throw err;
  }
  if (deleted === 0 && wasConcentrator) await syncConcentratorPresence(id);
  if (deleted > 0) emitToTenant(tenantId, SOCKET_EVENTS.DEVICE_DELETED, { deviceId: id });
  return deleted > 0;
}

/** How many CPEs still point at this concentrator. Used to give the operator a
 *  real answer instead of a foreign-key error string. */
export async function concentratorChildCount(tenantId: number, id: number): Promise<number> {
  const [{ count }] = await db('devices')
    .where({ concentrator_id: id, tenant_id: tenantId })
    .count<{ count: string }[]>('id as count');
  return Number(count);
}

// ============================================================================
// Transports and the vault
// ============================================================================

export interface UpsertTransportData {
  enabled?: boolean;
  priority?: number;
  host?: string | null;
  port?: number | null;
  username?: string | null;
  /** Plaintext in, ciphertext stored. Absent = leave the stored one alone;
   *  explicit `null` = delete it. */
  secret?: string | null;
  privateKey?: string | null;
  useTls?: boolean;
  tlsFingerprintSha256?: string | null;
  params?: Record<string, unknown>;
}

/**
 * Create or replace one channel of one device.
 *
 * The vault write is the only interesting part: `secret_enc` and `key_version`
 * are set in the same statement, because a row whose ciphertext and version
 * disagree is undecryptable and nothing will notice until the next rotation.
 */
export async function upsertTransport(
  tenantId: number,
  deviceId: number,
  transport: TransportKind,
  data: UpsertTransportData,
): Promise<PublicTransport> {
  if (!TRANSPORT_KINDS.includes(transport)) {
    throw new Error(`Unknown transport '${transport}'`);
  }
  const device = await getDevice(tenantId, deviceId);
  if (!device) throw new Error(`Device ${deviceId} does not exist in this tenant`);

  const columns: Record<string, unknown> = {};
  if (data.enabled !== undefined) columns.enabled = data.enabled;
  if (data.priority !== undefined) columns.priority = data.priority;
  if (data.host !== undefined) columns.host = data.host;
  if (data.port !== undefined) columns.port = data.port;
  if (data.username !== undefined) columns.username = data.username;
  if (data.useTls !== undefined) columns.use_tls = data.useTls;
  if (data.tlsFingerprintSha256 !== undefined) {
    columns.tls_fingerprint_sha256 = data.tlsFingerprintSha256;
  }
  if (data.params !== undefined) {
    // params must never carry a credential; the shape is documented per
    // transport by the driver layer and validated by the Zod schema.
    columns.params = JSON.stringify(data.params);
  }
  if (data.secret !== undefined) {
    columns.secret_enc = data.secret === null ? null : encrypt(data.secret);
    columns.key_version = currentKeyVersion();
  }
  if (data.privateKey !== undefined) {
    columns.private_key_enc = data.privateKey === null ? null : encrypt(data.privateKey);
    columns.key_version = currentKeyVersion();
  }

  const write = async (conn: Knex | Knex.Transaction): Promise<TransportRow> => {
    const [written] = await conn('device_transports')
      .insert({ device_id: deviceId, transport, ...columns })
      .onConflict(['device_id', 'transport'])
      .merge({ ...columns, updated_at: conn.fn.now() })
      .returning<TransportRow[]>('*');
    return written;
  };

  let row: TransportRow;
  let certificateRecordCleared = false;
  if (transport === 'routeros_api') {
    // A refused-certificate record (migration 069, tlsPresented.service.ts)
    // says what the box at THIS address and port presented over TLS against
    // THIS pin. A write that changes any of the four makes it describe a
    // channel that no longer exists — and a channel switched to cleartext
    // never handshakes again, so nothing else would ever forget it. Cleared
    // here with its alerts, under the lock the record and the re-pin take, so
    // a refusal being recorded and this write never interleave. A save that
    // changes none of them (a password, a priority) keeps it.
    row = await db.transaction(async (trx) => {
      await lockDeviceTls(trx, deviceId);
      const prev = (await trx('device_transports')
        .where({ device_id: deviceId, transport })
        .forUpdate()
        .first('host', 'port', 'use_tls', 'tls_fingerprint_sha256', 'tls_presented_sha256')) as
        | {
            host: string | null;
            port: number | null;
            use_tls: boolean | null;
            tls_fingerprint_sha256: string | null;
            tls_presented_sha256: string | null;
          }
        | undefined;
      const pin = (fp: string | null | undefined): string | null => (fp ? normalisePin(fp) : null);
      if (
        prev &&
        prev.tls_presented_sha256 !== null &&
        ((data.host !== undefined && (data.host ?? null) !== prev.host) ||
          (data.port !== undefined && (data.port ?? null) !== prev.port) ||
          (data.useTls !== undefined && data.useTls !== (prev.use_tls === true)) ||
          (data.tlsFingerprintSha256 !== undefined && pin(data.tlsFingerprintSha256) !== pin(prev.tls_fingerprint_sha256)))
      ) {
        columns.tls_presented_sha256 = null;
        columns.tls_presented_at = null;
        certificateRecordCleared = true;
      }
      const written = await write(trx);
      if (certificateRecordCleared) await settleCertificateAlerts(trx, deviceId);
      return written;
    });
  } else {
    row = await write(db);
  }

  logger.info(
    { deviceId, transport, secretChanged: data.secret !== undefined, certificateRecordCleared },
    'Device transport saved',
  );

  if (transport === 'routeros_api') {
    // The pool compares a target fingerprint on every `acquire()` since the
    // fingerprint fix, so a stale session would be dropped lazily anyway. Doing
    // it here as well makes the rotation take effect on the spot rather than on
    // the next dial, which is what an operator who just changed a password
    // expects — and it is the only way the CHR's `/ppp/active/listen`, which
    // holds the socket open indefinitely, ever notices.
    getRouterOsPool().close(String(deviceId));
    if (device.role === 'concentrator') {
      await syncConcentratorPresence(deviceId, { restart: true });
    }
  }
  return toPublicTransport(row);
}

export async function listTransports(
  tenantId: number,
  deviceId: number,
): Promise<PublicTransport[]> {
  const device = await getDevice(tenantId, deviceId);
  if (!device) throw new Error(`Device ${deviceId} does not exist in this tenant`);
  const rows = await db('device_transports')
    .where({ device_id: deviceId })
    .orderBy('priority')
    .select<TransportRow[]>('*');
  return rows.map(toPublicTransport);
}

export async function deleteTransport(
  tenantId: number,
  deviceId: number,
  transport: TransportKind,
): Promise<boolean> {
  const device = await getDevice(tenantId, deviceId);
  if (!device) throw new Error(`Device ${deviceId} does not exist in this tenant`);
  const n = await db('device_transports').where({ device_id: deviceId, transport }).delete();
  if (n > 0 && transport === 'routeros_api') {
    getRouterOsPool().close(String(deviceId));
    // No transport left to listen on: a monitor kept alive here would retry
    // every 5 s against a device that can no longer be dialled.
    if (device.role === 'concentrator') await stopConcentratorPresence(deviceId);
  }
  return n > 0;
}

// ============================================================================
// Connection test
// ============================================================================

interface SshTransportRow {
  host: string | null;
  port: number | null;
  username: string | null;
  secret_enc: string | null;
  enabled: boolean;
  params: unknown;
}

export interface ConnectionTestResult {
  ok: boolean;
  transport: TransportKind;
  /** Address actually dialled — reported so an operator can see that a stale
   *  tunnel IP is what failed, rather than guessing. */
  dialled: string | null;
  latencyMs: number | null;
  identity: { systemIdentity: string | null; serial: string | null; pppUsername: string | null } | null;
  tlsFingerprintSha256: string | null;
  error: string | null;
}

/**
 * "Does this credential work?" — the button next to a transport row.
 *
 * Three channels dial: `routeros_api` (through the pool, identity read),
 * `snmp` (one GET with the device's own credential) and `ssh` (the handshake,
 * plus one read-only command on RouterOS). Every other channel returns an
 * explicit refusal rather than a green tick that means nothing.
 *
 * A device whose status is `disabled` is refused before ANY of them dials —
 * the same invariant `resolveRouterOsTarget` and `assertTargetBinding` hold
 * ("no transport may be opened"). A decommissioned CPE keeps its transport
 * rows, and their host is an old tunnel or public address that may belong to
 * another box by now: dialling it would hand that box the vault's password or
 * community string.
 */
export async function testTransport(
  tenantId: number,
  deviceId: number,
  transport: TransportKind,
): Promise<ConnectionTestResult> {
  const device = await getDevice(tenantId, deviceId);
  if (!device) throw new Error(`Device ${deviceId} does not exist in this tenant`);

  const base: ConnectionTestResult = {
    ok: false,
    transport,
    dialled: null,
    latencyMs: null,
    identity: null,
    tlsFingerprintSha256: null,
    error: null,
  };

  // Before every branch, so no channel added later can forget it. Nothing is
  // written to the transport row: no dial happened, so nothing was learned
  // about the channel.
  if (device.status === 'disabled') {
    return {
      ...base,
      error: "This device's status is 'disabled', so no transport may be opened to it. "
        + 'Set it back to pending or active first.',
    };
  }

  // ── SNMP: a real GET, because the protocol never refuses ─────────────────
  // There is no handshake to observe: a wrong community, a disabled agent, an
  // address list and a dropped datagram all look identical from here — silence.
  // So the test IS the request, with the device's own credential, and its
  // failure names the four authors rather than picking one.
  if (transport === 'snmp') {
    const started = Date.now();
    try {
      const resolved = await getSnmpTargetForDevice(deviceId);
      if (!resolved) {
        return {
          ...base,
          error: 'This device has no SNMP target, so there is no credential to test with. '
            + 'Name one in Settings — "Automatic SNMP target credential" — and confirmed devices '
            + 'are given a target automatically.',
        };
      }
      const dialable = resolveSnmpTarget(resolved);
      const connection = openSnmpConnection(dialable);
      try {
        const vbs = await getMany(connection, [SNMP_SYS_OID.sysName, SNMP_SYS_OID.sysDescr]);
        const sysName = asSnmpText(vbs.get(SNMP_SYS_OID.sysName));
        await db('device_transports')
          .where({ device_id: deviceId, transport })
          .update({ last_ok_at: db.fn.now(), last_error: null, updated_at: db.fn.now() });
        return {
          ...base,
          ok: true,
          dialled: dialable.host,
          latencyMs: Date.now() - started,
          // sysName is the box's own label. NOT written to `devices` from here:
          // this is a channel test, and `learnDeviceFacts` owns identity.
          identity: sysName ? { systemIdentity: sysName, serial: null, pppUsername: null } : null,
        };
      } finally {
        connection.close?.();
      }
    } catch (err) {
      const message = (err instanceof Error ? err.message : String(err)).slice(0, 500);
      await db('device_transports')
        .where({ device_id: deviceId, transport })
        .update({ last_error: message, updated_at: db.fn.now() });
      return {
        ...base,
        latencyMs: Date.now() - started,
        error: `No answer on UDP 161. SNMP never refuses, so this silence has four possible `
          + 'causes and they are indistinguishable from here: the agent is off '
          + '(`/snmp set enabled=yes`), the community or v3 user is wrong, an address list on '
          + `the agent rejects this server, or a firewall drops the datagram. (${message})`,
      };
    }
  }

  // ── SSH: open the session, and nothing more ──────────────────────────────
  //
  // ┌─ IT USED TO REFUSE, AND THE REFUSAL READ AS A FAILURE ──────────────────┐
  // │ This returned `ok: false` with "there is no standalone connection test   │
  // │ for 'ssh'", so the screen drew a red FAILED beside a channel that had    │
  // │ never been tried. "Not tested" and "broken" are different facts, and     │
  // │ showing the second for the first teaches an operator to distrust a       │
  // │ working channel — then to ignore the red when it finally means           │
  // │ something.                                                               │
  // │                                                                          │
  // │ The old reasoning was that dialling here would duplicate `collectRaw`    │
  // │ and become "a second acquisition path with its own bugs". That holds     │
  // │ for ACQUISITION, and this is not one: nothing is read, parsed, stored    │
  // │ or normalised. The test is the HANDSHAKE — which is exactly what fails   │
  // │ in practice (wrong password, closed port, a device that only offers      │
  // │ legacy key exchange) and exactly what "Collect now" cannot isolate,      │
  // │ because by the time it reports, a parse or a secret refusal may have     │
  // │ failed instead.                                                          │
  // │                                                                          │
  // │ One command is run, and only on RouterOS: `/system/identity/print`,      │
  // │ which reads a label. It proves the session is usable rather than merely  │
  // │ accepted — an SSH account can authenticate and still be denied a shell.  │
  // │ On the other three brands the open/close IS the test: their CLIs have    │
  // │ no command we have ever confirmed to be side-effect free.                │
  // └──────────────────────────────────────────────────────────────────────────┘
  if (transport === 'ssh') {
    const started = Date.now();
    const row = await db('device_transports')
      .where({ device_id: deviceId, transport: 'ssh' })
      .first<SshTransportRow | undefined>(
        'host', 'port', 'username', 'secret_enc', 'enabled', 'params',
      );

    if (!row || !row.host || !row.username) {
      return {
        ...base,
        error: !row
          ? 'This device has no SSH channel. Add one on the Settings tab — "Add a channel" — '
            + 'port 22, with the service account.'
          : 'This SSH channel is incomplete: it needs both a host and a username.',
      };
    }
    if (row.enabled === false) {
      return { ...base, error: 'This SSH channel is disabled. Enable it before testing.' };
    }

    const params = (row.params ?? {}) as { legacyAlgorithms?: boolean };
    try {
      const identity = await withSsh(
        {
          host: row.host,
          port: row.port ?? 22,
          username: row.username,
          password: row.secret_enc ? decrypt(row.secret_enc) : null,
          timeoutMs: 20_000,
          legacyAlgorithms: params.legacyAlgorithms === true,
        },
        async (ssh) => {
          // BRAND, not family. This compared `device.family` to the literal
          // 'mikrotik_routeros', which is not a family: the real values are
          // 'mikrotik_routeros6' and 'mikrotik_routeros7'. `family` is typed as a
          // plain string on this row, so nothing caught it, and the identity read
          // this test was written to perform never ran on any router.
          if (device.brand !== 'mikrotik') return null;
          // Read-only, and never a pty — same rule as the export path (N13).
          const res = await ssh.exec('/system/identity/print', {
            pty: false,
            timeoutMs: 15_000,
            maxOutputBytes: 64 * 1024,
          });
          if (res.code !== null && res.code !== 0) return null;
          const m = /^\s*name:\s*(.+?)\s*$/m.exec(res.stdout ?? '');
          return m ? m[1] : null;
        },
      );

      await db('device_transports')
        .where({ device_id: deviceId, transport: 'ssh' })
        .update({ last_ok_at: db.fn.now(), last_error: null, updated_at: db.fn.now() });

      return {
        ...base,
        ok: true,
        dialled: row.host,
        latencyMs: Date.now() - started,
        // Reported, never written: `learnDeviceFacts` owns identity, and a
        // channel test is not a place that may rewrite what an assertion
        // compares against.
        identity: identity ? { systemIdentity: identity, serial: null, pppUsername: null } : null,
      };
    } catch (err) {
      const message = (err instanceof Error ? err.message : String(err)).slice(0, 500);
      await db('device_transports')
        .where({ device_id: deviceId, transport: 'ssh' })
        .update({ last_error: message, updated_at: db.fn.now() });
      return {
        ...base,
        dialled: row.host,
        latencyMs: Date.now() - started,
        error: `SSH to ${row.host}:${row.port ?? 22} failed: ${message}`,
      };
    }
  }

  if (transport !== 'routeros_api') {
    return {
      ...base,
      // `rest` (SonicOS) stays untested here: its session is stateful and a
      // login costs a slot on the unit, so the dial belongs to the work that
      // needs it rather than to a button.
      error: `There is no standalone connection test for '${transport}'. Use "Collect now" on `
        + 'the Configuration tab, which opens the real session this channel exists for and '
        + 'reports what it found.',
    };
  }

  const started = Date.now();
  try {
    const target = await resolveRouterOsTarget(deviceId);
    const identity = await getRouterOsPool().withConnection(target, (conn) =>
      readRouterOsIdentity(conn, device.ppp_username),
    );
    const latencyMs = Date.now() - started;

    await db('device_transports')
      .where({ device_id: deviceId, transport })
      .update({ last_ok_at: db.fn.now(), last_error: null, updated_at: db.fn.now() });

    return {
      ...base,
      ok: true,
      dialled: target.host,
      latencyMs,
      identity,
    };
  } catch (err) {
    // The transport layer's errors are already redacted (proven by its own
    // self-test); truncating is belt-and-braces before it reaches a column.
    const message = (err instanceof Error ? err.message : String(err)).slice(0, 500);
    await db('device_transports')
      .where({ device_id: deviceId, transport })
      .update({ last_error: message, updated_at: db.fn.now() });
    return { ...base, latencyMs: Date.now() - started, error: message };
  }
}

/**
 * "Test this device" — every ENABLED channel it has, once, in priority order.
 *
 * This is the device-level gesture behind the button on the detail page;
 * `testTransport()` above is the channel-level one. Both exist because they
 * answer different questions ("can we reach this box at all?" vs "does this
 * credential work?").
 *
 * Sequential on purpose. Opening four channels to the same box at once is how
 * a management CPU on a small CPE gets saturated by a diagnostic, and the
 * RouterOS channel in particular shares one pooled socket per device whose
 * dial budget is global. A device with four channels takes four
 * round trips; that is the correct cost of the question.
 *
 * A failing channel is a RESULT, not an error: the operator asked, and "no"
 * is the answer. Only a device that does not exist in this tenant throws.
 */
export async function testAllTransports(
  tenantId: number,
  deviceId: number,
): Promise<ConnectionTestResult[]> {
  const device = await getDevice(tenantId, deviceId);
  if (!device) throw new Error(`Device ${deviceId} does not exist in this tenant`);

  const rows = await db('device_transports')
    .where({ device_id: deviceId, enabled: true })
    .orderBy('priority')
    .select<Array<{ transport: string }>>('transport');

  const results: ConnectionTestResult[] = [];
  for (const row of rows) {
    results.push(await testTransport(tenantId, deviceId, row.transport as TransportKind));
  }
  return results;
}

// ============================================================================
// Session history
// ============================================================================

export async function deviceSessions(
  tenantId: number,
  deviceId: number,
  limit = 50,
): Promise<
  Array<{
    id: string;
    pppUsername: string;
    tunnelIp: string | null;
    callerIp: string | null;
    startedAt: string;
    endedAt: string | null;
    durationSeconds: number | null;
    disconnectReason: string | null;
  }>
> {
  const device = await getDevice(tenantId, deviceId);
  if (!device) throw new Error(`Device ${deviceId} does not exist in this tenant`);
  const rows = await db('ppp_sessions')
    .where({ device_id: deviceId })
    .orderBy('started_at', 'desc')
    .limit(limit)
    .select<
      Array<{
        id: string;
        ppp_username: string;
        tunnel_ip: string | null;
        caller_ip: string | null;
        started_at: Date;
        ended_at: Date | null;
        duration_seconds: number | null;
        disconnect_reason: string | null;
      }>
    >('*');
  return rows.map((r) => ({
    id: String(r.id),
    pppUsername: r.ppp_username,
    tunnelIp: r.tunnel_ip,
    callerIp: r.caller_ip,
    startedAt: r.started_at.toISOString(),
    endedAt: r.ended_at ? r.ended_at.toISOString() : null,
    durationSeconds: r.duration_seconds,
    disconnectReason: r.disconnect_reason,
  }));
}

export async function deviceVerdicts(
  tenantId: number,
  deviceId: number,
  limit = 50,
): Promise<
  Array<{
    ts: string;
    verdict: string;
    confidence: number;
    reason: string | null;
    signals: { pppUp: boolean | null; snmpOk: boolean | null; externalOk: boolean | null; cwmpRecent: boolean | null };
  }>
> {
  const device = await getDevice(tenantId, deviceId);
  if (!device) throw new Error(`Device ${deviceId} does not exist in this tenant`);
  const rows = await db('reachability_verdicts')
    .where({ device_id: deviceId })
    .orderBy('ts', 'desc')
    .limit(limit)
    .select<
      Array<{
        ts: Date;
        verdict: string;
        confidence: string;
        reason: string | null;
        ppp_up: boolean | null;
        snmp_ok: boolean | null;
        external_ok: boolean | null;
        cwmp_recent: boolean | null;
      }>
    >('*');
  return rows.map((r) => ({
    ts: r.ts.toISOString(),
    verdict: r.verdict,
    confidence: Number(r.confidence),
    reason: r.reason,
    signals: {
      pppUp: r.ppp_up,
      snmpOk: r.snmp_ok,
      externalOk: r.external_ok,
      cwmpRecent: r.cwmp_recent,
    },
  }));
}

/** Concentrators visible to a tenant. The Discoveries page needs this because
 *  `discoveries` has no tenant column of its own (quarantine is pre-tenant).
 *  In the god view (a platform admin's READ on the master tenant): every
 *  tenant's concentrators, so the review queue covers every box. */
export async function concentratorIdsForTenant(tenantId: number): Promise<number[]> {
  const q = db('devices').where({ role: 'concentrator' });
  applyTenantScope(q, 'tenant_id', tenantId);
  return (await q.pluck<number[]>('id')).map(Number);
}
