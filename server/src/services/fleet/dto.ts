/**
 * ObliWAN — the fleet's wire shapes.
 *
 * THE RULE THIS FILE EXISTS TO HOLD: the database speaks `snake_case`, the API
 * speaks `camelCase`, and the translation happens HERE, at the edge, once.
 *
 * It was previously not happening at all: `sites`, `devices` and `discoveries`
 * handed their raw Knex rows to `res.json()`, so the client received
 * `ppp_username` / `site_id` / `is_managed` while every client-side type,
 * store and page was written against `pppUsername` / `siteId` / `isManaged`.
 * Nothing crashed — `undefined` renders as blank — which is precisely why it
 * survived: a device page silently missing its PPP identity looks like a
 * device that has none.
 *
 * SECOND RULE, non-negotiable (section 8.2): `secret_enc` and
 * `private_key_enc` do not appear in this file, in either direction. A
 * transport is serialised by `toPublicTransport()` in `device.service.ts`,
 * which emits `hasSecret` / `hasPrivateKey` booleans and nothing derived from
 * the ciphertext — not its length, not a mask, not the encrypted blob "because
 * it is encrypted anyway". Ciphertext plus a key that leaks later is still a
 * credential; the API never carries it.
 *
 * A note on what these mappers do NOT do: they never invent a field. A join
 * that was not performed yields `null` or an absent key, so the UI can say "not
 * known" instead of rendering a confident wrong answer.
 */

import {
  asRouterOsDeviceMode,
  healthDisplay,
  isSiteUplinkKind,
  readOpeningHours,
  type OpeningHours,
  type SiteOpenState,
  type DeviceHealthCheckView,
  type DeviceHealthState,
  type DeviceHealthSummary,
  type HealthSkipReason,
  type RouterOsDeviceMode,
  type SiteUplinkKind,
} from '@obliwan/shared';
import type { ObjectAccess } from '@obliwan/shared';
import type { DeviceRow, DeviceListItem, PublicTransport } from './device.service';
import type { SiteRow, SiteWithCounts } from './site.service';
import type { DiscoveryRow } from './concentratorDiscovery.service';

// ============================================================================
// Small helpers
// ============================================================================

/** Postgres timestamps arrive as `Date`; the wire carries ISO-8601 strings. */
function iso(value: Date | string | null | undefined): string | null {
  if (value == null) return null;
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function isoRequired(value: Date | string): string {
  return iso(value) ?? new Date(0).toISOString();
}

/** `jsonb` comes back parsed from `pg`, but a column written as a string by an
 *  older path can still arrive as text. Never throw on a display field. */
function json<T>(value: unknown, fallback: T): T {
  if (value == null) return fallback;
  if (typeof value === 'string') {
    try {
      return JSON.parse(value) as T;
    } catch {
      return fallback;
    }
  }
  return value as T;
}

// ============================================================================
// Sites
// ============================================================================

export interface SiteDto {
  id: number;
  uuid: string;
  tenantId: number;
  /** The caller's level on this site (migration 087); set by the controllers, absent on a socket payload. */
  access?: ObjectAccess;
  /** God view only: the owning tenant's name (utils/globalView.ts). */
  tenantName?: string | null;
  code: string;
  name: string;
  address: string | null;
  contact: string | null;
  timezone: string;
  maintenanceWindow: Record<string, unknown> | null;
  /** The declared access link (migration 076); null = not declared, ObliWAN
   *  infers it. A value the CHECK does not know reads as null, never a guess. */
  uplinkKind: SiteUplinkKind | null;
  /** The last declaration ("automatic" included): when, and by which user id. */
  uplinkKindSetAt: string | null;
  uplinkKindSetBy: number | null;
  /** The site's OWN opening hours (migration 096): null = it inherits its
   *  workspace's entirely. Not the effective hours — see `openState`. */
  openingHours: OpeningHours | null;
  /** « Ouvert / Fermé maintenant », in the site's zone; list and detail
   *  endpoints only (attached by the controller). */
  openState?: SiteOpenState;
  /** Detail endpoint only: the workspace's hours this site inherits. */
  tenantOpeningHours?: OpeningHours | null;
  /** Detail endpoint only: no explicit maintenance window, known hours, and
   *  the workspace's `closed_hours_maintenance` on — pushes wait for closing. */
  maintenanceFromClosedHours?: boolean;
  /** « Opérateur du lien fixe » (migration 095); null = not declared (the
   *  provider is then inferred: PPPoE realm, ASN, prefix). */
  fixedProvider: string | null;
  createdAt: string;
  updatedAt: string;
  /** Present only on the list endpoint, which computes them in SQL. */
  deviceCount?: number;
  onlineCount?: number;
  /** List endpoint, and only for a caller holding SIM_READ: the site's SIM
   *  lines as the 4G lines page lists them for this site (site.service
   *  `SiteSimCountOptions`). Absent = not asked, never 0. */
  simCount?: number;
}

export function toSiteDto(row: SiteRow | SiteWithCounts): SiteDto {
  const counts = row as Partial<SiteWithCounts>;
  const dto: SiteDto = {
    id: row.id,
    uuid: row.uuid,
    tenantId: row.tenant_id,
    code: row.code,
    name: row.name,
    address: row.address,
    contact: row.contact,
    timezone: row.timezone,
    maintenanceWindow: json<Record<string, unknown> | null>(row.maintenance_window, null),
    uplinkKind: isSiteUplinkKind(row.uplink_kind) ? row.uplink_kind : null,
    uplinkKindSetAt: iso(row.uplink_kind_set_at),
    uplinkKindSetBy: row.uplink_kind_set_by === null || row.uplink_kind_set_by === undefined ? null : Number(row.uplink_kind_set_by),
    openingHours: readOpeningHours(row.opening_hours),
    fixedProvider: typeof row.fixed_provider === 'string' && row.fixed_provider !== '' ? row.fixed_provider : null,
    createdAt: isoRequired(row.created_at),
    updatedAt: isoRequired(row.updated_at),
  };
  if (counts.tenant_name !== undefined) dto.tenantName = counts.tenant_name;
  if (counts.device_count !== undefined) dto.deviceCount = Number(counts.device_count);
  if (counts.online_count !== undefined) dto.onlineCount = Number(counts.online_count);
  if (counts.sim_count !== undefined && counts.sim_count !== null) dto.simCount = Number(counts.sim_count);
  return dto;
}

// ============================================================================
// Devices
// ============================================================================

/**
 * The client's third presence value.
 *
 * `up: null` means "nothing has been observed yet" and is NOT `false`. Folding
 * the two together is how a healthy fleet turns red on a page load, so the
 * distinction is carried on the wire rather than reconstructed in the UI.
 */
export interface DevicePresenceDto {
  up: boolean | null;
  verdict: string | null;
  at: string | null;
}

/**
 * One read of `/system/device-mode` as the API carries it.
 *
 * The whole object is `null` when nobody has ever asked this router — the state
 * every device is in before its first probe, and the only honest rendering for
 * a brand that has no such notion at all. Inside the object, `mode: null` means
 * we ASKED and the menu did not answer (pre-7.13 firmware, or a service account
 * without the policy): a different fact, and the one that must never be read as
 * "ungated, therefore fine".
 *
 * `device_mode_raw` is deliberately NOT on the wire. It is the ten-odd flags
 * this product does not model, kept server-side as evidence; the page has
 * nothing to do with it and an API field nobody reads is a field that drifts.
 */
export interface DeviceModeDto {
  mode: RouterOsDeviceMode | null;
  schedulerAllowed: boolean | null;
  fetchAllowed: boolean | null;
  observedAt: string;
}

export interface DeviceDto {
  id: number;
  uuid: string;
  tenantId: number;
  /** The caller's level on this device (migration 087); set by the controllers, absent on a socket payload. */
  access?: ObjectAccess;
  /** God view only: the owning tenant's name (utils/globalView.ts). */
  tenantName?: string | null;
  siteId: number | null;
  siteName: string | null;
  siteCode: string | null;
  groupId: number | null;
  name: string;
  brand: string;
  family: string;
  model: string | null;
  serial: string | null;
  osVersion: string | null;
  role: string;
  concentratorId: number | null;
  pppUsername: string | null;
  systemIdentity: string | null;
  tunnelIp: string | null;
  wanPublicIp: string | null;
  sourceIpHint: string | null;
  status: string;
  isManaged: boolean;
  firstSeenAt: string | null;
  lastSeenAt: string | null;
  notes: string | null;
  createdAt: string;
  updatedAt: string;
  deviceMode: DeviceModeDto | null;
  /** Learning mode (migration 089): null when the router is not learning. */
  learning: { since: string; byUserId: number | null } | null;
  presence?: DevicePresenceDto | null;
  /**
   * The permanent health check, compact — present only when the query joined
   * `device_health_checks` (the list). The detail endpoint carries the full
   * `healthCheck` view instead; both derive `display` from the one shared
   * `healthDisplay()`, so a dot and a page can never disagree about a row.
   */
  healthSummary?: DeviceHealthSummary;
}

export function toDeviceDto(row: DeviceRow | DeviceListItem): DeviceDto {
  const listed = row as Partial<DeviceListItem>;
  const dto: DeviceDto = {
    id: row.id,
    uuid: row.uuid,
    tenantId: row.tenant_id,
    siteId: row.site_id,
    siteName: listed.site_name ?? null,
    siteCode: listed.site_code ?? null,
    groupId: row.group_id,
    name: row.name,
    brand: row.brand,
    family: row.family,
    model: row.model,
    serial: row.serial,
    osVersion: row.os_version,
    role: row.role,
    concentratorId: row.concentrator_id,
    pppUsername: row.ppp_username,
    systemIdentity: row.system_identity,
    tunnelIp: row.tunnel_ip,
    wanPublicIp: row.wan_public_ip,
    sourceIpHint: row.source_ip_hint,
    status: row.status,
    isManaged: row.is_managed,
    firstSeenAt: iso(row.first_seen_at),
    lastSeenAt: iso(row.last_seen_at),
    notes: row.notes,
    createdAt: isoRequired(row.created_at),
    updatedAt: isoRequired(row.updated_at),
    // `observed_at` is what makes this a reading rather than an opinion, so it
    // is the field that decides whether the object exists at all: no timestamp,
    // no read, and the wire says `null` instead of shipping three nulls that
    // look like measured answers. Migration 033 enforces the same coupling in
    // the schema.
    deviceMode: row.device_mode_observed_at
      ? {
        mode: asRouterOsDeviceMode(row.device_mode),
        schedulerAllowed: row.device_mode_scheduler,
        fetchAllowed: row.device_mode_fetch,
        observedAt: isoRequired(row.device_mode_observed_at),
      }
      : null,
    learning: row.learning_since
      ? { since: isoRequired(row.learning_since), byUserId: row.learning_by ?? null }
      : null,
  };

  // A god-view list (or a god-view detail) joins the tenant's name; a
  // tenant's own list never carries the key.
  if (listed.tenant_name !== undefined) dto.tenantName = listed.tenant_name;

  // Only the list query joins presence. A row that did not carry the join gets
  // no `presence` key at all rather than a fabricated "down".
  if (listed.ppp_up !== undefined) {
    dto.presence = {
      up: listed.ppp_up,
      verdict: listed.verdict ?? null,
      at: listed.ppp_since ?? null,
    };
  }
  // Same rule for the health check: no join, no key. A joined row with no
  // health row (never checked yet) is `unknown`, which is the truth.
  if (listed.health_state !== undefined) {
    dto.healthSummary = {
      display: healthDisplay(
        listed.health_state === null
          ? null
          : {
            state: listed.health_state as DeviceHealthState,
            consecutiveFailures: Number(listed.health_failures ?? 0),
            skipReason: (listed.health_skip_reason ?? null) as HealthSkipReason | null,
            lastCheckAt: iso(listed.health_last_check_at ?? null),
            intervalSec: listed.health_interval_sec ?? null,
          },
        Date.now(),
        row.status === 'disabled',
      ),
      consecutiveFailures: Number(listed.health_failures ?? 0),
      downSince: iso(listed.health_down_since ?? null),
      lastCheckAt: iso(listed.health_last_check_at ?? null),
    };
  }
  return dto;
}

export interface DeviceHealthDto {
  transport: string;
  connState: string;
  circuitState: string;
  consecutiveFailures: number;
  nextRetryAt: string | null;
  lastError: string | null;
}

export interface DeviceDetailDto extends DeviceDto {
  transports: PublicTransport[];
  /** Per-TRANSPORT circuit breakers (`device_health`, the pool's). */
  health: DeviceHealthDto[];
  /** The permanent check of the device (`device_health_checks`), with the
   *  settings that apply to it now. Absent when the caller did not ask. */
  healthCheck?: DeviceHealthCheckView | null;
}

/**
 * `getDeviceDetail()` already returns camelCase for its joined blocks
 * (`transports`, `health`, `pppUp`, `verdict`); only the device row itself was
 * raw. This folds the two halves into one shape.
 */
export function toDeviceDetailDto(detail: {
  transports: PublicTransport[];
  health: DeviceHealthDto[];
  pppUp: boolean;
  verdict: string | null;
} & DeviceRow): DeviceDetailDto {
  const { transports, health, pppUp, verdict, ...row } = detail;
  return {
    ...toDeviceDto(row as DeviceRow),
    transports,
    health,
    presence: { up: pppUp, verdict, at: iso(row.last_seen_at) },
  };
}

// ============================================================================
// Discoveries
// ============================================================================

export interface DiscoveryDto {
  /** God view only: the bound device's tenant, else the concentrator's. */
  tenantId?: number;
  tenantName?: string | null;
  id: number;
  uuid: string;
  concentratorId: number;
  concentratorName: string | null;
  pppUsername: string;
  remoteAddress: string | null;
  callerIp: string | null;
  profile: string | null;
  pppComment: string | null;
  raw: Record<string, unknown>;
  state: string;
  boundDeviceId: number | null;
  reviewedBy: number | null;
  reviewedAt: string | null;
  firstSeenAt: string;
  lastSeenAt: string;
}

export function toDiscoveryDto(
  row: DiscoveryRow & { concentrator_name?: string | null },
): DiscoveryDto {
  return {
    id: row.id,
    uuid: row.uuid,
    concentratorId: row.concentrator_id,
    concentratorName: row.concentrator_name ?? null,
    pppUsername: row.ppp_username,
    remoteAddress: row.remote_address,
    callerIp: row.caller_ip,
    profile: row.profile,
    pppComment: row.ppp_comment,
    raw: json<Record<string, unknown>>(row.raw, {}),
    state: row.state,
    boundDeviceId: row.bound_device_id,
    reviewedBy: row.reviewed_by,
    reviewedAt: iso(row.reviewed_at),
    firstSeenAt: isoRequired(row.first_seen_at),
    lastSeenAt: isoRequired(row.last_seen_at),
  };
}
