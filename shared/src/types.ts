// ============================================================================
// @obliwan/shared — core DTOs shared by server and client
// ============================================================================
//
// Scope of this file: the core contract only — identity, tenants, device
// groups, settings envelope, notifications, SMTP, app config, teams/RBAC.
//
// Domain models for later milestones do NOT belong here:
//   ncm/        NcmDocument, resources, semantic keys, PlanOp
//   intent/    IntentDocument
//   device.ts   DeviceBrand, TransportKind, DeviceCapabilities
//   telemetry.ts InterfaceSample, ReachabilityVerdict
// They are created by their own milestone, not stubbed here.

import type { SettingsKey } from './settings';
import type { TenantRole } from './capabilities';

// ============================================
// User types
// ============================================
export const USER_ROLES = ['admin', 'user'] as const;
export type UserRole = (typeof USER_ROLES)[number];

/**
 * The Obli Design themes. Persisted client-side under the `ow-theme` key.
 * `obli-dim` is the mid-dark (Nord Polar Night) companion of `obli-daylight`:
 * it changes neutrals only, the ObliWAN amber accent stays as in Operator.
 */
export type AppTheme = 'obli-operator' | 'obli-daylight' | 'obli-dim' | 'modern' | 'neon';

export const APP_THEMES: readonly AppTheme[] = [
  'obli-operator',
  'obli-daylight',
  'obli-dim',
  'modern',
  'neon',
];

export interface UserPreferences {
  toastEnabled: boolean;
  toastPosition: 'top-center' | 'bottom-right';
  multiTenantNotificationsEnabled?: boolean;
  preferredTheme?: AppTheme;
  anonymousMode?: boolean;
}

/** Shape of a live alert as returned by the server. */
export interface LiveAlertData {
  id: number;
  tenantId: number;
  tenantName?: string;
  severity: 'down' | 'up' | 'warning' | 'info';
  title: string;
  message: string;
  navigateTo: string | null;
  stableKey: string | null;
  read: boolean;
  createdAt: string;
  /**
   * The grouped operator outage the alert belongs to (migration 095), or
   * null. `outageRole`: 'global' = the god view's group alert, 'tenant' = a
   * customer workspace's, 'member' = a per-store alert folded under it (not
   * sent to the channels; shown as a child of the group).
   */
  outageId?: number | null;
  outageRole?: 'global' | 'tenant' | 'member' | null;
}

export interface User {
  id: number;
  username: string;
  displayName: string | null;
  role: UserRole;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
  preferences?: UserPreferences | null;
  email?: string | null;
  preferredLanguage: string;
  enrollmentVersion: number;
  totpEnabled?: boolean;
  emailOtpEnabled?: boolean;
  foreignSource?: string | null;
  /** Profile picture as base64 data URI or remote URL — synced from Obligate when SSO is used. */
  avatar?: string | null;
}

export interface UserWithPassword extends User {
  /** Nullable for SSO-provisioned users, which have no local password. */
  passwordHash: string | null;
}

// ============================================
// Auth / session types
// ============================================
export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  user: User;
  /** Set when the credentials were valid but a second factor is still required. */
  twoFactorRequired?: boolean;
}

/** Second-factor state of the current user. */
export interface TwoFactorStatus {
  totpEnabled: boolean;
  emailOtpEnabled: boolean;
  /** True when app config forces 2FA and the user has not enrolled yet. */
  enrollmentRequired: boolean;
}

/** One active browser session of the current user. */
export interface SessionInfo {
  id: string;
  current: boolean;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: string;
  expiresAt: string;
}

/**
 * Obligate SSO enrollment stamp. `enrollmentVersion` is bumped by Obligate
 * when the federated profile changes; a mismatch forces a resync at login.
 */
export interface EnrollmentState {
  foreignSource: string | null;
  foreignId: string | null;
  foreignSourceUrl: string | null;
  enrollmentVersion: number;
}

// ============================================
// Tenant types
// ============================================
export interface Tenant {
  id: number;
  name: string;
  slug: string;
  createdAt: string;
  updatedAt: string;
}

export interface TenantMembership {
  tenantId: number;
  userId: number;
  role: TenantRole;
}

export interface TenantWithRole extends Tenant {
  role: TenantRole;
}

export interface UserTenantAssignment {
  tenantId: number;
  tenantName: string;
  tenantSlug: string;
  isMember: boolean;
  role: TenantRole;
}

// ============================================
// Device group types
// ============================================
/**
 * A node of the `device_groups` tree (ex `monitor_groups`).
 * The tree carries sites and devices; the transitive closure lives in
 * `group_closure` and drives both RBAC and settings inheritance.
 */
export interface DeviceGroup {
  /** God view only (shared/src/tenants.ts GodViewTenantTag). */
  tenantId?: number;
  tenantName?: string | null;
  id: number;
  name: string;
  slug: string;
  description: string | null;
  parentId: number | null;
  sortOrder: number;
  /** The undeletable catch-all group of a tenant. */
  isGeneral: boolean;
  groupNotifications: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface GroupTreeNode extends DeviceGroup {
  children: GroupTreeNode[];
}

export interface CreateGroupRequest {
  name: string;
  description?: string | null;
  parentId?: number | null;
  sortOrder?: number;
  isGeneral?: boolean;
  groupNotifications?: boolean;
}

export interface UpdateGroupRequest {
  name?: string;
  description?: string | null;
  parentId?: number | null;
  sortOrder?: number;
  isGeneral?: boolean;
  groupNotifications?: boolean;
}

export interface MoveGroupRequest {
  newParentId: number | null;
}

// ============================================
// Settings types
// ============================================
/** Inheritance chain: global → group chain → device. */
export type SettingsScope = 'global' | 'group' | 'device';

export interface SettingValue {
  value: number;
  /** `instance`: the Default (master) workspace's own global value, which
   *  every other workspace inherits until it sets its own. */
  source: SettingsScope | 'default' | 'instance';
  sourceId: number | null;
  sourceName: string;
}

export type ResolvedSettings = Record<SettingsKey, SettingValue>;

// ============================================
// Notification types
// ============================================
export interface NotificationChannel {
  id: number;
  name: string;
  type: string;
  config: Record<string, unknown>;
  isEnabled: boolean;
  createdBy: number | null;
  tenantId?: number;
  isShared?: boolean;
  createdAt: string;
  updatedAt: string;
}

export type OverrideMode = 'merge' | 'replace' | 'exclude';

export type NotificationScope = 'global' | 'group' | 'device';

export interface NotificationBinding {
  id: number;
  channelId: number;
  scope: NotificationScope;
  scopeId: number | null;
  overrideMode: OverrideMode;
}

export interface NotificationPluginMeta {
  type: string;
  name: string;
  description: string;
  configFields: NotificationConfigField[];
}

export interface NotificationConfigField {
  key: string;
  label: string;
  type: 'text' | 'password' | 'number' | 'url' | 'textarea' | 'boolean' | 'smtp_server_select' | 'select';
  placeholder?: string;
  required?: boolean;
  /** `select` only: the choices, and the one shown when nothing is stored. */
  options?: Array<{ value: string; label: string }>;
  defaultValue?: string;
}

/**
 * Per-scope opt-in/opt-out of notification categories. `null` means "inherit
 * from the parent scope"; only the global level is fully resolved.
 */
export interface NotificationTypeConfig {
  /** Master switch for the scope. */
  global: boolean | null;
  /** A device became unreachable. */
  down: boolean | null;
  /** A device came back. */
  up: boolean | null;
  /** A configuration drift was detected on a managed device. */
  drift: boolean | null;
  /** A change job failed or rolled back. */
  change: boolean | null;
  /** A monitored threshold (interface saturation, errors, …) was crossed. */
  threshold: boolean | null;
}

export const DEFAULT_NOTIFICATION_TYPES: Required<{
  [K in keyof NotificationTypeConfig]: boolean;
}> = {
  global: true,
  down: true,
  up: true,
  drift: true,
  change: true,
  threshold: true,
};

export interface CreateNotificationChannelRequest {
  name: string;
  type: string;
  config: Record<string, unknown>;
  isEnabled?: boolean;
}

export interface UpdateNotificationChannelRequest {
  name?: string;
  config?: Record<string, unknown>;
  isEnabled?: boolean;
}

// ============================================
// SMTP server types
// ============================================
export interface SmtpServer {
  id: number;
  name: string;
  host: string;
  port: number;
  secure: boolean;
  username: string;
  fromAddress: string;
  createdAt: string;
  updatedAt: string;
}

export interface CreateSmtpServerRequest {
  name: string;
  host: string;
  port: number;
  secure: boolean;
  username: string;
  password: string;
  fromAddress: string;
}

export interface UpdateSmtpServerRequest {
  name?: string;
  host?: string;
  port?: number;
  secure?: boolean;
  username?: string;
  /** Omit to keep the stored password. */
  password?: string;
  fromAddress?: string;
}

// ============================================
// App config types
// ============================================
export interface AppConfig {
  allow_2fa: boolean;
  force_2fa: boolean;
  otp_smtp_server_id: number | null;
  obligate_url: string | null;
  obligate_enabled: boolean;
  /** Third-party ASN lookups of site WAN addresses (Team Cymru DNS). Off unless an admin turns it on. */
  asn_lookup_enabled: boolean;
}

/**
 * Obligate SSO gateway settings stored under `obligate_config` in app_config.
 * The raw apiKey is never exposed to clients — only `apiKeySet` (boolean).
 */
export interface ObligateConfig {
  url: string | null;
  apiKeySet: boolean;
  /**
   * Whether the PUBLIC application id is configured. Reported separately from
   * `apiKeySet` because they are two different secrets-classes: `apiKey` is the
   * server-to-server bearer and never leaves the server, `clientId` is the only
   * half allowed in the /authorize URL. `/auth/sso-redirect` fails closed when
   * it is missing, so without this flag an operator sees `apiKeySet: true,
   * enabled: true` and no way to tell why SSO does not work.
   */
  clientIdSet: boolean;
  enabled: boolean;
}

// ============================================
// Team & permission types
// ============================================
export type PermissionLevel = 'ro' | 'rw';
/**
 * `monitor` scope becomes `device`. `ungrouped` (migration 084,
 * Obliance's scope): the tenant's devices filed under no group, and its sites
 * that carry no device yet; `scopeId` is 0.
 */
export type PermissionScope = 'group' | 'device' | 'ungrouped';

export interface UserTeam {
  id: number;
  name: string;
  description: string | null;
  canCreate: boolean;
  tenantId: number;
  tenantName?: string;
  createdAt: string;
  updatedAt: string;
}

export interface TeamPermission {
  id: number;
  teamId: number;
  scope: PermissionScope;
  scopeId: number;
  level: PermissionLevel;
}

export interface PermissionSet {
  id: number;
  name: string;
  slug: string;
  /** Values from `CAPABILITIES` in capabilities.ts — the single vocabulary. */
  capabilities: string[];
  /** Builtin set (one of the four tenant roles): not deletable. */
  isDefault: boolean;
  createdAt: string;
  /** Matrix hint (migration 084). */
  description?: string | null;
  updatedAt?: string;
  /** Memberships holding this set as their tenant role, across every tenant. */
  memberCount?: number;
  /** Tenants in which at least one membership holds it. */
  tenantCount?: number;
}

export interface UserPermissions {
  canCreate: boolean;
  teams: number[];
  permissions: Record<string, PermissionLevel>;
  /** Feature capabilities the user holds (admin ⇒ all). See capabilities.ts. */
  capabilities: string[];
  /**
   * True only for a PLATFORM admin (`users.role = 'admin'`), who sees the
   * whole tenant without a team. Everybody else — the tenant `admin` role
   * included since migration 087 (Obliance: a tenant admin sees what its teams
   * cover) — sees the devices, sites and groups their teams cover
   * (`permissions`, keys `group:<id>`, `device:<id>`, `ungrouped:0`).
   */
  tenantWide?: boolean;
  /** The tenant role (a permission-set slug) on the current tenant, if any. */
  tenantRole?: string | null;
  /**
   * Whether the user may create a site / import sites in this tenant: 'rw' on
   * every site of the tenant, the ungrouped grant included (the server's
   * `requireEverySiteWritable`). Always true for a platform admin.
   */
  canCreateSites?: boolean;
}

/**
 * The caller's level on ONE object of a list or detail answer (migration 087).
 *
 * WIRE CONVENTION — one spelling everywhere: device, site, SIM line, change
 * job, rollout and drift run / finding payloads carry an optional
 * `access: 'ro' | 'rw'`, computed by the server from the caller's teams (a
 * platform admin is always 'rw'). Rows the caller cannot read are never sent,
 * so the field only ever says "read only" or "writable". Absent = the server
 * did not annotate that payload; a client then falls back to its own map.
 */
export type ObjectAccess = PermissionLevel;

export interface CreateTeamRequest {
  name: string;
  description?: string | null;
  canCreate?: boolean;
}

export interface UpdateTeamRequest {
  name?: string;
  description?: string | null;
  canCreate?: boolean;
}

export interface SetTeamMembersRequest {
  userIds: number[];
}

export interface SetTeamPermissionsRequest {
  permissions: Array<{
    scope: PermissionScope;
    scopeId: number;
    level: PermissionLevel;
  }>;
}

// ============================================
// User API types
// ============================================
export interface CreateUserRequest {
  username: string;
  password: string;
  displayName?: string | null;
  role?: UserRole;
}

export interface UpdateUserRequest {
  username?: string;
  displayName?: string | null;
  role?: UserRole;
  isActive?: boolean;
}

// ============================================
// Import / export types
// ============================================
/**
 * A portable tenant bundle. The entity list grows with each milestone, but
 * the envelope is fixed now: nothing may be exported that cannot be
 * re-imported (design decision — no orphan entity).
 */
export interface ExportBundleMeta {
  /** Bundle format version — bumped on any breaking envelope change. */
  formatVersion: number;
  /** ObliWAN version that produced the bundle. */
  producedBy: string;
  producedAt: string;
  sourceInstance: string | null;
  tenantSlug: string;
  entityCounts: Record<string, number>;
}

export interface ExportBundle {
  meta: ExportBundleMeta;
  /** Entity name → array of exported records, keyed by their stable `uuid`. */
  entities: Record<string, unknown[]>;
}

export type ImportConflictStrategy = 'skip' | 'overwrite' | 'rename' | 'fail';

export interface ImportOptions {
  targetTenantId: number;
  strategy: ImportConflictStrategy;
  /** Validate and report without writing anything. */
  dryRun: boolean;
}

export interface ImportConflict {
  entity: string;
  uuid: string;
  label: string;
  reason: string;
  resolution: ImportConflictStrategy;
}

export interface ImportResult {
  dryRun: boolean;
  created: Record<string, number>;
  updated: Record<string, number>;
  skipped: Record<string, number>;
  conflicts: ImportConflict[];
  errors: string[];
}

// ============================================
// API envelope types
// ============================================
export interface ApiResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

export interface PaginatedResponse<T> extends ApiResponse<T[]> {
  total: number;
  page: number;
  pageSize: number;
}
