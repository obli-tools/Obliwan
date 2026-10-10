import apiClient from './client';
import type { ApiResponse, PlannedWave, RouterOsTargetMode, RouterOsTargetUnresolved } from '@obliwan/shared';

/**
 * Fleet OS upgrade ("mise a jour du parc") - `/api/os-upgrade`.
 *
 *   GET  /api/os-upgrade/devices  -> UpgradeListing      (DEVICE_READ; the change-queue
 *                                                        details only with PLAN_CREATE,
 *                                                        see `queueDetail`)
 *   POST /api/os-upgrade/preview  -> LaunchPreview       (CHANGE_APPLY, writes nothing)
 *   POST /api/os-upgrade          -> LaunchResult        (CHANGE_APPLY; + ROLLOUT_MANAGE
 *                                                        for several devices; + CHANGE_APPROVE
 *                                                        for the override reason every
 *                                                        upgrade carries)
 *   POST /api/os-upgrade/refresh-versions -> VersionRefreshState (DEVICE_WRITE; 202, the
 *                                                        re-read runs in the background)
 *
 * The shapes below mirror `server/src/controllers/osUpgrade.controller.ts`,
 * the only producer. A refusal of the launch arrives as a non-2xx with a
 * machine-readable `code` (and, for `launch_refused`, the list of refused
 * devices): `launchErrorOf()` reads it so the dialog can say WHICH device and
 * WHY instead of a generic failure.
 */

export const UPGRADE_STATUSES = ['behind', 'in_progress', 'unknown', 'up_to_date'] as const;
export type UpgradeStatus = (typeof UPGRADE_STATUSES)[number];

export type UpgradeStatusReason =
  | 'job_active'
  | 'rollout_active'
  | 'version_missing'
  | 'version_unparseable'
  | 'no_target'
  | 'major_differs'
  | 'at_target'
  | 'ahead_of_target'
  | 'below_target';

export type LaunchRefusalCode =
  | 'not_found'
  | 'not_routeros'
  | 'not_active'
  | 'not_managed'
  | 'device_busy'
  | 'in_rollout'
  | 'version_unknown'
  | 'no_target'
  | 'major_differs'
  | 'already_current'
  | 'concentrator';

export interface UpgradeProgress {
  targetVersion: string;
  fromVersion: string | null;
  architecture: string | null;
  fetchedAt: string | null;
  rebootedAt: string | null;
  returnedAt: string | null;
  observedVersion: string | null;
  outcome: string | null;
  outcomeDetail: string | null;
}

/** `id`, `rolloutId`, `createdAt`, `errorMessage` and `upgrade.outcomeDetail`
 *  are null when the caller lacks PLAN_CREATE (`queueDetail: false`), and the
 *  kind of a job that is not an upgrade then reads `other`. */
export interface UpgradeJobRef {
  id: number | null;
  kind: string;
  status: string;
  rolloutId: number | null;
  createdAt: string | null;
  finishedAt: string | null;
  errorMessage: string | null;
  upgrade: UpgradeProgress | null;
}

export interface UpgradeDevice {
  /** God view only: the router's workspace (server utils/globalView.ts). */
  tenantId?: number;
  tenantName?: string | null;
  id: number;
  name: string;
  role: string;
  deviceStatus: string;
  isManaged: boolean;
  family: string;
  model: string | null;
  siteId: number | null;
  siteName: string | null;
  groupId: number | null;
  groupName: string | null;
  clientName: string | null;
  currentVersion: string | null;
  versionSource: 'observed' | 'upgrade_job' | 'inventory' | null;
  versionObservedAt: string | null;
  /** Whole days since the reading; null when undated or absent. */
  versionAgeDays: number | null;
  /** Older than `versionMaxAgeDays`, or undated. Does not change the status. */
  versionStale: boolean;
  architecture: string | null;
  major: number;
  targetVersion: string | null;
  status: UpgradeStatus;
  statusReason: UpgradeStatusReason;
  activeJob: UpgradeJobRef | null;
  lastUpgradeJob: UpgradeJobRef | null;
  /** A `draft` rollout holds the device without running anything. */
  heldByRollout: { id: number | null; name: string | null; status: string; kind: string } | null;
  blockedReason: LaunchRefusalCode | null;
}

export interface VersionRefreshState {
  running: boolean;
  total: number;
  done: number;
  ok: number;
  failed: number;
  failedDeviceIds: number[];
  startedAt: string;
  finishedAt: string | null;
}

export interface UpgradeCounts extends Record<UpgradeStatus, number> {
  total: number;
  /** Behind AND selectable now. */
  behindSelectable: number;
  /** Routers whose version reading is missing or old: what a re-read starts with. */
  needsReading: number;
}

export interface FleetTarget {
  version: string | null;
  mode: RouterOsTargetMode | null;
  unresolvedReason: RouterOsTargetUnresolved | null;
  stale: boolean;
  observedAt: string | null;
}

export interface UpgradeListing {
  devices: UpgradeDevice[];
  counts: UpgradeCounts;
  target: FleetTarget;
  launch: { available: boolean; reason: string | null };
  killSwitch: { blocked: boolean; reason: string | null };
  requires: { overrideReason: boolean; degradedConfirmation: boolean };
  /** False = the change-queue details were withheld: draw no job/rollout link. */
  queueDetail: boolean;
  refresh: VersionRefreshState | null;
  versionMaxAgeDays: number;
}

export interface DeviceRefusal {
  deviceId: number;
  deviceName: string | null;
  code: LaunchRefusalCode;
}

export interface LaunchProblem {
  code: string;
  message: string;
}

export interface LaunchDecision {
  ok: boolean;
  mode: 'job' | 'rollout';
  version: string | null;
  waves: PlannedWave[];
  refusals: DeviceRefusal[];
  problems: LaunchProblem[];
  deviceIds: number[];
  requires: { overrideReason: boolean; degradedConfirmation: boolean };
}

/** The preview adds which router is in which wave, as the rollout service
 *  composes it; null for a single device or a refused decision. */
export interface LaunchPreview extends LaunchDecision {
  waveMembers: Array<{ index: number; label: string; deviceIds: number[] }> | null;
}

/** The server's ceiling on one launch (`MAX_DEVICES`). */
export const MAX_UPGRADE_DEVICES = 500;

export interface LaunchRequest {
  deviceIds: number[];
  version?: string;
  waves?: number[];
  name?: string;
  overrideReason?: string;
  confirmDegraded?: boolean;
}

export interface LaunchResult {
  /** `multi_tenant`: a god-view selection spanning several workspaces —
   *  one job or rollout per workspace, listed in `byTenant`. */
  mode: 'job' | 'rollout' | 'multi_tenant';
  jobId: number | null;
  rolloutId: number | null;
  version: string;
  waves: PlannedWave[];
  byTenant?: Array<{
    tenantId: number;
    tenantName: string | null;
    mode: 'job' | 'rollout';
    jobId: number | null;
    rolloutId: number | null;
    devices: number;
    error?: string;
  }>;
}

export interface LaunchError {
  status: number | null;
  /** `launch_refused`, `backend_unwired`, `kill_switch`, `guard_refused`... or null. */
  code: string | null;
  message: string | null;
  refusals: DeviceRefusal[];
  problems: LaunchProblem[];
}

/** Reads a launch / preview refusal. Never throws. */
export function launchErrorOf(err: unknown): LaunchError {
  const response = (err as { response?: { status?: number; data?: Record<string, unknown> } }).response;
  const data = response?.data ?? {};
  return {
    status: typeof response?.status === 'number' ? response.status : null,
    code: typeof data.code === 'string' ? data.code : null,
    message:
      typeof data.error === 'string'
        ? data.error
        : err instanceof Error
          ? err.message
          : null,
    refusals: Array.isArray(data.refusals) ? (data.refusals as DeviceRefusal[]) : [],
    problems: Array.isArray(data.problems) ? (data.problems as LaunchProblem[]) : [],
  };
}

/** 404 / 501 on the listing = the route is not mounted on this server yet. */
export function isUpgradeRouteAbsent(err: unknown): boolean {
  const st = (err as { response?: { status?: number } }).response?.status;
  return st === 404 || st === 501;
}

export const osUpgradeApi = {
  async listDevices(): Promise<UpgradeListing> {
    const res = await apiClient.get<ApiResponse<UpgradeListing>>('/os-upgrade/devices');
    return res.data.data!;
  },

  /** Everything the launch would decide, with nothing written. */
  async preview(req: LaunchRequest): Promise<LaunchPreview> {
    const res = await apiClient.post<ApiResponse<LaunchPreview>>('/os-upgrade/preview', req);
    return res.data.data!;
  },

  /** Start re-reading versions off the routers whose reading is missing or
   *  old (no ids), or off exactly `deviceIds`. Returns at once (202). */
  async refreshVersions(deviceIds?: number[]): Promise<VersionRefreshState> {
    const res = await apiClient.post<ApiResponse<VersionRefreshState>>(
      '/os-upgrade/refresh-versions',
      deviceIds ? { deviceIds } : {},
    );
    return res.data.data!;
  },

  /** One job for one device, a canary-wave rollout for several. */
  async launch(req: LaunchRequest): Promise<LaunchResult> {
    const res = await apiClient.post<ApiResponse<LaunchResult>>('/os-upgrade', req);
    return res.data.data!;
  },
};
