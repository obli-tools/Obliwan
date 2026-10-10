import apiClient from './client';
import type { ApiResponse, SiteUplinkKind } from '@obliwan/shared';

/**
 * Fleet anomalies (server: `GET /api/fleet-anomalies`, DEVICE_READ —
 * services/fleet/fleetAnomalies.service.ts). Read-only, computed on every
 * call from what ObliWAN already stores. The scope is the server's: the
 * session's tenant, or every tenant for a platform admin on the master tenant.
 */

export interface AnomalyDeviceRef {
  id: number;
  name: string;
  tenantId: number;
  tenantName: string;
  siteId: number | null;
  siteCode: string | null;
  siteName: string | null;
  status: string;
}

export interface DuplicateLogin {
  pppUsername: string;
  reason: 'concurrent' | 'churn' | 'both';
  openSessions: number;
  startsLastHour: number;
  distinctCallersLastHour: number;
  /** null in the tenant view: counted, not listed. */
  callerIps: string[] | null;
  lastStartedAt: string | null;
  device: AnomalyDeviceRef | null;
}

export interface IdentityMismatch {
  device: AnomalyDeviceRef;
  pppUsername: string;
  systemIdentity: string;
  loginSite: string;
  identitySite: string;
  siteCodeAgreesWith: 'login' | 'identity' | 'neither' | null;
}

export interface InventoryModel {
  brand: string;
  model: string | null;
  count: number;
}

export interface InventoryVersion {
  brand: string;
  osVersion: string | null;
  count: number;
  oldest: boolean;
  majorBehind: boolean;
}

export interface SharedPublicIp {
  callerIp: string;
  routers: Array<{ pppUsername: string; device: AnomalyDeviceRef | null; cellular: boolean }>;
  sameSite: boolean;
  anyCellular: boolean;
}

export interface CellularDevice {
  device: AnomalyDeviceRef;
  iface: string;
  gateway: string | null;
  since: string | null;
  observedAt: string;
  stale: boolean;
  online: boolean;
  sessionSince: string | null;
  callerIp: string | null;
  /** The site's declared access link (migration 076); null = not declared. */
  declaredUplink?: SiteUplinkKind | null;
  /** The site is declared 4G-only: cellular is its nominal path, not an
   *  anomaly. Absent on an older server = not expected. */
  expected?: boolean;
}

export interface FleetAnomaliesReport {
  generatedAt: string;
  scope: 'tenant' | 'all';
  duplicateLogins: DuplicateLogin[];
  identityMismatches: IdentityMismatch[];
  inventory: { total: number; models: InventoryModel[]; versions: InventoryVersion[] };
  sharedPublicIps: SharedPublicIp[];
  cellular: CellularDevice[];
}

export const fleetAnomaliesApi = {
  async get(): Promise<FleetAnomaliesReport> {
    const res = await apiClient.get<ApiResponse<FleetAnomaliesReport>>('/fleet-anomalies');
    if (!res.data.data) throw new Error(res.data.error ?? 'Empty response');
    return res.data.data;
  },
};
