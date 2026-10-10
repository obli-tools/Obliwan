import apiClient from './client';
import type { ApiResponse } from '@obliwan/shared';

/**
 * « Rapprochement SIM » — partner client → customer tenant (migration 081).
 * Platform admin in the master workspace only; the server refuses otherwise.
 * Shapes mirror `server/src/services/sim/clientTenant.service.ts`.
 */
export type SimNameMatch = 'exact' | 'partial' | null;

export interface SimClientCandidate {
  tenantId: number;
  tenantName: string;
  nameMatch: SimNameMatch;
  siteCodes: string[];
  strong: boolean;
}

export interface SimClientRow {
  accountId: number;
  accountName: string;
  clientCode: string;
  customerName: string | null;
  lineCount: number;
  lineTenants: Array<{ tenantId: number | null; tenantName: string | null; count: number }>;
  mapping: { tenantId: number; tenantName: string; decidedBy: number | null; decidedAt: string } | null;
  /** An operator removed the mapping (migration 085): no automatic suggestion
   *  is applied to this client until a human maps it again. Absent on an
   *  older server. */
  unmapped?: { decidedBy: number | null; decidedAt: string } | null;
  candidates: SimClientCandidate[];
  autoTenantId: number | null;
}

/** What happens to a client's lines when its mapping is removed. */
export type SimLinesOnUnmap = 'stay' | 'pool';

export interface SimMappingDecision {
  accountId: number;
  clientCode: string;
  tenantId: number | null;
  /** Required by the server when `tenantId` is null; never defaulted. */
  linesOnUnmap?: SimLinesOnUnmap;
}

export interface SimMappingResult {
  accountId: number;
  clientCode: string;
  ok: boolean;
  moved?: number;
  sitesAttached?: number;
  keptElsewhere?: number;
  /** A removal with 'pool': lines returned to the pool. */
  returnedToPool?: number;
  /** A removal with 'pool': lines kept because they are on a router of the workspace. */
  keptOnRouter?: number;
  error?: string;
}

/**
 * A card read in a router's modem whose line could NOT be linked to it
 * (`sim_link_conflicts`, migration 080). Mirrors
 * `server/src/services/sim/linkConflict.service.ts`.
 */
export type SimLinkConflictKind = 'other_tenant' | 'linked_elsewhere' | 'ambiguous';

export interface SimLinkConflict {
  id: number;
  kind: SimLinkConflictKind;
  iccidRead: string;
  /** Equal on the first 19 digits only (check digit printed on one side). */
  prefixMatch: boolean;
  detectedAt: string;
  lastSeenAt: string;
  dismissedAt: string | null;
  dismissedByName: string | null;
  dismissedNote: string | null;
  router: {
    id: number;
    name: string;
    tenantId: number;
    tenantName: string | null;
    siteId: number | null;
    siteName: string | null;
  };
  line: {
    id: number;
    msisdn: string;
    iccid: string | null;
    label: string | null;
    status: string;
    tenantId: number | null;
    tenantName: string | null;
    siteId: number | null;
    siteName: string | null;
    deviceId: number | null;
    deviceName: string | null;
  };
  otherRouters: Array<{ id: number; name: string; tenantId: number; tenantName: string | null }>;
}

export interface SimConflictAssignResult {
  lineId: number;
  deviceId: number;
  tenantId: number;
  previousTenantId: number | null;
  previousDeviceId: number | null;
  siteId: number | null;
  movedTenant: boolean;
  reevaluated: number;
}

const KINDS: readonly SimLinkConflictKind[] = ['other_tenant', 'linked_elsewhere', 'ambiguous'];

/** Defensive on the one field that picks a label: an unknown kind is `ambiguous`,
 *  the one that asks a human to look rather than the one that implies a move. */
function normalizeConflict(raw: SimLinkConflict): SimLinkConflict {
  return {
    ...raw,
    kind: KINDS.includes(raw.kind) ? raw.kind : 'ambiguous',
    prefixMatch: raw.prefixMatch === true,
    otherRouters: Array.isArray(raw.otherRouters) ? raw.otherRouters : [],
  };
}

export const simReconcileApi = {
  async clients(): Promise<SimClientRow[]> {
    const res = await apiClient.get<ApiResponse<SimClientRow[]>>('/sim/reconcile/clients');
    return Array.isArray(res.data.data) ? res.data.data : [];
  },
  async apply(decisions: SimMappingDecision[]): Promise<SimMappingResult[]> {
    const res = await apiClient.put<ApiResponse<SimMappingResult[]>>('/sim/reconcile/mappings', { decisions });
    return Array.isArray(res.data.data) ? res.data.data : [];
  },
  async conflicts(includeDismissed = false): Promise<SimLinkConflict[]> {
    const res = await apiClient.get<ApiResponse<SimLinkConflict[]>>('/sim/reconcile/conflicts', {
      params: includeDismissed ? { includeDismissed: 'true' } : {},
    });
    return Array.isArray(res.data.data) ? res.data.data.map(normalizeConflict) : [];
  },
  async assignConflict(id: number): Promise<SimConflictAssignResult> {
    const res = await apiClient.post<ApiResponse<SimConflictAssignResult>>(`/sim/reconcile/conflicts/${id}/assign`);
    return res.data.data as SimConflictAssignResult;
  },
  async dismissConflict(id: number, note: string | null): Promise<void> {
    await apiClient.post(`/sim/reconcile/conflicts/${id}/dismiss`, { note });
  },
  async reopenConflict(id: number): Promise<void> {
    await apiClient.post(`/sim/reconcile/conflicts/${id}/reopen`);
  },
};
