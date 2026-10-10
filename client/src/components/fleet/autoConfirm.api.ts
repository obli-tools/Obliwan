import apiClient from '@/api/client';
import type { ApiResponse } from '@obliwan/shared';

/**
 * The automatic conformity check of a bench-prepared device — the client half
 * of `server/src/routes/autoConfirm.routes.ts`. Kept beside its panel rather
 * than in `api/devices.api.ts` so the feature lands as one folder.
 *
 * Mirrors `ConformityView` in `server/src/services/fleet/autoConfirm.service.ts`.
 */

/** The live event the server emits on the tenant room after every check. */
export const AUTO_CONFIRM_EVENT = 'wan:device:conformity';

export type ConformityState = 'waiting' | 'conformant' | 'non_conformant' | 'anomaly' | 'superseded';

export interface ConformityDifference {
  op: string;
  resource: string;
  /** Empty when the caller may not read configuration (`configDetail`). */
  semKey: string;
  fields: string[];
  values: Array<{ field: string; intent: string; actual: string }>;
  reason: string;
}

export interface ConformityLimitation {
  resource: string;
  reason: string;
  missingCompared: boolean;
  /** `missing` was established by reading the box (what /export omits). */
  missingReadOnBox: boolean;
  extraCompared: boolean;
  desiredCoverage: string;
  observedCoverage: string;
}

export interface ConformityExcluded {
  /** The access and SNMP blocks' records. Without `fields`: set aside whole
   *  (the `obliwan` account). With `fields`: compared like any other record,
   *  except that these fields carry the value the blocks wrote. */
  accessBlock: Array<{ resource: string; semKey: string; fields?: string[] }>;
  benchFed: Array<{ resource: string; semKey: string; benchKeys: string[] }>;
  benchFedKinds: Array<{ resource: string; benchKeys: string[] }>;
  secretBearing: Array<{ resource: string; semKey: string; secrets: string[] }>;
  unmodelledSections: string[];
  notClaimedKinds: string[];
  /** Lines of the template render that are not configuration (the tail's
   *  DHCP-client release, a `:log`…), set aside before the comparison. */
  nonConfigLines: Array<{ line: number; what: string }>;
  /** Physical interfaces the plan names with nothing modelled. */
  factoryInterfaces: string[];
  /** Services /export omits, compared against the box's own read. */
  readOnBox: string[];
  limitations: ConformityLimitation[];
}

export interface ConformityView {
  deviceId: number;
  deviceStatus: string;
  /** False when the installation switched the automatic check off. */
  enabled: boolean;
  applicable: boolean;
  notApplicableReason: 'not_bench' | 'bench_failed' | null;
  /** False when the caller lacks CONFIG_READ: differences then carry their
   *  kind and operation only, and what was not compared is withheld. */
  configDetail: boolean;
  provisioning: {
    id: string; tag: string; outcome: string; compiledAt: string; revisionId: string | null;
    stationId: number; stationApproved: boolean;
  } | null;
  sessionUp: boolean;
  state: ConformityState | null;
  reasonCode: string | null;
  reason: string | null;
  attempts: number;
  firstAttemptAt: string | null;
  lastAttemptAt: string | null;
  /** Null while `waitingForTunnel`. */
  nextAttemptAt: string | null;
  /** Undecided and the PPP session is down: the next attempt waits for the
   *  tunnel, not for a date. */
  waitingForTunnel: boolean;
  lastError: string | null;
  confirmedAt: string | null;
  decidedAt: string | null;
  method: string | null;
  snapshotId: string | null;
  renderMatchesCompile: boolean | null;
  differenceCount: number | null;
  differences: ConformityDifference[];
  excluded: ConformityExcluded | null;
  planSummary: Record<string, unknown> | null;
  maxAttempts: number;
}

export interface RecheckResult {
  ran: boolean;
  outcome: 'confirmed' | 'non_conformant' | 'anomaly' | 'retry' | 'not_contacted' | 'superseded' | 'skipped';
  message: string;
  view: ConformityView;
}

export const autoConfirmApi = {
  async get(deviceId: number): Promise<ConformityView> {
    const res = await apiClient.get<ApiResponse<ConformityView>>(`/devices/${deviceId}/auto-confirm`);
    return res.data.data!;
  },

  async recheck(deviceId: number): Promise<RecheckResult> {
    const res = await apiClient.post<ApiResponse<RecheckResult>>(`/devices/${deviceId}/auto-confirm/recheck`);
    return res.data.data!;
  },
};
