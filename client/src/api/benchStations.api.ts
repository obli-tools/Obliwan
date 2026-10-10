import apiClient from './client';
import type { ApiResponse } from '@obliwan/shared';

/**
 * Bench workstations — the platform administrator's half
 * (`server/src/routes/benchStations.routes.ts`, mounted at `/api/bench-stations`).
 *
 * Stations are PLATFORM-scoped: a preparation desk prepares routers for every
 * customer, so no tenant owns one and the server guards every route here with
 * `requireRole('admin')`. The path carries no `/admin/` segment on purpose —
 * the edge proxy bans a caller on it.
 *
 * Nothing on this API ever carries a station's token or its hash.
 */

export type BenchStationStatus = 'pending' | 'approved' | 'revoked';

/** Mirror of the server's `BenchStationDto` (`services/bench/stations.service.ts`). */
export interface BenchStation {
  id: number;
  uuid: string;
  name: string;
  hostname: string | null;
  /**
   * The code the bench displays while it waits for approval (e.g. `4F3A-9C1B`).
   * The administrator approves only the row whose code the person at the desk
   * reads off the bench's screen: a name and a hostname can be copied by
   * anybody who can reach the public registration route, and the address is
   * the Docker bridge gateway for every caller.
   */
  verificationCode: string | null;
  status: BenchStationStatus;
  createdAt: string;
  approvedAt: string | null;
  approvedBy: number | null;
  approvedByUsername: string | null;
  revokedAt: string | null;
  revokedBy: number | null;
  revokedByUsername: string | null;
  lastSeenAt: string | null;
  lastIp: string | null;
  /** Devices this station enrolled — what to look at before revoking it. */
  enrolledDeviceCount: number;
}

/** `applied` = the state changed; `noop` = it was already in that state (a
 *  repeat approval keeps the first approver, by design). */
export type BenchStationOutcome = 'applied' | 'noop';

export interface BenchStationDecision {
  station: BenchStation;
  outcome: BenchStationOutcome;
}

export const benchStationsApi = {
  /** Every station, pending first (the server orders them). */
  async list(): Promise<BenchStation[]> {
    const res = await apiClient.get<ApiResponse<BenchStation[]>>('/bench-stations');
    return res.data.data ?? [];
  },

  /** pending → approved. A revoked station answers 409: revocation is final. */
  async approve(id: number): Promise<BenchStationDecision> {
    const res = await apiClient.post<ApiResponse<BenchStationDecision>>(`/bench-stations/${id}/approve`);
    return res.data.data!;
  },

  /** pending|approved → revoked, final. Effective on the station's next request. */
  async revoke(id: number): Promise<BenchStationDecision> {
    const res = await apiClient.post<ApiResponse<BenchStationDecision>>(`/bench-stations/${id}/revoke`);
    return res.data.data!;
  },
};
