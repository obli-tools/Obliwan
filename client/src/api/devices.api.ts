import apiClient from './client';
import type {
  ApiResponse,
  DeviceBrand,
  DeviceStatus,
  DeviceRole,
  DeviceFamily,
  DeviceHealthCheckView,
} from '@obliwan/shared';
import type {
  Device,
  DeviceDetail,
  DeviceInput,
  DeviceTransport,
  DeviceTransportInput,
  DeviceDiagnosis,
  LearnedFacts,
  TestConnectionResponse,
  TransportTestResult,
} from '@/types/fleet';

export interface DeviceListParams {
  search?: string;
  brand?: DeviceBrand;
  model?: string;
  status?: DeviceStatus;
  role?: DeviceRole;
  siteId?: number;
  groupId?: number;
  /** God view only: narrow to one tenant (ignored by the server otherwise). */
  filterTenantId?: number;
}

/** Strip empty filters so the query string stays readable in the network tab
 *  and the server never has to decide what `brand=` means. */
function clean(params: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') out[k] = v;
  }
  return out;
}

/** The server's page bound (device.schema.ts `limit` max) and how many pages
 *  one list may take. The server used to answer 200 rows by default and the
 *  client never asked for more: a fleet of 484 showed 200 with no sign that
 *  the rest existed (#33). Pages are read until `meta.total` is reached. */
const DEVICE_PAGE = 500;
const DEVICE_MAX_PAGES = 40;

export const devicesApi = {
  async list(params: DeviceListParams = {}): Promise<Device[]> {
    const out: Device[] = [];
    for (let page = 0; page < DEVICE_MAX_PAGES; page++) {
      const res = await apiClient.get<ApiResponse<Device[]> & { meta?: { total?: number } }>('/devices', {
        params: { ...clean(params as Record<string, unknown>), limit: DEVICE_PAGE, offset: out.length },
      });
      const rows = res.data.data ?? [];
      out.push(...rows);
      const total = Number(res.data.meta?.total ?? NaN);
      if (rows.length < DEVICE_PAGE || !Number.isFinite(total) || out.length >= total) break;
    }
    return out;
  },

  async getById(id: number): Promise<DeviceDetail> {
    const res = await apiClient.get<ApiResponse<DeviceDetail>>(`/devices/${id}`);
    return res.data.data!;
  },

  /**
   * Enrol a directly reachable device: the SERVER dials it, reads its identity
   * and keeps the credential in the vault.
   *
   * Distinct from `create()` — which only records a row — and from the bench
   * tool's `/enroll`, which transmits NO credential because a factory password
   * never leaves the preparer's workstation. Here the operator types the one
   * ObliWAN will keep, so the route demands CREDENTIAL_MANAGE.
   *
   * The device lands `pending` whatever happens: a row somebody typed is a
   * CLAIM about a box, confirmed by a human afterwards with the identity the
   * hardware actually reported in front of them.
   */
  async enrollProbe(data: {
    name: string; family: DeviceFamily; host: string; username: string; password: string;
    port?: number; useTls?: boolean; siteId?: number | null; notes?: string | null;
    // The descriptive half of the same form. It travelled nowhere until now:
    // the operator typed a model and a serial in front of the hardware and the
    // route dropped both on the floor.
    role?: DeviceRole; model?: string | null; serial?: string | null;
    pppUsername?: string | null; tunnelIp?: string | null;
  }): Promise<{ device: DeviceDetail | null; identityRead: boolean; connection: unknown }> {
    const res = await apiClient.post('/devices/enroll-probe', data);
    return res.data.data;
  },

  async create(data: DeviceInput): Promise<Device> {
    const res = await apiClient.post<ApiResponse<Device>>('/devices', data);
    return res.data.data!;
  },

  async update(id: number, data: Partial<DeviceInput>): Promise<Device> {
    const res = await apiClient.patch<ApiResponse<Device>>(`/devices/${id}`, data);
    return res.data.data!;
  },

  /**
   * Approve a quarantined device.
   *
   * The human half of anonymous bench enrolment: the workstation presents no
   * credential, so this act IS the authorisation. The server refuses a device
   * with no identity — approving one would produce an active device that
   * refuses every collection and every write.
   */
  async approve(id: number): Promise<Device> {
    const res = await apiClient.post<ApiResponse<Device>>(`/devices/${id}/approve`);
    return res.data.data!;
  },

  async remove(id: number): Promise<void> {
    await apiClient.delete(`/devices/${id}`);
  },

  /**
   * The device's channels — never their credentials.
   *
   * Each row carries `hasSecret` / `hasPrivateKey` booleans; `secret_enc` and
   * `private_key_enc` do not exist in this response, encrypted or otherwise
   * (section 8.2). If either ever appears here, that is a server bug worth
   * stopping the release for, not a field to render.
   *
   * `null` means the endpoint is absent, which the Settings tab says out loud
   * rather than pretending the device has no channel. A 404 is NOT folded in:
   * on this route it means "no such device in your tenant", which is a real
   * answer the caller must be allowed to see.
   */
  async transports(deviceId: number): Promise<DeviceTransport[] | null> {
    try {
      const res = await apiClient.get<ApiResponse<DeviceTransport[]>>(
        `/devices/${deviceId}/transports`,
      );
      return res.data.data ?? [];
    } catch (err) {
      const status = (err as { response?: { status?: number } }).response?.status;
      if (status === 501) return null;
      throw err;
    }
  },

  /**
   * Create or replace one channel.
   *
   * RECONCILED WITH THE SERVER: `PUT /devices/:id/transports/:transport`, not
   * `POST` on the collection. A device has at most one channel of each kind —
   * `(device_id, transport)` is a unique key — so the natural key belongs in
   * the URL and the write is an idempotent upsert. Retrying a `POST` that
   * timed out would otherwise be a second, different question.
   *
   * `secret` is write-only here: it is sent once and no read of this API
   * returns it. The one way back is the audited reveal (`secrets.api.ts`,
   * SECRET_READ).
   */
  async upsertTransport(
    deviceId: number,
    data: DeviceTransportInput,
  ): Promise<DeviceTransport> {
    const { transport, ...body } = data;
    const res = await apiClient.put<ApiResponse<DeviceTransport>>(
      `/devices/${deviceId}/transports/${transport}`,
      body,
    );
    return res.data.data!;
  },

  async removeTransport(deviceId: number, transport: string): Promise<void> {
    await apiClient.delete(`/devices/${deviceId}/transports/${transport}`);
  },

  /**
   * Open every ENABLED channel of the device once and report.
   *
   * A failing channel is a result, not an exception: the operator asked a
   * question and "no" is an answer. Only a device that does not exist in this
   * tenant raises. An unrecognised payload yields an empty result set — never
   * a fabricated "OK", which is the one outcome that would be worse than an
   * error.
   */
  /**
   * The follow-up to a failed test. Deliberately a separate call rather than
   * something the test always does: it opens half a dozen sockets and may run
   * a traceroute, which is a cost an operator should choose to pay, not one
   * charged to every routine check.
   */
  async diagnose(deviceId: number): Promise<DeviceDiagnosis> {
    const res = await apiClient.post<ApiResponse<DeviceDiagnosis>>(`/devices/${deviceId}/diagnose`);
    return res.data.data!;
  },

  /**
   * One run of the permanent health check, now — the scheduler's own code,
   * state row and alerts. Returns the device's health view as it stands after
   * the check, with the settings that apply to it.
   */
  async checkHealth(deviceId: number): Promise<DeviceHealthCheckView> {
    const res = await apiClient.post<ApiResponse<DeviceHealthCheckView>>(
      `/devices/${deviceId}/health-check`,
    );
    return res.data.data!;
  },

  /**
   * Returns the channel results AND whatever the probe taught us about the box.
   *
   * `learned` is null when nothing changed. It is not cosmetic: a device the
   * server has just talked to should stop showing "—" for facts that were on
   * the wire during the test, and a CONFLICT — the box reporting a serial that
   * contradicts the record — is something an operator must be told about
   * rather than left to discover when a write is refused.
   */
  async testConnection(
    deviceId: number,
  ): Promise<{
    results: TransportTestResult[];
    learned: LearnedFacts | null;
    learnError: string | null;
  }> {
    const res = await apiClient.post<ApiResponse<TestConnectionResponse | TransportTestResult[]>>(
      `/devices/${deviceId}/test-connection`,
    );
    const payload = res.data.data;
    if (Array.isArray(payload)) return { results: payload, learned: null, learnError: null };
    if (payload && Array.isArray(payload.results)) {
      return {
        results: payload.results,
        learned: payload.learned ?? null,
        // The server has produced this since the identity read was wired and
        // NOBODY read it here, so a failed read stayed exactly as silent as
        // before the field existed.
        learnError: payload.learnError ?? null,
      };
    }
    return { results: [], learned: null, learnError: null };
  },
};
