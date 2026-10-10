import apiClient from './client';
import type {
  ApiResponse,
  IdentityAttributeName,
  IdentityEventKind,
  IdentityEventSeverity,
  IdentitySnapshot,
} from '@obliwan/shared';

/**
 * Identity watch (`/api/identity`, `routes/identity.routes.ts`).
 *
 * Every handler of that router answers `{ success: true, data }`, and every
 * read is scoped by the session's tenant server-side. A device or a site of
 * another customer is a 404, never a 403.
 *
 * Only the two calls the identity-events screen needs are wrapped here:
 *   GET  /identity/events                  DEVICE_READ
 *   POST /identity/events/:id/acknowledge  DRIFT_MANAGE
 * `observe` and `sweep` DIAL routers (DEVICE_WRITE) and do not belong on a
 * feed; `baseline-trust` is CONFIG_READ and lives with the config screens.
 */

/** `IdentityEventRecord` in `services/fleet/identityWatch.service.ts`. */
export interface IdentityEvent {
  /** God view only: the event's workspace (server utils/globalView.ts). */
  tenantId?: number;
  tenantName?: string | null;
  id: number;
  uuid: string;
  deviceId: number;
  /** `null` when the device row is gone (LEFT JOIN). */
  deviceName: string | null;
  observationId: number;
  kind: IdentityEventKind;
  severity: IdentityEventSeverity;
  changedAttributes: IdentityAttributeName[];
  previous: IdentitySnapshot;
  observed: IdentitySnapshot;
  /** The last config snapshot no longer describes this box (replacement or
   *  factory reset). A FLAG — the server repairs nothing. */
  invalidatesBaseline: boolean;
  /** Server-side English sentence, rendered verbatim. */
  reason: string;
  detectedAt: string;
  acknowledgedAt: string | null;
  acknowledgedBy: number | null;
  acknowledgement: string | null;
}

/** The query the server accepts. Its schema is `.strict()`: an unknown word is
 *  a 400, so nothing outside this list is ever sent. */
export interface IdentityEventFilter {
  deviceId?: number;
  /** The device's CURRENT site. */
  siteId?: number;
  kind?: IdentityEventKind;
  severity?: IdentityEventSeverity;
  /** Not yet acknowledged. */
  pending?: boolean;
  /** Replacement or factory reset only. */
  invalidating?: boolean;
  /** 1 … 8760. */
  sinceHours?: number;
  /** 1 … 500 (`MAX_EVENT_PAGE`). */
  limit?: number;
}

/** Server ceiling on one page of the feed (`MAX_EVENT_PAGE`). */
export const IDENTITY_EVENT_PAGE_MAX = 500;

function toQuery(f: IdentityEventFilter): Record<string, string> {
  const q: Record<string, string> = {};
  if (f.deviceId !== undefined) q.deviceId = String(f.deviceId);
  if (f.siteId !== undefined) q.siteId = String(f.siteId);
  if (f.kind) q.kind = f.kind;
  if (f.severity) q.severity = f.severity;
  // The server reads the two words `true` / `false` and nothing else; `false`
  // is simply not sent, which is the same answer.
  if (f.pending) q.pending = 'true';
  if (f.invalidating) q.invalidating = 'true';
  if (f.sinceHours !== undefined) q.sinceHours = String(f.sinceHours);
  if (f.limit !== undefined) q.limit = String(f.limit);
  return q;
}

export function identityErrorOf(err: unknown): string {
  const data = (err as { response?: { data?: { error?: string; message?: string } } }).response?.data;
  return data?.error ?? data?.message ?? (err instanceof Error ? err.message : 'Unknown error');
}

export const identityApi = {
  async events(filter: IdentityEventFilter = {}): Promise<IdentityEvent[]> {
    const res = await apiClient.get<ApiResponse<IdentityEvent[]>>('/identity/events', {
      params: toQuery(filter),
    });
    return Array.isArray(res.data.data) ? res.data.data : [];
  },

  /** Records that a human reviewed the event. Repairs nothing; the note is
   *  required (≥ 12 visible characters, one letter or digit). */
  async acknowledge(eventId: number, note: string): Promise<IdentityEvent> {
    const res = await apiClient.post<ApiResponse<IdentityEvent>>(
      `/identity/events/${eventId}/acknowledge`,
      { note },
    );
    if (!res.data.data) throw new Error(res.data.error ?? 'Empty response');
    return res.data.data;
  },
};
