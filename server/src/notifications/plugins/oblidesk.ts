import type { NotificationPlugin, NotificationPayload } from '../types';

/**
 * Oblidesk — open, and auto-resolve, service-desk tickets.
 *
 * POST {baseUrl}/api/alerts/ingest with the suite's ingest key (Bearer). The
 * contract is Oblidesk's (`alert.service.ts` `validate`); this is a port of
 * Obliview's plugin with `source: 'obliwan'`.
 *
 * ┌─ WHAT OBLIDESK NEEDS FROM US ────────────────────────────────────────────┐
 * │ • `stableKey`: ONE incident, the same on its firing and its resolved    │
 * │   event. Without it Oblidesk can neither dedupe nor close: the send is  │
 * │   REFUSED here rather than opening one ticket per event.                │
 * │ • `tenantSlug`: Oblidesk files by slug and answers 422 to one it does    │
 * │   not know — the two products' tenant slugs must match.                 │
 * │ • ObliWAN announces each edge ONCE (a down is stamped, a threshold      │
 * │   notifies per transition), so `occurrenceCount` is 1: Oblidesk's       │
 * │   default binding (minOccurrences 2) would never open a ticket. Publish │
 * │   an alert binding for source `obliwan` with minOccurrences 1.          │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * `device.deviceUuid` stays null: a router has no hardware UUID Oblidesk
 * knows, and a serial sent in its place would create fake CIs.
 */

type Severity = 'info' | 'warning' | 'critical';

const SEVERITY_RANK: Record<Severity, number> = { info: 0, warning: 1, critical: 2 };

function normalizeSeverity(value: unknown, fallback: Severity): Severity {
  const s = String(value ?? '');
  return s === 'info' || s === 'warning' || s === 'critical' ? s : fallback;
}

function buildBody(config: Record<string, unknown>, payload: NotificationPayload) {
  return {
    source: 'obliwan' as const,
    version: 1 as const,
    stableKey: payload.stableKey!,
    severity: normalizeSeverity(payload.severity, 'warning'),
    status: payload.isRecovery ? ('resolved' as const) : ('firing' as const),
    title: payload.isGroupNotification
      ? `${payload.groupName ?? payload.entityName} — ${payload.downMembers?.length ?? 1} down`
      : `${payload.entityName} is ${payload.newStatus.toUpperCase()}`,
    message: payload.message ?? null,
    occurredAt: payload.occurredAt ?? payload.timestamp,
    resolvedAt: payload.isRecovery ? payload.recoveredAt ?? payload.timestamp : null,
    occurrenceCount: payload.occurrenceCount ?? 1,
    queueSlug: config.queueSlug ? String(config.queueSlug) : null,
    tenantSlug: payload.tenantSlug ?? null,
    tenantId: payload.tenantId ?? null,
    appName: payload.appName ?? null,
    monitor: {
      id: payload.entityId ?? null,
      name: payload.entityName,
      type: payload.entityType ?? null,
      url: payload.entityUrl ?? null,
      oldStatus: payload.oldStatus,
      newStatus: payload.newStatus,
    },
    group: payload.isGroupNotification
      ? {
          id: payload.groupId ?? null,
          name: payload.groupName ?? null,
          downMonitors: payload.downMembers ?? [],
          failingMonitors: payload.downMembers ?? [],
          totalFailingCount: payload.downMembers?.length ?? null,
        }
      : null,
    device: { agentDeviceId: null, deviceUuid: null },
    maintenance: { inMaintenance: false, suppressedReason: null },
  };
}

export const obliDeskPlugin: NotificationPlugin = {
  type: 'oblidesk',
  name: 'Oblidesk',
  description: 'Open and auto-resolve service desk tickets in Oblidesk',
  configFields: [
    { key: 'baseUrl', label: 'Oblidesk URL', type: 'url', required: true, placeholder: 'https://desk.example.com' },
    { key: 'apiKey', label: 'Alert ingest key', type: 'password', required: true, placeholder: 'Oblidesk setting alertIngestKey' },
    { key: 'queueSlug', label: 'Queue (optional)', type: 'text', placeholder: 'Leave blank for the default queue' },
    {
      key: 'minSeverity',
      label: 'Minimum severity',
      type: 'select',
      defaultValue: 'warning',
      options: [
        { value: 'info', label: 'Info' },
        { value: 'warning', label: 'Warning' },
        { value: 'critical', label: 'Critical' },
      ],
    },
  ],

  async send(config, payload) {
    // Without a stable key Oblidesk cannot dedupe or close: every event would
    // open a new ticket. Refuse instead (logged as a failed send).
    if (!payload.stableKey) {
      throw new Error('Oblidesk: this event has no stable key, refusing to open an undedupable ticket');
    }
    const severity = normalizeSeverity(payload.severity, 'warning');
    const minSeverity = normalizeSeverity(config.minSeverity, 'warning');
    // A recovery always goes through: it closes a ticket that may be open.
    if (!payload.isRecovery && SEVERITY_RANK[severity] < SEVERITY_RANK[minSeverity]) return;

    const url = `${String(config.baseUrl).replace(/\/$/, '')}/api/alerts/ingest`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${String(config.apiKey)}` },
      body: JSON.stringify(buildBody(config, payload)),
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => '');
      throw new Error(`Oblidesk returned ${res.status}${detail ? `: ${detail.slice(0, 200)}` : ''}`);
    }
  },

  async sendTest(config, context) {
    await this.send(config, {
      tenantId: context?.tenantId,
      tenantSlug: context?.tenantSlug,
      entityName: 'Test device',
      oldStatus: 'up',
      newStatus: 'down',
      message: 'This is a test notification from ObliWAN',
      timestamp: new Date().toISOString(),
      stableKey: 'obliwan:test',
      severity: 'critical',
      isRecovery: false,
      occurrenceCount: 1,
    });
  },
};
