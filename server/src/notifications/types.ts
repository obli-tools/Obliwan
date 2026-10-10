import type { NotificationConfigField } from '@obliwan/shared';

export interface NotificationPayload {
  entityName: string;
  entityUrl?: string;
  oldStatus: string;
  newStatus: string;
  message?: string;
  timestamp: string;
  appName?: string;
  // Group notification fields
  groupName?: string;
  groupId?: number;
  downMembers?: string[];
  isGroupNotification?: boolean;

  // ── Incident spine (consumed by ticketing channels such as Oblidesk) ──
  /** Identifies ONE incident: identical on its firing and its resolved event,
   *  different for the next incident. Always starts with `obliwan:`. */
  stableKey?: string;
  severity?: 'info' | 'warning' | 'critical';
  /** true: this event closes the incident `stableKey` opened. */
  isRecovery?: boolean;
  /** When the incident STARTED (not when it was noticed). */
  occurredAt?: string;
  recoveredAt?: string;
  occurrenceCount?: number;
  entityId?: number;
  entityType?: 'device' | 'tenant' | 'threshold' | 'sim_line';
  /** Filled by notification.service from the tenant the send is scoped to. */
  tenantId?: number;
  tenantSlug?: string;
  /**
   * Internal routing, never sent anywhere: when set, only channels of these
   * types receive the event. Used to close a device's ticket in a ticketing
   * channel when its recovery was folded into a grouped notice for the others.
   */
  onlyChannelTypes?: string[];
}

export interface NotificationPlugin {
  type: string;
  name: string;
  description: string;
  configFields: NotificationConfigField[];

  send(config: Record<string, unknown>, payload: NotificationPayload): Promise<void>;
  /** `context`: the tenant the operator tests from (a ticketing channel files by tenant). */
  sendTest(config: Record<string, unknown>, context?: { tenantId: number; tenantSlug?: string }): Promise<void>;
}
