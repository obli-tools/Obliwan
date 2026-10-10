import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { AlertTriangle, ChevronDown, ChevronRight, Fingerprint, RotateCw, X } from 'lucide-react';
import toast from 'react-hot-toast';
import {
  CAPABILITIES,
  IDENTITY_ATTRIBUTES,
  IDENTITY_EVENT_KINDS,
  IDENTITY_EVENT_SEVERITIES,
  MIN_IDENTITY_ACK_NOTE,
  identityAckNoteProblem,
  type IdentityAttributeName,
  type IdentityEventKind,
  type IdentityEventSeverity,
  type IdentitySnapshot,
} from '@obliwan/shared';
import {
  IDENTITY_EVENT_PAGE_MAX,
  identityApi,
  identityErrorOf,
  type IdentityEvent,
} from '@/api/identity.api';
import { useAuthStore } from '@/store/authStore';
import { useDeviceStore } from '@/store/deviceStore';
import { useSiteStore } from '@/store/siteStore';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { When } from '@/components/mobile/SimBits';
import { cn } from '@/utils/cn';
import { GodViewMarker, TenantBadge } from '@/components/common/TenantBadge';
import { GodViewTenantFilter } from '@/components/common/GodViewTenantFilter';

/**
 * ObliWAN — identity changes: what the routers said about THEMSELVES, and
 * when it moved. A serial that changes is a chassis that was swapped; the same
 * serial answering the vendor's default name is a box that was wiped.
 *
 * Reads `GET /api/identity/events` (DEVICE_READ). Every filter on this screen
 * is a SERVER filter — device, site, kind, severity, review state, period —
 * because the feed is paged at 500 rows: a fleet-wide firmware upgrade fills a
 * page, and a site filter applied after it would hide the one replacement the
 * operator came to look for. `siteId` is the device's CURRENT site.
 *
 * The one action is the acknowledgement (`POST …/acknowledge`, DRIFT_MANAGE):
 * a human writes what they found. It REPAIRS NOTHING — no snapshot is deleted,
 * no baseline retired, no device row written — it only stops the event being
 * reported as an unreviewed reason to distrust the reference config.
 *
 * `observe` and `sweep` (DEVICE_WRITE, they dial routers) are deliberately not
 * offered here.
 */

const selectClass =
  'rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent';

const PERIODS: Array<{ hours: number; key: string; en: string }> = [
  { hours: 24, key: '24h', en: 'Last 24 hours' },
  { hours: 168, key: '7d', en: 'Last 7 days' },
  { hours: 720, key: '30d', en: 'Last 30 days' },
  { hours: 2160, key: '90d', en: 'Last 90 days' },
  { hours: 8760, key: '365d', en: 'Last 12 months' },
];

const KIND_EN: Record<IdentityEventKind, string> = {
  identity_learned: 'Identity learned',
  hardware_replacement: 'Hardware replacement',
  factory_reset: 'Factory reset',
  system_identity_renamed: 'Renamed',
  firmware_upgraded: 'Firmware upgraded',
  firmware_downgraded: 'Firmware downgraded',
  firmware_changed: 'Firmware changed',
  model_changed: 'Model changed',
};

const SEVERITY_EN: Record<IdentityEventSeverity, string> = {
  info: 'Info',
  notice: 'Notice',
  critical: 'Critical',
};

const ATTR_EN: Record<IdentityAttributeName, string> = {
  serial: 'Serial',
  system_identity: 'System identity',
  model: 'Model',
  os_version: 'Firmware',
};

/** The snapshot's camelCase key for each attribute name. */
const ATTR_KEY: Record<IdentityAttributeName, keyof IdentitySnapshot> = {
  serial: 'serial',
  system_identity: 'systemIdentity',
  model: 'model',
  os_version: 'osVersion',
};

const SEVERITY_TONE: Record<IdentityEventSeverity, string> = {
  critical: 'border-status-down/40 bg-status-down/10 text-status-down',
  notice: 'border-status-ssl-warning/30 bg-status-ssl-warning/10 text-status-ssl-warning',
  info: 'border-border bg-bg-tertiary text-text-secondary',
};

function kindLabel(t: TFunction, kind: IdentityEventKind): string {
  return t(`identityEvents.kind.${kind}`, { defaultValue: KIND_EN[kind] ?? kind });
}

function attrLabel(t: TFunction, attr: IdentityAttributeName): string {
  return t(`identityEvents.attr.${attr}`, { defaultValue: ATTR_EN[attr] ?? attr });
}

export function IdentityEventsPage() {
  const { t } = useTranslation();
  const { hasCapability } = useAuthStore();
  const { devices, fetchDevices } = useDeviceStore();
  const { sites, fetchSites } = useSiteStore();
  const canAck = hasCapability(CAPABILITIES.DRIFT_MANAGE);

  const [deviceId, setDeviceId] = useState('');
  const [siteId, setSiteId] = useState('');
  const [kind, setKind] = useState<IdentityEventKind | ''>('');
  const [severity, setSeverity] = useState<IdentityEventSeverity | ''>('');
  const [sinceHours, setSinceHours] = useState(720);
  const [pendingOnly, setPendingOnly] = useState(false);
  const [invalidatingOnly, setInvalidatingOnly] = useState(false);

  const [events, setEvents] = useState<IdentityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);
  // Only the newest request may write the list (filters change faster than a
  // 500-row page comes back).
  const seq = useRef(0);

  useEffect(() => {
    void fetchDevices();
    void fetchSites();
  }, [fetchDevices, fetchSites]);

  const load = useCallback(async () => {
    const mine = ++seq.current;
    setLoading(true);
    setLoadError(null);
    try {
      const rows = await identityApi.events({
        deviceId: deviceId ? Number(deviceId) : undefined,
        siteId: siteId ? Number(siteId) : undefined,
        kind: kind || undefined,
        severity: severity || undefined,
        pending: pendingOnly,
        invalidating: invalidatingOnly,
        sinceHours,
        limit: IDENTITY_EVENT_PAGE_MAX,
      });
      if (mine !== seq.current) return;
      setEvents(rows);
    } catch (err) {
      if (mine !== seq.current) return;
      setEvents([]);
      setLoadError(identityErrorOf(err));
    } finally {
      if (mine === seq.current) setLoading(false);
    }
  }, [deviceId, siteId, kind, severity, pendingOnly, invalidatingOnly, sinceHours]);

  useEffect(() => {
    void load();
  }, [load]);

  const deviceById = useMemo(() => new Map(devices.map((d) => [d.id, d])), [devices]);
  const siteById = useMemo(() => new Map(sites.map((s) => [s.id, s])), [sites]);

  // With a site chosen, the device list narrows to that site's devices: the
  // two filters are ANDed server-side, and offering a device of another site
  // would only ever produce an empty list.
  const deviceOptions = useMemo(() => {
    const list = siteId ? devices.filter((d) => d.siteId === Number(siteId)) : devices;
    return [...list].sort((a, b) => a.name.localeCompare(b.name));
  }, [devices, siteId]);

  const activeFilterCount =
    (deviceId ? 1 : 0) +
    (siteId ? 1 : 0) +
    (kind ? 1 : 0) +
    (severity ? 1 : 0) +
    (pendingOnly ? 1 : 0) +
    (invalidatingOnly ? 1 : 0);

  const resetFilters = () => {
    setDeviceId('');
    setSiteId('');
    setKind('');
    setSeverity('');
    setPendingOnly(false);
    setInvalidatingOnly(false);
  };

  const replaceEvent = (next: IdentityEvent) =>
    setEvents((list) => list.map((e) => (e.id === next.id ? next : e)));

  const unreviewedInvalidating = events.filter((e) => e.invalidatesBaseline && e.acknowledgedAt === null).length;

  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-5 flex items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold text-text-primary">
            {t('identityEvents.title', { defaultValue: 'Identity changes' })}
            <GodViewMarker />
          </h1>
          <p className="mt-1 max-w-3xl text-sm text-text-muted">
            {t('identityEvents.subtitle', {
              defaultValue:
                'What the routers said about themselves changed: a replaced chassis, a factory reset, a rename, a firmware move. Nothing here is repaired automatically.',
            })}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <GodViewTenantFilter onChange={() => void load()} />
          <Button variant="secondary" size="sm" onClick={() => void load()}>
            <RotateCw size={14} className={cn('mr-1.5', loading && 'animate-spin')} />
            {t('common.refresh')}
          </Button>
        </div>
      </div>

      {unreviewedInvalidating > 0 && (
        <div className="mb-4 flex items-start gap-2 rounded-lg border border-status-ssl-warning/40 bg-status-ssl-warning/5 p-3 text-xs text-text-secondary">
          <AlertTriangle size={14} className="mt-0.5 shrink-0 text-status-ssl-warning" />
          <p>
            {t('identityEvents.unreviewedBanner', {
              defaultValue:
                '{{count}} unreviewed replacement(s) or factory reset(s) in this list: the last config snapshot of those devices no longer describes the box, and drift computed against it is not drift until someone reviews the change.',
              count: unreviewedInvalidating,
            })}
          </p>
        </div>
      )}

      {/* Filters */}
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <select
          className={selectClass}
          value={sinceHours}
          onChange={(e) => setSinceHours(Number(e.target.value))}
        >
          {PERIODS.map((p) => (
            <option key={p.hours} value={p.hours}>
              {t(`identityEvents.period.${p.key}`, { defaultValue: p.en })}
            </option>
          ))}
        </select>

        <select
          className={selectClass}
          value={siteId}
          onChange={(e) => {
            setSiteId(e.target.value);
            setDeviceId('');
          }}
        >
          <option value="">{t('devices.filters.allSites')}</option>
          {sites.map((s) => (
            <option key={s.id} value={s.id}>
              {s.code ? `${s.code} — ${s.name}` : s.name}
            </option>
          ))}
        </select>

        <select className={selectClass} value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
          <option value="">{t('interfaces.filters.allDevices')}</option>
          {deviceOptions.map((d) => (
            <option key={d.id} value={d.id}>{d.name}</option>
          ))}
        </select>

        <select className={selectClass} value={kind} onChange={(e) => setKind(e.target.value as IdentityEventKind | '')}>
          <option value="">{t('identityEvents.filters.allKinds', { defaultValue: 'All kinds of change' })}</option>
          {IDENTITY_EVENT_KINDS.map((k) => (
            <option key={k} value={k}>{kindLabel(t, k)}</option>
          ))}
        </select>

        <select
          className={selectClass}
          value={severity}
          onChange={(e) => setSeverity(e.target.value as IdentityEventSeverity | '')}
        >
          <option value="">{t('identityEvents.filters.allSeverities', { defaultValue: 'All severities' })}</option>
          {IDENTITY_EVENT_SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {t(`identityEvents.severity.${s}`, { defaultValue: SEVERITY_EN[s] })}
            </option>
          ))}
        </select>

        <Toggle checked={pendingOnly} onChange={setPendingOnly}>
          {t('identityEvents.filters.pendingOnly', { defaultValue: 'Not yet reviewed' })}
        </Toggle>
        <Toggle checked={invalidatingOnly} onChange={setInvalidatingOnly}>
          {t('identityEvents.filters.invalidatingOnly', { defaultValue: 'Invalidates the reference config' })}
        </Toggle>

        {activeFilterCount > 0 && (
          <button
            onClick={resetFilters}
            className="inline-flex items-center gap-1 rounded-md px-2 py-1.5 text-[12px] text-text-muted hover:bg-bg-hover hover:text-text-primary"
          >
            <X size={12} />
            {t('devices.filters.clear')}
          </button>
        )}

        <span className="ml-auto font-mono text-[11px] text-text-muted">
          {t('identityEvents.count', { defaultValue: '{{count}} event(s)', count: events.length })}
        </span>
      </div>

      {events.length >= IDENTITY_EVENT_PAGE_MAX && (
        <p className="mb-3 text-[12px] text-status-ssl-warning">
          {t('identityEvents.limitReached', {
            defaultValue:
              'Showing the newest {{count}} events, the most the server returns at once. Narrow the period or the filters to see older ones.',
            count: IDENTITY_EVENT_PAGE_MAX,
          })}
        </p>
      )}

      {/* Body */}
      {loadError ? (
        <div className="rounded-lg border border-status-ssl-expired/40 bg-status-ssl-expired/5 p-4 text-sm text-status-ssl-expired">
          {t('identityEvents.loadFailed', { defaultValue: 'Could not load identity changes' })} —{' '}
          <span className="font-mono text-xs">{loadError}</span>
        </div>
      ) : loading && events.length === 0 ? (
        <div className="flex justify-center py-16">
          <LoadingSpinner size="lg" />
        </div>
      ) : events.length === 0 ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <Fingerprint size={28} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">
            {activeFilterCount > 0
              ? t('identityEvents.noMatch', { defaultValue: 'No identity change matches these filters.' })
              : t('identityEvents.empty', { defaultValue: 'No identity change recorded over this period.' })}
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border bg-bg-secondary">
          <table className="w-full text-sm">
            <thead className="border-b border-border text-left text-xs text-text-muted">
              <tr>
                <th className="px-4 py-2 font-medium">{t('identityEvents.col.detected', { defaultValue: 'Detected' })}</th>
                <th className="px-4 py-2 font-medium">{t('identityEvents.col.device', { defaultValue: 'Device' })}</th>
                <th className="px-4 py-2 font-medium">{t('identityEvents.col.site', { defaultValue: 'Site' })}</th>
                <th className="px-4 py-2 font-medium">{t('identityEvents.col.kind', { defaultValue: 'Change' })}</th>
                <th className="px-4 py-2 font-medium">{t('identityEvents.col.change', { defaultValue: 'Before → after' })}</th>
                <th className="px-4 py-2 font-medium">{t('identityEvents.col.review', { defaultValue: 'Review' })}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {events.map((e) => {
                const device = deviceById.get(e.deviceId);
                const site = device?.siteId != null ? siteById.get(device.siteId) : undefined;
                const isOpen = expanded === e.id;
                return (
                  <Fragment key={e.id}>
                    <tr
                      onClick={() => setExpanded(isOpen ? null : e.id)}
                      className={cn('cursor-pointer align-top hover:bg-bg-hover', isOpen && 'bg-bg-active')}
                    >
                      <td className="whitespace-nowrap px-4 py-2 text-[12px]">
                        <span className="inline-flex items-center gap-1.5">
                          {isOpen ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                          <When iso={e.detectedAt} />
                        </span>
                      </td>
                      <td className="px-4 py-2">
                        <Link
                          to={`/devices/${e.deviceId}`}
                          onClick={(ev) => ev.stopPropagation()}
                          className="text-text-primary hover:text-accent"
                        >
                          {e.deviceName ??
                            t('identityEvents.unknownDevice', { defaultValue: 'Device #{{id}}', id: e.deviceId })}
                        </Link>
                        {/* God view: whose router this is. */}
                        <TenantBadge name={e.tenantName} className="ml-1.5 align-middle" />
                      </td>
                      <td className="px-4 py-2 text-[12px]">
                        {site ? (
                          <Link
                            to={`/sites/${site.id}`}
                            onClick={(ev) => ev.stopPropagation()}
                            className="text-text-secondary hover:text-accent"
                          >
                            {site.name}
                          </Link>
                        ) : (
                          <span className="text-text-muted">—</span>
                        )}
                      </td>
                      <td className="px-4 py-2">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="text-text-primary">{kindLabel(t, e.kind)}</span>
                          <span
                            className={cn(
                              'inline-flex items-center rounded-full border px-2 py-0.5 text-[11px]',
                              SEVERITY_TONE[e.severity] ?? SEVERITY_TONE.info,
                            )}
                          >
                            {t(`identityEvents.severity.${e.severity}`, { defaultValue: SEVERITY_EN[e.severity] ?? e.severity })}
                          </span>
                        </div>
                        {e.invalidatesBaseline && (
                          <span className="mt-0.5 block text-[11px] text-status-ssl-warning">
                            {t('identityEvents.invalidates', { defaultValue: 'Reference config no longer valid' })}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-2 text-[12px]">
                        {e.changedAttributes.map((attr) => (
                          <div key={attr} className="whitespace-nowrap">
                            <span className="text-text-muted">{attrLabel(t, attr)}: </span>
                            <span className="font-mono text-text-secondary">{e.previous[ATTR_KEY[attr]] ?? '—'}</span>
                            <span className="text-text-muted"> → </span>
                            <span className="font-mono text-text-primary">{e.observed[ATTR_KEY[attr]] ?? '—'}</span>
                          </div>
                        ))}
                      </td>
                      <td className="px-4 py-2 text-[12px]">
                        {e.acknowledgedAt ? (
                          <span className="text-status-up" title={e.acknowledgement ?? undefined}>
                            {t('identityEvents.reviewed', { defaultValue: 'Reviewed' })}{' '}
                            <span className="text-text-muted">
                              {new Date(e.acknowledgedAt).toLocaleDateString()}
                            </span>
                          </span>
                        ) : (
                          <span className="text-status-ssl-warning">
                            {t('identityEvents.pending', { defaultValue: 'Not reviewed' })}
                          </span>
                        )}
                      </td>
                    </tr>
                    {isOpen && (
                      <tr>
                        <td colSpan={6} className="bg-bg-tertiary/30 px-4 py-3">
                          <EventDetail event={e} canAck={canAck} onAcknowledged={replaceEvent} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function Toggle({
  checked,
  onChange,
  children,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  children: React.ReactNode;
}) {
  return (
    <label className="flex cursor-pointer items-center gap-1.5 rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-secondary">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="h-3.5 w-3.5 rounded border-border bg-bg-tertiary accent-accent"
      />
      {children}
    </label>
  );
}

/** The whole of one event: both snapshots side by side, the server's own
 *  explanation, and the review — or the form to write one. */
function EventDetail({
  event: e,
  canAck,
  onAcknowledged,
}: {
  event: IdentityEvent;
  canAck: boolean;
  onAcknowledged: (next: IdentityEvent) => void;
}) {
  const { t } = useTranslation();
  const [note, setNote] = useState('');
  const [saving, setSaving] = useState(false);
  const noteOk = identityAckNoteProblem(note) === null;

  const submit = async () => {
    if (!noteOk) return;
    setSaving(true);
    try {
      const next = await identityApi.acknowledge(e.id, note);
      onAcknowledged(next);
      setNote('');
      toast.success(t('identityEvents.ack.done', { defaultValue: 'Review recorded' }));
    } catch (err) {
      toast.error(identityErrorOf(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <div>
        <table className="w-full text-[12px]">
          <thead className="text-left text-text-muted">
            <tr>
              <th className="py-1 pr-3 font-medium" />
              <th className="py-1 pr-3 font-medium">{t('identityEvents.detail.previous', { defaultValue: 'Before' })}</th>
              <th className="py-1 font-medium">{t('identityEvents.detail.observed', { defaultValue: 'Observed' })}</th>
            </tr>
          </thead>
          <tbody>
            {IDENTITY_ATTRIBUTES.map((attr) => {
              const changed = e.changedAttributes.includes(attr);
              return (
                <tr key={attr}>
                  <td className="py-1 pr-3 text-text-muted">{attrLabel(t, attr)}</td>
                  <td className="py-1 pr-3 font-mono text-text-secondary">{e.previous[ATTR_KEY[attr]] ?? '—'}</td>
                  <td className={cn('py-1 font-mono', changed ? 'font-semibold text-text-primary' : 'text-text-secondary')}>
                    {e.observed[ATTR_KEY[attr]] ?? '—'}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        <p className="mt-2 text-[12px] text-text-secondary">
          <span className="text-text-muted">
            {t('identityEvents.detail.reason', { defaultValue: 'Server explanation' })}:{' '}
          </span>
          {e.reason}
        </p>
      </div>

      <div>
        {e.acknowledgedAt ? (
          <div className="text-[12px]">
            <div className="text-text-muted">
              {t('identityEvents.detail.reviewedAt', { defaultValue: 'Reviewed on {{when}}', when: new Date(e.acknowledgedAt).toLocaleString() })}
            </div>
            <p className="mt-1 whitespace-pre-wrap text-text-primary">{e.acknowledgement}</p>
          </div>
        ) : canAck ? (
          <div>
            <textarea
              value={note}
              onChange={(ev) => setNote(ev.target.value)}
              rows={3}
              maxLength={4000}
              placeholder={t('identityEvents.ack.placeholder', {
                defaultValue: 'What was found (e.g. chassis swapped under RMA 4471, config restored from backup)',
              })}
              className="w-full rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
            />
            <p className="mt-1 text-[11px] text-text-muted">
              {t('identityEvents.ack.hint', {
                defaultValue:
                  'At least {{min}} visible characters, with a letter or a digit. Acknowledging repairs nothing: it records that a human reviewed this change.',
                min: MIN_IDENTITY_ACK_NOTE,
              })}
            </p>
            <Button size="sm" className="mt-2" disabled={!noteOk} loading={saving} onClick={() => void submit()}>
              {t('identityEvents.ack.submit', { defaultValue: 'Record review' })}
            </Button>
          </div>
        ) : (
          <p className="text-[12px] text-text-muted">
            {t('identityEvents.ack.noRight', {
              defaultValue: 'Not reviewed yet. Recording a review requires the “Manage drift” permission.',
            })}
          </p>
        )}
      </div>
    </div>
  );
}
