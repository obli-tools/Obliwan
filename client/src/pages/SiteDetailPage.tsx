import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, CalendarClock, MapPin, Pencil, Radio, Router, Trash2, History, Braces, Eye } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { CAPABILITIES, SITE_SCHEDULE_CAPABILITY } from '@obliwan/shared';
import { sitesApi } from '@/api/sites.api';
import { useSiteStore } from '@/store/siteStore';
import { useDeviceStore } from '@/store/deviceStore';
import { useAuthStore } from '@/store/authStore';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { PresenceDot } from '@/components/fleet/PresenceDot';
import { VerdictBadge } from '@/components/fleet/VerdictBadge';
import {
  SiteDeleteDialog,
  SiteEditForm,
  fetchSiteEditContext,
  type SiteEditContext,
} from '@/components/sites/SiteEditForm';
import { cn } from '@/utils/cn';
import { deviceStatusStyle } from '@/utils/verdict';
import { formatMaintenanceWindow } from '@/utils/maintenance';
import { anonHostname } from '@/utils/anonymize';
import { SiteSimBlock } from '@/components/mobile/SimBlock';
import { SiteInfraBlock } from '@/components/infraConcentrator/SiteInfraBlock';
import { SiteUplinkBadge, choiceOf, useUplinkLabel } from '@/components/sites/SiteUplink';
import { SiteOpeningHoursCard } from '@/components/sites/OpeningHours';
import type { Device, PppSession, Site } from '@/types/fleet';
import toast from 'react-hot-toast';
import { TenantBadge } from '@/components/common/TenantBadge';

function formatDuration(seconds: number | null, endedAt: string | null, startedAt: string): string {
  const total = seconds ?? Math.max(
    0,
    Math.round(((endedAt ? new Date(endedAt).getTime() : Date.now()) - new Date(startedAt).getTime()) / 1000),
  );
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export function SiteDetailPage() {
  const { id } = useParams<{ id: string }>();
  const siteId = Number(id);
  const navigate = useNavigate();
  const { t } = useTranslation();
  const uplinkLabel = useUplinkLabel();
  const { hasCapability, isAdmin, canWriteObject } = useAuthStore();
  const { removeSite, upsertSite } = useSiteStore();
  const { fetchDevices, presence, siteRollup } = useDeviceStore();
  const [site, setSite] = useState<Site | null>(null);

  // The caller's level on THIS site (`site.access`, from their teams —
  // migration 087): a capability says what they may do, the teams say where.
  const siteWritable = canWriteObject(site);

  // Editing the record is SITE_WRITE (DEVICE_WRITE implies it); its schedule
  // (timezone, window) is SITE_SCHEDULE_CAPABILITY; a delete stays DEVICE_WRITE
  // (shared/src/capabilities.ts). Each also needs 'rw' on this site.
  const canEdit = siteWritable && (hasCapability(CAPABILITIES.SITE_WRITE) || hasCapability(CAPABILITIES.DEVICE_WRITE));
  const canSchedule = siteWritable && hasCapability(SITE_SCHEDULE_CAPABILITY);
  const canDelete = siteWritable && hasCapability(CAPABILITIES.DEVICE_WRITE);
  // The Site tab of /variables, opened on this site (#36: the account manager
  // holds SITE_VARIABLES_WRITE and no menu path to it otherwise).
  const canSiteVariables = hasCapability(CAPABILITIES.TEMPLATE_READ) || hasCapability(CAPABILITIES.SITE_VARIABLES_WRITE);
  const canReadSim = hasCapability(CAPABILITIES.SIM_READ);

  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);
  /** `null` = not read (yet, or the server could not say): the form then
   *  keeps the code read-only and does not offer the country. */
  const [editContext, setEditContext] = useState<SiteEditContext | null>(null);
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);

  /** `null` = the PPP timeline endpoint is not implemented yet — which is NOT
   *  the same thing as "this site has never connected". */
  const [sessions, setSessions] = useState<PppSession[] | null>(null);
  const [sessionsUnavailable, setSessionsUnavailable] = useState(false);
  const [sessionsLoading, setSessionsLoading] = useState(true);

  /** Devices filed under THIS site, filtered by the server (not by the
   *  browser over a paginated fleet list, which used to under-report a busy
   *  site as soon as the collection endpoint truncated). */
  const [siteDevices, setSiteDevices] = useState<Device[]>([]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const detail = await sitesApi.getById(siteId);
      setSite(detail);
      upsertSite(detail);
      setEditContext(await fetchSiteEditContext(siteId));
    } catch (err) {
      const status = (err as { response?: { status?: number } }).response?.status;
      if (status === 404) setNotFound(true);
      else toast.error(t('sites.loadFailed'));
    } finally {
      setLoading(false);
    }
  }, [siteId, t, upsertSite]);

  useEffect(() => {
    if (!Number.isFinite(siteId)) { setNotFound(true); setLoading(false); return; }
    void load();
    // The global fleet fetch still runs: the store feeds the live presence
    // overlay and the sidebar rollup, which are page-wide.
    void fetchDevices();
    sitesApi.devices(siteId).then(setSiteDevices).catch(() => setSiteDevices([]));
    setSessionsLoading(true);
    sitesApi.pppSessions(siteId)
      .then((rows) => {
        setSessions(rows);
        setSessionsUnavailable(rows === null);
      })
      .catch(() => { setSessions(null); setSessionsUnavailable(true); })
      .finally(() => setSessionsLoading(false));
  }, [siteId, load, fetchDevices]);

  const sortedSiteDevices = useMemo(
    () => [...siteDevices].sort((a, b) => a.name.localeCompare(b.name)),
    [siteDevices],
  );

  if (loading && !site) {
    return <div className="flex h-full items-center justify-center"><LoadingSpinner size="lg" /></div>;
  }

  if (notFound || !site) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-4">
        <p className="text-text-muted">{t('sites.notFound')}</p>
        <Link to="/sites"><Button variant="secondary">{t('sites.backToSites')}</Button></Link>
      </div>
    );
  }

  const rollup = siteRollup(site.id);

  const handleSaved = (updated: Site) => {
    // A PATCH answer carries no `access`; the caller's level did not change by saving.
    setSite({ ...updated, access: updated.access ?? site.access });
    upsertSite(updated);
    setEditing(false);
    // The country is not in the site DTO, and the lock may have moved.
    void fetchSiteEditContext(updated.id).then(setEditContext);
  };

  return (
    <div className="p-6">
      <Link to="/sites" className="mb-4 inline-flex items-center gap-1 text-sm text-text-secondary hover:text-text-primary">
        <ArrowLeft size={14} />
        {t('sites.backToSites')}
      </Link>

      <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-accent/10">
            <MapPin size={24} className="text-accent" />
          </div>
          <div>
            <h1 className="flex items-center gap-2 text-2xl font-semibold text-text-primary">
              {anonHostname(site.name)}
              {/* Opened from the god view: whose site this is. */}
              <TenantBadge name={site.tenantName} className="text-[11px]" />
            </h1>
            <div className="mt-1 flex flex-wrap items-center gap-2 text-sm text-text-muted">
              <span className="font-mono">{site.code}</span>
              {editContext?.country && <span className="font-mono">· {editContext.country}</span>}
              {site.address && <span>· {site.address}</span>}
              {site.contact && <span>· {site.contact}</span>}
            </div>
            {/* The declared access link (migration 076): what the 4G backup
                alert, the uplink card and the fleet anomalies read. */}
            <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-text-muted">
              <span>
                {t('sites.uplink.current', {
                  kind: uplinkLabel(choiceOf(site.uplinkKind)),
                  defaultValue: 'Access link: {{kind}}',
                })}
              </span>
              <SiteUplinkBadge kind={site.uplinkKind} />
              {site.uplinkKindSetAt && (
                <span title={new Date(site.uplinkKindSetAt).toLocaleString()}>
                  · {t('sites.uplink.declaredOn', {
                    date: new Date(site.uplinkKindSetAt).toLocaleDateString(),
                    defaultValue: 'declared on {{date}}',
                  })}
                </span>
              )}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {rollup.total > 0 && (
            <span className="flex items-center gap-2 rounded-md border border-border bg-bg-secondary px-3 py-1.5">
              <span className="font-mono text-sm text-text-primary">{rollup.up}/{rollup.total}</span>
              <VerdictBadge verdict={rollup.worstVerdict} />
            </span>
          )}
          {canSiteVariables && (
            <Link to={`/variables?tab=site&site=${site.id}`}>
              <Button variant="secondary" size="sm">
                <Braces size={14} className="mr-1.5" />
                {t('nav.variables')}
              </Button>
            </Link>
          )}
          {canEdit && !editing && (
            <Button variant="secondary" size="sm" onClick={() => setEditing(true)}>
              <Pencil size={14} className="mr-1.5" />
              {t('common.edit')}
            </Button>
          )}
          {canDelete && (
            <Button variant="danger" size="sm" onClick={() => setDeleting(true)}>
              <Trash2 size={14} className="mr-1.5" />
              {t('common.delete')}
            </Button>
          )}
        </div>
      </div>

      {!siteWritable && (hasCapability(CAPABILITIES.SITE_WRITE) || hasCapability(CAPABILITIES.DEVICE_WRITE)) && (
        <p className="mb-4 flex items-center gap-1.5 text-xs text-text-muted">
          <Eye size={12} />
          {t('teamScope.readOnlyHint')}
        </p>
      )}

      {editing && (
        <SiteEditForm
          site={site}
          context={editContext}
          canSchedule={canSchedule}
          onSaved={handleSaved}
          onCancel={() => setEditing(false)}
        />
      )}

      {deleting && (
        <SiteDeleteDialog
          site={{ id: site.id, code: site.code, name: site.name }}
          onClose={() => setDeleting(false)}
          onDeleted={() => {
            removeSite(site.id);
            navigate('/sites');
          }}
        />
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Devices */}
        <section className="rounded-lg border border-border bg-bg-secondary p-4 lg:col-span-2">
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-text-secondary">
            <Router size={14} />
            {t('sites.sections.devices')}
            <span className="font-mono text-[11px] normal-case text-text-muted">({sortedSiteDevices.length})</span>
          </h2>
          {sortedSiteDevices.length === 0 ? (
            <p className="rounded-md border border-dashed border-border px-3 py-6 text-center text-sm text-text-muted">
              {t('sites.noDevice')}
            </p>
          ) : (
            <ul className="divide-y divide-border rounded-md border border-border">
              {sortedSiteDevices.map((device) => {
                const live = presence[device.id] ?? device.presence ?? null;
                return (
                  <li key={device.id} className="flex flex-wrap items-center gap-2 px-3 py-2">
                    <PresenceDot presence={live} size={8} />
                    {device.role === 'concentrator'
                      ? <Radio size={13} className="shrink-0 text-accent" />
                      : <Router size={13} className="shrink-0 text-text-muted" />}
                    <Link to={`/devices/${device.id}`} className="text-sm font-medium text-text-primary hover:text-accent">
                      {anonHostname(device.name)}
                    </Link>
                    <span className="text-[11px] text-text-muted">
                      {t(`fleet.brand.${device.brand}`)} · {device.model ?? '—'}
                    </span>
                    <span className={cn(
                      'rounded-full border px-1.5 py-0.5 text-[10px] font-medium',
                      deviceStatusStyle(device.status),
                    )}>
                      {t(`fleet.status.${device.status}`)}
                    </span>
                    <span className="ml-auto">
                      <VerdictBadge verdict={live?.verdict ?? null} />
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
        </section>

        {/* Maintenance window */}
        <MaintenanceCard site={site} onEdit={canEdit && !editing ? () => setEditing(true) : null} />

        {/* Store opening hours (migration 096): open now, own or inherited,
            and whether its closed hours are its maintenance window. */}
        <SiteOpeningHoursCard site={site} canEdit={canEdit} onSaved={() => void load()} />

        {/* The site's mobile lines: SIM_READ only. */}
        {canReadSim && <SiteSimBlock siteId={site.id} />}

        {/* The site's account on its customer's infrastructure concentrator(s): platform admin. */}
        {isAdmin() && <SiteInfraBlock siteId={site.id} tenantId={site.tenantId} />}

        {/* PPP timeline */}
        <section className="rounded-lg border border-border bg-bg-secondary p-4">
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-text-secondary">
            <History size={14} />
            {t('sites.sections.pppTimeline')}
          </h2>
          {sessionsLoading ? (
            <div className="flex justify-center py-6"><LoadingSpinner /></div>
          ) : sessionsUnavailable ? (
            <p className="rounded-md border border-dashed border-border px-3 py-6 text-center text-xs text-text-muted">
              {t('sites.pppUnavailable')}
            </p>
          ) : !sessions || sessions.length === 0 ? (
            <p className="rounded-md border border-dashed border-border px-3 py-6 text-center text-xs text-text-muted">
              {t('sites.noPppSession')}
            </p>
          ) : (
            <ol className="space-y-2">
              {sessions.map((session) => (
                <li key={session.id} className="flex items-start gap-2 border-l-2 border-border pl-3">
                  <span
                    className={cn(
                      'mt-1.5 inline-block h-2 w-2 shrink-0 rounded-full',
                      session.endedAt === null ? 'bg-status-up' : 'bg-text-muted',
                    )}
                  />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-baseline gap-2">
                      <span className="font-mono text-[12px] text-text-primary">{session.pppUsername}</span>
                      <span className="text-[11px] text-text-muted">
                        {new Date(session.startedAt).toLocaleString()}
                        {' → '}
                        {session.endedAt
                          ? new Date(session.endedAt).toLocaleString()
                          : t('sites.stillOpen')}
                      </span>
                      <span className="font-mono text-[11px] text-text-muted">
                        {formatDuration(session.durationSeconds, session.endedAt, session.startedAt)}
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-2 font-mono text-[10px] text-text-muted">
                      {session.tunnelIp && <span>tunnel {session.tunnelIp}</span>}
                      {session.callerIp && <span>caller {session.callerIp}</span>}
                      {session.disconnectReason && <span>{session.disconnectReason}</span>}
                    </div>
                  </div>
                </li>
              ))}
            </ol>
          )}
        </section>
      </div>
    </div>
  );
}

// ── Maintenance window (display) ────────────────────────────────────────────
//
// Read-only: the window is edited in the site form (SiteEditForm), together
// with the timezone it is judged in — editing one without the other is how a
// window ends up evaluated in the wrong zone.

function MaintenanceCard({
  site,
  onEdit,
}: {
  site: Site;
  /** null = the viewer may not edit, or the form is already open. */
  onEdit: (() => void) | null;
}) {
  const { t, i18n } = useTranslation();

  return (
    <section className="rounded-lg border border-border bg-bg-secondary p-4">
      <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-text-secondary">
        <CalendarClock size={14} />
        <span className="flex-1">{t('sites.sections.maintenance')}</span>
        {onEdit && (
          <button
            type="button"
            onClick={onEdit}
            className="rounded p-1 normal-case text-text-muted hover:text-text-primary"
            aria-label={t('common.edit')}
          >
            <Pencil size={13} />
          </button>
        )}
      </h2>

      <p className="mb-3 text-xs text-text-muted">
        {t('sites.edit.windowHint', {
          defaultValue:
            'Changes are pushed only inside this window, in its own time zone when it carries one, otherwise in the site’s. No window means no constraint: changes may be pushed at any time.',
        })}
      </p>

      <div className="mb-3 rounded-md border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary">
        {formatMaintenanceWindow(site.maintenanceWindow, i18n.language)
          ?? <span className="italic text-text-muted">{t('sites.noMaintenanceWindow')}</span>}
      </div>
      <p className="font-mono text-[11px] text-text-muted">{t('sites.fields.timezone')}: {site.timezone}</p>
    </section>
  );
}
