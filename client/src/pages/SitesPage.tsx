import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Antenna, CaseLower, Clock, Eye, FileSpreadsheet, Globe, MapPin, Network, Plus, RotateCw, Search, Trash2, Upload, X } from 'lucide-react';
import { SiteRenameBulkDialog } from '@/components/sites/SiteRenameBulkDialog';
import { useTranslation } from 'react-i18next';
import { CAPABILITIES } from '@obliwan/shared';
import {
  sitesApi,
  SITE_DEPLOYMENT_STATES,
  type SiteDeployment,
  type SiteDeploymentState,
} from '@/api/sites.api';
import {
  SiteDeploymentBadge,
  SiteDeploymentChips,
  type SiteDeploymentLimits,
} from '@/components/sites/SiteDeploymentState';
import { useSiteStore } from '@/store/siteStore';
import { useDeviceStore } from '@/store/deviceStore';
import { useAuthStore } from '@/store/authStore';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { SiteImportModal } from '@/components/sites/SiteImportModal';
import { SiteDeleteDialog } from '@/components/sites/SiteEditForm';
import {
  SiteUplinkBadge,
  SiteUplinkSelect,
  kindOf,
  useUplinkLabel,
  type SiteUplinkChoice,
} from '@/components/sites/SiteUplink';
import { LanRepriseModal } from '@/components/allocation/LanRepriseModal';
import {
  OpenStateBadge,
  OpeningHoursBulkDialog,
  TenantOpeningHoursDialog,
  useCanEditTenantHours,
  type SiteOpeningFields,
} from '@/components/sites/OpeningHours';
import { useTenantStore } from '@/store/tenantStore';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { cn } from '@/utils/cn';
import { verdictStyle } from '@/utils/verdict';
import { anonHostname } from '@/utils/anonymize';
import { formatMaintenanceWindow } from '@/utils/maintenance';
import toast from 'react-hot-toast';
import { GodViewMarker, GodViewTenantCell, GodViewTenantHeader } from '@/components/common/TenantBadge';
import { GodViewTenantFilter } from '@/components/common/GodViewTenantFilter';

interface SiteForm {
  code: string;
  name: string;
  address: string;
  contact: string;
  timezone: string;
}

const emptyForm: SiteForm = {
  code: '',
  name: '',
  address: '',
  contact: '',
  timezone: 'Europe/Paris',
};

export function SitesPage() {
  const { t, i18n } = useTranslation();
  const { sites, isLoading, loadError, fetchSites } = useSiteStore();
  const { devices, fetchDevices, siteRollup } = useDeviceStore();
  const { hasCapability, isAdmin, canWriteObject, canCreateSites } = useAuthStore();

  const canWrite = hasCapability(CAPABILITIES.DEVICE_WRITE);
  // Creating or importing sites needs 'rw' on every site (the server's
  // `requireEverySiteWritable`); editing / deleting / declaring one needs 'rw'
  // on THAT site (`site.access`, migration 087).
  const canAddSite = canWrite && canCreateSites();
  // Declaring a site's access link is editing the site: SITE_WRITE, which
  // DEVICE_WRITE implies (as on the site page).
  const canDeclare = hasCapability(CAPABILITIES.SITE_WRITE) || canWrite;
  // A WAN link rollout: waves (ROLLOUT_MANAGE), writes (CHANGE_APPLY) and the
  // sites' WAN1 variables (SITE_VARIABLES_WRITE).
  const canChangeWan = isAdmin() || (hasCapability(CAPABILITIES.ROLLOUT_MANAGE) && hasCapability(CAPABILITIES.CHANGE_APPLY) &&
    hasCapability(CAPABILITIES.SITE_VARIABLES_WRITE));
  const navigate = useNavigate();
  /** The selected sites' MikroTik routers (concentrators left out), in the
   *  new-rollout panel with the wan_link kind chosen. */
  const openWanLinkRollout = () => {
    const ids = devices
      .filter((d) => d.siteId !== null && d.siteId !== undefined && selected.has(Number(d.siteId)) &&
        d.brand === 'mikrotik' && d.role !== 'concentrator')
      .map((d) => d.id);
    if (ids.length === 0) {
      toast.error(t('wanLink.bulk.noRouter'));
      return;
    }
    navigate(`/rollouts?new=wan_link&devices=${ids.join(',')}`);
  };
  // The SIM column: the server sends `simCount` only to a SIM_READ holder.
  const canReadSim = hasCapability(CAPABILITIES.SIM_READ);
  const uplinkLabel = useUplinkLabel();

  // Multi-select for the bulk access-link declaration. Ids, not rows: a site
  // hidden by the search or the state chip STAYS selected, and the bar says
  // how many of the selection the screen is not showing.
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [bulkChoice, setBulkChoice] = useState<SiteUplinkChoice>('cellular_only');
  const [bulkBusy, setBulkBusy] = useState(false);
  // « Opérateur du lien fixe » for the selection (migration 095); empty = clear.
  const [bulkProvider, setBulkProvider] = useState('');
  // « Tout en minuscules » on the selection (site_rename jobs; platform admins).
  const [showRename, setShowRename] = useState(false);
  // Opening hours (migration 096): the selection's, and the workspace's.
  const [showHoursBulk, setShowHoursBulk] = useState(false);
  const [showTenantHours, setShowTenantHours] = useState(false);
  const canEditTenantHours = useCanEditTenantHours();

  const [search, setSearch] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<SiteForm>(emptyForm);
  const [saving, setSaving] = useState(false);
  const [showImport, setShowImport] = useState(false);
  // The LAN reprise is a platform-admin act on the session's workspace
  // (POST /allocation/tenants/:id/lan-reprise, requireRole('admin')).
  const [showLanReprise, setShowLanReprise] = useState(false);
  const { currentTenantId, tenants } = useTenantStore();

  // Deployment state per site (GET /sites/deployment). Fetched beside the list
  // rather than inside it: a failure here leaves the list usable and says so.
  // A failed REFRESH drops what the previous one returned and clears the state
  // filter: the chips are hidden then, so a filter left on would narrow the
  // table (and the export) with no control left to undo it, and the old states
  // would be drawn as if they were current.
  const [deployments, setDeployments] = useState<Map<number, SiteDeployment>>(new Map());
  const [deploymentFailed, setDeploymentFailed] = useState(false);
  const [deploymentAt, setDeploymentAt] = useState<number>(() => Date.now());
  const [deploymentLimits, setDeploymentLimits] = useState<SiteDeploymentLimits | null>(null);
  const [stateFilter, setStateFilter] = useState<SiteDeploymentState | null>(null);
  const [exporting, setExporting] = useState(false);

  const fetchDeployments = useCallback(async () => {
    try {
      const { rows, meta } = await sitesApi.deployment();
      setDeployments(new Map(rows.map((r) => [r.siteId, r])));
      const generated = meta ? new Date(meta.generatedAt).getTime() : NaN;
      setDeploymentAt(Number.isFinite(generated) ? generated : Date.now());
      setDeploymentLimits(meta);
      setDeploymentFailed(false);
    } catch {
      setDeployments(new Map());
      setDeploymentLimits(null);
      setStateFilter(null);
      setDeploymentFailed(true);
    }
  }, []);

  const refreshAll = useCallback(() => {
    void fetchSites();
    void fetchDevices();
    void fetchDeployments();
  }, [fetchSites, fetchDevices, fetchDeployments]);

  useEffect(() => {
    refreshAll();
  }, [refreshAll]);

  // The row delete opens the SAME dialog as the site page: it reads what the
  // delete would leave behind (GET /sites/:id/edit-context) and asks one named
  // acknowledgement per thing — a bare confirm sent none, so any site with an
  // allocation, bench history or SLA reports was refused (409) every time.
  const [deleting, setDeleting] = useState<{ id: number; code: string; name: string } | null>(null);

  // The text search first (name, code, address, contact), then the state
  // chip. The export's `search` repeats this exact comparison server-side
  // (`matchesSearch` in siteDeployment.service.ts): change both together.
  const searched = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return [...sites]
      .filter((s) =>
        !needle ||
        [s.name, s.code, s.address, s.contact]
          .filter(Boolean)
          .some((v) => String(v).toLowerCase().includes(needle)),
      )
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [sites, search]);

  const stateCounts = useMemo(() => {
    const counts = Object.fromEntries(SITE_DEPLOYMENT_STATES.map((s) => [s, 0])) as Record<SiteDeploymentState, number>;
    for (const s of searched) {
      const d = deployments.get(s.id);
      if (d) counts[d.state] += 1;
    }
    return counts;
  }, [searched, deployments]);

  const filtered = useMemo(
    () => (stateFilter === null ? searched : searched.filter((s) => deployments.get(s.id)?.state === stateFilter)),
    [searched, deployments, stateFilter],
  );

  // A site deleted (or gone with a workspace switch) leaves the selection.
  useEffect(() => {
    setSelected((prev) => {
      const known = new Set(sites.map((s) => s.id));
      const next = new Set([...prev].filter((id) => known.has(id)));
      return next.size === prev.size ? prev : next;
    });
  }, [sites]);

  // Only the sites the caller may WRITE are selectable: the bulk gestures
  // (access link, WAN rollout) are writes, and a team that only reads a site
  // would get a 403 for the whole batch.
  const filteredIds = useMemo(
    () => filtered.filter((s) => canWriteObject(s)).map((s) => s.id),
    [filtered, canWriteObject],
  );
  const allFilteredSelected = filteredIds.length > 0 && filteredIds.every((id) => selected.has(id));
  const someFilteredSelected = filteredIds.some((id) => selected.has(id));
  const hiddenSelected = useMemo(() => {
    const shown = new Set(filteredIds);
    return [...selected].filter((id) => !shown.has(id)).length;
  }, [selected, filteredIds]);

  const toggleOne = (id: number) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  /** "Every site the current search and filter show" — a whole customer in one gesture. */
  const selectAllFiltered = () =>
    setSelected((prev) => new Set([...prev, ...filteredIds]));
  const toggleAllFiltered = () =>
    setSelected((prev) => {
      if (!allFilteredSelected) return new Set([...prev, ...filteredIds]);
      const next = new Set(prev);
      for (const id of filteredIds) next.delete(id);
      return next;
    });

  const handleBulkUplink = async () => {
    const ids = [...selected];
    if (ids.length === 0) return;
    const question = t('sites.uplink.bulk.confirm', {
      count: ids.length,
      kind: uplinkLabel(bulkChoice),
      defaultValue: 'Declare the access link of {{count}} site(s) as “{{kind}}”?',
    }) + (hiddenSelected > 0
      ? `

${t('sites.uplink.bulk.confirmHidden', {
        count: hiddenSelected,
        defaultValue: 'Including {{count}} selected site(s) not shown by the current search or filter.',
      })}`
      : '');
    if (!window.confirm(question)) return;
    setBulkBusy(true);
    try {
      const r = await sitesApi.bulkUplinkKind(ids, kindOf(bulkChoice));
      toast.success(
        t('sites.uplink.bulk.done', {
          changed: r.changed,
          unchanged: r.unchanged,
          defaultValue: '{{changed}} site(s) declared, {{unchanged}} already so',
        }) +
          (r.backupAlertsClosed > 0
            ? ` · ${t('sites.uplink.bulk.alertsClosed', {
                count: r.backupAlertsClosed,
                defaultValue: '{{count}} 4G backup alert(s) closed',
              })}`
            : ''),
      );
      setSelected(new Set());
      void fetchSites();
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(
        message ??
          t('sites.uplink.bulk.failed', { defaultValue: 'The declaration failed: no site was changed.' }),
      );
    } finally {
      setBulkBusy(false);
    }
  };

  const handleBulkProvider = async () => {
    const ids = [...selected];
    if (ids.length === 0) return;
    const provider = bulkProvider.trim().replace(/\s+/g, ' ');
    if (provider.length > 64) {
      toast.error(t('operatorOutage.site.tooLong', { defaultValue: 'At most 64 characters.' }));
      return;
    }
    const question = (provider === ''
      ? t('operatorOutage.site.bulkConfirmClear', {
          count: ids.length,
          defaultValue: 'Clear the fixed-line provider of {{count}} site(s)? It will be inferred again.',
        })
      : t('operatorOutage.site.bulkConfirm', {
          count: ids.length,
          provider,
          defaultValue: 'Set the fixed-line provider of {{count}} site(s) to “{{provider}}”?',
        })) + (hiddenSelected > 0
      ? `

${t('sites.uplink.bulk.confirmHidden', {
        count: hiddenSelected,
        defaultValue: 'Including {{count}} selected site(s) not shown by the current search or filter.',
      })}`
      : '');
    if (!window.confirm(question)) return;
    setBulkBusy(true);
    try {
      const r = await sitesApi.bulkSetSiteFixedProvider(ids, provider === '' ? null : provider);
      toast.success(
        t('operatorOutage.site.bulkDone', {
          changed: r.changed,
          unchanged: r.unchanged,
          defaultValue: '{{changed}} site(s) changed, {{unchanged}} already so',
        }),
      );
      setSelected(new Set());
      void fetchSites();
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(message ?? t('operatorOutage.site.bulkFailed', { defaultValue: 'The change failed: no site was changed.' }));
    } finally {
      setBulkBusy(false);
    }
  };

  const handleExport = async () => {
    setExporting(true);
    try {
      const { blob, fileName } = await sitesApi.exportXlsx({
        search,
        states: stateFilter ? [stateFilter] : undefined,
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = fileName;
      a.click();
      // Revoked a moment later: some browsers start the download asynchronously.
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch {
      toast.error(t('sites.deployment.exportFailed', { defaultValue: 'L’export Excel a échoué. Réessayez dans un instant.' }));
    } finally {
      setExporting(false);
    }
  };

  const handleCreate = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      await sitesApi.create({
        code: form.code,
        name: form.name,
        address: form.address || null,
        contact: form.contact || null,
        timezone: form.timezone || undefined,
      });
      toast.success(t('sites.created'));
      setForm(emptyForm);
      setShowForm(false);
      void fetchSites();
      void fetchDeployments();
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(message ?? t('sites.failedCreate'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="p-6">
      <div className="mb-5 flex items-start justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold text-text-primary">
            {t('nav.sites')}
            <GodViewMarker />
          </h1>
          <p className="mt-1 text-sm text-text-muted">{t('sites.subtitle', { count: sites.length })}</p>
        </div>
        <div className="flex items-center gap-2">
          <GodViewTenantFilter onChange={() => refreshAll()} />
          <Button variant="secondary" size="sm" onClick={refreshAll}>
            <RotateCw size={14} className={cn('mr-1.5', isLoading && 'animate-spin')} />
            {t('devices.refresh')}
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => void handleExport()}
            loading={exporting}
            title={t('sites.deployment.exportHint', {
              defaultValue: 'Télécharge la liste affichée (recherche et filtre d’état compris) au format Excel',
            })}
          >
            <FileSpreadsheet size={14} className="mr-1.5" />
            {t('sites.deployment.export', { defaultValue: 'Exporter Excel' })}
          </Button>
          <Button variant="secondary" size="sm" onClick={() => setShowTenantHours(true)} title={t('openingHours.tenantHint')}>
            <Clock size={14} className="mr-1.5" />
            {t('openingHours.tenantButton')}
          </Button>
          {canAddSite && (
            <Button variant="secondary" size="sm" onClick={() => setShowImport(true)}>
              <Upload size={14} className="mr-1.5" />
              {t('sites.import.button', { defaultValue: 'Import CSV' })}
            </Button>
          )}
          {isAdmin() && currentTenantId !== null && (
            <Button variant="secondary" size="sm" onClick={() => setShowLanReprise(true)}>
              <Network size={14} className="mr-1.5" />
              {t('allocation.lanReprise.button', { defaultValue: 'Record existing LANs' })}
            </Button>
          )}
          {canAddSite && (
            <Button size="sm" onClick={() => setShowForm((v) => !v)}>
              <Plus size={14} className="mr-1.5" />
              {t('sites.newSite')}
            </Button>
          )}
        </div>
      </div>

      {showImport && canAddSite && (
        <SiteImportModal
          canAllocate={isAdmin()}
          onClose={() => setShowImport(false)}
          onImported={() => { void fetchSites(); void fetchDeployments(); }}
        />
      )}

      {deleting && canWrite && (
        <SiteDeleteDialog
          site={deleting}
          onClose={() => setDeleting(null)}
          onDeleted={() => {
            setDeleting(null);
            void Promise.all([fetchSites(), fetchDevices(), fetchDeployments()]);
          }}
        />
      )}

      {showRename && isAdmin() && selected.size > 0 && (
        <SiteRenameBulkDialog siteIds={[...selected]} onClose={() => setShowRename(false)} />
      )}

      {showHoursBulk && selected.size > 0 && (
        <OpeningHoursBulkDialog
          siteIds={[...selected]}
          onClose={() => setShowHoursBulk(false)}
          onDone={() => { void fetchSites(); }}
        />
      )}
      {showTenantHours && (
        <TenantOpeningHoursDialog
          canEdit={canEditTenantHours}
          onClose={() => setShowTenantHours(false)}
          onSaved={() => { void fetchSites(); }}
        />
      )}

      {showLanReprise && isAdmin() && currentTenantId !== null && (
        <LanRepriseModal
          tenantId={currentTenantId}
          tenantLabel={tenants.find((x) => x.id === currentTenantId)?.name}
          onClose={() => setShowLanReprise(false)}
          onApplied={() => { void fetchDeployments(); }}
        />
      )}

      {showForm && canAddSite && (
        <form onSubmit={handleCreate} className="mb-5 rounded-lg border border-border bg-bg-secondary p-4">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-text-secondary">
            {t('sites.newSite')}
          </h2>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
            <Input
              label={t('sites.fields.code')}
              value={form.code}
              onChange={(e) => setForm({ ...form, code: e.target.value })}
              placeholder="SIEGE"
              required
            />
            <Input
              label={t('sites.fields.name')}
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              required
            />
            <Input
              label={t('sites.fields.timezone')}
              value={form.timezone}
              onChange={(e) => setForm({ ...form, timezone: e.target.value })}
            />
            <Input
              label={t('sites.fields.address')}
              value={form.address}
              onChange={(e) => setForm({ ...form, address: e.target.value })}
              className="md:col-span-2"
            />
            <Input
              label={t('sites.fields.contact')}
              value={form.contact}
              onChange={(e) => setForm({ ...form, contact: e.target.value })}
            />
          </div>
          <p className="mt-3 text-xs text-text-muted">{t('sites.codeHint')}</p>
          <div className="mt-3 flex gap-2">
            <Button type="submit" size="sm" loading={saving}>{t('common.create')}</Button>
            <Button type="button" size="sm" variant="secondary" onClick={() => setShowForm(false)}>
              {t('common.cancel')}
            </Button>
          </div>
        </form>
      )}

      <div className="mb-4 flex items-center gap-2">
        <div className="relative">
          <Search size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t('sites.searchPlaceholder')}
            className="w-64 rounded-md border border-border bg-bg-tertiary py-1.5 pl-8 pr-2.5 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
          />
        </div>
        {canDeclare && filteredIds.length > 0 && !allFilteredSelected && (
          <Button variant="ghost" size="sm" onClick={selectAllFiltered}>
            {t('sites.uplink.bulk.selectAllFiltered', {
              count: filteredIds.length,
              defaultValue: 'Select the {{count}} sites shown',
            })}
          </Button>
        )}
        <span className="ml-auto font-mono text-[11px] text-text-muted">
          {t('devices.showing', { shown: filtered.length, total: sites.length })}
        </span>
      </div>

      {canDeclare && selected.size > 0 && (
        <div className="mb-4 flex flex-wrap items-center gap-2 rounded-lg border border-accent/40 bg-accent/5 px-3 py-2">
          <span className="text-sm font-medium text-text-primary">
            {t('sites.uplink.bulk.selected', { count: selected.size, defaultValue: '{{count}} site(s) selected' })}
          </span>
          {hiddenSelected > 0 && (
            <span className="text-xs text-status-pending">
              {t('sites.uplink.bulk.hiddenSelected', {
                count: hiddenSelected,
                defaultValue: 'including {{count}} hidden by the search or the filter',
              })}
            </span>
          )}
          <span className="ml-2 inline-flex items-center gap-1.5 text-sm text-text-secondary">
            <Antenna size={14} />
            {t('sites.uplink.bulk.button', { defaultValue: 'Access link…' })}
          </span>
          <SiteUplinkSelect
            compact
            value={bulkChoice}
            onChange={setBulkChoice}
            disabled={bulkBusy}
            ariaLabel={t('sites.uplink.label', { defaultValue: 'Access link' })}
          />
          <Button size="sm" onClick={() => void handleBulkUplink()} loading={bulkBusy}>
            {t('sites.uplink.bulk.apply', { defaultValue: 'Apply' })}
          </Button>
          <span className="ml-2 inline-flex items-center gap-1.5 text-sm text-text-secondary">
            {t('operatorOutage.site.bulkButton', { defaultValue: 'Fixed-line provider…' })}
          </span>
          <input
            type="text"
            value={bulkProvider}
            maxLength={64}
            disabled={bulkBusy}
            onChange={(e) => setBulkProvider(e.target.value)}
            placeholder={t('operatorOutage.site.bulkPlaceholder', { defaultValue: 'Orange, SFR… (empty = clear)' })}
            aria-label={t('operatorOutage.site.label', { defaultValue: 'Fixed-line provider' })}
            className="w-44 rounded-md border border-border bg-bg-tertiary px-2 py-1 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
          />
          <Button size="sm" variant="secondary" onClick={() => void handleBulkProvider()} loading={bulkBusy}>
            {t('sites.uplink.bulk.apply', { defaultValue: 'Apply' })}
          </Button>
          {canChangeWan && (
            <Button variant="secondary" size="sm" onClick={openWanLinkRollout} disabled={bulkBusy}>
              <Globe size={14} className="mr-1.5" />
              {t('wanLink.bulk.button')}
            </Button>
          )}
          {isAdmin() && (
            <Button variant="secondary" size="sm" onClick={() => setShowRename(true)} disabled={bulkBusy}>
              <CaseLower size={14} className="mr-1.5" />
              {t('siteRename.bulk.open')}
            </Button>
          )}
          <Button variant="secondary" size="sm" onClick={() => setShowHoursBulk(true)} disabled={bulkBusy}>
            <Clock size={14} className="mr-1.5" />
            {t('openingHours.bulk.button')}
          </Button>
          <Button variant="ghost" size="sm" onClick={() => setSelected(new Set())} disabled={bulkBusy}>
            <X size={14} className="mr-1" />
            {t('sites.uplink.bulk.clear', { defaultValue: 'Clear selection' })}
          </Button>
        </div>
      )}

      <div className="mb-4">
        {deploymentFailed ? (
          <p className="text-xs italic text-text-muted">
            {t('sites.deployment.loadFailed', {
              defaultValue: 'L’état de déploiement des sites n’a pas pu être chargé. Cliquez sur « Actualiser » pour réessayer.',
            })}
          </p>
        ) : (
          <SiteDeploymentChips
            counts={stateCounts}
            total={searched.length}
            selected={stateFilter}
            onSelect={setStateFilter}
          />
        )}
      </div>

      {loadError ? (
        <div className="rounded-lg border border-status-down/40 bg-status-down/5 p-4 text-sm text-status-down">
          {t('sites.loadFailed')} — <span className="font-mono text-xs">{loadError}</span>
        </div>
      ) : isLoading && sites.length === 0 ? (
        <div className="flex justify-center py-16"><LoadingSpinner size="lg" /></div>
      ) : filtered.length === 0 ? (
        <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
          <MapPin size={28} className="mx-auto mb-2 text-text-muted" />
          <p className="text-sm text-text-muted">
            {sites.length === 0 ? t('sites.empty') : t('sites.noMatch')}
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border bg-bg-secondary">
          <table className="w-full min-w-[960px] text-left text-sm">
            <thead>
              <tr className="border-b border-border text-[11px] uppercase tracking-wider text-text-muted">
                {canDeclare && (
                  <th className="w-8 px-3 py-2">
                    <input
                      type="checkbox"
                      checked={allFilteredSelected}
                      ref={(el) => { if (el) el.indeterminate = someFilteredSelected && !allFilteredSelected; }}
                      onChange={toggleAllFiltered}
                      disabled={filteredIds.length === 0}
                      className="h-3.5 w-3.5 cursor-pointer accent-accent disabled:cursor-not-allowed disabled:opacity-40"
                      title={t('sites.uplink.bulk.selectAllFiltered', {
                        count: filteredIds.length,
                        defaultValue: 'Select the {{count}} sites shown',
                      })}
                      aria-label={t('sites.uplink.bulk.selectAllFiltered', {
                        count: filteredIds.length,
                        defaultValue: 'Select the {{count}} sites shown',
                      })}
                    />
                  </th>
                )}
                <th className="px-3 py-2 font-medium">{t('sites.columns.code')}</th>
                <th className="px-3 py-2 font-medium">{t('sites.columns.name')}</th>
                <GodViewTenantHeader />
                <th className="px-3 py-2 font-medium">
                  {t('sites.columns.deployment', { defaultValue: 'État' })}
                </th>
                <th className="px-3 py-2 font-medium">{t('sites.columns.presence')}</th>
                <th className="px-3 py-2 font-medium" title={t('openingHours.columnHint')}>{t('openingHours.column')}</th>
                <th className="px-3 py-2 font-medium">{t('sites.columns.devices')}</th>
                {canReadSim && (
                  <th className="px-3 py-2 font-medium">{t('sites.columns.sim', { defaultValue: 'SIM' })}</th>
                )}
                <th className="px-3 py-2 font-medium">{t('sites.columns.maintenance')}</th>
                <th className="px-3 py-2 font-medium">{t('sites.columns.timezone')}</th>
                {canWrite && <th className="w-10 px-3 py-2" />}
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.map((site) => {
                const rollup = siteRollup(site.id);
                const style = verdictStyle(rollup.worstVerdict);
                const known = rollup.total - rollup.unknown;
                return (
                  <tr
                    key={site.id}
                    className={cn('transition-colors hover:bg-bg-hover', selected.has(site.id) && 'bg-accent/5')}
                  >
                    {canDeclare && (
                      <td className="px-3 py-2">
                        {canWriteObject(site) && (
                        <input
                          type="checkbox"
                          checked={selected.has(site.id)}
                          onChange={() => toggleOne(site.id)}
                          className="h-3.5 w-3.5 cursor-pointer accent-accent"
                          aria-label={t('sites.uplink.bulk.selectRow', {
                            code: site.code,
                            defaultValue: 'Select site {{code}}',
                          })}
                        />
                        )}
                      </td>
                    )}
                    <td className="px-3 py-2 font-mono text-[12px] text-text-secondary">{site.code}</td>
                    <td className="px-3 py-2">
                      <Link
                        to={`/sites/${site.id}`}
                        className="flex items-center gap-2 font-medium text-text-primary hover:text-accent"
                      >
                        <MapPin size={13} className="shrink-0 text-text-muted" />
                        {anonHostname(site.name)}
                        <SiteUplinkBadge kind={site.uplinkKind} />
                      </Link>
                      {site.address && <div className="text-[11px] text-text-muted">{site.address}</div>}
                      {site.fixedProvider && (
                        <div
                          className="text-[11px] text-text-muted"
                          title={t('operatorOutage.site.label', { defaultValue: 'Fixed-line provider' })}
                        >
                          {t('operatorOutage.site.listLine', { provider: site.fixedProvider, defaultValue: 'Fixed line: {{provider}}' })}
                        </div>
                      )}
                    </td>
                    <GodViewTenantCell name={site.tenantName} tenantId={site.tenantId} />
                    <td className="px-3 py-2">
                      <SiteDeploymentBadge
                        row={deployments.get(site.id)}
                        limits={deploymentLimits}
                        nowMs={deploymentAt}
                      />
                    </td>
                    <td className="px-3 py-2">
                      <OpenStateBadge state={(site as typeof site & SiteOpeningFields).openState} timezone={site.timezone} dash />
                    </td>
                    <td className="px-3 py-2">
                      {rollup.total === 0 ? (
                        <span className="text-xs italic text-text-muted">{t('sites.noDevice')}</span>
                      ) : (
                        <span className="inline-flex items-center gap-2">
                          <span
                            className={cn(
                              'inline-block h-2 w-2 shrink-0 rounded-full',
                              known === 0 ? 'border-2 border-text-muted/60 bg-transparent' : style.dot,
                            )}
                          />
                          <span className="font-mono text-[12px] text-text-secondary">
                            {rollup.up}/{rollup.total}
                          </span>
                          {rollup.unknown > 0 && (
                            <span className="text-[10px] italic text-text-muted">
                              {t('sites.unknownCount', { count: rollup.unknown })}
                            </span>
                          )}
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2 font-mono text-[12px] text-text-secondary">
                      {site.deviceCount ?? devices.filter((d) => d.siteId === site.id).length}
                    </td>
                    {canReadSim && (
                      <td className="px-3 py-2 font-mono text-[12px]">
                        {site.simCount === undefined ? (
                          <span className="text-text-muted">—</span>
                        ) : site.simCount === 0 ? (
                          <span className="text-text-muted">0</span>
                        ) : (
                          <Link
                            to={`/mobile/lines?siteId=${site.id}${site.tenantName !== undefined ? `&tenantId=${site.tenantId}` : ''}`}
                            className="text-accent hover:underline"
                            title={t('sites.simCountTitle', {
                              count: site.simCount,
                              defaultValue: '{{count}} SIM line(s) on this site — open them in 4G / SIM',
                            })}
                          >
                            {site.simCount}
                          </Link>
                        )}
                      </td>
                    )}
                    <td className="px-3 py-2 text-[12px] text-text-secondary">
                      {formatMaintenanceWindow(site.maintenanceWindow, i18n.language)
                        ?? <span className="italic text-text-muted">{t('sites.noMaintenanceWindow')}</span>}
                    </td>
                    <td className="px-3 py-2 font-mono text-[11px] text-text-muted">{site.timezone}</td>
                    {canWrite && (
                      <td className="px-3 py-2 text-right">
                        {canWriteObject(site) ? (
                          <button
                            type="button"
                            onClick={() => setDeleting({ id: site.id, code: site.code, name: site.name })}
                            className="rounded p-1 text-text-muted hover:bg-bg-hover hover:text-status-down"
                            title={t('sites.delete', { defaultValue: 'Delete this site' })}
                            aria-label={t('sites.delete', { defaultValue: 'Delete this site' })}
                          >
                            <Trash2 size={14} />
                          </button>
                        ) : (
                          <span
                            className="inline-flex p-1 text-text-muted"
                            title={t('teamScope.readOnlyHint')}
                            aria-label={t('teamScope.readOnlyHint')}
                          >
                            <Eye size={14} />
                          </span>
                        )}
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
