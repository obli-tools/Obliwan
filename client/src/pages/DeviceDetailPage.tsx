import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import {
  ArrowLeft,
  Activity,
  Archive,
  DownloadCloud,
  FileCode,
  GitCompareArrows,
  Lock,
  PlayCircle,
  Plug,
  Radio,
  RadioTower,
  Router,
  ScrollText,
  Settings as SettingsIcon,
  ShieldAlert,
  Smartphone,
  Trash2,
  KeyRound,
  Wand2,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import {
  CAPABILITIES,
  TRANSPORT_KINDS,
  DEVICE_STATUSES,
  isMasterTenant,
  type TransportKind,
  type DeviceStatus,
} from '@obliwan/shared';
import { devicesApi } from '@/api/devices.api';
import { useDeviceStore } from '@/store/deviceStore';
import { useSiteStore } from '@/store/siteStore';
import { useAuthStore } from '@/store/authStore';
import { useTenantStore } from '@/store/tenantStore';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { cn } from '@/utils/cn';
import { TRANSPORT_DEFAULT_PORT } from '@/utils/verdict';
import { DeviceInterfacesTab } from '@/components/telemetry/DeviceInterfacesTab';
import { DeviceConfigTab } from '@/components/config/DeviceConfigTab';
import { DeviceDriftTab } from '@/components/config/DeviceDriftTab';
import { DeviceChangesTab } from '@/components/change/DeviceChangesTab';
import { DeviceAcsTab } from '@/components/acs/DeviceAcsTab';
import { DeviceBackupsTab } from '@/components/config/DeviceBackupsTab';
import { DeviceLogsTab } from '@/components/telemetry/DeviceLogsTab';
import { DeviceSnmpCard } from '@/components/telemetry/DeviceSnmpCard';
import { TlsCertificateChangedNotice } from '@/components/fleet/TlsCertificateChangedNotice';
import { RevealSecretButton } from '@/components/secrets/RevealSecretButton';
import { DeviceHeader } from '@/components/device/DeviceHeader';
import { DeviceOverview } from '@/components/device/DeviceOverview';
import { DeviceSimTab } from '@/components/device/DeviceSimTab';
import { DeviceTestResults } from '@/components/device/DeviceTestResults';
import { LINK_BUTTON } from '@/components/device/StatusSection';
import { useCollectNow } from '@/components/device/useCollectNow';
import { useDeviceSignals } from '@/components/device/useDeviceSignals';
import {
  isDeviceTabId,
  type DeviceTabId,
  type PageTarget,
  type SectionFocus,
} from '@/components/device/devicePage';
import { secretsApi } from '@/api/secrets.api';
import type {
  DeviceDetail, DeviceDiagnosis, DeviceTransport, TransportTestResult,
} from '@/types/fleet';
import toast from 'react-hot-toast';

// ── Tabs ────────────────────────────────────────────────────────────────────
//
// The page design lists nine tabs; « 4G / SIM » is the tenth (the mobile fleet on the router's own
// page). A tab with a `milestone` is rendered DISABLED with the milestone that
// unlocks it — never as a tab that opens on an empty pane, which reads as a
// broken page rather than as an unfinished one.
//
// The tab is in the URL (`?tab=sim`): a status chip, a bookmark or an alert
// can land on it, and the browser's back button walks between tabs.

interface TabDef {
  id: DeviceTabId;
  labelKey: string;
  icon: React.ReactNode;
  /** Absent = the tab works today. */
  milestone?: string;
  /** Absent = shown for every device. */
  shownFor?: (device: DeviceDetail) => boolean;
}

const TABS: TabDef[] = [
  { id: 'overview',   labelKey: 'devices.tabs.overview',   icon: <Router size={14} /> },
  // A concentrator carries no customer SIM: its 4G is not a thing to manage.
  { id: 'sim',        labelKey: 'devices.sim.tab',         icon: <Smartphone size={14} />, shownFor: (d) => d.role !== 'concentrator' },
  { id: 'interfaces', labelKey: 'devices.tabs.interfaces', icon: <Activity size={14} /> },
  { id: 'config',     labelKey: 'devices.tabs.config',     icon: <FileCode size={14} /> },
  { id: 'drift',      labelKey: 'devices.tabs.drift',      icon: <GitCompareArrows size={14} /> },
  { id: 'changes',    labelKey: 'devices.tabs.changes',    icon: <PlayCircle size={14} /> },
  { id: 'backups',    labelKey: 'devices.tabs.backups',    icon: <Archive size={14} /> },
  // TR-069. The tab is enabled for EVERY brand on purpose: on a
  // MikroTik or a SonicWall its content is the sentence "this platform ships no
  // CWMP client, use <transport> instead", and that sentence is exactly
  // what the operator came looking for. A tab greyed out on three quarters of
  // the fleet would leave him to guess it.
  { id: 'acs',        labelKey: 'devices.tabs.acs',        icon: <RadioTower size={14} /> },
  { id: 'logs',       labelKey: 'devices.tabs.logs',       icon: <ScrollText size={14} /> },
  { id: 'settings',   labelKey: 'devices.tabs.settings',   icon: <SettingsIcon size={14} /> },
];

// ── Small presentational helpers ────────────────────────────────────────────

/** Shown in place of a tab the session may not read. The no-secrets rule keeps CONFIG_READ
 *  distinct from DEVICE_READ, so this is a normal state, not an error. */
function CapabilityNotice() {
  const { t } = useTranslation();
  return (
    <div className="rounded-lg border border-border bg-bg-secondary py-16 text-center">
      <ShieldAlert size={26} className="mx-auto mb-2 text-text-muted" />
      <p className="text-sm text-text-muted">{t('config.noCapability')}</p>
    </div>
  );
}

function Card({ title, children, className }: { title: string; children: React.ReactNode; className?: string }) {
  return (
    <section className={cn('rounded-lg border border-border bg-bg-secondary p-4', className)}>
      <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-text-secondary">{title}</h2>
      {children}
    </section>
  );
}

// ── Page ────────────────────────────────────────────────────────────────────

export function DeviceDetailPage() {
  const { id } = useParams<{ id: string }>();
  const deviceId = Number(id);
  const navigate = useNavigate();
  const { t } = useTranslation();
  const { deviceAccess, hasCapability, isAdmin } = useAuthStore();
  const { sites, fetchSites } = useSiteStore();
  const livePresence = useDeviceStore((s) => s.presence[deviceId]);
  const removeFromStore = useDeviceStore((s) => s.removeDevice);

  const [searchParams, setSearchParams] = useSearchParams();
  const [device, setDevice] = useState<DeviceDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);

  /** `null` = the server does not expose the channel list yet. */
  const [transports, setTransports] = useState<DeviceTransport[] | null>(null);
  const [transportsUnavailable, setTransportsUnavailable] = useState(false);
  /** Bumped on every (re)load of the channel list: a password revealed before
   *  a save must not stay on screen as the current one after it (RevealSecretButton). */
  const [transportsLoad, setTransportsLoad] = useState(0);
  const [testResults, setTestResults] = useState<TransportTestResult[] | null>(null);
  const [testing, setTesting] = useState(false);
  const [diagnosis, setDiagnosis] = useState<DeviceDiagnosis | null>(null);
  const [diagnosing, setDiagnosing] = useState(false);
  /** A chip click aimed at an overview section. */
  const [focus, setFocus] = useState<SectionFocus | null>(null);
  /** Bumped by the header's « Collecter maintenant »: the Configuration tab
   *  re-reads its snapshot list. */
  const [configNonce, setConfigNonce] = useState(0);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const detail = await devicesApi.getById(deviceId);
      setDevice(detail);
      setTransportsLoad((n) => n + 1);
      if (detail.transports) {
        setTransports(detail.transports);
      } else {
        const list = await devicesApi.transports(deviceId);
        setTransports(list);
        setTransportsUnavailable(list === null);
      }
    } catch (err) {
      const status = (err as { response?: { status?: number } }).response?.status;
      if (status === 404) setNotFound(true);
      else toast.error(t('devices.loadFailed'));
    } finally {
      setLoading(false);
    }
  }, [deviceId, t]);

  useEffect(() => {
    if (!Number.isFinite(deviceId)) { setNotFound(true); setLoading(false); return; }
    void load();
    void fetchSites();
  }, [deviceId, load, fetchSites]);

  const presence = livePresence ?? device?.presence ?? null;
  // The caller's level on THIS router: the server's `access` (migration 087,
  // from the caller's teams), else the permission map for a payload without it.
  const permission = device ? deviceAccess(device) : null;
  const canWrite = permission === 'rw';

  const canReadConfig = isAdmin() || hasCapability(CAPABILITIES.CONFIG_READ);
  // The CONFIG_READ argument applied once more: seeing a router and being allowed to
  // watch (or start) a write against it are two different privileges.
  const canSeeChanges = isAdmin() || hasCapability(CAPABILITIES.CHANGE_APPLY);
  // Asking the platform to DIAL the box is CONFIG_WRITE, not CONFIG_READ.
  const canCollect = isAdmin() || hasCapability(CAPABILITIES.CONFIG_WRITE);
  // The planner's own route guard: compiling a plan touches no equipment.
  const canPlan = isAdmin() || hasCapability(CAPABILITIES.PLAN_CREATE);

  const signals = useDeviceSignals(device?.id ?? null, {
    simReadable: device !== null && device.role !== 'concentrator'
      && (isAdmin() || hasCapability(CAPABILITIES.SIM_READ)),
    configReadable: canReadConfig,
  });
  const onCollected = useCallback(() => setConfigNonce((n) => n + 1), []);
  const { collect, collecting } = useCollectNow(deviceId, onCollected);

  const visibleTabs = device ? TABS.filter((def) => !def.shownFor || def.shownFor(device)) : TABS;
  const requested = searchParams.get('tab');
  const tab: DeviceTabId = isDeviceTabId(requested) && visibleTabs.some((def) => def.id === requested)
    ? requested
    : 'overview';

  const setTab = useCallback((next: DeviceTabId) => {
    setSearchParams((prev) => {
      const params = new URLSearchParams(prev);
      if (next === 'overview') params.delete('tab');
      else params.set('tab', next);
      return params;
    });
  }, [setSearchParams]);

  /** A status chip: open its tab, and on the overview unfold its section. */
  const goTo = useCallback((target: PageTarget) => {
    setTab(target.tab);
    const section = target.section;
    if (section) setFocus((prev) => ({ section, nonce: (prev?.nonce ?? 0) + 1 }));
  }, [setTab]);

  if (loading && !device) {
    return <div className="flex h-full items-center justify-center"><LoadingSpinner size="lg" /></div>;
  }

  if (notFound || !device) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-4">
        <p className="text-text-muted">{t('devices.notFound')}</p>
        <Link to="/devices"><Button variant="secondary">{t('devices.backToFleet')}</Button></Link>
      </div>
    );
  }

  const siteName = device.siteId !== null
    ? device.siteName ?? sites.find((s) => s.id === device.siteId)?.name ?? `#${device.siteId}`
    : null;

  /**
   * Deliberately NOT automatic on a failed test. It opens half a dozen sockets
   * and may run a traceroute; charging that to every routine check would make
   * the cheap question expensive. The operator asks the second question when
   * the first one disappoints them.
   */
  const handleDiagnose = async () => {
    setDiagnosing(true);
    setDiagnosis(null);
    try {
      setDiagnosis(await devicesApi.diagnose(device.id));
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(message ?? t('devices.diagnoseFailed'));
    } finally {
      setDiagnosing(false);
    }
  };

  const handleTestConnection = async () => {
    setTesting(true);
    setTestResults(null);
    setDiagnosis(null);
    try {
      const { results, learned, learnError } = await devicesApi.testConnection(device.id);
      setTestResults(results);

      // ── The page must stop contradicting itself ─────────────────────────────
      // "Reachable, 80 ms" next to a transport health card still reading
      // "circuit open — timed out" is one screen telling an operator two
      // opposite things, and the stale half is the one that looks official.
      // The health row and the identity columns both changed server-side
      // during the test; reload so the page shows the device as it is NOW.
      if (results.some((r) => r.ok)) void load();

      // ── The channel answered and the identity read did not ─────────────────
      // Without this the operator sees "reachable, 80 ms" and an identity card
      // still full of em-dashes, with nothing anywhere saying why — which is
      // indistinguishable from the feature not existing. The server has sent
      // this field since the read was wired; it was simply never read here.
      // Long duration on purpose: it names a server-side cause the operator
      // will want to copy.
      if (learnError) {
        toast.error(t('devices.factsReadFailed', { reason: learnError }), { duration: 12_000 });
      }
      if (learned && Object.keys(learned.filled).length > 0) {
        toast.success(t('devices.factsLearned', { count: Object.keys(learned.filled).length }));
      }
      if (learned && learned.conflicts.length > 0) {
        // Deliberately an error, and deliberately not auto-applied. See
        // `learnDeviceFacts`: this is the event the binding check exists for.
        toast.error(
          t('devices.factsConflict', {
            // Both values, so the operator can tell a typo from another box
            // without leaving the page — and correct the record in Settings.
            fields: learned.conflicts
              .map((c: { field: string; stored: string; observed: string }) => `${c.field} (« ${c.stored} » ≠ « ${c.observed} »)`)
              .join(', '),
          }),
          { duration: 10_000 },
        );
      }
      if (results.length === 0) {
        toast(
          !transports || transports.length === 0
            ? t('devices.testNoChannel')
            : t('devices.testAllChannelsDisabled'),
        );
      }
      else if (results.every((r) => r.ok)) toast.success(t('devices.testAllOk'));
      else toast.error(t('devices.testSomeFailed'));
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(message ?? t('devices.testFailed'));
    } finally {
      setTesting(false);
    }
  };

  const handleDelete = async () => {
    if (!confirm(t('devices.confirmDelete', { name: device.name }))) return;
    try {
      await devicesApi.remove(device.id);
      removeFromStore(device.id);
      toast.success(t('devices.deleted'));
      navigate('/devices');
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(message ?? t('devices.failedDelete'));
    }
  };

  return (
    <div className="p-4 sm:p-6">
      <Link to="/devices" className="mb-4 inline-flex items-center gap-1 text-sm text-text-secondary hover:text-text-primary">
        <ArrowLeft size={14} />
        {t('devices.backToFleet')}
      </Link>

      <DeviceHeader
        device={device}
        presence={presence}
        siteName={siteName}
        readOnly={permission === 'ro'}
        sources={signals.sources}
        onSelect={goTo}
        actions={(
          <>
            <Button
              variant="secondary"
              size="sm"
              onClick={handleTestConnection}
              loading={testing}
              disabled={!canWrite}
              title={canWrite ? undefined : t('teamScope.readOnlyHint')}
            >
              <Plug size={14} className="mr-1.5" />
              {t('devices.testConnection')}
            </Button>
            {canCollect && (
              <Button
                variant="secondary"
                size="sm"
                onClick={() => void collect()}
                disabled={collecting || !canWrite}
                title={canWrite ? t('config.collectHint') : t('teamScope.readOnlyHint')}
              >
                <DownloadCloud size={14} className={cn('mr-1.5', collecting && 'animate-pulse')} />
                {collecting ? t('config.collecting') : t('config.collectNow')}
              </Button>
            )}
            {canPlan && (
              <Link to={`/plan/${device.id}`} className={LINK_BUTTON}>
                <Wand2 size={14} className="mr-1.5" />
                {t('devices.page.actions.plan')}
              </Link>
            )}
            {canWrite && (
              <Button variant="ghost" size="sm" onClick={handleDelete} className="text-status-down hover:text-status-down">
                <Trash2 size={14} className="mr-1.5" />
                {t('common.delete')}
              </Button>
            )}
          </>
        )}
      />

      {/* Tabs */}
      <div className="mb-5 flex gap-1 overflow-x-auto border-b border-border">
        {visibleTabs.map((def) => {
          if (def.milestone) {
            return (
              <div
                key={def.id}
                aria-disabled="true"
                title={t('devices.tabLocked', { milestone: def.milestone })}
                className="flex cursor-not-allowed select-none items-center gap-1.5 whitespace-nowrap border-b-2 border-transparent px-3 py-2 text-[13px] text-text-muted opacity-40"
              >
                {def.icon}
                {t(def.labelKey)}
                <Lock size={10} />
                <span className="font-mono text-[10px] tracking-wider">{def.milestone}</span>
              </div>
            );
          }
          return (
            <button
              key={def.id}
              onClick={() => setTab(def.id)}
              className={cn(
                'flex items-center gap-1.5 whitespace-nowrap border-b-2 px-3 py-2 text-[13px] transition-colors',
                tab === def.id
                  ? 'border-accent text-text-primary'
                  : 'border-transparent text-text-secondary hover:text-text-primary',
              )}
            >
              {def.icon}
              {t(def.labelKey)}
            </button>
          );
        })}
      </div>

      {/* Test-connection results: the answer to a header button, on every tab. */}
      {testResults && (
        <DeviceTestResults
          results={testResults}
          hasChannels={!!transports && transports.length > 0}
          canDiagnose={canWrite}
          diagnosing={diagnosing}
          diagnosis={diagnosis}
          onDiagnose={() => void handleDiagnose()}
          onDismiss={() => { setTestResults(null); setDiagnosis(null); }}
        />
      )}

      {/* ── Overview ──
          Kept MOUNTED (hidden) while another tab is shown: its cards are the
          sources of the header's status chips (`useDeviceSignals`), and a
          chip must not go blank because the operator opened the Logs tab.
          Keyed by device: a router's sections must not open or close on the
          strength of the previous router's state. */}
      <div hidden={tab !== 'overview'}>
        <DeviceOverview
          key={device.id}
          device={device}
          presence={presence}
          siteName={siteName}
          canWrite={canWrite}
          sources={signals.sources}
          report={signals.report}
          focus={focus}
          onHealthChecked={(view) => {
            setDevice((d) => (d ? { ...d, healthCheck: view } : d));
            void load();
            // The permanent check re-reads the LTE modems: the SIM view (and
            // the « ICCID non lu » it may have explained) follows it.
            signals.reloadSim();
          }}
          onReload={() => void load()}
          onOpenTab={setTab}
        />
      </div>

      {/* ── 4G / SIM ── */}
      {tab === 'sim' && (
        <DeviceSimTab
          key={device.id}
          device={device}
          sim={signals.sources.sim}
          uplink={signals.sources.uplink}
          onReloadSim={signals.reloadSim}
        />
      )}

      {/* ── Interfaces ── */}
      {tab === 'interfaces' && <DeviceInterfacesTab deviceId={device.id} />}

      {/* ── Configuration + Dérive ──
          Both are behind CONFIG_READ, which is kept distinct from
          DEVICE_READ: a user who may see that this router exists is not
          thereby allowed to read its configuration. The tab is hidden rather
          than shown-and-empty, because an empty pane reads as "this device has
          no configuration", which is a statement we would be inventing. */}
      {tab === 'config' && (
        canReadConfig
          ? <DeviceConfigTab key={configNonce} deviceId={device.id} deviceName={device.name} />
          : <CapabilityNotice />
      )}

      {tab === 'drift' && (
        canReadConfig ? <DeviceDriftTab deviceId={device.id} /> : <CapabilityNotice />
      )}

      {/* Changements. Behind CHANGE_APPLY rather than DEVICE_READ: this
          tab is where a change is started from, and the queue is the only path
          along which this product writes to an equipment. The
          tab shows the safety net BEFORE it shows the link to the
          planner. */}
      {tab === 'changes' && (
        canSeeChanges
          ? <DeviceChangesTab deviceId={device.id} deviceName={device.name} />
          : <CapabilityNotice />
      )}

      {/* ── TR-069 ──
          No capability gate at the tab: the coverage answer ("MikroTik ships no
          CWMP client") is architectural, not privileged, and `DeviceAcsTab`
          checks ACS_ADMIN itself before it fetches anything. */}
      {tab === 'acs' && (
        <DeviceAcsTab deviceId={device.id} brand={device.brand} family={device.family} />
      )}

      {/* ── Backups ──
          CONFIG_READ, not DEVICE_READ: knowing a device exists and reading its
          configuration history are different privileges, and the capability
          vocabulary keeps them apart precisely so config can be withheld. */}
      {tab === 'backups' && (
        hasCapability(CAPABILITIES.CONFIG_READ)
          ? <DeviceBackupsTab deviceId={device.id} />
          : <CapabilityNotice />
      )}

      {/* ── Logs ── */}
      {tab === 'logs' && (
        hasCapability(CAPABILITIES.SNMP_READ)
          ? <DeviceLogsTab deviceId={device.id} />
          : <CapabilityNotice />
      )}

      {/* ── Settings ──
          The LTE APN moved to « 4G / SIM » and the template compliance to the
          overview's « État »: each sits beside the facts it acts on. */}
      {tab === 'settings' && (
        <SettingsTab
          device={device}
          canWrite={canWrite}
          transports={transports}
          transportsUnavailable={transportsUnavailable}
          transportsLoad={transportsLoad}
          onChanged={load}
        />
      )}
    </div>
  );
}

// ── Settings tab ────────────────────────────────────────────────────────────

interface SettingsTabProps {
  device: DeviceDetail;
  canWrite: boolean;
  transports: DeviceTransport[] | null;
  transportsUnavailable: boolean;
  /** Changes on every reload of `transports` (e.g. after a save). */
  transportsLoad: number;
  onChanged: () => Promise<void>;
}

interface TransportForm {
  transport: TransportKind;
  host: string;
  port: string;
  username: string;
  secret: string;
  useTls: boolean;
}

function SettingsTab({ device, canWrite, transports, transportsUnavailable, transportsLoad, onChanged }: SettingsTabProps) {
  const { t } = useTranslation();
  // The site picker lists the DEVICE's tenant only. In the god view the shared
  // store holds every tenant's sites (other pages read it, so it is not
  // refetched with a filter), and a router was offered other tenants' sites.
  // Outside the god view every row is the session's tenant: nothing changes.
  const sites = useSiteStore((s) => s.sites).filter((s) => s.tenantId === device.tenantId);
  // Only decides whether the reveal row is drawn at all; each RevealSecretButton
  // checks the same rule itself (SECRET_READ, and a platform admin in the
  // master tenant), and the server decides.
  const masterTenant = useTenantStore((s) => isMasterTenant(s.currentTenantId));
  const canReveal = useAuthStore((s) => (masterTenant ? s.isAdmin() : s.hasCapability(CAPABILITIES.SECRET_READ)));

  const [name, setName] = useState(device.name);
  const [status, setStatus] = useState<DeviceStatus>(device.status);
  const [siteId, setSiteId] = useState<string>(device.siteId === null ? '' : String(device.siteId));
  const [isManaged, setIsManaged] = useState(device.isManaged);
  const [notes, setNotes] = useState(device.notes ?? '');
  // Identity, editable HERE and nowhere else in the app. See the form below.
  const [model, setModel] = useState(device.model ?? '');
  const [osVersion, setOsVersion] = useState(device.osVersion ?? '');
  const [serial, setSerial] = useState(device.serial ?? '');
  const [systemIdentity, setSystemIdentity] = useState(device.systemIdentity ?? '');
  const [saving, setSaving] = useState(false);

  const [showTransportForm, setShowTransportForm] = useState(false);
  const [tf, setTf] = useState<TransportForm>({
    transport: 'ssh', host: '', port: '', username: '', secret: '', useTls: false,
  });
  const [addingTransport, setAddingTransport] = useState(false);

  const save = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      await devicesApi.update(device.id, {
        name,
        status,
        siteId: siteId ? Number(siteId) : null,
        isManaged,
        notes: notes || null,
        // Trimmed to null, never stored as an empty string. A blank column is
        // what `compareIdentity` scores `unrecorded`; an empty STRING would
        // score `match` against a box that answered nothing, which is the one
        // outcome the identity rule exists to prevent — an identity check that passes because
        // both sides are empty.
        model: model.trim() || null,
        osVersion: osVersion.trim() || null,
        serial: serial.trim() || null,
        systemIdentity: systemIdentity.trim() || null,
      });
      toast.success(t('devices.updated'));
      await onChanged();
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(message ?? t('devices.failedUpdate'));
    } finally {
      setSaving(false);
    }
  };

  const addTransport = async (e: FormEvent) => {
    e.preventDefault();
    setAddingTransport(true);
    try {
      await devicesApi.upsertTransport(device.id, {
        transport: tf.transport,
        host: tf.host || null,
        port: tf.port ? Number(tf.port) : null,
        username: tf.username || null,
        secret: tf.secret || null,
        useTls: tf.useTls,
      });
      toast.success(t('devices.transportAdded'));
      // Wipe the secret from component state the moment it leaves the browser.
      setTf({ transport: 'ssh', host: '', port: '', username: '', secret: '', useTls: false });
      setShowTransportForm(false);
      await onChanged();
    } catch (err) {
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(message ?? t('devices.transportFailed'));
    } finally {
      setAddingTransport(false);
    }
  };

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <Card title={t('devices.sections.general')}>
        {!canWrite && (
          <p className="mb-3 rounded-md border border-border bg-bg-tertiary px-3 py-2 text-xs text-text-muted">
            {t('devices.readOnlyHint')}
          </p>
        )}
        <form onSubmit={save} className="space-y-3">
          <Input
            label={t('devices.fields.name')}
            value={name}
            onChange={(e) => setName(e.target.value)}
            disabled={!canWrite}
            required
          />
          <div className="space-y-1">
            <label className="block text-sm font-medium text-text-secondary">{t('devices.fields.status')}</label>
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value as DeviceStatus)}
              disabled={!canWrite}
              className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent disabled:opacity-50"
            >
              {DEVICE_STATUSES.map((s) => (
                <option key={s} value={s}>{t(`fleet.status.${s}`)}</option>
              ))}
            </select>
          </div>
          <div className="space-y-1">
            <label className="block text-sm font-medium text-text-secondary">{t('devices.fields.site')}</label>
            <select
              value={siteId}
              onChange={(e) => setSiteId(e.target.value)}
              disabled={!canWrite}
              className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent disabled:opacity-50"
            >
              <option value="">{t('devices.noSite')}</option>
              {sites.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
            </select>
          </div>
          <label className="flex items-center gap-2 text-sm text-text-primary">
            <input
              type="checkbox"
              checked={isManaged}
              disabled={!canWrite}
              onChange={(e) => setIsManaged(e.target.checked)}
              className="h-4 w-4 rounded border-border bg-bg-tertiary accent-accent"
            />
            {t('devices.fields.managed')}
          </label>
          {/* ── Identity, and the only place in the app that can record it ────
              The identity rule makes identity the triple ppp_username + system_identity +
              serial, and `assertTargetBinding` refuses every write and every
              collection when NONE of them corroborates ("the device is
              unproven, fail closed"). The probe normally fills them — but when
              it cannot, there was no screen anywhere that could, so a device
              whose read fails was permanently unusable with no recourse. That
              is motif 12: a feature no screen can start is not a feature.

              Typing one is a CLAIM, exactly like typing it on the enrolment
              form. The probe still overwrites nothing (`learnDeviceFacts` fills
              blanks only) and a box answering something else still trips the identity check. */}
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <Input
              label={t('devices.fields.model')}
              value={model}
              onChange={(e) => setModel(e.target.value)}
              disabled={!canWrite}
              placeholder={t('devices.identityPlaceholder')}
            />
            <Input
              label={t('devices.fields.osVersion')}
              value={osVersion}
              onChange={(e) => setOsVersion(e.target.value)}
              disabled={!canWrite}
              placeholder={t('devices.identityPlaceholder')}
            />
            <Input
              label={t('devices.fields.serial')}
              value={serial}
              onChange={(e) => setSerial(e.target.value)}
              disabled={!canWrite}
              placeholder={t('devices.identityPlaceholder')}
            />
            <Input
              label={t('devices.fields.systemIdentity')}
              value={systemIdentity}
              onChange={(e) => setSystemIdentity(e.target.value)}
              disabled={!canWrite}
              placeholder={t('devices.identityPlaceholder')}
            />
          </div>
          <p className="-mt-1 text-xs text-text-muted">{t('devices.identityHint')}</p>

          <div className="space-y-1">
            <label className="block text-sm font-medium text-text-secondary">{t('devices.fields.notes')}</label>
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              disabled={!canWrite}
              rows={3}
              className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent disabled:opacity-50"
            />
          </div>
          {canWrite && (
            <Button type="submit" size="sm" loading={saving}>{t('common.save')}</Button>
          )}
        </form>
      </Card>

      {/* Supervision for THIS device — and where the answer comes from when it
          has not been decided here. Placed above the channels panel on purpose:
          it is the question an operator arrives with, and the panel below is
          the one that used to answer it wrongly. */}
      <DeviceSnmpCard deviceId={device.id} tenantId={device.tenantId} canWrite={canWrite} />

      <Card title={t('devices.sections.transports')}>
        <div className="mb-3 flex items-start gap-2 rounded-md border border-accent/20 bg-accent/5 p-3">
          <KeyRound size={14} className="mt-0.5 shrink-0 text-accent" />
          <p className="text-xs text-text-secondary">
            {t('devices.vaultHintReveal', {
              defaultValue:
                'Credentials are held by the platform vault and are never sent back to this screen on their own. '
                + 'An account allowed to reveal secrets can display one for 30 seconds with the eye next to it; '
                + 'every reveal is recorded in the audit log.',
            })}
          </p>
        </div>

        {/* ── A TRAP THIS PANEL SETS, SAID OUT LOUD ──────────────────────────
            "Add a channel" offers `snmp` like any other transport, and an
            operator who wants supervision will reasonably pick it, type a
            community, save — and nothing will ever be polled. Interface
            polling reads `snmp_targets` + `snmp_credentials`; this panel writes
            `device_transports`. Two credential stores, one purpose each, and
            only one of them starts a graph.

            The channel here is not useless — the driver uses it to identify a
            box that has no API — but it is not supervision, and the screen must
            not let that be discovered by waiting for a graph that never comes. */}
        <div className="mb-3 flex items-start gap-2 rounded-md border border-border bg-bg-tertiary p-3">
          <Radio size={14} className="mt-0.5 shrink-0 text-text-muted" />
          <p className="text-xs text-text-muted">
            {t('devices.snmpChannelHint')}{' '}
            <Link to="/settings" className="text-accent hover:underline">
              {t('nav.settings')}
            </Link>
          </p>
        </div>

        {transportsUnavailable ? (
          <p className="rounded-md border border-dashed border-border px-3 py-4 text-center text-xs text-text-muted">
            {t('devices.transportsUnavailable')}
          </p>
        ) : !transports || transports.length === 0 ? (
          <p className="rounded-md border border-dashed border-border px-3 py-4 text-center text-xs text-text-muted">
            {t('devices.noTransport')}
          </p>
        ) : (
          <ul className="divide-y divide-border rounded-md border border-border">
            {transports.map((tr) => (
              <li key={tr.id} className="px-3 py-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-[12px] text-text-primary">
                    {t(`fleet.transport.${tr.transport}`)}
                  </span>
                  <span className={cn(
                    'rounded-full border px-1.5 py-0.5 text-[10px]',
                    tr.enabled
                      ? 'border-status-up/30 bg-status-up/10 text-status-up'
                      : 'border-border bg-bg-tertiary text-text-muted',
                  )}>
                    {tr.enabled ? t('fleet.enabled') : t('fleet.disabled')}
                  </span>
                  <span className="font-mono text-[11px] text-text-muted">
                    {tr.host ?? '—'}{tr.port ? `:${tr.port}` : ''}
                  </span>
                  {tr.username && (
                    <span className="font-mono text-[11px] text-text-muted">{tr.username}</span>
                  )}
                  <span className="ml-auto flex items-center gap-1.5">
                    {tr.hasSecret && (
                      <span
                        className="inline-flex items-center gap-0.5 rounded-full border border-border bg-bg-tertiary px-1.5 py-0.5 text-[10px] text-text-muted"
                        title={t('devices.secretStoredHintReveal', {
                          defaultValue:
                            'A credential is stored in the vault for this channel. Its value is only sent to the '
                            + 'browser when an account allowed to reveal secrets asks for it, and that reveal is audited.',
                        })}
                      >
                        <KeyRound size={9} />
                        {t('devices.secretStored', { version: tr.keyVersion })}
                      </span>
                    )}
                    {tr.useTls && (
                      <span className="rounded-full border border-border bg-bg-tertiary px-1.5 py-0.5 text-[10px] text-text-muted">
                        TLS
                      </span>
                    )}
                  </span>
                </div>
                {/* SECRET_READ: the stored password / private key, revealed on
                    purpose for 30 seconds (audited server-side). On a line of
                    its own: a revealed private key is several lines long. */}
                {canReveal && (tr.hasSecret || tr.hasPrivateKey) && (
                  <div className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1">
                    {tr.hasSecret && (
                      <RevealSecretButton
                        showLabel
                        label={t('secrets.field.password', { defaultValue: 'password' })}
                        resetKey={`${device.id}:${tr.transport}:${transportsLoad}`}
                        reveal={() => secretsApi.revealTransport(device.id, tr.transport, 'secret')}
                      />
                    )}
                    {tr.hasPrivateKey && (
                      <RevealSecretButton
                        showLabel
                        label={t('secrets.field.privateKey', { defaultValue: 'private key' })}
                        resetKey={`${device.id}:${tr.transport}:${transportsLoad}`}
                        reveal={() => secretsApi.revealTransport(device.id, tr.transport, 'privateKey')}
                      />
                    )}
                  </div>
                )}
                {tr.tlsFingerprintSha256 && (
                  <div className="mt-1 break-all font-mono text-[10px] text-text-muted">
                    {t('devices.pinnedFingerprint')}: {tr.tlsFingerprintSha256}
                  </div>
                )}
                {/* A refused certificate the server recorded: both fingerprints,
                    and the re-pin to the presented one (draws nothing otherwise). */}
                <TlsCertificateChangedNotice
                  deviceId={device.id}
                  deviceName={device.name}
                  isConcentrator={device.role === 'concentrator'}
                  transport={tr}
                  onRepinned={onChanged}
                />
                {tr.lastError && (
                  <div className="mt-1 font-mono text-[10px] text-status-down">{tr.lastError}</div>
                )}
              </li>
            ))}
          </ul>
        )}

        {canWrite && (
          <div className="mt-3">
            {!showTransportForm ? (
              <Button size="sm" variant="secondary" onClick={() => setShowTransportForm(true)}>
                <Plug size={14} className="mr-1.5" />
                {t('devices.addTransport')}
              </Button>
            ) : (
              <form onSubmit={addTransport} className="space-y-3 rounded-md border border-border p-3">
                <div className="space-y-1">
                  <label className="block text-sm font-medium text-text-secondary">
                    {t('devices.fields.transport')}
                  </label>
                  <select
                    value={tf.transport}
                    onChange={(e) => {
                      const transport = e.target.value as TransportKind;
                      const port = TRANSPORT_DEFAULT_PORT[transport];
                      setTf({ ...tf, transport, port: port === null ? '' : String(port) });
                    }}
                    className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent"
                  >
                    {TRANSPORT_KINDS.map((k) => (
                      <option key={k} value={k}>{t(`fleet.transport.${k}`)}</option>
                    ))}
                  </select>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <Input
                    label={t('devices.fields.host')}
                    value={tf.host}
                    onChange={(e) => setTf({ ...tf, host: e.target.value })}
                    placeholder={device.tunnelIp ?? ''}
                  />
                  <Input
                    label={t('devices.fields.port')}
                    value={tf.port}
                    onChange={(e) => setTf({ ...tf, port: e.target.value })}
                  />
                  <Input
                    label={t('devices.fields.username')}
                    value={tf.username}
                    onChange={(e) => setTf({ ...tf, username: e.target.value })}
                    autoComplete="off"
                  />
                  <Input
                    label={t('devices.fields.secret')}
                    type="password"
                    value={tf.secret}
                    onChange={(e) => setTf({ ...tf, secret: e.target.value })}
                    autoComplete="new-password"
                  />
                </div>
                <label className="flex items-center gap-2 text-sm text-text-primary">
                  <input
                    type="checkbox"
                    checked={tf.useTls}
                    onChange={(e) => setTf({ ...tf, useTls: e.target.checked })}
                    className="h-4 w-4 rounded border-border bg-bg-tertiary accent-accent"
                  />
                  {t('devices.fields.useTls')}
                </label>
                {tf.transport === 'routeros_api' && !tf.useTls && (
                  <p className="flex items-start gap-1.5 text-xs text-status-ssl-warning">
                    <ShieldAlert size={12} className="mt-0.5 shrink-0" />
                    {t('devices.plaintextApiWarning')}
                  </p>
                )}
                <div className="flex gap-2">
                  <Button type="submit" size="sm" loading={addingTransport}>{t('common.save')}</Button>
                  <Button type="button" size="sm" variant="secondary" onClick={() => setShowTransportForm(false)}>
                    {t('common.cancel')}
                  </Button>
                </div>
              </form>
            )}
          </div>
        )}
      </Card>
    </div>
  );
}
