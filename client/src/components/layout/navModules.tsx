import type { ReactNode } from 'react';
import { useLocation } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import {
  Activity,
  AlertTriangle,
  Archive,
  ArrowUpCircle,
  BellRing,
  Braces,
  Building2,
  Cpu,
  FileCode,
  Fingerprint,
  Gauge,
  GitCompareArrows,
  GitMerge,
  Globe,
  Layers,
  MapPin,
  MonitorCheck,
  Network,
  PlayCircle,
  Radar,
  RadioTower,
  Rocket,
  Router,
  ScanSearch,
  GraduationCap,
  ScrollText,
  Search,
  Settings,
  ShieldCheck,
  Signal,
  SquareStack,
  Users,
  Wand2,
} from 'lucide-react';
import { CAPABILITIES } from '@obliwan/shared';
import { useAuthStore } from '@/store/authStore';
import { interfacesTabs, mobileTabs, organisationTabs, settingsTabs } from '@/pages/TabbedSections';
import {
  resolveActiveNav,
  visibleModules,
  type ActiveNav,
  type NavModule,
} from './navModuleMatch';

export type NavModuleDef = NavModule<ReactNode>;

/**
 * The modules of the left menu, in order, with every gate copied from the
 * route that serves the screen (App.tsx) — a sidebar guard that disagrees with
 * its route is decorative, or worse, a door to a 403.
 *
 * The order follows the sequence the work takes: what exists (Parc), how it
 * reaches us (Raccordement), what it says and should say (Configuration),
 * pushing that under guard (Changements), the mobile fleet — a separate trade
 * because it spends money rather than configuration (4G / SIM) — watching
 * (Supervision), and running the installation itself (Administration).
 *
 * Module labels reuse `nav.sections.*` (and `nav.mobile`): they were the
 * section headings of the old menu, and all eighteen locales translate them.
 */
export function buildNavModules(t: TFunction, isAdmin: boolean): NavModuleDef[] {
  return [
    {
      id: 'fleet',
      label: t('nav.sections.fleet'),
      icon: <Router size={18} />,
      tabs: [
        { to: '/devices', label: t('nav.tabs.devices'), icon: <Router size={15} />, capability: CAPABILITIES.DEVICE_READ },
        { to: '/sites', label: t('nav.sites'), icon: <MapPin size={15} />, capability: CAPABILITIES.DEVICE_READ },
        { to: '/interfaces', label: t('nav.interfaces'), icon: <Activity size={15} />, capability: CAPABILITIES.DEVICE_READ,
          alsoMatch: ['/interfaces/thresholds'], subTabs: interfacesTabs(t) },
        { to: '/fleet-anomalies', label: t('nav.tabs.anomalies'), icon: <AlertTriangle size={15} />, capability: CAPABILITIES.DEVICE_READ },
        { to: '/line-quality', label: t('nav.tabs.lineQuality'), icon: <Gauge size={15} />, capability: CAPABILITIES.DEVICE_READ },
        // CONFIG_READ at the route; QUERY_RUN is checked inside the page.
        { to: '/query', label: t('nav.tabs.query'), icon: <Search size={15} />, capability: CAPABILITIES.CONFIG_READ },
        { to: '/identity-events', label: t('nav.identityEvents'), icon: <Fingerprint size={15} />, capability: CAPABILITIES.DEVICE_READ },
      ],
    },
    {
      id: 'onboarding',
      label: t('nav.sections.onboarding'),
      icon: <Radar size={18} />,
      tabs: [
        { to: '/manage/discoveries', label: t('nav.discoveries'), icon: <Radar size={15} />, adminOnly: true },
        // The session workspace's own reconciliation (the account manager's).
        { to: '/reconcile', label: t('nav.reconcile'), icon: <GitMerge size={15} />, capability: CAPABILITIES.RECONCILE_READ },
        { to: '/manage/quick-setup', label: t('nav.tabs.quickSetup'), icon: <Wand2 size={15} />, adminOnly: true },
        // Platform admin, like its route: it dials routers with fleet credentials.
        { to: '/manage/infra-analysis', label: t('nav.tabs.infraAnalysis'), icon: <ScanSearch size={15} />, adminOnly: true },
        // Platform admin, like its route: a capture reads routers with their secrets.
        { to: '/manage/learning', label: t('nav.tabs.learning'), icon: <GraduationCap size={15} />, adminOnly: true },
        // Mining reads snapshots (CONFIG_READ); promoting is TEMPLATE_WRITE, checked inside.
        { to: '/baseline', label: t('nav.baseline'), icon: <SquareStack size={15} />, capability: CAPABILITIES.CONFIG_READ },
        // DrayTek + Zyxel CPE only — the page says so first.
        { to: '/acs', label: t('nav.tabs.acs'), icon: <RadioTower size={15} />, capability: CAPABILITIES.ACS_ADMIN },
      ],
    },
    {
      id: 'config',
      label: t('nav.sections.config'),
      icon: <FileCode size={18} />,
      tabs: [
        // No-secrets rule: CONFIG_READ is distinct from DEVICE_READ.
        { to: '/config', label: t('nav.configurations'), icon: <FileCode size={15} />, capability: CAPABILITIES.CONFIG_READ },
        { to: '/drift', label: t('nav.drift'), icon: <GitCompareArrows size={15} />, capability: CAPABILITIES.CONFIG_READ },
        { to: '/templates', label: t('nav.templates'), icon: <Layers size={15} />, capability: CAPABILITIES.TEMPLATE_WRITE },
        // The Site tab is the account manager's (SITE_VARIABLES_WRITE without
        // TEMPLATE_WRITE): VariablesPage shows each viewer the tabs they hold.
        { to: '/variables', label: t('nav.variables'), icon: <Braces size={15} />,
          anyCapability: [CAPABILITIES.TEMPLATE_WRITE, CAPABILITIES.SITE_VARIABLES_WRITE] },
        { to: '/backups', label: t('nav.backups'), icon: <Archive size={15} />, capability: CAPABILITIES.CONFIG_READ },
        { to: '/intent', label: t('nav.intent'), icon: <Cpu size={15} />, capability: CAPABILITIES.TEMPLATE_WRITE },
      ],
    },
    {
      id: 'change',
      label: t('nav.sections.change'),
      icon: <PlayCircle size={18} />,
      tabs: [
        // `/plan` compiles what a change would do: it belongs here without
        // being a tab, so it lights the module and draws no strip.
        { to: '/changes', label: t('nav.changes'), icon: <PlayCircle size={15} />, capability: CAPABILITIES.CHANGE_APPLY,
          drillDowns: ['/plan'] },
        { to: '/rollouts', label: t('nav.rollouts'), icon: <Rocket size={15} />, capability: CAPABILITIES.CHANGE_APPLY },
        // DEVICE_READ, like the route: the launch is checked inside the page.
        { to: '/fleet-upgrade', label: t('nav.fleetUpgrade'), icon: <ArrowUpCircle size={15} />, capability: CAPABILITIES.DEVICE_READ },
      ],
    },
    {
      // SIM_READ and not DEVICE_READ: a SIM is commercial inventory carrying
      // an MSISDN and a cost. The tabs are `mobileTabs` itself, so a tab added
      // to that list is in this module, the strip and the search at once; the
      // partner-accounts tab is already filtered there on the platform role.
      id: 'mobile',
      label: t('nav.mobile'),
      icon: <Signal size={18} />,
      capability: CAPABILITIES.SIM_READ,
      tabs: mobileTabs(t, isAdmin).map((tab) => ({ ...tab, icon: <Signal size={15} /> })),
    },
    {
      id: 'monitor',
      label: t('nav.sections.monitor'),
      icon: <BellRing size={18} />,
      tabs: [
        // No capability — `/api/live-alerts` is session-scoped.
        { to: '/alerts', label: t('nav.alerts'), icon: <BellRing size={15} /> },
        { to: '/logs', label: t('nav.logs'), icon: <ScrollText size={15} />, capability: CAPABILITIES.DEVICE_READ },
        { to: '/sla', label: t('nav.sla'), icon: <Gauge size={15} />, capability: CAPABILITIES.DEVICE_READ },
      ],
    },
    {
      // Platform admin throughout, like every route behind it.
      id: 'admin',
      label: t('nav.sections.admin'),
      icon: <Settings size={18} />,
      tabs: [
        { to: '/manage/users', label: t('nav.users'), icon: <Users size={15} />, adminOnly: true },
        // Workspaces + groups. Platform admin, like the strip in
        // `organisationTabs` (group edits are team grants; `groups.manage` reorders and configures).
        { to: '/manage/tenants', label: t('nav.organisation'), icon: <Building2 size={15} />, adminOnly: true,
          alsoMatch: ['/manage/groups'], subTabs: organisationTabs(t, isAdmin) },
        { to: '/manage/audit', label: t('nav.audit'), icon: <ShieldCheck size={15} />, adminOnly: true },
        { to: '/manage/allocation', label: t('allocation.title'), icon: <Network size={15} />, adminOnly: true },
        { to: '/manage/bench-stations', label: t('nav.benchStations'), icon: <MonitorCheck size={15} />, adminOnly: true },
        // The Instance tab of the Variables page. Its query string outranks
        // Configuration's `/variables` (see `resolveActiveNav`), so following
        // it keeps Administration lit; any other Variables tab is Configuration's.
        { to: '/variables?tab=instance', label: t('nav.instanceVariables'), icon: <Globe size={15} />, adminOnly: true },
        { to: '/manage/settings', label: t('nav.settings'), icon: <Settings size={15} />, adminOnly: true,
          alsoMatch: ['/manage/notifications', '/manage/import-export'], subTabs: settingsTabs(t) },
      ],
    },
  ];
}

/**
 * The modules this viewer may open, and which one the current page belongs
 * to. ONE hook for the Sidebar and the strip, so they cannot disagree.
 */
export function useNavModules(): { modules: NavModuleDef[]; active: ActiveNav } {
  const { t } = useTranslation();
  const location = useLocation();
  const { isAdmin, hasCapability } = useAuthStore();
  const admin = isAdmin();
  const modules = visibleModules(buildNavModules(t, admin), { isAdmin: admin, hasCapability });
  const active = resolveActiveNav(modules, location.pathname, location.search);
  return { modules, active };
}
