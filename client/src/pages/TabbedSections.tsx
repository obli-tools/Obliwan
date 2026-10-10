import { Suspense } from 'react';
import { Outlet } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { PageTabs, type PageTab } from '@/components/common/PageTabs';
import { useAuthStore } from '@/store/authStore';

/**
 * The tab strips that turn families of sidebar entries into single entries.
 *
 * ┌─ WHY THESE EXIST ────────────────────────────────────────────────────────┐
 * │ The sidebar carried thirty flat rows, four of them for the mobile data   │
 * │ screens alone and nine for administration. A flat list that long stops   │
 * │ being navigation and becomes a search problem — and it lit two rows at   │
 * │ once, because a parent path is its own children's prefix.                │
 * │                                                                          │
 * │ Grouping is done with ROUTES, never with component state: see the header │
 * │ of `PageTabs`. Each layout below is a pathless <Route> wrapping the      │
 * │ screens it gathers, so every tab keeps its own URL and nothing that      │
 * │ linked to one of these pages before has to change.                       │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * A tab is dropped, not disabled, when the viewer cannot reach it: the routes
 * underneath already enforce their own guard, and a visible tab leading to a
 * 403 is worse than one that was never offered.
 *
 * ── ONE LIST PER FAMILY, READ BY TWO SCREENS ────────────────────────────────
 *
 * The tab lists are plain functions rather than literals inside each layout
 * because the SIDEBAR reads them too: its search box matches a grouped entry
 * by the names of its tabs, since those names stopped being menu entries of
 * their own when they moved in here. One list means a tab added to a strip is
 * findable by name the moment it exists, and offered to exactly the same
 * people in both places.
 */

/** 4G / LTE — the mobile data fleet. */
export function mobileTabs(t: TFunction, isAdmin: boolean): PageTab[] {
  const tabs: PageTab[] = [
    { to: '/mobile', label: t('nav.tabs.mobileOverview'), end: true },
    { to: '/mobile/lines', label: t('nav.mobileLines') },
    { to: '/mobile/recharges', label: t('nav.mobileRecharges') },
    { to: '/mobile/report', label: t('nav.mobileReport') },
  ];
  // Partner accounts hold a credential and are `requireRole('admin')` on the
  // server, not a SIM capability — so the tab follows the platform role.
  if (isAdmin) tabs.push({ to: '/mobile/accounts', label: t('nav.mobileAccounts') });
  // Partner client -> workspace (« Rapprochement SIM »): platform admin, and the
  // server further requires the master workspace (the page says so elsewhere).
  if (isAdmin) tabs.push({ to: '/mobile/reconcile', label: t('nav.mobileReconcile', { defaultValue: 'SIM reconciliation' }) });
  return tabs;
}

/**
 * Interfaces — traffic, and the thresholds that decide when it is a problem.
 *
 * `/interfaces/thresholds` was a registered route with NO menu entry at all:
 * reachable only by typing the URL. The tab is how it rejoins the product.
 */
export function interfacesTabs(t: TFunction): PageTab[] {
  return [
    { to: '/interfaces', label: t('nav.tabs.interfacesTraffic'), end: true },
    { to: '/interfaces/thresholds', label: t('nav.tabs.interfacesThresholds') },
  ];
}

/**
 * Organisation — who the tenants are, and how devices are filed under them.
 *
 * ┌─ BOTH TABS ARE PLATFORM-ADMIN, THOUGH THE ROUTES DIFFER ─────────────────┐
 * │ `/manage/tenants` is `requiredRole="admin"`. `/manage/groups` admits     │
 * │ `GROUPS_MANAGE` at the route (migration 084, Obliance's name), which the │
 * │ server honours for REORDERING and a group's CONFIGURATION only. Editing, │
 * │ moving and deleting a group need an 'rw' team grant on it (or the        │
 * │ platform admin), creating needs a team with `can_create` — so a tenant   │
 * │ admin (who holds `groups.manage`) reaches the page and may still get a   │
 * │ 403 on a rename where no team of theirs holds 'rw'. That is the rule.     │
 * │                                                                          │
 * │ The strip stays platform-admin, where the old sidebar kept the Groups    │
 * │ entry. Whoever reaches `/manage/groups` by URL still gets the page; they │
 * │ get no strip, because `PageTabs` draws nothing for fewer than two tabs.  │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
export function organisationTabs(t: TFunction, isAdmin: boolean): PageTab[] {
  if (!isAdmin) return [];
  return [
    { to: '/manage/tenants', label: t('nav.workspaces') },
    { to: '/manage/groups', label: t('nav.groups') },
  ];
}

/** Settings — the installation's own knobs, plus the two screens that move them. */
export function settingsTabs(t: TFunction): PageTab[] {
  return [
    { to: '/manage/settings', label: t('nav.tabs.settingsGeneral') },
    { to: '/manage/notifications', label: t('nav.notifications') },
    { to: '/manage/import-export', label: t('nav.importExport') },
  ];
}

/**
 * The strip, then the tab's own screen.
 *
 * ┌─ THE SUSPENSE BOUNDARY IS HERE, UNDER THE STRIP, ON PURPOSE ─────────────┐
 * │ Every screen behind a tab is a `lazy()` chunk. One that suspends outside │
 * │ a transition makes React swap the NEAREST <Suspense> for its fallback —  │
 * │ and the only other boundary sits above <Routes> in App.tsx, i.e. above   │
 * │ the header, the sidebar and this strip. Without this one, the first      │
 * │ click on a tab whose chunk had not been fetched yet swapped the whole    │
 * │ application for "…". Here, only the tab's own area waits. (App.tsx also  │
 * │ makes navigations transitions, which keep the current tab on screen      │
 * │ instead; this boundary does not depend on that.)                         │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
function TabbedShell({ tabs }: { tabs: PageTab[] }) {
  return (
    <div className="flex h-full flex-col">
      <PageTabs tabs={tabs} className="shrink-0 px-4" />
      <div className="min-h-0 flex-1 overflow-auto">
        <Suspense fallback={<div className="p-8 text-sm text-text-secondary">…</div>}>
          <Outlet />
        </Suspense>
      </div>
    </div>
  );
}

/**
 * The 4G family draws NO strip of its own any more: its tabs (`mobileTabs`)
 * are the 4G / SIM module's, and the module strip (`ModuleTabs`, drawn by
 * AppLayout) shows them above this shell. Drawing them here too would stack
 * the same row twice. The shell stays for its Suspense boundary.
 */
export function MobileLayout() {
  return <TabbedShell tabs={[]} />;
}

export function InterfacesLayout() {
  const { t } = useTranslation();
  return <TabbedShell tabs={interfacesTabs(t)} />;
}

export function OrganisationLayout() {
  const { t } = useTranslation();
  const isAdmin = useAuthStore((s) => s.isAdmin());
  return <TabbedShell tabs={organisationTabs(t, isAdmin)} />;
}

export function SettingsLayout() {
  const { t } = useTranslation();
  return <TabbedShell tabs={settingsTabs(t)} />;
}
