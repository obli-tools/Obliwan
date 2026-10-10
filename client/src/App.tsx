import { useEffect, lazy, Suspense } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import { useAuthStore } from '@/store/authStore';
import { ProtectedRoute } from '@/components/layout/ProtectedRoute';
import { AppLayout } from '@/components/layout/AppLayout';
import { LoginPage } from '@/pages/LoginPage';
import { NotFoundPage } from '@/pages/NotFoundPage';
import { CAPABILITIES } from '@obliwan/shared';
import '@/i18n';
import { initTheme } from '@/utils/theme';

// Lazily loaded: one chunk per screen. Vite names them after the file, so a
// slow route is identifiable in the network tab without a source map.
const EnrollmentPage = lazy(() => import('@/pages/EnrollmentPage').then((m) => ({ default: m.EnrollmentPage })));
const ForgotPasswordPage = lazy(() => import('@/pages/ForgotPasswordPage').then((m) => ({ default: m.ForgotPasswordPage })));
const ResetPasswordPage = lazy(() => import('@/pages/ResetPasswordPage').then((m) => ({ default: m.ResetPasswordPage })));
const DashboardPage = lazy(() => import('@/pages/DashboardPage').then((m) => ({ default: m.DashboardPage })));
const GroupManagePage = lazy(() => import('@/pages/GroupManagePage').then((m) => ({ default: m.GroupManagePage })));
const DevicesPage = lazy(() => import('@/pages/DevicesPage').then((m) => ({ default: m.DevicesPage })));
const InterfacesPage = lazy(() => import('@/pages/InterfacesPage').then((m) => ({ default: m.InterfacesPage })));
const ThresholdsPage = lazy(() => import('@/pages/ThresholdsPage').then((m) => ({ default: m.ThresholdsPage })));
const DeviceDetailPage = lazy(() => import('@/pages/DeviceDetailPage').then((m) => ({ default: m.DeviceDetailPage })));
const ConfigPage = lazy(() => import('@/pages/ConfigPage').then((m) => ({ default: m.ConfigPage })));
const DriftPage = lazy(() => import('@/pages/DriftPage').then((m) => ({ default: m.DriftPage })));
const DriftDetailPage = lazy(() => import('@/pages/DriftDetailPage').then((m) => ({ default: m.DriftDetailPage })));
const PlanPage = lazy(() => import('@/pages/PlanPage').then((m) => ({ default: m.PlanPage })));
const ChangesPage = lazy(() => import('@/pages/ChangesPage').then((m) => ({ default: m.ChangesPage })));
const ChangeJobPage = lazy(() => import('@/pages/ChangeJobPage').then((m) => ({ default: m.ChangeJobPage })));
const RolloutsPage = lazy(() => import('@/pages/RolloutsPage').then((m) => ({ default: m.RolloutsPage })));
const RolloutDetailPage = lazy(() => import('@/pages/RolloutDetailPage').then((m) => ({ default: m.RolloutDetailPage })));
const FleetUpgradePage = lazy(() => import('@/pages/FleetUpgradePage').then((m) => ({ default: m.FleetUpgradePage })));
const FleetAnomaliesPage = lazy(() => import('@/pages/FleetAnomaliesPage').then((m) => ({ default: m.FleetAnomaliesPage })));
const LineQualityPage = lazy(() => import('@/pages/LineQualityPage').then((m) => ({ default: m.LineQualityPage })));
const LogsPage = lazy(() => import('@/pages/LogsPage').then((m) => ({ default: m.LogsPage })));
const QueryPage = lazy(() => import('@/pages/QueryPage').then((m) => ({ default: m.QueryPage })));
const AlertsPage = lazy(() => import('@/pages/AlertsPage').then((m) => ({ default: m.AlertsPage })));
const SitesPage = lazy(() => import('@/pages/SitesPage').then((m) => ({ default: m.SitesPage })));
const TemplatesPage = lazy(() => import('@/pages/TemplatesPage').then((m) => ({ default: m.TemplatesPage })));
const VariablesPage = lazy(() => import('@/pages/VariablesPage').then((m) => ({ default: m.VariablesPage })));
const AuditPage = lazy(() => import('@/pages/AuditPage').then((m) => ({ default: m.AuditPage })));
const BackupsPage = lazy(() => import('@/pages/BackupsPage').then((m) => ({ default: m.BackupsPage })));
const SiteDetailPage = lazy(() => import('@/pages/SiteDetailPage').then((m) => ({ default: m.SiteDetailPage })));
const DiscoveriesPage = lazy(() => import('@/pages/DiscoveriesPage').then((m) => ({ default: m.DiscoveriesPage })));
const SettingsPage = lazy(() => import('@/pages/SettingsPage').then((m) => ({ default: m.SettingsPage })));
const NotificationsPage = lazy(() => import('@/pages/NotificationsPage').then((m) => ({ default: m.NotificationsPage })));
const AdminUsersPage = lazy(() => import('@/pages/AdminUsersPage').then((m) => ({ default: m.AdminUsersPage })));
const ProfilePage = lazy(() => import('@/pages/ProfilePage').then((m) => ({ default: m.ProfilePage })));
const GroupDetailPage = lazy(() => import('@/pages/GroupDetailPage').then((m) => ({ default: m.GroupDetailPage })));
const GroupEditPage = lazy(() => import('@/pages/GroupEditPage').then((m) => ({ default: m.GroupEditPage })));
const ImportExportPage = lazy(() => import('@/pages/ImportExportPage').then((m) => ({ default: m.ImportExportPage })));
const AdminTenantsPage = lazy(() => import('@/pages/AdminTenantsPage').then((m) => ({ default: m.AdminTenantsPage })));
const SsoEnrollPage = lazy(() => import('@/pages/SsoEnrollPage').then((m) => ({ default: m.SsoEnrollPage })));
const AcsPage = lazy(() => import('@/pages/AcsPage').then((m) => ({ default: m.AcsPage })));
const IntentPage = lazy(() => import('@/pages/IntentPage').then((m) => ({ default: m.IntentPage })));
const BaselinePage = lazy(() => import('@/pages/BaselinePage').then((m) => ({ default: m.BaselinePage })));
const MobileDashboardPage = lazy(() => import('@/pages/MobileDashboardPage').then((m) => ({ default: m.MobileDashboardPage })));
const MobileLinesPage = lazy(() => import('@/pages/MobileLinesPage').then((m) => ({ default: m.MobileLinesPage })));
const MobileLineDetailPage = lazy(() => import('@/pages/MobileLineDetailPage').then((m) => ({ default: m.MobileLineDetailPage })));
const MobileRechargesPage = lazy(() => import('@/pages/MobileRechargesPage').then((m) => ({ default: m.MobileRechargesPage })));
const MobileReportPage = lazy(() => import('@/pages/MobileReportPage').then((m) => ({ default: m.MobileReportPage })));
const AdminSimAccountsPage = lazy(() => import('@/pages/AdminSimAccountsPage').then((m) => ({ default: m.AdminSimAccountsPage })));
const SimReconcilePage = lazy(() => import('@/pages/SimReconcilePage').then((m) => ({ default: m.SimReconcilePage })));
const AllocationPage = lazy(() => import('@/pages/AllocationPage').then((m) => ({ default: m.AllocationPage })));
const QuickSetupTenantPage = lazy(() => import('@/pages/QuickSetupTenantPage').then((m) => ({ default: m.QuickSetupTenantPage })));
const InfraAnalysisPage = lazy(() => import('@/pages/InfraAnalysisPage').then((m) => ({ default: m.InfraAnalysisPage })));
const LearningPage = lazy(() => import('@/pages/LearningPage').then((m) => ({ default: m.LearningPage })));
const BenchStationsPage = lazy(() => import('@/pages/BenchStationsPage').then((m) => ({ default: m.BenchStationsPage })));
const ReconcilePage = lazy(() => import('@/pages/ReconcilePage').then((m) => ({ default: m.ReconcilePage })));
const SlaPage = lazy(() => import('@/pages/SlaPage').then((m) => ({ default: m.SlaPage })));
const IdentityEventsPage = lazy(() => import('@/pages/IdentityEventsPage').then((m) => ({ default: m.IdentityEventsPage })));
// Tab strips. Not lazy, and each one wraps its own <Outlet /> in a <Suspense>
// (`TabbedShell`): a lazy child that suspends is caught UNDER the strip, so the
// strip, the header and the sidebar stay drawn while the tab's chunk arrives.
// Not being lazy was never enough on its own — with the only boundary above
// <Routes>, the first click on each tab replaced the whole app with "…".
import { MobileLayout, InterfacesLayout, OrganisationLayout, SettingsLayout } from '@/pages/TabbedSections';

// Apply saved theme immediately to avoid flash of unstyled content
initTheme();

/**
 * Route table.
 *
 * Only the pages that actually exist are routed: the inventory
 * (/devices, /devices/:id, /sites, /sites/:id, /manage/discoveries), the
 * telemetry (/interfaces and its thresholds screen) and the NCM screens
 * (/config, /config/:deviceId, /drift, /drift/:id).
 *
 * Then the safe-write screens (/plan, /plan/:deviceId, /changes,
 * /changes/:id). /plan sits behind PLAN_CREATE and /changes behind
 * CHANGE_APPLY: reading what a plan would do and being allowed to push it are
 * two different privileges, exactly as CONFIG_READ is distinct from
 * DEVICE_READ below.
 *
 * /rollouts and /rollouts/:id sit behind CHANGE_APPLY (a rollout is N change
 * jobs and nothing else); /logs (DEVICE_READ) and the attribution
 * banner inside /drift/:id come next, then /query (CONFIG_READ at the route, QUERY_RUN
 * checked inside the page: reading configuration and being allowed to sweep the
 * whole fleet for a pattern are two different privileges). /alerts is opened
 * with no capability, matching the sidebar design — it reads `/api/live-alerts`, which is
 * session-scoped rather than capability-scoped.
 *
 * /acs sits behind ACS_ADMIN (the sidebar design names that capability explicitly). /intent
 * and /baseline have no row in the sidebar design, which stops at the
 * screens known when the spec was written, so their guards are derived from
 * what the pages actually do. /intent sits behind TEMPLATE_WRITE: composing a
 * site intent is authoring configuration, and `capabilities.ts` files intent
 * under "Templates & intent" itself. /baseline sits behind
 * CONFIG_READ because mining reads snapshots; the promote-to-template gesture
 * inside it carries its own TEMPLATE_WRITE check, exactly as /query opens on
 * CONFIG_READ and then checks QUERY_RUN before executing.
 *
 * /templates, /variables, /backups and /manage/audit are routed too, inside
 * the DEVICE_READ block below. The sidebar offers them on different terms —
 * TEMPLATE_WRITE for the first two, CONFIG_READ for /backups, platform admins
 * only for the audit — so for these four the two guards do NOT agree yet,
 * which the next paragraph says they must.
 *
 * `/config` and `/drift` sit behind CONFIG_READ, which the no-secrets rule makes
 * deliberately DISTINCT from DEVICE_READ: seeing that a router exists and
 * reading its configuration are two different privileges, and the sidebar
 * guard and the route guard have to agree on that or one of them is decorative.
 */
export default function App() {
  const { checkSession } = useAuthStore();

  useEffect(() => {
    checkSession();
  }, [checkSession]);

  // ┌─ NAVIGATIONS ARE TRANSITIONS ──────────────────────────────────────────┐
  // │ `v7_startTransition` makes every route change a React transition. In a │
  // │ transition React keeps what is on screen ONLY when the screen that     │
  // │ suspends sits under a <Suspense> that is already showing content; a    │
  // │ boundary that the navigation itself mounts shows its fallback at once. │
  // │ So, while the destination's lazy chunk loads:                          │
  // │   - a screen drawn straight into AppLayout (/devices -> /sites) has    │
  // │     the <Suspense> below as its nearest boundary. That one is showing  │
  // │     the app, so the CURRENT page stays up until the chunk arrives.     │
  // │     Without the flag, the same update replaced the header, the sidebar │
  // │     and the page with "…" on the first visit to every screen;          │
  // │   - between two tabs of one strip (/mobile -> /mobile/lines) the       │
  // │     nearest boundary is TabbedShell's, already showing a tab, so the   │
  // │     current tab stays up;                                              │
  // │   - entering a tab family from outside (/devices -> /mobile) MOUNTS    │
  // │     TabbedShell's boundary, so the previous page goes at once and the  │
  // │     strip is drawn over its "…". The header and sidebar stay.          │
  // │ The fallback below is left to renders that are not navigations — the   │
  // │ first load above all, when there is no current page to keep. This is   │
  // │ also how React Router v7 behaves by default.                           │
  // └────────────────────────────────────────────────────────────────────────┘
  return (
    <BrowserRouter future={{ v7_startTransition: true }}>
      <Suspense fallback={<div className="p-8 text-sm text-text-secondary">…</div>}>
        <Routes>
        {/* Public routes */}
        <Route path="/login" element={<LoginPage />} />
        <Route path="/forgot-password" element={<ForgotPasswordPage />} />
        <Route path="/reset-password" element={<ResetPasswordPage />} />
        {/* Protected routes */}
        <Route element={<ProtectedRoute />}>
          {/* Enrollment — full-screen, outside AppLayout */}
          <Route path="/enroll" element={<EnrollmentPage />} />
          {/* SSO new-user enrollment — full-screen, outside AppLayout */}
          <Route path="/sso-enroll" element={<SsoEnrollPage />} />
          <Route element={<AppLayout />}>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/profile" element={<ProfilePage />} />
            <Route path="/group/:id" element={<GroupDetailPage />} />
            <Route path="/group/:id/edit" element={<GroupEditPage />} />

            {/* Fleet inventory → DEVICE_READ capability */}
            <Route element={<ProtectedRoute requiredCapability={CAPABILITIES.DEVICE_READ} />}>
              <Route path="/devices" element={<DevicesPage />} />
              <Route path="/devices/:id" element={<DeviceDetailPage />} />
              <Route path="/sites" element={<SitesPage />} />
              <Route path="/templates" element={<TemplatesPage />} />
              <Route path="/variables" element={<VariablesPage />} />
              <Route path="/manage/audit" element={<AuditPage />} />
              <Route path="/backups" element={<BackupsPage />} />
              <Route path="/sites/:id" element={<SiteDetailPage />} />
              {/* Telemetry. The thresholds screen sits UNDER /interfaces
                  rather than under a sidebar entry of its own: the sidebar design gives
                  it no row, and the mission for this milestone unlocks the
                  Interfaces entry only. */}
              <Route element={<InterfacesLayout />}>
                <Route path="/interfaces" element={<InterfacesPage />} />
                <Route path="/interfaces/thresholds" element={<ThresholdsPage />} />
              </Route>
              {/* Unified log: syslog + traps + RouterOS /log.
                  DEVICE_READ and not CONFIG_READ — a log line is an event about
                  a box, not its configuration. */}
              <Route path="/logs" element={<LogsPage />} />
              {/* Calculated SLA and identity changes. DEVICE_READ,
                  exactly what every READ of `/api/sla` and `/api/identity`
                  requires: both are fleet observation and carry no
                  configuration. The two actions inside carry their own checks —
                  issuing an SLA report needs EXPORT_RUN on top, acknowledging
                  an identity change DRIFT_MANAGE. */}
              <Route path="/sla" element={<SlaPage />} />
              <Route path="/identity-events" element={<IdentityEventsPage />} />
            </Route>

            {/* Configuration + drift → CONFIG_READ capability */}
            <Route element={<ProtectedRoute requiredCapability={CAPABILITIES.CONFIG_READ} />}>
              <Route path="/config" element={<ConfigPage />} />
              <Route path="/config/:deviceId" element={<ConfigPage />} />
              <Route path="/drift" element={<DriftPage />} />
              <Route path="/drift/:id" element={<DriftDetailPage />} />
              {/* Fleet Query. CONFIG_READ opens the screen because a
                  query answers about configuration; the page itself then checks
                  QUERY_RUN before it will execute one. */}
              <Route path="/query" element={<QueryPage />} />
              {/* Fleet takeover / Golden Site. Mining reads every
                  snapshot the session may read, which is CONFIG_READ and
                  nothing more — it touches no equipment. Promoting a
                  deduced draft into a template is a different privilege and is
                  checked inside the page against TEMPLATE_WRITE. */}
              <Route path="/baseline" element={<BaselinePage />} />
            </Route>

            {/* Intent compiler -> TEMPLATE_WRITE.
                Composing an intent is authoring configuration for a whole site,
                and `capabilities.ts` files intent under "Templates & intent"
                itself. The screen compiles and stops there: the Intent Compiler puts
                `capabilityCheck` BEFORE any network access, and applying stays
                behind /plan and the change queue. */}
            <Route element={<ProtectedRoute requiredCapability={CAPABILITIES.TEMPLATE_WRITE} />}>
              <Route path="/intent" element={<IntentPage />} />
            </Route>

            {/* Mobile data lines -> SIM_READ.
                A SIM is commercial inventory carrying an MSISDN and a cost, not
                a router, so it is NOT gated on DEVICE_READ: a role that may see
                the fleet need not see what its lines cost. The screens then
                check SIM_MANAGE before editing a line and SIM_RECHARGE before
                approving or recording a top-up — the only capability in this
                product that commits a purchase.

                The partner ACCOUNTS screen is not in this block: it holds
                credentials and is platform-scoped, so it sits behind the
                platform admin guard further down, like tenants. Its URL is
                /mobile/accounts, inside the same MobileLayout strip;
                /manage/mobile-accounts is only a redirect to it.

                `/manage`, not `/admin`: Oblihub's edge security bans a caller
                that requests an `/admin/*` path, so the prefix cost real access
                and bought nothing — the authorisation is `ProtectedRoute` plus
                the server's own capability checks, never the spelling of the
                URL. The whole suite is moving off it. */}
            <Route element={<ProtectedRoute requiredCapability={CAPABILITIES.SIM_READ} />}>
              <Route element={<MobileLayout />}>
                <Route path="/mobile" element={<MobileDashboardPage />} />
                <Route path="/mobile/lines" element={<MobileLinesPage />} />
                <Route path="/mobile/recharges" element={<MobileRechargesPage />} />
                <Route path="/mobile/report" element={<MobileReportPage />} />
              </Route>
              {/* Outside the strip: a single line is a drill-down, not a tab.
                  The low-balance alert deep-links straight here. */}
              <Route path="/mobile/lines/:id" element={<MobileLineDetailPage />} />
            </Route>

            {/* ACS / TR-069 -> ACS_ADMIN, as the sidebar design requires.
                CPEs, the CWMP task queue, the parameter map and firmware — the
                four things that capability's description names. Coverage is
                DrayTek + Zyxel CPE only and the page states that before it
                states anything else. */}
            <Route element={<ProtectedRoute requiredCapability={CAPABILITIES.ACS_ADMIN} />}>
              <Route path="/acs" element={<AcsPage />} />
            </Route>

            {/* Plan compilation -> PLAN_CREATE.
                Deliberately NOT CHANGE_APPLY: compiling and reading a plan
                touches no equipment, and an operator who may not push must
                still be able to ask "what would ObliWAN change on this box".
                The apply controls inside the page carry their own
                CHANGE_APPLY / CHANGE_APPROVE checks. */}
            <Route element={<ProtectedRoute requiredCapability={CAPABILITIES.PLAN_CREATE} />}>
              <Route path="/plan" element={<PlanPage />} />
              <Route path="/plan/:deviceId" element={<PlanPage />} />
            </Route>

            {/* Change jobs -> CHANGE_APPLY.
                The queue is the ONLY path along which this product writes to an
                equipment, so the screens that watch it sit behind the same
                capability that enqueues one. The kill switch lives here too:
                it is reached in a panic and must not be behind an admin page. */}
            <Route element={<ProtectedRoute requiredCapability={CAPABILITIES.CHANGE_APPLY} />}>
              <Route path="/changes" element={<ChangesPage />} />
              <Route path="/changes/:id" element={<ChangeJobPage />} />
              {/* Wave rollouts. Same capability as the queue
                  they feed: a rollout is N change jobs and nothing else, so
                  gating it more loosely than /changes would be a way around
                  CHANGE_APPLY rather than a separate privilege. */}
              <Route path="/rollouts" element={<RolloutsPage />} />
              <Route path="/rollouts/:id" element={<RolloutDetailPage />} />
            </Route>

            {/* CHR <-> sites reconciliation of the SESSION's workspace ->
                RECONCILE_READ (the account manager's "view + re-read"). Not
                under /manage: the server route is tenant-scoped (/api/reconcile,
                the tenant read off the session), redacted, and refuses a
                workspace whose login rule names no tenant. The full report over
                any tenant stays on /manage/allocation (platform admin). */}
            <Route element={<ProtectedRoute requiredCapability={CAPABILITIES.RECONCILE_READ} />}>
              <Route path="/reconcile" element={<ReconcilePage />} />
            </Route>

            {/* Fleet update ("mise à jour du parc"). DEVICE_READ, like the
                server's listing: the page shows every router's version
                read-only to anyone who may see the fleet. Launching is
                checked again inside the page and on the server
                (CHANGE_APPLY, plus ROLLOUT_MANAGE and CHANGE_APPROVE), and
                still reaches a router only through change_jobs. */}
            <Route element={<ProtectedRoute requiredCapability={CAPABILITIES.DEVICE_READ} />}>
              <Route path="/fleet-upgrade" element={<FleetUpgradePage />} />
              {/* Fleet anomalies: a read-only audit of what is stored
                  (DEVICE_READ, like the server route). */}
              <Route path="/fleet-anomalies" element={<FleetAnomaliesPage />} />
              {/* Degraded fixed lines, measured at night (DEVICE_READ, like the server route). */}
              <Route path="/line-quality" element={<LineQualityPage />} />
            </Route>

            {/* Alerts (no capability guard). Backed by
                `/api/live-alerts`, which is scoped by the session's tenants
                rather than by a capability. */}
            <Route path="/alerts" element={<AlertsPage />} />

            {/* ── Organisation: who the tenants are, and how devices file under
                   them. Two different guards under ONE strip — the layout
                   wraps them, it does not authorise them. */}
            <Route element={<OrganisationLayout />}>
              <Route element={<ProtectedRoute requiredCapability={CAPABILITIES.GROUPS_MANAGE} />}>
                <Route path="/manage/groups" element={<GroupManagePage />} />
              </Route>
              <Route element={<ProtectedRoute requiredRole="admin" />}>
                <Route path="/manage/tenants" element={<AdminTenantsPage />} />
              </Route>
            </Route>

            {/* Admin-only routes */}
            <Route element={<ProtectedRoute requiredRole="admin" />}>
              <Route path="/manage/discoveries" element={<DiscoveriesPage />} />
              <Route path="/manage/users" element={<AdminUsersPage />} />
              {/* Platform-scoped, like their APIs (`/api/allocation`,
                  `/api/bench-stations`: requireRole('admin') inside the router):
                  address pools span tenants, and a bench workstation prepares
                  routers for every customer. */}
              <Route path="/manage/allocation" element={<AllocationPage />} />
              {/* Quick Setup Tenant: platform admin, like /api/tenant-setup (requireRole('admin')).
                  It writes instance variables and the allocation rule, both
                  platform-admin-only already, so no tenant capability can grant it. */}
              <Route path="/manage/quick-setup" element={<QuickSetupTenantPage />} />
              {/* Infrastructure analysis: platform admin, like /api/infra-analysis
                  (requireRole('admin')): it dials the routers with fleet
                  credentials and writes site variables. */}
              <Route path="/manage/infra-analysis" element={<InfraAnalysisPage />} />
              {/* Learning mode: platform admin, like /api/learning (requireRole('admin')):
                  a capture reads routers in production with their secrets. */}
              <Route path="/manage/learning" element={<LearningPage />} />
              <Route path="/manage/bench-stations" element={<BenchStationsPage />} />
              {/* Mobile partner accounts. Behind the PLATFORM admin role
                  and not a capability: the rows hold a partner credential and
                  have no tenant_id, so one write changes what every tenant is
                  shown — and SETTINGS_MANAGE is granted to the admin of ANY
                  tenant through TENANT_ROLE_CAPABILITIES, which is the exact
                  shape of the defect the ASN enrichment once shipped on ip_asn_ranges. */}
              {/* Moved under /mobile so it sits inside the family it belongs
                  to, both in the URL and in the tab strip. The old path is
                  kept as a redirect: it was a working link, and a reorganised
                  menu is no reason to break somebody's bookmark. */}
              <Route element={<MobileLayout />}>
                <Route path="/mobile/accounts" element={<AdminSimAccountsPage />} />
                <Route path="/mobile/reconcile" element={<SimReconcilePage />} />
              </Route>
              <Route
                path="/manage/mobile-accounts"
                element={<Navigate to="/mobile/accounts" replace />}
              />
              {/* Settings, and the two screens that were loose entries beside
                  it. All three are admin-only, so the strip needs no filter. */}
              <Route element={<SettingsLayout />}>
                <Route path="/manage/settings" element={<SettingsPage />} />
                <Route path="/manage/notifications" element={<NotificationsPage />} />
                <Route path="/manage/import-export" element={<ImportExportPage />} />
              </Route>
            </Route>
          </Route>
        </Route>

        {/* 404 */}
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
      </Suspense>

      <Toaster
        position="top-right"
        toastOptions={{
          className: '!bg-bg-secondary !text-text-primary !border !border-border',
          duration: 4000,
        }}
      />
    </BrowserRouter>
  );
}
