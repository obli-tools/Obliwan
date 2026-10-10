import { useEffect, useRef, useState } from 'react';
import { LogOut, MoreHorizontal, ChevronDown } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useAuthStore } from '@/store/authStore';
import { useTenantStore } from '@/store/tenantStore';
import { useSocketStore } from '@/store/socketStore';
import { anonUsername } from '@/utils/anonymize';
import { NotificationCenter } from './NotificationCenter';
import { DownloadAppButton } from './DownloadAppButton';
import { TenantSwitcher } from './TenantSwitcher';
import { UserAvatar } from '@/components/common/UserAvatar';
import { Logo } from '@/components/common/Logo';
import { cn } from '@/utils/cn';

/** True when running inside the native desktop app overlay. */
const isNativeApp = typeof window !== 'undefined' &&
  !!(window as Window & { __obliwan_is_native_app?: boolean }).__obliwan_is_native_app;

// ── App switcher data ───────────────────────────────────────────────────────
//
// Every app, its order, name and accent colour come from Obligate
// (/api/auth/connected-apps, already sorted): a newly registered app shows up
// here with no code change. ObliWAN only knows its own identity.

/** app_type this instance is registered under in Obligate. */
const CURRENT_APP = 'obliwan';

// Fallback colour for an app whose accent colour Obligate does not know yet.
const FALLBACK_APP_COLOR = '#8b949e';

interface ConnectedApp {
  appType: string;
  name: string;
  baseUrl: string;
  icon: string | null;
  color: string | null;
  /** Marks the entry that is this app itself (resolved by Obligate from the Bearer key). */
  self?: boolean;
  /** Not an Obli* app (filed under "More…" in Obligate): listed in the "More…" dropdown. */
  thirdParty?: boolean;
}

/** Used only until the dynamic list loads / if Obligate ever omits self — never for other apps. */
const CURRENT_APP_FALLBACK: ConnectedApp = { appType: CURRENT_APP, name: 'ObliWAN', baseUrl: '', icon: null, color: '#90A4AE', self: true };

// Apps are refreshed periodically so a newly-registered app in Obligate
// appears here without requiring a reload of this tab.
const REFRESH_INTERVAL_MS = 5 * 60_000;

export function Header() {
  const { t } = useTranslation();
  const { user, logout } = useAuthStore();
  const { status: socketStatus } = useSocketStore();
  const [connectedApps, setConnectedApps] = useState<ConnectedApp[]>([]);
  const [collapsed, setCollapsed] = useState(false);
  const [moreOpen, setMoreOpen] = useState(false);

  const switcherWrapRef = useRef<HTMLDivElement>(null); // flexible-width slot: its clientWidth is the space actually granted
  const measureRef = useRef<HTMLDivElement>(null); // hidden, always full-label, used only to measure the width the switcher would need
  const moreRef = useRef<HTMLDivElement>(null);

  const loadApps = () => {
    fetch('/api/auth/connected-apps', { credentials: 'include' })
      .then(r => r.json())
      .then((d: { success: boolean; data?: ConnectedApp[] }) => {
        if (d.success && d.data) setConnectedApps(d.data);
      })
      .catch(() => {});
  };

  useEffect(() => {
    loadApps();
    const interval = setInterval(loadApps, REFRESH_INTERVAL_MS);
    return () => clearInterval(interval);
  }, []);

  // The current app is whichever entry Obligate marked `self` (falls back to
  // matching appType for older Obligate versions), synthesised from
  // CURRENT_APP_FALLBACK if Obligate omits it — ObliWAN's own pill must never
  // disappear from its own switcher.
  const selfEntry = connectedApps.find(a => a.self) ?? connectedApps.find(a => a.appType === CURRENT_APP);
  const visibleApps: ConnectedApp[] = selfEntry ? connectedApps : [CURRENT_APP_FALLBACK, ...connectedApps];
  const isCurrentApp = (app: ConnectedApp) => app === selfEntry || app.self === true || (!selfEntry && app.appType === CURRENT_APP);
  // Obli* apps in the main row, third-party apps (Passly…) in "More…". The
  // current app always stays in the main row, even when it is third-party.
  const mainApps = visibleApps.filter(a => !a.thirdParty || isCurrentApp(a));
  const moreApps = visibleApps.filter(a => a.thirdParty && !isCurrentApp(a));

  // "More…" dropdown: outside click and Escape close it.
  useEffect(() => {
    if (!moreOpen) return;
    const onDown = (e: PointerEvent) => { if (moreRef.current && !moreRef.current.contains(e.target as Node)) setMoreOpen(false); };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setMoreOpen(false); };
    document.addEventListener('pointerdown', onDown);
    document.addEventListener('keydown', onKey);
    return () => { document.removeEventListener('pointerdown', onDown); document.removeEventListener('keydown', onKey); };
  }, [moreOpen]);

  const goApp = (app: ConnectedApp) => {
    if (isCurrentApp(app) || !app.baseUrl) return;
    // Cross-app tenant handoff: forward the current tenant slug so the target
    // app can re-select the same tenant after Obligate SSO completes. Falls
    // back to the user's first available tenant on the target side if the
    // slug does not exist there.
    const ts = useTenantStore.getState();
    const tenantSlug = ts.tenants.find(t => t.id === ts.currentTenantId)?.slug;
    const url = new URL(`${app.baseUrl}/auth/sso-redirect`);
    if (tenantSlug) url.searchParams.set('tenant', tenantSlug);
    window.location.href = url.toString();
  };

  // Collapse to colour-dot-only pills the moment the fully-labelled row would
  // not fit the space flexbox grants the switcher — re-measured on every
  // resize and every time the app list changes (new app registered).
  useEffect(() => {
    const el = switcherWrapRef.current;
    const measure = measureRef.current;
    if (!el || !measure) return;
    const update = () => setCollapsed(measure.scrollWidth > el.clientWidth);
    update();
    const ro = new ResizeObserver(update);
    ro.observe(el);
    return () => ro.disconnect();
  }, [mainApps.length, moreApps.length]);

  const moreButton = (labelled: boolean, interactive: boolean) => (
    <button
      type="button"
      onClick={interactive ? () => setMoreOpen(v => !v) : undefined}
      tabIndex={interactive ? undefined : -1}
      aria-haspopup={interactive ? 'true' : undefined}
      aria-expanded={interactive ? moreOpen : undefined}
      className={cn(
        'flex items-center gap-1.5 rounded-md py-1.5 text-[12.5px] font-medium text-text-secondary transition-colors hover:bg-bg-active hover:text-text-primary shrink-0',
        labelled ? 'px-3' : 'px-1.5',
      )}
      title={t('header.moreApps', 'More…')}
      aria-label={t('header.moreApps', 'More…')}
    >
      <MoreHorizontal size={14} className="shrink-0" />
      {labelled && <span>{t('header.moreApps', 'More…')}</span>}
      {labelled && <ChevronDown size={12} className={cn('shrink-0 text-text-muted transition-transform', moreOpen && 'rotate-180')} />}
    </button>
  );

  const pill = (app: ConnectedApp, labelled: boolean) => {
    const isCurrent = isCurrentApp(app);
    return (
      <button
        key={`${app.appType}-${app.baseUrl}`}
        type="button"
        onClick={() => goApp(app)}
        className={cn(
          'flex items-center gap-2 py-1.5 rounded-md text-[12.5px] font-medium transition-colors shrink-0',
          labelled ? 'px-3' : 'px-1.5',
          isCurrent
            ? 'bg-bg-secondary text-text-primary font-semibold shadow-[0_1px_3px_rgb(46_52_64_/_0.1)]'
            : 'text-text-secondary hover:bg-bg-active hover:text-text-primary',
        )}
        title={app.name}
        aria-label={app.name}
      >
        <span className="w-2 h-2 rounded-full shrink-0" style={{ background: app.color || FALLBACK_APP_COLOR }} />
        {labelled && app.name}
      </button>
    );
  };

  const username = user?.username ?? '';
  const rawName = user?.displayName?.trim() || (username.startsWith('og_') ? username.slice(3) : username);
  const displayedUsername = anonUsername(rawName);

  return (
    <header className="relative flex h-13 shrink-0 items-center gap-3 bg-bg-secondary px-4" style={{ height: 52 }}>
      {/* Logo — always visible in the topbar so it stays accessible regardless
          of sidebar state (pinned, collapsed, floating). */}
      <Link to="/" className="flex items-center gap-2 shrink-0">
        <Logo className="h-8 w-auto max-w-[160px] object-contain" />
      </Link>

      {/* Tenant selector — sits left of the app switcher, preserving the
          context that gets carried across apps. */}
      <TenantSwitcher />

      {/* App switcher pills — the apps the user can actually reach (returned
          by /api/auth/connected-apps, ordered by Obligate). Flexible-width
          slot so its siblings can squeeze it: labelled pills when they fit,
          colour dots only (name in the tooltip) when they don't. */}
      {!isNativeApp ? (
        <>
          {/* No overflow-hidden here: it would clip the "More…" dropdown. */}
          <div ref={switcherWrapRef} className="ml-1 flex-1 min-w-0 flex items-center">
            <nav className="flex items-center gap-1 rounded-lg bg-bg-hover p-1">
              {mainApps.map(app => pill(app, !collapsed))}
              {moreApps.length > 0 && (
                <div ref={moreRef} className="relative">
                  {moreButton(!collapsed, true)}
                  {moreOpen && (
                    <div className="absolute left-0 top-9 z-50 w-56 max-w-[calc(100vw-1.5rem)] rounded-xl bg-bg-secondary shadow-2xl overflow-hidden">
                      <div className="px-3 py-2">
                        <p className="text-xs font-semibold text-text-muted uppercase tracking-wide">{t('header.otherApps', 'Other apps')}</p>
                      </div>
                      <div className="py-1 max-h-64 overflow-y-auto overscroll-contain">
                        {moreApps.map(app => (
                          <button
                            key={`${app.appType}-${app.baseUrl}`}
                            type="button"
                            onClick={() => { setMoreOpen(false); goApp(app); }}
                            className="w-full flex items-center gap-2 px-3 py-2 text-sm text-left text-text-primary transition-colors hover:bg-bg-hover"
                          >
                            <span className="h-2 w-2 rounded-full shrink-0" style={{ background: app.color || FALLBACK_APP_COLOR }} />
                            <span className="truncate">{app.name}</span>
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </nav>
          </div>
          {/* Hidden measurer: always the full-label version, off-screen, used
              only to know whether the labelled switcher would fit. */}
          <div
            ref={measureRef}
            aria-hidden
            className="absolute -z-10 opacity-0 pointer-events-none flex items-center gap-1 p-1"
            style={{ top: -9999, left: -9999 }}
          >
            {mainApps.map(app => pill(app, true))}
            {moreApps.length > 0 && moreButton(true, false)}
          </div>
        </>
      ) : (
        <div className="flex-1" />
      )}

      <div className="ml-auto flex items-center gap-3 shrink-0">
        {/* The bench installer, where Obliance puts its own download. Drawn
            only once the server has answered: a link when an installer is
            published; when none is, nothing for an operator and a disabled
            control saying why for a platform admin (see DownloadAppButton). */}
        <DownloadAppButton />

        {/* Socket connection status dot */}
        <button
          onClick={socketStatus !== 'connected' ? () => window.location.reload() : undefined}
          title={
            socketStatus === 'connected'    ? t('header.socketConnected')    :
            socketStatus === 'reconnecting' ? t('header.socketReconnecting') :
                                              t('header.socketDisconnected')
          }
          className={cn(
            'flex h-7 w-7 items-center justify-center rounded-md transition-opacity',
            socketStatus !== 'connected' && 'cursor-pointer hover:opacity-70',
            socketStatus === 'connected'  && 'cursor-default',
          )}
        >
          <span
            className={cn(
              'h-2 w-2 rounded-full transition-colors',
              socketStatus === 'connected'    && 'bg-green-500',
              socketStatus === 'reconnecting' && 'bg-amber-400 animate-pulse',
              socketStatus === 'disconnected' && 'bg-red-500 animate-pulse',
            )}
          />
        </button>

        {/* Notification Center */}
        <NotificationCenter />

        {user && (
          <>
            <div className="flex items-center gap-2 pl-1.5 pr-3 py-1 rounded-lg bg-bg-hover">
              <UserAvatar avatar={user.avatar} username={username} size={28} />
              <span className="text-[13px] font-medium text-text-primary">{displayedUsername}</span>
              <span className="text-[10px] font-mono uppercase tracking-wider text-accent pl-2 border-l border-border-light">
                {user.role}
              </span>
            </div>
            <button
              onClick={logout}
              title={t('nav.signOut')}
              className="flex h-7 w-7 items-center justify-center rounded-md text-text-muted hover:bg-bg-hover hover:text-text-primary transition-colors"
            >
              <LogOut size={15} />
            </button>
          </>
        )}
      </div>
    </header>
  );
}

