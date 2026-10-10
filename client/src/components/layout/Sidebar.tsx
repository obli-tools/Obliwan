import { useCallback, useEffect, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import {
  DndContext,
  PointerSensor,
  useSensor,
  useSensors,
  useDroppable,
  useDraggable,
  type DragEndEvent,
} from '@dnd-kit/core';
import {
  ChevronDown,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  GripVertical,
  LayoutDashboard,
  LogOut,
  Pin,
  PinOff,
  Plus,
  Router,
  Server,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { cn } from '@/utils/cn';
import { useAuthStore } from '@/store/authStore';
import { useGroupStore } from '@/store/groupStore';
import { useUiStore } from '@/store/uiStore';
import type { GroupTreeNode } from '@obliwan/shared';
import { CAPABILITIES } from '@obliwan/shared';
import { groupsApi } from '@/api/groups.api';
import { anonHostname, anonUsername } from '@/utils/anonymize';
import { UserAvatar } from '@/components/common/UserAvatar';
import { useDeviceStore } from '@/store/deviceStore';
import { PresenceDot } from '@/components/fleet/PresenceDot';
import { FleetTree } from '@/components/fleet/FleetTree';
import { useNavModules, type NavModuleDef } from './navModules';
import { moduleHome, searchNav } from './navModuleMatch';
import toast from 'react-hot-toast';
// ── localStorage helpers ─────────────────────────────────────────────────────
function usePersisted<T>(key: string, initial: T): [T, (v: T | ((prev: T) => T)) => void] {
  const [value, setValue] = useState<T>(() => {
    try {
      const stored = localStorage.getItem(key);
      return stored !== null ? (JSON.parse(stored) as T) : initial;
    } catch {
      return initial;
    }
  });
  const set = useCallback((v: T | ((prev: T) => T)) => {
    setValue(prev => {
      const next = typeof v === 'function' ? (v as (p: T) => T)(prev) : v;
      localStorage.setItem(key, JSON.stringify(next));
      return next;
    });
  }, [key]);
  return [value, set];
}
// ── Recursive group section ───────────────────────────────────────────────────
//
// The group tree now carries the devices filed under each group, each with
// its live PPP pastille. The dot is fed by `deviceStore.presence`, which the
// socket writes directly — the tree repaints on `wan:site:presence` without a
// refetch and without the fleet page being open. The sites → devices tree
// sits below, in <FleetTree />.
function GroupSection({ group, depth }: { group: GroupTreeNode; depth: number }) {
  const { t } = useTranslation();
  const location = useLocation();
  const [expanded, setExpanded] = usePersisted<boolean>(`sidebar:group-${group.id}-open`, true);
  const devices = useDeviceStore(s => s.devices);
  const livePresence = useDeviceStore(s => s.presence);
  const groupDevices = devices
    .filter(d => d.groupId === group.id)
    .sort((a, b) => a.name.localeCompare(b.name));
  const isGroupActive = location.pathname === `/group/${group.id}`;
  const hasContent = group.children.length > 0 || groupDevices.length > 0;
  const { setNodeRef: setDropRef, isOver } = useDroppable({
    id: `drop-group-${group.id}`,
    data: { type: 'group', groupId: group.id },
  });
  const { attributes, listeners, setNodeRef: setDragRef, isDragging } = useDraggable({
    id: `drag-group-${group.id}`,
    data: { type: 'group-drag', group },
  });
  return (
    <div
      ref={setDropRef}
      className={cn(
        'rounded-md transition-colors',
        isOver && 'ring-1 ring-accent bg-accent/10',
        isDragging && 'opacity-40',
      )}
    >
      <div
        className="flex items-center gap-0.5 group/row"
        style={{ paddingLeft: `${depth * 14}px` }}
      >
        <div
          ref={setDragRef}
          {...attributes}
          {...listeners}
          className="cursor-grab p-1 text-text-muted opacity-0 group-hover/row:opacity-50 hover:!opacity-100 shrink-0 transition-opacity"
          title={t('groups.dragReparent')}
        >
          <GripVertical size={10} />
        </div>
        <button
          onClick={() => setExpanded(v => !v)}
          className={cn(
            'p-0.5 text-text-muted hover:text-text-primary shrink-0 transition-colors',
            !hasContent && 'invisible pointer-events-none',
          )}
        >
          {expanded ? <ChevronDown size={10} /> : <ChevronRight size={10} />}
        </button>
        <Link
          to={`/group/${group.id}`}
          className={cn(
            'flex flex-1 items-center gap-2 rounded-md px-2 py-1 text-[13px] transition-colors',
            isGroupActive
              ? 'bg-bg-active text-text-primary'
              : 'text-text-secondary hover:bg-bg-hover hover:text-text-primary',
          )}
        >
          <Server size={13} className="shrink-0 text-text-muted" />
          <span className="truncate flex-1 font-medium">{anonHostname(group.name)}</span>
        </Link>
      </div>
      {expanded && groupDevices.map(device => {
        const presence = livePresence[device.id] ?? device.presence ?? null;
        const isDeviceActive = location.pathname === `/devices/${device.id}`;
        return (
          <Link
            key={device.id}
            to={`/devices/${device.id}`}
            style={{ paddingLeft: `${depth * 14 + 30}px` }}
            className={cn(
              'flex items-center gap-2 rounded-md py-1 pr-2 text-[12px] transition-colors',
              isDeviceActive
                ? 'bg-bg-active text-text-primary'
                : 'text-text-secondary hover:bg-bg-hover hover:text-text-primary',
            )}
          >
            <PresenceDot presence={presence} size={7} />
            <Router size={11} className="shrink-0 text-text-muted" />
            <span className="truncate flex-1">{anonHostname(device.name)}</span>
          </Link>
        );
      })}
      {expanded && group.children.map(child => (
        <GroupSection key={child.id} group={child} depth={depth + 1} />
      ))}
    </div>
  );
}
// ── Droppable root (un-parent target) ─────────────────────────────────────────
function DroppableRoot({ children }: { children: React.ReactNode }) {
  const { setNodeRef, isOver } = useDroppable({
    id: 'drop-group-root',
    data: { type: 'group', groupId: null },
  });
  return (
    <div
      ref={setNodeRef}
      className={cn('rounded-md transition-colors', isOver && 'ring-1 ring-accent bg-accent/10')}
    >
      {children}
    </div>
  );
}
// ── Nav modules ──────────────────────────────────────────────────────────────
/**
 * ┌─ ONE ENTRY PER MODULE ───────────────────────────────────────────────────┐
 * │ Thirty-five rows under seven headings was not a menu, it was a list to   │
 * │ be searched. The headings became the entries: one per module (Parc,      │
 * │ Raccordement, Configuration, Changements, 4G / SIM, Supervision,         │
 * │ Administration), and every screen that was a row is a TAB of its module, │
 * │ drawn at the top of the page by `ModuleTabs`. The list, its gates and    │
 * │ the "which one is lit" rule live in `navModules.tsx` /                   │
 * │ `navModuleMatch.ts`, read by this menu and by the strip alike.           │
 * │                                                                          │
 * │ An entry can be UNFOLDED to list its tabs here as well — one click to    │
 * │ any screen for whoever wants it — and the fold is remembered per module. │
 * │ Folded by default: unfolding everything would rebuild the long list.     │
 * │                                                                          │
 * │ The old arrival override ("the section you arrive in opens for the       │
 * │ visit") is gone with the sections: it existed because a folded heading  │
 * │ HID the current page's own entry. A module entry is never hidden by a    │
 * │ fold — only its tab rows are — so the lit row is always on screen.       │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
function ModuleEntry({
  mod,
  isActive,
  activeTabTo,
}: {
  mod: NavModuleDef;
  isActive: boolean;
  activeTabTo: string;
}) {
  const { t } = useTranslation();
  const [open, setOpen] = usePersisted<boolean>(`sidebar:module-${mod.id}`, false);
  // A module seen through a single tab has nothing to unfold.
  const foldable = mod.tabs.length > 1;
  return (
    <div>
      <div className="group/mod flex items-center">
        <Link
          to={moduleHome(mod)}
          className={cn(
            'flex min-w-0 flex-1 items-center gap-3 rounded-md px-3 py-2 text-[14px] transition-colors',
            isActive
              ? 'bg-bg-active text-text-primary'
              : 'text-text-secondary hover:bg-bg-hover hover:text-text-primary',
          )}
        >
          {mod.icon}
          <span className="truncate">{mod.label}</span>
        </Link>
        {foldable && (
          <button
            onClick={() => setOpen(v => !v)}
            aria-expanded={open}
            title={open ? t('nav.hideTabs') : t('nav.showTabs')}
            className="ml-0.5 shrink-0 rounded p-1 text-text-muted transition-colors hover:bg-bg-hover hover:text-text-primary"
          >
            <ChevronDown
              size={13}
              className={cn('transition-transform duration-200', !open && '-rotate-90')}
            />
          </button>
        )}
      </div>
      {foldable && open && (
        <nav className="mb-1 ml-5 border-l border-border pl-2">
          {mod.tabs.map(tab => (
            <Link
              key={tab.to}
              to={tab.to}
              className={cn(
                'flex items-center gap-2 rounded-md px-2 py-1.5 text-[13px] transition-colors',
                isActive && tab.to === activeTabTo
                  ? 'bg-bg-active text-text-primary'
                  : 'text-text-secondary hover:bg-bg-hover hover:text-text-primary',
              )}
            >
              <span className="shrink-0 text-text-muted">{tab.icon}</span>
              <span className="truncate">{tab.label}</span>
            </Link>
          ))}
        </nav>
      )}
    </div>
  );
}
// ── Main Sidebar ──────────────────────────────────────────────────────────────
export function Sidebar() {
  const { t } = useTranslation();
  const location = useLocation();
  const navigate = useNavigate();
  const { user, isAdmin, hasCapability } = useAuthStore();
  // The modules THIS viewer may open (a tab they cannot reach is dropped, a
  // module left empty goes with it), and the one the current page belongs to.
  const { modules, active } = useNavModules();
  const {
    sidebarFloating,
    toggleSidebarFloating,
    sidebarCollapsed,
    toggleSidebarCollapsed,
  } = useUiStore();
  const { tree, fetchTree } = useGroupStore();
  const [search, setSearch] = useState('');
  const admin = isAdmin();
  const canManageGroups = admin || hasCapability(CAPABILITIES.GROUPS_MANAGE);
  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 8 } }),
  );
  useEffect(() => {
    void fetchTree();
  }, [fetchTree]);
  const handleGroupDragEnd = useCallback(
    async (event: DragEndEvent) => {
      if (!canManageGroups) return; // read-only members: no drag-to-move
      const { active: dragged, over } = event;
      if (!over) return;
      const dragData = dragged.data.current;
      const dropData = over.data.current;
      if (dragData?.type === 'group-drag' && dropData?.type === 'group') {
        const group = dragData.group as GroupTreeNode;
        const targetGroupId = dropData.groupId as number | null;
        if (group.id === targetGroupId) return;
        try {
          await groupsApi.move(group.id, targetGroupId);
          void fetchTree();
          toast.success(t('groups.moved', { defaultValue: 'Group moved' }));
        } catch {
          toast.error(t('groups.moveFailed', { defaultValue: 'Failed to move group' }));
        }
      }
    },
    [fetchTree, canManageGroups, t],
  );
  // The dashboard belongs to no module and sits above them all.
  const dashboardLabel = t('nav.dashboard');
  const dashboardActive = location.pathname === '/';
  // The search box matches a module by its name, a tab by its label, and the
  // screens of a second-level strip by theirs (`searchNav`). A search
  // FLATTENS: each hit is a row of its own, "Module › Tab", linking to that
  // very tab — typing "notif" lands on Notifications, not on Administration.
  const query = search.trim().toLowerCase();
  const searchHits = searchNav(modules, search, active, location.pathname);
  const dashboardShown = !query || dashboardLabel.toLowerCase().includes(query);
  const renderGroupTree = () => (
    <DndContext sensors={sensors} onDragEnd={handleGroupDragEnd}>
      <div className="mt-2 pt-2 border-t border-border">
        <div className="px-2 py-1.5 flex items-center gap-2 text-[11px] font-mono font-medium text-text-muted uppercase tracking-[0.12em]">
          <Server size={12} />
          {t('nav.groups')}
        </div>
        <DroppableRoot>
          {tree.length === 0 ? (
            <div className="px-2 py-2 text-[12px] text-text-muted">
              {t('groups.empty', { defaultValue: 'No groups yet' })}
            </div>
          ) : (
            tree.map(group => <GroupSection key={group.id} group={group} depth={0} />)
          )}
        </DroppableRoot>
      </div>
    </DndContext>
  );
  // ── Collapsed mode (Obli Design v1) — 64 px icon-only column ─────────────
  if (sidebarCollapsed) {
    // One icon per module: the strip at the top of the page carries the tabs.
    const iconEntries = [
      { key: 'dashboard', to: '/', label: dashboardLabel, icon: <LayoutDashboard size={18} />, isActive: dashboardActive },
      ...modules.map(m => ({ key: m.id, to: moduleHome(m), label: m.label, icon: m.icon, isActive: m.id === active.moduleId })),
    ];
    return (
      <aside className="flex h-full w-16 shrink-0 flex-col bg-bg-secondary">
        <div className="flex h-12 shrink-0 items-center justify-center">
          <button
            onClick={toggleSidebarCollapsed}
            title={t('nav.expandSidebar', 'Expand sidebar')}
            className="rounded-md p-1.5 text-text-muted transition-colors hover:bg-bg-hover hover:text-text-primary"
          >
            <ChevronsRight size={16} />
          </button>
        </div>
        <nav className="flex-1 overflow-y-auto px-2 pt-3 space-y-1">
          {iconEntries.map(entry => (
            <Link
              key={entry.key}
              to={entry.to}
              title={entry.label}
              className={cn(
                'relative flex h-10 w-full items-center justify-center rounded-md transition-colors',
                entry.isActive
                  ? 'bg-accent/12 text-accent'
                  : 'text-text-muted hover:bg-bg-hover hover:text-text-primary',
              )}
            >
              {entry.icon}
            </Link>
          ))}
        </nav>
        <div className="p-2 space-y-1">
          <Link
            to="/profile"
            title={anonUsername(user?.displayName || (user?.username?.startsWith('og_') ? user.username.slice(3) : user?.username))}
            className={cn(
              'flex h-10 w-full items-center justify-center rounded-md transition-colors',
              location.pathname === '/profile'
                ? 'bg-bg-active text-text-primary'
                : 'text-text-secondary hover:bg-bg-hover hover:text-text-primary',
            )}
          >
            <UserAvatar avatar={user?.avatar} username={user?.username ?? '?'} size={24} />
          </Link>
          <button
            onClick={() => useAuthStore.getState().logout()}
            title={t('nav.signOut')}
            className="flex h-10 w-full items-center justify-center rounded-md text-text-muted transition-colors hover:bg-bg-hover hover:text-text-primary"
          >
            <LogOut size={18} />
          </button>
        </div>
      </aside>
    );
  }
  // ── Expanded mode ───────────────────────────────────────────────────────────
  const moduleIcon = (moduleId: string) => modules.find(m => m.id === moduleId)?.icon;
  return (
    <aside className="flex h-full w-full flex-col bg-bg-secondary">
      {/* Sidebar head — collapse + float/pin toggles only. The logo and
          tenant selector live in the topbar (Header.tsx) so they remain
          visible when the sidebar is collapsed or floating. */}
      <div className="flex h-9 shrink-0 items-center justify-end px-3 pt-2">
        <div className="flex items-center gap-1">
          {!sidebarFloating && (
            <button
              onClick={toggleSidebarCollapsed}
              title={t('nav.collapseSidebar', 'Collapse sidebar')}
              className="rounded p-1.5 text-text-muted transition-colors hover:bg-bg-hover hover:text-text-primary"
            >
              <ChevronsLeft size={15} />
            </button>
          )}
          <button
            onClick={toggleSidebarFloating}
            title={sidebarFloating ? t('nav.pinSidebar', 'Pin sidebar') : t('nav.floatSidebar', 'Float sidebar (auto-hide)')}
            className={cn(
              'p-1.5 rounded transition-colors',
              sidebarFloating
                ? 'text-accent hover:text-accent hover:bg-accent/10'
                : 'text-text-muted hover:text-text-primary hover:bg-bg-hover',
            )}
          >
            {sidebarFloating ? <PinOff size={15} /> : <Pin size={15} />}
          </button>
        </div>
      </div>
      {/* ┌─ ADD A DEVICE — the first thing an operator needs, where Obliance
              puts it ────────────────────────────────────────────────────────┐
          It is in the SIDEBAR and not on the devices page on purpose: adding a
          box is not something you do while already looking at the list, it is
          how you START. Obliance puts its "Ajouter un agent" pill here for the
          same reason, and muscle memory across the suite is worth more than a
          locally clever placement.

          Same capability as the form it opens — DEVICE_WRITE. A button that
          leads to a 403 is worse than no button.                              */}
      {(admin || hasCapability(CAPABILITIES.DEVICE_WRITE)) && (
        <div className="px-3 pt-2">
          <button
            onClick={() => navigate('/devices?add=1')}
            className="flex w-full items-center justify-center gap-2 rounded-md bg-accent/12 px-3 py-2 text-[13px] font-medium text-accent transition-colors hover:bg-accent/20"
          >
            <Plus size={15} />
            {t('nav.addDevice', { defaultValue: 'Add a device' })}
          </button>
        </div>
      )}

      {/* Search */}
      <div className="px-3 py-2.5">
        <input
          type="text"
          placeholder={t('common.search')}
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="w-full rounded-md bg-bg-tertiary px-3 py-2 text-[13px] text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent"
        />
      </div>
      {/* Main nav + group tree */}
      <div className="flex-1 overflow-y-auto px-2 min-h-0">
        {dashboardShown && (
          <nav>
            <Link
              to="/"
              className={cn(
                'flex items-center gap-3 rounded-md px-3 py-2 text-[14px] transition-colors',
                dashboardActive
                  ? 'bg-bg-active text-text-primary'
                  : 'text-text-secondary hover:bg-bg-hover hover:text-text-primary',
              )}
            >
              <LayoutDashboard size={18} />
              {dashboardLabel}
            </Link>
          </nav>
        )}
        {query ? (
          <nav>
            {searchHits.map(hit => (
              <Link
                key={`${hit.moduleId}:${hit.to}:${hit.label}`}
                to={hit.to}
                className={cn(
                  'flex items-center gap-3 rounded-md px-3 py-2 text-[14px] transition-colors',
                  hit.active
                    ? 'bg-bg-active text-text-primary'
                    : 'text-text-secondary hover:bg-bg-hover hover:text-text-primary',
                )}
              >
                {moduleIcon(hit.moduleId)}
                <span className="truncate">{hit.label}</span>
              </Link>
            ))}
          </nav>
        ) : (
          <nav className="space-y-0.5">
            {modules.map(m => (
              <ModuleEntry
                key={m.id}
                mod={m}
                isActive={m.id === active.moduleId}
                activeTabTo={active.tabTo}
              />
            ))}
          </nav>
        )}
        {renderGroupTree()}
        {(admin || hasCapability(CAPABILITIES.DEVICE_READ)) && <FleetTree />}
      </div>
      {/* User section */}
      <div className="border-t border-border p-2">
        <Link
          to="/profile"
          className={cn(
            'flex items-center gap-2.5 rounded-md px-2 py-1.5 transition-colors',
            location.pathname === '/profile'
              ? 'bg-accent/10'
              : 'hover:bg-bg-hover',
          )}
        >
          <UserAvatar avatar={user?.avatar} username={user?.username ?? '?'} size={20} />
          <div className="min-w-0 flex-1">
            <div className="truncate text-[13px] font-medium text-text-primary">
              {anonUsername(user?.displayName || (user?.username?.startsWith('og_') ? user.username.slice(3) : user?.username))}
            </div>
            <div className="truncate font-mono text-[10px] text-text-muted">
              {(user?.username?.startsWith('og_') ? user.username.slice(3) : user?.username) ?? ''} · {user?.role ?? ''}
            </div>
          </div>
        </Link>
        <button
          onClick={() => useAuthStore.getState().logout()}
          className="flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm text-text-secondary transition-colors hover:bg-bg-hover hover:text-text-primary"
        >
          <LogOut size={18} />
          {t('nav.signOut')}
        </button>
      </div>
    </aside>
  );
}
