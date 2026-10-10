import { PageTabs, type PageTab } from '@/components/common/PageTabs';
import { useNavModules } from './navModules';

/**
 * The module strip — the tab bar at the top of every module screen.
 *
 * ┌─ ONE COMPONENT, DRAWN ONCE, BY THE LAYOUT ───────────────────────────────┐
 * │ AppLayout draws it above every page, and it decides for itself whether   │
 * │ the page is a tab of a module (`resolveActiveNav().showStrip`). So no    │
 * │ page has to remember to mount it, and the strip and the sidebar read the │
 * │ same list through the same hook: a tab hidden from a viewer in one place │
 * │ is hidden in the other.                                                  │
 * │                                                                          │
 * │ It draws nothing on a detail page (`/devices/42`, `/mobile/lines/7`) or  │
 * │ a drill-down (`/plan`) — those keep their module lit in the sidebar and  │
 * │ their own header, as before — and nothing for a module the viewer sees   │
 * │ through a single tab (PageTabs: one tab is not a choice).                │
 * │                                                                          │
 * │ Second-level strips (Interfaces → Traffic / Thresholds, Organisation,    │
 * │ Settings) stay where they were, in their layouts, UNDER this one. The    │
 * │ 4G layout no longer draws its own: its tabs ARE this module's.           │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Sticky, so a long list scrolled to its bottom still says which module and
 * which tab it is, one click from its siblings.
 */
export function ModuleTabs() {
  const { modules, active } = useNavModules();
  if (!active.showStrip) return null;
  const mod = modules.find((m) => m.id === active.moduleId);
  if (!mod || mod.tabs.length < 2) return null;
  const tabs: PageTab[] = mod.tabs.map((tab) => ({
    to: tab.to,
    label: tab.label,
    end: tab.end,
    active: tab.to === active.tabTo,
  }));
  return (
    <div className="sticky top-0 z-20 flex shrink-0 items-center border-b border-border bg-bg-primary px-4">
      <span className="mr-2 hidden shrink-0 items-center gap-1.5 font-mono text-[10px] font-medium uppercase tracking-[0.12em] text-text-muted md:flex [&>svg]:h-3.5 [&>svg]:w-3.5">
        {mod.icon}
        {mod.label}
      </span>
      <PageTabs tabs={tabs} className="min-w-0 flex-1 border-b-0" />
    </div>
  );
}
