import { NavLink } from 'react-router-dom';
import { cn } from '@/utils/cn';

/**
 * The horizontal tab strip that sits at the top of a grouped screen.
 *
 * ┌─ TABS ARE ROUTES, NOT COMPONENT STATE ───────────────────────────────────┐
 * │ Every tab is a real URL rendered through <NavLink>, so a tabbed family    │
 * │ keeps everything a flat list of menu entries gave us: a tab is            │
 * │ bookmarkable, the browser's back button walks between tabs, and a         │
 * │ deep link still lands where it was aimed.                                 │
 * │                                                                          │
 * │ That last point is load-bearing and was the stated objection to grouping  │
 * │ the mobile screens in the first place — `Sidebar.tsx` argued for four     │
 * │ separate entries because "the low-balance alert deep-links to             │
 * │ /mobile/lines/:id". It still does. A tab strip built on local state       │
 * │ WOULD have broken that link, which is presumably what the comment had in  │
 * │ mind; one built on routes does not.                                      │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * `end` exists for the index tab only. Without it, `/mobile` matches every
 * `/mobile/*` path and the first tab stays lit alongside the real one — the
 * same parent-is-its-child's-prefix defect that lit two sidebar entries at
 * once. Here it is expressed with NavLink's own flag rather than re-derived.
 */
export interface PageTab {
  to: string;
  label: string;
  /** Match this path exactly. Set on the tab whose path is the family root. */
  end?: boolean;
  /**
   * The caller's own verdict, overriding NavLink's path match. The module
   * strip (`ModuleTabs`) passes it: one of its tabs owns sibling URLs
   * (Organisation is lit on /manage/groups) and one carries a query string
   * (/variables?tab=instance), neither of which NavLink can judge.
   */
  active?: boolean;
}

export function PageTabs({ tabs, className }: { tabs: PageTab[]; className?: string }) {
  // One tab is not a choice. Rendering a lone tab would suggest siblings that
  // a capability check has hidden, which is worse than no strip at all.
  if (tabs.length < 2) return null;

  return (
    <nav
      className={cn(
        'flex items-center gap-1 overflow-x-auto border-b border-border',
        className,
      )}
    >
      {tabs.map((tab) => (
        <NavLink
          key={tab.to}
          to={tab.to}
          end={tab.end}
          className={({ isActive }) =>
            cn(
              'relative whitespace-nowrap px-4 py-2.5 text-[13px] transition-colors',
              'after:absolute after:inset-x-2 after:-bottom-px after:h-0.5 after:rounded-full',
              (tab.active ?? isActive)
                ? 'text-text-primary after:bg-accent'
                : 'text-text-secondary hover:text-text-primary after:bg-transparent',
            )
          }
        >
          {tab.label}
        </NavLink>
      ))}
    </nav>
  );
}
