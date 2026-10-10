import type { Capability } from '@obliwan/shared';

/**
 * The navigation, cut into MODULES — pure data and pure functions, no React.
 *
 * ┌─ ONE ENTRY PER MODULE, ONE TAB PER SCREEN ───────────────────────────────┐
 * │ The sidebar used to carry some thirty-five rows under seven headings.    │
 * │ It now carries one entry per module (Parc, Raccordement, Configuration,  │
 * │ Changements, 4G / SIM, Supervision, Administration), and every screen    │
 * │ that was a row is a TAB of its module — drawn at the top of the page by  │
 * │ `ModuleTabs`, and listed under the module's entry when that entry is     │
 * │ unfolded. Tabs are routes (see `PageTabs`): no URL changed, so every     │
 * │ bookmark and every deep link still lands where it was aimed.             │
 * │                                                                          │
 * │ The Sidebar and the strip read the SAME list through these functions, so │
 * │ a tab is offered to exactly the same people in both places, and the two  │
 * │ can never disagree about which tab is the current one.                   │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Kept free of React, icons and i18n so the matching rules can be exercised
 * on their own: they decide which entry is lit and whether a page shows a
 * strip, and a wrong answer there is a screen that looks unreachable.
 */

/** Who is looking — the two checks every tab gate is written in. */
export interface NavViewer {
  isAdmin: boolean;
  hasCapability: (capability: Capability) => boolean;
}

/** A searchable sub-screen of a tab: the second-level strips (Interfaces, Organisation, Settings). */
export interface NavSubTab {
  to: string;
  label: string;
}

export interface NavTab<Icon = unknown> {
  /** The tab's URL. May carry a query string (`/variables?tab=instance`). */
  to: string;
  label: string;
  icon?: Icon;
  /**
   * Handed to the strip's NavLink only. Resolution does not need it: a deeper
   * path under `/mobile` is won by the longer sibling that owns it, and one no
   * tab owns keeps the module lit as a drill-down, with no strip.
   */
  end?: boolean;
  /**
   * Sibling TAB-LEVEL URLs this tab owns: its own second-level strip
   * (`/interfaces/thresholds`, `/manage/groups`, `/manage/notifications`…).
   * They light the tab AND show the module strip.
   */
  alsoMatch?: string[];
  /**
   * Pages that belong to this tab without being one of its screens
   * (`/plan` under Changes). They light the tab in the sidebar but draw no
   * module strip, exactly like a detail page (`/devices/42`) does.
   */
  drillDowns?: string[];
  /** The second-level tabs behind this one, offered to the search box only. */
  subTabs?: NavSubTab[];
  adminOnly?: boolean;
  /** Visible to non-admins holding this capability (admins always see it). */
  capability?: Capability;
  /** Visible to non-admins holding ANY of these (with or instead of `capability`). */
  anyCapability?: Capability[];
}

export interface NavModule<Icon = unknown> {
  id: string;
  label: string;
  icon?: Icon;
  /** A gate every tab of the module inherits on top of its own (4G: SIM_READ). */
  capability?: Capability;
  tabs: NavTab<Icon>[];
}

function canSee(gate: Pick<NavTab, 'adminOnly' | 'capability' | 'anyCapability'>, viewer: NavViewer): boolean {
  if (gate.adminOnly && !viewer.isAdmin) return false;
  if (viewer.isAdmin) return true;
  if (gate.capability && !viewer.hasCapability(gate.capability)) return false;
  if (gate.anyCapability && !gate.anyCapability.some((c) => viewer.hasCapability(c))) return false;
  return true;
}

/**
 * The modules as THIS viewer sees them: every tab they may not open is
 * dropped (a visible tab leading to a 403 is worse than one never offered),
 * and a module left with no tab disappears with it.
 */
export function visibleModules<Icon>(modules: NavModule<Icon>[], viewer: NavViewer): NavModule<Icon>[] {
  return modules
    .map((m) => ({
      ...m,
      tabs: m.tabs.filter((tab) => canSee({ capability: m.capability }, viewer) && canSee(tab, viewer)),
    }))
    .filter((m) => m.tabs.length > 0);
}

/** Where a module's entry leads: its first tab the viewer may open. */
export function moduleHome(module: NavModule<unknown>): string {
  return module.tabs[0]?.to ?? '/';
}

function splitUrl(url: string): { path: string; query: URLSearchParams } {
  const i = url.indexOf('?');
  return i < 0
    ? { path: url, query: new URLSearchParams() }
    : { path: url.slice(0, i), query: new URLSearchParams(url.slice(i + 1)) };
}

/**
 * The score of one candidate URL against the current location, or -1.
 *
 * A candidate matches its own path, and any path below it
 * (`/devices` owns `/devices/42`: a detail page belongs to the tab its list
 * lives in). A candidate carrying a query string matches only when every
 * parameter it names is present with that value, and then outranks the same
 * path without one: `/variables?tab=instance` is the Administration tab,
 * `/variables` on any other tab is Configuration's.
 */
function score(candidate: string, pathname: string, search: URLSearchParams): number {
  const { path, query } = splitUrl(candidate);
  const matches = pathname === path || (path !== '/' && pathname.startsWith(path + '/'));
  if (!matches) return -1;
  let params = 0;
  for (const [k, v] of query) {
    if (search.get(k) !== v) return -1;
    params += 1;
  }
  return path.length * 10 + params;
}

export interface ActiveNav {
  /** The lit module, or '' when the page belongs to none (dashboard, profile…). */
  moduleId: string;
  /** The lit tab's own `to`, or ''. */
  tabTo: string;
  /** True when the page IS a tab-level screen of that module, i.e. it draws the module strip. */
  showStrip: boolean;
}

/**
 * ONE entry is lit, never two: the most specific match wins.
 *
 * A parent is its children's own prefix (`/mobile` against `/mobile/report`),
 * so each tab cannot decide on its own — every candidate is scored by the
 * length of the path it matched, over the viewer's VISIBLE modules and never
 * over a search-filtered list (typing in the search box must not change which
 * entry is the current one).
 *
 * `showStrip` is false on a detail page (`/devices/42`, `/mobile/lines/7`) and
 * on a drill-down (`/plan`): those keep the module lit in the sidebar but draw
 * no strip, as they did before modules existed — a single line is a drill-down,
 * not a tab.
 */
export function resolveActiveNav(
  modules: NavModule<unknown>[],
  pathname: string,
  searchString: string,
): ActiveNav {
  const search = new URLSearchParams(searchString);
  let best: ActiveNav & { score: number } = { moduleId: '', tabTo: '', showStrip: false, score: -1 };
  for (const m of modules) {
    for (const tab of m.tabs) {
      const candidates: Array<{ url: string; strip: boolean }> = [
        { url: tab.to, strip: true },
        ...(tab.alsoMatch ?? []).map((url) => ({ url, strip: true })),
        ...(tab.drillDowns ?? []).map((url) => ({ url, strip: false })),
      ];
      for (const c of candidates) {
        const s = score(c.url, pathname, search);
        if (s > best.score) {
          best = {
            moduleId: m.id,
            tabTo: tab.to,
            // A tab-level candidate draws the strip only on its own path: a
            // deeper path under it is a detail page.
            showStrip: c.strip && splitUrl(c.url).path === pathname,
            score: s,
          };
        }
      }
    }
  }
  return { moduleId: best.moduleId, tabTo: best.tabTo, showStrip: best.showStrip };
}

export interface NavSearchHit {
  /** Row label: "Module", "Module › Tab" or "Module › Tab › Sub-tab". */
  label: string;
  to: string;
  moduleId: string;
  active: boolean;
}

/**
 * The flat search result. A module matches by its own name, a tab by its
 * label, and the screens of a second-level strip by theirs — they were menu
 * entries of their own once (Notifications, Thresholds…) and typing their name
 * must still find them. A hit on a tab is a row of its own that links to that
 * tab and says why it matched; a URL already listed is never listed twice.
 * Trimmed, so a stray space is not a query that matches every two-word label.
 */
export function searchNav(
  modules: NavModule<unknown>[],
  rawQuery: string,
  active: ActiveNav,
  pathname: string,
): NavSearchHit[] {
  const query = rawQuery.trim().toLowerCase();
  if (!query) return [];
  const hit = (label: string) => label.toLowerCase().includes(query);
  const out: NavSearchHit[] = [];
  for (const m of modules) {
    const seen = new Set<string>();
    if (hit(m.label)) {
      const to = moduleHome(m);
      seen.add(to);
      out.push({ label: m.label, to, moduleId: m.id, active: active.moduleId === m.id });
    }
    for (const tab of m.tabs) {
      if (hit(tab.label) && !seen.has(tab.to)) {
        seen.add(tab.to);
        out.push({
          label: `${m.label} › ${tab.label}`,
          to: tab.to,
          moduleId: m.id,
          active: active.moduleId === m.id && active.tabTo === tab.to,
        });
      }
      for (const sub of tab.subTabs ?? []) {
        if (hit(sub.label) && !seen.has(sub.to)) {
          seen.add(sub.to);
          out.push({
            label: `${m.label} › ${tab.label} › ${sub.label}`,
            to: sub.to,
            moduleId: m.id,
            active: pathname === splitUrl(sub.to).path,
          });
        }
      }
    }
  }
  return out;
}
