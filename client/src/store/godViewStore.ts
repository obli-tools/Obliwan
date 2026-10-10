import { create } from 'zustand';

/**
 * The master tenant's GOD VIEW, as the API reports it.
 *
 * The server decides it (a platform admin positioned on the master tenant —
 * server/src/utils/globalView.ts) and says so on every tenant-routed response
 * with the `X-Obliwan-God-View` header (`1` / `0`). The axios interceptor
 * (api/client.ts) copies it here; nothing on the client re-derives it from the
 * role or the tenant id, so a screen never shows a tenant column the server
 * did not fill.
 *
 * `filterTenantId` is the operator's tenant filter in the god view: the
 * interceptor adds it as `?filterTenantId=` to every request while the god
 * view is on, and every god-view list narrows to that tenant (the server
 * ignores it for anyone else). Kept per browser tab (sessionStorage).
 */
interface GodViewState {
  active: boolean;
  filterTenantId: number | null;
  setActive: (active: boolean) => void;
  setFilterTenantId: (tenantId: number | null) => void;
}

const FILTER_KEY = 'obliwan.godView.filterTenantId';

function readFilter(): number | null {
  try {
    const raw = sessionStorage.getItem(FILTER_KEY);
    const n = raw === null ? NaN : Number(raw);
    return Number.isInteger(n) && n > 0 ? n : null;
  } catch {
    return null;
  }
}

export const useGodViewStore = create<GodViewState>((set, get) => ({
  active: false,
  filterTenantId: readFilter(),
  setActive: (active) => {
    if (get().active !== active) set({ active });
  },
  setFilterTenantId: (tenantId) => {
    try {
      if (tenantId === null) sessionStorage.removeItem(FILTER_KEY);
      else sessionStorage.setItem(FILTER_KEY, String(tenantId));
    } catch {
      // per-tab convenience only
    }
    set({ filterTenantId: tenantId });
  },
}));

/** True while the API says this session is the master tenant's god view. */
export function useGodView(): boolean {
  return useGodViewStore((s) => s.active);
}
