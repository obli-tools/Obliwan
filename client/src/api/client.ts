import axios from 'axios';
import { GOD_VIEW_RESPONSE_HEADER, GOD_VIEW_TENANT_FILTER_PARAM } from '@obliwan/shared';
import { useGodViewStore } from '@/store/godViewStore';

// ObliTools (cross-site iframe / WebView2 shell): Chrome blocks all cookies for cross-site
// iframes, so we use X-Auth-Token header instead. The token = req.sessionID, stored in
// sessionStorage after login and sent on every request via the interceptor below.
export const isInObliTools = (() => {
  try { return window !== window.top; } catch { return true; }
})() || !!(window as unknown as { __obliwan_is_native_app?: boolean }).__obliwan_is_native_app;

export const OBLITOOLS_TOKEN_KEY = 'oblitools_auth_token';

const apiClient = axios.create({
  baseURL: '/api',
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor: inject X-Auth-Token header when running inside ObliTools.
apiClient.interceptors.request.use((config) => {
  if (isInObliTools) {
    const token = sessionStorage.getItem(OBLITOOLS_TOKEN_KEY);
    if (token) {
      config.headers['X-Auth-Token'] = token;
    }
  }
  // God view (store/godViewStore.ts): the operator's tenant filter rides on
  // every request while the server says the session is the god view. The
  // server ignores it for anyone else. A request that names its own tenant
  // (a form listing one workspace's inventory) keeps it: the global filter
  // only fills the parameter in.
  const { active, filterTenantId } = useGodViewStore.getState();
  if (active && filterTenantId !== null) {
    config.params = { [GOD_VIEW_TENANT_FILTER_PARAM]: filterTenantId, ...(config.params ?? {}) };
  }
  return config;
});

/** Copies the server's god-view verdict (header) into the store. */
function noteGodView(headers: unknown): void {
  const h = headers as { get?: (k: string) => unknown } & Record<string, unknown> | undefined;
  if (!h) return;
  const raw = typeof h.get === 'function' ? h.get(GOD_VIEW_RESPONSE_HEADER) : h[GOD_VIEW_RESPONSE_HEADER];
  if (raw === '1') useGodViewStore.getState().setActive(true);
  else if (raw === '0') useGodViewStore.getState().setActive(false);
}

// Response interceptor: handle 401
apiClient.interceptors.response.use(
  (response) => {
    noteGodView(response.headers);
    return response;
  },
  (error) => {
    noteGodView(error.response?.headers);
    if (error.response?.status === 401) {
      if (isInObliTools) {
        // In ObliTools: clear the stale token but don't hard-redirect — let React Router handle it.
        sessionStorage.removeItem(OBLITOOLS_TOKEN_KEY);
      } else {
        // Normal browser: redirect to login if session expired — but not on SSO pages
        const { pathname } = window.location;
        if (pathname !== '/login' && pathname !== '/auth/foreign') {
          window.location.href = '/login';
        }
      }
    }
    return Promise.reject(error);
  },
);

export default apiClient;
