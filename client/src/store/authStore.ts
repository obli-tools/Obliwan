import { create } from 'zustand';
import type { User, UserPermissions, PermissionLevel, Capability, ObjectAccess } from '@obliwan/shared';
import { authApi, type LoginResult } from '../api/auth.api';
import { connectSocket, disconnectSocket } from '../socket/socketClient';
import { useLiveAlertsStore } from './liveAlertsStore';
import { setLanguage } from '../i18n';
import { useTenantStore } from './tenantStore';
import { useGroupStore } from './groupStore';
import { applyTheme } from '../utils/theme';

function syncPreferencesToStore(user: User) {
  const prefs = user.preferences;
  if (prefs) {
    useLiveAlertsStore.getState().setEnabled(prefs.toastEnabled ?? true);
    useLiveAlertsStore.getState().setPosition(prefs.toastPosition ?? 'bottom-right');
    if (prefs.preferredTheme) {
      applyTheme(prefs.preferredTheme);
    }
  }
  if (user.preferredLanguage) {
    setLanguage(user.preferredLanguage);
  }
}

interface AuthState {
  user: User | null;
  permissions: UserPermissions | null;
  requires2faSetup: boolean;
  isLoading: boolean;
  isInitialized: boolean;

  login: (username: string, password: string) => Promise<LoginResult>;
  logout: () => Promise<void>;
  checkSession: () => Promise<void>;
  refreshPermissions: () => Promise<void>;

  // Convenience permission checkers
  isAdmin: () => boolean;
  /** Feature capability check (admin ⇒ always true). */
  hasCapability: (capability: Capability) => boolean;
  canCreate: () => boolean;
  /**
   * Whether the caller may write THIS object, from the `access` the server put
   * on its payload (device, site, SIM line, job, rollout, drift run / finding;
   * shared `ObjectAccess`). A platform admin always may. An object that carries
   * no `access` (a socket payload, an older server) is NOT writable here: the
   * safe side is a hidden button, never a button that answers 403.
   */
  canWriteObject: (obj?: { access?: ObjectAccess } | null) => boolean;
  /**
   * The caller's level on a device: the server's `access` when the payload has
   * one, else the `permissions` map (device grant, group grant, or the
   * `ungrouped:0` grant for a device filed under no group).
   */
  deviceAccess: (device: { id: number; groupId: number | null; access?: ObjectAccess }) => PermissionLevel | null;
  /**
   * Whether the caller may file a new device somewhere — Obliance's
   * can-create: 'rw' on the ungrouped scope or on some group. Pass the target
   * to be exact: `null` = no group (the ungrouped grant), a number = that group.
   */
  canPlaceDevice: (groupId?: number | null) => boolean;
  /** Whether the caller may create or import sites (rw on every site, `permissions.canCreateSites`). */
  canCreateSites: () => boolean;
  canWriteDevice: (deviceId: number, groupId: number | null) => boolean;
  canWriteGroup: (groupId: number) => boolean;
  getDevicePermission: (deviceId: number, groupId: number | null) => PermissionLevel | null;
  getGroupPermission: (groupId: number) => PermissionLevel | null;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  permissions: null,
  requires2faSetup: false,
  isLoading: false,
  isInitialized: false,

  login: async (username: string, password: string) => {
    set({ isLoading: true });
    try {
      const result = await authApi.login({ username, password });

      // 2FA required — don't set user yet, return the challenge to caller
      if (result.requires2fa) {
        set({ isLoading: false });
        return result;
      }

      const user = result.user;
      set({ user, isLoading: false });
      syncPreferencesToStore(user);
      connectSocket(user.id);
      useTenantStore.getState().fetchTenants();
      useLiveAlertsStore.getState().fetchAlerts();
      // Fetch permissions in the background; failure is non-fatal here.
      authApi.me()
        .then(({ permissions, user: fullUser, requires2faSetup, currentTenantId }) => {
          set({ permissions, requires2faSetup: requires2faSetup ?? false });
          syncPreferencesToStore(fullUser);
          if (currentTenantId != null) {
            useTenantStore.setState({ currentTenantId });
          }
        })
        .catch(() => { /* non-critical — permissions will load on next checkSession */ });
      return result;
    } catch (err) {
      set({ isLoading: false });
      const axiosErr = err as { response?: { data?: { error?: string }; status?: number }; message?: string };
      const serverMessage = axiosErr?.response?.data?.error;
      const status = axiosErr?.response?.status;
      if (status === 429) {
        throw new Error(serverMessage ?? 'Too many login attempts, please try again later');
      } else if (status === 401) {
        throw new Error(serverMessage ?? 'Invalid username or password');
      } else if (serverMessage) {
        throw new Error(serverMessage);
      } else {
        throw new Error(axiosErr?.message ?? 'Unable to connect to the server');
      }
    }
  },

  logout: async () => {
    // Fetch Obligate logout URL BEFORE destroying local state
    let obligateLogoutUrl: string | null = null;
    try {
      const res = await fetch('/api/auth/sso-logout-url', { credentials: 'include' });
      const data = await res.json() as { success: boolean; data: string | null };
      if (data.success && data.data) obligateLogoutUrl = data.data;
    } catch { /* ignore */ }

    try {
      await authApi.logout();
    } finally {
      disconnectSocket();
      set({ user: null, permissions: null, requires2faSetup: false });
    }

    if (obligateLogoutUrl) {
      window.location.href = obligateLogoutUrl;
    }
  },

  checkSession: async () => {
    try {
      const { user, permissions, requires2faSetup, currentTenantId } = await authApi.me();
      set({ user, permissions, requires2faSetup: requires2faSetup ?? false, isInitialized: true });
      syncPreferencesToStore(user);
      connectSocket(user.id, currentTenantId ?? undefined);
      useTenantStore.getState().fetchTenants();
      useLiveAlertsStore.getState().fetchAlerts();
      useGroupStore.getState().fetchTree();
      if (currentTenantId != null) {
        useTenantStore.setState({ currentTenantId });
      }
    } catch {
      set({ user: null, permissions: null, requires2faSetup: false, isInitialized: true });
    }
  },

  refreshPermissions: async () => {
    try {
      const permissions = await authApi.getPermissions();
      set({ permissions });
    } catch {
      // Ignore errors
    }
  },

  isAdmin: () => get().user?.role === 'admin',

  hasCapability: (capability: Capability) => {
    const { user, permissions } = get();
    if (!user) return false;
    if (user.role === 'admin') return true;
    return permissions?.capabilities?.includes(capability) ?? false;
  },

  canCreate: () => {
    const { user, permissions } = get();
    if (!user) return false;
    if (user.role === 'admin') return true;
    return permissions?.canCreate ?? false;
  },

  canWriteObject: (obj) => {
    const { user } = get();
    if (!user) return false;
    if (user.role === 'admin') return true;
    return obj?.access === 'rw';
  },

  deviceAccess: (device) => {
    const { user } = get();
    if (!user) return null;
    if (user.role === 'admin') return 'rw';
    if (device.access) return device.access;
    return get().getDevicePermission(device.id, device.groupId);
  },

  canPlaceDevice: (groupId) => {
    const { user, permissions } = get();
    if (!user) return false;
    if (user.role === 'admin') return true;
    if (!permissions) return false;
    const map = permissions.permissions;
    if (groupId === null) return map['ungrouped:0'] === 'rw';
    if (typeof groupId === 'number') return map[`group:${groupId}`] === 'rw';
    return map['ungrouped:0'] === 'rw'
      || Object.keys(map).some((k) => k.startsWith('group:') && map[k] === 'rw');
  },

  canCreateSites: () => {
    const { user, permissions } = get();
    if (!user) return false;
    if (user.role === 'admin') return true;
    // Absent on an older server, where a tenant admin was tenant-wide: the
    // server's own refusal stays the judge.
    return permissions?.canCreateSites !== false;
  },

  canWriteDevice: (deviceId: number, groupId: number | null) => {
    const { user, permissions } = get();
    if (!user) return false;
    if (user.role === 'admin') return true;
    if (!permissions) return false;

    // Check direct device permission
    const devicePerm = permissions.permissions[`device:${deviceId}`];
    if (devicePerm === 'rw') return true;

    // Check group permission
    if (groupId !== null) {
      const groupPerm = permissions.permissions[`group:${groupId}`];
      if (groupPerm === 'rw') return true;
    } else if (permissions.permissions['ungrouped:0'] === 'rw') {
      // A device filed under no group is covered by the ungrouped grant.
      return true;
    }

    return false;
  },

  canWriteGroup: (groupId: number) => {
    const { user, permissions } = get();
    if (!user) return false;
    if (user.role === 'admin') return true;
    if (!permissions) return false;
    return permissions.permissions[`group:${groupId}`] === 'rw';
  },

  getDevicePermission: (deviceId: number, groupId: number | null) => {
    const { user, permissions } = get();
    if (!user) return null;
    if (user.role === 'admin') return 'rw';
    if (!permissions) return null;

    const devicePerm = permissions.permissions[`device:${deviceId}`];
    const groupPerm = groupId !== null
      ? permissions.permissions[`group:${groupId}`]
      : permissions.permissions['ungrouped:0']; // no group: the ungrouped grant

    if (devicePerm === 'rw' || groupPerm === 'rw') return 'rw';
    if (devicePerm === 'ro' || groupPerm === 'ro') return 'ro';
    return null;
  },

  getGroupPermission: (groupId: number) => {
    const { user, permissions } = get();
    if (!user) return null;
    if (user.role === 'admin') return 'rw';
    if (!permissions) return null;
    return permissions.permissions[`group:${groupId}`] ?? null;
  },
}));
