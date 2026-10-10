/**
 * ObliWAN — reading a numeric setting at the scope its consumer can honour.
 *
 * `settings.service.ts` resolves the whole tree (default → workspace → group
 * chain → device) and hands back every key with its source. What each consumer
 * then did with that answer used to be written out again at each call site —
 * `Number(...)`, a clamp or not, a fallback or not — and a call site that
 * forgot the clamp read whatever a hand-written row held. This file is that
 * last step, once:
 *
 *   deviceSettingNumbers    a consumer that knows the device (presence, the
 *                           SNMP poller, a change job): the full chain.
 *   tenantSettingNumber     a consumer that knows the workspace and no device
 *                           (the audit ledger is a per-tenant chain).
 *   platformSettingNumber   a consumer that is one per INSTALLATION (the change
 *                           queue, the partition maintenance): the MAIN
 *                           workspace's value — the same convention the SIM
 *                           sweep uses (`services/sim/index.ts`), never
 *                           "whichever tenant answered first".
 *
 * ┌─ AN ENVIRONMENT VARIABLE IS A FALLBACK, NEVER AN OVERRIDE ────────────────┐
 * │ Two settings had an env variable that did the job before the setting was │
 * │ read (`SNMP_POLL_INTERVAL_SEC`, `OBLIWAN_CHANGE_CONCURRENCY`, and the     │
 * │ soak's `OBLIWAN_SOAK_MS`). A deployment that tuned one must not have its │
 * │ tuning silently undone by this change, so the variable still applies —  │
 * │ but only where NOTHING is stored in the settings tree. The moment an     │
 * │ operator writes the setting, the screen is the truth. The reverse order  │
 * │ would show a value in Settings that the process ignores, which is the    │
 * │ defect these settings were wired to close.                               │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Every value leaves clamped to its definition: a row written by hand, or one
 * stored before a definition's bounds moved, is read as the nearest legal
 * value, never as itself.
 */

import {
  MASTER_TENANT_ID,
  HARDCODED_DEFAULTS,
  clampSetting,
  type ResolvedSettings,
  type SettingsKey,
} from '@obliwan/shared';
import { settingsService } from './settings.service';

export interface SettingRead {
  value: number;
  /** True when the value came from a row in `settings` at some level of the
   *  tree, false when it is the env fallback or the hardcoded default. */
  stored: boolean;
}

/**
 * THE rule, pure: a stored number (clamped) wins; otherwise the env fallback
 * when the deployment set one; otherwise the hardcoded default. Exported for
 * the harness, and so the rule is written down in exactly one place.
 */
export function effectiveSettingNumber(
  key: SettingsKey,
  stored: unknown,
  envFallback: number | null = null,
): SettingRead {
  const n = typeof stored === 'number' ? stored : typeof stored === 'string' && stored.trim() !== '' ? Number(stored) : NaN;
  if (Number.isFinite(n)) return { value: clampSetting(key, n), stored: true };
  if (envFallback !== null && Number.isFinite(envFallback)) {
    return { value: clampSetting(key, envFallback), stored: false };
  }
  return { value: HARDCODED_DEFAULTS[key], stored: false };
}

/**
 * The full chain for one device. One resolution for all the keys asked: the
 * tree is three queries whatever the number of keys.
 */
export async function deviceSettingNumbers<K extends SettingsKey>(
  tenantId: number,
  deviceId: number,
  groupId: number | null,
  keys: readonly K[],
  envFallbacks: Partial<Record<K, number | null>> = {},
): Promise<Record<K, SettingRead>> {
  const resolved = await settingsService.resolveForDevice(tenantId, deviceId, groupId);
  return settingNumbersFrom(resolved, keys, envFallbacks);
}

/**
 * The same, from a tree a caller has already resolved — so a caller that
 * needs other keys of that tree too does not resolve it twice. Pure.
 */
export function settingNumbersFrom<K extends SettingsKey>(
  resolved: Partial<ResolvedSettings>,
  keys: readonly K[],
  envFallbacks: Partial<Record<K, number | null>> = {},
): Record<K, SettingRead> {
  const out = {} as Record<K, SettingRead>;
  for (const key of keys) {
    const entry = resolved[key];
    const stored = entry && entry.source !== 'default' ? entry.value : undefined;
    out[key] = effectiveSettingNumber(key, stored, envFallbacks[key] ?? null);
  }
  return out;
}

/** The workspace (`global` scope) value of one tenant, else — for any tenant
 *  but the master — the Default workspace's (settings.service header). */
export async function tenantSettingNumber(
  tenantId: number,
  key: SettingsKey,
  envFallback: number | null = null,
): Promise<SettingRead> {
  const overrides = await settingsService.getByScope(tenantId, 'global', null);
  if (overrides[key] === undefined && tenantId !== MASTER_TENANT_ID) {
    const general = await settingsService.getByScope(MASTER_TENANT_ID, 'global', null);
    return effectiveSettingNumber(key, general[key], envFallback);
  }
  return effectiveSettingNumber(key, overrides[key], envFallback);
}

/**
 * The installation's value: the main workspace's. A read that FAILS answers
 * the fallback rather than throwing — every caller is a background loop for
 * which "use the default this tick" is safer than "stop".
 */
export async function platformSettingNumber(
  key: SettingsKey,
  envFallback: number | null = null,
): Promise<SettingRead> {
  try {
    return await tenantSettingNumber(MASTER_TENANT_ID, key, envFallback);
  } catch {
    return effectiveSettingNumber(key, undefined, envFallback);
  }
}

/**
 * An integer env variable, or null when it is unset, blank or not a number.
 * `Number(' ')` is 0, not NaN (a known trap): trimmed first.
 */
export function envInteger(name: string): number | null {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === '') return null;
  const n = Number(raw.trim());
  return Number.isFinite(n) ? Math.trunc(n) : null;
}
