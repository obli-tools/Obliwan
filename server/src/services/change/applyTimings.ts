/**
 * ObliWAN — the two clocks of an armed change, read from the settings.
 *
 * `commit_confirm_timeout` (how long the on-box dead-man waits before it
 * restores the preflight backup) and `apply_soak_seconds` (how long the change
 * is watched, net still armed, before the dead-man is removed) were shown in
 * Settings and read by nothing: the queue path armed a hard-coded 600 s and
 * soaked `OBLIWAN_SOAK_MS`. They are now resolved PER DEVICE — default →
 * workspace → group chain → device — once, when the job reaches the point of
 * no return, and both halves of the job use that ONE resolution: the soak in
 * `apply.service.ts` and the arming in `changeExecutor.armDeadman()` (it rides
 * on the exec context). Two separate reads could straddle an operator's edit
 * and arm a window computed for a different soak.
 *
 * ┌─ AN INCOHERENT PAIR IS REFUSED BEFORE THE BACKUP, NEVER CLAMPED ─────────┐
 * │ The dead-man must outlive everything that happens inside it — reconnect,  │
 * │ soak, disarm — or a change that WORKED is reverted by our own clock while │
 * │ we are still watching it. That is `assertTimingsCoherent()` in             │
 * │ safeApply.service.ts, and the queue path never called it: with the two    │
 * │ numbers now in an operator's hands (60 s and 300 s are both legal), it    │
 * │ has to. The check runs BEFORE the preflight backup, so a refused job has │
 * │ spent nothing on the device. Stretching the window instead would arm a   │
 * │ net nobody configured.                                                   │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Statically importable by `apply.service.ts` on purpose: it imports nothing
 * from `safeApply.service.ts`, the module the queue reaches only dynamically.
 */

import { SETTINGS_KEYS } from '@obliwan/shared';
import { db } from '../../db';
import { deviceSettingNumbers, envInteger, tenantSettingNumber } from '../settingsRead';

export interface ApplyWindow {
  /** The on-box dead-man's interval, in seconds. */
  deadmanSeconds: number;
  /** How long the change is watched before the dead-man is removed. */
  soakMs: number;
}

/**
 * The disarm budget inside the window, mirrored from
 * `SAFE_APPLY_DEFAULTS.disarmAttempts × disarmBackoffMs` (6 × 3 s) for the same
 * reason `apply.service.ts` mirrors the reconnect constants: this module must
 * not import safeApply statically.
 */
export const DISARM_BUDGET_MS = 6 * 3_000;

/**
 * `OBLIWAN_SOAK_MS`, the soak's only knob before the setting was read, in
 * SECONDS so it can sit under the setting as its fallback (`settingsRead.ts`):
 * it applies only while nothing is stored anywhere in the device's chain.
 */
function soakEnvFallbackSec(): number | null {
  const ms = envInteger('OBLIWAN_SOAK_MS');
  return ms === null ? null : Math.round(ms / 1000);
}

/** Resolve the window for one device of one tenant. */
export async function resolveApplyWindow(tenantId: number, deviceId: number): Promise<ApplyWindow> {
  const device = await db('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first<{ group_id: number | null } | undefined>('group_id');
  const s = await deviceSettingNumbers(
    tenantId,
    deviceId,
    device?.group_id ?? null,
    [SETTINGS_KEYS.COMMIT_CONFIRM_TIMEOUT, SETTINGS_KEYS.APPLY_SOAK_SECONDS],
    { [SETTINGS_KEYS.APPLY_SOAK_SECONDS]: soakEnvFallbackSec() },
  );
  return {
    deadmanSeconds: s[SETTINGS_KEYS.COMMIT_CONFIRM_TIMEOUT].value,
    soakMs: s[SETTINGS_KEYS.APPLY_SOAK_SECONDS].value * 1000,
  };
}

/**
 * The soak a device with no group or device override gets in this workspace —
 * what `GET /changes/config` reports. A device's own value may differ; the job
 * trace states the one it actually soaked for.
 */
export async function workspaceSoakMs(tenantId: number): Promise<number> {
  const s = await tenantSettingNumber(tenantId, SETTINGS_KEYS.APPLY_SOAK_SECONDS, soakEnvFallbackSec());
  return s.value * 1000;
}

/**
 * Why this window cannot hold the sequence it has to hold, or null when it
 * can. Pure. `reconnectBudgetMs` is the caller's: the wait before the first
 * reconnection plus every attempt's interval.
 */
export function applyWindowProblem(window: ApplyWindow, reconnectBudgetMs: number): string | null {
  const neededMs = reconnectBudgetMs + window.soakMs + DISARM_BUDGET_MS;
  if (window.deadmanSeconds * 1000 > neededMs) return null;
  return (
    `the commit-confirm timeout (${window.deadmanSeconds}s) is not longer than the ` +
    `${Math.ceil(neededMs / 1000)}s that reconnecting, a ${Math.round(window.soakMs / 1000)}s soak ` +
    'and disarming need, so the dead-man would revert this change while it is still being ' +
    'watched. Raise the commit-confirm timeout or shorten the post-apply soak for this device.'
  );
}
