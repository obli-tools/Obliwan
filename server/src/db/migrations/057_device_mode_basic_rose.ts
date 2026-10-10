import type { Knex } from 'knex';

/**
 * `devices.device_mode` accepts the two RouterOS modes 033 did not know:
 * `basic` and `rose`.
 *
 * MikroTik's "Device-mode" page documents home, basic, advanced ("previously
 * called enterprise") and rose. 033 allowed home, advanced and enterprise;
 * `asRouterOsDeviceMode()` (shared/src/deviceMode.ts) now narrows to all five,
 * and both writers of the column store the narrowed mode — `recordDeviceMode()`
 * through the driver's parse, and the bench's `deviceModeColumns()`. Without
 * this, the CHECK would refuse the write that records a `basic` or `rose`
 * unit's reading.
 *
 * Knowing the mode infers nothing new: `deadmanReadiness()` still derives a
 * verdict from `home` alone, and every other mode needs its `scheduler` flag
 * printed.
 *
 * An IN list of literals, for 033's reason: no `?` for knex to rewrite.
 *
 * down: a row holding one of the two modes would violate the narrower CHECK,
 * so its `device_mode` goes back to NULL first — what 033's vocabulary stored
 * for those units (`asRouterOsDeviceMode()` narrowed them to null). The rest of
 * the reading stays: the flags, `device_mode_raw` (which keeps the mode as
 * printed) and `device_mode_observed_at`.
 */
export async function up(knex: Knex): Promise<void> {
  await knex.schema.raw('ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_device_mode_chk');
  await knex.schema.raw(
    'ALTER TABLE devices ADD CONSTRAINT devices_device_mode_chk ' +
      "CHECK (device_mode IS NULL OR device_mode IN ('home', 'basic', 'advanced', 'enterprise', 'rose'))",
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex('devices').whereIn('device_mode', ['basic', 'rose']).update({ device_mode: null });
  await knex.schema.raw('ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_device_mode_chk');
  await knex.schema.raw(
    'ALTER TABLE devices ADD CONSTRAINT devices_device_mode_chk ' +
      "CHECK (device_mode IS NULL OR device_mode IN ('home', 'advanced', 'enterprise'))",
  );
}
