import type { ObjectAccess } from '@obliwan/shared';

/**
 * Reads the `access` field the server puts on a device, site, SIM line, job,
 * rollout or drift payload (shared `ObjectAccess`, migration 087).
 *
 * One spelling, read in one place: anything that is not exactly 'rw' or 'ro'
 * is ABSENT (undefined), never 'rw'. A client then falls back to its own
 * permission map, or hides the button — it never invents a right.
 */
export function readAccess(v: unknown): ObjectAccess | undefined {
  return v === 'rw' || v === 'ro' ? v : undefined;
}

/** Spread helper: `{ ...accessField(raw.access) }` adds the key only when the server sent it. */
export function accessField(v: unknown): { access?: ObjectAccess } {
  const a = readAccess(v);
  return a ? { access: a } : {};
}
