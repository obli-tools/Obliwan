import crypto from 'node:crypto';

/**
 * The password of ObliWAN's own `obliwan` account, generated per device — the
 * ONE generator for its two writers: the bench compile
 * (bench/compile.service.ts, which re-exports it) and the `management_access`
 * job that creates the same account on a router in service
 * (change/managementAccess.service.ts). A module of its own so the job does
 * not have to load the bench compiler and everything it imports.
 *
 * 24 characters drawn from 57 ([A-Za-z0-9] minus the look-alikes I, O, l, 0
 * and 1), about 140 bits, and nothing RouterOS or the vault splice would have
 * to escape.
 */
export function generateAccountPassword(): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  let out = '';
  for (let i = 0; i < 24; i++) out += alphabet[crypto.randomInt(alphabet.length)];
  return out;
}
