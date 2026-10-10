/**
 * ObliWAN — the identity alternates of a device whose RENAME is in flight or
 * unsettled (the `site_rename` change job, services/change/siteRename.service.ts).
 *
 * A rename changes two of the three attributes the identity rule compares — the management
 * tunnel's PPP login and the /system identity — on the router and on the
 * device row, and the two cannot change at the same instant. Between them, and
 * for as long as a rename stays `unsettled` (the router did not come back
 * within the bound and nobody knows which names it holds), every identity
 * check would read a PROVEN mismatch and quarantine the device: the very box
 * the job is renaming, during the one job that knows exactly why it differs.
 *
 * So, for ONE device, while its LATEST `site_rename_jobs` row has no outcome
 * yet or the outcome `unsettled`, each of the two attributes may match the
 * record OR either name of that row's frozen pair — the old one and the new
 * one, nothing else. The serial is never widened and still decides when it is
 * recorded; a box answering a name outside the pair is a mismatch and is
 * quarantined exactly as before. Once the latest rename is `renamed`,
 * `reverted`, `present`, `refused` or `failed`, the record alone decides
 * again.
 *
 * Read on every identity check (no cache: a stale "rename in flight" would be
 * a widened identity check that outlived its reason). One indexed query
 * (`site_rename_jobs_device_idx`). A database without the table (a build
 * running against migrations before 088) answers "none".
 */

import { db } from '../../db';

export interface IdentityAlternates {
  ppp_username: string[];
  system_identity: string[];
}

export async function renameIdentityAlternates(deviceId: number): Promise<IdentityAlternates | null> {
  let row: { outcome: string | null; from_login: string; to_login: string; from_identity: string; to_identity: string } | undefined;
  try {
    row = (await db('site_rename_jobs')
      .where({ device_id: deviceId })
      .orderBy('job_id', 'desc')
      .first('outcome', 'from_login', 'to_login', 'from_identity', 'to_identity')) as typeof row;
  } catch (err) {
    // 42P01: the table does not exist (pre-088). Anything else is a real
    // failure of the identity path and must not pass silently.
    if ((err as { code?: string }).code === '42P01') return null;
    throw err;
  }
  if (!row) return null;
  if (row.outcome !== null && row.outcome !== 'unsettled') return null;
  return {
    ppp_username: [row.from_login, row.to_login],
    system_identity: [row.from_identity, row.to_identity],
  };
}
