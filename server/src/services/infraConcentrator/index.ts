/**
 * ObliWAN — each customer's infrastructure VPN concentrator (migration 074).
 * See types.ts (the driver contract), store.ts (declarations, vault, account
 * registry), routerosChr.driver.ts (real), opnsense.driver.ts (connection test
 * only) and job.service.ts (the `infra_account` change job).
 */

export * from './types';
export {
  createInfraConcentrator,
  deleteInfraConcentrator,
  getInfraConcentratorRow,
  getInfraConcentratorView,
  listInfraConcentrators,
  listSiteAccounts,
  recordTestResult,
  updateInfraConcentrator,
  type InfraConcentratorInput,
} from './store';
export { resetInfraCredentialDeps, setInfraCredentialDeps, type InfraCredentialDeps, type SiteValues } from './credentials';
export { driverFor } from './drivers';
export {
  INFRA_ACCOUNT_NO_APPLY_OUTCOME,
  INFRA_ACCOUNT_NO_BACKUP,
  INFRA_ACCOUNT_NO_DEADMAN,
  InfraAccountJobError,
  enqueueInfraAccount,
  getInfraAccountJobState,
  infraAccountGuard,
  previewInfraAccount,
  readInfraAccount,
  runInfraAccountApply,
  runInfraAccountVerify,
  settleInfraAccount,
} from './job.service';

import type { InfraDriverResult } from '@obliwan/shared';
import { driverFor } from './drivers';
import { getInfraConcentratorRow, recordTestResult } from './store';

/** Test a declared concentrator and record the verdict on its row. */
export async function testInfraConcentrator(id: number): Promise<InfraDriverResult & { fingerprint?: string | null }> {
  const c = await getInfraConcentratorRow(id);
  const result = await driverFor(c.kind).testConnection(c);
  await recordTestResult(id, result.ok, result.message);
  return result;
}
