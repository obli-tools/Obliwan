/**
 * Quick Setup Tenant — the allocation rule as a file.
 *
 * The file is the body PUT /allocation/tenants/:id/policy takes, with pools
 * and the concentrator designated by NAME as an alternative to their ids: a
 * name is portable between installations, an id is not, and an export writes
 * names. `resolvePolicyRefs` turns names into ids and NOTHING else — every
 * judgement of the rule itself stays the allocator's (`validatePolicyInput`,
 * then `checkPolicy` / `upsertPolicy` under the allocation lock).
 *
 * Pure given its inputs (the pools and the concentrators this tenant may
 * use), so the harness runs it on fixtures.
 */

import { POLICY_FILE_FORMAT, type SetupIssue } from '@obliwan/shared';
import { issue } from './issues';

/** The top-level fields a rule file may carry: the API body's, the two name
 *  references, and the format tag. Anything else is refused by name — a
 *  misspelt `derivedValues` silently dropped would save a rule without them. */
export const POLICY_FILE_FIELDS: ReadonlySet<string> = new Set([
  'format', 'tunnel', 'lan', 'pppLoginTemplate', 'systemIdentityTemplate', 'pppPasswordMode',
  'derived', 'pppProfile', 'concentratorId', 'concentratorName', 'siteCodeFormat',
]);

export interface PoolRef {
  id: number;
  name: string;
  purpose: string;
}

export interface ConcentratorRef {
  id: number;
  name: string;
  tenantId: number;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

const lower = (s: string): string => s.trim().toLowerCase();

/**
 * Resolve the name references of a rule file into the API body. `input` is
 * null when any reference failed (the issues say which); otherwise it is the
 * body `checkPolicy` / `upsertPolicy` take, with ids only.
 *
 * A name is matched case-insensitively. Two matches are ambiguous (the
 * operator gives the id instead); a pool of the wrong purpose is named as
 * such rather than left to the allocator's id-based sentence; an id given
 * WITH a name must designate the same entry, since a file that says two
 * different things is not one this setup may pick between.
 */
export function resolvePolicyRefs(
  policy: unknown,
  pools: readonly PoolRef[],
  concentrators: readonly ConcentratorRef[],
): { input: Record<string, unknown> | null; issues: SetupIssue[] } {
  const issues: SetupIssue[] = [];
  if (!isRecord(policy)) {
    issues.push(issue('POLICY_FIELD_UNKNOWN', 'allocationPolicy', { field: '(body)' }));
    return { input: null, issues };
  }
  for (const k of Object.keys(policy)) {
    if (!POLICY_FILE_FIELDS.has(k)) issues.push(issue('POLICY_FIELD_UNKNOWN', 'allocationPolicy', { field: k }));
  }
  if (policy.format !== undefined && policy.format !== POLICY_FILE_FORMAT) {
    issues.push(issue('POLICY_FIELD_UNKNOWN', 'allocationPolicy', { field: 'format' }));
  }

  let ok = issues.length === 0;
  const refFail = (field: string, ref: string, problem: 'unknown' | 'ambiguous' | 'wrongPurpose' | 'mismatch'): void => {
    ok = false;
    issues.push(issue('POLICY_REF', 'allocationPolicy', { field, ref, problem }));
  };

  /** A rule ({ poolId?, poolName?, … }) with its pool name resolved. */
  const resolveRule = (raw: unknown, field: string, purpose: 'tunnel' | 'lan'): unknown => {
    if (!isRecord(raw) || raw.poolName === undefined) return raw;
    const { poolName, ...rest } = raw;
    if (typeof poolName !== 'string' || poolName.trim() === '') {
      refFail(`${field}.poolName`, String(poolName ?? ''), 'unknown');
      return rest;
    }
    const matches = pools.filter((p) => lower(p.name) === lower(poolName));
    if (matches.length === 0) {
      refFail(`${field}.poolName`, poolName, 'unknown');
      return rest;
    }
    if (matches.length > 1) {
      refFail(`${field}.poolName`, poolName, 'ambiguous');
      return rest;
    }
    const pool = matches[0];
    if (pool.purpose !== purpose) {
      refFail(`${field}.poolName`, poolName, 'wrongPurpose');
      return rest;
    }
    if (rest.poolId !== undefined && rest.poolId !== null && Number(rest.poolId) !== pool.id) {
      refFail(`${field}.poolName`, poolName, 'mismatch');
      return rest;
    }
    return { ...rest, poolId: pool.id };
  };

  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(policy)) {
    if (!POLICY_FILE_FIELDS.has(k) || k === 'format' || k === 'concentratorName') continue;
    out[k] = v;
  }
  if ('tunnel' in policy) out.tunnel = resolveRule(policy.tunnel, 'tunnel', 'tunnel');
  if ('lan' in policy) out.lan = resolveRule(policy.lan, 'lan', 'lan');

  if (policy.concentratorName !== undefined) {
    const name = policy.concentratorName;
    if (typeof name !== 'string' || name.trim() === '') {
      refFail('concentratorName', String(name ?? ''), 'unknown');
    } else {
      const matches = concentrators.filter((c) => lower(c.name) === lower(name));
      if (matches.length === 0) refFail('concentratorName', name, 'unknown');
      else if (matches.length > 1) refFail('concentratorName', name, 'ambiguous');
      else if (
        policy.concentratorId !== undefined && policy.concentratorId !== null &&
        Number(policy.concentratorId) !== matches[0].id
      ) {
        refFail('concentratorName', name, 'mismatch');
      } else out.concentratorId = matches[0].id;
    }
  }

  return { input: ok ? out : null, issues };
}
