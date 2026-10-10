/**
 * ObliWAN — WHO CARRIES A STORE'S FIXED LINE (migration 095).
 *
 * The facts the provider inference reads (shared/src/operatorOutage.ts
 * `inferFixedProvider`, best evidence first: declared on the site → PPPoE
 * realm → ASN → /24 prefix), loaded for many devices at once, and the MEMORY
 * of the fixed line those last two read.
 *
 * ┌─ THE MEMORY, AND THE ONE INVERSION IT EXISTS TO PREVENT ──────────────────┐
 * │ `devices.wan_public_ip` is the PPP caller-id: the address the store       │
 * │ dials the concentrator FROM. On the fixed line that is the fixed          │
 * │ provider's address; on the 4G backup it is the MOBILE operator's. During │
 * │ an outage every affected store is on its backup — so the current address │
 * │ would label an Orange outage "Bouygues Telecom" on fourteen stores at     │
 * │ once. The ASN and prefix evidence therefore read ONLY `device_fixed_link`,│
 * │ written while the store was demonstrably on its fixed link:               │
 * │  · its active default route was read (fresh, < ROUTE_FRESH_MS) on a NAMED │
 * │    NON-cellular interface,                                               │
 * │  · that reading was taken during the CURRENT PPP session (a reading from │
 * │    before the session says nothing about the path it was dialled over),  │
 * │  · and no route transition was recorded from ROUTE_FRESH_MS before the   │
 * │    session started until now: the session was opened, and has lived,    │
 * │    while the route was on the fixed line — a session opened during a 4G  │
 * │    episode and kept after the failback is not taken. The margin is the   │
 * │    health check's reading lag.                                           │
 * │ The row is never cleared by an outage; it moves only when another         │
 * │ fixed-line address is confirmed the same way.                            │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE ASN, AND WHO IS ASKED ───────────────────────────────────────────────┐
 * │ First the operator's OFFLINE table (weather/asn.service.ts: a             │
 * │ longest-prefix match, nothing leaves the installation); then, only when   │
 * │ a platform administrator allowed it (`asn_lookup_enabled`, fleet/         │
 * │ asn.service.ts), the third-party lookup — bounded per sweep, and a miss   │
 * │ is not retried for six hours. A resolved ASN is stored with the address  │
 * │ and kept: it is a remembered fact about the fixed line, and reading it   │
 * │ again discloses nothing.                                                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * Reads only, towards the routers: nothing here dials anything.
 */

import {
  WAN1_VARIABLE_KEYS,
  classifyIpScope,
  inferFixedProvider,
  type FixedProviderFacts,
  type FixedProviderInference,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { attributeAddress } from '../weather/asn.service';
import { asnLookupEnabled, lookupAsn } from './asn.service';
import { isCellularIface, ROUTE_FRESH_MS } from './backup4g.service';

/** A memory row older than this is re-confirmed (observed_at moves). */
const MEMORY_REFRESH_MS = 3600_000;
/** Third-party ASN lookups per sweep, at most (asked one by one); the
 *  offline table is read for every row. */
export const MAX_ASN_RESOLUTIONS_PER_SWEEP = 20;
/** Remembered addresses considered per sweep. */
const MAX_ASN_ROWS_PER_SWEEP = 1000;
/** A resolution that answered nothing is not retried before this. */
const ASN_RETRY_MS = 6 * 3600_000;
/** A resolved ASN older than this is resolved again. */
const ASN_MAX_AGE_MS = 30 * 86_400_000;

const asnTried = new Map<string, number>();

/** Addresses that may be a fixed line's: public, or carrier-grade NAT (a
 *  fixed line behind CGNAT still names its provider by its block). */
export function isMemorableAddress(ip: string | null | undefined): boolean {
  const scope = classifyIpScope(ip);
  return scope === 'public' || scope === 'cgnat';
}

export interface MemoryRefreshOutcome {
  /** Rows written: a new address, or one re-confirmed after an hour. */
  written: number;
  /** Rows whose ADDRESS changed (or appeared). */
  changed: number;
  asnResolved: number;
}

/**
 * Confirm the fixed-line address of every store that is on its fixed link
 * now (the rule of the header), then resolve a bounded number of missing
 * ASNs. Leader-only (the sweep calls it).
 */
export async function refreshFixedLinkMemory(now: Date = new Date()): Promise<MemoryRefreshOutcome> {
  const { rows } = (await db.raw(
    `SELECT d.id, d.tenant_id, d.default_route_iface,
            host(s.caller_ip) AS caller_ip,
            host(f.public_ip) AS memory_ip, f.observed_at AS memory_observed_at
       FROM devices d
       JOIN ppp_sessions s ON s.device_id = d.id AND s.ended_at IS NULL
       LEFT JOIN device_fixed_link f ON f.device_id = d.id
      WHERE d.status = 'active' AND d.role <> 'concentrator'
        AND d.default_route_iface IS NOT NULL
        AND d.default_route_observed_at > ?
        AND d.default_route_observed_at >= s.started_at
        AND s.caller_ip IS NOT NULL
        AND NOT EXISTS (
          SELECT 1 FROM device_route_transitions t
           WHERE t.device_id = d.id AND t.at >= s.started_at - make_interval(secs => ?))`,
    [new Date(now.getTime() - ROUTE_FRESH_MS), ROUTE_FRESH_MS / 1000],
  )) as {
    rows: Array<{
      id: number; tenant_id: number; default_route_iface: string; caller_ip: string | null;
      memory_ip: string | null; memory_observed_at: Date | null;
    }>;
  };
  let written = 0;
  let changed = 0;
  for (const r of rows) {
    if (isCellularIface(r.default_route_iface)) continue;
    if (!r.caller_ip || !isMemorableAddress(r.caller_ip)) continue;
    const same = r.memory_ip === r.caller_ip;
    if (same && r.memory_observed_at && now.getTime() - new Date(r.memory_observed_at).getTime() < MEMORY_REFRESH_MS) {
      continue;
    }
    if (same) {
      await db('device_fixed_link').where({ device_id: r.id }).update({ observed_at: now });
    } else {
      // A new address: its ASN is the new address's, to be resolved again.
      await db('device_fixed_link')
        .insert({
          device_id: r.id, tenant_id: r.tenant_id, public_ip: r.caller_ip,
          first_seen_at: now, observed_at: now, asn: null, asn_name: null, asn_source: null, asn_at: null,
        })
        .onConflict('device_id')
        .merge(['tenant_id', 'public_ip', 'first_seen_at', 'observed_at', 'asn', 'asn_name', 'asn_source', 'asn_at']);
      changed += 1;
    }
    written += 1;
  }
  const asnResolved = await resolveMissingAsns(now).catch((err: unknown) => {
    logger.warn({ err }, 'Fixed-line ASN resolution failed; the prefix stays the evidence');
    return 0;
  });
  return { written, changed, asnResolved };
}

/** Resolve the ASN of remembered addresses that have none (bounded). */
export async function resolveMissingAsns(now: Date = new Date()): Promise<number> {
  const rows = (await db('device_fixed_link')
    .where((q) => {
      void q.whereNull('asn').orWhere('asn_at', '<', new Date(now.getTime() - ASN_MAX_AGE_MS));
    })
    .orderBy('observed_at', 'desc')
    .limit(MAX_ASN_ROWS_PER_SWEEP)
    .select('device_id', db.raw('host(public_ip) AS ip'))) as Array<{ device_id: number; ip: string }>;
  let resolved = 0;
  let attempts = 0;
  const lookupAllowed = await asnLookupEnabled();
  for (const r of rows) {
    const tried = asnTried.get(r.ip);
    if (tried !== undefined && now.getTime() - tried < ASN_RETRY_MS) continue;
    let asn: { asn: number; name: string | null; source: 'local_table' | 'lookup' } | null = null;
    // The offline table first: a local read, never capped.
    const local = await attributeAddress(r.ip).catch(() => null);
    if (local?.asn) asn = { asn: local.asn.asn, name: local.asn.asOrg, source: 'local_table' };
    else if (lookupAllowed && attempts < MAX_ASN_RESOLUTIONS_PER_SWEEP) {
      // The third party: bounded per sweep.
      attempts += 1;
      const found = await lookupAsn(r.ip).catch(() => null);
      if (found) asn = { asn: found.asn, name: found.name, source: 'lookup' };
    } else if (lookupAllowed) {
      continue; // over this sweep's budget: next sweep, not "tried"
    }
    if (!asn) {
      asnTried.set(r.ip, now.getTime());
      continue;
    }
    asnTried.delete(r.ip);
    // Conditional on the address: a row re-addressed meanwhile keeps its own.
    const n = await db('device_fixed_link')
      .where({ device_id: r.device_id })
      .whereRaw('host(public_ip) = ?', [r.ip])
      .update({ asn: asn.asn, asn_name: asn.name ? asn.name.slice(0, 200) : null, asn_source: asn.source, asn_at: now });
    if (n > 0) resolved += 1;
  }
  return resolved;
}

/** For harnesses: forget the "tried and found nothing" memory. */
export function resetAsnAttempts(): void {
  asnTried.clear();
}

// ============================================================================
// The facts, for many stores at once
// ============================================================================

export interface ProviderSubject {
  deviceId: number;
  tenantId: number;
  siteId: number | null;
  /** `sites.fixed_provider` when the caller already read it; undefined = read here. */
  declared?: string | null;
}

/**
 * The provider of each store, with its evidence. Three queries whatever the
 * number of stores: the sites' declarations (when not given), the WAN1
 * variables (device level wins over site level, secrets never read), the
 * fixed-line memory.
 */
export async function providersFor(
  subjects: readonly ProviderSubject[],
): Promise<Map<number, FixedProviderInference>> {
  const facts = await providerFactsFor(subjects);
  const out = new Map<number, FixedProviderInference>();
  for (const [id, f] of facts) out.set(id, inferFixedProvider(f));
  return out;
}

export async function providerFactsFor(
  subjects: readonly ProviderSubject[],
): Promise<Map<number, FixedProviderFacts>> {
  const out = new Map<number, FixedProviderFacts>();
  if (subjects.length === 0) return out;
  const deviceIds = [...new Set(subjects.map((s) => Number(s.deviceId)))];
  const siteIds = [...new Set(subjects.filter((s) => s.siteId !== null).map((s) => Number(s.siteId)))];

  const declared = new Map<number, string | null>();
  const missing = subjects.filter((s) => s.declared === undefined && s.siteId !== null).map((s) => Number(s.siteId));
  if (missing.length > 0) {
    const rows = (await db('sites').whereIn('id', [...new Set(missing)]).select('id', 'tenant_id', 'fixed_provider')) as Array<{
      id: number; tenant_id: number; fixed_provider: string | null;
    }>;
    for (const r of rows) declared.set(Number(r.id), r.fixed_provider);
    // A site of another tenant is not this store's: no declaration.
    const tenantOfSite = new Map(rows.map((r) => [Number(r.id), Number(r.tenant_id)]));
    for (const s of subjects) {
      if (s.siteId !== null && tenantOfSite.get(Number(s.siteId)) !== Number(s.tenantId)) declared.delete(Number(s.siteId));
    }
  }

  // WAN1 variables: device level first, then site level; never a secret.
  const vars = (await db('config_variables')
    .whereIn('key', [WAN1_VARIABLE_KEYS.mode, WAN1_VARIABLE_KEYS.pppoeUsername])
    .where('is_secret', false)
    .where((q) => {
      void q.where((d) => void d.where('scope', 'device').whereIn('scope_id', deviceIds));
      if (siteIds.length > 0) void q.orWhere((s) => void s.where('scope', 'site').whereIn('scope_id', siteIds));
    })
    .select('tenant_id', 'scope', 'scope_id', 'key', 'value')) as Array<{
      tenant_id: number; scope: 'device' | 'site'; scope_id: number; key: string; value: unknown;
    }>;
  const varOf = (tenantId: number, scope: 'device' | 'site', id: number | null, key: string): string | null => {
    if (id === null) return null;
    const hit = vars.find((v) => v.scope === scope && Number(v.scope_id) === id && v.key === key && Number(v.tenant_id) === tenantId);
    if (!hit || typeof hit.value !== 'string') return null;
    const t = hit.value.trim();
    return t === '' ? null : t;
  };

  const memory = (await db('device_fixed_link')
    .whereIn('device_id', deviceIds)
    .select('device_id', 'tenant_id', db.raw('host(public_ip) AS ip'), 'asn', 'asn_name')) as Array<{
      device_id: number; tenant_id: number; ip: string; asn: number | null; asn_name: string | null;
    }>;
  const memOf = new Map(memory.map((m) => [Number(m.device_id), m]));

  for (const s of subjects) {
    const id = Number(s.deviceId);
    const t = Number(s.tenantId);
    const site = s.siteId === null ? null : Number(s.siteId);
    const pick = (key: string) => varOf(t, 'device', id, key) ?? varOf(t, 'site', site, key);
    const mem = memOf.get(id);
    const ownMem = mem && Number(mem.tenant_id) === t ? mem : undefined;
    out.set(id, {
      declared: s.declared !== undefined ? s.declared : site !== null ? declared.get(site) ?? null : null,
      wan1Mode: pick(WAN1_VARIABLE_KEYS.mode),
      pppoeUsername: pick(WAN1_VARIABLE_KEYS.pppoeUsername),
      fixedPublicIp: ownMem?.ip ?? null,
      asn: ownMem && ownMem.asn !== null ? { asn: Number(ownMem.asn), name: ownMem.asn_name } : null,
    });
  }
  return out;
}
