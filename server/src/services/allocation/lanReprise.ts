import { randomUUID } from 'crypto';
import type { Knex } from 'knex';
import {
  LAN_REPRISE_MAX_CHARS,
  LAN_REPRISE_MAX_ROWS,
  RECORDED_LAN_SOURCE,
  SITE_LAN_SOURCES,
  type LanRepriseRefusal,
  type LanRepriseRefusalView,
  type LanRepriseResult,
  type LanRepriseRowResult,
  type LanRepriseVerdict,
  type LanRepriseWarning,
  type SiteLanSource,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { appendAudit } from '../attestation/auditLog.service';
import { SiteImportFileError, parseCsv } from '../fleet/siteImport.service';
import { loadLoginContext, loadPolicy, loadPools } from './allocator';
import { evaluateDerived } from './derived';
import { AllocationError, assertId, isPgError } from './errors';
import { takeAllocationLock } from './lock';
import {
  FREE_SITE_CODE_FORMAT,
  PG_INT_MAX,
  POOL_PREFIX_MAX,
  POOL_PREFIX_MIN,
  cidrContains,
  cidrLast,
  formatCidr,
  formatIpv4,
  judgeSiteCode,
  parseCidr,
  parseIpv4,
  rangesOverlap,
  siteLabel,
  type AllocationPolicy,
  type Cidr,
  type LoginContext,
} from './policy';
import { siteNumber } from './pppIdentity';

/**
 * lanReprise.ts — record the REAL LAN of sites already deployed (B1).
 *
 * ┌─ WHY THIS EXISTS ────────────────────────────────────────────────────────┐
 * │ An existing store is ADOPTED (policy.ts, `adoptDeclared`): its login and │
 * │ tunnel address are what its CHR secret declares. Its LAN is not on the   │
 * │ CHR. With a LAN rule active the adoption would draw a block that is not  │
 * │ the store's; with "no LAN" `lan_subnet` stays empty, and every computed  │
 * │ value derived from it (`lan_router_ip = cidrHost(lan_subnet, 1)`)        │
 * │ resolves to nothing, so every render of the store refuses or proposes to │
 * │ renumber it. The operator holds a verified table of the deployed LANs;   │
 * │ this records each one on the site's EXISTING allocation, as             │
 * │ `lan_source` 'recorded' (migration 070). The computed values are then   │
 * │ recomputed from it on every read (allocator.ts `computedValues`), exactly │
 * │ as for a LAN drawn by a rule. Nothing is written to any router or CHR.  │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHAT A ROW MUST BE ─────────────────────────────────────────────────────┐
 * │ A site of THIS tenant that already has an allocation (adopted or        │
 * │ allocated: this never creates one), and a network-aligned IPv4 block    │
 * │ /8../30 (the allocator's LAN bounds). Refused by name, nothing written: │
 * │  - a LAN overlapping a pool of the tenant's policy (its LAN pool: new    │
 * │    stores are drawn there, and a deployed LAN inside it means the pool  │
 * │    was chosen over the existing plan) or ANY tunnel pool (tunnel        │
 * │    addresses and LANs are one address space, installation-wide);       │
 * │  - a LAN containing a site allocation's tunnel address, any tenant's;   │
 * │  - a LAN overlapping the LAN another site of the tenant keeps, or       │
 * │    another row of the same request (BOTH rows: the file contradicts    │
 * │    itself, and which one is right is not this module's guess);          │
 * │  - a site that already carries a DIFFERENT LAN, unless `overwrite`;     │
 * │  - a router address outside the LAN, or on its network or broadcast.   │
 * │ Not judged: other tenants' LANs. A LAN plan is the customer's own, and  │
 * │ two customers may reuse one (policy.ts, UNIQUENESS) — the same rule as  │
 * │ the allocator's manual LAN mode.                                        │
 * │                                                                          │
 * │ A tenant's FIXED LAN (the same block on every site, never routed) is    │
 * │ not a sibling LAN to overlap: migration 039 takes it out of the unique  │
 * │ index for that reason. It is replaced like any LAN, under `overwrite`.  │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ LATER ALLOCATIONS WALK AROUND IT ───────────────────────────────────────┐
 * │ A recorded LAN is a row of `site_provisioning` like any other: the      │
 * │ allocator's LAN read (allocator.ts `loadLanSubnets`) sees the tenant's   │
 * │ own rows by `tenant_id`, and every tenant sharing the pool its policy   │
 * │ draws from by `lan_source`; a tunnel address is never taken from inside │
 * │ any site's LAN. So no later allocation hands out an address inside it.  │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * IDEMPOTENT: a row whose site already carries exactly that LAN is
 * 'unchanged' and nothing is written for it — not even `updated_at`, and no
 * audit entry. AUDITED: every row written is one `audit_log` entry
 * (`allocation.lan_recorded`, the site, before/after), all of one request
 * under one correlation id. The DRY RUN runs every judgement and writes
 * nothing; the APPLY runs them again under the allocation lock (the state
 * may have changed since the dry run) and writes the rows that pass.
 *
 * The router address of a row is JUDGED (inside the LAN, a usable host) and
 * compared with what the policy derives, and stored nowhere but the audit
 * entry: the router's LAN address is a computed value of the template
 * (`cidrHost(lan_subnet, N)`), recomputed on every read, and a second copy
 * of it here would be free to disagree with the first. A store whose router
 * is not where the policy's rule puts it is a WARNING on its row.
 */

// ============================================================================
// Input
// ============================================================================

export interface LanRepriseInputRow {
  /** 1-based line of the CSV the row starts on. */
  line: number;
  code: string;
  lan: string;
  /** '' when the column is absent or the cell empty. */
  routerIp: string;
  /** Cells of the row against cells of the header, when they differ. */
  width: { cells: number; expected: number } | null;
}

export interface ParsedLanFile {
  rows: LanRepriseInputRow[];
  ignoredColumns: string[];
}

const CODE_COLUMNS = ['code'];
const LAN_COLUMNS = ['lan', 'lan_subnet'];
const ROUTER_COLUMNS = ['router_ip', 'lan_router_ip'];

function fileError(message: string): AllocationError {
  return new AllocationError('INVALID_INPUT', `The LAN file cannot be read: ${message}`, { csv: [message] });
}

/**
 * The CSV as the screen sends it: a header naming `code` and `lan` (or
 * `lan_subnet`), optionally `router_ip` (or `lan_router_ip`), in any order and
 * any case, with `,`, `;` or a tab. Other columns (a store's name, the source
 * of the figure…) are carried by the operator's table and ignored here, so the
 * table can be uploaded as it is. The site import's parser reads it: one
 * reading of a CSV in this server.
 */
export function parseLanFile(csv: unknown): ParsedLanFile {
  if (typeof csv !== 'string' || csv.trim() === '') throw fileError('csv is required (the text of the file).');
  if (csv.length > LAN_REPRISE_MAX_CHARS) {
    throw fileError(`the file is longer than ${LAN_REPRISE_MAX_CHARS} characters.`);
  }
  let records: Array<{ line: number; cells: string[] }>;
  try {
    records = parseCsv(csv).records;
  } catch (err) {
    if (err instanceof SiteImportFileError) throw fileError(err.problems.join('; '));
    throw err;
  }
  const nonEmpty = records.filter((r) => r.cells.some((c) => c !== ''));
  if (nonEmpty.length === 0) throw fileError('it is empty.');
  const [header, ...body] = nonEmpty;
  const names = header.cells.map((c) => c.trim().toLowerCase());
  const find = (aliases: readonly string[]): number => {
    const at = names.flatMap((n, i) => (aliases.includes(n) ? [i] : []));
    if (at.length > 1) {
      throw fileError(`the header names the same column twice (${at.map((i) => header.cells[i]).join(', ')}).`);
    }
    return at.length === 1 ? at[0] : -1;
  };
  const codeAt = find(CODE_COLUMNS);
  const lanAt = find(LAN_COLUMNS);
  const routerAt = find(ROUTER_COLUMNS);
  if (codeAt < 0 || lanAt < 0) {
    throw fileError('the first line must be a header naming the columns "code" and "lan" (and optionally "router_ip").');
  }
  if (body.length === 0) throw fileError('it has a header and no row.');
  if (body.length > LAN_REPRISE_MAX_ROWS) throw fileError(`it has more than ${LAN_REPRISE_MAX_ROWS} rows.`);
  const used = new Set([codeAt, lanAt, routerAt]);
  const ignoredColumns = header.cells.filter((c, i) => !used.has(i) && c.trim() !== '');
  const width = header.cells.length;
  return {
    ignoredColumns,
    rows: body.map((r) => ({
      line: r.line,
      code: (r.cells[codeAt] ?? '').trim(),
      lan: (r.cells[lanAt] ?? '').trim(),
      routerIp: routerAt < 0 ? '' : (r.cells[routerAt] ?? '').trim(),
      width: r.cells.length === width ? null : { cells: r.cells.length, expected: width },
    })),
  };
}

// ============================================================================
// State
// ============================================================================

export interface RepriseSite {
  id: number;
  code: string;
  name: string;
  country: string | null;
}

export interface RepriseAllocation {
  siteId: number;
  /** Network text as stored (`a.b.c.d/nn`), or null. */
  lanSubnet: string | null;
  lanSource: SiteLanSource | null;
}

export interface ReprisePool {
  name: string;
  cidr: Cidr;
  purpose: 'tunnel' | 'lan';
}

export interface RepriseTunnelHolder {
  address: number;
  tenantId: number;
  siteId: number;
}

/** Everything the judgement reads, as the database returns it. */
export interface RepriseState {
  tenantId: number;
  /** The tenant's sites. */
  sites: readonly RepriseSite[];
  /** The tenant's allocations, one per allocated site. */
  allocations: readonly RepriseAllocation[];
  /** Blocks a recorded LAN may not overlap: every tunnel pool, and the LAN
   *  pool the tenant's stored policy draws from. */
  pools: readonly ReprisePool[];
  /** The tunnel address of every site allocation, every tenant. */
  tunnelHolders: readonly RepriseTunnelHolder[];
}

// ============================================================================
// Judgement — pure
// ============================================================================

/** One row as judged, before the policy's derived values are added. */
export interface JudgedRow {
  input: LanRepriseInputRow;
  site: RepriseSite | null;
  codeRestored: boolean;
  current: RepriseAllocation | null;
  verdict: LanRepriseVerdict;
  refusal: LanRepriseRefusalView | null;
  /** Parsed, when the row is not refused. */
  cidr: Cidr | null;
  routerIp: number | null;
  warnings: LanRepriseWarning[];
}

type Matched = { site: RepriseSite; restored: boolean } | { refusal: LanRepriseRefusalView };

function refusal(reason: LanRepriseRefusal, params: Record<string, string> = {}): LanRepriseRefusalView {
  return { reason, params };
}

/**
 * Which site a `code` cell names. A spreadsheet drops leading zeros ("00002"
 * becomes 2), so an all-digit cell also matches by site NUMBER — but only
 * when that is unambiguous: a cell carrying a leading zero was not stripped,
 * and a cell without one names the exact code only when no other site
 * shares its number ("2889" beside "02889" could be either).
 */
function matchSite(
  cell: string,
  byCode: ReadonlyMap<string, RepriseSite>,
  byLowerCode: ReadonlyMap<string, RepriseSite[]>,
  byNumber: ReadonlyMap<number, RepriseSite[]>,
): Matched {
  const exact = byCode.get(cell);
  const n = /^[0-9]+$/.test(cell) ? siteNumber(cell) : null;
  if (n !== null) {
    const siblings = byNumber.get(n) ?? [];
    if (exact && (cell.startsWith('0') || siblings.length <= 1)) return { site: exact, restored: false };
    if (siblings.length > 1) {
      return { refusal: refusal('site_ambiguous', { code: cell, candidates: siblings.map((s) => s.code).sort().join(', ') }) };
    }
    if (siblings.length === 1) return { site: siblings[0], restored: siblings[0].code !== cell };
    return { refusal: refusal('site_unknown', { code: cell }) };
  }
  if (exact) return { site: exact, restored: false };
  const folded = byLowerCode.get(cell.toLowerCase()) ?? [];
  if (folded.length === 1) return { site: folded[0], restored: false };
  if (folded.length > 1) {
    return { refusal: refusal('site_ambiguous', { code: cell, candidates: folded.map((s) => s.code).sort().join(', ') }) };
  }
  return { refusal: refusal('site_unknown', { code: cell }) };
}

type LanParse = { ok: true; cidr: Cidr } | { ok: false; refusal: LanRepriseRefusalView };

/** A LAN cell: a.b.c.d/nn, /8 to /30, the network address. A block with host
 *  bits set is refused, naming the block it lies in, never masked: the
 *  operator's table is the truth, and silently correcting it would record a
 *  LAN nobody verified. */
export function parseLanCell(text: string): LanParse {
  const m = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/.exec(text);
  const address = m ? parseIpv4(m[1]) : null;
  const prefix = m ? Number(m[2]) : NaN;
  if (!m || address === null || prefix > 32) return { ok: false, refusal: refusal('lan_invalid', { lan: text }) };
  if (prefix < POOL_PREFIX_MIN || prefix > POOL_PREFIX_MAX) {
    return { ok: false, refusal: refusal('lan_prefix', { lan: text, min: String(POOL_PREFIX_MIN), max: String(POOL_PREFIX_MAX) }) };
  }
  const size = 2 ** (32 - prefix);
  const network = address - (address % size);
  if (network !== address) {
    return { ok: false, refusal: refusal('lan_not_aligned', { lan: text, network: `${formatIpv4(network)}/${prefix}` }) };
  }
  return { ok: true, cidr: { network, prefix, size } };
}

function sameCidr(a: Cidr, b: Cidr): boolean {
  return a.network === b.network && a.prefix === b.prefix;
}

function overlaps(a: Cidr, b: Cidr): boolean {
  return rangesOverlap(a.network, cidrLast(a), b.network, cidrLast(b));
}

function storedCidr(text: string | null): Cidr | null {
  if (text === null) return null;
  const p = parseCidr(text);
  return p.ok ? p.cidr : null;
}

const WRITES: ReadonlySet<LanRepriseVerdict> = new Set(['record', 'replace']);

/**
 * Judge every row against `state`. PURE — the dry run and the apply call it
 * on the state each read, so on the same state they give the same answer.
 *
 * In four passes, so the answer never depends on the order of the rows:
 *  1. each row alone (its cells, its site, its LAN, its router address, the
 *     site's allocation, the pools, the tunnel addresses);
 *  2. a site named by several rows: all of them refused;
 *  3. rows to write whose LANs overlap each other: both refused;
 *  4. a row to write against the LAN another site KEEPS — a site no row
 *     rewrites, or whose row was refused — repeated until nothing changes,
 *     because a refusal leaves that site's old LAN in place, and that LAN
 *     may stand in another row's way.
 */
export function judgeLanReprise(
  rows: readonly LanRepriseInputRow[],
  state: RepriseState,
  opts: { overwrite: boolean },
): JudgedRow[] {
  const byCode = new Map<string, RepriseSite>();
  const byLowerCode = new Map<string, RepriseSite[]>();
  const byNumber = new Map<number, RepriseSite[]>();
  for (const s of state.sites) {
    byCode.set(s.code, s);
    const lower = s.code.toLowerCase();
    byLowerCode.set(lower, [...(byLowerCode.get(lower) ?? []), s]);
    const n = /^[0-9]+$/.test(s.code) ? siteNumber(s.code) : null;
    if (n !== null) byNumber.set(n, [...(byNumber.get(n) ?? []), s]);
  }
  const allocationOf = new Map(state.allocations.map((a) => [a.siteId, a]));
  const codeOf = new Map(state.sites.map((s) => [s.id, s.code]));

  // ── 1. each row alone ────────────────────────────────────────────────────
  const judged: JudgedRow[] = rows.map((input) => {
    const row: JudgedRow = {
      input,
      site: null,
      codeRestored: false,
      current: null,
      verdict: 'refused',
      refusal: null,
      cidr: null,
      routerIp: null,
      warnings: [],
    };
    const refuse = (r: LanRepriseRefusalView): JudgedRow => ({ ...row, verdict: 'refused', refusal: r });

    if (input.width !== null) {
      return refuse(refusal('row_malformed', { cells: String(input.width.cells), expected: String(input.width.expected) }));
    }
    if (input.code === '') return refuse(refusal('code_missing'));
    if (!judgeSiteCode(input.code, FREE_SITE_CODE_FORMAT, { restoreZeros: false }).ok) {
      return refuse(refusal('code_spreadsheet', { code: input.code }));
    }
    const matched = matchSite(input.code, byCode, byLowerCode, byNumber);
    if ('refusal' in matched) return refuse(matched.refusal);
    row.site = matched.site;
    row.codeRestored = matched.restored;
    row.current = allocationOf.get(matched.site.id) ?? null;

    if (input.lan === '') return refuse(refusal('lan_missing'));
    const lan = parseLanCell(input.lan);
    if (!lan.ok) return refuse(lan.refusal);
    const c = lan.cidr;
    const lanText = formatCidr(c);

    if (input.routerIp !== '') {
      const ip = parseIpv4(input.routerIp);
      if (ip === null) return refuse(refusal('router_ip_invalid', { routerIp: input.routerIp }));
      if (!cidrContains(c, ip)) return refuse(refusal('router_ip_outside_lan', { routerIp: input.routerIp, lan: lanText }));
      if (ip === c.network || ip === cidrLast(c)) {
        return refuse(refusal('router_ip_not_host', { routerIp: input.routerIp, lan: lanText }));
      }
      row.routerIp = ip;
    }

    if (row.current === null) return refuse(refusal('not_allocated', { site: matched.site.code }));
    const stored = storedCidr(row.current.lanSubnet);
    row.cidr = c;
    if (stored !== null && sameCidr(stored, c)) return { ...row, verdict: 'unchanged' };
    if (stored !== null && !opts.overwrite) {
      return refuse(
        refusal('lan_differs', { current: formatCidr(stored), currentSource: row.current.lanSource ?? '', lan: lanText }),
      );
    }

    const pool = state.pools.find((p) => overlaps(c, p.cidr));
    if (pool) {
      return refuse(refusal('lan_overlaps_pool', { lan: lanText, pool: pool.name, poolCidr: formatCidr(pool.cidr), purpose: pool.purpose }));
    }
    const holder = state.tunnelHolders.find((h) => cidrContains(c, h.address));
    if (holder) {
      const mine = holder.tenantId === state.tenantId;
      return refuse(
        refusal('lan_contains_tunnel_ip', {
          lan: lanText,
          address: formatIpv4(holder.address),
          // Another tenant's site is described by kind only (describeHolder's rule).
          site: mine ? (codeOf.get(holder.siteId) ?? String(holder.siteId)) : '',
        }),
      );
    }
    if (stored !== null) {
      row.warnings.push({
        code: 'replaces_lan',
        params: { current: formatCidr(stored), currentSource: row.current.lanSource ?? '' },
      });
      return { ...row, verdict: 'replace' };
    }
    return { ...row, verdict: 'record' };
  });

  const refuseRow = (r: JudgedRow, v: LanRepriseRefusalView): void => {
    r.verdict = 'refused';
    r.refusal = v;
    r.warnings = [];
  };

  // ── 2. one site, several rows ────────────────────────────────────────────
  const linesOfSite = new Map<number, number[]>();
  for (const r of judged) if (r.site) linesOfSite.set(r.site.id, [...(linesOfSite.get(r.site.id) ?? []), r.input.line]);
  for (const r of judged) {
    if (!r.site) continue;
    const lines = linesOfSite.get(r.site.id) ?? [];
    if (lines.length > 1) refuseRow(r, refusal('site_duplicate', { site: r.site.code, lines: lines.join(', ') }));
  }

  // ── 3. rows to write that overlap each other ─────────────────────────────
  const writing = judged.filter((r) => WRITES.has(r.verdict));
  const clashes = new Map<JudgedRow, JudgedRow>();
  for (let i = 0; i < writing.length; i += 1) {
    for (let j = i + 1; j < writing.length; j += 1) {
      const a = writing[i];
      const b = writing[j];
      if (a.cidr && b.cidr && overlaps(a.cidr, b.cidr)) {
        if (!clashes.has(a)) clashes.set(a, b);
        if (!clashes.has(b)) clashes.set(b, a);
      }
    }
  }
  for (const [r, other] of clashes) {
    refuseRow(
      r,
      refusal('lan_overlaps_row', {
        lan: r.cidr ? formatCidr(r.cidr) : r.input.lan,
        otherLine: String(other.input.line),
        otherCode: other.site?.code ?? other.input.code,
        otherLan: other.cidr ? formatCidr(other.cidr) : other.input.lan,
      }),
    );
  }

  // ── 4. against the LAN every other site keeps ────────────────────────────
  const kept = state.allocations
    .filter((a) => a.lanSource !== 'fixed')
    .flatMap((a) => {
      const c = storedCidr(a.lanSubnet);
      return c ? [{ siteId: a.siteId, cidr: c }] : [];
    });
  for (let changed = true; changed; ) {
    changed = false;
    const rewritten = new Set(judged.filter((r) => WRITES.has(r.verdict)).map((r) => r.site?.id));
    for (const r of judged) {
      if (!WRITES.has(r.verdict) || !r.cidr || !r.site) continue;
      const self = r.site.id;
      const cidr = r.cidr;
      const clash = kept.find((k) => k.siteId !== self && !rewritten.has(k.siteId) && overlaps(cidr, k.cidr));
      if (clash) {
        refuseRow(
          r,
          refusal('lan_overlaps_site', {
            lan: formatCidr(cidr),
            site: codeOf.get(clash.siteId) ?? String(clash.siteId),
            siteLan: formatCidr(clash.cidr),
          }),
        );
        changed = true;
      }
    }
  }

  for (const r of judged) if (r.verdict === 'refused') r.cidr = null;
  return judged;
}

// ============================================================================
// Computed values — pure
// ============================================================================

/**
 * What the site's computed values resolve to with this LAN — `lan_subnet` and
 * each of the policy's derived values, evaluated ONE BY ONE so that every one
 * that cannot be computed is named, not only the first — and what the router
 * address given says about them.
 */
export function annotate(
  row: JudgedRow,
  policy: { derived: AllocationPolicy['derived']; ctx: LoginContext } | null,
): { values: Record<string, string> | null; warnings: LanRepriseWarning[] } {
  if (row.verdict === 'refused' || !row.cidr || !row.site) return { values: null, warnings: [] };
  const lanSubnet = formatCidr(row.cidr);
  const values: Record<string, string> = { lan_subnet: lanSubnet };
  const warnings: LanRepriseWarning[] = [];
  const hostValues: Array<{ key: string; value: string }> = [];
  if (policy) {
    const label = siteLabel(row.site);
    const login = {
      siteName: row.site.name,
      siteCode: row.site.code,
      siteCountry: row.site.country,
      tenantSlug: policy.ctx.tenantSlug,
      instanceDomain: policy.ctx.instanceDomain,
    };
    for (const d of policy.derived) {
      const r = evaluateDerived([d], { lanSubnet, login, siteLabel: label });
      if (!r.ok) {
        warnings.push({ code: 'derived_invalid', params: { key: d.key, expression: d.expr.source } });
        continue;
      }
      values[d.key] = r.values[d.key];
      if (d.expr.kind === 'host') hostValues.push({ key: d.key, value: r.values[d.key] });
    }
  }
  if (row.routerIp !== null) {
    const routerIp = formatIpv4(row.routerIp);
    if (hostValues.length > 0) {
      if (!hostValues.some((h) => h.value === routerIp)) {
        warnings.push({
          code: 'router_ip_not_derived',
          params: { routerIp, derived: hostValues.map((h) => `${h.key} = ${h.value}`).join(', ') },
        });
      }
    } else if (row.routerIp !== row.cidr.network + 1) {
      warnings.push({ code: 'router_ip_not_first_host', params: { routerIp, firstHost: formatIpv4(row.cidr.network + 1) } });
    }
  }
  return { values, warnings };
}

// ============================================================================
// Database
// ============================================================================

function asLanSource(v: unknown): SiteLanSource | null {
  return typeof v === 'string' && (SITE_LAN_SOURCES as readonly string[]).includes(v) ? (v as SiteLanSource) : null;
}

async function loadState(q: Knex, tenantId: number): Promise<RepriseState> {
  const sites = (await q('sites')
    .where({ tenant_id: tenantId })
    .select('id', 'code', 'name', 'country')) as RepriseSite[];
  const allocations = (
    (await q('site_provisioning')
      .where({ tenant_id: tenantId })
      .select('site_id', q.raw('lan_subnet::text AS lan_subnet'), 'lan_source')) as Array<{
      site_id: number;
      lan_subnet: string | null;
      lan_source: string | null;
    }>
  ).map((r) => ({ siteId: r.site_id, lanSubnet: r.lan_subnet, lanSource: asLanSource(r.lan_source) }));

  // The stored policy's LAN pool, read from the raw row: a policy that no
  // longer validates still names the pool its new sites would be drawn from.
  const policyRow = (await q('tenant_allocation_policies').where({ tenant_id: tenantId }).first('lan_pool_id')) as
    | { lan_pool_id: number | null }
    | undefined;
  const pools: ReprisePool[] = [];
  for (const p of (await loadPools(q)).values()) {
    if (p.purpose === 'tunnel' || p.id === policyRow?.lan_pool_id) pools.push({ name: p.name, cidr: p.cidr, purpose: p.purpose });
  }

  const tunnelHolders = (
    (await q('site_provisioning').select(q.raw('host(tunnel_ip) AS address'), 'tenant_id', 'site_id')) as Array<{
      address: string;
      tenant_id: number;
      site_id: number;
    }>
  ).flatMap((r) => {
    const a = parseIpv4(r.address);
    return a === null ? [] : [{ address: a, tenantId: r.tenant_id, siteId: r.site_id }];
  });
  return { tenantId, sites, allocations, pools, tunnelHolders };
}

/** The policy's derived values and the login context, or why there are none. */
async function loadDerivation(
  q: Knex,
  tenantId: number,
): Promise<{ policy: { derived: AllocationPolicy['derived']; ctx: LoginContext } | null; problem: LanRepriseResult['policyProblem'] }> {
  try {
    const { policy } = await loadPolicy(q, tenantId, await loadPools(q));
    return { policy: { derived: policy.derived, ctx: await loadLoginContext(q, tenantId) }, problem: null };
  } catch (err) {
    if (err instanceof AllocationError && err.reason === 'NO_POLICY') return { policy: null, problem: 'no_policy' };
    if (err instanceof AllocationError && err.reason === 'INVALID_POLICY') return { policy: null, problem: 'invalid_policy' };
    throw err;
  }
}

function toResult(
  tenantId: number,
  opts: { dryRun: boolean; overwrite: boolean },
  file: ParsedLanFile,
  judged: readonly JudgedRow[],
  derivation: Awaited<ReturnType<typeof loadDerivation>>,
  correlationId: string | null,
): LanRepriseResult {
  const counts: Record<LanRepriseVerdict, number> = { record: 0, replace: 0, unchanged: 0, refused: 0 };
  const rows: LanRepriseRowResult[] = judged.map((r) => {
    counts[r.verdict] += 1;
    const { values, warnings } = annotate(r, derivation.policy);
    return {
      line: r.input.line,
      code: r.input.code,
      lan: r.input.lan,
      routerIp: r.input.routerIp === '' ? null : r.input.routerIp,
      site: r.site ? { id: r.site.id, code: r.site.code, name: r.site.name } : null,
      codeRestored: r.codeRestored,
      current: r.current ? { lanSubnet: r.current.lanSubnet, lanSource: r.current.lanSource } : null,
      verdict: r.verdict,
      refusal: r.refusal,
      lanSubnet: r.cidr ? formatCidr(r.cidr) : null,
      values,
      warnings: [...r.warnings, ...warnings],
    };
  });
  return {
    tenantId,
    dryRun: opts.dryRun,
    overwrite: opts.overwrite,
    counts,
    ignoredColumns: file.ignoredColumns,
    policyProblem: derivation.problem,
    correlationId,
    rows,
  };
}

export interface LanRepriseActor {
  userId: number | null;
  username: string | null;
}

/**
 * Judge `csv` against tenant `tenantId`'s sites and, unless `dryRun`, record
 * every row that passes. See the header. The dry run reads in one READ ONLY
 * REPEATABLE READ transaction and takes no lock, like the allocation preview;
 * the apply takes the allocation lock (every writer of `site_provisioning`
 * does) and judges again on what it reads under it.
 *
 * Throws AllocationError: TENANT_NOT_FOUND, INVALID_INPUT (the file as a whole:
 * no header, too large, an unclosed quote), CONFLICT (a row written around the
 * lock). Per-row refusals are verdicts, never exceptions.
 */
export async function lanReprise(
  tenantId: number,
  input: { csv: unknown; overwrite?: unknown },
  opts: { dryRun: boolean; actor: LanRepriseActor },
): Promise<LanRepriseResult> {
  assertId(tenantId, 'tenantId', PG_INT_MAX);
  if (input.overwrite !== undefined && typeof input.overwrite !== 'boolean') {
    throw new AllocationError('INVALID_INPUT', 'overwrite must be true or false.', { overwrite: ['true or false'] });
  }
  const overwrite = input.overwrite === true;
  const file = parseLanFile(input.csv);
  if (!(await db('tenants').where({ id: tenantId }).first('id'))) {
    throw new AllocationError('TENANT_NOT_FOUND', `tenant ${tenantId} does not exist.`);
  }

  if (opts.dryRun) {
    return db.transaction(async (trx) => {
      await trx.raw('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
      const judged = judgeLanReprise(file.rows, await loadState(trx, tenantId), { overwrite });
      return toResult(tenantId, { dryRun: true, overwrite }, file, judged, await loadDerivation(trx, tenantId), null);
    });
  }

  const correlationId = randomUUID();
  try {
    const result = await db.transaction(async (trx) => {
      await takeAllocationLock(trx);
      const judged = judgeLanReprise(file.rows, await loadState(trx, tenantId), { overwrite });
      const writes = judged.filter((r) => WRITES.has(r.verdict) && r.site && r.cidr);
      if (writes.length > 0) {
        const ids = writes.map((r) => r.site!.id);
        // Cleared first, then written: a row may take the LAN another row of
        // this request gives up (judgeLanReprise, pass 4), and the per-tenant
        // unique index is checked row by row, not at the end of the statement.
        await trx('site_provisioning')
          .where({ tenant_id: tenantId })
          .whereIn('site_id', ids)
          .update({ lan_subnet: null, lan_source: null, lan_pool_id: null });
        for (const r of writes) {
          const lanSubnet = formatCidr(r.cidr!);
          await trx('site_provisioning')
            .where({ tenant_id: tenantId, site_id: r.site!.id })
            .update({ lan_subnet: lanSubnet, lan_source: RECORDED_LAN_SOURCE, lan_pool_id: null, updated_at: trx.fn.now() });
          await appendAudit(
            {
              tenantId,
              actorType: 'user',
              actorId: opts.actor.userId,
              actorName: opts.actor.username ? opts.actor.username.slice(0, 128) : null,
              action: 'allocation.lan_recorded',
              entityType: 'site',
              entityId: r.site!.id,
              before: { lanSubnet: r.current?.lanSubnet ?? null, lanSource: r.current?.lanSource ?? null },
              after: {
                lanSubnet,
                lanSource: RECORDED_LAN_SOURCE,
                routerIp: r.routerIp === null ? null : formatIpv4(r.routerIp),
                siteCode: r.site!.code,
                line: r.input.line,
                overwrite,
              },
              correlationId,
            },
            trx,
          );
        }
      }
      return toResult(
        tenantId,
        { dryRun: false, overwrite },
        file,
        judged,
        await loadDerivation(trx, tenantId),
        writes.length > 0 ? correlationId : null,
      );
    });
    logger.info(
      { tenantId, ...result.counts, overwrite, correlationId: result.correlationId, userId: opts.actor.userId },
      'Site LANs recorded from the deployed stores (LAN reprise)',
    );
    return result;
  } catch (err) {
    // Every row this request writes was judged under the allocation lock, so
    // a unique violation is a row written around it (hand-made SQL).
    if (isPgError(err, '23505')) {
      throw new AllocationError(
        'CONFLICT',
        'a LAN of this request was taken by a concurrent write that bypassed the allocation lock. Nothing ' +
          'was recorded; run the check again.',
      );
    }
    throw err;
  }
}
