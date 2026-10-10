/**
 * ObliWAN — partner CLIENT → customer TENANT distribution ("Rapprochement
 * SIM"), CHR-reconciliation style.
 *
 * The Phenix account lives in the Default (master) tenant and lists every
 * customer's lines, client by client. A line lands in the POOL (tenant_id
 * NULL). This file records ONE decision per partner client — "client C0001 is
 * tenant Customer B" (`sim_partner_client_tenants`, migration 081) — and applies it
 * to the client's lines: on the decision, and on every later sweep.
 *
 * ┌─ WHAT A MAPPING MOVES, AND WHAT IT NEVER TOUCHES ───────────────────────┐
 * │ · A POOL line of a mapped client goes to the mapped tenant (decision,     │
 * │   and every sweep — so a line the partner lists tomorrow lands directly). │
 * │ · On a RE-MAP (C was tenant A, is now tenant B), the lines that were in A │
 * │   move to B. Lines an operator put in a THIRD tenant by hand are kept     │
 * │   where they are and counted (`keptElsewhere`): a per-line decision is    │
 * │   more specific than a per-client one, and is never overruled silently.   │
 * │ · A move follows the existing assignment model exactly (`updateLine`):   │
 * │   `tenant_assigned_at` = now (the consumption cut — the new owner never  │
 * │   reads the previous owner's history), site and router cleared (they     │
 * │   belong to the old tenant), open top-up proposals expired and episodes  │
 * │   reopened (`settleOpenWorkOnMove`), router re-linked by ICCID.           │
 * │ · Un-mapping is a human decision recorded as a row with tenant NULL     │
 * │   (migration 085): the automatic rule never maps that client again until  │
 * │   a human does. The operator says what happens to the lines: they STAY   │
 * │   in the workspace, or go back to the POOL — except a line on a router   │
 * │   of that workspace (its card is in the router: the ICCID link would     │
 * │   bring it straight back) and a line put in a third workspace by hand.   │
 * │ · Site attach: a line of the tenant with NO site whose partner site label │
 * │   carries exactly one of THAT tenant's site codes is attached to it. A    │
 * │   label naming two sites attaches nothing; a site already set is kept.    │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE AUTOMATIC RULE — the only case where no human decides ─────────────┐
 * │ A client is mapped automatically (by the sweep, `decided_by` NULL) ONLY  │
 * │ when it has NO row (never decided — a removed mapping is a decision) AND │
 * │ exactly ONE tenant matches it STRONGLY, i.e.                              │
 * │ BOTH: (1) its folded name EQUALS the partner customer name folded        │
 * │ (accents, case, punctuation and legal forms removed: "ABCD" = "Ab&Cd",   │
 * │ "Acme SAS" = "ACME"), AND (2) at least one site code read in the         │
 * │ client's partner site labels exists in that tenant. Anything else — a    │
 * │ A second tenant whose name folds to the same string blocks it too.       │
 * │ partial name, a code match without a name, two tenants — is a SUGGESTION │
 * │ only, shown with its reason on /mobile/reconcile.                         │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * Nothing here spends, proposes or approves anything.
 */

import type { Knex } from 'knex';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { appendAudit } from '../attestation/auditLog.service';
import { linkDeviceByLineIccid } from './deviceLink.service';
import { settleOpenWorkOnMove } from './line.service';

// ============================================================================
// Pure matching helpers (exported for the harness)
// ============================================================================

/** Legal-form words that say nothing about WHICH customer a name is. */
const LEGAL_FORMS = new Set(['sas', 'sasu', 'sarl', 'eurl', 'sa', 'sci', 'snc', 'sca', 'ste', 'societe', 'ets', 'group', 'groupe']);

/** Accents, case, punctuation and legal forms removed: "Dupont&Fils SAS" → "dupontfils". */
export function foldName(raw: string | null | undefined): string {
  if (typeof raw !== 'string') return '';
  const words = raw
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .split(/\s+/)
    .map((w) => w.replace(/[^a-z0-9]/g, ''))
    .filter((w) => w.length > 0 && !LEGAL_FORMS.has(w));
  return words.join('');
}

/**
 * Candidate site codes in a partner site label: alphanumeric runs carrying at
 * least one digit, 2 characters or more. A word with no digit ("PARIS",
 * "Magasin") is never a code — matching it would attach by city name.
 */
export function siteCodeTokens(label: string | null | undefined): string[] {
  if (typeof label !== 'string') return [];
  const out = new Set<string>();
  for (const tok of label.split(/[^A-Za-z0-9]+/)) {
    if (tok.length >= 2 && /[0-9]/.test(tok)) out.add(codeKey(tok));
  }
  return [...out];
}

/** Comparison key for a site code: case-folded; an all-digit code loses its
 *  leading zeros ("00971" and "971" are the same store number). */
export function codeKey(code: string): string {
  const c = code.trim().toLowerCase();
  if (/^[0-9]+$/.test(c)) return c.replace(/^0+(?=[0-9])/, '');
  return c;
}

export type NameMatch = 'exact' | 'partial' | null;

export function nameMatch(customerNames: string[], tenant: { name: string; slug: string }): NameMatch {
  const tn = [foldName(tenant.name), foldName(tenant.slug)].filter((s) => s.length > 0);
  let best: NameMatch = null;
  for (const raw of customerNames) {
    const cn = foldName(raw);
    if (!cn) continue;
    for (const t of tn) {
      if (cn === t) return 'exact';
      const shorter = cn.length < t.length ? cn : t;
      if (shorter.length >= 4 && (cn.includes(t) || t.includes(cn))) best = 'partial';
    }
  }
  return best;
}

// ============================================================================
// Reads
// ============================================================================

interface TenantRow { id: number; name: string; slug: string }
interface SiteRow { id: number; tenant_id: number; code: string }

/** Per tenant: code key → site ids carrying it. */
type SiteIndex = Map<number, Map<string, number[]>>;

async function loadTenantsAndSites(q: Knex | Knex.Transaction = db): Promise<{ tenants: TenantRow[]; sites: SiteIndex }> {
  const tenants = (await q('tenants').select('id', 'name', 'slug')) as TenantRow[];
  const siteRows = (await q('sites').select('id', 'tenant_id', 'code')) as SiteRow[];
  const sites: SiteIndex = new Map();
  for (const s of siteRows) {
    const tid = Number(s.tenant_id);
    let m = sites.get(tid);
    if (!m) sites.set(tid, (m = new Map()));
    const k = codeKey(s.code);
    const arr = m.get(k) ?? [];
    arr.push(Number(s.id));
    m.set(k, arr);
  }
  return { tenants, sites };
}

/** The ONE site of `tenantId` a label names, or null (none, or two). */
export function siteForLabel(sites: SiteIndex, tenantId: number, label: string | null): number | null {
  const m = sites.get(tenantId);
  if (!m) return null;
  const found = new Set<number>();
  for (const k of siteCodeTokens(label)) for (const id of m.get(k) ?? []) found.add(id);
  return found.size === 1 ? [...found][0] : null;
}

export interface SimClientCandidate {
  tenantId: number;
  tenantName: string;
  nameMatch: NameMatch;
  /** Site codes read in the partner labels that exist in this tenant. */
  siteCodes: string[];
  /** BOTH an exact folded name and at least one site code. */
  strong: boolean;
}

export interface SimClientRow {
  accountId: number;
  accountName: string;
  clientCode: string;
  customerName: string | null;
  lineCount: number;
  /** Where the client's lines are now: tenant id (null = pool) → count. */
  lineTenants: Array<{ tenantId: number | null; tenantName: string | null; count: number }>;
  mapping: { tenantId: number; tenantName: string; decidedBy: number | null; decidedAt: string } | null;
  /**
   * An operator REMOVED this client's mapping (migration 085: a row with no
   * tenant): no automatic suggestion is applied until a human maps it again.
   */
  unmapped: { decidedBy: number | null; decidedAt: string } | null;
  /** Best candidate first; at most three. */
  candidates: SimClientCandidate[];
  /** The automatic rule holds: never decided (no row) and exactly one strong candidate. */
  autoTenantId: number | null;
}

interface ClientLineRow {
  account_id: number;
  client_code: string;
  tenant_id: number | null;
  customer_name: string | null;
  partner_site_label: string | null;
}

function scoreOf(c: SimClientCandidate): number {
  return (c.nameMatch === 'exact' ? 100 : c.nameMatch === 'partial' ? 50 : 0) + Math.min(c.siteCodes.length, 9) * 10;
}

function candidatesFor(
  names: string[],
  labels: string[],
  tenants: TenantRow[],
  sites: SiteIndex,
): SimClientCandidate[] {
  const tokens = new Set<string>();
  for (const l of labels) for (const t of siteCodeTokens(l)) tokens.add(t);
  const out: SimClientCandidate[] = [];
  for (const t of tenants) {
    const nm = nameMatch(names, t);
    const m = sites.get(Number(t.id));
    const codes = m ? [...tokens].filter((k) => m.has(k)) : [];
    if (nm === null && codes.length === 0) continue;
    out.push({
      tenantId: Number(t.id),
      tenantName: t.name,
      nameMatch: nm,
      siteCodes: codes.sort(),
      strong: nm === 'exact' && codes.length > 0,
    });
  }
  return out.sort((a, b) => scoreOf(b) - scoreOf(a) || a.tenantId - b.tenantId);
}

/** Every partner client of every account, with its mapping and suggestions. */
export async function listSimClients(): Promise<SimClientRow[]> {
  const lines = (await db('sim_lines')
    .whereNotNull('client_code')
    .whereRaw("btrim(client_code) <> ''")
    .select('account_id', 'client_code', 'tenant_id', 'customer_name', 'partner_site_label')) as ClientLineRow[];
  const accounts = (await db('sim_accounts').select('id', 'name')) as Array<{ id: number; name: string }>;
  const accountName = new Map(accounts.map((a) => [Number(a.id), a.name]));
  const mappings = (await db('sim_partner_client_tenants').select(
    'account_id', 'client_code', 'tenant_id', 'decided_by', 'decided_at',
  )) as Array<{ account_id: number; client_code: string; tenant_id: number | null; decided_by: number | null; decided_at: Date | string }>;
  const mapKey = (a: number, c: string) => `${a}\u0000${c}`;
  const mapped = new Map(mappings.map((m) => [mapKey(Number(m.account_id), m.client_code), m]));
  const { tenants, sites } = await loadTenantsAndSites();
  const tenantName = new Map(tenants.map((t) => [Number(t.id), t.name]));

  const groups = new Map<string, { accountId: number; clientCode: string; rows: ClientLineRow[] }>();
  for (const l of lines) {
    const k = mapKey(Number(l.account_id), l.client_code);
    let g = groups.get(k);
    if (!g) groups.set(k, (g = { accountId: Number(l.account_id), clientCode: l.client_code, rows: [] }));
    g.rows.push(l);
  }

  const out: SimClientRow[] = [];
  for (const [k, g] of groups) {
    const names = [...new Set(g.rows.map((r) => r.customer_name).filter((s): s is string => !!s && s.trim() !== ''))];
    const labels = [...new Set(g.rows.map((r) => r.partner_site_label).filter((s): s is string => !!s && s.trim() !== ''))];
    const byTenant = new Map<number | null, number>();
    for (const r of g.rows) {
      const t = r.tenant_id === null ? null : Number(r.tenant_id);
      byTenant.set(t, (byTenant.get(t) ?? 0) + 1);
    }
    const m = mapped.get(k);
    const candidates = candidatesFor(names, labels, tenants, sites);
    const strong = candidates.filter((c) => c.strong);
    out.push({
      accountId: g.accountId,
      accountName: accountName.get(g.accountId) ?? String(g.accountId),
      clientCode: g.clientCode,
      customerName: names[0] ?? null,
      lineCount: g.rows.length,
      lineTenants: [...byTenant.entries()].map(([tenantId, count]) => ({
        tenantId,
        tenantName: tenantId === null ? null : (tenantName.get(tenantId) ?? null),
        count,
      })),
      mapping: m && m.tenant_id !== null
        ? {
            tenantId: Number(m.tenant_id),
            tenantName: tenantName.get(Number(m.tenant_id)) ?? String(m.tenant_id),
            decidedBy: m.decided_by === null ? null : Number(m.decided_by),
            decidedAt: new Date(m.decided_at).toISOString(),
          }
        : null,
      unmapped: m && m.tenant_id === null
        ? { decidedBy: m.decided_by === null ? null : Number(m.decided_by), decidedAt: new Date(m.decided_at).toISOString() }
        : null,
      candidates: candidates.slice(0, 3),
      // The automatic rule (header): no row at all (a removed mapping is a row,
      // migration 085), exactly ONE strong candidate, and no OTHER tenant whose
      // name folds to the same string (two "Alpha-Mart"s).
      autoTenantId:
        !m && strong.length === 1 && candidates.filter((c) => c.nameMatch === 'exact').length === 1
          ? strong[0].tenantId
          : null,
    });
  }
  // Unmapped first, then by account and client code.
  return out.sort(
    (a, b) =>
      (a.mapping ? 1 : 0) - (b.mapping ? 1 : 0) ||
      a.accountId - b.accountId ||
      a.clientCode.localeCompare(b.clientCode),
  );
}

// ============================================================================
// Writes
// ============================================================================

export class SimClientMapError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

export interface ApplyOutcome {
  moved: number;
  sitesAttached: number;
  /** Lines an operator put in another tenant by hand: kept there. */
  keptElsewhere: number;
}

interface MoveLineRow {
  id: number;
  tenant_id: number | null;
  site_id: number | null;
  partner_site_label: string | null;
}

/**
 * Applies a mapping to the client's lines, inside the caller's transaction.
 * `previousTenantId` is the tenant the client was mapped to BEFORE this
 * decision (a re-map): its lines follow. The sweep passes null — it only
 * fills the pool and attaches sites.
 */
async function applyToLines(
  trx: Knex.Transaction,
  accountId: number,
  clientCode: string,
  tenantId: number,
  previousTenantId: number | null,
  sites: SiteIndex,
): Promise<ApplyOutcome> {
  const res: ApplyOutcome = { moved: 0, sitesAttached: 0, keptElsewhere: 0 };
  const rows = (await trx('sim_lines')
    .where({ account_id: accountId, client_code: clientCode })
    .forUpdate()
    .select('id', 'tenant_id', 'site_id', 'partner_site_label')) as MoveLineRow[];
  for (const r of rows) {
    const id = Number(r.id);
    const current = r.tenant_id === null ? null : Number(r.tenant_id);
    let siteId = r.site_id === null ? null : Number(r.site_id);
    if (current !== tenantId) {
      const follows = current === null || (previousTenantId !== null && current === previousTenantId);
      if (!follows) {
        res.keptElsewhere += 1;
        continue;
      }
      await trx('sim_lines').where({ id }).update({
        tenant_id: tenantId,
        // The consumption cut (`getLineHistory`, `simConsumptionCut`).
        tenant_assigned_at: trx.fn.now(),
        // They belonged to the previous tenant (composite FKs, migration 032).
        site_id: null,
        device_id: null,
        updated_at: trx.fn.now(),
      });
      await settleOpenWorkOnMove(trx, id, current);
      siteId = null;
      res.moved += 1;
    }
    if (siteId === null) {
      const site = siteForLabel(sites, tenantId, r.partner_site_label);
      if (site !== null) {
        await trx('sim_lines').where({ id, tenant_id: tenantId }).whereNull('site_id')
          .update({ site_id: site, updated_at: trx.fn.now() });
        res.sitesAttached += 1;
      }
    }
    if (current !== tenantId) {
      const linked = await linkDeviceByLineIccid(trx, id);
      if (linked.linked) logger.info({ lineId: id, deviceId: linked.deviceId }, 'SIM line linked to the router whose modem holds its ICCID');
    }
  }
  return res;
}

/** What happens to the client's lines when its mapping is removed. */
export type LinesOnUnmap = 'stay' | 'pool';
export const LINES_ON_UNMAP: readonly LinesOnUnmap[] = ['stay', 'pool'];

export interface MappingDecision {
  accountId: number;
  clientCode: string;
  /** null = remove the mapping (a human decision: see `linesOnUnmap`). */
  tenantId: number | null;
  /**
   * Required to REMOVE an existing mapping, never defaulted:
   *   - 'stay' — every line stays in its workspace;
   *   - 'pool' — the lines in the mapped workspace go back to the pool
   *     (tenant, site and router cleared, open top-up proposals expired),
   *     EXCEPT a line on a router of that workspace (its card is in the
   *     router: the ICCID link would bring it straight back, operator decision
   *     2026-10-07) and a line an operator put in a third workspace by hand.
   */
  linesOnUnmap?: LinesOnUnmap;
}

export interface MappingOutcome extends ApplyOutcome {
  previousTenantId: number | null;
  /** False when nothing was recorded: a removal of a client that had no
   *  mapping, or the automatic rule meeting a row a human wrote first. */
  recorded: boolean;
  /** Removal with 'pool': lines returned to the pool. */
  returnedToPool: number;
  /** Removal with 'pool': lines kept because they are on a router of the workspace. */
  keptOnRouter: number;
}

export const UNMAP_NEEDS_CHOICE =
  "Say whether the client's lines stay in their workspace or return to the pool (linesOnUnmap: 'stay' or 'pool').";

/**
 * Records (or removes) one client → tenant decision and applies it. Audited
 * in the target tenant and, on a re-map, in the tenant the lines left; a
 * removal in the tenant it was mapped to. `actor` null = the automatic rule,
 * which only ever fills a client NO human has decided on: it never removes a
 * mapping and never overrides a row (a removed mapping included).
 */
export async function setClientMapping(
  decision: MappingDecision,
  actor: { id: number; name: string } | null,
): Promise<MappingOutcome> {
  const clientCode = decision.clientCode.trim();
  if (!clientCode) throw new SimClientMapError('Client code is required', 400);
  const account = await db('sim_accounts').where({ id: decision.accountId }).first('id');
  if (!account) throw new SimClientMapError('Partner account not found', 404);
  if (decision.tenantId !== null) {
    const t = await db('tenants').where({ id: decision.tenantId }).first('id');
    if (!t) throw new SimClientMapError('Workspace not found', 400);
  }
  const { sites } = await loadTenantsAndSites();

  return db.transaction(async (trx) => {
    const prev = (await trx('sim_partner_client_tenants')
      .where({ account_id: decision.accountId, client_code: clientCode })
      .forUpdate()
      .first('tenant_id')) as { tenant_id: number | null } | undefined;
    // A row with no tenant (085) is a removed mapping: no previous tenant.
    const previousTenantId = prev && prev.tenant_id !== null ? Number(prev.tenant_id) : null;
    const nothing: MappingOutcome = {
      moved: 0, sitesAttached: 0, keptElsewhere: 0, previousTenantId, returnedToPool: 0, keptOnRouter: 0, recorded: false,
    };
    // The automatic rule only fills a client nobody has decided on. A row —
    // mapped, or removed by a human — is a decision it never overrides (the
    // candidates may have changed between its read and this lock).
    if (actor === null && prev) return nothing;
    const auditBase = {
      actorType: actor ? ('user' as const) : ('automation' as const),
      actorId: actor ? actor.id : 'sim-client-map',
      actorName: actor ? actor.name : 'SIM client mapping (automatic rule)',
      entityType: 'sim_partner_client',
      entityId: `${decision.accountId}:${clientCode}`,
    };

    if (decision.tenantId === null) {
      if (previousTenantId === null) return nothing;
      if (actor === null) throw new SimClientMapError('Only an operator removes a client mapping', 400);
      const linesOnUnmap = decision.linesOnUnmap;
      if (linesOnUnmap !== 'stay' && linesOnUnmap !== 'pool') throw new SimClientMapError(UNMAP_NEEDS_CHOICE, 400);
      // The row stays, with no tenant: "a human decided this client belongs
      // to no workspace" — the automatic rule never maps it back (085).
      await trx('sim_partner_client_tenants')
        .where({ account_id: decision.accountId, client_code: clientCode })
        .update({ tenant_id: null, decided_by: actor.id, decided_at: trx.fn.now() });
      const out: MappingOutcome = { ...nothing, recorded: true };
      const lineIds: number[] = [];
      if (linesOnUnmap === 'pool') {
        const rows = (await trx('sim_lines')
          .where({ account_id: decision.accountId, client_code: clientCode })
          .forUpdate()
          .select('id', 'tenant_id', 'device_id')) as Array<{ id: number; tenant_id: number | null; device_id: number | null }>;
        for (const r of rows) {
          if (r.tenant_id === null) continue; // already in the pool
          if (Number(r.tenant_id) !== previousTenantId) {
            out.keptElsewhere += 1; // a per-line decision, never overruled
            continue;
          }
          if (r.device_id !== null) {
            // Its card is in a router of this workspace (composite FK, 032):
            // pooled, the ICCID link would bring it straight back.
            out.keptOnRouter += 1;
            continue;
          }
          const id = Number(r.id);
          await trx('sim_lines').where({ id }).update({
            tenant_id: null,
            site_id: null,
            device_id: null,
            // NULL = in the pool (getLineHistory's consumption cut).
            tenant_assigned_at: null,
            updated_at: trx.fn.now(),
          });
          await settleOpenWorkOnMove(trx, id, previousTenantId);
          out.returnedToPool += 1;
          lineIds.push(id);
        }
      }
      await appendAudit({
        ...auditBase,
        tenantId: previousTenantId,
        action: 'sim_client.unmapped',
        before: { accountId: decision.accountId, clientCode, tenantId: previousTenantId },
        after: {
          tenantId: null,
          linesOnUnmap,
          returnedToPool: out.returnedToPool,
          keptOnRouter: out.keptOnRouter,
          keptElsewhere: out.keptElsewhere,
          lineIds,
        },
      }, trx);
      return out;
    }

    await trx('sim_partner_client_tenants')
      .insert({
        account_id: decision.accountId,
        client_code: clientCode,
        tenant_id: decision.tenantId,
        decided_by: actor ? actor.id : null,
        decided_at: trx.fn.now(),
      })
      .onConflict(['account_id', 'client_code'])
      .merge(['tenant_id', 'decided_by', 'decided_at']);

    const outcome = await applyToLines(trx, decision.accountId, clientCode, decision.tenantId, previousTenantId, sites);
    const after = { accountId: decision.accountId, clientCode, tenantId: decision.tenantId, ...outcome };
    await appendAudit({
      ...auditBase,
      tenantId: decision.tenantId,
      action: previousTenantId !== null && previousTenantId !== decision.tenantId ? 'sim_client.remapped' : 'sim_client.mapped',
      before: previousTenantId === null ? null : { tenantId: previousTenantId },
      after,
    }, trx);
    if (previousTenantId !== null && previousTenantId !== decision.tenantId) {
      await appendAudit({
        ...auditBase,
        tenantId: previousTenantId,
        action: 'sim_client.remapped_away',
        before: { tenantId: previousTenantId },
        after,
      }, trx);
    }
    return { ...outcome, previousTenantId, returnedToPool: 0, keptOnRouter: 0, recorded: true };
  });
}

/**
 * The sweep's hook, after the inventory upsert and before balances (so the
 * balance pass already sees the right tenant). For one account: (1) every
 * mapped client's POOL lines go to its tenant and unattached lines get their
 * site; (2) the automatic rule maps the clients it holds for. Never throws:
 * a failure here must not blind the account's balance read.
 */
export async function applyClientMappingsForAccount(accountId: number): Promise<{ moved: number; sitesAttached: number; autoMapped: number }> {
  const total = { moved: 0, sitesAttached: 0, autoMapped: 0 };
  try {
    // A row with no tenant is a REMOVED mapping (085): nothing to apply.
    const mappings = (await db('sim_partner_client_tenants')
      .where({ account_id: accountId })
      .whereNotNull('tenant_id')
      .select('client_code', 'tenant_id')) as Array<{ client_code: string; tenant_id: number }>;
    if (mappings.length > 0) {
      const { sites } = await loadTenantsAndSites();
      for (const m of mappings) {
        const r = await db.transaction((trx) =>
          applyToLines(trx, accountId, m.client_code, Number(m.tenant_id), null, sites),
        );
        total.moved += r.moved;
        total.sitesAttached += r.sitesAttached;
        if (r.moved > 0) {
          await appendAudit({
            tenantId: Number(m.tenant_id),
            actorType: 'automation',
            actorId: 'sim-sweep',
            actorName: 'SIM inventory sweep',
            action: 'sim_client.lines_assigned',
            entityType: 'sim_partner_client',
            entityId: `${accountId}:${m.client_code}`,
            after: { accountId, clientCode: m.client_code, tenantId: Number(m.tenant_id), ...r },
          });
        }
      }
    }
    const clients = (await listSimClients()).filter((c) => c.accountId === accountId && c.autoTenantId !== null);
    for (const c of clients) {
      const r = await setClientMapping({ accountId, clientCode: c.clientCode, tenantId: c.autoTenantId }, null);
      // A row appeared between the read and the lock: a human decided first.
      if (!r.recorded) continue;
      total.autoMapped += 1;
      total.moved += r.moved;
      total.sitesAttached += r.sitesAttached;
    }
  } catch (err) {
    logger.warn(
      { accountId, err: err instanceof Error ? err.message : String(err) },
      'SIM client → tenant distribution failed for this sweep; lines stay where they were',
    );
  }
  return total;
}
