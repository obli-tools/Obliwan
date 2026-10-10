// ============================================================================
// ObliWAN — bench planning: what the preparation bench may read
// ============================================================================
//
// The read half of the bench HTTP contract (/api/bench/v1). The compile half
// is `compile.service.ts`; both are reached only through
// `requireApprovedBenchStation` (routes/benchApi.routes.ts).
//
// ┌─ AN APPROVED STATION IS AN INSTANCE-LEVEL TRUSTED DEVICE ────────────────┐
// │ A platform administrator approved this workstation, and its job is to    │
// │ prepare a router for ANY customer's site. So it lists every tenant and   │
// │ every tenant's sites. What it never reads here: a secret, a variable's   │
// │ value, a credential, another device's configuration. The plan answers    │
// │ the allocation PREVIEW (no password in it) and the declarations of the   │
// │ bench-level variables — names, labels and types, never values.           │
// └──────────────────────────────────────────────────────────────────────────┘
//
// ┌─ THE PLAN COMMITS NOTHING ───────────────────────────────────────────────┐
// │ `previewForSite` writes nothing and returns no password. Choosing a site │
// │ at the bench and walking away must leave the allocator as it was: the   │
// │ allocation is committed by the compile, and only there.                  │
// └──────────────────────────────────────────────────────────────────────────┘
//
// Every sentence a refusal carries is French: it is shown verbatim on the
// bench, whose operators read French (the bench application has no i18n).
//
// The plan also answers, additively (a bench built before them ignores
// them): `blocking` — the sentences of `warnings` that WILL refuse the
// compile, so the bench can disable it; `replaces` — the device a compile
// would retire, which the compile then requires to be confirmed by id;
// per candidate, the device-mode features its render uses and those the
// box's reading denies; and `upgrade` — the RouterOS upgrade towards the
// fleet target (services/firmware) when one is required or merely behind.

import net from 'node:net';
import type { Knex } from 'knex';
import { routerOsPackageArchFromResource, tryRouterOsPackageUrl, type RouterOsPackageArch } from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { previewForSite, AllocationError } from '../allocation';
import { compareOsVersions, modelMatches, satisfiesOsWindow } from '../template/assignment.service';
import { renderForSite, SiteRenderError, type BoxFacts } from '../template/siteRender.service';
import { loadRevisionBundle } from '../template/loader';
import { resolveRouterOsFleetTarget } from '../firmware/releases.service';
import { BenchApiError } from './benchApiError';
import {
  deniedFeatures,
  deviceModeFeaturesOf,
  deviceModeFeaturesOfSources,
  featureList,
  parseBenchDeviceMode,
  type BenchDeviceModeReading,
} from './bodyFeatures';

export { BenchApiError };

// ============================================================================
// The box, as the bench read it
// ============================================================================

export interface BenchBoxInput {
  brand: 'mikrotik';
  model: string | null;
  board: string | null;
  serial: string | null;
  ros_version: string | null;
  wifi_stack: 'wifi' | 'wireless' | null;
  /** Upper-case, colon-separated. */
  mac: string;
  /** `/system/resource` `architecture-name` as the box printed it, or null
   *  (additive: a bench built before it sends none). Optional in the type so
   *  that a caller building a box by hand need not name it; `parseBenchBox`
   *  always sets the three fields below, and readers treat absent as null. */
  architecture?: string | null;
  /** The names of the packages installed on the box (`routeros`,
   *  `wifi-qcom`…), or null when the bench sent none. */
  packages?: string[] | null;
  /** `/system/device-mode/print` as the bench read it, or null. */
  deviceMode?: BenchDeviceModeReading | null;
}

/** Printable ASCII, no leading or trailing blank, 1 to 64 characters: what a
 *  MikroTik reports as its model, board, serial or version. The same shape
 *  `siteRender.service` demands of the facts it puts in the context. */
const BOX_TEXT_RE = /^[\x21-\x7e](?:[\x20-\x7e]{0,62}[\x21-\x7e])?$/;
const MAC_RE = /^([0-9A-F]{2}:){5}[0-9A-F]{2}$/;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * The box block of a plan or compile body. A field the bench could not read
 * arrives as null and stays null — never a default: a model read as '' would
 * match a template's `*` pattern, a version read as '0' would fail every OS
 * window with the wrong reason.
 */
export function parseBenchBox(raw: unknown): BenchBoxInput {
  const bad = (field: string): never => {
    throw new BenchApiError(400, `Description du routeur invalide : le champ « box.${field} » est absent ou illisible.`, 'bad_input');
  };
  if (!isRecord(raw)) bad('');
  const box = raw as Record<string, unknown>;
  if (box.brand !== 'mikrotik') {
    throw new BenchApiError(400, 'Seuls les routeurs MikroTik sont préparés au banc (« box.brand » doit valoir « mikrotik »).', 'bad_input');
  }
  const text = (field: 'model' | 'board' | 'serial' | 'ros_version'): string | null => {
    const v = box[field];
    if (v === undefined || v === null) return null;
    if (typeof v !== 'string') return bad(field);
    const t = v.trim();
    if (t === '') return null;
    if (!BOX_TEXT_RE.test(t)) return bad(field);
    return t;
  };
  const stack = box.wifi_stack;
  if (stack !== undefined && stack !== null && stack !== 'wifi' && stack !== 'wireless') bad('wifi_stack');
  const mac = typeof box.mac === 'string' ? box.mac.trim().toUpperCase().replace(/-/g, ':') : '';
  if (!MAC_RE.test(mac)) bad('mac');
  let architecture: string | null = null;
  if (box.architecture !== undefined && box.architecture !== null) {
    if (typeof box.architecture !== 'string') return bad('architecture');
    const t = box.architecture.trim();
    if (t !== '' && !BOX_TEXT_RE.test(t)) return bad('architecture');
    architecture = t === '' ? null : t;
  }
  let packages: string[] | null = null;
  if (box.packages !== undefined && box.packages !== null) {
    if (!Array.isArray(box.packages) || box.packages.length > 32) return bad('packages');
    const names = new Set<string>();
    for (const p of box.packages) {
      // The package-name rule of the shared URL builder, judged here so that
      // a name the builder would refuse is a 400 and never a half-built list.
      if (typeof p !== 'string' || !tryRouterOsPackageUrl('7.1', p.trim(), 'arm').ok) return bad('packages');
      names.add(p.trim());
    }
    packages = [...names];
  }
  return {
    brand: 'mikrotik',
    model: text('model'),
    board: text('board'),
    serial: text('serial'),
    ros_version: text('ros_version'),
    wifi_stack: stack === 'wifi' || stack === 'wireless' ? stack : null,
    mac,
    architecture,
    packages,
    deviceMode: parseBenchDeviceMode(box.deviceMode),
  };
}

/** The facts a render receives about the box, or null when its Wi-Fi stack
 *  is unknown (the render requires it). */
export function boxFactsOf(box: BenchBoxInput): BoxFacts | null {
  if (box.wifi_stack === null) return null;
  const facts: BoxFacts = { wifi_stack: box.wifi_stack };
  if (box.board !== null) facts.board = box.board;
  if (box.model !== null) facts.model = box.model;
  if (box.ros_version !== null) facts.ros_version = box.ros_version;
  return facts;
}

/** The largest value of a PostgreSQL `integer` column (`increments` ids). */
export const INT4_MAX = 2_147_483_647;

/** Positive integer from a body field or a route parameter, or a 400. `max`
 *  is the id column's range: an `integer` id by default, so an out-of-range
 *  id is a 400 here instead of a PostgreSQL 22003 surfacing as a 500. A
 *  `bigIncrements` id (template revisions) passes `Number.MAX_SAFE_INTEGER`. */
export function positiveId(raw: unknown, what: string, max: number = INT4_MAX): number {
  const n = typeof raw === 'string' && /^\d{1,16}$/.test(raw.trim()) ? Number(raw.trim()) : raw;
  if (typeof n !== 'number' || !Number.isSafeInteger(n) || n <= 0 || n > max) {
    throw new BenchApiError(400, `Identifiant invalide : « ${what} ».`, 'bad_input');
  }
  return n;
}

// ============================================================================
// The management range — an INSTANCE variable
// ============================================================================

/**
 * The instance variable (config_variables, scope 'instance') that names where
 * ObliWAN reaches the fleet FROM: one or more CIDR prefixes, comma-separated
 * (or a JSON array of them). The compiled access block opens ssh, api and the
 * ObliWAN SNMP community to these prefixes only, and binds the ObliWAN
 * account to them. Unset means the compile is refused: guessing it would
 * either open the box to the world or lock ObliWAN out of it.
 */
export const MANAGEMENT_RANGE_KEY = 'obliwan_management_range';

export type ManagementRange =
  | { ok: true; prefixes: string[] }
  | { ok: false; message: string };

function validPrefix(p: string): boolean {
  const m = /^([0-9A-Fa-f.:]+)\/(\d{1,3})$/.exec(p);
  if (!m) return false;
  const family = net.isIP(m[1]);
  const len = Number(m[2]);
  if (family === 4) return len >= 1 && len <= 32;
  if (family === 6) return len >= 1 && len <= 128;
  return false;
}

/** Judged, never repaired: a malformed entry is named and refused. A prefix
 *  length of 0 is refused too — "the whole internet" is not a management
 *  range, it is the absence of one. */
export function judgeManagementRange(value: unknown): ManagementRange {
  const unset = {
    ok: false as const,
    message: `La variable d'instance « ${MANAGEMENT_RANGE_KEY} » n'est pas définie : ObliWAN ne sait pas depuis quelles adresses il administre la flotte, et refuse de compiler un accès ouvert à tous. Définissez-la (Variables, niveau Instance, par exemple « 10.0.0.0/24 »), puis relancez.`,
  };
  let parts: string[];
  if (typeof value === 'string') parts = value.split(',');
  else if (Array.isArray(value) && value.every((v) => typeof v === 'string')) parts = value as string[];
  else return unset;
  const prefixes = parts.map((p) => p.trim()).filter((p) => p !== '');
  if (prefixes.length === 0) return unset;
  for (const p of prefixes) {
    if (!validPrefix(p)) {
      return {
        ok: false,
        message: `La variable d'instance « ${MANAGEMENT_RANGE_KEY} » contient « ${p.slice(0, 60)} », qui n'est pas un préfixe IP (adresse/longueur, longueur 1 au moins). Corrigez-la, puis relancez.`,
      };
    }
  }
  return { ok: true, prefixes };
}

export async function readManagementRange(q: Knex | Knex.Transaction = db): Promise<ManagementRange> {
  const row = (await q('config_variables')
    .whereNull('tenant_id')
    .whereNull('scope_id')
    .where({ scope: 'instance', key: MANAGEMENT_RANGE_KEY })
    .first('value', 'is_secret')) as { value: unknown; is_secret: boolean } | undefined;
  if (row && row.is_secret) {
    return {
      ok: false,
      message: `La variable d'instance « ${MANAGEMENT_RANGE_KEY} » est enregistrée comme secret : un préfixe d'administration n'en est pas un, et ObliWAN ne le déchiffre pas pour l'écrire dans un routeur. Enregistrez-la en clair, puis relancez.`,
    };
  }
  return judgeManagementRange(row?.value);
}

// ============================================================================
// Tenants and sites
// ============================================================================

export interface BenchTenantView { id: number; name: string; slug: string }
export interface BenchSiteView {
  id: number;
  code: string;
  name: string;
  country: string | null;
  provisioned: boolean;
  /** The outcome of the site's latest bench run, or null when there is none. */
  lastOutcome: 'compiled' | 'applied' | 'failed' | null;
  lastRunAt: string | null;
}

export async function listBenchTenants(): Promise<BenchTenantView[]> {
  const rows = (await db('tenants').orderBy('name').select('id', 'name', 'slug')) as Array<{ id: number; name: string; slug: string }>;
  return rows.map((r) => ({ id: Number(r.id), name: r.name, slug: r.slug }));
}

/** `%`, `_` and `\` are literal in a search typed at the bench. */
function likeLiteral(s: string): string {
  return s.replace(/[\\%_]/g, (c) => `\\${c}`);
}

/**
 * "provisioned" = the bench API has released a configuration file for a
 * device of this site, and the LATEST such run was not reported failed: a
 * site whose last preparation failed is not "already equipped", whatever
 * succeeded before it. A run compiled and never reported still counts, as it
 * always did. `lastOutcome` / `lastRunAt` (additive) say which run decided.
 */
export async function listBenchSites(tenantId: number, search: string): Promise<BenchSiteView[]> {
  const tenant = await db('tenants').where({ id: tenantId }).first('id');
  if (!tenant) throw new BenchApiError(404, `Client #${tenantId} introuvable.`, 'not_found');
  const latest = (column: string): string =>
    `(SELECT b.${column} FROM bench_provisionings b WHERE b.site_id = s.id AND b.tenant_id = s.tenant_id `
    + 'ORDER BY b.compiled_at DESC, b.id DESC LIMIT 1)';
  const q = db('sites as s')
    .where('s.tenant_id', tenantId)
    .select(
      's.id', 's.code', 's.name', 's.country',
      db.raw(`${latest('outcome')} AS last_outcome`),
      db.raw(`${latest('compiled_at')} AS last_run_at`),
    )
    .orderBy('s.code')
    .limit(200);
  const term = search.trim().slice(0, 64);
  if (term !== '') {
    const pattern = `%${likeLiteral(term)}%`;
    // Backslash is PostgreSQL's default LIKE escape, which `likeLiteral` uses.
    q.andWhere((w) => {
      w.where('s.code', 'ilike', pattern).orWhere('s.name', 'ilike', pattern);
    });
  }
  const rows = (await q) as Array<{
    id: number; code: string; name: string; country: string | null; last_outcome: string | null; last_run_at: Date | string | null;
  }>;
  return rows.map((r) => {
    const lastOutcome = r.last_outcome === 'compiled' || r.last_outcome === 'applied' || r.last_outcome === 'failed' ? r.last_outcome : null;
    return {
      id: Number(r.id),
      code: r.code,
      name: r.name,
      country: r.country ?? null,
      provisioned: lastOutcome !== null && lastOutcome !== 'failed',
      lastOutcome,
      lastRunAt: r.last_run_at === null ? null : new Date(r.last_run_at).toISOString(),
    };
  });
}

export interface BenchSiteRow {
  id: number;
  tenant_id: number;
  code: string;
  name: string;
  country: string | null;
  timezone: string;
}

/** The site and its tenant. The station chose the site; its tenant is read
 *  from the site row, never from the request. */
export async function loadBenchSite(siteId: number): Promise<{ site: BenchSiteRow; tenant: BenchTenantView }> {
  const site = (await db('sites')
    .where({ id: siteId })
    .first('id', 'tenant_id', 'code', 'name', 'country', 'timezone')) as BenchSiteRow | undefined;
  if (!site) throw new BenchApiError(404, `Site #${siteId} introuvable.`, 'not_found');
  const tenant = (await db('tenants').where({ id: site.tenant_id }).first('id', 'name', 'slug')) as
    | { id: number; name: string; slug: string }
    | undefined;
  if (!tenant) throw new BenchApiError(404, `Le client du site #${siteId} est introuvable.`, 'not_found');
  return {
    site: { ...site, id: Number(site.id), tenant_id: Number(site.tenant_id) },
    tenant: { id: Number(tenant.id), name: tenant.name, slug: tenant.slug },
  };
}

// ============================================================================
// Template candidates and their bench-level declarations
// ============================================================================

export interface BenchVariableDecl { key: string; label: string; type: string; secret: boolean; required: boolean }

export interface BenchCandidate {
  revisionId: number;
  templateName: string;
  revision: number;
  varSchema: Record<string, unknown>;
  /** The revision's RouterOS window, as published. */
  osMin: string | null;
  osMax: string | null;
}

/** Names the render supplies as fact objects; a revision may declare them at
 *  the bench level to TYPE them, and they are never typed at the bench. */
const FACT_KEYS: ReadonlySet<string> = new Set(['box', 'site']);
const SCALAR_TYPES: ReadonlySet<string> = new Set(['string', 'integer', 'number', 'boolean']);

/** The variables a revision expects to be typed at the bench: declared
 *  `x-obliwan-level: 'bench'`, scalar, not a fact object. */
export function benchDeclarationsOf(varSchema: unknown): BenchVariableDecl[] {
  if (!isRecord(varSchema) || !isRecord(varSchema.properties)) return [];
  const required = new Set(Array.isArray(varSchema.required) ? varSchema.required.filter((k): k is string => typeof k === 'string') : []);
  const out: BenchVariableDecl[] = [];
  for (const [key, prop] of Object.entries(varSchema.properties)) {
    if (!isRecord(prop) || prop['x-obliwan-level'] !== 'bench' || FACT_KEYS.has(key)) continue;
    const type = typeof prop.type === 'string' ? prop.type : 'string';
    if (!SCALAR_TYPES.has(type)) continue;
    out.push({
      key,
      label: typeof prop['x-obliwan-label'] === 'string' && prop['x-obliwan-label'] ? prop['x-obliwan-label'] : key,
      type,
      secret: prop['x-obliwan-secret'] === true,
      required: required.has(key),
    });
  }
  return out.sort((a, b) => a.key.localeCompare(b.key));
}

/** A revision left out for ONE reason only: the box's RouterOS is below its
 *  `os_min`. Upgrading RouterOS is what would make it a candidate. */
export interface BelowOsMinRevision {
  templateName: string;
  osMin: string;
  osMax: string | null;
}

/**
 * The published revisions this box may receive for this tenant: an active
 * MikroTik template of the tenant's own or of the shipped library, whose model
 * pattern matches the box and whose OS window admits its version. The same
 * rules `renderForSite` enforces (`assertRevisionFitsBox`), applied here so
 * that a candidate offered at the bench is one the compile will accept.
 * `excluded` explains, in French, every revision left out for this box;
 * `belowOsMin` lists those of them an upgrade of RouterOS would admit.
 */
export async function listBenchCandidates(
  tenantId: number,
  box: Pick<BenchBoxInput, 'model' | 'ros_version'>,
): Promise<{ candidates: BenchCandidate[]; excluded: string[]; belowOsMin: BelowOsMinRevision[] }> {
  const rows = (await db('template_revisions as r')
    .join('templates as t', 't.id', 'r.template_id')
    .where('r.status', 'published')
    .andWhere('t.status', 'active')
    .andWhere('t.brand', 'mikrotik')
    .andWhere((w) => {
      w.where('r.tenant_id', tenantId).orWhereNull('r.tenant_id');
    })
    .orderBy([{ column: 't.name' }, { column: 'r.revision', order: 'desc' }])
    .select(
      'r.id as id', 'r.revision as revision', 'r.var_schema as var_schema', 'r.os_min as os_min',
      'r.os_max as os_max', 't.name as template_name', 't.model_pattern as model_pattern',
    )) as Array<{
      id: string | number; revision: number; var_schema: unknown; os_min: string | null; os_max: string | null;
      template_name: string; model_pattern: string | null;
    }>;
  const candidates: BenchCandidate[] = [];
  const excluded: string[] = [];
  const belowOsMin: BelowOsMinRevision[] = [];
  for (const r of rows) {
    const name = `${r.template_name} (révision ${r.revision})`;
    if (r.model_pattern && box.model === null) {
      excluded.push(`« ${name} » vise les modèles « ${r.model_pattern} » et le modèle du routeur n'a pas pu être lu : il n'est pas proposé.`);
      continue;
    }
    if (!modelMatches(r.model_pattern, box.model)) {
      excluded.push(`« ${name} » vise les modèles « ${r.model_pattern} », ce routeur est un « ${box.model} » : il n'est pas proposé.`);
      continue;
    }
    const os = satisfiesOsWindow(box.ros_version, r.os_min, r.os_max);
    if (!os.ok) {
      if (os.reason === 'os_below_min' && box.ros_version !== null && upgradeWouldAdmit(box.ros_version, r.os_min, r.os_max)) {
        belowOsMin.push({ templateName: r.template_name, osMin: r.os_min as string, osMax: r.os_max });
      }
      const window = [r.os_min ? `≥ ${r.os_min}` : null, r.os_max ? `≤ ${r.os_max}` : null].filter(Boolean).join(' et ');
      excluded.push(
        box.ros_version
          ? `« ${name} » exige RouterOS ${window}, ce routeur est en ${box.ros_version} : il n'est pas proposé.`
          : `« ${name} » exige RouterOS ${window} et la version du routeur n'a pas pu être lue : il n'est pas proposé.`,
      );
      continue;
    }
    candidates.push({
      revisionId: Number(r.id),
      templateName: r.template_name,
      revision: Number(r.revision),
      varSchema: isRecord(r.var_schema) ? r.var_schema : {},
      osMin: r.os_min,
      osMax: r.os_max,
    });
  }
  return { candidates, excluded, belowOsMin };
}

/**
 * `os_below_min` is also what `satisfiesOsWindow` answers when the comparison
 * could not be MADE (an `os_min` that does not parse): no upgrade cures that.
 * Nor one whose window is empty (`os_max` below `os_min`). So the version is
 * compared again here, and only a box that is measurably below a reachable
 * window counts.
 */
function upgradeWouldAdmit(version: string, osMin: string | null, osMax: string | null): boolean {
  if (osMin === null) return false;
  const below = compareOsVersions(version, osMin);
  if (below === null || below >= 0) return false;
  if (osMax === null) return true;
  const window = compareOsVersions(osMin, osMax);
  return window !== null && window <= 0;
}

/**
 * The RouterOS upgrade the plan offers the bench, or null.
 *
 * REQUIRED when NOTHING can be compiled for this box as it is, and at least
 * one published revision was left out for its RouterOS alone — model matched,
 * version read, window reachable (`belowOsMin`). A box refused for its model,
 * or whose version could not be read, is not offered one: it would not make
 * anything compilable. `minimum` is then the smallest such `os_min`;
 * `maximum` the largest `os_max` among them (null when one has none), and
 * `templates` their names.
 *
 * OPTIONAL (`required: false`, `minimum: null`) when candidates exist and the
 * box runs below the fleet target.
 *
 * `target` is THE fleet target (`resolveRouterOsFleetTarget`, an instance
 * decision), never a version chosen here — and it is withheld (null, with a
 * warning saying why) when it is unknown, below `minimum`, or admitted by none
 * of the revisions it is meant to unlock (required) or keep (optional):
 * proposing it would trade "too old" for "too new", or would not unlock
 * anything. Even an admitted target does not guarantee a candidate afterwards;
 * the bench asks for the plan again after the upgrade, and that answer decides.
 *
 * `packages`: one URL per package name the bench sent (`box.packages`), built
 * with the shared `tryRouterOsPackageUrl` for the box's architecture — null
 * when the bench sent no names (it then builds them itself with the same
 * helper), when the architecture is not one the shared allow-list knows, or
 * when the box is not on RouterOS 7 (a 6 -> 7 upgrade does not keep package
 * names: v7 merged and split them).
 */
export interface BenchUpgradeView {
  required: boolean;
  minimum: string | null;
  maximum: string | null;
  /** Template names, once each, in the order the plan listed them (required only). */
  templates: string[];
  target: { version: string; source: 'fleet_target'; stale: boolean } | null;
  packages: Array<{ name: string; url: string }> | null;
  /** The package architecture of the box, or null when not recognised. */
  arch: RouterOsPackageArch | null;
}

/** The fleet target as the plan reads it (`RouterOsTargetStatus`, narrowed). */
export interface FleetTargetFacts {
  resolved: string | null;
  unresolvedReason: string | null;
  stale: boolean;
}

export function benchUpgradeView(input: {
  candidates: Array<Pick<BenchCandidate, 'osMin' | 'osMax'>>;
  belowOsMin: BelowOsMinRevision[];
  box: Pick<BenchBoxInput, 'ros_version' | 'architecture' | 'packages'>;
  fleet: FleetTargetFacts;
}): { upgrade: BenchUpgradeView | null; warnings: string[] } {
  const { candidates, belowOsMin, box, fleet } = input;
  const warnings: string[] = [];
  const required = candidates.length === 0 && belowOsMin.length > 0;
  let minimum: string | null = null;
  let maximum: string | null = null;
  if (required) {
    minimum = belowOsMin[0].osMin;
    maximum = belowOsMin[0].osMax;
    let unbounded = belowOsMin[0].osMax === null;
    for (const r of belowOsMin.slice(1)) {
      if ((compareOsVersions(r.osMin, minimum) ?? 0) < 0) minimum = r.osMin;
      if (r.osMax === null) unbounded = true;
      else if (maximum === null || (compareOsVersions(r.osMax, maximum) ?? 0) > 0) maximum = r.osMax;
    }
    if (unbounded) maximum = null;
  }
  const target = fleet.resolved;
  const below = target !== null && box.ros_version !== null ? compareOsVersions(box.ros_version, target) : null;
  if (!required && (target === null || below === null || below >= 0)) return { upgrade: null, warnings };

  let offered: BenchUpgradeView['target'] = null;
  if (target === null) {
    warnings.push(
      `Aucune version cible de RouterOS n’est connue pour la flotte (${fleet.unresolvedReason ?? 'raison inconnue'}) : la mise à jour exigée ne peut pas être proposée. Un administrateur doit vérifier la version cible (Micrologiciel).`,
    );
  } else if (required && (compareOsVersions(target, minimum as string) ?? -1) < 0) {
    warnings.push(
      `La version cible de la flotte (RouterOS ${target}) est inférieure au minimum exigé par les modèles (${minimum}) : elle n’est pas proposée. Un administrateur doit relever la version cible ou corriger les modèles.`,
    );
  } else {
    const windows = required ? belowOsMin : candidates;
    if (!windows.some((w) => satisfiesOsWindow(target, w.osMin, w.osMax).ok)) {
      warnings.push(
        required
          ? `La version cible de la flotte (RouterOS ${target}) n’est admise par aucun des modèles qui l’exigent : elle n’est pas proposée.`
          : `La version cible de la flotte (RouterOS ${target}) n’est admise par aucun des modèles proposés pour ce routeur : la mise à jour n’est pas proposée.`,
      );
    } else {
      offered = { version: target, source: 'fleet_target', stale: fleet.stale };
    }
  }
  if (!required && offered === null) return { upgrade: null, warnings };

  const arch = routerOsPackageArchFromResource(box.architecture);
  const major = box.ros_version !== null ? /^(\d+)\./.exec(box.ros_version)?.[1] ?? null : null;
  let packages: BenchUpgradeView['packages'] = null;
  const names = box.packages ?? null;
  if (offered !== null && arch !== null && major === '7' && names !== null && names.length > 0) {
    const built = names.map((name) => ({ name, r: tryRouterOsPackageUrl(offered.version, name, arch) }));
    packages = built.every((b) => b.r.ok) ? built.map((b) => ({ name: b.name, url: (b.r as { ok: true; url: string }).url })) : null;
  }
  return {
    upgrade: {
      required,
      minimum,
      maximum,
      templates: required ? Array.from(new Set(belowOsMin.map((r) => r.templateName))) : [],
      target: offered,
      packages,
      arch,
    },
    warnings,
  };
}

/** The fleet target, or "unknown" when it cannot be read: the plan still
 *  answers, without an upgrade target. */
async function readFleetTarget(): Promise<FleetTargetFacts> {
  try {
    const t = await resolveRouterOsFleetTarget();
    return { resolved: t.resolved, unresolvedReason: t.unresolvedReason, stale: t.stale };
  } catch (err) {
    logger.warn({ err }, 'Bench plan: the RouterOS fleet target could not be read');
    return { resolved: null, unresolvedReason: 'TARGET_UNREADABLE', stale: false };
  }
}

// ============================================================================
// What the plan warns about and the compile refuses — one judgement for both
// ============================================================================

/** The lines of a text that configure something: nunjucks `{# … #}` comments
 *  and RouterOS `#` comment lines name a stack without configuring it. */
function configuredLines(text: string): string[] {
  return text
    .replace(/\{#[\s\S]*?#\}/g, '')
    .replace(/\r\n?/g, '\n')
    .split('\n')
    .filter((l) => !l.trim().startsWith('#'));
}

const OTHER_STACK = {
  wifi: {
    label: 'wireless',
    menu: /\/interface[ /]wireless\b/,
    radio: /\b(?:[a-z-]*interfaces?|name|default-name)="?wlan\d+\b/,
  },
  wireless: {
    label: 'wifi',
    menu: /\/interface[ /]wifi(?:wave2)?\b/,
    radio: /\b(?:[a-z-]*interfaces?|name|default-name)="?wifi\d+\b/,
  },
} as const;

/**
 * The Wi-Fi stack a text configures that the box does NOT have, as a French
 * clause, or null. A `wifi` box has `/interface wifi` and `wifiN`, a
 * `wireless` box `/interface wireless` and `wlanN`; a file naming the other
 * stack's menu or radios configures interfaces the box does not have, so the
 * box would leave the bench without the configuration it was prepared for.
 */
export function wifiStackMismatch(text: string, stack: 'wifi' | 'wireless'): string | null {
  const other = OTHER_STACK[stack];
  const hit = configuredLines(text).some((l) => other.menu.test(l) || other.radio.test(l));
  return hit
    ? `il configure la pile Wi-Fi « ${other.label} » (/interface ${other.label}) alors que ce routeur utilise la pile « ${stack} »`
    : null;
}

/** What the compile needs to know about a device of the site it may take over. */
export interface SiteDeviceFacts {
  id: number;
  status: string;
  is_managed: boolean;
  /** A `bench_provisionings` row names it: the bench prepared it. */
  bench_prepared: boolean;
}

/**
 * Whether a compile may take over a device of the site, or the French refusal.
 * REUSE: the same box (same site, same serial) gets the new identity and a new
 * vault credential. RETIRE: another device of the site holds the PPP login the
 * allocation gives this box; it is disabled and its login and tunnel address
 * cleared.
 *
 * A device a human confirmed (`active`, `quarantined`) or marked managed is
 * never taken over by a compile: that would cut a live router off presence,
 * polling and its working credential, from a bench desk. `disabled` is the
 * operator's own statement that it is out of service, and the refusal names
 * that operation. A `pending`, unmanaged device is reused when it is the same
 * box, and retired only when the bench prepared it (an unconfirmed earlier
 * bench box, never a discovered or enrolled one).
 */
export function takeoverRefusal(d: SiteDeviceFacts, role: 'reuse' | 'retire'): string | null {
  if (d.status === 'disabled') return null;
  if (d.status === 'pending' && !d.is_managed && (role === 'reuse' || d.bench_prepared)) return null;
  const state = `statut « ${d.status} »${d.is_managed ? ', géré par ObliWAN' : ''}${d.bench_prepared ? '' : ', non préparé au banc'}`;
  const what = role === 'reuse'
    ? `Ce routeur est déjà enregistré pour ce site (appareil #${d.id}, ${state}) : le préparer remplacerait l’identifiant qu’ObliWAN utilise pour le joindre.`
    : `Le compte PPP de ce site est porté par l’appareil #${d.id} (${state}) : le préparer le couperait d’ObliWAN.`;
  return `${what} Si ce routeur est bien remplacé ou réinitialisé, passez le statut de l’appareil #${d.id} à « désactivé » (disabled) dans sa fiche ObliWAN, puis relancez.`;
}

// ============================================================================
// The plan
// ============================================================================

export interface BenchPlanCandidateView {
  revisionId: number;
  templateName: string;
  revision: number;
  /** The device-mode features this revision uses for this box, sorted. */
  deviceModeFeatures: string[];
  /** 'render': read off a redacted render for this box and site (exact for
   *  the values known at plan time). 'template': no render could be made yet
   *  (a required bench value is typed only at the compile), so read off the
   *  revision's sources, both branches of every condition counted
   *  (`deviceModeFeaturesOfSources`). The compile judges its own render. */
  deviceModeFeaturesFrom: 'render' | 'template';
  /** Those of them the box's reading denies: the compile refuses them unless
   *  the bench declares `deviceModeOverride`. */
  deviceModeDenied: string[];
  /** Why the compile WILL refuse this revision for this box, in French. */
  blocking: string[];
}

export interface BenchPlanView {
  site: { id: number; code: string; name: string; country: string | null; timezone: string };
  tenant: BenchTenantView;
  candidates: BenchPlanCandidateView[];
  benchVariables: BenchVariableDecl[];
  allocation: { ppp_username: string | null; tunnel_ip: string | null; lan_subnet: string | null; system_identity: string | null };
  warnings: string[];
  /** The sentences of `warnings` that WILL refuse the compile whatever
   *  revision is chosen: the bench disables the compile while one remains. */
  blocking: string[];
  /** The device of this site a compile would retire (disable, login and
   *  address moved to this box), or null. The compile then requires
   *  `confirmReplaceDeviceId` equal to `deviceId`. */
  replaces: { deviceId: number; message: string } | null;
  /** See `benchUpgradeView`. Null when no upgrade is required or offered. */
  upgrade: BenchUpgradeView | null;
}

/** The value a computed SECRET is given in a REDACTED render only: the
 *  redacted context carries the secret's placeholder in its place
 *  (variableResolver `lay`), so this text never reaches the output; it only
 *  makes the variable "supplied". A pattern it does not match refuses the
 *  render, which the callers treat as "no render". */
const REDACTED_STAND_IN = 'ObliwanRedactedStandIn00';

/**
 * A REDACTED render of `candidate` for this site and box, or null when none
 * can be made with what is known (the render refused: a value missing or
 * mistyped, the Wi-Fi stack unknown…; or failed otherwise, which is logged).
 * Writes nothing and holds no secret: the plan and the compile use it to read
 * the device-mode features BEFORE anything is committed — advice, since the
 * compile judges its own secrets-mode render again after the commit.
 */
export async function preRenderRedacted(p: {
  tenantId: number;
  siteId: number;
  candidate: BenchCandidate;
  computed: Record<string, unknown>;
  bench: Record<string, unknown>;
  box: BenchBoxInput;
}): Promise<string | null> {
  const facts = boxFactsOf(p.box);
  if (facts === null) return null;
  const computed = { ...p.computed };
  const props = (isRecord(p.candidate.varSchema.properties) ? p.candidate.varSchema.properties : {}) as Record<string, unknown>;
  const ppp = props.ppp_password;
  if (isRecord(ppp) && ppp['x-obliwan-level'] === 'computed' && ppp['x-obliwan-secret'] === true) {
    computed.ppp_password = REDACTED_STAND_IN;
  }
  try {
    const r = await renderForSite({
      tenantId: p.tenantId,
      siteId: p.siteId,
      revisionId: p.candidate.revisionId,
      computed,
      bench: p.bench,
      box: facts,
      mode: 'redacted',
    });
    return r.redacted;
  } catch (err) {
    if (!(err instanceof SiteRenderError)) {
      logger.warn({ err, revisionId: p.candidate.revisionId }, 'Bench: a redacted pre-render failed; its device-mode features are read otherwise');
    }
    return null;
  }
}

/**
 * The device-mode features a revision's SOURCES use, both branches of every
 * condition counted (`deviceModeFeaturesOfSources`), or null when its sources
 * could not be loaded (logged). For when no render can be made.
 */
export async function revisionSourceFeatures(revisionId: number): Promise<string[] | null> {
  try {
    return deviceModeFeaturesOfSources((await loadRevisionBundle(revisionId)).sources);
  } catch (err) {
    logger.warn({ err, revisionId }, 'Bench: a revision\'s sources could not be loaded to read its device-mode features');
    return null;
  }
}

/** Why a compile refuses a box whose serial a MikroTik device of another
 *  site holds (`serial_taken`), in French. Another tenant's device is not
 *  named. */
export function serialTakenReason(holderId: number, sameTenant: boolean): string {
  return sameTenant
    ? `Ce numéro de série est déjà enregistré pour l’appareil #${holderId}, rattaché à un autre site de ce client. Rattachez-le à ce site, ou supprimez-le, dans sa fiche ObliWAN, puis relancez.`
    : 'Ce numéro de série est déjà enregistré sur la plateforme (un autre client, ou un enrôlement en attente). Demandez à un administrateur de le retrouver dans la liste des appareils.';
}

/** Why a compile refuses a site whose PPP login a device of another site
 *  holds (`ppp_taken`), in French. */
export const PPP_TAKEN_REASON =
  'Le compte PPP alloué à ce site est déjà porté par un appareil d’un autre site. Un administrateur doit corriger l’inventaire.';

/** The compile's device-mode refusal, in French. `committed`: the site's
 *  allocation was already committed when the refusal was decided.
 *  `fromSources`: no render could be made, and the revision's text decided
 *  (every branch of its conditions counted). */
export function deviceModeRefusal(
  templateName: string,
  denied: string[],
  reading: BenchDeviceModeReading | null,
  committed: boolean,
  fromSources = false,
): BenchApiError {
  return new BenchApiError(
    409,
    `Ce routeur interdit, par son mode appareil (« ${reading?.mode ?? 'inconnu'} »), ${featureList(denied)}, `
      + (fromSources
        ? `que le texte du modèle « ${templateName} » utilise (aucun rendu n’a pu être fait avant la réservation : chaque branche de ses conditions est comptée) : la compilation est refusée. `
        : `dont le modèle « ${templateName} » a besoin : la compilation est refusée. `)
      + (committed
        ? 'Rien n’est enregistré pour ce routeur ; seul l’adressage du site, déjà réservé, est conservé. '
        : 'Rien n’a été enregistré ni réservé. ')
      + 'Pour l’autoriser : demandez le changement de mode appareil depuis le banc, puis, dans les 5 minutes, '
      + 'appuyez brièvement sur le bouton Reset (ou Mode) du routeur, ou coupez puis rétablissez son alimentation ; '
      + 'relancez ensuite l’identification du routeur. Pour un essai à distance, la compilation peut être forcée '
      + '(dérogation au mode appareil) : les lignes concernées échoueront alors seules, et la préparation sera signalée en échec.',
    'device_mode_denied',
  );
}

/** The bench-level variables of every candidate, once per key. A key one
 *  candidate requires is reported required: the bench asks for it, and the
 *  compile keeps only what the CHOSEN revision declares. */
export function unionDeclarations(candidates: BenchCandidate[]): BenchVariableDecl[] {
  const byKey = new Map<string, BenchVariableDecl>();
  for (const c of candidates) {
    for (const d of benchDeclarationsOf(c.varSchema)) {
      const prev = byKey.get(d.key);
      byKey.set(d.key, prev
        ? { ...prev, secret: prev.secret || d.secret, required: prev.required || d.required }
        : d);
    }
  }
  return [...byKey.values()].sort((a, b) => a.key.localeCompare(b.key));
}

export async function planForBox(siteId: number, box: BenchBoxInput): Promise<BenchPlanView> {
  const { site, tenant } = await loadBenchSite(siteId);
  const warnings: string[] = [];
  const blocking: string[] = [];
  /** A warning the compile WILL refuse on, whatever revision is chosen. */
  const refused = (sentence: string): void => {
    warnings.push(sentence);
    blocking.push(sentence);
  };

  const { candidates, excluded, belowOsMin } = await listBenchCandidates(tenant.id, box);
  if (candidates.length === 0) {
    refused(
      `Aucun modèle de configuration publié ne convient à ce routeur pour le client « ${tenant.name} » ` +
        `(modèle ${box.model ?? 'inconnu'}, RouterOS ${box.ros_version ?? 'inconnu'}) : rien ne peut être compilé.`,
    );
  }
  warnings.push(...excluded);
  if (box.wifi_stack === null) {
    refused("La pile Wi-Fi du routeur (« wifi » ou « wireless ») n'a pas pu être lue : la compilation sera refusée tant qu'elle ne l'est pas.");
  }
  if (box.ros_version === null) {
    refused("La version de RouterOS du routeur n'a pas pu être lue : la compilation sera refusée tant qu'elle ne l'est pas.");
  }

  const mgmt = await readManagementRange();
  if (!mgmt.ok) refused(mgmt.message);

  let allocation: BenchPlanView['allocation'] = { ppp_username: null, tunnel_ip: null, lan_subnet: null, system_identity: null };
  let previewValues: Record<string, unknown> | null = null;
  try {
    const pv = await previewForSite(tenant.id, site.id);
    allocation = {
      ppp_username: pv.ppp_username,
      tunnel_ip: pv.tunnel_ip,
      lan_subnet: pv.lan_subnet,
      system_identity: pv.system_identity,
    };
    previewValues = pv.values;
    if (pv.blockedBy) refused(`Allocation bloquée : ${pv.blockedBy.message}`);
    if (pv.system_identity === null) {
      refused("Aucune identité système n'est prévue pour ce site (politique d'allocation du client sans modèle d'identité) : la compilation sera refusée.");
    }
  } catch (err) {
    if (!(err instanceof AllocationError)) throw err;
    refused(`L'adressage de ce site ne peut pas être calculé : ${err.message}`);
  }

  // Per candidate: the other Wi-Fi stack and the device-mode features. Both
  // are read off a redacted render for this box when one can be made — what
  // the compile itself judges, but for the bench values typed only at the
  // compile — and otherwise off the revision's text: its entry body for the
  // Wi-Fi stack (when it never reads `box.wifi_stack`), its sources, every
  // branch counted, for the device-mode.
  const views: BenchPlanCandidateView[] = [];
  const bodies = candidates.length === 0 ? [] : (await db('template_revisions')
    .whereIn('id', candidates.map((c) => c.revisionId))
    .select('id', 'body')) as Array<{ id: string | number; body: string }>;
  for (const c of candidates) {
    const candidateBlocking: string[] = [];
    const redacted = previewValues === null ? null : await preRenderRedacted({
      tenantId: tenant.id, siteId: site.id, candidate: c, computed: previewValues, bench: {}, box,
    });
    const body = bodies.find((b) => Number(b.id) === c.revisionId)?.body ?? '';
    const mismatch = box.wifi_stack === null
      ? null
      : redacted !== null
        ? wifiStackMismatch(redacted, box.wifi_stack)
        : body.includes('wifi_stack') ? null : wifiStackMismatch(body, box.wifi_stack);
    if (mismatch) {
      const sentence = `« ${c.templateName} (révision ${c.revision}) » : ${mismatch}. La compilation de ce modèle sera refusée pour ce routeur.`;
      warnings.push(sentence);
      candidateBlocking.push(sentence);
    }
    let features: string[];
    let from: 'render' | 'template';
    if (redacted !== null) {
      features = deviceModeFeaturesOf(redacted);
      from = 'render';
    } else {
      from = 'template';
      const fromSources = await revisionSourceFeatures(c.revisionId);
      if (fromSources === null) {
        // The compile's own render will refuse such a revision; the plan says
        // it could not tell rather than claim the revision needs nothing.
        warnings.push(`« ${c.templateName} (révision ${c.revision}) » : les fonctions du mode appareil qu’il utilise n’ont pas pu être lues ; la compilation les vérifiera.`);
      }
      features = fromSources ?? [];
    }
    const denied = deniedFeatures(box.deviceMode ?? null, features);
    if (denied.length > 0) {
      // Certain only when the render was made with every value the compile
      // will have: a revision declaring no bench value. Otherwise a value
      // typed at the compile (or, from the sources, an untaken branch) may
      // drop the need — the compile judges its own render.
      const certain = from === 'render' && benchDeclarationsOf(c.varSchema).length === 0;
      warnings.push(
        `« ${c.templateName} (révision ${c.revision}) » ${certain ? 'a besoin' : 'peut avoir besoin'} de ${featureList(denied)}, que le mode appareil de ce routeur `
          + `(« ${box.deviceMode?.mode ?? 'inconnu'} ») interdit : `
          + (certain
            ? 'la compilation sera refusée, sauf dérogation au mode appareil pour un essai à distance.'
            : `${from === 'render' ? 'd’après un rendu fait sans les valeurs saisies au banc' : 'd’après son texte, chaque branche de ses conditions comptée'} ; la compilation vérifiera son propre rendu et le refusera s’il en a besoin, sauf dérogation au mode appareil pour un essai à distance.`),
      );
    }
    views.push({
      revisionId: c.revisionId,
      templateName: c.templateName,
      revision: c.revision,
      deviceModeFeatures: features,
      deviceModeFeaturesFrom: from,
      deviceModeDenied: denied,
      blocking: candidateBlocking,
    });
  }
  // Each candidate refused on its own: whichever is chosen, the compile is.
  if (views.length > 0 && views.every((v) => v.blocking.length > 0)) {
    refused(views.length === 1
      ? 'Le seul modèle candidat sera refusé pour ce routeur (raison ci-dessus) : rien ne peut être compilé.'
      : `Les ${views.length} modèles candidats seront tous refusés pour ce routeur (raisons ci-dessus) : rien ne peut être compilé.`);
  }

  // Every device of the site the compile would take over or leave beside the
  // new box — whatever created it (discovery, import, enrolment, the bench).
  const siteDevices = (await db('devices as d')
    .where({ 'd.tenant_id': tenant.id, 'd.site_id': site.id })
    .orderBy('d.id')
    .select(
      'd.id as id', 'd.status as status', 'd.is_managed as is_managed', 'd.serial as serial', 'd.ppp_username as ppp_username',
      db.raw('EXISTS (SELECT 1 FROM bench_provisionings b WHERE b.device_id = d.id) AS bench_prepared'),
    )) as Array<SiteDeviceFacts & { serial: string | null; ppp_username: string | null }>;
  let replaces: BenchPlanView['replaces'] = null;
  for (const d of siteDevices) {
    const facts: SiteDeviceFacts = { id: Number(d.id), status: d.status, is_managed: d.is_managed === true, bench_prepared: d.bench_prepared === true };
    if (box.serial !== null && d.serial === box.serial) {
      const refusal = takeoverRefusal(facts, 'reuse');
      if (refusal) refused(`La compilation sera refusée. ${refusal}`);
      else warnings.push(`Ce routeur est déjà enregistré pour ce site (appareil #${facts.id}) : il sera repris, et sa configuration recompilée.`);
    } else if (allocation.ppp_username !== null && d.ppp_username === allocation.ppp_username) {
      const refusal = takeoverRefusal(facts, 'retire');
      if (refusal) {
        refused(`La compilation sera refusée. ${refusal}`);
      } else {
        const message = `Ce site a déjà un routeur (appareil #${facts.id}) : il sera remplacé par celui-ci, et désactivé.`;
        warnings.push(message);
        replaces = { deviceId: facts.id, message };
      }
    } else if (facts.status === 'active' || facts.status === 'quarantined' || (facts.is_managed && facts.status !== 'disabled')) {
      warnings.push(`Ce site a déjà un appareil confirmé (appareil #${facts.id}, statut « ${facts.status} ») : la préparation n’y touche pas ; vérifiez qu’il ne s’agit pas du routeur que celui-ci remplace.`);
    }
  }
  // What the compile's takeover check refuses BEYOND this site, read the same
  // way (compile.service `inspectTakeover`): the box's serial held by a
  // MikroTik device of another site, and the site's PPP login held by a
  // device of another site.
  let reusedId: number | null = null;
  if (box.serial !== null) {
    const serial = box.serial;
    const sameSiteMikrotik = (await db('devices')
      .where({ tenant_id: tenant.id, site_id: site.id, brand: 'mikrotik', serial })
      .orderBy('id')
      .first('id')) as { id: number } | undefined;
    if (sameSiteMikrotik) {
      reusedId = Number(sameSiteMikrotik.id);
    } else {
      const holder = (await db('devices').where({ brand: 'mikrotik', serial }).orderBy('id').first('id', 'tenant_id')) as
        | { id: number; tenant_id: number }
        | undefined;
      if (holder) refused(`La compilation sera refusée. ${serialTakenReason(Number(holder.id), Number(holder.tenant_id) === tenant.id)}`);
    }
  }
  if (allocation.ppp_username !== null) {
    const pppHolder = (await db('devices')
      .where({ ppp_username: allocation.ppp_username })
      .modify((b) => { if (reusedId !== null) b.whereNot('id', reusedId); })
      .orderBy('id')
      .first('id', 'tenant_id', 'site_id')) as { id: number; tenant_id: number; site_id: number | null } | undefined;
    if (pppHolder && (Number(pppHolder.tenant_id) !== tenant.id || Number(pppHolder.site_id) !== site.id)) {
      refused(`La compilation sera refusée. ${PPP_TAKEN_REASON}`);
    }
  }

  const upgrade = benchUpgradeView({ candidates, belowOsMin, box, fleet: await readFleetTarget() });
  warnings.push(...upgrade.warnings);

  return {
    site: { id: site.id, code: site.code, name: site.name, country: site.country ?? null, timezone: site.timezone },
    tenant,
    candidates: views,
    benchVariables: unionDeclarations(candidates),
    allocation,
    warnings,
    blocking,
    replaces,
    upgrade: upgrade.upgrade,
  };
}
