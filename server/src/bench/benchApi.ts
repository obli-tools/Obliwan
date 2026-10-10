import {
  compareRouterOsVersion,
  isRouterOsPackageArch,
  isRouterOsReleaseVersion,
  parseRouterOsVersion,
} from '@obliwan/shared';
import type { BenchStation } from './station';

/**
 * ObliWAN bench — the client side of the bench HTTP contract.
 *
 *   GET  /api/bench/v1/tenants                       -> { data: [{ id, name, slug }] }
 *   GET  /api/bench/v1/tenants/:tenantId/sites?search= -> { data: [{ id, code, name, country, provisioned }] }
 *   POST /api/bench/v1/plan     { siteId, box }      -> { data: { site, tenant, candidates, benchVariables, allocation, warnings, upgrade } }
 *        `box` also carries, additively, what the bench read: `deviceMode`
 *        { mode, flags, observedAt }, `packages` (installed package names)
 *        and `architecture` (`architecture-name`).
 *        `upgrade` (additive; absent from a server built before it, which
 *        reads as null): { required, minimum, target: { version, source:
 *        'fleet_target' }, packages: [{ name, url }] | null, arch } when
 *        nothing can be compiled for this box only because its RouterOS is
 *        below `minimum` — the older shape { required, minimum, maximum,
 *        templates } is read too. `candidates[i].deviceModeFeatures` (additive)
 *        lists the device-mode features the rendered revision needs.
 *        `replaces` (additive; absent from a server built before it, which
 *        reads as null): { deviceId, message } — the device of this site the
 *        compile would retire (disabled, its login and address moved to this
 *        box). The compile then requires `confirmReplaceDeviceId` = deviceId.
 *   POST /api/bench/v1/compile  { siteId, revisionId, box, bench, deviceModeOverride?, confirmReplaceDeviceId? }
 *        -> { data: { fileName, content, sha256, tag, deviceId, concentrator, files?, testOverride?, warnings? } }
 *        `confirmReplaceDeviceId` is sent only when the operator confirmed the
 *        plan's `replaces`; the server refuses a compile that would retire a
 *        device without it, or with another device's id.
 *        `files` [{ name, content, sha256, role: 'runner'|'body' }] when the
 *        body is split (the single `content` stays, for older benches);
 *        `testOverride` echoes a declared `deviceModeOverride`; `warnings`
 *        (additive; absent from an older server, read as none) are sentences
 *        that refused nothing — a default group the platform could not apply.
 *   POST /api/bench/v1/devices/:deviceId/result { status, detail, localCheck?, deviceModeOverride?, sim? } -> { data: { ok: true } }
 *        `sim` (additive): { iccid, imsi } read in the box's modem, or null
 *        for "read, and no SIM found"; absent when nothing was read.
 *
 * Every call carries `Authorization: Bench <token>` from `BenchStation` — the
 * token registered at THIS URL and no other — and follows no redirect, for the
 * reason `station.ts` gives: a followed 307/308 re-sends the request (the
 * compile body holds the SIM PIN, the compile ANSWER holds every secret of the
 * site) to wherever `Location` points.
 *
 * Every answer is read defensively. A field of the wrong type is a refusal
 * naming the field, never a default: a missing `sha256` read as "" would make
 * the integrity check compare two empty strings.
 */

export type BenchApiErrorKind =
  /** No answer: network, DNS, timeout. */
  | 'unreachable'
  /** A 3xx, not followed. */
  | 'redirected'
  /** 401 / 403: the platform refuses this workstation (pending, revoked, unknown). */
  | 'station'
  /** Any other refusal (400, 404, 409, 422, 5xx…), with the server's sentence. */
  | 'refused'
  /** A 2xx whose body is not the shape the contract describes. */
  | 'invalid'
  /** THIS workstation failed before anything was sent (the station file
   *  could not be read or written). Never reported as the platform's answer. */
  | 'local';

export class BenchApiError extends Error {
  readonly kind: BenchApiErrorKind;
  readonly status: number | null;
  constructor(kind: BenchApiErrorKind, status: number | null, message: string) {
    super(message);
    this.name = 'BenchApiError';
    this.kind = kind;
    this.status = status;
  }
}

export interface BenchBox {
  brand: 'mikrotik';
  model: string | null;
  board: string | null;
  serial: string | null;
  ros_version: string | null;
  wifi_stack: 'wifi' | 'wireless' | null;
  mac: string;
  /** `/system/device-mode/print` as read; mode null and no flags when the
   *  menu did not answer. */
  deviceMode?: { mode: string | null; flags: Record<string, boolean>; observedAt: string };
  /** Installed package names (`/system/package/print`). */
  packages?: string[];
  /** `/system/resource` `architecture-name`, verbatim. */
  architecture?: string | null;
}

export interface BenchTenant { id: number; name: string; slug: string }
export interface BenchSite { id: number; code: string | null; name: string; country: string | null; provisioned: boolean }
export interface BenchCandidate {
  revisionId: number;
  templateName: string;
  revision: number | string | null;
  /** The device-mode features the rendered revision needs on this box;
   *  `null` when the server did not say (a server built before it). */
  deviceModeFeatures: string[] | null;
}
export interface BenchVariable { key: string; label: string; type: string; secret: boolean; required: boolean }
export interface BenchAllocation {
  ppp_username: string | null;
  tunnel_ip: string | null;
  lan_subnet: string | null;
  system_identity: string | null;
  /** The router's own LAN address, when the server sends it (additive). */
  lan_router_ip: string | null;
}
/** The platform's answer to "nothing fits this box until its RouterOS is upgraded". */
export interface BenchUpgradeRequirement {
  required: true;
  /** The smallest RouterOS a template needs. */
  minimum: string | null;
  /** The largest RouterOS the templates accept (older servers only). */
  maximum: string | null;
  /** The version to install: the fleet target. `null` when the server gave
   *  none, or one the bench refuses (see `targetRefusal`). */
  target: { version: string; source: 'fleet_target' } | null;
  /** Why a target the server sent is not used, in French. */
  targetRefusal: string | null;
  packages: Array<{ name: string; url: string }> | null;
  arch: string | null;
  templates: string[];
}
/** The site's current router, which preparing this box would retire. */
export interface BenchReplacement {
  /** The ObliWAN device the compile would disable; it must be confirmed by this id. */
  deviceId: number;
  /** The platform's sentence, in French, shown as it is. */
  message: string;
}
export interface BenchPlan {
  site: Record<string, unknown>;
  tenant: Record<string, unknown>;
  candidates: BenchCandidate[];
  benchVariables: BenchVariable[];
  allocation: BenchAllocation;
  warnings: string[];
  upgrade: BenchUpgradeRequirement | null;
  /** Null when the compile retires nothing (or the server does not say). */
  replaces: BenchReplacement | null;
}

/** A RouterOS version as a template's `os_min` / `os_max` holds it. */
const OS_VERSION_RE = /^\d{1,3}(?:\.\d{1,3}){0,2}[A-Za-z0-9.]{0,16}$/;
const PACKAGE_NAME_RE = /^[a-z0-9][a-z0-9-]{0,39}$/;

/**
 * `upgrade` as the platform sent it, or null. Read the way the rest of the
 * plan is: a block that is not the contract's shape offers nothing — an
 * upgrade aimed at a minimum nobody can read is not one to start. A target
 * BELOW the minimum is not used (`targetRefusal` says why): installing it
 * would cost a reboot and leave the box exactly as uncompilable.
 */
function readUpgrade(v: unknown): BenchUpgradeRequirement | null {
  if (!isObj(v) || v.required !== true) return null;
  const minimum = typeof v.minimum === 'string' && OS_VERSION_RE.test(v.minimum.trim()) ? v.minimum.trim() : null;
  if (v.minimum !== null && v.minimum !== undefined && minimum === null) return null;
  const maximum = typeof v.maximum === 'string' && OS_VERSION_RE.test(v.maximum.trim()) ? v.maximum.trim() : null;
  if (v.maximum !== null && v.maximum !== undefined && maximum === null) return null;
  const templates = Array.isArray(v.templates)
    ? v.templates.filter((t): t is string => typeof t === 'string' && t.trim() !== '').map((t) => t.slice(0, 120)).slice(0, 20)
    : [];
  let target: BenchUpgradeRequirement['target'] = null;
  let targetRefusal: string | null = null;
  if (isObj(v.target)) {
    const version = typeof v.target.version === 'string' ? v.target.version.trim() : '';
    if (!isRouterOsReleaseVersion(version) || v.target.source !== 'fleet_target') {
      targetRefusal = 'ObliWAN n\'a pas indiqué de version cible du parc utilisable.';
    } else if (minimum && parseRouterOsVersion(minimum) && compareRouterOsVersion(version, minimum) < 0) {
      targetRefusal = `La version cible du parc (${version}) est plus ancienne que celle qu'exige le modèle (${minimum}).`;
    } else if (maximum && parseRouterOsVersion(maximum) && compareRouterOsVersion(version, maximum) > 0) {
      targetRefusal = `La version cible du parc (${version}) est plus récente que celle qu'accepte le modèle (${maximum}).`;
    } else {
      target = { version, source: 'fleet_target' };
    }
  } else {
    targetRefusal = 'ObliWAN n\'a pas indiqué de version cible du parc.';
  }
  const packages = Array.isArray(v.packages)
    ? v.packages.flatMap((p) => (isObj(p) && typeof p.name === 'string' && PACKAGE_NAME_RE.test(p.name) && typeof p.url === 'string'
      ? [{ name: p.name, url: p.url }] : [])).slice(0, 40)
    : null;
  const arch = isRouterOsPackageArch(v.arch) ? v.arch : null;
  return { required: true, minimum, maximum, target, targetRefusal, packages, arch, templates };
}

/**
 * `replaces` as the platform sent it. Absent or null: nothing is retired (or
 * a server built before the field — whose compile does not ask for a
 * confirmation either). PRESENT but not the contract's shape is a refusal
 * naming the field, never a default: read as null, the summary would show no
 * confirmation and every compile for that site would be refused for want of
 * one, with nothing on the page to give it.
 */
function readReplaces(v: unknown): BenchReplacement | null {
  if (v === undefined || v === null) return null;
  const deviceId = isObj(v) ? posInt(v.deviceId) : null;
  if (!isObj(v) || deviceId === null) throw invalid('« replaces » illisible');
  const message = typeof v.message === 'string' && v.message.trim() !== ''
    ? v.message.trim().slice(0, 600)
    : `Ce site a déjà un routeur (appareil n°${deviceId}) : il sera remplacé par celui-ci, et désactivé.`;
  return { deviceId, message };
}

export interface BenchCompiledFile {
  name: string;
  content: string;
  sha256: string;
  role: 'runner' | 'body';
}
export interface BenchCompiled {
  fileName: string;
  content: string;
  sha256: string;
  tag: string;
  deviceId: number;
  concentrator: { state: 'provisioned' | 'pending' | 'failed'; message: string };
  /** The split compile, when the server sent one; null otherwise. */
  files: BenchCompiledFile[] | null;
  /** The server's echo of a declared `deviceModeOverride`; null when absent. */
  testOverride: boolean | null;
  /** What the platform says and that refused nothing; [] when absent. */
  warnings: string[];
}

/** What the bench saw after the reset, sent with the result. */
export interface BenchLocalCheck {
  /** The identity MNDP announced for this box after the reset, if any. */
  mndpIdentity: string | null;
  identityMatches: boolean;
  /** `null`: not tried (no address on the new LAN, or none known). */
  lanReachable: boolean | null;
}

const TIMEOUT_MS = 20_000;
/** Below this, the PC's clock is taken as the platform's (see `onServerClock`). */
const CLOCK_SKEW_TOLERANCE_MS = 30_000;
/** The compile also provisions the concentrator before it answers. */
const COMPILE_TIMEOUT_MS = 90_000;

type Json = Record<string, unknown>;

const isObj = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v);
const strOrNull = (v: unknown): string | null => (typeof v === 'string' && v.trim() !== '' ? v : null);
const posInt = (v: unknown): number | null => (typeof v === 'number' && Number.isInteger(v) && v > 0 ? v : null);

function invalid(what: string): BenchApiError {
  return new BenchApiError('invalid', 200, `Réponse inattendue d'ObliWAN : ${what}. Rien n'a été fait sur le routeur.`);
}

export class BenchApi {
  /**
   * ObliWAN's clock minus this PC's (ms), from the `Date` header of its last
   * answer; null until one carried a readable header. The header is whole
   * seconds, so this is good to about a second — plenty for what reads it.
   */
  private skewMs: number | null = null;

  constructor(private readonly station: BenchStation) {}

  get baseUrl(): string {
    return this.station.baseUrl;
  }

  /** ObliWAN's clock minus this PC's, as last measured (ms), or null. */
  get clockSkewMs(): number | null {
    return this.skewMs;
  }

  /**
   * `iso` — an instant stamped on THIS PC's clock (the device-mode reading's
   * `observedAt`) — restated on ObliWAN's clock when the two disagree by more
   * than `CLOCK_SKEW_TOLERANCE_MS`; unchanged otherwise, or when no answer
   * has told us the platform's time yet.
   *
   * Why: the platform refuses an `observedAt` more than 5 min ahead of its
   * own clock (services/bench/bodyFeatures.ts), and judges the reading's age
   * on it. A bench PC whose clock runs fast (a dead CMOS battery, no time
   * sync) would otherwise have every plan and compile refused over a field
   * the technician cannot see. The instant stays the one at which the bench
   * asked the router; only the clock it is written on changes.
   */
  onServerClock(iso: string): string {
    const t = Date.parse(iso);
    const skew = this.skewMs;
    if (!Number.isFinite(t) || skew === null || Math.abs(skew) <= CLOCK_SKEW_TOLERANCE_MS) return iso;
    return new Date(t + skew).toISOString();
  }

  private async call(method: 'GET' | 'POST', path: string, body: unknown, timeoutMs = TIMEOUT_MS): Promise<unknown> {
    const url = `${this.station.baseUrl}/api/bench/v1${path}`;
    // Outside the network try: a station file this workstation cannot read or
    // write is a LOCAL fault, and must not read "ObliWAN ne répond pas".
    let auth: { authorization: string };
    try {
      auth = this.station.authHeader();
    } catch (err) {
      throw new BenchApiError('local', null, `Problème sur ce poste : ${err instanceof Error ? err.message : String(err)}. Rien n'a été envoyé à ObliWAN.`);
    }
    let res: Response;
    const sentAt = Date.now();
    try {
      res = await fetch(url, {
        method,
        headers: {
          ...auth,
          accept: 'application/json',
          'cache-control': 'no-store',
          ...(body === undefined ? {} : { 'content-type': 'application/json' }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        redirect: 'manual',
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      const e = err as Error & { cause?: { code?: string } };
      const detail = e?.name === 'TimeoutError' ? `pas de réponse en ${timeoutMs / 1000} s` : e?.cause?.code ?? e?.message ?? String(err);
      throw new BenchApiError('unreachable', null, `ObliWAN ne répond pas (${detail}).`);
    }
    // Every answer, refusals included: the one that refuses a skewed reading
    // is also the one that teaches the next attempt the platform's time.
    const serverDate = Date.parse(res.headers.get('date') ?? '');
    if (Number.isFinite(serverDate)) {
      // The header truncates to the second (+500 ms: its middle), and the
      // answer left somewhere between our send and now (their middle).
      this.skewMs = Math.round(serverDate + 500 - (sentAt + Date.now()) / 2);
    }
    const text = await res.text().catch(() => '');
    if (res.status >= 300 && res.status <= 399) {
      throw new BenchApiError('redirected', res.status, `ObliWAN a répondu par une redirection (${res.status}) : elle n'est pas suivie. Vérifiez l'adresse d'ObliWAN.`);
    }
    let parsed: unknown = null;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = null;
    }
    const serverError = isObj(parsed) && typeof parsed.error === 'string' ? parsed.error : null;
    if (res.status === 401 || res.status === 403) {
      throw new BenchApiError('station', res.status, serverError ?? `ObliWAN refuse ce poste (${res.status}).`);
    }
    if (!res.ok) {
      throw new BenchApiError('refused', res.status, serverError ?? `ObliWAN a refusé la demande (${res.status}).`);
    }
    if (!isObj(parsed) || !('data' in parsed)) throw invalid('pas de champ « data »');
    return parsed.data;
  }

  async tenants(): Promise<BenchTenant[]> {
    const data = await this.call('GET', '/tenants', undefined);
    if (!Array.isArray(data)) throw invalid('la liste des clients n\'est pas une liste');
    return data.flatMap((t) => {
      if (!isObj(t) || posInt(t.id) === null || typeof t.name !== 'string') return [];
      return [{ id: t.id as number, name: t.name, slug: typeof t.slug === 'string' ? t.slug : '' }];
    });
  }

  async sites(tenantId: number, search: string): Promise<BenchSite[]> {
    const q = search ? `?search=${encodeURIComponent(search)}` : '';
    const data = await this.call('GET', `/tenants/${tenantId}/sites${q}`, undefined);
    if (!Array.isArray(data)) throw invalid('la liste des sites n\'est pas une liste');
    return data.flatMap((s) => {
      if (!isObj(s) || posInt(s.id) === null || typeof s.name !== 'string') return [];
      return [{
        id: s.id as number,
        code: strOrNull(s.code) ?? (typeof s.code === 'number' ? String(s.code) : null),
        name: s.name,
        country: strOrNull(s.country),
        provisioned: s.provisioned === true,
      }];
    });
  }

  async plan(siteId: number, box: BenchBox): Promise<BenchPlan> {
    const d = await this.call('POST', '/plan', { siteId, box });
    if (!isObj(d)) throw invalid('le plan n\'est pas un objet');
    if (!Array.isArray(d.candidates)) throw invalid('« candidates » manquant');
    const candidates = d.candidates.flatMap((c) => {
      if (!isObj(c) || posInt(c.revisionId) === null) return [];
      return [{
        revisionId: c.revisionId as number,
        templateName: typeof c.templateName === 'string' ? c.templateName : `révision ${String(c.revisionId)}`,
        revision: typeof c.revision === 'number' || typeof c.revision === 'string' ? c.revision : null,
        deviceModeFeatures: Array.isArray(c.deviceModeFeatures)
          ? Array.from(new Set(c.deviceModeFeatures.filter((f): f is string => typeof f === 'string' && /^[a-z][a-z0-9-]{1,30}$/.test(f)))).slice(0, 30)
          : null,
      }];
    });
    const vars = Array.isArray(d.benchVariables) ? d.benchVariables : [];
    const benchVariables = vars.flatMap((v) => {
      if (!isObj(v) || typeof v.key !== 'string' || !/^[A-Za-z0-9_.-]{1,64}$/.test(v.key)) return [];
      return [{
        key: v.key,
        label: typeof v.label === 'string' && v.label ? v.label : v.key,
        type: typeof v.type === 'string' ? v.type : 'string',
        secret: v.secret === true,
        required: v.required === true,
      }];
    });
    const a = isObj(d.allocation) ? d.allocation : {};
    return {
      site: isObj(d.site) ? d.site : {},
      tenant: isObj(d.tenant) ? d.tenant : {},
      candidates,
      benchVariables,
      allocation: {
        ppp_username: strOrNull(a.ppp_username),
        tunnel_ip: strOrNull(a.tunnel_ip),
        lan_subnet: strOrNull(a.lan_subnet),
        system_identity: strOrNull(a.system_identity),
        lan_router_ip: typeof a.lan_router_ip === 'string' && /^\d{1,3}(\.\d{1,3}){3}$/.test(a.lan_router_ip) ? a.lan_router_ip : null,
      },
      warnings: Array.isArray(d.warnings) ? d.warnings.filter((w): w is string => typeof w === 'string') : [],
      upgrade: readUpgrade(d.upgrade),
      replaces: readReplaces(d.replaces),
    };
  }

  async compile(
    siteId: number,
    revisionId: number,
    box: BenchBox,
    bench: Record<string, string>,
    opts: {
      deviceModeOverride?: boolean;
      /** The plan's `replaces.deviceId`, once the operator confirmed it.
       *  Sent only when set: an unconfirmed replacement sends nothing. */
      confirmReplaceDeviceId?: number | null;
    } = {},
  ): Promise<BenchCompiled> {
    const body: Record<string, unknown> = { siteId, revisionId, box, bench };
    if (opts.deviceModeOverride) body.deviceModeOverride = true;
    const confirmReplace = posInt(opts.confirmReplaceDeviceId);
    if (confirmReplace !== null) body.confirmReplaceDeviceId = confirmReplace;
    const d = await this.call('POST', '/compile', body, COMPILE_TIMEOUT_MS);
    if (!isObj(d)) throw invalid('la compilation n\'est pas un objet');
    if (typeof d.fileName !== 'string' || !d.fileName) throw invalid('« fileName » manquant');
    if (typeof d.content !== 'string' || !d.content) throw invalid('« content » manquant ou vide');
    if (typeof d.sha256 !== 'string' || !/^[0-9a-fA-F]{64}$/.test(d.sha256.trim())) throw invalid('« sha256 » manquant ou illisible');
    if (typeof d.tag !== 'string' || !d.tag) throw invalid('« tag » manquant');
    const deviceId = posInt(d.deviceId);
    if (deviceId === null) throw invalid('« deviceId » manquant');
    const c = isObj(d.concentrator) ? d.concentrator : {};
    const state = c.state === 'provisioned' || c.state === 'pending' || c.state === 'failed' ? c.state : null;
    if (!state) throw invalid('« concentrator.state » manquant');
    let files: BenchCompiledFile[] | null = null;
    if (d.files !== undefined && d.files !== null) {
      // Present means the server split the body: every entry must be whole,
      // or the compile is refused — a split compile missing a file is a box
      // that resets into a runner with nothing to import.
      // At most MAX_COMPILED_FILES (services/bench/splitFile.ts) — the server
      // refuses a compile above it, so a larger list here is not one it sent.
      if (!Array.isArray(d.files) || d.files.length === 0 || d.files.length > 20) throw invalid('« files » illisible');
      files = d.files.map((f, i) => {
        if (!isObj(f)) throw invalid(`« files[${i}] » illisible`);
        if (typeof f.name !== 'string' || !f.name) throw invalid(`« files[${i}].name » manquant`);
        if (typeof f.content !== 'string' || !f.content) throw invalid(`« files[${i}].content » manquant ou vide`);
        if (typeof f.sha256 !== 'string' || !/^[0-9a-fA-F]{64}$/.test(f.sha256.trim())) throw invalid(`« files[${i}].sha256 » illisible`);
        if (f.role !== 'runner' && f.role !== 'body') throw invalid(`« files[${i}].role » illisible`);
        return { name: f.name, content: f.content, sha256: f.sha256.trim().toLowerCase(), role: f.role };
      });
    }
    return {
      fileName: d.fileName,
      content: d.content,
      sha256: d.sha256.trim().toLowerCase(),
      tag: d.tag,
      deviceId,
      concentrator: { state, message: typeof c.message === 'string' ? c.message : '' },
      files,
      testOverride: typeof d.testOverride === 'boolean' ? d.testOverride : null,
      warnings: Array.isArray(d.warnings)
        ? d.warnings.filter((w): w is string => typeof w === 'string' && w.trim() !== '').map((w) => w.slice(0, 600)).slice(0, 6)
        : [],
    };
  }

  async result(
    deviceId: number,
    status: 'applied' | 'failed',
    detail: string,
    extra: {
      localCheck?: BenchLocalCheck | null;
      deviceModeOverride?: boolean;
      /** The SIM card read in the modem: an object, or null for "read, no SIM
       *  found". Left undefined when nothing was read (a failed run). */
      sim?: { iccid: string; imsi: string | null } | null;
    } = {},
  ): Promise<void> {
    const body: Record<string, unknown> = { status, detail: detail.slice(0, 2000) };
    if (extra.localCheck) body.localCheck = extra.localCheck;
    if (extra.deviceModeOverride !== undefined) body.deviceModeOverride = extra.deviceModeOverride;
    if (extra.sim !== undefined) body.sim = extra.sim;
    await this.call('POST', `/devices/${deviceId}/result`, body);
  }
}
