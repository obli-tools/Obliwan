/**
 * ObliWAN — infrastructure concentrators: the declarations and the per-site
 * account registry (migration 074). Database only: nothing here dials.
 *
 * ┌─ THE CREDENTIAL ───────────────────────────────────────────────────────────┐
 * │ A CHR holds no secret here: it is dialled through its devices row, whose   │
 * │ RouterOS API transport is in the vault already. An OPNsense's REST key and │
 * │ secret go through `secretVault.encrypt` on the way in and come out only in │
 * │ `revealOpnsenseCredential`, in memory, for the one call that needs them.   │
 * │ No view, no log line and no error carries either; a view says only         │
 * │ `hasCredential`.                                                           │
 * └────────────────────────────────────────────────────────────────────────────┘
 *
 * The host an OPNsense is dialled on is STORED by a platform administrator and
 * read back from here; no route takes an address to dial (a diagnostic that
 * takes a host from the request is SSRF).
 */

import {
  ACTIVE_CHANGE_JOB_STATUSES,
  DEFAULT_INFRA_CONCENTRATOR_PARAMS,
  INFRA_CONCENTRATOR_KINDS,
  MASTER_TENANT_ID,
  infraAccountKindFor,
  type InfraAccountKind,
  type InfraAccountState,
  type InfraConcentratorKind,
  type InfraConcentratorParams,
  type InfraConcentratorView,
  type InfraSiteAccountView,
} from '@obliwan/shared';
import { db } from '../../db';
import { currentKeyVersion, decrypt, encrypt } from '../secretVault.service';
import { InfraConcentratorError, type InfraConcentratorRow } from './types';

// ============================================================================
// Validation
// ============================================================================

// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f]/;
const HOST_RE = /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
const VAR_KEY_RE = /^[a-z][a-z0-9_]{0,63}$/;
const PROFILE_RE = /^[A-Za-z0-9._-]{1,64}$/;
const FINGERPRINT_RE = /^[0-9a-f]{64}$/;

function bad(message: string, code = 'invalid_request'): InfraConcentratorError {
  return new InfraConcentratorError(code, message, 400);
}

function cleanName(raw: unknown): string {
  if (typeof raw !== 'string' || raw.trim() === '' || raw.trim().length > 64 || CONTROL_RE.test(raw)) {
    throw bad('Le nom du concentrateur est obligatoire (1 à 64 caractères, sans caractère de contrôle).');
  }
  return raw.trim();
}

function cleanHost(raw: unknown): string {
  if (typeof raw !== 'string' || raw.trim().length > 253 || !HOST_RE.test(raw.trim())) {
    throw bad("L'hôte doit être un nom DNS ou une adresse IPv4 (lettres, chiffres, points et tirets).");
  }
  return raw.trim().toLowerCase();
}

function cleanPort(raw: unknown): number | null {
  if (raw === null || raw === undefined || raw === '') return null;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > 65535) throw bad('Le port doit être un entier entre 1 et 65535.');
  return n;
}

function cleanCredentialPart(raw: unknown, label: string): string {
  if (typeof raw !== 'string' || raw === '' || raw.length > 512 || CONTROL_RE.test(raw)) {
    // Never echo the value: it is a credential.
    throw bad(`${label} est obligatoire (1 à 512 caractères, sans caractère de contrôle).`);
  }
  return raw;
}

/** Lowercase hex, separators dropped; null clears. */
export function normaliseFingerprint(raw: unknown): string | null {
  if (raw === null || raw === undefined || raw === '') return null;
  if (typeof raw !== 'string') throw bad("L'empreinte TLS doit être une chaîne hexadécimale SHA-256.");
  const fp = raw.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  if (!FINGERPRINT_RE.test(fp)) throw bad("L'empreinte TLS doit être un SHA-256 (64 chiffres hexadécimaux).");
  return fp;
}

export function cleanParams(raw: unknown, base: InfraConcentratorParams = DEFAULT_INFRA_CONCENTRATOR_PARAMS): InfraConcentratorParams {
  const src = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
  const out: InfraConcentratorParams = { ...base };
  const key = (v: unknown, label: string): string => {
    if (typeof v !== 'string' || !VAR_KEY_RE.test(v)) {
      throw bad(`${label} doit être une clé de variable (minuscules, chiffres et _, 64 caractères au plus).`);
    }
    return v;
  };
  if (src.usernameKey !== undefined) out.usernameKey = key(src.usernameKey, 'La variable du login');
  if (src.passwordKey !== undefined) out.passwordKey = key(src.passwordKey, 'La variable du mot de passe');
  if (src.remoteAddressKey !== undefined) {
    out.remoteAddressKey = src.remoteAddressKey === null || src.remoteAddressKey === ''
      ? null
      : key(src.remoteAddressKey, "La variable de l'adresse distante");
  }
  if (src.pppProfile !== undefined) {
    if (src.pppProfile === null || src.pppProfile === '') out.pppProfile = null;
    else if (typeof src.pppProfile !== 'string' || !PROFILE_RE.test(src.pppProfile)) {
      throw bad('Le profil PPP doit tenir en [A-Za-z0-9._-], 64 caractères au plus.');
    } else out.pppProfile = src.pppProfile;
  }
  return out;
}

function parseParams(raw: unknown): InfraConcentratorParams {
  try {
    return cleanParams(typeof raw === 'string' ? JSON.parse(raw) : raw);
  } catch {
    return { ...DEFAULT_INFRA_CONCENTRATOR_PARAMS };
  }
}

async function assertTenant(tenantId: number): Promise<void> {
  const t = await db('tenants').where({ id: tenantId }).first('id');
  if (!t) throw new InfraConcentratorError('tenant_not_found', `Le tenant ${tenantId} n'existe pas.`, 404);
}

/** A CHR's device: a MikroTik of this tenant or of the master tenant. */
async function assertChrDevice(tenantId: number, deviceId: unknown): Promise<number> {
  const id = Number(deviceId);
  if (!Number.isInteger(id) || id <= 0) {
    throw bad("Un concentrateur RouterOS (CHR) doit être lié à l'appareil qui le représente dans l'inventaire.");
  }
  const d = (await db('devices').where({ id }).first('id', 'tenant_id', 'brand', 'name')) as
    | { id: number; tenant_id: number; brand: string; name: string }
    | undefined;
  if (!d || (d.tenant_id !== tenantId && d.tenant_id !== MASTER_TENANT_ID)) {
    throw bad(`L'appareil ${id} n'existe ni dans ce tenant ni dans le tenant maître.`, 'device_not_found');
  }
  if (d.brand !== 'mikrotik') {
    throw bad(`L'appareil ${d.name} n'est pas un MikroTik : il ne peut pas représenter un CHR.`, 'device_not_mikrotik');
  }
  await assertNotManagementConcentrator(d.id, d.name);
  return d.id;
}

/** A CHR that devices name as their concentrator carries the stores'
 *  MANAGEMENT tunnels (MkManagement): infra jobs run with no backup and no
 *  dead-man on the premise that an infra CHR carries none, so it is refused. */
export async function assertNotManagementConcentrator(deviceId: number, name: string): Promise<void> {
  const served = await db('devices').where({ concentrator_id: deviceId }).first('id');
  if (served) {
    throw bad(
      `L'appareil ${name} est le concentrateur de gestion d'équipements du parc : il ne peut pas servir de concentrateur d'infrastructure d'un client.`,
      'device_is_management_concentrator',
    );
  }
}

// ============================================================================
// Rows and views
// ============================================================================

const COLUMNS = [
  'c.id', 'c.tenant_id', 'c.kind', 'c.name', 'c.host', 'c.port', 'c.device_id', 'c.enabled', 'c.params',
  'c.api_key_enc', 'c.api_secret_enc', 'c.key_version', 'c.tls_fingerprint_sha256',
  'c.last_test_at', 'c.last_test_ok', 'c.last_test_message', 'c.created_at', 'c.updated_at',
];

function toRow(r: Record<string, unknown>): InfraConcentratorRow {
  return { ...(r as unknown as InfraConcentratorRow), params: parseParams(r.params) };
}

const iso = (v: Date | string | null | undefined): string | null =>
  v === null || v === undefined ? null : v instanceof Date ? v.toISOString() : new Date(v).toISOString();

function toView(r: InfraConcentratorRow & { device_name?: string | null; account_count?: string | number }): InfraConcentratorView {
  return {
    id: r.id,
    tenantId: r.tenant_id,
    kind: r.kind,
    name: r.name,
    host: r.host,
    port: r.port,
    deviceId: r.device_id,
    deviceName: r.device_name ?? null,
    enabled: r.enabled,
    params: r.params,
    hasCredential: r.kind === 'routeros_chr' ? r.device_id !== null : Boolean(r.api_key_enc && r.api_secret_enc),
    tlsFingerprint: r.tls_fingerprint_sha256,
    lastTestAt: iso(r.last_test_at),
    lastTestOk: r.last_test_ok,
    lastTestMessage: r.last_test_message,
    accountCount: Number(r.account_count ?? 0),
    createdAt: iso(r.created_at) as string,
    updatedAt: iso(r.updated_at) as string,
  };
}

function viewQuery() {
  return db('infra_concentrators as c')
    .leftJoin('devices as d', 'd.id', 'c.device_id')
    .select(
      ...COLUMNS,
      'd.name as device_name',
      db.raw('(SELECT count(*) FROM infra_site_accounts a WHERE a.concentrator_id = c.id) AS account_count'),
    );
}

export async function getInfraConcentratorRow(id: number): Promise<InfraConcentratorRow> {
  const r = (await db('infra_concentrators as c').where('c.id', id).first(...COLUMNS)) as Record<string, unknown> | undefined;
  if (!r) throw new InfraConcentratorError('concentrator_not_found', `Le concentrateur d'infrastructure ${id} n'existe pas.`, 404);
  return toRow(r);
}

export async function getInfraConcentratorView(id: number): Promise<InfraConcentratorView> {
  const r = (await viewQuery().where('c.id', id).first()) as Record<string, unknown> | undefined;
  if (!r) throw new InfraConcentratorError('concentrator_not_found', `Le concentrateur d'infrastructure ${id} n'existe pas.`, 404);
  return toView(toRow(r) as InfraConcentratorRow & { device_name?: string | null; account_count?: string | number });
}

export async function listInfraConcentrators(tenantId: number): Promise<InfraConcentratorView[]> {
  await assertTenant(tenantId);
  const rows = (await viewQuery().where('c.tenant_id', tenantId).orderBy('c.name')) as Array<Record<string, unknown>>;
  return rows.map((r) => toView(toRow(r) as InfraConcentratorRow & { device_name?: string | null; account_count?: string | number }));
}

// ============================================================================
// Create / update / delete
// ============================================================================

export interface InfraConcentratorInput {
  kind?: unknown;
  name?: unknown;
  host?: unknown;
  port?: unknown;
  deviceId?: unknown;
  enabled?: unknown;
  params?: unknown;
  /** OPNsense: write-only. Never returned. */
  apiKey?: unknown;
  apiSecret?: unknown;
  /** OPNsense: set to pin, null to clear (the next test pins on first use). */
  tlsFingerprint?: unknown;
}

function uniqueViolation(err: unknown): boolean {
  const pg = err as { code?: string; constraint?: string };
  return pg.code === '23505' && pg.constraint === 'infra_concentrators_tenant_name_uq';
}

export async function createInfraConcentrator(
  tenantId: number,
  input: InfraConcentratorInput,
  createdBy: number | null,
): Promise<InfraConcentratorView> {
  await assertTenant(tenantId);
  if (typeof input.kind !== 'string' || !(INFRA_CONCENTRATOR_KINDS as readonly string[]).includes(input.kind)) {
    throw bad(`Le type doit être l'un de : ${INFRA_CONCENTRATOR_KINDS.join(', ')}.`);
  }
  const kind = input.kind as InfraConcentratorKind;
  const row: Record<string, unknown> = {
    tenant_id: tenantId,
    kind,
    name: cleanName(input.name),
    host: cleanHost(input.host),
    port: cleanPort(input.port),
    enabled: input.enabled === undefined ? true : input.enabled === true,
    params: JSON.stringify(cleanParams(input.params)),
    created_by: createdBy,
  };
  if (kind === 'routeros_chr') {
    if (input.apiKey !== undefined || input.apiSecret !== undefined) {
      throw bad("Un CHR ne prend pas de clé d'API ici : il est joint par le canal RouterOS de son appareil (coffre).");
    }
    row.device_id = await assertChrDevice(tenantId, input.deviceId);
  } else {
    row.device_id = null;
    row.api_key_enc = encrypt(cleanCredentialPart(input.apiKey, "La clé d'API OPNsense"));
    row.api_secret_enc = encrypt(cleanCredentialPart(input.apiSecret, "Le secret d'API OPNsense"));
    row.key_version = currentKeyVersion();
    row.tls_fingerprint_sha256 = normaliseFingerprint(input.tlsFingerprint);
  }
  try {
    const [inserted] = (await db('infra_concentrators').insert(row).returning('id')) as Array<{ id: number }>;
    return getInfraConcentratorView(inserted.id);
  } catch (err) {
    if (uniqueViolation(err)) throw new InfraConcentratorError('name_taken', 'Ce tenant a déjà un concentrateur de ce nom.', 409);
    throw err;
  }
}

export async function updateInfraConcentrator(id: number, input: InfraConcentratorInput): Promise<InfraConcentratorView> {
  const current = await getInfraConcentratorRow(id);
  if (input.kind !== undefined && input.kind !== current.kind) {
    throw bad("Le type d'un concentrateur ne change pas : déclarez-en un nouveau.");
  }
  const patch: Record<string, unknown> = { updated_at: db.fn.now() };
  if (input.name !== undefined) patch.name = cleanName(input.name);
  if (input.host !== undefined) patch.host = cleanHost(input.host);
  if (input.port !== undefined) patch.port = cleanPort(input.port);
  if (input.enabled !== undefined) patch.enabled = input.enabled === true;
  if (input.params !== undefined) patch.params = JSON.stringify(cleanParams(input.params, current.params));
  if (current.kind === 'routeros_chr') {
    if (input.apiKey !== undefined || input.apiSecret !== undefined || input.tlsFingerprint !== undefined) {
      throw bad("Un CHR n'a ni clé d'API ni empreinte ici : son canal RouterOS se règle sur la page de l'appareil.");
    }
    if (input.deviceId !== undefined) patch.device_id = await assertChrDevice(current.tenant_id, input.deviceId);
  } else {
    if (input.deviceId !== undefined && input.deviceId !== null) {
      throw bad("Un OPNsense n'est pas lié à un appareil de l'inventaire (décision de demain).");
    }
    // The key and the secret move together: half of a rotated credential is
    // a credential that matches nothing.
    if (input.apiKey !== undefined || input.apiSecret !== undefined) {
      patch.api_key_enc = encrypt(cleanCredentialPart(input.apiKey, "La clé d'API OPNsense"));
      patch.api_secret_enc = encrypt(cleanCredentialPart(input.apiSecret, "Le secret d'API OPNsense"));
      patch.key_version = currentKeyVersion();
    }
    if (input.tlsFingerprint !== undefined) patch.tls_fingerprint_sha256 = normaliseFingerprint(input.tlsFingerprint);
  }
  try {
    await db('infra_concentrators').where({ id }).update(patch);
  } catch (err) {
    if (uniqueViolation(err)) throw new InfraConcentratorError('name_taken', 'Ce tenant a déjà un concentrateur de ce nom.', 409);
    throw err;
  }
  return getInfraConcentratorView(id);
}

/** Removes the DECLARATION (and its account registry); nothing on the
 *  concentrator itself. Refused while a job of it is in flight. */
export async function deleteInfraConcentrator(id: number): Promise<void> {
  await getInfraConcentratorRow(id);
  const inflight = (await db('infra_account_jobs as i')
    .join('change_jobs as j', 'j.id', 'i.job_id')
    .where('i.concentrator_id', id)
    .whereIn('j.status', ACTIVE_CHANGE_JOB_STATUSES as unknown as string[])
    .first('j.id')) as { id: string | number } | undefined;
  if (inflight) {
    throw new InfraConcentratorError(
      'job_in_flight',
      `Le job ${Number(inflight.id)} travaille encore sur ce concentrateur ; réessayez quand il sera terminé.`,
      409,
    );
  }
  const history = await db('infra_account_jobs').where({ concentrator_id: id }).first('job_id');
  if (history) {
    throw new InfraConcentratorError(
      'has_history',
      "Ce concentrateur a déjà servi à des jobs : il n'est pas supprimé, pour garder leur historique. Désactivez-le plutôt.",
      409,
    );
  }
  await db('infra_concentrators').where({ id }).del();
}

/** The OPNsense REST credential, IN MEMORY ONLY, for the one call that needs it. */
export function revealOpnsenseCredential(row: InfraConcentratorRow): { key: string; secret: string } {
  if (!row.api_key_enc || !row.api_secret_enc) {
    throw new InfraConcentratorError('no_credential', "Ce concentrateur n'a pas de clé d'API dans le coffre.");
  }
  return { key: decrypt(row.api_key_enc), secret: decrypt(row.api_secret_enc) };
}

export async function recordTestResult(id: number, ok: boolean, message: string): Promise<void> {
  await db('infra_concentrators').where({ id }).update({
    last_test_at: db.fn.now(),
    last_test_ok: ok,
    last_test_message: message.slice(0, 2000),
    updated_at: db.fn.now(),
  });
}

/** Trust on first use (RouterOS's rule, transport/routeros/connection.ts):
 *  written only when nothing is pinned yet, so a race never replaces a pin. */
export async function pinFingerprintIfUnset(id: number, fingerprint: string): Promise<boolean> {
  const n = await db('infra_concentrators')
    .where({ id })
    .whereNull('tls_fingerprint_sha256')
    .update({ tls_fingerprint_sha256: fingerprint, updated_at: db.fn.now() });
  return Number(n) > 0;
}

// ============================================================================
// The per-site account registry
// ============================================================================

export async function listSiteAccounts(tenantId: number, siteId: number): Promise<InfraSiteAccountView[]> {
  const rows = (await db('infra_site_accounts as a')
    .join('infra_concentrators as c', 'c.id', 'a.concentrator_id')
    .leftJoin('change_jobs as j', 'j.id', 'a.last_job_id')
    .where('a.tenant_id', tenantId)
    .where('a.site_id', siteId)
    .orderBy('c.name')
    .select(
      'a.id', 'a.tenant_id', 'a.site_id', 'a.concentrator_id', 'c.name as concentrator_name',
      'c.kind as concentrator_kind', 'a.account_kind', 'a.identifier', 'a.state', 'a.last_job_id',
      'j.status as last_job_status', 'a.observed_at', 'a.detail', 'a.updated_at',
    )) as Array<Record<string, unknown>>;
  return rows.map((r) => ({
    id: Number(r.id),
    tenantId: Number(r.tenant_id),
    siteId: Number(r.site_id),
    concentratorId: Number(r.concentrator_id),
    concentratorName: String(r.concentrator_name),
    concentratorKind: r.concentrator_kind as InfraConcentratorKind,
    accountKind: r.account_kind as InfraAccountKind,
    identifier: String(r.identifier),
    state: r.state as InfraAccountState,
    lastJobId: r.last_job_id === null ? null : Number(r.last_job_id),
    lastJobStatus: (r.last_job_status as string | null) ?? null,
    observedAt: iso(r.observed_at as Date | null),
    detail: (r.detail as string | null) ?? null,
    updatedAt: iso(r.updated_at as Date) as string,
  }));
}

/** The registry row a job was queued for: created 'planned' when absent; an
 *  existing row keeps its state (a re-verification proves nothing yet). */
export async function noteJobQueued(input: {
  tenantId: number;
  siteId: number;
  concentrator: InfraConcentratorRow;
  identifier: string;
  jobId: number;
}): Promise<void> {
  await db('infra_site_accounts')
    .insert({
      tenant_id: input.tenantId,
      site_id: input.siteId,
      concentrator_id: input.concentrator.id,
      account_kind: infraAccountKindFor(input.concentrator.kind),
      identifier: input.identifier,
      state: 'planned',
      last_job_id: input.jobId,
    })
    .onConflict(['concentrator_id', 'site_id'])
    .merge({ identifier: input.identifier, last_job_id: input.jobId, updated_at: db.fn.now() });
}

/**
 * What a finished job says about the account. A job never overwrites the
 * mirror of a NEWER job. `state` null = the failure proved nothing about the
 * account (unreachable, refused before reading): the state stays, only the
 * detail and the job move.
 */
export async function noteJobSettled(input: {
  tenantId: number;
  siteId: number;
  concentratorId: number;
  jobId: number;
  state: InfraAccountState | null;
  observed: boolean;
  detail: string;
}): Promise<void> {
  const patch: Record<string, unknown> = {
    last_job_id: input.jobId,
    detail: input.detail.slice(0, 4000),
    updated_at: db.fn.now(),
  };
  if (input.state !== null) patch.state = input.state;
  if (input.observed) patch.observed_at = db.fn.now();
  await db('infra_site_accounts')
    .where({ tenant_id: input.tenantId, site_id: input.siteId, concentrator_id: input.concentratorId })
    .where((q) => q.whereNull('last_job_id').orWhere('last_job_id', '<=', input.jobId))
    .update(patch);
}

