/**
 * ObliWAN — a site's account on its infrastructure concentrator, built from
 * the tenant's template variables.
 *
 * The concentrator's `params` names KEYS, never values (shared
 * `InfraConcentratorParams`): for customer A, `infra_ppp_username` is COMPUTED by
 * the allocation policy (= the site code), `infra_ppp_password` is a tenant
 * SECRET. Values are looked up, in this order:
 *   1. the allocator's computed values for the site (`previewForSite`:
 *      NON-COMMITTING, so a preview never allocates anything);
 *   2. the stored variables that apply to the site (instance -> tenant ->
 *      group -> site), clear ones as values;
 *   3. the secret ones, as plaintexts, IN MEMORY ONLY, and only by
 *      `resolveL2tpCredential` — which only the job's apply step calls.
 *
 * The source is a DEPENDENCY (`setInfraCredentialDeps`) so the harness can
 * hand in a site's values without an allocation policy.
 */

import { db } from '../../db';
import { logger } from '../../utils/logger';
import { previewForSite } from '../allocation';
import { hostAddress } from '../change/concentratorSecret.service';
import { loadStoredValuesForSite } from '../template/variableResolver.service';
import { InfraConcentratorError, type InfraConcentratorRow } from './types';

export interface SiteValues {
  siteCode: string;
  /** Clear values by key (computed first, then stored). */
  values: Record<string, string>;
  /** Secret plaintexts by key. IN MEMORY ONLY. */
  secrets: Map<string, string>;
  /** French notes on what could not be read (never a value). */
  warnings: string[];
}

export interface InfraCredentialDeps {
  siteValues(tenantId: number, siteId: number, withSecrets: boolean): Promise<SiteValues>;
}

function stringOf(v: unknown): string | null {
  if (typeof v === 'string') return v;
  if (typeof v === 'number' && Number.isFinite(v)) return String(v);
  return null;
}

const defaultDeps: InfraCredentialDeps = {
  async siteValues(tenantId, siteId, withSecrets) {
    const site = (await db('sites').where({ id: siteId, tenant_id: tenantId }).first('code')) as { code: string } | undefined;
    if (!site) throw new InfraConcentratorError('site_not_found', `Le site ${siteId} n'existe pas dans ce tenant.`, 404);
    const warnings: string[] = [];
    const values: Record<string, string> = Object.create(null) as Record<string, string>;
    const secrets = new Map<string, string>();
    try {
      const stored = await loadStoredValuesForSite({ tenantId, siteId });
      for (const [k, v] of Object.entries(stored.values)) {
        const s = stringOf(v);
        if (s !== null) values[k] = s;
      }
      if (withSecrets) for (const [k, v] of stored.plaintexts) secrets.set(k, v);
      else for (const k of stored.plaintexts.keys()) secrets.set(k, '');
    } catch (err) {
      warnings.push(`Les variables enregistrées du site n'ont pas pu être lues : ${err instanceof Error ? err.message : String(err)}`);
    }
    // Only for a site already allocated: for one that is not, the allocator's
    // preview may re-read the MANAGEMENT concentrator's seed first, and a plan
    // on the infrastructure concentrator must not dial another box.
    const allocated = await db('site_provisioning').where({ site_id: siteId, tenant_id: tenantId }).first('site_id');
    if (!allocated) {
      warnings.push("Le site n'a pas encore d'allocation : ses valeurs calculées ne sont pas disponibles.");
    } else try {
      const computed = await previewForSite(tenantId, siteId);
      // Computed values win over a stored one of the same key: the allocator
      // derives them from the allocation, and a stored copy is free to drift.
      for (const [k, v] of Object.entries(computed.values)) values[k] = v;
    } catch (err) {
      warnings.push(`Les valeurs calculées du site sont indisponibles : ${err instanceof Error ? err.message : String(err)}`);
    }
    values.site_code ??= site.code;
    return { siteCode: site.code, values, secrets, warnings };
  },
};

let deps: InfraCredentialDeps = defaultDeps;

export function setInfraCredentialDeps(next: Partial<InfraCredentialDeps>): InfraCredentialDeps {
  const previous = deps;
  deps = { ...deps, ...next };
  return previous;
}

export function resetInfraCredentialDeps(): void {
  deps = defaultDeps;
}

// ============================================================================
// The L2TP account (routeros_chr)
// ============================================================================

const LOGIN_RE = /^[A-Za-z0-9._-]{1,128}$/;
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f]/;
export const INFRA_COMMENT_PREFIX = 'obliwan:infra:';

export function infraComment(siteCode: string): string {
  return `${INFRA_COMMENT_PREFIX}${siteCode}`;
}

/** What the CHR must carry for one site. Never a password. */
export interface InfraL2tpSpec {
  name: string;
  /** null = no `remote-address=` sent, none compared. */
  remoteAddress: string | null;
  /** null = the CHR's `default` profile (no `profile=` sent). */
  profile: string | null;
  comment: string;
  /** Whether the password variable resolves (its value is not carried). */
  passwordResolvable: boolean;
  warnings: string[];
}

function refuse(code: string, message: string): InfraConcentratorError {
  return new InfraConcentratorError(code, message, 422);
}

function specFrom(c: InfraConcentratorRow, v: SiteValues): InfraL2tpSpec {
  const p = c.params;
  const name = v.values[p.usernameKey];
  if (name === undefined || name === '') {
    throw refuse(
      'variable_unresolved',
      `La variable « ${p.usernameKey} » (login PPP d'infrastructure) n'a pas de valeur pour ce site` +
        (v.warnings.length ? ` (${v.warnings.join(' ; ')})` : '') + '.',
    );
  }
  if (!LOGIN_RE.test(name) || name.includes('..')) {
    throw refuse('invalid_login', `Le login « ${p.usernameKey} » sort de l'alphabet autorisé ([A-Za-z0-9._-], 128 caractères au plus).`);
  }
  let remoteAddress: string | null = null;
  if (p.remoteAddressKey !== null) {
    const raw = v.values[p.remoteAddressKey];
    remoteAddress = hostAddress(raw ?? null);
    if (remoteAddress === null) {
      throw refuse(
        'variable_unresolved',
        `La variable « ${p.remoteAddressKey} » (adresse distante) n'a pas de valeur IPv4 pour ce site.`,
      );
    }
  }
  const comment = infraComment(v.siteCode);
  if (comment.length > 160 || CONTROL_RE.test(comment)) {
    throw refuse('invalid_site_code', 'Le code du site ne peut pas être écrit en commentaire RouterOS.');
  }
  return {
    name,
    remoteAddress,
    profile: p.pppProfile,
    comment,
    passwordResolvable: v.secrets.has(p.passwordKey) || v.values[p.passwordKey] !== undefined,
    warnings: v.warnings,
  };
}

/** The spec, without the password (preview, enqueue, read-back). */
export async function resolveL2tpSpec(c: InfraConcentratorRow, tenantId: number, siteId: number): Promise<InfraL2tpSpec> {
  return specFrom(c, await deps.siteValues(tenantId, siteId, false));
}

/** The spec WITH the password, in memory, for the one API word that carries
 *  it. Only the job's apply step calls this. */
export async function resolveL2tpCredential(
  c: InfraConcentratorRow,
  tenantId: number,
  siteId: number,
): Promise<InfraL2tpSpec & { password: string }> {
  const v = await deps.siteValues(tenantId, siteId, true);
  const spec = specFrom(c, v);
  const password = v.secrets.get(c.params.passwordKey) ?? v.values[c.params.passwordKey];
  if (password === undefined || password === '') {
    throw refuse(
      'password_unresolved',
      `La variable « ${c.params.passwordKey} » (mot de passe PPP d'infrastructure) n'a pas de valeur pour ce site. ` +
        "Rien n'a été écrit.",
    );
  }
  if (CONTROL_RE.test(password)) {
    // Never says which character: that is a bit of a credential.
    throw refuse('password_unusable', 'Le mot de passe contient un caractère que RouterOS ne peut pas porter. Rien n\'a été écrit.');
  }
  if (!v.secrets.has(c.params.passwordKey)) {
    logger.warn(
      { concentratorId: c.id, key: c.params.passwordKey },
      'infra concentrator: the password variable is stored IN CLEAR, not as a secret',
    );
  }
  return { ...spec, password };
}
