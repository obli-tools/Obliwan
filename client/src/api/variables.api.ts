import apiClient from './client';
import type { ApiResponse } from '@obliwan/shared';

/**
 * Inherited configuration variables.
 *
 * ┌─ THE ONE THING THIS API WILL NEVER GIVE YOU BACK ────────────────────────┐
 * │ A variable marked secret is encrypted on the way in and NEVER returned.   │
 * │ Its `value` comes back as the placeholder `__OBLIWAN_SECRET_<KEY>__`      │
 * │ with `isSecret: true`, `redacted: true` and a keyed fingerprint — at      │
 * │ every level of this API, with no parameter that changes it. A screen      │
 * │ must therefore show THAT a secret is set, never its `value` (which is     │
 * │ the placeholder, not the secret). The secrets rule: the plaintext leaves  │
 * │ the vault on the vault → device path, and otherwise only through the      │
 * │ audited reveal of `secrets.api.ts` (SECRET_READ) — never through this     │
 * │ API.                                                                      │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Levels, widest first: `instance` (one value for every tenant, platform
 * administrators write it) → `global` (despite its name, ONE tenant's widest
 * level) → `tenant` → group chain → `site` → `device`. A value set closer to
 * the device wins. `site` sits between the groups and the device on purpose
 * (server: `VARIABLE_SCOPE_RANK`): a group states a policy, a site states a
 * fact about one premises, and the fact must win.
 *
 * Wire shapes mirror `server/src/services/template/variableResolver.service.ts`
 * (`ResolvedVariable`, `SiteVariableForm`); the routes are
 * `server/src/routes/variables.routes.ts`.
 */

/** The five levels a tenant stores values at, widest first — the server's
 *  `VARIABLE_SCOPES`. `group`, `site` and `device` require a scope id. */
export type VariableScope = 'global' | 'tenant' | 'group' | 'site' | 'device';

/** Where a resolved value came from. `'default'` = the template's `var_schema`
 *  default; `'instance'` = the fleet-wide level below every tenant. */
export type VariableSource = VariableScope | 'instance' | 'default';

/** Any JSON value — what a variable holds. */
export type JsonValue = null | boolean | number | string | JsonValue[] | { [k: string]: JsonValue };

/** One variable as the server returns it (`ResolvedVariable`), redacted. */
export interface StoredVariable {
  key: string;
  /** The PLACEHOLDER when `isSecret` — never display it as a value. */
  value: JsonValue;
  source: string;
  sourceId: number | null;
  sourceName: string;
  sourceDepth: number | null;
  isSecret: boolean;
  redacted: boolean;
  fingerprint: unknown;
}

/** What every "values set at one level" read returns: keyed by variable key. */
export type StoredVariables = Record<string, StoredVariable>;

/** Loose shape of the folded reads (`forDevice` / `forGroup` / `forTenant`),
 *  kept loose because their report shape is the resolver's to own. */
export type ResolvedVariables = Record<string, unknown> & {
  variables?: unknown;
};

/** Which published template revision declared a site key. */
export interface DeclaredBy {
  templateId: number;
  templateName: string;
  revisionId: number;
  revision: number;
  library: boolean;
}

/** One field of the site form (`DeclaredSiteKey`). */
export interface DeclaredSiteKey {
  key: string;
  /** `x-obliwan-label` — the plain-language name, when the author gave one. */
  label: string | null;
  secret: boolean;
  level: string | null;
  /** The key's JSON Schema in the newest declaring revision. */
  schema: Record<string, unknown>;
  declaredBy: DeclaredBy[];
  consistent: boolean;
  /** Declarations disagree on secrecy: unwritable until a template author settles it. */
  secrecyConflict: boolean;
  /** Every declaration opens the key to the site form. */
  siteWritable: boolean;
  withheldBy: (DeclaredBy & { level: string | null })[];
}

/** `GET /variables/sites/:siteId`. */
export interface SiteVariableForm {
  site: { id: number; code: string; name: string };
  /** Every value set AT the site level, redacted — declared or not. */
  values: StoredVariables;
  /** One entry per declared key, sorted by key. */
  declared: DeclaredSiteKey[];
}

/** One refused site entry: the KEY and why, never the value. */
export interface SiteValueError {
  key: string;
  message: string;
}

export type SiteFormSaveResult =
  | { ok: true; written: string[]; unset: string[] }
  /** 422 — nothing was written; every refused key is listed. */
  | { ok: false; message: string; errors: SiteValueError[] };

function scopePath(scope: VariableScope, scopeId?: number): string {
  return scopeId === undefined ? `/variables/at/${scope}` : `/variables/at/${scope}/${scopeId}`;
}

export const variablesApi = {
  /** Everything that applies to a device, after the whole chain is folded. */
  async forDevice(deviceId: number): Promise<ResolvedVariables> {
    const res = await apiClient.get<ApiResponse<ResolvedVariables>>(`/variables/devices/${deviceId}`);
    return res.data.data ?? {};
  },

  async forGroup(groupId: number): Promise<ResolvedVariables> {
    const res = await apiClient.get<ApiResponse<ResolvedVariables>>(`/variables/groups/${groupId}`);
    return res.data.data ?? {};
  },

  async forTenant(): Promise<ResolvedVariables> {
    const res = await apiClient.get<ApiResponse<ResolvedVariables>>('/variables/tenant');
    return res.data.data ?? {};
  },

  /** The variables set AT one level of the current tenant, nothing inherited. */
  async atScope(scope: VariableScope, scopeId?: number): Promise<StoredVariables> {
    const res = await apiClient.get<ApiResponse<StoredVariables>>(scopePath(scope, scopeId));
    return res.data.data ?? {};
  },

  /** A secret must be a non-empty string; it goes to the vault and never comes
   *  back through this API (only through the audited reveal, `secrets.api.ts`). */
  async setAtScope(
    scope: VariableScope,
    scopeId: number | undefined,
    body: { key: string; value: JsonValue; isSecret?: boolean },
  ): Promise<void> {
    await apiClient.put(scopePath(scope, scopeId), body);
  },

  /**
   * The key travels in the QUERY STRING (`?key=`), never in a body: the
   * server's `removeAtScope` reads `req.query.key` and answers 400 to
   * anything else. axios encodes the value.
   */
  async removeAtScope(scope: VariableScope, scopeId: number | undefined, key: string): Promise<void> {
    await apiClient.delete(scopePath(scope, scopeId), { params: { key } });
  },

  // ── Instance level: one value for every tenant ────────────────────────────
  // Read: TEMPLATE_READ. Write: platform administrators only (the server
  // refuses anybody else with a 403).

  async instance(): Promise<StoredVariables> {
    const res = await apiClient.get<ApiResponse<StoredVariables>>('/variables/instance');
    return res.data.data ?? {};
  },

  async setInstance(body: { key: string; value: JsonValue; isSecret?: boolean }): Promise<void> {
    await apiClient.put('/variables/instance', body);
  },

  async removeInstance(key: string): Promise<void> {
    await apiClient.delete('/variables/instance', { params: { key } });
  },

  // ── Site form (read: TEMPLATE_READ or SITE_VARIABLES_WRITE; write:
  //    SITE_VARIABLES_WRITE) ─────────────────────────────────────────────────

  async siteForm(siteId: number): Promise<SiteVariableForm> {
    const res = await apiClient.get<ApiResponse<SiteVariableForm>>(`/variables/sites/${siteId}`);
    return res.data.data ?? { site: { id: siteId, code: '', name: '' }, values: {}, declared: [] };
  },

  /**
   * All or nothing. Whether a value goes to the vault is decided by the
   * template's declaration, never by this call — hence no `isSecret` here.
   * `unset` removes a key AT THE SITE, so the site falls back on what it
   * inherits. A 422 is returned as `{ ok: false }` with every refused key;
   * any other failure throws.
   */
  async saveSiteForm(
    siteId: number,
    body: { entries: { key: string; value: JsonValue }[]; unset: string[] },
  ): Promise<SiteFormSaveResult> {
    try {
      const res = await apiClient.put<ApiResponse<{ written: string[]; unset: string[] }>>(
        `/variables/sites/${siteId}`,
        body,
      );
      const done = res.data.data;
      return { ok: true, written: done?.written ?? [], unset: done?.unset ?? [] };
    } catch (err) {
      const r = (err as { response?: { status?: number; data?: { error?: unknown; errors?: unknown } } }).response;
      if (r?.status === 422 && r.data && Array.isArray(r.data.errors)) {
        const errors = (r.data.errors as unknown[]).filter(isSiteValueError);
        return { ok: false, message: typeof r.data.error === 'string' ? r.data.error : '', errors };
      }
      throw err;
    }
  },
};

function isSiteValueError(e: unknown): e is SiteValueError {
  return typeof e === 'object' && e !== null
    && typeof (e as SiteValueError).key === 'string'
    && typeof (e as SiteValueError).message === 'string';
}
