import apiClient from './client';
import type { ApiResponse, SimLineSecretField, TransportKind } from '@obliwan/shared';

/**
 * Revealing a stored secret in clear — the client of `SECRET_READ`'s four
 * routes (server/src/routes/secretReveal.routes.ts).
 *
 * Each call returns ONE plaintext and nothing keeps it here: no store, no
 * cache, no module-level variable. The caller (`RevealSecretButton`) holds it
 * in component state for a few seconds and drops it. The server answers
 * `Cache-Control: no-store`, writes an `audit_log` row per reveal, and limits
 * a user to 30 reveals per 5 minutes.
 *
 * POST, not GET, on purpose: a GET is what browsers, proxies and history lists
 * feel free to cache, prefetch and replay.
 */

/** A level of `config_variables` that stores values (never `computed` / `bench`). */
export type RevealVariableScope = 'instance' | 'global' | 'tenant' | 'group' | 'site' | 'device';

export type TransportSecretField = 'secret' | 'privateKey';
export type SnmpSecretField = 'community' | 'authKey' | 'privKey';

function valueOf(res: { data: ApiResponse<{ value?: unknown }> }): string {
  const value = res.data.data?.value;
  // A 200 without a string is a server defect; failing beats showing "undefined".
  if (typeof value !== 'string') throw new Error('The server returned no value.');
  return value;
}

export const secretsApi = {
  /** One secret template variable at exactly one level. `instance` needs a platform admin. */
  async revealVariable(input: { scope: RevealVariableScope; scopeId?: number | null; key: string }): Promise<string> {
    const body: { scope: RevealVariableScope; key: string; scopeId?: number } = { scope: input.scope, key: input.key };
    if (input.scopeId !== undefined && input.scopeId !== null) body.scopeId = input.scopeId;
    return valueOf(await apiClient.post<ApiResponse<{ value?: unknown }>>('/variables/reveal', body));
  },

  /** The password (`secret`) or the private key of one channel of one device. */
  async revealTransport(deviceId: number, transport: TransportKind, field: TransportSecretField = 'secret'): Promise<string> {
    return valueOf(await apiClient.post<ApiResponse<{ value?: unknown }>>(
      `/devices/${deviceId}/transports/${transport}/reveal`,
      { field },
    ));
  },

  /** The community (v1/v2c) or one of the v3 keys of an SNMP credential. */
  async revealSnmpCredential(credentialId: number, field: SnmpSecretField): Promise<string> {
    return valueOf(await apiClient.post<ApiResponse<{ value?: unknown }>>(
      `/snmp/credentials/${credentialId}/reveal`,
      { field },
    ));
  },

  /** A secret a learning capture vaulted for a site (`learned_secrets`). Audited. */
  async revealLearnedSecret(secretId: number): Promise<string> {
    return valueOf(await apiClient.post<ApiResponse<{ value?: unknown }>>(`/learning/secrets/${secretId}/reveal`, {}));
  },

  /** A mobile line's PUK1, PUK2, RADIUS password or RIO. SIM_READ + SECRET_READ, audited. */
  async revealSimLineSecret(lineId: number, field: SimLineSecretField): Promise<string> {
    return valueOf(await apiClient.post<ApiResponse<{ value?: unknown }>>(
      `/sim/lines/${lineId}/reveal`,
      { field },
    ));
  },
};
