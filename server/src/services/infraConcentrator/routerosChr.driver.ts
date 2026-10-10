/**
 * ObliWAN — infrastructure concentrator driver: a customer's own RouterOS CHR
 * (customer A: the stores' `l2tp-infra` client, L2TP over IPsec, PPP login = the
 * site code).
 *
 * The concentrator-secret machinery (services/change/concentratorSecret.service.ts),
 * applied to ANOTHER CHR with ANOTHER login:
 *   - reached through the CHR's devices row and the process-wide RouterOS pool
 *     (its credential is the device transport's, in the vault);
 *   - read with TWO FILTERED queries (`?name=`, and `?remote-address=` when the
 *     concentrator declares one) and an allow-listed `.proplist` naming no
 *     password. NEVER a full `/ppp/secret/print`: commit 0772c0d's rule —
 *     a print of every secret timed out through the link and cost whole
 *     accounts. API queries are exact and case-sensitive, so a case variant of
 *     the name is not looked for (said in the plan, never guessed);
 *   - written by exactly one `/ppp/secret/add`, the password word built LAST
 *     and only here, the audited text carrying `password=***`, a refusal
 *     scrubbed of the value before it can reach a column;
 *   - revoked by exactly one `/ppp/secret/remove` of an entry whose comment is
 *     ObliWAN's for THIS site (`obliwan:infra:<code>`): an account ObliWAN did
 *     not create is somebody's working tunnel, and is never removed.
 *
 * An entry found with the right name, service, profile (when one is set) and
 * remote-address (when one is set), and enabled, is the site's account
 * whatever its comment: the stores were connected long before ObliWAN, and
 * their accounts are ADOPTED as they are. Its password is never compared — it
 * is never read back — and the plan says so.
 */

import { randomUUID } from 'crypto';
import type { InfraAccountAction, InfraDriverResult, InfraPlanView } from '@obliwan/shared';
import { db } from '../../db';
import { auditedCommand, type CommandIntent } from '../audit.service';
import { hostAddress } from '../change/concentratorSecret.service';
import { parseSecretRow, type PppSecretEntry } from '../fleet/concentratorDiscovery.service';
import { getRouterOsPool, resolveRouterOsTarget } from '../fleet/routerosPool';
import {
  CircuitOpenError,
  RouterOsAuthError,
  RouterOsConnectionClosedError,
  RouterOsFingerprintError,
  RouterOsTimeoutError,
  RouterOsTrapError,
  type RouterOsConnection,
} from '../transport/routeros';
import { resolveL2tpCredential, resolveL2tpSpec, type InfraL2tpSpec } from './credentials';
import {
  InfraConcentratorError,
  type InfraConcentratorDriver,
  type InfraConcentratorRow,
  type InfraExecContext,
  type InfraJobSpec,
  type InfraSiteRef,
  type InfraStepResult,
} from './types';

// ============================================================================
// The decision — pure
// ============================================================================

export interface InfraExpectedSecret {
  name: string;
  remoteAddress: string | null;
  profile: string | null;
  comment: string;
}

/** French: what makes an entry NOT this site's account. `afterAdd`: the job
 *  wrote it, so its comment and its `default` profile are checked too. */
export function infraSecretMismatches(
  entry: PppSecretEntry,
  expected: InfraExpectedSecret,
  options: { afterAdd?: boolean } = {},
): string[] {
  const out: string[] = [];
  if (expected.remoteAddress !== null && hostAddress(entry.remoteAddress) !== expected.remoteAddress) {
    out.push(`remote-address vaut ${entry.remoteAddress ?? '(aucune)'}, attendu ${expected.remoteAddress}`);
  }
  const service = entry.service ?? 'any';
  if (service !== 'l2tp' && service !== 'any') out.push(`service vaut ${service}, attendu l2tp`);
  const wanted = expected.profile ?? (options.afterAdd ? 'default' : null);
  const profile = entry.profile ?? 'default';
  if (wanted !== null && profile !== wanted) out.push(`profil ${profile}, attendu ${wanted}`);
  if (entry.disabled) out.push("le compte est désactivé (ObliWAN ne réactive pas un compte existant)");
  if (options.afterAdd && (entry.comment ?? '') !== expected.comment) {
    out.push(`commentaire « ${entry.comment ?? ''} », attendu « ${expected.comment} »`);
  }
  return out;
}

export type InfraEnsureDecision =
  | { decision: 'add' }
  | { decision: 'present'; entry: PppSecretEntry; ours: boolean }
  | { decision: 'conflict'; reasons: string[] };

export function decideInfraEnsure(entries: PppSecretEntry[], expected: InfraExpectedSecret): InfraEnsureDecision {
  const exact = entries.filter((e) => e.name === expected.name);
  const lower = expected.name.toLowerCase();
  const otherCase = entries.filter((e) => e.name !== expected.name && e.name.toLowerCase() === lower);
  const sameAddress = expected.remoteAddress === null
    ? []
    : entries.filter((e) => e.name.toLowerCase() !== lower && hostAddress(e.remoteAddress) === expected.remoteAddress);
  const reasons: string[] = [];
  if (exact.length > 1) reasons.push(`${exact.length} comptes s'appellent « ${expected.name} »`);
  for (const e of otherCase) reasons.push(`un compte « ${e.name} » ne diffère de « ${expected.name} » que par la casse`);
  for (const e of sameAddress) reasons.push(`l'adresse ${expected.remoteAddress} est déjà déclarée par le compte « ${e.name} »`);
  if (exact.length === 1) {
    const diff = infraSecretMismatches(exact[0], expected);
    if (diff.length > 0) reasons.push(`le compte « ${expected.name} » existe et diffère : ${diff.join(' ; ')}`);
  }
  if (reasons.length > 0) return { decision: 'conflict', reasons };
  if (exact.length === 1) return { decision: 'present', entry: exact[0], ours: (exact[0].comment ?? '') === expected.comment };
  return { decision: 'add' };
}

export type InfraRevokeDecision =
  | { decision: 'remove'; entry: PppSecretEntry }
  | { decision: 'absent' }
  | { decision: 'conflict'; reasons: string[] };

export function decideInfraRevoke(entries: PppSecretEntry[], expected: InfraExpectedSecret): InfraRevokeDecision {
  const exact = entries.filter((e) => e.name === expected.name);
  if (exact.length === 0) return { decision: 'absent' };
  if (exact.length > 1) return { decision: 'conflict', reasons: [`${exact.length} comptes s'appellent « ${expected.name} »`] };
  const e = exact[0];
  if ((e.comment ?? '') !== expected.comment) {
    return {
      decision: 'conflict',
      reasons: [
        `le compte « ${expected.name} » porte le commentaire « ${e.comment ?? ''} » et non « ${expected.comment} » : ` +
          "ObliWAN ne l'a pas créé pour ce site et ne retire que les comptes qu'il a lui-même créés",
      ],
    };
  }
  if (!e.routerId) return { decision: 'conflict', reasons: [`le CHR n'a pas donné d'identifiant (.id) pour « ${expected.name} »`] };
  return { decision: 'remove', entry: e };
}

/** The API words of the one add. The password word is built LAST and only here. */
export function addInfraSecretWords(expected: InfraExpectedSecret, password: string): string[] {
  const words = ['/ppp/secret/add', `=name=${expected.name}`, '=service=l2tp', `=comment=${expected.comment}`];
  if (expected.remoteAddress !== null) words.push(`=remote-address=${expected.remoteAddress}`);
  if (expected.profile !== null) words.push(`=profile=${expected.profile}`);
  words.push(`=password=${password}`);
  return words;
}

/** The same command as `command_audit` stores it: never the password. */
export function addInfraSecretAuditText(expected: InfraExpectedSecret): string {
  return (
    `/ppp/secret/add name=${expected.name} password=*** service=l2tp comment=${expected.comment}` +
    (expected.remoteAddress !== null ? ` remote-address=${expected.remoteAddress}` : '') +
    (expected.profile !== null ? ` profile=${expected.profile}` : '')
  );
}

const PRINT_WORDS = [
  '/ppp/secret/print',
  // No-secrets rule: an allow-list, so no password crosses the wire.
  '=.proplist=.id,name,service,profile,remote-address,comment,disabled',
];

function scrub(text: string, secret: string): string {
  if (!secret || !text.includes(secret)) return text;
  if (secret.length < 4) return 'RouterOS a refusé la commande (message retenu : il pourrait contenir le mot de passe)';
  return text.split(secret).join('***');
}

// ============================================================================
// Reading
// ============================================================================

function intent(ctx: InfraExecContext, command: string, isWrite: boolean, secrets: string[] = []): CommandIntent {
  return {
    tenantId: ctx.auditTenantId,
    deviceId: ctx.device.id,
    deviceUuid: ctx.device.uuid ?? null,
    deviceName: ctx.device.name ?? null,
    jobId: ctx.jobId,
    transport: 'routeros_api',
    command,
    isWrite,
    correlationId: ctx.correlationId,
    secrets,
  };
}

/** The entries that can decide this account: two FILTERED queries, never a
 *  full print (header). */
async function readEntries(
  conn: RouterOsConnection,
  ctx: InfraExecContext,
  expected: InfraExpectedSecret,
): Promise<PppSecretEntry[]> {
  const queries = [[...PRINT_WORDS, `?name=${expected.name}`]];
  if (expected.remoteAddress !== null) queries.push([...PRINT_WORDS, `?remote-address=${expected.remoteAddress}`]);
  const byId = new Map<string, Record<string, string>>();
  for (const words of queries) {
    const rows = await auditedCommand(intent(ctx, words.join(' '), false), () => conn.query(words));
    for (const r of rows) byId.set(r['.id'] ?? `${r.name ?? ''}|${r['remote-address'] ?? ''}`, r);
  }
  const entries = [...byId.values()].map(parseSecretRow).filter((e): e is PppSecretEntry => e !== null);
  // A filtered query answers only what it was asked; keep only what concerns
  // this account (a server that ignored a filter must not widen the decision).
  return entries.filter(
    (e) =>
      e.name.toLowerCase() === expected.name.toLowerCase() ||
      (expected.remoteAddress !== null && hostAddress(e.remoteAddress) === expected.remoteAddress),
  );
}

function observedOf(entries: PppSecretEntry[]): Array<Record<string, string | boolean | null>> {
  return entries.map((e) => ({
    name: e.name,
    service: e.service,
    profile: e.profile,
    remoteAddress: e.remoteAddress,
    comment: e.comment,
    disabled: e.disabled,
  }));
}

async function chrDevice(c: InfraConcentratorRow): Promise<{ id: number; uuid: string | null; name: string; system_identity: string | null }> {
  if (c.device_id === null) {
    throw new InfraConcentratorError('no_device', "Ce CHR n'est lié à aucun appareil : ObliWAN ne sait pas comment le joindre.", 422);
  }
  const d = (await db('devices').where({ id: c.device_id }).first('id', 'uuid', 'name', 'system_identity')) as
    | { id: number; uuid: string | null; name: string; system_identity: string | null }
    | undefined;
  if (!d) throw new InfraConcentratorError('no_device', `L'appareil ${c.device_id} de ce CHR n'existe plus.`, 422);
  return d;
}

/** A transport failure, in French, with a closed code. */
export function describeChrFailure(err: unknown): { code: string; message: string } {
  const raw = err instanceof Error ? err.message : String(err);
  if (err instanceof InfraConcentratorError) return { code: err.code, message: err.message };
  if (err instanceof RouterOsAuthError || /login failed|invalid user name or password/i.test(raw)) {
    return { code: 'AUTH_REFUSED', message: `Le CHR a refusé l'identifiant de son canal RouterOS (coffre de l'appareil) : ${raw}` };
  }
  if (err instanceof RouterOsFingerprintError) return { code: 'TLS_PIN_MISMATCH', message: `Empreinte TLS différente de celle épinglée : ${raw}` };
  if (err instanceof RouterOsTimeoutError) return { code: 'TIMEOUT', message: `Le CHR n'a pas répondu à temps : ${raw}` };
  if (err instanceof RouterOsConnectionClosedError) return { code: 'CONNECTION_CLOSED', message: `La session RouterOS s'est fermée : ${raw}` };
  if (err instanceof CircuitOpenError) return { code: 'CIRCUIT_OPEN', message: `Le CHR est en quarantaine après des échecs répétés : ${raw}` };
  if (err instanceof RouterOsTrapError) return { code: 'ROUTEROS_TRAP', message: `RouterOS a refusé la commande : ${raw}` };
  if (/ECONNREFUSED|EHOSTUNREACH|ENETUNREACH|ETIMEDOUT|EAI_AGAIN|ENOTFOUND/i.test(raw)) {
    return { code: 'UNREACHABLE', message: `Le CHR est injoignable : ${raw}` };
  }
  return { code: 'ERROR', message: `Échec du dialogue avec le CHR : ${raw}` };
}

function expectedOfJob(job: InfraJobSpec): InfraExpectedSecret {
  return { name: job.identifier, remoteAddress: job.remoteAddress, profile: job.pppProfile, comment: job.comment };
}

function expectedOfSpec(spec: InfraL2tpSpec): InfraExpectedSecret {
  return { name: spec.name, remoteAddress: spec.remoteAddress, profile: spec.profile, comment: spec.comment };
}

// ============================================================================
// The driver
// ============================================================================

async function planChr(
  c: InfraConcentratorRow,
  site: InfraSiteRef,
  action: InfraAccountAction,
): Promise<InfraPlanView> {
  const base = { concentratorId: c.id, siteId: site.siteId, action, observed: [] as InfraPlanView['observed'] };
  let spec: InfraL2tpSpec;
  try {
    spec = await resolveL2tpSpec(c, site.tenantId, site.siteId);
  } catch (err) {
    const d = describeChrFailure(err);
    return { ...base, decision: 'refused', identifier: null, message: d.message, reasons: [], code: d.code };
  }
  const expected = expectedOfSpec(spec);
  const device = await chrDevice(c);
  const ctx: InfraExecContext = {
    auditTenantId: c.tenant_id,
    jobId: null,
    correlationId: randomUUID(),
    device,
  };
  let entries: PppSecretEntry[];
  try {
    const target = await resolveRouterOsTarget(device.id);
    entries = await getRouterOsPool().withConnection(target, (conn) => readEntries(conn, ctx, expected));
  } catch (err) {
    const d = describeChrFailure(err);
    return { ...base, decision: 'refused', identifier: spec.name, message: d.message, reasons: [], code: d.code };
  }
  const observed = observedOf(entries);
  const notes = [
    ...spec.warnings,
    'Les variantes de casse du login ne sont pas recherchées (requêtes RouterOS exactes ; aucune lecture complète des comptes).',
  ];
  if (action === 'revoke') {
    const d = decideInfraRevoke(entries, expected);
    if (d.decision === 'absent') {
      return { ...base, observed, decision: 'absent', identifier: spec.name, code: 'OK', reasons: notes,
        message: `Le compte « ${spec.name} » n'existe pas sur ${c.name} : rien à retirer.` };
    }
    if (d.decision === 'conflict') {
      return { ...base, observed, decision: 'conflict', identifier: spec.name, code: 'CONFLICT', reasons: d.reasons,
        message: `Retrait refusé : ${d.reasons.join(' | ')}.` };
    }
    return { ...base, observed, decision: 'remove', identifier: spec.name, code: 'OK', reasons: notes,
      message: `Le compte « ${spec.name} » (créé par ObliWAN pour ce site) serait retiré de ${c.name}.` };
  }
  const d = decideInfraEnsure(entries, expected);
  if (d.decision === 'conflict') {
    return { ...base, observed, decision: 'conflict', identifier: spec.name, code: 'CONFLICT', reasons: d.reasons,
      message: `Conflit, rien ne serait écrit : ${d.reasons.join(' | ')}. ObliWAN ne modifie ni ne retire jamais un compte existant.` };
  }
  if (d.decision === 'present') {
    return { ...base, observed, decision: 'present', identifier: spec.name, code: 'OK', reasons: notes,
      message:
        `Le compte « ${spec.name} » est déjà présent sur ${c.name}` +
        (d.ours ? ' (créé par ObliWAN).' : " (créé hors ObliWAN : adopté tel quel, son commentaire n'est pas réécrit).") +
        " Son mot de passe n'est pas comparé : il n'est jamais relu." };
  }
  if (!spec.passwordResolvable) {
    return { ...base, observed, decision: 'refused', identifier: spec.name, code: 'password_unresolved', reasons: notes,
      message: `Le compte « ${spec.name} » est absent de ${c.name}, et la variable « ${c.params.passwordKey} » n'a pas de valeur : il ne peut pas être créé.` };
  }
  return { ...base, observed, decision: 'add', identifier: spec.name, code: 'OK', reasons: notes,
    message:
      `Le compte « ${spec.name} » est absent de ${c.name} : il serait créé (service l2tp` +
      (spec.remoteAddress ? `, remote-address ${spec.remoteAddress}` : '') +
      `, profil ${spec.profile ?? 'default'}, commentaire « ${spec.comment} »).` };
}

export const routerosChrDriver: InfraConcentratorDriver = {
  kind: 'routeros_chr',
  writesImplemented: true,

  async testConnection(c): Promise<InfraDriverResult> {
    let device: Awaited<ReturnType<typeof chrDevice>>;
    try {
      device = await chrDevice(c);
    } catch (err) {
      const d = describeChrFailure(err);
      return { ok: false, code: d.code, message: d.message, details: [] };
    }
    const ctx: InfraExecContext = { auditTenantId: c.tenant_id, jobId: null, correlationId: randomUUID(), device };
    try {
      const target = await resolveRouterOsTarget(device.id);
      const facts = await getRouterOsPool().withConnection(target, async (conn) => {
        const identity = await auditedCommand(intent(ctx, '/system/identity/print', false), () => conn.query(['/system/identity/print']));
        const resource = await auditedCommand(intent(ctx, '/system/resource/print', false), () =>
          conn.query(['/system/resource/print', '=.proplist=version,board-name']));
        return { identity: identity[0]?.name ?? null, version: resource[0]?.version ?? null, board: resource[0]?.['board-name'] ?? null };
      });
      const details = [
        `Identité lue : « ${facts.identity ?? '?'} »`,
        `RouterOS ${facts.version ?? '?'}${facts.board ? ` (${facts.board})` : ''}`,
      ];
      if (device.system_identity && facts.identity !== device.system_identity) {
        return {
          ok: false,
          code: 'IDENTITY_MISMATCH',
          message:
            `Le CHR joint répond « ${facts.identity ?? '?'} », alors que l'appareil ${device.name} est inventorié ` +
            `« ${device.system_identity} » : ce n'est peut-être pas la bonne machine. Rien n'y sera écrit.`,
          details,
        };
      }
      return { ok: true, code: 'OK', message: `Connexion RouterOS établie avec ${c.name} (appareil ${device.name}).`, details };
    } catch (err) {
      const d = describeChrFailure(err);
      return { ok: false, code: d.code, message: d.message, details: [] };
    }
  },

  async readSiteEntry(c, site) {
    const plan = await planChr(c, site, 'ensure');
    // A read states what IS, not what a job would do.
    if (plan.decision === 'add') {
      return { ...plan, decision: 'absent', message: `Aucun compte « ${plan.identifier} » sur ${c.name}.` };
    }
    return plan;
  },

  plan: planChr,

  async apply(c, job, ctx): Promise<InfraStepResult> {
    // The credential, at the last moment, and still what the job was queued with.
    const cred = await resolveL2tpCredential(c, job.tenantId, job.siteId);
    const moved: string[] = [];
    if (cred.name !== job.identifier) moved.push('login');
    if (cred.remoteAddress !== job.remoteAddress) moved.push('adresse distante');
    if (cred.profile !== job.pppProfile) moved.push('profil PPP');
    if (moved.length > 0) {
      throw new InfraConcentratorError(
        'spec_moved',
        `Les valeurs du site ont changé depuis la mise en file (${moved.join(', ')}). Rien n'a été écrit ; relancez une demande.`,
        409,
      );
    }
    const expected = expectedOfJob(job);
    const password = cred.password;
    const target = await resolveRouterOsTarget(ctx.device.id);
    // A refusal the CHR ANSWERED leaves the callback as a VALUE, thrown below:
    // the pool counts what is thrown inside against the CHR's breaker
    // (concentratorSecret.service.ts, the same rule).
    const decided = await getRouterOsPool().withConnection(target, async (conn): Promise<InfraStepResult | InfraConcentratorError> => {
      const entries = await readEntries(conn, ctx, expected);
      const d = decideInfraEnsure(entries, expected);
      if (d.decision === 'conflict') {
        return new InfraConcentratorError(
          'infra_account_conflict',
          `Refusé, rien n'a été écrit : ${d.reasons.join(' | ')}. ObliWAN ne modifie ni ne retire jamais un compte existant ; ` +
            'corrigez-le sur le concentrateur, puis relancez.',
          409,
          'conflict',
        );
      }
      if (d.decision === 'present') {
        return {
          outcome: 'present',
          output:
            `Compte « ${expected.name} » déjà présent sur ${c.name}` +
            (d.ours ? ' (créé par ObliWAN)' : ' (créé hors ObliWAN, adopté tel quel)') +
            " ; rien n'a été écrit. Son mot de passe n'est pas comparé (jamais relu).",
          detail: { outcome: 'present', ours: d.ours },
        };
      }
      ctx.onWrite?.();
      try {
        await auditedCommand(intent(ctx, addInfraSecretAuditText(expected), true, [password]), async () => {
          try {
            return await conn.query(addInfraSecretWords(expected, password));
          } catch (err) {
            const message = scrub(err instanceof Error ? err.message : String(err), password);
            if (err instanceof RouterOsTrapError) throw new InfraConcentratorError('infra_account_add_refused', `RouterOS a refusé l'ajout : ${message}`, 502);
            throw new InfraConcentratorError(
              'infra_account_add_unconfirmed',
              `La réponse du CHR à l'ajout est perdue (${message}) : le compte existe peut-être ; relancez, le job relit d'abord le CHR.`,
              504,
            );
          }
        });
      } catch (err) {
        if (err instanceof InfraConcentratorError && err.code === 'infra_account_add_refused') return err;
        throw err;
      }
      return {
        outcome: 'added',
        output:
          `Compte « ${expected.name} » créé sur ${c.name} (service l2tp` +
          (expected.remoteAddress ? `, remote-address ${expected.remoteAddress}` : '') +
          `, profil ${expected.profile ?? 'default'}, commentaire « ${expected.comment} »).`,
        detail: { outcome: 'added' },
      };
    });
    if (decided instanceof InfraConcentratorError) throw decided;
    return decided;
  },

  async revoke(c, job, ctx): Promise<InfraStepResult> {
    const expected = expectedOfJob(job);
    const target = await resolveRouterOsTarget(ctx.device.id);
    const decided = await getRouterOsPool().withConnection(target, async (conn): Promise<InfraStepResult | InfraConcentratorError> => {
      const entries = await readEntries(conn, ctx, expected);
      const d = decideInfraRevoke(entries, expected);
      if (d.decision === 'conflict') {
        return new InfraConcentratorError('infra_account_conflict', `Retrait refusé, rien n'a été écrit : ${d.reasons.join(' | ')}.`, 409, 'conflict');
      }
      if (d.decision === 'absent') {
        return { outcome: 'absent', output: `Compte « ${expected.name} » absent de ${c.name} : rien à retirer.`, detail: { outcome: 'absent' } };
      }
      const words = ['/ppp/secret/remove', `=.id=${d.entry.routerId as string}`];
      ctx.onWrite?.();
      try {
        await auditedCommand(intent(ctx, `/ppp/secret/remove .id=${d.entry.routerId as string} (name=${expected.name})`, true), () =>
          conn.query(words));
      } catch (err) {
        if (err instanceof RouterOsTrapError) {
          return new InfraConcentratorError('infra_account_remove_refused', `RouterOS a refusé le retrait : ${err.message}`, 502);
        }
        throw err;
      }
      return { outcome: 'removed', output: `Compte « ${expected.name} » retiré de ${c.name}.`, detail: { outcome: 'removed' } };
    });
    if (decided instanceof InfraConcentratorError) throw decided;
    return decided;
  },

  async verify(c, job, ctx): Promise<InfraStepResult> {
    const expected = expectedOfJob(job);
    const target = await resolveRouterOsTarget(ctx.device.id);
    const entries = await getRouterOsPool().withConnection(target, (conn) => readEntries(conn, ctx, expected));
    const exact = entries.filter((e) => e.name === expected.name);
    if (job.action === 'revoke') {
      if (exact.length !== 0) {
        throw new InfraConcentratorError('infra_account_unverified', `Relecture : « ${expected.name} » est encore présent sur ${c.name}.`, 502);
      }
      return { output: `Relecture : « ${expected.name} » n'est plus sur ${c.name}.`, detail: { verified: true } };
    }
    if (exact.length !== 1) {
      throw new InfraConcentratorError(
        'infra_account_unverified',
        `Relecture : ${exact.length} compte(s) « ${expected.name} » sur ${c.name}, un seul attendu.`,
        502,
      );
    }
    const diff = infraSecretMismatches(exact[0], expected, { afterAdd: job.outcome === 'added' });
    if (diff.length > 0) {
      throw new InfraConcentratorError('infra_account_unverified', `Relecture de « ${expected.name} » non conforme : ${diff.join(' ; ')}.`, 502);
    }
    return {
      output: `Relecture : « ${expected.name} » présent une fois sur ${c.name}, activé (mot de passe non relu).`,
      detail: { verified: true },
    };
  },
};
