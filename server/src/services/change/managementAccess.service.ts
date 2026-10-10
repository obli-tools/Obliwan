/**
 * ObliWAN — the management API of a router already in service: api-ssl on
 * 8729, restricted to the management range, serving a certificate made ON the
 * router, opened by a change job over SSH (kind `management_access`,
 * migration 058).
 *
 * ┌─ WHY THIS JOB EXISTS ─────────────────────────────────────────────────────┐
 * │ ObliWAN reaches every CPE tunnel address through the WireGuard link to   │
 * │ the shared CHR, which masquerades it onto the per-tenant L2TP sessions — │
 * │ and those sessions are NOT encrypted and cross the internet. A cleartext │
 * │ RouterOS API session there would carry the account's password on every  │
 * │ poll. Design decision: the management API is api-ssl on                 │
 * │ 8729, restricted to the management range, with a certificate generated  │
 * │ on the router; ObliWAN pins its fingerprint on first contact. Routers   │
 * │ already in service answer only SSH today (the customer templates disable │
 * │ api and api-ssl), so this job travels over SSH, with the device's        │
 * │ EXISTING SSH credential — on a router attached from the reconciliation,  │
 * │ the historical `admin` account.                                          │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE `obliwan` ACCOUNT (operator decision 2026-10-04, binding) ──────────┐
 * │ ObliWAN must not keep dialling a customer router with `admin`, the        │
 * │ customer's and the technicians' account, unrestricted. So the job CREATES │
 * │ ObliWAN's own account, restricted to the management range, where the     │
 * │ router lacks it — the one written exception to "no user creation on      │
 * │ in-service routers" — and switches ObliWAN's SSH and API channels to it:  │
 * │   lint    reads `/user` and `/user group` for `obliwan` and decides       │
 * │           (`AccountPlan`), nothing written:                               │
 * │             - the SSH credential already IS `obliwan` (a bench router,    │
 * │               or an earlier run switched) -> `in_use`, untouched;         │
 * │             - no user `obliwan` -> `create`: the group too when absent;   │
 * │               a group of that name with ANOTHER policy is REFUSED by      │
 * │               name, never altered (one exception, box below); the       │
 * │               password is the one an earlier run left in the vault      │
 * │               (`account_secret_enc`, migration 071), else a new one from │
 * │               the bench's own generator;                                 │
 * │             - a user `obliwan` already there -> the password ObliWAN     │
 * │               holds for it (an earlier run's, or its API channel's) must  │
 * │               open a fresh, identity-proven SSH session NOW -> `present`, │
 * │               untouched. None held, or none accepted -> REFUSED by name: │
 * │               ObliWAN never resets a password it did not set.            │
 * │   apply   after api-ssl: the password is written to the vault FIRST      │
 * │           (this job's row), then `/user group add` and `/user add`, one  │
 * │           console command each, allow-listed (`assertAccountOnlyLines`), │
 * │           the password quoted by `routerOsQuoted` and protected on every │
 * │           audited command and error. Nothing else of `/user` is sent:    │
 * │           no remove, no other name, and one `set` only — the group      │
 * │           alignment below.                                               │
 * │   postcheck  api-ssl read back, then the API dialled AS `obliwan` on a    │
 * │           fresh TLS session (login + identity read) whose handshake       │
 * │           must show the certificate the router prints over SSH (or the    │
 * │           pin) BEFORE `/login` sends the password; then a fresh SSH       │
 * │           session as `obliwan` (login + identity read); only then are     │
 * │           the device's `routeros_api` AND `ssh` transports switched to    │
 * │           `obliwan`, in one transaction. Until then the previous          │
 * │           credential stays in place: a failed proof leaves the account    │
 * │           created and unused, says so, and keeps its password in the      │
 * │           vault so the next run converges on it instead of minting a      │
 * │           second one. A password a login DID carry to a certificate that  │
 * │           was not the expected one is disclosed: erased from the vault,   │
 * │           never reused, and the account refused until it is removed       │
 * │           (`account_secret_disclosed_at`, migration 071).                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE GROUP ALIGNMENT (operator decision 2026-10-05, binding) ────────────┐
 * │ `OBLIWAN_GROUP_POLICY` gained `sensitive` (shared/src/managementAccess.ts │
 * │ says why: without it the account cannot read the preflight `.backup`     │
 * │ over SFTP). Groups ObliWAN made before carry the old list. The job       │
 * │ ALIGNS such a group, and that is the one change it makes to something it │
 * │ finds — narrowly:                                                         │
 * │   - only a group named `obliwan` that carries `OBLIWAN_ACCOUNT_COMMENT`    │
 * │     (read at lint, `gcomment|`: ObliWAN made it, the bench or this job)  │
 * │     and whose granted policies are exactly the new list minus            │
 * │     `sensitive` — nothing extra, nothing else missing                    │
 * │     (`obliwanGroupAlignable`). Any other difference keeps the refusal   │
 * │     of the create path, by name; on the present and in_use paths, which  │
 * │     never judged the group, it is left as it is and said so;            │
 * │   - whatever the user's state: absent (`create`, the user is then added  │
 * │     into the aligned group), present (`present`), or the account the     │
 * │     job travels with (`in_use`);                                         │
 * │   - the account that sends the line must itself hold `sensitive` and     │
 * │     `policy` (`GROUP_ALIGNMENT_POLICIES`): RouterOS does not let an      │
 * │     account grant a policy its own group lacks (REASONED, not observed). │
 * │     On `create` that is the SSH account (its required policies already  │
 * │     include the group's), refused by name at lint otherwise; on          │
 * │     `present`, the SSH account when its group grants both (or does not   │
 * │     print — the router then judges, as for every other policy);          │
 * │   - otherwise — always on `in_use`, where the SSH account IS `obliwan`   │
 * │     and cannot grant itself `sensitive` — THE LEGACY SESSION: a separate │
 * │     SSH session with the historical `admin` account and its vault        │
 * │     password (`admin_password`, `RECONCILE_ATTACH_VAULT_KEY`), resolved  │
 * │     for THIS device's site (when the site is its tenant's), then its     │
 * │     tenant, global, instance — `resolveLegacyVariable`, the bench's and  │
 * │     the reconciliation's one resolution; never another site's or        │
 * │     tenant's. At lint, nothing written: the session's identity is        │
 * │     proven like every session of the job (a mismatch quarantines), the   │
 * │     account's group must grant both policies, and its SFTP road is       │
 * │     proven. It then carries ONLY the alignment line, its re-read and its │
 * │     read-back, plus — a read — the SFTP pull of the preflight backup:    │
 * │     the `.backup` an account without `sensitive` cannot read (the very   │
 * │     failure of 2026-10-05), so the job's own `obliwan` session saves the │
 * │     files and `admin` pulls them. It is never a transport, never stored, │
 * │     never logged; ObliWAN keeps dialling with `obliwan`. No credential, │
 * │     a refused login, a group lacking the policies, a closed SFTP road:  │
 * │     the alignment is NOT made and the job is NOT failed — it goes on as │
 * │     before (nothing to write, or api-ssl alone), and the plan and the   │
 * │     outcome carry the remedy (`alignmentRemedy`);                        │
 * │   - recorded on the job row whatever the plan: `observed.groupAlignment` │
 * │     (071's CHECK ties `account_detail` to `account_action`, so on the    │
 * │     create path the sentence waits for the user), the account's sentence │
 * │     when it has one, and appended to any refusal that follows it;        │
 * │   - ONE console command, allow-listed by an exact shape                  │
 * │     (`ACCOUNT_WRITES.groupAlign`): `/user group set [find where          │
 * │     name=obliwan comment="obliwan:access"] policy=<list>`, so a group    │
 * │     whose comment changed since lint is not matched; re-read on the      │
 * │     apply session before any write, sent FIRST in `apply` (before        │
 * │     api-ssl, the user, and every login as `obliwan`), and read back on   │
 * │     the same session: `judgeObliwanGroupPolicy` must say `same`, else    │
 * │     the job fails naming what it read.                                   │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE JOB, STEP BY STEP (a branch of `runPhases()` in apply.service.ts) ──┐
 * │   bind_assert   identity/SSH: `assertMikrotikBindingOverSsh()` below, a   │
 * │                 fresh SSH session, the same three attributes and the same │
 * │                 comparison (`compareIdentity`) as `assertTargetBinding`,  │
 * │                 which can only prove a MikroTik over its RouterOS API —   │
 * │                 the one channel these routers do not answer yet. A        │
 * │                 mismatch quarantines the device, as there.                │
 * │   guard         ACCEPT, by construction (`managementAccessGuard`): the    │
 * │                 job sends nothing but `/certificate`, the api-ssl         │
 * │                 service, the ADDITION of the `obliwan` group and user,    │
 * │                 and the alignment of the group ObliWAN made (box above),  │
 * │                 and refuses any other line before sending one.            │
 * │   lint          the frozen range still holds, the SSH address did not     │
 * │                 move, the SFTP road is PROVEN open (a probe, before any   │
 * │                 file exists); then, on one proven SSH session: the        │
 * │                 `obliwan` account's state and the plan for it (box       │
 * │                 above), the SSH account's group grants what that plan     │
 * │                 needs (when the router prints it), what the router        │
 * │                 carries (api-ssl, the two certificates), and the lines    │
 * │                 BUILT and passed through the allow-lists. Already as      │
 * │                 wanted -> nothing to write. Refused here, nothing         │
 * │                 written: a SIGNED certificate of our name that is not     │
 * │                 ready, an api-ssl enabled for a use that is not ObliWAN's │
 * │                 (`classifyEnabledApiSsl`). ObliWAN's OWN earlier state is │
 * │                 taken over, never refused: api-ssl serving obliwan-api or │
 * │                 obliwan-ca on 8729, and an unsigned obliwan-* template.   │
 * │   preflight_backup  binary + rsc, saved on the router, PULLED by SFTP     │
 * │                 over the SSH channel (a non-public address only: no SSH   │
 * │                 host key is pinned), proven, stored, erased, recorded.    │
 * │   arm_deadman   SKIPPED (MANAGEMENT_ACCESS_NO_DEADMAN).                   │
 * │   apply         the `obliwan` group aligned when lint planned it (box     │
 * │                 above), read back; an unsigned obliwan-* template lint    │
 * │                 found (and this session still sees) removed; then the     │
 * │                 lines of                                                  │
 * │                 shared/src/managementAccess.ts — the SAME builder as the  │
 * │                 bench compile — as ONE `/system script`, run once and     │
 * │                 removed, every command audited (skipped when api-ssl was  │
 * │                 already as wanted); then the `obliwan` group and user     │
 * │                 when the plan is `create`.                                │
 * │   postcheck     api-ssl read back over a NEW SSH session (enabled, 8729,  │
 * │                 the management range, `obliwan-api` holding its private   │
 * │                 key); then ONE RouterOS API identity read over TLS on     │
 * │                 8729 — as `obliwan` when the plan is `create`/`present`,  │
 * │                 else with the SSH credential — dialled EXPECTING the      │
 * │                 fingerprint the router prints for `obliwan-api` over SSH  │
 * │                 when it reads as a SHA-256 (or the pin it keeps), so a    │
 * │                 certificate the router does not declare is refused at the │
 * │                 handshake, before any credential is sent; for a switch, a │
 * │                 fresh SSH session as `obliwan` too; then, everything      │
 * │                 proven, the device's `routeros_api` transport written     │
 * │                 with the pin (created or updated: 8729, TLS, the account  │
 * │                 just proven) and, for a switch, its `ssh` transport moved │
 * │                 to `obliwan` in the SAME transaction.                     │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE PIN IS WRITTEN WITH THE ROW, NOT BEFORE IT ──────────────────────────┐
 * │ Trust-on-first-use (transport/routeros/connection.ts) pins what the first │
 * │ handshake shows. Here that first handshake is made by this job —          │
 * │ EXPECTING the fingerprint the router prints for `obliwan-api` over SSH    │
 * │ whenever that print reads as a SHA-256, so the certificate is checked     │
 * │ before `/login` sends any password; with no comparable print and no pin   │
 * │ it is plain trust-on-first-use, and the outcome says so — and the         │
 * │ transport row is written only AFTER it succeeded and the box answered     │
 * │ with this device's identity, with the fingerprint it saw. The end state   │
 * │ is the one "create the transport with no fingerprint, pin at first        │
 * │ contact" describes; the order means a failed first contact leaves the     │
 * │ device's previous API transport exactly as it was, instead of an enabled, │
 * │ unpinned row the pool would pin on its own later. A row already pinned on │
 * │ 8729, at the address the job dials, keeps its pin, and the job then dials │
 * │ EXPECTING it — unless this very run created the server certificate, which │
 * │ makes the old pin ours to replace; a pin the router's own SSH print       │
 * │ contradicts is refused before any dial. A pin that no longer matches is a │
 * │ refusal, never a re-pin.                                                  │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ WHAT IS NOT OBSERVED ────────────────────────────────────────────────────┐
 * │ No line of this file has reached a router. The RouterOS console commands  │
 * │ it sends over SSH (`:put` reads, `/user` and `/user group` reads,         │
 * │ `/user group add`, `/user add` with a quoted `password=`,                 │
 * │ `/system backup save`, `/export file=`, `/file`, `/certificate remove`,   │
 * │ `/system script add|run|remove` with a quoted `source=`), the string      │
 * │ escapes it relies on (`\\ \" \$ \? \n \r \t`), how `:tostr` prints a      │
 * │ group's policy list, that an account cannot give a group policies its    │
 * │ own group lacks, that `/user`'s `address=` also binds api-ssl and SSH     │
 * │ logins, and that RouterOS prints a certificate's fingerprint              │
 * │ as the SHA-256 of its DER are REASONED from the RouterOS manual. The      │
 * │ harness (testing/managementAccess.verify.ts) runs them against a fake SSH │
 * │ router that answers by the same assumptions, and runs the builder's       │
 * │ lines on the bench's MODEL of the script engine                           │
 * │ (bench/testing/fakeRouterOsScript.ts) — it proves this file's logic, not  │
 * │ RouterOS. The read-back is what decides success: a script that printed    │
 * │ nothing is judged by what the router carries afterwards, never assumed    │
 * │ to have worked.                                                           │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * SECRETS: the SSH password is decrypted for one session and never
 * leaves memory; the backup password and the `obliwan` password are
 * protected on every audited command and scrubbed from every error. None
 * reaches a step, an audit row, a log line or a response; the `obliwan`
 * password is stored only ENCRYPTED — on this job's row until the switch,
 * then in the device's transports. The legacy `admin` password (group
 * alignment box) is decrypted from the vault for the run, protected on its
 * sessions' audited commands and SFTP pulls, scrubbed from their errors, and
 * stored NOWHERE. Operator-facing sentences are French, like the bench's.
 */

import crypto from 'crypto';
import fsp from 'fs/promises';
import path from 'path';
import {
  API_SSL_PORT,
  API_SSL_REASON_PREFIX,
  API_SSL_SERVICE,
  CERTIFICATE_SIGN_WAIT_SECONDS,
  ManagementAccessInputError,
  OBLIWAN_ACCOUNT,
  OBLIWAN_ACCOUNT_COMMENT,
  OBLIWAN_API_CERTIFICATE,
  OBLIWAN_CA_CERTIFICATE,
  OBLIWAN_GROUP_POLICY,
  RECONCILE_ATTACH_DEFAULT_USERNAME,
  RECONCILE_ATTACH_VAULT_KEY,
  SOCKET_EVENTS,
  addressAtom,
  apiSslAccessLines,
  apiSslStateDifferences,
  isActiveJobStatus,
  managementTunnelLogin,
  serviceKey,
  type ApiSslAccessInput,
  type L2tpClientReading,
  type ApiSslStateDifference,
  type BackupKind,
  type ChangeJobStatus,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { auditedCommand } from '../audit.service';
import { currentKeyVersion, decrypt, encrypt } from '../secretVault.service';
import { emitToDevice } from '../fleet/fleetEvents';
import { emitToTenantAudience } from '../fleet/scopedEmit';
import { generateAccountPassword } from '../bench/obliwanAccount';
import { resolveLegacyVariable, type LegacyVariableScope } from '../bench/compile.service';
import {
  BindingAssertionError,
  compareIdentity,
  readRouterOsIdentity,
  type AttributeCheck,
  type BindingAssertion,
  type ObservedIdentity,
} from '../fleet/deviceBinding.service';
import { renameIdentityAlternates } from '../fleet/identityAlternates';
import { readManagementRange } from '../bench/planning.service';
import { withSsh, type SshExecResult, type SshTransport } from '../transport/ssh.transport';
import {
  RouterOsAuthError,
  RouterOsFingerprintError,
  createRouterOsConnection,
  type RouterOsConnection,
  type RouterOsConnectionOptions,
} from '../transport/routeros';
import { ExportDialectRefusal, assertSshBoxSpeaksFamily, routerOsExportCommand } from '../drivers/mikrotik/driver';
import { DriverError } from '../drivers/types';
import {
  MIN_BACKUP_BYTES,
  assertNoSecrets,
  assertRscCarriesNoSecret,
  backupBaseName,
  backupRoot,
  redactForAudit,
  retentionDays,
} from './backup.service';
import {
  TransferError,
  defaultSpoolDir,
  hashFile,
  isNonPublicAddress,
  sftpPullFile,
  sftpPullToSpool,
  verifyArtefact,
  type ReceivedFile,
} from './transfer.service';
import { KillSwitchEngagedError, readKillSwitch } from './killSwitch.service';
import { DeviceBusyError, renewLease, type ChangeJobRow } from './jobQueue.service';

// ============================================================================
// Vocabulary
// ============================================================================

export const MANAGEMENT_ACCESS_KIND = 'management_access' as const;

/**
 * What the job concluded. Mirrors `management_access_jobs_outcome_chk` (058).
 *  - `enabled`  this job wrote, read api-ssl back as wanted, and pinned the API;
 *  - `present`  api-ssl was already as wanted: nothing written on the router,
 *               the API reached and pinned;
 *  - `refused`  ended before anything was written on the router;
 *  - `failed`   ended after a write on the router.
 */
export const MANAGEMENT_ACCESS_OUTCOMES = ['enabled', 'present', 'refused', 'failed'] as const;
export type ManagementAccessOutcome = (typeof MANAGEMENT_ACCESS_OUTCOMES)[number];

/** What the job did to the device's `routeros_api` transport (058). */
export const MANAGEMENT_ACCESS_TRANSPORT_ACTIONS = ['created', 'updated', 'unchanged'] as const;
export type ManagementAccessTransportAction = (typeof MANAGEMENT_ACCESS_TRANSPORT_ACTIONS)[number];

/** What the job did about the `obliwan` account. Mirrors
 *  `management_access_jobs_account_action_chk` (071), whose header says what
 *  each one means. */
export const MANAGEMENT_ACCOUNT_ACTIONS = ['in_use', 'created', 'present', 'refused'] as const;
export type ManagementAccountAction = (typeof MANAGEMENT_ACCOUNT_ACTIONS)[number];

/** A refusal of this service. apply.service turns it into a
 *  `ChangeRefusedError` with the same `kind`; the controller maps `httpStatus`. */
export class ManagementAccessError extends Error {
  constructor(
    readonly kind: string,
    message: string,
    readonly httpStatus = 409,
    /** The transport's own code when this wraps a `DriverError` (`ssh_failed`):
     *  `AUTH_FAILED` is how the job tells "this password was refused" from
     *  "the router did not answer". */
    readonly driverCode: string | null = null,
  ) {
    super(message);
    this.name = 'ManagementAccessError';
  }
}

export const MANAGEMENT_ACCESS_NO_DEADMAN =
  "Aucun dead-man n'est armé pour 'management_access' : la tâche n'envoie que /certificate, le service " +
  "api-ssl, l'AJOUT du groupe et de l'utilisateur « obliwan » quand ils manquent, et l'ajout de la politique " +
  "sensitive au groupe « obliwan » qu'ObliWAN a lui-même créé (commentaire obliwan:access) quand c'est la seule " +
  "politique qui lui manque (toute autre ligne est " +
  "refusée avant l'envoi), et ne touche jamais le service SSH par lequel elle passe, ni le pare-feu, les " +
  "adresses, les routes, ni aucun compte existant (aucun utilisateur n'est retiré ni modifié, aucun mot de " +
  "passe n'est changé). Elle ajoute le chemin de gestion d'ObliWAN " +
  "(api-ssl) sans toucher celui qu'elle emprunte ; un api-ssl utilisé pour autre chose qu'ObliWAN (un autre " +
  "port, un certificat qui n'est pas le sien, ou aucun certificat et des adresses hors de la plage) est refusé " +
  "à l'inspection, sans écriture, et celui qu'ObliWAN a lui-même réglé (obliwan-api ou obliwan-ca sur 8729) est " +
  'repris. La sauvegarde préalable est prise ' +
  'avant la première écriture ; la tâche est mise en file au niveau de sécurité degraded, avec la confirmation ' +
  'explicite de l’opérateur.';

export const MANAGEMENT_ACCESS_NO_APPLY_OUTCOME =
  "No row written to apply_outcomes: 'management_access' opens api-ssl with no net, it is not an " +
  'observation of how this hardware survives a change. Its outcome is on management_access_jobs.';

/** The guard verdict for this kind: ACCEPT, by construction (header). */
export function managementAccessGuard(): {
  verdict: 'ACCEPT';
  reasons: unknown[];
  summary: string;
  unavailable: false;
} {
  return {
    verdict: 'ACCEPT',
    reasons: [
      {
        code: 'API_SSL_ADDITIVE_PATH',
        effect: 'accept',
        message:
          'Adds (or reuses) the obliwan-ca and obliwan-api certificates — an unsigned obliwan-* template an earlier ' +
          'run left is removed first — enables api-ssl restricted to the management range, and ADDS the obliwan ' +
          'group and user when the router lacks them (ObliWAN\'s own account, restricted to the management range); ' +
          'a group obliwan ObliWAN made earlier (comment obliwan:access) that lacks only the sensitive policy gets ' +
          'it (operator decision 2026-10-05) — a policy added, never one removed. ' +
          'The job refuses, before sending anything, any line outside /certificate, the api-ssl service, those ' +
          'two additions and that one alignment; the SSH service it travels on, the firewall, addresses, routes and ' +
          'every existing user are never written (no user is removed or modified, no password is changed). It adds ObliWAN\'s management ' +
          'path; an api-ssl used for something other than ObliWAN (another port, a certificate that is not ' +
          'ObliWAN\'s, or no certificate and addresses outside the range) is refused at lint, before anything is ' +
          'written, and the api-ssl ObliWAN itself left (obliwan-api or obliwan-ca on 8729) is taken over.',
      },
    ],
    summary:
      'Management-Path Guard: ACCEPT — only /certificate, the api-ssl service, the addition of the obliwan ' +
      'group and user, and sensitive added to the obliwan group ObliWAN made, are written; SSH, the path the job ' +
      'uses, is never touched (no plan was simulated: the job refuses any other line).',
    unavailable: false,
  };
}

/** The net this kind gets: none, said in the words the safety-net rule uses. */
export function managementAccessSafetyNet(): {
  level: 'degraded';
  peerDeviceId: null;
  peerDeviceName: null;
  rationale: string;
  unverified: false;
  requiresConfirmation: true;
} {
  return {
    level: 'degraded',
    peerDeviceId: null,
    peerDeviceName: null,
    rationale:
      "DEGRADED — aucun dead-man n'est armé : rien de ce que la tâche écrit ne peut couper le chemin SSH qu'elle " +
      'utilise (seuls /certificate, le service api-ssl, l’ajout du compte « obliwan » et l’ajout de sensitive au ' +
      'groupe « obliwan » qu’ObliWAN a créé sont écrits ; le compte ' +
      'qu’elle emprunte n’est jamais modifié, et ObliWAN ne bascule sur « obliwan » qu’après une connexion prouvée ' +
      'avec lui en api-ssl et en SSH). La sauvegarde préalable, récupérée par SFTP ' +
      'avant la première écriture, est le seul filet. La règle de sécurité exige une confirmation explicite et tracée.',
    unverified: false,
    requiresConfirmation: true,
  };
}

// ============================================================================
// Dependencies (test seams)
// ============================================================================

export interface ManagementAccessDeps {
  /** Dial the RouterOS API (the harness redirects the port to its fake). */
  openApi(options: RouterOsConnectionOptions): Promise<RouterOsConnection>;
  sleep(ms: number): Promise<void>;
  /** The shared builder (shared/src/managementAccess.ts). A seam so the
   *  harness can prove that a builder drifting outside the allow-list is
   *  refused at lint, before any file exists on the router. */
  buildLines(input: ApiSslAccessInput): string[];
}

const DEFAULT_DEPS: ManagementAccessDeps = {
  openApi: (options) => createRouterOsConnection(options),
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  buildLines: (input) => apiSslAccessLines(input),
};
let deps: ManagementAccessDeps = { ...DEFAULT_DEPS };

export function setManagementAccessDeps(next: Partial<ManagementAccessDeps>): ManagementAccessDeps {
  deps = { ...deps, ...next };
  return deps;
}
export function resetManagementAccessDeps(): void {
  deps = { ...DEFAULT_DEPS };
}

// ============================================================================
// The RouterOS console text this job sends (pure)
// ============================================================================

/** Printed by every write command after it completed; absent = it did not. */
export const CMD_OK = 'OBLIWAN-CMD-OK';
/** Printed by the wrapped script at its end, or by its `on-error` branch. */
export const SCRIPT_MARK_OK = 'OBLIWAN-MGMT-OK';
export const SCRIPT_MARK_FAILED = 'OBLIWAN-MGMT-FAILED';
/** The policies the job's script runs with — the set safeApply.service gives
 *  its own `/system/script` (read, write, policy, test). */
export const SCRIPT_POLICY = 'read,write,policy,test';

export function scriptNameFor(jobId: number): string {
  return `obliwan-mgmt-${jobId}`;
}
/** What every `:log` line of the builder starts with (`logPrefix`). */
export function logPrefixFor(jobId: number): string {
  return `obliwan-mgmt job=${jobId}`;
}

/**
 * A RouterOS double-quoted string literal. Escapes, per the RouterOS
 * scripting manual (REASONED, not observed): `\\`, `\"`, `\$` (a bare `$`
 * would be substituted when the console parses the command), `\?`, and the
 * three control characters a script can hold, `\n`, `\r`, `\t`. Any other
 * control character or any non-ASCII character is REFUSED rather than
 * guessed: the builder's lines are plain ASCII.
 */
export function routerOsQuoted(text: string): string {
  let out = '';
  for (const ch of text) {
    const code = ch.codePointAt(0) as number;
    if (ch === '\\') out += '\\\\';
    else if (ch === '"') out += '\\"';
    else if (ch === '$') out += '\\$';
    else if (ch === '?') out += '\\?';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else if (code < 0x20 || code >= 0x7f) {
      throw new ManagementAccessError(
        'script_unquotable',
        'Le script à envoyer contient un caractère que la tâche ne sait pas écrire dans une chaîne RouterOS ' +
          '(caractère de contrôle ou non ASCII) : refus, rien n’a été envoyé.',
      );
    } else out += ch;
  }
  return `"${out}"`;
}

/** The builder's lines, inside the job's own `:do { } on-error={ }` (the
 *  builder raises `:error` on a refusal and expects exactly this wrapper). */
export function scriptSourceFor(lines: readonly string[]): string {
  return [':do {', ...lines, `:put "${SCRIPT_MARK_OK}"`, `} on-error={ :put "${SCRIPT_MARK_FAILED}" }`].join('\n');
}

/** The script commands the builder's lines may use: variables, control flow,
 *  conversions, a wait, a log line, an error. None reaches outside the
 *  script — `:execute`, `:parse`, `/import` and friends are refused. */
const COLON_COMMANDS_ALLOWED = new Set([
  'local', 'set', 'if', 'do', 'while', 'foreach', 'delay', 'log', 'error', 'tostr', 'toarray', 'len', 'put',
]);

const reLiteral = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
/**
 * The ONE line of the builder that may name `/ip service`, spelled here with
 * literals rather than read from the builder, so a builder that drifts is
 * caught: the CONFIGURED api-ssl row chosen as shared/src/routerOsService.ts
 * chooses it (a connection entry named api-ssl skipped), then one `set` on
 * THAT row — enabled, 8729, an address list of prefixes, `obliwan-api`.
 */
const API_SSL_SERVICE_LINE_RE = new RegExp(
  `^${reLiteral(
    ':local oasSvc ""; :foreach r in=[/ip service find where name="api-ssl"] do={ ' +
      ':do { :if ([:tostr [/ip service get $r dynamic]] != "true") do={ :set oasSvc $r } } on-error={ :set oasSvc $r } }; ' +
      '/ip service set $oasSvc disabled=no port=8729 address="',
  )}[0-9A-Fa-f.:/,]+${reLiteral('" certificate="obliwan-api"')}$`,
);

/**
 * The structural half of the guard's ACCEPT: every line sent may touch
 * `/certificate` and the api-ssl service, and nothing else. A menu, a service
 * name or a script command outside that is REFUSED before anything is sent —
 * so if the shared builder ever grows a line for ssh, a user or the firewall,
 * this job stops instead of carrying it to a router in service.
 */
export function assertApiSslOnlyLines(lines: readonly string[]): void {
  const offending: string[] = [];
  for (const raw of lines) {
    const line = raw.replace(/"(?:[^"\\]|\\.)*"/g, '""');
    for (const m of line.matchAll(/(^|[\s[{(;])\/([a-z][a-z0-9-]*)(?:[\s/]+([a-z][a-z0-9-]*))?/g)) {
      const menu = m[2];
      if (menu === 'certificate') continue;
      // `/ip service` only in THE api-ssl line, whole: the configured row
      // chosen, then one write on that row (`API_SSL_SERVICE_LINE_RE`).
      if (menu === 'ip' && m[3] === 'service' && API_SSL_SERVICE_LINE_RE.test(raw)) continue;
      offending.push(`/${menu}${m[3] ? ` ${m[3]}` : ''}`);
    }
    for (const m of line.matchAll(/(^|[\s[{(;])\s*:([a-z]+)/g)) {
      if (!COLON_COMMANDS_ALLOWED.has(m[2])) offending.push(`:${m[2]}`);
    }
  }
  if (offending.length > 0) {
    throw new ManagementAccessError(
      'line_outside_api_ssl',
      `Le générateur partagé a produit une ligne hors de /certificate et du service api-ssl (${[...new Set(offending)].join(', ')}) : ` +
        'la tâche refuse de l’envoyer, rien n’a été écrit sur le routeur.',
    );
  }
}

/** The server certificate's common-name: the router's identity, reduced to
 *  what the builder can write unescaped. The CN is cosmetic for ObliWAN —
 *  the client checks the PINNED fingerprint, never the name — so a reduced
 *  spelling is better than refusing a router whose identity holds a space. */
export function certificateCommonName(identity: string | null): string {
  const reduced = (identity ?? '').replace(/[^A-Za-z0-9._-]/g, '-').slice(0, 64);
  return /[A-Za-z0-9]/.test(reduced) ? reduced : OBLIWAN_API_CERTIFICATE;
}

/** The reads, as console commands whose output this file parses. */
export const SSH_READS = {
  identity: ':put ("identity|" . [/system identity get name])',
  board:
    ':put ("board|" . [:tostr [/system routerboard get serial-number]] . "|" . [:tostr [/system routerboard get model]])',
  /** Every l2tp-client's name AND user (`l2tp|<name>|<user>`): which one is
   *  the management tunnel is decided by its NAME (`managementTunnelLogin`,
   *  shared/src/managementTunnel.ts), never by `find` order. No password. */
  l2tp:
    ':foreach i in=[/interface l2tp-client find] do={ :put ("l2tp|" . [/interface l2tp-client get $i name] . "|" . ' +
    '[/interface l2tp-client get $i user]) }',
  /** The allowed-address list is `available-from` on recent RouterOS 7 (seen
   *  on 7.24.5: `print` shows only that name, and `get … address` reads
   *  nothing) and `address` before; `set … address=` is still accepted by
   *  both. Read the new name first, the old one when the router does not know
   *  it — never "nothing", which would read as "open to every address".
   *  The CONFIGURED row only: RouterOS 7.24.5 lists every open api-ssl
   *  connection — ObliWAN's own health check, this job's API proof — as a
   *  dynamic entry named api-ssl, with no address list and no certificate
   *  [prod, 2026-10-05]. A row whose `dynamic` reads "true" prints nothing;
   *  one whose `get … dynamic` fails (7.16: no such property, no such entry)
   *  is the service. Why `get` and not `find where … !dynamic`, and what is
   *  REASONED: shared/src/routerOsService.ts. Two rows printed anyway are no
   *  reading (`parseService`). */
  service:
    `:foreach s in=[/ip service find where name="${API_SSL_SERVICE}"] do={ :local d ""; ` +
    ':do { :set d [:tostr [/ip service get $s dynamic]] } on-error={}; :if ($d != "true") do={ :local a ""; ' +
    ':do { :set a [:tostr [/ip service get $s available-from]] } on-error={ ' +
    ':do { :set a [:tostr [/ip service get $s address]] } on-error={} }; :put ("svc|" . ' +
    '[:tostr [/ip service get $s disabled]] . "|" . [:tostr [/ip service get $s port]] . "|" . ' +
    '$a . "|" . [:tostr [/ip service get $s certificate]]) } }',
  certificates:
    `:foreach c in=[/certificate find where name="${OBLIWAN_CA_CERTIFICATE}" or name="${OBLIWAN_API_CERTIFICATE}"] ` +
    'do={ :local k ""; :local f ""; :do { :set k [:tostr [/certificate get $c private-key]] } on-error={}; ' +
    ':do { :set f [:tostr [/certificate get $c fingerprint]] } on-error={}; ' +
    ':put ("cert|" . [/certificate get $c name] . "|" . $k . "|" . $f) }',
} as const;

/** A RouterOS user or group name the reads below can quote unescaped. A name
 *  outside it is not read (the policy is then UNKNOWN, never assumed). */
const SAFE_ACCOUNT_NAME = /^[A-Za-z0-9._@-]{1,64}$/;

/** The SSH account's group, then that group's policy list — what decides,
 *  BEFORE anything is written, whether the account can run the job's script,
 *  create the `obliwan` account when the plan says so, and log in to the API
 *  when the API is to ride this same account (`in_use`). Also the presence
 *  of the `obliwan` user and group, as COUNTS (`oacct|<users>|<groups>`): a
 *  count is an answer either way, where a `:foreach` that printed nothing
 *  could be an absence or a read that failed. That `:tostr` of `policy` joins
 *  the list with ';' and prints a denied policy as `!name` is REASONED, not
 *  observed. */
export const SSH_ACCOUNT_READS = {
  group: (username: string): string | null =>
    SAFE_ACCOUNT_NAME.test(username)
      ? `:foreach u in=[/user find where name="${username}"] do={ :put ("user|" . [/user get $u group]) }`
      : null,
  policy: (group: string): string | null =>
    SAFE_ACCOUNT_NAME.test(group)
      ? `:foreach g in=[/user group find where name="${group}"] do={ :put ("policy|" . [:tostr [/user group get $g policy]]) }`
      : null,
  obliwanPresence:
    `:put ("oacct|" . [:len [/user find where name="${OBLIWAN_ACCOUNT}"]] . "|" . ` +
    `[:len [/user group find where name="${OBLIWAN_ACCOUNT}"]])`,
  /** The `obliwan` group's comment (`gcomment|<text>`): `OBLIWAN_ACCOUNT_COMMENT`
   *  is how the job knows ObliWAN made the group, the one condition, with its
   *  policy, under which it aligns it (header box). A group with no comment
   *  prints an empty one (REASONED); nothing printed is UNKNOWN, never
   *  "ObliWAN's". */
  obliwanGroupComment:
    `:foreach g in=[/user group find where name="${OBLIWAN_ACCOUNT}"] do={ ` +
    ':put ("gcomment|" . [:tostr [/user group get $g comment]]) }',
} as const;

/** The policies the job needs on the SSH account's group when the API rides
 *  that same account (`in_use`: the SSH credential already is `obliwan`):
 *  `read,write,policy,test` to add and run its script (`SCRIPT_POLICY`),
 *  `api` for the identity read over API-SSL that pins the certificate. */
export const REQUIRED_ACCOUNT_POLICIES = ['read', 'write', 'policy', 'test', 'api'] as const;
/** What the script alone needs (`SCRIPT_POLICY`): the plan `present`, where the
 *  API rides `obliwan`, not the SSH account. */
export const SCRIPT_ACCOUNT_POLICIES = ['read', 'write', 'policy', 'test'] as const;
/** The plan `create`: the script's policies, plus every policy of the group
 *  the job creates or fills — that an account cannot hand a group (or a user
 *  in it) policies its own group lacks is REASONED from RouterOS's rule for
 *  scripts (bench/compile.service.ts), not observed; required here so such a
 *  router is refused by name at lint rather than failing at the write. */
export function accountCreationPolicies(): string[] {
  return [...new Set([...SCRIPT_ACCOUNT_POLICIES, ...OBLIWAN_GROUP_POLICY.split(',')])];
}
/** What the SSH account must hold to ALIGN the `obliwan` group (header box):
 *  `sensitive`, the policy it grants — an account cannot grant a policy its
 *  own group lacks (REASONED, not observed) — and `policy`, which RouterOS
 *  requires to edit users and groups at all. */
export const GROUP_ALIGNMENT_POLICIES = ['sensitive', 'policy'] as const;

/** `oacct|<users>|<groups>` -> the two counts, or null when the line is
 *  missing or not two integers (UNKNOWN: the job then refuses, it never reads
 *  silence as an absence it would act on). */
export function parseObliwanPresence(out: string): { user: boolean; group: boolean } | null {
  const row = tagged(out, 'oacct')[0];
  if (!row || row.length !== 2 || !row.every((n) => /^\d+$/.test(n.trim()))) return null;
  return { user: Number(row[0]) > 0, group: Number(row[1]) > 0 };
}

/**
 * A group named `obliwan` found on the router, against the bench's policy:
 * `same` when the policies it GRANTS (a `!name` is a denial and is ignored)
 * are exactly `OBLIWAN_GROUP_POLICY`, `different` otherwise (the extra and the
 * missing ones named), `unknown` when nothing readable came back. The job
 * creates its user in a `same` group, ALIGNS a group ObliWAN made whose only
 * difference is a missing `sensitive` (`obliwanGroupAlignable`), and REFUSES
 * any other — it never alters a group it did not make. Also the read-back of
 * the alignment: `same`, or the job fails.
 */
export function judgeObliwanGroupPolicy(out: string): {
  state: 'same' | 'different' | 'unknown';
  extra: string[];
  missing: string[];
  read: string | null;
} {
  const row = tagged(out, 'policy')[0];
  const text = row ? row.join('|').trim() : '';
  const items = text.split(/[;,]/).map((p) => p.trim().toLowerCase()).filter((p) => p !== '');
  if (items.length === 0 || items.some((p) => !/^!?[a-z-]+$/.test(p))) {
    return { state: 'unknown', extra: [], missing: [], read: text || null };
  }
  const granted = new Set(items.filter((p) => !p.startsWith('!')));
  const wanted = new Set(OBLIWAN_GROUP_POLICY.split(','));
  const extra = [...granted].filter((p) => !wanted.has(p)).sort();
  const missing = [...wanted].filter((p) => !granted.has(p)).sort();
  return { state: extra.length === 0 && missing.length === 0 ? 'same' : 'different', extra, missing, read: text };
}

/** `gcomment|<text>` -> the `obliwan` group's comment, trimmed (`''` when it
 *  has none), or null when nothing was printed (UNKNOWN). */
export function parseObliwanGroupComment(out: string): string | null {
  const row = tagged(out, 'gcomment')[0];
  return row ? row.join('|').trim() : null;
}

/**
 * The ONE group the job alters (header box, operator decision 2026-10-05): a
 * group `obliwan` that carries `OBLIWAN_ACCOUNT_COMMENT` — ObliWAN made it —
 * and whose granted policies are exactly `OBLIWAN_GROUP_POLICY` minus
 * `sensitive`: nothing extra, nothing else missing. The list ObliWAN wrote
 * before `sensitive` joined it, so the alignment adds that one policy and
 * nothing else. Anything else — another difference, no or another comment,
 * an unreadable policy or comment — is not ObliWAN's to change.
 */
export function obliwanGroupAlignable(
  policy: ReturnType<typeof judgeObliwanGroupPolicy> | null,
  comment: string | null,
): boolean {
  return (
    policy !== null &&
    policy.state === 'different' &&
    policy.extra.length === 0 &&
    policy.missing.length === 1 &&
    policy.missing[0] === 'sensitive' &&
    comment === OBLIWAN_ACCOUNT_COMMENT
  );
}

/** A `different` group `obliwan`, said for the operator: what it grants in
 *  more, what it lacks, and — when it would be ObliWAN's old list — that it
 *  does not carry ObliWAN's comment (the reason it is not aligned). */
export function obliwanGroupDifference(
  policy: ReturnType<typeof judgeObliwanGroupPolicy>,
  comment: string | null,
): string {
  const parts = [
    ...(policy.extra.length > 0 ? [`en plus : ${policy.extra.join(', ')}`] : []),
    ...(policy.missing.length > 0 ? [`manquent : ${policy.missing.join(', ')}`] : []),
  ];
  const oldList = policy.extra.length === 0 && policy.missing.length === 1 && policy.missing[0] === 'sensitive';
  const commentNote = oldList && comment !== OBLIWAN_ACCOUNT_COMMENT
    ? ` ; ce serait la politique d’ObliWAN d’avant le 2026-10-05, mais le groupe ne porte pas le commentaire ` +
      `« ${OBLIWAN_ACCOUNT_COMMENT} » qu’ObliWAN pose sur ce qu’il crée (${comment === null
        ? 'commentaire illisible'
        : comment === '' ? 'aucun commentaire' : `commentaire « ${comment.slice(0, 100)} »`}) : rien ne prouve qu’il soit le sien`
    : '';
  return `avec une autre politique que celle d’ObliWAN (${parts.join(' ; ')}${commentNote})`;
}

/**
 * Said in the plan and in the outcome when the `obliwan` group ObliWAN made
 * lacks `sensitive` and this run cannot align it — no legacy credential, a
 * refused login, a group lacking the policies, a closed SFTP road (header
 * box). The job is NOT failed for it; `why` names the reason (never a
 * password).
 */
export function alignmentRemedy(why: string): string {
  return (
    `le groupe « ${OBLIWAN_ACCOUNT} » n’a pas sensitive : les sauvegardes préalables échoueront tant qu’il n’est pas ` +
    `aligné ; ajoutez-le — renseignez « ${RECONCILE_ATTACH_VAULT_KEY} » (Variables, au niveau du site ou du client) avec ` +
    `le mot de passe du compte « ${RECONCILE_ATTACH_DEFAULT_USERNAME} » de ce routeur, dont le groupe doit avoir ` +
    'sensitive et policy, puis relancez la tâche : elle alignera le groupe par une session SSH distincte avec ce ' +
    `compte, sans rien modifier d’autre. Non aligné par cette exécution : ${why}`
  );
}

/** The historical account that aligns the `obliwan` group when the SSH
 *  account cannot (header box, the legacy session). In memory for the run
 *  only — never a transport, never a row, never a log line. */
interface LegacyAligner {
  username: string;
  password: string;
  /** The vault level its password came from (said in the plan). */
  scope: LegacyVariableScope;
}

// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;

/** The device's site, ONLY when it is its own tenant's: a `site_id` that
 *  points at another tenant's site resolves nothing at the site level. */
async function deviceSiteInTenant(deviceId: number, tenantId: number): Promise<number | null> {
  const row = (await db('devices as d')
    .join('sites as s', 's.id', 'd.site_id')
    .where('d.id', deviceId)
    .where('d.tenant_id', tenantId)
    .where('s.tenant_id', tenantId)
    .first('s.id')) as { id: number } | undefined;
  return row ? Number(row.id) : null;
}

/** The three writes the job may send about the account — nothing else of
 *  `/user` exists in this file. Each is ONE console command, alone (a refused
 *  one stops the job before the next is sent), ending in `CMD_OK`. The
 *  password goes through `routerOsQuoted`, the quoter of the script source;
 *  the generator's alphabet needs no escape, the quoter is there so a value
 *  that did would be escaped rather than spliced. */
export const ACCOUNT_WRITES = {
  groupAdd: (): string =>
    `/user group add name=${OBLIWAN_ACCOUNT} policy=${OBLIWAN_GROUP_POLICY} comment="${OBLIWAN_ACCOUNT_COMMENT}"; :put "${CMD_OK}"`,
  /** The alignment (header box): the policy of the group named `obliwan`
   *  AND commented `OBLIWAN_ACCOUNT_COMMENT` set to `OBLIWAN_GROUP_POLICY`.
   *  Found by both on the router itself, so a group whose comment changed
   *  since the job read it is not matched (the read-back then fails). */
  groupAlign: (): string =>
    `/user group set [find where name=${OBLIWAN_ACCOUNT} comment="${OBLIWAN_ACCOUNT_COMMENT}"] ` +
    `policy=${OBLIWAN_GROUP_POLICY}; :put "${CMD_OK}"`,
  userAdd: (prefixes: readonly string[], password: string): string => {
    if (prefixes.length === 0 || prefixes.some((p) => !/^[0-9A-Fa-f.:]+\/\d{1,3}$/.test(p))) {
      throw new ManagementAccessError('range_invalid', 'La plage d’administration ne peut pas restreindre le compte « obliwan » : refus.');
    }
    if (password.length < 16) throw new ManagementAccessError('internal', 'Mot de passe du compte « obliwan » invalide : refus.');
    return `/user add name=${OBLIWAN_ACCOUNT} group=${OBLIWAN_ACCOUNT} address=${routerOsQuoted(prefixes.join(','))} ` +
      `password=${routerOsQuoted(password)} comment="${OBLIWAN_ACCOUNT_COMMENT}"; :put "${CMD_OK}"`;
  },
} as const;

const reEscape = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const ACCOUNT_LINE_SHAPES: readonly RegExp[] = [
  new RegExp(
    `^/user group add name=${OBLIWAN_ACCOUNT} policy=${reEscape(OBLIWAN_GROUP_POLICY)} ` +
      `comment="${OBLIWAN_ACCOUNT_COMMENT}"; :put "${CMD_OK}"$`,
  ),
  // The alignment, to the byte: this name, this comment, this policy list.
  new RegExp(
    `^${reEscape(`/user group set [find where name=${OBLIWAN_ACCOUNT} comment="${OBLIWAN_ACCOUNT_COMMENT}"] `)}` +
      `policy=${reEscape(OBLIWAN_GROUP_POLICY)}; :put "${CMD_OK}"$`,
  ),
  // The password between quotes: any character but a bare quote, backslash or
  // dollar — those only as the quoter's escapes.
  new RegExp(
    `^/user add name=${OBLIWAN_ACCOUNT} group=${OBLIWAN_ACCOUNT} address="[0-9A-Fa-f.:/,]+" ` +
      `password="(?:[^"\\\\$]|\\\\.)+" comment="${OBLIWAN_ACCOUNT_COMMENT}"; :put "${CMD_OK}"$`,
  ),
];

/**
 * The account half of the guard's ACCEPT, as `assertApiSslOnlyLines` is the
 * api-ssl half: every account line the job sends is EXACTLY one of the three
 * `ACCOUNT_WRITES` shapes — an addition of the `obliwan` group with the
 * bench's policy, an addition of the `obliwan` user in it, the alignment of
 * the `obliwan` group ObliWAN made on that policy — and nothing else: no
 * remove, no other set, no other name, no second command on the line. Judged
 * at lint on the lines built, again at apply on the exact text about to leave.
 */
export function assertAccountOnlyLines(lines: readonly string[]): void {
  const offending = lines.filter((l) => !ACCOUNT_LINE_SHAPES.some((re) => re.test(l)));
  if (offending.length > 0) {
    throw new ManagementAccessError(
      'line_outside_account',
      `${offending.length} ligne(s) du compte « ${OBLIWAN_ACCOUNT} » ne sont ni l’ajout du groupe ou de l’utilisateur, ` +
        'ni l’alignement du groupe, tels qu’ObliWAN les écrit : la tâche refuse de les envoyer, rien n’a été écrit sur le routeur.',
    );
  }
}

const SAFE_FILE_NAME = /^[A-Za-z0-9._-]{1,120}$/;

function assertSafeName(name: string): void {
  if (!SAFE_FILE_NAME.test(name)) {
    throw new ManagementAccessError('internal', `Nom de fichier interne invalide : refus.`);
  }
}

export const SSH_WRITES = {
  backupSave: (base: string, password: string): string => {
    assertSafeName(base);
    if (!/^[A-Za-z0-9_-]{16,64}$/.test(password)) throw new ManagementAccessError('internal', 'Mot de passe de sauvegarde invalide.');
    return `/system backup save name="${base}" password="${password}"; :put "${CMD_OK}"`;
  },
  exportFile: (family: string, base: string): string => {
    assertSafeName(base);
    return `${routerOsExportCommand(family)} file="${base}"; :put "${CMD_OK}"`;
  },
  fileInfo: (name: string): string => {
    assertSafeName(name);
    return `:foreach f in=[/file find where name="${name}" or name="flash/${name}"] do={ :put ("file|" . [/file get $f name] . "|" . [:tostr [/file get $f size]]) }`;
  },
  fileRemove: (name: string): string => {
    if (!/^(flash\/)?[A-Za-z0-9._-]{1,120}$/.test(name)) throw new ManagementAccessError('internal', 'Nom de fichier interne invalide : refus.');
    return `/file remove [find where name="${name}"]; :put "${CMD_OK}"`;
  },
  /** Every script an earlier job of this kind left (a worker that died between
   *  `add` and `remove`, or a `remove` that failed): they are named
   *  `obliwan-mgmt-<job id>` (`scriptNameFor`), hold no secret, and only one
   *  job of this kind runs per device at a time. */
  scriptRemoveLeftovers: (): string =>
    `:do { /system script remove [find where name~"^obliwan-mgmt-"] } on-error={}; :put "${CMD_OK}"`,
  /** An UNSIGNED certificate template of ObliWAN's own name (no private key,
   *  no fingerprint), left by an earlier run whose signing never completed. */
  certificateTemplateRemove: (name: string): string => {
    if (name !== OBLIWAN_CA_CERTIFICATE && name !== OBLIWAN_API_CERTIFICATE) {
      throw new ManagementAccessError('internal', 'Seuls les certificats obliwan-ca et obliwan-api peuvent être retirés : refus.');
    }
    return `/certificate remove [find where name="${name}"]; :put "${CMD_OK}"`;
  },
  scriptRemove: (name: string): string => {
    assertSafeName(name);
    return `/system script remove [find where name="${name}"]; :put "${CMD_OK}"`;
  },
  scriptAdd: (name: string, source: string): string => {
    assertSafeName(name);
    return `/system script add name="${name}" policy=${SCRIPT_POLICY} source=${routerOsQuoted(source)}; :put "${CMD_OK}"`;
  },
  scriptRun: (name: string): string => {
    assertSafeName(name);
    return `/system script run ${name}`;
  },
  logRead: (prefix: string): string =>
    `:foreach l in=[/log find where message~"${prefix} "] do={ :put ("log|" . [/log get $l message]) }`,
} as const;

/** Lines of `out` that start with `<tag>|`, split on `|` after the tag. */
function tagged(out: string, tag: string): string[][] {
  return out
    .split(/\r?\n/)
    .map((l) => l.replace(/\r$/, '').trim())
    .filter((l) => l.startsWith(`${tag}|`))
    .map((l) => l.slice(tag.length + 1).split('|'));
}

export interface ServiceReading {
  disabled: string;
  port: string;
  /** Comma-joined, as `apiSslStateDifferences` reads it. */
  address: string;
  certificate: string;
}

export interface CertificateReading {
  name: string;
  privateKey: boolean;
  fingerprint: string | null;
  /** Has its private key and a fingerprint — the builder's own test. */
  ready: boolean;
  /** Neither a private key nor a fingerprint: a template that was never
   *  signed (`/certificate add` alone; the builder header: a template has no
   *  fingerprint, REASONED). Under ObliWAN's own name, that is an earlier
   *  run's leftover, which this job removes after its backup. A certificate
   *  with ONE of the two is not a template, and is never removed. */
  unsignedTemplate: boolean;
}

export function parseIdentity(out: string): string | null {
  const row = out.split(/\r?\n/).map((l) => l.trim()).find((l) => l.startsWith('identity|'));
  if (!row) return null;
  const v = row.slice('identity|'.length).trim();
  return v === '' ? null : v;
}

export function parseBoard(out: string): { serial: string | null; model: string | null } {
  const row = tagged(out, 'board')[0];
  if (!row) return { serial: null, model: null };
  return { serial: (row[0] ?? '').trim() || null, model: (row[1] ?? '').trim() || null };
}

/** Every `l2tp|<name>|<user>` line of `SSH_READS.l2tp`, in `find` order
 *  (the order means nothing: `managementTunnelLogin` picks by name). The name
 *  is the first field, the user the rest — a name holding `|` then reads as
 *  another name, which only ever makes the client NOT the management one. */
export function parseL2tpClients(out: string): L2tpClientReading[] {
  return tagged(out, 'l2tp').map((row) => ({
    name: (row[0] ?? '').trim() || null,
    user: row.slice(1).join('|').trim() || null,
  }));
}

/** The ONE api-ssl row `SSH_READS.service` printed; null when it printed
 *  none, or more than one — two rows are a connection entry the read failed
 *  to skip (shared/src/routerOsService.ts), and never one of them is picked. */
export function parseService(out: string): ServiceReading | null {
  const rows = tagged(out, 'svc');
  if (rows.length !== 1) return null;
  const row = rows[0];
  if (row.length < 4) return null;
  return {
    disabled: row[0].trim(),
    port: row[1].trim(),
    // `:tostr` of a list joins with ';' (REASONED); the API prints ','.
    address: row[2].split(/[;,]/).map((a) => a.trim()).filter((a) => a !== '').join(','),
    certificate: row[3].trim(),
  };
}

export function parseCertificates(out: string): CertificateReading[] {
  return tagged(out, 'cert').map((row) => {
    const privateKey = (row[1] ?? '').trim().toLowerCase() === 'true';
    const fingerprint = (row[2] ?? '').trim() || null;
    return {
      name: (row[0] ?? '').trim(),
      privateKey,
      fingerprint,
      ready: privateKey && fingerprint !== null,
      unsignedTemplate: !privateKey && fingerprint === null,
    };
  });
}

export function parseAccountGroup(out: string): string | null {
  const row = tagged(out, 'user')[0];
  return row ? (row.join('|').trim() || null) : null;
}

/**
 * What the group's policy list says about `required` (by default
 * `REQUIRED_ACCOUNT_POLICIES`; the account plan narrows or widens it).
 * `unknown` when nothing readable came back — never a refusal, never an
 * assumption: the router's own answer (the write, the API login at
 * postcheck) is then the judge. `missing` lists the required policies the
 * reading does not grant (absent, or printed denied as `!name`).
 */
export function judgeAccountPolicy(
  out: string,
  required: readonly string[] = REQUIRED_ACCOUNT_POLICIES,
): { state: 'granted' | 'missing' | 'unknown'; missing: string[]; read: string | null } {
  const row = tagged(out, 'policy')[0];
  const text = row ? row.join('|').trim() : '';
  const items = text.split(/[;,]/).map((p) => p.trim().toLowerCase()).filter((p) => p !== '');
  if (items.length === 0 || items.some((p) => !/^!?[a-z-]+$/.test(p))) {
    return { state: 'unknown', missing: [], read: text || null };
  }
  const granted = new Set(items.filter((p) => !p.startsWith('!')));
  const missing = required.filter((p) => !granted.has(p));
  return { state: missing.length === 0 ? 'granted' : 'missing', missing, read: text };
}

export function parseFiles(out: string): Array<{ name: string; size: number | null; exact: boolean }> {
  return tagged(out, 'file').map((row) => {
    const sizeText = (row[1] ?? '').trim();
    const exact = /^\d+$/.test(sizeText);
    return { name: (row[0] ?? '').trim(), size: exact ? Number(sizeText) : null, exact };
  });
}

/** The builder's refusal, from its `:log error` line (shared builder header). */
export function parseScriptReason(out: string): { reason: string; certificate: string } | null {
  for (const row of tagged(out, 'log')) {
    const m = new RegExp(`reason=${API_SSL_REASON_PREFIX}([a-z-]+) certificate=([A-Za-z0-9._-]+)`).exec(row.join('|'));
    if (m) return { reason: m[1], certificate: m[2] };
  }
  return null;
}

/** The operator's sentence for the builder's refusal reasons. */
export function scriptReasonMessage(found: { reason: string; certificate: string } | null): string {
  if (!found) {
    return (
      'Le script s’est arrêté sur une erreur sans raison lisible dans le journal du routeur. api-ssl a été ' +
      'relu : voir l’état ci-dessous. La sauvegarde préalable est conservée.'
    );
  }
  const name = found.certificate;
  switch (found.reason) {
    case 'conflict':
      return (
        `Au moment du script, un certificat nommé « ${name} » était sur le routeur sans clé privée ou sans empreinte, ` +
        'alors que l’inspection l’avait lu autrement. api-ssl n’a pas été modifié. Relancez : la tâche relit le ' +
        'routeur, retire un modèle non signé laissé par ObliWAN et ne touche jamais un certificat signé.'
      );
    case 'not-signed':
      return (
        `Le certificat « ${name} » n’a pas obtenu sa clé privée dans le délai de ${CERTIFICATE_SIGN_WAIT_SECONDS} s. ` +
        'api-ssl n’a pas été modifié ; relancez (un routeur lent peut demander plus de temps).'
      );
    case 'sign-failed':
      return (
        `La création ou la signature du certificat « ${name} » a échoué sur le routeur ; le modèle créé par cette ` +
        'tâche a été retiré. api-ssl n’a pas été modifié.'
      );
    default:
      return `Le script s’est arrêté (raison « ${found.reason} », certificat « ${name} »). api-ssl n’a pas été modifié.`;
  }
}

/**
 * Whose is the api-ssl the router carries now — the decision `lint` takes
 * before anything is written:
 *  - `disabled`    nobody uses it: taken;
 *  - `conformant`  already as this job leaves it;
 *  - `ours`        ObliWAN's own earlier state, TAKEN OVER whatever its
 *                  addresses: it serves `obliwan-api` or `obliwan-ca` on 8729
 *                  (a run made under another management range; or the CA
 *                  bound to the service, the TLS alert 40 seen in production).
 *                  Refusing it would leave the operator a hand edit on every
 *                  router to repair what ObliWAN itself wrote;
 *  - `factory`     RouterOS's own shape (8729, no certificate, open to all or
 *                  to a part of the range): taken over and restricted;
 *  - `foreign`     another port, a certificate that is not ObliWAN's, or no
 *                  certificate with addresses outside the range: somebody's
 *                  use, which rewriting would cut — refused.
 */
export function classifyEnabledApiSsl(
  service: ServiceReading,
  prefixes: readonly string[],
): { kind: 'disabled' | 'conformant' | 'ours' | 'factory' | 'foreign'; why: string } {
  if (!/^(false|no)$/i.test(service.disabled.trim())) return { kind: 'disabled', why: 'api-ssl désactivé' };
  if (apiSslStateDifferences({ ...service }, prefixes).length === 0) return { kind: 'conformant', why: 'déjà conforme' };
  const certificate = service.certificate.trim();
  const portOk = service.port.trim() === String(API_SSL_PORT);
  if (portOk && certificate === OBLIWAN_CA_CERTIFICATE) {
    return {
      kind: 'ours',
      why: 'api-ssl servait le certificat de l’autorité obliwan-ca au lieu de obliwan-api (l’alerte TLS 40) : il est rebranché sur obliwan-api',
    };
  }
  if (portOk && certificate === OBLIWAN_API_CERTIFICATE) {
    return {
      kind: 'ours',
      why: `api-ssl servait déjà obliwan-api, avec d’autres adresses autorisées (« ${service.address || 'toutes'} ») : elles sont remplacées par la plage d’administration actuelle`,
    };
  }
  const noCertificate = certificate === '' || certificate === 'none';
  const outside = service.address.split(',').map((a) => a.trim()).filter((a) => a !== '' && !prefixes.includes(a));
  if (portOk && noCertificate && outside.length === 0) return { kind: 'factory', why: 'forme d’usine' };
  if (!portOk) return { kind: 'foreign', why: `port ${service.port || '—'} au lieu de ${API_SSL_PORT}` };
  if (!noCertificate) return { kind: 'foreign', why: `certificat « ${certificate} », qui n’est pas un certificat d’ObliWAN` };
  return { kind: 'foreign', why: `adresses ${outside.join(', ')} hors de la plage d’administration, sans certificat` };
}

/** The differences in French, for a refusal or a read-back that failed. */
export function describeDifferences(diffs: readonly ApiSslStateDifference[]): string {
  const label: Record<ApiSslStateDifference['field'], string> = {
    present: 'service api-ssl absent',
    enabled: 'activé',
    port: 'port',
    address: 'adresses autorisées',
    certificate: 'certificat',
  };
  return diffs
    .map((d) => (d.field === 'present' ? label.present : `${label[d.field]} : « ${d.actual || '—'} » au lieu de « ${d.expected} »`))
    .join(' ; ');
}

// ============================================================================
// Loading what the job needs
// ============================================================================

export interface DeviceFacts {
  id: number;
  tenant_id: number;
  uuid: string;
  name: string;
  brand: string;
  family: string;
  role: string | null;
  status: string;
  is_managed: boolean;
  ppp_username: string | null;
  system_identity: string | null;
  serial: string | null;
  tunnel_ip: string | null;
  model: string | null;
  os_version: string | null;
}

export interface SshRow {
  host: string | null;
  port: number | null;
  username: string | null;
  secret_enc: string | null;
  private_key_enc: string | null;
  key_version: number | null;
  enabled: boolean;
  params: Record<string, unknown> | null;
}

export interface ApiRow {
  host: string | null;
  port: number | null;
  username: string | null;
  secret_enc: string | null;
  use_tls: boolean;
  tls_fingerprint_sha256: string | null;
  enabled: boolean;
  last_ok_at: Date | null;
  last_error: string | null;
  params: Record<string, unknown> | null;
}

export interface Facts {
  device: DeviceFacts;
  ssh: SshRow | null;
  api: ApiRow | null;
}

const DEVICE_COLUMNS = [
  'id', 'tenant_id', 'uuid', 'name', 'brand', 'family', 'role', 'status', 'is_managed',
  'ppp_username', 'system_identity', 'serial', 'tunnel_ip', 'model', 'os_version',
] as const;

export async function loadFacts(deviceId: number, tenantId: number | null): Promise<Facts | null> {
  const q = db('devices').where({ id: deviceId });
  if (tenantId !== null) q.where({ tenant_id: tenantId });
  const device = (await q.first(...DEVICE_COLUMNS)) as DeviceFacts | undefined;
  if (!device) return null;
  const ssh = (await db('device_transports')
    .where({ device_id: deviceId, transport: 'ssh' })
    .first('host', 'port', 'username', 'secret_enc', 'private_key_enc', 'key_version', 'enabled', 'params')) as
    | SshRow
    | undefined;
  const api = (await db('device_transports')
    .where({ device_id: deviceId, transport: 'routeros_api' })
    .first(
      'host', 'port', 'username', 'secret_enc', 'use_tls', 'tls_fingerprint_sha256', 'enabled',
      'last_ok_at', 'last_error', 'params',
    )) as ApiRow | undefined;
  return { device, ssh: ssh ?? null, api: api ?? null };
}

/** The address the job dials: the SSH row's host, else the tunnel address. */
export function sshHostOf(facts: Facts): string | null {
  return (facts.ssh?.host ?? facts.device.tunnel_ip ?? '').trim() || null;
}

export interface Refusal {
  kind: string;
  message: string;
}

/**
 * Every reason a `management_access` job would be refused on this device,
 * whatever the management range says (that one is judged beside it).
 * Exported for the rollout composition, which lists them per device.
 */
export function managementAccessDeviceRefusals(facts: Facts): Refusal[] {
  const d = facts.device;
  const out: Refusal[] = [];
  if (d.status === 'disabled' || d.status === 'quarantined') {
    out.push({ kind: 'device_not_writable', message: `${d.name} est « ${d.status} » : aucune tâche ne peut le viser.` });
  }
  if (!d.is_managed) {
    out.push({ kind: 'device_not_managed', message: `${d.name} n’est pas géré par ObliWAN (lecture seule).` });
  }
  if (d.brand !== 'mikrotik') {
    out.push({
      kind: 'brand_unsupported',
      message: `${d.name} est un équipement ${d.brand} : l’accès de gestion API-SSL concerne les routeurs MikroTik.`,
    });
    return out;
  }
  if (d.role === 'concentrator') {
    out.push({
      kind: 'concentrator_refused',
      message:
        `${d.name} est un concentrateur : son API est gérée par le lien ObliWAN ↔ concentrateur, pas par cette tâche.`,
    });
  }
  const ssh = facts.ssh;
  const host = sshHostOf(facts);
  if (!ssh || !ssh.enabled || !host || !ssh.username) {
    out.push({
      kind: 'no_ssh',
      message:
        `${d.name} n’a pas de canal SSH activé et complet (adresse, utilisateur, mot de passe) : la tâche passe par SSH, ` +
        'le seul canal sur lequel répondent les routeurs en service. Ajoutez-le dans l’onglet Paramètres.',
    });
    return out;
  }
  if (!ssh.secret_enc) {
    out.push({
      kind: ssh.private_key_enc ? 'ssh_key_only' : 'no_ssh',
      message: ssh.private_key_enc
        ? `Le canal SSH de ${d.name} s’authentifie par clé : les sessions de la tâche (console et récupération SFTP de ` +
          'la sauvegarde) s’authentifient par mot de passe, et c’est ce compte qui crée « obliwan » quand il manque. ' +
          'Enregistrez le mot de passe du compte.'
        : `Le canal SSH de ${d.name} n’a pas de mot de passe dans le coffre.`,
    });
  }
  if (!isNonPublicAddress(host)) {
    out.push({
      kind: 'no_backup_road',
      message:
        `${d.name} est joint en SSH sur ${host}, une adresse publique ou un nom : ObliWAN n’épingle aucune clé d’hôte ` +
        'SSH, donc la sauvegarde préalable ne peut pas être récupérée par SFTP sur ce chemin. Rien n’est écrit sans ' +
        'sauvegarde : la tâche est refusée.',
    });
  }
  return out;
}

async function rangeRefusal(): Promise<{ prefixes: string[]; refusal: Refusal | null }> {
  const range = await readManagementRange();
  if (!range.ok) return { prefixes: [], refusal: { kind: 'range_invalid', message: range.message } };
  return { prefixes: range.prefixes, refusal: null };
}

function sameSet(a: readonly string[], b: readonly string[]): boolean {
  const x = [...new Set(a)].sort().join(',');
  const y = [...new Set(b)].sort().join(',');
  return x === y;
}

// ============================================================================
// The audited SSH console
// ============================================================================

export interface CliContext {
  tenantId: number;
  deviceId: number;
  deviceUuid: string | null;
  deviceName: string | null;
  jobId: number | null;
  correlationId: string | null;
  purpose: string;
}

function scrub(text: string, secrets: readonly string[]): string {
  let out = text;
  for (const s of secrets) if (s && s.length >= 4) out = out.split(s).join('***');
  return out;
}

/**
 * One SSH session, every command recorded in `command_audit` BEFORE it is
 * sent (`auditedCommand`: no trace, no bytes), every secret it was told about
 * scrubbed from the audited line and from any error that leaves.
 */
export class AuditedCli {
  private readonly secrets: string[];

  constructor(
    private readonly ssh: SshTransport,
    private readonly ctx: CliContext,
    secrets: readonly string[],
  ) {
    this.secrets = secrets.filter((s) => s && s.length >= 4);
  }

  protect(secret: string): void {
    if (secret && secret.length >= 4) this.secrets.push(secret);
  }

  async exec(
    command: string,
    opts: { isWrite: boolean; timeoutMs?: number; maxOutputBytes?: number },
  ): Promise<SshExecResult> {
    const line = redactForAudit([command], this.secrets);
    assertNoSecrets(line, this.secrets);
    return auditedCommand(
      {
        tenantId: this.ctx.tenantId,
        deviceId: this.ctx.deviceId,
        deviceUuid: this.ctx.deviceUuid,
        deviceName: this.ctx.deviceName,
        jobId: this.ctx.jobId,
        transport: 'ssh',
        command: line,
        args: { purpose: this.ctx.purpose },
        isWrite: opts.isWrite,
        correlationId: this.ctx.correlationId,
        secrets: this.secrets,
      },
      async () => {
        try {
          return await this.ssh.exec(command, {
            pty: false,
            timeoutMs: opts.timeoutMs ?? 30_000,
            maxOutputBytes: opts.maxOutputBytes ?? 256 * 1024,
          });
        } catch (err) {
          // SshTransport puts the COMMAND in its timeout message, and a
          // command can carry the backup password.
          if (err instanceof Error) err.message = scrub(err.message, this.secrets);
          throw err;
        }
      },
    );
  }

  /** A write: it completed only if it printed `CMD_OK`. The error names the
   *  router's own words (scrubbed, cut), never the command. */
  async write(command: string, opts: { timeoutMs?: number } = {}): Promise<string> {
    const res = await this.exec(command, { isWrite: true, timeoutMs: opts.timeoutMs });
    const out = `${res.stdout}\n${res.stderr}`;
    if (!out.includes(CMD_OK)) {
      const said = scrub(out.replace(/\s+/g, ' ').trim(), this.secrets).slice(0, 300);
      throw new ManagementAccessError('router_refused', `le routeur a refusé la commande : ${said || 'aucune réponse'}`);
    }
    return res.stdout;
  }

  async read(command: string, timeoutMs = 30_000): Promise<string> {
    const res = await this.exec(command, { isWrite: false, timeoutMs });
    return res.stdout;
  }

  /** `assertSshBoxSpeaksFamily` wants an `exec`; this one is audited. */
  asExec(): Pick<SshTransport, 'exec'> {
    return {
      exec: (command: string, o?: { timeoutMs?: number; maxOutputBytes?: number }) =>
        this.exec(command, { isWrite: false, timeoutMs: o?.timeoutMs, maxOutputBytes: o?.maxOutputBytes }),
    } as Pick<SshTransport, 'exec'>;
  }
}

export interface SshCredential {
  host: string;
  port: number;
  username: string;
  password: string;
  legacyAlgorithms: boolean;
}

export function sshCredentialOf(facts: Facts): SshCredential {
  const ssh = facts.ssh;
  const host = sshHostOf(facts);
  if (!ssh || !ssh.enabled || !host || !ssh.username || !ssh.secret_enc) {
    throw new ManagementAccessError('no_ssh', `${facts.device.name} n’a plus de canal SSH utilisable : rien n’a été écrit.`);
  }
  const params = (ssh.params ?? {}) as { legacyAlgorithms?: boolean };
  return {
    host,
    port: ssh.port ?? 22,
    username: ssh.username,
    password: decrypt(ssh.secret_enc),
    legacyAlgorithms: params.legacyAlgorithms === true,
  };
}

/** Read the three identity attributes over the console, as `readRouterOsIdentity`
 *  reads them over the API: identity, the RouterBOARD serial (a CHR has
 *  none — the read then answers nothing, which is null), and the login of
 *  the MANAGEMENT tunnel — the l2tp-client named l2tp-mgmt, else the sole
 *  one carrying `recordedPppUsername` (`managementTunnelLogin`), never simply
 *  the first one. Also the board model, kept for the record. */
async function readIdentityOverCli(
  cli: AuditedCli,
  recordedPppUsername: string | null,
): Promise<ObservedIdentity & { model: string | null }> {
  const identity = parseIdentity(await cli.read(SSH_READS.identity));
  const board = parseBoard(await cli.read(SSH_READS.board));
  const ppp = managementTunnelLogin(parseL2tpClients(await cli.read(SSH_READS.l2tp)), recordedPppUsername).login;
  return { systemIdentity: identity, serial: board.serial, pppUsername: ppp, model: board.model };
}

/** `assertSshBoxSpeaksFamily` (driver.ts), its refusal in the operator's
 *  language: the rsc backup's export is spelled for `devices.family`. */
export async function assertFamily(cli: AuditedCli, facts: Facts): Promise<void> {
  try {
    await assertSshBoxSpeaksFamily(cli.asExec(), facts.device.family, { timeoutMs: 30_000 });
  } catch (err) {
    if (err instanceof ExportDialectRefusal) {
      throw new ManagementAccessError(
        'family_mismatch',
        `La famille enregistrée pour ${facts.device.name} (« ${facts.device.family} ») ne correspond pas à la version que ` +
          `le routeur annonce, ou cette version n’a pas pu être lue : l’export de sauvegarde ne peut pas être écrit ` +
          `sans risque. Corrigez la famille de l’équipement ; rien n’a été écrit. (${err.message.slice(0, 200)})`,
      );
    }
    throw err;
  }
}

/** `compareIdentity` against the device row, plus the frozen old/new pair of a
 *  rename in flight or unsettled on the login and the identity (never the
 *  serial; fleet/identityAlternates.ts): the site_rename job changes them on
 *  the router before the row, and must not quarantine its own box. */
async function compareWithRecord(device: DeviceFacts, observed: ObservedIdentity) {
  return compareIdentity(
    { ppp_username: device.ppp_username, system_identity: device.system_identity, serial: device.serial },
    observed,
    await renameIdentityAlternates(device.id),
  );
}

/** The identity-binding consequence, as `assertTargetBinding` applies it: a box that answers
 *  with ANOTHER device's identity takes the device out of management. Only a
 *  proven MISMATCH quarantines; silence or an unproven identity refuses the
 *  session and changes nothing. */
async function quarantineDevice(deviceId: number, reason: string, checks: AttributeCheck[], where: string): Promise<void> {
  await db('devices').where({ id: deviceId }).update({ status: 'quarantined', is_managed: false, updated_at: db.fn.now() });
  logger.error({ deviceId, reason, checks, where }, 'Device quarantined: the box at its SSH address is not the recorded device');
}

/**
 * Open ONE SSH session and prove, on it, that the box is the device (the
 * DeviceSession rule: a PPP pool can move a lease between the assertion's
 * socket and the one we write on). A proven mismatch quarantines the device,
 * exactly as at bind_assert — the lease moved after the assertion, and the identity
 * signal is the same; an unproven session is refused without one.
 *
 * `as` logs in with ANOTHER account than the device's SSH credential, at the
 * same address and port: the `obliwan` account the job created or found,
 * proven on a session of its own before ObliWAN switches to it. A refused
 * login then surfaces as `ssh_failed` with `driverCode` `AUTH_FAILED`.
 */
export async function withProvenCli<T>(
  facts: Facts,
  ctx: CliContext,
  fn: (cli: AuditedCli, observed: ObservedIdentity & { model: string | null }) => Promise<T>,
  as?: { username: string; password: string },
): Promise<T> {
  const own = sshCredentialOf(facts);
  const cred = as ? { ...own, username: as.username, password: as.password } : own;
  try {
    return await withSsh(
      {
        host: cred.host,
        port: cred.port,
        username: cred.username,
        password: cred.password,
        timeoutMs: 20_000,
        legacyAlgorithms: cred.legacyAlgorithms,
      },
      async (ssh) => {
        const cli = new AuditedCli(ssh, ctx, [cred.password]);
        const observed = await readIdentityOverCli(cli, facts.device.ppp_username);
        if (!observed.systemIdentity && !observed.serial && !observed.pppUsername) {
          throw new ManagementAccessError(
            'identity_unproven',
            `La session SSH vers ${cred.host} n’a renvoyé aucun attribut d’identité : refus, rien n’a été écrit.`,
          );
        }
        const cmp = await compareWithRecord(facts.device, observed);
        if (!cmp.ok) {
          if (cmp.mismatched > 0) {
            await quarantineDevice(facts.device.id, cmp.reason, cmp.checks, ctx.purpose);
            throw new ManagementAccessError(
              'identity_mismatch',
              `La boîte jointe en SSH sur ${cred.host} (phase « ${ctx.purpose} ») n’est pas ${facts.device.name} ` +
                `(${cmp.reason}). Rien n’a été écrit dans cette session ; l’équipement est mis en quarantaine.`,
            );
          }
          throw new ManagementAccessError(
            'identity_unproven',
            `La session SSH vers ${cred.host} (phase « ${ctx.purpose} ») n’a corroboré aucun attribut d’identité ` +
              `de ${facts.device.name} (${cmp.reason}). Rien n’a été écrit dans cette session.`,
          );
        }
        return fn(cli, observed);
      },
    );
  } catch (err) {
    // The transport's own failures (unreachable, refused login, timeout) in
    // the operator's language; whether anything was written is the job row's
    // `wrote_at`, which the outcome reads.
    if (err instanceof DriverError && !(err instanceof ExportDialectRefusal)) {
      throw new ManagementAccessError(
        'ssh_failed',
        `La session SSH vers ${cred.host}:${cred.port} (phase « ${ctx.purpose} ») a échoué : ${scrub(err.message, [cred.password, own.password]).slice(0, 300)}.`,
        409,
        err.code,
      );
    }
    throw err;
  }
}

// ============================================================================
// Identity binding over SSH — the capability `assertTargetBinding` does not have
// ============================================================================

/**
 * Prove that the box at the device's SSH address IS the device, on a fresh
 * SSH session. `assertTargetBinding()` proves a MikroTik over its RouterOS API
 * only (BINDING_TRANSPORT) — the one channel a router in service does not
 * answer before this job — so this is that assertion, narrowly, for this job:
 * the same three attributes (read as the API path reads them), the same
 * `compareIdentity`, the same refusal of silence, the same quarantine on a
 * mismatch, the same "fill a blank identity column, never overwrite one".
 * Throws `BindingAssertionError` on every failure.
 */
export async function assertMikrotikBindingOverSsh(
  deviceId: number,
  audit: { jobId: number | null; correlationId: string | null } = { jobId: null, correlationId: null },
): Promise<BindingAssertion> {
  const at = new Date().toISOString();
  const facts = await loadFacts(deviceId, null);
  if (!facts) throw new Error(`Device ${deviceId} does not exist`);
  const fail = async (reason: string, checks: AttributeCheck[] = [], dialled = '-'): Promise<never> => {
    const assertion: BindingAssertion = {
      deviceId,
      ok: false,
      checks,
      matched: checks.filter((c) => c.outcome === 'match').length,
      mismatched: checks.filter((c) => c.outcome === 'mismatch').length,
      dialled,
      reason,
      at,
    };
    if (assertion.mismatched > 0) await quarantineDevice(deviceId, reason, checks, 'bind_assert');
    throw new BindingAssertionError(assertion);
  };

  if (facts.device.status === 'disabled') return fail("device status is 'disabled'; no transport may be opened");
  if (facts.device.brand !== 'mikrotik') return fail(`SSH identity proof is written for MikroTik only, not '${facts.device.brand}'`);
  let cred: SshCredential;
  try {
    cred = sshCredentialOf(facts);
  } catch {
    return fail('ssh transport is absent, disabled or has no password in the vault');
  }

  let observed: ObservedIdentity;
  try {
    observed = await withSsh(
      { host: cred.host, port: cred.port, username: cred.username, password: cred.password, timeoutMs: 15_000, legacyAlgorithms: cred.legacyAlgorithms },
      async (ssh) => {
        const cli = new AuditedCli(
          ssh,
          {
            tenantId: facts.device.tenant_id,
            deviceId,
            deviceUuid: facts.device.uuid,
            deviceName: facts.device.name,
            jobId: audit.jobId,
            correlationId: audit.correlationId,
            purpose: 'bind_assert',
          },
          [cred.password],
        );
        return readIdentityOverCli(cli, facts.device.ppp_username);
      },
    );
  } catch (err) {
    const message = scrub(err instanceof Error ? err.message : String(err), [cred.password]);
    return fail(`fresh ssh session to ${cred.host} failed: ${message}`, [], cred.host);
  }

  if (!observed.systemIdentity && !observed.serial && !observed.pppUsername) {
    return fail('ssh answered but reported no identity attribute at all — refusing rather than treating silence as agreement', [], cred.host);
  }
  const comparison = await compareWithRecord(facts.device, observed);
  if (!comparison.ok) return fail(comparison.reason, comparison.checks, cred.host);

  const learn: Record<string, unknown> = {};
  if (!facts.device.system_identity && observed.systemIdentity) learn.system_identity = observed.systemIdentity;
  if (!facts.device.serial && observed.serial) learn.serial = observed.serial;
  if (Object.keys(learn).length > 0) {
    await db('devices').where({ id: deviceId }).update({ ...learn, updated_at: db.fn.now() });
  }
  logger.info({ deviceId, dialled: cred.host, matched: comparison.matched }, 'Target binding asserted on a fresh SSH session');
  return {
    deviceId,
    ok: true,
    checks: comparison.checks,
    matched: comparison.matched,
    mismatched: 0,
    dialled: cred.host,
    reason: comparison.reason,
    at,
  };
}

// ============================================================================
// The channel this job opens, as the PUSH path's guard must see it
// ============================================================================

/** The reason code `evaluateGuardForPlan` (apply.service.ts) adds to a push
 *  plan that would close the API channel this job opened. */
export const API_CHANNEL_REASON_CODE = 'API_CHANNEL_CLOSED';

export interface ApiChannelReason {
  code: typeof API_CHANNEL_REASON_CODE;
  effect: 'reject';
  probe: null;
  message: string;
  culprit: {
    resource: 'service';
    semKey: string;
    index: null;
    chain: null;
    describe: string;
    opSeq: number | null;
    opKind: string | null;
  };
}

/**
 * Pure: the ops of a plan that would leave api-ssl in a state ObliWAN's API
 * channel cannot ride — disabled, deleted, another port, another
 * certificate, or addresses that no longer include every management prefix.
 *
 * ┌─ WHY THE MANAGEMENT-PATH GUARD ALONE DOES NOT SEE IT ─────────────────────┐
 * │ `guardPlan` (plan/mgmtPathGuard.ts) refuses a plan that leaves NO          │
 * │ management service open to the platform (MGMT_SERVICE_LOST). SSH stays    │
 * │ open on these routers, so a template that writes                          │
 * │ `/ip service set api-ssl disabled=yes` — the customer templates do —      │
 * │ passes it, and the next push would silently shut the channel this job     │
 * │ opened: the RouterOS API every poll, log pull and push to the router      │
 * │ uses. The desired state is the operator's, kept in ObliWAN: such a plan   │
 * │ is REFUSED here, by name, and the message says what the template's        │
 * │ api-ssl line must say. Overridable like any REJECT, with a signed reason. │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * Only the fields an op CHANGES are judged when it lists them (`fields`): a
 * plan that leaves api-ssl's port alone is not refused for it. `prefixes`
 * null = the management range could not be read: a changed address list is
 * then refused rather than assumed to still hold the platform.
 */
export function apiChannelReasonsForOps(ops: readonly unknown[], prefixes: readonly string[] | null): ApiChannelReason[] {
  const key = serviceKey(API_SSL_SERVICE, null);
  const out: ApiChannelReason[] = [];
  for (const raw of ops) {
    if (!raw || typeof raw !== 'object') continue;
    const op = raw as {
      seq?: unknown; kind?: unknown; resource?: unknown; semKey?: unknown;
      before?: unknown; after?: unknown; fields?: unknown;
    };
    if (op.resource !== 'service') continue;
    const side = (v: unknown): Record<string, unknown> | null => (v && typeof v === 'object' ? (v as Record<string, unknown>) : null);
    const after = side(op.after);
    const before = side(op.before);
    if (op.semKey !== key && after?.service !== API_SSL_SERVICE && before?.service !== API_SSL_SERVICE) continue;
    const kind = typeof op.kind === 'string' ? op.kind : null;
    if (kind === 'verify' || kind === 'blocked' || kind === 'move' || kind === 'enable') continue;
    const fields = Array.isArray(op.fields) ? op.fields.map(String) : [];
    const touched = (...names: string[]): boolean => fields.length === 0 || names.some((n) => fields.includes(n));

    const problems: string[] = [];
    if (kind === 'delete' || kind === 'disable') problems.push(`the op would ${kind} it`);
    else if (!after) problems.push('the op carries no resulting state that could be checked');
    else {
      if (touched('enabled', 'disabled') && (after.enabled === false || after.disabled === true)) problems.push('it would be disabled');
      if (touched('port') && after.port !== null && after.port !== undefined && Number(after.port) !== API_SSL_PORT) {
        problems.push(`its port would be ${String(after.port)} instead of ${API_SSL_PORT}`);
      }
      if (touched('certificate') && after.certificate !== OBLIWAN_API_CERTIFICATE &&
        (fields.includes('certificate') || (after.certificate !== null && after.certificate !== undefined))) {
        problems.push(`it would serve "${String(after.certificate ?? 'none')}" instead of ${OBLIWAN_API_CERTIFICATE}`);
      }
      const allowed = Array.isArray(after.allowedFrom) ? after.allowedFrom.map(String) : null;
      if (touched('allowedFrom') && allowed && !allowed.includes('any')) {
        if (prefixes === null) {
          problems.push('its allowed addresses change, and the management range variable cannot be read to check them');
        } else {
          const lost = prefixes.filter((p) => !allowed.includes(addressAtom(p)));
          if (lost.length > 0) problems.push(`its allowed addresses would no longer include ${lost.join(', ')}`);
        }
      }
    }
    if (problems.length === 0) continue;
    const seq = typeof op.seq === 'number' ? op.seq : null;
    out.push({
      code: API_CHANNEL_REASON_CODE,
      effect: 'reject',
      probe: null,
      message:
        `Op${seq === null ? '' : ` #${seq}`} changes api-ssl, the service ObliWAN's RouterOS API channel to this router ` +
        `rides (8729, TLS, pinned): ${problems.join('; ')}. SSH would stay open, so no lockout check fires, but ` +
        'ObliWAN would lose its API channel — polling, the log pull and the push path itself. The template\'s ' +
        `/ip service line for api-ssl must leave it as the management access does: disabled=no port=${API_SSL_PORT} ` +
        `address=<the management range, instance variable obliwan_management_range> certificate=${OBLIWAN_API_CERTIFICATE}.`,
      culprit: {
        resource: 'service',
        semKey: key,
        index: null,
        chain: null,
        describe: `service=${API_SSL_SERVICE}`,
        opSeq: seq,
        opKind: kind,
      },
    });
  }
  return out;
}

/** `apiChannelReasonsForOps` for a device whose RouterOS API channel rides
 *  api-ssl (its `routeros_api` transport enabled, TLS, on 8729 — what this
 *  job and the bench leave). Any other device: nothing to protect, []. */
export async function managementApiChannelReasons(deviceId: number, ops: readonly unknown[]): Promise<ApiChannelReason[]> {
  const api = (await db('device_transports')
    .where({ device_id: deviceId, transport: 'routeros_api' })
    .first('enabled', 'use_tls', 'port')) as { enabled: boolean; use_tls: boolean; port: number | null } | undefined;
  if (!api || !api.enabled || !api.use_tls || Number(api.port) !== API_SSL_PORT) return [];
  const range = await readManagementRange();
  return apiChannelReasonsForOps(ops, range.ok ? range.prefixes : null);
}

/** A guard outcome with the channel reasons folded in: any reason makes it a
 *  REJECT, whatever the forwarding guard concluded. */
export function withApiChannelReasons<
  T extends { verdict: string; reasons: unknown[]; summary: string; unavailable: boolean },
>(base: T, reasons: readonly ApiChannelReason[]): T {
  if (reasons.length === 0) return base;
  return {
    ...base,
    verdict: 'REJECT',
    reasons: [...base.reasons, ...reasons],
    summary: `Management-Path Guard: REJECT — ${reasons[0].message}`,
  };
}

// ============================================================================
// Enqueue — the only door that creates a management_access job
// ============================================================================

/** Same convention as apply.service: a plan-less job records no base state. */
const NO_BASE_STATE = '0'.repeat(64);

export interface EnqueueManagementAccessInput {
  tenantId: number;
  deviceId: number;
  requestedBy: number | null;
  /** The job has no net, so the explicit confirmation is required. */
  confirmDegraded: { userId: number | null } | null;
  /** The device page: a job already queued or running for THIS kind on this
   *  device is returned instead of refused. A rollout never sets it. */
  allowExisting?: boolean;
  scheduledFor?: Date | null;
  windowStart?: Date | null;
  windowEnd?: Date | null;
}

export interface EnqueueManagementAccessResult {
  jobId: number;
  alreadyQueued: boolean;
  guard: ReturnType<typeof managementAccessGuard>;
  safetyNet: ReturnType<typeof managementAccessSafetyNet>;
}

export async function activeJobOf(deviceId: number): Promise<{ id: number; kind: string } | null> {
  const row = (await db('change_jobs')
    .where({ device_id: deviceId })
    .whereIn('status', ['queued', 'claimed', 'backing_up', 'arming', 'applying', 'verifying', 'soaking', 'disarming'])
    .orderBy('id', 'desc')
    .first('id', 'kind')) as { id: string | number; kind: string } | undefined;
  return row ? { id: Number(row.id), kind: row.kind } : null;
}

/** Every refusal for one device, the range included. */
export async function managementAccessRefusals(
  tenantId: number,
  deviceId: number,
): Promise<{ facts: Facts | null; prefixes: string[]; refusals: Refusal[] }> {
  const facts = await loadFacts(deviceId, tenantId);
  const range = await rangeRefusal();
  if (!facts) {
    return { facts: null, prefixes: range.prefixes, refusals: [{ kind: 'device_not_found', message: `Équipement #${deviceId} introuvable.` }] };
  }
  const refusals = [...(range.refusal ? [range.refusal] : []), ...managementAccessDeviceRefusals(facts)];
  return { facts, prefixes: range.prefixes, refusals };
}

/**
 * Create one management_access job and its `management_access_jobs` row in ONE
 * transaction, so no worker can claim a job whose frozen range it cannot read.
 * `change_jobs_one_in_flight_uq` is the one-job-per-device rule; its 23505
 * becomes `DeviceBusyError` (or, for the device page, the job already there).
 */
export async function enqueueManagementAccessJob(
  input: EnqueueManagementAccessInput,
): Promise<EnqueueManagementAccessResult> {
  const killSwitch = await readKillSwitch(input.tenantId);
  if (killSwitch.blocked) throw new KillSwitchEngagedError(killSwitch);

  const guard = managementAccessGuard();
  const safetyNet = managementAccessSafetyNet();
  const { facts, prefixes, refusals } = await managementAccessRefusals(input.tenantId, input.deviceId);
  if (refusals.length > 0 || !facts) {
    const first = refusals[0] ?? { kind: 'device_not_found', message: `Équipement #${input.deviceId} introuvable.` };
    throw new ManagementAccessError(first.kind, refusals.map((r) => r.message).join(' '), first.kind === 'device_not_found' ? 404 : 409);
  }
  if (!input.confirmDegraded) {
    throw new ManagementAccessError('degraded_unconfirmed', `${safetyNet.rationale} La tâche doit être confirmée explicitement.`, 422);
  }

  const existingFirst = await activeJobOf(facts.device.id);
  if (existingFirst) {
    if (existingFirst.kind === MANAGEMENT_ACCESS_KIND && input.allowExisting) {
      return { jobId: existingFirst.id, alreadyQueued: true, guard, safetyNet };
    }
    throw new DeviceBusyError(facts.device.id);
  }

  const sshHost = sshHostOf(facts) as string;
  const now = new Date();
  let jobId: number;
  try {
    jobId = await db.transaction(async (trx) => {
      const inserted = (await trx('change_jobs')
        .insert({
          tenant_id: input.tenantId,
          device_id: facts.device.id,
          plan_id: null,
          kind: MANAGEMENT_ACCESS_KIND,
          status: 'queued',
          attempt: 0,
          // A write is not retried silently; the operator (or the rollout) asks again.
          max_attempts: 1,
          base_state_hash: NO_BASE_STATE,
          safety_level: safetyNet.level,
          safety_peer_device_id: null,
          guard_verdict: guard.verdict,
          guard_reasons: JSON.stringify(guard.reasons),
          degraded_confirmed_by: input.confirmDegraded!.userId,
          degraded_confirmed_at: now,
          scheduled_for: input.scheduledFor ?? null,
          window_start: input.windowStart ?? null,
          window_end: input.windowEnd ?? null,
          requested_by: input.requestedBy,
        })
        .returning('id')) as Array<{ id: string | number }>;
      const id = Number(inserted[0].id);
      await trx('management_access_jobs').insert({
        job_id: id,
        tenant_id: input.tenantId,
        device_id: facts.device.id,
        mgmt_prefixes: JSON.stringify(prefixes),
        api_port: API_SSL_PORT,
        ssh_host: sshHost,
      });
      return id;
    });
  } catch (err) {
    const pg = err as { code?: string; constraint?: string; message?: string };
    if (pg.code === '23505' && pg.constraint === 'change_jobs_one_in_flight_uq') {
      const existing = await activeJobOf(facts.device.id);
      if (existing && existing.kind === MANAGEMENT_ACCESS_KIND && input.allowExisting) {
        return { jobId: existing.id, alreadyQueued: true, guard, safetyNet };
      }
      throw new DeviceBusyError(facts.device.id);
    }
    if (pg.code === '23001' && /subtree interlock/i.test(pg.message ?? '')) {
      throw new ManagementAccessError(
        'subtree_interlock',
        'Une tâche est en cours sur le concentrateur qui porte le tunnel de ce routeur : rien n’a été mis en ' +
          'file. Relancez quand elle sera terminée.',
      );
    }
    throw err;
  }

  logger.warn(
    { jobId, deviceId: facts.device.id, kind: MANAGEMENT_ACCESS_KIND, requestedBy: input.requestedBy },
    'management_access job QUEUED — api-ssl is about to be opened on a customer router over SSH',
  );
  const summary = { jobId, deviceId: facts.device.id, kind: MANAGEMENT_ACCESS_KIND, status: 'queued' };
  emitToTenantAudience(input.tenantId, SOCKET_EVENTS.JOB_QUEUED, summary, { deviceId: facts.device.id });
  emitToDevice(facts.device.id, SOCKET_EVENTS.JOB_QUEUED, summary);
  return { jobId, alreadyQueued: false, guard, safetyNet };
}

// ============================================================================
// The view — the device page's card
// ============================================================================

export interface ManagementAccessStepView {
  seq: number;
  kind: string;
  status: string;
  output: string | null;
  error: string | null;
}

export interface ManagementAccessJobView {
  id: number;
  status: ChangeJobStatus;
  active: boolean;
  outcome: ManagementAccessOutcome | null;
  outcomeDetail: string | null;
  errorKind: string | null;
  errorMessage: string | null;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  wroteAt: string | null;
  backupId: number | null;
  transportAction: ManagementAccessTransportAction | null;
  pinnedFingerprint: string | null;
  rolloutId: number | null;
  /** What the job did about ObliWAN's own account (migration 071). `action`
   *  null = the job did not get that far, or predates 071. `switchedAt` null
   *  beside `created`/`present` = the account exists and ObliWAN does not use
   *  it yet. `disclosedAt`: this run's API login carried the `obliwan`
   *  password to a certificate that was not the expected one — the password
   *  was discarded, the account must be removed and recreated. Never the
   *  password, in any form. */
  account: { action: ManagementAccountAction | null; detail: string | null; switchedAt: string | null; disclosedAt: string | null };
  steps: ManagementAccessStepView[];
}

export interface ManagementAccessView {
  deviceId: number;
  deviceName: string;
  state: 'unsupported' | 'not_enabled' | 'in_progress' | 'enabled' | 'failed';
  eligible: boolean;
  refusals: Refusal[];
  range: { ok: boolean; prefixes: string[]; message: string | null };
  /** `username`: the account ObliWAN logs in with over SSH — `obliwan` once a
   *  job switched it, the historical one before. */
  ssh: { host: string | null; port: number | null; enabled: boolean; auth: 'password' | 'key' | 'none'; username: string | null } | null;
  api: {
    host: string | null;
    port: number | null;
    username: string | null;
    enabled: boolean;
    tls: boolean;
    pinned: boolean;
    fingerprint: string | null;
    lastOkAt: string | null;
    lastError: string | null;
  } | null;
  /** api-ssl on the router, as ObliWAN last READ it (never guessed): by the
   *  latest job, or by the health check (migration 064), whichever is newer. */
  apiSsl: {
    state: 'unknown' | 'conformant' | 'different';
    readAt: string | null;
    differences: ApiSslStateDifference[];
    source: 'job' | 'automatic' | null;
  };
  job: ManagementAccessJobView | null;
}

function iso(d: Date | string | null | undefined): string | null {
  return d ? new Date(d).toISOString() : null;
}

export async function getManagementAccessView(tenantId: number, deviceId: number): Promise<ManagementAccessView | null> {
  const { facts, prefixes, refusals } = await managementAccessRefusals(tenantId, deviceId);
  if (!facts) return null;
  const rangeMessage = refusals.find((r) => r.kind === 'range_invalid')?.message ?? null;

  const jobRow = (await db('management_access_jobs as m')
    .join('change_jobs as j', 'j.id', 'm.job_id')
    .where('m.device_id', deviceId)
    .where('m.tenant_id', tenantId)
    .orderBy('m.job_id', 'desc')
    .first(
      'm.job_id', 'm.mgmt_prefixes', 'm.backup_id', 'm.wrote_at', 'm.outcome', 'm.outcome_detail', 'm.observed',
      'm.transport_action', 'm.pinned_fingerprint', 'j.status', 'j.error_kind', 'j.error_message', 'j.created_at',
      'j.started_at', 'j.finished_at', 'j.rollout_id',
      // 071 — never `account_secret_enc`: the view carries no credential.
      'm.account_action', 'm.account_detail', 'm.account_switched_at', 'm.account_secret_disclosed_at',
    )) as Record<string, any> | undefined;

  let job: ManagementAccessJobView | null = null;
  let apiSsl: ManagementAccessView['apiSsl'] = { state: 'unknown', readAt: null, differences: [], source: null };
  if (jobRow) {
    const steps = (await db('change_job_steps')
      .where({ job_id: jobRow.job_id })
      .orderBy([{ column: 'attempt', order: 'asc' }, { column: 'seq', order: 'asc' }])
      .select('seq', 'kind', 'status', 'output_redacted', 'error_redacted')) as Array<Record<string, any>>;
    const status = jobRow.status as ChangeJobStatus;
    job = {
      id: Number(jobRow.job_id),
      status,
      active: isActiveJobStatus(status),
      outcome: (jobRow.outcome ?? null) as ManagementAccessOutcome | null,
      outcomeDetail: jobRow.outcome_detail ?? null,
      errorKind: jobRow.error_kind ?? null,
      errorMessage: jobRow.error_message ?? null,
      createdAt: iso(jobRow.created_at) as string,
      startedAt: iso(jobRow.started_at),
      finishedAt: iso(jobRow.finished_at),
      wroteAt: iso(jobRow.wrote_at),
      backupId: jobRow.backup_id === null ? null : Number(jobRow.backup_id),
      transportAction: (jobRow.transport_action ?? null) as ManagementAccessTransportAction | null,
      pinnedFingerprint: jobRow.pinned_fingerprint ?? null,
      rolloutId: jobRow.rollout_id === null ? null : Number(jobRow.rollout_id),
      account: {
        action: (jobRow.account_action ?? null) as ManagementAccountAction | null,
        detail: jobRow.account_detail ?? null,
        switchedAt: iso(jobRow.account_switched_at),
        disclosedAt: iso(jobRow.account_secret_disclosed_at),
      },
      steps: steps.map((s) => ({
        seq: Number(s.seq),
        kind: String(s.kind),
        status: String(s.status),
        output: s.output_redacted ?? null,
        error: s.error_redacted ?? null,
      })),
    };
    const observed = (jobRow.observed ?? null) as { service?: ServiceReading | null; readAt?: string } | null;
    if (observed && observed.readAt) {
      const frozen = Array.isArray(jobRow.mgmt_prefixes) ? (jobRow.mgmt_prefixes as string[]) : prefixes;
      const want = prefixes.length > 0 ? prefixes : frozen;
      const diffs = apiSslStateDifferences(observed.service ? { ...observed.service } : null, want);
      apiSsl = { state: diffs.length === 0 ? 'conformant' : 'different', readAt: observed.readAt, differences: diffs, source: 'job' };
    }
  }

  const auto = (await db('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first('api_ssl_observed', 'api_ssl_observed_at')) as
    | { api_ssl_observed: { service?: ServiceReading | null } | null; api_ssl_observed_at: Date | null }
    | undefined;
  if (auto?.api_ssl_observed && auto.api_ssl_observed_at
    && (apiSsl.readAt === null || new Date(auto.api_ssl_observed_at) > new Date(apiSsl.readAt))) {
    const svc = auto.api_ssl_observed.service ?? null;
    const diffs = apiSslStateDifferences(svc ? { ...svc } : null, prefixes);
    apiSsl = {
      state: diffs.length === 0 ? 'conformant' : 'different',
      readAt: iso(auto.api_ssl_observed_at),
      differences: diffs,
      source: 'automatic',
    };
  }

  const api = facts.api;
  const apiView = api
    ? {
        host: api.host,
        port: api.port,
        username: api.username,
        enabled: api.enabled,
        tls: api.use_tls,
        pinned: Boolean(api.tls_fingerprint_sha256),
        fingerprint: api.tls_fingerprint_sha256 ?? null,
        lastOkAt: iso(api.last_ok_at),
        lastError: api.last_error ?? null,
      }
    : null;
  const ssh = facts.ssh;
  const unsupported = refusals.some((r) => r.kind === 'brand_unsupported' || r.kind === 'concentrator_refused');
  const apiReady = apiView !== null && apiView.enabled && apiView.tls && apiView.port === API_SSL_PORT && apiView.pinned;
  let state: ManagementAccessView['state'];
  if (job?.active) state = 'in_progress';
  else if (unsupported) state = 'unsupported';
  // A failed job is history once a later automatic read shows api-ssl right.
  else if (apiReady && (job === null || job.status === 'succeeded'
    || (apiSsl.source === 'automatic' && apiSsl.state === 'conformant'))) state = 'enabled';
  else if (job && (job.status === 'failed' || job.status === 'aborted')) state = 'failed';
  else state = 'not_enabled';

  return {
    deviceId,
    deviceName: facts.device.name,
    state,
    eligible: refusals.length === 0,
    refusals,
    range: { ok: rangeMessage === null, prefixes, message: rangeMessage },
    ssh: ssh
      ? {
          host: sshHostOf(facts),
          port: ssh.port ?? 22,
          enabled: ssh.enabled,
          auth: ssh.secret_enc ? 'password' : ssh.private_key_enc ? 'key' : 'none',
          username: ssh.username,
        }
      : null,
    api: apiView,
    apiSsl,
    job,
  };
}

// ============================================================================
// The job's phases (called from apply.service.ts runPhases)
// ============================================================================

export interface ManagementAccessStepResult {
  output: string;
  detail: Record<string, unknown>;
}

interface FrozenRow {
  job_id: string | number;
  tenant_id: number;
  device_id: number;
  mgmt_prefixes: unknown;
  api_port: number;
  ssh_host: string;
  backup_id: string | number | null;
  wrote_at: Date | null;
  outcome: string | null;
}

interface Observation {
  phase: 'lint' | 'verify';
  readAt: string;
  identity: string | null;
  serial: string | null;
  model: string | null;
  service: ServiceReading | null;
  certificates: CertificateReading[];
}

async function patchJob(jobId: number, patch: Record<string, unknown>): Promise<void> {
  await db('management_access_jobs').where({ job_id: jobId }).update({ ...patch, updated_at: db.fn.now() });
}

/**
 * Record a failure on the job's row when its own steps did not: `refused` if
 * nothing was written on the router, `failed` otherwise. Called by `failJob`
 * (apply.service) for every failure of this kind, including the ones before
 * its branch (bind_assert, kill switch, guard). An outcome already recorded is
 * kept. Never throws.
 */
export async function settleManagementAccess(job: Pick<ChangeJobRow, 'id'>, message: string): Promise<void> {
  try {
    const jobId = Number(job.id);
    const row = (await db('management_access_jobs').where({ job_id: jobId }).first('outcome', 'wrote_at')) as
      | { outcome: string | null; wrote_at: Date | null }
      | undefined;
    if (!row || row.outcome !== null) return;
    await patchJob(jobId, {
      outcome: row.wrote_at ? 'failed' : 'refused',
      outcome_detail: (message || 'échec sans message').slice(0, 4000),
    });
  } catch (err) {
    logger.error({ err, jobId: Number(job.id) }, 'management_access: could not record the outcome of a failed job');
  }
}

const EXTENSION: Record<BackupKind, string> = { binary: '.backup', rsc: '.rsc' };
const KIND_LABEL: Record<BackupKind, string> = { binary: 'binaire', rsc: 'texte (rsc)' };
const BACKUP_MAX_BYTES = 128 * 1024 * 1024;

/**
 * The pre-change backup over SSH, for a job that reaches a MikroTik by SSH only: the SFTP road
 * PROVEN before any file exists, then a backup saved on the router, pulled by
 * SFTP, proven, stored, erased from the router, recorded in `device_backups`
 * as this job's preflight. Shared by `management_access` and `lte_apn`
 * (lteApn.service.ts), so the two jobs cannot drift on how a customer's
 * configuration leaves the box. Its refusals are `ManagementAccessError`s;
 * a caller of another kind renames them.
 */
export class SshPreflightBackup {
  constructor(
    private readonly job: ChangeJobRow,
    private readonly device: { id: number; uuid?: string | null; name?: string | null },
    private readonly correlationId: string,
    /** The job kind, for the log line. */
    private readonly label: string,
  ) {}

  private get jobId(): number {
    return Number(this.job.id);
  }

  /** The SFTP road, PROVEN before any file exists: a STAT of a name that
   *  cannot exist must answer "no such file" — the subsystem is there and
   *  serves this account. Anything else refuses the job here. */
  async probeRoad(cred: SshCredential): Promise<void> {
    const probe = `obliwan-probe-${crypto.randomBytes(6).toString('hex')}.none`;
    const local = path.join(defaultSpoolDir(), `${probe}.part`);
    await fsp.mkdir(defaultSpoolDir(), { recursive: true });
    const line = `sftp stat ${probe}`;
    let verdict: 'open' | string = 'open';
    await auditedCommand(
      {
        tenantId: this.job.tenant_id,
        deviceId: this.device.id,
        deviceUuid: this.device.uuid ?? null,
        deviceName: this.device.name ?? null,
        jobId: this.jobId,
        transport: 'ssh',
        command: line,
        args: { purpose: 'lint', road: 'sftp', host: cred.host },
        isWrite: false,
        correlationId: this.correlationId,
        secrets: [cred.password],
      },
      async () => {
        try {
          await sftpPullFile({
            host: cred.host,
            port: cred.port,
            username: cred.username,
            password: cred.password,
            remotePath: probe,
            localPath: local,
            maxBytes: 1,
            timeoutMs: 30_000,
          });
          verdict = 'une lecture d’un fichier inexistant a réussi';
        } catch (err) {
          if (err instanceof TransferError && err.code === 'FILE_ABSENT') verdict = 'open';
          else verdict = scrub(err instanceof Error ? err.message : String(err), [cred.password]);
        } finally {
          await fsp.rm(local, { force: true }).catch(() => undefined);
        }
      },
    );
    if (verdict !== 'open') {
      throw new ManagementAccessError(
        'no_backup_road',
        `La sauvegarde préalable ne peut pas être récupérée : le sous-système SFTP de ${cred.host} n’a pas répondu comme ` +
          `attendu (${verdict}). Rien n’est écrit sans sauvegarde : refus, aucun fichier n’a été créé sur le routeur.`,
      );
    }
  }

  private async eraseOnDevice(cli: AuditedCli, name: string): Promise<boolean> {
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        await cli.write(SSH_WRITES.fileRemove(name));
      } catch {
        // judged by the look below
      }
      const left = parseFiles(await cli.read(SSH_WRITES.fileInfo(name.replace(/^flash\//, '')))).filter((f) => f.name === name);
      if (left.length === 0) return true;
      await deps.sleep(500);
    }
    return false;
  }

  private async eraseNote(cli: AuditedCli, name: string): Promise<string> {
    try {
      return (await this.eraseOnDevice(cli, name))
        ? ''
        : ` Le fichier ${name} n’a PAS pu être prouvé effacé du routeur : supprimez-le à la main.`;
    } catch {
      return ` Le fichier ${name} n’a PAS pu être prouvé effacé du routeur : supprimez-le à la main.`;
    }
  }

  async backupOne(
    cli: AuditedCli,
    cred: SshCredential,
    facts: Facts,
    kind: BackupKind,
  ): Promise<{ id: number; kind: BackupKind; bytes: number }> {
    const base = backupBaseName(`obliwan-${this.jobId}-${kind}`);
    const fileName = `${base}${EXTENSION[kind]}`;
    const password = kind === 'binary' ? crypto.randomBytes(24).toString('base64url') : null;
    if (password) cli.protect(password);
    const fail = async (message: string, onDevice: string): Promise<never> => {
      const note = await this.eraseNote(cli, onDevice);
      throw new ManagementAccessError('backup_failed', `Sauvegarde ${KIND_LABEL[kind]} : ${message}.${note} Rien n’a été écrit sur la configuration.`);
    };

    // 1. produce it
    try {
      await cli.write(
        kind === 'binary' ? SSH_WRITES.backupSave(base, password as string) : SSH_WRITES.exportFile(facts.device.family, base),
        { timeoutMs: 120_000 },
      );
    } catch (err) {
      return fail(err instanceof Error ? err.message : String(err), fileName);
    }

    // 2. it exists and its size stopped moving
    let file: { name: string; size: number | null; exact: boolean } | null = null;
    let previous: number | null = null;
    const deadline = Date.now() + 120_000;
    while (Date.now() < deadline) {
      const found = parseFiles(await cli.read(SSH_WRITES.fileInfo(fileName)))[0] ?? null;
      if (found && found.size !== null && found.size > 0 && found.size === previous) {
        file = found;
        break;
      }
      if (found && !found.exact && found.name) {
        // A size the box could not state exactly: one stable look is all there
        // is; SFTP's own STAT is then the exact one.
        file = found;
        break;
      }
      previous = found?.size ?? null;
      await deps.sleep(500);
    }
    if (!file) return fail('le fichier n’est pas apparu sur le routeur, ou sa taille n’a pas cessé de varier', fileName);

    // 3. pull it off, over the SSH channel's SFTP
    let received: ReceivedFile & { remoteSize: number | null };
    try {
      received = await auditedCommand(
        {
          tenantId: this.job.tenant_id,
          deviceId: this.device.id,
          deviceUuid: this.device.uuid ?? null,
          deviceName: this.device.name ?? null,
          jobId: this.jobId,
          transport: 'ssh',
          command: `sftp get ${file.name}`,
          args: { purpose: 'backup', road: 'sftp', host: cred.host, bytes: file.size },
          isWrite: false,
          correlationId: this.correlationId,
          secrets: [cred.password],
        },
        async () => {
          try {
            return await sftpPullToSpool({
              host: cred.host,
              port: cred.port,
              username: cred.username,
              password: cred.password,
              remotePath: (file as { name: string }).name,
              maxBytes: BACKUP_MAX_BYTES,
              timeoutMs: 5 * 60_000,
            });
          } catch (err) {
            if (err instanceof Error) err.message = scrub(err.message, [cred.password]);
            throw err;
          }
        },
      );
    } catch (err) {
      return fail(`la récupération SFTP a échoué (${err instanceof Error ? err.message : String(err)})`, file.name);
    }

    // 4. prove it
    let verified: { path: string; bytes: number; sha256: string };
    try {
      verified = await verifyArtefact(received, {
        minBytes: MIN_BACKUP_BYTES[kind],
        deviceReportedBytes: file.size,
        exactDeviceBytes: file.exact,
      });
    } catch (err) {
      await fsp.rm(received.path, { force: true }).catch(() => undefined);
      return fail(`la vérification a échoué (${err instanceof Error ? err.message : String(err)})`, file.name);
    }

    // 4b. No secrets: an rsc carrying a secret is refused, never stored
    if (kind === 'rsc') {
      try {
        assertRscCarriesNoSecret(await fsp.readFile(verified.path, 'utf8'), `l’export rsc de ${facts.device.name}`);
      } catch (err) {
        await fsp.rm(verified.path, { force: true }).catch(() => undefined);
        return fail(err instanceof Error ? err.message : String(err), file.name);
      }
    }

    // 5. move it into place
    const relative = path.join(String(facts.device.tenant_id), String(facts.device.id), fileName).replace(/\\/g, '/');
    const absolute = path.join(backupRoot(), relative);
    let settled: { sha256: string; bytes: number };
    try {
      await fsp.mkdir(path.dirname(absolute), { recursive: true });
      await fsp.rename(verified.path, absolute).catch(async () => {
        await fsp.copyFile(verified.path, absolute);
        await fsp.rm(verified.path, { force: true });
      });
      settled = await hashFile(absolute);
    } catch (err) {
      await fsp.rm(absolute, { force: true }).catch(() => undefined);
      await fsp.rm(verified.path, { force: true }).catch(() => undefined);
      return fail(`le stockage a échoué (${err instanceof Error ? err.message : String(err)})`, file.name);
    }
    if (settled.sha256 !== verified.sha256 || settled.bytes !== verified.bytes) {
      await fsp.rm(absolute, { force: true }).catch(() => undefined);
      return fail('le fichier a changé entre la réception et le stockage', file.name);
    }

    // 6. erase it from the router, and prove it — before the row exists
    if (!(await this.eraseOnDevice(cli, file.name))) {
      await fsp.rm(absolute, { force: true }).catch(() => undefined);
      throw new ManagementAccessError(
        'backup_failed',
        `La sauvegarde ${KIND_LABEL[kind]} n’a pas pu être prouvée effacée du routeur (${file.name}) : refus de laisser une copie de ` +
          'la configuration du client sur l’équipement. Supprimez-la à la main. Rien n’a été écrit sur la configuration.',
      );
    }

    // 7. record it
    const classes = await retentionDays();
    const days = classes.standard;
    const [row] = (await db('device_backups')
      .insert({
        tenant_id: facts.device.tenant_id,
        device_id: facts.device.id,
        kind,
        trigger_kind: 'preflight',
        storage_path: relative,
        size_bytes: settled.bytes,
        sha256: settled.sha256,
        encryption_password_enc: password ? encrypt(password) : null,
        retention_class: 'standard',
        expires_at: days === null ? null : new Date(Date.now() + days * 86_400_000),
        status: 'available',
        taken_before_job_id: this.jobId,
        os_version: facts.device.os_version,
        verified_at: new Date(),
        created_by: this.job.requested_by ?? null,
      })
      .returning('id')) as Array<{ id: string | number } | string | number>;
    const id = typeof row === 'object' ? Number((row as { id: string | number }).id) : Number(row);
    logger.info(
      { deviceId: facts.device.id, jobId: this.jobId, backupId: id, kind, bytes: settled.bytes, road: 'sftp' },
      `${this.label}: preflight backup taken over SSH, verified and erased from the equipment`,
    );
    return { id, kind, bytes: settled.bytes };
  }
}

/** What `lint` read about the `obliwan` account (never a password). */
interface ObliwanReading {
  user: boolean;
  group: boolean;
  /** The group's policy against the bench's, when the group exists. */
  groupPolicy: ReturnType<typeof judgeObliwanGroupPolicy> | null;
  /** The group's comment when the group exists (null: not read, or nothing
   *  printed) — `OBLIWAN_ACCOUNT_COMMENT` marks a group ObliWAN made. */
  groupComment: string | null;
}

/** The `obliwan` group alone, as `in_use` reads it (the job travels with the
 *  account, so its presence is not counted): its policy and comment, each
 *  null when nothing was printed — a group that is absent and one that could
 *  not be read look the same here, and neither is aligned. */
interface ObliwanGroupReading {
  groupPolicy: ReturnType<typeof judgeObliwanGroupPolicy> | null;
  groupComment: string | null;
}

/** What `lint` decided about the `obliwan` account (header box). The
 *  plaintext lives in memory for the run only; `passwordEnc` is what the job
 *  row holds (`account_secret_enc`, migration 071) until the switch. */
type AccountPlan =
  | { action: 'in_use' }
  | {
      action: 'create';
      createGroup: boolean;
      password: string;
      passwordEnc: string;
      keyVersion: number;
      /** The password an earlier run left in the vault, not a new one. */
      reused: boolean;
      /** `ACCOUNT_WRITES`, built and judged by `assertAccountOnlyLines`. */
      lines: string[];
    }
  | {
      action: 'present';
      password: string;
      passwordEnc: string;
      keyVersion: number;
      /** Where the password that opened a session came from. */
      source: 'pending' | 'api_channel';
    };

/**
 * The newest password an earlier `management_access` job of this device left
 * in the vault for `obliwan` (071: written before the user was added, cleared
 * once the switch landed), or null. Tenant-scoped like every read of the job.
 */
async function pendingAccountSecret(
  deviceId: number,
  tenantId: number,
  exceptJobId: number,
): Promise<{ enc: string; keyVersion: number; jobId: number } | null> {
  const row = (await db('management_access_jobs')
    .where({ device_id: deviceId, tenant_id: tenantId })
    .whereNot({ job_id: exceptJobId })
    .whereNotNull('account_secret_enc')
    .orderBy('job_id', 'desc')
    .first('job_id', 'account_secret_enc', 'account_key_version')) as
    | { job_id: string | number; account_secret_enc: string; account_key_version: number }
    | undefined;
  return row ? { enc: row.account_secret_enc, keyVersion: Number(row.account_key_version), jobId: Number(row.job_id) } : null;
}

/**
 * The earlier job of this device whose API login carried the `obliwan`
 * password to a certificate that was not the expected one (071,
 * `account_secret_disclosed_at`, written by `credentialSentUnverified`), when
 * it is still the newest word on that password: the newest row that created,
 * found, staged or disclosed one. A later row that created or staged a
 * password — the account was removed and a run recreated it — supersedes the
 * disclosure. Tenant-scoped like every read of the job.
 */
async function disclosedAccountSecret(
  deviceId: number,
  tenantId: number,
  exceptJobId: number,
): Promise<{ jobId: number } | null> {
  const row = (await db('management_access_jobs')
    .where({ device_id: deviceId, tenant_id: tenantId })
    .whereNot({ job_id: exceptJobId })
    .where((q) => {
      q.whereIn('account_action', ['created', 'present'])
        .orWhereNotNull('account_secret_enc')
        .orWhereNotNull('account_secret_disclosed_at');
    })
    .orderBy('job_id', 'desc')
    .first('job_id', 'account_secret_disclosed_at')) as
    | { job_id: string | number; account_secret_disclosed_at: Date | null }
    | undefined;
  return row && row.account_secret_disclosed_at ? { jobId: Number(row.job_id) } : null;
}

/** A fingerprint as RouterOS prints it (any separators, any case) reduced
 *  to 64 lowercase hex digits, or null when it does not read as a SHA-256. */
function sha256Hex(printed: string | null | undefined): string | null {
  const hex = (printed ?? '').replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  return /^[0-9a-f]{64}$/.test(hex) ? hex : null;
}

/** A stored pin in the form `connect()` compares it (its own normaliser:
 *  separators and blanks dropped, lowercase) — a malformed pin stays
 *  malformed, so it can never match, rather than turning into "no pin". */
function normalisedPin(pin: string): string {
  return pin.replace(/[:\s]/g, '').toLowerCase();
}

export class ManagementAccessRun {
  private frozen: FrozenRow | null = null;
  private prefixes: string[] = [];
  private facts: Facts | null = null;
  private lint: Observation | null = null;
  /** The builder's lines, built and judged by the allow-list at `lint`. */
  private lines: string[] | null = null;
  /** ObliWAN's own unsigned templates `lint` found, removed in `apply`. */
  private templatesToRemove: string[] = [];
  /** What `lint` decided about the `obliwan` account (header box). */
  private account: AccountPlan | null = null;
  /** `lint` found the `obliwan` group ObliWAN made with the policy of before
   *  2026-10-05: `apply` aligns it first (header box). */
  private alignGroup = false;
  /** Who sends the alignment (header box): the job's SSH session, or the
   *  legacy session with the historical account. */
  private alignVia: 'ssh' | 'legacy' | null = null;
  /** The historical account, proven at lint, when `alignVia` is `legacy`. */
  private legacy: LegacyAligner | null = null;
  /** The group ObliWAN made lacks `sensitive` and this run does not align it
   *  (header box): the remedy the plan and the outcome carry. */
  private alignmentRemedy: string | null = null;
  /** What the job row's `observed.groupAlignment` says (aligned or not, by
   *  whom) — kept through postcheck's own `observed`. */
  private alignmentRecord: Record<string, unknown> | null = null;
  /** Set once `apply` aligned the group and read it back `same`. */
  private groupAligned = false;
  private wrote = false;
  private readonly backups: SshPreflightBackup;

  constructor(
    private readonly job: ChangeJobRow,
    private readonly device: { id: number; uuid?: string | null; name?: string | null },
    private readonly correlationId: string,
    /** The worker holding the lease, renewed while a phase runs: signing two
     *  keys on a slow router can outlast LEASE_TTL_MS. A lost lease is seen by
     *  apply.service's `assertLease` at the next phase boundary. */
    private readonly workerId?: string,
  ) {
    this.backups = new SshPreflightBackup(job, device, correlationId, MANAGEMENT_ACCESS_KIND);
  }

  private get jobId(): number {
    return Number(this.job.id);
  }

  /** Run one phase with the lease renewed every 30 s (osUpgrade's keepLease). */
  private async held<T>(fn: () => Promise<T>): Promise<T> {
    if (!this.workerId) return fn();
    const workerId = this.workerId;
    const timer = setInterval(() => {
      void renewLease(this.jobId, workerId).catch(() => undefined);
    }, 30_000);
    timer.unref?.();
    try {
      return await fn();
    } finally {
      clearInterval(timer);
    }
  }

  /** True once `inspect` found api-ssl already as this job would leave it. */
  private get apiSslNoop(): boolean {
    return this.lint !== null && this.lintNeedsNothing(this.lint);
  }

  /** True once `inspect` found NOTHING to write: api-ssl already as wanted,
   *  no `obliwan` account to create (already used, or already present
   *  with a password ObliWAN holds — its switch, if any, is a postcheck
   *  matter and writes nothing on the router), and no group to align. */
  get isNoop(): boolean {
    return this.apiSslNoop && this.account !== null && this.account.action !== 'create' && !this.alignGroup;
  }

  get noopReason(): string {
    const account = this.account?.action === 'in_use'
      ? ', et ObliWAN se connecte déjà avec son compte « obliwan »'
      : ', et le compte « obliwan » est déjà sur le routeur avec un mot de passe qu’ObliWAN détient';
    return (
      'api-ssl est déjà activé sur 8729, restreint à la plage d’administration, et sert obliwan-api (clé privée ' +
      `présente)${account} : rien ne sera écrit sur le routeur, donc aucune sauvegarde préalable n’est nécessaire.`
    );
  }

  private lintNeedsNothing(o: Observation): boolean {
    const api = o.certificates.find((c) => c.name === OBLIWAN_API_CERTIFICATE);
    return apiSslStateDifferences(o.service ? { ...o.service } : null, this.prefixes).length === 0 && Boolean(api?.ready);
  }

  private ctx(purpose: string): CliContext {
    return {
      tenantId: this.job.tenant_id,
      deviceId: this.device.id,
      deviceUuid: this.device.uuid ?? null,
      deviceName: this.device.name ?? null,
      jobId: this.jobId,
      correlationId: this.correlationId,
      purpose,
    };
  }

  private requireFacts(): Facts {
    if (!this.facts) throw new ManagementAccessError('internal', 'La tâche n’a pas été inspectée avant d’agir.');
    return this.facts;
  }

  private async observe(cli: AuditedCli, identity: ObservedIdentity & { model: string | null }, phase: Observation['phase']): Promise<Observation> {
    const service = parseService(await cli.read(SSH_READS.service));
    const certificates = parseCertificates(await cli.read(SSH_READS.certificates));
    return {
      phase,
      readAt: new Date().toISOString(),
      identity: identity.systemIdentity,
      serial: identity.serial,
      model: identity.model,
      service,
      certificates,
    };
  }

  /** `lint`: frozen range and address still hold, the SFTP road is open, and
   *  what the router carries now. Decides before any write. */
  async inspect(): Promise<ManagementAccessStepResult> {
    return this.held(() => this.inspectNow());
  }

  private async inspectNow(): Promise<ManagementAccessStepResult> {
    const frozen = (await db('management_access_jobs').where({ job_id: this.jobId }).first('*')) as FrozenRow | undefined;
    if (!frozen) {
      throw new ManagementAccessError('job_row_missing', 'La tâche n’a pas de paramètres figés (management_access_jobs) : refus.');
    }
    this.frozen = frozen;
    const frozenPrefixes = Array.isArray(frozen.mgmt_prefixes) ? (frozen.mgmt_prefixes as string[]) : [];
    this.prefixes = frozenPrefixes;

    const range = await readManagementRange();
    if (!range.ok) throw new ManagementAccessError('range_invalid', range.message);
    if (!sameSet(range.prefixes, frozenPrefixes)) {
      throw new ManagementAccessError(
        'range_changed',
        `La plage d’administration a changé depuis la mise en file (${frozenPrefixes.join(', ')} → ${range.prefixes.join(', ')}) : ` +
          'rien n’a été écrit ; relancez la tâche pour qu’elle porte la plage actuelle.',
      );
    }

    const facts = await loadFacts(this.device.id, this.job.tenant_id);
    if (!facts) throw new ManagementAccessError('device_not_found', `Équipement #${this.device.id} introuvable.`);
    this.facts = facts;
    const refusals = managementAccessDeviceRefusals(facts);
    if (refusals.length > 0) {
      throw new ManagementAccessError(refusals[0].kind, refusals.map((r) => r.message).join(' '));
    }
    const host = sshHostOf(facts);
    if (host !== frozen.ssh_host) {
      throw new ManagementAccessError(
        'ssh_moved',
        `Le canal SSH de ${facts.device.name} pointe désormais vers ${host ?? 'aucune adresse'} au lieu de ${frozen.ssh_host} : ` +
          'rien n’a été écrit ; relancez la tâche.',
      );
    }

    const cred = sshCredentialOf(facts);
    await this.backups.probeRoad(cred);

    const looked = await withProvenCli(facts, this.ctx('lint'), async (cli, identity) => {
      // The rsc backup is spelled for devices.family: checked against the box
      // here, before any file exists (driver.ts).
      await assertFamily(cli, facts);
      const account = await this.readAccountPolicy(cli, cred.username);
      // ObliWAN's own account — unless the job already travels with it.
      const obliwan: ObliwanReading | 'in_use' | 'unreadable' =
        cred.username === OBLIWAN_ACCOUNT ? 'in_use' : await this.readObliwanAccount(cli);
      // Travelling with it, the job still reads its group: the alignment
      // applies there too (header box).
      const inUseGroup = obliwan === 'in_use' ? await this.readObliwanGroup(cli) : null;
      return { observation: await this.observe(cli, identity, 'lint'), account, obliwan, inUseGroup };
    });
    const observation = looked.observation;
    this.lint = observation;
    // What was read, recorded before any refusal below (never a password).
    await patchJob(this.jobId, {
      observed: JSON.stringify({
        ...observation,
        account: { group: looked.account.group, policy: looked.account.out ? judgeAccountPolicy(looked.account.out).read : null },
        obliwan: looked.obliwan,
        ...(looked.inUseGroup ? { obliwanGroup: looked.inUseGroup } : {}),
      }),
    });

    // ── The `obliwan` account: what is to be done (header box) ─────────────
    // Decided on what was read, before any other refusal can hide it; the
    // password is resolved further down, once every refusal that needs no
    // extra session has had its say.
    let intent: 'in_use' | 'create' | 'present';
    let createGroup = false;
    // The group ObliWAN made with the policy of before 2026-10-05 is aligned
    // whatever the user's state (header box); a group that is neither
    // ObliWAN's list nor that one is refused on `create` (below), and left as
    // it is — said in the plan — on `present` and `in_use`, which never
    // judged the group.
    let alignGroup = false;
    let groupLeft: string | null = null;
    if (looked.obliwan === 'in_use') {
      intent = 'in_use';
      const g = looked.inUseGroup;
      alignGroup = obliwanGroupAlignable(g?.groupPolicy ?? null, g?.groupComment ?? null);
      if (!alignGroup && g?.groupPolicy?.state === 'different') groupLeft = obliwanGroupDifference(g.groupPolicy, g.groupComment);
    } else if (looked.obliwan === 'unreadable') {
      throw await this.accountRefusal(
        'account_unreadable',
        `La présence du compte « ${OBLIWAN_ACCOUNT} » n’a pas pu être lue sur ${facts.device.name} (la lecture de /user ` +
          'n’a rien répondu d’interprétable) : la tâche ne crée pas un compte sans savoir s’il existe déjà. Refus, rien ' +
          'n’a été écrit.',
      );
    } else if (!looked.obliwan.user) {
      intent = 'create';
      if (looked.obliwan.group) {
        const gp = looked.obliwan.groupPolicy;
        if (obliwanGroupAlignable(gp, looked.obliwan.groupComment)) alignGroup = true;
        else if (!gp || gp.state !== 'same') {
          const how = !gp || gp.state === 'unknown'
            ? `dont la politique n’a pas pu être lue${gp?.read ? ` (« ${gp.read.slice(0, 200)} »)` : ''}`
            : obliwanGroupDifference(gp, looked.obliwan.groupComment);
          throw await this.accountRefusal(
            'obliwan_group_conflict',
            `Un groupe « ${OBLIWAN_ACCOUNT} » existe déjà sur ${facts.device.name}, ${how} : ObliWAN ne modifie pas un ` +
              'groupe qu’il n’a pas créé et n’y place pas son compte. Refus, rien n’a été écrit. Retirez ou renommez ce ' +
              `groupe sur le routeur (ou alignez sa politique sur ${OBLIWAN_GROUP_POLICY}), puis relancez.`,
          );
        }
      } else createGroup = true;
    } else {
      intent = 'present';
      const gp = looked.obliwan.group ? looked.obliwan.groupPolicy : null;
      alignGroup = obliwanGroupAlignable(gp, looked.obliwan.groupComment);
      if (!alignGroup && gp?.state === 'different') groupLeft = obliwanGroupDifference(gp, looked.obliwan.groupComment);
    }
    this.alignGroup = alignGroup;

    if (!observation.service) {
      throw new ManagementAccessError(
        'no_api_ssl_service',
        `${facts.device.name} n’a pas, dans /ip service, une et une seule entrée « ${API_SSL_SERVICE} » configurée lisible ` +
          '(les connexions ouvertes, listées à part, sont écartées) : rien n’a été écrit.',
      );
    }

    // Who sends the alignment line (header box). `create`: the SSH account,
    // whose required policies already include the whole group's. `in_use`:
    // never the SSH account — it IS `obliwan`, whose group lacks `sensitive`,
    // and an account cannot grant itself a policy it lacks (REASONED). So the
    // legacy session. `present`: the SSH account when its group grants
    // `sensitive` and `policy` or does not print (the router then judges, as
    // for every policy), the legacy session when it is read lacking them.
    let alignVia: 'ssh' | 'legacy' | null = null;
    if (alignGroup) {
      alignVia = intent === 'create'
        ? 'ssh'
        : intent === 'in_use'
          ? 'legacy'
          : judgeAccountPolicy(looked.account.out ?? '', GROUP_ALIGNMENT_POLICIES).state === 'missing' ? 'legacy' : 'ssh';
    }

    // The account the job travels with must be able to do what the plan asks
    // of it — run the job's script; create `obliwan` when it is to be
    // created; log in to the API when the API rides it (`in_use`); grant
    // `sensitive` when it is the one to align the group — read now, refused
    // now, before any file exists, rather than discovered at the write or at
    // postcheck with api-ssl already open.
    const base = intent === 'in_use'
      ? [...REQUIRED_ACCOUNT_POLICIES]
      : intent === 'create' ? accountCreationPolicies() : [...SCRIPT_ACCOUNT_POLICIES];
    const required = [...new Set([...base, ...(alignVia === 'ssh' ? GROUP_ALIGNMENT_POLICIES : [])])];
    const accountPolicy = { ...judgeAccountPolicy(looked.account.out ?? '', required), group: looked.account.group };
    if (accountPolicy.state === 'missing') {
      const why = intent === 'in_use'
        ? 'La tâche utilise ce compte pour exécuter son script (read, write, policy, test) et pour l’API (api).'
        : intent === 'create'
          ? 'La tâche utilise ce compte pour exécuter son script (read, write, policy, test) et pour créer le compte ' +
            `« ${OBLIWAN_ACCOUNT} », dont le groupe reçoit ${OBLIWAN_GROUP_POLICY} : RouterOS ne laisse pas un compte ` +
            'donner des politiques que son propre groupe n’a pas (raisonné, non observé).'
          : 'La tâche utilise ce compte pour exécuter son script (read, write, policy, test).';
      const alignWhy = alignVia === 'ssh'
        ? ` Elle doit aussi aligner le groupe « ${OBLIWAN_ACCOUNT} » qu’ObliWAN a créé (commentaire ` +
          `${OBLIWAN_ACCOUNT_COMMENT}) sur ${OBLIWAN_GROUP_POLICY}, c’est-à-dire lui ajouter sensitive (décision du ` +
          '2026-10-05 : sans elle, le compte « obliwan » ne peut pas lire la sauvegarde préalable par SFTP) : RouterOS ' +
          'ne laisse pas un compte accorder une politique que son propre groupe n’a pas (raisonné, non observé), d’où ' +
          `${GROUP_ALIGNMENT_POLICIES.join(' et ')} sur le compte SSH.`
        : '';
      throw new ManagementAccessError(
        'account_policy_missing',
        `Le compte SSH « ${cred.username} » de ${facts.device.name} appartient au groupe « ${accountPolicy.group} », dont ` +
          `la politique n’accorde pas : ${accountPolicy.missing.join(', ')}. ${why}${alignWhy} Donnez ces politiques au ` +
          'groupe par le modèle de configuration du client, puis relancez. Rien n’a été écrit.',
      );
    }
    // The alignment line, built and judged by the account allow-list now,
    // while nothing exists on the router.
    if (alignGroup) assertAccountOnlyLines([ACCOUNT_WRITES.groupAlign()]);

    // ObliWAN's OWN unsigned templates (an earlier run whose signing never
    // completed) are this job's to remove — after the backup, in `apply`. A
    // certificate of our name with ONE of key and fingerprint is not a
    // template: nothing proves it ours, and it is never removed.
    const notReady = observation.certificates.filter((c) => !c.ready);
    const blocking = notReady.filter((c) => !c.unsignedTemplate);
    if (blocking.length > 0) {
      throw new ManagementAccessError(
        'certificate_conflict',
        blocking
          .map((c) =>
            `Un certificat nommé « ${c.name} » est sur le routeur avec ${c.privateKey ? 'sa clé privée mais sans empreinte' : 'une empreinte mais sans clé privée'} : ` +
            'ce n’est pas un modèle non signé laissé par ObliWAN (que la tâche retirerait), et rien ne prouve qu’il soit ' +
            'le sien. ObliWAN ne le retire pas et ne le réutilise pas.')
          .join(' ') + ' Refus, rien n’a été écrit.',
      );
    }
    this.templatesToRemove = notReady.filter((c) => c.unsignedTemplate).map((c) => c.name);

    const diffs = apiSslStateDifferences({ ...observation.service }, this.prefixes);
    const takeover = classifyEnabledApiSsl(observation.service, this.prefixes);
    if (takeover.kind === 'foreign') {
      throw new ManagementAccessError(
        'api_ssl_in_use',
        `api-ssl est activé sur ${facts.device.name} pour un usage qui n’est pas celui d’ObliWAN (${takeover.why} ; port ` +
          `${observation.service.port || '—'}, certificat « ${observation.service.certificate || '—'} », adresses ` +
          `« ${observation.service.address || 'toutes'} ») : le régler pour ObliWAN couperait cet usage, et ObliWAN ne ` +
          'coupe pas un usage qu’il n’a pas créé. Refus, rien n’a été écrit. Si cet usage n’a plus lieu d’être, ' +
          'désactivez api-ssl par le modèle de configuration du client (une poussée ObliWAN), puis relancez : un ' +
          'api-ssl désactivé est repris.',
      );
    }

    // The builder's lines are BUILT and judged by the allow-list HERE, while
    // nothing exists on the router: a builder that drifted outside
    // /certificate and api-ssl is refused before the backup, not after it.
    this.lines = this.buildLines(observation);
    assertApiSslOnlyLines([
      ...this.lines,
      ...this.templatesToRemove.map((n) => SSH_WRITES.certificateTemplateRemove(n)),
    ]);

    // The account's password, last: `present` costs a session of its own.
    this.account = await this.resolveAccount(facts, intent, createGroup);

    // The legacy session (header box), after every refusal that needs no
    // session of its own: proven now, or the alignment is not made — and the
    // job goes on without it, saying so. Never a refusal of the job, except
    // on identity (a box answering another identity is quarantined, as everywhere).
    if (alignVia === 'legacy') {
      const found = await this.resolveLegacyAligner(facts, cred);
      if ('why' in found) {
        this.alignGroup = false;
        alignVia = null;
        this.alignmentRemedy = alignmentRemedy(found.why);
        await this.recordAlignment({ state: 'not_aligned', reason: found.why });
        logger.warn(
          { jobId: this.jobId, deviceId: facts.device.id },
          'management_access: the obliwan group lacks sensitive and this run cannot align it (no usable legacy account); going on without it',
        );
      } else this.legacy = found;
    }
    this.alignVia = alignVia;

    const present = observation.certificates.filter((c) => c.ready).map((c) => c.name);
    const plan = this.account;
    const accountText =
      plan.action === 'in_use'
        ? 'déjà celui avec lequel ObliWAN se connecte, inchangé'
        : plan.action === 'present'
          ? 'déjà présent, et le mot de passe qu’ObliWAN détient pour lui ouvre une session : inchangé, ObliWAN y ' +
            'basculera une fois api-ssl prouvé'
          : `à créer${plan.createGroup
            ? ' avec son groupe'
            : this.alignGroup ? ' dans le groupe « obliwan » existant, une fois celui-ci aligné' : ' dans le groupe « obliwan » existant (même politique)'}` +
            (plan.reused ? ', avec le mot de passe qu’une tâche précédente a laissé dans le coffre' : '') +
            ', après api-ssl ; ObliWAN y basculera une fois la connexion prouvée';
    const legacyText = this.legacy
      ? ` — par une session SSH distincte, ouverte avec le compte historique « ${this.legacy.username} » (mot de passe ` +
        `« ${RECONCILE_ATTACH_VAULT_KEY} » du coffre, niveau ${this.legacy.scope}), identité vérifiée, groupe accordant ` +
        `sensitive et policy : ce compte n’envoie que cette ligne et sa relecture, et récupère par SFTP la sauvegarde ` +
        `préalable (que « ${cred.username} » ne peut pas lire sans sensitive) ; il n’est ni enregistré ni utilisé ensuite, ` +
        `ObliWAN ${plan.action === 'in_use' ? 'reste' : 'bascule'} sur « ${OBLIWAN_ACCOUNT} »`
      : '';
    const groupText = this.alignGroup
      ? `groupe ${OBLIWAN_ACCOUNT} : créé par ObliWAN (commentaire ${OBLIWAN_ACCOUNT_COMMENT}) avec sa politique d’avant le ` +
        `2026-10-05, à aligner sur ${OBLIWAN_GROUP_POLICY} (ajout de sensitive) — en premier, après la sauvegarde, puis ` +
        `relu ; rien d’autre du groupe ni du compte n’est modifié${legacyText}`
      : this.alignmentRemedy
        ? `groupe ${OBLIWAN_ACCOUNT} : ${this.alignmentRemedy}`
        : groupLeft
          ? `groupe ${OBLIWAN_ACCOUNT} : ${groupLeft} — laissé tel quel (ObliWAN n’aligne que le groupe qu’il a créé, ` +
            'auquel ne manque que sensitive)'
          : null;
    const parts = [
      `api-ssl : ${diffs.length === 0 ? 'déjà conforme' : describeDifferences(diffs)}`,
      ...(takeover.kind === 'ours' ? [`repris : ${takeover.why}`] : []),
      ...(takeover.kind === 'factory' ? ['repris : api-ssl dans sa forme d’usine (8729, sans certificat, ouvert à tous)'] : []),
      `certificats prêts : ${present.length > 0 ? present.join(', ') : 'aucun'}`,
      ...(this.templatesToRemove.length > 0
        ? [`modèle(s) non signé(s) laissé(s) par ObliWAN, retiré(s) après la sauvegarde : ${this.templatesToRemove.join(', ')}`]
        : []),
      `compte ${OBLIWAN_ACCOUNT} : ${accountText}`,
      ...(groupText ? [groupText] : []),
      `compte ${cred.username} : ${accountPolicy.state === 'granted'
        ? `groupe « ${accountPolicy.group} », politiques requises accordées`
        : 'politique non lue (la réponse du routeur en jugera)'}`,
      this.isNoop ? 'rien à écrire' : `à écrire : ${[
        ...(this.alignGroup
          ? [`sensitive au groupe ${OBLIWAN_ACCOUNT}${this.legacy ? ` (par le compte historique « ${this.legacy.username} »)` : ''}`]
          : []),
        ...(this.apiSslNoop ? [] : [
          ...[OBLIWAN_CA_CERTIFICATE, OBLIWAN_API_CERTIFICATE].filter((n) => !present.includes(n)),
          `service ${API_SSL_SERVICE}`,
        ]),
        ...(plan.action === 'create' ? [`${plan.createGroup ? 'groupe et ' : ''}utilisateur ${OBLIWAN_ACCOUNT}`] : []),
      ].join(', ')}`,
    ];
    return {
      output: parts.join(' ; '),
      detail: {
        noop: this.isNoop,
        differences: diffs.map((d) => d.field),
        certificates: present,
        templatesToRemove: this.templatesToRemove,
        takeover: takeover.kind,
        accountPolicy: accountPolicy.state,
        account: plan.action,
        accountGroupCreated: plan.action === 'create' ? plan.createGroup : false,
        accountGroupAlignment: this.alignGroup,
        accountGroupAlignmentVia: this.alignVia,
        accountGroupAlignmentSkipped: this.alignmentRemedy !== null,
        lines: this.lines.length,
      },
    };
  }

  /** Record the account refusal on the job row (the card shows it beside
   *  the account), and return the error for the caller to throw. */
  private async accountRefusal(kind: string, message: string): Promise<ManagementAccessError> {
    await patchJob(this.jobId, { account_action: 'refused', account_detail: message.slice(0, 4000) });
    return new ManagementAccessError(kind, message);
  }

  /**
   * The plan's password (header box), and what the job row records about it.
   *  - `in_use`: nothing to resolve.
   *  - `create`: the password an earlier run left in the vault, else a new
   *    one from the bench's generator; staged ENCRYPTED on this job's row
   *    now, before any write to the router (vault first: a run that dies
   *    after `/user add` landed still leaves the password it set).
   *  - `present`: the passwords ObliWAN holds for `obliwan` — an earlier run's,
   *    then its API channel's — each tried on a fresh, identity-proven SSH
   *    session as `obliwan`; the first accepted is the plan's, copied to this
   *    job's row. None held, or none accepted: refused by name, nothing
   *    written — ObliWAN never resets a password it did not set. An earlier
   *    run DISCLOSED the password (`disclosedAccountSecret`): refused by name
   *    before any candidate is tried, the account to be removed and recreated.
   */
  private async resolveAccount(
    facts: Facts,
    intent: 'in_use' | 'create' | 'present',
    createGroup: boolean,
  ): Promise<AccountPlan> {
    if (intent === 'in_use') {
      await patchJob(this.jobId, {
        account_action: 'in_use',
        account_detail: `ObliWAN se connecte déjà avec son compte « ${OBLIWAN_ACCOUNT} » : le compte n’est pas modifié.`,
      });
      return { action: 'in_use' };
    }
    const pending = await pendingAccountSecret(facts.device.id, this.job.tenant_id, this.jobId);

    if (intent === 'create') {
      let password: string;
      let passwordEnc: string;
      let keyVersion: number;
      let reused = false;
      if (pending) {
        password = decrypt(pending.enc);
        passwordEnc = pending.enc;
        keyVersion = pending.keyVersion;
        reused = true;
      } else {
        password = generateAccountPassword();
        passwordEnc = encrypt(password);
        keyVersion = currentKeyVersion();
      }
      const lines = [...(createGroup ? [ACCOUNT_WRITES.groupAdd()] : []), ACCOUNT_WRITES.userAdd(this.prefixes, password)];
      assertAccountOnlyLines(lines);
      await patchJob(this.jobId, { account_secret_enc: passwordEnc, account_key_version: keyVersion });
      return { action: 'create', createGroup, password, passwordEnc, keyVersion, reused, lines };
    }

    // A password an earlier run's API login carried to a certificate that was
    // not the expected one is DISCLOSED: it is no longer in the vault, and
    // whatever ObliWAN still holds for `obliwan` (its API channel's) is not
    // tried either — the account is refused until it is removed, so that a
    // run recreates it with a new password.
    const disclosed = await disclosedAccountSecret(facts.device.id, this.job.tenant_id, this.jobId);
    if (disclosed) {
      throw await this.accountRefusal(
        'obliwan_account_disclosed',
        `Un utilisateur « ${OBLIWAN_ACCOUNT} » existe sur ${facts.device.name}, mais le mot de passe qu’ObliWAN lui avait ` +
          `fixé a été présenté, par la tâche n° ${disclosed.jobId}, à un service API dont le certificat n’était pas celui ` +
          'attendu : il est tenu pour divulgué, a été retiré du coffre et ne sera pas réutilisé. ObliWAN ne réinitialise ' +
          'pas un mot de passe : refus, rien n’a été écrit. Retirez ce compte du routeur ; la tâche suivante le recréera ' +
          'avec un nouveau mot de passe.',
      );
    }
    const candidates: Array<{ enc: string; source: 'pending' | 'api_channel' }> = [];
    if (pending) candidates.push({ enc: pending.enc, source: 'pending' });
    if (facts.api?.username === OBLIWAN_ACCOUNT && facts.api.secret_enc) candidates.push({ enc: facts.api.secret_enc, source: 'api_channel' });
    if (candidates.length === 0) {
      throw await this.accountRefusal(
        'obliwan_account_foreign',
        `Un utilisateur « ${OBLIWAN_ACCOUNT} » existe déjà sur ${facts.device.name}, et ObliWAN n’en détient aucun mot de ` +
          'passe : ce compte n’a pas été créé par cette tâche (ou son mot de passe n’a jamais été enregistré). ObliWAN ' +
          'ne réinitialise pas un mot de passe qu’il n’a pas fixé. Refus, rien n’a été écrit. Si ce compte est bien ' +
          `celui d’ObliWAN et que vous connaissez son mot de passe, enregistrez « ${OBLIWAN_ACCOUNT} » et ce mot de passe ` +
          'dans le canal SSH de l’équipement (onglet Paramètres) ; sinon retirez-le du routeur ; puis relancez.',
      );
    }
    const refused: string[] = [];
    for (const c of candidates) {
      let password: string;
      try {
        password = decrypt(c.enc);
      } catch {
        refused.push(c.source === 'pending' ? 'celui d’une tâche précédente (illisible dans le coffre)' : 'celui du canal API (illisible dans le coffre)');
        continue;
      }
      try {
        await withProvenCli(facts, this.ctx('lint'), async () => undefined, { username: OBLIWAN_ACCOUNT, password });
      } catch (err) {
        if (err instanceof ManagementAccessError && err.kind === 'ssh_failed' && err.driverCode === 'AUTH_FAILED') {
          refused.push(c.source === 'pending' ? 'celui qu’une tâche précédente a fixé' : 'celui du canal API');
          continue;
        }
        throw err;
      }
      const passwordEnc = c.source === 'pending' ? c.enc : encrypt(password);
      const keyVersion = c.source === 'pending' && pending ? pending.keyVersion : currentKeyVersion();
      await patchJob(this.jobId, {
        account_action: 'present',
        account_detail:
          `Le compte « ${OBLIWAN_ACCOUNT} » était déjà sur le routeur, et le mot de passe qu’ObliWAN détient pour lui ` +
          `(${c.source === 'pending' ? 'fixé par une tâche précédente' : 'celui de son canal API'}) a ouvert une session : ` +
          'le compte n’est pas modifié.',
        account_secret_enc: passwordEnc,
        account_key_version: keyVersion,
      });
      return { action: 'present', password, passwordEnc, keyVersion, source: c.source };
    }
    throw await this.accountRefusal(
      'obliwan_account_unusable',
      `Un utilisateur « ${OBLIWAN_ACCOUNT} » existe sur ${facts.device.name}, mais le mot de passe qu’ObliWAN détient ` +
        `pour lui (${refused.join(' ; ')}) a été refusé à la connexion SSH : il a été changé sur le routeur, ou l’adresse ` +
        'source d’ObliWAN n’est pas dans la liste « address » du compte. ObliWAN ne réinitialise pas un mot de passe : ' +
        'refus, rien n’a été écrit. Retirez ce compte du routeur (la tâche le recréera), ou enregistrez son mot de passe ' +
        'actuel dans le canal SSH de l’équipement, puis relancez.',
    );
  }

  /** The builder's lines for this router, through the dependency seam. */
  private buildLines(observation: Observation): string[] {
    try {
      return deps.buildLines({
        identity: certificateCommonName(observation.identity),
        mgmtPrefixes: this.prefixes,
        logPrefix: logPrefixFor(this.jobId),
      });
    } catch (err) {
      if (err instanceof ManagementAccessInputError) {
        throw new ManagementAccessError('range_invalid', `Paramètres refusés par le générateur (${err.field}) : rien n’a été écrit.`);
      }
      throw err;
    }
  }

  /** The SSH account's group and that group's policy output, as read
   *  (`SSH_ACCOUNT_READS`); judged once the account plan says what is needed.
   *  `out` null = not read (an unsafe name, no group printed): UNKNOWN. */
  private async readAccountPolicy(cli: AuditedCli, username: string): Promise<{ group: string | null; out: string | null }> {
    const groupRead = SSH_ACCOUNT_READS.group(username);
    if (!groupRead) return { group: null, out: null };
    const group = parseAccountGroup(await cli.read(groupRead));
    const policyRead = group ? SSH_ACCOUNT_READS.policy(group) : null;
    if (!group || !policyRead) return { group, out: null };
    return { group, out: await cli.read(policyRead) };
  }

  /** The `obliwan` user and group as counts, and the group's policy and
   *  comment when it exists. `unreadable`: the counts did not come back as two
   *  integers. */
  private async readObliwanAccount(cli: AuditedCli): Promise<ObliwanReading | 'unreadable'> {
    const presence = parseObliwanPresence(await cli.read(SSH_ACCOUNT_READS.obliwanPresence));
    if (!presence) return 'unreadable';
    if (!presence.group) return { ...presence, groupPolicy: null, groupComment: null };
    return { ...presence, ...(await this.readObliwanGroup(cli)) };
  }

  /** The `obliwan` group's policy (judged against ObliWAN's) and comment. */
  private async readObliwanGroup(cli: AuditedCli): Promise<ObliwanGroupReading> {
    const groupPolicy = judgeObliwanGroupPolicy(await cli.read(SSH_ACCOUNT_READS.policy(OBLIWAN_ACCOUNT) as string));
    const groupComment = parseObliwanGroupComment(await cli.read(SSH_ACCOUNT_READS.obliwanGroupComment));
    return { groupPolicy, groupComment };
  }

  /**
   * The legacy session, proven at lint (header box): the historical account
   * and its vault password for THIS device — its site when the site is its
   * tenant's, else its tenant, global, instance levels; never another site's
   * or tenant's — on a fresh SSH session whose identity is proven like
   * every session of the job (a mismatch quarantines and throws), whose
   * group must grant `sensitive` and `policy`, and whose SFTP road must be
   * open (it pulls the preflight backup). Anything short of that returns the
   * reason, said in French, never the password: the alignment is then not
   * made, and the job is not failed for it.
   */
  private async resolveLegacyAligner(facts: Facts, cred: SshCredential): Promise<LegacyAligner | { why: string }> {
    const username = RECONCILE_ATTACH_DEFAULT_USERNAME;
    const key = RECONCILE_ATTACH_VAULT_KEY;
    if (username === cred.username) {
      return {
        why: `le compte historique « ${username} » est déjà le compte SSH de la tâche, et son groupe n’accorde pas sensitive et policy`,
      };
    }
    const site = await deviceSiteInTenant(facts.device.id, facts.device.tenant_id);
    let found: { value: string; scope: LegacyVariableScope } | null;
    try {
      found = await resolveLegacyVariable(key, facts.device.tenant_id, site);
    } catch {
      return { why: `« ${key} » n’a pas pu être déchiffré dans le coffre` };
    }
    if (!found) {
      return {
        why: `aucun mot de passe « ${key} » n’est renseigné pour ce routeur (ni sur ${site === null ? 'son site — il n’en a pas —' : 'son site'}, ni pour le client, ni pour l’instance)`,
      };
    }
    if (CONTROL_CHARS.test(found.value)) {
      return { why: `« ${key} » (niveau ${found.scope}) contient un caractère de contrôle` };
    }
    const password = found.value;
    const scope = found.scope;
    let reading: ReturnType<typeof judgeAccountPolicy> & { group: string | null };
    try {
      reading = await withProvenCli(facts, this.ctx('lint:legacy'), async (cli) => {
        const read = await this.readAccountPolicy(cli, username);
        return { ...judgeAccountPolicy(read.out ?? '', GROUP_ALIGNMENT_POLICIES), group: read.group };
      }, { username, password });
    } catch (err) {
      if (err instanceof ManagementAccessError && err.kind === 'ssh_failed') {
        return {
          why: err.driverCode === 'AUTH_FAILED'
            ? `le compte historique « ${username} » a été refusé à la connexion SSH avec le mot de passe « ${key} » du coffre ` +
              `(niveau ${scope})`
            : `la session SSH avec le compte historique « ${username} » a échoué (${scrub(err.message, [password]).slice(0, 200)})`,
        };
      }
      throw err;
    }
    if (reading.state !== 'granted') {
      return {
        why: reading.state === 'missing'
          ? `le groupe « ${reading.group ?? '—'} » du compte historique « ${username} » n’accorde pas : ${reading.missing.join(', ')}`
          : `la politique du groupe du compte historique « ${username} » n’a pas pu être lue`,
      };
    }
    try {
      await this.backups.probeRoad({ ...cred, username, password });
    } catch (err) {
      if (err instanceof ManagementAccessError && err.kind === 'no_backup_road') {
        return { why: `le sous-système SFTP ne sert pas le compte historique « ${username} », qui doit récupérer la sauvegarde préalable` };
      }
      throw err;
    }
    logger.info(
      { jobId: this.jobId, deviceId: facts.device.id, account: username, scope },
      'management_access: the legacy account will align the obliwan group (separate session; never stored)',
    );
    return { username, password, scope };
  }

  /** `observed.groupAlignment` on the job row (header box), merged into what
   *  is there — and kept by postcheck, which rewrites `observed`. */
  private async recordAlignment(record: Record<string, unknown>): Promise<void> {
    this.alignmentRecord = { ...record, at: new Date().toISOString() };
    await db('management_access_jobs')
      .where({ job_id: this.jobId })
      .update({
        observed: db.raw("coalesce(observed, '{}'::jsonb) || ?::jsonb", [JSON.stringify({ groupAlignment: this.alignmentRecord })]),
        updated_at: db.fn.now(),
      });
  }

  /**
   * The alignment (header box), on the apply session, FIRST: the one
   * allow-listed `/user group set`, then the policy read back on the same
   * session — `same`, or the job fails naming what it read. Recorded on the
   * job row beside the account's sentence. Nothing else of the group or of
   * any user is written.
   */
  private async alignObliwanGroup(
    cli: AuditedCli,
    facts: Facts,
    /** The account sending the line: the SSH account, or the legacy one. */
    sender: { username: string; via: 'ssh' | 'legacy' },
  ): Promise<{ output: string; detail: Record<string, unknown> }> {
    const line = ACCOUNT_WRITES.groupAlign();
    assertAccountOnlyLines([line]);
    const after = ' api-ssl n’a pas été modifié, aucun compte n’a été ajouté ni basculé : ObliWAN continue d’utiliser son ' +
      'accès actuel. La sauvegarde préalable est conservée.';
    try {
      await cli.write(line);
    } catch (err) {
      if (err instanceof ManagementAccessError && err.kind === 'router_refused') {
        throw new ManagementAccessError(
          'obliwan_group_align_failed',
          `Le routeur a refusé d’ajouter sensitive au groupe « ${OBLIWAN_ACCOUNT} » (${err.message}) ; le compte ` +
            `« ${sender.username} » qui l’envoie doit lui-même avoir sensitive et policy (raisonné, non observé).` + after,
        );
      }
      throw err;
    }
    const back = judgeObliwanGroupPolicy(await cli.read(SSH_ACCOUNT_READS.policy(OBLIWAN_ACCOUNT) as string));
    if (back.state !== 'same') {
      const read = back.state === 'unknown'
        ? `illisible${back.read ? ` (« ${back.read.slice(0, 200)} »)` : ''}`
        : [
          ...(back.extra.length > 0 ? [`en plus : ${back.extra.join(', ')}`] : []),
          ...(back.missing.length > 0 ? [`manquent : ${back.missing.join(', ')}`] : []),
        ].join(' ; ');
      throw new ManagementAccessError(
        'obliwan_group_align_failed',
        `Le routeur a accepté l’alignement du groupe « ${OBLIWAN_ACCOUNT} » sur ${OBLIWAN_GROUP_POLICY}, mais la relecture ` +
          `ne donne pas cette politique (${read}) : le groupe a peut-être changé de commentaire depuis l’inspection, ou le ` +
          'routeur n’a pas appliqué la commande.' + after,
      );
    }
    this.groupAligned = true;
    const sentence =
      `Groupe « ${OBLIWAN_ACCOUNT} » (créé par ObliWAN) aligné sur ${OBLIWAN_GROUP_POLICY} : sensitive ajouté, relu` +
      (sender.via === 'legacy'
        ? ` (envoyé par le compte historique « ${sender.username} », sur une session distincte qui n’a rien écrit d’autre)`
        : '') + '.';
    // Recorded on the job row whatever the plan (header box): in `observed`
    // at once — the create path has no account sentence yet, and 071 forbids
    // one without its action — and in the account's sentence when there is
    // one (`present`, `in_use`); `create` writes its own after the user,
    // which carries it too, and a refusal after this point is told it.
    await this.recordAlignment({ state: 'aligned', via: sender.via, account: sender.username, readBack: back.read });
    const row = (await db('management_access_jobs').where({ job_id: this.jobId }).first('account_detail')) as
      | { account_detail: string | null }
      | undefined;
    if (row?.account_detail) await patchJob(this.jobId, { account_detail: `${row.account_detail} ${sentence}`.slice(0, 4000) });
    logger.info(
      { jobId: this.jobId, deviceId: facts.device.id, via: sender.via, account: sender.username },
      'management_access: the obliwan group ObliWAN made was aligned (sensitive added) and read back',
    );
    return { output: sentence, detail: { groupAligned: true, groupAlignedVia: sender.via } };
  }

  /**
   * The alignment over the legacy session (header box): a fresh SSH session
   * as the historical account, identity proven; the group re-read there
   * before any write — still ObliWAN's, still lacking only `sensitive`, or
   * `account_changed` with nothing written; then `markWritten` (the job's
   * first write), the one line and its read-back. A session that cannot be
   * opened BEFORE the line is sent does not fail the job: the alignment is
   * dropped, said as the remedy, and null is returned. Once the line may have
   * left, any failure is the job's.
   */
  private async alignOverLegacy(
    facts: Facts,
    markWritten: () => Promise<void>,
  ): Promise<{ output: string; detail: Record<string, unknown> } | null> {
    const legacy = this.legacy;
    if (!legacy) throw new ManagementAccessError('internal', 'Le compte historique n’a pas été vérifié à l’inspection : refus d’écrire.');
    let sent = false;
    try {
      return await withProvenCli(facts, this.ctx('apply:legacy'), async (lcli) => {
        const now = await this.readObliwanGroup(lcli);
        if (!obliwanGroupAlignable(now.groupPolicy, now.groupComment)) {
          throw new ManagementAccessError(
            'account_changed',
            `Le groupe « ${OBLIWAN_ACCOUNT} » n’est plus sur le routeur tel que l’inspection l’a lu (politique ou ` +
              'commentaire modifié, ou groupe retiré depuis) : refus, rien n’a été écrit. Relancez : la tâche relit le routeur.',
          );
        }
        sent = true;
        await markWritten();
        return this.alignObliwanGroup(lcli, facts, { username: legacy.username, via: 'legacy' });
      }, { username: legacy.username, password: legacy.password });
    } catch (err) {
      if (!sent && err instanceof ManagementAccessError && err.kind === 'ssh_failed') {
        const why = err.driverCode === 'AUTH_FAILED'
          ? `le compte historique « ${legacy.username} », accepté à l’inspection, a été refusé au moment d’écrire`
          : `la session SSH avec le compte historique « ${legacy.username} » a échoué au moment d’écrire ` +
            `(${scrub(err.message, [legacy.password]).slice(0, 200)})`;
        this.alignGroup = false;
        this.alignmentRemedy = alignmentRemedy(why);
        await this.recordAlignment({ state: 'not_aligned', reason: why });
        logger.warn(
          { jobId: this.jobId, deviceId: facts.device.id },
          'management_access: the legacy session failed before the alignment was sent; going on without it',
        );
        return null;
      }
      throw err;
    }
  }

  /** Binary + rsc, saved on the router, pulled by SFTP, proven, stored,
   *  erased from the router, recorded. Returns the binary's backup id. */
  async backup(): Promise<{ backupId: number; output: string; detail: Record<string, unknown> }> {
    return this.held(() => this.backupNow());
  }

  private async backupNow(): Promise<{ backupId: number; output: string; detail: Record<string, unknown> }> {
    const facts = this.requireFacts();
    const cred = sshCredentialOf(facts);
    // When the group is to be aligned over the legacy account, the WHOLE
    // backup — save, measure, SFTP pull, erase — rides that account: the
    // account without `sensitive` can neither read the `.backup` (job 28)
    // nor erase it (job 29, 2026-10-05: pulled as admin, then "could not be
    // proven erased" on the obliwan session). Otherwise the job's own session.
    const legacy = this.alignGroup && this.alignVia === 'legacy' ? this.legacy : null;
    const pull: SshCredential = legacy ? { ...cred, username: legacy.username, password: legacy.password } : cred;
    const stored = await withProvenCli(facts, this.ctx('backup'), async (cli) => {
      if (legacy) cli.protect(legacy.password);
      await assertFamily(cli, facts);
      const out: Array<{ id: number; kind: BackupKind; bytes: number }> = [];
      for (const kind of ['binary', 'rsc'] as BackupKind[]) {
        out.push(await this.backups.backupOne(cli, pull, facts, kind));
      }
      return out;
    }, legacy ? { username: legacy.username, password: legacy.password } : undefined);
    const binary = stored.find((s) => s.kind === 'binary');
    if (!binary) throw new ManagementAccessError('backup_failed', 'Le routeur n’a produit aucune sauvegarde binaire : refus.');
    await patchJob(this.jobId, { backup_id: binary.id });
    return {
      backupId: binary.id,
      output:
        `sauvegarde préalable #${binary.id} stockée (${stored.map((s) => `${s.kind} ${s.bytes} o`).join(', ')}), ` +
        `${legacy ? `prise, récupérée par SFTP et effacée avec le compte historique « ${legacy.username} »` : 'récupérée par SFTP et effacée du routeur'}`,
      detail: { backupIds: stored.map((s) => s.id), road: 'sftp', pulledAs: pull.username },
    };
  }

  /** The write: the builder's lines as one `/system script`, run once,
   *  removed — unless api-ssl was already as wanted; then the `obliwan`
   *  account when the plan is `create`. */
  async apply(onWrite: () => void): Promise<ManagementAccessStepResult> {
    return this.held(() => this.applyNow(onWrite));
  }

  private async applyNow(onWrite: () => void): Promise<ManagementAccessStepResult> {
    const facts = this.requireFacts();
    const lint = this.lint;
    if (!lint) throw new ManagementAccessError('internal', 'La tâche n’a pas été inspectée avant d’écrire.');
    const plan = this.account;
    if (!plan) throw new ManagementAccessError('internal', 'La tâche n’a pas décidé du compte « obliwan » à l’inspection : refus d’écrire.');
    const backupRow = (await db('management_access_jobs').where({ job_id: this.jobId }).first('backup_id', 'account_secret_enc')) as
      | { backup_id: string | number | null; account_secret_enc: string | null }
      | undefined;
    if (!backupRow || backupRow.backup_id === null) {
      throw new ManagementAccessError('backup_missing', 'Aucune sauvegarde préalable n’est enregistrée pour cette tâche : refus d’écrire.');
    }
    // Vault first: the password the account is about to receive must already
    // be on this job's row (staged at lint) before the router holds it.
    if (plan.action === 'create' && backupRow.account_secret_enc !== plan.passwordEnc) {
      throw new ManagementAccessError('internal', 'Le mot de passe du compte « obliwan » n’est pas dans le coffre : refus d’écrire.');
    }

    // Built and judged at lint, before any file existed; judged again here,
    // with the template removals, on the exact text about to leave.
    const writeApiSsl = !this.apiSslNoop;
    const lines = this.lines;
    if (!lines) throw new ManagementAccessError('internal', 'La tâche n’a pas construit ses lignes à l’inspection : refus d’écrire.');
    assertApiSslOnlyLines(lines);
    const accountLines = plan.action === 'create' ? plan.lines : [];
    assertAccountOnlyLines([...(this.alignGroup ? [ACCOUNT_WRITES.groupAlign()] : []), ...accountLines]);
    if (!writeApiSsl && accountLines.length === 0 && !this.alignGroup) {
      throw new ManagementAccessError('internal', 'Rien à écrire : l’étape aurait dû être sautée.');
    }
    const source = scriptSourceFor(lines);
    const name = scriptNameFor(this.jobId);
    const addCommand = SSH_WRITES.scriptAdd(name, source);

    try {
      return await this.applyOnSession(facts, plan, onWrite, { writeApiSsl, lines, name, addCommand });
    } catch (err) {
      // A refusal after the group was aligned says so (header box): the
      // alignment stays on the router whatever failed after it.
      if (this.groupAligned && err instanceof ManagementAccessError && err.kind !== 'obliwan_group_align_failed') {
        throw new ManagementAccessError(
          err.kind,
          `${err.message} Le groupe « ${OBLIWAN_ACCOUNT} » a, lui, été aligné sur ${OBLIWAN_GROUP_POLICY} (sensitive ` +
            'ajouté, relu) avant cet échec : ce changement reste en place.',
          err.httpStatus,
          err.driverCode,
        );
      }
      throw err;
    }
  }

  private async applyOnSession(
    facts: Facts,
    plan: AccountPlan,
    onWrite: () => void,
    built: { writeApiSsl: boolean; lines: string[]; name: string; addCommand: string },
  ): Promise<ManagementAccessStepResult> {
    const { writeApiSsl, lines, name, addCommand } = built;
    const viaLegacy = this.alignGroup && this.alignVia === 'legacy';
    return withProvenCli(facts, this.ctx('apply'), async (cli) => {
      if (plan.action === 'create') cli.protect(plan.password);
      // The account is re-read on THIS session, before any write: a user or a
      // group of that name that appeared since lint is not this run's to
      // create over — refused, nothing written.
      // The group to align is re-read the same way: still ObliWAN's, still
      // lacking only `sensitive` — or nothing is written (on the legacy
      // session, by `alignOverLegacy`, before its own write).
      if (plan.action === 'create') {
        const now = await this.readObliwanAccount(cli);
        const groupAsLint = now !== 'unreadable' && now.group && (this.alignGroup
          ? obliwanGroupAlignable(now.groupPolicy, now.groupComment)
          : now.groupPolicy?.state === 'same');
        const changed = now === 'unreadable' || now.user || (plan.createGroup ? now.group : !groupAsLint);
        if (changed) {
          throw new ManagementAccessError(
            'account_changed',
            `Le compte « ${OBLIWAN_ACCOUNT} » n’est plus sur le routeur tel que l’inspection l’a lu (utilisateur ou groupe ` +
              'apparu, retiré ou modifié depuis) : refus, rien n’a été écrit. Relancez : la tâche relit le routeur.',
          );
        }
      } else if (this.alignGroup && !viaLegacy) {
        const now = await this.readObliwanGroup(cli);
        if (!obliwanGroupAlignable(now.groupPolicy, now.groupComment)) {
          throw new ManagementAccessError(
            'account_changed',
            `Le groupe « ${OBLIWAN_ACCOUNT} » n’est plus sur le routeur tel que l’inspection l’a lu (politique ou ` +
              'commentaire modifié, ou groupe retiré depuis) : refus, rien n’a été écrit. Relancez : la tâche relit le routeur.',
          );
        }
      }

      // The templates to remove are re-read on THIS session: only a name that
      // is still an unsigned template now is removed (a signing that finished
      // since lint made it a certificate, which the builder then reuses).
      const removeNow = !writeApiSsl || this.templatesToRemove.length === 0
        ? []
        : parseCertificates(await cli.read(SSH_READS.certificates))
          .filter((c) => c.unsignedTemplate && this.templatesToRemove.includes(c.name))
          .map((c) => c.name);
      const removals = removeNow.map((n) => SSH_WRITES.certificateTemplateRemove(n));
      assertApiSslOnlyLines(removals);

      // The first byte that changes the router: recorded first (058's CHECK
      // needs the backup id already there), then the leftover cleanup.
      const markWritten = async (): Promise<void> => {
        if (this.wrote) return;
        await db('management_access_jobs').where({ job_id: this.jobId }).whereNull('wrote_at')
          .update({ wrote_at: db.fn.now(), updated_at: db.fn.now() });
        this.wrote = true;
        onWrite();
      };
      // The group FIRST: before api-ssl, before the user is added into it, and
      // before any login as `obliwan` (postcheck) relies on what it grants.
      // Over the legacy session when the SSH account cannot grant it (header
      // box) — which may drop it, saying so, when that session no longer opens.
      let aligned: { output: string; detail: Record<string, unknown> } | null = null;
      if (viaLegacy) aligned = await this.alignOverLegacy(facts, markWritten);
      else {
        await markWritten();
        if (this.alignGroup) aligned = await this.alignObliwanGroup(cli, facts, { username: facts.ssh?.username ?? '—', via: 'ssh' });
      }
      if (!writeApiSsl) {
        const account = plan.action === 'create' ? await this.createAccount(cli, facts, plan) : null;
        if (!aligned && !account) {
          // Only the alignment was to be written, and the legacy session that
          // was to send it no longer opens: nothing was written at all.
          if (this.alignmentRemedy && !this.wrote) {
            return {
              output: `rien n’a été écrit : ${this.alignmentRemedy}`,
              detail: { marker: 'skipped', lines: 0, scriptRemoved: true, templatesRemoved: [], groupAligned: false, account: plan.action },
            };
          }
          throw new ManagementAccessError('internal', 'Rien à écrire : l’étape aurait dû être sautée.');
        }
        return {
          output: ['api-ssl déjà conforme : aucun script envoyé', ...(aligned ? [aligned.output] : []), ...(account ? [account.output] : [])]
            .join(' ; '),
          detail: {
            marker: 'skipped', lines: 0, scriptRemoved: true, templatesRemoved: [],
            ...(aligned ? aligned.detail : {}),
            ...(account ? account.detail : { account: plan.action }),
          },
        };
      }
      await markWritten();
      for (const [i, removal] of removals.entries()) {
        try {
          await cli.write(removal);
        } catch (err) {
          throw new ManagementAccessError(
            'apply_failed',
            `Le modèle non signé « ${removeNow[i]} » laissé par ObliWAN n’a pas pu être retiré ` +
              `(${err instanceof Error ? err.message : String(err)}) : api-ssl n’a pas été modifié. La sauvegarde préalable est conservée.`,
          );
        }
      }
      try {
        await cli.write(SSH_WRITES.scriptRemoveLeftovers());
        await cli.write(addCommand);
      } catch (err) {
        if (err instanceof ManagementAccessError && err.kind === 'router_refused') {
          throw new ManagementAccessError(
            'apply_failed',
            `Le script n’a pas pu être déposé sur le routeur (${err.message}) : api-ssl n’a pas été modifié. ` +
              'La sauvegarde préalable est conservée.',
          );
        }
        throw err;
      }
      const run = await cli.exec(SSH_WRITES.scriptRun(name), {
        isWrite: true,
        timeoutMs: (2 * CERTIFICATE_SIGN_WAIT_SECONDS + 90) * 1000,
      });
      const printed = `${run.stdout}\n${run.stderr}`;
      let removedNote = '';
      try {
        await cli.write(SSH_WRITES.scriptRemove(name));
      } catch {
        removedNote = ` Le script ${name} n’a pas pu être retiré du routeur (il ne contient aucun secret) : la prochaine tâche ` +
          'd’accès de gestion sur ce routeur le retirera avant d’écrire.';
      }
      if (printed.includes(SCRIPT_MARK_FAILED)) {
        const reason = parseScriptReason(await cli.read(SSH_WRITES.logRead(logPrefixFor(this.jobId))));
        throw new ManagementAccessError('apply_failed', `${scriptReasonMessage(reason)}${removedNote}`);
      }
      const marked = printed.includes(SCRIPT_MARK_OK);
      // After api-ssl, and only once it is in place: an account created
      // beside an api-ssl that failed would be an account nothing can use yet.
      const account = plan.action === 'create' ? await this.createAccount(cli, facts, plan) : null;
      return {
        output:
          (aligned ? `${aligned.output} ; ` : '') +
          (removeNow.length > 0 ? `modèle(s) non signé(s) d’ObliWAN retiré(s) : ${removeNow.join(', ')} ; ` : '') +
          (marked
            ? `script ${name} exécuté jusqu’au bout (certificats prêts, api-ssl réglé) et retiré`
            : `script ${name} exécuté sans imprimer de marqueur : la relecture décide`) + removedNote +
          (account ? ` ; ${account.output}` : ''),
        detail: {
          marker: marked ? 'ok' : 'none',
          lines: lines.length,
          scriptRemoved: removedNote === '',
          templatesRemoved: removeNow,
          ...(aligned ? aligned.detail : {}),
          ...(account ? account.detail : { account: plan.action }),
        },
      };
    });
  }

  /**
   * The account writes, on the apply session (`ACCOUNT_WRITES`): the group
   * when absent, then the user — each its own command, judged again by
   * `assertAccountOnlyLines` on the exact text, the password protected on
   * the audited line and scrubbed from any error. Then read back on the same
   * session: the user must be there, in group `obliwan`. Recorded on the job
   * row as `created`; the switch is postcheck's.
   */
  private async createAccount(
    cli: AuditedCli,
    facts: Facts,
    plan: Extract<AccountPlan, { action: 'create' }>,
  ): Promise<{ output: string; detail: Record<string, unknown> }> {
    assertAccountOnlyLines(plan.lines);
    cli.protect(plan.password);
    for (const line of plan.lines) {
      const isGroup = line.startsWith('/user group add');
      try {
        await cli.write(line);
      } catch (err) {
        if (err instanceof ManagementAccessError && err.kind === 'router_refused') {
          throw new ManagementAccessError(
            'account_failed',
            isGroup
              ? `Le groupe « ${OBLIWAN_ACCOUNT} » n’a pas pu être créé (${err.message}) : aucun compte n’a été ajouté. ` +
                'ObliWAN continue d’utiliser son accès actuel. La sauvegarde préalable est conservée.'
              : `L’utilisateur « ${OBLIWAN_ACCOUNT} » n’a pas pu être créé (${err.message})` +
                (plan.createGroup ? ` ; le groupe « ${OBLIWAN_ACCOUNT} » créé par cette tâche reste en place, la prochaine la réutilisera` : '') +
                '. ObliWAN continue d’utiliser son accès actuel. La sauvegarde préalable est conservée.',
          );
        }
        throw err;
      }
    }
    const now = await this.readObliwanAccount(cli);
    const groupRead = SSH_ACCOUNT_READS.group(OBLIWAN_ACCOUNT) as string;
    const inGroup = parseAccountGroup(await cli.read(groupRead));
    if (now === 'unreadable' || !now.user || inGroup !== OBLIWAN_ACCOUNT) {
      throw new ManagementAccessError(
        'account_failed',
        `Le routeur a accepté la création du compte « ${OBLIWAN_ACCOUNT} », mais la relecture ne le trouve pas dans le ` +
          `groupe « ${OBLIWAN_ACCOUNT} » (groupe lu : « ${inGroup ?? '—'} ») : ObliWAN n’y bascule pas et continue ` +
          'd’utiliser son accès actuel. La sauvegarde préalable est conservée.',
      );
    }
    const detail =
      `Compte « ${OBLIWAN_ACCOUNT} » créé${plan.createGroup
        ? ' avec son groupe'
        : this.groupAligned
          ? ` dans le groupe « obliwan » existant, créé par ObliWAN et d’abord aligné sur ${OBLIWAN_GROUP_POLICY} (sensitive ajouté)`
          : ' dans le groupe « obliwan » existant (même politique)'}, ` +
      `restreint à ${this.prefixes.join(', ')}` +
      (plan.reused ? ', avec le mot de passe qu’une tâche précédente avait laissé dans le coffre' : '') + '.';
    await patchJob(this.jobId, { account_action: 'created', account_detail: detail });
    logger.info(
      { jobId: this.jobId, deviceId: facts.device.id, groupCreated: plan.createGroup, reused: plan.reused },
      'management_access: the obliwan account was created on the router (not used until proven)',
    );
    return {
      output: `${detail} ObliWAN n’y bascule qu’après une connexion prouvée (relecture)`,
      detail: { account: 'created', accountGroupCreated: plan.createGroup, accountPasswordReused: plan.reused },
    };
  }

  /** `postcheck`: api-ssl read back over a NEW SSH session, then ONE API
   *  identity read over TLS on 8729 — as `obliwan` when the account is to be
   *  switched to, with a fresh SSH login as `obliwan` too — then the
   *  transports written: the API's with its pin, and for a switch the SSH
   *  one moved to `obliwan` in the same transaction. */
  async verify(): Promise<ManagementAccessStepResult> {
    return this.held(() => this.verifyNow());
  }

  /** For a failure after the account was created or found, before the
   *  switch: what the operator must know about it. */
  private accountNote(cred: SshCredential): string {
    const plan = this.account;
    if (!plan || plan.action === 'in_use') return '';
    return (
      ` Le compte « ${OBLIWAN_ACCOUNT} » ${plan.action === 'create' ? 'a été créé' : 'est sur le routeur'} mais n’est pas ` +
      `utilisé : ObliWAN continue d’utiliser « ${cred.username} ». Son mot de passe reste dans le coffre ; relancez la ` +
      'tâche, elle le réutilisera (aucun second mot de passe n’est créé).'
    );
  }

  private async verifyNow(): Promise<ManagementAccessStepResult> {
    const facts = this.requireFacts();
    const lint = this.lint;
    const plan = this.account;
    if (!plan) throw new ManagementAccessError('internal', 'La tâche n’a pas décidé du compte « obliwan » à l’inspection.');
    const observation = await withProvenCli(facts, this.ctx('postcheck'), (cli, identity) => this.observe(cli, identity, 'verify'));
    const apiCert = observation.certificates.find((c) => c.name === OBLIWAN_API_CERTIFICATE);
    await patchJob(this.jobId, {
      // What lint and apply recorded about the group alignment stays (header box).
      observed: JSON.stringify({ ...observation, ...(this.alignmentRecord ? { groupAlignment: this.alignmentRecord } : {}) }),
      certificate_fingerprint: apiCert?.fingerprint ? apiCert.fingerprint.slice(0, 128) : null,
    });
    const diffs = apiSslStateDifferences(observation.service ? { ...observation.service } : null, this.prefixes);
    if (diffs.length > 0 || !apiCert?.ready) {
      const certNote = apiCert?.ready ? '' : ` ; certificat ${OBLIWAN_API_CERTIFICATE} ${apiCert ? 'sans clé privée ou sans empreinte' : 'absent'}`;
      throw new ManagementAccessError(
        'readback_failed',
        `Relecture : api-ssl n’est pas dans l’état attendu (${describeDifferences(diffs) || 'service conforme'}${certNote}). ` +
          (this.wrote ? 'La sauvegarde préalable est conservée.' : 'Rien n’a été écrit.'),
      );
    }

    // ── The API, over TLS, on a socket that did not exist a moment ago ─────
    // As `obliwan` when the plan switches to it (`create`, `present`): that
    // login IS the API half of the account's proof. Otherwise with the SSH
    // credential, which then already is `obliwan` (`in_use`).
    const cred = sshCredentialOf(facts);
    const switching = plan.action === 'create' || plan.action === 'present';
    const login = switching
      ? { username: OBLIWAN_ACCOUNT, password: plan.password }
      : { username: cred.username, password: cred.password };
    const note = this.accountNote(cred);
    const api = facts.api;
    const sameRow =
      api !== null &&
      api.enabled &&
      api.use_tls &&
      api.port === API_SSL_PORT &&
      (api.host ?? '') === cred.host &&
      Boolean(api.tls_fingerprint_sha256);
    // A pin is kept unless this run made the server certificate: lint saw no
    // ready `obliwan-api`, so the key the old pin described is gone.
    const lintApiReady = Boolean(lint?.certificates.find((c) => c.name === OBLIWAN_API_CERTIFICATE)?.ready);
    const pin = sameRow && lintApiReady ? normalisedPin((api as ApiRow).tls_fingerprint_sha256 as string) : null;

    // ── What the TLS handshake must show, decided BEFORE any credential
    // leaves ObliWAN. The second witness of the certificate is the
    // fingerprint the router prints for `obliwan-api` over SSH — read just
    // above on a fresh session, a channel the TLS session does not share.
    // When it reads as a SHA-256 (64 hex digits) it is the dial's EXPECTED
    // fingerprint: `connect()` (transport/routeros/connection.ts) compares the
    // certificate at the handshake and refuses BEFORE `/login`, so a
    // certificate on 8729 that the router does not declare never receives the
    // password — for a switch, the `obliwan` password this job (or an earlier
    // run) has set on the router. Comparing the two once the session had
    // opened, as this step first did, compared too late: the login had
    // already carried the password to whatever answered, and the next run
    // would have reused it. A print in any other shape is not comparable (that
    // RouterOS prints the SHA-256 of the DER, as the TLS side computes it, is
    // REASONED): the dial then expects the pin when one holds, else it is
    // trust-on-first-use — the credential goes to the first certificate that
    // answers, by design, and the outcome says the pin rests on that alone. A
    // pin and a comparable print that differ are refused before any dial: the
    // router itself declares a certificate ObliWAN did not pin.
    const sshPrinted = sha256Hex(apiCert.fingerprint);
    if (pin !== null && sshPrinted !== null && pin !== sshPrinted) {
      await patchJob(this.jobId, { api_checked_at: db.fn.now() });
      throw new ManagementAccessError(
        'api_fingerprint_changed',
        `${facts.device.name} déclare en SSH servir sur ${API_SSL_PORT} un certificat ${OBLIWAN_API_CERTIFICATE} (empreinte ` +
          `${sshPrinted.slice(0, 16)}…) qui n’est pas celui qu’ObliWAN a épinglé (${pin.slice(0, 16)}…) : refus avant toute ` +
          'connexion API, aucun identifiant n’a été envoyé. Rien n’a été ré-épinglé, le canal API est inchangé.' +
          (this.wrote ? ' La sauvegarde préalable est conservée.' : '') + note,
      );
    }
    const expected = pin ?? sshPrinted;
    /** Where `expected` comes from; null = trust-on-first-use. */
    const expectedFrom: 'pin' | 'ssh_print' | null = pin !== null ? 'pin' : sshPrinted !== null ? 'ssh_print' : null;

    let seen: string | null = null;
    let conn: RouterOsConnection | null = null;
    let observedApi: ObservedIdentity | null = null;
    // A session that OPENED on a certificate other than the expected one: the
    // handshake did not refuse it, so `/login` has already carried the
    // credential there. `connect()` makes this unreachable; it is still
    // checked here, because the cost — a password handed to an unverified
    // endpoint, then reused and switched to — must not rest on one module's
    // behaviour behind a dependency seam.
    let presentedAfterLogin: string | null = null;
    try {
      conn = await deps.openApi({
        host: cred.host,
        port: API_SSL_PORT,
        tls: true,
        username: login.username,
        password: login.password,
        expectedFingerprint: expected,
        onFingerprint: (fp) => {
          seen = fp;
        },
        connectTimeoutMs: 15_000,
        requestTimeoutMs: 15_000,
        label: `management_access:${facts.device.name}`,
      });
      // What the handshake showed: the TOFU callback's value, or — when a
      // fingerprint was expected and held — the connection's own record of it.
      seen = conn.fingerprint ?? seen;
      const presented = (seen ?? '').toLowerCase();
      if (expected !== null && presented !== expected) presentedAfterLogin = presented;
      else observedApi = await readRouterOsIdentity(conn, facts.device.ppp_username);
    } catch (err) {
      const raw = scrub(err instanceof Error ? err.message : String(err), [cred.password, login.password]).slice(0, 300);
      await patchJob(this.jobId, { api_checked_at: db.fn.now() });
      if (err instanceof RouterOsFingerprintError) {
        // Refused at the handshake: nothing was sent, so a staged `obliwan`
        // password stays reusable (`note`).
        if (expectedFrom === 'ssh_print') {
          logger.error(
            { jobId: this.jobId, deviceId: facts.device.id },
            'management_access: the TLS certificate on 8729 is not the one RouterOS prints over SSH — refused before login, nothing pinned',
          );
          throw new ManagementAccessError(
            'api_fingerprint_disagrees',
            `Le certificat que ${facts.device.name} présente en TLS sur ${API_SSL_PORT} (empreinte ` +
              `${String(err.actual).slice(0, 16)}…) n’est pas celui que le routeur déclare servir en SSH ` +
              `(${OBLIWAN_API_CERTIFICATE}, empreinte ${(sshPrinted as string).slice(0, 16)}…) : ce peut être une interception, ` +
              'ou un autre service sur ce port. Refusé à la poignée de main TLS, avant tout envoi d’identifiant : ' +
              `« ${login.username} » et son mot de passe n’ont pas été présentés à ce service. Rien n’a été épinglé, le ` +
              'canal API est inchangé.' + (this.wrote ? ' La sauvegarde préalable est conservée.' : '') + note,
          );
        }
        throw new ManagementAccessError(
          'api_fingerprint_changed',
          `Le certificat servi par ${facts.device.name} sur ${API_SSL_PORT} n’a pas l’empreinte qu’ObliWAN a épinglée : refus ` +
            `à la poignée de main TLS, avant tout envoi d’identifiant (ce peut être une interception). Rien n’a été ` +
            `ré-épinglé, le canal API est inchangé.${note}`,
        );
      }
      if (err instanceof RouterOsAuthError) {
        if (switching) {
          throw new ManagementAccessError(
            'account_proof_failed',
            `api-ssl répond, mais le routeur refuse la connexion du compte « ${OBLIWAN_ACCOUNT} » sur l’API (l’adresse ` +
              'source qu’il voit est peut-être hors de la liste « address » du compte, c’est-à-dire de la plage ' +
              `d’administration). Le canal API n’a pas été enregistré, le canal SSH est inchangé.${note}`,
          );
        }
        throw new ManagementAccessError(
          'api_login_refused',
          `api-ssl répond, mais le routeur refuse l’identifiant du canal SSH (« ${cred.username} ») sur l’API : le groupe ` +
            'de ce compte n’a peut-être pas la politique « api ». Le canal API n’a pas été enregistré.',
        );
      }
      throw new ManagementAccessError(
        'api_unreachable',
        `api-ssl est en place sur le routeur, mais ObliWAN n’a pas pu s’y connecter (${raw}). Vérifiez que la plage ` +
          'd’administration couvre l’adresse source que voit le routeur (l’adresse L2TP du concentrateur). Le canal API ' +
          `n’a pas été enregistré.${note}`,
      );
    } finally {
      conn?.close();
    }
    if (presentedAfterLogin !== null) {
      await patchJob(this.jobId, { api_checked_at: db.fn.now() });
      throw await this.credentialSentUnverified(facts, cred, login.username, switching, {
        presented: presentedAfterLogin,
        expected: expected as string,
        from: expectedFrom as 'pin' | 'ssh_print',
      });
    }
    if (observedApi === null) {
      throw new ManagementAccessError('internal', 'La connexion API-SSL n’a rendu aucune lecture d’identité.');
    }
    const fingerprint = (seen ?? '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(fingerprint)) {
      throw new ManagementAccessError(
        'api_fingerprint_unknown',
        `La connexion API-SSL a abouti sans qu’ObliWAN puisse lire l’empreinte du certificat : rien n’a été épinglé.${note}`,
      );
    }
    const cmp = await compareWithRecord(facts.device, observedApi);
    if (!cmp.ok || (!observedApi.systemIdentity && !observedApi.serial && !observedApi.pppUsername)) {
      await patchJob(this.jobId, { api_checked_at: db.fn.now() });
      // A PROVEN mismatch on the API is the identity signal the SSH sessions treat
      // the same way: the device is quarantined. An API that proved nothing
      // is refused without one.
      if (cmp.mismatched > 0) await quarantineDevice(facts.device.id, cmp.reason, cmp.checks, 'postcheck_api');
      throw new ManagementAccessError(
        'api_identity_mismatch',
        cmp.mismatched > 0
          ? `La connexion API-SSL a répondu avec une autre identité que celle de la fiche (${cmp.reason}) : rien n’a été ` +
            `épinglé, le canal API est inchangé, l’équipement est mis en quarantaine.${note}`
          : `La connexion API-SSL n’a corroboré aucun attribut d’identité de la fiche (${cmp.reason}) : rien n’a été épinglé.${note}`,
      );
    }
    // The handshake held the SSH print whenever it was comparable (above),
    // so here the two agree by construction; null = not comparable.
    const agrees = sshPrinted === null ? null : sshPrinted === fingerprint;

    // ── The SSH half of the account's proof: a fresh login as `obliwan`,
    // identity proven on it (`withProvenCli`), before anything is switched.
    if (switching) {
      try {
        await withProvenCli(facts, this.ctx('postcheck'), async () => undefined, login);
      } catch (err) {
        if (err instanceof ManagementAccessError && err.kind === 'ssh_failed') {
          await patchJob(this.jobId, { api_checked_at: db.fn.now() });
          throw new ManagementAccessError(
            'account_proof_failed',
            `api-ssl accepte le compte « ${OBLIWAN_ACCOUNT} », mais la connexion SSH avec lui a échoué ` +
              `(${err.message.slice(0, 300)}). Rien n’a été basculé : le canal API n’a pas été enregistré, le canal SSH ` +
              `est inchangé.${note}`,
          );
        }
        throw err;
      }
    }

    const action = await this.writeTransport(facts, cred, fingerprint, switching ? login : null);
    const outcome: ManagementAccessOutcome = this.wrote ? 'enabled' : 'present';
    const detailText =
      // `enabled` = this job wrote; the script itself ran only when api-ssl
      // was not already as wanted (a run may write the account or the group
      // alone).
      (outcome === 'enabled' && !this.apiSslNoop ? 'api-ssl ouvert' : 'api-ssl était déjà en place') +
      ` sur ${API_SSL_PORT}, restreint à ${this.prefixes.join(', ')}, certificat ${OBLIWAN_API_CERTIFICATE} ; ` +
      `canal API ${action === 'created' ? 'créé' : action === 'updated' ? 'mis à jour' : 'inchangé'}, empreinte épinglée ` +
      `${fingerprint.slice(0, 16)}…` +
      (agrees === true
        ? ' (identique à celle que le routeur imprime en SSH, vérifiée à la poignée de main TLS, avant tout envoi d’identifiant)'
        : expectedFrom === 'pin'
          ? ' (l’épingle existante, vérifiée à la poignée de main TLS ; l’empreinte imprimée en SSH n’a pas un format comparable)'
          : ' (l’empreinte imprimée en SSH n’a pas un format comparable : épinglée au premier contact seulement, l’identifiant ' +
            'présenté à ce premier contact)') +
      (switching
        ? ` ; ObliWAN utilise désormais son compte « ${OBLIWAN_ACCOUNT} » en API et en SSH (connexion prouvée sur les ` +
          `deux), « ${cred.username} » n’est plus utilisé`
        : ` ; ObliWAN se connecte avec « ${login.username} »`) +
      (this.groupAligned
        ? ` ; groupe « ${OBLIWAN_ACCOUNT} » aligné sur ${OBLIWAN_GROUP_POLICY} (sensitive ajouté)` +
          (this.alignVia === 'legacy' && this.legacy
            ? ` par le compte historique « ${this.legacy.username} », sur une session distincte — ObliWAN ne l’utilise pas`
            : '')
        : '') +
      (this.alignmentRemedy ? ` ; ${this.alignmentRemedy}` : '');
    await patchJob(this.jobId, {
      outcome,
      outcome_detail: detailText,
      transport_action: action,
      pinned_fingerprint: fingerprint,
      api_checked_at: db.fn.now(),
    });
    return {
      output: detailText,
      detail: {
        outcome,
        transportAction: action,
        fingerprintAgrees: agrees,
        identityMatched: cmp.matched,
        account: plan.action,
        switched: switching,
        groupAligned: this.groupAligned,
      },
    };
  }

  /**
   * An API session OPENED on 8729 on a certificate other than the expected
   * one (the router's SSH print, or the pin): the handshake did not refuse
   * it, so `/login` has already carried `username`'s password to that
   * endpoint (see `verifyNow`). For a switch that password is the `obliwan`
   * one this job — or an earlier run — set on the router and staged in the
   * vault: it is DISCLOSED, not merely unproven. It is erased from every job
   * row of the device and the disclosure stamped on this one (071,
   * `account_secret_disclosed_at`), in one transaction, so the next run
   * refuses the account by name (`obliwan_account_disclosed`) and asks for it
   * to be removed — a run then recreates it with a NEW password — instead of
   * reusing this one and switching both channels to it. Outside a switch the
   * password is the SSH channel's: the job says so and changes nothing (it
   * never sets a password). Nothing pinned, no transport written. Returns the
   * error for the caller to throw.
   */
  private async credentialSentUnverified(
    facts: Facts,
    cred: SshCredential,
    username: string,
    switching: boolean,
    seen: { presented: string; expected: string; from: 'pin' | 'ssh_print' },
  ): Promise<ManagementAccessError> {
    logger.error(
      { jobId: this.jobId, deviceId: facts.device.id, expectedFrom: seen.from, switching },
      'management_access: an API session opened on a certificate other than the expected one — the credential was sent, nothing pinned',
    );
    const kind = seen.from === 'pin' ? 'api_fingerprint_changed' : 'api_fingerprint_disagrees';
    const expectedText = seen.from === 'pin'
      ? `celui qu’ObliWAN a épinglé (${seen.expected.slice(0, 16)}…)`
      : `celui que le routeur déclare servir en SSH (${OBLIWAN_API_CERTIFICATE}, empreinte ${seen.expected.slice(0, 16)}…)`;
    const head =
      `Une session API s’est ouverte sur ${API_SSL_PORT} avec un certificat (empreinte ` +
      `${seen.presented ? `${seen.presented.slice(0, 16)}…` : 'illisible'}) qui n’est pas ${expectedText} : la poignée de ` +
      `main ne l’a pas refusé, et la connexion a donc présenté l’identifiant « ${username} » et son mot de passe à ce ` +
      'service, qui peut être une interception. Rien n’a été épinglé, le canal API est inchangé.' +
      (this.wrote ? ' La sauvegarde préalable est conservée.' : '');
    const plan = this.account;
    if (!switching || !plan || plan.action === 'in_use') {
      return new ManagementAccessError(
        kind,
        `${head} Tenez ce mot de passe pour divulgué : changez-le sur le routeur, puis enregistrez le nouveau dans le ` +
          'canal SSH de l’équipement (onglet Paramètres).',
      );
    }
    const detail =
      `Le mot de passe du compte « ${OBLIWAN_ACCOUNT} » a été présenté à un service API dont le certificat n’est pas ` +
      'celui attendu : il est tenu pour divulgué, retiré du coffre, et ne sera pas réutilisé. Retirez ce compte du ' +
      'routeur ; la tâche suivante le recréera avec un nouveau mot de passe.';
    await db.transaction(async (trx) => {
      await trx('management_access_jobs')
        .where({ device_id: facts.device.id, tenant_id: this.job.tenant_id })
        .whereNotNull('account_secret_enc')
        .update({ account_secret_enc: null, account_key_version: null, updated_at: trx.fn.now() });
      await trx('management_access_jobs')
        .where({ job_id: this.jobId })
        .update({ account_secret_disclosed_at: trx.fn.now(), account_detail: detail, updated_at: trx.fn.now() });
    });
    return new ManagementAccessError(
      kind,
      `${head} Le compte « ${OBLIWAN_ACCOUNT} » ${plan.action === 'create' ? 'a été créé' : 'est sur le routeur'} mais ` +
        `n’est pas utilisé : ObliWAN continue d’utiliser « ${cred.username} ». ${detail}`,
    );
  }

  /** The device's routeros_api transport: 8729, TLS, the fingerprint the
   *  first contact saw, and the credential just proven on it — the SSH
   *  credential's ciphertext copied, or, for a switch (`account`), the
   *  `obliwan` password freshly encrypted. A switch ALSO moves the `ssh`
   *  transport to `obliwan` (a key ObliWAN held for the previous account and
   *  a pending rotation candidate minted for it are dropped: neither belongs
   *  to `obliwan`), stamps `account_switched_at` and clears the staged
   *  password from every job row of the device — the transports hold it now.
   *  One transaction: the two channels never disagree on the account. */
  private async writeTransport(
    facts: Facts,
    cred: SshCredential,
    fingerprint: string,
    account: { username: string; password: string } | null,
  ): Promise<ManagementAccessTransportAction> {
    const ssh = facts.ssh as SshRow;
    const keyVersion = currentKeyVersion();
    const apiSecretEnc = account ? encrypt(account.password) : ssh.secret_enc;
    const apiKeyVersion = account ? keyVersion : ssh.key_version ?? 1;
    return db.transaction(async (trx) => {
      if (account) {
        const moved = await trx('device_transports')
          .where({ device_id: facts.device.id, transport: 'ssh' })
          .update({
            username: account.username,
            secret_enc: encrypt(account.password),
            key_version: keyVersion,
            private_key_enc: null,
            secret_next_enc: null,
            secret_next_key_version: null,
            secret_next_at: null,
            updated_at: trx.fn.now(),
          });
        if (moved !== 1) throw new ManagementAccessError('internal', 'Le canal SSH de l’équipement a disparu pendant la tâche : rien n’a été basculé.');
        await trx('management_access_jobs')
          .where({ device_id: facts.device.id, tenant_id: this.job.tenant_id })
          .whereNotNull('account_secret_enc')
          .update({ account_secret_enc: null, account_key_version: null, updated_at: trx.fn.now() });
        await trx('management_access_jobs').where({ job_id: this.jobId })
          .update({ account_switched_at: trx.fn.now(), updated_at: trx.fn.now() });
      }
      const current = (await trx('device_transports')
        .where({ device_id: facts.device.id, transport: 'routeros_api' })
        .forUpdate()
        .first('id', 'host', 'port', 'use_tls', 'tls_fingerprint_sha256', 'enabled', 'username', 'secret_enc')) as
        | (ApiRow & { id: number })
        | undefined;
      const columns = {
        enabled: true,
        host: cred.host,
        port: API_SSL_PORT,
        username: account ? account.username : ssh.username,
        secret_enc: apiSecretEnc,
        key_version: apiKeyVersion,
        private_key_enc: null,
        use_tls: true,
        tls_fingerprint_sha256: fingerprint,
        secret_next_enc: null,
        secret_next_key_version: null,
        secret_next_at: null,
        last_ok_at: trx.fn.now(),
        last_error: null,
        updated_at: trx.fn.now(),
      };
      if (!current) {
        await trx('device_transports').insert({
          device_id: facts.device.id,
          transport: 'routeros_api',
          params: JSON.stringify({}),
          ...columns,
        });
        return 'created';
      }
      let sameSecret = false;
      try {
        const wantUser = account ? account.username : ssh.username;
        const wantPassword = account ? account.password : ssh.secret_enc !== null ? decrypt(ssh.secret_enc) : null;
        sameSecret =
          current.username === wantUser &&
          current.secret_enc !== null &&
          wantPassword !== null &&
          decrypt(current.secret_enc) === wantPassword;
      } catch {
        sameSecret = false;
      }
      const unchanged =
        sameSecret &&
        current.enabled &&
        current.use_tls &&
        current.port === API_SSL_PORT &&
        current.host === cred.host &&
        current.tls_fingerprint_sha256 === fingerprint;
      if (unchanged) {
        await trx('device_transports').where({ id: current.id }).update({
          last_ok_at: trx.fn.now(),
          last_error: null,
          updated_at: trx.fn.now(),
        });
        return 'unchanged';
      }
      await trx('device_transports').where({ id: current.id }).update(columns);
      return 'updated';
    });
  }
}
