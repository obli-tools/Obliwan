/**
 * ObliWAN — renaming ONE site's router, by a change job (kind `site_rename`,
 * migration 088; the lines, the alphabets and the allow-list are
 * shared/src/siteRename.ts).
 *
 * ┌─ WHAT CHANGES, TOGETHER ──────────────────────────────────────────────────┐
 * │ A store is known to the fleet by its PPP login on the shared CHR (the     │
 * │ /ppp/secret it authenticates with, and the user of the router's          │
 * │ management tunnel, the l2tp-client named l2tp-mgmt), by the router's      │
 * │ /system identity, and by the device row that records both. Renaming      │
 * │ one of them by hand cuts the tunnel or quarantines the router: the CHR    │
 * │ refuses the new login, or the next identity check reads a proven          │
 * │ mismatch. This job changes all of them, in an order that never leaves the │
 * │ router without an account to dial, and the site code with them when asked │
 * │ (the code is locked once an allocation rendered the login from it —       │
 * │ site.service `siteCodeLockReasons`; this job is the operation that        │
 * │ re-renders them coherently). The first use is lowercasing customer C's    │
 * │ logins and identities (`StoreName` -> `storename`) before the identity    │
 * │ checks of their attach.                                                   │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE ORDER, AND THE NET UNDER EACH STEP ──────────────────────────────────┐
 * │ 1. CHR: a SECOND secret under the new name, copied from the old one       │
 * │    (`/ppp/secret/add copy-from=<.id> name=<to>`): same password — which   │
 * │    ObliWAN never reads (an adopted 'per_site' allocation does not         │
 * │    even hold it) —, same address, same profile. The old secret stays.     │
 * │    A CASE-ONLY rename the CHR refuses as a duplicate is done IN PLACE     │
 * │    (`set name=`) instead (operator decision 2026-10-07): then there is no │
 * │    old account to fall back on, and ObliWAN itself renames the secret     │
 * │    back when the router's new session is not up by the self-revert's     │
 * │    decision — the CHR is always reachable from ObliWAN.                   │
 * │ 2. Router: a self-revert started with `:execute` (no scheduler: many      │
 * │    Chateaux run device-mode home): after 120 s, if the management client │
 * │    is not running and still dials the new login, it puts the old one      │
 * │    back. Its job id must then be seen LISTED from a NEW identity-proven   │
 * │    session within 30 s of its start — its outliving the session that     │
 * │    started it is observed on each router, never assumed (legacy_          │
 * │    compliance's rule).                                                    │
 * │ 3. Device row: `ppp_username` switched to the new login JUST BEFORE the  │
 * │    cut (T1), so presence (pppPresence, which matches sessions by exact    │
 * │    login on the concentrator) attributes the new session to the device.  │
 * │    Switched back if the router reverts.                                   │
 * │ 4. The cut, LAST and alone: `set user=<to>` on the management client. It │
 * │    restarts the tunnel the job's session rides: its silence is expected. │
 * │ 5. The wait: the new session on the CHR, past the self-revert's decision │
 * │    (so what is read next is final), then a fresh proven session reads   │
 * │    the new user running, and the identity is set if asked.               │
 * │ 6. Postcheck on a fresh session; then the device row, the allocation,    │
 * │    the site code, the CHR inventory and the audit in ONE transaction;     │
 * │    then the OLD secret removed — only once the new session is up, the    │
 * │    old one inactive, and its .id and address re-read unchanged.           │
 * │ A router that never comes back within the bound leaves the job           │
 * │ `unsettled`: both secrets kept, the device row at the job's best guess,  │
 * │ and the identity check widened to exactly that device's frozen pair      │
 * │ (fleet/identityAlternates.ts) so no identity check quarantines it. The   │
 * │ card's « Relancer » re-enqueues the same pair: every stage is idempotent │
 * │ and a re-run settles what is left.                                       │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * THE JOB, STEP BY STEP (a branch of `runPhases()` in apply.service.ts, on the
 * ROUTER's device row; the per-device lock and the subtree interlock apply):
 *   bind_assert       identity binding over SSH (`assertMikrotikBindingOverSsh`), with the
 *                     rename's alternates.
 *   guard             ACCEPT by construction (`siteRenameGuard`).
 *   lint              the frozen row, the device's refusals, both kill
 *                     switches, the CHR proven on a fresh socket (never
 *                     quarantined: it is shared), the CHR read by filtered
 *                     queries with no password in the proplist, the router
 *                     read on a proven session, the plan. Nothing to do ->
 *                     `present`, nothing written.
 *   preflight_backup  by SFTP, only when a router line is planned.
 *   arm_deadman       SKIPPED (SITE_RENAME_NO_DEADMAN).
 *   apply             1, 2, 3, 4 above; or the identity line alone.
 *   reconnect         5 (SKIPPED when no cut left).
 *   postcheck         the read-back on fresh sessions (router and CHR).
 *   cleanup           6.
 *
 * WHAT IS NOT OBSERVED: no line of this file has reached a router or the CHR.
 * The RouterOS behaviours relied on are listed in shared/src/siteRename.ts;
 * each failure of one lands in a named outcome. testing/siteRename.verify.ts
 * runs the job against a fake CHR (RouterOS API) and a fake MikroTik (SSH)
 * answering by the same assumptions.
 *
 * Operator-facing sentences are French, like the other SSH jobs'.
 */

import {
  MANAGEMENT_TUNNEL_NAME,
  SITE_RENAME_GUARD_MARGIN_S,
  SITE_RENAME_GUARD_MAX_LEAD_S,
  SITE_RENAME_KIND,
  SITE_RENAME_REVERT_AFTER_S,
  SITE_RENAME_TUNNEL_WAIT_S,
  SOCKET_EVENTS,
  SiteRenameInputError,
  SiteRenameLineRefused,
  assertSiteRenameOnlyLines,
  isActiveJobStatus,
  isCaseOnlyChange,
  isRenameIdentity,
  isRenameLogin,
  lowercaseRename,
  parseSiteRenameGuardLog,
  siteRenameCutLine,
  siteRenameGuardLogPrefix,
  siteRenameIdentityLine,
  siteRenameSelfRevertLine,
  type ChangeJobStatus,
  type SiteRenameBulkLaunchRow,
  type SiteRenameBulkPreviewRow,
  type SiteRenameChrMode,
  type SiteRenameGuardVerdict,
  type SiteRenameNames,
  type SiteRenameOutcome,
  type SiteRenameTransform,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { auditedCommand, type CommandIntent } from '../audit.service';
import { appendAudit } from '../attestation/auditLog.service';
import { emitToDevice } from '../fleet/fleetEvents';
import { emitToTenantAudience } from '../fleet/scopedEmit';
import { getRouterOsPool, resolveRouterOsTarget } from '../fleet/routerosPool';
import {
  parseActiveRow,
  parseSecretRow,
  recordSecretInventoryChange,
  type PppSecretEntry,
} from '../fleet/concentratorDiscovery.service';
import { assertTargetBinding, BindingAssertionError } from '../fleet/deviceBinding.service';
import { recordIdentityObservation } from '../fleet/identityWatch.service';
import { assertSiteCodeFormat } from '../fleet/siteCodeFormat';
import { renameAllocationNames, takeAllocationLock } from '../allocation';
import type { RouterOsConnection } from '../transport/routeros';
import {
  CMD_OK,
  ManagementAccessError,
  SshPreflightBackup,
  activeJobOf,
  assertFamily,
  loadFacts,
  sshCredentialOf,
  sshHostOf,
  withProvenCli,
  type AuditedCli,
  type CliContext,
  type Facts,
  type Refusal,
} from './managementAccess.service';
import { LEGACY_SSH_READS, parseGuardJobAlive, parseGuardJobId } from './legacyCompliance.service';
import { hostAddress } from './concentratorSecret.service';
import { isNonPublicAddress } from './transfer.service';
import { KillSwitchEngagedError, assertWritable, readKillSwitch } from './killSwitch.service';
import { DeviceBusyError, renewLease, type ChangeJobRow } from './jobQueue.service';

// ============================================================================
// Vocabulary
// ============================================================================

export class SiteRenameError extends Error {
  constructor(readonly kind: string, message: string, readonly httpStatus = 409) {
    super(message);
    this.name = 'SiteRenameError';
  }
}

export const SITE_RENAME_NO_DEADMAN =
  "Aucun dead-man n'est armé sur le routeur pour 'site_rename' : beaucoup de Chateau sont en device-mode « home », " +
  'où le planificateur est bloqué. La seule ligne qui coupe le chemin de gestion (le user du l2tp-mgmt) part en ' +
  'dernier, derrière un retour arrière lancé sur le routeur avec :execute et vu vivant depuis une nouvelle session ; ' +
  'le CHR garde l’ancien compte tant que la nouvelle session n’est pas montée. La sauvegarde préalable est prise ' +
  'avant la première ligne envoyée au routeur ; la tâche est mise en file au niveau de sécurité degraded, avec la ' +
  'confirmation explicite de l’opérateur.';

export const SITE_RENAME_NO_APPLY_OUTCOME =
  "No row written to apply_outcomes: 'site_rename' renames the management login and identity behind a self-revert; " +
  'it is not an observation of how this hardware survives a change. Its outcome is on site_rename_jobs.';

export function siteRenameGuard(): { verdict: 'ACCEPT'; reasons: unknown[]; summary: string; unavailable: false } {
  return {
    verdict: 'ACCEPT',
    reasons: [
      {
        code: 'SITE_RENAME_GUARDED',
        effect: 'accept',
        message:
          'Renames the management login on the CHR (a second secret copied from the old one, the old one removed only ' +
          'once the new session is up; a case-only rename the CHR refuses is renamed in place and renamed back by ' +
          'ObliWAN if the new session does not come up), the user of the management l2tp-client (last, behind a ' +
          'self-revert seen alive from a new session) and the /system identity. Any other line is refused before ' +
          'anything is sent.',
      },
    ],
    summary:
      'Management-Path Guard: ACCEPT — the one line that restarts the management tunnel leaves last, behind a ' +
      'self-revert on the router and the old account kept on the CHR (no plan was simulated: the job refuses any other line).',
    unavailable: false,
  };
}

export function siteRenameSafetyNet(): {
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
      "DEGRADED — aucun dead-man n'est armé ; la ligne qui redémarre le tunnel de gestion part en dernier, derrière un " +
      'retour arrière lancé sur le routeur, et l’ancien compte reste sur le CHR tant que la nouvelle session n’est pas ' +
      'montée. La sauvegarde préalable, récupérée par SFTP, précède toute ligne envoyée au routeur. La règle de sécurité exige une ' +
      'confirmation explicite et tracée.',
    unverified: false,
    requiresConfirmation: true,
  };
}

// ============================================================================
// Dependencies (test seams)
// ============================================================================

export interface SiteRenameDeps {
  /** Milliseconds; the tunnel wait is measured on it. */
  now(): number;
  sleep(ms: number): Promise<void>;
  /** Between two looks at the PPP sessions. */
  pollMs: number;
  /** The cut line's own budget: its session is expected to drop. */
  cutTimeoutMs: number;
  /** Between the end of the session that started the self-revert and the
   *  look at its job from a new one. */
  guardSettleMs: number;
  /** Frozen on each job at enqueue. */
  revertAfterS: number;
  tunnelWaitS: number;
}
const DEFAULT_DEPS: SiteRenameDeps = {
  now: () => Date.now(),
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  pollMs: 5_000,
  cutTimeoutMs: 15_000,
  guardSettleMs: 3_000,
  revertAfterS: SITE_RENAME_REVERT_AFTER_S,
  tunnelWaitS: SITE_RENAME_TUNNEL_WAIT_S,
};
let deps: SiteRenameDeps = { ...DEFAULT_DEPS };
export function setSiteRenameDeps(next: Partial<SiteRenameDeps>): SiteRenameDeps {
  deps = { ...deps, ...next };
  return deps;
}
export function resetSiteRenameDeps(): void {
  deps = { ...DEFAULT_DEPS };
}

// ============================================================================
// The router reads (console) and their parsers
// ============================================================================

/** One command per read. The client read is bracketed: a read that stopped
 *  part-way prints no `end` marker and is UNREAD, never a short list. */
export const SITE_RENAME_SSH_READS = {
  identity: ':put ("identity|" . [/system identity get name])',
  clients:
    ':put "rnclients|begin"; :foreach i in=[/interface l2tp-client find] do={ :put ("rnclient|" . ' +
    '[/interface l2tp-client get $i name] . "|" . [:tostr [/interface l2tp-client get $i running]] . "|" . ' +
    '[:tostr [/interface l2tp-client get $i disabled]] . "|" . [/interface l2tp-client get $i user]) }; :put "rnclients|end"',
  /** The self-revert's decision, by its log prefix (digits and fixed text). */
  guardLog: (jobId: number): string =>
    `:foreach l in=[/log find where message~"${siteRenameGuardLogPrefix(jobId)}"] do={ :put ("log|" . [/log get $l message]) }`,
} as const;

export interface RenameClientReading {
  name: string;
  running: boolean;
  disabled: boolean;
  user: string;
}

export interface RenameRouterReading {
  identity: string | null;
  /** Every l2tp-client; null when the read did not complete. */
  clients: RenameClientReading[] | null;
  /** The management client, by the rule `managementClientOf` applies. */
  client: RenameClientReading | null;
}

function outLines(out: string): string[] {
  return out.split(/\r?\n/).map((l) => l.replace(/\r$/, '').trim());
}

export function parseRenameClients(out: string): RenameClientReading[] | null {
  const ls = outLines(out);
  if (!ls.includes('rnclients|end')) return null;
  const yes = (v: string | undefined) => ['true', 'yes'].includes((v ?? '').trim().toLowerCase());
  return ls.filter((l) => l.startsWith('rnclient|')).map((l) => {
    const p = l.slice('rnclient|'.length).split('|');
    return { name: (p[0] ?? '').trim(), running: yes(p[1]), disabled: yes(p[2]), user: p.slice(3).join('|').trim() };
  });
}

export function parseRenameIdentity(out: string): string | null {
  const row = outLines(out).find((l) => l.startsWith('identity|'));
  if (!row) return null;
  const v = row.slice('identity|'.length).trim();
  return v === '' ? null : v;
}

/**
 * The management client: the one frozen by name on an earlier read; else the
 * one named l2tp-mgmt; else the ONE client dialling the old or the new login
 * (case-folded) — shared/src/managementTunnel.ts's rule, with both names of
 * the pair. Anything else is no reading.
 */
export function managementClientOf(
  clients: readonly RenameClientReading[] | null,
  frozenName: string | null,
  from: string,
  to: string,
): RenameClientReading | null {
  if (!clients) return null;
  if (frozenName) {
    const m = clients.filter((c) => c.name === frozenName);
    return m.length === 1 ? m[0] : null;
  }
  const named = clients.filter((c) => c.name === MANAGEMENT_TUNNEL_NAME);
  if (named.length === 1) return named[0];
  if (named.length > 1) return null;
  const want = [from.toLowerCase(), to.toLowerCase()];
  const carrying = clients.filter((c) => want.includes(c.user.toLowerCase()));
  return carrying.length === 1 ? carrying[0] : null;
}

async function readRouter(cli: AuditedCli, frozenName: string | null, from: string, to: string): Promise<RenameRouterReading> {
  const identity = parseRenameIdentity(await cli.read(SITE_RENAME_SSH_READS.identity));
  const clients = parseRenameClients(await cli.read(SITE_RENAME_SSH_READS.clients));
  return { identity, clients, client: managementClientOf(clients, frozenName, from, to) };
}

// ============================================================================
// The CHR reads (RouterOS API) and the plan
// ============================================================================

const SECRET_PROPLIST = '=.proplist=.id,name,service,profile,remote-address,local-address,comment,disabled';
const ACTIVE_PROPLIST = '=.proplist=.id,name,service,address,caller-id';

export interface RenameChrSecret {
  id: string | null;
  name: string;
  /** The declared remote-address as a host, or null. */
  remoteAddress: string | null;
  localAddress: string | null;
  service: string | null;
  profile: string | null;
  comment: string | null;
  disabled: boolean;
}

export interface RenameChrReading {
  /** Secrets named EXACTLY so (API queries are exact and case-sensitive). */
  from: RenameChrSecret[];
  to: RenameChrSecret[];
  /** Every secret declaring the frozen tunnel address. */
  atAddress: RenameChrSecret[];
  fromActive: boolean;
  toActive: boolean;
  readAt: string;
}

function toChrSecret(e: PppSecretEntry): RenameChrSecret {
  return {
    id: e.routerId,
    name: e.name,
    remoteAddress: hostAddress(e.remoteAddress),
    localAddress: e.localAddress ?? null,
    service: e.service,
    profile: e.profile,
    comment: e.comment,
    disabled: e.disabled,
  };
}

/** The frozen pairs a plan judges. */
export interface RenameFrozen {
  from_login: string;
  to_login: string;
  from_identity: string;
  to_identity: string;
  from_site_code: string | null;
  to_site_code: string | null;
  tunnel_address: string;
  tunnel_client: string | null;
}

export interface SiteRenamePlan {
  login: boolean;
  identity: boolean;
  code: boolean;
  /** `add`: the secret named <to> must be created; `present`: it is there
   *  (a re-run); `none`: the login does not change. */
  chr: 'add' | 'present' | 'none';
  /** `cut`: the management client dials <from> and must switch. */
  routerLogin: 'cut' | 'done' | 'none';
  routerIdentity: 'set' | 'done' | 'none';
  /** The old secret is still on the CHR and goes once the new session is up. */
  removeOld: boolean;
  /** The device row, the allocation or the site still hold an old name. */
  db: boolean;
  /** The .id of the old secret, when it is there. */
  fromId: string | null;
  /** The .id of the secret named <to>, when it is there. */
  toId: string | null;
  refusal: Refusal | null;
}

/** A pure plan from what the CHR and the router said. `chr`/`router` null =
 *  not read (not needed for this rename). */
export function siteRenamePlan(
  frozen: RenameFrozen,
  chr: RenameChrReading | null,
  router: RenameRouterReading | null,
  current: { login: string | null; identity: string | null; siteCode: string | null },
): SiteRenamePlan {
  const login = frozen.from_login !== frozen.to_login;
  const identity = frozen.from_identity !== frozen.to_identity;
  const code = frozen.from_site_code !== frozen.to_site_code;
  const plan: SiteRenamePlan = {
    login, identity, code, chr: 'none', routerLogin: 'none', routerIdentity: 'none', removeOld: false,
    db: (login && current.login !== frozen.to_login) || (identity && current.identity !== frozen.to_identity) ||
      (code && current.siteCode !== frozen.to_site_code),
    fromId: null, toId: null, refusal: null,
  };
  const refuse = (kind: string, message: string): SiteRenamePlan => ({ ...plan, refusal: { kind, message } });
  const fold = (v: string | null | undefined) => (v ?? '').toLowerCase();

  if (login) {
    if (!chr) return refuse('internal', 'Le CHR n’a pas été lu.');
    if (chr.from.length > 1 || chr.to.length > 1) {
      return refuse('chr_ambiguous', 'Le CHR liste plusieurs secrets sous le même nom : rien n’est écrit, vérifiez le CHR.');
    }
    const from = chr.from[0] ?? null;
    const to = chr.to[0] ?? null;
    plan.fromId = from?.id ?? null;
    plan.toId = to?.id ?? null;
    const others = chr.atAddress.filter((s) => s.name !== frozen.from_login && s.name !== frozen.to_login);
    if (others.length > 0) {
      return refuse('chr_address_shared',
        `L’adresse ${frozen.tunnel_address} est déclarée sur le CHR par un autre compte (${others.map((o) => o.name).join(', ')}) : ` +
          'rien n’est écrit, ObliWAN ne copie pas un compte dont l’adresse n’est pas à lui seul.');
    }
    if (to) {
      if (to.remoteAddress !== frozen.tunnel_address) {
        return refuse('chr_conflict',
          `Le CHR porte déjà un secret « ${frozen.to_login} » avec une autre adresse (${to.remoteAddress ?? 'aucune'}) : ` +
            'ce nom est pris par un autre compte, rien n’est écrit.');
      }
      if (from && (from.service !== to.service || from.profile !== to.profile)) {
        return refuse('chr_conflict',
          `Le CHR porte déjà un secret « ${frozen.to_login} » à la même adresse mais avec un autre service ou profil que ` +
            `« ${frozen.from_login} » : rien n’est écrit ; vérifiez le CHR.`);
      }
      plan.chr = 'present';
    } else {
      if (!from) {
        return refuse('chr_from_missing',
          `Le CHR ne porte ni « ${frozen.from_login} » ni « ${frozen.to_login} » : il n’y a pas de compte à copier, rien n’est écrit.`);
      }
      if (from.remoteAddress !== frozen.tunnel_address) {
        return refuse('chr_address_moved',
          `Le secret « ${frozen.from_login} » déclare ${from.remoteAddress ?? 'aucune adresse fixe'} sur le CHR, pas ` +
            `${frozen.tunnel_address} comme au moment de la mise en file : rien n’est écrit ; relancez la tâche.`);
      }
      if (!from.id) return refuse('chr_unreadable', `Le CHR n’a pas rendu l’identifiant du secret « ${frozen.from_login} » : rien n’est écrit.`);
      plan.chr = 'add';
    }
    // The old secret stays until the new session is up, then goes.
    plan.removeOld = from !== null;
  }

  if (login || identity) {
    if (!chr) return refuse('internal', 'Le CHR n’a pas été lu.');
    if (!chr.fromActive && !chr.toActive) {
      return refuse('router_offline',
        `Aucune session « ${frozen.from_login} »${login ? ` ni « ${frozen.to_login} »` : ''} n’est active sur le CHR : le ` +
          'routeur n’est pas joignable, rien n’est écrit.');
    }
    if (!router) return refuse('internal', 'Le routeur n’a pas été lu.');
    if (login) {
      if (router.clients === null) return refuse('router_unreadable', 'Les l2tp-clients du routeur n’ont pas pu être lus : rien n’est écrit.');
      const c = router.client;
      if (!c) {
        return refuse('tunnel_client_unknown',
          `Le tunnel de gestion du routeur n’est pas identifiable (aucun l2tp-client nommé « ${MANAGEMENT_TUNNEL_NAME} », et pas ` +
            `exactement un qui compose « ${frozen.from_login} » ou « ${frozen.to_login} ») : rien n’est écrit.`);
      }
      if (c.user === frozen.to_login) plan.routerLogin = 'done';
      else if (fold(c.user) === fold(frozen.from_login) || fold(c.user) === fold(frozen.to_login)) plan.routerLogin = 'cut';
      else {
        return refuse('router_login_unexpected',
          `Le tunnel de gestion « ${c.name} » compose « ${c.user} », ni l’ancien ni le nouveau login : rien n’est écrit.`);
      }
      if (plan.routerLogin === 'cut' && plan.chr === 'present' && chr?.toActive) {
        return refuse('router_login_unexpected',
          `Le CHR voit déjà une session « ${frozen.to_login} » alors que le routeur compose encore « ${c.user} » : ` +
            'ce n’est pas ce routeur qui l’ouvre ; rien n’est écrit.');
      }
      if (plan.routerLogin === 'cut' && c.disabled) {
        return refuse('tunnel_client_disabled', `Le tunnel de gestion « ${c.name} » est désactivé : rien n’est écrit.`);
      }
    }
    if (identity) {
      const id = router.identity;
      if (id === frozen.to_identity) plan.routerIdentity = 'done';
      else if (id !== null && (fold(id) === fold(frozen.from_identity) || fold(id) === fold(frozen.to_identity))) plan.routerIdentity = 'set';
      else {
        return refuse('router_identity_unexpected',
          `Le routeur s’annonce « ${id ?? '—'} », ni l’ancienne ni la nouvelle identité : rien n’est écrit.`);
      }
    }
  }
  return plan;
}

export function siteRenamePlanIsNoop(plan: SiteRenamePlan): boolean {
  return plan.refusal === null && plan.chr !== 'add' && plan.routerLogin !== 'cut' && plan.routerIdentity !== 'set' &&
    !plan.removeOld && !plan.db;
}

// ============================================================================
// Refusals, targets and enqueue
// ============================================================================

export function siteRenameDeviceRefusals(facts: Facts): Refusal[] {
  const d = facts.device;
  const out: Refusal[] = [];
  if (d.status === 'disabled' || d.status === 'quarantined') {
    out.push({ kind: 'device_not_writable', message: `${d.name} est « ${d.status} » : aucune tâche ne peut le viser.` });
  }
  if (!d.is_managed) out.push({ kind: 'device_not_managed', message: `${d.name} n’est pas géré par ObliWAN (lecture seule).` });
  if (d.brand !== 'mikrotik') {
    out.push({ kind: 'brand_unsupported', message: `${d.name} est un équipement ${d.brand} : le renommage concerne les routeurs MikroTik.` });
    return out;
  }
  if (d.role === 'concentrator') {
    out.push({ kind: 'concentrator_refused', message: `${d.name} est un concentrateur : le renommage concerne les routeurs des sites.` });
    return out;
  }
  const ssh = facts.ssh;
  const host = sshHostOf(facts);
  if (!ssh || !ssh.enabled || !host || !ssh.username || !ssh.secret_enc) {
    out.push({
      kind: 'no_ssh',
      message:
        `${d.name} n’a pas de canal SSH activé et complet (adresse, utilisateur, mot de passe) : la tâche passe par SSH ` +
        'avec le compte existant du routeur. Ajoutez-le dans l’onglet Paramètres.',
    });
    return out;
  }
  if (!isNonPublicAddress(host)) {
    out.push({
      kind: 'no_backup_road',
      message:
        `${d.name} est joint en SSH sur ${host}, une adresse publique ou un nom : la sauvegarde préalable ne peut pas ` +
        'être récupérée par SFTP sur ce chemin. Rien n’est écrit sans sauvegarde.',
    });
  }
  return out;
}

interface DeviceRow {
  id: number;
  tenant_id: number;
  name: string;
  site_id: number | null;
  concentrator_id: number | null;
  ppp_username: string | null;
  system_identity: string | null;
  serial: string | null;
  tunnel_ip: string | null;
}

async function loadDeviceRow(deviceId: number, tenantId: number): Promise<DeviceRow | null> {
  const row = (await db('devices')
    .where({ id: deviceId, tenant_id: tenantId })
    .first('id', 'tenant_id', 'name', 'site_id', 'concentrator_id', 'ppp_username', 'system_identity', 'serial',
      db.raw('host(tunnel_ip) AS tunnel_ip'))) as DeviceRow | undefined;
  return row ?? null;
}

interface LatestRow {
  job_id: string | number;
  outcome: SiteRenameOutcome | null;
  from_login: string;
  to_login: string;
  from_identity: string;
  to_identity: string;
  from_site_code: string | null;
  to_site_code: string | null;
  transform: SiteRenameTransform;
  chr_mode: SiteRenameChrMode | null;
  chr_old_removed_at: Date | null;
  finalized_at: Date | null;
}

async function latestRow(deviceId: number): Promise<LatestRow | null> {
  const row = (await db('site_rename_jobs')
    .where({ device_id: deviceId })
    .orderBy('job_id', 'desc')
    .first('job_id', 'outcome', 'from_login', 'to_login', 'from_identity', 'to_identity', 'from_site_code', 'to_site_code',
      'transform', 'chr_mode', 'chr_old_removed_at', 'finalized_at')) as LatestRow | undefined;
  return row ?? null;
}

/** A renamed job whose old secret was left on the CHR (its session lingered). */
function oldSecretLeft(row: LatestRow | null): boolean {
  return row !== null && row.outcome === 'renamed' && row.from_login !== row.to_login && row.chr_mode !== 'in_place' &&
    row.chr_old_removed_at === null;
}

/** The pair a relaunch re-enqueues: the latest row, when it is unsettled or
 *  renamed with its old secret left. */
function relaunchable(row: LatestRow | null): boolean {
  return row !== null && (row.outcome === 'unsettled' || oldSecretLeft(row));
}

export interface SiteRenameTarget {
  login?: string;
  identity?: string;
  siteCode?: string;
}

export interface SiteRenamePair {
  from: SiteRenameNames;
  to: SiteRenameNames;
  transform: SiteRenameTransform;
}

/** What the rename would change, from the device row and the site, for an
 *  explicit target or the lowercase transform. Pure. */
export function siteRenamePairOf(
  device: Pick<DeviceRow, 'ppp_username' | 'system_identity'>,
  siteCode: string | null,
  input: { to?: SiteRenameTarget; transform?: 'lowercase'; includeSiteCode?: boolean },
): SiteRenamePair {
  const from: SiteRenameNames = { login: device.ppp_username, identity: device.system_identity, siteCode };
  if (input.transform === 'lowercase') {
    return {
      from,
      to: {
        login: from.login === null ? null : lowercaseRename(from.login),
        identity: from.identity === null ? null : lowercaseRename(from.identity),
        siteCode: siteCode !== null && input.includeSiteCode ? lowercaseRename(siteCode) : siteCode,
      },
      transform: 'lowercase',
    };
  }
  const t = input.to ?? {};
  const pick = (v: string | undefined, cur: string | null) => (v === undefined || v.trim() === '' ? cur : v.trim());
  return {
    from,
    to: { login: pick(t.login, from.login), identity: pick(t.identity, from.identity), siteCode: siteCode === null ? null : pick(t.siteCode, siteCode) },
    transform: 'explicit',
  };
}

function pairChanges(p: SiteRenamePair): boolean {
  return p.from.login !== p.to.login || p.from.identity !== p.to.identity || p.from.siteCode !== p.to.siteCode;
}

interface Judged {
  facts: Facts | null;
  device: DeviceRow | null;
  pair: SiteRenamePair | null;
  tunnelAddress: string | null;
  chrTenantId: number | null;
  refusals: Refusal[];
}

/**
 * Every refusal for one rename, nothing written (the bulk preview lists them,
 * the enqueue throws the first).
 */
export async function judgeSiteRename(
  tenantId: number,
  deviceId: number,
  input: { to?: SiteRenameTarget; transform?: 'lowercase'; includeSiteCode?: boolean; relaunch?: boolean },
): Promise<Judged> {
  const out: Judged = { facts: null, device: null, pair: null, tunnelAddress: null, chrTenantId: null, refusals: [] };
  const facts = await loadFacts(deviceId, tenantId);
  const device = await loadDeviceRow(deviceId, tenantId);
  if (!facts || !device) {
    out.refusals.push({ kind: 'device_not_found', message: `Équipement #${deviceId} introuvable.` });
    return out;
  }
  out.facts = facts;
  out.device = device;
  out.refusals.push(...siteRenameDeviceRefusals(facts));
  if (out.refusals.some((r) => r.kind === 'brand_unsupported' || r.kind === 'concentrator_refused')) return out;
  if (device.concentrator_id === null || !device.ppp_username || !device.system_identity) {
    out.refusals.push({
      kind: 'device_unbound',
      message: `${device.name} n’a pas de concentrateur, de login PPP ou d’identité enregistrés : rattachez-le d’abord, la tâche renomme un équipement rattaché.`,
    });
    return out;
  }
  const site = device.site_id === null
    ? null
    : ((await db('sites').where({ id: device.site_id, tenant_id: tenantId }).first('id', 'code')) as { id: number; code: string } | undefined) ?? null;
  const latest = await latestRow(deviceId);

  let pair: SiteRenamePair;
  if (input.relaunch) {
    if (!relaunchable(latest)) {
      out.refusals.push({ kind: 'nothing_to_relaunch', message: 'Le dernier renommage de cet équipement n’est pas à reprendre.' });
      return out;
    }
    const l = latest as LatestRow;
    pair = {
      from: { login: l.from_login, identity: l.from_identity, siteCode: l.from_site_code },
      to: { login: l.to_login, identity: l.to_identity, siteCode: l.to_site_code },
      transform: l.transform,
    };
  } else {
    pair = siteRenamePairOf(device, site?.code ?? null, input);
    if (latest && latest.outcome === 'unsettled') {
      out.refusals.push({
        kind: 'rename_unsettled',
        message:
          `Le renommage #${latest.job_id} (« ${latest.from_login} » -> « ${latest.to_login} ») est resté incertain : relancez-le ` +
          'tel quel (« Relancer ») avant tout autre renommage.',
      });
    }
  }
  out.pair = pair;
  const changes = pairChanges(pair);
  if (!changes) {
    out.refusals.push({ kind: 'nothing_to_rename', message: 'Rien ne change : les noms demandés sont les noms actuels.' });
    return out;
  }
  const login = pair.from.login !== pair.to.login;
  const identity = pair.from.identity !== pair.to.identity;
  const code = pair.from.siteCode !== pair.to.siteCode;
  const fromLogin = pair.from.login as string;
  const toLogin = pair.to.login as string;
  const toIdentity = pair.to.identity as string;

  if (!isRenameLogin(toLogin) || (login && !isRenameLogin(fromLogin))) {
    out.refusals.push({
      kind: 'login_alphabet',
      message: `Le login « ${login ? toLogin : fromLogin} » sort de l’alphabet des logins ([A-Za-z0-9._-], 128 caractères au plus, ni « .. » ni point au bord).`,
    });
  }
  if (!isRenameIdentity(toIdentity)) {
    out.refusals.push({
      kind: 'identity_alphabet',
      message: `L’identité « ${toIdentity} » sort de l’alphabet de la tâche ([A-Za-z0-9._-], 64 caractères au plus, ni « .. » ni point au bord).`,
    });
  }
  // Beyond case, the serial is what still proves the box while the two other
  // attributes move: a device without one is not renamed.
  const beyondCase = (login && !isCaseOnlyChange(fromLogin, toLogin)) || (identity && !isCaseOnlyChange(pair.from.identity, toIdentity));
  if (beyondCase && !device.serial) {
    out.refusals.push({
      kind: 'serial_missing',
      message: `${device.name} n’a pas de numéro de série enregistré : pendant un renommage qui change plus que la casse, c’est lui qui prouve le routeur. Testez la connexion pour l’apprendre.`,
    });
  }

  if (login) {
    const otherDevice = (await db('devices').whereRaw('lower(ppp_username) = lower(?)', [toLogin]).whereNot('id', deviceId).first('id', 'name')) as
      | { id: number; name: string }
      | undefined;
    if (otherDevice) out.refusals.push({ kind: 'login_taken', message: `Le login « ${toLogin} » est déjà celui d’un autre équipement (${otherDevice.name}).` });
    const q = db('site_provisioning').whereRaw('lower(ppp_username) = lower(?)', [toLogin]);
    if (device.site_id !== null) q.whereNot('site_id', device.site_id);
    if (await q.first('site_id')) out.refusals.push({ kind: 'login_taken', message: `Le login « ${toLogin} » est déjà alloué à un autre site.` });
    const held = (await db('concentrator_ppp_secrets')
      .where({ concentrator_id: device.concentrator_id })
      .whereNull('vanished_at')
      .whereRaw('lower(name) = lower(?)', [toLogin])
      .whereNot('name', fromLogin)
      .select('name')) as Array<{ name: string }>;
    const foreign = held.filter((h) => !(input.relaunch && h.name === toLogin));
    if (foreign.length > 0) {
      out.refusals.push({
        kind: 'login_taken',
        message: `Le CHR porte déjà un secret « ${foreign[0].name} » (dernière lecture du CHR) : ce login n’est pas libre.`,
      });
    }
    const inFlight = device.site_id === null
      ? undefined
      : await db('concentrator_secret_jobs as c').join('change_jobs as j', 'j.id', 'c.job_id')
        .where('c.site_id', device.site_id)
        .whereIn('j.status', ['queued', 'claimed', 'backing_up', 'arming', 'applying', 'verifying', 'soaking', 'disarming'])
        .first('c.job_id');
    if (inFlight) {
      out.refusals.push({ kind: 'concentrator_secret_in_flight', message: 'Une tâche crée en ce moment le compte de ce site sur le CHR : attendez-la.' });
    }
  }
  if (identity && !isCaseOnlyChange(pair.from.identity, toIdentity)) {
    const otherDevice = (await db('devices').whereRaw('lower(system_identity) = lower(?)', [toIdentity]).whereNot('id', deviceId).first('name')) as
      | { name: string }
      | undefined;
    if (otherDevice) {
      out.refusals.push({ kind: 'identity_taken', message: `L’identité « ${toIdentity} » est déjà celle d’un autre équipement (${otherDevice.name}) : syslog et traps ne sauraient plus à qui attribuer leurs messages.` });
    }
    const q = db('site_provisioning').whereRaw('lower(system_identity) = lower(?)', [toIdentity]);
    if (device.site_id !== null) q.whereNot('site_id', device.site_id);
    if (await q.first('site_id')) out.refusals.push({ kind: 'identity_taken', message: `L’identité « ${toIdentity} » est déjà allouée à un autre site.` });
  }
  if (code) {
    const toCode = pair.to.siteCode as string;
    if (!site) {
      out.refusals.push({ kind: 'no_site', message: `${device.name} n’est rattaché à aucun site : il n’y a pas de code à renommer.` });
    } else {
      if (toCode.length > 64 || toCode.trim() === '') out.refusals.push({ kind: 'site_code_invalid', message: 'Le code de site est vide ou trop long.' });
      try {
        await assertSiteCodeFormat(db, tenantId, toCode, { renamingSiteId: site.id });
      } catch (err) {
        out.refusals.push({ kind: 'site_code_invalid', message: err instanceof Error ? err.message : String(err) });
      }
      const dup = await db('sites').where({ tenant_id: tenantId, code: toCode }).whereNot('id', site.id).first('id');
      if (dup) out.refusals.push({ kind: 'site_code_taken', message: `Le code « ${toCode} » est déjà celui d’un autre site de ce client.` });
      const bench = (await db('bench_provisionings').where({ site_id: site.id }).count<{ n: string }>({ n: '*' }).first())?.n ?? '0';
      if (Number(bench) > 0) {
        out.refusals.push({ kind: 'site_code_bench', message: 'Le banc a déjà compilé des fichiers pour ce site avec son code actuel : le code ne peut pas changer.' });
      }
      const infra = (await db('infra_site_accounts').where({ site_id: site.id }).count<{ n: string }>({ n: '*' }).first())?.n ?? '0';
      if (Number(infra) > 0) {
        out.refusals.push({ kind: 'site_code_infra', message: 'Ce site a un compte sur le concentrateur d’infrastructure du client (nommé d’après son code) : le code ne peut pas changer.' });
      }
    }
  }

  // The address the new secret must keep: the CHR's last full read, else the
  // allocation, else where the device answers today.
  const inv = login
    ? ((await db('concentrator_ppp_secrets')
      .where({ concentrator_id: device.concentrator_id, name: fromLogin })
      .whereNull('vanished_at')
      .first(db.raw('host(remote_address) AS remote_address'))) as { remote_address: string | null } | undefined)
    : undefined;
  const prov = device.site_id === null
    ? undefined
    : ((await db('site_provisioning').where({ site_id: device.site_id }).first(db.raw('host(tunnel_ip) AS tunnel_ip'))) as
      | { tunnel_ip: string | null }
      | undefined);
  out.tunnelAddress = hostAddress(inv?.remote_address) ?? hostAddress(prov?.tunnel_ip) ?? hostAddress(device.tunnel_ip);
  if (out.tunnelAddress === null) {
    out.refusals.push({
      kind: 'no_static_address',
      message: `Aucune adresse fixe n’est connue pour le tunnel de ${device.name} (secret du CHR, allocation) : le nouveau compte ne pourrait pas garder la même.`,
    });
  }
  const chr = (await db('devices').where({ id: device.concentrator_id }).first('tenant_id')) as { tenant_id: number } | undefined;
  out.chrTenantId = chr?.tenant_id ?? null;
  return out;
}

export interface EnqueueSiteRenameInput {
  tenantId: number;
  deviceId: number;
  to?: SiteRenameTarget;
  transform?: 'lowercase';
  includeSiteCode?: boolean;
  /** Re-enqueue the latest unsettled pair (« Relancer »). */
  relaunch?: boolean;
  requestedBy: number | null;
  confirmDegraded: { userId: number | null; at?: Date } | null;
  /** The device page: a rename already queued or running is returned. */
  allowExisting?: boolean;
}

export interface EnqueueSiteRenameResult {
  jobId: number;
  alreadyQueued: boolean;
}

const NO_BASE_STATE = '0'.repeat(64);

export async function enqueueSiteRenameJob(input: EnqueueSiteRenameInput): Promise<EnqueueSiteRenameResult> {
  const killSwitch = await readKillSwitch(input.tenantId);
  if (killSwitch.blocked) throw new KillSwitchEngagedError(killSwitch);
  const judged = await judgeSiteRename(input.tenantId, input.deviceId, input);
  const { facts, device, pair } = judged;
  if (!facts || !device || !pair || judged.refusals.length > 0) {
    const first = judged.refusals[0] ?? { kind: 'internal', message: 'Renommage impossible.' };
    throw new SiteRenameError(first.kind, judged.refusals.map((r) => r.message).join(' '), first.kind === 'device_not_found' ? 404 : 409);
  }
  if (judged.chrTenantId !== null && judged.chrTenantId !== input.tenantId) {
    const chrSwitch = await readKillSwitch(judged.chrTenantId);
    if (chrSwitch.blocked) throw new KillSwitchEngagedError(chrSwitch);
  }
  const safetyNet = siteRenameSafetyNet();
  if (!input.confirmDegraded) {
    throw new SiteRenameError('degraded_unconfirmed', `${safetyNet.rationale} La tâche doit être confirmée explicitement.`, 422);
  }
  const existing = await activeJobOf(device.id);
  if (existing) {
    if (existing.kind === SITE_RENAME_KIND && input.allowExisting) return { jobId: existing.id, alreadyQueued: true };
    throw new DeviceBusyError(device.id);
  }
  const guard = siteRenameGuard();
  const now = new Date();
  let jobId: number;
  try {
    jobId = await db.transaction(async (trx) => {
      const inserted = (await trx('change_jobs')
        .insert({
          tenant_id: input.tenantId,
          device_id: device.id,
          plan_id: null,
          kind: SITE_RENAME_KIND,
          status: 'queued',
          attempt: 0,
          max_attempts: 1,
          base_state_hash: NO_BASE_STATE,
          safety_level: safetyNet.level,
          safety_peer_device_id: null,
          guard_verdict: guard.verdict,
          guard_reasons: JSON.stringify(guard.reasons),
          degraded_confirmed_by: input.confirmDegraded!.userId,
          degraded_confirmed_at: input.confirmDegraded!.at ?? now,
          requested_by: input.requestedBy,
        })
        .returning('id')) as Array<{ id: string | number }>;
      const id = Number(inserted[0].id);
      await trx('site_rename_jobs').insert({
        job_id: id,
        tenant_id: input.tenantId,
        device_id: device.id,
        site_id: device.site_id,
        concentrator_id: device.concentrator_id,
        from_login: pair.from.login,
        to_login: pair.to.login,
        from_identity: pair.from.identity,
        to_identity: pair.to.identity,
        from_site_code: pair.from.siteCode,
        to_site_code: pair.to.siteCode,
        transform: pair.transform,
        ssh_host: sshHostOf(facts),
        tunnel_address: judged.tunnelAddress,
        revert_after_s: deps.revertAfterS,
        tunnel_wait_s: deps.tunnelWaitS,
      });
      return id;
    });
  } catch (err) {
    const pg = err as { code?: string; constraint?: string; message?: string };
    if (pg.code === '23505' && pg.constraint === 'change_jobs_one_in_flight_uq') {
      const again = await activeJobOf(device.id);
      if (again && again.kind === SITE_RENAME_KIND && input.allowExisting) return { jobId: again.id, alreadyQueued: true };
      throw new DeviceBusyError(device.id);
    }
    if (pg.code === '23001' && /subtree interlock/i.test(pg.message ?? '')) {
      throw new SiteRenameError(
        'subtree_interlock',
        'Une tâche est en cours sur le concentrateur qui porte le tunnel de ce routeur : rien n’a été mis en file.',
      );
    }
    throw err;
  }
  logger.warn(
    { jobId, deviceId: device.id, kind: SITE_RENAME_KIND, from: pair.from, to: pair.to, requestedBy: input.requestedBy },
    'site_rename job QUEUED — a router\'s management login / identity about to be renamed on the CHR and on the box',
  );
  const summary = { jobId, deviceId: device.id, kind: SITE_RENAME_KIND, status: 'queued' };
  emitToTenantAudience(input.tenantId, SOCKET_EVENTS.JOB_QUEUED, summary, { deviceId: device.id });
  emitToDevice(device.id, SOCKET_EVENTS.JOB_QUEUED, summary);
  return { jobId, alreadyQueued: false };
}

// ============================================================================
// Bulk (the Sites page selection)
// ============================================================================

/** The ONE router of a site the job can rename: a MikroTik CPE attached
 *  behind a concentrator. */
async function routerOfSite(tenantId: number, siteId: number): Promise<{ deviceId: number | null; name: string | null; refusal: Refusal | null }> {
  const rows = (await db('devices')
    .where({ tenant_id: tenantId, site_id: siteId, brand: 'mikrotik' })
    .whereNot('role', 'concentrator')
    .whereNotNull('ppp_username')
    .whereNotNull('concentrator_id')
    .select('id', 'name')) as Array<{ id: number; name: string }>;
  if (rows.length === 1) return { deviceId: rows[0].id, name: rows[0].name, refusal: null };
  if (rows.length === 0) {
    return { deviceId: null, name: null, refusal: { kind: 'no_router', message: 'Aucun routeur MikroTik rattaché (login PPP, concentrateur) sur ce site.' } };
  }
  return {
    deviceId: null,
    name: null,
    refusal: { kind: 'several_routers', message: `${rows.length} routeurs rattachés sur ce site : renommez-les un par un depuis leur fiche.` },
  };
}

export async function previewSiteRenameBulk(
  tenantId: number,
  siteIds: readonly number[],
  includeSiteCode: boolean,
): Promise<SiteRenameBulkPreviewRow[]> {
  const out: SiteRenameBulkPreviewRow[] = [];
  for (const siteId of [...new Set(siteIds)]) {
    const site = (await db('sites').where({ id: siteId, tenant_id: tenantId }).first('id', 'code', 'name')) as
      | { id: number; code: string; name: string }
      | undefined;
    if (!site) continue;
    const r = await routerOfSite(tenantId, siteId);
    const empty: SiteRenameNames = { login: null, identity: null, siteCode: site.code };
    if (r.deviceId === null) {
      out.push({
        siteId, siteCode: site.code, siteName: site.name, deviceId: null, deviceName: null,
        from: empty, to: { ...empty, siteCode: includeSiteCode ? lowercaseRename(site.code) : site.code },
        nothingToRename: false, refusals: r.refusal ? [r.refusal] : [],
      });
      continue;
    }
    const judged = await judgeSiteRename(tenantId, r.deviceId, { transform: 'lowercase', includeSiteCode });
    const pair = judged.pair;
    const nothing = judged.refusals.length === 1 && judged.refusals[0].kind === 'nothing_to_rename';
    out.push({
      siteId,
      siteCode: site.code,
      siteName: site.name,
      deviceId: r.deviceId,
      deviceName: r.name,
      from: pair?.from ?? empty,
      to: pair?.to ?? empty,
      nothingToRename: nothing,
      refusals: nothing ? [] : judged.refusals,
    });
  }
  return out;
}

export async function launchSiteRenameBulk(input: {
  tenantId: number;
  siteIds: readonly number[];
  includeSiteCode: boolean;
  requestedBy: number | null;
  confirmDegraded: { userId: number | null };
}): Promise<SiteRenameBulkLaunchRow[]> {
  const out: SiteRenameBulkLaunchRow[] = [];
  for (const siteId of [...new Set(input.siteIds)]) {
    const site = await db('sites').where({ id: siteId, tenant_id: input.tenantId }).first('id');
    if (!site) continue;
    const r = await routerOfSite(input.tenantId, siteId);
    if (r.deviceId === null) {
      out.push({ siteId, deviceId: null, jobId: null, alreadyQueued: false, refusal: r.refusal });
      continue;
    }
    try {
      const q = await enqueueSiteRenameJob({
        tenantId: input.tenantId,
        deviceId: r.deviceId,
        transform: 'lowercase',
        includeSiteCode: input.includeSiteCode,
        requestedBy: input.requestedBy,
        confirmDegraded: input.confirmDegraded,
        allowExisting: true,
      });
      out.push({ siteId, deviceId: r.deviceId, jobId: q.jobId, alreadyQueued: q.alreadyQueued, refusal: null });
    } catch (err) {
      let refusal: Refusal;
      if (err instanceof SiteRenameError) refusal = { kind: err.kind, message: err.message };
      else if (err instanceof DeviceBusyError) refusal = { kind: 'device_busy', message: 'Une autre tâche est en cours sur ce routeur.' };
      else if (err instanceof KillSwitchEngagedError) refusal = { kind: 'kill_switch', message: `Arrêt d’urgence engagé : ${err.message}` };
      else throw err;
      out.push({ siteId, deviceId: r.deviceId, jobId: null, alreadyQueued: false, refusal });
    }
  }
  return out;
}

// ============================================================================
// The view — the device card
// ============================================================================

export interface SiteRenameJobView {
  id: number;
  status: ChangeJobStatus;
  active: boolean;
  outcome: SiteRenameOutcome | null;
  outcomeDetail: string | null;
  errorKind: string | null;
  errorMessage: string | null;
  createdAt: string;
  finishedAt: string | null;
  from: SiteRenameNames;
  to: SiteRenameNames;
  transform: SiteRenameTransform;
  chrMode: SiteRenameChrMode | null;
  backupId: number | null;
  cutSentAt: string | null;
  toSessionSeenAt: string | null;
  finalizedAt: string | null;
  oldSecretRemovedAt: string | null;
  steps: Array<{ seq: number; kind: string; status: string; output: string | null; error: string | null }>;
}

export interface SiteRenameView {
  deviceId: number;
  deviceName: string;
  supported: boolean;
  eligible: boolean;
  refusals: Refusal[];
  current: SiteRenameNames;
  siteId: number | null;
  job: SiteRenameJobView | null;
  /** The latest rename is unsettled: only « Relancer » is offered. */
  unsettled: boolean;
  /** The latest rename left its old secret on the CHR: « Relancer » removes it. */
  oldSecretLeft: boolean;
}

function iso(d: Date | string | null | undefined): string | null {
  return d ? new Date(d).toISOString() : null;
}

export async function getSiteRenameView(tenantId: number, deviceId: number): Promise<SiteRenameView | null> {
  const facts = await loadFacts(deviceId, tenantId);
  const device = await loadDeviceRow(deviceId, tenantId);
  if (!facts || !device) return null;
  const refusals = siteRenameDeviceRefusals(facts);
  const supported = !refusals.some((r) => r.kind === 'brand_unsupported' || r.kind === 'concentrator_refused');
  if (supported && (device.concentrator_id === null || !device.ppp_username || !device.system_identity)) {
    refusals.push({ kind: 'device_unbound', message: `${device.name} n’a pas de concentrateur, de login PPP ou d’identité enregistrés.` });
  }
  const site = device.site_id === null
    ? null
    : ((await db('sites').where({ id: device.site_id, tenant_id: tenantId }).first('code')) as { code: string } | undefined) ?? null;
  const row = (await db('site_rename_jobs as r').join('change_jobs as j', 'j.id', 'r.job_id')
    .where('r.device_id', deviceId).where('r.tenant_id', tenantId).orderBy('r.job_id', 'desc')
    .first('r.*', 'j.status', 'j.error_kind', 'j.error_message', 'j.created_at as job_created_at', 'j.finished_at')) as
    | Record<string, any>
    | undefined;
  let job: SiteRenameJobView | null = null;
  if (row) {
    const steps = (await db('change_job_steps')
      .where({ job_id: row.job_id })
      .orderBy([{ column: 'attempt', order: 'asc' }, { column: 'seq', order: 'asc' }])
      .select('seq', 'kind', 'status', 'output_redacted', 'error_redacted')) as Array<Record<string, any>>;
    const status = row.status as ChangeJobStatus;
    job = {
      id: Number(row.job_id),
      status,
      active: isActiveJobStatus(status),
      outcome: (row.outcome ?? null) as SiteRenameOutcome | null,
      outcomeDetail: row.outcome_detail ?? null,
      errorKind: row.error_kind ?? null,
      errorMessage: row.error_message ?? null,
      createdAt: iso(row.job_created_at) as string,
      finishedAt: iso(row.finished_at),
      from: { login: row.from_login, identity: row.from_identity, siteCode: row.from_site_code ?? null },
      to: { login: row.to_login, identity: row.to_identity, siteCode: row.to_site_code ?? null },
      transform: row.transform,
      chrMode: row.chr_mode ?? null,
      backupId: row.backup_id === null ? null : Number(row.backup_id),
      cutSentAt: iso(row.cut_sent_at),
      toSessionSeenAt: iso(row.to_session_seen_at),
      finalizedAt: iso(row.finalized_at),
      oldSecretRemovedAt: iso(row.chr_old_removed_at),
      steps: steps.map((s) => ({
        seq: Number(s.seq),
        kind: String(s.kind),
        status: String(s.status),
        output: s.output_redacted ?? null,
        error: s.error_redacted ?? null,
      })),
    };
  }
  const latest = row
    ? ({ ...row, outcome: row.outcome ?? null } as unknown as LatestRow)
    : null;
  return {
    deviceId,
    deviceName: device.name,
    supported,
    eligible: refusals.length === 0,
    refusals,
    current: { login: device.ppp_username, identity: device.system_identity, siteCode: site?.code ?? null },
    siteId: device.site_id,
    job,
    unsettled: latest?.outcome === 'unsettled',
    oldSecretLeft: oldSecretLeft(latest),
  };
}

// ============================================================================
// The job's phases (called from apply.service.ts runPhases)
// ============================================================================

export interface SiteRenameStepResult {
  output: string;
  detail: Record<string, unknown>;
}

interface FrozenRow extends RenameFrozen {
  job_id: string | number;
  tenant_id: number;
  device_id: number;
  site_id: number | null;
  concentrator_id: number;
  transform: SiteRenameTransform;
  ssh_host: string;
  revert_after_s: number;
  tunnel_wait_s: number;
  backup_id: string | number | null;
  chr_mode: SiteRenameChrMode | null;
  chr_to_id: string | null;
  chr_from_id: string | null;
}

async function loadFrozen(jobId: number): Promise<FrozenRow | null> {
  const row = (await db('site_rename_jobs')
    .where({ job_id: jobId })
    .first(
      'job_id', 'tenant_id', 'device_id', 'site_id', 'concentrator_id', 'from_login', 'to_login', 'from_identity', 'to_identity',
      'from_site_code', 'to_site_code', 'transform', 'tunnel_client', 'ssh_host', db.raw('host(tunnel_address) AS tunnel_address'),
      'revert_after_s', 'tunnel_wait_s', 'backup_id', 'chr_mode', 'chr_to_id', 'chr_from_id',
    )) as FrozenRow | undefined;
  return row ?? null;
}

async function patchJob(jobId: number, patch: Record<string, unknown>): Promise<void> {
  await db('site_rename_jobs').where({ job_id: jobId }).update({ ...patch, updated_at: db.fn.now() });
}

/**
 * Called by `failJob` for every failure of this kind; an outcome the run
 * recorded is kept. Otherwise: `unsettled` when the router may hold a new
 * name (the cut left, or the device row was switched and not switched back,
 * or the identity was set before the end); `failed` when the CHR was written;
 * `refused` when nothing was. Never throws.
 */
export async function settleSiteRename(job: Pick<ChangeJobRow, 'id'>, message: string): Promise<void> {
  try {
    const jobId = Number(job.id);
    const row = (await db('site_rename_jobs').where({ job_id: jobId })
      .first('outcome', 'cut_sent_at', 'db_login_switched_at', 'db_login_restored_at', 'identity_set_at', 'finalized_at',
        'chr_written_at', 'chr_old_removed_at')) as Record<string, Date | string | null> | undefined;
    if (!row || row.outcome !== null) return;
    const unsettled = row.cut_sent_at !== null ||
      (row.db_login_switched_at !== null && row.db_login_restored_at === null) ||
      (row.identity_set_at !== null && row.finalized_at === null);
    const outcome: SiteRenameOutcome = unsettled
      ? 'unsettled'
      : row.chr_written_at !== null || row.finalized_at !== null || row.chr_old_removed_at !== null || row.identity_set_at !== null
        ? 'failed'
        : 'refused';
    await patchJob(jobId, { outcome, outcome_detail: (message || 'échec sans message').slice(0, 4000) });
  } catch (err) {
    logger.error({ err, jobId: Number(job.id) }, 'site_rename: could not record the outcome of a failed job');
  }
}

/** A ManagementAccessError raised by the shared SSH machinery, renamed. */
function renamed(err: unknown): unknown {
  return err instanceof ManagementAccessError ? new SiteRenameError(err.kind, err.message) : err;
}

/** What became of one line sent. */
export interface RenameSendResult {
  status: 'accepted' | 'refused' | 'lost' | 'dropped' | 'not_sent';
  said?: string;
}

/** Send ONE line on its own command; never throws (legacy_compliance's rule). */
async function sendRaw(cli: AuditedCli, line: string, timeoutMs?: number): Promise<{ result: RenameSendResult; out: string }> {
  try {
    const res = await cli.exec(`${line}; :put "${CMD_OK}"`, { isWrite: true, timeoutMs });
    const out = `${res.stdout}\n${res.stderr}`;
    if (out.includes(CMD_OK)) return { result: { status: 'accepted' }, out };
    const said = out.replace(/\s+/g, ' ').trim().slice(0, 300);
    return { result: said === '' ? { status: 'lost', said: 'aucune réponse, la session s’est fermée' } : { status: 'refused', said }, out };
  } catch (err) {
    return { result: { status: 'lost', said: (err instanceof Error ? err.message : String(err)).slice(0, 300) }, out: '' };
  }
}

interface ChrRef {
  id: number;
  tenant_id: number;
  uuid: string | null;
  name: string;
}

export class SiteRenameRun {
  private facts: Facts | null = null;
  private frozen: FrozenRow | null = null;
  private chrRef: ChrRef | null = null;
  private plan: SiteRenamePlan | null = null;
  private noop = false;
  private chrBefore: RenameChrReading | null = null;
  private routerBefore: RenameRouterReading | null = null;
  private sent: Record<string, RenameSendResult> = {};
  private chrMode: SiteRenameChrMode | null = null;
  private toId: string | null = null;
  private cutAt: number | null = null;
  private guardAcceptedAt: number | null = null;
  private guardJobId: string | null = null;
  private guardCheck: { id: string | null; listed: boolean | null; leadS: number | null } | null = null;
  private awaitedGuard = false;
  private identityDone = false;
  private toSeen = false;
  private precutFromSession: string | null = null;
  private renamedBack = false;
  private readonly backups: SshPreflightBackup;

  constructor(
    private readonly job: ChangeJobRow,
    private readonly device: { id: number; uuid?: string | null; name?: string | null },
    private readonly correlationId: string,
    private readonly workerId?: string,
  ) {
    this.backups = new SshPreflightBackup(job, device, correlationId, SITE_RENAME_KIND);
  }

  private get jobId(): number {
    return Number(this.job.id);
  }

  get isNoop(): boolean {
    return this.noop;
  }

  get noopReason(): string {
    return 'Le CHR, le routeur et la fiche portent déjà les noms demandés : rien ne sera écrit, aucune sauvegarde n’est nécessaire.';
  }

  /** A router line is planned: the backup is taken first. */
  get needsBackup(): boolean {
    return this.plan !== null && (this.plan.routerLogin === 'cut' || this.plan.routerIdentity === 'set');
  }

  get noBackupReason(): string {
    return this.noop
      ? this.noopReason
      : 'Aucune ligne n’est à envoyer au routeur (le CHR, la fiche ou le code du site seulement) : aucune sauvegarde préalable n’est nécessaire.';
  }

  get mustAwaitTunnel(): boolean {
    return this.cutAt !== null;
  }

  get noTunnelReason(): string {
    return this.plan?.routerLogin === 'cut'
      ? 'La ligne qui change le login du tunnel n’est pas partie : aucun tunnel n’a redémarré, rien à attendre.'
      : 'Le login du tunnel de gestion ne change pas sur le routeur : aucun tunnel ne redémarre, rien à attendre.';
  }

  private async held<T>(fn: () => Promise<T>): Promise<T> {
    const timer = this.workerId
      ? setInterval(() => void renewLease(this.jobId, this.workerId as string).catch(() => undefined), 30_000)
      : null;
    timer?.unref?.();
    try {
      return await fn();
    } catch (err) {
      throw renamed(err);
    } finally {
      if (timer) clearInterval(timer);
    }
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
    if (!this.facts) throw new SiteRenameError('internal', 'La tâche n’a pas été inspectée avant d’agir.');
    return this.facts;
  }

  private requireFrozen(): FrozenRow {
    if (!this.frozen) throw new SiteRenameError('internal', 'La tâche n’a pas lu ses paramètres figés.');
    return this.frozen;
  }

  private requirePlan(): SiteRenamePlan {
    if (!this.plan) throw new SiteRenameError('internal', 'La tâche n’a pas établi son plan.');
    return this.plan;
  }

  private requireChr(): ChrRef {
    if (!this.chrRef) throw new SiteRenameError('internal', 'Le CHR de la tâche n’est pas connu.');
    return this.chrRef;
  }

  // ── The CHR ───────────────────────────────────────────────────────────────

  private intent(command: string, isWrite: boolean): CommandIntent {
    const chr = this.requireChr();
    return {
      tenantId: chr.tenant_id,
      deviceId: chr.id,
      deviceUuid: chr.uuid,
      deviceName: chr.name,
      jobId: this.jobId,
      transport: 'routeros_api',
      command,
      args: { purpose: 'site_rename', renamedDeviceId: this.device.id },
      isWrite,
      correlationId: this.correlationId,
      secrets: [],
    };
  }

  private async onChr<T>(fn: (conn: RouterOsConnection) => Promise<T>): Promise<T> {
    const target = await resolveRouterOsTarget(this.requireChr().id);
    return getRouterOsPool().withConnection(target, fn);
  }

  private async chrQuery(conn: RouterOsConnection, words: string[], isWrite: boolean): Promise<Record<string, string>[]> {
    return auditedCommand(this.intent(words.join(' '), isWrite), () => conn.query(words));
  }

  /** A write the CHR may refuse: its `!trap` comes back as a value (the pool
   *  must not count an answer against the shared CHR's breaker). */
  private async chrWrite(conn: RouterOsConnection, words: string[]): Promise<{ ok: true } | { ok: false; said: string }> {
    try {
      await this.chrQuery(conn, words, true);
      return { ok: true };
    } catch (err) {
      if ((err as { kind?: string }).kind === 'trap') return { ok: false, said: (err as Error).message.slice(0, 300) };
      throw err;
    }
  }

  private async readChr(conn: RouterOsConnection): Promise<RenameChrReading> {
    const f = this.requireFrozen();
    const secrets = async (q: string) =>
      (await this.chrQuery(conn, ['/ppp/secret/print', SECRET_PROPLIST, q], false))
        .map(parseSecretRow).filter((e): e is PppSecretEntry => e !== null).map(toChrSecret);
    const active = async (name: string) =>
      (await this.chrQuery(conn, ['/ppp/active/print', ACTIVE_PROPLIST, `?name=${name}`], false))
        .map(parseActiveRow).filter((e) => e !== null && e.name === name).length > 0;
    const from = (await secrets(`?name=${f.from_login}`)).filter((s) => s.name === f.from_login);
    const to = f.to_login === f.from_login ? [] : (await secrets(`?name=${f.to_login}`)).filter((s) => s.name === f.to_login);
    const atAddress = (await secrets(`?remote-address=${f.tunnel_address}`)).filter((s) => s.remoteAddress === f.tunnel_address);
    return {
      from,
      to,
      atAddress,
      fromActive: await active(f.from_login),
      toActive: f.to_login === f.from_login ? false : await active(f.to_login),
      readAt: new Date().toISOString(),
    };
  }

  /** The CHR, proven on a fresh socket — never quarantined (it is shared:
   *  a mismatch refuses this job and nothing else). */
  private async proveChr(): Promise<void> {
    try {
      await assertTargetBinding(this.requireChr().id, { throwOnFailure: true, quarantineOnMismatch: false });
    } catch (err) {
      if (err instanceof BindingAssertionError) {
        throw new SiteRenameError('chr_identity', `Le CHR n’a pas prouvé son identité sur une nouvelle connexion (${err.assertion.reason}) : rien n’est écrit.`);
      }
      throw err;
    }
  }

  // ── lint ─────────────────────────────────────────────────────────────────

  private async currentNames(): Promise<{ login: string | null; identity: string | null; siteCode: string | null }> {
    const f = this.requireFrozen();
    const d = (await db('devices').where({ id: this.device.id }).first('ppp_username', 'system_identity')) as
      | { ppp_username: string | null; system_identity: string | null }
      | undefined;
    const site = f.site_id === null ? undefined : ((await db('sites').where({ id: f.site_id }).first('code')) as { code: string } | undefined);
    return { login: d?.ppp_username ?? null, identity: d?.system_identity ?? null, siteCode: site?.code ?? f.from_site_code };
  }

  private routerNeeded(f: FrozenRow): boolean {
    return f.from_login !== f.to_login || f.from_identity !== f.to_identity;
  }

  async inspect(): Promise<SiteRenameStepResult> {
    return this.held(async () => {
      const frozen = await loadFrozen(this.jobId);
      if (!frozen) throw new SiteRenameError('job_row_missing', 'La tâche n’a pas de paramètres figés (site_rename_jobs) : refus.');
      this.frozen = frozen;
      const facts = await loadFacts(this.device.id, this.job.tenant_id);
      if (!facts) throw new SiteRenameError('device_not_found', `Équipement #${this.device.id} introuvable.`);
      this.facts = facts;
      const refusals = siteRenameDeviceRefusals(facts);
      if (refusals.length > 0) throw new SiteRenameError(refusals[0].kind, refusals.map((r) => r.message).join(' '));
      const host = sshHostOf(facts);
      if (host !== frozen.ssh_host) {
        throw new SiteRenameError(
          'ssh_moved',
          `Le canal SSH de ${facts.device.name} pointe désormais vers ${host ?? 'aucune adresse'} au lieu de ${frozen.ssh_host} : rien n’a été écrit ; relancez la tâche.`,
        );
      }
      const chr = (await db('devices').where({ id: frozen.concentrator_id }).first('id', 'tenant_id', 'uuid', 'name', 'is_managed', 'status')) as
        | (ChrRef & { is_managed: boolean; status: string })
        | undefined;
      if (!chr || !chr.is_managed || chr.status === 'disabled' || chr.status === 'quarantined') {
        throw new SiteRenameError('chr_unavailable', 'Le concentrateur de ce routeur n’est pas géré ou pas actif : rien n’est écrit.');
      }
      this.chrRef = { id: chr.id, tenant_id: chr.tenant_id, uuid: chr.uuid ?? null, name: chr.name };
      // runPhases checked the device tenant's switch; the CHR's stops it too.
      await assertWritable(chr.tenant_id);

      const login = frozen.from_login !== frozen.to_login;
      let chrReading: RenameChrReading | null = null;
      if (this.routerNeeded(frozen)) {
        await this.proveChr();
        chrReading = await this.onChr((conn) => this.readChr(conn));
      }
      this.chrBefore = chrReading;
      let routerReading: RenameRouterReading | null = null;
      if (this.routerNeeded(frozen)) {
        // The router is dialled only when the CHR says its tunnel is up.
        const reachable = chrReading !== null && (chrReading.fromActive || chrReading.toActive);
        if (reachable) {
          routerReading = await withProvenCli(facts, this.ctx('lint'), async (cli) => {
            await assertFamily(cli, facts);
            return readRouter(cli, frozen.tunnel_client, frozen.from_login, frozen.to_login);
          });
        }
      }
      this.routerBefore = routerReading;
      const current = await this.currentNames();
      const plan = siteRenamePlan(frozen, chrReading, routerReading ?? { identity: null, clients: null, client: null }, current);
      this.plan = plan;
      const tunnelClient = routerReading?.client?.name ?? null;
      const patch: Record<string, unknown> = {
        before: JSON.stringify({ chr: chrReading, router: routerReading, current, plan, readAt: new Date().toISOString() }),
      };
      if (tunnelClient && login && frozen.tunnel_client === null) {
        patch.tunnel_client = tunnelClient;
        frozen.tunnel_client = tunnelClient;
      }
      if (plan.fromId) patch.chr_from_id = plan.fromId;
      if (plan.toId) {
        patch.chr_to_id = plan.toId;
        this.toId = plan.toId;
      }
      // A re-run that finds the router already dialling the new login with
      // the session up has seen it: what the cleanup's removal waits for.
      if (plan.routerLogin === 'done' && chrReading?.toActive) {
        patch.to_session_seen_at = db.fn.now();
        this.toSeen = true;
      }
      await patchJob(this.jobId, patch);
      if (plan.refusal) throw new SiteRenameError(plan.refusal.kind, plan.refusal.message);
      if (plan.routerLogin === 'cut' || plan.routerIdentity === 'set') await this.backups.probeRoad(sshCredentialOf(facts));
      if (siteRenamePlanIsNoop(plan)) {
        this.noop = true;
        return { output: 'le CHR, le routeur et la fiche portent déjà les noms demandés : rien à écrire', detail: { noop: true, plan } };
      }
      return { output: this.describePlan(plan), detail: { noop: false, plan } };
    });
  }

  private describePlan(plan: SiteRenamePlan): string {
    const f = this.requireFrozen();
    const parts: string[] = [];
    if (plan.chr === 'add') parts.push(`CHR : copier « ${f.from_login} » sous « ${f.to_login} »`);
    if (plan.chr === 'present') parts.push(`CHR : « ${f.to_login} » déjà présent`);
    if (plan.routerLogin === 'cut') parts.push(`routeur : tunnel de gestion vers « ${f.to_login} » (dernière ligne, derrière un retour arrière)`);
    if (plan.routerLogin === 'done') parts.push('routeur : le tunnel compose déjà le nouveau login');
    if (plan.routerIdentity === 'set') parts.push(`routeur : identité « ${f.to_identity} »`);
    if (plan.routerIdentity === 'done') parts.push('routeur : identité déjà à jour');
    if (plan.code) parts.push(`code du site « ${f.from_site_code} » -> « ${f.to_site_code} »`);
    if (plan.db) parts.push('fiche à mettre à jour');
    if (plan.removeOld) parts.push(`ancien secret « ${f.from_login} » retiré une fois la nouvelle session montée`);
    return parts.join(' ; ');
  }

  async backup(): Promise<{ backupId: number; output: string; detail: Record<string, unknown> }> {
    return this.held(async () => {
      const facts = this.requireFacts();
      const cred = sshCredentialOf(facts);
      const stored = await withProvenCli(facts, this.ctx('backup'), async (cli) => {
        await assertFamily(cli, facts);
        const out: Array<{ id: number; kind: string; bytes: number }> = [];
        for (const kind of ['binary', 'rsc'] as const) out.push(await this.backups.backupOne(cli, cred, facts, kind));
        return out;
      });
      const binary = stored.find((s) => s.kind === 'binary');
      if (!binary) throw new SiteRenameError('backup_failed', 'Le routeur n’a produit aucune sauvegarde binaire : refus.');
      await patchJob(this.jobId, { backup_id: binary.id });
      return {
        backupId: binary.id,
        output: `sauvegarde préalable #${binary.id} stockée (${stored.map((s) => `${s.kind} ${s.bytes} o`).join(', ')}), récupérée par SFTP et effacée du routeur`,
        detail: { backupIds: stored.map((s) => s.id), road: 'sftp' },
      };
    });
  }

  // ── apply ────────────────────────────────────────────────────────────────

  private lineCtx(login: boolean, identity: boolean) {
    const f = this.requireFrozen();
    return {
      jobId: this.jobId,
      revertAfterS: f.revert_after_s,
      login: login ? { client: f.tunnel_client as string, from: f.from_login, to: f.to_login } : null,
      identity: identity ? { to: f.to_identity } : null,
    };
  }

  private judged(lines: string[], login: boolean, identity: boolean): void {
    try {
      assertSiteRenameOnlyLines(lines, this.lineCtx(login, identity));
    } catch (err) {
      if (err instanceof SiteRenameLineRefused || err instanceof SiteRenameInputError) {
        throw new SiteRenameError('line_outside_site_rename', `${err.message} — rien n’a été envoyé.`);
      }
      throw err;
    }
  }

  async apply(onWrite: () => void): Promise<SiteRenameStepResult> {
    return this.held(async () => {
      const f = this.requireFrozen();
      const plan = this.requirePlan();
      const facts = this.requireFacts();
      await assertWritable(this.requireChr().tenant_id);
      const out: string[] = [];

      if (plan.chr === 'add') out.push(await this.writeChr());

      if (plan.routerLogin === 'cut') {
        try {
          await this.startCut(facts, onWrite);
        } catch (err) {
          // Nothing left on the router that needs the new account: the CHR's
          // own write is undone before the failure leaves.
          if (this.cutAt === null) await this.undoChr('la ligne du routeur n’est pas partie').catch((e) => logger.error({ err: e, jobId: this.jobId }, 'site_rename: CHR undo failed'));
          throw err;
        }
        out.push(this.cutAt !== null ? `tunnel de gestion basculé sur « ${f.to_login} » (${this.sent.cut?.status ?? '?'})` : 'la ligne du tunnel n’est pas partie');
      } else if (plan.routerIdentity === 'set') {
        await withProvenCli(facts, this.ctx('apply'), async (cli) => {
          const r = await readRouter(cli, f.tunnel_client, f.from_login, f.to_login);
          if (r.identity !== this.routerBefore?.identity) {
            throw new SiteRenameError('state_changed', `L’identité du routeur a changé depuis l’inspection (« ${r.identity ?? '—'} ») : rien n’a été écrit ; relancez la tâche.`);
          }
          await this.setIdentity(cli, onWrite);
        });
        out.push(`identité « ${f.to_identity} » écrite`);
      }
      await patchJob(this.jobId, { sent: JSON.stringify({ ...this.sent, ...(this.guardCheck ? { self_revert_check: this.guardCheck } : {}) }) });
      return { output: out.length > 0 ? out.join(' ; ') : 'rien à écrire sur le CHR ni sur le routeur', detail: { sent: this.sent, chrMode: this.chrMode, guardCheck: this.guardCheck } };
    });
  }

  /** 1: the secret named <to> on the CHR. Returns the step's sentence. */
  private async writeChr(): Promise<string> {
    const f = this.requireFrozen();
    const plan = this.requirePlan();
    const caseOnly = isCaseOnlyChange(f.from_login, f.to_login);
    const outcome = await this.onChr(async (conn) => {
      // Read again on the session that writes: the CHR is shared.
      const again = await this.readChr(conn);
      const replan = siteRenamePlan(f, again, this.routerBefore, await this.currentNames());
      if (replan.refusal || replan.chr !== 'add' || replan.fromId !== plan.fromId) {
        return { refused: replan.refusal?.message ?? 'le CHR a changé depuis l’inspection' };
      }
      const from = again.from[0];
      const words = ['/ppp/secret/add', `=copy-from=${from.id}`, `=name=${f.to_login}`];
      const comment = this.rewrittenComment(from.comment);
      if (comment !== null) words.push(`=comment=${comment}`);
      await patchJob(this.jobId, { chr_mode: 'copy', chr_written_at: db.fn.now(), chr_from_id: from.id });
      let r = await this.chrWrite(conn, words);
      let mode: SiteRenameChrMode = 'copy';
      if (!r.ok && caseOnly) {
        // The CHR keeps one secret per name WITHOUT case: the case-only rename
        // is done in place, and renamed back by ObliWAN if the new session
        // does not come up (operator decision 2026-10-07).
        const setWords = ['/ppp/secret/set', `=.id=${from.id}`, `=name=${f.to_login}`];
        if (comment !== null) setWords.push(`=comment=${comment}`);
        this.sent.chr_copy = { status: 'refused', said: r.said };
        await patchJob(this.jobId, { chr_mode: 'in_place' });
        mode = 'in_place';
        r = await this.chrWrite(conn, setWords);
      }
      if (!r.ok) {
        await patchJob(this.jobId, { chr_mode: null, chr_written_at: null });
        return { refused: `le CHR a refusé l’écriture : ${r.said}` };
      }
      const back = await this.readChr(conn);
      const to = back.to[0];
      const ok = back.to.length === 1 && to.remoteAddress === f.tunnel_address && to.service === from.service &&
        to.profile === from.profile && to.disabled === from.disabled && to.id !== null &&
        (mode === 'copy' ? back.from.length === 1 && back.from[0].id === from.id : back.from.length === 0 && to.id === from.id);
      return { mode, to: ok ? to : null, back };
    });
    if ('refused' in outcome) {
      throw new SiteRenameError('chr_refused', `CHR : ${outcome.refused}. Rien n’a été écrit sur le routeur.`);
    }
    this.chrMode = outcome.mode;
    if (!outcome.to) {
      await this.undoChr('la relecture du CHR ne montre pas le nouveau secret attendu');
      throw new SiteRenameError('chr_readback', `CHR : le secret « ${f.to_login} » relu n’a pas l’adresse, le service ou le profil de « ${f.from_login} » : écriture défaite, rien n’a été écrit sur le routeur.`);
    }
    this.toId = outcome.to.id;
    this.sent.chr = { status: 'accepted' };
    await patchJob(this.jobId, { chr_to_id: outcome.to.id });
    return outcome.mode === 'copy'
      ? `CHR : « ${f.to_login} » copié de « ${f.from_login} » (même mot de passe, adresse ${f.tunnel_address}), l’ancien gardé`
      : `CHR : la casse seule changeant et le CHR refusant un second compte, « ${f.from_login} » renommé en place en « ${f.to_login} »`;
  }

  /** ObliWAN's comment carries the site code; rewritten only when it is
   *  ObliWAN's for the OLD code and the code changes. */
  private rewrittenComment(comment: string | null): string | null {
    const f = this.requireFrozen();
    if (f.from_site_code === null || f.to_site_code === null || f.from_site_code === f.to_site_code) return null;
    return comment === `obliwan:site:${f.from_site_code}` ? `obliwan:site:${f.to_site_code}` : null;
  }

  /** Undo the CHR's write when nothing on the router needs it: the copy
   *  removed, or the in-place name put back — each after a re-read that shows
   *  the same .id, the frozen address and no live session under the new name. */
  private async undoChr(why: string): Promise<boolean> {
    const f = this.requireFrozen();
    const row = (await db('site_rename_jobs').where({ job_id: this.jobId }).first('chr_mode', 'chr_to_id', 'chr_written_at', 'chr_undone_at')) as
      | { chr_mode: SiteRenameChrMode | null; chr_to_id: string | null; chr_written_at: Date | null; chr_undone_at: Date | null }
      | undefined;
    if (!row || row.chr_written_at === null || row.chr_undone_at !== null || !row.chr_to_id) return false;
    const done = await this.onChr(async (conn) => {
      const now = await this.readChr(conn);
      const to = now.to[0];
      if (now.to.length !== 1 || to.id !== row.chr_to_id || to.remoteAddress !== f.tunnel_address || now.toActive) return false;
      const words = row.chr_mode === 'in_place'
        ? ['/ppp/secret/set', `=.id=${row.chr_to_id}`, `=name=${f.from_login}`]
        : ['/ppp/secret/remove', `=.id=${row.chr_to_id}`];
      // An in-place rename that rewrote ObliWAN's comment puts it back too.
      if (row.chr_mode === 'in_place' && f.from_site_code !== null && f.to_site_code !== null &&
        f.from_site_code !== f.to_site_code && to.comment === `obliwan:site:${f.to_site_code}`) {
        words.push(`=comment=obliwan:site:${f.from_site_code}`);
      }
      const r = await this.chrWrite(conn, words);
      return r.ok;
    });
    if (done) {
      await patchJob(this.jobId, { chr_undone_at: db.fn.now() });
      this.sent.chr_undo = { status: 'accepted', said: why };
      if (row.chr_mode === 'in_place') this.renamedBack = true;
    } else {
      this.sent.chr_undo = { status: 'not_sent', said: `${why} ; le CHR relu ne permet pas de défaire sans risque (secret changé ou session active)` };
    }
    return done;
  }

  /** 2, 3, 4: the self-revert, seen alive from a new session, the device row
   *  switched, then the cut. */
  private async startCut(facts: Facts, onWrite: () => void): Promise<void> {
    const f = this.requireFrozen();
    if (!f.tunnel_client) throw new SiteRenameError('internal', 'Le tunnel de gestion n’a pas été figé à l’inspection.');
    const guard = siteRenameSelfRevertLine(this.jobId, f.tunnel_client, f.from_login, f.to_login, f.revert_after_s);
    const cut = siteRenameCutLine(f.tunnel_client, f.from_login, f.to_login);
    this.judged([guard, cut], true, false);

    await withProvenCli(facts, this.ctx('apply'), async (cli) => {
      const r = await readRouter(cli, f.tunnel_client, f.from_login, f.to_login);
      if (r.client?.user !== this.routerBefore?.client?.user || r.client?.name !== f.tunnel_client || !r.client?.running) {
        throw new SiteRenameError('state_changed', 'Le tunnel de gestion du routeur a changé depuis l’inspection, ou ne tourne pas : rien n’a été envoyé au routeur ; relancez la tâche.');
      }
      onWrite();
      const { result, out } = await sendRaw(cli, guard);
      this.sent.self_revert = result;
      if (result.status !== 'accepted') {
        throw new SiteRenameError('self_revert_refused', `Le retour arrière n’a pas pu être lancé sur le routeur (${result.said ?? result.status}) : la ligne du tunnel n’est pas envoyée.`);
      }
      this.guardJobId = parseGuardJobId(out);
      this.guardAcceptedAt = deps.now();
      await patchJob(this.jobId, { self_revert_armed_at: db.fn.now() });
    });

    // The cut leaves only from a NEW proven session that still lists the
    // self-revert's job (legacy_compliance's rule).
    await deps.sleep(deps.guardSettleMs);
    let notSent: string | null = null;
    try {
      await withProvenCli(facts, this.ctx('apply'), async (cli) => {
        const id = this.guardJobId;
        const listed = id === null ? null : parseGuardJobAlive(await cli.read(LEGACY_SSH_READS.guardJob(id)));
        this.guardCheck = { id, listed, leadS: null };
        if (id === null) {
          notSent = ':execute n’a pas rendu d’identifiant de tâche : que le retour arrière survive à sa session ne peut pas être constaté';
          return;
        }
        if (listed !== true) {
          notSent = listed === false
            ? `la tâche ${id} du retour arrière n’est plus listée sur une nouvelle session : elle n’a pas survécu à la session qui l’a lancée`
            : `la présence de la tâche ${id} du retour arrière n’a pas pu être lue`;
          return;
        }
        const r = await readRouter(cli, f.tunnel_client, f.from_login, f.to_login);
        if (r.client?.user !== this.routerBefore?.client?.user || !r.client?.running) {
          notSent = 'le tunnel de gestion relu n’est plus celui que le retour arrière surveille';
          return;
        }
        const leadS = Math.round((deps.now() - (this.guardAcceptedAt as number)) / 1000);
        this.guardCheck.leadS = leadS;
        if (leadS > SITE_RENAME_GUARD_MAX_LEAD_S) {
          notSent = `le retour arrière a démarré il y a ${leadS} s (plus de ${SITE_RENAME_GUARD_MAX_LEAD_S} s) : il jugerait le tunnel trop tôt`;
          return;
        }
        // T1: the device row follows the router just before it moves, so the
        // new session is attributed to the device the moment it opens.
        await this.switchDbLogin('to');
        const open = (await db('ppp_sessions').where({ concentrator_id: this.requireChr().id, ppp_username: f.from_login })
          .whereNull('ended_at').first('id')) as { id: string | number } | undefined;
        this.precutFromSession = open ? String(open.id) : null;
        await patchJob(this.jobId, { cut_sent_at: db.fn.now() });
        this.cutAt = deps.now();
        const sent = await sendRaw(cli, cut, deps.cutTimeoutMs);
        // The tunnel the session rides restarts on this very line.
        this.sent.cut = sent.result.status === 'lost' ? { status: 'dropped', said: sent.result.said } : sent.result;
        if (sent.result.status === 'refused') {
          this.cutAt = null;
          await this.switchDbLogin('back');
          await patchJob(this.jobId, { cut_sent_at: null });
          throw new SiteRenameError('cut_refused', `Le routeur a refusé la ligne du tunnel (${sent.result.said}) : rien n’a changé sur le routeur ; le CHR est remis en état.`);
        }
      });
    } catch (err) {
      if (err instanceof SiteRenameError) throw err;
      if (err instanceof ManagementAccessError && err.kind === 'identity_mismatch') throw err;
      if (this.cutAt !== null) throw err;
      notSent = `la nouvelle session qui devait constater le retour arrière n’a pas pu s’ouvrir (${(err instanceof Error ? err.message : String(err)).slice(0, 200)})`;
    }
    if (notSent !== null && this.cutAt === null) {
      this.sent.cut = { status: 'not_sent', said: notSent };
      throw new SiteRenameError('self_revert_unconfirmed', `La ligne du tunnel n’est pas envoyée : ${notSent}. Le retour arrière lancé sur le routeur se retire de lui-même (le tunnel tourne).`);
    }
  }

  /** T1 and its reverse, in ONE transaction under the allocation lock. */
  private async switchDbLogin(direction: 'to' | 'back'): Promise<void> {
    const f = this.requireFrozen();
    const [a, b] = direction === 'to' ? [f.from_login, f.to_login] : [f.to_login, f.from_login];
    await db.transaction(async (trx) => {
      await takeAllocationLock(trx);
      const n = await trx('devices').where({ id: this.device.id }).whereIn('ppp_username', [a, b])
        .update({ ppp_username: b, updated_at: trx.fn.now() });
      if (n === 0) {
        throw new SiteRenameError('device_login_moved', `Le login de la fiche n’est plus « ${a} » ni « ${b} » : rien n’est basculé.`);
      }
      if (f.site_id !== null) await renameAllocationNames(trx, f.site_id, f.tenant_id, { login: { from: a, to: b } });
      await trx('site_rename_jobs').where({ job_id: this.jobId })
        .update(direction === 'to' ? { db_login_switched_at: trx.fn.now(), updated_at: trx.fn.now() } : { db_login_restored_at: trx.fn.now(), updated_at: trx.fn.now() });
    });
  }

  private async setIdentity(cli: AuditedCli, onWrite: () => void): Promise<void> {
    const f = this.requireFrozen();
    const line = siteRenameIdentityLine(f.to_identity);
    this.judged([line], false, true);
    onWrite();
    const { result } = await sendRaw(cli, line);
    this.sent.identity = result;
    if (result.status !== 'accepted') {
      throw new SiteRenameError('identity_refused', `Le routeur n’a pas pris la nouvelle identité (${result.said ?? result.status}).`);
    }
    this.identityDone = true;
    // Identity watch sees the box answer the new name while the registry still holds the
    // old one: a `system_identity_renamed` event beyond case (the classifier
    // folds case, so a lowercase rename raises none). Never fails the job.
    try {
      const d = (await db('devices').where({ id: this.device.id }).first('serial')) as { serial: string | null } | undefined;
      await recordIdentityObservation(f.tenant_id, this.device.id, { systemIdentity: f.to_identity, serial: d?.serial ?? null }, { source: 'binding' });
    } catch (err) {
      logger.warn({ err, jobId: this.jobId }, 'site_rename: identity observation not recorded');
    }
    // T3: the row follows at once — the next identity check reads the new name.
    await db('devices').where({ id: this.device.id }).update({ system_identity: f.to_identity, updated_at: db.fn.now() });
    await patchJob(this.jobId, { identity_set_at: db.fn.now() });
  }

  // ── reconnect ────────────────────────────────────────────────────────────

  private async openSession(name: string): Promise<{ id: string } | null> {
    const row = (await db('ppp_sessions').where({ concentrator_id: this.requireChr().id, ppp_username: name })
      .whereNull('ended_at').orderBy('started_at', 'desc').first('id')) as { id: string | number } | undefined;
    return row ? { id: String(row.id) } : null;
  }

  async reconnect(): Promise<SiteRenameStepResult> {
    return this.held(async () => {
      const f = this.requireFrozen();
      const plan = this.requirePlan();
      const cutAt = this.cutAt;
      if (cutAt === null) throw new SiteRenameError('internal', 'Aucune ligne de tunnel n’a été envoyée.');
      const startedAt = this.guardAcceptedAt ?? cutAt;
      const decidedAt = startedAt + (f.revert_after_s + SITE_RENAME_GUARD_MARGIN_S) * 1000;
      const deadline = Math.max(cutAt + f.tunnel_wait_s * 1000, decidedAt + SITE_RENAME_GUARD_MARGIN_S * 1000);
      let lastLive = -Infinity;
      for (;;) {
        const now = deps.now();
        const to = await this.openSession(f.to_login);
        if (to && !this.toSeen) {
          this.toSeen = true;
          await patchJob(this.jobId, { to_session_seen_at: db.fn.now() });
        }
        const fromBack = await this.openSession(f.from_login);
        const reverted = fromBack !== null && fromBack.id !== this.precutFromSession && !to;
        if (reverted) return this.concludeReverted('la session de l’ancien login est revenue sur le CHR');

        if (this.toSeen && now >= decidedAt) {
          const facts = (await loadFacts(this.device.id, this.job.tenant_id)) ?? this.requireFacts();
          try {
            const r = await withProvenCli(facts, this.ctx('reconnect'), async (cli) => {
              const reading = await readRouter(cli, f.tunnel_client, f.from_login, f.to_login);
              const guard = parseSiteRenameGuardLog(await cli.read(SITE_RENAME_SSH_READS.guardLog(this.jobId)));
              if (reading.client?.user === f.to_login && reading.client.running && plan.routerIdentity === 'set' && !this.identityDone) {
                await this.setIdentity(cli, () => undefined);
              }
              return { reading, guard };
            });
            this.facts = facts;
            this.awaitedGuard = true;
            if (r.reading.client?.user !== f.to_login) {
              // The box dials the old login again: the self-revert fired.
              return this.concludeReverted(`le routeur compose de nouveau « ${r.reading.client?.user ?? '—'} »`);
            }
            return {
              output: `tunnel revenu sous « ${f.to_login} » ${Math.round((now - cutAt) / 1000)} s après la bascule ; retour arrière : ${verdictText(r.guard.verdict)}` +
                (plan.routerIdentity === 'set' ? ` ; identité « ${f.to_identity} » écrite` : ''),
              detail: { returnedAfterS: Math.round((now - cutAt) / 1000), guard: r.guard.verdict },
            };
          } catch (err) {
            if (err instanceof ManagementAccessError && err.kind === 'identity_mismatch') throw err;
            if (err instanceof SiteRenameError) throw err;
          }
        }

        // Past the decision with no new session recorded: the CHR itself is
        // asked (the presence listener may have missed an event), at most
        // every 15 s. The new login live -> seen. The old one live -> the
        // self-revert fired. Neither, in place: no old account to fall back
        // on, so ObliWAN renames the secret back itself (operator decision
        // 2026-10-07).
        if (!this.toSeen && now >= decidedAt && now - lastLive >= 15_000) {
          lastLive = now;
          const live = await this.onChr((conn) => this.readChr(conn)).catch(() => null);
          if (live?.toActive) {
            this.toSeen = true;
            await patchJob(this.jobId, { to_session_seen_at: db.fn.now() });
            continue;
          }
          if (live?.fromActive) return this.concludeReverted('le CHR voit de nouveau une session sous l’ancien login');
          if (live && this.chrMode === 'in_place' && !this.renamedBack) {
            await this.undoChr('la nouvelle session n’est pas montée à la décision du retour arrière');
            if (this.renamedBack) await this.switchDbLogin('back');
          }
        }

        if (now >= deadline) return this.concludeUnsettled();
        await deps.sleep(deps.pollMs);
      }
    });
  }

  private async concludeReverted(how: string): Promise<never> {
    const f = this.requireFrozen();
    const row = (await db('site_rename_jobs').where({ job_id: this.jobId }).first('db_login_restored_at')) as { db_login_restored_at: Date | null } | undefined;
    if (!row?.db_login_restored_at) await this.switchDbLogin('back');
    if (this.chrMode === 'copy') await this.undoChr('le routeur a repris l’ancien login').catch(() => false);
    if (this.identityDone) {
      // Not reachable on the cut path (the identity follows the new session),
      // kept so the row never claims an identity the job did not leave.
      await db('devices').where({ id: this.device.id }).update({ system_identity: f.from_identity, updated_at: db.fn.now() });
    }
    const detail =
      `Le retour arrière a remis « ${f.from_login} » sur le tunnel de gestion (${how}) : la nouvelle session n’est pas montée ` +
      `dans les ${f.revert_after_s} s. La fiche est revenue à « ${f.from_login} »` +
      (this.chrMode === 'copy' ? ', le secret copié est retiré du CHR quand c’est sûr.' : this.renamedBack ? ', le secret du CHR a été renommé en arrière.' : '.') +
      ' Vérifiez que le CHR accepte bien le nouveau nom avant de relancer.';
    await patchJob(this.jobId, { outcome: 'reverted', outcome_detail: detail.slice(0, 4000), sent: JSON.stringify(this.sent) });
    throw new SiteRenameError('rename_reverted', detail);
  }

  private async concludeUnsettled(): Promise<never> {
    const f = this.requireFrozen();
    // The device row holds the job's best guess: the new login if its session
    // was ever seen since the cut, the old one otherwise.
    const row = (await db('site_rename_jobs').where({ job_id: this.jobId }).first('db_login_restored_at')) as { db_login_restored_at: Date | null } | undefined;
    if (!this.toSeen && !row?.db_login_restored_at) await this.switchDbLogin('back');
    const backup = (await db('site_rename_jobs').where({ job_id: this.jobId }).first('backup_id'))?.backup_id;
    const detail =
      `Le tunnel de ${this.device.name ?? `#${this.device.id}`} n’est pas revenu dans les ${f.tunnel_wait_s} s qui suivent la ` +
      `bascule vers « ${f.to_login} ». Les deux comptes sont gardés sur le CHR${this.renamedBack ? ' (le secret renommé en place a été remis à l’ancien nom)' : ''} ; ` +
      `la fiche garde « ${this.toSeen ? f.to_login : f.from_login} ». Aucune vérification d’identité ne met le routeur en ` +
      'quarantaine tant que ce renommage reste incertain. Vérifiez le site, puis « Relancer » le même renommage.' +
      (backup ? ` La sauvegarde préalable #${backup} est conservée.` : '');
    await patchJob(this.jobId, { outcome: 'unsettled', outcome_detail: detail.slice(0, 4000), sent: JSON.stringify(this.sent) });
    throw new SiteRenameError('tunnel_not_back', detail);
  }

  // ── postcheck ────────────────────────────────────────────────────────────

  async verify(): Promise<SiteRenameStepResult> {
    return this.held(async () => {
      const f = this.requireFrozen();
      const plan = this.requirePlan();
      if (this.noop) {
        await patchJob(this.jobId, { outcome: 'present', outcome_detail: this.noopReason, observed: JSON.stringify({ readAt: new Date().toISOString(), noop: true }) });
        return { output: this.noopReason, detail: { outcome: 'present' } };
      }
      const problems: string[] = [];
      let router: RenameRouterReading | null = null;
      let guard: SiteRenameGuardVerdict | null = null;
      let chr: RenameChrReading | null = null;
      if (this.routerNeeded(f)) {
        const facts = (await loadFacts(this.device.id, this.job.tenant_id)) ?? this.requireFacts();
        const read = await withProvenCli(facts, this.ctx('postcheck'), async (cli) => ({
          reading: await readRouter(cli, f.tunnel_client, f.from_login, f.to_login),
          guard: this.awaitedGuard || this.cutAt !== null ? parseSiteRenameGuardLog(await cli.read(SITE_RENAME_SSH_READS.guardLog(this.jobId))).verdict : null,
        }));
        router = read.reading;
        guard = read.guard;
        if (plan.login) {
          if (router.client?.user !== f.to_login) problems.push(`le tunnel de gestion compose « ${router.client?.user ?? '—'} »`);
          else if (!router.client.running) problems.push('le tunnel de gestion ne tourne pas');
        }
        if (plan.identity && router.identity !== f.to_identity) problems.push(`le routeur s’annonce « ${router.identity ?? '—'} »`);
        if (guard === 'reverted') problems.push('le retour arrière a rendu son verdict REVERTED');
      }
      if (plan.login) {
        chr = await this.onChr((conn) => this.readChr(conn));
        const to = chr.to[0];
        if (chr.to.length !== 1 || to.remoteAddress !== f.tunnel_address) problems.push(`le CHR ne porte plus « ${f.to_login} » à ${f.tunnel_address}`);
        else {
          if (!this.toId) {
            this.toId = to.id;
            await patchJob(this.jobId, { chr_to_id: to.id });
          }
          if (!chr.toActive) problems.push(`le CHR ne voit pas de session « ${f.to_login} »`);
          else if (!this.toSeen) {
            this.toSeen = true;
            await patchJob(this.jobId, { to_session_seen_at: db.fn.now() });
          }
        }
      }
      const readAt = new Date().toISOString();
      await patchJob(this.jobId, { observed: JSON.stringify({ router, chr, guard, readAt }) });
      if (problems.length > 0) {
        const detail = `Relecture : ${problems.join(' ; ')}. Rien n’est finalisé sur la fiche ; « Relancer » reprend le même renommage.`;
        const wrote = this.cutAt !== null || this.identityDone;
        await patchJob(this.jobId, { outcome: wrote ? 'unsettled' : 'failed', outcome_detail: detail.slice(0, 4000) });
        throw new SiteRenameError('readback_failed', detail);
      }
      return {
        output: `relu sur une nouvelle session : ${[plan.login ? `login « ${f.to_login} » en service` : '', plan.identity ? `identité « ${f.to_identity} »` : '',
          guard ? `retour arrière : ${verdictText(guard)}` : ''].filter((s) => s !== '').join(' ; ') || 'rien à relire sur le routeur'}`,
        detail: { guard },
      };
    });
  }

  // ── cleanup (finalize) ───────────────────────────────────────────────────

  async finalize(): Promise<SiteRenameStepResult> {
    return this.held(async () => {
      const f = this.requireFrozen();
      const plan = this.requirePlan();
      const before = await this.currentNames();
      const chrId = this.requireChr().id;
      const toSecret = plan.login ? (await this.onChr((conn) => this.readChr(conn))).to[0] ?? null : null;
      await db.transaction(async (trx) => {
        await takeAllocationLock(trx);
        const patch: Record<string, unknown> = {};
        if (plan.login) patch.ppp_username = f.to_login;
        if (plan.identity) patch.system_identity = f.to_identity;
        if (Object.keys(patch).length > 0) {
          await trx('devices').where({ id: this.device.id, tenant_id: f.tenant_id }).update({ ...patch, updated_at: trx.fn.now() });
        }
        if (f.site_id !== null && (plan.login || plan.identity)) {
          await renameAllocationNames(trx, f.site_id, f.tenant_id, {
            ...(plan.login ? { login: { from: f.from_login, to: f.to_login } } : {}),
            ...(plan.identity ? { identity: { from: f.from_identity, to: f.to_identity } } : {}),
          });
        }
        if (plan.code && f.site_id !== null) {
          const toCode = f.to_site_code as string;
          const bench = Number((await trx('bench_provisionings').where({ site_id: f.site_id }).count<{ n: string }>({ n: '*' }).first())?.n ?? 0);
          const infra = Number((await trx('infra_site_accounts').where({ site_id: f.site_id }).count<{ n: string }>({ n: '*' }).first())?.n ?? 0);
          if (bench > 0 || infra > 0) {
            throw new SiteRenameError('site_code_locked', 'Le banc ou le concentrateur d’infrastructure a utilisé le code du site entre-temps : le code ne change pas.');
          }
          try {
            await assertSiteCodeFormat(trx, f.tenant_id, toCode, { renamingSiteId: f.site_id });
          } catch (err) {
            throw new SiteRenameError('site_code_invalid', err instanceof Error ? err.message : String(err));
          }
          const n = await trx('sites').where({ id: f.site_id, tenant_id: f.tenant_id }).whereIn('code', [f.from_site_code as string, toCode])
            .update({ code: toCode, updated_at: trx.fn.now() });
          if (n === 0) throw new SiteRenameError('site_code_moved', `Le code du site n’est plus « ${f.from_site_code} » : il n’est pas changé.`);
        }
        if (plan.login && toSecret) {
          await recordSecretInventoryChange(trx, chrId, {
            added: {
              name: f.to_login, remoteAddress: toSecret.remoteAddress, localAddress: toSecret.localAddress,
              profile: toSecret.profile, disabled: toSecret.disabled,
            },
            // Renamed in place (now or by the job this one settles): the old
            // name is gone from the CHR.
            ...(this.chrMode === 'in_place' || plan.fromId === null ? { removedName: f.from_login } : {}),
          }, new Date());
          await trx('discoveries').where({ concentrator_id: chrId, state: 'pending' }).whereIn('ppp_username', [f.from_login, f.to_login])
            .update({ state: 'bound', bound_device_id: this.device.id, reviewed_at: trx.fn.now(), updated_at: trx.fn.now() });
          await trx('ppp_sessions').where({ concentrator_id: chrId, ppp_username: f.to_login }).whereNull('ended_at').whereNull('device_id')
            .update({ device_id: this.device.id });
        }
        await appendAudit({
          tenantId: f.tenant_id,
          actorType: this.job.requested_by ? 'user' : 'system',
          actorId: this.job.requested_by ?? 'site_rename',
          action: 'device.renamed',
          entityType: 'device',
          entityId: this.device.id,
          before: { login: f.from_login, identity: f.from_identity, siteCode: f.from_site_code },
          after: { login: f.to_login, identity: f.to_identity, siteCode: f.to_site_code, jobId: this.jobId, chrMode: this.chrMode },
          correlationId: this.correlationId,
        }, trx);
        await trx('site_rename_jobs').where({ job_id: this.jobId }).update({ finalized_at: trx.fn.now(), updated_at: trx.fn.now() });
      });

      // The old secret, last: only once the new session is up, the old one
      // inactive, and its .id and address re-read unchanged.
      let oldNote = '';
      if (plan.login && this.chrMode !== 'in_place' && plan.removeOld) {
        const removed = await this.removeOldSecret();
        oldNote = removed
          ? ` ; ancien secret « ${f.from_login} » retiré du CHR`
          : ` ; ancien secret « ${f.from_login} » LAISSÉ sur le CHR (session encore ouverte ou secret changé) — « Relancer » le retirera`;
      }
      const summary = { deviceId: this.device.id, login: f.to_login, identity: f.to_identity, siteCode: f.to_site_code, jobId: this.jobId };
      emitToDevice(this.device.id, SOCKET_EVENTS.DEVICE_UPDATED, summary);
      emitToTenantAudience(f.tenant_id, SOCKET_EVENTS.DEVICE_UPDATED, summary, { deviceId: this.device.id });
      if (plan.code && f.site_id !== null) emitToTenantAudience(f.tenant_id, SOCKET_EVENTS.SITE_UPDATED, { siteId: f.site_id, code: f.to_site_code }, { siteId: f.site_id });
      const detail = `renommé : login « ${before.login} » -> « ${f.to_login} », identité « ${before.identity} » -> « ${f.to_identity} »` +
        (plan.code ? `, code « ${f.from_site_code} » -> « ${f.to_site_code} »` : '') +
        (this.chrMode === 'in_place' ? ' (secret du CHR renommé en place)' : '') + oldNote;
      await patchJob(this.jobId, {
        outcome: 'renamed',
        outcome_detail: detail.slice(0, 4000),
        ...(this.routerNeeded(f) ? {} : { observed: JSON.stringify({ readAt: new Date().toISOString(), dbOnly: true }) }),
      });
      return { output: detail, detail: { outcome: 'renamed' } };
    });
  }

  private async removeOldSecret(): Promise<boolean> {
    const f = this.requireFrozen();
    const row = (await db('site_rename_jobs').where({ job_id: this.jobId }).first('chr_from_id', 'to_session_seen_at')) as
      | { chr_from_id: string | null; to_session_seen_at: Date | null }
      | undefined;
    if (!row?.to_session_seen_at) return false;
    const chrId = this.requireChr().id;
    const removed = await this.onChr(async (conn) => {
      const now = await this.readChr(conn);
      const from = now.from[0];
      if (now.from.length !== 1 || now.fromActive || !now.toActive || from.remoteAddress !== f.tunnel_address ||
        (row.chr_from_id !== null && from.id !== row.chr_from_id) || from.id === null) return false;
      return (await this.chrWrite(conn, ['/ppp/secret/remove', `=.id=${from.id}`])).ok;
    });
    if (removed) {
      await db.transaction(async (trx) => {
        await recordSecretInventoryChange(trx, chrId, { removedName: f.from_login }, new Date());
        await trx('site_rename_jobs').where({ job_id: this.jobId }).update({ chr_old_removed_at: trx.fn.now(), updated_at: trx.fn.now() });
      });
    }
    return removed;
  }
}

function verdictText(v: SiteRenameGuardVerdict): string {
  return v === 'stood_down' ? 'retiré (le tunnel tournait)' : v === 'reverted' ? 'REVERTED' : 'aucune ligne dans le journal du routeur';
}
