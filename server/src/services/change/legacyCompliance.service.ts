/**
 * ObliWAN — bringing ONE MikroTik in service up to the corrected customer
 * templates (operator decision 2026-10-04), by a change job over SSH (kind
 * `legacy_compliance`, migration 066; the lines, the allow-list, the plan and
 * the expected read-back state are shared/src/legacyCompliance.ts).
 *
 * ┌─ WHY THIS JOB EXISTS, AND WHY IT IS NARROW ───────────────────────────────┐
 * │ The routers configured before ObliWAN carry the templates as they were:   │
 * │ mac-server and mac-winbox restricted to the LAN list, RoMON sometimes     │
 * │ off, ssh and winbox open to the management range and 192.168.88.0/24 but  │
 * │ not to the store's own LAN, no DNS-Amp rules. The NCM models none of      │
 * │ those menus, so no plan can carry the correction; this job sends the      │
 * │ statements of the shared builder and nothing else, every line judged by   │
 * │ `assertLegacyComplianceOnlyLines` before it is sent.                      │
 * │ It reuses the device's EXISTING SSH credential — on these routers the     │
 * │ legacy administrator account, or ObliWAN's own `obliwan` once a           │
 * │ management_access job created it and switched to it — and creates no      │
 * │ account on the router (creating `obliwan` is management_access's alone).  │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ RANDOM-SOURCE-PORT IS RETIRED (operator decision 2026-10-05) ────────────┐
 * │ The l2tp fix is in shared `LEGACY_RETIRED_FIXES`: a production job READS  │
 * │ random-source-port, reports it (skipped, `retired`) and never writes it — │
 * │ the right value depends on the site's operator and box, both values work  │
 * │ in the fleet, and the value of a router that works is never changed       │
 * │ (shared header). The job freezes the six other fixes; one whose frozen    │
 * │ list still names the l2tp fix writes nothing for it either. With no l2tp  │
 * │ line, no self-revert is started and no tunnel restarts: `reconnect` is    │
 * │ SKIPPED and a–e is the whole write. The box below describes the DORMANT   │
 * │ machinery, kept and exercised by the harness (`retiredFixes: []`).        │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE ONE LINE THAT CUTS ITS OWN PATH, AND ITS NET (dormant) ──────────────┐
 * │ a–e cannot cut the SSH path the job travels on: they only OPEN            │
 * │ mac-server, mac-winbox and RoMON, and only ADD an address to the ssh and  │
 * │ winbox lists. Whether RouterOS keeps an ESTABLISHED session when the ssh  │
 * │ service's list changes is not established, so the ssh line is the last    │
 * │ of a–e, and a session lost on exactly that line sends the l2tp pair on a  │
 * │ fresh, identity-proven session. The l2tp line restarts every client it    │
 * │ changes — the tunnel the job rides included — and many Chateaux run       │
 * │ device-mode `home`, where the scheduler (hence an on-box dead-man) is     │
 * │ denied. So:                                                               │
 * │  1. it is the LAST command, alone, and the session dropping on it is the  │
 * │     expected answer, not a failure;                                       │
 * │  2. before it, a self-revert is started ON THE ROUTER with `:execute`     │
 * │     (shared `legacySelfRevertLine`): after `revert_after_s` it puts       │
 * │     random-source-port back to `no` on the clients the line changed       │
 * │     unless EVERY watched one (changed AND running before) is running, and │
 * │     logs its decision either way. Refused by the router -> the l2tp line  │
 * │     is not sent. Accepted, it printed its job id; the session that        │
 * │     started it is then ENDED, and the l2tp line leaves only from a new,   │
 * │     identity-proven session on which that id is still listed in           │
 * │     `/system script job`, within `LEGACY_GUARD_MAX_LEAD_S` of the start:  │
 * │     the self-revert outliving the session that started it — the one      │
 * │     thing the net rests on — is OBSERVED on each router before the line   │
 * │     that needs it, never assumed. Not listed -> the line is not sent;     │
 * │  3. the job then waits, bounded by `tunnel_wait_s`, for the device's PPP  │
 * │     session to come back on the concentrator (a device whose PPP          │
 * │     session is down is never dialled), AND past the self-revert's         │
 * │     decision, and reads back on a FRESH, identity-proven session — the    │
 * │     state and the self-revert's own log line. Waiting past the decision   │
 * │     makes the outcome final: a job that read back at second 20 could      │
 * │     report success on a router its guard reverts at second 120. A         │
 * │     tunnel that does not come back within the bound fails the job by      │
 * │     name; the self-revert is then the router's only way back.             │
 * │ That `:execute` runs under device-mode `home`, returns its job's id and   │
 * │ that the job outlives its session are REASONED (shared header), which is  │
 * │ why 2 checks the last two on each router; the read-back still reports     │
 * │ "no log line" when the guard left none, it never assumes it ran. Once a   │
 * │ tunnel stays down nothing the job does reaches the router: the            │
 * │ self-revert seen alive before the line is then the whole net.             │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * THE JOB, STEP BY STEP (a branch of `runPhases()` in apply.service.ts):
 *   bind_assert       identity check over SSH (`assertMikrotikBindingOverSsh`).
 *   guard             ACCEPT by construction (`legacyComplianceGuard`).
 *   lint              the SSH address did not move, the SFTP road is proven,
 *                     then on one proven session: the reading, the plan, the
 *                     lines built and passed through the allow-list. Nothing
 *                     needed -> nothing written, no backup.
 *   preflight_backup  binary + rsc pulled by SFTP (`SshPreflightBackup`).
 *   arm_deadman       SKIPPED (LEGACY_COMPLIANCE_NO_DEADMAN).
 *   apply             on the writing session: read again (a router that
 *                     changed since lint is refused, nothing written), a–e
 *                     one command each (winbox before ssh). Dormant while the
 *                     l2tp fix is retired: then the self-revert (on a fresh
 *                     proven session when the ssh line took the first one with
 *                     it); then, on a NEW proven session, the self-revert's
 *                     job seen alive, the router read again, and the l2tp line.
 *   reconnect         the tunnel's return and the self-revert's decision,
 *                     waited for (SKIPPED when no running tunnel was changed —
 *                     always, while the l2tp fix is retired).
 *   postcheck         the read-back on a new session, the per-fix outcome.
 *
 * WHAT IS NOT OBSERVED: no line of this file has reached a router. The console
 * reads (`:tostr` spellings, `/system device-mode get`, `/log find`) are
 * REASONED from the RouterOS manual; testing/legacyCompliance.verify.ts runs
 * them against a fake MikroTik answering by the same assumptions.
 *
 * Operator-facing sentences are French, like management_access's.
 */

import {
  LEGACY_COMPLIANCE_KIND,
  LEGACY_DNS_AMP_COMMENT,
  LEGACY_FIX_KEYS,
  LEGACY_GUARD_JOB_TAG,
  LEGACY_GUARD_MARGIN_S,
  LEGACY_GUARD_MAX_LEAD_S,
  LEGACY_GUARD_REVERTED,
  LEGACY_GUARD_STOOD_DOWN,
  LEGACY_RETIRED_FIXES,
  LEGACY_REVERT_AFTER_S,
  LEGACY_TUNNEL_WAIT_S,
  LegacyComplianceInputError,
  LegacyComplianceLineRefused,
  SOCKET_EVENTS,
  assertLegacyComplianceOnlyLines,
  isActiveJobStatus,
  legacyComplianceLines,
  legacyFixHolds,
  legacyGuardLogPrefix,
  legacyOutcomeFails,
  legacyPlan,
  legacyPlanIsNoop,
  legacyReasonUnobserved,
  legacyRequestedFixes,
  legacyWatchedNotRunning,
  type ChangeJobStatus,
  type LegacyCompliancePlan,
  type LegacyComplianceReading,
  type LegacyFilterRuleReading,
  type LegacyFixKey,
  type LegacyFixOutcome,
  type LegacyFixWarning,
  type LegacyL2tpClientReading,
  type LegacyLanDerivation,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { emitToDevice } from '../fleet/fleetEvents';
import { emitToTenantAudience } from '../fleet/scopedEmit';
import { featureVerdict } from '../../bench/deviceModeGate';
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
import { isNonPublicAddress } from './transfer.service';
import { KillSwitchEngagedError, readKillSwitch } from './killSwitch.service';
import { DeviceBusyError, renewLease, type ChangeJobRow } from './jobQueue.service';

// ============================================================================
// Vocabulary
// ============================================================================

/**
 * What the job concluded. Mirrors `legacy_compliance_jobs_outcome_chk` (066).
 *  - `applied`  this job wrote, and the read-back holds every fix it could
 *               (skips named, a RoMON refusal recorded);
 *  - `present`  nothing needed writing: nothing written, no backup;
 *  - `refused`  ended before anything was written on the router;
 *  - `failed`   ended after a write on the router.
 */
export const LEGACY_COMPLIANCE_OUTCOMES = ['applied', 'present', 'refused', 'failed'] as const;
export type LegacyComplianceOutcome = (typeof LEGACY_COMPLIANCE_OUTCOMES)[number];

export class LegacyComplianceError extends Error {
  constructor(readonly kind: string, message: string, readonly httpStatus = 409) {
    super(message);
    this.name = 'LegacyComplianceError';
  }
}

export const LEGACY_COMPLIANCE_NO_DEADMAN =
  "Aucun dead-man n'est armé sur le routeur pour 'legacy_compliance' : beaucoup de Chateau sont en device-mode " +
  "« home », où le planificateur est bloqué. Les correctifs a–e n'ouvrent que mac-server, mac-winbox et RoMON, " +
  "n'AJOUTENT que les deux règles DNS-Amp (rejet du port 53 venant de la liste WAN) et une adresse aux listes ssh et " +
  "winbox : rien ne peut couper le chemin SSH de la tâche. random-source-port n'est plus écrit (correctif retiré " +
  "le 2026-10-05 : la bonne valeur dépend de l'opérateur et de la box du site) : aucune ligne ne redémarre les " +
  'tunnels L2TP. La tâche relit sur une nouvelle session. La ' +
  'sauvegarde préalable est prise avant la première écriture ; la tâche est mise en file au niveau de sécurité ' +
  'degraded, avec la confirmation explicite de l’opérateur.';

export const LEGACY_COMPLIANCE_NO_APPLY_OUTCOME =
  "No row written to apply_outcomes: 'legacy_compliance' sends template corrections with no on-box dead-man; " +
  'it is not an observation of how this hardware survives a change. Its outcome is on legacy_compliance_jobs.';

export function legacyComplianceGuard(): { verdict: 'ACCEPT'; reasons: unknown[]; summary: string; unavailable: false } {
  return {
    verdict: 'ACCEPT',
    reasons: [
      {
        code: 'LEGACY_COMPLIANCE_ADDITIVE',
        effect: 'accept',
        message:
          'Opens mac-server and mac-winbox to every interface and enables RoMON (never restricts them), adds the ' +
          'two DNS-Amp input rules (reject udp/tcp 53 arriving on the WAN list) when missing, adds the store LAN ' +
          'network to the ssh and winbox address lists when they are restricted and lack it (never removes an ' +
          'address). random-source-port on the l2tp-clients is read and never written (fix retired 2026-10-05: the ' +
          'right value depends on the site\'s operator and box), so no line restarts the tunnels. Any other line is ' +
          'refused before anything is sent; the IPsec policy, the netwatch entries, every other firewall rule, ' +
          'routes and users are never written.',
      },
    ],
    summary:
      'Management-Path Guard: ACCEPT — the template corrections only open or add, and none restarts the tunnels ' +
      '(no plan was simulated: the job refuses any other line).',
    unavailable: false,
  };
}

export function legacyComplianceSafetyNet(): {
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
      "DEGRADED — aucun dead-man n'est armé ; les correctifs n'ouvrent ou n'ajoutent que ce qui manque, et " +
      'random-source-port n’est plus écrit : aucune ligne ne redémarre le tunnel. La sauvegarde préalable, récupérée ' +
      'par SFTP avant la première écriture, est le seul filet. La règle de sécurité exige une confirmation explicite et tracée.',
    unverified: false,
    requiresConfirmation: true,
  };
}

// ============================================================================
// Dependencies (test seams)
// ============================================================================

export interface LegacyComplianceDeps {
  /** Milliseconds; the tunnel wait is measured on it. */
  now(): number;
  sleep(ms: number): Promise<void>;
  /** Between two looks at the PPP session / two probes. */
  pollMs: number;
  /** The l2tp line's own budget: its session is expected to drop. */
  cutTimeoutMs: number;
  /** Between the end of the session that started the self-revert and the
   *  look at its job from a new one: the router's teardown of a closed
   *  session is not instantaneous, and a look that beat it would see a job
   *  about to die. */
  guardSettleMs: number;
  /** The fixes no job writes (shared `LEGACY_RETIRED_FIXES`): left out of the
   *  frozen list at enqueue, and skipped as `retired` by every plan whatever
   *  the frozen list says. The harness sets `[]` to exercise the dormant
   *  machinery. */
  retiredFixes: readonly LegacyFixKey[];
}
const DEFAULT_DEPS: LegacyComplianceDeps = {
  now: () => Date.now(),
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  pollMs: 5_000,
  cutTimeoutMs: 15_000,
  guardSettleMs: 3_000,
  retiredFixes: LEGACY_RETIRED_FIXES,
};
let deps: LegacyComplianceDeps = { ...DEFAULT_DEPS };
export function setLegacyComplianceDeps(next: Partial<LegacyComplianceDeps>): LegacyComplianceDeps {
  deps = { ...deps, ...next };
  return deps;
}
export function resetLegacyComplianceDeps(): void {
  deps = { ...DEFAULT_DEPS };
}

// ============================================================================
// The console reads (pure text) and their parsers
// ============================================================================

/** The DNS-Amp read prints, per rule carrying the comment, these properties
 *  in this order (`fwamp|`-tagged, `|`-joined). The first seven decide
 *  whether it is the operator's rule; any of the others set = a narrower
 *  variant. A property `get` cannot read prints empty (an unset matcher). */
export const LEGACY_DNS_AMP_PROPS = [
  'chain', 'action', 'protocol', 'dst-port', 'in-interface-list', 'reject-with', 'disabled',
  'src-address', 'src-address-list', 'dst-address', 'dst-address-type', 'in-interface', 'connection-state',
] as const;

function dnsAmpRead(): string {
  const gets = LEGACY_DNS_AMP_PROPS.map((p, i) =>
    `:local p${i} ""; :do { :set p${i} [:tostr [/ip firewall filter get $r ${p}]] } on-error={}`).join('; ');
  const row = LEGACY_DNS_AMP_PROPS.map((_, i) => `$p${i}`).join(' . "|" . ');
  return ':put "fw|begin"; :put ("fwinput|" . [:len [/ip firewall filter find where chain=input]]); ' +
    `:foreach r in=[/ip firewall filter find where comment="${LEGACY_DNS_AMP_COMMENT}"] do={ ${gets}; :put ("fwamp|" . ${row}) }; ` +
    ':put "fw|end"';
}

/**
 * One command per read, each tagged. A bracketed read prints its `end`
 * marker only when it completed, so a read that stopped part-way is UNREAD,
 * never a short list. Reads that may legitimately not exist (device-mode
 * before 7.13, random-source-port on RouterOS 6) are guarded, and their
 * absence printed as such.
 */
export const LEGACY_SSH_READS = {
  version: ':put ("version|" . [/system resource get version])',
  macServer: ':put ("macsrv|" . [:tostr [/tool mac-server get allowed-interface-list]])',
  macWinbox: ':put ("macwb|" . [:tostr [/tool mac-server mac-winbox get allowed-interface-list]])',
  romon: ':put ("romon|" . [:tostr [/tool romon get enabled]])',
  deviceMode:
    ':local m ""; :local r ""; :do { :set m [:tostr [/system device-mode get mode]] } on-error={}; ' +
    ':do { :set r [:tostr [/system device-mode get romon]] } on-error={}; :put ("devmode|" . $m . "|" . $r)',
  // The CONFIGURED rows only: RouterOS 7.24.5 lists every open connection to
  // a service as a dynamic entry of the same name, with no address list —
  // this job's own SSH session among them. A row whose `dynamic` reads "true"
  // is skipped; one whose `get … dynamic` fails (7.16, no such property, and
  // no such entries) is a service. Why `get` and not `find where … !dynamic`,
  // and what is REASONED: shared/src/routerOsService.ts. Two rows of one name
  // left anyway are judged unread by the plan (shared `legacyPlan`).
  services:
    ':put "svcs|begin"; :foreach s in=[/ip service find where name="ssh" or name="winbox"] do={ :local d ""; ' +
    ':do { :set d [:tostr [/ip service get $s dynamic]] } on-error={}; :if ($d != "true") do={ ' +
    ':local a ""; :do { :set a [:tostr [/ip service get $s available-from]] } on-error={ ' +
    ':do { :set a [:tostr [/ip service get $s address]] } on-error={} }; :put ("svc|" . ' +
    // `available-from` on recent RouterOS 7 (7.24.5), `address` before (7.16
    // is still in the fleet): reading only the old name read every list as
    // empty, i.e. "open to every address", on the new builds.
    '[/ip service get $s name] . "|" . $a) } }; :put "svcs|end"',
  bridges: ':put "bridges|begin"; :foreach b in=[/interface bridge find] do={ :put ("bridge|" . [/interface bridge get $b name]) }; :put "bridges|end"',
  lanList:
    ':put "lanlist|begin"; :foreach m in=[/interface list member find where list="LAN" and disabled=no] do={ ' +
    ':put ("lanmember|" . [:tostr [/interface list member get $m interface]]) }; :put "lanlist|end"',
  addresses:
    ':put "addrs|begin"; :foreach a in=[/ip address find where disabled=no] do={ :put ("addr|" . ' +
    '[:tostr [/ip address get $a interface]] . "|" . [:tostr [/ip address get $a address]]) }; :put "addrs|end"',
  l2tp:
    ':put "l2tp|begin"; :foreach i in=[/interface l2tp-client find] do={ :local r "absent"; ' +
    ':do { :set r [:tostr [/interface l2tp-client get $i random-source-port]] } on-error={}; ' +
    ':put ("l2tpc|" . [/interface l2tp-client get $i name] . "|" . $r . "|" . ' +
    '[:tostr [/interface l2tp-client get $i running]] . "|" . [:tostr [/interface l2tp-client get $i disabled]]) }; :put "l2tp|end"',
  wan:
    ':put "wan|begin"; :put ("wanexists|" . [:len [/interface list find where name="WAN"]]); ' +
    ':foreach m in=[/interface list member find where list="WAN" and disabled=no] do={ ' +
    ':put ("wanmember|" . [:tostr [/interface list member get $m interface]]) }; :put "wan|end"',
  dnsAmp: dnsAmpRead(),
  dnsRemote: ':put ("dnsremote|" . [:tostr [/ip dns get allow-remote-requests]])',
  ipsecPolicies:
    ':local n "unread"; :do { :set n [:len [/ip ipsec policy find where disabled=no and template=no and dynamic=no]] } on-error={}; ' +
    ':put ("ipsecpol|" . $n)',
  /** The self-revert's decision, by its log prefix (digits and fixed text). */
  guardLog: (jobId: number): string =>
    `:foreach l in=[/log find where message~"${legacyGuardLogPrefix(jobId)}"] do={ :put ("log|" . [/log get $l message]) }`,
  /** Whether the self-revert's job is still listed. `id` is what `:execute`
   *  printed, accepted only in RouterOS's `*<hex>` shape (`parseGuardJobId`). */
  guardJob: (id: string): string => {
    if (!SCRIPT_JOB_ID_RE.test(id)) throw new LegacyComplianceError('internal', 'Identifiant de tâche RouterOS invalide.');
    return `:put ("revertalive|" . [:len [/system script job find where .id=${id}]])`;
  },
} as const;

/** A RouterOS internal id as `:execute` returns it (`*1A2`). */
const SCRIPT_JOB_ID_RE = /^\*[0-9A-Fa-f]{1,8}$/;

/** The id the self-revert line printed; null when it printed none this file
 *  can carry into the next read. */
export function parseGuardJobId(out: string): string | null {
  const id = single(out, LEGACY_GUARD_JOB_TAG);
  return id !== null && SCRIPT_JOB_ID_RE.test(id) ? id : null;
}

/** `revertalive|1` -> true, `revertalive|0` -> false, anything else unread. */
export function parseGuardJobAlive(out: string): boolean | null {
  const n = single(out, 'revertalive');
  if (n === null || !/^\d+$/.test(n)) return null;
  return Number(n) > 0;
}

function lines(out: string): string[] {
  return out.split(/\r?\n/).map((l) => l.replace(/\r$/, '').trim());
}

function tagged(out: string, tag: string): string[][] {
  return lines(out).filter((l) => l.startsWith(`${tag}|`)).map((l) => l.slice(tag.length + 1).split('|'));
}

/** The one value of a single-line read; null when the tag is absent. */
function single(out: string, tag: string): string | null {
  const row = tagged(out, tag)[0];
  return row === undefined ? null : row.join('|').trim();
}

function bracketed(out: string, bracket: string, tag: string): string[][] | null {
  return lines(out).some((l) => l === `${bracket}|end`) ? tagged(out, tag) : null;
}

const yes = (v: string | undefined): boolean => ['true', 'yes'].includes((v ?? '').trim().toLowerCase());

function flag(v: string): boolean | undefined {
  const t = v.trim().toLowerCase();
  if (t === 'yes' || t === 'true') return true;
  if (t === 'no' || t === 'false') return false;
  return undefined;
}

export interface LegacyRawReads {
  version: string;
  macServer: string;
  macWinbox: string;
  romon: string;
  deviceMode: string;
  services: string;
  bridges: string;
  lanList: string;
  addresses: string;
  l2tp: string;
  wan: string;
  dnsAmp: string;
  dnsRemote: string;
  ipsecPolicies: string;
}

/** The WAN read: null unless it completed and said whether the list exists. */
function parseWan(out: string): LegacyComplianceReading['wan'] {
  if (!lines(out).some((l) => l === 'wan|end')) return null;
  const n = single(out, 'wanexists');
  if (n === null || !/^\d+$/.test(n)) return null;
  return { exists: Number(n) > 0, members: tagged(out, 'wanmember').map(([m]) => (m ?? '').trim()).filter((m) => m !== '') };
}

/** The DNS-Amp read: null unless it completed, counted the input chain and
 *  printed every property of every rule (a row of another width, or a
 *  `disabled` that is not a flag, makes the whole read unread). */
export function parseDnsAmp(out: string): LegacyComplianceReading['dnsAmp'] {
  const rows = bracketed(out, 'fw', 'fwamp');
  const n = single(out, 'fwinput');
  if (rows === null || n === null || !/^\d+$/.test(n)) return null;
  const rules: LegacyFilterRuleReading[] = [];
  for (const r of rows) {
    if (r.length !== LEGACY_DNS_AMP_PROPS.length) return null;
    const v = r.map((x) => (x ?? '').trim());
    const disabled = flag(v[6]);
    if (disabled === undefined) return null;
    rules.push({
      chain: v[0], action: v[1], protocol: v[2], dstPort: v[3], inInterfaceList: v[4], rejectWith: v[5],
      disabled, narrowed: v.slice(7).some((x) => x !== ''),
    });
  }
  return { inputRules: Number(n), rules };
}

export function parseLegacyReading(raw: LegacyRawReads): LegacyComplianceReading {
  const [mode, romonFlag] = (tagged(raw.deviceMode, 'devmode')[0] ?? []).map((v) => (v ?? '').trim());
  const flags: Record<string, boolean> = {};
  const f = flag(romonFlag ?? '');
  if (f !== undefined) flags.romon = f;
  // bench/deviceModeGate.ts is the one reader of MikroTik's device-mode table:
  // a printed flag decides, `home` with none printed denies RoMON, anything
  // else is unknown — and unknown is attempted, the router having the word.
  const romonDeviceMode = featureVerdict(
    { answered: Boolean(mode) || f !== undefined, mode: mode ? mode.toLowerCase() : null, flags, observedAt: new Date().toISOString() },
    'romon',
  );
  const services = bracketed(raw.services, 'svcs', 'svc');
  const bridges = bracketed(raw.bridges, 'bridges', 'bridge');
  const lanMembers = bracketed(raw.lanList, 'lanlist', 'lanmember');
  const addresses = bracketed(raw.addresses, 'addrs', 'addr');
  const l2tp = bracketed(raw.l2tp, 'l2tp', 'l2tpc');
  return {
    version: single(raw.version, 'version'),
    macServer: single(raw.macServer, 'macsrv'),
    macWinbox: single(raw.macWinbox, 'macwb'),
    romon: single(raw.romon, 'romon'),
    deviceMode: { mode: mode || null, romonFlag: romonFlag || null, romon: romonDeviceMode },
    services: services === null ? null : services.map(([name, address]) => ({ name: (name ?? '').trim(), address: (address ?? '').trim() })),
    bridges: bridges === null ? null : bridges.map(([n]) => (n ?? '').trim()).filter((n) => n !== ''),
    lanMembers: lanMembers === null ? null : lanMembers.map(([n]) => (n ?? '').trim()).filter((n) => n !== ''),
    addresses: addresses === null ? null : addresses.map(([iface, address]) => ({ interface: (iface ?? '').trim(), address: (address ?? '').trim() })),
    l2tpClients: l2tp === null
      ? null
      : l2tp.map(([name, rsp, running, disabled]): LegacyL2tpClientReading => ({
        name: (name ?? '').trim(),
        randomSourcePort: (rsp ?? '').trim(),
        running: yes(running),
        disabled: yes(disabled),
      })),
    wan: parseWan(raw.wan),
    dnsAmp: parseDnsAmp(raw.dnsAmp),
    dnsRemote: single(raw.dnsRemote, 'dnsremote') || null,
    ipsecPolicies: ((n) => (n !== null && /^\d+$/.test(n) ? Number(n) : null))(single(raw.ipsecPolicies, 'ipsecpol')),
  };
}

/** The job's own read of the router, for a caller that only reads: the
 *  workspace verification (fleet/accessCheck.service.ts) plans on it with
 *  `legacyPlan` exactly as lint does, over the same channel. */
export async function readLegacyCompliance(cli: AuditedCli): Promise<LegacyComplianceReading> {
  return readRouter(cli);
}

/** The fixes no job writes in this process (`LegacyComplianceDeps.retiredFixes`):
 *  a verification plans with the job's own list, harness included. */
export function legacyComplianceRetiredFixes(): readonly LegacyFixKey[] {
  return deps.retiredFixes;
}

async function readRouter(cli: AuditedCli): Promise<LegacyComplianceReading> {
  const r = LEGACY_SSH_READS;
  return parseLegacyReading({
    version: await cli.read(r.version),
    macServer: await cli.read(r.macServer),
    macWinbox: await cli.read(r.macWinbox),
    romon: await cli.read(r.romon),
    deviceMode: await cli.read(r.deviceMode),
    services: await cli.read(r.services),
    bridges: await cli.read(r.bridges),
    lanList: await cli.read(r.lanList),
    addresses: await cli.read(r.addresses),
    l2tp: await cli.read(r.l2tp),
    wan: await cli.read(r.wan),
    dnsAmp: await cli.read(r.dnsAmp),
    dnsRemote: await cli.read(r.dnsRemote),
    ipsecPolicies: await cli.read(r.ipsecPolicies),
  });
}

/** The self-revert's decision as its log line says it. */
export type LegacyGuardVerdict = 'reverted' | 'stood_down' | 'no_log_line';

export function parseGuardLog(out: string): { verdict: LegacyGuardVerdict; lines: string[] } {
  const found = tagged(out, 'log').map((p) => p.join('|'));
  if (found.some((l) => l.includes(LEGACY_GUARD_REVERTED))) return { verdict: 'reverted', lines: found };
  if (found.some((l) => l.includes(LEGACY_GUARD_STOOD_DOWN))) return { verdict: 'stood_down', lines: found };
  return { verdict: 'no_log_line', lines: found };
}

// ============================================================================
// Refusals and enqueue
// ============================================================================

export function legacyComplianceDeviceRefusals(facts: Facts): Refusal[] {
  const d = facts.device;
  const out: Refusal[] = [];
  if (d.status === 'disabled' || d.status === 'quarantined') {
    out.push({ kind: 'device_not_writable', message: `${d.name} est « ${d.status} » : aucune tâche ne peut le viser.` });
  }
  if (!d.is_managed) out.push({ kind: 'device_not_managed', message: `${d.name} n’est pas géré par ObliWAN (lecture seule).` });
  if (d.brand !== 'mikrotik') {
    out.push({
      kind: 'brand_unsupported',
      message: `${d.name} est un équipement ${d.brand} : les correctifs des modèles concernent les routeurs MikroTik.`,
    });
    return out;
  }
  if (d.role === 'concentrator') {
    out.push({
      kind: 'concentrator_refused',
      message: `${d.name} est un concentrateur : les correctifs des modèles clients ne le concernent pas.`,
    });
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
        'être récupérée par SFTP sur ce chemin (aucune clé d’hôte n’est épinglée). Rien n’est écrit sans sauvegarde.',
    });
  }
  return out;
}

/** Every refusal for one device (the rollout composition lists them). */
export async function legacyComplianceRefusals(
  tenantId: number,
  deviceId: number,
): Promise<{ facts: Facts | null; refusals: Refusal[] }> {
  const facts = await loadFacts(deviceId, tenantId);
  if (!facts) return { facts: null, refusals: [{ kind: 'device_not_found', message: `Équipement #${deviceId} introuvable.` }] };
  return { facts, refusals: legacyComplianceDeviceRefusals(facts) };
}

export interface EnqueueLegacyComplianceInput {
  tenantId: number;
  deviceId: number;
  requestedBy: number | null;
  /** The safety-net rule's confirmation. `at` is the instant it was given when that is not
   *  now (a job queued later on the operator's behalf — jobFollowup.service);
   *  absent, the enqueue's own instant. */
  confirmDegraded: { userId: number | null; at?: Date } | null;
  /** The device page: a job of this kind already queued or running is
   *  returned instead of refused. A rollout never sets it. */
  allowExisting?: boolean;
  /** Narrow the frozen list to these fixes (the workspace re-apply freezes
   *  exactly the fixes its verification found missing). It only NARROWS: a
   *  retired fix or an unknown key is never frozen, and a list that leaves
   *  nothing is refused (`no_fix_requested`). Absent: every fix not retired. */
  fixes?: readonly LegacyFixKey[];
}

export interface EnqueueLegacyComplianceResult {
  jobId: number;
  alreadyQueued: boolean;
  guard: ReturnType<typeof legacyComplianceGuard>;
  safetyNet: ReturnType<typeof legacyComplianceSafetyNet>;
}

const NO_BASE_STATE = '0'.repeat(64);

export async function enqueueLegacyComplianceJob(input: EnqueueLegacyComplianceInput): Promise<EnqueueLegacyComplianceResult> {
  const killSwitch = await readKillSwitch(input.tenantId);
  if (killSwitch.blocked) throw new KillSwitchEngagedError(killSwitch);
  const guard = legacyComplianceGuard();
  const safetyNet = legacyComplianceSafetyNet();
  const { facts, refusals } = await legacyComplianceRefusals(input.tenantId, input.deviceId);
  if (!facts || refusals.length > 0) {
    const first = refusals[0];
    throw new LegacyComplianceError(first.kind, refusals.map((r) => r.message).join(' '), first.kind === 'device_not_found' ? 404 : 409);
  }
  if (!input.confirmDegraded) {
    throw new LegacyComplianceError('degraded_unconfirmed', `${safetyNet.rationale} La tâche doit être confirmée explicitement.`, 422);
  }
  // A retired fix is not frozen: the row lists what this job may write —
  // narrowed, when the caller names them, to the fixes it asked for.
  const frozenFixes = LEGACY_FIX_KEYS.filter(
    (k) => !deps.retiredFixes.includes(k) && (input.fixes === undefined || input.fixes.includes(k)),
  );
  if (frozenFixes.length === 0) {
    throw new LegacyComplianceError(
      'no_fix_requested',
      'Aucun des correctifs demandés n’est de ceux que la tâche écrit : rien n’a été mis en file.',
      422,
    );
  }
  const existing = await activeJobOf(facts.device.id);
  if (existing) {
    if (existing.kind === LEGACY_COMPLIANCE_KIND && input.allowExisting) {
      return { jobId: existing.id, alreadyQueued: true, guard, safetyNet };
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
          kind: LEGACY_COMPLIANCE_KIND,
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
          degraded_confirmed_at: input.confirmDegraded!.at ?? now,
          requested_by: input.requestedBy,
        })
        .returning('id')) as Array<{ id: string | number }>;
      const id = Number(inserted[0].id);
      await trx('legacy_compliance_jobs').insert({
        job_id: id,
        tenant_id: input.tenantId,
        device_id: facts.device.id,
        fixes: JSON.stringify(frozenFixes),
        ssh_host: sshHost,
        revert_after_s: LEGACY_REVERT_AFTER_S,
        tunnel_wait_s: LEGACY_TUNNEL_WAIT_S,
      });
      return id;
    });
  } catch (err) {
    const pg = err as { code?: string; constraint?: string; message?: string };
    if (pg.code === '23505' && pg.constraint === 'change_jobs_one_in_flight_uq') {
      const again = await activeJobOf(facts.device.id);
      if (again && again.kind === LEGACY_COMPLIANCE_KIND && input.allowExisting) {
        return { jobId: again.id, alreadyQueued: true, guard, safetyNet };
      }
      throw new DeviceBusyError(facts.device.id);
    }
    if (pg.code === '23001' && /subtree interlock/i.test(pg.message ?? '')) {
      throw new LegacyComplianceError(
        'subtree_interlock',
        'Une tâche est en cours sur le concentrateur qui porte le tunnel de ce routeur : rien n’a été mis en file.',
      );
    }
    throw err;
  }
  logger.warn(
    { jobId, deviceId: facts.device.id, kind: LEGACY_COMPLIANCE_KIND, requestedBy: input.requestedBy },
    'legacy_compliance job QUEUED — template corrections about to be written on a customer router over SSH',
  );
  const summary = { jobId, deviceId: facts.device.id, kind: LEGACY_COMPLIANCE_KIND, status: 'queued' };
  emitToTenantAudience(input.tenantId, SOCKET_EVENTS.JOB_QUEUED, summary, { deviceId: facts.device.id });
  emitToDevice(facts.device.id, SOCKET_EVENTS.JOB_QUEUED, summary);
  return { jobId, alreadyQueued: false, guard, safetyNet };
}

// ============================================================================
// The view — the device settings card
// ============================================================================

export type LegacyFixViewState = 'unknown' | 'needed' | LegacyFixOutcome;

export interface LegacyComplianceFixView {
  key: LegacyFixKey;
  state: LegacyFixViewState;
  /** The plan's reason code (shared `LEGACY_FIX_REASONS`). */
  reason: string | null;
  /** What could still break, written anyway (shared `LEGACY_FIX_WARNINGS`). */
  warnings: string[];
  detail: string | null;
  current: string | null;
}

export interface LegacyComplianceJobView {
  id: number;
  status: ChangeJobStatus;
  active: boolean;
  outcome: LegacyComplianceOutcome | null;
  outcomeDetail: string | null;
  errorKind: string | null;
  errorMessage: string | null;
  createdAt: string;
  finishedAt: string | null;
  wroteAt: string | null;
  backupId: number | null;
  selfRevertArmedAt: string | null;
  randomSourcePortSentAt: string | null;
  tunnelReturnedAt: string | null;
  rolloutId: number | null;
  steps: Array<{ seq: number; kind: string; status: string; output: string | null; error: string | null }>;
}

export interface LegacyComplianceView {
  deviceId: number;
  deviceName: string;
  supported: boolean;
  eligible: boolean;
  refusals: Refusal[];
  ssh: { host: string | null; port: number | null; enabled: boolean } | null;
  /** When the per-fix state below was read, and by which step. */
  readAt: string | null;
  readBy: 'readback' | 'lint' | null;
  lan: LegacyLanDerivation | null;
  fixes: LegacyComplianceFixView[];
  job: LegacyComplianceJobView | null;
  /** The latest promise of these fixes after another job on this device
   *  (`change_job_followups`, jobFollowup.service.ts — the bulk attach's
   *  `legacy_compliance` after its `management_access`); null when none. */
  followUp: LegacyComplianceFollowUpView | null;
}

/** What became of a promise: `pending` while it is open, else its outcome.
 *  `reason`/`detail` are the code and the French sentence of a refusal or a
 *  skip, shown as they are. */
export interface LegacyComplianceFollowUpView {
  id: number;
  state: 'pending' | 'queued' | 'refused' | 'skipped';
  afterJobId: number;
  thenJobId: number | null;
  reason: string | null;
  detail: string | null;
  createdAt: string;
  doneAt: string | null;
}

/** The device's latest promise of `legacy_compliance`, under its tenant. */
async function latestFollowUp(tenantId: number, deviceId: number): Promise<LegacyComplianceFollowUpView | null> {
  const f = (await db('change_job_followups')
    .where({ tenant_id: tenantId, device_id: deviceId, then_kind: LEGACY_COMPLIANCE_KIND })
    .orderBy('id', 'desc')
    .first('id', 'after_job_id', 'then_job_id', 'outcome', 'outcome_reason', 'outcome_detail', 'created_at', 'done_at')) as
    | Record<string, any>
    | undefined;
  if (!f) return null;
  const outcome = f.outcome as 'queued' | 'refused' | 'skipped' | null;
  return {
    id: Number(f.id),
    state: f.done_at === null || outcome === null ? 'pending' : outcome,
    afterJobId: Number(f.after_job_id),
    thenJobId: f.then_job_id === null ? null : Number(f.then_job_id),
    reason: f.outcome_reason ?? null,
    detail: f.outcome_detail ?? null,
    createdAt: iso(f.created_at) as string,
    doneAt: iso(f.done_at),
  };
}

function iso(d: Date | string | null | undefined): string | null {
  return d ? new Date(d).toISOString() : null;
}

interface StoredRead {
  reading?: LegacyComplianceReading;
  plan?: LegacyCompliancePlan;
  readAt?: string;
}

export async function getLegacyComplianceView(tenantId: number, deviceId: number): Promise<LegacyComplianceView | null> {
  const facts = await loadFacts(deviceId, tenantId);
  if (!facts) return null;
  const refusals = legacyComplianceDeviceRefusals(facts);
  const supported = !refusals.some((r) => r.kind === 'brand_unsupported' || r.kind === 'concentrator_refused');

  const base = () => db('legacy_compliance_jobs as l').join('change_jobs as j', 'j.id', 'l.job_id')
    .where('l.device_id', deviceId).where('l.tenant_id', tenantId).orderBy('l.job_id', 'desc');
  const row = (await base().first(
    'l.job_id', 'l.backup_id', 'l.wrote_at', 'l.outcome', 'l.outcome_detail', 'l.self_revert_armed_at',
    'l.random_source_port_sent_at', 'l.tunnel_returned_at', 'j.status', 'j.error_kind', 'j.error_message',
    'j.created_at', 'j.finished_at', 'j.rollout_id',
  )) as Record<string, any> | undefined;
  // The per-fix state comes from the latest job that READ the router — a job
  // refused at bind_assert read nothing and must not blank what an earlier
  // one established.
  const read = (await base().whereNotNull('l.before').first('l.before', 'l.observed', 'l.fix_outcomes')) as
    | { before: StoredRead | null; observed: StoredRead | null; fix_outcomes: Record<string, { outcome: LegacyFixOutcome }> | null }
    | undefined;

  const plan = read?.before?.plan ?? null;
  const fixes: LegacyComplianceFixView[] = LEGACY_FIX_KEYS.map((key) => {
    const p = plan?.fixes?.[key];
    const final = read?.fix_outcomes?.[key]?.outcome;
    // A plan stored before a fix was retired may still call it "needed": with
    // no final outcome recorded, the card would announce a write no job will
    // ever make.
    if (!final && LEGACY_RETIRED_FIXES.includes(key)) {
      return { key, state: 'skipped', reason: 'retired', warnings: [], detail: null, current: p?.current ?? null };
    }
    return {
      key,
      state: final ?? (p ? (p.state === 'needed' ? 'needed' : p.state) : 'unknown'),
      reason: p?.reason ?? null,
      warnings: p?.warnings ?? [],
      detail: p?.detail ?? null,
      current: p?.current ?? null,
    };
  });

  let job: LegacyComplianceJobView | null = null;
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
      outcome: (row.outcome ?? null) as LegacyComplianceOutcome | null,
      outcomeDetail: row.outcome_detail ?? null,
      errorKind: row.error_kind ?? null,
      errorMessage: row.error_message ?? null,
      createdAt: iso(row.created_at) as string,
      finishedAt: iso(row.finished_at),
      wroteAt: iso(row.wrote_at),
      backupId: row.backup_id === null ? null : Number(row.backup_id),
      selfRevertArmedAt: iso(row.self_revert_armed_at),
      randomSourcePortSentAt: iso(row.random_source_port_sent_at),
      tunnelReturnedAt: iso(row.tunnel_returned_at),
      rolloutId: row.rollout_id === null || row.rollout_id === undefined ? null : Number(row.rollout_id),
      steps: steps.map((s) => ({
        seq: Number(s.seq),
        kind: String(s.kind),
        status: String(s.status),
        output: s.output_redacted ?? null,
        error: s.error_redacted ?? null,
      })),
    };
  }
  const last = read?.observed?.readAt ? 'readback' : read?.before?.readAt ? 'lint' : null;
  return {
    deviceId,
    deviceName: facts.device.name,
    supported,
    eligible: refusals.length === 0,
    refusals,
    ssh: facts.ssh ? { host: sshHostOf(facts), port: facts.ssh.port ?? 22, enabled: facts.ssh.enabled } : null,
    readAt: read?.observed?.readAt ?? read?.before?.readAt ?? null,
    readBy: last,
    lan: plan?.lan ?? null,
    fixes,
    job,
    followUp: await latestFollowUp(tenantId, deviceId),
  };
}

// ============================================================================
// The job's phases (called from apply.service.ts runPhases)
// ============================================================================

export interface LegacyComplianceStepResult {
  output: string;
  detail: Record<string, unknown>;
}

interface FrozenRow {
  job_id: string | number;
  /** The fixes frozen at enqueue (jsonb array of keys). */
  fixes: unknown;
  ssh_host: string;
  revert_after_s: number;
  tunnel_wait_s: number;
  backup_id: string | number | null;
}

/** What became of one line sent. */
export interface LegacySendResult {
  status: 'accepted' | 'refused' | 'lost' | 'dropped' | 'not_sent';
  /** The router's words (refused), or why it was not sent / was lost. */
  said?: string;
}

async function patchJob(jobId: number, patch: Record<string, unknown>): Promise<void> {
  await db('legacy_compliance_jobs').where({ job_id: jobId }).update({ ...patch, updated_at: db.fn.now() });
}

/** `refused` if nothing was written, `failed` otherwise; an outcome already
 *  recorded is kept. Called by `failJob` for every failure of this kind. Never throws. */
export async function settleLegacyCompliance(job: Pick<ChangeJobRow, 'id'>, message: string): Promise<void> {
  try {
    const jobId = Number(job.id);
    const row = (await db('legacy_compliance_jobs').where({ job_id: jobId }).first('outcome', 'wrote_at')) as
      | { outcome: string | null; wrote_at: Date | null }
      | undefined;
    if (!row || row.outcome !== null) return;
    await patchJob(jobId, { outcome: row.wrote_at ? 'failed' : 'refused', outcome_detail: (message || 'échec sans message').slice(0, 4000) });
  } catch (err) {
    logger.error({ err, jobId: Number(job.id) }, 'legacy_compliance: could not record the outcome of a failed job');
  }
}

/** A ManagementAccessError raised by the shared SSH machinery, renamed. */
function renamed(err: unknown): unknown {
  return err instanceof ManagementAccessError ? new LegacyComplianceError(err.kind, err.message) : err;
}

const FIX_LABEL: Record<LegacyFixKey, string> = {
  mac_server: 'mac-server',
  mac_winbox: 'mac-winbox',
  romon: 'RoMON',
  service_ssh: 'service ssh',
  service_winbox: 'service winbox',
  dns_amp_protection: 'DNS-Amp Protection',
  l2tp_random_source_port: 'random-source-port',
};

/** The warnings (shared `LEGACY_FIX_WARNINGS`) in the job's own words. */
const WARNING_TEXT: Record<LegacyFixWarning, string> = {
  wan_holds_tunnel: 'un tunnel L2TP est membre de la liste WAN : le DNS demandé par l’autre bout de ce tunnel sera rejeté',
  dns_not_served: 'le routeur ne répond pas au DNS aujourd’hui : les règles sont inertes tant que allow-remote-requests reste à no',
};

/** Send ONE line on its own command; never throws. A line that printed the
 *  marker completed; words without it are the router's refusal; nothing at
 *  all, or a transport error, is a session that went away under the line. */
async function sendRaw(cli: AuditedCli, line: string, timeoutMs?: number): Promise<{ result: LegacySendResult; out: string }> {
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

async function send(cli: AuditedCli, line: string, timeoutMs?: number): Promise<LegacySendResult> {
  return (await sendRaw(cli, line, timeoutMs)).result;
}

/** The non-guard lines of a plan, for "did the router change since lint". */
function writeLinesOf(plan: LegacyCompliancePlan, jobId: number, revertAfterS: number): string[] {
  const l = legacyComplianceLines(plan, jobId, revertAfterS);
  return [...l.pre.map((p) => p.line), ...(l.cut ? [l.cut] : [])];
}

function describeNeeded(plan: LegacyCompliancePlan): string {
  const needed = LEGACY_FIX_KEYS.filter((k) => plan.fixes[k].state === 'needed');
  const skipped = LEGACY_FIX_KEYS.filter((k) => plan.fixes[k].state === 'skipped');
  const unread = skipped.filter((k) => legacyReasonUnobserved(plan.fixes[k].reason));
  const retired = skipped.filter((k) => plan.fixes[k].reason === 'retired');
  const named = skipped.filter((k) => !unread.includes(k) && !retired.includes(k));
  const list = (keys: LegacyFixKey[]) => keys.map((k) => `${FIX_LABEL[k]} (${plan.fixes[k].detail})`).join(' ; ');
  const warned = LEGACY_FIX_KEYS.filter((k) => (plan.fixes[k].warnings ?? []).length > 0);
  return [
    needed.length > 0 ? `à corriger : ${list(needed)}` : 'rien à corriger',
    warned.length > 0
      ? `à vérifier : ${warned.map((k) => `${FIX_LABEL[k]} — ${(plan.fixes[k].warnings ?? []).map((w) => WARNING_TEXT[w]).join(' ; ')}`).join(' ; ')}`
      : '',
    named.length > 0 ? `écartés : ${list(named)}` : '',
    retired.length > 0
      ? `retirés du lot, lus et jamais écrits : ${retired.map((k) => `${FIX_LABEL[k]}${plan.fixes[k].current ? ` (${plan.fixes[k].current})` : ''}`).join(' ; ')}`
      : '',
    unread.length > 0 ? `non établis (rien n’y sera écrit, la relecture en décide) : ${list(unread)}` : '',
  ].filter((s) => s !== '').join(' — ');
}

export class LegacyComplianceRun {
  private facts: Facts | null = null;
  private frozen: FrozenRow | null = null;
  private plan: LegacyCompliancePlan | null = null;
  private noop = false;
  private sent: Partial<Record<LegacyFixKey | 'self_revert', LegacySendResult>> = {};
  /** `deps.now()` when the l2tp line left; null = not sent. */
  private cutAt: number | null = null;
  private guardArmed = false;
  /** The self-revert line as accepted, the id its job printed and
   *  `deps.now()` at its acceptance: what the cut session checks. */
  private armedGuard: string | null = null;
  private guardJobId: string | null = null;
  private guardAcceptedAt: number | null = null;
  /** What the cut session saw of the self-revert's job (recorded in `sent`). */
  private guardCheck: { id: string | null; listed: boolean | null; leadS: number | null } | null = null;
  /** True once `reconnect` waited past the self-revert's decision: only then
   *  does its log line (or its absence) say anything. */
  private awaitedGuard = false;
  /** The open PPP session just before the l2tp line (its id), to tell a new one. */
  private precutSession: string | null = null;
  private readonly backups: SshPreflightBackup;

  constructor(
    private readonly job: ChangeJobRow,
    private readonly device: { id: number; uuid?: string | null; name?: string | null },
    private readonly correlationId: string,
    private readonly workerId?: string,
  ) {
    this.backups = new SshPreflightBackup(job, device, correlationId, LEGACY_COMPLIANCE_KIND);
  }

  private get jobId(): number {
    return Number(this.job.id);
  }

  get isNoop(): boolean {
    return this.noop;
  }

  get noopReason(): string {
    return 'Le routeur porte déjà chaque correctif applicable (les autres sont écartés pour une raison nommée) : rien ne ' +
      'sera écrit, donc aucune sauvegarde préalable n’est nécessaire.';
  }

  /** True when the l2tp line left on a session and a running tunnel was
   *  restarted by it: the job must wait for the tunnel and the self-revert. */
  get mustAwaitTunnel(): boolean {
    return this.cutAt !== null && this.guardArmed;
  }

  get noTunnelReason(): string {
    const l2tp = this.plan?.fixes.l2tp_random_source_port;
    if (this.cutAt === null && l2tp && l2tp.state !== 'needed') {
      return l2tp.reason === 'retired'
        ? 'Aucune ligne random-source-port : ce correctif est retiré du lot (la bonne valeur dépend de l’opérateur et de ' +
          'la box du site, ObliWAN ne la change plus) ; aucun tunnel n’a redémarré, rien à attendre.'
        : 'Aucune ligne random-source-port n’était à envoyer : aucun tunnel n’a redémarré, rien à attendre.';
    }
    if (this.cutAt === null) {
      const said = this.sent.l2tp_random_source_port?.status === 'not_sent' ? ` (${this.sent.l2tp_random_source_port.said})` : '';
      return `La ligne random-source-port n’a pas été envoyée, ou le routeur l’a refusée${said} : aucun tunnel n’a redémarré, rien à attendre.`;
    }
    return 'Aucun l2tp-client en service n’a été modifié (aucun retour arrière n’était nécessaire) : aucun tunnel à attendre.';
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
    if (!this.facts) throw new LegacyComplianceError('internal', 'La tâche n’a pas été inspectée avant d’agir.');
    return this.facts;
  }

  private requireFrozen(): FrozenRow {
    if (!this.frozen) throw new LegacyComplianceError('internal', 'La tâche n’a pas lu ses paramètres figés.');
    return this.frozen;
  }

  /** The fixes this job was queued with: it writes no other. */
  private requestedFixes(): LegacyFixKey[] {
    const requested = legacyRequestedFixes(this.requireFrozen().fixes);
    if (!requested) {
      throw new LegacyComplianceError('job_row_invalid', 'La liste figée des correctifs de la tâche est illisible : rien n’a été écrit.');
    }
    return requested;
  }

  private linesFor(plan: LegacyCompliancePlan): string[] {
    const frozen = this.requireFrozen();
    try {
      const l = legacyComplianceLines(plan, this.jobId, frozen.revert_after_s);
      const all = [...l.pre.map((p) => p.line), ...(l.guard ? [l.guard] : []), ...(l.cut ? [l.cut] : [])];
      assertLegacyComplianceOnlyLines(all, plan, this.jobId, frozen.revert_after_s);
      return all;
    } catch (err) {
      if (err instanceof LegacyComplianceLineRefused || err instanceof LegacyComplianceInputError) {
        throw new LegacyComplianceError('line_outside_legacy_compliance', `${err.message} — rien n’a été écrit.`);
      }
      throw err;
    }
  }

  async inspect(): Promise<LegacyComplianceStepResult> {
    return this.held(async () => {
      const frozen = (await db('legacy_compliance_jobs').where({ job_id: this.jobId }).first('*')) as FrozenRow | undefined;
      if (!frozen) throw new LegacyComplianceError('job_row_missing', 'La tâche n’a pas de paramètres figés (legacy_compliance_jobs) : refus.');
      this.frozen = frozen;
      this.requestedFixes();
      const facts = await loadFacts(this.device.id, this.job.tenant_id);
      if (!facts) throw new LegacyComplianceError('device_not_found', `Équipement #${this.device.id} introuvable.`);
      this.facts = facts;
      const refusals = legacyComplianceDeviceRefusals(facts);
      if (refusals.length > 0) throw new LegacyComplianceError(refusals[0].kind, refusals.map((r) => r.message).join(' '));
      const host = sshHostOf(facts);
      if (host !== frozen.ssh_host) {
        throw new LegacyComplianceError(
          'ssh_moved',
          `Le canal SSH de ${facts.device.name} pointe désormais vers ${host ?? 'aucune adresse'} au lieu de ${frozen.ssh_host} : rien n’a été écrit ; relancez la tâche.`,
        );
      }
      await this.backups.probeRoad(sshCredentialOf(facts));
      const reading = await withProvenCli(facts, this.ctx('lint'), async (cli) => {
        // The rsc backup's export is spelled for devices.family.
        await assertFamily(cli, facts);
        return readRouter(cli);
      });
      const plan = legacyPlan(reading, this.requestedFixes(), deps.retiredFixes);
      this.plan = plan;
      await patchJob(this.jobId, { before: JSON.stringify({ reading, plan, readAt: new Date().toISOString() }) });
      if (legacyPlanIsNoop(plan)) {
        this.noop = true;
        return { output: `${describeNeeded(plan)} : rien à écrire`, detail: { noop: true } };
      }
      const lines = this.linesFor(plan);
      return {
        output: `${describeNeeded(plan)} ; à écrire : ${lines.length} commande(s)`,
        detail: {
          noop: false,
          needed: LEGACY_FIX_KEYS.filter((k) => plan.fixes[k].state === 'needed'),
          lan: plan.lan.network,
          lines: lines.length,
        },
      };
    });
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
      if (!binary) throw new LegacyComplianceError('backup_failed', 'Le routeur n’a produit aucune sauvegarde binaire : refus.');
      await patchJob(this.jobId, { backup_id: binary.id });
      return {
        backupId: binary.id,
        output: `sauvegarde préalable #${binary.id} stockée (${stored.map((s) => `${s.kind} ${s.bytes} o`).join(', ')}), récupérée par SFTP et effacée du routeur`,
        detail: { backupIds: stored.map((s) => s.id), road: 'sftp' },
      };
    });
  }

  async apply(onWrite: () => void): Promise<LegacyComplianceStepResult> {
    return this.held(async () => {
      const facts = this.requireFacts();
      const frozen = this.requireFrozen();
      const lintPlan = this.plan;
      if (!lintPlan) throw new LegacyComplianceError('internal', 'La tâche n’a pas établi son plan à l’inspection : refus d’écrire.');
      const backupRow = (await db('legacy_compliance_jobs').where({ job_id: this.jobId }).first('backup_id')) as
        | { backup_id: string | number | null }
        | undefined;
      if (!backupRow || backupRow.backup_id === null) {
        throw new LegacyComplianceError('backup_missing', 'Aucune sauvegarde préalable n’est enregistrée pour cette tâche : refus d’écrire.');
      }
      const deviceRow = (await db('devices').where({ id: this.device.id }).first('concentrator_id')) as
        | { concentrator_id: number | null }
        | undefined;
      const concentrated = deviceRow?.concentrator_id !== null && deviceRow?.concentrator_id !== undefined;
      const LOST_BEFORE = 'la session a été perdue sur une commande précédente';

      const first = await withProvenCli(facts, this.ctx('apply'), async (cli) => {
        // Read AGAIN on the session that writes: what lint saw was before the
        // backup, and an address list rewritten from a stale read could drop
        // an entry added since. A router that changed is refused, unwritten.
        const reading = await readRouter(cli);
        const plan = legacyPlan(reading, this.requestedFixes(), deps.retiredFixes);
        // Judged by the allow-list before anything else is done with it.
        const all = legacyPlanIsNoop(plan) ? [] : this.linesFor(plan);
        const before = writeLinesOf(lintPlan, this.jobId, frozen.revert_after_s);
        const now = all.length === 0 ? [] : writeLinesOf(plan, this.jobId, frozen.revert_after_s);
        if (JSON.stringify(before) !== JSON.stringify(now)) {
          throw new LegacyComplianceError(
            'state_changed',
            `Le routeur a changé entre l’inspection et l’écriture (${describeNeeded(plan)}) : rien n’a été écrit ; relancez la tâche.`,
          );
        }
        // The self-revert is built from THIS read: which clients run now.
        this.plan = plan;
        const built = legacyComplianceLines(plan, this.jobId, frozen.revert_after_s);
        await patchJob(this.jobId, {
          before: JSON.stringify({ reading, plan, readAt: new Date().toISOString() }),
        });
        await db('legacy_compliance_jobs').where({ job_id: this.jobId }).whereNull('wrote_at')
          .update({ wrote_at: db.fn.now(), updated_at: db.fn.now() });
        onWrite();

        let lostOn: LegacyFixKey | null = null;
        for (const { fix, line } of built.pre) {
          if (lostOn) {
            this.sent[fix] = { status: 'not_sent', said: LOST_BEFORE };
            continue;
          }
          const r = await send(cli, line);
          this.sent[fix] = r;
          if (r.status === 'lost') lostOn = fix;
        }
        if (built.cut && lostOn === null) await this.startL2tp(cli, built.guard, built.cut, concentrated);
        return { built, lostOn, count: all.length };
      });

      // The ssh service line is the last of a–e because it is the one write
      // that touches the service the job's session rides: whether RouterOS
      // keeps an established session when that service's address list
      // changes is not established. A session lost on EXACTLY that line is
      // therefore not taken as a broken path: the l2tp pair starts on a
      // fresh, identity-proven session, rebuilt from what that session reads
      // (the l2tp line must be the one planned). A session lost on any
      // earlier line is: nothing more is sent.
      const lastPre = first.built.pre[first.built.pre.length - 1]?.fix ?? null;
      const plannedCut = first.built.cut;
      if (plannedCut !== null && first.lostOn !== null) {
        if (first.lostOn === 'service_ssh' && lastPre === 'service_ssh') {
          await withProvenCli(facts, this.ctx('apply'), async (cli) => {
            const plan = legacyPlan(await readRouter(cli), this.requestedFixes(), deps.retiredFixes);
            const again = legacyComplianceLines(plan, this.jobId, frozen.revert_after_s);
            if (again.cut === null || again.cut !== plannedCut) {
              this.sent.l2tp_random_source_port = {
                status: 'not_sent',
                said: 'les l2tp-clients relus sur la nouvelle session ne sont plus ceux du plan : la ligne n’est pas envoyée',
              };
              return;
            }
            this.assertPair(again.guard, again.cut, plan);
            await this.startL2tp(cli, again.guard, again.cut, concentrated);
          });
        } else {
          this.sent.l2tp_random_source_port = { status: 'not_sent', said: LOST_BEFORE };
        }
      }
      // A self-revert accepted and no verdict on the l2tp line yet: the line
      // waits for a NEW session to see the self-revert's job alive.
      if (plannedCut !== null && this.guardArmed && this.sent.l2tp_random_source_port === undefined) {
        await this.confirmGuardThenCut(facts, plannedCut, concentrated);
      }
      await patchJob(this.jobId, { sent: JSON.stringify({ ...this.sent, ...(this.guardCheck ? { self_revert_check: this.guardCheck } : {}) }) });
      const summary = (Object.entries(this.sent) as Array<[string, LegacySendResult]>)
        .map(([k, r]) => `${FIX_LABEL[k as LegacyFixKey] ?? 'retour arrière'} : ${r.status}${r.status === 'refused' || r.status === 'not_sent' ? ` (${r.said})` : ''}`)
        .join(' ; ');
      return {
        output: `${first.count} commande(s) préparée(s) — ${summary}`,
        detail: {
          sent: this.sent,
          guardArmed: this.guardArmed,
          guardCheck: this.guardCheck,
          l2tpAfterSshLost: first.lostOn === 'service_ssh' && this.cutAt !== null,
        },
      };
    });
  }

  /** The allow-list on a pair rebuilt from a later session's read. */
  private assertPair(guard: string | null, cut: string, plan: LegacyCompliancePlan): void {
    try {
      assertLegacyComplianceOnlyLines([...(guard ? [guard] : []), cut], plan, this.jobId, this.requireFrozen().revert_after_s);
    } catch (err) {
      if (err instanceof LegacyComplianceLineRefused) {
        throw new LegacyComplianceError('line_outside_legacy_compliance', `${err.message} — la ligne l2tp n’a pas été envoyée.`);
      }
      throw err;
    }
  }

  /**
   * The start of the l2tp pair on `cli`. With a self-revert (a running client
   * is changed), only the self-revert goes here: the l2tp line restarts the
   * tunnel this session rides, and the self-revert must first be seen to
   * outlive the session that started it (`confirmGuardThenCut`). Without one,
   * no running tunnel restarts and the line goes here.
   */
  private async startL2tp(cli: AuditedCli, guard: string | null, cut: string, concentrated: boolean): Promise<void> {
    if (!guard) {
      await this.sendCut(cli, cut, concentrated);
      return;
    }
    const { result: g, out } = await sendRaw(cli, guard);
    this.sent.self_revert = g;
    if (g.status !== 'accepted') {
      this.sent.l2tp_random_source_port = {
        status: 'not_sent',
        said: `le retour arrière n’a pas pu être lancé sur le routeur (${g.said ?? g.status}) : sans lui, la ligne qui redémarre les tunnels n’est pas envoyée`,
      };
      return;
    }
    this.guardArmed = true;
    this.armedGuard = guard;
    this.guardJobId = parseGuardJobId(out);
    this.guardAcceptedAt = deps.now();
    await patchJob(this.jobId, { self_revert_armed_at: db.fn.now() });
  }

  /**
   * The self-revert is the l2tp line's only net, and its surviving the end of
   * the session that started it is REASONED, not observed (header). So the
   * line leaves only from a NEW SSH connection — the one that started the
   * self-revert has ended, as the l2tp line will end this one — once:
   *   - the id the self-revert printed is listed in `/system script job`;
   *   - the router, read again, still plans this very pair (the self-revert
   *     watches the clients that run NOW);
   *   - no more than LEGACY_GUARD_MAX_LEAD_S passed since the self-revert
   *     started (its clock runs from then, not from the line).
   * Any of them false: the line is not sent, by name; the self-revert, its
   * watched clients still running, stands down on its own.
   */
  private async confirmGuardThenCut(facts: Facts, cut: string, concentrated: boolean): Promise<void> {
    const frozen = this.requireFrozen();
    const notSent = (said: string): void => {
      this.sent.l2tp_random_source_port = { status: 'not_sent', said };
    };
    await deps.sleep(deps.guardSettleMs);
    try {
      await withProvenCli(facts, this.ctx('apply'), async (cli) => {
        const id = this.guardJobId;
        const listed = id === null ? null : parseGuardJobAlive(await cli.read(LEGACY_SSH_READS.guardJob(id)));
        this.guardCheck = { id, listed, leadS: null };
        if (id === null) {
          notSent(':execute n’a pas rendu d’identifiant de tâche : que le retour arrière survive à sa session ne peut pas être constaté, la ligne n’est pas envoyée');
          return;
        }
        if (listed !== true) {
          notSent(listed === false
            ? `la tâche ${id} du retour arrière n’est plus listée dans /system script job sur une nouvelle session : elle n’a pas survécu à la session qui l’a lancée, la ligne n’est pas envoyée`
            : `la présence de la tâche ${id} du retour arrière n’a pas pu être lue : la ligne n’est pas envoyée`);
          return;
        }
        const plan = legacyPlan(await readRouter(cli), this.requestedFixes(), deps.retiredFixes);
        const again = legacyComplianceLines(plan, this.jobId, frozen.revert_after_s);
        if (again.cut !== cut || again.guard !== this.armedGuard) {
          notSent('les l2tp-clients relus ne sont plus ceux que le retour arrière surveille : la ligne n’est pas envoyée');
          return;
        }
        this.assertPair(again.guard, again.cut, plan);
        const leadS = Math.round((deps.now() - (this.guardAcceptedAt as number)) / 1000);
        this.guardCheck.leadS = leadS;
        if (leadS > LEGACY_GUARD_MAX_LEAD_S) {
          notSent(`le retour arrière a démarré il y a ${leadS} s (plus de ${LEGACY_GUARD_MAX_LEAD_S} s) : il jugerait le tunnel trop tôt, la ligne n’est pas envoyée`);
          return;
        }
        await this.sendCut(cli, cut, concentrated);
      });
    } catch (err) {
      // A box answering as ANOTHER device is quarantined and ends the job;
      // a line outside the allow-list too. Anything else is a session that
      // could not be opened: the line is not sent.
      if (err instanceof ManagementAccessError && err.kind === 'identity_mismatch') throw err;
      if (err instanceof LegacyComplianceError) throw err;
      // Never overwrite what the line already got (sent, or refused by name).
      if (this.sent.l2tp_random_source_port !== undefined) throw err;
      notSent(`la nouvelle session qui devait constater le retour arrière n’a pas pu s’ouvrir (${(err instanceof Error ? err.message : String(err)).slice(0, 200)}) : la ligne n’est pas envoyée`);
    }
  }

  /**
   * The l2tp line, on `cli`. `random_source_port_sent_at` is written BEFORE
   * it leaves, and the PPP session open at that instant is remembered so a
   * new one can be told from it.
   */
  private async sendCut(cli: AuditedCli, cut: string, concentrated: boolean): Promise<void> {
    const open = concentrated
      ? ((await db('ppp_sessions').where({ device_id: this.device.id }).whereNull('ended_at')
        .orderBy('started_at', 'desc').first('id')) as { id: string | number } | undefined)
      : undefined;
    this.precutSession = open ? String(open.id) : null;
    await patchJob(this.jobId, { random_source_port_sent_at: db.fn.now() });
    this.cutAt = deps.now();
    const r = await send(cli, cut, deps.cutTimeoutMs);
    // The tunnel the session rides restarts on this very line: its silence
    // is the expected answer.
    this.sent.l2tp_random_source_port = r.status === 'lost' ? { status: 'dropped', said: r.said } : r;
    if (r.status === 'refused') this.cutAt = null;
  }

  /**
   * The tunnel's return and the self-revert's decision. Bounded by
   * `tunnel_wait_s` from the l2tp line. Never dials while the concentrator
   * says the PPP session is down. The return is a NEW open PPP session,
   * or — the listener may have missed a short flap — a proven session once
   * a few seconds passed; and the job does not leave before the self-revert
   * has decided, so that what it reads next is final.
   */
  async reconnect(): Promise<LegacyComplianceStepResult> {
    return this.held(async () => {
      const frozen = this.requireFrozen();
      const cutAt = this.cutAt;
      if (cutAt === null) throw new LegacyComplianceError('internal', 'Aucune ligne random-source-port n’a été envoyée.');
      const decidedAt = cutAt + (frozen.revert_after_s + LEGACY_GUARD_MARGIN_S) * 1000;
      // Never shorter than the self-revert's decision: a bound that ended
      // before it could not read what the router decided.
      const deadline = Math.max(cutAt + frozen.tunnel_wait_s * 1000, decidedAt);
      const settleAt = cutAt + 10_000;
      const deviceRow = (await db('devices').where({ id: this.device.id }).first('concentrator_id')) as
        | { concentrator_id: number | null }
        | undefined;
      const watched = deviceRow?.concentrator_id !== null && deviceRow?.concentrator_id !== undefined;
      let returnedAt: number | null = null;
      let how = '';
      for (;;) {
        const now = deps.now();
        let pppDown = false;
        if (watched) {
          const open = (await db('ppp_sessions').where({ device_id: this.device.id }).whereNull('ended_at')
            .orderBy('started_at', 'desc').first('id')) as { id: string | number } | undefined;
          pppDown = !open;
          if (open && String(open.id) !== this.precutSession && returnedAt === null) {
            returnedAt = now;
            how = 'nouvelle session PPP sur le concentrateur';
            await patchJob(this.jobId, { tunnel_returned_at: db.fn.now() });
          }
        }
        if (now >= decidedAt && !pppDown && (returnedAt !== null || now >= settleAt)) {
          const facts = (await loadFacts(this.device.id, this.job.tenant_id)) ?? this.requireFacts();
          try {
            await withProvenCli(facts, this.ctx('reconnect'), async () => undefined);
            this.facts = facts;
            this.awaitedGuard = true;
            if (returnedAt === null) {
              returnedAt = now;
              how = watched
                ? 'le concentrateur n’a pas noté de nouvelle session, le routeur a répondu sur une nouvelle session SSH'
                : 'le routeur a répondu sur une nouvelle session SSH';
              await patchJob(this.jobId, { tunnel_returned_at: db.fn.now() });
            }
            return {
              output: `tunnel revenu ${Math.round((returnedAt - cutAt) / 1000)} s après l’envoi (${how}) ; identité prouvée sur une nouvelle session`,
              detail: { returnedAfterS: Math.round((returnedAt - cutAt) / 1000), how },
            };
          } catch (err) {
            // A box that answers as ANOTHER device is quarantined by
            // withProvenCli and ends the job; anything else is "not back yet".
            if (err instanceof ManagementAccessError && err.kind === 'identity_mismatch') throw err;
          }
        }
        if (now >= deadline) {
          const backup = frozen.backup_id ?? (await db('legacy_compliance_jobs').where({ job_id: this.jobId }).first('backup_id'))?.backup_id;
          throw new LegacyComplianceError(
            'tunnel_not_back',
            `Le tunnel de ${this.device.name ?? `#${this.device.id}`} n’est pas revenu dans les ${frozen.tunnel_wait_s} s qui ` +
              `suivent l’envoi de random-source-port=yes${pppDown ? ' (le concentrateur voit la session PPP fermée)' : ''}. Le retour ` +
              `arrière lancé sur le routeur, vu vivant avant l’envoi, remet random-source-port=no au plus tard ${frozen.revert_after_s} s ` +
              'après l’envoi si un l2tp-client surveillé ne tourne pas ; vérifiez le site. ' +
              (backup ? `La sauvegarde préalable #${backup} est conservée.` : ''),
          );
        }
        await deps.sleep(deps.pollMs);
      }
    });
  }

  async verify(wrote: boolean): Promise<LegacyComplianceStepResult> {
    return this.held(async () => {
      const plan = this.plan;
      if (!plan) throw new LegacyComplianceError('internal', 'La tâche n’a pas établi son plan.');
      const facts = (await loadFacts(this.device.id, this.job.tenant_id)) ?? this.requireFacts();
      const { reading, guard } = await withProvenCli(facts, this.ctx('postcheck'), async (cli) => ({
        reading: await readRouter(cli),
        guard: this.awaitedGuard ? parseGuardLog(await cli.read(LEGACY_SSH_READS.guardLog(this.jobId))) : null,
      }));
      const outcomes = {} as Record<LegacyFixKey, { outcome: LegacyFixOutcome; said?: string }>;
      // The l2tp line restarted the clients the self-revert watched: each of
      // them must run again, not merely carry the new value.
      const down = legacyWatchedNotRunning(reading, plan);
      for (const key of LEGACY_FIX_KEYS) {
        const p = plan.fixes[key];
        const holds = legacyFixHolds(key, reading, plan);
        const s = this.sent[key];
        let outcome: LegacyFixOutcome;
        // A skip the design names is not a failure; a fix whose state was
        // never observed is not conforming either: only the read-back saying
        // it holds makes it `present`.
        if (p.state === 'skipped') outcome = !legacyReasonUnobserved(p.reason) ? 'skipped' : holds === true ? 'present' : 'unverified';
        else if (p.state === 'present') outcome = holds === true ? 'present' : holds === null ? 'unverified' : 'not_applied';
        else if (s?.status === 'refused') outcome = 'refused';
        else if (key === 'l2tp_random_source_port' && guard?.verdict === 'reverted') outcome = 'reverted';
        else if (holds === true) {
          outcome = key !== 'l2tp_random_source_port' ? 'applied' : down === null ? 'unverified' : down.length > 0 ? 'tunnel_down' : 'applied';
        } else if (holds === null) outcome = 'unverified';
        else if (!s || s.status === 'not_sent') outcome = 'not_sent';
        else outcome = 'not_applied';
        outcomes[key] = { outcome, ...(s?.said ? { said: s.said } : {}) };
      }
      const failing = LEGACY_FIX_KEYS.filter((k) => legacyOutcomeFails(k, outcomes[k].outcome));
      const describe = (keys: readonly LegacyFixKey[]) => keys.map((k) => `${FIX_LABEL[k]} ${outcomes[k].outcome}${outcomes[k].said && (outcomes[k].outcome === 'refused' || outcomes[k].outcome === 'not_sent') ? ` (${outcomes[k].said})` : ''}`).join(' ; ');
      // A self-revert armed in front of an l2tp line that did not leave (not
      // seen alive, the router changed, too late) or that the router refused
      // was not waited for: no tunnel restarted, its watched clients run, so
      // if it still runs it stands down on its own.
      const guardNote = guard === null
        ? this.guardArmed
          ? ' Le retour arrière lancé sur le routeur n’a pas été attendu : la ligne random-source-port n’est pas partie ou ' +
            'a été refusée, aucun tunnel n’a redémarré ; s’il tourne encore, il se retire de lui-même.'
          : ''
        : guard.verdict === 'no_log_line'
          ? ' Le retour arrière n’a laissé aucune ligne dans le journal du routeur : qu’il ait tourné n’est pas établi.'
          : ` Retour arrière : ${guard.verdict === 'reverted' ? 'il a remis random-source-port=no' : 'il s’est retiré, chaque tunnel surveillé tournait'}.`;
      const readAt = new Date().toISOString();
      const patch: Record<string, unknown> = {
        observed: JSON.stringify({ reading, readAt, guard }),
        fix_outcomes: JSON.stringify(outcomes),
      };
      if (failing.length > 0) {
        const l2tp = outcomes.l2tp_random_source_port.outcome;
        const kind = l2tp === 'reverted'
          ? 'random_source_port_reverted'
          : l2tp === 'tunnel_down'
            ? 'tunnel_down'
            : failing.every((k) => outcomes[k].outcome === 'unverified') ? 'state_unverified' : 'readback_failed';
        const lead = {
          random_source_port_reverted: 'Le retour arrière lancé sur le routeur a remis random-source-port=no : un tunnel surveillé ne ' +
            `tournait pas ${this.frozen?.revert_after_s ?? LEGACY_REVERT_AFTER_S} s après son lancement. `,
          tunnel_down: 'random-source-port=yes est en place, mais ces l2tp-clients, qui tournaient avant la ligne, ne tournent pas ' +
            `à la relecture : ${(down ?? []).join(', ')}. `,
          state_unverified: 'Une partie de l’état du routeur n’a pas pu être lue : sa conformité n’est pas établie. ',
          readback_failed: '',
        }[kind];
        const message =
          lead + `Relecture sur une nouvelle session : ${describe(failing)}.` + guardNote +
          (wrote ? ' La sauvegarde préalable est conservée.' : ' Rien n’a été écrit.');
        await patchJob(this.jobId, { ...patch, outcome: wrote ? 'failed' : 'refused', outcome_detail: message.slice(0, 4000) });
        throw new LegacyComplianceError(kind, message);
      }
      const outcome: LegacyComplianceOutcome = wrote ? 'applied' : 'present';
      const detail = `relu sur une nouvelle session : ${describe(LEGACY_FIX_KEYS)}.${guardNote}`;
      await patchJob(this.jobId, { ...patch, outcome, outcome_detail: detail.slice(0, 4000) });
      return { output: detail, detail: { outcome, outcomes } };
    });
  }
}
