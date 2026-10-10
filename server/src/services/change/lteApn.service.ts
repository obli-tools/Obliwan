/**
 * ObliWAN — the LTE APN of ONE router in service, chosen in its settings and
 * applied by a change job over SSH (kind `lte_apn`, migration 065, lines and
 * allow-list in shared/src/lteApn.ts).
 *
 * ┌─ WHY THIS JOB EXISTS, AND WHY IT IS NARROW ───────────────────────────────┐
 * │ The NCM does not model `/interface lte`: no plan, push or drift report    │
 * │ can carry an APN. The customer templates render a catalogue of profiles   │
 * │ (`lte_apn_catalogue`) and point lte1 at one; this job points ONE router's │
 * │ lte1 at the profile an operator picked from the catalogue RESOLVED FOR    │
 * │ THAT DEVICE (its applicable revision, through the variable resolver), and │
 * │ writes nothing else: at most one `/interface lte apn add|set` for that    │
 * │ entry and one `/interface lte set [find default-name=lte1]              │
 * │ apn-profiles=`, every line judged by `assertLteApnOnlyLines` before it is │
 * │ sent.                                                                     │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE DIFFERENCE WITH management_access: THIS WRITE CAN CUT ITS OWN PATH ──┐
 * │ management_access arms no dead-man because it never touches the path it   │
 * │ travels on. An APN change re-attaches the modem, and on these sites LTE   │
 * │ is a WAN: when the L2TP tunnel that carries ObliWAN's management traffic  │
 * │ leaves through lte1, the write drops the session that would read it back, │
 * │ and many Chateaux run device-mode `home`, where the scheduler — hence an  │
 * │ on-box dead-man — is blocked. So no dead-man is armed, and the job        │
 * │ REFUSES unless it proved on the router, at lint AND again on the session  │
 * │ it writes on, that the route to every enabled l2tp-client's address —     │
 * │ `connect-to`, or the router's own `:resolve` of the name, plus every live │
 * │ L2TP flow (the default route on a router with no client) — leaves through │
 * │ a non-LTE interface, that no route through the modem could take it over   │
 * │ once the modem attaches on the new profile (the one it installs, or an    │
 * │ inactive one, at a longer prefix or a distance no greater), and that no   │
 * │ policy routing could send it elsewhere (`judgeLteEgress`). Unknown is a   │
 * │ refusal. No lte1 is a refusal.                                            │
 * │ What this does NOT cover: a failover that moves the tunnel onto the modem │
 * │ in the seconds between that read and the write, and a site whose backup  │
 * │ path is the modem — the APN change then lands on the backup path, which   │
 * │ is the operator's intent.                                                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * THE JOB, STEP BY STEP (a branch of `runPhases()` in apply.service.ts):
 *   bind_assert       identity check over SSH (`assertMikrotikBindingOverSsh`).
 *   guard             ACCEPT by construction (`lteApnGuard`).
 *   lint              the frozen profile is still in the device's resolved
 *                     catalogue with the same APN, the SSH address did not
 *                     move, the SFTP road is proven, then on one proven
 *                     session: lte1, the profiles, the egress verdict. Already
 *                     on the profile -> nothing to write.
 *   preflight_backup  binary + rsc pulled by SFTP (`SshPreflightBackup`).
 *   arm_deadman       SKIPPED (LTE_APN_NO_DEADMAN).
 *   apply             the egress verdict READ AGAIN on the session that
 *                     writes, then the allow-listed lines, each audited.
 *   postcheck         lte1 and the profile read back on a NEW session; the
 *                     device's `lte_apn_profile` is set only then.
 *
 * WHAT IS NOT OBSERVED: no line of this file has reached a router. The
 * console reads (`immediate-gw`, `routing-table`, `/routing rule`, `:resolve`,
 * `/ip firewall connection`, the `:tostr` spellings) are REASONED from the
 * RouterOS 7 manual; the harness (testing/lteApn.verify.ts) runs them against
 * a fake SSH router answering by the same assumptions. A RouterOS 6 box has
 * no `immediate-gw` and no `routing-table`: its route read comes back
 * incomplete or without an attributable gateway, which is `unknown`, which is
 * a refusal.
 *
 * Operator-facing sentences are French, like management_access's.
 */

import {
  LTE_APN_CATALOGUE_KEY,
  LTE_APN_KIND,
  LTE_DEFAULT_APN_PROFILE_KEYS,
  LTE_DEFAULT_NAME,
  LTE_SIM_APN_PROFILE_KEY,
  LteApnLineRefused,
  SOCKET_EVENTS,
  assertLteApnOnlyLines,
  isActiveJobStatus,
  judgeLteEgress,
  l2tpFlowAddress,
  lteApnLines,
  lteApnProfileAction,
  lteApnStateDifferences,
  lteRouteAfterWrite,
  parseLteApnCatalogue,
  type ChangeJobStatus,
  type LteApnDifference,
  type LteApnEntry,
  type LteApnReading,
  type LteApnRouteSettings,
  type LteEgressReading,
  type LteEgressVerdict,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { emitToDevice } from '../fleet/fleetEvents';
import { emitToTenantAudience } from '../fleet/scopedEmit';
import {
  RenderRefusedError,
  RenderTargetError,
  deviceRenderTimeValues,
  loadDevice,
  resolveRevision,
} from '../template/render.service';
import { variableResolver, type VarSchema } from '../template/variableResolver.service';
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
} from './managementAccess.service';
import { isNonPublicAddress } from './transfer.service';
import { KillSwitchEngagedError, readKillSwitch } from './killSwitch.service';
import { DeviceBusyError, renewLease, type ChangeJobRow } from './jobQueue.service';

// ============================================================================
// Vocabulary
// ============================================================================

/**
 * What the job concluded. Mirrors `lte_apn_jobs_outcome_chk` (065).
 *  - `applied`  this job wrote, and the router read back on the profile;
 *  - `present`  the router was already on the profile: nothing written;
 *  - `refused`  ended before anything was written on the router;
 *  - `failed`   ended after a write on the router.
 */
export const LTE_APN_OUTCOMES = ['applied', 'present', 'refused', 'failed'] as const;
export type LteApnOutcome = (typeof LTE_APN_OUTCOMES)[number];

export class LteApnError extends Error {
  constructor(readonly kind: string, message: string, readonly httpStatus = 409) {
    super(message);
    this.name = 'LteApnError';
  }
}

export const LTE_APN_NO_DEADMAN =
  "Aucun dead-man n'est armé pour 'lte_apn' : beaucoup de Chateau sont en device-mode « home », où le " +
  "planificateur (donc un dead-man sur le routeur) est bloqué. À la place, la tâche a vérifié sur le routeur, à " +
  "l'inspection puis dans la session qui écrit, que le tunnel L2TP qui porte le chemin de gestion ne sort PAS par " +
  "l'interface LTE (sinon, ou si cela n'a pas pu être établi, elle refuse sans écrire). Elle n'écrit qu'un profil " +
  "APN du catalogue et le choix de profil de lte1. La sauvegarde préalable est prise avant la première écriture ; " +
  "la tâche est mise en file au niveau de sécurité degraded, avec la confirmation explicite de l’opérateur.";

export const LTE_APN_NO_APPLY_OUTCOME =
  "No row written to apply_outcomes: 'lte_apn' changes one APN profile with no net; it is not an " +
  'observation of how this hardware survives a change. Its outcome is on lte_apn_jobs.';

export function lteApnGuard(): { verdict: 'ACCEPT'; reasons: unknown[]; summary: string; unavailable: false } {
  return {
    verdict: 'ACCEPT',
    reasons: [
      {
        code: 'LTE_APN_OFF_PATH',
        effect: 'accept',
        message:
          'Writes at most one /interface lte apn profile (add or set, for the chosen catalogue entry) and lte1\'s ' +
          'apn-profiles, and refuses any other line before sending one. It refuses, before any write, when the ' +
          'route carrying the L2TP tunnel (or the default route) leaves through an LTE interface, when that ' +
          'cannot be established, or when policy routing is present.',
      },
    ],
    summary:
      'Management-Path Guard: ACCEPT — only the chosen APN profile and lte1\'s apn-profiles are written, and the ' +
      'job refuses on the router when the management path may ride the modem (no plan was simulated).',
    unavailable: false,
  };
}

export function lteApnSafetyNet(): {
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
      "DEGRADED — aucun dead-man n'est armé ; la tâche refuse d'écrire tant qu'elle n'a pas établi sur le routeur que " +
      'le chemin de gestion ne passe pas par le modem LTE. La sauvegarde préalable, récupérée par SFTP avant la ' +
      'première écriture, est le seul filet. La règle de sécurité exige une confirmation explicite et tracée.',
    unverified: false,
    requiresConfirmation: true,
  };
}

// ============================================================================
// The catalogue resolved for one device
// ============================================================================

export interface LteApnCatalogue {
  ok: boolean;
  /** Why there is no catalogue, in the operator's language. */
  message: string | null;
  entries: LteApnEntry[];
  /** The tenant/group default profile name, when the revision declares one. */
  defaultProfile: string | null;
  /** True when the revision declares the bench-level `sim_apn_profile`, i.e.
   *  when the device's choice reaches the next render. */
  feedsRender: boolean;
  revision: { id: string; number: number | null; templateId: string | null } | null;
}

/** The catalogue as the device's applicable revision resolves it: the same
 *  revision (`resolveRevision`), the same render-time values and the same
 *  variable chain a render of this device uses. */
export async function resolveLteApnCatalogue(tenantId: number, deviceId: number): Promise<LteApnCatalogue> {
  const none = (message: string): LteApnCatalogue => ({
    ok: false, message, entries: [], defaultProfile: null, feedsRender: false, revision: null,
  });
  let device;
  try {
    device = await loadDevice(tenantId, deviceId);
  } catch (err) {
    if (err instanceof RenderTargetError) return none(`Équipement #${deviceId} introuvable.`);
    throw err;
  }
  let resolved;
  try {
    resolved = await resolveRevision(tenantId, device, null, db);
  } catch (err) {
    if (err instanceof RenderRefusedError || err instanceof RenderTargetError) {
      return none(`Aucune révision de modèle ne s’applique à cet équipement (${err.message}) : pas de catalogue APN.`);
    }
    throw err;
  }
  const schema = (resolved.revision.var_schema ?? null) as VarSchema | null;
  const props = (schema?.properties ?? {}) as Record<string, Record<string, unknown> | undefined>;
  const revision = {
    id: String(resolved.revision.id),
    number: typeof (resolved.revision as { revision?: unknown }).revision === 'number'
      ? (resolved.revision as { revision: number }).revision
      : null,
    templateId: resolved.templateId,
  };
  if (!props[LTE_APN_CATALOGUE_KEY]) {
    return { ...none(`La révision qui s’applique à cet équipement ne déclare pas « ${LTE_APN_CATALOGUE_KEY} ».`), revision };
  }
  const rt = await deviceRenderTimeValues(device, schema, db);
  const report = await variableResolver.resolveForDevice(tenantId, deviceId, schema, {
    groupId: device.group_id,
    renderTime: rt.renderTime,
  });
  const entries = parseLteApnCatalogue(report.variables[LTE_APN_CATALOGUE_KEY]?.value);
  let defaultProfile: string | null = null;
  for (const k of LTE_DEFAULT_APN_PROFILE_KEYS) {
    const v = report.variables[k]?.value;
    if (typeof v === 'string' && v.trim() !== '') {
      defaultProfile = v.trim();
      break;
    }
  }
  const feedsRender = props[LTE_SIM_APN_PROFILE_KEY]?.['x-obliwan-level'] === 'bench';
  if (entries.length === 0) {
    return {
      ok: false,
      message: `Le catalogue « ${LTE_APN_CATALOGUE_KEY} » résolu pour cet équipement est vide ou mal formé.`,
      entries, defaultProfile, feedsRender, revision,
    };
  }
  return { ok: true, message: null, entries, defaultProfile, feedsRender, revision };
}

// ============================================================================
// Dependencies (test seams)
// ============================================================================

export interface LteApnDeps {
  resolveCatalogue(tenantId: number, deviceId: number): Promise<LteApnCatalogue>;
}
const DEFAULT_DEPS: LteApnDeps = { resolveCatalogue: resolveLteApnCatalogue };
let deps: LteApnDeps = { ...DEFAULT_DEPS };
export function setLteApnDeps(next: Partial<LteApnDeps>): LteApnDeps {
  deps = { ...deps, ...next };
  return deps;
}
export function resetLteApnDeps(): void {
  deps = { ...DEFAULT_DEPS };
}

// ============================================================================
// The console reads (pure text) and their parsers
// ============================================================================

export const LTE_SSH_READS = {
  lte:
    ':foreach i in=[/interface lte find] do={ :put ("lte|" . [/interface lte get $i name] . "|" . ' +
    '[:tostr [/interface lte get $i default-name]] . "|" . [:tostr [/interface lte get $i apn-profiles]]) }',
  /** With each profile's default-route settings: the target profile's are
   *  the route the modem installs once it attaches after the write. */
  apn:
    ':foreach a in=[/interface lte apn find] do={ :put ("apn|" . [/interface lte apn get $a name] . "|" . ' +
    '[:tostr [/interface lte apn get $a apn]] . "|" . [:tostr [/interface lte apn get $a add-default-route]] . "|" . ' +
    '[:tostr [/interface lte apn get $a default-route-distance]]) }',
  /** `connect-to` and the router's own `:resolve` of it: the concentrators
   *  are DNS names, and only the router knows what it resolves them to. An
   *  unresolvable name leaves the last field empty. */
  l2tp:
    ':foreach i in=[/interface l2tp-client find] do={ :local c [:tostr [/interface l2tp-client get $i connect-to]]; ' +
    ':local a ""; :do { :set a [:tostr [:resolve $c]] } on-error={}; ' +
    ':put ("l2tpc|" . [/interface l2tp-client get $i name] . "|" . $c . "|" . ' +
    '[:tostr [/interface l2tp-client get $i disabled]] . "|" . $a) }',
  /** The live L2TP flows (udp/1701): the address the tunnel uses now. The
   *  `~` is a prefilter; the port is checked exactly by `l2tpFlowAddress`. */
  flows:
    ':put "flows|begin"; :foreach c in=[/ip firewall connection find where protocol="udp" and dst-address~":1701"] do={ ' +
    ':do { :put ("flow|" . [:tostr [/ip firewall connection get $c dst-address]]) } on-error={} }; :put "flows|end"',
  /** Every interface name: a gateway is attributed only to one of these. */
  interfaces:
    ':put "ifaces|begin"; :foreach i in=[/interface find] do={ :put ("if|" . [/interface get $i name]) }; :put "ifaces|end"',
  /** Every ENABLED route, active or not: an inactive route through the modem
   *  is the one the write would bring back. `routes|end` is printed only when
   *  every route was read. `immediate-gw` is absent on an inactive route, so
   *  its read is guarded; on RouterOS 6 it is absent everywhere, which leaves
   *  every active route without an attributable gateway — `unknown`. */
  routes:
    ':put "routes|begin"; :foreach r in=[/ip route find where disabled=no] do={ :local g ""; ' +
    ':do { :set g [:tostr [/ip route get $r immediate-gw]] } on-error={}; :put ("route|" . ' +
    '[:tostr [/ip route get $r dst-address]] . "|" . $g . "|" . [:tostr [/ip route get $r routing-table]] . "|" . ' +
    '[:tostr [/ip route get $r active]] . "|" . [:tostr [/ip route get $r distance]] . "|" . ' +
    '[:tostr [/ip route get $r gateway]]) }; :put "routes|end"',
  /** A negative count = a menu that could not be read. */
  policy:
    ':local n 0; :do { :set n ($n + [:len [/routing rule find where disabled=no]]) } on-error={ :set n -1000 }; ' +
    ':do { :set n ($n + [:len [/ip firewall mangle find where action=mark-routing and disabled=no]]) } on-error={ :set n -1000 }; ' +
    ':put ("policy|" . $n)',
} as const;

function tagged(out: string, tag: string): string[][] {
  return out
    .split(/\r?\n/)
    .map((l) => l.replace(/\r$/, '').trim())
    .filter((l) => l.startsWith(`${tag}|`))
    .map((l) => l.slice(tag.length + 1).split('|'));
}

/** The tagged lines of a read bracketed by `<tag>|begin` / `<tag>|end`;
 *  null when the end marker is missing (the read stopped part-way). */
function bracketed(out: string, bracket: string, tag: string): string[][] | null {
  return out.split(/\r?\n/).some((l) => l.trim() === `${bracket}|end`) ? tagged(out, tag) : null;
}

const yes = (v: string | undefined): boolean => ['true', 'yes'].includes((v ?? '').trim().toLowerCase());

export type LteRouterReading = LteApnReading & {
  lteInterfaces: string[];
  /** Each profile's `add-default-route` / `default-route-distance`, as printed. */
  profileRoutes: Record<string, LteApnRouteSettings>;
};

export function parseLteReading(lteOut: string, apnOut: string): LteRouterReading {
  const lte = tagged(lteOut, 'lte').map(([name, def, profiles]) => ({ name: (name ?? '').trim(), def: (def ?? '').trim(), profiles: (profiles ?? '').trim() }));
  const lte1 = lte.find((l) => l.def === LTE_DEFAULT_NAME) ?? null;
  const rows = tagged(apnOut, 'apn')
    .map(([name, apn, addDefaultRoute, distance]) => ({
      name: (name ?? '').trim(),
      apn: (apn ?? '').trim(),
      route: { addDefaultRoute: (addDefaultRoute ?? '').trim(), defaultRouteDistance: (distance ?? '').trim() },
    }))
    .filter((p) => p.name !== '');
  const profileRoutes: Record<string, LteApnRouteSettings> = {};
  for (const r of rows) if (!(r.name in profileRoutes)) profileRoutes[r.name] = r.route;
  return {
    lte1Present: lte1 !== null,
    lte1Name: lte1?.name || null,
    apnProfiles: lte1 ? lte1.profiles : null,
    profiles: rows.map((r) => ({ name: r.name, apn: r.apn })),
    lteInterfaces: lte.map((l) => l.name).filter((n) => n !== ''),
    profileRoutes,
  };
}

export function parseEgressReading(
  lteInterfaces: string[],
  outs: { l2tp: string; flows: string; interfaces: string; routes: string; policy: string },
): LteEgressReading {
  const routes = bracketed(outs.routes, 'routes', 'route');
  const interfaces = bracketed(outs.interfaces, 'ifaces', 'if');
  const flows = bracketed(outs.flows, 'flows', 'flow');
  const policy = tagged(outs.policy, 'policy')[0]?.[0];
  const n = policy === undefined || policy.trim() === '' ? NaN : Number(policy.trim());
  return {
    lteInterfaces,
    interfaces: interfaces === null ? null : interfaces.map(([name]) => (name ?? '').trim()).filter((x) => x !== ''),
    l2tpClients: tagged(outs.l2tp, 'l2tpc').map(([name, connectTo, disabled, resolved]) => ({
      name: (name ?? '').trim(),
      connectTo: (connectTo ?? '').trim(),
      disabled: yes(disabled),
      resolved: (resolved ?? '').trim(),
    })),
    routes: routes === null
      ? null
      : routes.map(([dst, gw, table, active, distance, gateway]) => ({
        dst: (dst ?? '').trim(),
        immediateGw: (gw ?? '').trim(),
        table: (table ?? '').trim(),
        active: yes(active),
        distance: (distance ?? '').trim(),
        gateway: (gateway ?? '').trim(),
      })),
    policyRules: Number.isInteger(n) && n >= 0 ? n : null,
    l2tpFlows: flows === null ? null : flows.map(([d]) => l2tpFlowAddress(d ?? '')).filter((a): a is string => a !== null),
  };
}

/** One read of everything the job decides on, on a proven session. The
 *  verdict is judged for `entry`: the route its profile installs once the
 *  modem attaches is part of what the write changes. */
async function readRouter(cli: AuditedCli, entry: LteApnEntry): Promise<{ lte: LteRouterReading; egress: LteEgressVerdict }> {
  const lte = parseLteReading(await cli.read(LTE_SSH_READS.lte), await cli.read(LTE_SSH_READS.apn));
  const egress = judgeLteEgress(
    parseEgressReading(lte.lteInterfaces, {
      l2tp: await cli.read(LTE_SSH_READS.l2tp),
      flows: await cli.read(LTE_SSH_READS.flows),
      interfaces: await cli.read(LTE_SSH_READS.interfaces),
      routes: await cli.read(LTE_SSH_READS.routes),
      policy: await cli.read(LTE_SSH_READS.policy),
    }),
    lteRouteAfterWrite(lte.profileRoutes[entry.name] ?? null),
  );
  return { lte, egress };
}

/** The egress verdict as a refusal, or null when the write may go. */
export function egressRefusal(verdict: LteEgressVerdict, deviceName: string): LteApnError | null {
  if (verdict.state === 'via_lte') {
    return new LteApnError(
      'egress_via_lte',
      `Le chemin de gestion de ${deviceName} sort par l’interface LTE (${verdict.summary}) : changer l’APN ` +
        'ferait décrocher le modem et couperait la session qui doit relire le résultat, sans dead-man pour revenir. ' +
        'Refus, rien n’a été écrit.',
    );
  }
  if (verdict.state === 'unknown') {
    return new LteApnError(
      'egress_unknown',
      `Impossible d’établir sur ${deviceName} par où sort le chemin de gestion (${verdict.summary}) : sans cette ` +
        'preuve, changer l’APN pourrait couper la session, sans dead-man pour revenir. Refus, rien n’a été écrit.',
    );
  }
  return null;
}

export function describeLteDifferences(diffs: readonly LteApnDifference[]): string {
  return diffs
    .map((d) => d.field === 'lte1'
      ? 'aucune interface lte1'
      : d.field === 'profile'
        ? `profil « ${d.expected} » absent`
        : `${d.field} : « ${d.actual || '—'} » au lieu de « ${d.expected} »`)
    .join(' ; ');
}

// ============================================================================
// Refusals and enqueue
// ============================================================================

export interface LteApnRefusal {
  kind: string;
  message: string;
}

export function lteApnDeviceRefusals(facts: Facts): LteApnRefusal[] {
  const d = facts.device;
  const out: LteApnRefusal[] = [];
  if (d.status === 'disabled' || d.status === 'quarantined') {
    out.push({ kind: 'device_not_writable', message: `${d.name} est « ${d.status} » : aucune tâche ne peut le viser.` });
  }
  if (!d.is_managed) out.push({ kind: 'device_not_managed', message: `${d.name} n’est pas géré par ObliWAN (lecture seule).` });
  if (d.brand !== 'mikrotik') {
    out.push({ kind: 'brand_unsupported', message: `${d.name} est un équipement ${d.brand} : le choix d’APN concerne les routeurs MikroTik.` });
    return out;
  }
  if (d.role === 'concentrator') {
    out.push({ kind: 'concentrator_refused', message: `${d.name} est un concentrateur : il n’a pas d’APN à choisir ici.` });
  }
  const ssh = facts.ssh;
  const host = sshHostOf(facts);
  if (!ssh || !ssh.enabled || !host || !ssh.username || !ssh.secret_enc) {
    out.push({
      kind: 'no_ssh',
      message: `${d.name} n’a pas de canal SSH activé et complet (adresse, utilisateur, mot de passe) : la tâche passe par SSH.`,
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

export interface EnqueueLteApnInput {
  tenantId: number;
  deviceId: number;
  profile: string;
  requestedBy: number | null;
  confirmDegraded: { userId: number | null } | null;
  allowExisting?: boolean;
}

const NO_BASE_STATE = '0'.repeat(64);

export async function enqueueLteApnJob(
  input: EnqueueLteApnInput,
): Promise<{ jobId: number; alreadyQueued: boolean; entry: LteApnEntry }> {
  const killSwitch = await readKillSwitch(input.tenantId);
  if (killSwitch.blocked) throw new KillSwitchEngagedError(killSwitch);
  const facts = await loadFacts(input.deviceId, input.tenantId);
  if (!facts) throw new LteApnError('device_not_found', `Équipement #${input.deviceId} introuvable.`, 404);
  const refusals = lteApnDeviceRefusals(facts);
  if (refusals.length > 0) throw new LteApnError(refusals[0].kind, refusals.map((r) => r.message).join(' '));

  const catalogue = await deps.resolveCatalogue(input.tenantId, input.deviceId);
  if (!catalogue.ok) throw new LteApnError('catalogue_unavailable', catalogue.message ?? 'Pas de catalogue APN.', 422);
  const entry = catalogue.entries.find((e) => e.name === input.profile);
  if (!entry) {
    throw new LteApnError(
      'profile_not_in_catalogue',
      `« ${String(input.profile).slice(0, 63)} » n’est pas un profil du catalogue APN résolu pour ${facts.device.name} ` +
        `(${catalogue.entries.map((e) => e.name).join(', ')}).`,
      422,
    );
  }
  const safetyNet = lteApnSafetyNet();
  if (!input.confirmDegraded) {
    throw new LteApnError('degraded_unconfirmed', `${safetyNet.rationale} La tâche doit être confirmée explicitement.`, 422);
  }

  const existing = await activeJobOf(facts.device.id);
  if (existing) {
    if (existing.kind === LTE_APN_KIND && input.allowExisting) {
      const row = (await db('lte_apn_jobs').where({ job_id: existing.id }).first('profile_name')) as { profile_name: string } | undefined;
      if (row?.profile_name === entry.name) return { jobId: existing.id, alreadyQueued: true, entry };
    }
    throw new DeviceBusyError(facts.device.id);
  }

  const guard = lteApnGuard();
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
          kind: LTE_APN_KIND,
          status: 'queued',
          attempt: 0,
          max_attempts: 1,
          base_state_hash: NO_BASE_STATE,
          safety_level: safetyNet.level,
          safety_peer_device_id: null,
          guard_verdict: guard.verdict,
          guard_reasons: JSON.stringify(guard.reasons),
          degraded_confirmed_by: input.confirmDegraded!.userId,
          degraded_confirmed_at: now,
          requested_by: input.requestedBy,
        })
        .returning('id')) as Array<{ id: string | number }>;
      const id = Number(inserted[0].id);
      await trx('lte_apn_jobs').insert({
        job_id: id,
        tenant_id: input.tenantId,
        device_id: facts.device.id,
        profile_name: entry.name,
        apn: entry.apn,
        ssh_host: sshHost,
      });
      return id;
    });
  } catch (err) {
    const pg = err as { code?: string; constraint?: string; message?: string };
    if (pg.code === '23505' && pg.constraint === 'change_jobs_one_in_flight_uq') throw new DeviceBusyError(facts.device.id);
    if (pg.code === '23001' && /subtree interlock/i.test(pg.message ?? '')) {
      throw new LteApnError(
        'subtree_interlock',
        'Une tâche est en cours sur le concentrateur qui porte le tunnel de ce routeur : rien n’a été mis en file.',
      );
    }
    throw err;
  }
  logger.warn({ jobId, deviceId: facts.device.id, kind: LTE_APN_KIND, profile: entry.name }, 'lte_apn job QUEUED');
  const summary = { jobId, deviceId: facts.device.id, kind: LTE_APN_KIND, status: 'queued' };
  emitToTenantAudience(input.tenantId, SOCKET_EVENTS.JOB_QUEUED, summary, { deviceId: facts.device.id });
  emitToDevice(facts.device.id, SOCKET_EVENTS.JOB_QUEUED, summary);
  return { jobId, alreadyQueued: false, entry };
}

// ============================================================================
// The view — the device settings card
// ============================================================================

export interface LteApnJobView {
  id: number;
  status: ChangeJobStatus;
  active: boolean;
  profile: string;
  apn: string;
  outcome: LteApnOutcome | null;
  outcomeDetail: string | null;
  errorKind: string | null;
  errorMessage: string | null;
  createdAt: string;
  finishedAt: string | null;
  wroteAt: string | null;
  backupId: number | null;
  /** lte1's `apn-profiles` as the job last read it (read-back, else lint). */
  observedApnProfiles: string | null;
  observedAt: string | null;
  egress: { state: string; summary: string } | null;
  steps: Array<{ seq: number; kind: string; status: string; output: string | null; error: string | null }>;
}

export interface LteApnView {
  deviceId: number;
  deviceName: string;
  supported: boolean;
  eligible: boolean;
  refusals: LteApnRefusal[];
  catalogue: LteApnCatalogue;
  chosenProfile: string | null;
  job: LteApnJobView | null;
}

function iso(d: Date | string | null | undefined): string | null {
  return d ? new Date(d).toISOString() : null;
}

export async function getLteApnView(tenantId: number, deviceId: number): Promise<LteApnView | null> {
  const facts = await loadFacts(deviceId, tenantId);
  if (!facts) return null;
  const refusals = lteApnDeviceRefusals(facts);
  const supported = !refusals.some((r) => r.kind === 'brand_unsupported' || r.kind === 'concentrator_refused');
  const catalogue = supported
    ? await deps.resolveCatalogue(tenantId, deviceId)
    : { ok: false, message: null, entries: [], defaultProfile: null, feedsRender: false, revision: null };
  const chosen = (await db('devices').where({ id: deviceId, tenant_id: tenantId }).first('lte_apn_profile')) as
    | { lte_apn_profile: string | null }
    | undefined;

  const row = (await db('lte_apn_jobs as l')
    .join('change_jobs as j', 'j.id', 'l.job_id')
    .where('l.device_id', deviceId)
    .where('l.tenant_id', tenantId)
    .orderBy('l.job_id', 'desc')
    .first(
      'l.job_id', 'l.profile_name', 'l.apn', 'l.backup_id', 'l.wrote_at', 'l.outcome', 'l.outcome_detail', 'l.before',
      'l.observed', 'l.egress', 'j.status', 'j.error_kind', 'j.error_message', 'j.created_at', 'j.finished_at',
    )) as Record<string, any> | undefined;
  let job: LteApnJobView | null = null;
  if (row) {
    const steps = (await db('change_job_steps')
      .where({ job_id: row.job_id })
      .orderBy([{ column: 'attempt', order: 'asc' }, { column: 'seq', order: 'asc' }])
      .select('seq', 'kind', 'status', 'output_redacted', 'error_redacted')) as Array<Record<string, any>>;
    const read = (row.observed ?? row.before ?? null) as { reading?: LteApnReading; readAt?: string } | null;
    const egress = (row.egress ?? null) as LteEgressVerdict | null;
    const status = row.status as ChangeJobStatus;
    job = {
      id: Number(row.job_id),
      status,
      active: isActiveJobStatus(status),
      profile: row.profile_name,
      apn: row.apn,
      outcome: (row.outcome ?? null) as LteApnOutcome | null,
      outcomeDetail: row.outcome_detail ?? null,
      errorKind: row.error_kind ?? null,
      errorMessage: row.error_message ?? null,
      createdAt: iso(row.created_at) as string,
      finishedAt: iso(row.finished_at),
      wroteAt: iso(row.wrote_at),
      backupId: row.backup_id === null ? null : Number(row.backup_id),
      observedApnProfiles: read?.reading?.apnProfiles ?? null,
      observedAt: read?.readAt ?? null,
      egress: egress ? { state: egress.state, summary: egress.summary } : null,
      steps: steps.map((s) => ({
        seq: Number(s.seq),
        kind: String(s.kind),
        status: String(s.status),
        output: s.output_redacted ?? null,
        error: s.error_redacted ?? null,
      })),
    };
  }
  return {
    deviceId,
    deviceName: facts.device.name,
    supported,
    eligible: refusals.length === 0 && catalogue.ok,
    refusals,
    catalogue,
    chosenProfile: chosen?.lte_apn_profile ?? null,
    job,
  };
}

// ============================================================================
// The job's phases (called from apply.service.ts runPhases)
// ============================================================================

export interface LteApnStepResult {
  output: string;
  detail: Record<string, unknown>;
}

interface FrozenRow {
  job_id: string | number;
  profile_name: string;
  apn: string;
  ssh_host: string;
  backup_id: string | number | null;
}

async function patchJob(jobId: number, patch: Record<string, unknown>): Promise<void> {
  await db('lte_apn_jobs').where({ job_id: jobId }).update({ ...patch, updated_at: db.fn.now() });
}

/** `refused` if nothing was written, `failed` otherwise; an outcome already
 *  recorded is kept. Called by `failJob` for every failure of this kind. Never throws. */
export async function settleLteApn(job: Pick<ChangeJobRow, 'id'>, message: string): Promise<void> {
  try {
    const jobId = Number(job.id);
    const row = (await db('lte_apn_jobs').where({ job_id: jobId }).first('outcome', 'wrote_at')) as
      | { outcome: string | null; wrote_at: Date | null }
      | undefined;
    if (!row || row.outcome !== null) return;
    await patchJob(jobId, { outcome: row.wrote_at ? 'failed' : 'refused', outcome_detail: (message || 'échec sans message').slice(0, 4000) });
  } catch (err) {
    logger.error({ err, jobId: Number(job.id) }, 'lte_apn: could not record the outcome of a failed job');
  }
}

/** A ManagementAccessError raised by the shared SSH machinery, renamed. */
function renamed(err: unknown): unknown {
  return err instanceof ManagementAccessError ? new LteApnError(err.kind, err.message) : err;
}

export class LteApnRun {
  private facts: Facts | null = null;
  private entry: LteApnEntry | null = null;
  private lines: string[] | null = null;
  private noop = false;
  private readonly backups: SshPreflightBackup;

  constructor(
    private readonly job: ChangeJobRow,
    private readonly device: { id: number; uuid?: string | null; name?: string | null },
    private readonly correlationId: string,
    private readonly workerId?: string,
  ) {
    this.backups = new SshPreflightBackup(job, device, correlationId, LTE_APN_KIND);
  }

  private get jobId(): number {
    return Number(this.job.id);
  }

  get isNoop(): boolean {
    return this.noop;
  }

  get noopReason(): string {
    return `lte1 utilise déjà le profil « ${this.entry?.name ?? '?'} » avec l’APN attendu : rien ne sera écrit, donc aucune sauvegarde préalable n’est nécessaire.`;
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
    if (!this.facts) throw new LteApnError('internal', 'La tâche n’a pas été inspectée avant d’agir.');
    return this.facts;
  }

  async inspect(): Promise<LteApnStepResult> {
    return this.held(() => this.inspectNow());
  }

  private async inspectNow(): Promise<LteApnStepResult> {
    const frozen = (await db('lte_apn_jobs').where({ job_id: this.jobId }).first('*')) as FrozenRow | undefined;
    if (!frozen) throw new LteApnError('job_row_missing', 'La tâche n’a pas de paramètres figés (lte_apn_jobs) : refus.');
    const entry: LteApnEntry = { name: frozen.profile_name, apn: frozen.apn };
    this.entry = entry;

    const facts = await loadFacts(this.device.id, this.job.tenant_id);
    if (!facts) throw new LteApnError('device_not_found', `Équipement #${this.device.id} introuvable.`);
    this.facts = facts;
    const refusals = lteApnDeviceRefusals(facts);
    if (refusals.length > 0) throw new LteApnError(refusals[0].kind, refusals.map((r) => r.message).join(' '));
    const host = sshHostOf(facts);
    if (host !== frozen.ssh_host) {
      throw new LteApnError(
        'ssh_moved',
        `Le canal SSH de ${facts.device.name} pointe désormais vers ${host ?? 'aucune adresse'} au lieu de ${frozen.ssh_host} : rien n’a été écrit ; relancez la tâche.`,
      );
    }
    // The catalogue may have changed since the job was queued: the job
    // carries what the operator chose, and refuses rather than write a
    // profile the templates no longer declare, or declare with another APN.
    const catalogue = await deps.resolveCatalogue(this.job.tenant_id, this.device.id);
    const now = catalogue.ok ? catalogue.entries.find((e) => e.name === entry.name) : undefined;
    if (!now || now.apn !== entry.apn) {
      throw new LteApnError(
        'catalogue_changed',
        `Le profil « ${entry.name} » (APN ${entry.apn}) ${now ? `porte désormais l’APN ${now.apn}` : 'n’est plus dans le catalogue résolu'} ` +
          'pour cet équipement : rien n’a été écrit ; choisissez à nouveau.',
      );
    }

    const cred = sshCredentialOf(facts);
    await this.backups.probeRoad(cred);

    const looked = await withProvenCli(facts, this.ctx('lint'), async (cli) => {
      // The rsc backup's export is spelled for devices.family.
      await assertFamily(cli, facts);
      return readRouter(cli, entry);
    });
    const readAt = new Date().toISOString();
    await patchJob(this.jobId, {
      before: JSON.stringify({ reading: looked.lte, readAt }),
      egress: JSON.stringify(looked.egress),
    });
    if (!looked.lte.lte1Present) {
      throw new LteApnError('no_lte1', `${facts.device.name} n’a pas d’interface LTE « ${LTE_DEFAULT_NAME} » (default-name) : rien n’a été écrit.`);
    }
    const diffs = lteApnStateDifferences(looked.lte, entry);
    if (diffs.length === 0) {
      this.noop = true;
      return {
        output: `lte1 (${looked.lte.lte1Name}) utilise déjà « ${entry.name} » (APN ${entry.apn}) : rien à écrire`,
        detail: { noop: true, egress: looked.egress.state },
      };
    }
    const refusal = egressRefusal(looked.egress, facts.device.name);
    if (refusal) throw refusal;

    const current = looked.lte.profiles.find((p) => p.name === entry.name) ?? null;
    const action = lteApnProfileAction(entry, current);
    const selected = diffs.some((d) => d.field === 'apn-profiles');
    this.lines = lteApnLines(entry, action, selected);
    try {
      assertLteApnOnlyLines(this.lines, entry);
    } catch (err) {
      if (err instanceof LteApnLineRefused) throw new LteApnError('line_outside_lte_apn', `${err.message} — rien n’a été écrit.`);
      throw err;
    }
    return {
      output:
        `écart : ${describeLteDifferences(diffs)} ; chemin de gestion : ${looked.egress.summary} ; ` +
        `à écrire : ${this.lines.length} ligne(s)`,
      detail: { noop: false, differences: diffs.map((d) => d.field), egress: looked.egress.state, action, lines: this.lines.length },
    };
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
      if (!binary) throw new LteApnError('backup_failed', 'Le routeur n’a produit aucune sauvegarde binaire : refus.');
      await patchJob(this.jobId, { backup_id: binary.id });
      return {
        backupId: binary.id,
        output: `sauvegarde préalable #${binary.id} stockée (${stored.map((s) => `${s.kind} ${s.bytes} o`).join(', ')}), récupérée par SFTP et effacée du routeur`,
        detail: { backupIds: stored.map((s) => s.id), road: 'sftp' },
      };
    });
  }

  async apply(onWrite: () => void): Promise<LteApnStepResult> {
    return this.held(async () => {
      const facts = this.requireFacts();
      const entry = this.entry;
      const lines = this.lines;
      if (!entry || !lines) throw new LteApnError('internal', 'La tâche n’a pas construit ses lignes à l’inspection : refus d’écrire.');
      const backupRow = (await db('lte_apn_jobs').where({ job_id: this.jobId }).first('backup_id')) as
        | { backup_id: string | number | null }
        | undefined;
      if (!backupRow || backupRow.backup_id === null) {
        throw new LteApnError('backup_missing', 'Aucune sauvegarde préalable n’est enregistrée pour cette tâche : refus d’écrire.');
      }
      assertLteApnOnlyLines(lines, entry);
      return withProvenCli(facts, this.ctx('apply'), async (cli) => {
        // The egress verdict is read AGAIN on the session that writes: a
        // failover since lint may have moved the tunnel onto the modem.
        const again = await readRouter(cli, entry);
        await patchJob(this.jobId, { egress: JSON.stringify(again.egress) });
        const refusal = egressRefusal(again.egress, facts.device.name);
        if (refusal) throw refusal;
        await db('lte_apn_jobs').where({ job_id: this.jobId }).whereNull('wrote_at')
          .update({ wrote_at: db.fn.now(), updated_at: db.fn.now() });
        onWrite();
        for (const line of lines) {
          try {
            await cli.write(`${line}; :put "${CMD_OK}"`);
          } catch (err) {
            throw new LteApnError(
              'apply_failed',
              `La ligne « ${line} » a été refusée (${err instanceof Error ? err.message : String(err)}). La sauvegarde préalable est conservée.`,
            );
          }
        }
        return { output: `${lines.length} ligne(s) envoyée(s) : ${lines.join(' ; ')}`, detail: { lines: lines.length } };
      });
    });
  }

  async verify(wrote: boolean): Promise<LteApnStepResult> {
    return this.held(async () => {
      const facts = this.requireFacts();
      const entry = this.entry as LteApnEntry;
      const read = await withProvenCli(facts, this.ctx('postcheck'), async (cli) => readRouter(cli, entry));
      const readAt = new Date().toISOString();
      await patchJob(this.jobId, { observed: JSON.stringify({ reading: read.lte, readAt }) });
      const diffs = lteApnStateDifferences(read.lte, entry);
      if (diffs.length > 0) {
        throw new LteApnError(
          'readback_failed',
          `Relecture : lte1 n’est pas dans l’état attendu (${describeLteDifferences(diffs)}). ` +
            (wrote ? 'La sauvegarde préalable est conservée.' : 'Rien n’a été écrit.'),
        );
      }
      const outcome: LteApnOutcome = wrote ? 'applied' : 'present';
      await db.transaction(async (trx) => {
        await trx('lte_apn_jobs').where({ job_id: this.jobId }).update({
          outcome,
          outcome_detail: `lte1 relu sur « ${entry.name} » (APN ${entry.apn})`,
          updated_at: db.fn.now(),
        });
        await trx('devices').where({ id: this.device.id, tenant_id: this.job.tenant_id }).update({
          lte_apn_profile: entry.name,
          updated_at: db.fn.now(),
        });
      });
      return { output: `relu : lte1 utilise « ${entry.name} » (APN ${entry.apn})`, detail: { outcome } };
    });
  }
}
