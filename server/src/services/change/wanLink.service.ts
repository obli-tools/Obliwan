/**
 * ObliWAN — switching a store's WAN1 link (kind `wan_link`, migration 090; the
 * shapes, the plan, the script and its allow-list are shared/src/wanLink.ts).
 *
 * ┌─ WHAT IT DOES ────────────────────────────────────────────────────────────┐
 * │ A store goes from a box handing out DHCP to a PPPoE login (ADSL / FTTH /  │
 * │ FTTO), to a fixed address, or back — on the router in service, without a  │
 * │ visit. The fixed line is cut ON PURPOSE: the store rides its 4G while the │
 * │ link changes, and the management tunnel (l2tp-mgmt) fails over to the 4G  │
 * │ and back (the operator's observed 30–60 s each way). So:                  │
 * │  - lint REFUSES unless the router is in the mode its site declares (the   │
 * │    standard structure only — an ISP1/ISP2 WAN is refused), lte1 runs,     │
 * │    registered, with a usable signal, and the routes say l2tp-mgmt will    │
 * │    leave through the 4G once WAN1-GW is down;                             │
 * │  - a pre-change backup is pulled by SFTP before anything is written;      │
 * │  - the expected cut is ANNOUNCED (an info alert, no incident) and the     │
 * │    down and 4G-backup alerts are HELD for the window (wanLinkWindow.ts);  │
 * │  - ONE `:execute` line starts the script on the router; the job ends that │
 * │    session and sees the script's job listed on a NEW one (the self-revert │
 * │    outliving its session is observed on each router, never assumed);     │
 * │  - the script decides alone: it reverts by itself unless the new link     │
 * │    carries a ping to the probe host through WAN1 within its delay;        │
 * │  - the job waits (never dialling while the concentrator says the PPP      │
 * │    session is down), reads the script's decision, waits one more         │
 * │    failover, reads the router back on a fresh proven session, and only    │
 * │    then writes the site's variables (wan1_mode and the target's keys, the │
 * │    password to the vault) so the next render matches the router.         │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * The old link is DISABLED, never removed (operator decision 2026-10-07):
 * an instant manual way back; drift reports the disabled objects until
 * somebody removes them. A WAN exposure (pppoe or static put the public
 * address on the router) is WARNED, never refused and never fixed here: the
 * card links to the legacy compliance job (DNS-Amp).
 *
 * The PPPoE password: typed (or read from the vault) at enqueue, stored
 * ENCRYPTED on the job row, spliced into the one line last (after the
 * allow-list judged the redacted line), protected in command_audit, written
 * to the site's vault on success, and wiped from the job row when the job
 * concludes, whatever the outcome.
 *
 * WHAT IS NOT OBSERVED: no line of this file has reached a router; the reads
 * and the script are REASONED (shared header), and
 * testing/wanLink.verify.ts runs them against a fake router built on the
 * same assumptions.
 *
 * Operator-facing sentences are French, like legacy_compliance's.
 */

import {
  LEGACY_GUARD_JOB_TAG,
  SOCKET_EVENTS,
  WAN1_MODES,
  WAN1_PPPOE_NAMES,
  WAN1_VARIABLE_KEYS,
  WAN_LINK_ARM_LEAD_S,
  WAN_LINK_FAILOVER_BUDGET_S,
  WAN_LINK_KIND,
  WAN_LINK_MARGIN_S,
  WAN_LINK_MIN_RSRP_DBM,
  WAN_LINK_MIN_SINR_DB,
  WAN_LINK_REVERT_AFTER_S,
  WAN_LINK_REVERT_MAX_S,
  WAN_LINK_REVERT_MIN_S,
  WAN_PPPOE_PASSWORD_PLACEHOLDER,
  WAN_PPPOE_PASSWORD_RE,
  WAN_PPPOE_USER_RE,
  WAN1_IF,
  WanLinkInputError,
  WanLinkLineRefused,
  assertWanLinkOnlyLines,
  classifyWan1,
  isActiveJobStatus,
  isWan1Mode,
  isWan1PppoeName,
  judgeLteReady,
  judgeLteTakeover,
  legacyDnsAmpExact,
  parseSignal,
  parseWanLinkLog,
  validateStaticTarget,
  wanLinkFromHolds,
  wanLinkLine,
  wanLinkLogPrefix,
  wanLinkPlan,
  wanLinkRevertAfterValid,
  wanLinkTargetHolds,
  wanLinkWaitS,
  type ChangeJobStatus,
  type LteReadyVerdict,
  type LteTakeoverVerdict,
  type Wan1Classification,
  type Wan1Mode,
  type WanEgressRoute,
  type WanLinkFrozen,
  type WanLinkPlan,
  type WanLinkReading,
  type WanStaticRefusal,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { emitToDevice } from '../fleet/fleetEvents';
import { emitToTenantAudience } from '../fleet/scopedEmit';
import { liveAlertService } from '../liveAlert.service';
import { notificationService } from '../notification.service';
import { currentKeyVersion, decrypt, encrypt } from '../secretVault.service';
import { listLines } from '../sim/line.service';
import { assertConsoleLine } from '../drivers/mikrotik/render';
import { substituteLine } from './renderer/secrets';
import {
  RenderRefusedError,
  RenderTargetError,
  deviceRenderTimeValues,
  loadDevice,
  resolveRevision,
} from '../template/render.service';
import {
  SiteVariablesRefusedError,
  loadSiteDeclarations,
  validateSiteValues,
  variableResolver,
  type RenderTimeValues,
  type VarSchema,
} from '../template/variableResolver.service';
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
import { LEGACY_SSH_READS, parseDnsAmp, parseGuardJobAlive, parseGuardJobId } from './legacyCompliance.service';
import { LTE_SSH_READS, parseEgressReading, parseLteReading } from './lteApn.service';
import { isNonPublicAddress } from './transfer.service';
import { KillSwitchEngagedError, readKillSwitch } from './killSwitch.service';
import { DeviceBusyError, renewLease, type ChangeJobRow } from './jobQueue.service';

// ============================================================================
// Vocabulary
// ============================================================================

/**
 * What the job concluded. Mirrors `wan_link_jobs_outcome_chk` (090).
 *  - `applied`  the script switched the link, the read-back holds, the site's
 *               variables were written;
 *  - `present`  the router already was on the target: nothing written, the
 *               variables recorded;
 *  - `reverted` the script put the old link back (the new one never carried
 *               traffic, or a step failed);
 *  - `refused`  ended before anything was started on the router;
 *  - `failed`   anything else after the script was sent.
 */
export const WAN_LINK_OUTCOMES = ['applied', 'present', 'reverted', 'refused', 'failed'] as const;
export type WanLinkOutcome = (typeof WAN_LINK_OUTCOMES)[number];

export class WanLinkError extends Error {
  constructor(readonly kind: string, message: string, readonly httpStatus = 409) {
    super(message);
    this.name = 'WanLinkError';
  }
}

export const WAN_LINK_NO_DEADMAN =
  "Aucun dead-man n'est armé sur le routeur pour 'wan_link' : beaucoup de Chateau sont en device-mode « home », où " +
  'le planificateur est bloqué. Le filet est le script lui-même : lancé par :execute, il bascule sur la 4G, installe ' +
  'le nouveau lien et remet l’ancien de lui-même si le nouveau ne passe pas de trafic dans son délai. La tâche ne ' +
  'l’envoie qu’après avoir vu la 4G montée et la sauvegarde préalable prise, et vérifie qu’il survit à sa session.';

export const WAN_LINK_NO_APPLY_OUTCOME =
  "No row written to apply_outcomes: 'wan_link' switches the WAN link by a self-reverting script with no on-box " +
  'dead-man; it is not an observation of how this hardware survives a change. Its outcome is on wan_link_jobs.';

export function wanLinkGuard(): { verdict: 'ACCEPT'; reasons: unknown[]; summary: string; unavailable: false } {
  return {
    verdict: 'ACCEPT',
    reasons: [
      {
        code: 'WAN_LINK_SELF_REVERTED',
        effect: 'accept',
        message:
          'Writes only the standard WAN1 objects (the pppoe-client, the DHCP client and the fixed address on ' +
          'ether1-WAN1, their WAN list member, routes NW-WAN1 / WAN1-GW and netwatch WAN1), in ONE script started on ' +
          'the router that reverts by itself unless the new link carries traffic within its delay. Refused unless ' +
          'lte1 runs with a usable signal and the management tunnel provably leaves through the 4G once WAN1-GW is ' +
          'down. Never touches lte1, the l2tp-clients, random-source-port, mac-server / mac-winbox / RoMON, a ' +
          'service, a user or the firewall.',
      },
    ],
    summary:
      'Management-Path Guard: ACCEPT — the management tunnel rides the 4G while WAN1 changes, and the script on ' +
      'the router puts the old link back by itself (no plan was simulated: the job refuses any other line).',
    unavailable: false,
  };
}

export function wanLinkSafetyNet(): {
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
      "DEGRADED — aucun dead-man n'est armé ; le lien fixe est coupé volontairement, le magasin passe sur sa 4G et le " +
      'script lancé sur le routeur remet l’ancien lien de lui-même si le nouveau ne passe pas de trafic. La sauvegarde ' +
      'préalable, récupérée par SFTP, est prise avant. La règle de sécurité exige une confirmation explicite et tracée de la coupure.',
    unverified: false,
    requiresConfirmation: true,
  };
}

// ============================================================================
// Dependencies (test seams)
// ============================================================================

export interface WanSchemaResolution {
  ok: boolean;
  message: string | null;
  schema: VarSchema | null;
  renderTime?: RenderTimeValues;
  groupId?: number | null;
}

export interface WanLinkDeps {
  now(): number;
  sleep(ms: number): Promise<void>;
  /** Between two looks at the PPP session / the router. */
  pollMs: number;
  /** Between the end of the session that started the script and the look at
   *  its job from a new one. */
  guardSettleMs: number;
  /** The revision that applies to the device and its schema. */
  resolveSchema(tenantId: number, deviceId: number): Promise<WanSchemaResolution>;
  /** The configuration collection after a switch (drift, uplink card). */
  collect(deviceId: number, tenantId: number): Promise<void>;
}

async function resolveSchemaFromRevision(tenantId: number, deviceId: number): Promise<WanSchemaResolution> {
  let device;
  try {
    device = await loadDevice(tenantId, deviceId);
  } catch (err) {
    if (err instanceof RenderTargetError) return { ok: false, message: `Équipement #${deviceId} introuvable.`, schema: null };
    throw err;
  }
  try {
    const resolved = await resolveRevision(tenantId, device, null, db);
    const schema = (resolved.revision.var_schema ?? null) as VarSchema | null;
    const rt = await deviceRenderTimeValues(device, schema, db);
    return { ok: true, message: null, schema, renderTime: rt.renderTime, groupId: device.group_id };
  } catch (err) {
    if (err instanceof RenderRefusedError || err instanceof RenderTargetError) {
      return {
        ok: false,
        message: `Aucune révision de modèle ne s’applique à cet équipement (${err.message}) : les variables WAN1 du site ne peuvent pas être lues.`,
        schema: null,
      };
    }
    throw err;
  }
}

async function collectAfterSwitch(deviceId: number, tenantId: number): Promise<void> {
  const { collectAndStore } = await import('../config/collect.service');
  await collectAndStore(deviceId, tenantId, { source: 'ssh' } as Parameters<typeof collectAndStore>[2]);
}

const DEFAULT_DEPS: WanLinkDeps = {
  now: () => Date.now(),
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  pollMs: 10_000,
  guardSettleMs: 3_000,
  resolveSchema: resolveSchemaFromRevision,
  collect: collectAfterSwitch,
};
let deps: WanLinkDeps = { ...DEFAULT_DEPS };
export function setWanLinkDeps(next: Partial<WanLinkDeps>): WanLinkDeps {
  deps = { ...deps, ...next };
  return deps;
}
export function resetWanLinkDeps(): void {
  deps = { ...DEFAULT_DEPS };
}

// ============================================================================
// The console reads (pure text) and their parsers
// ============================================================================

const W = `"${WAN1_IF}"`;

/** One command per read, each tagged; a bracketed read prints its `end`
 *  marker only when it completed, so one that stopped part-way is UNREAD. */
export const WAN_SSH_READS = {
  wan1if: `:put ("wan1if|" . [:len [/interface find where name=${W}]])`,
  pppoe:
    ':put "pppoe|begin"; :foreach i in=[/interface pppoe-client find] do={ :put ("pppoec|" . ' +
    '[/interface pppoe-client get $i name] . "|" . [:tostr [/interface pppoe-client get $i interface]] . "|" . ' +
    '[:tostr [/interface pppoe-client get $i disabled]] . "|" . [:tostr [/interface pppoe-client get $i running]] . "|" . ' +
    '[:tostr [/interface pppoe-client get $i user]]) }; :put "pppoe|end"',
  dhcp:
    `:put "dhcp|begin"; :foreach i in=[/ip dhcp-client find where interface=${W}] do={ :local s ""; ` +
    ':do { :set s [:tostr [/ip dhcp-client get $i script]] } on-error={}; :local std "no"; ' +
    ':if ([:typeof [:find $s "WAN1-GW"]] != "nil") do={ :set std "yes" }; :local g ""; ' +
    ':do { :set g [:tostr [/ip dhcp-client get $i gateway]] } on-error={}; :local st ""; ' +
    ':do { :set st [:tostr [/ip dhcp-client get $i status]] } on-error={}; :put ("dhcpc|" . ' +
    '[:tostr [/ip dhcp-client get $i disabled]] . "|" . $st . "|" . [:tostr [/ip dhcp-client get $i add-default-route]] . ' +
    '"|" . $std . "|" . $g . "|" . [:tostr [/ip dhcp-client get $i comment]]) }; :put "dhcp|end"',
  addr:
    `:put "addr|begin"; :foreach a in=[/ip address find where interface=${W} and dynamic=no] do={ :put ("addrw|" . ` +
    '[:tostr [/ip address get $a address]] . "|" . [:tostr [/ip address get $a disabled]]) }; :put "addr|end"',
  wanRoutes:
    ':put "wroutes|begin"; :foreach r in=[/ip route find where comment="NW-WAN1" or comment="WAN1-GW"] do={ ' +
    ':put ("wroute|" . [:tostr [/ip route get $r comment]] . "|" . [:tostr [/ip route get $r dst-address]] . "|" . ' +
    '[:tostr [/ip route get $r gateway]] . "|" . [:tostr [/ip route get $r disabled]] . "|" . [:tostr [/ip route get $r active]]) }; ' +
    ':put "wroutes|end"',
  netwatch:
    ':put "nw|begin"; :foreach n in=[/tool netwatch find where comment="WAN1"] do={ :put ("nwatch|" . ' +
    '[:tostr [/tool netwatch get $n host]] . "|" . [:tostr [/tool netwatch get $n disabled]]) }; :put "nw|end"',
  wanMembers:
    ':put "wmem|begin"; :foreach m in=[/interface list member find where list="WAN"] do={ :put ("wmember|" . ' +
    '[:tostr [/interface list member get $m interface]] . "|" . [:tostr [/interface list member get $m disabled]]) }; ' +
    ':put "wmem|end"',
  lteRun:
    ':put "lter|begin"; :foreach i in=[/interface lte find where default-name="lte1"] do={ :put ("lte1|" . ' +
    '[/interface lte get $i name] . "|" . [:tostr [/interface lte get $i running]] . "|" . ' +
    '[:tostr [/interface lte get $i disabled]]) }; :put "lter|end"',
  /** `monitor … once as-value` (REASONED field names): an unprinted value is
   *  empty, which the parser reads as unknown — never 0. */
  lteMon:
    ':local m ""; :local reg ""; :local rsrp ""; :local sinr ""; :local tech ""; :do { ' +
    ':set m [/interface lte monitor [find where default-name="lte1"] once as-value]; ' +
    ':do { :set reg [:tostr ($m->"registration-status")] } on-error={}; :do { :set rsrp [:tostr ($m->"rsrp")] } on-error={}; ' +
    ':do { :set sinr [:tostr ($m->"sinr")] } on-error={}; :do { :set tech [:tostr ($m->"access-technology")] } on-error={} ' +
    '} on-error={}; :put ("ltemon|" . $reg . "|" . $rsrp . "|" . $sinr . "|" . $tech)',
  mgmt:
    ':put "mgmt|begin"; :foreach i in=[/interface l2tp-client find where name="l2tp-mgmt"] do={ :put ("mgmtc|" . ' +
    '[:tostr [/interface l2tp-client get $i running]] . "|" . [:tostr [/interface l2tp-client get $i disabled]]) }; ' +
    ':put "mgmt|end"',
  /** Every enabled route WITH its comment: the takeover judge leaves WAN1-GW
   *  out by name. */
  egressRoutes:
    ':put "routes|begin"; :foreach r in=[/ip route find where disabled=no] do={ :local g ""; ' +
    ':do { :set g [:tostr [/ip route get $r immediate-gw]] } on-error={}; :local c ""; ' +
    ':do { :set c [:tostr [/ip route get $r comment]] } on-error={}; :put ("route|" . ' +
    '[:tostr [/ip route get $r dst-address]] . "|" . $g . "|" . [:tostr [/ip route get $r routing-table]] . "|" . ' +
    '[:tostr [/ip route get $r active]] . "|" . [:tostr [/ip route get $r distance]] . "|" . ' +
    '[:tostr [/ip route get $r gateway]] . "|" . $c) }; :put "routes|end"',
  /** The script's log lines, by its prefix (digits and fixed text). */
  wanLog: (jobId: number): string =>
    `:foreach l in=[/log find where message~"${wanLinkLogPrefix(jobId)}"] do={ :put ("log|" . [/log get $l message]) }`,
} as const;

function lines(out: string): string[] {
  return out.split(/\r?\n/).map((l) => l.replace(/\r$/, '').trim());
}
function tagged(out: string, tag: string): string[][] {
  return lines(out).filter((l) => l.startsWith(`${tag}|`)).map((l) => l.slice(tag.length + 1).split('|'));
}
function single(out: string, tag: string): string | null {
  const row = tagged(out, tag)[0];
  return row === undefined ? null : row.join('|').trim();
}
function bracketed(out: string, bracket: string, tag: string): string[][] | null {
  return lines(out).some((l) => l === `${bracket}|end`) ? tagged(out, tag) : null;
}
function flag(v: string | undefined): boolean | undefined {
  const t = (v ?? '').trim().toLowerCase();
  if (t === 'yes' || t === 'true') return true;
  if (t === 'no' || t === 'false') return false;
  return undefined;
}

export interface WanRawReads {
  wan1if: string;
  pppoe: string;
  dhcp: string;
  addr: string;
  wanRoutes: string;
  netwatch: string;
  wanMembers: string;
  lteRun: string;
  lteMon: string;
  mgmt: string;
  lteAll: string;
  l2tp: string;
  flows: string;
  interfaces: string;
  egressRoutes: string;
  policy: string;
}

/** Flags that must read as flags: one that does not makes the whole read unread. */
function flags(values: Array<string | undefined>): boolean[] | null {
  const out: boolean[] = [];
  for (const v of values) {
    const f = flag(v);
    if (f === undefined) return null;
    out.push(f);
  }
  return out;
}

export function parseWanReading(raw: WanRawReads): WanLinkReading {
  const n = single(raw.wan1if, 'wan1if');
  const pppoeRows = bracketed(raw.pppoe, 'pppoe', 'pppoec');
  let pppoeClients: WanLinkReading['pppoeClients'] = null;
  if (pppoeRows !== null) {
    pppoeClients = [];
    for (const r of pppoeRows) {
      const f = flags([r[2], r[3]]);
      if (r.length < 5 || f === null) {
        pppoeClients = null;
        break;
      }
      pppoeClients.push({ name: r[0].trim(), interface: r[1].trim(), disabled: f[0], running: f[1], user: r.slice(4).join('|').trim() });
    }
  }
  const dhcpRows = bracketed(raw.dhcp, 'dhcp', 'dhcpc');
  let dhcpClients: WanLinkReading['dhcpClients'] = null;
  if (dhcpRows !== null) {
    dhcpClients = [];
    for (const r of dhcpRows) {
      const f = flags([r[0], r[3]]);
      if (r.length < 6 || f === null) {
        dhcpClients = null;
        break;
      }
      dhcpClients.push({
        disabled: f[0], status: r[1].trim(), addDefaultRoute: r[2].trim(), stdScript: f[1], gateway: r[4].trim(),
        comment: r.slice(5).join('|').trim(),
      });
    }
  }
  const addrRows = bracketed(raw.addr, 'addr', 'addrw');
  let staticAddrs: WanLinkReading['staticAddrs'] = null;
  if (addrRows !== null) {
    staticAddrs = [];
    for (const r of addrRows) {
      const f = flags([r[1]]);
      if (r.length !== 2 || f === null) {
        staticAddrs = null;
        break;
      }
      staticAddrs.push({ address: r[0].trim(), disabled: f[0] });
    }
  }
  const routeRows = bracketed(raw.wanRoutes, 'wroutes', 'wroute');
  let routes: WanLinkReading['routes'] = null;
  if (routeRows !== null) {
    routes = [];
    for (const r of routeRows) {
      const f = flags([r[3], r[4]]);
      if (r.length !== 5 || f === null) {
        routes = null;
        break;
      }
      routes.push({ comment: r[0].trim(), dst: r[1].trim(), gateway: r[2].trim(), disabled: f[0], active: f[1] });
    }
  }
  const nwRows = bracketed(raw.netwatch, 'nw', 'nwatch');
  let netwatch: WanLinkReading['netwatch'] = null;
  if (nwRows !== null) {
    netwatch = [];
    for (const r of nwRows) {
      const f = flags([r[1]]);
      if (r.length !== 2 || f === null) {
        netwatch = null;
        break;
      }
      netwatch.push({ host: r[0].trim(), disabled: f[0] });
    }
  }
  const memRows = bracketed(raw.wanMembers, 'wmem', 'wmember');
  let wanMembers: WanLinkReading['wanMembers'] = null;
  if (memRows !== null) {
    wanMembers = [];
    for (const r of memRows) {
      const f = flags([r[1]]);
      if (r.length !== 2 || f === null) {
        wanMembers = null;
        break;
      }
      wanMembers.push({ interface: r[0].trim(), disabled: f[0] });
    }
  }
  const lteRows = bracketed(raw.lteRun, 'lter', 'lte1');
  const mon = tagged(raw.lteMon, 'ltemon')[0];
  let lte: WanLinkReading['lte'] = null;
  if (lteRows !== null) {
    const row = lteRows[0];
    if (row === undefined) {
      lte = { present: false, name: null, running: false, disabled: false, registration: null, rsrp: null, sinr: null, tech: null };
    } else {
      const f = flags([row[1], row[2]]);
      if (f !== null && lteRows.length === 1) {
        const text = (v: string | undefined) => ((v ?? '').trim() === '' ? null : (v as string).trim());
        lte = {
          present: true,
          name: row[0].trim() || null,
          running: f[0],
          disabled: f[1],
          registration: mon ? text(mon[0]) : null,
          rsrp: mon ? parseSignal(mon[1]) : null,
          sinr: mon ? parseSignal(mon[2]) : null,
          tech: mon ? text(mon[3]) : null,
        };
      }
    }
  }
  const mgmtRows = bracketed(raw.mgmt, 'mgmt', 'mgmtc');
  let l2tpMgmt: WanLinkReading['l2tpMgmt'] = null;
  if (mgmtRows !== null) {
    const row = mgmtRows[0];
    if (row === undefined) l2tpMgmt = { present: false, running: false, disabled: false };
    else {
      const f = flags([row[0], row[1]]);
      if (f !== null) l2tpMgmt = { present: true, running: f[0], disabled: f[1] };
    }
  }
  const lteAll = parseLteReading(raw.lteAll, '');
  const base = parseEgressReading(lteAll.lteInterfaces, {
    l2tp: raw.l2tp, flows: raw.flows, interfaces: raw.interfaces, routes: ':put "routes|begin"', policy: raw.policy,
  });
  const egressRows = bracketed(raw.egressRoutes, 'routes', 'route');
  const egressRoutes: WanEgressRoute[] | null = egressRows === null
    ? null
    : egressRows.map(([dst, gw, table, active, distance, gateway, ...comment]) => ({
      dst: (dst ?? '').trim(),
      immediateGw: (gw ?? '').trim(),
      table: (table ?? '').trim(),
      active: flag(active) === true,
      distance: (distance ?? '').trim(),
      gateway: (gateway ?? '').trim(),
      comment: comment.join('|').trim(),
    }));
  return {
    wan1If: n === null || !/^\d+$/.test(n) ? null : Number(n) > 0,
    pppoeClients,
    dhcpClients,
    staticAddrs,
    routes,
    netwatch,
    wanMembers,
    lte,
    l2tpMgmt,
    egress: { ...base, routes: egressRoutes },
  };
}

/** What the read-back compares with lint, beside the WAN1 objects: what the
 *  job must never have changed. */
export interface WanCollateral {
  lteApnProfiles: string | null;
  l2tpMgmt: WanLinkReading['l2tpMgmt'];
}

export async function readWanRouter(cli: AuditedCli): Promise<{ reading: WanLinkReading; collateral: WanCollateral }> {
  const r = WAN_SSH_READS;
  const lteAll = await cli.read(LTE_SSH_READS.lte);
  const reading = parseWanReading({
    wan1if: await cli.read(r.wan1if),
    pppoe: await cli.read(r.pppoe),
    dhcp: await cli.read(r.dhcp),
    addr: await cli.read(r.addr),
    wanRoutes: await cli.read(r.wanRoutes),
    netwatch: await cli.read(r.netwatch),
    wanMembers: await cli.read(r.wanMembers),
    lteRun: await cli.read(r.lteRun),
    lteMon: await cli.read(r.lteMon),
    mgmt: await cli.read(r.mgmt),
    lteAll,
    l2tp: await cli.read(LTE_SSH_READS.l2tp),
    flows: await cli.read(LTE_SSH_READS.flows),
    interfaces: await cli.read(LTE_SSH_READS.interfaces),
    egressRoutes: await cli.read(r.egressRoutes),
    policy: await cli.read(LTE_SSH_READS.policy),
  });
  const lte = parseLteReading(lteAll, '');
  return { reading, collateral: { lteApnProfiles: lte.apnProfiles, l2tpMgmt: reading.l2tpMgmt } };
}

/** Never refusals: what an operator should know before the cut. */
export type WanLinkWarning =
  | 'leftover_kept'
  | 'public_address_on_router'
  | 'dns_open_on_wan'
  | 'ipsec_static_policies'
  | 'no_sim_line'
  | 'sim_low'
  | 'sim_balance_unknown';

async function readWarnings(cli: AuditedCli, to: Wan1Mode): Promise<WanLinkWarning[]> {
  const out: WanLinkWarning[] = [];
  if (to !== 'dhcp') {
    out.push('public_address_on_router');
    const amp = parseDnsAmp(await cli.read(LEGACY_SSH_READS.dnsAmp));
    const remote = single(await cli.read(LEGACY_SSH_READS.dnsRemote), 'dnsremote');
    const served = flag(remote ?? '') === true;
    const protectedBoth = amp !== null &&
      (['udp', 'tcp'] as const).every((p) => amp.rules.some((x) => !x.disabled && legacyDnsAmpExact(x, p)));
    if (served && !protectedBoth) out.push('dns_open_on_wan');
  }
  const n = single(await cli.read(LEGACY_SSH_READS.ipsecPolicies), 'ipsecpol');
  if (n !== null && /^\d+$/.test(n) && Number(n) > 0) out.push('ipsec_static_policies');
  return out;
}

async function simWarnings(tenantId: number, deviceId: number): Promise<WanLinkWarning[]> {
  try {
    const lines = await listLines({ tenantId }, { deviceId });
    if (lines.length === 0) return ['no_sim_line'];
    if (lines.some((l) => l.verdict === 'low')) return ['sim_low'];
    // null is not 0: a balance nobody read is unknown, said as such.
    if (lines.some((l) => l.verdict === 'unknown')) return ['sim_balance_unknown'];
    return [];
  } catch (err) {
    logger.warn({ err, deviceId }, 'wan_link: SIM lines unreadable; the warning says unknown');
    return ['sim_balance_unknown'];
  }
}

// ============================================================================
// The site's declared WAN1 variables
// ============================================================================

export interface WanDeclaredValue<T> {
  value: T | null;
  /** Where the value came from (`site`, `default`, `device`, …); null when unset. */
  source: string | null;
}

export interface WanDeclared {
  ok: boolean;
  message: string | null;
  /** Which of the six keys the revision declares. */
  declaredKeys: string[];
  mode: WanDeclaredValue<Wan1Mode>;
  /** The mode as stored, when it is not one of the three. */
  modeInvalid: string | null;
  pppoeName: WanDeclaredValue<string>;
  pppoeUsername: WanDeclaredValue<string>;
  passwordSet: boolean;
  address: WanDeclaredValue<string>;
  gateway: WanDeclaredValue<string>;
  /** Keys set at the DEVICE level: the site value would not reach the render. */
  deviceOverrides: string[];
}

const KEYS = WAN1_VARIABLE_KEYS;

export async function resolveWanVariables(tenantId: number, deviceId: number): Promise<WanDeclared> {
  const empty = <T>(): WanDeclaredValue<T> => ({ value: null, source: null });
  const none = (message: string): WanDeclared => ({
    ok: false, message, declaredKeys: [], mode: empty(), modeInvalid: null, pppoeName: empty(), pppoeUsername: empty(),
    passwordSet: false, address: empty(), gateway: empty(), deviceOverrides: [],
  });
  const res = await deps.resolveSchema(tenantId, deviceId);
  if (!res.ok || !res.schema) return none(res.message ?? 'Aucune révision de modèle ne s’applique à cet équipement.');
  const props = (res.schema.properties ?? {}) as Record<string, unknown>;
  const declaredKeys = Object.values(KEYS).filter((k) => props[k] !== undefined);
  if (!declaredKeys.includes(KEYS.mode)) {
    return {
      ...none(
        `La révision qui s’applique à cet équipement ne déclare pas « ${KEYS.mode} » : ce n’est pas la structure WAN1 ` +
          'standard (les routeurs en structure ISP1/ISP2 sont refusés).',
      ),
      declaredKeys,
    };
  }
  const report = await variableResolver.resolveForDevice(tenantId, deviceId, res.schema, {
    groupId: res.groupId,
    renderTime: res.renderTime,
  });
  const v = report.variables;
  const val = (k: string): WanDeclaredValue<string> => {
    const x = v[k];
    if (!x || x.value === null || x.value === undefined || (typeof x.value === 'string' && x.value.trim() === '')) {
      return { value: null, source: null };
    }
    return { value: typeof x.value === 'string' ? x.value.trim() : String(x.value), source: x.source };
  };
  const modeRaw = val(KEYS.mode);
  const mode = isWan1Mode(modeRaw.value) ? { value: modeRaw.value, source: modeRaw.source } : { value: null, source: modeRaw.source };
  const deviceOverrides = Object.values(KEYS).filter((k) => v[k]?.source === 'device');
  return {
    ok: true,
    message: null,
    declaredKeys,
    mode,
    modeInvalid: modeRaw.value !== null && !isWan1Mode(modeRaw.value) ? modeRaw.value : null,
    pppoeName: val(KEYS.pppoeName),
    pppoeUsername: val(KEYS.pppoeUsername),
    passwordSet: v[KEYS.pppoePassword] !== undefined && v[KEYS.pppoePassword].value !== null && v[KEYS.pppoePassword].source !== 'default',
    address: val(KEYS.address),
    gateway: val(KEYS.gateway),
    deviceOverrides,
  };
}

async function vaultPassword(tenantId: number, deviceId: number): Promise<string | null> {
  const secrets = await variableResolver.loadSecrets(tenantId, deviceId);
  const hit = secrets.find((s) => s.key === KEYS.pppoePassword);
  return hit && hit.plaintext !== '' ? hit.plaintext : null;
}

// ============================================================================
// Refusals
// ============================================================================

interface PlacementFacts {
  siteId: number | null;
  siteCode: string | null;
  concentratorId: number | null;
  uplinkKind: string | null;
  groupId: number | null;
}

async function loadPlacement(tenantId: number, deviceId: number): Promise<PlacementFacts> {
  const row = (await db('devices as d')
    .leftJoin('sites as s', function joinSite(this: any) {
      this.on('s.id', '=', 'd.site_id').andOn('s.tenant_id', '=', 'd.tenant_id');
    })
    .where('d.id', deviceId)
    .where('d.tenant_id', tenantId)
    .first('d.site_id', 'd.concentrator_id', 'd.group_id', 's.code as site_code', 's.uplink_kind', 's.id as joined_site')) as
    | Record<string, any>
    | undefined;
  return {
    siteId: row?.joined_site === null || row?.joined_site === undefined ? null : Number(row.joined_site),
    siteCode: row?.site_code ?? null,
    concentratorId: row?.concentrator_id === null || row?.concentrator_id === undefined ? null : Number(row.concentrator_id),
    uplinkKind: row?.uplink_kind ?? null,
    groupId: row?.group_id === null || row?.group_id === undefined ? null : Number(row.group_id),
  };
}

export function wanLinkDeviceRefusals(facts: Facts, place: PlacementFacts): Refusal[] {
  const d = facts.device;
  const out: Refusal[] = [];
  if (d.status === 'disabled' || d.status === 'quarantined') {
    out.push({ kind: 'device_not_writable', message: `${d.name} est « ${d.status} » : aucune tâche ne peut le viser.` });
  }
  if (!d.is_managed) out.push({ kind: 'device_not_managed', message: `${d.name} n’est pas géré par ObliWAN (lecture seule).` });
  if (d.brand !== 'mikrotik') {
    out.push({
      kind: 'brand_unsupported',
      message: `${d.name} est un équipement ${d.brand} : le changement de lien WAN concerne les routeurs MikroTik.`,
    });
    return out;
  }
  if (d.role === 'concentrator') {
    out.push({ kind: 'concentrator_refused', message: `${d.name} est un concentrateur : il n’a pas de lien WAN1 de magasin.` });
    return out;
  }
  if (place.siteId === null) {
    out.push({
      kind: 'no_site',
      message: `${d.name} n’est rattaché à aucun site : la tâche lit et met à jour les variables WAN1 du site.`,
    });
  }
  if (place.uplinkKind === 'cellular_only') {
    out.push({
      kind: 'site_cellular_only',
      message: `Le site de ${d.name} est déclaré « 4G seule » : il n’a pas de lien fixe à changer.`,
    });
  }
  if (place.concentratorId === null) {
    out.push({
      kind: 'not_concentrated',
      message:
        `${d.name} n’est pas joint par le concentrateur (l2tp-mgmt) : la tâche suit le retour du tunnel de gestion ` +
        'pendant la bascule, et ne peut pas viser un routeur joint autrement.',
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

/** What the operator asks for: the target mode and, unless `site`, its
 *  parameters (a PPPoE password omitted = the one in the site's vault). */
export interface WanLinkRequest {
  toMode: Wan1Mode;
  params:
    | 'site'
    | {
      pppoe?: { name: string; username: string; password?: string | null } | null;
      static?: { address: string; gateway: string } | null;
    };
}

export interface WanLinkResolved {
  facts: Facts;
  place: PlacementFacts;
  declared: WanDeclared;
  from: Wan1Mode;
  to: Wan1Mode;
  target: { pppoeName: string | null; pppoeUser: string | null; address: string | null; gateway: string | null };
  /** IN MEMORY ONLY: the PPPoE password the job will splice. */
  password: string | null;
  passwordSource: 'typed' | 'site' | null;
  expect: WanLinkFrozen['expect'];
  /** The site values the success path writes (the password among them only
   *  when typed). */
  entries: Array<{ key: string; value: string }>;
}

const STATIC_REFUSAL_TEXT: Record<WanStaticRefusal, string> = {
  address_invalid: 'l’adresse fixe doit être une adresse IPv4 avec son préfixe (ex. 192.0.2.10/29)',
  prefix_out_of_range: 'le préfixe de l’adresse fixe doit aller de /8 à /32',
  gateway_invalid: 'la passerelle doit être une adresse IPv4 seule',
  gateway_outside_network: 'la passerelle n’est pas dans le réseau de l’adresse fixe',
  gateway_is_own_address: 'la passerelle est l’adresse du routeur lui-même',
  address_not_host: 'l’adresse fixe est l’adresse de réseau ou de diffusion de son préfixe',
};

const MODE_LABEL: Record<Wan1Mode, string> = { dhcp: 'box (DHCP)', pppoe: 'PPPoE', static: 'IP fixe' };

/** Every refusal for one device and one request; the resolved job when none. */
export async function wanLinkRefusals(
  tenantId: number,
  deviceId: number,
  request: WanLinkRequest,
): Promise<{ resolved: WanLinkResolved | null; refusals: Refusal[] }> {
  const facts = await loadFacts(deviceId, tenantId);
  if (!facts) return { resolved: null, refusals: [{ kind: 'device_not_found', message: `Équipement #${deviceId} introuvable.` }] };
  const place = await loadPlacement(tenantId, deviceId);
  const refusals = wanLinkDeviceRefusals(facts, place);
  if (refusals.some((r) => ['brand_unsupported', 'concentrator_refused'].includes(r.kind))) return { resolved: null, refusals };
  const to = request.toMode;
  if (!isWan1Mode(to)) {
    refusals.push({ kind: 'invalid_request', message: 'Mode cible inconnu : box (DHCP), PPPoE ou IP fixe.' });
    return { resolved: null, refusals };
  }
  const declared = await resolveWanVariables(tenantId, deviceId);
  if (!declared.ok) {
    refusals.push({ kind: 'wan_modes_not_declared', message: declared.message ?? 'Variables WAN1 non déclarées.' });
    return { resolved: null, refusals };
  }
  const need = to === 'pppoe' ? [KEYS.pppoeName, KEYS.pppoeUsername, KEYS.pppoePassword] : to === 'static' ? [KEYS.address, KEYS.gateway] : [];
  const undeclared = need.filter((k) => !declared.declaredKeys.includes(k));
  if (undeclared.length > 0) {
    refusals.push({
      kind: 'wan_modes_not_declared',
      message: `La révision qui s’applique à cet équipement ne déclare pas ${undeclared.map((k) => `« ${k} »`).join(', ')} : le mode ${MODE_LABEL[to]} ne peut pas être enregistré.`,
    });
  }
  if (declared.deviceOverrides.length > 0) {
    refusals.push({
      kind: 'device_override',
      message:
        `${declared.deviceOverrides.map((k) => `« ${k} »`).join(', ')} ${declared.deviceOverrides.length > 1 ? 'sont définies' : 'est définie'} ` +
        'au niveau de l’équipement : la valeur du site ne gagnerait pas au prochain rendu. Retirez la valeur de ' +
        'l’équipement d’abord.',
    });
  }
  if (declared.mode.value === null) {
    refusals.push({
      kind: 'declared_mode_invalid',
      message: declared.modeInvalid
        ? `« ${KEYS.mode} » vaut « ${declared.modeInvalid} » pour ce site : ni dhcp, ni pppoe, ni static.`
        : `« ${KEYS.mode} » n’a pas de valeur pour ce site.`,
    });
  }
  const from = declared.mode.value;

  // The target's parameters: the request, else the site's values.
  let pppoeName: string | null = null;
  let pppoeUser: string | null = null;
  let address: string | null = null;
  let gateway: string | null = null;
  let password: string | null = null;
  let passwordSource: 'typed' | 'site' | null = null;
  const p = request.params;
  if (to === 'pppoe') {
    if (p === 'site') {
      pppoeName = declared.pppoeName.value;
      pppoeUser = declared.pppoeUsername.value;
    } else {
      pppoeName = p.pppoe?.name ?? null;
      pppoeUser = p.pppoe?.username?.trim() ?? null;
      const typed = p.pppoe?.password;
      if (typeof typed === 'string' && typed !== '') {
        password = typed;
        passwordSource = 'typed';
      }
    }
    if (password === null) {
      password = await vaultPassword(tenantId, deviceId);
      if (password !== null) passwordSource = 'site';
    }
    const missing: string[] = [
      pppoeName ? null : KEYS.pppoeName,
      pppoeUser ? null : KEYS.pppoeUsername,
      password ? null : KEYS.pppoePassword,
    ].filter((x): x is NonNullable<typeof x> => x !== null);
    if (missing.length > 0) {
      refusals.push({
        kind: 'pppoe_params_missing',
        message: `Il manque ${missing.map((k) => `« ${k} »`).join(', ')} pour passer en PPPoE${p === 'site' ? ' (lu dans les variables du site)' : ''}.`,
      });
    } else {
      if (!isWan1PppoeName(pppoeName)) refusals.push({ kind: 'pppoe_name_invalid', message: `Le nom du client PPPoE doit être ${WAN1_PPPOE_NAMES.join(', ')}.` });
      if (!WAN_PPPOE_USER_RE.test(pppoeUser as string)) {
        refusals.push({ kind: 'pppoe_user_invalid', message: 'L’identifiant PPPoE doit faire 1 à 64 caractères parmi lettres, chiffres et . _ @ + / -.' });
      }
      // Never echoes the value: one character is one bit of a credential.
      if (!WAN_PPPOE_PASSWORD_RE.test(password as string)) {
        refusals.push({
          kind: 'pppoe_password_invalid',
          message:
            'Le mot de passe PPPoE doit faire 4 à 64 caractères ASCII imprimables, sans espace ni aucun de " \\ $ ; ? [ ] { } ' +
            'ou accent grave : il est placé dans une commande du routeur.',
        });
      }
    }
  }
  if (to === 'static') {
    if (p === 'site') {
      address = declared.address.value;
      gateway = declared.gateway.value;
    } else {
      address = p.static?.address?.trim() ?? null;
      gateway = p.static?.gateway?.trim() ?? null;
    }
    if (!address || !gateway) {
      refusals.push({
        kind: 'static_params_missing',
        message: `Il manque ${[address ? null : `« ${KEYS.address} »`, gateway ? null : `« ${KEYS.gateway} »`].filter(Boolean).join(' et ')} pour passer en IP fixe : ObliWAN ne devine jamais une adresse.`,
      });
    } else {
      const why = validateStaticTarget(address, gateway);
      if (why) refusals.push({ kind: 'static_target_invalid', message: `Adresse fixe refusée : ${STATIC_REFUSAL_TEXT[why]}.` });
    }
  }
  if (from !== null && from === to) {
    const same =
      to === 'dhcp' ||
      (to === 'pppoe' && pppoeName === declared.pppoeName.value && pppoeUser === declared.pppoeUsername.value && passwordSource !== 'typed') ||
      (to === 'static' && address === declared.address.value && gateway === declared.gateway.value);
    if (same) {
      refusals.push({
        kind: 'nothing_to_change',
        message: `Le site est déjà déclaré en ${MODE_LABEL[to]} avec ces paramètres : rien à changer.`,
      });
    }
  }
  if (refusals.length > 0 || from === null) return { resolved: null, refusals };

  // The values the success path writes, judged NOW against the site form's
  // declarations, so the final write cannot be refused after the switch.
  const entries: Array<{ key: string; value: string }> = [{ key: KEYS.mode, value: to }];
  if (to === 'pppoe') {
    entries.push({ key: KEYS.pppoeName, value: pppoeName as string }, { key: KEYS.pppoeUsername, value: pppoeUser as string });
    if (passwordSource === 'typed') entries.push({ key: KEYS.pppoePassword, value: password as string });
  }
  if (to === 'static') entries.push({ key: KEYS.address, value: address as string }, { key: KEYS.gateway, value: gateway as string });
  const verdict = validateSiteValues(await loadSiteDeclarations(db, tenantId), { entries });
  if (verdict.errors.length > 0) {
    // Names the KEY and the rule, never a value.
    refusals.push({
      kind: 'site_values_refused',
      message:
        'Les variables du site ne pourraient pas être enregistrées après la bascule : ' +
        `${verdict.errors.map((e) => `« ${e.key} » ${e.message}`).join(' ; ')}. Rien n’a été mis en file.`,
    });
    return { resolved: null, refusals };
  }
  const expect: WanLinkFrozen['expect'] = {};
  // A template default is not the operator's word: only a value set somewhere
  // is held against the router.
  if (from === 'pppoe' && declared.pppoeName.source && declared.pppoeName.source !== 'default') expect.pppoeName = declared.pppoeName.value;
  if (from === 'static' && declared.address.source && declared.address.source !== 'default') expect.address = declared.address.value;
  if (from === 'static' && declared.gateway.source && declared.gateway.source !== 'default') expect.gateway = declared.gateway.value;
  return {
    resolved: {
      facts, place, declared, from, to,
      target: { pppoeName, pppoeUser, address, gateway },
      password: to === 'pppoe' ? password : null,
      passwordSource: to === 'pppoe' ? passwordSource : null,
      expect,
      entries,
    },
    refusals,
  };
}

// ============================================================================
// Enqueue
// ============================================================================

export interface EnqueueWanLinkInput {
  tenantId: number;
  deviceId: number;
  requestedBy: number | null;
  request: WanLinkRequest;
  revertAfterS?: number;
  /** The safety-net rule's confirmation of the expected cut. */
  confirmExpectedCut: { userId: number | null; at?: Date } | null;
  /** The device page: a job of this kind already queued or running is
   *  returned instead of refused. A rollout never sets it. */
  allowExisting?: boolean;
}

export interface EnqueueWanLinkResult {
  jobId: number;
  alreadyQueued: boolean;
  guard: ReturnType<typeof wanLinkGuard>;
  safetyNet: ReturnType<typeof wanLinkSafetyNet>;
}

const NO_BASE_STATE = '0'.repeat(64);

export async function enqueueWanLinkJob(input: EnqueueWanLinkInput): Promise<EnqueueWanLinkResult> {
  const killSwitch = await readKillSwitch(input.tenantId);
  if (killSwitch.blocked) throw new KillSwitchEngagedError(killSwitch);
  const guard = wanLinkGuard();
  const safetyNet = wanLinkSafetyNet();
  const revertAfterS = input.revertAfterS ?? WAN_LINK_REVERT_AFTER_S;
  if (!wanLinkRevertAfterValid(revertAfterS)) {
    throw new WanLinkError(
      'invalid_request',
      `Le délai de retour arrière doit aller de ${WAN_LINK_REVERT_MIN_S / 60} à ${WAN_LINK_REVERT_MAX_S / 60} minutes.`,
      400,
    );
  }
  const { resolved, refusals } = await wanLinkRefusals(input.tenantId, input.deviceId, input.request);
  if (!resolved || refusals.length > 0) {
    const first = refusals[0] ?? { kind: 'refused', message: 'Refusé.' };
    throw new WanLinkError(first.kind, refusals.map((r) => r.message).join(' '), first.kind === 'device_not_found' ? 404 : 409);
  }
  if (!input.confirmExpectedCut) {
    throw new WanLinkError('degraded_unconfirmed', `${safetyNet.rationale} La coupure prévue doit être confirmée explicitement.`, 422);
  }
  const facts = resolved.facts;
  const existing = await activeJobOf(facts.device.id);
  if (existing) {
    if (existing.kind === WAN_LINK_KIND && input.allowExisting) return { jobId: existing.id, alreadyQueued: true, guard, safetyNet };
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
          kind: WAN_LINK_KIND,
          status: 'queued',
          attempt: 0,
          // A cut is not retried silently; the operator (or the rollout) asks again.
          max_attempts: 1,
          base_state_hash: NO_BASE_STATE,
          safety_level: safetyNet.level,
          safety_peer_device_id: null,
          guard_verdict: guard.verdict,
          guard_reasons: JSON.stringify(guard.reasons),
          degraded_confirmed_by: input.confirmExpectedCut!.userId,
          degraded_confirmed_at: input.confirmExpectedCut!.at ?? now,
          requested_by: input.requestedBy,
        })
        .returning('id')) as Array<{ id: string | number }>;
      const id = Number(inserted[0].id);
      const t = resolved.target;
      await trx('wan_link_jobs').insert({
        job_id: id,
        tenant_id: input.tenantId,
        device_id: facts.device.id,
        site_id: resolved.place.siteId,
        from_mode: resolved.from,
        to_mode: resolved.to,
        pppoe_name: resolved.to === 'pppoe' ? t.pppoeName : null,
        pppoe_username: resolved.to === 'pppoe' ? t.pppoeUser : null,
        pppoe_password_enc: resolved.password ? encrypt(resolved.password) : null,
        pppoe_key_version: resolved.password ? currentKeyVersion() : null,
        pppoe_password_source: resolved.passwordSource,
        static_address: resolved.to === 'static' ? t.address : null,
        static_gateway: resolved.to === 'static' ? t.gateway : null,
        expect: JSON.stringify(resolved.expect ?? {}),
        ssh_host: sshHost,
        revert_after_s: revertAfterS,
        wait_s: wanLinkWaitS(revertAfterS),
      });
      return id;
    });
  } catch (err) {
    const pg = err as { code?: string; constraint?: string; message?: string };
    if (pg.code === '23505' && pg.constraint === 'change_jobs_one_in_flight_uq') {
      const again = await activeJobOf(facts.device.id);
      if (again && again.kind === WAN_LINK_KIND && input.allowExisting) return { jobId: again.id, alreadyQueued: true, guard, safetyNet };
      throw new DeviceBusyError(facts.device.id);
    }
    if (pg.code === '23001' && /subtree interlock/i.test(pg.message ?? '')) {
      throw new WanLinkError(
        'subtree_interlock',
        'Une tâche est en cours sur le concentrateur qui porte le tunnel de ce routeur : rien n’a été mis en file.',
      );
    }
    throw err;
  }
  logger.warn(
    { jobId, deviceId: facts.device.id, kind: WAN_LINK_KIND, from: resolved.from, to: resolved.to, requestedBy: input.requestedBy },
    'wan_link job QUEUED — a WAN1 link switch is about to be started on a customer router',
  );
  const summary = { jobId, deviceId: facts.device.id, kind: WAN_LINK_KIND, status: 'queued' };
  emitToTenantAudience(input.tenantId, SOCKET_EVENTS.JOB_QUEUED, summary, { deviceId: facts.device.id });
  emitToDevice(facts.device.id, SOCKET_EVENTS.JOB_QUEUED, summary);
  return { jobId, alreadyQueued: false, guard, safetyNet };
}

// ============================================================================
// The view — the device card
// ============================================================================

export interface WanLinkJobView {
  id: number;
  status: ChangeJobStatus;
  active: boolean;
  from: Wan1Mode;
  to: Wan1Mode;
  outcome: WanLinkOutcome | null;
  outcomeDetail: string | null;
  errorKind: string | null;
  errorMessage: string | null;
  createdAt: string;
  finishedAt: string | null;
  wroteAt: string | null;
  scriptStartedAt: string | null;
  scriptSeenAliveAt: string | null;
  decision: string | null;
  decidedAt: string | null;
  tunnelReturnedAt: string | null;
  cutExpectedUntil: string | null;
  varsWrittenAt: string | null;
  backupId: number | null;
  revertAfterS: number;
  rolloutId: number | null;
  steps: Array<{ seq: number; kind: string; status: string; output: string | null; error: string | null }>;
}

export interface WanLinkView {
  deviceId: number;
  deviceName: string;
  supported: boolean;
  eligible: boolean;
  refusals: Refusal[];
  site: { id: number; code: string | null } | null;
  declared: {
    ok: boolean;
    message: string | null;
    mode: Wan1Mode | null;
    modeSource: string | null;
    pppoeName: string | null;
    pppoeUsername: string | null;
    passwordSet: boolean;
    address: string | null;
    gateway: string | null;
    deviceOverrides: string[];
  };
  /** The latest read of the router (lint or read-back). */
  observed: {
    readAt: string;
    readBy: 'lint' | 'readback';
    mode: Wan1Mode | null;
    reasons: string[];
    params: Wan1Classification['params'];
    lte: LteReadyVerdict | null;
    takeover: { state: LteTakeoverVerdict['state']; summary: string } | null;
    warnings: WanLinkWarning[];
  } | null;
  job: WanLinkJobView | null;
  constants: {
    revertAfterS: number;
    revertMinS: number;
    revertMaxS: number;
    minRsrpDbm: number;
    minSinrDb: number;
    failoverBudgetS: number;
    armLeadS: number;
    marginS: number;
    modes: readonly Wan1Mode[];
    pppoeNames: readonly string[];
  };
}

function iso(d: Date | string | null | undefined): string | null {
  return d ? new Date(d).toISOString() : null;
}

interface StoredRead {
  reading?: WanLinkReading;
  plan?: WanLinkPlan;
  lte?: LteReadyVerdict;
  takeover?: LteTakeoverVerdict;
  warnings?: WanLinkWarning[];
  readAt?: string;
}

export async function getWanLinkView(tenantId: number, deviceId: number): Promise<WanLinkView | null> {
  const facts = await loadFacts(deviceId, tenantId);
  if (!facts) return null;
  const place = await loadPlacement(tenantId, deviceId);
  const refusals = wanLinkDeviceRefusals(facts, place);
  const supported = !refusals.some((r) => r.kind === 'brand_unsupported' || r.kind === 'concentrator_refused');
  let declared: WanDeclared | null = null;
  if (supported) {
    try {
      declared = await resolveWanVariables(tenantId, deviceId);
    } catch (err) {
      logger.warn({ err, deviceId }, 'wan_link view: the site variables could not be resolved');
    }
  }
  if (supported && declared && !declared.ok) refusals.push({ kind: 'wan_modes_not_declared', message: declared.message ?? '' });
  if (supported && declared && declared.ok && declared.deviceOverrides.length > 0) {
    refusals.push({ kind: 'device_override', message: `${declared.deviceOverrides.join(', ')} défini(es) au niveau de l’équipement.` });
  }

  const base = () => db('wan_link_jobs as w').join('change_jobs as j', 'j.id', 'w.job_id')
    .where('w.device_id', deviceId).where('w.tenant_id', tenantId).orderBy('w.job_id', 'desc');
  const row = (await base().first(
    'w.job_id', 'w.from_mode', 'w.to_mode', 'w.backup_id', 'w.wrote_at', 'w.script_started_at', 'w.script_seen_alive_at',
    'w.decision', 'w.decided_at', 'w.tunnel_returned_at', 'w.cut_expected_until', 'w.vars_written_at', 'w.outcome',
    'w.outcome_detail', 'w.revert_after_s', 'j.status', 'j.error_kind', 'j.error_message', 'j.created_at', 'j.finished_at',
    'j.rollout_id',
  )) as Record<string, any> | undefined;
  const read = (await base().whereNotNull('w.before').first('w.before', 'w.observed')) as
    | { before: StoredRead | null; observed: StoredRead | null }
    | undefined;
  const latest: { s: StoredRead; by: 'lint' | 'readback' } | null = read?.observed?.readAt
    ? { s: read.observed, by: 'readback' }
    : read?.before?.readAt
      ? { s: read.before, by: 'lint' }
      : null;
  let observed: WanLinkView['observed'] = null;
  if (latest?.s.reading) {
    const c = classifyWan1(latest.s.reading);
    observed = {
      readAt: latest.s.readAt as string,
      readBy: latest.by,
      mode: c.mode,
      reasons: c.reasons,
      params: c.params,
      lte: latest.s.lte ?? judgeLteReady(latest.s.reading.lte),
      takeover: latest.s.takeover ? { state: latest.s.takeover.state, summary: latest.s.takeover.summary } : null,
      warnings: latest.s.warnings ?? read?.before?.warnings ?? [],
    };
  }
  let job: WanLinkJobView | null = null;
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
      from: row.from_mode as Wan1Mode,
      to: row.to_mode as Wan1Mode,
      outcome: (row.outcome ?? null) as WanLinkOutcome | null,
      outcomeDetail: row.outcome_detail ?? null,
      errorKind: row.error_kind ?? null,
      errorMessage: row.error_message ?? null,
      createdAt: iso(row.created_at) as string,
      finishedAt: iso(row.finished_at),
      wroteAt: iso(row.wrote_at),
      scriptStartedAt: iso(row.script_started_at),
      scriptSeenAliveAt: iso(row.script_seen_alive_at),
      decision: row.decision ?? null,
      decidedAt: iso(row.decided_at),
      tunnelReturnedAt: iso(row.tunnel_returned_at),
      cutExpectedUntil: iso(row.cut_expected_until),
      varsWrittenAt: iso(row.vars_written_at),
      backupId: row.backup_id === null ? null : Number(row.backup_id),
      revertAfterS: Number(row.revert_after_s),
      rolloutId: row.rollout_id === null || row.rollout_id === undefined ? null : Number(row.rollout_id),
      steps: steps.map((s) => ({
        seq: Number(s.seq), kind: String(s.kind), status: String(s.status), output: s.output_redacted ?? null, error: s.error_redacted ?? null,
      })),
    };
  }
  return {
    deviceId,
    deviceName: facts.device.name,
    supported,
    eligible: supported && refusals.length === 0,
    refusals,
    site: place.siteId === null ? null : { id: place.siteId, code: place.siteCode },
    declared: {
      ok: declared?.ok ?? false,
      message: declared?.message ?? null,
      mode: declared?.mode.value ?? null,
      modeSource: declared?.mode.source ?? null,
      pppoeName: declared?.pppoeName.value ?? null,
      pppoeUsername: declared?.pppoeUsername.value ?? null,
      passwordSet: declared?.passwordSet ?? false,
      address: declared?.address.value ?? null,
      gateway: declared?.gateway.value ?? null,
      deviceOverrides: declared?.deviceOverrides ?? [],
    },
    observed,
    job,
    constants: {
      revertAfterS: WAN_LINK_REVERT_AFTER_S,
      revertMinS: WAN_LINK_REVERT_MIN_S,
      revertMaxS: WAN_LINK_REVERT_MAX_S,
      minRsrpDbm: WAN_LINK_MIN_RSRP_DBM,
      minSinrDb: WAN_LINK_MIN_SINR_DB,
      failoverBudgetS: WAN_LINK_FAILOVER_BUDGET_S,
      armLeadS: WAN_LINK_ARM_LEAD_S,
      marginS: WAN_LINK_MARGIN_S,
      modes: WAN1_MODES,
      pppoeNames: WAN1_PPPOE_NAMES,
    },
  };
}

// ============================================================================
// The cut window and its alerts
// ============================================================================

async function patchJob(jobId: number, patch: Record<string, unknown>): Promise<void> {
  await db('wan_link_jobs').where({ job_id: jobId }).update({ ...patch, updated_at: db.fn.now() });
}

/** Opens the window, from now, `seconds` long. */
/** An outcome, ALWAYS with the password wiped in the same write
 *  (`wan_link_jobs_password_wiped_chk`: no password beside an outcome). */
async function conclude(jobId: number, outcome: WanLinkOutcome, detail: string, extra: Record<string, unknown> = {}): Promise<void> {
  await patchJob(jobId, {
    ...extra,
    outcome,
    outcome_detail: (detail || 'sans détail').slice(0, 4000),
    pppoe_password_enc: null,
    pppoe_key_version: null,
  });
}

async function openCutWindow(jobId: number, seconds: number): Promise<Date> {
  const from = new Date();
  const until = new Date(from.getTime() + seconds * 1000);
  await patchJob(jobId, { cut_expected_from: from, cut_expected_until: until });
  return until;
}

/** Ends the window now (never extends it). */
async function closeCutWindow(jobId: number): Promise<void> {
  await db('wan_link_jobs')
    .where({ job_id: jobId })
    .whereNotNull('cut_expected_until')
    .update({
      cut_expected_until: db.raw('GREATEST(cut_expected_from, LEAST(cut_expected_until, now()))'),
      updated_at: db.fn.now(),
    });
}

async function wipePassword(jobId: number): Promise<void> {
  await db('wan_link_jobs').where({ job_id: jobId }).whereNotNull('pppoe_password_enc')
    .update({ pppoe_password_enc: null, pppoe_key_version: null, updated_at: db.fn.now() });
}

interface AlertTarget {
  tenantId: number;
  deviceId: number;
  deviceName: string;
  groupId: number | null;
}

async function alertTarget(jobId: number): Promise<AlertTarget | null> {
  const r = (await db('wan_link_jobs as w').join('devices as d', 'd.id', 'w.device_id')
    .where('w.job_id', jobId).first('w.tenant_id', 'w.device_id', 'd.name', 'd.group_id')) as Record<string, any> | undefined;
  return r ? { tenantId: Number(r.tenant_id), deviceId: Number(r.device_id), deviceName: String(r.name), groupId: r.group_id ?? null } : null;
}

function hhmm(d: Date): string {
  return d.toISOString().slice(11, 16);
}

/** The announcement of the planned cut: an info alert (English, like every
 *  alert) and a channel message WITHOUT a stable key — no incident opens. */
async function raiseCutStart(jobId: number, from: Wan1Mode, to: Wan1Mode, until: Date, lte: LteReadyVerdict | null): Promise<void> {
  try {
    const t = await alertTarget(jobId);
    if (!t) return;
    const signal = lte && lte.rsrp !== null ? `lte1 RSRP ${lte.rsrp} dBm${lte.sinr !== null ? `, SINR ${lte.sinr} dB` : ''}` : 'lte1 signal unread';
    const message =
      `Planned WAN link change on ${t.deviceName} (${from} → ${to}), job #${jobId}: the fixed line is cut on purpose and ` +
      `the store rides its 4G (${signal}). Down and 4G-backup alerts are held until ${until.toISOString()} (${hhmm(until)} UTC); ` +
      'the script on the router restores the old link by itself if the new one does not carry traffic.';
    await liveAlertService.add(t.tenantId, {
      severity: 'info',
      title: `${t.deviceName}: planned WAN link change (${from} → ${to})`,
      message,
      navigateTo: `/devices/${t.deviceId}`,
      deviceId: t.deviceId,
      stableKey: `wanlink:${jobId}:start`,
    });
    void notificationService
      .sendForDevice(t.tenantId, t.deviceId, t.groupId, {
        entityName: t.deviceName,
        entityUrl: `/devices/${t.deviceId}`,
        oldStatus: 'up',
        newStatus: 'maintenance',
        message,
        timestamp: new Date().toISOString(),
        severity: 'info',
        entityId: t.deviceId,
        entityType: 'device',
      })
      .catch((err: unknown) => logger.warn({ err, jobId }, 'wan_link: the planned-cut notice could not be sent'));
  } catch (err) {
    logger.warn({ err, jobId }, 'wan_link: the planned-cut alert could not be raised');
  }
}

/** The end of the window: info when the link changed (or already was),
 *  warning otherwise. Never an incident (no stable key on the channel). */
async function raiseCutEnd(jobId: number, outcome: WanLinkOutcome, detail: string): Promise<void> {
  try {
    const row = (await db('wan_link_jobs').where({ job_id: jobId }).first('cut_expected_from', 'from_mode', 'to_mode')) as
      | { cut_expected_from: Date | null; from_mode: string; to_mode: string }
      | undefined;
    // Only a window that was opened is closed out loud.
    if (!row || row.cut_expected_from === null) return;
    const t = await alertTarget(jobId);
    if (!t) return;
    const ok = outcome === 'applied' || outcome === 'present';
    const what = {
      applied: `WAN1 is now ${row.to_mode}`,
      present: `WAN1 already was ${row.to_mode}`,
      reverted: `the router put WAN1 back to ${row.from_mode} (the new link did not carry traffic)`,
      refused: 'nothing was started on the router',
      failed: 'the job failed; check the device page',
    }[outcome];
    const message = `WAN link change job #${jobId} on ${t.deviceName} ended: ${what}. Alerts are no longer held. ${detail}`.slice(0, 2000);
    await liveAlertService.add(t.tenantId, {
      severity: ok ? 'info' : 'warning',
      title: `${t.deviceName}: WAN link change ${ok ? 'done' : outcome}`,
      message,
      navigateTo: `/devices/${t.deviceId}`,
      deviceId: t.deviceId,
      stableKey: `wanlink:${jobId}:end`,
    });
    void notificationService
      .sendForDevice(t.tenantId, t.deviceId, t.groupId, {
        entityName: t.deviceName,
        entityUrl: `/devices/${t.deviceId}`,
        oldStatus: 'maintenance',
        newStatus: ok ? 'up' : 'alert',
        message,
        timestamp: new Date().toISOString(),
        severity: ok ? 'info' : 'warning',
        entityId: t.deviceId,
        entityType: 'device',
      })
      .catch((err: unknown) => logger.warn({ err, jobId }, 'wan_link: the end-of-cut notice could not be sent'));
  } catch (err) {
    logger.warn({ err, jobId }, 'wan_link: the end-of-cut alert could not be raised');
  }
}

/**
 * Called by `failJob` for every failure of this kind, and by the reaper's
 * neighbour: the outcome when none is recorded (`refused` when nothing was
 * started, `failed` otherwise), the window closed, the password wiped, the end
 * alert raised. Never throws.
 */
export async function settleWanLink(job: Pick<ChangeJobRow, 'id'>, message: string): Promise<void> {
  const jobId = Number(job.id);
  try {
    const row = (await db('wan_link_jobs').where({ job_id: jobId }).first('outcome', 'wrote_at')) as
      | { outcome: string | null; wrote_at: Date | null }
      | undefined;
    if (!row) return;
    let outcome = row.outcome as WanLinkOutcome | null;
    if (outcome === null) {
      outcome = row.wrote_at ? 'failed' : 'refused';
      await db('wan_link_jobs').where({ job_id: jobId }).whereNull('outcome').update({
        outcome,
        outcome_detail: (message || 'échec sans message').slice(0, 4000),
        pppoe_password_enc: null,
        pppoe_key_version: null,
        updated_at: db.fn.now(),
      });
    }
    await wipePassword(jobId);
    await closeCutWindow(jobId);
    await raiseCutEnd(jobId, outcome, '');
  } catch (err) {
    logger.error({ err, jobId }, 'wan_link: could not record the outcome of a failed job');
  }
}

// ============================================================================
// The job's phases (called from apply.service.ts runPhases)
// ============================================================================

export interface WanLinkStepResult {
  output: string;
  detail: Record<string, unknown>;
}

interface FrozenRow {
  job_id: string | number;
  tenant_id: number;
  device_id: number;
  site_id: number | null;
  from_mode: Wan1Mode;
  to_mode: Wan1Mode;
  pppoe_name: string | null;
  pppoe_username: string | null;
  pppoe_password_enc: string | null;
  pppoe_password_source: 'typed' | 'site' | null;
  static_address: string | null;
  static_gateway: string | null;
  expect: WanLinkFrozen['expect'] | null;
  ssh_host: string;
  revert_after_s: number;
  wait_s: number;
  backup_id: string | number | null;
}

function frozenOf(row: FrozenRow): WanLinkFrozen {
  return {
    from: row.from_mode,
    to: row.to_mode,
    target: { pppoeName: row.pppoe_name, pppoeUser: row.pppoe_username, address: row.static_address, gateway: row.static_gateway },
    expect: row.expect ?? {},
    passwordTyped: row.pppoe_password_source === 'typed',
  };
}

/** A ManagementAccessError raised by the shared SSH machinery, renamed. */
function renamed(err: unknown): unknown {
  return err instanceof ManagementAccessError ? new WanLinkError(err.kind, err.message) : err;
}

const REASON_TEXT: Record<string, string> = {
  no_wan1_interface: 'aucune interface ether1-WAN1',
  no_probe_route: 'pas de route NW-WAN1',
  two_probe_routes: 'deux routes NW-WAN1',
  no_gw_route: 'pas de route WAN1-GW',
  two_gw_routes: 'deux routes WAN1-GW',
  probe_route_not_host: 'NW-WAN1 n’est pas un /32 vers l’hôte sondé',
  gw_route_not_default: 'WAN1-GW n’est pas la route par défaut',
  no_netwatch: 'pas de netwatch WAN1',
  two_netwatch: 'deux netwatch WAN1',
  netwatch_host_mismatch: 'le netwatch WAN1 ne sonde pas l’hôte de NW-WAN1',
  wan1_not_in_wan_list: 'ether1-WAN1 n’est pas membre actif de la liste WAN',
  lte_not_in_wan_list: 'lte1 n’est pas membre actif de la liste WAN',
  pppoe_elsewhere: 'un client PPPoE actif sur une autre interface (VLAN ?)',
  two_pppoe_clients: 'deux clients PPPoE actifs sur ether1-WAN1',
  pppoe_name_not_standard: 'le client PPPoE ne s’appelle ni ADSL, ni FTTH, ni FTTO',
  pppoe_routes_enabled: 'en PPPoE, NW-WAN1 et WAN1-GW devraient être désactivées',
  pppoe_netwatch_enabled: 'en PPPoE, le netwatch WAN1 devrait être désactivé',
  pppoe_not_in_wan_list: 'le client PPPoE n’est pas membre actif de la liste WAN',
  pppoe_and_static: 'un client PPPoE ET une adresse fixe actifs',
  two_static_addresses: 'deux adresses fixes actives sur ether1-WAN1',
  two_dhcp_clients: 'deux clients DHCP sur ether1-WAN1',
  static_and_dhcp: 'une adresse fixe ET un client DHCP actifs',
  no_link: 'ni client PPPoE, ni client DHCP, ni adresse fixe actifs',
  probe_route_disabled: 'NW-WAN1 est désactivée',
  netwatch_disabled: 'le netwatch WAN1 est désactivé',
  static_address_unreadable: 'l’adresse fixe est illisible',
  static_gateway_outside: 'la passerelle de WAN1-GW n’est pas dans le réseau de l’adresse fixe',
  static_routes_differ: 'NW-WAN1 et WAN1-GW n’ont pas la même passerelle',
  dhcp_adds_default_route: 'le client DHCP ajoute sa propre route par défaut',
  dhcp_script_not_standard: 'le script du client DHCP ne repointe pas WAN1-GW',
  pppoe_name_taken: 'le nom du client PPPoE cible est déjà pris par un client actif',
  route_gateway: 'la passerelle d’une route WAN1 ne peut pas être réécrite telle quelle',
  probe_host: 'l’hôte sondé de NW-WAN1 est illisible',
};

function describeReasons(codes: readonly string[]): string {
  return codes.map((c) => (c.startsWith('unread:') ? `lecture incomplète (${c.slice(7)})` : REASON_TEXT[c] ?? c)).join(' ; ');
}

function describeMode(c: Wan1Classification): string {
  if (c.mode === null) return `structure non standard (${describeReasons(c.reasons)})`;
  if (c.mode === 'pppoe') return `PPPoE ${c.params.pppoeName ?? '?'} (${c.params.pppoeUser ?? '?'})`;
  if (c.mode === 'static') return `IP fixe ${c.params.address ?? '?'} via ${c.params.gateway ?? '?'}`;
  return 'box (DHCP)';
}

function describeLte(v: LteReadyVerdict): string {
  const parts = [
    v.registration ? `enregistrement ${v.registration}` : 'enregistrement non lu',
    v.rsrp !== null ? `RSRP ${v.rsrp} dBm` : 'RSRP non lu',
    v.sinr !== null ? `SINR ${v.sinr} dB` : 'SINR non lu',
  ];
  return parts.join(', ');
}

const WARNING_TEXT: Record<WanLinkWarning, string> = {
  leftover_kept: 'l’ancien lien reste sur le routeur, désactivé (retour manuel immédiat) ; la dérive le signalera',
  public_address_on_router: 'le routeur portera l’adresse publique : vérifiez le filtrage en entrée WAN',
  dns_open_on_wan: 'le routeur répond au DNS sans les règles DNS-Amp : lancez la conformité (DNS-Amp)',
  ipsec_static_policies: 'des politiques IPsec statiques existent : les tunnels se rétabliront depuis la nouvelle adresse',
  no_sim_line: 'aucune ligne SIM n’est rattachée à ce routeur',
  sim_low: 'la ligne SIM du routeur est presque épuisée',
  sim_balance_unknown: 'le solde de la ligne SIM n’est pas connu',
};

export function describeWanWarnings(ws: readonly WanLinkWarning[]): string {
  return ws.map((w) => WARNING_TEXT[w]).join(' ; ');
}

/** What became of the one line. */
interface SendResult {
  status: 'accepted' | 'refused' | 'lost';
  said?: string;
}

export class WanLinkRun {
  private facts: Facts | null = null;
  private frozenRow: FrozenRow | null = null;
  private plan: WanLinkPlan | null = null;
  private lte: LteReadyVerdict | null = null;
  private collateral: WanCollateral | null = null;
  private noop = false;
  private sent: SendResult | null = null;
  private scriptId: string | null = null;
  private scriptDead = false;
  /** `deps.now()` when the line left; null = not sent. */
  private startedAt: number | null = null;
  private decision: 'applied' | 'reverted' | 'abandoned' | 'none' | null = null;
  private readonly backups: SshPreflightBackup;

  constructor(
    private readonly job: ChangeJobRow,
    private readonly device: { id: number; uuid?: string | null; name?: string | null },
    private readonly correlationId: string,
    private readonly workerId?: string,
  ) {
    this.backups = new SshPreflightBackup(job, device, correlationId, WAN_LINK_KIND);
  }

  private get jobId(): number {
    return Number(this.job.id);
  }

  get isNoop(): boolean {
    return this.noop;
  }

  get noopReason(): string {
    return 'Le routeur est déjà sur le lien demandé : rien ne sera écrit, donc aucune sauvegarde préalable n’est nécessaire ; ' +
      'les variables du site seront enregistrées.';
  }

  /** True when the script was sent (or may have been) and was not seen dead:
   *  the job must wait for its decision. */
  get mustAwaitDecision(): boolean {
    return this.startedAt !== null && !this.scriptDead && this.sent?.status !== 'refused';
  }

  get noAwaitReason(): string {
    if (this.sent?.status === 'refused') return `Le routeur a refusé de lancer le script (${this.sent.said ?? ''}) : rien n’a démarré, rien à attendre.`;
    if (this.scriptDead) return `Le script ${this.scriptId ?? ''} n’est plus listé sur une nouvelle session : il n’a pas survécu à sa session, rien à attendre.`;
    return 'Aucun script n’a été lancé : rien à attendre.';
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
    if (!this.facts) throw new WanLinkError('internal', 'La tâche n’a pas été inspectée avant d’agir.');
    return this.facts;
  }

  private requireFrozen(): FrozenRow {
    if (!this.frozenRow) throw new WanLinkError('internal', 'La tâche n’a pas lu ses paramètres figés.');
    return this.frozenRow;
  }

  private name(): string {
    return this.device.name ?? `#${this.device.id}`;
  }

  /** The plan's refusal, the 4G's and the takeover's, by name. */
  private judge(reading: WanLinkReading, plan: WanLinkPlan): { lte: LteReadyVerdict; takeover: LteTakeoverVerdict } {
    const frozen = this.requireFrozen();
    if (plan.state === 'refused') {
      if (plan.reason === 'mode_differs') {
        throw new WanLinkError(
          'mode_differs',
          `${this.name()} est en ${describeMode(plan.observed)} alors que son site est déclaré en ${MODE_LABEL[frozen.from_mode]} : ` +
            `rien n’a été écrit. Corrigez « ${KEYS.mode} » du site (ou le routeur) avant de relancer.`,
        );
      }
      if (plan.reason === 'params_differ') {
        throw new WanLinkError(
          'params_differ',
          `${this.name()} est en ${describeMode(plan.observed)}, mais les variables du site déclarent d’autres paramètres ` +
            `(${plan.details.join(', ')}) : rien n’a été écrit.`,
        );
      }
      if (plan.reason === 'mode_not_standard') {
        throw new WanLinkError(
          'mode_not_standard',
          `Le WAN1 de ${this.name()} n’a pas la structure standard des modèles (${describeReasons(plan.details)}) : rien n’a ` +
            'été écrit. Les routeurs en structure ISP1/ISP2 passent d’abord par leur migration.',
        );
      }
      throw new WanLinkError(plan.reason ?? 'plan_refused', `Plan refusé (${describeReasons(plan.details)}) : rien n’a été écrit.`);
    }
    const lte = judgeLteReady(reading.lte);
    if (lte.state !== 'ready') {
      throw new WanLinkError(
        'lte_not_ready',
        `La 4G de ${this.name()} n’est pas prête à porter le magasin (${describeLte(lte)}${lte.reasons.length > 0 ? ` — ${lte.reasons.join(', ')}` : ''} ; ` +
          `il faut lte1 en marche, enregistrée, RSRP ≥ ${WAN_LINK_MIN_RSRP_DBM} dBm et SINR ≥ ${WAN_LINK_MIN_SINR_DB} dB) : rien n’a été écrit.`,
      );
    }
    const mgmt = reading.l2tpMgmt;
    if (!mgmt || !mgmt.present || mgmt.disabled || !mgmt.running) {
      throw new WanLinkError(
        'no_l2tp_mgmt',
        `${this.name()} n’a pas de tunnel l2tp-mgmt en marche${mgmt === null ? ' (lecture incomplète)' : ''} : la tâche suit la ` +
          'bascule par ce tunnel. Rien n’a été écrit.',
      );
    }
    const takeover = judgeLteTakeover(reading.egress, plan.retiredInterfaces);
    if (takeover.state !== 'via_lte') {
      throw new WanLinkError(
        'mgmt_not_via_lte',
        `Une fois WAN1-GW coupée, le tunnel de gestion de ${this.name()} ne passerait pas de façon établie par la 4G ` +
          `(${takeover.summary}) : rien n’a été écrit.`,
      );
    }
    return { lte, takeover };
  }

  private line(plan: WanLinkPlan): string {
    const frozen = this.requireFrozen();
    try {
      const l = wanLinkLine(plan, this.jobId, frozen.revert_after_s);
      assertWanLinkOnlyLines(l, plan, this.jobId, frozen.revert_after_s);
      return l;
    } catch (err) {
      if (err instanceof WanLinkLineRefused || err instanceof WanLinkInputError) {
        throw new WanLinkError('line_outside_wan_link', `${err.message} — rien n’a été écrit.`);
      }
      throw err;
    }
  }

  async inspect(): Promise<WanLinkStepResult> {
    return this.held(async () => {
      const frozen = (await db('wan_link_jobs').where({ job_id: this.jobId }).first('*')) as FrozenRow | undefined;
      if (!frozen) throw new WanLinkError('job_row_missing', 'La tâche n’a pas de paramètres figés (wan_link_jobs) : refus.');
      this.frozenRow = frozen;
      const facts = await loadFacts(this.device.id, this.job.tenant_id);
      if (!facts) throw new WanLinkError('device_not_found', `Équipement #${this.device.id} introuvable.`);
      this.facts = facts;
      const place = await loadPlacement(this.job.tenant_id, this.device.id);
      const refusals = wanLinkDeviceRefusals(facts, place);
      if (refusals.length > 0) throw new WanLinkError(refusals[0].kind, refusals.map((r) => r.message).join(' '));
      const host = sshHostOf(facts);
      if (host !== frozen.ssh_host) {
        throw new WanLinkError(
          'ssh_moved',
          `Le canal SSH de ${facts.device.name} pointe désormais vers ${host ?? 'aucune adresse'} au lieu de ${frozen.ssh_host} : rien n’a été écrit ; relancez la tâche.`,
        );
      }
      await this.backups.probeRoad(sshCredentialOf(facts));
      const { reading, collateral, warnings } = await withProvenCli(facts, this.ctx('lint'), async (cli) => {
        await assertFamily(cli, facts);
        const r = await readWanRouter(cli);
        return { ...r, warnings: await readWarnings(cli, frozen.to_mode) };
      });
      this.collateral = collateral;
      const plan = wanLinkPlan(reading, frozenOf(frozen), this.jobId);
      this.plan = plan;
      const all = [...new Set([...plan.warnings as WanLinkWarning[], ...warnings, ...(await simWarnings(this.job.tenant_id, this.device.id))])];
      const stored: StoredRead = { reading, plan, warnings: all, readAt: new Date().toISOString() };
      await patchJob(this.jobId, { before: JSON.stringify({ ...stored, collateral }) });
      if (plan.state === 'present') {
        this.noop = true;
        return { output: `${this.name()} est déjà en ${describeMode(plan.observed)} : rien à écrire`, detail: { noop: true } };
      }
      const { lte, takeover } = this.judge(reading, plan);
      this.lte = lte;
      await patchJob(this.jobId, { before: JSON.stringify({ ...stored, lte, takeover, collateral }) });
      const line = this.line(plan);
      return {
        output:
          `${describeMode(plan.observed)} → ${MODE_LABEL[frozen.to_mode]} ; 4G prête (${describeLte(lte)}) ; tunnel de gestion par la 4G ` +
          `une fois WAN1-GW coupée ; un script de ${line.length} caractères à lancer, retour arrière seul après ${frozen.revert_after_s} s` +
          (all.length > 0 ? ` — à savoir : ${describeWanWarnings(all)}` : ''),
        detail: { noop: false, from: plan.from, to: plan.to, retired: plan.retiredInterfaces, warnings: all, lte, takeover: takeover.state },
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
      if (!binary) throw new WanLinkError('backup_failed', 'Le routeur n’a produit aucune sauvegarde binaire : refus.');
      await patchJob(this.jobId, { backup_id: binary.id });
      return {
        backupId: binary.id,
        output: `sauvegarde préalable #${binary.id} stockée (${stored.map((s) => `${s.kind} ${s.bytes} o`).join(', ')}), récupérée par SFTP et effacée du routeur`,
        detail: { backupIds: stored.map((s) => s.id), road: 'sftp' },
      };
    });
  }

  async apply(onWrite: () => void): Promise<WanLinkStepResult> {
    return this.held(async () => {
      const facts = this.requireFacts();
      const frozen = this.requireFrozen();
      const lintPlan = this.plan;
      if (!lintPlan) throw new WanLinkError('internal', 'La tâche n’a pas établi son plan à l’inspection : refus d’écrire.');
      const backupRow = (await db('wan_link_jobs').where({ job_id: this.jobId }).first('backup_id', 'pppoe_password_enc')) as
        | { backup_id: string | number | null; pppoe_password_enc: string | null }
        | undefined;
      if (!backupRow || backupRow.backup_id === null) {
        throw new WanLinkError('backup_missing', 'Aucune sauvegarde préalable n’est enregistrée pour cette tâche : refus d’écrire.');
      }
      const password = frozen.to_mode === 'pppoe' ? (backupRow.pppoe_password_enc ? decrypt(backupRow.pppoe_password_enc) : null) : null;
      if (frozen.to_mode === 'pppoe' && password === null) {
        throw new WanLinkError('password_missing', 'Le mot de passe PPPoE de la tâche n’est plus disponible : rien n’a été écrit ; relancez la tâche.');
      }

      const out = await withProvenCli(facts, this.ctx('apply'), async (cli) => {
        // Read AGAIN on the session that writes: a router that changed since
        // lint is refused, unwritten.
        const { reading } = await readWanRouter(cli);
        const plan = wanLinkPlan(reading, frozenOf(frozen), this.jobId);
        const shape = (p: WanLinkPlan) => JSON.stringify({ s: p.state, f: p.from, t: p.to, st: p.steps, h: p.probeHost });
        if (shape(plan) !== shape(lintPlan)) {
          throw new WanLinkError(
            'state_changed',
            `Le WAN1 de ${this.name()} a changé entre l’inspection et l’écriture (${describeMode(plan.observed)}) : rien n’a été écrit ; relancez la tâche.`,
          );
        }
        const { lte } = this.judge(reading, plan);
        this.lte = lte;
        this.plan = plan;
        // The allow-list judges the REDACTED line; the password goes in last.
        const redacted = this.line(plan);
        let line = redacted;
        if (password !== null) {
          cli.protect(password);
          line = substituteLine(
            redacted,
            [{ placeholder: WAN_PPPOE_PASSWORD_PLACEHOLDER, key: KEYS.pppoePassword, plaintext: password }],
            (l: string) => {
              assertConsoleLine(l);
              if (l.includes('?')) throw new Error('a "?" in the line');
            },
          ).substituted.command;
        }
        // The window opens, and is announced, BEFORE the line leaves.
        const until = await openCutWindow(this.jobId, frozen.wait_s);
        await raiseCutStart(this.jobId, frozen.from_mode, frozen.to_mode, until, lte);
        // Stamped BEFORE the line: a worker that dies on it leaves "maybe
        // written" behind, never "nothing written".
        await patchJob(this.jobId, { wrote_at: db.fn.now(), script_started_at: db.fn.now() });
        this.startedAt = deps.now();
        let result: SendResult;
        let printed = '';
        try {
          const res = await cli.exec(`${line}; :put "${CMD_OK}"`, { isWrite: true });
          printed = `${res.stdout}\n${res.stderr}`;
          if (printed.includes(CMD_OK)) result = { status: 'accepted' };
          else {
            const said = printed.replace(/\s+/g, ' ').trim().slice(0, 300);
            result = said === '' ? { status: 'lost', said: 'aucune réponse, la session s’est fermée' } : { status: 'refused', said };
          }
        } catch (err) {
          result = { status: 'lost', said: (err instanceof Error ? err.message : String(err)).slice(0, 300) };
        }
        // The router's words may quote the line it refused, and the line holds
        // the password: it never leaves this function in clear.
        if (password !== null && result.said) result = { ...result, said: result.said.split(password).join('***') };
        return { result, printed, until };
      });
      this.sent = out.result;
      if (out.result.status === 'refused') {
        // Nothing started on the router: the stamps go, the window closes.
        this.startedAt = null;
        await patchJob(this.jobId, { wrote_at: null, script_started_at: null, sent: JSON.stringify({ line: out.result }) });
        await closeCutWindow(this.jobId);
        throw new WanLinkError('script_refused', `Le routeur a refusé de lancer le script (${out.result.said ?? ''}) : rien n’a été modifié.`);
      }
      onWrite();
      this.scriptId = parseGuardJobId(out.printed);
      if (this.scriptId) await patchJob(this.jobId, { script_job_id: this.scriptId });
      // The script outliving the session that started it is OBSERVED on a
      // NEW session, before its lead ends.
      let alive: boolean | null = null;
      if (this.scriptId) {
        await deps.sleep(deps.guardSettleMs);
        try {
          alive = await withProvenCli(facts, this.ctx('apply'), async (cli) =>
            parseGuardJobAlive(await cli.read(LEGACY_SSH_READS.guardJob(this.scriptId as string))));
        } catch (err) {
          if (err instanceof ManagementAccessError && err.kind === 'identity_mismatch') throw err;
          alive = null;
        }
        if (alive === true) await patchJob(this.jobId, { script_seen_alive_at: db.fn.now() });
        if (alive === false) this.scriptDead = true;
      }
      await patchJob(this.jobId, { sent: JSON.stringify({ line: out.result, scriptId: this.scriptId, alive }) });
      const state = out.result.status === 'lost'
        ? `la session s’est fermée sur la ligne (${out.result.said ?? ''}) : le script a pu démarrer, il décide seul`
        : this.scriptId === null
          ? `script lancé, sans identifiant de tâche (« ${LEGACY_GUARD_JOB_TAG}| » vide) : sa survie ne peut pas être constatée, il décide seul`
          : alive === true
            ? `script ${this.scriptId} lancé et vu vivant sur une nouvelle session`
            : alive === false
              ? `script ${this.scriptId} lancé mais plus listé sur une nouvelle session : il n’a pas survécu à sa session`
              : `script ${this.scriptId} lancé ; sa présence n’a pas pu être relue (la coupure a pu commencer), il décide seul`;
      return {
        output: `coupure annoncée jusqu’à ${hhmm(out.until)} UTC ; ${state}`,
        detail: { sent: out.result, scriptId: this.scriptId, alive, waitS: frozen.wait_s },
      };
    });
  }

  /**
   * The script's decision. Bounded by `wait_s` from the line. Never dials
   * while the concentrator says the PPP session is down. After APPLIED
   * or REVERTED the default route moved again — the tunnel's second failover —
   * so the job waits one more failover budget before the read-back.
   */
  async awaitDecision(): Promise<WanLinkStepResult> {
    return this.held(async () => {
      const frozen = this.requireFrozen();
      const startedAt = this.startedAt;
      if (startedAt === null) throw new WanLinkError('internal', 'Aucun script n’a été lancé.');
      const cutAt = startedAt + WAN_LINK_ARM_LEAD_S * 1000;
      const deadline = startedAt + frozen.wait_s * 1000;
      const deviceRow = (await db('devices').where({ id: this.device.id }).first('concentrator_id')) as { concentrator_id: number | null } | undefined;
      const watched = deviceRow?.concentrator_id !== null && deviceRow?.concentrator_id !== undefined;
      const openSession = async () => (await db('ppp_sessions').where({ device_id: this.device.id }).whereNull('ended_at')
        .orderBy('started_at', 'desc').first('id')) as { id: string | number } | undefined;
      const precut = watched ? (await openSession())?.id ?? null : null;
      let returned = false;
      let lastSaid = '';
      for (;;) {
        const now = deps.now();
        let pppDown = false;
        if (watched) {
          const open = await openSession();
          pppDown = !open;
          if (open && precut !== null && String(open.id) !== String(precut) && !returned) {
            returned = true;
            await patchJob(this.jobId, { tunnel_returned_at: db.fn.now() });
          }
        }
        if (!pppDown) {
          const facts = (await loadFacts(this.device.id, this.job.tenant_id)) ?? this.requireFacts();
          try {
            const log = await withProvenCli(facts, this.ctx('reconnect'), async (cli) =>
              parseWanLinkLog(await cli.read(WAN_SSH_READS.wanLog(this.jobId)), this.jobId));
            this.facts = facts;
            if (log.verdict === 'abandoned') {
              this.decision = 'abandoned';
              await patchJob(this.jobId, { decision: 'abandoned', decided_at: db.fn.now() });
              return { output: `le script a renoncé sans rien modifier : ${log.lines.join(' / ').slice(0, 300)}`, detail: { decision: 'abandoned', lines: log.lines } };
            }
            if (log.verdict === 'applied' || log.verdict === 'reverted') {
              this.decision = log.verdict;
              await patchJob(this.jobId, { decision: log.verdict, decided_at: db.fn.now() });
              // The POST (or the revert) moved the default route again: the
              // tunnel fails over a second time before the read-back.
              await deps.sleep(WAN_LINK_FAILOVER_BUDGET_S * 1000);
              return {
                output: `décision du script lue ${Math.round((deps.now() - startedAt) / 1000)} s après son lancement : ` +
                  `${log.verdict === 'applied' ? 'nouveau lien en place' : 'ancien lien remis'} (${log.lines[log.lines.length - 1] ?? ''})`,
                detail: { decision: log.verdict, lines: log.lines },
              };
            }
            if (log.verdict === 'none' && now > cutAt + WAN_LINK_MARGIN_S * 1000) {
              this.decision = 'none';
              return {
                output: `aucune ligne du script dans le journal ${Math.round((now - startedAt) / 1000)} s après son lancement : il n’a pas tourné`,
                detail: { decision: 'none' },
              };
            }
            lastSaid = log.verdict === 'started' ? 'le script a commencé, sa décision n’est pas encore prise' : 'le script n’a pas encore commencé';
          } catch (err) {
            if (err instanceof ManagementAccessError && err.kind === 'identity_mismatch') throw err;
            lastSaid = 'le routeur ne répond pas encore (bascule du tunnel)';
          }
        } else {
          lastSaid = 'le concentrateur voit la session PPP fermée : le routeur n’est pas appelé';
        }
        if (now >= deadline) {
          const backup = frozen.backup_id ?? (await db('wan_link_jobs').where({ job_id: this.jobId }).first('backup_id'))?.backup_id;
          throw new WanLinkError(
            'tunnel_not_back',
            `${this.name()} n’a pas pu être relu dans les ${frozen.wait_s} s qui suivent le lancement du script (${lastSaid}). ` +
              `Le script, lancé sur le routeur, remet l’ancien lien de lui-même si le nouveau ne passe pas de trafic dans les ` +
              `${frozen.revert_after_s} s ; vérifiez le site. Les variables du site n’ont pas été modifiées. ` +
              (backup ? `La sauvegarde préalable #${backup} est conservée.` : ''),
          );
        }
        await deps.sleep(deps.pollMs);
      }
    });
  }

  /** The read-back on fresh proven sessions, the outcome, and — on success —
   *  the site's variables. */
  async verify(wrote: boolean): Promise<WanLinkStepResult> {
    return this.held(async () => {
      const frozen = this.requireFrozen();
      const plan = this.plan;
      if (!plan) throw new WanLinkError('internal', 'La tâche n’a pas établi son plan.');
      if (!wrote) return this.settleSuccess('present', plan, null, null, 'le routeur était déjà sur le lien demandé');

      // Retried until the job's bound plus one failover: the tunnel may still
      // be settling after the script's decision.
      const startedAt = this.startedAt ?? deps.now();
      const deadline = startedAt + (frozen.wait_s + WAN_LINK_FAILOVER_BUDGET_S) * 1000;
      let got: { reading: WanLinkReading; collateral: WanCollateral; log: ReturnType<typeof parseWanLinkLog> } | null = null;
      let lastErr = '';
      for (;;) {
        const facts = (await loadFacts(this.device.id, this.job.tenant_id)) ?? this.requireFacts();
        const open = (await db('devices').where({ id: this.device.id }).first('concentrator_id'))?.concentrator_id
          ? await db('ppp_sessions').where({ device_id: this.device.id }).whereNull('ended_at').first('id')
          : { id: 'unconcentrated' };
        if (open) {
          try {
            got = await withProvenCli(facts, this.ctx('postcheck'), async (cli) => {
              const r = await readWanRouter(cli);
              const log = parseWanLinkLog(await cli.read(WAN_SSH_READS.wanLog(this.jobId)), this.jobId);
              return { ...r, log };
            });
            break;
          } catch (err) {
            if (err instanceof ManagementAccessError && err.kind === 'identity_mismatch') throw err;
            lastErr = err instanceof Error ? err.message.slice(0, 200) : String(err);
          }
        } else {
          lastErr = 'session PPP fermée sur le concentrateur';
        }
        if (deps.now() >= deadline) {
          throw new WanLinkError(
            'tunnel_not_back',
            `${this.name()} n’a pas pu être relu après la décision du script (${lastErr}). Les variables du site n’ont pas été ` +
              'modifiées ; la sauvegarde préalable est conservée.',
          );
        }
        await deps.sleep(deps.pollMs);
      }
      const { reading, collateral, log } = got;
      const frozenPlan = frozenOf(frozen);
      // What the job must never have changed.
      const before = this.collateral;
      const collateralChanged = before !== null && (
        (before.lteApnProfiles ?? '') !== (collateral.lteApnProfiles ?? '') ||
        JSON.stringify(before.l2tpMgmt ? { p: before.l2tpMgmt.present, d: before.l2tpMgmt.disabled } : null) !==
          JSON.stringify(collateral.l2tpMgmt ? { p: collateral.l2tpMgmt.present, d: collateral.l2tpMgmt.disabled } : null)
      );
      const target = wanLinkTargetHolds(reading, frozenPlan);
      const fromBack = wanLinkFromHolds(reading, plan.observed);
      const observed = { reading, collateral, log, readAt: new Date().toISOString(), lte: judgeLteReady(reading.lte) };
      await patchJob(this.jobId, { observed: JSON.stringify(observed) });
      const now = classifyWan1(reading);
      if (collateralChanged) {
        const msg = `La relecture montre un changement hors du périmètre WAN1 (profils APN de lte1 ou l2tp-mgmt) : vérifiez ${this.name()}. ` +
          `WAN1 : ${describeMode(now)}. Les variables du site n’ont pas été modifiées ; la sauvegarde préalable est conservée.`;
        await conclude(this.jobId, 'failed', msg);
        throw new WanLinkError('collateral_change', msg);
      }
      if (target === true) {
        const note = log.verdict === 'applied' ? '' : ' (aucune ligne APPLIED dans le journal du routeur : redémarrage ? jugé sur la relecture)';
        return this.settleSuccess('applied', plan, observed, log.verdict, `${describeMode(now)} relu sur une nouvelle session${note}`);
      }
      if (fromBack === true) {
        if (log.verdict === 'reverted') {
          const msg = `Le script a remis l’ancien lien (${describeMode(now)}) : le nouveau ne passait pas de trafic dans les ` +
            `${frozen.revert_after_s} s (${log.lines[log.lines.length - 1] ?? ''}). Les variables du site n’ont pas été modifiées ; ` +
            'l’ancien lien est en place. Vérifiez les paramètres (identifiants PPPoE, box, passerelle) avant de relancer.';
          await conclude(this.jobId, 'reverted', msg);
          throw new WanLinkError('wan_link_reverted', msg);
        }
        const why = log.verdict === 'abandoned' || this.decision === 'abandoned'
          ? `le script a renoncé (${log.lines.find((l) => l.includes('ABANDONED')) ?? ''})`
          : this.scriptDead
            ? 'le script n’a pas survécu à la session qui l’a lancé'
            : 'le script n’a laissé aucune décision';
        const kind = this.scriptDead ? 'script_not_running' : log.verdict === 'abandoned' ? 'script_abandoned' : 'script_not_running';
        const msg = `${why} : rien n’a été modifié, ${this.name()} est toujours en ${describeMode(now)}. Les variables du site n’ont pas été modifiées.`;
        await conclude(this.jobId, 'failed', msg);
        throw new WanLinkError(kind, msg);
      }
      const msg = `La relecture ne montre ni le nouveau lien en marche ni l’ancien : ${describeMode(now)}` +
        `${target === null || fromBack === null ? ' (lecture incomplète)' : ''} ; journal du script : ${log.verdict}. ` +
        'Les variables du site n’ont pas été modifiées ; la sauvegarde préalable est conservée.';
      await conclude(this.jobId, 'failed', msg);
      throw new WanLinkError('readback_failed', msg);
    });
  }

  /** applied / present: the site's variables, the outcome, the window closed,
   *  the password wiped, the end alert, the collection (best effort). */
  private async settleSuccess(
    outcome: 'applied' | 'present',
    plan: WanLinkPlan,
    observed: Record<string, unknown> | null,
    verdict: string | null,
    said: string,
  ): Promise<WanLinkStepResult> {
    const frozen = this.requireFrozen();
    const row = (await db('wan_link_jobs').where({ job_id: this.jobId }).first('pppoe_password_enc', 'site_id')) as
      | { pppoe_password_enc: string | null; site_id: number | null }
      | undefined;
    const entries: Array<{ key: string; value: string }> = [{ key: KEYS.mode, value: frozen.to_mode }];
    if (frozen.to_mode === 'pppoe') {
      entries.push({ key: KEYS.pppoeName, value: frozen.pppoe_name as string }, { key: KEYS.pppoeUsername, value: frozen.pppoe_username as string });
      if (frozen.pppoe_password_source === 'typed' && row?.pppoe_password_enc) {
        entries.push({ key: KEYS.pppoePassword, value: decrypt(row.pppoe_password_enc) });
      }
    }
    if (frozen.to_mode === 'static') {
      entries.push({ key: KEYS.address, value: frozen.static_address as string }, { key: KEYS.gateway, value: frozen.static_gateway as string });
    }
    const siteId = row?.site_id ?? null;
    try {
      if (siteId === null) throw new WanLinkError('no_site', 'Le routeur n’est plus rattaché à un site.');
      await variableResolver.setSiteValues(this.job.tenant_id, siteId, { entries }, { updatedBy: this.job.requested_by ?? null });
    } catch (err) {
      const why = err instanceof SiteVariablesRefusedError
        ? err.message.slice(0, 400)
        : err instanceof Error ? err.message.slice(0, 300) : String(err);
      const msg = `${outcome === 'applied' ? `Le lien de ${this.name()} a changé (${said})` : said}, mais les variables du site n’ont ` +
        `pas pu être enregistrées (${why}) : mettez « ${KEYS.mode} » et ses paramètres à jour à la main avant le prochain rendu.`;
      await conclude(this.jobId, 'failed', msg);
      throw new WanLinkError('vars_not_written', msg);
    }
    const detail = `${said} ; variables du site enregistrées (${entries.map((e) => e.key).join(', ')}).` +
      (outcome === 'applied' && plan.warnings.includes('leftover_kept') ? ` ${WARNING_TEXT.leftover_kept}.` : '');
    await conclude(this.jobId, outcome, detail, { vars_written_at: db.fn.now() });
    await closeCutWindow(this.jobId);
    await raiseCutEnd(this.jobId, outcome, detail);
    if (outcome === 'applied') {
      deps.collect(this.device.id, this.job.tenant_id).catch((err: unknown) =>
        logger.warn({ err, deviceId: this.device.id, jobId: this.jobId }, 'wan_link: the configuration collection after the switch failed'));
    }
    return { output: detail, detail: { outcome, verdict } };
  }
}
