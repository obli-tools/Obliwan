/**
 * ObliWAN — the WireGuard link between the ObliWAN host and a concentrator,
 * so the host reaches 100.64.0.0/10 (every CPE's tunnel address) through it.
 *
 *   ensureConcentratorLink(input)        enqueue the CHR half (a change job)
 *   ConcentratorLinkRun                  that job's phases (apply.service.ts)
 *   getConcentratorLinkView(id)          both halves, probed, for the device page
 *   switchConcentratorApi(id, via, user) the SECOND, separate gesture: move the
 *                                        CHR's own RouterOS API transport into
 *                                        the tunnel, or back to its public address
 *
 * THE DESIGN (shared/src/concentratorLink.ts says it in full): a /30 transit
 * inside 100.64.0.0/10 and outside every allocation pool; the CHR on .1 of it,
 * the host on .2; the host routes 100.64.0.0/10 into WireGuard; the CHR
 * masquerades what comes from the host address towards 100.64.0.0/10, so each
 * CPE sees its own L2TP peer as the source and answers it. No CPE changes.
 *
 * ┌─ THE CHR HALF IS A CHANGE JOB ───────────────────────────────────────────┐
 * │ Kind `concentrator_link`, on the CHR's device row: the per-device lock,  │
 * │ the identity assertion on a fresh socket and the guard run in           │
 * │ `runPhases`; then this job's branch:                                     │
 * │   lint              read six menus (audited), decide. A CONFLICT stops   │
 * │                     here, before any backup, having written nothing.     │
 * │   preflight_backup  `takeDeviceBackup()`, before the first write.        │
 * │                     SKIPPED when every item is already present (nothing │
 * │                     will be written) — the step says so.                │
 * │   arm_deadman       SKIPPED (CONCENTRATOR_LINK_NO_DEADMAN).               │
 * │   apply             re-read, re-decide on the same socket, then one      │
 * │                     `/add` at a time, each one read back before the next.│
 * │   postcheck         the whole set read back; the CHR's public key        │
 * │                     recorded; the host's config file written.            │
 * │ ADDITIVE ONLY (chrMenus.ts): `add`, never set/move/remove/enable, and a  │
 * │ conflict instead of any of them.                                         │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE PRIVATE KEY ───────────────────────────────────────────────────────┐
 * │ ObliWAN's key pair is generated here (wgKeys.ts). The PRIVATE key is      │
 * │ vault ciphertext on `concentrator_links` and is decrypted in exactly one │
 * │ place, `writeHostConfig`, straight into the 0600 file the sidecar reads.  │
 * │ It is in no change_jobs / concentrator_link_jobs column, no step output,  │
 * │ no audit row and no log line: the job sends the CHR only the PUBLIC key.│
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ ONE LINK PER INSTALLATION ─────────────────────────────────────────────┐
 * │ The host half is one interface, one config file and ONE peer whose      │
 * │ AllowedIPs is all of 100.64.0.0/10: it follows one CHR. A link is BOUND  │
 * │ from its first write on the CHR (or its provisioning), and a second     │
 * │ concentrator is refused while one is (`host_link_taken`), at enqueue and │
 * │ again at lint; migration 053's `concentrator_links_one_bound_uq` is the  │
 * │ backstop, and it fires before the second job's first add. There is no  │
 * │ "unbind" operation. The view binds the sidecar's report to THIS link by  │
 * │ key: a status or config file for another CHR's key is never shown as     │
 * │ this link being up.                                                      │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ THE PREFLIGHT BACKUP IS PULLED, NEVER UPLOADED BY THE CHR ─────────────┐
 * │ `takeDeviceBackup()` (backup.service.ts) pulls the files over a channel │
 * │ ObliWAN already holds: `/file/read` on the CHR's RouterOS API session   │
 * │ (RouterOS 7.13+) when that session is TLS with a pinned fingerprint or  │
 * │ runs on a non-public address, else SFTP over an SSH transport on that   │
 * │ same non-public address. No URL is handed to the CHR. A binary backup   │
 * │ of the CHR carries every site's PPP secret, so a CHR dialled in         │
 * │ cleartext on its public address, with no such channel, is refused       │
 * │ BEFORE any file is created: the job stops at `preflight_backup` with    │
 * │ nothing written, and the message says what to add (`defaultTakeBackup`).│
 * │ The harness runs the REAL `takeDeviceBackup()` both ways.               │
 * └─────────────────────────────────────────────────────────────────────────┘
 */

import fsp from 'fs/promises';
import net from 'net';
import type { Knex } from 'knex';
import {
  ACTIVE_CHANGE_JOB_STATUSES,
  CONCENTRATOR_LINK_KIND,
  DEFAULT_LINK_LISTEN_PORT,
  DEFAULT_LINK_TRANSIT,
  LINK_HANDSHAKE_FRESH_SECONDS,
  LINK_PROBE_MAX_CLIENTS,
  LINK_PROBE_SITES_PER_CLIENT,
  LINK_PROBE_STABLE_SECONDS,
  LINK_SIDECAR_STALE_SECONDS,
  SOCKET_EVENTS,
  deriveTransit,
  isWireGuardKey,
  listenPortProblem,
  routerOsServiceSet,
  transitProblem,
  type ConcentratorLinkView,
  type LinkChrSide,
  type LinkClientProbe,
  type LinkItem,
  type LinkProbe,
  type LinkSiteProbe,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { auditedCommand, type CommandIntent } from '../audit.service';
import { appendAudit } from '../attestation/auditLog.service';
import { decrypt, encrypt, currentKeyVersion } from '../secretVault.service';
import { emitToDevice } from '../fleet/fleetEvents';
import { emitToTenantAudience } from '../fleet/scopedEmit';
import { getRouterOsPool, resolveRouterOsTarget } from '../fleet/routerosPool';
import { assertTargetBinding } from '../fleet/deviceBinding.service';
import {
  apiChannelAcceptable,
  ChangeError,
  takeDeviceBackup,
  type ApiChannelJudgement,
} from '../change/backup.service';
import { ROUTEROS_FILE_READ_SINCE } from '../change/transfer.service';
import type { ChangeJobRow } from '../change/jobQueue.service';
import { RouterOsTrapError, type RouterOsConnection } from '../transport/routeros';
import {
  MENU_NAMES,
  auditText,
  decideLinkActions,
  itemSpecs,
  locateItem,
  printWords,
  verifyLinkSnapshot,
  type ChrLinkSnapshot,
  type LinkDecision,
  type LinkSpec,
  type MenuName,
} from './chrMenus';
import { generateWireGuardKeyPair } from './wgKeys';
import {
  configHash,
  defaultWgDir,
  endpointHostProblem,
  newHostConfig,
  parseHostConfig,
  readHostConfigText,
  readSidecarStatus,
  writeHostConfigFile,
  type WgFs,
} from './wgConfig';

// ============================================================================
// Vocabulary
// ============================================================================

/** What the job found. Mirrors `concentrator_link_jobs_outcome_chk` (053). */
export const CONCENTRATOR_LINK_OUTCOMES = ['added', 'present', 'conflict'] as const;
export type ConcentratorLinkOutcome = (typeof CONCENTRATOR_LINK_OUTCOMES)[number];

/** A refusal. apply.service turns it into a `ChangeRefusedError` with the same
 *  `kind`; the controller maps `httpStatus`. */
export class ConcentratorLinkError extends Error {
  constructor(readonly kind: string, message: string, readonly httpStatus = 409) {
    super(message);
    this.name = 'ConcentratorLinkError';
  }
}

export const CONCENTRATOR_LINK_NO_DEADMAN =
  "'concentrator_link' arms no dead-man: nothing it adds can cut the management path ObliWAN " +
  "uses to reach the CHR — its PUBLIC address. It adds a new interface, an address on that " +
  'interface, a peer, ACCEPT rules (an accept can drop nothing) and a srcnat rule matching only ' +
  "the transit's ObliWAN address. It never sets, moves or removes anything, and refuses when an " +
  'item exists differently. The job is queued at safety level degraded, which is the truth about ' +
  'its net, with the operator\'s explicit confirmation.';

export const CONCENTRATOR_LINK_NO_APPLY_OUTCOME =
  "No row written to apply_outcomes: 'concentrator_link' is an additive set of items on the " +
  'concentrator made with no net, not an observation of how this hardware survives a change. ' +
  'Its outcome is on concentrator_link_jobs.';

export function concentratorLinkGuard(): {
  verdict: 'ACCEPT';
  reasons: unknown[];
  summary: string;
  unavailable: false;
} {
  return {
    verdict: 'ACCEPT',
    reasons: [
      {
        code: 'ADDITIVE_CONCENTRATOR_LINK',
        effect: 'accept',
        message:
          'Adds a WireGuard interface, its address and one peer, ACCEPT rules and one srcnat rule ' +
          'matching only the transit address, on the concentrator; refuses instead of modifying ' +
          'when any of them exists differently. None of them removes the public-address path ' +
          'ObliWAN manages the concentrator through.',
      },
    ],
    summary:
      'Management-Path Guard: ACCEPT — additive items only, none on the path ObliWAN manages the ' +
      'concentrator through (no plan was simulated: the job refuses every case that is not a pure addition).',
    unavailable: false,
  };
}

// ============================================================================
// Dependencies (test seams)
// ============================================================================

export interface TcpProbeResult {
  connected: boolean;
  reachable: boolean;
  detail: string;
}

export interface ConcentratorLinkDeps {
  takeBackup(args: {
    deviceId: number;
    jobId: number;
    correlationId: string;
    createdBy: number | null;
  }): Promise<{ backupId: number; summary: string }>;
  wgDir(): string;
  wgFs: WgFs;
  probe(host: string, port: number, timeoutMs: number): Promise<TcpProbeResult>;
  /** The identity check on a fresh socket to wherever the transport now points; never
   *  quarantines (a CHR that does not answer on its TRANSIT address is fine on
   *  its public one). */
  assertBinding(deviceId: number): Promise<{ ok: boolean; reason: string }>;
  now(): Date;
}

async function defaultAssertBinding(deviceId: number): Promise<{ ok: boolean; reason: string }> {
  try {
    const a = await assertTargetBinding(deviceId, { throwOnFailure: false, quarantineOnMismatch: false });
    return { ok: a.ok, reason: a.reason };
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.message : String(err) };
  }
}

/** What to add on a concentrator whose backup no channel can carry. */
export const CHR_BACKUP_CHANNEL_HINT =
  'For this concentrator, add one of: api-ssl (8729) enabled on the CHR, with TLS on its RouterOS API ' +
  'transport and the certificate fingerprint pinned there (the only channel that may carry its backup ' +
  `across a public address; API file read needs RouterOS ${ROUTEROS_FILE_READ_SINCE} or later); or, if ` +
  'ObliWAN reaches the CHR on a non-public address, an SSH transport on that same address with the same ' +
  'service account (SFTP).';

/** The same, for a CHR whose RouterOS predates API file read: api-ssl cannot
 *  carry its backup there, so it is not offered. */
export const CHR_BACKUP_CHANNEL_HINT_OLD_ROUTEROS =
  `For this concentrator: its RouterOS predates API file read (/file/read, RouterOS ${ROUTEROS_FILE_READ_SINCE}), ` +
  'so no API session, api-ssl included, can carry its backup. Either reach it on a non-public address and ' +
  'add an SSH transport on that same address with the same service account (SFTP), or upgrade it by hand ' +
  `to RouterOS ${ROUTEROS_FILE_READ_SINCE} or later and then enable api-ssl (8729) with its certificate ` +
  'fingerprint pinned on its RouterOS API transport.';

/**
 * The concentrator-specific line appended to backup.service's "no acceptable
 * way to pull" refusal (`BACKUP_FAILED` whose detail names `apiChannel`), or
 * null when there is nothing to add. That refusal's own remedy may point at a
 * tunnel IP, which a concentrator does not have; this says what to ADD on the
 * CHR instead, and never offers a channel the refusal's own detail rules out:
 *  - `fileRead: 'no'`: the RouterOS predates `/file/read`, so api-ssl would
 *    not help — the version comes first;
 *  - an API channel already acceptable (pinned TLS, or a non-public address)
 *    with `/file/read` not ruled out: that road was open and gave way on the
 *    box, and the refusal's own reasons say why — adding api-ssl is not it.
 */
export function chrBackupChannelHint(detail: Record<string, unknown>): string | null {
  if (detail.fileRead === 'no') return CHR_BACKUP_CHANNEL_HINT_OLD_ROUTEROS;
  const channel = detail.apiChannel as ApiChannelJudgement | undefined;
  if (channel && typeof channel === 'object' && apiChannelAcceptable(channel)) return null;
  return CHR_BACKUP_CHANNEL_HINT;
}

async function defaultTakeBackup(args: {
  deviceId: number;
  jobId: number;
  correlationId: string;
  createdBy: number | null;
}): Promise<{ backupId: number; summary: string }> {
  let set: Awaited<ReturnType<typeof takeDeviceBackup>>;
  try {
    set = await takeDeviceBackup({
      deviceId: args.deviceId,
      trigger: 'preflight',
      kinds: ['binary', 'rsc'],
      jobId: args.jobId,
      correlationId: args.correlationId,
      createdBy: args.createdBy,
      // NO `keepOnDeviceKinds`: no dead-man loads it, so it is pulled off,
      // proven against our own disk and erased from the CHR.
    });
  } catch (err) {
    // The card shows this message. When NO road could carry the backup
    // (backup.service's "no acceptable way to pull" refusal, whose detail
    // names the API channel: at plan time before any file exists, or once
    // every road gave way), say what to ADD on the CHR (`chrBackupChannelHint`).
    // Any other failure is the transfer's own, and its message stands as it is.
    if (err instanceof ChangeError && err.kind === 'BACKUP_FAILED' && 'apiChannel' in err.detail) {
      const hint = chrBackupChannelHint(err.detail);
      if (hint) err.message += ` ${hint}`;
    }
    if (err instanceof Error) err.message += ' No link item was added.';
    throw err;
  }
  if (!set.binary) {
    throw new ConcentratorLinkError(
      'backup_failed',
      'the CHR produced no binary backup; refusing to write on a concentrator nothing could restore.',
    );
  }
  return {
    backupId: set.binary.id,
    summary: `pre-change backup #${set.binary.id} stored (${set.artefacts.length} artefact(s))`,
  };
}

/** A TCP connect. A REFUSAL counts as reachable: an RST came back through the
 *  path, which is what "the link carries traffic" means. */
export function tcpProbe(host: string, port: number, timeoutMs: number): Promise<TcpProbeResult> {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port });
    let settled = false;
    const done = (r: TcpProbeResult): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(r);
    };
    socket.setTimeout(timeoutMs, () => done({ connected: false, reachable: false, detail: `no answer within ${timeoutMs} ms` }));
    socket.once('connect', () => done({ connected: true, reachable: true, detail: 'TCP connection established' }));
    socket.once('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'ECONNREFUSED') {
        done({ connected: false, reachable: true, detail: 'refused: the address answered, nothing listens on that port' });
      } else {
        done({ connected: false, reachable: false, detail: err.code ?? err.message });
      }
    });
  });
}

const defaultDeps: ConcentratorLinkDeps = {
  takeBackup: defaultTakeBackup,
  wgDir: defaultWgDir,
  wgFs: fsp,
  probe: tcpProbe,
  assertBinding: defaultAssertBinding,
  now: () => new Date(),
};
let deps: ConcentratorLinkDeps = { ...defaultDeps };

export function setConcentratorLinkDeps(next: Partial<ConcentratorLinkDeps>): ConcentratorLinkDeps {
  deps = { ...deps, ...next };
  return deps;
}
export function resetConcentratorLinkDeps(): void {
  deps = { ...defaultDeps };
}

// ============================================================================
// Rows
// ============================================================================

const ACTIVE: readonly string[] = ACTIVE_CHANGE_JOB_STATUSES;
const NO_BASE_STATE = '0'.repeat(64);
const ROUTEROS = 'routeros_api';

interface LinkRow {
  concentrator_id: number;
  tenant_id: number;
  transit: string;
  chr_address: string;
  host_address: string;
  listen_port: number;
  host_public_key: string;
  host_private_key_enc: string;
  chr_public_key: string | null;
  endpoint_host: string | null;
  first_write_at: Date | null;
  provisioned_job_id: string | number | null;
  provisioned_at: Date | null;
  api_via_tunnel_at: Date | null;
  api_public_host: string | null;
  api_public_port: number | null;
}

async function loadLink(concentratorId: number): Promise<LinkRow | null> {
  const row = (await db('concentrator_links')
    .where({ concentrator_id: concentratorId })
    .first(
      'concentrator_id',
      'tenant_id',
      db.raw('transit::text AS transit'),
      db.raw('host(chr_address) AS chr_address'),
      db.raw('host(host_address) AS host_address'),
      'listen_port',
      'host_public_key',
      'host_private_key_enc',
      'chr_public_key',
      'endpoint_host',
      'first_write_at',
      'provisioned_job_id',
      'provisioned_at',
      'api_via_tunnel_at',
      'api_public_host',
      'api_public_port',
    )) as LinkRow | undefined;
  return row ?? null;
}

interface LinkJobRow {
  job_id: string | number;
  concentrator_id: number;
  transit: string;
  chr_address: string;
  host_address: string;
  listen_port: number;
  host_public_key: string;
  backup_id: string | number | null;
  wrote_at: Date | null;
  outcome: ConcentratorLinkOutcome | null;
  outcome_detail: string | null;
}

async function loadLinkJob(jobId: number): Promise<LinkJobRow> {
  const row = (await db('concentrator_link_jobs')
    .where({ job_id: jobId })
    .first(
      'job_id',
      'concentrator_id',
      db.raw('transit::text AS transit'),
      db.raw('host(chr_address) AS chr_address'),
      db.raw('host(host_address) AS host_address'),
      'listen_port',
      'host_public_key',
      'backup_id',
      'wrote_at',
      'outcome',
      'outcome_detail',
    )) as LinkJobRow | undefined;
  if (!row) {
    throw new ConcentratorLinkError(
      'concentrator_link_missing',
      `Job ${jobId} has no concentrator_link_jobs row: nothing says what it adds.`,
    );
  }
  return row;
}

function specOf(row: LinkJobRow): LinkSpec {
  return {
    transit: row.transit,
    chrAddress: row.chr_address,
    hostAddress: row.host_address,
    listenPort: row.listen_port,
    hostPublicKey: row.host_public_key,
  };
}

async function recordFound(
  jobId: number,
  outcome: ConcentratorLinkOutcome,
  detail: string,
  items: unknown,
  chrPublicKey: string | null,
): Promise<void> {
  await db('concentrator_link_jobs')
    .where({ job_id: jobId })
    .update({
      outcome,
      outcome_detail: detail,
      items: JSON.stringify(items),
      chr_public_key: chrPublicKey,
      updated_at: db.fn.now(),
    });
}

/**
 * What the transit would collide with in ObliWAN's own records: an address
 * pool (any purpose), an allocated tunnel address, a device's tunnel address,
 * an address a concentrator's /ppp/secret declares, a live PPP session, or
 * another concentrator's link. Empty = free.
 */
export async function transitCollisions(transit: string, concentratorId: number): Promise<string[]> {
  const out: string[] = [];
  const pools = (await db('address_pools')
    .whereRaw('cidr && ?::cidr', [transit])
    .select('name', db.raw('cidr::text AS cidr'))) as Array<{ name: string; cidr: string }>;
  for (const p of pools) out.push(`address pool "${p.name}" (${p.cidr})`);

  const count = async (q: Knex.QueryBuilder): Promise<number> =>
    Number(((await q.count('* as n')) as Array<{ n: string | number }>)[0].n);
  const allocated = await count(db('site_provisioning').whereRaw('tunnel_ip <<= ?::cidr', [transit]));
  if (allocated > 0) out.push(`${allocated} allocated site tunnel address(es)`);
  const devices = await count(db('devices').whereNotNull('tunnel_ip').whereRaw('tunnel_ip <<= ?::cidr', [transit]));
  if (devices > 0) out.push(`${devices} device tunnel address(es)`);
  const secrets = await count(
    db('concentrator_ppp_secrets').where((q) =>
      q.whereRaw('remote_address <<= ?::cidr', [transit]).orWhereRaw('local_address <<= ?::cidr', [transit]),
    ),
  );
  if (secrets > 0) out.push(`${secrets} address(es) declared by a concentrator's /ppp/secret`);
  const sessions = await count(
    db('ppp_sessions').whereNull('ended_at').whereNotNull('tunnel_ip').whereRaw('tunnel_ip <<= ?::cidr', [transit]),
  );
  if (sessions > 0) out.push(`${sessions} live PPP session address(es)`);
  const links = (await db('concentrator_links')
    .whereRaw('transit && ?::cidr', [transit])
    .whereNot('concentrator_id', concentratorId)
    .select('concentrator_id', db.raw('transit::text AS transit'))) as Array<{ concentrator_id: number; transit: string }>;
  for (const l of links) out.push(`the link of concentrator ${l.concentrator_id} (${l.transit})`);
  return out;
}

// ============================================================================
// Enqueue
// ============================================================================

export interface EnsureLinkInput {
  concentratorId: number;
  requestedBy: number;
  transit?: string | null;
  listenPort?: number | null;
  /** The operator read that no dead-man is armed, and confirms. */
  confirmNoDeadman: boolean;
}

export interface EnsureLinkResult {
  jobId: number;
  /** A job for this concentrator was already in flight; it is the answer. */
  alreadyQueued: boolean;
}

interface ConcentratorDevice {
  id: number;
  tenant_id: number;
  name: string;
  role: string;
  brand: string;
  family: string;
  status: string;
  is_managed: boolean;
}

async function loadConcentrator(concentratorId: number): Promise<ConcentratorDevice> {
  const chr = (await db('devices')
    .where({ id: concentratorId })
    .first('id', 'tenant_id', 'name', 'role', 'brand', 'family', 'status', 'is_managed')) as
    | ConcentratorDevice
    | undefined;
  if (!chr) throw new ConcentratorLinkError('not_found', `Device ${concentratorId} does not exist.`, 404);
  if (chr.role !== 'concentrator') {
    throw new ConcentratorLinkError('not_a_concentrator', `${chr.name} is not a concentrator.`, 409);
  }
  return chr;
}

async function inFlightLinkJob(concentratorId: number): Promise<number | null> {
  const row = (await db('change_jobs')
    .where({ device_id: concentratorId, kind: CONCENTRATOR_LINK_KIND })
    .whereIn('status', ACTIVE as string[])
    .orderBy('id', 'desc')
    .first('id')) as { id: string | number } | undefined;
  return row ? Number(row.id) : null;
}

/** Another concentrator whose link holds the host half (header, ONE LINK PER
 *  INSTALLATION): bound by a write or a provisioning, or with a link job in
 *  flight that may bind it. Null when the host half is free for this one. */
async function hostBoundElsewhere(
  concentratorId: number,
): Promise<{ concentratorId: number; name: string; why: string } | null> {
  const bound = (await db('concentrator_links as l')
    .join('devices as d', 'd.id', 'l.concentrator_id')
    .whereNot('l.concentrator_id', concentratorId)
    .where((q) => q.whereNotNull('l.provisioned_at').orWhereNotNull('l.first_write_at'))
    .first('l.concentrator_id', 'd.name')) as { concentrator_id: number; name: string } | undefined;
  if (bound) return { concentratorId: bound.concentrator_id, name: bound.name, why: 'its link is in place' };
  const inFlight = (await db('change_jobs as j')
    .join('devices as d', 'd.id', 'j.device_id')
    .where('j.kind', CONCENTRATOR_LINK_KIND)
    .whereNot('j.device_id', concentratorId)
    .whereIn('j.status', ACTIVE as string[])
    .first('j.device_id', 'd.name')) as { device_id: number; name: string } | undefined;
  if (inFlight) return { concentratorId: inFlight.device_id, name: inFlight.name, why: 'a link job for it is in flight' };
  return null;
}

function hostLinkTaken(chrName: string, other: { name: string; why: string }): ConcentratorLinkError {
  return new ConcentratorLinkError(
    'host_link_taken',
    `${chrName} cannot be connected: the host half of the link (one WireGuard interface, one peer for all ` +
      `of 100.64.0.0/10) already follows ${other.name} (${other.why}). ObliWAN links one concentrator per ` +
      'installation, and has no operation that unbinds a link.',
  );
}

const ONE_BOUND_INDEX = 'concentrator_links_one_bound_uq';
const TRANSIT_RESERVED = 'concentrator_link_transit_reserved';

function pgCodeOf(err: unknown): { code?: string; constraint?: string } {
  return typeof err === 'object' && err !== null ? (err as { code?: string; constraint?: string }) : {};
}

export async function ensureConcentratorLink(input: EnsureLinkInput): Promise<EnsureLinkResult> {
  if (!Number.isInteger(input.requestedBy) || input.requestedBy <= 0) {
    throw new ConcentratorLinkError('requester_required', 'A connect request names the operator who made it.', 400);
  }
  if (input.confirmNoDeadman !== true) {
    throw new ConcentratorLinkError(
      'confirmation_required',
      'This job arms no dead-man on the CHR (nothing it adds can cut the public-address path ObliWAN ' +
        'manages it through). Confirm explicitly to queue it.',
      400,
    );
  }
  const chr = await loadConcentrator(input.concentratorId);
  if (chr.brand !== 'mikrotik' || chr.family !== 'mikrotik_routeros7') {
    throw new ConcentratorLinkError(
      'wireguard_unsupported',
      `${chr.name} is not a RouterOS 7 device (${chr.brand}/${chr.family}); WireGuard needs RouterOS 7.`,
      409,
    );
  }
  if (chr.status === 'disabled' || chr.status === 'quarantined') {
    throw new ConcentratorLinkError('concentrator_not_writable', `${chr.name} is ${chr.status}; nothing is written to it.`);
  }
  if (!chr.is_managed) {
    throw new ConcentratorLinkError(
      'concentrator_not_managed',
      `${chr.name} is not marked as managed, so ObliWAN does not write to it.`,
    );
  }

  const inflight = await inFlightLinkJob(chr.id);
  if (inflight !== null) return { jobId: inflight, alreadyQueued: true };

  const transport = (await db('device_transports')
    .where({ device_id: chr.id, transport: ROUTEROS })
    .first('host', 'enabled')) as { host: string | null; enabled: boolean } | undefined;
  const link = await loadLink(chr.id);

  // Where the host's WireGuard dials: the CHR's PUBLIC address. Once the API
  // has moved into the tunnel the transport says the tunnel side, so the
  // address recorded before is kept.
  const endpointHost = link?.api_via_tunnel_at ? link.endpoint_host : transport?.host ?? null;
  if (!endpointHost) {
    throw new ConcentratorLinkError(
      'no_endpoint',
      `${chr.name} has no RouterOS API transport with a host: there is no public address for the link to dial.`,
    );
  }
  const endpointProblem = endpointHostProblem(endpointHost);
  if (endpointProblem) {
    throw new ConcentratorLinkError('endpoint_not_public', `The CHR's API host "${endpointHost}" cannot be the link endpoint: ${endpointProblem}.`);
  }

  const transitText = input.transit?.trim() || link?.transit || DEFAULT_LINK_TRANSIT;
  const tp = transitProblem(transitText);
  if (tp) throw new ConcentratorLinkError('invalid_transit', `Invalid transit: ${tp}.`, 400);
  const t = deriveTransit(transitText);
  const listenPort = input.listenPort ?? link?.listen_port ?? DEFAULT_LINK_LISTEN_PORT;
  const pp = listenPortProblem(listenPort);
  if (pp) throw new ConcentratorLinkError('invalid_listen_port', `Invalid port: ${pp}.`, 400);
  if (link?.first_write_at && (link.transit !== t.transit || link.listen_port !== listenPort)) {
    throw new ConcentratorLinkError(
      'link_frozen',
      `${chr.name} already carries the link on ${link.transit}, UDP ${link.listen_port} (a job wrote there on ` +
        `${new Date(link.first_write_at).toISOString()}). ObliWAN never moves an item it added; keep that ` +
        'transit and port, or remove the obliwan:link items from the CHR by hand first.',
    );
  }
  const collisions = await transitCollisions(t.transit, chr.id);
  if (collisions.length > 0) {
    throw new ConcentratorLinkError(
      'transit_collision',
      `The transit ${t.transit} overlaps ${collisions.join('; ')}. Choose a /30 inside 100.64.0.0/10 ` +
        'that no pool and no site uses.',
    );
  }
  const elsewhere = await hostBoundElsewhere(chr.id);
  if (elsewhere) throw hostLinkTaken(chr.name, elsewhere);

  // ObliWAN's key pair: generated once per concentrator, kept across re-runs.
  let hostPublicKey = link?.host_public_key ?? null;
  let privateEnc = link?.host_private_key_enc ?? null;
  let keyVersion: number | null = null;
  if (!hostPublicKey || !privateEnc) {
    const pair = generateWireGuardKeyPair();
    hostPublicKey = pair.publicKey;
    privateEnc = encrypt(pair.privateKey);
    keyVersion = currentKeyVersion();
  }

  let jobId: number;
  try {
    jobId = await db.transaction(async (trx) => {
      const base = {
        tenant_id: chr.tenant_id,
        transit: t.transit,
        chr_address: t.chrAddress,
        host_address: t.hostAddress,
        listen_port: listenPort,
        endpoint_host: endpointHost,
        updated_at: trx.fn.now(),
      };
      if (link) {
        await trx('concentrator_links').where({ concentrator_id: chr.id }).update(base);
      } else {
        await trx('concentrator_links').insert({
          concentrator_id: chr.id,
          ...base,
          host_public_key: hostPublicKey,
          host_private_key_enc: privateEnc,
          key_version: keyVersion,
        });
      }
      const guard = concentratorLinkGuard();
      const inserted = (await trx('change_jobs')
        .insert({
          // The CHR's tenant: the queue loads a job's device scoped by it.
          tenant_id: chr.tenant_id,
          device_id: chr.id,
          plan_id: null,
          kind: CONCENTRATOR_LINK_KIND,
          status: 'queued',
          attempt: 0,
          // A write is not retried silently; the operator asks again.
          max_attempts: 1,
          // Plan-less: the job decides on what it reads on the CHR.
          base_state_hash: NO_BASE_STATE,
          // No dead-man (CONCENTRATOR_LINK_NO_DEADMAN), confirmed by the
          // requester (053 widens the confirmation CHECK).
          safety_level: 'degraded',
          safety_peer_device_id: null,
          degraded_confirmed_by: input.requestedBy,
          degraded_confirmed_at: trx.fn.now(),
          guard_verdict: guard.verdict,
          guard_reasons: JSON.stringify(guard.reasons),
          requested_by: input.requestedBy,
        })
        .returning('id')) as Array<{ id: string | number }>;
      const id = Number(inserted[0].id);
      await trx('concentrator_link_jobs').insert({
        job_id: id,
        concentrator_id: chr.id,
        tenant_id: chr.tenant_id,
        transit: t.transit,
        chr_address: t.chrAddress,
        host_address: t.hostAddress,
        listen_port: listenPort,
        host_public_key: hostPublicKey,
      });
      return id;
    });
  } catch (err) {
    const pg = err as { code?: string; constraint?: string };
    if (pg.code === '23505' && pg.constraint === 'change_jobs_one_in_flight_uq') {
      throw new ConcentratorLinkError('concentrator_busy', `${chr.name} is busy with another job; retry once it ends.`);
    }
    if (pg.code === '23001') {
      throw new ConcentratorLinkError(
        'subtree_interlock',
        `A job is in flight on a device behind ${chr.name}: a concentrator job cannot ` +
          'start meanwhile. Retry once it ends.',
      );
    }
    if (pg.code === '23P01') {
      throw new ConcentratorLinkError('transit_collision', `The transit ${t.transit} overlaps another concentrator's link.`);
    }
    if (pg.code === '23514' && pg.constraint === TRANSIT_RESERVED) {
      // 053's guard: a pool created over the transit while this request ran.
      throw new ConcentratorLinkError(
        'transit_collision',
        `The transit ${t.transit} overlaps an address pool created meanwhile. Choose another /30.`,
      );
    }
    throw err;
  }

  const summary = { jobId, deviceId: chr.id, kind: CONCENTRATOR_LINK_KIND, status: 'queued' };
  emitToTenantAudience(chr.tenant_id, SOCKET_EVENTS.JOB_QUEUED, summary, { deviceId: chr.id });
  emitToDevice(chr.id, SOCKET_EVENTS.JOB_QUEUED, summary);
  logger.info(
    { jobId, concentratorId: chr.id, transit: t.transit, listenPort, requestedBy: input.requestedBy },
    'concentrator link job QUEUED (additive WireGuard link on the CHR)',
  );
  return { jobId, alreadyQueued: false };
}

// ============================================================================
// The job's phases (called from apply.service.ts runPhases)
// ============================================================================

export interface AuditedDevice {
  id: number;
  uuid?: string | null;
  name?: string | null;
}

export interface LinkStepResult {
  output: string;
  detail: Record<string, unknown>;
}

export class ConcentratorLinkRun {
  private spec: LinkSpec | null = null;
  private decision: LinkDecision | null = null;
  private backupId: number | null = null;

  constructor(
    private readonly job: ChangeJobRow,
    private readonly device: AuditedDevice,
    private readonly correlationId: string,
  ) {}

  /** True once `inspect` found every item already present. */
  get isNoop(): boolean {
    return this.decision !== null && this.decision.adds.length === 0;
  }

  get noopReason(): string {
    return (
      'every item of the link is already on the CHR, as this job would add it: nothing will be ' +
      'written, so there is nothing for a pre-change backup to restore.'
    );
  }

  private intent(command: string, isWrite: boolean): CommandIntent {
    return {
      tenantId: this.job.tenant_id,
      deviceId: this.device.id,
      deviceUuid: this.device.uuid ?? null,
      deviceName: this.device.name ?? null,
      jobId: Number(this.job.id),
      transport: 'routeros_api',
      command,
      isWrite,
      correlationId: this.correlationId,
    };
  }

  private async readMenu(conn: RouterOsConnection, menu: MenuName): Promise<Record<string, string>[]> {
    const words = printWords(menu);
    try {
      return await auditedCommand(this.intent(words.join(' '), false), () => conn.query(words));
    } catch (err) {
      if (err instanceof RouterOsTrapError && menu === 'interfaces') {
        throw new ConcentratorLinkError(
          'wireguard_unsupported',
          `The CHR refused ${words[0]} (${err.message}): RouterOS 7 with WireGuard, and an API account allowed to read it, are needed. Nothing was written.`,
        );
      }
      throw err;
    }
  }

  private async snapshot(conn: RouterOsConnection): Promise<ChrLinkSnapshot> {
    const s = {} as ChrLinkSnapshot;
    for (const m of MENU_NAMES) s[m] = await this.readMenu(conn, m);
    return s;
  }

  private async withChr<T>(fn: (conn: RouterOsConnection) => Promise<T>): Promise<T> {
    const target = await resolveRouterOsTarget(this.job.device_id);
    return getRouterOsPool().withConnection(target, fn);
  }

  /** `lint`: the frozen spec still holds, the transit is still free, and what
   *  the CHR carries now. A conflict refuses here, before any backup. */
  async inspect(): Promise<LinkStepResult> {
    const jobId = Number(this.job.id);
    const row = await loadLinkJob(jobId);
    const link = await loadLink(row.concentrator_id);
    if (
      !link ||
      link.host_public_key !== row.host_public_key ||
      link.transit !== row.transit ||
      link.listen_port !== row.listen_port
    ) {
      throw new ConcentratorLinkError(
        'link_moved',
        'The link record changed after this job was queued (key, transit or port). Nothing was written; ' +
          'queue a new job.',
      );
    }
    this.spec = specOf(row);
    const collisions = await transitCollisions(row.transit, row.concentrator_id);
    if (collisions.length > 0) {
      const detail = `Refused, nothing written: the transit ${row.transit} now overlaps ${collisions.join('; ')}.`;
      await recordFound(jobId, 'conflict', detail, [], null);
      throw new ConcentratorLinkError('transit_collision', detail);
    }
    // Re-asked here: another concentrator may have been bound since enqueue.
    const elsewhere = await hostBoundElsewhere(row.concentrator_id);
    if (elsewhere && elsewhere.why === 'its link is in place') {
      const refusal = hostLinkTaken(this.device.name ?? `concentrator ${row.concentrator_id}`, elsewhere);
      await recordFound(jobId, 'conflict', `Refused, nothing written: ${refusal.message}`, [], null);
      throw refusal;
    }
    const spec = this.spec;
    const decision = await this.withChr(async (conn) => decideLinkActions(await this.snapshot(conn), spec));
    this.decision = decision;
    if (decision.conflicts.length > 0) {
      const detail =
        `Refused, nothing written: ${decision.conflicts.join(' | ')}. ObliWAN never modifies, moves or ` +
        'removes an item on the concentrator; resolve it there, then connect again.';
      await recordFound(jobId, 'conflict', detail, decision.present.map((item) => ({ item, action: 'present' })), decision.chrPublicKey);
      throw new ConcentratorLinkError('concentrator_link_conflict', detail);
    }
    const parts = [
      decision.adds.length > 0
        ? `to add: ${decision.adds.map((a) => (a.placeBefore ? `${a.item} (before ${a.placeBefore})` : a.item)).join(', ')}`
        : 'nothing to add',
      decision.present.length > 0 ? `already present: ${decision.present.join(', ')}` : '',
      decision.skipped.length > 0 ? `not needed: ${decision.skipped.map((s) => `${s.item} (${s.why})`).join(', ')}` : '',
      ...decision.notes,
    ].filter(Boolean);
    return {
      output: parts.join('; '),
      detail: {
        adds: decision.adds.map((a) => a.item),
        present: decision.present,
        skipped: decision.skipped.map((s) => s.item),
        notes: decision.notes.length,
      },
    };
  }

  /** `preflight_backup`, before the first write. */
  async backup(): Promise<{ backupId: number; output: string; detail: Record<string, unknown> }> {
    const jobId = Number(this.job.id);
    const out = await deps.takeBackup({
      deviceId: this.job.device_id,
      jobId,
      correlationId: this.correlationId,
      createdBy: this.job.requested_by,
    });
    this.backupId = out.backupId;
    await db('concentrator_link_jobs').where({ job_id: jobId }).update({ backup_id: out.backupId, updated_at: db.fn.now() });
    return { backupId: out.backupId, output: out.summary, detail: { backupId: out.backupId } };
  }

  /** `apply`: re-read and re-decide on the socket that writes, then one add at
   *  a time, each read back before the next. */
  async apply(onWrite: () => void): Promise<LinkStepResult> {
    const jobId = Number(this.job.id);
    const spec = this.spec;
    if (!spec) throw new Error('ConcentratorLinkRun.apply before inspect');
    if (this.backupId === null) {
      throw new ConcentratorLinkError('backup_missing', 'No pre-change backup was taken; nothing is written without one.');
    }
    const specs = new Map(itemSpecs(spec).map((s) => [s.item, s]));
    const added: Array<{ item: LinkItem; action: 'added'; placedBefore: string | null }> = [];

    return this.withChr(async (conn) => {
      const decision = decideLinkActions(await this.snapshot(conn), spec);
      if (decision.conflicts.length > 0) {
        const detail =
          `Refused, nothing written: the CHR changed while the backup was taken — ${decision.conflicts.join(' | ')}.`;
        await recordFound(jobId, 'conflict', detail, [], decision.chrPublicKey);
        throw new ConcentratorLinkError('concentrator_link_conflict', detail);
      }
      if (decision.adds.length === 0) {
        return { output: 'nothing left to add: every item is already present', detail: { added: 0 } };
      }

      // Recorded BEFORE the first add: a worker that dies mid-way leaves a CHR
      // that may carry some items, and the link's transit is frozen from now.
      // One transaction: binding the link is what 053's one-bound index may
      // refuse (a second concentrator racing this one), and then neither
      // record may say a write happened — none will.
      try {
        await db.transaction(async (trx) => {
          await trx('concentrator_links')
            .where({ concentrator_id: this.job.device_id })
            .whereNull('first_write_at')
            .update({ first_write_at: trx.fn.now(), updated_at: trx.fn.now() });
          await trx('concentrator_link_jobs').where({ job_id: jobId }).update({ wrote_at: trx.fn.now(), updated_at: trx.fn.now() });
        });
      } catch (err) {
        const pg = pgCodeOf(err);
        if (pg.code === '23505' && pg.constraint === ONE_BOUND_INDEX) {
          const elsewhere = await hostBoundElsewhere(this.job.device_id);
          throw hostLinkTaken(this.device.name ?? `concentrator ${this.job.device_id}`, elsewhere ?? {
            name: 'another concentrator',
            why: 'its link was bound while this job ran',
          });
        }
        throw err;
      }

      let chrPublicKey = decision.chrPublicKey;
      for (const add of decision.adds) {
        onWrite();
        try {
          await auditedCommand(this.intent(auditText(add.words), true), () => conn.query(add.words));
        } catch (err) {
          const done = added.map((a) => a.item).join(', ') || 'none';
          throw new ConcentratorLinkError(
            'concentrator_link_add_refused',
            `The CHR refused adding ${add.item}: ${err instanceof Error ? err.message : String(err)}. ` +
              `Already added by this job (left in place, found again by the next run): ${done}.`,
          );
        }
        const back = locateItem(specs.get(add.item)!, await this.readMenu(conn, add.menu));
        if (!back.row) {
          throw new ConcentratorLinkError(
            'concentrator_link_unverified',
            `${add.item} was accepted by the CHR but is not there when read back.`,
          );
        }
        if (add.item === 'wg_interface') {
          const key = back.row['public-key'];
          chrPublicKey = isWireGuardKey(key) ? key : null;
        }
        added.push({ item: add.item, action: 'added', placedBefore: add.placeBefore });
      }
      const items = [...added, ...decision.present.map((item) => ({ item, action: 'present' as const }))];
      const detail =
        `added on the CHR: ${added.map((a) => a.item).join(', ')}` +
        (decision.present.length > 0 ? `; already present: ${decision.present.join(', ')}` : '');
      await recordFound(jobId, 'added', detail, items, chrPublicKey);
      return { output: detail, detail: { added: added.length, present: decision.present.length } };
    });
  }

  /** `postcheck`: the whole set read back; the CHR's key recorded; the host's
   *  config file written. */
  async verify(): Promise<LinkStepResult> {
    const jobId = Number(this.job.id);
    const spec = this.spec;
    if (!spec) throw new Error('ConcentratorLinkRun.verify before inspect');
    const result = await this.withChr(async (conn) => verifyLinkSnapshot(await this.snapshot(conn), spec));
    if (result.problems.length > 0 || !result.chrPublicKey) {
      throw new ConcentratorLinkError(
        'concentrator_link_unverified',
        `Read-back of the link on the CHR does not hold: ${result.problems.join('; ') || 'no public key'}.`,
      );
    }
    const row = await loadLinkJob(jobId);
    if (row.outcome === null) {
      await recordFound(
        jobId,
        'present',
        'every item of the link was already on the CHR; nothing written',
        itemSpecs(spec).map((s) => ({ item: s.item, action: 'present' })),
        result.chrPublicKey,
      );
    } else {
      await db('concentrator_link_jobs').where({ job_id: jobId }).update({ chr_public_key: result.chrPublicKey, updated_at: db.fn.now() });
    }
    try {
      await db('concentrator_links').where({ concentrator_id: this.job.device_id }).update({
        chr_public_key: result.chrPublicKey,
        provisioned_at: db.fn.now(),
        provisioned_job_id: jobId,
        updated_at: db.fn.now(),
      });
    } catch (err) {
      // Reachable only by a run that wrote nothing (every item was already on
      // its CHR) racing another concentrator's link: 053's backstop.
      const pg = pgCodeOf(err);
      if (pg.code === '23505' && pg.constraint === ONE_BOUND_INDEX) {
        const elsewhere = await hostBoundElsewhere(this.job.device_id);
        throw hostLinkTaken(this.device.name ?? `concentrator ${this.job.device_id}`, elsewhere ?? {
          name: 'another concentrator',
          why: 'its link was bound while this job ran',
        });
      }
      throw err;
    }
    let host: string;
    try {
      const w = await writeHostConfig(this.job.device_id);
      host = `host config written (${w.file})`;
    } catch (err) {
      host =
        `host config NOT written: ${err instanceof Error ? err.message : String(err)} — the CHR side is ` +
        'in place; connect again once the shared volume is writable';
      logger.warn({ jobId, concentratorId: this.job.device_id, err: host }, 'concentrator link: host config not written');
    }
    return {
      output:
        `read back: every item present and placed; CHR public key ${result.chrPublicKey} recorded` +
        `${result.forwardNeeded ? '' : ' (chain forward drops nothing: no forward accept needed)'}; ${host}`,
      detail: { verified: true, forwardNeeded: result.forwardNeeded },
    };
  }
}

// ============================================================================
// The host half: the config file the sidecar reads
// ============================================================================

/**
 * Render and write the host's desired WireGuard config (0600) for a
 * provisioned link. The only place the private key is decrypted.
 */
export async function writeHostConfig(concentratorId: number): Promise<{ file: string; hash: string }> {
  const link = await loadLink(concentratorId);
  if (!link || !link.chr_public_key || !link.provisioned_at) {
    throw new ConcentratorLinkError('link_not_provisioned', 'The CHR side of the link is not provisioned yet.');
  }
  if (!link.endpoint_host) throw new ConcentratorLinkError('no_endpoint', 'The link has no endpoint recorded.');
  const config = newHostConfig({
    privateKey: decrypt(link.host_private_key_enc),
    address: `${link.host_address}/30`,
    peerPublicKey: link.chr_public_key,
    endpointHost: link.endpoint_host,
    endpointPort: link.listen_port,
  });
  return writeHostConfigFile(deps.wgDir(), config, deps.wgFs);
}

// ============================================================================
// The view
// ============================================================================

/** Management ports worth knocking on, per brand (never from a request). */
const CPE_PORTS: Record<string, number[]> = {
  mikrotik: [8728, 22, 8291],
  draytek: [22, 443, 80],
  zyxel: [22, 443, 80],
  sonicwall: [443, 22],
};
const PROBE_TIMEOUT_MS = 1500;

function apiPortOf(t: { port: number | null; use_tls: boolean | null }): number {
  return t.port ?? (t.use_tls ? 8729 : 8728);
}

async function probeAny(address: string, ports: number[]): Promise<LinkProbe> {
  const results = await Promise.all(ports.map((p) => deps.probe(address, p, PROBE_TIMEOUT_MS).then((r) => ({ p, r }))));
  const best = results.find((x) => x.r.connected) ?? results.find((x) => x.r.reachable) ?? results[0];
  return {
    address,
    port: best.p,
    reachable: best.r.reachable,
    connected: best.r.connected,
    detail: results.map((x) => `${x.p}: ${x.r.detail}`).join('; '),
  };
}

/** Parallel sockets while probing sites: a few hundred sessions must not open
 *  a few hundred sockets at once from the server. */
const PROBE_CONCURRENCY = 12;

interface LiveSessionRow {
  device_id: number | null;
  name: string | null;
  brand: string | null;
  device_tenant_id: number | null;
  pool_tenant_id: number | null;
  tunnel_ip: string;
  started_at: Date | string;
}

/**
 * Probe the link client by client. The CHR is SHARED by every tenant, and the
 * view used to knock on ONE site — the most recent session, i.e. the router
 * that had just (re)connected and was the least likely to answer — and showed
 * its result as "a site through the link". One flapping router then made the
 * link look broken for every client, and one healthy client's site could make
 * it look fine for a client whose address plan is not reached at all.
 *
 * Each client is now judged on its own sites: up to LINK_PROBE_SITES_PER_CLIENT
 * sessions, longest-running first, among those up LINK_PROBE_STABLE_SECONDS.
 * A client with no stable session gets its oldest ones probed and flagged
 * `stable: false` rather than skipped — silence there is weak evidence and the
 * UI says so. Targets come from the database, never the request.
 *
 * A session is attributed to its bound device's tenant; an unbound one (a
 * login nobody has reconciled yet) to the tenant whose TUNNEL pool holds the
 * address. Tunnel pools never overlap (address_pools_tunnel_no_overlap), but
 * two tenants may share one pool, and then the session stays unattributed
 * rather than guessed.
 */
async function probeClients(chrId: number, now: Date): Promise<{ clients: LinkClientProbe[]; notProbed: number }> {
  const rows = (await db('ppp_sessions as s')
    .leftJoin('devices as d', 'd.id', 's.device_id')
    .where('s.concentrator_id', chrId)
    .whereNull('s.ended_at')
    .whereNotNull('s.tunnel_ip')
    .select(
      's.device_id',
      'd.name',
      'd.brand',
      'd.tenant_id as device_tenant_id',
      's.started_at',
      db.raw('host(s.tunnel_ip) AS tunnel_ip'),
      db.raw(
        `(SELECT CASE WHEN count(DISTINCT p.tenant_id) = 1 THEN min(p.tenant_id) END
            FROM tenant_allocation_policies p
            JOIN address_pools ap ON ap.id = p.tunnel_pool_id
           WHERE s.tunnel_ip <<= ap.cidr) AS pool_tenant_id`,
      ),
    )) as LiveSessionRow[];

  type Group = { tenantId: number | null; attribution: LinkClientProbe['attribution']; rows: LiveSessionRow[] };
  const groups = new Map<string, Group>();
  for (const r of rows) {
    const tenantId = r.device_tenant_id ?? r.pool_tenant_id ?? null;
    const key = tenantId === null ? 'none' : String(tenantId);
    const g: Group = groups.get(key) ?? { tenantId, attribution: tenantId === null ? 'none' : 'pool', rows: [] };
    // A client is 'device'-attributed as soon as one of its sessions is bound.
    if (r.device_tenant_id != null) g.attribution = 'device';
    g.rows.push(r);
    groups.set(key, g);
  }

  const tenantIds = [...groups.values()].map((g) => g.tenantId).filter((id): id is number => id !== null);
  const names = new Map<number, string>();
  if (tenantIds.length > 0) {
    const tenants = (await db('tenants').whereIn('id', tenantIds).select('id', 'name')) as Array<{ id: number; name: string }>;
    for (const t of tenants) names.set(t.id, t.name);
  }

  const ordered = [...groups.values()].sort((a, b) => {
    if (a.tenantId === null) return 1;
    if (b.tenantId === null) return -1;
    return (names.get(a.tenantId) ?? '').localeCompare(names.get(b.tenantId) ?? '');
  });
  const probed = ordered.slice(0, LINK_PROBE_MAX_CLIENTS);
  const stableBefore = now.getTime() - LINK_PROBE_STABLE_SECONDS * 1000;
  const startedMs = (r: LiveSessionRow) => new Date(r.started_at).getTime();
  const oldestFirst = (a: LiveSessionRow, b: LiveSessionRow) => startedMs(a) - startedMs(b);

  const plan = probed.map((g) => {
    const stable = g.rows.filter((r) => startedMs(r) <= stableBefore).sort(oldestFirst);
    const picks = stable.length > 0
      ? stable.slice(0, LINK_PROBE_SITES_PER_CLIENT).map((r) => ({ r, stable: true }))
      : [...g.rows].sort(oldestFirst).slice(0, LINK_PROBE_SITES_PER_CLIENT).map((r) => ({ r, stable: false }));
    return { g, stableCount: stable.length, picks };
  });

  const jobs = plan.flatMap((p) => p.picks.map((x) => x.r));
  const results = new Map<LiveSessionRow, LinkProbe>();
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(PROBE_CONCURRENCY, jobs.length) }, async () => {
      while (next < jobs.length) {
        const r = jobs[next++];
        results.set(r, await probeAny(r.tunnel_ip, CPE_PORTS[r.brand ?? ''] ?? [22, 443, 8728]));
      }
    }),
  );

  const clients = plan.map(({ g, stableCount, picks }): LinkClientProbe => {
    const sites = picks.map(({ r, stable }): LinkSiteProbe => ({
      ...(results.get(r) as LinkProbe),
      deviceId: r.device_id,
      name: r.name,
      sessionStartedAt: new Date(r.started_at).toISOString(),
      stable,
    }));
    const answered = sites.filter((x) => x.reachable).length;
    return {
      tenantId: g.tenantId,
      tenantName: g.tenantId !== null ? names.get(g.tenantId) ?? null : null,
      attribution: g.attribution,
      liveSessions: g.rows.length,
      stableSessions: stableCount,
      sites,
      verdict: answered === sites.length ? 'reached' : answered > 0 ? 'partial' : 'unreached',
    };
  });
  return { clients, notProbed: ordered.length - probed.length };
}

function iso(d: Date | string | null | undefined): string | null {
  return d ? new Date(d).toISOString() : null;
}

export async function getConcentratorLinkView(concentratorId: number): Promise<ConcentratorLinkView> {
  const chr = await loadConcentrator(concentratorId);
  const link = await loadLink(chr.id);
  const transport = (await db('device_transports')
    .where({ device_id: chr.id, transport: ROUTEROS })
    .first('host', 'port', 'use_tls')) as { host: string | null; port: number | null; use_tls: boolean | null } | undefined;

  // The latest job of this kind, and its steps.
  const jobRow = (await db('change_jobs as j')
    .leftJoin('concentrator_link_jobs as c', 'c.job_id', 'j.id')
    .where('j.device_id', chr.id)
    .where('j.kind', CONCENTRATOR_LINK_KIND)
    .orderBy('j.id', 'desc')
    .first('j.id', 'j.status', 'j.error_kind', 'j.error_message', 'j.created_at', 'c.outcome', 'c.outcome_detail')) as
    | {
        id: string | number;
        status: string;
        error_kind: string | null;
        error_message: string | null;
        created_at: Date;
        outcome: string | null;
        outcome_detail: string | null;
      }
    | undefined;
  let job: ConcentratorLinkView['job'] = null;
  if (jobRow) {
    const steps = (await db('change_job_steps')
      .where({ job_id: jobRow.id })
      .orderBy('seq')
      .select('kind', 'status', 'output_redacted')) as Array<{ kind: string; status: string; output_redacted: string | null }>;
    job = {
      id: Number(jobRow.id),
      status: jobRow.status,
      errorKind: jobRow.error_kind,
      errorMessage: jobRow.error_message,
      outcome: jobRow.outcome,
      outcomeDetail: jobRow.outcome_detail,
      createdAt: new Date(jobRow.created_at).toISOString(),
      steps: steps.map((s) => ({ kind: s.kind, status: s.status, output: s.output_redacted })),
    };
  }
  const jobActive = job !== null && ACTIVE.includes(job.status);
  let chrSide: LinkChrSide = 'not_started';
  if (jobActive) chrSide = 'pending';
  else if (link?.provisioned_at) chrSide = 'provisioned';
  else if (job) chrSide = 'failed';

  // The host half, from the sidecar's status file — and bound to THIS link by
  // key (header, ONE LINK PER INSTALLATION): the volume holds one config and
  // one status, and neither says which concentrator it is for except through
  // the CHR's public key and the transit address it carries.
  const now = deps.now();
  const dir = deps.wgDir();
  const status = await readSidecarStatus(dir, deps.wgFs);
  const configText = await readHostConfigText(dir, deps.wgFs);
  const statusFresh = status !== null && now.getTime() - new Date(status.at).getTime() <= LINK_SIDECAR_STALE_SECONDS * 1000;
  const parsedConfig = configText !== null ? parseHostConfig(configText) : null;
  const configIsThisLink =
    parsedConfig !== null &&
    parsedConfig.ok &&
    link?.chr_public_key != null &&
    parsedConfig.config.peerPublicKey === link.chr_public_key &&
    parsedConfig.config.address === `${link.host_address}/30`;
  const statusPeer = statusFresh && status?.peer ? status.peer : null;
  const peerIsThisLink = statusPeer ? link?.chr_public_key != null && statusPeer.publicKey === link.chr_public_key : null;
  const handshake = peerIsThisLink ? statusPeer?.latestHandshake ?? 0 : 0;
  const handshakeFresh =
    status?.state === 'up' && handshake > 0 && now.getTime() / 1000 - handshake <= LINK_HANDSHAKE_FRESH_SECONDS;
  const hostWarnings = statusFresh && status ? [...status.warnings] : [];
  if (configText !== null && !configIsThisLink) {
    hostWarnings.push(
      `the config file on the volume is not this link's (${parsedConfig?.ok ? 'another CHR key or transit address' : 'unreadable'}): ` +
        'the host is not set up for this concentrator',
    );
  }
  if (peerIsThisLink === false) {
    hostWarnings.push("the host's WireGuard peer is not this concentrator's key: its handshake and traffic are not shown here");
  }
  const host: ConcentratorLinkView['host'] = {
    state: statusFresh && status ? status.state : 'sidecar_absent',
    message: statusFresh && status
      ? status.message
      : status
        ? `The obliwan-wg sidecar's last report is from ${status.at}: it is not running, or does not share the volume with the server.`
        : 'No report from the obliwan-wg sidecar: it is not running (compose profile "wg"), or does not share the volume with the server.',
    statusAt: status?.at ?? null,
    configWritten: configIsThisLink,
    configApplied: configIsThisLink && configText !== null && statusFresh && status?.configHash === configHash(configText),
    peerIsThisLink,
    latestHandshakeAt: handshake > 0 ? new Date(handshake * 1000).toISOString() : null,
    handshakeFresh,
    rxBytes: peerIsThisLink && statusPeer ? statusPeer.rxBytes : null,
    txBytes: peerIsThisLink && statusPeer ? statusPeer.txBytes : null,
    warnings: hostWarnings,
  };

  // Probes through the link — targets from the database, never the request.
  const probes: ConcentratorLinkView['probes'] = { chr: null, clients: [], clientsNotProbed: 0, skipped: null };
  if (!link?.provisioned_at) {
    probes.skipped = 'the CHR side is not provisioned';
  } else if (host.state !== 'up') {
    probes.skipped = 'the host side is not up';
  } else if (peerIsThisLink !== true) {
    // 100.64.0.0/10 is routed to whatever peer the host carries: a probe now
    // would test another concentrator's link and be reported as this one's.
    probes.skipped = "the host's WireGuard peer is not this concentrator";
  } else {
    const apiPort = transport ? apiPortOf(transport) : 8728;
    const [chrProbe, clientProbes] = await Promise.all([
      probeAny(link.chr_address, [apiPort]),
      probeClients(chr.id, now),
    ]);
    probes.chr = chrProbe;
    probes.clients = clientProbes.clients;
    probes.clientsNotProbed = clientProbes.notProbed;
    if (clientProbes.clients.length === 0) probes.skipped = 'no live PPP session on this concentrator to probe';
  }

  const viaTunnel = link?.api_via_tunnel_at != null;
  const blockers: string[] = [];
  if (!link?.provisioned_at) blockers.push('the CHR side of the link is not provisioned');
  if (viaTunnel) blockers.push('the API already goes through the tunnel');
  if (peerIsThisLink !== true) blockers.push("the host's WireGuard peer is not (or not yet) this concentrator");
  if (!handshakeFresh) blockers.push(`no WireGuard handshake in the last ${LINK_HANDSHAKE_FRESH_SECONDS} s`);
  if (!probes.chr?.connected) blockers.push(`the CHR does not accept a connection on ${link?.chr_address ?? 'its transit address'}`);
  if (jobActive) blockers.push('a link job is in flight');

  const boundOther = await hostBoundElsewhere(chr.id);
  const service = transport?.use_tls ? 'api-ssl' : 'api';
  return {
    concentratorId: chr.id,
    concentratorName: chr.name,
    defaults: { transit: DEFAULT_LINK_TRANSIT, listenPort: DEFAULT_LINK_LISTEN_PORT },
    hostBoundTo: boundOther ? { concentratorId: boundOther.concentratorId, name: boundOther.name } : null,
    link: link
      ? {
          transit: link.transit,
          chrAddress: link.chr_address,
          hostAddress: link.host_address,
          listenPort: link.listen_port,
          hostPublicKey: link.host_public_key,
          chrPublicKey: link.chr_public_key,
          endpointHost: link.endpoint_host,
          provisionedAt: iso(link.provisioned_at),
          frozen: link.first_write_at !== null,
          apiViaTunnelAt: iso(link.api_via_tunnel_at),
          apiPublicHost: link.api_public_host,
          apiPublicPort: link.api_public_port,
        }
      : null,
    chrSide,
    job,
    host,
    probes,
    apiTransport: {
      host: transport?.host ?? null,
      port: transport?.port ?? null,
      viaTunnel,
      useTls: transport?.use_tls === true,
    },
    canSwitchApi: blockers.length === 0,
    switchBlockers: blockers,
    // Typed on the CHR while ObliWAN holds its API session over that very
    // service — which RouterOS 7.24.5 lists as a dynamic `/ip service` entry
    // of the same name (seen on a CPE; the CHR runs 7.21.5, where whether it
    // does is not observed). The command writes the CONFIGURED row only
    // (shared/src/routerOsService.ts), never a bare `set <name>`.
    operatorCommand: link ? routerOsServiceSet(service, `address=${link.host_address}/32`) : null,
  };
}

// ============================================================================
// The second gesture: the CHR's own API through the tunnel (or back)
// ============================================================================

export interface SwitchResult {
  via: 'tunnel' | 'public';
  host: string;
  port: number;
  bindingOk: boolean;
  bindingReason: string;
}

/**
 * Point the CHR's routeros_api transport at its transit address (`tunnel`),
 * or back at the public address recorded when it was moved (`public`).
 *
 * `tunnel` is refused unless the link is PROVEN now: provisioned, a fresh
 * handshake, and the CHR accepting a TCP connection on its transit address.
 * After the switch the CHR's identity is asserted on a fresh socket to the new
 * address; if that fails the transport is put back on the public address at
 * once, and the refusal says why. Nothing is written to the CHR — its
 * `/ip service` restriction is the operator's to make by hand
 * (`operatorCommand` in the view).
 *
 * Every move — into the tunnel, back to the public address, and the automatic
 * revert after a failed identity check — appends to `audit_log` (the
 * ledger) INSIDE the transaction that re-points the transport: who, when,
 * from where to where. `command_audit` cannot carry it (nothing is sent to a
 * device), and a move the ledger refused is not made.
 */
export async function switchConcentratorApi(
  concentratorId: number,
  via: 'tunnel' | 'public',
  userId: number,
): Promise<SwitchResult> {
  const chr = await loadConcentrator(concentratorId);
  const busy = (await db('change_jobs')
    .where({ device_id: chr.id })
    .whereIn('status', ACTIVE as string[])
    .first('id', 'kind')) as { id: string | number; kind: string } | undefined;
  if (busy) {
    throw new ConcentratorLinkError(
      'concentrator_busy',
      `Job ${Number(busy.id)} (${busy.kind}) is in flight on ${chr.name}; its socket must not change address under it.`,
    );
  }
  const link = await loadLink(chr.id);
  if (!link) throw new ConcentratorLinkError('link_not_provisioned', `${chr.name} has no link.`);
  const transport = (await db('device_transports')
    .where({ device_id: chr.id, transport: ROUTEROS })
    .first('id', 'host', 'port', 'use_tls')) as
    | { id: number; host: string | null; port: number | null; use_tls: boolean | null }
    | undefined;
  if (!transport || !transport.host) {
    throw new ConcentratorLinkError('no_transport', `${chr.name} has no RouterOS API transport.`);
  }

  const assertNow = async (): Promise<{ ok: boolean; reason: string }> => {
    getRouterOsPool().close(String(chr.id));
    return deps.assertBinding(chr.id);
  };

  const actor = (await db('users').where({ id: userId }).first('username')) as { username: string | null } | undefined;
  const audit = (
    trx: Knex.Transaction,
    action: string,
    before: { host: string | null; port: number | null },
    after: { host: string | null; port: number | null },
    extra: Record<string, unknown> = {},
  ) =>
    appendAudit(
      {
        tenantId: chr.tenant_id,
        actorType: 'user',
        actorId: userId,
        actorName: actor?.username ? actor.username.slice(0, 128) : null,
        action,
        entityType: 'device',
        entityId: chr.id,
        before: { transport: ROUTEROS, ...before },
        after: { transport: ROUTEROS, ...after, ...extra },
      },
      trx,
    );
  const currentPort = transport.port ?? apiPortOf(transport);

  if (via === 'public') {
    if (!link.api_public_host || !link.api_public_port) {
      throw new ConcentratorLinkError('no_fallback', 'No public address was recorded for this CHR\'s API.');
    }
    const publicHost = link.api_public_host;
    const publicPort = link.api_public_port;
    await db.transaction(async (trx) => {
      await trx('device_transports')
        .where({ id: transport.id })
        .update({ host: publicHost, port: publicPort, updated_at: trx.fn.now() });
      await trx('concentrator_links')
        .where({ concentrator_id: chr.id })
        .update({ api_via_tunnel_at: null, updated_at: trx.fn.now() });
      await audit(trx, 'concentrator_link.api_to_public',
        { host: transport.host, port: currentPort }, { host: publicHost, port: publicPort });
    });
    const b = await assertNow();
    logger.info({ concentratorId: chr.id, userId, binding: b.ok }, 'concentrator API transport moved back to its public address');
    return { via, host: publicHost, port: publicPort, bindingOk: b.ok, bindingReason: b.reason };
  }

  const view = await getConcentratorLinkView(chr.id);
  if (!view.canSwitchApi) {
    throw new ConcentratorLinkError('link_not_proven', `Not switched: ${view.switchBlockers.join('; ')}.`);
  }
  const publicHost = transport.host;
  const publicPort = apiPortOf(transport);
  await db.transaction(async (trx) => {
    await trx('concentrator_links').where({ concentrator_id: chr.id }).update({
      api_public_host: publicHost,
      api_public_port: publicPort,
      api_via_tunnel_at: trx.fn.now(),
      updated_at: trx.fn.now(),
    });
    await trx('device_transports').where({ id: transport.id }).update({ host: link.chr_address, updated_at: trx.fn.now() });
    await audit(trx, 'concentrator_link.api_to_tunnel',
      { host: publicHost, port: currentPort }, { host: link.chr_address, port: currentPort });
  });
  const b = await assertNow();
  if (!b.ok) {
    await db.transaction(async (trx) => {
      await trx('device_transports').where({ id: transport.id }).update({ host: publicHost, updated_at: trx.fn.now() });
      await trx('concentrator_links')
        .where({ concentrator_id: chr.id })
        .update({ api_via_tunnel_at: null, updated_at: trx.fn.now() });
      await audit(trx, 'concentrator_link.api_to_public',
        { host: link.chr_address, port: currentPort }, { host: publicHost, port: currentPort },
        { automatic: true, reason: `identity not confirmed through the tunnel: ${b.reason}`.slice(0, 500) });
    });
    getRouterOsPool().close(String(chr.id));
    throw new ConcentratorLinkError(
      'binding_failed_reverted',
      `The CHR's identity could not be confirmed through ${link.chr_address} (${b.reason}); the API transport ` +
        `was put back on ${publicHost}.`,
    );
  }
  logger.info({ concentratorId: chr.id, userId, host: link.chr_address }, 'concentrator API transport moved into the tunnel');
  return { via, host: link.chr_address, port: transport.port ?? publicPort, bindingOk: true, bindingReason: b.reason };
}
