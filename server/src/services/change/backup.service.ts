/**
 * ObliWAN. The mandatory pre-change backup.
 *
 * A push can cut the tunnel we administer through and turn a mistake
 * into a van. Two things stand between that mistake and the van: the on-box
 * dead-man (`safeApply.service.ts`) and THIS FILE, because the dead-man has
 * nothing to restore if the backup was never taken — or, worse, if it was
 * "taken" and is 43 bytes of nothing.
 *
 * So a backup here is not "we ran /system/backup/save and it said !done". It is
 * a chain in which every link is checked:
 *
 *   save  -> the file appears AND its size stops growing   (waitForDeviceFile)
 *   pull  -> WE read it off over a channel we hold: `/file/read` on this
 *            API session, or SFTP; never the router uploading it across
 *            the internet in clear                          (pullDeviceFile)
 *   prove -> the exact size the box printed, re-read from OUR disk,
 *            re-hash, compare, floor on the size
 *   erase -> delete on the device and RE-READ to prove absence
 *   record-> one row in `device_backups`, with the digest and the firmware
 *
 * Any link that fails fails the backup, and a failed preflight backup fails the
 * job before anything is written. That is not a policy this service enforces by
 * being careful: migration 009's `change_jobs_preflight_backup_chk` makes a
 * write job at `arming` or beyond IMPOSSIBLE to represent without a backup id.
 *
 * TWO KINDS, ON PURPOSE (shared/change.ts):
 *   binary  `/system/backup/save` — what the dead-man restores. Complete
 *           (users, certificates), but only onto a compatible RouterOS.
 *   rsc     `/export terse file=…` — what a human reads at 3 a.m. before
 *           deciding what he is restoring. Portable, diffable, and the thing
 *           we compare against to PROVE a rollback actually happened.
 *
 * THE NO-SECRETS RULE IS HELD HERE THREE TIMES, BECAUSE AN `.rsc` IS A FILE ON THE ROUTER FIRST.
 *  1. The words. `buildExportWords()` is the one API spelling of the export
 *     (rollback.service uses it too), read from the driver's per-family table
 *     like the SSH collector's command: `=hide-sensitive=` on RouterOS 6, which
 *     PRINTS secrets unless told not to, and no sensitivity word at all on
 *     RouterOS 7, which hides them unless told to show them. An unknown family
 *     is refused, and `show-sensitive` in any form is refused.
 *  2. The family. It is an inventory claim and it goes stale, so before any
 *     export `assertBoxSpeaksRecordedFamily()` reads the version the box
 *     reports and refuses when its major contradicts `devices.family` — and
 *     when the read itself fails, since a box nobody heard has claimed
 *     nothing. This is the check that matters most on THIS path: on the API
 *     the export is written to the router's flash and then pulled off it, so
 *     a secret the words failed to hide has already left the router by the
 *     time anything here can read it.
 *  3. The read-back. Every pulled `.rsc` is judged by `findSensitiveProps()`
 *     and REFUSED, before it is moved into the store, on any hit — a secret no
 *     flag hides (a script source, a comment), or a firmware that ignored its
 *     flag. A `.rsc` with PSKs in it becomes a snapshot, a diff, a UI panel and
 *     a log line, and there is no taking it back.
 *
 * HOW THE FILE COMES OFF THE ROUTER (a binary backup holds every PPP and
 * IPsec secret of the box — on the CHR, every site's):
 *   1. `/file/read` in chunks on THIS API session — RouterOS 7.13+, and only
 *      when the session reaches the box on a non-public address (its tunnel
 *      IP, RFC 1918, CGNAT, loopback) or is TLS WITH a pinned certificate
 *      fingerprint. TLS without a pin is encryption to whoever answered: on a
 *      public path an active man in the middle terminates it, so it is not
 *      counted;
 *   2. SFTP over the device's SSH channel — for boxes without `/file/read`
 *      (RouterOS 6, 7.0–7.12) whose SSH server serves SFTP to the service
 *      account. ObliWAN pins no SSH host key, so this road is taken only to
 *      the SAME address the identity-checked API session reached (an SSH
 *      row pointing elsewhere — stale, or another box — would hand the vault
 *      credential to whatever answers there), and only when that address is
 *      not public: there it is strictly better than the cleartext API session
 *      already accepted on the same path, and on a public one it would be the
 *      unpinned channel road 1 refuses;
 *   3. `/tool/fetch upload=yes` to our one-shot HTTP receiver — ONLY when a
 *      callback address was explicitly configured (`callbackHost`, or a
 *      receiver with a `publicBaseUrl`), the box is reached on a non-public
 *      address, and the callback is a non-public IP the box can reach.
 *      Nothing in production configures one today, so in production this
 *      road is closed. It used to be the only road, handed
 *      `http://127.0.0.1:<ephemeral>` in production, which no router can
 *      reach; and it is plain HTTP.
 * The road is chosen BEFORE the file is created (`planBackupPull`), so a box
 * with no acceptable road is refused with nothing left on it, and the refusal
 * names what is missing. A road that turns out unavailable on the box
 * (`/file/read` trapped, SFTP subsystem refused) gives way to the next
 * acceptable one, logged. A `/file/read` whose bytes fail the size checks
 * gives way to SFTP ONLY — an equally protected road over a different wire,
 * because the API's binary encoding is the one thing never observed on
 * hardware — and never to the upload. Every other failure is a failed backup.
 *
 * THIS FILE ALSO OWNS THE DEVICE SESSION, and that is deliberate rather than
 * accidental: it is the lowest layer above the transport that needs both the
 * database (to resolve a device and to write `command_audit`) and a fresh
 * socket. `rollback.service.ts` and `safeApply.service.ts` import it from here
 * so there is exactly one place where a command goes to an equipment and
 * exactly one place where that fact is recorded.
 */

import crypto from 'crypto';
import fsp from 'fs/promises';
import path from 'path';
import {
  FAMILY_BRAND,
  type BackupKind,
  type BackupRetentionClass,
  type BackupTrigger,
  type DeviceFamily,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { decrypt, encrypt } from '../secretVault.service';
import {
  createRouterOsConnection,
  redactWords,
  RouterOsTrapError,
  type RouterOsConnection,
} from '../transport/routeros';
import { compareIdentity, readRouterOsIdentity } from '../fleet/deviceBinding.service';
import { renameIdentityAlternates } from '../fleet/identityAlternates';
import {
  findSensitiveProps,
  routerOsExportApiFlagWords,
  SENSITIVE_REFUSAL_HINT,
} from '../drivers/mikrotik/driver';
import { familyFromVersion } from '../drivers/mikrotik/mikrotik.driver';
import { DriverError } from '../drivers/types';
import { auditedCommand, type AuditTransport } from '../audit.service';
import { markNothingTransmitted } from './applyFrontier';
import {
  deviceFileInfo,
  hashFile,
  isLoopbackAddress,
  isNonPublicAddress,
  readFileOverApi,
  removeDeviceFile,
  redactTransferUrl,
  ROUTEROS_FILE_READ_MAX_CHUNK,
  ROUTEROS_FILE_READ_SINCE,
  routerOsFileReadSupport,
  sftpPullToSpool,
  TRANSFER_TOKEN_IN_TEXT,
  TransferError,
  TransferReceiver,
  uploadFileFromDevice,
  verifyArtefact,
  waitForDeviceFile,
  type DeviceFile,
  type ReceivedFile,
} from './transfer.service';

// ============================================================================
// Errors
// ============================================================================

export type ChangeErrorKind =
  | 'DEVICE_UNKNOWN'
  | 'NO_TRANSPORT'
  | 'NO_CREDENTIAL'
  | 'CONNECT_FAILED'
  | 'IDENTITY_MISMATCH'
  | 'BRAND_UNSUPPORTED'
  | 'BACKUP_FAILED'
  | 'BACKUP_UNVERIFIED'
  | 'ONDEVICE_CLEANUP_FAILED'
  | 'SECRET_LEAK_REFUSED'
  /** The box reports a RouterOS major that contradicts `devices.family`, so
   *  any command whose spelling depends on the family (the export, first of
   *  all) is refused rather than sent in the wrong dialect. */
  | 'FAMILY_MISMATCH'
  /** The version read that must precede a family-spelled command did not
   *  complete (a timeout, a dropped socket, a `!trap`), so the family could
   *  not be checked and the command was not sent. Retryable: nothing ran. */
  | 'FAMILY_UNVERIFIED'
  /** A command was refused because its audit trace could not be guaranteed. */
  | 'AUDIT_REQUIRED'
  /** The executor was handed a job KIND it does not serve. Distinct from
   *  `BRAND_UNSUPPORTED`, which is "this brand, that operation": this one is
   *  "that operation, full stop", and it must never be answered by guessing. */
  | 'KIND_UNSUPPORTED';

export class ChangeError extends Error {
  readonly kind: ChangeErrorKind;
  readonly detail: Record<string, unknown>;
  constructor(kind: ChangeErrorKind, message: string, detail: Record<string, unknown> = {}) {
    super(message);
    this.name = 'ChangeError';
    this.kind = kind;
    this.detail = detail;
  }
}

// ============================================================================
// Redaction for the audit trail — the secrets rule, stricter than the transport's
// ============================================================================

/**
 * Build the audit-safe rendering of a sentence.
 *
 * Three passes, each closing a different hole:
 *  1. the transport's `redactWords()`: secret attributes masked (`=password=`
 *     etc.) AND body attributes (`=source=`, `=on-event=`, `=contents=`,
 *     `=value=`, `=comment=`) collapsed to a byte count — you learn that a
 *     4 812-byte script was sent, never what was in it. The whole point of
 *     `safeApply` is that it ships the rendered configuration, WITH the secrets
 *     the vault injected, inside `=source=` of a `/system/script/add`. The body
 *     pass used to live here only, so `command_audit` was protected while the
 *     transport's own trace log printed the same `=source=` in full; it now
 *     lives in `protocol.ts`, where every path goes through it;
 *  2. the single-use transfer token, which travels inside `=url=`;
 *  3. literal scrubbing of any secret value the caller declares, which catches
 *     a secret that arrived through an attribute nobody thought to name.
 */
export function redactForAudit(
  words: readonly string[],
  secretValues: readonly string[] = [],
): string {
  let line = redactWords(words).join(' ');
  // A single-use transfer token is a bearer credential for the seconds it is
  // alive, and it travels inside `=url=`, which no secret-attribute list would
  // ever flag. The first run of the safe-write recipe caught it sitting in
  // `command_audit`; this replacement is what closes it.
  line = line.replace(TRANSFER_TOKEN_IN_TEXT, '/_obliwan/transfer/***');
  for (const secret of secretValues) {
    if (secret && secret.length >= 4) line = line.split(secret).join('***');
  }
  return line;
}

/**
 * Refuse to persist a string that still contains a known secret.
 *
 * This exists because the secrets rule is a property of the SYSTEM, not a habit of the
 * author: the redacted rendering is produced in one place and then checked
 * against the secrets we know we injected. If the check fires, we throw rather
 * than write — a job that stops is a meeting, a PSK in `command_audit` is a
 * disclosure that cannot be undone.
 */
export function assertNoSecrets(text: string, secretValues: readonly string[]): void {
  for (const secret of secretValues) {
    if (secret && secret.length >= 4 && text.includes(secret)) {
      throw new ChangeError(
        'SECRET_LEAK_REFUSED',
        'refusing to persist a value that still contains a secret',
        { length: text.length },
      );
    }
  }
}

// ============================================================================
// The device target and the fresh session
// ============================================================================

export interface DeviceTarget {
  id: number;
  tenantId: number;
  uuid: string;
  name: string;
  brand: string;
  family: DeviceFamily;
  model: string | null;
  osVersion: string | null;
  siteId: number | null;
  status: string;
  isManaged: boolean;
  tunnelIp: string | null;
  /** The device immediately upstream ON THE MANAGEMENT PATH (migration 030).
   *  Null = the topology was never declared, which is not the same as "there
   *  is none": every consumer takes the closed branch on null. */
  upstreamDeviceId: number | null;
  pppUsername: string | null;
  systemIdentity: string | null;
  serial: string | null;
  concentratorId: number | null;
  /** Where to dial TODAY. Never an identity. */
  host: string | null;
  port: number | null;
  useTls: boolean;
  username: string | null;
  fingerprint: string | null;
  /** Ciphertext. Decrypted only inside `openDeviceSession`, never stored. */
  secretEnc: string | null;
  transportEnabled: boolean;
}

export async function loadDeviceTarget(deviceId: number): Promise<DeviceTarget> {
  const row = await db('devices as d')
    .leftJoin('device_transports as t', function joinApi(this: any) {
      this.on('t.device_id', '=', 'd.id').andOn('t.transport', '=', db.raw('?', ['routeros_api']));
    })
    .where('d.id', deviceId)
    .first<any>(
      'd.id',
      'd.tenant_id',
      'd.uuid',
      'd.name',
      'd.brand',
      'd.family',
      'd.model',
      'd.os_version',
      'd.site_id',
      'd.status',
      'd.is_managed',
      'd.tunnel_ip',
      'd.upstream_device_id',
      'd.ppp_username',
      'd.system_identity',
      'd.serial',
      'd.concentrator_id',
      't.host',
      't.port',
      't.use_tls',
      't.username',
      't.secret_enc',
      't.tls_fingerprint_sha256',
      't.enabled',
    );
  if (!row) throw new ChangeError('DEVICE_UNKNOWN', `Device ${deviceId} does not exist`);
  return {
    id: row.id,
    tenantId: row.tenant_id,
    uuid: row.uuid,
    name: row.name,
    brand: row.brand,
    family: row.family,
    model: row.model ?? null,
    osVersion: row.os_version ?? null,
    siteId: row.site_id ?? null,
    status: row.status,
    isManaged: row.is_managed === true,
    tunnelIp: row.tunnel_ip ?? null,
    upstreamDeviceId: row.upstream_device_id ?? null,
    pppUsername: row.ppp_username ?? null,
    systemIdentity: row.system_identity ?? null,
    serial: row.serial ?? null,
    concentratorId: row.concentrator_id ?? null,
    host: row.host ?? null,
    port: row.port ?? null,
    useTls: row.use_tls === true,
    username: row.username ?? null,
    fingerprint: row.tls_fingerprint_sha256 ?? null,
    secretEnc: row.secret_enc ?? null,
    transportEnabled: row.enabled === true,
  };
}

/** Test seam. The only thing the self-test replaces is the socket factory. */
export type DialFn = (
  target: DeviceTarget,
  opts: { connectTimeoutMs: number; requestTimeoutMs: number; label: string },
) => Promise<RouterOsConnection>;

export interface SessionOptions {
  /** Free-form, goes into the log line and the connection label. */
  purpose: string;
  jobId?: number | null;
  stepId?: number | null;
  userId?: number | null;
  username?: string | null;
  correlationId?: string | null;
  connectTimeoutMs?: number;
  requestTimeoutMs?: number;
  /** Verify the identity ON THIS SOCKET before handing it over. Default
   *  true, and there is no production reason to pass false. */
  assertIdentity?: boolean;
  dial?: DialFn;
  /** Secrets whose literal value must never appear in the audit trail. */
  secretValues?: readonly string[];
}

export interface RunOptions {
  isWrite: boolean;
  timeoutMs?: number;
  /** Extra secrets for this command only (a one-shot backup password). */
  secretValues?: readonly string[];
  /** Do not write a `command_audit` row. Reserved for the polling reads that
   *  would otherwise write one row per 250 ms.
   *
   *  NEVER legal together with `isWrite: true` — `run()` throws on that pair.
   *  The exit door exists for `/file/print` loops, not for gestures that change
   *  a customer's box. */
  skipAudit?: boolean;
}

/**
 * ONE authenticated socket, opened for one purpose, whose identity was proven
 * on the socket itself.
 *
 * `assertTargetBinding()` opens its OWN fresh connection and closes
 * it. That proves the identity of the box that answered THAT socket. Between
 * that socket and the one we then write on, a PPP pool has all the time it
 * needs to move the lease. So this class re-runs the identity comparison on the
 * connection it is about to hand out, using the same exported primitives —
 * `readRouterOsIdentity()` + `compareIdentity()` — so there is one comparison
 * rule in the codebase and it is the inventory's.
 */
export class DeviceSession {
  readonly conn: RouterOsConnection;
  readonly target: DeviceTarget;
  readonly openedAt = Date.now();
  private readonly opts: SessionOptions;
  private readonly secrets: string[];
  private closed = false;

  constructor(conn: RouterOsConnection, target: DeviceTarget, opts: SessionOptions) {
    this.conn = conn;
    this.target = target;
    this.opts = opts;
    this.secrets = [...(opts.secretValues ?? [])];
  }

  /** Add a secret that must be scrubbed from every later audit line. */
  protect(secret: string): void {
    if (secret) this.secrets.push(secret);
  }

  /**
   * Send one sentence and record it — IN THAT ORDER, WHICH IS THE REVERSE OF
   * WHAT THE SENTENCE SAYS.
   *
   * The intent row goes in FIRST, through `auditedCommand()`, and its INSERT is
   * not wrapped in a try/catch: if `command_audit` cannot be appended, this
   * method throws and `conn.query` is never reached. No trace, no bytes. That
   * Is the secrets rule and it is the reason this file exists at the layer it does —
   * it is the single place where a command leaves for an equipment, so it is
   * the single place where that rule can be made true rather than described.
   *
   * The RESULT row is appended afterwards and `recordCommandResult()` never
   * throws: once the box has been written to, losing the outcome row must not
   * turn a good change into a failed job. The attempt row — the one that proves
   * the gesture was made — is already committed.
   *
   * A `!trap` is an ANSWER (the menu refused); a socket death is not, and the
   * two are different incidents. The result row cannot carry NULL, so the
   * distinction is carried in the error text instead: a non-trap failure is
   * prefixed `no answer: `.
   */
  async run(words: string[], options: RunOptions): Promise<Record<string, string>[]> {
    // Every refusal raised BEFORE the sentence is handed to the socket — a
    // secret left in the audit line, a write asking to skip the audit, the
    // audit intent row that could not be written — is MARKED as such
    // (`applyFrontier.ts`): this sentence never left, which is what lets the
    // apply path tell "the run was refused here" from "the run may have
    // reached the router". Anything raised once it was handed over is not.
    let handed = false;
    try {
      return await this.runUnmarked(words, options, () => {
        handed = true;
      });
    } catch (err) {
      throw handed ? err : markNothingTransmitted(err);
    }
  }

  private async runUnmarked(
    words: string[],
    options: RunOptions,
    onHand: () => void,
  ): Promise<Record<string, string>[]> {
    const secrets = [...this.secrets, ...(options.secretValues ?? [])];
    const line = redactForAudit(words, secrets);
    assertNoSecrets(line, secrets);

    if (options.skipAudit) {
      // The only exit door, and it may never cover a write.
      if (options.isWrite) {
        throw new ChangeError(
          'AUDIT_REQUIRED',
          'skipAudit is not available for a write',
          { deviceId: this.target.id, purpose: this.opts.purpose },
        );
      }
      onHand();
      return this.conn.query(words, { timeoutMs: options.timeoutMs });
    }

    return auditedCommand(
      {
        tenantId: this.target.tenantId,
        deviceId: this.target.id,
        deviceUuid: this.target.uuid,
        deviceName: this.target.name,
        userId: this.opts.userId ?? null,
        username: this.opts.username ?? null,
        jobId: this.opts.jobId ?? null,
        stepId: this.opts.stepId ?? null,
        transport: 'routeros_api',
        command: line,
        args: { purpose: this.opts.purpose },
        isWrite: options.isWrite,
        correlationId: this.opts.correlationId ?? null,
        secrets,
      },
      async () => {
        onHand();
        try {
          return await this.conn.query(words, { timeoutMs: options.timeoutMs });
        } catch (err) {
          // The device's OWN answer can echo back a single-use transfer token
          // or a literal we injected. `auditedCommand` stores `err.message`, so
          // it is redacted here, in place, before it can reach `command_audit`,
          // `change_job_steps` or a log line. Nothing in this tree branches on
          // the text of a device error.
          if (err instanceof Error) {
            const prefix = err instanceof RouterOsTrapError ? '' : 'no answer: ';
            err.message = prefix + redactForAudit([err.message], secrets);
          }
          throw err;
        }
      },
    );
  }

  /**
   * ONE gesture carried out as several exchanges — a chunked `/file/read` on
   * this socket, an SFTP pull on the device's SSH channel — recorded as ONE
   * `command_audit` row, in the same order as `run()`: the intent row first,
   * unguarded, so a trace that cannot be written stops the gesture before
   * anything is asked of the box. One row rather than one per chunk, because
   * the gesture is "read file X", and a 2 MB backup is 64 chunks.
   *
   * Reads only: a write must go through `run()`, one audited sentence each.
   */
  async runGesture<T>(
    words: string[],
    options: { transport?: AuditTransport; args?: Record<string, unknown> },
    send: () => Promise<T>,
  ): Promise<T> {
    const line = redactForAudit(words, this.secrets);
    assertNoSecrets(line, this.secrets);
    return auditedCommand(
      {
        tenantId: this.target.tenantId,
        deviceId: this.target.id,
        deviceUuid: this.target.uuid,
        deviceName: this.target.name,
        userId: this.opts.userId ?? null,
        username: this.opts.username ?? null,
        jobId: this.opts.jobId ?? null,
        stepId: this.opts.stepId ?? null,
        transport: options.transport ?? 'routeros_api',
        command: line,
        args: { purpose: this.opts.purpose, ...(options.args ?? {}) },
        isWrite: false,
        correlationId: this.opts.correlationId ?? null,
        secrets: this.secrets,
      },
      async () => {
        try {
          return await send();
        } catch (err) {
          // Same rule as `run()`: what reaches `command_audit` is redacted.
          if (err instanceof Error) err.message = redactForAudit([err.message], this.secrets);
          throw err;
        }
      },
    );
  }

  /**
   * The device's `ssh` transport row, as the SFTP road reads it — ciphertext
   * only, or null. A method rather than a bare query so a harness without
   * PostgreSQL can substitute it, as it substitutes `run()` and
   * `runGesture()`; what the row is judged on stays in `loadSshPullChannel()`.
   */
  async readSshTransportRow(): Promise<SshTransportRow | null> {
    const row = await db('device_transports')
      .where({ device_id: this.target.id, transport: 'ssh' })
      .first<any>('host', 'port', 'username', 'secret_enc', 'private_key_enc', 'enabled');
    if (!row) return null;
    return {
      host: row.host ?? null,
      port: row.port ?? null,
      username: row.username ?? null,
      secretEnc: row.secret_enc ?? null,
      privateKeyEnc: row.private_key_enc ?? null,
      enabled: row.enabled === true,
    };
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.conn.close();
  }
}

const defaultDial: DialFn = async (target, opts) => {
  if (!target.host && !target.tunnelIp) {
    throw new ChangeError('NO_TRANSPORT', 'no address to dial', { deviceId: target.id });
  }
  if (!target.username || !target.secretEnc) {
    throw new ChangeError('NO_CREDENTIAL', 'no credential in the vault', { deviceId: target.id });
  }
  return createRouterOsConnection({
    host: (target.host ?? target.tunnelIp) as string,
    port: target.port ?? undefined,
    tls: target.useTls,
    username: target.username,
    password: decrypt(target.secretEnc),
    expectedFingerprint: target.fingerprint,
    connectTimeoutMs: opts.connectTimeoutMs,
    requestTimeoutMs: opts.requestTimeoutMs,
    label: opts.label,
  });
};

/**
 * Open a NEW socket to a device and prove, on that socket, that it is the right
 * device.
 *
 * There is no pooled variant and there will not be one. The safe write asks for a fresh
 * socket after the change specifically because an ALREADY-OPEN socket survives
 * a rule that blocks NEW connections: reusing it would report "everything is
 * fine" from inside a box nobody else can reach any more.
 */
export async function openDeviceSession(
  deviceId: number,
  options: SessionOptions,
): Promise<DeviceSession> {
  const target = await loadDeviceTarget(deviceId);
  if (target.status === 'disabled') {
    throw new ChangeError('NO_TRANSPORT', "device status is 'disabled'; no transport may be opened");
  }
  const brand = FAMILY_BRAND[target.family];
  if (brand !== 'mikrotik') {
    throw new ChangeError(
      'BRAND_UNSUPPORTED',
      `there is no RouterOS API session for family '${target.family}' — ` +
        'see the per-brand write paths in safeApply.service.ts',
      { family: target.family, brand },
    );
  }
  if (!target.transportEnabled) {
    throw new ChangeError('NO_TRANSPORT', 'routeros_api transport is absent or disabled');
  }

  const dial = options.dial ?? defaultDial;
  let conn: RouterOsConnection;
  try {
    conn = await dial(target, {
      connectTimeoutMs: options.connectTimeoutMs ?? 10_000,
      requestTimeoutMs: options.requestTimeoutMs ?? 30_000,
      label: `${options.purpose}:${target.name}`,
    });
  } catch (err) {
    if (err instanceof ChangeError) throw err;
    throw new ChangeError(
      'CONNECT_FAILED',
      `fresh connection to ${target.host ?? target.tunnelIp} failed: ${
        err instanceof Error ? err.message : String(err)
      }`,
      { deviceId },
    );
  }

  if (options.assertIdentity !== false) {
    try {
      const observed = await readRouterOsIdentity(conn, target.pppUsername);
      const comparison = compareIdentity(
        {
          ppp_username: target.pppUsername,
          system_identity: target.systemIdentity,
          serial: target.serial,
        },
        observed,
        // A rename in flight or unsettled accepts its frozen pair (site_rename).
        await renameIdentityAlternates(deviceId),
      );
      if (!comparison.ok) {
        conn.close();
        throw new ChangeError(
          'IDENTITY_MISMATCH',
          `${comparison.reason} (device ${deviceId}, dialled ${target.host ?? target.tunnelIp})`,
          { deviceId, checks: comparison.checks },
        );
      }
    } catch (err) {
      conn.close();
      if (err instanceof ChangeError) throw err;
      throw new ChangeError(
        'IDENTITY_MISMATCH',
        `identity could not be read on the fresh socket: ${
          err instanceof Error ? err.message : String(err)
        }`,
        { deviceId },
      );
    }
  }

  return new DeviceSession(conn, target, options);
}

// ============================================================================
// Storage layout and retention
// ============================================================================

/**
 * Where every stored backup lives: `device_backups.storage_path` is RELATIVE
 * to this root, so moving the root moves every backup with it.
 *
 * `OBLIWAN_BACKUP_ROOT` when set, else `<cwd>/data/backups` — which in the
 * server image is `/app/server/data/backups` (WORKDIR /app/server). A path
 * inside a container is not storage: unless a volume is mounted there, every
 * backup written here is deleted when the container is recreated by an image
 * update, while its `device_backups` row still says `available` until the daily
 * retention pass (backupRetention.service.ts) re-verifies it and marks it
 * `missing` — and that pass reaches each row only in its turn, a bounded
 * sample a day, so a rollback can still be the first to find the loss. The
 * compose files mount the `change_backups` volume at
 * `${OBLIWAN_BACKUP_ROOT:-/app/server/data/backups}` and pass that same
 * expression as the variable, so the two cannot disagree.
 *
 * The transfer spool is NOT under this root (transfer.service.ts defaults it to
 * `os.tmpdir()`, and no caller overrides it); the move in `takeBackupOfKind()`
 * falls back to copy + unlink when the rename crosses a filesystem, which it
 * does as soon as this root is a volume. That makes the copy the normal path,
 * so step 5 there erases a partial copy, the spooled copy and the router's
 * blob when it fails (a full volume, most likely: the retention pass purges
 * only what has expired, and only on the leader, once a day).
 */
export function backupRoot(): string {
  const configured = (process.env.OBLIWAN_BACKUP_ROOT ?? '').trim();
  return configured.length > 0 ? configured : path.join(process.cwd(), 'data', 'backups');
}

/**
 * Retention in days per class. `legal_hold` is `null` — a hold that expires is
 * not a hold, and migration 009 enforces that with a CHECK.
 *
 * Configurable through `app_config` key `backup_retention_days`, a JSON object.
 * The defaults are deliberately unambitious: a preflight backup is interesting
 * for as long as somebody might want to undo the change it protected.
 */
export const DEFAULT_RETENTION_DAYS: Readonly<Record<BackupRetentionClass, number | null>> = {
  short: 7,
  standard: 90,
  long: 365,
  legal_hold: null,
};

export async function retentionDays(): Promise<Record<BackupRetentionClass, number | null>> {
  const row = await db('app_config').where({ key: 'backup_retention_days' }).first('value');
  const result = { ...DEFAULT_RETENTION_DAYS } as Record<BackupRetentionClass, number | null>;
  if (!row?.value) return result;
  try {
    const parsed = JSON.parse(row.value) as Record<string, unknown>;
    for (const key of Object.keys(result) as BackupRetentionClass[]) {
      const v = parsed[key];
      if (key === 'legal_hold') continue; // never expires, whatever the config says
      if (typeof v === 'number' && Number.isFinite(v) && v > 0) result[key] = Math.floor(v);
    }
  } catch {
    logger.warn('backup_retention_days is not valid JSON; using defaults');
  }
  return result;
}

// ============================================================================
// The RouterOS commands, built in one place
// ============================================================================

/** File extension RouterOS gives each kind. */
const EXTENSION: Record<BackupKind, string> = { binary: '.backup', rsc: '.rsc' };

/** A backup below this is not a backup. Both floors are deliberately low
 *  enough for a bare CHR and high enough to catch a zero-length file. */
export const MIN_BACKUP_BYTES: Record<BackupKind, number> = { binary: 1024, rsc: 128 };

export function backupBaseName(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`;
}

/**
 * The ONE API spelling of the export: the family's flags, read from the same
 * driver table as the SSH collector's command (`routerOsExportApiFlagWords()`
 * beside `routerOsExportCommand()`), and a file name.
 *
 *   mikrotik_routeros6   /export =terse= =hide-sensitive= =file=<base>
 *   mikrotik_routeros7   /export =terse= =file=<base>
 *
 * ┌─ IT USED TO SEND `=show-sensitive=no`, AND REQUIRE IT ───────────────────┐
 * │ The SSH collector dropped that spelling when a real router refused it    │
 * │ ("expected end of command": `show-sensitive` is a bare FLAG on RouterOS  │
 * │ 7, and RouterOS 6 has no such parameter at all). This path kept it, and  │
 * │ threw unless it was present, so the preflight backup — step 1 of every   │
 * │ push — sent the one token the driver had just shown a router rejecting.  │
 * │ What the API does with a value on a flag is unobserved; two plausible    │
 * │ answers are "trap", which stops every push, and "treat as present",      │
 * │ which on RouterOS 7 is the request that REVEALS the secrets.             │
 * │                                                                          │
 * │ Its replacement sent NO sensitivity word to every family, on the belief  │
 * │ that RouterOS redacts by default. RouterOS 7 does; RouterOS 6 does the   │
 * │ opposite. On a RouterOS 6 box every preflight `.rsc` and every rollback  │
 * │ comparison therefore wrote the box's secrets to its flash and had        │
 * │ `/tool/fetch` POST them to us over plain HTTP — the read-back refused    │
 * │ them only after both had happened.                                       │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * There is no options object, no default, no override. An unknown family is
 * refused (`BRAND_UNSUPPORTED`) instead of given a guessed spelling, and the
 * tripwire below makes a future refactor that adds `show-sensitive` in any
 * form fail loudly instead of changing what the no-secrets rule rests on. `terse` is there
 * too: the one-line-per-item form is what the NCM parser and the diff read.
 * The words are only as right as `devices.family` — which is why every caller
 * runs `assertBoxSpeaksRecordedFamily()` first — and the read-back in
 * `takeBackupOfKind()` / `exportCanonicalHash()` still judges what comes back.
 */
export function buildExportWords(family: string, fileBaseName: string): string[] {
  let flags: string[];
  try {
    flags = routerOsExportApiFlagWords(family);
  } catch (err) {
    const unknownFamily = err instanceof DriverError && err.code === 'NOT_IMPLEMENTED';
    throw new ChangeError(
      unknownFamily ? 'BRAND_UNSUPPORTED' : 'SECRET_LEAK_REFUSED',
      err instanceof Error ? err.message : String(err),
      { family },
    );
  }
  const words = ['/export', ...flags, `=file=${fileBaseName}`];
  if (words.some((w) => /^=show-sensitive(?:=|$)/i.test(w))) {
    throw new ChangeError('SECRET_LEAK_REFUSED', '/export must never carry show-sensitive', {
      family,
    });
  }
  return words;
}

/**
 * The family check the export needs and the inventory cannot give.
 *
 * `devices.family` is what the export is spelled for, and nothing keeps it
 * current: `learnDeviceFacts()` does not write it, and an operator who upgrades
 * a hEX from 6.49 to 7.x changes the dialect without touching the inventory.
 * So the box's OWN version is read on this session (`/system/resource/print`,
 * a read with no audit row, like the uptime read) and compared with the
 * recorded family BEFORE any export file exists:
 *
 *  - recorded 7, box 6: the words would carry no `hide-sensitive`, RouterOS 6
 *    would print every secret into a file on its flash, and the file would be
 *    pulled off it before the read-back could refuse it.
 *    This is the case the check exists for.
 *  - recorded 6, box 7: `hide-sensitive` would go to a RouterOS 7 that may not
 *    accept it, and the push would stop on a trap naming a flag instead of the
 *    cause.
 *
 * Both refuse with `FAMILY_MISMATCH`, naming the two.
 *
 * A read that did NOT COMPLETE — a timeout, a dropped socket, a `!trap` —
 * refuses too, with `FAMILY_UNVERIFIED`. It used to be read as "the box
 * reports no version" (`.catch(() => [])`), i.e. as permission to spell the
 * export from the inventory, so a tunnel that hiccupped on this one read sent
 * a RouterOS 6 box recorded as 7 the words that write its secrets to flash.
 * Nothing has been exported at that point, so the refusal costs a retry.
 *
 * Only a read that COMPLETED and carries no usable `version` (absent,
 * unparsable) is not a mismatch: the recorded family is then the only claim
 * there is, and the export is spelled from it — refusing there would stop
 * every push on a box that merely hides its version. That residual is stated
 * rather than hidden: on such a box, recorded under the wrong major, the
 * read-back still keeps the secrets out of the store, but not off the
 * router's flash or the wire.
 */
export async function assertBoxSpeaksRecordedFamily(session: DeviceSession): Promise<void> {
  let rows: Record<string, string>[];
  try {
    rows = await session.run(['/system/resource/print'], { isWrite: false, skipAudit: true });
  } catch (err) {
    const how = err instanceof RouterOsTrapError ? 'the box refused it' : 'no answer';
    const why = (err instanceof Error ? err.message : String(err)).slice(0, 200);
    throw new ChangeError(
      'FAMILY_UNVERIFIED',
      `the version read that must precede the export on ${session.target.name} failed ` +
        `(${how}: ${why}), so '${session.target.family}' could not be checked against the box. ` +
        'Nothing was exported; the job can be retried.',
      { recorded: session.target.family },
    );
  }
  const version = rows[0]?.version ?? null;
  const observed = familyFromVersion(version);
  const recorded = session.target.family;
  if (observed !== null && observed !== recorded) {
    throw new ChangeError(
      'FAMILY_MISMATCH',
      `${session.target.name} is recorded as '${recorded}' but reports RouterOS ${version}. ` +
        'The export is spelled differently on RouterOS 6 (hide-sensitive) and RouterOS 7 (no ' +
        "flag), so it is refused rather than sent in the wrong dialect. Correct the device's " +
        'family; nothing was exported.',
      { recorded, observed, version },
    );
  }
}

/**
 * The no-secrets rule on an `.rsc` that has already left the router: the same detector the SSH
 * collector runs (`findSensitiveProps()`, the driver's), wrapped in this file's
 * error type. Names the props, never a value.
 */
export function assertRscCarriesNoSecret(text: string, what: string): void {
  const props = findSensitiveProps(text);
  if (props.length > 0) throw rscSecretRefusal(props, what);
}

function rscSecretRefusal(props: readonly string[], what: string): ChangeError {
  return new ChangeError(
    'SECRET_LEAK_REFUSED',
    `${what} carries a value for sensitive prop(s) [${props.join(', ')}]. ${SENSITIVE_REFUSAL_HINT}`,
    { props: [...props] },
  );
}

/**
 * On a failure path: erase the device copy of an artefact, and return the
 * sentence to APPEND to the failure when that erasure cannot be proven ('' when
 * it was). Never throws — the failure being reported is the one that matters —
 * but never stays silent either: "refusing to leave a copy of the customer
 * configuration on the equipment" is only true if a copy that WAS left is said.
 */
async function eraseAfterFailure(session: DeviceSession, fileName: string): Promise<string> {
  const removal = await removeDeviceFile(session.conn, fileName, { attempts: 3 });
  if (removal.verified) return '';
  logger.error(
    { deviceId: session.target.id, fileName, lastError: removal.lastError },
    'a failed backup left its file on the equipment',
  );
  return (
    ` ${fileName} could NOT be proven deleted from ${session.target.name} ` +
    `(${removal.attempts} attempt(s)): remove it by hand.`
  );
}

/** Same contract for the spooled copy on THIS host: '' when it is gone. */
async function eraseSpoolFile(filePath: string): Promise<string> {
  try {
    await fsp.rm(filePath, { force: true });
    return '';
  } catch (err) {
    logger.error({ err, file: path.basename(filePath) }, 'could not delete a refused spool file');
    return ` The spooled copy (${path.basename(filePath)}, in the transfer spool) could NOT be deleted: remove it by hand.`;
  }
}

export function buildBackupSaveWords(fileBaseName: string, password: string): string[] {
  // The password is what makes the blob useless to whoever finds it in transit.
  // It is generated per backup, stored ENCRYPTED in `device_backups`, and never
  // written next to the blob.
  return ['/system/backup/save', `=name=${fileBaseName}`, `=password=${password}`];
}

// ============================================================================
// Getting the file off the router — three roads, chosen before the file exists
// ============================================================================

/** How a backup came off the router (see the file header). */
export type BackupTransferMethod = 'api_file_read' | 'sftp' | 'http_upload';

/** How the RouterOS API session reaches the box, as far as this side can tell
 *  from the transport row it is dialled from (`defaultDial`). */
export interface ApiChannelJudgement {
  /** The address the session dials: the transport's `host`, else `tunnel_ip`. */
  host: string | null;
  /** api-ssl (TLS, 8729). Encrypted, but not by itself authenticated. */
  encrypted: boolean;
  /** TLS AND a certificate fingerprint pinned on the transport row, which
   *  `defaultDial` enforces (a different certificate refuses the session).
   *  Without it the connection trusts whatever certificate it is shown. */
  pinned: boolean;
  /**
   * `tunnel`: the device's own tunnel IP, and a non-public one. `private`: any
   * other non-public IP literal (RFC 1918, CGNAT, loopback, link-local).
   * `public`: everything else — a public IP, or a NAME, whose resolution is
   * not known here and is therefore not trusted.
   *
   * "tunnel" means "addressed through the concentrator", nothing more: whether
   * the L2TP leg itself is IPsec-protected is a concentrator setting this code
   * cannot see.
   */
  addressClass: 'tunnel' | 'private' | 'public';
}

export function judgeApiChannel(target: DeviceTarget): ApiChannelJudgement {
  const host = target.host ?? target.tunnelIp ?? null;
  let addressClass: ApiChannelJudgement['addressClass'] = 'public';
  if (host !== null && isNonPublicAddress(host)) {
    addressClass = target.tunnelIp !== null && host === target.tunnelIp ? 'tunnel' : 'private';
  }
  const pinned = target.useTls && (target.fingerprint ?? '').trim().length > 0;
  return { host, encrypted: target.useTls, pinned, addressClass };
}

/** Whether the API session may carry a backup: a non-public path, or a pinned
 *  TLS session. Never an unpinned TLS session to a public address. */
export function apiChannelAcceptable(channel: ApiChannelJudgement): boolean {
  return channel.addressClass !== 'public' || channel.pinned;
}

/** Two spellings of one address compare equal: case, brackets around IPv6. */
function sameHost(a: string | null | undefined, b: string | null | undefined): boolean {
  const norm = (h: string | null | undefined): string =>
    (h ?? '').trim().replace(/^\[|\]$/g, '').toLowerCase();
  return norm(a) !== '' && norm(a) === norm(b);
}

/** A `device_transports` row of kind `ssh`, as stored. */
export interface SshTransportRow {
  host: string | null;
  port: number | null;
  username: string | null;
  secretEnc: string | null;
  privateKeyEnc: string | null;
  enabled: boolean;
}

/** The device's SSH channel, as the SFTP road needs it. Ciphertext only; the
 *  credential is decrypted at the moment of the pull. */
export interface SshPullChannel {
  host: string;
  port: number;
  username: string;
  secretEnc: string | null;
  privateKeyEnc: string | null;
}

/**
 * The device's SSH transport, when it may carry a backup — else null and the
 * reason, worded for the refusal sentence.
 *
 * Its host key is NOT pinned: nothing in ObliWAN records an SSH host key today
 * (the config collector dials the same way), and a pin needs a column of its
 * own — `device_transports.params` is replaced wholesale whenever the device
 * page saves the transport, so a pin kept there would vanish on the next edit,
 * or survive a change of host. Without a pin, the channel is held to two
 * conditions instead:
 *  - its host is the address the API session dialled — the one whose
 *    identity `openDeviceSession` has just proven. An SSH row that
 *    points elsewhere (a stale tunnel IP, a typo, another customer's box)
 *    would present the vault credential to whatever answers there;
 *  - that address is not public. On a non-public path SSH is strictly better
 *    than the cleartext API session already accepted there (that session
 *    carried the login and the backup password); on a public path, an
 *    unpinned SSH is exactly the unauthenticated channel the API road refuses.
 * What then ties the bytes to the box is the size: the SFTP server's own
 * STAT, held exactly (`sftpPullFile`), and the API session's `/file/print` —
 * exact on RouterOS 7 and re-read after the pull, rounded on RouterOS 6 and
 * then only held to a tolerance — for a file whose name was random and minted
 * seconds earlier.
 */
export async function loadSshPullChannel(
  session: DeviceSession,
  api: ApiChannelJudgement,
): Promise<{ channel: SshPullChannel | null; why: string }> {
  const row = await session.readSshTransportRow();
  if (!row) return { channel: null, why: 'it has no SSH transport' };
  if (!row.enabled) return { channel: null, why: 'its SSH transport is disabled' };
  if (!row.host || !row.username || (!row.secretEnc && !row.privateKeyEnc)) {
    return {
      channel: null,
      why: 'its SSH transport is incomplete (it needs a host, a username and a credential)',
    };
  }
  if (!sameHost(row.host, api.host)) {
    return {
      channel: null,
      why:
        `its SSH transport dials ${row.host}, not ${api.host ?? 'the address'} its RouterOS API ` +
        'session reached and proved its identity on, so SFTP there could be talking to another box',
    };
  }
  if (api.addressClass === 'public') {
    return {
      channel: null,
      why:
        `its SSH transport reaches ${row.host}, a public address or a name, and ObliWAN pins no SSH ` +
        'host key, so SFTP there could not tell the router from a man in the middle',
    };
  }
  return {
    channel: {
      host: row.host,
      port: row.port ?? 22,
      username: row.username,
      secretEnc: row.secretEnc,
      privateKeyEnc: row.privateKeyEnc,
    },
    why: '',
  };
}

/**
 * Whether the router-to-us HTTP upload may be used, and why not.
 *
 * Only on an EXPLICIT configuration — a `callbackHost`, or a receiver built
 * with a `publicBaseUrl`; without one, `TransferReceiver.baseUrl()` falls back
 * to this host's loopback, which no remote router can reach — and only when
 * neither leg crosses the public internet as addressed: the box is reached on
 * a non-public address, and the callback is a non-public IP literal (a name is
 * not judged). A loopback callback is accepted only for a box that is itself
 * dialled on loopback, i.e. on this host.
 */
export function judgeUploadCallback(
  channel: ApiChannelJudgement,
  callbackHost: string | undefined,
  receiver: TransferReceiver | null | undefined,
): { configured: boolean; ok: boolean; why: string } {
  const explicitHost = (callbackHost ?? '').trim();
  const baseUrl = receiver?.configuredBaseUrl ?? null;
  if (!explicitHost && !baseUrl) {
    return { configured: false, ok: false, why: 'no upload callback is configured' };
  }
  // A configured base URL WINS over `callbackHost` in `TransferReceiver.baseUrl()`,
  // so it is the address judged whenever there is one.
  let cbHost = explicitHost;
  if (baseUrl) {
    try {
      cbHost = new URL(baseUrl).hostname.replace(/^\[|\]$/g, '');
    } catch {
      return { configured: true, ok: false, why: `the receiver's base URL is not a URL` };
    }
  }
  if (channel.addressClass === 'public') {
    return {
      configured: true,
      ok: false,
      why: `the box is reached on ${channel.host ?? 'no address'} (a public address or a name), so its upload would cross the internet in clear`,
    };
  }
  if (!isNonPublicAddress(cbHost)) {
    return {
      configured: true,
      ok: false,
      why: `the callback ${cbHost} is not a non-public IP address, so the upload could cross the internet in clear`,
    };
  }
  if (isLoopbackAddress(cbHost) && !isLoopbackAddress(channel.host)) {
    return {
      configured: true,
      ok: false,
      why: `the callback ${cbHost} is this server's loopback, which a box at ${channel.host} cannot reach`,
    };
  }
  return { configured: true, ok: true, why: '' };
}

export interface BackupPullPlan {
  /** What the box reported (`/system/resource/print`), or null when that read
   *  did not complete or carried no version. */
  version: string | null;
  api: {
    channel: ApiChannelJudgement;
    /** A non-public address, or pinned TLS (`apiChannelAcceptable`). */
    acceptable: boolean;
    support: 'yes' | 'no' | 'unknown';
  };
  /** Loaded at plan time when the API road cannot carry the file; otherwise
   *  only if that road turns out unavailable on the box. */
  ssh: { channel: SshPullChannel | null; why: string } | null;
  http: { configured: boolean; ok: boolean; why: string };
}

/** The box's version on this session, or null. A read with no audit row, like
 *  the family check's. Never throws: an unread version only makes the API
 *  road "unknown" — tried, and judged by the box's answer. */
async function readBoxVersion(session: DeviceSession): Promise<string | null> {
  try {
    const rows = await session.run(['/system/resource/print'], { isWrite: false, skipAudit: true });
    const v = (rows[0]?.version ?? '').trim();
    return v.length > 0 ? v : null;
  } catch {
    return null;
  }
}

function apiRoadOpen(plan: BackupPullPlan): boolean {
  return plan.api.acceptable && plan.api.support !== 'no';
}

/**
 * The sentence for "no acceptable road": every reason, then what to do. It
 * names the RouterOS version and the missing channel, because those are what
 * the operator changes.
 */
function noRoadMessage(target: DeviceTarget, plan: BackupPullPlan, skipped: readonly string[]): string {
  const parts: string[] = [];
  const ch = plan.api.channel;
  const publicPath = ch.addressClass === 'public';
  const tooOld = plan.api.support === 'no';
  if (!plan.api.acceptable) {
    parts.push(
      ch.encrypted
        ? `its RouterOS API session is TLS to ${ch.host ?? 'no address'}, a public address or a name, ` +
            'with no certificate fingerprint pinned on its API channel, so the router cannot be told ' +
            'from a man in the middle, and a backup holding its secrets is never pulled over that'
        : `its RouterOS API session is cleartext to ${ch.host ?? 'no address'}, a public address or a name ` +
            ', and a backup holding its secrets is never pulled across the internet in clear',
    );
  }
  if (tooOld) {
    parts.push(
      `API file read (/file/read) is unavailable on RouterOS ${plan.version ?? '?'} — it needs ` +
        `${ROUTEROS_FILE_READ_SINCE} or later`,
    );
  }
  parts.push(...skipped);
  // A channel that exists and failed is already explained by `skipped`.
  if (!plan.ssh?.channel) parts.push(plan.ssh?.why || 'it has no usable SSH transport');
  if (plan.http.configured && !plan.http.ok) {
    parts.push(`the configured upload callback was not used: ${plan.http.why}`);
  }
  // An upgrade THROUGH ObliWAN takes this same preflight backup first, so it
  // is never offered as the way out of a refusal it would itself hit.
  const sshChannel =
    'an SSH channel (port 22, same service account, the same address as its API channel)';
  let remedy: string;
  if (publicPath && tooOld) {
    remedy =
      `Reach it on a non-public address (its tunnel IP) and add ${sshChannel} on the device page; ` +
      `on a public address only a pinned api-ssl session can carry a backup, and that needs ` +
      `RouterOS ${ROUTEROS_FILE_READ_SINCE} or later, installed by hand — an upgrade through ` +
      'ObliWAN takes this same backup first.';
  } else if (publicPath && !plan.api.acceptable && ch.encrypted) {
    remedy =
      "Pin the router's API certificate on its API channel (the RouterOS poller records its " +
      'fingerprint on its first TLS connection), or reach it on a non-public address (its tunnel IP).';
  } else if (publicPath && !plan.api.acceptable) {
    remedy =
      'Enable api-ssl (8729) on the router and TLS on its API channel, with its certificate pinned ' +
      '(the RouterOS poller records it on its first TLS connection), or reach it on a non-public ' +
      'address (its tunnel IP).';
  } else if (publicPath) {
    remedy =
      `Reach it on a non-public address (its tunnel IP) and add ${sshChannel} on the device page; ` +
      'on a public address SFTP is not used, since no SSH host key is pinned.';
  } else if (tooOld) {
    remedy =
      `Add ${sshChannel} on the device page — below RouterOS ${ROUTEROS_FILE_READ_SINCE} it is the ` +
      'only road, including for an upgrade through ObliWAN, which takes this same backup first.';
  } else {
    remedy = `Add ${sshChannel} on the device page.`;
  }
  return `no acceptable way to pull the backup off ${target.name}: ${parts.join('; ')}. ${remedy}`;
}

/**
 * Decide how the file will come off the router — BEFORE it exists.
 *
 * Throws `BACKUP_FAILED` when no road can possibly carry it, so the refusal
 * leaves nothing on the box. Returns a plan otherwise; a road the plan keeps
 * open may still turn out unavailable on the box (`/file/read` trapping on a
 * version that could not be read), which `pullDeviceFile` handles.
 */
export async function planBackupPull(
  session: DeviceSession,
  options: { callbackHost?: string; receiver?: TransferReceiver | null } = {},
): Promise<BackupPullPlan> {
  const version = await readBoxVersion(session);
  const channel = judgeApiChannel(session.target);
  const plan: BackupPullPlan = {
    version,
    api: {
      channel,
      acceptable: apiChannelAcceptable(channel),
      support: routerOsFileReadSupport(version),
    },
    ssh: null,
    http: judgeUploadCallback(channel, options.callbackHost, options.receiver),
  };
  if (plan.api.acceptable && plan.api.support === 'yes') return plan;
  plan.ssh = await loadSshPullChannel(session, channel);
  if (!apiRoadOpen(plan) && !plan.ssh.channel && !plan.http.ok) {
    throw new ChangeError(
      'BACKUP_FAILED',
      `${noRoadMessage(session.target, plan, [])} No backup file was created on the router.`,
      {
        version,
        apiChannel: channel,
        fileRead: plan.api.support,
        ssh: false,
        httpUpload: plan.http.configured ? plan.http.why : 'not configured',
      },
    );
  }
  return plan;
}

export interface PulledFile {
  received: ReceivedFile;
  method: BackupTransferMethod;
  /** `/file/read` round trips; null on the other roads. */
  chunks: number | null;
}

export interface PullOptions {
  /** For the receiver's token and the log line. */
  purpose: string;
  maxBytes: number;
  timeoutMs: number;
  /** A STARTED receiver, for the upload road; its spool directory is used by
   *  every road. Without one, the upload road starts and stops its own. */
  receiver?: TransferReceiver | null;
  callbackHost?: string;
}

/** After a pull, the file must still be listed at the size it was read at —
 *  a box still writing it would otherwise hand us a prefix that matches the
 *  size we asked for. */
async function assertUnchangedAfterPull(
  session: DeviceSession,
  file: DeviceFile,
  received: ReceivedFile,
): Promise<void> {
  const after = await deviceFileInfo(session.conn, file.name).catch(() => null);
  const changed =
    after === null || (after.sizeExact && file.sizeExact && after.sizeBytes !== file.sizeBytes);
  if (changed) {
    await fsp.rm(received.path, { force: true }).catch(() => undefined);
    throw new TransferError(
      'SIZE_MISMATCH',
      after === null
        ? `'${file.name}' is no longer listed on the box after it was read`
        : `'${file.name}' changed on the box while it was read (${file.sizeBytes} → ${after.sizeBytes} bytes)`,
      { before: file.sizeBytes, after: after?.sizeBytes ?? null },
    );
  }
}

async function pullOverApi(
  session: DeviceSession,
  file: DeviceFile,
  options: PullOptions,
): Promise<PulledFile> {
  if (!file.sizeExact) {
    // Every RouterOS that has `/file/read` prints an exact size; one that does
    // not leaves the read nothing to stop on, so this road is not available.
    throw new TransferError(
      'NOT_SUPPORTED',
      `the box printed a rounded size for '${file.name}', and /file/read needs the exact byte count`,
    );
  }
  const result = await session.runGesture(
    ['/file/read', `=file=${file.name}`, `=chunk-size=${ROUTEROS_FILE_READ_MAX_CHUNK}`],
    { args: { road: 'api_file_read', bytes: file.sizeBytes } },
    () =>
      readFileOverApi(session.conn, {
        name: file.name,
        expectedBytes: file.sizeBytes,
        maxBytes: options.maxBytes,
        spoolDir: options.receiver?.spoolDirectory,
        timeoutMs: options.timeoutMs,
      }),
  );
  await assertUnchangedAfterPull(session, file, result);
  return { received: result, method: 'api_file_read', chunks: result.chunks };
}

async function pullOverSftp(
  session: DeviceSession,
  channel: SshPullChannel,
  file: DeviceFile,
  options: PullOptions,
): Promise<PulledFile> {
  const password = channel.secretEnc ? decrypt(channel.secretEnc) : undefined;
  const privateKey = channel.privateKeyEnc ? decrypt(channel.privateKeyEnc) : undefined;
  if (password) session.protect(password);
  const received = await session.runGesture(
    ['sftp', 'get', file.name],
    { transport: 'ssh', args: { road: 'sftp', host: channel.host, bytes: file.sizeBytes } },
    () =>
      sftpPullToSpool({
        host: channel.host,
        port: channel.port,
        username: channel.username,
        password,
        privateKey,
        remotePath: file.name,
        maxBytes: options.maxBytes,
        timeoutMs: options.timeoutMs,
        spoolDir: options.receiver?.spoolDirectory,
      }),
  );
  if (received.remoteSize === null && !file.sizeExact) {
    // Neither side gave an exact size: the RouterOS 6 tolerance in
    // `verifyArtefact` is all that is left, and it would pass a stream that
    // ended a few hundred bytes early.
    logger.warn(
      { deviceId: session.target.id, fileName: file.name, bytes: received.bytes, printed: file.sizeBytes },
      'SFTP stated no size and /file/print a rounded one: this pull is held only to the RouterOS 6 tolerance',
    );
  }
  await assertUnchangedAfterPull(session, file, received);
  return { received, method: 'sftp', chunks: null };
}

/** The router dials US (`/tool/fetch upload=yes`) — plain HTTP, gated by
 *  `judgeUploadCallback()` before this is ever reached. */
async function pullOverHttp(
  session: DeviceSession,
  file: DeviceFile,
  options: PullOptions,
): Promise<PulledFile> {
  const own = options.receiver ? null : new TransferReceiver();
  const receiver = options.receiver ?? (own as TransferReceiver);
  if (own) await own.start();
  try {
    const expectation = receiver.expect({
      purpose: options.purpose,
      maxBytes: options.maxBytes,
      timeoutMs: options.timeoutMs,
      callbackHost: options.callbackHost,
    });
    try {
      const fetchOutcome = await session
        .run(['/tool/fetch', '=upload=yes', `=src-path=${file.name}`, `=url=${expectation.url}`], {
          isWrite: false,
          timeoutMs: options.timeoutMs,
        })
        .then(
          (rows) => ({ ok: true, rows }),
          (err) => ({ ok: false, err }),
        );
      if (!fetchOutcome.ok) {
        expectation.cancel('the device refused or failed the /tool/fetch upload');
      }
      return { received: await expectation.received, method: 'http_upload', chunks: null };
    } catch (err) {
      expectation.cancel('transfer failed');
      throw err;
    }
  } finally {
    if (own) await own.stop();
  }
}

/**
 * Bring one file off the router along the plan's roads, in order: the API
 * read, then SFTP, then — only if `judgeUploadCallback()` allowed it — the
 * upload.
 *  - A road that answers "not available here" (`NOT_SUPPORTED`) gives way to
 *    the next, with a warning.
 *  - A `/file/read` whose bytes fail the size checks (`SIZE_MISMATCH`) gives
 *    way to SFTP ONLY, with a warning: SFTP is the same protection over a
 *    different wire, and how RouterOS encodes binary `/file/read` data has
 *    never been observed — a fleet-wide preflight stop on that unknown is
 *    worse than taking the other encrypted road. Never to the upload: bytes
 *    that already failed a check are not a reason to open the cleartext road.
 *    When SFTP is not there to take over, the size failure is thrown as it is.
 *  - ANY other failure is the transfer failing and is thrown as it is.
 *
 * Exported for the other callers that pull a file the box just wrote (the
 * rollback comparison export, `exportCanonicalHash`).
 */
export async function pullDeviceFile(
  session: DeviceSession,
  plan: BackupPullPlan,
  file: DeviceFile,
  options: PullOptions,
): Promise<PulledFile> {
  const skipped: string[] = [];
  let integrityFailure: TransferError | null = null;
  const giveWay = (road: string, err: unknown): void => {
    if (!(err instanceof TransferError && err.code === 'NOT_SUPPORTED')) throw err;
    skipped.push(`${road} is not available on the box (${err.message})`);
    logger.warn(
      { deviceId: session.target.id, fileName: file.name, road, reason: err.message },
      'backup pull: road unavailable on this box, trying the next acceptable one',
    );
  };

  if (apiRoadOpen(plan)) {
    try {
      return await pullOverApi(session, file, options);
    } catch (err) {
      if (err instanceof TransferError && err.code === 'SIZE_MISMATCH') {
        integrityFailure = err;
        logger.warn(
          { deviceId: session.target.id, fileName: file.name, reason: err.message },
          'backup pull: /file/read bytes failed the size check; SFTP may take over, the upload never',
        );
      } else {
        giveWay('/file/read', err);
      }
    }
  }
  if (!plan.ssh) plan.ssh = await loadSshPullChannel(session, plan.api.channel);
  if (plan.ssh.channel) {
    try {
      return await pullOverSftp(session, plan.ssh.channel, file, options);
    } catch (err) {
      if (integrityFailure && err instanceof TransferError && err.code === 'NOT_SUPPORTED') {
        throw new TransferError(
          'SIZE_MISMATCH',
          `${integrityFailure.message}; SFTP could not take over (${err.message})`,
          integrityFailure.detail,
        );
      }
      giveWay('SFTP', err);
    }
  }
  if (integrityFailure) {
    throw new TransferError(
      'SIZE_MISMATCH',
      `${integrityFailure.message}; no SFTP road could take over (${plan.ssh.why || 'none'})`,
      integrityFailure.detail,
    );
  }
  if (plan.http.ok) return pullOverHttp(session, file, options);
  throw new ChangeError('BACKUP_FAILED', noRoadMessage(session.target, plan, skipped), {
    version: plan.version,
    apiChannel: plan.api.channel,
    fileRead: plan.api.support,
    ssh: plan.ssh.channel !== null,
    httpUpload: plan.http.configured ? plan.http.why || 'allowed' : 'not configured',
  });
}

// ============================================================================
// Taking a backup
// ============================================================================

export interface TakeBackupOptions {
  deviceId: number;
  trigger: BackupTrigger;
  /** Default: both. A preflight backup takes both where the driver can. */
  kinds?: BackupKind[];
  jobId?: number | null;
  retentionClass?: BackupRetentionClass;
  createdBy?: number | null;
  correlationId?: string | null;
  /** Reuse a session the caller already opened and proved. When absent, one is
   *  opened (and closed) here. */
  session?: DeviceSession;
  dial?: DialFn;
  /** The address the ROUTER would dial to UPLOAD to our receiver — the last
   *  road, used only when `judgeUploadCallback()` accepts it (a non-public IP
   *  the box can reach, on a box reached on a non-public address). Nothing in
   *  production sets it; the pull roads need no callback at all. */
  callbackHost?: string;
  /** A STARTED receiver. Its spool directory is used by every road; it is
   *  only ever handed to the router on the upload road. */
  receiver?: TransferReceiver;
  maxBytes?: number;
  saveTimeoutMs?: number;
  transferTimeoutMs?: number;
  filePollMs?: number;
  /**
   * THE ONE EXCEPTION TO "ERASE IT FROM THE DEVICE", AND IT IS NOT A LOOPHOLE.
   *
   * The on-box dead-man restores with `/system/backup/load name=<file>`. It has
   * to run when the tunnel is down, ObliWAN is unreachable and nobody is
   * watching — so the blob it loads MUST be on the router. A dead-man that
   * fetches its own backup over the network is not a dead-man; it is a rollback
   * that needs the very link the change just cut.
   *
   * So the binary preflight backup is kept on the device for the length of the
   * change window and ONLY that: `safeApply` deletes it at disarm,
   * `rollback.service.cleanupDeadmanArtefacts()` deletes it after a fire, and
   * on the two failure paths it is deleted by whoever was holding it —
   * `takeDeviceBackup()` when a later kind of the same set fails, and
   * `runSafeApply()` when the job fails after the backup and before the apply.
   * A job cannot reach `succeeded` while it is still there. The `.rsc` is never
   * kept — nothing restores from it, so leaving it would be pure exposure.
   */
  keepOnDeviceKinds?: BackupKind[];
  /** Force the on-device file name (the dead-man references it by name). */
  fileBaseName?: Partial<Record<BackupKind, string>>;
}

export interface BackupArtefact {
  id: number;
  kind: BackupKind;
  storagePath: string;
  absolutePath: string;
  sizeBytes: number;
  sha256: string;
  osVersion: string | null;
  /** True only when the file was PROVEN gone from the device. */
  onDeviceRemoved: boolean;
  /** Non-null when the blob was deliberately LEFT on the device for the
   *  dead-man to load. Whoever holds this name owes a deletion. */
  onDeviceFileName: string | null;
  removalAttempts: number;
  transferMs: number;
  deviceReportedBytes: number;
  /** The road it came off the router by. */
  transferMethod: BackupTransferMethod;
}

export interface BackupSet {
  deviceId: number;
  jobId: number | null;
  artefacts: BackupArtefact[];
  /** The binary one, which is what the dead-man restores. */
  binary: BackupArtefact | null;
  rsc: BackupArtefact | null;
  totalMs: number;
}

/**
 * Take one backup of one kind, pull it off, prove it, erase it, record it.
 *
 * The order is the contract. In particular the on-device deletion happens
 * BEFORE the row is written, and a deletion we could not verify aborts the
 * whole thing: we would rather have no backup and a loud failure than a backup
 * whose original is still sitting on the customer's router.
 *
 * `receiver` is optional: the pull roads need none, and the upload road starts
 * its own when it is allowed and none was given. `plan` is the road decision
 * `takeDeviceBackup` already made for the set; when absent it is made here,
 * before the file exists.
 */
export async function takeBackupOfKind(
  session: DeviceSession,
  kind: BackupKind,
  options: TakeBackupOptions,
  receiver?: TransferReceiver | null,
  plan?: BackupPullPlan,
): Promise<BackupArtefact> {
  const target = session.target;
  const base = options.fileBaseName?.[kind] ?? backupBaseName(`obliwan-${options.jobId ?? 'man'}-${kind}`);
  const fileName = `${base}${EXTENSION[kind]}`;
  const keepOnDevice = (options.keepOnDeviceKinds ?? []).includes(kind);
  const maxBytes = options.maxBytes ?? 128 * 1024 * 1024;
  const password = kind === 'binary' ? crypto.randomBytes(24).toString('base64url') : null;
  if (password) session.protect(password);

  // --- 1. ask the device to produce it -------------------------------------
  let produce: string[];
  if (kind === 'binary') {
    produce = buildBackupSaveWords(base, password as string);
  } else {
    // The words are spelled for `devices.family`, so the family is checked
    // against the box first — on THIS session, before any file exists (
    // see `assertBoxSpeaksRecordedFamily`). `takeDeviceBackup` already asked
    // once; this function is exported and called on its own too.
    await assertBoxSpeaksRecordedFamily(session);
    produce = buildExportWords(target.family, base);
  }
  // The road off the router is decided BEFORE the file exists, so a box no
  // acceptable road can carry it from is refused with nothing left on it.
  const road =
    plan ?? (await planBackupPull(session, { callbackHost: options.callbackHost, receiver }));
  try {
    await session.run(produce, {
      isWrite: kind === 'binary',
      timeoutMs: options.saveTimeoutMs ?? 120_000,
      ...(password ? { secretValues: [password] } : {}),
    });
  } catch (err) {
    // A sentence that failed or timed out says nothing about the FILE: on a
    // timeout the connection cancels the tag, and the router may finish
    // writing the export or the backup anyway. So the failure path erases by
    // name like every later one, and says so when that cannot be proven. A
    // file the router completes only after this look is not caught — a
    // removal is a look at the flash, not a lock on it.
    const leftover = await eraseAfterFailure(session, fileName);
    if (leftover && err instanceof Error) err.message += leftover;
    throw err;
  }

  // --- 2. wait for it to actually exist and stop growing --------------------
  let onDevice;
  try {
    onDevice = await waitForDeviceFile(session.conn, fileName, {
      timeoutMs: options.saveTimeoutMs ?? 120_000,
      pollMs: options.filePollMs ?? 250,
    });
  } catch (err) {
    // A file that never settled may still be half-written on the router.
    const leftover = await eraseAfterFailure(session, fileName);
    if (leftover && err instanceof Error) err.message += leftover;
    throw err;
  }

  // --- 3. pull it off, over a channel we hold ------------------------------
  let pulled: PulledFile;
  try {
    pulled = await pullDeviceFile(session, road, onDevice, {
      purpose: `backup:${target.id}:${kind}`,
      maxBytes,
      timeoutMs: options.transferTimeoutMs ?? 5 * 60_000,
      receiver,
      callbackHost: options.callbackHost,
    });
  } catch (err) {
    // Leave nothing behind even on the failure path: the file exists on the
    // customer's router right now and the reason we failed is irrelevant to
    // that fact. And SAY so when the erasure cannot be proven — a failure
    // message that stays silent about a copy left on the box is how it stays
    // there.
    const leftover = await eraseAfterFailure(session, fileName);
    if (err instanceof TransferError) {
      // A pull that came back the wrong size is a backup that does not
      // verify; anything else is a transfer that did not happen.
      const integrity = err.code === 'SIZE_MISMATCH' || err.code === 'DIGEST_MISMATCH';
      throw new ChangeError(
        integrity ? 'BACKUP_UNVERIFIED' : 'BACKUP_FAILED',
        `${kind} backup transfer failed: ${err.message}${leftover}`,
        { ...err.detail, transferCode: err.code },
      );
    }
    if (leftover && err instanceof Error) err.message += leftover;
    throw err;
  }
  const received = pulled.received;

  // --- 4. prove it ---------------------------------------------------------
  // A RouterOS 7 box prints the exact byte count, and then nothing but
  // equality proves the file; the 2 % tolerance is for 6.x's rounded sizes.
  let verified;
  try {
    verified = await verifyArtefact(received, {
      minBytes: MIN_BACKUP_BYTES[kind],
      deviceReportedBytes: onDevice.sizeBytes,
      exactDeviceBytes: onDevice.sizeExact,
    });
  } catch (err) {
    const spool = await eraseSpoolFile(received.path);
    const leftover = await eraseAfterFailure(session, fileName);
    throw new ChangeError(
      'BACKUP_UNVERIFIED',
      `${kind} backup failed verification: ${err instanceof Error ? err.message : String(err)}` +
        `${leftover}${spool}`,
      err instanceof TransferError ? err.detail : {},
    );
  }

  // --- 4b. An `.rsc` carrying a secret is refused, never stored -------------
  // The words asked for no secret (`buildExportWords`) on a box whose major
  // was just checked against the family, so a hit here is a secret NO flag
  // hides — a script source, a comment — or a firmware that ignored its flag,
  // or a box that hid its version while recorded under the wrong major. The
  // text is judged HERE, on the spool, before it is moved into the backup
  // store; the spooled copy and the copy on the router, which hold the same
  // values in readable files, are erased on the way out, and the message says
  // so when either erasure cannot be proven.
  if (kind === 'rsc') {
    const props = findSensitiveProps(await fsp.readFile(verified.path, 'utf8'));
    if (props.length > 0) {
      const spool = await eraseSpoolFile(verified.path);
      const removal = await removeDeviceFile(session.conn, fileName, { attempts: 3 });
      const refusal = rscSecretRefusal(props, `the rsc backup of ${target.name}`);
      refusal.detail.onDeviceRemoved = removal.verified;
      refusal.detail.spoolRemoved = spool === '';
      if (!removal.verified) {
        refusal.message +=
          ` ${fileName}, which holds the same values, could NOT be proven deleted from the ` +
          `device (${removal.attempts} attempts): remove it by hand.`;
      }
      refusal.message += spool;
      throw refusal;
    }
  }

  // --- 5. move it into place ----------------------------------------------
  // The spool is in `os.tmpdir()` and every compose file mounts a volume at
  // `backupRoot()`, so in a container the rename crosses a filesystem and the
  // copy fallback is the NORMAL path, not a rare one. A failure anywhere in
  // this step (a full volume, a copy cut short, a hash that moved) erases what
  // it leaves behind before the error leaves: the stored file, whole or
  // partial, the spooled copy, and the blob on the router, which no backup row
  // will ever name. The message says so when an erasure cannot be proven, as
  // in step 4. Before, a full volume threw the raw I/O error and left the
  // customer configuration on the equipment AND in the spool.
  const relative = path
    .join(String(target.tenantId), String(target.id), `${base}${EXTENSION[kind]}`)
    .replace(/\\/g, '/');
  const absolute = path.join(backupRoot(), relative);
  const failStore = async (
    errKind: ChangeErrorKind,
    message: string,
    detail: Record<string, unknown>,
  ): Promise<never> => {
    let stored = '';
    try {
      await fsp.rm(absolute, { force: true });
    } catch (rmErr) {
      logger.error({ err: rmErr, storagePath: relative }, 'could not delete a failed stored backup');
      stored = ` The stored copy (${relative}, under the backup root) could NOT be deleted: remove it by hand.`;
    }
    const spool = await eraseSpoolFile(verified.path);
    const leftover = await eraseAfterFailure(session, fileName);
    throw new ChangeError(errKind, `${message}${stored}${spool}${leftover}`, detail);
  };
  let settled: { sha256: string; bytes: number };
  try {
    await fsp.mkdir(path.dirname(absolute), { recursive: true });
    await fsp.rename(verified.path, absolute).catch(async () => {
      // rename fails across devices; fall back to a copy + unlink.
      await fsp.copyFile(verified.path, absolute);
      await fsp.rm(verified.path, { force: true });
    });
    settled = await hashFile(absolute);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | null)?.code;
    return failStore(
      'BACKUP_FAILED',
      `the ${kind} backup could not be stored under the backup root` +
        `${code ? ` (${code})` : ''}: ${err instanceof Error ? err.message : String(err)}.`,
      { storagePath: relative, code: code ?? null },
    );
  }
  if (settled.sha256 !== verified.sha256 || settled.bytes !== verified.bytes) {
    return failStore('BACKUP_UNVERIFIED', 'the backup changed between spool and storage.', {
      spooled: verified.sha256,
      stored: settled.sha256,
    });
  }

  // --- 6. ERASE IT FROM THE DEVICE, and prove that too ---------------------
  // ...unless this is the blob the on-box dead-man has to load. See the long
  // note on `keepOnDeviceKinds`: the deletion is deferred, never cancelled.
  let removal = { verified: true, attempts: 0, lastError: null as string | null };
  if (!keepOnDevice) {
    removal = await removeDeviceFile(session.conn, fileName, { attempts: 3 });
    if (!removal.verified) {
      await fsp.rm(absolute, { force: true }).catch(() => undefined);
      throw new ChangeError(
        'ONDEVICE_CLEANUP_FAILED',
        `the ${kind} backup could not be proven deleted from ${target.name} ` +
          `(${removal.attempts} attempts): ${removal.lastError ?? 'unknown'} — ` +
          'refusing to leave a copy of the customer configuration on the equipment',
        { fileName, attempts: removal.attempts },
      );
    }
  }

  // --- 7. record it --------------------------------------------------------
  const classes = await retentionDays();
  const retention = options.retentionClass ?? 'standard';
  const days = classes[retention];
  const [row] = await db('device_backups')
    .insert({
      tenant_id: target.tenantId,
      device_id: target.id,
      kind,
      trigger_kind: options.trigger,
      storage_path: relative,
      size_bytes: settled.bytes,
      sha256: settled.sha256,
      encryption_password_enc: password ? encrypt(password) : null,
      retention_class: retention,
      expires_at: days === null ? null : new Date(Date.now() + days * 86_400_000),
      status: 'available',
      taken_before_job_id: options.jobId ?? null,
      os_version: target.osVersion,
      verified_at: new Date(),
      created_by: options.createdBy ?? null,
    })
    .returning('id');

  const id = typeof row === 'object' ? Number((row as any).id) : Number(row);
  logger.info(
    {
      deviceId: target.id,
      backupId: id,
      kind,
      bytes: settled.bytes,
      transferMs: received.durationMs,
      road: pulled.method,
      chunks: pulled.chunks,
      onDeviceRemoved: !keepOnDevice,
      keptOnDeviceAs: keepOnDevice ? fileName : null,
    },
    keepOnDevice
      ? 'backup taken and verified; the blob is LEFT on the equipment for the dead-man and owes a deletion'
      : 'backup taken, verified and erased from the equipment',
  );
  return {
    id,
    kind,
    storagePath: relative,
    absolutePath: absolute,
    sizeBytes: settled.bytes,
    sha256: settled.sha256,
    osVersion: target.osVersion,
    onDeviceRemoved: !keepOnDevice,
    onDeviceFileName: keepOnDevice ? fileName : null,
    removalAttempts: removal.attempts,
    transferMs: received.durationMs,
    deviceReportedBytes: onDevice.sizeBytes,
    transferMethod: pulled.method,
  };
}

/**
 * The public entry point: take the pre-change backup.
 *
 * Both kinds by default, and the BINARY one is mandatory for a preflight: it is
 * the artefact the on-box dead-man restores. A `.rsc`-only preflight would give
 * an operator something to read and the dead-man nothing to load.
 */
export async function takeDeviceBackup(options: TakeBackupOptions): Promise<BackupSet> {
  const started = Date.now();
  const kinds = options.kinds ?? ['binary', 'rsc'];
  const ownSession = !options.session;
  const session =
    options.session ??
    (await openDeviceSession(options.deviceId, {
      purpose: 'backup',
      jobId: options.jobId ?? null,
      userId: options.createdBy ?? null,
      correlationId: options.correlationId ?? null,
      dial: options.dial,
    }));
  // No receiver is started here any more: the pull roads need none, and the
  // upload road — when `judgeUploadCallback()` allows it at all — starts its
  // own for the length of one transfer if the caller did not hand one in.

  try {
    if (options.trigger === 'preflight' && !kinds.includes('binary')) {
      throw new ChangeError(
        'BACKUP_FAILED',
        'a preflight backup must include the binary kind — it is what the dead-man restores',
      );
    }
    // The `.rsc` is spelled for `devices.family`; a family the box contradicts
    // is refused HERE, before the binary blob is created, so the refusal leaves
    // nothing on the router (`takeBackupOfKind` checks again for its own
    // callers).
    if (kinds.includes('rsc')) await assertBoxSpeaksRecordedFamily(session);
    // Same principle for the road off the router: decided once for the set,
    // before the first file exists.
    const plan = await planBackupPull(session, {
      callbackHost: options.callbackHost,
      receiver: options.receiver,
    });
    const artefacts: BackupArtefact[] = [];
    try {
      for (const kind of kinds) {
        artefacts.push(await takeBackupOfKind(session, kind, options, options.receiver, plan));
      }
    } catch (err) {
      // A set that failed half-way is not a set: no dead-man will be armed on
      // it, so a blob kept on the device FOR one (`keepOnDeviceKinds`) is owed
      // its deletion now — by the code that kept it, not by a caller that may
      // never learn it exists.
      for (const kept of artefacts) {
        if (!kept.onDeviceFileName) continue;
        const leftover = await eraseAfterFailure(session, kept.onDeviceFileName);
        if (leftover && err instanceof Error) err.message += leftover;
      }
      throw err;
    }
    return {
      deviceId: options.deviceId,
      jobId: options.jobId ?? null,
      artefacts,
      binary: artefacts.find((a) => a.kind === 'binary') ?? null,
      rsc: artefacts.find((a) => a.kind === 'rsc') ?? null,
      totalMs: Date.now() - started,
    };
  } finally {
    if (ownSession) session.close();
  }
}

// ============================================================================
// Reading a backup back
// ============================================================================

export interface StoredBackupRow {
  id: number;
  tenantId: number;
  deviceId: number;
  kind: BackupKind;
  storagePath: string;
  sizeBytes: number;
  sha256: string;
  status: string;
  osVersion: string | null;
  takenAt: string;
  encryptionPasswordEnc: string | null;
}

export async function getBackup(id: number): Promise<StoredBackupRow | null> {
  const row = await db('device_backups').where({ id }).first<any>();
  if (!row) return null;
  return {
    id: row.id,
    tenantId: row.tenant_id,
    deviceId: row.device_id,
    kind: row.kind,
    storagePath: row.storage_path,
    sizeBytes: Number(row.size_bytes),
    sha256: row.sha256,
    status: row.status,
    osVersion: row.os_version ?? null,
    takenAt: row.taken_at,
    encryptionPasswordEnc: row.encryption_password_enc ?? null,
  };
}

/** The blob's password, decrypted. In memory, for the length of one restore. */
export function backupPassword(row: StoredBackupRow): string | null {
  return row.encryptionPasswordEnc ? decrypt(row.encryptionPasswordEnc) : null;
}

/**
 * Prove a stored backup is still what it claims to be.
 *
 * "A backup nobody verified is a backup nobody has." A row whose blob has gone
 * missing becomes `missing` — a distinct state from `purged`, so a lost backup
 * is an incident and an expired one is routine.
 *
 * Only two findings demote a row, and nothing ever re-promotes one: NO FILE at
 * the storage path (ENOENT / ENOTDIR) makes it `missing`, and a digest or size
 * that does not match makes it `failed`. A file that is there and could not be
 * read — a permission or owner change on the volume, an I/O error, a stale
 * mount, a directory where the file should be — is `unreadable` and the row is
 * left as it was: the fault is on this side, the backup may be intact, and a
 * demotion would drop it out of the restorable set for good. A database error
 * is not caught here either: it reaches the caller with no status written.
 */
export type StoredBackupOutcome = 'ok' | 'missing' | 'failed' | 'unreadable' | 'no_such_backup';

export async function verifyStoredBackup(
  id: number,
): Promise<{ ok: boolean; outcome: StoredBackupOutcome; reason: string; sha256?: string }> {
  const row = await getBackup(id);
  if (!row) return { ok: false, outcome: 'no_such_backup', reason: 'no such backup' };
  const absolute = path.join(backupRoot(), row.storagePath);
  let digest: { sha256: string; bytes: number };
  try {
    digest = await hashFile(absolute);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | null)?.code;
    if (code === 'ENOENT' || code === 'ENOTDIR') {
      await db('device_backups').where({ id }).update({ status: 'missing', updated_at: db.fn.now() });
      return { ok: false, outcome: 'missing', reason: 'the blob is not on disk' };
    }
    // The code only, never the message: the message carries the absolute path.
    return {
      ok: false,
      outcome: 'unreadable',
      reason: `the blob is there but could not be read (${code ?? 'no error code'}); its status is unchanged`,
    };
  }
  const { sha256, bytes } = digest;
  if (sha256 !== row.sha256 || bytes !== row.sizeBytes) {
    await db('device_backups').where({ id }).update({ status: 'failed', updated_at: db.fn.now() });
    return { ok: false, outcome: 'failed', reason: 'digest or size does not match the recorded value', sha256 };
  }
  await db('device_backups')
    .where({ id })
    .update({ verified_at: new Date(), status: 'available', updated_at: db.fn.now() });
  return { ok: true, outcome: 'ok', reason: 'digest and size match', sha256 };
}

/**
 * Read a `.rsc` backup back as text, for the diff that PROVES a rollback.
 *
 * Comment lines are stripped before the caller hashes: a RouterOS export starts
 * with `# 2026-08-29 14:02:11 by RouterOS 7.14.3`, so two exports of an
 * identical configuration never hash the same. Comparing the canonical forms is
 * the difference between "we think it restored" and "the configuration on the
 * box is byte-identical to the one we backed up".
 */
export function canonicaliseRsc(text: string): string {
  return text
    .split(/\r?\n/)
    .map((l) => l.trimEnd())
    .filter((l) => l.length > 0 && !l.startsWith('#'))
    .join('\n');
}

export function canonicalRscHash(text: string): string {
  return crypto.createHash('sha256').update(canonicaliseRsc(text), 'utf8').digest('hex');
}

export async function readRscBackup(id: number): Promise<string> {
  const row = await getBackup(id);
  if (!row) throw new ChangeError('BACKUP_FAILED', `no such backup ${id}`);
  if (row.kind !== 'rsc') throw new ChangeError('BACKUP_FAILED', `backup ${id} is not an .rsc`);
  return fsp.readFile(path.join(backupRoot(), row.storagePath), 'utf8');
}

// ============================================================================
// Retention sweep
// ============================================================================

export interface PurgeReport {
  examined: number;
  purged: number;
  missing: number;
  errors: string[];
}

/**
 * Delete expired blobs and mark their rows `purged`.
 *
 * Rows are never deleted: the fact that a backup EXISTED on a given night is
 * part of the change record, and the row is small. `legal_hold` has no
 * `expires_at` and therefore cannot be selected here at all.
 */
export async function purgeExpiredBackups(now = new Date()): Promise<PurgeReport> {
  const rows = await db('device_backups')
    .where('status', 'available')
    .whereNotNull('expires_at')
    .andWhere('expires_at', '<=', now)
    .select<any[]>('id', 'storage_path');
  const report: PurgeReport = { examined: rows.length, purged: 0, missing: 0, errors: [] };
  for (const row of rows) {
    const absolute = path.join(backupRoot(), row.storage_path);
    try {
      await fsp.rm(absolute, { force: true });
      await db('device_backups')
        .where({ id: row.id })
        .update({ status: 'purged', updated_at: db.fn.now() });
      report.purged++;
    } catch (err) {
      report.missing++;
      report.errors.push(`${row.id}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  return report;
}

// ============================================================================
// The other three brands
// ============================================================================

/**
 * DrayTek / Zyxel / SonicWall.
 *
 * There is no backup path here, and pretending otherwise would be the exact
 * Failure the safety-net rule warns about: a backup that does not exist is discovered at the
 * moment somebody needs to restore. The three brands' configuration export runs
 * over SSH/HTTPS and belongs to their drivers; until those exist,
 * this refuses by name.
 *
 * The consequence is stated where it matters — `resolveSafetyNet()` in
 * `safeApply.service.ts` cannot return `armed` for these families, because
 * `armed` means "the box restores itself from a backup" and there is no backup.
 */
export async function takeBackupNonMikrotik(family: DeviceFamily): Promise<never> {
  throw new ChangeError(
    'BRAND_UNSUPPORTED',
    `no backup path for family '${family}' (${FAMILY_BRAND[family] ?? 'unknown brand'}). ` +
      'DrayTek/Zyxel/SonicWall configuration export lands with their drivers. ' +
      'Until then a write job on these families cannot claim safety level "armed".',
    { family },
  );
}

/** True when this family has a backup path AND therefore a restorable net. */
export function familyHasBackupPath(family: DeviceFamily): boolean {
  return FAMILY_BRAND[family] === 'mikrotik';
}

/** Present a device file listing, for the operator screen that answers
 *  "did we leave anything on this router?". */
export async function listObliwanFilesOnDevice(
  session: DeviceSession,
): Promise<Array<{ name: string; sizeBytes: number }>> {
  const rows = await session.run(['/file/print'], { isWrite: false, skipAudit: true });
  return rows
    .filter((r) => (r.name ?? '').startsWith('obliwan-'))
    .map((r) => ({ name: r.name, sizeBytes: Number(r.size ?? 0) || 0 }));
}

/** Exported for the self-test: probe one file without an audit row. */
export async function peekDeviceFile(session: DeviceSession, name: string) {
  return deviceFileInfo(session.conn, name);
}

/**
 * Collect the deferred deletion owed by `keepOnDeviceKinds`.
 *
 * Called at disarm and after a dead-man fire. Returns the removal result rather
 * than throwing, because the caller has to decide: at disarm a failure is a
 * loud incident; after a rollback it is a follow-up task on a device that is,
 * at least, back up.
 */
export async function removeBackupFromDevice(
  session: DeviceSession,
  fileName: string,
): Promise<{ verified: boolean; attempts: number; lastError: string | null }> {
  const removal = await removeDeviceFile(session.conn, fileName, { attempts: 4, backoffMs: 400 });
  if (removal.verified) {
    logger.info(
      { deviceId: session.target.id, fileName },
      'dead-man backup erased from the equipment',
    );
  } else {
    logger.error(
      { deviceId: session.target.id, fileName, lastError: removal.lastError },
      'dead-man backup still present on the equipment — a copy of the customer config remains',
    );
  }
  return { verified: removal.verified, attempts: removal.attempts, lastError: removal.lastError };
}
