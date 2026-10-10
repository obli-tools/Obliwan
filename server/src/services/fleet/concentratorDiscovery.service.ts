/**
 * ObliWAN — fleet discovery from the concentrator (C4).
 *
 * The CHR is a `devices` row with `role = 'concentrator'`. It knows two things nobody
 * else does:
 *
 *   /ppp/secret   the accounts that were DECLARED — every site that is supposed
 *                 to exist, including the ones that have never dialled in.
 *   /ppp/active   the sessions that are UP right now.
 *
 * Every PPP username the platform does not already know becomes a row in
 * `discoveries`, state `pending`. That is a QUARANTINE, and it is the whole
 * point: nothing here binds a discovery to a tenant, to a site, or to a device.
 *
 * Why so strict. PPP pools reassign addresses. If discovery guessed
 * "this username at 10.66.0.11 must be customer A's router", then a pool
 * reshuffle silently turns that guess into pushing customer A's configuration
 * onto customer B's box. There is no clever heuristic that makes that safe, so
 * there is no heuristic at all: a human binds, and `discoveries.reviewed_by`
 * records who.
 *
 * The scan is idempotent. `discoveries` carries UNIQUE(concentrator_id,
 * ppp_username), so a re-scan refreshes `last_seen_at` through an UPSERT rather
 * than exploding on the second reconnect of the same secret.
 *
 * It also records the SEED the address allocator needs (services/allocation):
 * after every SUCCESSFUL /ppp/secret read, every declared secret — bound to a
 * device or not — lands in `concentrator_ppp_secrets` with the remote-address
 * and local-address the SECRET declares, and the read itself in
 * `concentrator_secret_reads`. `discoveries` cannot serve that purpose: it
 * skips usernames already bound to a device, its remote_address is the live
 * session's when one is up, and its rows are never retired. See
 * `recordSecretInventory`; `refreshSecretInventory` is the same read on its
 * own, for the allocator, which re-reads a CHR whose last read is too old.
 */

import { MASTER_TENANT_ID, SOCKET_EVENTS } from '@obliwan/shared';
import type { Knex } from 'knex';
import { db } from '../../db';
import { AppError } from '../../middleware/errorHandler';
import { logger } from '../../utils/logger';
import { getRouterOsPool, resolveRouterOsTarget } from './routerosPool';
import { redactSentence } from '../transport/routeros/protocol';
import { emitToTenantAdmins } from './fleetEvents';
import { takeAllocationLock } from '../allocation/lock';

// ============================================================================
// What the CHR tells us
// ============================================================================

/** One row of `/ppp/active`. Field names are RouterOS's, normalised to camel. */
export interface PppActiveEntry {
  /** RouterOS internal `.id` (`*1`). Volatile across reboots — used ONLY to
   *  correlate a `listen` event with the session it refers to, never stored as
   *  an identity. */
  routerId: string | null;
  name: string;
  service: string | null;
  /** Tunnel address handed to the peer. "Where to dial today". */
  address: string | null;
  /** Peer's public address as the CHR sees it. */
  callerId: string | null;
  uptime: string | null;
  raw: Record<string, string>;
}

/** One row of `/ppp/secret`. */
export interface PppSecretEntry {
  routerId: string | null;
  name: string;
  service: string | null;
  profile: string | null;
  remoteAddress: string | null;
  /** The CHR's own end of the tunnel, when the secret declares one. Optional
   *  because entries built before this field existed do not carry it; absent
   *  and null both mean "not declared". */
  localAddress?: string | null;
  comment: string | null;
  disabled: boolean;
  raw: Record<string, string>;
}

/** RouterOS booleans are the strings `true` / `false` / `yes` / `no`. */
function rosBool(value: string | undefined): boolean {
  return value === 'true' || value === 'yes';
}

function orNull(value: string | undefined): string | null {
  const v = value?.trim();
  return v ? v : null;
}

/**
 * `inet` columns reject anything that is not an address, and a malformed
 * `caller-id` (RouterOS puts a MAC there for PPPoE, and a hostname for some
 * L2TP clients) would abort the whole scan on one bad row. Anything that is not
 * plainly an IPv4/IPv6 literal is dropped to NULL and kept in `raw`, where it
 * remains visible to the operator.
 */
export function asInetOrNull(value: string | null | undefined): string | null {
  if (!value) return null;
  const v = value.trim().split('%')[0];
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) {
    return v.split('.').every((o) => Number(o) <= 255) ? v : null;
  }
  // A MAC address is colon-separated hex too, and RouterOS puts one in
  // `caller-id` for PPPoE. Six groups of exactly two hex digits is a MAC, not
  // an IPv6 address — refuse it before the loose check below lets it through.
  if (/^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$/.test(v)) return null;
  // Deliberately loose on IPv6 beyond that: Postgres is the real validator, and
  // all this needs to do is keep the obvious non-addresses out of an `inet`
  // column so one odd row cannot abort a whole discovery scan.
  if (/^[0-9a-fA-F:]+$/.test(v) && v.includes(':')) return v;
  return null;
}

export function parseActiveRow(row: Record<string, string>): PppActiveEntry | null {
  const name = orNull(row.name);
  if (!name) return null;
  return {
    routerId: orNull(row['.id']),
    name,
    service: orNull(row.service),
    address: orNull(row.address),
    callerId: orNull(row['caller-id']),
    uptime: orNull(row.uptime),
    raw: row,
  };
}

export function parseSecretRow(row: Record<string, string>): PppSecretEntry | null {
  const name = orNull(row.name);
  if (!name) return null;
  return {
    routerId: orNull(row['.id']),
    name,
    service: orNull(row.service),
    profile: orNull(row.profile),
    remoteAddress: orNull(row['remote-address']),
    localAddress: orNull(row['local-address']),
    comment: orNull(row.comment),
    disabled: rosBool(row.disabled),
    raw: row,
  };
}

// ============================================================================
// Reading the concentrator
// ============================================================================

export interface ConcentratorRow {
  id: number;
  tenant_id: number;
  name: string;
  role: string;
  status: string;
}

/** Load a device and refuse it if it is not a concentrator. */
export async function requireConcentrator(concentratorId: number): Promise<ConcentratorRow> {
  const row = await db('devices')
    .where({ id: concentratorId })
    .first<ConcentratorRow | undefined>('id', 'tenant_id', 'name', 'role', 'status');
  if (!row) throw new Error(`Device ${concentratorId} does not exist`);
  if (row.role !== 'concentrator') {
    throw new Error(`Device ${concentratorId} is not a concentrator (role=${row.role})`);
  }
  return row;
}

/** `/ppp/active/print` on the concentrator, through the shared pool socket. */
export async function readPppActive(concentratorId: number): Promise<PppActiveEntry[]> {
  const target = await resolveRouterOsTarget(concentratorId);
  const rows = await getRouterOsPool().withConnection(target, (conn) =>
    conn.query(['/ppp/active/print']),
  );
  return rows.map(parseActiveRow).filter((e): e is PppActiveEntry => e !== null);
}

/** `/ppp/secret/print` — the declared accounts, present or not. */
export async function readPppSecrets(concentratorId: number): Promise<PppSecretEntry[]> {
  const target = await resolveRouterOsTarget(concentratorId);
  const rows = await getRouterOsPool().withConnection(target, (conn) =>
    // No secrets: the `.proplist` ALLOW-LIST is what keeps `password` off the wire.
    // RouterOS returns only the properties named there, so the L2TP credential
    // of every site is never sent — whatever the firmware's default, and
    // whatever policy the account holds (this comment used to state that the
    // ObliWAN account on the concentrator holds `sensitive`; nothing in this
    // repo checks it either way). An allow-list also cannot leak a field a
    // future RouterOS version decides to add. Discovery needs identity and
    // routing, not credentials.
    //
    // There is deliberately NO `show-sensitive` word. It used to send
    // `=show-sensitive=no`, mirroring `/export` in collect.service and
    // backup.service, and those dropped it: `show-sensitive` is a bare FLAG on
    // RouterOS 7 (a real router refused a value on it) and does not exist on
    // RouterOS 6. What the API does with a value on that flag is unobserved;
    // two plausible readings are "trap" and "flag present" — the request that
    // REVEALS sensitive values — and the proplist makes the no-secrets rule independent of
    // which one a given firmware picks.
    conn.query([
      '/ppp/secret/print',
      '=.proplist=.id,name,service,profile,remote-address,local-address,comment,disabled',
    ]),
  );
  return rows.map(parseSecretRow).filter((e): e is PppSecretEntry => e !== null);
}

// ============================================================================
// The allocator's seed — what each CHR declares
// ============================================================================

export interface SecretInventoryRow {
  name: string;
  /** As DECLARED by the secret — never the live session's address. */
  remoteAddress: string | null;
  localAddress: string | null;
  profile: string | null;
  disabled: boolean;
}

export interface SecretInventoryResult {
  /** Secrets written (inserted or refreshed). */
  recorded: number;
  /** Secrets a previous read had and this one did not. */
  vanished: number;
  /** Secrets dropped because an earlier one of the same read had their name. */
  duplicateNames: number;
}

/**
 * One row per secret NAME, as the inventory table keys it. Pure.
 *
 * RouterOS is assumed to keep secret names unique per CHR — `discoveries`
 * makes the same assumption with UNIQUE(concentrator_id, ppp_username). A read
 * that breaks it keeps the FIRST secret of each name and counts the others in
 * `duplicateNames`; their addresses are then not recorded, and the scan logs
 * a warning saying so.
 *
 * Addresses go through `asInetOrNull`, the same filter the quarantine uses, so
 * a malformed value cannot abort the write of the whole inventory.
 */
export function secretInventoryRows(secrets: PppSecretEntry[]): {
  rows: SecretInventoryRow[];
  duplicateNames: number;
} {
  const seen = new Set<string>();
  const rows: SecretInventoryRow[] = [];
  let duplicateNames = 0;
  for (const s of secrets) {
    if (seen.has(s.name)) {
      duplicateNames += 1;
      continue;
    }
    seen.add(s.name);
    rows.push({
      name: s.name,
      remoteAddress: asInetOrNull(s.remoteAddress),
      localAddress: asInetOrNull(s.localAddress ?? null),
      profile: s.profile,
      disabled: s.disabled,
    });
  }
  return { rows, duplicateNames };
}

/** Rows per INSERT statement: well under PostgreSQL's 65535 bind parameters. */
const INVENTORY_BATCH = 500;

/**
 * Replace what the allocator knows about one CHR's declared secrets with the
 * read that just succeeded, and stamp the read. ONE transaction, under the
 * allocation lock (services/allocation/lock.ts): an allocation then sees this
 * read entirely or not at all. Nothing here dials the router — the read is
 * already done — so the lock is never held across a network round trip.
 *
 * Secrets absent from this read are stamped `vanished_at` and stop counting as
 * held; they are never deleted, so their history stays readable. A secret that
 * reappears is un-vanished by the upsert.
 */
export async function recordSecretInventory(
  concentratorId: number,
  secrets: PppSecretEntry[],
  now: Date,
): Promise<SecretInventoryResult> {
  const { rows, duplicateNames } = secretInventoryRows(secrets);
  if (duplicateNames > 0) {
    logger.warn(
      { concentratorId, duplicateNames },
      '/ppp/secret returned several secrets with the same name; only the first of each is recorded',
    );
  }
  const vanished = await db.transaction(async (trx) => {
    await takeAllocationLock(trx);
    for (let i = 0; i < rows.length; i += INVENTORY_BATCH) {
      const batch = rows.slice(i, i + INVENTORY_BATCH).map((r) => ({
        concentrator_id: concentratorId,
        name: r.name,
        remote_address: r.remoteAddress,
        local_address: r.localAddress,
        profile: r.profile,
        disabled: r.disabled,
        first_seen_at: now,
        last_seen_at: now,
        vanished_at: null,
      }));
      await trx('concentrator_ppp_secrets')
        .insert(batch)
        .onConflict(['concentrator_id', 'name'])
        // A column list merges the incoming row's values; first_seen_at is kept.
        .merge(['remote_address', 'local_address', 'profile', 'disabled', 'last_seen_at', 'vanished_at']);
    }
    // Every secret of this read now carries last_seen_at = now exactly.
    const gone = await trx('concentrator_ppp_secrets')
      .where({ concentrator_id: concentratorId })
      .whereNull('vanished_at')
      .where('last_seen_at', '<', now)
      .update({ vanished_at: now });
    await trx('concentrator_secret_reads')
      .insert({ concentrator_id: concentratorId, read_at: now, secret_count: rows.length })
      .onConflict('concentrator_id')
      .merge(['read_at', 'secret_count']);
    return gone;
  });
  return { recorded: rows.length, vanished, duplicateNames };
}

/**
 * ONE change ObliWAN itself just made to a CHR's secrets (the `site_rename`
 * job: a secret copied under the new name, the old one removed or renamed),
 * recorded in the stored inventory without re-reading the whole CHR — so a
 * later case-variant check (concentratorSecret.service `readSecrets`) sees
 * the dead name gone and the new one held. In the CALLER's transaction; the
 * allocation lock is taken here (reentrant within it). Nothing dials.
 */
export async function recordSecretInventoryChange(
  trx: Knex.Transaction,
  concentratorId: number,
  change: { added?: SecretInventoryRow; removedName?: string },
  now: Date,
): Promise<void> {
  await takeAllocationLock(trx);
  if (change.added) {
    await trx('concentrator_ppp_secrets')
      .insert({
        concentrator_id: concentratorId,
        name: change.added.name,
        remote_address: asInetOrNull(change.added.remoteAddress),
        local_address: asInetOrNull(change.added.localAddress),
        profile: change.added.profile,
        disabled: change.added.disabled,
        first_seen_at: now,
        last_seen_at: now,
        vanished_at: null,
      })
      .onConflict(['concentrator_id', 'name'])
      .merge(['remote_address', 'local_address', 'profile', 'disabled', 'last_seen_at', 'vanished_at']);
  }
  if (change.removedName) {
    await trx('concentrator_ppp_secrets')
      .where({ concentrator_id: concentratorId, name: change.removedName })
      .whereNull('vanished_at')
      .update({ vanished_at: now });
  }
}

/**
 * Re-read one CHR's /ppp/secret and record it as the allocator's seed — the
 * secret half of a discovery scan, without the quarantine. READ-ONLY towards
 * the router (one `/ppp/secret/print` with the `.proplist` allow-list, the same
 * query as the scan). For the allocator, which calls it when a gating CHR's
 * last read is older than its bound, BEFORE opening its own transaction: the
 * dial happens with no lock held, and `recordSecretInventory` takes the lock
 * only for its write.
 *
 * Throws when the device is not a concentrator or the read fails; nothing is
 * recorded then, so a failed read can never mark a secret vanished.
 */
export async function refreshSecretInventory(concentratorId: number): Promise<SecretInventoryResult> {
  await requireConcentrator(concentratorId);
  const secrets = await readPppSecrets(concentratorId);
  return recordSecretInventory(concentratorId, secrets, new Date());
}

// ============================================================================
// The scan
// ============================================================================

export interface DiscoveryScanResult {
  concentratorId: number;
  /** Accounts declared on the CHR. */
  secrets: number;
  /** Sessions up at scan time. */
  active: number;
  /** Usernames already bound to a `devices` row: skipped entirely. */
  known: number;
  /** New quarantine rows. */
  created: number;
  /** Existing quarantine rows whose `last_seen_at` / details were refreshed. */
  refreshed: number;
  /** The usernames that landed in quarantine on THIS scan. */
  newUsernames: string[];
  /** The allocator's seed, recorded from this scan's /ppp/secret read; null
   *  when that read failed and nothing was recorded. */
  secretInventory: SecretInventoryResult | null;
  scannedAt: string;
}

interface Candidate {
  username: string;
  remoteAddress: string | null;
  callerIp: string | null;
  profile: string | null;
  comment: string | null;
  online: boolean;
  raw: Record<string, unknown>;
}

/**
 * Merge `/ppp/secret` and `/ppp/active` into one candidate per username.
 *
 * Pure, so the merge rules are testable without a router. The active session
 * wins on addressing (it is what is true right now); the secret wins on profile
 * and comment (that is where an operator writes the site name).
 */
export function mergeCandidates(
  secrets: PppSecretEntry[],
  active: PppActiveEntry[],
): Candidate[] {
  const byName = new Map<string, Candidate>();

  for (const s of secrets) {
    byName.set(s.name, {
      username: s.name,
      remoteAddress: asInetOrNull(s.remoteAddress),
      callerIp: null,
      profile: s.profile,
      comment: s.comment,
      online: false,
      raw: { secret: redactSentence(s.raw) },
    });
  }

  for (const a of active) {
    const existing = byName.get(a.name);
    if (existing) {
      existing.online = true;
      existing.remoteAddress = asInetOrNull(a.address) ?? existing.remoteAddress;
      existing.callerIp = asInetOrNull(a.callerId);
      existing.raw = { ...existing.raw, active: a.raw };
      continue;
    }
    // A session with no declared secret: RADIUS, or a secret removed while the
    // session stayed up. It is still a device on the fleet, so it is still a
    // discovery — that is exactly what quarantine is for.
    byName.set(a.name, {
      username: a.name,
      remoteAddress: asInetOrNull(a.address),
      callerIp: asInetOrNull(a.callerId),
      profile: null,
      comment: null,
      online: true,
      raw: { active: redactSentence(a.raw), note: 'active session with no /ppp/secret entry' },
    });
  }

  return Array.from(byName.values());
}

/**
 * Full discovery pass. Safe to run repeatedly and safe to run concurrently with
 * presence reconciliation: every write is an UPSERT on the unique key.
 */
export async function runChrDiscovery(concentratorId: number): Promise<DiscoveryScanResult> {
  const chr = await requireConcentrator(concentratorId);

  let secretsRead = true;
  const [secrets, active] = await Promise.all([
    readPppSecrets(concentratorId).catch((err) => {
      // A CHR whose /ppp/secret is not readable (permissions) still gives us
      // the live sessions, which is the more valuable half. Degrade, do not
      // abort: an empty inventory would look like "no sites". The empty list
      // is NOT recorded as the CHR's secret inventory — see below.
      secretsRead = false;
      logger.warn({ err, concentratorId }, '/ppp/secret unreadable; scanning active sessions only');
      return [] as PppSecretEntry[];
    }),
    readPppActive(concentratorId),
  ]);

  // Only a read that succeeded may say what the CHR declares: recording the
  // degraded empty list would mark every secret vanished and free its address
  // for the allocator.
  const secretInventory = secretsRead
    ? await recordSecretInventory(concentratorId, secrets, new Date())
    : null;

  const candidates = mergeCandidates(secrets, active);

  // Usernames already attached to a device are not discoveries any more. The
  // lookup is global, not tenant-scoped: `devices.ppp_username` is UNIQUE
  // fleet-wide precisely so presence can never be ambiguous.
  const usernames = candidates.map((c) => c.username);
  const bound = usernames.length
    ? await db('devices').whereIn('ppp_username', usernames).pluck<string[]>('ppp_username')
    : [];
  const boundSet = new Set(bound);

  // Which quarantine rows already exist. Read up-front rather than inferred
  // from the UPSERT's return value: "did this INSERT actually insert" is not
  // something `ON CONFLICT ... RETURNING` answers portably, and a wrong answer
  // here would re-announce every known site as a new discovery on every scan.
  const existing = new Set(
    await db('discoveries')
      .where({ concentrator_id: concentratorId })
      .pluck<string[]>('ppp_username'),
  );

  const now = new Date();
  let created = 0;
  let refreshed = 0;
  const newUsernames: string[] = [];

  for (const c of candidates) {
    if (boundSet.has(c.username)) continue;
    const isNew = !existing.has(c.username);

    // `state` is deliberately absent from the merge list: a row an operator
    // moved to `ignored` must stay ignored, and one moved to `bound` must not
    // be dragged back to `pending` by the next scan.
    const inserted = await db('discoveries')
      .insert({
        concentrator_id: concentratorId,
        ppp_username: c.username,
        remote_address: c.remoteAddress,
        caller_ip: c.callerIp,
        profile: c.profile,
        ppp_comment: c.comment,
        raw: JSON.stringify(c.raw),
        state: 'pending',
        first_seen_at: now,
        last_seen_at: now,
      })
      .onConflict(['concentrator_id', 'ppp_username'])
      .merge({
        remote_address: c.remoteAddress,
        caller_ip: c.callerIp,
        profile: c.profile,
        ppp_comment: c.comment,
        raw: JSON.stringify(c.raw),
        last_seen_at: now,
        updated_at: now,
      })
      .returning<Array<{ id: number; state: string }>>(['id', 'state']);

    const row = inserted[0];
    if (isNew && row) {
      created++;
      newUsernames.push(c.username);
      emitToTenantAdmins(chr.tenant_id, SOCKET_EVENTS.DISCOVERY_NEW, {
        id: row.id,
        concentratorId,
        concentratorName: chr.name,
        pppUsername: c.username,
        remoteAddress: c.remoteAddress,
        callerIp: c.callerIp,
        profile: c.profile,
        online: c.online,
        state: row.state,
        at: now.toISOString(),
      });
    } else {
      refreshed++;
    }
  }

  const result: DiscoveryScanResult = {
    concentratorId,
    secrets: secrets.length,
    active: active.length,
    known: candidates.filter((c) => boundSet.has(c.username)).length,
    created,
    refreshed,
    newUsernames,
    secretInventory,
    scannedAt: now.toISOString(),
  };

  logger.info(result, 'CHR discovery scan complete');
  return result;
}

// ============================================================================
// Quarantine review — the human gesture
// ============================================================================

export interface DiscoveryRow {
  id: number;
  uuid: string;
  concentrator_id: number;
  ppp_username: string;
  remote_address: string | null;
  caller_ip: string | null;
  profile: string | null;
  ppp_comment: string | null;
  raw: Record<string, unknown>;
  state: string;
  bound_device_id: number | null;
  reviewed_by: number | null;
  reviewed_at: Date | null;
  first_seen_at: Date;
  last_seen_at: Date;
}

export interface ListDiscoveriesFilter {
  /** Concentrators visible to the caller's tenant. Always supplied by the
   *  controller — `discoveries` has no tenant column of its own. */
  concentratorIds: number[];
  state?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export async function listDiscoveries(
  filter: ListDiscoveriesFilter,
): Promise<{
  items: Array<DiscoveryRow & { concentrator_name: string; concentrator_tenant_id?: number; bound_tenant_id?: number | null }>;
  total: number;
}> {
  if (filter.concentratorIds.length === 0) return { items: [], total: 0 };

  const base = db('discoveries as d')
    .join('devices as c', 'c.id', 'd.concentrator_id')
    .whereIn('d.concentrator_id', filter.concentratorIds);

  if (filter.state) base.andWhere('d.state', filter.state);
  if (filter.search) {
    const like = `%${filter.search}%`;
    base.andWhere((q) => {
      q.whereILike('d.ppp_username', like).orWhereILike('d.ppp_comment', like);
    });
  }

  const [{ count }] = await base.clone().clearSelect().count<{ count: string }[]>('d.id as count');
  const items = await base
    .clone()
    // The two tenants a discovery relates to, for a god-view list's tenant
    // column: the bound device's (whose site it is, once a human said so),
    // else the concentrator's.
    .leftJoin('devices as bd', 'bd.id', 'd.bound_device_id')
    .select('d.*', 'c.name as concentrator_name', 'c.tenant_id as concentrator_tenant_id', 'bd.tenant_id as bound_tenant_id')
    .orderBy('d.last_seen_at', 'desc')
    .limit(filter.limit ?? 100)
    .offset(filter.offset ?? 0);

  return { items, total: Number(count) };
}

export async function getDiscovery(id: number): Promise<DiscoveryRow | undefined> {
  return db('discoveries').where({ id }).first<DiscoveryRow | undefined>();
}

// ============================================================================
// Who may bind a discovery — and who may review one
// ============================================================================

/**
 * Binding a discovery CLAIMS a PPP session for a device: it writes the
 * (concentrator, username) pair onto the device, with the session's tunnel
 * address and public WAN address, and files the session history the CHR
 * recorded before the binding under that device. The question is therefore the
 * one `decidePppClaim` (fleet/device.service.ts) asks of a device write — whose
 * session is this? — and the answer is the same.
 *
 * ┌─ THE MASTER TENANT DOES NOT OWN THE SESSIONS ON ITS SHARED CHR ──────────┐
 * │ The review screen scopes discoveries through their concentrator          │
 * │ (`concentratorIdsForTenant`), and the operator's shared CHR is a row of  │
 * │ the MASTER tenant. Every member of tenant 1 therefore sees every         │
 * │ customer's dialled site in that list — `requireTenant` parks every "for  │
 * │ now" account there, and that membership grants nothing beyond the        │
 * │ master tenant's own rows. With DEVICE_DISCOVER + DEVICE_WRITE alone such │
 * │ a member could bind any of those sessions to a tenant-1 device: tenant   │
 * │ A's tunnel address, public address and session history, filed under a    │
 * │ row A cannot see, and A's site taken out of the review queue.            │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * THE RULE.
 *  - A discovery on a concentrator of a NON-master tenant T is T's: every
 *    session on that box is T's by construction. It binds to a device of T and
 *    of no other tenant, whoever asks — a platform administrator included,
 *    because here the session's owner is KNOWN, and any other tenant is wrong.
 *  - A discovery on a concentrator of the MASTER tenant — shared
 *    infrastructure — is bound by a platform administrator (`users.role =
 *    'admin'`, active) or not at all. Nothing in the session says whose site it
 *    is: usernames follow a pattern, and `site_provisioning` (migration 036) is
 *    not consulted, for the reason `decidePppClaim` gives. The only party who
 *    can say is the operator who created the account in the CHR's
 *    `/ppp/secret`.
 *  - A concentrator found in no tenant fails CLOSED.
 *
 * The refusal is a 403, not the 404 an invisible discovery gets: the caller can
 * already see this row in the list, so the status tells them nothing new.
 *
 * WHY THE REVIEWER'S ROW, NOT A FLAG THE CALLER PASSES. `reviewed_by` is the
 * audit record of who bound the session; the authority checked is that same
 * person's, read from `users` inside the binding's own transaction. A flag
 * could disagree with the row it stamps, and a caller that forgot it would
 * write as somebody it is not.
 *
 * Why the shared CHR's discoveries stay VISIBLE to tenant 1: platform
 * administrators review them from the master tenant, through that same list.
 * The read is unchanged; the gestures are gated — binding here, and the review
 * queue's other gesture, `ignored` / back to `pending`, by
 * `decideDiscoveryReview` below.
 */
export type DiscoveryBindVerdict =
  | { allow: true; reason: 'own_concentrator' | 'platform_admin' }
  | { allow: false; reason: 'shared_concentrator' | 'foreign_device' | 'unknown_concentrator' };

/** The rule above, with its two reads passed in, so it can be exercised
 *  without a database (fleet/testing/pppClaim.verify.ts). */
export function decideDiscoveryBind(input: {
  /** Tenant of the discovery's concentrator; null when no row was found. */
  concentratorTenantId: number | null;
  /** Tenant of the device the session would be bound to. */
  deviceTenantId: number;
  /** The reviewer is an ACTIVE user with `users.role = 'admin'`. */
  platformAdmin: boolean;
}): DiscoveryBindVerdict {
  const owner = input.concentratorTenantId;
  if (owner === null) return { allow: false, reason: 'unknown_concentrator' };
  if (owner !== MASTER_TENANT_ID) {
    return owner === input.deviceTenantId
      ? { allow: true, reason: 'own_concentrator' }
      : { allow: false, reason: 'foreign_device' };
  }
  return input.platformAdmin
    ? { allow: true, reason: 'platform_admin' }
    : { allow: false, reason: 'shared_concentrator' };
}

/** The two reads both rules need: the tenant of the discovery's concentrator,
 *  and whether the reviewer's OWN `users` row is an active platform
 *  administrator. On `conn`, so a caller holding a transaction judges inside
 *  it. */
async function readDiscoveryAuthority(
  conn: Knex | Knex.Transaction,
  concentratorId: number,
  reviewedBy: number,
): Promise<{ concentratorTenantId: number | null; platformAdmin: boolean }> {
  const concentrator = await conn('devices')
    .where({ id: concentratorId })
    .first<{ tenant_id: number } | undefined>('tenant_id');
  const reviewer = await conn('users')
    .where({ id: reviewedBy })
    .first<{ role: string; is_active: boolean } | undefined>('role', 'is_active');
  return {
    concentratorTenantId: concentrator ? Number(concentrator.tenant_id) : null,
    platformAdmin: reviewer?.role === 'admin' && reviewer.is_active === true,
  };
}

/**
 * `decideDiscoveryBind` against the database, refusing with a 403.
 *
 * The HTTP path runs it twice: the controller calls it BEFORE it resolves or
 * creates the target device, so a bind refused by this rule leaves no orphan
 * `pending` device behind; `bindDiscovery` calls it again inside its
 * transaction, against the tenant of the device actually being bound, and that
 * call is the one that decides. Both read the same reviewer row.
 */
export async function assertDiscoveryBindAllowed(
  input: { concentratorId: number; deviceTenantId: number; reviewedBy: number },
  conn: Knex | Knex.Transaction = db,
): Promise<void> {
  const facts = await readDiscoveryAuthority(conn, input.concentratorId, input.reviewedBy);
  const verdict = decideDiscoveryBind({ ...facts, deviceTenantId: input.deviceTenantId });
  if (verdict.allow) return;

  if (verdict.reason === 'shared_concentrator') {
    throw new AppError(
      403,
      `Concentrator ${input.concentratorId} is shared infrastructure: a PPP session on it ` +
        'belongs to whichever customer the operator created the account for, and nothing in ' +
        'the session says which. Only a platform administrator can bind it to a device.',
    );
  }
  if (verdict.reason === 'foreign_device') {
    throw new AppError(
      403,
      'The device and the concentrator this session was seen on belong to different tenants. ' +
        "A session on a customer's own concentrator can only be bound to one of that customer's devices.",
    );
  }
  throw new AppError(
    403,
    'The concentrator this session was seen on could not be found, so nobody can say whose ' +
      'session it is. Nothing was bound.',
  );
}

/**
 * The review queue's other gesture — `ignored` ("not ours"), or back to
 * `pending` — takes the same authority as binding, for the same reason: it is
 * a decision about whose site this is.
 *
 * `ignored` takes a site out of the queue for good. `runChrDiscovery` leaves
 * `state` out of its merge on purpose, so no later scan brings the row back,
 * and the site stays unbound — no device, no presence, no polling — until
 * somebody goes looking for it. `pending` overwrites the `reviewed_by` of
 * whoever ignored it. On the shared CHR both decide about another customer's
 * site, which a plain member of the master tenant may SEE but not decide: the
 * same member who cannot bind that session must not be able to bury it.
 *
 * THE RULE — `decideDiscoveryBind`'s, with the acting tenant in place of the
 * device's, since this gesture names no device:
 *  - a NON-master tenant's concentrator: the acting tenant must be its owner
 *    (the review screen already answers 404 to anybody else; the service holds
 *    the rule too, so a second caller cannot forget it);
 *  - a MASTER-tenant concentrator: a platform administrator, from the
 *    reviewer's own `users` row, or nobody;
 *  - a concentrator found in no tenant fails CLOSED.
 */
export type DiscoveryReviewVerdict =
  | { allow: true; reason: 'own_concentrator' | 'platform_admin' }
  | { allow: false; reason: 'shared_concentrator' | 'foreign_tenant' | 'unknown_concentrator' };

/** The rule above, with its reads passed in (fleet/testing/pppClaim.verify.ts). */
export function decideDiscoveryReview(input: {
  /** Tenant of the discovery's concentrator; null when no row was found. */
  concentratorTenantId: number | null;
  /** The tenant the reviewer acts in — the request's tenant. */
  actingTenantId: number;
  /** The reviewer is an ACTIVE user with `users.role = 'admin'`. */
  platformAdmin: boolean;
}): DiscoveryReviewVerdict {
  const owner = input.concentratorTenantId;
  if (owner === null) return { allow: false, reason: 'unknown_concentrator' };
  if (owner !== MASTER_TENANT_ID) {
    return owner === input.actingTenantId
      ? { allow: true, reason: 'own_concentrator' }
      : { allow: false, reason: 'foreign_tenant' };
  }
  return input.platformAdmin
    ? { allow: true, reason: 'platform_admin' }
    : { allow: false, reason: 'shared_concentrator' };
}

/** `decideDiscoveryReview` against the database, refusing with a 403. */
export async function assertDiscoveryReviewAllowed(
  input: { concentratorId: number; actingTenantId: number; reviewedBy: number },
  conn: Knex | Knex.Transaction = db,
): Promise<void> {
  const facts = await readDiscoveryAuthority(conn, input.concentratorId, input.reviewedBy);
  const verdict = decideDiscoveryReview({ ...facts, actingTenantId: input.actingTenantId });
  if (verdict.allow) return;

  if (verdict.reason === 'shared_concentrator') {
    throw new AppError(
      403,
      `Concentrator ${input.concentratorId} is shared infrastructure: a PPP session on it ` +
        'belongs to whichever customer the operator created the account for, and nothing in ' +
        'the session says which. Only a platform administrator can ignore it or return it to review.',
    );
  }
  if (verdict.reason === 'foreign_tenant') {
    throw new AppError(
      403,
      "This session was seen on another tenant's concentrator. Only that tenant can ignore it " +
        'or return it to review.',
    );
  }
  throw new AppError(
    403,
    'The concentrator this session was seen on could not be found, so nobody can say whose ' +
      'session it is. Its review state was not changed.',
  );
}

/**
 * Bind a quarantined username to an existing device.
 *
 * What makes this safe:
 *  - WHO may bind is decided here, inside the transaction, from the reviewer's
 *    own `users` row and the tenant of the device being bound ("Who may bind a
 *    discovery", above) — not left to the caller;
 *  - `devices.ppp_username` is UNIQUE fleet-wide, so binding the same username
 *    to a second device is refused by Postgres, not by an `if`;
 *  - `discoveries.state='bound'` without `bound_device_id` is refused by a
 *    CHECK constraint, so there is no half-finished binding to trip over.
 */
export async function bindDiscovery(
  discoveryId: number,
  deviceId: number,
  reviewedBy: number,
): Promise<DiscoveryRow> {
  return db.transaction(async (trx) => {
    const discovery = await trx('discoveries')
      .where({ id: discoveryId })
      .forUpdate()
      .first<DiscoveryRow | undefined>();
    if (!discovery) throw new Error(`Discovery ${discoveryId} does not exist`);

    const device = await trx('devices')
      .where({ id: deviceId })
      .first<
        | { id: number; tenant_id: number; ppp_username: string | null; concentrator_id: number | null }
        | undefined
      >('id', 'tenant_id', 'ppp_username', 'concentrator_id');
    if (!device) throw new Error(`Device ${deviceId} does not exist`);

    // Before anything that answers about the binding itself.
    await assertDiscoveryBindAllowed(
      {
        concentratorId: discovery.concentrator_id,
        deviceTenantId: Number(device.tenant_id),
        reviewedBy,
      },
      trx,
    );

    if (discovery.state === 'bound') {
      throw new Error(`Discovery ${discoveryId} is already bound to device ${discovery.bound_device_id}`);
    }
    if (device.ppp_username && device.ppp_username !== discovery.ppp_username) {
      throw new Error(
        `Device ${deviceId} is already bound to PPP user '${device.ppp_username}'`,
      );
    }

    await trx('devices').where({ id: deviceId }).update({
      ppp_username: discovery.ppp_username,
      concentrator_id: discovery.concentrator_id,
      // The tunnel address is recorded because the arbiter needs somewhere to
      // dial. It is NOT an identity, and `assertTargetBinding()` re-proves the
      // identity on a fresh connection before anything is written.
      tunnel_ip: discovery.remote_address,
      wan_public_ip: discovery.caller_ip,
      first_seen_at: trx.raw('COALESCE(first_seen_at, ?)', [discovery.first_seen_at]),
      updated_at: trx.fn.now(),
    });

    // Adopt any session history the CHR observed before the binding existed.
    await trx('ppp_sessions')
      .where({
        concentrator_id: discovery.concentrator_id,
        ppp_username: discovery.ppp_username,
      })
      .whereNull('device_id')
      .update({ device_id: deviceId });

    const [updated] = await trx('discoveries')
      .where({ id: discoveryId })
      .update({
        state: 'bound',
        bound_device_id: deviceId,
        reviewed_by: reviewedBy,
        reviewed_at: trx.fn.now(),
        updated_at: trx.fn.now(),
      })
      .returning<DiscoveryRow[]>('*');

    return updated;
  });
}

/**
 * Mark a discovery as deliberately not ours (a test account, another MSP), or
 * push it back into the review queue.
 *
 * A `bound` row is refused: clearing `bound_device_id` while the device keeps
 * `ppp_username` is exactly how the two halves of an identity drift apart, and
 * a drifted identity is exactly what the identity-binding check forbids. Unbinding is a device-level gesture (clear
 * `ppp_username` on the device), not a discovery-level one.
 *
 * WHO may do it is decided here, inside the transaction, from the reviewer's
 * own `users` row and the tenant the review is made in
 * (`decideDiscoveryReview`, above) — the same shape as `bindDiscovery`.
 */
export async function setDiscoveryState(
  discoveryId: number,
  state: 'pending' | 'ignored',
  review: { reviewedBy: number; actingTenantId: number },
): Promise<DiscoveryRow> {
  const row = await db.transaction(async (trx): Promise<DiscoveryRow> => {
    // Locked, like `bindDiscovery` locks it: the authority, the `bound`
    // refusal and the write all judge ONE state of the row. Unlocked, a bind
    // committing between the read and the write would be overwritten to
    // `ignored` while its device keeps the pair — a state the CHECK allows
    // (`bound_device_id` stays set), and exactly the re-stating of a bound
    // row that the refusal below exists to prevent.
    const current = await trx('discoveries')
      .where({ id: discoveryId })
      .forUpdate()
      .first<DiscoveryRow | undefined>();
    if (!current) throw new Error(`Discovery ${discoveryId} does not exist`);

    // Before anything that answers about the row itself (its bound device).
    await assertDiscoveryReviewAllowed(
      {
        concentratorId: current.concentrator_id,
        actingTenantId: review.actingTenantId,
        reviewedBy: review.reviewedBy,
      },
      trx,
    );

    if (current.state === 'bound') {
      throw new Error(
        `Discovery ${discoveryId} is bound to device ${current.bound_device_id}; ` +
          'clear the device PPP username first',
      );
    }

    const [updated] = await trx('discoveries')
      .where({ id: discoveryId })
      .update({
        state,
        reviewed_by: review.reviewedBy,
        reviewed_at: trx.fn.now(),
        updated_at: trx.fn.now(),
      })
      .returning<DiscoveryRow[]>('*');
    if (!updated) throw new Error(`Discovery ${discoveryId} does not exist`);
    return updated;
  });

  // The quarantine row has no tenant; its concentrator does, and that is the
  // scope the review screen is served under. One lookup, so the event cannot
  // reach an admin positioned on a different customer.
  const owner = await db('devices')
    .where({ id: row.concentrator_id })
    .first<{ tenant_id: number } | undefined>('tenant_id');
  if (owner) {
    emitToTenantAdmins(owner.tenant_id, SOCKET_EVENTS.DISCOVERY_RESOLVED, {
      id: discoveryId,
      state,
    });
  }
  return row;
}
