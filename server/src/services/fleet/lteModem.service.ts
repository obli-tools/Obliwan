/**
 * ObliWAN — the SIM card in every LTE modem of a RouterOS router, read by the
 * FLEET (migration 080), so a box that never went through the bench — or
 * whose card was swapped after it — still says which mobile line it carries.
 *
 * ┌─ WHY THE ICCID WAS NEVER READ OUTSIDE THE BENCH ─────────────────────────┐
 * │ Nothing on the fleet side asked. The only reader was the bench's         │
 * │ `readSimCard` (bench/routerosApply.ts), once per preparation, on `lte1`  │
 * │ only — and it took `row.uicc ?? row.iccid`, so a modem printing an EMPTY │
 * │ `uicc` beside a filled `iccid` was read as "no card" (`??` keeps "").    │
 * │ Both readers now judge every candidate field independently.              │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * ┌─ HOW IT IS READ — defensively, nothing invented ─────────────────────────┐
 * │ `/interface/lte/print` lists the modems (every row is an LTE interface:  │
 * │ `lte1`, `lte2`…). For each, `/interface/lte/monitor =numbers=<n> =once=` │
 * │ (RouterOS 7 prints the card there), then `/interface/lte/info` with the │
 * │ same words when monitor showed no ICCID (older builds printed it there; │
 * │ RouterOS 7 removed the menu, which then traps). The ICCID is the `uicc`  │
 * │ field (RouterOS's own name for it) or `iccid`; IMSI `imsi`; IMEI `imei`, │
 * │ each from whichever row printed a VALID one. A field not printed is      │
 * │ NULL — NOT READ, never "no SIM": a card still locked by its PIN shows no │
 * │ IMSI, a modem still booting shows nothing.                               │
 * │ A modem neither menu answered for is NOT written: the previous reading  │
 * │ keeps its own, older, `observed_at`. An interface no longer listed (the  │
 * │ list answered) loses its row.                                            │
 * │ REASONED, not observed on a Chateau: the field names and that `once`    │
 * │ makes both menus answer one reply over the API.                          │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Read-only on the router. Filed ONLY when the identity just read on the same
 * session is this device's own, exactly like the health check's other
 * observations: a tunnel address answered by another box must never link a
 * line to this one.
 */

import { db } from '../../db';
import { logger } from '../../utils/logger';
import { autoLinkDeviceModems } from '../sim/deviceLink.service';

export interface LteModemReading {
  interface: string;
  iccid: string | null;
  imsi: string | null;
  imei: string | null;
}

/** What one read of a router's modems produced. `null` list: the LTE menu
 *  did not answer (no LTE support, a trap, a timeout) — nothing is known. */
export interface LteModemsRead {
  /** Every LTE interface listed, answered or not. */
  listed: string[] | null;
  /** The modems at least one menu answered for. */
  readings: LteModemReading[];
}

export interface ModemQueryable {
  query: (words: string[], opts?: { timeoutMs?: number }) => Promise<unknown>;
}

/** An ICCID as a modem prints it, or null: blanks dropped, a trailing BCD
 *  filler `F` dropped, then 18 to 22 digits or nothing. */
export function parseModemIccid(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  let v = raw.replace(/\s+/g, '').toUpperCase();
  if (v.endsWith('F')) v = v.slice(0, -1);
  return /^[0-9]{18,22}$/.test(v) ? v : null;
}

function digits(raw: unknown, min: number, max: number): string | null {
  if (typeof raw !== 'string') return null;
  const v = raw.replace(/\s+/g, '');
  return new RegExp(`^[0-9]{${min},${max}}$`).test(v) ? v : null;
}

export const parseModemImsi = (raw: unknown): string | null => digits(raw, 6, 15);
export const parseModemImei = (raw: unknown): string | null => digits(raw, 14, 17);

/** The card fields of a set of rows: each field from the first row that
 *  printed a VALID value under any of its names. */
export function modemFieldsOf(rows: Array<Record<string, unknown>>): Omit<LteModemReading, 'interface'> {
  let iccid: string | null = null;
  let imsi: string | null = null;
  let imei: string | null = null;
  for (const r of rows) {
    iccid ??= parseModemIccid(r.uicc) ?? parseModemIccid(r.iccid);
    imsi ??= parseModemImsi(r.imsi);
    imei ??= parseModemImei(r.imei);
  }
  return { iccid, imsi, imei };
}

function asRows(v: unknown): Array<Record<string, unknown>> {
  return Array.isArray(v) ? (v.filter((r) => r && typeof r === 'object') as Array<Record<string, unknown>>) : [];
}

/** Read every LTE modem of the router on `conn`. Never throws for a menu that
 *  traps or times out; only the list's own failure leaves `listed` null. */
export async function readLteModems(conn: ModemQueryable, timeoutMs: number): Promise<LteModemsRead> {
  let listRows: Array<Record<string, unknown>>;
  try {
    listRows = asRows(await conn.query(['/interface/lte/print'], { timeoutMs }));
  } catch {
    return { listed: null, readings: [] };
  }
  const listed: string[] = [];
  for (const r of listRows) {
    const name = typeof r.name === 'string' ? r.name.trim() : '';
    if (name !== '' && name.length <= 64 && !listed.includes(name)) listed.push(name);
  }
  const readings: LteModemReading[] = [];
  for (const name of listed) {
    const seen: Array<Record<string, unknown>> = listRows.filter((r) => r.name === name);
    let answered = false;
    for (const menu of ['/interface/lte/monitor', '/interface/lte/info']) {
      if (answered && modemFieldsOf(seen).iccid !== null) break;
      try {
        const rows = asRows(await conn.query([menu, `=numbers=${name}`, '=once='], { timeoutMs }));
        answered = true;
        seen.push(...rows);
      } catch {
        /* a trap (no such menu on this build) or a timeout: the other menu */
      }
    }
    if (!answered) continue;
    readings.push({ interface: name, ...modemFieldsOf(seen) });
  }
  return { listed, readings };
}

/** File one read of `deviceId`'s modems. Returns true when a card changed. */
export async function recordLteModems(deviceId: number, read: LteModemsRead, observedAt = new Date()): Promise<boolean> {
  if (read.listed === null) return false;
  let changed = false;
  await db.transaction(async (trx) => {
    const before = (await trx('device_lte_modems').where({ device_id: deviceId }).select('interface', 'iccid')) as Array<{
      interface: string;
      iccid: string | null;
    }>;
    const gone = before.filter((b) => !read.listed!.includes(b.interface)).map((b) => b.interface);
    if (gone.length > 0) {
      await trx('device_lte_modems').where({ device_id: deviceId }).whereIn('interface', gone).delete();
      changed = true;
    }
    for (const r of read.readings) {
      const prev = before.find((b) => b.interface === r.interface);
      if (!prev || prev.iccid !== r.iccid) changed = true;
      await trx('device_lte_modems')
        .insert({ device_id: deviceId, interface: r.interface, iccid: r.iccid, imsi: r.imsi, imei: r.imei, observed_at: observedAt })
        .onConflict(['device_id', 'interface'])
        .merge(['iccid', 'imsi', 'imei', 'observed_at']);
    }
  });
  return changed;
}

/** A router's modems are read again no sooner than this. A card is not
 *  swapped every minute, and each modem costs up to two queries. */
export const LTE_MODEM_OBSERVE_EVERY_MS = 6 * 3600_000;
/** A router whose read failed or found nothing is asked again after this. */
const LTE_MODEM_RETRY_MS = 3600_000;
const lteAskedAt = new Map<number, { at: number; ok: boolean }>();

/** Test seam: forget when each router was last asked. */
export function resetLteModemSchedule(): void {
  lteAskedAt.clear();
}

/**
 * The health check's observation (healthCheck.service.ts): on the session it
 * already holds, at most every `LTE_MODEM_OBSERVE_EVERY_MS`, only when the
 * identity just read is this device's own. Then offers the cards read to
 * the SIM lines (`autoLinkDeviceModems`). Never changes the check's verdict:
 * the caller swallows any failure.
 */
export async function observeLteModems(
  deviceId: number,
  conn: ModemQueryable,
  identityRows: unknown,
  timeoutMs: number,
): Promise<void> {
  const last = lteAskedAt.get(deviceId);
  if (last && Date.now() - last.at < (last.ok ? LTE_MODEM_OBSERVE_EVERY_MS : LTE_MODEM_RETRY_MS)) return;
  const row = (await db('devices').where({ id: deviceId }).first('system_identity', 'family')) as
    | { system_identity: string | null; family: string }
    | undefined;
  if (!row || !row.system_identity || !String(row.family).startsWith('mikrotik_')) return;
  const first = Array.isArray(identityRows) ? (identityRows[0] as Record<string, unknown> | undefined) : undefined;
  if (String(first?.name ?? '') !== row.system_identity) return;

  lteAskedAt.set(deviceId, { at: Date.now(), ok: false });
  const read = await readLteModems(conn, timeoutMs);
  if (read.listed === null) return;
  const changed = await recordLteModems(deviceId, read);
  lteAskedAt.set(deviceId, { at: Date.now(), ok: true });
  if (changed) logger.info({ deviceId, modems: read.readings.length }, 'LTE modem card reading changed');
  await autoLinkDeviceModems(db, deviceId);
}
