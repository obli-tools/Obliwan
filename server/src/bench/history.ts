import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { localDataDir } from './window';

/**
 * ObliWAN bench — the local "Préparés aujourd'hui" history (#24).
 *
 * One line per preparation that ENDED on this PC, success or failure, kept in
 * %LOCALAPPDATA%\ObliWAN\bench-history.json: what the preparer needs to
 * re-check a batch before shipping it (which box went to which store, which
 * one failed, which was a TEST). No label is printed (operator, 2026-10-03).
 *
 * Nothing secret is written: no password, no file content — the site, the
 * box's MAC, serial and model, the ObliWAN device record, the PPP login, the
 * ICCID the bench read, the outcome and its message. Best effort: a history
 * that cannot be read or written never stops a preparation.
 */

export interface HistoryEntry {
  at: string;
  ok: boolean;
  site: string | null;
  tenant: string | null;
  mac: string | null;
  serial: string | null;
  model: string | null;
  deviceId: number | null;
  pppUsername: string | null;
  iccid: string | null;
  test: boolean;
  message: string | null;
}

/** Kept on disk: enough for weeks of preparation, small enough to rewrite. */
const KEEP = 1000;

export function defaultHistoryFile(): string {
  return join(localDataDir(), 'bench-history.json');
}

export function readHistory(file: string | null): HistoryEntry[] {
  if (!file) return [];
  try {
    const parsed = JSON.parse(readFileSync(file, 'utf8')) as unknown;
    return Array.isArray(parsed) ? (parsed as HistoryEntry[]) : [];
  } catch {
    return [];
  }
}

export function appendHistory(file: string | null, entry: HistoryEntry): void {
  if (!file) return;
  try {
    const all = [...readHistory(file), entry].slice(-KEEP);
    mkdirSync(dirname(file), { recursive: true });
    const tmp = `${file}.part`;
    writeFileSync(tmp, JSON.stringify(all, null, 1), 'utf8');
    renameSync(tmp, file);
  } catch {
    /* best effort: see the header */
  }
}

/** Today's entries (the PC's local date), newest first. */
export function todaysHistory(file: string | null, now: Date = new Date()): HistoryEntry[] {
  const day = now.toLocaleDateString('fr-FR');
  return readHistory(file)
    .filter((e) => new Date(e.at).toLocaleDateString('fr-FR') === day)
    .reverse();
}
