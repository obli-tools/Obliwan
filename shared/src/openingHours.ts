// ============================================================================
// @obliwan/shared — store OPENING HOURS (migration 096)
// ============================================================================
//
// WHY. A store down at 03:00 is not an emergency; at 15:00 it is. ObliWAN
// knew neither: every outage and every 4G backup episode was announced with
// the same severity whatever the hour. A workspace (tenant) now states its
// stores' usual hours once, a site overrides them, and dated exceptions say
// "closed on the 25th" or "open this Sunday in December".
//
// THE MODEL, AND WHAT INHERITS.
//   week        one entry per weekday, 0 to 2 ranges each; [] = closed all day.
//               null on a SITE = "the workspace's week". null on the
//               WORKSPACE = no usual hours known.
//   exceptions  dated (local calendar date of the site), 0 to 2 ranges each;
//               [] = closed that day. They MERGE: the workspace's exceptions
//               apply to every site, a site's own exception wins on its date.
// The hours are KNOWN for a site iff an effective week exists (its own or its
// workspace's). Unknown hours change nothing anywhere: every consumer keeps
// the behaviour it had before 096. Exceptions alone, with no week, are not
// "known hours" — "open on the 20th" says nothing about the 21st.
//
// A RANGE is { open: 'HH:MM', close: 'HH:MM' } in the SITE's local wall time
// (sites.timezone). `close` may be '24:00'. A `close` at or before `open`
// is an OVERNIGHT range (18:00-02:00): it ends on the next calendar day, and
// it belongs to the day it STARTS on — an exception on the next day does not
// cut it short. Only the LAST range of a day may be overnight.
//
// DST. Everything is evaluated on the wall clock of the instant asked about,
// so a range means what the store's door says on a change day too: a store
// "09:00-19:00" opens at 09:00 local on the last Sunday of March. A boundary
// that does not exist that day (02:30 when 02:00 jumps to 03:00) takes effect
// at the jump.
//
// No server import here: the client draws the same parser, formatter and
// evaluator ("Ouvert / Fermé maintenant" is computed by the server, but the
// bulk dialog previews the text the operator types with this file).

export const OPENING_DAYS = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'] as const;
export type OpeningDay = (typeof OPENING_DAYS)[number];

export interface OpeningRange {
  /** 'HH:MM', 00:00-23:59. */
  open: string;
  /** 'HH:MM', 00:00-24:00. At or before `open` = overnight (ends next day). */
  close: string;
}

export type WeeklyHours = Record<OpeningDay, OpeningRange[]>;

export interface OpeningException {
  /** Local calendar date, 'YYYY-MM-DD'. */
  date: string;
  /** [] = closed all day. */
  ranges: OpeningRange[];
}

/** What a workspace or a site stores (`tenants.opening_hours`, `sites.opening_hours`). */
export interface OpeningHours {
  /** null = no week at this level (a site inherits its workspace's). */
  week: WeeklyHours | null;
  exceptions: OpeningException[];
}

/** The hours that apply to one site, after inheritance. */
export interface EffectiveOpeningHours {
  week: WeeklyHours;
  /** Where the week comes from. */
  weekSource: 'site' | 'tenant';
  /** date -> ranges, workspace's then site's (the site's win on a date). */
  exceptions: Record<string, OpeningRange[]>;
}

/** Ranges per day / exception. Two covers "morning and afternoon". */
export const OPENING_MAX_RANGES = 2;
/** Exceptions per level: a few years of holidays, not a calendar. */
export const OPENING_MAX_EXCEPTIONS = 200;
/** How far `nextClosedWindowIn` looks ahead. */
export const OPENING_HORIZON_DAYS = 400;

// ============================================================================
// Validation
// ============================================================================

const HHMM = /^([01]\d|2[0-4]):([0-5]\d)$/;
const ISO_DATE = /^(\d{4})-(\d{2})-(\d{2})$/;

/** Minutes after local midnight of 'HH:MM' (24:00 = 1440), or null. */
export function hhmmToMinutes(raw: string): number | null {
  const m = HHMM.exec(raw);
  if (!m) return null;
  const h = Number(m[1]);
  const min = Number(m[2]);
  if (h === 24 && min !== 0) return null;
  return h * 60 + min;
}

export function minutesToHhmm(minutes: number): string {
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}`;
}

function isRealDate(date: string): boolean {
  const m = ISO_DATE.exec(date);
  if (!m) return false;
  const y = Number(m[1]);
  const mo = Number(m[2]);
  const d = Number(m[3]);
  const t = new Date(Date.UTC(y, mo - 1, d));
  return t.getUTCFullYear() === y && t.getUTCMonth() === mo - 1 && t.getUTCDate() === d;
}

/** Why one day's ranges are not acceptable, or null. `where` names the day. */
function rangesError(ranges: unknown, where: string): string | null {
  if (!Array.isArray(ranges)) return `${where}: ranges must be a list`;
  if (ranges.length > OPENING_MAX_RANGES) {
    return `${where}: at most ${OPENING_MAX_RANGES} ranges per day`;
  }
  const spans: Array<[number, number]> = [];
  for (let i = 0; i < ranges.length; i += 1) {
    const r = ranges[i] as Partial<OpeningRange> | null;
    if (!r || typeof r !== 'object' || typeof r.open !== 'string' || typeof r.close !== 'string') {
      return `${where}: a range must be { open: "HH:MM", close: "HH:MM" }`;
    }
    const o = hhmmToMinutes(r.open);
    const c = hhmmToMinutes(r.close);
    if (o === null || o >= 1440) return `${where}: "${r.open}" is not an opening time (00:00-23:59)`;
    if (c === null) return `${where}: "${r.close}" is not a closing time (00:00-24:00)`;
    if (o === c) return `${where}: the range ${r.open}-${r.close} is empty`;
    const overnight = c < o;
    if (overnight && i !== ranges.length - 1) {
      return `${where}: only the last range of a day may run past midnight (${r.open}-${r.close})`;
    }
    spans.push([o, overnight ? 1440 : c]);
  }
  for (let i = 1; i < spans.length; i += 1) {
    if (spans[i][0] < spans[i - 1][1]) return `${where}: ranges must be in order and must not overlap`;
  }
  return null;
}

/**
 * Validate a stored or submitted value. Returns the NORMALISED value (fresh
 * arrays, exceptions sorted by date) or the first error, in English — the
 * server's 400 text; the client's form validates with the same function.
 */
export function validateOpeningHours(
  raw: unknown,
): { ok: true; value: OpeningHours } | { ok: false; error: string } {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, error: 'opening hours must be an object { week, exceptions }' };
  }
  const v = raw as { week?: unknown; exceptions?: unknown };
  let week: WeeklyHours | null = null;
  if (v.week !== null && v.week !== undefined) {
    if (typeof v.week !== 'object' || Array.isArray(v.week)) {
      return { ok: false, error: 'week must be an object with one entry per day' };
    }
    const w = v.week as Record<string, unknown>;
    for (const k of Object.keys(w)) {
      if (!(OPENING_DAYS as readonly string[]).includes(k)) return { ok: false, error: `week: unknown day "${k}"` };
    }
    const out = {} as WeeklyHours;
    for (const day of OPENING_DAYS) {
      const ranges = w[day] ?? [];
      const err = rangesError(ranges, day);
      if (err) return { ok: false, error: err };
      out[day] = (ranges as OpeningRange[]).map((r) => ({ open: r.open, close: r.close }));
    }
    week = out;
  }
  const exceptions: OpeningException[] = [];
  if (v.exceptions !== null && v.exceptions !== undefined) {
    if (!Array.isArray(v.exceptions)) return { ok: false, error: 'exceptions must be a list' };
    if (v.exceptions.length > OPENING_MAX_EXCEPTIONS) {
      return { ok: false, error: `at most ${OPENING_MAX_EXCEPTIONS} dated exceptions` };
    }
    const seen = new Set<string>();
    for (const e of v.exceptions as unknown[]) {
      const x = e as Partial<OpeningException> | null;
      if (!x || typeof x !== 'object' || typeof x.date !== 'string' || !isRealDate(x.date)) {
        return { ok: false, error: 'an exception needs a real date "YYYY-MM-DD"' };
      }
      if (seen.has(x.date)) return { ok: false, error: `${x.date}: two exceptions on the same date` };
      seen.add(x.date);
      const err = rangesError(x.ranges ?? [], x.date);
      if (err) return { ok: false, error: err };
      exceptions.push({ date: x.date, ranges: ((x.ranges ?? []) as OpeningRange[]).map((r) => ({ open: r.open, close: r.close })) });
    }
    exceptions.sort((a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : 0));
  }
  return { ok: true, value: { week, exceptions } };
}

/** A stored value as read back: validated, or null when absent or unreadable. */
export function readOpeningHours(raw: unknown): OpeningHours | null {
  if (raw === null || raw === undefined) return null;
  let v: unknown = raw;
  if (typeof raw === 'string') {
    try {
      v = JSON.parse(raw) as unknown;
    } catch {
      return null;
    }
  }
  const r = validateOpeningHours(v);
  return r.ok ? r.value : null;
}

/** True when the value says nothing (no week, no exception). */
export function isEmptyOpeningHours(h: OpeningHours | null): boolean {
  return h === null || (h.week === null && h.exceptions.length === 0);
}

// ============================================================================
// Inheritance — workspace -> site
// ============================================================================

export function effectiveOpeningHours(
  tenant: OpeningHours | null,
  site: OpeningHours | null,
): EffectiveOpeningHours | null {
  const week = site?.week ?? tenant?.week ?? null;
  if (week === null) return null;
  const exceptions: Record<string, OpeningRange[]> = {};
  for (const e of tenant?.exceptions ?? []) exceptions[e.date] = e.ranges;
  for (const e of site?.exceptions ?? []) exceptions[e.date] = e.ranges;
  return { week, weekSource: site?.week ? 'site' : 'tenant', exceptions };
}

// ============================================================================
// Time zones — wall clock of an instant, and the instant of a wall clock
// ============================================================================

interface LocalParts {
  y: number;
  mo: number; // 1-12
  d: number;
  h: number;
  mi: number;
}

const formatters = new Map<string, Intl.DateTimeFormat>();

function formatterFor(tz: string): Intl.DateTimeFormat {
  let f = formatters.get(tz);
  if (!f) {
    // Throws a RangeError on an unknown zone: the caller decides.
    f = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    });
    formatters.set(tz, f);
  }
  return f;
}

/** True when `tz` is an IANA zone this runtime knows. */
export function isKnownTimeZone(tz: string): boolean {
  try {
    formatterFor(tz);
    return true;
  } catch {
    return false;
  }
}

function localParts(at: number, tz: string): LocalParts {
  const parts = formatterFor(tz).formatToParts(new Date(at));
  const get = (type: string): number => Number(parts.find((p) => p.type === type)?.value ?? NaN);
  const h = get('hour');
  return { y: get('year'), mo: get('month'), d: get('day'), h: h === 24 ? 0 : h, mi: get('minute') };
}

/** Local minus UTC, in ms, at instant `at` (minute precision). */
function offsetAt(at: number, tz: string): number {
  const floor = at - (((at % 60_000) + 60_000) % 60_000);
  const p = localParts(floor, tz);
  return Date.UTC(p.y, p.mo - 1, p.d, p.h, p.mi) - floor;
}

/** 'YYYY-MM-DD' of a UTC-midnight day number. */
function dayKey(dayMs: number): string {
  const t = new Date(dayMs);
  return `${t.getUTCFullYear()}-${String(t.getUTCMonth() + 1).padStart(2, '0')}-${String(t.getUTCDate()).padStart(2, '0')}`;
}

/** The weekday of a UTC-midnight day number (calendar arithmetic only). */
function dayOf(dayMs: number): OpeningDay {
  return OPENING_DAYS[(new Date(dayMs).getUTCDay() + 6) % 7];
}

const DAY_MS = 86_400_000;

/** The ranges that apply on a local calendar day: its exception, or its weekday. */
function rangesOn(h: EffectiveOpeningHours, dayMs: number): OpeningRange[] {
  return h.exceptions[dayKey(dayMs)] ?? h.week[dayOf(dayMs)];
}

function spanOf(r: OpeningRange): [number, number] {
  const o = hhmmToMinutes(r.open) as number;
  const c = hhmmToMinutes(r.close) as number;
  return [o, c <= o ? c + 1440 : c];
}

/** Open at local wall time (`dayMs` = the local date at UTC midnight, `m` = minutes). */
function openAtWall(h: EffectiveOpeningHours, dayMs: number, m: number): boolean {
  for (const r of rangesOn(h, dayMs)) {
    const [o, c] = spanOf(r);
    if (m >= o && m < c) return true;
  }
  // Yesterday's overnight range spills into today.
  for (const r of rangesOn(h, dayMs - DAY_MS)) {
    const [o, c] = spanOf(r);
    if (c > 1440 && m + 1440 >= o && m + 1440 < c) return true;
  }
  return false;
}

/**
 * Is the store open at `at`, on the wall clock of `tz`? Throws on an unknown
 * zone (the server service turns that into "unknown").
 */
export function isOpenAt(h: EffectiveOpeningHours, tz: string, at: Date): boolean {
  const p = localParts(at.getTime(), tz);
  return openAtWall(h, Date.UTC(p.y, p.mo - 1, p.d), p.h * 60 + p.mi);
}

/**
 * Every instant at which the open/closed state MAY change during local days
 * [firstDay, lastDay] (UTC-midnight day numbers): each range boundary under
 * the offsets in force before and after the day, plus the DST jump itself
 * when the day has one. Spurious candidates are harmless — the state is
 * re-evaluated at each — and a missing one is the only way to be wrong, which
 * is why a boundary that does not exist that day (inside a spring gap) is
 * covered by the jump instant.
 */
function candidatesBetween(h: EffectiveOpeningHours, tz: string, firstDay: number, lastDay: number): number[] {
  const out = new Set<number>();
  for (let day = firstDay; day <= lastDay; day += DAY_MS) {
    const before = offsetAt(day - 14 * 3_600_000, tz);
    const after = offsetAt(day + 38 * 3_600_000, tz);
    const offsets = before === after ? [before] : [before, after];
    if (before !== after) {
      // The jump: first minute at which the offset is `after`.
      let lo = day - 14 * 3_600_000;
      let hi = day + 38 * 3_600_000;
      while (hi - lo > 60_000) {
        const mid = lo + Math.floor((hi - lo) / 120_000) * 60_000;
        if (offsetAt(mid, tz) === after) hi = mid;
        else lo = mid;
      }
      out.add(hi);
    }
    const minutes = new Set<number>([0]);
    for (const r of rangesOn(h, day)) {
      const [o, c] = spanOf(r);
      minutes.add(o);
      minutes.add(c);
    }
    for (const m of minutes) {
      for (const off of offsets) out.add(day + m * 60_000 - off);
    }
  }
  return Array.from(out).sort((a, b) => a - b);
}

/**
 * The next period the store is CLOSED, seen from `from`. When it is closed at
 * `from`, that is the period in progress, starting at `from`. `end` is the
 * next opening; a store that never opens again within the horizon gets
 * `end` = `from` + OPENING_HORIZON_DAYS. null when it is never closed within
 * the horizon (open around the clock).
 */
export function nextClosedWindowIn(
  h: EffectiveOpeningHours,
  tz: string,
  from: Date,
): { start: Date; end: Date } | null {
  const t0 = from.getTime();
  const p = localParts(t0, tz);
  const today = Date.UTC(p.y, p.mo - 1, p.d);
  const horizonEnd = t0 + OPENING_HORIZON_DAYS * DAY_MS;
  // A short look first (the common answer is tonight), the horizon after.
  for (const span of [9, OPENING_HORIZON_DAYS + 1]) {
    const lastDay = today + span * DAY_MS;
    // Candidates past this instant may be missing a later day's boundaries;
    // a conclusion is only trusted before it.
    const trustedUntil = lastDay - 2 * DAY_MS;
    let start: number | null = isOpenAt(h, tz, from) ? null : t0;
    for (const c of candidatesBetween(h, tz, today - DAY_MS, lastDay)) {
      if (c <= t0) continue;
      if (c > trustedUntil) break;
      const open = isOpenAt(h, tz, new Date(c));
      if (start === null) {
        if (!open) start = c;
      } else if (open) {
        return { start: new Date(start), end: new Date(c) };
      }
    }
    if (span > OPENING_HORIZON_DAYS) {
      return start === null ? null : { start: new Date(start), end: new Date(Math.max(horizonEnd, start)) };
    }
  }
  return null;
}

/**
 * The next instant after `from` at which the state (open/closed) changes,
 * looking `spanDays` local days ahead at most; null when it does not change
 * within them. Cheap with the default span — what a list of 400 sites calls.
 */
export function nextChangeIn(
  h: EffectiveOpeningHours,
  tz: string,
  from: Date,
  spanDays = 9,
): Date | null {
  const t0 = from.getTime();
  const p = localParts(t0, tz);
  const today = Date.UTC(p.y, p.mo - 1, p.d);
  const lastDay = today + spanDays * DAY_MS;
  const trustedUntil = lastDay - 2 * DAY_MS;
  const now = isOpenAt(h, tz, from);
  for (const c of candidatesBetween(h, tz, today - DAY_MS, lastDay)) {
    if (c <= t0) continue;
    if (c > trustedUntil) break;
    if (isOpenAt(h, tz, new Date(c)) !== now) return new Date(c);
  }
  return null;
}

// ============================================================================
// The readable text format — CSV column and bulk dialog
// ============================================================================
//
//   lun-ven 09:00-12:00,14:00-19:00; sam 10:00-18:00; dim fermé; 2026-12-25 fermé; 2026-12-20 10:00-18:00
//
// Groups are separated by ';', '|' or a new line. A group is a SUBJECT and
// its hours:
//   subject  a day (lun, mardi, mon, tuesday — French or English, the first
//            three letters count), a run (lun-ven), a list (lun,mer,ven), or a
//            date (2026-12-25 or 25/12/2026) for a dated exception;
//   hours    one or two ranges separated by ',' or '+' — 09:00-19:00, 9h-19h,
//            9h30-12h30 — or fermé / ferme / closed.
// A weekday not named in a text that names at least one is CLOSED. A text
// with dates only sets exceptions and no week (a site keeps its workspace's).
// The CSV words for "inherit the workspace's hours" are in
// OPENING_HOURS_INHERIT_WORDS; the caller tests them (and emptiness) first.

export const OPENING_HOURS_CSV_COLUMN = 'horaires';
export const OPENING_HOURS_INHERIT_WORDS = ['hérité', 'herite', 'inherit', 'client'] as const;

const DAY_ALIASES: Record<string, OpeningDay> = {
  lun: 'mon', mar: 'tue', mer: 'wed', jeu: 'thu', ven: 'fri', sam: 'sat', dim: 'sun',
  mon: 'mon', tue: 'tue', wed: 'wed', thu: 'thu', fri: 'fri', sat: 'sat', sun: 'sun',
};

const CLOSED_WORDS = new Set(['fermé', 'ferme', 'closed', 'fermée', 'fermee']);

const DAY_FULL_NAMES = [
  'lundi', 'mardi', 'mercredi', 'jeudi', 'vendredi', 'samedi', 'dimanche',
  'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday',
];

/** A day: its three-letter abbreviation, or a beginning of its full name. */
function parseDayToken(tok: string): OpeningDay | null {
  const t = tok.trim().toLowerCase().replace(/\.$/, '');
  if (t.length < 3) return null;
  if (t.length > 3 && !DAY_FULL_NAMES.some((n) => n.startsWith(t))) return null;
  return DAY_ALIASES[t.slice(0, 3)] ?? null;
}

function parseTime(tok: string): string | null {
  const t = tok.trim().toLowerCase();
  const m = /^(\d{1,2})(?:[:h](\d{2})?)?$/.exec(t);
  if (!m) return null;
  const h = Number(m[1]);
  const mi = m[2] === undefined ? 0 : Number(m[2]);
  if (h > 24 || mi > 59 || (h === 24 && mi !== 0)) return null;
  return minutesToHhmm(h * 60 + mi);
}

function parseRanges(text: string): OpeningRange[] | string {
  const t = text.trim().toLowerCase();
  if (CLOSED_WORDS.has(t)) return [];
  const out: OpeningRange[] = [];
  for (const part of t.split(/[,+]/)) {
    const m = /^\s*([0-9:h]+)\s*-\s*([0-9:h]+)\s*$/.exec(part);
    if (!m) return `"${part.trim()}" is not a range like 09:00-19:00`;
    const open = parseTime(m[1]);
    const close = parseTime(m[2]);
    if (!open || !close) return `"${part.trim()}" is not a range like 09:00-19:00`;
    out.push({ open, close });
  }
  return out;
}

function parseDateToken(tok: string): string | null {
  const iso = ISO_DATE.exec(tok);
  if (iso) return isRealDate(tok) ? tok : null;
  const fr = /^(\d{1,2})\/(\d{1,2})\/(\d{4})$/.exec(tok);
  if (!fr) return null;
  const date = `${fr[3]}-${fr[2].padStart(2, '0')}-${fr[1].padStart(2, '0')}`;
  return isRealDate(date) ? date : null;
}

/**
 * Parse the readable format. Errors are in English and name the group at
 * fault; the import wraps them in its own French row message.
 */
export function parseOpeningHoursText(
  text: string,
): { ok: true; value: OpeningHours } | { ok: false; error: string } {
  const groups = text.split(/[;|\n]/).map((g) => g.trim()).filter((g) => g !== '');
  if (groups.length === 0) return { ok: false, error: 'no opening hours given' };
  const week: Partial<Record<OpeningDay, OpeningRange[]>> = {};
  let anyDay = false;
  const exceptions: OpeningException[] = [];
  for (const g of groups) {
    const m = /^(\S+)\s+(.+)$/.exec(g);
    if (!m) return { ok: false, error: `"${g}": expected a day or a date followed by hours` };
    const ranges = parseRanges(m[2]);
    if (typeof ranges === 'string') return { ok: false, error: `"${g}": ${ranges}` };
    const date = parseDateToken(m[1]);
    if (date) {
      exceptions.push({ date, ranges });
      continue;
    }
    const days: OpeningDay[] = [];
    for (const item of m[1].split(',')) {
      const run = item.split('-');
      if (run.length === 1) {
        const d = parseDayToken(run[0]);
        if (!d) return { ok: false, error: `"${g}": "${item}" is neither a day nor a date` };
        days.push(d);
      } else if (run.length === 2) {
        const a = parseDayToken(run[0]);
        const b = parseDayToken(run[1]);
        if (!a || !b) return { ok: false, error: `"${g}": "${item}" is not a run of days like lun-ven` };
        const ia = OPENING_DAYS.indexOf(a);
        const ib = OPENING_DAYS.indexOf(b);
        if (ib < ia) return { ok: false, error: `"${g}": the run ${item} goes backwards` };
        for (let i = ia; i <= ib; i += 1) days.push(OPENING_DAYS[i]);
      } else {
        return { ok: false, error: `"${g}": "${item}" is not a day` };
      }
    }
    for (const d of days) {
      if (week[d]) return { ok: false, error: `"${g}": ${d} is given twice` };
      week[d] = ranges;
      anyDay = true;
    }
  }
  const candidate: OpeningHours = {
    week: anyDay
      ? (Object.fromEntries(OPENING_DAYS.map((d) => [d, week[d] ?? []])) as WeeklyHours)
      : null,
    exceptions,
  };
  return validateOpeningHours(candidate);
}

const FR_DAYS: Record<OpeningDay, string> = { mon: 'lun', tue: 'mar', wed: 'mer', thu: 'jeu', fri: 'ven', sat: 'sam', sun: 'dim' };

function formatRanges(ranges: OpeningRange[], lang: 'fr' | 'en'): string {
  if (ranges.length === 0) return lang === 'fr' ? 'fermé' : 'closed';
  return ranges.map((r) => `${r.open}-${r.close}`).join(',');
}

/** The readable text of a value — what the parser reads back unchanged. */
export function formatOpeningHours(h: OpeningHours, lang: 'fr' | 'en' = 'fr'): string {
  const name = (d: OpeningDay): string => (lang === 'fr' ? FR_DAYS[d] : d);
  const groups: string[] = [];
  if (h.week) {
    let i = 0;
    while (i < OPENING_DAYS.length) {
      const text = formatRanges(h.week[OPENING_DAYS[i]], lang);
      let j = i;
      while (j + 1 < OPENING_DAYS.length && formatRanges(h.week[OPENING_DAYS[j + 1]], lang) === text) j += 1;
      groups.push(`${i === j ? name(OPENING_DAYS[i]) : `${name(OPENING_DAYS[i])}-${name(OPENING_DAYS[j])}`} ${text}`);
      i = j + 1;
    }
  }
  for (const e of h.exceptions) groups.push(`${e.date} ${formatRanges(e.ranges, lang)}`);
  return groups.join('; ');
}

// ============================================================================
// What the server says about a site — lists and the device page
// ============================================================================

/** "Ouvert / Fermé maintenant", computed by the server in the site's zone. */
export interface SiteOpenState {
  /** null = no hours known for this site (nothing changes anywhere). */
  open: boolean | null;
  /** The next change of state (opening or closing), ISO; null if none in the horizon or unknown. */
  nextChangeAt: string | null;
  /** Where the week comes from; null when unknown. */
  source: 'site' | 'tenant' | null;
}

/**
 * The two inherited settings that act on a closed store (settings.ts):
 * `closed_store_notify` and `closed_hours_maintenance`. Their values.
 */
export const CLOSED_STORE_NOTIFY_ANYWAY = 0;
export const CLOSED_STORE_NOTIFY_AT_OPENING = 1;

/** The marker a lowered alert carries in its title, French first. */
export const CLOSED_STORE_MARK = 'magasin fermé';
