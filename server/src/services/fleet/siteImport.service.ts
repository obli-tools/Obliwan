/**
 * ObliWAN — bulk site import from CSV (the infra operator's onboarding path).
 *
 * One CSV, one row per site. Columns: `code` and `name` (required), `country`
 * (ISO 3166-1 alpha-2), `timezone` (IANA), `address`, `contact`, `uplink`
 * (the declared access link, migration 076: `auto` | `fixe` | `4g`, also
 * `fixed` | `cellular_only`; `auto` CLEARS a declaration — it is a value, not
 * an empty cell), `horaires` (the store's opening hours, migration 096, in
 * the readable format of shared/src/openingHours.ts — "lun-ven 09:00-19:00;
 * dim fermé"; `hérité` returns the site to its workspace's hours),
 * `operateur` (« Opérateur du lien fixe », migration 095: free text, 64
 * characters at most), and any number of `var:<key>` columns holding
 * SITE-level template variable values.
 *
 * ┌─ What this file promises ─────────────────────────────────────────────────┐
 * │ • A site is identified by (tenant, code). An existing code is UPDATED,    │
 * │   never duplicated, and the code is never parsed as a number, so         │
 * │   "00001" stays "00001".                                                 │
 * │ • The code is judged against the tenant's SITE CODE FORMAT (migration    │
 * │   052, policy.ts `judgeSiteCode`). The ONE correction ever made: under   │
 * │   'digits:N', a purely numeric code shorter than N gets back the zeros   │
 * │   Excel stripped ("102" -> "00102"), and the row says so                 │
 * │   (`codeRestored`) in the dry-run before anything is written. Anything   │
 * │   else that does not fit (wrong length, letters, Excel's "102.0" or      │
 * │   "1,02E+02", refused under every format) refuses the row, in French.    │
 * │   Under 'digits:N', a row that would CREATE a site whose site number     │
 * │   the tenant already holds under another spelling (a "7" or "0102"       │
 * │   from before the format) is refused, restored cell or exact one; a      │
 * │   restored cell matching an existing site while such a sibling exists    │
 * │   is refused as ambiguous.                                               │
 * │ • An EMPTY cell never erases anything: it means "leave as it is" on an   │
 * │   update and "nothing to set" on a create. Clearing a value is done      │
 * │   through the site page, not by a blank in a spreadsheet.                │
 * │ • Dry-run writes NOTHING. It reads the same declarations and the same   │
 * │   existing sites the apply would, and reports what it would do.          │
 * │ • Apply is all-or-nothing PER ROW: the site row and its variable values  │
 * │   are written in ONE transaction, so a row is either entirely written   │
 * │   or not at all; a refused row does not block the others, and the       │
 * │   result says which rows were written.                                   │
 * │ • Variable values go through the SAME judge as the site form            │
 * │   (`validateSiteValues`: declared keys only, the opt-in                  │
 * │   `x-obliwan-level: "site"`, ajv against EVERY published declaration,   │
 * │   secrecy from the declaration) under the SAME declaration lock          │
 * │   (`SITE_FORM_LOCK_SQL`), and are written through the resolver's own    │
 * │   writer, so a secret lands in the vault column and never in `value`.   │
 * │ • No result, error or log line produced here carries a variable VALUE.  │
 * │   Errors name the column; a secret is never echoed back.                 │
 * └───────────────────────────────────────────────────────────────────────────┘
 *
 * The import is reachable under SITE_WRITE, a role that writes nothing to a
 * device. An existing site's TIMEZONE is part of its push schedule (its
 * maintenance window is evaluated in it, `middleware/siteSchedule.ts`), so a
 * row that would move it is refused unless the caller holds
 * `SITE_SCHEDULE_CAPABILITY` (`canWriteSchedule`) — judged at planning AND
 * again inside the row's transaction, against the locked row. A create sets
 * whatever timezone the file gives: a new site has no queued push to release.
 *
 * Why the import does not simply call `variableResolver.setSiteValues()`:
 * that method opens its own transaction on its own connection, so a site
 * INSERTED in this row's transaction would not be visible to it yet, and
 * committing the site first would leave a half-written row behind whenever the
 * values are then refused. The pieces it is made of — the lock, the
 * declaration query, the pure judge and the vault-aware writer — are all
 * exported, and this file composes exactly those, inside the row's
 * transaction. Nothing of the rule set is re-implemented here.
 *
 * Allocation (`allocateForSite`) is optional and runs AFTER the row has
 * committed, one site at a time, each call isolated: an allocation refusal is
 * reported on its row and never undoes the site that was written. What the
 * allocator WARNS about (an account adopted from the CHR rather than computed,
 * a formula address that differs from the deployed one, the shared-password
 * assumption) is relayed on the row, verbatim: it is what the operator must
 * read before that site is deployed.
 *
 * The DRY RUN also compares the file with the CHR when the caller may see CHR
 * matching (`opts.chr`, decided by the controller: platform admin, or
 * RECONCILE_READ): each row says "takes over <login>", "new" or "suspect:
 * looks like <login> (<reasons>)" — the reconciliation's own classifier
 * (`compareWithChr`), against the last recorded /ppp/secret read, whose age
 * the result carries. It dials nothing, writes nothing and refuses nothing.
 * `orphansImportXlsx` is the round trip's other half: the reconciliation's
 * orphans as a workbook this import reads back as it is.
 */

import {
  OPENING_HOURS_CSV_COLUMN,
  OPENING_HOURS_INHERIT_WORDS,
  SITE_FIXED_PROVIDER_CSV_COLUMN,
  SITE_SCHEDULE_CAPABILITY,
  normalizeFixedProvider,
  SITE_UPLINK_CSV_COLUMN,
  SOCKET_EVENTS,
  parseOpeningHoursText,
  parseSiteUplinkCell,
  readOpeningHours,
  type OpeningHours,
  type SiteUplinkKind,
} from '@obliwan/shared';
import { db } from '../../db';
import { logger } from '../../utils/logger';
import { emitToTenantAudience } from './scopedEmit';
import { toSiteDto } from './dto';
import { closeBackup4gForSites } from './backup4g.service';
import {
  insertSiteRow,
  updateSiteRow,
  type SiteRow,
  type UpdateSiteData,
} from './site.service';
import {
  SITE_FORM_LOCK_SQL,
  declaredSiteKeys,
  siteDeclarationsQuery,
  validateSiteValues,
  variableResolver,
  type DeclaredSiteKey,
  type JsonValue,
  type SiteVariableDeclaration,
  type VarSchema,
} from '../template/variableResolver.service';
import { AllocationError, allocateForSite, normalizeCountry } from '../allocation';
import {
  ambiguousRestoredCodeMessage,
  judgeSiteCode,
  restoredCodeNote,
  siteNumberClashMessage,
  siteNumberSiblings,
  type SiteCodeFormat,
} from '../allocation/policy';
import { loadSiteCodeFormat, loadSiteNumberIndex } from './siteCodeFormat';
import { SITE_CODE_MAX, SITE_CODE_RE, SITE_CODE_SHAPE_MESSAGE } from '../../validators/site.schema';
import {
  TEMPLATE_NAMES_NO_TENANT_MESSAGE,
  classifyProposedSites,
  orphanImportRows,
  orphansFileName,
  redactVerdict,
  type ChrRowKind,
  type ChrRowVerdict,
  type ProposedSite,
  type ReconcileReport,
} from '../allocation/reconcile.service';
import type { SeedFreshness } from '../allocation/seed';
import { buildXlsx, type XlsxColumn } from './xlsx';
import type { Knex } from 'knex';

// ============================================================================
// Limits and errors
// ============================================================================

/** A few hundred sites is the real size; this bounds a mistaken upload. Rows
 *  are applied one after the other (about a dozen queries each, plus an
 *  optional allocation), so the bound also keeps one apply well inside
 *  nginx's 300 s `proxy_read_timeout`. */
export const SITE_IMPORT_MAX_ROWS = 2000;
/** The ceiling a caller actually meets first is app.ts's
 *  `express.json({ limit: '1mb' })` on the `{ csv }` body (the client checks
 *  it before sending). This bound is the service's own, for a caller that
 *  did not come through that parser. */
export const SITE_IMPORT_MAX_CHARS = 1_000_000;

/** `createSiteSchema`'s rules, applied as plain checks so each failure can be
 *  reported on its row and column instead of as one zod blob. The code's
 *  shape is the schema's own exported constants; these lengths repeat it. */
const NAME_MAX = 255;
const ADDRESS_MAX = 2000;
const CONTACT_MAX = 500;
const TIMEZONE_MAX = 64;

/** The file as a whole cannot be read (no header, unknown column, too big).
 *  Every problem is listed; none of them quotes a cell. */
export class SiteImportFileError extends Error {
  constructor(readonly problems: string[]) {
    super(`The CSV cannot be imported: ${problems.join('; ')}`);
    this.name = 'SiteImportFileError';
  }
}

/** The file carries variable values and the caller may not write them. */
export class SiteImportForbiddenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SiteImportForbiddenError';
  }
}

/** The row error for a timezone change the caller may not make. Names the
 *  column, like every row error, and carries no value. */
const TIMEZONE_CHANGE_REFUSED =
  `timezone: changing the timezone of an existing site needs the ${SITE_SCHEDULE_CAPABILITY} capability ` +
  '(its maintenance window is evaluated in it)';

/** A row refused inside its transaction — thrown to roll it back. */
class RowRefused extends Error {
  constructor(readonly errors: string[]) {
    super('row refused');
    this.name = 'RowRefused';
  }
}

// ============================================================================
// CSV
// ============================================================================

export interface CsvRecord {
  /** 1-based line of the file on which the record STARTS (a quoted cell may
   *  span several lines). The header is line 1. */
  line: number;
  cells: string[];
}

export type CsvDelimiter = ',' | ';' | '\t';

/** Pick the delimiter from the header line: the one that occurs most often
 *  outside quotes. A French spreadsheet writes ';', most tools ','. */
function detectDelimiter(text: string): CsvDelimiter {
  const counts: Record<CsvDelimiter, number> = { ',': 0, ';': 0, '\t': 0 };
  let inQuotes = false;
  for (const ch of text) {
    if (ch === '"') inQuotes = !inQuotes;
    else if (!inQuotes && (ch === '\n' || ch === '\r')) break;
    else if (!inQuotes && (ch === ',' || ch === ';' || ch === '\t')) counts[ch] += 1;
  }
  let best: CsvDelimiter = ',';
  for (const d of [';', '\t'] as const) if (counts[d] > counts[best]) best = d;
  return best;
}

/**
 * RFC 4180, leniently: quoted cells may hold the delimiter, newlines and
 * doubled quotes; CRLF and LF are both line ends; a quote in the middle of an
 * unquoted cell is kept literally. An unterminated quote is a file error,
 * because everything after it would otherwise be swallowed into one cell.
 */
export function parseCsv(input: string): { delimiter: CsvDelimiter; records: CsvRecord[] } {
  const text = input.charCodeAt(0) === 0xfeff ? input.slice(1) : input;
  const delimiter = detectDelimiter(text);
  const records: CsvRecord[] = [];
  let cells: string[] = [];
  let cell = '';
  let inQuotes = false;
  let quotedCell = false;
  let line = 1;
  let recordLine = 1;
  let quoteOpenedOn = 0;

  const endCell = (): void => {
    // Every cell is trimmed, quoted or not: a blank in a spreadsheet cell is
    // never meaningful here, and an untrimmed " " would pass an emptiness test.
    cells.push(cell.trim());
    cell = '';
    quotedCell = false;
  };
  const endRecord = (): void => {
    endCell();
    records.push({ line: recordLine, cells });
    cells = [];
  };

  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') { cell += '"'; i += 1; } else inQuotes = false;
      } else {
        if (ch === '\n') line += 1;
        cell += ch;
      }
      continue;
    }
    if (ch === '"' && cell.trim() === '' && !quotedCell) {
      inQuotes = true;
      quotedCell = true;
      quoteOpenedOn = line;
      cell = '';
    } else if (ch === delimiter) {
      endCell();
    } else if (ch === '\r' || ch === '\n') {
      if (ch === '\r' && text[i + 1] === '\n') i += 1;
      endRecord();
      line += 1;
      recordLine = line;
    } else if (!(quotedCell && (ch === ' ' || ch === '\t'))) {
      // Characters after a closing quote other than blanks are kept, which
      // is what a spreadsheet does with `"a"b`; blanks there are dropped.
      cell += ch;
    }
  }
  if (inQuotes) {
    throw new SiteImportFileError([`a quoted cell opened on line ${quoteOpenedOn} is never closed`]);
  }
  if (cell !== '' || cells.length > 0 || quotedCell) endRecord();
  return { delimiter, records };
}

// ============================================================================
// Header
// ============================================================================

const FIXED_COLUMNS = [
  'code', 'name', 'country', 'timezone', 'address', 'contact', SITE_UPLINK_CSV_COLUMN, OPENING_HOURS_CSV_COLUMN,
  SITE_FIXED_PROVIDER_CSV_COLUMN,
] as const;
type FixedColumn = (typeof FIXED_COLUMNS)[number];
/** The fixed columns, in the order the CSV template and the orphans workbook
 *  (`orphansImportXlsx`) write them: ONE list, so a file this server hands out
 *  is a file this import reads back as it is. */
export const SITE_IMPORT_FIXED_COLUMNS: readonly string[] = FIXED_COLUMNS;

export interface ImportColumns {
  fixed: Partial<Record<FixedColumn, number>>;
  vars: { key: string; index: number }[];
}

/** Column names are matched case-insensitively; a `var:` key is kept as
 *  typed, because variable keys are case-sensitive.
 *
 *  A problem names a column by its POSITION, never by its text: when the
 *  header line is missing, the first data row is read as the header, and its
 *  cells may be customer data or a secret. Only a name this function itself
 *  recognised (one of FIXED_COLUMNS) is ever spelled out. */
export function mapHeader(header: readonly string[]): ImportColumns {
  const problems: string[] = [];
  const fixed: ImportColumns['fixed'] = {};
  const vars: ImportColumns['vars'] = [];
  const seen = new Map<string, number>();
  header.forEach((raw, index) => {
    const name = raw.trim();
    const col = index + 1;
    if (name === '') {
      problems.push(`column ${col} has no name`);
      return;
    }
    if (/^var:/i.test(name)) {
      const key = name.slice(4).trim();
      if (key === '') { problems.push(`column ${col} is "var:" without a variable key`); return; }
      const id = `var:${key}`;
      const first = seen.get(id);
      if (first !== undefined) {
        problems.push(`column ${col} repeats the variable of column ${first}`);
        return;
      }
      seen.set(id, col);
      vars.push({ key, index });
      return;
    }
    const lower = name.toLowerCase() as FixedColumn;
    if (!(FIXED_COLUMNS as readonly string[]).includes(lower)) {
      problems.push(
        `column ${col} is not recognised (expected ${FIXED_COLUMNS.join(', ')} or var:<key>)`,
      );
      return;
    }
    if (seen.has(lower)) { problems.push(`column "${lower}" appears more than once`); return; }
    seen.set(lower, col);
    fixed[lower] = index;
  });
  if (fixed.code === undefined) problems.push('the "code" column is missing');
  if (fixed.name === undefined) problems.push('the "name" column is missing');
  if (problems.length > 0) throw new SiteImportFileError(problems);
  return { fixed, vars };
}

// ============================================================================
// Rows — pure judgement
// ============================================================================

/** An IANA zone name ("Europe/Paris", "UTC"). Offsets such as "+01:00" are
 *  refused on shape even where Intl would accept them: a fixed offset does not
 *  follow daylight saving, and a maintenance window computed with one is wrong
 *  half the year. */
const TIMEZONE_SHAPE = /^[A-Za-z][A-Za-z0-9_+-]*(\/[A-Za-z0-9_+-]+)*$/;
export function isIanaTimeZone(tz: string): boolean {
  if (tz.length > TIMEZONE_MAX || !TIMEZONE_SHAPE.test(tz)) return false;
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

function primaryType(schema: Record<string, unknown> | undefined): string | null {
  const t = schema?.type;
  if (typeof t === 'string') return t;
  if (Array.isArray(t)) {
    const first = t.find((x) => typeof x === 'string' && x !== 'null');
    return typeof first === 'string' ? first : null;
  }
  return null;
}

/**
 * A CSV cell is text; a declared variable may be a number, a boolean or a
 * list. Convert ONLY when the text is unambiguously of the declared type and
 * hand the text through otherwise — ajv then refuses it on its type, with the
 * declaration's own message. The emptiness test is done by the caller on the
 * trimmed text, never by `Number()`: `Number(' ')` is 0.
 */
export function coerceCell(text: string, decl: DeclaredSiteKey | undefined): unknown {
  switch (primaryType(decl?.schema)) {
    case 'integer':
      if (/^[+-]?\d{1,15}$/.test(text)) return Number(text);
      return text;
    case 'number':
      if (/^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?$/.test(text)) return Number(text);
      // A French spreadsheet writes "1,5".
      if (/^[+-]?\d+,\d+$/.test(text)) return Number(text.replace(',', '.'));
      return text;
    case 'boolean': {
      const l = text.toLowerCase();
      if (['true', 'vrai', 'oui', 'yes', '1'].includes(l)) return true;
      if (['false', 'faux', 'non', 'no', '0'].includes(l)) return false;
      return text;
    }
    case 'array':
    case 'object':
      try {
        const parsed = JSON.parse(text) as unknown;
        return parsed !== null && typeof parsed === 'object' ? parsed : text;
      } catch {
        return text;
      }
    default:
      return text;
  }
}

/** Key-order-independent JSON, to compare a cell with a stored value. */
function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v !== null && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`).join(',')}}`;
  }
  return JSON.stringify(v) ?? 'null';
}

export type SiteImportAction = 'create' | 'update' | 'skip';

export interface SiteImportAllocation {
  status: 'allocated' | 'existing' | 'failed';
  pppUsername?: string;
  tunnelIp?: string;
  lanSubnet?: string | null;
  /** `AllocationError.reason`, or 'ERROR' for anything else. */
  reason?: string;
  message?: string;
  /** 'allocated' and 'existing': the allocator's `warnings`, verbatim (an
   *  adoption from the CHR, a formula address that differs from the deployed
   *  one, the shared-password assumption). Empty when there is nothing to say. */
  warnings?: string[];
}

/** The zeros Excel stripped, given back under the tenant's 'digits:N' format. */
export interface SiteImportCodeRestored {
  /** The cell as read ("102"). */
  from: string;
  /** The code written ("00102"). */
  to: string;
  /** The same fact as a French sentence: "102 -> 00102 (zéros rétablis)". */
  note: string;
}

export interface SiteImportRowResult {
  line: number;
  /** The code the row writes: the cell verbatim, except when zeros were
   *  restored (then `codeRestored` holds the cell). */
  code: string;
  /** Present only when the code written is not the cell as read. */
  codeRestored?: SiteImportCodeRestored;
  action: SiteImportAction;
  /** Empty when the row is valid. Never carries a variable value. */
  errors: string[];
  /** What would change / changed: `name`, `country`, …, `var:<key>`. */
  changes: string[];
  /** true once the row's transaction committed (always false in dry-run). */
  applied: boolean;
  siteId: number | null;
  /** Present only when allocation was requested and the row has a site. */
  allocation?: SiteImportAllocation;
  /**
   * Dry run, for a caller allowed to see CHR matching, when the comparison
   * ran (`SiteImportResult.chr.status === 'compared'`): what the row's site
   * would be to the CHR — "takes over <login>", "new", "suspect: looks like
   * <login> (<reasons>)" (reconcile.service `ChrRowVerdict`). A row whose code
   * was refused, or repeats an earlier line's, has none. Never an error: a
   * SUSPECT row is written like any other, and the allocator still adopts an
   * account only when the login is exactly its name.
   */
  chr?: ChrRowVerdict;
}

/** How a dry run compared the file with the CHR. Absent from the result when
 *  the caller may not see CHR matching. */
export type SiteImportChrSummary =
  | {
      status: 'compared';
      /** The policy CHR's last /ppp/secret read the rows were compared with. */
      readAt: string;
      ageSeconds: number;
      freshness: SeedFreshness;
      /** false: the template names no tenant, so an account it reads may be
       *  another customer's (platform admin only — a tenant user is refused). */
      namesTenant: boolean;
      pattern: string;
      counts: Record<ChrRowKind, number>;
    }
  /** The policy CHR was never read: there is nothing to compare with yet. */
  | { status: 'neverRead'; message: string }
  /** A tenant user's comparison, refused because the template names no tenant. */
  | { status: 'refused'; reason: 'TEMPLATE_NAMES_NO_TENANT'; message: string }
  /** No comparison can be built (no policy, an invalid template, no domain…). */
  | { status: 'unavailable'; reason: string; message: string };

export interface SiteImportResult {
  dryRun: boolean;
  allocate: boolean;
  delimiter: CsvDelimiter;
  variableKeys: string[];
  /** See `SiteImportChrSummary`. */
  chr?: SiteImportChrSummary;
  rows: SiteImportRowResult[];
  /** create / update / skip count the rows WITHOUT errors; `rejected` the
   *  rows with at least one (refused on reading, or on writing). */
  summary: {
    rows: number;
    create: number;
    update: number;
    skip: number;
    rejected: number;
    applied: number;
    allocated: number;
    allocationFailed: number;
    /** Rows (refused or not) whose code had its zeros restored. */
    codesRestored: number;
  };
}

/** One row once read, before anything is compared with the database. */
interface ParsedRow {
  line: number;
  /** The code the row writes (zeros restored when the format says so). */
  code: string;
  /** The cell as read, when it is not `code`; null otherwise. */
  restoredFrom: string | null;
  /** `code` passed the format and the shape: only then is it compared with
   *  the tenant's other site numbers. */
  codeOk: boolean;
  fields: {
    name: string;
    country?: string | null;
    timezone?: string;
    address?: string;
    contact?: string;
    /** The `uplink` cell: null = `auto` (back to "not declared"). Absent =
     *  empty cell, changes nothing. */
    uplinkKind?: SiteUplinkKind | null;
    /** The `horaires` cell: null = `hérité` (back to the workspace's hours).
     *  Absent = empty cell, changes nothing. */
    openingHours?: OpeningHours | null;
    /** The `operateur` cell (« Opérateur du lien fixe », migration 095).
     *  Absent = empty cell, changes nothing. */
    fixedProvider?: string;
  };
  entries: { key: string; value: unknown }[];
  errors: string[];
}

function readRow(
  rec: CsvRecord,
  cols: ImportColumns,
  width: number,
  declared: Map<string, DeclaredSiteKey>,
  codeFormat: SiteCodeFormat,
): ParsedRow {
  const errors: string[] = [];
  const cell = (i: number | undefined): string => (i === undefined ? '' : (rec.cells[i] ?? ''));
  if (rec.cells.length > width && rec.cells.slice(width).some((c) => c !== '')) {
    errors.push(
      `has ${rec.cells.length} cells but the header has ${width} — an unquoted delimiter inside a cell?`,
    );
  }

  // U+FFFD is what a UTF-8 decoder writes in place of a byte it could not
  // decode: a Windows-1252 file (Excel's "CSV (séparateur : point-virgule)")
  // read as UTF-8 turns every accented letter into it. Writing such a cell
  // would overwrite a correct name or address with a damaged one, so the row
  // is refused. The client decodes Windows-1252 itself; this is the barrier
  // for the paste path and for any other caller. Names the column, never the
  // cell.
  const columnName = new Map<number, string>();
  for (const [n, i] of Object.entries(cols.fixed)) if (i !== undefined) columnName.set(i, n);
  for (const v of cols.vars) columnName.set(v.index, `var:${v.key}`);
  rec.cells.forEach((c, i) => {
    if (c.includes('�')) {
      errors.push(
        `${columnName.get(i) ?? `column ${i + 1}`}: contains an unreadable character (U+FFFD) — the file was not saved as UTF-8`,
      );
    }
  });

  // The tenant's format first (it knows Excel's artefacts and restores the
  // stripped zeros), then the schema's shape on the code it returns.
  let code = cell(cols.fixed.code);
  let restoredFrom: string | null = null;
  let codeOk = false;
  if (code === '') errors.push('code: required');
  else if (code.length > SITE_CODE_MAX) errors.push(`code: longer than ${SITE_CODE_MAX} characters`);
  else {
    const verdict = judgeSiteCode(code, codeFormat, { restoreZeros: true });
    if (!verdict.ok) errors.push(verdict.error);
    else {
      code = verdict.code;
      restoredFrom = verdict.restoredFrom;
      if (!SITE_CODE_RE.test(code)) errors.push(`code: ${SITE_CODE_SHAPE_MESSAGE}`);
      else codeOk = true;
    }
  }

  const name = cell(cols.fixed.name);
  if (name === '') errors.push('name: required');
  else if (name.length > NAME_MAX) errors.push(`name: longer than ${NAME_MAX} characters`);

  const fields: ParsedRow['fields'] = { name };

  const countryText = cell(cols.fixed.country);
  if (countryText !== '') {
    const c = normalizeCountry(countryText);
    if (c.ok) fields.country = c.country;
    else errors.push('country: not an ISO 3166-1 alpha-2 code (two letters)');
  }
  const tz = cell(cols.fixed.timezone);
  if (tz !== '') {
    if (isIanaTimeZone(tz)) fields.timezone = tz;
    else errors.push('timezone: not an IANA time zone name (e.g. Europe/Paris)');
  }
  const address = cell(cols.fixed.address);
  if (address !== '') {
    if (address.length > ADDRESS_MAX) errors.push(`address: longer than ${ADDRESS_MAX} characters`);
    else fields.address = address;
  }
  const contact = cell(cols.fixed.contact);
  if (contact !== '') {
    if (contact.length > CONTACT_MAX) errors.push(`contact: longer than ${CONTACT_MAX} characters`);
    else fields.contact = contact;
  }
  const uplink = cell(cols.fixed.uplink);
  if (uplink !== '') {
    const parsed = parseSiteUplinkCell(uplink);
    // Names the column and the accepted values, never the cell (see mapHeader).
    if (parsed.ok) fields.uplinkKind = parsed.kind;
    else errors.push(UPLINK_CELL_REFUSED);
  }
  const hours = cell(cols.fixed[OPENING_HOURS_CSV_COLUMN]).trim();
  if (hours !== '') {
    if ((OPENING_HOURS_INHERIT_WORDS as readonly string[]).includes(hours.toLowerCase())) {
      fields.openingHours = null;
    } else {
      const parsed = parseOpeningHoursText(hours);
      // The parser's message quotes the group at fault: opening hours are not
      // customer secrets, and "« sam 10h-25h »" is what the operator must fix.
      if (parsed.ok) fields.openingHours = parsed.value;
      else errors.push(`${OPENING_HOURS_CSV_COLUMN} : ${parsed.error} — attendu par exemple « lun-ven 09:00-12:00,14:00-19:00; sam 10:00-18:00; dim fermé; 2026-12-25 fermé », ou « hérité »`);
    }
  }
  // « Opérateur du lien fixe » (migration 095): an empty cell changes nothing
  // (the import's rule); clearing it is done from the site page or in bulk.
  const provider = cell(cols.fixed[SITE_FIXED_PROVIDER_CSV_COLUMN]);
  if (provider.trim() !== '') {
    const parsed = normalizeFixedProvider(provider);
    // Names the column and the rule, never the cell (see mapHeader).
    if (parsed.ok && parsed.value !== null) fields.fixedProvider = parsed.value;
    else if (!parsed.ok) errors.push(`${SITE_FIXED_PROVIDER_CSV_COLUMN} : ${parsed.error}`);
  }

  const entries: ParsedRow['entries'] = [];
  for (const v of cols.vars) {
    const text = cell(v.index);
    if (text === '') continue;
    entries.push({ key: v.key, value: coerceCell(text, declared.get(v.key)) });
  }

  return { line: rec.line, code, restoredFrom, codeOk, fields, entries, errors };
}

/** The row error of an `uplink` cell this import does not know, in French. */
export const UPLINK_CELL_REFUSED =
  'uplink : valeur non reconnue — attendu auto (non déclaré), fixe (fixe + secours 4G) ou 4g (4G uniquement) ; ' +
  'fixed et cellular_only sont aussi acceptés';

/** Which columns of an existing site the row would change. Empty cells were
 *  never put in `fields`, so they change nothing; an `uplink` restating the
 *  stored declaration is not a change (its "who and when" stay). */
function changedColumns(row: ParsedRow, site: SiteRow): UpdateSiteData {
  const out: UpdateSiteData = {};
  const f = row.fields;
  if (f.name !== site.name) out.name = f.name;
  if (f.country !== undefined && f.country !== site.country) out.country = f.country;
  if (f.timezone !== undefined && f.timezone !== site.timezone) out.timezone = f.timezone;
  if (f.address !== undefined && f.address !== site.address) out.address = f.address;
  if (f.contact !== undefined && f.contact !== site.contact) out.contact = f.contact;
  if (f.uplinkKind !== undefined && f.uplinkKind !== (site.uplink_kind ?? null)) out.uplinkKind = f.uplinkKind;
  if (f.openingHours !== undefined && JSON.stringify(f.openingHours) !== JSON.stringify(readOpeningHours(site.opening_hours))) {
    out.openingHours = f.openingHours;
  }
  if (f.fixedProvider !== undefined && f.fixedProvider !== (site.fixed_provider ?? null)) out.fixedProvider = f.fixedProvider;
  return out;
}

/** A change as the result names it: the CSV column, as for every other field. */
function changeName(key: string): string {
  return key === 'uplinkKind'
    ? SITE_UPLINK_CSV_COLUMN
    : key === 'openingHours'
      ? OPENING_HOURS_CSV_COLUMN
      : key === 'fixedProvider'
        ? SITE_FIXED_PROVIDER_CSV_COLUMN
        : key;
}

/** The variable entries that would change. A SECRET always counts as a
 *  change: comparing it would mean reading the stored plaintext back, and the
 *  import never does. */
function changedEntries(
  entries: ParsedRow['entries'],
  current: Record<string, { value: JsonValue; isSecret: boolean }>,
  declared: Map<string, DeclaredSiteKey>,
): ParsedRow['entries'] {
  return entries.filter((e) => {
    const cur = current[e.key];
    if (!cur || cur.isSecret || declared.get(e.key)?.secret) return true;
    return canonical(cur.value) !== canonical(e.value);
  });
}

function judgeEntries(
  decls: readonly SiteVariableDeclaration[],
  entries: ParsedRow['entries'],
): { errors: string[]; verdict: ReturnType<typeof validateSiteValues> } {
  const verdict = validateSiteValues(decls, { entries });
  // `SiteValueError` names the key and never the value (variableResolver).
  return { errors: verdict.errors.map((e) => `var:${e.key}: ${e.message}`), verdict };
}

// ============================================================================
// Declarations
// ============================================================================

/** The same rows, in the same order, `setSiteValues` judges against. */
async function loadDeclarations(
  executor: Knex | Knex.Transaction,
  tenantId: number,
): Promise<SiteVariableDeclaration[]> {
  const rows = (await siteDeclarationsQuery(executor, tenantId)) as {
    revision_id: string | number;
    revision: number;
    tenant_id: number | null;
    var_schema: unknown;
    template_id: string | number;
    template_name: string;
  }[];
  return rows.map((r) => ({
    templateId: Number(r.template_id),
    templateName: r.template_name,
    revisionId: Number(r.revision_id),
    revision: Number(r.revision),
    library: r.tenant_id === null,
    varSchema: (r.var_schema !== null && typeof r.var_schema === 'object' && !Array.isArray(r.var_schema)
      ? r.var_schema
      : {}) as VarSchema,
  }));
}

/** The site variables a CSV template should offer: every declared key the
 *  site form accepts. */
export interface ImportTemplateVariable {
  key: string;
  label: string | null;
  secret: boolean;
  type: string | null;
  required: boolean;
}

export async function describeImportTemplate(tenantId: number): Promise<{
  columns: string[];
  variables: ImportTemplateVariable[];
}> {
  const declared = declaredSiteKeys(await loadDeclarations(db, tenantId));
  const variables = [...declared.values()]
    .filter((d) => d.siteWritable && !d.secrecyConflict)
    .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0))
    .map((d) => ({
      key: d.key,
      label: d.label,
      secret: d.secret,
      type: primaryType(d.schema),
      required: false,
    }));
  return {
    columns: [...FIXED_COLUMNS, ...variables.map((v) => `var:${v.key}`)],
    variables,
  };
}

// ============================================================================
// The import
// ============================================================================

export interface SiteImportOptions {
  dryRun: boolean;
  allocate: boolean;
  /** The caller holds SITE_VARIABLES_WRITE (checked by the controller). */
  canWriteVariables: boolean;
  /**
   * The caller holds SITE_SCHEDULE_CAPABILITY (checked by the controller).
   * Without it, a row that would MOVE an existing site's timezone is refused.
   * Absent means NO: a caller that forgets it gets refusals, never a wider
   * import.
   */
  canWriteSchedule?: boolean;
  /**
   * The dry run's comparison with the CHR (checked by the controller): 'full'
   * for a platform admin, 'redacted' for a holder of RECONCILE_READ (refused
   * when the template names no tenant; no blocker codes, no slug-only
   * near-match). Absent means NO comparison and no `chr` field anywhere in
   * the result. Ignored on a real run.
   */
  chr?: 'full' | 'redacted';
  updatedBy: number | null;
  /**
   * DRY RUN ONLY (ignored when `dryRun` is false): the code format to judge
   * the file against instead of the stored one — the Quick Setup check, when
   * the same request saves a new code format before the sites are written.
   * The apply always reads the stored format of the moment it writes.
   */
  codeFormatOverride?: SiteCodeFormat;
  /**
   * DRY RUN ONLY (ignored when `dryRun` is false): declarations judged as if
   * they were published, NEWEST, ahead of the published ones — the Quick
   * Setup check, when the same request publishes a revision before the sites
   * are written. The apply judges against what is actually published.
   */
  extraDeclarations?: SiteVariableDeclaration[];
}

/** Read and judge the whole file, without writing. Shared by dry-run and
 *  apply, so the apply can never accept a row the dry-run showed refused. */
async function plan(tenantId: number, csv: string, opts: SiteImportOptions) {
  if (csv.length > SITE_IMPORT_MAX_CHARS) {
    throw new SiteImportFileError([`the file is larger than ${SITE_IMPORT_MAX_CHARS} characters`]);
  }
  const { delimiter, records } = parseCsv(csv);
  const nonBlank = records.filter((r) => r.cells.some((c) => c !== ''));
  if (nonBlank.length === 0) throw new SiteImportFileError(['the file is empty']);
  const [header, ...body] = nonBlank;
  const cols = mapHeader(header.cells);
  if (body.length > SITE_IMPORT_MAX_ROWS) {
    throw new SiteImportFileError([`more than ${SITE_IMPORT_MAX_ROWS} rows`]);
  }

  // The two overrides are the Quick Setup check's, when the same request
  // publishes a revision / saves a new code format before the sites are
  // written; a real run never takes them (see SiteImportOptions).
  const decls = [
    ...(opts.dryRun ? (opts.extraDeclarations ?? []) : []),
    ...(await loadDeclarations(db, tenantId)),
  ];
  const declared = declaredSiteKeys(decls);
  // Read again on every call, so the apply judges by the format of the moment
  // it writes, never by the one the dry-run saw.
  const codeFormat =
    opts.dryRun && opts.codeFormatOverride ? opts.codeFormatOverride : await loadSiteCodeFormat(db, tenantId);
  const rows = body.map((rec) => readRow(rec, cols, header.cells.length, declared, codeFormat));

  if (!opts.canWriteVariables && rows.some((r) => r.entries.length > 0)) {
    throw new SiteImportForbiddenError(
      'This file sets site variable values, which requires the SITE_VARIABLES_WRITE capability. ' +
        'Remove the var: columns (or empty them) to import the sites alone.',
    );
  }

  // Duplicate codes inside the file: the first one wins, the others refuse.
  const firstLine = new Map<string, number>();
  for (const r of rows) {
    if (r.code === '') continue;
    const prev = firstLine.get(r.code);
    if (prev !== undefined) r.errors.push(`code: already used on line ${prev} of this file`);
    else firstLine.set(r.code, r.line);
  }

  const codes = [...firstLine.keys()];
  const existing = new Map<string, SiteRow>();
  for (let i = 0; i < codes.length; i += 1000) {
    const chunk = (await db('sites')
      .where('tenant_id', tenantId)
      .whereIn('code', codes.slice(i, i + 1000))
      .select('*')) as SiteRow[];
    for (const s of chunk) existing.set(s.code, s);
  }
  // Under 'digits:N', the tenant's codes by site number: a "7" or a "0102"
  // created before the format is the same site number as the "00007" or the
  // "00102" a row writes, whether the cell was restored or typed exactly
  // (`siteNumber` drops leading zeros). Empty under 'free'.
  const byNumber = await loadSiteNumberIndex(db, tenantId, codeFormat);

  const results: SiteImportRowResult[] = [];
  const work: { row: ParsedRow; result: SiteImportRowResult; site: SiteRow | null }[] = [];
  for (const row of rows) {
    const site = existing.get(row.code);
    const result: SiteImportRowResult = {
      line: row.line,
      code: row.code,
      action: site ? 'update' : 'create',
      errors: [...row.errors],
      changes: [],
      applied: false,
      siteId: site ? site.id : null,
    };
    if (row.restoredFrom !== null) {
      result.codeRestored = {
        from: row.restoredFrom,
        to: row.code,
        note: restoredCodeNote(row.restoredFrom, row.code),
      };
    }
    // Another spelling of this site number already exists. No guess is safe:
    // a CREATE would make two sites of one number (restored cell or exact
    // one alike), updating the out-of-format site would keep its code, and a
    // restored cell that matches an existing site does not say which of the
    // two it means. An EXACT cell naming an existing site updates that site
    // and makes nothing new, so it passes.
    const siblings = row.codeOk ? siteNumberSiblings(row.code, byNumber) : [];
    if (siblings.length > 0) {
      if (!site) result.errors.push(siteNumberClashMessage(row.code, siblings));
      else if (row.restoredFrom !== null) {
        result.errors.push(ambiguousRestoredCodeMessage(row.restoredFrom, row.code, siblings));
      }
    }
    if (row.entries.length > 0) result.errors.push(...judgeEntries(decls, row.entries).errors);

    if (site) {
      const cols2 = changedColumns(row, site);
      if (opts.canWriteSchedule !== true && cols2.timezone !== undefined) {
        result.errors.push(TIMEZONE_CHANGE_REFUSED);
      }
      result.changes.push(...Object.keys(cols2).map(changeName));
      if (row.entries.length > 0) {
        const current = await variableResolver.getByScope(tenantId, 'site', site.id);
        for (const e of changedEntries(row.entries, current, declared)) result.changes.push(`var:${e.key}`);
      }
      if (result.changes.length === 0 && result.errors.length === 0) result.action = 'skip';
    } else {
      result.changes.push(...setFields(row), ...row.entries.map((e) => `var:${e.key}`));
    }
    results.push(result);
    work.push({ row, result, site: site ?? null });
  }

  return { delimiter, cols, work, results, declared };
}

/** Write one row: the site and its values, in ONE transaction. */
async function applyRow(
  tenantId: number,
  row: ParsedRow,
  declared: Map<string, DeclaredSiteKey>,
  updatedBy: number | null,
  canWriteSchedule: boolean,
): Promise<{ site: SiteRow; created: boolean; changes: string[] }> {
  return db.transaction(async (trx) => {
    const changes: string[] = [];
    if (row.entries.length > 0) await trx.raw(SITE_FORM_LOCK_SQL, { tenantId });

    const current = (await trx('sites')
      .where({ tenant_id: tenantId, code: row.code })
      .forUpdate()
      .first('*')) as SiteRow | undefined;

    let site: SiteRow;
    let created = false;
    if (current) {
      const cols = changedColumns(row, current);
      // Judged again on the LOCKED row: the timezone may have moved since the
      // plan read it (or the site may have been created meanwhile), and
      // writing the file's value back would be a schedule change too.
      if (!canWriteSchedule && cols.timezone !== undefined) throw new RowRefused([TIMEZONE_CHANGE_REFUSED]);
      changes.push(...Object.keys(cols).map(changeName));
      // A declaration is stamped with the importing user (076's set_at/by).
      if (cols.uplinkKind !== undefined) cols.uplinkKindSetBy = updatedBy;
      site = Object.keys(cols).length > 0
        ? ((await updateSiteRow(trx, tenantId, current.id, cols)) as SiteRow)
        : current;
    } else {
      // A new site is "not declared" already: `auto` on a create stamps nothing.
      const { uplinkKind, ...fields } = row.fields;
      site = await insertSiteRow(
        trx,
        tenantId,
        uplinkKind ? { code: row.code, ...fields, uplinkKind, uplinkKindSetBy: updatedBy } : { code: row.code, ...fields },
      );
      created = true;
      changes.push(...setFields(row));
    }

    if (row.entries.length > 0) {
      // Judged again on the declarations held by the lock: the dry-run's view
      // may be minutes old, and the declarations decide what goes to the vault.
      const { errors, verdict } = judgeEntries(await loadDeclarations(trx, tenantId), row.entries);
      if (errors.length > 0) throw new RowRefused(errors);
      const before = current
        ? await variableResolver.getByScope(tenantId, 'site', current.id)
        : {};
      const toWrite = new Set(changedEntries(row.entries, before, declared).map((e) => e.key));
      for (const w of verdict.writes) {
        if (!toWrite.has(w.key)) continue;
        await variableResolver._write(trx, tenantId, 'site', site.id, w.key, w.value, w.isSecret, {
          updatedBy,
        });
        changes.push(`var:${w.key}`);
      }
    }
    return { site, created, changes };
  });
}

/** The fields a create sets (empty cells were never put in `fields`; an
 *  `auto` uplink sets nothing on a new site). */
function setFields(row: ParsedRow): string[] {
  return Object.entries(row.fields)
    .filter(([, v]) => v !== undefined && v !== null)
    .map(([k]) => changeName(k));
}

/** For the server log: name, pg code and message, never a pg `detail`
 *  (which quotes the refused row). */
function describeError(err: unknown): Record<string, unknown> {
  if (!(err instanceof Error)) return { name: 'unknown' };
  return { name: err.name, code: (err as { code?: unknown }).code, message: err.message };
}

function isUniqueViolation(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: string }).code === '23505';
}

/**
 * Run the import. Throws `SiteImportFileError` (the file cannot be read) or
 * `SiteImportForbiddenError` (variable values without the capability); every
 * other refusal is reported on its row.
 */
export async function importSites(
  tenantId: number,
  csv: string,
  opts: SiteImportOptions,
): Promise<SiteImportResult> {
  const { delimiter, cols, work, results, declared } = await plan(tenantId, csv, opts);

  let chr: SiteImportChrSummary | undefined;
  if (opts.dryRun && opts.chr !== undefined) chr = await compareWithChr(tenantId, work, opts.chr);

  if (!opts.dryRun) {
    /** Sites this run declared 4G-only: their open backup alerts close below. */
    const declaredCellularOnly: number[] = [];
    for (const { row, result } of work) {
      if (result.errors.length > 0) continue;
      if (result.action !== 'skip') {
        try {
          const done = await applyRow(tenantId, row, declared, opts.updatedBy, opts.canWriteSchedule === true);
          result.applied = true;
          result.siteId = done.site.id;
          // What was actually written, which may differ from the plan if the
          // site changed between the read and the row's transaction.
          result.changes = done.changes;
          result.action = done.created ? 'create' : done.changes.length > 0 ? 'update' : 'skip';
          if (!done.created && row.fields.uplinkKind === 'cellular_only' && done.changes.includes(SITE_UPLINK_CSV_COLUMN)) {
            declaredCellularOnly.push(done.site.id);
          }
          emitToTenantAudience(
            tenantId,
            done.created ? SOCKET_EVENTS.SITE_CREATED : SOCKET_EVENTS.SITE_UPDATED,
            { site: toSiteDto(done.site) },
            { siteId: done.site.id },
          );
        } catch (err) {
          if (err instanceof RowRefused) {
            result.errors.push(...err.errors);
          } else if (isUniqueViolation(err)) {
            result.errors.push('code: a site with this code was created meanwhile — run the import again');
          } else {
            // The message of an unknown error is not relayed: a database error
            // detail can quote the row it refused.
            logger.error({ err: describeError(err), line: row.line }, 'site import: row failed');
            result.errors.push('the row could not be written (see the server log)');
          }
        }
      }
      if (opts.allocate && result.errors.length === 0 && result.siteId !== null) {
        result.allocation = await allocateOne(tenantId, result.siteId);
      }
    }
    if (declaredCellularOnly.length > 0) {
      // After every row committed, never undoing one: the next health check
      // would close them anyway (backup4g.service reads the declaration).
      await closeBackup4gForSites(tenantId, declaredCellularOnly).catch((err: unknown) =>
        logger.warn({ err: describeError(err) }, 'site import: open 4G backup alerts stay until the next check'),
      );
    }
  }

  const ok = results.filter((r) => r.errors.length === 0);
  return {
    dryRun: opts.dryRun,
    allocate: opts.allocate,
    delimiter,
    variableKeys: cols.vars.map((v) => v.key),
    ...(chr ? { chr } : {}),
    rows: results,
    summary: {
      rows: results.length,
      create: ok.filter((r) => r.action === 'create').length,
      update: ok.filter((r) => r.action === 'update').length,
      skip: ok.filter((r) => r.action === 'skip').length,
      rejected: results.length - ok.length,
      applied: results.filter((r) => r.applied).length,
      allocated: results.filter((r) => r.allocation?.status === 'allocated').length,
      allocationFailed: results.filter((r) => r.allocation?.status === 'failed').length,
      codesRestored: results.filter((r) => r.codeRestored !== undefined).length,
    },
  };
}

/** One isolated allocation. Never throws; never reports a password (the view
 *  carries none) nor an AllocationError's `holder` (another tenant's ids). */
async function allocateOne(tenantId: number, siteId: number): Promise<SiteImportAllocation> {
  try {
    const { provisioning, created, warnings } = await allocateForSite(siteId, { tenantId });
    return {
      status: created ? 'allocated' : 'existing',
      pppUsername: provisioning.pppUsername,
      tunnelIp: provisioning.tunnelIp,
      lanSubnet: provisioning.lanSubnet,
      // The allocator's own sentences (allocator.ts `storedWarnings`, policy.ts
      // `adoptDeclared`): they name the site, its CHR, its addresses, profile
      // and pool — never a password, and no holder of another tenant.
      warnings: [...warnings],
    };
  } catch (err) {
    if (err instanceof AllocationError) {
      return { status: 'failed', reason: err.reason, message: err.message };
    }
    logger.error({ err: describeError(err), siteId }, 'site import: allocation failed');
    return { status: 'failed', reason: 'ERROR', message: 'allocation failed (see the server log)' };
  }
}

// ============================================================================
// The dry run against the CHR, and the orphans as an import file
// ============================================================================

/** Sentences for a tenant user, whose comparison must not relay the
 *  allocation engine's own (they name the policy's template and its parse
 *  error, which are the platform admin's). */
const CHR_NEVER_READ =
  "The concentrator's accounts have never been read, so no row can be compared with the CHR yet. " +
  'This check dials nothing: it compares with the last recorded read only.';
const CHR_NO_POLICY_REDACTED =
  'No address allocation policy is set for this workspace: there is no login rule to compare the rows with.';
const CHR_UNAVAILABLE_REDACTED =
  "This workspace's login rule cannot be evaluated right now; a platform administrator can see why.";

/**
 * The CHR column of a dry run: each row as reconcile.service's ONE classifier
 * (`classifyProposedSites`) sees it once written — the rows laid over the
 * stored sites, against the LAST recorded /ppp/secret read, whose age is
 * returned. Dials nothing, writes nothing, and never refuses a row: the
 * verdict is information, the row's `errors` are unchanged. A comparison that
 * cannot be built says why on the result instead of failing the dry run.
 *
 * The rows compared are those whose code passed (the zeros a 'digits:N'
 * format restores included, so a code is compared as it would be written),
 * each code once — the first line, as the import itself keeps it. An update
 * row keeps the stored country when its cell is empty ("an empty cell never
 * erases anything"), and the stored name when its name cell is empty (that
 * row is refused anyway).
 */
async function compareWithChr(
  tenantId: number,
  work: ReadonlyArray<{ row: ParsedRow; result: SiteImportRowResult; site: SiteRow | null }>,
  mode: 'full' | 'redacted',
): Promise<SiteImportChrSummary> {
  const seen = new Set<string>();
  const proposed: ProposedSite[] = [];
  const resultOf = new Map<number, SiteImportRowResult>();
  for (const { row, result, site } of work) {
    if (!row.codeOk || seen.has(row.code)) continue;
    seen.add(row.code);
    const name = row.fields.name !== '' ? row.fields.name : (site?.name ?? '');
    const country = row.fields.country !== undefined ? row.fields.country : (site?.country ?? null);
    proposed.push({ ref: row.line, siteId: site ? site.id : null, code: row.code, name, country });
    resultOf.set(row.line, result);
  }

  let comparison: Awaited<ReturnType<typeof classifyProposedSites>>;
  try {
    comparison = await classifyProposedSites(tenantId, proposed);
  } catch (err) {
    if (err instanceof AllocationError) {
      if (mode === 'full') return { status: 'unavailable', reason: err.reason, message: err.message };
      return {
        status: 'unavailable',
        reason: err.reason,
        message: err.reason === 'NO_POLICY' ? CHR_NO_POLICY_REDACTED : CHR_UNAVAILABLE_REDACTED,
      };
    }
    // The comparison is advisory: a failure of it must not cost the operator
    // the dry run itself. Its detail stays in the log (it may quote a row).
    logger.error({ err: describeError(err) }, 'site import: CHR comparison failed');
    return { status: 'unavailable', reason: 'ERROR', message: 'the comparison with the CHR failed (see the server log)' };
  }

  if (mode === 'redacted' && !comparison.namesTenant) {
    return { status: 'refused', reason: 'TEMPLATE_NAMES_NO_TENANT', message: TEMPLATE_NAMES_NO_TENANT_MESSAGE };
  }
  if (comparison.readAt === null) return { status: 'neverRead', message: CHR_NEVER_READ };

  const counts: Record<ChrRowKind, number> = { takesOver: 0, allocated: 0, new: 0, suspect: 0, noLogin: 0 };
  for (const v of comparison.verdicts) {
    const result = resultOf.get(v.ref);
    if (!result) continue;
    result.chr = mode === 'full' ? v : redactVerdict(v);
    counts[v.kind] += 1;
  }
  return {
    status: 'compared',
    readAt: comparison.readAt,
    ageSeconds: Math.max(0, Math.floor((Date.parse(comparison.generatedAt) - Date.parse(comparison.readAt)) / 1000)),
    freshness: comparison.freshness,
    namesTenant: comparison.namesTenant,
    pattern: comparison.pattern,
    counts,
  };
}

/**
 * The reconciliation's orphans as a workbook THIS import reads back as it is:
 * the header is `SITE_IMPORT_FIXED_COLUMNS` and nothing else (an extra column
 * would be refused by `mapHeader`), one row per orphan with the code, the
 * country and — under a {site.slug} template only — the name read off the
 * account (reconcile.service `orphanImportRows`). The operator types the
 * names, saves, and imports it through the ordinary import, whose dry run
 * says, row by row, whether the site takes its account over — judged on the
 * inventory of THAT moment, by the allocator's own adoption rules restated,
 * never by this file: an orphan claimed meanwhile is simply no longer one.
 *
 * Every cell is TEXT (fleet/xlsx.ts writes no number): Excel keeps "0042" as
 * typed, and saving the sheet as CSV writes it as typed. Where it is
 * stripped anyway, a 'digits:N' code format gives the zeros back on import
 * and the row says so (`codeRestored`).
 */
export function orphansImportXlsx(report: ReconcileReport, timeZone: string): { buffer: Buffer; fileName: string } {
  const columns: XlsxColumn[] = SITE_IMPORT_FIXED_COLUMNS.map((header) => ({
    header,
    width: header === 'name' || header === 'address' ? 32 : header === 'timezone' ? 18 : 12,
    type: 'text',
  }));
  const rows = orphanImportRows(report).map((o) =>
    SITE_IMPORT_FIXED_COLUMNS.map((c) => (c === 'code' ? o.code : c === 'name' ? o.name : c === 'country' ? o.country : null)),
  );
  return {
    buffer: buildXlsx({ sheetName: 'Sites', columns, rows, timeZone }),
    fileName: orphansFileName(report, timeZone),
  };
}
