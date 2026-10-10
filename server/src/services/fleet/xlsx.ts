/**
 * ObliWAN — a minimal .xlsx (Office Open XML spreadsheet) writer.
 *
 * Why it exists: the site deployment export (`siteDeployment.service.ts`) must
 * hand an account manager a file Excel opens as a workbook, not a CSV that
 * Excel re-interprets on open (a site code "00001" read as the number 1, a
 * date read in the wrong order, a cell starting with "=" read as a formula).
 * No xlsx or zip library is a dependency of the server, and the format needed
 * here is small: ONE worksheet, text and dates, a bold frozen header with an
 * autofilter. So the package is written by hand — six XML parts in a ZIP whose
 * entries are deflated with `zlib.deflateRawSync` and checksummed with
 * `zlib.crc32` (added in Node 22.2 and 20.15; the image is node:24).
 *
 * ┌─ NO CELL IS EVER A FORMULA ──────────────────────────────────────────────┐
 * │ Every text cell is written as an INLINE STRING (`t="inlineStr"`), and    │
 * │ this module has no code path that emits an `<f>` element: a value such   │
 * │ as `=HYPERLINK("http://x")` is stored as those characters and displayed  │
 * │ as text, never evaluated. A text cell that STARTS with = + - @ (or a tab │
 * │ or a carriage return, the rest of the usual injection prefixes) also     │
 * │ gets the `quotePrefix` style — Excel's own "apostrophe" marker — so an    │
 * │ operator who opens the cell and presses Enter keeps it as text instead of │
 * │ having Excel re-parse it as a formula at that moment. The value itself   │
 * │ is never altered: no apostrophe is prepended to the data.                │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Dates are REAL Excel dates (a serial number with a date format), converted to
 * the wall-clock time of the time zone the caller names: an Excel date carries
 * no zone, so the conversion has to happen here, once, for the whole sheet.
 */

import zlib from 'node:zlib';

export type XlsxValue = string | number | Date | null | undefined;

export interface XlsxColumn {
  header: string;
  /** Column width in Excel character units. */
  width: number;
  /** 'date' cells must hold a Date (or null); 'text' cells a string/number. */
  type: 'text' | 'date';
}

export interface XlsxSheetInput {
  /** 1..31 characters, none of `[ ] : * ? / \` (Excel's rule for sheet names). */
  sheetName: string;
  columns: XlsxColumn[];
  rows: XlsxValue[][];
  /** IANA zone the dates are shown in, e.g. "Europe/Paris". */
  timeZone: string;
}

export const XLSX_CONTENT_TYPE =
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';

/** Cell styles, as indexes into `cellXfs` in styles.xml below. */
const STYLE_HEADER = 1;
const STYLE_DATE = 2;
const STYLE_TEXT_QUOTED = 3;

/** Excel refuses a cell longer than this. */
const CELL_MAX = 32_767;

/** The prefixes a spreadsheet may read as the start of a formula (OWASP's
 *  CSV-injection list). Matched on the first character of a text cell. */
const FORMULA_PREFIX = /^[=+\-@\t\r]/;

// ============================================================================
// XML text
// ============================================================================

/**
 * Text as XML 1.0 may carry it. Characters XML forbids (C0 controls other than
 * tab/LF/CR, lone surrogates, U+FFFE/U+FFFF) would make the whole part
 * unreadable, so they are replaced — controls by a space, the rest by U+FFFD.
 */
export function xmlText(value: string): string {
  let out = '';
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        out += value[i] + value[i + 1];
        i += 1;
      } else {
        out += '�';
      }
      continue;
    }
    if (code >= 0xdc00 && code <= 0xdfff) { out += '�'; continue; }
    if (code === 0xfffe || code === 0xffff) { out += '�'; continue; }
    if (code < 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d) { out += ' '; continue; }
    switch (value[i]) {
      case '&': out += '&amp;'; break;
      case '<': out += '&lt;'; break;
      case '>': out += '&gt;'; break;
      case '"': out += '&quot;'; break;
      default: out += value[i];
    }
  }
  return out;
}

/** "A", "B", ..., "Z", "AA", ... for a 0-based column index. */
export function columnLetter(index: number): string {
  let n = index + 1;
  let s = '';
  while (n > 0) {
    const r = (n - 1) % 26;
    s = String.fromCharCode(65 + r) + s;
    n = Math.floor((n - 1) / 26);
  }
  return s;
}

// ============================================================================
// Dates
// ============================================================================

const wallClockFormatters = new Map<string, Intl.DateTimeFormat>();

function wallClockFormatter(timeZone: string): Intl.DateTimeFormat {
  let f = wallClockFormatters.get(timeZone);
  if (!f) {
    f = new Intl.DateTimeFormat('en-US', {
      timeZone,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hourCycle: 'h23',
    });
    wallClockFormatters.set(timeZone, f);
  }
  return f;
}

/**
 * The Excel serial of an instant as a clock in `timeZone` reads it: days since
 * 1899-12-30 (the epoch that absorbs Excel's 1900 leap-year bug for every date
 * after February 1900), fraction = time of day.
 */
export function excelSerial(instant: Date, timeZone: string): number {
  const parts: Record<string, number> = {};
  for (const p of wallClockFormatter(timeZone).formatToParts(instant)) {
    if (p.type !== 'literal') parts[p.type] = Number(p.value);
  }
  const wallMs = Date.UTC(
    parts.year,
    parts.month - 1,
    parts.day,
    parts.hour,
    parts.minute,
    parts.second,
    instant.getUTCMilliseconds(),
  );
  return wallMs / 86_400_000 + 25_569;
}

/** The calendar date of an instant in `timeZone`, as YYYY-MM-DD. */
export function isoDateIn(instant: Date, timeZone: string): string {
  const serial = excelSerial(instant, timeZone);
  const wall = new Date((serial - 25_569) * 86_400_000);
  return wall.toISOString().slice(0, 10);
}

// ============================================================================
// The parts
// ============================================================================

const NS_MAIN = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main';
const NS_REL = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships';
const NS_PKG_REL = 'http://schemas.openxmlformats.org/package/2006/relationships';
const XML_HEAD = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n';

const CONTENT_TYPES =
  XML_HEAD +
  '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' +
  '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>' +
  '<Default Extension="xml" ContentType="application/xml"/>' +
  '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>' +
  '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' +
  '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>' +
  '</Types>';

const ROOT_RELS =
  XML_HEAD +
  `<Relationships xmlns="${NS_PKG_REL}">` +
  `<Relationship Id="rId1" Type="${NS_REL}/officeDocument" Target="xl/workbook.xml"/>` +
  '</Relationships>';

const WORKBOOK_RELS =
  XML_HEAD +
  `<Relationships xmlns="${NS_PKG_REL}">` +
  `<Relationship Id="rId1" Type="${NS_REL}/worksheet" Target="worksheets/sheet1.xml"/>` +
  `<Relationship Id="rId2" Type="${NS_REL}/styles" Target="styles.xml"/>` +
  '</Relationships>';

// cellXfs: 0 default · 1 bold header · 2 date-time · 3 text with quotePrefix.
const STYLES =
  XML_HEAD +
  `<styleSheet xmlns="${NS_MAIN}">` +
  '<numFmts count="1"><numFmt numFmtId="164" formatCode="dd/mm/yyyy hh:mm"/></numFmts>' +
  '<fonts count="2">' +
  '<font><sz val="11"/><name val="Calibri"/><family val="2"/></font>' +
  '<font><b/><sz val="11"/><name val="Calibri"/><family val="2"/></font>' +
  '</fonts>' +
  '<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>' +
  '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>' +
  '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>' +
  '<cellXfs count="4">' +
  '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>' +
  '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>' +
  '<xf numFmtId="164" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/>' +
  '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" quotePrefix="1"/>' +
  '</cellXfs>' +
  '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>' +
  '</styleSheet>';

function assertSheetName(name: string): void {
  if (name.length < 1 || name.length > 31 || /[[\]:*?/\\]/.test(name)) {
    throw new Error(`invalid worksheet name: ${JSON.stringify(name)}`);
  }
}

function workbookXml(sheetName: string, filterRef: string): string {
  // The defined name is what Excel itself writes beside an autofilter; some
  // readers expect it. The sheet name is quoted, with ' doubled.
  const quoted = `'${sheetName.replace(/'/g, "''")}'`;
  // <bookViews> is optional in the schema, but the sheet's <sheetView> names
  // workbookViewId="0", and that index must point at a declared view. It sits
  // before <sheets>: CT_Workbook is a sequence, and the order is part of it.
  return (
    XML_HEAD +
    `<workbook xmlns="${NS_MAIN}" xmlns:r="${NS_REL}">` +
    '<bookViews><workbookView activeTab="0"/></bookViews>' +
    `<sheets><sheet name="${xmlText(sheetName)}" sheetId="1" r:id="rId1"/></sheets>` +
    '<definedNames>' +
    `<definedName name="_xlnm._FilterDatabase" localSheetId="0" hidden="1">${xmlText(`${quoted}!${filterRef}`)}</definedName>` +
    '</definedNames>' +
    '</workbook>'
  );
}

function textCell(ref: string, value: string, style: number | null): string {
  const text = value.length > CELL_MAX ? value.slice(0, CELL_MAX) : value;
  const s = style ?? (FORMULA_PREFIX.test(text) ? STYLE_TEXT_QUOTED : null);
  const space = /^\s|\s$/.test(text) ? ' xml:space="preserve"' : '';
  return `<c r="${ref}"${s === null ? '' : ` s="${s}"`} t="inlineStr"><is><t${space}>${xmlText(text)}</t></is></c>`;
}

function sheetXml(input: XlsxSheetInput): { xml: string; filterRef: string } {
  const { columns, rows, timeZone } = input;
  const lastCol = columnLetter(Math.max(columns.length - 1, 0));
  const lastRow = rows.length + 1;
  const absRef = `$A$1:$${lastCol}$${lastRow}`;

  const parts: string[] = [];
  parts.push(XML_HEAD + `<worksheet xmlns="${NS_MAIN}" xmlns:r="${NS_REL}">`);
  parts.push(`<dimension ref="A1:${lastCol}${lastRow}"/>`);
  parts.push(
    '<sheetViews><sheetView tabSelected="1" workbookViewId="0">' +
      '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>' +
      '<selection pane="bottomLeft" activeCell="A2" sqref="A2"/>' +
      '</sheetView></sheetViews>',
  );
  parts.push('<sheetFormatPr defaultRowHeight="15"/>');
  parts.push('<cols>');
  columns.forEach((c, i) => {
    parts.push(`<col min="${i + 1}" max="${i + 1}" width="${c.width}" customWidth="1"/>`);
  });
  parts.push('</cols>');

  parts.push('<sheetData>');
  parts.push('<row r="1">');
  columns.forEach((c, i) => parts.push(textCell(`${columnLetter(i)}1`, c.header, STYLE_HEADER)));
  parts.push('</row>');
  rows.forEach((row, r) => {
    const rowNumber = r + 2;
    parts.push(`<row r="${rowNumber}">`);
    columns.forEach((col, i) => {
      const value = row[i];
      if (value === null || value === undefined || value === '') return;
      const ref = `${columnLetter(i)}${rowNumber}`;
      if (value instanceof Date) {
        if (Number.isNaN(value.getTime())) return;
        parts.push(`<c r="${ref}" s="${STYLE_DATE}"><v>${excelSerial(value, timeZone)}</v></c>`);
        return;
      }
      if (col.type === 'date') {
        throw new Error(`column "${col.header}" is a date column and row ${rowNumber} holds a non-date`);
      }
      // Numbers are written as text too: every value this export carries is
      // an identifier or a label, and a code like "00001" must keep its zeros.
      parts.push(textCell(ref, String(value), null));
    });
    parts.push('</row>');
  });
  parts.push('</sheetData>');
  parts.push(`<autoFilter ref="A1:${lastCol}${lastRow}"/>`);
  parts.push('</worksheet>');
  return { xml: parts.join(''), filterRef: absRef };
}

// ============================================================================
// ZIP container
// ============================================================================

interface ZipEntry {
  name: string;
  data: Buffer;
}

function dosDateTime(at: Date): { time: number; date: number } {
  const year = Math.max(at.getUTCFullYear(), 1980);
  return {
    time: (at.getUTCHours() << 11) | (at.getUTCMinutes() << 5) | Math.floor(at.getUTCSeconds() / 2),
    date: ((year - 1980) << 9) | ((at.getUTCMonth() + 1) << 5) | at.getUTCDate(),
  };
}

/**
 * A ZIP archive (PKWARE APPNOTE, no ZIP64: an export of a few hundred sites is
 * nowhere near 4 GB). Entries are deflated unless deflate would not shrink
 * them, in which case they are stored.
 */
export function zipArchive(entries: ZipEntry[], at: Date = new Date()): Buffer {
  const { time, date } = dosDateTime(at);
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;

  for (const entry of entries) {
    const name = Buffer.from(entry.name, 'utf8');
    const crc = zlib.crc32(entry.data) >>> 0;
    const deflated = zlib.deflateRawSync(entry.data, { level: 9 });
    const stored = deflated.length >= entry.data.length;
    const body = stored ? entry.data : deflated;
    const method = stored ? 0 : 8;

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed: 2.0 (deflate)
    local.writeUInt16LE(0x0800, 6); // bit 11: names are UTF-8
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(time, 10);
    local.writeUInt16LE(date, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(entry.data.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    locals.push(local, name, body);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4); // made by: 2.0, MS-DOS attributes
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt16LE(time, 12);
    central.writeUInt16LE(date, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(body.length, 20);
    central.writeUInt32LE(entry.data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(0, 30); // extra
    central.writeUInt16LE(0, 32); // comment
    central.writeUInt16LE(0, 34); // disk
    central.writeUInt16LE(0, 36); // internal attributes
    central.writeUInt32LE(0, 38); // external attributes
    central.writeUInt32LE(offset, 42);
    centrals.push(central, name);

    offset += local.length + name.length + body.length;
  }

  const centralDir = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralDir.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20);
  return Buffer.concat([...locals, centralDir, end]);
}

// ============================================================================
// Entry point
// ============================================================================

/** One worksheet, bold frozen header, autofilter over every row, set widths. */
export function buildXlsx(input: XlsxSheetInput): Buffer {
  assertSheetName(input.sheetName);
  if (input.columns.length === 0) throw new Error('an xlsx sheet needs at least one column');
  // Throws on an unknown zone before anything is assembled.
  wallClockFormatter(input.timeZone);
  const sheet = sheetXml(input);
  return zipArchive([
    { name: '[Content_Types].xml', data: Buffer.from(CONTENT_TYPES, 'utf8') },
    { name: '_rels/.rels', data: Buffer.from(ROOT_RELS, 'utf8') },
    { name: 'xl/workbook.xml', data: Buffer.from(workbookXml(input.sheetName, sheet.filterRef), 'utf8') },
    { name: 'xl/_rels/workbook.xml.rels', data: Buffer.from(WORKBOOK_RELS, 'utf8') },
    { name: 'xl/styles.xml', data: Buffer.from(STYLES, 'utf8') },
    { name: 'xl/worksheets/sheet1.xml', data: Buffer.from(sheet.xml, 'utf8') },
  ]);
}
