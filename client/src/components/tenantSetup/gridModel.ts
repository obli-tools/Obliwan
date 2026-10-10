import { parseDelimited } from '@obliwan/shared';
import { normalizeSitesHeader } from './fileLoaders';
import { newId } from './policyModel';
import { SITE_FIXED_COLUMNS, isBlankRow, type GridRow, type SitesDraft } from './quickSetupStore';

/**
 * The sites grid as data: what a local check can say about a row before the
 * server does, and how a block pasted from a spreadsheet lands in it.
 *
 * The SERVER's site import stays the verdict (codes against the code format,
 * timezones, declared variables…). What is checked here is what a person
 * pasting from Excel gets wrong in a way that is visible at once: a missing
 * code or name, a code the spreadsheet rewrote, the same code twice.
 */

export type GridProblem = 'codeMissing' | 'nameMissing' | 'excelCode' | 'duplicateCode';

/** "102.0" and "1,02E+02" are what Excel makes of a numeric code it was not
 *  told to keep as text. */
export function looksExcelMangled(code: string): boolean {
  return /^\d+\.0$/.test(code) || /E\+/i.test(code);
}

export function gridProblems(sites: SitesDraft): Map<string, GridProblem[]> {
  const out = new Map<string, GridProblem[]>();
  const ci = sites.header.indexOf('code');
  const ni = sites.header.indexOf('name');
  const seen = new Map<string, string[]>();
  for (const r of sites.rows) {
    if (isBlankRow(r)) continue;
    const list: GridProblem[] = [];
    const code = ci >= 0 ? (r.cells[ci] ?? '').trim() : '';
    const name = ni >= 0 ? (r.cells[ni] ?? '').trim() : '';
    if (code === '') list.push('codeMissing');
    else {
      if (looksExcelMangled(code)) list.push('excelCode');
      seen.set(code, [...(seen.get(code) ?? []), r.id]);
    }
    if (name === '') list.push('nameMissing');
    if (list.length > 0) out.set(r.id, list);
  }
  for (const ids of seen.values()) {
    if (ids.length < 2) continue;
    for (const id of ids) out.set(id, [...(out.get(id) ?? []), 'duplicateCode']);
  }
  return out;
}

export function isKnownColumn(name: string): boolean {
  return (SITE_FIXED_COLUMNS as readonly string[]).includes(name) || (name.startsWith('var:') && name.length > 4);
}

/**
 * Paste a tab-separated block at (row, col). When EVERY cell of the first
 * pasted line is a column name the import knows (`code`, `var:wifi_ssid`…),
 * that line is a mapping, not data: the following lines go into those
 * columns, which are added when missing. Otherwise the block fills right and
 * down from the cell, rows are added as needed, and cells beyond the last
 * column are dropped (and counted).
 */
export function pasteBlock(
  sites: SitesDraft,
  rowIndex: number,
  colIndex: number,
  text: string,
  maxRows: number,
): { sites: SitesDraft; droppedCells: number; droppedRows: number } | { error: 'unterminated_quote' } {
  const parsed = parseDelimited(text, { delimiter: '\t' });
  if ('error' in parsed) return { error: 'unterminated_quote' };
  const records = [...parsed.records];
  // Excel ends a copied block with a newline: a trailing blank record is not a row.
  while (records.length > 0 && records[records.length - 1].cells.every((c) => c === '')) records.pop();
  if (records.length === 0) return { sites, droppedCells: 0, droppedRows: 0 };

  const header = [...sites.header];
  const rows = sites.rows.map((r) => ({ ...r, cells: [...r.cells] }));
  const first = records[0].cells.map(normalizeSitesHeader);
  const isMapping = first.length > 0 && first.every((c) => c !== '' && isKnownColumn(c));
  let targets: number[];
  let data = records;
  if (isMapping) {
    targets = first.map((name) => {
      const at = header.indexOf(name);
      if (at >= 0) return at;
      header.push(name);
      for (const r of rows) r.cells.push('');
      return header.length - 1;
    });
    data = records.slice(1);
  } else {
    const width = Math.max(...records.map((r) => r.cells.length));
    targets = Array.from({ length: width }, (_, j) => (colIndex + j < header.length ? colIndex + j : -1));
  }

  let droppedCells = 0;
  let droppedRows = 0;
  data.forEach((rec, i) => {
    const at = rowIndex + i;
    if (at >= maxRows) {
      droppedRows += 1;
      return;
    }
    while (rows.length <= at) rows.push({ id: newId('s'), cells: header.map(() => '') });
    const row = rows[at];
    while (row.cells.length < header.length) row.cells.push('');
    rec.cells.forEach((cell, j) => {
      const target = targets[j];
      if (target === undefined || target < 0) {
        if (cell !== '') droppedCells += 1;
        return;
      }
      row.cells[target] = cell;
    });
  });
  return { sites: { header, rows }, droppedCells, droppedRows };
}

export function emptyRow(width: number): GridRow {
  return { id: newId('s'), cells: Array.from({ length: width }, () => '') };
}
