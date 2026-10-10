// ============================================================================
// Brick 10 — aligning N exports into the rows of ONE template
// ============================================================================
//
// "The same line at two sites" is the whole problem. A `set [ find
// default-name=ether1 ]` names itself; an `add` does not — the LAN address of
// store 02196 and of store 00102 share no value at all, and they are still the
// same template line. So every `add` is matched to the row it shares the most
// with: same verb, same selector, mostly the same property NAMES, and as many
// identical VALUES as possible. A value that differs on a matched line is
// exactly what becomes a variable later; a line nobody else carries becomes a
// row of its own, which the presence analysis turns into an option or a
// deviation.
//
// ORDER. In an ordered menu (`isOrderedSection`: firewall, NAT, mangle, queues,
// IPsec policies — and every menu the catalogue does not know, the
// conservative default of N07) the match is a monotone alignment (dynamic
// programming), so a rule is never paired with a rule above its own position
// and the template keeps the chain order every site agrees on. In an unordered
// menu the match is a one-to-one assignment by score, and the template keeps
// the order of the reference site (the miner's medoid) — the order a hand-made
// template would have, and the safe one to apply (a pool that names its
// next-pool keeps it after).
//
// Deterministic: same exports, same reference, same rows, same slots.

import { createHash } from 'crypto';
import { isOrderedSection, propValue, type ExportEntry } from './exportText';

export interface TemplateRow {
  /** Stable within a run: `<path>#<identity>` — what overrides target. */
  key: string;
  path: string;
  verb: string;
  selectorRaw: string | null;
  selectorCanon: string;
  positional: string[];
  opaqueText: string | null;
  /** site index -> the entry of that site on this row. */
  members: Map<number, ExportEntry>;
  /** The first member (the reference site's entry when it has one). */
  ref: ExportEntry;
  /** Property names in first-seen order (reference order first). */
  keyOrder: string[];
}

export interface PathBlock {
  path: string;
  ordered: boolean;
  rows: TemplateRow[];
}

const INCOMPATIBLE = -1;

function keySet(e: ExportEntry): Set<string> {
  return new Set(e.props.map((p) => p.key));
}

/**
 * How well `entry` fits `row`, or INCOMPATIBLE. The identity parts (verb,
 * selector, positional) must be equal; then the score rewards identical
 * values first, identical property names second.
 */
export function similarity(entry: ExportEntry, row: TemplateRow): number {
  if (entry.verb !== row.verb) return INCOMPATIBLE;
  if (entry.verb === 'opaque') return entry.text === row.opaqueText ? 20 : INCOMPATIBLE;
  if (entry.selectorCanon !== row.selectorCanon) return INCOMPATIBLE;
  if (entry.positional.join(' ') !== row.positional.join(' ')) return INCOMPATIBLE;
  const hasIdentity = row.selectorCanon !== '' || row.positional.length > 0;

  const e = keySet(entry);
  const r = new Set(row.keyOrder);
  let inter = 0;
  let valueMatches = 0;
  for (const k of e) {
    if (!r.has(k)) continue;
    inter++;
    if (propValue(entry, k) === propValue(row.ref, k)) valueMatches++;
  }
  const union = e.size + r.size - inter;
  const jaccard = union === 0 ? 1 : inter / union;
  if (!hasIdentity) {
    if (jaccard < 0.5) return INCOMPATIBLE;
    if (valueMatches === 0 && jaccard < 1) return INCOMPATIBLE;
  }
  let score = 1 + 2 * valueMatches + jaccard;
  const n1 = propValue(entry, 'name');
  const n2 = propValue(row.ref, 'name');
  if (n1 !== undefined && n2 !== undefined && n1 === n2) score += 4;
  if (hasIdentity) score += 10;
  return score;
}

function newRow(entry: ExportEntry, site: number): TemplateRow {
  return {
    key: '',
    path: entry.path,
    verb: entry.verb,
    selectorRaw: entry.selectorRaw,
    selectorCanon: entry.selectorCanon,
    positional: [...entry.positional],
    opaqueText: entry.verb === 'opaque' ? entry.text : null,
    members: new Map([[site, entry]]),
    ref: entry,
    keyOrder: entry.props.map((p) => p.key),
  };
}

function attach(row: TemplateRow, entry: ExportEntry, site: number): void {
  row.members.set(site, entry);
  for (const p of entry.props) if (!row.keyOrder.includes(p.key)) row.keyOrder.push(p.key);
}

/** Monotone alignment (ordered menus). Returns entry index -> row index. */
function alignOrdered(entries: ExportEntry[], rows: TemplateRow[]): Map<number, number> {
  const n = entries.length;
  const m = rows.length;
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  const score: number[][] = Array.from({ length: n }, (_, i) =>
    rows.map((row) => similarity(entries[i], row)));
  for (let i = 1; i <= n; i++) {
    for (let j = 1; j <= m; j++) {
      let best = Math.max(dp[i - 1][j], dp[i][j - 1]);
      const s = score[i - 1][j - 1];
      if (s !== INCOMPATIBLE) best = Math.max(best, dp[i - 1][j - 1] + s);
      dp[i][j] = best;
    }
  }
  const match = new Map<number, number>();
  let i = n;
  let j = m;
  while (i > 0 && j > 0) {
    const s = score[i - 1][j - 1];
    if (s !== INCOMPATIBLE && dp[i][j] === dp[i - 1][j - 1] + s) {
      match.set(i - 1, j - 1);
      i--; j--;
    } else if (dp[i][j] === dp[i - 1][j]) {
      i--;
    } else {
      j--;
    }
  }
  return match;
}

/** One-to-one assignment by score (unordered menus). */
function alignUnordered(entries: ExportEntry[], rows: TemplateRow[]): Map<number, number> {
  const pairs: Array<{ i: number; j: number; s: number }> = [];
  for (let i = 0; i < entries.length; i++) {
    for (let j = 0; j < rows.length; j++) {
      const s = similarity(entries[i], rows[j]);
      if (s !== INCOMPATIBLE) pairs.push({ i, j, s });
    }
  }
  pairs.sort((a, b) => b.s - a.s || a.i - b.i || a.j - b.j);
  const usedE = new Set<number>();
  const usedR = new Set<number>();
  const match = new Map<number, number>();
  for (const p of pairs) {
    if (usedE.has(p.i) || usedR.has(p.j)) continue;
    usedE.add(p.i);
    usedR.add(p.j);
    match.set(p.i, p.j);
  }
  return match;
}

/** Merges one site's menu sequence into the running order. */
function mergeOrder(order: string[], sitePaths: readonly string[]): void {
  let last = -1;
  for (const p of sitePaths) {
    const at = order.indexOf(p);
    if (at >= 0) { last = at; continue; }
    order.splice(last + 1, 0, p);
    last += 1;
  }
}

function shortHash(text: string): string {
  return createHash('sha256').update(text).digest('hex').slice(0, 8);
}

/**
 * The row's stable identity, for overrides and deviations: the selector or
 * positional item when it has one, else its constant `name`, else a hash of
 * the values every member agrees on, else its rank in the menu.
 */
function rowIdentity(row: TemplateRow, rank: number): string {
  if (row.opaqueText !== null) return `opaque:${shortHash(row.opaqueText)}`;
  if (row.selectorCanon) return `${row.verb}[${row.selectorCanon}]`;
  if (row.positional.length) return `${row.verb} ${row.positional.join(' ')}`;
  const members = [...row.members.values()];
  const name = propValue(row.ref, 'name');
  if (name !== undefined && members.every((e) => propValue(e, 'name') === name)) {
    return `${row.verb} name=${name}`;
  }
  const constant: string[] = [];
  for (const k of row.keyOrder) {
    const v = propValue(row.ref, k);
    if (v !== undefined && members.every((e) => propValue(e, k) === v)) constant.push(`${k}=${v}`);
  }
  if (constant.length > 0) return `${row.verb}~${shortHash(constant.join('\u0000'))}`;
  return `${row.verb}#${rank}`;
}

/**
 * Align every site's entries into rows. `order` is the order sites are folded
 * in: the reference first.
 */
export function alignSites(sites: readonly ExportEntry[][], order: readonly number[]): PathBlock[] {
  const pathOrder: string[] = [];
  const blocks = new Map<string, PathBlock>();

  for (const s of order) {
    const entries = sites[s];
    const byPath = new Map<string, ExportEntry[]>();
    const sitePaths: string[] = [];
    for (const e of entries) {
      let list = byPath.get(e.path);
      if (!list) { list = []; byPath.set(e.path, list); sitePaths.push(e.path); }
      list.push(e);
    }
    mergeOrder(pathOrder, sitePaths);

    for (const [path, list] of byPath) {
      let block = blocks.get(path);
      if (!block) {
        block = { path, ordered: isOrderedSection(path), rows: [] };
        blocks.set(path, block);
      }
      const rows = block.rows;
      const byIndex = block.ordered ? alignOrdered(list, rows) : alignUnordered(list, rows);
      // Resolved to ROW OBJECTS before anything is inserted: a new row shifts
      // every index after it, and an index read after the splice would attach
      // this site's next line to the row just created.
      const match = new Map<number, TemplateRow>();
      for (const [i, j] of byIndex) match.set(i, rows[j]);
      // New rows go right after the row of the previous entry of this site,
      // so a line one site adds lands where that site has it.
      let insertAt = 0;
      const placed: TemplateRow[] = [];
      for (let i = 0; i < list.length; i++) {
        const matched = match.get(i);
        if (matched !== undefined) {
          const row = matched;
          attach(row, list[i], s);
          placed.push(row);
          insertAt = rows.indexOf(row) + 1;
        } else {
          const row = newRow(list[i], s);
          const at = placed.length === 0 && !block.ordered ? rows.length : insertAt;
          rows.splice(at, 0, row);
          placed.push(row);
          insertAt = at + 1;
        }
      }
    }
  }

  const out: PathBlock[] = [];
  for (const path of pathOrder) {
    const block = blocks.get(path)!;
    const seen = new Map<string, number>();
    block.rows.forEach((row, rank) => {
      const base = `${path}#${rowIdentity(row, rank)}`;
      const n = seen.get(base) ?? 0;
      seen.set(base, n + 1);
      row.key = n === 0 ? base : `${base}~${n}`;
    });
    out.push(block);
  }
  return out;
}
