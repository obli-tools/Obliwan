// ============================================================================
// Brick 10 — the extrapolator's view of a RouterOS export
// ============================================================================
//
// The NCM (and therefore the miner's facts) models ten resource kinds; a store
// router's export carries forty menus — the L2TP clients, the LTE APNs, the
// radios, SNMP, the scheduler. A template that reproduces a router has to
// reproduce all of them, so the extrapolator works on the REDACTED raw export
// the collector keeps beside each snapshot (`config_snapshots.raw_gz`, taken
// with the frozen hide-sensitive command).
//
// This file turns that text into entries that keep BOTH spellings of every
// value: the RAW token, exactly as the router printed it (so a constant line is
// put back into the template byte for byte), and the DECODED value (so two
// spellings RouterOS reads the same — `name=x` and `name="x"`, a comma list
// bare or quoted — compare equal). It is built only from the NCM tokenizer's
// own primitives (`drivers/mikrotik/parse.ts`): one grammar of the export, not
// two that could disagree.
//
// ┌─ THE SECRET FUNNEL ───────────────────────────────────────────────────────┐
// │ `isSensitiveProp` (the collector's own verdict, drivers/mikrotik/driver)  │
// │ is called on EVERY property of every line, here and nowhere later. A      │
// │ sensitive property never becomes an `ExportProp`: its VALUE is dropped on │
// │ the spot (and counted — a non-empty one means the export was not          │
// │ redacted, which the collector refuses anyway), its NAME is kept on the    │
// │ entry so the template can declare the secret. Nothing downstream can      │
// │ persist a value it was never handed.                                      │
// └───────────────────────────────────────────────────────────────────────────┘

import {
  canonicalSectionPath, canonicalizeText, parsePreamble, tokenize, unfoldLines, unquote,
} from '../../drivers/mikrotik/parse';
import { isSensitiveProp } from '../../drivers/mikrotik/driver';
import { isOrderedSection } from '../../drivers/mikrotik/quirks';

const VERBS = new Set(['add', 'set', 'remove']);
const NEVER_KEPT = new Set(['.id', '.nextid', '.dead', '.about', '.proplist']);

export interface ExportProp {
  key: string;
  /** The value token exactly as printed (quotes and escapes included). */
  raw: string;
  /** Decoded: unquoted, escapes resolved, UTF-8 repaired, NFC. */
  value: string;
}

export interface ExportEntry {
  /** Canonical slash form, `/ip/firewall/filter`. */
  path: string;
  /** add | set | remove, or `opaque` for a line the grammar does not cover
   *  (`:delay 5s`), compared and reproduced by its exact text. */
  verb: string;
  /** `[ find default-name=ether1 ]`, raw, or null. */
  selectorRaw: string | null;
  /** The selector, decoded and sorted — part of the row identity. */
  selectorCanon: string;
  /** `set telnet …` / `!comment`: raw tokens. */
  positional: string[];
  props: ExportProp[];
  /** Names of the sensitive properties the line carried (value dropped). */
  secretKeys: string[];
  /** The source line (opaque lines: the whole line). */
  text: string;
  index: number;
}

export interface ParsedRouterOsExport {
  entries: ExportEntry[];
  /** Sensitive properties that arrived WITH a value. Should be 0. */
  refusedSecretValues: number;
  osVersion: string | null;
  model: string | null;
}

/**
 * RouterOS prints a non-ASCII byte as `\XX`; the NCM `unquote` turns each into
 * the code point U+00XX. So "é" (C3 A9) decodes as "Ã©". Re-read as UTF-8 when
 * the bytes ARE valid UTF-8, so a value means the text the router displays —
 * and is rendered back as that text, which the worker emits as UTF-8.
 */
export function repairUtf8(s: string): string {
  if (!/[\u0080-ÿ]/.test(s) || /[^\u0000-ÿ]/.test(s)) return s.normalize('NFC');
  const bytes = Buffer.from(s, 'latin1');
  const text = bytes.toString('utf8');
  if (text.includes('�') || !Buffer.from(text, 'utf8').equals(bytes)) return s.normalize('NFC');
  return text.normalize('NFC');
}

export function decodeValue(raw: string): string {
  return repairUtf8(unquote(raw));
}

/** `/ip/firewall/filter` -> `/ip firewall filter` (the sectioned header). */
export function menuHeader(path: string): string {
  return '/' + path.split('/').filter((p) => p !== '').join(' ');
}

/** Short French-neutral label for a menu: `l2tp-client`, `firewall filter`. */
export function menuShortName(path: string): string {
  const parts = path.split('/').filter((p) => p !== '');
  return parts.slice(-2).join(' ');
}

function hex2(n: number): string {
  return n.toString(16).toUpperCase().padStart(2, '0');
}

/** A value RouterOS prints bare. Deliberately narrower than what it accepts. */
const BARE_RE = /^[A-Za-z0-9_.:/+@,*-]+$/;

/** The interior of a RouterOS double-quoted string, RouterOS's own escapes. */
export function rosQuoteBody(s: string): string {
  let out = '';
  for (const ch of s) {
    const code = ch.codePointAt(0)!;
    if (ch === '\\') out += '\\\\';
    else if (ch === '"') out += '\\"';
    else if (ch === '$') out += '\\$';
    else if (ch === '?') out += '\\?';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else if (code < 0x20 || code === 0x7f) out += '\\' + hex2(code);
    else if (code >= 0x80) for (const b of Buffer.from(ch, 'utf8')) out += '\\' + hex2(b);
    else out += ch;
  }
  return out;
}

/** A decoded value as a RouterOS token: bare when nothing needs quoting. */
export function encodeRosValue(value: string): string {
  if (value !== '' && BARE_RE.test(value)) return value;
  return `"${rosQuoteBody(value)}"`;
}

function selectorCanonOf(tokens: readonly string[]): string {
  const pairs: string[] = [];
  for (const t of tokens) {
    if (t === 'find' || t === 'where') continue;
    const eq = t.indexOf('=');
    if (eq > 0) pairs.push(`${t.slice(0, eq)}=${decodeValue(t.slice(eq + 1))}`);
    else pairs.push(t);
  }
  return pairs.sort().join(' ');
}

function buildEntry(
  path: string,
  tokens: readonly string[],
  verbAt: number,
  index: number,
  counters: { refused: number },
): ExportEntry {
  const props: ExportProp[] = [];
  const positional: string[] = [];
  const secretKeys: string[] = [];
  let selectorRaw: string | null = null;
  let selectorCanon = '';
  for (let i = verbAt + 1; i < tokens.length; i++) {
    const tok = tokens[i];
    if (tok === '[') {
      const inner: string[] = [];
      for (i++; i < tokens.length && tokens[i] !== ']'; i++) inner.push(tokens[i]);
      selectorRaw = `[ ${inner.join(' ')} ]`;
      selectorCanon = selectorCanonOf(inner);
      continue;
    }
    const eq = tok.indexOf('=');
    if (eq <= 0 || tok.startsWith('!')) { positional.push(tok); continue; }
    const key = tok.slice(0, eq);
    if (NEVER_KEPT.has(key)) continue;
    const raw = tok.slice(eq + 1);
    if (isSensitiveProp(key, path)) {
      // The funnel. The value never leaves this branch.
      if (raw !== '' && raw !== '""') counters.refused++;
      if (!secretKeys.includes(key)) secretKeys.push(key);
      continue;
    }
    props.push({ key, raw, value: decodeValue(raw) });
  }
  const entry: ExportEntry = {
    path,
    verb: tokens[verbAt],
    selectorRaw,
    selectorCanon,
    positional,
    props,
    secretKeys,
    text: '',
    index,
  };
  // The source line is NOT kept: it is rebuilt from what passed the funnel, so
  // a value the funnel dropped cannot come back through `text`.
  entry.text = displayLine(entry);
  return entry;
}

/** An opaque line keeps its text minus any sensitive `key=value` token. */
function redactOpaque(path: string, text: string, counters: { refused: number }): string {
  const tokens = tokenize(text);
  let dropped = false;
  const kept = tokens.filter((tok) => {
    const eq = tok.indexOf('=');
    if (eq <= 0) return true;
    const key = tok.slice(tok.startsWith('!') ? 1 : 0, eq);
    if (!isSensitiveProp(key, path)) return true;
    const raw = tok.slice(eq + 1);
    if (raw !== '' && raw !== '""') counters.refused++;
    dropped = true;
    return false;
  });
  return dropped ? kept.join(' ') : text;
}

function findVerb(tokens: readonly string[]): number {
  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.includes('=') || t === '[') return -1;
    if (VERBS.has(t)) return i;
  }
  return -1;
}

/**
 * Terse (`/ip address add …` on every line) and sectioned (`/ip address` then
 * `add …`) are both read — the collector stores terse, the template body is
 * sectioned, and the reproduction proof reads both with this one function.
 */
export function parseRouterOsExport(raw: string): ParsedRouterOsExport {
  const counters = { refused: 0 };
  const { lines } = unfoldLines(canonicalizeText(raw));
  const { preamble, rest } = parsePreamble(lines);
  const entries: ExportEntry[] = [];
  let section: string | null = null;
  for (const line of rest) {
    const text = line.trim();
    if (text === '' || text.startsWith('#')) continue;
    if (text.startsWith('/')) {
      const tokens = tokenize(text);
      const at = findVerb(tokens);
      if (at < 0) {
        if (tokens.some((t) => t.includes('='))) {
          entries.push(opaque(section ?? '/', redactOpaque(section ?? '/', text, counters), entries.length));
        } else {
          section = canonicalSectionPath(tokens);
        }
        continue;
      }
      const path = canonicalSectionPath(tokens.slice(0, at));
      entries.push(buildEntry(path, tokens, at, entries.length, counters));
      continue;
    }
    const tokens = tokenize(text);
    if (section !== null && tokens.length > 0 && VERBS.has(tokens[0])) {
      entries.push(buildEntry(section, tokens, 0, entries.length, counters));
      continue;
    }
    entries.push(opaque(section ?? '/', redactOpaque(section ?? '/', text, counters), entries.length));
  }
  return {
    entries,
    refusedSecretValues: counters.refused,
    osVersion: preamble.osVersion,
    model: preamble.model,
  };
}

function opaque(path: string, text: string, index: number): ExportEntry {
  return {
    path,
    verb: 'opaque',
    selectorRaw: null,
    selectorCanon: '',
    positional: [],
    props: [],
    secretKeys: [],
    text,
    index,
  };
}

export function propValue(e: ExportEntry, key: string): string | undefined {
  for (const p of e.props) if (p.key === key) return p.value;
  return undefined;
}

export function propRaw(e: ExportEntry, key: string): string | undefined {
  for (const p of e.props) if (p.key === key) return p.raw;
  return undefined;
}

/**
 * The comparison key of an entry: what RouterOS would read, not how it was
 * spelled. Property ORDER is ignored (RouterOS ignores it), sensitive
 * properties are absent on both sides (the export never carries them), values
 * are decoded. Two entries with the same key are the same configuration line.
 */
export function canonicalKey(e: ExportEntry): string {
  if (e.verb === 'opaque') return `${e.path} :: ${e.text}`;
  const props = e.props
    .map((p) => `${p.key}=${JSON.stringify(p.value)}`)
    .sort()
    .join(' ');
  return `${e.path} ${e.verb}${e.selectorCanon ? ` [${e.selectorCanon}]` : ''}`
    + `${e.positional.length ? ` ${e.positional.join(' ')}` : ''} ${props}`;
}

/** A line for a human: the entry in terse form. */
export function displayLine(e: ExportEntry): string {
  if (e.verb === 'opaque') return e.text;
  const parts = [menuHeader(e.path), e.verb];
  if (e.selectorRaw) parts.push(e.selectorRaw);
  parts.push(...e.positional);
  for (const p of e.props) parts.push(`${p.key}=${p.raw}`);
  return parts.join(' ');
}

export { isOrderedSection, isSensitiveProp };
