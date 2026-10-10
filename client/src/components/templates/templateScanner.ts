/**
 * templateScanner — which names does a Nunjucks body READ?
 *
 * Used by the revision editor to say "this variable is used but not declared"
 * and "this one is declared but never used". It is an AUTHORING AID, not a
 * verdict: the server parses the body with Nunjucks itself (`createDraft`) and
 * the render worker runs with `throwOnUndefined`, so a name this scanner
 * misses still fails loudly at preview time. What it must never do is report a
 * name that is NOT a variable — a loop variable, a `{% set %}` local, a filter,
 * an attribute — because a false "undeclared" teaches people to ignore the
 * panel. Hence the rules below, each of which removes a false positive:
 *
 *   - `{# comments #}`, `{% raw %}` and `{% verbatim %}` blocks are skipped;
 *   - string literals are lexed, so `"{{ x }}"` inside a string is text;
 *   - `a.b` reads `a` only; `x | filter(arg)` reads `x` and `arg`, never
 *     `filter`; `x is defined` never reads `defined`;
 *   - `{% set %}`, `{% for %}`, `{% macro %}` parameters and `{% import %}` /
 *     `{% from %}` names are LOCALS;
 *   - keyword arguments `f(name=1)` and dict keys `{ name: 1 }` are not reads;
 *   - a free name CALLED like a function is not a variable (a variable is
 *     JSON): it is a macro, a global, or a deliberate `{{ refuse_…() }}`;
 *   - Nunjucks' own globals (`range`, `cycler`, `joiner`, `loop`, `caller`).
 */

export interface ScanResult {
  /** Free names the body reads, each with the 1-based lines it appears on. */
  used: Map<string, number[]>;
  /** Names the body defines itself (`set`, `for`, macro parameters, imports). */
  locals: Set<string>;
}

type Tok =
  | { t: 'id'; v: string }
  | { t: 'str'; v: string }
  | { t: 'num'; v: string }
  | { t: 'op'; v: string };

const KEYWORDS = new Set([
  'and', 'or', 'not', 'in', 'is', 'if', 'else', 'elif', 'elseif',
  'true', 'false', 'True', 'False', 'none', 'None', 'null',
]);

const GLOBALS = new Set(['range', 'cycler', 'joiner', 'loop', 'caller', 'super', 'self']);

const TWO_CHAR_OPS = new Set(['==', '!=', '<=', '>=', '//', '**']);

function tokenize(src: string): Tok[] {
  const out: Tok[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < src.length && src[j] !== c) j += src[j] === '\\' ? 2 : 1;
      out.push({ t: 'str', v: src.slice(i + 1, j) });
      i = j + 1;
      continue;
    }
    if (/[0-9]/.test(c)) {
      let j = i + 1;
      while (j < src.length && /[0-9_.]/.test(src[j])) j++;
      out.push({ t: 'num', v: src.slice(i, j) });
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      let j = i + 1;
      while (j < src.length && /[A-Za-z0-9_]/.test(src[j])) j++;
      out.push({ t: 'id', v: src.slice(i, j) });
      i = j;
      continue;
    }
    const two = src.slice(i, i + 2);
    if (TWO_CHAR_OPS.has(two)) { out.push({ t: 'op', v: two }); i += 2; continue; }
    out.push({ t: 'op', v: c });
    i++;
  }
  return out;
}

const isOp = (k: Tok | undefined, v: string): boolean => k !== undefined && k.t === 'op' && k.v === v;
const isId = (k: Tok | undefined, v?: string): boolean =>
  k !== undefined && k.t === 'id' && (v === undefined || k.v === v);

/** Collect the free names read by `toks[from..to)`. */
function collectExpr(toks: Tok[], from: number, to: number, read: (name: string) => void): void {
  const brackets: string[] = [];
  for (let i = from; i < to; i++) {
    const k = toks[i];
    if (k.t === 'op') {
      if (k.v === '(' || k.v === '[' || k.v === '{') brackets.push(k.v);
      else if (k.v === ')' || k.v === ']' || k.v === '}') brackets.pop();
      continue;
    }
    if (k.t !== 'id') continue;
    const prev = toks[i - 1];
    const next = toks[i + 1];
    const top = brackets[brackets.length - 1];
    if (isOp(prev, '.') || isOp(prev, '|')) continue;              // attribute / filter name
    if (isId(prev, 'is')) continue;                                  // `is defined`
    if (isId(prev, 'not') && isId(toks[i - 2], 'is')) continue;      // `is not none`
    if (KEYWORDS.has(k.v) || GLOBALS.has(k.v)) continue;
    if (top === '(' && isOp(next, '=')) continue;                    // keyword argument
    if (top === '{' && isOp(next, ':')) continue;                    // dict key
    // A call. A variable is JSON and is never callable, so a free name called
    // like a function is a macro, a global, or the deliberate refusal idiom
    // `{{ refuse_lan_ip_outside_subnet() }}` — which throws on purpose.
    if (isOp(next, '(')) continue;
    read(k.v);
  }
}

/** Index of the first `id` token equal to `word` at bracket depth 0, or -1. */
function findTopLevel(toks: Tok[], from: number, match: (k: Tok) => boolean): number {
  let depth = 0;
  for (let i = from; i < toks.length; i++) {
    const k = toks[i];
    if (k.t === 'op' && (k.v === '(' || k.v === '[' || k.v === '{')) depth++;
    else if (k.t === 'op' && (k.v === ')' || k.v === ']' || k.v === '}')) depth--;
    else if (depth === 0 && match(k)) return i;
  }
  return -1;
}

function statement(
  toks: Tok[],
  read: (name: string) => void,
  local: (name: string) => void,
): void {
  const head = toks[0];
  if (!head || head.t !== 'id') return;
  switch (head.v) {
    case 'set': {
      const eq = findTopLevel(toks, 1, (k) => k.t === 'op' && k.v === '=');
      const end = eq === -1 ? toks.length : eq;
      for (let i = 1; i < end; i++) if (toks[i].t === 'id') local(toks[i].v);
      if (eq !== -1) collectExpr(toks, eq + 1, toks.length, read);
      return;
    }
    case 'for':
    case 'asyncEach':
    case 'asyncAll': {
      const inAt = findTopLevel(toks, 1, (k) => k.t === 'id' && k.v === 'in');
      if (inAt === -1) return;
      for (let i = 1; i < inAt; i++) if (toks[i].t === 'id') local(toks[i].v);
      collectExpr(toks, inAt + 1, toks.length, read);
      return;
    }
    case 'macro':
    case 'call': {
      // `macro name(a, b=default)`; `call(args) name(...)`. A parameter is an
      // identifier right after `(` or `,` inside the FIRST parenthesis group.
      let i = 1;
      if (head.v === 'macro' && isId(toks[1])) { local(toks[1].v); i = 2; }
      if (isOp(toks[i], '(')) {
        let depth = 0;
        let j = i;
        for (; j < toks.length; j++) {
          const k = toks[j];
          if (isOp(k, '(')) depth++;
          else if (isOp(k, ')')) { depth--; if (depth === 0) break; }
          else if (depth === 1 && k.t === 'id' && (isOp(toks[j - 1], '(') || isOp(toks[j - 1], ','))) {
            local(k.v);
          }
        }
        // Default values inside the parameter list are reads; the parameter
        // names themselves were just declared local and are filtered later.
        collectExpr(toks, i, j, read);
        collectExpr(toks, j + 1, toks.length, read);
      } else {
        collectExpr(toks, i, toks.length, read);
      }
      return;
    }
    case 'import': {
      const asAt = findTopLevel(toks, 1, (k) => k.t === 'id' && k.v === 'as');
      if (asAt !== -1 && isId(toks[asAt + 1])) local(toks[asAt + 1].v);
      collectExpr(toks, 1, asAt === -1 ? toks.length : asAt, read);
      return;
    }
    case 'from': {
      const impAt = findTopLevel(toks, 1, (k) => k.t === 'id' && k.v === 'import');
      if (impAt === -1) return;
      collectExpr(toks, 1, impAt, read);
      for (let i = impAt + 1; i < toks.length; i++) {
        const k = toks[i];
        if (k.t === 'id' && k.v !== 'as' && k.v !== 'with' && k.v !== 'without' && k.v !== 'context') {
          local(k.v);
        }
      }
      return;
    }
    case 'include':
    case 'extends': {
      collectExpr(
        toks.filter((k) => !(k.t === 'id' && (k.v === 'ignore' || k.v === 'missing'))),
        1,
        toks.length,
        read,
      );
      return;
    }
    case 'if':
    case 'elif':
    case 'elseif':
    case 'switch':
    case 'case':
      collectExpr(toks, 1, toks.length, read);
      return;
    case 'filter':
      // `{% filter name(args) %}`: the name is a filter, its arguments are reads.
      collectExpr(toks, 2, toks.length, read);
      return;
    default:
      // end tags, `else`, `block name`, `raw`… read nothing.
      return;
  }
}

/** Find the end of a `{{ … }}` / `{% … %}` tag, stepping over string literals. */
function tagEnd(src: string, from: number, close: string): number {
  let i = from;
  while (i < src.length) {
    const c = src[i];
    if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < src.length && src[j] !== c) j += src[j] === '\\' ? 2 : 1;
      i = j + 1;
      continue;
    }
    if (src.startsWith(close, i)) return i;
    i++;
  }
  return -1;
}

function stripControl(inner: string): string {
  let s = inner;
  if (s.startsWith('-')) s = s.slice(1);
  if (s.endsWith('-')) s = s.slice(0, -1);
  return s;
}

const RAW_OPEN = /^\{%-?\s*(raw|verbatim)\s*-?%\}/;

export function scanTemplate(body: string): ScanResult {
  const used = new Map<string, number[]>();
  const locals = new Set<string>();

  // Line starts, for a 1-based line number from an offset.
  const lineStarts = [0];
  for (let i = 0; i < body.length; i++) if (body[i] === '\n') lineStarts.push(i + 1);
  const lineOf = (offset: number): number => {
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lineStarts[mid] <= offset) lo = mid; else hi = mid - 1;
    }
    return lo + 1;
  };

  let i = 0;
  while (i < body.length) {
    const open = body.indexOf('{', i);
    if (open === -1 || open + 1 >= body.length) break;
    const kind = body[open + 1];
    if (kind === '#') {
      const end = body.indexOf('#}', open + 2);
      i = end === -1 ? body.length : end + 2;
      continue;
    }
    if (kind !== '{' && kind !== '%') { i = open + 1; continue; }

    const raw = kind === '%' ? RAW_OPEN.exec(body.slice(open, open + 40)) : null;
    if (raw) {
      const closeRe = new RegExp(`\\{%-?\\s*end${raw[1]}\\s*-?%\\}`, 'g');
      closeRe.lastIndex = open + raw[0].length;
      const m = closeRe.exec(body);
      i = m ? m.index + m[0].length : body.length;
      continue;
    }

    const close = kind === '{' ? '}}' : '%}';
    const end = tagEnd(body, open + 2, close);
    if (end === -1) break;
    const inner = stripControl(body.slice(open + 2, end));
    const line = lineOf(open);
    const read = (name: string): void => {
      const lines = used.get(name);
      if (!lines) used.set(name, [line]);
      else if (lines[lines.length - 1] !== line) lines.push(line);
    };
    const toks = tokenize(inner);
    if (kind === '{') collectExpr(toks, 0, toks.length, read);
    else statement(toks, read, (n) => locals.add(n));
    i = end + 2;
  }

  for (const l of locals) used.delete(l);
  return { used, locals };
}
