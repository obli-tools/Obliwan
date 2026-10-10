/**
 * formula.ts — the operator's address formulas. PURE: no database, no clock.
 *
 *   tunnel   "100.65.{id/100}.{id%100}"          site 1091 -> 100.65.10.91
 *   LAN      "10.{100+id/100}.{id%100}.0/24"     site 108  -> 10.101.8.0/24
 *
 * An address formula is four octets separated by dots, each octet either a
 * decimal literal (0-255) or ONE braced integer expression over the variable
 * `id`, the site's number. A LAN formula ends with a literal "/prefix".
 *
 * ┌─ A PARSER OF ITS OWN, NEVER eval ────────────────────────────────────────┐
 * │ A formula is text an administrator typed into a form, evaluated by the   │
 * │ process that holds the fleet's credentials — the lesson learned from     │
 * │ Nunjucks. It is tokenised and parsed HERE, by a recursive-descent parser │
 * │ over a closed grammar, and evaluated by walking the resulting tree. No   │
 * │ `eval`, no `Function`, no `vm`, no template engine: what the grammar     │
 * │ cannot spell, the server cannot run. The harness feeds it injection      │
 * │ attempts and checks they are refused as text.                            │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Grammar, inside one pair of braces:
 *
 *   expr    := term (('+' | '-') term)*
 *   term    := unary (('*' | '/' | '%') unary)*
 *   unary   := ('+' | '-') unary | primary
 *   primary := NUMBER | 'id' | '(' expr ')'
 *
 * Integer arithmetic: '/' truncates toward zero and '%' takes the sign of the
 * dividend — the C, JavaScript and PostgreSQL integer rules — so 1091/100 = 10
 * and 1091%100 = 91. Division or remainder by zero is an evaluation error, and
 * so is any intermediate value outside the safe-integer range. Evaluation runs
 * on BigInt, so a quotient is exact rather than a rounded float truncated.
 */

/** Longest formula accepted. Long enough for any octet arithmetic an operator
 *  writes, short enough that a pasted paragraph is refused as such. */
export const FORMULA_MAX_LENGTH = 200;

/** Deepest nesting of parentheses and unary signs. A recursive-descent parser
 *  recurses once per level; this keeps "((((…" from reaching the stack limit. */
const MAX_DEPTH = 32;

const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

export type BinaryOperator = '+' | '-' | '*' | '/' | '%';

export type ExprNode =
  | { kind: 'num'; value: number }
  | { kind: 'id' }
  | { kind: 'neg'; operand: ExprNode }
  | { kind: 'bin'; op: BinaryOperator; left: ExprNode; right: ExprNode };

type Token =
  | { t: 'num'; value: number; at: number }
  | { t: 'id'; at: number }
  | { t: 'op'; value: BinaryOperator | '(' | ')'; at: number };

type OpToken = Extract<Token, { t: 'op' }>;

class FormulaSyntaxError extends Error {}

function tokenize(src: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  while (i < src.length) {
    const ch = src[i];
    if (ch === ' ' || ch === '\t') {
      i += 1;
      continue;
    }
    if (ch >= '0' && ch <= '9') {
      let j = i;
      while (j < src.length && src[j] >= '0' && src[j] <= '9') j += 1;
      const text = src.slice(i, j);
      // A leading zero is octal to some readers; "010" meaning 8 to one tool
      // and 10 to another is how two routers end up on one address.
      if (text.length > 1 && text[0] === '0') {
        throw new FormulaSyntaxError(`"${text}" has a leading zero; write the number without it.`);
      }
      if (text.length > 15) throw new FormulaSyntaxError(`"${text}" is too large a number.`);
      tokens.push({ t: 'num', value: Number(text), at: i });
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      let j = i;
      while (j < src.length && /[A-Za-z0-9_]/.test(src[j])) j += 1;
      const word = src.slice(i, j);
      if (word !== 'id') {
        throw new FormulaSyntaxError(`unknown name "${word}"; the only variable is id.`);
      }
      tokens.push({ t: 'id', at: i });
      i = j;
      continue;
    }
    if (ch === '+' || ch === '-' || ch === '*' || ch === '/' || ch === '%' || ch === '(' || ch === ')') {
      tokens.push({ t: 'op', value: ch, at: i });
      i += 1;
      continue;
    }
    throw new FormulaSyntaxError(
      `"${ch}" is not allowed in an expression; use digits, id, + - * / % and parentheses.`,
    );
  }
  return tokens;
}

class Parser {
  private pos = 0;
  private depth = 0;

  constructor(private readonly tokens: Token[]) {}

  parse(): ExprNode {
    if (this.tokens.length === 0) throw new FormulaSyntaxError('the expression is empty.');
    const node = this.expr();
    if (this.pos < this.tokens.length) {
      throw new FormulaSyntaxError(`unexpected ${this.describe(this.tokens[this.pos])}.`);
    }
    return node;
  }

  private describe(tok: Token | undefined): string {
    if (!tok) return 'end of expression';
    if (tok.t === 'num') return `number ${tok.value}`;
    if (tok.t === 'id') return 'id';
    return `"${tok.value}"`;
  }

  private peekOp(): OpToken | undefined {
    const tok = this.tokens[this.pos];
    return tok && tok.t === 'op' ? tok : undefined;
  }

  private enter(): void {
    this.depth += 1;
    if (this.depth > MAX_DEPTH) {
      throw new FormulaSyntaxError(`the expression nests deeper than ${MAX_DEPTH} levels.`);
    }
  }

  private expr(): ExprNode {
    let left = this.term();
    for (let op = this.peekOp(); op && (op.value === '+' || op.value === '-'); op = this.peekOp()) {
      this.pos += 1;
      left = { kind: 'bin', op: op.value, left, right: this.term() };
    }
    return left;
  }

  private term(): ExprNode {
    let left = this.unary();
    for (
      let op = this.peekOp();
      op && (op.value === '*' || op.value === '/' || op.value === '%');
      op = this.peekOp()
    ) {
      this.pos += 1;
      left = { kind: 'bin', op: op.value, left, right: this.unary() };
    }
    return left;
  }

  private unary(): ExprNode {
    const op = this.peekOp();
    if (op && (op.value === '+' || op.value === '-')) {
      this.pos += 1;
      this.enter();
      const operand = this.unary();
      this.depth -= 1;
      return op.value === '-' ? { kind: 'neg', operand } : operand;
    }
    return this.primary();
  }

  private primary(): ExprNode {
    const tok = this.tokens[this.pos];
    if (!tok) throw new FormulaSyntaxError('the expression ends where a number, id or "(" was expected.');
    if (tok.t === 'num') {
      this.pos += 1;
      return { kind: 'num', value: tok.value };
    }
    if (tok.t === 'id') {
      this.pos += 1;
      return { kind: 'id' };
    }
    if (tok.value === '(') {
      this.pos += 1;
      this.enter();
      const inner = this.expr();
      const close = this.tokens[this.pos];
      if (!close || close.t !== 'op' || close.value !== ')') {
        throw new FormulaSyntaxError(`expected ")" but found ${this.describe(close)}.`);
      }
      this.pos += 1;
      this.depth -= 1;
      return inner;
    }
    throw new FormulaSyntaxError(`unexpected ${this.describe(tok)}.`);
  }
}

export type ExpressionParse =
  | { ok: true; node: ExprNode; usesId: boolean }
  | { ok: false; error: string };

function nodeUsesId(node: ExprNode): boolean {
  switch (node.kind) {
    case 'num':
      return false;
    case 'id':
      return true;
    case 'neg':
      return nodeUsesId(node.operand);
    case 'bin':
      return nodeUsesId(node.left) || nodeUsesId(node.right);
  }
}

/** Parse one integer expression (the text between braces). */
export function parseExpression(src: string): ExpressionParse {
  if (src.length > FORMULA_MAX_LENGTH) {
    return { ok: false, error: `the expression is longer than ${FORMULA_MAX_LENGTH} characters.` };
  }
  try {
    const node = new Parser(tokenize(src)).parse();
    return { ok: true, node, usesId: nodeUsesId(node) };
  } catch (err) {
    if (err instanceof FormulaSyntaxError) return { ok: false, error: err.message };
    throw err;
  }
}

export type Evaluation = { ok: true; value: number } | { ok: false; error: string };

class FormulaArithmeticError extends Error {}

function bounded(v: bigint): bigint {
  if (v > MAX_SAFE || v < -MAX_SAFE) {
    throw new FormulaArithmeticError('an intermediate value leaves the safe integer range.');
  }
  return v;
}

function evalNode(node: ExprNode, id: bigint): bigint {
  switch (node.kind) {
    case 'num':
      return BigInt(node.value);
    case 'id':
      return id;
    case 'neg':
      return bounded(-evalNode(node.operand, id));
    case 'bin': {
      const l = evalNode(node.left, id);
      const r = evalNode(node.right, id);
      switch (node.op) {
        case '+':
          return bounded(l + r);
        case '-':
          return bounded(l - r);
        case '*':
          return bounded(l * r);
        case '/':
          if (r === BigInt(0)) throw new FormulaArithmeticError('division by zero.');
          // BigInt division truncates toward zero.
          return bounded(l / r);
        case '%':
          if (r === BigInt(0)) throw new FormulaArithmeticError('remainder by zero.');
          // BigInt remainder takes the sign of the dividend.
          return bounded(l % r);
      }
    }
  }
}

/** Evaluate a parsed expression for one site number. */
export function evaluateExpression(node: ExprNode, id: number): Evaluation {
  if (!Number.isSafeInteger(id)) return { ok: false, error: `site number ${id} is not a safe integer.` };
  try {
    return { ok: true, value: Number(evalNode(node, BigInt(id))) };
  } catch (err) {
    if (err instanceof FormulaArithmeticError) return { ok: false, error: err.message };
    throw err;
  }
}

// ============================================================================
// Address formulas
// ============================================================================

export type OctetSpec =
  | { kind: 'literal'; value: number }
  | { kind: 'expr'; node: ExprNode; source: string };

export interface AddressFormula {
  /** The formula as the operator wrote it (trimmed). */
  source: string;
  /** Exactly four. */
  octets: OctetSpec[];
  /** The literal "/nn" of a LAN formula; null for a tunnel formula. */
  prefix: number | null;
}

export type AddressFormulaParse = { ok: true; formula: AddressFormula } | { ok: false; error: string };

/**
 * Parse an address formula. `prefix: 'required'` for a LAN subnet formula,
 * `'forbidden'` for a tunnel formula — a tunnel address is a single /32 host.
 *
 * The '/' that separates the prefix is told apart from the division operator
 * by position: outside braces it is the prefix, inside braces it divides.
 */
export function parseAddressFormula(
  text: string,
  opts: { prefix: 'required' | 'forbidden' },
): AddressFormulaParse {
  const src = text.trim();
  if (src === '') return { ok: false, error: 'the formula is empty.' };
  if (src.length > FORMULA_MAX_LENGTH) {
    return { ok: false, error: `the formula is longer than ${FORMULA_MAX_LENGTH} characters.` };
  }

  // Braces must pair, one level only, and the prefix '/' sits outside them.
  let depth = 0;
  let slashAt = -1;
  for (let i = 0; i < src.length; i += 1) {
    const ch = src[i];
    if (ch === '{') {
      depth += 1;
      if (depth > 1) return { ok: false, error: 'braces cannot nest; use parentheses inside an expression.' };
    } else if (ch === '}') {
      depth -= 1;
      if (depth < 0) return { ok: false, error: 'a "}" closes nothing.' };
    } else if (ch === '/' && depth === 0) {
      if (slashAt >= 0) return { ok: false, error: 'the formula has two "/" outside braces.' };
      slashAt = i;
    } else if (depth === 0 && /\s/.test(ch)) {
      return { ok: false, error: 'whitespace is only allowed inside braces.' };
    }
  }
  if (depth !== 0) return { ok: false, error: 'a "{" is never closed.' };

  const body = slashAt >= 0 ? src.slice(0, slashAt) : src;
  const prefixText = slashAt >= 0 ? src.slice(slashAt + 1) : null;

  let prefix: number | null = null;
  if (opts.prefix === 'forbidden' && prefixText !== null) {
    return {
      ok: false,
      error: 'a tunnel address is a single /32 host; remove the "/' + prefixText + '" suffix.',
    };
  }
  if (opts.prefix === 'required') {
    if (prefixText === null) {
      return { ok: false, error: 'a LAN formula ends with its prefix length, e.g. ".0/24".' };
    }
    if (!/^(0|[1-9]\d?)$/.test(prefixText) || Number(prefixText) > 32) {
      return { ok: false, error: `"/${prefixText}" is not a prefix length; write a literal /0 to /32.` };
    }
    prefix = Number(prefixText);
  }

  const parts: string[] = [];
  let current = '';
  let inside = false;
  for (const ch of body) {
    if (ch === '{') inside = true;
    else if (ch === '}') inside = false;
    if (ch === '.' && !inside) {
      parts.push(current);
      current = '';
    } else current += ch;
  }
  parts.push(current);
  if (parts.length !== 4) {
    return {
      ok: false,
      error: `an IPv4 address has four octets separated by dots; this formula has ${parts.length}.`,
    };
  }

  const octets: OctetSpec[] = [];
  for (let n = 0; n < 4; n += 1) {
    const part = parts[n];
    const label = `octet ${n + 1} ("${part}")`;
    if (/^\d+$/.test(part)) {
      if (part.length > 1 && part[0] === '0') {
        return { ok: false, error: `${label} has a leading zero; write it without one.` };
      }
      const value = Number(part);
      if (part.length > 3 || value > 255) return { ok: false, error: `${label} is above 255.` };
      octets.push({ kind: 'literal', value });
      continue;
    }
    if (part.length >= 2 && part[0] === '{' && part[part.length - 1] === '}' && part.indexOf('{', 1) < 0) {
      const inner = part.slice(1, -1);
      const parsed = parseExpression(inner);
      if (!parsed.ok) return { ok: false, error: `${label}: ${parsed.error}` };
      octets.push({ kind: 'expr', node: parsed.node, source: inner.trim() });
      continue;
    }
    return {
      ok: false,
      error: `${label} must be a number from 0 to 255 or one {expression}, with nothing around it.`,
    };
  }
  return { ok: true, formula: { source: src, octets, prefix } };
}

/** True when at least one octet depends on the site number. A formula without
 *  `id` would give every site the same address. */
export function formulaUsesId(f: AddressFormula): boolean {
  return f.octets.some((o) => o.kind === 'expr' && nodeUsesId(o.node));
}

export type FormulaRender =
  | { ok: true; address: number; prefix: number | null; text: string }
  | { ok: false; error: string };

/**
 * Render a formula for one site number. Every octet must come out in 0-255;
 * the caller judges the result against the pool. A ".0" or ".255" host is a
 * legitimate result: a tunnel address is a /32, with no network or broadcast.
 */
export function renderAddressFormula(f: AddressFormula, id: number): FormulaRender {
  const values: number[] = [];
  for (let n = 0; n < f.octets.length; n += 1) {
    const o = f.octets[n];
    if (o.kind === 'literal') {
      values.push(o.value);
      continue;
    }
    const r = evaluateExpression(o.node, id);
    if (!r.ok) return { ok: false, error: `octet ${n + 1} {${o.source}}: ${r.error}` };
    if (r.value < 0 || r.value > 255) {
      return {
        ok: false,
        error: `octet ${n + 1} {${o.source}} is ${r.value} for site number ${id}, outside 0-255.`,
      };
    }
    values.push(r.value);
  }
  const address = values[0] * 16777216 + values[1] * 65536 + values[2] * 256 + values[3];
  const dotted = values.join('.');
  return {
    ok: true,
    address,
    prefix: f.prefix,
    text: f.prefix === null ? dotted : `${dotted}/${f.prefix}`,
  };
}
