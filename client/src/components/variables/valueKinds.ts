import type { TFunction } from 'i18next';
import type { JsonValue } from '@/api/variables.api';

/**
 * How the variables screens turn what a person types into the JSON the server
 * stores, and back.
 *
 * A variable is TYPED JSON on the server (ajv runs with `coerceTypes: false`:
 * the string "835" is not the integer VLAN 835), so the screen asks for the
 * kind explicitly instead of guessing it from the text. Guessing is what made
 * a postcode starting with 0, or a password made of digits, change type on
 * the way in.
 */

export type ValueKind = 'text' | 'number' | 'boolean' | 'json' | 'secret';

/** The server's `VARIABLE_KEY_RE`: lowercase letter first, then letters,
 *  digits and `_`, at most 120 characters. */
export const VARIABLE_KEY_RE = /^[a-z][a-zA-Z0-9_]{0,119}$/;

/** The kind an existing value is edited as. */
export function kindOf(value: JsonValue, isSecret: boolean): ValueKind {
  if (isSecret) return 'secret';
  if (typeof value === 'number') return 'number';
  if (typeof value === 'boolean') return 'boolean';
  if (typeof value === 'string') return 'text';
  return 'json';
}

/** The text an existing value is edited as. A secret is never pre-filled: the
 *  server returns a placeholder, not the secret. */
export function draftOf(value: JsonValue, kind: ValueKind): string {
  switch (kind) {
    case 'secret': return '';
    case 'text': return typeof value === 'string' ? value : '';
    case 'number': return typeof value === 'number' ? String(value) : '';
    case 'boolean': return value === true ? 'true' : value === false ? 'false' : '';
    case 'json': return value === undefined ? '' : JSON.stringify(value, null, 2);
  }
}

export type ParseResult = { ok: true; value: JsonValue } | { ok: false; reason: ParseFailure };
export type ParseFailure = 'empty' | 'notNumber' | 'notInteger' | 'notBoolean' | 'badJson';

/**
 * Typed text → JSON. Trims BEFORE testing for emptiness on numbers: in
 * JavaScript `Number(' ')` is 0, and a blank field must never become a real
 * zero (a known trap).
 */
export function parseDraft(text: string, kind: ValueKind, opts: { integer?: boolean } = {}): ParseResult {
  switch (kind) {
    case 'text':
      return { ok: true, value: text };
    case 'secret':
      return text.length === 0 ? { ok: false, reason: 'empty' } : { ok: true, value: text };
    case 'number': {
      const s = text.trim();
      if (s === '') return { ok: false, reason: 'empty' };
      const n = Number(s);
      if (!Number.isFinite(n)) return { ok: false, reason: 'notNumber' };
      if (opts.integer && !Number.isInteger(n)) return { ok: false, reason: 'notInteger' };
      return { ok: true, value: n };
    }
    case 'boolean':
      if (text === 'true') return { ok: true, value: true };
      if (text === 'false') return { ok: true, value: false };
      return { ok: false, reason: 'notBoolean' };
    case 'json': {
      const s = text.trim();
      if (s === '') return { ok: false, reason: 'empty' };
      try {
        return { ok: true, value: JSON.parse(s) as JsonValue };
      } catch {
        return { ok: false, reason: 'badJson' };
      }
    }
  }
}

/** One-line rendering of a non-secret value for a table cell. */
export function displayValue(value: JsonValue): string {
  if (typeof value === 'string') return value;
  return JSON.stringify(value);
}

/** What a person reads when their typing could not be turned into a value. */
export function parseFailureText(t: TFunction, reason: ParseFailure): string {
  switch (reason) {
    case 'empty': return t('variables.err.empty', { defaultValue: 'Enter a value.' });
    case 'notNumber': return t('variables.err.notNumber', { defaultValue: 'Enter a number, for example 1500.' });
    case 'notInteger': return t('variables.err.notInteger', { defaultValue: 'Enter a whole number, without decimals.' });
    case 'notBoolean': return t('variables.err.notBoolean', { defaultValue: 'Choose Yes or No.' });
    case 'badJson':
      return t('variables.err.badJson', { defaultValue: 'This is not valid JSON. Check the brackets and the quotes.' });
  }
}

/** Server error text from an axios failure, when it sent one. */
export function apiErrorText(err: unknown): string | null {
  const m = (err as { response?: { data?: { error?: unknown } } }).response?.data?.error;
  return typeof m === 'string' && m.trim() !== '' ? m : null;
}
