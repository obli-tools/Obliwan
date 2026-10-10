/**
 * ObliWAN — RouterOS API wire protocol (pure, no I/O).
 *
 * This file owns the byte-level contract with a MikroTik box and NOTHING else:
 * no sockets, no timers, no logging. Everything here is synchronous and
 * deterministic, which is what makes it testable against a fake server.
 *
 * -- Word length encoding ----------------------------------------------------
 * A "word" is a length prefix followed by that many bytes — UTF-8 text in
 * nearly every reply, raw binary in a `/file/read` chunk (see `LOSSY_WORDS`
 * for how the reader keeps those bytes). The prefix is self-describing on its
 * first byte:
 *
 *   len < 0x80        1 byte   0xxxxxxx
 *   len < 0x4000      2 bytes  10xxxxxx  + 1
 *   len < 0x200000    3 bytes  110xxxxx  + 2
 *   len < 0x10000000  4 bytes  1110xxxx  + 3
 *   otherwise         5 bytes  0xF0      + 4 (plain big-endian uint32)
 *
 * A "sentence" is a list of words terminated by a zero-length word.
 *
 * -- Why the reader is an automaton ------------------------------------------
 * TCP gives us byte streams, not messages. A single `data` event may carry
 * half a length prefix, three sentences, or the middle of a 40 KB /export.
 * `SentenceReader` therefore consumes bytes only when a complete unit is
 * available and keeps the remainder for the next chunk. Nothing in this file
 * ever assumes "one read = one sentence".
 */

/**
 * Hard ceiling on a single word. A real /export word stays well under this;
 * anything larger means we lost frame sync and must kill the connection
 * rather than allocate whatever the peer claims.
 */
export const MAX_WORD_LENGTH = 32 * 1024 * 1024;

const EMPTY = Buffer.alloc(0);

// ============================================================================
// Errors
// ============================================================================

/** Frame-level failure: the bytes on the wire are not RouterOS API. */
export class RouterOsProtocolError extends Error {
  readonly kind = 'protocol';
  constructor(message: string) {
    super(message);
    this.name = 'RouterOsProtocolError';
  }
}

/**
 * A `!trap` — the router refused the command. Milestone requirement #5: traps
 * must REJECT, never be swallowed. `category` is RouterOS's own `=category=`
 * when present (0 missing item, 1 argument, 2 failure, 3 busy, 4 not allowed,
 * 5 not implemented, 6 not implemented on hardware, 7 timeout).
 */
export class RouterOsTrapError extends Error {
  readonly kind = 'trap';
  readonly category?: number;
  readonly attrs: Record<string, string>;
  readonly command: string;
  constructor(message: string, command: string, attrs: Record<string, string>) {
    super(message);
    this.name = 'RouterOsTrapError';
    this.command = command;
    this.attrs = attrs;
    const c = attrs.category;
    this.category = c !== undefined && c !== '' && !Number.isNaN(Number(c)) ? Number(c) : undefined;
  }

  /**
   * RouterOS sets category 0 for "no such item" — callers routinely want to
   * treat that as an empty result rather than as an error.
   */
  get isNoSuchItem(): boolean {
    return this.category === 0 || /no such item/i.test(this.message);
  }
}

/** A `!fatal` — the session is over. The connection MUST be closed. */
export class RouterOsFatalError extends Error {
  readonly kind = 'fatal';
  constructor(message: string) {
    super(message);
    this.name = 'RouterOsFatalError';
  }
}

// ============================================================================
// Encoding
// ============================================================================

/** Encode a word length using the 1..5 byte RouterOS scheme. */
export function encodeLength(len: number): Buffer {
  if (!Number.isInteger(len) || len < 0) {
    throw new RouterOsProtocolError(`Invalid word length ${len}`);
  }
  if (len < 0x80) {
    return Buffer.from([len]);
  }
  if (len < 0x4000) {
    return Buffer.from([0x80 | ((len >> 8) & 0x3f), len & 0xff]);
  }
  if (len < 0x200000) {
    return Buffer.from([0xc0 | ((len >> 16) & 0x1f), (len >> 8) & 0xff, len & 0xff]);
  }
  if (len < 0x10000000) {
    return Buffer.from([
      0xe0 | ((len >>> 24) & 0x0f),
      (len >>> 16) & 0xff,
      (len >>> 8) & 0xff,
      len & 0xff,
    ]);
  }
  const out = Buffer.alloc(5);
  out[0] = 0xf0;
  out.writeUInt32BE(len >>> 0, 1);
  return out;
}

/**
 * Encode one word: length prefix + payload. A string is sent as UTF-8; bytes
 * are sent as they are — which is what a router does with the `=data=` of a
 * `/file/read` chunk, and what a test double has to do to stand for one.
 */
export function encodeWord(word: string | Uint8Array): Buffer {
  const data = typeof word === 'string' ? Buffer.from(word, 'utf8') : Buffer.from(word);
  if (data.length > MAX_WORD_LENGTH) {
    throw new RouterOsProtocolError(`Word of ${data.length} bytes exceeds MAX_WORD_LENGTH`);
  }
  return Buffer.concat([encodeLength(data.length), data]);
}

/** Encode a full sentence: every word, then the zero-length terminator. */
export function encodeSentence(words: readonly (string | Uint8Array)[]): Buffer {
  const parts: Buffer[] = [];
  for (const w of words) parts.push(encodeWord(w));
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

// ============================================================================
// Decoding
// ============================================================================

export interface LengthHeader {
  /** Decoded word length. */
  length: number;
  /** How many bytes the prefix itself occupied (1..5). */
  headerSize: number;
}

/**
 * Peek at a length prefix at `offset` WITHOUT consuming it.
 * Returns `null` when the prefix is not fully present yet (need more bytes).
 * Throws only on a genuinely illegal first byte (> 0xF0), which means the
 * stream is desynchronised and cannot be recovered.
 */
export function peekLength(buf: Buffer, offset: number): LengthHeader | null {
  if (offset >= buf.length) return null;
  const b0 = buf[offset];

  if ((b0 & 0x80) === 0) {
    return { length: b0, headerSize: 1 };
  }
  if ((b0 & 0xc0) === 0x80) {
    if (buf.length < offset + 2) return null;
    return { length: ((b0 & 0x3f) << 8) | buf[offset + 1], headerSize: 2 };
  }
  if ((b0 & 0xe0) === 0xc0) {
    if (buf.length < offset + 3) return null;
    return {
      length: ((b0 & 0x1f) << 16) | (buf[offset + 1] << 8) | buf[offset + 2],
      headerSize: 3,
    };
  }
  if ((b0 & 0xf0) === 0xe0) {
    if (buf.length < offset + 4) return null;
    return {
      length:
        ((b0 & 0x0f) << 24 >>> 0) +
        (buf[offset + 1] << 16) +
        (buf[offset + 2] << 8) +
        buf[offset + 3],
      headerSize: 4,
    };
  }
  if (b0 === 0xf0) {
    if (buf.length < offset + 5) return null;
    return { length: buf.readUInt32BE(offset + 1), headerSize: 5 };
  }
  throw new RouterOsProtocolError(
    `Illegal length prefix 0x${b0.toString(16)} - stream desynchronised`,
  );
}

/**
 * The exact bytes of every word whose UTF-8 decoding LOST information, keyed by
 * the sentence's word array (as `SentenceReader.push()` returned it) and then
 * by the word's index in it.
 *
 * Why it exists: a word is a byte string, and almost every word RouterOS sends
 * is text, so the reader decodes words as UTF-8 — the right call for an
 * identity or a comment with an accent in it. But `/file/read` answers with
 * `=data=<the raw bytes of a chunk>`, and a binary backup is not UTF-8: every
 * invalid sequence becomes U+FFFD and the bytes are gone. Rather than change
 * the type every caller already reads (`string`), the reader keeps the
 * original bytes ON THE SIDE for exactly the words where decoding was lossy;
 * a word that decoded losslessly re-encodes to its own bytes, so it needs no
 * copy. `attributeBytes()` is the one way to read an attribute as bytes.
 *
 * A WeakMap so that a sentence nobody kept costs nothing once it is dropped.
 */
const LOSSY_WORDS = new WeakMap<readonly string[], Map<number, Buffer>>();

/**
 * Decode one word as UTF-8 and say whether that decoding was lossless.
 *
 * Node replaces every invalid sequence with U+FFFD and decodes every valid one
 * to the code point it encodes, which re-encodes to the same bytes. So a result
 * WITHOUT U+FFFD is lossless, and a result with one is lossless only if the
 * original bytes really spelled U+FFFD — which a re-encode settles.
 */
function decodeWord(raw: Buffer): { text: string; lossless: boolean } {
  const text = raw.toString('utf8');
  if (!text.includes('�')) return { text, lossless: true };
  return { text, lossless: Buffer.from(text, 'utf8').equals(raw) };
}

/**
 * The exact bytes of word `index` of a sentence returned by
 * `SentenceReader.push()`. For a word that decoded losslessly this is its
 * UTF-8 encoding; for one that did not, the bytes the peer actually sent.
 */
export function wordBytes(words: readonly string[], index: number): Buffer {
  const kept = LOSSY_WORDS.get(words)?.get(index);
  if (kept) return Buffer.from(kept);
  return Buffer.from(words[index] ?? '', 'utf8');
}

/**
 * Incremental sentence reader. Feed it whatever TCP hands you; it returns the
 * sentences that became complete, and keeps any trailing partial bytes.
 */
export class SentenceReader {
  private buf: Buffer = EMPTY;
  private words: string[] = [];
  /** Raw bytes of the words of the CURRENT sentence that did not decode
   *  losslessly (see `LOSSY_WORDS`); null while there are none. */
  private lossy: Map<number, Buffer> | null = null;

  /** Bytes buffered but not yet forming a complete word (diagnostics only). */
  get pendingBytes(): number {
    return this.buf.length;
  }

  /** Feed a chunk; get back zero or more complete sentences, in order. */
  push(chunk: Buffer): string[][] {
    this.buf = this.buf.length === 0 ? chunk : Buffer.concat([this.buf, chunk]);
    const out: string[][] = [];
    let pos = 0;

    for (;;) {
      const header = peekLength(this.buf, pos);
      if (header === null) break;

      if (header.length > MAX_WORD_LENGTH) {
        throw new RouterOsProtocolError(
          `Peer announced a ${header.length}-byte word (max ${MAX_WORD_LENGTH})`,
        );
      }

      const wordStart = pos + header.headerSize;
      if (header.length === 0) {
        // Zero-length word: end of sentence.
        pos = wordStart;
        if (this.lossy) LOSSY_WORDS.set(this.words, this.lossy);
        out.push(this.words);
        this.words = [];
        this.lossy = null;
        continue;
      }
      if (this.buf.length < wordStart + header.length) break; // word split across TCP segments

      const raw = this.buf.subarray(wordStart, wordStart + header.length);
      const { text, lossless } = decodeWord(raw);
      if (!lossless) {
        // A COPY: `this.buf` is compacted and reused below, and a subarray
        // would pin (and later alias) the whole receive buffer.
        (this.lossy ??= new Map()).set(this.words.length, Buffer.from(raw));
      }
      this.words.push(text);
      pos = wordStart + header.length;
    }

    // Compact: copy the tail so we never pin a large chunk through subarray().
    if (pos > 0) {
      this.buf = pos === this.buf.length ? EMPTY : Buffer.from(this.buf.subarray(pos));
    }
    return out;
  }

  /** Drop everything. Called when a connection dies. */
  reset(): void {
    this.buf = EMPTY;
    this.words = [];
    this.lossy = null;
  }
}

// ============================================================================
// Sentence semantics
// ============================================================================

/** `!empty`: RouterOS 7.18+ says a command returned no data, then sends `!done`. */
export type SentenceType = '!re' | '!done' | '!trap' | '!fatal' | '!empty' | 'unknown';

export interface Sentence {
  /**
   * Reply category. Anything unexpected lands on `unknown` rather than
   * throwing — an unknown reply must not take the connection down.
   */
  type: SentenceType;
  /** Value of `.tag=`, or `undefined` for untagged replies (notably `!fatal`). */
  tag?: string;
  /** `=key=value` attributes, key without the leading `=`. */
  attrs: Record<string, string>;
  /** `.key=value` API attributes other than `.tag` (e.g. `.section`). */
  api: Record<string, string>;
  /** The raw words, first one included. Kept for audit and debugging. */
  words: string[];
  /**
   * The exact value BYTES of every `=key=value` attribute whose UTF-8 decoding
   * was lossy — absent when there is none, which is every sentence that
   * carries only text. Read it through `attributeBytes()`, never directly: a
   * key missing here means "its string is exact", not "it has no bytes".
   */
  rawAttrs?: Record<string, Buffer>;
}

/**
 * Split `key=value` on the FIRST `=`, since values legally contain `=`
 * (comments, scripts, base64 blobs).
 */
function splitAttribute(rest: string): [string, string] {
  const eq = rest.indexOf('=');
  if (eq === -1) return [rest, ''];
  return [rest.slice(0, eq), rest.slice(eq + 1)];
}

export function parseSentence(words: string[]): Sentence {
  const head = words[0] ?? '';
  const type: SentenceType =
    head === '!re' || head === '!done' || head === '!trap' || head === '!fatal' || head === '!empty' ? head : 'unknown';

  const attrs: Record<string, string> = {};
  const api: Record<string, string> = {};
  let tag: string | undefined;
  const lossy = LOSSY_WORDS.get(words);
  let rawAttrs: Record<string, Buffer> | undefined;

  for (let i = 1; i < words.length; i++) {
    const w = words[i];
    if (w.startsWith('=')) {
      const [k, v] = splitAttribute(w.slice(1));
      attrs[k] = v;
      const raw = lossy?.get(i);
      if (raw) {
        // The value starts after the SECOND `=` byte. 0x3D is ASCII: it never
        // occurs inside a multi-byte UTF-8 sequence and always decodes to `=`,
        // so the first 0x3D after the sigil is the very `=` `splitAttribute`
        // split on.
        const eq = raw.indexOf(0x3d, 1);
        (rawAttrs ??= {})[k] = eq === -1 ? Buffer.alloc(0) : Buffer.from(raw.subarray(eq + 1));
      }
    } else if (w.startsWith('.')) {
      const [k, v] = splitAttribute(w.slice(1));
      if (k === 'tag') tag = v;
      else api[k] = v;
    } else {
      // `!fatal <reason>` carries its reason as a bare word on some firmwares.
      if (i === 1 && attrs.message === undefined) attrs.message = w;
      else attrs[w] = '';
    }
  }

  return rawAttrs ? { type, tag, attrs, api, words, rawAttrs } : { type, tag, attrs, api, words };
}

/**
 * An attribute's value as the exact bytes the peer sent, or `null` when the
 * sentence has no such attribute. The one correct way to read a binary value
 * (`/file/read`'s `data`): `attrs[key]` is its UTF-8 decoding, which is exact
 * for text and lossy for anything else.
 */
export function attributeBytes(sentence: Sentence, key: string): Buffer | null {
  const raw = sentence.rawAttrs?.[key];
  if (raw) return Buffer.from(raw);
  if (!Object.prototype.hasOwnProperty.call(sentence.attrs, key)) return null;
  return Buffer.from(sentence.attrs[key], 'utf8');
}

/** Convenience: the `!re` rows of a reply as plain attribute maps. */
export function rowsOf(sentences: readonly Sentence[]): Record<string, string>[] {
  return sentences.filter((s) => s.type === '!re').map((s) => s.attrs);
}

// ============================================================================
// Redaction — the secrets rule
// ============================================================================

/**
 * Attribute names whose value must never leave memory. The rendered config
 * exists in two versions; every path except vault -> device gets the redacted
 * one, LOGS included.
 */
const SECRET_ATTRIBUTE =
  /(^|-)(password|passwd|secret|psk|pre-shared-key|private-key|key|response|token|community)$/i;

/**
 * True when an attribute name designates a secret.
 *
 * Exported because redaction is needed on more than the log path: a RouterOS
 * sentence also gets PERSISTED (discovery evidence) and SERVED to a screen, and
 * those paths had no redaction at all — `/ppp/secret/print` returned every site's
 * L2TP password and it travelled to `discoveries.raw` and out through the API.
 * One definition of "this is a secret", used everywhere it matters.
 */
export function isSecretAttribute(name: string): boolean {
  return SECRET_ATTRIBUTE.test(name);
}

/**
 * Strip secret-valued keys from a parsed RouterOS sentence before it is stored
 * or returned. Redacts rather than deletes: an operator reading the evidence
 * should see that a field existed and was withheld, not wonder if the router
 * failed to report it.
 */
export function redactSentence(row: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(row)) {
    out[k] = isSecretAttribute(k) && v !== '' && v != null ? '***' : v;
  }
  return out;
}

/**
 * Attribute values that are a BODY rather than a scalar: a script
 * (`/system/script/add =source=`), a scheduler's `=on-event=`, a file written
 * whole (`/file/add =contents=`), and the two free-text fields a template can
 * fill (`=value=`, `=comment=`).
 *
 * A body is redacted by its NAME, not by what it holds, because what it holds
 * is exactly what no name-based list can see. `safeApply` ships the rendered
 * configuration — vault secrets spliced in — inside `=source=`; the dead-man's
 * rollback script carries the backup password inside `=source=`; the bench
 * writes a rendered configuration through `=contents=`. `SECRET_ATTRIBUTE`
 * matches none of those names, so until this rule lived HERE the transport's
 * trace log (`connection.ts`, "RouterOS command sent") printed every one of
 * them in full, and only `command_audit` — which used to add this pass on its
 * own, in `backup.service.ts` — was protected. One rule, at the layer every
 * path goes through.
 *
 * Only `=` attribute words: a `?comment=` QUERY locates an item by its marker
 * and carries no body, and masking it would make every trace of a rule lookup
 * unreadable for nothing.
 */
const BODY_ATTRIBUTES: ReadonlySet<string> = new Set([
  'source',
  'on-event',
  'contents',
  'value',
  'comment',
]);

/**
 * Redact a single word for logs/audit. A secret attribute keeps its name and
 * loses its value (`=password=hunter2` -> `=password=***`); a body attribute
 * keeps its name and its SIZE (`=source=<4812 bytes, redacted>`), so the trace
 * still says that a 4 812-byte script was sent, and never what was in it.
 */
export function redactWord(word: string): string {
  if (!word.startsWith('=') && !word.startsWith('?')) return word;
  const sigil = word[0];
  const [k, v] = splitAttribute(word.slice(1));
  if (v !== '' && SECRET_ATTRIBUTE.test(k)) return `${sigil}${k}=***`;
  if (sigil === '=' && v !== '' && BODY_ATTRIBUTES.has(k)) {
    return `=${k}=<${Buffer.byteLength(v, 'utf8')} bytes, redacted>`;
  }
  return word;
}

/** Redact a whole sentence for logs/audit. Never log the raw words. */
export function redactWords(words: readonly string[]): string[] {
  return words.map(redactWord);
}

/** The command word of a sentence (`/ppp/active/listen`), for error context. */
export function commandOf(words: readonly string[]): string {
  return words[0] ?? '<empty>';
}
