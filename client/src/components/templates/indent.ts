/**
 * What Tab / Shift+Tab do to the template body — as a pure function, so the
 * rule can be checked without a browser. `CodeEditor` applies the edit it
 * returns through the browser's own editing command (undo keeps working).
 *
 *  - Tab on a bare caret: two spaces at the caret.
 *  - Tab with a selection: two spaces at the start of every line the
 *    selection touches (empty lines left alone). The selection is never
 *    REPLACED — that used to delete 40 selected lines for two spaces.
 *  - Shift+Tab: up to two spaces (or one tab) removed from the start of
 *    every line the selection touches, or of the caret's line.
 *
 * A selection that ends at the very start of a line does not include that
 * line, as in every editor after selecting whole lines.
 */
export const INDENT = '  ';

export interface IndentEdit {
  /** Replace `[start, end)` of the text with `text`… */
  start: number;
  end: number;
  text: string;
  /** …then select this range. */
  selectStart: number;
  selectEnd: number;
}

/** Null when the key changes nothing (Shift+Tab on lines with no indent). */
export function indentEdit(
  value: string,
  selectionStart: number,
  selectionEnd: number,
  outdent: boolean,
): IndentEdit | null {
  const start = Math.min(selectionStart, selectionEnd);
  const end = Math.max(selectionStart, selectionEnd);

  if (start === end && !outdent) {
    return { start, end, text: INDENT, selectStart: start + INDENT.length, selectEnd: start + INDENT.length };
  }

  const blockStart = value.lastIndexOf('\n', start - 1) + 1;
  const lastChar = end > start && value[end - 1] === '\n' ? end - 1 : end;
  const nl = value.indexOf('\n', lastChar);
  const blockEnd = nl === -1 ? value.length : nl;
  const before = value.slice(blockStart, blockEnd);
  const lines = before.split('\n');
  const nextLines = outdent
    ? lines.map((l) => l.replace(/^( {1,2}|\t)/, ''))
    : lines.map((l) => (l.length > 0 ? INDENT + l : l));
  const after = nextLines.join('\n');
  if (after === before) return null;

  if (start === end) {
    // Shift+Tab on a caret: the caret keeps its place in its text.
    const removed = lines[0].length - nextLines[0].length;
    const caret = Math.max(blockStart, start - removed);
    return { start: blockStart, end: blockEnd, text: after, selectStart: caret, selectEnd: caret };
  }
  // The block stays selected, so the key can be pressed again.
  return { start: blockStart, end: blockEnd, text: after, selectStart: blockStart, selectEnd: blockStart + after.length };
}
