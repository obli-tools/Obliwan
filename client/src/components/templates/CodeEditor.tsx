import { useEffect, useMemo, useRef, type KeyboardEvent } from 'react';
import { cn } from '@/utils/cn';
import { indentEdit } from './indent';

/**
 * A monospace editor for a RouterOS template body: a plain `<textarea>` with a
 * line-number gutter. No code-editor dependency — `client/package.json` has
 * none, and a template body is a few hundred lines of text, which a textarea
 * handles without help.
 *
 * Behaviour that matters for this content:
 *  - no wrapping: a RouterOS command is ONE line, and a wrapped one reads as
 *    two commands;
 *  - no spell check, no autocorrect, no auto-capitalisation: each of them
 *    would silently rewrite configuration;
 *  - Tab inserts two spaces instead of leaving the field; with a selection it
 *    indents every selected line, and Shift+Tab removes up to two spaces of
 *    indentation from them. Both go through the browser's own editing command,
 *    so Ctrl+Z undoes them like typing — a selection is never REPLACED by the
 *    indent. Escape, then Tab or Shift+Tab, leaves the field — a keyboard user
 *    is never trapped;
 *  - `highlightLines` marks lines in the gutter (a render error's line), and
 *    `focusLine` scrolls to a line and puts the caret on it.
 */
interface CodeEditorProps {
  value: string;
  onChange?: (value: string) => void;
  readOnly?: boolean;
  highlightLines?: number[];
  /** Changing this scrolls to the line. Pass a fresh object to re-trigger. */
  focusLine?: { line: number } | null;
  ariaLabel: string;
  className?: string;
}

const LINE_PX = 20; // `leading-5`
const MODIFIER_KEYS: ReadonlySet<string> = new Set(['Shift', 'Control', 'Alt', 'Meta']);

/**
 * Replace `[start, end)` with `text` the way typing would: through
 * `execCommand('insertText')`, which records the edit in the textarea's own
 * undo history and fires the `input` event React's `onChange` listens to.
 * Writing the value through React state instead would reset that history, so
 * Ctrl+Z could not bring back what the edit removed. When the command is not
 * available, `setRangeText` does the edit (without an undo step) and the new
 * value is reported by hand.
 */
function replaceRange(
  area: HTMLTextAreaElement,
  start: number,
  end: number,
  text: string,
  onChange?: (value: string) => void,
): void {
  area.focus();
  area.setSelectionRange(start, end);
  let done = false;
  try {
    done = document.execCommand('insertText', false, text);
  } catch {
    done = false;
  }
  if (!done) {
    area.setRangeText(text, start, end, 'end');
    onChange?.(area.value);
  }
}

export function CodeEditor({
  value, onChange, readOnly = false, highlightLines = [], focusLine = null, ariaLabel, className,
}: CodeEditorProps) {
  const areaRef = useRef<HTMLTextAreaElement>(null);
  const gutterRef = useRef<HTMLDivElement>(null);
  const escaped = useRef(false);

  const lineCount = useMemo(() => {
    let n = 1;
    for (let i = 0; i < value.length; i++) if (value.charCodeAt(i) === 10) n++;
    return n;
  }, [value]);
  const marked = useMemo(() => new Set(highlightLines), [highlightLines]);

  useEffect(() => {
    const area = areaRef.current;
    if (!area || !focusLine) return;
    const lines = value.split('\n');
    const line = Math.min(Math.max(focusLine.line, 1), lines.length);
    let offset = 0;
    for (let i = 0; i < line - 1; i++) offset += lines[i].length + 1;
    area.focus();
    area.setSelectionRange(offset, offset);
    area.scrollTop = Math.max(0, (line - 1) * LINE_PX - area.clientHeight / 3);
    // `value` deliberately not a dependency: typing must not jump the caret.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusLine]);

  const syncScroll = () => {
    if (gutterRef.current && areaRef.current) gutterRef.current.scrollTop = areaRef.current.scrollTop;
  };

  const onKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Escape') { escaped.current = true; return; }
    // Pressing Shift (or Ctrl…) on its way to Shift+Tab must not cancel the
    // Escape that precedes it.
    if (MODIFIER_KEYS.has(e.key)) return;
    if (e.key !== 'Tab' || readOnly || escaped.current) {
      escaped.current = false;
      return;
    }
    e.preventDefault();
    const area = e.currentTarget;
    const edit = indentEdit(area.value, area.selectionStart, area.selectionEnd, e.shiftKey);
    if (!edit) return;
    replaceRange(area, edit.start, edit.end, edit.text, onChange);
    area.setSelectionRange(edit.selectStart, edit.selectEnd);
  };

  return (
    <div
      className={cn(
        'flex h-[28rem] overflow-hidden rounded-md border border-border bg-bg-primary font-mono text-xs leading-5',
        className,
      )}
    >
      <div
        ref={gutterRef}
        aria-hidden="true"
        className="shrink-0 select-none overflow-hidden border-r border-border bg-bg-tertiary/60 py-2 text-right text-text-muted"
      >
        {Array.from({ length: lineCount }, (_, i) => (
          <div
            key={i}
            className={cn(
              'h-5 px-2',
              marked.has(i + 1) && 'bg-status-down/20 font-semibold text-status-down',
            )}
          >
            {i + 1}
          </div>
        ))}
        {/* Room for the textarea's horizontal scrollbar, so the last numbers
            stay level with the last lines. */}
        <div className="h-6" />
      </div>
      <textarea
        ref={areaRef}
        aria-label={ariaLabel}
        value={value}
        readOnly={readOnly}
        onChange={(e) => onChange?.(e.target.value)}
        onScroll={syncScroll}
        onKeyDown={onKeyDown}
        wrap="off"
        spellCheck={false}
        autoCorrect="off"
        autoCapitalize="off"
        autoComplete="off"
        className={cn(
          'min-w-0 flex-1 resize-none overflow-auto whitespace-pre bg-transparent px-3 py-2 text-text-primary',
          'focus:outline-none',
          readOnly && 'cursor-default text-text-secondary',
        )}
      />
    </div>
  );
}
