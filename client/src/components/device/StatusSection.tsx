import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { ChevronRight } from 'lucide-react';
import { cn } from '@/utils/cn';
import { needsAttention, type SignalTone } from './deviceSignals';

/**
 * The colour vocabulary of a status, shared by the header chips and the
 * section headers so a chip and the section it opens always look alike.
 * `unknown` is HOLLOW and dashed, never grey-filled: "we cannot tell" must not
 * read as "fine", nor as "down".
 */
export const TONE_DOT: Record<SignalTone, string> = {
  ok: 'bg-status-up',
  warn: 'bg-status-ssl-warning',
  bad: 'bg-status-down',
  info: 'bg-accent',
  unknown: 'border-2 border-text-muted/60 bg-transparent',
  loading: 'border-2 border-text-muted/40 bg-transparent animate-pulse',
};

export const TONE_TEXT: Record<SignalTone, string> = {
  ok: 'text-status-up',
  warn: 'text-status-ssl-warning',
  bad: 'text-status-down',
  info: 'text-accent',
  unknown: 'text-text-muted',
  loading: 'text-text-muted',
};

export const TONE_PILL: Record<SignalTone, string> = {
  ok: 'border-status-up/30 bg-status-up/10 text-status-up',
  warn: 'border-status-ssl-warning/40 bg-status-ssl-warning/10 text-status-ssl-warning',
  bad: 'border-status-down/40 bg-status-down/10 text-status-down',
  info: 'border-accent/30 bg-accent/10 text-accent',
  unknown: 'border-dashed border-text-muted/50 text-text-muted',
  loading: 'border-dashed border-text-muted/30 text-text-muted',
};

/** A router link drawn as a secondary button (a <button> inside an <a> is
 *  not valid HTML, and a screen reader announces it twice). */
export const LINK_BUTTON =
  'inline-flex items-center justify-center rounded-md border border-border bg-bg-tertiary px-3 py-1.5 text-sm '
  + 'font-medium text-text-primary transition-colors hover:bg-bg-hover';

export function ToneDot({ tone, className }: { tone: SignalTone; className?: string }) {
  return <span aria-hidden="true" className={cn('inline-block h-2 w-2 shrink-0 rounded-full', TONE_DOT[tone], className)} />;
}

/**
 * One « État » topic of the device page: a header that answers in one line,
 * and the full card underneath.
 *
 * ┌─ FOLDED WHEN HEALTHY, OPEN WHEN NOT ──────────────────────────────────────┐
 * │ A problem (`warn`, `bad`) is shown unfolded; a healthy or unread topic is │
 * │ folded to its one-line summary. The tone usually arrives after the first  │
 * │ render (the card loads it), so the default follows it — until the        │
 * │ operator clicks: from then on his choice wins and a poll that changes the │
 * │ tone does not fold a section under his cursor.                           │
 * │                                                                          │
 * │ The body stays MOUNTED while folded (`hidden`): the cards inside are the │
 * │ page's status sources, and a folded card must keep reporting.            │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
export function StatusSection({
  title,
  icon,
  tone,
  summary,
  focusNonce = 0,
  hidden = false,
  children,
}: {
  title: string;
  icon: ReactNode;
  tone: SignalTone;
  summary: ReactNode;
  /** Changes on every chip click aimed at this section: unfold and scroll to it. */
  focusNonce?: number;
  /** The topic does not apply (the card said so): draw nothing, stay mounted. */
  hidden?: boolean;
  children: ReactNode;
}) {
  const [chosen, setChosen] = useState<boolean | null>(null);
  const ref = useRef<HTMLElement>(null);
  const bodyId = useId();
  const open = chosen ?? needsAttention(tone);

  useEffect(() => {
    if (focusNonce === 0) return;
    setChosen(true);
    // Next frame: the chip may have just switched the tab back to the
    // overview, and an element still hidden cannot be scrolled to.
    const frame = requestAnimationFrame(() => ref.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }));
    return () => cancelAnimationFrame(frame);
  }, [focusNonce]);

  return (
    <section
      ref={ref}
      hidden={hidden}
      className={cn(
        'scroll-mt-4 rounded-lg border bg-bg-secondary',
        tone === 'bad' ? 'border-status-down/40' : tone === 'warn' ? 'border-status-ssl-warning/40' : 'border-border',
      )}
    >
      <button
        type="button"
        onClick={() => setChosen(!open)}
        aria-expanded={open}
        aria-controls={bodyId}
        className="flex w-full flex-wrap items-center gap-x-2.5 gap-y-1 rounded-lg px-4 py-3 text-left hover:bg-bg-hover/40"
      >
        <ChevronRight
          size={15}
          className={cn('shrink-0 text-text-muted transition-transform', open && 'rotate-90')}
        />
        <span className="shrink-0 text-text-secondary">{icon}</span>
        <span className="shrink-0 text-sm font-semibold text-text-primary">{title}</span>
        <span className={cn('flex min-w-0 max-w-full items-center gap-1.5 text-[13px]', TONE_TEXT[tone])}>
          <ToneDot tone={tone} />
          <span className="truncate">{summary}</span>
        </span>
      </button>
      <div id={bodyId} hidden={!open} className="border-t border-border px-4 py-4">
        {children}
      </div>
    </section>
  );
}
