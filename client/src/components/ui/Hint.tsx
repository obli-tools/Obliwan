import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Info } from 'lucide-react';
import { cn } from '@/utils/cn';

/**
 * The "why" behind a card, folded by default: a card shows facts first, and
 * a paragraph of rationale running across a wide screen is read by nobody.
 * Unfolded, the text keeps a readable measure (max-w-prose).
 */
export function Hint({ children, className }: { children: React.ReactNode; className?: string }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  return (
    <div className={cn('mt-3', className)}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="inline-flex items-center gap-1 text-xs text-text-muted hover:text-text-secondary"
      >
        <Info size={12} aria-hidden="true" />
        {open ? t('common.hideWhy') : t('common.why')}
      </button>
      {open && <div className="mt-1.5 max-w-prose text-xs leading-relaxed text-text-muted">{children}</div>}
    </div>
  );
}
