import { useTranslation } from 'react-i18next';
import { Antenna, Cable } from 'lucide-react';
import { SITE_UPLINK_KINDS, SITE_UPLINK_LABELS, type SiteUplinkKind } from '@obliwan/shared';
import { cn } from '@/utils/cn';

/**
 * The access link a site is DECLARED with (migration 076, shared/src/siteUplink.ts).
 *
 * Three choices, and "automatic" is one of them, not an absence: it means
 * "not declared — ObliWAN infers the link from the router", which is what
 * every site was before 076. Declaring 'fixed' makes a 4G episode a backup
 * (alerted after the delay) even when no fixed interface is recognised;
 * declaring 'cellular_only' makes cellular the site's nominal path (never a
 * backup alert, never a fleet anomaly).
 */

export type SiteUplinkChoice = 'auto' | SiteUplinkKind;
export const SITE_UPLINK_CHOICES: readonly SiteUplinkChoice[] = ['auto', ...SITE_UPLINK_KINDS];

export function choiceOf(kind: SiteUplinkKind | null | undefined): SiteUplinkChoice {
  return kind === 'fixed' || kind === 'cellular_only' ? kind : 'auto';
}
export function kindOf(choice: SiteUplinkChoice): SiteUplinkKind | null {
  return choice === 'auto' ? null : choice;
}

/** The translated label of a choice, the shared French/English text as default. */
export function useUplinkLabel(): (choice: SiteUplinkChoice) => string {
  const { t, i18n } = useTranslation();
  const fr = i18n.language.startsWith('fr');
  return (choice) =>
    t(`sites.uplink.kind.${choice}`, {
      defaultValue: fr ? SITE_UPLINK_LABELS[choice].fr : SITE_UPLINK_LABELS[choice].en,
    });
}

/** A small pill for a declared site; nothing for a site not declared. */
export function SiteUplinkBadge({ kind, className }: { kind: SiteUplinkKind | null | undefined; className?: string }) {
  const { t } = useTranslation();
  const label = useUplinkLabel();
  if (kind !== 'fixed' && kind !== 'cellular_only') return null;
  const cellular = kind === 'cellular_only';
  return (
    <span
      title={label(kind)}
      className={cn(
        'inline-flex items-center gap-1 rounded-full border px-1.5 py-0.5 text-[10px] font-medium',
        cellular ? 'border-accent/40 bg-accent/10 text-accent' : 'border-border bg-bg-tertiary text-text-secondary',
        className,
      )}
    >
      {cellular ? <Antenna size={10} /> : <Cable size={10} />}
      {t(`sites.uplink.short.${kind}`, { defaultValue: cellular ? '4G' : 'Fixe' })}
    </span>
  );
}

/** The select of the site form and of the bulk action. */
export function SiteUplinkSelect({
  id,
  value,
  onChange,
  disabled,
  compact,
  ariaLabel,
}: {
  id?: string;
  value: SiteUplinkChoice;
  onChange: (choice: SiteUplinkChoice) => void;
  disabled?: boolean;
  /** The bulk bar's size; the form's is the Input's. */
  compact?: boolean;
  ariaLabel?: string;
}) {
  const label = useUplinkLabel();
  return (
    <select
      id={id}
      value={value}
      disabled={disabled}
      aria-label={ariaLabel}
      onChange={(e) => onChange(e.target.value as SiteUplinkChoice)}
      className={cn(
        'rounded-md border border-border bg-bg-tertiary text-text-primary focus:outline-none disabled:cursor-not-allowed disabled:opacity-50',
        compact
          ? 'px-2 py-1 text-[13px] focus:ring-1 focus:ring-accent'
          : 'w-full px-3 py-2 text-sm focus:border-transparent focus:ring-2 focus:ring-accent',
      )}
    >
      {SITE_UPLINK_CHOICES.map((c) => (
        <option key={c} value={c}>
          {label(c)}
        </option>
      ))}
    </select>
  );
}
