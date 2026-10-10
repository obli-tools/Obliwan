import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Check, Copy, Eye, EyeOff, Loader2 } from 'lucide-react';
import toast from 'react-hot-toast';
import { CAPABILITIES, isMasterTenant } from '@obliwan/shared';
import { useAuthStore } from '@/store/authStore';
import { useTenantStore } from '@/store/tenantStore';
import { cn } from '@/utils/cn';

/** How long a revealed value stays on screen before it is dropped from state. */
export const REVEAL_DURATION_MS = 30_000;

/**
 * A secret variable's keyed fingerprint (`StoredVariable.fingerprint`), as a
 * string to fold into a `resetKey`: it changes exactly when the stored value
 * does, so replacing a secret drops the old value from the screen, and
 * re-saving the same one does not.
 */
export function secretVersion(fingerprint: unknown): string {
  return JSON.stringify(fingerprint ?? null);
}

/**
 * The eye button of `SECRET_READ`: reveals ONE stored secret, shows it for 30
 * seconds with a copy button, then forgets it.
 *
 * ┌─ WHERE THE PLAINTEXT LIVES, AND FOR HOW LONG ────────────────────────────┐
 * │ In this component's state, and nowhere else in the client: not in a      │
 * │ store, not in a cache, not in the URL. It is dropped                       │
 * │  - after REVEAL_DURATION_MS,                                              │
 * │  - when the operator presses "hide",                                      │
 * │  - when `resetKey` changes (another tenant, another site, another         │
 * │    device — or the same secret REPLACED: callers fold the secret's        │
 * │    fingerprint or a reload counter into the key, because a value shown    │
 * │    as current after it was rotated is the wrong password believed),       │
 * │  - on unmount (the state goes with the component; the timers are         │
 * │    cleared, and an answer arriving after it is ignored).                  │
 * │ The value is stored WITH the key it was revealed for, and drawn only      │
 * │ while that key is still the current one: the effect that clears it runs   │
 * │ after a paint, and without that check the previous object's value would   │
 * │ be painted once under the new one.                                        │
 * │ The copy button is the operator's explicit act; what the clipboard does   │
 * │ afterwards is outside this page.                                          │
 * │                                                                          │
 * │ `translate="no"` keeps a browser's page-translation feature from sending  │
 * │ the value to a translation service along with the rest of the page.      │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Rendered only for an account holding SECRET_READ in the current tenant (a
 * platform admin holds every capability), or — with `platformAdminOnly`, for
 * the instance level, and always in the MASTER tenant, whose secrets are
 * shared infrastructure — only for a platform admin. That is a convenience:
 * the server decides (secretReveal.routes.ts), and every reveal it serves is
 * written to the audit log.
 */
export function RevealSecretButton({
  reveal,
  label,
  showLabel = false,
  resetKey,
  platformAdminOnly = false,
  className,
}: {
  /** Fetches the plaintext. Called on click only, never on render. */
  reveal: () => Promise<string>;
  /** What is revealed ("password", "community"…), for the tooltip and screen readers. */
  label?: string;
  /** Also print `label` next to the eye, when two secrets sit side by side. */
  showLabel?: boolean;
  /**
   * Any change drops a value already on screen. Compared with `Object.is`:
   * pass a string or a number, never an object built during render.
   */
  resetKey?: string | number | null;
  /** The instance level: a platform administrator only, whatever the capability. */
  platformAdminOnly?: boolean;
  className?: string;
}) {
  const { t } = useTranslation();
  const { hasCapability, isAdmin } = useAuthStore();
  const currentTenantId = useTenantStore((s) => s.currentTenantId);
  const allowed = platformAdminOnly || isMasterTenant(currentTenantId)
    ? isAdmin()
    : hasCapability(CAPABILITIES.SECRET_READ);

  /** The plaintext, tagged with the `resetKey` it was revealed for. */
  const [revealed, setRevealed] = useState<{ value: string; forKey: string | number | null | undefined } | null>(null);
  // Drawn only while it still belongs to the object on screen (see the header).
  const value = revealed !== null && Object.is(revealed.forKey, resetKey) ? revealed.value : null;
  const [loading, setLoading] = useState(false);
  const [remaining, setRemaining] = useState(0);
  const [copied, setCopied] = useState(false);

  /** Bumped on every hide / reset / unmount: an answer from an older generation is dropped. */
  const generation = useRef(0);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      generation.current += 1;
    };
  }, []);

  // Another tenant / site / device, or the secret replaced: forget what was
  // revealed for the previous one (it is already not drawn, see `value`).
  useEffect(() => {
    generation.current += 1;
    setRevealed(null);
    setLoading(false);
    setCopied(false);
  }, [resetKey]);

  // The 30-second life of a revealed value.
  useEffect(() => {
    if (revealed === null) return undefined;
    const until = Date.now() + REVEAL_DURATION_MS;
    setRemaining(Math.ceil(REVEAL_DURATION_MS / 1000));
    const tick = window.setInterval(() => {
      setRemaining(Math.max(0, Math.ceil((until - Date.now()) / 1000)));
    }, 1000);
    const drop = window.setTimeout(() => {
      generation.current += 1;
      setRevealed(null);
      setCopied(false);
    }, REVEAL_DURATION_MS);
    return () => {
      window.clearInterval(tick);
      window.clearTimeout(drop);
    };
  }, [revealed]);

  if (!allowed) return null;

  const name = label ?? t('secrets.secret', { defaultValue: 'secret' });

  const onReveal = async () => {
    const mine = ++generation.current;
    // The object this click is about; a key change while the request is in
    // flight bumps `generation` and the answer is dropped below.
    const forKey = resetKey;
    setLoading(true);
    try {
      const plaintext = await reveal();
      if (!mounted.current || mine !== generation.current) return;
      setRevealed({ value: plaintext, forKey });
    } catch (err) {
      if (!mounted.current || mine !== generation.current) return;
      // Server refusals arrive as an English sentence (a known, unlocalised
      // gap); none of them ever carries the value.
      const m = (err as { response?: { data?: { error?: unknown } } }).response?.data?.error;
      toast.error(typeof m === 'string' && m.trim() !== ''
        ? m
        : t('secrets.revealFailed', { defaultValue: 'Could not reveal this secret.' }));
    } finally {
      if (mounted.current && mine === generation.current) setLoading(false);
    }
  };

  const onHide = () => {
    generation.current += 1;
    setRevealed(null);
    setCopied(false);
  };

  const onCopy = () => {
    if (value === null) return;
    const clipboard = typeof navigator !== 'undefined' ? navigator.clipboard : undefined;
    if (!clipboard) {
      // No Clipboard API outside a secure context (plain HTTP): say so rather than fail silently.
      toast.error(t('secrets.copyFailed', {
        defaultValue: 'Copy is not available here: select the value and copy it by hand.',
      }));
      return;
    }
    clipboard.writeText(value).then(
      () => {
        if (!mounted.current) return;
        setCopied(true);
        toast.success(t('secrets.copied', { defaultValue: 'Copied to the clipboard' }));
      },
      () => {
        toast.error(t('secrets.copyFailed', {
          defaultValue: 'Copy is not available here: select the value and copy it by hand.',
        }));
      },
    );
  };

  if (value === null) {
    return (
      <button
        type="button"
        onClick={() => void onReveal()}
        disabled={loading}
        className={cn(
          'inline-flex items-center gap-1 rounded text-text-muted hover:text-text-primary disabled:opacity-50',
          className,
        )}
        title={t('secrets.revealTitle', {
          defaultValue: 'Reveal the {{name}} for 30 seconds. Every reveal is recorded in the audit log.',
          name,
        })}
        aria-label={t('secrets.revealNamed', { defaultValue: 'Reveal the {{name}}', name })}
      >
        {loading ? <Loader2 size={13} className="animate-spin" /> : <Eye size={13} />}
        {showLabel && <span className="text-[11px]">{name}</span>}
      </button>
    );
  }

  return (
    <span className={cn('inline-flex max-w-full flex-wrap items-center gap-1.5', className)}>
      {showLabel && <span className="text-[11px] text-text-muted">{name}</span>}
      <code
        translate="no"
        className="notranslate select-all whitespace-pre-wrap break-all rounded border border-accent/30 bg-accent/5 px-1.5 py-0.5 font-mono text-[12px] text-text-primary"
      >
        {value}
      </code>
      <button
        type="button"
        onClick={onCopy}
        className="text-text-muted hover:text-text-primary"
        title={t('secrets.copy', { defaultValue: 'Copy' })}
        aria-label={t('secrets.copy', { defaultValue: 'Copy' })}
      >
        {copied ? <Check size={13} className="text-status-up" /> : <Copy size={13} />}
      </button>
      <button
        type="button"
        onClick={onHide}
        className="text-text-muted hover:text-text-primary"
        title={t('secrets.hide', { defaultValue: 'Hide' })}
        aria-label={t('secrets.hide', { defaultValue: 'Hide' })}
      >
        <EyeOff size={13} />
      </button>
      <span className="text-[10px] text-text-muted">
        {t('secrets.hidesIn', { defaultValue: 'hidden in {{seconds}} s', seconds: remaining })}
      </span>
    </span>
  );
}
