import { useTranslation } from 'react-i18next';
import { ShieldQuestion, Check, ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';
import toast from 'react-hot-toast';
import { useState } from 'react';
import { devicesApi } from '@/api/devices.api';
import type { Device } from '@/types/fleet';
import { Button } from '@/components/common/Button';

/**
 * Devices waiting for a human — the visible half of anonymous bench enrolment.
 *
 * ┌─ WITHOUT THIS SCREEN THE WHOLE DESIGN IS A SENTENCE IN A COMMENT ────────┐
 * │ `POST /devices/enroll` accepts no session and no token, on the reasoning  │
 * │ that an explicit human approval is a better control than a bearer         │
 * │ credential sitting on a workstation. That reasoning only holds if the     │
 * │ approval EXISTS and somebody can find it. A quarantine nobody can see is  │
 * │ a list that fills up, and a fleet that quietly stops being enrolled.      │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * It renders NOTHING when nothing is pending. A permanent empty panel teaches
 * operators to stop looking at that part of the screen, and then the one day it
 * has content is the day nobody reads it.
 *
 * The identity is shown beside each row rather than just the name, because it
 * is what the approver is actually being asked to judge: an anonymous caller
 * chose that name, and only the serial or the system identity says which box
 * this is. A row with neither cannot be approved at all — the server refuses
 * it, and the button says so before the click rather than after.
 */
export function QuarantineBanner({
  devices,
  canWrite,
  onApproved,
}: {
  devices: Device[];
  canWrite: boolean;
  onApproved: () => void | Promise<void>;
}) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState<number | null>(null);

  const pending = devices.filter((d) => d.status === 'pending');
  if (pending.length === 0) return null;

  const approve = async (d: Device) => {
    setBusy(d.id);
    try {
      await devicesApi.approve(d.id);
      toast.success(t('quarantine.approved', { name: d.name }));
      await onApproved();
    } catch (err) {
      // The server's refusals are the interesting content here — "no identity",
      // "it is quarantined, not pending" — so they are shown verbatim and for
      // long enough to read.
      const message = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(message ?? t('quarantine.approveFailed'), { duration: 10_000 });
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="mb-5 rounded-lg border border-status-warn/40 bg-status-warn/5 p-4">
      <h2 className="mb-1 flex items-center gap-2 text-sm font-semibold text-status-warn">
        <ShieldQuestion size={16} />
        {t('quarantine.title', { count: pending.length })}
      </h2>
      <p className="mb-3 text-xs text-text-secondary">{t('quarantine.hint')}</p>

      <ul className="divide-y divide-border">
        {pending.map((d) => {
          const identity = d.serial ?? d.systemIdentity ?? null;
          return (
            <li key={d.id} className="flex flex-wrap items-center gap-3 py-2">
              <Link to={`/devices/${d.id}`} className="text-sm text-text-primary hover:text-accent">
                {d.name}
              </Link>
              <span className="rounded-full border border-border px-2 py-0.5 text-[10px] text-text-muted">
                {d.brand}
              </span>
              {identity ? (
                <span className="font-mono text-[11px] text-text-muted">{identity}</span>
              ) : (
                // Not an error state — a fact about what is missing, and the
                // reason the button beside it is disabled.
                <span className="text-[11px] italic text-status-down">
                  {t('quarantine.noIdentity')}
                </span>
              )}
              <div className="ml-auto flex items-center gap-2">
                <Link
                  to={`/devices/${d.id}`}
                  className="flex items-center gap-1 text-xs text-text-muted hover:text-text-primary"
                >
                  {t('quarantine.inspect')} <ArrowRight size={12} />
                </Link>
                {canWrite && d.access !== 'ro' && (
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={!identity || busy === d.id}
                    title={identity ? undefined : t('quarantine.noIdentityHint')}
                    onClick={() => void approve(d)}
                  >
                    <Check size={13} className="mr-1.5" />
                    {t('quarantine.approve')}
                  </Button>
                )}
              </div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
