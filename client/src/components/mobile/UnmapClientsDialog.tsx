import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Unlink, X } from 'lucide-react';
import { Button } from '@/components/common/Button';
import { cn } from '@/utils/cn';
import type { SimClientRow, SimLinesOnUnmap } from '@/api/simReconcile.api';

export const unmapKey = (r: { accountId: number; clientCode: string }) => `${r.accountId}\u0000${r.clientCode}`;

/**
 * Removing a partner client's workspace mapping asks, per client, what happens
 * to its lines — with NO default, because both answers are legitimate and one
 * of them moves lines out of a customer's workspace:
 *   - stay: every line stays where it is;
 *   - pool: the lines of the mapped workspace go back to the pool (their open
 *     top-up proposals are expired), except the lines on one of its routers —
 *     their card is in the router and the ICCID link would bring them back.
 * Either way the automatic suggestion no longer maps the client by itself
 * (server: clientTenant.service, migration 085).
 */
export function UnmapClientsDialog({
  clients,
  busy,
  onCancel,
  onConfirm,
}: {
  clients: SimClientRow[];
  busy: boolean;
  onCancel: () => void;
  onConfirm: (choices: Map<string, SimLinesOnUnmap>) => void;
}) {
  const { t } = useTranslation();
  const [choices, setChoices] = useState<Map<string, SimLinesOnUnmap>>(new Map());
  const ready = clients.every((r) => choices.has(unmapKey(r)));

  const pick = (k: string, v: SimLinesOnUnmap) =>
    setChoices((prev) => {
      const next = new Map(prev);
      next.set(k, v);
      return next;
    });

  const radio = (k: string, v: SimLinesOnUnmap, label: string) => (
    <label
      className={cn(
        'flex cursor-pointer items-center gap-1.5 rounded-md border px-2 py-1 text-xs',
        choices.get(k) === v ? 'border-accent bg-accent/10 text-accent' : 'border-border text-text-secondary hover:bg-bg-hover',
      )}
    >
      <input
        type="radio"
        name={`unmap-${k}`}
        className="accent-accent"
        checked={choices.get(k) === v}
        onChange={() => pick(k, v)}
        disabled={busy}
      />
      {label}
    </label>
  );

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="unmap-clients-title"
        className="my-16 w-full max-w-2xl rounded-xl border border-border bg-bg-secondary shadow-2xl"
      >
        <div className="flex items-center gap-2 border-b border-border px-5 py-4">
          <Unlink size={18} className="text-status-pending" />
          <h2 id="unmap-clients-title" className="flex-1 text-base font-semibold text-text-primary">
            {t('simReconcile.unmapDialog.title', {
              count: clients.length,
              defaultValue: 'Remove the workspace of {{count}} client(s)',
            })}
          </h2>
          <button
            type="button"
            onClick={onCancel}
            className="rounded p-1 text-text-muted hover:text-text-primary"
            aria-label={t('common.close')}
          >
            <X size={16} />
          </button>
        </div>

        <div className="space-y-3 p-5 text-sm text-text-secondary">
          <p>
            {t('simReconcile.unmapDialog.intro', {
              defaultValue:
                'Say, for each client, what happens to its lines. Either way the automatic suggestion will no longer map this client by itself.',
            })}
          </p>
          <ul className="space-y-2">
            {clients.map((r) => {
              const k = unmapKey(r);
              const mapped = r.mapping;
              const inWorkspace = mapped ? (r.lineTenants.find((x) => x.tenantId === mapped.tenantId)?.count ?? 0) : 0;
              return (
                <li key={k} className="rounded-md border border-border bg-bg-tertiary/40 p-3">
                  <div className="flex flex-wrap items-baseline gap-x-2">
                    <span className="font-mono text-text-primary">{r.clientCode}</span>
                    {r.customerName && <span className="text-text-primary">{r.customerName}</span>}
                    <span className="text-[11px] text-text-muted">{r.accountName}</span>
                  </div>
                  <div className="mt-0.5 text-xs text-text-muted">
                    {t('simReconcile.unmapDialog.linesInWorkspace', {
                      count: inWorkspace,
                      workspace: mapped?.tenantName ?? '—',
                      defaultValue: '{{count}} line(s) in {{workspace}}',
                    })}
                  </div>
                  <div className="mt-2 flex flex-wrap gap-2" role="radiogroup">
                    {radio(k, 'stay', t('simReconcile.unmapDialog.stay', { defaultValue: 'The lines stay in the workspace' }))}
                    {radio(k, 'pool', t('simReconcile.unmapDialog.pool', { defaultValue: 'The lines return to the pool' }))}
                  </div>
                </li>
              );
            })}
          </ul>
          <p className="rounded-md border border-status-pending/40 bg-status-pending/10 p-3 text-xs text-text-primary">
            {t('simReconcile.unmapDialog.poolRouterNote', {
              defaultValue:
                'Returning to the pool: a line on one of the workspace’s routers stays there (its card is in the router and would come back on its own), a line moved by hand to another workspace stays there, and the open top-up proposals of the returned lines are expired.',
            })}
          </p>
        </div>

        <div className="flex justify-end gap-2 border-t border-border px-5 py-3">
          <Button variant="secondary" size="sm" onClick={onCancel} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button size="sm" onClick={() => onConfirm(choices)} disabled={!ready} loading={busy}>
            {t('simReconcile.unmapDialog.confirm', { defaultValue: 'Remove and apply' })}
          </Button>
        </div>
      </div>
    </div>
  );
}
