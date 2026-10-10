import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { ShieldCheck, ShieldOff } from 'lucide-react';
import type { BenchStation } from '@/api/benchStations.api';
import { Button } from '@/components/common/Button';
import { cn } from '@/utils/cn';

/**
 * The two decisions an administrator takes about a bench workstation.
 *
 * APPROVE asks the administrator to TYPE the verification code the person at
 * the desk reads off the bench's screen, and stays disabled until it matches.
 * That code is the only thing on the row an impostor cannot copy (the name and
 * the hostname are free text on a public route, the address is the Docker
 * bridge gateway for every caller), and a code that is merely displayed is a
 * code nobody compares. The check is a guide for the human, not a security
 * boundary: the server approves by id.
 *
 * REVOKE is final — the server refuses to approve a revoked station again,
 * because its token may be in somebody else's hands — so the dialog says so,
 * and names how many routers that station prepared.
 */
export function StationDecisionDialog({
  station,
  action,
  busy,
  onConfirm,
  onCancel,
}: {
  station: BenchStation;
  action: 'approve' | 'revoke';
  busy: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const { t } = useTranslation();
  const [typed, setTyped] = useState('');

  const expected = normaliseCode(station.verificationCode);
  const codeMatches = expected !== '' && normaliseCode(typed) === expected;
  const approving = action === 'approve';
  const canConfirm = !busy && (!approving || codeMatches);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (canConfirm) onConfirm();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <form
        onSubmit={submit}
        className="w-full max-w-lg rounded-xl border border-border bg-bg-secondary shadow-2xl"
      >
        <div
          className={cn(
            'flex items-center gap-2 rounded-t-xl border-b px-5 py-4',
            approving ? 'border-border' : 'border-status-down/40 bg-status-down/10',
          )}
        >
          {approving
            ? <ShieldCheck size={18} className="text-status-up" />
            : <ShieldOff size={18} className="text-status-down" />}
          <h2 className="text-base font-semibold text-text-primary">
            {approving
              ? t('benchStations.approveTitle', { defaultValue: 'Approve "{{name}}"', name: station.name })
              : t('benchStations.revokeTitle', { defaultValue: 'Revoke "{{name}}"', name: station.name })}
          </h2>
        </div>

        <div className="space-y-3 p-5 text-[13px] text-text-secondary">
          {approving ? (
            <>
              <p>
                {t('benchStations.approveExplain', {
                  defaultValue:
                    'Once approved, this workstation can prepare routers for every customer. Ask the person '
                    + 'at the desk to read you the code shown on the bench screen, and type it below.',
                })}
              </p>
              {expected === '' ? (
                <p className="text-status-down">
                  {t('benchStations.noCode', {
                    defaultValue:
                      'This workstation has no verification code, so it cannot be checked. Do not approve it: '
                      + 'have the bench register again.',
                  })}
                </p>
              ) : (
                <label className="block space-y-1">
                  <span className="block text-sm font-medium text-text-secondary">
                    {t('benchStations.typeCode', { defaultValue: 'Code shown on the bench screen' })}
                  </span>
                  <input
                    autoFocus
                    value={typed}
                    onChange={(e) => setTyped(e.target.value)}
                    autoComplete="off"
                    spellCheck={false}
                    placeholder="XXXX-XXXX"
                    className={cn(
                      'w-full rounded-md border bg-bg-tertiary px-3 py-2 font-mono text-sm uppercase tracking-widest text-text-primary',
                      'focus:outline-none focus:ring-2 focus:ring-accent',
                      typed !== '' && !codeMatches ? 'border-status-down' : 'border-border',
                    )}
                  />
                  {typed !== '' && !codeMatches && (
                    <span className="block text-xs text-status-down">
                      {t('benchStations.codeMismatch', {
                        defaultValue:
                          'This is not the code of this workstation. If the bench shows another code, you are '
                          + 'looking at the wrong row.',
                      })}
                    </span>
                  )}
                </label>
              )}
            </>
          ) : (
            <>
              <p>
                {t('benchStations.revokeExplain', {
                  defaultValue:
                    'This workstation will be refused from its next request. A revocation is final: to use '
                    + 'this desk again, the bench must register again and be approved as a new workstation.',
                })}
              </p>
              {station.enrolledDeviceCount > 0 && (
                <p>
                  {t('benchStations.revokeDevices', {
                    defaultValue:
                      'It has prepared {{count}} router(s). They are not affected; review them if you '
                      + 'revoke because the workstation was compromised.',
                    count: station.enrolledDeviceCount,
                  })}
                </p>
              )}
            </>
          )}
        </div>

        <div className="flex justify-end gap-2 border-t border-border px-5 py-3">
          <Button type="button" variant="secondary" size="sm" onClick={onCancel} disabled={busy}>
            {t('common.cancel')}
          </Button>
          <Button
            type="submit"
            size="sm"
            variant={approving ? 'primary' : 'danger'}
            disabled={!canConfirm}
            loading={busy}
          >
            {approving
              ? t('benchStations.approve', { defaultValue: 'Approve' })
              : t('benchStations.revoke', { defaultValue: 'Revoke' })}
          </Button>
        </div>
      </form>
    </div>
  );
}

/** Compare codes the way a person reads them aloud: case, spaces and dashes
 *  do not matter. */
function normaliseCode(raw: string | null): string {
  return (raw ?? '').toUpperCase().replace(/[^0-9A-Z]/g, '');
}
