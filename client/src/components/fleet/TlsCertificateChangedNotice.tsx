import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ShieldAlert, X } from 'lucide-react';
import toast from 'react-hot-toast';
import { CAPABILITIES, type TlsRepinRefusal } from '@obliwan/shared';
import { Button } from '@/components/common/Button';
import { useAuthStore } from '@/store/authStore';
import { anonHostname } from '@/utils/anonymize';
import type { DeviceTransport } from '@/types/fleet';
import { tlsRepinApi, tlsRepinRefusalOf } from './tlsRepin.api';

/**
 * Under the RouterOS API channel of the device page: the certificate the
 * device PRESENTED when ObliWAN refused it against the pin, beside that pin,
 * and the one gesture that re-pins to it.
 *
 * Drawn only when the server recorded a presented fingerprint that differs from
 * the pin, on an enabled channel that still uses TLS. The button sends back exactly the two values shown — the server
 * accepts only the fingerprint it recorded itself, and only while the pin is
 * still the one the operator read. The confirmation states both fingerprints
 * and the consequence, because the same screen is what an interception would
 * look like: a re-pin is a human vouching for a certificate, not a fix.
 *
 * Rights mirror the server: CREDENTIAL_MANAGE, and a platform administrator
 * for a concentrator (shared by every workspace). The server decides; this
 * only decides whether to draw the button.
 */
export function TlsCertificateChangedNotice({
  deviceId,
  deviceName,
  isConcentrator,
  transport,
  onRepinned,
}: {
  deviceId: number;
  deviceName: string;
  isConcentrator: boolean;
  transport: DeviceTransport;
  onRepinned: () => Promise<void>;
}) {
  const { t } = useTranslation();
  const canManage = useAuthStore((s) => s.hasCapability(CAPABILITIES.CREDENTIAL_MANAGE));
  const platformAdmin = useAuthStore((s) => s.isAdmin());
  const [confirming, setConfirming] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const presented = transport.tlsPresentedSha256 ?? null;
  // Sent back exactly as stored: the server compares it with the stored text.
  const pinned = transport.tlsFingerprintSha256;
  // The transport form accepts the `AA:BB:…` spelling of a pin; the pool
  // compares it without colons, in lower case, and so does this test.
  const samePin = pinned !== null && pinned.replace(/[:\s]/g, '').toLowerCase() === presented;
  // Only on an enabled channel that dials over TLS: a record left on one since
  // switched to cleartext, or disabled, describes a handshake ObliWAN no
  // longer makes, and "the device presents another certificate" would be read
  // as a fact about now.
  if (transport.transport !== 'routeros_api' || !transport.useTls || !transport.enabled) return null;
  if (!presented || samePin) return null;

  const allowed = canManage && (!isConcentrator || platformAdmin);
  const since = transport.tlsPresentedAt ? new Date(transport.tlsPresentedAt).toLocaleString() : null;
  const name = anonHostname(deviceName);

  const refusalText = (code: TlsRepinRefusal | null, message: string | null): string => {
    if (code) return t(`devices.tlsRepin.refusal.${code}`, { defaultValue: message ?? code });
    return message ?? t('devices.tlsRepin.failed');
  };

  const submit = async () => {
    setSubmitting(true);
    try {
      const result = await tlsRepinApi.repin(deviceId, { presented, pinned });
      if (result.check.kind === 'done' && result.check.outcome === 'ok') {
        toast.success(t('devices.tlsRepin.doneOk'));
      } else {
        const why = result.check.kind === 'done'
          ? result.check.lastError ?? result.check.outcome
          : result.check.reason;
        // The re-pin stands; only the check that followed did not pass.
        toast(t('devices.tlsRepin.doneCheckFailed', { reason: why }), { duration: 8000 });
      }
      setConfirming(false);
      await onRepinned();
    } catch (err) {
      const { code, message } = tlsRepinRefusalOf(err);
      toast.error(refusalText(code, message));
      // A pin that moved or a record that is gone: what is on screen is stale.
      if (code === 'pin_changed' || code === 'nothing_recorded' || code === 'presented_mismatch') {
        setConfirming(false);
        await onRepinned();
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="mt-2 rounded-md border border-status-down/40 bg-status-down/5 p-2.5">
      <div className="flex items-start gap-2">
        <ShieldAlert size={14} className="mt-0.5 shrink-0 text-status-down" />
        <div className="min-w-0 flex-1 space-y-1.5">
          <p className="text-xs font-medium text-status-down">{t('devices.tlsRepin.title')}</p>
          <p className="text-[11px] text-text-secondary">
            {since ? t('devices.tlsRepin.explainSince', { since }) : t('devices.tlsRepin.explain')}
          </p>
          <dl className="space-y-0.5 font-mono text-[10px]">
            <div className="break-all">
              <dt className="inline text-text-muted">{t('devices.tlsRepin.pinned')}: </dt>
              <dd className="inline text-text-primary">{pinned ?? '—'}</dd>
            </div>
            <div className="break-all">
              <dt className="inline text-text-muted">{t('devices.tlsRepin.presented')}: </dt>
              <dd className="inline text-status-down">{presented}</dd>
            </div>
          </dl>
          {allowed ? (
            <Button size="sm" variant="secondary" onClick={() => setConfirming(true)}>
              {t('devices.tlsRepin.button')}
            </Button>
          ) : (
            <p className="text-[11px] text-text-muted">
              {isConcentrator && canManage
                ? t('devices.tlsRepin.concentratorAdminOnly')
                : t('devices.tlsRepin.noRight')}
            </p>
          )}
        </div>
      </div>

      {confirming && (
        <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/70 p-4">
          <div className="my-8 w-full max-w-xl rounded-xl border border-border bg-bg-secondary shadow-2xl">
            <div className="flex items-start gap-3 border-b border-border px-5 py-4">
              <ShieldAlert size={20} className="mt-0.5 shrink-0 text-status-down" />
              <h2 className="flex-1 text-base font-semibold text-text-primary">
                {t('devices.tlsRepin.confirmTitle', { name })}
              </h2>
              <button
                onClick={() => setConfirming(false)}
                className="text-text-muted hover:text-text-primary"
                aria-label={t('common.cancel')}
              >
                <X size={18} />
              </button>
            </div>
            <div className="space-y-3 p-5 text-[13px] text-text-primary">
              <p>{t('devices.tlsRepin.confirmBody')}</p>
              <dl className="space-y-1.5 rounded-md border border-border bg-bg-tertiary p-3 font-mono text-[11px]">
                <div>
                  <dt className="text-text-muted">{t('devices.tlsRepin.confirmReplaced')}</dt>
                  <dd className="break-all text-text-primary">{pinned ?? '—'}</dd>
                </div>
                <div>
                  <dt className="text-text-muted">{t('devices.tlsRepin.confirmNew')}</dt>
                  <dd className="break-all text-status-down">{presented}</dd>
                </div>
              </dl>
              <p className="rounded-md border border-status-down/40 bg-status-down/5 p-3 text-status-down">
                {t('devices.tlsRepin.confirmWarning')}
              </p>
              {isConcentrator && <p>{t('devices.tlsRepin.confirmConcentrator')}</p>}
              <p className="text-text-secondary">{t('devices.tlsRepin.confirmCheck')}</p>
            </div>
            <div className="flex justify-end gap-2 border-t border-border px-5 py-3">
              <Button size="sm" variant="secondary" onClick={() => setConfirming(false)} disabled={submitting}>
                {t('common.cancel')}
              </Button>
              <Button size="sm" variant="danger" loading={submitting} onClick={() => void submit()}>
                {t('devices.tlsRepin.confirmButton')}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
