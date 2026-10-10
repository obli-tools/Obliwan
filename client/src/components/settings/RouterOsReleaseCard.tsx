import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, RefreshCw, Target } from 'lucide-react';
import toast from 'react-hot-toast';
import {
  ROUTEROS_RELEASE_STALE_AFTER_HOURS,
  ROUTEROS_TARGET_MODES,
  validateRouterOsTarget,
  type RouterOsFirmwareStatus,
  type RouterOsReleaseInfo,
  type RouterOsTargetMode,
} from '@obliwan/shared';
import { firmwareApi } from '@/api/firmware.api';
import { Button } from '@/components/common/Button';
import { useAuthStore } from '@/store/authStore';
import { cn } from '@/utils/cn';

/**
 * RouterOS releases (latest stable / long-term read from MikroTik) and the
 * fleet's TARGET version, for the settings page.
 *
 * Readable by every signed-in user; the target selector and "Check now" are
 * enabled for a platform admin only (the server enforces it either way).
 *
 * A version that was never read renders as a dash, never as a version. A
 * channel whose last check failed still shows the last value read, with the
 * error beside it: that is what the server keeps, and hiding the value would
 * suggest MikroTik published nothing.
 */

const DASH = '—';

function errorText(err: unknown): string | null {
  const m = (err as { response?: { data?: { error?: unknown } } }).response?.data?.error;
  return typeof m === 'string' && m.trim() !== '' ? m : null;
}

/** "3 hours ago" / "il y a 3 heures", from Intl so no string needs translating. */
function relative(iso: string | null, lang: string): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  const diffS = Math.round((d.getTime() - Date.now()) / 1000);
  const a = Math.abs(diffS);
  const rtf = new Intl.RelativeTimeFormat(lang, { numeric: 'auto' });
  return a < 60 ? rtf.format(diffS, 'second')
    : a < 3600 ? rtf.format(Math.round(diffS / 60), 'minute')
      : a < 86_400 ? rtf.format(Math.round(diffS / 3600), 'hour')
        : rtf.format(Math.round(diffS / 86_400), 'day');
}

function absoluteDate(iso: string | null, lang: string): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d.toLocaleDateString(lang, { dateStyle: 'medium' });
}

function ChannelTile({ label, info, lang }: { label: string; info: RouterOsReleaseInfo; lang: string }) {
  const { t } = useTranslation();
  const checked = relative(info.lastSuccessAt, lang);
  const published = absoluteDate(info.releasedAt, lang);
  return (
    <div className="rounded-md border border-border bg-bg-tertiary/40 p-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs font-medium uppercase tracking-wide text-text-muted">{label}</p>
        {info.stale && info.version !== null && (
          <span
            className="rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium text-amber-500"
            title={t('firmware.routeros.staleHint', {
              defaultValue: 'Not read successfully for over {{hours}} hours.',
              hours: ROUTEROS_RELEASE_STALE_AFTER_HOURS,
            })}
          >
            {t('firmware.routeros.stale', { defaultValue: 'Stale' })}
          </span>
        )}
      </div>
      <p className="mt-1 font-mono text-2xl font-semibold text-text-primary">{info.version ?? DASH}</p>
      <p className="mt-1 text-xs text-text-muted">
        {info.version === null
          ? t('firmware.routeros.neverRead', { defaultValue: 'Never read yet' })
          : [
            published && t('firmware.routeros.publishedOn', { defaultValue: 'Published {{date}}', date: published }),
            checked && t('firmware.routeros.checkedAgo', { defaultValue: 'checked {{when}}', when: checked }),
          ].filter(Boolean).join(' · ')}
      </p>
      {info.lastError && (
        <p className="mt-2 flex items-start gap-1.5 text-xs text-amber-500">
          <AlertTriangle size={12} className="mt-0.5 shrink-0" />
          <span>
            {t('firmware.routeros.lastError', {
              defaultValue: 'Last check failed: {{error}}. The last value read is kept.',
              error: info.lastError,
            })}
          </span>
        </p>
      )}
    </div>
  );
}

const MODE_LABEL_KEY: Record<RouterOsTargetMode, [string, string]> = {
  stable: ['firmware.routeros.target.mode.stable', 'Latest stable'],
  'long-term': ['firmware.routeros.target.mode.longTerm', 'Latest long-term'],
  pinned: ['firmware.routeros.target.mode.pinned', 'Pinned version'],
};

export function RouterOsReleaseCard() {
  const { t, i18n } = useTranslation();
  const { isAdmin } = useAuthStore();
  const admin = isAdmin();
  const lang = i18n.language;

  const [status, setStatus] = useState<RouterOsFirmwareStatus | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);
  const [checking, setChecking] = useState(false);
  const [saving, setSaving] = useState(false);
  const [mode, setMode] = useState<RouterOsTargetMode>('stable');
  const [pinned, setPinned] = useState('');

  const adopt = useCallback((s: RouterOsFirmwareStatus) => {
    setStatus(s);
    // An unreadable stored target has no mode: leave the selector where it is.
    if (s.target.mode !== null) {
      setMode(s.target.mode);
      setPinned(s.target.pinned ?? '');
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    firmwareApi.getRouterOs()
      .then((s) => { if (!cancelled) { adopt(s); setLoadFailed(false); } })
      .catch(() => { if (!cancelled) setLoadFailed(true); });
    return () => { cancelled = true; };
  }, [adopt]);

  const candidate = { mode, pinned: mode === 'pinned' ? pinned.trim() : null };
  const valid = validateRouterOsTarget(candidate).ok;
  const dirty = status !== null
    && (status.target.mode !== mode || (mode === 'pinned' && (status.target.pinned ?? '') !== pinned.trim()));

  const save = async () => {
    if (!valid) return;
    setSaving(true);
    try {
      adopt(await firmwareApi.setTarget(candidate));
      toast.success(t('firmware.routeros.target.saved', { defaultValue: 'Target saved' }));
    } catch (err) {
      toast.error(errorText(err) ?? t('firmware.routeros.target.saveFailed', { defaultValue: 'Could not save the target' }));
    } finally {
      setSaving(false);
    }
  };

  const checkNow = async () => {
    setChecking(true);
    try {
      const r = await firmwareApi.checkNow();
      adopt(r.status);
      const failedChannels = r.outcomes.filter((o) => !o.ok).map((o) => o.channel);
      if (failedChannels.length) {
        toast.error(t('firmware.routeros.checkFailed', {
          defaultValue: 'Check failed for {{channels}}; the last values read are kept.',
          channels: failedChannels.join(', '),
        }));
      } else {
        toast.success(t('firmware.routeros.checked', { defaultValue: 'Releases checked' }));
      }
    } catch (err) {
      toast.error(errorText(err) ?? t('firmware.routeros.checkError', { defaultValue: 'Could not run the check' }));
    } finally {
      setChecking(false);
    }
  };

  const target = status?.target;
  const lastAttempt = relative(status?.lastCheckedAt ?? null, lang);

  return (
    <div>
      <h2 className="mb-1 text-lg font-semibold text-text-primary">
        {t('firmware.routeros.title', { defaultValue: 'RouterOS releases' })}
      </h2>
      <p className="mb-4 text-xs text-text-muted">
        {t('firmware.routeros.description', {
          defaultValue: 'Latest RouterOS 7 versions published by MikroTik, read once every 24 hours.',
        })}
      </p>

      <div className="rounded-lg border border-border bg-bg-secondary divide-y divide-border">
        {loadFailed && !status ? (
          <p className="p-4 text-sm text-red-400">
            {t('firmware.routeros.loadFailed', { defaultValue: 'Could not load RouterOS releases' })}
          </p>
        ) : !status ? (
          <p className="p-4 text-sm text-text-muted">{DASH}</p>
        ) : (
          <>
            <div className="grid gap-3 p-4 sm:grid-cols-2">
              <ChannelTile
                label={t('firmware.routeros.channel.stable', { defaultValue: 'Latest stable' })}
                info={status.stable}
                lang={lang}
              />
              <ChannelTile
                label={t('firmware.routeros.channel.longTerm', { defaultValue: 'Latest long-term' })}
                info={status.longTerm}
                lang={lang}
              />
            </div>

            <div className="p-4">
              <div className="flex items-start gap-3">
                <Target size={16} className="mt-0.5 shrink-0 text-text-muted" />
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-text-primary">
                    {t('firmware.routeros.target.title', { defaultValue: 'Fleet target version' })}
                  </p>
                  <p className="mt-0.5 text-xs text-text-muted">
                    {t('firmware.routeros.target.description', {
                      defaultValue: 'The version the bench and the fleet update aim at. Instance-wide; only a platform administrator can change it.',
                    })}
                  </p>

                  <div className="mt-3 flex flex-wrap items-center gap-2">
                    <select
                      value={mode}
                      disabled={!admin || saving}
                      onChange={(e) => setMode(e.target.value as RouterOsTargetMode)}
                      className={cn(
                        'w-48 rounded-md border border-border bg-bg-tertiary px-2 py-1 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent',
                        !admin && 'cursor-not-allowed text-text-muted',
                      )}
                    >
                      {ROUTEROS_TARGET_MODES.map((m) => (
                        <option key={m} value={m}>{t(MODE_LABEL_KEY[m][0], { defaultValue: MODE_LABEL_KEY[m][1] })}</option>
                      ))}
                    </select>
                    {mode === 'pinned' && (
                      <input
                        type="text"
                        inputMode="decimal"
                        value={pinned}
                        disabled={!admin || saving}
                        onChange={(e) => setPinned(e.target.value)}
                        placeholder={t('firmware.routeros.target.pinnedPlaceholder', { defaultValue: 'e.g. 7.24.5' })}
                        className={cn(
                          'w-32 rounded-md border bg-bg-tertiary px-2 py-1 font-mono text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-accent',
                          pinned.trim() !== '' && !valid ? 'border-red-500' : 'border-border',
                        )}
                      />
                    )}
                    {admin && (
                      <Button size="sm" onClick={() => void save()} disabled={!dirty || !valid} loading={saving}>
                        {t('firmware.routeros.target.save', { defaultValue: 'Save target' })}
                      </Button>
                    )}
                  </div>
                  {mode === 'pinned' && pinned.trim() !== '' && !valid && (
                    <p className="mt-1 text-xs text-red-400">
                      {t('firmware.routeros.target.pinnedInvalid', {
                        defaultValue: 'Enter a RouterOS 7 release version such as 7.24.5 (no rc or beta).',
                      })}
                    </p>
                  )}

                  {target && (
                    <div className="mt-3 text-xs">
                      {target.resolved !== null ? (
                        <p className="text-text-secondary">
                          {t('firmware.routeros.target.resolves', {
                            defaultValue: 'Resolves to {{version}}',
                            version: target.resolved,
                          })}
                          {target.isDefault && (
                            <span className="text-text-muted">
                              {' '}({t('firmware.routeros.target.default', { defaultValue: 'default' })})
                            </span>
                          )}
                          {target.stale && (
                            <span className="ml-2 text-amber-500">
                              {t('firmware.routeros.target.staleWarning', {
                                defaultValue: 'From a reading older than {{hours}} hours.',
                                hours: ROUTEROS_RELEASE_STALE_AFTER_HOURS,
                              })}
                            </span>
                          )}
                        </p>
                      ) : (
                        <p className="flex items-start gap-1.5 text-amber-500">
                          <AlertTriangle size={12} className="mt-0.5 shrink-0" />
                          <span>
                            {target.unresolvedReason === 'TARGET_UNREADABLE'
                              ? t('firmware.routeros.target.unresolved.TARGET_UNREADABLE', {
                                defaultValue: 'The stored target cannot be read: choose it again.',
                              })
                              : t('firmware.routeros.target.unresolved.NO_RELEASE_KNOWN', {
                                defaultValue: 'No release has been read yet: there is nothing to aim at.',
                              })}
                          </span>
                        </p>
                      )}
                      {target.updatedAt && (
                        <p className="mt-0.5 text-text-muted">
                          {t('firmware.routeros.target.updated', {
                            defaultValue: 'Changed {{when}}',
                            when: relative(target.updatedAt, lang) ?? DASH,
                          })}
                        </p>
                      )}
                    </div>
                  )}
                  {!admin && (
                    <p className="mt-2 text-xs text-text-muted">
                      {t('firmware.routeros.target.adminOnly', {
                        defaultValue: 'Only a platform administrator can change the target.',
                      })}
                    </p>
                  )}
                </div>
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 p-4">
              <p className="text-xs text-text-muted">
                {t('firmware.routeros.schedule', {
                  defaultValue: 'Checked automatically every {{hours}} h. Last attempt: {{when}}.',
                  hours: status.checkIntervalHours,
                  when: lastAttempt ?? t('firmware.routeros.neverChecked', { defaultValue: 'never' }),
                })}
              </p>
              {admin && (
                <Button size="sm" variant="secondary" onClick={() => void checkNow()} loading={checking}>
                  <RefreshCw size={14} className="mr-1.5" />
                  {t('firmware.routeros.checkNow', { defaultValue: 'Check now' })}
                </Button>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
