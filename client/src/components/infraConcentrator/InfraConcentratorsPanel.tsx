import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { CheckCircle2, Plug, Plus, ShieldAlert, Trash2, XCircle } from 'lucide-react';
import {
  DEFAULT_INFRA_CONCENTRATOR_PARAMS,
  type InfraConcentratorKind,
  type InfraConcentratorView,
  type InfraDriverResult,
} from '@obliwan/shared';
import { Button } from '@/components/common/Button';
import { allocationApi, type ConcentratorOption } from '@/api/allocation.api';
import { infraConcentratorApi, infraErrorOf, type InfraConcentratorInput } from '@/api/infraConcentrator.api';

/**
 * Each customer's infrastructure VPN concentrator, declared and tested from the
 * tenant's allocation screen (platform admin). A CHR is linked to its device
 * (its RouterOS channel and credential are the device's); an OPNsense takes a
 * REST API key and secret, WRITE-only, and its certificate is pinned on the
 * first test. Site accounts are created from the site page.
 */

const INPUT =
  'w-full rounded-lg border border-border bg-bg-primary px-3 py-1.5 text-sm text-text-primary ' +
  'focus:outline-none focus:ring-1 focus:ring-accent';
const LABEL = 'block text-xs text-text-muted mb-1';
const CARD = 'mb-4 rounded-xl border border-border bg-bg-secondary p-4';
const TH = 'px-2 py-1.5 text-left text-xs font-medium text-text-muted';
const TD = 'px-2 py-1.5 text-sm text-text-primary align-top';

interface Draft {
  kind: InfraConcentratorKind;
  name: string;
  host: string;
  port: string;
  deviceId: string;
  apiKey: string;
  apiSecret: string;
  tlsFingerprint: string;
  usernameKey: string;
  passwordKey: string;
  remoteAddressKey: string;
  pppProfile: string;
}

const EMPTY: Draft = {
  kind: 'routeros_chr',
  name: '',
  host: '',
  port: '',
  deviceId: '',
  apiKey: '',
  apiSecret: '',
  tlsFingerprint: '',
  usernameKey: DEFAULT_INFRA_CONCENTRATOR_PARAMS.usernameKey,
  passwordKey: DEFAULT_INFRA_CONCENTRATOR_PARAMS.passwordKey,
  remoteAddressKey: '',
  pppProfile: '',
};

function inputOf(d: Draft): InfraConcentratorInput {
  const base: InfraConcentratorInput = {
    kind: d.kind,
    name: d.name.trim(),
    host: d.host.trim(),
    port: d.port.trim() === '' ? null : Number(d.port),
    params: {
      usernameKey: d.usernameKey.trim(),
      passwordKey: d.passwordKey.trim(),
      remoteAddressKey: d.remoteAddressKey.trim() === '' ? null : d.remoteAddressKey.trim(),
      pppProfile: d.pppProfile.trim() === '' ? null : d.pppProfile.trim(),
    },
  };
  if (d.kind === 'routeros_chr') return { ...base, deviceId: d.deviceId ? Number(d.deviceId) : null };
  return {
    ...base,
    apiKey: d.apiKey,
    apiSecret: d.apiSecret,
    tlsFingerprint: d.tlsFingerprint.trim() === '' ? null : d.tlsFingerprint.trim(),
  };
}

export function InfraConcentratorsPanel({ tenantId }: { tenantId: number }) {
  const { t } = useTranslation();
  const [rows, setRows] = useState<InfraConcentratorView[]>([]);
  const [devices, setDevices] = useState<ConcentratorOption[]>([]);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [busy, setBusy] = useState<number | 'new' | null>(null);
  const [results, setResults] = useState<Record<number, InfraDriverResult>>({});
  const [rotate, setRotate] = useState<{ id: number; apiKey: string; apiSecret: string } | null>(null);

  const load = useCallback(async () => {
    try {
      setRows(await infraConcentratorApi.list(tenantId));
    } catch (err) {
      toast.error(infraErrorOf(err) ?? t('infraConcentrator.loadFailed'));
    }
  }, [tenantId, t]);

  useEffect(() => {
    void load();
    allocationApi
      .concentrators()
      .then((all) => setDevices(all.filter((d) => d.tenantId === tenantId || d.tenantId === 1)))
      .catch(() => setDevices([]));
  }, [load, tenantId]);

  const set = (patch: Partial<Draft>) => setDraft((d) => (d ? { ...d, ...patch } : d));

  const save = async () => {
    if (!draft) return;
    setBusy('new');
    try {
      await infraConcentratorApi.create(tenantId, inputOf(draft));
      toast.success(t('infraConcentrator.saved'));
      setDraft(null);
      await load();
    } catch (err) {
      toast.error(infraErrorOf(err) ?? t('infraConcentrator.saveFailed'));
    } finally {
      setBusy(null);
    }
  };

  const test = async (row: InfraConcentratorView) => {
    setBusy(row.id);
    try {
      const r = await infraConcentratorApi.test(row.id);
      setResults((m) => ({ ...m, [row.id]: r }));
      await load();
    } catch (err) {
      toast.error(infraErrorOf(err) ?? t('infraConcentrator.testFailed'));
    } finally {
      setBusy(null);
    }
  };

  const update = async (row: InfraConcentratorView, input: InfraConcentratorInput) => {
    setBusy(row.id);
    try {
      await infraConcentratorApi.update(row.id, input);
      await load();
      return true;
    } catch (err) {
      toast.error(infraErrorOf(err) ?? t('infraConcentrator.saveFailed'));
      return false;
    } finally {
      setBusy(null);
    }
  };

  const remove = async (row: InfraConcentratorView) => {
    if (!window.confirm(t('infraConcentrator.confirmDelete', { name: row.name }))) return;
    setBusy(row.id);
    try {
      await infraConcentratorApi.remove(row.id);
      await load();
    } catch (err) {
      toast.error(infraErrorOf(err) ?? t('infraConcentrator.saveFailed'));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className={CARD}>
      <div className="mb-2 flex items-center gap-2">
        <h2 className="flex-1 text-sm font-semibold text-text-primary">{t('infraConcentrator.title')}</h2>
        {!draft && (
          <Button size="sm" variant="secondary" onClick={() => setDraft({ ...EMPTY })}>
            <Plus size={14} /> {t('infraConcentrator.declare')}
          </Button>
        )}
      </div>
      <p className="mb-3 text-xs text-text-muted">{t('infraConcentrator.hint')}</p>

      {rows.length === 0 ? (
        <p className="rounded-md border border-dashed border-border px-3 py-4 text-center text-xs text-text-muted">
          {t('infraConcentrator.none')}
        </p>
      ) : (
        <table className="w-full">
          <thead>
            <tr>
              <th className={TH}>{t('infraConcentrator.fields.name')}</th>
              <th className={TH}>{t('infraConcentrator.fields.kind')}</th>
              <th className={TH}>{t('infraConcentrator.fields.host')}</th>
              <th className={TH}>{t('infraConcentrator.fields.access')}</th>
              <th className={TH}>{t('infraConcentrator.fields.lastTest')}</th>
              <th className={TH}>{t('infraConcentrator.fields.accounts')}</th>
              <th className={TH} />
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const r = results[row.id];
              return (
                <tr key={row.id} className="border-t border-border">
                  <td className={TD}>
                    {row.name}
                    {!row.enabled && <span className="ml-1 text-xs text-text-muted">({t('infraConcentrator.disabled')})</span>}
                  </td>
                  <td className={TD}>{t(`infraConcentrator.kinds.${row.kind}`)}</td>
                  <td className={TD}>
                    <span className="font-mono text-xs">{row.host}{row.port ? `:${row.port}` : ''}</span>
                  </td>
                  <td className={TD}>
                    {row.kind === 'routeros_chr' ? (
                      <span className="text-xs">{t('infraConcentrator.viaDevice', { name: row.deviceName ?? `#${row.deviceId}` })}</span>
                    ) : (
                      <div className="space-y-1 text-xs">
                        <div>{row.hasCredential ? t('infraConcentrator.keyInVault') : t('infraConcentrator.noKey')}</div>
                        <div className="font-mono text-[10px] text-text-muted" title={row.tlsFingerprint ?? ''}>
                          {row.tlsFingerprint
                            ? `${t('infraConcentrator.pinned')} ${row.tlsFingerprint.slice(0, 16)}…`
                            : t('infraConcentrator.notPinned')}
                        </div>
                      </div>
                    )}
                  </td>
                  <td className={TD}>
                    {row.lastTestAt === null ? (
                      <span className="text-xs text-text-muted">{t('infraConcentrator.neverTested')}</span>
                    ) : (
                      <div className="flex items-start gap-1 text-xs">
                        {row.lastTestOk ? (
                          <CheckCircle2 size={14} className="mt-0.5 shrink-0 text-status-up" />
                        ) : (
                          <XCircle size={14} className="mt-0.5 shrink-0 text-status-down" />
                        )}
                        <span>{row.lastTestMessage}</span>
                      </div>
                    )}
                    {r && r.details.length > 0 && (
                      <ul className="mt-1 list-disc pl-5 text-[11px] text-text-muted">
                        {r.details.map((d) => <li key={d}>{d}</li>)}
                      </ul>
                    )}
                  </td>
                  <td className={TD}>{row.accountCount}</td>
                  <td className={TD}>
                    <div className="flex flex-wrap justify-end gap-1">
                      <Button size="sm" variant="secondary" disabled={busy !== null} onClick={() => void test(row)}>
                        <Plug size={13} /> {t('infraConcentrator.test')}
                      </Button>
                      <Button size="sm" variant="ghost" disabled={busy !== null} onClick={() => void update(row, { enabled: !row.enabled })}>
                        {row.enabled ? t('infraConcentrator.disable') : t('infraConcentrator.enable')}
                      </Button>
                      {row.kind === 'opnsense' && row.tlsFingerprint && (
                        <Button
                          size="sm"
                          variant="ghost"
                          disabled={busy !== null}
                          onClick={() => {
                            if (window.confirm(t('infraConcentrator.confirmClearPin'))) void update(row, { tlsFingerprint: null });
                          }}
                        >
                          <ShieldAlert size={13} /> {t('infraConcentrator.clearPin')}
                        </Button>
                      )}
                      {row.kind === 'opnsense' && (
                        <Button size="sm" variant="ghost" disabled={busy !== null} onClick={() => setRotate({ id: row.id, apiKey: '', apiSecret: '' })}>
                          {t('infraConcentrator.replaceKey')}
                        </Button>
                      )}
                      <Button size="sm" variant="danger" disabled={busy !== null} onClick={() => void remove(row)} aria-label={t('common.delete')}>
                        <Trash2 size={13} />
                      </Button>
                    </div>
                    {rotate?.id === row.id && (
                      <div className="mt-2 space-y-1">
                        <input className={INPUT} placeholder={t('infraConcentrator.fields.apiKey')} value={rotate.apiKey}
                          onChange={(e) => setRotate({ ...rotate, apiKey: e.target.value })} autoComplete="off" />
                        <input className={INPUT} type="password" placeholder={t('infraConcentrator.fields.apiSecret')} value={rotate.apiSecret}
                          onChange={(e) => setRotate({ ...rotate, apiSecret: e.target.value })} autoComplete="new-password" />
                        <div className="flex justify-end gap-1">
                          <Button size="sm" variant="ghost" onClick={() => setRotate(null)}>{t('common.cancel')}</Button>
                          <Button
                            size="sm"
                            disabled={!rotate.apiKey || !rotate.apiSecret || busy !== null}
                            onClick={async () => {
                              if (await update(row, { apiKey: rotate.apiKey, apiSecret: rotate.apiSecret })) setRotate(null);
                            }}
                          >
                            {t('common.save')}
                          </Button>
                        </div>
                      </div>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}

      {draft && (
        <div className="mt-3 rounded-lg border border-border p-3">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
            <div>
              <label className={LABEL}>{t('infraConcentrator.fields.kind')}</label>
              <select className={INPUT} value={draft.kind} onChange={(e) => set({ kind: e.target.value as InfraConcentratorKind })}>
                <option value="routeros_chr">{t('infraConcentrator.kinds.routeros_chr')}</option>
                <option value="opnsense">{t('infraConcentrator.kinds.opnsense')}</option>
              </select>
            </div>
            <div>
              <label className={LABEL}>{t('infraConcentrator.fields.name')}</label>
              <input className={INPUT} value={draft.name} onChange={(e) => set({ name: e.target.value })} />
            </div>
            <div>
              <label className={LABEL}>
                {draft.kind === 'routeros_chr' ? t('infraConcentrator.fields.hostChr') : t('infraConcentrator.fields.hostApi')}
              </label>
              <input className={INPUT} value={draft.host} onChange={(e) => set({ host: e.target.value })} />
            </div>
            <div>
              <label className={LABEL}>{t('infraConcentrator.fields.port')}</label>
              <input className={INPUT} value={draft.port} placeholder={draft.kind === 'opnsense' ? '443' : ''} onChange={(e) => set({ port: e.target.value })} />
            </div>
            {draft.kind === 'routeros_chr' ? (
              <div className="md:col-span-2">
                <label className={LABEL}>{t('infraConcentrator.fields.device')}</label>
                <select className={INPUT} value={draft.deviceId} onChange={(e) => set({ deviceId: e.target.value })}>
                  <option value="">—</option>
                  {devices.map((d) => <option key={d.id} value={d.id}>{d.name} (#{d.id})</option>)}
                </select>
                <p className="mt-1 text-[11px] text-text-muted">{t('infraConcentrator.deviceHint')}</p>
              </div>
            ) : (
              <>
                <div>
                  <label className={LABEL}>{t('infraConcentrator.fields.apiKey')}</label>
                  <input className={INPUT} value={draft.apiKey} autoComplete="off" onChange={(e) => set({ apiKey: e.target.value })} />
                </div>
                <div>
                  <label className={LABEL}>{t('infraConcentrator.fields.apiSecret')}</label>
                  <input className={INPUT} type="password" value={draft.apiSecret} autoComplete="new-password"
                    onChange={(e) => set({ apiSecret: e.target.value })} />
                </div>
                <div className="md:col-span-2">
                  <label className={LABEL}>{t('infraConcentrator.fields.fingerprint')}</label>
                  <input className={INPUT} value={draft.tlsFingerprint} placeholder={t('infraConcentrator.fingerprintPlaceholder')}
                    onChange={(e) => set({ tlsFingerprint: e.target.value })} />
                </div>
              </>
            )}
            <div>
              <label className={LABEL}>{t('infraConcentrator.fields.usernameKey')}</label>
              <input className={INPUT} value={draft.usernameKey} onChange={(e) => set({ usernameKey: e.target.value })} />
            </div>
            <div>
              <label className={LABEL}>{t('infraConcentrator.fields.passwordKey')}</label>
              <input className={INPUT} value={draft.passwordKey} onChange={(e) => set({ passwordKey: e.target.value })} />
            </div>
            <div>
              <label className={LABEL}>{t('infraConcentrator.fields.remoteAddressKey')}</label>
              <input className={INPUT} value={draft.remoteAddressKey} onChange={(e) => set({ remoteAddressKey: e.target.value })} />
            </div>
            <div>
              <label className={LABEL}>{t('infraConcentrator.fields.pppProfile')}</label>
              <input className={INPUT} value={draft.pppProfile} placeholder="default" onChange={(e) => set({ pppProfile: e.target.value })} />
            </div>
          </div>
          <div className="mt-3 flex justify-end gap-2">
            <Button size="sm" variant="ghost" onClick={() => setDraft(null)}>{t('common.cancel')}</Button>
            <Button size="sm" disabled={busy !== null || !draft.name || !draft.host} onClick={() => void save()}>
              {t('common.save')}
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
