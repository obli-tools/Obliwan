import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import toast from 'react-hot-toast';
import { Camera, Download, GraduationCap, LogOut, RefreshCw } from 'lucide-react';
import type { LearningDeviceRow, LearningRunView } from '@obliwan/shared';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { TenantBadge } from '@/components/common/TenantBadge';
import { cn } from '@/utils/cn';
import { useTenantStore } from '@/store/tenantStore';
import { downloadText } from '@/api/query.api';
import { apiErrorText } from '@/components/variables/valueKinds';
import { learningApi, learningErrorCode } from '@/api/learning.api';
import { LearningDeviceDrawer } from '@/components/learning/LearningDeviceDrawer';

/**
 * Learning mode — routers whose production configuration ObliWAN learns
 * before any template may write to them.
 *
 * ┌─ WHAT THIS SCREEN PROMISES ──────────────────────────────────────────────┐
 * │ • « Mettre en apprentissage » refuses every template push on the router  │
 * │   until it leaves learning; targeted jobs (management access, APN,       │
 * │   compliance, OS upgrade) stay allowed.                                  │
 * │ • « Capturer » reads the router WITH its secrets (the sole exception):   │
 * │   every secret goes to the vault, server side; nothing on this page ever │
 * │   shows a value except the eye button (SECRET_READ, audited).            │
 * │ • The dataset is the REDACTED material only (secret:<ref>), not          │
 * │   pseudonymised — keep it outside any versioned repository.              │
 * └──────────────────────────────────────────────────────────────────────────┘
 */

const CARD = 'mb-4 rounded-xl border border-border bg-bg-secondary p-4';
const TH = 'px-2 py-1.5 text-left text-xs font-medium text-text-muted';
const TD = 'px-2 py-1.5 text-sm text-text-primary align-top';
const POLL_MS = 2000;

export function LearningPage() {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const currentTenantId = useTenantStore((s) => s.currentTenantId);
  const tenants = useTenantStore((s) => s.tenants);

  const [rows, setRows] = useState<LearningDeviceRow[]>([]);
  const [godView, setGodView] = useState(false);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [learningOnly, setLearningOnly] = useState(false);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [busy, setBusy] = useState(false);
  const [run, setRun] = useState<LearningRunView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const drawerId = Number(params.get('device') ?? '') || null;

  const errorText = useCallback((err: unknown): string => {
    const code = learningErrorCode(err);
    if (code) return t(`learning.error.${code}`, { defaultValue: apiErrorText(err) ?? code });
    return apiErrorText(err) ?? (err instanceof Error ? err.message : String(err));
  }, [t]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await learningApi.devices({ learningOnly, search });
      setRows(res.rows);
      setGodView(res.godView);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setLoading(false);
    }
  }, [learningOnly, search, errorText]);

  useEffect(() => {
    setSelected(new Set());
    setRun(null);
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentTenantId, learningOnly]);

  // Poll a running capture.
  useEffect(() => {
    if (!run || run.status !== 'running') return undefined;
    pollRef.current = setTimeout(() => {
      learningApi.run(run.runId)
        .then((r) => {
          setRun(r);
          if (r.status === 'done') void load();
        })
        .catch((err: unknown) => setError(errorText(err)));
    }, POLL_MS);
    return () => {
      if (pollRef.current) clearTimeout(pollRef.current);
    };
  }, [run, load, errorText]);

  const allSelected = rows.length > 0 && rows.every((r) => selected.has(r.deviceId));
  const ids = useMemo(() => [...selected], [selected]);
  const toggle = (id: number): void => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const setState = async (on: boolean, thenCapture = false): Promise<void> => {
    if (!on && !window.confirm(t('learning.confirm.disable'))) return;
    setBusy(true);
    setError(null);
    try {
      const res = await learningApi.setLearningBulk(ids, on);
      toast.success(t(on ? 'learning.toast.enabled' : 'learning.toast.disabled', { count: res.changed.length }));
      if (thenCapture) await capture();
      else await load();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  const capture = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      const started = await learningApi.startCapture(ids);
      toast.success(t('learning.run.started', { count: started.total }));
      setRun(await learningApi.run(started.runId));
      await load();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  const exportDataset = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      const ds = await learningApi.dataset(ids);
      const slug = (ds.tenant.name ?? `tenant-${ds.tenant.id}`).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
      const day = new Date().toISOString().slice(0, 10).replace(/-/g, '');
      downloadText(`obliwan-apprentissage-${slug}-${day}.json`, 'application/json', JSON.stringify(ds, null, 2));
      toast.success(t('learning.dataset.downloaded', { count: ds.devices.length }));
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  const openDrawer = (id: number | null): void => {
    const next = new URLSearchParams(params);
    if (id === null) next.delete('device');
    else next.set('device', String(id));
    setParams(next, { replace: true });
  };
  const drawerRow = drawerId ? rows.find((r) => r.deviceId === drawerId) : undefined;
  const tenantName = tenants.find((x) => x.id === currentTenantId)?.name ?? null;

  return (
    <div className="p-6">
      <div className="mb-5 flex flex-wrap items-center justify-between gap-2">
        <h1 className="flex items-center gap-2 text-2xl font-semibold text-text-primary">
          <GraduationCap size={22} /> {t('learning.title')}
        </h1>
        <Button size="sm" variant="secondary" onClick={() => void load()} loading={loading}>
          <RefreshCw size={14} /> {t('learning.refresh')}
        </Button>
      </div>
      {tenantName && <p className="mb-1 text-sm text-text-primary">{tenantName}</p>}
      <p className="mb-4 text-xs text-text-muted">{t('learning.help')}</p>

      {error && <div className="mb-4 rounded-md border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-400">{error}</div>}

      <div className={CARD}>
        <div className="mb-3 flex flex-wrap items-end gap-3">
          <div className="w-64">
            <Input
              id="learning-search"
              placeholder={t('learning.filter.search')}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') void load(); }}
            />
          </div>
          <label className="flex items-center gap-2 text-sm text-text-primary">
            <input type="checkbox" checked={learningOnly} onChange={(e) => setLearningOnly(e.target.checked)} />
            {t('learning.filter.learningOnly')}
          </label>
        </div>

        <div className="mb-3 flex flex-wrap items-center gap-2">
          <span className="text-xs text-text-muted">{t('learning.selected', { count: selected.size })}</span>
          <Button size="sm" disabled={selected.size === 0 || busy} onClick={() => void setState(true)}>
            <GraduationCap size={14} /> {t('learning.actions.enable')}
          </Button>
          <Button size="sm" disabled={selected.size === 0 || busy} onClick={() => void setState(true, true)}>
            <Camera size={14} /> {t('learning.actions.enableAndCapture')}
          </Button>
          <Button size="sm" variant="secondary" disabled={selected.size === 0 || busy} onClick={() => void capture()}>
            <Camera size={14} /> {t('learning.actions.capture')}
          </Button>
          <Button size="sm" variant="secondary" disabled={selected.size === 0 || busy} onClick={() => void exportDataset()}>
            <Download size={14} /> {t('learning.actions.exportDataset')}
          </Button>
          <Button size="sm" variant="danger" disabled={selected.size === 0 || busy} onClick={() => void setState(false)}>
            <LogOut size={14} /> {t('learning.actions.disable')}
          </Button>
        </div>
        <p className="mb-3 text-xs text-text-muted">{t('learning.dataset.hint')}</p>

        {run && (
          <div className="mb-3 rounded-md border border-border bg-bg-tertiary p-2 text-sm text-text-primary">
            {t('learning.run.progress', {
              done: run.total - run.counts.running,
              total: run.total,
              succeeded: run.counts.succeeded,
              failed: run.counts.failed,
              skipped: run.counts.skipped,
            })}
          </div>
        )}

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <th className={TH}>
                  <input
                    type="checkbox"
                    checked={allSelected}
                    onChange={() => setSelected(allSelected ? new Set() : new Set(rows.map((r) => r.deviceId)))}
                  />
                </th>
                <th className={TH}>{t('learning.table.site')}</th>
                <th className={TH}>{t('learning.table.device')}</th>
                <th className={TH}>{t('learning.table.state')}</th>
                <th className={TH}>{t('learning.table.lastCapture')}</th>
                <th className={TH}>{t('learning.table.wan1')}</th>
                <th className={TH}>{t('learning.table.pppoe')}</th>
                <th className={TH}>{t('learning.table.timezone')}</th>
                <th className={TH}>{t('learning.table.apn')}</th>
                <th className={TH}>{t('learning.table.vaulted')}</th>
                <th className={TH}>{t('learning.table.withheld')}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => {
                const c = r.lastCapture;
                return (
                  <tr key={r.deviceId} className="border-b border-border/60 hover:bg-bg-hover/40">
                    <td className={TD}>
                      <input type="checkbox" checked={selected.has(r.deviceId)} onChange={() => toggle(r.deviceId)} />
                    </td>
                    <td className={TD}>{r.site ? `${r.site.code} · ${r.site.name}` : '—'}</td>
                    <td className={TD}>
                      <button type="button" className="text-accent hover:underline" onClick={() => openDrawer(r.deviceId)}>
                        {r.deviceName}
                      </button>
                      {godView && <TenantBadge name={r.tenantName} tenantId={r.tenantId} className="ml-1" />}
                    </td>
                    <td className={TD}>
                      {r.learning ? (
                        <span className="rounded-full bg-accent/15 px-2 py-0.5 text-[11px] text-accent" title={new Date(r.learning.since).toLocaleString()}>
                          {t('learning.badge')}
                        </span>
                      ) : (
                        <span className="text-xs text-text-muted">{t('learning.off')}</span>
                      )}
                    </td>
                    <td className={TD}>
                      {c ? (
                        <span className={cn(
                          'text-xs',
                          c.status === 'succeeded' ? 'text-emerald-400' : c.status === 'running' ? 'text-text-muted' : 'text-amber-400',
                        )}>
                          {t(`learning.status.${c.status}`)}
                          {c.reason ? ` — ${t(`learning.reason.${c.reason}`)}` : ''}
                          <span className="block text-[10px] text-text-muted">{new Date(c.finishedAt ?? c.startedAt).toLocaleString()}</span>
                        </span>
                      ) : '—'}
                    </td>
                    <td className={TD}>
                      {c?.wan1Mode ? (
                        <span className={cn(c.wan1Mode === 'static' && 'font-semibold text-amber-400', c.wan1Mode === 'ambiguous' && 'text-red-400')}>
                          {t(`learning.facts.wan1Mode.${c.wan1Mode}`)}
                        </span>
                      ) : '—'}
                    </td>
                    <td className={TD}>{c?.pppoeName ?? '—'}</td>
                    <td className={TD}>{c?.timezone ?? '—'}</td>
                    <td className={TD}>{c && c.apns.length > 0 ? c.apns.join(', ') : '—'}</td>
                    <td className={TD}>{c?.secretCount ?? '—'}</td>
                    <td className={TD}>{c ? (c.withheldCount > 0 ? <span className="text-amber-400">{c.withheldCount}</span> : 0) : '—'}</td>
                  </tr>
                );
              })}
              {rows.length === 0 && !loading && (
                <tr><td className={cn(TD, 'text-text-muted')} colSpan={11}>{t('learning.empty')}</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {drawerId && (
        <LearningDeviceDrawer
          deviceId={drawerId}
          deviceName={drawerRow?.deviceName ?? `#${drawerId}`}
          onClose={() => openDrawer(null)}
        />
      )}
    </div>
  );
}
