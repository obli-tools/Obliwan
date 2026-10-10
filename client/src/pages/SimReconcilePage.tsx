import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { CheckCheck, RefreshCw } from 'lucide-react';
import toast from 'react-hot-toast';
import { isMasterTenant } from '@obliwan/shared';
import { errorMessageOf } from '@/api/sim.api';
import {
  simReconcileApi,
  type SimClientCandidate,
  type SimClientRow,
  type SimLinesOnUnmap,
} from '@/api/simReconcile.api';
import { useAuthStore } from '@/store/authStore';
import { useTenantStore } from '@/store/tenantStore';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { EmptyState, When } from '@/components/mobile/SimBits';
import { SimLinkConflicts } from '@/components/mobile/SimLinkConflicts';
import { UnmapClientsDialog, unmapKey } from '@/components/mobile/UnmapClientsDialog';

/**
 * « Rapprochement SIM » — which customer workspace each partner client's lines
 * belong to (migration 081). One decision per client; the sweep applies it
 * to the client's lines now and on every later sweep. Unmapped clients first.
 *
 * The automatic rule (server, clientTenant.service.ts) only fires when exactly
 * one workspace matches by BOTH name and site codes; everything else is shown
 * here as a suggestion with its reason, for a human to decide.
 *
 * Removing a mapping asks, client by client and with no default, whether the
 * lines stay in the workspace or return to the pool (UnmapClientsDialog); the
 * removal is recorded, and the automatic rule no longer maps that client.
 */
const selectClass =
  'w-full rounded-md border border-border bg-bg-tertiary px-2 py-1 text-[13px] text-text-primary focus:outline-none focus:ring-1 focus:ring-accent';

const rowKey = (r: { accountId: number; clientCode: string }) => `${r.accountId}\u0000${r.clientCode}`;

export function SimReconcilePage() {
  const { t, i18n } = useTranslation();
  const tenants = useTenantStore((s) => s.tenants);
  const fetchTenants = useTenantStore((s) => s.fetchTenants);
  const currentTenantId = useTenantStore((s) => s.currentTenantId);
  const isPlatformAdmin = useAuthStore((s) => s.isAdmin)();
  const allowed = isPlatformAdmin && isMasterTenant(currentTenantId);

  const [rows, setRows] = useState<SimClientRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  /** Pending choice per row: tenant id, '' = unmap, undefined = unchanged. */
  const [choice, setChoice] = useState<Record<string, string>>({});
  /** Clients whose mapping is being removed: the dialog asks what their lines do. */
  const [unmapping, setUnmapping] = useState<SimClientRow[] | null>(null);

  const load = useCallback(async () => {
    if (!allowed) {
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      setRows(await simReconcileApi.clients());
      setChoice({});
    } catch (err) {
      toast.error(errorMessageOf(err));
    } finally {
      setLoading(false);
    }
  }, [allowed]);

  useEffect(() => {
    void load();
    if (allowed && tenants.length === 0) void fetchTenants?.();
  }, [load, allowed, tenants.length, fetchTenants]);

  const changed = useMemo(
    () =>
      rows.filter((r) => {
        const c = choice[rowKey(r)];
        if (c === undefined) return false;
        const current = r.mapping ? String(r.mapping.tenantId) : '';
        return c !== current;
      }),
    [rows, choice],
  );

  const acceptSuggestions = () => {
    const next = { ...choice };
    for (const r of rows) {
      if (!r.mapping && r.candidates[0]) next[rowKey(r)] = String(r.candidates[0].tenantId);
    }
    setChoice(next);
  };

  const apply = () => {
    if (changed.length === 0) return;
    // A removal (a mapped client set to "not mapped") asks first what its lines do.
    const removals = changed.filter((r) => choice[rowKey(r)] === '' && r.mapping);
    if (removals.length > 0) {
      setUnmapping(removals);
      return;
    }
    void send(new Map());
  };

  const send = async (linesOnUnmap: Map<string, SimLinesOnUnmap>) => {
    if (changed.length === 0) return;
    setSaving(true);
    try {
      const results = await simReconcileApi.apply(
        changed.map((r) => {
          const c = choice[rowKey(r)];
          const lines = c === '' ? linesOnUnmap.get(unmapKey(r)) : undefined;
          return {
            accountId: r.accountId,
            clientCode: r.clientCode,
            tenantId: c === '' ? null : Number(c),
            ...(lines ? { linesOnUnmap: lines } : {}),
          };
        }),
      );
      setUnmapping(null);
      const ok = results.filter((x) => x.ok);
      const moved = ok.reduce((n, x) => n + (x.moved ?? 0), 0);
      const kept = ok.reduce((n, x) => n + (x.keptElsewhere ?? 0), 0);
      const pooled = ok.reduce((n, x) => n + (x.returnedToPool ?? 0), 0);
      const onRouter = ok.reduce((n, x) => n + (x.keptOnRouter ?? 0), 0);
      toast.success(
        t('simReconcile.applied', {
          defaultValue: '{{clients}} client(s) saved, {{moved}} line(s) moved',
          clients: ok.length,
          moved,
        }),
      );
      if (kept > 0) {
        toast(t('simReconcile.keptElsewhere', {
          defaultValue: '{{count}} line(s) placed by hand in another workspace were left there',
          count: kept,
        }));
      }
      if (pooled > 0) {
        toast(t('simReconcile.returnedToPool', {
          defaultValue: '{{count}} line(s) returned to the pool',
          count: pooled,
        }));
      }
      if (onRouter > 0) {
        toast(t('simReconcile.keptOnRouter', {
          defaultValue: '{{count}} line(s) on a router of the workspace were left there',
          count: onRouter,
        }));
      }
      for (const f of results.filter((x) => !x.ok)) toast.error(`${f.clientCode}: ${f.error ?? ''}`);
      await load();
    } catch (err) {
      toast.error(errorMessageOf(err));
    } finally {
      setSaving(false);
    }
  };

  if (!allowed) {
    return (
      <EmptyState
        message={t('simReconcile.masterOnly', {
          defaultValue: 'SIM reconciliation is a platform action: switch to the master workspace as a platform administrator.',
        })}
      />
    );
  }

  const reason = (c: SimClientCandidate): string => {
    const parts: string[] = [];
    if (c.nameMatch === 'exact') parts.push(t('simReconcile.reasonNameExact', { defaultValue: 'same name' }));
    if (c.nameMatch === 'partial') parts.push(t('simReconcile.reasonNamePartial', { defaultValue: 'similar name' }));
    if (c.siteCodes.length > 0) {
      parts.push(t('simReconcile.reasonSites', { defaultValue: 'site codes {{codes}}', codes: c.siteCodes.join(', ') }));
    }
    return parts.join(' + ');
  };

  return (
    <div className="space-y-4 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-lg font-semibold text-text-primary">
            {t('simReconcile.title', { defaultValue: 'SIM reconciliation' })}
          </h1>
          <p className="text-[13px] text-text-secondary">
            {t('simReconcile.intro', {
              defaultValue:
                'Which workspace each partner client belongs to. Its lines follow, now and on every sweep; a line whose partner site label carries one of that workspace\'s site codes is attached to the site. Automatic only when exactly one workspace matches by both name and site codes.',
            })}
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="ghost" size="sm" onClick={() => void load()} disabled={loading}>
            <RefreshCw size={14} />
          </Button>
          <Button variant="secondary" size="sm" onClick={acceptSuggestions} disabled={loading || saving}>
            {t('simReconcile.acceptSuggestions', { defaultValue: 'Pre-fill suggestions' })}
          </Button>
          <Button size="sm" onClick={apply} disabled={saving || changed.length === 0}>
            <CheckCheck size={14} />
            <span className="ml-1">
              {t('simReconcile.apply', { defaultValue: 'Apply ({{count}})', count: changed.length })}
            </span>
          </Button>
        </div>
      </div>

      {unmapping && (
        <UnmapClientsDialog
          clients={unmapping}
          busy={saving}
          onCancel={() => setUnmapping(null)}
          onConfirm={(choices) => void send(choices)}
        />
      )}

      {/* Cards read in a router whose line could not be linked to it (brick 3). */}
      <SimLinkConflicts />

      <h2 className="pt-2 text-sm font-semibold text-text-primary">
        {t('simReconcile.clientsTitle', { defaultValue: 'Partner clients' })}
      </h2>
      {loading ? (
        <LoadingSpinner />
      ) : rows.length === 0 ? (
        <EmptyState message={t('simReconcile.empty', { defaultValue: 'No partner client known yet: run a sweep first.' })} />
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-[13px]">
            <thead className="bg-bg-secondary text-left text-text-secondary">
              <tr>
                <th className="px-3 py-2">{t('simReconcile.colClient', { defaultValue: 'Client' })}</th>
                <th className="px-3 py-2">{t('simReconcile.colName', { defaultValue: 'Company name' })}</th>
                <th className="px-3 py-2 text-right">{t('simReconcile.colLines', { defaultValue: 'Lines' })}</th>
                <th className="px-3 py-2">{t('simReconcile.colSuggestion', { defaultValue: 'Suggestion' })}</th>
                <th className="px-3 py-2">{t('simReconcile.colMapping', { defaultValue: 'Current mapping' })}</th>
                <th className="px-3 py-2">{t('simReconcile.colWorkspace', { defaultValue: 'Workspace' })}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => {
                const k = rowKey(r);
                const best = r.candidates[0];
                const value = choice[k] ?? (r.mapping ? String(r.mapping.tenantId) : '');
                const pooled = r.lineTenants.find((x) => x.tenantId === null)?.count ?? 0;
                return (
                  <tr key={k} className="border-t border-border align-top">
                    <td className="px-3 py-2 font-mono">
                      {r.clientCode}
                      <div className="text-[11px] text-text-muted">{r.accountName}</div>
                    </td>
                    <td className="px-3 py-2">{r.customerName ?? <span className="text-text-muted">—</span>}</td>
                    <td className="px-3 py-2 text-right">
                      {r.lineCount}
                      {pooled > 0 && (
                        <div className="text-[11px] text-text-muted">
                          {t('simReconcile.pooled', { defaultValue: '{{count}} in pool', count: pooled })}
                        </div>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      {best ? (
                        <>
                          <span className={best.strong ? 'font-medium text-text-primary' : 'text-text-secondary'}>
                            {best.tenantName}
                          </span>
                          <div className="text-[11px] text-text-muted">
                            {reason(best)}
                            {r.autoTenantId !== null &&
                              ` · ${t('simReconcile.autoNext', { defaultValue: 'applied automatically at the next sweep' })}`}
                          </div>
                        </>
                      ) : (
                        <span className="text-text-muted">—</span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      {r.mapping ? (
                        <>
                          {r.mapping.tenantName}
                          <div className="text-[11px] text-text-muted">
                            {r.mapping.decidedBy === null
                              ? t('simReconcile.decidedAuto', { defaultValue: 'automatic' })
                              : t('simReconcile.decidedManual', { defaultValue: 'by an operator' })}
                            {' · '}
                            <When iso={r.mapping.decidedAt} />
                          </div>
                        </>
                      ) : (
                        <>
                          <span className="text-text-muted">{t('simReconcile.unmapped', { defaultValue: 'Unmapped' })}</span>
                          {r.unmapped && (
                            <div className="text-[11px] text-status-pending">
                              {t('simReconcile.unmappedBy', {
                                date: new Date(r.unmapped.decidedAt).toLocaleDateString(i18n.language),
                                defaultValue: 'Mapping removed on {{date}} — no automatic suggestion for this client',
                              })}
                            </div>
                          )}
                        </>
                      )}
                    </td>
                    <td className="px-3 py-2 min-w-[180px]">
                      <select
                        className={selectClass}
                        value={value}
                        onChange={(e) => setChoice((c) => ({ ...c, [k]: e.target.value }))}
                      >
                        <option value="">{t('simReconcile.none', { defaultValue: '— not mapped —' })}</option>
                        {tenants.map((tn) => (
                          <option key={tn.id} value={String(tn.id)}>
                            {tn.name}
                          </option>
                        ))}
                      </select>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
