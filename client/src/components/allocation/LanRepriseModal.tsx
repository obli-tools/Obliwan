import { useState, type ChangeEvent } from 'react';
import { FileUp, Network, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import type {
  LanRepriseRefusalView,
  LanRepriseResult,
  LanRepriseRowResult,
  LanRepriseVerdict,
  LanRepriseWarning,
} from '@obliwan/shared';
import { Button } from '@/components/common/Button';
import { cn } from '@/utils/cn';
import { lanRepriseApi } from './lanReprise.api';

interface Props {
  tenantId: number;
  /** How the screen names the tenant, shown so the operator sees whose sites
   *  the table is matched against. */
  tenantLabel?: string;
  onClose: () => void;
  /** Called after an apply that wrote at least one row. */
  onApplied: () => void;
  /** A table prepared by another screen (the infrastructure analysis's LAN
   *  rows), put in the text area to be checked like a pasted one. */
  initialCsv?: string;
}

/** What the server answered on a refused request (the file as a whole). */
function errorLines(err: unknown): string[] {
  const data = (err as { response?: { data?: { error?: unknown; details?: unknown } } }).response?.data;
  const details = data?.details as Record<string, unknown> | undefined;
  const csv = details && Array.isArray(details.csv) ? details.csv.filter((e): e is string => typeof e === 'string') : [];
  if (csv.length > 0) return csv;
  if (typeof data?.error === 'string') return [data.error];
  return [err instanceof Error ? err.message : String(err)];
}

const VERDICT_STYLE: Record<LanRepriseVerdict, string> = {
  record: 'bg-emerald-500/15 text-emerald-400',
  replace: 'bg-amber-500/15 text-amber-400',
  unchanged: 'bg-bg-tertiary text-text-muted',
  refused: 'bg-red-500/15 text-red-400',
};

/**
 * "Record existing LANs" — the deployed LAN of each existing (adopted) site,
 * from the operator's table, onto its allocation. Paste or choose the CSV,
 * check it (a dry run: nothing is written), read the verdict of every row,
 * then apply. Apply is offered only for the exact text AND overwrite choice
 * that were checked, so what is written is always what was shown; the server
 * judges every row again under its lock and answers what it actually did.
 *
 * Nothing here talks to a router: the server records the LAN in ObliWAN only.
 */
export function LanRepriseModal({ tenantId, tenantLabel, onClose, onApplied, initialCsv }: Props) {
  const { t } = useTranslation();
  const [csv, setCsv] = useState(initialCsv ?? '');
  const [overwrite, setOverwrite] = useState(false);
  const [busy, setBusy] = useState<'check' | 'apply' | null>(null);
  const [result, setResult] = useState<LanRepriseResult | null>(null);
  const [checked, setChecked] = useState<{ csv: string; overwrite: boolean } | null>(null);
  const [fileErrors, setFileErrors] = useState<string[]>([]);
  const [legacyEncoding, setLegacyEncoding] = useState(false);

  const stale = checked !== null && (checked.csv !== csv || checked.overwrite !== overwrite);
  const toWrite = result ? result.counts.record + result.counts.replace : 0;
  const canApply = result !== null && result.dryRun && !stale && toWrite > 0;

  const onFile = (e: ChangeEvent<HTMLInputElement>): void => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    // A strict UTF-8 decode, then Windows-1252 — what Excel writes for a CSV —
    // as the site import does: file.text() would silently mangle the latter.
    file
      .arrayBuffer()
      .then((buf) => {
        let text: string;
        let legacy = false;
        try {
          text = new TextDecoder('utf-8', { fatal: true }).decode(buf);
        } catch {
          text = new TextDecoder('windows-1252').decode(buf);
          legacy = true;
        }
        setCsv(text);
        setLegacyEncoding(legacy);
        setResult(null);
        setFileErrors([]);
      })
      .catch((err: unknown) => setFileErrors(errorLines(err)));
  };

  const run = async (dryRun: boolean): Promise<void> => {
    setFileErrors([]);
    setBusy(dryRun ? 'check' : 'apply');
    try {
      const res = await lanRepriseApi.run(tenantId, csv, { overwrite, dryRun });
      setResult(res);
      if (dryRun) {
        setChecked({ csv, overwrite });
      } else {
        setChecked(null);
        const written = res.counts.record + res.counts.replace;
        toast.success(
          t('allocation.lanReprise.appliedToast', { defaultValue: '{{count}} LAN(s) recorded', count: written }),
        );
        if (written > 0) onApplied();
      }
    } catch (err) {
      setResult(null);
      setFileErrors(errorLines(err));
    } finally {
      setBusy(null);
    }
  };

  const sourceText = (s: string | undefined): string =>
    t(`allocation.lanReprise.source.${s && s !== '' ? s : 'none'}`, { defaultValue: s || '—' });

  const refusalText = (r: LanRepriseRefusalView): string => {
    const p: Record<string, string> = { ...r.params };
    if (p.currentSource !== undefined) p.currentSource = sourceText(p.currentSource);
    if (p.purpose !== undefined) p.purpose = t(`allocation.lanReprise.purpose.${p.purpose}`, { defaultValue: p.purpose });
    // Another workspace's site is described by kind only (the server sends no code).
    const key = r.reason === 'lan_contains_tunnel_ip' && (p.site ?? '') === '' ? 'lan_contains_tunnel_ip_foreign' : r.reason;
    return t(`allocation.lanReprise.reason.${key}`, { defaultValue: r.reason, ...p });
  };

  const warningText = (w: LanRepriseWarning): string => {
    const p: Record<string, string> = { ...w.params };
    if (p.currentSource !== undefined) p.currentSource = sourceText(p.currentSource);
    return t(`allocation.lanReprise.warning.${w.code}`, { defaultValue: w.code, ...p });
  };

  const siteCell = (r: LanRepriseRowResult) => {
    if (!r.site) return <span className="font-mono">{r.code || '—'}</span>;
    return (
      <div>
        <span className="font-mono">{r.site.code}</span> <span className="text-text-muted">{r.site.name}</span>
        {r.codeRestored && (
          <div className="text-xs text-amber-400">
            {t('allocation.lanReprise.restored', {
              defaultValue: '“{{from}}” → {{to}} (leading zeros restored)',
              from: r.code,
              to: r.site.code,
            })}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4">
      <div className="my-8 w-full max-w-6xl rounded-xl border border-border bg-bg-secondary shadow-2xl">
        <div className="flex items-center gap-2 border-b border-border px-5 py-4">
          <Network size={18} className="text-accent" />
          <h2 className="flex-1 text-base font-semibold text-text-primary">
            {t('allocation.lanReprise.title', { defaultValue: 'Record the LAN of existing sites' })}
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="rounded p-1 text-text-muted hover:text-text-primary"
            aria-label={t('allocation.lanReprise.close', { defaultValue: 'Close' })}
          >
            <X size={16} />
          </button>
        </div>

        <div className="space-y-4 p-5">
          {tenantLabel && (
            <p className="text-sm text-text-primary">
              {t('allocation.lanReprise.tenant', { defaultValue: 'Sites of: {{tenant}}', tenant: tenantLabel })}
            </p>
          )}
          <p className="text-sm text-text-muted">
            {t('allocation.lanReprise.help', {
              defaultValue:
                'One row per site, with a header naming the columns code and lan (or lan_subnet), and optionally router_ip; other columns are ignored. Each site must already be allocated (adopted from the CHR or allocated). Its LAN is recorded on its allocation, so lan_subnet and the values derived from it (lan_router_ip…) resolve for it, and no later allocation hands out an address inside it. Nothing is written to any router.',
            })}
          </p>
          <p className="text-xs text-text-muted">
            {t('allocation.lanReprise.codeHint', {
              defaultValue:
                'A code a spreadsheet stripped of its leading zeros (2 for 00002) is matched by its site number when only one site has that number, and the check says so.',
            })}
          </p>

          <div className="flex flex-wrap items-center gap-2">
            <label className="inline-flex cursor-pointer items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-sm text-text-primary hover:bg-bg-tertiary">
              <FileUp size={14} />
              {t('allocation.lanReprise.chooseFile', { defaultValue: 'Choose a file' })}
              <input type="file" accept=".csv,text/csv,text/plain" className="hidden" onChange={onFile} />
            </label>
          </div>

          <textarea
            value={csv}
            onChange={(e) => { setCsv(e.target.value); setLegacyEncoding(false); }}
            rows={8}
            spellCheck={false}
            placeholder={t('allocation.lanReprise.pastePlaceholder', {
              defaultValue: '…or paste the CSV here, e.g.\ncode,lan,router_ip\n00002,10.20.30.0/27,10.20.30.1',
            })}
            className="w-full rounded-md border border-border bg-bg-primary p-2 font-mono text-xs text-text-primary"
          />
          {legacyEncoding && (
            <p className="text-xs text-text-muted">
              {t('allocation.lanReprise.legacyEncoding', {
                defaultValue: 'This file is not UTF-8: it was read as Windows-1252 (Excel).',
              })}
            </p>
          )}

          <label className="flex items-start gap-2 text-sm text-text-primary">
            <input type="checkbox" checked={overwrite} onChange={(e) => setOverwrite(e.target.checked)} className="mt-0.5" />
            <span>
              {t('allocation.lanReprise.overwrite', { defaultValue: 'Replace a different LAN already recorded' })}
              <span className="block text-xs text-text-muted">
                {t('allocation.lanReprise.overwriteHint', {
                  defaultValue:
                    'Without it, a site that already has another LAN (drawn by a rule, or recorded before) is refused. A router already prepared with the old LAN keeps it.',
                })}
              </span>
            </span>
          </label>

          <div className="flex flex-wrap items-center gap-2">
            <Button
              type="button"
              size="sm"
              variant="secondary"
              onClick={() => void run(true)}
              loading={busy === 'check'}
              disabled={busy !== null || csv.trim() === ''}
            >
              {t('allocation.lanReprise.check', { defaultValue: 'Check (nothing is written)' })}
            </Button>
            <Button type="button" size="sm" onClick={() => void run(false)} loading={busy === 'apply'} disabled={busy !== null || !canApply}>
              {t('allocation.lanReprise.apply', { defaultValue: 'Record {{count}} LAN(s)', count: toWrite })}
            </Button>
          </div>

          {fileErrors.length > 0 && (
            <div className="rounded-md border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-400">
              <p className="font-medium">{t('allocation.lanReprise.fileError', { defaultValue: 'The file cannot be read' })}</p>
              <ul className="mt-1 list-disc pl-5 text-xs">
                {fileErrors.map((e) => <li key={e}>{e}</li>)}
              </ul>
            </div>
          )}

          {stale && (
            <p className="text-xs text-amber-400">
              {t('allocation.lanReprise.stale', {
                defaultValue: 'The CSV or the replace option changed since the check — check again before recording.',
              })}
            </p>
          )}

          {result && (
            <div className="space-y-2">
              <p className="text-sm text-text-primary">
                {result.dryRun
                  ? t('allocation.lanReprise.summaryDry', {
                      defaultValue: 'Check: {{record}} to record, {{replace}} to replace, {{unchanged}} unchanged, {{refused}} refused',
                      ...result.counts,
                    })
                  : t('allocation.lanReprise.summaryApplied', {
                      defaultValue: 'Done: {{record}} recorded, {{replace}} replaced, {{unchanged}} unchanged, {{refused}} refused',
                      ...result.counts,
                    })}
              </p>
              {result.ignoredColumns.length > 0 && (
                <p className="text-xs text-text-muted">
                  {t('allocation.lanReprise.ignored', {
                    defaultValue: 'Columns not read: {{columns}}',
                    columns: result.ignoredColumns.join(', '),
                  })}
                </p>
              )}
              {result.policyProblem && (
                <p className="text-xs text-amber-400">
                  {t(`allocation.lanReprise.policyProblem.${result.policyProblem}`, { defaultValue: result.policyProblem })}
                </p>
              )}
              <div className="max-h-[50vh] overflow-auto rounded-md border border-border">
                <table className="w-full text-sm">
                  <thead className="sticky top-0 bg-bg-secondary">
                    <tr className="text-left text-xs text-text-muted">
                      <th className="px-2 py-1.5">{t('allocation.lanReprise.col.line', { defaultValue: 'Line' })}</th>
                      <th className="px-2 py-1.5">{t('allocation.lanReprise.col.site', { defaultValue: 'Site' })}</th>
                      <th className="px-2 py-1.5">{t('allocation.lanReprise.col.lan', { defaultValue: 'LAN' })}</th>
                      <th className="px-2 py-1.5">{t('allocation.lanReprise.col.router', { defaultValue: 'Router' })}</th>
                      <th className="px-2 py-1.5">{t('allocation.lanReprise.col.verdict', { defaultValue: 'Verdict' })}</th>
                      <th className="px-2 py-1.5">{t('allocation.lanReprise.col.values', { defaultValue: 'Computed values' })}</th>
                      <th className="px-2 py-1.5">{t('allocation.lanReprise.col.detail', { defaultValue: 'Detail' })}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.rows.map((r) => (
                      <tr key={r.line} className="border-t border-border align-top">
                        <td className="px-2 py-1.5 text-xs text-text-muted">{r.line}</td>
                        <td className="px-2 py-1.5">{siteCell(r)}</td>
                        <td className="px-2 py-1.5 font-mono text-xs">
                          {r.lanSubnet ?? (r.lan || '—')}
                          {r.current?.lanSubnet && r.verdict !== 'unchanged' && (
                            <div className="text-text-muted">
                              {t('allocation.lanReprise.currentLan', {
                                defaultValue: 'now: {{lan}}',
                                lan: r.current.lanSubnet,
                              })}
                            </div>
                          )}
                        </td>
                        <td className="px-2 py-1.5 font-mono text-xs">{r.routerIp ?? '—'}</td>
                        <td className="px-2 py-1.5">
                          <span className={cn('rounded px-1.5 py-0.5 text-xs', VERDICT_STYLE[r.verdict])}>
                            {t(`allocation.lanReprise.verdict.${r.verdict}`, { defaultValue: r.verdict })}
                          </span>
                        </td>
                        <td className="px-2 py-1.5 font-mono text-xs">
                          {r.values
                            ? Object.entries(r.values).map(([k, v]) => (
                                <div key={k}>
                                  <span className="text-text-muted">{k}</span> = {v}
                                </div>
                              ))
                            : '—'}
                        </td>
                        <td className="px-2 py-1.5 text-xs">
                          {r.refusal && <div className="text-red-400">{refusalText(r.refusal)}</div>}
                          {r.warnings.map((w, i) => (
                            <div key={i} className="text-amber-400">
                              {warningText(w)}
                            </div>
                          ))}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
