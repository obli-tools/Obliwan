import { useMemo, useRef, useState, type ChangeEvent, type ClipboardEvent } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import {
  AlertTriangle, ChevronLeft, ChevronRight, DownloadCloud, Eraser, FileUp, KeyRound, Plus, Trash2, X,
} from 'lucide-react';
import { Button } from '@/components/common/Button';
import { cn } from '@/utils/cn';
import { asSitesResult } from '@/api/tenantSetup.api';
import type { SiteImportRow } from '@/api/sites.api';
import { cellText } from './fieldModel';
import { loadSitesFile } from './fileLoaders';
import { emptyRow, gridProblems, isKnownColumn, pasteBlock, type GridProblem } from './gridModel';
import { SITE_FIXED_COLUMNS, isBlankRow, useQuickSetupStore, type GridRow } from './quickSetupStore';
import { CARD } from './ui';
import { newId } from './policyModel';

/**
 * Designer step 4 — the sites, as a grid that reads like the site-import CSV
 * it is sent as: `code, name, country, timezone, address, contact`, then one
 * `var:<key>` column per site-level variable.
 *
 * Pasting a block copied from Excel (tab-separated) into any cell fills the
 * grid from that cell, adding rows; a first pasted line made only of column
 * names maps the columns instead. The server's site import judges the grid on
 * "Check" exactly as it judges a file — this grid is its editor, not a second
 * judge — and its per-row verdict is drawn back on the row it came from.
 *
 * A secret site variable is a password cell. An empty one keeps what is
 * stored; an export leaves every secret column empty.
 */

const PAGE = 100;

type ImportRowExtra = SiteImportRow & { codeRestored?: { from: string; to: string; note: string } };

export function SitesGrid({ stale }: { stale: boolean }) {
  const { t } = useTranslation();
  const context = useQuickSetupStore((s) => s.context);
  const sites = useQuickSetupStore((s) => s.sites);
  const allocate = useQuickSetupStore((s) => s.allocate);
  const lastCheck = useQuickSetupStore((s) => s.lastCheck);
  const setSites = useQuickSetupStore((s) => s.setSites);
  const setAllocate = useQuickSetupStore((s) => s.setAllocate);
  const markEdited = useQuickSetupStore((s) => s.markEdited);
  const [page, setPage] = useState(0);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const fileRef = useRef<HTMLInputElement>(null);

  const maxRows = context?.limits.maxSiteRows ?? 2000;
  const declarations = useMemo(() => context?.declarations ?? [], [context]);
  const siteDecls = useMemo(() => declarations.filter((d) => d.level === 'site'), [declarations]);
  const declByKey = useMemo(() => new Map(declarations.map((d) => [d.key, d])), [declarations]);
  const problems = useMemo(() => gridProblems(sites), [sites]);
  const pages = Math.max(1, Math.ceil(sites.rows.length / PAGE));
  const current = Math.min(page, pages - 1);
  const shown = sites.rows.slice(current * PAGE, current * PAGE + PAGE);

  // The server's verdict per row, found through the line each row was sent on.
  const verdicts = useMemo(() => {
    const out = new Map<string, ImportRowExtra>();
    const result = asSitesResult(lastCheck?.report.sites?.result);
    if (!result || !lastCheck) return out;
    const byLine = new Map(result.rows.map((r) => [r.line, r as ImportRowExtra]));
    for (const [rowId, line] of Object.entries(lastCheck.siteLines)) {
      const v = byLine.get(line);
      if (v) out.set(rowId, v);
    }
    return out;
  }, [lastCheck]);

  const commit = (next: typeof sites) => {
    setSites(next);
    markEdited('sites');
  };

  const setCell = (rowId: string, col: number, value: string) => {
    commit({
      ...sites,
      rows: sites.rows.map((r) => {
        if (r.id !== rowId) return r;
        const cells = [...r.cells];
        while (cells.length < sites.header.length) cells.push('');
        cells[col] = value;
        return { ...r, cells };
      }),
    });
  };

  const onPaste = (e: ClipboardEvent<HTMLInputElement>, rowIndex: number, col: number) => {
    const text = e.clipboardData.getData('text/plain');
    if (!/[\t\n]/.test(text)) return;
    e.preventDefault();
    const r = pasteBlock(sites, rowIndex, col, text, maxRows);
    if ('error' in r) {
      toast.error(t('quickSetup.csvProblem.unterminated_quote', { defaultValue: 'A quoted cell is never closed.' }));
      return;
    }
    commit(r.sites);
    if (r.droppedCells > 0 || r.droppedRows > 0) {
      toast(t('quickSetup.grid.pasteDropped', {
        defaultValue: 'Pasted. {{cells}} cell(s) beyond the last column and {{rows}} row(s) beyond the limit were dropped.',
        cells: r.droppedCells, rows: r.droppedRows,
      }));
    }
  };

  const hasColumn = (name: string) => sites.header.includes(name);
  const toggleVar = (key: string) => {
    const name = `var:${key}`;
    const at = sites.header.indexOf(name);
    if (at < 0) {
      commit({ header: [...sites.header, name], rows: sites.rows.map((r) => ({ ...r, cells: [...r.cells, ''] })) });
      return;
    }
    removeColumn(at);
  };
  const removeColumn = (at: number) => {
    const name = sites.header[at];
    if ((SITE_FIXED_COLUMNS as readonly string[]).includes(name) && (name === 'code' || name === 'name')) return;
    const filled = sites.rows.some((r) => (r.cells[at] ?? '').trim() !== '');
    if (filled && !window.confirm(t('quickSetup.grid.confirmRemoveColumn', {
      defaultValue: 'Column "{{name}}" holds values. Remove it and its values?', name,
    }))) return;
    commit({
      header: sites.header.filter((_, i) => i !== at),
      rows: sites.rows.map((r) => ({ ...r, cells: r.cells.filter((_, i) => i !== at) })),
    });
  };

  const addRow = () => {
    if (sites.rows.length >= maxRows) return;
    commit({ ...sites, rows: [...sites.rows, emptyRow(sites.header.length)] });
    setPage(Math.floor(sites.rows.length / PAGE));
  };

  const deletePicked = () => {
    commit({ ...sites, rows: sites.rows.filter((r) => !picked.has(r.id)) });
    setPicked(new Set());
  };

  const clearAll = () => {
    if (sites.rows.length > 0 && !window.confirm(t('quickSetup.grid.confirmClear', { defaultValue: 'Remove every row of the grid?' }))) return;
    commit({ ...sites, rows: [] });
    setPicked(new Set());
    setPage(0);
  };

  /** The workspace's existing sites, appended — those whose code is already
   *  in the grid are left as they are. Secret values are never in the browser,
   *  so a secret column stays empty, which keeps what is stored. */
  const loadExisting = () => {
    if (!context) return;
    const header = [...sites.header];
    const keysWithValues = new Set<string>();
    for (const s of context.sites) {
      for (const [k, v] of Object.entries(s.values)) {
        if (!v.isSecret && !v.redacted && declByKey.get(k)?.level === 'site') keysWithValues.add(k);
      }
    }
    for (const k of [...keysWithValues].sort()) if (!header.includes(`var:${k}`)) header.push(`var:${k}`);
    const ci = header.indexOf('code');
    const existing = new Set(sites.rows.map((r) => (r.cells[ci] ?? '').trim()));
    const rows: GridRow[] = sites.rows.map((r) => ({ ...r, cells: header.map((_, i) => r.cells[i] ?? '') }));
    let added = 0;
    for (const s of context.sites) {
      if (existing.has(s.code) || rows.length >= maxRows) continue;
      const fixed: Record<string, string> = {
        code: s.code, name: s.name, country: s.country ?? '', timezone: s.timezone ?? '',
        address: s.address ?? '', contact: s.contact ?? '',
      };
      const cells = header.map((h) => {
        if (h.startsWith('var:')) {
          const v = s.values[h.slice(4)];
          return v && !v.isSecret && !v.redacted ? cellText(v.value) : '';
        }
        return fixed[h] ?? '';
      });
      rows.push({ id: newId('s'), cells });
      added += 1;
    }
    commit({ header, rows });
    toast.success(t('quickSetup.grid.loadedExisting', { defaultValue: '{{count}} existing site(s) added to the grid.', count: added }));
  };

  const onFile = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    if (sites.rows.length > 0 && !window.confirm(t('quickSetup.grid.confirmReplace', {
      defaultValue: 'Replace the grid with this file?',
    }))) return;
    const r = await loadSitesFile(t, file);
    if (!r.ok) toast.error(r.message);
    else if (r.note) toast(r.note);
    setPage(0);
  };

  const problemText = (p: GridProblem) => {
    switch (p) {
      case 'codeMissing': return t('quickSetup.grid.problem.codeMissing', { defaultValue: 'The code is missing.' });
      case 'nameMissing': return t('quickSetup.grid.problem.nameMissing', { defaultValue: 'The name is missing.' });
      case 'excelCode':
        return t('quickSetup.grid.excelCode', {
          defaultValue: 'This code looks rewritten by Excel (format the column as Text).',
        });
      case 'duplicateCode':
      default:
        return t('quickSetup.grid.problem.duplicateCode', { defaultValue: 'The same code appears on another row.' });
    }
  };

  const verdictCell = (row: GridRow) => {
    const v = verdicts.get(row.id);
    if (!v) return <span className="text-text-muted">—</span>;
    const rejected = v.errors.length > 0;
    const label = rejected
      ? t('quickSetup.grid.status.rejected', { defaultValue: 'rejected' })
      : t(`quickSetup.grid.status.${v.action}`, { defaultValue: v.action });
    return (
      <div className={cn('max-w-[260px]', stale && 'opacity-50')} title={v.errors.join('\n') || undefined}>
        <span
          className={cn(
            'rounded px-1.5 py-0.5 text-[10px] font-medium uppercase',
            rejected ? 'bg-status-down/15 text-status-down'
              : v.action === 'create' ? 'bg-emerald-500/15 text-emerald-400'
                : v.action === 'update' ? 'bg-accent/15 text-accent' : 'bg-bg-tertiary text-text-muted',
          )}
        >
          {label}
        </span>
        {v.chr && <span className="ml-1 text-[10px] text-text-muted">CHR: {v.chr.kind}</span>}
        {v.codeRestored && (
          <div className="mt-0.5 text-[11px] text-amber-400">
            {t('quickSetup.grid.codeRestored', {
              defaultValue: '{{from}} → {{to}} (leading zeros restored)', from: v.codeRestored.from, to: v.codeRestored.to,
            })}
          </div>
        )}
        {v.errors.slice(0, 2).map((e, i) => (
          <div key={i} className="mt-0.5 truncate text-[11px] text-status-down">{e}</div>
        ))}
        {v.errors.length > 2 && <div className="text-[11px] text-text-muted">+{v.errors.length - 2}</div>}
      </div>
    );
  };

  const headerIssue = (name: string): string | null => {
    if (!isKnownColumn(name)) {
      return t('quickSetup.grid.unknownColumn', {
        defaultValue: 'Not a column of the site import (code, name, country, timezone, address, contact or var:<key>).',
      });
    }
    if (name.startsWith('var:')) {
      const d = declByKey.get(name.slice(4));
      if (!d) return t('quickSetup.grid.undeclaredVar', { defaultValue: 'No reference template declares this variable.' });
      if (d.level !== 'site') {
        return t('quickSetup.grid.notSiteVar', {
          defaultValue: 'Declared at level "{{level}}", not "site": the import refuses it per site.', level: d.level ?? 'device',
        });
      }
    }
    return null;
  };

  return (
    <section className={CARD} id="qs-step-sites">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <Button type="button" size="sm" variant="secondary" onClick={addRow} disabled={sites.rows.length >= maxRows}>
          <Plus size={13} className="mr-1" />{t('quickSetup.grid.addRow', { defaultValue: 'Row' })}
        </Button>
        <Button type="button" size="sm" variant="secondary" onClick={deletePicked} disabled={picked.size === 0}>
          <Trash2 size={13} className="mr-1" />
          {t('quickSetup.grid.deleteRows', { defaultValue: 'Delete selected ({{count}})', count: picked.size })}
        </Button>
        <Button type="button" size="sm" variant="secondary" onClick={loadExisting} disabled={!context || context.sites.length === 0}>
          <DownloadCloud size={13} className="mr-1" />{t('quickSetup.grid.loadExisting', { defaultValue: 'Load the existing sites' })}
        </Button>
        <input ref={fileRef} type="file" accept=".csv,text/csv,text/plain" className="hidden" onChange={(e) => void onFile(e)} />
        <Button type="button" size="sm" variant="secondary" onClick={() => fileRef.current?.click()}>
          <FileUp size={13} className="mr-1" />{t('quickSetup.grid.importCsv', { defaultValue: 'Import a CSV' })}
        </Button>
        <Button type="button" size="sm" variant="ghost" onClick={clearAll} disabled={sites.rows.length === 0}>
          <Eraser size={13} className="mr-1" />{t('quickSetup.grid.clear', { defaultValue: 'Clear' })}
        </Button>
        <span className="ml-auto text-xs text-text-muted">
          {t('quickSetup.grid.count', { defaultValue: '{{n}} / {{max}} rows', n: sites.rows.length, max: maxRows })}
        </span>
      </div>

      {siteDecls.length > 0 && (
        <div className="mb-2 flex flex-wrap items-center gap-1.5 text-xs">
          <span className="text-text-muted">{t('quickSetup.grid.columns', { defaultValue: 'Site variables:' })}</span>
          {siteDecls.map((d) => (
            <button
              key={d.key}
              type="button"
              onClick={() => toggleVar(d.key)}
              title={d.label ?? undefined}
              className={cn(
                'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 font-mono',
                hasColumn(`var:${d.key}`) ? 'border-accent bg-accent/15 text-accent' : 'border-border text-text-muted hover:text-text-primary',
                d.required && !hasColumn(`var:${d.key}`) && 'border-status-down/60',
              )}
            >
              {d.secret && <KeyRound size={10} />}
              {d.key}
              {d.required && <span className="text-status-down">*</span>}
            </button>
          ))}
        </div>
      )}
      <p className="mb-2 text-xs text-text-muted">
        {t('quickSetup.grid.pasteHint', { defaultValue: 'Paste rows from Excel (tab-separated) into any cell.' })}
      </p>

      <div className="overflow-x-auto rounded-lg border border-border">
        <table className="w-full text-left text-xs">
          <thead className="bg-bg-tertiary/50 text-text-muted">
            <tr>
              <th className="w-8 px-1 py-1.5">
                <input
                  type="checkbox"
                  checked={shown.length > 0 && shown.every((r) => picked.has(r.id))}
                  onChange={(e) => {
                    const next = new Set(picked);
                    for (const r of shown) {
                      if (e.target.checked) next.add(r.id);
                      else next.delete(r.id);
                    }
                    setPicked(next);
                  }}
                />
              </th>
              <th className="w-10 px-1 py-1.5 font-medium">#</th>
              {sites.header.map((h, i) => {
                const issue = headerIssue(h);
                const secret = h.startsWith('var:') && declByKey.get(h.slice(4))?.secret === true;
                return (
                  <th key={`${h}-${i}`} className="min-w-[120px] px-1 py-1.5 font-medium">
                    <span className={cn('inline-flex items-center gap-1 font-mono', issue && 'text-amber-400')} title={issue ?? undefined}>
                      {issue && <AlertTriangle size={11} />}
                      {secret && <KeyRound size={11} />}
                      {h}
                      {h !== 'code' && h !== 'name' && (
                        <button
                          type="button"
                          onClick={() => removeColumn(i)}
                          className="rounded text-text-muted hover:text-status-down"
                          aria-label={t('quickSetup.grid.removeColumn', { defaultValue: 'Remove the column' })}
                        >
                          <X size={11} />
                        </button>
                      )}
                    </span>
                  </th>
                );
              })}
              <th className="min-w-[160px] px-1 py-1.5 font-medium">{t('quickSetup.grid.statusCol', { defaultValue: 'Check' })}</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((r, k) => {
              const index = current * PAGE + k;
              const rowProblems = problems.get(r.id) ?? [];
              const blank = isBlankRow(r);
              return (
                <tr key={r.id} className={cn('border-t border-border align-top', blank && 'opacity-60')}>
                  <td className="px-1 py-1">
                    <input
                      type="checkbox"
                      checked={picked.has(r.id)}
                      onChange={(e) => {
                        const next = new Set(picked);
                        if (e.target.checked) next.add(r.id);
                        else next.delete(r.id);
                        setPicked(next);
                      }}
                    />
                  </td>
                  <td className="px-1 py-1 font-mono text-text-muted" title={rowProblems.map(problemText).join('\n') || undefined}>
                    {index + 1}
                    {rowProblems.length > 0 && <AlertTriangle size={11} className="ml-0.5 inline text-amber-400" />}
                  </td>
                  {sites.header.map((h, col) => {
                    const secret = h.startsWith('var:') && declByKey.get(h.slice(4))?.secret === true;
                    const bad =
                      (h === 'code' && rowProblems.some((p) => p === 'codeMissing' || p === 'excelCode' || p === 'duplicateCode'))
                      || (h === 'name' && rowProblems.includes('nameMissing'));
                    return (
                      <td key={`${h}-${col}`} className="px-0.5 py-0.5">
                        <input
                          type={secret ? 'password' : 'text'}
                          autoComplete={secret ? 'new-password' : 'off'}
                          value={r.cells[col] ?? ''}
                          onChange={(e) => setCell(r.id, col, e.target.value)}
                          onPaste={(e) => onPaste(e, index, col)}
                          placeholder={secret ? t('quickSetup.grid.secretKeep', { defaultValue: 'empty = keep' }) : undefined}
                          className={cn(
                            'w-full rounded border bg-bg-primary px-1.5 py-1 text-xs text-text-primary focus:outline-none focus:ring-1 focus:ring-accent',
                            h === 'code' && 'font-mono',
                            bad ? 'border-status-down/60' : 'border-transparent hover:border-border',
                          )}
                        />
                      </td>
                    );
                  })}
                  <td className="px-1 py-1">{verdictCell(r)}</td>
                </tr>
              );
            })}
            {sites.rows.length === 0 && (
              <tr>
                <td colSpan={sites.header.length + 3} className="px-3 py-6 text-center text-text-muted">
                  {t('quickSetup.grid.empty', {
                    defaultValue: 'No site yet: add a row, paste from Excel, import a CSV or load the existing sites.',
                  })}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {pages > 1 && (
        <div className="mt-2 flex items-center justify-end gap-2 text-xs text-text-muted">
          <button type="button" disabled={current === 0} onClick={() => setPage(current - 1)} className="rounded p-1 hover:text-text-primary disabled:opacity-40">
            <ChevronLeft size={14} />
          </button>
          {t('quickSetup.grid.page', { defaultValue: 'Page {{page}} / {{pages}}', page: current + 1, pages })}
          <button type="button" disabled={current >= pages - 1} onClick={() => setPage(current + 1)} className="rounded p-1 hover:text-text-primary disabled:opacity-40">
            <ChevronRight size={14} />
          </button>
        </div>
      )}

      <label className="mt-3 flex items-start gap-2 text-sm text-text-primary">
        <input type="checkbox" className="mt-0.5" checked={allocate} onChange={(e) => { setAllocate(e.target.checked); markEdited('sites'); }} />
        <span>
          {t('quickSetup.options.allocate', { defaultValue: 'Allocate addresses on import' })}
          <span className="block text-xs text-text-muted">
            {t('quickSetup.options.allocateHint', { defaultValue: 'Uses the rule saved in this same run.' })}
          </span>
        </span>
      </label>
    </section>
  );
}
