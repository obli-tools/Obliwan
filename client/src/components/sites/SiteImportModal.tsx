import { useEffect, useState, type ChangeEvent } from 'react';
import { AlertTriangle, CheckCircle2, Download, FileUp, Upload, X, XCircle } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import {
  sitesApi,
  type SiteImportResult,
  type SiteImportRow,
  type SiteImportTemplate,
} from '@/api/sites.api';
import { downloadText } from '@/api/query.api';
import { Button } from '@/components/common/Button';
import { cn } from '@/utils/cn';

interface Props {
  /** Platform admin: may ask for the addresses to be allocated. */
  canAllocate: boolean;
  onClose: () => void;
  /** Called after a real (non dry-run) import, so the page reloads its list. */
  onImported: () => void;
}

/** app.ts's `express.json({ limit: '1mb' })`: the largest body the import can send. */
const IMPORT_MAX_BODY_BYTES = 1024 * 1024;

/**
 * Fields the server's import result carries (siteImport.service.ts) that the
 * types in `@/api/sites.api` do not declare yet. They belong there; until they
 * move, this is their only client-side spelling.
 */
type ImportRow = SiteImportRow & {
  /** The zeros Excel stripped, restored under the tenant's 'digits:N' code
   *  format: `code` is what is written, `from` the cell as read. */
  codeRestored?: { from: string; to: string; note: string };
  allocation?: SiteImportRow['allocation'] & {
    /** The allocator's warnings (an adoption from the CHR, a formula address
     *  that differs from the deployed one…), server text, verbatim. */
    warnings?: string[];
  };
};
type ImportResult = Omit<SiteImportResult, 'rows' | 'summary'> & {
  rows: ImportRow[];
  summary: SiteImportResult['summary'] & { codesRestored?: number };
};

/** What the server answered on a refused file: `error` and `errors[]`. */
function errorLines(err: unknown): string[] {
  const data = (err as { response?: { data?: { error?: string; errors?: unknown } } }).response?.data;
  if (Array.isArray(data?.errors) && data.errors.every((e) => typeof e === 'string')) {
    return data.errors as string[];
  }
  if (typeof data?.error === 'string') return [data.error];
  return [err instanceof Error ? err.message : String(err)];
}

/** "3 hours ago", in the interface's language, from an age in seconds. */
function ageText(seconds: number, lang: string): string {
  const rtf = new Intl.RelativeTimeFormat(lang, { numeric: 'auto' });
  if (seconds < 3600) return rtf.format(-Math.max(1, Math.round(seconds / 60)), 'minute');
  if (seconds < 172_800) return rtf.format(-Math.round(seconds / 3600), 'hour');
  return rtf.format(-Math.round(seconds / 86_400), 'day');
}

/**
 * Bulk site import: paste or choose a CSV, check it (dry-run, nothing is
 * written), read the per-row verdict, then import. "Import" is only offered
 * for the exact text that was checked — editing the text asks for a new check,
 * so what is written is always what was shown.
 *
 * For a caller allowed to see CHR matching (platform admin, RECONCILE_READ),
 * the check also says what each row would be to the concentrator — "takes
 * over account X", "new", "suspect: looks like X" — against the CHR's LAST
 * recorded read, whose age it shows (the server dials nothing for it). It is
 * a warning column, never a refusal: a suspect row is imported like any
 * other. Anybody else gets no CHR column at all (the server sends none).
 */
export function SiteImportModal({ canAllocate, onClose, onImported }: Props) {
  const { t, i18n } = useTranslation();
  const [csv, setCsv] = useState('');
  const [allocate, setAllocate] = useState(false);
  const [busy, setBusy] = useState<'check' | 'import' | null>(null);
  const [result, setResult] = useState<ImportResult | null>(null);
  const [checkedText, setCheckedText] = useState<string | null>(null);
  const [fileErrors, setFileErrors] = useState<string[]>([]);
  const [template, setTemplate] = useState<SiteImportTemplate | null>(null);
  /** The chosen file failed a strict UTF-8 decode and was read as Windows-1252. */
  const [legacyEncoding, setLegacyEncoding] = useState(false);

  useEffect(() => {
    let alive = true;
    sitesApi
      .importTemplate()
      .then((tpl) => { if (alive) setTemplate(tpl); })
      .catch(() => { /* the template button then builds the fixed columns only */ });
    return () => { alive = false; };
  }, []);

  const stale = checkedText !== null && checkedText !== csv;
  const canImport =
    result !== null &&
    result.dryRun &&
    !stale &&
    result.rows.some((r) => r.errors.length === 0 && (r.action !== 'skip' || allocate));

  const downloadTemplate = (): void => {
    const columns = template?.columns ?? ['code', 'name', 'country', 'timezone', 'address', 'contact', 'uplink'];
    // ';' and a BOM: what a French spreadsheet opens without an import wizard.
    downloadText('sites-import.csv', 'text/csv', `﻿${columns.join(';')}\r\n`);
  };

  const onFile = (e: ChangeEvent<HTMLInputElement>): void => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    // Not file.text(): that decodes as UTF-8 and silently turns every accented
    // byte of a Windows-1252 file (Excel's "CSV (séparateur : point-virgule)")
    // into U+FFFD, which an import would then write over a correct site name.
    // A strict UTF-8 decode throws on such a file, and it is read as
    // Windows-1252 instead — the only other encoding Excel writes for a CSV.
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
    // app.ts parses JSON bodies up to 1 MB and answers a bare 500 beyond it,
    // so a file that cannot fit is refused here, with a reason.
    if (new Blob([JSON.stringify({ csv, allocate })]).size > IMPORT_MAX_BODY_BYTES) {
      setResult(null);
      setFileErrors([
        t('sites.import.tooLarge', {
          defaultValue: 'The file is too large to import in one go (1 MB at most). Split it into several files.',
        }),
      ]);
      return;
    }
    setBusy(dryRun ? 'check' : 'import');
    try {
      const res = await sitesApi.importCsv(csv, { dryRun, allocate: canAllocate && allocate });
      setResult(res);
      if (dryRun) {
        setCheckedText(csv);
      } else {
        setCheckedText(null);
        toast.success(t('sites.import.done', { defaultValue: 'Import finished' }));
        onImported();
      }
    } catch (err) {
      setResult(null);
      setFileErrors(errorLines(err));
      if (!dryRun) toast.error(t('sites.import.failed', { defaultValue: 'Import failed' }));
    } finally {
      setBusy(null);
    }
  };

  const actionLabel = (r: ImportRow): string =>
    r.action === 'create'
      ? t('sites.import.action.create', { defaultValue: 'Create' })
      : r.action === 'update'
        ? t('sites.import.action.update', { defaultValue: 'Update' })
        : t('sites.import.action.skip', { defaultValue: 'Unchanged' });

  const allocationLine = (r: ImportRow): string | null => {
    const a = r.allocation;
    if (!a) return null;
    if (a.status === 'failed') {
      return t('sites.import.alloc.failed', {
        defaultValue: 'Allocation failed: {{message}}',
        message: a.message ?? a.reason ?? '',
      });
    }
    const values = { login: a.pppUsername ?? '', ip: a.tunnelIp ?? '' };
    return a.status === 'allocated'
      ? t('sites.import.alloc.allocated', { defaultValue: 'Allocated: {{login}} · {{ip}}', ...values })
      : t('sites.import.alloc.existing', { defaultValue: 'Already allocated: {{login}} · {{ip}}', ...values });
  };

  const variables = template?.variables ?? [];

  // ── The CHR column (dry run, callers allowed to see CHR matching) ─────────
  // Same wording keys as the reconciliation screen, so a reason reads the
  // same in both places.
  const reasonText = (r: string): string =>
    t(`allocation.reconcile.reason.${r}`, {
      defaultValue:
        ({
          country: 'country',
          prefix: 'prefix',
          zeros: 'leading zeros',
          separator: 'separator',
          name: 'name',
          template: 'fixed part differs',
          device: 'router of the site',
        } as Record<string, string>)[r] ?? r,
    });
  const blockerText = (b: string): string =>
    t(`allocation.reconcile.blocker.${b}`, {
      defaultValue:
        ({
          ambiguous: 'several spellings on the CHR',
          noAddress: 'no fixed remote-address',
          sessionOnly: 'no /ppp/secret entry',
          otherTenant: 'login held by another tenant',
          sharedLogin: 'another site has the same login',
          loginTaken: 'login held elsewhere',
          addressTaken: 'address held elsewhere',
          addressInLan: "address inside a site's LAN",
          foreignPool: "address in another tenant's plan",
          profileInvalid: 'PPP profile an allocation cannot store',
          otherConcentrator: "on another CHR than the policy's",
        } as Record<string, string>)[b] ?? b,
    });
  const chrSummary = result?.dryRun ? result.chr : undefined;
  const showChrColumn = chrSummary?.status === 'compared';
  const online = (up: boolean) =>
    up ? (
      <span className="ml-1 rounded bg-emerald-500/15 px-1 text-emerald-400">
        {t('sites.import.chr.online', { defaultValue: 'online' })}
      </span>
    ) : null;
  const chrCell = (r: ImportRow) => {
    const v = r.chr;
    if (!v) return <span className="text-text-muted">—</span>;
    switch (v.kind) {
      case 'takesOver':
        return (
          <div>
            <span className={v.blocked ? 'text-amber-400' : 'text-emerald-400'}>
              {t('sites.import.chr.takesOver', { defaultValue: 'takes over CHR account {{login}}', login: v.account?.name ?? v.login ?? '' })}
            </span>
            {online(v.account?.online ?? false)}
            {v.blocked && (
              <div className="font-semibold text-amber-400">
                {t('sites.import.chr.blocked', { defaultValue: 'its allocation would NOT take this account over' })}
                {v.blockers.length > 0 && <span className="font-normal"> ({v.blockers.map(blockerText).join(', ')})</span>}
              </div>
            )}
          </div>
        );
      case 'allocated':
        return (
          <span className="text-text-muted">
            {t('sites.import.chr.allocated', { defaultValue: 'already allocated ({{login}})', login: v.login ?? '—' })}
          </span>
        );
      case 'new':
        return (
          <span className="text-text-primary">
            {t('sites.import.chr.new', { defaultValue: 'new site (no CHR account)' })}
          </span>
        );
      case 'noLogin':
        return (
          <span className="text-red-400" title={v.loginError ?? undefined}>
            {t('sites.import.chr.noLogin', { defaultValue: 'login cannot be computed' })}
          </span>
        );
      case 'suspect':
        return (
          <div className="text-amber-400">
            <span className="inline-flex items-center gap-1 font-semibold">
              <AlertTriangle size={12} />
              {t('sites.import.chr.suspect', { defaultValue: 'suspect' })}
            </span>
            {v.nearMatches.map((n) => (
              <div key={n.name}>
                {t('sites.import.chr.looksLike', {
                  defaultValue: 'looks like {{login}} ({{reasons}})',
                  login: n.name,
                  reasons: n.reasons.map(reasonText).join(', '),
                })}
                {online(n.online)}
              </div>
            ))}
            {v.withheld > 0 && (
              <div className="text-text-muted">
                {t('sites.import.chr.withheld', {
                  defaultValue: '{{count}} more resembling account(s): a platform administrator must check them',
                  count: v.withheld,
                })}
              </div>
            )}
          </div>
        );
      default:
        return null;
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4">
      <div className="my-8 w-full max-w-5xl rounded-xl border border-border bg-bg-secondary shadow-2xl">
        <div className="flex items-center gap-2 border-b border-border px-5 py-4">
          <Upload size={18} className="text-accent" />
          <h2 className="flex-1 text-base font-semibold text-text-primary">
            {t('sites.import.title', { defaultValue: 'Import sites from a CSV' })}
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="rounded p-1 text-text-muted hover:text-text-primary"
            aria-label={t('sites.import.close', { defaultValue: 'Close' })}
          >
            <X size={16} />
          </button>
        </div>

        <div className="space-y-4 p-5">
          <p className="text-sm text-text-muted">
            {t('sites.import.help', {
              defaultValue:
                'One row per site. Columns: code and name (required), country (ISO, e.g. FR), timezone (IANA, e.g. Europe/Paris), address, contact, and var:<key> for each site variable. An existing code is updated, never duplicated; an empty cell changes nothing.',
            })}
          </p>
          <p className="text-xs text-text-muted">
            {variables.length > 0
              ? t('sites.import.variables', {
                  defaultValue: 'Site variables available: {{keys}}',
                  keys: variables
                    .map((v) =>
                      v.secret
                        ? `${v.key} (${t('sites.import.secretTag', { defaultValue: 'secret' })})`
                        : v.key,
                    )
                    .join(', '),
                })
              : t('sites.import.noVariables', {
                  defaultValue: 'No site variable is declared by a published template yet.',
                })}
            {variables.some((v) => v.secret) && (
              <> {t('sites.import.secretNoteReveal', {
                defaultValue: 'Secret values are stored encrypted in the vault and never shown again — except '
                  + 'to an account allowed to reveal secrets, and every reveal is recorded in the audit log.',
              })}</>
            )}
          </p>
          <p className="text-xs text-text-muted">
            {t('sites.import.uplinkHint', {
              defaultValue:
                'Optional column uplink — the site’s access link: auto (not declared, ObliWAN infers it), fixe (fixed line + 4G backup) or 4g (4G only); fixed and cellular_only are accepted too. An empty cell changes nothing; auto clears a declaration.',
            })}
          </p>
          <p className="text-xs text-text-muted">{t('openingHours.importHint')}</p>
          <p className="text-xs text-text-muted">
            {t('operatorOutage.site.importHint', {
              defaultValue:
                'Optional column operateur — the fixed-line provider (free text, 64 characters at most, e.g. Orange). It groups stores falling back to 4G at the same time into one « probable operator outage » alert. An empty cell changes nothing.',
            })}
          </p>
          <p className="text-xs text-text-muted">
            {t('sites.import.codeHint', {
              defaultValue:
                'Format the code column as Text in your spreadsheet: Excel drops leading zeros (00102 becomes 102). Under a fixed-length code format, a numeric code that lost its zeros gets them back and the check says so; any other mismatch is refused.',
            })}
          </p>
          <p className="text-xs text-text-muted">
            {t('sites.import.orphansHint', {
              defaultValue:
                "The CHR reconciliation's orphans workbook is this import's format: fill in the names, save it as CSV UTF-8, and check it here — each row then says which CHR account it takes over.",
            })}
          </p>

          <div className="flex flex-wrap items-center gap-2">
            <Button type="button" size="sm" variant="secondary" onClick={downloadTemplate}>
              <Download size={14} className="mr-1.5" />
              {t('sites.import.downloadTemplate', { defaultValue: 'Download the CSV template' })}
            </Button>
            <label className="inline-flex cursor-pointer items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-sm text-text-primary hover:bg-bg-tertiary">
              <FileUp size={14} />
              {t('sites.import.chooseFile', { defaultValue: 'Choose a file' })}
              <input type="file" accept=".csv,text/csv,text/plain" className="hidden" onChange={onFile} />
            </label>
          </div>

          <textarea
            value={csv}
            onChange={(e) => { setCsv(e.target.value); setLegacyEncoding(false); }}
            rows={8}
            spellCheck={false}
            placeholder={t('sites.import.pastePlaceholder', { defaultValue: '…or paste the CSV here' })}
            className="w-full rounded-md border border-border bg-bg-primary p-2 font-mono text-xs text-text-primary"
          />
          {legacyEncoding && (
            <p className="text-xs text-text-muted">
              {t('sites.import.legacyEncoding', {
                defaultValue: 'This file is not UTF-8: it was read as Windows-1252 (Excel). Check the accents above before importing.',
              })}
            </p>
          )}

          {canAllocate && (
            <label className="flex items-start gap-2 text-sm text-text-primary">
              <input
                type="checkbox"
                checked={allocate}
                onChange={(e) => setAllocate(e.target.checked)}
                className="mt-0.5"
              />
              <span>
                {t('sites.import.allocate', { defaultValue: 'Allocate addresses' })}
                <span className="block text-xs text-text-muted">
                  {t('sites.import.allocateHint', {
                    defaultValue:
                      "Reserves the PPP login, tunnel address and LAN subnet of every imported site, using the tenant's allocation policy.",
                  })}
                </span>
              </span>
            </label>
          )}

          {fileErrors.length > 0 && (
            <div className="rounded-md border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-400">
              <p className="font-medium">
                {t('sites.import.fileErrors', { defaultValue: 'The file cannot be imported' })}
              </p>
              <ul className="mt-1 list-disc pl-5 text-xs">
                {fileErrors.map((e) => <li key={e}>{e}</li>)}
              </ul>
            </div>
          )}

          {stale && (
            <p className="text-xs text-amber-400">
              {t('sites.import.stale', {
                defaultValue: 'The CSV changed since the check — check it again before importing.',
              })}
            </p>
          )}

          {result && (
            <div className="space-y-2">
              <p className="text-sm text-text-primary">
                {result.dryRun
                  ? t('sites.import.summary', {
                      defaultValue:
                        '{{rows}} rows: {{create}} to create, {{update}} to update, {{skip}} unchanged, {{rejected}} rejected',
                      ...result.summary,
                    })
                  : t('sites.import.appliedSummary', {
                      defaultValue: '{{applied}} rows written, {{rejected}} rejected',
                      ...result.summary,
                    })}
                {!result.dryRun && result.allocate && (
                  <> · {t('sites.import.allocSummary', {
                    defaultValue: '{{allocated}} allocated, {{failed}} allocation failures',
                    allocated: result.summary.allocated,
                    failed: result.summary.allocationFailed,
                  })}</>
                )}
                {(result.summary.codesRestored ?? 0) > 0 && (
                  <> · <span className="text-amber-400">{t('sites.import.codesRestoredSummary', {
                    defaultValue: '{{count}} code(s) given back their leading zeros — read them below',
                    count: result.summary.codesRestored,
                  })}</span></>
                )}
              </p>
              {chrSummary?.status === 'compared' && (
                <div className="space-y-1 text-xs">
                  <p className="text-text-muted">
                    {t('sites.import.chr.summary', {
                      defaultValue:
                        "Compared with the CHR's accounts as last read {{age}} ({{date}}) — nothing was dialled for this check: {{takesOver}} take over an account, {{new}} new, {{suspect}} suspect, {{allocated}} already allocated.",
                      age: ageText(chrSummary.ageSeconds, i18n.language),
                      date: new Date(chrSummary.readAt).toLocaleString(i18n.language),
                      takesOver: chrSummary.counts.takesOver,
                      new: chrSummary.counts.new,
                      suspect: chrSummary.counts.suspect,
                      allocated: chrSummary.counts.allocated,
                    })}
                  </p>
                  <p className="text-text-muted">
                    {t('sites.import.chr.asOfRead', {
                      defaultValue:
                        'An account created or removed on the CHR since that read is not reflected: re-read the CHR from the reconciliation page, then check again, if that matters here.',
                    })}
                  </p>
                  {chrSummary.counts.suspect > 0 && (
                    <p className="text-amber-400">
                      {t('sites.import.chr.suspectHelp', {
                        defaultValue:
                          'A suspect row is imported all the same — it is a warning. Its allocation will NOT take over the account it resembles (only an exact login is adopted): correct its code or country first if it is that store.',
                      })}
                    </p>
                  )}
                  {!chrSummary.namesTenant && (
                    <p className="text-amber-400">
                      {t('sites.import.chr.unproven', {
                        defaultValue:
                          "This tenant's login template does not name the tenant: on a CHR shared with other customers, an account it matches may be theirs.",
                      })}
                    </p>
                  )}
                </div>
              )}
              {chrSummary && chrSummary.status !== 'compared' && (
                <p className="text-xs text-amber-400">
                  {chrSummary.status === 'neverRead'
                    ? t('sites.import.chr.neverRead', {
                        defaultValue:
                          "The CHR's accounts have never been read, so no row can be compared with it yet. Nothing was dialled for this check.",
                      })
                    : chrSummary.status === 'refused'
                      ? t('sites.import.chr.refused', {
                          defaultValue:
                            "No comparison with the CHR: this workspace's login rule does not name the workspace, so the accounts it matches may belong to other customers. Only a platform administrator can compare them.",
                        })
                      : t('sites.import.chr.unavailable', {
                          defaultValue: 'No comparison with the CHR: {{message}}',
                          message: chrSummary.message,
                        })}
                </p>
              )}
              <div className="max-h-96 overflow-auto rounded-md border border-border">
                <table className="w-full text-left text-xs">
                  <thead className="sticky top-0 bg-bg-tertiary text-text-muted">
                    <tr>
                      <th className="px-2 py-1.5 font-medium">{t('sites.import.col.line', { defaultValue: 'Line' })}</th>
                      <th className="px-2 py-1.5 font-medium">{t('sites.import.col.code', { defaultValue: 'Code' })}</th>
                      <th className="px-2 py-1.5 font-medium">{t('sites.import.col.action', { defaultValue: 'Action' })}</th>
                      <th className="px-2 py-1.5 font-medium">{t('sites.import.col.changes', { defaultValue: 'Changes' })}</th>
                      {showChrColumn && (
                        <th className="px-2 py-1.5 font-medium">{t('sites.import.col.chr', { defaultValue: 'CHR' })}</th>
                      )}
                      <th className="px-2 py-1.5 font-medium">{t('sites.import.col.result', { defaultValue: 'Result' })}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.rows.map((r) => {
                      const ok = r.errors.length === 0;
                      const alloc = allocationLine(r);
                      return (
                        <tr key={`${r.line}-${r.code}`} className="border-t border-border align-top">
                          <td className="px-2 py-1.5 font-mono text-text-muted">{r.line}</td>
                          <td className="px-2 py-1.5 font-mono text-text-primary">
                            {r.code || '—'}
                            {r.codeRestored && (
                              <div className="mt-0.5 whitespace-nowrap font-sans text-amber-400">
                                {t('sites.import.codeRestored', {
                                  defaultValue: '{{from}} → {{to}} (leading zeros restored)',
                                  from: r.codeRestored.from,
                                  to: r.codeRestored.to,
                                })}
                              </div>
                            )}
                          </td>
                          <td className="px-2 py-1.5 text-text-primary">{actionLabel(r)}</td>
                          <td className="px-2 py-1.5 font-mono text-text-muted">{r.changes.join(', ') || '—'}</td>
                          {showChrColumn && <td className="px-2 py-1.5">{chrCell(r)}</td>}
                          <td className="px-2 py-1.5">
                            {ok ? (
                              <span className="inline-flex items-center gap-1 text-emerald-400">
                                <CheckCircle2 size={12} />
                                {result.dryRun
                                  ? t('sites.import.status.ok', { defaultValue: 'Valid' })
                                  : r.applied
                                    ? t('sites.import.status.applied', { defaultValue: 'Written' })
                                    : t('sites.import.action.skip', { defaultValue: 'Unchanged' })}
                              </span>
                            ) : (
                              <div className="text-red-400">
                                <span className="inline-flex items-center gap-1">
                                  <XCircle size={12} />
                                  {t('sites.import.status.notApplied', { defaultValue: 'Not written' })}
                                </span>
                                <ul className="mt-0.5 list-disc pl-4">
                                  {r.errors.map((e, i) => <li key={i}>{e}</li>)}
                                </ul>
                              </div>
                            )}
                            {alloc && (
                              <div className={cn('mt-0.5', r.allocation?.status === 'failed' ? 'text-amber-400' : 'text-text-muted')}>
                                {alloc}
                              </div>
                            )}
                            {(r.allocation?.warnings?.length ?? 0) > 0 && (
                              <div className="mt-1 text-amber-400">
                                <span className="inline-flex items-center gap-1 font-medium">
                                  <AlertTriangle size={12} />
                                  {t('sites.import.alloc.warningsTitle', {
                                    defaultValue: 'Read before deploying this site:',
                                  })}
                                </span>
                                <ul className="mt-0.5 list-disc pl-4">
                                  {r.allocation?.warnings?.map((w, i) => <li key={i}>{w}</li>)}
                                </ul>
                              </div>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>

        <div className="flex justify-end gap-2 border-t border-border px-5 py-3">
          <Button type="button" size="sm" variant="secondary" onClick={onClose}>
            {t('sites.import.close', { defaultValue: 'Close' })}
          </Button>
          <Button
            type="button"
            size="sm"
            variant="secondary"
            loading={busy === 'check'}
            disabled={busy !== null || csv.trim() === ''}
            onClick={() => void run(true)}
          >
            {t('sites.import.dryRun', { defaultValue: 'Check' })}
          </Button>
          <Button
            type="button"
            size="sm"
            loading={busy === 'import'}
            disabled={busy !== null || !canImport}
            onClick={() => void run(false)}
          >
            {t('sites.import.apply', { defaultValue: 'Import' })}
          </Button>
        </div>
      </div>
    </div>
  );
}
