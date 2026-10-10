import { useRef, useState, type ChangeEvent, type MouseEvent } from 'react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { Link } from 'react-router-dom';
import {
  AlertTriangle, CheckCircle2, FileJson, FileUp, Info, MinusCircle, Upload, XCircle,
} from 'lucide-react';
import { templatesApi, type TemplateImportItem, type TemplateImportReport } from '@/api/templates.api';
import { Button } from '@/components/common/Button';
import { issueWhere } from './labels';

/**
 * Import a template file (`obliwan-template/1`) or a bundle
 * (`obliwan-template-bundle/1`) in three steps: pick the file, read the
 * server's dry run, import.
 *
 * The dry run is the SERVER's verdict, not a client guess: the same
 * validators as a template made by hand, the same name lookup as the import.
 * The import repeats both — what the table showed is advice, not a promise —
 * and writes each valid template in its own transaction. Nothing is
 * published: every revision arrives as a draft, to be read, previewed and
 * published by a person. An entry identical to its template's latest revision
 * is reported unchanged and not written, so choosing the same file again after
 * fixing one entry does not stack duplicate drafts of the others.
 */
interface TemplateImportDialogProps {
  onClose: () => void;
  /** Called after a real import wrote at least one draft, with its report. */
  onImported: (report: TemplateImportReport) => void;
  /** Asked before an "Open" link leaves the page's current state (an editor
   *  with unsaved changes). Returning false keeps everything where it is. */
  confirmNavigate?: (target: { templateId: string; revisionId: string }) => boolean;
}

type Step = 'pick' | 'checking' | 'checked' | 'importing' | 'done';

function serverError(err: unknown): string | null {
  return (err as { response?: { data?: { error?: string } } }).response?.data?.error ?? null;
}

export function TemplateImportDialog({ onClose, onImported, confirmNavigate }: TemplateImportDialogProps) {
  const { t } = useTranslation();
  const fileRef = useRef<HTMLInputElement>(null);
  const [step, setStep] = useState<Step>('pick');
  const [fileName, setFileName] = useState<string | null>(null);
  const [payload, setPayload] = useState<unknown>(null);
  const [report, setReport] = useState<TemplateImportReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  const reset = () => {
    setStep('pick'); setFileName(null); setPayload(null); setReport(null); setError(null);
    if (fileRef.current) fileRef.current.value = '';
  };

  const onFile = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    // Cleared at once, so choosing the SAME file again after fixing it on
    // disk fires a change and is checked again.
    e.target.value = '';
    if (!file) return;
    setFileName(file.name);
    setReport(null);
    setError(null);
    let parsed: unknown;
    try {
      parsed = JSON.parse(await file.text()) as unknown;
    } catch (err) {
      setError(t('templates.import.notJson', {
        defaultValue: 'This file is not valid JSON: {{message}}', message: (err as Error).message,
      }));
      setStep('pick');
      return;
    }
    setPayload(parsed);
    setStep('checking');
    try {
      setReport(await templatesApi.importFile(parsed, { dryRun: true }));
      setStep('checked');
    } catch (err) {
      setError(
        (err as { response?: { status?: number } }).response?.status === 413
          ? t('templates.import.tooLarge', {
            defaultValue: 'The file is larger than the server accepts in one request (1 MB). Split the bundle.',
          })
          : serverError(err) ?? t('templates.import.checkFailed', { defaultValue: 'The file could not be checked.' }),
      );
      setStep('pick');
    }
  };

  const runImport = async () => {
    if (!payload) return;
    setStep('importing');
    setError(null);
    try {
      const done = await templatesApi.importFile(payload, { dryRun: false });
      setReport(done);
      setStep('done');
      if (done.summary.created > 0) onImported(done);
    } catch (err) {
      setError(serverError(err) ?? t('templates.import.failed', { defaultValue: 'The import failed.' }));
      setStep('checked');
    }
  };

  const valid = report?.summary.valid ?? 0;
  const invalid = report?.summary.invalid ?? 0;
  const unchanged = report?.summary.unchanged ?? 0;
  /** What the Import button would actually write. */
  const toImport = Math.max(valid - unchanged, 0);

  const navigate = (target: { templateId: string; revisionId: string }): boolean => {
    if (confirmNavigate && !confirmNavigate(target)) return false;
    onClose();
    return true;
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="template-import-title"
        className="my-8 w-full max-w-4xl rounded-xl border border-border bg-bg-secondary shadow-2xl"
      >
        <div className="flex items-center gap-2 border-b border-border px-5 py-4">
          <FileUp size={18} className="text-accent" />
          <h2 id="template-import-title" className="text-base font-semibold text-text-primary">
            {t('templates.import.title', { defaultValue: 'Import templates' })}
          </h2>
        </div>

        <div className="space-y-4 p-5">
          <p className="flex items-start gap-1.5 text-xs text-text-secondary">
            <Info size={13} className="mt-0.5 shrink-0 text-text-muted" />
            {t('templates.import.intro', {
              defaultValue:
                'Pick a .owt.json file (one template) or a bundle (several). ObliWAN checks it first and shows what it would do; nothing is written until you click Import. Imported templates arrive as DRAFTS: nothing is published.',
            })}
          </p>

          <div className="flex flex-wrap items-center gap-3">
            <input
              ref={fileRef}
              type="file"
              accept=".json,application/json"
              className="hidden"
              onChange={(e) => void onFile(e)}
            />
            <Button
              type="button"
              variant="secondary"
              size="sm"
              onClick={() => fileRef.current?.click()}
              disabled={step === 'checking' || step === 'importing'}
            >
              <FileJson size={14} className="mr-1.5" />
              {fileName
                ? t('templates.import.pickOther', { defaultValue: 'Choose another file' })
                : t('templates.import.pick', { defaultValue: 'Choose a file' })}
            </Button>
            {fileName && <span className="font-mono text-xs text-text-secondary">{fileName}</span>}
            {step === 'checking' && (
              <span className="text-xs text-text-muted">
                {t('templates.import.checking', { defaultValue: 'Checking…' })}
              </span>
            )}
          </div>

          {error && (
            <p className="flex items-start gap-1.5 rounded border border-status-down/50 bg-status-down/10 p-2 text-xs text-status-down">
              <AlertTriangle size={13} className="mt-0.5 shrink-0" />
              <span className="whitespace-pre-wrap break-words">{error}</span>
            </p>
          )}

          {report && (
            <>
              {/* WHERE it goes: the session's customer, never the file's. */}
              <p className="rounded-md border border-accent/40 bg-accent/10 px-3 py-2 text-xs text-text-primary">
                {t('templates.import.target', {
                  defaultValue: 'These templates go into the customer: {{tenant}}',
                  tenant: report.tenant.name ?? `#${report.tenant.id}`,
                })}
              </p>

              <ReportTable report={report} onNavigate={navigate} />

              {step === 'checked' && (
                <div className="space-y-1 text-xs text-text-secondary">
                  <p>
                    {invalid === 0
                      ? t('templates.import.allValid', {
                        defaultValue: 'Everything is valid: {{n}} template(s) ready to import as drafts.', n: toImport,
                      })
                      : t('templates.import.someInvalidReimport', {
                        defaultValue:
                          '{{valid}} template(s) ready; {{invalid}} with errors will be skipped. Once they are fixed, choose the file again: the entries already imported are recognised as unchanged and are not imported twice.',
                        valid: toImport, invalid,
                      })}
                  </p>
                  {unchanged > 0 && (
                    <p>
                      {t('templates.import.unchangedNote', {
                        defaultValue:
                          '{{n}} template(s) identical to their latest revision: nothing to import for them.',
                        n: unchanged,
                      })}
                    </p>
                  )}
                </div>
              )}
              {step === 'done' && (
                <p className="text-xs text-text-secondary">
                  {t('templates.import.doneSummaryWithUnchanged', {
                    defaultValue:
                      '{{created}} draft(s) created, {{unchanged}} unchanged, {{skipped}} skipped, {{failed}} failed. Open a draft to check it, preview it, then publish it.',
                    created: report.summary.created,
                    unchanged: report.summary.unchanged ?? 0,
                    skipped: report.summary.skipped,
                    failed: report.summary.failed,
                  })}
                </p>
              )}
            </>
          )}
        </div>

        <div className="flex flex-wrap justify-end gap-2 border-t border-border px-5 py-3">
          {step === 'done' ? (
            <>
              <Button type="button" size="sm" variant="secondary" onClick={reset}>
                {t('templates.import.another', { defaultValue: 'Import another file' })}
              </Button>
              <Button type="button" size="sm" onClick={onClose}>{t('common.close')}</Button>
            </>
          ) : (
            <>
              <Button type="button" size="sm" variant="secondary" onClick={onClose}>{t('common.cancel')}</Button>
              <Button
                type="button"
                size="sm"
                onClick={() => void runImport()}
                loading={step === 'importing'}
                disabled={step !== 'checked' || toImport === 0}
              >
                <Upload size={14} className="mr-1.5" />
                {t('templates.import.confirm', { defaultValue: 'Import {{n}} template(s)', n: toImport })}
              </Button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function revisionStatusText(t: TFunction, status: string): string {
  if (status === 'published') return t('templates.frozen', { defaultValue: 'Published — frozen' });
  if (status === 'draft') return t('templates.draft', { defaultValue: 'Draft' });
  return status;
}

function actionText(t: TFunction, item: TemplateImportItem): string {
  if (item.action === 'unchanged' && item.sameAs) {
    return item.sameAs.kind === 'revision'
      ? t('templates.import.actionUnchanged', {
        defaultValue: 'Nothing: identical to revision {{n}} ({{status}})',
        n: item.sameAs.revision, status: revisionStatusText(t, item.sameAs.status),
      })
      : t('templates.import.actionUnchangedEntry', {
        defaultValue: 'Nothing: identical to entry {{n}} of this file',
        n: item.sameAs.index + 1,
      });
  }
  return item.action === 'create'
    ? t('templates.import.actionCreate', { defaultValue: 'New template, draft revision 1' })
    : t('templates.import.actionRevision', {
      defaultValue: 'New draft revision of the existing template of the same name',
    });
}

type NavigateTo = (target: { templateId: string; revisionId: string }) => boolean;

function ReportTable({ report, onNavigate }: { report: TemplateImportReport; onNavigate: NavigateTo }) {
  const { t } = useTranslation();
  return (
    <div className="overflow-x-auto rounded-lg border border-border">
      <table className="w-full min-w-[640px] text-left text-xs">
        <thead>
          <tr className="border-b border-border bg-bg-tertiary/40 text-[11px] uppercase tracking-wider text-text-muted">
            <th className="px-3 py-2 font-medium">{t('templates.import.col.template', { defaultValue: 'Template' })}</th>
            <th className="px-3 py-2 font-medium">{t('templates.import.col.action', { defaultValue: 'What happens' })}</th>
            <th className="px-3 py-2 font-medium">{t('templates.import.col.result', { defaultValue: 'Result' })}</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {report.items.map((item) => (
            <tr key={item.index} className="align-top">
              <td className="px-3 py-2">
                <div className="font-medium text-text-primary">
                  {item.name || t('templates.import.unnamed', { defaultValue: '(no name)' })}
                </div>
                {item.brand && <div className="text-[11px] text-text-muted">{item.brand}</div>}
              </td>
              <td className="px-3 py-2 text-text-secondary">{actionText(t, item)}</td>
              <td className="px-3 py-2">
                <ItemResult item={item} dryRun={report.dryRun} onNavigate={onNavigate} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ItemResult({ item, dryRun, onNavigate }: { item: TemplateImportItem; dryRun: boolean; onNavigate: NavigateTo }) {
  const { t } = useTranslation();
  // The link changes the page's URL; `onNavigate` may refuse (unsaved edits).
  const guard = (e: MouseEvent<HTMLAnchorElement>) => {
    if (!item.templateId || !item.revisionId) return;
    if (!onNavigate({ templateId: item.templateId, revisionId: item.revisionId })) e.preventDefault();
  };
  return (
    <div className="space-y-1">
      {dryRun ? (
        item.errors.length === 0 && item.action === 'unchanged' ? (
          <span className="inline-flex items-center gap-1 text-text-muted">
            <MinusCircle size={13} />{t('templates.import.unchanged', { defaultValue: 'Unchanged — not imported' })}
          </span>
        ) : item.errors.length === 0 ? (
          <span className="inline-flex items-center gap-1 text-status-up">
            <CheckCircle2 size={13} />{t('templates.import.ready', { defaultValue: 'Ready' })}
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 text-status-down">
            <XCircle size={13} />
            {t('templates.import.errorCount', { defaultValue: '{{n}} error(s) — will be skipped', n: item.errors.length })}
          </span>
        )
      ) : item.outcome === 'created' ? (
        <span className="inline-flex flex-wrap items-center gap-1 text-status-up">
          <CheckCircle2 size={13} />
          {t('templates.import.created', { defaultValue: 'Draft revision {{n}} created', n: item.revision })}
          {item.templateId && item.revisionId && (
            <Link
              to={`/templates?template=${item.templateId}&revision=${item.revisionId}`}
              onClick={guard}
              className="ml-1 text-accent hover:underline"
            >
              {t('templates.import.openDraft', { defaultValue: 'Open the draft' })}
            </Link>
          )}
        </span>
      ) : item.outcome === 'unchanged' ? (
        <span className="inline-flex flex-wrap items-center gap-1 text-text-muted">
          <MinusCircle size={13} />
          {t('templates.import.unchangedKept', {
            defaultValue: 'Unchanged — revision {{n}} is identical, nothing written', n: item.revision,
          })}
          {item.templateId && item.revisionId && (
            <Link
              to={`/templates?template=${item.templateId}&revision=${item.revisionId}`}
              onClick={guard}
              className="ml-1 text-accent hover:underline"
            >
              {t('templates.import.openRevision', { defaultValue: 'Open it' })}
            </Link>
          )}
        </span>
      ) : item.outcome === 'skipped' ? (
        <span className="inline-flex items-center gap-1 text-text-muted">
          <MinusCircle size={13} />{t('templates.import.skipped', { defaultValue: 'Skipped (errors)' })}
        </span>
      ) : (
        <span className="inline-flex items-center gap-1 text-status-down">
          <XCircle size={13} />{t('templates.import.writeFailed', { defaultValue: 'Not imported' })}
        </span>
      )}

      {item.errors.length > 0 && (
        <ul className="space-y-0.5 text-[11px] text-status-down">
          {item.errors.slice(0, 25).map((e, i) => (
            <li key={i}>
              <span className="font-medium">{issueWhere(t, e)}</span>
              {' — '}
              <span className="text-text-secondary">{e.message}</span>
            </li>
          ))}
          {item.errors.length > 25 && (
            <li className="text-text-muted">
              {t('templates.import.moreErrors', { defaultValue: '… and {{n}} more', n: item.errors.length - 25 })}
            </li>
          )}
        </ul>
      )}
      {item.warnings.length > 0 && (
        <ul className="space-y-0.5 text-[11px] text-status-ssl-warning">
          {item.warnings.map((w) => <li key={w}>{w}</li>)}
        </ul>
      )}
    </div>
  );
}
