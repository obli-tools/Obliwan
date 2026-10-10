import { useMemo, useRef, useState, type ChangeEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { FileJson, Info, Library, X } from 'lucide-react';
import { Button } from '@/components/common/Button';
import { cn } from '@/utils/cn';
import { loadTemplateFile } from './fileLoaders';
import { useQuickSetupStore } from './quickSetupStore';
import { CARD, INPUT, LABEL } from './ui';

/**
 * Designer step 1 — which template the setup is about.
 *
 * Either an EXISTING revision of this workspace (or of the shipped library):
 * then it is only a reference — the check types the values against its
 * `var_schema` and nothing is imported or published. Or a FILE: then the
 * template part is selected, the file is imported as a draft revision, and
 * published after the variables and the rule are written when "Publish" is
 * ticked (the bench offers every published revision, so a revision is offered
 * only once its inputs exist).
 */
export function TemplateSection() {
  const { t } = useTranslation();
  const context = useQuickSetupStore((s) => s.context);
  const contextError = useQuickSetupStore((s) => s.contextError);
  const template = useQuickSetupStore((s) => s.template);
  const publish = useQuickSetupStore((s) => s.publish);
  const setTemplate = useQuickSetupStore((s) => s.setTemplate);
  const setPublish = useQuickSetupStore((s) => s.setPublish);
  const setFile = useQuickSetupStore((s) => s.setFile);
  const fileRef = useRef<HTMLInputElement>(null);
  const [error, setError] = useState<string | null>(null);
  const [pref, setPref] = useState<'existing' | 'file'>('existing');
  // The radio shows what is in effect; switching it drops the other choice,
  // so a file can never stay selected behind a select that reads "(none)".
  const mode = template.source === 'file' ? 'file' : template.source === 'existing' ? 'existing' : pref;
  const setMode = (m: 'existing' | 'file') => {
    if (m === mode) return;
    if (template.source !== 'none') {
      setTemplate({ source: 'none' });
      setFile('template', null);
    }
    setPref(m);
  };

  const templates = useMemo(() => context?.templates ?? [], [context]);
  const chosenTemplateId = useMemo(() => {
    if (template.source !== 'existing') return '';
    return templates.find((tp) => tp.revisions.some((r) => r.id === template.revisionId))?.templateId ?? '';
  }, [template, templates]);
  const chosen = templates.find((tp) => tp.templateId === chosenTemplateId);

  const pickTemplate = (templateId: string) => {
    const tp = templates.find((x) => x.templateId === templateId);
    if (!tp) {
      setTemplate({ source: 'none' });
      return;
    }
    // The newest PUBLISHED revision — what the bench would offer; else the newest.
    const rev = tp.revisions.find((r) => r.status === 'published') ?? tp.revisions[0];
    if (!rev) return;
    setTemplate({ source: 'existing', revisionId: rev.id, label: `${tp.name} r${rev.revision}` });
  };

  const pickRevision = (revisionId: string) => {
    if (!chosen) return;
    const rev = chosen.revisions.find((r) => r.id === revisionId);
    if (rev) setTemplate({ source: 'existing', revisionId: rev.id, label: `${chosen.name} r${rev.revision}` });
  };

  const onFile = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    setError(null);
    const r = await loadTemplateFile(t, file);
    if (!r.ok) setError(r.message);
  };

  const removeFile = () => {
    setTemplate({ source: 'none' });
    setFile('template', null);
  };

  const statusText = (status: string) =>
    status === 'published'
      ? t('templates.frozen', { defaultValue: 'Published — frozen' })
      : status === 'draft'
        ? t('templates.draft', { defaultValue: 'Draft' })
        : status;

  return (
    <section className={CARD} id="qs-step-template">
      <div className="mb-3 flex flex-wrap gap-4 text-sm">
        <label className="inline-flex items-center gap-1.5 text-text-primary">
          <input type="radio" name="qs-template-mode" checked={mode === 'existing'} onChange={() => setMode('existing')} />
          {t('quickSetup.template.existing', { defaultValue: "A template of this workspace" })}
        </label>
        <label className="inline-flex items-center gap-1.5 text-text-primary">
          <input type="radio" name="qs-template-mode" checked={mode === 'file'} onChange={() => setMode('file')} />
          {t('quickSetup.template.upload', { defaultValue: 'Import a .owt.json file' })}
        </label>
      </div>

      {mode === 'existing' ? (
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <div>
            <label className={LABEL}>{t('quickSetup.template.template', { defaultValue: 'Template' })}</label>
            <select className={INPUT} value={chosenTemplateId} onChange={(e) => pickTemplate(e.target.value)}>
              <option value="">{t('quickSetup.template.noTemplate', { defaultValue: '(none: the published templates of the workspace)' })}</option>
              {templates.map((tp) => (
                <option key={tp.templateId} value={tp.templateId}>
                  {tp.name}
                  {tp.brand ? ` — ${tp.brand}` : ''}
                  {tp.library ? ` (${t('quickSetup.template.library', { defaultValue: 'library' })})` : ''}
                </option>
              ))}
            </select>
          </div>
          {chosen && template.source === 'existing' && (
            <div>
              <label className={LABEL}>{t('quickSetup.template.revision', { defaultValue: 'Revision' })}</label>
              <select className={INPUT} value={template.revisionId} onChange={(e) => pickRevision(e.target.value)}>
                {chosen.revisions.map((r) => (
                  <option key={r.id} value={r.id}>
                    r{r.revision} — {statusText(r.status)}
                  </option>
                ))}
              </select>
            </div>
          )}
          <p className="flex items-start gap-1.5 text-xs text-text-muted md:col-span-2">
            <Info size={13} className="mt-0.5 shrink-0" />
            {t('quickSetup.template.existingHint', {
              defaultValue:
                'A reference only: the form is generated from its variables and the check types the values against it. Nothing is imported or published.',
            })}
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <input ref={fileRef} type="file" accept=".json,application/json" className="hidden" onChange={(e) => void onFile(e)} />
            <Button type="button" size="sm" variant="secondary" onClick={() => fileRef.current?.click()}>
              <FileJson size={14} className="mr-1.5" />
              {template.source === 'file'
                ? t('templates.import.pickOther', { defaultValue: 'Choose another file' })
                : t('templates.import.pick', { defaultValue: 'Choose a file' })}
            </Button>
            {template.source === 'file' && (
              <>
                <span className="font-mono text-xs text-text-secondary">{template.fileName}</span>
                <span className="text-xs text-text-muted">
                  {template.summary.entries > 1
                    ? t('quickSetup.template.bundleSummary', {
                      defaultValue: '{{count}} templates, the first "{{name}}"',
                      count: template.summary.entries, name: template.summary.name,
                    })
                    : `${template.summary.name}${template.summary.brand ? ` — ${template.summary.brand}` : ''}`}
                </span>
                <button
                  type="button"
                  onClick={removeFile}
                  className="rounded p-1 text-text-muted hover:text-status-down"
                  aria-label={t('quickSetup.files.remove', { defaultValue: 'Remove' })}
                >
                  <X size={14} />
                </button>
              </>
            )}
          </div>
          <label className="flex items-start gap-2 text-sm text-text-primary">
            <input type="checkbox" className="mt-0.5" checked={publish} onChange={(e) => setPublish(e.target.checked)} />
            <span>
              {t('quickSetup.options.publish', { defaultValue: 'Publish the new revision' })}
              <span className="block text-xs text-text-muted">
                {t('quickSetup.options.publishHint', { defaultValue: 'Published after the variables and the rule are written.' })}
              </span>
            </span>
          </label>
        </div>
      )}

      {(error || (template.source === 'file' && contextError)) && (
        <p className="mt-3 whitespace-pre-wrap rounded border border-status-down/50 bg-status-down/10 p-2 text-xs text-status-down">
          {error ?? contextError}
        </p>
      )}

      {context && context.references.length > 0 && (
        <div className="mt-3 text-xs text-text-muted">
          <span className="mr-1">{t('quickSetup.template.references', { defaultValue: 'Variables typed against:' })}</span>
          {context.references.map((r, i) => (
            <span
              key={`${r.kind}-${r.revisionId ?? i}`}
              className={cn('mr-1.5 inline-flex items-center gap-1 rounded bg-bg-tertiary px-1.5 py-0.5')}
            >
              {r.kind === 'published' && <Library size={11} />}
              {r.name}
              {r.revision !== null ? ` r${r.revision}` : ''}
              {r.kind === 'file' ? ` (${t('quickSetup.template.fromFile', { defaultValue: 'file' })})` : ''}
            </span>
          ))}
        </div>
      )}
    </section>
  );
}
