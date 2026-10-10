import { useRef, useState, type DragEvent, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { CheckCircle2, FileJson, FileSpreadsheet, Package, PencilRuler, Upload, X } from 'lucide-react';
import type { SetupPart } from '@obliwan/shared';
import { cn } from '@/utils/cn';
import {
  loadBundleFile, loadPolicyFile, loadSitesFile, loadTemplateFile, loadVariablesFile, type LoadResult,
} from './fileLoaders';
import { FIELD_LEVELS, emptySites, isBlankRow, useQuickSetupStore } from './quickSetupStore';
import { CARD } from './ui';

/**
 * The "Files" tab: up to five drop zones — one bundle (`obliwan-tenant-setup/1`)
 * or the four files on their own. A file fills the same state the designer
 * edits, ticks its part, and can be opened in the designer to be corrected
 * there; nothing is sent before "Check".
 */

type Slot = SetupPart | 'bundle';

function DropZone({
  slot,
  title,
  hint,
  accept,
  icon,
  load,
  summary,
  onRemove,
  onOpen,
  children,
}: {
  slot: Slot;
  title: string;
  hint: string;
  accept: string;
  icon: ReactNode;
  load: (file: File) => Promise<LoadResult>;
  summary: string | null;
  onRemove: () => void;
  onOpen?: () => void;
  children?: ReactNode;
}) {
  const { t } = useTranslation();
  const loaded = useQuickSetupStore((s) => s.files[slot]);
  const inputRef = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);
  const [message, setMessage] = useState<{ kind: 'error' | 'note'; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const take = async (file: File | undefined) => {
    if (!file) return;
    setBusy(true);
    setMessage(null);
    try {
      const r = await load(file);
      if (!r.ok) setMessage({ kind: 'error', text: r.message });
      else if (r.note) setMessage({ kind: 'note', text: r.note });
    } catch (err) {
      setMessage({ kind: 'error', text: (err as Error).message });
    } finally {
      setBusy(false);
    }
  };

  const onDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setOver(false);
    void take(e.dataTransfer.files?.[0]);
  };

  return (
    <div className={CARD}>
      <div className="mb-2 flex items-center gap-2">
        {icon}
        <h3 className="flex-1 text-sm font-semibold text-text-primary">{title}</h3>
        {loaded && <CheckCircle2 size={15} className="text-emerald-400" />}
      </div>
      <p className="mb-2 text-xs text-text-muted">{hint}</p>
      <div
        onDragOver={(e) => { e.preventDefault(); setOver(true); }}
        onDragLeave={() => setOver(false)}
        onDrop={onDrop}
        className={cn(
          'flex flex-wrap items-center justify-center gap-1 rounded-lg border border-dashed px-3 py-4 text-xs text-text-muted',
          over ? 'border-accent bg-accent/10' : 'border-border',
        )}
      >
        <Upload size={14} />
        {t('quickSetup.files.drop', { defaultValue: 'Drop a file here or' })}
        <button type="button" onClick={() => inputRef.current?.click()} className="text-accent hover:underline" disabled={busy}>
          {t('quickSetup.files.choose', { defaultValue: 'choose…' })}
        </button>
        <input
          ref={inputRef}
          type="file"
          accept={accept}
          className="hidden"
          onChange={(e) => {
            const f = e.target.files?.[0];
            // Cleared at once, so choosing the same file again after fixing
            // it on disk loads it again.
            e.target.value = '';
            void take(f);
          }}
        />
      </div>
      {loaded && (
        <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
          <span className="font-mono text-text-secondary">{loaded.name}</span>
          {summary && <span className="text-text-muted">{summary}</span>}
          <span className="ml-auto flex items-center gap-2">
            {onOpen && (
              <button type="button" onClick={onOpen} className="inline-flex items-center gap-1 text-accent hover:underline">
                <PencilRuler size={12} />
                {t('quickSetup.files.openInDesigner', { defaultValue: 'Open in the designer' })}
              </button>
            )}
            <button
              type="button"
              onClick={() => { onRemove(); setMessage(null); }}
              className="inline-flex items-center gap-1 text-text-muted hover:text-status-down"
            >
              <X size={12} />
              {t('quickSetup.files.remove', { defaultValue: 'Remove' })}
            </button>
          </span>
        </div>
      )}
      {message && (
        <p
          className={cn(
            'mt-2 whitespace-pre-wrap rounded border p-2 text-xs',
            message.kind === 'error'
              ? 'border-status-down/50 bg-status-down/10 text-status-down'
              : 'border-amber-500/40 bg-amber-500/10 text-amber-400',
          )}
        >
          {message.text}
        </p>
      )}
      {children}
    </div>
  );
}

export function FilesPanel({ onOpenDesigner }: { onOpenDesigner: (sectionId: string) => void }) {
  const { t } = useTranslation();
  const fields = useQuickSetupStore((s) => s.fields);
  const extraRows = useQuickSetupStore((s) => s.extraRows);
  const variablesProblems = useQuickSetupStore((s) => s.variablesProblems);
  const template = useQuickSetupStore((s) => s.template);
  const sites = useQuickSetupStore((s) => s.sites);
  const policy = useQuickSetupStore((s) => s.policy);
  const store = useQuickSetupStore.getState;

  const fieldCount = FIELD_LEVELS.reduce((n, l) => n + Object.keys(fields[l]).length, 0);
  const siteCount = sites.rows.filter((r) => !isBlankRow(r)).length;

  return (
    <div className="space-y-4">
      <DropZone
        slot="bundle"
        title={t('quickSetup.files.bundle', { defaultValue: 'One bundle file' })}
        hint={t('quickSetup.files.bundleHint', { defaultValue: 'One obliwan-tenant-setup/1 file carrying any of the four parts.' })}
        accept=".json,application/json"
        icon={<Package size={16} className="text-accent" />}
        load={(f) => loadBundleFile(t, f)}
        summary={null}
        onRemove={() => store().setFile('bundle', null)}
      />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <DropZone
          slot="variables"
          title={t('quickSetup.parts.variables', { defaultValue: 'Variables table' })}
          hint={t('quickSetup.files.variablesHint', {
            defaultValue: 'CSV columns level, scope_ref, key, value, secret. An empty cell keeps the stored value; it never erases.',
          })}
          accept=".csv,.json,text/csv,application/json,text/plain"
          icon={<FileSpreadsheet size={16} className="text-accent" />}
          load={(f) => loadVariablesFile(t, f)}
          summary={t('quickSetup.files.variablesSummary', {
            defaultValue: '{{fields}} in the form, {{extra}} other row(s)', fields: fieldCount, extra: extraRows.length,
          })}
          onRemove={() => {
            store().clearVariables();
            store().setFile('variables', null);
            store().setSelected('variables', false);
          }}
          onOpen={() => onOpenDesigner('qs-step-variables')}
        >
          {variablesProblems.length > 0 && (
            <ul className="mt-2 space-y-0.5 text-xs text-status-down">
              {variablesProblems.slice(0, 20).map((p, i) => (
                <li key={i}>
                  {p.message ?? t('quickSetup.files.parseError', {
                    defaultValue: 'Line {{line}}: {{problem}}',
                    line: p.line,
                    problem: t(`quickSetup.csvProblem.${p.code}`, { defaultValue: p.code, column: p.column ?? '' }),
                  })}
                </li>
              ))}
            </ul>
          )}
        </DropZone>

        <DropZone
          slot="template"
          title={t('quickSetup.parts.template', { defaultValue: 'Template' })}
          hint={t('quickSetup.files.templateHint', { defaultValue: '.owt.json (one template or a bundle)' })}
          accept=".json,application/json"
          icon={<FileJson size={16} className="text-accent" />}
          load={(f) => loadTemplateFile(t, f)}
          summary={template.source === 'file'
            ? template.summary.entries > 1
              ? t('quickSetup.template.bundleSummary', {
                defaultValue: '{{count}} templates, the first "{{name}}"', count: template.summary.entries, name: template.summary.name,
              })
              : `${template.summary.name}${template.summary.brand ? ` — ${template.summary.brand}` : ''}`
            : null}
          onRemove={() => {
            store().setTemplate({ source: 'none' });
            store().setFile('template', null);
          }}
          onOpen={() => onOpenDesigner('qs-step-template')}
        />

        <DropZone
          slot="allocationPolicy"
          title={t('quickSetup.parts.allocationPolicy', { defaultValue: 'Allocation rule' })}
          hint={t('quickSetup.files.policyHint', { defaultValue: 'JSON of the allocation rule; pools and CHR by name' })}
          accept=".json,application/json"
          icon={<FileJson size={16} className="text-accent" />}
          load={(f) => loadPolicyFile(t, f)}
          summary={policy
            ? [policy.tunnelPool.name, policy.concentrator.name, policy.login].filter((x) => x !== '').join(' · ')
            : null}
          onRemove={() => {
            store().setPolicy(null);
            store().setFile('allocationPolicy', null);
            store().setSelected('allocationPolicy', false);
          }}
          onOpen={() => onOpenDesigner('qs-step-policy')}
        />

        <DropZone
          slot="sites"
          title={t('quickSetup.parts.sites', { defaultValue: 'Sites list' })}
          hint={t('quickSetup.files.sitesHint', {
            defaultValue: 'The Sites import CSV: code, name, country, timezone, address, contact, var:<key>',
          })}
          accept=".csv,text/csv,text/plain"
          icon={<FileSpreadsheet size={16} className="text-accent" />}
          load={(f) => loadSitesFile(t, f)}
          summary={t('quickSetup.files.sitesSummary', {
            defaultValue: '{{rows}} site(s), {{cols}} column(s)', rows: siteCount, cols: sites.header.length,
          })}
          onRemove={() => {
            store().setSites(emptySites());
            store().setFile('sites', null);
            store().setSelected('sites', false);
          }}
          onOpen={() => onOpenDesigner('qs-step-sites')}
        />
      </div>
    </div>
  );
}
