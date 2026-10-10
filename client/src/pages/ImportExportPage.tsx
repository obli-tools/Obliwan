import { useState, useRef, useCallback, type ReactNode } from 'react';
import { Download, Upload, FileJson, CheckCircle2, PackageOpen, ExternalLink, AlertTriangle } from 'lucide-react';
import type { TFunction } from 'i18next';
import { Button } from '@/components/common/Button';
import apiClient from '@/api/client';
import toast from 'react-hot-toast';
import { useTranslation } from 'react-i18next';

// ── Types ─────────────────────────────────────────────────────────────────────

// The sections this page imports, in the server's order (`SECTIONS` in
// importExport.controller.ts). The server accepts one more,
// `deviceTransports`, which this page deliberately does not send — see the
// box below. The design: every exported entity must be re-importable — no
// orphans.
type Section =
  | 'deviceGroups'
  | 'settings'
  | 'notificationChannels'
  | 'teams'
  | 'sites'
  | 'devices';

type ConflictStrategy = 'update' | 'generateNew' | 'ignore';

// ┌─ THE FLEET SECTIONS: OPT-IN ON IMPORT, NEVER EXPORTED HERE ──────────────┐
// │ The server has exported and imported sites, devices and their channels   │
// │ for a while. A bundle carrying them comes from `GET /api/import-export/  │
// │ export` or a hand-edited file — never from this page's own export, which │
// │ stays on its four sections: `deviceTransports` carries each channel's    │
// │ host and account name, and this button produces a file that travels by   │
// │ mail and chat. Templates, revisions and variables are not in the         │
// │ server's bundle at all yet.                                              │
// │                                                                          │
// │ `sites` and `devices` are offered UNTICKED (OPT_IN_SECTIONS), so a full  │
// │ bundle imports what it did before this page knew them unless the         │
// │ operator asks for more. They are here because the importer's per-device  │
// │ warnings (a concentrator the bundle names that cannot be referenced      │
// │ here) need a screen to appear on. What ticking `devices` costs is said   │
// │ beside its switch: on "Update existing" the importer overwrites the      │
// │ serial, system identity and PPP username of a device already here —      │
// │ emptying any the file lacks, which `compareIdentity` then scores         │
// │ `unrecorded`, so the binding check stops looking at it. And a PPP        │
// │ username or (brand, serial) another device holds violates a unique       │
// │ index and rolls back the WHOLE import, core sections included.           │
// │                                                                          │
// │ `deviceTransports` is NOT sent from this page. For a (device, transport) │
// │ pair that already exists the importer overwrites host, port and account  │
// │ name and KEEPS the stored secret — whatever the conflict strategy, since │
// │ that loop never reads it — so the next dial presents the device's vault  │
// │ credential to whatever host the file names. Offering that is a decision  │
// │ for a human once the server side is settled; until then the page says    │
// │ the file carries channels, and does not send them.                       │
// └──────────────────────────────────────────────────────────────────────────┘
const EXPORT_SECTIONS: Section[] = [
  'deviceGroups',
  'settings',
  'notificationChannels',
  'teams',
];

/** Offered on import, never ticked for the operator — see the box above. */
const OPT_IN_SECTIONS: Section[] = ['sites', 'devices'];

const IMPORT_SECTIONS: Section[] = [...EXPORT_SECTIONS, ...OPT_IN_SECTIONS];

/** One label per section, for both selectors and the result summary. */
function sectionLabels(t: TFunction): Record<Section, string> {
  return {
    deviceGroups:         t('importExport.deviceGroups'),
    settings:             t('importExport.settingsSection'),
    notificationChannels: t('importExport.notificationChannels'),
    teams:                t('importExport.teams'),
    sites:                t('importExport.sites'),
    devices:              t('importExport.devices'),
  };
}

/**
 * What the importer answers per section (`SectionResult` in
 * importExport.controller.ts). `warnings` is present only when there is one:
 * a notification channel imported disabled because its SMTP relay belongs to
 * nobody here, a device whose concentrator the bundle names but this
 * instance cannot resolve (only when the operator ticked `devices`). The
 * counts alone say "created" or "updated" for both.
 */
interface SectionResult {
  created: number;
  updated: number;
  skipped: number;
  warnings?: string[];
}

/** The warnings of one section, read defensively: the server owns the shape. */
function warningsOf(r: SectionResult | undefined): string[] {
  return Array.isArray(r?.warnings) ? r.warnings.filter((w): w is string => typeof w === 'string') : [];
}

// ── Sub-components ────────────────────────────────────────────────────────────

function Toggle({
  checked,
  indeterminate = false,
  onChange,
}: {
  checked:        boolean;
  indeterminate?: boolean;
  onChange:       (v: boolean) => void;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      className={[
        'relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent',
        'transition-colors duration-200 focus:outline-none focus-visible:ring-2',
        'focus-visible:ring-accent focus-visible:ring-offset-2',
        checked
          ? 'bg-accent'
          : indeterminate
            ? 'bg-accent/40'
            : 'bg-bg-tertiary border border-border',
      ].join(' ')}
    >
      <span
        className={[
          'pointer-events-none inline-block h-4 w-4 transform rounded-full',
          'bg-white shadow-lg ring-0 transition-transform duration-200',
          checked ? 'translate-x-4' : 'translate-x-0',
        ].join(' ')}
      />
    </button>
  );
}

function SectionSelector({
  sections,
  enabled,
  onToggle,
  onToggleAll,
  descriptions = {},
  extra,
}: {
  sections:      Section[];
  enabled:       Set<Section>;
  onToggle:      (s: Section) => void;
  onToggleAll:   (on: boolean) => void;
  descriptions?: Partial<Record<Section, string>>;
  extra?:        ReactNode;
}) {
  const { t } = useTranslation();

  const SECTION_LABELS = sectionLabels(t);

  const allOn  = sections.length > 0 && sections.every(s => enabled.has(s));
  const someOn = sections.some(s => enabled.has(s));

  return (
    <div className="space-y-1">
      {/* All toggle */}
      <div className="flex items-center justify-between py-2 border-b border-border">
        <span className="text-sm font-medium text-text-primary">{t('importExport.all')}</span>
        <Toggle
          checked={allOn}
          indeterminate={!allOn && someOn}
          onChange={onToggleAll}
        />
      </div>

      {/* Individual sections */}
      {sections.map((s) => (
        <div key={s} className="py-1.5">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-sm text-text-secondary">{SECTION_LABELS[s]}</span>
              {descriptions[s] && (
                <p className="text-[11px] text-text-muted mt-0.5">{descriptions[s]}</p>
              )}
            </div>
            <Toggle checked={enabled.has(s)} onChange={() => onToggle(s)} />
          </div>
        </div>
      ))}

      {/* Extra content (sub-options) */}
      {extra}
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export function ImportExportPage() {
  const { t } = useTranslation();

  const SECTION_LABELS = sectionLabels(t);

  // Said beside the switch the operator ticks: what "Update existing" does to
  // a device that is ALREADY here (its identity columns rewritten from the
  // file) and what a created one lacks are neither of them obvious.
  const SECTION_DESCRIPTIONS: Partial<Record<Section, string>> = {
    devices: t('importExport.devicesDesc'),
  };

  const CONFLICT_OPTIONS: { value: ConflictStrategy; label: string; description: string }[] = [
    {
      value:       'update',
      label:       t('importExport.conflictUpdate'),
      description: t('importExport.conflictUpdateDesc'),
    },
    {
      value:       'generateNew',
      label:       t('importExport.conflictCopy'),
      description: t('importExport.conflictCopyDesc'),
    },
    {
      value:       'ignore',
      label:       t('importExport.conflictSkip'),
      description: t('importExport.conflictSkipDesc'),
    },
  ];

  // ── Export state ──
  const [exportSections,       setExportSections]       = useState<Set<Section>>(new Set(EXPORT_SECTIONS));
  const [exporting,            setExporting]            = useState(false);

  // ── Import state ──
  const [importFile,       setImportFile]       = useState<File | null>(null);
  const [importData,       setImportData]       = useState<Record<string, unknown> | null>(null);
  const [availableSections,setAvailableSections]= useState<Section[]>([]);
  const [importSections,   setImportSections]   = useState<Set<Section>>(new Set());
  const [conflictStrategy, setConflictStrategy] = useState<ConflictStrategy>('update');
  const [importing,        setImporting]        = useState(false);
  const [importResults,    setImportResults]    = useState<Record<string, SectionResult> | null>(null);
  // The file carries device channels this page will not send (box above).
  const [carriesTransports, setCarriesTransports] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const [isDragging, setIsDragging] = useState(false);

  // ── Export handlers ──────────────────────────────────────────────────────

  const toggleExportSection = useCallback((s: Section) => {
    setExportSections(prev => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s); else next.add(s);
      return next;
    });
  }, []);

  const toggleAllExport = useCallback((on: boolean) => {
    setExportSections(on ? new Set(EXPORT_SECTIONS) : new Set());
  }, []);

  const handleExport = useCallback(async () => {
    if (exportSections.size === 0) {
      toast.error(t('importExport.selectSection'));
      return;
    }
    setExporting(true);
    try {
      const sections = [...exportSections].join(',');
      const res = await apiClient.get(
        `/import-export/export?sections=${encodeURIComponent(sections)}`,
        { responseType: 'blob' },
      );
      const url = URL.createObjectURL(res.data as Blob);
      const a   = document.createElement('a');
      a.href     = url;
      a.download = `obliwan-export-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success(t('importExport.exported'));
    } catch {
      toast.error(t('importExport.failedExport'));
    } finally {
      setExporting(false);
    }
  }, [exportSections, t]);

  // ── Import handlers ──────────────────────────────────────────────────────

  /** Shared file-processing logic used by both click-select and drag-drop */
  const processFile = useCallback((file: File) => {
    setImportFile(file);
    setImportResults(null);
    setCarriesTransports(false);

    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        const json = JSON.parse(ev.target?.result as string) as Record<string, unknown>;
        if (typeof json !== 'object' || Array.isArray(json)) throw new Error('Not an object');

        const available = IMPORT_SECTIONS.filter(s => Array.isArray(json[s]));
        setAvailableSections(available);
        // The core sections a file carries are ticked, as they always were; the
        // fleet ones wait for the operator (OPT_IN_SECTIONS, box above).
        setImportSections(new Set(available.filter(s => !OPT_IN_SECTIONS.includes(s))));
        const transports = json.deviceTransports;
        setCarriesTransports(Array.isArray(transports) && transports.length > 0);
        setImportData(json);
      } catch {
        toast.error('Invalid export file — expected ObliWAN JSON export');
        setImportFile(null);
        setImportData(null);
        setAvailableSections([]);
        setImportSections(new Set());
        setCarriesTransports(false);
        // Reset file input so the same file can be re-selected after error
        if (fileInputRef.current) fileInputRef.current.value = '';
      }
    };
    reader.readAsText(file);
  }, []);

  const handleFileChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    processFile(file);
  }, [processFile]);

  const handleDragOver = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (!file) return;
    if (!file.name.endsWith('.json') && file.type !== 'application/json') {
      toast.error('Please drop a .json file');
      return;
    }
    processFile(file);
  }, [processFile]);

  const toggleImportSection = useCallback((s: Section) => {
    setImportSections(prev => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s); else next.add(s);
      return next;
    });
  }, []);

  const toggleAllImport = useCallback((on: boolean) => {
    setImportSections(on ? new Set(availableSections) : new Set());
  }, [availableSections]);

  const handleImport = useCallback(async () => {
    if (!importData) {
      toast.error(t('importExport.noFile'));
      return;
    }
    if (importSections.size === 0) {
      toast.error(t('importExport.noSections'));
      return;
    }
    setImporting(true);
    setImportResults(null);
    try {
      const res = await apiClient.post('/import-export/import', {
        sections:         [...importSections],
        data:             importData,
        conflictStrategy,
      });
      const results = (res.data?.data ?? {}) as Record<string, SectionResult>;
      setImportResults(results);
      // A warning is the server saying "done, but not as the bundle said" —
      // a success toast over it would be read as the whole answer.
      if (Object.values(results).some(r => warningsOf(r).length > 0)) {
        toast(t('importExport.importWarnings'), {
          icon: <AlertTriangle size={16} className="shrink-0 text-yellow-400" />,
        });
      } else {
        toast.success(t('importExport.importOk'));
      }
    } catch (err: any) {
      toast.error(err?.response?.data?.error ?? t('importExport.failedImport'));
    } finally {
      setImporting(false);
    }
  }, [importData, importSections, conflictStrategy, t]);

  // ── Render ───────────────────────────────────────────────────────────────

  return (
    <div className="min-w-0 px-4 py-8">

      {/* Page header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <PackageOpen size={22} className="text-accent" />
          <h1 className="text-2xl font-semibold text-text-primary">{t('importExport.title')}</h1>
        </div>
        <p className="text-sm text-text-muted">
          {t('importExport.description')}
        </p>
        <a
          href="/obliwan-import-example.json"
          download="obliwan-import-example.json"
          className="mt-2 inline-flex items-center gap-1.5 text-xs text-accent hover:underline"
        >
          <ExternalLink size={11} />
          {t('importExport.downloadTemplate')}
        </a>
      </div>

      {/* ── Export card ── */}
      <div className="mb-6 rounded-xl border border-border bg-bg-secondary p-6">
        <div className="flex items-center gap-2 mb-1">
          <Download size={15} className="text-accent" />
          <h2 className="text-base font-semibold text-text-primary">{t('importExport.exportTitle')}</h2>
        </div>
        <p className="text-xs text-text-muted mb-5">
          {t('importExport.exportDesc')}
        </p>

        <SectionSelector
          sections={EXPORT_SECTIONS}
          enabled={exportSections}
          onToggle={toggleExportSection}
          onToggleAll={toggleAllExport}
          descriptions={SECTION_DESCRIPTIONS}
        />

        <div className="mt-5 flex justify-end">
          <Button
            onClick={handleExport}
            loading={exporting}
            disabled={exportSections.size === 0}
          >
            <Download size={14} className="mr-1.5" />
            {t('importExport.downloadJson')}
          </Button>
        </div>
      </div>

      {/* ── Import card ── */}
      <div className="rounded-xl border border-border bg-bg-secondary p-6">
        <div className="flex items-center gap-2 mb-1">
          <Upload size={15} className="text-accent" />
          <h2 className="text-base font-semibold text-text-primary">{t('importExport.importTitle')}</h2>
        </div>
        <p className="text-xs text-text-muted mb-5">
          {t('importExport.importDesc')}
        </p>

        {/* File drop zone */}
        <div
          onClick={() => fileInputRef.current?.click()}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          className={[
            'mb-5 flex cursor-pointer flex-col items-center gap-2 rounded-lg border-2 border-dashed',
            'px-6 py-6 transition-colors',
            isDragging
              ? 'border-accent bg-accent/10 scale-[1.01]'
              : importFile
                ? 'border-accent/50 bg-accent/5'
                : 'border-border bg-bg-tertiary hover:border-accent hover:bg-accent/5',
          ].join(' ')}
        >
          <FileJson size={28} className={importFile || isDragging ? 'text-accent' : 'text-text-muted'} />
          <span className="text-sm text-text-secondary text-center">
            {isDragging
              ? t('importExport.dropzoneActive')
              : importFile
                ? importFile.name
                : t('importExport.dropzone')}
          </span>
          {importFile && (
            <span className="text-xs text-text-muted">
              {(importFile.size / 1024).toFixed(1)} KB
              {availableSections.length > 0 && (
                <> · {t('importExport.sectionsFound', { count: availableSections.length })}</>
              )}
            </span>
          )}
          <input
            ref={fileInputRef}
            type="file"
            accept=".json"
            className="hidden"
            onChange={handleFileChange}
          />
        </div>

        {/* Channels in the file are named, not silently dropped: an operator
            restoring a fleet would otherwise believe they came back. */}
        {importData && carriesTransports && (
          <div className="mb-5 flex items-start gap-2 rounded-md border border-yellow-400/30 bg-yellow-400/5 p-3">
            <AlertTriangle size={14} className="mt-0.5 shrink-0 text-yellow-400" aria-hidden="true" />
            <p className="text-xs text-text-secondary">{t('importExport.deviceTransportsNotImported')}</p>
          </div>
        )}

        {/* Options shown only once a file is loaded */}
        {importData && availableSections.length > 0 && (
          <>
            {/* Section selector */}
            <div className="mb-5">
              <p className="text-xs font-medium text-text-muted uppercase tracking-wider mb-3">
                {t('importExport.sectionsToImport')}
              </p>
              <SectionSelector
                sections={availableSections}
                enabled={importSections}
                onToggle={toggleImportSection}
                onToggleAll={toggleAllImport}
                descriptions={SECTION_DESCRIPTIONS}
              />
            </div>

            {/* Conflict strategy */}
            <div className="mb-5">
              <p className="text-xs font-medium text-text-muted uppercase tracking-wider mb-3">
                {t('importExport.conflictLabel')}
              </p>
              <div className="space-y-2">
                {CONFLICT_OPTIONS.map(opt => (
                  <label
                    key={opt.value}
                    className={[
                      'flex items-start gap-3 rounded-lg border p-3 cursor-pointer transition-colors',
                      conflictStrategy === opt.value
                        ? 'border-accent bg-accent/5'
                        : 'border-border hover:border-accent/40',
                    ].join(' ')}
                  >
                    <input
                      type="radio"
                      name="conflictStrategy"
                      value={opt.value}
                      checked={conflictStrategy === opt.value}
                      onChange={() => setConflictStrategy(opt.value)}
                      className="mt-0.5 accent-accent"
                    />
                    <div>
                      <div className="text-sm font-medium text-text-primary">{opt.label}</div>
                      <div className="text-xs text-text-muted mt-0.5">{opt.description}</div>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            <div className="flex justify-end">
              <Button
                onClick={handleImport}
                loading={importing}
                disabled={importSections.size === 0}
              >
                <Upload size={14} className="mr-1.5" />
                {t('importExport.importBtn')}
              </Button>
            </div>
          </>
        )}

        {/* No sections found */}
        {importData && availableSections.length === 0 && (
          <p className="text-sm text-text-muted text-center py-4">
            {t('importExport.noImportable')}
          </p>
        )}

        {/* Results summary */}
        {/* The server's warnings are English sentences built server-side and
            drawn verbatim — the same unlocalised gap as every other refusal
            this product's server words. They are shown under the section
            that produced them, because "3 created" is also what a device
            imported without its concentrator looks like. */}
        {importResults && (() => {
          const anyWarning = Object.values(importResults).some(r => warningsOf(r).length > 0);
          return (
            <div className="mt-5 rounded-lg border border-border bg-bg-tertiary p-4">
              <div className={['flex items-center gap-2 mb-3', anyWarning ? 'text-yellow-400' : 'text-green-400'].join(' ')}>
                {anyWarning ? <AlertTriangle size={15} /> : <CheckCircle2 size={15} />}
                <span className="text-sm font-medium">
                  {anyWarning ? t('importExport.importWarnings') : t('importExport.importOk')}
                </span>
              </div>
              <div className="space-y-1.5">
                {Object.entries(importResults).map(([section, r]) => {
                  const warnings = warningsOf(r);
                  return (
                    <div key={section} className="text-xs">
                      <div className="flex items-center justify-between">
                        <span className="text-text-secondary">
                          {SECTION_LABELS[section as Section] ?? section}
                        </span>
                        <span className="text-text-muted tabular-nums">
                          <span className="text-green-400">{t('importExport.statCreated', { count: r.created })}</span>
                          {' · '}
                          <span className="text-blue-400">{t('importExport.statUpdated', { count: r.updated })}</span>
                          {r.skipped > 0 && (
                            <>{' · '}<span className="text-yellow-400">{t('importExport.statSkipped', { count: r.skipped })}</span></>
                          )}
                        </span>
                      </div>
                      {warnings.length > 0 && (
                        <ul className="mt-1 space-y-1 border-l-2 border-yellow-400/40 pl-2">
                          {warnings.map((w, i) => (
                            <li key={i} className="flex items-start gap-1.5 break-words text-yellow-400">
                              <AlertTriangle size={11} className="mt-0.5 shrink-0" aria-hidden="true" />
                              <span>{w}</span>
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })()}
      </div>
    </div>
  );
}
