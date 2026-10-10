import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import toast from 'react-hot-toast';
import { AlertTriangle, Braces, Copy, FileCode2, History, Info, Save, Settings2, Table2, X } from 'lucide-react';
import {
  templatesApi, type RenderOptionsInput, type RevisionDraftInput, type Template, type TemplateRevision,
  type TemplateRevisionWithBody, type TemplateVocabulary, type VarSchema,
} from '@/api/templates.api';
import { Button } from '@/components/common/Button';
import { cn } from '@/utils/cn';
import { CodeEditor } from './CodeEditor';
import { PreviewPanel } from './PreviewPanel';
import { VariablesTable } from './VariablesTable';
import { defaultErrorText, problemText } from './labels';
import { scanTemplate } from './templateScanner';
import {
  addVar, analyseSchema, emptySchema, jsonSchemaShapeError, liveDraft,
  type DefaultDraft, type JsonSchemaShapeError,
} from './varSchemaModel';

/**
 * Write or read one revision: the RouterOS body, its variables as a table,
 * its OS window and notes — and a preview beside it.
 *
 * A DRAFT is saved in place (`PATCH /templates/revisions/:id`). A PUBLISHED
 * revision is shown read-only: it is frozen, and "change it" means a NEW
 * revision, which is what "New revision from this one" starts. A new revision
 * is always a draft; publishing stays the button in the revision list — a
 * human decision on a revision somebody has looked at, never a side effect of
 * saving.
 *
 * ┌─ UNSAVED WORK ───────────────────────────────────────────────────────────┐
 * │ Three nets, because no single one catches every way out of this screen:  │
 * │  - the page asks before any of ITS OWN navigations would close the       │
 * │    editor (another template, "New template", an import's "Open" link,    │
 * │    Back inside the page) — it learns that there is something to lose   │
 * │    through `onDirtyChange`;                                              │
 * │  - `beforeunload` asks before a reload or a closed tab;                  │
 * │  - every edit is also kept in this tab's `sessionStorage`, and offered   │
 * │    back the next time the same revision is opened. That is the net for  │
 * │    what nothing can ask about: the sidebar and other in-app links (the   │
 * │    app's router has no navigation blocker), and an editor that crashed.  │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
interface RevisionEditorProps {
  template: Template;
  /** The revision opened, with its body. null: a new, empty draft. */
  revision: TemplateRevisionWithBody | null;
  canWrite: boolean;
  vocabulary: TemplateVocabulary | null;
  onSaved: (revision: TemplateRevision) => void;
  onClose: () => void;
  /** True while closing the editor would lose something typed here. */
  onDirtyChange?: (dirty: boolean) => void;
}

type Tab = 'body' | 'variables' | 'settings';

const OS_VERSION_RE = /^[0-9]+(\.[0-9]+){0,2}[A-Za-z0-9.+-]*$/; // the server's `osVersion`

function asSchema(v: unknown): VarSchema {
  if (v && typeof v === 'object' && !Array.isArray(v)) {
    const s = v as VarSchema;
    return s.properties ? s : { ...s, properties: {} };
  }
  return emptySchema();
}

/** Only the four knobs `createRevisionSchema.renderOptions` accepts (strict). */
function asRenderOptions(v: unknown): RenderOptionsInput {
  const src = (v && typeof v === 'object' ? v : {}) as Record<string, unknown>;
  const out: RenderOptionsInput = {};
  if (src.throwOnUndefined === true) out.throwOnUndefined = true;
  if (typeof src.trimBlocks === 'boolean') out.trimBlocks = src.trimBlocks;
  if (typeof src.lstripBlocks === 'boolean') out.lstripBlocks = src.lstripBlocks;
  if (typeof src.autoescape === 'boolean') out.autoescape = src.autoescape;
  return out;
}

type SectionSeverity = NonNullable<RevisionDraftInput['sectionSeverity']>;

interface EditorState {
  body: string;
  schema: VarSchema;
  osMin: string;
  osMax: string;
  notes: string;
  renderOptions: RenderOptionsInput;
  /** Not edited on this screen, but CARRIED: a new revision made from this
   *  one keeps the drift weights its source had. */
  sectionSeverity: SectionSeverity;
}

function asSectionSeverity(v: unknown): SectionSeverity {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as SectionSeverity) : {};
}

function initialState(revision: TemplateRevisionWithBody | null): EditorState {
  return {
    body: revision?.body ?? '',
    schema: asSchema(revision?.varSchema),
    osMin: revision?.osMin ?? '',
    osMax: revision?.osMax ?? '',
    notes: revision?.notes ?? '',
    renderOptions: asRenderOptions(revision?.renderOptions),
    sectionSeverity: asSectionSeverity(revision?.sectionSeverity),
  };
}

function serverError(err: unknown): string | null {
  return (err as { response?: { data?: { error?: string } } }).response?.data?.error ?? null;
}

function jsonShapeText(t: TFunction, e: JsonSchemaShapeError): string {
  switch (e.kind) {
    case 'notObject':
      return t('templates.editor.jsonNotObject', { defaultValue: 'The schema must be a JSON object.' });
    case 'propertiesNotObject':
      return t('templates.editor.jsonPropertiesNotObject', {
        defaultValue: '"properties" must be a JSON object listing the variables by name.',
      });
    case 'propNotObject':
      return t('templates.editor.jsonPropNotObject', {
        defaultValue: 'The variable "{{key}}" must be described by a JSON object, such as {"type": "string"}.',
        key: e.key,
      });
    case 'requiredNotList':
    default:
      return t('templates.editor.jsonRequiredNotList', {
        defaultValue: '"required" must be a list of variable names, such as ["wifi_ssid"].',
      });
  }
}

// ── Unsaved work kept in this tab (see the box above) ───────────────────────

const RECOVERY_PREFIX = 'obliwan.templateDraft.v1:';

interface Recovery {
  state: EditorState;
  copyMode: boolean;
  /** ISO timestamp of the last edit kept. */
  at: string;
}

/** One slot per thing being edited: a draft, a new first draft, or a new
 *  revision started from a published one. */
function recoveryKey(templateId: string, revision: TemplateRevisionWithBody | null, copy: boolean): string {
  if (!revision) return `${RECOVERY_PREFIX}${templateId}:new`;
  return `${RECOVERY_PREFIX}${templateId}:${copy ? `from-${revision.id}` : revision.id}`;
}

/** Rebuilt field by field, in `initialState`'s order: what comes back from
 *  storage is input, and a shape the editor cannot hold is no recovery. */
function stateFrom(v: unknown): EditorState | null {
  if (!v || typeof v !== 'object') return null;
  const s = v as Record<string, unknown>;
  if (typeof s.body !== 'string' || jsonSchemaShapeError(s.schema) !== null) return null;
  const str = (x: unknown): string => (typeof x === 'string' ? x : '');
  return {
    body: s.body,
    schema: asSchema(s.schema),
    osMin: str(s.osMin),
    osMax: str(s.osMax),
    notes: str(s.notes),
    renderOptions: asRenderOptions(s.renderOptions),
    sectionSeverity: asSectionSeverity(s.sectionSeverity),
  };
}

function readRecovery(key: string): Recovery | null {
  try {
    const raw = window.sessionStorage.getItem(key);
    if (!raw) return null;
    const v = JSON.parse(raw) as { state?: unknown; copyMode?: unknown; at?: unknown };
    const state = stateFrom(v.state);
    if (!state) return null;
    return { state, copyMode: v.copyMode === true, at: typeof v.at === 'string' ? v.at : '' };
  } catch {
    return null;
  }
}

function writeRecovery(key: string, value: Recovery | null): void {
  try {
    if (value) window.sessionStorage.setItem(key, JSON.stringify(value));
    else window.sessionStorage.removeItem(key);
  } catch {
    // Storage full or blocked: the in-page questions still stand.
  }
}

export function RevisionEditor({
  template, revision, canWrite, vocabulary, onSaved, onClose, onDirtyChange,
}: RevisionEditorProps) {
  const { t } = useTranslation();
  const [state, setState] = useState<EditorState>(() => initialState(revision));
  const [saved, setSaved] = useState<string>(() => JSON.stringify(initialState(revision)));
  const [copyMode, setCopyMode] = useState(false);
  const [tab, setTab] = useState<Tab>('body');
  const [jsonView, setJsonView] = useState(false);
  const [jsonText, setJsonText] = useState('');
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [defaultDrafts, setDefaultDrafts] = useState<Record<string, DefaultDraft>>({});
  const [errorLines, setErrorLines] = useState<number[]>([]);
  const [focusLine, setFocusLine] = useState<{ line: number } | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  // Unsaved work left in this tab the last time this revision was open. A
  // decision (restore / discard) is asked before anything overwrites it.
  const [recovery, setRecovery] = useState<Recovery | null>(() => {
    if (!canWrite || template.isLibrary) return null;
    const copy = revision !== null && revision.status !== 'draft';
    const found = readRecovery(recoveryKey(template.id, revision, copy));
    if (!found) return null;
    return JSON.stringify(found.state) === JSON.stringify(initialState(revision)) ? null : found;
  });

  const isDraft = revision?.status === 'draft';
  const editable = canWrite && !template.isLibrary && (revision === null || isDraft || copyMode);
  const savesAsNew = revision === null || copyMode;
  const edited = JSON.stringify(state) !== saved;
  const dirty = edited || copyMode;
  const storageKey = recoveryKey(template.id, revision, copyMode);

  const scan = useMemo(() => scanTemplate(state.body), [state.body]);
  const analysis = useMemo(
    () => analyseSchema(state.schema, scan.used, vocabulary),
    [state.schema, scan.used, vocabulary],
  );
  const varCount = Object.keys(state.schema.properties ?? {}).length;

  // Defaults typed in the table that do not parse: they hold the save, and
  // count as unsaved work.
  const invalidDefaults: { key: string; text: string }[] = [];
  for (const [key, draft] of Object.entries(defaultDrafts)) {
    const live = liveDraft(draft, state.schema.properties?.[key]);
    if (live?.error) invalidDefaults.push({ key, text: defaultErrorText(t, live.error, key) });
  }
  /** Something typed here would be lost by closing. (Copy mode alone is not:
   *  it can be started again with one click.) */
  const unsaved = editable && (edited || invalidDefaults.length > 0);

  const set = <K extends keyof EditorState>(k: K, v: EditorState[K]) => setState((s) => ({ ...s, [k]: v }));
  const setSchema = (schema: VarSchema) => set('schema', schema);
  /** A schema change that does NOT come from the JSON textarea: the textarea
   *  is refilled with it, or its next keystroke would re-parse the old text
   *  and undo the change. */
  const setSchemaFromOutside = (schema: VarSchema) => {
    setSchema(schema);
    if (jsonView) { setJsonText(JSON.stringify(schema, null, 2)); setJsonError(null); }
  };
  const setDefaultDraft = (key: string, draft: DefaultDraft | null) => setDefaultDrafts((d) => {
    const next = { ...d };
    if (draft) next[key] = draft; else delete next[key];
    return next;
  });

  // The JSON view is (re)filled from the schema each time it is opened.
  useEffect(() => {
    if (jsonView) { setJsonText(JSON.stringify(state.schema, null, 2)); setJsonError(null); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jsonView]);

  // A reload or a closed tab is asked about by the browser.
  useEffect(() => {
    if (!unsaved) return;
    const h = (e: BeforeUnloadEvent) => { e.preventDefault(); };
    window.addEventListener('beforeunload', h);
    return () => window.removeEventListener('beforeunload', h);
  }, [unsaved]);

  // The page asks before its own navigations.
  useEffect(() => { onDirtyChange?.(unsaved); }, [unsaved, onDirtyChange]);
  useEffect(() => () => onDirtyChange?.(false), [onDirtyChange]);

  // Every edit is kept in this tab, written as it happens rather than after a
  // pause: an editor that crashes runs no timer.
  // `saved` is a dependency so that what was typed WHILE a save was in flight
  // is written back after the save cleared the slot.
  useEffect(() => {
    if (recovery || !editable) return;
    writeRecovery(storageKey, edited ? { state, copyMode, at: new Date().toISOString() } : null);
  }, [state, copyMode, edited, editable, recovery, storageKey, saved]);

  const restore = () => {
    if (!recovery) return;
    setState(recovery.state);
    setCopyMode(recovery.copyMode && revision !== null && revision.status !== 'draft');
    setDefaultDrafts({});
    if (jsonView) { setJsonText(JSON.stringify(recovery.state.schema, null, 2)); setJsonError(null); }
    setRecovery(null);
  };
  const discardRecovery = () => {
    if (!recovery) return;
    writeRecovery(recoveryKey(template.id, revision, recovery.copyMode), null);
    setRecovery(null);
  };

  const onJsonText = (text: string) => {
    setJsonText(text);
    let v: unknown;
    try {
      v = JSON.parse(text) as unknown;
    } catch (e) {
      setJsonError(t('templates.editor.jsonInvalid', {
        defaultValue: 'Invalid JSON: {{message}}', message: (e as Error).message,
      }));
      return;
    }
    // Valid JSON is not enough: a variable written `null` or `"Paris"` would
    // crash every view of the schema. Such a text never reaches the state.
    const shape = jsonSchemaShapeError(v);
    if (shape) { setJsonError(jsonShapeText(t, shape)); return; }
    setJsonError(null);
    setSchema(asSchema(v));
  };

  const osError = (v: string) => v !== '' && !OS_VERSION_RE.test(v);

  const blockers: string[] = [];
  if (state.body.trim() === '') blockers.push(t('templates.editor.bodyEmpty', { defaultValue: 'The configuration is empty.' }));
  if (jsonView && jsonError) blockers.push(t('templates.editor.jsonBlocks', { defaultValue: 'The advanced JSON is not valid.' }));
  if (osError(state.osMin) || osError(state.osMax)) {
    blockers.push(t('templates.editor.osInvalid', { defaultValue: 'A RouterOS version must look like 7.21 or 7.15rc2.' }));
  }
  for (const p of analysis.problems) blockers.push(problemText(t, p));
  for (const d of invalidDefaults) blockers.push(d.text);

  const close = () => {
    if (unsaved && !window.confirm(t('templates.editor.discardConfirm', {
      defaultValue: 'Close without saving your changes?',
    }))) return;
    // Discarding on purpose: nothing to offer back next time. A recovery not
    // decided on yet is left alone — closing is not answering it.
    if (editable && !recovery) writeRecovery(storageKey, null);
    onClose();
  };

  const save = async () => {
    if (blockers.length > 0) return;
    setSaving(true);
    setSaveError(null);
    const keptUnder = storageKey; // copy mode ends below, and the key with it
    const payload: RevisionDraftInput = {
      body: state.body,
      varSchema: state.schema,
      osMin: state.osMin === '' ? null : state.osMin,
      osMax: state.osMax === '' ? null : state.osMax,
      notes: state.notes.trim() === '' ? null : state.notes,
      renderOptions: state.renderOptions,
      sectionSeverity: state.sectionSeverity,
    };
    try {
      const out = savesAsNew
        ? await templatesApi.createRevision(template.id, payload)
        : await templatesApi.updateRevision(revision!.id, payload);
      writeRecovery(keptUnder, null);
      setSaved(JSON.stringify(state));
      setCopyMode(false);
      toast.success(savesAsNew
        ? t('templates.editor.createdDraft', { defaultValue: 'Draft revision {{n}} created', n: out.revision })
        : t('templates.editor.savedDraft', { defaultValue: 'Draft saved' }));
      onSaved(out);
    } catch (err) {
      setSaveError(serverError(err) ?? t('templates.editor.saveFailed', { defaultValue: 'The draft could not be saved.' }));
    } finally {
      setSaving(false);
    }
  };

  const declare = (key: string) => {
    setSchemaFromOutside(addVar(state.schema, key, { type: 'string' }));
    setTab('variables');
  };

  const statusLabel = revision === null || copyMode
    ? t('templates.editor.newDraft', { defaultValue: 'New draft' })
    : isDraft
      ? t('templates.editor.draftN', { defaultValue: 'Draft — revision {{n}}', n: revision.revision })
      : t('templates.editor.frozenN', {
        defaultValue: 'Revision {{n}} — {{status}}, read-only', n: revision.revision, status: revision.status,
      });

  const tabBtn = (id: Tab, icon: JSX.Element, label: string, badge?: JSX.Element | null) => (
    <button
      type="button"
      onClick={() => setTab(id)}
      className={cn(
        'inline-flex items-center gap-1.5 border-b-2 px-3 py-2 text-sm',
        tab === id ? 'border-accent text-text-primary' : 'border-transparent text-text-secondary hover:text-text-primary',
      )}
    >
      {icon}{label}{badge}
    </button>
  );

  const warnCount = analysis.problems.length + analysis.undeclared.length;

  return (
    <div className="rounded-lg border border-border bg-bg-secondary">
      {/* Header */}
      <div className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-3">
        <FileCode2 size={18} className="text-accent" />
        <div className="min-w-0 flex-1">
          <h2 className="truncate text-sm font-semibold text-text-primary">{template.name}</h2>
          <p className="text-xs text-text-muted">
            {statusLabel}
            {unsaved && (
              <span className="ml-2 text-status-ssl-warning">
                {t('templates.editor.unsaved', { defaultValue: '· unsaved changes' })}
              </span>
            )}
          </p>
        </div>
        {!editable && canWrite && !template.isLibrary && revision && !isDraft && (
          <Button size="sm" variant="secondary" onClick={() => setCopyMode(true)}>
            <Copy size={14} className="mr-1.5" />
            {t('templates.editor.copyToDraft', { defaultValue: 'New revision from this one' })}
          </Button>
        )}
        {editable && (
          <Button size="sm" onClick={() => void save()} loading={saving} disabled={blockers.length > 0 || !dirty}>
            <Save size={14} className="mr-1.5" />
            {savesAsNew
              ? t('templates.editor.createDraft', { defaultValue: 'Create the draft' })
              : t('templates.editor.saveDraft', { defaultValue: 'Save the draft' })}
          </Button>
        )}
        <Button size="sm" variant="ghost" onClick={close} aria-label={t('common.close')}>
          <X size={16} />
        </Button>
      </div>

      {recovery && (
        <div className="flex flex-wrap items-center gap-2 border-b border-border bg-status-ssl-warning/10 px-4 py-2 text-xs">
          <History size={14} className="shrink-0 text-status-ssl-warning" />
          <span className="min-w-0 flex-1 text-text-primary">
            {t('templates.editor.recoveryFound', {
              defaultValue:
                'Changes to this revision that were never saved were kept in this browser tab ({{when}}). Get them back?',
              when: recovery.at ? new Date(recovery.at).toLocaleString() : '—',
            })}
          </span>
          <Button size="sm" onClick={restore}>
            {t('templates.editor.recoveryRestore', { defaultValue: 'Restore them' })}
          </Button>
          <Button size="sm" variant="secondary" onClick={discardRecovery}>
            {t('templates.editor.recoveryDiscard', { defaultValue: 'Discard them' })}
          </Button>
        </div>
      )}

      {editable && (
        <p className="flex items-start gap-1.5 border-b border-border bg-bg-tertiary/30 px-4 py-2 text-[11px] text-text-muted">
          <Info size={12} className="mt-0.5 shrink-0" />
          {t('templates.editor.neverPublished', {
            defaultValue:
              'Saving never publishes. When the draft is ready, publish it from the revision list: that freezes it for good.',
          })}
        </p>
      )}

      {(blockers.length > 0 || saveError) && editable && (
        <div className="space-y-1 border-b border-border bg-status-down/5 px-4 py-2">
          {saveError && (
            <p className="flex items-start gap-1.5 text-xs text-status-down">
              <AlertTriangle size={13} className="mt-0.5 shrink-0" />
              <span className="whitespace-pre-wrap break-words">{saveError}</span>
            </p>
          )}
          {blockers.map((b) => (
            <p key={b} className="flex items-start gap-1.5 text-xs text-status-down">
              <AlertTriangle size={13} className="mt-0.5 shrink-0" />{b}
            </p>
          ))}
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 p-4 2xl:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)]">
        {/* Left: the revision */}
        <div className="min-w-0">
          <div className="mb-3 flex flex-wrap border-b border-border">
            {tabBtn('body', <FileCode2 size={14} />, t('templates.editor.tabBody', { defaultValue: 'Configuration' }))}
            {tabBtn(
              'variables',
              <Table2 size={14} />,
              t('templates.editor.tabVariables', { defaultValue: 'Variables ({{n}})', n: varCount }),
              warnCount > 0
                ? <span className="ml-1 rounded-full bg-status-ssl-warning/20 px-1.5 text-[10px] text-status-ssl-warning">{warnCount}</span>
                : null,
            )}
            {tabBtn('settings', <Settings2 size={14} />, t('templates.editor.tabSettings', { defaultValue: 'Settings' }))}
          </div>

          {tab === 'body' && (
            <div className="space-y-2">
              <CodeEditor
                value={state.body}
                onChange={editable ? (v) => set('body', v) : undefined}
                readOnly={!editable}
                highlightLines={errorLines}
                focusLine={focusLine}
                ariaLabel={t('templates.editor.bodyAria', { defaultValue: 'RouterOS configuration template' })}
                className="h-[32rem]"
              />
              <p className="text-[11px] text-text-muted">
                {t('templates.editor.bodyHintIndent', {
                  defaultValue:
                    'RouterOS commands with {{open}} variable {{close}} where a value goes. Tab indents (every selected line), Shift+Tab removes the indent; Escape, then Tab, leaves the editor.',
                  open: '{{', close: '}}',
                })}
              </p>
            </div>
          )}

          {tab === 'variables' && (
            <div className="space-y-3">
              {(analysis.undeclared.length > 0 || analysis.unused.length > 0 || analysis.facts.length > 0) && (
                <div className="space-y-2 rounded-md border border-border bg-bg-primary/40 p-3 text-xs">
                  {analysis.undeclared.length > 0 && (
                    <div>
                      <p className="flex items-center gap-1.5 font-medium text-status-ssl-warning">
                        <AlertTriangle size={13} />
                        {t('templates.editor.undeclaredUnchecked', {
                          defaultValue:
                            'Used in the configuration but not declared. Such a name renders only if a value happens to be stored for the router (otherwise the render stops on it), and its value is never typed or checked:',
                        })}
                      </p>
                      <ul className="mt-1 flex flex-wrap gap-1.5">
                        {analysis.undeclared.map((u) => (
                          <li key={u.key} className="inline-flex items-center gap-1 rounded border border-border px-1.5 py-0.5">
                            <button
                              type="button"
                              className="font-mono text-text-primary hover:underline"
                              title={t('templates.editor.showLine', { defaultValue: 'Show line {{n}}', n: u.lines[0] })}
                              onClick={() => { setTab('body'); setFocusLine({ line: u.lines[0] }); }}
                            >
                              {u.key}
                            </button>
                            {/* Not while the JSON text holds an edit that is not
                                in the schema yet: declaring would overwrite it. */}
                            {editable && !(jsonView && jsonError) && (
                              <button
                                type="button"
                                className="text-[10px] text-accent hover:underline"
                                onClick={() => declare(u.key)}
                              >
                                {t('templates.editor.declare', { defaultValue: 'declare' })}
                              </button>
                            )}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {analysis.unused.length > 0 && (
                    <p className="text-text-secondary">
                      {t('templates.editor.unusedTitle', {
                        defaultValue: 'Declared but never used in the configuration: {{list}}',
                        list: analysis.unused.join(', '),
                      })}
                    </p>
                  )}
                  {analysis.facts.length > 0 && (
                    <p className="text-text-muted">
                      {t('templates.editor.factsTitle', {
                        defaultValue: 'Facts supplied by ObliWAN when it renders (not variables): {{list}}',
                        list: analysis.facts.join(', '),
                      })}
                    </p>
                  )}
                </div>
              )}

              <div className="flex items-center justify-end">
                <button
                  type="button"
                  className="inline-flex items-center gap-1.5 text-xs text-accent hover:underline"
                  onClick={() => setJsonView((v) => !v)}
                  disabled={jsonView && jsonError !== null}
                >
                  {jsonView ? <Table2 size={13} /> : <Braces size={13} />}
                  {jsonView
                    ? t('templates.editor.backToTable', { defaultValue: 'Back to the table' })
                    : t('templates.editor.advancedJson', { defaultValue: 'Advanced JSON' })}
                </button>
              </div>

              {jsonView ? (
                <div className="space-y-1">
                  <textarea
                    className="h-[28rem] w-full resize-y rounded-md border border-border bg-bg-primary p-3 font-mono text-xs leading-5 text-text-primary focus:outline-none focus:ring-1 focus:ring-accent"
                    value={jsonText}
                    readOnly={!editable}
                    spellCheck={false}
                    onChange={(e) => onJsonText(e.target.value)}
                    aria-label={t('templates.editor.jsonAria', { defaultValue: 'Variable schema (JSON)' })}
                  />
                  {jsonError && <p className="text-xs text-status-down">{jsonError}</p>}
                </div>
              ) : (
                <VariablesTable
                  schema={state.schema}
                  onChange={editable ? setSchema : undefined}
                  used={scan.used}
                  levels={vocabulary?.levels ?? null}
                  onGoToLine={(line) => { setTab('body'); setFocusLine({ line }); }}
                  defaultDrafts={defaultDrafts}
                  onDefaultDraft={editable ? setDefaultDraft : undefined}
                />
              )}
              {!vocabulary && (
                <p className="text-[11px] text-text-muted">
                  {t('templates.editor.noVocabulary', {
                    defaultValue: 'The list of levels could not be loaded; existing levels are kept as they are.',
                  })}
                </p>
              )}
            </div>
          )}

          {tab === 'settings' && (
            <div className="max-w-xl space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <label className="text-text-secondary">
                  {t('templates.editor.osMin', { defaultValue: 'Minimum RouterOS version' })}
                  <input
                    className={cn(
                      'mt-1 w-full rounded border border-border bg-bg-tertiary px-2 py-1 font-mono text-text-primary',
                      osError(state.osMin) && 'border-status-down',
                    )}
                    value={state.osMin}
                    disabled={!editable}
                    placeholder="7.21"
                    onChange={(e) => set('osMin', e.target.value.trim())}
                  />
                </label>
                <label className="text-text-secondary">
                  {t('templates.editor.osMax', { defaultValue: 'Maximum RouterOS version' })}
                  <input
                    className={cn(
                      'mt-1 w-full rounded border border-border bg-bg-tertiary px-2 py-1 font-mono text-text-primary',
                      osError(state.osMax) && 'border-status-down',
                    )}
                    value={state.osMax}
                    disabled={!editable}
                    placeholder={t('templates.editor.osNone', { defaultValue: 'none' })}
                    onChange={(e) => set('osMax', e.target.value.trim())}
                  />
                </label>
              </div>
              <p className="text-[11px] text-text-muted">
                {t('templates.editor.osHint', {
                  defaultValue: 'A router outside this window never receives this revision. Empty: no limit.',
                })}
              </p>

              <label className="block text-text-secondary">
                {t('templates.editor.notes', { defaultValue: 'Notes for this revision (what changed, why)' })}
                <textarea
                  className="mt-1 w-full rounded border border-border bg-bg-tertiary px-2 py-1 text-text-primary"
                  rows={5}
                  value={state.notes}
                  disabled={!editable}
                  onChange={(e) => set('notes', e.target.value)}
                />
              </label>

              <fieldset className="space-y-1.5">
                <legend className="text-text-secondary">
                  {t('templates.editor.whitespace', { defaultValue: 'Blank lines left by the template tags' })}
                </legend>
                <label className="flex items-center gap-1.5 text-text-secondary">
                  <input
                    type="checkbox"
                    className="h-3.5 w-3.5 accent-accent"
                    checked={state.renderOptions.trimBlocks === true}
                    disabled={!editable}
                    onChange={(e) => set('renderOptions', { ...state.renderOptions, trimBlocks: e.target.checked })}
                  />
                  {t('templates.editor.trimBlocks', {
                    defaultValue: 'Remove the line break after a {% … %} tag (trimBlocks)',
                  })}
                </label>
                <label className="flex items-center gap-1.5 text-text-secondary">
                  <input
                    type="checkbox"
                    className="h-3.5 w-3.5 accent-accent"
                    checked={state.renderOptions.lstripBlocks === true}
                    disabled={!editable}
                    onChange={(e) => set('renderOptions', { ...state.renderOptions, lstripBlocks: e.target.checked })}
                  />
                  {t('templates.editor.lstripBlocks', {
                    defaultValue: 'Remove the spaces before a {% … %} tag (lstripBlocks)',
                  })}
                </label>
              </fieldset>
            </div>
          )}
        </div>

        {/* Right: the preview */}
        <div className="min-w-0 rounded-md border border-border bg-bg-primary/30 p-3">
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-text-muted">
            {t('templates.preview.title', { defaultValue: 'Preview' })}
          </h3>
          <PreviewPanel
            brand={template.brand}
            templateTenantId={template.tenantId ?? null}
            isLibrary={template.isLibrary}
            body={state.body}
            schema={state.schema}
            renderOptions={state.renderOptions}
            sectionSeverity={state.sectionSeverity}
            storedRevisionId={revision && !copyMode ? revision.id : null}
            dirty={dirty}
            canWrite={canWrite && !template.isLibrary}
            used={scan.used}
            deviceRenderFacts={vocabulary?.deviceRenderFacts ?? []}
            renderTimeLevels={vocabulary?.renderTimeLevels ?? []}
            onErrorLines={setErrorLines}
            onGoToLine={(line) => { setTab('body'); setFocusLine({ line }); }}
          />
        </div>
      </div>
    </div>
  );
}
