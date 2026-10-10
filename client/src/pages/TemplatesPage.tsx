import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import toast from 'react-hot-toast';
import {
  Layers, Plus, RotateCw, Search, Lock, FileText, CheckCircle2, FileUp, PencilLine, Eye,
  Trash2, Archive, ArchiveRestore, Ban,
} from 'lucide-react';
import { CAPABILITIES, DEVICE_BRANDS, type DeviceBrand } from '@obliwan/shared';
import {
  templatesApi, type Template, type TemplateRevision, type TemplateRevisionWithBody, type TemplateVocabulary,
} from '@/api/templates.api';
import { useAuthStore } from '@/store/authStore';
import { Button } from '@/components/common/Button';
import { Input } from '@/components/common/Input';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { EditorErrorBoundary } from '@/components/templates/EditorErrorBoundary';
import { RevisionDeprecateDialog } from '@/components/templates/RevisionDeprecateDialog';
import { RevisionEditor } from '@/components/templates/RevisionEditor';
import { TemplateImportDialog } from '@/components/templates/TemplateImportDialog';
import { GodViewMarker, TenantBadge } from '@/components/common/TenantBadge';
import { GodViewTenantFilter } from '@/components/common/GodViewTenantFilter';

/**
 * Templates and their revisions.
 *
 * ┌─ THE TWO REFUSALS THIS SCREEN MUST MAKE VISIBLE ─────────────────────────┐
 * │ 1. A PUBLISHED REVISION IS FROZEN. Publishing is offered once and then    │
 * │    the button is gone — not disabled with a tooltip, gone. A plan pins    │
 * │    itself to a revision, and a pin that can be edited afterwards is not   │
 * │    a pin: the plan an operator approved in March would silently mean      │
 * │    something else in June. The editor opens a published revision          │
 * │    read-only; changing it means a new draft revision.                     │
 * │ 2. LIBRARY TEMPLATES ARE READ-ONLY. They belong to no tenant (`isLibrary`)│
 * │    and are shared by every one of them. The screen shows the padlock      │
 * │    rather than letting a save fail server-side, because a form that       │
 * │    accepts input it cannot save is a form that wastes somebody's work.    │
 * └──────────────────────────────────────────────────────────────────────────┘
 *
 * Importing and editing write DRAFTS only. Publishing stays the button in the
 * revision list, one human click per revision.
 *
 * The URL carries the selection — `?template=<id>&revision=<id>` opens that
 * revision in the editor — so the import's "open the draft" links, a reload
 * and a link pasted to a colleague all land on the same screen.
 *
 * While the editor holds unsaved changes, every way THIS page can close or
 * replace it asks first: its own buttons (`confirmLeave`), the import's
 * "Open" links, and a URL change it did not make itself (Back / Forward) —
 * declining puts the URL back. Leaving the page altogether (the sidebar)
 * cannot be asked about: the app's `BrowserRouter` has no navigation blocker.
 * That path is covered by the editor keeping each edit in this tab's
 * `sessionStorage` and offering it back on reopening (`RevisionEditor`).
 *
 * Delete is for DRAFTS ONLY. "Delete" is offered on a template none of whose
 * revisions ever left draft, and on a draft revision that is not the
 * template's only one (deleting that one is the template's delete). A
 * template whose revisions produced renders that produced plans is the answer
 * to "why is this line on this router" (`config_renders.revision_id` is ON
 * DELETE RESTRICT), so it is archived — a status change, offered on every
 * tenant template, deletable or not. What the list cannot see (a render, an
 * assignment, a rollout pointing at a draft) the server refuses with a 409
 * whose sentence is shown as is.
 *
 * DEPRECATE is the gesture for a PUBLISHED revision that was superseded: the
 * provisioning bench offers every published revision, so a superseded one
 * stays on its list until it is deprecated. It is offered on each published
 * revision of a tenant template, and right after a publication for the newest
 * older published revision of the same template (`RevisionDeprecateDialog`,
 * which says what it changes). There is no "reactivate": the server's status
 * route accepts `quarantined` and `deprecated` only.
 */
/** The part of the URL this page reads, as one comparable string. */
function locationKey(template: string | null, revision: string | null): string {
  return `${template ?? ''}|${revision ?? ''}`;
}

export function TemplatesPage() {
  const { t } = useTranslation();
  const { hasCapability } = useAuthStore();
  const canWrite = hasCapability(CAPABILITIES.TEMPLATE_WRITE);
  const [searchParams, setSearchParams] = useSearchParams();
  const templateParam = searchParams.get('template');
  const revisionParam = searchParams.get('revision');

  const [templates, setTemplates] = useState<Template[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<Template | null>(null);
  const [revisions, setRevisions] = useState<TemplateRevision[] | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [showImport, setShowImport] = useState(false);
  const [saving, setSaving] = useState(false);
  /** The delete / archive in flight (`template:<id>`, `revision:<id>`,
   *  `archive:<id>`), so its button shows a spinner and cannot be sent twice. */
  const [busy, setBusy] = useState<string | null>(null);
  /** The published revision the deprecate dialog is about; `supersededBy` is
   *  set when it is offered right after that newer revision was published. */
  const [deprecating, setDeprecating] = useState<{
    revision: TemplateRevision; supersededBy: TemplateRevision | null;
  } | null>(null);
  const [form, setForm] = useState<{ name: string; description: string; brand: DeviceBrand }>({
    name: '', description: '', brand: 'mikrotik',
  });
  const [vocabulary, setVocabulary] = useState<TemplateVocabulary | null>(null);
  /** The revision open in the editor; `'new'` is an empty first draft. */
  const [editing, setEditing] = useState<TemplateRevisionWithBody | 'new' | null>(null);
  /** The template a `'new'` draft was started on. */
  const [newFor, setNewFor] = useState<string | null>(null);
  /** True while the open editor would lose something if it closed. */
  const [editorUnsaved, setEditorUnsaved] = useState(false);
  const unsavedRef = useRef(false);
  unsavedRef.current = editorUnsaved;
  /** Where a navigation this page makes itself is going (it already asked).
   *  A destination, not a flag: a navigation to the URL already shown changes
   *  nothing, and a flag left set by it would let the next Back through
   *  unasked. */
  const ownNavRef = useRef<string | null>(null);
  /** Set while a refused URL change is being put back. */
  const revertRef = useRef(false);
  /** The URL the screen currently shows. */
  const shownRef = useRef<{ template: string | null; revision: string | null }>({
    template: templateParam, revision: revisionParam,
  });

  const leaveText = () => t('templates.leaveConfirm', {
    defaultValue:
      'The open revision has changes that are not saved. Leave the editor? This browser tab keeps them and offers them back when the revision is reopened.',
  });
  /** Asked before anything that would close or replace the editor. */
  const confirmLeave = (): boolean => !unsavedRef.current || window.confirm(leaveText());
  /** This page's own URL changes: asked about by the caller, not again. */
  const go = (params: Record<string, string>) => {
    const target = locationKey(params.template ?? null, params.revision ?? null);
    const here = new URLSearchParams(window.location.search);
    if (target !== locationKey(here.get('template'), here.get('revision'))) ownNavRef.current = target;
    setSearchParams(params);
  };

  const load = async () => {
    setLoading(true);
    try {
      setTemplates(await templatesApi.list({ includeLibrary: true }));
    } catch {
      toast.error(t('templates.loadFailed', { defaultValue: 'Could not load templates' }));
    } finally {
      setLoading(false);
    }
  };

  /** Only the LATEST request may write the list. Without this, selecting A
   *  (slow) then B let A's reply land last and stand as B's revisions, and the
   *  Delete button and its confirm count are computed from that list. */
  const revisionsSeqRef = useRef(0);
  const loadRevisions = async (templateId: string) => {
    const seq = ++revisionsSeqRef.current;
    try {
      const rows = await templatesApi.revisions(templateId);
      if (seq === revisionsSeqRef.current) setRevisions(rows);
    } catch {
      if (seq === revisionsSeqRef.current) setRevisions([]);
    }
  };

  useEffect(() => { void load(); }, []);
  useEffect(() => {
    templatesApi.vocabulary().then(setVocabulary).catch(() => setVocabulary(null));
  }, []);

  // A URL change this page did not make (Back, Forward, a link elsewhere in
  // the app) would close or replace an editor holding unsaved changes: ask,
  // and on "no" put the URL back. Declared BEFORE the two effects that follow
  // the URL, which skip the refused change (`revertRef`).
  useEffect(() => {
    const own = ownNavRef.current === locationKey(templateParam, revisionParam);
    if (own) ownNavRef.current = null;
    const shown = shownRef.current;
    if (shown.template === templateParam && shown.revision === revisionParam) {
      revertRef.current = false;
      return;
    }
    if (!own && unsavedRef.current && !window.confirm(leaveText())) {
      revertRef.current = true;
      const back: Record<string, string> = {};
      if (shown.template) back.template = shown.template;
      if (shown.revision) back.revision = shown.revision;
      setSearchParams(back, { replace: true });
      return;
    }
    revertRef.current = false;
    shownRef.current = { template: templateParam, revision: revisionParam };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [templateParam, revisionParam]);

  // The URL decides which template is selected.
  useEffect(() => {
    if (revertRef.current) return;
    if (!templateParam) { setSelected(null); return; }
    const found = templates.find((x) => x.id === templateParam) ?? null;
    setSelected((prev) => (prev?.id === found?.id ? prev : found));
  }, [templateParam, templates]);

  useEffect(() => {
    // A deprecate dialog belongs to the template it was opened on. Left set, it
    // would keep every Deprecate button disabled on the next template and come
    // back, with a stale revision, on returning to this one.
    setDeprecating(null);
    if (!selected) {
      // Retire any reply still in flight, so it cannot land after this.
      revisionsSeqRef.current++;
      setRevisions(null);
      return;
    }
    setRevisions(null);
    void loadRevisions(selected.id);
  }, [selected?.id]);

  // …and which revision is open in the editor.
  useEffect(() => {
    if (revertRef.current) return;
    if (!revisionParam) {
      setEditing((prev) => (prev === 'new' ? prev : null));
      return;
    }
    let alive = true;
    templatesApi.revision(revisionParam)
      .then((rev) => { if (alive) setEditing(rev); })
      .catch(() => {
        if (!alive) return;
        toast.error(t('templates.revisionNotFound', { defaultValue: 'This revision could not be opened.' }));
        go(templateParam ? { template: templateParam } : {});
      });
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [revisionParam]);

  const selectTemplate = (tpl: Template) => {
    if (!confirmLeave()) return;
    setEditing(null);
    // Clicking the template already selected changes no URL: re-read its
    // revisions, which is what the click is for.
    if (tpl.id === selected?.id) void loadRevisions(tpl.id);
    go({ template: tpl.id });
  };

  const openRevision = (rev: TemplateRevision) => {
    if (!confirmLeave()) return;
    go({ template: rev.templateId, revision: rev.id });
  };

  /** The editor asked already (its own close button), so this does not. The
   *  list it returns to is re-read: the editor may have saved a draft. */
  const closeEditor = () => {
    setEditing(null);
    go(selected ? { template: selected.id } : {});
    if (selected) void loadRevisions(selected.id);
  };

  const onSaved = (rev: TemplateRevision) => {
    void loadRevisions(rev.templateId);
    if (rev.id !== revisionParam) go({ template: rev.templateId, revision: rev.id });
  };

  /** Templates AND the open template's revisions: an import or another
   *  operator may have added a draft to the template already selected, and
   *  its Publish button lives in that list. */
  const refresh = () => {
    void load();
    if (selected) void loadRevisions(selected.id);
  };

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return templates;
    return templates.filter((x) =>
      x.name.toLowerCase().includes(q) || (x.description ?? '').toLowerCase().includes(q));
  }, [templates, search]);

  const handleCreate = async (e: FormEvent) => {
    e.preventDefault();
    // The new template is selected once created, which closes the editor.
    if (!confirmLeave()) return;
    setSaving(true);
    try {
      const created = await templatesApi.create({
        name: form.name,
        description: form.description || null,
        brand: form.brand,
      });
      toast.success(t('templates.created', { defaultValue: 'Template created' }));
      setShowCreate(false);
      setForm({ name: '', description: '', brand: 'mikrotik' });
      setTemplates((prev) => [...prev, created].sort((a, b) => a.name.localeCompare(b.name)));
      setEditing(null);
      go({ template: created.id });
    } catch (err) {
      const m = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(m ?? t('templates.createFailed', { defaultValue: 'Could not create the template' }));
    } finally {
      setSaving(false);
    }
  };

  const handlePublish = async (rev: TemplateRevision) => {
    // Asked in plain words, because it cannot be undone and the consequence is
    // not obvious from a button labelled "publish".
    const ok = window.confirm(t('templates.publishConfirm', {
      defaultValue:
        'Publishing revision {{n}} freezes it for good. Plans will pin themselves to it and it '
        + 'can never be edited again — a change means a new revision. Continue?',
      n: rev.revision,
    }));
    if (!ok) return;
    // Read before the reply: the list the click was made on.
    const before = revisions ?? [];
    try {
      const updated = await templatesApi.publish(rev.id);
      // Merged, not replaced: the publish reply does not carry the list-only
      // `pinnedAssignments`.
      setRevisions((prev) => (prev ?? []).map((r) => (r.id === updated.id ? { ...r, ...updated } : r)));
      toast.success(t('templates.published', { defaultValue: 'Revision published and frozen' }));
      // The bench offers every published revision: offer to retire the newest
      // OLDER published one of this template, in one click. Only while this
      // template is still the one on screen, and never one numbered above the
      // revision just published (an older draft published late supersedes
      // nothing).
      const previous = before
        .filter((r) => r.status === 'published' && r.id !== updated.id
          && r.templateId === updated.templateId && r.revision < updated.revision)
        .sort((a, b) => b.revision - a.revision)[0];
      if (previous && shownRef.current.template === updated.templateId) {
        setDeprecating({ revision: previous, supersededBy: updated });
      }
    } catch (err) {
      const m = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(m ?? t('templates.publishFailed', { defaultValue: 'Could not publish' }));
    }
  };

  /** Offered only when every revision is a draft. The server re-checks under a
   *  lock and also refuses what this list cannot see (a render, an assignment,
   *  a rollout pointing at a draft): its sentence is shown as is, and the
   *  revisions are re-read in case one was published meanwhile. */
  const handleDeleteTemplate = async (tpl: Template, drafts: number) => {
    const ok = window.confirm(t('templates.deleteConfirm', {
      defaultValue:
        'Delete the template "{{name}}" and its {{n}} draft revision(s)? None of them was ever '
        + 'published. This cannot be undone.',
      name: tpl.name,
      n: drafts,
    }));
    if (!ok) return;
    setBusy(`template:${tpl.id}`);
    try {
      const result = await templatesApi.remove(tpl.id);
      setTemplates((prev) => prev.filter((x) => x.id !== tpl.id));
      setRevisions(null);
      setEditing(null);
      go({});
      // A promoted baseline proposal went back to review: that changes another
      // screen, so it is said rather than left to be discovered there.
      toast.success(result.extrapolationProposalsReopened > 0
        ? t('templates.deletedReopened', {
          defaultValue:
            'Template deleted. The extrapolator proposal it came from is back to « proposed ».',
        })
        : result.baselineDraftsUnpromoted > 0
          ? t('templates.deletedUnpromoted', {
            defaultValue:
              'Template deleted. The baseline proposal it was promoted from is back in the baseline review.',
          })
          : t('templates.deleted', { defaultValue: 'Template deleted' }));
    } catch (err) {
      const m = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(m ?? t('templates.deleteFailed', { defaultValue: 'Could not delete the template' }));
      void loadRevisions(tpl.id);
    } finally {
      setBusy(null);
    }
  };

  /** A draft revision that is not the template's only one. */
  const handleDeleteRevision = async (tpl: Template, rev: TemplateRevision) => {
    const ok = window.confirm(t('templates.deleteRevisionConfirm', {
      defaultValue:
        'Delete draft revision #{{n}} of "{{name}}"? It was never published. This cannot be undone.',
      n: rev.revision,
      name: tpl.name,
    }));
    if (!ok) return;
    setBusy(`revision:${rev.id}`);
    try {
      await templatesApi.removeRevision(tpl.id, rev.id);
      setRevisions((prev) => (prev ?? []).filter((r) => r.id !== rev.id));
      toast.success(t('templates.revisionDeleted', { defaultValue: 'Draft revision deleted' }));
    } catch (err) {
      const m = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(m ?? t('templates.deleteRevisionFailed', { defaultValue: 'Could not delete the revision' }));
      void loadRevisions(tpl.id);
    } finally {
      setBusy(null);
    }
  };

  /** Archive (or restore) — the gesture for a template that is provenance. An
   *  archived template is skipped by the assignment resolver and refused by
   *  the render path; its revisions stay. */
  const handleArchive = async (tpl: Template, archive: boolean) => {
    if (archive) {
      const ok = window.confirm(t('templates.archiveConfirm', {
        defaultValue:
          'Archive the template "{{name}}"? Its assignments stop applying it and it can no longer '
          + 'be rendered. Its revisions are kept as the record of what they produced, and it can be '
          + 'restored later.',
        name: tpl.name,
      }));
      if (!ok) return;
    }
    setBusy(`archive:${tpl.id}`);
    try {
      const updated = await templatesApi.update(tpl.id, { status: archive ? 'archived' : 'active' });
      // Merged, not replaced: the PATCH answer carries no god-view tenant tag.
      setTemplates((prev) => prev.map((x) => (x.id === updated.id ? { ...x, ...updated } : x)));
      setSelected((prev) => (prev?.id === updated.id ? { ...prev, ...updated } : prev));
      toast.success(archive
        ? t('templates.archived', { defaultValue: 'Template archived' })
        : t('templates.restored', { defaultValue: 'Template restored' }));
    } catch (err) {
      const m = (err as { response?: { data?: { error?: string } } }).response?.data?.error;
      toast.error(m ?? (archive
        ? t('templates.archiveFailed', { defaultValue: 'Could not archive the template' })
        : t('templates.restoreFailed', { defaultValue: 'Could not restore the template' })));
    } finally {
      setBusy(null);
    }
  };

  const revisionStatus = (rev: TemplateRevision): string => {
    if (rev.status === 'published') return t('templates.frozen', { defaultValue: 'Published — frozen' });
    if (rev.status === 'draft') return t('templates.draft', { defaultValue: 'Draft' });
    if (rev.status === 'quarantined') return t('templates.quarantined', { defaultValue: 'Quarantined' });
    if (rev.status === 'deprecated') return t('templates.deprecated', { defaultValue: 'Deprecated' });
    return rev.status;
  };

  if (loading && templates.length === 0) return <div className="p-6"><LoadingSpinner /></div>;

  // A new first draft belongs to the template it was started on: selecting
  // another one (Back, say) must not reopen it there.
  const editorOpen = selected !== null && editing !== null
    && (editing === 'new' ? newFor === selected.id : editing.templateId === selected.id);

  return (
    <div className="p-6">
      <div className="mb-5 flex flex-wrap items-center justify-between gap-2">
        <h1 className="flex items-center gap-2 text-2xl font-semibold text-text-primary">
          <Layers size={22} /> {t('nav.templates')}
          <GodViewMarker />
        </h1>
        <div className="flex items-center gap-2">
          <GodViewTenantFilter onChange={refresh} />
          <Button size="sm" variant="secondary" onClick={refresh}>
            <RotateCw size={14} className="mr-1.5" />{t('common.refresh', { defaultValue: 'Refresh' })}
          </Button>
          {canWrite && (
            <Button size="sm" variant="secondary" onClick={() => setShowImport(true)}>
              <FileUp size={14} className="mr-1.5" />{t('templates.import.button', { defaultValue: 'Import' })}
            </Button>
          )}
          {canWrite && (
            <Button size="sm" onClick={() => setShowCreate((v) => !v)}>
              <Plus size={14} className="mr-1.5" />{t('templates.new', { defaultValue: 'New template' })}
            </Button>
          )}
        </div>
      </div>

      {showImport && (
        <TemplateImportDialog
          onClose={() => setShowImport(false)}
          onImported={refresh}
          // An "Open" link changes the URL by itself: asked here, and its
          // destination marked as this page's own so the URL guard does not
          // ask again.
          confirmNavigate={(target) => {
            if (!confirmLeave()) return false;
            ownNavRef.current = locationKey(target.templateId, target.revisionId);
            return true;
          }}
        />
      )}

      {deprecating && selected && deprecating.revision.templateId === selected.id && (
        <RevisionDeprecateDialog
          template={selected}
          revision={deprecating.revision}
          supersededBy={deprecating.supersededBy}
          onClose={() => setDeprecating(null)}
          onDeprecated={(updated) => {
            setRevisions((prev) => (prev ?? []).map((r) => (r.id === updated.id ? { ...r, ...updated } : r)));
            setDeprecating(null);
          }}
        />
      )}

      {showCreate && canWrite && (
        <form onSubmit={handleCreate} className="mb-5 rounded-lg border border-border bg-bg-secondary p-4">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
            <Input
              label={t('templates.fields.name', { defaultValue: 'Name' })}
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              required
            />
            <Input
              label={t('templates.fields.description', { defaultValue: 'Description' })}
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
            />
            <div className="space-y-1">
              <label className="block text-sm font-medium text-text-secondary">
                {t('templates.fields.brand', { defaultValue: 'Brand' })}
              </label>
              {/* A template is brand-specific (its body is RouterOS syntax or it
                  is not), and the server requires one: there is no "any brand". */}
              <select
                className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary"
                value={form.brand}
                onChange={(e) => setForm({ ...form, brand: e.target.value as DeviceBrand })}
                required
              >
                {DEVICE_BRANDS.map((b) => <option key={b} value={b}>{t(`fleet.brand.${b}`)}</option>)}
              </select>
            </div>
          </div>
          <div className="mt-3 flex gap-2">
            <Button type="submit" size="sm" loading={saving}>{t('common.create')}</Button>
            <Button type="button" size="sm" variant="secondary" onClick={() => setShowCreate(false)}>
              {t('common.cancel')}
            </Button>
          </div>
        </form>
      )}

      {editorOpen && selected ? (
        <EditorErrorBoundary
          key={editing === 'new' ? `new:${selected.id}` : editing.id}
          onClose={closeEditor}
        >
          <RevisionEditor
            template={selected}
            revision={editing === 'new' ? null : editing}
            canWrite={canWrite}
            vocabulary={vocabulary}
            onSaved={onSaved}
            onClose={closeEditor}
            onDirtyChange={setEditorUnsaved}
          />
        </EditorErrorBoundary>
      ) : (
        <>
          <div className="mb-4 flex items-center gap-2">
            <Search size={16} className="text-text-muted" />
            <input
              className="w-full max-w-sm rounded-md border border-border bg-bg-tertiary px-3 py-1.5 text-sm text-text-primary"
              placeholder={t('templates.search', { defaultValue: 'Search templates…' })}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <div className="rounded-lg border border-border bg-bg-secondary">
              {filtered.length === 0 ? (
                <div className="px-6 py-12 text-center text-sm text-text-secondary">
                  {t('templates.empty', { defaultValue: 'No template yet.' })}
                </div>
              ) : (
                <ul className="divide-y divide-border">
                  {filtered.map((tpl) => (
                    <li key={tpl.id}>
                      <button
                        type="button"
                        onClick={() => selectTemplate(tpl)}
                        className={`flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-bg-tertiary ${
                          selected?.id === tpl.id ? 'bg-bg-tertiary' : ''
                        }`}
                      >
                        <FileText size={16} className="shrink-0 text-text-muted" />
                        <span className="min-w-0 flex-1">
                          <span className="flex items-center gap-1.5 truncate text-sm text-text-primary">
                            <span className="truncate">{tpl.name}</span>
                            <TenantBadge name={tpl.tenantName} />
                          </span>
                          <span className="block truncate text-xs text-text-muted">
                            {tpl.description ?? '—'}
                          </span>
                        </span>
                        {tpl.isLibrary && (
                          <Lock
                            size={14}
                            className="shrink-0 text-text-muted"
                            aria-label={t('templates.libraryReadOnly', { defaultValue: 'Shipped library — read-only' })}
                          />
                        )}
                        <span className="shrink-0 font-mono text-[10px] uppercase text-text-muted">
                          {tpl.status}
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div className="rounded-lg border border-border bg-bg-secondary p-4">
              {!selected ? (
                <p className="py-10 text-center text-sm text-text-secondary">
                  {t('templates.pickOne', { defaultValue: 'Select a template to see its revisions.' })}
                </p>
              ) : (
                <>
                  <div className="mb-3 flex items-start gap-2">
                    <div className="min-w-0 flex-1">
                      <h2 className="text-sm font-semibold text-text-primary">{selected.name}</h2>
                      {selected.isLibrary && (
                        <p className="mt-1 text-xs text-text-muted">
                          {t('templates.libraryNote', {
                            defaultValue:
                              'Shipped library: shared by every tenant and read-only. Duplicate it to change anything.',
                          })}
                        </p>
                      )}
                    </div>
                    {canWrite && !selected.isLibrary && (
                      <div className="flex shrink-0 flex-wrap items-center justify-end gap-2">
                        {revisions !== null && revisions.length === 0 && (
                          <Button size="sm" onClick={() => { setNewFor(selected.id); setEditing('new'); }}>
                            <PencilLine size={14} className="mr-1.5" />
                            {t('templates.writeFirst', { defaultValue: 'Write the first revision' })}
                          </Button>
                        )}
                        {selected.status === 'archived' ? (
                          <Button
                            size="sm"
                            variant="secondary"
                            loading={busy === `archive:${selected.id}`}
                            disabled={busy !== null}
                            onClick={() => void handleArchive(selected, false)}
                          >
                            <ArchiveRestore size={14} className="mr-1.5" />
                            {t('templates.restore', { defaultValue: 'Restore' })}
                          </Button>
                        ) : (
                          <Button
                            size="sm"
                            variant="secondary"
                            loading={busy === `archive:${selected.id}`}
                            disabled={busy !== null}
                            onClick={() => void handleArchive(selected, true)}
                          >
                            <Archive size={14} className="mr-1.5" />
                            {t('templates.archive', { defaultValue: 'Archive' })}
                          </Button>
                        )}
                        {/* Only while no revision ever left draft: a published
                            revision is provenance, and its template is archived. */}
                        {/* `templateId` too: a list that is not this template's
                            must never arm an irreversible delete. */}
                        {revisions !== null
                          && revisions.every((r) => r.status === 'draft' && r.templateId === selected.id) && (
                          <Button
                            size="sm"
                            variant="danger"
                            loading={busy === `template:${selected.id}`}
                            disabled={busy !== null}
                            onClick={() => void handleDeleteTemplate(selected, revisions.length)}
                          >
                            <Trash2 size={14} className="mr-1.5" />
                            {t('common.delete', { defaultValue: 'Delete' })}
                          </Button>
                        )}
                      </div>
                    )}
                  </div>

                  {revisions === null ? (
                    <LoadingSpinner />
                  ) : revisions.length === 0 ? (
                    <p className="py-6 text-center text-sm text-text-secondary">
                      {t('templates.noRevision', { defaultValue: 'No revision yet.' })}
                    </p>
                  ) : (
                    <ul className="divide-y divide-border">
                      {revisions.map((rev) => {
                        const draft = rev.status === 'draft';
                        return (
                          <li key={rev.id} className="flex items-center gap-3 py-2.5">
                            <span className="font-mono text-xs text-text-muted">#{rev.revision}</span>
                            <span className="min-w-0 flex-1">
                              <span className="block text-sm text-text-primary">{revisionStatus(rev)}</span>
                              <span className="block font-mono text-[10px] text-text-muted">
                                {rev.bodySha256?.slice(0, 12)}
                              </span>
                            </span>
                            <Button size="sm" variant="ghost" onClick={() => openRevision(rev)}>
                              {draft && canWrite && !selected.isLibrary
                                ? <><PencilLine size={14} className="mr-1" />{t('templates.edit', { defaultValue: 'Edit' })}</>
                                : <><Eye size={14} className="mr-1" />{t('templates.open', { defaultValue: 'Open' })}</>}
                            </Button>
                            {/* A published revision stays on the bench's list
                                until it is deprecated; the dialog says what
                                else that changes. */}
                            {rev.status === 'published' && canWrite && !selected.isLibrary
                              && rev.templateId === selected.id && (
                              <Button
                                size="sm"
                                variant="ghost"
                                disabled={busy !== null || deprecating !== null}
                                onClick={() => setDeprecating({ revision: rev, supersededBy: null })}
                                title={t('templates.deprecate.action', {
                                  defaultValue: 'Deprecate: the bench stops offering this revision',
                                })}
                              >
                                <Ban size={14} className="mr-1" />
                                {t('templates.deprecate.button', { defaultValue: 'Deprecate' })}
                              </Button>
                            )}
                            {!draft ? (
                              <CheckCircle2 size={16} className="shrink-0 text-text-muted" />
                            ) : canWrite && !selected.isLibrary ? (
                              <Button size="sm" variant="secondary" onClick={() => void handlePublish(rev)}>
                                {t('templates.publish', { defaultValue: 'Publish' })}
                              </Button>
                            ) : null}
                            {/* Not on the only revision: removing that one is the
                                template's own delete, offered above. */}
                            {draft && canWrite && !selected.isLibrary && revisions.length > 1
                              && rev.templateId === selected.id && (
                              <Button
                                size="sm"
                                variant="ghost"
                                loading={busy === `revision:${rev.id}`}
                                disabled={busy !== null}
                                onClick={() => void handleDeleteRevision(selected, rev)}
                                title={t('templates.deleteRevision', { defaultValue: 'Delete this draft revision' })}
                                aria-label={t('templates.deleteRevision', { defaultValue: 'Delete this draft revision' })}
                              >
                                <Trash2 size={14} className="text-status-down" />
                              </Button>
                            )}
                          </li>
                        );
                      })}
                    </ul>
                  )}
                </>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
