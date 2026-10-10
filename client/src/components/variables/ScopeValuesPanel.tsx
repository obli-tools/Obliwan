import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import toast from 'react-hot-toast';
import { KeyRound, Pencil, Plus, RotateCw, Trash2, X } from 'lucide-react';
import type { JsonValue, StoredVariable } from '@/api/variables.api';
import { Button } from '@/components/common/Button';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { cn } from '@/utils/cn';
import {
  VARIABLE_KEY_RE,
  apiErrorText,
  displayValue,
  draftOf,
  kindOf,
  parseDraft,
  parseFailureText,
  type ValueKind,
} from './valueKinds';

/**
 * Free-form values at ONE level (instance, or the current client) — a list
 * plus an editor.
 *
 * A secret is listed as "set" and offered for REPLACEMENT only: the server
 * returns a placeholder in its `value`, never the secret, and this panel never
 * renders that placeholder either (a value that looks like data invites
 * somebody to copy it into a template). The one way to SEE a secret is the
 * optional `secretReveal` slot, which the page fills with a
 * `RevealSecretButton` (SECRET_READ): that button fetches the plaintext on
 * click, holds it for 30 seconds in its own state, and the value never enters
 * this panel's.
 *
 * `level` on a row is an optional badge, used by the Client tab to show the
 * few values stored at the tenant's older `global` level; `save` and `remove`
 * receive it back so a change or a removal hits the level the row came from.
 */

export interface ScopeRow {
  variable: StoredVariable;
  /** Shown as a badge when set; passed back to `onRemove`. */
  level?: string;
  levelLabel?: string;
}

interface Editor {
  /** null = a new value; else the key being edited (locked). */
  editing: string | null;
  key: string;
  kind: ValueKind;
  text: string;
  /** The level of the row being edited, so the change lands where the value lives. */
  level?: string;
  /** The row being edited is a secret today: saving it under another kind
   *  would store it readable, so that is confirmed first. */
  wasSecret?: boolean;
}

const EMPTY_EDITOR: Editor = { editing: null, key: '', kind: 'text', text: '' };

export function ScopeValuesPanel({
  load,
  save,
  remove,
  canWrite,
  readOnlyNote,
  hint,
  emptyText,
  removeConfirmText,
  reloadKey,
  secretReveal,
}: {
  load: () => Promise<ScopeRow[]>;
  save: (body: { key: string; value: JsonValue; isSecret: boolean }, level: string | undefined) => Promise<void>;
  remove: (key: string, level: string | undefined) => Promise<void>;
  canWrite: boolean;
  /** Shown instead of the editor when `canWrite` is false. */
  readOnlyNote?: string;
  hint: string;
  emptyText: string;
  /** The question asked before a removal. It differs per level: at the
   *  instance level nothing wider takes over, and every client loses it. */
  removeConfirmText: (key: string) => string;
  /** Changing it reloads the list and drops any open edit (e.g. the current
   *  tenant changed: a draft typed for one client must not be saved into another). */
  reloadKey?: unknown;
  /** Drawn next to a secret marked "set": the page's reveal control for that
   *  row (`level` as on the row; `fingerprint` the row's keyed fingerprint,
   *  which changes when the secret is replaced — a revealed value must not
   *  outlive it). Omitted, a secret has no reveal control. */
  secretReveal?: (key: string, level: string | undefined, fingerprint: unknown) => ReactNode;
}) {
  const { t } = useTranslation();
  const [rows, setRows] = useState<ScopeRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [editor, setEditor] = useState<Editor>(EMPTY_EDITOR);
  const [fieldError, setFieldError] = useState<{ key?: string; value?: string }>({});
  const [saving, setSaving] = useState(false);
  const formRef = useRef<HTMLFormElement>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const list = await load();
      setRows([...list].sort((a, b) => a.variable.key.localeCompare(b.variable.key)));
      setLoadError(null);
    } catch (err) {
      setRows([]);
      setLoadError(apiErrorText(err) ?? t('variables.loadFailed', { defaultValue: 'Could not load the values.' }));
    } finally {
      setLoading(false);
    }
  }, [load, t]);

  useEffect(() => { void refresh(); }, [refresh, reloadKey]);
  // A separate effect on purpose: `refresh` also changes when `load` does, and
  // only a `reloadKey` change (another tenant) must throw the draft away.
  useEffect(() => { setEditor(EMPTY_EDITOR); setFieldError({}); }, [reloadKey]);

  const startEdit = (row: ScopeRow) => {
    const v = row.variable;
    const kind = kindOf(v.value, v.isSecret);
    setEditor({
      editing: v.key, key: v.key, kind, text: draftOf(v.value, kind), level: row.level, wasSecret: v.isSecret,
    });
    setFieldError({});
    formRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  };

  const cancelEdit = () => { setEditor(EMPTY_EDITOR); setFieldError({}); };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const key = editor.key.trim();
    const errs: { key?: string; value?: string } = {};
    if (!VARIABLE_KEY_RE.test(key)) {
      errs.key = t('variables.err.badKey', {
        defaultValue: 'Start with a lowercase letter, then letters, digits or _ only (no spaces, no dots).',
      });
    }
    const parsed = parseDraft(editor.text, editor.kind);
    if (!parsed.ok) errs.value = parseFailureText(t, parsed.reason);
    // "Add a value" never replaces an existing one: the server upserts, so a
    // name typed again would silently overwrite it (a secret included). The
    // check covers every row listed, whatever its level, so a value is never
    // duplicated at a second level of the same panel either.
    if (!errs.key && editor.editing === null && rows.some((r) => r.variable.key === key)) {
      errs.key = t('variables.err.exists', {
        defaultValue: '"{{key}}" already exists here. Use the pencil on its row to change it.',
        key,
      });
    }
    setFieldError(errs);
    if (errs.key || errs.value || !parsed.ok) return;
    if (editor.editing !== null && editor.wasSecret && editor.kind !== 'secret'
      && !window.confirm(t('variables.secretDowngradeConfirm', {
        defaultValue:
          '"{{key}}" is a secret today. Saved like this, it will be stored as a plain value that anyone who '
          + 'can view variables can read. Continue?',
        key,
      }))) return;

    setSaving(true);
    try {
      await save({ key, value: parsed.value, isSecret: editor.kind === 'secret' }, editor.level);
      toast.success(
        editor.kind === 'secret'
          ? t('variables.secretSavedHidden', {
            defaultValue: 'Secret "{{key}}" saved, encrypted. It is shown as set, never in clear — except to an '
              + 'account allowed to reveal secrets, and every reveal is recorded in the audit log.',
            key,
          })
          : t('variables.saved', { defaultValue: '"{{key}}" saved.', key }),
      );
      setEditor(EMPTY_EDITOR);
      void refresh();
    } catch (err) {
      toast.error(apiErrorText(err) ?? t('variables.saveFailed', { defaultValue: 'Could not save.' }));
    } finally {
      setSaving(false);
    }
  };

  const handleRemove = async (row: ScopeRow) => {
    const key = row.variable.key;
    if (!window.confirm(removeConfirmText(key))) return;
    try {
      await remove(key, row.level);
      toast.success(t('variables.removed', { defaultValue: '"{{key}}" deleted.', key }));
      if (editor.editing === key) cancelEdit();
      void refresh();
    } catch (err) {
      toast.error(apiErrorText(err) ?? t('variables.removeFailed', { defaultValue: 'Could not delete.' }));
    }
  };

  const kindOptions: { value: ValueKind; label: string }[] = [
    { value: 'text', label: t('variables.kind.text', { defaultValue: 'Text' }) },
    { value: 'number', label: t('variables.kind.number', { defaultValue: 'Number' }) },
    { value: 'boolean', label: t('variables.kind.boolean', { defaultValue: 'Yes / No' }) },
    { value: 'secret', label: t('variables.kind.secret', { defaultValue: 'Secret (password, key…)' }) },
    { value: 'json', label: t('variables.kind.json', { defaultValue: 'List or structure (JSON, advanced)' }) },
  ];

  const inputCls = (bad?: string) => cn(
    'w-full rounded-md border bg-bg-tertiary px-3 py-2 text-sm text-text-primary placeholder:text-text-muted',
    'focus:outline-none focus:ring-2 focus:ring-accent disabled:opacity-60',
    bad ? 'border-status-down' : 'border-border',
  );

  return (
    <div>
      <p className="mb-4 max-w-3xl text-sm text-text-secondary">{hint}</p>

      {canWrite ? (
        <form
          ref={formRef}
          onSubmit={(e) => void submit(e)}
          className="mb-5 rounded-lg border border-border bg-bg-secondary p-4"
        >
          <div className="mb-3 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-text-primary">
              {editor.editing
                ? t('variables.editTitle', { defaultValue: 'Change "{{key}}"', key: editor.editing })
                : t('variables.addTitle', { defaultValue: 'Add a value' })}
            </h3>
            {editor.editing && (
              <button type="button" onClick={cancelEdit} className="text-text-muted hover:text-text-primary">
                <X size={16} />
              </button>
            )}
          </div>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-[1fr_1fr_2fr]">
            <label className="space-y-1">
              <span className="block text-sm font-medium text-text-secondary">
                {t('variables.fields.key', { defaultValue: 'Name' })}
              </span>
              <input
                value={editor.key}
                onChange={(e) => setEditor({ ...editor, key: e.target.value })}
                disabled={editor.editing !== null}
                placeholder="wan_mtu"
                autoComplete="off"
                spellCheck={false}
                className={cn(inputCls(fieldError.key), 'font-mono')}
              />
              {fieldError.key && <span className="block text-xs text-status-down">{fieldError.key}</span>}
            </label>
            <label className="space-y-1">
              <span className="block text-sm font-medium text-text-secondary">
                {t('variables.fields.kind', { defaultValue: 'Kind of value' })}
              </span>
              <select
                value={editor.kind}
                onChange={(e) => {
                  const kind = e.target.value as ValueKind;
                  setEditor({ ...editor, kind, text: kind === 'boolean' ? 'true' : editor.kind === 'secret' ? '' : editor.text });
                }}
                className={inputCls()}
              >
                {kindOptions.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </label>
            <label className="space-y-1">
              <span className="block text-sm font-medium text-text-secondary">
                {t('variables.fields.value', { defaultValue: 'Value' })}
              </span>
              {editor.kind === 'boolean' ? (
                <select
                  value={editor.text === 'false' ? 'false' : 'true'}
                  onChange={(e) => setEditor({ ...editor, text: e.target.value })}
                  className={inputCls(fieldError.value)}
                >
                  <option value="true">{t('common.yes')}</option>
                  <option value="false">{t('common.no')}</option>
                </select>
              ) : editor.kind === 'json' ? (
                <textarea
                  value={editor.text}
                  onChange={(e) => setEditor({ ...editor, text: e.target.value })}
                  rows={3}
                  spellCheck={false}
                  placeholder='["10.0.0.1", "10.0.0.2"]'
                  className={cn(inputCls(fieldError.value), 'font-mono')}
                />
              ) : (
                <input
                  value={editor.text}
                  onChange={(e) => setEditor({ ...editor, text: e.target.value })}
                  type={editor.kind === 'secret' ? 'password' : 'text'}
                  inputMode={editor.kind === 'number' ? 'decimal' : undefined}
                  autoComplete={editor.kind === 'secret' ? 'new-password' : 'off'}
                  placeholder={editor.kind === 'secret' && editor.editing
                    ? t('variables.secretReplacePlaceholder', { defaultValue: 'Type the new value to replace it' })
                    : undefined}
                  className={inputCls(fieldError.value)}
                />
              )}
              {fieldError.value && <span className="block text-xs text-status-down">{fieldError.value}</span>}
              {editor.kind === 'secret' && !fieldError.value && (
                <span className="block text-xs text-text-muted">
                  {t('variables.secretNoteReveal', {
                    defaultValue: 'Stored encrypted and never displayed. Only an account allowed to reveal secrets '
                      + 'can display it, for 30 seconds, and every reveal is recorded in the audit log.',
                  })}
                </span>
              )}
            </label>
          </div>
          <div className="mt-3 flex gap-2">
            <Button type="submit" size="sm" loading={saving}>
              {editor.editing ? null : <Plus size={14} className="mr-1.5" />}
              {t('common.save')}
            </Button>
            {editor.editing && (
              <Button type="button" size="sm" variant="secondary" onClick={cancelEdit}>
                {t('common.cancel')}
              </Button>
            )}
          </div>
        </form>
      ) : readOnlyNote ? (
        <p className="mb-4 rounded-md border border-border bg-bg-secondary px-3 py-2 text-xs text-text-muted">
          {readOnlyNote}
        </p>
      ) : null}

      <div className="mb-2 flex justify-end">
        <Button size="sm" variant="ghost" onClick={() => void refresh()}>
          <RotateCw size={14} className="mr-1.5" />{t('common.refresh')}
        </Button>
      </div>

      {loading ? <LoadingSpinner /> : loadError ? (
        <div className="rounded-lg border border-status-down/40 bg-status-down/10 px-4 py-3 text-sm text-status-down">
          {loadError}
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border bg-bg-secondary">
          {rows.length === 0 ? (
            <div className="px-6 py-12 text-center text-sm text-text-secondary">{emptyText}</div>
          ) : (
            <table className="w-full text-sm">
              <thead className="border-b border-border text-left text-xs uppercase tracking-wide text-text-muted">
                <tr>
                  <th className="px-4 py-2 font-medium">{t('variables.fields.key', { defaultValue: 'Name' })}</th>
                  <th className="px-4 py-2 font-medium">{t('variables.fields.value', { defaultValue: 'Value' })}</th>
                  <th className="px-4 py-2" />
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {rows.map((row) => {
                  const v = row.variable;
                  return (
                    <tr key={`${row.level ?? ''}:${v.key}`} className={cn(editor.editing === v.key && 'bg-accent/5')}>
                      <td className="px-4 py-2.5 align-top">
                        <span className="font-mono text-text-primary">{v.key}</span>
                        {row.levelLabel && (
                          <span className="ml-2 rounded-full border border-border px-2 py-0.5 text-[11px] text-text-muted">
                            {row.levelLabel}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-2.5 align-top text-text-secondary">
                        {v.isSecret ? (
                          <span className="inline-flex flex-wrap items-center gap-1.5 text-text-muted">
                            <KeyRound size={13} />
                            {t('variables.secretSetHidden', { defaultValue: 'Secret — set (hidden)' })}
                            {secretReveal?.(v.key, row.level, v.fingerprint)}
                          </span>
                        ) : (
                          <span className="break-all font-mono">{displayValue(v.value)}</span>
                        )}
                      </td>
                      <td className="w-24 whitespace-nowrap px-4 py-2.5 text-right align-top">
                        {canWrite && (
                          <div className="flex justify-end gap-3">
                            <button
                              type="button"
                              onClick={() => startEdit(row)}
                              className="text-text-muted hover:text-text-primary"
                              title={v.isSecret
                                ? t('variables.replace', { defaultValue: 'Replace' })
                                : t('common.edit')}
                            >
                              <Pencil size={14} />
                            </button>
                            <button
                              type="button"
                              onClick={() => void handleRemove(row)}
                              className="text-text-muted hover:text-status-down"
                              title={t('common.delete')}
                            >
                              <Trash2 size={14} />
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
