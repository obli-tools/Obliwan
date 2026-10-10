import { useEffect, useState, type KeyboardEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { ChevronDown, ChevronRight, Lock, Plus, Trash2 } from 'lucide-react';
import type { VarSchema } from '@/api/templates.api';
import { Button } from '@/components/common/Button';
import { cn } from '@/utils/cn';
import {
  EDITABLE_KINDS, VARIABLE_KEY_RE, addVar, defaultSig, defaultToText, kindOf, liveDraft, parseDefault,
  removeVar, renameVar, rowsOf, setKey, setProp, setRequired, withKind, arrayItemsAreScalar,
  type DefaultDraft, type VarRow,
} from './varSchemaModel';
import { defaultErrorText, kindLabel, levelHint, levelLabel } from './labels';

/**
 * The variables of a revision, as a table — no JSON. Each control edits one
 * key of the property it sits on (`varSchemaModel` explains why), so the keys
 * the table does not show (`pattern`, `minLength`, `items`, a formula…) are
 * kept as they were and listed, read-only, in the row's details.
 *
 * A default being typed is NOT row state: it is a `DefaultDraft` the editor
 * holds (`defaultDrafts` / `onDefaultDraft`), so an invalid one survives a tab
 * switch and keeps the draft from being saved while the screen shows it.
 */
interface VariablesTableProps {
  schema: VarSchema;
  /** Absent: read-only (a published revision, a library template). */
  onChange?: (schema: VarSchema) => void;
  used: Map<string, number[]>;
  /** The server's level list (`GET /templates/vocabulary`), null until loaded. */
  levels: string[] | null;
  onGoToLine?: (line: number) => void;
  /** Defaults as typed, per variable (see `DefaultDraft`). */
  defaultDrafts?: Record<string, DefaultDraft>;
  onDefaultDraft?: (key: string, draft: DefaultDraft | null) => void;
}

const inputCls =
  'w-full rounded border border-border bg-bg-tertiary px-2 py-1 text-xs text-text-primary ' +
  'placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent disabled:opacity-60';
const checkCls = 'h-3.5 w-3.5 rounded border-border bg-bg-tertiary accent-accent';

/** Keys every row shows in a column; the kind adds its own (see `shown`), and
 *  everything else goes to "other rules". */
const SHOWN_KEYS: ReadonlySet<string> = new Set([
  'default', 'x-obliwan-label', 'x-obliwan-level', 'x-obliwan-secret', 'description',
]);

export function VariablesTable({
  schema, onChange, used, levels, onGoToLine, defaultDrafts, onDefaultDraft,
}: VariablesTableProps) {
  const { t } = useTranslation();
  const readOnly = !onChange;
  const rows = rowsOf(schema);
  const [newKey, setNewKey] = useState('');
  const [newKeyError, setNewKeyError] = useState<string | null>(null);

  const addNew = () => {
    const key = newKey.trim();
    if (!VARIABLE_KEY_RE.test(key)) {
      setNewKeyError(t('templates.vars.newKeyInvalid', {
        defaultValue: 'A variable name starts with a lowercase letter, then letters, digits or _ only (e.g. wifi_ssid).',
      }));
      return;
    }
    if (key in (schema.properties ?? {})) {
      setNewKeyError(t('templates.vars.newKeyExists', { defaultValue: '"{{key}}" is already declared.', key }));
      return;
    }
    onChange?.(addVar(schema, key, { type: 'string' }));
    setNewKey('');
    setNewKeyError(null);
  };

  return (
    <div className="space-y-2">
      <div className="overflow-x-auto rounded-lg border border-border">
        <table className="w-full min-w-[1080px] text-left text-xs">
          <thead>
            <tr className="border-b border-border bg-bg-tertiary/40 text-[11px] uppercase tracking-wider text-text-muted">
              <th className="w-6 px-2 py-2" />
              <th className="px-2 py-2 font-medium">{t('templates.vars.col.key', { defaultValue: 'Variable' })}</th>
              <th className="px-2 py-2 font-medium">{t('templates.vars.col.label', { defaultValue: 'Label' })}</th>
              <th className="px-2 py-2 font-medium">{t('templates.vars.col.type', { defaultValue: 'Type' })}</th>
              <th className="px-2 py-2 font-medium">{t('templates.vars.col.level', { defaultValue: 'Set at' })}</th>
              <th className="px-2 py-2 text-center font-medium">{t('templates.vars.col.secret', { defaultValue: 'Secret' })}</th>
              <th className="px-2 py-2 text-center font-medium">{t('templates.vars.col.required', { defaultValue: 'Required' })}</th>
              <th className="px-2 py-2 font-medium">{t('templates.vars.col.default', { defaultValue: 'Default value' })}</th>
              <th className="px-2 py-2 font-medium">{t('templates.vars.col.usage', { defaultValue: 'Used' })}</th>
              <th className="w-8 px-2 py-2" />
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {rows.length === 0 && (
              <tr>
                <td colSpan={10} className="px-3 py-6 text-center text-text-muted">
                  {t('templates.vars.empty', { defaultValue: 'No variable declared yet.' })}
                </td>
              </tr>
            )}
            {rows.map((row) => (
              <VariableRow
                key={row.key}
                row={row}
                schema={schema}
                onChange={onChange}
                readOnly={readOnly}
                usedLines={used.get(row.key) ?? null}
                levels={levels}
                onGoToLine={onGoToLine}
                draft={defaultDrafts?.[row.key]}
                onDraft={onDefaultDraft}
              />
            ))}
          </tbody>
        </table>
      </div>

      {!readOnly && (
        <div className="flex flex-wrap items-start gap-2">
          <div className="w-64">
            <input
              className={cn(inputCls, 'font-mono')}
              value={newKey}
              placeholder={t('templates.vars.newKeyPlaceholder', { defaultValue: 'new_variable_name' })}
              onChange={(e) => { setNewKey(e.target.value); setNewKeyError(null); }}
              onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addNew(); } }}
              aria-label={t('templates.vars.newKeyAria', { defaultValue: 'Name of the variable to add' })}
            />
            {newKeyError && <p className="mt-1 text-[11px] text-status-down">{newKeyError}</p>}
          </div>
          <Button type="button" size="sm" variant="secondary" onClick={addNew}>
            <Plus size={14} className="mr-1" />
            {t('templates.vars.add', { defaultValue: 'Add a variable' })}
          </Button>
        </div>
      )}
    </div>
  );
}

interface RowProps {
  row: VarRow;
  schema: VarSchema;
  onChange?: (schema: VarSchema) => void;
  readOnly: boolean;
  usedLines: number[] | null;
  levels: string[] | null;
  onGoToLine?: (line: number) => void;
  draft?: DefaultDraft;
  onDraft?: (key: string, draft: DefaultDraft | null) => void;
}

function VariableRow({ row, schema, onChange, readOnly, usedLines, levels, onGoToLine, draft, onDraft }: RowProps) {
  const { t } = useTranslation();
  const { key, prop, required } = row;
  const kind = kindOf(prop);
  const secret = prop['x-obliwan-secret'] === true;
  const level = typeof prop['x-obliwan-level'] === 'string' ? (prop['x-obliwan-level'] as string) : '';
  const label = typeof prop['x-obliwan-label'] === 'string' ? (prop['x-obliwan-label'] as string) : '';
  const description = typeof prop.description === 'string' ? prop.description : '';
  const enumValues = Array.isArray(prop.enum) ? (prop.enum as unknown[]).map(String) : [];

  const [open, setOpen] = useState(false);
  const [keyDraft, setKeyDraft] = useState(key);
  const [keyError, setKeyError] = useState<string | null>(null);
  const [enumText, setEnumText] = useState(enumValues.join('\n'));
  const [secretNote, setSecretNote] = useState(false);

  // The default cell: the editor's draft while it is live (it may be invalid,
  // or a list with a trailing newline being typed), else the schema's value.
  const live = liveDraft(draft, prop);
  const defaultText = live ? live.text : defaultToText(prop);
  const defaultError = live?.error ? defaultErrorText(t, live.error, key) : null;

  // Re-sync from the schema when it changed from elsewhere (advanced JSON).
  useEffect(() => { setKeyDraft(key); }, [key]);
  useEffect(() => {
    const typed = enumText.split('\n').map((s) => s.trim()).filter((s) => s.length > 0);
    if (JSON.stringify(typed) !== JSON.stringify(enumValues)) setEnumText(enumValues.join('\n'));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [JSON.stringify(prop.enum)]);

  const update = (next: Record<string, unknown>) => onChange?.(setProp(schema, key, next));

  const commitKey = () => {
    const next = keyDraft.trim();
    if (next === key) { setKeyError(null); return; }
    if (!VARIABLE_KEY_RE.test(next)) {
      setKeyError(t('templates.vars.newKeyInvalid', {
        defaultValue: 'A variable name starts with a lowercase letter, then letters, digits or _ only (e.g. wifi_ssid).',
      }));
      return;
    }
    if (next in (schema.properties ?? {})) {
      setKeyError(t('templates.vars.newKeyExists', { defaultValue: '"{{key}}" is already declared.', key: next }));
      return;
    }
    setKeyError(null);
    onChange?.(renameVar(schema, key, next));
  };

  const onDefaultText = (text: string) => {
    const parsed = parseDefault(text, prop);
    if (!parsed.ok) {
      // Kept as typed, and it holds the save until it is fixed: the schema
      // still has the last valid value, which is not what the screen shows.
      onDraft?.(key, { text, base: defaultSig(prop), kind });
      return;
    }
    const next = setKey(prop, 'default', parsed.value);
    onDraft?.(key, { text, base: defaultSig(next), kind });
    update(next);
  };

  const onEnumText = (text: string) => {
    setEnumText(text);
    const values = text.split('\n').map((s) => s.trim()).filter((s) => s.length > 0);
    let next = setKey(prop, 'enum', [...new Set(values)]);
    if ('default' in next && !values.includes(String(next.default))) next = setKey(next, 'default', undefined);
    update(next);
  };

  const onSecret = (checked: boolean) => {
    let next = setKey(prop, 'x-obliwan-secret', checked ? true : undefined);
    if (checked && 'default' in next) {
      next = setKey(next, 'default', undefined);
      setSecretNote(true);
    } else {
      setSecretNote(false);
    }
    update(next);
  };

  const remove = () => {
    const ok = window.confirm(t('templates.vars.removeConfirm', {
      defaultValue: 'Remove the variable "{{key}}" from this revision?', key,
    }));
    if (ok) onChange?.(removeVar(schema, key));
  };

  // What a column already shows for THIS kind; the rest is listed as-is.
  const shown = new Set(SHOWN_KEYS);
  if (kind !== 'other') shown.add('type');
  if (kind === 'enum') shown.add('enum');
  if (kind === 'ipv4') shown.add('format');
  const otherKeys = Object.entries(prop).filter(([k]) => !shown.has(k));
  const levelOptions = levels ? [...levels] : [];
  if (level && !levelOptions.includes(level)) levelOptions.push(level);

  const onKeyKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') { e.preventDefault(); commitKey(); }
    if (e.key === 'Escape') { setKeyDraft(key); setKeyError(null); }
  };

  return (
    <>
      <tr className="align-top">
        <td className="px-2 py-2">
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            className="text-text-muted hover:text-text-primary"
            aria-expanded={open}
            aria-label={t('templates.vars.details', { defaultValue: 'Details' })}
          >
            {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          </button>
        </td>
        <td className="px-2 py-2">
          {readOnly ? (
            <span className="font-mono text-text-primary">{key}</span>
          ) : (
            <>
              <input
                className={cn(inputCls, 'font-mono', keyError && 'border-status-down')}
                value={keyDraft}
                onChange={(e) => setKeyDraft(e.target.value)}
                onBlur={commitKey}
                onKeyDown={onKeyKey}
                aria-label={t('templates.vars.col.key', { defaultValue: 'Variable' })}
              />
              {keyError && <p className="mt-1 max-w-[16rem] text-[11px] text-status-down">{keyError}</p>}
            </>
          )}
        </td>
        <td className="px-2 py-2">
          <input
            className={inputCls}
            value={label}
            disabled={readOnly}
            placeholder={t('templates.vars.labelPlaceholder', { defaultValue: 'Shown in forms' })}
            onChange={(e) => update(setKey(prop, 'x-obliwan-label', e.target.value === '' ? undefined : e.target.value))}
            aria-label={t('templates.vars.col.label', { defaultValue: 'Label' })}
          />
        </td>
        <td className="px-2 py-2">
          {kind === 'other' ? (
            <span className="text-text-muted" title={t('templates.vars.otherHint', {
              defaultValue: 'This variable has a shape the table cannot edit. Use the advanced JSON view.',
            })}
            >
              {kindLabel(t, 'other')}
            </span>
          ) : (
            <select
              className={inputCls}
              value={kind}
              disabled={readOnly}
              onChange={(e) => update(withKind(prop, e.target.value as (typeof EDITABLE_KINDS)[number]))}
              aria-label={t('templates.vars.col.type', { defaultValue: 'Type' })}
            >
              {EDITABLE_KINDS.map((k) => <option key={k} value={k}>{kindLabel(t, k)}</option>)}
            </select>
          )}
          {kind === 'enum' && (
            <textarea
              className={cn(inputCls, 'mt-1 font-mono')}
              rows={Math.min(Math.max(enumValues.length, 2), 6)}
              value={enumText}
              disabled={readOnly}
              placeholder={t('templates.vars.enumPlaceholder', { defaultValue: 'One choice per line' })}
              onChange={(e) => onEnumText(e.target.value)}
              aria-label={t('templates.vars.enumAria', { defaultValue: 'Possible choices, one per line' })}
            />
          )}
        </td>
        <td className="px-2 py-2">
          <select
            className={inputCls}
            value={level}
            disabled={readOnly}
            title={level ? levelHint(t, level) : undefined}
            onChange={(e) => update(setKey(prop, 'x-obliwan-level', e.target.value === '' ? undefined : e.target.value))}
            aria-label={t('templates.vars.col.level', { defaultValue: 'Set at' })}
          >
            <option value="">{t('templates.vars.levelUnset', { defaultValue: '— not stated' })}</option>
            {levelOptions.map((l) => <option key={l} value={l} title={levelHint(t, l)}>{levelLabel(t, l)}</option>)}
          </select>
        </td>
        <td className="px-2 py-2 text-center">
          <input
            type="checkbox"
            className={checkCls}
            checked={secret}
            disabled={readOnly}
            onChange={(e) => onSecret(e.target.checked)}
            aria-label={t('templates.vars.col.secret', { defaultValue: 'Secret' })}
          />
        </td>
        <td className="px-2 py-2 text-center">
          <input
            type="checkbox"
            className={checkCls}
            checked={required}
            disabled={readOnly}
            onChange={(e) => onChange?.(setRequired(schema, key, e.target.checked))}
            aria-label={t('templates.vars.col.required', { defaultValue: 'Required' })}
          />
        </td>
        <td className="px-2 py-2">
          {secret ? (
            <span className="inline-flex items-center gap-1 text-text-muted">
              <Lock size={12} />
              {t('templates.vars.secretNoDefault', { defaultValue: 'From the vault' })}
            </span>
          ) : kind === 'boolean' ? (
            <select
              className={inputCls}
              value={defaultText}
              disabled={readOnly}
              onChange={(e) => onDefaultText(e.target.value)}
              aria-label={t('templates.vars.col.default', { defaultValue: 'Default value' })}
            >
              <option value="">{t('templates.vars.noDefault', { defaultValue: '— none' })}</option>
              <option value="true">{t('common.yes')}</option>
              <option value="false">{t('common.no')}</option>
            </select>
          ) : kind === 'enum' ? (
            <select
              className={inputCls}
              value={defaultText}
              disabled={readOnly}
              onChange={(e) => onDefaultText(e.target.value)}
              aria-label={t('templates.vars.col.default', { defaultValue: 'Default value' })}
            >
              <option value="">{t('templates.vars.noDefault', { defaultValue: '— none' })}</option>
              {enumValues.map((v) => <option key={v} value={v}>{v}</option>)}
            </select>
          ) : kind === 'array' || kind === 'other' ? (
            <textarea
              className={cn(inputCls, 'font-mono', defaultError && 'border-status-down')}
              rows={Math.min(Math.max(defaultText.split('\n').length, 2), 6)}
              value={defaultText}
              disabled={readOnly}
              placeholder={kind === 'array' && arrayItemsAreScalar(prop)
                ? t('templates.vars.listPlaceholder', { defaultValue: 'One value per line' })
                : t('templates.vars.jsonPlaceholder', { defaultValue: 'JSON value' })}
              onChange={(e) => onDefaultText(e.target.value)}
              aria-label={t('templates.vars.col.default', { defaultValue: 'Default value' })}
            />
          ) : (
            <input
              className={cn(inputCls, 'font-mono', defaultError && 'border-status-down')}
              value={defaultText}
              disabled={readOnly}
              placeholder={t('templates.vars.noDefault', { defaultValue: '— none' })}
              onChange={(e) => onDefaultText(e.target.value)}
              aria-label={t('templates.vars.col.default', { defaultValue: 'Default value' })}
            />
          )}
          {defaultError && <p className="mt-1 max-w-[16rem] text-[11px] text-status-down">{defaultError}</p>}
          {secretNote && (
            <p className="mt-1 max-w-[16rem] text-[11px] text-status-ssl-warning">
              {t('templates.vars.secretDefaultRemoved', {
                defaultValue: 'The default value was removed: a secret never has one.',
              })}
            </p>
          )}
        </td>
        <td className="px-2 py-2">
          {usedLines && usedLines.length > 0 ? (
            <span className="text-text-secondary">
              {t('templates.vars.usedOnLines', { defaultValue: 'lines' })}{' '}
              {usedLines.slice(0, 6).map((l, i) => (
                <span key={l}>
                  {i > 0 && ', '}
                  {onGoToLine ? (
                    <button type="button" className="font-mono text-accent hover:underline" onClick={() => onGoToLine(l)}>
                      {l}
                    </button>
                  ) : <span className="font-mono">{l}</span>}
                </span>
              ))}
              {usedLines.length > 6 && '…'}
            </span>
          ) : (
            <span className="rounded bg-status-ssl-warning/15 px-1.5 py-0.5 text-[10px] text-status-ssl-warning">
              {t('templates.vars.unused', { defaultValue: 'not used' })}
            </span>
          )}
        </td>
        <td className="px-2 py-2">
          {!readOnly && (
            <button
              type="button"
              onClick={remove}
              className="text-text-muted hover:text-status-down"
              aria-label={t('templates.vars.remove', { defaultValue: 'Remove this variable' })}
            >
              <Trash2 size={14} />
            </button>
          )}
        </td>
      </tr>
      {open && (
        <tr className="bg-bg-tertiary/30">
          <td />
          <td colSpan={9} className="space-y-2 px-2 py-2">
            <label className="block text-[11px] text-text-muted">
              {t('templates.vars.description', { defaultValue: 'Description (help text for whoever fills it in)' })}
              <textarea
                className={cn(inputCls, 'mt-1')}
                rows={2}
                value={description}
                disabled={readOnly}
                onChange={(e) => update(setKey(prop, 'description', e.target.value === '' ? undefined : e.target.value))}
              />
            </label>
            {level && <p className="text-[11px] text-text-muted">{levelHint(t, level)}</p>}
            {otherKeys.length > 0 && (
              <div>
                <p className="text-[11px] text-text-muted">
                  {t('templates.vars.otherConstraints', {
                    defaultValue: 'Other rules kept as they are (editable in the advanced JSON view):',
                  })}
                </p>
                <ul className="mt-1 space-y-0.5 font-mono text-[11px] text-text-secondary">
                  {otherKeys.map(([k, v]) => (
                    <li key={k} className="break-all">
                      <span className="text-text-muted">{k}:</span> {JSON.stringify(v)}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  );
}
