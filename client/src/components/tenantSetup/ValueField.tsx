import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Eye, EyeOff, KeyRound, RotateCcw } from 'lucide-react';
import type { DeclaredKeyView, StoredValueView } from '@obliwan/shared';
import type { JsonValue } from '@/api/variables.api';
import { cn } from '@/utils/cn';
import { levelLabel } from '@/components/templates/labels';
import { fieldSpec, fingerprintText, parseField, shortValue, textOf } from './fieldModel';
import { INPUT, fieldErrorText, storedText } from './ui';
import type { FieldDraft, FieldLevel } from './quickSetupStore';

interface Props {
  id: string;
  decl: DeclaredKeyView;
  level: FieldLevel;
  draft: FieldDraft | undefined;
  /** What is stored at this field's own level. */
  stored: StoredValueView | undefined;
  /** What is stored at the WIDER levels, nearest first — inherited if this one is empty. */
  inherited: Array<{ level: string; value: StoredValueView }>;
  /** The server's VAR_TYPE / row verdicts for this key at this level. */
  serverErrors: string[];
  onChange: (text: string, asJson: boolean) => void;
  onReset: () => void;
}

export function ValueField({ id, decl, level, draft, stored, inherited, serverErrors, onChange, onReset }: Props) {
  const { t } = useTranslation();
  const [reveal, setReveal] = useState(false);
  const spec = fieldSpec(decl);
  const base = storedText(decl, stored);
  const text = draft ? draft.text : base.text;
  const asJson = draft ? draft.asJson : base.asJson;
  const touched = draft !== undefined;
  const label = decl.label ?? decl.key;

  const change = (next: string, nextAsJson = asJson) => onChange(next, nextAsJson);

  const toggleJson = () => {
    const current = parseField(text, spec, asJson).value;
    if (asJson) {
      change(current === undefined ? '' : textOf(current, spec, false), false);
    } else {
      change(current === undefined ? '' : JSON.stringify(current, null, 2), true);
    }
  };

  let control;
  if (asJson || spec.kind === 'json') {
    control = (
      <textarea
        id={id}
        className={cn(INPUT, 'font-mono text-xs')}
        rows={Math.min(10, Math.max(3, text.split('\n').length))}
        value={text}
        spellCheck={false}
        onChange={(e) => change(e.target.value)}
        placeholder={decl.hasDefault && decl.default !== undefined ? JSON.stringify(decl.default) : undefined}
      />
    );
  } else if (spec.kind === 'secret') {
    control = (
      <div className="flex items-center gap-1">
        <input
          id={id}
          type={reveal ? 'text' : 'password'}
          autoComplete="new-password"
          className={cn(INPUT, 'font-mono')}
          value={text}
          onChange={(e) => change(e.target.value)}
          placeholder={
            stored
              ? t('quickSetup.designer.field.secretKeep', { defaultValue: 'Leave empty to keep the stored secret' })
              : undefined
          }
        />
        {/* Reveals what the operator TYPED in this field. The stored secret is
            never in the browser, so there is nothing else it could show. */}
        <button
          type="button"
          onClick={() => setReveal((r) => !r)}
          disabled={text === ''}
          className="rounded p-1.5 text-text-muted hover:text-text-primary disabled:opacity-40"
          aria-label={t('quickSetup.designer.field.revealTyped', { defaultValue: 'Show what I typed' })}
          title={t('quickSetup.designer.field.revealTyped', { defaultValue: 'Show what I typed' })}
        >
          {reveal ? <EyeOff size={14} /> : <Eye size={14} />}
        </button>
      </div>
    );
  } else if (spec.kind === 'enum') {
    control = (
      <select id={id} className={INPUT} value={text} onChange={(e) => change(e.target.value)}>
        <option value="">
          {stored
            ? t('quickSetup.designer.field.keepCurrent', { defaultValue: '(keep the current value)' })
            : t('quickSetup.designer.field.notSet', { defaultValue: '(do not set)' })}
        </option>
        {spec.options.map((o) => (
          <option key={JSON.stringify(o)} value={JSON.stringify(o)}>
            {typeof o === 'string' ? o : JSON.stringify(o)}
          </option>
        ))}
      </select>
    );
  } else if (spec.kind === 'boolean') {
    control = (
      <select id={id} className={INPUT} value={text} onChange={(e) => change(e.target.value)}>
        <option value="">
          {stored
            ? t('quickSetup.designer.field.keepCurrent', { defaultValue: '(keep the current value)' })
            : t('quickSetup.designer.field.notSet', { defaultValue: '(do not set)' })}
        </option>
        <option value="true">{t('quickSetup.designer.field.yes', { defaultValue: 'Yes' })}</option>
        <option value="false">{t('quickSetup.designer.field.no', { defaultValue: 'No' })}</option>
      </select>
    );
  } else if (spec.kind === 'scalarArray') {
    control = (
      <textarea
        id={id}
        className={cn(INPUT, 'font-mono text-xs')}
        rows={Math.min(8, Math.max(2, text.split('\n').length))}
        value={text}
        spellCheck={false}
        onChange={(e) => change(e.target.value)}
        placeholder={t('quickSetup.designer.field.oneItemPerLine', { defaultValue: 'One item per line' })}
      />
    );
  } else {
    control = (
      <input
        id={id}
        className={cn(INPUT, spec.kind === 'number' ? 'font-mono' : undefined)}
        value={text}
        inputMode={spec.kind === 'number' ? 'decimal' : undefined}
        onChange={(e) => change(e.target.value)}
        placeholder={
          decl.hasDefault && decl.default !== undefined
            ? shortValue(decl.default as JsonValue)
            : spec.placeholder ?? undefined
        }
      />
    );
  }

  const fp = stored?.isSecret ? fingerprintText(stored.fingerprint) : null;

  return (
    <div
      className={cn(
        'rounded-lg border p-3',
        serverErrors.length > 0 || draft?.error ? 'border-status-down/60' : touched ? 'border-accent/50' : 'border-border',
      )}
    >
      <div className="mb-1 flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
        <label htmlFor={id} className="text-sm font-medium text-text-primary">{label}</label>
        <code className="text-[11px] text-text-muted">{decl.key}</code>
        {decl.required && (
          <span className="rounded bg-status-down/15 px-1.5 text-[10px] font-medium uppercase text-status-down">
            {t('quickSetup.designer.field.required', { defaultValue: 'required' })}
          </span>
        )}
        {decl.secret && <KeyRound size={12} className="text-amber-400" aria-label="secret" />}
        {(spec.kind === 'scalarArray' || (asJson && spec.kind !== 'json')) && (
          <label className="ml-auto inline-flex items-center gap-1 text-[11px] text-text-muted">
            <input type="checkbox" checked={asJson} onChange={toggleJson} />
            {t('quickSetup.designer.field.asJson', { defaultValue: 'JSON' })}
          </label>
        )}
        {touched && (
          <button
            type="button"
            onClick={onReset}
            className={cn(
              'inline-flex items-center gap-0.5 text-[11px] text-text-muted hover:text-text-primary',
              spec.kind === 'scalarArray' || asJson ? '' : 'ml-auto',
            )}
            title={t('quickSetup.designer.field.undo', { defaultValue: 'Undo my change' })}
          >
            <RotateCcw size={11} />
            {t('quickSetup.designer.field.undo', { defaultValue: 'Undo my change' })}
          </button>
        )}
      </div>
      {decl.description && <p className="mb-1.5 text-xs text-text-muted">{decl.description}</p>}
      {control}
      <div className="mt-1 space-y-0.5 text-[11px] text-text-muted">
        {decl.secret ? (
          <p>
            {stored
              ? fp
                ? t('quickSetup.designer.field.secretSetFp', {
                  defaultValue: 'Set at this level (fingerprint {{fp}}…)', fp,
                })
                : t('quickSetup.designer.field.secretSet', { defaultValue: 'Set at this level' })
              : t('quickSetup.designer.field.secretNotSet', { defaultValue: 'Not set at this level' })}
          </p>
        ) : stored && !stored.isSecret ? (
          <p>
            {t('quickSetup.designer.field.current', {
              defaultValue: 'Current: {{value}} ({{level}})',
              value: shortValue(stored.value),
              level: levelLabel(t, level),
            })}
          </p>
        ) : null}
        {!stored && inherited.length > 0 && (
          <p>
            {inherited.map((h) => (
              <span key={h.level} className="mr-2">
                {t('quickSetup.designer.field.inherited', {
                  defaultValue: 'Inherited: {{value}}',
                  value: h.value.isSecret || h.value.redacted
                    ? t('quickSetup.designer.field.secretValue', { defaultValue: '(secret)' })
                    : shortValue(h.value.value),
                })}{' '}
                <span className="rounded bg-bg-tertiary px-1">{levelLabel(t, h.level)}</span>
              </span>
            ))}
          </p>
        )}
        {decl.hasDefault && decl.default !== undefined && (
          <p>
            {t('quickSetup.designer.field.default', {
              defaultValue: 'Default: {{value}}', value: shortValue(decl.default as JsonValue),
            })}
          </p>
        )}
        {draft?.error && <p className="text-status-down">{fieldErrorText(t, draft.error)}</p>}
        {serverErrors.map((e, i) => (
          <p key={i} className="text-status-down">{e}</p>
        ))}
      </div>
    </div>
  );
}
