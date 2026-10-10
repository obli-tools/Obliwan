import type { TFunction } from 'i18next';
import type { DeclaredKeyView, StoredValueView } from '@obliwan/shared';
import { fieldSpec, textOf, valueFitsKind, type FieldErrorCode } from './fieldModel';

/** Shared looks and small words of the Quick Setup screens. */

export const LABEL = 'mb-1 block text-xs text-text-muted';
export const CARD = 'rounded-xl border border-border bg-bg-secondary p-4';

export const INPUT =
  'w-full rounded-lg border border-border bg-bg-primary px-3 py-1.5 text-sm text-text-primary ' +
  'focus:outline-none focus:ring-1 focus:ring-accent';

export function fieldErrorText(t: TFunction, code: FieldErrorCode): string {
  switch (code) {
    case 'jsonInvalid':
      return t('quickSetup.designer.field.jsonInvalid', { defaultValue: 'This is not valid JSON.' });
    case 'notNumber':
      return t('variables.err.notNumber', { defaultValue: 'Enter a number, for example 1500.' });
    case 'notInteger':
      return t('variables.err.notInteger', { defaultValue: 'Enter a whole number, without decimals.' });
    case 'notArray':
      return t('quickSetup.designer.field.notArray', { defaultValue: 'Expected a list (a JSON array).' });
    case 'pattern':
      return t('quickSetup.designer.field.pattern', { defaultValue: 'Does not match the expected format.' });
    case 'notInEnum':
    default:
      return t('quickSetup.designer.field.notInEnum', { defaultValue: 'Not one of the listed choices.' });
  }
}

/** The text an untouched field shows: the value stored AT ITS LEVEL, never a
 *  secret (a secret's stored `value` is a placeholder, and is never shown). */
export function storedText(decl: DeclaredKeyView, stored: StoredValueView | undefined): { text: string; asJson: boolean } {
  if (!stored || stored.isSecret || stored.redacted || decl.secret) return { text: '', asJson: false };
  const spec = fieldSpec(decl);
  const asJson = !valueFitsKind(stored.value, spec);
  return { text: textOf(stored.value, spec, asJson), asJson };
}

