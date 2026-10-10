import type { TFunction } from 'i18next';
import type { TemplateImportIssue } from '@/api/templates.api';
import type { DefaultError, SchemaProblem, VarKind } from './varSchemaModel';

/**
 * Words for the template screens. The person reading them is not assumed to
 * know JSON Schema: a kind is "Text" or "IPv4 address", never `type: string,
 * format: ipv4`, and a refusal names the VARIABLE, never a JSON path.
 *
 * Every key is written out literally so the translation pass can find it.
 */

export function kindLabel(t: TFunction, kind: VarKind): string {
  switch (kind) {
    case 'string': return t('templates.kind.string', { defaultValue: 'Text' });
    case 'integer': return t('templates.kind.integer', { defaultValue: 'Whole number' });
    case 'boolean': return t('templates.kind.boolean', { defaultValue: 'Yes / No' });
    case 'enum': return t('templates.kind.enum', { defaultValue: 'List of choices' });
    case 'ipv4': return t('templates.kind.ipv4', { defaultValue: 'IPv4 address' });
    case 'cidr': return t('templates.kind.cidr', { defaultValue: 'Network (CIDR)' });
    case 'array': return t('templates.kind.array', { defaultValue: 'List' });
    case 'other':
    default: return t('templates.kind.other', { defaultValue: 'Other (advanced JSON)' });
  }
}

export function levelLabel(t: TFunction, level: string): string {
  switch (level) {
    case 'instance': return t('templates.level.instance', { defaultValue: 'Platform (all customers)' });
    case 'global': return t('templates.level.global', { defaultValue: 'Global (this customer)' });
    case 'tenant': return t('templates.level.tenant', { defaultValue: 'Customer' });
    case 'group': return t('templates.level.group', { defaultValue: 'Group' });
    case 'site': return t('templates.level.site', { defaultValue: 'Site' });
    case 'device': return t('templates.level.device', { defaultValue: 'Router' });
    case 'computed': return t('templates.level.computed', { defaultValue: 'Computed by ObliWAN' });
    case 'bench': return t('templates.level.bench', { defaultValue: 'Typed at the bench' });
    default: return level;
  }
}

export function levelHint(t: TFunction, level: string): string {
  switch (level) {
    case 'instance':
      return t('templates.levelHint.instance', {
        defaultValue: 'One value shared by every customer of this installation, set by a platform administrator.',
      });
    case 'global':
      return t('templates.levelHint.global', { defaultValue: "The customer's widest level: applies to all its routers." });
    case 'tenant':
      return t('templates.levelHint.tenant', { defaultValue: 'Set once for the customer.' });
    case 'group':
      return t('templates.levelHint.group', { defaultValue: 'Set per group of routers.' });
    case 'site':
      return t('templates.levelHint.site', { defaultValue: 'Set per site, in the site form.' });
    case 'device':
      return t('templates.levelHint.device', { defaultValue: 'Set per router.' });
    case 'computed':
      return t('templates.levelHint.computed', {
        defaultValue: 'Never typed: ObliWAN computes it when it renders (for example the PPP user name).',
      });
    case 'bench':
      return t('templates.levelHint.bench', {
        defaultValue: 'Typed at the provisioning bench for one box, and never stored.',
      });
    default:
      return '';
  }
}

export function defaultErrorText(t: TFunction, error: DefaultError, key: string): string {
  switch (error) {
    case 'notInteger':
      return t('templates.defaultError.notInteger', { defaultValue: '"{{key}}": expected a whole number.', key });
    case 'notBoolean':
      return t('templates.defaultError.notBoolean', { defaultValue: '"{{key}}": expected yes or no.', key });
    case 'notInEnum':
      return t('templates.defaultError.notInEnum', {
        defaultValue: '"{{key}}": the value must be one of the listed choices.', key,
      });
    case 'notIpv4':
      return t('templates.defaultError.notIpv4', {
        defaultValue: '"{{key}}": expected an IPv4 address such as 192.168.1.1.', key,
      });
    case 'notCidr':
      return t('templates.defaultError.notCidr', {
        defaultValue: '"{{key}}": expected a network such as 192.168.1.0/24.', key,
      });
    case 'notJson':
      return t('templates.defaultError.notJson', { defaultValue: '"{{key}}": this is not valid JSON.', key });
    case 'notArray':
      return t('templates.defaultError.notArray', {
        defaultValue: '"{{key}}": expected a list (one value per line, or a JSON array).', key,
      });
    case 'secretDefault':
    default:
      return t('templates.defaultError.secretDefault', {
        defaultValue:
          '"{{key}}" is a secret: it cannot have a default value, which would be a password written in clear in the template.',
        key,
      });
  }
}

export function problemText(t: TFunction, p: SchemaProblem): string {
  switch (p.kind) {
    case 'badKey':
      return t('templates.problem.badKey', {
        defaultValue:
          '"{{key}}" is not a valid variable name: start with a lowercase letter, then letters, digits or _ only.',
        key: p.key,
      });
    case 'forbiddenKey':
      return t('templates.problem.forbiddenKey', {
        defaultValue: '"{{key}}" is a reserved word and cannot be a variable name.', key: p.key,
      });
    case 'secretDefault':
      return defaultErrorText(t, 'secretDefault', p.key);
    case 'emptyEnum':
      return t('templates.problem.emptyEnum', {
        defaultValue: '"{{key}}" is a list of choices with no choice in it.', key: p.key,
      });
    case 'defaultNotInEnum':
      return t('templates.problem.defaultNotInEnum', {
        defaultValue: '"{{key}}": the default value is not one of the choices.', key: p.key,
      });
    case 'unknownLevel':
      return t('templates.problem.unknownLevel', {
        defaultValue: '"{{key}}": the level "{{level}}" does not exist.', key: p.key, level: p.level,
      });
    case 'factAtStoredLevel':
      return t('templates.problem.factAtStoredLevel', {
        defaultValue:
          '"{{key}}" is a fact read off the box or the site: it can only be declared at the "Computed" or "Typed at the bench" level.',
        key: p.key,
      });
    case 'requiredUndeclared':
    default:
      return t('templates.problem.requiredUndeclared', {
        defaultValue: '"{{key}}" is marked required but is not declared.', key: p.key,
      });
  }
}

/** A file field, in words. */
export function fieldLabel(t: TFunction, field: string): string {
  switch (field) {
    case 'format': return t('templates.field.format', { defaultValue: 'File format' });
    case 'name': return t('templates.field.name', { defaultValue: 'Name' });
    case 'description': return t('templates.field.description', { defaultValue: 'Description' });
    case 'brand': return t('templates.field.brand', { defaultValue: 'Brand' });
    case 'modelPattern': return t('templates.field.modelPattern', { defaultValue: 'Router models' });
    case 'osMin': return t('templates.field.osMin', { defaultValue: 'Minimum RouterOS version' });
    case 'osMax': return t('templates.field.osMax', { defaultValue: 'Maximum RouterOS version' });
    case 'body': return t('templates.field.body', { defaultValue: 'Configuration (body)' });
    case 'varSchema': return t('templates.field.varSchema', { defaultValue: 'Variables' });
    case 'sectionSeverity': return t('templates.field.sectionSeverity', { defaultValue: 'Section severity' });
    case 'renderOptions': return t('templates.field.renderOptions', { defaultValue: 'Render options' });
    case 'notes': return t('templates.field.notes', { defaultValue: 'Notes' });
    default: return field;
  }
}

/** What part of ONE variable a refusal is about (`…properties.<v>.<this>`). */
function variablePartLabel(t: TFunction, part: string | undefined): string | null {
  switch (part) {
    case undefined: return null;
    case 'x-obliwan-level': return t('templates.varPart.level', { defaultValue: 'level' });
    case 'x-obliwan-label': return t('templates.varPart.label', { defaultValue: 'label' });
    case 'x-obliwan-secret': return t('templates.varPart.secret', { defaultValue: 'secret' });
    case 'default': return t('templates.varPart.default', { defaultValue: 'default value' });
    case 'type': return t('templates.varPart.type', { defaultValue: 'type' });
    case 'enum': return t('templates.varPart.enum', { defaultValue: 'choices' });
    case 'pattern': return t('templates.varPart.pattern', { defaultValue: 'expected format' });
    default: return part;
  }
}

/** "Variable « wifi_psk » — default value" / "Name", never a JSON path. */
export function issueWhere(t: TFunction, issue: TemplateImportIssue): string {
  if (issue.variable) {
    const parts = issue.path.split('.');
    const part = variablePartLabel(t, parts[3]);
    return part
      ? t('templates.issue.variablePart', {
        defaultValue: 'Variable "{{variable}}" — {{part}}', variable: issue.variable, part,
      })
      : t('templates.issue.variable', { defaultValue: 'Variable "{{variable}}"', variable: issue.variable });
  }
  if (issue.path === '') return t('templates.issue.whole', { defaultValue: 'Template' });
  return fieldLabel(t, issue.path.split('.')[0]);
}
