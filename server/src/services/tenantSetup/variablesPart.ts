/**
 * Quick Setup Tenant — the variables table, judged row by row.
 *
 * `judgeRows` is PURE given its inputs (the declarations, the references, the
 * stored values, the sites), so the harness runs it on fixtures. It decides,
 * per row, whether it is valid, which site it lands on, whether it is a
 * secret, and what it would do (create / update / unchanged / set_secret /
 * keep), and it returns the WRITES the apply hands to the resolver's own
 * writers — `setInstanceBulk`, `setBulk` — which judge every entry again
 * (`assertWritable`) and send a secret to the vault.
 *
 * The judges it composes are the existing ones: `storedVariableKey` and
 * `setVariableSchema` (the API boundary of every variables write), and
 * `judgeValueAgainstSchema` (the site form's ajv cut, at any level). A value
 * is checked against EVERY reference that declares its key, as the site form
 * does: a value must satisfy each revision that may render it.
 *
 * Secrecy is the row's flag OR the declaration's OR the stored value's, in
 * that one direction: a declaration or a secret already in the vault routes a
 * value to the vault, never a secret to clear. A row flagged secret for a key
 * declared NOT secret is refused, because every render refuses a stored
 * secret the template does not declare; and so is an unflagged row that would
 * replace a stored secret under a declaration that says clear
 * (VAR_SECRET_DOWNGRADE) — that move is made on the Variables page, on purpose.
 *
 * NOTHING returned here carries a value: the row reports have none, the
 * issues name keys, levels and site codes. `writes` carries values, and is
 * internal to the service — never serialised into a response.
 */

import {
  SETUP_VARIABLE_LEVELS,
  type DeclaredKeyView,
  type JsonValue,
  type SetupIssue,
  type SetupRowAction,
  type SetupVariableLevel,
  type SetupVariableRow,
  type SetupVariableRowReport,
} from '@obliwan/shared';
import { setVariableSchema, storedVariableKey } from '../../validators/template.schema';
import { judgeValueAgainstSchema } from '../template/variableResolver.service';
import type { SetupReference } from './declarations';
import { issue } from './issues';

/** A stored value as the redacted reads return it (`ResolvedVariable`). */
export interface StoredValue {
  value: JsonValue;
  isSecret: boolean;
}
export type StoredValues = Record<string, StoredValue>;

/** One row of the sites CSV as the check saw it (index-aligned with the
 *  import's result rows). */
export interface FileSite {
  /** The code the import writes (zeros restored under 'digits:N'). */
  writtenCode: string;
  /** The cell as typed, when the import restored it; else `writtenCode`. */
  originalCode: string;
  rejected: boolean;
  /** `var:` columns whose cell is non-empty. */
  csvKeys: Set<string>;
  /** The existing site this row updates, or null for a create. */
  existingSiteId: number | null;
}

export interface JudgeRowsInput {
  rows: readonly SetupVariableRow[];
  declarations: ReadonlyMap<string, DeclaredKeyView>;
  refs: readonly SetupReference[];
  stored: { instance: StoredValues; global: StoredValues; tenant: StoredValues };
  /** Stored site values by site id (existing sites only). */
  siteValues: ReadonlyMap<number, StoredValues>;
  /** The sites file's rows; empty when the sites part is not selected. */
  fileSites: readonly FileSite[];
  /** The tenant's existing sites among the codes the rows name: code -> id. */
  existingSites: ReadonlyMap<string, number>;
}

/** One value to write, grouped by the apply. */
export interface RowWrite {
  index: number;
  level: SetupVariableLevel;
  /** Site level: the code the site is (or will be) written under. */
  siteCode: string | null;
  key: string;
  value: JsonValue;
  isSecret: boolean;
}

export interface JudgeRowsResult {
  rows: SetupVariableRowReport[];
  /** By row index: the code a site row lands on (the file's written code or
   *  an existing site's), null for other levels and unresolved rows. */
  siteCodes: Array<string | null>;
  issues: SetupIssue[];
  /** Valid rows with a value whose action is not 'unchanged'. */
  writes: RowWrite[];
  /** Instance rows that carry a value (the acknowledgement's count). */
  instanceValueRows: number;
}

function own<T>(map: Record<string, T> | undefined, key: string): T | undefined {
  return map && Object.prototype.hasOwnProperty.call(map, key) ? map[key] : undefined;
}

/** Key-order-independent JSON, as the site import compares a cell with a
 *  stored value. */
function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v !== null && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`).join(',')}}`;
  }
  return JSON.stringify(v) ?? 'null';
}

const STORED_LEVELS: ReadonlySet<string> = new Set(['instance', 'global', 'tenant', 'group', 'site', 'device']);

export function judgeRows(input: JudgeRowsInput): JudgeRowsResult {
  const issues: SetupIssue[] = [];
  const reports: SetupVariableRowReport[] = [];
  const writes: RowWrite[] = [];
  const firstAt = new Map<string, number>();
  const siteCodes: Array<string | null> = [];
  let instanceValueRows = 0;

  // A site code may be typed as written or as the CSV cell before its zeros
  // were restored; both find the file's row. Later rows of the same code do
  // not override the first (the import refuses them anyway).
  const fileByCode = new Map<string, FileSite>();
  for (const s of input.fileSites) {
    if (s.writtenCode !== '' && !fileByCode.has(s.writtenCode)) fileByCode.set(s.writtenCode, s);
  }
  for (const s of input.fileSites) {
    if (s.originalCode !== '' && !fileByCode.has(s.originalCode)) fileByCode.set(s.originalCode, s);
  }

  input.rows.forEach((row, index) => {
    const line = row.line ?? null;
    const scopeText = typeof row.scopeRef === 'string' ? row.scopeRef.trim() : '';
    const where = { index, line };
    const report: SetupVariableRowReport = {
      index,
      line,
      level: row.level,
      scopeRef: scopeText === '' ? null : scopeText,
      key: row.key,
      secret: row.secret === true,
      secretForced: false,
      siteId: null,
      action: 'invalid',
    };
    reports.push(report);

    if (!(SETUP_VARIABLE_LEVELS as readonly string[]).includes(row.level)) {
      issues.push(issue('VAR_LEVEL_UNSUPPORTED', 'variables', { ...where, level: row.level }));
      siteCodes[index] = null;
      return;
    }
    const level = row.level as SetupVariableLevel;
    let bad = false;

    const keyCheck = storedVariableKey.safeParse(row.key);
    if (!keyCheck.success) {
      bad = true;
      for (const i of keyCheck.error.issues) {
        issues.push(issue('VAR_ROW_INVALID', 'variables', { ...where, field: 'key', message: i.message }));
      }
    }

    // ── the scope ───────────────────────────────────────────────────────────
    let siteCode: string | null = null;
    let siteId: number | null = null;
    let fileSite: FileSite | null = null;
    if (level === 'site') {
      if (scopeText === '') {
        bad = true;
        issues.push(issue('VAR_SCOPE_REF_REQUIRED', 'variables', { ...where }));
      } else {
        const inFile = fileByCode.get(scopeText);
        if (inFile) {
          if (inFile.rejected) {
            bad = true;
            issues.push(issue('VAR_SITE_ROW_REJECTED', 'variables', { ...where, scopeRef: scopeText }));
          } else {
            fileSite = inFile;
            siteCode = inFile.writtenCode;
            siteId = inFile.existingSiteId;
          }
        } else {
          const id = input.existingSites.get(scopeText);
          if (id === undefined) {
            bad = true;
            issues.push(issue('VAR_SITE_UNKNOWN', 'variables', { ...where, scopeRef: scopeText }));
          } else {
            siteCode = scopeText;
            siteId = id;
          }
        }
      }
    } else if (scopeText !== '') {
      bad = true;
      issues.push(issue('VAR_SCOPE_REF_FORBIDDEN', 'variables', { ...where, level }));
    }
    report.siteId = siteId;
    siteCodes[index] = siteCode;

    // ── the declaration ─────────────────────────────────────────────────────
    const decl = input.declarations.get(row.key);
    const declaredBy = decl ? decl.declaredBy.map((d) => d.name) : [];
    if (decl && (decl.level === 'computed' || decl.level === 'bench')) {
      bad = true;
      issues.push(issue('VAR_RENDER_TIME_KEY', 'variables', { ...where, key: row.key, level: decl.level }));
    }
    if (decl?.secrecyConflict) {
      bad = true;
      issues.push(issue('VAR_SECRECY_CONFLICT', 'variables', { ...where, key: row.key, declaredBy }));
    }
    const hasValue = Object.prototype.hasOwnProperty.call(row, 'value') && row.value !== undefined;
    // The row this one would replace, redacted (an existing site's, or the
    // wide level's); none for a site the sites file creates.
    const storedAt =
      level === 'site'
        ? siteId === null ? undefined : input.siteValues.get(siteId)
        : input.stored[level];
    const cur = keyCheck.success ? own(storedAt, row.key) : undefined;

    let effectiveSecret = row.secret === true || decl?.secret === true;
    if (row.secret === true && decl && !decl.secret && !decl.secrecyConflict) {
      bad = true;
      issues.push(issue('VAR_SECRET_NOT_DECLARED', 'variables', { ...where, key: row.key, declaredBy }));
    }
    if (row.secret !== true && decl?.secret === true) {
      report.secretForced = true;
      issues.push(issue('VAR_SECRET_FORCED', 'variables', { ...where, key: row.key }));
    }
    // A value stored as a secret is never replaced by a clear one. The
    // `secret` column is optional in the CSV, so an absent or unticked flag is
    // not a decision to move a credential out of the vault, and the writer
    // (`upsertVariable`) would honour it: it only ever upgrades a key a
    // published revision declares secret. The clear column of an instance row
    // is readable by every tenant's TEMPLATE_READ users, and a clear
    // `ppp_password` breaks every 'shared' PPP rule. When no reference
    // declares the key, the stored secrecy wins (VAR_SECRET_KEPT). When one
    // declares it CLEAR, keeping it secret would leave a value every render
    // refuses, so the row is refused instead: deleting the stored secret on
    // the Variables page is the deliberate act that downgrade takes.
    if (hasValue && cur?.isSecret === true && !effectiveSecret) {
      if (!decl) {
        effectiveSecret = true;
        report.secretForced = true;
        issues.push(issue('VAR_SECRET_KEPT', 'variables', { ...where, key: row.key, level }));
      } else if (!decl.secrecyConflict && decl.level !== 'computed' && decl.level !== 'bench') {
        // (A secrecy conflict and a render-time key are refused above.)
        bad = true;
        issues.push(issue('VAR_SECRET_DOWNGRADE', 'variables', { ...where, key: row.key, level, declaredBy }));
      }
    }
    report.secret = effectiveSecret;

    // ── the value ───────────────────────────────────────────────────────────
    if (hasValue) {
      const parsed = setVariableSchema.safeParse({ key: row.key, value: row.value, isSecret: effectiveSecret });
      if (!parsed.success) {
        // The key's own refusals were reported above; zod's messages here are
        // built from the rule, never from the value.
        const valueIssues = parsed.error.issues.filter((i) => i.path[0] !== 'key');
        if (valueIssues.length > 0) bad = true;
        for (const i of valueIssues) {
          issues.push(issue('VAR_ROW_INVALID', 'variables', { ...where, field: 'value', message: i.message }));
        }
      } else if (decl) {
        for (const ref of input.refs) {
          const verdict = judgeValueAgainstSchema(ref.decl.varSchema, row.key, row.value, {
            secret: effectiveSecret,
          });
          if (verdict.uncheckable) {
            issues.push(issue('VAR_TYPE_UNCHECKABLE', 'variables', { ...where, key: row.key, declaredBy: ref.name }));
          } else if (verdict.reasons.length > 0) {
            bad = true;
            issues.push(issue('VAR_TYPE', 'variables', {
              ...where, key: row.key, level, reasons: verdict.reasons, declaredBy: ref.name,
            }));
          }
        }
      }
    }

    if (!decl && input.refs.length > 0) {
      issues.push(issue('VAR_UNDECLARED', 'variables', { ...where, key: row.key }));
    }
    if (decl && decl.level !== null && STORED_LEVELS.has(decl.level) && decl.level !== level) {
      issues.push(issue('VAR_LEVEL_DIFFERS', 'variables', { ...where, key: row.key, declared: decl.level, row: level }));
    }

    // ── duplicates ──────────────────────────────────────────────────────────
    const scopeKnown = level !== 'site' || siteCode !== null;
    if (scopeKnown && keyCheck.success) {
      const id = `${level}\u0000${siteCode ?? ''}\u0000${row.key}`;
      const first = firstAt.get(id);
      if (first !== undefined) {
        bad = true;
        issues.push(issue('VAR_DUPLICATE', 'variables', {
          ...where, key: row.key, level, scopeRef: siteCode, firstIndex: first,
        }));
      } else firstAt.set(id, index);
    }
    if (fileSite && hasValue && fileSite.csvKeys.has(row.key)) {
      bad = true;
      issues.push(issue('VAR_SITE_DUP_WITH_CSV', 'variables', { ...where, key: row.key, scopeRef: siteCode }));
    }

    // ── what it would do ────────────────────────────────────────────────────
    let action: SetupRowAction;
    if (bad) action = 'invalid';
    else if (!hasValue) action = 'keep';
    // Never compared: comparing would mean decrypting the stored one.
    else if (effectiveSecret) action = 'set_secret';
    // `cur` is clear here: a stored secret made the row secret or refused it.
    else if (!cur) action = 'create';
    else action = canonical(cur.value) === canonical(row.value) ? 'unchanged' : 'update';
    report.action = action;

    if (level === 'instance' && hasValue) instanceValueRows += 1;
    if (action === 'create' || action === 'update' || action === 'set_secret') {
      writes.push({
        index,
        level,
        siteCode,
        key: row.key,
        value: row.value as JsonValue,
        isSecret: effectiveSecret,
      });
    }
  });

  return { rows: reports, siteCodes, issues, writes, instanceValueRows };
}
