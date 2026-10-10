/**
 * ObliWAN — Quick Setup Tenant: the shared contract.
 *
 * Prepares ONE customer workspace (the session's current tenant) from up to
 * four optional parts: a variables table, a template file (.owt.json), the
 * site list (the ordinary site-import CSV) and the tenant's allocation rule.
 * One dry run judges every selected part together with the cross-checks
 * between them; the apply writes the parts one after the other, each through
 * the service that already writes it (server/src/services/tenantSetup/).
 *
 * This module holds the types both sides speak, the file formats, and the
 * PURE helpers both sides run: the client parses the variables CSV and draws
 * its live requirement panel with them, the server judges with the same ones.
 * No I/O here.
 *
 * ┌─ What this file promises ─────────────────────────────────────────────────┐
 * │ • No type in it carries a secret VALUE back to a browser: report rows    │
 * │   have no value field and issues carry key names, levels, codes and     │
 * │   counts only. A secret travels in a REQUEST body and nowhere else.       │
 * │ • An EMPTY cell never erases: in a variables row it means "keep what is  │
 * │   stored" (`value` absent), exactly as the site import reads an empty     │
 * │   cell. A CSV therefore cannot set an empty string; JSON can.            │
 * │ • Emptiness is decided on TRIMMED text, never by `Number()`:             │
 * │   `Number(' ')` is 0.                                                     │
 * └───────────────────────────────────────────────────────────────────────────┘
 */

// ============================================================================
// Constants
// ============================================================================

export const TENANT_SETUP_FORMAT = 'obliwan-tenant-setup/1' as const;
export const VARIABLES_FILE_FORMAT = 'obliwan-variables/1' as const;
export const POLICY_FILE_FORMAT = 'obliwan-allocation-policy/1' as const;

/** The four parts an operator may select. A part is selected iff present. */
export const SETUP_PARTS = ['variables', 'template', 'allocationPolicy', 'sites'] as const;
export type SetupPart = (typeof SETUP_PARTS)[number];

/**
 * The APPLY order. Not the order the parts are listed in, on purpose:
 *  - the site import judges `var:` columns against PUBLISHED declarations
 *    only, so the sites go after `publish`;
 *  - site-level variable rows need their site to exist, so they go last;
 *  - a secret written before publication takes its secrecy from the uploaded
 *    template (the request says so), not from the published ones;
 *  - a 'shared' PPP password rule needs the instance secret `ppp_password`
 *    stored first, so the variables go before the rule;
 *  - the template is imported as a DRAFT first and published only once its
 *    inputs exist, because the bench offers every published revision.
 */
export const SETUP_STEPS = [
  'template',
  'variables',
  'allocationPolicy',
  'publish',
  'sites',
  'siteVariables',
] as const;
export type SetupStep = (typeof SETUP_STEPS)[number];

/** The levels a setup row may target. group/device are edited on the
 *  Variables page (VAR_LEVEL_UNSUPPORTED). */
export const SETUP_VARIABLE_LEVELS = ['instance', 'global', 'tenant', 'site'] as const;
export type SetupVariableLevel = (typeof SETUP_VARIABLE_LEVELS)[number];

export const MAX_SETUP_VARIABLE_ROWS = 2000;
/** app.ts's `express.json({ limit: '1mb' })`. The client checks
 *  `JSON.stringify(body).length` against it before sending. */
export const MAX_SETUP_BODY_CHARS = 1_000_000;
/** At most this many existing revisions may be named as references. */
export const MAX_SETUP_REFERENCE_REVISIONS = 10;

/**
 * What the allocator ALWAYS supplies at render time for an allocated site
 * (allocator.ts `computedValues` + the compile path's `ppp_password`).
 * `lan_subnet` and `system_identity` are conditional on the rule
 * (`computedSuppliedKeys`), and the rule's derived values come on top.
 */
export const ALLOCATOR_COMPUTED_KEYS = ['site_code', 'ppp_username', 'tunnel_ip', 'ppp_password'] as const;

// ============================================================================
// Types
// ============================================================================

/** JSON and nothing but JSON (`undefined` is not a value: it means "absent"). */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [k: string]: JsonValue };

export interface SetupVariableRow {
  /** Judged server-side; one of SETUP_VARIABLE_LEVELS to be valid. The CSV
   *  parser accepts 'client' as an alias of 'tenant'. */
  level: string;
  /** The site CODE for level 'site'; null otherwise. */
  scopeRef: string | null;
  key: string;
  /** ABSENT = keep what is stored (nothing written). JSON null is a value. */
  value?: JsonValue;
  /** The file's or the designer's flag. A declaration, or a value already
   *  stored as a secret at the same place, can only force it to true, never
   *  back to false. */
  secret: boolean;
  /** 1-based line in the source CSV, for messages. */
  line?: number;
}

/** The allocation rule as a file: the PUT /allocation/.../policy body, with
 *  pools and the concentrator designated by NAME as an alternative to their
 *  ids (a name is portable between installations, an id is not). When both
 *  are given they must agree. */
export interface SetupPolicyFile {
  format?: typeof POLICY_FILE_FORMAT;
  tunnel: {
    poolId?: number;
    poolName?: string;
    mode: 'incremental' | 'formula';
    start?: string;
    formula?: string;
  };
  lan:
    | null
    | {
        mode: 'incremental' | 'formula' | 'fixed' | 'manual';
        poolId?: number;
        poolName?: string;
        prefix?: number;
        formula?: string;
        subnet?: string;
        variable?: string;
      };
  pppLoginTemplate: string;
  systemIdentityTemplate?: string | null;
  pppPasswordMode?: 'shared' | 'per_site';
  derived?: Record<string, string> | null;
  pppProfile?: string | null;
  concentratorId?: number;
  concentratorName?: string;
  /** ABSENT = the stored format is kept (upsertPolicy's own semantics). */
  siteCodeFormat?: string;
}

/**
 * The workspace a request was PREPARED for, compared with the session's.
 *
 * The setup acts on the session's current workspace (`req.tenantId`), which
 * lives server-side in the session and is therefore shared by every tab of the
 * browser: a workspace switch in another tab would otherwise send drafts
 * checked and shown for customer A to customer B. `expectedTenantId` never
 * CHOOSES a workspace. The server only compares it with the session's and,
 * before reading or writing anything, refuses with 409 and
 * `code: SETUP_TENANT_MISMATCH` when they differ.
 */
export const SETUP_TENANT_MISMATCH = 'TENANT_MISMATCH' as const;

/** The body of POST /api/tenant-setup/context. */
export interface TenantSetupContextRequest {
  /** See SETUP_TENANT_MISMATCH. */
  expectedTenantId: number;
  /** A parsed obliwan-template/1 or obliwan-template-bundle/1. */
  template?: unknown;
  referenceRevisionIds?: string[];
}

/** The body of POST /api/tenant-setup/check and /apply. */
export interface TenantSetupRequest {
  /** The workspace the drafts were prepared for (see SETUP_TENANT_MISMATCH). */
  expectedTenantId: number;
  /** A part is SELECTED iff present; at least one. */
  parts: {
    variables?: { rows: SetupVariableRow[] };
    /** `file` = a parsed obliwan-template/1 or obliwan-template-bundle/1. */
    template?: { file: unknown; publish: boolean };
    allocationPolicy?: { policy: SetupPolicyFile };
    /** The ordinary site-import CSV (code,name,country,timezone,address,contact,var:<key>…). */
    sites?: { csv: string; allocate: boolean };
  };
  /** Existing revisions the cross-check types values against (the designer's
   *  "pick a template"). At most MAX_SETUP_REFERENCE_REVISIONS. */
  referenceRevisionIds?: string[];
  /** Required on APPLY when any instance row carries a value. */
  acknowledgeInstanceScope?: boolean;
}

/** The single-file form. A CLIENT-side container: the API body carries the
 *  parts directly (`TenantSetupRequest`). */
export interface TenantSetupBundle {
  format: typeof TENANT_SETUP_FORMAT;
  exportedAt?: string;
  /** INFORMATIONAL ONLY. Never used to choose a tenant: the setup always
   *  acts on the session's current workspace. */
  tenant?: { name: string; slug: string };
  variables?: { format: typeof VARIABLES_FILE_FORMAT; rows: SetupVariableRow[] };
  template?: unknown;
  publish?: boolean;
  allocationPolicy?: SetupPolicyFile;
  sites?: { csv: string; allocate?: boolean };
}

export type IssueSeverity = 'error' | 'warning' | 'info';

/** Every cross-check code, by severity (the severity is fixed per code). */
export const SETUP_ISSUE_SEVERITY = {
  // errors — variables
  VAR_LEVEL_UNSUPPORTED: 'error',
  VAR_ROW_INVALID: 'error',
  VAR_SCOPE_REF_REQUIRED: 'error',
  VAR_SCOPE_REF_FORBIDDEN: 'error',
  VAR_SITE_UNKNOWN: 'error',
  VAR_SITE_ROW_REJECTED: 'error',
  VAR_DUPLICATE: 'error',
  VAR_SITE_DUP_WITH_CSV: 'error',
  VAR_TYPE: 'error',
  VAR_RENDER_TIME_KEY: 'error',
  VAR_SECRET_NOT_DECLARED: 'error',
  VAR_SECRECY_CONFLICT: 'error',
  VAR_SECRET_DOWNGRADE: 'error',
  INSTANCE_NOT_ACKNOWLEDGED: 'error',
  // errors — template / setup
  TEMPLATE_FORMAT: 'error',
  TEMPLATE_ENTRY_INVALID: 'error',
  PUBLISH_DEPENDENCY: 'error',
  REFERENCE_REVISION_NOT_FOUND: 'error',
  // errors — allocation rule
  POLICY_FIELD_UNKNOWN: 'error',
  POLICY_REF: 'error',
  POLICY_INVALID: 'error',
  // errors — sites
  SITES_FILE: 'error',
  SITES_ROWS_REJECTED: 'error',
  SITE_VAR_NEEDS_PUBLISH: 'error',
  ALLOCATE_WITHOUT_POLICY: 'error',
  // warnings
  MASTER_TENANT: 'warning',
  INSTANCE_ROWS: 'warning',
  SLUG_FREEZES: 'warning',
  VAR_TYPE_UNCHECKABLE: 'warning',
  INSTANCE_SHADOWS_DEFAULT: 'warning',
  STORED_SECRECY_MISMATCH: 'warning',
  OTHER_PUBLISHED: 'warning',
  DERIVED_NOT_COMPUTED: 'warning',
  REQUIREMENTS_INCOMPLETE: 'warning',
  NO_REFERENCE_TEMPLATE: 'warning',
  // info
  VAR_SECRET_FORCED: 'info',
  VAR_SECRET_KEPT: 'info',
  VAR_UNDECLARED: 'info',
  VAR_LEVEL_DIFFERS: 'info',
  DERIVED_UNDECLARED: 'info',
  SITES_CODE_FORMAT_OVERRIDE: 'info',
  CHR_COMPARE_STORED_RULE: 'info',
} as const satisfies Record<string, IssueSeverity>;

export type SetupIssueCode = keyof typeof SETUP_ISSUE_SEVERITY;
export const SETUP_ISSUE_CODES = Object.keys(SETUP_ISSUE_SEVERITY) as SetupIssueCode[];

export type SetupIssueParam =
  | string
  | number
  | boolean
  | string[]
  | Record<string, string[]>
  | null;

/**
 * One finding. The client translates `quickSetup.issue.<code>` with `params`
 * as interpolation values (arrays joined with ", "); `message` is the English
 * fallback built server-side from the same params. Never a value.
 */
export interface SetupIssue {
  severity: IssueSeverity;
  code: SetupIssueCode;
  part: SetupPart | 'setup';
  params: Record<string, SetupIssueParam>;
  message: string;
}

/** One declared key, merged across the reference schemas (newest first). */
export interface DeclaredKeyView {
  key: string;
  /** `x-obliwan-level` of the newest declaration; null = none stated (a
   *  render treats it as 'device'). */
  level: string | null;
  label: string | null;
  description: string | null;
  /** true when ANY declaration marks it `x-obliwan-secret`. */
  secret: boolean;
  /** In the `required` array of ANY reference schema. */
  required: boolean;
  /** The newest declaration's property schema. */
  schema: Record<string, unknown>;
  hasDefault: boolean;
  /** Never present for a secret (a secret has no default). */
  default?: JsonValue;
  /** The declarations disagree on `x-obliwan-secret`. */
  secrecyConflict: boolean;
  /** false when two declarations of the key differ. */
  consistent: boolean;
  declaredBy: Array<{
    name: string;
    revisionId: string | null;
    revision: number | null;
    source: 'file' | 'stored';
  }>;
}

export type RequirementLevel =
  | 'instance'
  | 'global'
  | 'tenant'
  | 'group'
  | 'site'
  | 'device'
  | 'computed'
  | 'bench';

export const REQUIREMENT_LEVELS: readonly RequirementLevel[] = [
  'instance', 'global', 'tenant', 'group', 'site', 'device', 'computed', 'bench',
];

export interface RequirementMissing {
  key: string;
  /** Site level: the codes of the sites that lack it (first 50). */
  sites?: string[];
  sitesTotal?: number;
  reason: 'not_set' | 'not_supplied' | 'no_policy' | 'policy_refused';
}

export interface RequirementReport {
  /** No missing key at any CHECKED level. */
  complete: boolean;
  levels: Array<{
    level: RequirementLevel;
    /** Required keys whose effective level is this one (no level = 'device'). */
    required: string[];
    /** false for group, device and bench: not knowable from a setup. */
    checked: boolean;
    missing: RequirementMissing[];
  }>;
}

/** A stored value in its REDACTED form: a secret's `value` is the placeholder. */
export interface StoredValueView {
  value: JsonValue;
  isSecret: boolean;
  redacted: boolean;
  fingerprint: unknown;
}

export interface SetupTemplateSummary {
  templateId: string;
  name: string;
  brand: string;
  status: string;
  /** A shipped library template (no tenant). */
  library: boolean;
  revisions: Array<{ id: string; revision: number; status: string; publishedAt: string | null }>;
}

/** What POST /api/tenant-setup/context returns. Values are redacted. */
export interface TenantSetupContext {
  tenant: { id: number; name: string; slug: string; slugFrozen: boolean; isMaster: boolean };
  declarations: DeclaredKeyView[];
  references: Array<{
    kind: 'file' | 'revision' | 'published';
    name: string;
    revisionId: string | null;
    revision: number | null;
    status: string | null;
  }>;
  values: {
    instance: Record<string, StoredValueView>;
    global: Record<string, StoredValueView>;
    tenant: Record<string, StoredValueView>;
  };
  sites: Array<{
    id: number;
    code: string;
    name: string;
    country: string | null;
    timezone: string | null;
    address: string | null;
    contact: string | null;
    values: Record<string, StoredValueView>;
  }>;
  /** The server's AllocationPolicyView plus the concentrator's name. */
  policy: (Record<string, unknown> & { concentratorName: string | null }) | null;
  /** The server's AddressPoolView[]. */
  pools: Array<Record<string, unknown> & { id: number; name: string; cidr: string; purpose: string }>;
  concentrators: Array<{ id: number; name: string; tenantId: number }>;
  instanceDomain: string;
  templates: SetupTemplateSummary[];
  limits: { maxVariableRows: number; maxSiteRows: number; maxBodyChars: number };
}

export type SetupRowAction = 'create' | 'update' | 'unchanged' | 'set_secret' | 'keep' | 'invalid';

export interface SetupVariableRowReport {
  /** Position in the request's rows, 0-based. */
  index: number;
  line: number | null;
  level: string;
  scopeRef: string | null;
  key: string;
  /** The EFFECTIVE secrecy: the row's flag, the declaration's, or a value
   *  already stored as a secret at the same place. */
  secret: boolean;
  /** The declaration, or the secret already stored there, made it secret
   *  although the row did not say so (VAR_SECRET_FORCED / VAR_SECRET_KEPT). */
  secretForced: boolean;
  siteId: number | null;
  action: SetupRowAction;
  /** Apply only: the row's value was written. */
  applied?: boolean;
}

export type SetupPublishAction =
  | 'publish_new_draft'
  | 'publish_existing_draft'
  | 'already_published'
  | 'none';

export interface SetupStepResult {
  step: SetupStep;
  status: 'done' | 'failed' | 'not_run';
  summary: Record<string, number>;
  message?: string;
}

/** What /check and /apply return. */
export interface TenantSetupReport {
  dryRun: boolean;
  tenant: { id: number; name: string; slug: string };
  selected: SetupPart[];
  /** The steps that will run (check) or ran (apply), in SETUP_STEPS order. */
  steps: SetupStep[];
  /** No issue with severity 'error'. */
  canApply: boolean;
  issues: SetupIssue[];
  requirements: RequirementReport;
  /** What the check typed against (the same builder as the context). */
  declarations: DeclaredKeyView[];
  variables?: { rows: SetupVariableRowReport[] };
  template?: {
    /** The server's ImportReport (= the client's TemplateImportReport). */
    report: unknown;
    publish: {
      requested: boolean;
      plan: Array<{
        index: number;
        name: string;
        action: SetupPublishAction;
        revisionId: string | null;
        revision: number | null;
      }>;
      results?: Array<{
        index: number;
        revisionId: string;
        revision: number;
        status: 'published' | 'failed';
        message?: string;
      }>;
    };
  };
  allocationPolicy?: {
    /** The rule with ids resolved from names; null when a reference did not resolve. */
    resolved: Record<string, unknown> | null;
    ok: boolean;
    error?: { reason: string; message: string; details: Record<string, string[]> };
    /** Apply only: the saved AllocationPolicyView. */
    saved?: unknown;
  };
  /** The server's SiteImportResult (= the client's SiteImportResult). */
  sites?: { result: unknown };
  siteVariables?: { sites: Array<{ code: string; siteId: number | null; keys: string[]; applied: boolean }> };
  /** Apply only. */
  outcome?: 'applied' | 'failed';
  stepResults?: SetupStepResult[];
}

// ============================================================================
// Delimited text (CSV / TSV)
// ============================================================================

export type SetupDelimiter = ',' | ';' | '\t';

export interface DelimitedRecord {
  /** 1-based line on which the record STARTS (a quoted cell may span lines). */
  line: number;
  cells: string[];
}

export type DelimitedParse =
  | { delimiter: SetupDelimiter; records: DelimitedRecord[] }
  | { error: { line: number; problem: 'unterminated_quote' } };

/** The one that occurs most often outside quotes on the first line; ',' wins
 *  ties — siteImport.service's `detectDelimiter`, verbatim. */
function detectDelimiter(text: string): SetupDelimiter {
  const counts: Record<SetupDelimiter, number> = { ',': 0, ';': 0, '\t': 0 };
  let inQuotes = false;
  for (const ch of text) {
    if (ch === '"') inQuotes = !inQuotes;
    else if (!inQuotes && (ch === '\n' || ch === '\r')) break;
    else if (!inQuotes && (ch === ',' || ch === ';' || ch === '\t')) counts[ch] += 1;
  }
  let best: SetupDelimiter = ',';
  for (const d of [';', '\t'] as const) if (counts[d] > counts[best]) best = d;
  return best;
}

/**
 * RFC 4180, leniently — the same reading as siteImport.service's `parseCsv`,
 * which stays the VERDICT for a sites file (the server parses it again): the
 * BOM is stripped, every cell is trimmed, CRLF and LF both end a line, a
 * quoted cell may hold the delimiter, newlines and doubled quotes, a quote in
 * the middle of an unquoted cell is kept literally. Blank records are kept:
 * the caller decides what a blank line means.
 *
 * `delimiter` forces one (a paste from Excel is tab-separated whatever its
 * first line looks like); absent, it is detected.
 */
export function parseDelimited(text: string, opts: { delimiter?: SetupDelimiter } = {}): DelimitedParse {
  const body = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  const delimiter = opts.delimiter ?? detectDelimiter(body);
  const records: DelimitedRecord[] = [];
  let cells: string[] = [];
  let cell = '';
  let inQuotes = false;
  let quotedCell = false;
  let line = 1;
  let recordLine = 1;
  let quoteOpenedOn = 0;

  const endCell = (): void => {
    cells.push(cell.trim());
    cell = '';
    quotedCell = false;
  };
  const endRecord = (): void => {
    endCell();
    records.push({ line: recordLine, cells });
    cells = [];
  };

  for (let i = 0; i < body.length; i += 1) {
    const ch = body[i];
    if (inQuotes) {
      if (ch === '"') {
        if (body[i + 1] === '"') {
          cell += '"';
          i += 1;
        } else inQuotes = false;
      } else {
        if (ch === '\n') line += 1;
        cell += ch;
      }
      continue;
    }
    if (ch === '"' && cell.trim() === '' && !quotedCell) {
      inQuotes = true;
      quotedCell = true;
      quoteOpenedOn = line;
      cell = '';
    } else if (ch === delimiter) {
      endCell();
    } else if (ch === '\r' || ch === '\n') {
      if (ch === '\r' && body[i + 1] === '\n') i += 1;
      endRecord();
      line += 1;
      recordLine = line;
    } else if (!(quotedCell && (ch === ' ' || ch === '\t'))) {
      cell += ch;
    }
  }
  if (inQuotes) return { error: { line: quoteOpenedOn, problem: 'unterminated_quote' } };
  if (cell !== '' || cells.length > 0 || quotedCell) endRecord();
  return { delimiter, records };
}

/** A cell that must be quoted to read back as itself. */
function needsQuotes(cell: string, delimiter: string): boolean {
  return (
    cell.includes(delimiter) ||
    cell.includes('"') ||
    cell.includes('\r') ||
    cell.includes('\n') ||
    cell !== cell.trim()
  );
}

/**
 * Rows back to delimited text: a cell holding the delimiter, a quote, CR, LF
 * or a leading/trailing blank is quoted (quotes doubled); lines end with CRLF;
 * the text starts with a BOM so Excel reads it as UTF-8.
 */
export function toDelimited(rows: string[][], delimiter: SetupDelimiter = ';'): string {
  const lines = rows.map((r) =>
    r
      .map((c) => {
        const cell = c ?? '';
        return needsQuotes(cell, delimiter) ? `"${cell.replace(/"/g, '""')}"` : cell;
      })
      .join(delimiter),
  );
  return `﻿${lines.join('\r\n')}\r\n`;
}

// ============================================================================
// Typing a cell
// ============================================================================

function primaryType(prop: Record<string, unknown> | undefined): string | null {
  const t = prop?.type;
  if (typeof t === 'string') return t;
  if (Array.isArray(t)) {
    const first = t.find((x) => typeof x === 'string' && x !== 'null');
    return typeof first === 'string' ? first : null;
  }
  return null;
}

const TRUE_WORDS = ['true', 'vrai', 'oui', 'yes', '1'];
const FALSE_WORDS = ['false', 'faux', 'non', 'no', '0'];

/**
 * A cell is text; a declared variable may be a number, a boolean or a list.
 * Convert ONLY when the text is unambiguously of the declared type and hand
 * the text through otherwise, so the schema refuses it on its type with its
 * own message — siteImport.service's `coerceCell`, rule for rule. An
 * undeclared key stays text. The caller decides emptiness on the trimmed text.
 */
export function coerceVariableCell(text: string, prop: Record<string, unknown> | undefined): JsonValue {
  switch (primaryType(prop)) {
    case 'integer':
      if (/^[+-]?\d{1,15}$/.test(text)) return Number(text);
      return text;
    case 'number':
      if (/^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?$/.test(text)) return Number(text);
      // A French spreadsheet writes "1,5".
      if (/^[+-]?\d+,\d+$/.test(text)) return Number(text.replace(',', '.'));
      return text;
    case 'boolean': {
      const l = text.toLowerCase();
      if (TRUE_WORDS.includes(l)) return true;
      if (FALSE_WORDS.includes(l)) return false;
      return text;
    }
    case 'array':
    case 'object':
      try {
        const parsed = JSON.parse(text) as unknown;
        return parsed !== null && typeof parsed === 'object' ? (parsed as JsonValue) : text;
      } catch {
        return text;
      }
    default:
      return text;
  }
}

// ============================================================================
// The variables table — CSV
// ============================================================================

export const VARIABLES_CSV_COLUMNS = ['level', 'scope_ref', 'key', 'value', 'secret'] as const;
const REQUIRED_VARIABLES_COLUMNS = ['level', 'key', 'value'] as const;

export type VariablesCsvProblemCode =
  | 'missing_column'
  | 'unknown_column'
  | 'bad_secret_flag'
  | 'unterminated_quote'
  | 'too_many_rows';

export interface VariablesCsvProblem {
  line: number;
  code: VariablesCsvProblemCode;
  /** The header text for one of the five known columns, else its 1-based
   *  POSITION — a header line may be missing, and the first data row read as
   *  a header can hold a secret. */
  column?: string;
}

function isBlankRecord(r: DelimitedRecord): boolean {
  return r.cells.every((c) => c === '');
}

/**
 * Read the variables table. Header (any case, any order): `level`, `key`,
 * `value` required; `scope_ref`, `secret` optional; any other column is a
 * problem. Per row: a blank record is skipped; `level` is lower-cased and
 * 'client' read as 'tenant'; an empty `scope_ref` is null; an EMPTY value
 * cell leaves `value` absent (keep what is stored); otherwise the value is
 * typed from the declaration (`coerceVariableCell`) — except a secret (by
 * flag or by declaration), which stays the raw string. A row whose secret
 * flag cannot be read is left out: guessing "not secret" could put a
 * credential in the clear column.
 */
export function parseVariablesCsv(
  text: string,
  declarations: Record<string, DeclaredKeyView>,
): { rows: SetupVariableRow[]; problems: VariablesCsvProblem[] } {
  const parsed = parseDelimited(text);
  if ('error' in parsed) {
    return { rows: [], problems: [{ line: parsed.error.line, code: 'unterminated_quote' }] };
  }
  const records = parsed.records.filter((r) => !isBlankRecord(r));
  if (records.length === 0) {
    return {
      rows: [],
      problems: REQUIRED_VARIABLES_COLUMNS.map((c) => ({ line: 1, code: 'missing_column' as const, column: c })),
    };
  }
  const [header, ...body] = records;
  const problems: VariablesCsvProblem[] = [];
  const index: Partial<Record<(typeof VARIABLES_CSV_COLUMNS)[number], number>> = {};
  header.cells.forEach((raw, i) => {
    const name = raw.trim().toLowerCase();
    const known = (VARIABLES_CSV_COLUMNS as readonly string[]).includes(name)
      ? (name as (typeof VARIABLES_CSV_COLUMNS)[number])
      : null;
    if (!known) {
      problems.push({ line: header.line, code: 'unknown_column', column: String(i + 1) });
      return;
    }
    if (index[known] !== undefined) {
      problems.push({ line: header.line, code: 'unknown_column', column: known });
      return;
    }
    index[known] = i;
  });
  for (const c of REQUIRED_VARIABLES_COLUMNS) {
    if (index[c] === undefined) problems.push({ line: header.line, code: 'missing_column', column: c });
  }
  if (REQUIRED_VARIABLES_COLUMNS.some((c) => index[c] === undefined)) return { rows: [], problems };
  if (body.length > MAX_SETUP_VARIABLE_ROWS) {
    problems.push({ line: body[MAX_SETUP_VARIABLE_ROWS].line, code: 'too_many_rows' });
    return { rows: [], problems };
  }

  const rows: SetupVariableRow[] = [];
  for (const rec of body) {
    const cell = (i: number | undefined): string => (i === undefined ? '' : (rec.cells[i] ?? '').trim());
    const rawLevel = cell(index.level).toLowerCase();
    const level = rawLevel === 'client' ? 'tenant' : rawLevel;
    const key = cell(index.key);
    const scopeText = cell(index.scope_ref);
    const flag = cell(index.secret).toLowerCase();
    let secret: boolean;
    if (flag === '' || FALSE_WORDS.includes(flag)) secret = false;
    else if (TRUE_WORDS.includes(flag)) secret = true;
    else {
      problems.push({ line: rec.line, code: 'bad_secret_flag', column: 'secret' });
      continue;
    }
    const row: SetupVariableRow = {
      level,
      scopeRef: scopeText === '' ? null : scopeText,
      key,
      secret,
      line: rec.line,
    };
    const valueText = cell(index.value);
    if (valueText !== '') {
      const decl = Object.prototype.hasOwnProperty.call(declarations, key) ? declarations[key] : undefined;
      row.value = secret || decl?.secret === true ? valueText : coerceVariableCell(valueText, decl?.schema);
    }
    rows.push(row);
  }
  return { rows, problems };
}

/** A typed value as a CSV cell: text verbatim, a number or boolean as text,
 *  anything else as JSON. */
function valueCell(v: JsonValue | undefined): string {
  if (v === undefined) return '';
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  return JSON.stringify(v);
}

/**
 * The variables table as CSV (';', BOM, CRLF). A secret row ALWAYS has an
 * empty value cell and secret=true: an export never carries a secret, and an
 * empty cell on import means "keep the stored one".
 */
export function variablesToCsv(rows: SetupVariableRow[]): string {
  const out: string[][] = [[...VARIABLES_CSV_COLUMNS]];
  for (const r of rows) {
    out.push([
      r.level,
      r.scopeRef ?? '',
      r.key,
      r.secret ? '' : valueCell(r.value),
      r.secret ? 'true' : 'false',
    ]);
  }
  return toDelimited(out, ';');
}

// ============================================================================
// The bundle
// ============================================================================

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

const BUNDLE_KEYS: ReadonlySet<string> = new Set([
  'format', 'exportedAt', 'tenant', 'variables', 'template', 'publish', 'allocationPolicy', 'sites',
]);
const ROW_KEYS: ReadonlySet<string> = new Set(['level', 'scopeRef', 'key', 'value', 'secret', 'line']);

/** Check one row's SHAPE (not its meaning: the server judges that). */
export function setupRowShapeProblem(raw: unknown, where: string): string | null {
  if (!isRecord(raw)) return `${where} is not an object`;
  const unknown = Object.keys(raw).filter((k) => !ROW_KEYS.has(k));
  if (unknown.length > 0) return `${where} has unknown field(s): ${unknown.join(', ')}`;
  if (typeof raw.level !== 'string') return `${where}.level must be a string`;
  if (typeof raw.key !== 'string') return `${where}.key must be a string`;
  if (raw.scopeRef !== undefined && raw.scopeRef !== null && typeof raw.scopeRef !== 'string') {
    return `${where}.scopeRef must be a string or null`;
  }
  if (raw.secret !== undefined && typeof raw.secret !== 'boolean') return `${where}.secret must be a boolean`;
  if (raw.line !== undefined && !(Number.isInteger(raw.line) && (raw.line as number) > 0)) {
    return `${where}.line must be a positive integer`;
  }
  return null;
}

/** A row read from a JSON file, normalised (scopeRef null, secret false). */
function normaliseRow(raw: Record<string, unknown>): SetupVariableRow {
  const row: SetupVariableRow = {
    level: raw.level as string,
    scopeRef: typeof raw.scopeRef === 'string' && raw.scopeRef.trim() !== '' ? raw.scopeRef : null,
    key: raw.key as string,
    secret: raw.secret === true,
  };
  if ('value' in raw && raw.value !== undefined) row.value = raw.value as JsonValue;
  if (typeof raw.line === 'number') row.line = raw.line;
  return row;
}

/** Read an `obliwan-variables/1` JSON file. */
export function parseVariablesFile(
  obj: unknown,
): { ok: true; rows: SetupVariableRow[] } | { ok: false; problem: string } {
  if (!isRecord(obj)) return { ok: false, problem: 'the variables file is not a JSON object' };
  if (obj.format !== VARIABLES_FILE_FORMAT) {
    return { ok: false, problem: `the variables file's format must be "${VARIABLES_FILE_FORMAT}"` };
  }
  const unknown = Object.keys(obj).filter((k) => k !== 'format' && k !== 'rows');
  if (unknown.length > 0) return { ok: false, problem: `unknown field(s) in the variables file: ${unknown.join(', ')}` };
  if (!Array.isArray(obj.rows)) return { ok: false, problem: 'the variables file has no "rows" array' };
  if (obj.rows.length > MAX_SETUP_VARIABLE_ROWS) {
    return { ok: false, problem: `more than ${MAX_SETUP_VARIABLE_ROWS} variable rows` };
  }
  const rows: SetupVariableRow[] = [];
  for (let i = 0; i < obj.rows.length; i += 1) {
    const p = setupRowShapeProblem(obj.rows[i], `rows[${i}]`);
    if (p) return { ok: false, problem: p };
    rows.push(normaliseRow(obj.rows[i] as Record<string, unknown>));
  }
  return { ok: true, rows };
}

/**
 * Read an `obliwan-tenant-setup/1` bundle: the format, the known members
 * only, and each member's type. The members' CONTENT (the template, the rule,
 * the CSV) is judged by the server's check, as if each had been loaded alone.
 */
export function parseSetupBundle(
  obj: unknown,
): { ok: true; bundle: TenantSetupBundle } | { ok: false; problem: string } {
  if (!isRecord(obj)) return { ok: false, problem: 'the bundle is not a JSON object' };
  if (obj.format !== TENANT_SETUP_FORMAT) {
    return { ok: false, problem: `the bundle's format must be "${TENANT_SETUP_FORMAT}"` };
  }
  const unknown = Object.keys(obj).filter((k) => !BUNDLE_KEYS.has(k));
  if (unknown.length > 0) return { ok: false, problem: `unknown field(s) in the bundle: ${unknown.join(', ')}` };
  const bundle: TenantSetupBundle = { format: TENANT_SETUP_FORMAT };

  if (obj.exportedAt !== undefined) {
    if (typeof obj.exportedAt !== 'string') return { ok: false, problem: 'exportedAt must be a string' };
    bundle.exportedAt = obj.exportedAt;
  }
  if (obj.tenant !== undefined) {
    const t = obj.tenant;
    if (!isRecord(t) || typeof t.name !== 'string' || typeof t.slug !== 'string') {
      return { ok: false, problem: 'tenant must be { name, slug }' };
    }
    bundle.tenant = { name: t.name, slug: t.slug };
  }
  if (obj.variables !== undefined) {
    const v = parseVariablesFile(obj.variables);
    if (!v.ok) return { ok: false, problem: `variables: ${v.problem}` };
    bundle.variables = { format: VARIABLES_FILE_FORMAT, rows: v.rows };
  }
  if (obj.template !== undefined) {
    if (!isRecord(obj.template)) return { ok: false, problem: 'template must be a template file (a JSON object)' };
    bundle.template = obj.template;
  }
  if (obj.publish !== undefined) {
    if (typeof obj.publish !== 'boolean') return { ok: false, problem: 'publish must be a boolean' };
    bundle.publish = obj.publish;
  }
  if (obj.allocationPolicy !== undefined) {
    const p = obj.allocationPolicy;
    if (!isRecord(p)) return { ok: false, problem: 'allocationPolicy must be a JSON object' };
    if (p.format !== undefined && p.format !== POLICY_FILE_FORMAT) {
      return { ok: false, problem: `allocationPolicy.format must be "${POLICY_FILE_FORMAT}"` };
    }
    bundle.allocationPolicy = p as unknown as SetupPolicyFile;
  }
  if (obj.sites !== undefined) {
    const s = obj.sites;
    if (!isRecord(s) || typeof s.csv !== 'string') return { ok: false, problem: 'sites must be { csv, allocate? }' };
    if (s.allocate !== undefined && typeof s.allocate !== 'boolean') {
      return { ok: false, problem: 'sites.allocate must be a boolean' };
    }
    const unknownSites = Object.keys(s).filter((k) => k !== 'csv' && k !== 'allocate');
    if (unknownSites.length > 0) return { ok: false, problem: `unknown field(s) in sites: ${unknownSites.join(', ')}` };
    bundle.sites = { csv: s.csv, ...(s.allocate !== undefined ? { allocate: s.allocate as boolean } : {}) };
  }
  return { ok: true, bundle };
}

// ============================================================================
// Requirements
// ============================================================================

/**
 * The keys an allocation rule supplies at render time — allocator.ts
 * `computedValues` (site_code, ppp_username, tunnel_ip, lan_subnet when the
 * rule has a LAN, system_identity when it has an identity template, then the
 * derived values) plus `ppp_password`, which the compile path adds. null when
 * there is no rule: then no computed key is supplied at all.
 */
export function computedSuppliedKeys(
  p: { hasLan: boolean; hasIdentity: boolean; derivedKeys: string[] } | null,
): Set<string> | null {
  if (p === null) return null;
  const out = new Set<string>(ALLOCATOR_COMPUTED_KEYS);
  if (p.hasLan) out.add('lan_subnet');
  if (p.hasIdentity) out.add('system_identity');
  for (const k of p.derivedKeys) out.add(k);
  return out;
}

const SITE_LIST_MAX = 50;
const CHECKED_LEVELS: ReadonlySet<RequirementLevel> = new Set([
  'instance', 'global', 'tenant', 'site', 'computed',
]);

function requirementLevelOf(level: string | null): RequirementLevel {
  return level !== null && (REQUIREMENT_LEVELS as readonly string[]).includes(level)
    ? (level as RequirementLevel)
    : 'device';
}

/**
 * Which REQUIRED keys would still be missing once the setup is written, by
 * level. One function for the server's check and the designer's live panel.
 *
 *  - instance/global/tenant: present iff the key has a value at one of those
 *    three levels (`wide`: in the request or stored) or a default;
 *  - site: per site, present iff in `wide`, in that site's keys, or defaulted;
 *  - group/device: not knowable here (unchecked), but a key nobody provides
 *    anywhere wide is listed as information;
 *  - computed: supplied by the allocation rule (`computed`), or missing —
 *    every one of them when there is no rule (`policy_refused` when the rule
 *    in the file was refused and nothing is stored to fall back on);
 *  - bench: typed at the bench for one box; never missing here.
 */
export function resolveRequirements(input: {
  declarations: DeclaredKeyView[];
  wide: Set<string>;
  sites: Array<{ code: string; keys: Set<string> }>;
  computed: Set<string> | null;
  computedRefused?: boolean;
}): RequirementReport {
  const levels: RequirementReport['levels'] = REQUIREMENT_LEVELS.map((level) => ({
    level,
    required: [],
    checked: CHECKED_LEVELS.has(level),
    missing: [],
  }));
  const at = new Map(levels.map((l) => [l.level, l]));
  const sorted = [...input.declarations].filter((d) => d.required).sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));

  for (const d of sorted) {
    const level = requirementLevelOf(d.level);
    const entry = at.get(level)!;
    entry.required.push(d.key);
    const wide = input.wide.has(d.key) || d.hasDefault;
    switch (level) {
      case 'instance':
      case 'global':
      case 'tenant':
      case 'group':
      case 'device':
        if (!wide) entry.missing.push({ key: d.key, reason: 'not_set' });
        break;
      case 'site': {
        if (wide) break;
        const lacking = input.sites.filter((s) => !s.keys.has(d.key)).map((s) => s.code);
        if (lacking.length > 0) {
          entry.missing.push({
            key: d.key,
            sites: lacking.slice(0, SITE_LIST_MAX),
            sitesTotal: lacking.length,
            reason: 'not_set',
          });
        }
        break;
      }
      case 'computed':
        if (input.computed === null) entry.missing.push({ key: d.key, reason: input.computedRefused ? 'policy_refused' : 'no_policy' });
        else if (!input.computed.has(d.key)) entry.missing.push({ key: d.key, reason: 'not_supplied' });
        break;
      case 'bench':
        break;
    }
  }
  const complete = levels.every((l) => !l.checked || l.missing.length === 0);
  return { complete, levels };
}
