// ============================================================================
// ObliWAN — siteRender.service : the bench render, for a router with no row yet
// ============================================================================
//
// `renderForSite()` is the ONE entry point the provisioning bench compiler
// calls: a published template revision, the site the box is being prepared
// for, what ObliWAN computed for that site (the allocator's outputs), what the
// operator typed at the bench (a SIM PIN), and what the bench read off the box
// (its Wi-Fi stack) — in, and the RouterOS text that goes onto the box, out.
//
// ┌─ WHAT THE TEMPLATE SEES ─────────────────────────────────────────────────┐
// │ Every variable the chain resolves for the site — instance -> global ->   │
// │ tenant -> [group] -> site — with the revision's `computed` and `bench`   │
// │ keys taken from the caller's two maps and from nothing else, plus two    │
// │ nested FACT objects:                                                     │
// │   site.code  site.name  site.timezone  [site.country, once migration 036 │
// │              has added the column]                                      │
// │   box.wifi_stack ('wifi' | 'wireless')  [box.board  box.model            │
// │              box.ros_version, when the bench read them]                  │
// │ A revision may DECLARE `site` or `box` at a render-time level to type    │
// │ them (`box: { required: ['wifi_stack'] … }`); it never stores them.      │
// └──────────────────────────────────────────────────────────────────────────┘
//
// ┌─ SECRETS: ONE MECHANISM, THE SPLICE — AND WHY THAT ONE ──────────────────┐
// │ The body is rendered ONCE, with the REDACTED context: every secret is    │
// │ `__OBLIWAN_SECRET_<KEY>__`, which is `[A-Z0-9_]` and therefore passes    │
// │ the sandbox's RouterOS escaper bare and untouched. The plaintexts are     │
// │ then spliced into that text, line by line, by `substituteLine()` from    │
// │ `services/change/renderer/secrets.ts` — the push path's own splice,      │
// │ REUSED, not copied — and each spliced line is re-checked twice there:    │
// │ `assertSubstitutableSecret` judges the VALUE (no whitespace, no control  │
// │ character, none of " \ $ ; [ ] { } or a backtick), and the line          │
// │ assertion this file supplies (`assertSpliceKeepsShape`) judges the       │
// │ RESULT: the substituted line must have exactly the structure the         │
// │ redacted one had.                                                        │
// │                                                                          │
// │ The alternative — rendering a 'secrets' context through the autoescaper  │
// │ — was rejected for three reasons:                                        │
// │  1. TWO MECHANISMS. The push path splices after rendering; a bench that  │
// │     escaped instead would put the same secret on the wire in two textual │
// │     forms (the escaper QUOTES a value with any character outside its     │
// │     bare set — the conversion of one operator template found 3 of its 8 │
// │     secrets would be), and the configuration a box ships with would      │
// │     differ, byte for byte, from what a later push would write.           │
// │  2. THE PLAINTEXT WOULD ENTER THE SANDBOX. A secrets-mode render hands   │
// │     the credential to template code — filters, `fail()` messages, error  │
// │     strings — and anything a template can compute from it can end up in │
// │     an error message. Rendered redacted, the sandbox never holds one.    │
// │  3. ONE REDACTED ARTEFACT. The text that was rendered IS the masked twin │
// │     (`redacted`), so what may be stored for audit is exactly what was    │
// │     rendered, not a second render somebody has to keep in step.         │
// │ The price is the splice's refusal: a secret holding a space, a quote, a  │
// │ `$`… is refused by name rather than escaped, exactly as on the push path.│
// └──────────────────────────────────────────────────────────────────────────┘
//
// ┌─ A SECRET IS INTERPOLATED VERBATIM, OR THE RENDER IS REFUSED ────────────┐
// │ Rendered redacted, a template that computes ON a secret computes on its  │
// │ placeholder: `{{ psk | lower }}` would ship `__obliwan_secret_psk__`,    │
// │ `{{ psk[17:] }}` would ship `PSK__` — a predictable string on every box  │
// │ in place of the credential, or a lockout. Two checks refuse that:        │
// │  - the engine's residue lint refuses an ALTERED placeholder still        │
// │    recognisable as one (case, separators) — on every render path;        │
// │  - here, the PROBE: the body is rendered a second time, each secret      │
// │    replaced by a random mixed-case stand-in of another length that       │
// │    shares neither its first nor its last character. Mapped back, the     │
// │    probe output must equal the redacted output byte for byte, and it     │
// │    must hold no placeholder of its own. Any filter, slice, length,       │
// │    padding or comparison whose result differs between the two forms      │
// │    makes them differ, and so does a placeholder the template text (or a  │
// │    clear value) spelled by hand — the splice would fill a place where no │
// │    secret was interpolated.                                              │
// │ What still passes is an operation that leaves BOTH forms unchanged: a    │
// │ `default(…)`, a `trim`, a branch on whether a secret is defined, or a    │
// │ `replace` of a character neither form contains — on which the plaintext  │
// │ is then spliced as it is, not as the template would have rewritten it.   │
// │ A template that needs a transformed credential stores the transformed    │
// │ value. None of the converted operator templates transforms a secret.     │
// └──────────────────────────────────────────────────────────────────────────┘
//
// The 'secrets' text exists IN MEMORY ONLY. This function never writes
// it, never logs it, and no route returns it; its caller must not either.
// Nothing here persists anything at all — a bench render is not a fleet render
// and does not write `config_renders`.

import crypto from 'crypto';
import type { Knex } from 'knex';
import { db } from '../../db';
import { renderTemplates, type RenderErrorKind, type RenderRequest } from './engine';
import { loadRevisionBundle } from './loader';
import { modelMatches, satisfiesOsWindow } from './assignment.service';
import {
  assertNoStoredSecretInRender, buildSiteRenderContexts, loadSecretsForSite, redactedPlaceholder,
  SECRET_PLACEHOLDER_RE, VariableResolutionError,
  type JsonValue, type MissingVariable, type RenderContext, type ResolvedVariables,
  type VariableReport, type VariableTypeError,
} from './variableResolver.service';
import { substituteLine, type SecretSubstitution } from '../change/renderer/secrets';
import { ChangeError } from '../change/backup.service';

// ============================================================================
// Types
// ============================================================================

/** What the bench read off the box. `wifi_stack` decides between the legacy
 *  `/interface wireless` (wlanN) and the `/interface wifi` (wifiN) syntax. */
export interface BoxFacts {
  wifi_stack: 'wifi' | 'wireless';
  board?: string;
  model?: string;
  ros_version?: string;
}

export interface RenderForSiteOptions {
  /** Mandatory, no default. */
  tenantId: number;
  /** Must be this tenant's site. */
  siteId: number;
  /** A published (or deprecated) revision of an active MikroTik template,
   *  this tenant's own or the shipped library's. */
  revisionId: number;
  /** The group the router will be filed under, when the bench knows it. */
  groupId?: number | null;
  /** ObliWAN's values for this site — a superset is fine: only the keys the
   *  revision declares `computed` are rendered (`report.unusedComputed`). */
  computed: Record<string, unknown>;
  /** Typed at the bench, secrets included. Every key must be declared `bench`
   *  by the revision. Kept in memory for this call only. */
  bench: Record<string, unknown>;
  box: BoxFacts;
  /** 'secrets' splices the plaintexts into `text`; 'redacted' leaves the
   *  placeholders (a preview: `text === redacted`). */
  mode: 'secrets' | 'redacted';
  executor?: Knex | Knex.Transaction;
}

export interface SiteRenderResult {
  /** The RouterOS text for the box. In 'secrets' mode it carries PLAINTEXT
   *  secrets: IN MEMORY ONLY — never persist it, log it, or return it through
   *  an API. In 'redacted' mode it is identical to `redacted`. */
  text: string;
  /** The same text with `__OBLIWAN_SECRET_<KEY>__` placeholders — the only
   *  form that may be stored, shown or diffed. */
  redacted: string;
  redactedSha256: string;
  mode: 'secrets' | 'redacted';
  /** NAMES of the secrets spliced into `text`, sorted. Never their values. */
  substitutedSecrets: string[];
  revision: { id: string; templateId: string; templateName: string; revision: number; status: string };
  /** Redacted, each with its origin (Instance / Tenant / Site / Computed by
   *  ObliWAN / Typed at the bench / …). */
  variables: ResolvedVariables;
  report: VariableReport;
  durationMs: number;
}

export type SiteRenderErrorCode =
  /** The site or the revision is not this tenant's (or does not exist). */
  | 'NOT_FOUND'
  /** `box`, `computed`, `bench` or `mode` is malformed. */
  | 'BAD_INPUT'
  /** The revision may not go onto this box: brand, archived template, draft
   *  or quarantined revision, model pattern, OS window. */
  | 'REVISION_REFUSED'
  /** The variables do not resolve: a required one missing (stored, computed
   *  or bench), a type error, a bench key the revision does not declare. */
  | 'VARIABLES'
  /** The template itself failed: syntax, a filter refusal, `fail()`, template
   *  residue in the output, a timeout, a stored secret typed into the text. */
  | 'TEMPLATE'
  /** A secret could not be spliced into the text — its value, a placeholder
   *  collision — or the template does not interpolate its secrets verbatim
   *  (the probe: a filter on a secret, a placeholder spelled by hand). */
  | 'SECRET_REFUSED';

/**
 * Every refusal of `renderForSite`. The message is safe to show and to log:
 * it names keys, levels and rules, never a secret's value and never a line of
 * the 'secrets' text.
 */
export class SiteRenderError extends Error {
  constructor(
    readonly code: SiteRenderErrorCode,
    message: string,
    readonly detail: {
      reason?: string;
      errorKind?: RenderErrorKind | null;
      missing?: MissingVariable[];
      typeErrors?: VariableTypeError[];
    } = {},
  ) {
    super(message);
    this.name = 'SiteRenderError';
  }
}

// ============================================================================
// Input checks
// ============================================================================

const BOX_KEYS: ReadonlySet<string> = new Set(['wifi_stack', 'board', 'model', 'ros_version']);

/** Printable ASCII, no leading or trailing blank: what a box reports as its
 *  board, model or version. A value outside it is not something the bench
 *  read off a MikroTik. */
const BOX_TEXT_RE = /^[\x21-\x7e](?:[\x20-\x7e]{0,62}[\x21-\x7e])?$/;

function isPlainRecord(v: unknown): v is Record<string, unknown> {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v) as object | null;
  return proto === Object.prototype || proto === null;
}

/** The box facts as they enter the context: only the keys the bench read. */
export function parseBoxFacts(box: unknown): Record<string, string> {
  if (!isPlainRecord(box)) {
    throw new SiteRenderError('BAD_INPUT', 'box facts must be a plain object');
  }
  for (const k of Object.keys(box)) {
    if (!BOX_KEYS.has(k)) {
      throw new SiteRenderError(
        'BAD_INPUT',
        `box fact "${k}" is not one the bench supplies (expected ${[...BOX_KEYS].join(', ')})`,
      );
    }
  }
  if (box.wifi_stack !== 'wifi' && box.wifi_stack !== 'wireless') {
    throw new SiteRenderError(
      'BAD_INPUT',
      'box.wifi_stack must be "wifi" (the /interface wifi package, wifi1/wifi2) or "wireless" ' +
        '(the legacy /interface wireless package, wlan1/wlan2) — read off the box, never guessed',
    );
  }
  const out: Record<string, string> = { wifi_stack: box.wifi_stack };
  for (const k of ['board', 'model', 'ros_version'] as const) {
    const v = box[k];
    if (v === undefined) continue;
    if (typeof v !== 'string' || !BOX_TEXT_RE.test(v)) {
      throw new SiteRenderError(
        'BAD_INPUT',
        `box.${k} must be 1 to 64 printable ASCII characters with no leading or trailing blank`,
      );
    }
    out[k] = v;
  }
  return out;
}

// ============================================================================
// Reads — tenant-scoped, always
// ============================================================================

interface BenchRevision {
  id: string;
  template_id: string;
  template_name: string;
  revision: number;
  status: string;
  os_min: string | null;
  os_max: string | null;
  render_options: Record<string, unknown> | null;
  brand: string;
  template_status: string;
  model_pattern: string | null;
}

/** The site facts the template reads as `site.*`. `country` only when the
 *  column exists (migration 036 adds it): the row is read whole, so this file
 *  neither fails before that migration nor hides the column after it.
 *  Exported for the fleet render of a bench-prepared router
 *  (`render.service`), so the two paths cannot disagree on what `site` is. */
export async function loadSiteFacts(
  executor: Knex | Knex.Transaction,
  tenantId: number,
  siteId: number,
): Promise<Record<string, string | null>> {
  const row = (await executor('sites').where({ id: siteId, tenant_id: tenantId }).first()) as
    | Record<string, unknown>
    | undefined;
  if (!row) throw new SiteRenderError('NOT_FOUND', `Site #${siteId} does not exist in this tenant.`);
  const facts: Record<string, string | null> = {
    code: String(row.code),
    name: String(row.name),
    timezone: String(row.timezone),
  };
  if (Object.prototype.hasOwnProperty.call(row, 'country')) {
    facts.country = typeof row.country === 'string' ? row.country : null;
  }
  return facts;
}

/** The revision and its template, scoped to the tenant's own or the shipped
 *  library — the same visibility rule as `loadRevisionSchema`. */
async function loadBenchRevision(
  executor: Knex | Knex.Transaction,
  tenantId: number,
  revisionId: number,
): Promise<BenchRevision> {
  const row = (await executor('template_revisions as r')
    .join('templates as t', 't.id', 'r.template_id')
    .where('r.id', revisionId)
    .andWhere(function ownOrLibrary(this: Knex.QueryBuilder) {
      this.where('r.tenant_id', tenantId).orWhereNull('r.tenant_id');
    })
    .first(
      'r.id as id',
      'r.template_id as template_id',
      'r.revision as revision',
      'r.status as status',
      'r.os_min as os_min',
      'r.os_max as os_max',
      'r.render_options as render_options',
      't.name as template_name',
      't.brand as brand',
      't.status as template_status',
      't.model_pattern as model_pattern',
    )) as BenchRevision | undefined;
  if (!row) {
    throw new SiteRenderError(
      'NOT_FOUND',
      `Template revision #${revisionId} does not exist in this tenant.`,
    );
  }
  return row;
}

/**
 * May this revision go onto this box? The same four guarantees
 * `render.service` gives an explicit revision on the device path — brand,
 * archived template, quarantined revision, model and OS window, through the
 * same `modelMatches` / `satisfiesOsWindow` — plus one of its own: no DRAFT.
 * A draft can still change after it was rendered, and a box that leaves the
 * bench carries a configuration nobody can recall from it.
 */
function assertRevisionFitsBox(rev: BenchRevision, box: Record<string, string>): void {
  const refuse = (reason: string, message: string): never => {
    throw new SiteRenderError('REVISION_REFUSED', message, { reason });
  };
  if (rev.brand !== 'mikrotik') {
    refuse('brand_unsupported', `template ${rev.template_id} targets ${rev.brand}; the bench renders RouterOS templates only`);
  }
  if (rev.template_status !== 'active') {
    refuse('template_archived', `template ${rev.template_id} is ${rev.template_status} and may not be rendered`);
  }
  if (rev.status === 'quarantined') {
    refuse('revision_quarantined', `template revision ${rev.id} is quarantined and may not be rendered`);
  }
  if (rev.status === 'draft') {
    refuse(
      'revision_draft',
      `template revision ${rev.id} is a draft: a draft can still change after the box is ` +
        'configured, so the bench renders published (or deprecated) revisions only',
    );
  }
  if (rev.model_pattern) {
    const model = box.model ?? null;
    if (model === null) {
      refuse(
        'model_unknown',
        `template ${rev.template_id} targets models matching '${rev.model_pattern}', and the ` +
          'bench did not supply the box\'s model — refusing to guess',
      );
    }
    if (!modelMatches(rev.model_pattern, model)) {
      refuse(
        'model_mismatch',
        `template ${rev.template_id} targets models matching '${rev.model_pattern}', the box ` +
          `is '${model}'`,
      );
    }
  }
  const os = satisfiesOsWindow(box.ros_version ?? null, rev.os_min, rev.os_max);
  if (!os.ok) {
    refuse(
      os.reason ?? 'os_unknown',
      `template revision ${rev.id} may not be rendered on this box: ${os.detail}` +
        (box.ros_version === undefined ? ' (the bench did not supply box.ros_version)' : ''),
    );
  }
}

// ============================================================================
// The splice
// ============================================================================

/**
 * The characters that carry the structure of a RouterOS line: whitespace and
 * every C0/C1 control, and " \ $ ; [ ] { } and the backtick — the same set
 * `secrets.ts` refuses in a secret's VALUE. Judged here on the RESULT: a
 * spliced line whose structural skeleton differs from the redacted line's has
 * gained or lost an argument, a string, a block or a statement.
 */
// eslint-disable-next-line no-control-regex
const STRUCTURE_CHARS = /[\s\u0000-\u001f\u007f-\u009f"\\$;[\]{}`]/g;

function shapeOf(line: string): string {
  // A '#' as the line's first non-blank character makes it a COMMENT: a
  // placeholder at the start of a line whose secret begins with '#' would
  // silently delete the command.
  return (line.match(STRUCTURE_CHARS) ?? []).join('') + (/^\s*#/.test(line) ? '#' : '');
}

/**
 * The brand line assertion `substituteLine` requires, for template output. The
 * push path's own (`assertConsoleLine`) cannot be used here: it demands a
 * balanced line, and a template body legitimately opens a `:do {` on one line
 * and closes it several lines below. What CAN be demanded of any line is that
 * the splice did not change its shape. The message never quotes the line —
 * after the splice it holds a plaintext.
 */
export function assertSpliceKeepsShape(redactedLine: string): (command: string) => void {
  const expected = shapeOf(redactedLine);
  return (command: string) => {
    if (shapeOf(command) !== expected) {
      throw new Error('the substituted line does not have the structure of the redacted line');
    }
  };
}

/**
 * placeholder -> plaintext, for the placeholders the redacted text actually
 * carries. Built from the 'secrets' context of the SAME report the text was
 * rendered from. Refuses, naming keys only:
 *  - two secret keys that mask to the same placeholder (`sitePsk`/`sitepsk`):
 *    the text cannot say which one it means — the push path's rule
 *    (`buildSecretSubstitutions`), applied here to the placeholders in use;
 *  - a placeholder in the text that no secret of this render resolves to —
 *    the template text spelled one by hand, or names a key that is not a
 *    secret here; pushing the literal would write twenty-odd characters of
 *    garbage where a credential belongs. In `renderForSite` the probe has
 *    already refused every hand-spelled placeholder by then; this stays the
 *    table's own invariant, for a caller that builds one without the probe.
 */
export function benchSubstitutionTable(
  secrets: Pick<RenderContext, 'context' | 'secretKeys'>,
  redactedText: string,
): SecretSubstitution[] {
  const present = new Set(redactedText.match(SECRET_PLACEHOLDER_RE) ?? []);
  const table = new Map<string, SecretSubstitution>();
  for (const key of secrets.secretKeys) {
    const placeholder = redactedPlaceholder(key);
    if (!present.has(placeholder)) continue;
    const existing = table.get(placeholder);
    if (existing) {
      throw new SiteRenderError(
        'SECRET_REFUSED',
        `the secret variables "${existing.key}" and "${key}" both mask to ${placeholder}, and the ` +
          'rendered text uses it: the placeholder is the uppercased key, so the text cannot say ' +
          'which one it needs. Rename one of them.',
      );
    }
    const plaintext = secrets.context[key];
    if (typeof plaintext !== 'string') {
      throw new SiteRenderError(
        'SECRET_REFUSED',
        `the secret variable "${key}" did not resolve to a string — refusing to coerce it.`,
      );
    }
    table.set(placeholder, { placeholder, key, plaintext });
  }
  for (const placeholder of present) {
    if (!table.has(placeholder)) {
      throw new SiteRenderError(
        'SECRET_REFUSED',
        `the rendered text carries ${placeholder}, and no secret variable of this render ` +
          'resolves to it: the template text spells the placeholder by hand, or the key is not ' +
          'a secret for this site.',
      );
    }
  }
  return [...table.values()];
}

/**
 * Splice the plaintexts into the redacted text, line by line, through the push
 * path's `substituteLine`. Pure — exported for the harness.
 */
export function spliceSecrets(
  redactedText: string,
  table: readonly SecretSubstitution[],
): { text: string; used: string[] } {
  const used = new Set<string>();
  const out: string[] = [];
  for (const line of redactedText.split('\n')) {
    try {
      const { substituted, used: entries } = substituteLine(line, table, assertSpliceKeepsShape(line));
      out.push(substituted.command);
      for (const e of entries) used.add(e.key);
    } catch (err) {
      if (err instanceof ChangeError) {
        // secrets.ts words its refusals for the push path ("re-plan"); the
        // rule is the same here, and the remedy is to change the value and
        // render again.
        throw new SiteRenderError(
          'SECRET_REFUSED',
          `the bench render was refused while splicing secrets into the text: ${err.message}`,
        );
      }
      throw err;
    }
  }
  const text = out.join('\n');
  // Exact placeholders only, and that is enough: the engine refused any
  // ALTERED one in the redacted text before it got here (`findTemplateResidue`,
  // case-insensitive), and the probe refused any other transformation, so the
  // only placeholder-like text the redacted body may hold is an exact one —
  // which this proves is gone. A case-insensitive scan of the SPLICED text
  // would add nothing but a false refusal of a credential that happens to
  // spell "ObliwanSecret".
  if ((text.match(SECRET_PLACEHOLDER_RE) ?? []).length > 0) {
    throw new SiteRenderError(
      'SECRET_REFUSED',
      'a secret placeholder survived the splice — refusing to put it on the box.',
    );
  }
  return { text, used: [...used].sort() };
}

// ============================================================================
// The probe — a secret is interpolated verbatim, or not at all
// ============================================================================

/**
 * One stand-in per secret key, for the probe render (see the file header).
 * Each is `[A-Za-z0-9]` only — bare to the sandbox's RouterOS escaper exactly
 * as the `[A-Z0-9_]` placeholder is, so both forms are emitted the same way —
 * and differs from its key's placeholder in its first character, its last
 * character, its length and its case mix, so a prefix, a suffix, a length or a
 * case change taken of one is not the same as of the other. `nonce` is random
 * per render: a template cannot recognise a stand-in it has never seen. Each
 * ends with its own index and a closing `Q`, so no stand-in contains another.
 * Exported for the harness.
 */
export function probeStandIns(secretKeys: readonly string[], nonce: string): Map<string, string> {
  if (!/^[A-Za-z0-9]{8,}$/.test(nonce)) {
    throw new Error('probe nonce must be at least 8 characters of [A-Za-z0-9]');
  }
  const out = new Map<string, string>();
  secretKeys.forEach((key, i) => {
    let body = `Pq${nonce}x${i}`;
    if (body.length + 1 === redactedPlaceholder(key).length) body += 'r';
    out.set(key, `${body}Q`);
  });
  return out;
}

function probeNonce(): string {
  // 18 random bytes -> 24 base64 characters, of which the two non-alphanumeric
  // ones are dropped: never fewer than 8 survive in practice, and
  // `probeStandIns` refuses if they somehow did.
  return crypto.randomBytes(18).toString('base64').replace(/[^A-Za-z0-9]/g, '');
}

/**
 * The probe's verdict: `probeText` (rendered with `standIns`) mapped back to
 * placeholders must BE `redactedText`, and must carry no placeholder of its own.
 * Throws `SiteRenderError('SECRET_REFUSED')` naming the first differing line —
 * its number only: the line of a refused render is not echoed. Pure — exported
 * for the harness.
 */
export function assertSecretsVerbatim(
  redactedText: string,
  probeText: string,
  standIns: ReadonlyMap<string, string>,
): void {
  const spelled = probeText.match(SECRET_PLACEHOLDER_RE);
  if (spelled) {
    throw new SiteRenderError(
      'SECRET_REFUSED',
      `the rendered text carries ${spelled[0]} at a place where no secret variable was ` +
        'interpolated: the template text, or a value handed to it in clear, spells the ' +
        'placeholder itself. Only a secret the template interpolates is spliced in — reference ' +
        'the variable instead.',
      { reason: 'placeholder_spelled' },
    );
  }
  let mapped = probeText;
  for (const [key, standIn] of standIns) mapped = mapped.split(standIn).join(redactedPlaceholder(key));
  if (mapped === redactedText) return;
  const a = redactedText.split('\n');
  const b = mapped.split('\n');
  let line = 0;
  while (line < a.length && line < b.length && a[line] === b[line]) line++;
  throw new SiteRenderError(
    'SECRET_REFUSED',
    `line ${line + 1} of the rendered text depends on the TEXT of a secret, not only on where ` +
      'it goes: a filter, a slice, a length, a padding or a comparison is applied to a secret ' +
      'variable (or the template is not deterministic). The bench renders a secret as its ' +
      'placeholder and splices the credential in verbatim afterwards, so a template that ' +
      'transforms one would ship the transformed placeholder — a predictable string — in place ' +
      'of the credential. Interpolate the secret as it is; store the value the box needs.',
    { reason: 'secret_transformed' },
  );
}

// ============================================================================
// The entry point
// ============================================================================

/**
 * Render a revision for the box on the bench. See the file header for what the
 * template sees and how secrets reach the text. Throws `SiteRenderError` and
 * nothing else on a refusal; never writes anything.
 */
export async function renderForSite(opts: RenderForSiteOptions): Promise<SiteRenderResult> {
  const started = Date.now();
  const executor = opts.executor ?? db;

  if (opts.mode !== 'secrets' && opts.mode !== 'redacted') {
    throw new SiteRenderError('BAD_INPUT', 'mode must be "secrets" or "redacted"');
  }
  if (!isPlainRecord(opts.computed) || !isPlainRecord(opts.bench)) {
    throw new SiteRenderError('BAD_INPUT', '`computed` and `bench` must be plain objects');
  }
  const box = parseBoxFacts(opts.box);
  const site = await loadSiteFacts(executor, opts.tenantId, opts.siteId);
  const rev = await loadBenchRevision(executor, opts.tenantId, opts.revisionId);
  assertRevisionFitsBox(rev, box);

  // ── 1. Variables: ONE report, two contexts ──────────────────────────────
  let contexts: { redacted: RenderContext; secrets: RenderContext | null };
  try {
    contexts = await buildSiteRenderContexts({
      tenantId: opts.tenantId,
      siteId: opts.siteId,
      groupId: opts.groupId ?? null,
      revisionId: opts.revisionId,
      computed: opts.computed,
      bench: opts.bench,
      facts: { site, box },
      withSecrets: opts.mode === 'secrets',
      executor,
    });
  } catch (err) {
    if (err instanceof VariableResolutionError) {
      throw new SiteRenderError('VARIABLES', err.message, {
        missing: err.missing,
        typeErrors: err.typeErrors,
      });
    }
    if (err instanceof Error && /does not exist in tenant/.test(err.message)) {
      throw new SiteRenderError('NOT_FOUND', err.message.replace(/ in tenant #\d+/, ' in this tenant'));
    }
    if (err instanceof Error) throw new SiteRenderError('VARIABLES', err.message);
    throw err;
  }

  // ── 2. The sandbox, with the REDACTED context — always — and the probe ───
  let bundle: Awaited<ReturnType<typeof loadRevisionBundle>>;
  try {
    bundle = await loadRevisionBundle(rev.id, { trx: executor });
  } catch (err) {
    throw new SiteRenderError('TEMPLATE', err instanceof Error ? err.message : String(err));
  }
  const request: RenderRequest = {
    id: `site${opts.siteId}:rev${rev.id}`,
    entry: bundle.entry,
    sources: bundle.sources,
    context: contexts.redacted.context,
    options: (rev.render_options ?? undefined) as Record<string, boolean> | undefined,
  };
  // The probe (file header): the same body, each secret replaced by its
  // stand-in. Rendered in the same batch — one worker, two fresh realms. With
  // no secret in the context there is nothing to probe, and the redacted text
  // is its own probe (a placeholder spelled by hand is still refused below).
  const standIns = probeStandIns(contexts.redacted.secretKeys, probeNonce());
  let probeRequest: RenderRequest | null = null;
  if (standIns.size > 0) {
    const probeContext = { ...(contexts.redacted.context as Record<string, JsonValue>) };
    for (const [key, standIn] of standIns) probeContext[key] = standIn;
    probeRequest = { ...request, id: `${request.id}:probe`, context: probeContext };
  }
  const [rendered, probed] = await renderTemplates(probeRequest ? [request, probeRequest] : [request]);
  if (!rendered.ok || rendered.output === null) {
    throw new SiteRenderError(
      'TEMPLATE',
      rendered.errorMessage ?? 'the render failed without recording a reason',
      { errorKind: rendered.errorKind },
    );
  }
  // The engine has already refused template residue and any secret
  // placeholder a filter rewrote (`findTemplateResidue`).
  const redacted = rendered.output;

  // ── 3. The secrets rule: a STORED secret's plaintext in the template or its output ───
  // The context was redacted, so no variable carried one in. The template
  // TEXT can — an author who typed a credential into the body or a partial —
  // and that is judged on the sources themselves; the output is judged for
  // what the sources cannot explain (`assertNoStoredSecretInRender`: a short
  // secret such as a PIN inside a store code is a coincidence, not a leak). The
  // same check, over the same kind of secrets, as the device path
  // (`render.service`). Not over the bench and computed ones: those are typed
  // or generated for this box after the template was written, and the text
  // cannot carry them except by coincidence.
  const stored = await loadSecretsForSite({
    tenantId: opts.tenantId,
    siteId: opts.siteId,
    groupId: opts.groupId ?? null,
    executor,
  });
  try {
    assertNoStoredSecretInRender({
      sources: bundle.sources,
      output: redacted,
      context: contexts.redacted.context,
      secrets: stored,
      what: 'this bench render',
    });
  } catch (err) {
    throw new SiteRenderError('TEMPLATE', err instanceof Error ? err.message : String(err));
  }

  // ── 3b. The probe's verdict: every secret is interpolated verbatim ───────
  if (probed && (!probed.ok || probed.output === null)) {
    // Its message was computed on stand-ins, never on a plaintext.
    throw new SiteRenderError(
      'SECRET_REFUSED',
      'the template renders with its secrets as placeholders and fails with them as other ' +
        'text, so whether it renders at all depends on the TEXT of a secret (a filter, a ' +
        'length or a comparison applied to one): ' +
        (probed.errorMessage ?? 'no reason was recorded'),
      { reason: 'secret_transformed', errorKind: probed.errorKind },
    );
  }
  assertSecretsVerbatim(redacted, probed?.output ?? redacted, standIns);

  // ── 4. The splice ────────────────────────────────────────────────────────
  let text = redacted;
  let substitutedSecrets: string[] = [];
  if (opts.mode === 'secrets') {
    const secrets = contexts.secrets as RenderContext;
    const spliced = spliceSecrets(redacted, benchSubstitutionTable(secrets, redacted));
    text = spliced.text;
    substitutedSecrets = spliced.used;
  }

  return {
    text,
    redacted,
    redactedSha256: crypto.createHash('sha256').update(redacted, 'utf8').digest('hex'),
    mode: opts.mode,
    substitutedSecrets,
    revision: {
      id: String(rev.id),
      templateId: String(rev.template_id),
      templateName: rev.template_name,
      revision: Number(rev.revision),
      status: rev.status,
    },
    variables: contexts.redacted.variables,
    report: contexts.redacted.report,
    durationMs: Date.now() - started,
  };
}

export const siteRenderService = { renderForSite };
