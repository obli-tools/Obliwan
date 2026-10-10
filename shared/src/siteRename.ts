// ============================================================================
// @obliwan/shared — renaming a site's router (the `site_rename` change job)
// ============================================================================
//
// One job changes TOGETHER what the fleet knows a store by: the PPP login on
// the shared concentrator (its /ppp/secret), the user of the router's
// management tunnel (the l2tp-client named l2tp-mgmt), the router's
// /system identity, the device row, and — when asked — the site code. The
// first use is lowercasing customer C's logins (`StoreName` ->
// `storename`), but nothing here is specific to it.
//
// This file is PURE: the vocabulary, the alphabets, the three router lines,
// the allow-list that judges them (spelled independently of the builders, so
// a builder that drifts is caught), and the self-revert's log grammar. The
// job is services/change/siteRename.service.ts; the table is migration 088.
//
// ┌─ ROUTEROS BEHAVIOUR RELIED ON — REASONED, NOT OBSERVED ───────────────────┐
// │ `/ppp/secret/add copy-from=<.id> name=<new>` copies the password the API  │
// │ never reads; a CHR refusing a second secret differing only by case is   │
// │ handled (the in-place `set name=` path, case-only renames alone); PPP    │
// │ authentication matching the name case-sensitively; `set user=` on an      │
// │ l2tp-client restarting it; removing or renaming a secret leaving an      │
// │ active session alone; `:execute` returning its job id and that job       │
// │ outliving the SSH session that started it — the last one is OBSERVED on │
// │ every router before the cut line leaves (the job id seen listed on a NEW │
// │ session), as legacy_compliance does. No line of this file has reached a  │
// │ router.                                                                   │
// └───────────────────────────────────────────────────────────────────────────┘

/** The `change_jobs.kind` of the job. */
export const SITE_RENAME_KIND = 'site_rename' as const;

/**
 * What a job concluded. Mirrors `site_rename_jobs_outcome_chk` (088).
 *  - `renamed`   every planned name holds, read back on a fresh session;
 *  - `present`   nothing needed changing: nothing written anywhere;
 *  - `reverted`  the router's self-revert (or ObliWAN, on the CHR) put the old
 *                login back: the device row is back at the old names;
 *  - `unsettled` the router did not come back within the bound: the names are
 *                in an unknown state; « Relancer » settles it;
 *  - `refused`   ended before anything was written, on the CHR or the router;
 *  - `failed`    ended after a write that was undone or could not be judged.
 */
export const SITE_RENAME_OUTCOMES = ['renamed', 'present', 'reverted', 'unsettled', 'refused', 'failed'] as const;
export type SiteRenameOutcome = (typeof SITE_RENAME_OUTCOMES)[number];

/** How the target names were chosen: typed by the operator, or the bulk
 *  « all lowercase » transform. Mirrors `site_rename_jobs_transform_chk`. */
export const SITE_RENAME_TRANSFORMS = ['lowercase', 'explicit'] as const;
export type SiteRenameTransform = (typeof SITE_RENAME_TRANSFORMS)[number];

/**
 * How the new login reached the CHR. Mirrors `site_rename_jobs_chr_mode_chk`.
 *  - `copy`      a second secret beside the old one (`copy-from`), the old one
 *                removed only once the new session is up: the router's
 *                self-revert always has an account to fall back on;
 *  - `in_place`  the old secret renamed (`set name=`), for a CASE-ONLY rename
 *                the CHR refused as a duplicate. No account to fall back on:
 *                ObliWAN renames it back itself when the new session is not
 *                up by the self-revert's decision (operator decision
 *                2026-10-07; the CHR is always reachable from ObliWAN).
 */
export const SITE_RENAME_CHR_MODES = ['copy', 'in_place'] as const;
export type SiteRenameChrMode = (typeof SITE_RENAME_CHR_MODES)[number];

/** The self-revert's delay after it starts on the router. */
export const SITE_RENAME_REVERT_AFTER_S = 120;
/** The job's bound on the management tunnel's return, from the cut line. */
export const SITE_RENAME_TUNNEL_WAIT_S = 240;
/** The cut line leaves no later than this after the self-revert started. */
export const SITE_RENAME_GUARD_MAX_LEAD_S = 30;
/** Waited past the self-revert's decision before its log line is read. */
export const SITE_RENAME_GUARD_MARGIN_S = 15;

export const SITE_RENAME_LOGIN_MAX = 128;
export const SITE_RENAME_IDENTITY_MAX = 64;
export const SITE_RENAME_SITE_CODE_MAX = 64;

/** The self-revert line prints `revertjob|<id>` (legacy_compliance's tag, so
 *  its parser reads it): the id `:execute` returns. */
export const SITE_RENAME_GUARD_JOB_TAG = 'revertjob';
export const SITE_RENAME_GUARD_REVERTED = 'REVERTED';
export const SITE_RENAME_GUARD_STOOD_DOWN = 'STOOD-DOWN';

/** Marks the self-revert's decision in the router's log:
 *  `obliwan-rename job=<id>: REVERTED|STOOD-DOWN …`. */
export function siteRenameGuardLogPrefix(jobId: number): string {
  return `obliwan-rename job=${jobId}:`;
}

// ============================================================================
// Alphabets
// ============================================================================

const NAME_CHARS = /^[A-Za-z0-9._-]+$/;

/** A login or an identity this job writes: letters, digits, `.`, `_`, `-`;
 *  no `..`, no leading or trailing `.` (the logins as migration 036 admits
 *  them). Nothing in it needs quoting on a RouterOS console line. */
function inAlphabet(value: string, max: number): boolean {
  return value.length > 0 && value.length <= max && NAME_CHARS.test(value) &&
    !value.includes('..') && !value.startsWith('.') && !value.endsWith('.');
}

export function isRenameLogin(value: unknown): value is string {
  return typeof value === 'string' && inAlphabet(value, SITE_RENAME_LOGIN_MAX);
}

export function isRenameIdentity(value: unknown): value is string {
  return typeof value === 'string' && inAlphabet(value, SITE_RENAME_IDENTITY_MAX);
}

/** An l2tp-client name the lines carry inside `name="…"`: no quote, no `$`,
 *  no backslash, no `?` — legacy_compliance's safe set. */
export const SITE_RENAME_CLIENT_NAME_RE = /^[A-Za-z0-9._@:+() -]{1,64}$/;

export function isRenameClientName(value: unknown): value is string {
  return typeof value === 'string' && SITE_RENAME_CLIENT_NAME_RE.test(value);
}

/** The bulk transform: the same text, lowercased. */
export function lowercaseRename(from: string): string {
  return from.toLowerCase();
}

/** Two different spellings of one name, differing only by case. */
export function isCaseOnlyChange(from: string | null | undefined, to: string | null | undefined): boolean {
  return typeof from === 'string' && typeof to === 'string' && from !== to && from.toLowerCase() === to.toLowerCase();
}

/** An input the lines could not carry. Names the field. */
export class SiteRenameInputError extends Error {
  constructor(readonly field: string, message: string) {
    super(message);
    this.name = 'SiteRenameInputError';
  }
}

// ============================================================================
// The three router lines
// ============================================================================

/**
 * RouterOS double-quoted string literal for the self-revert's source: `\\`,
 * `\"`, `\$`, `\?` escaped (legacy_compliance's rule). The source is built
 * from validated names and integers only; a control or non-ASCII character
 * is refused rather than written.
 */
function quoted(text: string): string {
  let out = '';
  for (const ch of text) {
    const code = ch.codePointAt(0) as number;
    if (code < 0x20 || code >= 0x7f) throw new SiteRenameInputError('script', 'The self-revert holds a character the job does not write.');
    out += ch === '\\' ? '\\\\' : ch === '"' ? '\\"' : ch === '$' ? '\\$' : ch === '?' ? '\\?' : ch;
  }
  return `"${out}"`;
}

function assertLine(client: string, from: string, to: string): void {
  if (!isRenameClientName(client)) throw new SiteRenameInputError('client', 'The management tunnel name is outside the alphabet this job writes.');
  if (!isRenameLogin(from)) throw new SiteRenameInputError('from', 'The current login is outside the alphabet this job writes.');
  if (!isRenameLogin(to)) throw new SiteRenameInputError('to', 'The new login is outside the alphabet this job writes.');
  if (from === to) throw new SiteRenameInputError('to', 'The new login is the current one.');
}

/**
 * What `:execute` runs. After `afterS`, it looks at the ONE management client
 * (by its frozen name): running -> it stands down; not running and still
 * dialling the NEW login -> it puts the old login back (which restarts the
 * client) and logs REVERTED; not running under another login (somebody
 * changed it since) -> it stands down and says why. Its decision is logged
 * either way, so the job can read it back.
 */
export function siteRenameSelfRevertSource(jobId: number, client: string, from: string, to: string, afterS: number): string {
  const prefix = siteRenameGuardLogPrefix(jobId);
  return (
    `:delay ${afterS}s; :local f [/interface l2tp-client find where name="${client}"]; ` +
    ':if ([:len $f] = 1) do={ :local c [:pick $f 0]; ' +
    ':if ([/interface l2tp-client get $c running]) do={ ' +
    `:log info "${prefix} ${SITE_RENAME_GUARD_STOOD_DOWN} the management tunnel is running as ${to}" } else={ ` +
    `:if ([/interface l2tp-client get $c user] = "${to}") do={ /interface l2tp-client set $c user="${from}"; ` +
    `:log warning "${prefix} ${SITE_RENAME_GUARD_REVERTED} the management tunnel was not running ${afterS} s after user=${to}, user=${from} put back" } else={ ` +
    `:log warning "${prefix} ${SITE_RENAME_GUARD_STOOD_DOWN} the management tunnel dials another login, left alone" } } } else={ ` +
    `:log warning "${prefix} ${SITE_RENAME_GUARD_STOOD_DOWN} no single client named ${client}, left alone" }`
  );
}

/** The background self-revert, started BEFORE the cut line, printing the job
 *  id `:execute` returns (`revertjob|<id>`). */
export function siteRenameSelfRevertLine(jobId: number, client: string, from: string, to: string, afterS: number): string {
  if (!Number.isInteger(jobId) || jobId <= 0) throw new SiteRenameInputError('job', 'Invalid job id.');
  if (!Number.isInteger(afterS) || afterS < 30 || afterS > 600) throw new SiteRenameInputError('delay', 'Invalid self-revert delay.');
  assertLine(client, from, to);
  return `:put ("${SITE_RENAME_GUARD_JOB_TAG}|" . [:execute script=${quoted(siteRenameSelfRevertSource(jobId, client, from, to, afterS))}])`;
}

/** The cut: the management client dials the new login. It restarts the
 *  tunnel the job's own session rides, so it is sent LAST, alone. */
export function siteRenameCutLine(client: string, from: string, to: string): string {
  assertLine(client, from, to);
  return `/interface l2tp-client set [find where name="${client}"] user="${to}"`;
}

/** The router's new /system identity. Cuts nothing. */
export function siteRenameIdentityLine(to: string): string {
  if (!isRenameIdentity(to)) throw new SiteRenameInputError('identity', 'The new identity is outside the alphabet this job writes.');
  return `/system identity set name="${to}"`;
}

// ============================================================================
// The allow-list
// ============================================================================

export class SiteRenameLineRefused extends Error {
  constructor(readonly offending: string[]) {
    super(`Refused line(s) outside the site rename allow-list: ${offending.join(' | ').slice(0, 400)}`);
    this.name = 'SiteRenameLineRefused';
  }
}

export interface SiteRenameLineContext {
  jobId: number;
  revertAfterS: number;
  /** Present when the login changes on the router. */
  login: { client: string; from: string; to: string } | null;
  /** Present when the identity changes on the router. */
  identity: { to: string } | null;
}

/**
 * The allow-list, spelled again with literals: each line must be EXACTLY the
 * self-revert, the cut or the identity line for THIS context; the cut must
 * come right after its self-revert, and nothing follows the cut. No other
 * menu, no second property, no chained command. Throws `SiteRenameLineRefused`.
 */
export function assertSiteRenameOnlyLines(lines: readonly string[], ctx: SiteRenameLineContext): void {
  const allowed = new Set<string>();
  let guard: string | null = null;
  let cut: string | null = null;
  const safe = (v: string) => /^[A-Za-z0-9._-]+$/.test(v) && !v.includes('..') && !v.startsWith('.') && !v.endsWith('.');
  if (ctx.login && /^[A-Za-z0-9._@:+() -]{1,64}$/.test(ctx.login.client) && safe(ctx.login.from) && safe(ctx.login.to) &&
    ctx.login.from !== ctx.login.to) {
    const { client, from, to } = ctx.login;
    cut = `/interface l2tp-client set [find where name="${client}"] user="${to}"`;
    allowed.add(cut);
    try {
      guard = siteRenameSelfRevertLine(ctx.jobId, client, from, to, ctx.revertAfterS);
      allowed.add(guard);
    } catch {
      guard = null;
    }
  }
  if (ctx.identity && safe(ctx.identity.to) && ctx.identity.to.length <= SITE_RENAME_IDENTITY_MAX) {
    allowed.add(`/system identity set name="${ctx.identity.to}"`);
  }
  const offending = lines.filter((l) => !allowed.has(l));
  if (new Set(lines).size !== lines.length) offending.push('(a line sent twice)');
  const cutAt = cut === null ? -1 : lines.indexOf(cut);
  if (cutAt >= 0 && cutAt !== lines.length - 1) offending.push('(the cut line is not the last)');
  if (cutAt >= 0 && (guard === null || lines[cutAt - 1] !== guard)) offending.push('(the cut line is not immediately preceded by its self-revert)');
  const guardAt = guard === null ? -1 : lines.indexOf(guard);
  if (guardAt >= 0 && cutAt !== guardAt + 1) offending.push('(a self-revert with no cut line after it)');
  if (offending.length > 0 || lines.length === 0) throw new SiteRenameLineRefused(offending.length > 0 ? offending : ['(no line)']);
}

/** The self-revert's decision, as its log line says it. */
export type SiteRenameGuardVerdict = 'reverted' | 'stood_down' | 'no_log_line';

export function parseSiteRenameGuardLog(out: string): { verdict: SiteRenameGuardVerdict; lines: string[] } {
  const found = out.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.startsWith('log|')).map((l) => l.slice(4));
  if (found.some((l) => l.includes(SITE_RENAME_GUARD_REVERTED))) return { verdict: 'reverted', lines: found };
  if (found.some((l) => l.includes(SITE_RENAME_GUARD_STOOD_DOWN))) return { verdict: 'stood_down', lines: found };
  return { verdict: 'no_log_line', lines: found };
}

// ============================================================================
// Views (the card and the bulk dialog)
// ============================================================================

export interface SiteRenameNames {
  login: string | null;
  identity: string | null;
  siteCode: string | null;
}

export interface SiteRenameRefusalView {
  kind: string;
  message: string;
}

export interface SiteRenameBulkPreviewRow {
  siteId: number;
  siteCode: string;
  siteName: string;
  deviceId: number | null;
  deviceName: string | null;
  from: SiteRenameNames;
  to: SiteRenameNames;
  /** Nothing differs once lowercased. */
  nothingToRename: boolean;
  refusals: SiteRenameRefusalView[];
}

export interface SiteRenameBulkLaunchRow {
  siteId: number;
  deviceId: number | null;
  jobId: number | null;
  alreadyQueued: boolean;
  refusal: SiteRenameRefusalView | null;
}
