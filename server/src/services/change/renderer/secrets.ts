// ============================================================================
// ObliWAN — the vault -> equipment substitution, and nothing else
// ============================================================================
//
// ┌─ THE ONE PLACE A PLAINTEXT SECRET ENTERS A COMMAND ───────────────────────┐
// │ The secrets rule: a secret exists in memory on the vault -> equipment     │
// │ path and NOWHERE else. This module is that path's last few metres. It     │
// │ produces two strings from one line, in ONE pass:                         │
// │                                                                          │
// │   command   the complete version, secrets substituted. Goes into          │
// │             `=source=` of `/system/script/add` and nowhere else.          │
// │   redacted  the same line with the placeholders LEFT IN PLACE. This is    │
// │             the only form allowed into `command_audit`,                   │
// │             `change_job_steps`, a log line, the UI or an export.          │
// │                                                                          │
// │ One pass, because `assertRenderingIsSafe()` deliberately does NOT compare │
// │ `commands.length` to `redacted.length` — and the two arrays are then read │
// │ by DIFFERENT consumers (`appliedOps` from one, the step output from the   │
// │ other, the dead-man's `opsCount` from the first again). A renderer that   │
// │ built them separately could ship an audit trail that disagrees with what  │
// │ was sent, which is the same class of defect `m6-sshapply.verify.ts`       │
// │ already caught once on `applied`.                                        │
// └──────────────────────────────────────────────────────────────────────────┘
//
// ┌─ WHY THE PLACEHOLDER IS THE LINK, AND WHY IT IS THE ONLY ONE ────────────┐
// │ A `PlanOp` carries NO secret value — that is a hard rule and it is not    │
// │ negotiable. So the renderer cannot get a PSK out of                       │
// │ `ipsecPeer.pskFingerprint`: that field is an irreversible HMAC, and       │
// │ `mikrotik/render.ts` refuses every op that would need one.                │
// │                                                                          │
// │ What CAN reach a plan op is the template path's own masked form.          │
// │ `variableResolver.redactedPlaceholder(key)` writes                        │
// │ `__OBLIWAN_SECRET_<KEY>__` into `config_renders.body`; the driver parses   │
// │ that body back into `ncm_desired`; the planner copies the resulting       │
// │ resource into `PlanOp.after`. A free-text field a template author wrote   │
// │ with `{{ some_secret }}` therefore arrives here carrying the placeholder  │
// │ — which NAMES THE VARIABLE. That name is the mapping, it is exact, and it │
// │ is the mapping the comment on `secretPlaceholder` in `shared/src/intent`  │
// │ describes when it says "the push path is the only code allowed to         │
// │ replace it".                                                             │
// │                                                                          │
// │ Substituting the CURRENT vault value rather than the one in force when    │
// │ the plan was compiled is correct and deliberate: the placeholder is       │
// │ byte-stable across a rotation ON PURPOSE (the masked artefact must not be │
// │ a rotation oracle), so what the operator approved was "the value of       │
// │ variable X", never a literal. Pushing a stale secret after a rotation     │
// │ would lock the fleet out of the very thing that was rotated.              │
// └──────────────────────────────────────────────────────────────────────────┘
//
// ┌─ THIS MODULE IS DOWNSTREAM OF EVERY ESCAPING BARRIER ─────────────────────┐
// │ The brand renderer escapes (`rosQuote`/`token`) and then asserts          │
// │ (`assertConsoleLine`) — and BOTH run while the value is still the          │
// │ placeholder `__OBLIWAN_SECRET_<KEY>__`, which is `[A-Z0-9_]` and survives  │
// │ every one of them untouched. So the splice below is the LAST text          │
// │ transformation before `=source=`, and for a while it was an unguarded      │
// │ one: a vault value carrying `" }; /user add … ;` broke out of the          │
// │ argument, out of the command and out of the `:do={} on-error={}` wrapper   │
// │ the rollback depends on, and a value carrying a newline emitted a second   │
// │ statement — `/import` included, which the backup rule bans.               │
// │                                                                          │
// │ Hence TWO barriers here, with different jobs, and neither replaces the     │
// │ other:                                                                   │
// │                                                                          │
// │  1. `assertSubstitutableSecret` judges the VALUE. It refuses a plaintext   │
// │     holding whitespace, a control character or a dialect metacharacter.    │
// │     It is the only one that can see the bare-argument case                 │
// │     (`domain=${token(x)}`): a lone SPACE splits the argument there and     │
// │     leaves every brace balanced, so no structural check will ever notice.  │
// │  2. `assertLine` judges the RESULT. The caller supplies its own brand's    │
// │     hard stop — RouterOS passes `assertConsoleLine` — so the assertion     │
// │     that guards the wrapper finally runs on the text that actually goes    │
// │     into the wrapper. It is a required argument on purpose: a barrier you  │
// │     get by default is a barrier a second transport forgets.               │
// │                                                                          │
// │ Neither refusal may echo the line or the value. The secrets rule holds on  │
// │ the error path too: a `ChangeError` message reaches `change_jobs.error`,   │
// │ the step output and a log line, so these name the VARIABLE and the rule,  │
// │ never the plaintext and never the command it produced.                    │
// └──────────────────────────────────────────────────────────────────────────┘

import {
  SECRET_PLACEHOLDER_RE,
  redactedPlaceholder,
  variableResolver,
} from '../../template/variableResolver.service';
import { ChangeError } from '../backup.service';
import type { RenderedChange } from '../safeApply.service';

/** The literal prefix of every `redactedPlaceholder()` output. Callers use it to
 *  decide whether a rendering needs the vault at all — the alternative is
 *  paying for the variable chain and a decrypt on every push, inside the armed
 *  dead-man window, for plans that carry no secret. */
export const SECRET_PLACEHOLDER_PREFIX = '__OBLIWAN_SECRET_';

/** One placeholder and the plaintext it stands for. Never logged, never
 *  returned by an API, never stored — the type exists so the plaintext has one
 *  shape and one lifetime. */
export interface SecretSubstitution {
  /** `__OBLIWAN_SECRET_<KEY>__` */
  placeholder: string;
  /** The `config_variables.key` the placeholder names. Safe to log. */
  key: string;
  /** IN MEMORY ONLY. */
  plaintext: string;
}

export interface SubstitutedLine {
  /** Secrets substituted. `=source=` only. */
  command: string;
  /** Placeholders left in place. The only form that may be persisted. */
  redacted: string;
}

/**
 * The brand's own "this line is safe to interpolate" hard stop, applied to the
 * SUBSTITUTED text. RouterOS passes `assertConsoleLine`; a future DrayTek or
 * SonicWall renderer passes its own, because what closes a `:do={}` block is not
 * what ends a Vigor CLI statement.
 *
 * It must throw, and its message must not contain the line it was given — that
 * line carries a plaintext.
 */
export type LineAssertion = (line: string) => unknown;

/**
 * Characters a secret plaintext may not contain, because the splice happens
 * after every escaper has already run.
 *
 * The set is derived, not chosen: it is the union of what the dialect escapers
 * in `intent/renderers.ts` substitute — `rosQuote` takes `" \ $ ; [ ] { }` and
 * a backtick, `vigorText`/`zldText` take `" \` and a backtick — plus ALL
 * whitespace and C0/C1 controls. Whitespace is in there for the bare-argument
 * position (`domain=${token(x)}`, `address=${token(x)}`), where there is no
 * quote to break out of and one space is already a second argument.
 *
 * A refusal rather than a substitution, and that is the opposite trade from
 * `rosQuote`: mangling a comment is harmless, mangling a PSK writes a
 * credential the far end does not have and takes the tunnel down. There is also
 * nothing to fall back on — a secret has no safe approximation.
 */
const SECRET_UNSAFE_CHAR = /[\s\u0000-\u001f\u007f-\u009f"\\$;[\]{}`]/;

/**
 * Refuse a secret whose value cannot be placed in a command line.
 *
 * The message names the variable and the RULE, never the offending character:
 * "it contains a space" is one bit of a credential, and this text lands in
 * `change_jobs.error` and in the step output.
 */
function assertSubstitutableSecret(entry: SecretSubstitution): void {
  if (!SECRET_UNSAFE_CHAR.test(entry.plaintext)) return;
  throw new ChangeError(
    'SECRET_LEAK_REFUSED',
    `the secret variable "${entry.key}" contains a character that cannot be placed in a device ` +
      'command line: whitespace, a control character, or one of " \\ $ ; [ ] { } or a backtick. ' +
      'Those characters are substituted in every other field precisely because they end an ' +
      'argument or a statement, and a secret is spliced in after that escaping has run — so ' +
      'pushing this value would not write the credential, it would write a new command. Change ' +
      'the value to one built from the remaining printable characters and re-plan.',
    { key: entry.key },
  );
}

/**
 * Build the placeholder -> plaintext table for one device.
 *
 * Resolution is the ordinary variable chain (global -> tenant -> group ->
 * device), read at mode `'secrets'`, which is the only mode that decrypts. No
 * `var_schema` is passed because this is not a render: nothing here validates a
 * template's declared inputs, it only needs the values that exist.
 *
 * ┌─ THE COLLISION THAT MUST NOT BE GUESSED ─────────────────────────────────┐
 * │ `redactedPlaceholder` UPPERCASES the key, while `VARIABLE_KEY_RE` is      │
 * │ `/^[a-z][a-zA-Z0-9_]{0,119}$/` — mixed case is legal. So `sitePsk` and    │
 * │ `sitepsk` both produce `__OBLIWAN_SECRET_SITEPSK__`, and two different    │
 * │ secrets share one placeholder. The masked artefact is then ambiguous and  │
 * │ NOTHING can resolve it correctly; picking either one has a 50 % chance of │
 * │ pushing the wrong credential to a customer's router. So it refuses, and   │
 * │ names both keys so an operator can rename one.                           │
 * └──────────────────────────────────────────────────────────────────────────┘
 */
export async function buildSecretSubstitutions(
  tenantId: number,
  deviceId: number,
): Promise<SecretSubstitution[]> {
  const ctx = await variableResolver.buildRenderContext(tenantId, deviceId, null, {
    mode: 'secrets',
  });

  const byPlaceholder = new Map<string, SecretSubstitution>();
  for (const key of ctx.secretKeys) {
    const placeholder = redactedPlaceholder(key);
    const existing = byPlaceholder.get(placeholder);
    if (existing && existing.key !== key) {
      throw new ChangeError(
        'SECRET_LEAK_REFUSED',
        `the secret variables "${existing.key}" and "${key}" both mask to ${placeholder}: the ` +
          'placeholder is the uppercased key, so the masked plan cannot say which of the two a ' +
          'command needs. Rename one of them and recompile the plan — guessing has a one-in-two ' +
          'chance of pushing the wrong credential to a router.',
        { placeholder, keys: [existing.key, key] },
      );
    }
    const plaintext = ctx.context[key];
    if (typeof plaintext !== 'string') {
      // `buildRenderContext` at mode 'secrets' throws when a declared secret is
      // unreadable, so reaching this means the contract changed. Refuse rather
      // than coerce: `String(undefined)` on this path writes the four
      // characters "unde" into a router as a PSK.
      throw new ChangeError(
        'SECRET_LEAK_REFUSED',
        `the vault returned a non-string value for the secret variable "${key}". Refusing to ` +
          'coerce it — a coerced secret is a wrong secret written to a customer device.',
        { key },
      );
    }
    byPlaceholder.set(placeholder, { placeholder, key, plaintext });
  }
  return [...byPlaceholder.values()];
}

/**
 * Substitute one line, producing both halves at once.
 *
 * A placeholder with no entry in the table is a REFUSAL, not a pass-through: the
 * plan was compiled against a variable set that no longer declares that secret,
 * and sending the literal `__OBLIWAN_SECRET_FOO__` writes twenty-three
 * characters of garbage where a credential belongs — the failure mode
 * `assertRenderingIsSafe` cannot see, because a placeholder is not a secret.
 *
 * Four refusals, in the order they can fire: an unresolvable placeholder, an
 * empty value, a value that cannot sit in a command line, and a substituted line
 * the brand refuses to send. The last two are this function's injection barrier
 * and are the reason `assertLine` is a required argument — see the header box.
 */
export function substituteLine(
  line: string,
  table: readonly SecretSubstitution[],
  assertLine: LineAssertion,
): { substituted: SubstitutedLine; used: SecretSubstitution[] } {
  const found = line.match(SECRET_PLACEHOLDER_RE);
  // A line with no placeholder is returned untouched and UNASSERTED: nothing
  // here changed it, its producer already put it through the same hard stop, and
  // re-judging it would move the blame for a renderer bug into this module.
  if (!found) return { substituted: { command: line, redacted: line }, used: [] };

  const used: SecretSubstitution[] = [];
  let command = line;
  for (const placeholder of new Set(found)) {
    const entry = table.find((t) => t.placeholder === placeholder);
    if (!entry) {
      throw new ChangeError(
        'SECRET_LEAK_REFUSED',
        `the plan needs the secret ${placeholder}, and no secret variable resolves to it for ` +
          'this device. The variable was renamed, unset or stopped being a secret since the ' +
          'plan was compiled; recompile the plan rather than push the placeholder.',
        { placeholder },
      );
    }
    if (entry.plaintext.length === 0) {
      // An empty secret would render `password=""`, which is not "no change" —
      // it is an empty credential on a customer box.
      throw new ChangeError(
        'SECRET_LEAK_REFUSED',
        `the secret variable "${entry.key}" resolves to an empty string. Writing it would set an ` +
          'EMPTY credential on the device, which is worse than refusing.',
        { key: entry.key },
      );
    }
    assertSubstitutableSecret(entry);
    command = command.split(placeholder).join(entry.plaintext);
    used.push(entry);
  }

  // The brand's hard stop, on the text that will actually be sent. Reached only
  // when the value-level rule above let something through, so it is a
  // structural backstop rather than the barrier — but it is the one that keeps
  // the `:do={} on-error={}` wrapper intact if a dialect escaper ever loses a
  // character.
  try {
    assertLine(command);
  } catch {
    // The caught error is deliberately not re-used: a brand assertion is free to
    // quote the line it refused, and that line holds a plaintext. Name
    // the variables instead.
    throw new ChangeError(
      'SECRET_LEAK_REFUSED',
      `substituting ${used.map((u) => `"${u.key}"`).join(', ')} produced a command line this ` +
        "brand's renderer refuses to send. The value breaks the statement it sits in, which on " +
        'RouterOS means closing the :do{} wrapper and orphaning the rollback branch. Refusing to ' +
        'push it.',
      { keys: used.map((u) => u.key) },
    );
  }

  // `redacted` is the ORIGINAL line: the placeholder is already the masked form,
  // it names the variable rather than its value, and it is what a reviewer needs
  // in order to know which secret landed where.
  return { substituted: { command, redacted: line }, used };
}

/**
 * Assemble the `RenderedChange` the secrets rule asks for, in ONE pass over the lines.
 *
 * Pure — the secret table is an argument — so the property that matters can be
 * asserted without a database (`renderer.verify.ts`). That is deliberate: the
 * caller that has the database must not own a second copy of this loop, because
 * a test written against a copy passes while the product leaks.
 *
 * Two checks live here rather than in the caller:
 *
 *  - INDEX ALIGNMENT. `assertRenderingIsSafe()` does not compare the two
 *    lengths, and their consumers differ — `appliedOps` and the dead-man's
 *    `opsCount` read `commands`, the step output reads `redacted`. A rendering
 *    whose halves disagree produces an audit trail that disagrees with what was
 *    sent, and the safety-net rule decides how much to roll back from that number.
 *  - NO PLAINTEXT IN THE MASKED HALF, at ANY length. `assertNoSecrets()` and
 *    `redactForAudit()` both guard with `secret.length >= 4`, so a three-
 *    character secret passes them silently. Here the masked half keeps the
 *    PLACEHOLDER rather than a scrubbed value, so a plaintext appearing in it is
 *    a bug in `substituteLine` — and this is what says so instead of persisting
 *    it.
 *
 * `assertLine` is forwarded, not applied here: it must run on each line as it is
 * substituted, so the refusal can still name the variables responsible.
 */
export function assembleRendering(
  texts: readonly string[],
  table: readonly SecretSubstitution[],
  assertLine: LineAssertion,
): RenderedChange {
  const commands: string[] = [];
  const redacted: string[] = [];
  // Keyed by variable so one secret used on six lines is declared once.
  const used = new Map<string, string>();

  for (const text of texts) {
    const { substituted, used: entries } = substituteLine(text, table, assertLine);
    commands.push(substituted.command);
    redacted.push(substituted.redacted);
    for (const e of entries) used.set(e.key, e.plaintext);
  }

  if (commands.length !== redacted.length) {
    throw new ChangeError(
      'SECRET_LEAK_REFUSED',
      `the rendering produced ${commands.length} commands and ${redacted.length} redacted ` +
        'lines. They must be index-aligned: the audit trail is written from one and the device ' +
        'receives the other.',
    );
  }

  const secretValues = [...used.values()];
  for (const plaintext of secretValues) {
    for (let i = 0; i < redacted.length; i++) {
      if (redacted[i].includes(plaintext)) {
        throw new ChangeError(
          'SECRET_LEAK_REFUSED',
          `the masked rendering of command ${i + 1} still contains a secret plaintext. ` +
            'Refusing to hand it to the audit trail.',
          { index: i },
        );
      }
    }
  }

  return { commands, redacted, secretValues };
}
