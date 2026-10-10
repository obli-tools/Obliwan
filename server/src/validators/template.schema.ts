// ============================================================================
// template.schema.ts — the API boundary (templates, revisions, variables)
// ============================================================================
//
// Everything the outside world can say about a template, a revision, a partial,
// an assignment or a variable passes through this file first.
//
// Two of these schemas are not "input validation" in the ordinary sense — they
// are part of the mitigation of the risk of RCE (through Nunjucks on the server
// that holds every customer's admin credentials), and they must not be relaxed
// for convenience:
//
//   • `variableKey` — lowercase snake_case, letter-initial. This is what makes
//     `__proto__`, `constructor` and `prototype` UNREPRESENTABLE as variable
//     names, so a render context cannot be handed a polluted prototype. The
//     same regex is re-checked at write time and again at read time in
//     `variableResolver.service.ts`; three checks for one rule, because the
//     cost of the rule failing is an attacker-controlled prototype inside the
//     template sandbox.
//   • `renderPreviewSchema` — has NO `mode` field on purpose. The API can only
//     ever ask for the REDACTED render. The plaintext-secret context
//     exists solely on the in-memory path vault -> equipment and is reachable
//     only from server code — `variableResolver.buildRenderContext(...,
//     { mode: 'secrets' })` inside the apply path, and the bench render
//     `siteRender.renderForSite(..., mode: 'secrets')` — never from a route.
//     If a future endpoint needs it, that is a design decision, not a patch.
//
// Capability note: every route fed by this file is
// `TEMPLATE_WRITE`, except the read-only listings which are `TEMPLATE_READ`,
// the site form (`setSiteVariablesSchema`), which is `SITE_VARIABLES_WRITE` —
// typed values for keys every published declaration opens to it with
// `x-obliwan-level: 'site'`, never a body — and the INSTANCE level
// (`/variables/instance`), whose writes are `requireRole('admin')`: a value
// there reaches every tenant's render, which no tenant capability may decide.
// The schemas below do not enforce that — `requireCapability` does — but a
// reviewer reading this file should know that a template body is executable
// input and is gated accordingly.
// ============================================================================

import { z } from 'zod';
import { DEVICE_BRANDS, varSchemaDiscoverProblems } from '@obliwan/shared';

// ============================================================================
// Shared atoms
// ============================================================================

/**
 * The canonical variable-name rule. Defined HERE rather than in the service so
 * the API boundary owns it and nothing has to import a module that opens a
 * database connection just to validate a form field;
 * `variableResolver.service.ts` re-exports it so there is exactly one regex in
 * the codebase.
 *
 * It is byte-for-byte migration 008's `config_variables_key_chk`
 * (`^[a-z][a-zA-Z0-9_]{0,119}$`) ON PURPOSE. A stricter application rule would
 * reject rows the database happily accepts from any other writer, and a render
 * would fail on a variable an operator can see in the table.
 *
 * ⚠ What this regex does NOT do — and 008's header claims it does: it refuses
 * `__proto__` (leading underscore), but `constructor` and `prototype` MATCH it.
 * They are stopped by `FORBIDDEN_KEYS` in the resolver and by the explicit list
 * below, at write time, at read time and again before the context crosses into
 * the worker. Do not remove either check on the strength of the other.
 */
export const VARIABLE_KEY_RE = /^[a-z][a-zA-Z0-9_]{0,119}$/;

/** Names that are legal per the regex but must never become context keys. */
export const FORBIDDEN_VARIABLE_KEYS = ['__proto__', 'constructor', 'prototype'] as const;

/**
 * The shape of a redacted secret, `variableResolver.redactedPlaceholder(key)`:
 * `__OBLIWAN_SECRET_<KEY>__`, the key uppercased. Defined here, beside the key
 * rule it is built from, so the engine's output lint can recognise one without
 * importing a module that opens a database connection. `variableResolver`
 * re-exports it (as do the push path's callers through it), so there is exactly
 * one. Global: use it with `match` / `replace`, never with a stateful `test`.
 */
export const SECRET_PLACEHOLDER_RE = /__OBLIWAN_SECRET_[A-Z0-9_]+__/g;

/**
 * The five inheritance levels of a VARIABLE, narrowest last (migration 035).
 *
 * `site` sits between `group` and `device`: a site value is more specific than
 * a group policy (a group is a fleet-wide grouping, a site is one customer
 * premises with its own VLAN and subnet) and less specific than a per-router
 * override. The order of this list is documentation; the precedence itself is
 * `VARIABLE_SCOPE_RANK` in the resolver, which is what the chain is sorted on.
 */
export const VARIABLE_SCOPES = ['global', 'tenant', 'group', 'site', 'device'] as const;

/**
 * The INSTANCE level (migration 038): one value shared by EVERY tenant of the
 * installation — the management L2TP password, the SNMP community, the
 * management concentrator's host name. Stored in `config_variables` with a
 * NULL `tenant_id`, ranked below `global` (which, despite its name, is one
 * tenant's widest level: the chain query filters it on `tenant_id`).
 *
 * Deliberately NOT in `VARIABLE_SCOPES`: that list is what the tenant-scoped
 * `/variables/at|bulk/:scope` routes accept under TEMPLATE_WRITE, and an
 * instance value is written by a platform administrator only
 * (`requireRole('admin')`, `/variables/instance`), never through a tenant
 * capability — it reaches every customer's render at once.
 */
export const INSTANCE_SCOPE = 'instance' as const;

/** Every level a `config_variables` row can be stored at, widest first. */
export const STORED_VARIABLE_SCOPES = [INSTANCE_SCOPE, ...VARIABLE_SCOPES] as const;

/**
 * The two levels a variable can be DECLARED at but never STORED at. Both are
 * supplied to the render by its caller and exist in memory only:
 *
 *  - `computed` — produced by ObliWAN itself at render time: the allocator's
 *    outputs (`ppp_username`, `lan_subnet`, `tunnel_ip`…). No variables route
 *    writes one; a render whose REQUIRED computed key was not supplied is
 *    refused, naming the key.
 *  - `bench`    — typed at the provisioning bench for ONE box (a SIM PIN).
 *    Never persisted, secrets included.
 */
export const RENDER_TIME_LEVELS = ['computed', 'bench'] as const;

/** What `x-obliwan-level` may say: a stored scope or a render-time level. */
export const VARIABLE_LEVELS = [...STORED_VARIABLE_SCOPES, ...RENDER_TIME_LEVELS] as const;

/**
 * Context names the bench render (`renderForSite`) fills with FACTS rather
 * than with variables: `site.*` from the site record, `box.*` from the box on
 * the bench. A revision may declare one of them only at a render-time level,
 * and the declaration then TYPES the facts object (its `required`, `enum`…);
 * it can never be stored, and never typed into the bench map.
 */
export const RESERVED_FACT_KEYS = ['site', 'box'] as const;

/**
 * Every name a render fills with a FACT object rather than a variable: `site`
 * and `box` on the bench (`RESERVED_FACT_KEYS`), `device` on the device path
 * (`render.service`'s `deviceFacts`). A STORED variable is resolved on both
 * paths — the same tenant row feeds a bench render and a fleet render — so no
 * level may store one under any of the three: the facts would collide with it
 * on every render that reads the chain, and at the instance level that is every
 * render of every tenant. Refused at write time (`storedVariableKey`, and the
 * resolver's `assertWritable` for service callers) and at read time (`fold`
 * rejects such a row by name). Removing one stays possible — the DELETE routes
 * take the key as it is — so a row stored before this rule can be cleared.
 */
export const CONTEXT_FACT_KEYS = [...RESERVED_FACT_KEYS, 'device'] as const;

/** Is `key` one of `CONTEXT_FACT_KEYS`? */
export function isContextFactKey(key: string): boolean {
  return (CONTEXT_FACT_KEYS as readonly string[]).includes(key);
}

/**
 * What a scope segment of a variables PATH may be, with the reason each
 * non-tenant level is refused there. Used by the controller's `parseScope`,
 * and exported so the harness can prove the refusals without a request.
 */
export const variableScopeParam = z.string().superRefine((raw, ctx) => {
  if ((VARIABLE_SCOPES as readonly string[]).includes(raw)) return;
  let message: string;
  if (raw === INSTANCE_SCOPE) {
    message =
      'scope "instance" is shared by every tenant: it is written by a platform administrator ' +
      'through /variables/instance, never through a tenant-scoped route';
  } else if ((RENDER_TIME_LEVELS as readonly string[]).includes(raw)) {
    message =
      `scope "${raw}" is never stored: ` +
      (raw === 'computed'
        ? 'a computed value is supplied by ObliWAN at render time (the allocator)'
        : 'a bench value is typed at the provisioning bench for one box and kept in memory only');
  } else {
    message = `invalid scope "${raw}": expected one of ${VARIABLE_SCOPES.join(', ')}`;
  }
  ctx.addIssue({ code: z.ZodIssueCode.custom, message });
});

/**
 * The four levels a template ASSIGNMENT may target — migration 008's
 * `template_assignments_scope_chk`, mirrored by `assignment.service`'s own
 * `ASSIGNMENT_SCOPES`. Deliberately NOT `VARIABLE_SCOPES`: migration 035 opened
 * `site` on `config_variables` only, and an assignment accepted here at scope
 * `site` would reach that CHECK and come back as a 500 instead of a 400.
 */
const ASSIGNMENT_TARGET_SCOPES = ['global', 'tenant', 'group', 'device'] as const;

/** The levels whose identity is the tenant itself, hence a NULL `scope_id`. */
const UNSCOPED_LEVELS: readonly string[] = ['global', 'tenant'];

export const variableKey = z
  .string()
  .regex(
    VARIABLE_KEY_RE,
    'variable name must start with a lowercase letter and contain only letters, digits and _ (max 120 characters)',
  )
  .refine((k) => !(FORBIDDEN_VARIABLE_KEYS as readonly string[]).includes(k), {
    message: 'this name would collide with a JavaScript prototype member',
  });

/**
 * A key a variable may be STORED under: `variableKey`, minus the context fact
 * names (`CONTEXT_FACT_KEYS`). Every write body uses it — one variable and bulk
 * (the tenant levels and the instance level alike) and the site form's
 * entries. A removal does not: the DELETE routes take the key as it is, so a
 * row stored under one of these names before the rule existed can still be
 * cleared.
 */
export const storedVariableKey = variableKey.refine((k) => !isContextFactKey(k), {
  message:
    `${CONTEXT_FACT_KEYS.map((k) => `"${k}"`).join(', ')} name the fact objects a render supplies ` +
    '(the site record, the box on the bench, the router itself): a variable stored under one ' +
    'of them would collide with those facts on every render that reads it — choose another name',
});

const scopeEnum = z.enum(VARIABLE_SCOPES);
const brandEnum = z.enum(DEVICE_BRANDS as unknown as [string, ...string[]]);

/**
 * A JSON value, bounded.
 *
 * The depth cap matters: the value ends up in a Nunjucks context, and an
 * arbitrarily deep structure is a cheap way to make the serializer between the
 * main thread and the render worker do unbounded work. 12 levels is far more
 * than any real template variable (a list of VLANs, a map of site codes) and
 * far less than a problem.
 *
 * `z.record` here rejects nothing by key name — that is `variableKey`'s job at
 * the top level. Nested keys never become context identifiers; they are only
 * reachable as `{{ obj.field }}`, and `variableResolver.assertJsonPure()`
 * refuses `__proto__` at every depth before anything crosses into the worker.
 */
export type JsonInput = z.infer<typeof jsonValue>;
const jsonLiteral = z.union([z.string().max(8192), z.number().finite(), z.boolean(), z.null()]);
const jsonValue: z.ZodType<unknown> = z.lazy(() =>
  z.union([jsonLiteral, z.array(jsonValue).max(512), z.record(jsonValue)]),
);

/** Depth guard — zod cannot express it, so it is a refinement. */
function depthOf(v: unknown, d = 0): number {
  if (d > 16 || v === null || typeof v !== 'object') return d;
  const children = Array.isArray(v) ? v : Object.values(v as Record<string, unknown>);
  let max = d;
  for (const c of children) max = Math.max(max, depthOf(c, d + 1));
  return max;
}

export const variableValue = jsonValue.refine((v) => depthOf(v) <= 12, {
  message: 'variable value is nested more than 12 levels deep',
});

// ============================================================================
// Variables — `config_variables`
// ============================================================================

/**
 * `scope_id` is NULL for 'global' and 'tenant' (their identity is carried by
 * `tenant_id`, exactly as in `settings`) and REQUIRED for every other level —
 * 'group', 'site' and 'device'. Expressing it here means the controller never
 * has to guess, and the two PARTIAL unique indexes on `config_variables` are
 * never asked to constrain a row that sits outside both of them.
 *
 * The rule is written as "everything but the two unscoped levels needs an id"
 * rather than as a list of the levels that need one, so that the next level
 * added to `VARIABLE_SCOPES` is scoped by default — the safe way round: a
 * scoped level mistaken for an unscoped one would land in the UNSCOPED index
 * and behave like a tenant-wide variable.
 */
function refineScopeId(
  v: { scope: string; scopeId?: number | null },
  ctx: z.RefinementCtx,
): void {
  const needsId = !UNSCOPED_LEVELS.includes(v.scope);
  const hasId = v.scopeId !== null && v.scopeId !== undefined;
  if (needsId && !hasId) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['scopeId'],
      message: `scope "${v.scope}" requires a scopeId`,
    });
  }
  if (!needsId && hasId) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['scopeId'],
      message: `scope "${v.scope}" must not carry a scopeId — it is identified by the tenant`,
    });
  }
}

const scopeIdField = z.number().int().positive().nullable().optional();

const scopeTarget = z
  .object({ scope: scopeEnum, scopeId: scopeIdField })
  .superRefine(refineScopeId);

/** Same rule, on the four levels an assignment may target. */
const assignmentScopeTarget = z
  .object({ scope: z.enum(ASSIGNMENT_TARGET_SCOPES), scopeId: scopeIdField })
  .superRefine(refineScopeId);

/**
 * Setting one variable.
 *
 * `isSecret: true` means the value goes to the vault and comes back redacted
 * everywhere but the in-memory push path. It therefore MUST be a string:
 * the vault encrypts strings, and "a secret that is an object" has no meaning
 * on a router. A non-empty one, because an empty secret is almost always a form
 * that was submitted before the operator pasted the value, and storing it would
 * silently push an empty password.
 */
export const setVariableSchema = z
  .object({
    key: storedVariableKey,
    value: variableValue,
    isSecret: z.boolean().optional().default(false),
  })
  .superRefine((v, ctx) => {
    if (!v.isSecret) return;
    if (typeof v.value !== 'string') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['value'],
        message: 'a secret variable must be a string',
      });
      return;
    }
    if (v.value.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['value'],
        message: 'a secret variable must not be empty',
      });
    }
    if (v.value.length > 4096) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['value'],
        message: 'a secret variable must be at most 4096 characters',
      });
    }
  });

export const setVariablesBulkSchema = z.object({
  entries: z.array(setVariableSchema).min(1).max(200),
});

export const variableScopeParamsSchema = scopeTarget;

/**
 * `PUT /variables/sites/:siteId` — the account manager's form
 * (`SITE_VARIABLES_WRITE`).
 *
 * Narrower than `setVariablesBulkSchema` on purpose, in two ways:
 *
 *  - there is NO `isSecret` field, and the entry object is `.strict()` so a
 *    caller that sends one is told so instead of being silently ignored.
 *    Whether a value goes to the vault is decided by the template's own
 *    `x-obliwan-secret` declaration, not by the person typing it: a form that
 *    could store a declared secret in clear would put a credential in a jsonb
 *    column that gets rendered, diffed and exported (migration 008 decision 6).
 *  - `unset` lists keys to remove AT THE SITE LEVEL, so the site falls back on
 *    whatever it inherits. It is a separate list rather than `value: null`,
 *    because `null` is a legal JSON value a template may genuinely ask for.
 *
 * Whether a key is DECLARED and opened to the site form, and whether its value
 * matches the declaration, is not knowable here — it depends on which
 * revisions are published for the tenant — and is judged by
 * `variableResolver.setSiteValues()`.
 */
export const setSiteVariablesSchema = z
  .object({
    entries: z
      .array(z.object({ key: storedVariableKey, value: variableValue }).strict())
      .max(200)
      .default([]),
    // A plain `variableKey`, as on the DELETE routes: a removal is never
    // refused for the name alone. Whether a key may be unset HERE is the
    // declarations' question (`validateSiteValues`).
    unset: z.array(variableKey).max(200).default([]),
  })
  .strict()
  .superRefine((v, ctx) => {
    if (v.entries.length === 0 && v.unset.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['entries'],
        message: 'nothing to write: send at least one entry or one key to unset',
      });
    }
  });

// ============================================================================
// `var_schema` — the JSON Schema a revision carries
// ============================================================================

/**
 * A shallow structural check only. The real verdict is `ajv.compile()` in
 * `variableResolver.compileVarSchema()`, which is the same compiler that will
 * run at render time — validating a schema with anything else would let a
 * revision be published with a schema that only fails on the first device it is
 * applied to.
 *
 * What is enforced here is what ajv does NOT check and what matters to us:
 *  - the document is an object schema with named properties (a template's
 *    inputs are named, never positional);
 *  - every property name is a legal variable name, so `var_schema` cannot
 *    declare `__proto__`;
 *  - every `required` entry is actually declared, so an operator cannot publish
 *    a revision that is unsatisfiable by construction;
 *  - a property marked `x-obliwan-secret` carries no `default` — a default for
 *    a secret is a plaintext credential in the revision body, which is exactly
 *    what the vault exists to prevent;
 *  - `x-obliwan-level` names a level that exists (`VARIABLE_LEVELS`), and a
 *    `computed` property carries no `default` either: a computed value is
 *    ObliWAN's (an allocator output, an identity), and a default would turn
 *    "the allocator did not supply it" into a made-up value rendered without
 *    a word;
 *  - `site` and `box` (`RESERVED_FACT_KEYS`) are declared only at a
 *    render-time level, never secret and with no default — they name the facts
 *    the bench render supplies, and a declaration of them can only TYPE those
 *    facts, never invent one;
 *  - `device` is not declared at all: it names the facts the device path
 *    supplies, which no declaration types (`CONTEXT_FACT_KEYS`);
 *  - an `x-obliwan-discover` probe follows its grammar
 *    (`varSchemaDiscoverProblems`, @obliwan/shared infraAnalysis.ts): an
 *    allow-listed menu, a site-level variable, a sensitive property only on
 *    a secret variable and always marked so. ajv ignores the keyword's
 *    content, and the analysis would otherwise meet a broken probe on the
 *    first router it reads.
 */
export const varSchemaSchema = z
  .object({
    type: z.literal('object').optional(),
    properties: z.record(z.record(z.unknown())).default({}),
    required: z.array(z.string()).max(200).optional(),
    additionalProperties: z.boolean().optional(),
  })
  .passthrough()
  .superRefine((s, ctx) => {
    const props = s.properties ?? {};
    const names = Object.keys(props);
    if (names.length > 200) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['properties'],
        message: 'a template may declare at most 200 variables',
      });
    }
    for (const name of names) {
      if (!VARIABLE_KEY_RE.test(name)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['properties', name],
          message: `"${name}" is not a legal variable name (lowercase snake_case)`,
        });
      }
      const p = props[name] as Record<string, unknown>;
      const secret = p['x-obliwan-secret'] === true;
      if (secret && 'default' in p) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['properties', name, 'default'],
          message:
            'a secret variable must not carry a default — that would put a plaintext ' +
            'credential in the revision body',
        });
      }
      const level = p['x-obliwan-level'];
      if (
        level !== undefined &&
        !(typeof level === 'string' && (VARIABLE_LEVELS as readonly string[]).includes(level))
      ) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['properties', name, 'x-obliwan-level'],
          message: `x-obliwan-level must be one of ${VARIABLE_LEVELS.join(', ')}`,
        });
      }
      if (level === 'computed' && 'default' in p) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['properties', name, 'default'],
          message:
            'a computed variable must not carry a default — its value is supplied by ObliWAN at ' +
            'render time, and a default would render a made-up value whenever it was not',
        });
      }
      if (name === 'device') {
        // Unlike `site` and `box`, nothing could ever type it: the device path
        // lays the router's own facts into the context as they are. Declared,
        // it is at best inert and at worst — with a default — a resolved
        // variable that collides with those facts on every render.
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['properties', name],
          message:
            '"device" names the facts every fleet render supplies about the router itself ' +
            '(device.model, device.serial…): it cannot be declared as a variable',
        });
      }
      if ((RESERVED_FACT_KEYS as readonly string[]).includes(name)) {
        const renderTime =
          typeof level === 'string' && (RENDER_TIME_LEVELS as readonly string[]).includes(level);
        if (!renderTime || secret || 'default' in p) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['properties', name],
            message:
              `"${name}" names the ${name} facts the bench render supplies: it may be declared ` +
              `only with x-obliwan-level ${RENDER_TIME_LEVELS.join(' or ')}, never secret and ` +
              'without a default, and the declaration then types those facts',
          });
        }
      }
    }
    // `x-obliwan-discover` — how the variable's value is read off a router in
    // service (shared/src/infraAnalysis.ts holds the grammar). Judged here so
    // a malformed probe is refused at authoring AND at import (both reach this
    // schema) with the variable named, rather than skipped at analysis time.
    for (const problem of varSchemaDiscoverProblems(s)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: problem.path, message: problem.message });
    }
    for (const r of s.required ?? []) {
      // OWN properties only: `'toString' in props` is true through the prototype.
      if (!Object.prototype.hasOwnProperty.call(props, r)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['required'],
          message: `"${r}" is required but is not declared in properties`,
        });
      }
    }
  });

// ============================================================================
// Templates and revisions
// ============================================================================

/**
 * A template body is EXECUTABLE INPUT. The cap is not politeness: the body is
 * parsed and rendered inside the worker whose `resourceLimits` and 5 s timeout
 * are the template-RCE mitigation, and a multi-megabyte body is a cheap way to spend that
 * budget before the template does anything. 512 KB is roughly 8 000 lines of
 * RouterOS — an order of magnitude more than a full site configuration.
 */
const templateBody = z.string().min(1).max(512 * 1024);

/**
 * RouterOS is not strictly semver: `7`, `7.14`, `7.14.3`, `6.49.10`, `7.15rc2`
 * and `7.16beta4` are all versions MikroTik actually ships. This is migration
 * 008's `VERSION_SHAPE`, so a value accepted here cannot be rejected by the
 * column check; the real ordering is `semver.coerce` in `assignment.service`.
 */
const osVersion = z
  .string()
  .min(1)
  .max(32)
  .regex(/^[0-9]+(\.[0-9]+){0,2}[A-Za-z0-9.+-]*$/, 'expected a version like 7.14.3 or 7.15rc2');

/**
 * Why a model GLOB would not do what its author meant, or null when it is fine.
 *
 * The characters refused are regular-expression syntax that no MikroTik model
 * code uses and that `modelMatches()` would take LITERALLY — so a pattern
 * carrying one is a regular expression typed into a glob field, and it would
 * silently match nothing. What model codes DO carry stays legal: `+`
 * (`S53UG+5HaxD2HaxD`), `&` (the LTE kits, `RBD53G-5HacD2HnD-TC&EG12-EA`),
 * `^` inside a name (`hAP ac^2`), spaces inside a board name. A leading `*` is
 * legal too (`*LTE*`): it is the glob's own wildcard, not a dangling
 * quantifier. A glob has no alternation, so one pattern cannot cover two
 * model families (`RBD53*` and `S53UG*`); that takes one template per family.
 */
export function modelGlobProblem(pattern: string): string | null {
  const syntax =
    'a model pattern is a glob — "*" any run of characters, "?" exactly one, matched ' +
    'case-insensitively against the whole model';
  if (pattern.trim().length === 0) return `${syntax}; an empty pattern matches nothing`;
  if (pattern !== pattern.trim()) {
    return `${syntax}; leading or trailing whitespace would have to be part of the model`;
  }
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(pattern)) return `${syntax}; it contains a control character`;
  const regexChar = /[\\|()[\]{}$]/.exec(pattern);
  if (regexChar) {
    return (
      `${syntax}; "${regexChar[0]}" is regular-expression syntax the glob would take literally, ` +
      'so the pattern would match no device'
    );
  }
  if (pattern.startsWith('^')) {
    return `${syntax}; a leading "^" is a regular-expression anchor — a glob is always anchored`;
  }
  if (/\.[*+]/.test(pattern)) {
    return `${syntax}; ".*" and ".+" are regular expressions — write "*" alone`;
  }
  return null;
}

export const createTemplateSchema = z.object({
  name: z.string().min(1).max(120),
  description: z.string().max(2000).nullable().optional(),
  brand: brandEnum,
  /**
   * A GLOB — `*` any run of characters, `?` exactly one — matched against the
   * WHOLE `devices.model`, case-insensitively. The matcher is
   * `assignment.service.modelMatches()`, and it is the contract: it escapes
   * every other character, so this field is validated as what that function
   * evaluates, not as a regular expression (migration 008 chose a glob so an
   * operator-typed pattern can never backtrack on the API thread).
   *
   * Every string is a syntactically valid glob, so what is refused here is the
   * pattern that would match nothing its author meant: regular-expression
   * syntax the glob takes literally (`RB(4011|5009).*`), stray whitespace at
   * either end, a control character (`modelGlobProblem`). A pattern that only
   * misbehaves inside the assignment resolver would surface as "no devices
   * matched", indistinguishable from a correct empty result — the worst
   * failure mode a rollout selector can have.
   */
  modelPattern: z
    .string()
    .max(120)
    .superRefine((p, ctx) => {
      const problem = modelGlobProblem(p);
      if (problem) ctx.addIssue({ code: z.ZodIssueCode.custom, message: problem });
    })
    .nullable()
    .optional(),
  status: z.enum(['active', 'archived']).optional(),
});

export const updateTemplateSchema = createTemplateSchema.partial();

/**
 * The sandbox knobs frozen WITH the body (migration 008): a published revision
 * whose `autoescape` could be flipped afterwards is a published revision whose
 * escaping is not published.
 *
 * `throwOnUndefined` is not offered as `false`. Nunjucks' default is to render
 * an undefined expression as the empty string, which produces exactly the
 * silent hole this milestone's variable resolver refuses to produce; allowing
 * a revision to opt back into it would route around the check.
 */
const renderOptions = z
  .object({
    throwOnUndefined: z.literal(true).optional(),
    trimBlocks: z.boolean().optional(),
    lstripBlocks: z.boolean().optional(),
    autoescape: z.boolean().optional(),
  })
  .strict();

export const createRevisionSchema = z.object({
  body: templateBody,
  varSchema: varSchemaSchema.optional(),
  /** `path -> severity`, consumed by the drift engine to weight a finding
   *  produced by this section of the template. */
  sectionSeverity: z.record(z.enum(['info', 'low', 'medium', 'high', 'critical'])).optional(),
  /** Per-REVISION OS window — a revision that starts using `/interface/wifi`
   *  is RouterOS 7 only while its predecessor was not. */
  osMin: osVersion.nullable().optional(),
  osMax: osVersion.nullable().optional(),
  renderOptions: renderOptions.optional(),
  notes: z.string().max(4000).nullable().optional(),
});

/**
 * Publishing is the moment a revision becomes immutable and its partial
 * dependencies are PINNED. There is deliberately no `body` here: you
 * publish a draft that already exists, you do not publish new content in one
 * shot. That is what makes "editing a partial does not change the render of a
 * published revision" true rather than aspirational.
 */
export const publishRevisionSchema = z.object({
  /** Optional operator note, stored with the publication event. */
  note: z.string().max(1000).nullable().optional(),
});

export const revisionStatusSchema = z.object({
  status: z.enum(['quarantined', 'deprecated']),
  reason: z.string().min(1).max(1000),
});

// ============================================================================
// Partials
// ============================================================================

/**
 * A partial is addressed by name from `{% include %}` / `{% import %}`, so its
 * name is a loader key and must not be able to escape the DB loader into the
 * filesystem. This is migration 008's `PARTIAL_NAME_SHAPE`: slash-separated
 * segments, each starting with a letter or a digit — which structurally
 * excludes a leading slash, a `..` segment, a leading dot and a `C:` drive
 * letter. Backslashes are excluded by not being in the character class.
 */
export const PARTIAL_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]*(\/[A-Za-z0-9][A-Za-z0-9_.-]*)*$/;

export const partialNameSchema = z
  .string()
  .min(1)
  .max(120)
  .regex(PARTIAL_NAME_RE, 'partial name must be slash-separated segments of letters, digits, _ . -')
  // `..` cannot appear as a whole segment given the regex, but a segment such
  // as `..foo` is legal and a future loader that concatenated names would be
  // one join away from a traversal. Refuse the substring outright.
  .refine((n) => !n.includes('..'), { message: 'partial name must not contain ".."' });

export const createPartialSchema = z.object({
  name: partialNameSchema,
  description: z.string().max(2000).nullable().optional(),
  brand: brandEnum.nullable().optional(),
});

export const createPartialRevisionSchema = z.object({
  body: templateBody,
  changelog: z.string().max(4000).nullable().optional(),
});

// ============================================================================
// Assignments
// ============================================================================

/**
 * `revisionId: null` means "follow the latest published revision"; a number
 * pins the assignment to one revision forever. `pinMode` says which of the two
 * the operator MEANT, so a null that arrived by accident is distinguishable
 * from a null that was chosen.
 *
 * `priority` breaks ties WITHIN a scope level only. Precedence BETWEEN levels
 * (device > group > tenant > global) is decided by the level itself and is not
 * configurable — migration 008 says so, and it is right: a priority that could
 * invert the levels would make the resolution unexplainable in the UI.
 */
export const createAssignmentSchema = assignmentScopeTarget.and(
  z.object({
    templateId: z.number().int().positive(),
    revisionId: z.number().int().positive().nullable().optional(),
    pinMode: z.enum(['latest_published', 'pinned']).default('latest_published'),
    priority: z.number().int().min(0).max(10000).default(100),
    enabled: z.boolean().default(true),
  }),
).superRefine((v, ctx) => {
  if (v.pinMode === 'pinned' && (v.revisionId === null || v.revisionId === undefined)) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['revisionId'],
      message: 'pinMode "pinned" requires a revisionId',
    });
  }
  if (v.pinMode === 'latest_published' && v.revisionId) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['revisionId'],
      message:
        'pinMode "latest_published" must not carry a revisionId — pick "pinned" if you meant to freeze it',
    });
  }
});

export const updateAssignmentSchema = z.object({
  priority: z.number().int().min(0).max(10000).optional(),
  enabled: z.boolean().optional(),
  revisionId: z.number().int().positive().nullable().optional(),
  pinMode: z.enum(['latest_published', 'pinned']).optional(),
});

// ============================================================================
// Render preview
// ============================================================================

/**
 * Preview a revision against a witness device.
 *
 * NOTE THE ABSENCE OF A `mode` FIELD. The API renders the REDACTED form and
 * nothing else: secrets exist in plaintext only in memory, on the path
 * vault -> equipment. There is no query parameter, no header and no
 * admin flag that turns this endpoint into a credential reader.
 *
 * `overrides` lets an operator try a value without writing it — the same typed
 * validation applies, and a secret cannot be overridden this way (that would be
 * a plaintext credential in an HTTP body).
 */
export const renderPreviewSchema = z.object({
  deviceId: z.number().int().positive(),
  overrides: z
    .array(
      z.object({
        key: variableKey,
        value: variableValue,
      }),
    )
    .max(50)
    .optional(),
});

// ============================================================================
// Inferred types — what the controllers receive
// ============================================================================

export type SetVariableInput = z.infer<typeof setVariableSchema>;
export type SetVariablesBulkInput = z.infer<typeof setVariablesBulkSchema>;
export type SetSiteVariablesInput = z.infer<typeof setSiteVariablesSchema>;
export type VariableScopeInput = z.infer<typeof variableScopeParamsSchema>;
export type VarSchemaInput = z.infer<typeof varSchemaSchema>;
export type CreateTemplateInput = z.infer<typeof createTemplateSchema>;
export type UpdateTemplateInput = z.infer<typeof updateTemplateSchema>;
export type CreateRevisionInput = z.infer<typeof createRevisionSchema>;
export type PublishRevisionInput = z.infer<typeof publishRevisionSchema>;
export type CreatePartialInput = z.infer<typeof createPartialSchema>;
export type CreatePartialRevisionInput = z.infer<typeof createPartialRevisionSchema>;
export type CreateAssignmentInput = z.infer<typeof createAssignmentSchema>;
export type UpdateAssignmentInput = z.infer<typeof updateAssignmentSchema>;
export type RenderPreviewInput = z.infer<typeof renderPreviewSchema>;
